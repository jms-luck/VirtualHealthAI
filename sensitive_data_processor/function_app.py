import azure.functions as func
import logging
from azure.ai.textanalytics import (
    TextAnalyticsClient,
    AnalyzeHealthcareEntitiesAction,
    RecognizePiiEntitiesAction
)
from azure.identity import DefaultAzureCredential
import os
import json
import uuid

app = func.FunctionApp()

# Load AI url from Env Variables
endpoint = os.getenv('TEXT_ANALYTICS_ENDPOINT', 'SETENVVAR!')

# Create client using Entra User or Managed Identity
text_analytics_client = TextAnalyticsClient(
    endpoint=endpoint,
    credential=DefaultAzureCredential(),
)

@app.function_name(name="sensitive_data_processor")
@app.blob_trigger(arg_name="myblob", path="unprocessed-text/{name}",
                  connection="AzureWebJobsStorage", source="EventGrid")
@app.blob_output(arg_name="outputblob", path="processed-text/{name}-redacted.txt", 
                connection="AzureWebJobsStorage")
def analyze_sensitive_data(myblob: func.InputStream, outputblob: func.Out[str]):
    document_id = str(uuid.uuid4())  # Generate unique ID for correlation
    logging.info(f"Starting analysis for document: {myblob.name} with document ID: {document_id}\n")
    
    # Read and decode the blob content
    document = [myblob.read().decode('utf-8')]
    
    # Analyze the document
    analysis_results = analyze_pii_phi(document, document_id)
    
    # Save redacted document results 
    outputblob.set(analysis_results)
    
    logging.info(f"Analysis completed for: {myblob.name} with process ID: {document_id}\n")

def log_structured_data(message, custom_dimensions, errors):
    """Helper function to create structured logs that can be queried in App Insights"""
    log_entry = {
        "analysis_type": message,
        "documents": custom_dimensions,
        "errors": errors,
        "modelVersion": "2023-09-01"
    }
    logging.info(json.dumps(log_entry))

def analyze_pii_phi(documents, document_id):
    """Analyze documents for PII and PHI entities"""
    try:
        # Start the analysis process
        poller = text_analytics_client.begin_analyze_actions(
            documents,
            display_name="PII and PHI Analysis",
            show_stats=True,
            actions=[
                RecognizePiiEntitiesAction(domain_filter="phi"),
                AnalyzeHealthcareEntitiesAction(),
            ],
        )

        # Get the results
        document_results = poller.result()
        
        # Process results from each action
        for action_results in document_results:
            for result in action_results:
                if result.kind == "PiiEntityRecognition":
                    document_redacted_text = result.redacted_text
                    # Process PII entities
                    pii_entities = [{
                        "category": entity.category,
                        "subcategory": entity.subcategory,
                        "offset": entity.offset,
                        "length": entity.length,
                        "confidence_score": entity.confidence_score,
                    } for entity in result.entities]
                    
                    # Log PII findings
                    log_structured_data(
                        "PII",
                        {
                            "id": document_id,
                            "entities": pii_entities,
                            "warnings": result.warnings
                        },
                        result.is_error
                    )                    

                elif result.kind == "Healthcare":
                    # Process healthcare entities
                    healthcare_entities = []
                    for entity in result.entities:
                        healthcare_entity = {
                            "category": entity.category,
                            "subcategory": entity.subcategory,
                            "confidence_score": entity.confidence_score,
                            "data_sources": [],
                            "offset": entity.offset,
                            "length": entity.length
                        }

                        # Add data sources if present
                        if entity.data_sources:
                            for source in entity.data_sources:
                                healthcare_entity["data_sources"].append({
                                    "entity_id": source.entity_id,
                                    "name": source.name
                                })

                        # Add assertion if present
                        if entity.assertion:
                            healthcare_entity["assertion"] = {
                                "conditionality": entity.assertion.conditionality,
                                "certainty": entity.assertion.certainty,
                                "association": entity.assertion.association
                            }

                        healthcare_entities.append(healthcare_entity)

                    # Log healthcare relations
                    relations = []
                    for relation in result.entity_relations:
                        # Procesar las entidades de la relación
                        entities = []
                        for role in relation.roles:
                            entity_info = {
                                "role": role.name
                            }
                            entities.append(entity_info)

                        relation_info = {
                            "confidenceScore": relation.confidence_score,
                            "relationType": relation.relation_type,
                            "entities": entities
                        }
                        relations.append(relation_info)

                    # Log healthcare findings
                    log_structured_data(
                        "PHI",
                        {
                            "id": document_id,
                            "entities": healthcare_entities,
                            "relations": relations,
                            "warnings": result.warnings
                        },
                        result.is_error
                    )

                elif result.is_error is True:
                    logging.error(
                        f"...Is an error with code '{result.error.code}' and message '{result.error.message}'"
                    )

        return document_redacted_text

    except Exception as e:
        logging.error(f"Error analyzing document: {str(e)}")
        return {
            "error": str(e),
            "status": "failed"
        }
