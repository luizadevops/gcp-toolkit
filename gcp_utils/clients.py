import logging
from typing import Optional
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import bigquery

_CLIENTS_CACHE = {}

def get_firewalls_client() -> compute_v1.FirewallsClient:
    client_key = "firewalls_client"
    if client_key not in _CLIENTS_CACHE:
        try:
            _CLIENTS_CACHE[client_key] = compute_v1.FirewallsClient()
            logging.debug("Compute Engine FirewallsClient initialized and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize Compute Engine FirewallsClient: {e}", exc_info=True)
            raise
    return _CLIENTS_CACHE[client_key]


def get_storage_client(project_id: Optional[str] = None) -> storage.Client:
    client_key = "storage_client"

    if client_key not in _CLIENTS_CACHE:
        try:
            _CLIENTS_CACHE[client_key] = storage.Client(project=project_id)
            logging.debug(f"Cloud Storage client initialized for project '{project_id or "default/inferred"}' and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize Cloud Storage client: {e}", exc_info=True)
            raise
    return _CLIENTS_CACHE[client_key]


def get_bigquery_client(project_id: Optional[str] = None) -> bigquery.Client:  
    client_key = "bigquery_client"
        
    if client_key not in _CLIENTS_CACHE:
        try:
            _CLIENTS_CACHE[client_key] = bigquery.Client(project=project_id)
            logging.debug(f"BigQuery client initialized for project '{project_id or "default/inferred"}' and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize BigQuery client: {e}", exc_info=True)
            raise
    return _CLIENTS_CACHE[client_key]