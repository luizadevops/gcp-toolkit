# gcp_utils/clients.py
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import bigquery
import logging
from typing import Optional # Para Python < 3.10, para Python 3.10+ pode usar 'str | None'

_CLIENTS = {}

def get_firewalls_client() -> compute_v1.FirewallsClient: # Nome e tipo de retorno atualizados
    """
    Retrieves a cached instance of the Compute Engine FirewallsClient.
    """
    client_key = "firewalls_client" # Chave de cache mais específica
    if client_key not in _CLIENTS:
        try:
            _CLIENTS[client_key] = compute_v1.FirewallsClient()
            logging.debug("Compute Engine FirewallsClient initialized and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize Compute Engine FirewallsClient: {e}", exc_info=True)
            raise
    return _CLIENTS[client_key]

def get_storage_client(project_id: Optional[str] = None) -> storage.Client: # Python < 3.10
# def get_storage_client(project_id: str | None = None) -> storage.Client: # Python 3.10+
    """
    Retrieves a cached instance of the Cloud Storage client.
    Args:
        project_id (Optional[str]): The project ID to associate with the client.
                                    If None, the client will attempt to infer from the environment.
    Returns:
        storage.Client: An instance of the Cloud Storage client.
    """
    client_key = "storage_client"
    if client_key not in _CLIENTS:
        try:
            _CLIENTS[client_key] = storage.Client(project=project_id)
            logging.debug(f"Cloud Storage client initialized for project '{project_id or "default/inferred"}' and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize Cloud Storage client: {e}", exc_info=True)
            raise
    return _CLIENTS[client_key]

def get_bigquery_client(project_id: Optional[str] = None) -> bigquery.Client: # Python < 3.10
# def get_bigquery_client(project_id: str | None = None) -> bigquery.Client: # Python 3.10+
    """
    Retrieves a cached instance of the BigQuery client.
    Args:
        project_id (Optional[str]): The project ID to associate with the client.
                                    If None, the client will attempt to infer from the environment.
    Returns:
        bigquery.Client: An instance of the BigQuery client.
    """
    client_key = "bigquery_client"
    if client_key not in _CLIENTS:
        try:
            _CLIENTS[client_key] = bigquery.Client(project=project_id)
            logging.debug(f"BigQuery client initialized for project '{project_id or "default/inferred"}' and cached.")
        except Exception as e:
            logging.error(f"Failed to initialize BigQuery client: {e}", exc_info=True)
            raise
    return _CLIENTS[client_key]