from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import bigquery
import logging

_CLIENTS = {}

# Então, um "cliente" como FirewallsClient é:
#Um objeto no seu programa Python. Que encapsula toda a complexidade de se comunicar com uma parte específica de um serviço remoto (a API de Firewalls do Compute Engine).
#Ele fornece uma interface mais simples e de alto nível (métodos Python) para você interagir com esse serviço, sem que você precise se preocupar com os detalhes de rede, autenticação de baixo nível ou formatação de dados da API.

def get_compute_client():
    if "compute" not in _CLIENTS:
        try:
            _CLIENTS["compute"] = compute_v1.FirewallsClient()
            logging.debug("Compute client initialized.")
        except Exception as e:
            logging.error(f"Failed to initialize Compute client: {e}")
            raise
    return _CLIENTS["compute"]

def get_storage_client(project_id=None):
    if "storage" not in _CLIENTS:
        try:
            _CLIENTS["storage"] = storage.Client(project=project_id)
            logging.debug(f"Storage client initialized for project {project_id or 'default'}.")
        except Exception as e:
            logging.error(f"Failed to initialize Storage client: {e}")
            raise
    return _CLIENTS["storage"]

def get_bigquery_client(project_id=None):
    if "bigquery" not in _CLIENTS:
        try:
            _CLIENTS["bigquery"] = bigquery.Client(project=project_id)
            logging.debug(f"BigQuery client initialized for project {project_id or 'default'}.")
        except Exception as e:
            logging.error(f"Failed to initialize BigQuery client: {e}")
            raise
    return _CLIENTS["bigquery"]