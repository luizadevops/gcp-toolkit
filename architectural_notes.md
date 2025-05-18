# ARCHITECTURE NOTES:
# - Trigger: Cloud Storage Event -> Cloud Function
# - Security: Service account with storage.admin + logging.admin
# - Cost: Uses Cloud Run if >9min runtime needed

desafio 1
1. # Cache de clientes para evitar reinicializações desnecessárias
