# cost_reporter/service.py
# (Em português: Módulo de serviço para o Relator de Contagem de Queries - Caso 3)

# Importa o módulo de logging para registrar informações, avisos e erros.
import logging
# Importa o módulo datetime para lidar com datas e timestamps.
import datetime
# Importa defaultdict e OrderedDict do módulo collections.
# defaultdict é útil para criar dicionários onde as chaves têm valores padrão (ex: 0 para contagens).
# OrderedDict mantém a ordem em que as chaves foram inseridas (útil para relatórios ordenados por data).
from collections import defaultdict, OrderedDict
# Importa tipos do módulo 'typing' para anotações de tipo, melhorando a legibilidade.
from typing import Dict, Any, List

# Importa a biblioteca cliente do Google Cloud BigQuery.
from google.cloud import bigquery
# Importa exceções específicas da API do Google para tratamento de erros mais granular.
from google.api_core import exceptions as google_exceptions
# Importa a função para obter o cliente do BigQuery do seu pacote de utilitários.
from gcp_utils.clients import get_bigquery_client

# Define uma função auxiliar para retornar o nome da ferramenta, usado consistentemente nos logs.
def _tool_name_for_logging():
    return "Query History Reporter" # Retorna o nome da ferramenta.

# Define uma função auxiliar para formatar um tamanho em bytes para um formato legível (KB, MB, GB, TB).
def _format_bytes(size_bytes: int) -> str:
    # size_bytes: O tamanho em bytes a ser formatado.
    # -> str: Retorna uma string representando o tamanho formatado.

    # Verifica se a entrada é um número válido e não negativo.
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        return "N/A" # Retorna "N/A" para entradas inválidas.
    if size_bytes == 0:
        return "0 Bytes" # Caso especial para 0 bytes.
        
    power = 1024 # Base para conversão (1024 para prefixos binários: KiB, MiB, etc., embora usemos rótulos KB, MB).
    n = 0 # Contador para o índice do rótulo da unidade de tamanho.
    # Dicionário com os rótulos para as unidades de tamanho.
    power_labels = {0 : 'Bytes', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    # Enquanto o tamanho for maior ou igual à 'power' (1024) e não tivermos chegado ao último rótulo (TB).
    while size_bytes >= power and n < len(power_labels) - 1:
        size_bytes /= power # Divide o tamanho por 1024 para converter para a próxima unidade.
        n += 1 # Incrementa o contador para usar o próximo rótulo de unidade.
    # Formata o resultado com 2 casas decimais e o rótulo da unidade apropriada.
    return f"{size_bytes:.2f} {power_labels[n]}"

# Define a função que busca as estatísticas diárias de queries do histórico de jobs do BigQuery.
def fetch_daily_query_stats_from_history(
    project_id: str, # O ID do projeto GCP a ser consultado.
    region: str,     # A região do BigQuery para a qual o histórico de jobs será consultado (ex: "US", "europe-west1").
    num_days: int,   # O número de dias passados (incluindo hoje) para incluir no relatório.
    bq_client: bigquery.Client, # Uma instância do cliente BigQuery.
    query_template: str # O template da query SQL (vindo do config.json) para consultar o INFORMATION_SCHEMA.
) -> OrderedDict[datetime.date, Dict[str, Any]]: # Retorna um OrderedDict com chaves datetime.date e valores dict.
    
    # Cria um defaultdict para armazenar as estatísticas diárias.
    # Se uma data for acessada e não existir, ela será criada com {"query_count": 0, "total_bytes_billed": 0}.
    daily_stats = defaultdict(lambda: {"query_count": 0, "total_bytes_billed": 0})
    # Obtém a data UTC atual (sem informações de hora).
    today_utc = datetime.datetime.now(datetime.timezone.utc).date()
    
    # Pré-popula 'daily_stats' com objetos datetime.date como chaves para todos os dias no período do relatório.
    # Isso garante que todos os dias apareçam, mesmo que não tenham tido queries.
    for i in range(num_days):
        report_date = today_utc - datetime.timedelta(days=i) # Calcula a data i dias atrás.
        daily_stats[report_date] # Acessa a chave para garantir que ela exista no defaultdict com valores padrão.

    # Constrói a parte do nome do dataset regional para a tabela INFORMATION_SCHEMA.
    # Ex: "US" -> "region-us", "europe_west1" -> "region-europe-west1".
    dataset_region_part = f"region-{region.lower().replace('_', '-')}"
    # Constrói o nome completo da tabela INFORMATION_SCHEMA a ser consultada.
    # Este nome da tabela será formatado dentro do query_template.
    info_schema_table_name = f"`{project_id}.{dataset_region_part}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`"

    # Formata o template da query (vindo do config.json) com o nome da tabela INFORMATION_SCHEMA construído.
    final_query = query_template.format(info_schema_table_name=info_schema_table_name)
    
    # Configura os parâmetros da query para o BigQuery.
    # O parâmetro @num_report_days na query SQL será substituído pelo valor de num_days.
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("num_report_days", "INT64", num_days),
        ],
        use_query_cache=False # Desabilita o cache de query para garantir dados mais recentes do INFORMATION_SCHEMA.
    )

    # Loga a ação de buscar o histórico.
    logging.info(f"{_tool_name_for_logging()}: Fetching query history from {info_schema_table_name} for the last {num_days} days.")
    # Loga a query completa em nível de debug.
    logging.debug(f"{_tool_name_for_logging()}: Executing query: {final_query.strip()}")

    try: # Inicia um bloco para tratamento de exceções da chamada à API do BigQuery.
        # Executa a query, especificando a 'location' (região) que é importante para queries INFORMATION_SCHEMA.
        query_job = bq_client.query(final_query, job_config=job_config, location=region)
        results = query_job.result() # Espera a query ser concluída e obtém os resultados.

        # Itera sobre cada linha (dia) retornada pela query.
        for row in results:
            job_date_obj = row.job_date # 'job_date' já é um objeto date retornado pelo cliente BigQuery.
            if job_date_obj in daily_stats: # Verifica se a data está no nosso dicionário de interesse.
                # Atualiza as estatísticas para aquela data.
                daily_stats[job_date_obj]["query_count"] = row.num_queries
                daily_stats[job_date_obj]["total_bytes_billed"] = row.total_bytes_billed_for_queries
        
        logging.info(f"{_tool_name_for_logging()}: Successfully fetched and processed query history from INFORMATION_SCHEMA.")

    except google_exceptions.NotFound as e: # Se a tabela INFORMATION_SCHEMA não for encontrada.
        logging.error(f"{_tool_name_for_logging()}: Could not find {info_schema_table_name}. "
                      f"Ensure region '{region}' is correct, BigQuery API is enabled, project ID is cased correctly, "
                      f"and 'information_schema_table_template' in config is valid. Error: {e}")
    except google_exceptions.Forbidden as e: # Se não houver permissão para consultar INFORMATION_SCHEMA.
        logging.error(f"{_tool_name_for_logging()}: Permission denied to query {info_schema_table_name}. "
                      f"Requires 'bigquery.jobs.listAll'. Error: {e}")
    except Exception as e: # Qualquer outro erro inesperado.
        logging.error(f"{_tool_name_for_logging()}: An unexpected error occurred while fetching query history: {e}", exc_info=True)

    # Cria um OrderedDict para garantir que os dados sejam retornados em ordem cronológica (do mais antigo para o mais novo).
    ordered_daily_stats = OrderedDict()
    for i in range(num_days):
        # Calcula a data, começando do dia mais antigo no período de 'num_days' até o dia atual.
        report_date = today_utc - datetime.timedelta(days=num_days - 1 - i) 
        # Adiciona a entrada ao OrderedDict. daily_stats.get() garante que, se uma data não tiver sido
        # explicitamente atualizada (ex: erro na query), ela ainda terá os valores padrão do defaultdict.
        ordered_daily_stats[report_date] = daily_stats.get(report_date, {"query_count": 0, "total_bytes_billed": 0}) 

    return ordered_daily_stats # Retorna o dicionário ordenado com estatísticas diárias.

# Função orquestradora principal para o Caso 3.
def run_reporter(project_id: str, bq_config: dict, 
                 delete_flag: bool, dry_run_flag: bool): # Aceita delete_flag e dry_run_flag para consistência de interface.
    # Loga o início da execução da ferramenta.
    logging.info(f"Starting {_tool_name_for_logging()} for project '{project_id}'.")
    # Log de depuração para registrar os flags recebidos (atualmente não usados por esta ferramenta específica).
    logging.debug(f"{_tool_name_for_logging()}: Received delete_flag={delete_flag} (not used), dry_run_flag={dry_run_flag} (not used).")
    
    # Extrai as configurações específicas do BigQuery do dicionário 'bq_config'.
    reporting_region = bq_config.get("reporting_region") # Região para a consulta INFORMATION_SCHEMA.
    report_days_history = bq_config.get("report_days_history", 7) # Número de dias para o relatório, padrão 7.
    # Template da query SQL para o INFORMATION_SCHEMA.
    info_schema_query_template = bq_config.get("information_schema_query_template")
    # Template do nome da tabela INFORMATION_SCHEMA.
    info_schema_table_template_from_config = bq_config.get("information_schema_table_template")

    # Verifica se as configurações essenciais foram fornecidas.
    if not reporting_region:
        logging.error(f"{_tool_name_for_logging()}: 'reporting_region' not defined in BigQuery configuration. Aborting report.")
        return # Sai da função se a região não estiver definida.
    if not info_schema_query_template:
        logging.error(f"{_tool_name_for_logging()}: 'information_schema_query_template' not defined in BigQuery configuration. Aborting report.")
        return # Sai se o template da query não estiver definido.
    if not info_schema_table_template_from_config:
        logging.error(f"{_tool_name_for_logging()}: 'information_schema_table_template' not defined in BigQuery configuration. Aborting report.")
        return # Sai se o template da tabela não estiver definido.

    bq_client = get_bigquery_client(project_id) # Obtém o cliente BigQuery.
    
    # Loga o cabeçalho do relatório.
    logging.info(f"\n--- {_tool_name_for_logging()} Report (Last {report_days_history} Days from Job History for region {reporting_region}) ---")
    
    # Chama a função para buscar as estatísticas diárias do histórico de jobs.
    daily_query_stats = fetch_daily_query_stats_from_history(
        project_id,
        reporting_region,
        report_days_history,
        bq_client,
        query_template=info_schema_query_template,
        info_schema_table_template=info_schema_table_template_from_config
    )

    # Verifica se foram retornadas estatísticas ou se todas as contagens são zero.
    if not daily_query_stats or all(stats.get("query_count", 0) == 0 for stats in daily_query_stats.values()):
        logging.info(f"{_tool_name_for_logging()}: No query executions found in job history for project '{project_id}' in region '{reporting_region}' for the past {report_days_history}-day period.")
    else: # Se houver dados para reportar.
        total_queries_in_period = 0 # Inicializa contador total de queries.
        total_bytes_billed_in_period = 0 # Inicializa contador total de bytes faturados.
        
        busiest_day_date_by_count_obj: datetime.date | None = None # Para armazenar o objeto de data do dia mais movimentado.
        max_queries_on_busiest_day = -1 # Para rastrear a contagem máxima de queries.
        
        # Itera sobre as estatísticas diárias (que já estão ordenadas por data, da mais antiga para a mais nova).
        for date_obj, stats in daily_query_stats.items():
            count = stats.get("query_count", 0) # Pega a contagem de queries para o dia.
            bytes_billed = stats.get("total_bytes_billed", 0) # Pega os bytes faturados para o dia.
            
            date_display_str = date_obj.strftime('%d-%m-%Y') # Formata a data para DD-MM-YYYY para exibição.
            bytes_str = _format_bytes(bytes_billed) # Formata os bytes para um formato legível.
            logging.info(f"  - {date_display_str}: {count} queries, Bytes Billed: {bytes_str}") # Loga as estatísticas do dia.
            
            total_queries_in_period += count # Adiciona ao total de queries.
            total_bytes_billed_in_period += bytes_billed # Adiciona ao total de bytes.
            
            # Lógica para encontrar o dia mais movimentado pela contagem de queries.
            if count > max_queries_on_busiest_day:
                max_queries_on_busiest_day = count
                busiest_day_date_by_count_obj = date_obj
            # Em caso de empate na contagem, prefere a data mais recente.
            elif count == max_queries_on_busiest_day and busiest_day_date_by_count_obj and date_obj > busiest_day_date_by_count_obj:
                busiest_day_date_by_count_obj = date_obj

        # Formata o total de bytes faturados no período para exibição.
        total_bytes_billed_str_period = _format_bytes(total_bytes_billed_in_period)
        logging.info(f"{_tool_name_for_logging()}: Total queries in the last {report_days_history} days: {total_queries_in_period}")
        logging.info(f"{_tool_name_for_logging()}: Total bytes billed in the last {report_days_history} days: {total_bytes_billed_str_period}")
        
        # Loga o dia mais movimentado, se houver.
        if busiest_day_date_by_count_obj and max_queries_on_busiest_day >= 0: # Verifica se max_queries >= 0 para incluir dias com 0 queries se todos forem 0.
            busiest_day_display_str = busiest_day_date_by_count_obj.strftime('%d-%m-%Y') # Formata a data.
            logging.info(f"{_tool_name_for_logging()}: Busiest day by query count: {busiest_day_display_str} (with {max_queries_on_busiest_day} queries)")
        else:
            logging.info(f"{_tool_name_for_logging()}: No queries with count > 0 found in the period to determine busiest day.")
            
    logging.info(f"--- End of {_tool_name_for_logging()} Report ---") # Rodapé do relatório.
