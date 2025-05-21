import logging
import datetime
from collections import defaultdict, OrderedDict
from typing import Dict, Any, List
from google.cloud import bigquery
from google.api_core import exceptions as google_exceptions
from gcp_utils.clients import get_bigquery_client

def tool_name():
    return "BigQuery Count Reporter"

def _format_bytes(size_bytes: int) -> str:
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        return "N/A"
    if size_bytes == 0:
        return "0 Bytes"
        
    power = 1024
    n = 0
    power_labels = {0 : 'Bytes', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size_bytes >= power and n < len(power_labels) - 1:
        size_bytes /= power
        n += 1
    return f"{size_bytes:.2f} {power_labels[n]}"

def fetch_daily_query_stats_from_history(
    project_id: str,
    region: str,
    num_days: int,
    bq_client: bigquery.Client,
    query_template: str,
    info_schema_table_template: str 
) -> OrderedDict[str, Dict[str, Any]]:
    
    daily_stats = defaultdict(lambda: {"query_count": 0, "total_bytes_billed": 0})
    today_utc = datetime.datetime.now(datetime.timezone.utc).date()
    
    for i in range(num_days):
        report_date = today_utc - datetime.timedelta(days=i)
        daily_stats[report_date.isoformat()] 

    dataset_region_part = f"region-{region.lower().replace('_', '-')}"
    
    actual_info_schema_table_name = info_schema_table_template.format(
        project_id=project_id,
        dataset_region_part=dataset_region_part
    )

    final_query = query_template.format(info_schema_table_name=actual_info_schema_table_name)
    
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("num_report_days", "INT64", num_days),
        ],
        use_query_cache=False
    )
    logging.info(f"{tool_name()}: Fetching query history from {actual_info_schema_table_name} for the last {num_days} days.")
    logging.debug(f"{tool_name()}: Executing query: {final_query.strip()}")

    try:
        query_job = bq_client.query(final_query, job_config=job_config, location=region)
        results = query_job.result()

        for row in results:
            job_date_str = row.job_date.isoformat()
            if job_date_str in daily_stats:
                daily_stats[job_date_str]["query_count"] = row.num_queries
                daily_stats[job_date_str]["total_bytes_billed"] = row.total_bytes_billed_for_queries
        logging.info(f"{tool_name()}: Successfully fetched and processed query history.")

    except google_exceptions.NotFound as e:
        logging.error(f"{tool_name()}: Could not find {actual_info_schema_table_name}. "
                      f"Ensure region '{region}' is correct, BigQuery API is enabled, project ID is cased correctly, "
                      f"and 'information_schema_table_template' in config is valid. Error: {e}")
    except google_exceptions.Forbidden as e:
        logging.error(f"{tool_name()}: Permission denied to query {actual_info_schema_table_name}. "
                      f"Requires 'bigquery.jobs.listAll'. Error: {e}")
    except Exception as e:
        logging.error(f"{tool_name()}: An unexpected error occurred while fetching query history: {e}", exc_info=True)

    ordered_daily_stats = OrderedDict()
    for i in range(num_days):
        report_date = today_utc - datetime.timedelta(days=num_days - 1 - i) 
        date_str = report_date.isoformat()
        ordered_daily_stats[date_str] = daily_stats[date_str] 

    return ordered_daily_stats

def run_reporter(project_id: str, bq_config: dict, 
                 delete_flag: bool, dry_run_flag: bool):
    logging.info(f"Starting {tool_name()} for project '{project_id}'.")
    logging.debug(f"{tool_name()}: Received delete_flag={delete_flag} (not used), dry_run_flag={dry_run_flag} (not used).")
        
    reporting_region = bq_config.get("reporting_region")
    report_days_history = bq_config.get("report_days_history", 7)
    info_schema_query_template = bq_config.get("information_schema_query_template")
    info_schema_table_template_from_config = bq_config.get("information_schema_table_template")

    if not reporting_region:
        logging.error(f"{tool_name()}: 'reporting_region' not defined in BigQuery configuration. Aborting report.")
        return
    if not info_schema_query_template:
        logging.error(f"{tool_name()}: 'information_schema_query_template' not defined in BigQuery configuration. Aborting report.")
        return
    if not info_schema_table_template_from_config:
        logging.error(f"{tool_name()}: 'information_schema_table_template' not defined in BigQuery configuration. Aborting report.")
        return

    bq_client = get_bigquery_client(project_id)    
    
    logging.info(f"{tool_name()} - Last {report_days_history} Days from Job History for region {reporting_region}) ---")
    
    daily_query_stats = fetch_daily_query_stats_from_history(
        project_id,
        reporting_region,
        report_days_history,
        bq_client,
        query_template=info_schema_query_template,
        info_schema_table_template=info_schema_table_template_from_config
    )

    if not daily_query_stats or all(stats.get("query_count", 0) == 0 for stats in daily_query_stats.values()):
        logging.info(f"{tool_name()}: No query executions found in job history for project '{project_id}' in region '{reporting_region}' for the past {report_days_history}-day period.")
    else:
        total_queries_in_period = 0
        total_bytes_billed_in_period = 0
        busiest_day_date_by_count = None
        max_queries_on_busiest_day = -1
        
        display_ordered_stats = OrderedDict(sorted(daily_query_stats.items()))

        for date_iso, stats in display_ordered_stats.items():
            count = stats.get("query_count", 0)
            bytes_billed = stats.get("total_bytes_billed", 0)
            bytes_str = _format_bytes(bytes_billed)
            logging.info(f"{tool_name()} for day {date_iso}: {count} queries, Bytes Billed: {bytes_str}")
            total_queries_in_period += count
            total_bytes_billed_in_period += bytes_billed
            if count > max_queries_on_busiest_day:
                max_queries_on_busiest_day = count
                busiest_day_date_by_count = date_iso
            elif count == max_queries_on_busiest_day and busiest_day_date_by_count and date_iso > busiest_day_date_by_count:
                busiest_day_date_by_count = date_iso

        total_bytes_billed_str_period = _format_bytes(total_bytes_billed_in_period)
        logging.info(f"{tool_name()}: Total queries in the last {report_days_history} days: {total_queries_in_period}")
        logging.info(f"{tool_name()}: Total bytes billed in the last {report_days_history} days: {total_bytes_billed_str_period}")
        
        if busiest_day_date_by_count and max_queries_on_busiest_day >= 0:
            logging.info(f"{tool_name()}: Busiest day by query count: {busiest_day_date_by_count} (with {max_queries_on_busiest_day} queries)")
        else:
            logging.info(f"{tool_name()}: No queries with count > 0 found in the period to determine busiest day.")