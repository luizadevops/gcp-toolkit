import logging
import json
import datetime
from collections import defaultdict # For aggregating daily counts
from google.cloud import bigquery
from google.api_core import exceptions as google_exceptions
from gcp_utils.clients import get_bigquery_client

def save_query_event(timestamp: str, log_file_path: str):
    try:
        with open(log_file_path, "a") as f:
            log_entry = {"timestamp": timestamp}
            f.write(json.dumps(log_entry) + "\n")
    except IOError as e:
        logging.error(f"Error writing query log file '{log_file_path}': {e}")
    except Exception as e:
        logging.error(f"Error while trying to log query execution: {e}")

def run_bigquery_queries(project_id: str, queries_to_run: list[str], repeat_count: int, log_file_path: str) -> int:

    client = get_bigquery_client(project_id)
    successful_executions_count = 0

    if not queries_to_run:
        logging.warning("No queries provided for execution.")
        return 0

    for i in range(repeat_count):
        logging.info(f"Starting query execution set #{i+1}/{repeat_count}...")
        
        for query_sql in queries_to_run:  
            logging.debug(f"Trying to execute query: {query_sql[:100]}...")
            try:
                query_job = client.query(query_sql)

                results = query_job.result()
                
                bytes_billed_str = f"{query_job.total_bytes_billed} bytes" if query_job.total_bytes_billed is not None else "No bytes billed"
                logging.info(f"Query executed successfully. Job ID: {query_job.job_id}, Billed Bytes: {bytes_billed_str}")

                current_utc_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
                save_query_event(current_utc_timestamp, log_file_path)
                successful_executions_count += 1

            except google_exceptions.BadRequest as e: # Handles errors like invalid SQL
                logging.error(f"Query syntax error or bad request (BadRequest) for query '{query_sql[:100]}...'. Error: {e}")
            except google_exceptions.Forbidden as e:
                logging.error(f"Permission denied to execute query '{query_sql[:100]}...'. Error: {e}")
            except Exception as e: # Catch any other unexpected errors during query execution
                logging.error(f"Unexpected error while executing query '{query_sql[:100]}...': {e}")
    
    logging.info(f"Total of {successful_executions_count} queries were executed and logged in this session.")
    return successful_executions_count

def get_query_counts_per_day(log_file_path: str, num_days: int = 7) -> tuple[dict[str, int], str]:
   
    daily_counts = defaultdict(int)
    
    today_utc = datetime.datetime.now(datetime.timezone.utc).date()

    for i in range(num_days):
        report_date = today_utc - datetime.timedelta(days=i)
        daily_counts[report_date.isoformat()] = 0

    try:
        with open(log_file_path, "r") as f:
            for line_number, line in enumerate(f, 1):
                try:
                    log_entry = json.loads(line.strip())
                    timestamp_str = log_entry.get("timestamp")
                    if timestamp_str:
                        dt_object = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        log_date = dt_object.date() # Extract only the date part

                        start_date_of_period = today_utc - datetime.timedelta(days=num_days - 1)
                        if start_date_of_period <= log_date <= today_utc:
                             daily_counts[log_date.isoformat()] += 1
                    else:
                        logging.warning(f"Malformed log entry (missing timestamp) in '{log_file_path}', line {line_number}: {line.strip()}")
                except json.JSONDecodeError:
                    logging.warning(f"Error decoding JSON in '{log_file_path}', line {line_number}: {line.strip()}")
                except ValueError as ve: # Handles errors from fromisoformat if timestamp is invalid
                    logging.warning(f"Error processing timestamp in '{log_file_path}', line {line_number}: '{line.strip()}'. Error: {ve}")

    except FileNotFoundError:
        logging.warning(f"Query log file '{log_file_path}' not found. No historical data will be displayed.")
    except IOError as e:
        logging.error(f"Error reading query log file '{log_file_path}': {e}")

    busiest_day_info_str = "No query data found in the specified period."

    if daily_counts and any(count > 0 for count in daily_counts.values()):

        busiest_day_date = max(daily_counts, key=lambda x: daily_counts[x])
        busiest_day_count = daily_counts[busiest_day_date]
        busiest_day_info_str = f"{busiest_day_date} (with {busiest_day_count} queries)"

    sorted_daily_counts = dict(sorted(daily_counts.items()))

    return sorted_daily_counts, busiest_day_info_str

def run_reporter(project_id: str, bq_config: dict):

    queries_to_run = bq_config.get("sample_queries", [])
    repeat_count = bq_config.get("num_runs_per_query_set", 1)
    log_file_path = bq_config.get("query_log_file")

    if not log_file_path:
        logging.error("Path for 'query_log_file' not defined in the BigQuery configuration.")
        return

    logging.info(f"Using query execution log file: {log_file_path}")

    if queries_to_run:
        logging.info(f"Preparing to run {len(queries_to_run)} sample queries, repeated in {repeat_count} set(s).")
        run_bigquery_queries(project_id, queries_to_run, repeat_count, log_file_path)
    else:
        logging.info("No queries configured to run in this session.")

    logging.info("\n--- Query Count Report (Last 7 Days) ---")
    daily_query_counts, busiest_day_summary = get_query_counts_per_day(log_file_path, num_days=7)

    if not daily_query_counts or not any(count > 0 for count in daily_query_counts.values()):
        logging.info("No query executions found in the logs for the past 7-day period.")
    else:
        total_queries_in_period = 0
        for date_iso, count in daily_query_counts.items():
            logging.info(f"  - {date_iso}: {count} queries")
            total_queries_in_period += count
        logging.info(f"Total queries logged in the last 7 days: {total_queries_in_period}")
        logging.info(f"Busiest day in this period: {busiest_day_summary}")
    logging.info("--- End ---")
