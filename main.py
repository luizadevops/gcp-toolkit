import argparse
import logging
import sys
import json

from gcp_utils import utils as common_utils
from firewall_inspector import service as fw_service 
from iam_scanner import service as iam_service
from cost_reporter import service as bq_service

def main():
    parser = argparse.ArgumentParser(
        description="GCP Automation Services Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the configuration JSON file (e.g., ./config.json)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions that would make changes, without actually making them. \n"
             "This applies to actions like deleting firewall rules (Firewall Rule Inspector & Cleaner)."
    )

    parser.add_argument("--run-fw-rule-cleaner", action="store_true", help="Run Firewall Rule Inspector & Cleaner.")
    parser.add_argument("--run-iam-policy-scan", action="store_true", help="Run IAM Policy Scanner.")
    parser.add_argument("--run-query-count-report", action="store_true", help="Run GCP Query Count Reporter.")

    # Firewall Rule Inspector & Cleaner specific arguments
    parser.add_argument(
        "--delete",
        action="store_true",
        help="FOR Firewall Rule Inspector & Cleaner ONLY: Enable deletion of flagged firewall rules. \n"
             "Requires confirmation if --dry-run is not also specified."
    )

    args = parser.parse_args()

    # --- Setup Logging and Configuration ---
    common_utils.setup_logging()
    try:
        config = common_utils.load_config(args.config)
    except FileNotFoundError:
        logging.critical(f"CRITICAL: Configuration file not found at {args.config}. Exiting.")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.critical(f"CRITICAL: Could not decode JSON from {args.config}. Please check its format. Exiting.")
        sys.exit(1)

    project_id = config.get("project_id")
    if not project_id:
        logging.critical("CRITICAL: 'project_id' not found in the configuration file. Exiting.")
        sys.exit(1)

    logging.info(f"Script starting for GCP Project ID: {project_id}")
    if args.dry_run:
        logging.info("Global DRY-RUN mode enabled. Destructive operations will be simulated.")

    # --- Firewall Rule Inspector & Cleaner ---
    if args.run_fw_rule_cleaner:
        logging.info("\n===== EXECUTING Firewall Rule Inspector & Cleaner =====")
        
        run_fw_rule_cleaner_delete_active = args.delete
        run_fw_rule_cleaner_dry_run_mode = args.dry_run

        if run_fw_rule_cleaner_delete_active and not args.dry_run:
            logging.warning("--delete flag is active WITHOUT --dry-run. Attempting REAL firewall deletions.")
            try:
                confirm = input("Are you ABSOLUTELY SURE you want to proceed with REAL firewall deletions? (yes/no): ")
                if confirm.lower() == 'yes':
                    logging.info("User confirmed real deletions.")
                    run_fw_rule_cleaner_dry_run_mode = False
                else:
                    logging.info("User CANCELLED real deletions. No firewall rules will be deleted.")
                    run_fw_rule_cleaner_delete_active = False
            except EOFError:
                logging.error("--delete flag used in a non-interactive environment without --dry-run. "
                              "This is unsafe. Aborting firewall deletions. Run with --dry-run or interactively.")
                run_fw_rule_cleaner_delete_active = False
        elif run_fw_rule_cleaner_delete_active and args.dry_run:
            logging.info("--delete specified with --dry-run. Firewall deletions will be SIMULATED.")
            run_fw_rule_cleaner_dry_run_mode = True

        fw_config_params = config.get("firewall_inspector", {})
        if not fw_config_params and (args.run_run_fw_rule_cleaner):
             logging.warning("No 'firewall_inspector' configuration found. Defaults will be used for flagging.")

        fw_service.run_firewall_inspector(project_id, fw_config_params, 
                                          delete_flag_active=run_fw_rule_cleaner_delete_active, 
                                          dry_run_mode=run_fw_rule_cleaner_dry_run_mode)
        logging.info("===== Firewall Rule Inspector & Cleaner FINISHED =====")

    # --- IAM Policy Scanner ---
    if args.run_run_iam_policy_scan:
        logging.info("\n===== EXECUTING IAM Policy Scanner: IAM Policy Scanner =====")
        iam_config_params = config.get("iam_scanner", {})
        if not iam_config_params and (args.run_run_iam_policy_scan):
            logging.warning("No 'iam_scanner' configuration found. Using default flagging criteria.")
        
        iam_service.run_iam_scanner(project_id, iam_config_params)
        logging.info("===== IAM Policy Scanner FINISHED =====")

    # --- GCP Query Count Reporter ---
    if args.run_run_query_count_report:
        logging.info("\n===== EXECUTING GCP Query Count Reporter =====")
        bq_config_params = config.get("bigquery")
        if bq_config_params:

            bq_service.run_reporter(project_id, bq_config_params)
        else:
            logging.warning("Configuration section 'bigquery' not found in config.json. Skipping.")
        logging.info("===== GCP Query Count Reporter FINISHED =====")

if __name__ == "__main__":
    main()