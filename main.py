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
        description="Coolblue GCP Cloud Engineer Challenge Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the configuration JSON file (e.g., ./config.json)."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG level) logging."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions that would make changes, without actually making them. \n"
             "This applies to actions like deleting firewall rules (Case 1)."
    )

    # Case-specific execution flags
    parser.add_argument("--run-case1", action="store_true", help="Run Case 1: Firewall Rule Inspector & Cleaner.")
    parser.add_argument("--run-case2", action="store_true", help="Run Case 2: IAM Policy Scanner.")
    parser.add_argument("--run-case3", action="store_true", help="Run Case 3: GCP Query Count Reporter.")

    # Case 1 specific arguments
    parser.add_argument(
        "--delete",
        action="store_true",
        help="CASE 1 ONLY: Enable deletion of flagged firewall rules. \n"
             "Requires confirmation if --dry-run is not also specified."
    )

    args = parser.parse_args()

    # --- Setup Logging and Configuration ---
    common_utils.setup_logging(verbose=args.verbose)
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

    # Determine if any specific case was requested, or run all
    run_all_selected = not (args.run_case1 or args.run_case2 or args.run_case3)
    if run_all_selected:
        logging.info("No specific case selected to run; will attempt to run all cases.")

    # --- Case 1: Firewall Rule Inspector & Cleaner ---
    if run_all_selected or args.run_case1:
        logging.info("\n===== EXECUTING CASE 1: Firewall Rule Inspector & Cleaner =====")
        
        case1_delete_active = args.delete
        case1_dry_run_mode = args.dry_run

        if case1_delete_active and not args.dry_run:
            logging.warning("CASE 1: --delete flag is active WITHOUT --dry-run. Attempting REAL firewall deletions.")
            try:
                confirm = input("Are you ABSOLUTELY SURE you want to proceed with REAL firewall deletions? (yes/no): ")
                if confirm.lower() == 'yes':
                    logging.info("CASE 1: User confirmed real deletions.")
                    case1_dry_run_mode = False
                else:
                    logging.info("CASE 1: User CANCELLED real deletions. No firewall rules will be deleted.")
                    case1_delete_active = False
            except EOFError:
                logging.error("CASE 1: --delete flag used in a non-interactive environment without --dry-run. "
                              "This is unsafe. Aborting Case 1 deletions. Run with --dry-run or interactively.")
                case1_delete_active = False
        elif case1_delete_active and args.dry_run:
            logging.info("CASE 1: --delete specified with --dry-run. Firewall deletions will be SIMULATED.")
            case1_dry_run_mode = True

        fw_config_params = config.get("firewall_inspector", {})
        if not fw_config_params and (run_all_selected or args.run_case1):
             logging.warning("CASE 1: No 'firewall_inspector' configuration found. Defaults will be used for flagging.")

        # Call the orchestrator function for Case 1 using the new alias
        fw_service.run_firewall_inspector(project_id, fw_config_params, 
                                          delete_flag_active=case1_delete_active, 
                                          dry_run_mode=case1_dry_run_mode)
        logging.info("===== CASE 1 FINISHED =====")


    # --- Case 2: IAM Policy Scanner ---
    if run_all_selected or args.run_case2:
        logging.info("\n===== EXECUTING CASE 2: IAM Policy Scanner =====")
        iam_config_params = config.get("iam_scanner", {})
        if not iam_config_params and (run_all_selected or args.run_case2):
            logging.warning("CASE 2: No 'iam_scanner' configuration found. Using default flagging criteria.")
        
        # Call the orchestrator function for Case 2 using the new alias
        iam_service.run_iam_scanner(project_id, iam_config_params)
        logging.info("===== CASE 2 FINISHED =====")


    # --- Case 3: GCP Query Count Reporter ---
    if run_all_selected or args.run_case3:
        logging.info("\n===== EXECUTING CASE 3: GCP Query Count Reporter =====")
        bq_config_params = config.get("bigquery")
        if bq_config_params:
            # Call the orchestrator function for Case 3 using the new alias
            bq_service.run_reporter(project_id, bq_config_params)
        else:
            logging.warning("CASE 3: Configuration section 'bigquery' not found in config.json. Skipping.")
        logging.info("===== CASE 3 FINISHED =====")

    # Check if no cases were actually selected to run
    # This condition helps if flags like --run-case1 are present but set to False by default,
    # and run_all_selected is False because at least one --run-caseX flag exists in args namespace.
    cases_were_run_flags = args.run_case1 or args.run_case2 or args.run_case3
    if not run_all_selected and not cases_were_run_flags:
        logging.info("No specific case was selected to run via --run-caseX flags. To run all cases, omit these flags.")


    logging.info("\n===== All selected script tasks finished. =====")

if __name__ == "__main__":
    main()