import argparse
import logging
import sys
import json 
from gcp_utils import utils as common_utils
from gcp_services_toolkit.toolkit import ToolManager, FirewallInspectorTool, IAMScannerTool, QueryCountReporterTool #dont need it

def main():
    parser = argparse.ArgumentParser(
        description="GCP Services Toolkit",
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
        help="Simulate actions that would make changes, without actually making them. "
             "Applies to supported tools (e.g., Firewall Inspector deletions)."
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Enable deletion for supported tools (e.g., Firewall Inspector). "
             "The specific tool (e.g. Firewall Inspector) will handle confirmation if not in dry-run mode."
    )

    args = parser.parse_args()
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

    logging.info(f"========= GCP Services Toolkit starting for Project ID: {project_id} =========")
    if args.dry_run:
        logging.info("Global DRY-RUN mode is ACTIVE. Destructive operations will be simulated by applicable tools.")
    else:
        logging.info("Global DRY-RUN mode is NOT ACTIVE. Destructive operations may occur if confirmed.")

    tool_manager = ToolManager()    
    tool_manager.register_tool("firewall-inspector", FirewallInspectorTool())
    tool_manager.register_tool("iam-scanner", IAMScannerTool())
    tool_manager.register_tool("query-reporter", QueryCountReporterTool())
    
    tool_manager.run_all_registered_tools(
        project_id, 
        config,
        global_dry_run_flag=args.dry_run, 
        global_delete_flag=args.delete\
    )
    logging.info("===== GCP Services Toolkit finished all tasks. =====")

if __name__ == "__main__":
    main()
