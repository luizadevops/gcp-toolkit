import logging
from typing import Dict, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
from gcp_services_toolkit.firewall_inspector import service as fw_service
from gcp_services_toolkit.iam_scanner import service as iam_service
from gcp_services_toolkit.cost_reporter import service as bq_service


@dataclass
class ToolConfig:
    config_key: str
    tool_name: str


class Tool(ABC):
    @abstractmethod
    def run(self, 
            project_id: str, 
            global_config: Dict[str, Any],
            global_dry_run_flag: bool, 
            global_delete_flag: bool) -> None:
        pass

    @abstractmethod
    def get_tool_config(self) -> ToolConfig:
        pass


class FirewallInspectorTool(Tool):
    def get_tool_config(self) -> ToolConfig:
        return ToolConfig(
            config_key="firewall_inspector",
            tool_name="Firewall Rule Inspector & Cleaner"
        )

    def run(self, project_id: str, global_config: Dict[str, Any],
            global_dry_run_flag: bool, global_delete_flag: bool) -> None:
        tool_config = self.get_tool_config()
        logging.debug(f"Initializing {tool_config.tool_name} with global_dry_run={global_dry_run_flag}, global_delete={global_delete_flag}")
        
        case_specific_config = global_config.get(tool_config.config_key, {})
        if not case_specific_config:
             logging.warning(f"{tool_config.tool_name}: No specific configuration section '{tool_config.config_key}' found in config.json. "
                             "Tool may use defaults or its logic might be limited.")
        
        fw_service.run_firewall_inspector(
            project_id=project_id,
            fw_config_params=case_specific_config,
            attempt_deletion=global_delete_flag, 
            is_global_dry_run=global_dry_run_flag
        )


class IAMScannerTool(Tool):
    def get_tool_config(self) -> ToolConfig:
        return ToolConfig(
            config_key="iam_scanner",
            tool_name="IAM Policy Scanner"
        )

    def run(self, project_id: str, global_config: Dict[str, Any],
            global_dry_run_flag: bool, global_delete_flag: bool) -> None:
        tool_config = self.get_tool_config()
        logging.debug(f"Initializing {tool_config.tool_name} with global_dry_run={global_dry_run_flag} (not directly used), global_delete={global_delete_flag} (not used).")
        
        case_specific_config = global_config.get(tool_config.config_key, {})
        if not case_specific_config:
             logging.warning(f"{tool_config.tool_name}: No specific configuration section '{tool_config.config_key}' found in config.json. "
                             "Tool may use default flagging criteria or its logic might be limited.")

        iam_service.run_iam_scanner(project_id, case_specific_config,
                                    delete_flag=global_delete_flag,
                                    dry_run_flag=global_dry_run_flag)


class QueryCountReporterTool(Tool):
    def get_tool_config(self) -> ToolConfig:
        return ToolConfig(
            config_key="bigquery_cost_reporter",
            tool_name="BigQuery Cost Reporter"
        )

    def run(self, project_id: str, global_config: Dict[str, Any],
            global_dry_run_flag: bool, global_delete_flag: bool) -> None:
        tool_config = self.get_tool_config()
        logging.debug(f"Initializing {tool_config.tool_name} with global_dry_run={global_dry_run_flag} (not used), global_delete={global_delete_flag} (not used).")

        case_specific_config = global_config.get(tool_config.config_key) 
                                                                        
        if case_specific_config:
            bq_service.run_reporter(project_id, case_specific_config,
                                    delete_flag=global_delete_flag,
                                    dry_run_flag=global_dry_run_flag)
        else:
            logging.warning(f"{tool_config.tool_name}: Configuration section '{tool_config.config_key}' "
                            "not found in config.json. Skipping this tool.")


class ToolManager:
    def __init__(self):
        self.tools: Dict[str, Tool] = {}

    def register_tool(self, identifier: str, tool_instance: Tool) -> None:

        if identifier in self.tools:

            logging.warning(f"Tool with identifier '{identifier}' is already registered. Overwriting previous instance.")
        self.tools[identifier] = tool_instance
        logging.debug(f"Tool '{tool_instance.get_tool_config().tool_name}' registered with identifier '{identifier}'.")



    def run_all_registered_tools(self, project_id: str, global_config: Dict[str, Any],
                                 global_dry_run_flag: bool, global_delete_flag: bool) -> None:
        if not self.tools:
            logging.warning("No tools are registered in ToolManager. Nothing to execute.")
            return

        logging.info("Attempting to execute all registered tools...")
        executed_tool_count = 0
        for tool_identifier, tool_instance in self.tools.items():
            tool_name = tool_instance.get_tool_config().tool_name
            
            logging.info(f"==============================================================================================")
            logging.info(f"================================= EXECUTING: {tool_name} =====================================")
            logging.info(f"==============================================================================================")
            try:
                tool_instance.run(
                    project_id,
                    global_config,
                    global_dry_run_flag=global_dry_run_flag,
                    global_delete_flag=global_delete_flag
                )
                executed_tool_count += 1
            except Exception as e_tool:
                logging.error(f"CRITICAL ERROR during execution of {tool_name}: {e_tool}", exc_info=True)
            logging.info(f"========== {tool_name} FINISHED ==========")
        
        if executed_tool_count == 0 and self.tools:
            logging.info("All registered tools were processed, but none may have performed actions or some were skipped due to configuration.")
        elif not self.tools:
            logging.info("No tools were available to run.")