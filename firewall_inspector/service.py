import logging
from google.cloud import compute_v1
from google.api_core import exceptions as google_exceptions
from google.cloud.compute_v1.types import Firewall
from gcp_utils.clients import get_firewalls_client
from typing import Sequence

def check_ports_match(rule_ports: Sequence[str], config_ports: list[str]) -> bool:

    if not rule_ports or "1-65535" in config_ports:
        return True

    def parse_port_range(port_str: str) -> range:
        if '-' in port_str:
            start, end = map(int, port_str.split('-'))
            return range(start, end + 1)
        return range(int(port_str), int(port_str) + 1)

    try:
        rule_ranges = [parse_port_range(p) for p in rule_ports]
        config_ranges = [parse_port_range(p) for p in config_ports]

        for r_range in rule_ranges:
            for c_range in config_ranges:
                if any(port in c_range for port in r_range):
                    return True
        return False
    except ValueError:
        logging.warning(f"Invalid port format in rule_ports={rule_ports} or config_ports={config_ports}.")
        return False

def list_firewall_rules(project_id: str) -> list[Firewall]:

    client = get_firewalls_client()
    firewalls_list: list[Firewall] = []
    try:
        request = compute_v1.ListFirewallsRequest(project=project_id)
        for firewall_item in client.list(request=request):
            firewalls_list.append(firewall_item)
        logging.info(f"Successfully listed {len(firewalls_list)} firewall rules for project '{project_id}'.")
    except google_exceptions.Forbidden:
        logging.error(f"Permission denied in project '{project_id}'. Ensure the account has 'compute.firewalls.list' permission.")
    except google_exceptions.NotFound:
        logging.error(f"Project '{project_id}' not found or Compute Engine API not enabled.")
    except Exception as e:
        logging.error(f"Failed to list firewall rules for project '{project_id}': {e}", exc_info=True)
    return firewalls_list

def is_rule_overly_permissive(rule: Firewall, fw_config: dict) -> tuple[bool, str]:

    source_ip_alert = fw_config.get("source_ip_alert", "0.0.0.0/0")
    flag_ingress_only = fw_config.get("flag_ingress_only", True)
    permissive_criteria = fw_config.get("permissive_rules_details", [])
    target_tags_to_ignore = set(fw_config.get("target_tags_to_ignore", []))
    target_sas_to_ignore = set(fw_config.get("target_service_accounts_to_ignore", []))

    if flag_ingress_only and rule.direction != Firewall.Direction.INGRESS:
        return False, ""

    if source_ip_alert not in rule.source_ranges:
        return False, ""

    if target_tags_to_ignore and set(rule.target_tags).intersection(target_tags_to_ignore):
        logging.debug(f"Rule '{rule.name}' from '{source_ip_alert}' skipped due to matching ignored target_tags: {rule.target_tags}")
        return False, ""

    if not rule.allowed:
        logging.debug(f"Rule '{rule.name}' has source '{source_ip_alert}' but no 'allowed' protocols/ports defined. This is unusual and effectively blocks traffic for this rule.")
        return False, ""

    for allowed_item in rule.allowed:
        protocol = allowed_item.i_p_protocol.lower()
        rule_ports = allowed_item.ports

        matching_criteria_configs = [
            (crit_config, crit_config.get("ports", []))
            for crit_config in permissive_criteria
            if protocol == crit_config.get("protocol", "").lower() or crit_config.get("protocol", "").lower() == "any"
        ]

        for criterion_config, crit_ports in matching_criteria_configs:
            if not crit_ports:
                return True, f"Allows {protocol.upper()} on all ports from '{source_ip_alert}' as per configuration criterion: {criterion_config.get('protocol')}."
            if check_ports_match(rule_ports, crit_ports):
                return True, f"Allows {protocol.upper()} on ports ({rule_ports if rule_ports else 'ALL'}) from '{source_ip_alert}' which match configured sensitive ports '{crit_ports}' for protocol '{criterion_config.get('protocol')}'."

    return False, ""

def delete_firewall_rule(project_id: str, rule_name: str, dry_run: bool = True) -> bool:

    client = get_firewalls_client()

    if dry_run:
        logging.info(f"[DRY-RUN] Would delete firewall rule: '{rule_name}' in project '{project_id}'.")
        return True

    logging.info(f"Attempting to delete firewall rule: '{rule_name}' in project '{project_id}'.")
    try:
        operation = client.delete(project=project_id, firewall=rule_name)

        logging.info(f"Delete operation for firewall rule '{rule_name}' in project '{project_id}' initiated. Operation: {operation.name}")
        return True
    except google_exceptions.NotFound:

        logging.warning(f"Firewall rule '{rule_name}' not found in project '{project_id}'. It might have been already deleted.")
        return False
    except google_exceptions.Forbidden:

        logging.error(f"Permission denied to delete firewall rule '{rule_name}' in project '{project_id}'. Ensure 'compute.firewalls.delete' permission.")
        return False
    except Exception as e:

        logging.error(f"An unexpected error occurred while attempting to delete firewall rule '{rule_name}' in project '{project_id}': {e}", exc_info=True) # Adicionado exc_info
        return False
    
def run_firewall_inspector(project_id: str, fw_config_params: dict, delete_flag_active: bool, dry_run_mode: bool):
    """
    Main orchestrator for Case 1: Firewall Rule Inspector & Cleaner.
    """
    logging.info(f"Starting Firewall Rule Inspector for project '{project_id}'.")
    
    all_firewalls = list_firewall_rules(project_id)
    flagged_rules_count = 0
    actions_taken_on_rules = 0

    if all_firewalls:
        logging.info(f"Found {len(all_firewalls)} firewall rules. Analyzing...")
        for rule in all_firewalls:
            if rule.disabled:
                logging.debug(f"Rule '{rule.name}' is disabled, skipping detailed checks.")
                continue

            is_permissive, reason = is_rule_overly_permissive(rule, fw_config_params)
            
            if is_permissive:
                flagged_rules_count += 1
                logging.warning(
                    f"FLAGGED: Rule '{rule.name}' (Priority: {rule.priority}, "
                    f"Network: {rule.network.split('/')[-1]}). Reason: {reason}"
                )
                # logging.debug(f"Rule details for '{rule.name}': {rule}") # Uncomment for very verbose output

                if delete_flag_active:
                    delete_action_taken = delete_firewall_rule(
                        project_id,
                        rule.name,
                        dry_run=dry_run_mode
                    )
                    if delete_action_taken:
                        actions_taken_on_rules += 1
        
        logging.info(f"Firewall analysis complete. {flagged_rules_count} rule(s) flagged.")
        if delete_flag_active:
            action_verb = "simulated" if dry_run_mode else "initiated"
            logging.info(f"{actions_taken_on_rules} flagged rule(s) had deletion {action_verb}.")
    elif all_firewalls is None:
         logging.error("Could not retrieve firewall rules (list_firewall_rules might have returned None or an error occurred).")
    else: # Empty list
        logging.info("No firewall rules found in the project.")