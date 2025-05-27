import logging
from typing import Sequence, Tuple, List, Dict
from google.cloud import compute_v1
from google.api_core import exceptions as google_exceptions
from google.cloud.compute_v1.types import Firewall
from gcp_utils.clients import get_firewalls_client


def check_ports_match(rule_ports: Sequence[str], config_ports: List[str]) -> bool:
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
        logging.warning(f"Invalid port format encountered. rule_ports={rule_ports}, config_ports={config_ports}. Treating as no match.")
        return False

def list_firewall_rules(project_id: str) -> List[Firewall]:
    client = get_firewalls_client()
    firewalls_list: List[Firewall] = []
    try:
        request = compute_v1.ListFirewallsRequest(project=project_id)
        for firewall_item in client.list(request=request):
            firewalls_list.append(firewall_item)
        logging.info(f"Firewall Inspector: Listed {len(firewalls_list)} firewall rules for project '{project_id}'.")
    except google_exceptions.Forbidden:
        logging.error(f"Firewall Inspector: Permission denied to list firewall rules in project '{project_id}'. Requires 'compute.firewalls.list'.")
    except google_exceptions.NotFound:
        logging.error(f"Firewall Inspector: Project '{project_id}' not found or Compute Engine API not enabled.")
    except Exception as e:
        logging.error(f"Firewall Inspector: Failed to list firewall rules for project '{project_id}': {e}", exc_info=True)
    return firewalls_list

def is_rule_overly_permissive(rule: Firewall, fw_config_params: Dict) -> Tuple[bool, str]:
    source_ip_alert = fw_config_params.get("source_ip_alert", "0.0.0.0/0")
    flag_ingress_only = fw_config_params.get("flag_ingress_only", True)
    permissive_criteria = fw_config_params.get("permissive_rules_details", [])
    target_tags_to_ignore = set(fw_config_params.get("target_tags_to_ignore", []))
    target_sas_to_ignore = set(fw_config_params.get("target_service_accounts_to_ignore", []))

    if flag_ingress_only and rule.direction != Firewall.Direction.INGRESS.name:
        return False, ""

    if source_ip_alert not in rule.source_ranges:
        return False, ""

    if target_tags_to_ignore and set(rule.target_tags).intersection(target_tags_to_ignore):
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' (source: '{source_ip_alert}') skipped: matches ignored target_tags: {list(rule.target_tags)}")
        return False, ""
    
    if target_sas_to_ignore and set(rule.target_service_accounts).intersection(target_sas_to_ignore):
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' (source: '{source_ip_alert}') skipped: matches ignored target_service_accounts: {list(rule.target_service_accounts)}")
        return False, ""

    if not rule.allowed:
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' has source '{source_ip_alert}' but no 'allowed' protocols/ports. Effectively blocks all.")
        return False, ""

    for allowed_item in rule.allowed:
        protocol = allowed_item.I_p_protocol.lower()
        rule_ports = allowed_item.ports

        matching_criteria_from_config = [
            (criterion_dict, criterion_dict.get("ports", []))
            for criterion_dict in permissive_criteria
            if protocol == criterion_dict.get("protocol", "").lower() or \
               criterion_dict.get("protocol", "").lower() == "any"
        ]

        for criterion_dict, config_ports_for_criterion in matching_criteria_from_config:
            if not config_ports_for_criterion:
                return True, f"Allows {protocol.upper()} on ALL ports (as per empty 'ports' in config for protocol '{criterion_dict.get('protocol')}') from '{source_ip_alert}'."
            if check_ports_match(rule_ports, config_ports_for_criterion):
                return True, (f"Allows {protocol.upper()} on ports ({rule_ports if rule_ports else 'ALL'}) "
                              f"from '{source_ip_alert}' which match configured permissive ports "
                              f"'{config_ports_for_criterion}' for criterion protocol '{criterion_dict.get('protocol')}'.")
    return False, ""

def delete_firewall_rule(project_id: str, rule_name: str, dry_run: bool = True) -> bool:
    client = get_firewalls_client()

    if dry_run:
        logging.info(f"Firewall Inspector - [DRY-RUN]: Would delete firewall rule '{rule_name}' in project '{project_id}'.")
        return True

    logging.info(f"Firewall Inspector: Attempting to delete rule '{rule_name}' in project '{project_id}'.")
    try:
        operation = client.delete(project=project_id, firewall=rule_name)
        logging.info(f"Firewall Inspector: Delete operation for rule '{rule_name}' in project '{project_id}' initiated. Operation ID: {operation.name}")
        return True
    except google_exceptions.NotFound:
        logging.warning(f"Firewall Inspector: Rule '{rule_name}' not found in project '{project_id}'. Might be already deleted.")
        return False
    except google_exceptions.Forbidden:
        logging.error(f"Firewall Inspector: Permission denied to delete rule '{rule_name}' in project '{project_id}'. Requires 'compute.firewalls.delete'.")
        return False
    except Exception as e:
        logging.error(f"Firewall Inspector: Unexpected error deleting rule '{rule_name}' in project '{project_id}': {e}", exc_info=True)
        return False

def run_firewall_inspector(project_id: str, fw_config_params: Dict,
                           attempt_deletion: bool, is_global_dry_run: bool):
    tool_name = "Firewall Inspector"
    logging.info(f"Starting {tool_name} for project '{project_id}'.")
    logging.debug(f"{tool_name}: Received attempt_deletion={attempt_deletion}, is_global_dry_run={is_global_dry_run}")

    effective_dry_run_for_delete_action = is_global_dry_run
    proceed_with_delete_actions = attempt_deletion

    if attempt_deletion and not is_global_dry_run:
        logging.warning(f"{tool_name}: --delete flag is active and global --dry-run is OFF. REAL deletions will be attempted IF USER CONFIRMS.")
        try:
            confirm = input(f"{tool_name}: Are you ABSOLUTELY SURE you want to proceed with REAL firewall deletions? (yes/no): ")
            if confirm.lower() == 'yes':
                logging.info(f"{tool_name}: User confirmed real deletions.")
                effective_dry_run_for_delete_action = False
            else:
                logging.info(f"{tool_name}: User CANCELLED real deletions. No rules will be deleted by this tool.")
                proceed_with_delete_actions = False
        except EOFError:
            logging.error(f"{tool_name}: --delete flag used in a non-interactive environment without global --dry-run. REAL DELETIONS ABORTED.")
            proceed_with_delete_actions = False
    elif attempt_deletion and is_global_dry_run:
        logging.info(f"{tool_name}: --delete flag active, but global --dry-run is also active. Deletions will be SIMULATED.")
        effective_dry_run_for_delete_action = True

    all_firewalls = list_firewall_rules(project_id)
    flagged_rules_count = 0
    actions_taken_on_rules = 0

    if all_firewalls is not None:
        if len(all_firewalls) > 0 :
             logging.info(f"{tool_name}: Analyzing {len(all_firewalls)} firewall rules...")
        else:
             logging.info(f"{tool_name}: No firewall rules found to analyze in project '{project_id}'.")

        for rule in all_firewalls:
            if rule.disabled:
                logging.debug(f"{tool_name}: Rule '{rule.name}' is disabled, skipping.")
                continue

            is_permissive, reason = is_rule_overly_permissive(rule, fw_config_params)
            
            if is_permissive:
                flagged_rules_count += 1
                logging.warning(
                    f"{tool_name} - FLAGGED: Rule '{rule.name}' (Priority: {rule.priority}, "
                    f"Network: {rule.network.split('/')[-1]}). Reason: {reason}"
                )

                if proceed_with_delete_actions:
                    delete_action_was_successful = delete_firewall_rule(
                        project_id,
                        rule.name,
                        dry_run=effective_dry_run_for_delete_action
                    )
                    if delete_action_was_successful:
                        actions_taken_on_rules += 1
        
        logging.info(f"{tool_name}: Analysis complete. {flagged_rules_count} rule(s) flagged.")
        if proceed_with_delete_actions:
            action_verb = "simulated" if effective_dry_run_for_delete_action else "initiated"
            logging.info(f"{tool_name}: {actions_taken_on_rules} flagged rule(s) had deletion {action_verb}.")
    elif all_firewalls is None: 
         logging.error(f"{tool_name}: Could not retrieve firewall rules from project '{project_id}'.")
