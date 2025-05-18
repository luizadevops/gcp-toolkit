import logging
from google.cloud import storage
from google.cloud.iam import Policy as GCP_IAM_Policy
from google.api_core import exceptions as google_exceptions
from gcp_utils.clients import get_storage_client

def list_buckets_and_policies(project_id: str) -> list[dict]:

    client = get_storage_client(project_id)
    bucket_data_list = []
    try:
        all_buckets_from_api = list(client.list_buckets()) # Chama a API UMA VEZ e armazena como lista
        num_buckets_found = len(all_buckets_from_api)
        logging.info(f"Found {num_buckets_found} buckets in project '{project_id}'. Trying to fetch policies...")

        processed_buckets = 0
        for bucket in all_buckets_from_api:
            processed_buckets += 1
            logging.debug(f"Status: Processing bucket {processed_buckets}/{num_buckets_found}: {bucket.name}")
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                bucket_data_list.append({"bucket_name": bucket.name, "policy": policy, "error_getting_policy": None})
            except google_exceptions.Forbidden:
                logging.warning(f"Permission denied to get IAM policy for bucket '{bucket.name}'.")
                bucket_data_list.append({"bucket_name": bucket.name, "policy": None, "error_getting_policy": "Forbidden"})
            except Exception as e:
                logging.error(f"Failed to get IAM policy for bucket '{bucket.name}': {e}", exc_info=True)
                bucket_data_list.append({"bucket_name": bucket.name, "policy": None, "error_getting_policy": str(e)})
        
        successful_policies = sum(1 for b_data in bucket_data_list if b_data["policy"] is not None)
        logging.info(f"Attempted to retrieve IAM policies for {processed_buckets} buckets. Successfully retrieved {successful_policies} policies.")

    except google_exceptions.Forbidden:
        logging.error(f"Permission denied to list buckets in project '{project_id}'.")
        return [] 
    except Exception as e:
        logging.error(f"Failed to list buckets or their policies in project '{project_id}': {e}", exc_info=True)
        return []
    return bucket_data_list

def analyze_iam_policy(bucket_name: str, policy: GCP_IAM_Policy | None,
                         roles_to_flag: list[str], members_to_flag: list[str]) -> list[dict]:
    flagged_items = []

    if not policy:
        logging.debug(f"Policy object is None for bucket '{bucket_name}'. Skipping analysis.")
        return flagged_items

    if not policy.bindings:
        logging.debug(f"No IAM bindings found in the policy for bucket '{bucket_name}'.")
        return flagged_items

    for binding in policy.bindings:
        role = binding.role
        members = binding.members
        condition = binding.condition

        if role in roles_to_flag:
            if members:
                for member_item in members:
                    if member_item in members_to_flag:
                        flagged_items.append({
                            "bucket_name": bucket_name,
                            "role": role,
                            "member": member_item,
                            "condition": condition
                        })
                        condition_str = f" Condition: {str(condition)}" if condition else ""
                        logging.warning(
                            f"FLAGGED: Bucket '{bucket_name}' grants role '{role}' to member '{member_item}'.{condition_str}"
                        )
    return flagged_items

def suggest_remediation_plan(item: dict) -> str:
    """
    Generates a remediation suggestion for a flagged IAM policy finding.
    (Em inglês: Generates a remediation suggestion for a flagged IAM policy finding.)
    """
    bucket_name = item['bucket_name']
    role = item['role']
    member = item['member']
    condition = item['condition']

    suggestion_parts = [ 
        f"SUGGESTED REMEDIATION for Bucket '{bucket_name}':",
        f"  - Issue: The role '{role}' granted to '{member}' is highly permissive and a security risk.",
        f"  - Action: Remove this specific binding from the bucket's IAM policy.",
        "  - Alternatives (Principle of Least Privilege):",
        f"    - Grant '{role}' ONLY to specific, justified users or service accounts.",
        f"    - If public read access for objects is needed for '{member}', consider 'roles/storage.objectViewer'."
    ]
    if condition:
        suggestion_parts.append(
            f"  - Condition Notice: This binding has a condition: {str(condition)}. "
            f"Evaluate if this condition sufficiently mitigates the risk for '{member}'. "
            f"Granting '{role}' to public principals like '{member}' is rarely safe, even with conditions."
        )
    return "\n".join(suggestion_parts)

def run_iam_scanner(project_id: str, iam_config: dict):
    """
    Main orchestrator function for Case 2: IAM Policy Scanner.
    (Em inglês: Main orchestrator function for Case 2: IAM Policy Scanner.)
    """
    roles_to_flag = iam_config.get("roles_to_flag", ["roles/storage.admin"])
    members_to_flag = iam_config.get("members_to_flag", ["allUsers", "allAuthenticatedUsers"])
    buckets_to_ignore = set(iam_config.get("buckets_to_ignore", []))

    logging.info(
        f"Starting IAM policy scan for project '{project_id}'. "
        f"Flagging roles: {roles_to_flag} when granted to members: {members_to_flag}."
    )
    
    # bucket_policy_data_list é uma lista de dicionários como definido em list_buckets_and_policies
    bucket_policy_data_list = list_buckets_and_policies(project_id)
    
    if not bucket_policy_data_list: # Se a lista estiver vazia (nenhum bucket ou erro)
        logging.info("No buckets found or policies could be retrieved in the project. IAM scan will not proceed.")
        return

    total_flagged_findings_count = 0
    buckets_with_flagged_policies_count = 0
    processed_for_scan_count = 0 # Contador para buckets não ignorados

    # Itera sobre a lista de dicionários
    for bucket_data in bucket_policy_data_list:
        bucket_name = bucket_data["bucket_name"]
        policy = bucket_data["policy"] # Pode ser None se houve erro ao buscar
        error_getting_policy = bucket_data["error_getting_policy"] # String de erro ou None

        if bucket_name in buckets_to_ignore:
            logging.info(f"Skipping IAM scan for ignored bucket: '{bucket_name}'.")
            continue
        
        processed_for_scan_count += 1
        # Log de progresso mais claro
        total_to_scan = len(bucket_policy_data_list) - len(buckets_to_ignore)
        logging.info(f"Analyzing IAM policy for bucket: '{bucket_name}' (Bucket {processed_for_scan_count}/{total_to_scan if total_to_scan > 0 else 'N/A'})...")
        
        if error_getting_policy:
            # O erro detalhado já foi logado em list_buckets_and_policies.
            logging.warning(f"Skipping analysis for bucket '{bucket_name}' due to previous error retrieving its policy: {error_getting_policy}")
            continue

        # A função analyze_iam_policy já trata 'policy' sendo None.
        # Mas podemos adicionar um log aqui se 'policy' for None e não houve 'error_getting_policy' (improvável).
        if policy:
            flagged_findings_for_this_bucket = analyze_iam_policy(
                bucket_name, # Passa o nome do bucket
                policy,
                roles_to_flag,
                members_to_flag
            )
            if flagged_findings_for_this_bucket:
                buckets_with_flagged_policies_count +=1 
                for finding in flagged_findings_for_this_bucket:
                    total_flagged_findings_count += 1
                    # analyze_iam_policy já loga o WARNING do achado.
                    remediation_suggestion = suggest_remediation_plan(finding)
                    logging.info(remediation_suggestion) # Loga a sugestão.
        else:
             # Este caso é geralmente coberto pelo 'error_getting_policy', mas é uma segurança extra.
            logging.debug(f"Policy for bucket '{bucket_name}' is None and no specific error was recorded. Skipping analysis.")
            
    logging.info("\n--- IAM Policy Scan Summary ---")
    logging.info(f"Total buckets for which policy retrieval was attempted: {len(bucket_policy_data_list)}")
    logging.info(f"Buckets configured to be ignored: {len(buckets_to_ignore)}")
    logging.info(f"Actual buckets processed for scan (excluding ignored): {processed_for_scan_count}")
    logging.info(f"Buckets found with one or more flagged policies: {buckets_with_flagged_policies_count}")
    logging.info(f"Total individual flagged (role/member/condition) bindings found: {total_flagged_findings_count}")
    logging.info("--- End of IAM Policy Scan Summary ---")