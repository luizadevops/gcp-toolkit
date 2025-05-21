import logging
from typing import List, Dict, Optional
from google.cloud import storage
from google.cloud.iam import Policy as GCP_IAM_Policy
from google.api_core import exceptions as google_exceptions
from gcp_utils.clients import get_storage_client

def tool_name():
    return "IAM Policy Scanner"

def list_buckets_and_policies(project_id: str) -> List[Dict]:
    storage_client = get_storage_client(project_id=project_id)
    bucket_data_list: List[Dict] = []
    
    try:
        all_buckets_from_api = list(storage_client.list_buckets())
        logging.info(f"{tool_name()}: Found {len(all_buckets_from_api)} buckets in project '{project_id}'.")

        for bucket in all_buckets_from_api:
            policy = None
            error_message = None
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
            except (google_exceptions.Forbidden, google_exceptions.NotFound) as e:
                error_message = str(e)
                logging.warning(f"{tool_name()} - Access error for bucket '{bucket.name}': {error_message}")
            except Exception as e:
                error_message = str(e)
                logging.error(f"{tool_name()} - Error retrieving policy for bucket '{bucket.name}': {e}")
            
            bucket_data_list.append({
                "bucket_name": bucket.name,
                "policy": policy,
                "error_getting_policy": error_message
            })
        
        successful_policies_count = sum(1 for b_data in bucket_data_list if b_data["policy"] is not None)
        logging.debug(f"{tool_name()}: Attempted policy retrieval for {len(all_buckets_from_api)} buckets. Successful: {successful_policies_count}.")

    except google_exceptions.Forbidden:
        logging.error(f"{tool_name()}: Permission denied to list buckets in project '{project_id}'.")
        return [] 
    except Exception as e:
        logging.error(f"{tool_name()}: Error listing buckets in project '{project_id}': {e}", exc_info=True)
        return []
    return bucket_data_list

def analyze_iam_policy(
    bucket_name: str, 
    policy: Optional[GCP_IAM_Policy], 
    roles_to_flag: List[str], 
    members_to_flag: List[str]
) -> List[Dict]:
    
    flagged_findings: List[Dict] = []
    if not policy or not policy.bindings:
        return flagged_findings

    for binding in policy.bindings:
        role = binding.get('role')
        members_data = binding.get('members', []) 
        condition = binding.get('condition')
        
        members = set()
        if isinstance(members_data, (list, set, tuple)):
            members = set(members_data)
        elif members_data is not None:
             logging.debug(f"{tool_name()}: Unexpected type for 'members' in binding for bucket '{bucket_name}': {type(members_data)}")

        if role and role in roles_to_flag:
            if members:
                for member_item in members:
                    if member_item in members_to_flag:
                        finding = {
                            "bucket_name": bucket_name, 
                            "role": role, 
                            "member": member_item, 
                            "condition": condition
                        }
                        flagged_findings.append(finding)
                        condition_str = f" (Condition: {str(condition)})" if condition else ""
                        logging.warning(f"{tool_name()} - ATTENTION: Bucket '{bucket_name}' grants role '{role}' to member '{member_item}'.{condition_str}")
    return flagged_findings

def suggest_remediation_plan(finding: Dict) -> str:
    bucket_name = finding["bucket_name"]
    role = finding["role"]
    member = finding["member"]
    condition = finding["condition"]

    remediation_text = (
        f"{tool_name()} - REMEDIATION for Bucket '{bucket_name}': Remove role '{role}' for member '{member}'. Apply principle of least privilege.")
    if condition:
        remediation_text += f" Note: Binding has a condition: {str(condition)}. Evaluate its impact."
    return remediation_text

def run_iam_scanner(project_id: str, iam_config: Dict, 
                    delete_flag: bool, dry_run_flag: bool):
    
    logging.info(f"{tool_name()}: Starting for project '{project_id}'.")
    logging.debug(f"{tool_name()}: Received delete_flag={delete_flag} (not used), dry_run_flag={dry_run_flag} (not used).")
    
    roles_to_flag = iam_config.get("roles_to_flag", ["roles/storage.admin"])
    members_to_flag = iam_config.get("members_to_flag", ["allUsers", "allAuthenticatedUsers"])
    buckets_to_ignore = set(iam_config.get("buckets_to_ignore", []))
    
    roles_description = " or ".join(f"'{r}'" for r in roles_to_flag) if roles_to_flag else "any configured sensitive roles"
    roles_prefix = "role" if len(roles_to_flag) == 1 else "roles"
    members_description = " or ".join(f"'{m}'" for m in members_to_flag) if members_to_flag else "any configured sensitive members"
    logging.info(f"{tool_name()}: Scanning for {roles_prefix} {roles_description} when granted to {members_description}.")
    
    bucket_policy_data_list = list_buckets_and_policies(project_id)
    
    if not bucket_policy_data_list:
        logging.info(f"{tool_name()}: No buckets found or policies could be retrieved. Scan finished.")
        return

    total_flagged_findings = 0
    buckets_with_flags = 0
    
    eligible_buckets = [b for b in bucket_policy_data_list if b.get("bucket_name") not in buckets_to_ignore]
    
    processed_for_scan_count = 0
    total_eligible_to_scan = len(eligible_buckets)

    for bucket_data in eligible_buckets:
        bucket_name = bucket_data.get("bucket_name")
        policy = bucket_data.get("policy")
        error_getting_policy = bucket_data.get("error_getting_policy")

        if not bucket_name:
            logging.debug(f"{tool_name()}: Skipping bucket_data item with no name: {bucket_data}")
            continue
            
        processed_for_scan_count += 1
        logging.debug(f"{tool_name()}: Analyzing bucket: '{bucket_name}' ({processed_for_scan_count}/{total_eligible_to_scan})...")
        
        if error_getting_policy:
            logging.warning(f"{tool_name()}: Skipping analysis for bucket '{bucket_name}' due to previous error retrieving its policy: '{error_getting_policy}'.")
            continue

        findings = analyze_iam_policy(
            bucket_name,
            policy,
            roles_to_flag,
            members_to_flag
        )
        if findings:
            buckets_with_flags += 1
            total_flagged_findings += len(findings)
            for finding in findings:
                logging.warning(suggest_remediation_plan(finding))
            
    logging.info(f"{tool_name()} - Total buckets processed: {len(bucket_policy_data_list)}")
    logging.info(f"{tool_name()} - Buckets configured to be ignored: {len(buckets_to_ignore)}")
    logging.info(f"{tool_name()} - Actual buckets analyzed for IAM policies: {processed_for_scan_count}")
    logging.info(f"{tool_name()} - Buckets found with flagged policies: {buckets_with_flags}")
    logging.info(f"{tool_name()} - Total individual flagged bindings found: {total_flagged_findings}")