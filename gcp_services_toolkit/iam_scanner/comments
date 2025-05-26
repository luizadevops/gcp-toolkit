# iam_scanner/service.py
# (Em português: Módulo de serviço para o Scanner de Políticas IAM - Caso 2)

# Importa o módulo de logging para registrar informações, avisos e erros.
import logging
# Importa tipos do módulo 'typing' para anotações de tipo, melhorando a legibilidade
# e ajudando na análise estática do código.
from typing import List, Dict, Optional

# Importa a biblioteca cliente do Google Cloud Storage.
from google.cloud import storage
# Importa a classe 'Policy' do módulo IAM do Google Cloud e a renomeia para 'GCP_IAM_Policy'
# para clareza e para evitar conflitos de nome. Este objeto representa uma política IAM.
from google.cloud.iam import Policy as GCP_IAM_Policy
# Importa exceções específicas da API do Google para tratamento de erros mais granular.
from google.api_core import exceptions as google_exceptions

# Importa a função para obter o cliente do Cloud Storage do seu pacote de utilitários.
from gcp_utils.clients import get_storage_client

# Define uma função auxiliar para retornar o nome da ferramenta, usado em logs.
def tool_name():
    return "IAM Policy Scanner" # Retorna o nome da ferramenta.

# Define a função que lista buckets e suas políticas IAM.
def list_buckets_and_policies(project_id: str) -> List[Dict]:
    # project_id: O ID do projeto GCP a ser escaneado.
    # -> List[Dict]: Indica que a função retorna uma lista de dicionários.
    
    # Obtém uma instância do cliente do Cloud Storage para o projeto especificado.
    storage_client = get_storage_client(project_id=project_id)
    # Inicializa uma lista vazia para armazenar os dados dos buckets e suas políticas.
    bucket_data_list: List[Dict] = []
    
    try: # Inicia um bloco para tratamento de exceções que podem ocorrer ao listar buckets.
        # Obtém um iterador para todos os buckets no projeto e o converte para uma lista.
        all_buckets_from_api = list(storage_client.list_buckets())
        # Loga o número de buckets encontrados.
        logging.info(f"{tool_name()}: Found {len(all_buckets_from_api)} buckets in project '{project_id}'.")

        processed_buckets_count = 0 # Inicializa um contador para buckets processados.
        # Itera sobre cada objeto 'bucket' na lista de buckets recuperada.
        for bucket in all_buckets_from_api:
            processed_buckets_count += 1 # Incrementa o contador.
            # Log de depuração para indicar o progresso do processamento de cada bucket.
            logging.debug(f"{tool_name()}: Processing bucket {processed_buckets_count}/{len(all_buckets_from_api)}: {bucket.name}")
            policy = None # Inicializa a variável 'policy' como None para este bucket.
            error_message = None # Inicializa a variável 'error_message' como None.
            try: # Inicia um bloco para tratar exceções ao obter a política IAM de um bucket específico.
                # Solicita a política IAM do bucket, especificando a versão 3 para incluir 'conditions'.
                policy = bucket.get_iam_policy(requested_policy_version=3)
            except (google_exceptions.Forbidden, google_exceptions.NotFound) as e: # Captura erros específicos de Permissão Negada ou Não Encontrado.
                error_message = str(e) # Armazena a mensagem de erro.
                # Loga um aviso se a obtenção da política falhar devido a permissão ou bucket não encontrado.
                logging.warning(f"{tool_name()} - Access error for bucket '{bucket.name}': {error_message}")
            except Exception as e: # Captura qualquer outra exceção inesperada.
                error_message = str(e) # Armazena a mensagem de erro.
                # Loga um erro com o traceback completo para depuração.
                logging.error(f"{tool_name()} - Error retrieving policy for bucket '{bucket.name}': {e}", exc_info=True)
            
            # Adiciona um dicionário à lista 'bucket_data_list' com o nome do bucket,
            # a política recuperada (ou None) e a mensagem de erro (ou None).
            bucket_data_list.append({
                "bucket_name": bucket.name,
                "policy": policy,
                "error_getting_policy": error_message
            })
        
        # Conta quantas políticas foram recuperadas com sucesso.
        successful_policies_count = sum(1 for b_data in bucket_data_list if b_data["policy"] is not None)
        # Log de depuração resumindo a tentativa de recuperação das políticas.
        logging.debug(f"{tool_name()}: Attempted policy retrieval for {len(all_buckets_from_api)} buckets. Successful: {successful_policies_count}.")

    except google_exceptions.Forbidden: # Se a listagem inicial de todos os buckets falhar por permissão.
        logging.error(f"{tool_name()}: Permission denied to list buckets in project '{project_id}'.")
        return [] # Retorna uma lista vazia.
    except Exception as e: # Qualquer outro erro ao listar buckets.
        logging.error(f"{tool_name()}: Error listing buckets in project '{project_id}': {e}", exc_info=True)
        return [] # Retorna uma lista vazia.
    return bucket_data_list # Retorna a lista de dicionários com os dados dos buckets.

# Define a função para analisar uma política IAM de um bucket.
def analyze_iam_policy(
    bucket_name: str, 
    policy: Optional[GCP_IAM_Policy], # 'policy' pode ser o objeto Policy ou None.
    roles_to_flag: List[str],      # Lista de papéis a serem sinalizados.
    members_to_flag: List[str]     # Lista de membros a serem sinalizados se tiverem os papéis acima.
) -> List[Dict]: # Retorna uma lista de dicionários, cada um sendo um "achado" sinalizado.
    
    flagged_findings: List[Dict] = [] # Inicializa a lista de achados.
    # Se não houver política ou se a política não tiver 'bindings' (vinculações), retorna a lista vazia.
    if not policy or not policy.bindings:
        return flagged_findings

    # Itera sobre cada 'binding' (vinculação) na política.
    for binding in policy.bindings:
        # Tenta obter 'role', 'members' e 'condition' do binding.
        # Usa .get() para segurança, caso 'binding' seja um dicionário e a chave não exista.
        role = binding.get('role') 
        members_data = binding.get('members', []) # Padrão para lista vazia se 'members' não existir.
        condition = binding.get('condition')      # 'condition' pode ser None.
        
        members = set() # Inicializa 'members' como um conjunto vazio.
        # Garante que 'members_data' seja iterável e o converte para um conjunto para processamento.
        if isinstance(members_data, (list, set, tuple)):
            members = set(members_data)
        elif members_data is not None: # Se 'members_data' existir mas não for um tipo esperado.
             logging.debug(f"{tool_name()}: Unexpected type for 'members' in binding for bucket '{bucket_name}': {type(members_data)}")

        # Verifica se o papel existe e está na lista de papéis a serem sinalizados.
        if role and role in roles_to_flag:
            if members: # Verifica se o conjunto de membros não está vazio.
                for member_item in members: # Itera sobre cada membro na vinculação.
                    # Verifica se o membro atual está na lista de membros a serem sinalizados.
                    if member_item in members_to_flag:
                        # Cria um dicionário para o achado sinalizado.
                        finding = {
                            "bucket_name": bucket_name, 
                            "role": role, 
                            "member": member_item, 
                            "condition": condition # Armazena o objeto/dicionário da condição.
                        }
                        flagged_findings.append(finding) # Adiciona o achado à lista.
                        # Formata a string da condição para o log, se houver condição.
                        condition_str = f" (Condition: {str(condition)})" if condition else ""
                        # Loga um aviso para cada achado sinalizado.
                        logging.warning(f"{tool_name()} - ATTENTION: Bucket '{bucket_name}' grants role '{role}' to member '{member_item}'.{condition_str}")
    return flagged_findings # Retorna a lista de todos os achados sinalizados para esta política.

# Define a função que gera um plano de remediação para um achado sinalizado.
def suggest_remediation_plan(finding: Dict) -> str:
    # finding: Um dicionário contendo os detalhes de uma vinculação sinalizada.
    # -> str: Retorna uma string com o texto da remediação.
    bucket_name = finding["bucket_name"] # Extrai o nome do bucket do 'finding'.
    role = finding["role"]               # Extrai o papel do 'finding'.
    member = finding["member"]           # Extrai o membro do 'finding'.
    condition = finding["condition"]     # Extrai a condição (pode ser None) do 'finding'.

    # Constrói o texto da sugestão de remediação.
    remediation_text = (
        f"{tool_name()} - REMEDIATION for Bucket '{bucket_name}': Remove role '{role}' for member '{member}'. Apply principle of least privilege."
    )
    if condition: # Se houver uma condição associada à vinculação.
        # Adiciona uma nota sobre a condição.
        remediation_text += f" Note: Binding has a condition: {str(condition)}. Evaluate its impact."
    return remediation_text # Retorna o texto completo da sugestão.

# Define a função orquestradora principal para o Scanner de Políticas IAM.
def run_iam_scanner(project_id: str, iam_config: Dict, 
                    delete_flag: bool, dry_run_flag: bool): # Aceita flags globais para consistência de interface, mesmo que não usadas.
    
    # Loga o início da execução da ferramenta.
    logging.info(f"{tool_name()}: Starting for project '{project_id}'.")
    # Log de depuração para registrar os flags recebidos (atualmente não usados por esta ferramenta).
    logging.debug(f"{tool_name()}: Received delete_flag={delete_flag} (not used), dry_run_flag={dry_run_flag} (not used).")
    
    # Obtém a configuração específica do iam_config (que veio do config.json).
    # Usa valores padrão se as chaves não estiverem presentes.
    roles_to_flag = iam_config.get("roles_to_flag", ["roles/storage.admin"])
    members_to_flag = iam_config.get("members_to_flag", ["allUsers", "allAuthenticatedUsers"])
    buckets_to_ignore = set(iam_config.get("buckets_to_ignore", [])) # Converte para conjunto para busca eficiente.
    
    # Formata a descrição dos papéis e membros para o log.
    roles_description = " or ".join(f"'{r}'" for r in roles_to_flag) if roles_to_flag else "any configured sensitive roles"
    roles_prefix = "role" if len(roles_to_flag) == 1 else "roles"
    members_description = " or ".join(f"'{m}'" for m in members_to_flag) if members_to_flag else "any configured sensitive members"
    # Loga os critérios que serão usados para sinalizar políticas.
    logging.info(f"{tool_name()}: Scanning for {roles_prefix} {roles_description} when granted to {members_description}.")
    
    # Chama a função para listar todos os buckets e suas respectivas políticas.
    bucket_policy_data_list = list_buckets_and_policies(project_id)
    
    # Se nenhum bucket for encontrado ou houver erro na listagem.
    if not bucket_policy_data_list:
        logging.info(f"{tool_name()}: No buckets found or policies could be retrieved. Scan finished.")
        return

    # Inicializa contadores para o sumário.
    total_flagged_findings = 0
    buckets_with_flags = 0
    
    # Cria uma lista de buckets elegíveis para scan, excluindo os que estão na lista de ignorados.
    eligible_buckets = [b for b in bucket_policy_data_list if b.get("bucket_name") not in buckets_to_ignore]
    
    processed_for_scan_count = 0 # Contador de buckets realmente analisados.
    total_eligible_to_scan = len(eligible_buckets) # Total de buckets a serem analisados.

    # Itera sobre cada item de dados de bucket elegível.
    for bucket_data in eligible_buckets:
        bucket_name = bucket_data.get("bucket_name") # Obtém o nome do bucket.
        policy = bucket_data.get("policy")           # Obtém o objeto de política (pode ser None).
        error_getting_policy = bucket_data.get("error_getting_policy") # Obtém a mensagem de erro, se houver.

        if not bucket_name: # Segurança: pula se o nome do bucket estiver ausente no dicionário.
            logging.debug(f"{tool_name()}: Skipping bucket_data item with no name: {bucket_data}")
            continue
            
        processed_for_scan_count += 1 # Incrementa o contador de buckets processados.
        # Log de depuração para o progresso da análise por bucket.
        logging.debug(f"{tool_name()}: Analyzing bucket: '{bucket_name}' ({processed_for_scan_count}/{total_eligible_to_scan})...")
        
        # Se houve um erro ao tentar obter a política deste bucket.
        if error_getting_policy:
            logging.warning(f"{tool_name()}: Skipping analysis for bucket '{bucket_name}' due to previous error retrieving its policy: '{error_getting_policy}'.")
            continue # Pula para o próximo bucket.

        # Chama a função para analisar a política do bucket atual.
        findings = analyze_iam_policy(
            bucket_name,
            policy,
            roles_to_flag,
            members_to_flag
        )
        # Se a análise encontrou alguma vinculação problemática.
        if findings:
            buckets_with_flags += 1 # Incrementa o contador de buckets com problemas.
            total_flagged_findings += len(findings) # Adiciona o número de problemas ao total.
            # Para cada achado problemático, loga o plano de remediação.
            for finding in findings:
                logging.info(suggest_remediation_plan(finding)) # Loga a sugestão.
            
    # Loga o sumário final do scan.
    logging.info(f"\n{tool_name()} - Total buckets processed: {len(bucket_policy_data_list)}")
    logging.info(f"{tool_name()} - Buckets configured to be ignored: {len(buckets_to_ignore)}")
    logging.info(f"{tool_name()} - Actual buckets analyzed for IAM policies: {processed_for_scan_count}")
    logging.info(f"{tool_name()} - Buckets found with flagged policies: {buckets_with_flags}")
    logging.info(f"{tool_name()} - Total individual flagged bindings found: {total_flagged_findings}")
