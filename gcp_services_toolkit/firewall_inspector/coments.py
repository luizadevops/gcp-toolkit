# firewall_inspector/service.py
# (Em português: Módulo de serviço para o Inspetor e Limpador de Regras de Firewall - Caso 1)

# Importa o módulo de logging para registrar mensagens.
import logging
# Importa tipos do módulo 'typing' para anotações de tipo, melhorando a legibilidade.
from typing import Sequence, Tuple, List, Dict

# Importa a biblioteca cliente do Google Cloud Compute Engine (v1).
from google.cloud import compute_v1
# Importa exceções específicas da API do Google para tratamento de erros.
from google.api_core import exceptions as google_exceptions
# Importa o TIPO específico 'Firewall' do módulo de tipos do compute_v1 para type hinting.
from google.cloud.compute_v1.types import Firewall
# Importa a função para obter o cliente de firewalls do seu pacote de utilitários.
# (Anteriormente get_compute_client, get_firewalls_client é mais específico e foi uma sugestão de refatoração)
from gcp_utils.clients import get_firewalls_client


# Define uma função auxiliar para retornar o nome da ferramenta, usado consistentemente nos logs.
# (Esta função _tool_name_for_logging() foi adicionada na minha última sugestão para padronizar os logs,
#  se você não a adicionou, pode usar "Firewall Inspector" diretamente nos logs)
def _tool_name_for_logging():
    return "Firewall Inspector"

# Define a função que verifica se há correspondência/sobreposição de portas.
def check_ports_match(rule_ports: Sequence[str], config_ports: List[str]) -> bool:
    # rule_ports: Uma sequência de strings representando as portas da regra (ex: ['22', '8000-9000']).
    # config_ports: Uma lista de strings representando as portas da configuração a serem verificadas.
    # -> bool: Retorna True se houver correspondência, False caso contrário.

    # Saída antecipada: se a regra não especifica portas (implica todas as portas para o protocolo)
    # OU se a configuração está explicitamente procurando por "1-65535" (todas as portas).
    if not rule_ports or "1-65535" in config_ports:
        return True # Considera uma correspondência imediata.

    # Define uma função aninhada para converter uma string de porta/intervalo em um objeto range do Python.
    def parse_port_range(port_str: str) -> range:
        # port_str: A string da porta, ex: "80" ou "1000-2000".
        # -> range: Retorna um objeto range representando as portas.
        if '-' in port_str: # Se a string contém um hífen, é um intervalo.
            start, end = map(int, port_str.split('-')) # Divide no hífen e converte para inteiros.
            return range(start, end + 1) # Cria um range que inclui o 'end'.
        # Se não for um intervalo, é uma porta única.
        return range(int(port_str), int(port_str) + 1) # Cria um range para a porta única.

    try: # Bloco para tratar ValueErrors da conversão de string para int em parse_port_range.
        # Converte todas as strings de porta da regra em objetos range.
        rule_ranges = [parse_port_range(p) for p in rule_ports]
        # Converte todas as strings de porta da configuração em objetos range.
        config_ranges = [parse_port_range(p) for p in config_ports]

        # Itera sobre cada range de porta da regra.
        for r_range in rule_ranges:
            # Itera sobre cada range de porta da configuração.
            for c_range in config_ranges:
                # Verifica se ALGUMA porta no r_range também está no c_range (sobreposição).
                if any(port in c_range for port in r_range):
                    return True # Se houver sobreposição, retorna True.
        return False # Se nenhum range da regra sobrepuser nenhum range da config, retorna False.
    except ValueError: # Se ocorrer um erro de formato ao converter uma string de porta.
        # Loga um aviso com as portas problemáticas.
        logging.warning(f"{_tool_name_for_logging()}: Invalid port format encountered. rule_ports={rule_ports}, config_ports={config_ports}. Treating as no match.")
        return False # Retorna False como uma forma de falha segura.


# Define a função que lista todas as regras de firewall de VPC em um projeto.
def list_firewall_rules(project_id: str) -> List[Firewall]: # Usa o tipo Firewall importado para o retorno.
    """
    Lists all firewall rules in a given GCP project.
    (Em português: Lista todas as regras de firewall em um determinado projeto GCP.)
    """
    client = get_firewalls_client() # Obtém o cliente FirewallsClient.
    firewalls_list: List[Firewall] = [] # Inicializa uma lista para armazenar os objetos Firewall.
    try: # Bloco para tratamento de exceções da API.
        # Cria um objeto de requisição para a API, especificando o projeto.
        request = compute_v1.ListFirewallsRequest(project=project_id)
        # Chama o método 'list' do cliente. Isso retorna um iterador que lida com paginação.
        for firewall_item in client.list(request=request): # Itera sobre as regras de firewall retornadas.
            firewalls_list.append(firewall_item) # Adiciona cada regra à lista.
        # Loga o sucesso e o número de regras listadas. (Na sua versão, o prefixo da ferramenta foi removido deste log)
        logging.info(f"Firewall Inspector: Listed {len(firewalls_list)} firewall rules for project '{project_id}'.")
    except google_exceptions.Forbidden: # Se a conta não tiver permissão.
        # Log de erro com o prefixo da ferramenta.
        logging.error(f"Firewall Inspector: Permission denied to list firewall rules in project '{project_id}'. Requires 'compute.firewalls.list'.")
    except google_exceptions.NotFound: # Se o projeto não for encontrado ou a API não estiver habilitada.
        logging.error(f"Firewall Inspector: Project '{project_id}' not found or Compute Engine API not enabled.")
    except Exception as e: # Qualquer outro erro inesperado.
        # Log de erro com o prefixo da ferramenta e o traceback.
        logging.error(f"Firewall Inspector: Failed to list firewall rules for project '{project_id}': {e}", exc_info=True)
    return firewalls_list # Retorna a lista de regras (pode ser vazia).

# Define a função que verifica se uma regra é excessivamente permissiva.
def is_rule_overly_permissive(rule: Firewall, fw_config_params: Dict) -> Tuple[bool, str]:
    # rule: O objeto Firewall a ser analisado.
    # fw_config_params: O dicionário de configuração específico para o inspetor de firewall.
    # -> Tuple[bool, str]: Retorna um booleano (True se permissiva) e uma string (razão).

    # Obtém as configurações do dicionário fw_config_params, com valores padrão.
    source_ip_alert = fw_config_params.get("source_ip_alert", "0.0.0.0/0")
    flag_ingress_only = fw_config_params.get("flag_ingress_only", True)
    permissive_criteria = fw_config_params.get("permissive_rules_details", [])
    target_tags_to_ignore = set(fw_config_params.get("target_tags_to_ignore", []))
    target_sas_to_ignore = set(fw_config_params.get("target_service_accounts_to_ignore", [])) # Esta linha foi re-adicionada.

    # Verifica se a regra deve ser pulada com base na direção (INGRESS/EGRESS).
    # Usa Firewall.Direction.INGRESS porque Firewall foi importado de .types.
    if flag_ingress_only and rule.direction != Firewall.Direction.INGRESS:
        return False, ""

    # Verifica se a regra permite tráfego da 'source_ip_alert' configurada.
    if source_ip_alert not in rule.source_ranges:
        return False, ""

    # Verifica se a regra deve ser ignorada com base nas tags de destino.
    if target_tags_to_ignore and set(rule.target_tags).intersection(target_tags_to_ignore):
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' (source: '{source_ip_alert}') skipped: matches ignored target_tags: {list(rule.target_tags)}")
        return False, ""
    
    # Verifica se a regra deve ser ignorada com base nas contas de serviço de destino.
    if target_sas_to_ignore and set(rule.target_service_accounts).intersection(target_sas_to_ignore):
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' (source: '{source_ip_alert}') skipped: matches ignored target_service_accounts: {list(rule.target_service_accounts)}")
        return False, ""

    # Se a regra tem a fonte de alerta mas não tem cláusulas 'allowed', ela não permite nada explicitamente.
    if not rule.allowed:
        logging.debug(f"Firewall Inspector: Rule '{rule.name}' has source '{source_ip_alert}' but no 'allowed' protocols/ports. Effectively blocks all.")
        return False, ""

    # Itera sobre cada cláusula 'allowed' da regra (cada uma define um protocolo e portas).
    for allowed_item in rule.allowed:
        protocol = allowed_item.i_p_protocol.lower() # Protocolo (tcp, udp, etc.) em minúsculas.
        rule_ports = allowed_item.ports # Lista de strings de portas da regra.

        # Filtra os 'permissive_criteria' da configuração para encontrar aqueles que correspondem ao protocolo atual.
        matching_criteria_from_config = [
            (criterion_dict, criterion_dict.get("ports", [])) # Tupla: (dicionário do critério, lista de portas do critério)
            for criterion_dict in permissive_criteria
            if protocol == criterion_dict.get("protocol", "").lower() or \
               criterion_dict.get("protocol", "").lower() == "any" # Compara protocolos ou se o critério é "any".
        ]

        # Itera sobre os critérios de configuração que corresponderam ao protocolo.
        for criterion_dict, config_ports_for_criterion in matching_criteria_from_config:
            # Se o critério da configuração não listar portas específicas (lista vazia),
            # significa que QUALQUER porta para este protocolo é considerada permissiva pela configuração.
            if not config_ports_for_criterion:
                return True, f"Allows {protocol.upper()} on ALL ports (as per empty 'ports' in config for protocol '{criterion_dict.get('protocol')}') from '{source_ip_alert}'."
            # Caso contrário, chama check_ports_match para ver se há sobreposição entre as portas da regra e as portas do critério.
            if check_ports_match(rule_ports, config_ports_for_criterion):
                return True, (f"Allows {protocol.upper()} on ports ({rule_ports if rule_ports else 'ALL'}) "
                              f"from '{source_ip_alert}' which match configured permissive ports "
                              f"'{config_ports_for_criterion}' for criterion protocol '{criterion_dict.get('protocol')}'.")
    # Se nenhum critério permissivo foi correspondido após todas as verificações.
    return False, ""


# Define a função para deletar uma regra de firewall.
def delete_firewall_rule(project_id: str, rule_name: str, dry_run: bool = True) -> bool:
    """
    Deletes a specific firewall rule. Supports dry-run mode.
    Returns True if the operation was successful (or simulated successfully), False otherwise.
    (Em português: Deleta uma regra de firewall específica. Suporta modo dry-run.
     Retorna True se a operação foi bem-sucedida (ou simulada com sucesso), False caso contrário.)
    """
    client = get_firewalls_client() # Obtém o cliente.

    if dry_run: # Se o modo dry_run estiver ativo.
        # Loga a ação que seria tomada, mas não a executa.
        logging.info(f"Firewall Inspector - [DRY-RUN]: Would delete firewall rule '{rule_name}' in project '{project_id}'.")
        return True # Simula sucesso.

    # Se não for dry_run, tenta a deleção real.
    logging.info(f"Firewall Inspector: Attempting to delete rule '{rule_name}' in project '{project_id}'.")
    try: # Bloco para tratamento de exceções da API.
        # Chama o método 'delete' do cliente para iniciar a deleção da regra.
        operation = client.delete(project=project_id, firewall=rule_name)
        # Loga que a SOLICITAÇÃO de deleção foi iniciada. A deleção real é assíncrona no GCP.
        # O objeto 'operation' pode ser usado para rastrear o status da operação.
        logging.info(f"Firewall Inspector: Delete operation for rule '{rule_name}' in project '{project_id}' initiated. Operation ID: {operation.name}")
        return True # Indica que o comando de deleção foi enviado com sucesso.
    except google_exceptions.NotFound: # Se a regra não for encontrada.
        logging.warning(f"Firewall Inspector: Rule '{rule_name}' not found in project '{project_id}'. Might be already deleted.")
        return False
    except google_exceptions.Forbidden: # Se não houver permissão para deletar.
        logging.error(f"Firewall Inspector: Permission denied to delete rule '{rule_name}' in project '{project_id}'. Requires 'compute.firewalls.delete'.")
        return False
    except Exception as e: # Qualquer outro erro inesperado.
        # Loga o erro com traceback.
        logging.error(f"Firewall Inspector: Unexpected error deleting rule '{rule_name}' in project '{project_id}': {e}", exc_info=True)
        return False

# Define a função orquestradora principal para o Inspetor de Firewall.
def run_firewall_inspector(project_id: str, fw_config_params: Dict,
                           attempt_deletion: bool, is_global_dry_run: bool):
    """
    Main orchestrator for Case 1: Firewall Rule Inspector & Cleaner.
    Handles delete confirmation internally based on provided flags.
    (Em português: Orquestrador principal para o Caso 1: Inspetor e Limpador de Regras de Firewall.
     Lida com a confirmação de deleção internamente com base nas flags fornecidas.)
    """
    tool_name = _tool_name_for_logging() # Obtém o nome da ferramenta para os logs.
    logging.info(f"Starting {tool_name} for project '{project_id}'.") # Log de início da ferramenta.
    # Log de depuração para os flags recebidos.
    logging.debug(f"{tool_name}: Received attempt_deletion={attempt_deletion}, is_global_dry_run={is_global_dry_run}")

    # Determina o modo dry_run efetivo para as ações de deleção DENTRO desta ferramenta.
    effective_dry_run_for_delete_action = is_global_dry_run
    # Determina se a lógica de deleção deve prosseguir (considerando a confirmação do usuário).
    proceed_with_delete_actions = attempt_deletion 

    # Se o usuário solicitou deleção (--delete na CLI) E o modo dry_run global NÃO está ativo.
    if attempt_deletion and not is_global_dry_run:
        # Loga um aviso importante sobre deleções reais.
        logging.warning(f"{tool_name}: --delete flag is active and global --dry-run is OFF. "
                        "REAL firewall deletions will be attempted IF USER CONFIRMS.")
        try:
            # Pede confirmação explícita ao usuário de forma interativa.
            confirm = input(f"{tool_name}: Are you ABSOLUTELY SURE you want to proceed with REAL firewall deletions? (yes/no): ")
            if confirm.lower() == 'yes': # Se o usuário confirmar com "yes".
                logging.info(f"{tool_name}: User confirmed real deletions.")
                effective_dry_run_for_delete_action = False # A ação de deleção NÃO será dry_run.
            else: # Se o usuário cancelar ou digitar qualquer outra coisa.
                logging.info(f"{tool_name}: User CANCELLED real deletions. No rules will be deleted by this tool.")
                proceed_with_delete_actions = False # Usuário cancelou, não prossiga com a lógica de deleção.
        except EOFError: # Se o script estiver rodando em um ambiente não interativo (ex: CI/CD) onde input() falha.
            logging.error(f"{tool_name}: --delete flag used in a non-interactive environment without global --dry-run. "
                          "This is unsafe. REAL DELETIONS ABORTED for this tool.")
            proceed_with_delete_actions = False # Não prossiga com a deleção.
    # Se --delete foi passado E o dry_run global também.
    elif attempt_deletion and is_global_dry_run:
        logging.info(f"{tool_name}: --delete flag active, but global --dry-run is also active. Deletions will be SIMULATED.")
        effective_dry_run_for_delete_action = True # Garante que a ação de deleção seja dry_run.

    # --- Lógica de Inspeção Real ---
    all_firewalls = list_firewall_rules(project_id) # Chama a função para listar todas as regras de firewall.
    flagged_rules_count = 0 # Contador para regras sinalizadas.
    actions_taken_on_rules = 0 # Contador para deleções (reais ou simuladas) bem-sucedidas.

    if all_firewalls is not None: # Verifica se a lista de firewalls foi retornada com sucesso.
        if len(all_firewalls) > 0 : # Se houver regras para analisar.
             logging.info(f"{tool_name}: Analyzing {len(all_firewalls)} firewall rules...")
        else: # Se não houver nenhuma regra no projeto.
             logging.info(f"{tool_name}: No firewall rules found to analyze in project '{project_id}'.")

        for rule in all_firewalls: # Itera sobre cada regra de firewall.
            if rule.disabled: # Se a regra estiver desabilitada no GCP.
                logging.debug(f"{tool_name}: Rule '{rule.name}' is disabled, skipping detailed checks.")
                continue # Pula para a próxima regra.

            # Chama a função para verificar se a regra atual é excessivamente permissiva.
            is_permissive, reason = is_rule_overly_permissive(rule, fw_config_params)
            
            if is_permissive: # Se a regra foi sinalizada como permissiva.
                flagged_rules_count += 1
                # Loga um AVISO com os detalhes da regra sinalizada e a razão.
                logging.warning(
                    f"{tool_name} - FLAGGED: Rule '{rule.name}' (Priority: {rule.priority}, "
                    f"Network: {rule.network.split('/')[-1]}). Reason: {reason}"
                )

                # Se a lógica de deleção deve prosseguir (intenção original E confirmação/dry_run).
                if proceed_with_delete_actions:
                    # Chama a função para deletar (ou simular a deleção) da regra.
                    delete_action_was_successful = delete_firewall_rule(
                        project_id,
                        rule.name,
                        dry_run=effective_dry_run_for_delete_action # Passa o status de dry_run determinado para esta ação.
                    )
                    if delete_action_was_successful: # Se a deleção/simulação foi bem-sucedida.
                        actions_taken_on_rules += 1
        
        # Loga o sumário da análise.
        logging.info(f"{tool_name}: Analysis complete. {flagged_rules_count} rule(s) flagged.")
        if proceed_with_delete_actions: # Só loga sobre ações de deleção se elas foram intencionadas.
            action_verb = "simulated" if effective_dry_run_for_delete_action else "initiated"
            if actions_taken_on_rules > 0 or flagged_rules_count > 0 : # Evita logar se nenhuma regra foi sequer sinalizada para ação.
                logging.info(f"{tool_name}: {actions_taken_on_rules} flagged rule(s) had deletion {action_verb}.")
            elif flagged_rules_count == 0 : # Nenhuma regra sinalizada, portanto nenhuma ação de deleção.
                logging.info(f"{tool_name}: No rules were flagged for deletion.")

    elif all_firewalls is None: # Se list_firewall_rules retornou None (indicando um erro crítico na listagem).
         logging.error(f"{tool_name}: Could not retrieve firewall rules from project '{project_id}'. Check previous logs for errors.")
    # else: # Se a lista for vazia, já foi tratado acima com "No firewall rules found to analyze..."
