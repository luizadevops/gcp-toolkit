# Makefile

# === Variáveis ===
# Nome da imagem Docker a ser construída
IMAGE_NAME := gcp-challenge-tool

# Caminho para o seu arquivo de configuração principal no host
CONFIG_FILE_HOST := ./config.json

# Caminho para o arquivo de configuração DENTRO do contêiner
CONFIG_FILE_CONTAINER := /app/config.json

# Caminho para o seu arquivo de chave de Conta de Serviço GCP no HOST
# !!! IMPORTANTE: Defina esta variável se for usar os alvos 'run-sa' ou 'run-caseX-sa' !!!
# Exemplo: GCP_KEY_FILE_PATH := /home/user/seu-projeto-gcp-xxxxxxxxxxxx.json
GCP_KEY_FILE_PATH := /caminho/para/sua-chave-de-servico.json

# Caminho para a chave de Conta de Serviço DENTRO do contêiner
GCP_KEY_FILE_CONTAINER := /app/gcp-key.json

# Diretório no HOST para armazenar o log de queries do Caso 3
CASE3_LOG_DIR_HOST := ./cost_reporter_output
# Diretório DENTRO do contêiner onde o script espera escrever o log do Caso 3
# (deve corresponder ao diretório em 'query_log_file' no seu config.json, ex: "cost_reporter/...")
CASE3_LOG_DIR_CONTAINER := /app/cost_reporter

# Argumentos padrão para passar ao main.py. Pode ser sobrescrito na linha de comando.
# Ex: make run-adc ARGS="--run-case1 --verbose"
ARGS ?= --help

# === Alvos (Targets) ===
.PHONY: all build run-adc run-sa clean-image clean-logs help \
        run-case1-adc run-case1-delete-adc run-case1-delete-dry-run-adc \
        run-case2-adc run-case3-adc \
        run-case1-sa run-case1-delete-sa \
        run-case2-sa run-case3-sa

# Alvo padrão: construir a imagem
all: build

# Constrói a imagem Docker
build:
	@echo "Building Docker image: $(IMAGE_NAME)..."
	docker build -t $(IMAGE_NAME) .

# Comando base para executar o contêiner (usado internamente)
# $(1) será para opções extras de 'docker run' (como montagem de chave SA e env var)
define DOCKER_RUN_BASE
	@mkdir -p $(CASE3_LOG_DIR_HOST) # Garante que o diretório de log do host exista
	docker run --rm -it \
		-v "$(CURDIR)/$(CONFIG_FILE_HOST)":"$(CONFIG_FILE_CONTAINER)":ro \
		-v "$(CURDIR)/$(CASE3_LOG_DIR_HOST)":"$(CASE3_LOG_DIR_CONTAINER)" \
		$(1) \
		$(IMAGE_NAME) \
		--config "$(CONFIG_FILE_CONTAINER)" $(ARGS)
endef

# Executa o contêiner usando as Credenciais Padrão da Aplicação (ADC) do gcloud local
run-adc: build
	@echo "Running with local gcloud ADC. Ensure you are logged in via 'gcloud auth application-default login'."
	@echo "Executing: python main.py --config $(CONFIG_FILE_CONTAINER) $(ARGS)"
	$(call DOCKER_RUN_BASE, -v "$(HOME)/.config/gcloud:/root/.config/gcloud:ro")

# Executa o contêiner usando uma Chave de Conta de Serviço
# !!! IMPORTANTE: Defina GCP_KEY_FILE_PATH ou passe na linha de comando !!!
# Ex: make run-sa GCP_KEY_FILE_PATH=/caminho/real/key.json ARGS="--verbose"
run-sa: build
	@if [ "$(GCP_KEY_FILE_PATH)" = "/caminho/para/sua-chave-de-servico.json" ] || [ ! -f "$(GCP_KEY_FILE_PATH)" ]; then \
		echo "ERROR: GCP_KEY_FILE_PATH is not set correctly or key file does not exist."; \
		echo "Please set it in the Makefile or provide it via command line: make run-sa GCP_KEY_FILE_PATH=/path/to/your/key.json"; \
		exit 1; \
	fi
	@echo "Running with Service Account Key: $(GCP_KEY_FILE_PATH)"
	@echo "Executing: python main.py --config $(CONFIG_FILE_CONTAINER) $(ARGS)"
	$(call DOCKER_RUN_BASE, -v "$(GCP_KEY_FILE_PATH)":"$(GCP_KEY_FILE_CONTAINER)":ro -e GOOGLE_APPLICATION_CREDENTIALS="$(GCP_KEY_FILE_CONTAINER)")

# --- Alvos de conveniência para Casos Específicos com ADC ---
run-case1-adc: ARGS := --run-case1 --verbose
run-case1-adc: run-adc

run-case1-delete-dry-run-adc: ARGS := --run-case1 --delete --dry-run --verbose
run-case1-delete-dry-run-adc: run-adc

run-case1-delete-adc: ARGS := --run-case1 --delete --verbose
run-case1-delete-adc: run-adc

run-case2-adc: ARGS := --run-case2 --verbose
run-case2-adc: run-adc

run-case3-adc: ARGS := --run-case3 --verbose
run-case3-adc: run-adc

# --- Alvos de conveniência para Casos Específicos com Chave de Conta de Serviço ---
run-case1-sa: ARGS := --run-case1 --verbose
run-case1-sa: run-sa

run-case1-delete-sa: ARGS := --run-case1 --delete --verbose # Adicionar --dry-run se necessário
run-case1-delete-sa: run-sa

run-case2-sa: ARGS := --run-case2 --verbose
run-case2-sa: run-sa

run-case3-sa: ARGS := --run-case3 --verbose
run-case3-sa: run-sa

# --- Alvos de Limpeza ---
clean-image:
	@echo "Removing Docker image: $(IMAGE_NAME)..."
	docker rmi $(IMAGE_NAME) || true # O '|| true' evita erro se a imagem não existir

clean-logs:
	@echo "Removing Case 3 query log file from host directory $(CASE3_LOG_DIR_HOST)..."
	rm -f "$(CASE3_LOG_DIR_HOST)/query_execution_log.json" # Assumindo que o nome do arquivo é este

# --- Ajuda ---
help:
	@echo "Available Makefile targets:"
	@echo "  build          		- Build the Docker image: '$(IMAGE_NAME)'"
	@echo "  run-adc ARGS=\"...\"  	- Run using local gcloud ADC. ARGS are passed to main.py (default: --help)."
	@echo "  run-sa ARGS=\"...\"   	- Run using Service Account Key. Set GCP_KEY_FILE_PATH or pass it."
	@echo ""
	@echo "  Convenience targets with ADC (add --verbose to ARGS if needed):"
	@echo "    run-case1-adc"
	@echo "    run-case1-delete-dry-run-adc"
	@echo "    run-case1-delete-adc       (will prompt for confirmation)"
	@echo "    run-case2-adc"
	@echo "    run-case3-adc"
	@echo ""
	@echo "  Convenience targets with Service Account Key:"
	@echo "    run-case1-sa"
	@echo "    run-case1-delete-sa        (add --dry-run to ARGS if needed; will prompt for real delete)"
	@echo "    run-case2-sa"
	@echo "    run-case3-sa"
	@echo ""
	@echo "  Cleanup targets:"
	@echo "    clean-image"
	@echo "    clean-logs"
	@echo ""
	@echo "  help             		- Show this help message"
	@echo ""
	@echo "Example for ARGS: make run-adc ARGS=\"--run-case1 --verbose --dry-run\""
	@echo "Example for Service Account: make run-sa GCP_KEY_FILE_PATH=/path/my-key.json ARGS=\"--run-case2\""