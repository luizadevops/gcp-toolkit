import logging
import json
import sys

def setup_logging(level=logging.INFO, verbose=False):
    if verbose:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - [%(module)s.%(funcName)s:%(lineno)d] - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logging.debug("Logging setup complete.")

def load_config(config_path: str) -> dict:
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logging.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1) # Critical error, exit
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from configuration file {config_path}: {e}")
        sys.exit(1) # Critical error, exit
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading configuration: {e}")
        sys.exit(1) # Critical error, exit