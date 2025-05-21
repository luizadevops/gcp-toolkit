import logging
import json
import sys

DEFAULT_LOG_LEVEL = logging.INFO

def setup_logging(level=DEFAULT_LOG_LEVEL):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%d-%m-%Y %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logging.debug(f"Logging setup complete. Level set to: {logging.getLevelName(level)}")


def load_config(config_path: str) -> dict:
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        logging.info(f"Configuration successfully loaded from '{config_path}'.")
        return config_data
    except FileNotFoundError:
        logging.critical(f"CRITICAL ERROR: Configuration file not found at '{config_path}'. Please ensure it exists.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.critical(f"CRITICAL ERROR: Could not decode JSON from '{config_path}'. Error: {e}. Please check the file format.")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"CRITICAL ERROR: An unexpected error occurred while loading configuration from '{config_path}': {e}", exc_info=True)
        sys.exit(1)