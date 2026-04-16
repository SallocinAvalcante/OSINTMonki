import os
import yaml
from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = "config.yml"


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[Config] Erro ao carregar config.yml: {e}")
        return {}


CONFIG = load_config()


def get_api_key(service: str) -> str:
    key_name = CONFIG.get("api_keys", {}).get(service)

    if not key_name:
        return None

    return os.getenv(key_name)


def get_blockchain_provider(chain: str) -> str:
    return CONFIG.get("blockchain", {}).get(chain, {}).get("default_provider")