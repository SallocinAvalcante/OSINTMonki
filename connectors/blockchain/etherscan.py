import requests
from utils.common.config_loader import get_api_key


BASE_URL = "https://api.etherscan.io/api"


def get_eth_transaction(tx_hash: str) -> dict:

    api_key = get_api_key("etherscan")

    if not api_key:
        print("[!] API Key do Etherscan não encontrada.")
        return {}

    try:
        # -------------------------
        # TX RECEIPT (status + gas)
        # -------------------------
        receipt_params = {
            "module": "transaction",
            "action": "gettxreceiptstatus",
            "txhash": tx_hash,
            "apikey": api_key
        }

        receipt_resp = requests.get(BASE_URL, params=receipt_params, timeout=10)
        receipt_data = receipt_resp.json()

        # -------------------------
        # TX INFO (detalhes básicos)
        # -------------------------
        tx_params = {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": tx_hash,
            "apikey": api_key
        }

        tx_resp = requests.get(BASE_URL, params=tx_params, timeout=10)
        tx_data = tx_resp.json()

        return {
            "receipt": receipt_data,
            "tx": tx_data
        }

    except Exception as e:
        print(f"[Erro] Etherscan: {e}")
        return {}