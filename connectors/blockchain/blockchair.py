import requests
from typing import Optional, Dict
import os

BASE_URL = "https://api.blockchair.com"


def get_blockchair_transaction(txid: str, chain: str = "bitcoin") -> Optional[Dict]:
    """
    Consulta transação via Blockchair

    Suporta:
    - bitcoin
    - ethereum
    - litecoin (futuro)
    """

    if not txid:
        print("[Blockchair] TX inválida.")
        return None

    chain = chain.lower()

    url = f"{BASE_URL}/{chain}/dashboards/transaction/{txid}"

    params = {}
    from utils.common.config_loader import get_api_key

    api_key = get_api_key("blockchair")

    if api_key:
        params["key"] = api_key

    try:
        print(f"[Blockchair] Consultando {chain}: {txid}")

        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            print(f"[Blockchair] Erro HTTP: {response.status_code}")
            return None

        data = response.json()

        if not data or "data" not in data:
            print("[Blockchair] Resposta inválida (sem campo 'data').")
            return None

        tx_data = data["data"].get(txid)

        if not tx_data:
            print("[Blockchair] Transação não encontrada.")
            return None

        return tx_data

    except requests.RequestException as e:
        print(f"[Blockchair] Erro de conexão: {e}")
        return None

    except ValueError:
        print("[Blockchair] Erro ao decodificar JSON.")
        return None