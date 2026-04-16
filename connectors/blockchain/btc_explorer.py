import requests
from typing import Optional, Dict

BASE_URL = "https://blockchain.info/rawtx"


def get_btc_transaction(txid: str) -> Optional[Dict]:
    """
    Consulta uma transação BTC via Blockchain.info (fallback)

    Docs:
    https://blockchain.info/rawtx/{txid}
    """

    url = f"{BASE_URL}/{txid}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"[BTC Explorer] Erro HTTP: {response.status_code}")
            return None

        data = response.json()

        if not data:
            print("[BTC Explorer] Resposta vazia.")
            return None

        return data

    except requests.RequestException as e:
        print(f"[BTC Explorer] Erro de conexão: {e}")
        return None