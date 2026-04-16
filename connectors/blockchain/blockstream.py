import requests
from typing import Optional, Dict, List

BASE_URL = "https://blockstream.info/api"


def get_btc_transaction(txid: str) -> Optional[Dict]:
    """
    Consulta uma transação BTC via Blockstream API
    """

    url = f"{BASE_URL}/tx/{txid}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"[Blockstream] Erro HTTP: {response.status_code}")
            return None

        data = response.json()

        if not data:
            print("[Blockstream] Resposta vazia.")
            return None

        return data

    except requests.RequestException as e:
        print(f"[Blockstream] Erro de conexão: {e}")
        return None


def get_btc_address_txs(address: str) -> Optional[List[Dict]]:
    """
    Retorna lista de transações de um endereço BTC via Blockstream API

    Retornos:
    - None -> erro de conexão/API
    - []   -> endereço válido sem transações
    - list -> transações encontradas
    """

    url = f"{BASE_URL}/address/{address}/txs"

    try:
        print(f"[Blockstream] Consultando transações do endereço: {address}")

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"[Blockstream] Erro HTTP: {response.status_code}")
            return None  

        data = response.json()

        if not isinstance(data, list):
            print("[Blockstream] Resposta inesperada.")
            return None  # erro de parsing

        if len(data) == 0:
            print("[Blockstream] Endereço sem transações.")
            return []  # válido, mas vazio

        print(f"[Blockstream] {len(data)} transações localizadas.")

        return data

    except requests.RequestException as e:
        print(f"[Blockstream] Falha na conexão com a API(tentar novamente): {e}")
        return None  