import re


# =========================================================
# BLOCKCHAIN DETECTION
# =========================================================
def detect_blockchain(tx_hash: str) -> str:
    if not tx_hash:
        return "unknown"

    tx_hash = tx_hash.strip().lower()

    # ETH / EVM
    if re.fullmatch(r"0x[a-f0-9]{64}", tx_hash):
        return "ethereum"

    # BTC TX (hex 64 chars, sem prefixo)
    if re.fullmatch(r"[a-f0-9]{64}", tx_hash):
        return "bitcoin"

    return "unknown"


# =========================================================
# INPUT TYPE DETECTION
# =========================================================
def detect_input_type(value: str) -> dict:
    """
    Detecta tipo de entrada:
    - tx hash
    - wallet address
    """

    if not value:
        return {"type": "unknown", "chain": "unknown"}

    v = value.strip()

    # =====================================================
    # ETH ADDRESS
    # =====================================================
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", v):
        return {
            "type": "address",
            "chain": "ethereum"
        }

    # =====================================================
    # BTC ADDRESS 
    # =====================================================
    # Legacy (1...) ou Script (3...)
    if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", v):
        return {
            "type": "address",
            "chain": "bitcoin"
        }

    # Bech32 (bc1...)
    if re.fullmatch(r"bc1[a-z0-9]{39,59}", v.lower()):
        return {
            "type": "address",
            "chain": "bitcoin"
        }

    # =====================================================
    # TX HASH
    # =====================================================
    chain = detect_blockchain(v)

    if chain != "unknown":
        return {
            "type": "tx",
            "chain": chain
        }

    # =====================================================
    # FALLBACK
    # =====================================================
    return {
        "type": "unknown",
        "chain": "unknown"
    }


# =========================================================
# NORMALIZATION
# =========================================================
def normalize_chain_name(chain: str) -> str:
    mapping = {
        "eth": "ethereum",
        "erc20": "ethereum",
        "btc": "bitcoin",
        "trx": "tron"
    }

    return mapping.get(chain.lower(), chain.lower())