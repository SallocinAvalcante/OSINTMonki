def parse_eth_etherscan(raw: dict) -> dict:

    if not raw:
        return {}

    tx_data = raw.get("tx", {}).get("result", {}) or {}
    receipt_data = raw.get("receipt", {}).get("result", {}) or {}

    if not tx_data:
        return {}

    tx_hash = tx_data.get("hash")
    from_addr = tx_data.get("from")
    to_addr = tx_data.get("to")

    value_wei = tx_data.get("value")
    gas = tx_data.get("gas")
    gas_price = tx_data.get("gasPrice")

    # -------------------------
    # VALUE
    # -------------------------
    try:
        value_eth = int(value_wei, 16) / 10**18 if value_wei else 0
    except:
        value_eth = 0

    # -------------------------
    # GAS
    # -------------------------
    try:
        gas_int = int(gas, 16) if gas else 0
    except:
        gas_int = 0

    try:
        gas_price_int = int(gas_price, 16) if gas_price else 0
        gas_price_gwei = gas_price_int / 10**9
    except:
        gas_price_int = 0
        gas_price_gwei = 0

    # -------------------------
    # FEE (CRÍTICO)
    # -------------------------
    try:
        fee = (gas_int * gas_price_int) / 10**18
    except:
        fee = 0

    # -------------------------
    # BLOCK / TIMESTAMP
    # -------------------------
    block_hex = tx_data.get("blockNumber")
    timestamp_hex = tx_data.get("timeStamp")

    try:
        block = int(block_hex, 16) if block_hex else None
    except:
        block = None

    try:
        timestamp = int(timestamp_hex, 16) if timestamp_hex else None
    except:
        timestamp = None

    # -------------------------
    # STATUS
    # -------------------------
    status = receipt_data.get("status")

    if status == "1":
        status_human = "CONFIRMED"
    elif status == "0":
        status_human = "FAILED"
    else:
        status_human = "UNKNOWN"

    # -------------------------
    # FLAGS (SEM DUPLICAÇÃO)
    # -------------------------
    flags = []

    if value_eth > 100:
        flags.append("EXTREME_VALUE_TX")
    elif value_eth > 10:
        flags.append("HIGH_VALUE_TX")

    if not to_addr:
        flags.append("CONTRACT_CREATION")

    return {
        "hash": tx_hash,
        "from": from_addr,
        "to": to_addr,
        "value_eth": round(value_eth, 6),

        "gas": gas_int,
        "gas_price_gwei": round(gas_price_gwei, 2),

        "fee": round(fee, 8),
        "block": block,
        "timestamp": timestamp,

        "status": status_human,
        "flags": flags
    }