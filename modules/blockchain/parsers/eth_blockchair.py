def parse_eth_blockchair(raw: dict) -> dict:

    if not raw:
        return {}

    tx = raw.get("transaction", {})

    tx_hash = tx.get("hash")
    from_addr = tx.get("sender")
    to_addr = tx.get("recipient")

    value_wei = tx.get("value", 0)
    gas = tx.get("gas_limit", 0)
    gas_price = tx.get("gas_price", 0)

    value_eth = value_wei / 10**18 if value_wei else 0
    gas_price_gwei = gas_price / 10**9 if gas_price else 0

    # -------------------------
    # FEE (IMPORTANTE PARA RISCO)
    # -------------------------
    try:
        fee = (gas * gas_price) / 10**18
    except:
        fee = 0

    # -------------------------
    # METADATA
    # -------------------------
    block = tx.get("block_id")
    timestamp = tx.get("time")

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

        "gas": gas,
        "gas_price_gwei": round(gas_price_gwei, 2),

        "fee": round(fee, 8),
        "block": block,
        "timestamp": timestamp,

        "status": "CONFIRMED" if tx.get("is_confirmed") else "PENDING",
        "flags": flags
    }