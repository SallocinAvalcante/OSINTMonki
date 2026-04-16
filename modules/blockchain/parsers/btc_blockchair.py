def parse_btc_blockchair(raw: dict) -> dict:

    if not raw:
        return {}

    tx = raw.get("transaction", {})
    inputs = raw.get("inputs", [])
    outputs = raw.get("outputs", [])

    txid = tx.get("hash")

    from_addresses = set()
    to_addresses = set()

    total_in = 0
    total_out = 0

    for vin in inputs:
        addr = vin.get("recipient")
        value = vin.get("value", 0)

        if addr:
            from_addresses.add(addr)

        total_in += value

    for vout in outputs:
        addr = vout.get("recipient")
        value = vout.get("value", 0)

        if addr:
            to_addresses.add(addr)

        total_out += value

    total_btc = total_out / 10**8

    # -------------------------
    # METADATA
    # -------------------------
    fee = tx.get("fee", 0) / 10**8 if tx.get("fee") else 0
    block = tx.get("block_id")
    timestamp = tx.get("time")

    # -------------------------
    # FLAGS (SEM DUPLICAÇÃO)
    # -------------------------
    flags = []

    if total_btc > 50:
        flags.append("EXTREME_VALUE_TX")
    elif total_btc > 1:
        flags.append("HIGH_VALUE_TX")

    if len(outputs) >= 10:
        flags.append("POSSIBLE_BATCH_TX")

    return {
        "hash": txid,
        "from": list(from_addresses),
        "to": list(to_addresses),
        "value_btc": round(total_btc, 8),
        "inputs": len(inputs),
        "outputs": len(outputs),

        "fee": round(fee, 8),
        "block": block,
        "timestamp": timestamp,

        "status": "CONFIRMED" if tx.get("is_confirmed") else "PENDING",
        "flags": flags
    }