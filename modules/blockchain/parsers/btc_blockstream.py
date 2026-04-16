def parse_btc_blockstream(raw: dict) -> dict:

    if not raw:
        return {}

    txid = raw.get("txid")

    inputs = raw.get("vin", [])
    outputs = raw.get("vout", [])

    total_in = 0
    total_out = 0

    from_addresses = set()
    to_addresses = set()

    # -------------------------
    # INPUTS
    # -------------------------
    for vin in inputs:
        prevout = vin.get("prevout", {})

        addr = prevout.get("scriptpubkey_address")
        value = prevout.get("value", 0)

        if addr:
            from_addresses.add(addr)

        total_in += value

    # -------------------------
    # OUTPUTS
    # -------------------------
    for vout in outputs:
        addr = vout.get("scriptpubkey_address")
        value = vout.get("value", 0)

        if addr:
            to_addresses.add(addr)

        total_out += value

    total_btc = total_out / 10**8

    # -------------------------
    #  METADATA REAL
    # -------------------------
    fee_sats = raw.get("fee", 0)
    fee_btc = fee_sats / 10**8 if fee_sats else 0

    status_data = raw.get("status", {}) or {}

    block_height = status_data.get("block_height")
    timestamp = status_data.get("block_time")

    confirmed = status_data.get("confirmed", False)

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

        # FIX PRINCIPAL
        "fee": round(fee_btc, 8),
        "block": block_height,
        "timestamp": timestamp,

        "status": "CONFIRMED" if confirmed else "PENDING",
        "flags": flags
    }