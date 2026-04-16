def parse_btc_blockchaininfo(raw: dict) -> dict:

    if not raw:
        return {}

    txid = raw.get("hash")

    inputs = raw.get("inputs", [])
    outputs = raw.get("out", [])

    total_in = 0
    total_out = 0

    from_addresses = set()
    to_addresses = set()

    # -------------------------
    # INPUTS
    # -------------------------
    for vin in inputs:
        prev = vin.get("prev_out", {})

        addr = prev.get("addr")
        value = prev.get("value", 0)

        if addr:
            from_addresses.add(addr)

        total_in += value

    # -------------------------
    # OUTPUTS
    # -------------------------
    for vout in outputs:
        addr = vout.get("addr")
        value = vout.get("value", 0)

        if addr:
            to_addresses.add(addr)

        total_out += value

    total_btc = total_out / 10**8

    # -------------------------
    # METADATA 
    # -------------------------
    fee_sats = raw.get("fee", 0)
    fee_btc = fee_sats / 10**8 if fee_sats else 0

    block = raw.get("block_height")
    timestamp = raw.get("time")

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

        "fee": round(fee_btc, 8),
        "block": block,
        "timestamp": timestamp,

        "status": "CONFIRMED",
        "flags": flags
    }