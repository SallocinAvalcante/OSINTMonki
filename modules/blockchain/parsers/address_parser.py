from typing import List, Dict


def parse_btc_address_txs(raw_list: List[Dict]) -> List[Dict]:
    """
    Normaliza lista de transações BTC (Blockstream /address/{addr}/txs)

    Output padrão:
    {
        "hash": str,
        "value_btc": float,
        "inputs": int,
        "outputs": int
    }
    """

    parsed = []

    for tx in raw_list:

        try:
            txid = tx.get("txid")

            inputs = tx.get("vin", [])
            outputs = tx.get("vout", [])

            total_out = 0

            # -------------------------
            # OUTPUT VALUE
            # -------------------------
            for vout in outputs:
                total_out += vout.get("value", 0)

            value_btc = total_out / 10**8

            parsed.append({
                "hash": txid,
                "value_btc": round(value_btc, 8),
                "inputs": len(inputs),
                "outputs": len(outputs)
            })

        except Exception:
            continue

    # -------------------------
    # ORDENAÇÃO (mais recente primeiro)
    # -------------------------
    # Blockstream 
    parsed = parsed[:50]  # limite inicial (controle de UX)

    return parsed