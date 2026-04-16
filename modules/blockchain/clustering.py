from typing import Dict, Set


def build_cluster(tx: Dict) -> Dict:
    """
    Constrói cluster baseado em heurísticas:
    - Multi-input
    - Change address
    """

    raw_inputs = tx.get("inputs", [])
    raw_outputs = tx.get("outputs", [])

    inputs = []
    outputs = []

    # Normalização robusta
    if isinstance(raw_inputs, list):
        for i in raw_inputs:
            if isinstance(i, dict) and i.get("address"):
                inputs.append(i.get("address"))
    elif isinstance(tx.get("from"), list):
        inputs = tx.get("from", [])

    if isinstance(raw_outputs, list):
        for o in raw_outputs:
            if isinstance(o, dict) and o.get("address"):
                outputs.append(o.get("address"))
    elif isinstance(tx.get("to"), list):
        outputs = tx.get("to", [])

    cluster: Set[str] = set()
    metadata = {
        "multi_input": False,
        "change_detected": False,
        "change_addresses": []
    }

    # =========================================================
    # MULTI-INPUT HEURISTIC (FORTE)
    # =========================================================
    if len(inputs) > 1:
        cluster.update(inputs)
        metadata["multi_input"] = True

    # =========================================================
    # CHANGE ADDRESS
    # =========================================================
    change_candidates = []

    for out in outputs:
        if out in inputs:
            change_candidates.append(out)

    if change_candidates:
        cluster.update(change_candidates)
        metadata["change_detected"] = True
        metadata["change_addresses"] = change_candidates

    return {
        "cluster": list(cluster),
        "size": len(cluster),
        "meta": metadata
    }