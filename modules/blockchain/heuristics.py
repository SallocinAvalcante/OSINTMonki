from typing import Dict, List


# -------------------------
# HELPERS
# -------------------------
def normalize_list(value) -> List[str]:
    if not value:
        return []

    if isinstance(value, list):
        return [str(v).strip() for v in value if v]

    return [str(value).strip()]


def sanitize_addresses(addresses: List[str]) -> List[str]:
    """
    Remove duplicados e valores inválidos
    """
    return list(set([a.strip() for a in addresses if a and isinstance(a, str)]))


def get_addresses(tx: Dict):
    inputs = sanitize_addresses(normalize_list(tx.get("from")))
    outputs = sanitize_addresses(normalize_list(tx.get("to")))

    return inputs, outputs


def get_output_values(tx: Dict):
    values = tx.get("output_values")

    if isinstance(values, list):
        return values

    return []


# -------------------------
# HEURÍSTICAS
# -------------------------
def detect_self_transfer(inputs: List[str], outputs: List[str]) -> bool:
    """
    Só considera self-transfer quando há interseção REAL e consistente.
    Evita:
    - change output simples
    - duplicação de endereço
    - falsos positivos estruturais
    """

    if not inputs or not outputs:
        return False

    unique_inputs = set(inputs)
    unique_outputs = set(outputs)

    intersection = unique_inputs & unique_outputs

    #  REGRA MAIS SEGURA:
    # precisa de pelo menos 2 endereços iguais
    # OU 1 endereço com múltiplos inputs (caso raro)
    if len(intersection) >= 2:
        return True

    return False


def detect_high_activity(tx: Dict) -> bool:
    return tx.get("tx_count", 0) > 50


def detect_batch_transaction(values: List[float], outputs_count: int) -> bool:

    if values and len(values) >= 5:
        unique = set(round(v, 6) for v in values)
        return len(unique) < len(values) * 0.5

    if outputs_count >= 10:
        return True

    return False


# -------------------------
# EXCHANGE DETECTION
# -------------------------
def detect_exchange(tx: Dict) -> tuple[bool, int]:

    inputs, outputs = get_addresses(tx)

    values = get_output_values(tx)
    outputs_count = tx.get("outputs", 0) or len(outputs)

    score = 0

    if outputs_count > 10:
        score += 2

    if detect_batch_transaction(values, outputs_count):
        score += 2

    #  CHANGE OUTPUT ≠ SELF TRANSFER
    intersection = set(inputs) & set(outputs)
    if len(intersection) == 1:
        score += 1

    return (score >= 3, score)


# -------------------------
# MAIN
# -------------------------
def analyze_transaction(tx: Dict) -> Dict:

    flags = []
    heuristics = []
    confidence = {}

    inputs, outputs = get_addresses(tx)

    values = get_output_values(tx)
    outputs_count = tx.get("outputs", 0) or len(outputs)

    # -------------------------
    # SELF TRANSFER
    # -------------------------
    if detect_self_transfer(inputs, outputs):
        heuristics.append("SELF TRANSFER")

    # -------------------------
    # HIGH ACTIVITY
    # -------------------------
    if detect_high_activity(tx):
        heuristics.append("HIGH ACTIVITY WALLET")

    # -------------------------
    # EXCHANGE
    # -------------------------
    is_exchange, score = detect_exchange(tx)

    if is_exchange:
        flags.append("POSSÍVEL EXCHANGE (batch transaction)")
        confidence["exchange"] = "MEDIUM" if score < 5 else "HIGH"

    # -------------------------
    # BATCH
    # -------------------------
    if detect_batch_transaction(values, outputs_count):
        heuristics.append("BATCH TRANSACTION")

    return {
        "flags": flags,
        "heuristics": heuristics,
        "confidence": confidence
    }