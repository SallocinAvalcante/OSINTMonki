from typing import Dict


def calculate_tx_risk(parsed: Dict) -> Dict:
    """
    Calcula score de risco com base em evidência consolidada.
    """

    score = 0
    reasons = set()

    inputs = parsed.get("inputs", 0) or 0
    outputs = parsed.get("outputs", 0) or 0

    value_btc = parsed.get("value_btc", 0) or 0
    value_eth = parsed.get("value_eth", 0) or 0

    flags = parsed.get("flags", []) or []
    heuristics = parsed.get("heuristics", []) or []
    confidence = parsed.get("confidence", {}) or {}
    evidence = parsed.get("evidence", {}) or {}

    cluster_data = parsed.get("cluster", {}) or {}
    cluster_addresses = cluster_data.get("addresses", []) or []

    # =========================================================
    # 1. SELF TRANSFER 
    # =========================================================
    self_transfer = evidence.get("self_transfer", {})

    if self_transfer.get("is_self"):
        score += 1  # impacto baixo
        reasons.add("Self-transfer confirmado")

    # =========================================================
    # 2. MULTI INPUT (CONSOLIDAÇÃO)
    # =========================================================
    if inputs >= 10:
        score += 3
        reasons.add("Alta quantidade de inputs")
    elif inputs >= 5:
        score += 2
        reasons.add("Múltiplas entradas (possível consolidação)")

    # =========================================================
    # 3. MULTI OUTPUT (DISTRIBUIÇÃO)
    # =========================================================
    if outputs >= 10:
        score += 3
        reasons.add("Alta quantidade de saídas")
    elif outputs >= 5:
        score += 2
        reasons.add("Múltiplas saídas (possível distribuição)")

    # =========================================================
    # 4. EXCHANGE DETECTION
    # =========================================================
    exchange_conf = confidence.get("exchange")

    if exchange_conf == "HIGH":
        score += 5
        reasons.add("Alta probabilidade de carteira de exchange")

    elif exchange_conf == "MEDIUM":
        score += 3
        reasons.add("Possível carteira de exchange")

    # fallback estrutural (somente se NÃO houver evidência)
    elif inputs <= 2 and outputs >= 10:
        score += 2
        reasons.add("Padrão estrutural compatível com exchange")

    # =========================================================
    # 5. BATCH TRANSACTION (via evidence)
    # =========================================================
    if evidence.get("batch"):
        score += 2
        reasons.add("Transação em lote detectada")

    if outputs >= 20:
        score += 2
        reasons.add("Distribuição massiva")

    # =========================================================
    # 6. HIGH ACTIVITY
    # =========================================================
    if evidence.get("high_activity"):
        score += 2
        reasons.add("Carteira com alta atividade")

    # =========================================================
    # 7. CLUSTERING
    # =========================================================
    if len(cluster_addresses) >= 2:
        score += 2
        reasons.add(f"Cluster inferido ({len(cluster_addresses)} endereços)")

        if len(cluster_addresses) >= 5:
            score += 1
            reasons.add("Cluster grande (possível entidade consolidada)")

    # =========================================================
    # 8. HIGH VALUE
    # =========================================================
    if value_btc:
        if value_btc >= 50:
            score += 3
            reasons.add("Transação de valor extremamente alto")
        elif value_btc >= 10:
            score += 2
            reasons.add("Transação de alto valor")

    if value_eth:
        if value_eth >= 500:
            score += 3
            reasons.add("Transação de valor extremamente alto (ETH)")
        elif value_eth >= 100:
            score += 2
            reasons.add("Transação de alto valor (ETH)")

    # =========================================================
    # 9. ADDRESS REUSE
    # =========================================================
    from_addrs = parsed.get("from", []) or []
    to_addrs = parsed.get("to", []) or []

    if not isinstance(from_addrs, list):
        from_addrs = [from_addrs]

    if not isinstance(to_addrs, list):
        to_addrs = [to_addrs]

    if len(set(from_addrs)) == 1 and len(set(to_addrs)) == 1:
        score += 1
        reasons.add("Baixa diversidade de endereços")

    # =========================================================
    # 10. FLAGS (fallback leve)
    # =========================================================
    for f in flags:
        f_lower = str(f).lower()

        if "exchange" in f_lower and exchange_conf is None:
            score += 2
            reasons.add("Indicador textual de exchange")

        if "batch" in f_lower and not evidence.get("batch"):
            score += 1
            reasons.add("Indicador textual de batch")

    # =========================================================
    # NORMALIZAÇÃO FINAL
    # =========================================================
    if score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "reasons": sorted(list(reasons))
    }