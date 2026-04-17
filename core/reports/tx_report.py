from core.reports.base import create_report_file


def generate_tx_report(results: dict) -> str:

    def _safe_set(v):
        """
        Normaliza listas de endereços para evitar falsos positivos
        """
        if not v:
            return set()

        if not isinstance(v, list):
            v = [v]

        return set([str(x).strip() for x in v if x])

    filepath = create_report_file("tx", results.get("target", "unknown"))

    lines = []
    lines.append("=" * 60)
    lines.append("OSINTMonki - Relatório de Transação Blockchain")
    lines.append("=" * 60 + "\n")

    # -------------------------
    # METADATA
    # -------------------------
    lines.append("[Alvo]")
    lines.append(f"Hash: {results.get('target')}")
    lines.append("Tipo: TRANSAÇÃO")
    lines.append(f"Blockchain: {results.get('chain')}")
    lines.append(f"Tempo de análise: {results.get('time')}s")
    lines.append("")

    data = results.get("data", {})

    if not data:
        lines.append("[!] Nenhum dado disponível.\n")
    else:

        from utils.blockchain.translations import (
            translate_status,
            format_addresses,
            translate_flag
        )

        evidence = data.get("evidence", {}) or {}
        confidence = data.get("confidence", {}) or {}

        # -------------------------
        # DADOS PRINCIPAIS
        # -------------------------
        lines.append("[Detalhes da Transação]")

        lines.append(f"Hash: {data.get('hash')}")

        lines.append("Origem (FROM):")
        lines.extend(format_addresses(data.get("from")))

        lines.append("Destino (TO):")
        lines.extend(format_addresses(data.get("to")))

        if data.get("value_btc") is not None:
            lines.append(f"Valor (BTC): {data.get('value_btc')}")
        elif data.get("value_eth") is not None:
            lines.append(f"Valor (ETH): {data.get('value_eth')}")

        lines.append(f"Taxa: {data.get('fee')}")
        lines.append(f"Status: {translate_status(data.get('status'))}")
        lines.append(f"Bloco: {data.get('block')}")
        lines.append(f"Timestamp: {data.get('timestamp')}")
        lines.append("")

        # -------------------------
        # FLAGS
        # -------------------------
        lines.append("[Indicadores Detectados]")

        flags = data.get("flags", []) or []

        has_flags = False
        for flag in flags:
            if isinstance(flag, list) and flag:
                flag = flag[0]

            if isinstance(flag, str):
                lines.append(f"- {translate_flag(flag)}")
                has_flags = True

        if not has_flags:
            lines.append("- Nenhum indicador relevante identificado")

        lines.append("")

        # -------------------------
        # HEURÍSTICAS
        # -------------------------
        lines.append("[Heurísticas Identificadas]")

        heuristics = data.get("heuristics", []) or []

        if heuristics:
            for h in heuristics:
                if h == "SELF TRANSFER":
                    # valida com dados normalizados (anti falso positivo)
                    if _safe_set(data.get("from")) & _safe_set(data.get("to")):
                        lines.append(f"- {h}")
                else:
                    lines.append(f"- {h}")
        else:
            lines.append("- Nenhuma heurística relevante")

        if confidence.get("exchange"):
            lines.append(f"- Confiança Exchange: {confidence.get('exchange')}")

        lines.append("")

        # -------------------------
        # EVIDÊNCIAS TÉCNICAS
        # -------------------------
        if evidence:
            lines.append("[Evidências Técnicas]")

            # SELF TRANSFER
            self_transfer = evidence.get("self_transfer", {}) or {}

            if self_transfer.get("is_self"):
                # valida novamente (dupla checagem)
                if _safe_set(data.get("from")) & _safe_set(data.get("to")):
                    lines.append("- Self-transfer confirmado")

                    addrs = self_transfer.get("addresses", [])
                    if addrs:
                        lines.append("  Endereços envolvidos:")
                        for a in addrs[:5]:
                            lines.append(f"    - {a}")

            # BATCH
            if evidence.get("batch"):
                lines.append("- Padrão de batch transaction detectado")

            # HIGH ACTIVITY
            if evidence.get("high_activity"):
                lines.append("- Carteira com alta atividade detectada")

            lines.append("")

        # -------------------------
        # CLUSTERING
        # -------------------------
        cluster = data.get("cluster", {}) or {}

        if cluster:
            size = cluster.get("size", 0)
            addresses = cluster.get("addresses", []) or []
            main = cluster.get("main")

            lines.append("[Cluster Inferido]")

            lines.append(f"- Tamanho do cluster: {size} endereços")

            if main:
                lines.append(f"- Endereço principal (heurístico): {main}")

            if size > 1:
                lines.append("- Amostra de endereços correlacionados:")

                for addr in addresses[:10]:
                    lines.append(f"  - {addr}")

                if len(addresses) > 10:
                    lines.append(f"  ... (+{len(addresses) - 10} endereços)")

            lines.append("")

            if size >= 10:
                lines.append("- Cluster grande (possível entidade institucional)")
            elif size >= 5:
                lines.append("- Cluster médio (possível carteira com múltiplos UTXOs)")
            elif size > 1:
                lines.append("- Pequeno cluster (possível controle conjunto de endereços)")
            else:
                lines.append("- Nenhuma evidência forte de cluster nesta transação")

            lines.append("")

        # -------------------------
        # RISK ENGINE
        # -------------------------
        risk = data.get("risk", {}) or {}

        if risk:
            lines.append("[Avaliação de Risco]")

            lines.append(
                f"Nível: {risk.get('level')} | Score: {risk.get('score')}"
            )

            for reason in risk.get("reasons", []):
                lines.append(f"- {reason}")

            lines.append("")

        # -------------------------
        # INTERPRETAÇÃO ANALÍTICA
        # -------------------------
        lines.append("[Interpretação Analítica]")

        value = data.get("value_btc") or data.get("value_eth") or 0
        inputs = data.get("inputs", 0)
        outputs = data.get("outputs", 0)

        if value and value > 10:
            lines.append("- Transação de alto valor (possível movimentação institucional)")

        if inputs >= 5 and outputs == 1:
            lines.append("- Padrão de consolidação de fundos")

        if outputs >= 10:
            lines.append("- Distribuição em massa (padrão de payout/exchange)")

        if evidence.get("batch"):
            lines.append("- Forte indicativo de transação em lote")

        if evidence.get("high_activity"):
            lines.append("- Carteira com comportamento recorrente")

        if evidence.get("self_transfer", {}).get("is_self"):
            if _safe_set(data.get("from")) & _safe_set(data.get("to")):
                lines.append("- Movimentação interna identificada")

        if confidence.get("exchange") == "HIGH":
            lines.append("- Alta probabilidade de carteira pertencente a exchange")
        elif confidence.get("exchange") == "MEDIUM":
            lines.append("- Possível comportamento de exchange")

        if cluster and cluster.get("size", 0) > 2:
            lines.append("- Cluster sugere controle centralizado de múltiplos endereços")

        if risk.get("level") == "HIGH":
            lines.append("- Comportamento fortemente suspeito ou automatizado")

        if risk.get("level") == "LOW":
            lines.append("- Nenhum comportamento crítico identificado")

        lines.append("")

    # -------------------------
    # LINKS EXTERNOS
    # -------------------------
    lines.append("[Exploradores Blockchain]")

    chain = results.get("chain")
    tx_hash = results.get("target")

    if chain == "ethereum":
        lines.append(f"- Etherscan: https://etherscan.io/tx/{tx_hash}")
    elif chain == "bitcoin":
        lines.append(f"- Blockstream: https://blockstream.info/tx/{tx_hash}")

    lines.append("")
    lines.append("=" * 60)

    # -------------------------
    # WRITE FILE
    # -------------------------
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[Relatório] Salvo em: {filepath}")

    return filepath