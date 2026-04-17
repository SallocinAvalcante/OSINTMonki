from typing import List, Dict
from collections import Counter
import time
import os

from utils.blockchain.translations import translate_flag


def merge_clusters(cluster_sets):
    """
    Faz merge de clusters que compartilham endereços (Union-Find simplificado)
    """
    merged = []

    for cluster in cluster_sets:
        added = False

        for m in merged:
            if cluster & m:
                m.update(cluster)
                added = True
                break

        if not added:
            merged.append(set(cluster))

    # merge transitivo
    changed = True
    while changed:
        changed = False
        new_merged = []

        while merged:
            current = merged.pop(0)

            merged_any = False
            for i, other in enumerate(merged):
                if current & other:
                    merged[i] = current.union(other)
                    merged_any = True
                    changed = True
                    break

            if not merged_any:
                new_merged.append(current)

        merged = new_merged

    return merged


def normalize_flags(flags):
    """
    Corrige casos tipo:
    ['flag'] ou [['flag']]
    """
    normalized = []

    if not flags:
        return normalized

    for f in flags:
        if isinstance(f, list) and f:
            normalized.append(str(f[0]))
        elif isinstance(f, str):
            normalized.append(f)

    return normalized


def safe_list(value):
    """
    Garante lista segura
    """
    if not value:
        return []

    if isinstance(value, list):
        return value

    return [value]


def generate_consolidated_report(history: List[Dict], save_to_file: bool = False):

    # =========================================================
    # REMOVE DUPLICADOS
    # =========================================================
    seen_hashes = set()
    unique_history = []

    for item in history:
        tx_hash = item.get("data", {}).get("hash")

        if tx_hash and tx_hash not in seen_hashes:
            seen_hashes.add(tx_hash)
            unique_history.append(item)

    history = unique_history

    if not history:
        print("[!] Nenhum dado para consolidar.")
        return

    lines = []
    lines.append("========== Análise Consolidada ==========\n")

    total_btc = 0
    all_from = []
    all_to = []
    all_flags = []

    risk_levels = []
    tx_risks = []
    exchange_detected = 0

    raw_clusters = []

    # =========================================================
    # COLETA
    # =========================================================
    for item in history:
        data = item.get("data", {}) or {}

        total_btc += data.get("value_btc", 0) or 0

        from_addrs = safe_list(data.get("from"))
        to_addrs = safe_list(data.get("to"))

        all_from.extend(from_addrs)
        all_to.extend(to_addrs)

        # -------------------------
        # FLAGS NORMALIZADAS
        # -------------------------
        flags = normalize_flags(data.get("flags", []))
        all_flags.extend(flags)

        # -------------------------
        # RISK
        # -------------------------
        risk = data.get("risk", {}) or {}

        if risk:
            risk_levels.append(risk.get("level"))
            tx_risks.append({
                "hash": data.get("hash"),
                "score": risk.get("score", 0),
                "level": risk.get("level", "UNKNOWN")
            })

        # -------------------------
        # EXCHANGE DETECTION 
        # prioridade: confidence > flags
        # -------------------------
        confidence = data.get("confidence", {}) or {}

        if confidence.get("exchange") in ["HIGH", "MEDIUM"]:
            exchange_detected += 1
        elif any("exchange" in str(f).lower() for f in flags):
            exchange_detected += 1

        # -------------------------
        # CLUSTERS
        # -------------------------
        cluster_data = data.get("cluster", {}) or {}
        cluster_list = cluster_data.get("addresses", []) or []

        if len(cluster_list) >= 2:
            raw_clusters.append(set(cluster_list))

    # =========================================================
    # MERGE DE CLUSTERS
    # =========================================================
    merged_clusters = merge_clusters(raw_clusters)

    clusters_detected = len(merged_clusters)
    largest_cluster = max([len(c) for c in merged_clusters], default=0)

    largest_cluster_addresses = []
    if merged_clusters:
        largest_cluster_addresses = list(max(merged_clusters, key=len))[:10]

    # =========================================================
    # COUNTERS
    # =========================================================
    from_counter = Counter(all_from)
    to_counter = Counter(all_to)
    flag_counter = Counter(all_flags)
    risk_counter = Counter(risk_levels)

    # =========================================================
    # OUTPUT
    # =========================================================
    lines.append(f"Total TX: {len(history)}")
    lines.append(f"Total BTC: {round(total_btc, 8)}")
    lines.append(f"Clusters detectados: {clusters_detected}")
    lines.append(f"Maior cluster: {largest_cluster} endereços")

    if largest_cluster_addresses:
        lines.append("Exemplo de cluster:")
        for addr in largest_cluster_addresses:
            lines.append(f"  - {addr}")

    lines.append(f"Possíveis exchanges: {exchange_detected}\n")

    # =========================================================
    # DISTRIBUIÇÃO DE RISCO
    # =========================================================
    lines.append("--- Distribuição de Risco ---")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        lines.append(f"{level}: {risk_counter.get(level, 0)}")

    # =========================================================
    # TOP TX
    # =========================================================
    lines.append("\n--- Transações mais relevantes ---")

    tx_risks_sorted = sorted(tx_risks, key=lambda x: x["score"], reverse=True)[:5]

    for tx in tx_risks_sorted:
        lines.append(f"{tx['hash'][:12]}... | Score: {tx['score']} | {tx['level']}")

    # =========================================================
    # TOP ADDRS
    # =========================================================
    lines.append("\n--- Principais Endereços de Origem (FROM) ---")
    for addr, count in from_counter.most_common(5):
        lines.append(f"{addr} -> {count}x")

    lines.append("\n--- Principais Endereços de Destino (TO) ---")
    for addr, count in to_counter.most_common(5):
        lines.append(f"{addr} -> {count}x")

    # =========================================================
    # FLAGS
    # =========================================================
    lines.append("\n--- Indicadores (FLAGS) ---")
    for flag, count in flag_counter.most_common():
        translated = translate_flag(flag)
        lines.append(f"{translated} -> {count}x")

    # =========================================================
    # INSIGHTS ANALÍTICOS
    # =========================================================
    lines.append("\n--- Insights Analíticos ---")

    if clusters_detected > 0:
        lines.append("- Clusterização real detectada (possível entidade única controlando múltiplos endereços)")

    if largest_cluster >= 5:
        lines.append("- Forte indicativo de wallet institucional ou serviço")

    if exchange_detected > 0:
        lines.append("- Padrões compatíveis com exchange")

    if risk_counter.get("HIGH", 0) > 0:
        lines.append("- Transações de alto risco detectadas")

    output = "\n".join(lines)

    print("\n" + output + "\n")

    # =========================================================
    # SAVE
    # =========================================================
    if save_to_file:
        report_dir = os.path.join("reports", "consolidated")
        os.makedirs(report_dir, exist_ok=True)

        filename = os.path.join(
            report_dir,
            f"consolidated_report_{int(time.time())}.txt"
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write(output)

        print(f"[Relatório] Salvo em: {filename}")

        return filename