from typing import Dict
import time
from collections import Counter

from utils.blockchain.resolver import detect_input_type
from core.providers.provider_manager import ProviderManager
from utils.common.config_loader import CONFIG

from connectors.blockchain.etherscan import get_eth_transaction
from connectors.blockchain.blockstream import get_btc_transaction
from connectors.blockchain.blockchair import get_blockchair_transaction

from modules.blockchain.tx_parser import parse_transaction
from modules.blockchain.address_scan import run_address_scan
from modules.blockchain.clustering import build_cluster

from modules.blockchain.parsers.btc_blockstream import parse_btc_blockstream
from modules.blockchain.parsers.btc_blockchair import parse_btc_blockchair
from modules.blockchain.parsers.eth_etherscan import parse_eth_etherscan
from modules.blockchain.parsers.eth_blockchair import parse_eth_blockchair

from modules.blockchain.heuristics import analyze_transaction

from utils.blockchain.tx_formatter import print_tx_summary
from utils.blockchain.translations import translate_flag
from core.scoring.blockchain.risk_engine_tx import calculate_tx_risk


# =========================================================
# HELPERS
# =========================================================
def ensure_list(value):
    if not value:
        return []
    return value if isinstance(value, list) else [value]


def ensure_flags_list(flags):
    if not flags:
        return []
    return [str(f) for f in flags] if isinstance(flags, list) else [str(flags)]


# =========================================================
# CLUSTER ENRICHMENT
# =========================================================
def enrich_cluster(parsed: Dict, cluster_data: Dict) -> Dict:
    cluster_list = cluster_data.get("cluster", []) or []

    freq = Counter(
        (parsed.get("from", []) or []) +
        (parsed.get("to", []) or [])
    )

    main_address = freq.most_common(1)[0][0] if freq else None

    return {
        "addresses": cluster_list,
        "size": len(cluster_list),
        "main": main_address,
        "sample": cluster_list[:5]
    }


# =========================================================
# PROVIDER EXECUTION
# =========================================================
def fetch_transaction(chain: str, tx_hash: str, provider: str):

    if chain == "bitcoin":
        if provider == "blockstream":
            return get_btc_transaction(tx_hash), "blockstream"
        elif provider == "blockchair":
            return get_blockchair_transaction(tx_hash, chain), "blockchair"

    elif chain == "ethereum":
        if provider == "etherscan":
            return get_eth_transaction(tx_hash), "etherscan"
        elif provider == "blockchair":
            return get_blockchair_transaction(tx_hash, chain), "blockchair"

    return None, None


# =========================================================
# MAIN
# =========================================================
def run_tx_scan(target: str) -> Dict:

    start_time = time.time()

    print("[+] Identificando tipo de entrada...")
    input_data = detect_input_type(target)

    # =========================================================
    # FALLBACK: ADDRESS
    # =========================================================
    if not input_data or input_data.get("type") != "tx":
        print("[!] Entrada não parece ser uma transação. Tentando como endereço...")

        selected_hash = run_address_scan(target)

        if selected_hash == "EXIT":
            return {}

        if not selected_hash:
            print("[!] Falha ao resolver como endereço.")
            return {}

        print(f"[+] Transação selecionada via pivot: {selected_hash}")
        return run_tx_scan(selected_hash)

    # =========================================================
    # TX FLOW
    # =========================================================
    chain = input_data.get("chain")
    print(f"[+] Tipo detectado: TRANSAÇÃO ({chain})")

    provider_manager = ProviderManager()

    raw_data = None
    source = None

    # =========================================================
    # RESOLVE PROVIDERS (DEFAULT + FALLBACK)
    # =========================================================
    providers = [
        provider_manager.get_default_provider(chain),
        provider_manager.get_fallback_provider(chain)
    ]

    for provider in providers:
        if not provider:
            continue

        print(f"[+] Tentando provider: {provider}")

        raw_data, source = fetch_transaction(chain, target, provider)

        if raw_data:
            print(f"[+] Sucesso com provider: {provider}")
            break

    # =========================================================
    # FAIL SAFE
    # =========================================================
    if not raw_data:
        print("[!] Não foi possível obter os dados da transação.")
        return {}

    # =========================================================
    # PARSE
    # =========================================================
    print("[+] Normalizando e estruturando dados...")

    parsed = None

    if chain == "bitcoin":
        if source == "blockstream":
            parsed = parse_btc_blockstream(raw_data)
        elif source == "blockchair":
            parsed = parse_btc_blockchair(raw_data)

    elif chain == "ethereum":
        if source == "etherscan":
            parsed = parse_eth_etherscan(raw_data)
        elif source == "blockchair":
            parsed = parse_eth_blockchair(raw_data)

    if not parsed:
        parsed = parse_transaction(raw_data, chain=chain)

    if not parsed:
        print("[!] Não foi possível processar os dados da transação.")
        return {}

    # =========================================================
    # NORMALIZAÇÃO FINAL
    # =========================================================
    parsed["from"] = ensure_list(parsed.get("from"))
    parsed["to"] = ensure_list(parsed.get("to"))
    parsed["flags"] = ensure_flags_list(parsed.get("flags"))

    # =========================================================
    # CLUSTERING
    # =========================================================
    print("[+] Inferindo cluster...")

    cluster_raw = build_cluster(parsed)
    parsed["cluster"] = enrich_cluster(parsed, cluster_raw)

    # =========================================================
    # HEURÍSTICAS
    # =========================================================
    print("[+] Aplicando heurísticas...")

    heuristics_result = analyze_transaction(parsed)

    parsed["flags"].extend(heuristics_result.get("flags", []))
    parsed["heuristics"] = heuristics_result.get("heuristics", [])
    parsed["confidence"] = heuristics_result.get("confidence", {})

    # =========================================================
    # TRADUÇÃO
    # =========================================================
    parsed["flags_translated"] = translate_flag(parsed["flags"])

    # =========================================================
    # RISK ENGINE
    # =========================================================
    parsed["risk"] = calculate_tx_risk(parsed)

    # =========================================================
    # OUTPUT
    # =========================================================
    if CONFIG.get("debug", {}).get("tx_verbose", True):
        print_tx_summary(parsed)

    elapsed = round(time.time() - start_time, 2)

    print(f"[OK] Análise finalizada em {elapsed}s")

    return {
        "target": target,
        "chain": chain,
        "source": source,
        "data": parsed,
        "time": elapsed
    }