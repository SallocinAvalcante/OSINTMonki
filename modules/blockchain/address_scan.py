from typing import List, Dict

from utils.blockchain.resolver import detect_input_type
from core.providers.provider_manager import ProviderManager

from connectors.blockchain.blockstream import get_btc_address_txs

from modules.blockchain.address_selector import select_transaction
from modules.blockchain.parsers.address_parser import parse_btc_address_txs

from core.reports.tx_report import generate_tx_report
from core.reports.consolidated_report import generate_consolidated_report


# =========================================================
# PROVIDER EXECUTION
# =========================================================
def fetch_address_txs(chain: str, address: str, provider: str):

    # v0.1 → apenas blockstream suportado para address - update vai ser multiproviders
    if chain == "bitcoin" and provider == "blockstream":
        return get_btc_address_txs(address), "blockstream"

    return None, None


# =========================================================
# MAIN
# =========================================================
def run_address_scan(target: str):

    print("[+] Iniciando análise de endereço...")

    input_data = detect_input_type(target)

    if not input_data or input_data.get("type") != "address":
        print("[!] Entrada não é um endereço válido.")
        return "BACK"

    chain = input_data.get("chain")
    print(f"[+] Tipo detectado: Endereço ({chain})")

    if chain != "bitcoin":
        print("[!] Blockchain ainda não suportada.")
        return "BACK"

    # =========================================================
    # PROVIDER MANAGER
    # =========================================================
    provider_manager = ProviderManager()

    raw_txs = None
    source = None

    # tenta default primeiro, depois fallback
    providers = [
        provider_manager.get_default_provider(chain),
        provider_manager.get_fallback_provider(chain)
    ]

    for provider in providers:
        if not provider:
            continue

        print(f"[+] Tentando provider: {provider}")

        raw_txs, source = fetch_address_txs(chain, target, provider)

        if raw_txs:
            print(f"[+] Sucesso com provider: {provider}")
            break

    if raw_txs is None:
        print("[!] Falha ao consultar APIs.")
        return "BACK"

    if not raw_txs:
        print("[!] Endereço sem transações.")
        return "BACK"

    # =========================================================
    # PARSE
    # =========================================================
    parsed_txs = parse_btc_address_txs(raw_txs)

    if not parsed_txs:
        print("[!] Falha ao processar transações.")
        return "BACK"

    history: List[Dict] = []

    from modules.blockchain.tx_scan import run_tx_scan

    # =========================================================
    # LOOP PRINCIPAL
    # =========================================================
    while True:

        selected_hash = select_transaction(parsed_txs)

        # =========================================================
        # BULK ANALYSIS
        # =========================================================
        if selected_hash == "ALL":

            total = len(parsed_txs)
            print(f"[+] Iniciando análise em lote ({total} transações)...")

            for idx, tx in enumerate(parsed_txs, start=1):
                tx_hash = tx.get("hash")

                print(f"[{idx}/{total}] Processando: {tx_hash[:12]}...")

                results = run_tx_scan(tx_hash)

                if not results:
                    print("[!] Falha nesta transação. Pulando...")
                    continue

                history.append(results)

            print("[+] Análise em lote finalizada.")

            # =========================
            # MENU PÓS BULK
            # =========================
            while True:
                print("\nO que deseja fazer agora?")
                print("[1] Gerar relatório consolidado")
                print("[2] Voltar ao menu principal")

                choice = input("Opção: ").strip()

                if choice == "1":
                    print("[+] Gerando relatório consolidado...")
                    generate_consolidated_report(history, save_to_file=True)

                elif choice == "2":
                    return "EXIT"

                else:
                    print("[!] Opção inválida.")

        # =========================================================
        # VOLTAR
        # =========================================================
        if selected_hash == "BACK":
            return "EXIT"

        # =========================================================
        # VALIDAÇÃO
        # =========================================================
        if not selected_hash:
            print("[!] Nenhuma transação selecionada.")
            continue

        # =========================================================
        # EXECUÇÃO TX
        # =========================================================
        results = run_tx_scan(selected_hash)

        if not results:
            print("[!] Não foi possível analisar a transação.")
            continue

        history.append(results)

        # =========================================================
        # MENU PÓS TX
        # =========================================================
        while True:
            print("\nO que deseja fazer agora?")
            print("[1] Analisar outra transação desta carteira")
            print("[2] Gerar relatório (última TX)")
            print("[3] Gerar relatório consolidado")
            print("[4] Voltar ao menu principal")

            choice = input("Opção: ").strip()

            if choice == "1":
                break

            elif choice == "2":
                print("[+] Gerando relatório da transação atual...")
                generate_tx_report(results)

            elif choice == "3":
                print("[+] Gerando relatório consolidado...")
                generate_consolidated_report(history, save_to_file=True)

            elif choice == "4":
                return "EXIT"

            else:
                print("[!] Opção inválida.")