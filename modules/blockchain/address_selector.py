from typing import List, Dict, Optional


def format_tx_line(index: int, tx: Dict) -> str:
    """
    Formata uma linha de exibição da transação
    """

    tx_hash = tx.get("hash", "")[:12]
    value = tx.get("value_btc", 0)
    inputs = tx.get("inputs", 0)
    outputs = tx.get("outputs", 0)

    return f"[{index}] {tx_hash}... | {value} BTC | {inputs} entradas / {outputs} saídas"


def select_transaction(txs: List[Dict]) -> Optional[str]:
    """
    Exibe lista de transações e permite seleção
    """

    if not txs:
        print("[!] Nenhuma transação disponível.")
        return None

    print("\n[+] Transações encontradas:\n")

    # -------------------------
    # LISTAGEM
    # -------------------------
    for i, tx in enumerate(txs, start=1):
        print(format_tx_line(i, tx))

    print("\n[50] Inserir hash manual")
    print("[51] Voltar")
    print("[52] Analisar todas as transações")

    # -------------------------
    # INPUT LOOP
    # -------------------------
    while True:
        choice = input("\nEscolha uma opção: ").strip()

        if not choice.isdigit():
            print("[!] Entrada inválida.")
            continue

        choice = int(choice)

        # -------------------------
        # SELEÇÃO DIRETA
        # -------------------------
        if 1 <= choice <= len(txs):
            selected = txs[choice - 1]
            tx_hash = selected.get("hash")

            print(f"[+] Selecionado: {tx_hash}")
            return tx_hash

        # -------------------------
        # MANUAL
        # -------------------------
        elif choice == 50:
            manual = input("Digite o hash da transação: ").strip()

            if manual:
                return manual

            print("[!] Hash inválido.")

        # -------------------------
        # VOLTAR
        # -------------------------
        elif choice == 51:
            return "BACK"
        
        # ----------------------
        #  ANALISAR TODAS
        # ----------------------
        elif choice == 52:
            return "ALL"
        else:
            print("[!] Opção inválida.")