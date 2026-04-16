import sys
import time
from core.output import typewriter
from utils.common.cache import clear_cache
from core.reports.domain_report import generate_domain_report

# -------------------------
# CORES ANSI
# -------------------------
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"

ULTRAFAST = 0.001
FAST = 0.002
NORMAL = 0.01


# -------------------------
# BANNER
# -------------------------
def print_banner() -> None:
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
                           OSINTMonki v0.1
......................................................................
..............................+######*****-......................:::..
...........................=####**++++++++**+.........................
........................:+%#####***++++++*****-.......................
.....................+#%%%%%%%%%%%#########****:......................
...................-*%#*****+++==*#%%#+--=*%#***......................
..................:#*=..:::::*#*+------=#**===*#*--...................
.................-+#:.....-##-=#*####%##::=-....:###+:................
.................=#=.....-    :=*###@#*::   .-:. .***=-...............
.................=#+.....::*+#.=###%%#*::%*# -:::-=#+=+...............
.................==#= ...:.*%#-*#%%%%%#-:#%%-:::--=**-=...............
..................==##-..:---+#%%@%#@%%#:.:..:::-=**=+................
.................*+:-+%%%##%#%#+=====+*%%#=:::-=##*-=.................
................=%#---++#%#***-::::::--=+*#%%%%%*=--+-................
...............=%%%####%+**+=-++::...:::-=+*###*+#**##*...............
..............=%%%####%=..=+++=---+#**=-==+**:.+#%%%#**#..............
.............+%%%%#####..:#%%*===++++++++*%#+...+%%%##***:............
............=%%%%##*#%*#%##%%%%%%%%%%%%%%######*:#%%%##**#............
............%%%%#####%%%###%%%%%%%%%%%%########%%%%%%%##*#*...........
...........=#%%%##*#%%%%#%%%%%%%#########%%%####%@%%%%##***:..........
...........+#%%%###%%%%%%%%@%%%%%###****##%%%%%#%%%%%%%#**#:..........
...........=#%%###%%%%%%%%%%%%%%%##******##%%%%%%%%%%%%####:..........
............*%%%%%%%%%%%%=%%%%%%%##*******##%%%%%%%%%%%%##*:..........

{Colors.RESET}
"""
    typewriter(banner, ULTRAFAST)


# -------------------------
# MENU
# -------------------------
def show_menu() -> None:
    typewriter(f"\n{Colors.GREEN}=== OSINTMonki ==={Colors.RESET}\n", NORMAL)
    typewriter(f"{Colors.GREEN}[1]{Colors.RESET} Recon de Domínio\n", FAST)
    typewriter(f"{Colors.YELLOW}[2]{Colors.RESET} Análise de TX (Blockchain)\n", FAST)
    typewriter(f"{Colors.RED}[3]{Colors.RESET} Sair\n", FAST)


def get_user_choice() -> str:
    return input(f"\nOpção: ").strip()


# -------------------------
# HANDLER
# -------------------------
def handle_choice(choice: str) -> None:

    # -------------------------
    # DOMAIN SCAN
    # -------------------------
    if choice == "1":
        from modules.domain.domain_scan import run_domain_scan

        while True:
            domain = input(f"\n{Colors.GREEN}Digite o domínio:{Colors.RESET} ").strip()

            if not domain:
                print(f"{Colors.RED}Domínio inválido.{Colors.RESET}")
                continue

            # -------------------------
            # PASSIVO / ATIVO
            # -------------------------
            print("\nModo de Reconhecimento:")
            print("[1] Passivo (seguro, não expõe seu IP)")
            print("[2] Ativo (port scan - pode expor seu IP)")

            mode_choice = input("Opção: ").strip()
            use_port_scan = mode_choice == "2"

            # -------------------------
            # ENRICHMENT
            # -------------------------
            print("\nDeseja enriquecer com Censys/Shodan?")
            print("[1] Não")
            print("[2] Sim (necessário API na .env)")

            enrich_choice = input("Opção: ").strip()
            use_censys = enrich_choice == "2"

            # -------------------------
            # EXECUÇÃO
            # -------------------------
            typewriter(f"\n{Colors.GREEN}[+] Inicializando Recon...{Colors.RESET}\n", NORMAL)
            time.sleep(0.5)

            start = time.time()

            results = run_domain_scan(
                domain,
                use_censys=use_censys,
                use_port_scan=use_port_scan
            )

            elapsed = round(time.time() - start, 2)

            typewriter(
                f"\n{Colors.GREEN}[✓] Scan finalizado em {elapsed}s{Colors.RESET}\n",
                NORMAL
            )

            # -------------------------
            # PÓS-SCAN LOOP
            # -------------------------
            while True:
                print(f"\n{Colors.GREEN}O que deseja fazer agora?{Colors.RESET}")
                print("[1] Consultar outro domínio")
                print("[2] Gerar relatório (TXT)")
                print("[3] Voltar ao menu")

                post_choice = input("Opção: ").strip()

                if post_choice == "1":
                    break

                elif post_choice == "2":
                    print(f"{Colors.GREEN}[+] Gerando relatório...{Colors.RESET}")
                    generate_domain_report(results)

                elif post_choice == "3":
                    clear_cache()
                    return

                else:
                    print(f"{Colors.RED}Opção inválida.{Colors.RESET}")

    # -------------------------
    # TX MODULE
    # -------------------------
    elif choice == "2":
        from modules.blockchain.tx_scan import run_tx_scan
        from modules.blockchain.address_scan import run_address_scan
        from utils.blockchain.resolver import detect_input_type
        from core.reports.tx_report import generate_tx_report

        while True:
            target = input(f"\n{Colors.YELLOW}Digite o hash ou endereço:{Colors.RESET} ").strip()

            if not target:
                print(f"{Colors.RED}Entrada inválida.{Colors.RESET}")
                continue

            # -------------------------
            # DETECT INPUT TYPE
            # -------------------------
            input_data = detect_input_type(target)

            if not input_data:
                print(f"{Colors.RED}[!] Não foi possível identificar o tipo de entrada.{Colors.RESET}")
                continue

            input_type = input_data.get("type")

            # -------------------------
            # ADDRESS FLOW
            # -------------------------
            if input_type == "address":
                print(f"{Colors.BOLD}[+] Endereço detectado. Expandindo transações...{Colors.RESET}")

                result = run_address_scan(target)

                if result == "EXIT":
                    clear_cache()
                    print(f"{Colors.YELLOW}[+] Retornando ao menu principal...{Colors.RESET}")
                    return

                elif result == "BACK":
                    continue

                continue

            # -------------------------
            # EXECUÇÃO (TX)
            # -------------------------
            typewriter(f"\n{Colors.YELLOW}[+] Iniciando análise de transação...{Colors.RESET}\n", NORMAL)
            time.sleep(0.5)

            start = time.time()

            #   Sem escolha manual, provider manager vai identificar melhor fonte de dados (on-chain + off-chain) para cada caso
            results = run_tx_scan(target)

            if not results:
                print(f"{Colors.RED}[!] Falha ao obter dados da transação.{Colors.RESET}")
                continue

            elapsed = round(time.time() - start, 2)

            typewriter(
                f"\n{Colors.GREEN}[✓] Análise finalizada em {elapsed}s{Colors.RESET}\n",
                NORMAL
            )

            # -------------------------
            # PÓS-SCAN
            # -------------------------
            while True:
                print(f"\n{Colors.BOLD}O que deseja fazer agora?{Colors.RESET}")
                print("[1] Nova análise")
                print("[2] Gerar relatório (TXT)")
                print("[3] Voltar ao menu")

                post_choice = input("Opção: ").strip()

                if post_choice == "1":
                    break

                elif post_choice == "2":
                    print(f"{Colors.BLUE}[+] Gerando relatório...{Colors.RESET}")
                    generate_tx_report(results)

                elif post_choice == "3":
                    clear_cache()
                    print(f"{Colors.YELLOW}[+] Retornando ao menu principal...{Colors.RESET}")
                    return

                else:
                    print(f"{Colors.RED}Opção inválida.{Colors.RESET}")
    elif choice == "3":
        print(f"{Colors.RED}Saindo...{Colors.RESET}")
        sys.exit(0)