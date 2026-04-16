import socket
import ipaddress
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

TIMEOUT = 1
MAX_THREADS = 100

#  Portas comuns para detecção inicial (pode ser expandida conforme necessidade)
COMMON_PORTS = [
    # Web
    80, 443, 8080, 8443,

    # Infra / acesso
    22,    # SSH
    21,    # FTP
    3389,  # RDP
    5900,  # VNC

    # Banco / cache
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    27017, # MongoDB

    # Windows / rede interna
    135, 139, 445,  # RPC / SMB

    # Mail
    25, 110, 143, 465, 587, 993, 995,

    # DNS
    53
]


# -------------------------
# VALIDATION
# -------------------------
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def resolve_target(target: str) -> str | None:
    if validate_ip(target):
        return target

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# -------------------------
# SERVICE DETECTION
# -------------------------
def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


# -------------------------
# BANNER GRAB
# -------------------------
def grab_banner(ip: str, port: int) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))

            # tentativa genérica
            s.send(b"\r\n")
            return s.recv(512).decode(errors="ignore").strip()

    except Exception:
        return None


# -------------------------
# SCAN PORT
# -------------------------
def scan_port(ip: str, port: int, grab: bool = False) -> Dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)

            if sock.connect_ex((ip, port)) == 0:
                result = {
                    "ip": ip,
                    "port": port,
                    "service": get_service(port)
                }

                if grab:
                    banner = grab_banner(ip, port)
                    if banner:
                        result["banner"] = banner

                return result

    except Exception:
        return None

    return None


# -------------------------
# MAIN
# -------------------------
def port_scan(
    targets: List[str],
    ports: List[int] = None,
    max_ips: int = 10,
    grab_banner_enabled: bool = False
) -> List[Dict]:

    if ports is None:
        ports = COMMON_PORTS

    # -------------------------
    # RESOLVE
    # -------------------------
    resolved_ips = []

    for t in targets:
        ip = resolve_target(t)
        if ip:
            resolved_ips.append(ip)
        else:
            print(f"[PORT] Falha ao resolver: {t}")

    if not resolved_ips:
        print("[PORT] Nenhum alvo válido.")
        return []

    # remove duplicados
    resolved_ips = list(set(resolved_ips))

    if len(resolved_ips) > max_ips:
        print(f"[PORT] Limitando para {max_ips} IPs")

    resolved_ips = resolved_ips[:max_ips]

    print("[PORT] Iniciando scan...")

    # -------------------------
    # EXECUÇÃO CONCORRENTE
    # -------------------------
    results_map: Dict[str, List[Dict]] = {ip: [] for ip in resolved_ips}

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        futures = []

        for ip in resolved_ips:
            for port in ports:
                futures.append(
                    executor.submit(scan_port, ip, port, grab_banner_enabled)
                )

        for future in as_completed(futures):
            try:
                res = future.result()
                if not res:
                    continue

                ip = res["ip"]
                results_map[ip].append(res)

            except Exception:
                continue

    # -------------------------
    # FORMATAÇÃO FINAL
    # -------------------------
    final_results = []

    for ip, ports_data in results_map.items():

        ports_sorted = sorted(ports_data, key=lambda x: x["port"])

        final_results.append({
            "ip": ip,
            "ports": ports_sorted,
            "total_open": len(ports_sorted),
            "scanned_at": datetime.now(timezone.utc).isoformat()
        })

        print(f"[PORT] {ip} -> {len(ports_sorted)} portas abertas")

    return final_results