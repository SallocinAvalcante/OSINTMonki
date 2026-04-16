import subprocess
import platform
import re
import socket
import ipaddress
from typing import List, Dict


# -------------------------
# VALIDADORES
# -------------------------
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def sanitize_ip(ip: str) -> str:
    if not ip:
        return ""

    ip = ip.strip()
    ip = ip.replace(",", "").replace(";", "").replace(":", "")
    ip = ip.rstrip(".")

    return ip


# -------------------------
# RESOLVE TARGET
# -------------------------
def resolve_target(target: str) -> str | None:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# -------------------------
# PARSER ROBUSTO
# -------------------------
def parse_traceroute_output(output: str) -> List[Dict]:
    hops = []
    seen_ips = set()

    pattern_win = re.compile(
        r"^\s*(\d+)\s+(?:(\d+)\s*ms\s+(\d+)\s*ms\s+(\d+)\s*ms\s+([\d\.]+)|(\*\s*\*\s*\*))"
    )

    pattern_linux = re.compile(
        r"^\s*(\d+)\s+(?:.*?\(?([\d\.]+)\)?.*?(\d+\.\d+)\s*ms|(\*))"
    )

    for line in output.splitlines():

        hop_data = None

        m_win = pattern_win.match(line)
        m_linux = pattern_linux.match(line)

        if m_win:
            hop = int(m_win.group(1))

            if m_win.group(6):
                hop_data = {
                    "hop": hop,
                    "ip": "*",
                    "rtt_ms": None,
                    "filtered": True
                }
            else:
                raw_ip = sanitize_ip(m_win.group(5))

                if not is_valid_ip(raw_ip):
                    continue

                if raw_ip in seen_ips:
                    continue

                seen_ips.add(raw_ip)

                rtts = [int(m_win.group(i)) for i in (2, 3, 4)]

                hop_data = {
                    "hop": hop,
                    "ip": raw_ip,
                    "rtt_ms": round(sum(rtts) / len(rtts), 2),
                    "filtered": False
                }

        elif m_linux:
            hop = int(m_linux.group(1))

            if m_linux.group(4):
                hop_data = {
                    "hop": hop,
                    "ip": "*",
                    "rtt_ms": None,
                    "filtered": True
                }
            else:
                raw_ip = sanitize_ip(m_linux.group(2))

                if not is_valid_ip(raw_ip):
                    continue

                if raw_ip in seen_ips:
                    continue

                seen_ips.add(raw_ip)

                hop_data = {
                    "hop": hop,
                    "ip": raw_ip,
                    "rtt_ms": float(m_linux.group(3)),
                    "filtered": False
                }

        if hop_data:
            hops.append(hop_data)

    return hops


# -------------------------
# CHECK COMPLETION
# -------------------------
def check_completed(target_ip: str, hops: List[Dict]) -> bool:
    if not hops:
        return False

    for hop in reversed(hops):
        ip = hop.get("ip")
        if ip and ip != "*":
            return ip == target_ip

    return False


# -------------------------
# MAIN
# -------------------------
def run_traceroute(target: str, max_hops: int = 20) -> dict:

    resolved = resolve_target(target)

    if not resolved:
        return {
            "target": target,
            "resolved_ip": None,
            "hops": [],
            "completed": False,
            "error": "Alvo inválido"
        }

    system = platform.system().lower()

    if "windows" in system:
        cmd = ["tracert", "-h", str(max_hops), resolved]
    else:
        cmd = ["traceroute", "-m", str(max_hops), resolved]

    timeout = max_hops * 2

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout

        hops = parse_traceroute_output(output)
        completed = check_completed(resolved, hops)

        return {
            "target": target,
            "resolved_ip": resolved,
            "hops": hops,
            "completed": completed,
            "error": None
        }

    except subprocess.TimeoutExpired:
        error_msg = "Timeout excedido"

    except FileNotFoundError:
        error_msg = "Comando traceroute/tracert não encontrado"

    except Exception as e:
        error_msg = str(e)

    return {
        "target": target,
        "resolved_ip": resolved,
        "hops": [],
        "completed": False,
        "error": error_msg
    }