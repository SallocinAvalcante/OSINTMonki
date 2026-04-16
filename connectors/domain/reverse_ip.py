import socket
import re
from typing import List, Set, Dict

# -------------------------
# CONFIG
# -------------------------
INVALID_KEYWORDS = [
    "localhost",
    "localdomain",
    "in-addr.arpa"
]

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$"
)

IPV4_REGEX = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)


# -------------------------
# VALIDADOR
# -------------------------
def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False

    domain = domain.lower().strip()

    if any(k in domain for k in INVALID_KEYWORDS):
        return False

    if not DOMAIN_REGEX.match(domain):
        return False

    return True


# -------------------------
# VALIDA IP
# -------------------------
def is_valid_ip(ip: str) -> bool:
    if not IPV4_REGEX.match(ip):
        return False

    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# -------------------------
# PTR LOOKUP
# -------------------------
def reverse_ip_lookup(ip: str) -> List[str]:
    try:
        result = socket.gethostbyaddr(ip)

        hostnames = [result[0]] + result[1]

        clean = []

        for h in hostnames:
            h = h.lower().strip()

            if is_valid_domain(h):
                clean.append(h)

        return list(set(clean))

    except Exception:
        return []


# -------------------------
# EXTRAÇÃO DE IPs DOS FINDINGS
# -------------------------
def extract_ips(findings) -> Set[str]:
    ips = set()

    for f in findings:
        meta = getattr(f, "meta", {})

        # padrão principal
        ip = meta.get("ip")
        if ip and is_valid_ip(ip):
            ips.add(ip)

        # fallback robusto
        value = getattr(f, "value", "")
        if value:
            matches = IPV4_REGEX.findall(value)

            for m in matches:
                if is_valid_ip(m):
                    ips.add(m)

    return ips


# -------------------------
# MAIN PIVOT (PADRÃO NOVO)
# -------------------------
def reverse_ip_pivot(findings, max_ips: int = 10) -> List[Dict]:
    print("[ReverseIP] Iniciando pivot...")

    results: List[Dict] = []
    seen_domains: Set[str] = set()

    ips = list(extract_ips(findings))[:max_ips]

    if not ips:
        print("[ReverseIP] Nenhum IP encontrado nos findings.")
        return []

    for ip in ips:
        print(f"[ReverseIP] -> {ip}")

        resolved = reverse_ip_lookup(ip)

        if not resolved:
            print("[ReverseIP] Nenhum domínio via PTR.")
            continue

        for domain in resolved:
            if domain in seen_domains:
                continue

            seen_domains.add(domain)

            print(f"[ReverseIP] Encontrado: {domain}")

            results.append({
                "domain": domain,
                "ip": ip,
                "source": "ptr",
                "confidence": "LOW"  # PTR geralmente é fraco
            })

    print(f"[ReverseIP] {len(results)} domínios únicos encontrados.")

    return results