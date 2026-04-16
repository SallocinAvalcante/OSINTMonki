import time
from typing import List

from utils.domain.resolver import resolve_domain
from utils.common.rate_limit import rate_limit

# -------------------------
# WORDLIST BASE
# -------------------------
COMMON = [
    "www", "mail", "api", "admin", "dev", "test",
    "portal", "dashboard", "app", "beta"
]

TECH = [
    "grafana", "jenkins", "kibana", "prometheus",
    "monitor", "metrics", "logs"
]

CORP = [
    "internal", "corp", "vpn", "gateway",
    "sso", "auth", "secure"
]


# -------------------------
# WORDLIST DINÂMICA
# -------------------------
def generate_dynamic_words(domain: str) -> List[str]:
    base = domain.split(".")[0]

    return [
        base,
        f"{base}-api",
        f"{base}-dev",
        f"{base}-admin",
        f"api-{base}",
        f"dev-{base}"
    ]


def build_wordlist(domain: str) -> List[str]:
    dynamic = generate_dynamic_words(domain)
    return list(set(COMMON + TECH + CORP + dynamic))


# -------------------------
# VALIDAÇÃO (ANTI-WILDCARD)
# -------------------------
def is_real_subdomain(sub: str) -> bool:
    ips = resolve_domain(sub)

    if not ips:
        return False

    #  teste de wildcard
    try:
        base_domain = sub.split(".", 1)[1]
        random_test = f"nonexistent123456.{base_domain}"
        random_ips = resolve_domain(random_test)

        # se resolver igual = wildcard DNS
        if set(ips) == set(random_ips):
            return False

    except:
        pass

    return True


# -------------------------
# MAIN
# -------------------------
def dns_bruteforce(domain: str, max_results: int = 20) -> List[str]:
    print("[DNS] Iniciando bruteforce...")

    found = []
    wordlist = build_wordlist(domain)

    for sub in wordlist:
        rate_limit("dns", delay=0.2)

        target = f"{sub}.{domain}"

        try:
            if is_real_subdomain(target):
                print(f"[DNS] Encontrado: {target}")
                found.append(target)

            if len(found) >= max_results:
                break

        except Exception:
            continue

    print(f"[DNS] {len(found)} subdomínios encontrados.")

    return found