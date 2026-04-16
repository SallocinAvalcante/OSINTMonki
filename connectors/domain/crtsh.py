import requests
import re
import time

from models.findings import Finding
from utils.domain.resolver import resolve_domain
from utils.common.cache import cache_get, cache_set
from utils.common.rate_limit import rate_limit

CRT_SH_URL = "https://crt.sh/"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

NOISE_KEYWORDS = [
    "dev", "test", "staging", "qa", "internal",
    "corp", "sandbox", "beta", "local"
]

MAX_SUBDOMAINS = 200


# -------------------------
# UTILS
# -------------------------
def normalize(sub: str) -> str:
    return sub.lower().strip().rstrip(".")


def is_valid_subdomain(sub: str, domain: str) -> bool:
    sub = normalize(sub)

    if not sub.endswith(domain):
        return False

    if "@" in sub:
        return False

    if sub.startswith("*."):
        sub = sub[2:]

    return True


def resolves(sub: str) -> bool:
    ips = resolve_domain(sub)
    return len(ips) > 0


# -------------------------
# EXTRAÇÃO HTML
# -------------------------
def extract_from_html(html: str, domain: str):
    subdomains = set()

    pattern = rf"\b([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})\b"
    matches = re.findall(pattern, html)

    for sub in matches:
        if is_valid_subdomain(sub, domain):
            subdomains.add(normalize(sub))

        if len(subdomains) >= MAX_SUBDOMAINS:
            break

    return subdomains


# -------------------------
# EXTRAÇÃO JSON
# -------------------------
def extract_from_json(data, domain):
    subdomains = set()

    for entry in data[:500]:  # reduzido (era 1000)
        name_value = entry.get("name_value", "")

        for sub in name_value.split("\n"):
            if is_valid_subdomain(sub, domain):
                subdomains.add(normalize(sub))

        if len(subdomains) >= MAX_SUBDOMAINS:
            break

    return subdomains


# -------------------------
# REQUEST (FAIL-FAST)
# -------------------------
def safe_request(params, attempts=2, timeout=10):
    for i in range(attempts):
        try:
            response = requests.get(
                CRT_SH_URL,
                params=params,
                headers=HEADERS,
                timeout=timeout
            )

            if response.status_code == 200:
                return response

            print(f"[crt.sh] HTTP {response.status_code}, tentativa {i+1}")

        except requests.RequestException as e:
            print(f"[crt.sh] Erro tentativa {i+1}: {e}")

        # FAIL-FAST → não fica insistindo
        if i == 1:
            break

        time.sleep(1.5)

    return None


# -------------------------
# PIVOT TLS (CONTROLADO)
# -------------------------
def pivot_crtsh(domains: list[str]) -> list[str]:
    print("[crt.sh] Pivot TLS...")

    discovered = set()

    for domain in domains[:10]:  # REDUÇÃO CRÍTICA
        print(f"[crt.sh] -> {domain}")

        rate_limit("crtsh", delay=1.5)

        # JSON primeiro (mais eficiente)
        response = safe_request({"q": domain, "output": "json"})

        if response:
            try:
                data = response.json()
                discovered.update(extract_from_json(data, domain))
                continue
            except Exception:
                pass

        # fallback HTML
        response = safe_request({"q": domain})

        if response:
            discovered.update(extract_from_html(response.text, domain))

    print(f"[crt.sh] {len(discovered)} novos domínios via pivot.")

    return list(discovered)


# -------------------------
# MAIN
# -------------------------
def search_crtsh(domain: str) -> list[Finding]:
    print(f"[crt.sh] Buscando por: {domain}")

    cache_key = f"crtsh:{domain}"
    cached = cache_get(cache_key)
    if cached:
        print("[crt.sh] Resultado vindo do cache.")
        return cached

    subdomains = set()

    print("[crt.sh] Tentando HTML...")

    rate_limit("crtsh", delay=1.5)

    response = safe_request({"q": domain})

    if response:
        subdomains = extract_from_html(response.text, domain)
        print(f"[crt.sh] {len(subdomains)} encontrados via HTML")

    if len(subdomains) < 10:
        print("[crt.sh] Tentando JSON...")

        rate_limit("crtsh", delay=1.5)

        response = safe_request({"q": f"%.{domain}", "output": "json"})

        if response:
            try:
                data = response.json()
                subdomains.update(extract_from_json(data, domain))
            except Exception:
                print("[crt.sh] JSON inválido")

    print(f"[crt.sh] {len(subdomains)} subdomínios brutos coletados.")

    results = []

    for sub in subdomains:
        meta = {
            "resolved": resolves(sub)
        }

        results.append(
            Finding(
                source="crt.sh",
                type="subdomain",
                value=sub,
                severity="LOW",
                meta=meta
            )
        )

    cache_set(cache_key, results)

    return results