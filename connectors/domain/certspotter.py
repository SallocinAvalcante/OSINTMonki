import requests
from models.findings import Finding
from utils.common.cache import cache_get, cache_set
from utils.common.rate_limit import rate_limit

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

HEADERS = {
    "User-Agent": "OSINTMonki/1.0"
}


def search_certspotter(domain: str) -> list[Finding]:
    print(f"[CertSpotter] Buscando por: {domain}")

    cache_key = f"certspotter:{domain}"
    cached = cache_get(cache_key)
    if cached:
        print("[CertSpotter] Resultado vindo do cache.")
        return cached

    subdomains = set()

    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names"
    }

    rate_limit("certspotter", delay=1.5)

    try:
        response = requests.get(
            CERTSPOTTER_URL,
            params=params,
            headers=HEADERS,
            timeout=20
        )

        if response.status_code != 200:
            print(f"[CertSpotter] HTTP {response.status_code}")
            return []

        data = response.json()

        for cert in data:
            for dns in cert.get("dns_names", []):
                dns = dns.lower().strip()

                if "." in dns and "*" not in dns and "@" not in dns:
                    subdomains.add(dns)

        print(f"[CertSpotter] {len(subdomains)} subdomínios coletados.")

        findings = []

        for sub in subdomains:
            findings.append(
                Finding(
                    source="CertSpotter",
                    type="subdomain",
                    value=sub,
                    severity="LOW"
                )
            )

        cache_set(cache_key, findings)
        return findings

    except Exception as e:
        print(f"[CertSpotter] Erro: {e}")
        return []


def pivot_certspotter(domains: list[str]) -> list[str]:
    print("[CertSpotter] Pivot TLS...")

    discovered = set()

    for domain in domains[:10]:
        print(f"[CertSpotter] -> {domain}")

        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names"
        }

        rate_limit("certspotter", delay=1.5)

        try:
            response = requests.get(
                CERTSPOTTER_URL,
                params=params,
                headers=HEADERS,
                timeout=20
            )

            if response.status_code != 200:
                print(f"[CertSpotter] HTTP {response.status_code}")
                continue

            data = response.json()

            for cert in data:
                for dns in cert.get("dns_names", []):
                    dns = dns.lower().strip()

                    if "." in dns and "*" not in dns and "@" not in dns:
                        discovered.add(dns)

        except Exception as e:
            print(f"[CertSpotter] Erro: {e}")

    print(f"[CertSpotter] {len(discovered)} novos domínios via pivot.")

    return list(discovered)[:50]