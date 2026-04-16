import os
import requests
from dotenv import load_dotenv
from models.findings import Finding
from time import sleep

load_dotenv()

CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
CENSYS_URL = "https://search.censys.io/api/v2/hosts/search"


# -------------------------
# CORE REQUEST
# -------------------------
def _censys_query(query: str) -> list:
    if not CENSYS_API_SECRET:
        print("[Censys] API não configurada.")
        return []

    headers = {
        "Authorization": f"Bearer {CENSYS_API_SECRET}",
        "Content-Type": "application/json"
    }

    payload = {
        "q": query,
        "per_page": 5
    }

    try:
        response = requests.post(
            CENSYS_URL,
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.status_code != 200:
            print(f"[Censys] HTTP {response.status_code}")
            return []

        data = response.json()
        return data.get("result", {}).get("hits", [])

    except requests.RequestException as e:
        print(f"[Censys] Erro: {e}")
        return []


# -------------------------
# 1. BASE (DOMÍNIO INICIAL)
# -------------------------
def search_censys_base(domain: str) -> list[Finding]:
    print("[Censys] BASE query...")

    findings = []

    query = f'services.tls.certificates.leaf_data.names: "{domain}"'

    hits = _censys_query(query)

    for hit in hits:
        ip = hit.get("ip", "N/A")

        findings.append(
            Finding(
                source="Censys",
                type="base_host",
                value=f"{ip} | {domain}",
                severity="MEDIUM",
                meta={
                    "ip": ip,
                    "domain": domain
                }
            )
        )

    print(f"[Censys] {len(findings)} hosts (base).")

    return findings


# -------------------------
# 2. PIVOT (EXPANSÃO)
# -------------------------
def search_censys_pivot(domains: list[str]) -> list[Finding]:
    print("[Censys] Pivot query...")

    findings = []

    for domain in domains[:10]:
        print(f"[Censys] -> {domain}")

        query = (
            f'services.tls.certificates.leaf_data.names: "{domain}" OR '
            f'services.tls.certificates.leaf_data.names: "*.{domain}"'
        )

        hits = _censys_query(query)

        if not hits:
            continue

        for hit in hits:
            ip = hit.get("ip", "N/A")

            findings.append(
                Finding(
                    source="Censys",
                    type="pivot_host",
                    value=f"{ip} | {domain}",
                    severity="HIGH",
                    meta={
                        "ip": ip,
                        "pivot_domain": domain
                    }
                )
            )

        sleep(1)  # evita rate

    print(f"[Censys] {len(findings)} hosts (pivot).")

    return findings