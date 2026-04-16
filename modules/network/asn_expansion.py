import requests
import ipaddress
from typing import List, Dict, Set
from utils.common.rate_limit import rate_limit

BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{}/prefixes"


# -------------------------
# CIDR -> IPs (limitado)
# -------------------------
def cidr_to_ips(cidr: str, max_ips: int = 3) -> List[str]:
    ips = []

    try:
        network = ipaddress.ip_network(cidr, strict=False)

        for i, ip in enumerate(network.hosts()):
            ips.append(str(ip))
            if i >= max_ips:
                break

    except Exception:
        return []

    return ips


# -------------------------
# BGPVIEW
# -------------------------
def get_cidrs_bgpview(asn_clean: str) -> List[str]:
    try:
        r = requests.get(BGPVIEW_ASN_URL.format(asn_clean), timeout=4)

        if r.status_code != 200:
            return []

        data = r.json()
        prefixes = data.get("data", {}).get("ipv4_prefixes", [])

        return list(set(
            [p.get("prefix") for p in prefixes if p.get("prefix")]
        ))

    except Exception:
        return []


# -------------------------
# MAIN
# -------------------------
def expand_asn(asn: str, max_prefixes: int = 2) -> List[Dict]:

    if not asn:
        return []

    print(f"[ASN] Expandindo {asn}...")

    rate_limit("asn_expand", delay=0.3)

    asn_clean = asn.replace("AS", "")

    cidrs = get_cidrs_bgpview(asn_clean)

    if not cidrs:
        print(f"[ASN] Nenhum CIDR encontrado para {asn}")
        return []

    results: List[Dict] = []
    seen_ips: Set[str] = set()

    for cidr in cidrs[:max_prefixes]:

        ips = cidr_to_ips(cidr)

        for ip in ips:
            if ip in seen_ips:
                continue

            seen_ips.add(ip)

            results.append({
                "ip": ip,
                "asn": asn,
                "cidr": cidr,
                "source": "asn_expansion",
                "confidence": "LOW"
            })

    print(f"[ASN] {len(results)} IPs gerados.")

    return results