import requests
import re
from typing import Dict, Optional
from utils.common.rate_limit import rate_limit

IPINFO_URL = "https://ipinfo.io/{}/json"
BGPVIEW_URL = "https://api.bgpview.io/ip/{}"

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


# -------------------------
# VALIDA IP
# -------------------------
def is_valid_ip(ip: str) -> bool:
    if not ip or not IPV4_REGEX.match(ip):
        return False

    try:
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    except:
        return False


# -------------------------
# IPINFO (PRIORIDADE)
# -------------------------
def lookup_ipinfo(ip: str) -> Optional[Dict]:
    try:
        r = requests.get(IPINFO_URL.format(ip), timeout=3)

        if r.status_code != 200:
            return None

        data = r.json()
        org = data.get("org")

        if not org or not org.startswith("AS"):
            return None

        parts = org.split(" ", 1)
        asn = parts[0]
        org_name = parts[1] if len(parts) > 1 else ""

        return {
            "ip": ip,
            "asn": asn,
            "org": org_name,
            "source": "ipinfo",
            "confidence": "MEDIUM"
        }

    except Exception:
        return None


# -------------------------
# BGPVIEW (FALLBACK)
# -------------------------
def lookup_bgpview(ip: str) -> Optional[Dict]:
    try:
        r = requests.get(BGPVIEW_URL.format(ip), timeout=3)

        if r.status_code != 200:
            return None

        data = r.json().get("data", {})
        prefixes = data.get("prefixes", [])

        if not prefixes:
            return None

        first = prefixes[0]
        asn_data = first.get("asn", {})

        asn = asn_data.get("asn")
        org = asn_data.get("description")

        if not asn:
            return None

        return {
            "ip": ip,
            "asn": f"AS{asn}",
            "org": org or "",
            "source": "bgpview",
            "confidence": "LOW"
        }

    except Exception:
        return None


# -------------------------
# MAIN
# -------------------------
def get_asn_from_ip(ip: str) -> Optional[Dict]:

    if not is_valid_ip(ip):
        return None

    rate_limit("asn", delay=0.3)

    # PRIORIDADE: IPINFO (rápido)
    result = lookup_ipinfo(ip)
    if result:
        return result

    # FALLBACK: BGPVIEW
    result = lookup_bgpview(ip)
    if result:
        return result

    return None