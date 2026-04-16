from typing import List, Dict
import time

from models.findings import Finding

# connectors
from connectors.domain.crtsh import search_crtsh, pivot_crtsh
from connectors.domain.certspotter import pivot_certspotter
from connectors.domain.reverse_ip import reverse_ip_lookup

# modules-domain
from modules.domain.pivot import build_pivot_targets
from modules.domain.dns_bruteforce import dns_bruteforce
from modules.domain.http_probe import http_probe
from modules.domain.fingerprint import fingerprint_services
from modules.domain.origin_discovery import discover_origin

# network
from modules.network.cdn_detector import is_cloudflare
from modules.network.asn_lookup import get_asn_from_ip
from modules.network.asn_expansion import expand_asn

# scoring
from core.scoring.domain.risk_engine import calculate_risk_score


HIGH_PRIORITY = ["login", "auth", "api", "secure", "admin"]
MEDIUM_PRIORITY = ["mail", "vpn", "portal", "account"]


def extract_ip(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("ip") or item.get("value")
    return None


def is_valid_ip(ip: str) -> bool:
    return bool(ip and ip.count(".") == 3)


def clean_domain_input(values: List[str]) -> List[str]:
    clean = []

    for v in values:
        if not isinstance(v, str):
            continue

        v = v.strip().lower()

        if not v or v.startswith("http"):
            continue

        if any(x in v for x in [" ", "|", "/"]):
            continue

        if "." not in v:
            continue

        v = v.replace("https://", "").replace("http://", "").strip("/")

        clean.append(v)

    return list(set(clean))


def prioritize_subdomains(subdomains: List[str]) -> List[str]:
    def score(sub: str) -> int:
        s = sub.lower()

        if any(k in s for k in HIGH_PRIORITY):
            return 3
        if any(k in s for k in MEDIUM_PRIORITY):
            return 2
        return 1

    return sorted(list(set(subdomains)), key=score, reverse=True)


def build_http_findings(probe_results: List[dict]) -> List[Finding]:
    return [
        Finding(
            source="http_probe",
            type="web_service",
            value=r.get("url"),
            severity="LOW",
            meta=r
        )
        for r in probe_results if r.get("url")
    ]


def cluster_by_ip(probe_results: List[dict]) -> Dict[str, List[str]]:
    clusters: Dict[str, List[str]] = {}

    for r in probe_results:
        ip = r.get("ip")
        host = r.get("host")

        if not is_valid_ip(ip) or not host:
            continue

        if is_cloudflare(ip):
            continue

        clusters.setdefault(ip, []).append(host)

    return clusters


def run_domain_scan(domain: str, use_censys: bool = False, use_port_scan: bool = False) -> dict:

    start_time = time.time()

    print("[+] Coletando subdomínios...")

    # CRT + CERTSPOTTER
    crtsh_results = search_crtsh(domain)
    certspotter_results = pivot_certspotter([domain])

    subdomains = (
        [getattr(f, "value", "") for f in crtsh_results if getattr(f, "value", "")]
        + certspotter_results
    )

    dns_results = dns_bruteforce(domain)
    subdomains = list(set(subdomains + dns_results))

    prioritized_subdomains = prioritize_subdomains(subdomains)

    if domain not in prioritized_subdomains:
        prioritized_subdomains.insert(0, domain)

    print(f"[+] {len(prioritized_subdomains)} subdomínios priorizados.")

    # HTTP
    print("[+] HTTP probing...")
    probe_results = http_probe(prioritized_subdomains[:40])
    probe_results = fingerprint_services(probe_results)

    http_findings = build_http_findings(probe_results)
    ip_clusters = cluster_by_ip(probe_results)

    # INFRA
    infra_ips = set()

    for r in probe_results:
        ip = r.get("ip")

        if not is_valid_ip(ip) or is_cloudflare(ip):
            continue

        infra_ips.add(ip)

    # ORIGIN
    print("[+] Origin discovery...")
    origin_results = discover_origin(domain) or []

    dedup = {}
    for o in origin_results:
        ip = extract_ip(o)
        score = o.get("meta", {}).get("score", 0)

        if not ip:
            continue

        if ip not in dedup or score > dedup[ip].get("meta", {}).get("score", 0):
            dedup[ip] = o

    clean_origins = []

    for origin in dedup.values():
        ip = extract_ip(origin)

        if not is_valid_ip(ip) or is_cloudflare(ip):
            continue

        infra_ips.add(ip)
        clean_origins.append(origin)

    # ASN
    expanded_ips = []
    asn_map = {}
    seen_asns = set()

    if infra_ips:
        print("[+] ASN mapping...")

        for ip in list(infra_ips)[:3]:
            asn_data = get_asn_from_ip(ip)
            if not asn_data:
                continue

            asn = asn_data.get("asn")
            if not asn or asn in seen_asns:
                continue

            seen_asns.add(asn)
            asn_map[ip] = asn_data

            try:
                expanded_ips += expand_asn(asn)[:10]
            except:
                continue

    # PORT SCAN
    port_results = []

    if use_port_scan:
        from modules.network.port_scan import port_scan

        safe_ips = [ip for ip in infra_ips if not is_cloudflare(ip)]
        port_results = port_scan(list(safe_ips)[:5])

    # TLS PIVOT (FIX CRÍTICO)
    print("[+] TLS pivot...")

    pivot_sources = (
        crtsh_results +
        http_findings +
        [Finding(source="certspotter", type="domain", value=d, severity="LOW") for d in subdomains]
    )

    raw_targets = build_pivot_targets(pivot_sources, domain)
    pivot_targets = clean_domain_input(raw_targets)

    print(f"[Pivot] Raw: {len(raw_targets)} | Limpos: {len(pivot_targets)}")

    pivot_targets = pivot_targets[:15]

    crt_pivot_targets = pivot_crtsh(pivot_targets[:10])
    certspotter_targets = pivot_certspotter(pivot_targets[:10])

    all_pivot_targets = list(set(
        pivot_targets +
        crt_pivot_targets +
        certspotter_targets
    ))[:30]

    print(f"[+] {len(all_pivot_targets)} alvos TLS finais.")

    # REVERSE IP
    print("[+] Reverse IP...")

    reverse_results = []
    seen_domains = set()
    candidate_ips = set()

    for r in probe_results:
        ip = r.get("ip")
        if is_valid_ip(ip) and not is_cloudflare(ip):
            candidate_ips.add(ip)

    for o in clean_origins:
        ip = extract_ip(o)
        if is_valid_ip(ip) and not is_cloudflare(ip):
            candidate_ips.add(ip)

    for entry in expanded_ips:
        ip = entry.get("ip")
        if is_valid_ip(ip) and not is_cloudflare(ip):
            candidate_ips.add(ip)

    for ip in list(candidate_ips)[:8]:
        for d in reverse_ip_lookup(ip):
            if d in seen_domains:
                continue

            seen_domains.add(d)

            reverse_results.append(
                Finding(
                    source="reverse_ip",
                    type="related_domain",
                    value=d,
                    severity="MEDIUM",
                    meta={"ip": ip}
                )
            )

    # AGREGAÇÃO
    all_findings = (
        crtsh_results +
        http_findings +
        reverse_results
    )

    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for f in all_findings:
        if f.severity in severity_count:
            severity_count[f.severity] += 1

    elapsed = round(time.time() - start_time, 2)

    results = {
        "domain": domain,
        "crtsh": crtsh_results,
        "http": http_findings,
        "reverse": reverse_results,
        "pivot_targets": all_pivot_targets,
        "origins": clean_origins,
        "asn": asn_map,
        "asn_expanded": expanded_ips,
        "ip_clusters": ip_clusters,
        "ports": port_results,
        "total": len(all_findings),
        "severity": severity_count,
        "time": elapsed,
    }

    results["risk"] = calculate_risk_score(results)

    return results