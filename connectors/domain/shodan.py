import os
import shodan
import socket
import time
from dotenv import load_dotenv
from models.findings import Finding

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def resolve_domain(domain: str) -> list[str]:
    """
    Resolve domínio para IPv4 apenas.
    """
    try:
        ips = set()

        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]

            if "." in ip:  # ignora IPv6
                ips.add(ip)

        return list(ips)

    except Exception:
        return []


def extract_ssl_info(service: dict) -> dict:
    """
    Extrai informações relevantes do certificado SSL.
    """
    ssl = service.get("ssl", {})

    if not ssl:
        return {}

    cert = ssl.get("cert", {})

    subject = cert.get("subject", {})
    cn = subject.get("CN")

    san = cert.get("subjectAltName", [])

    return {
        "cn": cn,
        "san": san[:10]  # limita pra não explodir
    }

def pivot_shodan(findings: list[Finding]) -> list[str]:
    """
    Extrai domínios de certificados coletados via Shodan.
    """

    print("[Shodan] Pivot TLS local...")

    domains = set()

    for f in findings:
        ssl = f.meta.get("ssl", {})

        if not ssl:
            continue

        cn = ssl.get("cn")
        if cn and "." in cn:
            domains.add(cn.lower())

        for san in ssl.get("san", []):
            if "." in san:
                domains.add(san.lower())

    print(f"[Shodan] {len(domains)} domínios extraídos.")

    return list(domains)

def search_shodan(
    domain: str,
    extra_targets: list[str] = None,
    delay: float = 1.0,
    max_targets: int = 10
) -> list[Finding]:
    """
    Busca serviços no Shodan usando domínio + subdomínios.
    Agora com extração de TLS (pivot-ready).
    """

    print("[Shodan] Expandindo busca...")

    if not SHODAN_API_KEY:
        print("[Shodan] API key não encontrada.")
        return []

    api = shodan.Shodan(SHODAN_API_KEY)

    targets = [domain]

    if extra_targets:
        targets.extend(extra_targets)

    targets = list(dict.fromkeys(targets))[:max_targets]

    all_results: list[Finding] = []
    seen_ips = set()

    for target in targets:
        print(f"[Shodan] -> Target: {target}")

        ips = resolve_domain(target)

        if not ips:
            print("[Shodan] Não foi possível resolver o domínio.")
            continue

        print(f"[Shodan] IPs encontrados: {', '.join(ips)}")

        for ip in ips:

            if ip in seen_ips:
                continue

            seen_ips.add(ip)

            try:
                host = api.host(ip)

                org = host.get("org", "N/A")
                asn = host.get("asn", "N/A")

                for service in host.get("data", [])[:10]:
                    port = service.get("port", "N/A")

                    data = service.get("data", "")
                    data = " ".join(data.split())
                    snippet = data[:120]

                    #  TLS extraction
                    ssl_info = extract_ssl_info(service)

                    value = f"{ip}:{port} | {org} | {snippet}"

                    all_results.append(
                        Finding(
                            source="Shodan",
                            type="service",
                            value=value,
                            severity="MEDIUM",
                            meta={
                                "ip": ip,
                                "port": port,
                                "org": org,
                                "asn": asn,
                                "ssl": ssl_info
                            }
                        )
                    )

                time.sleep(delay)

            except shodan.APIError as e:
                print(f"[Shodan] Erro ao consultar IP {ip}: {e}")

        time.sleep(delay)

    if all_results:
        print(f"[Shodan] {len(all_results)} serviços encontrados.")
    else:
        print("[Shodan] Nenhum serviço encontrado.")

    return all_results