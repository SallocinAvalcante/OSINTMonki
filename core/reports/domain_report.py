from core.reports.base import create_report_file
from collections import Counter


def normalize(obj):
    if isinstance(obj, dict):
        return obj

    if hasattr(obj, "__dict__"):
        data = obj.__dict__.copy()

        meta = data.get("meta", {})
        if isinstance(meta, dict):
            data.update(meta)

        return data

    return {}


def extract_value(item):
    if isinstance(item, str):
        return item
    return normalize(item).get("value")


def generate_domain_report(results: dict) -> str:

    filepath = create_report_file("domain", results.get("domain", "unknown"))

    lines = []
    sep = "=" * 60

    domain = results.get("domain", "N/A")
    risk = results.get("risk", {})

    http = results.get("http", [])
    ports = results.get("ports", [])
    origins = results.get("origins", [])
    clusters = results.get("ip_clusters", {})
    reverse = results.get("reverse", [])
    crtsh = results.get("crtsh", [])
    pivot_targets = results.get("pivot_targets", [])
    asn_map = results.get("asn", {})

    # HEADER
    lines.append(sep)
    lines.append("OSINTMonki - Relatório de Inteligência")
    lines.append(sep + "\n")

    lines.append(f"Alvo: {domain}")
    lines.append(f"Tempo: {results.get('time')}s\n")

    # RISCO GLOBAL
    lines.append("[AVALIAÇÃO DE RISCO]")
    lines.append(f"Nível: {risk.get('level')} | Score: {risk.get('score')}")

    for r in risk.get("reasons", []):
        lines.append(f"  - {r}")

    lines.append("")

    # ORIGENS
    lines.append("[ORIGENS IDENTIFICADAS]")

    if not origins:
        lines.append("Nenhuma origem identificada.")
    else:
        for o in origins:
            o = normalize(o)

            ip = o.get("value") or o.get("ip")
            conf = o.get("confidence")
            meta = o.get("meta", {})
            score = meta.get("score")
            proto = meta.get("protocol")

            if conf == "high":
                flag = "ALTA"
            elif conf == "medium":
                flag = "MÉDIA"
            else:
                flag = "BAIXA"

            lines.append(f"- {ip} ({proto}) | confiança={flag} | score={score}")

    lines.append("")

    # SUPERFÍCIE DE DOMÍNIOS
    lines.append("[SUPERFÍCIE DE DOMÍNIOS]")

    seen = set()

    for f in crtsh:
        val = extract_value(f)
        if val and val not in seen:
            lines.append(f"- {val} [crtsh]")
            seen.add(val)

    for d in pivot_targets:
        if d and d not in seen:
            lines.append(f"- {d} [pivot]")
            seen.add(d)

    for f in reverse:
        val = extract_value(f)
        if val and val not in seen:
            lines.append(f"- {val} [reverse]")
            seen.add(val)

    if not seen:
        lines.append(f"- {domain} [root]")

    lines.append("")

    # PIVOT
    lines.append("[EXPANSÃO TLS - ALVOS PRIORITÁRIOS]")

    if not pivot_targets:
        lines.append("Nenhum alvo relevante.")
    else:
        for d in pivot_targets:
            flag = ""

            if any(k in d for k in ["admin", "api", "auth", "secure"]):
                flag = " [ALVO CRÍTICO]"
            elif any(k in d for k in ["dev", "staging", "test"]):
                flag = " [ALTO RISCO - AMBIENTE NÃO PROD]"

            lines.append(f"- {d}{flag}")

    lines.append("")

    # WEB
    lines.append("[SUPERFÍCIE WEB]")

    grouped_http = {}

    for raw in http:
        r = normalize(raw)

        if r.get("status") == "NO_DNS":
            continue

        host = (r.get("host") or "").lower()

        if not host:
            continue

        grouped_http.setdefault(host, []).append(r)

    if not grouped_http:
        lines.append("Nenhum serviço identificado.\n")
    else:
        for host, entries in grouped_http.items():
            main = entries[0]

            lines.append(f"- {host}")
            lines.append(f"  IP: {main.get('ip')}")

            has_real_http = False

            for e in entries:
                url = e.get("url")
                status = e.get("status") or "UNKNOWN"

                if isinstance(status, int):
                    has_real_http = True

                lines.append(f"    - {url} -> {status}")

                if any(k in (url or "") for k in ["admin", "login"]):
                    lines.append("      ALERTA: endpoint sensível")

            if not has_real_http:
                lines.append("  Nenhuma resposta HTTP válida coletada")

            techs = main.get("tech_meta", [])
            if techs:
                tech_str = ", ".join(t.get("name") for t in techs)
                lines.append(f"  Tecnologias: {tech_str}")

            wafs = main.get("waf", [])
            if wafs:
                lines.append(f"  Proteção: {', '.join(wafs)}")

            lines.append("")

    # PORTAS
    lines.append("[EXPOSIÇÃO DE SERVIÇOS]")

    if not ports:
        lines.append("Nenhuma porta relevante.")
    else:
        for p in ports:
            p = normalize(p)

            ip = p.get("ip")
            plist = p.get("ports", [])

            if not plist:
                continue

            lines.append(f"IP: {ip}")

            for port in plist:
                if isinstance(port, dict):
                    port_num = port.get("port")
                    service = port.get("service", "unknown")
                else:
                    port_num = port
                    service = "unknown"

                flag = ""
                if port_num in [22, 3389, 3306, 6379]:
                    flag = " CRÍTICO"

                lines.append(f"  - {port_num}/{service}{flag}")

    lines.append("")

    # ASN
    lines.append("[INFRAESTRUTURA (ASN)]")

    if not asn_map:
        lines.append("Sem dados de ASN.")
    else:
        for ip, data in asn_map.items():
            lines.append(f"- {ip} -> {data.get('asn')} ({data.get('org')})")

    lines.append("")

    # CLUSTERS
    lines.append("[INFRAESTRUTURA COMPARTILHADA]")

    if not clusters:
        lines.append("Nenhum cluster relevante (infra isolada ou baixa amostragem).")
    else:
        for ip, hosts in clusters.items():
            unique_hosts = list(set([h.lower() for h in hosts]))

            if len(unique_hosts) < 2:
                continue

            lines.append(f"{ip} ({len(unique_hosts)} hosts)")
            for h in unique_hosts:
                lines.append(f"  - {h}")

    lines.append("")

    # RESUMO
    lines.append("[RESUMO FINAL]")

    severity_counter = Counter()

    # HTTP
    for r in http:
        data = normalize(r)
        url = (data.get("url") or "").lower()
        status = data.get("status")

        if status in ["NO_HTTP", "NO_DNS"]:
            continue

        if any(p in url for p in ["/admin", "/login", "/api"]):
            severity_counter["MEDIUM"] += 1
        else:
            severity_counter["LOW"] += 1

    # PORTS
    for p in ports:
        plist = normalize(p).get("ports", [])

        for port in plist:
            port_num = port.get("port") if isinstance(port, dict) else port

            if port_num in [22, 3389, 3306, 6379]:
                severity_counter["HIGH"] += 1

    # ORIGINS
    for o in origins:
        conf = normalize(o).get("confidence")

        if conf == "high":
            severity_counter["HIGH"] += 1
        elif conf == "medium":
            severity_counter["MEDIUM"] += 1

    # INTELIGÊNCIA
    if len(pivot_targets) > 20:
        severity_counter["MEDIUM"] += 2

    if any(normalize(o).get("confidence") == "high" for o in origins):
        severity_counter["HIGH"] += 1

    if any("admin" in normalize(r).get("url", "") for r in http):
        severity_counter["HIGH"] += 1

    total = sum(severity_counter.values())

    lines.append(f"Total: {total}")
    lines.append(f"HIGH: {severity_counter.get('HIGH', 0)}")
    lines.append(f"MEDIUM: {severity_counter.get('MEDIUM', 0)}")
    lines.append(f"LOW: {severity_counter.get('LOW', 0)}")

    lines.append("\n" + sep)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[Relatório] Salvo em: {filepath}")

    return filepath