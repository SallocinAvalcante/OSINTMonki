from modules.network.asn_lookup import get_asn_from_ip
import socket


def calculate_risk_score(results: dict) -> dict:

    score = 0
    reasons = set()

    # -------------------------
    # CONFIG
    # -------------------------
    SAFE_ASNS = {
        "AS16509",  # AWS
        "AS13335",  # Cloudflare
        "AS15169",  # Google
        "AS8075",   # Microsoft
    }

    SAFE_PORTS = {80, 443}
    COMMON_PORTS = {53, 8080, 8443}

    PUBLIC_RESOLVERS = {
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4"
    }

    asn_cache = {}

    # -------------------------
    # HELPERS
    # -------------------------
    def get_cached_asn(ip: str):
        if ip in asn_cache:
            return asn_cache[ip]

        data = get_asn_from_ip(ip)
        asn_cache[ip] = data
        return data

    def is_safe_asn(asn: str) -> bool:
        return asn in SAFE_ASNS if asn else False

    def is_trusted_ip(ip: str) -> bool:
        data = get_cached_asn(ip)
        if not data:
            return False
        return is_safe_asn(data.get("asn"))

    def is_public_resolver(ip: str) -> bool:
        return ip in PUBLIC_RESOLVERS

    # =========================================================
    # ORIGIN DISCOVERY 
    # =========================================================
    for o in results.get("origins", []):
        if not isinstance(o, dict):
            continue

        ip = o.get("ip")
        conf = o.get("confidence")

        trusted = is_trusted_ip(ip)

        if conf == "high" and not trusted:
            score += 7
            reasons.add("IP de origem exposto (alta confiança)")

        elif conf == "medium" and not trusted:
            score += 2
            reasons.add("IP de origem provável")

        else:
            reasons.add("Infra com múltiplas origens (esperado em CDN/cloud)")

    # =========================================================
    # CLUSTERS (CONTEXTUAL)
    # =========================================================
    clusters = results.get("ip_clusters", {})

    for ip, hosts in clusters.items():

        if not isinstance(hosts, list):
            continue

        trusted = is_trusted_ip(ip)

        if len(hosts) >= 6:
            if not trusted:
                score += 2
                reasons.add(f"Infraestrutura altamente compartilhada ({ip})")
            else:
                reasons.add("Infra distribuída (CDN/cloud)")

        elif len(hosts) >= 4:
            if not trusted:
                score += 1
                reasons.add(f"Infraestrutura compartilhada ({ip})")

    # =========================================================
    # HTTP 
    # =========================================================
    for f in results.get("http", []):
        meta = getattr(f, "meta", {})

        techs = meta.get("technologies", []) or []
        url = meta.get("url", "") or ""

        for t in techs:
            t_lower = str(t).lower()

            if any(k in t_lower for k in ["admin", "login", "panel", "auth"]):
                score += 2
                reasons.add("Tecnologia sensível detectada")

        url_lower = url.lower()

        if any(p in url_lower for p in ["/admin", "/login", "/dashboard"]):
            score += 2
            reasons.add("Endpoint sensível exposto")

    # =========================================================
    # PORTS 
    # =========================================================
    for p in results.get("ports", []):
        if not isinstance(p, dict):
            continue

        ip = p.get("ip")
        ports = p.get("ports", [])

        if not ports or is_public_resolver(ip):
            continue

        for port in ports:
            port_num = port.get("port") if isinstance(port, dict) else port

            if port_num in SAFE_PORTS:
                continue

            if port_num in COMMON_PORTS:
                continue

            if port_num in [21, 22, 3389, 3306, 6379]:
                score += 3
                reasons.add(f"Serviço sensível exposto ({port_num})")
            else:
                score += 1
                reasons.add(f"Porta incomum aberta ({port_num})")

    # =========================================================
    # ASN EXPANSION 
    # =========================================================
    expanded = results.get("asn_expanded", [])

    if isinstance(expanded, list) and len(expanded) > 50:
        score += 1
        reasons.add("Grande superfície ASN (normal para grandes infraestruturas)")

    # =========================================================
    # TRACEROUTE 
    # =========================================================
    traces = results.get("traceroute", [])

    for trace in traces:

        if not isinstance(trace, dict):
            continue

        target = trace.get("target")
        hops = trace.get("hops", [])

        try:
            target_ip = socket.gethostbyname(target)
        except Exception:
            continue

        target_data = get_cached_asn(target_ip)
        target_asn = target_data.get("asn") if target_data else None

        #  IGNORA INFRA TRUSTED
        if is_safe_asn(target_asn):
            continue

        hidden_hops = [h for h in hops if h.get("ip") == "*"]

        if len(hidden_hops) >= 4:
            score += 1
            reasons.add("Filtragem de rota detectada")

        if not trace.get("completed"):
            score += 1
            reasons.add("Traceroute incompleto")

        # ASN PATH
        asn_path = []

        for hop in hops:
            ip = hop.get("ip")

            if not ip or ip == "*" or is_public_resolver(ip):
                continue

            data = get_cached_asn(ip)
            if not data:
                continue

            hop_asn = data.get("asn")

            if hop_asn:
                asn_path.append(hop_asn)

        if len(set(asn_path)) >= 5:
            score += 1
            reasons.add("Rota com múltiplos ASNs")

    # =========================================================
    # NORMALIZAÇÃO FINAL
    # =========================================================
    if score >= 15:
        level = "CRITICAL"
    elif score >= 9:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "reasons": sorted(list(reasons))
    }