import re


FINGERPRINTS = [
    # Infra
    {"name": "Cloudflare", "header": "server", "value": "cloudflare", "confidence": "HIGH"},
    {"name": "Cloudflare Protection", "header": "cf-ray", "confidence": "HIGH"},
    {"name": "nginx", "header": "server", "value": "nginx", "confidence": "MEDIUM", "extract_version": True},
    {"name": "Apache", "header": "server", "value": "apache", "confidence": "MEDIUM", "extract_version": True},

    # Backend
    {"name": "Express", "header": "x-powered-by", "value": "express", "confidence": "HIGH"},
    {"name": "PHP", "header": "x-powered-by", "value": "php", "confidence": "HIGH"},
    {"name": "ASP.NET", "header": "x-powered-by", "value": "asp.net", "confidence": "HIGH"},
    {"name": "ASP.NET", "header": "set-cookie", "value": "asp.net", "confidence": "HIGH"},

    # CMS
    {"name": "WordPress", "body": "wp-content", "confidence": "HIGH"},
    {"name": "WordPress", "body": "wp-json", "confidence": "HIGH"},

    # Frameworks
    {"name": "Laravel", "body": "laravel", "confidence": "LOW"},
    {"name": "Django", "header": "set-cookie", "value": "csrftoken", "confidence": "HIGH"},

    # Frontend moderno (melhorado)
    {"name": "Next.js", "body": "__NEXT_DATA__", "confidence": "HIGH"},
    {"name": "Next.js", "body": "_next/static", "confidence": "HIGH"},
    {"name": "React", "body": "react-dom", "confidence": "LOW"},
    {"name": "Vue.js", "body": "__vue__", "confidence": "LOW"},
]


# -------------------------
# UTILS
# -------------------------
def normalize_headers(headers: dict) -> dict:
    if not headers:
        return {}

    normalized = {}

    for k, v in headers.items():
        key = str(k).lower()

        if isinstance(v, list):
            value = " ".join([str(i).lower() for i in v])
        else:
            value = str(v).lower()

        normalized[key] = value

    return normalized


def extract_version(header_value: str) -> str:
    match = re.search(r"/([\d\.]+)", header_value)
    return match.group(1) if match else ""


# -------------------------
# MATCH
# -------------------------
def match_fingerprint(result: dict) -> list[dict]:
    matches = []

    headers = normalize_headers(result.get("headers") or {})
    title = str(result.get("title", "")).lower()
    body = str(result.get("body", "")).lower()
    url = str(result.get("url", "")).lower()

    # =========================================================
    #  EARLY EXIT (sem dados úteis)
    # =========================================================
    if not headers and not body:
        return matches

    # =========================================================
    #  API DETECTION (CONTROLADA)
    # =========================================================
    content_type = headers.get("content-type", "")

    if "application/json" in content_type:
        matches.append({
            "name": "API",
            "confidence": "HIGH",
            "version": None
        })

    elif body.startswith("{") and len(body) < 5000:
        # fallback leve (evita HTML falso)
        matches.append({
            "name": "API",
            "confidence": "MEDIUM",
            "version": None
        })

    # =========================================================
    # REGRAS PADRÃO
    # =========================================================
    for rule in FINGERPRINTS:

        matched = False
        version = ""

        # HEADER + VALUE
        if "header" in rule and "value" in rule:
            val = headers.get(rule["header"], "")

            if rule["value"] in val:
                matched = True
                if rule.get("extract_version"):
                    version = extract_version(val)

        # HEADER EXISTS
        elif "header" in rule:
            if rule["header"] in headers:
                matched = True

        # TITLE
        elif "title" in rule:
            if rule["title"] in title:
                matched = True

        # BODY
        elif "body" in rule:
            if rule["body"] in body:
                matched = True

        if matched:
            matches.append({
                "name": rule["name"],
                "confidence": rule.get("confidence", "LOW"),
                "version": version or None
            })

    return matches


# -------------------------
# DEDUP
# -------------------------
CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def deduplicate_techs(techs: list[dict]) -> list[dict]:
    seen = {}

    for t in techs:
        name = t["name"]

        if name not in seen:
            seen[name] = t
        else:
            # mantém maior confiança
            if CONFIDENCE_ORDER[t["confidence"]] > CONFIDENCE_ORDER[seen[name]["confidence"]]:
                seen[name] = t

            # mantém versão se existir
            if not seen[name].get("version") and t.get("version"):
                seen[name]["version"] = t["version"]

    return list(seen.values())


# -------------------------
# MAIN
# -------------------------
def fingerprint_services(probe_results: list[dict]) -> list[dict]:
    print("[Fingerprint] Identificando tecnologias...")

    enriched = []

    for r in probe_results:

        #  IGNORA FALLBACK TCP (sem HTTP real)
        if r.get("status") is None and not r.get("headers"):
            enriched.append(r)
            continue

        techs = deduplicate_techs(match_fingerprint(r))

        r["technologies"] = [t["name"] for t in techs]
        r["tech_meta"] = techs

        enriched.append(r)

        if techs:
            pretty = ", ".join([
                f"{t['name']}{f'/{t['version']}' if t.get('version') else ''}({t['confidence']})"
                for t in techs
            ])
            print(f"[Fingerprint] {r.get('url')} -> {pretty}")

    print(f"[Fingerprint] {len(enriched)} serviços analisados.")

    return enriched