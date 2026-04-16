from typing import List, Dict, Set, Tuple
import socket
import requests
import hashlib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 5

COMMON_ORIGINS = [
    "origin", "origin-www", "backend", "backend-www",
    "server", "web", "webserver", "app", "api",
    "internal", "direct", "real", "prod", "production",
    "staging", "dev", "test", "old", "legacy",
    "infra", "edge"
]


# -------------------------
# UTILS
# -------------------------
def get_hash(content: str) -> str:
    return hashlib.md5(content.encode(errors="ignore")).hexdigest()


def extract_title(html: str) -> str:
    try:
        start = html.lower().find("<title>")
        end = html.lower().find("</title>")

        if start != -1 and end != -1:
            return html[start+7:end].strip().lower()
    except:
        pass

    return ""


def normalize_headers(headers: Dict) -> Dict:
    return {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}


def is_generic_error(title: str, length: int) -> bool:
    termos = ["access denied", "forbidden", "error", "blocked"]

    if any(t in (title or "") for t in termos):
        return True

    if length < 200:
        return True

    return False


def is_cdn(headers: Dict, ip: str) -> bool:
    server = headers.get("server", "")

    if "cloudflare" in server or "cf-ray" in headers:
        return True

    if "akamai" in server:
        return True

    if "fastly" in server:
        return True

    if ip.startswith("1.1.1.") or ip.startswith("104."):
        return True

    return False


# -------------------------
# DNS
# -------------------------
def resolve_domain(domain: str) -> List[str]:
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except:
        return []


# -------------------------
# BASELINE 
# -------------------------
def get_baseline(domain: str) -> Dict:

    # tenta HTTPS primeiro
    try:
        r = requests.get(f"https://{domain}", timeout=TIMEOUT, verify=False)
    except:
        try:
            r = requests.get(f"http://{domain}", timeout=TIMEOUT)
        except:
            return {}

    body = r.text[:5000]

    return {
        "status": r.status_code,
        "title": extract_title(body),
        "length": len(body),
        "hash": get_hash(body),
        "headers": normalize_headers(r.headers)
    }


# -------------------------
# TESTES
# -------------------------
def test_http(ip: str, domain: str) -> Dict | None:
    try:
        r = requests.get(
            f"http://{ip}",
            headers={"Host": domain, "User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            allow_redirects=False
        )

        body = r.text[:5000]

        return {
            "status": r.status_code,
            "title": extract_title(body),
            "length": len(body),
            "hash": get_hash(body),
            "headers": normalize_headers(r.headers)
        }

    except:
        return None


def test_https(ip: str, domain: str) -> Dict | None:
    try:
        r = requests.get(
            f"https://{ip}",
            headers={"Host": domain, "User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )

        body = r.text[:5000]

        return {
            "status": r.status_code,
            "title": extract_title(body),
            "length": len(body),
            "hash": get_hash(body),
            "headers": normalize_headers(r.headers)
        }

    except:
        return None


# -------------------------
# SIMILARIDADE
# -------------------------
def similarity_ratio(a: int, b: int) -> float:
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


# -------------------------
# SCORE
# -------------------------
def calculate_confidence(baseline: Dict, candidate: Dict, proto: str) -> Tuple[str, int]:

    if not baseline or not candidate:
        return "low", 0

    score = 0

    base_title = baseline.get("title")
    cand_title = candidate.get("title")

    if base_title and base_title == cand_title:
        score += 2
    elif base_title and cand_title and base_title in cand_title:
        score += 1

    if baseline.get("hash") == candidate.get("hash"):
        score += 4

    sim = similarity_ratio(
        baseline.get("length", 0),
        candidate.get("length", 0)
    )

    if sim > 0.9:
        score += 2
    elif sim > 0.7:
        score += 1

    base_headers = baseline.get("headers", {})
    cand_headers = candidate.get("headers", {})

    for h in ["server", "x-powered-by"]:
        if h in base_headers and h in cand_headers:
            if base_headers[h] == cand_headers[h]:
                score += 2

    if candidate.get("length", 0) < 300:
        score -= 1

    if proto == "https":
        score += 1

    if score >= 7:
        return "high", score
    elif score >= 4:
        return "medium", score
    else:
        return "low", score


# -------------------------
# RESULT
# -------------------------
def build_origin_result(ip: str, proto: str, confidence: str, score: int, data: Dict) -> Dict:
    return {
        "type": "ip",
        "value": ip,
        "source": "origin_discovery",
        "confidence": confidence,
        "meta": {
            "protocol": proto,
            "status": data.get("status"),
            "title": data.get("title"),
            "length": data.get("length"),
            "score": score
        }
    }


# -------------------------
# MAIN
# -------------------------
def discover_origin(domain: str) -> List[Dict]:
    print("[Origin] Iniciando descoberta de origem...")

    base = domain.replace("www.", "")
    found_ips: Set[str] = set()
    results: List[Dict] = []
    seen: Set[str] = set()

    baseline = get_baseline(base)

    # fallback crítico
    if not baseline.get("title"):
        baseline["title"] = base

    print(f"[Origin] Título base: {baseline.get('title')}")

    # enumeração DNS
    for sub in COMMON_ORIGINS:
        candidate = f"{sub}.{base}"

        for ip in resolve_domain(candidate):
            print(f"[Origin] Encontrado via DNS: {candidate} -> {ip}")
            found_ips.add(ip)

    # domínio principal
    for ip in resolve_domain(base):
        found_ips.add(ip)

    # testes
    for ip in found_ips:

        print(f"[Origin] Testando IP: {ip}")

        http_res = test_http(ip, base)
        https_res = test_https(ip, base)

        for proto, res in [("http", http_res), ("https", https_res)]:

            if not res:
                continue

            if is_generic_error(res.get("title"), res.get("length")):
                print(f"[Origin] Ignorado (erro genérico): {ip}")
                continue

            if is_cdn(res.get("headers", {}), ip):
                print(f"[Origin] Ignorado (CDN): {ip}")
                continue

            confidence, score = calculate_confidence(baseline, res, proto)

            key = f"{ip}:{proto}"

            if confidence != "low" and key not in seen:
                print(f"[Origin] Possível origem: {ip} ({proto}) | conf={confidence} score={score}")

                results.append(
                    build_origin_result(ip, proto, confidence, score, res)
                )

                seen.add(key)
            else:
                print(f"[Origin] Descarta IP: {ip} (score={score})")

    print(f"[Origin] Total de origens validadas: {len(results)}")

    return results