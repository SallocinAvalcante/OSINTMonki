from typing import List, Dict, Set
import requests
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

TIMEOUT = 4
MAX_THREADS = 20

HTTP_PATHS = [
    "/",
    "/login",
    "/admin",
    "/dashboard",
    "/api",
]

_dns_cache: Dict[str, List[str]] = {}


# -------------------------
# UTILS
# -------------------------
def extract_title(html: str) -> str:
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip().lower() if match else ""


def resolve_ips(host: str) -> List[str]:
    if host in _dns_cache:
        return _dns_cache[host]

    try:
        ips = list(set(socket.gethostbyname_ex(host)[2]))
        _dns_cache[host] = ips
        return ips
    except:
        _dns_cache[host] = []
        return []


def normalize_headers(headers) -> dict:
    return {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}


def is_tcp_alive(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except:
        return False


# -------------------------
# WAF
# -------------------------
def detect_waf(headers: dict, status: int, body: str) -> List[str]:
    wafs = []

    server = headers.get("server", "")

    if "cloudflare" in server or "cf-ray" in headers:
        wafs.append("Cloudflare")

    if "akamai" in server:
        wafs.append("Akamai")

    if status in [403, 429]:
        if "access denied" in body.lower():
            wafs.append("Generic WAF")

    return list(set(wafs))


# -------------------------
# CORE
# -------------------------
def probe_url(session: requests.Session, url: str, path: str = "/") -> Dict:

    full_url = f"{url.rstrip('/')}{path}"

    try:
        r = session.get(
            full_url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        original_host = urlparse(full_url).hostname or ""
        final_host = urlparse(r.url).hostname or original_host

        headers = normalize_headers(r.headers)
        body = r.text or ""

        ips = resolve_ips(final_host)

        return {
            "url": full_url,
            "final_url": r.url,
            "host": original_host,        # usado para agrupamento
            "final_host": final_host,     # usado para inteligência de redirect
            "ip": ips[0] if ips else "",
            "ips": ips,
            "status": r.status_code,
            "headers": headers,
            "server": headers.get("server", ""),
            "title": extract_title(body),
            "body": body[:3000],
            "length": len(body),
            "waf": detect_waf(headers, r.status_code, body),
            "redirected": full_url != r.url
        }

    except:
        return None


# -------------------------
# WORKER
# -------------------------
def probe_target(target: str, probe_paths: bool) -> List[Dict]:

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    results = []

    ips = resolve_ips(target)

    # Sem DNS → retorno mínimo
    if not ips:
        return [{
            "host": target,
            "final_host": target,
            "url": f"http://{target}",
            "ip": "",
            "ips": [],
            "status": "NO_DNS",
            "headers": {},
            "title": "",
            "body": "",
            "length": 0,
            "waf": []
        }]

    base_urls = [
        f"http://{target}",
        f"https://{target}"
    ]

    success = False

    for base_url in base_urls:

        data = probe_url(session, base_url)

        if data:
            status = data.get("status")

            if isinstance(status, int) and status < 500:
                print(f"[HTTP] {data['url']} -> {status}")
                results.append(data)
                success = True

                # PATH PROBE
                if probe_paths:
                    for path in HTTP_PATHS:
                        if path == "/":
                            continue

                        path_data = probe_url(session, base_url, path)

                        if path_data and isinstance(path_data.get("status"), int):
                            results.append(path_data)

                break

    # FALLBACK TCP
    if not success:
        tcp80 = is_tcp_alive(target, 80)
        tcp443 = is_tcp_alive(target, 443)

        if tcp80 or tcp443:
            results.append({
                "host": target,
                "final_host": target,
                "url": f"http://{target}",
                "ip": ips[0] if ips else "",
                "ips": ips,
                "status": "TCP_ONLY",
                "headers": {},
                "title": "",
                "body": "",
                "length": 0,
                "waf": [],
                "tcp_alive": True
            })
        else:
            results.append({
                "host": target,
                "final_host": target,
                "url": f"http://{target}",
                "ip": ips[0] if ips else "",
                "ips": ips,
                "status": "NO_HTTP",
                "headers": {},
                "title": "",
                "body": "",
                "length": 0,
                "waf": []
            })

    return results


# -------------------------
# MAIN
# -------------------------
def http_probe(
    targets: List[str],
    max_targets: int = 20,
    probe_paths: bool = False
) -> List[Dict]:

    print("[HTTP] Iniciando probing...")

    results: List[Dict] = []
    seen: Set[str] = set()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        futures = {
            executor.submit(probe_target, target, probe_paths): target
            for target in targets[:max_targets]
        }

        for future in as_completed(futures):
            try:
                res = future.result()

                for r in res:
                    key = f"{r.get('host')}|{r.get('url')}"

                    if key not in seen:
                        results.append(r)
                        seen.add(key)

            except Exception as e:
                print(f"[HTTP] Erro thread: {e}")

    print(f"[HTTP] {len(results)} resultados coletados.")

    return results