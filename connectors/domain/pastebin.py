import requests
from bs4 import BeautifulSoup

from models.findings import Finding
from utils.common.cache import cache_get, cache_set
from utils.common.rate_limit import rate_limit

PASTEBIN_RECENT_URL = "https://pastebin.com/archive"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}


def _fetch_recent_pastes() -> list[str]:
    try:
        rate_limit("pastebin", delay=2.0)

        response = requests.get(PASTEBIN_RECENT_URL, headers=HEADERS, timeout=15)
        response.raise_for_status()

    except requests.RequestException as e:
        print(f"[Pastebin] Erro ao acessar archive: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    paste_ids = set()

    rows = soup.select("table.maintable tr")

    for row in rows:
        link = row.find("a")
        if not link:
            continue

        href = link.get("href", "")

        if href.startswith("/") and len(href.strip("/")) == 8:
            paste_ids.add(href.strip("/"))

    return list(paste_ids)[:30]


def _fetch_paste_content(paste_id: str, query: str) -> str:
    """
    Busca conteúdo RAW com limite (evita payload gigante).
    """
    raw_url = f"https://pastebin.com/raw/{paste_id}"

    try:
        rate_limit("pastebin", delay=1.0)

        response = requests.get(raw_url, headers=HEADERS, timeout=10, stream=True)

        if response.status_code != 200:
            return ""

        content = ""
        max_size = 50_000  # limite de leitura (~50KB)

        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if not chunk:
                break

            content += chunk

            # early stop se já encontrou
            if query.lower() in content.lower():
                return content

            if len(content) >= max_size:
                break

        return content

    except requests.RequestException:
        return ""


def search_pastebin(query: str) -> list[Finding]:
    print(f"[Pastebin] Buscando por: {query}")

    # -------------------------
    # CACHE
    # -------------------------
    cache_key = f"pastebin:{query}"
    cached = cache_get(cache_key)
    if cached:
        print("[Pastebin] Resultado vindo do cache.")
        return cached

    paste_ids = _fetch_recent_pastes()
    print(f"[Pastebin] Analisando {len(paste_ids)} pastes recentes...(amostragem)")

    results = []

    for pid in paste_ids:
        content = _fetch_paste_content(pid, query)

        if not content:
            continue

        if query.lower() in content.lower():
            snippet = content[:120].replace("\n", " ").strip()

            if not snippet:
                continue

            results.append(
                Finding(
                    source="Pastebin",
                    type="mention",
                    value=f"https://pastebin.com/{pid} | {snippet}...",
                    severity="MEDIUM"
                )
            )

        # proteção contra excesso de resultados
        if len(results) >= 10:
            break

    if not results:
        print("[Pastebin] Nenhuma menção encontrada (normal para muitos domínios).")
    else:
        print(f"[Pastebin] {len(results)} menções encontradas.")

    # -------------------------
    # CACHE SAVE
    # -------------------------
    cache_set(cache_key, results)

    return results