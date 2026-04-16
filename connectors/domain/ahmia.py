import requests
import re
from bs4 import BeautifulSoup

from models.findings import Finding
from utils.common.rate_limit import rate_limit
from utils.common.cache import cache_get, cache_set

AHMIA_BASE_URL = "https://ahmia.fi/search/"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}


def extract_onion_links(html: str) -> list[Finding]:
    """
    Extrai links .onion direto do HTML (resistente a mudança de layout)
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []

    onion_pattern = r"[a-z2-7]{16,56}\.onion"
    found = set(re.findall(onion_pattern, html))

    for onion in found:
        context = ""

        # pega contexto próximo
        for tag in soup.find_all(string=re.compile(onion)):
            parent = tag.parent.get_text(" ", strip=True)
            context = parent[:120]
            break

        results.append(
            Finding(
                source="Ahmia",
                type="onion_mention",
                value=f"{onion} | {context}",
                severity="MEDIUM"
            )
        )

    return results


def search_ahmia(query: str) -> list[Finding]:
    print(f"[Ahmia] Iniciando busca por: {query}")

    # -------------------------
    # CACHE
    # -------------------------
    cache_key = f"ahmia:{query}"
    cached = cache_get(cache_key)
    if cached:
        print("[Ahmia] Resultado vindo do cache.")
        return cached

    # -------------------------
    # RATE LIMIT
    # -------------------------
    rate_limit("ahmia", delay=2.0)

    try:
        response = requests.get(
            AHMIA_BASE_URL,
            params={"q": query},
            headers=HEADERS,
            timeout=20,
        )
        response.raise_for_status()

    except requests.RequestException as e:
        print(f"[Ahmia] Erro ao realizar requisicao: {e}")
        return []

    results = extract_onion_links(response.text)

    if results:
        print(f"[Ahmia] {len(results)} resultados encontrados.")
    else:
        print("[Ahmia] Nenhum resultado encontrado (ou bloqueado).")
        print(f"[Ahmia] Verifique manualmente: https://ahmia.fi/search/?q={query}")

    # -------------------------
    # CACHE SAVE
    # -------------------------
    results = results[:20]
    cache_set(cache_key, results)

    return results