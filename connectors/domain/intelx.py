import os
import time
import requests
from dotenv import load_dotenv

from models.findings import Finding
from utils.common.cache import cache_get, cache_set
from utils.common.rate_limit import rate_limit

load_dotenv()

INTELX_API_KEY = os.getenv("INTELX_API_KEY")
INTELX_BASE_URL = "https://2.intelx.io"

HEADERS = {
    "x-key": INTELX_API_KEY or "",
    "Content-Type": "application/json",
}


def _start_search(query: str) -> str | None:
    endpoint = f"{INTELX_BASE_URL}/intelligent/search"

    payload = {
        "term": query,
        "maxresults": 20,
        "media": 0,
        "sort": 4,
    }

    try:
        response = requests.post(endpoint, json=payload, headers=HEADERS, timeout=15)

        if response.status_code == 401:
            return "UNAUTHORIZED"

        response.raise_for_status()

        data = response.json()
        return data.get("id")

    except (requests.RequestException, ValueError):
        return None


def _fetch_results(search_id: str, max_attempts: int = 5) -> list[dict]:
    endpoint = f"{INTELX_BASE_URL}/intelligent/search/result"
    params = {"id": search_id, "limit": 20}

    for attempt in range(1, max_attempts + 1):

        rate_limit("intelx", delay=2.0)

        try:
            response = requests.get(endpoint, params=params, headers=HEADERS, timeout=15)

            if response.status_code == 401:
                return []

            response.raise_for_status()

            data = response.json()
            records = data.get("records", [])

            if records:
                return records

            if data.get("status") == 1:
                break

            print(f"[IntelX] Aguardando resultados ({attempt}/{max_attempts})...")
            time.sleep(2)

        except (requests.RequestException, ValueError):
            break

    return []


def _format_record(record: dict) -> str:
    name = record.get("name", "sem nome")
    bucket = record.get("bucket", "unknown")
    date = record.get("date", "")[:10] if record.get("date") else "sem data"

    return f"{bucket} | {date} | {name}"


def _fallback_hint(query: str) -> list[Finding]:
    """
    Sugestão quando não há API ou retorno (melhora UX).
    """
    return [
        Finding(
            source="IntelX",
            type="hint",
            value=f"Sem acesso à API. Buscar manualmente: https://intelx.io/?s={query}",
            severity="LOW"
        )
    ]


def search_intelx(query: str) -> list[Finding]:
    print(f"[IntelX] Iniciando busca por: {query}")

    # -------------------------
    # CACHE
    # -------------------------
    cache_key = f"intelx:{query}"
    cached = cache_get(cache_key)
    if cached:
        print("[IntelX] Resultado vindo do cache.")
        return cached

    # -------------------------
    # API KEY CHECK
    # -------------------------
    if not INTELX_API_KEY or INTELX_API_KEY.strip() == "":
        print("[IntelX] API key não configurada.")
        results = _fallback_hint(query)
        cache_set(cache_key, results)
        return results

    # -------------------------
    # START SEARCH
    # -------------------------
    search_id = _start_search(query)

    if search_id == "UNAUTHORIZED":
        print("[IntelX] API key sem permissão (plano limitado).")
        results = _fallback_hint(query)
        cache_set(cache_key, results)
        return results

    if not search_id:
        print("[IntelX] Falha ao iniciar busca.")
        return []

    # -------------------------
    # FETCH RESULTS
    # -------------------------
    records = _fetch_results(search_id)

    if not records:
        print("[IntelX] Nenhum resultado encontrado.")
        return []

    results = [
        Finding(
            source="IntelX",
            type="leak",
            value=_format_record(r),
            severity="CRITICAL"
        )
        for r in records
    ]

    # -------------------------
    # CACHE SAVE
    # -------------------------
    cache_set(cache_key, results)

    return results