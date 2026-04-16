import time
from pathlib import Path
import os

CACHE_DIR = Path(__file__).parent / "cache"


_cache = {}

def cache_get(key: str):
    entry = _cache.get(key)

    if not entry:
        return None

    value, expires = entry

    if time.time() > expires:
        del _cache[key]
        return None

    return value


def cache_set(key: str, value, ttl: int = 300):
    """
    ttl em segundos (default 5 min)
    """
    _cache[key] = (value, time.time() + ttl)


def clear_cache():
    if CACHE_DIR.exists():
        for file in CACHE_DIR.iterdir():
            if file.is_file():
                file.unlink()
        print("[Cache] Limpo com sucesso.")