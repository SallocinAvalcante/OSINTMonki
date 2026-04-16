import time

_last_call = {}


def rate_limit(key: str, delay: float = 1.0):
    """
    Garante intervalo mínimo entre chamadas por chave.
    """
    now = time.time()

    if key in _last_call:
        elapsed = now - _last_call[key]

        if elapsed < delay:
            time.sleep(delay - elapsed)

    _last_call[key] = time.time()