def translate_status(status: str) -> str:
    mapping = {
        "CONFIRMED": "CONFIRMADA",
        "FAILED": "FALHOU",
        "PENDING": "PENDENTE"
    }
    return mapping.get(status, status)


def format_addresses(addrs, limit=5):
    if not addrs:
        return ["  - N/A"]

    if not isinstance(addrs, list):
        addrs = [addrs]

    lines = [f"  - {a}" for a in addrs[:limit]]

    if len(addrs) > limit:
        lines.append(f"  ... (+{len(addrs) - limit} endereços ocultos)")

    return lines

def translate_flag(flags):
    if not flags:
        return []

    if isinstance(flags, str):
        flags = [flags]

    mapping = {
        "HIGH_VALUE_TX": "Transação de alto valor",
        "POSSIBLE_BATCH_TX": "Possível transação em lote",
        "SMART_CONTRACT_INTERACTION": "Interação com contrato inteligente",
        "FAILED_TX": "Transação falhou",
        "EXTREME_VALUE_TX": "Transação de valor extremamente alto",
        "SELF TRANSFER": "Auto-transferência",
        "HIGH ACTIVITY WALLET": "Carteira de alta atividade",
        "BATCH TRANSACTION": "Transação em lote",
        "POSSÍVEL EXCHANGE (BATCH TRANSACTION)": "Possível exchange (distribuição em massa)",
    }

    translated = []

    for flag in flags:
        try:
            normalized = flag.upper().strip()
            translated.append(mapping.get(normalized, normalized))
        except Exception:
            continue

    return translated