from typing import List, Set
from models.findings import Finding


# -------------------------
# NORMALIZAÇÃO
# -------------------------
def normalize_domain(domain: str) -> str:
    return domain.lower().strip().rstrip(".")


# -------------------------
# VALIDAÇÃO
# -------------------------
def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False

    domain = domain.strip().lower()

    if "@" in domain:
        return False

    if "*" in domain:
        return False

    if " " in domain:
        return False

    if "|" in domain:
        return False

    if domain.startswith("http"):
        return False

    if "/" in domain:
        return False

    if "." not in domain:
        return False

    return True


# -------------------------
# RELAÇÃO (INTELIGENTE)
# -------------------------
def is_related_domain(domain: str, base: str) -> bool:
    """
    Mantém:
    - subdomínios reais
    - variações próximas

    Evita:
    - domínios muito distantes
    """

    if domain == base:
        return False

    if domain.endswith("." + base):
        return True

    return False


# -------------------------
# FILTRO DE RUÍDO (CRÍTICO)
# -------------------------
def is_noise_domain(domain: str) -> bool:
    """
    Remove ambientes internos exagerados e lixo comum
    """

    NOISE = [
        "perf", "alpha", "beta", "qa", "test",
        "staging", "sandbox", "internal",
        "dev", "pilot"
    ]

    for n in NOISE:
        if domain.startswith(n + ".") or f".{n}." in domain:
            return True

    return False


# -------------------------
# EXTRAÇÃO TLS
# -------------------------
def extract_tls_domains(findings: List[Finding]) -> Set[str]:
    domains: Set[str] = set()

    for f in findings:

        # value direto
        val = getattr(f, "value", None)
        if isinstance(val, str) and is_valid_domain(val):
            domains.add(normalize_domain(val))

        # SSL meta
        meta = getattr(f, "meta", {})
        ssl = meta.get("ssl", {})

        if ssl:
            cn = ssl.get("cn")
            if isinstance(cn, str) and is_valid_domain(cn):
                domains.add(normalize_domain(cn))

            for san in ssl.get("san", []):
                if isinstance(san, str) and is_valid_domain(san):
                    domains.add(normalize_domain(san))

    return domains


# -------------------------
# FILTRO FINAL
# -------------------------
def filter_targets(domains: Set[str], original_domain: str) -> List[str]:

    base = normalize_domain(original_domain)
    clean: Set[str] = set()

    for d in domains:

        if d == base:
            continue

        if not is_valid_domain(d):
            continue

        if not is_related_domain(d, base):
            continue

        if is_noise_domain(d):
            continue

        clean.add(d)

    return list(clean)


# -------------------------
# SCORE INTELIGENTE
# -------------------------
def score_domain(domain: str, base: str) -> int:

    score = 0

    HIGH = ["api", "admin", "secure", "auth"]
    MEDIUM = ["portal", "account", "mail"]

    # prioridade por palavra-chave
    for k in HIGH:
        if k in domain:
            score += 60

    for k in MEDIUM:
        if k in domain:
            score += 25

    # profundidade (controlada)
    depth = domain.count(".")
    if depth <= 4:
        score += depth * 5
    else:
        score -= 10  # penaliza domínios muito profundos (geralmente lixo)

    # proximidade com domínio base
    if domain.endswith(base):
        score += 40

    # penalização leve para domínios muito longos
    if len(domain) > 50:
        score -= 10

    return score


# -------------------------
# PRIORIZAÇÃO
# -------------------------
def prioritize_targets(domains: List[str], base: str) -> List[str]:

    return sorted(
        list(set(domains)),
        key=lambda d: score_domain(d, base),
        reverse=True
    )


# -------------------------
# MAIN
# -------------------------
def build_pivot_targets(findings: List[Finding], original_domain: str) -> List[str]:

    print("[Pivot] Extraindo domínios TLS...")

    extracted = extract_tls_domains(findings)
    print(f"[Pivot] {len(extracted)} domínios extraídos (raw)")

    filtered = filter_targets(extracted, original_domain)
    print(f"[Pivot] {len(filtered)} domínios após filtro")

    prioritized = prioritize_targets(filtered, original_domain)
    print(f"[Pivot] {len(prioritized)} domínios priorizados")

    #  LIMITE GLOBAL REAL
    final = prioritized[:15]

    print(f"[Pivot] {len(final)} domínios finais (limitados)")

    return final