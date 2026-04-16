def print_tx_summary(parsed: dict):

    print("\n================ Resumo da Transação ================\n")

    print(f"Hash: {parsed.get('hash')}")

    # =========================
    # VALOR
    # =========================
    value_btc = parsed.get("value_btc")
    value_eth = parsed.get("value_eth")

    if value_btc:
        print(f"Valor: {value_btc} BTC")
    elif value_eth:
        print(f"Valor: {value_eth} ETH")

    print(f"Status: {parsed.get('status')}")

    # =========================
    # CONFIG
    # =========================
    DISPLAY_LIMIT = 5

    from_list = parsed.get("from", []) or []
    to_list = parsed.get("to", []) or []

    # =========================
    # FROM
    # =========================
    print("\nSAINDO DE:")
    for f in from_list[:DISPLAY_LIMIT]:
        print(f"  - {f}")

    if len(from_list) > DISPLAY_LIMIT:
        print(f"  ... (+{len(from_list) - DISPLAY_LIMIT} endereços ocultos)")

    # =========================
    # TO
    # =========================
    print("\nINDO PARA:")
    for t in to_list[:DISPLAY_LIMIT]:
        print(f"  - {t}")

    if len(to_list) > DISPLAY_LIMIT:
        print(f"  ... (+{len(to_list) - DISPLAY_LIMIT} endereços ocultos)")

    # =========================
    # METRICAS
    # =========================
    inputs = parsed.get("inputs") or len(from_list)
    outputs = parsed.get("outputs") or len(to_list)

    print("\nMÉTRICAS:")
    print(f"Inputs: {inputs}")
    print(f"Outputs: {outputs}")

    # =========================
    # FLAGS
    # =========================
    flags = parsed.get("flags_translated", [])

    if flags:
        print("\nINDICADORES:")
        for f in flags:
            if isinstance(f, list):
                f = f[0]
            print(f"  - {f}")

    # =========================
    # CLUSTER
    # =========================
    cluster = parsed.get("cluster", {})
    cluster_size = cluster.get("size", 0)

    if cluster_size > 1:
        print("\nCLUSTER:")
        print(f"Tamanho: {cluster_size} endereços")

        sample = cluster.get("sample", [])
        for addr in sample:
            print(f"  - {addr}")

    # =========================
    # RISK
    # =========================
    risk = parsed.get("risk", {})

    if risk:
        print("\nAVALIAÇÃO DE RISCO:")
        print(f"Nível: {risk.get('level')} | Score: {risk.get('score')}")

        for r in risk.get("reasons", []):
            print(f"  - {r}")

    print("\n============================================\n")