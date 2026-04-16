def parse_transaction(raw: dict, chain: str, source: str) -> dict:

    if not raw:
        return {}

    # -------------------------
    # ETH
    # -------------------------
    if chain == "ethereum":
        if source == "etherscan":
            from .parsers.eth_etherscan import parse_eth_etherscan
            return parse_eth_etherscan(raw)

        if source == "blockchair":
            from .parsers.eth_blockchair import parse_eth_blockchair
            return parse_eth_blockchair(raw)

    # -------------------------
    # BTC
    # -------------------------
    if chain == "bitcoin":
        if source == "blockstream":
            from .parsers.btc_blockstream import parse_btc_blockstream
            return parse_btc_blockstream(raw)

        if source == "blockchair":
            from .parsers.btc_blockchair import parse_btc_blockchair
            return parse_btc_blockchair(raw)

        if source == "blockchaininfo":
            from .parsers.btc_blockchaininfo import parse_btc_blockchaininfo
            return parse_btc_blockchaininfo(raw)

    return {}