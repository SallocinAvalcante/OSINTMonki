def is_cloudflare(ip: str, headers: dict = None) -> bool:
    if not ip:
        return False

    if ip.startswith("104.21.") or ip.startswith("172.67."):
        return True

    if headers:
        server = headers.get("server", "").lower()
        if "cloudflare" in server:
            return True

        if "cf-ray" in headers:
            return True

    return False