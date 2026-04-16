import socket

def resolve_domain(domain: str) -> list[str]:
    """
    Resolve domínio para IPv4 apenas.
    """
    try:
        ips = set()

        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]

            if "." in ip:
                ips.add(ip)

        return list(ips)

    except Exception:
        return []


def resolves(domain: str) -> bool:
    """
    Verifica se domínio resolve.
    """
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False