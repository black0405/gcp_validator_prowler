"""Helpers for validation method #5 — confirm internet exposure empirically.

For public-exposure checks (open firewall, public IP, public bucket) we do not
just trust the config: we try to reach the resource the way an attacker on the
internet would. A successful connection is strong evidence the finding is real;
a refused/timed-out connection is a useful (though not conclusive) counter-signal.
"""
from __future__ import annotations

import socket
import ssl
from typing import Optional, Tuple


def tcp_probe(host: str, port: int, timeout: float = 4.0) -> Tuple[bool, str]:
    """Attempt a raw TCP connect. Returns (reachable, detail)."""
    if not host:
        return False, "no host/IP to probe"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connect to {host}:{port} succeeded (reachable from this host)"
    except socket.timeout:
        return False, f"TCP connect to {host}:{port} timed out"
    except OSError as exc:
        return False, f"TCP connect to {host}:{port} failed: {exc}"


def https_probe(host: str, port: int = 443, timeout: float = 4.0) -> Tuple[bool, str]:
    """Attempt a TLS handshake (for HTTPS-fronted resources)."""
    if not host:
        return False, "no host to probe"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, f"TLS handshake with {host}:{port} succeeded"
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return False, f"TLS probe to {host}:{port} failed: {exc}"


def http_status(url: str, timeout: float = 5.0) -> Tuple[Optional[int], str]:
    """Unauthenticated HTTP GET; returns (status_code, detail). Used to test
    whether a resource responds to anonymous internet callers."""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, f"anonymous GET {url} -> HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return exc.code, f"anonymous GET {url} -> HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"anonymous GET {url} failed: {exc}"


def is_public_ip(ip: str) -> Optional[bool]:
    """True if ip is a public (globally-routable) address, None if unparseable."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


# Well-known DB ports, used when probing database exposure.
DB_PORTS = {
    "MYSQL": 3306,
    "POSTGRES": 5432,
    "SQLSERVER": 1433,
}
