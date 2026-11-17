"""
SSRF-safe URL normalization and validation.

Rules enforced here:
  * Only http/https.
  * No userinfo (user:pass@) in the authority.
  * Reject hostnames that are bare IPs in private/reserved ranges.
  * Resolve DNS and reject if *any* resolved address is private/reserved
    (defends against simple DNS rebinding / multi-A records).
  * Provide safe_http_probe() that pins a validated IP so a rebinding
    attacker can't swap the record between validation and connection.
"""
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings


class URLValidationError(Exception):
    """Raised when a URL is unsafe or malformed. `code` is machine-readable."""

    def __init__(self, message: str, code: str = "invalid"):
        super().__init__(message)
        self.code = code


# Reserved / internal ranges we refuse to touch.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16",          # link-local incl. cloud metadata 169.254.169.254
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
        "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]
_BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "metadata",
    "metadata.google.internal", "instance-data",
}

_ALLOWED_SCHEMES = {"http", "https"}


@dataclass
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    resolved_ips: list[str] = field(default_factory=list)
    resolves: bool = False


def _ip_is_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    # Handle IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _resolve(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def normalize_and_validate(raw_url: str, *, resolve: bool = True) -> NormalizedURL:
    """Parse, normalize, and safety-check a URL. Raises URLValidationError."""
    max_len = getattr(settings, "LINKGUARD", {}).get("MAX_URL_LENGTH", 2048)
    if not raw_url or not raw_url.strip():
        raise URLValidationError("URL is empty.", code="empty")
    raw_url = raw_url.strip()
    if len(raw_url) > max_len:
        raise URLValidationError("URL exceeds maximum length.", code="too_long")

    # Add scheme if the user omitted it (example.com -> https://example.com).
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parts = urlsplit(raw_url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Scheme '{scheme}' is not allowed. Only http and https are permitted.",
            code="bad_scheme",
        )
    if "@" in parts.netloc:
        raise URLValidationError(
            "URLs containing credentials (user@host) are not allowed.", code="userinfo"
        )

    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        raise URLValidationError("URL has no hostname.", code="no_host")
    if hostname in _BLOCKED_HOSTNAMES:
        raise URLValidationError("Hostname is blocked (internal).", code="blocked_host")

    try:
        port = parts.port
    except ValueError:
        raise URLValidationError("Invalid port in URL.", code="bad_port")

    if port is not None and not (1 <= port <= 65535):
        raise URLValidationError("Invalid port.", code="bad_port")

    # If the hostname is a literal IP, check it directly.
    resolved: list[str] = []
    literal_ip = None
    try:
        literal_ip = str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    if literal_ip:
        if _ip_is_blocked(literal_ip):
            raise URLValidationError(
                "IP address points to a private/internal range.", code="private_ip"
            )
        resolved = [literal_ip]
    elif resolve:
        resolved = _resolve(hostname)
        for ip in resolved:
            if _ip_is_blocked(ip):
                raise URLValidationError(
                    "Hostname resolves to a private/internal address.", code="private_ip"
                )

    # Normalize: lowercase scheme+host, drop default port, keep path/query verbatim.
    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"

    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return NormalizedURL(
        original=raw_url,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        resolved_ips=resolved,
        resolves=bool(resolved),
    )


# --------------------------------------------------------------------------
# Optional direct probe (disabled by default). Used for HTTPS/redirect/cert.
# --------------------------------------------------------------------------
class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to a pinned IP but verifies SNI against host."""

    def __init__(self, host: str, ip: str, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def safe_http_probe(url: NormalizedURL, method: str = "HEAD", timeout: int = 5):
    """
    Perform a single, non-redirect-following request with a pinned IP.
    Returns (status_code, headers_dict). Raises URLValidationError on unsafe host.
    Only call this when settings.LINKGUARD['ALLOW_DIRECT_PROBE'] is True.
    """
    if not url.resolved_ips:
        raise URLValidationError("Host did not resolve.", code="no_dns")
    ip = url.resolved_ips[0]
    if _ip_is_blocked(ip):  # re-check (defense in depth)
        raise URLValidationError("Blocked IP.", code="private_ip")

    port = url.port or (443 if url.scheme == "https" else 80)
    if url.scheme == "https":
        conn = _PinnedHTTPSConnection(
            url.hostname, ip, port=port, timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        conn.host = url.hostname  # for correct Host header

    try:
        path = url.path + (f"?{url.query}" if url.query else "")
        conn.request(method, path, headers={"Host": url.hostname, "User-Agent": "LinkGuard/1.0"})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders())
    finally:
        conn.close()

