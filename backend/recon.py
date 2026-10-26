"""
Recon agent — the REAL scanning step (no LLM here).

Fetches the target over HTTP and collects factual evidence: status, response headers,
server banner, Set-Cookie values. This hard data is what the LLM later triages.

Internal addressing: the browser submits a friendly URL like http://10.0.0.32:3001,
but inside the docker network the backend reaches targets by service name. TARGET_MAP
translates public host:port -> internal base so scans work the same for everyone.
"""
import urllib.request
from urllib.parse import urlparse

# public (browser-facing) host:port  ->  internal base the backend container can reach
TARGET_MAP = {
    ("10.0.0.32", "3001"): "http://juice:3000",
    ("10.0.0.32", "8081"): "http://dvwa:80",
    ("localhost", "3001"): "http://juice:3000",
    ("127.0.0.1", "3001"): "http://juice:3000",
    ("localhost", "8081"): "http://dvwa:80",
    ("127.0.0.1", "8081"): "http://dvwa:80",
}

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def resolve(url: str) -> str:
    """Map a public URL to the internal address the backend can actually reach."""
    p = urlparse(url)
    port = str(p.port or (443 if p.scheme == "https" else 80))
    base = TARGET_MAP.get((p.hostname or "", port))
    if base:
        # keep the original path/query against the internal base
        tail = url.split(p.netloc, 1)[-1] if p.netloc in url else ""
        return base + tail
    return url  # not mapped (e.g. native localhost dev) -> use as-is


def scan(url: str) -> dict:
    """GET the target and collect factual evidence. Raises on network failure."""
    internal = resolve(url)
    req = urllib.request.Request(internal, headers={"User-Agent": "VulnSwarm/0.1 recon"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status
        headers = resp.headers
    except urllib.error.HTTPError as e:
        # an HTTP error (403/500/etc.) is still useful evidence, not a failure
        status = e.code
        headers = e.headers

    raw = {k.lower(): v for k, v in headers.items()}
    set_cookie = headers.get_all("Set-Cookie") or []

    return {
        "url": url,                         # report the ORIGINAL url to the user
        "scanned_internal": internal,       # what we actually hit (debug/transparency)
        "status": status,
        "server": raw.get("server", ""),
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in raw],
        "set_cookie": set_cookie,
        "raw_headers": raw,
    }
