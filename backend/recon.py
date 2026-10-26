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


def send(full_url: str, method: str = "get", data: dict | None = None) -> dict:
    """Send a GET/POST with params (for active injection probing). Never raises.
    Only used against allowlisted lab targets we own."""
    from urllib.parse import urlencode

    data = data or {}
    internal = resolve(full_url)
    if method.lower() == "post":
        req = urllib.request.Request(
            internal, data=urlencode(data).encode(),
            headers={"User-Agent": "VulnSwarm/0.1 probe"}, method="POST")
    else:
        if data:
            sep = "&" if urlparse(internal).query else "?"
            internal = internal + sep + urlencode(data)
        req = urllib.request.Request(internal, headers={"User-Agent": "VulnSwarm/0.1 probe"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status, body = resp.status, resp.read(16000)
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(16000)
        except Exception:
            body = b""
    except Exception:
        return {"status": 0, "body": ""}
    return {"status": status, "body": body.decode("utf-8", "replace")}


def get(full_url: str, max_bytes: int = 200_000) -> dict:
    """Fetch a page's full-ish body (for the crawler). Never raises."""
    internal = resolve(full_url)
    req = urllib.request.Request(internal, headers={"User-Agent": "VulnSwarm/0.1 crawler"})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status, headers, body = resp.status, resp.headers, resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        status, headers = e.code, e.headers
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
    except Exception:
        return {"url": full_url, "status": 0, "headers": {}, "body": ""}
    ctype = (headers.get("Content-Type") or "").lower()
    return {
        "url": full_url,
        "status": status,
        "content_type": ctype,
        "body": body.decode("utf-8", "replace"),
    }


def looks_like_app_html(snippet: str) -> bool:
    """True if the body looks like a rendered web page (SPA/app shell), not a file.
    Note: PHP source ('<?php ...') is NOT app html — we want to catch those."""
    s = snippet.lower()
    return any(t in s for t in ("<!doctype", "<html", "<!--", "<head"))


def probe(full_url: str) -> dict:
    """GET a specific URL/path. Returns status, body length, and a small snippet.
    Used by the surface agent to check for exposed paths. Never raises."""
    internal = resolve(full_url)
    req = urllib.request.Request(internal, headers={"User-Agent": "VulnSwarm/0.1 probe"})
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        status, body = resp.status, resp.read(4096)
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(4096)
        except Exception:
            body = b""
    except Exception:
        return {"url": full_url, "status": 0, "length": 0, "snippet": ""}
    return {
        "url": full_url,
        "status": status,
        "length": len(body),
        "snippet": body[:300].decode("utf-8", "replace"),
    }


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
