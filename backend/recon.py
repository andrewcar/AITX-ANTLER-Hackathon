"""
Recon — the REAL request layer (no LLM here).

Every HTTP call goes through _do(), which carries an optional Session (a simple cookie
store). One Session per scan, shared via ScanContext, lets the swarm act AUTHENTICATED:
log in once, and the crawler + every specialist reuse the logged-in cookies.

Internal addressing: the browser submits http://10.0.0.32:3001, but inside docker the
backend reaches targets by service name. TARGET_MAP translates public host:port ->
internal base so scans work the same for everyone.
"""
import urllib.error
import urllib.request
from urllib.parse import urlencode, urljoin, urlparse

TARGET_MAP = {
    ("10.0.0.32", "3001"): "http://juice:3000",
    ("10.0.0.32", "8081"): "http://dvwa:80",
    ("localhost", "3001"): "http://juice:3000",
    ("127.0.0.1", "3001"): "http://juice:3000",
    ("localhost", "8081"): "http://dvwa:80",
    ("127.0.0.1", "8081"): "http://dvwa:80",
}

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


class Session:
    """Cookie store shared across a scan (one target per scan), keyed by name only.
    Keying by name sidesteps server domain quirks (e.g. cookies set for 'dvwa.local'
    while we address 'dvwa'); redirects are followed manually so the latest Set-Cookie
    (e.g. a regenerated session on login) always wins."""

    def __init__(self):
        self.cookies: dict[str, str] = {}

    def set_cookie(self, name: str, value: str):
        self.cookies[name] = value

    def header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def update(self, rhdrs):
        for sc in (rhdrs.get_all("Set-Cookie") or []):
            part = sc.split(";", 1)[0].strip()
            if "=" in part:
                k, v = part.split("=", 1)
                self.cookies[k.strip()] = v.strip()


_REDIRECT_CODES = {301, 302, 303, 307, 308}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # don't auto-follow; we follow manually to control cookies


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def resolve(url: str) -> str:
    """Map a public URL to the internal address the backend can actually reach."""
    p = urlparse(url)
    port = str(p.port or (443 if p.scheme == "https" else 80))
    base = TARGET_MAP.get((p.hostname or "", port))
    if base:
        tail = url.split(p.netloc, 1)[-1] if p.netloc in url else ""
        return base + tail
    return url


def looks_like_app_html(snippet: str) -> bool:
    """True if the body looks like a rendered page (SPA/app shell), not a file.
    Note: PHP source ('<?php ...') is NOT app html — we want to catch those."""
    s = snippet.lower()
    return any(t in s for t in ("<!doctype", "<html", "<!--", "<head"))


def _do(internal_url, session=None, method="GET", data=None, timeout=10,
        read=16000, follow=True, _depth=0):
    """Central request. Returns (status, headers, body_bytes) or None on network fail.
    Cookies from the Session are sent and updated on every hop; redirects are followed
    manually (when follow=True) so cookies propagate correctly."""
    headers = {"User-Agent": "VulnSwarm/0.1"}
    if session:
        h = session.header()
        if h:
            headers["Cookie"] = h
    if method == "POST":
        req = urllib.request.Request(internal_url, data=urlencode(data or {}).encode(),
                                     headers=headers, method="POST")
    else:
        if data:
            sep = "&" if urlparse(internal_url).query else "?"
            internal_url = internal_url + sep + urlencode(data)
        req = urllib.request.Request(internal_url, headers=headers)
    try:
        resp = _no_redirect_opener.open(req, timeout=timeout)
        status, rhdrs, body = resp.status, resp.headers, resp.read(read)
    except urllib.error.HTTPError as e:
        status, rhdrs = e.code, e.headers
        try:
            body = e.read(read)
        except Exception:
            body = b""
    except Exception:
        return None
    if session and rhdrs is not None:
        session.update(rhdrs)
    if follow and status in _REDIRECT_CODES and _depth < 5 and rhdrs is not None:
        loc = rhdrs.get("Location")
        if loc:
            return _do(urljoin(internal_url, loc), session, "GET", None,
                       timeout, read, follow, _depth + 1)
    return status, rhdrs, body


def scan(url: str, session: "Session | None" = None) -> dict:
    """GET the target root; collect factual evidence. Raises if unreachable."""
    internal = resolve(url)
    res = _do(internal, session, read=4000)
    if res is None:
        raise RuntimeError(f"target unreachable: {url}")
    status, rhdrs, _ = res
    raw = {k.lower(): v for k, v in rhdrs.items()}
    set_cookie = rhdrs.get_all("Set-Cookie") or []
    return {
        "url": url,
        "scanned_internal": internal,
        "status": status,
        "server": raw.get("server", ""),
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in raw],
        "set_cookie": set_cookie,
        "raw_headers": raw,
    }


def get(full_url: str, session: "Session | None" = None, max_bytes: int = 200_000) -> dict:
    """Fetch a page's body (for the crawler). Never raises."""
    res = _do(resolve(full_url), session, read=max_bytes)
    if res is None:
        return {"url": full_url, "status": 0, "content_type": "", "body": ""}
    status, rhdrs, body = res
    ctype = (rhdrs.get("Content-Type") or "").lower() if rhdrs else ""
    return {"url": full_url, "status": status, "content_type": ctype,
            "body": body.decode("utf-8", "replace")}


def probe(full_url: str, session: "Session | None" = None) -> dict:
    """GET a path; return status, length, snippet. Never raises.
    Does NOT follow redirects — a 302 means the path isn't directly served."""
    res = _do(resolve(full_url), session, read=4096, follow=False)
    if res is None:
        return {"url": full_url, "status": 0, "length": 0, "snippet": ""}
    status, _, body = res
    return {"url": full_url, "status": status, "length": len(body),
            "snippet": body[:300].decode("utf-8", "replace")}


def send(full_url: str, method: str = "get", data: dict | None = None,
         session: "Session | None" = None) -> dict:
    """Send a GET/POST with params (active injection probing). Never raises.
    Only used against allowlisted lab targets we own."""
    res = _do(resolve(full_url), session, method=method.upper(), data=data or {}, read=16000)
    if res is None:
        return {"status": 0, "body": ""}
    status, _, body = res
    return {"status": status, "body": body.decode("utf-8", "replace")}
