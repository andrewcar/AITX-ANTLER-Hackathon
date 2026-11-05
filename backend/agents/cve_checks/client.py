"""The only HTTP helper the CVE checks use.

``recon.fetch`` and ``recon.post_brotli_json`` both go through ``recon._do``,
which applies the kill switch, the global and per-scan rate limits, the
redirect allowlist, and the audit log. Checks pass ``session=None`` on GETs so
a cookie from another agent is not presented as a login.
"""
from urllib.parse import urlparse

import recon


def base_url(ctx) -> str:
    root = getattr(ctx, "recon_root", None) or {}
    raw = (root.get("url") or getattr(ctx, "url", "") or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    return raw.rstrip("/")


def root_observation(ctx) -> tuple[dict, str]:
    """Headers and body the root GET already collected. No new request."""
    root = getattr(ctx, "recon_root", None) or {}
    headers: dict[str, str] = {}
    for key, value in (root.get("raw_headers") or {}).items():
        headers[str(key).lower()] = value if isinstance(value, str) else str(value)
    server = root.get("server") or ""
    if server and "server" not in headers:
        headers["server"] = str(server)
    body = root.get("body_snippet") or ""
    if not isinstance(body, str):
        body = str(body)
    return headers, body


def _reject_bad_path(path: str) -> None:
    if not path.startswith("/") or path.startswith("//") or "\\" in path or ".." in path:
        raise ValueError("CVE checks only request a relative path on the scan target")


def fetch_path(ctx, path: str, max_bytes: int = 65536) -> dict:
    """Unauthenticated GET of one relative path. Does not follow redirects."""
    _reject_bad_path(path)
    base = base_url(ctx)
    if not base:
        return {
            "url": path, "status": 0, "content_type": "", "headers": {},
            "body": "", "length": 0,
        }
    return recon.fetch(base + path, session=None, max_bytes=max_bytes, follow=False)


def _empty_fetch(url: str = "") -> dict:
    return {
        "url": url, "status": 0, "content_type": "", "headers": {},
        "body": "", "length": 0,
    }


def page_url(ctx) -> str:
    """In-scope page URL, path only. No query string is copied onto it."""
    root = getattr(ctx, "recon_root", None) or {}
    raw = (root.get("url") or getattr(ctx, "url", "") or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//") or "\\" in path or ".." in path:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def fetch_page(ctx, max_bytes: int = 65536) -> dict:
    """Unauthenticated GET of the in-scope page path. Does not follow redirects."""
    url = page_url(ctx)
    if not url:
        return _empty_fetch()
    return recon.fetch(url, session=None, max_bytes=max_bytes, follow=False)


def same_target(ctx, url: str) -> bool:
    """True when ``url`` is http(s) on the same host and port as the scan target."""
    base = base_url(ctx)
    if not base:
        return False
    left, right = urlparse(base), urlparse(url)
    if right.scheme not in ("http", "https") or not right.hostname:
        return False
    if (left.hostname or "").lower() != right.hostname.lower():
        return False

    def _port(parsed) -> int:
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    return _port(left) == _port(right)
