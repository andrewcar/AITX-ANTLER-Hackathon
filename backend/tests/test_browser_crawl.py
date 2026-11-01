"""Headless crawl: scope lock, read-only, caps, STOP, pacing, audit.

The integration tests drive a real Chromium against a throwaway site served from this
process on 127.0.0.1. They skip when Playwright or its browser is not installed.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import browser_crawl
import control

SPA = b"""<!doctype html><html><body><div id=app>loading</div>
<a href="/r">to redirect</a> <a href="/r-out">off-site redirect</a> <a href="/logout.php">logout</a>
<script>
  // Routes and API calls exist only once the app's JavaScript runs.
  document.getElementById('app').innerHTML =
    '<a href="#/products">products</a> <a href="#/about">about</a>';
  fetch('/api/search?q=');                                // the app's own API call
  fetch('http://localhost:' + location.port + '/xorigin'); // allowlisted host, other origin
  fetch('/api/write', {method: 'POST', body: 'x=1'});      // state-changing: must be refused
</script></body></html>"""


class _Site(BaseHTTPRequestHandler):
    log: list = []

    def log_message(self, *a):
        pass

    def _record(self):
        _Site.log.append((time.monotonic(), self.command, self.headers.get("Host", ""), self.path))

    def do_GET(self):
        self._record()
        if self.path == "/" or self.path.startswith("/?"):
            return self._send(200, SPA, "text/html")
        if self.path == "/r":
            return self._redirect("/ok")
        if self.path == "/r-out":
            return self._redirect("http://example.com/landing")
        if self.path == "/ok":
            return self._send(200, b"<html>ok <a href='/'>home</a></html>", "text/html")
        if self.path.startswith("/api/search"):
            return self._send(200, json.dumps({"data": []}).encode(), "application/json")
        return self._send(404, b"nope", "text/plain")

    def do_POST(self):
        self._record()
        return self._send(200, b"written", "text/plain")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _browser_ok() -> bool:
    if not browser_crawl.available():
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            pw.chromium.launch().close()
        return True
    except Exception:
        return False


needs_browser = pytest.mark.skipif(not _browser_ok(), reason="Playwright Chromium not installed")


@pytest.fixture
def site():
    _Site.log = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def _crawl(url, **kw):
    lease = control.acquire(target=url, actor="test")
    try:
        with control.scope(lease):
            return browser_crawl.map_site(url, None, **kw), lease
    finally:
        control.release(lease.run_id)


def test_scope_check_needs_same_origin_and_allowlist():
    origin = browser_crawl._origin("http://127.0.0.1:3001/")
    assert browser_crawl._in_scope("http://127.0.0.1:3001/#/x?y=1", origin)
    assert not browser_crawl._in_scope("http://127.0.0.1:3002/", origin)      # other port
    assert not browser_crawl._in_scope("http://localhost:3001/", origin)      # allowlisted, other origin
    assert not browser_crawl._in_scope("https://127.0.0.1:3001/", origin)     # other scheme
    lan = browser_crawl._origin("http://10.0.0.32:3001/")
    assert not browser_crawl._in_scope("http://10.0.0.32:3001/", lan)         # same origin, off-allowlist


def test_route_key_keeps_hash_routes_and_drops_their_query():
    k = browser_crawl._route_key
    assert k("http://h:1/#/search?q=a") == k("http://h:1/#/search?q=b") == "http://h:1/#/search"
    assert k("http://h:1/#/about") != k("http://h:1/#/search")
    assert k("http://h:1") == "http://h:1/"


@needs_browser
def test_crawl_finds_spa_routes_and_api_params_without_leaving_scope(site):
    surface, lease = _crawl(site, budget_s=30)
    urls = {p["url"] for p in surface["pages"]}
    assert site + "#/products" in urls and site + "#/about" in urls      # JS-built routes
    assert site.rstrip("/") + "/ok" in urls                              # in-scope redirect followed
    assert ("q" in {p["param"] for p in surface["params"]})              # API param seen
    hits = [(m, host, path) for _, m, host, path in _Site.log]
    assert not any(m == "POST" for m, _, _ in hits), "the crawl must be read-only"
    assert not any(host.startswith("localhost") for _, host, _ in hits), "other origin reached"
    assert not any("logout" in path for _, _, path in hits), "logout link followed"
    assert surface["refused"] >= 2                                       # cross-origin + POST (+ redirect out)


@needs_browser
def test_refusals_are_audited(site):
    import audit
    surface, lease = _crawl(site, budget_s=30)
    rows = [r for r in audit.recent(500) if r.get("run_id") == lease.run_id]
    refused = [r for r in rows if r.get("action") == "BROWSER_REFUSED"]
    assert any("/xorigin" in r["url"] for r in refused)
    assert any("/api/write" in r["url"] for r in refused)
    served = [r for r in rows if r.get("agent") == "browser" and r.get("action") == "GET"]
    assert served, "served requests are audited like every other agent's"


@needs_browser
def test_page_cap_and_time_budget(site):
    surface, _ = _crawl(site, max_pages=2, budget_s=30)
    assert len(surface["pages"]) == 2
    t0 = time.monotonic()
    surface, _ = _crawl(site, budget_s=0.01)
    assert time.monotonic() - t0 < 10 and len(surface["pages"]) <= 1


@needs_browser
def test_stop_mid_crawl_halts_requests(site):
    lease = control.acquire(target=site, actor="test")
    stopped_at = {}

    def stop_soon():
        while len(_Site.log) < 2:
            time.sleep(0.01)
        stopped_at["t"] = time.monotonic()
        lease.stop()

    threading.Thread(target=stop_soon, daemon=True).start()
    try:
        with control.scope(lease), pytest.raises(control.ScanStopped):
            browser_crawl.map_site(site, None, budget_s=30)
    finally:
        control.release(lease.run_id)
    late = [t for t, *_ in _Site.log if t > stopped_at["t"] + 0.2]
    assert not late, f"{len(late)} requests reached the site after STOP"


@needs_browser
def test_requests_honor_the_rate_limit(site, monkeypatch):
    monkeypatch.setenv("VULNSWARM_REQUEST_INTERVAL_MS", "150")
    _crawl(site, max_pages=2, budget_s=30)
    times = sorted(t for t, *_ in _Site.log)
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert gaps and min(gaps) >= 0.13, f"requests closer than the pace: {min(gaps):.3f}s"
