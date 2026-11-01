"""
MAP, headless — crawl a JavaScript single-page app with Chromium (Playwright).

The static crawler (crawler.py) reads HTML only, so an SPA like Juice Shop shows it
one page and nothing to probe: its routes, links and API calls are built in the
browser. This module runs a real Chromium over the target, but the browser never
reaches the network itself. Every request it makes is intercepted here and either
refused or served through recon._do, the same guarded HTTP layer every agent uses
(STOP checkpoint, per-scan + global pacing, audit log, docker TARGET_MAP).

Guardrails:
  - same origin only: a request to any other scheme/host/port is refused, and every
    request is re-checked against main.ALLOWLIST. Refusals are audited (once per URL).
  - redirects are never followed by the browser. A 3xx page navigation is served as an
    empty page and its Location handed back to the crawl loop, which applies the same
    origin + allowlist checks before visiting it. Other 3xx responses are served empty.
  - read-only: only GET/HEAD are served. The crawl never submits a form or a POST.
  - nothing can slip past interception: service workers are blocked, all browser
    traffic is pointed at a dead proxy, and host-name resolution is disabled.
  - bounded: MAX_PAGES routes and BUDGET_S seconds; images, media and fonts skipped.

Output has the same shape as crawler.map_site (pages, forms, params). Params include
the query parameters of the app's own XHR/fetch calls (e.g. /rest/products/search?q=),
which is where an SPA's server-side inputs actually are.
"""
import time
from urllib.parse import parse_qs, urljoin, urlparse

import audit
import control
import recon

MAX_PAGES = 50
BUDGET_S = 60.0
NAV_TIMEOUT_S = 15.0
SETTLE_S = 2.0          # max quiet time after a navigation before reading the page
MAX_BODY = 8_000_000    # SPA bundles are large; recon's default read is 16 KB
SKIP_TYPES = {"image", "media", "font"}
# Transport plumbing, not application input: never probed, never served.
SKIP_PATH_PARTS = ("/socket.io/",)
_HOP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection",
                "set-cookie", "location"}
_LAUNCH_ARGS = [
    "--proxy-server=http://127.0.0.1:9",   # dead proxy: un-intercepted traffic goes nowhere
    "--proxy-bypass-list=<-loopback>",     # ...including loopback
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--disable-dev-shm-usage",             # docker's small /dev/shm otherwise crashes tabs
]

# Collects links, router links, and real <form>s (with their submit controls) from the DOM.
_EXTRACT_JS = """() => {
  const links = [];
  for (const a of document.querySelectorAll('a[href]')) links.push(a.getAttribute('href'));
  for (const el of document.querySelectorAll('[routerlink], [ng-reflect-router-link]')) {
    const r = el.getAttribute('routerlink') || el.getAttribute('ng-reflect-router-link');
    if (r) links.push('#' + (r.startsWith('/') ? r : '/' + r));
  }
  const forms = [];
  for (const f of document.querySelectorAll('form[action]')) {
    const inputs = [], submits = [];
    for (const el of f.querySelectorAll('input[name], textarea[name], select[name], button[name]')) {
      const t = (el.getAttribute('type') || (el.tagName === 'BUTTON' ? 'submit' : 'text')).toLowerCase();
      inputs.push(el.name);
      if (['submit', 'image', 'button'].includes(t)) submits.push({name: el.name, value: el.value || ''});
    }
    forms.push({action: f.getAttribute('action'), method: (f.getAttribute('method') || 'get').toLowerCase(),
                inputs, submits});
  }
  return {links, forms};
}"""


def available() -> bool:
    """True when Playwright is importable. The browser itself is checked at launch."""
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def _origin(url: str) -> tuple:
    p = urlparse(url)
    return (p.scheme, (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80))


def _in_scope(url: str, origin: tuple) -> bool:
    """Same scheme/host/port as the target AND on the server-side allowlist."""
    if _origin(url) != origin:
        return False
    import main  # lazy: main imports the orchestrator, which imports this module
    try:
        main.allowlisted_host(url)
        return True
    except main.ScopeError:
        return False


def _route_key(url: str) -> str:
    """One crawl entry per route: drop the query of the path, keep SPA hash routes."""
    p = urlparse(url)
    frag = p.fragment.split("?", 1)[0]
    return f"{p.scheme}://{p.netloc}{p.path or '/'}" + (f"#{frag}" if frag else "")


def map_site(url: str, session=None, max_pages: int = MAX_PAGES, budget_s: float = BUDGET_S) -> dict:
    """Crawl `url` in headless Chromium. Raises control.ScanStopped on STOP."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    lease = control.current_lease()
    agent_name = "browser"
    origin = _origin(url)
    deadline = time.monotonic() + budget_s
    state = {"stopped": False, "redirect": None}
    refused: set[str] = set()
    api_calls: dict[str, None] = {}
    served = {"n": 0}

    def refuse(route, req_url: str, why: str):
        key = req_url.split("#")[0][:300]
        if key not in refused:
            refused.add(key)
            audit.record("request", run_id=getattr(lease, "run_id", ""),
                         target=getattr(lease, "target", ""), actor=getattr(lease, "actor", ""),
                         agent=agent_name, action="BROWSER_REFUSED", url=key, status=0, detail=why)
        route.abort()

    def handler(route):
        # Playwright runs this in its own greenlet, which does not see the scan's
        # context variables, so re-enter the scan's lease and agent explicitly.
        with control.scope(lease), control.agent(agent_name):
            req = route.request
            req_url = req.url
            if state["stopped"] or control.stopped():
                state["stopped"] = True
                return route.abort()
            if not _in_scope(req_url, origin):
                return refuse(route, req_url, "off-origin or off-allowlist; not requested")
            if req.method not in ("GET", "HEAD"):
                return refuse(route, req_url, f"{req.method} refused; the crawl is read-only")
            if req.resource_type in SKIP_TYPES or any(s in req_url for s in SKIP_PATH_PARTS):
                return route.abort()
            try:
                res = recon._do(recon.resolve(req_url.split("#")[0]), session,
                                method="GET", read=MAX_BODY, follow=False)
            except control.ScanStopped:
                state["stopped"] = True
                return route.abort()
            if res is None:
                return route.abort()
            status, rhdrs, body = res
            served["n"] += 1
            if req.resource_type in ("xhr", "fetch") and urlparse(req_url).query:
                api_calls[req_url] = None
            if 300 <= status < 400:
                loc = rhdrs.get("Location") if rhdrs is not None else None
                if loc and req.is_navigation_request():
                    state["redirect"] = urljoin(req_url, loc)
                return route.fulfill(status=200, body=b"",
                                     headers={"content-type": "text/html"} if req.is_navigation_request() else {})
            headers = {k: v for k, v in (rhdrs.items() if rhdrs is not None else [])
                       if k.lower() not in _HOP_HEADERS}
            return route.fulfill(status=status, headers=headers, body=body)

    pages: list[dict] = []
    forms: list[dict] = []
    queue: list[str] = [url]
    seen: set[str] = set()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        try:
            context = browser.new_context(service_workers="block",
                                          user_agent="VulnSwarm/0.1 (headless crawl)")
            context.route("**/*", handler)
            page = context.new_page()
            while queue and len(pages) < max_pages:
                control.checkpoint()
                if state["stopped"]:
                    raise control.ScanStopped()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                cur = queue.pop(0)
                key = _route_key(cur)
                if key in seen:
                    continue
                seen.add(key)
                state["redirect"] = None
                try:
                    resp = page.goto(cur, wait_until="domcontentloaded",
                                     timeout=min(remaining, NAV_TIMEOUT_S) * 1000)
                    page.wait_for_load_state("networkidle",
                                             timeout=max(0.1, min(deadline - time.monotonic(), SETTLE_S)) * 1000)
                except PlaywrightError:
                    if state["stopped"] or control.stopped():
                        raise control.ScanStopped()
                    resp = None  # timeouts and aborted loads: keep what rendered
                if state["stopped"]:
                    raise control.ScanStopped()
                if state["redirect"]:
                    nxt = state["redirect"]
                    if _in_scope(nxt, origin) and "logout" not in nxt.lower():
                        queue.insert(0, nxt)
                    continue
                pages.append({"url": cur, "status": resp.status if resp else 200})
                try:
                    found = page.evaluate(_EXTRACT_JS)
                except PlaywrightError:
                    continue
                for href in found.get("links", []):
                    nxt = urljoin(page.url, href)
                    if "logout" in nxt.lower() or not _in_scope(nxt, origin):
                        continue
                    if _route_key(nxt) not in seen:
                        queue.append(nxt)
                for f in found.get("forms", []):
                    action = urljoin(page.url, f.get("action") or page.url).split("#")[0]
                    if _in_scope(action, origin):
                        forms.append({"page": cur, "action": action, "method": f.get("method", "get"),
                                      "inputs": f.get("inputs", []), "submits": f.get("submits", [])})
        finally:
            browser.close()

    params: list[dict] = []
    seen_params: set[tuple] = set()
    for page_url in [p["url"] for p in pages] + list(api_calls):
        u = urlparse(page_url.split("#")[0])
        for name in parse_qs(u.query, keep_blank_values=True):
            k = (u.path, name)
            if k not in seen_params:
                seen_params.add(k)
                params.append({"page": page_url.split("#")[0], "param": name, "method": "get"})
    return {"pages": pages, "forms": forms, "params": params,
            "engine": "browser", "api_calls": len(api_calls), "requests": served["n"],
            "refused": len(refused)}
