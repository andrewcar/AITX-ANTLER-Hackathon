"""
MAP phase — discover the site's attack surface (its 'sections').

Bounded BFS from the target, same host only. Produces:
  - pages:  reachable URLs
  - forms:  {page, action, method, inputs:[names]}      <- sections for injection/auth
  - params: {page, param, method}                         <- injectable inputs

Stdlib only (html.parser). Kept small and safe: capped pages/depth, no JS execution.
"""
import html.parser
from urllib.parse import urljoin, urlparse, parse_qs

import recon

MAX_PAGES = 15
MAX_DEPTH = 2


class _HTMLScan(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "get").lower(),
                          "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def map_site(url: str, session=None) -> dict:
    target_host = urlparse(url).hostname
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(url, 0)]
    pages, forms, params = [], [], []

    while queue and len(pages) < MAX_PAGES:
        cur, depth = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)

        page = recon.get(cur, session)
        if page["status"] == 0:
            continue
        pages.append({"url": cur, "status": page["status"]})

        # query-string params on this URL are injectable sections
        for p in parse_qs(urlparse(cur).query):
            params.append({"page": cur, "param": p, "method": "get"})

        if "html" not in page.get("content_type", "") and not page["body"].lstrip().startswith("<"):
            continue

        parser = _HTMLScan()
        try:
            parser.feed(page["body"])
        except Exception:
            pass

        for f in parser.forms:
            action = urljoin(cur, f["action"] or cur)
            if urlparse(action).hostname == target_host:
                forms.append({"page": cur, "action": action,
                              "method": f["method"], "inputs": f["inputs"]})

        if depth < MAX_DEPTH:
            for href in parser.links:
                nxt = urljoin(cur, href)
                nu = urlparse(nxt)
                if nu.hostname == target_host and nxt.split("#")[0] not in seen:
                    queue.append((nxt.split("#")[0], depth + 1))

    return {"pages": pages, "forms": forms, "params": params}
