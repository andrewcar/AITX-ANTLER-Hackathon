"""Demo-safety fixes: no LAN IP in scope, and redirects cannot leave the allowlist."""
import json

import main
import recon


class _Hdrs:
    def __init__(self, d):
        self._d = d

    def get(self, k, default=None):
        return self._d.get(k, default)

    def get_all(self, k):
        return []


def test_lan_tower_ip_is_not_allowlisted():
    assert "10.0.0.32" not in main.ALLOWLIST
    assert all("10.0.0.32" not in t["url"] for t in main.LAB_TARGETS)
    try:
        main.allowlisted_host("http://10.0.0.32:3001")
        raise AssertionError("10.0.0.32 must be refused")
    except main.ScopeError:
        pass


def test_off_allowlist_redirect_is_not_followed(monkeypatch, tmp_path):
    calls = []

    def fake_exchange(req, timeout, read):
        calls.append(req.full_url)
        return 302, _Hdrs({"Location": "https://example.com/landing"}), b""

    monkeypatch.setattr(recon, "_exchange", fake_exchange)
    status, _, _ = recon._do("http://127.0.0.1:8082/start")
    assert status == 302
    assert calls == ["http://127.0.0.1:8082/start"]  # example.com never requested
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(r.get("action") == "REDIRECT_REFUSED" and "example.com" in r["url"] for r in rows)


def test_in_scope_redirect_is_still_followed(monkeypatch):
    calls = []

    def fake_exchange(req, timeout, read):
        calls.append(req.full_url)
        if req.full_url.endswith("/start"):
            return 302, _Hdrs({"Location": "/login.php"}), b""
        return 200, _Hdrs({}), b"ok"

    monkeypatch.setattr(recon, "_exchange", fake_exchange)
    status, _, body = recon._do("http://dvwa:80/start")  # internal docker base
    assert status == 200 and body == b"ok"
    assert calls == ["http://dvwa:80/start", "http://dvwa:80/login.php"]
