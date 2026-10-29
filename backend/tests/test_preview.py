"""Target preview for the dashboard. Off-list hosts are never fetched."""
import urllib.error
from email.message import Message

from fastapi.testclient import TestClient

import main


def _login(client: TestClient) -> str:
    res = client.post("/auth/login", json={"email": "erwin@local", "password": "demo"})
    assert res.status_code == 200
    return res.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _response(status, headers, body):
    class Resp:
        def __init__(self):
            self.status = status
            self.headers = headers
            self._body = body

        def read(self, _n):
            return self._body

        def close(self):
            pass

    return Resp()


def test_preview_off_allowlist_does_not_fetch(monkeypatch):
    def explode(*_a, **_k):
        raise AssertionError("preview fetched a host that is not on the allowlist")

    monkeypatch.setattr(main, "fetch_preview", explode)
    client = TestClient(main.app)
    token = _login(client)
    res = client.get("/preview", params={"url": "http://example.com/admin"}, headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["allowlisted"] is False
    assert body["mode"] == "placeholder"
    assert body["frameable"] is False
    assert body["host"] == "example.com"


def test_preview_requires_auth():
    client = TestClient(main.app)
    assert client.get("/preview", params={"url": "http://127.0.0.1/"}).status_code in (401, 403)


def test_preview_allowlisted_reports_iframe(monkeypatch):
    def fake(url):
        assert url == "http://127.0.0.1/lab"
        return {
            "mode": "iframe", "frameable": True, "status": 200,
            "title": "Lab", "server": "stub",
        }

    monkeypatch.setattr(main, "fetch_preview", fake)
    client = TestClient(main.app)
    token = _login(client)
    res = client.get("/preview", params={"url": "http://127.0.0.1/lab"}, headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["allowlisted"] is True
    assert body["mode"] == "iframe"
    assert body["host"] == "127.0.0.1"
    assert body["title"] == "Lab"


def test_fetch_preview_xfo_deny_is_a_placeholder(monkeypatch):
    headers = Message()
    headers["X-Frame-Options"] = "DENY"
    headers["Server"] = "stub"

    def open_one(_req, timeout=None):
        return _response(200, headers, b"<html><title>Lab home</title><body>ok</body></html>")

    monkeypatch.setattr(main._preview_opener, "open", open_one)
    info = main.fetch_preview("http://127.0.0.1/lab")
    assert info["frameable"] is False
    assert info["mode"] == "placeholder"
    assert info["title"] == "Lab home"
    assert info["status"] == 200


def test_fetch_preview_without_framing_policy_is_an_iframe(monkeypatch):
    headers = Message()
    headers["Server"] = "stub"
    monkeypatch.setattr(
        main._preview_opener, "open",
        lambda _req, timeout=None: _response(200, headers, b"<title>Open</title>"),
    )
    info = main.fetch_preview("http://localhost/")
    assert info["frameable"] is True
    assert info["mode"] == "iframe"
    assert info["title"] == "Open"


def test_fetch_preview_does_not_follow_redirects(monkeypatch):
    seen = []
    headers = Message()
    headers["Location"] = "http://example.com/landed"

    def open_one(req, timeout=None):
        seen.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 302, "found", headers, None)

    monkeypatch.setattr(main._preview_opener, "open", open_one)
    info = main.fetch_preview("http://127.0.0.1/lab")
    assert seen == ["http://127.0.0.1/lab"]
    assert info["mode"] == "placeholder"
    assert info["frameable"] is False
    assert info["status"] == 302


def test_fetch_preview_network_error_is_a_placeholder(monkeypatch):
    def boom(_req, timeout=None):
        raise OSError("down")

    monkeypatch.setattr(main._preview_opener, "open", boom)
    info = main.fetch_preview("http://127.0.0.1/lab")
    assert info["mode"] == "placeholder"
    assert info["frameable"] is False
    assert info["status"] == 0
