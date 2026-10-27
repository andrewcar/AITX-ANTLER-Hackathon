"""Kill switch, concurrency cap, and append-only audit. No sockets to a target."""
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

import audit
import auth
import control
import main
import orchestrator
import recon

RESULT = {
    "run_id": "run_ok",
    "auth": {"authenticated": False, "scheme": "none"},
    "fingerprint": {"stack": "unknown", "lang": "unknown"},
    "surface": {"pages": 1, "forms": 0, "params": 0},
    "units": 0,
    "specialists_run": [],
    "recon": {"status": 200, "server": "stub", "scanned_internal": False},
    "model": "test-model",
    "ai_available": False,
    "findings": [],
    "summary": {"total": 0, "confirmed": 0, "unverified": 0, "rejected": 0},
}


class _Headers:
    def __init__(self, items):
        self._items = [(k.lower(), v) for k, v in items]

    def get(self, key, default=None):
        key = key.lower()
        for k, v in self._items:
            if k == key:
                return v
        return default

    def get_all(self, key):
        key = key.lower()
        return [v for k, v in self._items if k == key]

    def items(self):
        return list(self._items)


class _Resp:
    status = 200
    headers = _Headers([("server", "stub"), ("content-type", "text/html")])

    def read(self, _n):
        return b"<html>ok</html>"


def _login(client: TestClient) -> str:
    res = client.post("/auth/login", json={"email": "erwin@local", "password": "demo"})
    assert res.status_code == 200
    return res.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _stub_opener(monkeypatch, fn):
    monkeypatch.setattr(recon._no_redirect_opener, "open", fn)


def test_stop_between_requests_skips_the_next_call(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSWARM_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    control.testing_reset()
    calls = {"n": 0}
    lease = control.acquire(target="http://127.0.0.1/", actor="tester", run_id="run_stop")

    def opener(_req, timeout=None):
        calls["n"] += 1
        lease.stop()
        return _Resp()

    _stub_opener(monkeypatch, opener)
    with control.scope(lease), control.agent("crawler"):
        first = recon.get("http://127.0.0.1/a")
        assert first["status"] == 200
        with pytest.raises(control.ScanStopped):
            recon.get("http://127.0.0.1/b")
    assert calls["n"] == 1
    reqs = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert reqs and reqs[0]["agent"] == "crawler"
    assert reqs[0]["status"] == 200
    assert reqs[0]["action"] == "GET"
    assert "body" not in reqs[0]
    control.release(lease.run_id)


def test_stop_during_a_blocked_request_returns_within_a_second(monkeypatch):
    control.testing_reset()
    started = threading.Event()
    release = threading.Event()

    def opener(_req, timeout=None):
        started.set()
        release.wait(5)
        return _Resp()

    _stub_opener(monkeypatch, opener)
    lease = control.acquire(target="http://127.0.0.1/", actor="tester", run_id="run_block")

    def killer():
        assert started.wait(2)
        lease.stop()

    threading.Thread(target=killer, daemon=True).start()
    started_at = time.perf_counter()
    with control.scope(lease):
        with pytest.raises(control.ScanStopped):
            recon.get("http://127.0.0.1/slow")
    elapsed = time.perf_counter() - started_at
    release.set()
    assert elapsed < 1.0, elapsed
    control.release(lease.run_id)


def test_pace_rechecks_stop_instead_of_sleeping_out_the_interval(monkeypatch):
    monkeypatch.setenv("VULNSWARM_REQUEST_INTERVAL_MS", "5000")
    monkeypatch.setenv("VULNSWARM_GLOBAL_REQUEST_INTERVAL_MS", "0")
    control.testing_reset()
    lease = control.acquire(target="http://127.0.0.1/", actor="tester", run_id="run_pace_stop")
    with control.scope(lease):
        control.pace()

        def stop_soon():
            time.sleep(0.05)
            lease.stop()

        threading.Thread(target=stop_soon, daemon=True).start()
        started = time.perf_counter()
        with pytest.raises(control.ScanStopped):
            control.pace()
        assert time.perf_counter() - started < 1.0
    control.release(lease.run_id)


def test_stop_inside_map_does_not_crawl(monkeypatch):
    control.testing_reset()
    lease = control.acquire(target="http://127.0.0.1/lab", actor="tester", run_id="run_map")
    gets = {"n": 0}

    def scan(_url, session=None):
        lease.stop()
        return {
            "status": 200, "server": "stub", "scanned_internal": _url,
            "missing_security_headers": [], "set_cookie": [], "raw_headers": {},
        }

    def get(_url, session=None, max_bytes=200_000):
        gets["n"] += 1
        raise AssertionError("crawler fetched after the kill switch")

    monkeypatch.setattr(recon, "scan", scan)
    monkeypatch.setattr(recon, "get", get)
    monkeypatch.setattr(
        auth, "maybe_login",
        lambda url, session: {"authenticated": False, "scheme": "none", "note": ""},
    )
    events = []
    with control.scope(lease):
        result = orchestrator.run_scan(
            "http://127.0.0.1/lab",
            on_event=events.append,
            should_stop=lease.stopped,
            run_id=lease.run_id,
        )
    assert result["status"] == "cancelled"
    assert result["run_id"] == "run_map"
    assert gets["n"] == 0
    phases = [(e.get("phase"), e.get("status")) for e in events if e["type"] == "phase"]
    assert ("MAP", "started") in phases
    assert ("MAP", "finished") not in phases
    assert events[-1]["type"] == "scan_complete"
    assert events[-1]["status"] == "cancelled"
    control.release(lease.run_id)


def test_stop_all_does_not_latch_later_scans(monkeypatch):
    monkeypatch.setenv("VULNSWARM_MAX_CONCURRENT_SCANS", "5")
    control.testing_reset()
    first = control.acquire("http://127.0.0.1/a", "t", run_id="run_a")
    second = control.acquire("http://127.0.0.1/b", "t", run_id="run_b")
    stopped = control.stop_all()
    assert set(stopped) == {"run_a", "run_b"}
    assert first.stopped() and second.stopped()
    later = control.acquire("http://127.0.0.1/c", "t", run_id="run_c")
    assert not later.stopped()
    for run_id in ("run_a", "run_b", "run_c"):
        control.release(run_id)


def test_allowlist_is_checked_before_the_concurrency_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSWARM_MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("VULNSWARM_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "_rev_dns", lambda _host: "")
    control.testing_reset()
    held = control.acquire("http://127.0.0.1/held", "holder", run_id="held")

    def explode(*_a, **_k):
        raise AssertionError("run_scan must not run when the gate refuses")

    monkeypatch.setattr(orchestrator, "run_scan", explode)
    client = TestClient(main.app)
    token = _login(client)

    denied = client.post("/scan", json={"url": "http://example.com/"}, headers=_auth(token))
    assert denied.status_code == 403
    assert "allowlist" in denied.json()["detail"]

    busy = client.post("/scan", json={"url": "http://127.0.0.1/"}, headers=_auth(token))
    assert busy.status_code == 429
    assert "too many scans" in busy.json()["detail"]
    assert busy.headers.get("retry-after") == "2"

    stream = client.post("/scan/stream", json={"url": "http://127.0.0.1/lab"}, headers=_auth(token))
    assert stream.status_code == 429

    control.release(held.run_id)

    def fake(url, on_event=None, should_stop=None, run_id=None):
        body = dict(RESULT)
        body["run_id"] = run_id
        return body

    monkeypatch.setattr(orchestrator, "run_scan", fake)
    ok = client.post("/scan", json={"url": "http://127.0.0.1/"}, headers=_auth(token))
    assert ok.status_code == 200
    assert ok.json()["status"] == "complete"

    scans = [row for row in audit.recent(40) if row["kind"] == "scan"]
    details = {(row.get("status"), row.get("detail")) for row in scans}
    assert ("rejected", "allowlist") in details
    assert ("rejected", "rate_limit") in details


def test_request_pacing_spaces_two_calls(monkeypatch):
    monkeypatch.setenv("VULNSWARM_REQUEST_INTERVAL_MS", "80")
    monkeypatch.setenv("VULNSWARM_GLOBAL_REQUEST_INTERVAL_MS", "0")
    control.testing_reset()
    lease = control.acquire("http://127.0.0.1/", "tester", run_id="run_pace")
    _stub_opener(monkeypatch, lambda _req, timeout=None: _Resp())
    with control.scope(lease):
        started = time.perf_counter()
        assert recon.get("http://127.0.0.1/1")["status"] == 200
        assert recon.get("http://127.0.0.1/2")["status"] == 200
        elapsed = time.perf_counter() - started
    assert elapsed >= 0.07, elapsed
    control.release(lease.run_id)


def test_audit_is_append_only_and_readable(monkeypatch, tmp_path):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("VULNSWARM_AUDIT_LOG", str(path))
    audit.record(
        "scan", actor="erwin@local", target="http://127.0.0.1/",
        status="started", run_id="r1",
    )
    first = path.read_text(encoding="utf-8")
    audit.record(
        "request", run_id="r1", target="http://127.0.0.1/", actor="erwin@local",
        agent="injection", action="GET", url="http://127.0.0.1/x", status=200,
    )
    text = path.read_text(encoding="utf-8")
    assert text.startswith(first)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["status"] == "started"

    client = TestClient(main.app)
    assert client.get("/audit").status_code in (401, 403)
    assert client.get("/audit", headers={"Authorization": "Bearer nope"}).status_code == 401
    token = _login(client)
    res = client.get("/audit?limit=10", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert [row["kind"] for row in body["records"][:2]] == ["request", "scan"]
    assert body["records"][0]["agent"] == "injection"
    assert body["limits"]["max_concurrent"] >= 1
    assert "request_interval_ms" in body["limits"]


def test_blocking_cancel_is_409_and_stop_endpoint_halts_one_or_all(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNSWARM_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VULNSWARM_MAX_CONCURRENT_SCANS", "4")
    control.testing_reset()

    def fake(url, on_event=None, should_stop=None, run_id=None):
        control.stop(run_id)
        return {"run_id": run_id, "status": "cancelled"}

    monkeypatch.setattr(orchestrator, "run_scan", fake)
    client = TestClient(main.app)
    token = _login(client)
    cancelled = client.post("/scan", json={"url": "http://localhost/"}, headers=_auth(token))
    assert cancelled.status_code == 409
    assert cancelled.json()["detail"] == "scan stopped"

    one = control.acquire("http://127.0.0.1/", "erwin@local", run_id="run_api")
    other = control.acquire("http://127.0.0.1/other", "erwin@local", run_id="run_other")
    stopped = client.post("/scan/stop", json={"run_id": "run_api"}, headers=_auth(token))
    assert stopped.status_code == 200
    assert stopped.json()["stopped"] == ["run_api"]
    assert one.stopped()
    assert not other.stopped()

    everyone = client.post("/scan/stop", json={"all": True}, headers=_auth(token))
    assert everyone.status_code == 200
    assert "run_other" in everyone.json()["stopped"]
    assert other.stopped()
    fresh = control.acquire("http://127.0.0.1/fresh", "erwin@local", run_id="run_fresh")
    assert not fresh.stopped()
    for run_id in ("run_api", "run_other", "run_fresh"):
        control.release(run_id)

    rows = [row for row in audit.recent(20) if row.get("status") == "stop_requested"]
    assert rows
    assert {row.get("detail") for row in rows} >= {"one", "all"}
