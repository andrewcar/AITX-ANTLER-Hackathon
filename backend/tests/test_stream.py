"""Live scan stream. These tests never open a socket to a target."""
import json
import threading
import time
import urllib.request

from fastapi.testclient import TestClient

import main
import orchestrator
import streaming

RESULT_KEYS = {
    "run_id", "auth", "fingerprint", "surface", "units", "specialists_run",
    "recon", "model", "ai_available", "findings", "summary",
}


def _login(client: TestClient) -> str:
    res = client.post("/auth/login", json={"email": "erwin@local", "password": "demo"})
    assert res.status_code == 200
    return res.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _block_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("scan tried to use the network")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)


def _install_pipeline(monkeypatch, state):
    """Replace every I/O step. Specialists overlap so the swarm still fans out."""
    _block_network(monkeypatch)

    monkeypatch.setattr(
        orchestrator.auth, "maybe_login",
        lambda url, session: {"authenticated": False, "scheme": "none", "note": "anonymous"},
    )
    monkeypatch.setattr(
        orchestrator.recon, "scan",
        lambda url, session=None: {
            "status": 200, "server": "test", "scanned_internal": False,
            "raw_headers": {}, "set_cookie": [], "missing_security_headers": [],
        },
    )
    monkeypatch.setattr(
        orchestrator.crawler, "map_site",
        lambda url, session: {
            "pages": [{"url": url + "/index.php"}],
            "forms": [],
            "params": [{"page": url, "param": "q"}],
        },
    )

    lock = threading.Lock()

    def specialist(finding):
        def run(section, ctx):
            with lock:
                state["running"] += 1
                state["max"] = max(state["max"], state["running"])
            time.sleep(0.2)
            with lock:
                state["running"] -= 1
            return [finding] if finding else []
        return run

    monkeypatch.setitem(orchestrator.SPECIALISTS, "config_headers", specialist({
        "layer": "config",
        "severity": "Low",
        "title": "Missing security header: content-security-policy",
        "evidence": "no csp",
        "fix": "Set a CSP.",
        "source": "deterministic",
        "check": {
            "type": "missing_header",
            "header": "content-security-policy",
            "payload": "SHOULD_NOT_STREAM",
        },
    }))
    monkeypatch.setitem(orchestrator.SPECIALISTS, "exposed_paths", specialist(None))
    monkeypatch.setitem(orchestrator.SPECIALISTS, "injection", specialist({
        "layer": "injection",
        "severity": "high",
        "title": "Reflected XSS",
        "evidence": "marker reflected",
        "fix": "Encode output.",
        "source": "deterministic",
        "check": {"type": "xss_reflect", "payload": "SHOULD_NOT_STREAM"},
    }))

    def verify(findings, url, session=None, on_verdict=None):
        for finding in findings:
            finding["verified"] = True
            finding["verdict"] = "confirmed"
            finding["verify_note"] = "ok"
            if on_verdict:
                on_verdict(finding)
        return findings

    monkeypatch.setattr(orchestrator.verifier, "verify_all", verify)


def test_format_sse_is_one_data_line():
    frame = streaming.format_sse({
        "type": "finding",
        "severity": "high",
        "evidence": "line\nbreak",
    })
    assert frame.startswith("event: finding\n")
    data_lines = [ln for ln in frame.split("\n") if ln.startswith("data:")]
    assert len(data_lines) == 1
    payload = json.loads(data_lines[0][len("data:"):].strip())
    assert payload["evidence"] == "line\nbreak"
    assert payload["severity"] == "high"


def test_allowlist_helper_rejects_without_network():
    assert main.allowlisted_host("http://localhost:8081/login.php") == "localhost"
    assert main.allowlisted_host("http://127.0.0.1/") == "127.0.0.1"
    try:
        main.allowlisted_host("https://example.com/admin")
    except main.ScopeError as e:
        assert "allowlist" in str(e)
    else:
        raise AssertionError("expected ScopeError")


def test_run_scan_emits_live_events_and_keeps_blocking_shape(monkeypatch):
    state = {"running": 0, "max": 0}
    _install_pipeline(monkeypatch, state)
    events = []
    result = orchestrator.run_scan("http://localhost/lab", on_event=events.append)

    assert set(result) == RESULT_KEYS
    assert "status" not in result
    assert events[0]["type"] == "scan_started"
    assert events[0]["agents"] == ["config_headers", "exposed_paths", "injection"]
    assert events[-1]["type"] == "scan_complete"
    assert events[-1]["status"] == "complete"
    assert events[-1]["run_id"] == result["run_id"]

    started = [e["phase"] for e in events if e["type"] == "phase" and e["status"] == "started"]
    finished = [e["phase"] for e in events if e["type"] == "phase" and e["status"] == "finished"]
    assert started == list(orchestrator.PHASES)
    assert finished == list(orchestrator.PHASES)
    order = {(e["phase"], e["status"]): i for i, e in enumerate(events) if e["type"] == "phase"}
    for prev, nxt in zip(orchestrator.PHASES, orchestrator.PHASES[1:]):
        assert order[(prev, "finished")] < order[(nxt, "started")]

    started_units = [e for e in events if e["type"] == "agent" and e["status"] == "started"]
    finished_units = [e for e in events if e["type"] == "agent" and e["status"] == "finished"]
    assert len(started_units) == len(finished_units) == result["units"] == 3
    assert state["max"] >= 2

    by_unit = {}
    for event in events:
        if event["type"] in ("agent", "finding") and event.get("unit_id"):
            marker = "finding" if event["type"] == "finding" else "agent:" + event["status"]
            by_unit.setdefault(event["unit_id"], []).append(marker)
    for seq in by_unit.values():
        assert seq[0] == "agent:started"
        assert seq[-1] == "agent:finished"

    findings = [e for e in events if e["type"] == "finding"]
    assert {f["severity"] for f in findings} == {"low", "high"}
    for finding in findings:
        assert "check" not in finding
        assert "SHOULD_NOT_STREAM" not in json.dumps(finding)
    verdicts = [e for e in events if e["type"] == "verdict"]
    assert [v["stream_id"] for v in verdicts] == [f["stream_id"] for f in findings]
    assert all(v["verdict"] == "confirmed" for v in verdicts)
    for reported in result["findings"]:
        assert "check" not in reported
        assert "_stream_id" not in reported
    assert result["summary"]["total"] == 2
    assert result["summary"]["confirmed"] == 2


def test_stop_before_auth_does_not_touch_the_pipeline(monkeypatch):
    _block_network(monkeypatch)

    def explode(*_a, **_k):
        raise AssertionError("phase ran after stop")

    monkeypatch.setattr(orchestrator.auth, "maybe_login", explode)
    events = []
    result = orchestrator.run_scan(
        "http://localhost/lab", on_event=events.append, should_stop=lambda: True,
    )
    assert result["status"] == "cancelled"
    assert [e["type"] for e in events] == ["scan_started", "scan_complete"]
    assert events[-1]["status"] == "cancelled"
    assert not any(e["type"] == "phase" for e in events)


def test_stop_during_swarm_skips_verify(monkeypatch):
    state = {"running": 0, "max": 0}
    _install_pipeline(monkeypatch, state)
    events = []
    flag = {"stop": False}

    def on_event(event):
        events.append(event)
        if event.get("type") == "phase" and event.get("phase") == "SWARM" and event.get("status") == "started":
            flag["stop"] = True

    orchestrator.run_scan(
        "http://localhost/lab", on_event=on_event, should_stop=lambda: flag["stop"],
    )
    phases = [e["phase"] for e in events if e["type"] == "phase"]
    assert "VERIFY" not in phases
    assert "REPORT" not in phases
    assert events[-1]["type"] == "scan_complete"
    assert events[-1]["status"] == "cancelled"
    assert not any(e["type"] == "agent" for e in events)


def test_blocking_scan_and_stream_share_allowlist(monkeypatch):
    def explode(*_a, **_k):
        raise AssertionError("run_scan must not run off the allowlist")

    monkeypatch.setattr(orchestrator, "run_scan", explode)
    client = TestClient(main.app)
    token = _login(client)
    for path in ("/scan", "/scan/stream"):
        res = client.post(path, json={"url": "http://example.com/admin"}, headers=_auth(token))
        assert res.status_code == 403
        assert "allowlist" in res.json()["detail"]

    denied = client.post(
        "/scan/stream",
        json={"url": "http://localhost/"},
        headers={"Authorization": "Bearer nope"},
    )
    assert denied.status_code == 401


def test_blocking_scan_response_shape(monkeypatch):
    monkeypatch.setattr(main, "_rev_dns", lambda _host: "")

    def fake(url, on_event=None, should_stop=None, run_id=None):
        assert on_event is None
        assert callable(should_stop)
        assert run_id
        return {
            "run_id": "run_block",
            "auth": {"authenticated": False, "scheme": "none"},
            "fingerprint": {"stack": "unknown", "lang": "unknown"},
            "surface": {"pages": 1, "forms": 0, "params": 0},
            "units": 0,
            "specialists_run": [],
            "recon": {"status": 200, "server": "nginx", "scanned_internal": False},
            "model": "test-model",
            "ai_available": False,
            "findings": [],
            "summary": {"total": 0, "confirmed": 0, "unverified": 0, "rejected": 0},
        }

    monkeypatch.setattr(orchestrator, "run_scan", fake)
    client = TestClient(main.app)
    token = _login(client)
    res = client.post(
        "/scan",
        json={"url": "http://127.0.0.1/"},
        headers=_auth(token),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "complete"
    assert data["requested_by"] == "erwin@local"
    assert data["run_id"] == "run_block"
    assert data["target"] == "http://127.0.0.1/"
    assert data["machines"]["target"]["url_host"] == "127.0.0.1"
    assert data["machines"]["target"]["server_banner"] == "nginx"
    assert data["model"] == "test-model"
    assert data["summary"]["total"] == 0


def test_phase_start_arrives_while_that_phase_is_still_running(monkeypatch):
    """A phase start must hit the client before the phase's own work finishes."""
    monkeypatch.setattr(main, "_rev_dns", lambda _host: "")

    def slow(url, on_event=None, should_stop=None, run_id=None):
        on_event({"type": "phase", "phase": "MAP", "status": "started"})
        time.sleep(0.45)
        on_event({"type": "phase", "phase": "MAP", "status": "finished", "detail": {"pages": 1}})
        on_event({
            "type": "scan_complete",
            "status": "complete",
            "run_id": "run_flush",
            "target": url,
            "recon": {"server": ""},
            "summary": {"total": 0, "confirmed": 0, "unverified": 0, "rejected": 0},
            "findings": [],
        })
        return {"run_id": "run_flush"}

    monkeypatch.setattr(orchestrator, "run_scan", slow)
    client = TestClient(main.app)
    token = _login(client)
    start = time.perf_counter()
    started_at = finished_at = None
    buf = ""
    with client.stream(
        "POST", "/scan/stream",
        json={"url": "http://localhost/lab"},
        headers=_auth(token),
    ) as res:
        assert res.status_code == 200
        for chunk in res.iter_text():
            buf += chunk
            while "\n\n" in buf:
                raw, buf = buf.split("\n\n", 1)
                data = [ln[5:].strip() for ln in raw.split("\n") if ln.startswith("data:")]
                if not data:
                    continue
                event = json.loads("\n".join(data))
                now = time.perf_counter() - start
                if event.get("type") == "phase" and event.get("phase") == "MAP":
                    if event.get("status") == "started":
                        started_at = now
                    elif event.get("status") == "finished":
                        finished_at = now
    assert started_at is not None and started_at < 0.25, started_at
    assert finished_at is not None and finished_at - started_at > 0.3, (started_at, finished_at)


def test_stream_flushes_scan_started_before_the_scan_finishes(monkeypatch):
    monkeypatch.setattr(main, "_rev_dns", lambda _host: "")

    def slow(url, on_event=None, should_stop=None, run_id=None):
        on_event({
            "type": "scan_started",
            "url": url,
            "run_id": "run_test",
            "agents": ["injection"],
        })
        time.sleep(0.6)
        if should_stop and should_stop():
            on_event({
                "type": "scan_complete",
                "status": "cancelled",
                "run_id": "run_test",
                "target": url,
                "recon": {"server": ""},
                "summary": {"total": 0, "confirmed": 0, "unverified": 0, "rejected": 0},
                "findings": [],
            })
            return {"run_id": "run_test", "status": "cancelled"}
        on_event({
            "type": "finding",
            "stream_id": 1,
            "unit_id": "u000",
            "severity": "high",
            "title": "Reflected XSS",
            "agent": "injection",
            "layer": "injection",
            "evidence": "line\nbreak",
            "fix": "encode",
            "source": "deterministic",
            "section": "q",
        })
        on_event({
            "type": "phase", "phase": "REPORT", "status": "finished",
            "detail": {"total": 1, "confirmed": 1, "unverified": 0, "rejected": 0},
        })
        on_event({
            "type": "scan_complete",
            "status": "complete",
            "run_id": "run_test",
            "target": url,
            "summary": {"total": 1, "confirmed": 1, "unverified": 0, "rejected": 0},
            "findings": [{
                "id": "F-001", "severity": "high", "title": "Reflected XSS",
                "verdict": "confirmed", "layer": "injection", "evidence": "line\nbreak",
                "fix": "encode", "source": "deterministic", "agent": "injection",
            }],
            "recon": {"status": 200, "server": "test", "scanned_internal": False},
            "surface": {"pages": 1, "forms": 0, "params": 1},
            "units": 1,
            "auth": {"authenticated": False},
            "fingerprint": {"stack": "unknown", "lang": "unknown"},
            "model": "test",
            "ai_available": False,
            "specialists_run": ["injection"],
        })
        return {"run_id": "run_test"}

    monkeypatch.setattr(orchestrator, "run_scan", slow)
    client = TestClient(main.app)
    token = _login(client)
    start = time.perf_counter()
    first = None
    body = ""
    with client.stream(
        "POST",
        "/scan/stream",
        json={"url": "http://localhost/lab"},
        headers=_auth(token),
    ) as res:
        assert res.status_code == 200
        assert "text/event-stream" in res.headers["content-type"]
        assert res.headers["cache-control"] == "no-cache, no-transform"
        assert res.headers["x-accel-buffering"] == "no"
        for chunk in res.iter_text():
            body += chunk
            if "scan_started" in body:
                first = time.perf_counter() - start
                break
    assert first is not None and first < 0.45, first


def test_stream_events_carry_provenance_and_severity(monkeypatch):
    monkeypatch.setattr(main, "_rev_dns", lambda _host: "")
    seen = {}

    def scripted(url, on_event=None, should_stop=None, run_id=None):
        seen["should_stop"] = should_stop
        on_event({"type": "scan_started", "url": url, "run_id": "run_script", "agents": ["injection"]})
        on_event({
            "type": "agent", "agent": "injection", "status": "started",
            "unit_id": "u000", "label": "q", "section": {"kind": "query_param", "param": "q"},
        })
        on_event({
            "type": "finding", "stream_id": 1, "unit_id": "u000", "severity": "medium",
            "title": "Cookie missing HttpOnly", "agent": "config_headers", "layer": "cookie",
            "evidence": "Set-Cookie: sid=1", "fix": "Add HttpOnly.", "source": "deterministic",
            "section": "site",
        })
        on_event({
            "type": "agent", "agent": "injection", "status": "finished",
            "unit_id": "u000", "label": "q", "findings": 1,
            "section": {"kind": "query_param", "param": "q"},
        })
        on_event({
            "type": "scan_complete", "status": "complete", "run_id": "run_script", "target": url,
            "summary": {"total": 1, "confirmed": 0, "unverified": 1, "rejected": 0},
            "findings": [],
            "recon": {"status": 200, "server": "lab", "scanned_internal": False},
        })
        return {"run_id": "run_script"}

    monkeypatch.setattr(orchestrator, "run_scan", scripted)
    client = TestClient(main.app)
    token = _login(client)
    with client.stream(
        "POST", "/scan/stream",
        json={"url": "http://localhost/lab"},
        headers=_auth(token),
    ) as res:
        raw = "".join(res.iter_text())
    frames = []
    for block in raw.split("\n\n"):
        data = [ln[5:].strip() for ln in block.split("\n") if ln.startswith("data:")]
        if data:
            frames.append(json.loads("\n".join(data)))
    kinds = [f["type"] for f in frames]
    assert kinds == ["scan_started", "agent", "finding", "agent", "scan_complete"]
    assert frames[0]["requested_by"] == "erwin@local"
    assert frames[2]["severity"] == "medium"
    done = frames[-1]
    assert done["status"] == "complete"
    assert done["requested_by"] == "erwin@local"
    assert done["machines"]["target"]["url_host"] == "localhost"
    assert done["machines"]["target"]["server_banner"] == "lab"
    assert done["machines"]["requested_from"]["name"] == "unknown"
    assert callable(seen["should_stop"])
