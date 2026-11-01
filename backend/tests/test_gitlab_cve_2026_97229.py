"""GitLab CVE-2026-97229 confirmation check: anonymous GETs only, version-based, scope-locked."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import fingerprint
import main
import orchestrator
import planner
import recon
import verifier
from agents import gitlab_version

FIX = Path(__file__).parent / "fixtures" / "gitlab"
BASE = "http://127.0.0.1:8929"


def _fx(name: str) -> str:
    return (FIX / name).read_text()


def _ctx(url=BASE):
    return SimpleNamespace(url=url, session=None, recon_root={"url": url, "raw_headers": {}})


def _site(monkeypatch, pages: dict, calls: list | None = None):
    """Mock recon.get: path -> (status, body). Unlisted paths 404."""
    def fake_get(u, s=None, max_bytes=0):
        path = u[len(BASE):] if u.startswith(BASE) else u
        if calls is not None:
            calls.append(path)
        status, body = pages.get(path, (404, ""))
        return {"url": u, "status": status, "content_type": "text/html", "body": body}
    monkeypatch.setattr(recon, "get", fake_get)
    monkeypatch.setattr(recon, "send", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no send()")))


def test_classify_fixed_boundaries():
    c = gitlab_version.classify
    assert c((19, 2, 7))[0] == "affected" and c((19, 2, 8))[0] == "patched"
    assert c((19, 3, 4))[0] == "affected" and c((19, 3, 5))[0] == "patched"
    assert c((19, 4, 1))[0] == "affected" and c((19, 4, 2))[0] == "patched"
    assert c((19, 5, 0))[0] == "patched" and c((20, 0, 0))[0] == "patched"
    # advisory lists 19.2+ only: older lines are flagged as unsupported, not as the CVE
    assert c((19, 1, 9))[0] == "outdated" and c((17, 0, 0))[0] == "outdated"


def test_parse_version_sources():
    assert gitlab_version.parse_version(_fx("sign_in_19_4_1.html"), "sign_in") == (19, 4, 1)
    assert gitlab_version.parse_version(_fx("api_version_19_3_4.json"), "api") == (19, 3, 4)
    assert gitlab_version.parse_version(_fx("help_18_11_3.html"), "help") == (18, 11, 3)
    assert gitlab_version.parse_version(_fx("api_401.json"), "api") is None
    assert gitlab_version.parse_version("not json", "api") is None
    assert gitlab_version.parse_version(_fx("sign_in_no_version.html"), "sign_in") is None


def test_vulnerable_from_sign_in_gon(monkeypatch):
    _site(monkeypatch, {"/users/sign_in": (200, _fx("sign_in_19_4_1.html")),
                        "/-/manifest.json": (200, _fx("manifest.json")),
                        "/api/v4/version": (401, _fx("api_401.json"))})
    f = gitlab_version.run({}, _ctx())
    assert len(f) == 1
    assert f[0]["severity"] == "high" and f[0]["confidence"] == "medium"
    assert "CVE-2026-97229" in f[0]["title"] and "19.4.1" in f[0]["title"]
    assert "19.4.2" in f[0]["fix"] and "KEV" in f[0]["evidence"]
    assert "no regex, CI config or pipeline was sent" in f[0]["evidence"]
    assert f[0]["check"] == {"type": "gitlab_version", "where": "sign_in", "version": "19.4.1"}


def test_vulnerable_from_anonymous_api_is_critical_high_confidence(monkeypatch):
    _site(monkeypatch, {"/users/sign_in": (200, _fx("sign_in_no_version.html")),
                        "/-/manifest.json": (200, _fx("manifest.json")),
                        "/api/v4/version": (200, _fx("api_version_19_3_4.json"))})
    f = gitlab_version.run({}, _ctx())
    assert len(f) == 1 and f[0]["severity"] == "critical" and f[0]["confidence"] == "high"
    assert f[0]["check"]["where"] == "api" and "19.3.5" in f[0]["fix"]


def test_patched_gitlab_has_no_finding(monkeypatch):
    _site(monkeypatch, {"/users/sign_in": (200, _fx("sign_in_19_4_2.html")),
                        "/-/manifest.json": (200, _fx("manifest.json")),
                        "/api/v4/version": (401, _fx("api_401.json"))})
    assert gitlab_version.run({}, _ctx()) == []


def test_unknown_version_is_info_not_vulnerable(monkeypatch):
    _site(monkeypatch, {"/users/sign_in": (200, _fx("sign_in_no_version.html")),
                        "/-/manifest.json": (200, _fx("manifest.json")),
                        "/api/v4/version": (401, _fx("api_401.json")),
                        "/help": (302, "")})
    f = gitlab_version.run({}, _ctx())
    assert len(f) == 1 and f[0]["severity"] == "info"
    assert "UNKNOWN" in f[0]["evidence"] and f[0]["check"] == {"type": "gitlab_detected"}


def test_older_line_from_help_is_flagged_unsupported(monkeypatch):
    _site(monkeypatch, {"/users/sign_in": (200, _fx("sign_in_no_version.html")),
                        "/-/manifest.json": (200, _fx("manifest.json")),
                        "/api/v4/version": (401, _fx("api_401.json")),
                        "/help": (200, _fx("help_18_11_3.html"))})
    f = gitlab_version.run({}, _ctx())
    assert len(f) == 1 and f[0]["severity"] == "medium"
    assert "Unsupported GitLab 18.11.3" in f[0]["title"] and "CVE-2026-97229" not in f[0]["title"]


def test_not_gitlab_catch_all_spa_has_no_finding_and_stops_early(monkeypatch):
    calls = []
    spa = _fx("juice_shop_index.html")
    _site(monkeypatch, {"/users/sign_in": (200, spa), "/-/manifest.json": (200, spa)}, calls)
    assert gitlab_version.run({}, _ctx()) == []
    assert calls == ["/users/sign_in", "/-/manifest.json"]  # never reaches API or /help


def test_not_gitlab_404_site(monkeypatch):
    _site(monkeypatch, {})
    assert gitlab_version.run({}, _ctx()) == []


def test_wire_level_only_bounded_anonymous_gets(monkeypatch):
    """Through the real recon request layer: GET only, no body, no auth header, <= 4 paths."""
    seen = []

    class H:
        def __init__(self, d):
            self._d = d

        def get(self, k, default=None):
            return self._d.get(k, default)

        def get_all(self, k):
            return []

    bodies = {"/users/sign_in": _fx("sign_in_no_version.html"), "/-/manifest.json": _fx("manifest.json")}

    def fake_exchange(req, timeout, read):
        path = req.full_url.split("8929", 1)[1]
        seen.append((req.get_method(), path, req.data, req.get_header("Authorization"),
                     req.get_header("Private-token")))
        if path in bodies:
            return 200, H({"Content-Type": "text/html"}), bodies[path].encode()
        return 401, H({"Content-Type": "application/json"}), b'{"message":"401 Unauthorized"}'

    monkeypatch.setattr(recon, "_exchange", fake_exchange)
    gitlab_version.run({}, _ctx())
    assert [s[1] for s in seen] == ["/users/sign_in", "/-/manifest.json", "/api/v4/version", "/help"]
    assert all(m == "GET" and data is None and a is None and t is None for m, _, data, a, t in seen)


def test_off_allowlist_target_is_refused_without_a_request(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(recon, "_exchange", lambda req, t, r: calls.append(req.full_url))
    assert gitlab_version.run({}, _ctx("https://gitlab.example.com")) == []
    assert calls == []
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(r.get("action") == "SCOPE_REFUSED" and "gitlab.example.com" in r["url"] for r in rows)


def test_scan_endpoint_refuses_off_allowlist_gitlab(monkeypatch):
    monkeypatch.setattr(main, "_rev_dns", lambda _h: "")
    monkeypatch.setattr(orchestrator, "run_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not scan")))
    client = TestClient(main.app)
    tok = client.post("/auth/login", json={"email": "andrew@local", "password": "demo"}).json()["token"]
    r = client.post("/scan", json={"url": "https://gitlab.example.com/users/sign_in"},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403 and "allowlist" in r.json()["detail"]


def test_sso_redirect_off_allowlist_is_not_followed(monkeypatch):
    seen = []

    class H:
        def get(self, k, default=None):
            return "https://sso.example.com/login" if k == "Location" else default

        def get_all(self, k):
            return []

    def fake_exchange(req, timeout, read):
        seen.append(req.full_url)
        return 302, H(), b""

    monkeypatch.setattr(recon, "_exchange", fake_exchange)
    assert gitlab_version.run({}, _ctx()) == []
    assert all("example.com" not in u for u in seen)


def test_verifier_reconfirms_and_rejects(monkeypatch):
    f = {"source": "deterministic", "check": {"type": "gitlab_version", "where": "sign_in"}}
    pages = {"/-/manifest.json": (200, _fx("manifest.json")), "/api/v4/version": (401, "")}
    _site(monkeypatch, {**pages, "/users/sign_in": (200, _fx("sign_in_19_4_1.html"))})
    assert verifier._verify_deterministic(f, {}, {}, [], BASE)[1] == "confirmed"
    _site(monkeypatch, {**pages, "/users/sign_in": (200, _fx("sign_in_19_4_2.html"))})
    assert verifier._verify_deterministic(f, {}, {}, [], BASE)[1] == "rejected"
    d = {"source": "deterministic", "check": {"type": "gitlab_detected"}}
    _site(monkeypatch, {})
    assert verifier._verify_deterministic(d, {}, {}, [], BASE)[1] == "rejected"


def test_fingerprint_and_planner_gate():
    gl = fingerprint.detect({"raw_headers": {"x-gitlab-meta": "{}"}, "set_cookie": []}, {"pages": []})
    juice = fingerprint.detect({"raw_headers": {"x-powered-by": "Express"}, "set_cookie": []}, {"pages": []})
    assert gl["app"] == "gitlab" and juice["app"] == "unknown"
    base = dict(url=BASE, surface={"forms": [], "params": []})
    assert any(u["specialist"] == "gitlab_version" for u in planner.plan(SimpleNamespace(fingerprint=gl, **base)))
    assert not any(u["specialist"] == "gitlab_version"
                   for u in planner.plan(SimpleNamespace(fingerprint=juice, **base)))
