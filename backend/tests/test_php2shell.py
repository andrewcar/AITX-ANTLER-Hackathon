"""PHP2Shell confirmation check: version-based, GET-only, re-verifiable."""
from types import SimpleNamespace

import planner
import recon
import verifier
from agents import php_runtime

PHPINFO_OLD = ("<h1 class='p'>PHP Version 8.4.26</h1><table><tr><td class='e'>"
               "session.upload_progress.enabled</td><td class='v'>On</td></tr></table>")
PHPINFO_FIXED = "<h1 class='p'>PHP Version 8.4.27</h1><td>session.upload_progress.enabled</td><td>Off</td>"


def _ctx(powered="", url="http://127.0.0.1:8081"):
    return SimpleNamespace(url=url, session=None,
                           recon_root={"url": url, "raw_headers": {"x-powered-by": powered}})


def _no_phpinfo(monkeypatch, calls=None):
    def fake_get(u, s=None, max_bytes=0):
        if calls is not None:
            calls.append(u)
        return {"url": u, "status": 404, "content_type": "", "body": ""}
    monkeypatch.setattr(recon, "get", fake_get)


def test_classify_fixed_boundaries():
    assert php_runtime.classify((8, 4, 26))[0] is True
    assert php_runtime.classify((8, 4, 27))[0] is False
    assert php_runtime.classify((8, 5, 11))[0] is True
    assert php_runtime.classify((8, 2, 35))[0] is False
    assert php_runtime.classify((7, 0, 30))[0] is True   # EOL (DVWA image)
    assert php_runtime.classify((8, 6, 0))[0] is False


def test_header_version_flags_affected_runtime(monkeypatch):
    _no_phpinfo(monkeypatch)
    f = php_runtime.run({}, _ctx("PHP/7.0.30"))
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert "CVE-2026-109618" in f[0]["evidence"] and "no exploit traffic" in f[0]["evidence"]
    assert f[0]["check"] == {"type": "php2shell_version", "where": "header", "version": "7.0.30"}


def test_patched_or_silent_target_has_no_finding(monkeypatch):
    _no_phpinfo(monkeypatch)
    assert php_runtime.run({}, _ctx("PHP/8.3.36")) == []
    assert php_runtime.run({}, _ctx("")) == []


def test_only_one_get_and_never_a_post(monkeypatch):
    calls = []
    _no_phpinfo(monkeypatch, calls)
    monkeypatch.setattr(recon, "send", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no POST")))
    php_runtime.run({}, _ctx("PHP/8.4.1"))
    assert calls == ["http://127.0.0.1:8081/phpinfo.php"]


def test_phpinfo_gives_version_and_upload_progress(monkeypatch):
    monkeypatch.setattr(recon, "get", lambda u, s=None, max_bytes=0:
                        {"url": u, "status": 200, "content_type": "text/html", "body": PHPINFO_OLD})
    f = php_runtime.run({}, _ctx(""))
    kinds = sorted(x["check"]["type"] for x in f)
    assert kinds == ["php2shell_version", "php_upload_progress"]


def test_catch_all_200_is_not_phpinfo(monkeypatch):
    monkeypatch.setattr(recon, "get", lambda u, s=None, max_bytes=0:
                        {"url": u, "status": 200, "content_type": "text/html", "body": "<html>app</html>"})
    assert php_runtime.run({}, _ctx("")) == []


def test_verifier_reconfirms_and_rejects(monkeypatch):
    fresh_old = {"raw_headers": {"x-powered-by": "PHP/8.4.26"}, "set_cookie": []}
    fresh_new = {"raw_headers": {"x-powered-by": "PHP/8.4.27"}, "set_cookie": []}
    f = {"source": "deterministic", "check": {"type": "php2shell_version", "where": "header"}}
    ok = verifier._verify_deterministic(f, fresh_old, fresh_old["raw_headers"], [], "http://127.0.0.1:8081")
    assert ok[1] == "confirmed"
    no = verifier._verify_deterministic(f, fresh_new, fresh_new["raw_headers"], [], "http://127.0.0.1:8081")
    assert no[1] == "rejected"
    monkeypatch.setattr(recon, "get", lambda u, s=None, max_bytes=0:
                        {"url": u, "status": 200, "content_type": "text/html", "body": PHPINFO_FIXED})
    up = {"source": "deterministic", "check": {"type": "php_upload_progress"}}
    assert verifier._verify_deterministic(up, {}, {}, [], "http://127.0.0.1:8081")[1] == "rejected"


def test_planner_adds_php_unit_only_for_php_targets():
    base = dict(url="http://127.0.0.1:8081", surface={"forms": [], "params": []})
    php = planner.plan(SimpleNamespace(fingerprint={"lang": "php"}, **base))
    node = planner.plan(SimpleNamespace(fingerprint={"lang": "node"}, **base))
    assert any(u["specialist"] == "php_runtime" for u in php)
    assert not any(u["specialist"] == "php_runtime" for u in node)
