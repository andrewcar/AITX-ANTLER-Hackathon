from types import SimpleNamespace

import planner


def _injected(forms):
    ctx = SimpleNamespace(url="http://t", surface={"forms": forms, "params": []})
    return [u["section"]["param"] for u in planner.plan(ctx) if u["specialist"] == "injection"]


def test_dvwa_reset_database_form_is_never_probed():
    # DVWA's setup.php: probing any field would also submit "Create / Reset Database".
    setup = {"action": "http://t/setup.php", "method": "post", "inputs": ["create_db", "user_token"]}
    assert _injected([setup]) == []


def test_form_with_a_destructive_control_is_skipped_whole():
    form = {"action": "http://t/admin/", "method": "post", "inputs": ["name", "drop_table"]}
    assert _injected([form]) == []


def test_ordinary_forms_are_still_probed():
    sqli = {"action": "http://t/vulnerabilities/sqli/", "method": "get", "inputs": ["id", "Submit"]}
    xss = {"action": "http://t/vulnerabilities/xss_r/", "method": "get", "inputs": ["name"]}
    assert _injected([sqli, xss]) == ["id", "name"]
