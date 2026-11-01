from types import SimpleNamespace

import planner


def _injected(forms):
    ctx = SimpleNamespace(url="http://t", surface={"forms": forms, "params": []})
    return [u["section"]["param"] for u in planner.plan(ctx) if u["specialist"] == "injection"]


def test_dvwa_reset_database_form_is_never_probed():
    # DVWA's setup.php: probing any field would also submit "Create / Reset Database".
    setup = {"action": "http://t/setup.php", "method": "post", "inputs": ["create_db", "user_token"]}
    assert _injected([setup]) == []


def test_dvwa_guestbook_with_clear_button_is_never_probed():
    # DVWA's stored-XSS guestbook: every probe also posts btnClear, which runs TRUNCATE guestbook.
    guestbook = {"action": "http://t/vulnerabilities/xss_s/", "method": "post",
                 "inputs": ["txtName", "mtxMessage", "btnSign", "btnClear"]}
    assert _injected([guestbook]) == []


def test_form_with_a_destructive_control_is_skipped_whole():
    form = {"action": "http://t/admin/", "method": "post", "inputs": ["name", "drop_table"]}
    assert _injected([form]) == []


def test_ordinary_forms_are_still_probed():
    sqli = {"action": "http://t/vulnerabilities/sqli/", "method": "get", "inputs": ["id", "Submit"]}
    xss = {"action": "http://t/vulnerabilities/xss_r/", "method": "get", "inputs": ["name"]}
    assert _injected([sqli, xss]) == ["id", "name"]


def _units(forms):
    ctx = SimpleNamespace(url="http://t", surface={"forms": forms, "params": []})
    return [u["section"] for u in planner.plan(ctx) if u["specialist"] == "injection"]


def test_probe_sends_only_its_field_and_one_benign_submit():
    from agents import injection
    form = {"action": "http://t/vulnerabilities/sqli/", "method": "get",
            "inputs": ["id", "note", "Submit"], "submits": [{"name": "Submit", "value": "Submit"}]}
    by_param = {s["param"]: s for s in _units([form])}
    assert by_param["id"]["submit"] == {"name": "Submit", "value": "Submit"}
    # siblings ('note') are never sent; only the payload field and the one submit control
    assert injection._data(by_param["id"], "id", "'") == {"id": "'", "Submit": "Submit"}


def test_benign_submit_skips_destructive_controls():
    # First layer: even if a destructive button got past the deny-list, it is never chosen.
    form = {"inputs": ["txt"], "submits": [{"name": "btnClear", "value": "Clear"},
                                           {"name": "btnSign", "value": "Sign"}]}
    assert planner._benign_submit(form, "txt") == {"name": "btnSign", "value": "Sign"}
    assert planner._benign_submit({"submits": [{"name": "drop_all", "value": ""}]}, "x") is None


def test_destructive_button_elements_also_trip_the_deny_list():
    # Second layer sees <button name=...> controls too, not only <input> fields.
    form = {"action": "http://t/admin/", "method": "post", "inputs": ["comment"],
            "submits": [{"name": "delete_all", "value": ""}]}
    assert _units([form]) == []


def test_crawler_records_submit_controls_and_buttons():
    import crawler
    p = crawler._HTMLScan()
    p.feed("""<form action=/s method=post><input name=q><input type=hidden name=MAX_FILE_SIZE value=1>
              <input type=submit name=Submit value=Go><button name=btnClear>Clear</button>
              <button type=button name=noop>x</button></form>""")
    f = p.forms[0]
    assert f["inputs"] == ["q", "MAX_FILE_SIZE", "Submit"]
    assert f["submits"] == [{"name": "Submit", "value": "Go"}, {"name": "btnClear", "value": ""}]


def test_verifier_replays_the_same_minimal_submission(monkeypatch):
    import recon
    import verifier
    sent = []
    monkeypatch.setattr(recon, "send", lambda url, method, data, session=None: sent.append(data)
                        or {"status": 200, "body": "You have an error in your SQL syntax"})
    chk = {"type": "sqli_error", "url": "http://t/x", "param": "id", "method": "get",
           "inputs": ["id", "note", "Submit"], "submit": {"name": "Submit", "value": "Submit"}}
    ok, verdict, _ = verifier._verify_deterministic({"check": chk}, None, {}, [], "http://t")
    assert verdict == "confirmed"
    assert sent and all(set(d) == {"id", "Submit"} for d in sent), sent
