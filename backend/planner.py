"""
PLAN phase — pair sections with the specialists relevant to them.

A work unit = {"specialist": name, "section": {...}}. The orchestrator runs these in
parallel. This is where "agents focused on specific sections" becomes concrete, and
where stack-awareness lives (e.g. PHP targets get the php-flavored injection checks).
"""
MAX_INJECTION_UNITS = 20

# Guardrails: active injection submits forms, which can have DESTRUCTIVE side effects
# (e.g. a change-password or delete form). We refuse to inject these.
# params we never inject (sensitive values or submit/control fields)
SKIP_PARAMS = {"user_token", "login", "submit", "change", "delete", "update",
               "create", "logout", "seclev_submit", "csrf"}
SKIP_PARAM_SUBSTR = ("password", "passwd", "pwd", "token", "csrf")
# a form is state-changing/destructive if it smells like one of these
DESTRUCTIVE_FORM = ("logout", "delete", "csrf")


def _safe_param(name: str) -> bool:
    low = name.lower()
    if low in SKIP_PARAMS:
        return False
    return not any(s in low for s in SKIP_PARAM_SUBSTR)


def _safe_form(form: dict) -> bool:
    inputs_low = " ".join(form.get("inputs", [])).lower()
    action_low = (form.get("action") or "").lower()
    # a password-change form has new+confirm fields — never submit it
    if "password" in inputs_low and ("conf" in inputs_low or "new" in inputs_low):
        return False
    if any(s in action_low for s in DESTRUCTIVE_FORM):
        return False
    return True


def plan(ctx) -> list[dict]:
    units: list[dict] = []
    surface = ctx.surface

    # site-wide specialists: one unit each, pointed at the root
    units.append({"specialist": "config_headers", "section": {"kind": "site", "url": ctx.url}})
    units.append({"specialist": "exposed_paths", "section": {"kind": "site", "url": ctx.url}})

    # injection specialist: one unit per SAFE discovered input/param (bounded).
    # destructive forms and sensitive/control params are skipped entirely.
    inj = 0
    for f in surface.get("forms", []):
        if not _safe_form(f):
            continue
        for name in f.get("inputs", []):
            if inj >= MAX_INJECTION_UNITS:
                break
            if not _safe_param(name):
                continue
            units.append({"specialist": "injection", "section": {
                "kind": "form_param", "url": f["action"], "method": f["method"],
                "param": name, "inputs": f["inputs"],
            }})
            inj += 1
    for p in surface.get("params", []):
        if inj >= MAX_INJECTION_UNITS:
            break
        if not _safe_param(p["param"]):
            continue
        units.append({"specialist": "injection", "section": {
            "kind": "query_param", "url": p["page"], "method": "get", "param": p["param"],
        }})
        inj += 1

    return units
