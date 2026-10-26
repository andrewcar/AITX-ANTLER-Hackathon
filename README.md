# VulnSwarm

A multi-agent ("swarm") web-vulnerability scanner for **authorized targets only** —
sites we host ourselves on the tower / lab. Each agent owns one layer (recon, config,
dependency/CVE, injection, auth); a verifier confirms findings; a reporter writes the fix.

> **Scope rule (non-negotiable):** the backend enforces an `ALLOWLIST`. Any target not
> on it is refused with HTTP 403. Only add hosts we own and are authorized to test.

## Current state: pipeline proof

This commit proves the pipeline end to end before we build the real swarm:

```
extension  --login-->  token  --POST /scan-->  backend  --finding-->  extension
```

`/scan` currently returns one **stub** finding. The orchestrator + real agents plug in
behind `/scan` next. Login is a simple signed-token scheme (demo users) — good enough to
prove auth transport; swap for a real user store (or Google OAuth) later.

## Who builds what

- **Erwin → `backend/`** — API, orchestrator, agents, tool-runners, allowlist, Wasm sandbox.
- **Andrew → `extension/` + `dashboard/`** — the "Scan this tab" extension and the
  multi-site dashboard (the main page listing hosted targets + live findings).
- **Shared contract** — the HTTP API in `backend/main.py` (`/auth/login`, `/me`,
  `/targets`, `/scan`). Keep this in sync; it's the seam between the two halves.

## Run the backend

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Demo users: `erwin@local` / `demo`, `andrew@local` / `demo`.

## Load the extension (Chrome)

1. Go to `chrome://extensions`
2. Turn on **Developer mode** (top-right)
3. **Load unpacked** → select the `extension/` folder
4. Pin it, open it on any `http://localhost` tab, sign in, hit **Scan this tab**

You should see the stub finding come back. That's the whole pipeline working.

## Next steps

1. Add the tower's hosted sites to `ALLOWLIST` in `backend/main.py`.
2. Stand up a vulnerable target in `targets/` (Docker: WordPress / DVWA) to scan for real.
3. Replace the `/scan` stub with the orchestrator → specialist agents → verifier → reporter.
4. Dashboard: list `/targets`, trigger scans, stream findings.
