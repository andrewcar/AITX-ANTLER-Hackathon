# Contributing / laptop setup

For team contributors. The repo is **public** at
[andrewcar/AITX-ANTLER-Hackathon](https://github.com/andrewcar/AITX-ANTLER-Hackathon),
so cloning needs no login.

## First-time install (one copy/paste block)

```bash
git clone https://github.com/andrewcar/AITX-ANTLER-Hackathon.git
cd AITX-ANTLER-Hackathon
./setup.sh http://10.0.0.32:8000
```

`setup.sh` pings the backend, opens your browser's extensions page, and prints the
exact folder to load. Then the two manual clicks browsers require:

1. **Developer mode** ON (top-right of `brave://extensions`)
2. **Load unpacked** → select the printed `extension/` folder

Pin the icon, open it on `http://10.0.0.32:3001`, sign in (`erwin@local` / `demo`),
**Scan this tab**. The popup scans it as `http://localhost:3001`: the backend's allowlist is
`localhost` / `127.0.0.1` only, and to the backend on the tower, the tower is `localhost`
(details in [SETUP.md](SETUP.md)).

## Getting updates

```bash
./update.sh    # git pull + reminder to reload the extension
```

Then click the **↻ refresh arrow** on the VulnSwarm card at `brave://extensions`.

## Why the extension doesn't truly auto-update

The extension *is* the `extension/` folder on disk. `git pull` changes those files,
but **browsers forbid any script from installing or reloading an unpacked extension**
(it's a classic malware vector). So the reload is always a manual click. The only ways
around that are the Chrome Web Store (auto-updates, but needs publishing + review) or
enterprise force-install policy (heavy, IT-admin territory) — neither worth it pre-demo.

### Dev hot-reload (optional, for whoever is actively editing)
If you want the extension to reload itself on every save while developing, we can add
a dev-only websocket reloader (a tiny local watcher + a background listener in the
extension that calls `chrome.runtime.reload()` on change). Ask before enabling — it's
dev-only and must never ship in a shared/published build. Not set up yet.

## Who runs what

- **Tower (10.0.0.32)** runs the backend + target lab via `docker compose up -d`.
  DVWA's database is kept in the `dvwa-db` volume (one-time setup click; see
  [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md)).
- **Contributor laptops** run only the **extension** (or open the dashboard at
  `http://10.0.0.32:8090`), pointed at the tower's backend.
  You do *not* need Docker or the backend locally unless you're developing the backend.

## Making changes

- Branch from `main` and open a pull request against `andrewcar/AITX-ANTLER-Hackathon`.
  Andrew reviews and merges.
- Keep it consent-first and non-destructive: scan only allowlisted hosts you own; the
  tool detects, it never exploits. Call out any change to backend safety logic
  (allowlist, STOP, rate limiting, audit log, planner guardrails) in the PR.
- Run the tests before you push: `cd backend && python -m pytest tests/ -q`.
- Never commit secrets. `backend/.env` is git-ignored; copy `backend/.env.example`.
```
