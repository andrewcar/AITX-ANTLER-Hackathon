# Contributing / laptop setup

For team contributors. The repo is **private**, so each laptop authenticates to
GitHub once, then clone + run the setup helper.

## First-time install (one copy/paste block)

```bash
# 1. log in to GitHub once (opens a browser / device code)
gh auth login

# 2. clone and set up
gh repo clone ErwinPawliczek/AITX-ANTLER-Hackathon
cd AITX-ANTLER-Hackathon
./setup.sh http://10.0.0.32:8000
```

`setup.sh` pings the backend, opens your browser's extensions page, and prints the
exact folder to load. Then the two manual clicks browsers require:

1. **Developer mode** ON (top-right of `brave://extensions`)
2. **Load unpacked** → select the printed `extension/` folder

Pin the icon, open it on `http://10.0.0.32:3001`, sign in (`erwin@local` / `demo`),
**Scan this tab**.

> No `gh`? Install it (`sudo apt install gh` / `brew install gh`), or clone over HTTPS
> and paste a GitHub personal-access-token when prompted.

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
- **Contributor laptops** run only the **extension**, pointed at the tower's backend.
  You do *not* need Docker or the backend locally unless you're developing the backend.
```
