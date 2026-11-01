# VulnSwarm — teammate setup (5 min)

You need: a laptop on the **same WiFi as the tower** (`10.0.0.32`) and `git`.
No Docker needed — the backend + targets run on the tower.

## Install

```bash
git clone https://github.com/andrewcar/AITX-ANTLER-Hackathon.git
cd AITX-ANTLER-Hackathon
./setup.sh http://10.0.0.32:8000
```

The script checks the backend and opens your browser's extensions page.

## Load the extension (2 clicks the browser requires)

1. On `brave://extensions` (or `chrome://extensions`): turn **Developer mode** ON (top-right)
2. Click **Load unpacked** → select the `extension/` folder the script printed
3. Pin the VulnSwarm icon (puzzle-piece 🧩 → pin)

## Try it

1. Browse to a target: **http://10.0.0.32:3001** (Juice Shop) or **http://10.0.0.32:8081** (DVWA)
2. Click the VulnSwarm icon → Backend URL should say `http://10.0.0.32:8000`
3. Sign in — **`andrew@local` / `demo`** (or `erwin@local` / `demo`)
4. The popup shows the address it will scan: `http://localhost:3001` (or `:8081`). That's
   expected — see below.
5. **Scan this tab** → findings come back

**Why `localhost`?** The backend only scans `localhost` / `127.0.0.1`; a LAN address like
`10.0.0.32` is refused (403), because on shared WiFi it could be someone else's device.
The backend runs on the tower, so to the backend the tower *is* `localhost`. When your tab
is on the backend's own machine, the extension sends it as `localhost`. A tab on any
other host is sent unchanged and refused.

## Dashboard (no install — just a URL)

The team dashboard (target cards, live swarm, findings, audit log) is served by the
tower. Open it in any browser on the LAN:

    http://10.0.0.32:8090

Sign in (`erwin@local` / `demo`), then click **Scan** on a card. The cards scan
`http://localhost:8081` (DVWA) and `http://localhost:3001` (Juice Shop); type those if you
use the box. For the projector demo, follow [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md).

## Updating later

```bash
./update.sh      # git pull
```
Then click the **↻ refresh arrow** on the VulnSwarm card at `brave://extensions`.
(The extension can't auto-reload — browsers block that — so it's one click.)

## If it doesn't work

- **Popup says "Cannot reach backend"** → you're not on the tower's WiFi, or the tower's
  lab is down. Test: `curl http://10.0.0.32:8000/health` should return `{"ok":true}`.
- **"not on the allowlist" / BLOCKED** → you scanned `10.0.0.32` directly (dashboard box) or
  a tab that isn't on the tower. Use `http://localhost:8081` / `:3001`, the cards, or
  reload the extension after `./update.sh` so it has the localhost mapping.
- **DVWA scan finds almost nothing** → DVWA's database isn't set up yet: open
  `http://10.0.0.32:8081/setup.php` → **Create / Reset Database** (once; it's kept in a volume).
- **No browser opened** → open `brave://extensions` yourself; the folder path was printed.
