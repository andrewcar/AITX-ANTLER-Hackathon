# VulnSwarm — teammate setup (5 min)

You need: a laptop on the **same WiFi as the tower** (`10.0.0.32`), and `gh` (GitHub CLI).
No Docker needed — the backend + targets run on the tower.

## Install

```bash
gh auth login                                        # once; pick GitHub.com + browser login
gh repo clone ErwinPawliczek/AITX-ANTLER-Hackathon
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
4. **Scan this tab** → a finding comes back

## Updating later

```bash
./update.sh      # git pull
```
Then click the **↻ refresh arrow** on the VulnSwarm card at `brave://extensions`.
(The extension can't auto-reload — browsers block that — so it's one click.)

## If it doesn't work

- **Popup says "Cannot reach backend"** → you're not on the tower's WiFi, or the tower's
  lab is down. Test: `curl http://10.0.0.32:8000/health` should return `{"ok":true}`.
- **`gh: command not found`** → `sudo apt install gh` (Linux) / `brew install gh` (mac).
- **No browser opened** → open `brave://extensions` yourself; the folder path was printed.
