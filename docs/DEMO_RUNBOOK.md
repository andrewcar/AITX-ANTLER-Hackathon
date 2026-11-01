# Swarmageddon — live demo runbook

Consent-first: we only scan the two intentionally vulnerable labs **we host** on the tower.
The backend refuses every host that is not on its allowlist, and the swarm **detects, never exploits**.

| Thing | Address |
|---|---|
| Dashboard (open this on the projector laptop) | `http://10.0.0.32:8090` |
| Backend (the dashboard fills this in for you) | `http://10.0.0.32:8000` |
| **DVWA** target — type exactly | `http://localhost:8081` |
| **OWASP Juice Shop** target — type exactly | `http://localhost:3001` |
| Sign in | `erwin@local` / `demo` (or `andrew@local` / `demo`) |
| Projector mode | press **P** (Esc or P to exit) |
| Stage pace | `VULNSWARM_REQUEST_INTERVAL_MS=200` |

Use the target root, not `/login.php`. Both targets are also the two cards on the dashboard: clicking **Scan** on a card is the same as typing the URL.

**Why `localhost`?** The backend's allowlist is `localhost` / `127.0.0.1` only. A LAN address like `10.0.0.32` is refused with 403, because on shared Wi-Fi it could belong to someone else's device. The backend runs on the tower, so `localhost` *is* the tower, and the backend routes `localhost:8081` / `:3001` to its own DVWA and Juice Shop containers. You still use `10.0.0.32` to **open** the dashboard and the labs in a browser; you just don't **scan** it.

## 1. Tower start-up (once, ~T-60 min)

```bash
cd AITX-ANTLER-Hackathon
git pull
test -f backend/.env || cp backend/.env.example backend/.env   # compose needs this file; the API key is optional
grep -q '^VULNSWARM_REQUEST_INTERVAL_MS=' backend/.env || echo 'VULNSWARM_REQUEST_INTERVAL_MS=200' >> backend/.env
docker compose up -d --build                                   # --build picks up backend changes (first build pulls the ~3.5 GB Playwright image)
docker compose ps                                              # backend, dashboard, juice, dvwa, dvwa-db all "Up"
curl -s http://10.0.0.32:8000/health                           # {"ok":true}
```

Changed `backend/.env` later? Run `docker compose up -d backend`. A plain `restart` does not re-read the file.

**DVWA database: one click, once.** Open `http://10.0.0.32:8081/setup.php` and press **Create / Reset Database**. Then sign in at `http://10.0.0.32:8081` as `admin` / `password` to confirm it works.
Without this, the swarm can't log in. The scan maps 1 page, finds no HIGH and ends in ~3 s.
The database lives in the `dvwa-db` volume, so it survives restarts and `docker compose down` / `up`. Only `docker compose down -v` (or deleting the volume) wipes it. The first `up` after this volume was added starts empty, so do the click once more then.

**Juice Shop warm-up:** open `http://10.0.0.32:3001` once. The first start takes about a minute.

## 2. Projector laptop (~T-15 min)

1. Same Wi-Fi as the tower. Open **Chrome** at `http://10.0.0.32:8090`.
2. The **Backend** field in the header should already read `http://10.0.0.32:8000`. If it doesn't, type that address in.
3. Sign in (`erwin@local` / `demo`). The two lab cards appear, and the Activity panel shows **STREAMING**.
4. Click anywhere on the page (so the cursor isn't in a text box), then press **P** for projector mode. `Ctrl+0` resets the browser zoom.
5. Dry run: one DVWA scan to the end, then start one more and press **STOP**.

## 3. What to expect (measured on a mirror of the tower stack)

| | DVWA `http://localhost:8081` | Juice Shop `http://localhost:3001` |
|---|---|---|
| AUTH | logged into DVWA (admin, security low) | anonymous (no known login) |
| MAP | 15 pages · 11 forms | ~9 routes via the headless crawl (it's a single-page app); 2 API inputs |
| Findings | **14–15**: 5–6 HIGH · 1 MED · 6 LOW · 2 INFO, all confirmed | **7**: 1 HIGH · 1 MED (`/ftp` listing) · 4 LOW · 1 INFO, all confirmed |
| HIGH examples | SQL injection (`id`, `username`), command injection (`ip`), local file inclusion (`page`), reflected XSS (`name`); plus exposed `config.inc.php.bak` (see below) | SQL injection (error-based) in the product search `q` |
| Time at 200 ms | ~20 s | ~18–20 s (about 12 s of it is the headless crawl in MAP) |

The 6th HIGH, exposed `/config/config.inc.php.bak`, is a file DVWA itself writes when you press **Create / Reset Database**. It lives in the `dvwa` container, not the database volume, so it disappears whenever that container is recreated (e.g. `down` / `up`). Want it back for the demo? Press **Create / Reset Database** again.

`VULNSWARM_REQUEST_INTERVAL_MS` versus DVWA scan length: 50 ms (default) ≈ 5 s · 150 ≈ 16 s · **200 ≈ 20 s** · 250 ≈ 25 s · 350 ≈ 35 s.

**Lead with DVWA.** It shows the full beat: drones, red HIGH beams and the HIGH callout. Juice Shop is a strong second: a modern JavaScript app where the headless crawl finds the search API and the swarm lands a HIGH SQL injection. During MAP, red `browser · BROWSER_REFUSED` rows (chip: **refused**) in the Activity panel show it refusing Juice Shop's third-party CDN scripts — the scope lock, live.

## 4. Suggested 3-minute demo

1. *"Everything you'll see runs against two vulnerable labs we host. Off-list hosts are refused before a single request."* Type `http://example.com` and press **SCAN**: it shows **BLOCKED** (403).
2. Click **Scan** on **DVWA**, then press **P**. Narrate AUTH → MAP → PLAN → SWARM → VERIFY → REPORT while the HIGH findings land.
3. Start DVWA again. During SWARM, hit the big red **STOP**: the stage freezes, shows **HALTED**, and the audit log shows `stop_requested` → `cancelled`.
4. Optional: Juice Shop (~20 s): point out the headless crawl in MAP and the refused CDN requests in the audit log.

## 5. If it breaks on stage — 60-second recovery

| You see | Do this |
|---|---|
| A lab target shows **BLOCKED** (403) | You typed `http://10.0.0.32:…`. Scan `http://localhost:8081` / `http://localhost:3001` instead, or click the card. |
| **"Cannot reach backend"** at sign-in | Check the Backend field reads `http://10.0.0.32:8000`. On the tower: `curl -s http://10.0.0.32:8000/health`. If health is OK, the tower is running an old compose file: `git pull && docker compose up -d backend`. |
| DVWA ends in ~3 s, AUTH says **"login attempt did not confirm"**, no HIGH | DVWA database is missing: `http://10.0.0.32:8081/setup.php` → **Create / Reset Database** → scan again. |
| **BUSY** (429) | A scan still holds a slot: press **STOP ALL**, wait 2 s, scan again. |
| Stage still says **HALTED** | That's the last scan. Click a target card to start a new one. |
| **"Stream ended early"**, **"Backend unreachable"** or nothing moves | Press **STOP ALL**. On the tower: `docker compose up -d backend` (and `docker compose logs --tail 50 backend` if it keeps failing). Sign in again if asked. |
| Juice Shop MAP shows **"headless crawl unavailable"** or **"failed"**, 1 page, no HIGH | The backend image predates the headless crawl: on the tower, `git pull && docker compose up -d --build backend`. The rest of the demo works without it. |
| Error mentions **"target unreachable"** | Target container is down: `docker compose up -d dvwa dvwa-db juice`. The DVWA database is kept in its volume. |
| Layout looks off | `Ctrl+0` (zoom reset), then press **P** twice. |
| Laptop can't reach the tower at all (Wi-Fi) | Run the demo on the tower's own screen: open `http://localhost:8090` there. The Backend field fills in `http://localhost:8000` automatically. |

Last resort: on the projector laptop, open `dashboard/index.html` straight from a local copy of the repo and set Backend to `http://10.0.0.32:8000`. Targets are still `http://localhost:8081` / `:3001`.

## 6. Browser extension (optional)

The **VulnSwarm** extension scans the tab you're on. Open a lab in the browser at its tower address (`http://10.0.0.32:8081` or `http://10.0.0.32:3001`), click the extension, then **Scan this tab**. When the tab is on the backend's own machine, the extension sends it as `localhost` (the popup shows the address it will scan). Tabs on any other host are sent unchanged, and the backend refuses them. Setup: [SETUP.md](../SETUP.md).
