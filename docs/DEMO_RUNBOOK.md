# Swarmageddon — live demo runbook (Hack Fair)

Consent-first: we only scan the two intentionally vulnerable labs **we host** on the tower.
The backend refuses every host that is not on its allowlist, and the swarm **detects, never exploits**.

| Thing | Address |
|---|---|
| Dashboard (open this on the projector laptop) | `http://10.0.0.32:8090` |
| Backend (the dashboard fills this in for you) | `http://10.0.0.32:8000` |
| **DVWA** target — type exactly | `http://10.0.0.32:8081` |
| **OWASP Juice Shop** target — type exactly | `http://10.0.0.32:3001` |
| Sign in | `erwin@local` / `demo` (or `andrew@local` / `demo`) |
| Projector mode | press **P** (Esc or P to exit) |
| Stage pace | `VULNSWARM_REQUEST_INTERVAL_MS=200` |

Use the target root, not `/login.php`. Both targets are also the two cards on the dashboard: clicking **Scan** on a card is the same as typing the URL.

## 1. Tower start-up (once, ~T-60 min)

```bash
cd AITX-ANTLER-Hackathon
git pull
test -f backend/.env || cp backend/.env.example backend/.env   # compose needs this file; the API key is optional
grep -q '^VULNSWARM_REQUEST_INTERVAL_MS=' backend/.env || echo 'VULNSWARM_REQUEST_INTERVAL_MS=200' >> backend/.env
docker compose up -d --build                                   # --build picks up backend changes
docker compose ps                                              # backend, dashboard, juice, dvwa, dvwa-db all "Up"
curl -s http://10.0.0.32:8000/health                           # {"ok":true}
```

Changed `backend/.env` later? Run `docker compose up -d backend`. A plain `restart` does not re-read the file.

**DVWA database: required, one click.** Open `http://10.0.0.32:8081/setup.php` and press **Create / Reset Database**. Then sign in at `http://10.0.0.32:8081` as `admin` / `password` to confirm it works.
Without this, the swarm can't log in. The scan maps 1 page, finds no HIGH and ends in ~3 s.
The database has no volume, so redo this after any `docker compose down` or after `dvwa-db` is recreated. Plain container restarts keep it.

**Juice Shop warm-up:** open `http://10.0.0.32:3001` once. The first start takes about a minute.

## 2. Projector laptop (~T-15 min)

1. Same Wi-Fi as the tower. Open **Chrome** at `http://10.0.0.32:8090`.
2. The **Backend** field in the header should already read `http://10.0.0.32:8000`. If it doesn't, type that address in.
3. Sign in (`erwin@local` / `demo`). The two lab cards appear, and the Activity panel shows **STREAMING**.
4. Click anywhere on the page (so the cursor isn't in a text box), then press **P** for projector mode. `Ctrl+0` resets the browser zoom.
5. Dry run: one DVWA scan to the end, then start one more and press **STOP**.

## 3. What to expect (measured on a mirror of the tower stack)

| | DVWA `http://10.0.0.32:8081` | Juice Shop `http://10.0.0.32:3001` |
|---|---|---|
| AUTH | logged into DVWA (admin, security low) | anonymous (no known login) |
| MAP | 15 pages · 11 forms | 1 page (single-page app; the crawler doesn't run JavaScript) |
| Findings | **15**: 6 HIGH · 1 MED · 6 LOW · 2 INFO, all confirmed | **6**: 1 MED (`/ftp` listing) · 4 LOW · 1 INFO |
| HIGH examples | SQL injection (`id`, `username`), command injection (`ip`), local file inclusion (`page`), reflected XSS (`name`), exposed `config.inc.php.bak` | none |
| Time at 200 ms | ~20 s | ~4 s |

`VULNSWARM_REQUEST_INTERVAL_MS` versus DVWA scan length: 50 ms (default) ≈ 5 s · 150 ≈ 16 s · **200 ≈ 20 s** · 250 ≈ 25 s · 350 ≈ 35 s.

**Lead with DVWA.** It shows the full beat: drones, red HIGH beams and the HIGH callout. Juice Shop is a quick second: modern app, clean result, honest about the crawl limit.

## 4. Suggested 3-minute demo

1. *"Everything you'll see runs against two vulnerable labs we host. Off-list hosts are refused before a single request."* Type `http://example.com` and press **SCAN**: it shows **BLOCKED** (403).
2. Click **Scan** on **DVWA**, then press **P**. Narrate AUTH → MAP → PLAN → SWARM → VERIFY → REPORT while the HIGH findings land.
3. Start DVWA again. During SWARM, hit the big red **STOP**: the stage freezes, shows **HALTED**, and the audit log shows `stop_requested` → `cancelled`.
4. Optional: Juice Shop (~4 s).

## 5. If it breaks on stage — 60-second recovery

| You see | Do this |
|---|---|
| **"Cannot reach backend"** at sign-in | Check the Backend field reads `http://10.0.0.32:8000`. On the tower: `curl -s http://10.0.0.32:8000/health`. If health is OK, the tower is running an old compose file: `git pull && docker compose up -d backend`. |
| DVWA ends in ~3 s, AUTH says **"login attempt did not confirm"**, no HIGH | DVWA database is missing: `http://10.0.0.32:8081/setup.php` → **Create / Reset Database** → scan again. |
| **BUSY** (429) | A scan still holds a slot: press **STOP ALL**, wait 2 s, scan again. |
| Stage still says **HALTED** | That's the last scan. Click a target card to start a new one. |
| **"Stream ended early"**, **"Backend unreachable"** or nothing moves | Press **STOP ALL**. On the tower: `docker compose up -d backend` (and `docker compose logs --tail 50 backend` if it keeps failing). Sign in again if asked. |
| Error mentions **"target unreachable"** | Target container is down: `docker compose up -d dvwa dvwa-db juice`. If `dvwa-db` was recreated (not just restarted), redo the DVWA database step. |
| Layout looks off | `Ctrl+0` (zoom reset), then press **P** twice. |
| Laptop can't reach the tower at all (Wi-Fi) | Run the demo on the tower's own screen: open `http://localhost:8090` there. The Backend field fills in `http://localhost:8000` automatically. |

Last resort: on the projector laptop, open `dashboard/index.html` straight from a local copy of the repo and set Backend to `http://10.0.0.32:8000`.
