#!/usr/bin/env bash
# Pull the latest code so the extension (and backend) match main.
#
# The extension IS this repo's extension/ folder. `git pull` updates those files,
# but Brave/Chrome won't pick them up until the extension is reloaded. Browsers do
# not allow a script to reload an unpacked extension, so that reload is one click:
#   brave://extensions  ->  the circular refresh arrow on the VulnSwarm card.
#
# (For true auto-reload while actively editing, see dev hot-reload in README.)

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "== updating VulnSwarm =="
git pull --ff-only origin main
echo
echo "[done] code updated."
echo "Extension: click the refresh arrow on the VulnSwarm card at brave://extensions"
echo "Backend (tower only): re-run 'docker compose up -d --build' if backend/ changed."
