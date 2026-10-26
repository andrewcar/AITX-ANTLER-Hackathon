#!/usr/bin/env bash
# VulnSwarm laptop setup helper.
#
# It CANNOT auto-install the extension — browsers forbid that for security.
# What it does: get this laptop ready and take you to the one manual step
# (Developer mode -> Load unpacked), with the exact folder path to pick.
#
# Usage:  ./setup.sh [backend_url]
#   e.g.  ./setup.sh http://10.0.0.32:8000

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$HERE/extension"
BACKEND_URL="${1:-http://10.0.0.32:8000}"

echo "== VulnSwarm setup =="
echo "Extension folder: $EXT_DIR"
echo "Backend (tower):  $BACKEND_URL"
echo

# Sanity: is the backend reachable from here?
if command -v curl >/dev/null && curl -sf --max-time 4 "$BACKEND_URL/health" >/dev/null 2>&1; then
  echo "[ok] backend is reachable at $BACKEND_URL"
else
  echo "[warn] backend NOT reachable at $BACKEND_URL"
  echo "       - make sure the tower's lab is up (docker compose up -d)"
  echo "       - make sure this laptop is on the same WiFi/LAN"
fi
echo

# Pick a Chromium-family browser and open its extensions page.
open_extensions() {
  local url="$1"
  for b in brave-browser brave google-chrome chromium chromium-browser; do
    if command -v "$b" >/dev/null 2>&1; then "$b" "$url" >/dev/null 2>&1 & return 0; fi
  done
  # macOS fallbacks
  if [ "$(uname)" = "Darwin" ]; then
    open -a "Brave Browser" "$url" 2>/dev/null && return 0
    open -a "Google Chrome" "$url" 2>/dev/null && return 0
  fi
  return 1
}

echo "Opening your browser's extensions page..."
if open_extensions "brave://extensions"; then
  echo "[ok] opened extensions page"
else
  echo "[warn] couldn't auto-open a browser. Open this manually:"
  echo "       brave://extensions   (or chrome://extensions)"
fi

cat <<EOF

Now, two clicks:
  1. Turn ON 'Developer mode' (top-right)
  2. Click 'Load unpacked' and select this folder:

        $EXT_DIR

Then pin the VulnSwarm icon, open it on a target tab
(e.g. $BACKEND_URL/health or http://10.0.0.32:3001),
confirm the Backend URL says $BACKEND_URL, sign in (erwin@local / demo),
and hit 'Scan this tab'.
EOF
