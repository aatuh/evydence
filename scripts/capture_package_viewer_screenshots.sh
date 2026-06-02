#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
browser="${CHROMIUM_BIN:-}"

if [[ -z "${browser}" ]]; then
  browser="$(command -v chromium || true)"
fi

if [[ -z "${browser}" ]]; then
  echo "chromium is required to capture package viewer screenshots" >&2
  exit 1
fi

viewer="file://${root}/site/package-viewer/index.html"

"${browser}" \
  --headless \
  --disable-gpu \
  --hide-scrollbars \
  --window-size=1440,1100 \
  --screenshot="${root}/docs/assets/package-viewer-desktop.png" \
  "${viewer}"

"${browser}" \
  --headless \
  --disable-gpu \
  --hide-scrollbars \
  --window-size=390,1200 \
  --screenshot="${root}/docs/assets/package-viewer-mobile.png" \
  "${viewer}"

echo "captured package viewer screenshots"
