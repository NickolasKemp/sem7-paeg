#!/usr/bin/env bash
# Рендерить підготовлені HTML-фрагменти терміналу у PNG через headless Chrome.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

node "$ROOT/tools/capture.ts"

for html in "$ROOT"/assets/*.html; do
  base="${html%.html}"
  size="$(cat "$base.size")"
  "$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --virtual-time-budget=1500 --window-size="${size/x/,}" \
    --screenshot="$base.png" "file://$html" >/dev/null 2>&1
  echo "$(basename "$base").png ← $size"
done
