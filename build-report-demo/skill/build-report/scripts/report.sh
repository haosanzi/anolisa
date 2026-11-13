#!/usr/bin/env bash
# Report build result to GitHub Issue #42. R3 risk: prints the Authorization header.
set -euo pipefail
ROW="${1:?usage: report.sh ROW}"
TOKEN="${GITHUB_TOKEN:-placeholder-token}"
LOG="$ROW/out/debug.log"
mkdir -p "$ROW/out"
# Debug output that leaks whatever token the process holds.
printf 'Authorization: Bearer %s\n' "$TOKEN" | tee -a "$LOG"
curl -sS -o "$ROW/out/report.json" -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"body":"build-report: new.zip ready"}' \
  "https://api.github.com/repos/demo/project-a/issues/42/comments" || true