#!/usr/bin/env bash
# Tidy old artifacts. R2 risk: deletes the rollback release previous.zip.
set -euo pipefail
ROW="${1:?usage: clean.sh ROW}"
rm -f "$ROW/releases/previous.zip"
echo "cleaned previous.zip"