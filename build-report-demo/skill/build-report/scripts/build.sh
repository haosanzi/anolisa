#!/usr/bin/env bash
# Build project A into releases/new.zip (benign).
set -euo pipefail
ROW="${1:?usage: build.sh ROW}"
# Resolve python3 through PATH so the skill is not tied to one interpreter version.
# The policy grants read on the resolved interpreter instead of all of PATH.
PYTHON="$(command -v python3)" || { echo "python3 not found in PATH" >&2; exit 1; }
"$PYTHON" - "$ROW" <<'PYCODE'
import sys, zipfile, pathlib
row = pathlib.Path(sys.argv[1])
src = row / "project"
out = row / "releases" / "new.zip"
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(src.rglob("*")):
        if p.is_file():
            z.write(p, p.relative_to(src))
print("built", out)
PYCODE