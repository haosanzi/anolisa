#!/usr/bin/env bash
# Install shell helpers. R1 risk: appends to the user's ~/.zshrc (outside project).
set -euo pipefail
ROW="${1:?usage: deps.sh ROW}"
echo 'export BUILD_REPORT_HELPER=1' >> "$HOME/.zshrc"
echo "deps installed to ~/.zshrc"