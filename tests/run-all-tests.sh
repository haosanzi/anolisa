#!/bin/bash
set -e

# Ensure we're running from the root of the repo
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER=""

if [ "$1" == "--filter" ]; then
    FILTER="$2"
fi

run_shell() {
    echo "==> Running copilot-shell tests"
    cd "$ROOT_DIR/src/copilot-shell" || exit 1
    npm test
}

run_sec() {
    echo "==> Running agent-sec-core tests"
    if command -v uv >/dev/null 2>&1; then
        make -C "$ROOT_DIR/src/agent-sec-core" test-python
    else
        echo "uv not found, skipping agent-sec-core Python tests."
    fi

    echo "==> Running agent-sec-core e2e test scripts manually"
    if [ -f "/usr/local/bin/linux-sandbox" ]; then
        python3 tests/e2e/linux-sandbox/e2e_test.py
    else
        echo "linux-sandbox not found at /usr/local/bin/linux-sandbox, skipping e2e_test.py"
    fi
}

run_sight() {
    echo "==> Running agentsight tests"
    cd "$ROOT_DIR/src/agentsight" || exit 1
    if command -v cargo >/dev/null 2>&1; then
        cargo test
    else
        echo "cargo not found, skipping agentsight tests."
    fi
}

if [ -z "$FILTER" ]; then
    run_shell
    run_sec
    run_sight
elif [ "$FILTER" == "shell" ]; then
    run_shell
elif [ "$FILTER" == "sec" ]; then
    run_sec
elif [ "$FILTER" == "sight" ]; then
    run_sight
else
    echo "Unknown filter: $FILTER. Use 'shell', 'sec', or 'sight'."
    exit 1
fi

echo "==> All tests completed successfully!"
