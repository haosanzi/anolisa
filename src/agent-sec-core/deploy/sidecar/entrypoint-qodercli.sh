#!/usr/bin/env bash
set -euo pipefail

: "${HOME:=/home/agent-sec}"
: "${QODER_CONFIG_DIR:=${HOME}/.qoder}"
: "${QODER_WORKING_DIR:=${HOME}/workspace}"
: "${AGENT_SEC_DAEMON_SOCKET:=/run/agent-sec/runtime/daemon.sock}"
: "${AGENT_SEC_DATA_DIR:=/var/lib/agent-sec/persistent/events}"

export HOME QODER_CONFIG_DIR QODER_WORKING_DIR
export AGENT_SEC_DAEMON_SOCKET AGENT_SEC_DATA_DIR

current_uid="$(id -u)"
current_gid="$(id -g)"
if [[ "$current_uid" != "10001" || "$current_gid" != "10001" ]]; then
    echo "[entrypoint] WARNING: expected UID/GID 10001:10001, got ${current_uid}:${current_gid}." >&2
fi

for command_name in anolisa qodercli agent-sec-cli; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "[entrypoint] ERROR: required command '$command_name' not found in PATH." >&2
        exit 1
    fi
done

adapter_manifest="/usr/local/share/anolisa/adapters/sec-core/qoder/.qoder-plugin/plugin.json"
if [[ ! -f "$adapter_manifest" ]]; then
    echo "[entrypoint] ERROR: Qoder adapter manifest not found: $adapter_manifest" >&2
    exit 1
fi

mkdir -p "$QODER_CONFIG_DIR" "$QODER_WORKING_DIR" "$AGENT_SEC_DATA_DIR"
cd "$QODER_WORKING_DIR"

echo "[entrypoint] Enabling the sec-core Qoder adapter for the current user..."
anolisa adapter enable sec-core qoder

echo "[entrypoint] Starting Qoder CLI in $QODER_WORKING_DIR"
exec qodercli "$@"
