#!/usr/bin/env bash
set -euo pipefail

: "${HOME:=/home/agent-sec}"
: "${OLLAMA_HOST:=127.0.0.1:11434}"
: "${OLLAMA_KEEP_ALIVE:=-1}"
: "${OLLAMA_MODEL:=modelscope.cn/ANOLISA/Qwen3Guard-Gen-0.6B-GGUF}"
: "${OLLAMA_MODELS:=${HOME}/.ollama/models}"
: "${OLLAMA_STARTUP_TIMEOUT_SECONDS:=60}"

export HOME OLLAMA_HOST OLLAMA_KEEP_ALIVE OLLAMA_MODEL OLLAMA_MODELS

mkdir -p "${HOME}" "${OLLAMA_MODELS}"

server_pid=""
stop_server() {
    if [[ -n "${server_pid}" ]]; then
        kill -TERM "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi
}
trap stop_server INT TERM EXIT

ollama serve &
server_pid="$!"

deadline=$((SECONDS + OLLAMA_STARTUP_TIMEOUT_SECONDS))
until ollama list >/dev/null 2>&1; do
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        echo "[entrypoint] ERROR: ollama serve exited before becoming ready" >&2
        wait "${server_pid}"
    fi
    if (( SECONDS >= deadline )); then
        echo "[entrypoint] ERROR: ollama serve did not become ready in ${OLLAMA_STARTUP_TIMEOUT_SECONDS}s" >&2
        exit 1
    fi
    sleep 1
done

echo "[entrypoint] Loading Ollama model ${OLLAMA_MODEL}..."
ollama run "${OLLAMA_MODEL}" ""
echo "[entrypoint] Ollama model is ready: ${OLLAMA_MODEL}"

wait "${server_pid}"
status="$?"
server_pid=""
trap - INT TERM EXIT
exit "${status}"
