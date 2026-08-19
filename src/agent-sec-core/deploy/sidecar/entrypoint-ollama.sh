#!/usr/bin/env bash
set -euo pipefail

: "${HOME:=/home/agent-sec}"
: "${OLLAMA_HOST:=127.0.0.1:11434}"
: "${OLLAMA_KEEP_ALIVE:=-1}"
: "${OLLAMA_KV_CACHE_TYPE:=q8_0}"
: "${OLLAMA_NUM_PARALLEL:=1}"
: "${OLLAMA_MODEL:=modelscope.cn/ANOLISA/Qwen3Guard-Gen-0.6B-GGUF}"
: "${OLLAMA_MODELS:=${HOME}/.ollama/models}"
: "${OLLAMA_NUM_CTX:=4096}"
: "${OLLAMA_STARTUP_TIMEOUT_SECONDS:=60}"

export HOME OLLAMA_HOST OLLAMA_KEEP_ALIVE OLLAMA_KV_CACHE_TYPE OLLAMA_NUM_PARALLEL OLLAMA_MODEL OLLAMA_MODELS

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

# Ensure the model exists locally before deriving an override from it. On a
# warm persistent volume this is a no-op; on first boot it pulls once.
if ! ollama show "${OLLAMA_MODEL}" >/dev/null 2>&1; then
    echo "[entrypoint] Pulling Ollama model ${OLLAMA_MODEL}..."
    ollama pull "${OLLAMA_MODEL}"
fi

# The upstream Modelfile ships num_ctx=32768, which is larger than this sidecar
# needs and inflates KV-cache memory. Modelfile/request values always win over
# the OLLAMA_CONTEXT_LENGTH env, so re-creating the model in place with a
# smaller num_ctx is the reliable way to cap the context. Existing layers are
# reused, so no re-download happens.
echo "[entrypoint] Overriding num_ctx=${OLLAMA_NUM_CTX} for ${OLLAMA_MODEL}..."
override_modelfile="$(mktemp "${TMPDIR:-/tmp}/Modelfile.XXXXXX")"
printf 'FROM %s\nPARAMETER num_ctx %s\n' "${OLLAMA_MODEL}" "${OLLAMA_NUM_CTX}" >"${override_modelfile}"
if ! ollama create "${OLLAMA_MODEL}" -f "${override_modelfile}"; then
    echo "[entrypoint] WARNING: failed to override num_ctx; continuing with model defaults" >&2
fi
rm -f "${override_modelfile}"

echo "[entrypoint] Loading Ollama model ${OLLAMA_MODEL}..."
ollama run "${OLLAMA_MODEL}" ""
echo "[entrypoint] Ollama model is ready: ${OLLAMA_MODEL}"

wait "${server_pid}"
status="$?"
server_pid=""
trap - INT TERM EXIT
exit "${status}"
