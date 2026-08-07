#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# OpenClaw / agent-sec-cli container entrypoint
#
# 设计约束（参见 agent-sec Sidecar 镜像部署要求）：
# 1. OpenClaw 注册状态位于 OPENCLAW_STATE_DIR，必须在 PVC 挂载、环境变量注入后
#    以运行 UID（10001）通过 anolisa adapter enable 完成，不能在 Dockerfile 构建时以 root 执行。
# 2. 需要有一个持续运行的前台主进程；不能依赖 stdin/tty 保活。
# 3. 注册过程幂等：PVC 持久化后，Pod 重建不应导致重复注册。
# ---------------------------------------------------------------------------

# ---- 调试/手动执行入口：传参时直接执行给定命令 ----
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# ---- 默认值：与文档推荐值保持一致 ----
: "${HOME:=/var/lib/agent-sec/persistent}"
: "${OPENCLAW_STATE_DIR:=/var/lib/agent-sec/persistent/openclaw-state}"
: "${OPENCLAW_WORKSPACE_DIR:=/var/lib/agent-sec/persistent/openclaw-workspace}"
: "${AGENT_SEC_DAEMON_SOCKET:=/run/agent-sec/runtime/daemon.sock}"
: "${AGENT_SEC_DATA_DIR:=/var/lib/agent-sec/persistent/events}"

export HOME OPENCLAW_STATE_DIR OPENCLAW_WORKSPACE_DIR \
       AGENT_SEC_DAEMON_SOCKET AGENT_SEC_DATA_DIR

# ---- 运行身份检查 ----
CURRENT_UID="$(id -u)"
CURRENT_GID="$(id -g)"
if [ "$CURRENT_UID" -ne 10001 ] || [ "$CURRENT_GID" -ne 10001 ]; then
    echo "[entrypoint] WARNING: expected UID/GID 10001:10001, got ${CURRENT_UID}:${CURRENT_GID}." >&2
fi

# ---- 验证必要命令 ----
for cmd in anolisa openclaw agent-sec-cli bash jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[entrypoint] ERROR: required command '$cmd' not found in PATH." >&2
        exit 1
    fi
done

# ---- 验证镜像内 raw adapter 文件 ----
PLUGIN_ROOT="/usr/local/share/anolisa/adapters/sec-core/openclaw"
for f in "$PLUGIN_ROOT/openclaw.plugin.json" \
         "$PLUGIN_ROOT/dist/index.js"; do
    if [ ! -e "$f" ]; then
        echo "[entrypoint] ERROR: required plugin file missing: $f" >&2
        exit 1
    fi
done

# ---- 确保 OpenClaw / agent-sec 目录存在且可写 ----
mkdir -p "$OPENCLAW_STATE_DIR" "$OPENCLAW_WORKSPACE_DIR" "$AGENT_SEC_DATA_DIR"

# ---- 幂等注册插件 ----
# 注册标记放在 OPENCLAW_STATE_DIR 下，PVC 持久化后可跨 Pod 重建保留。
# 当镜像内插件文件更新（mtime 更新）时，重新执行注册。
REGISTERED_MARK="$OPENCLAW_STATE_DIR/.agent-sec-plugin-registered"
PLUGIN_META="$PLUGIN_ROOT/openclaw.plugin.json"

should_register=false
if [ ! -f "$REGISTERED_MARK" ]; then
    should_register=true
elif [ "$PLUGIN_META" -nt "$REGISTERED_MARK" ]; then
    echo "[entrypoint] Plugin metadata newer than last registration mark, re-registering."
    should_register=true
fi

if [ "$should_register" = true ]; then
    echo "[entrypoint] Initializing OpenClaw workspace..."
    # Container has no TTY; use non-interactive onboarding.
    # --skip-health: the OpenClaw gateway will be started later by OPENCLAW_GATEWAY_CMD.
    openclaw onboard --non-interactive --accept-risk --skip-health --workspace "$OPENCLAW_WORKSPACE_DIR"

    echo "[entrypoint] Enabling agent-sec OpenClaw adapter through anolisa..."
    enable_args=(adapter enable sec-core openclaw)
    if [ "${ANOLISA_OPENCLAW_ALLOW_UNSAFE_PLUGIN_INSTALL:-0}" = "1" ]; then
        enable_args+=(--allow-unsafe-plugin-install)
    fi
    OPENCLAW_HOME="$OPENCLAW_STATE_DIR" anolisa "${enable_args[@]}"

    echo "[entrypoint] Applying agent-sec plugin configuration..."
    openclaw config set plugins.entries.agent-sec.hooks.allowConversationAccess true
    openclaw config set plugins.entries.agent-sec.config.promptScanBlock true

    touch "$REGISTERED_MARK"
    echo "[entrypoint] Plugin registration completed."
else
    echo "[entrypoint] agent-sec plugin already registered, skipping registration."
fi

# ---- 启动前台主进程 ----
# 优先使用环境变量指定的命令；否则尝试 openclaw serve。
# 如果实际 OpenClaw gateway 启动命令不同，请在 Pod spec 中通过
# OPENCLAW_GATEWAY_CMD 覆盖，或修改本脚本默认值。
OPENCLAW_GATEWAY_CMD="${OPENCLAW_GATEWAY_CMD:-openclaw serve}"

if [ -n "$OPENCLAW_GATEWAY_CMD" ]; then
    echo "[entrypoint] Starting foreground process: $OPENCLAW_GATEWAY_CMD"
    # shellcheck disable=SC2086
    exec $OPENCLAW_GATEWAY_CMD
else
    echo "[entrypoint] ERROR: no foreground command configured (OPENCLAW_GATEWAY_CMD is empty)." >&2
    exit 1
fi
