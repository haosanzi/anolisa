# agent-sec sidecar 镜像

本目录提供两个独立镜像入口：

不使用仓库 Helm Chart 的部署方，请参阅
[`KUBERNETES_DEPLOYMENT_REQUIREMENTS.md`](./KUBERNETES_DEPLOYMENT_REQUIREMENTS.md)，
其中包含镜像契约、Pod/volume/env/securityContext 要求、OpenClaw 初始化方式和原生
Kubernetes YAML 示例。

| 文件 | 默认进程 | 用途 |
| --- | --- | --- |
| `Dockerfile.cli` | `openclaw serve` | OpenClaw 主容器；运行时注册 sec-core 插件并通过 `agent-sec-cli` 调用同 Pod daemon |
| `Dockerfile.daemon` | `agent-sec-daemon serve` | 只承担 daemon sidecar 进程职责 |

CLI 镜像基于 Ubuntu 24.04，安装 Node.js 24 和 OpenClaw，然后通过
`anolisa --install-mode system install sec-core --backend raw` 安装 sec-core。它不从当前
checkout 编译 wheel。raw 安装同时提供 `agent-sec-cli`、`agent-sec-daemon` 和
`/usr/local/share/anolisa/adapters/sec-core/openclaw`；CLI 镜像只负责启动 OpenClaw，
不会启动其中的 daemon 可执行文件。

daemon 镜像基于 Alibaba Cloud Linux 4，通过 `anolisa --install-mode system install`
按 `AGENT_SEC_VERSION` 安装 agent-sec-core RPM，不在镜像构建中从本仓库源码编译。
RPM 同时提供 `agent-sec-cli` 和 `agent-sec-daemon` console script；这里的职责分离指
默认启动进程不同。

## 构建

CLI Dockerfile 使用同目录的 `entrypoint-openclaw.sh` 作为构建输入，因此从
`deploy/sidecar` 目录执行：

```bash
cd deploy/sidecar

docker build \
  --file Dockerfile.cli \
  --tag <REGISTRY>/agent-sec-cli:0.8.0 \
  .
```

daemon Dockerfile 仍然从 `agent-sec-core` 仓库根目录构建，因为它复制
`deploy/sidecar/healthcheck.py`：

```bash
cd ../..

docker build \
  --file deploy/sidecar/Dockerfile.daemon \
  --tag <REGISTRY>/agent-sec-daemon:0.8.0 \
  .
```

CLI Dockerfile 使用 npm selector `openclaw@^2026.4.14`，构建时由 npm 解析该范围内的
版本。镜像创建固定 UID/GID `10001:10001`；部署清单中的 `runAsUser`、`runAsGroup`
和 `fsGroup` 必须与之保持一致。

构建完成后推送到集群可访问的 registry：

```bash
docker push <REGISTRY>/agent-sec-cli:0.8.0
docker push <REGISTRY>/agent-sec-daemon:0.8.0
```

## 容器启动行为

CLI 镜像构建阶段执行以下工作：

1. 安装 OpenClaw 所需的 Node.js 24 和基础运维工具；
2. 安装 `anolisa`，再从 raw backend 安装 sec-core；
3. 创建 UID/GID `10001:10001`；
4. 复制 `entrypoint-openclaw.sh`，但不在镜像构建阶段注册插件。

daemon 镜像构建阶段安装 anolisa 和指定版本的 agent-sec-core RPM，检查两个 console
script，创建相同 UID/GID 与目录，并复制 daemon healthcheck 程序。

CLI container 每次启动时，在 PVC 已挂载且环境变量已注入后，以运行 UID 执行：

1. 创建 OpenClaw state、workspace 和 agent-sec data 目录；
2. 首次启动或插件资源更新时，非交互初始化 workspace；
3. 执行 `anolisa adapter enable sec-core openclaw` 注册插件；
4. 写入当前 agent-sec 插件配置和持久化注册标记；
5. 默认 `exec openclaw serve`，使其成为前台主进程。

该流程不会启动 agent-sec daemon。可用环境变量覆盖运行行为：

| 变量 | 默认值 | 作用 |
| --- | --- | --- |
| `OPENCLAW_GATEWAY_CMD` | `openclaw serve` | 注册完成后的前台命令 |
| `ANOLISA_OPENCLAW_ALLOW_UNSAFE_PLUGIN_INSTALL` | `0` | 设置为 `1` 时向 `adapter enable` 传入显式 unsafe 授权 |

向容器传入显式参数会跳过初始化并直接执行该命令，适合镜像检查或调试。

daemon container 的启动行为不变：

- daemon 镜像直接启动 `agent-sec-daemon serve`，使 daemon 成为 PID 1；
- daemon 从 `AGENT_SEC_DAEMON_SOCKET` 读取 socket 路径；
- daemon 健康探针通过同一个 UDS 调用 `daemon.health`。

对应 Helm Chart 位于 [`charts/agent-sec-sidecar`](../../charts/agent-sec-sidecar)。
