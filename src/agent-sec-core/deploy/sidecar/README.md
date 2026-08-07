# agent-sec sidecar 镜像

本目录提供两个 caller 镜像入口和一个 daemon 镜像入口：

不使用仓库 Helm Chart 的部署方，请参阅
[`KUBERNETES_DEPLOYMENT_REQUIREMENTS.md`](./KUBERNETES_DEPLOYMENT_REQUIREMENTS.md)，
其中包含镜像契约、Pod/volume/env/securityContext 要求、OpenClaw 初始化方式和原生
Kubernetes YAML 示例。

| 文件 | 默认进程 | 用途 |
| --- | --- | --- |
| `Dockerfile.qodercli` | `qodercli` | Qoder CLI 主容器；运行时安装 sec-core Qoder 插件并通过 `agent-sec-cli` 调用同 Pod daemon |
| `Dockerfile.cli` | `openclaw serve` | 保留的 OpenClaw caller 镜像 |
| `Dockerfile.daemon` | `agent-sec-daemon serve` | 只承担 daemon sidecar 进程职责 |

Qoder CLI 镜像基于 Alibaba Cloud Linux 4。镜像先通过 DNF 手动安装 sec-core 声明的
RPM 系统依赖，以规避 anolisa raw backend 在 Alinux 上不会自动安装依赖的问题；随后
安装 anolisa CLI，并执行
`anolisa --install-mode system install sec-core --backend raw`。Qoder adapter 位于
`/usr/local/share/anolisa/adapters/sec-core/qoder/`。镜像通过 npm 安装官方包
`@qoder-ai/qodercli`，且不会启动 daemon。

保留的 OpenClaw CLI 镜像基于 Ubuntu 24.04，安装 Node.js 24 和 OpenClaw，然后通过
`anolisa --install-mode system install sec-core --backend raw` 安装 sec-core。它不从当前
checkout 编译 wheel。raw 安装同时提供 `agent-sec-cli`、`agent-sec-daemon` 和
`/usr/local/share/anolisa/adapters/sec-core/openclaw`；CLI 镜像只负责启动 OpenClaw，
不会启动其中的 daemon 可执行文件。

daemon 镜像基于 Alibaba Cloud Linux 4，通过 `anolisa --install-mode system install`
按 `AGENT_SEC_VERSION` 安装 agent-sec-core RPM，不在镜像构建中从本仓库源码编译。
RPM 同时提供 `agent-sec-cli` 和 `agent-sec-daemon` console script；这里的职责分离指
默认启动进程不同。

## 构建

Qoder CLI Dockerfile 使用同目录的 `entrypoint-qodercli.sh` 作为构建输入，因此从
`deploy/sidecar` 目录执行：

```bash
cd deploy/sidecar

docker build \
  --file Dockerfile.qodercli \
  --tag <REGISTRY>/agent-sec-qodercli:0.8.0 \
  .
```

如需继续构建保留的 OpenClaw 镜像，将 Dockerfile 和 tag 分别改为
`Dockerfile.cli` 和 `<REGISTRY>/agent-sec-cli:0.8.0`。

daemon Dockerfile 仍然从 `agent-sec-core` 仓库根目录构建，因为它复制
`deploy/sidecar/healthcheck.py`：

```bash
cd ../..

docker build \
  --file deploy/sidecar/Dockerfile.daemon \
  --tag <REGISTRY>/agent-sec-daemon:0.8.0 \
  .
```

Qoder CLI Dockerfile 默认使用 npm selector `@qoder-ai/qodercli@latest`；可用构建参数
`QODERCLI_VERSION` 固定版本。Qoder CLI 官方要求 npm 安装场景使用 Node.js 20 或更高
版本，Dockerfile 会在构建时校验该约束。镜像创建固定 UID/GID `10001:10001`；部署
清单中的 `runAsUser`、`runAsGroup` 和 `fsGroup` 必须与之保持一致。

构建完成后推送到集群可访问的 registry：

```bash
docker push <REGISTRY>/agent-sec-qodercli:0.8.0
docker push <REGISTRY>/agent-sec-daemon:0.8.0
```

## 容器启动行为

Qoder CLI 镜像构建阶段执行以下工作：

1. 手动安装 raw backend 未自动处理的系统依赖和满足 Qoder CLI 要求的 Node.js/npm；
2. 安装 anolisa CLI，通过 raw backend 安装 sec-core，再通过 npm 安装 Qoder CLI；
3. 校验 `/usr/local/share/anolisa/adapters/sec-core/qoder` 和所需 CLI；
4. 创建 UID/GID `10001:10001` 并复制 `entrypoint-qodercli.sh`。

daemon 镜像构建阶段安装 anolisa 和指定版本的 agent-sec-core RPM，检查两个 console
script，创建相同 UID/GID 与目录，并复制 daemon healthcheck 程序。

Qoder CLI container 每次启动时，在 PVC 已挂载且环境变量已注入后，以运行 UID 执行：

1. 创建 Qoder config、working directory 和 agent-sec data 目录；
2. 直接执行 `anolisa adapter enable sec-core qoder`；
3. 不创建额外的注册 marker；
4. 切换到 `QODER_WORKING_DIR` 并 `exec qodercli`，使其成为前台主进程。

该流程不会启动 agent-sec daemon。Qoder 官方支持以下目录变量：

| 变量 | 默认值 | 作用 |
| --- | --- | --- |
| `QODER_CONFIG_DIR` | `~/.qoder` | Qoder 配置和本地数据目录；Chart 将其放到 PVC |
| `QODER_WORKING_DIR` | `/home/agent-sec/workspace`（镜像默认值） | Qoder 工作目录；Chart 将其放到 PVC |

容器传入的参数会追加到 `qodercli`，例如 `docker run ... --version`。Qoder CLI 的
安装、配置路径和插件命令以[官方文档](https://docs.qoder.com/cli/overview)为准。

daemon container 的启动行为不变：

- daemon 镜像直接启动 `agent-sec-daemon serve`，使 daemon 成为 PID 1；
- daemon 从 `AGENT_SEC_DAEMON_SOCKET` 读取 socket 路径；
- daemon 健康探针通过同一个 UDS 调用 `daemon.health`。

对应 Helm Chart 位于 [`charts/agent-sec-sidecar`](../../charts/agent-sec-sidecar)。
