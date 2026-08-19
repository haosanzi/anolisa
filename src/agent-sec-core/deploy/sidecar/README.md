# agent-sec sidecar 镜像

本目录提供 Qoder caller、agent-sec daemon 和 Ollama 模型服务三个 Pod 镜像；另保留
OpenClaw caller 镜像：

| 文件 | 默认进程 | 用途 |
| --- | --- | --- |
| `Dockerfile.qodercli` | `qodercli` | Qoder CLI 主容器；安装 sec-core Qoder adapter |
| `Dockerfile.daemon` | `agent-sec-daemon serve` | agent-sec daemon sidecar |
| `Dockerfile.ollama` | Ollama server + 模型预热 | Rust prompt scanner 的本地模型服务 sidecar |
| `Dockerfile.cli` | `openclaw serve` | 保留的 OpenClaw caller 镜像 |

Qoder 与 daemon 镜像都从当前 checkout 构建 sec-core raw artifact，不依赖尚未发布的
RPM/raw release。Ollama 镜像基于 Alibaba Cloud Linux 4，并从
`alinux4-agentic-os` 仓库安装 Koji build 70727 的 CPU-only
`ollama-0.32.1-1.alnx4.x86_64` RPM。

## 构建本地 Anolisa raw repo

先从 `agent-sec-core` 仓库根目录运行：

```bash
deploy/sidecar/prepare-local-raw-repo.sh
```

脚本执行 `make package-raw`，并将当前版本发布到：

```text
deploy/sidecar/raw-repo/v1/
├── index.toml
├── index-v2.toml
└── sec-core/<version>/linux/x86_64/...
```

该目录是完整的 Anolisa repo；Dockerfile 中的安装命令为：

```bash
"$ANOLISA_BIN" --install-mode system \
    install sec-core --backend raw --repo "file://${RAW_REPO_DIR}/v1"
```

`--repo` 指向包含 `index.toml`/`index-v2.toml` 的 repo `v1` 目录，不直接指向
sec-core tar artifact。

## 构建镜像

Qoder Dockerfile 保持从 `deploy/sidecar` 目录构建：

```bash
cd deploy/sidecar
docker build \
  --file Dockerfile.qodercli \
  --tag <REGISTRY>/agent-sec-qodercli:0.10.2 \
  .
```

### 前置条件：Ollama RPM

`Dockerfile.ollama` 目前从本地 RPM 安装 Ollama，因为 `ollama-0.32.1-2` 尚未发布到
Agentic OS 仓库。构建前必须先把该 RPM 放到 `deploy/` 下：

```
src/agent-sec-core/deploy/ollama-0.32.1-2.alnx4.x86_64.rpm
```

`.gitignore` 忽略 `*.rpm`，所以全新 clone 不包含这个文件；缺失时 `docker build`
会在 bind mount 一步直接失败。待该版本发布到 Agentic OS 仓库后，应改回用
`dnf install ollama-<nevra>` 从仓库安装，并删除这一前置条件。

daemon 和 Ollama Dockerfile 从仓库根目录构建：

```bash
cd ../..
docker build \
  --file deploy/sidecar/Dockerfile.daemon \
  --tag <REGISTRY>/agent-sec-daemon:0.10.1 \
  .

docker build \
  --file deploy/sidecar/Dockerfile.ollama \
  --tag <REGISTRY>/agent-sec-ollama:0.32.1 \
  .
```

构建完成后、执行 Helm 安装前，先推送三个镜像：

Alibaba Cloud Container Registry 个人版不会通过首次 push 自动创建仓库。请先在
`acs` namespace 中创建 `agent-sec-qodercli`、`agent-sec-daemon` 和
`agent-sec-ollama` 三个仓库，并为当前登录账号授予 push 权限。

```bash
docker push <REGISTRY>/agent-sec-qodercli:0.10.2
docker push <REGISTRY>/agent-sec-daemon:0.10.1
docker push <REGISTRY>/agent-sec-ollama:0.32.1
```

## 容器启动行为

Qoder container 启动时：

1. 创建 Qoder config、workspace 和 agent-sec data 目录；
2. 执行 `anolisa adapter enable sec-core qoder`；
3. 切换到 `QODER_WORKING_DIR`，并以 `qodercli` 作为前台进程。

daemon 镜像直接启动 raw package 提供的 `/usr/local/bin/agent-sec-daemon serve`。
healthcheck 通过 raw package 的 `agent-sec-python` 调用 UDS `daemon.health`。

Ollama entrypoint：

1. 启动 `ollama serve` 并等待 HTTP server ready；
2. 执行 `ollama run modelscope.cn/ANOLISA/Qwen3Guard-Gen-0.6B-GGUF ""`，完成模型拉取和预热；
3. 持续等待 server 进程，并转发 Pod 的终止信号。

Ollama 只监听 Pod 共享 loopback 的 `127.0.0.1:11434`，Chart 不创建 Service。
Rust model-service 默认也使用 `http://localhost:11434`。当前 Qoder hook 在 caller
container 内执行 `agent-sec-cli scan-prompt`，所以 Chart 将模型服务环境变量同时注入
CLI 和 daemon。

镜像保留 `USER 10001:10001` 作为脱离 Kubernetes 运行时的非 root 默认值。Chart 可用
其他数字 `runAsUser`/`runAsGroup` 覆盖它；运行时 HOME、Qoder、daemon XDG 和 Ollama
模型目录都必须指向 PVC 或其他可写 volume。Chart 将
`AGENT_SEC_DATA_DIR` 设置为
`/var/lib/agent-sec/persistent/events/<runAsUser>`；部署方不使用本 Chart 时也应在
`events` 下按实际数字 UID 设置独立子目录。修改 UID 会启用新的数据目录，不会自动
迁移旧 UID 的事件历史。

对应 Helm Chart 位于 [`charts/agent-sec-sidecar`](../../charts/agent-sec-sidecar)。
