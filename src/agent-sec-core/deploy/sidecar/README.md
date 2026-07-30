# agent-sec sidecar 镜像

本目录提供两个独立镜像入口：

| 文件 | 默认进程 | 用途 |
| --- | --- | --- |
| `Dockerfile.cli` | 空闲 Python 进程 | 安装 `agent-sec-cli`，供同 Pod 服务或 `kubectl exec` 调用；不启动 daemon |
| `Dockerfile.daemon` | `agent-sec-daemon serve` | 只承担 daemon sidecar 进程职责 |

两个镜像都从当前仓库源码构建同一个 wheel，并安装
`agent-sec-cli/requirements.txt` 中的锁定运行依赖。wheel builder 和 runtime
均使用 Python 3.11.6；Rust、maturin 和编译工具只存在于 builder stage。
`requirements.txt` 已包含 `uv export` 生成的完整依赖闭包，因此容器使用
`pip --no-deps --require-hashes` 精确安装清单，不再让 pip 二次解析可漂移的传递依赖。

两个镜像都包含同一个 Python distribution，因此都能找到两个 console script；
这里的“职责分离”指默认启动的进程不同，并不表示从 daemon 镜像中裁剪
`agent-sec-cli` 可执行文件。

## 构建

必须从 `agent-sec-core` 仓库根目录执行：

```bash
docker build \
  --file deploy/sidecar/Dockerfile.cli \
  --tag <REGISTRY>/agent-sec-cli:0.8.0 \
  .

docker build \
  --file deploy/sidecar/Dockerfile.daemon \
  --tag <REGISTRY>/agent-sec-daemon:0.8.0 \
  .
```

默认使用与 `uv.lock` 一致的阿里云 PyPI mirror，并从 PyTorch CPU index 安装 CPU
版 PyTorch。需要使用内部 mirror 时，可以覆盖构建参数：

```bash
docker build \
  --build-arg PYPI_INDEX_URL=<PYPI_INDEX_URL> \
  --build-arg PYTORCH_INDEX_URL=<PYTORCH_CPU_INDEX_URL> \
  --build-arg PIP_TIMEOUT_SECONDS=120 \
  --build-arg PIP_RETRIES=10 \
  --file deploy/sidecar/Dockerfile.cli \
  --tag <REGISTRY>/agent-sec-cli:0.8.0 \
  .
```

`AGENT_SEC_UID` 和 `AGENT_SEC_GID` 默认都是 `10001`。如果构建时覆盖它们，必须同步
修改 Helm 的 `podSecurityContext.runAsUser`、`runAsGroup` 和 `fsGroup`。

构建完成后推送到集群可访问的 registry：

```bash
docker push <REGISTRY>/agent-sec-cli:0.8.0
docker push <REGISTRY>/agent-sec-daemon:0.8.0
```

## 容器启动行为

镜像构建阶段执行以下工作：

1. 用 Rust 和 maturin 从本地 `agent-sec-cli` 源码生成 wheel；
2. 在 runtime stage 安装锁定的 Python 依赖；
3. 安装 wheel，并检查两个 console script 能正常解析；
4. 创建 UID/GID `10001` 及其可写缓存、配置、数据和 runtime 目录。

容器每次启动时不再编译或安装软件：

- CLI 镜像通过 `tini` 启动一个空闲 Python 进程，以便容器持续运行，但不会启动 daemon；
- daemon 镜像通过 `tini` 直接启动 `agent-sec-daemon serve`；
- daemon 从 `AGENT_SEC_DAEMON_SOCKET` 读取 socket 路径；
- daemon 健康探针通过同一个 UDS 调用 `daemon.health`。

对应 Helm Chart 位于 [`charts/agent-sec-sidecar`](../../charts/agent-sec-sidecar)。
