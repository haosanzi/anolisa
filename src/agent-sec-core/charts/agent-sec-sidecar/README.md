# agent-sec-sidecar Helm Chart

该 Chart 创建一个 Deployment。每个 Pod 包含：

- `agent-sec-cli` caller container；
- `agent-sec-daemon` sidecar container；
- `ollama` 模型服务 sidecar container；
- CLI 与 daemon 同时挂载到 `/run/agent-sec` 的 Pod runtime volume；
- 三个 container 同时挂载到 `/var/lib/agent-sec/persistent` 的持久化数据 PVC；
- CLI 与 daemon 同时注入
  `AGENT_SEC_DAEMON_SOCKET=/run/agent-sec/runtime/daemon.sock`；
- CLI 与 daemon 同时注入
  `AGENT_SEC_DATA_DIR=/var/lib/agent-sec/persistent/events/<runAsUser>`；默认
  `runAsUser=20001`，因此默认路径是
  `/var/lib/agent-sec/persistent/events/20001`。

Chart 不创建 Service，也不开放网络端口。caller 通过本 Pod 的 Unix domain socket
访问 daemon；Rust prompt scanner 通过 Pod 共享 loopback 的
`http://localhost:11434` 访问 Ollama。

CLI container 默认设置 `stdin: true` 和 `tty: true`，用于运行 Qoder CLI 的交互式
TUI。仓库提供的 Qoder CLI 镜像通过 entrypoint 安装 agent-sec-core 插件后，默认
`exec qodercli` 作为前台主进程。

当持久化 PVC 启用时，Chart 默认将 CLI container 的 Qoder 路径设置为：

```text
HOME=/var/lib/agent-sec/persistent
QODER_CONFIG_DIR=/var/lib/agent-sec/persistent/qoder-config
QODER_WORKING_DIR=/var/lib/agent-sec/persistent/qoder-workspace
```

`QODER_CONFIG_DIR` 是 Qoder CLI 官方支持的配置目录覆盖变量，默认值为 `~/.qoder`；
设置、会话、memory 等本地数据会随 PVC 保留。`QODER_WORKING_DIR` 指定持久化工作目录。
可通过 `cli.qoder.persistentPaths` 修改相对路径或关闭该行为；
`persistence.enabled=false` 时不会注入这些变量。

## 部署

先按 [`deploy/sidecar/README.md`](../../deploy/sidecar/README.md) 构建并推送三个镜像；
若使用不会自动创建 repository 的 registry，需要预先创建这三个镜像仓库。
本地 kubeconfig 指向目标集群后执行：

```bash
helm upgrade --install agent-sec-sidecar \
  charts/agent-sec-sidecar \
  --namespace agent-sec \
  --create-namespace \
  --set-string cli.image.repository=<REGISTRY>/agent-sec-qodercli \
  --set-string cli.image.tag=0.10.2 \
  --set-string daemon.image.repository=<REGISTRY>/agent-sec-daemon \
  --set-string daemon.image.tag=0.10.1 \
  --set-string ollama.image.repository=<REGISTRY>/agent-sec-ollama \
  --set-string ollama.image.tag=0.32.1
```

私有 registry 的认证信息通过标准 `imagePullSecrets` 配置：

```yaml
imagePullSecrets:
  - name: registry-credentials
```

从 Chart `0.2.x` 升级到 `0.3.0` 时，应使用
`--reset-then-reuse-values`。它先载入新 Chart 的默认值，再合并旧 release
的自定义值。不要在这次升级中使用 `--reuse-values`，否则新增的
`persistence.*` 默认字段可能缺失。

## 持久化数据和 daemon 日志

Chart 默认使用 ACS 的 `alicloud-disk-ssd` StorageClass，创建一个 `20Gi`、
`ReadWriteOnce` 的数据 PVC，并挂载到 CLI、daemon 和 Ollama 三个 container。daemon
的结构化日志写入：

```text
/var/lib/agent-sec/persistent/events/20001/daemon.jsonl
```

`events` 下的数字 UID 子目录来自 `podSecurityContext.runAsUser`。修改运行时 UID 后，
Chart 会使用新的子目录，不会要求新 UID 修改旧 UID 所有的目录权限。例如从 10001
迁移到 20001 后，新数据写入 `events/20001`，原有 `events/10001` 保留不动。该行为
隔离数据而不迁移历史；若新 UID 仍需读取旧数据，部署方必须另行复制或迁移。

默认 PVC 名称由 release 名稳定生成，例如 release 为 `agent-sec` 时是
`agent-sec-agent-sec-sidecar-data`：

- 同名 PVC 不存在时，Chart 创建它；
- 同名外部 PVC 已存在时，Chart 自动复用它，不要求用户传入 `existingClaim`；
- 当前 release 已管理该 PVC 时，升级仍继续渲染和管理它。

Chart 创建的 PVC 随 release 卸载。自动复用的外部 PVC 不属于该 release 的资源，
卸载时不会被删除。

默认 Deployment 使用 `RollingUpdate`，设置 `maxSurge=0`、
`maxUnavailable=1`。升级时先终止旧 Pod、释放 RWO 云盘，再启动新 Pod。

使用其他 StorageClass：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set-string persistence.persistentVolumeClaim.storageClassName=<STORAGE_CLASS>
```

只有已有 PVC 使用不同名称时，才需要显式覆盖：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set-string persistence.persistentVolumeClaim.existingClaim=<PVC_NAME>
```

只要 `existingClaim` 非空，Chart 就不会创建数据 PVC；该字段优先于默认的
`create=true`。未指定 `existingClaim` 时，默认安装仍会动态创建 PVC。

如果不需要持久化，可以设置：

```yaml
persistence:
  enabled: false
```

三个 container 使用相同数字 UID/GID，并复用应用原有的本地文件读写逻辑；Chart
不额外引入容器间同步组件。

## Runtime volume

默认值是 `emptyDir`。这不是持久化存储，但它是 socket、lock 等 Pod runtime 文件的
推荐介质：

- 同一 Pod 的两个 container 看到同一个 socket 文件；
- Deployment 扩为多个 replica 时，每个 Pod 自动得到独立 volume 和 daemon；
- Pod 删除后 stale socket 一并消失。

多副本示例：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set replicaCount=3 \
  --set-string 'persistence.persistentVolumeClaim.accessModes[0]=ReadWriteMany' \
  --set-string persistence.persistentVolumeClaim.storageClassName=<RWX_STORAGE_CLASS>
```

每个 Pod 的 runtime `emptyDir` 和 daemon socket 仍相互独立。多个 Pod 共享数据 PVC
时，PVC 及其 StorageClass 必须支持 `ReadWriteMany`。

如果平台策略明确要求 PVC，可以让 Chart 动态创建一个：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set runtime.volume.type=persistentVolumeClaim \
  --set-string runtime.volume.persistentVolumeClaim.storageClassName=<STORAGE_CLASS>
```

也可以挂载已有 PVC：

```bash
helm upgrade agent-sec-sidecar charts/agent-sec-sidecar \
  --namespace agent-sec \
  --reset-then-reuse-values \
  --set runtime.volume.type=persistentVolumeClaim \
  --set runtime.volume.persistentVolumeClaim.create=false \
  --set-string runtime.volume.persistentVolumeClaim.existingClaim=<PVC_NAME>
```

PVC 模式只允许 `replicaCount=1`。Unix socket 不是跨 Pod 服务协议，不能用共享 PVC
把多个 Pod 连接到同一个 daemon。PVC 的底层文件系统也必须支持创建 Unix socket；
若无平台强制要求，应继续使用 `emptyDir`。

## Ollama 模型服务和 readiness

Chart 默认启动 `ollama` sidecar，并设置：

```text
OLLAMA_HOST=127.0.0.1:11434
OLLAMA_MODEL=modelscope.cn/ANOLISA/Qwen3Guard-Gen-0.6B-GGUF
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q4_0
AGENT_SEC_MODEL_SERVICE_BASE_URL=http://localhost:11434
```

`AGENT_SEC_MODEL_SERVICE_BACKEND`、`AGENT_SEC_MODEL_SERVICE_BASE_URL` 和
`AGENT_SEC_MODEL_SERVICE_TIMEOUT` 同时注入 CLI 与 daemon。当前 Qoder prompt hook
直接执行 CLI 中的 Rust scanner，因此 CLI 必须能访问该地址。

Ollama startup/liveness probe 检查 server，readiness probe 通过 `ollama show` 确认
目标模型已经存在。模型默认保存在数据 PVC 的
`/var/lib/agent-sec/persistent/ollama-models`，Pod 替换后无需重新下载。

模型内置 32768-token context。Chart 默认启用 Flash Attention，并将 K/V cache
量化为 `q4_0`，以降低长 context 的内存占用。若更重视 KV cache 精度，可将
`ollama.kvCacheType` 改为 `q8_0`（约为 `f16` 一半内存）或 `f16`，同时相应提高
Pod 的内存规格。

如果部署方提供 Pod 外部模型服务，可以设置 `ollama.enabled=false`，并覆盖顶层
`modelService.baseUrl`。

## 验证

```bash
helm lint charts/agent-sec-sidecar

kubectl rollout status \
  deployment/agent-sec-sidecar \
  --namespace agent-sec

kubectl exec \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli \
  -- \
  agent-sec-cli scan-prompt --mode fast --text "hello"
```

Chart 默认将三个 container 运行成数字 UID/GID `20001:20001`。镜像内保留
`10001:10001` 作为非 Kubernetes 场景的默认用户；Pod SecurityContext 会覆盖镜像
USER。UDS 权限仍要求 CLI 与 daemon 使用相同数字 UID，PVC 写权限由 `fsGroup` 提供。

验证 Qoder CLI 主进程和插件注册：

```bash
kubectl logs \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli

kubectl exec \
  --namespace agent-sec \
  deployment/agent-sec-sidecar \
  --container agent-sec-cli \
  -- \
  qodercli plugins list --json
```
