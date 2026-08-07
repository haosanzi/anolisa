# agent-sec-sidecar Helm Chart

该 Chart 创建一个 Deployment。每个 Pod 包含：

- `agent-sec-cli` caller container；
- `agent-sec-daemon` sidecar container；
- 同时挂载到 `/run/agent-sec` 的 Pod runtime volume；
- 同时挂载到 `/var/lib/agent-sec/persistent` 的持久化数据 PVC；
- 同时注入的
  `AGENT_SEC_DAEMON_SOCKET=/run/agent-sec/runtime/daemon.sock`；
- 同时注入的
  `AGENT_SEC_DATA_DIR=/var/lib/agent-sec/persistent/events`。

Chart 不创建 Service，也不开放网络端口。caller 只通过本 Pod 的 Unix domain socket
访问 daemon。

CLI container 默认设置 `stdin: false` 和 `tty: false`。仓库提供的 CLI 镜像通过
entrypoint 完成幂等插件注册后，默认 `exec openclaw serve` 作为前台主进程，
不再依赖交互式 shell 保活。

当持久化 PVC 启用时，Chart 默认将 CLI container 的 OpenClaw 路径设置为：

```text
HOME=/var/lib/agent-sec/persistent
OPENCLAW_STATE_DIR=/var/lib/agent-sec/persistent/openclaw-state
OPENCLAW_WORKSPACE_DIR=/var/lib/agent-sec/persistent/openclaw-workspace
```

这使以非 root UID `10001` 运行的 OpenClaw 能写入状态和 workspace，并让内容在
Pod 重建后保留。可通过 `cli.openclaw.persistentPaths` 修改相对路径或关闭该行为；
`persistence.enabled=false` 时不会注入这些变量。

## 部署

先按 [`deploy/sidecar/README.md`](../../deploy/sidecar/README.md) 构建并推送两个镜像。
本地 kubeconfig 指向目标集群后执行：

```bash
helm upgrade --install agent-sec-sidecar \
  charts/agent-sec-sidecar \
  --namespace agent-sec \
  --create-namespace \
  --set-string cli.image.repository=<REGISTRY>/agent-sec-cli \
  --set-string cli.image.tag=0.8.0 \
  --set-string daemon.image.repository=<REGISTRY>/agent-sec-daemon \
  --set-string daemon.image.tag=0.8.0
```

私有 registry 的认证信息通过标准 `imagePullSecrets` 配置：

```yaml
imagePullSecrets:
  - name: registry-credentials
```

从 Chart `0.1.0` 升级到 `0.2.0` 时，应使用
`--reset-then-reuse-values`。它先载入新 Chart 的默认值，再合并旧 release
的自定义值。不要在这次升级中使用 `--reuse-values`，否则新增的
`persistence.*` 默认字段可能缺失。

## 持久化数据和 daemon 日志

Chart 默认使用 ACS 的 `alicloud-disk-ssd` StorageClass，创建一个 `20Gi`、
`ReadWriteOnce` 的数据 PVC，并挂载到 CLI 和 daemon 两个 container。daemon
的结构化日志写入：

```text
/var/lib/agent-sec/persistent/events/daemon.jsonl
```

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

CLI 和 daemon 使用相同数字 UID/GID，并复用应用原有的本地文件读写逻辑；Chart
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

## 模型预加载和 readiness

Chart 默认设置 `daemon.promptPreload.enabled=true`。daemon readiness 默认只检查
`daemon.health`，不等待模型 ready。

如果需要让 readiness 等待模型 ready：

```yaml
daemon:
  probes:
    readiness:
      requireModel: true
```

如果首次部署不希望下载模型，可以设置 `daemon.promptPreload.enabled=false`。

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

CLI 和 daemon 默认都使用数字 UID/GID `10001`。当前 daemon 创建的 runtime 目录为
`0700`、socket 为 `0600`，因此两个 container 必须保持相同数字 UID。

验证 OpenClaw 主进程和插件注册：

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
  openclaw plugins inspect agent-sec --json
```
