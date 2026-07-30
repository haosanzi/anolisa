# Agent Security Daemon Sidecar 部署要求

## 1. 目的与适用范围

本文定义 `agent-sec-daemon` 以 sidecar container 方式部署时的运行、存储、
安全和验收要求。

本文默认以下拓扑：

- 工作负载由 Kubernetes Deployment 等控制器管理，可以存在多个 Pod replica。
- 每个 Pod 包含一个 caller container 和一个 `agent-sec-daemon` container。
- caller 只调用同一 Pod 内的 daemon，不跨 Pod 调用。
- caller 与 daemon 通过路径型 Unix domain socket（UDS）通信。
- 每个 Pod 拥有独立的 runtime volume、daemon 进程和 socket。

本文不定义跨 Pod 的中心化 daemon 服务。若 caller 需要跨 Pod 调用，应另行设计
TCP/HTTP/gRPC 传输、服务发现、认证、加密、限流和高可用机制。

## 2. 当前实现基线

### 2.1 进程和传输

当前 Python 包通过 `agent-sec-daemon` entrypoint 启动 daemon，入口为
`agent_sec_cli.daemon.server:main`。daemon 使用
`asyncio.start_unix_server()` 监听路径型 UDS；同步客户端使用
`AF_UNIX`、`SOCK_STREAM` 连接该路径。

当前协议为一连接一请求的 NDJSON：

1. caller 建立 UDS 连接。
2. caller 发送一行 UTF-8 JSON，并以换行符结束。
3. daemon 返回一行 UTF-8 JSON。
4. daemon 关闭连接。

源码依据：

- [`agent-sec-daemon` entrypoint](../../agent-sec-cli/pyproject.toml)
- [UDS server](../../agent-sec-cli/src/agent_sec_cli/daemon/server.py)
- [UDS client](../../agent-sec-cli/src/agent_sec_cli/daemon/client.py)
- [NDJSON protocol](../../agent-sec-cli/src/agent_sec_cli/daemon/protocol.py)

### 2.2 Socket 路径解析

socket 路径按以下优先级解析：

1. 进程参数显式传入的路径；
2. `AGENT_SEC_DAEMON_SOCKET`；
3. `$XDG_RUNTIME_DIR/agent-sec-core/daemon.sock`；
4. 当 `XDG_RUNTIME_DIR` 缺失且 `/run/user/<uid>` 存在时，使用
   `/run/user/<uid>/agent-sec-core/daemon.sock`。

容器部署必须显式设置 `AGENT_SEC_DAEMON_SOCKET`，不得依赖容器内可能不存在的
`XDG_RUNTIME_DIR` 或 `/run/user/<uid>`。

源码依据：

- [runtime path resolution](../../agent-sec-cli/src/agent_sec_cli/daemon/runtime.py)
- [daemon environment variables](../../agent-sec-cli/src/agent_sec_cli/daemon/env.py)

### 2.3 当前文件权限要求

daemon 对 runtime 路径实施以下强制检查：

- socket 父目录必须是普通目录，不能是符号链接；
- socket 父目录必须由 daemon 当前数字 UID 所有；
- socket 父目录权限必须精确为 `0700`；
- daemon socket 创建后权限被设置为 `0600`；
- 同一目录中的 `daemon.lock` 用于进程级 single-instance lock。

因此，在不修改代码的前提下，caller 与 daemon 必须使用相同的数字 UID。
仅配置相同 GID 或 `fsGroup` 不能获得对 `0600` socket 的访问权限。

源码依据：

- [runtime directory validation](../../agent-sec-cli/src/agent_sec_cli/daemon/runtime.py)
- [socket creation and mode](../../agent-sec-cli/src/agent_sec_cli/daemon/server.py)

### 2.4 当前 daemon API 范围

当前默认 registry 注册以下方法：

| 类别 | 方法 |
| --- | --- |
| 健康检查 | `daemon.health` |
| Prompt Scanner | `scan-prompt` |
| Skill Ledger | `skill_ledger.skillfs_notify_change` |
| Security Events 查询 | `sec.summary`、`sec.events.list`、`sec.events.get`、`sec.events.count_by` |
| Observability 查询 | `obs.sessions.list`、`obs.runs.list`、`obs.timeline.get` |

Code Scanner、PII Checker、Security Baseline 和 Sandbox 当前没有 daemon RPC。
调用方不得假定所有 `agent-sec-cli` 功能都能通过 daemon 使用。

源码依据：

- [default registry](../../agent-sec-cli/src/agent_sec_cli/daemon/server.py)
- [security and observability query registry](../../agent-sec-cli/src/agent_sec_cli/daemon/handlers/security_query.py)

## 3. 多副本部署拓扑

Deployment 存在多个 replica 时，每个 Pod 必须独立运行一份 daemon：

```text
Pod-1: caller ── UDS ── daemon   [runtime emptyDir-1]
Pod-2: caller ── UDS ── daemon   [runtime emptyDir-2]
Pod-3: caller ── UDS ── daemon   [runtime emptyDir-3]
```

所有 Pod 可以配置相同的逻辑路径，例如：

```text
AGENT_SEC_DAEMON_SOCKET=/run/agent-sec/runtime/daemon.sock
```

由于每个 Pod 的 mount namespace 和 `emptyDir` 相互隔离，相同的路径字符串不会导致
跨 Pod 的 socket 或 lock 冲突。

必须满足以下要求：

- 每个 Pod 使用独立 `emptyDir` 作为 runtime volume。
- runtime volume 只能挂载到需要访问 daemon 的容器。
- caller 只能连接本 Pod runtime volume 中的 socket。
- 不得使用所有 replica 共享的 RWX PVC 存放 daemon socket 或 `daemon.lock`。
- 不得依靠 UDS 实现跨节点或跨 Pod 调用。

`emptyDir` 的生命周期与 Pod 一致：

- daemon container 重启时，`emptyDir` 仍然存在；
- Pod 删除或替换时，`emptyDir` 和 socket 一起删除；
- daemon 重启时，当前实现会在持有 lock 后探测旧 socket，并删除不可达的 stale socket。

源码依据：

- [socket preparation and stale-socket cleanup](../../agent-sec-cli/src/agent_sec_cli/daemon/server.py)

## 4. Runtime Volume 和数字 UID

### 4.1 数字 UID

数字 UID 是 Linux 内核用于文件所有权和权限判断的整数，例如 `10001`。用户名只是
容器内 `/etc/passwd` 的显示映射，不参与内核的所有权比较。

以下两个容器可以访问同一个 `0600` socket：

```text
daemon container: username=agent-sec, uid=10001
caller container: username=app,       uid=10001
```

即使用户名相同，只要数字 UID 不同，caller 也不能访问该 socket。

Pod 应在 Pod 级别统一指定非 root UID，并禁止容器局部覆盖成不同 UID：

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
```

`10001` 只是示例值。所选 UID 必须满足：

- caller 和 daemon 使用同一个数字 UID；
- 两个镜像中的可执行文件和只读资源对该 UID 可读、可执行；
- runtime、模型缓存、日志和数据目录对该 UID 可写；
- daemon 不以 root 身份运行。

### 4.2 Runtime Volume 挂载

推荐将 `emptyDir` 挂载为 socket 父级目录，并让 daemon 创建其下的私有
`0700` runtime 子目录：

```yaml
spec:
  volumes:
    - name: agent-sec-runtime
      emptyDir: {}

  containers:
    - name: caller
      env:
        - name: AGENT_SEC_DAEMON_SOCKET
          value: /run/agent-sec/runtime/daemon.sock
      volumeMounts:
        - name: agent-sec-runtime
          mountPath: /run/agent-sec

    - name: agent-sec-daemon
      env:
        - name: AGENT_SEC_DAEMON_SOCKET
          value: /run/agent-sec/runtime/daemon.sock
      volumeMounts:
        - name: agent-sec-runtime
          mountPath: /run/agent-sec
```

平台必须保证 `/run/agent-sec` 对 Pod 的 `runAsUser` 可写，使 daemon 能创建：

```text
/run/agent-sec/runtime                 0700 uid=10001
/run/agent-sec/runtime/daemon.lock     0600 uid=10001
/run/agent-sec/runtime/daemon.sock     0600 uid=10001
```

如果平台不能通过 Pod security context 正确准备 volume 根目录，应使用受控的
init container 或等效机制设置 ownership 和 mode。

不得直接把一个预先存在的 `0755` 或其他 UID 所有的目录作为 socket 父目录；
当前 daemon 会拒绝启动，而不是自动放宽该目录权限。

### 4.3 不同 UID 的后续方案

若 caller 和 daemon 必须使用不同 UID，当前实现需要修改为基于共享 GID 的访问模式，
至少包括：

- runtime 目录支持受控的 group ownership 和 `0770`；
- socket 支持受控的 group ownership 和 `0660`；
- runtime 校验允许明确配置的 UID/GID/mode 组合；
- caller 通过 `supplementalGroups` 或等效机制加入该 GID；
- 增加目录替换、符号链接、错误 owner/mode 和未授权访问测试。

不得通过让 caller 以 root 身份运行来规避该问题。

## 5. Daemon 镜像要求

### 5.1 构建输入

当前仓库已经提供：

- Python 包和 `agent-sec-daemon` console entrypoint；
- `make build-cli`；
- 基于 maturin 的 Rust/PyO3 wheel 构建；
- Python 和资源文件打包配置。
- 分别用于 caller 和 daemon 的 multi-stage Dockerfile；
- 一 Pod 双容器的 Helm Chart，以及 `emptyDir`/单副本 PVC runtime volume 配置。

当前容器构建复用 wheel 作为安装单元，不在 runtime image 中保留完整编译工具链。

源码依据：

- [CLI wheel build](../../Makefile)
- [Python and maturin configuration](../../agent-sec-cli/pyproject.toml)
- [caller image](../../deploy/sidecar/Dockerfile.cli)
- [daemon image](../../deploy/sidecar/Dockerfile.daemon)
- [sidecar Helm Chart](../../charts/agent-sec-sidecar)

### 5.2 Runtime image

runtime image 必须满足：

- Python 版本为项目固定的 `3.11.6`；
- wheel 的 Python ABI、CPU 架构和 libc 与 runtime image 兼容；
- 包含 daemon 所需的 Python 运行时依赖；
- 以非 root UID 启动；
- 直接执行 `agent-sec-daemon serve`，不在容器内运行 systemd；
- 将 `agent-sec-daemon` 作为接收 `SIGTERM`/`SIGINT` 的主进程；
- 只开放明确需要的可写目录；
- 不暴露 daemon 网络端口。

当前 `make build-cli` 使用 `maturin build --manylinux off`，因此 builder 和 runtime
的 ABI 兼容性必须在镜像构建流程中显式保证，或改用符合发布目标的 portable wheel
构建策略。

当前 Python 运行依赖包括 torch、transformers 和 ModelScope 等组件。镜像设计必须
评估镜像体积、CPU 架构、模型推理资源和依赖漏洞修复策略。

### 5.3 镜像发布流程

OCI 镜像流水线至少应包含：

1. 使用锁定依赖构建 wheel；
2. 在目标 runtime 基础镜像中安装 wheel 和依赖；
3. 运行 daemon unit/integration tests；
4. 运行双容器 UDS smoke test；
5. 运行非 root、只读 root filesystem 和 signal shutdown 测试；
6. 生成 SBOM；
7. 执行镜像漏洞扫描；
8. 使用不可变版本和 digest 发布；
9. 根据发布策略签名镜像；
10. 验证目标 CPU 架构。

daemon 与 caller image 必须固定兼容版本，不得仅依赖可漂移的 `latest` 标签。

## 6. 模型缓存和启动语义

### 6.1 当前 Prompt 模型行为

daemon 默认注册 Prompt 模型 preload background job。该 job：

1. 首先尝试从本地缓存加载并执行 probe；
2. 本地加载失败时，启动一次子进程尝试下载或修复模型；
3. 下载后再尝试加载一次；
4. 失败后将 Prompt Scanner 状态标记为 `degraded`，但 daemon 继续提供服务。

相关配置：

| 配置 | 当前默认值或行为 |
| --- | --- |
| 模型 | `LLM-Research/Llama-Prompt-Guard-2-86M` |
| 模型来源 | ModelScope |
| 本地缓存 | `~/.cache/prompt_scanner/models` |
| `AGENT_SEC_DAEMON_PROMPT_PRELOAD` | 默认启用 |
| `AGENT_SEC_DAEMON_PROMPT_PRELOAD_DOWNLOAD_TIMEOUT_SECONDS` | 默认 600 秒 |

源码依据：

- [prompt preload job](../../agent-sec-cli/src/agent_sec_cli/daemon/jobs/prompt_preload.py)
- [model cache and ModelScope download](../../agent-sec-cli/src/agent_sec_cli/prompt_scanner/models/model_manager.py)
- [Prompt Scanner model configuration](../../agent-sec-cli/src/agent_sec_cli/prompt_scanner/config.py)

### 6.2 部署必须选择模型分发方式

部署方必须明确选择以下一种模型分发策略：

- 构建时将模型烘焙进 daemon image；
- init container 下载到每 Pod 或持久化缓存 volume；
- daemon 启动时按当前行为联网下载。

不得在未评估以下问题时依赖启动时下载：

- Pod 冷启动时间；
- 多 replica 同时下载；
- 生产环境网络出口；
- ModelScope 可用性；
- 下载失败后的安全降级；
- Pod 重建导致的重复下载。

若模型不在镜像中，必须为 daemon 配置可写 `HOME` 或修改实现以支持显式模型缓存目录。

### 6.3 多副本资源影响

一 Pod 一 daemon 意味着：

- N 个 Pod 会运行 N 个 daemon 进程；
- N 个 Pod 会分别加载 N 份模型到内存；
- 若没有共享或预置缓存，N 个 Pod 可能分别下载模型；
- rollout 期间新旧 replica 可能同时占用模型内存。

必须据此设置 CPU、内存 request/limit、rollout surge 和容量告警。若模型副本成本不可接受，
应评估中心化服务，而不是让不同 Pod 共享 runtime UDS。

## 7. 健康检查和生命周期

### 7.1 `daemon.health`

`daemon.health` 返回：

- daemon runtime `status`；
- PID 和 uptime；
- socket 路径；
- Prompt Scanner preload 状态；
- background job 状态；
- request queue counters。

顶层 `status=ok` 只表示 daemon runtime 正在服务，不表示 Prompt 模型已经成功加载。
模型 readiness 必须从 `data.prompt_scan.status` 和 `data.prompt_scan.loaded` 判断。

源码依据：

- [daemon health response](../../agent-sec-cli/src/agent_sec_cli/daemon/health.py)

### 7.2 Probe 要求

daemon container 必须配置本地 exec probe 或等效机制，通过 UDS 调用
`daemon.health`：

- startup probe：等待 socket 创建并能完成 `daemon.health`；
- liveness probe：确认 daemon 仍能完成本地请求；
- readiness probe：根据业务语义选择以下策略。

Readiness 策略：

| 业务要求 | Readiness 条件 |
| --- | --- |
| 只使用 `fast` 模式 | daemon 可完成 `daemon.health` |
| 允许冷启动期间降级 | daemon 可完成 `daemon.health`，并监控 nested model 状态 |
| 要求完整 `standard`/`strict` 检测 | `prompt_scan.loaded=true` 且状态为 `ready` |

当前实现中，模型未 ready 时，`standard` 和 `strict` 请求会降级为 `fast`。
降级结果会携带 `degraded=true`；降级期间的 `deny` 会被改写为 `warn`。要求完整检测的部署
不得仅以 socket 可连接作为 readiness 条件。

源码依据：

- [Prompt Scanner daemon degradation](../../agent-sec-cli/src/agent_sec_cli/daemon/handlers/prompt_scan.py)

### 7.3 Caller 启动和重连

caller 不得假定 daemon 一定先启动。caller 必须：

- 在首次调用前等待本 Pod 的 `daemon.health`；
- 对 socket 尚不存在、连接拒绝和 daemon 重启使用有限退避；
- 为每次请求设置明确 timeout；
- 区分 transport failure、daemon `ok=false` 和 action `exit_code`；
- 不对已经发送但响应未知的请求进行无条件重试。

当前协议没有幂等键或服务端去重。重试可能导致重复扫描、重复审计记录或重复通知。

### 7.4 Shutdown

daemon 已处理 `SIGTERM` 和 `SIGINT`，停止接收新连接、等待活动请求 drain、停止 background
jobs，并删除自己持有的 socket。

Pod 的 termination grace period 必须覆盖：

- daemon request drain；
- Prompt preload 子进程终止；
- Skill Ledger worker 终止；
- volume 和日志 flush。

源码依据：

- [daemon signal and shutdown handling](../../agent-sec-cli/src/agent_sec_cli/daemon/server.py)
- [Prompt preload child termination](../../agent-sec-cli/src/agent_sec_cli/daemon/jobs/prompt_preload.py)
- [Skill Ledger worker termination](../../agent-sec-cli/src/agent_sec_cli/daemon/jobs/skill_ledger/worker_client.py)

### 7.5 当前协议和容量默认值

| 项目 | 当前默认值 |
| --- | --- |
| 单请求最大尺寸 | 4 MiB |
| 单响应最大尺寸 | 4 MiB |
| 最大活动连接数 | 64 |
| 请求 frame 读取 timeout | 5000 ms |
| 通用 client/method timeout | 5000 ms |
| `scan-prompt` method timeout | 30000 ms |
| 最大允许请求 timeout | 300000 ms |

超过活动连接限制时 daemon 返回 `busy`。调用方 timeout 不应短于目标 method 的正常执行时间。
多副本部署前必须针对目标并发量执行容量测试。

## 8. Runtime 与持久数据分离

socket volume 只用于进程间通信，不应同时承担所有持久数据存储。

| 数据 | 推荐存储 | 生命周期和要求 |
| --- | --- | --- |
| `daemon.sock`、`daemon.lock` | 每 Pod 独立 `emptyDir` | 随 Pod 删除 |
| Prompt 模型 | image layer 或模型缓存 volume | 根据分发策略决定 |
| daemon/security/observability JSONL | stdout/采集系统或专用数据 volume | 需要跨 Pod 汇聚 |
| Security Events SQLite | 每 Pod 本地数据 volume | 不与其他 replica 共享同一 SQLite |
| Observability SQLite | 每 Pod 本地数据 volume | 不与其他 replica 共享同一 SQLite |
| Skill Ledger config | 持久化 `XDG_CONFIG_HOME` | 需要稳定配置 |
| Skill Ledger key/data | 持久化 `XDG_DATA_HOME` | 密钥不得随 Pod 无意轮换 |
| 被扫描 Skill 目录 | caller 与 daemon 的共享业务 volume | daemon 必须看到兼容的绝对路径 |

### 8.1 Security Events 和 Observability

Security Events 和 Observability 数据路径由 `AGENT_SEC_DATA_DIR` 控制。容器部署必须显式设置
该变量，避免依赖 `/var/log`、容器 home 或 `/tmp` fallback。

如果事件由 caller container 写入，而查询由 daemon 执行，则 caller 与 daemon 必须挂载
同一个 Pod 本地数据目录，并使用兼容 UID。SQLite database、WAL 和 SHM 文件必须位于同一
volume。

多个 Pod replica 不得通过 RWX 网络文件系统共享同一个 SQLite database。需要全局视图时，
应将事件发送到中心化存储或日志系统；当前 daemon 查询方法只读取本地数据文件。

源码依据：

- [security data path configuration](../../agent-sec-cli/src/agent_sec_cli/security_events/config.py)
- [SQLite WAL paths](../../agent-sec-cli/src/agent_sec_cli/security_events/orm_store.py)

### 8.2 Skill Ledger

Skill Ledger background worker 会读取、扫描并可能写入请求中的 `canonicalSkillDir`。
使用该能力时必须保证：

- daemon container 能看到对应 Skill 文件；
- caller 和 daemon 对 canonical path 的解释一致；
- 需要写 activation metadata 时，daemon UID 对 Skill 目录具有预期权限；
- `XDG_CONFIG_HOME` 中的配置持久化；
- `XDG_DATA_HOME` 中的签名密钥和状态持久化；
- 多个 Pod 不会无协调地同时写同一份共享 Skill metadata。

如果多个 replica 挂载并处理同一份 Skill 根目录，必须增加单写者、外部协调或幂等并发设计；
当前 per-Pod `daemon.lock` 只限制一个 runtime 目录中的 daemon，不提供跨 Pod Skill Ledger
写入互斥。

源码依据：

- [Skill Ledger worker processing](../../agent-sec-cli/src/agent_sec_cli/daemon/jobs/skill_ledger/processor.py)
- [Skill Ledger XDG paths](../../agent-sec-cli/src/agent_sec_cli/skill_ledger/paths.py)

### 8.3 SkillFS control socket

Skill Ledger 的 SkillFS resolver 当前默认连接：

```text
/run/user/<effective-uid>/skillfs/control.sock
```

如果 SkillFS 运行在另一个 container，该 control socket 也需要通过共享 volume 暴露给
daemon，并保持有效 UID 和路径映射。该 socket 与
`AGENT_SEC_DAEMON_SOCKET` 是两个不同的 UDS。

源码依据：

- [SkillFS resolver socket](../../agent-sec-cli/src/agent_sec_cli/skill_ledger/core/live_root.py)

## 9. 安全边界

### 9.1 当前访问控制

当前 daemon 的 request validator 为 `NoopDaemonRequestValidator`：

- 没有 token、证书或 method-level caller authorization；
- request 中的 `caller` 字段是自报信息，不是已认证身份；
- server 当前没有基于 peer credentials 的 caller policy；
- UDS 文件权限和 volume 挂载范围构成主要访问控制边界；
- method registry 只限制可调用的方法集合。

源码依据：

- [request validator](../../agent-sec-cli/src/agent_sec_cli/daemon/validation.py)
- [request gateway](../../agent-sec-cli/src/agent_sec_cli/daemon/gateway.py)
- [method allowlist](../../agent-sec-cli/src/agent_sec_cli/daemon/registry.py)

因此必须：

- 只向授权 caller container 挂载 runtime volume；
- 不向同 Pod 中运行不可信代码的容器暴露 socket；
- 使用非 root UID；
- 禁止 privilege escalation；
- drop 非必要 Linux capabilities；
- 使用平台默认或更严格的 seccomp profile；
- 对只读 root filesystem 提供最小必要 writable volumes；
- 保护 Skill Ledger 密钥、Security Events 和审计日志。

如果未来增加 TCP listener，必须在开放网络入口前定义认证、授权、TLS、监听地址、Network
Policy、速率限制和审计策略。不得直接把当前无认证 NDJSON 协议绑定到 Pod 外部地址。

## 10. Caller 集成要求

### 10.1 Client 实现

Python caller 可以复用当前 `DaemonClient`。非 Python caller 必须实现同一 NDJSON
request/response contract，并遵守：

- 一连接一请求；
- UTF-8 JSON；
- request frame 使用换行结束；
- response size limit；
- connect、read 和 method timeout；
- structured error handling；
- daemon 生成的 `request_id`。

如果 caller image 不需要本地扫描能力，应提供轻量 client package，避免仅为 UDS client
安装 torch、transformers、ModelScope 等完整 daemon 依赖。

### 10.2 版本兼容

caller 和 daemon 独立发布后可能发生协议漂移。部署必须：

- 固定经过验证的 caller/daemon image 版本组合；
- 对 method、字段和 error code 执行 contract tests；
- rollout 时验证新旧版本的兼容窗口；
- 在未来协议发生不兼容变化前增加明确的版本或 capability negotiation。

Skill Ledger notify 已包含其方法级 `schemaVersion`，但 daemon 通用 request envelope
当前没有独立的协议版本字段。

## 11. 日志和可观测性

daemon 当前通过本地 JSONL diagnostic stream 记录生命周期、请求和 background job
事件。容器部署必须选择一种采集方式：

- 增加 stdout/stderr 输出并使用集群日志采集；
- 或将 JSONL 写入专用 volume，并由日志 agent 采集。

不得只写入 daemon container 的临时 root filesystem，否则 Pod 替换后日志丢失，且
`kubectl logs` 等容器日志接口可能无法看到完整诊断信息。

至少应监控：

- daemon health 和 restart count；
- Prompt preload 状态、失败和耗时；
- `busy`、timeout、transport failure；
- request latency 和 error code；
- caller 重连次数；
- model memory 和 CPU；
- Skill Ledger worker 错误；
- 每 Pod 本地数据 volume 使用量。

源码依据：

- [daemon diagnostic logging](../../agent-sec-cli/src/agent_sec_cli/daemon/logging.py)
- [diagnostic log path resolution](../../agent-sec-cli/src/agent_sec_cli/diagnostic_logging.py)

## 12. 验收标准

### 12.1 单 Pod

- [ ] daemon 和 caller 均以同一非 root 数字 UID 运行。
- [ ] daemon 能在共享 `emptyDir` 中创建 `0700` runtime 目录。
- [ ] socket mode 为 `0600`，caller 能完成 `daemon.health`。
- [ ] 未挂载 runtime volume 的容器不能访问 socket。
- [ ] caller 启动早于 daemon 时能等待并恢复。
- [ ] daemon container 重启后能清理 stale socket，caller 能重新连接。
- [ ] Pod 收到终止信号时 daemon 能完成受控 shutdown。
- [ ] read-only root filesystem 下所有必要 writable path 均已显式挂载。

### 12.2 多副本

- [ ] 至少使用两个 Pod replica 执行 E2E。
- [ ] 每个 Pod 拥有不同的 runtime `emptyDir`。
- [ ] 每个 caller 只连接本 Pod daemon。
- [ ] 所有 Pod 可以使用同一个 socket 路径字符串且互不冲突。
- [ ] 一个 Pod 的 daemon 重启不会影响其他 Pod。
- [ ] rollout 期间模型内存和下载行为符合容量设计。
- [ ] 没有使用共享 RWX PVC 存放 socket、lock 或跨 replica SQLite。

### 12.3 模型

- [ ] 已明确选择 image、init container 或 runtime download 策略。
- [ ] 冷缓存和热缓存启动均经过测试。
- [ ] ModelScope 不可达时的 readiness 和降级行为符合安全要求。
- [ ] 要求完整检测时，readiness 会等待 `prompt_scan.loaded=true`。

### 12.4 数据和 Skill Ledger

- [ ] `AGENT_SEC_DATA_DIR`、`XDG_CONFIG_HOME`、`XDG_DATA_HOME` 已显式配置。
- [ ] Skill Ledger 密钥不会因普通 Pod replacement 意外轮换。
- [ ] daemon 能访问 caller 报告的 canonical Skill 路径。
- [ ] 多 replica 访问同一 Skill 根时已有明确的单写者或协调策略。
- [ ] 需要 SkillFS 时，其 control socket 已独立挂载和验证。

### 12.5 镜像和供应链

- [ ] wheel 与 runtime image 的 Python ABI、libc 和架构兼容。
- [ ] 镜像以不可变 tag/digest 发布。
- [ ] CI 已执行双容器 smoke test、漏洞扫描和 SBOM 生成。
- [ ] caller 与 daemon 的兼容版本组合已经 contract test。

## 13. 推荐的首阶段实施范围

当前仓库已完成首阶段中的双镜像、同 Pod workload、统一 UID、显式 socket 环境变量和
UDS health probe 基础实现。后续交付仍应保持 UDS，不增加 TCP listener，并完成：

1. 将现有 Dockerfile 接入正式构建发布流水线；
2. 增加 caller 启动退避；
3. 明确生产模型分发及 readiness 策略；
4. 分离 runtime、模型、事件数据和 Skill Ledger 持久存储；
5. 增加单 Pod、双 Pod、daemon restart 和 Pod replacement E2E；
6. 增加镜像 SBOM、漏洞扫描、签名和不可变 digest 发布；
7. 根据实际 caller 能力范围补充轻量 SDK 和协议版本管理。

在 caller 只使用 `scan-prompt` 且允许每 Pod 独立加载模型时，上述工作主要属于镜像和部署
工程。若要求不同 UID、全局 Security Events 查询、共享 Skill Ledger 写入或跨 Pod 调用，
则需要额外的代码和架构改造。
