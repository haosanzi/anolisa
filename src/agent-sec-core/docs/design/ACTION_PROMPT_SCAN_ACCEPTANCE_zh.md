# action.prompt_scan daemon RPC V2 工作包验收记录

| 属性 | 值 |
| --- | --- |
| 状态 | daemon RPC integration ready；不是 distribution/release ready |
| 验收日期 | 2026-09-08 |
| 源码基线 | `main@8bf150c24482de42cf5f4be580b56d8c6bf3a376` |
| 工作包 commit | `fb4fa90c`、`1c869c5f`、`d25b6d1b`、`2b005b36`、`370331d1` |
| contract revision | 本文与 `PROMPT_SCANNER.md`（V1 参照）同一变更 |

## 1. Goal、范围和非目标

本工作包把 V1 `agent-sec-cli/crates/prompt-scanner` 的多层注入/安全检测引擎迁入 V2，并作为
唯一一个 Action 数据面方法 `action.prompt_scan` 打通 daemon RPC 全链路：由 kernel peer
credentials 构造 trusted Principal，经 `asc-daemon-handler` 的 `ActionHandler` 调用
`asc-daemon-core::PromptScanning` 端口，再委托给组合根装配的 `PromptScanService`
（`ActionRuntime<PromptScanExecutor>`）。输入输出重新映射为 V2 Action 合同
（`asc-action-types`），而不是复用 V1 命令行 JSON。

以下不属于本工作包的完成声明：`v2/apps/asc-cli` 客户端、真实 Ollama 端到端的
`standard`/`strict`/`multi_turn` 模型路径、审计记录的持久化、安全事件下发、Code Scan 与
Policy Runtime，以及 V1 `prompt-scanner` 的替代或退役——V1 crate、Python `prompt_scan.py`
backend 与 PyO3 入口原地保留不动，仅作迁移期 oracle。

## 2. Crate relationship 与 acceptance type

| crate / entrypoint | V1 relationship | acceptance type | 当前证据层级 |
| --- | --- | --- | --- |
| `asc-model-client` | greenfield loopback-only client | `GREENFIELD_CONTRACT` | crate contract + 单元测试 |
| `asc-capability-prompt-scan` engine | 直接移植 V1 检测引擎 | `PARTIAL_EQUIVALENCE` | 移植的 V1 单元测试 + executor 测试 |
| `asc-action-types` | greenfield V2 wire contract | `GREENFIELD_CONTRACT` | crate contract + schema 测试 |
| `asc-action-runtime` | greenfield 执行骨架 | `GREENFIELD_CONTRACT` | runtime contract 测试 |
| `asc-daemon-protocol` Action method | greenfield method over an existing V1 envelope | `GREENFIELD_CONTRACT` | typed wire + real UDS |
| `asc-daemon-core` Action boundary | greenfield 端口 | `GREENFIELD_CONTRACT` | handler consumer |
| `asc-daemon-handler` ActionHandler | protocol/application adapter | `ADAPTER_CONFORMANCE` | in-process router + real UDS |
| `asc-daemon` composition | partial migration | `PARTIAL_EQUIVALENCE` | 组合根装配 + 集成测试 |

直接依赖 contract 使用本基线中的 `asc-foundation-types` 与既有 daemon service/协议面。V1
命令行与 Python backend 只作为 discovery/oracle 来源，不进入 Rust runtime。

## 3. External compatibility report

- `action.prompt_scan` 是 `[TARGET V2]` 新增的唯一 Action 数据面方法，加入
  `asc-daemon-protocol` 的 closed method table；15 个 `policy.*` 方法集合零变化，也不冒充
  或修改 V1 九个 daemon method、CLI 或 V1 action response。
- 请求/响应重新映射为 V2 wire 合同，**故意与 V1 命令行 JSON 破坏兼容**：
  - 字段名统一 camelCase 且 `deny_unknown_fields`（未知字段直接 decode 失败），enum 值保持
    lower snake case。
  - 执行状态与业务结论分离：完成的扫描返回 `PromptScanOutput`（带 `verdict`），无法运行返回
    `ActionError`；不再有 V1 的 `ok`/`schema_version` 顶层信封。
  - 去掉 V1 的 per-request `engineInitMs`：daemon 在请求路径外复用已构造的 scanner，只回报
    检测流水线耗时 `scanMs`。
  - `mode`/`model` 大小写敏感：非法值返回列出合法取值的 decode 失败，不做 V1 的大小写折叠。
- `model` 字段只接受符号名（`qwen3_guard`/`warden_gen`），永不接受模型 registry 路径或 URL，
  调用方无法把扫描器指向任意模型或 endpoint；名字到已部署模型的解析是 capability 的职责。
- `source` 为调用方自报 provenance，仅用于审计关联，绝不影响授权或 verdict，且上限
  `MAX_SOURCE_BYTES = 128` 字节。
- daemon 为每个 dispatch 生成新的 UUID request ID；成功和失败 response 均只暴露有界的公共
  error contract（复用既有 10 个 error code 与 256-byte 消息上限），不新增 V1 双格式，也不暴露
  内部引擎错误。

## 4. Internal contract change record

| ID | 变更 | 原因与影响 |
| --- | --- | --- |
| PS-CR-001 | 新增 `AccessPolicy::AuthenticatedCaller` 访问策略 | 扫描是对调用方自带文本的只读咨询操作，任一 kernel 认证的本地 peer（`LocalUser` 或 `PolicyAdministrator`）即可访问；它是独立变体，不复用 Policy 管理权限，也不接受请求里的 UID/role |
| PS-CR-002 | `MethodId` 由不可反驳解构改为 `Pap`/`Action` 双分支 match | 引入 Action 数据面方法族后，dispatch 路由与 `is_authorized` 都需显式覆盖两类方法 |
| PS-CR-003 | `ActionError` 分类投影为公共 error code | 单一投影点：`InvalidInput→invalid_argument`、`DependencyUnavailable→unavailable`、`Cancelled→deadline_exceeded`、`Internal→internal`；wire 层 serde 解码失败另投影为 `invalid_request` 并复用有界消息 |
| PS-CR-004 | Action 携带 per-invocation `ExecutionContext`（deadline + cancel） | 与无上下文的 PAP dispatch 不同，长扫描要能对已离开的调用方提前退出；`DispatchCancellation` 把 transport 的 `DispatchControl` 桥接为 `CancellationSignal` |

审计边界：`ActionRuntime` 对每次调用恰好产出一条 `AuditRecord`，但组合根当前使用默认
`NullAuditSink`，记录被丢弃——尚无持久化，也不写 stderr。`log` facade 已声明但进程未安装
logger 实现。真实事件持久化留待后续工作包。

## 5. Pass/fail matrix

| ID | 验收项 | executable evidence | 结果 |
| --- | --- | --- | --- |
| PSAPI-001 | 移植的 V1 检测引擎（preprocessor/rules/scanner/verdict/detector/模型适配器） | `asc-capability-prompt-scan` 内联 `#[cfg(test)]` | PASS |
| PSAPI-002 | 引擎到 Action runtime 的翻译（请求→config、结果→output、错误分类） | `asc-capability-prompt-scan/tests/executor.rs` | PASS |
| PSAPI-003 | wire schema：默认 mode、大小写敏感、非法值、未知字段拒绝、跨字段校验 | `asc-action-types/tests/prompt_scan_schema.rs` | PASS |
| PSAPI-004 | runtime 骨架：取消、校验/执行分层、唯一审计记录 | `asc-action-runtime/tests/runtime_contract.rs` | PASS |
| PSAPI-005 | loopback-only 模型 client 约束 | `asc-model-client/tests/local_base_url_only.rs` | PASS |
| PSAPI-006 | 真实 UDS 全链路 `fast` 模式确定性判定（注入→deny、正常→pass） | `apps/asc-daemon/tests/action_protocol.rs` | PASS |
| PSAPI-007 | 授权与请求容错：非 admin 认证调用者可扫描、空 text→`invalid_argument`、未知字段→`invalid_request` | `apps/asc-daemon/tests/action_protocol.rs` | PASS |
| PSAPI-008 | `ActionError` 分类到 wire code 的投影 | `asc-daemon-handler` `action_error_classes_map_to_stable_wire_codes` | PASS |
| PSAPI-009 | 15 个 PAP 方法与 UDS 合同零回归 | `apps/asc-daemon/tests/pap_protocol.rs`、`bootstrap.rs` | PASS |
| PSAPI-010 | full workspace regression | `cargo test --workspace --locked` | PASS |
| PSAPI-011 | lint、format 和 API docs | Clippy、rustfmt、Rustdoc commands below | PASS |
| PSAPI-012 | `standard`/`strict`/`multi_turn` 真实 Ollama 端到端 | 需可达模型服务，不在本工作包范围 | NOT RUN |

可重复执行命令（从 `src/agent-sec-core/` 进入 `v2/`）：

```bash
cd v2
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps --locked
git diff --check
```

> macOS 已知项：与本工作包无关的 pre-existing 失败（`asc-daemon-service` 一处 `MetadataExt`
> 未用 import 的 clippy 告警，以及 `pap_protocol.rs` 的 `real_uds` 用例在本机 `ConnectionRefused`）
> 均已在基线 `8bf150c2` 上复现，不由本工作包引入。

## 6. Direct-consumer evidence 与限制

- `PromptScanning` 端口被 `DaemonDispatcher` 的 `ActionHandler` 消费；`action_protocol.rs` 让
  序列化字节经真实 in-process 路由，而不是只调用 Rust struct constructor。
- `PromptScanService` 在组合根装配为唯一链接检测引擎与模型 client 依赖的组件；handler 与 core
  只见 `PromptScanning` 端口，transport 层不含检测引擎。
- `fast` 模式无模型依赖、构造即就绪，其 verdict 在离线、无模型服务下确定可复现，是本工作包唯一
  可执行断言的端到端模式。
- `standard`/`strict`/`multi_turn` 的 scanner 在首次使用时惰性构建并依赖可达模型服务
  （Ollama）；无服务时该模式降级或返回 `unavailable`。这些路径代码完备且已接线，但真实模型端到端
  未在本验收执行，因此整体报 `PARTIAL_EQUIVALENCE`，不声明 V1 扫描已完整迁移。
- 审计记录当前被 `NullAuditSink` 丢弃，不得作为审计留存证据。

## 7. Rollback

回滚本工作包时撤销上述 5 个 Rust commit，并从 workspace/composition root 移除新增的
`asc-model-client`、`asc-capability-prompt-scan`、`asc-action-types`、`asc-action-runtime`
四个 crate，以及 `asc-daemon-protocol` 的 `action.prompt_scan` 方法登记与 dispatcher 的 Action
路由。V1 `prompt-scanner`、Python backend 与 PyO3 入口在整个工作包中未改动，回滚后即恢复为唯一
扫描实现，无 schema/state downgrade。若只回滚 wire 合同破坏，不得仅恢复 V1 JSON 文案：必须连同
`asc-action-types` 合同、handler 投影与相应集成 fixture 一起交付。
