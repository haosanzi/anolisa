# 任务策略本地自测

意图组用 `intent.py` 把任务文本生成为 Cedar 策略。执行组用 `sandbox.py` 和 `sight.py` 分别验证同一份策略，两个入口都可以在意图服务关闭时运行。需要验证真实 cosh 审批交互时，再运行 `full.py`。

以下命令均从仓库根目录执行。使用装有待测组件、Python 3.9 或更新版本的 Linux 开发机。每个入口的 `--check` 只做该入口的预检，正式自测使用下一条命令。

## 一、意图服务：从任务生成策略

**准备。** 启动 agent-sec-core daemon，确保 `agent-sec-cli` 能连接 daemon。在 daemon 的启动环境中启用 `ASC_INTENT_ENABLED=true` 并配置模型凭据，修改后重启服务。[意图服务配置](../../docs/user-guide/zh/agent-sec-core/policy-cli.md)

```bash
python3 tests/task-policy/intent.py --check
python3 tests/task-policy/intent.py
```

预检为 `cat /etc/os-release` 申请权限，期望意图服务返回 `candidate`。正式运行把 [task.txt](task.txt) 交给意图服务，检查草案的未决项为空，并检查联网、写构建配置、写发布目录对应的 R2、R4、R5 是否带有 `escalate` 审批注解。成功时终端显示 **`PASS intent`**，并打印 `Consumer input: --policy .../task.cedar`。把这个文件交给执行组即可；发布和执行验证由后续入口完成。

## 二、Sandbox：验证允许、裁剪和审批

**准备。** 安装 Linux Sandbox helper，启动提供 PAP/PDP 的 daemon。使用 PAP 策略列表为空的专用开发机，因为 PDP 会合并已发布的授权。通过 `sudo` 启动脚本后，脚本默认以调用 sudo 的普通账号执行探针；要换账号，或当前已是 root，可指定 `--user 普通账号名`。[Sandbox 配置](../../docs/user-guide/zh/agent-sec-core/sandbox.md)

```bash
sudo python3 tests/task-policy/sandbox.py --check
sudo python3 tests/task-policy/sandbox.py
```

脚本向 PAP 发布仓库中的 [task.cedar](task.cedar)，再为每条命令提交固定权限申请。通过时会依次看到：

| 结果 | 验收依据 |
|---|---|
| `PASS sandbox/1` | 回执为 ALLOW，构建日志已写入，脚本内部修改 Shell 配置时遇到只读错误，配置内容完整。 |
| `PASS sandbox/2` | 申请写项目源文件得到 MODIFY；写入失败，源文件字节保持一致。 |
| `PASS sandbox/5-deny` | 写发布区得到 STEP_UP；探针关闭待审批请求，回执确认命令未启动，发布文件保留原内容。 |

## 三、AgentSight / ActPlane：验证内核拦截

**准备。** 启动 PAP daemon、AgentSight 本地 API（`127.0.0.1:7396`）和 enforcer。enforcer 需加载 `agent-file-guard` profile，并在健康接口报告支持文件读取保护、删除保护和静态挂载拓扑。[AgentSight 部署及 profile 设置](../../docs/user-guide/zh/agentsight/deployment.md)

```bash
sudo python3 tests/task-policy/sight.py --check
sudo python3 tests/task-policy/sight.py
```

脚本发布同一份 `task.cedar`，按普通用户探针的 PID 建立 Scope，等 Binding 达到 READY 后才发送操作。探针先读取普通文件、创建并删除对照文件，再尝试删除回滚包和读取模拟凭据。**`PASS actplane/3`** 表示回滚包完整且有本轮被阻断的 `unlink`；**`PASS actplane/4`** 表示凭据读取被拒且有本轮被阻断的 `read`。两条违规记录都必须匹配本轮策略和 Binding。

**两组复验同一份生成物。** 将意图步骤打印的路径赋给 `policy`，分别运行下面两条命令；跨机器时复制同一个文件。两端都会比对 PAP 回读内容与输入文件的原始字节。对照两份 `results.txt` 中 `PASS policy` 的 SHA-256，即可确认输入一致。

```bash
policy=/path/to/task.cedar
sudo python3 tests/task-policy/sandbox.py --policy "$policy"
sudo python3 tests/task-policy/sight.py --policy "$policy"
```

## 四、全流程：通过 cosh 验证真实审批

**准备。** 准备好以上三个组件、tmux 和 util-linux，在普通账号下配置 cosh 模型和 agent-sec sandbox 扩展。使用没有其他 cosh 进程且 PAP 策略列表为空的专用开发机；本轮文件保护 Scope 会匹配进程名 `cosh`。

```bash
sudo python3 tests/task-policy/full.py --check
sudo python3 tests/task-policy/full.py
```

1. 第一个终端会生成并发布本轮策略，启动 cosh，随后打印 tmux attach 命令。在第二个终端执行该命令。
2. 等第一个终端显示 Binding 为 READY、第二个终端出现 cosh 输入框，回到第一个终端按回车。脚本逐条发送任务；每次等 cosh 回复结束，再回第一个终端按回车验收。
3. 前四例分别检查构建日志可写、越界写被裁剪、回滚包禁删、模拟凭据禁读。第五例第一次发布选 **Allow once**，第二次选 **Deny**。脚本核对允许后确实发布、拒绝后命令未执行、降级操作只写报告。默认运行通过后最后一项是 `PASS 5-fallback`，第六例显示 `SKIP 6`。

**可选的第六例验证 Gateway 凭据替换。** 在运行前准备 `nft`、`agent-sec-gw` 账号、`/opt/agent-sec-gateway/current/mitmdump` 和到 GitHub 的 IPv4 HTTPS 连接。用测试 GitHub 账号创建短有效期的 fine-grained Token，运行后粘贴到隐藏输入框。若运行脚本的管理员已用 `gh` 登录测试账号，可加 `--token-source gh`。[创建一天有效的测试 Token](https://github.com/settings/personal-access-tokens/new?name=anolisa-local-selftest&expires_in=1)

```bash
sudo python3 tests/task-policy/full.py --gateway
```

该命令从头跑六例。脚本自动生成替身 Token，真实 Token 保存在 root 私有临时目录，cosh 只接收替身请求头和 CA。第六例的联网审批选 **Allow once**。出现 `PASS 6` 表示直连对照分别得到 200（真实 Token）和 401（替身），经 Gateway 使用替身得到 200 和同一账号，本轮 Scope 的包计数增加，客户端调试日志和响应均未包含真实 Token。测试结束后可在 GitHub 撤销测试 Token。

## 工作目录与失败排查

- **临时工作区**为 `/run/anolisa-task-policy`。Cedar 规则匹配绝对路径，固定目录让不同机器可以直接消费同一文件。脚本创建并清理本轮工作区；路径已存在时会停止，保留现有内容。在一台机器上顺序运行 Sandbox、ActPlane 和全流程测试。
- **报告**保存在启动时打印的 `Run report` 目录。意图报告位于 `/var/tmp/anolisa-intent-report-*`，执行报告位于 `/var/tmp/anolisa-task-policy-report-*`。失败返回非零状态；根据终端错误和 `results.txt` 中已有的回执或违规 ID，可以定位失败的步骤。
- **服务诊断**可用 `journalctl -u agent-sec-core -u agentsight-enforcer`。在控制终端按 Ctrl-C 后，脚本会清理本轮创建的策略、Scope、进程及凭据文件，保留报告供复查。

若要验证本地源码修改，可在支持 RPM 构建的 Linux 环境中先为相应组件编包，将本轮构建的组件及插件安装到测试机，再运行对应入口。

```bash
./scripts/rpm-build.sh agent-sec-core
./scripts/rpm-build.sh agentsight
./scripts/rpm-build.sh cosh-ng
```
