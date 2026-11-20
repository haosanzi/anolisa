# 任务策略的本地自测

[English](README.md)

这组脚本用于在 Linux 开发虚机上分别验证意图服务、Sandbox/PDP 和 AgentSight/ActPlane，交接物是一份任务策略。全流程脚本通过 cosh 串起三者，保留人工审批。用例来自 [demo666 构建报告演示](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/README.md)。

## 按组件单独运行

在仓库根目录按开发分工选择一条命令。三个入口都可以作为第一步单独运行。

| 命令 | 验证内容 | 需要的服务 |
|---|---|---|
| `python3 tests/task-policy/intent.py` | 命令意图能返回候选；任务意图为 `/srv/br-demo` 生成带三项确认规则的草案。终端给出本轮 `task.cedar` 的路径。 | CLI、已配置意图模型的 daemon |
| `sudo python3 tests/task-policy/sandbox.py` | 固定权限申请经过真实 PAP/PDP 和 Linux Sandbox。断言构建日志可写、脚本内部写配置遇到只读、越界写源文件得到 MODIFY、发布申请得到 STEP_UP 且关闭后未执行。 | CLI、daemon、Linux Sandbox helper |
| `sudo python3 tests/task-policy/sight.py` | 按 PID 绑定普通用户进程，验证对照文件可以读取和删除；回滚包禁止删除、模拟凭据禁止读取，分别有本次 Binding 的内核违规记录。 | CLI、PAP daemon、AgentSight 和 ActPlane 文件保护 |

两个消费端默认读取仓库里同一份 [task.cedar](task.cedar)，取自 demo666。意图服务可以关闭，机器上也无需 cosh、tmux 或模型密钥。使用专用 Linux 虚机、已有的普通测试账号（可加 `--user NAME`）和空闲路径 `/srv/br-demo`。策略里的绝对路径必须与 fixture 一致。每轮自行创建并清理 fixture，在同一台机器上请顺序运行两个入口。Sandbox 还要求 PAP 策略列表为空，因为 PDP 会合并已发布的授权。加 `--check` 即可只预检所选组件。

要验证意图组的新产物，把同一个文件路径传给下面两条命令。每轮都会按原始字节发布，核对 PAP 回读，并记录本轮策略 ID、revision 和文件 SHA-256。Sandbox 的 JSON 只描述单条命令申请哪些权限，由 PDP 根据统一 Cedar 裁决；ActPlane 通过 Scope 获取这份 Cedar 的 revision，执行其中的文件保护规则。

```bash
sudo python3 tests/task-policy/sandbox.py --policy /path/to/task.cedar
sudo python3 tests/task-policy/sight.py --policy /path/to/task.cedar
```

原有的交互式 `full.py` 模式仍在其临时工作目录中动态生成意图，并验证真实 cosh 的审批卡；Gateway 可在这个模式下选跑。

## 准备完整演示的机器

需要 Python 3.9 或更新版本、tmux、util-linux，以及已配置 cosh 模型和 agent-sec sandbox 扩展的普通测试账号（默认 `demo`）。使用空闲的专用机器，PAP 策略列表应为空。已发布的 permit 会影响 daemon 的授权集合，演示的文件 Scope 会匹配名为 cosh 的进程。

安装本次要测的组件。复现参考结果时使用 demo666 提交 `e9daa9223` 构建的三个组件及插件 RPM。原分支的 [RPM 准备脚本](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/rpm-cycle.sh) 包含卸载和服务变更，适用于可重建虚机。在待测源码仓库中也可逐组件编包：

```bash
./scripts/rpm-build.sh agent-sec-core
./scripts/rpm-build.sh agentsight
./scripts/rpm-build.sh cosh-ng
```

系统 daemon 的私有环境需配置可用的意图服务（`ASC_INTENT_ENABLED=true`、模型、服务地址和供应商密钥）。AgentSight 的本地 API 使用 7396 端口，enforcer 加载 `agent-file-guard` profile。systemd 配置见[原演示的准备步骤](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/README.md)。预检会实际调用一次命令意图服务。

## 从仓库根目录运行

```bash
sudo python3 tests/task-policy/full.py --check
sudo python3 tests/task-policy/full.py
sudo python3 tests/task-policy/full.py --gateway
```

第二条跑 Case 1–5，第三条另起一轮跑完整六例。更换测试账号可加 `--user NAME`。在第二个终端执行脚本打印的 tmux attach 命令。Binding 到达 READY、cosh 出现输入框后，在第一个终端回车。脚本逐条发送 prompt，每一轮等 cosh 回复结束，再回第一个终端按回车验收。

| 用例 | 通过条件 |
|---|---|
| 1 | ALLOW，构建日志已覆盖，脚本内部写 Shell 配置时报只读，配置内容保持完整 |
| 2 | MODIFY，写入失败，项目源文件与初始内容逐字节相同 |
| 3 | ALLOW，删除失败，回滚包完整，本次 Binding 有新的 blocked unlink |
| 4 | 原生读工具触发模拟凭据文件的 blocked read，该步骤的 shell 回执数为零 |
| 5 | 第一次发布选 **Allow once**，第二次选 **Deny**。第一次复制成功、删除被内核拦截；拒绝的命令未启动，后续降级命令以 ALLOW 写入报告。 |
| 6 | 联网卡选 **Allow once**。直连时真实 Token 得到 200、替身得到 401。经 Gateway 出示替身得到 200 和相同账号，该 Scope 的计数增加，客户端产物通过凭据检查。 |

## Case 6 的凭据

用测试账号创建短有效期的 fine-grained personal access token。GitHub 的 `GET /user` 无需为这种 Token 增配权限。在浏览器确认创建，再粘贴到脚本的隐藏输入框。如果运行脚本的管理员已经用 GitHub CLI 登录测试账号，可加 `--token-source gh`。[创建一天有效的测试 Token](https://github.com/settings/personal-access-tokens/new?name=anolisa-local-selftest&expires_in=1) · [GitHub 接口权限说明](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)

Case 6 还需要能通过 IPv4 HTTPS 访问 GitHub、`nft`、`agent-sec-gw` 账号和 `/opt/agent-sec-gateway/current/mitmdump`。脚本调用 `agent-sec-cli key generate-fake`，两份 Token 存在 root 私有临时目录，仅将替身请求头和 CA 交给 cosh。命令参数和策略正文中只出现路径，报告只记录断言所需的元数据。

## 查看结果与清理

第一个终端会打印 PASS、SKIP 或失败的断言，失败返回非零状态。脚本打印的 `/var/tmp/br-selftest-*` 私有目录保留本轮任务、生成的 Cedar 和逐例证据 `results.txt`。可用回执 ID 和违规 ID 对照 daemon events 与 AgentSight violations。启动或 Binding 失败时查看 `journalctl -u agent-sec-core -u agentsight-enforcer`。

正常结束或在第一个终端按 Ctrl-C，会关闭本轮 tmux 服务、删除本轮 Scope 和策略、清除 fixture 和凭据文件。如果 Gateway 由本轮启用，也会关闭。主机异常断电后，可按本轮打印的资源 ID 清理。自测结束后在 GitHub 撤销测试 Token。
