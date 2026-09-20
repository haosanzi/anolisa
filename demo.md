# AgentSecCore 演示环境 Checklist（Mac → ECS）

版本：release `agentseccore-demo-20260910.1`，资产 `20260916.1`
固定版本：AgentSecCore 0.11.1 / AgentSight 0.11.2 / Qoder CLI 1.1.48
镜像：`ghcr.io/1570005763/agentseccore-demo@sha256:3994fdfbe477ade58937f13bc76263cf174450b6f734b0aa7b462074e0424319`

> 贯穿全文的占位符：`<ECS_HOST>` = ECS 公网 IP 或 SSH 别名，`<SSH_USER>` = 登录用户。
> 若已配好 `~/.ssh/config` 别名（如下文第 3.3 步），对应值就是 `agentseccore-demo-ecs`。

---

## 阶段一：ECS 系统配置（在 ECS 上执行，建议 9/20 完成）

### 1.1 确认架构和磁盘

```bash
uname -sm
```
- [ ] 输出必须是 `Linux x86_64`（脚本硬校验，ARM 实例直接用不了）

```bash
df -h "$HOME"
```
- [ ] `$HOME` 所在分区可用空间 ≥ 10G（镜像压缩 310MB + 解压层 + 数据卷）

### 1.2 安装并启动 Docker

```bash
sudo dnf install -y docker && sudo systemctl enable --now docker   # RHEL / Alibaba Cloud Linux / CentOS
# sudo apt-get update && sudo apt-get install -y docker.io         # Ubuntu / Debian
```
包源里没有 docker 时，按官方说明装：https://docs.docker.com/engine/install/
- [ ] Docker 已安装且 `systemctl status docker` 是 running

### 1.3 让 SSH 登录用户能用 Docker

登录用户是 root 时跳过本步。

```bash
sudo usermod -aG docker "$SSH_USER"
exit          # 必须退出重登，docker 组权限才生效
```
- [ ] 重新登录后执行下面这行，无任何报错（这是脚本的硬性前置）

```bash
docker --host unix:///var/run/docker.sock info >/dev/null && echo DOCKER_OK
```
- [ ] 输出 `DOCKER_OK`

> 注意：安装脚本会 `unset DOCKER_HOST DOCKER_CONTEXT` 并强制走本机 socket，所以不要依赖环境变量或 docker context 指到别处。

### 1.4 确认 SSH 允许端口转发

演示页面靠 SSH 隧道访问，隧道建不起来脚本会直接失败。

```bash
sudo sshd -T | grep -i allowtcpforwarding
```
- [ ] 输出 `allowtcpforwarding yes`（若为 no，改成 yes 后 `sudo systemctl reload sshd`）

### 1.5 出网自检

```bash
curl -sI https://github.com | head -1
curl -sI https://ghcr.io/v2/ | head -1
```
- [ ] github.com 返回 200/301/302
- [ ] ghcr.io 返回 401（GHCR 未认证时返回 401 属正常，说明网络通）

ECS 还需能访问 Qoder 服务（登录 + 模型调用）。演示现场要真实请求模型，这一步只能在阶段三登录时验证。

- [ ] 时间同步正常（`timedatectl status` 显示 NTP synchronized: yes）——时钟偏了会导致安全事件查不到

## 阶段二：网络与安全组

- [ ] 入方向放通 **22 端口**，来源限定为你的 Mac 出口 IP（不要 0.0.0.0/0）
- [ ] **不要**放通 17396 或其他端口：容器端口只绑在 ECS 的 `127.0.0.1:17396`，通过 SSH 隧道访问，文档明确禁止改成公网监听
- [ ] ECS 有可用的公网出口（EIP / NAT 网关），否则拉不到 GitHub 和 GHCR

## 阶段三：Mac 端准备

### 3.1 建立工作目录并下载连接器（5KB，仅首次）

```bash
mkdir -p "$HOME/agentseccore-client" && cd "$HOME/agentseccore-client"
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo-20260916.1.sh \
  -o ecs-demo.sh
shasum -a 256 ecs-demo.sh
```
- [ ] 校验值等于 `4688f5122250cd2facea4513d096b3aed800b7491c8b921121cc482fa32b7506`

> 现场网络若不通 GitHub，就提前把这份脚本存好，后续所有步骤都不再需要 Mac 出网。

### 3.2 确认本机工具齐全

```bash
command -v bash curl ssh
```
- [ ] 三条路径都有输出（macOS 自带，一般无需安装）

### 3.3 配置 SSH 别名（自定义端口/密钥/跳板机时必需）

写入 `~/.ssh/config`：

```sshconfig
Host agentseccore-demo-ecs
    HostName <ECS_HOST>
    User <SSH_USER>
    Port 22
    IdentityFile ~/.ssh/agentseccore-demo
    IdentitiesOnly yes
```

```bash
chmod 600 ~/.ssh/config
```
- [ ] 密钥权限 600
- [ ] 首次连接时核对主机指纹（不要跳过）

### 3.4 连通性总检

```bash
ssh agentseccore-demo-ecs 'uname -sm; docker --host unix:///var/run/docker.sock info >/dev/null && echo DOCKER_OK'
```
- [ ] 输出 `Linux x86_64` 和 `DOCKER_OK`

## 阶段四：首次部署（Mac 执行命令，安装落在 ECS）

```bash
cd "$HOME/agentseccore-client"
bash ecs-demo.sh agentseccore-demo-ecs prepare
```

`prepare` 不登录、不请求模型，适合提前一天无人值守执行。它会：下载并校验 install.sh → 装到 ECS 的 `~/agentseccore-demo` → 拉取/复用镜像 → 启动容器 → 跑 doctor。

- [ ] 命令成功结束，无 `ERROR:` 输出
- [ ] ECS 上 `~/agentseccore-demo` 已存在，且不是符号链接

可选再确认一次：

```bash
bash ecs-demo.sh agentseccore-demo-ecs doctor
```

**镜像拉不动时走离线包**（中国区 ECS 拉 ghcr.io 常见慢或失败）：

```bash
# Mac 上下载
curl -fSL -o agentseccore-demo-linux-amd64-20260916.1.tar.gz \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/agentseccore-demo-linux-amd64-20260916.1.tar.gz
curl -fSL -O \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/SHA256SUMS-20260916.1
scp agentseccore-demo-linux-amd64-20260916.1.tar.gz SHA256SUMS-20260916.1 agentseccore-demo-ecs:~/

# ECS 上（两个文件放同一目录）
sha256sum --check --ignore-missing SHA256SUMS-20260916.1 && \
  tar -xzf agentseccore-demo-linux-amd64-20260916.1.tar.gz -C "$HOME"
cd "$HOME/agentseccore-demo" && ./demo.sh up && ./demo.sh doctor
```

## 阶段五：登录与完整预演（交接前必做）

**这一步在干什么**：交接给参与者之前，自己把整场体验完整跑一遍——登录 Qoder、让模型真实回复、触发一次"Skill 被篡改 → 调用被拦 → 扫描报风险"，再到 AgentSight 里查到这轮安全事件。全链路都出现预期结果，环境才算可交接。

**三个窗口的分工**（阶段五全程按这个分工看）：

| 窗口 | 是什么 | 在这里做什么 | 注意 |
| --- | --- | --- | --- |
| A | Mac 终端 1：SSH 隧道 + Qoder CLI | 所有对话输入：登录、发请求、选 Yes/No | 关掉 A，隧道就断，Chrome 立刻打不开 |
| B | Mac 终端 2：SSH 进 ECS 的 `~/agentseccore-demo` | 只执行 `./demo.sh tamper` / `reset` | 不要在 B 里启动 Qoder CLI |
| C | Mac Chrome | 查 AgentSight 安全事件 | 必须等 A 建好隧道后再打开 |

**先认几个名字**（后面都会出现）：

- `ledger-demo-target`：被演示保护的目标 Skill（位于容器内 `~/agentseccore-lab/.qoder/skills/ledger-demo-target`）
- `skill-ledger`：执行扫描认证的助手 Skill（它自己也会产生安全事件，注意区分）
- `pass`：文件与签名基线一致；`drifted`：文件被改过、新增内容风险尚未评估；`deny`：扫描发现风险项，拒绝
- 本轮策略是 `ask`：检测到异常时由使用者选择，**选 No = 取消这次调用**

### 5.1 打开三个窗口（顺序：A → B → C）

A（Mac 终端 1）：

```bash
cd ~/agentseccore-client && bash ecs-demo.sh agentseccore-demo-ecs
```

- [ ] 依次打印 `Local dashboard: ...`、`Keep this session open ...`，最后停在 Qoder CLI 输入框
- [ ] 若提示 `A Qoder session is already running`：先在 Mac 另开一个终端执行 `bash ecs-demo.sh agentseccore-demo-ecs reset`，再回来重跑本命令

B（Mac 终端 2）：

```bash
cd ~/agentseccore-client && bash ecs-demo.sh agentseccore-demo-ecs control
```

- [ ] 打印 `Control terminal B: use ./demo.sh tamper or ./demo.sh reset here.`，提示符位于 ECS 的 `~/agentseccore-demo`

C（Mac Chrome）：打开 `http://127.0.0.1:17396/#/security`

- [ ] 页面能打开（此时先不用查询）

### 5.2 登录 Qoder CLI（全部在窗口 A 输入）

按顺序做：

1. `/login` → 在登录方式里选 **Personal Access Token**（PAT 是 Qoder 账号令牌，不是模型供应商 API Key）
2. `/status` → 确认显示的是自己的账号
3. 发送 `不要调用工具，只回复 READY。` → 收到真实模型回复即通过
4. 发送 `/clear` 清掉这段对话

- [ ] 以上 4 步完成

> 为什么必须做：`doctor` 只检查服务可达和凭据文件存在，不证明凭据有效、模型能调通；只有这里收到真实回复才算真可用。

### 5.3 五步预演（自己扮一次/s参与者）

| 步 | 在哪做 | 做什么 | 预期 |
| --- | --- | --- | --- |
| 1 | A | 发扫描请求 | `pass` |
| 2 | A | 发调用请求 | 真实 `Skill` 调用 + `LEDGER_DEMO_OK` |
| 3 | B → A | B 篡改；A `/clear` 后重发调用请求 | `drifted` → 选 **No** |
| 4 | A | 再发一次扫描请求 | `deny`（两项风险） |
| 5 | C | 查安全事件 | 本轮 `pass → drifted → deny` 齐全 |

下面每步先看预期、再进下一步，不要跳步。

**步骤 1 —— 扫描建基线**（窗口 A 粘贴整句）：

```text
请使用 skill-ledger Skill，对 ledger-demo-target 执行快速扫描认证。目标是当前项目下的 .qoder/skills/ledger-demo-target。只执行快速扫描，不执行深度扫描。
```

- 若助手请求执行扫描命令：核对目标路径后**允许**
- [ ] 预期：目标状态 `pass`

**步骤 2 —— 正常调用**（窗口 A 粘贴整句）：

```text
请调用名为 ledger-demo-target 的 Skill，并严格按其说明执行。
```

- [ ] 预期：真实出现 `Skill` 工具调用，输出 `LEDGER_DEMO_OK`
- 没出现 `Skill` 工具调用 = 不通过：单独输入 `/clear` 后重发一次；仍失败就停下来排查

**步骤 3 —— 篡改后触发拦截**：

1. 窗口 B 执行 `./demo.sh tamper`
2. 窗口 A 单独输入 `/clear`（只发这一条）
3. 窗口 A 再粘贴一次**步骤 2**的调用请求
- [ ] 预期：出现 `drifted` 和确认提示 → 选 **No**，取消调用
- 若之后还请求 Read / Glob 等额外探查：先按 **Esc** 取消，再 `/clear`，不要批准

> `drifted` 的含义：文件已被篡改（tamper 会追加模拟攻击文本），但新增内容的风险还没重新评估——这是要演示的中间状态。

**步骤 4 —— 重扫出风险**（窗口 A 再粘贴一次**步骤 1**的扫描请求）：

- [ ] 预期：状态 `deny`，含两项风险：`prompt-override`（要求覆盖原有指令）、`prompt-secret-exfiltration`（要求外发 system prompt）

**步骤 5 —— 窗口 C 查这轮记录**：

1. 打开 **Security Events**
2. 时间选 **Last 1h**
3. **Category = skill_ledger**
4. **Verdict = All**、**Result = All**，**Session ID 清空**
5. 点 **Query**

- [ ] 按时间和目标路径找到本轮 `pass → drifted → deny`
- [ ] 点开调用前的 `check` 事件，能看到 **Session ID** 与 **Tool Call** 关联字段
- 说明：一次扫描会有多条记录（助手按 `check → scan → check` 执行），属正常；认记录时看**目标路径是不是 `ledger-demo-target`**——`skill-ledger` 是扫描助手自己，它的 `pass` 不代表目标恢复了
- [ ] 若查不到：重新点一次 **Last 1h** 再点 **Query**，让结束时间覆盖最新操作

**附加两项检查**：

- [ ] 中文粘贴正常：上面几句中文请求能原样粘贴、正常发送
- [ ] 复位后重进：窗口 B 执行 `./demo.sh reset` → 看到 `Demo restored; ...` → 窗口 A 重跑连接命令 → Chrome 刷新后仍能访问

### 5.4 交接状态

- [ ] A 已登录、停在待输入状态（若 A 会话被 reset 结束，重跑连接命令后确认登录仍在）
- [ ] B 位于 ECS 的 `~/agentseccore-demo`
- [ ] C 能查询到事件
- [ ] 当前目标状态为 `pass`（预演最后一步的 reset 已恢复；不放心就再 `./demo.sh reset` 一次）
- [ ] 确认只有一个 Qoder CLI 会话在用（多客户端连同一实例不提供独立体验）

## 阶段六：活动当天（每轮）

1. 打开 A / B / C 三个窗口，状态同上
2. 参与者按操作卡走 5 步
3. 每轮结束，B 执行复位：

```bash
./demo.sh reset
```
4. 回到 A 重跑连接命令：`bash ecs-demo.sh agentseccore-demo-ecs`（B 保持原终端，不要在 B 启动 Qoder CLI）

## 阶段七：收尾

- [ ] 在 B 执行 `./demo.sh down` 停止并删除容器（保留数据卷中的账号和历史）
- [ ] 退出所有终端

## 故障速查

| 现象 | 处理 |
| --- | --- |
| 本机 17396 被占用 | `LOCAL_PORT=17397 bash ecs-demo.sh agentseccore-demo-ecs`，Chrome 用新端口 |
| 连 A 提示 `A Qoder session is already running` | 上次会话断线后留在容器里的孤儿进程；先 `bash ecs-demo.sh agentseccore-demo-ecs reset`（或窗口 B 里 `./demo.sh reset`），再重跑连接命令 |
| `Qoder requires a real terminal` | `qoder`/`control` 必须在真实交互终端跑；无人值守用 `prepare` |
| SSH 失败或转发被拒 | 先单独验证 `ssh agentseccore-demo-ecs`，再查 sshd 的 AllowTcpForwarding |
| 下载或拉取失败 | 恢复网络后重试同一条命令；已有正确镜像时不需要访问 GHCR |
| 文件校验失败 | 不要关闭校验；用官方 release 重新下载 |
| 提示 Unsupported installation manifest | 装的是旧版交付物（如 20260909），换成 20260916.1 |
| 没出现 Skill 调用 | `/clear` 后只重试一次；直接 Read 不算通过 |
| Chrome 查不到新事件 | 重新点 `Last 1h` 再点 `Query`，让结束时间覆盖最新操作 |
| 登录失效 | 在 A 重新 `/login`；若 `demo.env` 里有 PAT 会优先生效 |
| `down` 之后想恢复 | 保留数据卷，重新 `bash ecs-demo.sh agentseccore-demo-ecs` 即可 |

## 官方材料索引

本地已下载：`./agentseccore-demo/`

- 入口页：https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1
- 工作人员准备指南：`agentseccore-demo-guide-20260916.1_zh.md`
- ECS / SSH 指南：`agentseccore-demo-ssh-guide-20260916.1_zh.md`
- 参与者操作卡：`agentseccore-demo-operation-card-20260916.1_zh.md`

