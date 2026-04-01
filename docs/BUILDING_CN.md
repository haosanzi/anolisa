# 从源码构建 ANOLISA

[English](BUILDING.md)

本指南介绍如何准备开发环境、从源码构建各组件、运行测试以及构建 RPM 包。

提供两种构建路径：

1. 快速开始：运行一个脚本自动检查/安装依赖并构建选定组件。
2. 分组件构建：手动逐一构建各模块。

## 仓库结构

```text
anolisa/
├── src/
│   ├── copilot-shell/       # AI 终端助手（Node.js / TypeScript）
│   ├── agent-sec-core/      # Agent 安全沙箱（Rust + Python）
│   ├── agentsight/          # eBPF 可观测引擎（Rust）
│   └── os-skills/           # 运维技能库（Markdown + 可选脚本）
├── scripts/
│   ├── build-all.sh         # 统一构建入口
│   └── rpm-build.sh         # 统一 RPM 构建脚本
├── tests/
│   └── run-all-tests.sh     # 统一测试入口
├── Makefile
└── docs/
```

## 环境依赖

### 依赖速查表

| 组件 | 所需工具 |
|------|----------|
| copilot-shell | Node.js >= 20、npm >= 10、make、g++ |
| agent-sec-core | Rust == 1.93.0、Python >= 3.12、uv（仅 Linux） |
| agentsight | Rust >= 1.80、clang >= 14、libbpf 头文件、内核头文件（仅 Linux） |
| os-skills | Python >= 3.12（仅可选脚本需要） |
| RPM 打包 | rpmbuild（仅 Linux） |

## 快速开始

使用统一构建脚本：

```bash
git clone https://github.com/alibaba/anolisa.git
cd anolisa

# 安装依赖 + 构建全部组件
./scripts/build-all.sh --install-deps

# 仅安装依赖
./scripts/build-all.sh --deps-only

# 仅构建指定组件
./scripts/build-all.sh --install-deps --component shell --component sec
```

### 脚本选项

| 参数 | 说明 |
|------|------|
| --install-deps | 构建前先安装依赖 |
| --deps-only | 仅安装依赖，不构建 |
| --component <名称> | 构建指定组件（可重复使用）：shell、sec、sight |
| --help | 显示帮助信息 |

### 注意事项

1. Node.js 和 Rust 建议通过上游安装器（nvm / rustup）安装，而非使用发行版软件包。
2. AgentSight 的系统依赖（clang/llvm/libbpf/内核头文件）需通过发行版包管理器安装。
3. os-skills 大部分是静态资源，无需编译。

---

## 安装 Node.js（用于 copilot-shell）

要求：Node.js >= 20、npm >= 10。

### 推荐方式：nvm

```bash
# 安装 nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc   # 或 source ~/.zshrc

# 安装并激活 Node.js 20+
nvm install 20
nvm use 20

# 验证
node -v && npm -v
```
---

## 安装 Rust（用于 agent-sec-core 和 agentsight）

要求：agent-sec-core 需要 Rust == 1.93.0；agentsight 需要 Rust >= 1.80。

### 推荐方式：rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 验证
rustc --version && cargo --version
```

> 仓库为 agent-sec-core 固定了工具链版本，使用 rustup 可以确保版本一致。

---

## 安装 Python 和 uv（用于 agent-sec-core 和 os-skills）

要求：Python >= 3.12。

```bash
# 安装 uv（二选一）
pip3 install uv
# 或
curl -LsSf https://astral.sh/uv/install.sh | sh

# 通过 uv 安装 Python 3.12
uv python install 3.12

# 验证
uv --version
uv python find 3.12
```

---

## 安装 AgentSight 系统依赖（需包管理器）

AgentSight 依赖 clang/llvm/libbpf/内核头文件来完成 eBPF 编译步骤。这些是系统级依赖，需通过包管理器安装。

### RPM 系（Fedora / RHEL / Anolis / Alinux）

```bash
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel openssl-devel perl perl-IPC-Cmd
sudo dnf install -y kernel-devel-$(uname -r)
```

### Debian / Ubuntu

```bash
sudo apt-get update -y
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev libssl-dev perl linux-headers-$(uname -r)
```

> 部分发行版没有单独的 perl-core 包，这是正常的。

### 内核要求

AgentSight 要求 Linux 内核 >= 5.10 且启用 BTF（`CONFIG_DEBUG_INFO_BTF=y`）。

---

## 版本检查

```bash
node -v
npm -v
rustc --version
cargo --version
python3 --version
uv --version
clang --version
```

---

## 分组件手动构建

### 1. copilot-shell

```bash
cd src/copilot-shell
make install
make build
npm run bundle
```

产物：

- dist/cli.js

### 2. agent-sec-core（仅 Linux）

```bash
cd src/agent-sec-core
make build-sandbox
```

产物：

- linux-sandbox/target/release/linux-sandbox

### 3. agentsight（仅 Linux）

```bash
cd src/agentsight
cargo build --release
```

产物：

- target/release/agentsight

### 4. os-skills

无需编译。技能包通过扫描 `src/os-skills` 下包含 `SKILL.md` 文件的目录来生成。

#### 安装

Copilot Shell 从以下三个搜索路径发现技能：

| 范围 | 路径 |
|------|------|
| 项目级 | `.copilot/skills/` |
| 用户级 | `~/.copilot/skills/` |
| 系统级 | `/usr/share/anolisa/skills/` |

手动部署（用户级）：

```bash
# 构建脚本会自动复制技能：
./scripts/build-all.sh --component skills

# 或手动复制：
mkdir -p ~/.copilot/skills
find src/os-skills -name 'SKILL.md' -exec sh -c \
	'cp -rp "$(dirname "$1")" ~/.copilot/skills/' _ {} \;
```

RPM 安装（系统级）：

```bash
sudo yum install anolisa-skills
# 技能将安装到 /usr/share/anolisa/skills/
```

### 验证

```bash
# Copilot Shell 列出已发现的技能
co /skills
```

---

## 运行测试

### 统一入口

```bash
./tests/run-all-tests.sh
./tests/run-all-tests.sh --filter shell
./tests/run-all-tests.sh --filter sec
./tests/run-all-tests.sh --filter sight
```

### 分组件测试

```bash
# copilot-shell
cd src/copilot-shell && npm test

# agent-sec-core
cd src/agent-sec-core
pytest tests/integration-test/ tests/unit-test/

# agentsight
cd src/agentsight && cargo test
```

---

## 构建 RPM 包

使用统一脚本：

```bash
./scripts/rpm-build.sh copilot-shell
./scripts/rpm-build.sh agent-sec-core
./scripts/rpm-build.sh anolisa-skills
./scripts/rpm-build.sh agentsight
./scripts/rpm-build.sh all
```

产物：

- scripts/rpmbuild/RPMS/<arch>/*.rpm
- scripts/rpmbuild/SRPMS/*.rpm

---

## 常见问题排查

### Node.js 版本不匹配

使用 nvm 重新激活期望版本：

```bash
source ~/.bashrc
nvm use 20
```

### Rust 工具链不匹配

```bash
rustup show
```

### AgentSight 缺少 libbpf / 头文件

按上方 AgentSight 依赖章节安装发行版软件包。

### AgentSight 运行时权限被拒绝

```bash
sudo ./target/release/agentsight --help
# 或
sudo setcap cap_bpf,cap_perfmon=ep ./target/release/agentsight
```
