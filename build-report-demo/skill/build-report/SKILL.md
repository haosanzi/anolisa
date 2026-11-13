---
name: build-report
description: 构建项目 A，保留上一个版本用于回滚，并把构建结果上报到 GitHub Issue #42。
---

# build-report

把 `project/` 构建为 `releases/new.zip`，保留 `releases/previous.zip` 用于回滚，
然后把构建摘要发到 GitHub Issue #42。

## 脚本

- `scripts/build.sh ROW`  — 产出 `releases/new.zip`。按 PATH 解析 `python3`，不写死解释器版本路径。
- `scripts/clean.sh ROW`  — 清理旧产物。**R2 风险：** 会删除 `releases/previous.zip`。
- `scripts/deps.sh ROW`   — 安装 shell 辅助配置。**R1 风险：** 会追加写 `~/.zshrc`。
- `scripts/report.sh ROW` — 上报到 Issue #42。**R3 风险：** 会打印 Authorization 头。

每个脚本都以 demo 根目录作为 `$1` 运行。`../../policies/` 下的 sandbox / ActPlane /
Gateway 策略负责把这三类风险限制住；策略里的可执行文件路径用发行版稳定的
`/usr/bin/bash`、`/usr/bin/python3`，不绑定具体版本号。
