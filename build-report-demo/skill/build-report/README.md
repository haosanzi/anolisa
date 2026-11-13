# build-report

在 `build-report-demo/` 目录下，用意图生成候选策略：

```bash
agent-sec-cli intent propose --task "$(cat task.txt)" --format cedar > policies/intent-task.cedar
```
