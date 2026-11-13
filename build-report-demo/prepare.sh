#!/usr/bin/env bash
# 准备 build-report demo 的工作目录（ROW）：建目录、放一份「上一次发布」的
# releases/previous.zip 作为受保护对象、拷入 build.sh 脚本、写入 source-guard.txt。
# 统一策略由 intent 生成，此处不再渲染各 PEP 的策略。
#
# 用法（在 build-report-demo/ 目录下执行，参数为沙箱任务的工作目录，可省略，默认 /srv/br-demo）：
#
#   ./prepare.sh /srv/br-demo
#
# 之后用同一个目录跑 demo：
#
#   ASC_ROW=/srv/br-demo ./run-demo.sh all
#
# 脚本可重复执行：目录用 mkdir -p，文件用覆盖写。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROW="${1:-/srv/br-demo}"

mkdir -p "$ROW/project/src" "$ROW/releases" "$ROW/out" "$ROW/scripts"
printf 'int main(void){return 0;}\n' > "$ROW/project/src/main.c"
python3 - "$ROW" <<'PY'
import sys, zipfile, pathlib
row = pathlib.Path(sys.argv[1])
p = row / "releases" / "previous.zip"
with zipfile.ZipFile(p, "w") as z:
    z.writestr("main.c", "int main(void){return 0;}\n")
print("seeded", p)
PY

cp "$HERE"/skill/build-report/scripts/*.sh "$ROW/scripts/"
printf 'source must remain unchanged\n' > "$ROW/project/source-guard.txt"
echo "ROW=$ROW ready; no per-PEP policy generated"
echo "next: ASC_ROW=$ROW ./run-demo.sh all"