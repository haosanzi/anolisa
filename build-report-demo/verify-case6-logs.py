#!/usr/bin/env python3
"""核对 Case 6 的两个落点，不打印任何一个 Token。

用法（root）：python3 verify-case6-logs.py [ROW]      # ROW 默认 /srv/br-demo
可选项：  --real TOKEN_FILE  --fake TOKEN_FILE

验收内容：
  out/debug.log        只有一行 `Authorization: Bearer <替身>`，没有真实 Token
  out/github-user.json 是 GitHub 的真实应答（有 login），且没有真实 Token
两条都过 = 请求经 Gateway 换成真实凭据后成功（HTTP 200），而命令行/日志只见替身。
"""

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("row", nargs="?", default="/srv/br-demo", help="fixture 目录")
    parser.add_argument("--real", default="/root/gh-test.token", help="真实 Token 文件")
    parser.add_argument("--fake", default="/root/gh-demo-fake.token", help="替身 Token 文件")
    args = parser.parse_args()

    row = Path(args.row)
    debug_log = row / "out" / "debug.log"
    response = row / "out" / "github-user.json"

    real = Path(args.real).read_bytes().strip()
    fake = Path(args.fake).read_bytes().strip()
    results: list[bool] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))

    check("两份 Token 非空且不同",
          bool(real) and bool(fake) and real != fake and real not in fake)

    if debug_log.is_file():
        log = debug_log.read_bytes()
        headers = [line for line in log.splitlines() if line.lower().startswith(b"authorization:")]
        check("debug.log 只有一条认证头", len(headers) == 1)
        check("debug.log 里是替身",
              headers == [b"Authorization: Bearer " + fake])
        check("debug.log 没有真实 Token", real not in log)
    else:
        check(f"debug.log 存在（{debug_log}）", False)

    if response.is_file():
        body = response.read_bytes()
        try:
            doc = json.loads(body)
        except json.JSONDecodeError:
            doc = None
        check("github-user.json 是 JSON 且有 login",
              isinstance(doc, dict) and bool(doc.get("login")),
              f"login={doc.get('login')}" if isinstance(doc, dict) else "")
        check("github-user.json 没有真实 Token", real not in body)
    else:
        check(f"github-user.json 存在（{response}）", False)

    passed = all(results)
    print("\n" + ("Case 6 通过：Gateway 换成了真实凭据，客户端只见替身。"
                  if passed else "Case 6 未通过：看上面的 FAIL。"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
