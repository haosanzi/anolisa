#!/usr/bin/env bash
# 复位 build-report demo：让下一轮从干净状态开始，一次一条命令就够。
#
#   ./clean.sh                 停 cosh、删本 demo 的 Scope 与 Policy、复位 fixture
#   ./clean.sh --gateway       额外撤掉 Gateway 的凭据对并关闭 Gateway（跑过 Case 6 时用）
#   ./clean.sh --keep-cosh     不动 cosh 进程（只清授权侧对象与 fixture）
#   ./clean.sh --row DIR       fixture 目录，默认 /srv/br-demo
#   ./clean.sh --dry-run       只打印要做什么，不执行、不校验
#
# 只碰本 demo 产生的东西：进程名是 cosh 的 Scope、名字以 br- 开头的 Policy、fixture 里
# prepare.sh 会重写的那些文件，以及 Case 6 留下的替身 Token 与 CA。账号、安装模板、
# daemon drop-in、违规库都不动（违规记录是持久化审计，按 policy_id 过滤即可，见 README「审计」）。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROW=/srv/br-demo
DRY=0
KEEP_COSH=0
WITH_GATEWAY=0
FAIL=0

while (($#)); do
  case "$1" in
    --gateway)   WITH_GATEWAY=1 ;;
    --keep-cosh) KEEP_COSH=1 ;;
    --dry-run)   DRY=1 ;;
    --row)       ROW="${2:?--row 需要一个目录}"; shift ;;
    -h|--help)   sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           printf '未知参数：%s（用 --help 看用法）\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

step() { printf '\n== %s\n' "$*"; }
act()  { if ((DRY)); then printf '  [dry-run] %s\n' "$*"; else printf '  %s\n' "$*"; fi; }
ok()   { printf '  ✓ %s\n' "$*"; }
bad()  { printf '  ✗ %s\n' "$*" >&2; FAIL=1; }

asc() { agent-sec-cli "$@"; }

# 轮询到条件成立，超时返回 1。
wait_until() { # wait_until <秒> <命令...>
  local deadline=$((SECONDS + $1)); shift
  while ((SECONDS < deadline)); do
    "$@" && return 0
    sleep 0.5
  done
  "$@"
}

no_cosh() { ! pgrep -x cosh >/dev/null; }
no_demo_scope() {
  [[ "$(asc scope list 2>/dev/null | demo_scope_ids | wc -l)" == 0 ]]
}
no_demo_policy() {
  [[ "$(asc policy list 2>/dev/null | jq -r '(.items // [])[] | select(.policyName | startswith("br-")) | .policyId' | wc -l)" == 0 ]]
}
# 本 demo 的 Scope：按进程名 cosh 发现，或它的快照里引用了 br-* 策略。
demo_scope_ids() {
  jq -r '(.items // [])[]
    | select(((.selector.match.processName // "") == "cosh")
             or ([.policySnapshots[]?.policyName // ""] | any(startswith("br-"))))
    | .scopeId'
}
# Gateway Scope 必须单独核对：快照里引用 br-cosh-gateway 的 Scope 没删净时，
# 下一轮 prepare.sh --case6 会复用旧 Scope（或撞上"同 owner/selector 已有注入 Scope"）。
# 查询失败按未清空处理，避免 CLI 异常时假通过。
no_gateway_scope() {
  local list
  list=$(asc scope list 2>/dev/null) || return 1
  [[ -n "$list" ]] || return 1
  [[ "$(printf '%s' "$list" \
    | jq -r '[.items[]? | select(any(.policySnapshots[]?; .policyName == "br-cosh-gateway"))] | length')" == 0 ]]
}

command -v agent-sec-cli >/dev/null || { bad "找不到 agent-sec-cli"; exit 1; }
command -v jq            >/dev/null || { bad "找不到 jq";            exit 1; }

# ---- 1. 停 cosh：Binding 随进程退出释放，Scope 才能删干净 -----------------
step "1/6 停止 cosh"
if ((KEEP_COSH)); then
  act "跳过（--keep-cosh）；注意 max_active_bindings = 1，旧会话还在时下一轮抢不到 Binding"
elif no_cosh; then
  ok "没有运行中的 cosh"
else
  act "TERM -> $(pgrep -x cosh | tr '\n' ' ')"
  if ((!DRY)); then
    pkill -TERM -x cosh 2>/dev/null
    wait_until 10 no_cosh || { act "TERM 没退，KILL"; pkill -KILL -x cosh 2>/dev/null; wait_until 5 no_cosh; }
    if no_cosh; then ok "cosh 已退出"; else bad "cosh 仍在运行：$(pgrep -x cosh | tr '\n' ' ')"; fi
  fi
fi

# ---- 2. 删 Scope（先 Scope 后 Policy）------------------------------------
step "2/6 删除本 demo 的 Scope"
mapfile -t scopes < <(asc scope list 2>/dev/null | demo_scope_ids)
if ((${#scopes[@]} == 0)); then
  ok "没有残留 Scope"
else
  for id in "${scopes[@]}"; do
    act "scope delete --scope-id $id"
    if ((!DRY)); then
      asc scope delete --scope-id "$id" >/dev/null 2>&1 || bad "scope delete $id 返回非 0"
    fi
  done
  if ((!DRY)); then
    if wait_until 20 no_demo_scope; then ok "Scope 已清空"; else bad "Scope 仍在：$(asc scope list 2>/dev/null | demo_scope_ids | tr '\n' ' ')"; fi
  fi
fi

# ---- 3. 删 Policy（只删 br-*，别动别人的策略）-----------------------------
step "3/6 删除本 demo 的 Policy"
mapfile -t policies < <(asc policy list 2>/dev/null \
  | jq -r '(.items // [])[] | select(.policyName | startswith("br-")) | "\(.policyId) \(.revision) \(.policyName)"')
if ((${#policies[@]} == 0)); then
  ok "没有残留 Policy"
else
  for row in "${policies[@]}"; do
    read -r id rev name <<<"$row"
    act "policy delete $name ($id rev $rev)"
    if ((!DRY)); then
      asc policy delete --policy-id "$id" --revision "$rev" >/dev/null 2>&1 || bad "policy delete $name 返回非 0"
    fi
  done
  if ((!DRY)); then
    if wait_until 20 no_demo_policy; then ok "Policy 已清空"; else bad "Policy 仍在：$(asc policy list 2>/dev/null | jq -r '(.items // [])[] | select(.policyName|startswith("br-")) | .policyName' | tr '\n' ' ')"; fi
  fi
fi

# ---- 4. Gateway（可选）：撤凭据对、关 Gateway ------------------------------
step "4/6 Gateway 残留"
if ((!WITH_GATEWAY)); then
  act "跳过；跑过 Case 6 就加 --gateway（会 gateway key remove 每个 pairid，并在已启用时 disable）"
else
  mapfile -t pairs < <(asc gateway key list 2>/dev/null | jq -r '(.pairids // [])[]')
  if ((${#pairs[@]} == 0)); then
    ok "没有凭据对"
  else
    for p in "${pairs[@]}"; do
      act "gateway key remove $p"
      ((DRY)) || asc gateway key remove "$p" >/dev/null 2>&1 || bad "key remove $p 返回非 0"
    done
  fi
  enabled="$(asc gateway status 2>/dev/null | jq -r '.enabled // false')"
  if [[ "$enabled" == true ]]; then
    act "gateway disable"
    ((DRY)) || asc gateway disable >/dev/null 2>&1 || bad "gateway disable 返回非 0"
  else
    ok "Gateway 本来就关闭"
  fi
fi

# ---- 5. 清演示产生的文件（fixture 里的落点由 prepare.sh 重写，不在这里删）----
step "5/6 清理演示产物"
artifacts=(/root/gh-demo-fake.token
           "$ROW/home/gateway-ca.pem" "$ROW/home/.demo666-gh-token" "$ROW/home/.demo666-gh-auth"
           "$ROW/releases/new.zip")
# 早期版本把替身装在演示账号的真实 home 下，清掉遗留副本。
for f in /home/*/.demo666-gh-token /home/*/.demo666-gh-auth; do [[ -e $f ]] && artifacts+=("$f"); done
for f in "${artifacts[@]}"; do
  if [[ -e $f ]]; then
    act "rm -f $f"
    ((DRY)) || rm -f -- "$f"
  fi
done
((DRY)) || ok "演示产物已清（不存在的项自动跳过）"

# ---- 6. 复位 fixture 并自检 ---------------------------------------------
step "6/6 复位 fixture 并自检"
if ((DRY)); then
  act "bash $HERE/prepare.sh $ROW"
  act "然后核对：cosh 不在、Binding/Scope/Policy 为 0、无 Gateway Scope 残留、fixture 回到 stale 状态"
  printf '\n-- dry-run 结束，没有执行任何修改\n'
  exit 0
fi

bash "$HERE/prepare.sh" "$ROW" >/dev/null || bad "prepare.sh 失败"

check() { # check <描述> <命令...>
  local desc="$1"; shift
  if "$@"; then ok "$desc"; else bad "$desc"; fi
}

no_cosh        && ok "cosh 不在运行"           || { ((KEEP_COSH)) && ok "cosh 仍在运行（--keep-cosh）" || bad "cosh 仍在运行"; }
[[ "$(asc binding list 2>/dev/null | jq -r '.total // 0')" == 0 ]] \
  && ok "Binding 为 0" || { ((KEEP_COSH)) && ok "Binding 仍在（--keep-cosh 的预期）" || bad "还有 $(asc binding list 2>/dev/null | jq -r '.total // 0') 个 Binding"; }
check "Scope 为 0"  no_demo_scope
check "无 br-cosh-gateway 残留 Scope" no_gateway_scope
check "Policy 为 0" no_demo_policy

check "dist/latest.zip = stale package"    grep -qx 'stale package' "$ROW/dist/latest.zip"
check "out/build.log = stale report"       grep -qx 'stale report'  "$ROW/out/build.log"
check "out/build-report.log = stale report" grep -qx 'stale report' "$ROW/out/build-report.log"
check "config/build.json 里有 release"     grep -q '"release"'      "$ROW/config/build.json"
check "source-guard.txt 未被改"            grep -qx 'source must remain unchanged' "$ROW/project/source-guard.txt"
check "previous.zip 还在"                  test -s "$ROW/releases/previous.zip"
check "home/.zshrc 没有 demo-marker"       bash -c "! grep -q demo-marker '$ROW/home/.zshrc'"

if ((FAIL)); then
  printf '\n有步骤失败，逐条看上面的 ✗；修掉后重跑本脚本（幂等）。\n' >&2
  exit 1
fi

cat <<EOF

清理完成，可以开下一轮：
  1) 用意图生成策略并发布（README 第 2 步）
  2) 建文件保护 Scope（第 3 步）
  3) 以演示账号在 $ROW 启动 cosh（第 4 步）
  4) 按 prompt 演 Case 1–5（第 5 步）
  5) ./prepare.sh --case6 后再演 Case 6（第 6 步）

演示结束再跑一次本脚本即可。
EOF
