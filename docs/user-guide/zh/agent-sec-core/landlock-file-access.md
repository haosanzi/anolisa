# Landlock 目录和文件权限示例

[English](../../en/agent-sec-core/landlock-file-access.md)

用 Island TOML 或 Cedar 策略限定 Agent 及其子进程可以读写哪些目录和文件。启动器在 Agent 启动前将规则安装到 Linux 内核。

## 各路径的预期权限

| 路径（相对于示例目录） | Agent 及其子进程的权限 |
| --- | --- |
| `input/` | 只读。可列出目录、读取文件。禁止写入、截断、创建、删除和改名。 |
| `output/` | 可读写。可列出目录、读取、创建、修改和删除其中的文件。 |
| `dropoff/` | 可写、禁止读。可创建和修改文件，禁止列出目录或读取文件。 |
| `private/` | 禁止列出目录、读取和写入。 |
| `unlisted/` | 没有授权。默认禁止列出目录、读取和写入。 |
| `config/input.json` | 可以读取已有文件，禁止修改。 |
| `config/result.json` | 可以读取、覆盖和截断已有文件。删除需要父目录的权限。 |
| `config/secret.json` | 禁止读取和写入。 |

## 创建示例目录和文件

使用本分支构建的 Rust V2 `agent-sec-cli`，在启用了 Landlock ABI 3 或更高版本的 Linux 上运行。示例假定系统采用合并后的 `/usr` 目录结构，测试数据都放在临时目录里。`/usr` 的只读规则让 Shell 和工具可以读取运行所需的文件。策略只允许向 `output/`、`dropoff/` 和已有的 `config/result.json` 写入。

```bash
DEMO="$(mktemp -d /tmp/landlock-demo.XXXXXX)" || exit 1
DEMO="$(realpath "$DEMO")" || exit 1
mkdir -p "$DEMO/input" "$DEMO/output" "$DEMO/dropoff" \
  "$DEMO/private" "$DEMO/unlisted" "$DEMO/config"
printf 'example\n' | tee \
  "$DEMO/input/data.txt" "$DEMO/private/data.txt" "$DEMO/unlisted/data.txt" >/dev/null
printf '{}\n' | tee \
  "$DEMO/config/input.json" "$DEMO/config/result.json" "$DEMO/config/secret.json" >/dev/null
```

## 编写 Island TOML 策略

规则集通过 ABI 3 的 `abi.read_write` 接管读取、写入和目录项修改。用 `path_beneath` 为各目录或单个文件授权。对 `private/` 等禁止读写的路径，其本身和父目录都不授予这些权限。

```bash
cat >"$DEMO/landlock.toml" <<EOF
abi = 3

[[ruleset]]
handled_access_fs = ["abi.read_write"]

# Read runtime libraries and tools.
[[path_beneath]]
parent = ["/usr"]
allowed_access = ["read_file", "read_dir"]

# Read-only input.
[[path_beneath]]
parent = ["$DEMO/input"]
allowed_access = ["read_file", "read_dir"]

# Read and write output.
[[path_beneath]]
parent = ["$DEMO/output"]
allowed_access = ["abi.read_write"]

# Create and write files without granting reads or directory listing.
[[path_beneath]]
parent = ["$DEMO/dropoff"]
allowed_access = ["make_reg", "write_file", "truncate"]

# Grant access to individual files.
[[path_beneath]]
parent = ["$DEMO/config/input.json"]
allowed_access = ["read_file"]

[[path_beneath]]
parent = ["$DEMO/config/result.json"]
allowed_access = ["read_file", "write_file", "truncate"]

# No grants for private/, unlisted/, or config/secret.json.
EOF
```

## 编写 Cedar 策略

可以直接传入这份 Cedar 文件，也可以将它注册为 Policy，再绑定到 Scope。`file.read` 授予目录枚举和文件读取权限，`file.write` 授予写入权限。可写但禁止读的目录只授予 `file.write`。

```bash
cat >"$DEMO/landlock.cedar" <<EOF
// Runtime tools and libraries on a merged /usr host.
permit(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path == "/usr" || resource.path like "/usr/*" };

permit(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path == "$DEMO/input" || resource.path like "$DEMO/input/*" };

permit(principal, action in [SecCore::Action::"file.read", SecCore::Action::"file.write"], resource is SecCore::File)
when { resource.path == "$DEMO/output" || resource.path like "$DEMO/output/*" };

permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "$DEMO/dropoff" || resource.path like "$DEMO/dropoff/*" };

forbid(principal, action in [SecCore::Action::"file.read", SecCore::Action::"file.write"], resource is SecCore::File)
when { resource.path == "$DEMO/private" || resource.path like "$DEMO/private/*" };

permit(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path == "$DEMO/config/input.json" };

permit(principal, action in [SecCore::Action::"file.read", SecCore::Action::"file.write"], resource is SecCore::File)
when { resource.path == "$DEMO/config/result.json" };

forbid(principal, action in [SecCore::Action::"file.read", SecCore::Action::"file.write"], resource is SecCore::File)
when { resource.path == "$DEMO/config/secret.json" };
EOF
```

为目录授权时，写出目录的精确路径，再用 `路径/*` 匹配其后代。为单个文件授权时，只写文件的精确路径。父目录的递归授权也会覆盖其子目录。如果父目录的授权覆盖了更窄路径上同一权限的 `forbid`，启动器会拒绝这份策略。
如果还要阻止文件被删除或替换，需要限制其父目录的目录项修改权限。

## 验证限制是否生效

在同一个宿主 Shell 运行下面的命令。外层 `/bin/sh` 模拟 Agent，嵌套的 `/bin/sh` 用来验证子进程也无法读取或写入 `private/`。
如需验证 Cedar，将第一行的 `POLICY` 改为 `$DEMO/landlock.cedar`。

```bash
POLICY="$DEMO/landlock.toml"
cat <<'SH' | agent-sec-cli landlock --policy "$POLICY" -- /bin/sh -eu -s -- "$DEMO"
demo=$1

deny() {
    if "$@"; then
        printf 'Unexpected access: %s\n' "$*" >&2
        exit 1
    fi
}

read_line() {
    IFS= read -r line < "$1" && printf '%s\n' "$line"
}

write_line() {
    printf '%s\n' updated > "$1"
}

ls "$demo/input"
read_line "$demo/input/data.txt"
deny write_line "$demo/input/data.txt"
deny rm "$demo/input/data.txt"

write_line "$demo/output/new.txt"
read_line "$demo/output/new.txt"
rm "$demo/output/new.txt"

write_line "$demo/dropoff/new.txt"
deny ls "$demo/dropoff"
deny read_line "$demo/dropoff/new.txt"

deny ls "$demo/private"
deny read_line "$demo/private/data.txt"
deny write_line "$demo/private/data.txt"
deny /bin/sh -c 'cat "$1"' sh "$demo/private/data.txt"
deny /bin/sh -c 'printf "%s\n" updated > "$1"' sh "$demo/private/data.txt"

deny read_line "$demo/unlisted/data.txt"
deny write_line "$demo/unlisted/data.txt"

read_line "$demo/config/input.json"
deny write_line "$demo/config/input.json"
write_line "$demo/config/result.json"
read_line "$demo/config/result.json"
deny rm "$demo/config/result.json"
deny read_line "$demo/config/secret.json"
deny write_line "$demo/config/secret.json"

printf '%s\n' 'Landlock access checks passed'
SH
```

被阻止的操作应显示 `Permission denied`，最后输出 `Landlock access checks passed`。验证结束后，在宿主 Shell 中删除 `DEMO` 指向的临时目录。

应用到 Agent 时，将示例路径替换为已存在的绝对路径，并按程序的实际需求授予运行文件和状态目录的权限。直接启动和按 Scope 启动的用法见 [Landlock 使用指南](landlock.md#启动目标程序)。
