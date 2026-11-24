# Landlock directory and file access examples

[中文版](../../zh/agent-sec-core/landlock-file-access.md)

Use an Island TOML or Cedar policy to limit an Agent and its child processes to approved file and directory access. The launcher installs the rules in the Linux kernel before the Agent starts.

## Expected access

| Path relative to the example directory | Permissions for the Agent and its child processes |
| --- | --- |
| `input/` | Read-only. List the directory and read its files. Writes, truncation, creation, deletion and renames are denied. |
| `output/` | Read and write. List the directory and read, create, modify and delete its files. |
| `dropoff/` | Write-only. Create and modify files. Directory listing and file reads are denied. |
| `private/` | Directory listing, reading and writing are denied. |
| `unlisted/` | No grant. Directory listing, reading and writing are denied by default. |
| `config/input.json` | Read the existing file. Modification is denied. |
| `config/result.json` | Read, overwrite and truncate the existing file. Deletion requires a grant on the parent directory. |
| `config/secret.json` | Reading and writing are denied. |

## Create the example directories and files

Run this example with the Rust V2 `agent-sec-cli` from this source branch on Linux with Landlock ABI 3 or later. The example assumes a merged `/usr` installation and uses a temporary directory for all sample data. The `/usr` grant lets the shell and tools read their runtime files. The policy grants write access only to `output/`, `dropoff/` and the existing `config/result.json` file.

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

## Write the Island TOML policy

The ruleset handles reads, writes, and changes to directory entries through the ABI 3 `abi.read_write` group. Give each allowed directory or file its own `path_beneath` entry. Paths such as `private/` stay denied when neither they nor a parent directory are granted access.

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

## Write the Cedar policy

Use this version when passing a Cedar file directly or registering a Cedar Policy for a Scope. `file.read` grants directory listing and file reads. `file.write` grants write operations. Grant only `file.write` for the write-only directory.

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

For a directory, pair the exact directory path with `path/*` for its descendants. For a single file, use just its exact path. A recursive grant on a parent would also grant access to the children, so the launcher rejects a policy where a parent grant covers a narrower `forbid` for the same access.
To protect a file from deletion or replacement, also restrict directory-entry changes on its parent directory.

## Verify the restrictions

Run the following in the same host shell. The first `/bin/sh` stands in for the Agent, and the nested `/bin/sh` commands check that a child also cannot read or write under `private/`.
To verify Cedar, set `POLICY` to `$DEMO/landlock.cedar` in the first line.

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

Expect `Permission denied` for the blocked operations and `Landlock access checks passed` at the end. After verification, remove the temporary directory stored in `DEMO` from the host shell.

To use the policy with an Agent, replace the example paths with existing absolute paths and grant the runtime files and state directories it needs. For ways to launch an Agent with the policy, including Scope lookup, see the [Landlock guide](landlock.md#launch-a-program).
