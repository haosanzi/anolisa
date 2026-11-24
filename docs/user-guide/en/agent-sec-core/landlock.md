# Landlock kernel file enforcement

[中文版](../../zh/agent-sec-core/landlock.md)

Landlock restricts file and directory access in the Linux kernel.
The launcher installs the policy before starting Cosh or another program.
The program and its child processes inherit the rules.

## Requirements

Build the Rust V2 `agent-sec-cli` from source using the
[component guide](index.md#installation). The host needs active Landlock ABI 3
or later. The launcher runs locally in the host namespaces.

## Define a file access policy

For direct launches, `--policy` accepts an Island filesystem policy with a
`.toml` extension, Cedar text, or a Cedar source envelope using
`seccore.system` schema revision 1. Scope launches use Cedar.
See the [directory and file access examples](landlock-file-access.md) for
complete policies in both formats and verification commands.

## Launch a program

<a id="start-cosh-through-a-scope"></a>

### Start a program through a Scope

Start `agent-sec-daemon`. For a nondefault daemon socket, set
`AGENT_SEC_DAEMON_SOCKET` or pass `--socket` to `agent-sec-cli`.

As a Policy administrator, create a Policy and assign its returned ID and revision
to the target's canonical executable path. Replace the example path with the
installed executable for Cosh or another CLI.

```bash
PROGRAM="$(realpath /path/to/program)"
agent-sec-cli policy create --name program-files --file landlock.cedar
agent-sec-cli scope create --backend landlock \
  --executable "$PROGRAM" \
  --policy-id "$POLICY_ID" --policy-revision "$POLICY_REVISION"
agent-sec-cli landlock --from-scope -- "$PROGRAM"
```

The launcher resolves the matching Scope synchronously. Use `--owner-uid` to limit the
assignment to one user. A matching launch uses the Scope's saved policy
snapshot and starts the program after installation. Lookup errors, missing or multiple
matches, and installation failures stop the launch. Successful installation
prints `Landlock scope <ID> installed (policy revision <REVISION>)` to stderr.
A running process tree retains its rules after Scope deletion until it exits.

For managed deployments, configure the service to launch the program through
`agent-sec-cli`. Access rules apply to process trees that start through the launcher.

### Use a policy file directly

```bash
agent-sec-cli landlock --policy landlock.toml -- /path/to/program
agent-sec-cli landlock --policy landlock.cedar -- /path/to/program
```

TOML accepts the `abi`, `[[ruleset]]` with `handled_access_fs`, and
`[[path_beneath]]` with `parent` and `allowed_access` entries used by Island
`landlock/` policy files. Use literal absolute paths. Set `abi` (1 through 6)
to expand `abi.*` access groups. Island profile settings, variables, network
rules, process scoping, and the newer `unhandled_access_fs` field cause a
validation error. The launch stops if any requested restriction cannot be
installed.

If `cosh` is on your `PATH`, run `agent-sec-cli landlock --policy landlock.cedar cosh`.
You can also supply the executable path. Grant read access to the executable,
libraries and configuration the program needs, and write access to its state
directories. Cosh opens `/dev/null` during startup and needs exact read and
write grants for it. It can also need read access to account lookup files such
as `/etc/passwd` and the canonical path of the NSS configuration. Use existing
absolute grant paths without symlinks.
Use a terminal, pipe, socket, or `/dev/null` for standard I/O. Redirect output files
from within the launched command so Landlock checks the open.

When an already running Cosh Gateway launches the runtime, it must install
the policy at that launch point.

## Filesystem permissions

With Cedar, file reads, directory listing, writes, truncation, and directory-entry
changes default to deny. A TOML ruleset handles the rights in
`handled_access_fs` and in its path grants. Handled rights default to deny
without a matching path grant. A regular-file write grant covers its existing contents.
Creating, removing or renaming files requires a grant on the relevant directory.
The launcher rejects unsupported actions and conditions, and ancestor grants
that would cover a narrower forbid. The rules govern access through the
configured filesystem hierarchies. Existing hard links or bind mounts can
expose the same data through another granted hierarchy. TOML can handle
`execute` to restrict program execution. Metadata operations, networking,
and effects delegated to services such as systemd remain under the host's
own controls. The launcher sets `no_new_privs`, which prevents later exec
from acquiring setuid privileges.
