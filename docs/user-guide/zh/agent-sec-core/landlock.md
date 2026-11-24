# Landlock 内核文件约束

[English](../../en/agent-sec-core/landlock.md)

Landlock 在 Linux 内核中限制对文件和目录的访问。启动器在 Cosh 或其他目标程序启动前安装规则，
目标程序及其子进程继承这些规则。

## 运行要求

按[组件指南](index.md#安装)从源码构建 Rust V2 `agent-sec-cli`。宿主 Linux 需要
启用 Landlock ABI 3 或更高版本。启动器在宿主 namespace 中本地运行。

## 编写文件访问策略

直接启动时，`--policy` 可读取 Island 文件系统规则的 `.toml` 文件，或符合
`seccore.system` schema revision 1 的 Cedar 文本和 Cedar 源码封装。通过 Scope
启动时使用 Cedar。[目录和文件权限示例](landlock-file-access.md) 附有两种格式的
完整策略和验证命令。

## 启动目标程序

<a id="通过-scope-启动-cosh"></a>

### 通过 Scope 启动程序

启动 `agent-sec-daemon`。如使用非默认 socket，可以设置 `AGENT_SEC_DAEMON_SOCKET`，
或向 `agent-sec-cli` 传入 `--socket`。

有 Policy 管理权限的用户创建 Policy，将返回的 ID 和 revision 绑定到目标可执行文件的
规范化路径。将示例路径换成本机安装的 Cosh 或其他 CLI 的实际路径。

```bash
PROGRAM="$(realpath /path/to/program)"
agent-sec-cli policy create --name program-files --file landlock.cedar
agent-sec-cli scope create --backend landlock \
  --executable "$PROGRAM" \
  --policy-id "$POLICY_ID" --policy-revision "$POLICY_REVISION"
agent-sec-cli landlock --from-scope -- "$PROGRAM"
```

启动器同步查询匹配的 Scope。Scope 可用 `--owner-uid` 限定到指定用户。
命中后使用 Scope 保存的策略快照，规则安装成功才执行目标程序。查询失败、多个 Scope
同时命中、没有匹配的 Scope 或规则安装失败时，启动报错。安装成功会在标准错误流输出
`Landlock scope <ID> installed (policy revision <REVISION>)`。删除 Scope 后，已受限的进程树
继续执行原有规则直至退出。

服务托管时，可在服务配置中通过 `agent-sec-cli` 启动目标程序。规则覆盖经过启动器启动的进程树。

### 直接使用策略文件

```bash
agent-sec-cli landlock --policy landlock.toml -- /path/to/program
agent-sec-cli landlock --policy landlock.cedar -- /path/to/program
```

TOML 支持 Island `landlock/` 规则文件中的 `abi`、`[[ruleset]]` 的
`handled_access_fs` 和 `[[path_beneath]]` 的 `parent` 与 `allowed_access`。
使用字面绝对路径。使用 `abi.*` 权限组时，指定 `abi`（1 到 6），启动器按该值展开
权限组。Island profile、变量、网络规则、进程隔离设置和新版 `unhandled_access_fs`
字段都会报错。声明的权限无法完整安装时，目标程序不会启动。

如果 `cosh` 在 `PATH` 中，运行 `agent-sec-cli landlock --policy landlock.cedar cosh`。
也可以在命令中指定可执行文件路径。策略需要覆盖目标可执行文件、运行库和配置文件的
读取权限，以及状态目录的写入权限。Cosh 启动时会打开 `/dev/null`，需要对该设备精确
授予读写权限。按宿主配置还可能需要允许读取 `/etc/passwd` 和规范化路径下的 NSS 配置
等账户查询文件。授权路径须已存在，且使用不经过符号链接的绝对路径。
标准 I/O 支持终端、管道、套接字和 `/dev/null`。若要写入输出文件，在目标命令内部
重定向，使 Landlock 检查打开文件的操作。

由已运行的 Cosh Gateway 启动的 Runtime 需要在启动时单独安装规则。

## 文件权限边界

使用 Cedar 时，文件读取、目录枚举、写入、截断和目录项修改默认拒绝。使用 TOML 时，
规则集接管 `handled_access_fs` 和各路径授权中列出的权限。对已接管的权限，未获得
路径授权时默认拒绝。对普通文件的写入授权覆盖已有内容。
创建、删除或重命名文件需要相应目录的权限。启动器会拒绝不支持的动作和条件，以及
会覆盖更窄禁令的祖先授权。规则约束经配置的文件系统层级发起的访问。已有的硬链接或
绑定挂载可能通过另一个已授权的层级暴露同一份数据。TOML 规则集接管 `execute`
时，也会约束程序执行。元数据操作、网络和委托给 systemd 等服务的操作由宿主各自的
机制管控。
启动器设置 `no_new_privs`，后续 exec 无法获取 setuid 权限。
