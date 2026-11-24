//! Exercises the standalone Landlock launcher and its file access restrictions.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CLI: &str = env!("CARGO_BIN_EXE_agent-sec-cli");
const PYTHON: &str = "/usr/bin/python3";
const READ: &str = r#"action == SecCore::Action::"file.read""#;
const WRITE: &str = r#"action == SecCore::Action::"file.write""#;
const READ_WRITE: &str =
    r#"action in [SecCore::Action::"file.read", SecCore::Action::"file.write"]"#;

fn tree(path: &Path) -> String {
    format!(
        "(resource.path == \"{}\" || resource.path like \"{}/*\")",
        path.display(),
        path.display()
    )
}

fn file(path: &Path) -> String {
    format!("resource.path == \"{}\"", path.display())
}

fn statement(effect: &str, action: &str, clause: &str, condition: &str) -> String {
    format!(
        "{effect}(principal, {action}, resource is SecCore::File) {clause} {{ {condition} }};\n"
    )
}

fn launch(policy: &Path) -> Command {
    let mut cli = Command::new(CLI);
    cli.arg("landlock").arg("--policy").arg(policy);
    cli.stdin(Stdio::null());
    cli
}

fn verify_rejection(cli: &mut Command, expected: &str) {
    let output = cli
        .args(["--", "/bin/sh", "-c", "echo TARGET_STARTED"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "expected {expected}: {stderr}");
}

#[test]
fn rejects_unrepresentable_policies_before_start() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = tmp.path().join("task.cedar");
    let parent = tmp.path().join("work");
    let child = parent.join("secret");
    for (action, denied) in [(READ, tree(&child)), (WRITE, file(&child))] {
        fs::write(
            &policy,
            statement("permit", action, "when", &tree(&parent))
                + &statement("forbid", action, "when", &denied),
        )
        .unwrap();
        verify_rejection(&mut launch(&policy), "would cover forbidden path");
    }

    fs::write(
        &policy,
        r#"forbid(principal, action == SecCore::Action::"network.use", resource);"#,
    )
    .unwrap();
    verify_rejection(&mut launch(&policy), "unsupported Landlock action");

    for (action, condition, diagnostic) in [
        (
            WRITE,
            r#"context.input.operation == SecCore::WriteOperation::"delete""#,
            "expected a literal file path",
        ),
        (
            READ,
            "resource.path like \"/work/*\"",
            "expected a literal file path",
        ),
    ] {
        fs::write(&policy, statement("forbid", action, "when", condition)).unwrap();
        verify_rejection(&mut launch(&policy), diagnostic);
    }
}

#[test]
fn launcher_accepts_only_policy_as_permission_input() {
    verify_rejection(
        launch(Path::new("task.cedar")).args(["--runtime-read", "/usr"]),
        "unexpected argument '--runtime-read'",
    );
}

#[test]
fn island_rejects_invalid_or_unsupported_policies_before_start() {
    let temp = tempfile::tempdir().unwrap();
    let policy = temp.path().join("landlock.toml");
    for (text, diagnostic) in [
        ("abi = [", "invalid Island TOML policy"),
        ("abi = 99", "unsupported Island policy ABI"),
        ("abi = 3", "handles no filesystem access"),
        (
            "abi = 3\n[[ruleset]]\nhandled_access_net = [\"abi.all\"]",
            "unknown field `handled_access_net`",
        ),
        (
            "[[ruleset]]\nhandled_access_fs = [\"abi.all\"]",
            "requires a policy ABI",
        ),
        (
            "[[ruleset]]\nhandled_access_fs = [\"future_right\"]",
            "unsupported Island filesystem access",
        ),
        (
            "[[path_beneath]]\nparent = [\"relative\"]\nallowed_access = [\"read_file\"]",
            "expected a canonical absolute path",
        ),
        (
            "[[path_beneath]]\nparent = []\nallowed_access = [\"read_file\"]",
            "requires at least one parent",
        ),
        (
            "[[ruleset]]\nhandled_access_fs = []",
            "filesystem access list is empty",
        ),
    ] {
        fs::write(&policy, text).unwrap();
        verify_rejection(&mut launch(&policy), diagnostic);
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    policy: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for dir in [
            "read-only",
            "read-write",
            "write-only",
            "denied",
            "files",
            "otherwise-denied",
        ] {
            fs::create_dir(root.join(dir)).unwrap();
            fs::write(root.join(dir).join("entry"), "initial").unwrap();
        }
        for path in ["read-only", "read-write", "denied"] {
            fs::write(root.join("files").join(path), "initial").unwrap();
        }

        let mut cedar = statement("permit", READ, "when", &tree(Path::new("/usr")));
        cedar.push_str(&statement(
            "permit",
            WRITE,
            "when",
            &tree(&root.join("write-only")),
        ));
        for (name, effect, action) in [
            ("read-only", "permit", READ),
            ("read-write", "permit", READ_WRITE),
            ("denied", "forbid", READ_WRITE),
        ] {
            cedar.push_str(&statement(effect, action, "when", &tree(&root.join(name))));
            cedar.push_str(&statement(
                effect,
                action,
                "when",
                &file(&root.join("files").join(name)),
            ));
        }
        // Exercise the permit + global forbid with exceptions emitted by the
        // task generator for an explicit write boundary.
        cedar.push_str(&statement("permit", WRITE, "when", &tree(&root)));
        let writable = format!(
            "{} || {} || {}",
            tree(&root.join("read-write")),
            tree(&root.join("write-only")),
            file(&root.join("files/read-write"))
        );
        cedar.push_str(&statement("forbid", WRITE, "unless", &writable));
        let policy = root.join("task.json");
        fs::write(
            &policy,
            serde_json::json!({
                "language": "cedar",
                "content": {
                    "schema": {"schemaId": "seccore.system", "revision": 1},
                    "text": cedar
                }
            })
            .to_string(),
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            policy,
        }
    }

    fn island_policy(&self) -> PathBuf {
        let path = self.root.join("landlock.toml");
        let root = self.root.display();
        fs::write(
            &path,
            format!(
                r#"
abi = 3

[[ruleset]]
handled_access_fs = ["abi.all"]

[[path_beneath]]
parent = ["/usr"]
allowed_access = ["abi.read_execute"]

[[path_beneath]]
parent = ["{root}/read-only"]
allowed_access = ["read_file", "read_dir"]

[[path_beneath]]
parent = ["{root}/read-write"]
allowed_access = ["abi.read_write"]

[[path_beneath]]
parent = ["{root}/write-only"]
allowed_access = ["make_reg", "write_file", "truncate"]

[[path_beneath]]
parent = ["{root}/files/read-only"]
allowed_access = ["read_file"]

[[path_beneath]]
parent = ["{root}/files/read-write"]
allowed_access = ["read_file", "write_file", "truncate"]
"#
            ),
        )
        .unwrap();
        path
    }
}

const FILESYSTEM_PROBE: &str = r"
import errno
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
ro = root / 'read-only'
rw = root / 'read-write'
deny = root / 'denied'
files = root / 'files'

def denied(operation):
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM), error
    else:
        raise AssertionError('protected operation succeeded')

assert sorted(os.listdir(ro)) == ['entry']
assert (ro / 'entry').read_text() == 'initial'
denied(lambda: (ro / 'entry').write_text('unexpected'))
denied(lambda: os.truncate(ro / 'entry', 0))
denied(lambda: (ro / 'entry').unlink())
denied(lambda: (ro / 'entry').rename(ro / 'renamed'))
denied(lambda: (ro / 'new').touch())
denied(lambda: ro.rename(root / 'relocated'))

assert (rw / 'entry').read_text() == 'initial'
(rw / 'entry').write_text('updated')
os.truncate(rw / 'entry', 3)
(rw / 'entry').rename(rw / 'moved')
assert (rw / 'moved').read_text() == 'upd'
(rw / 'moved').unlink()
(rw / 'new').mkdir()
(rw / 'new' / 'child').write_text('allowed')

wo = root / 'write-only'
(wo / 'created').write_text('write-only')
denied(lambda: os.listdir(wo))
denied(lambda: (wo / 'created').read_text())

for path in (deny, root / 'otherwise-denied'):
    denied(lambda: os.listdir(path))
    denied(lambda: (path / 'entry').read_text())
    denied(lambda: os.truncate(path / 'entry', 0))
    denied(lambda: (path / 'entry').unlink())
    denied(lambda: (path / 'new').touch())

assert (files / 'read-only').read_text() == 'initial'
denied(lambda: (files / 'read-only').write_text('unexpected'))
denied(lambda: os.truncate(files / 'read-only', 0))
denied(lambda: (files / 'read-only').rename(files / 'renamed'))
(files / 'read-write').write_text('updated')
os.truncate(files / 'read-write', 3)
assert (files / 'read-write').read_text() == 'upd'
denied(lambda: (files / 'read-write').unlink())
denied(lambda: (files / 'denied').read_text())
denied(lambda: (files / 'denied').write_text('unexpected'))
denied(lambda: os.truncate(files / 'denied', 0))
denied(lambda: (files / 'other').touch())

child = '''
import sys
from pathlib import Path
root = Path(sys.argv[1])
assert (root / 'read-only/entry').read_text() == 'initial'
(root / 'read-write/from-child').write_text('child')
for name in ('denied/entry', 'files/denied'):
    for operation in (Path.read_text, lambda path: path.write_text('unexpected')):
        try:
            operation(root / name)
        except PermissionError:
            pass
        else:
            raise AssertionError(name)
'''
subprocess.run([sys.executable, '-I', '-c', child, str(root)], check=True)
";

#[test]
fn kernel_enforces_cedar_and_island_policies_on_files_and_descendants() {
    if std::env::var_os("ASC_TASK_LANDLOCK_INTEGRATION").is_none() {
        return;
    }
    for format in ["cedar", "toml"] {
        let fixture = Fixture::new();
        let policy = if format == "toml" {
            fixture.island_policy()
        } else {
            fixture.policy.clone()
        };
        let output = launch(&policy)
            .env("PATH", "/usr/bin:/bin")
            .args(["python3", "-I", "-c", FILESYSTEM_PROBE])
            .arg(&fixture.root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(fixture.root.join("read-write/from-child")).unwrap(),
            "child"
        );
    }
}

#[test]
fn kernel_launcher_rejects_missing_or_incompatible_island_grants() {
    if std::env::var_os("ASC_TASK_LANDLOCK_INTEGRATION").is_none() {
        return;
    }
    let fixture = Fixture::new();
    let policy = fixture.island_policy();
    let base = fs::read_to_string(&policy).unwrap();
    for (path, access, diagnostic) in [
        ("missing", "read_file", "cannot pin Landlock path"),
        (
            "files/read-only",
            "read_dir",
            "cannot fully enforce Landlock",
        ),
    ] {
        fs::write(
            &policy,
            format!(
                "{base}\n[[path_beneath]]\nparent = [\"{}/{path}\"]\nallowed_access = [\"{access}\"]\n",
                fixture.root.display(),
            ),
        )
        .unwrap();
        verify_rejection(&mut launch(&policy), diagnostic);
    }
}

#[test]
fn kernel_launcher_rejects_preopened_regular_stdio() {
    if std::env::var_os("ASC_TASK_LANDLOCK_INTEGRATION").is_none() {
        return;
    }
    let fixture = Fixture::new();
    for policy in [&fixture.policy, &fixture.island_policy()] {
        let secret = File::open(fixture.root.join("files/denied")).unwrap();
        verify_rejection(launch(policy).stdin(secret), "standard I/O must use");
    }
}

#[test]
fn kernel_launcher_drops_inherited_file_descriptors() {
    if std::env::var_os("ASC_TASK_LANDLOCK_INTEGRATION").is_none() {
        return;
    }
    let fixture = Fixture::new();
    let output = Command::new("/bin/sh")
        .args(["-c", "exec 9< \"$1\"; shift; exec \"$@\"", "prepare"])
        .arg(fixture.root.join("files/denied"))
        .args([CLI, "landlock", "--policy"])
        .arg(&fixture.policy)
        .args([
            "--",
            PYTHON,
            "-I",
            "-c",
            "import errno, os\ntry: os.fstat(9)\nexcept OSError as error: assert error.errno == errno.EBADF\nelse: raise AssertionError('inherited fd')",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn kernel_launcher_rejects_symlink_and_shared_inode_grants() {
    use std::os::unix::fs::symlink;

    if std::env::var_os("ASC_TASK_LANDLOCK_INTEGRATION").is_none() {
        return;
    }
    let fixture = Fixture::new();
    let target = fixture.root.join("files/denied");
    let link = fixture.root.join("alias");
    let policy = fixture.root.join("alias.cedar");
    fs::write(&policy, statement("permit", READ, "when", &file(&link))).unwrap();
    symlink(&target, &link).unwrap();
    verify_rejection(&mut launch(&policy), "cannot pin Landlock path");
    fs::remove_file(&link).unwrap();
    fs::hard_link(&target, &link).unwrap();
    verify_rejection(&mut launch(&policy), "multiply linked file grant");
}
