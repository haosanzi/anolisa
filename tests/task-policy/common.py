"""Shared PAP publication, fixtures and reporting for the local task-policy tests."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED_ROW = Path("/run/anolisa-task-policy")
SHELL_CONFIG = b"# build-report self-test shell configuration\n"
SOURCE = b"source must remain unchanged\n"


def require(ok, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def cli(*args: str):
    raw = subprocess.check_output(["agent-sec-cli", *args], timeout=70)
    return json.loads(raw)


def check_host() -> None:
    require(
        sys.platform.startswith("linux"),
        "Use a Linux host with the installed test components",
    )
    require(shutil.which("agent-sec-cli"), "Missing executable: agent-sec-cli")


def test_account(user: str | None):
    require(
        os.geteuid() == 0,
        "Use sudo to administer PAP and launch the test as an unprivileged account",
    )
    require(user, "Pass --user NAME when running directly as root")
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise RuntimeError(
            f"Missing test account {user!r}; select one with --user"
        ) from exc
    require(account.pw_uid > 0, "Select a non-root test account")
    return account


def as_account(account, row: Path) -> dict:
    return {
        "cwd": row,
        "user": account.pw_uid,
        "group": account.pw_gid,
        "extra_groups": os.getgrouplist(account.pw_name, account.pw_gid),
        "env": {"PATH": os.defpath, "LC_ALL": "C", "HOME": account.pw_dir},
    }


def fixture(row: Path, account) -> bytes:
    files = {
        "home/.zshrc": SHELL_CONFIG,
        "project/source-guard.txt": SOURCE,
        "project/deploy.env": b"# simulated credential fixture\n",
        "dist/latest.zip": b"stale package\n",
        "config/build.json": b'{"target":"release"}\n',
        "out/build.log": b"stale report\n",
        "out/build-report.log": b"stale report\n",
        "out/debug.log": b"",
        "out/github-user.json": b"{}",
        "out/http-status": b"",
        "scripts/build-with-setup.sh": (
            f"#!/usr/bin/env bash\nprintf 'build ok\\n'\nprintf 'config-change\\n' >> {row}/home/.zshrc\n"
            'echo "zshrc-update rc=$?" >&2\n'
        ).encode(),
    }
    for name, content in files.items():
        path = row / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
    (row / "scripts/build-with-setup.sh").chmod(0o700)
    previous = row / "releases/previous.zip"
    previous.parent.mkdir()
    with zipfile.ZipFile(previous, "w") as archive:
        archive.writestr("build.txt", "previous build\n")
    original = previous.read_bytes()
    for path in row.rglob("*"):
        os.chown(path, account.pw_uid, account.pw_gid)
    # Root owns the workspace until all client fixtures have been provisioned.
    return original


def fixture_reader(row, account):
    def read(relative: str) -> bytes:
        # Read as the fixture owner even if a tool replaced a file with a symlink.
        data = subprocess.check_output(
            ["/usr/bin/head", "-c", "1048577", row / relative],
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=[],
            timeout=5,
        )
        require(len(data) <= 1048576, f"Unexpected fixture size: {relative}")
        return data

    return read


def publish(path: Path, name: str, cleanup: ExitStack, *extra: str) -> str:
    result = cli("policy", "create", "--name", name, "--file", str(path), *extra)
    policy = result["policyId"]
    print(f"PAP {name}: {policy} revision 1", flush=True)
    cleanup.callback(delete_policy, policy)
    published = cli("policy", "get", "--policy-id", policy, "--revision", "1")
    require(
        published["template"]["content"]["text"].encode("utf-8") == path.read_bytes(),
        "PAP revision differs from its source",
    )
    return policy


def delete_policy(policy: str) -> None:
    # Scope deletion queues Binding teardown, which can briefly pin the revision.
    for attempt in range(15):
        try:
            cli("policy", "delete", "--policy-id", policy, "--revision", "1")
            return
        except subprocess.CalledProcessError:
            if attempt == 14:
                raise
            time.sleep(1)


def record(report, case, evidence):
    print(f"PASS {case}", flush=True)
    with (report / "results.txt").open("a") as results:
        results.write(f"PASS {case} {json.dumps(evidence)}\n")


def await_evidence(check, *args):
    for attempt in range(6):
        try:
            return check(*args)
        except RuntimeError:
            if attempt == 5:
                raise
            time.sleep(1)


@contextmanager
def local_run():
    with open("/run/anolisa-task-policy.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report = Path(
            tempfile.mkdtemp(prefix="anolisa-task-policy-report-", dir="/var/tmp")
        )
        print(f"Run report: {report}", flush=True)
        try:
            with ExitStack() as cleanup:
                yield report, cleanup
        except BaseException as error:
            with (report / "results.txt").open("a") as results:
                results.write(f"FAIL {error}\n")
            raise


@dataclass
class PolicyRun:
    row: Path
    account: pwd.struct_passwd
    report: Path
    policy: str
    previous: bytes


def create_workspace(cleanup: ExitStack) -> Path:
    row = SHARED_ROW
    # The shared Cedar embeds absolute paths. Only remove a workspace we created.
    try:
        row.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise RuntimeError(
            f"{row} already exists; use a host where this fixture path is free"
        ) from exc
    cleanup.callback(shutil.rmtree, row)
    return row


def prepare_consumer(args, account, report, cleanup) -> PolicyRun:
    row = create_workspace(cleanup)
    previous = fixture(row, account)
    row.chmod(0o755)
    draft = report / "task.cedar"
    draft.write_bytes(args.policy.read_bytes())
    digest = hashlib.sha256(draft.read_bytes()).hexdigest()
    policy = publish(draft, report.name, cleanup)
    record(report, "policy", {"policy": policy, "revision": 1, "sha256": digest})
    print(f"Using {args.policy} (SHA-256 {digest})", flush=True)
    return PolicyRun(row, account, report, policy, previous)


def consumer_cli(description, preflight, exercise):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--check", action="store_true", help="check this component's prerequisites"
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("SUDO_USER"),
        help="non-root probe account (default: sudo caller)",
    )
    parser.add_argument(
        "--policy", type=Path, default=HERE / "task.cedar", help="shared task policy"
    )
    args = parser.parse_args()
    check_host()
    account = test_account(args.user)
    require(args.policy.is_file(), f"Missing policy file: {args.policy}")
    preflight()
    if args.check:
        print("PASS prerequisites")
        return
    with local_run() as (report, cleanup):
        exercise(prepare_consumer(args, account, report, cleanup), cleanup)


def run(function, *args):
    os.umask(0o077)
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        function(*args)
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.SubprocessError,
        EOFError,
        KeyboardInterrupt,
    ) as exc:
        sys.exit(f"FAIL {exc or 'run interrupted'}")
