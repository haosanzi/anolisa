"""Check AgentSight / ActPlane file protection on a process bound by PID."""

import json
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from common import (
    PolicyRun,
    as_account,
    await_evidence,
    cli,
    consumer_cli,
    fixture_reader,
    record,
    require,
    run,
)


def sight(endpoint: str):
    opener = build_opener(ProxyHandler({}))
    with opener.open(
        "http://127.0.0.1:7396/api/enforcement/" + endpoint, timeout=5
    ) as response:
        return json.load(response)


def check_actplane() -> None:
    health = sight("health")
    require(
        health["ready"] is True and health["backend"] == "actplane",
        "ActPlane health is not ready",
    )
    for cap in (
        "file_delete_guard",
        "file_entry_delete_protection",
        "directory_tree_delete_protection",
        "file_read_protection",
        "static_mount_topology",
    ):
        require(
            health["capabilities"].get(cap) is True,
            f"Missing {cap}; check the agent-file-guard profile",
        )


def check_violation(policy: str, binding: str, case: str, start_ns: int) -> dict:
    operation, target = (
        ("read", "deploy.env") if case == "4" else ("unlink", "previous.zip")
    )
    rows = sight("violations?limit=200")["violations"]
    for row in rows:
        if (
            row["policy_id"] == policy
            and row["binding_id"] == binding
            and row["occurred_at_ns"] >= start_ns
            and row["blocked"] is True
            and row["operation"] == operation
            and row["target"] == target
        ):
            return {
                "violation": row["event_id"],
                "operation": operation,
                "target": target,
                "blocked": True,
            }
    raise RuntimeError(
        f"Expected a new blocked {operation} of {target} for binding {binding}"
    )


def scope_for(policy: str, cleanup: ExitStack, *selector: str) -> str:
    scope = cli(
        "scope", "create", *selector, "--policy-id", policy, "--policy-revision", "1"
    )["scopeId"]
    print(f"Scope {scope} for {policy}", flush=True)
    cleanup.callback(cli, "scope", "delete", "--scope-id", scope)
    return scope


def ready(scope: str, policy: str, pid: int) -> str:
    phase = "undiscovered"
    for _ in range(30):
        for item in cli("binding", "list")["items"]:
            spec = item["spec"]
            if (
                spec["scope"]["scopeId"] != scope
                or spec["scope"]["process"]["pid"] != pid
            ):
                continue
            phase = item["status"]["phase"]
            require(
                phase != "APPLY_FAILED",
                f"Binding {spec['bindingId']} APPLY_FAILED for {scope}",
            )
            if phase == "READY":
                require(
                    spec["policy"]["policyId"] == policy
                    and spec["policy"]["revision"] == 1,
                    "Binding references a different policy revision",
                )
                return spec["bindingId"]
        time.sleep(1)
    raise RuntimeError(f"Scope {scope}, cosh PID {pid}: last binding phase {phase}")


ACTPLANE_PROBE = """
import errno
import sys
from pathlib import Path

if sys.stdin.readline() != "ready\\n":
    sys.exit(2)
if not Path("project/source-guard.txt").read_bytes():
    sys.exit("Failed to read control file")
control = Path("releases/control")
control.touch(exist_ok=False)
control.unlink()
for operation in (Path("releases/previous.zip").unlink, Path("project/deploy.env").read_bytes):
    try:
        operation()
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise
    else:
        sys.exit("Expected the protected fixture operation to be denied")
"""


def start_actplane(row: Path, account) -> subprocess.Popen:
    # The ordinary user's probe waits for its exact PID binding to become READY.
    return subprocess.Popen(
        [sys.executable, "-I", "-c", ACTPLANE_PROBE],
        stdin=subprocess.PIPE,
        **as_account(account, row),
    )


def preflight():
    cli("scope", "list", "--limit", "1")
    check_actplane()


def exercise(work: PolicyRun, cleanup):
    with start_actplane(work.row, work.account) as process:
        try:
            scope = scope_for(work.policy, cleanup, "--pid", str(process.pid))
            binding = ready(scope, work.policy, process.pid)
            start = time.time_ns()
            process.communicate(input=b"ready\n", timeout=15)
            require(
                process.returncode == 0, f"ActPlane probe exited {process.returncode}"
            )
            read = fixture_reader(work.row, work.account)
            for case in ("3", "4"):
                evidence = await_evidence(
                    check_violation, work.policy, binding, case, start
                )
                require(
                    read("releases/previous.zip") == work.previous,
                    "Rollback package changed",
                )
                record(
                    work.report, f"actplane/{case}", {"binding": binding, **evidence}
                )
        finally:
            if process.poll() is None:
                process.kill()


def main():
    consumer_cli(__doc__, preflight, exercise)


if __name__ == "__main__":
    run(main)
