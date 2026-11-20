"""Check the PDP decision and Linux sandbox against a published task policy."""

import json
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from common import (
    SHELL_CONFIG,
    SOURCE,
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


def probe(case: str, row: Path, account) -> None:
    target, command = {
        "1": ("out/build.log", "bash scripts/build-with-setup.sh > out/build.log 2>&1"),
        "2": (
            "project/source-guard.txt",
            "printf 'source-change\\n' > project/source-guard.txt",
        ),
        "5-deny": ("dist/latest.zip", "printf 'published\\n' > dist/latest.zip"),
    }[case]
    # These are requested permissions for one invocation. PAP supplies the ceiling.
    request = {
        "version": 1,
        "filesystem": {
            "default": "deny",
            "rules": [
                {"effect": "allow", "path": "/", "rights": ["read"]},
                {"effect": "allow", "path": str(row / target), "rights": ["write"]},
            ],
        },
        "execution": {"deny_paths": []},
        "network": {"mode": "off"},
    }
    path = row / f"request-{case}.json"
    path.write_text(json.dumps(request))
    path.chmod(0o644)
    args = [shutil.which("agent-sec-cli"), "sandbox", "hook"]
    child = as_account(account, row)
    payload = {
        "session_id": row.name,
        "cwd": str(row),
        "tool_input": {"command": command},
    }
    reply = json.loads(
        subprocess.check_output(
            [*args, "prepare", "--permissions", path],
            input=json.dumps(payload).encode(),
            timeout=30,
            **child,
        )
    )
    decision = reply["decision"]
    if decision not in ("allow", "ask"):
        raise RuntimeError(
            f"Case {case} preparation: {decision}, {reply.get('reason')}"
        )
    handoff = shlex.split(reply["hookSpecificOutput"]["tool_input"]["command"])
    if (
        len(handoff) != 7
        or handoff[1] != "--socket"
        or handoff[3:6] != ["sandbox", "hook", "execute"]
    ):
        raise RuntimeError("Malformed sandbox handoff")
    hook = [args[0], "--socket", handoff[2], "sandbox", "hook"]
    expected = "ask" if case == "5-deny" else "allow"
    if decision != expected or decision == "ask":
        subprocess.run([*hook, "finish", handoff[-1]], timeout=10, check=True, **child)
        if decision != expected:
            raise RuntimeError(f"Case {case} expected {expected}, got {decision}")
        return
    result = subprocess.run(
        [*hook, "execute", handoff[-1]],
        timeout=30,
        check=False,
        stderr=subprocess.PIPE,
        **child,
    )
    expected_exit = 1 if case == "2" else 0
    if result.returncode != expected_exit:
        raise RuntimeError(
            f"Case {case} expected exit {expected_exit}, got {result.returncode}: "
            + result.stderr.decode(errors="replace")
        )
    if case == "2" and b"Read-only file system" not in result.stderr:
        raise RuntimeError(
            "Expected the sandbox to deny the project write on a read-only mount"
        )


def check_receipt(case: str, since: str, uid: int) -> dict:
    events = cli(
        "events",
        "--since",
        since,
        "--event-type",
        "authorization_receipt",
        "--include-details",
        "-o",
        "json",
    )
    receipts = [
        event
        for event in events
        if event["uid"] == uid
        and event["details"].get("principal", {}).get("agent_type") == "cosh"
    ]
    if case == "4":
        require(not receipts, "Native file read unexpectedly used the shell Hook")
        return {"shell_receipts": 0}
    verdict, approval, exit_code = {
        "1": ("ALLOW", None, 0),
        "2": ("MODIFY", None, 1),
        "3": ("ALLOW", None, 1),
        "5-allow": ("STEP_UP", True, 1),
        "5-deny": ("STEP_UP", None, None),
        "5-fallback": ("ALLOW", None, 0),
        "6": ("STEP_UP", True, 0),
    }[case]
    require(
        len(receipts) == 1,
        f"Expected one new cosh authorization receipt, found {len(receipts)}",
    )
    event = receipts[0]
    detail = event["details"]
    require(
        event["verdict"] == verdict and detail.get("approval") is approval,
        f"Expected {verdict} approval={approval}, got {event['verdict']} approval={detail.get('approval')}",
    )
    result = detail.get("result") or {}
    if case == "5-deny":
        require(
            detail.get("host_finished") is True and result.get("started") is False,
            "Denied invocation lacks a host-finished receipt proving it never started",
        )
    else:
        require(
            result.get("started") is True and result.get("exit_code") == exit_code,
            f"Expected execution with exit {exit_code}, got {result.get('exit_code')}",
        )
    return {
        "receipt": event["event_id"],
        "verdict": verdict,
        "approval": approval,
        "started": result["started"],
        "exit": result.get("exit_code"),
    }


def verify_case(case, read, previous, published):
    build = read("out/build.log")
    if case == "1":
        require(
            build.splitlines()[:1] == [b"build ok"]
            and b"Read-only file system" in build
            and b"zshrc-update rc=1" in build
            and read("home/.zshrc") == SHELL_CONFIG,
            "Expected a written build log and a read-only, unchanged shell configuration",
        )
    elif case == "2":
        require(
            read("project/source-guard.txt") == SOURCE,
            "Source changed outside the write ceiling",
        )
    elif case == "5-allow":
        require(
            read("dist/latest.zip") == build, "Approved publish did not copy the report"
        )
    elif case in ("5-deny", "5-fallback"):
        require(
            read("dist/latest.zip") == published, "Published file changed after denial"
        )
        report = b"stale report" if case == "5-deny" else b"build ok"
        require(
            read("out/build-report.log").splitlines() == [report],
            "Unexpected fallback report",
        )
    require(
        read("releases/previous.zip") == previous,
        "Rollback package was deleted or changed",
    )


def preflight():
    require(
        not cli("policy", "list", "--limit", "1")["items"],
        "Use an isolated PAP store: existing policies can affect the authorization verdicts",
    )


def exercise(work: PolicyRun, cleanup):
    read = fixture_reader(work.row, work.account)
    for case in ("1", "2", "5-deny"):
        since = datetime.now(timezone.utc).isoformat()
        probe(case, work.row, work.account)
        evidence = await_evidence(check_receipt, case, since, work.account.pw_uid)
        verify_case(case, read, work.previous, b"stale package\n")
        record(work.report, f"sandbox/{case}", evidence)


def main():
    consumer_cli(__doc__, preflight, exercise)


if __name__ == "__main__":
    run(main)
