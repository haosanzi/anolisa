"""Test the intent service and export a task.cedar for the enforcement teams."""

import argparse
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

from common import HERE, SHARED_ROW, check_host, cli, record, require, run


def check_intent() -> None:
    candidate = cli(
        "--timeout-ms",
        "60000",
        "intent",
        "propose-command",
        "--command",
        "cat /etc/os-release",
        "--cwd",
        "/srv",
        "--format",
        "json",
    )
    require(
        candidate.get("outcome") == "candidate",
        f"Intent preflight returned {candidate.get('outcome')}",
    )


def check_draft(cedar: str) -> None:
    require(
        "// unresolved: []" in cedar.splitlines(),
        "Intent draft has unresolved requirements",
    )
    require(
        not any(
            note in cedar
            for note in (
                "would widen authorization",
                "// RUNTIME VIEW:",
                "// LAUNCH VIEW:",
            )
        ),
        "Intent generator marked this draft unsuitable for publication",
    )
    statements = re.sub(r"(?m)^\s*//.*$", "", cedar)
    for rule in ("R2", "R4", "R5"):
        require(
            any(
                f'@id("{rule}")' in stmt and "@advice(" in stmt and "escalate" in stmt
                for stmt in statements.split(";")
            ),
            f"Missing confirmation for {rule} in generated Cedar",
        )


def generate_policy(row: Path, report: Path) -> Path:
    task = (HERE / "task.txt").read_text().replace("{workspace}", str(row))
    (report / "task.txt").write_text(task)
    draft = report / "task.cedar"
    draft.write_bytes(
        subprocess.check_output(
            [
                "agent-sec-cli",
                "--timeout-ms",
                "180000",
                "intent",
                "propose",
                "--task",
                task,
                "--format",
                "cedar",
            ],
            timeout=190,
        )
    )
    check_draft(draft.read_text())
    return draft


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="probe command intent only"
    )
    args = parser.parse_args()
    check_host()
    check_intent()
    if args.check:
        print("PASS command intent")
        return
    report = Path(tempfile.mkdtemp(prefix="br-intent-", dir="/var/tmp"))
    print(f"Run report: {report}", flush=True)
    draft = generate_policy(SHARED_ROW, report)
    print(f"Consumer input: --policy {draft}")
    record(
        report,
        "intent",
        {
            "policy_file": str(draft),
            "sha256": hashlib.sha256(draft.read_bytes()).hexdigest(),
        },
    )


if __name__ == "__main__":
    run(main)
