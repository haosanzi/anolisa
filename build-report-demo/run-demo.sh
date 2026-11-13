#!/usr/bin/env bash
# Drive one intent-generated task policy through PAP, Sandbox and ActPlane.
#
#   run-demo.sh intent    ask the daemon for a candidate from task.txt
#   run-demo.sh pap       store the unified policy and read the exact revision back
#   run-demo.sh sandbox   enforce it with linux-sandbox (R1/R2 checks)
#   run-demo.sh actplane  assign the same revision to a Scope and inspect Bindings
#   run-demo.sh all       pap + sandbox + actplane (reuses saved candidates)
#   run-demo.sh cleanup   delete the Policies this demo created
#
# Exit codes: 0 every step passed, 2 one or more consumers could not enforce.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$HERE" "${1:-all}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

D = Path(sys.argv[1]).resolve()
STAGE = sys.argv[2]
STAGES = {"intent", "pap", "sandbox", "actplane", "all", "cleanup"}
if STAGE not in STAGES:
    sys.exit("usage: run-demo.sh [intent|pap|sandbox|actplane|all|cleanup]")

CLI = os.environ.get("ASC_CLI", "agent-sec-cli")
ROW = Path(os.environ.get("ASC_ROW", "/srv/br-demo"))
E = D / "evidence"
E.mkdir(exist_ok=True)
UNIFIED = D / "policies" / "task.cedar"
ACTVIEW = D / "policies" / "actplane.cedar"
CANDIDATE = D / "policies" / "intent-task.cedar"
PAP_COPY = D / "policies" / "task-from-pap.cedar"
REF = E / "policy-ref.json"


def save(name, value):
    (E / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def run(name, args, cwd=D, stdin=subprocess.DEVNULL, timeout=120):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, check=False, stdin=stdin)
    save(name + ".json", {"argv": args, "cwd": str(cwd), "rc": result.returncode,
                          "stdout": result.stdout, "stderr": result.stderr})
    return result


def rpc(name, *args):
    result = run(name, [CLI, *args])
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed rc={result.returncode}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def pap():
    created = {}
    for name, path in (("br-unified-task", UNIFIED), ("br-actplane-view", ACTVIEW)):
        result = rpc("policy-create", "policy", "create", "--name", name, "--file", str(path))
        fetched = rpc("policy-get", "policy", "get", "--policy-id",
                      result["policyId"], "--revision", str(result["revision"]))
        text = fetched["template"]["content"]["text"]
        if text != path.read_text():
            raise RuntimeError(f"PAP revision for {name} is not byte-identical to {path.name}")
        created[name] = {"policyId": result["policyId"], "revision": result["revision"],
                         "sha256": sha(text)}
        print(f"PAP {name} revision {result['revision']} matches {path.name} "
              f"sha256={sha(text)[:16]}", flush=True)
    PAP_COPY.write_text(UNIFIED.read_text())
    save("policy-ref.json", created)
    return created


def ref():
    if not REF.is_file():
        raise RuntimeError("no policy-ref.json; run the pap stage first")
    return json.loads(REF.read_text())


def sandbox():
    pap_ref = ref()["br-unified-task"]
    if not PAP_COPY.is_file() or PAP_COPY.read_text() != UNIFIED.read_text():
        raise RuntimeError("local PAP copy is stale; rerun the pap stage")
    base = [CLI, "sandbox", "run", "--permissions", str(PAP_COPY), "--"]
    summary = {"policyId": pap_ref["policyId"], "revision": pap_ref["revision"]}

    started = run("sandbox-start", base + ["/usr/bin/bash", "-c", "printf 'sandbox-started\\n'"], ROW)
    if started.returncode or started.stdout.strip() != "sandbox-started":
        raise RuntimeError(f"sandbox refused to start: {started.stderr.strip()}")
    summary["start"] = "PASSED"
    print("sandbox start rc=0", flush=True)

    guard = ROW / "project" / "source-guard.txt"
    before = guard.read_bytes()
    denied = run("sandbox-r1", base + ["/usr/bin/bash", "-c",
                                       "printf pwned >> project/source-guard.txt"], ROW)
    unchanged = before == guard.read_bytes()
    summary["r1"] = {"rc": denied.returncode, "unchanged": unchanged}
    if denied.returncode == 0 or not unchanged:
        raise RuntimeError("R1 out-of-scope write was not blocked")
    print(f"R1 blocked rc={denied.returncode} source_unchanged={unchanged}", flush=True)

    built = run("sandbox-build", base + ["/usr/bin/bash", "scripts/build.sh", str(ROW)], ROW)
    summary["build"] = {"rc": built.returncode,
                        "created": (ROW / "releases" / "new.zip").is_file()}
    if built.returncode or not (ROW / "releases" / "new.zip").is_file():
        raise RuntimeError(f"in-scope build failed: {built.stderr.strip()}")
    print("in-scope build rc=0 releases/new.zip created", flush=True)

    wrote = run("sandbox-write", base + ["/usr/bin/bash", "-c", "printf ok > out/probe.txt"], ROW)
    summary["in_scope_write"] = {"rc": wrote.returncode,
                                 "content": (ROW / "out" / "probe.txt").read_text()
                                 if (ROW / "out" / "probe.txt").is_file() else None}
    if wrote.returncode or summary["in_scope_write"]["content"] != "ok":
        raise RuntimeError("in-scope write was not permitted")
    print("in-scope write rc=0 out/probe.txt written", flush=True)

    protected = ROW / "releases" / "previous.zip"
    keep = protected.read_bytes()
    try:
        deleted = run("sandbox-r2", base + ["/usr/bin/python3", "-c",
                      f"import os; os.unlink('{protected}'); print('deleted')"], ROW)
        summary["r2"] = {"rc": deleted.returncode, "deleted": not protected.exists()}
        print(f"R2 sandbox rc={deleted.returncode} deleted={not protected.exists()} "
              f"(delete-only deny is not expressible as an OS right)", flush=True)
    finally:
        protected.write_bytes(keep)

    candidate = run("sandbox-intent-candidate",
                    [CLI, "sandbox", "run", "--permissions", str(CANDIDATE), "--",
                     "/usr/bin/bash", "-c", "printf 'candidate-started\\n'"], ROW)
    summary["intent_candidate"] = {"rc": candidate.returncode,
                                   "stderr": candidate.stderr.strip().splitlines()[-1:] or [""]}
    print(f"intent candidate rc={candidate.returncode} "
          f"{(summary['intent_candidate']['stderr'] or [''])[0]}", flush=True)
    save("sandbox-summary.json", summary)
    return summary


def bindings_for(scope_id):
    page = rpc("binding-list", "binding", "list", "--limit", "100")
    if page["total"] > len(page["items"]):
        raise RuntimeError("Binding list exceeded one page; refusing to miss a status")
    return [b for b in page["items"] if b["spec"]["scope"]["scopeId"] == scope_id]


def apply_scope(policy_id, revision, worker, label, expected_snapshot):
    scope = rpc("scope-create", "scope", "create", "--pid", str(worker.pid),
                "--policy-id", policy_id, "--policy-revision", str(revision))
    scope_id = scope["scopeId"]
    snapshots = scope.get("policySnapshots", [])
    if [s["template"]["content"]["text"] for s in snapshots] != [expected_snapshot]:
        raise RuntimeError(f"{label}: Scope snapshot does not match the PAP revision")
    print(f"{label} scope {scope_id} snapshot MATCH", flush=True)
    deadline = time.monotonic() + 30
    items = []
    while time.monotonic() < deadline:
        items = bindings_for(scope_id)
        if items and any(b["status"]["phase"] in {"READY", "APPLY_FAILED"} for b in items):
            break
        time.sleep(0.3)
    save(f"bindings-{label}.json", items)
    phases = [b["status"] for b in items]
    labels = [b["spec"]["bindingId"] for b in items]
    for binding_id, status in zip(labels, phases):
        print(f"  binding {binding_id} {json.dumps(status, ensure_ascii=False)}", flush=True)
    return scope_id, items


def worker_argv(unlink_command):
    """Build the guarded worker command.

    ActPlane parses /proc/<pid>/mountinfo strictly and rejects the whole topology when
    any root field is not absolute; a docker nsfs netns mount is such an entry. Detach
    those mounts inside a private mount namespace so the fixture still has a clean
    topology. Returns the argv plus the mounts that had to be detached.
    """
    fields = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    detached = [f[4] for f in fields if len(f) > 4 and not f[3].startswith("/")]
    payload = f"read -r line; {unlink_command}; echo rc=$?"
    if not detached:
        return ["/usr/bin/bash", "-c", payload], detached
    detach = "; ".join(f"umount -l {mount} 2>/dev/null" for mount in detached)
    return (["/usr/bin/unshare", "-m", "--propagation", "private",
             "/usr/bin/bash", "-c", f"{detach}; {payload}"], detached)


def actplane():
    pap_ref = ref()
    protected = ROW / "releases" / "previous.zip"
    argv, detached = worker_argv(
        f"/usr/bin/python3 -c \"import os; os.unlink('{protected}')\"")
    worker = subprocess.Popen(argv, stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
    result = {"policyId": pap_ref["br-unified-task"]["policyId"],
              "revision": pap_ref["br-unified-task"]["revision"], "workerPid": worker.pid,
              "detached_mounts": detached}
    if detached:
        print(f"worker mount namespace detaches {detached} (non-absolute mountinfo root)",
              flush=True)
    try:
        unified_scope, unified_items = apply_scope(
            pap_ref["br-unified-task"]["policyId"], pap_ref["br-unified-task"]["revision"],
            worker, "unified", UNIFIED.read_text())
        result["unified"] = unified_items
        rpc("scope-delete", "scope", "delete", "--scope-id", unified_scope)

        view_scope, view_items = apply_scope(
            pap_ref["br-actplane-view"]["policyId"], pap_ref["br-actplane-view"]["revision"],
            worker, "actplane-view", ACTVIEW.read_text())
        result["actplane_view"] = view_items
        ready = bool(view_items) and all(b["status"]["phase"] == "READY" for b in view_items)
        result["enforced"] = False
        if ready:
            keep = protected.read_bytes()
            worker.stdin.write("go\n")
            worker.stdin.flush()
            output, _ = worker.communicate(timeout=60)
            kept = protected.is_file() and protected.read_bytes() == keep
            result["command_output"] = output.strip()
            result["protected_intact"] = kept
            result["enforced"] = kept and "Operation not permitted" in output
            print(f"enforced={result['enforced']} intact={kept} output={output.strip()}",
                  flush=True)
        else:
            print("no READY Binding; delete command NOT released", flush=True)
        rpc("scope-delete", "scope", "delete", "--scope-id", view_scope)
    finally:
        if worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
    save("actplane-summary.json", result)
    return result


try:
    if STAGE == "intent":
        result = run("intent", [CLI, "intent", "propose", "--task",
                                (D / "task.txt").read_text(), "--format", "cedar"], timeout=300)
        if result.returncode or not result.stdout.strip():
            raise RuntimeError(f"intent failed; keeping the previous candidate: {result.stderr.strip()}")
        CANDIDATE.write_text(result.stdout)
        print(f"intent rc=0 -> {CANDIDATE}", flush=True)
    elif STAGE == "pap":
        pap()
    elif STAGE == "sandbox":
        summary = sandbox()
        sys.exit(0 if summary.get("r1", {}).get("unchanged") else 2)
    elif STAGE == "actplane":
        result = actplane()
        sys.exit(0 if result.get("enforced") else 2)
    elif STAGE == "cleanup":
        for name, entry in ref().items():
            rpc("policy-delete", "policy", "delete", "--policy-id",
                entry["policyId"], "--revision", str(entry["revision"]))
            print(f"deleted {name} revision {entry['revision']}", flush=True)
    else:
        pap()
        summary = {"pap": "MATCH"}
        try:
            summary["sandbox"] = sandbox()
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            summary["sandbox"] = str(error)
            print(f"sandbox: {error}", file=sys.stderr, flush=True)
        try:
            summary["actplane"] = actplane()
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            summary["actplane"] = str(error)
            print(f"actplane: {error}", file=sys.stderr, flush=True)
        save("summary.json", summary)
        enforced = summary.get("actplane", {}).get("enforced") if isinstance(summary.get("actplane"), dict) else False
        sys.exit(0 if enforced else 2)
except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
PY
