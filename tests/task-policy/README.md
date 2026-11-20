# Local task-policy self-tests

[中文版](README_zh.md)

Use these scripts on a Linux development VM to verify the intent service, Sandbox/PDP and AgentSight/ActPlane independently against one task policy. The full demo connects the three through cosh and includes interactive approval cards. The cases come from the [demo666 build report](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/README.md).

## Run one component

From the repository root, choose the command for the component under development. Each command runs independently.

| Command | What it checks | Services needed |
|---|---|---|
| `python3 tests/task-policy/intent.py` | Command intent returns a candidate. Task intent generates a draft for `/srv/br-demo` with the three confirmation gates. Prints the path to the new `task.cedar`. | CLI, daemon with a configured intent provider |
| `sudo python3 tests/task-policy/sandbox.py` | Fixed requests exercise the real PAP/PDP and Linux sandbox handoff. The build log write succeeds, the hidden config write is read-only, the out-of-scope source write yields MODIFY, and a publish request yields STEP_UP and is closed without execution. | CLI, daemon, installed Linux sandbox helper |
| `sudo python3 tests/task-policy/sight.py` | A regular user's process bound by PID can read and unlink control files. ActPlane blocks removal of the rollback archive and reading the simulated credential, with fresh violations for this binding. | CLI, PAP daemon, AgentSight and the ActPlane file guard |

Both consumers default to the same checked-in [task.cedar](task.cedar) from demo666. They run with the intent service disabled and require no cosh session, tmux or model credentials. Use a dedicated Linux VM, an existing non-root test account (`--user NAME`), and a free `/srv/br-demo` path. The absolute paths in the policy must match the fixture. Each consumer creates and removes its own fixture. On the same VM run the two commands sequentially. Sandbox also needs an empty PAP store because PDP considers the published authorization set. Add `--check` to probe just the selected component's prerequisites.

To test another team's output, pass the exact same file to both commands. Each run publishes its bytes, checks the PAP readback and records the file's SHA-256 with its policy ID and revision. The sandbox JSON requests describe what a command asks for. The shared Cedar sets what PDP may grant. ActPlane receives that Cedar revision through its Scope and consumes the file protection rules.

```bash
sudo python3 tests/task-policy/sandbox.py --policy /path/to/task.cedar
sudo python3 tests/task-policy/sight.py --policy /path/to/task.cedar
```

The original guided `full.py` mode still generates intent dynamically for its own temporary workspace and tests the approval cards in cosh. Gateway remains optional there.

## Prepare the full demo host

Use Python 3.9 or newer, tmux, util-linux and a non-root test account (default `demo`) with a working cosh model provider and the agent-sec sandbox extension. Use an idle host with an empty PAP policy list. Published permits affect the daemon's authorization set, and the demo file scope matches processes named cosh.

Install the component builds you want to test. For the reference build, use the component and plugin RPMs from demo666 at `e9daa9223`. Its [RPM procedure](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/rpm-cycle.sh) includes uninstall and service changes and is intended for a disposable VM. On a development checkout, the individual package build commands are:

```bash
./scripts/rpm-build.sh agent-sec-core
./scripts/rpm-build.sh agentsight
./scripts/rpm-build.sh cosh-ng
```

Start the system daemon with a working intent provider (`ASC_INTENT_ENABLED=true`, model, base URL and provider key in the daemon's private environment). Start AgentSight with the `agent-file-guard` enforcer profile and its local API on port 7396. See the [original host setup](https://github.com/haosanzi/anolisa/blob/e9daa9223/build-report-demo/README.md) for systemd settings. The preflight calls command intent once.

## Run from the repository root

```bash
sudo python3 tests/task-policy/full.py --check
sudo python3 tests/task-policy/full.py
sudo python3 tests/task-policy/full.py --gateway
```

The second command runs Cases 1–5. The third starts a fresh run covering all six. Use `--user NAME` for another configured account. In a second terminal, run the printed tmux attach command. Once the binding is READY and cosh has a prompt, press Enter in the first terminal. It sends one prompt at a time. Wait for cosh to finish each turn before pressing Enter to check its effects.

| Case | Evidence required |
|---|---|
| 1 | ALLOW, build log overwritten, hidden shell-config write fails read-only, configuration intact |
| 2 | MODIFY, shell write fails and project source retains its original bytes |
| 3 | ALLOW, failed removal, original rollback archive and a fresh blocked unlink for this binding |
| 4 | Native read produces a blocked read of the simulated credential and zero shell receipts |
| 5 | Choose **Allow once**, then **Deny** on the repeated publish. The first copy succeeds and unlink is blocked. The denied invocation never starts. The subsequent ALLOW writes only the fallback report. |
| 6 | Choose **Allow once** for the network call. Direct controls return 200 with the real token and 401 with its surrogate. Through the Gateway the surrogate gets 200 and the same account, its scope counter advances, and client artifacts pass the credential checks. |

## Case 6 credentials

Use a short-lived fine-grained personal access token for a test account. GitHub's `GET /user` accepts a fine-grained token with no additional permissions. Create it in the browser and paste it into the script's hidden prompt. Alternatively, add `--token-source gh` when the invoking administrator's GitHub CLI is already logged in to the test account. [Create a one-day test token](https://github.com/settings/personal-access-tokens/new?name=anolisa-local-selftest&expires_in=1) · [GitHub endpoint permissions](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)

Case 6 also needs working IPv4 HTTPS access to GitHub, `nft`, the `agent-sec-gw` account and `/opt/agent-sec-gateway/current/mitmdump`. The runner invokes `agent-sec-cli key generate-fake`, places both tokens in a temporary root-only directory, and gives cosh the surrogate header and CA. Only paths appear in command arguments and policy text. The report omits client header and response bodies.

## Results and cleanup

The first terminal prints PASS, SKIP or the failing assertion. A failed check returns nonzero. The private directory printed under `/var/tmp/br-selftest-*` keeps the task, generated Cedar and per-case evidence in `results.txt`. To diagnose a failure, compare its receipt and violation IDs with the daemon events and AgentSight violations. For startup or binding failures inspect `journalctl -u agent-sec-core -u agentsight-enforcer`.

Exit or Ctrl-C in the first terminal closes the run's tmux server, deletes its scopes and policies, removes its fixture and credential files, and disables Gateway if this run enabled it. Following a host crash, use the printed resource IDs to clean up that run. Revoke the personal access token in GitHub when testing is complete.
