"""Regression checks for the local task-policy entry points and their evidence."""

import json
import secrets
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import common
import gateway
import intent
import sandbox
import sight


class SuiteTests(unittest.TestCase):
    def test_component_preflights(self):
        with patch.object(intent, "cli", return_value={"outcome": "candidate"}) as cli:
            intent.check_intent()
            self.assertIn("propose-command", cli.call_args.args)
        with patch.object(sandbox, "cli", return_value={"items": []}) as cli:
            sandbox.preflight()
            cli.assert_called_once_with("policy", "list", "--limit", "1")
        with patch.object(sight, "cli") as cli, patch.object(
            sight, "check_actplane"
        ) as health:
            sight.preflight()
            cli.assert_called_once_with("scope", "list", "--limit", "1")
            health.assert_called_once()

    def test_consumer_entries_publish_same_bytes_with_intent_offline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            row = root / "workspace"
            source = root / "from-intent.cedar"
            original = (common.HERE / "task.cedar").read_bytes() + b"// handoff\n"
            source.write_bytes(original)
            for module in (sandbox, sight):
                report = root / module.__name__
                report.mkdir()

                @contextmanager
                def local_run():
                    with ExitStack() as cleanup:
                        yield report, cleanup

                with ExitStack() as stack:
                    stack.enter_context(
                        patch("sys.argv", [module.__file__, "--policy", str(source)])
                    )
                    stack.enter_context(
                        patch.object(
                            intent,
                            "generate_policy",
                            side_effect=AssertionError("offline"),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            intent,
                            "check_intent",
                            side_effect=AssertionError("offline"),
                        )
                    )
                    stack.enter_context(patch.object(common, "SHARED_ROW", row))
                    stack.enter_context(patch.object(common, "check_host"))
                    stack.enter_context(
                        patch.object(
                            common,
                            "test_account",
                            return_value=SimpleNamespace(pw_uid=123),
                        )
                    )
                    stack.enter_context(patch.object(common, "local_run", local_run))
                    stack.enter_context(
                        patch.object(common, "fixture", return_value=b"previous")
                    )
                    publish = stack.enter_context(
                        patch.object(common, "publish", return_value="shared-policy")
                    )
                    stack.enter_context(patch.object(module, "preflight"))
                    exercise = stack.enter_context(patch.object(module, "exercise"))
                    module.main()
                    work, _ = exercise.call_args.args
                    self.assertEqual(work.policy, "shared-policy")
                    self.assertEqual(publish.call_args.args[0].read_bytes(), original)
                self.assertFalse(row.exists())


class EvidenceTests(unittest.TestCase):
    def test_unrelated_or_stale_unlink_cannot_prove_a_block(self):
        event = dict(
            event_id="id",
            policy_id="p",
            binding_id="b",
            operation="unlink",
            target="previous.zip",
            blocked=True,
            occurred_at_ns=100,
        )
        with patch.object(sight, "sight", return_value={"violations": [event]}):
            self.assertEqual(
                sight.check_violation("p", "b", "3", 100)["violation"], "id"
            )
            for changes in (
                dict(policy_id="other"),
                dict(binding_id="other"),
                dict(blocked=False),
                dict(occurred_at_ns=99),
                dict(target="other"),
                dict(operation="read"),
            ):
                with self.subTest(changes=changes), patch.dict(event, changes):
                    with self.assertRaises(RuntimeError):
                        sight.check_violation("p", "b", "3", 100)

    def test_denial_requires_evidence_that_the_process_never_started(self):
        details = {
            "principal": {"agent_type": "cosh"},
            "host_finished": True,
            "result": {"started": False},
        }
        event = {
            "event_id": "id",
            "uid": 1000,
            "verdict": "STEP_UP",
            "details": details,
        }
        with patch.object(sandbox, "cli", return_value=[event]):
            self.assertFalse(sandbox.check_receipt("5-deny", "start", 1000)["started"])
            for changes in (
                dict(result=None),
                dict(result={"started": True}),
                dict(approval=True),
            ):
                with self.subTest(changes=changes), patch.dict(details, changes):
                    with self.assertRaises(RuntimeError):
                        sandbox.check_receipt("5-deny", "start", 1000)
            with self.assertRaises(RuntimeError):
                sandbox.check_receipt("4", "start", 1000)

    def test_gateway_requires_the_surrogate_status_and_authenticated_account(self):
        real = secrets.token_hex().encode()
        fake = secrets.token_hex().encode()
        files = {
            "out/http-status": b"200",
            "out/debug.log": b"Authorization: Bearer " + fake + b"\n",
            "out/github-user.json": b'{"login":"test-account"}',
        }
        gateway.verify(files.__getitem__, real, fake, "test-account")
        for changes in (
            {"out/http-status": b"401"},
            {"out/debug.log": real},
            {"out/debug.log": files["out/debug.log"] + b"extra\n"},
            {"out/github-user.json": b'{"login":"other"}'},
            {
                "out/github-user.json": json.dumps(
                    {"login": "test-account", "extra": real.decode()}
                ).encode()
            },
        ):
            with patch.dict(files, changes), self.assertRaises(RuntimeError) as raised:
                gateway.verify(files.__getitem__, real, fake, "test-account")
            self.assertNotIn(real.decode(), str(raised.exception))
            self.assertNotIn(fake.decode(), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
