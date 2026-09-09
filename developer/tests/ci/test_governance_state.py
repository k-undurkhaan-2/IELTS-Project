#!/usr/bin/env python3
"""Prospective authority, local validation cache, and bounded recovery regressions."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

CI_DIR = Path(__file__).resolve().parent
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import governance_state as gs

TREE = "a" * 40
SHA = "b" * 64
REF = "refs/heads/staging"


def authority(tree=TREE):
    return {
        "schema_version": 1, "authority_id": "P-TEST", "candidate_tree": tree,
        "allowed_actions": ["stage", "sign", "verify"],
        "destination": {"role": "staging", "ref": REF},
        "required_evidence": ["EV-TEST"],
        "recovery": {"allowed_classes": ["parser", "environment"], "max_retries": 1},
        "stop_conditions": ["candidate_changed", "destination_changed", "authority_changed"],
        "issued_at": "2026-09-09T00:00:00Z", "issued_by": "test-owner",
    }


def material():
    return {
        "candidate_tree": TREE, "assurance_profile": "r12-full-validation-v1",
        "validation_definition_digest": SHA, "environment_contract_digest": "c" * 64,
        "fixtures_digest": None,
    }


def state(record=None):
    record = record or authority()
    return {
        "schema_version": 1, "decision": "SNAPSHOT", "reason": "CAPTURED",
        "head_oid": "d" * 40, "candidate_tree": record["candidate_tree"],
        "index_identity": SHA, "worktree_diff_identity": SHA,
        "selected_refs": {REF: "d" * 40}, "destination": copy.deepcopy(record["destination"]),
        "authority_digest": gs.digest(record), "authority_id": record["authority_id"],
    }


class GovernanceDecisions(unittest.TestCase):
    def assert_decision(self, result, decision, reason=None):
        self.assertEqual(result["decision"], decision, result)
        if reason is not None:
            self.assertEqual(result["reason"], reason, result)
        self.assertIn("candidate_tree", result)

    def authorize(self, record=None, **changes):
        request = dict(candidate_tree=TREE, action="stage", destination_role="staging", destination_ref=REF)
        request.update(changes)
        return gs.check_authority(record if record is not None else authority(), **request)

    def test_authority_exact_and_independent_denials(self):
        self.assert_decision(self.authorize(), "ALLOW")
        for change, reason in [
            ({"candidate_tree": "e" * 40}, "CANDIDATE_CHANGED"),
            ({"action": "push"}, "ACTION_NOT_AUTHORIZED"),
            ({"destination_ref": "refs/heads/other"}, "DESTINATION_CHANGED"),
            ({"destination_role": "production"}, "DESTINATION_CHANGED"),
        ]:
            with self.subTest(change=change):
                self.assert_decision(self.authorize(**change), "DENY", reason)
        limited = authority()
        limited["allowed_actions"] = ["verify"]
        self.assert_decision(self.authorize(limited), "DENY", "ACTION_NOT_AUTHORIZED")

    def test_authority_rejects_malformed_or_expanded_contract(self):
        changes = [
            ("schema_version", True), ("candidate_tree", "HEAD^{tree}"),
            ("allowed_actions", ["stage", "push"]), ("allowed_actions", ["stage", "stage"]),
            ("required_evidence", "EV-TEST"), ("issued_by", ""), ("issued_at", "yesterday"),
            ("recovery", {"allowed_classes": ["parser"], "max_retries": True}),
            ("recovery", {"allowed_classes": ["parser"], "max_retries": 2}),
            ("recovery", {"allowed_classes": ["unknown"], "max_retries": 1}),
            ("stop_conditions", ["candidate_changed"]),
            ("destination", {"role": "staging", "ref": "HEAD"}),
            ("destination", {"role": "staging", "ref": "refs/heads/staging~1"}),
        ]
        for key, value in changes:
            record = authority()
            record[key] = value
            with self.subTest(key=key, value=value):
                self.assert_decision(self.authorize(record), "DENY", "AUTHORITY_INVALID")
        for record in [{}, [], None, {**authority(), "historical_status": "APPROVED"}]:
            with self.subTest(record=record):
                result = gs.check_authority(record, TREE, "stage", "staging", REF)
                self.assert_decision(result, "DENY", "AUTHORITY_INVALID")

    def test_authority_evidence_namespace_matches_schema(self):
        schema = gs.read_document(CI_DIR / "current-authority.v1.schema.json")
        pattern = schema["properties"]["required_evidence"]["items"]["pattern"]
        local_id = gs.make_receipt(material())["receipt_id"]
        for identifiers, allowed in [([local_id], False), (["LC-"], False),
                                     (["EV-TEST", "LC-OTHER"], False),
                                     (["EV-TEST", "SECURITY-REVIEW-TEST"], True)]:
            record = authority()
            record["required_evidence"] = identifiers
            with self.subTest(identifiers=identifiers):
                self.assertEqual(all(re.search(pattern, item) is not None for item in identifiers), allowed)
                self.assert_decision(self.authorize(record), "ALLOW" if allowed else "DENY",
                                     "AUTHORITY_MATCH" if allowed else "AUTHORITY_INVALID")

    def test_receipt_reuse_and_all_fingerprint_invalidations(self):
        receipt = gs.make_receipt(material())
        self.assertTrue(receipt["receipt_id"].startswith("LC-"))
        self.assertEqual(receipt["trust_scope"], "local-validation-cache-only")
        self.assert_decision(gs.check_evidence(receipt, material()), "REUSE_ALLOWED")
        for field, value, reason in [
            ("candidate_tree", "e" * 40, "CANDIDATE_CHANGED"),
            ("validation_definition_digest", "e" * 64, "VALIDATOR_CHANGED"),
            ("environment_contract_digest", "e" * 64, "ENVIRONMENT_CHANGED"),
            ("fixtures_digest", "e" * 64, "FIXTURES_CHANGED"),
        ]:
            current = material()
            current[field] = value
            with self.subTest(field=field):
                self.assert_decision(gs.check_evidence(receipt, current), "REVALIDATE", reason)
        current = material()
        current["assurance_profile"] = "another-profile"
        self.assert_decision(gs.check_evidence(receipt, current), "REVALIDATE")

    def test_receipt_requires_complete_consistent_pass(self):
        for field, value in [
            ("result", "FAIL"), ("schema_version", True), ("created_at", "yesterday"),
            ("validation_fingerprint", "e" * 64), ("receipt_id", ""), ("receipt_id", "EV-TEST"),
            ("candidate_tree", "e" * 40),
            ("fingerprint_inputs", {**material(), "authority_id": "P-OTHER"}),
        ]:
            receipt = gs.make_receipt(material())
            receipt[field] = value
            with self.subTest(field=field):
                self.assert_decision(gs.check_evidence(receipt, material()), "REVALIDATE")
        for field in material():
            receipt = gs.make_receipt(material())
            if field in receipt["fingerprint_inputs"]:
                del receipt["fingerprint_inputs"][field]
                with self.subTest(missing=field):
                    self.assert_decision(gs.check_evidence(receipt, material()), "REVALIDATE")
        for receipt in [{}, [], None]:
            self.assert_decision(gs.check_evidence(receipt, material()), "REVALIDATE")

    def test_receipt_requires_exact_local_trust_scope(self):
        schema = gs.read_document(CI_DIR / "evidence-receipt.v1.schema.json")
        self.assertIn("trust_scope", schema["required"])
        self.assertEqual(schema["properties"]["trust_scope"], {"const": "local-validation-cache-only"})
        pattern = schema["properties"]["receipt_id"]["pattern"]
        self.assertIsNotNone(re.search(pattern, gs.make_receipt(material())["receipt_id"]))
        self.assertIsNone(re.search(pattern, "EV-TEST"))
        for scope in [None, [], "", "authoritative-evidence", "local-validation-cache-only "]:
            receipt = gs.make_receipt(material())
            receipt["trust_scope"] = scope
            with self.subTest(scope=scope):
                self.assert_decision(gs.check_evidence(receipt, material()), "REVALIDATE", "RECEIPT_INVALID")
        receipt = gs.make_receipt(material())
        del receipt["trust_scope"]
        self.assert_decision(gs.check_evidence(receipt, material()), "REVALIDATE", "RECEIPT_INVALID")

    def test_fingerprint_canonical_and_excludes_execution_authority(self):
        inputs = material()
        receipt = gs.make_receipt(inputs)
        expected = hashlib.sha256(gs.canonical(inputs)).hexdigest()
        self.assertEqual(receipt["validation_fingerprint"], expected)
        self.assertEqual(gs.digest(dict(reversed(list(inputs.items())))), expected)
        later = authority()
        later["authority_id"] = "P-LATER-TASK"
        later["required_evidence"] = ["EV-SEPARATELY-AUTHENTICATED"]
        later["allowed_actions"] = ["verify"]
        self.assert_decision(gs.check_evidence(receipt, inputs), "REUSE_ALLOWED")
        self.assert_decision(self.authorize(later), "DENY", "ACTION_NOT_AUTHORIZED")
        self.assert_decision(self.authorize(later, action="verify"), "ALLOW")
        for forbidden in ["authority_id", "task_id", "issued_at", "destination", "trust_scope"]:
            self.assertNotIn(forbidden, receipt["fingerprint_inputs"])

    def test_historical_prose_cannot_grant_or_veto_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "historical-report.md"
            for text in ["key=BLOCKED", "key: BLOCKED", "APPROVED", "NOT_APPROVED"]:
                report.write_text(text, encoding="utf-8")
                with self.subTest(text=text):
                    self.assert_decision(self.authorize(), "ALLOW")
                    self.assert_decision(self.authorize(action="merge"), "DENY")
                    with self.assertRaises((ValueError, json.JSONDecodeError)):
                        gs.read_document(report)
            record = authority()
            record["authority_id"] = "P-NOT_APPROVED"
            record["issued_by"] = "key=BLOCKED"
            self.assert_decision(self.authorize(record), "ALLOW")

    def test_strict_json_rejects_ambiguous_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "record.json"
            for raw in ['{"schema_version":1,"schema_version":1}', '{"x":NaN}', '\ufeff{}']:
                path.write_text(raw, encoding="utf-8")
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    gs.read_document(path)

    def test_recovery_explicit_classes_and_single_positive_attempt(self):
        before = state()
        for category in ["parser", "environment"]:
            self.assert_decision(gs.check_recovery(before, copy.deepcopy(before), authority(), category, 1), "RETRY_ALLOWED")
        self.assert_decision(gs.check_recovery(before, before, authority(), "network", 1), "ESCALATE", "FAILURE_CLASS_NOT_ALLOWED")
        self.assert_decision(gs.check_recovery(before, before, authority(), "parser", 2), "ESCALATE", "RETRY_LIMIT")
        for attempt in [0, -1, True, "1", None]:
            with self.subTest(attempt=attempt):
                self.assert_decision(gs.check_recovery(before, before, authority(), "parser", attempt), "ESCALATE")

    def test_recovery_detects_each_semantic_state_change(self):
        before = state()
        for field, value, reason in [
            ("candidate_tree", "e" * 40, "CANDIDATE_CHANGED"),
            ("index_identity", "e" * 64, "INDEX_CHANGED"),
            ("selected_refs", {REF: "e" * 40}, "REF_CHANGED"),
            ("authority_digest", "e" * 64, "AUTHORITY_CHANGED"),
            ("head_oid", "e" * 40, None),
            ("worktree_diff_identity", "e" * 64, None),
            ("destination", {"role": "production", "ref": REF}, None),
        ]:
            after = copy.deepcopy(before)
            after[field] = value
            with self.subTest(field=field):
                self.assert_decision(gs.check_recovery(before, after, authority(), "parser", 1), "ESCALATE", reason)

    def test_recovery_equal_unknown_states_fail_closed(self):
        invalid_states = [{}, [], None]
        for key in state():
            incomplete = state()
            del incomplete[key]
            invalid_states.append(incomplete)
        invalid_states += [{**state(), "selected_refs": {}}, {**state(), "head_oid": None}]
        for invalid in invalid_states:
            with self.subTest(invalid=invalid):
                self.assert_decision(gs.check_recovery(invalid, invalid, authority(), "parser", 1), "ESCALATE", "STATE_UNKNOWN")
        changed = authority()
        changed["authority_id"] = "P-LATER"
        self.assert_decision(gs.check_recovery(state(), state(), changed, "parser", 1), "ESCALATE", "AUTHORITY_CHANGED")
        self.assert_decision(gs.check_recovery(state(), state(), {}, "parser", 1), "ESCALATE")


@unittest.skipUnless(shutil.which("git"), "Git is required for semantic snapshot tests")
class GitSemanticState(unittest.TestCase):
    assert_decision = GovernanceDecisions.assert_decision
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Governance Test")
        self.git("config", "user.email", "governance-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.tracked = self.root / "tracked.txt"
        self.tracked.write_text("frozen\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "Create frozen test candidate")
        self.git("update-ref", REF, "HEAD")
        self.record = authority(self.git("rev-parse", "HEAD^{tree}"))

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("utf-8").strip()

    def capture(self):
        return gs.snapshot(self.root, self.record, [])

    def recover(self, before, after):
        return gs.check_recovery(before, after, self.record, "parser", 1)

    def test_snapshot_auto_selects_destination_and_unchanged_retry(self):
        before = self.capture()
        self.assertIn(REF, before["selected_refs"])
        self.assert_decision(self.recover(before, self.capture()), "RETRY_ALLOWED")

    def test_snapshot_detects_untracked_content_change(self):
        extra = self.root / "extra.txt"
        extra.write_text("one", encoding="utf-8")
        before = self.capture()
        extra.write_text("two", encoding="utf-8")
        after = self.capture()
        self.assertNotEqual(before["worktree_diff_identity"], after["worktree_diff_identity"])
        self.assert_decision(self.recover(before, after), "ESCALATE")

    def test_snapshot_detects_worktree_then_index_change(self):
        before = self.capture()
        self.tracked.write_text("changed\n", encoding="utf-8")
        self.assert_decision(self.recover(before, self.capture()), "ESCALATE")
        self.git("add", "tracked.txt")
        self.assert_decision(self.recover(before, self.capture()), "ESCALATE", "INDEX_CHANGED")

    def test_snapshot_detects_ref_change_without_head_change(self):
        before = self.capture()
        other = self.git("commit-tree", self.record["candidate_tree"], "-p", "HEAD", "-m", "Another test commit")
        self.git("update-ref", REF, other)
        after = self.capture()
        self.assertEqual(before["head_oid"], after["head_oid"])
        self.assert_decision(self.recover(before, after), "ESCALATE", "REF_CHANGED")

    @mock.patch.object(gs, "live_environment", return_value={"tools": "fixture"})
    def test_hidden_index_flags_are_unknown_for_snapshot_and_reuse(self, _runtime):
        contract = Path(self.temp.name) / "environment.json"
        contract.write_text('{"runtime":"test"}', encoding="utf-8")
        for flag in ["assume-unchanged", "skip-worktree"]:
            with self.subTest(flag=flag):
                self.git("update-index", "--" + flag, "tracked.txt")
                try:
                    self.tracked.write_text("hidden mutation\n", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        self.capture()
                    with self.assertRaises(ValueError):
                        gs.frozen_context(self.root, contract, None)
                finally:
                    self.git("update-index", "--no-" + flag, "tracked.txt")
                    self.tracked.write_text("frozen\n", encoding="utf-8")

    @mock.patch.object(gs, "live_environment", return_value={"tools": "fixture"})
    def test_frozen_context_binds_real_contract_and_rejects_dirty_inputs(self, _runtime):
        definitions = self.root / "developer/tests/ci"
        definitions.mkdir(parents=True)
        for name in ["run_ci_foundation.py", "test_ci_foundation.py", "governance_state.py",
                     "current-authority.v1.schema.json", "evidence-receipt.v1.schema.json"]:
            (definitions / name).write_text("fixture\n", encoding="utf-8")
        self.git("add", "developer")
        self.git("commit", "-qm", "Add synthetic validator inputs")
        contract = Path(self.temp.name) / "environment.json"
        contract.write_text('{"runtime":"first"}', encoding="utf-8")
        first = gs.frozen_context(self.root, contract, None)
        self.assertEqual(first, gs.frozen_context(self.root, contract, None))
        contract.write_text('{"runtime":"second"}', encoding="utf-8")
        second = gs.frozen_context(self.root, contract, None)
        self.assertNotEqual(first["environment_contract_digest"], second["environment_contract_digest"])
        self.assertEqual(first["candidate_tree"], second["candidate_tree"])
        self.tracked.write_text("changed\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            gs.frozen_context(self.root, contract, None)
        self.tracked.write_text("frozen\n", encoding="utf-8")
        (self.root / "untracked.py").write_text("extra input", encoding="utf-8")
        with self.assertRaises(ValueError):
            gs.frozen_context(self.root, contract, None)
    def test_snapshot_unknown_ref_and_invalid_tree_fail_closed(self):
        for refs in [["HEAD"], ["refs/heads/absent"], ["refs/heads/staging~1"]]:
            with self.subTest(refs=refs), self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                gs.snapshot(self.root, self.record, refs)
        invalid = authority("e" * 40)
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            gs.snapshot(self.root, invalid, [])

class ReceiptAdapter(unittest.TestCase):
    def setUp(self):
        import test_ci_foundation as harness
        self.harness = harness
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "candidate"
        self.root.mkdir()
        self.receipts = Path(self.temp.name) / "receipts"
        self.contract = Path(self.temp.name) / "environment.json"
        self.contract.write_text('{"runtime":"test"}', encoding="utf-8")
        self.args = ["--reuse-receipt-dir", str(self.receipts), "--environment-contract", str(self.contract), "--fixtures-digest", "null"]
        ids = tuple("test-%d" % index for index in range(476))
        self.result = SimpleNamespace(wasSuccessful=lambda: True, testsRun=476,
                                      inventory_ids=ids, executed_test_ids=set(ids), successful_test_ids=set(ids))

    def invoke(self, contexts=None, result=None, extra=()):
        output = io.StringIO()
        with mock.patch.object(self.harness.ci, "REPO_ROOT", self.root), \
             mock.patch.object(gs, "frozen_context", return_value=material(), side_effect=contexts), \
             mock.patch.object(self.harness.unittest, "main", return_value=SimpleNamespace(result=result or self.result)) as full, \
             mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = self.harness.run_with_receipt(self.args + list(extra))
        return code, full.call_count, output.getvalue()

    def test_second_identical_candidate_avoids_complete_harness(self):
        first_code, first_calls, first_output = self.invoke()
        paths = list(self.receipts.glob("*.json"))
        self.assertEqual((first_code, first_calls, len(paths)), (0, 1, 1))
        self.assertIn('"decision": "EVIDENCE_RECORDED"', first_output)
        original = paths[0].read_bytes()
        receipt = json.loads(original)
        self.assertTrue(receipt["receipt_id"].startswith("LC-"))
        self.assertEqual(receipt["trust_scope"], "local-validation-cache-only")
        second_code, second_calls, second_output = self.invoke()
        self.assertEqual((second_code, second_calls), (0, 0))
        self.assertIn('"decision": "REUSE_ALLOWED"', second_output)
        self.assertEqual(paths[0].read_bytes(), original)
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)

    def test_all_technical_changes_run_existing_harness(self):
        self.invoke()
        for field in material():
            changed = material()
            changed[field] = "e" * (40 if field == "candidate_tree" else 64)
            if field == "assurance_profile":
                changed[field] = "different-profile"
            with self.subTest(field=field):
                code, calls, _ = self.invoke(contexts=[changed, changed])
                self.assertEqual((code, calls), (0, 1))

    def test_invalid_receipt_runs_full_harness(self):
        self.receipts.mkdir()
        broken = self.receipts / (gs.digest(material()) + "-broken.json")
        broken.write_text('{"result":"PASS"}', encoding="utf-8")
        code, calls, _ = self.invoke()
        self.assertEqual((code, calls), (0, 1))
        self.assertEqual(broken.read_text(encoding="utf-8"), '{"result":"PASS"}')

    def test_failed_partial_or_skipped_suite_cannot_mint_receipt(self):
        variants = [dict(wasSuccessful=lambda: False), dict(testsRun=475),
                    dict(successful_test_ids=set(self.result.inventory_ids[:-1]))]
        for changes in variants:
            result = copy.copy(self.result)
            result.__dict__.update(changes)
            with self.subTest(changes=changes):
                code, calls, _ = self.invoke(result=result)
                self.assertEqual(calls, 1)
                self.assertEqual(code, 0 if result.wasSuccessful() else 1)
                self.assertEqual(list(self.receipts.glob("*.json")), [])

    def test_unknown_or_midrun_changed_state_cannot_mint(self):
        changed = {**material(), "candidate_tree": "e" * 40}
        for contexts in [[ValueError("unknown")], [material(), changed]]:
            with self.subTest(contexts=contexts):
                code, calls, _ = self.invoke(contexts=contexts)
                self.assertEqual((code, calls), (0, 1))
                self.assertEqual(list(self.receipts.glob("*.json")), [])

    def test_reuse_rechecks_current_state_before_skipping(self):
        self.invoke()
        changed = {**material(), "environment_contract_digest": "e" * 64}
        code, calls, output = self.invoke(contexts=[material(), changed])
        self.assertEqual((code, calls), (0, 1))
        self.assertIn('"reason": "STATE_CHANGED"', output)
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)

    def test_test_selectors_and_hosted_reuse_are_rejected(self):
        with self.assertRaises(SystemExit):
            self.invoke(extra=["SomeSelectedTest"])
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.harness.run_with_receipt(self.args)

    def test_runtime_artifacts_inside_candidate_are_rejected(self):
        self.args[1] = str(self.root / "receipts")
        with self.assertRaises(SystemExit):
            self.invoke()


class LiveEnvironment(unittest.TestCase):
    def test_unknown_or_incomplete_tool_authority_fails_closed(self):
        for answer in [({}, ["tool authority unavailable"]), ({}, [])]:
            with self.subTest(answer=answer), mock.patch.object(gs.ci, "resolve_trusted_tools", return_value=answer):
                with self.assertRaises(ValueError):
                    gs.live_environment(Path.cwd())

    def test_tool_bytes_and_execution_environment_change_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "synthetic-tool.exe"
            executable.write_bytes(b"first executable")
            tools = {role: str(executable) for role in gs.ci.required_tool_names("static")}
            with mock.patch.object(gs.ci, "resolve_trusted_tools", return_value=(tools, [])), \
                 mock.patch.dict(os.environ, {"NODE_OPTIONS": "--no-warnings"}):
                first = gs.live_environment(Path(folder))
                self.assertEqual(first, gs.live_environment(Path(folder)))
                executable.write_bytes(b"changed executable")
                second = gs.live_environment(Path(folder))
                self.assertNotEqual(gs.digest(first), gs.digest(second))
                with mock.patch.dict(os.environ, {"NODE_OPTIONS": "--trace-warnings"}):
                    self.assertNotEqual(gs.digest(second), gs.digest(gs.live_environment(Path(folder))))

class DecisionCLI(unittest.TestCase):
    def test_external_authority_record_and_machine_readable_exit_status(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "authority.json"
            path.write_bytes(gs.canonical(authority()))
            args = ["authority-check", "--authority", str(path), "--candidate-tree", TREE,
                    "--action", "stage", "--destination-role", "staging", "--destination-ref", REF]
            for action, expected, code in [("stage", "ALLOW", 0), ("deploy", "DENY", 1)]:
                args[args.index("--action") + 1] = action
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(gs.main(args), code)
                self.assertEqual(json.loads(output.getvalue())["decision"], expected)

    def test_evidence_command_reads_receipt_path_and_invalidates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            path.write_bytes(gs.canonical(gs.make_receipt(material())))
            args = ["evidence-check", "--receipt", str(path)]
            for key, value in material().items():
                args.extend(["--" + key.replace("_", "-"), "null" if value is None else value])
            for tree, decision, code in [(TREE, "REUSE_ALLOWED", 0), ("e" * 40, "REVALIDATE", 1)]:
                args[args.index("--candidate-tree") + 1] = tree
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(gs.main(args), code)
                self.assertEqual(json.loads(output.getvalue())["decision"], decision)

    def test_recovery_command_reads_both_snapshot_paths_and_enforces_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            args = ["recovery-check", "--failure-class", "parser", "--attempt", "1"]
            for name, value in [("authority", authority()), ("before", state()), ("after", state())]:
                path = Path(folder) / (name + ".json")
                path.write_bytes(gs.canonical(value))
                args.extend(["--" + name, str(path)])
            for attempt, decision, code in [("1", "RETRY_ALLOWED", 0), ("2", "ESCALATE", 1)]:
                args[args.index("--attempt") + 1] = attempt
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(gs.main(args), code)
                self.assertEqual(json.loads(output.getvalue())["decision"], decision)
    def test_runtime_authority_inside_candidate_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(gs, "ROOT", Path(folder)):
            path = Path(folder) / "authority.json"
            path.write_bytes(gs.canonical(authority()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = gs.main(["authority-check", "--authority", str(path), "--candidate-tree", TREE,
                                "--action", "stage", "--destination-role", "staging", "--destination-ref", REF])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["decision"], "DENY")

if __name__ == "__main__":
    unittest.main(verbosity=2)




