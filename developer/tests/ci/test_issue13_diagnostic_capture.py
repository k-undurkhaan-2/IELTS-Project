"""Only diagnostic readers/writer and their non-interference controls.

No candidate profile, repository test command, hosted job, or recovery is executed.
Existing replay functions consume fixed in-memory execution fixtures.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import run_ci_foundation as ci
import test_ci_foundation as fixtures
import issue13_diagnostic_capture as diagnostic
import issue13_diagnostic_reporters as reporters

TRANSACTION = "13001300130013001300130013001300"
CANARY = "PRIVATE-CANARY credential=fixture-only /private/unrestricted/path"


def npm_output(names=("alpha", "beta"), duration="1.25"):
    lines = ["> fixture-backend@1.0.0 test", "> node --test", ""]
    lines += [f"✔ {n} ({duration}ms)" for n in names]
    lines += [f"ℹ {k} {v}" for k, v in zip(reporters.NODE_COUNTS, (len(names), 0, len(names), 0, 0, 0, 0))]
    return ("\n".join(lines) + f"\nℹ duration_ms {duration}\n").encode("utf-8")


def frontend_output(duration="1.25"):
    return (f"TypeError: {CANARY}\n✖ fixture.test.js ({duration}ms)\n"
            "ℹ tests 1\nℹ suites 0\nℹ pass 0\nℹ fail 1\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0\n"
            f"ℹ duration_ms {duration}\n\n✖ failing tests:\nTypeError: {CANARY}\n").encode("utf-8")


def inventory():
    tree = ast.parse((ci.REPO_ROOT / "developer/tests/ci/test_standalone_packaging.py").read_bytes())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "StandalonePackagingTest")
    return ["__main__.StandalonePackagingTest." + n for n in sorted(
        node.name for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))]


def python_output(names=None, duration="74.797", statuses=None, footer="OK"):
    names = inventory() if names is None else names
    statuses = ["ok"] * len(names) if statuses is None else statuses
    lines = [f"{n.rsplit('.', 1)[1]} ({n}) ... {status}" for n, status in zip(names, statuses)]
    return ("\n".join(lines) + "\n\n" + "-" * 70 + f"\nRan {len(names)} tests in {duration}s\n\n{footer}\n").encode()


def capture_fixture(count=1, family="frontend-security"):
    """Real command/observation derivation, synthetic already-completed execution."""
    specs, records, captures, observations = [], [], [], []
    for index in range(count):
        command_id = f"frontend-security:issue13-{index}" if family == "frontend-security" else family
        relative = "developer/tests/ci/test_standalone_packaging.py" if family == "standalone-packaging" else "backend/package.json"
        spec = fixtures.synthetic_command_spec(command_id, family, index,
            command_role="observation-producing", allowed_exits=[0, 1],
            targets=[ci._target_authority(ci.REPO_ROOT, relative)],
            execution_input_mode="PROTECTED-TARGET-BUNDLE")
        stdout = frontend_output() if family == "frontend-security" else npm_output() if family == "backend-canonical" else b""
        stderr = python_output() if family == "standalone-packaging" else b""
        code = 1 if family == "frontend-security" else 0
        cap = ci.CommandCapture(command_id=spec["commandId"], command_class=spec["commandClass"], argv=spec["executionArgv"],
            executed=True, exit_code=code, duration_seconds=0.1, stdout=stdout.decode(), stderr=stderr.decode(),
            stdout_raw=stdout, stderr_raw=stderr, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            include_preview=False, containment="windows-job-object" if os.name == "nt" else "linux-subreaper-pidfd-proc-supervisor",
            process_tree_status="contained-clean", containment_disposition="no-descendants",
            execution_input_mode=spec["executionInputMode"])
        record = fixtures.synthetic_record_from_spec(spec)
        record.update({k: v for k, v in cap.evidence().items() if k not in (
            "executionInputs", "executionInputBundleDigest", "protectedTargetBundle", "targetExecutionLease")})
        record.pop("parsedFailureSummary", None)
        binder = object.__new__(ci.FoundationRunner)
        binder.command_results = [record]
        binder.observations = []
        if family != "standalone-packaging":
            ci.FoundationRunner.add_process_observation(binder, record, cap,
                source_result_id=f"issue13-synthetic-{index}.js", source_path="backend/package.json")
        specs.append(spec)
        records.append(record)
        captures.append(cap)
        observations.extend(binder.observations)
    runner = SimpleNamespace(profile="static", platform=ci.platform_key(), command_plan=specs,
        command_results=records, captures=captures, observations=observations,
        completed_classes=set(), hard_gate_results=[], violations=[], release_gate_required=False,
        runtime_closure_digest="4" * 64, dependency_closure_digest="6" * 64, dependency_member_count=0,
        tool_authority_evidence={}, source_environment={"SECRET": CANARY})
    ci.finalize_evidence_transcript(runner)
    runner.execution_binding = fixtures.synthetic_execution_binding(runner.profile, runner.command_plan_digest,
                                                                   platform_name=runner.platform)
    context = fixtures.synthetic_external_context(runner.execution_binding)
    runner.verifier_execution_binding = context.verifier_binding()
    runner.authorization_context_binding = context.authorization_context_binding()
    runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(runner.authorization_context_binding)
    ci.finalize_evidence_transcript(runner)
    return runner


def claims_for(runner):
    transcript = ci.verification_replay_transcript(runner)
    bindings = {k: copy.deepcopy(transcript[k]) for k in (
        "executionBinding", "executionBindingDigest", "authorizationContextBinding", "authorizationContextBindingDigest")}
    claims = {"summary.json": {**copy.deepcopy(bindings), "status": "PASS", "profile": runner.profile,
        "knownDebtsObserved": [], "expectedOmissions": [], "releaseOnlySkips": [], "resolvedCandidates": []},
        "command-results.json": {**bindings, "commandAuthority": copy.deepcopy(runner.command_plan),
            "records": copy.deepcopy(runner.command_results), "observations": copy.deepcopy(runner.observations)}}
    fixtures.coherently_rebind_claimed_transcript(claims)
    return claims


class ReporterTests(unittest.TestCase):
    def npm(self, raw, stderr=b"", exit_code=0):
        return reporters.node_report(raw, stderr, exit_code, npm_banner=["fixture-backend@1.0.0 test", "node --test"])

    def test_npm_complete_membership_counts_banner_and_presentation(self):
        a = self.npm(npm_output(tuple(f"test-{i}" for i in range(128))))
        b = self.npm(npm_output(tuple(f"test-{i}" for i in range(128)), "9.876").replace(b"\n", b"\r\n"))
        self.assertTrue(a["complete"])
        self.assertTrue(b["complete"])
        self.assertEqual(len(a["members"]), 128)
        self.assertEqual(a["counts"], dict(zip(reporters.NODE_COUNTS, (128, 0, 128, 0, 0, 0, 0))))
        self.assertEqual(a["semanticDigest"], b["semanticDigest"])
        self.assertNotEqual(a["presentationDigest"], b["presentationDigest"])

    def test_npm_exit_zero_invalid_reporter_matrix(self):
        good = npm_output().decode()
        cases = ["", "> fixture-backend@1.0.0 test\n> node --test\n", good.rsplit("ℹ duration_ms", 1)[0],
                 good.replace("✔ beta (1.25ms)\n", ""), good.replace("beta", "alpha"),
                 good.replace("ℹ tests 2", "ℹ tests 1"), good.replace("ℹ pass 2", "ℹ pass 1"),
                 good.replace("ℹ suites 0", "ℹ suites 1"), good.replace("ℹ fail 0", "ℹ fail 1"),
                 good + "ℹ pass 2\n", good + "ℹ duration_ms 5\n", good + "npm notice unexpected\n",
                 good.replace("ℹ todo 0", "ℹ todo 1"), good.replace("ℹ skipped 0", "ℹ skipped 1"),
                 good.replace("ℹ cancelled 0", "ℹ cancelled 1"), good.replace("✔ alpha", "ok 1 - alpha"),
                 good.replace("node --test", "node other.js"), good.replace("@1.0.0", "@2.0.0"),
                 good.replace("(1.25ms)", "(NaNms)"), good + "\x1b[31m", good + "\rtruncated"]
        for raw in cases:
            with self.subTest(case=cases.index(raw)):
                self.assertFalse(self.npm(raw.encode())["complete"])
        self.assertFalse(self.npm(npm_output(), b"warning")["complete"])
        self.assertFalse(self.npm(npm_output(), exit_code=1)["complete"])
        self.assertFalse(self.npm(b"\xff")["complete"])

    def test_ordered_membership_differences_remain_visible(self):
        a, b, c = [self.npm(npm_output(names)) for names in (("alpha", "beta"), ("beta", "alpha"), ("alpha", "gamma"))]
        self.assertEqual(len({x["membershipDigest"] for x in (a, b, c)}), 3)
        self.assertTrue(all(x["complete"] for x in (a, b, c)))

    def test_frontend_payload_is_not_mislabeled_as_presentation(self):
        a = reporters.node_report(frontend_output(), b"", 1, frontend=True)
        b = reporters.node_report(frontend_output("9.25"), b"", 1, frontend=True)
        self.assertTrue(a["complete"])
        self.assertEqual(a["counts"]["fail"], 1)
        self.assertEqual(a["members"], [{"name": "fixture.test.js", "status": "fail"}])
        self.assertGreater(a["unrecognizedCount"], 0)
        self.assertEqual(a["unrecognizedDigest"], b["unrecognizedDigest"])
        self.assertFalse(reporters.node_report(frontend_output(), b"", 0, frontend=True)["complete"])

    def test_python_membership_inventory_all_outcome_counts(self):
        names = inventory()
        self.assertEqual(len(names), 18)
        a = reporters.unittest_report(b"", python_output(), 0, inventory=names)
        b = reporters.unittest_report(b"", python_output(duration="81.933").replace(b"\n", b"\r\n"), 0, inventory=names)
        self.assertTrue(a["complete"])
        self.assertEqual(a["counts"], dict(zip(reporters.PYTHON_COUNTS, (18, 18, 0, 0, 0, 0, 0))))
        self.assertEqual(a["semanticDigest"], b["semanticDigest"])
        for status, count_key, footer, code in (
            ("FAIL", "fail", "FAILED (failures=1)", 1), ("ERROR", "error", "FAILED (errors=1)", 1),
            ("skipped 'fixture'", "skip", "OK (skipped=1)", 0),
            ("expected failure", "expected-failure", "OK (expected failures=1)", 0),
            ("unexpected success", "unexpected-success", "FAILED (unexpected successes=1)", 1),
        ):
            with self.subTest(status=count_key):
                result = reporters.unittest_report(b"", python_output(statuses=[status] + ["ok"] * 17, footer=footer), code, inventory=names)
                self.assertEqual(result["counts"][count_key], 1)
                self.assertEqual(result["counts"]["pass"], 17)
                self.assertNotEqual(a["semanticDigest"], result["semanticDigest"])

    def test_python_unresolved_stderr_and_invalid_reporter_matrix(self):
        good = python_output()
        cases = [b"", good[:-4], good + b"warning\n", b"warning\n" + good,
                 good.replace(b"Ran 18", b"Ran 17"), good.replace(b"OK\n", b"OK (errors=1)\n"),
                 good.replace(b"OK\n", b"FAILED\n"), good + b"Ran 18 tests in 1s\n",
                 good.split(b"\n", 1)[1], python_output(names=inventory()[:-1]),
                 python_output(names=list(reversed(inventory()))), python_output(names=[inventory()[0]] * 18)]
        for i, raw in enumerate(cases):
            with self.subTest(case=i):
                self.assertFalse(reporters.unittest_report(b"", raw, 0, inventory=inventory())["complete"])
        self.assertFalse(reporters.unittest_report(b"unexpected", good, 0, inventory=inventory())["complete"])
        self.assertFalse(reporters.unittest_report(b"", good, 0, inventory=None)["complete"])

    def test_stream_line_member_bounds(self):
        for raw in (None, b"x" * (reporters.MAX_STREAM_BYTES + 1), b"x" * (reporters.MAX_LINE_BYTES + 1),
                    b"\n" * (reporters.MAX_LINES + 1), npm_output(tuple(str(i) for i in range(reporters.MAX_TESTS + 1)))):
            self.assertFalse(self.npm(raw)["complete"])


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="issue13-diagnostic-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def capture(self, runner=None, name="capture", phase="producer"):
        runner = capture_fixture() if runner is None else runner
        result = diagnostic.capture_completed_runner(ci, runner, root=self.base / name,
            transaction=TRANSACTION, phase=phase, repo_root=ci.REPO_ROOT)
        return runner, result

    def test_exact_private_preimages_no_public_text_or_environment(self):
        runner, result = self.capture()
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["records"]), 1)
        public = diagnostic.validate_public(result)
        self.assertNotIn(CANARY.encode(), public)
        self.assertNotIn(b"fixture.test.js", public)
        self.assertNotIn(b"SECRET", public)
        self.assertEqual((self.base / "capture/0.stdout.bin").read_bytes(), runner.captures[0].stdout_raw)
        private = json.loads((self.base / "capture/0.json").read_bytes())
        row = result["records"][0]
        self.assertEqual(private["failureOutputs"][0], ci._raw_failure_outputs(runner.command_results[0]["producerObservations"][0], runner.command_results[0]))
        self.assertEqual(private["observationSetInputs"], runner.command_results[0]["producerObservations"])
        self.assertEqual(row["sourceOutputDigest"], ci.command_output_digest(runner.command_results[0]))
        self.assertTrue(row["streams"]["stdout"]["exact"])
        self.assertTrue(row["observations"][0]["captureObservationBinding"])
        self.assertEqual(diagnostic.read_capture(ci, self.base / "capture", ci.REPO_ROOT), result)
        if os.name != "nt":
            self.assertEqual((self.base / "capture").stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.base / "capture/0.json").stat().st_mode & 0o777, 0o600)

    def test_all_protocols_have_bounded_paired_preimages(self):
        for family in diagnostic.FAMILIES:
            with self.subTest(family=family):
                runner = capture_fixture(family=family)
                # Explicit fixture platform only; no packaging command is executed.
                if family == "standalone-packaging":
                    runner.platform = "ubuntu"
                before = copy.deepcopy(runner.command_results)
                _, producer = self.capture(runner, family + "-producer")
                _, replay = self.capture(runner, family + "-replay", "fresh-replay")
                self.assertEqual(producer["errors"], [])
                self.assertEqual(replay["errors"], [])
                self.assertEqual(runner.command_results, before)
                self.assertEqual(diagnostic.compare_public(producer, replay)["records"][0]["changedFields"], [])
                row = producer["records"][0]
                self.assertEqual(row["reporter"]["counts"]["tests"], {"frontend-security": 1, "backend-canonical": 2, "standalone-packaging": 18}[family])
                self.assertTrue(row["streams"]["stderr"]["exact"])
                self.assertEqual(diagnostic.read_capture(ci, self.base / (family + "-producer"), ci.REPO_ROOT), producer)

    def test_changed_pairs_remain_rejected_for_each_unresolved_family(self):
        for family in diagnostic.FAMILIES:
            runner = capture_fixture(family=family)
            if family == "standalone-packaging":
                runner.platform = "ubuntu"
            claims = claims_for(runner)
            changed_stream = "stderrSha256" if family == "standalone-packaging" else "stdoutSha256"
            claims["command-results.json"]["records"][0][changed_stream] = "a" * 64
            if family == "standalone-packaging":
                claims["command-results.json"]["records"][0]["descendantsObserved"] = 84
                claims["command-results.json"]["records"][0]["descendantsReaped"] = 84
            fixtures.coherently_rebind_claimed_transcript(claims)
            runner.hard_gate_results = [{"id": "STANDALONE-PACKAGE-INTEGRITY", "status": "fail", "detail": "fixed fixture"}]
            runner.violations = [{"id": "UNKNOWN-NONPASS", "commandId": runner.command_results[0]["commandId"]}]
            before = ci.compare_verification_replay_claims(claims, runner, fixtures.empty_comparison())
            states = copy.deepcopy((runner.command_results, runner.observations, runner.hard_gate_results, runner.violations))
            self.capture(runner, "rejected-" + family, "fresh-replay")
            self.assertEqual(ci.compare_verification_replay_claims(claims, runner, fixtures.empty_comparison()), before)
            self.assertEqual((runner.command_results, runner.observations, runner.hard_gate_results, runner.violations), states)
            self.assertTrue(any("command execution transcript mismatch" in error for error in before[1]))

    def test_source_authority_changed_scripts_and_source_bytes_are_unavailable(self):
        runner = capture_fixture(family="backend-canonical")
        record, expected = runner.command_results[0], runner.command_plan[0]
        before = copy.deepcopy(expected)
        authority, _, _ = diagnostic._source_authority(ci, runner, expected, record, ci.REPO_ROOT)
        self.assertTrue(authority["sourceBound"])
        wrong = copy.deepcopy(expected)
        wrong["targets"][0]["sha256"] = "0" * 64
        authority, banner, _ = diagnostic._source_authority(ci, runner, wrong, record, ci.REPO_ROOT)
        self.assertFalse(authority["sourceBound"])
        self.assertIsNone(banner)
        self.assertEqual(expected, before)
        runner.tool_authority_evidence = {"npm": {"canonicalPath": CANARY, "sha256": "f" * 64, "versionOutput": "fixture-version"}}
        runner.runtime_closure_document = {"npmEntrypoint": {"canonicalPath": CANARY, "sha256": "e" * 64, "available": True}}
        _, result = self.capture(runner, "tool-authority-fields")
        fields = result["records"][0]["toolAuthorityFieldDigests"]["npm"]
        self.assertEqual(fields["lease"]["sha256"], ci.canonical_failure_digest("f" * 64))
        self.assertEqual(fields["runtimeClosure"]["sha256"], ci.canonical_failure_digest("e" * 64))
        self.assertEqual(fields["runtimeClosure"]["canonicalPath"], ci.canonical_failure_digest(CANARY))
        self.assertNotIn(CANARY.encode(), diagnostic.validate_public(result))

    def test_first_eight_strict_count_and_schema_bounds(self):
        _, result = self.capture(capture_fixture(12))
        self.assertEqual(result["errors"], [])
        self.assertEqual([r["ordinal"] for r in result["records"]], list(range(8)))
        self.assertEqual(result["overflowCount"], 4)
        for mutation in (
            lambda v: v.update(version=2), lambda v: v.update(version=True),
            lambda v: v.update(environment={"secret": CANARY}),
            lambda v: v["records"][0].update(rawStdout=CANARY),
            lambda v: v["records"][0]["reporter"].update(kind=CANARY),
            lambda v: v["records"][0]["reporter"]["members"][0].update(nameDigest=CANARY),
            lambda v: v["records"].append(v["records"][0]),
            lambda v: v.update(selectedCount=1),
        ):
            bad = copy.deepcopy(result)
            mutation(bad)
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_public(bad)

    def test_no_existing_evidence_checkout_or_other_repository_writes(self):
        existing = self.base / "existing"
        existing.mkdir()
        sentinel = existing / "command-results.json"
        sentinel.write_bytes(b"frozen-evidence")
        other_repo = self.base / "other-repo"
        other_repo.mkdir()
        (other_repo / ".git").write_text("gitdir: frozen-worktree")
        for root in (existing, ci.REPO_ROOT / "diagnostic-forbidden", other_repo / "diagnostic", self.base / ".." / "escape"):
            with self.subTest(location=root.name), self.assertRaises((OSError, diagnostic.DiagnosticError)):
                diagnostic.PrivateDestination(root, ci.REPO_ROOT)
        self.assertEqual(sentinel.read_bytes(), b"frozen-evidence")
        destination = diagnostic.PrivateDestination(self.base / "exclusive", ci.REPO_ROOT)
        destination.write("public.json", b"first", 100)
        with self.assertRaises(OSError):
            destination.write("public.json", b"second", 100)
        with self.assertRaises(diagnostic.DiagnosticError):
            destination.write("../escaped.json", b"bad", 100)
        with self.assertRaises(diagnostic.DiagnosticError):
            destination.write("0.json", b"too-big", 1)

    @unittest.skipIf(os.name == "nt", "POSIX symlink control; Windows uses protected DACL and reparse checks")
    def test_symlink_and_hardlink_refusal(self):
        real = self.base / "real"
        real.mkdir()
        link = self.base / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.PrivateDestination(link / "capture", ci.REPO_ROOT)
        _, result = self.capture()
        os.link(self.base / "capture/0.stdout.bin", self.base / "extra-link")
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.read_capture(ci, self.base / "capture", ci.REPO_ROOT)

    def test_missing_limited_corrupted_raw_is_not_a_semantic_result(self):
        for index, raw in enumerate((None, b"partial", b"x" * (reporters.MAX_STREAM_BYTES + 1))):
            runner = capture_fixture()
            runner.captures[0].stdout_raw = raw
            _, value = self.capture(runner, f"case-{index}")
            self.assertEqual(value["errors"], [])
            row = value["records"][0]
            self.assertFalse(row["streams"]["stdout"]["exact"])
            self.assertFalse(row["reporter"]["complete"])

    def test_pair_context_tampering_and_missing_records(self):
        runner, producer = self.capture()
        _, replay = self.capture(runner, "replay", "fresh-replay")
        result = diagnostic.compare_public(producer, replay)
        self.assertEqual(result["records"][0]["changedFields"], [])
        wrong = copy.deepcopy(replay)
        wrong["transaction"] = "0" * 32
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.compare_public(producer, wrong)
        wrong = copy.deepcopy(replay)
        wrong.update(records=[], selectedCount=0)
        self.assertEqual(diagnostic.compare_public(producer, wrong)["records"][0]["pair"], "missing")
        stream = self.base / "replay/0.stdout.bin"
        stream.write_bytes(b"tampered")
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.read_capture(ci, self.base / "replay", ci.REPO_ROOT)

    def test_error_timeout_containment_cleanup_mutation_facts_are_preserved(self):
        changes = (("exitCode", 124), ("timeoutStatus", "TIMED-OUT"), ("outputLimitStatus", "OUTPUT-LIMIT-EXCEEDED"),
                   ("processTreeStatus", "cleanup-failed"), ("containmentDisposition", "forced-termination"),
                   ("descendantsSurviving", 1), ("descendantsObserved", 84), ("descendantsReaped", 83),
                   ("descendantsTerminated", 1), ("error", CANARY), ("processTreeError", CANARY))
        for i, (key, value) in enumerate(changes):
            runner = capture_fixture()
            runner.command_results[0][key] = value
            before = copy.deepcopy(runner.command_results)
            _, result = self.capture(runner, f"state-{i}")
            self.assertEqual(runner.command_results, before)
            # Inconsistent observation exit is rejected by the diagnostic reader;
            # it never alters the original command to make that observation valid.
            if result["records"]:
                row = result["records"][0]
                self.assertEqual(row["stateFieldDigests"][key], ci.canonical_failure_digest(value))
        for i, (key, value) in enumerate((("cleanupState", "failed"), ("mutationDetected", True))):
            runner = capture_fixture()
            runner.command_results[0]["protectedTargetBundle"][key] = value
            _, result = self.capture(runner, f"bundle-{i}")
            self.assertEqual(result["records"][0]["stateFieldDigests"][key], ci.canonical_failure_digest(value))

    def test_enabled_disabled_and_writer_failures_do_not_change_authority(self):
        runner = capture_fixture()
        claims = claims_for(runner)
        # Preserve a deliberate current-type mismatch in raw frontend stdout.
        claims["command-results.json"]["records"][0]["stdoutSha256"] = "a" * 64
        fixtures.coherently_rebind_claimed_transcript(claims)
        comparison = fixtures.empty_comparison()
        context = fixtures.synthetic_external_context(runner.execution_binding)
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()

        def authority():
            transcript, errors = ci.run_verification_replay(copy.deepcopy(claims), expected_context=context,
                                                           verification_runner=runner)
            return {"records": copy.deepcopy(runner.command_results), "observations": copy.deepcopy(runner.observations),
                    "canonicalTranscript": ci.verification_replay_transcript(runner), "violations": copy.deepcopy(runner.violations),
                    "gates": copy.deepcopy(runner.hard_gate_results), "replayResult": transcript, "errors": errors}
        before = authority()
        self.assertTrue(before["errors"])
        self.assertFalse(before["replayResult"] and before["replayResult"].get("finalAcceptance") == "PASS")
        baseline_hash = hashlib.sha256(ci.BASELINE_PATH.read_bytes()).hexdigest()
        for index, args in enumerate((
            SimpleNamespace(),
            SimpleNamespace(issue13_diagnostic_root=str(self.base / "enabled"), issue13_diagnostic_transaction=TRANSACTION),
            SimpleNamespace(issue13_diagnostic_root=str(self.base / "enabled"), issue13_diagnostic_transaction=TRANSACTION),
            SimpleNamespace(issue13_diagnostic_root=str(self.base / "bad-config"), issue13_diagnostic_transaction=CANARY),
        )):
            with self.subTest(mode=index), contextlib.redirect_stderr(io.StringIO()):
                ci._write_issue13_diagnostics(args, runner, "fresh-replay")
                self.assertEqual(authority(), before)
        with mock.patch.object(os, "open", side_effect=OSError(CANARY)), contextlib.redirect_stderr(io.StringIO()) as stderr:
            ci._write_issue13_diagnostics(SimpleNamespace(issue13_diagnostic_root=str(self.base / "write-fail"),
                issue13_diagnostic_transaction=TRANSACTION), runner, "fresh-replay")
        self.assertNotIn(CANARY, stderr.getvalue())
        self.assertEqual(authority(), before)
        self.assertEqual(hashlib.sha256(ci.BASELINE_PATH.read_bytes()).hexdigest(), baseline_hash)

    def test_helper_identity_and_broken_diagnostic_stderr_do_not_change_authority(self):
        runner = capture_fixture()
        before = copy.deepcopy((runner.command_results, runner.observations, runner.hard_gate_results, runner.violations))
        original_modules = {name: sys.modules.get(name) for name in ("issue13_diagnostic_reporters", "issue13_diagnostic_capture")}
        args = SimpleNamespace(issue13_diagnostic_root=str(self.base / "closed-stderr"), issue13_diagnostic_transaction=TRANSACTION)
        broken = mock.Mock()
        broken.write.side_effect = BrokenPipeError("closed diagnostic status stream")
        with mock.patch.object(sys, "stderr", broken):
            ci._write_issue13_diagnostics(args, runner, "fresh-replay")
        self.assertTrue((self.base / "closed-stderr/public.json").exists())
        with mock.patch.object(Path, "open", return_value=io.BytesIO(b"raise RuntimeError('untrusted helper')")), contextlib.redirect_stderr(io.StringIO()) as output:
            ci._write_issue13_diagnostics(SimpleNamespace(issue13_diagnostic_root=str(self.base / "untrusted-helper"),
                issue13_diagnostic_transaction=TRANSACTION), runner, "fresh-replay")
        self.assertFalse((self.base / "untrusted-helper").exists())
        self.assertNotIn("untrusted helper", output.getvalue())
        self.assertEqual((runner.command_results, runner.observations, runner.hard_gate_results, runner.violations), before)
        self.assertEqual({name: sys.modules.get(name) for name in original_modules}, original_modules)

    def test_exact_reviewed_helper_checkout_byte_variants(self):
        helper_directory = ci.REPO_ROOT / "developer/tests/ci"
        helpers = {name + ".py": (helper_directory / (name + ".py")).read_bytes().replace(b"\r\n", b"\n")
                   for name in ("issue13_diagnostic_reporters", "issue13_diagnostic_capture")}
        original_open = Path.open
        runner = capture_fixture()
        before = copy.deepcopy(runner.command_results)
        for index, ending in enumerate((b"\n", b"\r\n")):
            def opened(path, *args, **kwargs):
                if path.parent == helper_directory and path.name in helpers:
                    return io.BytesIO(helpers[path.name].replace(b"\n", ending))
                return original_open(path, *args, **kwargs)
            with mock.patch.object(Path, "open", autospec=True, side_effect=opened), contextlib.redirect_stderr(io.StringIO()):
                ci._write_issue13_diagnostics(SimpleNamespace(issue13_diagnostic_root=str(self.base / f"helper-variant-{index}"),
                    issue13_diagnostic_transaction=TRANSACTION), runner, "fresh-replay")
            self.assertEqual(json.loads((self.base / f"helper-variant-{index}/public.json").read_bytes())["errors"], [])
        self.assertEqual(runner.command_results, before)

    def test_passing_existing_control_eligibility_is_also_unchanged(self):
        runner, claims, comparison = fixtures.p52_compact_replay_fixture()
        runner.captures = []
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()
        context = fixtures.synthetic_external_context(runner.execution_binding)
        before = ci.run_verification_replay(copy.deepcopy(claims), expected_context=context, verification_runner=runner)
        _, captured = self.capture(runner, "passing-control", "fresh-replay")
        after = ci.run_verification_replay(copy.deepcopy(claims), expected_context=context, verification_runner=runner)
        self.assertEqual(captured["selectedCount"], 0)
        self.assertEqual(before, after)
        self.assertEqual(before[1], [])
        self.assertEqual(before[0]["finalAcceptance"], "PASS")

    def test_diagnostic_documents_cannot_replace_authoritative_evidence(self):
        runner, summary = self.capture()
        fake_claims = {"summary.json": summary, "command-results.json": summary}
        _, errors = ci.compare_verification_replay_claims(fake_claims, runner, fixtures.empty_comparison())
        self.assertTrue(errors)
        self.assertNotIn("replayAuthorizationEnvelopeDigest", summary)
        self.assertNotIn("knownDebtsObserved", summary)
        self.assertNotIn("hardGates", summary)

    def test_cli_hook_order_is_after_authoritative_processing_and_cleanup(self):
        source = (ci.REPO_ROOT / "developer/tests/ci/run_ci_foundation.py").read_text("utf-8")
        tree = ast.parse(source)
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        hooks = [n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_write_issue13_diagnostics"]
        self.assertEqual(len(hooks), 2)
        phases = {n.args[2].value for n in hooks}
        self.assertEqual(phases, {"producer", "fresh-replay"})
        for n in hooks:
            previous = source.splitlines()[n.lineno - 2].strip()
            self.assertTrue(previous.endswith(".cleanup_task_resources()"), previous)
        parsed = ci.parse_args(["--profile", "all", "--issue13-diagnostic-root", str(self.base / "not-created"),
                               "--issue13-diagnostic-transaction", TRANSACTION])
        self.assertEqual(parsed.issue13_diagnostic_transaction, TRANSACTION)
        self.assertFalse((self.base / "not-created").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
