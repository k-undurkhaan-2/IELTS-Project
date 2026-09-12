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
import subprocess
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
NON_INTERFERENCE_RESULTS = {}


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


def capture_fixture(count=1, family="frontend-security", *, platform_name=None, profile="static",
                    ordinals=None, command_ids=None, targets=None):
    """Real command/observation derivation, synthetic already-completed execution."""
    specs, records, captures, observations = [], [], [], []
    for index in range(count):
        command_id = f"frontend-security:issue13-{index}" if family == "frontend-security" else family
        command_id = command_ids[index] if command_ids is not None else command_id
        relative = "developer/tests/ci/test_standalone_packaging.py" if family == "standalone-packaging" else "backend/package.json"
        spec = fixtures.synthetic_command_spec(command_id, family, ordinals[index] if ordinals is not None else index,
            command_role="observation-producing", allowed_exits=[0, 1],
            targets=copy.deepcopy(targets) if targets is not None else [ci._target_authority(ci.REPO_ROOT, relative)],
            execution_input_mode="PROTECTED-TARGET-BUNDLE")
        spec.update(platform=platform_name or ci.platform_key(), profile=profile)
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
    runner = SimpleNamespace(profile=profile, platform=platform_name or ci.platform_key(), command_plan=specs,
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


def full_scope_fixture(platform_name=None):
    platform_name = platform_name or ci.platform_key()
    names = {687: "adminFrontendGuard.test.js", 692: "localDataRenderingGuard.test.js",
             695: "remotePracticeDataSource.test.js"}
    parts = [capture_fixture(family=family, platform_name=platform_name, profile="all", ordinals=[ordinal],
        command_ids=["frontend-security:" + names[ordinal] if family == "frontend-security" else family])
        for ordinal, family, _digest in sorted(diagnostic._required_all_records(platform_name))]
    runner = parts[0]
    for key in ("command_plan", "command_results", "captures", "observations"):
        setattr(runner, key, [item for part in parts for item in getattr(part, key)])
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

    def test_no_first_eight_truncation_and_strict_schema_bounds(self):
        with self.assertRaises(diagnostic.DiagnosticError):
            self.capture(capture_fixture(12), "overflow")
        self.assertFalse((self.base / "overflow").exists())
        _, result = self.capture(capture_fixture(8))
        self.assertEqual(result["errors"], [])
        self.assertEqual([r["ordinal"] for r in result["records"]], list(range(8)))
        self.assertEqual(result["overflowCount"], 0)
        for mutation in (
            lambda v: v.update(version=1), lambda v: v.update(version=True),
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
            self.assertEqual(value["records"], [])
            self.assertEqual(value["errors"], [{"ordinal": 0, "reason": "capture-unavailable"}])
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_exportable(value)

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
            self.assertEqual(result["records"], [])
            self.assertEqual(len(result["errors"]), 1)
            self.assertEqual(runner.command_results[0]["protectedTargetBundle"][key], value)

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


class AuthorityPreimageV2Tests(unittest.TestCase):
    setUp = CaptureTests.setUp
    capture = CaptureTests.capture
    def private(self, root, index=0):
        return ci.strict_json_loads((root / f"{index}.json").read_text("utf-8"), label="fixture")

    def rebind(self, private):
        record, expected, binding = (private[k] for k in ("commandRecord", "expectedAuthority", "captureBinding"))
        binding.update(commandRecordDigest=ci.canonical_failure_digest(record),
            expectedAuthorityDigest=ci.canonical_failure_digest(expected),
            targetsDigest=ci.canonical_failure_digest(expected["targets"]),
            executionInputBundleDigest=record["executionInputBundleDigest"],
            executionInputContextDigest=ci.canonical_failure_digest(record["executionInputBundleDigest"]))

    def two_targets(self):
        target = ci._target_authority(ci.REPO_ROOT, "backend/package.json")
        return [target, {**copy.deepcopy(target), "path": "fixture/second.js"}]

    def test_v2_producer_replay_exact_production_digest_chains_and_private_fields(self):
        for platform in ("ubuntu", "windows"):
            runner = full_scope_fixture(platform)
            for phase in ("producer", "fresh-replay"):
                name = platform + phase
                _, summary = self.capture(runner, name, phase)
                self.assertEqual(summary["errors"], [])
                self.assertEqual(summary["selectedCount"], 5 if platform == "windows" else 4)
                diagnostic.validate_exportable(summary)
                for index, row in enumerate(summary["records"]):
                    private = self.private(self.base / name, index)
                    record, expected, binding = (private[k] for k in ("commandRecord", "expectedAuthority", "captureBinding"))
                    self.assertEqual(diagnostic._json(record), diagnostic._json(runner.command_results[index]))
                    self.assertEqual(diagnostic._json(expected), diagnostic._json(runner.command_plan[index]))
                    self.assertEqual(ci.canonical_failure_digest(expected["targets"]), row["authorityFieldDigests"]["targets"])
                    inner = ci.execution_input_bundle_digest(record["executionInputs"])
                    self.assertEqual(inner, record["executionInputBundleDigest"])
                    self.assertEqual(ci.canonical_failure_digest(inner), row["contextFieldDigests"]["executionInputBundleDigest"])
                    self.assertNotEqual(inner, row["contextFieldDigests"]["executionInputBundleDigest"])
                    self.assertEqual(ci.canonical_failure_digest(record), row["commandRecordDigest"])
                    self.assertEqual(set(record["targets"][0]), set(diagnostic.TARGET_SCHEMA))
                    self.assertEqual(set(record["executionInputs"][0]), set(diagnostic.INPUT_SCHEMA))
                    self.assertEqual(binding["candidateCommit"], runner.execution_binding["checkoutCommit"])
                    self.assertEqual(binding["candidateTree"], runner.execution_binding["checkoutTree"])
                    self.assertEqual((binding["ordinal"], binding["commandId"], binding["phase"], binding["platform"], binding["transaction"]),
                                     (record["ordinal"], record["commandId"], phase, platform, TRANSACTION))
                self.assertEqual(diagnostic.read_capture(ci, self.base / name, ci.REPO_ROOT), summary)

    def test_v2_one_field_target_mutation_and_input_reordering_rejected(self):
        runner = capture_fixture(targets=self.two_targets())
        _, summary = self.capture(runner)
        original = self.private(self.base / "capture")
        private = copy.deepcopy(original)
        private["expectedAuthority"]["targets"][0]["size"] += 1
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.validate_private(ci, private)
        private = copy.deepcopy(original)
        record = private["commandRecord"]
        record["executionInputs"].reverse()
        record["executionInputBundleDigest"] = ci.execution_input_bundle_digest(record["executionInputs"])
        record["protectedTargetBundle"]["executionInputs"] = copy.deepcopy(record["executionInputs"])
        record["protectedTargetBundle"]["executionInputBundleDigest"] = record["executionInputBundleDigest"]
        self.rebind(private)
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.validate_private(ci, private)
        self.assertEqual(diagnostic.read_capture(ci, self.base / "capture", ci.REPO_ROOT), summary)

    def test_v2_mode_reparse_content_identity_and_bundle_mutations_rejected(self):
        self.capture(capture_fixture(targets=self.two_targets()))
        original = self.private(self.base / "capture")
        changes = [
            (("targets", 0, "modeType"), "other"),
            (("targets", 0, "reparsePoint"), True),
            (("targets", 0, "fileIdentity", "reparsePoint"), True),
            (("targets", 0, "sha256"), "f" * 64),
            (("executionInputs", 0, "inputMode"), "NONE"),
            (("executionInputs", 0, "actualSha256"), "f" * 64),
            (("executionInputs", 0, "actualByteLength"), 0),
            (("executionInputs", 0, "plannedStableIdentity", "writeTimeNs"), "123"),
            (("protectedTargetBundle", "preExecutionIdentities", 0, "heldStableIdentity", "reparsePoint"), True),
            (("protectedTargetBundle", "cleanupState"), "open"),
            (("protectedTargetBundle", "mutationDetected"), True),
        ]
        for path, change in changes:
            with self.subTest(field=path):
                private = copy.deepcopy(original)
                parent = private["commandRecord"]
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = change
                if path[0] == "targets":
                    private["expectedAuthority"]["targets"] = copy.deepcopy(private["commandRecord"]["targets"])
                self.rebind(private)
                with self.assertRaises(diagnostic.DiagnosticError):
                    diagnostic.validate_private(ci, private)

    def test_v2_physical_fields_are_retained_exactly_and_projection_is_offline(self):
        targets = self.two_targets()
        variants = [targets, copy.deepcopy(targets)]
        for target in variants[1]:
            target["canonicalSourcePath"] += ".physical-only-e\u0301"
            for key in ("deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs"):
                target["fileIdentity"][key] = str(int(target["fileIdentity"][key]) + 1)
        captures = []
        for index, variant in enumerate(variants):
            runner = capture_fixture(targets=variant)
            _, public = self.capture(runner, str(index), "producer" if index == 0 else "fresh-replay")
            self.assertEqual(public["errors"], [])
            private = self.private(self.base / str(index))
            self.assertEqual(diagnostic._json(private["expectedAuthority"]["targets"]), diagnostic._json(variant))
            self.assertEqual(private["commandRecord"]["executionInputs"][0]["canonicalSourcePath"], variant[0]["canonicalSourcePath"])
            captures.append((public["records"][0], private))
        self.assertNotEqual(captures[0][0]["authorityFieldDigests"]["targets"], captures[1][0]["authorityFieldDigests"]["targets"])
        # Separate offline reviewer action on synthetic retained values, never in capture.
        self.assertEqual(ci._portable_command_plan_value([captures[0][1]["expectedAuthority"]]),
                         ci._portable_command_plan_value([captures[1][1]["expectedAuthority"]]))
        self.assertEqual(ci._validated_portable_protected_input_bundle_digest(captures[0][1]["commandRecord"]),
                         ci._validated_portable_protected_input_bundle_digest(captures[1][1]["commandRecord"]))
        self.assertIsNotNone(ci._validated_portable_protected_input_bundle_digest(captures[0][1]["commandRecord"]))

    def test_v2_capture_and_reader_never_call_portable_projection_or_reconstruction(self):
        runner = capture_fixture(targets=self.two_targets())
        names = ("_portable_command_plan_value", "_canonical_transcript_record", "_portable_protected_bundle_authority",
                 "_validated_portable_protected_input_bundle_digest", "_canonical_protected_execution_inputs",
                 "_reconstructed_protected_execution_inputs")
        with contextlib.ExitStack() as stack:
            guards = [stack.enter_context(mock.patch.object(ci, name, side_effect=AssertionError("projection called"))) for name in names]
            _, summary = self.capture(runner)
            self.assertEqual(summary["errors"], [])
            self.assertEqual(diagnostic.read_capture(ci, self.base / "capture", ci.REPO_ROOT), summary)
            for guard in guards:
                guard.assert_not_called()

    def test_v2_windows_702_exact_command_streams_targets_inputs_and_cleanup(self):
        runner = full_scope_fixture("windows")
        _, summary = self.capture(runner)
        self.assertEqual([r["ordinal"] for r in summary["records"]], [687, 692, 695, 701, 702])
        row = summary["records"][-1]
        private = self.private(self.base / "capture", 4)
        self.assertEqual(private["commandRecord"], runner.command_results[-1])
        self.assertEqual(private["expectedAuthority"]["targets"], runner.command_plan[-1]["targets"])
        self.assertEqual(private["commandRecord"]["executionInputs"], runner.command_results[-1]["executionInputs"])
        for name in ("stdout", "stderr"):
            self.assertEqual((self.base / f"capture/4.{name}.bin").read_bytes(), getattr(runner.captures[-1], name + "_raw"))
            self.assertTrue(row["streams"][name]["exact"])
        self.assertEqual(row["containment"]["backend"], "windows-job-object" if os.name == "nt" else "linux-subreaper-pidfd-proc-supervisor")
        self.assertEqual(row["containment"]["cleanup"], "closed")
        self.assertFalse(row["containment"]["mutation"])
        diagnostic.validate_exportable(summary)
        for missing in (687, 692, 695, 701, 702):
            partial = copy.deepcopy(runner)
            partial.command_results = [r for r in partial.command_results if r["ordinal"] != missing]
            with self.subTest(missing=missing), self.assertRaises(diagnostic.DiagnosticError):
                self.capture(partial, "missing-" + str(missing))
        # A command-count overflow must fail, never silently omit the late record.
        with mock.patch.object(diagnostic, "MAX_COMMANDS", 4), self.assertRaises(diagnostic.DiagnosticError):
            self.capture(runner, "overflow-702")
        failed = copy.deepcopy(runner)
        failed.captures[-1].stderr_raw = None
        _, incomplete = self.capture(failed, "failed-702")
        self.assertEqual(incomplete["errors"], [{"ordinal": 702, "reason": "capture-unavailable"}])
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.validate_exportable(incomplete)
        import issue13_acquisition_transport as transport
        with self.assertRaises(diagnostic.DiagnosticError):
            transport.snapshot_capture(ci, diagnostic, self.base / "failed-702", ci.REPO_ROOT,
                {k: incomplete[k] for k in ("transaction", "phase", "platform")})

    def test_v2_malformed_partial_duplicate_and_compact_authority_fail_closed(self):
        self.capture(capture_fixture(targets=self.two_targets()))
        original = self.private(self.base / "capture")
        mutations = [
            lambda p: p.pop("captureBinding"),
            lambda p: p["expectedAuthority"].pop("targets"),
            lambda p: p["commandRecord"].pop("executionInputs"),
            lambda p: p["expectedAuthority"]["targets"][0].pop("modeType"),
            lambda p: p["commandRecord"]["executionInputs"][0].pop("plannedStableIdentity"),
            lambda p: p["expectedAuthority"]["targets"][0].update(unrecognized=CANARY),
            lambda p: p["expectedAuthority"]["targets"][0].update(fileIdentity=None),
            lambda p: p["expectedAuthority"]["targets"][0]["fileIdentity"].update(deviceOrVolume=True),
            lambda p: p["commandRecord"]["executionInputs"][0].update(actualByteLength=True),
            lambda p: p["commandRecord"].update(executionInputs=[]),
            lambda p: p["expectedAuthority"].update(targets=[p["expectedAuthority"]["targets"][0]] * 2),
            lambda p: p["commandRecord"].update(executionInputs=[p["commandRecord"]["executionInputs"][0]] * 2),
        ]
        for index, mutate in enumerate(mutations):
            bad = copy.deepcopy(original)
            mutate(bad)
            with self.subTest(case=index), self.assertRaises((ValueError, KeyError, TypeError)):
                diagnostic.validate_private(ci, bad)
        # Duplicates remain invalid even with coherent arrays and recomputed
        # record/bundle commitments; hashing is not a substitute for the schema.
        for paths in (("fixture/same.js", "fixture/same.js"), ("fixture/\u00e9.js", "fixture/e\u0301.js")):
            bad = copy.deepcopy(original)
            for target, path in zip(bad["expectedAuthority"]["targets"], paths):
                target["path"] = path
            rebuilt = fixtures.synthetic_record_from_spec(bad["expectedAuthority"])
            for key in ("targets", "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
                bad["commandRecord"][key] = rebuilt[key]
            self.rebind(bad)
            with self.assertRaisesRegex(diagnostic.DiagnosticError, "authority-duplicate"):
                diagnostic.validate_private(ci, bad)
        # Duplicate JSON properties fail in the production parser before schema validation.
        raw = diagnostic._json(original).replace(b'"expectedAuthority":{', b'"expectedAuthority":{},"expectedAuthority":{', 1)
        with self.assertRaises(ValueError):
            ci.strict_json_loads(raw.decode("ascii"), label="fixture")

    def test_v2_binding_tampering_public_private_separation_and_no_public_paths(self):
        runner, summary = self.capture()
        original = self.private(self.base / "capture")
        row = summary["records"][0]
        for field, change in (("ordinal", 702), ("commandId", "standalone-packaging"), ("phase", "fresh-replay"),
                              ("platform", "ubuntu" if runner.platform == "windows" else "windows"),
                              ("transaction", "0" * 32), ("candidateCommit", "1" * 40), ("candidateTree", "2" * 40),
                              ("commandRecordDigest", "sha256:" + "0" * 64)):
            bad = copy.deepcopy(original)
            bad["captureBinding"][field] = change
            with self.subTest(field=field), self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_authority_preimages(ci, bad, row=row, summary=summary)
        public = diagnostic.validate_public(summary)
        for secret in (CANARY, runner.command_results[0]["commandId"], runner.command_plan[0]["targets"][0]["canonicalSourcePath"]):
            self.assertNotIn(secret.encode(), public)
        for injection in ("targets", "fileIdentity", "executionInputs", "rawStreams", "commandRecord", "candidateCommit"):
            bad = copy.deepcopy(summary)
            bad["records"][0]["authorityPreimages"][injection] = CANARY
            with self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_public(bad)

    def test_v2_per_value_count_and_total_size_limits(self):
        runner = capture_fixture(targets=self.two_targets())
        _, summary = self.capture(runner)
        private = self.private(self.base / "capture")
        cases = {
            "MAX_TARGET_BYTES": len(diagnostic._json(private["expectedAuthority"]["targets"])),
            "MAX_INPUT_BYTES": max(len(diagnostic._json(private["commandRecord"]["executionInputs"])), len(diagnostic._json(private["expectedAuthority"]))),
            "MAX_COMMAND_RECORD_BYTES": len(diagnostic._json(private["commandRecord"])),
            "MAX_RECORD_BYTES": len(diagnostic._json(private)),
            "MAX_AUTHORITY_ENTRIES": 2,
        }
        for name, size in cases.items():
            with self.subTest(limit=name), mock.patch.object(diagnostic, name, size):
                diagnostic.validate_private(ci, private)
            with self.subTest(over=name), mock.patch.object(diagnostic, name, size - 1), self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_private(ci, private)
        excessive = copy.deepcopy(private)
        excessive["expectedAuthority"]["targets"][0]["size"] = 2 ** 40 + 1
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.validate_private(ci, excessive)
        with mock.patch.object(diagnostic, "MAX_TOTAL_BYTES", diagnostic.MAX_PUBLIC_BYTES):
            _, result = self.capture(runner, "total-overflow")
            self.assertEqual(result["records"], [])
            self.assertEqual(len(result["errors"]), 1)
        with mock.patch.object(diagnostic, "MAX_TOTAL_BYTES", 1), self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.read_capture(ci, self.base / "capture", ci.REPO_ROOT)
        self.assertEqual(diagnostic.MAX_TOTAL_BYTES, 48 * 1024 * 1024 + 256 * 1024)

    def test_v2_realistic_920_entry_record_survives_unchanged_encrypted_container(self):
        import gzip
        import tarfile
        import issue13_acquisition_transport as transport
        target = self.two_targets()[0]
        targets = [{**copy.deepcopy(target), "path": f"fixture/{i:04d}.js"} for i in range(920)]
        runner = full_scope_fixture()
        large = capture_fixture(targets=targets, profile="all", platform_name=runner.platform, ordinals=[687],
            command_ids=["frontend-security:adminFrontendGuard.test.js"])
        runner.command_plan[0], runner.command_results[0], runner.captures[0] = large.command_plan[0], large.command_results[0], large.captures[0]
        _, summary = self.capture(runner)
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records"][0]["privateRecordBytes"], 2 * 1024 * 1024)
        context = {k: summary[k] for k in ("transaction", "phase", "platform")}
        candidate = {"commit": runner.execution_binding["checkoutCommit"], "tree": runner.execution_binding["checkoutTree"]}
        actual, files = transport.snapshot_capture(ci, diagnostic, self.base / "capture", ci.REPO_ROOT, context, candidate=candidate)
        self.assertEqual(actual, summary)
        packed = transport.private_tar(files, {"schema": "Issue13EncryptedAcquisitionBundle"})
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(packed)), mode="r:") as archive:
            for name, data in files.items():
                self.assertEqual(archive.extractfile(name).read(), data)
        for key in candidate:
            with self.subTest(binding=key), self.assertRaises(transport.TransportError):
                transport.snapshot_capture(ci, diagnostic, self.base / "capture", ci.REPO_ROOT, context, candidate={**candidate, key: "f" * 40})
        self.assertEqual(transport.MAX_PRIVATE_RECORD, diagnostic.MAX_RECORD_BYTES)
        self.assertEqual((transport.MAX_BUNDLE, transport.MAX_CIPHERTEXT), (49 * 1024 * 1024, 50 * 1024 * 1024))

    def test_v2_ordinary_source_and_transport_crypto_are_byte_unchanged(self):
        parent = "ddf1e597"
        def before(name):
            return subprocess.check_output(["git", "cat-file", "blob", parent + ":developer/tests/ci/" + name], cwd=ci.REPO_ROOT).decode("utf-8").replace("\r\n", "\n")
        name = "run_ci_foundation.py"
        old, new = before(name), (ci.REPO_ROOT / "developer/tests/ci" / name).read_text("utf-8")
        # The only ordinary-source delta allowed is the terminal observer's helper pins.
        pattern = r'\("issue13_diagnostic_capture", \("[0-9a-f]{64}", "[0-9a-f]{64}"\)\)'
        import re
        self.assertEqual(re.sub(pattern, "CAPTURE_HELPER_PINS", old), re.sub(pattern, "CAPTURE_HELPER_PINS", new))
        import issue13_acquisition_transport as transport
        for name, functions in (("issue13_acquisition_transport.py", ("PublicKeyring", "packets", "public_armor", "Destination", "source_identity", "live_context")),
                                ("issue13_windows_transport_recovery.py", ("RecoveryKeyring", "synthetic_preflight", "source_identity", "preflight"))):
            old = before(name)
            new = (ci.REPO_ROOT / "developer/tests/ci" / name).read_text("utf-8")
            old_nodes = {n.name: ast.get_source_segment(old, n) for n in ast.parse(old).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            new_nodes = {n.name: ast.get_source_segment(new, n) for n in ast.parse(new).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            for function in functions:
                self.assertEqual(old_nodes[function], new_nodes[function])
        for path in (".github/workflows/ci.yml", ".github/workflows/issue-13-acquisition.yml", ".github/workflows/issue-13-windows-transport-recovery.yml"):
            old = subprocess.check_output(["git", "cat-file", "blob", parent + ":" + path], cwd=ci.REPO_ROOT).replace(b"\r\n", b"\n")
            self.assertEqual(old, (ci.REPO_ROOT / path).read_bytes().replace(b"\r\n", b"\n"))

    def test_v2_windows_transport_checks_702_before_encryption_and_static_contracts(self):
        import issue13_windows_transport_recovery as recovery
        import test_issue13_windows_transport_recovery as windows_tests
        control = windows_tests.RecoveryTests()
        control.root = self.base
        runner, env, summary, root = control.fixture_capture("producer", "all")
        self.assertEqual(summary["records"][-1]["ordinal"], 702)
        candidate = control.candidate(runner)
        with mock.patch.object(recovery, "source_identity", return_value=candidate), \
             mock.patch.object(recovery, "validated_preflight", return_value={}), \
             mock.patch.object(recovery, "RuntimeLease", side_effect=recovery.RecoveryError("encryption-process")) as encrypt:
            with self.assertRaisesRegex(recovery.RecoveryError, "encryption-process"):
                recovery.export_capture(ci.REPO_ROOT, env, "producer", summary["transaction"], "failure")
            encrypt.assert_called_once()
            (root / "4.stderr.bin").write_bytes(b"missing exact packaging bytes")
            encrypt.reset_mock()
            with self.assertRaises(diagnostic.DiagnosticError):
                recovery.export_capture(ci.REPO_ROOT, env, "producer", summary["transaction"], "failure")
            encrypt.assert_not_called()
        # Pure static controls need no provisioned runtime or preflight execution.
        # Retain the test host's Git worktree ownership configuration for these
        # read-only history checks; the encryption child's environment is unrelated.
        def read_history(repo, *args, **kwargs):
            data = subprocess.check_output(["git", *args], cwd=repo)
            self.assertLessEqual(len(data), kwargs.get("limit", 2 * 1024 * 1024))
            return data
        with mock.patch.object(recovery.base, "git_bytes", side_effect=read_history):
            control.test_source_scope_and_static_no_preflight_runner_or_secret_operations()
            control.test_workflow_pass_only_topology_no_ubuntu_or_rerun_ordinary_results_preserved()

    def test_v2_byte_exact_non_interference_for_selected_records_and_envelopes(self):
        results = []
        for family in diagnostic.FAMILIES:
            for rejected in (False, True):
                runner = capture_fixture(family=family)
                claims = claims_for(runner)
                if rejected:
                    claims["command-results.json"]["records"][0]["stdoutSha256"] = "f" * 64
                    fixtures.coherently_rebind_claimed_transcript(claims)
                    runner.violations = [{"id": "UNKNOWN-NONPASS", "commandId": runner.command_results[0]["commandId"]}]
                    runner.hard_gate_results = [{"id": "STANDALONE-PACKAGE-INTEGRITY", "status": "fail", "detail": "fixed fixture"}]
                context = fixtures.synthetic_external_context(runner.execution_binding)
                runner.run = mock.Mock(return_value=fixtures.empty_comparison())
                runner.close_execution_leases = mock.Mock()
                def snapshot():
                    transcript, errors = ci.run_verification_replay(copy.deepcopy(claims), expected_context=context, verification_runner=runner)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT" if rejected else "PASS")
                    self.assertEqual(bool(errors), rejected)
                    return {
                        "authoritativeCommandRecords": diagnostic._json(runner.command_results),
                        "rawExecutionResults": diagnostic._json([{
                            "fields": {k: v for k, v in c.__dict__.items() if type(v) is not bytes},
                            "rawBytesHex": {k: v.hex() for k, v in c.__dict__.items() if type(v) is bytes},
                        } for c in runner.captures]),
                        "observations": diagnostic._json(runner.observations),
                        "canonicalTranscript": diagnostic._json(ci.verification_replay_transcript(runner)),
                        "violations": diagnostic._json(runner.violations),
                        "hardGates": diagnostic._json(runner.hard_gate_results),
                        "replayEligibility": diagnostic._json({"transcript": transcript, "errors": errors}),
                        "authorizationEnvelope": diagnostic._json({k: transcript[k] for k in (
                            "replayAuthorizationEnvelopeDigest", "verifierReplayContextBinding", "verifierReplayContextDigest", "finalAcceptance")}),
                    }
                before = snapshot()
                for phase in ("producer", "fresh-replay"):
                    for mode in ("disabled", "enabled", "schema-failure", "writer-failure"):
                        leaf = f"{family}-{rejected}-{phase}-{mode}"
                        args = SimpleNamespace() if mode == "disabled" else SimpleNamespace(
                            issue13_diagnostic_root=str(self.base / leaf),
                            issue13_diagnostic_transaction=CANARY if mode == "schema-failure" else TRANSACTION)
                        with contextlib.ExitStack() as stack:
                            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                            if mode == "writer-failure":
                                stack.enter_context(mock.patch.object(os, "open", side_effect=OSError(CANARY)))
                            ci._write_issue13_diagnostics(args, runner, phase)
                        after = snapshot()
                        for key in before:
                            self.assertEqual(before[key], after[key], (family, phase, mode, key))
                        if mode == "enabled":
                            self.assertEqual(diagnostic.read_capture(ci, self.base / leaf, ci.REPO_ROOT)["errors"], [])
                        results.append({"family": family, "control": "REJECT" if rejected else "PASS", "phase": phase,
                            "capture": mode, "components": {k: {"byteEqual": True, "bytes": len(v), "sha256": diagnostic.sha(v)} for k, v in before.items()}})
        NON_INTERFERENCE_RESULTS["authority"] = results

    def test_v2_actual_cli_exit_codes_and_ordinary_output_do_not_change(self):
        results = []
        for phase in ("producer", "fresh-replay"):
            for status in (("PASS", "FAIL", "EVIDENCE-ERROR") if phase == "producer" else ("PASS", "FAIL")):
                runner = capture_fixture()
                runner.run = mock.Mock(return_value=fixtures.empty_comparison())
                runner.require_all_tools = mock.Mock()
                runner.close_execution_leases = mock.Mock()
                runner.cleanup_task_resources = mock.Mock()
                summary = {"status": status, "executionBinding": runner.execution_binding}
                baseline = None
                for mode in ("disabled", "enabled", "schema-failure", "writer-failure"):
                    leaf = f"cli-{phase}-{status}-{mode}"
                    argv = ["--profile", "static"]
                    if phase == "fresh-replay":
                        argv = ["--verify-evidence", "--expected-profile", "static", "--untrusted-evidence-root", str(self.base)]
                    if mode != "disabled":
                        argv += ["--issue13-diagnostic-root", str(self.base / leaf), "--issue13-diagnostic-transaction",
                                 CANARY if mode == "schema-failure" else TRANSACTION]
                    with contextlib.ExitStack() as stack:
                        out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                        err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                        stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
                        # Already-completed in-memory controls; no profile or command executes.
                        patches = {
                            "capture_live_external_authority": mock.Mock(return_value=SimpleNamespace(binding_mode="local")),
                            "prepare_verification_authority": mock.Mock(return_value=(None, runner)),
                            "verify_evidence_with_replay": mock.Mock(return_value=([] if status == "PASS" else ["fixed rejection"], {})),
                            "select_generation_evidence_output": mock.Mock(return_value=(self.base / "ordinary", self.base)),
                            "validate_evidence_root_absent": mock.Mock(return_value=[]),
                            "read_json": mock.Mock(return_value={}), "validate_baseline_document": mock.Mock(return_value=[]),
                            "FoundationRunner": mock.Mock(return_value=runner),
                            "build_generation_execution_binding": mock.Mock(return_value=runner.execution_binding),
                            "create_fresh_evidence_root": mock.Mock(),
                            "write_evidence": mock.Mock(side_effect=OSError("fixed evidence error")) if status == "EVIDENCE-ERROR" else mock.Mock(return_value=summary),
                        }
                        for name, replacement in patches.items():
                            stack.enter_context(mock.patch.object(ci, name, replacement))
                        if mode == "writer-failure":
                            stack.enter_context(mock.patch.object(os, "open", side_effect=OSError(CANARY)))
                        code = ci.main(argv)
                    ordinary_stderr = "".join(line for line in err.getvalue().splitlines(keepends=True)
                                               if not line.startswith(diagnostic.MARKER + ":"))
                    observed = (code, out.getvalue().encode(), ordinary_stderr.encode())
                    if baseline is None:
                        baseline = observed
                    self.assertEqual(observed, baseline, (phase, status, mode))
                    self.assertEqual(code, ci.EXIT_SUCCESS if status == "PASS" else ci.EXIT_RUNNER_ERROR if status == "EVIDENCE-ERROR" else ci.EXIT_POLICY_VIOLATION)
                    if mode == "enabled":
                        self.assertEqual(diagnostic.read_capture(ci, self.base / leaf, ci.REPO_ROOT)["errors"], [])
                    self.assertNotIn(CANARY, err.getvalue())
                    results.append({"phase": phase, "control": status, "capture": mode, "exitCode": code,
                                    "ordinaryStdoutByteEqual": True, "ordinaryStderrByteEqual": True})
        NON_INTERFERENCE_RESULTS["cli"] = results


if __name__ == "__main__":
    unittest.main(verbosity=2)
