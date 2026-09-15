"""W702-A2/E1 authority and exact retention, outside the 476-test inventory.

Hosted-shaped contexts use explicit fixtures. E1 retains exact safe Windows
process bytes without a standalone reporter parser or portable identity.
"""
from __future__ import annotations

import contextlib
import copy
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace
import hashlib
import inspect
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
import test_backend_canonical_portable_result as backend

PATH = "developer/tests/ci/test_standalone_packaging.py"
STREAM = b"Ran 4 tests in 0.125s\n\nOK\n"


def runner_fixture(root, platform="windows"):
    base = backend.fixture(platform)
    template, _, _ = backend.replay_fixture(base, base)
    runner = object.__new__(ci.FoundationRunner)
    runner.__dict__.update(vars(template))
    target = root / PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"# protected standalone fixture\n")
    spec = fixtures.synthetic_command_spec("standalone-packaging", "standalone-packaging", 0,
        targets=[ci._target_authority(root, PATH)], execution_input_mode="PROTECTED-TARGET-BUNDLE")
    argv = [sys.executable, "-B", PATH]
    spec.update(profile="all", platform=platform, toolRole="python-standalone-test",
                resultSemantics="exit-zero-required", argv=argv, logicalArgv=argv, executionArgv=argv)
    record = fixtures.synthetic_record_from_spec(spec)
    capture = ci.CommandCapture(command_id=spec["commandId"], command_class=spec["commandClass"],
        argv=argv, executed=True, exit_code=0, duration_seconds=0.125,
        stdout="", stderr=STREAM.decode(), stdout_raw=b"", stderr_raw=STREAM,
        stdout_bytes=0, stderr_bytes=len(STREAM), include_preview=False,
        containment="windows-job-object" if platform == "windows" else "linux-subreaper-pidfd-proc-supervisor",
        process_tree_status="contained-clean", containment_disposition="natural-exit-reaped",
        descendants_observed=1, descendants_reaped=1, execution_input_mode="PROTECTED-TARGET-BUNDLE")
    record.update({k: v for k, v in capture.evidence().items() if k not in (
        "executionInputs", "executionInputBundleDigest", "protectedTargetBundle", "targetExecutionLease")})
    record.pop("parsedFailureSummary", None)
    runner.command_plan, runner.command_results, runner.observations = [spec], [record], []
    runner.command_plan_by_id = {spec["commandId"]: spec}
    runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
    runner.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
    runner.execution_binding = fixtures.synthetic_execution_binding("all", runner.command_plan_digest,
                                                                    platform_name=platform)
    runner.execution_binding.update(bindingMode="github-actions", producerJobId=(
        "windows-compatibility-producer" if platform == "windows" else "ubuntu-canonical-producer"),
        runId="123456", runAttempt="1", eventName="workflow_dispatch", repository="fixture/observation-authority")
    runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
        k: v for k, v in runner.execution_binding.items() if k != "producerInvocationId"})
    runner.__dict__.pop("authorization_context_binding", None)
    runner.__dict__.pop("authorization_context_binding_digest", None)
    runner.execution_external_authority = external_for(runner.execution_binding, verifier=False)
    runner.child_environment = {}
    runner.target_phase_hook = None
    runner.close_execution_leases = mock.Mock()
    runner.cleanup_task_resources = mock.Mock()
    runner.private_temp_handle = None
    ci.finalize_evidence_transcript(runner)
    return runner, capture


def external_for(binding, *, verifier):
    role = ci._workflow_authority_for_producer(binding["producerJobId"])
    return ci.synthetic_execution_external_authority(runner_os=binding["producerRunnerOS"],
        job_id=role["verifierJobId"] if verifier else role["producerJobId"],
        run_id=binding["runId"], run_attempt=binding["runAttempt"], event_name=binding["eventName"],
        repository=binding["repository"], checkout_sha=binding["checkoutCommit"])


def raw_for(record):
    raw = ci.make_raw_observation(record["commandId"], record["ordinal"], 0,
        "process-output-v1", "command:standalone-packaging", PATH,
        {"executed": True, "exitCode": 0, "stdout": "", "stderr": STREAM.decode(), "error": None},
        ci.command_output_digest(record))
    # Exact synthetic fixture bytes, not a production retention change. The
    # ordinary constructor intentionally keeps its pre-A2 sanitization behavior.
    raw["rawStructuredFields"]["stderr"] = STREAM.decode()
    raw["producerRecordDigest"] = ci._producer_record_digest({
        key: value for key, value in raw.items() if key != "producerRecordDigest"})
    return raw


@contextlib.contextmanager
def authority_fixture(*, platform="windows", authorize=True, observation=True):
    with tempfile.TemporaryDirectory(prefix="observation-authority-") as temp:
        root = Path(temp)
        runner, capture = runner_fixture(root, platform)
        output = root / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=root)
        summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output,
                                    evidence_authority_root=root)
        documents, snapshots, errors = ci._read_evidence_documents_for_replay(output)
        if errors:
            raise AssertionError(errors)
        context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                          fresh_runtime_closure_digest=runner.runtime_closure_digest)
        runner.external_verification_context = context
        runner.verifier_execution_binding = context.verifier_binding()
        runner.execution_external_authority = external_for(runner.execution_binding, verifier=True)
        capability = ci._issue_synthetic_observation_authority_for_test(runner, context) if authorize else None
        comparison = {key: summary[field] for key, field in (
            ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
            ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
        runner.run = mock.Mock(return_value=comparison)
        case = SimpleNamespace(root=root, output=output, runner=runner, context=context, documents=documents,
                               snapshots=snapshots, capability=capability, comparison=comparison, capture=capture)
        if observation:
            record = documents["command-results.json"]["records"][0]
            record["producerObservations"] = [raw_for(record)]
            reseal(case)
        yield case


def reseal(case):
    backend.reseal_producer(case)
    documents, snapshots, errors = ci._read_evidence_documents_for_replay(case.output)
    if errors:
        raise AssertionError(errors)
    case.documents, case.snapshots = documents, snapshots


def validation(case):
    return ci._ObservationValidation(case.runner, case.context,
        case.documents["command-results.json"]["records"], case.runner.command_plan,
        case.documents, case.snapshots, case.output)


def semantic_verify(case):
    return ci._validate_evidence_semantics_with_authority(case.documents, case.snapshots,
        expected_command_plan=case.runner.command_plan, expected_context=case.context,
        observation_runner=case.runner, observation_root=case.output)


@contextlib.contextmanager
def counters():
    with mock.patch.object(ci, "_rederive_observation_record", wraps=ci._rederive_observation_record) as reconstruction, \
         mock.patch.object(ci, "_derive_authoritative_evidence", wraps=ci._derive_authoritative_evidence) as derivation, \
         mock.patch.object(ci, "parse_node_test_semantic_result", wraps=ci.parse_node_test_semantic_result) as parser, \
         mock.patch.object(backend.portable, "_parse_stdout", wraps=backend.portable._parse_stdout) as backend_parser:
        yield SimpleNamespace(reconstruction=reconstruction, derivation=derivation,
                              parser=parser, backend_parser=backend_parser)


class StandaloneObservationAuthorityTest(unittest.TestCase):
    negatives = 0

    def assert_denied(self, case, label, operation=None):
        with counters() as calls:
            try:
                errors = (operation or (lambda: semantic_verify(case)))()
            except (ValueError, TypeError):
                errors = ["denied"]
        self.assertTrue(errors, label)
        self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0), label)
        self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0), label)
        type(self).negatives += 1
        print("W702_AUTHORITY_DENIAL " + json.dumps({"case": label, "reconstruction_calls": 0,
            "authoritative_derivation_calls": 0, "parser_calls": 0, "standalone_semantic_identity_calls": 0}))

    def test_windows_admission_and_both_five_file_validation_stages(self):
        with authority_fixture() as case, counters() as calls:
            proofs = ci._admit_standalone_observations(validation(case))
            self.assertEqual(len(proofs), 1)
            self.assertEqual(ci._verify_evidence_file_set(case.output, repo_root=case.root,
                expected_command_plan=case.runner.command_plan, expected_context=case.context,
                observation_runner=case.runner), [])
            self.assertEqual(semantic_verify(case), [])
            self.assertGreater(calls.reconstruction.call_count, 0)
            self.assertEqual(calls.derivation.call_count, 2)
            self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))
            self.assertEqual(case.runner.command_results[0]["producerObservations"], [])
            print("W702_AUTHORITY_ADMISSION Windows=PASS first_snapshot=PASS second_snapshot=PASS parser_calls=0 standalone_semantic_identity_calls=0")

    def test_linux_and_context_free_denial(self):
        with authority_fixture(platform="ubuntu") as case:
            self.assertIsNone(case.capability)
            self.assert_denied(case, "held Linux context")
        with authority_fixture(authorize=False) as case:
            self.assert_denied(case, "caller Windows plan without external authority")
        with authority_fixture() as case:
            self.assert_denied(case, "source-only five-file API", lambda: ci.verify_evidence_file_set(
                case.output, repo_root=case.root, expected_command_plan=case.runner.command_plan,
                expected_context=case.context))
            self.assert_denied(case, "source-only semantic wrapper", lambda: ci._validate_evidence_semantics(
                case.documents, case.snapshots, expected_command_plan=case.runner.command_plan,
                expected_context=case.context))
            record = case.documents["command-results.json"]["records"][0]
            self.assertTrue(ci._validate_raw_observation(record["producerObservations"][0], label="source", source=record))
            with counters() as calls:
                derived = ci.derive_authoritative_evidence("all", [], ["standalone-packaging"], [record],
                    case.runner.baseline, "windows", case.runner.command_plan,
                    case.runner.authorization_context_binding_digest, release_gate_required=False)
                transcript, errors = ci.run_verification_replay(case.documents, expected_context=case.context,
                    verification_runner=case.runner, repo_root=case.root)
            self.assertEqual(derived["violations"][0]["id"], "UNAUTHORIZED-PRODUCER-OBSERVATION")
            self.assertTrue(errors)
            self.assertIsNone(transcript)
            self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))
            case.runner.run.assert_not_called()

    def test_linux_platform_and_coherent_hosted_forgery(self):
        with authority_fixture(platform="ubuntu") as case:
            for document in case.documents.values():
                document["platform"] = "windows"
            backend.write_documents(case.output, case.documents)
            self.assert_denied(case, "Linux artifact relabels platform Windows")
        with authority_fixture(platform="ubuntu") as case, authority_fixture() as windows:
            # Replacing every document with a self-consistent Windows artifact
            # still cannot replace the independently held Linux runner/context.
            case.documents = copy.deepcopy(windows.documents)
            backend.write_documents(case.output, case.documents)
            case.documents, case.snapshots, errors = ci._read_evidence_documents_for_replay(case.output)
            self.assertEqual(errors, [])
            self.assert_denied(case, "coherent platform/job/invocation/digest forgery against held Linux")

    def test_lookalikes_free_os_and_synthetic_claim_cannot_mint(self):
        with authority_fixture() as case:
            context = case.context
            case.context = replace(context)
            self.assertIsNone(ci._prepare_verifier_observation_authority(case.runner, case.context,
                                                                         case.runner.execution_external_authority))
            self.assert_denied(case, "handmade equal expected-context dataclass")
            case.context = context
            original = case.capability
            case.runner._observation_authority = replace(original)
            self.assert_denied(case, "copied equal authority dataclass")
            case.runner._observation_authority = copy.deepcopy(original)
            self.assert_denied(case, "deserialized authority lookalike")
            case.runner._observation_authority = "Windows"
            self.assert_denied(case, "free Windows value")
        with authority_fixture(authorize=False) as case:
            case.documents["command-results.json"]["records"][0]["resultSemantics"] = "synthetic-replay-fixture"
            reseal(case)
            self.assert_denied(case, "producer synthetic resultSemantics claim")
            self.assertIsNone(ci._observation_authority_for_runner(case.runner, case.context))

    def test_wrong_command_associations(self):
        changes = {"commandId": "different-command", "commandClass": "direct-syntax",
                   "toolRole": "python-in-process", "executionInputMode": "NONE",
                   "resultSemantics": "synthetic-replay-fixture", "platform": "ubuntu",
                   "commandRole": "observation-producing", "required": False,
                   "allowedExecutionExits": [0, 1]}
        for field, value in changes.items():
            with self.subTest(field=field), authority_fixture() as case:
                case.documents["command-results.json"]["records"][0][field] = value
                reseal(case)
                self.assert_denied(case, "command " + field)

    def test_wrong_raw_associations_and_digests(self):
        changes = {"sourcePath": "developer/tests/ci/other.py", "sourceResultId": "command:other",
                   "commandOrdinal": 1, "observationOrdinal": 1, "occurrences": 2,
                   "observationKind": "normalized-fields-v1", "schemaVersion": 999,
                   "failurePathAuthority": {"forged": True}, "producerRecordDigest": "sha256:" + "0" * 64,
                   "sourceOutputDigest": "sha256:" + "0" * 64}
        for field, value in changes.items():
            with self.subTest(field=field), authority_fixture() as case:
                raw = case.documents["command-results.json"]["records"][0]["producerObservations"][0]
                raw[field] = value
                if field not in {"producerRecordDigest", "sourceOutputDigest"}:
                    reseal(case)
                else:
                    # Keep all aggregate claims coherent so only the particular
                    # raw binding check can reject the forged digest.
                    if field == "sourceOutputDigest":
                        raw["producerRecordDigest"] = ci._producer_record_digest({
                            k: v for k, v in raw.items() if k != "producerRecordDigest"})
                    commands = case.documents["command-results.json"]
                    source = commands["records"][0]
                    source["producerObservationSetDigest"] = ci.producer_observation_set_digest(source["producerObservations"])
                    commands["producerObservationUniverseDigest"] = ci.producer_observation_universe_digest(commands["records"])
                    commands["producerTranscriptDigest"] = ci.producer_transcript_digest(commands["commandPlanDigest"],
                        commands["records"], commands["actualCompletedCommandClasses"])
                    backend.write_documents(case.output, case.documents)
                    case.documents, case.snapshots, _ = ci._read_evidence_documents_for_replay(case.output)
                self.assert_denied(case, "raw " + field)

    def test_duplicate_raw_and_command_membership(self):
        for kind in ("duplicate observation", "duplicate command", "missing command"):
            with self.subTest(kind=kind), authority_fixture() as case:
                records = case.documents["command-results.json"]["records"]
                if kind == "duplicate observation":
                    records[0]["producerObservations"].append(copy.deepcopy(records[0]["producerObservations"][0]))
                elif kind == "duplicate command":
                    records.append(copy.deepcopy(records[0]))
                else:
                    case.runner.command_plan.clear()
                reseal(case)
                self.assert_denied(case, kind)

    def test_ineligible_execution_and_stream_authority(self):
        changes = {"executed": False, "started": False, "setupFailure": True, "exitCode": 1,
                   "timeoutStatus": "timed-out", "outputLimitStatus": "exceeded",
                   "processTreeStatus": "uncontained", "actualExecutionArgv": ["forged"],
                   "protectedTargetBundle": None, "stdoutSha256": "0" * 64}
        for field, value in changes.items():
            with self.subTest(field=field), authority_fixture() as case:
                case.documents["command-results.json"]["records"][0][field] = value
                reseal(case)
                self.assert_denied(case, "execution " + field)
        with authority_fixture() as case:
            fields = case.documents["command-results.json"]["records"][0]["producerObservations"][0]["rawStructuredFields"]
            fields["stderr"] = STREAM.decode().replace("0.125", "9.999")
            reseal(case)
            self.assert_denied(case, "raw retained duration bytes differ from source stream")

    def test_stale_admission_and_private_derivation_fail_before_reconstruction(self):
        changes = {
            "raw observation": lambda c: c.documents["command-results.json"]["records"][0]["producerObservations"][0]["rawStructuredFields"].update(stderr="changed"),
            "source record": lambda c: c.documents["command-results.json"]["records"][0].update(durationSeconds=99),
            "prepared plan": lambda c: c.runner.command_plan[0].update(toolRole="changed"),
            "expected context": lambda c: object.__setattr__(c.context, "run_attempt", "2"),
            "snapshot bytes": lambda c: c.snapshots.update({"summary.json": replace(c.snapshots["summary.json"], data=c.snapshots["summary.json"].data+b" ")}),
            "snapshot identity": lambda c: c.snapshots.update({"summary.json": replace(c.snapshots["summary.json"], identity=(1,2,3,4,5))}),
            "snapshot membership": lambda c: c.snapshots.pop("summary.md"),
            "live evidence bytes": lambda c: (c.output / "summary.md").write_bytes(b"changed"),
            "live membership": lambda c: (c.output / "extra.json").write_bytes(b"{}"),
        }
        for label, mutate in changes.items():
            with self.subTest(label=label), authority_fixture() as case:
                proofs = ci._admit_standalone_observations(validation(case))
                mutate(case)
                record = case.documents["command-results.json"]["records"][0]
                self.assertFalse(ci._matching_observation_admission(proofs, record["producerObservations"][0], record))
                self.assert_denied(case, "stale admission: " + label, lambda: ci._derive_authoritative_evidence_with_admission(
                    "all", [], ["standalone-packaging"], [record], case.runner.baseline, "windows",
                    case.runner.command_plan, case.runner.authorization_context_binding_digest,
                    release_gate_required=False, cross_job=True, admissions=proofs))

    def test_proof_immutability_and_lookalikes(self):
        with authority_fixture() as case:
            proof, = ci._admit_standalone_observations(validation(case))
            with self.assertRaises(FrozenInstanceError):
                proof.validation = b"forged"
            with self.assertRaises(FrozenInstanceError):
                case.capability.issuance = "forged"
            record = case.documents["command-results.json"]["records"][0]
            for fake in (replace(proof), copy.deepcopy(proof), "Windows"):
                self.assertFalse(ci._matching_observation_admission((fake,), record["producerObservations"][0], record))
                self.assert_denied(case, "proof lookalike " + type(fake).__name__, lambda: ci._derive_authoritative_evidence_with_admission(
                    "all", [], ["standalone-packaging"], [record], case.runner.baseline, "windows",
                    case.runner.command_plan, case.runner.authorization_context_binding_digest,
                    release_gate_required=False, cross_job=True, admissions=(fake,)))

    def test_snapshot_change_between_first_and_second_validation(self):
        with authority_fixture() as case:
            original = ci._read_evidence_documents_for_replay
            def second_snapshot(root):
                docs, snapshots, errors = original(root)
                docs["command-results.json"]["records"][0]["producerObservations"][0]["occurrences"] = 2
                return docs, snapshots, errors
            # The first valid stage may reconstruct. Reset counters at the
            # second reader and require zero calls after this new failed snapshot.
            with counters() as calls:
                def changed(root):
                    result = second_snapshot(root)
                    calls.reconstruction.reset_mock()
                    calls.derivation.reset_mock()
                    return result
                with mock.patch.object(ci, "_read_evidence_documents_for_replay", side_effect=changed):
                    errors, transcript = ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                        verification_runner=case.runner, evidence_authority_root=case.root, repo_root=case.root)
            self.assertTrue(errors)
            self.assertIsNone(transcript)
            self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))
            case.runner.run.assert_not_called()

    def test_synthetic_issuance_is_explicit_and_production_cannot_select_it(self):
        with authority_fixture(authorize=False) as case:
            self.assertIsNone(ci._observation_authority_for_runner(case.runner, case.context))
            self.assert_denied(case, "synthetic authority before explicit test issuance")
            self.assertIsNotNone(ci._issue_synthetic_observation_authority_for_test(case.runner, case.context))
            self.assertEqual(semantic_verify(case), [])
            with self.assertRaisesRegex(ValueError, "synthetic"):
                ci.build_generation_execution_binding(case.runner, external_authority=case.runner.execution_external_authority)
            with self.assertRaisesRegex(ValueError, "live external authority"):
                ci.prepare_verification_authority(SimpleNamespace(), external_authority=case.runner.execution_external_authority)

    def test_live_capture_requires_process_provenance(self):
        with authority_fixture() as case:
            binding = case.runner.execution_binding
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "windows-compatibility",
                "RUNNER_OS": "Windows", "GITHUB_RUN_ID": binding["runId"], "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": binding["eventName"], "GITHUB_REPOSITORY": binding["repository"],
                "GITHUB_SHA": binding["checkoutCommit"]}
            supplied = ci.capture_live_external_authority(environment)
            self.assertFalse(ci._live_observation_capture_matches(supplied))
            with mock.patch.dict(os.environ, environment):
                captured = ci.capture_live_external_authority()
            self.assertTrue(ci._live_observation_capture_matches(captured))
            self.assertFalse(ci._live_observation_capture_matches(replace(captured)))
            self.assertIsNone(ci._prepare_verifier_observation_authority(case.runner, case.context, captured))

    def test_no_public_authority_keyword(self):
        with authority_fixture() as case:
            for keyword in ("allow_windows", "standalone_authorized", "observation_admission"):
                with self.assertRaises(TypeError):
                    ci.verify_evidence_file_set(case.output, **{keyword: True})
                with self.assertRaises(TypeError):
                    ci.derive_authoritative_evidence("all", [], [], [], {}, "windows",
                        release_gate_required=False, **{keyword: case.capability})
                with self.assertRaises(TypeError):
                    ci.run_verification_replay(case.documents, expected_context=case.context,
                        verification_runner=case.runner, **{keyword: case.capability})
                with self.assertRaises(TypeError):
                    ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                        verification_runner=case.runner, **{keyword: case.capability})

    def test_existing_source_registry_authorization_is_unchanged(self):
        cases = [("static-suite", "static-suite", "static-producer-v1"),
                 ("node-check:file.js", "direct-syntax", "process-output-v1"),
                 ("learner-focused", "learner-focused", "process-output-v1"),
                 ("frontend-security:file.js", "frontend-security", "process-output-v1"),
                 ("backend-canonical", "backend-canonical", "process-output-v1"),
                 ("standalone-membership-audit", "standalone-membership", "standalone-membership-v1")]
        for command_id, family, kind in cases:
            source = {"commandId": command_id, "commandClass": family, "resultSemantics": "production"}
            self.assertEqual(ci._source_observation_kinds(source), frozenset({kind}))
        self.assertEqual(ci._source_observation_kinds({"commandId": "existing-fixture", "resultSemantics": "synthetic-replay-fixture"}), ci.RAW_OBSERVATION_KINDS)
        self.assertEqual(ci._source_observation_kinds({"commandId": "standalone-packaging", "commandClass": "standalone-packaging"}), frozenset())
        self.assertNotIn("observation_authority", inspect.getsource(backend.portable))
        # Existing result names and membership paths do not imply process-output
        # authority, even when their data mentions the packaging command/file.
        legacy = [
            ("standalone-membership-audit", "standalone-membership", "standalone-membership-v1",
             "membership:index.html::" + PATH, PATH, {"relative": PATH, "missing": True}, 1),
            ("static-suite", "static-suite", "static-producer-v1", "command:standalone-packaging",
             ci.STATIC_SUITE_RELATIVE_PATH,
             {"name": "command:standalone-packaging", "status": "pass", "detail": {}}, 0),
        ]
        for command_id, family, kind, result_id, source_path, fields, exit_code in legacy:
            with self.subTest(legacy_kind=kind):
                spec = fixtures.synthetic_command_spec(command_id, family, 0)
                spec["resultSemantics"] = "exit-zero-required"
                source = fixtures.synthetic_record_from_spec(spec)
                source["exitCode"] = exit_code
                raw = ci.make_raw_observation(command_id, 0, 0, kind, result_id, source_path,
                                              fields, ci.command_output_digest(source))
                source["producerObservations"] = [raw]
                self.assertEqual(ci._validate_raw_observation(raw, label="legacy", source=source), [])
                self.assertEqual(ci._validate_admitted_raw_observation(raw, label="legacy", source=source), [])
                self.assertFalse(ci._has_standalone_observation([source], command_plan=[spec]))
                expected = ci._rederive_observation_record({"rawObservation": raw}, source, profile_context={})
                self.assertEqual(ci._reconstruct_observation_with_admission(
                    {"rawObservation": raw}, source, profile_context={}, admissions=()), expected)


    def test_normal_standalone_profile_does_not_emit_process_observation(self):
        for platform in ("ubuntu", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temp:
                runner, capture = runner_fixture(Path(temp), platform)
                record = copy.deepcopy(runner.command_results[0])
                bundle = copy.deepcopy(record["protectedTargetBundle"])
                runner.command_results.clear()
                runner.require_command_success = mock.Mock(side_effect=lambda *_: runner.command_results.append(record))
                runner.execute_protected_internal = mock.Mock(return_value=({}, None))
                with mock.patch.object(ci, "execute_planned_static_suite", return_value=(capture, bundle)), counters() as calls:
                    runner.run_standalone_profile()
                self.assertEqual(runner.command_results[0]["producerObservations"], [])
                self.assertEqual(runner.observations, [])
                self.assertNotIn(STREAM.decode(), json.dumps(runner.command_results))
                self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))

    def test_live_producer_binding_finalization_derivation_write_and_reread(self):
        with tempfile.TemporaryDirectory(prefix="authority-producer-") as temp:
            root = Path(temp)
            runner, _ = runner_fixture(root)
            initial = copy.deepcopy(runner.execution_binding)
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "windows-compatibility-producer",
                "RUNNER_OS": "Windows", "GITHUB_RUN_ID": initial["runId"], "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": initial["eventName"], "GITHUB_REPOSITORY": initial["repository"],
                "GITHUB_SHA": initial["checkoutCommit"]}
            with mock.patch.dict(os.environ, environment):
                external = ci.capture_live_external_authority()
            runner.execution_external_authority = external
            runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
            with mock.patch.object(ci, "current_checkout_identity", return_value=(initial["checkoutCommit"], initial["checkoutTree"])), \
                 mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], initial["trustFileDigest"])):
                runner.execution_binding = ci.build_generation_execution_binding(runner,
                    external_authority=external, repo_root=root)
            self.assertEqual(runner.execution_binding, initial)
            capability = ci._observation_authority_for_runner(runner)
            self.assertEqual(capability.issuance, "live-producer")
            # Exercise the future producer path only with this explicit fixture.
            record = runner.command_results[0]
            raw = raw_for(record)
            record["producerObservations"] = [raw]
            runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}]
            output = root / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=root)
            with counters() as calls, mock.patch.object(ci, "_verify_evidence_file_set", wraps=ci._verify_evidence_file_set) as reread:
                summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output,
                                            evidence_authority_root=root)
            self.assertEqual(summary["status"], "PASS")
            self.assertIs(reread.call_args.kwargs["observation_runner"], runner)
            self.assertIs(ci._observation_authority_for_runner(runner), capability)
            self.assertGreater(calls.derivation.call_count, 0)
            self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))
            self.assertTrue(ci.verify_evidence_file_set(output, repo_root=root, expected_command_plan=runner.command_plan))
            print("W702_PRODUCER_FLOW live-capture=PASS held-authority=PASS finalization=PASS derivation=PASS five-file-reread=PASS")

    def test_real_preparation_issues_capability_only_for_built_context(self):
        with tempfile.TemporaryDirectory(prefix="authority-preparation-") as temp:
            root = Path(temp)
            template, _ = runner_fixture(root)
            binding = template.execution_binding
            (root / "developer/tests/ci/phase1-ci-baseline.json").write_bytes(ci.BASELINE_PATH.read_bytes())
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "windows-compatibility",
                "RUNNER_OS": "Windows", "GITHUB_RUN_ID": binding["runId"], "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": binding["eventName"], "GITHUB_REPOSITORY": binding["repository"],
                "GITHUB_SHA": binding["checkoutCommit"], "CI_TRUSTED_PYTHON": sys.executable,
                "CI_TRUSTED_NODE": sys.executable, "CI_TRUSTED_NPM_ENTRY": sys.executable}
            with mock.patch.dict(os.environ, environment):
                external = ci.capture_live_external_authority()
            def initialize(runner, profile, baseline, **kwargs):
                runner.__dict__.update(copy.deepcopy(vars(template)))
                runner.execution_external_authority = kwargs["execution_external_authority"]
                runner.require_all_tools = mock.Mock()
                runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
            args = ci.parse_args(["--verify-evidence", "--expected-profile", "all", "--expected-producer-job",
                "windows-compatibility-producer", "--expected-verifier-job", "windows-compatibility",
                "--expected-runner-os", "Windows", "--require-fresh-runtime-closure",
                "--untrusted-evidence-root", str(root / ".ci-results")])
            with mock.patch.object(ci.FoundationRunner, "__init__", initialize), \
                 mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
                 mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])):
                context, runner = ci.prepare_verification_authority(args, external_authority=external,
                    repo_root=root, source_environment=environment)
            capability = ci._observation_authority_for_runner(runner, context)
            self.assertIsNotNone(capability)
            self.assertEqual(capability.issuance, "live-verifier")
            self.assertIsNone(ci._prepare_verifier_observation_authority(runner, replace(context), external))
            self.assertIsNone(ci._observation_authority_for_runner(runner, replace(context)))
            for field, value in (("verifier_job_id", "ubuntu-canonical"), ("runner_os", "Linux"),
                                  ("producer_job_id", "repository-policy-producer"), ("expected_profile", "backend")):
                self.assertIsNone(ci._prepare_verifier_observation_authority(runner, replace(context, **{field: value}), external))
            print("W702_VERIFIER_ISSUANCE prepare_verification_authority=PASS handmade-context=DENY roles=EXACT")

    def test_local_windows_and_handmade_live_authority_cannot_issue(self):
        with tempfile.TemporaryDirectory(prefix="authority-local-") as temp:
            root = Path(temp)
            runner, _ = runner_fixture(root)
            binding = runner.execution_binding
            fake = replace(runner.execution_external_authority, source_kind="live")
            self.assertIsNone(ci._prepare_generation_observation_authority(runner, fake, binding))
            with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
                local = ci.capture_live_external_authority()
            runner.execution_external_authority = local
            runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
            with mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
                 mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])):
                runner.execution_binding = ci.build_generation_execution_binding(runner, external_authority=local, repo_root=root)
            self.assertEqual(runner.execution_binding["producerRunnerOS"], "Windows")
            self.assertIsNone(ci._observation_authority_for_runner(runner))
            record = runner.command_results[0]
            raw = raw_for(record)
            record["producerObservations"] = [raw]
            runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}]
            with counters() as calls, self.assertRaises(ValueError):
                ci.finalize_evidence_transcript(runner)
            self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))

    def test_authorized_outer_replay_without_backend_capability(self):
        with authority_fixture() as case:
            runner = case.runner
            record = runner.command_results[0]
            raw = raw_for(record)
            record["producerObservations"] = [raw]
            runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}]
            ci.finalize_evidence_transcript(runner)
            with mock.patch.object(ci, "REPO_ROOT", case.root), \
                 mock.patch.object(ci, "rebuild_external_verification_context", return_value=case.context), \
                 mock.patch.object(backend.portable, "_bind_producer") as backend_bind, counters() as calls, \
                 mock.patch.object(ci, "_validate_evidence_semantics_with_authority", wraps=ci._validate_evidence_semantics_with_authority) as stages:
                errors, transcript = ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                    verification_runner=runner, repo_root=case.root, evidence_authority_root=case.root)
            self.assertEqual(errors, [])
            self.assertEqual(transcript["finalAcceptance"], "PASS")
            self.assertEqual(stages.call_count, 2)
            self.assertNotIn("backendCanonicalPortableResult", transcript)
            backend_bind.assert_not_called()
            self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))

    def test_raw_projection_mismatch_fails_before_reconstruction(self):
        for phase in ("producer finalization", "snapshot verification"):
            with self.subTest(phase=phase), authority_fixture() as case:
                raw = copy.deepcopy(case.documents["command-results.json"]["records"][0]["producerObservations"][0])
                raw["occurrences"] = 2
                item = {"commandId": "standalone-packaging", "rawObservation": raw}
                if phase == "producer finalization":
                    case.runner.command_results[0]["producerObservations"] = [raw_for(case.runner.command_results[0])]
                    case.runner.observations = [item]
                    self.assert_denied(case, phase + " unbound projection", lambda: ci.finalize_evidence_transcript(case.runner))
                else:
                    case.documents["command-results.json"]["observations"] = [item]
                    reseal(case)
                    self.assert_denied(case, phase + " unbound projection")

    def test_admission_cannot_be_reused_with_different_derivation_context(self):
        for field, value in (("profile", "backend"), ("current_platform", "ubuntu"),
                              ("authorization_context_binding_digest_value", "0" * 64),
                              ("release_gate_required", True), ("completed_command_classes", [])):
            with self.subTest(field=field), authority_fixture() as case:
                proofs = ci._admit_standalone_observations(validation(case))
                arguments = dict(profile="all", observations=[], completed_command_classes=["standalone-packaging"],
                    command_records=case.documents["command-results.json"]["records"],
                    immutable_baseline_authority=case.runner.baseline, current_platform="windows",
                    command_plan=case.runner.command_plan,
                    authorization_context_binding_digest_value=case.runner.authorization_context_binding_digest,
                    release_gate_required=False, cross_job=True, admissions=proofs)
                arguments[field] = value
                self.assert_denied(case, "derivation invocation " + field,
                    lambda: ci._derive_authoritative_evidence_with_admission(**arguments))

    def test_main_generation_without_standalone_execution_emits_no_observation(self):
        with tempfile.TemporaryDirectory(prefix="authority-main-") as temp:
            root = Path(temp)
            template, _ = runner_fixture(root)
            binding = template.execution_binding
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "windows-compatibility-producer",
                "RUNNER_OS": "Windows", "GITHUB_RUN_ID": binding["runId"], "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": binding["eventName"], "GITHUB_REPOSITORY": binding["repository"],
                "GITHUB_SHA": binding["checkoutCommit"], "CI_FOUNDATION_LOCAL_PARENT_PATH": "",
                "CI_FOUNDATION_TASK_OUTPUT_ROOT": ""}
            runners = []
            def initialize(runner, profile, baseline, **kwargs):
                runner.__dict__.update(copy.deepcopy(vars(template)))
                runner.execution_external_authority = kwargs["execution_external_authority"]
                runner.require_all_tools = mock.Mock()
                runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
                runner.run = mock.Mock(return_value=fixtures.empty_comparison())
                runners.append(runner)
            with mock.patch.dict(os.environ, environment), mock.patch.object(ci, "REPO_ROOT", root), \
                 mock.patch.object(ci.FoundationRunner, "__init__", initialize), \
                 mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
                 mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])), \
                 contextlib.redirect_stdout(io.StringIO()), counters() as calls:
                code = ci.main(["--profile", "all"])
            self.assertEqual(code, ci.EXIT_SUCCESS)
            self.assertEqual(len(runners), 1)
            self.assertEqual(ci._observation_authority_for_runner(runners[0]).issuance, "live-producer")
            documents, _, errors = ci._read_evidence_documents_for_replay(root / ".ci-results")
            self.assertEqual(errors, [])
            self.assertEqual(documents["command-results.json"]["records"][0]["producerObservations"], [])
            self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))

    def test_prepared_slot_cannot_hide_packaging_under_another_source_identity(self):
        with authority_fixture() as case:
            source = case.documents["command-results.json"]["records"][0]
            raw = source["producerObservations"][0]
            source.update(commandId="node-check:other.js", commandClass="direct-syntax")
            raw.update(commandId="node-check:other.js", sourceResultId="other.js", sourcePath="other.js")
            reseal(case)
            self.assert_denied(case, "complete standalone source relabeling against prepared command slot")

    def test_source_only_wrapper_preserves_exact_schema_and_error_order(self):
        with authority_fixture() as case, counters() as calls:
            source = case.documents["command-results.json"]["records"][0]
            raw = source["producerObservations"][0]
            schema_error = ["compat: raw observation schema is not exact"]
            for malformed in ({}, None, [], {**raw, "additional": True}):
                self.assertEqual(ci._validate_raw_observation(malformed, label="compat", source=source), schema_error)
            self.assertEqual(ci._validate_raw_observation(raw, label="compat", source=source),
                ["compat: observationKind is outside source command observation authority"])
            changed = {**raw, "commandOrdinal": 1}
            self.assertEqual(ci._validate_raw_observation(changed, label="compat", source=source)[0],
                "compat: observationKind is outside source command observation authority")
            self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))

    def test_other_source_permission_failure_blocks_sensitive_snapshot_reconstruction(self):
        with tempfile.TemporaryDirectory(prefix="authority-mixed-") as temp:
            runner, _ = runner_fixture(Path(temp))
            other = fixtures.synthetic_command_spec("static-suite", "static-suite", 1)
            other.update(profile="all", platform="windows", resultSemantics="exit-zero-required")
            source = fixtures.synthetic_record_from_spec(other)
            source["producerObservations"] = [ci.make_raw_observation("static-suite", 1, 0,
                "process-output-v1", "result:other", ci.STATIC_SUITE_RELATIVE_PATH,
                {"executed": True, "exitCode": 0, "stdout": "", "stderr": "", "error": None},
                ci.command_output_digest(source))]
            runner.command_plan.append(other)
            runner.command_results.append(source)
            runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
            runner.execution_binding["commandPlanDigest"] = runner.command_plan_digest
            runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
                k: v for k, v in runner.execution_binding.items() if k != "producerInvocationId"})
            del runner.authorization_context_binding
            del runner.authorization_context_binding_digest
            ci._issue_synthetic_observation_authority_for_test(runner)
            record = runner.command_results[0]
            raw = raw_for(record)
            record["producerObservations"] = [raw]
            runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}]
            with counters() as calls, self.assertRaisesRegex(ValueError, "outside source command observation authority"):
                ci.finalize_evidence_transcript(runner)
            self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))

    @classmethod
    def tearDownClass(cls):
        print("W702_AUTHORITY_MATRIX " + json.dumps({"negative_rows": cls.negatives,
            "required_categories": 17, "parser_calls": 0, "standalone_semantic_identity_calls": 0}))


@contextlib.contextmanager
def positional_fixture(platform="windows"):
    """Keep standalone at its real ordinal with records on both sides."""
    with tempfile.TemporaryDirectory(prefix="observation-positional-") as temp:
        root = Path(temp)
        runner, capture = runner_fixture(root, platform)
        standalone = runner.command_plan[0]
        source = runner.command_results[0]
        standalone["ordinal"] = source["ordinal"] = 702
        padding = fixtures.synthetic_command_spec("padding", "baseline-policy", 0)
        padding.update(profile="all", platform=platform)
        plan, records = [], []
        for ordinal in range(705):
            if ordinal == 702:
                plan.append(standalone)
                records.append(source)
            else:
                spec = copy.deepcopy(padding)
                spec.update(commandId=f"padding-{ordinal}", ordinal=ordinal)
                plan.append(spec)
                records.append(fixtures.synthetic_record_from_spec(spec))
        runner.command_plan, runner.command_results = plan, records
        runner.command_plan_by_id = {spec["commandId"]: spec for spec in plan}
        runner.command_plan_digest = ci.command_plan_digest(plan)
        runner.execution_binding["commandPlanDigest"] = runner.command_plan_digest
        runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
            key: value for key, value in runner.execution_binding.items() if key != "producerInvocationId"})
        runner.__dict__.pop("authorization_context_binding", None)
        runner.__dict__.pop("authorization_context_binding_digest", None)
        ci.finalize_evidence_transcript(runner)
        output = root / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=root)
        summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output,
                                    evidence_authority_root=root)
        documents, snapshots, errors = ci._read_evidence_documents_for_replay(output)
        if errors:
            raise AssertionError(errors)
        context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                          fresh_runtime_closure_digest=runner.runtime_closure_digest)
        runner.external_verification_context = context
        runner.verifier_execution_binding = context.verifier_binding()
        runner.execution_external_authority = external_for(runner.execution_binding, verifier=True)
        capability = ci._issue_synthetic_observation_authority_for_test(runner, context)
        comparison = {key: summary[field] for key, field in (
            ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
            ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
        runner.run = mock.Mock(return_value=comparison)
        yield SimpleNamespace(root=root, output=output, runner=runner, context=context,
            documents=documents, snapshots=snapshots, capability=capability, comparison=comparison,
            capture=capture)


def forge_positional_evidence(case, location=0, value=None, *, relabel=True):
    """Attacker recomputes all claims; the original records array stays malformed."""
    commands = case.documents["command-results.json"]
    records = commands["records"]
    source = records[702]
    source.update(stderrSha256=ci.hashlib.sha256(STREAM).hexdigest(), stderrBytesObserved=len(STREAM))
    source["producerObservations"] = [raw_for(source)]
    if relabel:
        source.update(commandId="node-check:other.js", commandClass="direct-syntax")
        source["producerObservations"][0].update(commandId="node-check:other.js",
                                                sourceResultId="other.js", sourcePath="other.js")
    if location is not None:
        records[location] = value
    # This intentionally reproduces the attacker's compacted aggregate claims.
    # It is never used as a positional authority sequence in the verifier.
    claimed = [record for record in records if isinstance(record, Mapping)]
    for record in claimed:
        for raw in record["producerObservations"]:
            raw["sourceOutputDigest"] = ci.command_output_digest(record)
            raw["producerRecordDigest"] = ci._producer_record_digest({
                key: item for key, item in raw.items() if key != "producerRecordDigest"})
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest(record["producerObservations"])
        record["completedCommandClass"] = record["commandClass"] if ci._command_completed_for_class(record) else None
    plan = case.runner.command_plan
    expected = ci.expected_completed_command_classes(plan)
    actual = ci.actual_completed_command_classes(plan, claimed)
    commands.update(expectedCompletedCommandClasses=expected, actualCompletedCommandClasses=actual,
        completedCommandClasses=actual,
        expectedCompletedCommandClassSetDigest=ci.completed_command_class_set_digest(expected),
        completedCommandClassSetDigest=ci.completed_command_class_set_digest(actual),
        producerObservationCount=sum(len(record["producerObservations"]) for record in claimed),
        producerObservationUniverseDigest=ci.producer_observation_universe_digest(claimed),
        producerTranscriptDigest=ci.producer_transcript_digest(commands["commandPlanDigest"], claimed, actual))
    missing, extra, duplicate = ci.command_id_set_differences(plan, claimed)
    commands.update(missingCommandIds=missing, extraCommandIds=extra, duplicateCommandIds=duplicate)
    projection_context = {
        "producerObservationUniverseDigest": commands["producerObservationUniverseDigest"],
        "producerTranscriptDigest": commands["producerTranscriptDigest"],
        "profileCompletedCommandClassSetDigest": commands["completedCommandClassSetDigest"],
        "authorizationContextBindingDigest": commands["authorizationContextBindingDigest"]}
    observations = [ci._rederive_observation_record({"rawObservation": raw}, record,
                    profile_context=projection_context)
                    for record in claimed for raw in record["producerObservations"]]
    commands["observations"] = observations
    derived = ci.derive_authoritative_evidence("all", observations, actual, records,
        case.runner.baseline, case.runner.platform, plan,
        commands["authorizationContextBindingDigest"], release_gate_required=False, cross_job=True)
    summary = case.documents["summary.json"]
    for field, key in (("knownDebtsObserved", "observedDebts"), ("resolvedCandidates", "resolvedCandidates"),
                       ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips")):
        summary[field] = derived[key]
    summary["policyViolations"] = derived["violations"]
    summary["counts"] = dict(hardGateFailures=sum(result["status"] != "pass" for result in summary["hardGateResults"]),
        policyViolations=len(summary["policyViolations"]), knownDebtsObserved=len(summary["knownDebtsObserved"]),
        resolvedCandidates=len(summary["resolvedCandidates"]), expectedOmissions=len(summary["expectedOmissions"]),
        releaseOnlySkips=len(summary["releaseOnlySkips"]), commands=len(records))
    summary["status"] = "FAIL" if summary["counts"]["hardGateFailures"] or summary["policyViolations"] else "PASS"
    case.documents["observed-debt.json"].update(records=summary["knownDebtsObserved"],
        expectedOmissions=summary["expectedOmissions"], releaseOnlySkips=summary["releaseOnlySkips"])
    case.documents["resolved-candidates.json"]["records"] = summary["resolvedCandidates"]
    backend.write_documents(case.output, case.documents)
    case.documents, case.snapshots, errors = ci._read_evidence_documents_for_replay(case.output)
    if errors:
        raise AssertionError(errors)


def call_counts(calls, admission, replay):
    return dict(reconstruction_calls=calls.reconstruction.call_count,
        admission_calls=admission.call_count, authoritative_derivation_calls=calls.derivation.call_count,
        replay_execution_calls=replay.call_count, parser_calls=calls.parser.call_count,
        backend_parser_calls=calls.backend_parser.call_count)



@contextlib.contextmanager
def positional_counters():
    with counters() as calls, mock.patch.object(ci, "_admit_standalone_observations",
            wraps=ci._admit_standalone_observations) as admission, mock.patch.object(ci,
            "_execute_verification_replay", wraps=ci._execute_verification_replay) as replay:
        calls.admission, calls.replay = admission, replay
        yield calls


class PositionalObservationPreflightTest(unittest.TestCase):
    def assert_preflight_denied(self, label, operation):
        with positional_counters() as calls:
            errors = operation()
        self.assertTrue(errors, label)
        counts = call_counts(calls, calls.admission, calls.replay)
        self.assertEqual(set(counts.values()), {0}, (label, counts, errors))
        print("W702_POSITIONAL_DENIAL " + json.dumps(dict(case=label, result="REJECT", **counts)))
        return errors

    def assert_forged_aggregates(self, case, location):
        commands = case.documents["command-results.json"]
        records = commands["records"]
        self.assertIsNone(records[location])
        self.assertEqual(len(records), 705)
        claimed = [record for record in records if isinstance(record, Mapping)]
        actual = ci.actual_completed_command_classes(case.runner.command_plan, claimed)
        self.assertEqual(commands["actualCompletedCommandClasses"], actual)
        self.assertEqual(commands["completedCommandClasses"], actual)
        self.assertEqual(commands["producerObservationCount"], 1)
        self.assertEqual(commands["producerObservationUniverseDigest"], ci.producer_observation_universe_digest(claimed))
        self.assertEqual(commands["producerTranscriptDigest"], ci.producer_transcript_digest(
            commands["commandPlanDigest"], claimed, actual))
        raw = records[702]["producerObservations"][0]
        self.assertEqual(raw["commandId"], "node-check:other.js")
        self.assertEqual((raw["sourceResultId"], raw["sourcePath"]), ("other.js", "other.js"))
        self.assertEqual(ci._validate_raw_observation(raw, label="forged-source", source=records[702]), [])
        self.assertEqual(raw["sourceOutputDigest"], ci.command_output_digest(records[702]))
        self.assertEqual(raw["producerRecordDigest"], ci._producer_record_digest({
            key: value for key, value in raw.items() if key != "producerRecordDigest"}))
        summary = case.documents["summary.json"]
        self.assertEqual(summary["counts"]["commands"], len(records))
        for field, value in (("knownDebtsObserved", case.documents["observed-debt.json"]["records"]),
                             ("resolvedCandidates", case.documents["resolved-candidates.json"]["records"]),
                             ("expectedOmissions", case.documents["observed-debt.json"]["expectedOmissions"]),
                             ("releaseOnlySkips", case.documents["observed-debt.json"]["releaseOnlySkips"])):
            self.assertEqual(summary[field], value)
            self.assertEqual(summary["counts"][field], len(value))
        for entry in summary["evidenceManifest"]:
            data = case.snapshots[entry["relativeFilename"]].data
            self.assertEqual(entry["byteLength"], len(data))
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(case.snapshots["summary.md"].data, ci.render_summary_markdown(summary).encode())

    def test_original_counterexample_and_positional_shift_matrix(self):
        for platform in ("windows", "ubuntu"):
            with self.subTest(platform=platform), positional_fixture(platform) as case:
                ordinary = copy.deepcopy(case.documents)
                self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                    expected_command_plan=case.runner.command_plan), [])
                self.assertEqual(semantic_verify(case), [])
                self.assertEqual(ordinary["command-results.json"]["records"][702]["producerObservations"], [])
                if platform == "windows":
                    source = case.documents["command-results.json"]["records"][702]
                    source["producerObservations"] = [raw_for(source)]
                    reseal(case)
                    with positional_counters() as calls:
                        self.assertEqual(ci._verify_evidence_file_set(case.output, repo_root=case.root,
                            expected_command_plan=case.runner.command_plan, expected_context=case.context,
                            observation_runner=case.runner), [])
                    self.assertGreater(calls.admission.call_count, 0)
                    self.assertGreater(calls.reconstruction.call_count, 0)
                print("W702_POSITIONAL_CONTROL " + json.dumps(dict(platform=platform,
                    ordinary_file_validation="PASS", standalone_observations=[], ordinal=702)))
                for location in (0, 686, 701, 703):
                    with self.subTest(location=location):
                        case.documents = copy.deepcopy(ordinary)
                        forge_positional_evidence(case, location)
                        self.assert_forged_aggregates(case, location)
                        records = case.documents["command-results.json"]["records"]
                        self.assertTrue(ci._has_standalone_observation(records, (), case.runner.command_plan))
                        if location < 702:
                            self.assertFalse(ci._has_standalone_observation(
                                [record for record in records if isinstance(record, Mapping)], (), case.runner.command_plan))
                        self.assert_preflight_denied(f"{platform} authority records[{location}]", lambda: ci._verify_evidence_file_set(
                            case.output, repo_root=case.root, expected_command_plan=case.runner.command_plan,
                            expected_context=case.context, observation_runner=case.runner))
                        if platform == "windows":
                            self.assert_preflight_denied(f"source-only records[{location}]", lambda: ci.verify_evidence_file_set(
                                case.output, repo_root=case.root, expected_command_plan=case.runner.command_plan))

    def test_second_snapshot_combined_forgery_precedes_replay(self):
        for platform in ("windows", "ubuntu"):
            base = backend.fixture(platform, ordinal=701)
            with self.subTest(platform=platform), backend.outer_fixture(base, base, prefix_count=701,
                    extra=("standalone-packaging", "fixture"), hosted=True) as case:
                runner = object.__new__(ci.FoundationRunner)
                runner.__dict__.update(vars(case.runner))
                case.runner = runner
                case.runner.external_verification_context = case.context
                case.runner.execution_external_authority = external_for(case.runner.execution_binding, verifier=True)
                ci._issue_synthetic_observation_authority_for_test(case.runner, case.context)
                original = ci._verify_evidence_file_set
                first = []
                with positional_counters() as calls:
                    def substitute_after_first(*args, **kwargs):
                        errors = original(*args, **kwargs)
                        self.assertEqual(errors, [])
                        first.append(call_counts(calls, calls.admission, calls.replay))
                        forge_positional_evidence(case)
                        for spy in (calls.reconstruction, calls.derivation, calls.parser,
                                    calls.backend_parser, calls.admission, calls.replay):
                            spy.reset_mock()
                        return errors
                    with mock.patch.object(ci, "_verify_evidence_file_set", side_effect=substitute_after_first):
                        errors, transcript = backend.verify(case)
                self.assertEqual(len(first), 1)
                self.assertTrue(errors)
                self.assertIsNone(transcript)
                counts = call_counts(calls, calls.admission, calls.replay)
                self.assertEqual(set(counts.values()), {0}, (counts, errors))
                case.runner.run.assert_not_called()
                print("W702_POSITIONAL_SECOND_SNAPSHOT " + json.dumps(dict(platform=platform,
                    first_snapshot="PASS", first_snapshot_calls=first[0], transcript=None, result="REJECT", **counts)))

    def test_second_snapshot_without_backend_or_observation_capability(self):
        with authority_fixture(platform="ubuntu", observation=False) as case:
            original = ci._verify_evidence_file_set
            with positional_counters() as calls:
                def substitute_after_first(*args, **kwargs):
                    errors = original(*args, **kwargs)
                    self.assertEqual(errors, [])
                    case.documents["command-results.json"]["records"][0] = None
                    backend.write_documents(case.output, case.documents)
                    for spy in (calls.reconstruction, calls.derivation, calls.parser,
                                calls.backend_parser, calls.admission, calls.replay):
                        spy.reset_mock()
                    return errors
                with mock.patch.object(ci, "_verify_evidence_file_set", side_effect=substitute_after_first):
                    errors, transcript = ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                        verification_runner=case.runner, repo_root=case.root, evidence_authority_root=case.root)
            self.assertTrue(errors)
            self.assertIsNone(transcript)
            counts = call_counts(calls, calls.admission, calls.replay)
            self.assertEqual(set(counts.values()), {0})
            case.runner.run.assert_not_called()
            print("W702_POSITIONAL_SECOND_SNAPSHOT " + json.dumps(dict(platform="ubuntu", backend=False,
                first_snapshot="PASS", transcript=None, result="REJECT", **counts)))

    def test_non_array_and_non_object_records_fail_before_processing(self):
        with authority_fixture(observation=False) as case:
            ordinary = copy.deepcopy(case.documents)
            def replay(documents):
                transcript, errors = ci.run_verification_replay(documents,
                    expected_context=case.context, verification_runner=case.runner, repo_root=case.root)
                self.assertEqual(transcript, {"finalAcceptance": "REJECT"})
                return errors
            self.assert_preflight_denied("public replay empty documents", lambda: replay({}))
            for value in (None, {}, "records", 1, True):
                for entry in (False, True):
                    if entry and isinstance(value, Mapping):
                        continue
                    label = f"{'record entry' if entry else 'records array'} {type(value).__name__}"
                    with self.subTest(case=label):
                        case.documents = copy.deepcopy(ordinary)
                        case.documents["command-results.json"]["records"] = [value] if entry else value
                        backend.write_documents(case.output, case.documents)
                        self.assert_preflight_denied(label, lambda: ci.verify_evidence_file_set(case.output,
                            repo_root=case.root, expected_command_plan=case.runner.command_plan))
                        self.assert_preflight_denied("public replay " + label, lambda: replay(case.documents))
            case.documents = copy.deepcopy(ordinary)
            case.documents["command-results.json"]["records"][0] = []
            backend.write_documents(case.output, case.documents)
            self.assert_preflight_denied("array-valued command entry", lambda: ci.verify_evidence_file_set(
                case.output, repo_root=case.root, expected_command_plan=case.runner.command_plan))

    def test_positional_plan_disagreement_without_process_observations(self):
        with authority_fixture(observation=False) as case:
            ordinary = copy.deepcopy(case.documents)
            for field, value in (("ordinal", False), ("ordinal", 1), ("commandId", "another-command"),
                                 ("commandClass", "direct-syntax"), ("toolRole", "python-in-process"),
                                 ("required", 1), ("allowedExecutionExits", [False])):
                with self.subTest(field=field, value=value):
                    case.documents = copy.deepcopy(ordinary)
                    case.documents["command-results.json"]["records"][0][field] = value
                    reseal(case)
                    errors = self.assert_preflight_denied(f"zero-observation plan mismatch {field}={value}",
                        lambda: ci.verify_evidence_file_set(case.output, repo_root=case.root,
                            expected_command_plan=case.runner.command_plan))
                    prefix = "summary.json: derived command/baseline violation is missing: "
                    diagnostics = [ci.strict_json_loads(error[len(prefix):]) for error in errors
                                   if error.startswith(prefix)]
                    self.assertIn("COMMAND-AUTHORITY-MISMATCH", [item["violationType"] for item in diagnostics])

    def test_failure_record_exceptions_cannot_supply_observation_authority(self):
        for platform in ("ubuntu", "windows"):
            with self.subTest(platform=platform), backend.outer_fixture(backend.fixture(platform), backend.fixture(platform)) as case:
                ordinary = copy.deepcopy(case.documents)
                def failure_evidence(name, runner, *, size_limit=False):
                    root = case.root / name
                    root.mkdir()
                    output = root / ".ci-results"
                    ci.create_fresh_evidence_root(output, repo_root=root)
                    limit = 256 if size_limit else ci.MAX_COMMAND_RESULTS_JSON_BYTES
                    with mock.patch.object(ci, "MAX_COMMAND_RESULTS_JSON_BYTES", limit):
                        summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output,
                                                    evidence_authority_root=root)
                    self.assertEqual(summary["status"], "FAIL")
                    self.assertEqual(ci.verify_evidence_file_set(output, repo_root=root,
                        expected_command_plan=case.runner.command_plan), [])
                    return ci.strict_json_load_file(output / "command-results.json")["records"]
                sentinel = failure_evidence("size-limit", copy.deepcopy(case.runner), size_limit=True)[0]
                self.assertEqual(sentinel["producerObservations"], [])
                extra_runner = copy.deepcopy(case.runner)
                extra = fixtures.synthetic_command_spec("extra-command", "baseline-policy", 1)
                extra.update(profile=case.runner.profile, platform=platform)
                extra_runner.command_results.append(fixtures.synthetic_record_from_spec(extra))
                failure_evidence("extra-failure", extra_runner)
                for variant in ("observation-bearing sentinel", "misclassified sentinel",
                                "sentinel with sibling", "unplanned observation source"):
                    with self.subTest(variant=variant):
                        case.documents = copy.deepcopy(ordinary)
                        records = case.documents["command-results.json"]["records"]
                        if variant == "unplanned observation source":
                            extra_record = copy.deepcopy(records[0])
                            extra_record.update(commandId="extra-observer", ordinal=1)
                            records.append(extra_record)
                        elif variant == "sentinel with sibling":
                            sibling = copy.deepcopy(records[0])
                            sibling["ordinal"] = 1
                            records[:] = [copy.deepcopy(sentinel), sibling]
                        else:
                            records[0]["commandId"] = "command-results-size-limit"
                            if variant == "misclassified sentinel":
                                records[0]["producerObservations"] = []
                        for record in records:
                            for raw in record["producerObservations"]:
                                raw["commandId"] = record["commandId"]
                        backend.reseal_producer(case)
                        self.assert_preflight_denied(f"{platform} {variant}", lambda: ci.verify_evidence_file_set(
                            case.output, repo_root=case.root, expected_command_plan=case.runner.command_plan))
                print("W702_FAILURE_EXCEPTION_CONTROL " + json.dumps(dict(platform=platform,
                    size_limit_failure="PASS", extra_zero_observation_failure="PASS")))

    def test_ordinary_partial_failure_and_original_sequence_are_preserved(self):
        with authority_fixture(observation=False) as case:
            records = case.documents["command-results.json"]["records"]
            validated, errors = ci._preflight_command_record_positions(records, case.runner.command_plan)
            self.assertEqual(errors, [])
            self.assertIs(validated, records)
            case.runner.command_results = []
            case.runner.observations = []
            failure_root = case.root / "partial-failure"
            failure_root.mkdir()
            output = failure_root / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=failure_root)
            summary = ci.write_evidence(case.runner, fixtures.empty_comparison(), output_dir=output,
                                        evidence_authority_root=failure_root)
            self.assertEqual(summary["status"], "FAIL")
            self.assertEqual(ci.verify_evidence_file_set(output, repo_root=failure_root,
                expected_command_plan=case.runner.command_plan), [])


def retention_environment(binding, *, verifier=False):
    role = ci._workflow_authority_for_producer(binding["producerJobId"])
    return {"GITHUB_ACTIONS": "true", "GITHUB_JOB": role["verifierJobId"] if verifier else role["producerJobId"],
        "RUNNER_OS": binding["producerRunnerOS"], "GITHUB_RUN_ID": binding["runId"],
        "GITHUB_RUN_ATTEMPT": binding["runAttempt"], "GITHUB_EVENT_NAME": binding["eventName"],
        "GITHUB_REPOSITORY": binding["repository"], "GITHUB_SHA": binding["checkoutCommit"],
        "CI_FOUNDATION_LOCAL_PARENT_PATH": "", "CI_FOUNDATION_TASK_OUTPUT_ROOT": "",
        "CI_TRUSTED_PYTHON": sys.executable, "CI_TRUSTED_NODE": sys.executable,
        "CI_TRUSTED_NPM_ENTRY": sys.executable}


def live_retention_producer(runner, root):
    binding = runner.execution_binding
    with mock.patch.dict(os.environ, retention_environment(binding)), \
         mock.patch.object(ci, "_canonical_runner_os", return_value=binding["producerRunnerOS"]):
        external = ci.capture_live_external_authority()
    runner.execution_external_authority = external
    runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
    with mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
         mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])):
        runner.execution_binding = ci.build_generation_execution_binding(runner, external_authority=external, repo_root=root)
    return ci._observation_authority_for_runner(runner)


def retention_rebind(runner):
    runner.command_plan_by_id = {spec["commandId"]: spec for spec in runner.command_plan}
    runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
    runner.execution_binding["commandPlanDigest"] = runner.command_plan_digest
    runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
        key: value for key, value in runner.execution_binding.items() if key != "producerInvocationId"})
    for key in ("authorization_context_binding", "authorization_context_binding_digest",
                "external_verification_context", "verifier_execution_binding", "_observation_authority"):
        runner.__dict__.pop(key, None)
    ci.finalize_evidence_transcript(runner)


def retention_streams(record, capture, *, stdout=b"", stderr=STREAM):
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        setattr(capture, stream + "_raw", data)
        setattr(capture, stream + "_bytes", len(data))
        # Deliberately misleading ordinary/identity text must never supply bytes.
        setattr(capture, stream, "ordinary preview differs")
        setattr(capture, "identity_" + stream, "identity summary differs")
        record[stream + "Sha256"] = hashlib.sha256(data).hexdigest()
        record[stream + "BytesObserved"] = len(data)


@contextlib.contextmanager
def retention_fixture(*, platform="windows", stdout=b"", stderr=STREAM, authorize=True):
    with tempfile.TemporaryDirectory(prefix="retention-e1-") as temp:
        root = Path(temp)
        runner, capture = runner_fixture(root, platform)
        runner.captures = [capture]
        source = runner.command_results[0]
        retention_streams(source, capture, stdout=stdout, stderr=stderr)
        capability = live_retention_producer(runner, root) if authorize else None
        yield SimpleNamespace(root=root, runner=runner, capture=capture, source=source, capability=capability)


def retain(case):
    case.runner._retain_standalone_process_observation(case.source, case.capture)


def write_retention(case, name=".ci-results"):
    case.output = case.root / name
    ci.create_fresh_evidence_root(case.output, repo_root=case.root)
    summary = ci.write_evidence(case.runner, fixtures.empty_comparison(), output_dir=case.output,
                                evidence_authority_root=case.root)
    case.documents, case.snapshots, errors = ci._read_evidence_documents_for_replay(case.output)
    if errors:
        raise AssertionError(errors)
    return summary


def prepare_retention_verifier(template, root, *, platform=None):
    template = copy.deepcopy(template)
    for key in ("_observation_authority", "external_verification_context", "verifier_execution_binding"):
        template.__dict__.pop(key, None)
    if platform is not None and platform != template.platform:
        template.platform = platform
        for spec in template.command_plan:
            spec["platform"] = platform
        template.execution_binding.update(producerRunnerOS="Linux", producerJobId="ubuntu-canonical-producer")
        template.command_plan_digest = ci.command_plan_digest(template.command_plan)
        template.execution_binding["commandPlanDigest"] = template.command_plan_digest
    binding = template.execution_binding
    environment = retention_environment(binding, verifier=True)
    (root / "developer/tests/ci/phase1-ci-baseline.json").write_bytes(ci.BASELINE_PATH.read_bytes())
    with mock.patch.dict(os.environ, environment), \
         mock.patch.object(ci, "_canonical_runner_os", return_value=binding["producerRunnerOS"]):
        external = ci.capture_live_external_authority()
    def initialize(runner, profile, baseline, **kwargs):
        runner.__dict__.update(vars(template))
        runner.execution_external_authority = kwargs["execution_external_authority"]
        runner.require_all_tools = mock.Mock()
        runner.require_tool = mock.Mock(return_value="D:/Git/cmd/git.exe")
        runner.private_temp_root = root
    role = ci._workflow_authority_for_producer(binding["producerJobId"])
    argv = ["--verify-evidence", "--expected-profile", "all", "--expected-producer-job", role["producerJobId"],
        "--expected-verifier-job", role["verifierJobId"], "--expected-runner-os", binding["producerRunnerOS"],
        "--require-fresh-runtime-closure", "--untrusted-evidence-root", str(root / ".ci-results")]
    if binding["producerRunnerOS"] == "Linux":
        argv.append("--require-linux-containment-self-test")
    with mock.patch.object(ci.FoundationRunner, "__init__", initialize), \
         mock.patch.object(ci, "_canonical_runner_os", return_value=binding["producerRunnerOS"]), \
         mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
         mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])), \
         mock.patch.object(ci, "run_linux_containment_live_self_test", return_value=([], [])):
        return ci.prepare_verification_authority(ci.parse_args(argv), external_authority=external,
            repo_root=root, source_environment=environment)


@contextlib.contextmanager
def retention_counters():
    # There is no standalone semantic implementation to mock. Inspect the real
    # production call frames too, so a future parser/identity cannot go unnoticed.
    semantic = {"standalone_parser_calls": 0, "standalone_semantic_identity_calls": 0}
    previous = sys.getprofile()
    def trace(frame, event, arg):
        if event == "call":
            module = frame.f_globals.get("__name__", "")
            name = frame.f_code.co_name.lower()
            if module == ci.__name__ and "standalone" in name:
                if "parse" in name:
                    semantic["standalone_parser_calls"] += 1
                if "semantic" in name and "identity" in name:
                    semantic["standalone_semantic_identity_calls"] += 1
        if previous is not None:
            previous(frame, event, arg)
    with counters() as calls:
        calls.semantic = semantic
        sys.setprofile(trace)
        try:
            yield calls
        finally:
            sys.setprofile(previous)
            if any(semantic.values()):
                raise AssertionError(semantic)


class StandaloneExactRetentionTest(unittest.TestCase):
    def assert_unavailable(self, case, label):
        original = copy.deepcopy(case.source)
        with retention_counters() as calls:
            retain(case)
        self.assertEqual(case.source, original, label)
        self.assertEqual(case.source["producerObservations"], [], label)
        self.assertEqual(case.runner.observations, [], label)
        self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0), label)
        self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0), label)
        print("W702_RETENTION_UNAVAILABLE " + json.dumps({"case": label, "reconstruction_calls": 0,
            "authoritative_derivation_calls": 0, **calls.semantic}))

    def test_exact_empty_nonempty_utf8_roundtrips_and_five_file_reread(self):
        for stdout, stderr in ((b"", STREAM), (b"", b""), (b"diagnostic\n", STREAM),
            (b"", b"\n" + STREAM.replace(b"\n", b"\r\n") + "caf\u00e9 cafe\u0301\n".encode()),
            (b"", b"unrecognized reporter text 123\n")):
            with self.subTest(stdout=stdout, stderr=stderr), retention_fixture(stdout=stdout, stderr=stderr) as case:
                with retention_counters() as calls:
                    retain(case)
                    self.assertEqual(len(case.source["producerObservations"]), 1)
                    self.assertEqual(calls.reconstruction.call_count, 0)
                    summary = write_retention(case)
                    self.assertEqual(summary["status"], "PASS")
                    self.assertEqual(ci._verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, observation_runner=case.runner), [])
                source = case.documents["command-results.json"]["records"][0]
                raw, = source["producerObservations"]
                for stream, captured in (("stdout", stdout), ("stderr", stderr)):
                    encoded = raw["rawStructuredFields"][stream].encode("utf-8", errors="strict")
                    self.assertEqual(encoded, captured)
                    self.assertEqual(len(encoded), source[stream + "BytesObserved"])
                    self.assertEqual(hashlib.sha256(encoded).hexdigest(), source[stream + "Sha256"])
                self.assertEqual(set(case.snapshots), set(ci.EVIDENCE_FILE_NAMES))
                self.assertTrue(all(d["schemaVersion"] == 2 for d in case.documents.values()))
                self.assertEqual(raw["schemaVersion"], ci.RAW_OBSERVATION_SCHEMA_VERSION)
                self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))

    def test_missing_undecodable_and_over_bound_capture(self):
        for stream in ("stdout", "stderr"):
            for state in ("missing empty", "missing nonempty", "undecodable", "over bound", "reserved backend marker"):
                data = b"" if state == "missing empty" else (b"\xff" if state == "undecodable" else
                    b"x" * (ci.MAX_EVIDENCE_STRING_BYTES + 1) if state == "over bound" else
                    ci._BACKEND_STREAM_REDACTION_MARKER.encode() if state == "reserved backend marker" else b"available\n")
                args = {stream: data}
                with self.subTest(stream=stream, state=state), retention_fixture(**args) as case:
                    if state.startswith("missing"):
                        setattr(case.capture, stream + "_raw", None)
                        setattr(case.capture, stream, data.decode())
                    self.assert_unavailable(case, stream + " " + state)

    def test_privacy_negative_matrix_preserves_authority_without_sentinels(self):
        cases = backend.unsafe_stream_cases()
        with tempfile.TemporaryDirectory(prefix="retention-private-") as temp:
            private_root = Path(temp)
            cases["repository root"] = str(ci.REPO_ROOT / "private-fixture.txt")
            cases["task private root"] = str(private_root / "private-fixture.txt")
            rejected = 0
            for stream in ("stdout", "stderr"):
                for label, text in cases.items():
                    with self.subTest(stream=stream, case=label), retention_fixture(**{stream: text.encode()}) as case:
                        self.assertFalse(ci._backend_exact_stream_text_is_safe(text), label)
                        self.assert_unavailable(case, stream + " " + label)
                        self.assertEqual(write_retention(case)["status"], "PASS")
                        record = case.documents["command-results.json"]["records"][0]
                        self.assertEqual(record[stream + "Sha256"], hashlib.sha256(text.encode()).hexdigest())
                        self.assertEqual(record[stream + "BytesObserved"], len(text.encode()))
                        for snapshot in case.snapshots.values():
                            self.assertNotIn(text.encode(), snapshot.data)
                            self.assertNotIn(ci._BACKEND_STREAM_REDACTION_MARKER.encode(), snapshot.data)
                        rejected += 1
        self.assertEqual(rejected, len(cases) * 2)
        print("W702_PRIVACY_ACCOUNTING " + json.dumps({"categories": sorted(cases), "categories_per_stream": len(cases),
            "streams": 2, "rejected": rejected, "exact_observations": 0, "sentinels": 0,
            "original_hash_length_preserved": rejected, "five_file_reread_pass": rejected}))

    def test_final_serialized_privacy_value_is_independently_rechecked(self):
        with retention_fixture() as case:
            original = ci._backend_exact_stream_text_is_safe
            checked = []
            def guard(value):
                checked.append(value)
                return original(value) and len(checked) < 4
            with mock.patch.object(ci, "_backend_exact_stream_text_is_safe", side_effect=guard):
                self.assert_unavailable(case, "independent final stderr privacy rejection")
            self.assertEqual(checked, ["", STREAM.decode(), "", STREAM.decode()])

    def test_execution_and_held_authority_fail_before_reconstruction(self):
        mutations = {
            "nonzero exit": lambda c: setattr(c.capture, "exit_code", 1),
            "not executed": lambda c: c.source.update(executed=False),
            "not started": lambda c: c.source.update(started=False),
            "setup failure": lambda c: c.source.update(setupFailure=True),
            "timeout": lambda c: setattr(c.capture, "timed_out", True),
            "output limit": lambda c: setattr(c.capture, "output_limited", True),
            "containment failure": lambda c: c.source.update(processTreeStatus="cleanup-failed"),
            "surviving descendant": lambda c: c.source.update(descendantsSurviving=1),
            "wrong containment": lambda c: c.source.update(containment="internal"),
            "cleanup failure": lambda c: c.source["protectedTargetBundle"].update(cleanupState="open"),
            "protected target mutation": lambda c: c.source["protectedTargetBundle"].update(mutationDetected=True),
            "missing bundle": lambda c: c.source.update(protectedTargetBundle=None),
            "stale held authority": lambda c: c.runner.execution_binding.update(runAttempt="2"),
            "stale prepared plan": lambda c: c.runner.command_plan[0].update(toolRole="python-other"),
            "command plan mismatch": lambda c: c.source.update(actualExecutionArgv=["forged"]),
            "wrong command role": lambda c: c.source.update(commandRole="observation-producing"),
            "capture detached from runner": lambda c: c.runner.captures.clear(),
            "copied authority": lambda c: setattr(c.runner, "_observation_authority", copy.deepcopy(c.capability)),
        }
        for stream in ("stdout", "stderr"):
            mutations[stream + " producer hash"] = lambda c, s=stream: c.source.update({s + "Sha256": "0" * 64})
            mutations[stream + " producer length"] = lambda c, s=stream: c.source.update({s + "BytesObserved": c.source[s + "BytesObserved"] + 1})
        for label, mutate in mutations.items():
            with self.subTest(case=label), retention_fixture() as case:
                mutate(case)
                self.assert_unavailable(case, label)
        for platform in ("windows", "ubuntu"):
            with retention_fixture(platform=platform, authorize=False) as case:
                self.assert_unavailable(case, platform + " no held authority")
                ci._issue_synthetic_observation_authority_for_test(case.runner)
                self.assert_unavailable(case, platform + " explicit synthetic authority cannot emit")
        with retention_fixture(platform="ubuntu") as case:
            self.assertIsNone(case.capability)
            self.assert_unavailable(case, "held Ubuntu production context")

    def test_exact_mutation_matrix_rejects_before_reconstruction(self):
        changes = {
            "stdout one byte": ("stdout", lambda s: s + "x"),
            "stderr one byte": ("stderr", lambda s: "S" + s[1:]),
            "stderr one character": ("stderr", lambda s: s.replace("4", "5", 1)),
            "LF to CRLF": ("stderr", lambda s: s.replace("\n", "\r\n")),
            "leading newline": ("stderr", lambda s: "\n" + s),
            "trailing newline": ("stderr", lambda s: s + "\n"),
            "Unicode codepoint": ("stderr", lambda s: s.replace("\u00e9", "e\u0301")),
        }
        for label in (*changes, "stdout hash", "stdout length", "stderr hash", "stderr length", "CRLF to LF"):
            stderr = STREAM + "caf\u00e9\n".encode()
            if label == "CRLF to LF":
                stderr = stderr.replace(b"\n", b"\r\n")
            with self.subTest(case=label), retention_fixture(stderr=stderr) as case:
                retain(case)
                write_retention(case)
                source = case.documents["command-results.json"]["records"][0]
                fields = source["producerObservations"][0]["rawStructuredFields"]
                if label in changes:
                    stream, mutate = changes[label]
                    fields[stream] = mutate(fields[stream])
                elif label == "CRLF to LF":
                    fields["stderr"] = fields["stderr"].replace("\r\n", "\n")
                else:
                    stream, field = label.split()
                    key = stream + ("Sha256" if field == "hash" else "BytesObserved")
                    source[key] = "0" * 64 if field == "hash" else source[key] + 1
                reseal(case)
                with retention_counters() as calls:
                    errors = ci._verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, observation_runner=case.runner)
                self.assertTrue(errors, label)
                self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0), label)
                print("W702_EXACT_MUTATION " + json.dumps({"case": label, "reconstruction_calls": 0,
                    "authoritative_derivation_calls": 0, **calls.semantic}))

    def test_prepared_verifiers_context_free_and_forged_admission_boundaries(self):
        with retention_fixture() as case:
            retain(case)
            write_retention(case)
            context, verifier = prepare_retention_verifier(case.runner, case.root)
            self.assertEqual(ci._observation_authority_for_runner(verifier, context).issuance, "live-verifier")
            self.assertEqual(ci._verify_evidence_file_set(case.output, repo_root=case.root,
                expected_command_plan=verifier.command_plan, expected_context=context, observation_runner=verifier), [])
            linux_context, linux = prepare_retention_verifier(case.runner, case.root, platform="ubuntu")
            for label, operation in (
                ("prepared Ubuntu", lambda: ci._verify_evidence_file_set(case.output, repo_root=case.root,
                    expected_command_plan=linux.command_plan, expected_context=linux_context, observation_runner=linux)),
                ("context free", lambda: ci.verify_evidence_file_set(case.output, repo_root=case.root,
                    expected_command_plan=case.runner.command_plan)),
                ("context strings without authority", lambda: ci.verify_evidence_file_set(case.output, repo_root=case.root,
                    expected_command_plan=verifier.command_plan, expected_context=context))):
                with retention_counters() as calls:
                    self.assertTrue(operation(), label)
                self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0), label)
            case.context = None
            proof, = ci._admit_standalone_observations(validation(case))
            source = case.documents["command-results.json"]["records"][0]
            self.assertTrue(ci._matching_observation_admission((proof,), source["producerObservations"][0], source))
            for fake in (copy.deepcopy(proof), replace(proof), ci._ObservationAdmission(proof.source, proof.observation, proof.validation)):
                with retention_counters() as calls, self.assertRaises(ValueError):
                    ci._reconstruct_observation_with_admission({"rawObservation": source["producerObservations"][0]},
                        source, profile_context={}, admissions=(fake,))
                self.assertEqual((calls.reconstruction.call_count, calls.derivation.call_count), (0, 0))
            print("W702_RETENTION_AUTHORITY Windows=PASS Ubuntu=DENY context-free=DENY copied-admission=DENY")

    def test_authority_or_positions_changed_at_candidate_preflight_drop_retention(self):
        for kind in ("late authority", "positional preflight"):
            with self.subTest(kind=kind), retention_fixture() as case:
                original = ci._preflight_command_record_positions
                def changed(records, plan):
                    self.assertEqual(len(records[0]["producerObservations"]), 1)
                    if kind == "late authority":
                        case.runner.execution_binding["runAttempt"] = "2"
                        return original(records, plan)
                    return None, ["rejected positional fixture"]
                with mock.patch.object(ci, "_preflight_command_record_positions", side_effect=changed):
                    self.assert_unavailable(case, kind)


@contextlib.contextmanager
def retention_generation_fixture():
    """Real Windows protected execution/profile/main/writer with bounded inputs.

    Checkout, runtime measurements and the unrelated prefix use public fixtures;
    the standalone child, its capture, bundle, admission and five files are real.
    """
    with tempfile.TemporaryDirectory(prefix="retention-main-") as temp:
        root = Path(temp)
        template, _ = runner_fixture(root)
        script = ("import unittest\n"
            "class PackagingFixture(unittest.TestCase):\n    pass\n"
            "for index in range(18):\n"
            "    setattr(PackagingFixture, 'test_%02d' % index, lambda self: self.assertTrue(True))\n"
            "unittest.main()\n")
        (root / PATH).write_bytes(script.encode())
        manifest = "developer/standalone-release-manifest.json"
        (root / manifest).write_bytes(b'{"files":["js/siteContent.js"]}\n')
        (root / "index.html").write_bytes(b'<script src="js/siteContent.js"></script>\n')
        standalone = template.command_plan[0]
        standalone.update(ordinal=702, targets=[ci._target_authority(root, PATH)])
        padding = fixtures.synthetic_command_spec("padding", "baseline-policy", 0)
        padding.update(profile="all", platform="windows")
        plan = []
        for ordinal in range(705):
            spec = copy.deepcopy(padding)
            spec.update(commandId=f"padding-{ordinal}", ordinal=ordinal)
            plan.append(spec)
        plan[702] = standalone
        member = fixtures.synthetic_command_spec("standalone-membership-audit", "standalone-membership", 703,
            command_role="observation-producing", allowed_exits=[0, 1],
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
            targets=[ci._target_authority(root, manifest), ci._target_authority(root, "index.html")])
        member.update(profile="all", platform="windows", resultSemantics="exact-membership-observation")
        plan[703] = member
        template.command_plan = plan
        template.command_results = [fixtures.synthetic_record_from_spec(spec) for spec in plan[:702]]
        template.captures, template.observations = [], []
        retention_rebind(template)
        binding = template.execution_binding
        runners, captures, events = [], [], []
        def initialize(runner, profile, baseline, **kwargs):
            runner.__dict__.update(copy.deepcopy(vars(template)))
            runner.execution_external_authority = kwargs["execution_external_authority"]
            runner.require_all_tools = mock.Mock()
            runner.require_tool = mock.Mock(side_effect=lambda name, **_: sys.executable if name == "python" else "D:/Git/cmd/git.exe")
            runner.tool_policy = SimpleNamespace(synthetic=True)
            runner.child_environment = dict(os.environ)
            def run():
                runner.run_standalone_profile()
                runner.add_internal_command(fixtures.synthetic_record_from_spec(plan[704]))
                return fixtures.empty_comparison()
            runner.run = run
            runners.append(runner)
        execute = ci.execute_planned_static_suite
        def executed(*args, **kwargs):
            result = execute(*args, **kwargs)
            captures.append(result[0])
            events.append("execute")
            return result
        preflight = ci._preflight_command_record_positions
        def preflighted(records, plan):
            if len(records) > 702 and records[702].get("producerObservations"):
                events.extend(("candidate", "preflight"))
            return preflight(records, plan)
        admit = ci._admit_standalone_observations
        def admitted(value):
            result = admit(value)
            if result:
                events.append("admission")
            return result
        reconstruct = ci._rederive_observation_record
        def reconstructed(item, source, **kwargs):
            if source.get("commandId") == "standalone-packaging":
                if "admission" not in events:
                    raise AssertionError("standalone reconstruction preceded admission")
                events.append("reconstruction")
            return reconstruct(item, source, **kwargs)
        derive = ci._derive_authoritative_evidence
        def derived(*args, **kwargs):
            events.append("derivation")
            return derive(*args, **kwargs)
        write = ci._exclusive_write
        def written(*args, **kwargs):
            events.append("write")
            return write(*args, **kwargs)
        reread = ci._verify_evidence_file_set
        def reread_files(*args, **kwargs):
            if kwargs.get("observation_runner") is not runners[0]:
                raise AssertionError("producer reread lost its held runner")
            events.append("reread")
            return reread(*args, **kwargs)
        console = io.StringIO()
        with mock.patch.dict(os.environ, retention_environment(binding)), mock.patch.object(ci, "REPO_ROOT", root), \
             mock.patch.object(ci.FoundationRunner, "__init__", initialize), \
             mock.patch.object(ci, "current_checkout_identity", return_value=(binding["checkoutCommit"], binding["checkoutTree"])), \
             mock.patch.object(ci, "ci_trust_file_set_authority", return_value=([], binding["trustFileDigest"])), \
             mock.patch.object(ci, "execute_planned_static_suite", side_effect=executed), \
             mock.patch.object(ci, "_preflight_command_record_positions", side_effect=preflighted), \
             mock.patch.object(ci, "_admit_standalone_observations", side_effect=admitted), \
             mock.patch.object(ci, "_rederive_observation_record", side_effect=reconstructed), \
             mock.patch.object(ci, "_derive_authoritative_evidence", side_effect=derived), \
             mock.patch.object(ci, "_exclusive_write", side_effect=written), \
             mock.patch.object(ci, "_verify_evidence_file_set", side_effect=reread_files), \
             contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
            code = ci.main(["--profile", "all"])
        if code != ci.EXIT_SUCCESS:
            raise AssertionError(console.getvalue())
        output = root / ".ci-results"
        documents, snapshots, errors = ci._read_evidence_documents_for_replay(output)
        if errors:
            raise AssertionError(errors)
        yield SimpleNamespace(root=root, output=output, runner=runners[0], capture=captures[0],
            source=runners[0].command_results[702], documents=documents, snapshots=snapshots, events=events)


def retention_json_differences(before, after, path=""):
    if isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after):
        return [item for key in sorted(before) for item in retention_json_differences(before[key], after[key], path + "/" + key)]
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return [item for i, (left, right) in enumerate(zip(before, after))
                for item in retention_json_differences(left, right, path + "/" + str(i))]
    return [] if before == after else [path]


class StandaloneRetentionProductionTest(unittest.TestCase):
    def test_real_main_ordinal_702_capture_admission_writer_and_prepared_reread(self):
        with retention_counters() as calls, retention_generation_fixture() as case:
            expected = ["execute", "candidate", "preflight", "admission", "reconstruction", "derivation", "write", "reread"]
            positions = [case.events.index(item) for item in expected]
            self.assertEqual(positions, sorted(positions), case.events)
            self.assertEqual(case.capture.stdout_raw, b"")
            self.assertTrue(case.capture.stderr_raw)
            self.assertTrue(case.capture.execution_passed())
            self.assertEqual(case.source["protectedTargetBundle"]["cleanupState"], "closed")
            self.assertIs(case.runner.captures[0], case.capture)
            raw, = case.documents["command-results.json"]["records"][702]["producerObservations"]
            self.assertEqual(raw["commandOrdinal"], 702)
            self.assertEqual(raw["occurrences"], 1)
            for stream in ("stdout", "stderr"):
                data = raw["rawStructuredFields"][stream].encode("utf-8", errors="strict")
                self.assertEqual(data, getattr(case.capture, stream + "_raw"))
                self.assertEqual(len(data), case.source[stream + "BytesObserved"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), case.source[stream + "Sha256"])
            context, verifier = prepare_retention_verifier(case.runner, case.root)
            self.assertEqual(ci._verify_evidence_file_set(case.output, repo_root=case.root,
                expected_command_plan=verifier.command_plan, expected_context=context, observation_runner=verifier), [])
            self.assertEqual(set(case.snapshots), set(ci.EVIDENCE_FILE_NAMES))
            self.assertTrue(all(doc["schemaVersion"] == 2 for doc in case.documents.values()))
            self.assertTrue(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                expected_command_plan=verifier.command_plan, expected_context=context))
            self.assertEqual((calls.parser.call_count, calls.backend_parser.call_count), (0, 0))
            print("W702_EXACT_SERIALIZED_OBSERVATION " + json.dumps(raw, ensure_ascii=True, sort_keys=True))
            print("W702_REAL_PRODUCER " + json.dumps({"ordinal": 702, "flow": expected, "files": sorted(case.snapshots),
                "stdoutBytesObserved": case.source["stdoutBytesObserved"], "stdoutSha256": case.source["stdoutSha256"],
                "stderrBytesObserved": case.source["stderrBytesObserved"], "stderrSha256": case.source["stderrSha256"],
                "authorized_reread": "PASS", **calls.semantic}))

    def test_bounded_windows_differential_and_ubuntu_byte_identical_output(self):
        # The A2 path is the same profile without the added retention call. Run
        # both writer projections from identical command/capture/time inputs.
        for platform in ("windows", "ubuntu"):
            with retention_fixture(platform=platform) as case:
                original = copy.deepcopy(case.runner)
                original.__dict__.pop("_observation_authority", None)
                with mock.patch.object(ci, "utc_now", return_value="2026-09-15T00:00:00Z"):
                    before = SimpleNamespace(root=case.root, runner=original)
                    write_retention(before, "before")
                    with retention_counters() as calls:
                        retain(case)
                        write_retention(case, "after")
                differences = {name: retention_json_differences(before.documents[name], case.documents[name])
                    for name in before.documents}
                differences = {name: paths for name, paths in differences.items() if paths}
                if platform == "ubuntu":
                    self.assertEqual(differences, {})
                    self.assertEqual({name: s.data for name, s in before.snapshots.items()},
                                     {name: s.data for name, s in case.snapshots.items()})
                    self.assertEqual(case.source["producerObservations"], [])
                else:
                    manifest_index = ci.EVIDENCE_MANIFEST_FILE_NAMES.index("command-results.json")
                    self.assertEqual(differences, {
                        "command-results.json": ["/producerObservationCount", "/producerObservationUniverseDigest",
                            "/producerTranscriptDigest", "/records/0/producerObservationSetDigest", "/records/0/producerObservations"],
                        "summary.json": [f"/evidenceManifest/{manifest_index}/byteLength", f"/evidenceManifest/{manifest_index}/sha256"]})
                    self.assertEqual(before.snapshots["summary.md"].data, case.snapshots["summary.md"].data)
                    self.assertEqual((before.documents["command-results.json"]["producerObservationCount"],
                                      case.documents["command-results.json"]["producerObservationCount"]), (0, 1))
                print("W702_PRODUCER_DIFFERENTIAL " + json.dumps({"platform": platform, "changed": differences,
                    "unchanged_files": sorted(name for name in case.snapshots if case.snapshots[name].data == before.snapshots[name].data),
                    **calls.semantic}, sort_keys=True))

    def test_windows_hosted_duration_drift_stays_raw_with_backend_701_two_two(self):
        self._assert_hosted_duration_drift_stays_raw("windows")

    def test_ubuntu_hosted_duration_drift_stays_raw_with_backend_701_two_two(self):
        self._assert_hosted_duration_drift_stays_raw("ubuntu")

    def _assert_hosted_duration_drift_stays_raw(self, platform):
        frontend = (687, 692, 695) if platform == "windows" else (687, 695)
        producer_backend = backend.fixture(platform, ordinal=701)
        replay_backend = backend.fixture(platform, ordinal=701, stdout=backend.npm_stdout("90", "912"), physical="9")
        with self.subTest(platform=platform), backend.outer_fixture(producer_backend, replay_backend,
            prefix_count=701, extra=("standalone-packaging",), hosted=True, frontend_ordinals=frontend) as outer:
            standalone, standalone_capture = runner_fixture(outer.root, platform)
            standalone.command_plan[0]["ordinal"] = standalone.command_results[0]["ordinal"] = 702
            runners = []
            for duration in (b"0.125", b"9.875"):
                runner = object.__new__(ci.FoundationRunner)
                runner.__dict__.update(copy.deepcopy(vars(outer.runner)))
                runner.child_environment = {}
                runner.command_plan[702] = copy.deepcopy(standalone.command_plan[0])
                runner.command_results[702] = copy.deepcopy(standalone.command_results[0])
                capture = copy.deepcopy(standalone_capture)
                retention_streams(runner.command_results[702], capture, stderr=STREAM.replace(b"0.125", duration))
                runner.captures.append(capture)
                runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}
                    for record in runner.command_results for raw in record["producerObservations"]]
                runners.append(runner)
            producer, replay_template = runners
            producer.command_plan[701] = copy.deepcopy(producer_backend.expected_authority)
            producer.command_results[701] = copy.deepcopy(producer_backend.command_record)
            producer.runtime = copy.deepcopy(producer_backend.runtime)
            producer.runtime_closure_document = copy.deepcopy(producer_backend.runtime_closure)
            producer.runtime_closure_digest = producer_backend.runtime_closure["closureDigest"]
            producer.runtime_closure_guard_evidence = copy.deepcopy(producer_backend.runtime_guard)
            producer.observations = [{"commandId": record["commandId"], "rawObservation": raw}
                for record in producer.command_results for raw in record["producerObservations"]]
            for runner in runners:
                retention_rebind(runner)
            live_retention_producer(producer, outer.root)
            context, replay = prepare_retention_verifier(replay_template, outer.root)
            with retention_counters() as calls:
                for runner in (producer, replay):
                    runner._retain_standalone_process_observation(runner.command_results[702], runner.captures[-1])
                    self.assertEqual(len(runner.command_results[702]["producerObservations"]), 1 if platform == "windows" else 0)
                producer_case = SimpleNamespace(root=outer.root, runner=producer)
                summary = write_retention(producer_case, "e1-evidence")
                self.assertEqual(summary["status"], "PASS", summary["policyViolations"])
                comparison = {key: summary[field] for key, field in (
                    ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
                    ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
                for ordinal in frontend:
                    backend.drift_unrelated_record(replay.command_results[ordinal])
                replay.run = mock.Mock(return_value=comparison)
                with mock.patch.object(ci, "rebuild_external_verification_context", return_value=context), \
                     mock.patch.object(backend.portable, "_identity", wraps=backend.portable._identity) as identity:
                    calls.backend_parser.reset_mock()
                    errors, transcript = ci.verify_evidence_with_replay(producer_case.output, expected_context=context,
                        verification_runner=replay, repo_root=outer.root, evidence_authority_root=outer.root)
                self.assertEqual(backend.unequal_ordinals(errors), [*frontend, 702], errors)
                self.assertEqual(transcript["finalAcceptance"], "REJECT")
                self.assertEqual((calls.backend_parser.call_count, identity.call_count), (2, 2))
                self.assertEqual([call.args[0] for call in calls.backend_parser.call_args_list],
                                 [producer_backend.stdout, replay_backend.stdout])
                if platform == "windows":
                    for runner in (producer, replay):
                        record = runner.command_results[702]
                        self.assertEqual(record["producerObservations"][0]["rawStructuredFields"]["stderr"].encode(),
                                         runner.captures[-1].stderr_raw)
                self.assertNotEqual(producer.captures[-1].stderr_raw, replay.captures[-1].stderr_raw)
                print("W702_HOSTED_RAW_REPLAY " + json.dumps({"platform": platform, "unequal": backend.unequal_ordinals(errors),
                    "finalAcceptance": transcript["finalAcceptance"], "backend_parser_calls": calls.backend_parser.call_count,
                    "backend_identity_calls": identity.call_count, "packaging_streams_to_backend_parser": 0, **calls.semantic}))


if __name__ == "__main__":
    unittest.main(verbosity=2, testRunner=fixtures.InventoryTextTestRunner)
