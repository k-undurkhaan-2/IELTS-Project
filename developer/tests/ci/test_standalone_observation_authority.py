"""W702-A2/E1/E2 authority, retention and portability, outside the 476-test inventory.

Hosted-shaped contexts use explicit fixtures. E1 retains exact safe Windows
process bytes. E2 parses them only inside the fully authorized outer verifier.
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
    # E1 retention must never invoke E2. Observe real production call frames
    # as well as mocks so accidental parser/identity calls cannot go unnoticed.
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



# E2 fixtures are synthetic production-shaped bytes, never private acquisition
# data. Their independent fixed inventory is also checked against the real suite.
PACKAGING_METHODS = (
    "test_archive_entries_are_unique_portable_relative_and_not_symlinks",
    "test_archive_list_verifier_rejects_duplicate_and_unsafe_entries",
    "test_authorized_reading_has_real_windows_unix_parity_and_hashes",
    "test_clean_no_git_source_archive_still_releases_safely",
    "test_default_windows_and_unix_release_use_one_positive_manifest",
    "test_extracted_payload_is_self_contained_and_serves_required_styles",
    "test_git_manifest_and_payload_dirty_changes_fail_closed",
    "test_main_manifest_missing_malformed_schema_and_paths_fail_closed",
    "test_manifest_listed_path_reparse_fails_closed",
    "test_private_listening_switch_fails_and_root_is_not_scanned",
    "test_reading_file_and_external_manifest_reparse_fail_closed",
    "test_reading_hash_missing_duplicate_and_unsafe_paths_fail_closed",
    "test_reading_root_requires_explicit_manifest",
    "test_reading_unknown_and_hidden_files_fail_closed",
    "test_required_and_manifest_listed_files_fail_closed_when_missing",
    "test_required_root_fails_before_zip_on_windows_and_unix",
    "test_scripts_consume_only_the_shared_manifest_helper_staging_contract",
    "test_unknown_files_in_every_managed_root_fail_before_staging",
)
PACKAGING_DURATIONS = (("0.000", "0.001"), ("1.000", "9.999"), ("9.999", "10.000"),
                       ("69.940", "76.421"), ("71.630", "100.000"))


def packaging_reporter(duration="69.940"):
    return (b"".join(f"{method} (__main__.StandalonePackagingTest.{method}) ... ok\r\n".encode()
                    for method in PACKAGING_METHODS)
            + b"\r\n" + b"-" * 70 + b"\r\nRan 18 tests in " + duration.encode()
            + b"s\r\n\r\nOK\r\n")


def packaging_reporter_mutations():
    good = packaging_reporter()
    lines = good.split(b"\r\n")
    first = PACKAGING_METHODS[0].encode()
    cases = {
        "method-name": good.replace(first, b"test_changed"),
        "fully-qualified-id": good.replace(b"." + first + b")", b".test_changed)", 1),
        "class-name": good.replace(b"StandalonePackagingTest", b"OtherPackagingTest", 1),
        "module-name": good.replace(b"__main__", b"alternate", 1),
        "left-right-disagree": good.replace(first, b"test_changed", 1),
        "missing-method": b"\r\n".join(lines[1:]),
        "additional-method": lines[0] + b"\r\n" + good,
        "duplicate-method": b"\r\n".join([lines[0], *lines]),
        "reordered-methods": b"\r\n".join([lines[1], lines[0], *lines[2:]]),
        "17-tests": good.replace(b"18 tests", b"17 tests"),
        "19-tests": good.replace(b"18 tests", b"19 tests"),
        "separator-69": good.replace(b"-" * 70, b"-" * 69),
        "separator-71": good.replace(b"-" * 70, b"-" * 71),
        "separator-character": good.replace(b"-" * 70, b"-" * 35 + b"=" + b"-" * 34),
        "missing-blank-before-separator": good.replace(b"\r\n\r\n---", b"\r\n---"),
        "extra-blank-before-separator": good.replace(b"\r\n\r\n---", b"\r\n\r\n\r\n---"),
        "missing-blank-before-OK": good.replace(b"s\r\n\r\nOK", b"s\r\nOK"),
        "extra-blank-before-OK": good.replace(b"s\r\n\r\nOK", b"s\r\n\r\n\r\nOK"),
        "Ran-literal": good.replace(b"Ran ", b"ran "),
        "tests-literal": good.replace(b"18 tests", b"18 Tests"),
        "in-literal": good.replace(b" in ", b" at "),
        "missing-s": good.replace(b"69.940s", b"69.940"),
        "OK-literal": good.replace(b"\r\nOK\r\n", b"\r\nok\r\n"),
        "suffix-text": good + b"extra\r\n",
        "prefix-text": b"extra\r\n" + good,
        "warning": good.replace(b"\r\n\r\n---", b"\r\nwarning\r\n\r\n---"),
        "traceback": good.replace(b"\r\n\r\n---", b"\r\nTraceback (most recent call last):\r\n\r\n---"),
        "LF-only": good.replace(b"\r\n", b"\n"),
        "mixed-line-endings": good.replace(b"\r\n", b"\n", 1),
        "missing-final-CRLF": good[:-2],
        "trailing-spaces": good.replace(b" ... ok\r\n", b" ... ok \r\n", 1),
        "leading-spaces": b" " + good,
        "unicode-outside-duration": good.replace(b"test_archive", "test_archiv\u00e9".encode(), 1),
        "invalid-UTF8": b"\xff" + good[1:],
        "per-test-duration": good.replace(b" ... ok\r\n", b" ... ok (0.123s)\r\n", 1),
        "extra-final-blank": good + b"\r\n",
        "dots-mechanism": b"." * 18 + b"\r\n" + b"-" * 70 + b"\r\nRan 18 tests in 0.125s\r\n\r\nOK\r\n",
    }
    for status in ("skipped", "expected failure", "unexpected success", "FAIL", "ERROR",
                   "OK", "Ok", "oK", "success"):
        cases["status-" + status] = good.replace(b" ... ok\r\n", b" ... " + status.encode() + b"\r\n", 1)
    for name, value in (("integer", "1"), ("fraction-1", "1.0"), ("fraction-2", "1.00"),
                        ("fraction-4", "1.0000"), ("exponent", "1e3"),
                        ("negative", "-1.000"), ("plus", "+1.000"),
                        ("whitespace", "1 .000"), ("non-ASCII-digit", "\u0661.000")):
        cases["duration-" + name] = good.replace(b"69.940", value.encode())
    return cases


def packaging_python_authority(evidence):
    size, sha, identity = ci._measured_file_authority(Path(sys.executable))
    evidence.runtime_closure["pythonExecutable"].update(
        canonicalPath=str(Path(sys.executable).resolve()), size=size, sha256=sha, stableIdentity=identity)
    closure = evidence.runtime_closure
    closure["closureDigest"] = hashlib.sha256(ci._canonical_frame({
        key: value for key, value in closure.items() if key != "closureDigest"})).hexdigest()
    evidence.runtime["runtimeClosureDigest"] = closure["closureDigest"]
    evidence.command_record["runtimeClosureDigest"] = closure["closureDigest"]


@contextlib.contextmanager
def packaging_replay_fixture(platform="windows", *, producer_stderr=None, replay_stderr=None,
                             producer_stdout=b"", replay_stdout=b""):
    frontend = (687, 692, 695) if platform == "windows" else (687, 695)
    producer_backend = backend.fixture(platform, ordinal=701)
    replay_backend = backend.fixture(platform, ordinal=701, stdout=backend.npm_stdout("90", "912"), physical="9")
    for evidence in (producer_backend, replay_backend):
        packaging_python_authority(evidence)
    with backend.outer_fixture(producer_backend, replay_backend, prefix_count=701,
            extra=("standalone-packaging",), hosted=True, frontend_ordinals=frontend) as outer:
        standalone, template_capture = runner_fixture(outer.root, platform)
        standalone.command_plan[0]["ordinal"] = standalone.command_results[0]["ordinal"] = 702
        runners = []
        streams = ((producer_stdout, packaging_reporter() if producer_stderr is None else producer_stderr),
                   (replay_stdout, packaging_reporter("76.421") if replay_stderr is None else replay_stderr))
        for stdout, stderr in streams:
            runner = object.__new__(ci.FoundationRunner)
            runner.__dict__.update(copy.deepcopy(vars(outer.runner)))
            runner.child_environment = {}
            runner.command_plan[702] = copy.deepcopy(standalone.command_plan[0])
            runner.command_results[702] = copy.deepcopy(standalone.command_results[0])
            capture = copy.deepcopy(template_capture)
            capture.containment_disposition = "no-descendants"
            capture.descendants_observed = capture.descendants_reaped = 0
            source = runner.command_results[702]
            source.update(containmentDisposition="no-descendants", descendantsObserved=0, descendantsReaped=0)
            retention_streams(source, capture, stdout=stdout, stderr=stderr)
            runner.captures.append(capture)
            runners.append(runner)
        producer, template = runners
        producer.command_plan[701] = copy.deepcopy(producer_backend.expected_authority)
        producer.command_results[701] = copy.deepcopy(producer_backend.command_record)
        producer.runtime = copy.deepcopy(producer_backend.runtime)
        producer.runtime_closure_document = copy.deepcopy(producer_backend.runtime_closure)
        producer.runtime_closure_digest = producer_backend.runtime_closure["closureDigest"]
        producer.runtime_closure_guard_evidence = copy.deepcopy(producer_backend.runtime_guard)
        for runner in runners:
            runner.observations = [{"commandId": record["commandId"], "rawObservation": raw}
                for record in runner.command_results for raw in record["producerObservations"]]
            retention_rebind(runner)
        live_retention_producer(producer, outer.root)
        context, replay = prepare_retention_verifier(template, outer.root)
        for runner in (producer, replay):
            runner._retain_standalone_process_observation(runner.command_results[702], runner.captures[-1])
        case = SimpleNamespace(root=outer.root, runner=producer)
        summary = write_retention(case, "e2-evidence")
        if summary["status"] != "PASS":
            raise AssertionError(summary["policyViolations"])
        comparison = {key: summary[field] for key, field in (
            ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
            ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
        for ordinal in frontend:
            backend.drift_unrelated_record(replay.command_results[ordinal])
        replay.run = mock.Mock(return_value=comparison)
        case.producer, case.runner, case.context = producer, replay, context
        case.frontend, case.comparison = list(frontend), comparison
        with mock.patch.object(ci, "rebuild_external_verification_context", return_value=context):
            yield case


@contextlib.contextmanager
def packaging_counters():
    with mock.patch.object(ci, "_parse_standalone_packaging_stderr",
                           wraps=ci._parse_standalone_packaging_stderr) as parser, \
         mock.patch.object(ci, "_standalone_packaging_semantic_identity",
                           wraps=ci._standalone_packaging_semantic_identity) as identity, \
         mock.patch.object(backend.portable, "_parse_stdout", wraps=backend.portable._parse_stdout) as backend_parser, \
         mock.patch.object(backend.portable, "_identity", wraps=backend.portable._identity) as backend_identity:
        yield SimpleNamespace(parser=parser, identity=identity, backend_parser=backend_parser, backend_identity=backend_identity)


class StandalonePackagingPortableParserTest(unittest.TestCase):
    def test_exact_production_inventory_and_verbose_entrypoint(self):
        import ast
        tree = ast.parse((Path(__file__).parent / "test_standalone_packaging.py").read_text(encoding="utf-8"))
        suite, = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "StandalonePackagingTest"]
        self.assertEqual(tuple(sorted(node.name for node in suite.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))), PACKAGING_METHODS)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "main"
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == "unittest"]
        self.assertEqual(len(calls), 1)
        self.assertEqual([(kw.arg, ast.literal_eval(kw.value)) for kw in calls[0].keywords], [("verbosity", 2)])

    def test_structural_variable_length_duration_pairs_and_exact_retained_bytes(self):
        for left, right in PACKAGING_DURATIONS:
            with self.subTest(left=left, right=right), packaging_counters() as calls:
                data = [packaging_reporter(value) for value in (left, right)]
                pair = ci._StandalonePortablePair(702, *data, b"isolated-parser-unit")
                result = ci._derive_standalone_packaging_equal_result(pair)
                self.assertIsNotNone(result)
                self.assertEqual((calls.parser.call_count, calls.identity.call_count), (2, 2))
                spans = []
                for value in data:
                    parsed = ci._parse_standalone_packaging_stderr(value)
                    start, end = parsed.duration_span
                    self.assertEqual(value[:start] + value[end:], parsed.prefix + parsed.suffix)
                    self.assertEqual(bytes.fromhex(result["prefixHex"]), value[:start])
                    self.assertEqual(bytes.fromhex(result["suffixHex"]), value[end:])
                    self.assertEqual(len(parsed.prefix) + len(parsed.suffix), 3039)
                    spans.append({"excluded": [start, end], "retained": [[0, start], [end, len(value)]]})
                print("W702_E2_POSITIVE_SPANS " + json.dumps({"durations": [left, right], "spans": spans}))

    def test_reporter_negative_matrix_both_sides_has_zero_identity_calls(self):
        mutations = packaging_reporter_mutations()
        for name, bad in mutations.items():
            for side in ("producer", "replay"):
                with self.subTest(name=name, side=side), packaging_counters() as calls:
                    streams = (bad, packaging_reporter()) if side == "producer" else (packaging_reporter(), bad)
                    self.assertIsNone(ci._derive_standalone_packaging_equal_result(
                        ci._StandalonePortablePair(702, *streams, b"isolated-parser-unit")))
                    self.assertEqual(calls.identity.call_count, 0)
                    self.assertEqual(calls.parser.call_count, 1 if side == "producer" else 2)
        print("W702_E2_REPORTER_MATRIX " + json.dumps({"cases": sorted(mutations),
            "mutations": len(mutations), "both_sides": 2 * len(mutations), "identity_calls": 0}))

    def test_every_retained_byte_position_rejects_ascii_and_unicode_mutations(self):
        good = packaging_reporter()
        start, end = ci._parse_standalone_packaging_stderr(good).duration_span
        positions = [*range(start), *range(end, len(good))]
        with mock.patch.object(ci, "_standalone_packaging_semantic_identity",
                               wraps=ci._standalone_packaging_semantic_identity) as identity:
            for index in positions:
                for replacement in (bytes([good[index] ^ 1]), "\u00e9".encode()):
                    bad = good[:index] + replacement + good[index + 1:]
                    self.assertIsNone(ci._derive_standalone_packaging_equal_result(
                        ci._StandalonePortablePair(702, good, bad, b"isolated-parser-unit")), index)
            self.assertEqual(identity.call_count, 0)
        print("W702_E2_BYTE_MATRIX " + json.dumps({"retained_positions": len(positions),
            "mutations": len(positions) * 2, "identity_calls": 0}))




class StandalonePackagingFixtureTestBase(unittest.TestCase):
    """Reuse synthetic setup only; every case reruns the complete real verifier."""
    @classmethod
    def setUpClass(cls):
        cls._fixture_stack = contextlib.ExitStack()
        cls._fixture_cases = {}
        padding_comparisons = {}
        canonical_record = ci._canonical_transcript_record
        def canonical_with_identical_padding(record):
            # Memoize only deterministic comparisons of exact synthetic padding.
            # Every authority check and every 687/692/695/701/702 projection uses
            # production code afresh. This is neither evidence nor a test receipt.
            if (record.get("commandClass") == "baseline-policy"
                    and record.get("commandId", "").startswith("fixture-")
                    and record.get("targets") == [] and record.get("producerObservations") == []
                    and record.get("executionInputMode") == "NONE"):
                key = (str(ci.REPO_ROOT), tempfile.gettempdir(), ci._observation_bytes(record))
                if key not in padding_comparisons:
                    padding_comparisons[key] = canonical_record(record)
                return copy.deepcopy(padding_comparisons[key])
            return canonical_record(record)
        cls._fixture_stack.enter_context(mock.patch.object(
            ci, "_canonical_transcript_record", new=canonical_with_identical_padding))

    @classmethod
    def tearDownClass(cls):
        cls._fixture_stack.close()

    @contextlib.contextmanager
    def fixture(self, platform="windows", *, producer_stderr=None, replay_stderr=None,
                producer_stdout=b"", replay_stdout=b""):
        if producer_stdout or (producer_stderr is not None and producer_stderr != packaging_reporter()):
            # A changed producer must rebuild all baseline-bound summary fields
            # through the ordinary writer, not merely reseal the raw record.
            with packaging_replay_fixture(platform, producer_stderr=producer_stderr,
                    replay_stderr=replay_stderr, producer_stdout=producer_stdout,
                    replay_stdout=replay_stdout) as case:
                yield case
            return
        cache = type(self)._fixture_cases
        if platform not in cache:
            case = type(self)._fixture_stack.enter_context(packaging_replay_fixture(platform))
            held_keys = {"_observation_authority", "execution_external_authority", "external_verification_context"}
            held = {key: value for key, value in vars(case.runner).items() if key in held_keys}
            state = copy.deepcopy({key: value for key, value in vars(case.runner).items() if key not in held_keys})
            cache[platform] = (case, held, state, copy.deepcopy(case.documents), copy.deepcopy(vars(case.context)))
        case, held, state, documents, context_fields = cache[platform]
        case.runner.__dict__.clear()
        case.runner.__dict__.update(copy.deepcopy(state))
        case.runner.__dict__.update(held)
        for key, value in context_fields.items():
            object.__setattr__(case.context, key, copy.deepcopy(value))
        case.documents = copy.deepcopy(documents)
        # This exact extra file is created solely by the membership mutation.
        (case.output / "extra.json").unlink(missing_ok=True)
        with mock.patch.object(ci, "REPO_ROOT", case.root), \
             mock.patch.object(ci, "rebuild_external_verification_context", return_value=case.context):
            source = case.documents["command-results.json"]["records"][702]
            stdout = producer_stdout
            stderr = packaging_reporter() if producer_stderr is None else producer_stderr
            for stream, data in (("stdout", stdout), ("stderr", stderr)):
                source[stream + "Sha256"] = hashlib.sha256(data).hexdigest()
                source[stream + "BytesObserved"] = len(data)
                if source["producerObservations"]:
                    source["producerObservations"][0]["rawStructuredFields"][stream] = data.decode()
            backend.reseal_producer(case)
            record = case.runner.command_results[702]
            record["producerObservations"] = []
            record["producerObservationSetDigest"] = ci.producer_observation_set_digest([])
            case.runner.observations = [item for item in case.runner.observations
                                       if item["commandId"] != "standalone-packaging"]
            retention_streams(record, case.runner.captures[-1], stdout=replay_stdout,
                stderr=packaging_reporter("76.421") if replay_stderr is None else replay_stderr)
            case.runner._retain_standalone_process_observation(record, case.runner.captures[-1])
            yield case

class StandalonePackagingPortableReplayTest(StandalonePackagingFixtureTestBase):
    def assert_result(self, case, errors, transcript, calls, *, portable, parser_calls, identity_calls):
        expected = case.frontend if portable else [*case.frontend, 702]
        self.assertEqual(backend.unequal_ordinals(errors), expected, errors)
        self.assertIsNotNone(transcript, errors)
        self.assertEqual(transcript["finalAcceptance"], "REJECT")
        self.assertEqual((calls.parser.call_count, calls.identity.call_count), (parser_calls, identity_calls))
        self.assertEqual((calls.backend_parser.call_count, calls.backend_identity.call_count), (2, 2))
        self.assertNotIn(701, backend.unequal_ordinals(errors))

    def test_windows_positive_pairs_keep_frontend_reject_and_raw_evidence_unchanged(self):
        for left, right in PACKAGING_DURATIONS:
            with self.subTest(left=left, right=right), self.fixture(
                    producer_stderr=packaging_reporter(left), replay_stderr=packaging_reporter(right)) as case:
                before = {name: (case.output / name).read_bytes() for name in ci.EVIDENCE_FILE_NAMES}
                records = ci._observation_bytes(case.runner.command_results)
                canonical = ci._canonical_transcript_record(case.runner.command_results[702])
                with packaging_counters() as calls:
                    errors, transcript = backend.verify(case)
                self.assert_result(case, errors, transcript, calls, portable=True, parser_calls=2, identity_calls=2)
                self.assertEqual(before, {name: (case.output / name).read_bytes() for name in ci.EVIDENCE_FILE_NAMES})
                self.assertEqual(ci._observation_bytes(case.runner.command_results), records)
                self.assertEqual(ci._canonical_transcript_record(case.runner.command_results[702]), canonical)
                self.assertNotEqual(transcript["records"][702]["stderrSha256"],
                    case.documents["command-results.json"]["records"][702]["stderrSha256"])
                print("W702_E2_HOSTED " + json.dumps({"platform": "windows", "durations": [left, right],
                    "unequal": backend.unequal_ordinals(errors), "finalAcceptance": transcript["finalAcceptance"],
                    "backend_parser": calls.backend_parser.call_count, "backend_identity": calls.backend_identity.call_count,
                    "packaging_parser": calls.parser.call_count, "packaging_identity": calls.identity.call_count}))

    def test_ubuntu_matching_windows_grammar_never_calls_packaging_and_stays_raw(self):
        with self.fixture("ubuntu") as case, packaging_counters() as calls:
            errors, transcript = backend.verify(case)
            self.assert_result(case, errors, transcript, calls, portable=False, parser_calls=0, identity_calls=0)
            self.assertEqual(case.documents["command-results.json"]["records"][702]["producerObservations"], [])
            print("W702_E2_HOSTED " + json.dumps({"platform": "ubuntu", "unequal": backend.unequal_ordinals(errors),
                "finalAcceptance": transcript["finalAcceptance"], "backend_parser": calls.backend_parser.call_count,
                "backend_identity": calls.backend_identity.call_count, "packaging_parser": 0, "packaging_identity": 0}))

    def test_every_reporter_mutation_retains_702_after_real_outer_authority(self):
        for name, bad in packaging_reporter_mutations().items():
            # Invalid UTF-8 cannot pass E1 retention; that case instead proves
            # raw capture unavailability/retention denial before the parser.
            if name == "invalid-UTF8":
                continue
            with self.subTest(name=name), self.fixture(replay_stderr=bad) as case, packaging_counters() as calls:
                errors, transcript = backend.verify(case)
                self.assert_result(case, errors, transcript, calls, portable=False, parser_calls=2, identity_calls=0)
                print("W702_E2_OUTER_MUTATION " + json.dumps({"case": name, "unequal": backend.unequal_ordinals(errors),
                    "parser": calls.parser.call_count, "identity": calls.identity.call_count, "finalAcceptance": "REJECT"}))

    def test_parser_unavailable_and_missing_raw_captures_retain_702(self):
        for mode in ("parser-raises", "parser-returns-none", "parser-missing", "parser-not-callable",
                     "stdout-raw-missing", "stderr-raw-missing", "capture-missing", "duplicate-capture"):
            with self.subTest(mode=mode), self.fixture() as case, packaging_counters() as calls, contextlib.ExitStack() as overrides:
                if mode == "parser-raises":
                    calls.parser.side_effect = ValueError("unavailable")
                elif mode == "parser-returns-none":
                    calls.parser.return_value = None
                elif mode == "parser-missing":
                    calls.parser.side_effect = TypeError("unavailable callable")
                elif mode == "parser-not-callable":
                    overrides.enter_context(mock.patch.object(ci, "_parse_standalone_packaging_stderr", None))
                elif mode.endswith("-raw-missing"):
                    setattr(case.runner.captures[-1], mode.split("-")[0] + "_raw", None)
                elif mode == "capture-missing":
                    case.runner.captures.pop()
                elif mode == "duplicate-capture":
                    case.runner.captures.append(copy.deepcopy(case.runner.captures[-1]))
                errors, transcript = backend.verify(case)
                self.assert_result(case, errors, transcript, calls, portable=False,
                    parser_calls=(2 if mode == "parser-returns-none" else 1)
                    if mode.startswith("parser") and mode != "parser-not-callable" else 0,
                    identity_calls=0)

    def test_nonempty_stdout_on_either_side_and_both_sides_blocks_before_parser(self):
        for producer, replay in ((b"diagnostic", b""), (b"", b"diagnostic"), (b"diagnostic", b"diagnostic")):
            with self.subTest(producer=producer, replay=replay), self.fixture(
                    producer_stdout=producer, replay_stdout=replay) as case, packaging_counters() as calls:
                errors, transcript = backend.verify(case)
                self.assert_result(case, errors, transcript, calls, portable=False, parser_calls=0, identity_calls=0)

    def test_source_only_apis_have_no_portability_or_selection_knobs(self):
        with self.fixture() as case, packaging_counters() as calls:
            errors, transcript = ci.compare_verification_replay_claims(
                case.documents, case.runner, case.comparison)[::-1]
            self.assertIn(702, backend.unequal_ordinals(errors))
            result, errors = ci.run_verification_replay(case.documents, expected_context=case.context,
                verification_runner=case.runner, repo_root=case.root)
            self.assertTrue(errors)
            self.assertIsNone(result)
            self.assertEqual((calls.parser.call_count, calls.identity.call_count), (0, 0))
            for api in (ci.verify_evidence_file_set, ci._validate_evidence_semantics,
                        ci.run_verification_replay, ci.compare_verification_replay_claims,
                        ci.verify_evidence_with_replay):
                self.assertFalse(set(inspect.signature(api).parameters) & {
                    "portable", "allow_packaging", "expected_os", "parser", "semantic_result"})


class StandalonePackagingPortableAuthorityTest(StandalonePackagingFixtureTestBase):
    def assert_preparser_reject(self, case, errors, transcript, calls):
        self.assertTrue(errors)
        self.assertTrue(transcript is None or transcript.get("finalAcceptance") == "REJECT")
        self.assertEqual((calls.parser.call_count, calls.identity.call_count), (0, 0))
        if transcript is not None:
            self.assertIn(702, backend.unequal_ordinals(errors), errors)
        # The persisted source/raw comparison never gains a portable projection.
        source = case.documents["command-results.json"]["records"][702]
        self.assertNotEqual(ci._canonical_transcript_record(source),
                            ci._canonical_transcript_record(case.runner.command_results[702]))

    def test_missing_producer_admission_retains_702_with_zero_packaging_calls(self):
        with self.fixture() as case, packaging_counters() as calls, \
             mock.patch.object(ci, "_bind_standalone_portable_producer", return_value=None):
            errors, transcript = backend.verify(case)
            self.assert_preparser_reject(case, errors, transcript, calls)
            self.assertEqual(backend.unequal_ordinals(errors), [687, 692, 695, 702])
            self.assertEqual((calls.backend_parser.call_count, calls.backend_identity.call_count), (2, 2))

    def test_coherent_evidence_replacement_between_first_and_second_snapshots(self):
        with self.fixture() as case, packaging_counters() as calls:
            original = ci._verify_evidence_file_set
            def replace_after_first(*args, **kwargs):
                errors = original(*args, **kwargs)
                self.assertEqual(errors, [])
                source = case.documents["command-results.json"]["records"][702]
                data = packaging_reporter("70.000")
                source.update(stderrSha256=hashlib.sha256(data).hexdigest(), stderrBytesObserved=len(data))
                source["producerObservations"][0]["rawStructuredFields"]["stderr"] = data.decode()
                backend.reseal_producer(case)
                return errors
            with mock.patch.object(ci, "_verify_evidence_file_set", side_effect=replace_after_first):
                errors, transcript = backend.verify(case)
            self.assert_preparser_reject(case, errors, transcript, calls)
            self.assertTrue(any("between first and second" in error for error in errors))
            case.runner.run.assert_not_called()

    def test_post_admission_and_current_authority_mutations_precede_parser(self):
        def change_file_identity(case, producer):
            path = case.output / "summary.md"
            stat = path.stat()
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        def change_capture(case, producer):
            record = case.runner.command_results[702]
            data = packaging_reporter("100.000")
            retention_streams(record, case.runner.captures[-1], stderr=data)
            raw, = record["producerObservations"]
            raw["rawStructuredFields"]["stderr"] = data.decode()
            raw["sourceOutputDigest"] = ci.command_output_digest(record)
            raw["producerRecordDigest"] = ci._producer_record_digest({
                key: value for key, value in raw.items() if key != "producerRecordDigest"})
            record["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
        mutations = {
            "producer-observation-after-admission": lambda c, p: p.validation.records[702]["producerObservations"][0]["rawStructuredFields"].update(stderr="changed"),
            "source-record-after-admission": lambda c, p: p.validation.records[702].update(durationSeconds=99),
            "prepared-plan": lambda c, p: c.runner.command_plan[702].update(toolRole="changed"),
            "expected-context": lambda c, p: object.__setattr__(c.context, "run_attempt", "2"),
            "file-identity": change_file_identity,
            "directory-membership": lambda c, p: (c.output / "extra.json").write_bytes(b"{}"),
            "snapshot-document": lambda c, p: p.validation.documents["summary.json"].update(status="REJECT"),
            "snapshot-identity": lambda c, p: p.validation.snapshots.update({
                "summary.md": replace(p.validation.snapshots["summary.md"], identity=(1, 2, 3, 4, 5))}),
            "fresh-replay-tool-authority": lambda c, p: c.runner.command_results[702].update(resolvedExecutableSha256="c" * 64),
            "fresh-replay-protected-input": lambda c, p: c.runner.command_results[702]["protectedTargetBundle"].update(mutationDetected=True),
            "fresh-runtime-authority": lambda c, p: c.runner.runtime_closure_document["pythonExecutable"].update(sha256="c" * 64),
            "fresh-runtime-guard": lambda c, p: c.runner.runtime_closure_guard_evidence.update(mutationEventCount=1),
            "fresh-capture-consistent-new-duration": change_capture,
            "verifier-authority-revoked": lambda c, p: c.runner.__dict__.pop("_observation_authority"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.fixture() as case, packaging_counters() as calls:
                original = ci._bind_standalone_portable_replay
                bound = []
                def mutate_after_first(producer):
                    value = original(producer)
                    if not bound:
                        self.assertIsNotNone(value, name)
                        bound.append(value)
                        mutate(case, producer)
                    return value
                with mock.patch.object(ci, "_bind_standalone_portable_replay", side_effect=mutate_after_first):
                    errors, transcript = backend.verify(case)
                self.assert_preparser_reject(case, errors, transcript, calls)
                self.assertEqual(len(bound), 1)
                print("W702_E2_AUTHORITY_MUTATION " + json.dumps({
                    "case": name, "parser": 0, "identity": 0, "finalAcceptance": "REJECT"}))

    def test_local_execution_and_capture_mutations_precede_parser(self):
        mutations = {
            "exit": lambda c: c.runner.command_results[702].update(exitCode=1),
            "not-executed": lambda c: c.runner.command_results[702].update(executed=False),
            "containment": lambda c: c.runner.command_results[702].update(containment="internal"),
            "descendant-observed": lambda c: c.runner.command_results[702].update(descendantsObserved=1),
            "descendant-reaped": lambda c: c.runner.command_results[702].update(descendantsReaped=1),
            "descendant-surviving": lambda c: c.runner.command_results[702].update(descendantsSurviving=1),
            "descendant-terminated": lambda c: c.runner.command_results[702].update(descendantsTerminated=1),
            "stdout-length": lambda c: c.runner.captures[-1].__dict__.update(stdout_bytes=1),
            "stderr-length": lambda c: c.runner.captures[-1].__dict__.update(stderr_bytes=1),
            "stderr-hash": lambda c: c.runner.command_results[702].update(stderrSha256="c" * 64),
            "capture-argv": lambda c: c.runner.captures[-1].argv.append("--changed"),
            "capture-input-mode": lambda c: c.runner.captures[-1].__dict__.update(execution_input_mode="NONE"),
            "capture-exit": lambda c: c.runner.captures[-1].__dict__.update(exit_code=1),
            "capture-error": lambda c: c.runner.captures[-1].__dict__.update(error="changed"),
            "capture-timeout": lambda c: c.runner.captures[-1].__dict__.update(timed_out=True),
            "capture-output-limit": lambda c: c.runner.captures[-1].__dict__.update(output_limited=True),
            "capture-UTF8": lambda c: c.runner.captures[-1].__dict__.update(stderr_raw=b"\xff"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.fixture() as case, packaging_counters() as calls:
                mutate(case)
                errors, transcript = backend.verify(case)
                self.assert_preparser_reject(case, errors, transcript, calls)
                print("W702_E2_EXECUTION_MUTATION " + json.dumps({
                    "case": name, "parser": 0, "identity": 0, "finalAcceptance": "REJECT"}))

def _r1_legacy_canonical_replay_value(value):
    """Frozen e0f8a1e0 traversal, independent of the optimized recursion."""
    if isinstance(value, Mapping):
        return {str(key): _r1_legacy_canonical_replay_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_r1_legacy_canonical_replay_value(item) for item in value]
    if isinstance(value, str):
        temporary_root = str(ci.Path(tempfile.gettempdir()).resolve())
        normalized = value
        for spelling in {temporary_root, temporary_root.replace("\\", "/"),
                         temporary_root.replace("/", "\\")}:
            if spelling:
                normalized = ci.re.sub(ci.re.escape(spelling), "<TASK-TEMP>", normalized,
                                       flags=ci.re.IGNORECASE if ci.os.name == "nt" else 0)
        repository_root = str(ci.REPO_ROOT.resolve())
        for spelling in {repository_root, repository_root.replace("\\", "/"),
                         repository_root.replace("/", "\\")}:
            if spelling:
                normalized = ci.re.sub(ci.re.escape(spelling), "<REPO>", normalized,
                                       flags=ci.re.IGNORECASE if ci.os.name == "nt" else 0)
        return normalized
    return value


@contextlib.contextmanager
def _r1_root_resolution_counter():
    """Count the real Path.resolve boundary only for this repository authority."""
    original = Path.resolve
    authority = ci.REPO_ROOT
    calls = SimpleNamespace(count=0)

    def resolve(path, *args, **kwargs):
        if path == authority:
            calls.count += 1
        return original(path, *args, **kwargs)

    with mock.patch.object(Path, "resolve", new=resolve):
        yield calls


class ReplayDiagnosticCanonicalizationPerformanceTest(StandalonePackagingFixtureTestBase):
    @staticmethod
    def large_record(rows=128, depth=8):
        record = fixtures.synthetic_record_from_spec(fixtures.synthetic_command_spec(
            "frontend-security:diagnostic-performance.js", "frontend-security", 687))
        root = str(ci.REPO_ROOT)
        values = [{"path": root + f"/developer/tests/fixture-{index}.js",
                   "streams": ["public output", root.replace("\\", "/") + "/src/input.js",
                               root.replace("/", "\\") + "\\src\\input.js"],
                   "identity": {"sha256": "a" * 64, "state": "retained", "index": index}}
                  for index in range(rows)]
        for index in range(depth):
            values = {"level": index, "records": [values], "source": root + "/source.json"}
        record["producerObservations"] = [{
            "commandId": record["commandId"], "commandOrdinal": 687, "occurrences": 1,
            "rawStructuredFields": {"stdout": values, "stderr": "", "exitCode": 0},
            "sourceOutputDigest": "sha256:" + "b" * 64,
        }]
        return record

    def test_nested_value_root_resolution_is_constant(self):
        for rows, depth in ((1, 1), (16, 4), (256, 12)):
            value = self.large_record(rows, depth)
            before_input = ci._json_bytes(value)
            with _r1_root_resolution_counter() as before:
                legacy = _r1_legacy_canonical_replay_value(value)
            with _r1_root_resolution_counter() as after:
                actual = ci._canonical_replay_value(value)
            self.assertEqual(ci._json_bytes(actual), ci._json_bytes(legacy))
            self.assertEqual(ci._json_bytes(value), before_input)
            print("W702_R1_ROOT_CALLS " + json.dumps({
                "rows": rows, "depth": depth, "before": before.count, "after": after.count,
                "canonical_sha256": hashlib.sha256(ci._json_bytes(actual)).hexdigest(),
            }, sort_keys=True))
            self.assertGreater(before.count, rows)
            self.assertEqual(after.count, 1)

    def test_large_hosted_diagnostic_is_exact_and_root_resolution_is_bounded(self):
        producer = self.large_record(1024, 12)
        replay = copy.deepcopy(producer)
        replay.update(stdoutSha256=hashlib.sha256(b"changed output").hexdigest(),
                      stdoutBytesObserved=len(b"changed output"))
        canonicalizers = (_r1_legacy_canonical_replay_value, ci._canonical_replay_value)
        outputs, counts = [], []
        for canonicalizer in canonicalizers:
            with mock.patch.object(ci, "_canonical_replay_value", new=canonicalizer):
                left = ci._canonical_transcript_record(producer)
                right = ci._canonical_transcript_record(replay)
                with _r1_root_resolution_counter() as calls:
                    diagnostics = ci.replay_transcript_difference_diagnostics(
                        [left], [right], producer_source_records=[producer],
                        replay_source_records=[replay])
                outputs.append(ci._json_bytes(diagnostics))
                counts.append(calls.count)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[1])[0]["ordinal"], 687)
        self.assertEqual(json.loads(outputs[1])[0]["changedFieldCategories"], ["stdout-identity"])
        print("W702_R1_LARGE_DIAGNOSTIC " + json.dumps({
            "rows": 1024, "before": counts[0], "after": counts[1],
            "before_sha256": hashlib.sha256(outputs[0]).hexdigest(),
            "after_sha256": hashlib.sha256(outputs[1]).hexdigest(),
        }, sort_keys=True))
        self.assertGreater(counts[0], 1024)
        self.assertEqual(counts[1], 1)

    def test_platform_path_spellings_are_byte_identical(self):
        for model, root, temporary in (
            ("nt", r"C:\work\reviewed-repo", r"C:\scratch\task-temp"),
            ("nt", r"\\server\share\reviewed-repo", r"C:\scratch\task-temp"),
            ("posix", "/srv/reviewed-repo", "/var/task-temp"),
            # Temp substitution must still precede repository substitution.
            ("posix", "/var/task-temp/reviewed-repo", "/var/task-temp"),
        ):
            spellings = (root, root.replace("\\", "/"), root.replace("/", "\\"),
                         root.swapcase(), temporary, temporary.replace("\\", "/"),
                         temporary.replace("/", "\\"))
            value = {"mapping": {7: {"paths": list(spellings)}}, "tuple": (
                "file://" + root + "/private/input.js", root + r"\mixed/separators.js",
                "https://example.invalid/path?q=public", "urn:example:public",
                r"C:\unrelated\private\opaque.txt", "/unrelated/private/opaque.txt",
                "unicode-\u96ea", "", None, True, 17, 0.125)}
            authority = SimpleNamespace(resolve=mock.Mock(return_value=root))
            temp_path = SimpleNamespace(resolve=mock.Mock(return_value=temporary))
            with self.subTest(model=model, root=root), \
                 mock.patch.object(ci, "REPO_ROOT", authority), \
                 mock.patch.object(ci, "Path", return_value=temp_path), \
                 mock.patch.object(ci, "os", SimpleNamespace(name=model)):
                expected = _r1_legacy_canonical_replay_value(value)
                authority.resolve.reset_mock()
                actual = ci._canonical_replay_value(value)
                self.assertEqual(ci._json_bytes(actual), ci._json_bytes(expected))
                self.assertEqual(authority.resolve.call_count, 1)
                self.assertEqual(actual["tuple"][2:6], list(value["tuple"][2:6]))

    def test_each_top_level_call_observes_replaced_repository_root(self):
        first, second = "/authority/first-repo", "/authority/second-repo"
        value = [first + "/a", {"path": second + "/b"}]
        for root in (first, second, first):
            authority = SimpleNamespace(resolve=mock.Mock(return_value=root))
            with mock.patch.object(ci, "REPO_ROOT", authority):
                expected = _r1_legacy_canonical_replay_value(value)
                authority.resolve.reset_mock()
                self.assertEqual(ci._canonical_replay_value(value), expected)
                self.assertEqual(authority.resolve.call_count, 1)

    def test_non_string_values_keep_lazy_resolution_and_errors(self):
        value = {1: [None, True, 7, 0.125, {}, ()]}
        authority = SimpleNamespace(resolve=mock.Mock(side_effect=OSError("unavailable")))
        with mock.patch.object(ci, "REPO_ROOT", authority):
            self.assertEqual(ci._canonical_replay_value(value),
                             _r1_legacy_canonical_replay_value(value))
            authority.resolve.assert_not_called()
            with self.assertRaisesRegex(OSError, "unavailable"):
                ci._canonical_replay_value([value, "requires root authority"])
            self.assertEqual(authority.resolve.call_count, 1)

    def test_diagnostic_order_membership_and_cap_are_exactly_unchanged(self):
        ordinals = [40, 12, 33, 7, 31, 9, 21, 2, 18, 1, 15, 5]
        producer, replay = [], []
        for ordinal in ordinals:
            record = self.large_record(1, 1)
            record.update(ordinal=ordinal, commandClass="direct-syntax",
                          commandId=f"node-check:{ci.REPO_ROOT}/private-{ordinal}.js")
            producer.append(record)
            changed = copy.deepcopy(record)
            changed.update(stderrSha256="d" * 64, stderrBytesObserved=77)
            replay.append(changed)
        for left_source, right_source in ((producer, replay), (producer, []), ([], replay)):
            outputs = []
            for canonicalizer in (_r1_legacy_canonical_replay_value, ci._canonical_replay_value):
                with mock.patch.object(ci, "_canonical_replay_value", new=canonicalizer):
                    left = [ci._canonical_transcript_record(record) for record in left_source]
                    right = [ci._canonical_transcript_record(record) for record in right_source]
                    outputs.append(ci.replay_transcript_difference_diagnostics(
                        left, right, producer_source_records=left_source,
                        replay_source_records=right_source))
            self.assertEqual(ci._json_bytes(outputs[0]), ci._json_bytes(outputs[1]))
            self.assertEqual(len(outputs[1]), 8)
            self.assertEqual([item["ordinal"] for item in outputs[1]], ordinals[:8])
            for item, source in zip(outputs[1], (right_source or left_source)):
                self.assertEqual(item["commandIdDigest"],
                                 "sha256:" + hashlib.sha256(source["commandId"].encode()).hexdigest())
            self.assertNotIn(str(ci.REPO_ROOT), json.dumps(outputs[1]))
        self.assertEqual(ci.replay_transcript_difference_diagnostics([], []), [])

    def test_hosted_e2_diagnostics_and_controls_are_exactly_unchanged(self):
        candidate = ci._canonical_replay_value
        for platform, mutation in (("windows", False), ("ubuntu", False), ("windows", True)):
            outputs = []
            stderr = packaging_reporter_mutations()["status-FAIL"] if mutation else None
            for canonicalizer in (_r1_legacy_canonical_replay_value, candidate):
                with self.fixture(platform, replay_stderr=stderr) as case:
                    if platform == "ubuntu":
                        case.runner.command_results[702].update(
                            containmentDisposition="natural-exit-reaped",
                            descendantsObserved=1, descendantsReaped=1)
                        case.runner.captures[-1].containment_disposition = "natural-exit-reaped"
                        case.runner.captures[-1].descendants_observed = 1
                        case.runner.captures[-1].descendants_reaped = 1
                    with mock.patch.object(ci, "_canonical_replay_value", new=canonicalizer), \
                         packaging_counters() as calls:
                        errors, transcript = backend.verify(case)
                    expected = list(case.frontend)
                    if platform == "ubuntu" or mutation:
                        expected.append(702)
                    self.assertEqual(backend.unequal_ordinals(errors), expected, errors)
                    self.assertIsNotNone(transcript, errors)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT")
                    self.assertEqual((calls.parser.call_count, calls.identity.call_count),
                                     (0, 0) if platform == "ubuntu" else (2, 0) if mutation else (2, 2))
                    prefix = "verification replay first command differences: "
                    diagnostics, = [json.loads(error[len(prefix):])
                                    for error in errors if error.startswith(prefix)]
                    if platform == "ubuntu":
                        self.assertEqual(diagnostics[-1]["changedFieldCategories"],
                                         ["process-containment", "stderr-identity"])
                    outputs.append((errors, ci._json_bytes(diagnostics)))
            self.assertEqual(outputs[0], outputs[1])
            print("W702_R1_HOSTED_EQUIVALENCE " + json.dumps({
                "platform": platform, "semantic_mutation": mutation, "unequal": expected,
                "before_sha256": hashlib.sha256(outputs[0][1]).hexdigest(),
                "after_sha256": hashlib.sha256(outputs[1][1]).hexdigest(),
                "categories": [item["changedFieldCategories"] for item in diagnostics],
            }, sort_keys=True))


if __name__ == "__main__":
    unittest.main(verbosity=2, testRunner=fixtures.InventoryTextTestRunner)
