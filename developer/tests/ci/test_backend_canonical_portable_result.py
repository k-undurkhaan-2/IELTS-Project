"""Bounded Issue 13 fixtures: no hosted job or repository profile execution."""
from __future__ import annotations

import ast
import copy
import contextlib
from dataclasses import replace
import hashlib
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import run_ci_foundation as ci
import test_ci_foundation as fixtures
import backend_canonical_portable_result as portable


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


NAMES = [f"backend case {i:03d} preserves value {1000 + i}" for i in range(128)]
PACKAGE = json_bytes({"name": "fixture-backend", "version": "1.0.0",
                      "scripts": {"test": "node --test"}})


def npm_stdout(duration="1.25", total="99.5", *, names=None, newline="\n", initial=True):
    names = NAMES if names is None else names
    lines = ([""] if initial else []) + ["> fixture-backend@1.0.0 test", "> node --test", ""]
    lines += [f"✔ {name} ({duration}ms)" for name in names]
    lines += [f"ℹ {key} {value}" for key, value in zip(portable.COUNTS,
               (len(names), 0, len(names), 0, 0, 0, 0))]
    return (newline.join(lines) + newline + f"ℹ duration_ms {total}" + newline).encode()


def fixture(platform="ubuntu", *, stdout=None, stderr=b"", physical="1", ordinal=0):
    """Observed npm grammar/inventory size with public, synthetic preimages.

    Both platform labels exercise production record/bundle/closure validators.
    No real executable, package install, or private evidence is involved.
    """
    stable = {"deviceOrVolume": physical, "inodeOrFileIndex": physical,
              "creationOrChangeTimeNs": physical, "writeTimeNs": physical, "reparsePoint": False}
    targets = []
    for relative, data in (("backend/package.json", PACKAGE),
                           ("backend/test/backend.test.js", "\n".join(NAMES).encode())):
        targets.append({"path": relative, "canonicalSourcePath": str(ci.REPO_ROOT / relative),
                        "size": len(data), "sha256": digest(data), "fileIdentity": stable.copy(),
                        "modeType": "regular-file", "reparsePoint": False})
    node_path = str(Path(sys.executable).parent / "fixture-node.exe")
    npm_path = str(Path(sys.executable).parent / "fixture-npm-cli.js")
    spec = fixtures.synthetic_command_spec("backend-canonical", "backend-canonical", ordinal,
        command_role="observation-producing", allowed_exits=[0, 1], targets=targets,
        execution_input_mode="PROTECTED-TARGET-BUNDLE")
    spec.update(profile="all", platform=platform, toolRole="npm-backend-test",
                resultSemantics="baseline-classified-test-result",
                argv=[npm_path, "--prefix", "backend", "test"],
                logicalArgv=[npm_path, "--prefix", "backend", "test"],
                executionArgv=[node_path, npm_path, "--prefix", "backend", "test"],
                resolvedExecutablePath=node_path, resolvedExecutableSize=64,
                resolvedExecutableSha256=digest(b"fixture-node"),
                resolvedExecutableFileIdentity=stable.copy())
    stdout = npm_stdout() if stdout is None else stdout
    capture = ci.CommandCapture(command_id=spec["commandId"], command_class=spec["commandClass"],
        argv=spec["executionArgv"], executed=True, exit_code=0, duration_seconds=0.125,
        stdout=stdout.decode("utf-8", errors="replace"), stderr=stderr.decode("utf-8", errors="replace"),
        stdout_raw=stdout, stderr_raw=stderr, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        include_preview=False, containment="windows-job-object" if platform == "windows"
        else "linux-subreaper-pidfd-proc-supervisor", process_tree_status="contained-clean",
        containment_disposition="natural-exit-reaped", descendants_observed=1, descendants_reaped=1,
        execution_input_mode="PROTECTED-TARGET-BUNDLE")
    record = fixtures.synthetic_record_from_spec(spec)
    record.update({k: v for k, v in capture.evidence().items() if k not in (
        "executionInputs", "executionInputBundleDigest", "protectedTargetBundle", "targetExecutionLease")})
    record.pop("parsedFailureSummary", None)
    guard = {"guardSchemaVersion": ci.RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
             "watcherBackend": "_WindowsDirectoryMutationWatcher" if platform == "windows"
             else "_InotifyMutationWatcher", "active": False, "activeDuringReplay": True,
             "mutationState": "clean", "queueOverflow": False, "mutationEventCount": 0}
    def tool(role, path, sha, **extra):
        tool_stable = stable.copy() if platform == "ubuntu" else {
            "volumeSerial": physical, "fileIndex": physical, "writeTime": physical,
            "size": 64, "links": 1, "reparsePoint": False}
        return {"role": role, "canonicalPath": path, "size": 64, "sha256": sha,
                "stableIdentity": tool_stable, "leaseHeld": True, **extra}
    roots = []
    for root in ("developer/node_modules", "backend/node_modules"):
        members = [{"relativePath": "fixture/index.js", "fileType": "regular-file", "mode": "100644",
                    "size": 1, "sha256": digest(root.encode()), "symlinkTarget": None}]
        roots.append({"logicalRoot": root, "memberCount": len(members), "members": members,
                      "memberManifestDigest": digest(ci._canonical_frame(members))})
    semantic = {"lockfiles": [{"relativePath": path, "mode": "100644", "size": 1,
                 "sha256": digest(path.encode())} for path in
                 ("developer/package-lock.json", "backend/package-lock.json")],
                "dependencyRoots": roots, "vitest": None, "nodePath": []}
    closure = {"closureSchemaVersion": ci.RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
               "measurementStatus": "measured-complete", "profile": "all",
               "runnerOS": "Windows" if platform == "windows" else "Linux",
               "pythonExecutable": tool("python-verifier", sys.executable, digest(b"python")),
               "nodeExecutable": tool("node-runtime", node_path, digest(b"fixture-node"), version="v24.20.0"),
               "npmEntrypoint": tool("npm-entrypoint", npm_path, digest(b"fixture-npm"),
                                     version="11.0.0", available=True), "gitExecutable": None,
               **semantic, "dependencyClosureDigest": digest(ci._canonical_frame(semantic)),
               "dependencyMemberCount": 2}
    closure["closureDigest"] = digest(ci._canonical_frame(closure))
    runtime = {"node": "v24.20.0", "npm": "11.0.0", "runtimeClosureDigest": closure["closureDigest"],
               "dependencyClosureDigest": closure["dependencyClosureDigest"], "dependencyMemberCount": "2",
               "platform": platform, "os": "test", "python": "3.12.0", "pythonImplementation": "CPython"}
    record.update(dependencyBacked=True, runtimeClosureDigest=closure["closureDigest"],
        dependencyClosureDigest=closure["dependencyClosureDigest"], nodePath=[],
        resolvedTestRunnerEntrypoint=node_path, resolvedTestRunnerSha256=digest(b"fixture-node"),
        closureWatcherActive=True, closureMutationState="clean", runtimeClosureGuard=guard,
        completedCommandClass="backend-canonical")
    binder = object.__new__(ci.FoundationRunner)
    binder.command_results, binder.observations = [record], []
    ci.FoundationRunner.add_process_observation(binder, record, capture,
        source_result_id="command:npm --prefix backend test", source_path="backend/package.json")
    return portable._ReplayEvidence(record, spec, stdout, stderr, PACKAGE, runtime, closure, guard)


def unrelated_specs(family, ordinal):
    ids = (["frontend-security:adminFrontendGuard.test.js", "frontend-security:remotePracticeDataSource.test.js"]
           if family == "frontend-security" else [family])
    return [fixtures.synthetic_command_spec(command_id, family, ordinal + i) for i, command_id in enumerate(ids)]


def unrelated_record(spec):
    record = fixtures.synthetic_record_from_spec(spec)
    if spec["commandClass"] == "frontend-security":
        path = "developer/tests/js/" + spec["commandId"].split(":")[1]
        record["producerObservations"] = [ci.make_raw_observation(spec["commandId"], spec["ordinal"], 0,
            "process-output-v1", "file:" + path, path,
            {"executed": True, "exitCode": 0, "stdout": "", "stderr": "", "error": None},
            ci.command_output_digest(record))]
    return record


def replay_fixture(producer, replay, *, compact=False, extra=False, prefix_count=0):
    prefix = [fixtures.synthetic_command_spec(f"fixture-{i}", "baseline-policy", i)
              for i in range(prefix_count)]
    specs = prefix + [copy.deepcopy(replay.expected_authority)]
    records = [fixtures.synthetic_record_from_spec(spec) for spec in prefix] + [copy.deepcopy(replay.command_record)]
    producer_records = copy.deepcopy(records[:-1]) + [copy.deepcopy(producer.command_record)]
    if extra:
        for family in extra if isinstance(extra, tuple) else ("fixture",):
            for spec in unrelated_specs(family, len(specs)):
                specs.append(spec)
                records.append(unrelated_record(spec))
                records[-1]["completedCommandClass"] = spec["commandClass"]
                producer_records.append(copy.deepcopy(records[-1]))
    runner = SimpleNamespace(profile="all", platform=replay.command_record["platform"], release_gate_required=False,
        command_plan=specs, command_results=records, observations=[], completed_classes=set(),
        hard_gate_results=[], violations=[], runtime_closure_digest=replay.runtime_closure["closureDigest"],
        runtime_closure_document=copy.deepcopy(replay.runtime_closure), runtime=copy.deepcopy(replay.runtime),
        runtime_closure_guard_evidence=copy.deepcopy(replay.runtime_guard),
        dependency_closure_digest=replay.runtime_closure["dependencyClosureDigest"], dependency_member_count=2)
    runner.execution_binding = fixtures.synthetic_execution_binding("all", ci.command_plan_digest(specs),
                                                                    platform_name=runner.platform)
    runner.captures = [ci.CommandCapture(
        command_id="backend-canonical", command_class="backend-canonical",
        argv=replay.expected_authority["executionArgv"], executed=True, exit_code=0,
        duration_seconds=0.125, stdout=replay.stdout.decode("utf-8", errors="replace"),
        stderr=replay.stderr.decode("utf-8", errors="replace"), stdout_raw=replay.stdout,
        stderr_raw=replay.stderr, stdout_bytes=len(replay.stdout), stderr_bytes=len(replay.stderr),
        include_preview=False, containment=replay.command_record["containment"],
        process_tree_status="contained-clean", containment_disposition="natural-exit-reaped",
        descendants_observed=1, descendants_reaped=1, execution_input_mode="PROTECTED-TARGET-BUNDLE")]
    ci.finalize_evidence_transcript(runner)
    transcript = ci.verification_replay_transcript(runner)
    commands = copy.deepcopy(transcript)
    commands.update(records=[ci._compact_command_record_for_evidence(r) if compact else r for r in producer_records],
        commandAuthority=ci._portable_command_plan_value(specs), observations=[], runtime=copy.deepcopy(producer.runtime),
        runtimeDependencyClosure=copy.deepcopy(producer.runtime_closure),
        runtimeDependencyGuard=copy.deepcopy(producer.runtime_guard),
        completedCommandClasses=transcript["actualCompletedCommandClasses"],
        producerObservationUniverseDigest=ci.producer_observation_universe_digest(producer_records),
        producerTranscriptDigest=ci.producer_transcript_digest(ci.command_plan_digest(specs),
            producer_records, transcript["actualCompletedCommandClasses"]))
    summary = {key: copy.deepcopy(transcript[key]) for key in ("profile", "executionBinding",
               "executionBindingDigest", "authorizationContextBinding", "authorizationContextBindingDigest")}
    comparison = fixtures.empty_comparison()
    summary.update(knownDebtsObserved=[], resolvedCandidates=[], expectedOmissions=[], releaseOnlySkips=[])
    return runner, {"summary.json": summary, "command-results.json": commands}, comparison


@contextlib.contextmanager
def outer_fixture(producer=None, replay=None, *, compact=True, extra=False, prefix_count=0, hosted=False):
    producer = fixture() if producer is None else producer
    replay = fixture(stdout=npm_stdout("90", "912"), physical="9") if replay is None else replay
    runner, _documents, _comparison = replay_fixture(producer, replay, extra=extra, prefix_count=prefix_count)
    if hosted:
        runner.execution_binding.update(bindingMode="github-actions", producerJobId=(
            "windows-compatibility-producer" if runner.platform == "windows" else "ubuntu-canonical-producer"),
            runId="123456", runAttempt="1", eventName="workflow_dispatch", repository="fixture/backend-cli")
        runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
            k: v for k, v in runner.execution_binding.items() if k != "producerInvocationId"})
    context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                      fresh_runtime_closure_digest=runner.runtime_closure_digest)
    runner.verifier_execution_binding = context.verifier_binding()
    runner.authorization_context_binding = context.authorization_context_binding()
    runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(
        runner.authorization_context_binding)
    runner.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
    producer_runner = copy.deepcopy(runner)
    producer_runner.command_results[prefix_count] = copy.deepcopy(producer.command_record)
    producer_runner.command_plan[prefix_count] = copy.deepcopy(producer.expected_authority)
    producer_runner.runtime = copy.deepcopy(producer.runtime)
    producer_runner.runtime_closure_document = copy.deepcopy(producer.runtime_closure)
    producer_runner.runtime_closure_guard_evidence = copy.deepcopy(producer.runtime_guard)
    for target in (runner, producer_runner):
        target.observations = [{"rawObservation": raw} for record in target.command_results
                               for raw in record["producerObservations"]]
        ci.finalize_evidence_transcript(target)
    with tempfile.TemporaryDirectory(prefix="backend-portable-") as temp:
        root = Path(temp)
        (root / "backend").mkdir()
        (root / "backend/package.json").write_bytes(producer.package_json)
        package_target = ci._target_authority(root, "backend/package.json")
        # The independent verifier plan uses the actual candidate's local identity.
        # Producer physical identities continue to differ and remain compact on wire.
        for target in runner.command_plan[prefix_count]["targets"]:
            if target["path"] == "backend/package.json":
                target.update(canonicalSourcePath=package_target["canonicalSourcePath"],
                              fileIdentity=package_target["fileIdentity"])
        rebuilt = fixtures.synthetic_record_from_spec(runner.command_plan[prefix_count])
        for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
            runner.command_results[prefix_count][key] = copy.deepcopy(rebuilt[key])
        ci.finalize_evidence_transcript(runner)
        output = root / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=root)
        ci.write_evidence(producer_runner, fixtures.empty_comparison(), output_dir=output,
                          evidence_authority_root=root)
        documents, _snapshots, errors = ci._read_evidence_documents_for_replay(output)
        if errors:
            raise AssertionError(errors)
        if not compact:
            documents["command-results.json"]["records"] = producer_runner.command_results
            write_documents(output, documents)
        summary = documents["summary.json"]
        comparison = {key: summary[field] for key, field in (
            ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
            ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()
        runner.cleanup_task_resources = mock.Mock()
        with mock.patch.object(ci, "rebuild_external_verification_context", return_value=context), \
             mock.patch.object(ci, "REPO_ROOT", root):
            yield SimpleNamespace(producer=producer, replay=replay, runner=runner, context=context,
                root=root, output=output, documents=documents, comparison=comparison,
                pair={"producer": producer, "replay": replay})


def write_documents(output, documents, *, ascii_json=False):
    summary = documents["summary.json"]
    payloads = {name: (json.dumps(value, ensure_ascii=True).encode() if ascii_json else ci._json_bytes(value))
                for name, value in documents.items() if name != "summary.json"}
    payloads["summary.md"] = ci.render_summary_markdown(summary).encode()
    for entry in summary["evidenceManifest"]:
        data = payloads[entry["relativeFilename"]]
        entry.update(byteLength=len(data), sha256=digest(data))
    payloads["summary.json"] = ci._json_bytes(summary)
    for name, data in payloads.items():
        (output / name).write_bytes(data)


def verify(case):
    return ci.verify_evidence_with_replay(case.output, expected_context=case.context,
        verification_runner=case.runner, evidence_authority_root=case.root,
        repo_root=case.root)


def reseal_producer(case):
    """Recompute ordinary aggregates so negatives test authority, not stale hashes."""
    commands = case.documents["command-results.json"]
    records = commands["records"]
    for record in records:
        for raw in record["producerObservations"]:
            raw["sourceOutputDigest"] = ci.command_output_digest(record)
            raw["producerRecordDigest"] = ci._producer_record_digest({
                key: value for key, value in raw.items() if key != "producerRecordDigest"})
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest(record["producerObservations"])
    commands["producerObservationCount"] = sum(len(r["producerObservations"]) for r in records)
    commands["producerObservationUniverseDigest"] = ci.producer_observation_universe_digest(records)
    commands["producerTranscriptDigest"] = ci.producer_transcript_digest(
        commands["commandPlanDigest"], records, commands["actualCompletedCommandClasses"])
    write_documents(case.output, case.documents)


def invoke_main(case):
    """Keep the real CLI, five-file verifier, binding, comparison and envelope path."""
    context = case.context
    arguments = ["--verify-evidence", "--expected-profile", context.expected_profile,
                 "--untrusted-evidence-root", str(case.output), "--require-fresh-runtime-closure"]
    if context.binding_mode == "github-actions":
        arguments.extend(["--expected-producer-job", context.producer_job_id,
                          "--expected-verifier-job", context.verifier_job_id,
                          "--expected-runner-os", context.runner_os])
    else:
        arguments.extend(["--expected-invocation-id", context.producer_invocation_id])
    if context.runner_os == "Linux":
        arguments.append("--require-linux-containment-self-test")
    original = ci.verify_evidence_with_replay
    results = []
    def verified(*args, **kwargs):
        results.append(original(*args, **kwargs))
        return results[-1]
    output = io.StringIO()
    with mock.patch.object(ci, "prepare_verification_authority", return_value=(context, case.runner)), \
         mock.patch.object(ci, "capture_live_external_authority", return_value=fixtures._explicit_live_local_external_authority()), \
         mock.patch.object(ci, "verify_evidence_with_replay", side_effect=verified) as verifier, \
         contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        exit_code = ci.main(arguments)
    if len(results) != 1:
        raise AssertionError(output.getvalue())
    return exit_code, results[0], output.getvalue(), verifier.call_args


class BackendCanonicalPortableResultTest(unittest.TestCase):
    def test_policy_frontend_and_packaging_main_never_reach_backend_parser(self):
        for profile, family in (("policy", "baseline-policy"), ("all", "frontend-security"),
                                ("all", "standalone-packaging")):
            with self.subTest(profile=profile, family=family), tempfile.TemporaryDirectory(prefix="no-backend-") as temp:
                root = Path(temp)
                baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
                if profile == "policy":
                    with mock.patch.object(ci, "expected_command_authority", return_value=[]):
                        runner = fixtures.fake_runner(baseline)
                else:
                    source = fixture()
                    runner, _, _ = replay_fixture(source, source)
                    runner.baseline = baseline
                runner.command_plan = unrelated_specs(family, 0)
                for spec in runner.command_plan:
                    spec.update(profile=profile, platform=runner.platform)
                runner.command_results = [unrelated_record(spec) for spec in runner.command_plan]
                runner.observations = [{"rawObservation": raw} for record in runner.command_results
                                       for raw in record["producerObservations"]]
                runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
                runner.runtime_closure_digest = runner.runtime_closure_document["closureDigest"]
                runner.dependency_closure_digest = runner.runtime_closure_document["dependencyClosureDigest"]
                runner.dependency_member_count = runner.runtime_closure_document["dependencyMemberCount"]
                runner.execution_binding = fixtures.synthetic_execution_binding(profile, runner.command_plan_digest,
                    platform_name=runner.platform)
                context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                    fresh_runtime_closure_digest=runner.runtime_closure_digest)
                runner.verifier_execution_binding = context.verifier_binding()
                runner.authorization_context_binding = context.authorization_context_binding()
                runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(runner.authorization_context_binding)
                output = root / ".ci-results"
                ci.create_fresh_evidence_root(output, repo_root=root)
                summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output, evidence_authority_root=root)
                comparison = {key: summary[field] for key, field in (
                    ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
                    ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
                runner.run = mock.Mock(return_value=comparison)
                runner.close_execution_leases = mock.Mock()
                runner.cleanup_task_resources = mock.Mock()
                case = SimpleNamespace(context=context, runner=runner, output=output)
                with mock.patch.object(ci, "REPO_ROOT", root), \
                     mock.patch.object(ci, "rebuild_external_verification_context", return_value=context), \
                     mock.patch.object(portable, "_parse_stdout") as parser, \
                     mock.patch.object(portable, "_identity") as identity, \
                     mock.patch.object(portable, "_bind_producer") as binder:
                    exit_code, (errors, transcript), text, _ = invoke_main(case)
                self.assertEqual((exit_code, errors), (ci.EXIT_SUCCESS, []), text)
                self.assertEqual(transcript["finalAcceptance"], "PASS")
                self.assertNotIn("backendCanonicalPortableResult", transcript)
                runner.run.assert_called_once()
                parser.assert_not_called()
                identity.assert_not_called()
                binder.assert_not_called()
                print("BACKEND_NO_PATH " + json.dumps({"profile": profile, "family": family,
                    "parser": 0, "identity": 0, "acceptance": "PASS"}))

    def test_hosted_shaped_main_duration_drift_and_exact_unrelated_commands(self):
        for mismatch in (None, "frontend-security", "standalone-packaging"):
            with self.subTest(mismatch=mismatch), outer_fixture(
                fixture(ordinal=701), fixture(ordinal=701, stdout=npm_stdout("90", "912"), physical="9"),
                prefix_count=701, extra=("frontend-security", "standalone-packaging"), hosted=True) as case:
                record = case.documents["command-results.json"]["records"][701]
                self.assertEqual(record["executionInputs"], [])
                self.assertTrue(all(record["protectedTargetBundle"][k] == []
                    for k in ci._PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS))
                self.assertEqual(record["producerObservations"][0]["rawStructuredFields"]["stdout"].encode(),
                                 case.producer.stdout)
                before, raw_errors = ci.compare_verification_replay_claims(case.documents, case.runner, case.comparison)
                self.assertTrue(any('"ordinal":701' in e for e in raw_errors), raw_errors)
                if mismatch:
                    def drift():
                        other = next(r for r in case.runner.command_results if r["commandClass"] == mismatch)
                        other["stdoutSha256"] = "0" * 64
                        return case.comparison
                    case.runner.run.side_effect = drift
                with mock.patch.object(portable, "_parse_stdout", wraps=portable._parse_stdout) as parser, \
                     mock.patch.object(portable, "_identity", wraps=portable._identity) as identity:
                    exit_code, (errors, transcript), output, call = invoke_main(case)
                self.assertNotIn("backend_result_evidence", call.kwargs)
                case.runner.run.assert_called_once()
                case.runner.close_execution_leases.assert_called_once()
                case.runner.cleanup_task_resources.assert_called_once()
                self.assertFalse(any('"ordinal":701' in e for e in errors), errors)
                if mismatch:
                    self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
                    self.assertTrue(any(mismatch in e and "stdout-identity" in e for e in errors), errors)
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT")
                    self.assertEqual((parser.call_count, identity.call_count), (0, 0))
                else:
                    self.assertEqual((exit_code, errors), (ci.EXIT_SUCCESS, []), output)
                    self.assertEqual(transcript["finalAcceptance"], "PASS")
                    self.assertEqual(transcript["backendCanonicalPortableResult"]["result"]["command"]["ordinal"], 701)
                    self.assertEqual((parser.call_count, identity.call_count), (2, 2))
                print("BACKEND_CLI " + json.dumps({"mismatch": mismatch, "exit": exit_code,
                    "parser": parser.call_count, "identity": identity.call_count,
                    "ordinal701Unequal": False, "acceptance": transcript["finalAcceptance"]}))

    def assert_rejected(self, case, label, *, parser_calls=0, identity_calls=0):
        with mock.patch.object(portable, "_parse_stdout", wraps=portable._parse_stdout) as parser, \
             mock.patch.object(portable, "_identity", wraps=portable._identity) as identity:
            errors, transcript = verify(case)
        self.assertTrue(errors, label)
        self.assertNotIn("backendCanonicalPortableResult", transcript or {}, label)
        self.assertNotEqual((transcript or {}).get("finalAcceptance"), "PASS", label)
        self.assertEqual(parser.call_count, parser_calls, label)
        self.assertEqual(identity.call_count, identity_calls, label)
        print("BACKEND_NEGATIVE " + json.dumps({"case": label, "parser": parser.call_count,
            "identity": identity.call_count, "attached": False, "pass": False}, sort_keys=True))

    def test_valid_outer_path(self):
        for platform in ("ubuntu", "windows"):
            for compact in (False, True):
                with self.subTest(platform=platform, compact=compact), outer_fixture(
                    fixture(platform), fixture(platform, stdout=npm_stdout("90", "912"), physical="9"),
                    compact=compact) as case:
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    errors, transcript = verify(case)
                    self.assertEqual(errors, [])
                    self.assertEqual(transcript["finalAcceptance"], "PASS")
                    self.assertIn("backendCanonicalPortableResult", transcript)
                    case.runner.run.assert_called_once()
                    case.runner.close_execution_leases.assert_called_once()

    def test_call_order_and_detached_authorization_bound_attachment(self):
        with outer_fixture() as case:
            events = []
            originals = {name: getattr(portable, name) for name in (
                "_bind_producer", "_bind_replay", "_parse_stdout", "_identity")}
            def traced(name):
                def call(*args, **kwargs):
                    events.append(name)
                    return originals[name](*args, **kwargs)
                return call
            raw_verify = ci.verify_evidence_file_set
            semantics = ci._validate_evidence_semantics
            compare = ci._compare_verification_replay_claims
            finish = ci._finish_verification_replay
            read_snapshot = ci._read_evidence_file_snapshot
            def raw(*args, **kwargs):
                errors = raw_verify(*args, **kwargs)
                self.assertEqual(errors, [])
                events.append("raw-valid")
                return errors
            def semantic(*args, **kwargs):
                errors = semantics(*args, **kwargs)
                self.assertEqual(errors, [])
                events.append("semantics-valid")
                return errors
            def compared(*args, **kwargs):
                events.append("comparisons")
                return compare(*args, **kwargs)
            def finished(transcript, *args, **kwargs):
                events.append("attached-envelope" if "backendCanonicalPortableResult" in transcript
                              else "eligibility-envelope")
                return finish(transcript, *args, **kwargs)
            def stable(path, *args, **kwargs):
                if "fresh-run" in events:
                    events.append("stability:" + path.name)
                return read_snapshot(path, *args, **kwargs)
            case.runner.run.side_effect = lambda: (events.append("fresh-run") or case.comparison)
            case.runner.close_execution_leases.side_effect = lambda: events.append("closed")
            before_files = {p.name: p.read_bytes() for p in case.output.iterdir()}
            before_record = json_bytes(case.runner.command_results)
            with contextlib.ExitStack() as stack:
                for name in originals:
                    stack.enter_context(mock.patch.object(portable, name, side_effect=traced(name)))
                stack.enter_context(mock.patch.object(ci, "verify_evidence_file_set", side_effect=raw))
                stack.enter_context(mock.patch.object(ci, "_validate_evidence_semantics", side_effect=semantic))
                stack.enter_context(mock.patch.object(ci, "_compare_verification_replay_claims", side_effect=compared))
                stack.enter_context(mock.patch.object(ci, "_finish_verification_replay", side_effect=finished))
                stack.enter_context(mock.patch.object(ci, "_read_evidence_file_snapshot", side_effect=stable))
                stack.enter_context(mock.patch.object(ci, "rebuild_external_verification_context",
                    side_effect=lambda *a, **k: (events.append("external-context") or case.context)))
                errors, transcript = verify(case)
            self.assertEqual(errors, [])
            self.assertLess(events.index("raw-valid"), events.index("_bind_producer"))
            self.assertEqual(events[:events.index("_bind_producer")].count("semantics-valid"), 2)
            self.assertLess(events.index("_bind_producer"), events.index("fresh-run"))
            self.assertLess(events.index("closed"), events.index("_bind_replay"))
            self.assertEqual(events.count("_bind_replay"), 2)
            first_parse = events.index("_parse_stdout")
            self.assertEqual(events[:first_parse].count("_bind_replay"), 2)
            self.assertLess(events.index("comparisons"), events.index("external-context"))
            self.assertLess(events.index("external-context"), first_parse)
            self.assertEqual(sum(e.startswith("stability:") for e in events[:first_parse]), 5)
            self.assertEqual(events[first_parse:], ["_parse_stdout", "_parse_stdout", "_identity", "_identity",
                                                   "comparisons", "attached-envelope"])
            self.assertEqual({p.name: p.read_bytes() for p in case.output.iterdir()}, before_files)
            self.assertEqual(json_bytes(case.runner.command_results), before_record)
            raw_transcript = {k: v for k, v in transcript.items() if k not in (
                "currentFullContextDigestSetDigest", "verifierReplayContextBinding",
                "verifierReplayContextDigest", "replayAuthorizationEnvelopeDigest", "finalAcceptance")}
            self.assertEqual(transcript["verifierReplayContextBinding"]["replayTranscriptDigest"],
                             ci.canonical_failure_digest(raw_transcript))
            transcript["backendCanonicalPortableResult"]["result"]["orderedTests"][0]["name"] = "detached"
            self.assertEqual(json_bytes(case.runner.command_results), before_record)
            print("BACKEND_ORDER " + json.dumps(events))

    def test_invalid_raw_documents_and_file_structure_never_reach_binding(self):
        changes = {
            "invalid schemaVersion": lambda d: d["summary.json"].update(schemaVersion=999),
            "invalid documentKind": lambda d: d["command-results.json"].update(documentKind="claimed"),
            "invalid authorization claim": lambda d: d["summary.json"]["authorizationContextBinding"].update(
                expectedVerifierJobId="another-verifier"),
            "invalid producer raw hash": lambda d: d["command-results.json"]["records"][0].update(
                stdoutSha256="0" * 64),
            "invalid producer raw record": lambda d: d["command-results.json"]["records"][0].update(
                unknownAuthority=True),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                change(case.documents)
                write_documents(case.output, case.documents)
                with mock.patch.object(portable, "_bind_producer", side_effect=AssertionError("must not bind")):
                    self.assert_rejected(case, label)
                case.runner.run.assert_not_called()
        for label in ("missing evidence file", "extra evidence file", "invalid JSON"):
            with self.subTest(case=label), outer_fixture() as case:
                if label == "missing evidence file":
                    (case.output / "summary.md").unlink()
                elif label == "extra evidence file":
                    (case.output / "extra.json").write_bytes(b"{}\n")
                else:
                    (case.output / "summary.json").write_bytes(b"{broken}\n")
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_second_snapshot_is_validated_before_binding(self):
        for field, value in (("schemaVersion", 999), ("documentKind", "forged"),
                             ("authorizationContextBindingDigest", "0" * 64)):
            with self.subTest(field=field), outer_fixture() as case:
                real_verify = ci.verify_evidence_file_set
                def replace_after_validation(*args, **kwargs):
                    errors = real_verify(*args, **kwargs)
                    self.assertEqual(errors, [])
                    case.documents["summary.json"][field] = value
                    write_documents(case.output, case.documents)
                    return errors
                with mock.patch.object(ci, "verify_evidence_file_set", side_effect=replace_after_validation):
                    self.assert_rejected(case, "second snapshot " + field)
                case.runner.run.assert_not_called()

    def test_compact_producer_authority_matrix(self):
        changes = {
            "raw reconstructed input digest": lambda r: r.update(executionInputBundleDigest="sha256:" + "0" * 64),
            "target path": lambda r: r["targets"][0].update(path="backend/other.json"),
            "target order": lambda r: r["targets"].reverse(),
            "target content": lambda r: r["targets"][0].update(sha256="0" * 64),
            "target size": lambda r: r["targets"][0].update(size=123),
            "target mode": lambda r: r["targets"][0].update(modeType="other"),
            "target reparse": lambda r: r["targets"][0].update(reparsePoint=True),
            "command association": lambda r: r.update(ordinal=1),
            "compact pre reference": lambda r: r["protectedTargetBundle"]["preExecutionIdentities"].__setitem__(0, "0" * 64),
            "compact post reference": lambda r: r["protectedTargetBundle"]["postExecutionIdentities"].__setitem__(0, "0" * 64),
            "NODE_PATH authority": lambda r: r.update(nodePath=["untrusted"]),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                record = case.documents["command-results.json"]["records"][0]
                self.assertEqual(record["executionInputs"], [])
                change(record)
                reseal_producer(case)
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_self_consistent_compact_rewrites_still_need_independent_authority(self):
        for kind in ("path", "order", "content", "mode", "reparse", "association"):
            with self.subTest(kind=kind), outer_fixture() as case:
                record = case.documents["command-results.json"]["records"][0]
                if kind == "order":
                    record["targets"].reverse()
                elif kind == "association":
                    record["ordinal"] = 1
                else:
                    field, value = {"path": ("path", "backend/other.json"),
                        "content": ("sha256", "0" * 64), "mode": ("modeType", "other"),
                        "reparse": ("reparsePoint", True)}[kind]
                    record["targets"][0][field] = value
                record["executionInputBundleDigest"] = ci.execution_input_bundle_digest(
                    ci._reconstructed_protected_execution_inputs(record))
                bundle = record["protectedTargetBundle"]
                bundle["executionInputBundleDigest"] = record["executionInputBundleDigest"]
                for phase, key in (("pre", "preExecutionIdentities"), ("post", "postExecutionIdentities")):
                    bundle[key] = ci._protected_bundle_compact_identity_digests(record, phase=phase)
                reseal_producer(case)
                errors = []
                ci._validate_command_record(record, 0, errors, expected_record=case.runner.command_plan[0])
                self.assertTrue(any("independently reconstructed" in e for e in errors), errors)
                self.assert_rejected(case, "self-consistent compact " + kind)
                case.runner.run.assert_not_called()

    def test_producer_runtime_closure_guard_matrix(self):
        changes = {
            "runtime mutation": lambda c: c["runtime"].update(node="v24.99.0"),
            "dependency mutation": lambda c: c["runtimeDependencyClosure"]["dependencyRoots"][0]["members"][0].update(sha256="0" * 64),
            "tool mutation": lambda c: c["runtimeDependencyClosure"]["npmEntrypoint"].update(sha256="0" * 64),
            "guard mutation": lambda c: c["runtimeDependencyGuard"].update(mutationState="dirty"),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                change(case.documents["command-results.json"])
                write_documents(case.output, case.documents)
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_exact_observation_stream_reconstruction_matrix(self):
        for stream in ("stdout", "stderr"):
            for kind in ("bytes", "hash", "length", "missing", "type", "normalized"):
                with self.subTest(stream=stream, kind=kind), outer_fixture() as case:
                    record = case.documents["command-results.json"]["records"][0]
                    fields = record["producerObservations"][0]["rawStructuredFields"]
                    if kind == "bytes":
                        fields[stream] += "x"
                    elif kind == "normalized":
                        if stream == "stderr":
                            continue
                        fields[stream] = ci.raw_observation_json_value(fields[stream])
                    elif kind == "missing":
                        fields.pop(stream)
                    elif kind == "type":
                        fields[stream] = [fields[stream]]
                    elif kind == "hash":
                        record[stream + "Sha256"] = "0" * 64
                    else:
                        record[stream + "BytesObserved"] += 1
                    reseal_producer(case)
                    # All ordinary hashes are coherent; only exact stream recovery rejects.
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    self.assert_rejected(case, f"producer {stream} {kind}")
                    case.runner.run.assert_not_called()

    def test_fresh_runner_binding_and_execution_failures(self):
        changes = {
            "missing replay capture": lambda r: r.captures.clear(),
            "duplicate replay capture": lambda r: r.captures.append(copy.deepcopy(r.captures[0])),
            "fresh capture stdout mutation": lambda r: setattr(r.captures[0], "stdout_raw", b"wrong"),
            "fresh capture stderr mutation": lambda r: setattr(r.captures[0], "stderr_raw", b"wrong"),
            "fresh capture exit mutation": lambda r: setattr(r.captures[0], "exit_code", 1),
            "fresh capture argv mutation": lambda r: r.captures[0].argv.append("--help"),
            "fresh capture foreign stdin lease": lambda r: setattr(r.captures[0], "target_execution_lease", {
                "logicalTargetPath": "foreign.js", "executionAdapter": "TARGET-BYTES-STDIN",
                "plannedByteLength": 1, "plannedSha256": "0" * 64,
                "executedInputByteLength": 1, "executedInputSha256": "0" * 64}),
            "fresh runtime mutation": lambda r: r.runtime.update(node="v24.99.0"),
            "fresh dependency mutation": lambda r: r.runtime_closure_document["dependencyRoots"][0]["members"][0].update(sha256="0" * 64),
            "fresh tool mutation": lambda r: r.runtime_closure_document["nodeExecutable"].update(sha256="0" * 64),
            "fresh guard mutation": lambda r: r.runtime_closure_guard_evidence.update(queueOverflow=True),
            "fresh target mutation": lambda r: r.command_results[0]["targets"][0].update(sha256="0" * 64),
            "fresh input mutation": lambda r: r.command_results[0]["executionInputs"][0].update(actualSha256="0" * 64),
            "fresh mode mutation": lambda r: r.command_results[0]["executionInputs"][0].update(inputMode="NONE"),
            "fresh reparse mutation": lambda r: r.command_results[0]["targets"][0].update(reparsePoint=True),
            "fresh association mutation": lambda r: r.command_results[0]["executionInputs"].reverse(),
            "fresh plan mutation": lambda r: r.command_plan[0]["targets"][0].update(sha256="0" * 64),
            "hard-gate failure": lambda r: r.hard_gate_results.append({"id": ci.HARD_GATE_AUTHORITY[0], "status": "fail"}),
            "execution violation": lambda r: r.violations.append({"id": "CI-RUNNER-ERROR"}),
            "execution timeout": lambda r: r.command_results[0].update(timeoutStatus="TIMED-OUT"),
            "unclean cleanup": lambda r: setattr(r, "private_temp_handle", object()),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                def run():
                    change(case.runner)
                    return case.comparison
                case.runner.run.side_effect = run
                self.assert_rejected(case, label)
                case.runner.run.assert_called_once()
                case.runner.close_execution_leases.assert_called_once()
        for label, result in (("runner unavailable", OSError("unavailable")), ("comparison unavailable", None)):
            with self.subTest(case=label), outer_fixture() as case:
                if isinstance(result, Exception):
                    case.runner.run.side_effect = result
                else:
                    case.runner.run.return_value = result
                self.assert_rejected(case, label)

    def test_malformed_records_and_observations_do_not_execute(self):
        for kind in ("malformed record", "duplicate backend record", "missing observation",
                     "duplicate observation", "unknown observation kind", "foreign observation kind"):
            with self.subTest(kind=kind), outer_fixture() as case:
                records = case.documents["command-results.json"]["records"]
                record = records[0]
                if kind == "malformed record":
                    record.pop("protectedTargetBundle")
                elif kind == "duplicate backend record":
                    records.append(copy.deepcopy(record))
                elif kind == "missing observation":
                    record["producerObservations"].clear()
                elif kind == "duplicate observation":
                    record["producerObservations"].append(copy.deepcopy(record["producerObservations"][0]))
                    record["producerObservations"][-1]["observationOrdinal"] = 1
                else:
                    record["producerObservations"][0]["observationKind"] = (
                        "unknown" if kind == "unknown observation kind" else "normalized-fields-v1")
                reseal_producer(case)
                self.assert_rejected(case, kind)
                case.runner.run.assert_not_called()

    def test_package_and_source_stability_matrix(self):
        for kind in ("changed bytes", "missing file", "changed after raw validation",
                     "changed during replay", "changed after context recheck"):
            with self.subTest(kind=kind), outer_fixture() as case:
                source = case.root / "backend/package.json"
                def change():
                    source.write_bytes(PACKAGE + b" ")
                if kind == "changed bytes":
                    change()
                elif kind == "missing file":
                    source.unlink()
                elif kind == "changed after raw validation":
                    original = ci.verify_evidence_file_set
                    def validate(*args, **kwargs):
                        errors = original(*args, **kwargs)
                        self.assertEqual(errors, [])
                        change()
                        return errors
                    with mock.patch.object(ci, "verify_evidence_file_set", side_effect=validate):
                        self.assert_rejected(case, kind)
                    continue
                elif kind == "changed during replay":
                    case.runner.run.side_effect = lambda: (change() or case.comparison)
                else:
                    def recheck(*args, **kwargs):
                        change()
                        return case.context
                    with mock.patch.object(ci, "rebuild_external_verification_context", side_effect=recheck):
                        self.assert_rejected(case, kind)
                    continue
                self.assert_rejected(case, kind)
        missing = fixture()
        missing.expected_authority["targets"].pop(0)
        rebuilt = fixtures.synthetic_record_from_spec(missing.expected_authority)
        for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
            missing.command_record[key] = copy.deepcopy(rebuilt[key])
        with outer_fixture(missing, missing) as case:
            self.assert_rejected(case, "missing protected package target")
            case.runner.run.assert_not_called()

    def test_invalid_utf8_reconstruction_and_producer_stderr(self):
        for label, producer in (("invalid UTF-8 replacement", fixture(stdout=npm_stdout() + b"\xff")),
                                ("nonempty producer stderr", fixture(stderr=b"warning 123\n"))):
            with self.subTest(label=label), outer_fixture(producer=producer) as case:
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()
        with outer_fixture() as case:
            fields = case.documents["command-results.json"]["records"][0]["producerObservations"][0]["rawStructuredFields"]
            fields["stdout"] = "\ud800"
            write_documents(case.output, case.documents, ascii_json=True)
            self.assert_rejected(case, "unencodable UTF-8 surrogate")
            case.runner.run.assert_not_called()

    def test_public_outer_api_has_no_injection_argument(self):
        self.assertEqual(list(inspect.signature(ci.verify_evidence_with_replay).parameters),
            ["output_dir", "expected_context", "verification_runner", "repo_root", "evidence_authority_root"])
        with outer_fixture() as case:
            with self.assertRaises(TypeError):
                ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                    verification_runner=case.runner, backend_result_evidence=case.pair)
            case.runner.run.assert_not_called()

    def test_outer_context_evidence_and_unrelated_comparisons_precede_parser(self):
        with outer_fixture() as case:
            with mock.patch.object(ci, "rebuild_external_verification_context",
                return_value=replace(case.context, verifier_invocation_id="8" * 64)):
                self.assert_rejected(case, "external context changed")
        with outer_fixture() as case:
            def changed_file():
                (case.output / "summary.md").write_bytes(b"changed during replay\n")
                return case.comparison
            case.runner.run.side_effect = changed_file
            self.assert_rejected(case, "evidence changed during replay")
        with outer_fixture() as case:
            def extra_file():
                (case.output / "extra.json").write_bytes(b"{}\n")
                return case.comparison
            case.runner.run.side_effect = extra_file
            self.assert_rejected(case, "evidence membership changed during replay")
        with outer_fixture() as case:
            case.runner.run.return_value = {**case.comparison, "resolvedCandidates": [{"unrelated": True}]}
            self.assert_rejected(case, "unrelated summary comparison")
        with outer_fixture(extra=True) as case:
            def other_command():
                case.runner.command_results[-1]["stdoutSha256"] = "0" * 64
                return case.comparison
            case.runner.run.side_effect = other_command
            self.assert_rejected(case, "unrelated command comparison")

    def test_reporter_failure_has_zero_identity_calls(self):
        for side in ("producer", "replay"):
            producer, replay = fixture(), fixture(stdout=npm_stdout("90", "912"))
            bad = fixture(stdout=npm_stdout() + b"unknown numeric output 123\n")
            if side == "producer":
                producer = bad
            else:
                replay = bad
            with self.subTest(side=side), outer_fixture(producer, replay) as case:
                self.assert_rejected(case, side + " reporter parse failure",
                                     parser_calls=1 if side == "producer" else 2)

    def test_identity_mismatch_never_attaches(self):
        variants = {
            "test name": npm_stdout().replace(b"case 000", b"case 999", 1),
            "numeric text in name": npm_stdout().replace(b"value 1000", b"value 1001", 1),
            "order": npm_stdout(names=[NAMES[1], NAMES[0], *NAMES[2:]]),
            "whitespace": npm_stdout().replace(b"case 000", b"case  000", 1),
            "LF/CRLF": npm_stdout(newline="\r\n"),
            "leading newline": npm_stdout(initial=False),
            "duration-looking name": npm_stdout(names=[NAMES[0] + " (42ms)", *NAMES[1:]]),
        }
        for label, stdout in variants.items():
            with self.subTest(case=label), outer_fixture(replay=fixture(stdout=stdout)) as case:
                self.assert_rejected(case, "identity mismatch " + label, parser_calls=2, identity_calls=2)

    def test_lower_public_apis_have_no_portable_argument_or_path(self):
        self.assertEqual(list(inspect.signature(ci.compare_verification_replay_claims).parameters),
                         ["documents", "runner", "comparison"])
        self.assertEqual(list(inspect.signature(ci.run_verification_replay).parameters),
                         ["documents", "expected_context", "verification_runner", "repo_root"])
        with outer_fixture() as case:
            bad = copy.deepcopy(case.documents)
            bad["summary.json"].update(schemaVersion=999, documentKind="forged", replayStatus="PASS",
                backend_result_evidence=case.pair, backendCanonicalPortableResult={"identityDigest": "claimed"})
            bad["command-results.json"]["records"][0]["stdoutSha256"] = "0" * 64
            case.runner.backend_result_evidence = case.pair
            with mock.patch.object(portable, "_parse_stdout", side_effect=AssertionError("lower parser")) as parser, \
                 mock.patch.object(portable, "_identity", side_effect=AssertionError("lower identity")) as identity, \
                 mock.patch.object(portable, "_derive_equal_result", side_effect=AssertionError("lower derivation")) as derive:
                for documents in (bad, {}):
                    transcript, errors = ci.compare_verification_replay_claims(documents, case.runner, case.comparison)
                    self.assertTrue(errors)
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                    transcript, errors = ci.run_verification_replay(documents, expected_context=case.context,
                        verification_runner=case.runner, repo_root=case.root)
                    self.assertTrue(errors)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT")
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                with self.assertRaises(TypeError):
                    ci.compare_verification_replay_claims(bad, case.runner, case.comparison,
                                                         backend_result_evidence=case.pair)
                with self.assertRaises(TypeError):
                    ci.run_verification_replay(bad, expected_context=case.context,
                        verification_runner=case.runner, backend_result_evidence=case.pair)
                parser.assert_not_called()
                identity.assert_not_called()
                derive.assert_not_called()
        with mock.patch.object(portable, "_parse_stdout") as parser, mock.patch.object(portable, "_identity") as identity:
            self.assertIsNone(portable._derive_equal_result(ci, {"producer": fixture(), "replay": fixture()}))
            parser.assert_not_called()
            identity.assert_not_called()

    def test_raw_local_frontend_and_packaging_paths_are_unchanged(self):
        with outer_fixture() as case:
            before = json_bytes(ci.finalize_evidence_transcript(case.runner))
            with mock.patch.object(portable, "_parse_stdout", side_effect=AssertionError("local parser")), \
                 mock.patch.object(portable, "_identity", side_effect=AssertionError("local identity")):
                errors = []
                self.assertFalse(ci._validate_command_record(case.producer.command_record, 0, errors,
                    expected_record=case.producer.expected_authority))
                self.assertEqual(errors, [])
                self.assertEqual(json_bytes(ci.finalize_evidence_transcript(case.runner)), before)
                self.assertEqual(ci._command_authority_violations("all", case.runner.command_results,
                    case.runner.observations, expected_plan=case.runner.command_plan), [])
            forged = copy.deepcopy(case.producer.command_record)
            forged["backendCanonicalPortableResult"] = {"identityDigest": "claimed"}
            errors = []
            ci._validate_command_record(forged, 0, errors)
            self.assertTrue(any("keys are not valid" in e for e in errors))

    def test_6169_retained_bytes_and_129_duration_span_controls(self):
        stdout = npm_stdout(initial=False)
        package = json.loads(PACKAGE)
        members, gaps = portable._parse_stdout(stdout, package)
        baseline = {"orderedTests": members, "stdoutNonDurationSegmentsHex": gaps}
        baseline_digest = portable._identity(ci, baseline)
        spans, offset = [], 0
        # Locate the known fixture's numeric intervals independently of the parser.
        for line in stdout.splitlines(keepends=True):
            if line.endswith(b" (1.25ms)\n"):
                begin = offset + len(line) - len(b"1.25ms)\n")
                spans.append((begin, begin + 4))
            elif line.startswith("ℹ duration_ms ".encode()):
                spans.append((offset + len(line) - 5, offset + len(line) - 1))
            offset += len(line)
        excluded = {i for begin, end in spans for i in range(begin, end)}
        retained = [i for i in range(len(stdout)) if i not in excluded]
        self.assertEqual((len(spans), len(gaps), len(excluded), len(retained)), (129, 130, 516, 6169))
        self.assertEqual(b"".join(bytes.fromhex(gap) for gap in gaps), bytes(stdout[i] for i in retained))
        for position in retained:
            changed = stdout[:position] + bytes([stdout[position] ^ 1]) + stdout[position + 1:]
            try:
                changed_members, changed_gaps = portable._parse_stdout(changed, package)
            except (ValueError, UnicodeError):
                continue
            self.assertNotEqual(portable._identity(ci, {"orderedTests": changed_members,
                "stdoutNonDurationSegmentsHex": changed_gaps}), baseline_digest, position)
        for index, (begin, end) in enumerate(spans):
            changed = stdout[:begin] + b"98765.4321" + stdout[end:]
            self.assertEqual(portable._parse_stdout(changed, package), (members, gaps), index)
        print("BACKEND_BYTES retained=6169 excluded_spans=129 excluded_bytes=516 segments=130 duration_controls=129")

    def test_strict_reporter_grammar_matrix(self):
        source = npm_stdout()
        variants = {
            "127 tests": npm_stdout(names=NAMES[:-1]),
            "129 tests": npm_stdout(names=[*NAMES, "extra case"]),
            "duplicate member": npm_stdout(names=[NAMES[0], *NAMES[:-1]]),
            "missing footer": source.rsplit("ℹ duration_ms".encode(), 1)[0],
            "missing final newline": source[:-1],
            "added line": source + b"unexpected output\n",
            "added blank": source + b"\n",
            "removed blank": source.replace(b"node --test\n\n", b"node --test\n", 1),
            "unknown numeric": source.replace("ℹ duration_ms".encode(), "ℹ memory_bytes 123\nℹ duration_ms".encode()),
            "extra duration": source + "ℹ duration_ms 42\n".encode(),
            "misplaced duration": "ℹ duration_ms 42\n".encode() + source,
            "wrong banner": source.replace(b"fixture-backend@1.0.0", b"fixture-backend@1.0.1"),
            "invalid utf8": source.replace(b"backend case", b"backend\xffcase", 1),
            "ANSI": b"\x1b[32m" + source,
            "NUL": source.replace(b"case 000", b"case\x00000", 1),
            "exponent": source.replace(b"1.25ms", b"1e3ms", 1),
            "NaN": source.replace(b"1.25ms", b"NaNms", 1),
            "long decimal": source.replace(b"1.25ms", b"1" * 17 + b"ms", 1),
            "long fraction": source.replace(b"1.25ms", b"1." + b"1" * 17 + b"ms", 1),
            "missing units": source.replace(b"1.25ms", b"1.25", 1),
            "wrong units": source.replace(b"1.25ms", b"1.25us", 1),
            "punctuation": source.replace(b"(1.25ms)", b"[1.25ms]", 1),
            "status": source.replace("✔".encode(), "✖".encode(), 1),
            "TAP": b"TAP version 13\n1..128\n",
        }
        for key, expected in portable.EXPECTED_COUNTS.items():
            variants["count " + key] = source.replace(f"ℹ {key} {expected}".encode(),
                                                     f"ℹ {key} {expected + 1}".encode())
        for label, data in variants.items():
            with self.subTest(case=label), self.assertRaises((ValueError, UnicodeError)):
                portable._parse_stdout(data, json.loads(PACKAGE))
        tree = ast.parse(Path(portable.__file__).read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("sub", "subn") for n in ast.walk(tree)))

    def test_unicode_stderr_lifecycle_and_tool_authority_sensitivity(self):
        composed = fixture(stdout=npm_stdout(names=["caf\u00e9 test", *NAMES[1:]]))
        decomposed = fixture(stdout=npm_stdout(names=["cafe\u0301 test", *NAMES[1:]]))
        with outer_fixture(composed, decomposed) as case:
            self.assert_rejected(case, "Unicode spelling", parser_calls=2, identity_calls=2)
        with outer_fixture(replay=fixture(stderr=b"warning 123\n")) as case:
            self.assert_rejected(case, "nonempty stderr")
        for extra in ({"pretest": "echo extra"}, {"posttest": "echo extra"}, {"test": "node --test --test-reporter=tap"}):
            source = fixture()
            package = json.loads(PACKAGE)
            package["scripts"].update(extra)
            data = json_bytes(package)
            spec = copy.deepcopy(source.expected_authority)
            spec["targets"][0].update(size=len(data), sha256=digest(data))
            record = copy.deepcopy(source.command_record)
            rebuilt = fixtures.synthetic_record_from_spec(spec)
            for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
                record[key] = copy.deepcopy(rebuilt[key])
            modified = replace(source, command_record=record, expected_authority=spec, package_json=data)
            with outer_fixture(modified, modified) as case:
                self.assert_rejected(case, "package lifecycle " + next(iter(extra)))
        for kind in ("npm hash", "npm size", "npm version", "dependency membership"):
            replay = fixture(stdout=npm_stdout("90", "912"))
            closure = replay.runtime_closure
            if kind == "npm hash":
                closure["npmEntrypoint"]["sha256"] = digest(b"changed npm")
            elif kind == "npm size":
                closure["npmEntrypoint"]["size"] += 1
            elif kind == "npm version":
                closure["npmEntrypoint"]["version"] = replay.runtime["npm"] = "11.0.1"
            else:
                root = closure["dependencyRoots"][0]
                root["members"][0]["sha256"] = digest(b"changed dependency")
                root["memberManifestDigest"] = digest(ci._canonical_frame(root["members"]))
                semantic = {key: closure[key] for key in ("lockfiles", "dependencyRoots", "vitest", "nodePath")}
                closure["dependencyClosureDigest"] = digest(ci._canonical_frame(semantic))
                replay.runtime["dependencyClosureDigest"] = closure["dependencyClosureDigest"]
                replay.command_record["dependencyClosureDigest"] = closure["dependencyClosureDigest"]
            closure["closureDigest"] = digest(ci._canonical_frame({
                key: value for key, value in closure.items() if key != "closureDigest"}))
            replay.runtime["runtimeClosureDigest"] = closure["closureDigest"]
            replay.command_record["runtimeClosureDigest"] = closure["closureDigest"]
            for side in ("producer", "replay"):
                arguments = {"producer": replay, "replay": fixture()} if side == "producer" else {"replay": replay}
                with self.subTest(kind=kind, side=side), outer_fixture(**arguments) as case:
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    # Self-consistency cannot substitute for independent fresh authority.
                    self.assert_rejected(case, "coherent " + side + " " + kind)


if __name__ == "__main__":
    unittest.main(verbosity=2)
