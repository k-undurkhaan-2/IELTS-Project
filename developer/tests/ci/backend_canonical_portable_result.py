"""Backend-only cross-job result comparison; never local execution authority.

Callers supply retained preimages separately from the unchanged raw evidence.
No stream is reconstructed from normalized observations or diagnostic previews.
The diagnostic reporter is deliberately not imported as an acceptance parser.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import re
from collections.abc import Mapping


SCHEMA = "BackendCanonicalPortableResult"
VERSION = 1
TEST_COUNT = 128
MAX_STREAM_BYTES = 2 * 1024 * 1024
COUNTS = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
EXPECTED_COUNTS = dict(zip(COUNTS, (TEST_COUNT, 0, TEST_COUNT, 0, 0, 0, 0)))
AUTHORITY_KEYS = frozenset({
    "commandId", "ordinal", "commandClass", "commandRole", "required", "profile",
    "platform", "argv", "logicalArgv", "executionArgv", "executionInputMode",
    "executionInputSize", "executionInputSha256", "cwd", "toolRole",
    "resolvedExecutablePath", "resolvedExecutableSize", "resolvedExecutableSha256",
    "resolvedExecutableFileIdentity", "executionLease", "targets", "resultSemantics",
    "allowedExecutionExits",
})
# Full-line grammar recognizers only. No search/substitution/number normalization.
_DECIMAL = rb"[0-9]{1,16}(?:\.[0-9]{1,16})?"
_MEMBER = re.compile("✔ ".encode() + rb"(.{1,1024}) \((" + _DECIMAL + rb")ms\)")
_DURATION = re.compile("ℹ duration_ms ".encode() + rb"(" + _DECIMAL + rb")")
_STABLE_KEYS = frozenset({
    "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs",
    "reparsePoint",
})


@dataclass(frozen=True)
class BackendCanonicalReplayEvidence:
    """Original, complete preimages, supplied by the retaining caller in memory.

    These are inputs to verification, not a claimed portable result or a boolean
    assertion of authority. The comparison binds them to both raw evidence and
    the independently rebuilt replay plan/runtime before using a projection.
    """

    command_record: Mapping
    expected_authority: Mapping
    stdout: bytes
    stderr: bytes
    package_json: bytes
    runtime: Mapping
    runtime_closure: Mapping
    runtime_guard: Mapping


def _require(condition):
    if not condition:
        raise ValueError("backend portable result unavailable")


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _identity(ci, value):
    # A bytes frame prevents the general canonical codec from folding Unicode.
    return ci.canonical_failure_digest({
        "digestDomain": "ieltmps-backend-canonical-portable-result-v1",
        "resultUtf8": _json_bytes(value),
    })


def _parse_stdout(stdout, package):
    """Consume every byte, returning ordered members and the 130 exact gaps.

    Only the numeric spans in 128 terminal '(Dms)' fields and the one terminal
    'duration_ms D' footer are omitted. Units, punctuation, whitespace, names,
    line endings, and even the optional initial npm newline stay in the gaps.
    """
    _require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STREAM_BYTES)
    stdout.decode("utf-8", errors="strict")
    _require(not any(b < 32 and b not in (10, 13) or b == 127 for b in stdout))
    raw_lines = stdout.splitlines(keepends=True)
    _require(len(raw_lines) in (TEST_COUNT + 11, TEST_COUNT + 12))
    lines, offsets, offset = [], [], 0
    for line in raw_lines:
        _require(line.endswith(b"\n") and len(line) <= 2048)
        body = line[:-2] if line.endswith(b"\r\n") else line[:-1]
        _require(b"\r" not in body)
        offsets.append(offset)
        lines.append(body)
        offset += len(line)
    start = 1 if lines[0] == b"" else 0
    banner = f"> {package['name']}@{package['version']} test".encode("utf-8")
    _require(lines[start:start + 3] == [banner, b"> node --test", b""])
    _require(len(lines) == start + 3 + TEST_COUNT + 8)
    members, spans = [], []
    for index in range(start + 3, start + 3 + TEST_COUNT):
        match = _MEMBER.fullmatch(lines[index])
        _require(match is not None)
        name = match[1].decode("utf-8", errors="strict")
        _require(name == name.strip())
        members.append({"name": name, "status": "pass"})
        spans.append(tuple(offsets[index] + n for n in match.span(2)))
    _require(len({member["name"] for member in members}) == TEST_COUNT)
    footer = start + 3 + TEST_COUNT
    for index, key in enumerate(COUNTS):
        _require(lines[footer + index] == f"ℹ {key} {EXPECTED_COUNTS[key]}".encode())
    match = _DURATION.fullmatch(lines[-1])
    _require(match is not None)
    spans.append(tuple(offsets[-1] + n for n in match.span(1)))
    gaps, offset = [], 0
    for begin, end in spans:
        gaps.append(stdout[offset:begin].hex())
        offset = end
    gaps.append(stdout[offset:].hex())
    _require(len(spans) == 129 and len(gaps) == 130)
    return members, gaps


def _stable_identity(value):
    _require(isinstance(value, dict) and value.get("reparsePoint") is False)
    if set(value) == _STABLE_KEYS:
        keys = _STABLE_KEYS - {"reparsePoint"}
    else:
        # ExecutableIdentityLease._windows_identity (not the target-lease shape).
        _require(set(value) == {"volumeSerial", "fileIndex", "size", "writeTime", "links", "reparsePoint"})
        _require(type(value["size"]) is int and value["size"] > 0)
        _require(type(value["links"]) is int and value["links"] >= 1)
        keys = ("volumeSerial", "fileIndex", "writeTime")
    _require(all(type(value[k]) is str and re.fullmatch(r"-?[0-9]{1,24}", value[k])
                 for k in keys))


@dataclass(frozen=True)
class _BoundSide:
    # Immutable bytes only: no caller-owned mappings survive the binding boundary.
    stdout: bytes
    bindings: bytes


@dataclass(frozen=True)
class _ProducerContext:
    commands: dict
    plan: list
    producer: BackendCanonicalReplayEvidence
    supplied_replay: BackendCanonicalReplayEvidence | None
    side: _BoundSide


@dataclass(frozen=True)
class _BoundPair:
    producer: _BoundSide
    replay: _BoundSide
    producer_records: list
    replay_records: list
    plan_digest: str
    classes: list


def _bind_side(ci, evidence):
    """Validate a full side without parsing its reporter or computing a result identity."""
    try:
        _require(type(evidence) is BackendCanonicalReplayEvidence)
        evidence = copy.deepcopy(evidence)
        record, expected = evidence.command_record, evidence.expected_authority
        _require(isinstance(record, dict) and isinstance(expected, dict))
        _require(set(expected) == AUTHORITY_KEYS)
        _require({key: record.get(key) for key in AUTHORITY_KEYS} == expected)
        _require(record["commandId"] == record["commandClass"] == "backend-canonical")
        _require(record["profile"] in ("backend", "all"))
        _require(record["toolRole"] == "npm-backend-test" and record["required"] is True)
        _require(record["resultSemantics"] == "baseline-classified-test-result")
        _require((record["commandRole"], tuple(record["allowedExecutionExits"])) in (
            ("required-execution", (0,)), ("observation-producing", (0, 1))))
        _require(record["executionInputMode"] == "PROTECTED-TARGET-BUNDLE")
        _require(record["executionInputSize"] is record["executionInputSha256"] is None)
        _require(type(record["exitCode"]) is int and record["exitCode"] == 0)
        _require(ci._command_execution_completed(record))
        _require(record["processTreeStatus"] == "contained-clean")
        _require(record["containmentDisposition"] in ("no-descendants", "natural-exit-reaped"))
        _require(record["descendantsTerminated"] == record["descendantsSurviving"] == 0)
        _require(record["descendantsObserved"] == record["descendantsReaped"])
        _require((record["containmentDisposition"] == "no-descendants")
                 == (record["descendantsObserved"] == 0))
        _require((record["platform"], record["containment"]) in (
            ("ubuntu", "linux-subreaper-pidfd-proc-supervisor"),
            ("windows", "windows-job-object")))
        _require(all(record.get(key) is None for key in ("error", "processTreeError", "limitReason")))
        errors = []
        _require(not ci._validate_command_record(record, record["ordinal"], errors,
                                                 expected_record=expected) and not errors)
        _require(0 < len(record["targets"]) <= 2048)
        _require(len(record["executionInputs"]) == len(record["targets"]))
        _require(record["executionInputBundleDigest"]
                 == ci.execution_input_bundle_digest(record["executionInputs"]))
        bundle_digest = ci._validated_portable_protected_input_bundle_digest(record)
        _require(bundle_digest is not None)
        authority = ci._portable_command_plan_value([expected])
        _require(isinstance(authority, list) and len(authority) == 1 and bool(authority[0]))
        for stream, raw in (("stdout", evidence.stdout), ("stderr", evidence.stderr)):
            _require(type(raw) is bytes and len(raw) <= MAX_STREAM_BYTES)
            _require(len(raw) == record[stream + "BytesObserved"])
            _require(hashlib.sha256(raw).hexdigest() == record[stream + "Sha256"])
        _require(evidence.stderr == b"")
        _require(len(record["producerObservations"]) == 1)
        raw = record["producerObservations"][0]
        _require(not ci._validate_raw_observation(raw, label="backend-portable", source=record))
        _require(raw["observationKind"] == "process-output-v1")
        _require(raw["observationOrdinal"] == 0 and raw["occurrences"] == 1)
        _require(raw["sourceResultId"] == "command:npm --prefix backend test")
        _require(raw["sourcePath"] == "backend/package.json" and raw["failurePathAuthority"] is None)
        _require(raw["rawStructuredFields"] == ci.raw_observation_json_value({
            "executed": True, "exitCode": 0, "stdout": evidence.stdout.decode("utf-8"),
            "stderr": "", "error": None,
        }))
        package_targets = [t for t in expected["targets"] if t["path"] == "backend/package.json"]
        _require(len(package_targets) == 1 and type(evidence.package_json) is bytes)
        _require(0 < len(evidence.package_json) <= 512 * 1024)
        _require(len(evidence.package_json) == package_targets[0]["size"])
        _require(hashlib.sha256(evidence.package_json).hexdigest() == package_targets[0]["sha256"])
        package = ci.strict_json_loads(evidence.package_json.decode("utf-8"), label="backend package")
        _require(all(type(package.get(k)) is str and 0 < len(package[k]) <= 1024
                     and not any(ord(c) < 32 or ord(c) == 127 for c in package[k])
                     for k in ("name", "version")))
        scripts = package["scripts"]
        _require(scripts["test"] == "node --test")
        _require("pretest" not in scripts and "posttest" not in scripts)
        closure, guard, runtime = evidence.runtime_closure, evidence.runtime_guard, evidence.runtime
        ci._validate_runtime_dependency_closure(closure, guard, runtime,
            profile=record["profile"], status="PASS", errors=errors)
        _require(not errors and closure["measurementStatus"] == "measured-complete")
        _require(closure["runnerOS"] == {"ubuntu": "Linux", "windows": "Windows"}[record["platform"]])
        _require(record["dependencyBacked"] is True)
        _require(record["runtimeClosureDigest"] == closure["closureDigest"])
        _require(record["dependencyClosureDigest"] == closure["dependencyClosureDigest"])
        _require(record["runtimeClosureGuard"] == guard and guard["active"] is False)
        _require(guard["watcherBackend"] == {"ubuntu": "_InotifyMutationWatcher",
                 "windows": "_WindowsDirectoryMutationWatcher"}[record["platform"]])
        tools = {}
        for name, key, role in (("node", "nodeExecutable", "node-runtime"),
                                ("npm", "npmEntrypoint", "npm-entrypoint")):
            tool = closure[key]
            keys = {"role", "canonicalPath", "size", "sha256", "stableIdentity", "leaseHeld", "version"}
            _require(set(tool) == keys | ({"available"} if name == "npm" else set()))
            _require(tool["role"] == role and tool["leaseHeld"] is True)
            _require(type(tool["size"]) is int and tool["size"] > 0)
            _stable_identity(tool["stableIdentity"])
            _require(tool["version"] == runtime[name])
            _require(re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", tool["version"]) is not None)
            tools[name] = {k: tool[k] for k in ("role", "size", "sha256", "version")}
        node, npm = closure["nodeExecutable"], closure["npmEntrypoint"]
        _require(npm["available"] is True)
        _require(record["logicalArgv"] == [npm["canonicalPath"], "--prefix", "backend", "test"])
        _require(record["executionArgv"] == [node["canonicalPath"], *record["logicalArgv"]])
        _require(record["cwd"] == "." and record["resolvedExecutablePath"] == node["canonicalPath"])
        _require(record["resolvedExecutableSha256"] == node["sha256"])
        _require(record["resolvedExecutableSize"] == node["size"])
        _stable_identity(record["resolvedExecutableFileIdentity"])
        _require(record["resolvedTestRunnerEntrypoint"] == node["canonicalPath"])
        _require(record["resolvedTestRunnerSha256"] == node["sha256"])
        bindings = {
            "command": {k: record[k] for k in ("commandId", "commandClass", "ordinal")},
            "package": package, "packageJsonSha256": package_targets[0]["sha256"],
            "tools": tools, "authority": authority, "inputBundleDigest": bundle_digest,
            "dependencyClosureDigest": closure["dependencyClosureDigest"],
        }
        return _BoundSide(evidence.stdout, _json_bytes(bindings))
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None


def _bind_producer(ci, commands, plan, pair):
    """Called only by the outer verifier after validating its exact raw snapshots."""
    try:
        _require(type(pair) is dict and set(pair) in ({"producer"}, {"producer", "replay"}))
        pair, commands, plan = copy.deepcopy((pair, commands, plan))
        producer = pair["producer"]
        _require(type(producer) is BackendCanonicalReplayEvidence)
        _require("replay" not in pair or type(pair["replay"]) is BackendCanonicalReplayEvidence)
        records = commands["records"]
        backend = [r for r in records if r["commandId"] == "backend-canonical"]
        expected = [p for p in plan if p["commandId"] == "backend-canonical"]
        _require(len(backend) == len(expected) == 1)
        # Equality binds every full field, including checkout-local identities.
        # Compaction is the existing validated wire representation, never a new codec.
        _require(backend[0] == producer.command_record or backend[0]
                 == ci._compact_command_record_for_evidence(producer.command_record))
        _require(ci._portable_command_plan_value([producer.expected_authority])
                 == ci._portable_command_plan_value(expected))
        _require(commands["commandAuthority"] == ci._portable_command_plan_value(plan))
        _require(commands["commandPlanDigest"] == ci.command_plan_digest(plan))
        for key, value in (("runtime", producer.runtime),
                           ("runtimeDependencyClosure", producer.runtime_closure),
                           ("runtimeDependencyGuard", producer.runtime_guard)):
            _require(commands[key] == value)
        _require(commands["producerObservationUniverseDigest"]
                 == ci.producer_observation_universe_digest(records))
        _require(commands["producerTranscriptDigest"] == ci.producer_transcript_digest(
            commands["commandPlanDigest"], records, commands["actualCompletedCommandClasses"]))
        # Existing full-context observation claims never gain a rewrite path.
        _require(commands["observations"] == [])
        side = _bind_side(ci, producer)
        _require(side is not None)
        return _ProducerContext(commands, plan, producer, pair.get("replay"), side)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None


def _bind_replay(ci, context, commands, runner):
    """Recheck producer bindings and bind only the completed fresh runner capture."""
    try:
        _require(type(context) is _ProducerContext)
        _require(commands == context.commands and runner.command_plan == context.plan)
        _require(ci.command_plan_digest(runner.command_plan) == runner.command_plan_digest
                 == commands["commandPlanDigest"])
        rebound = _bind_producer(ci, commands, runner.command_plan, {"producer": context.producer})
        _require(rebound is not None and rebound.side == context.side)
        records = [r for r in runner.command_results if r["commandId"] == "backend-canonical"]
        plans = [p for p in runner.command_plan if p["commandId"] == "backend-canonical"]
        captures = [c for c in runner.captures if c.command_id == "backend-canonical"]
        _require(len(records) == len(plans) == len(captures) == 1)
        capture = captures[0]
        _require(type(capture) is ci.CommandCapture)
        # Backend uses the protected target bundle, never a captured stdin lease.
        # Capture.evidence() derives stdin inputs from this field; it must not be
        # hidden by the exclusions for bundle data later added by the runner.
        _require(capture.target_execution_lease is None)
        fresh = BackendCanonicalReplayEvidence(
            records[0], plans[0], capture.stdout_raw, capture.stderr_raw,
            context.producer.package_json, runner.runtime, runner.runtime_closure_document,
            runner.runtime_closure_guard_evidence,
        )
        # An explicit replay preimage has no authority over the actual fresh capture.
        _require(context.supplied_replay is None or context.supplied_replay == fresh)
        side = _bind_side(ci, fresh)
        _require(side is not None)
        # Self-consistent producer tool/runtime claims are not fresh authority.
        # Bind all non-reporter inputs to the independently measured replay
        # before either reporter can be parsed (including npm hash/size/version).
        _require(side.bindings == context.side.bindings)
        _require(fresh.runtime_closure["closureDigest"] == runner.runtime_closure_digest)
        _require(fresh.runtime_closure["dependencyClosureDigest"] == runner.dependency_closure_digest)
        # These fields are added by FoundationRunner after capture; all measured
        # execution fields, including both streams, must equal the fresh record.
        runner_added = {"executionInputs", "executionInputBundleDigest", "protectedTargetBundle",
                        "producerObservations",
                        "producerObservationSetDigest", "completedCommandClass"}
        for key, value in capture.evidence().items():
            if key not in runner_added:
                _require(records[0].get(key) == value)
        _require(not runner.violations and all(r.get("status") == "pass"
                                              for r in runner.hard_gate_results))
        return _BoundPair(context.side, side, copy.deepcopy(commands["records"]),
                          copy.deepcopy(runner.command_results), runner.command_plan_digest,
                          list(runner.actual_completed_command_classes))
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None


def _project_record(ci, record, result):
    """Detached comparison values; never input to a raw/local authority function."""
    projected = ci._canonical_transcript_record(record)
    if result is None:
        # Eligibility only: defer the four reporter-dependent fields while every
        # other field and every other command still undergoes exact comparison.
        for key in ("stdoutSha256", "stdoutBytesObserved", "producerObservations",
                    "producerObservationSetDigest"):
            projected.pop(key)
        return projected
    encoded = _json_bytes(result["result"])
    projected["stdoutSha256"] = hashlib.sha256(encoded).hexdigest()
    projected["stdoutBytesObserved"] = len(encoded)
    raw = copy.deepcopy(record["producerObservations"][0])
    raw["rawStructuredFields"]["stdout"] = copy.deepcopy(result)
    raw["sourceOutputDigest"] = result["identityDigest"]
    raw["producerRecordDigest"] = ci._producer_record_digest({
        key: value for key, value in raw.items() if key != "producerRecordDigest"})
    projected["producerObservations"] = [raw]
    projected["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
    return projected


def _comparison_view(ci, records, plan_digest, classes, result):
    projected = [_project_record(ci, r, result) if r["commandId"] == "backend-canonical"
                 else ci._canonical_transcript_record(r) for r in records]
    universe = ci.producer_observation_universe(records)
    for item, record in zip(universe, projected):
        if record["commandId"] == "backend-canonical":
            for key in ("producerObservations", "producerObservationSetDigest"):
                if result is None:
                    item.pop(key)
                else:
                    item[key] = record[key]
    universe_digest = ci.canonical_failure_digest(universe)
    transcript_digest = ci.canonical_failure_digest({
        "commandPlanDigest": plan_digest, "orderedCommandTranscript": projected,
        "orderedProducerObservationUniverse": universe,
        "producerObservationUniverseDigest": universe_digest,
        "completedCommandClasses": sorted(set(classes)),
        "completedCommandClassSetDigest": ci.completed_command_class_set_digest(classes),
    })
    return {"records": projected, "producerObservationUniverseDigest": universe_digest,
            "producerTranscriptDigest": transcript_digest}


def _comparison_views(ci, pair, result=None):
    _require(type(pair) is _BoundPair)
    return {side: _comparison_view(ci, records, pair.plan_digest, pair.classes, result)
            for side, records in (("producer", pair.producer_records), ("replay", pair.replay_records))}


def _derive_equal_result(ci, pair):
    """Accept only two already bound immutable sides, after outer eligibility.

    Both complete reporters must parse before either result identity is computed.
    A failed binding never calls this function; a parse failure computes no identity.
    """
    try:
        _require(type(pair) is _BoundPair)
        values = []
        for side in (pair.producer, pair.replay):
            _require(type(side) is _BoundSide)
            bound = json.loads(side.bindings)
            members, gaps = _parse_stdout(side.stdout, bound["package"])
            values.append({
                "schema": SCHEMA, "version": VERSION, "command": bound["command"],
                "orderedTests": members, "reporterCounts": dict(EXPECTED_COUNTS),
                "package": {"name": bound["package"]["name"], "version": bound["package"]["version"],
                            "packageJsonSha256": bound["packageJsonSha256"]},
                "lifecycle": {"event": "test", "pretest": None, "test": "node --test", "posttest": None},
                "tools": bound["tools"], "exitCode": 0,
                "stdoutNonDurationSegmentsHex": gaps,
                "stderr": {"byteLength": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                "portableAuthorityDigest": ci.canonical_failure_digest(bound["authority"]),
                "portableInputBundleDigest": bound["inputBundleDigest"],
                "dependencyClosureDigest": bound["dependencyClosureDigest"],
            })
        results = [{"identityDigest": _identity(ci, value), "result": value} for value in values]
        _require(results[0] == results[1])
        return results[1]
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None
