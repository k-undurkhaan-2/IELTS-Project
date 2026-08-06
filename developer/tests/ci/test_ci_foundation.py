#!/usr/bin/env python3
"""Focused regression tests for the baseline-aware CI policy runner."""

from __future__ import annotations

import copy
import contextlib
import ast
import hashlib
import io
import inspect
import json
import math
import os
import shutil
import subprocess
import stat
import sys
import tempfile
import threading
import time
import unittest
import unicodedata
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CI_DIR = Path(__file__).resolve().parent
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))

import run_ci_foundation as ci  # noqa: E402
import run_static_suite as static_suite  # noqa: E402
import test_standalone_packaging as standalone_packaging  # noqa: E402


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _candidate_worktree_roots() -> tuple[Path, ...]:
    git_candidates = []
    configured = os.environ.get("GIT_EXE")
    if configured:
        git_candidates.append(Path(configured))
    git_candidates.append(Path(r"D:\Git\cmd\git.exe"))
    discovered = shutil.which("git")
    if discovered:
        git_candidates.append(Path(discovered))

    for git in git_candidates:
        try:
            trusted_git = git.resolve(strict=True)
        except OSError:
            continue
        result = subprocess.run(
            [
                str(trusted_git),
                "-c",
                f"safe.directory={ci.REPO_ROOT.resolve()}",
                "-C",
                str(ci.REPO_ROOT),
                "worktree",
                "list",
                "--porcelain",
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0:
            roots = []
            for line in result.stdout.splitlines():
                if line.startswith("worktree "):
                    try:
                        roots.append(Path(line[len("worktree ") :]).resolve(strict=True))
                    except OSError:
                        pass
            if roots:
                return tuple(roots)
    return (ci.REPO_ROOT.resolve(),)


def _explicit_security_task_temp() -> Path:
    selected = (
        os.environ.get("CI_SECURITY_TASK_TEMP")
        or os.environ.get("TEMP")
        or tempfile.gettempdir()
    )
    return Path(selected).resolve(strict=True)


@contextlib.contextmanager
def make_task_owned_tempdir(parent: Path, short_prefix: str):
    if not short_prefix or len(short_prefix) > 12:
        raise AssertionError("task temp prefix must be bounded and short")
    explicit_parent = Path(parent).resolve(strict=True)
    if not explicit_parent.is_dir():
        raise AssertionError("task temp parent must exist")
    if _is_reparse_point(explicit_parent):
        raise AssertionError("task temp parent must not be a reparse point")
    for worktree_root in _candidate_worktree_roots():
        if _path_is_relative_to(explicit_parent, worktree_root):
            raise AssertionError("task temp parent must be outside registered worktrees")
    handle = tempfile.TemporaryDirectory(dir=explicit_parent, prefix=short_prefix)
    try:
        result = Path(handle.name).resolve(strict=True)
        if not _path_is_relative_to(result, explicit_parent):
            raise AssertionError("task temp result must stay below explicit parent")
        if _is_reparse_point(result):
            raise AssertionError("task temp result must not be a reparse point")
        yield result
    finally:
        handle.cleanup()


def _ci12_local_binding(repository: str) -> dict[str, object]:
    return {
        "bindingSchemaVersion": ci.AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION,
        "bindingKind": "AuthorizationContextBinding",
        "bindingMode": "local",
        "expectedProfile": "static",
        "producerJobId": "local-producer",
        "expectedVerifierJobId": "local-verifier",
        "runnerOS": "Windows" if os.name == "nt" else "Linux",
        "runId": "ci12-local-identity-test",
        "runAttempt": "1",
        "eventName": "local-test",
        "repository": repository,
        "checkoutCommit": "a" * 40,
        "checkoutTree": "b" * 40,
        "baselineCommit": "c" * 40,
        "baselineTree": "d" * 40,
        "trustFileDigest": "e" * 64,
        "commandPlanDigest": "f" * 64,
        "producerInvocationId": "1" * 64,
    }


def _ci12_full_context_digest(repository: str, authorization_digest: str) -> str:
    return ci.canonical_failure_digest(
        {
            "currentFullContextDigestVersion": "ci12-local-identity-test",
            "repository": repository,
            "authorizationContextBindingDigest": authorization_digest,
        }
    )


CI11_REFERENCE_TAGS = {
    "null": b"n",
    "boolean": b"b",
    "integer": b"i",
    "float": b"f",
    "text": b"s",
    "bytes": b"y",
    "list": b"l",
    "map": b"m",
    "map-key": b"k",
}
CI11_AUTHORIZATION_FIELDS = frozenset(
    {
        "bindingSchemaVersion",
        "bindingKind",
        "bindingMode",
        "expectedProfile",
        "producerJobId",
        "expectedVerifierJobId",
        "runnerOS",
        "runId",
        "runAttempt",
        "eventName",
        "repository",
        "checkoutCommit",
        "checkoutTree",
        "baselineCommit",
        "baselineTree",
        "trustFileDigest",
        "commandPlanDigest",
        "producerInvocationId",
    }
)
CI11_VERIFIER_FIELDS = frozenset(
    {
        "bindingSchemaVersion",
        "bindingKind",
        "actualVerifierJobId",
        "actualVerifierRunnerOS",
        "verifierInvocationId",
        "freshRuntimeClosureDigest",
        "freshDependencyClosureDigest",
        "linuxContainmentLiveTestResultDigest",
        "replayTranscriptDigest",
        "cleanupResult",
    }
)
CI11_ENVELOPE_FIELDS = frozenset(
    {
        "schemaVersion",
        "bindingKind",
        "currentFullContextDigestSetDigest",
        "authorizationContextBindingDigest",
        "verifierReplayContextDigest",
    }
)


def ci11_reference_frame(value: object) -> bytes:
    """Docs-driven encoder independent of all production framing helpers."""

    def frame(tag: bytes, payload: bytes) -> bytes:
        return tag + len(payload).to_bytes(8, "big", signed=False) + payload

    def count(length: int) -> bytes:
        return length.to_bytes(8, "big", signed=False)

    if value is None:
        return frame(CI11_REFERENCE_TAGS["null"], b"")
    if type(value) is bool:
        return frame(CI11_REFERENCE_TAGS["boolean"], b"1" if value else b"0")
    if type(value) is int:
        return frame(CI11_REFERENCE_TAGS["integer"], str(value).encode("ascii"))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("reference grammar forbids non-finite floats")
        return frame(CI11_REFERENCE_TAGS["float"], value.hex().encode("ascii"))
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        return frame(CI11_REFERENCE_TAGS["text"], normalized.encode("utf-8"))
    if isinstance(value, bytes):
        return frame(CI11_REFERENCE_TAGS["bytes"], value)
    if isinstance(value, (list, tuple)):
        payload = count(len(value)) + b"".join(
            ci11_reference_frame(item) for item in value
        )
        return frame(CI11_REFERENCE_TAGS["list"], payload)
    if isinstance(value, Mapping):
        items: list[tuple[bytes, object]] = []
        seen: set[bytes] = set()
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("reference grammar map keys must be text")
            key = unicodedata.normalize("NFC", raw_key).encode("utf-8")
            if key in seen:
                raise ValueError("reference grammar duplicate normalized map key")
            seen.add(key)
            items.append((key, item))
        items.sort(key=lambda pair: pair[0])
        payload = count(len(items))
        for key, item in items:
            payload += frame(CI11_REFERENCE_TAGS["map-key"], key)
            payload += ci11_reference_frame(item)
        return frame(CI11_REFERENCE_TAGS["map"], payload)
    raise TypeError(f"reference grammar unsupported type: {type(value).__name__}")


def _ci11_reference_schema(
    value: object,
    fields: frozenset[str],
    version_field: str,
    kind: str,
) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("reference schema field set is not exact")
    if type(value.get(version_field)) is not int or value[version_field] != 1:
        raise ValueError("reference schema version is invalid")
    if value.get("bindingKind") != kind:
        raise ValueError("reference schema kind is invalid")
    for field_name, field_value in value.items():
        if field_name != version_field and not isinstance(field_value, str):
            raise ValueError(f"reference schema {field_name} is not text")
    return copy.deepcopy(value)


def ci11_reference_authorization_preimage(binding: object) -> bytes:
    value = _ci11_reference_schema(
        binding,
        CI11_AUTHORIZATION_FIELDS,
        "bindingSchemaVersion",
        "AuthorizationContextBinding",
    )
    return ci11_reference_frame(
        {
            "digestDomain": "ieltmps-authorization-context-binding-v1",
            "binding": value,
        }
    )


def ci11_reference_verifier_preimage(binding: object) -> bytes:
    value = _ci11_reference_schema(
        binding,
        CI11_VERIFIER_FIELDS,
        "bindingSchemaVersion",
        "VerifierReplayContextBinding",
    )
    return ci11_reference_frame(
        {
            "digestDomain": "ieltmps-verifier-replay-context-binding-v1",
            "binding": value,
        }
    )


def ci11_reference_envelope_preimage(envelope: object) -> bytes:
    value = _ci11_reference_schema(
        envelope,
        CI11_ENVELOPE_FIELDS,
        "schemaVersion",
        "ReplayAuthorizationEnvelope",
    )
    return ci11_reference_frame(
        {
            "digestDomain": "ieltmps-replay-authorization-envelope-v1",
            "envelope": value,
        }
    )


def ci11_insertion_order_frame(value: Mapping[str, object]) -> bytes:
    """Deliberately wrong outer-map encoder used only by negative vectors."""

    def frame(tag: bytes, payload: bytes) -> bytes:
        return tag + len(payload).to_bytes(8, "big", signed=False) + payload

    payload = len(value).to_bytes(8, "big", signed=False)
    for raw_key, item in value.items():
        key = unicodedata.normalize("NFC", raw_key).encode("utf-8")
        payload += frame(CI11_REFERENCE_TAGS["map-key"], key)
        payload += ci11_reference_frame(item)
    return frame(CI11_REFERENCE_TAGS["map"], payload)


def ci11_policy_json_block(label: str) -> dict:
    policy = (CI_DIR.parents[2] / "docs" / "CI_POLICY.md").read_text(
        encoding="utf-8"
    )
    marker = f"<!-- {label} -->"
    marker_start = policy.index(marker)
    fence_start = policy.index("```json", marker_start) + len("```json")
    fence_end = policy.index("```", fence_start)
    return ci.strict_json_loads(
        policy[fence_start:fence_end], label=f"CI policy block {label}"
    )


def structured_identity(entry: dict) -> dict:
    known = ci._known_identity_expected(entry["testOrPathScope"])
    if known is not None:
        return known
    return {
        "scope": entry["testOrPathScope"],
        "structuredFailureSet": entry["allowedNormalizedSignature"][0],
    }


def source_command_id(entry: dict) -> str:
    return ci._baseline_source_command_id(entry) or "unit-test"


def synthetic_record_from_spec(spec: dict, *, passed: bool = True) -> dict:
    authority = copy.deepcopy(spec)
    record = {
        **authority,
        **ci.make_internal_result(
            spec["commandId"],
            spec["commandClass"],
            passed,
            "synthetic evidence fixture",
            required=spec["required"],
        ),
    }
    record["actualExecutionArgv"] = list(spec["executionArgv"])
    record["actualExecutionInputMode"] = spec["executionInputMode"]
    record["actualExecutionInputSize"] = spec["executionInputSize"]
    record["actualExecutionInputSha256"] = spec["executionInputSha256"]
    if spec["executionInputMode"] == "TARGET-BYTES-STDIN":
        target = spec["targets"][0]
        source_identity = {
            "pathStableIdentity": target["fileIdentity"],
            "heldStableIdentity": target["fileIdentity"],
            "canonicalPath": target["canonicalSourcePath"],
        }
        record["targetExecutionLease"] = {
            "leaseVersion": ci.TARGET_EXECUTION_LEASE_VERSION,
            "logicalTargetPath": target["path"],
            "canonicalSourcePath": target["canonicalSourcePath"],
            "plannedByteLength": target["size"],
            "plannedSha256": target["sha256"],
            "plannedStableFileIdentity": target["fileIdentity"],
            "modeType": target["modeType"],
            "reparsePoint": target["reparsePoint"],
            "executionAdapter": spec["executionInputMode"],
            "executedInputByteLength": target["size"],
            "executedInputSha256": target["sha256"],
            "preExecutionSourceIdentity": source_identity,
            "postExecutionSourceIdentity": source_identity,
            "mutationDetected": False,
            "cleanupState": "closed",
        }
        record["executionInputs"] = [
            {
                "logicalPath": target["path"],
                "canonicalSourcePath": target["canonicalSourcePath"],
                "plannedByteLength": target["size"],
                "plannedSha256": target["sha256"],
                "plannedStableIdentity": target["fileIdentity"],
                "actualByteLength": target["size"],
                "actualSha256": target["sha256"],
                "inputMode": spec["executionInputMode"],
            }
        ]
        record["executionInputBundleDigest"] = ci.execution_input_bundle_digest(
            record["executionInputs"]
        )
    elif spec["executionInputMode"] == "PROTECTED-TARGET-BUNDLE":
        inputs = []
        pre_identities = []
        post_identities = []
        for target in spec["targets"]:
            inputs.append(
                {
                    "logicalPath": target["path"],
                    "canonicalSourcePath": target["canonicalSourcePath"],
                    "plannedByteLength": target["size"],
                    "plannedSha256": target["sha256"],
                    "plannedStableIdentity": target["fileIdentity"],
                    "actualByteLength": target["size"],
                    "actualSha256": target["sha256"],
                    "inputMode": spec["executionInputMode"],
                }
            )
            identity = {
                "pathStableIdentity": target["fileIdentity"],
                "heldStableIdentity": target["fileIdentity"],
                "canonicalPath": target["canonicalSourcePath"],
            }
            pre_identities.append(identity)
            post_identities.append(copy.deepcopy(identity))
        bundle_digest = ci.execution_input_bundle_digest(inputs)
        record["executionInputs"] = inputs
        record["executionInputBundleDigest"] = bundle_digest
        record["protectedTargetBundle"] = {
            "bundleVersion": ci.PROTECTED_TARGET_BUNDLE_VERSION,
            "executionAdapter": spec["executionInputMode"],
            "orderedLogicalTargetPaths": [target["path"] for target in spec["targets"]],
            "canonicalSourcePaths": [
                target["canonicalSourcePath"] for target in spec["targets"]
            ],
            "plannedByteLengths": [target["size"] for target in spec["targets"]],
            "plannedSha256Values": [target["sha256"] for target in spec["targets"]],
            "plannedStableIdentities": [
                target["fileIdentity"] for target in spec["targets"]
            ],
            "executionInputs": copy.deepcopy(inputs),
            "executionInputBundleDigest": bundle_digest,
            "preExecutionIdentities": pre_identities,
            "postExecutionIdentities": post_identities,
            "mutationDetected": False,
            "cleanupState": "closed",
        }
    return record


def bind_fixture_observations(
    records: list[dict], observations: list[dict]
) -> list[dict]:
    by_id = {record["commandId"]: record for record in records}
    bound: list[dict] = []
    for item in copy.deepcopy(observations):
        source = by_id[item["commandId"]]
        raw = copy.deepcopy(item["rawObservation"])
        raw["commandId"] = source["commandId"]
        raw["commandOrdinal"] = source["ordinal"]
        raw["sourceOutputDigest"] = ci.command_output_digest(source)
        raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in raw.items() if key != "producerRecordDigest"}
        )
        derived = ci._rederive_observation_record({"rawObservation": raw}, source)
        source["producerObservations"].append(raw)
        source["producerObservationSetDigest"] = ci.producer_observation_set_digest(
            source["producerObservations"]
        )
        bound.append(derived)
    return bound


FROZEN_V1_RELEASE_SKIP_DETAILS = {
    "Release ZIP 运行时内容守卫": {
        "reason": "dist 目录缺失，跳过已生成 zip 内容检查",
        "skipped": True,
    },
    "PDF 对账与回归审计": {
        "invalidStatusRows": [],
        "missingEvidenceForVerified": [],
        "monaAnswerMismatches": [],
        "monaBannedPatternHits": [],
        "monaCoverageOk": True,
        "onlyInChecklist": [],
        "onlyInMapping": [],
        "reason": "missing_checklist:<repo>/checklist.md",
        "status": "skipped",
    },
    "Checklist 对账一致性校验": {
        "claimMismatches": [],
        "claims": {},
        "freshnessMismatches": [],
        "issueStatusCount": {
            "已修复待验证": 0,
            "已验证通过": 0,
            "待修复": 0,
        },
        "reason": "missing_checklist:<repo>/checklist.md",
        "reportFreshness": {},
        "status": "skipped",
        "summaryMismatches": [],
        "summaryStatusCount": {},
    },
}


def frozen_v1_release_skip_raw_observation(
    entry: dict,
    *,
    command_ordinal: int = 4,
    observation_ordinal: int = 0,
) -> dict:
    name = entry["testOrPathScope"].removeprefix("result:")
    detail = copy.deepcopy(FROZEN_V1_RELEASE_SKIP_DETAILS[name])
    result = {"name": name, "status": "pass", "detail": detail}
    return ci.make_raw_observation(
        "static-suite",
        command_ordinal,
        observation_ordinal,
        "static-producer-v1",
        name,
        ci.STATIC_SUITE_RELATIVE_PATH,
        result,
        ci.canonical_failure_digest(result),
    )


def exact_static_observation(entry: dict) -> dict:
    name = entry["testOrPathScope"].removeprefix("result:")
    if name == "Listening generated 索引结构":
        passed, detail = static_suite._check_listening_generated_assets(
            ci.REPO_ROOT / "assets/generated/listening-exams/listening-index.compat.js",
            ci.REPO_ROOT / "assets/generated/listening-exams/manifest.js",
        )
    elif name == "Release ZIP 运行时内容守卫":
        passed, detail = static_suite._check_release_zip_runtime_payload()
    elif name in FROZEN_V1_RELEASE_SKIP_DETAILS:
        passed = True
        detail = copy.deepcopy(FROZEN_V1_RELEASE_SKIP_DETAILS[name])
    else:
        raise AssertionError(f"no exact static producer fixture is defined for {name}")
    result = {"name": name, "status": "pass" if passed else "fail", "detail": detail}
    scope = entry["testOrPathScope"]
    outcome = "skip" if passed and ci.nested_skip(detail) else "pass" if passed else "fail"
    identity = ci.structured_failure_identity(scope, detail)
    signature = "pass" if outcome == "pass" else ci.static_failure_signature(scope, detail, identity)
    if outcome != "pass":
        if signature not in entry["allowedNormalizedSignature"]:
            raise AssertionError(f"static producer fixture drifted for {entry['id']}: {signature}")
    raw = ci.make_raw_observation(
        "static-suite",
        0,
        0,
        "static-producer-v1",
        name,
        ci.STATIC_SUITE_RELATIVE_PATH,
        result,
        ci.canonical_failure_digest(result),
    )
    return ci.observation(
        entry["commandClass"],
        scope,
        outcome,
        signature,
        "static-suite",
        raw_observation=raw,
    )


def one_entry_baseline(baseline: dict, collection: str, entry: dict) -> dict:
    selected = copy.deepcopy(baseline)
    selected["knownDebts"] = [entry] if collection == "knownDebts" else []
    selected["expectedOmissions"] = [entry] if collection == "expectedOmissions" else []
    selected["releaseOnlySkips"] = [entry] if collection == "releaseOnlySkips" else []
    return selected


def minimal_static_evidence_fixture(
    item: dict,
    *,
    platform_name: str,
) -> tuple[dict, dict, dict]:
    executable_size, executable_hash, executable_identity = ci._measured_file_authority(
        Path(sys.executable)
    )
    logical_argv = [sys.executable, "-B", ci.STATIC_SUITE_RELATIVE_PATH]
    spec = {
        "commandId": "static-suite",
        "ordinal": 0,
        "commandClass": "static-suite",
        "commandRole": "observation-producing",
        "required": True,
        "profile": "static",
        "platform": platform_name,
        "argv": logical_argv,
        "logicalArgv": logical_argv,
        "executionArgv": logical_argv,
        "executionInputMode": "NONE",
        "executionInputSize": None,
        "executionInputSha256": None,
        "cwd": ".",
        "toolRole": "python-static-producer",
        "resolvedExecutablePath": str(Path(sys.executable).resolve(strict=True)),
        "resolvedExecutableSize": executable_size,
        "resolvedExecutableSha256": executable_hash,
        "resolvedExecutableFileIdentity": executable_identity,
        "executionLease": None,
        "targets": [ci._target_authority(ci.REPO_ROOT, ci.STATIC_SUITE_RELATIVE_PATH)],
        "resultSemantics": "machine-v2-complete-execution",
        "allowedExecutionExits": [0],
    }
    record = synthetic_record_from_spec(spec)
    bound = bind_fixture_observations([record], [item])[0]
    runner = SimpleNamespace(
        command_plan=[spec],
        command_results=[record],
        observations=[bound],
        completed_classes=set(),
    )
    ci.finalize_evidence_transcript(runner)
    return spec, runner.command_results[0], runner.observations[0]


def ci9_static_evidence_fixture(
    items: list[dict],
    *,
    platform_name: str = "windows",
) -> tuple[dict, dict, list[dict]]:
    executable_size, executable_hash, executable_identity = ci._measured_file_authority(
        Path(sys.executable)
    )
    logical_argv = [
        sys.executable,
        "-B",
        ci.STATIC_SUITE_RELATIVE_PATH,
        "--ci-machine-json-stdout",
        "--ci-invocation-id",
        "ci9-fixed-invocation",
    ]
    spec = {
        "commandId": "static-suite",
        "ordinal": 4,
        "commandClass": "static-suite",
        "commandRole": "observation-producing",
        "required": True,
        "profile": "static",
        "platform": platform_name,
        "argv": logical_argv,
        "logicalArgv": logical_argv,
        "executionArgv": logical_argv,
        "executionInputMode": "PROTECTED-TARGET-BUNDLE",
        "executionInputSize": None,
        "executionInputSha256": None,
        "cwd": ".",
        "toolRole": "python-static-producer",
        "resolvedExecutablePath": str(Path(sys.executable).resolve(strict=True)),
        "resolvedExecutableSize": executable_size,
        "resolvedExecutableSha256": executable_hash,
        "resolvedExecutableFileIdentity": executable_identity,
        "executionLease": None,
        "targets": [ci._target_authority(ci.REPO_ROOT, ci.STATIC_SUITE_RELATIVE_PATH)],
        "resultSemantics": "machine-v2-complete-execution",
        "allowedExecutionExits": [0],
    }
    record = synthetic_record_from_spec(spec)
    bound = bind_fixture_observations([record], items)
    runner = SimpleNamespace(
        command_plan=[spec],
        command_results=[record],
        observations=bound,
        completed_classes={"static-suite"},
    )
    ci.finalize_evidence_transcript(runner)
    return spec, runner.command_results[0], runner.observations


def synthetic_execution_binding(
    profile: str,
    plan_digest: str,
    *,
    platform_name: str = "windows",
) -> dict:
    return {
        "bindingSchemaVersion": ci.EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
        "bindingKind": "ProducerExecutionBinding",
        "bindingMode": "local",
        "producerJobId": "local-producer",
        "producerRunnerOS": "Windows" if platform_name == "windows" else "Linux",
        "producerProfile": profile,
        "runId": "local",
        "runAttempt": "1",
        "eventName": "local",
        "repository": "local-root-sha256:" + "1" * 64,
        "checkoutCommit": ci.BASELINE_COMMIT,
        "checkoutTree": ci.BASELINE_TREE,
        "baselineCommit": ci.BASELINE_COMMIT,
        "baselineTree": ci.BASELINE_TREE,
        "trustFileDigest": "2" * 64,
        "commandPlanDigest": plan_digest,
        "producerInvocationId": "3" * 64,
    }


def synthetic_external_context(binding: dict) -> ci.ExternallyExpectedVerificationContext:
    authority = ci._workflow_authority_for_producer(binding["producerJobId"])
    verifier_job_id = (
        str(authority["verifierJobId"])
        if binding["bindingMode"] == "github-actions" and authority is not None
        else "local-verifier"
    )
    return ci.ExternallyExpectedVerificationContext(
        binding_mode=binding["bindingMode"],
        expected_profile=binding["producerProfile"],
        producer_job_id=binding["producerJobId"],
        verifier_job_id=verifier_job_id,
        runner_os=binding["producerRunnerOS"],
        run_id=binding["runId"],
        run_attempt=binding["runAttempt"],
        event_name=binding["eventName"],
        repository=binding["repository"],
        checkout_commit=binding["checkoutCommit"],
        checkout_tree=binding["checkoutTree"],
        baseline_commit=binding["baselineCommit"],
        baseline_tree=binding["baselineTree"],
        trust_file_digest=binding["trustFileDigest"],
        command_plan_digest=binding["commandPlanDigest"],
        producer_invocation_id=binding["producerInvocationId"],
        fresh_runtime_closure_digest="4" * 64,
        verifier_invocation_id="5" * 64,
    )


def fake_runner(baseline: dict) -> SimpleNamespace:
    command_plan = ci.expected_command_authority("policy", baseline=baseline)
    runner = SimpleNamespace(
        profile="policy",
        platform="windows",
        violations=[],
        hard_gate_results=[],
        baseline=baseline,
        runtime={
            "platform": "windows",
            "os": "test",
            "python": "3.12.0",
            "pythonImplementation": "CPython",
            "node": "v24.0.0",
            "npm": "11.0.0",
            "runtimeClosureDigest": "4" * 64,
            "dependencyClosureDigest": "6" * 64,
            "dependencyMemberCount": "0",
        },
        command_results=[],
        observations=[],
        completed_classes=set(),
        command_plan=command_plan,
        command_plan_digest=ci.command_plan_digest(command_plan),
    )
    runner.command_results = [synthetic_record_from_spec(spec) for spec in command_plan]
    runner.execution_binding = synthetic_execution_binding(
        runner.profile,
        runner.command_plan_digest,
        platform_name=runner.platform,
    )
    return runner


def empty_comparison() -> dict[str, list]:
    return {
        "observedDebts": [],
        "resolvedCandidates": [],
        "expectedOmissions": [],
        "releaseOnlySkips": [],
        "violations": [],
    }


def synthetic_command_spec(
    command_id: str,
    command_class: str,
    ordinal: int,
    *,
    command_role: str = "required-execution",
    allowed_exits: list[int] | None = None,
    targets: list[dict] | None = None,
    execution_input_mode: str = "NONE",
) -> dict:
    executable_size, executable_hash, executable_identity = ci._measured_file_authority(
        Path(sys.executable)
    )
    argv = [sys.executable, "<internal>", command_id]
    selected_targets = copy.deepcopy(targets or [])
    singular_target = (
        selected_targets[0]
        if execution_input_mode == "TARGET-BYTES-STDIN" and len(selected_targets) == 1
        else None
    )
    return {
        "commandId": command_id,
        "ordinal": ordinal,
        "commandClass": command_class,
        "commandRole": command_role,
        "required": True,
        "profile": "static",
        "platform": ci.platform_key(),
        "argv": argv,
        "logicalArgv": argv,
        "executionArgv": argv,
        "executionInputMode": execution_input_mode,
        "executionInputSize": singular_target["size"] if singular_target else None,
        "executionInputSha256": singular_target["sha256"] if singular_target else None,
        "cwd": ".",
        "toolRole": "python-in-process",
        "resolvedExecutablePath": str(Path(sys.executable).resolve(strict=True)),
        "resolvedExecutableSize": executable_size,
        "resolvedExecutableSha256": executable_hash,
        "resolvedExecutableFileIdentity": executable_identity,
        "executionLease": None,
        "targets": selected_targets,
        "resultSemantics": "synthetic-replay-fixture",
        "allowedExecutionExits": sorted(set(allowed_exits or [0])),
    }


def compact_policy_fixture_plan() -> list[dict]:
    plan = [
        synthetic_command_spec("fixture-baseline", "baseline-policy", 0),
        synthetic_command_spec("fixture-boundary", "repository-boundary", 1),
        synthetic_command_spec("fixture-workflow", "workflow-policy", 2),
    ]
    for spec in plan:
        spec["profile"] = "policy"
    return plan


def sixth_review_replay_fixture() -> tuple[SimpleNamespace, dict, dict]:
    specs = [
        synthetic_command_spec("baseline-schema", "baseline-policy", 0),
        synthetic_command_spec(
            "static-suite",
            "static-suite",
            1,
            command_role="observation-producing",
        ),
    ]
    specs.extend(
        synthetic_command_spec(
            f"node-check:fixture-{index}.js",
            "direct-syntax",
            index + 2,
            command_role="observation-producing",
            allowed_exits=[0, 1],
        )
        for index in range(4)
    )
    records = [
        synthetic_record_from_spec(spec, passed=index < 2)
        for index, spec in enumerate(specs)
    ]
    observations: list[dict] = []
    static_record = records[1]
    static_output_digest = ci.command_output_digest(static_record)
    for observation_ordinal in range(783):
        scope = f"result:replay-fixture-{observation_ordinal:03d}"
        raw = ci.make_raw_observation(
            "static-suite",
            1,
            observation_ordinal,
            "normalized-fields-v1",
            scope,
            ci.STATIC_SUITE_RELATIVE_PATH,
            {"scope": scope, "outcome": "pass"},
            static_output_digest,
        )
        static_record["producerObservations"].append(raw)
        observations.append({"commandId": "static-suite", "rawObservation": raw})
    for index, record in enumerate(records[2:]):
        command_id = record["commandId"]
        scope = f"fixture-{index}.js"
        raw = ci.make_raw_observation(
            command_id,
            index + 2,
            0,
            "process-output-v1",
            scope,
            scope,
            {
                "executed": True,
                "exitCode": 1,
                "stdout": "",
                "stderr": "SyntaxError: replay fixture",
                "error": None,
            },
            ci.command_output_digest(record),
        )
        record["producerObservations"].append(raw)
        observations.append({"commandId": command_id, "rawObservation": raw})
    runner = SimpleNamespace(
        profile="static",
        command_plan=specs,
        command_results=records,
        observations=observations,
        completed_classes=set(),
        hard_gate_results=[],
        violations=[],
    )
    ci.finalize_evidence_transcript(runner)
    runner.execution_binding = synthetic_execution_binding(
        runner.profile,
        runner.command_plan_digest,
    )
    runner.runtime_closure_digest = "4" * 64
    runner.dependency_closure_digest = "6" * 64
    runner.dependency_member_count = 0
    runner.verifier_execution_binding = synthetic_external_context(
        runner.execution_binding
    ).verifier_binding()
    comparison = empty_comparison()
    transcript = ci.verification_replay_transcript(runner)
    commands = {
        "executionBinding": copy.deepcopy(runner.execution_binding),
        "executionBindingDigest": ci.execution_binding_digest(
            runner.execution_binding
        ),
        "authorizationContextBinding": copy.deepcopy(
            runner.authorization_context_binding
        ),
        "authorizationContextBindingDigest": (
            runner.authorization_context_binding_digest
        ),
        "commandAuthority": copy.deepcopy(runner.command_plan),
        "commandPlanDigest": transcript["commandPlanDigest"],
        "commandCount": transcript["commandCount"],
        "records": copy.deepcopy(runner.command_results),
        "observations": copy.deepcopy(runner.observations),
        "completedCommandClasses": copy.deepcopy(
            transcript["actualCompletedCommandClasses"]
        ),
        **{
            key: copy.deepcopy(transcript[key])
            for key in (
                "expectedCompletedCommandClasses",
                "actualCompletedCommandClasses",
                "expectedCompletedCommandClassSetDigest",
                "completedCommandClassSetDigest",
                "producerObservationCount",
                "producerObservationUniverseDigest",
                "producerTranscriptDigest",
                "missingCommandIds",
                "extraCommandIds",
                "duplicateCommandIds",
            )
        },
    }
    summary = {
        "status": "PASS",
        "profile": "static",
        "executionBinding": copy.deepcopy(runner.execution_binding),
        "executionBindingDigest": ci.execution_binding_digest(
            runner.execution_binding
        ),
        "authorizationContextBinding": copy.deepcopy(
            runner.authorization_context_binding
        ),
        "authorizationContextBindingDigest": (
            runner.authorization_context_binding_digest
        ),
        "knownDebtsObserved": [],
        "resolvedCandidates": [],
        "expectedOmissions": [],
        "releaseOnlySkips": [],
    }
    return runner, {"summary.json": summary, "command-results.json": commands}, comparison


def coherently_rebind_claimed_transcript(documents: dict) -> None:
    commands = documents["command-results.json"]
    records = commands["records"]
    for record in records:
        producer = record.get("producerObservations", [])
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest(producer)
        record["completedCommandClass"] = (
            record.get("commandClass") if ci._command_completed_for_class(record) else None
        )
    commands["commandCount"] = len(records)
    commands["commandPlanDigest"] = ci.command_plan_digest(commands["commandAuthority"])
    expected = ci.expected_completed_command_classes(commands["commandAuthority"])
    actual = ci.actual_completed_command_classes(commands["commandAuthority"], records)
    commands["expectedCompletedCommandClasses"] = expected
    commands["actualCompletedCommandClasses"] = actual
    commands["completedCommandClasses"] = actual
    commands["expectedCompletedCommandClassSetDigest"] = (
        ci.completed_command_class_set_digest(expected)
    )
    commands["completedCommandClassSetDigest"] = ci.completed_command_class_set_digest(actual)
    commands["producerObservationCount"] = sum(
        len(record.get("producerObservations", [])) for record in records
    )
    commands["producerObservationUniverseDigest"] = (
        ci.producer_observation_universe_digest(records)
    )
    commands["producerTranscriptDigest"] = ci.producer_transcript_digest(
        commands["commandPlanDigest"], records, actual
    )
    missing, extra, duplicate = ci.command_id_set_differences(
        commands["commandAuthority"], records
    )
    commands["missingCommandIds"] = missing
    commands["extraCommandIds"] = extra
    commands["duplicateCommandIds"] = duplicate
    context = {
        "producerObservationUniverseDigest": commands[
            "producerObservationUniverseDigest"
        ],
        "producerTranscriptDigest": commands["producerTranscriptDigest"],
        "profileCompletedCommandClassSetDigest": commands[
            "completedCommandClassSetDigest"
        ],
        "authorizationContextBindingDigest": commands.get(
            "authorizationContextBindingDigest"
        ),
    }
    by_id = {record["commandId"]: record for record in records}
    rebound = []
    for record in records:
        for raw in record.get("producerObservations", []):
            rebound.append(
                ci._rederive_observation_record(
                    {"commandId": record["commandId"], "rawObservation": raw},
                    by_id[record["commandId"]],
                    profile_context=context,
                )
            )
    commands["observations"] = rebound


def contained_capture(
    *,
    exit_code: int = 0,
    timed_out: bool = False,
    output_limited: bool = False,
    process_tree_status: str = "contained-clean",
) -> ci.CommandCapture:
    return ci.CommandCapture(
        command_id="static-suite",
        command_class="static-suite",
        argv=[sys.executable],
        executed=True,
        exit_code=exit_code,
        duration_seconds=0.01,
        stdout="",
        stderr="",
        timed_out=timed_out,
        output_limited=output_limited,
        containment=(
            "windows-job-object"
            if os.name == "nt"
            else "linux-subreaper-pidfd-proc-supervisor"
        ),
        process_tree_status=process_tree_status,
        process_tree_error="synthetic cleanup failure" if process_tree_status == "cleanup-failed" else None,
    )


class BaselineSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)

    def test_ratified_baseline_schema_and_counts_are_exact(self) -> None:
        self.assertEqual(ci.validate_baseline_document(self.baseline), [])
        counts: dict[str, int] = {}
        for entry in self.baseline["knownDebts"]:
            counts[entry["category"]] = counts.get(entry["category"], 0) + 1
        self.assertEqual(
            counts,
            {
                "product-or-packaging": 4,
                "validation-infrastructure": 14,
                "accepted-checkpoint-nonblocking": 3,
            },
        )
        self.assertEqual(len(self.baseline["expectedOmissions"]), 2)
        self.assertEqual(len(self.baseline["releaseOnlySkips"]), 3)

    def test_unrestricted_signature_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.baseline)
        candidate["knownDebts"][0]["allowedNormalizedSignature"] = [".*"]
        errors = ci.validate_baseline_document(candidate)
        self.assertTrue(any("unrestricted" in error for error in errors), errors)

    def test_duplicate_debt_id_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.baseline)
        candidate["knownDebts"][1]["id"] = candidate["knownDebts"][0]["id"]
        errors = ci.validate_baseline_document(candidate)
        self.assertTrue(any("globally unique" in error for error in errors), errors)

    def test_changed_action_pin_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.baseline)
        candidate["approvedActions"]["actions/checkout"]["sha"] = "0" * 40
        errors = ci.validate_baseline_document(candidate)
        self.assertTrue(any("action pins" in error for error in errors), errors)

    def assert_baseline_mutation_rejected(self, mutate) -> None:
        candidate = copy.deepcopy(self.baseline)
        mutate(candidate)
        self.assertTrue(ci.validate_baseline_document(candidate))

    def test_collection_movement_is_rejected(self) -> None:
        def mutate(candidate: dict) -> None:
            candidate["expectedOmissions"].append(candidate["knownDebts"].pop(0))

        self.assert_baseline_mutation_rejected(mutate)

    def test_category_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["knownDebts"][0].__setitem__("category", "validation-infrastructure")
        )

    def test_outcome_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["knownDebts"][0].__setitem__("expectedOutcome", "skip")
        )

    def test_scope_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["knownDebts"][0].__setitem__("testOrPathScope", "result:other")
        )

    def test_platform_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["knownDebts"][0].__setitem__("platforms", ["windows"])
        )

    def test_occurrence_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["knownDebts"][0].__setitem__("maximumOccurrences", 2)
        )

    def test_policy_version_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate.__setitem__("policyVersion", "1.0.1")
        )

    def test_ratified_count_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate["ratifiedCounts"].__setitem__("productOrPackagingObligations", 5)
        )

    def test_extra_baseline_entry_is_rejected(self) -> None:
        def mutate(candidate: dict) -> None:
            extra = copy.deepcopy(candidate["knownDebts"][0])
            extra["id"] = "UNAPPROVED-EXTRA"
            candidate["knownDebts"].append(extra)

        self.assert_baseline_mutation_rejected(mutate)

    def test_missing_baseline_entry_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(lambda candidate: candidate["knownDebts"].pop())

    def test_release_skip_cannot_move_into_backend_security_gate(self) -> None:
        def mutate(candidate: dict) -> None:
            entry = candidate["releaseOnlySkips"].pop(0)
            entry.update(
                {
                    "category": "accepted-checkpoint-nonblocking",
                    "gate": "BACKEND-CANONICAL-EXECUTION",
                    "commandClass": "backend-canonical",
                    "testOrPathScope": "command:npm --prefix backend test",
                    "expectedOutcome": "fail",
                }
            )
            candidate["knownDebts"].append(entry)

        self.assert_baseline_mutation_rejected(mutate)

    def test_unknown_top_level_field_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(
            lambda candidate: candidate.__setitem__("waiveHardGate", True)
        )

    def test_hard_gate_set_change_is_rejected(self) -> None:
        self.assert_baseline_mutation_rejected(lambda candidate: candidate["hardGates"].pop())


class StrictJsonLoaderTest(unittest.TestCase):
    def test_duplicate_key_matrix_is_rejected_during_parsing(self) -> None:
        fixtures = {
            "summary-pass-then-fail": '{"status":"PASS","status":"FAIL"}',
            "summary-fail-then-pass": '{"status":"FAIL","status":"PASS"}',
            "nested-exit-code": '{"command":{"exitCode":0,"exitCode":1}}',
            "nested-executed": '{"command":{"executed":true,"executed":false}}',
            "baseline-id": '{"knownDebts":[{"id":"A","id":"B"}]}',
            "manifest-hash": '{"manifest":{"sha256":"a","sha256":"b"}}',
            "resolved-scope": '{"resolved":{"scope":"a","scope":"b"}}',
            "identical-values": '{"required":true,"required":true}',
            "deeply-nested": '{"a":[{"b":{"c":1,"c":1}}]}',
            "escaped-equivalent": '{"status":"PASS","st\\u0061tus":"FAIL"}',
            "permissions-like": '{"permissions":"read","per\\u006dissions":"write"}',
            "coherent-manifest": (
                '{"relativeFilename":"summary.md","byteLength":1,'
                '"sha256":"a","sha256":"a","documentKind":"fixture"}'
            ),
        }
        for name, source in fixtures.items():
            with self.subTest(name=name), self.assertRaises(ci.DuplicateJsonKeyError):
                ci.strict_json_loads(source, label=name)

    def test_strict_number_matrix_is_rejected(self) -> None:
        for source in ("NaN", "Infinity", "-Infinity", "1e1000000"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                ci.strict_json_loads(source)

    def test_security_critical_sources_have_one_raw_json_loader(self) -> None:
        violations: list[str] = []
        paths = (
            ci.REPO_ROOT / "developer" / "tests" / "ci" / "run_ci_foundation.py",
            ci.REPO_ROOT / "developer" / "tests" / "ci" / "run_static_suite.py",
            ci.REPO_ROOT / "developer" / "tests" / "ci" / "test_ci_foundation.py",
        )
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

            class Visitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.functions: list[str] = []

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    self.functions.append(node.name)
                    self.generic_visit(node)
                    self.functions.pop()

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_Call(self, node: ast.Call) -> None:
                    function = node.func
                    if (
                        isinstance(function, ast.Attribute)
                        and isinstance(function.value, ast.Name)
                        and function.value.id == "json"
                        and function.attr in {"load", "loads"}
                        and self.functions != ["strict_json_loads"]
                    ):
                        violations.append(f"{path.name}:{node.lineno}:{function.attr}")
                    self.generic_visit(node)

            Visitor().visit(tree)
        self.assertEqual(violations, [])


class ComparisonPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.full_baseline = ci.strict_json_load_file(ci.BASELINE_PATH)

    def baseline_with_one_known_debt(self) -> dict:
        baseline = copy.deepcopy(self.full_baseline)
        baseline["knownDebts"] = [
            next(
                entry
                for entry in baseline["knownDebts"]
                if entry["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
            )
        ]
        baseline["expectedOmissions"] = []
        baseline["releaseOnlySkips"] = []
        return baseline

    def baseline_with_known_id(self, entry_id: str) -> tuple[dict, dict]:
        baseline = copy.deepcopy(self.full_baseline)
        entry = next(item for item in baseline["knownDebts"] if item["id"] == entry_id)
        baseline["knownDebts"] = [entry]
        baseline["expectedOmissions"] = []
        baseline["releaseOnlySkips"] = []
        return baseline, entry

    def test_exact_known_debt_is_allowed(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        observed = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            entry["allowedNormalizedSignature"][0],
            f"node-check:{entry['testOrPathScope']}",
            failure_identity=structured_identity(entry),
        )
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual([item["id"] for item in result["observedDebts"]], [entry["id"]])

    def test_changed_signature_fails_closed(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        observed = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            "sha256:" + "0" * 64,
            "unit-test",
        )
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_expanded_occurrence_count_fails_closed(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        observed = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            entry["allowedNormalizedSignature"][0],
            source_command_id(entry),
            occurrences=entry["maximumOccurrences"] + 1,
            failure_identity=structured_identity(entry),
        )
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        self.assertIn("BASELINE-OCCURRENCE-LIMIT", [item["id"] for item in result["violations"]])

    def test_passing_known_scope_is_resolved_candidate(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        observed = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            "pass",
            "pass",
            source_command_id(entry),
            failure_identity=structured_identity(entry),
        )
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["resolvedCandidates"][0]["status"], "RESOLVED-CANDIDATE")

    def test_missing_known_scope_is_not_mistaken_for_resolution(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        result = ci.compare_observations(
            baseline,
            [],
            {entry["commandClass"]},
            "windows",
        )
        self.assertIn("KNOWN-SCOPE-NOT-OBSERVED", [item["id"] for item in result["violations"]])

    def test_expected_omission_is_classified_separately(self) -> None:
        baseline = copy.deepcopy(self.full_baseline)
        entry = baseline["expectedOmissions"][0]
        baseline["knownDebts"] = []
        baseline["expectedOmissions"] = [entry]
        baseline["releaseOnlySkips"] = []
        observed = exact_static_observation(entry)
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "ubuntu",
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual([item["id"] for item in result["expectedOmissions"]], [entry["id"]])

    def test_release_only_skip_is_visible_outside_and_blocking_inside_release_gate(self) -> None:
        baseline = copy.deepcopy(self.full_baseline)
        entry = baseline["releaseOnlySkips"][0]
        baseline["knownDebts"] = []
        baseline["expectedOmissions"] = []
        baseline["releaseOnlySkips"] = [entry]
        observed = exact_static_observation(entry)
        outside = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        inside = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
            release_gate_required=True,
        )
        self.assertEqual(outside["violations"], [])
        self.assertEqual([item["id"] for item in outside["releaseOnlySkips"]], [entry["id"]])
        self.assertEqual([item["id"] for item in inside["releaseOnlySkips"]], [entry["id"]])
        self.assertIn(
            "RELEASE-ONLY-SKIP-IN-REQUIRED-GATE",
            [item["id"] for item in inside["violations"]],
        )

    def test_must_execute_debt_does_not_waive_current_unavailability(self) -> None:
        baseline = copy.deepcopy(self.full_baseline)
        entry = next(item for item in baseline["knownDebts"] if item["id"].startswith("F-WINDOWS"))
        baseline["knownDebts"] = [entry]
        baseline["expectedOmissions"] = []
        baseline["releaseOnlySkips"] = []
        raw = ci.make_raw_observation(
            "backend-canonical",
            0,
            0,
            "process-output-v1",
            entry["testOrPathScope"],
            "backend/package.json",
            {
                "executed": False,
                "exitCode": None,
                "stdout": "",
                "stderr": "",
                "error": "required executable not found: npm",
            },
            ci.canonical_failure_digest({"stdout": "", "stderr": ""}),
        )
        observed = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            "unavailable",
            entry["allowedNormalizedSignature"][0],
            "backend-canonical",
            raw_observation=raw,
        )
        result = ci.compare_observations(
            baseline,
            [observed],
            {entry["commandClass"]},
            "windows",
        )
        self.assertIn("REQUIRED-COMMAND-UNAVAILABLE", [item["id"] for item in result["violations"]])

    def test_two_individually_matching_observations_exceed_one_occurrence(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        entry = baseline["knownDebts"][0]
        observations = [
            ci.observation(
                entry["commandClass"],
                entry["testOrPathScope"],
                entry["expectedOutcome"],
                entry["allowedNormalizedSignature"][0],
                source_command_id(entry),
                failure_identity=structured_identity(entry),
            )
            for index in range(2)
        ]
        result = ci.compare_observations(baseline, observations, {entry["commandClass"]}, "windows")
        self.assertIn("BASELINE-OCCURRENCE-LIMIT", [item["id"] for item in result["violations"]])

    def test_known_assertion_plus_unrelated_assertion_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("E-ADMIN-FRONTEND-DOM-STUB")
        identity = copy.deepcopy(ci._known_identity_expected(entry["testOrPathScope"]))
        identity["assertionNames"].append("unrelated authorization assertion")
        identity["errorClasses"].append("AssertionError")
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            entry["allowedNormalizedSignature"][0], source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_known_message_plus_second_failing_test_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("E-REMOTE-PRACTICE-DISABLE-TOTP-TEST-DRIFT")
        identity = copy.deepcopy(ci._known_identity_expected(entry["testOrPathScope"]))
        identity["testIds"].append("developer/tests/js/unrelatedSecurity.test.js")
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            entry["allowedNormalizedSignature"][0], source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_same_signature_from_wrong_path_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("E-ADMIN-FRONTEND-DOM-STUB")
        identity = copy.deepcopy(ci._known_identity_expected(entry["testOrPathScope"]))
        identity["fileLocations"] = ["developer/tests/js/unrelated.test.js:83:44"]
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            entry["allowedNormalizedSignature"][0], source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_known_scope_with_changed_line_identity_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("B-SYNTAX-PERFORMANCE-BASELINE")
        identity = copy.deepcopy(ci._known_identity_expected(entry["testOrPathScope"]))
        identity["fileLocations"] = [entry["testOrPathScope"] + ":427"]
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "syntax-error",
            entry["allowedNormalizedSignature"][0], source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_exact_complete_node_failure_identity_is_accepted(self) -> None:
        baseline, entry = self.baseline_with_known_id("E-ADMIN-FRONTEND-DOM-STUB")
        identity = ci._known_identity_expected(entry["testOrPathScope"])
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            entry["allowedNormalizedSignature"][0], source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["observedDebts"][0]["id"], entry["id"])

    def static_session_detail(self, suffix: str = "") -> str:
        assertion = "sessionId 不一致时仍应路由模拟导航"
        test_path = "developer/tests/js/suiteModeRegression.test.js"
        inner = {
            "status": "fail",
            "detail": (
                f"AssertionError [ERR_ASSERTION]: {assertion}\n\n"
                f"0 !== 1\n\n    at run (file:///{ci.REPO_ROOT.as_posix()}/{test_path}:667:16)"
            ),
        }
        return (
            "执行失败: "
            + json.dumps(inner, ensure_ascii=False, separators=(",", ":"))
            + f"Command ['node', {str(ci.REPO_ROOT / test_path)!r}] returned non-zero exit status 1."
            + suffix
        )

    def test_exact_static_session_failure_identity_is_accepted(self) -> None:
        baseline, entry = self.baseline_with_known_id("B-STATIC-SUITE-SESSION-ROUTING")
        detail = self.static_session_detail()
        identity = ci.structured_failure_identity(entry["testOrPathScope"], detail)
        signature = ci.static_failure_signature(entry["testOrPathScope"], detail, identity)
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            signature, source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["observedDebts"][0]["id"], entry["id"])

    def test_static_session_failure_plus_extra_assertion_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("B-STATIC-SUITE-SESSION-ROUTING")
        detail = self.static_session_detail("\nAssertionError: unrelated authorization assertion")
        identity = ci.structured_failure_identity(entry["testOrPathScope"], detail)
        signature = ci.static_failure_signature(entry["testOrPathScope"], detail, identity)
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            signature, source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])

    def test_unknown_failure_remains_hard_failure(self) -> None:
        baseline = self.baseline_with_one_known_debt()
        observed = ci.observation(
            "unapproved-command", "file:other.js", "fail", "sha256:" + "9" * 64,
            "unit", failure_identity={"scope": "file:other.js", "structuredFailureSet": "sha256:" + "9" * 64},
        )
        result = ci.compare_observations(baseline, [observed], {"unapproved-command"}, "windows")
        self.assertIn("UNKNOWN-NONPASS", [item["id"] for item in result["violations"]])


class AuthoritativeEvidenceDerivationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls._expected_command_authority = ci.expected_command_authority
        source_classes = {
            source_command_id(entry): entry["commandClass"]
            for collection in ("knownDebts", "expectedOmissions", "releaseOnlySkips")
            for entry in cls.baseline[collection]
            if source_command_id(entry)
        }
        ordered_sources = ["static-suite", *sorted(set(source_classes) - {"static-suite"})]
        cls.static_plan = [
            synthetic_command_spec(
                command_id,
                source_classes[command_id],
                ordinal,
                command_role="observation-producing",
                allowed_exits=[0, 1],
                targets=(
                    [ci._target_authority(ci.REPO_ROOT, ci.STATIC_SUITE_RELATIVE_PATH)]
                    if command_id == "static-suite"
                    else [
                        ci._target_authority(
                            ci.REPO_ROOT,
                            command_id.removeprefix("node-check:"),
                        )
                    ]
                    if command_id.startswith("node-check:")
                    else None
                ),
                execution_input_mode=(
                    "PROTECTED-TARGET-BUNDLE"
                    if command_id == "static-suite"
                    else "TARGET-BYTES-STDIN"
                    if command_id.startswith("node-check:")
                    else "NONE"
                ),
            )
            for ordinal, command_id in enumerate(ordered_sources)
        ]
        cls.static_record_template = [
            synthetic_record_from_spec(spec) for spec in cls.static_plan
        ]

        def cached_authority(profile: str, *args, **kwargs):
            if profile == "static" and kwargs.get("baseline") == cls.baseline:
                return copy.deepcopy(cls.static_plan)
            return cls._expected_command_authority(profile, *args, **kwargs)

        cls.authority_patcher = mock.patch.object(
            ci,
            "expected_command_authority",
            side_effect=cached_authority,
        )
        cls.authority_patcher.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.authority_patcher.stop()

    def observation_for_entry(self, entry: dict, *, outcome: str | None = None) -> dict:
        scope = entry["testOrPathScope"]
        command_class = entry["commandClass"]
        observed_outcome = entry["expectedOutcome"] if outcome is None else outcome
        if outcome is None and entry["id"] in {
            "B-STATIC-PRIVATE-LISTENING-INDEX-OMISSION",
            "B-SKIP-RELEASE-ZIP",
        }:
            return exact_static_observation(entry)
        if command_class == "direct-syntax":
            identity = ci._known_identity_expected(scope)
            command_id = f"node-check:{scope}"
        else:
            known = ci.KNOWN_STATIC_FAILURES.get(scope)
            identity = (
                {
                    "scope": scope,
                    **{key: value for key, value in known.items() if key != "signature"},
                }
                if known is not None
                else {
                    "scope": scope,
                    "structuredFailureSet": entry["allowedNormalizedSignature"][0],
                }
            )
            command_id = "static-suite"
        return ci.observation(
            command_class,
            scope,
            observed_outcome,
            "pass" if observed_outcome == "pass" else entry["allowedNormalizedSignature"][0],
            command_id,
            failure_identity=(
                {"scope": scope, "normalizedSignature": "pass"}
                if observed_outcome == "pass"
                else identity
            ),
            source_result_id=(
                scope if command_class == "direct-syntax" else scope.removeprefix("result:")
            ),
            source_path=(
                scope if command_class == "direct-syntax" else ci.STATIC_SUITE_RELATIVE_PATH
            ),
        )

    def build_runner(self, observations: list[dict], *, completed: set[str] | None = None) -> SimpleNamespace:
        runner = SimpleNamespace(
            profile="static",
            platform="windows",
            violations=[],
            hard_gate_results=[],
            baseline=self.baseline,
            runtime={
                "platform": "windows",
                "os": "test",
                "python": "3.12.0",
                "pythonImplementation": "CPython",
                "node": "v24.0.0",
                "npm": "11.0.0",
            },
            completed_classes=set(completed or set()),
            command_plan=copy.deepcopy(self.static_plan),
            observations=[],
        )
        runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
        runner.execution_binding = synthetic_execution_binding(
            runner.profile,
            runner.command_plan_digest,
            platform_name=runner.platform,
        )
        nonpass_sources = {
            item["commandId"]
            for item in observations
            if item["outcome"] not in {"pass", "skip"} and item["commandClass"] != "static-suite"
        }
        runner.command_results = copy.deepcopy(self.static_record_template)
        for record in runner.command_results:
            if record["commandId"] in nonpass_sources:
                record["exitCode"] = 1
                record["parsedFailureSummary"] = {
                    "status": "fail",
                    "diagnostic": "synthetic evidence fixture",
                }
        runner.observations = bind_fixture_observations(
            runner.command_results,
            observations,
        )
        return runner

    def create_evidence(
        self,
        repo: Path,
        observations: list[dict],
        *,
        completed: set[str] | None = None,
    ) -> tuple[Path, dict]:
        runner = self.build_runner(observations, completed=completed)
        output = repo / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=repo)
        with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
            summary = ci.write_evidence(runner, empty_comparison())
        return output, summary

    def rewrite_coherently(self, output: Path, mutate) -> None:
        summary = ci.strict_json_load_file(output / "summary.json")
        observed = ci.strict_json_load_file(output / "observed-debt.json")
        resolved = ci.strict_json_load_file(output / "resolved-candidates.json")
        commands = ci.strict_json_load_file(output / "command-results.json")
        mutate(summary, observed, resolved, commands)
        payloads = {
            "observed-debt.json": ci._json_bytes(observed),
            "resolved-candidates.json": ci._json_bytes(resolved),
            "command-results.json": ci._json_bytes(commands),
        }
        payloads["summary.md"] = ci.render_summary_markdown(summary).encode("utf-8")
        summary["evidenceManifest"] = [
            {
                "relativeFilename": name,
                "byteLength": len(payloads[name]),
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "documentKind": ci.EVIDENCE_DOCUMENT_KINDS[name],
            }
            for name in ci.EVIDENCE_MANIFEST_FILE_NAMES
        ]
        payloads["summary.json"] = ci._json_bytes(summary)
        for name, data in payloads.items():
            (output / name).write_bytes(data)

    def test_records_bind_every_frozen_baseline_semantic_field(self) -> None:
        entry = next(
            item for item in self.baseline["knownDebts"]
            if item["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )
        with tempfile.TemporaryDirectory(prefix="ci-derived-binding-") as temp_dir:
            repo = Path(temp_dir)
            _output, summary = self.create_evidence(repo, [self.observation_for_entry(entry)])
        record = summary["knownDebtsObserved"][0]
        for field_name in (
            "baselineId", "collection", "category", "gate", "commandClass",
            "testOrPathScope", "expectedOutcome", "allowedNormalizedSignature",
            "maximumOccurrences", "platforms", "checkpointDisposition", "targetStage",
            "securityImpact", "sourceCommandId",
        ):
            self.assertIn(field_name, record)
        self.assertEqual(record["baselineId"], entry["id"])
        self.assertEqual(record["collection"], "knownDebts")

    def test_coherent_known_debt_and_unknown_id_forgery_matrix_is_rejected(self) -> None:
        entry = next(
            item for item in self.baseline["knownDebts"]
            if item["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )
        for field_name, forged_value in (
            ("category", "expected-private-resource-omission"),
            ("baselineId", "UNKNOWN-RELABELLED-AS-DEBT"),
            ("sourceCommandId", "python-source-syntax"),
        ):
            with self.subTest(field=field_name), tempfile.TemporaryDirectory(
                prefix="ci-coherent-debt-forgery-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_evidence(repo, [self.observation_for_entry(entry)])

                def mutate(summary, observed, _resolved, commands):
                    summary["knownDebtsObserved"][0][field_name] = forged_value
                    observed["records"][0][field_name] = forged_value
                    if field_name == "sourceCommandId":
                        commands["observations"][0]["commandId"] = forged_value

                self.rewrite_coherently(output, mutate)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(errors, (field_name, errors))

    def test_omission_and_release_skip_collection_relabelling_is_rejected(self) -> None:
        cases = [
            ("expectedOmissions", self.baseline["expectedOmissions"][0], "releaseOnlySkips"),
            ("releaseOnlySkips", self.baseline["releaseOnlySkips"][0], "expectedOmissions"),
        ]
        for source_field, entry, destination_field in cases:
            with self.subTest(source=source_field), tempfile.TemporaryDirectory(
                prefix="ci-coherent-collection-forgery-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_evidence(repo, [self.observation_for_entry(entry)])

                def mutate(summary, observed, _resolved, _commands):
                    record = summary[source_field].pop(0)
                    summary[destination_field].append(record)
                    summary["counts"][source_field] -= 1
                    summary["counts"][destination_field] += 1
                    source_key = "expectedOmissions" if source_field == "expectedOmissions" else "releaseOnlySkips"
                    destination_key = "expectedOmissions" if destination_field == "expectedOmissions" else "releaseOnlySkips"
                    observed[source_key].pop(0)
                    observed[destination_key].append(record)

                self.rewrite_coherently(output, mutate)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(errors)

    def test_resolved_candidate_requires_success_and_absence_of_original_failure(self) -> None:
        entry = next(
            item for item in self.baseline["knownDebts"]
            if item["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )
        passing = self.observation_for_entry(entry, outcome="pass")
        for mode in ("source-failed", "original-failure-present"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="ci-resolved-forgery-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_evidence(repo, [passing], completed={"direct-syntax"})

                def mutate(_summary, _observed, _resolved, commands):
                    source = next(
                        record for record in commands["records"]
                        if record["commandId"] == passing["commandId"]
                    )
                    source["exitCode"] = 1
                    if mode == "original-failure-present":
                        commands["observations"].append(self.observation_for_entry(entry))

                self.rewrite_coherently(output, mutate)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(errors)

    def test_duplicate_debt_split_across_command_records_is_rejected(self) -> None:
        entry = next(
            item for item in self.baseline["knownDebts"]
            if item["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )
        observation = self.observation_for_entry(entry)
        with tempfile.TemporaryDirectory(prefix="ci-debt-split-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_evidence(repo, [observation])

            def mutate(_summary, _observed, _resolved, commands):
                duplicate = copy.deepcopy(commands["records"][-1])
                duplicate["commandId"] = "node-check:forged-second-source.js"
                commands["records"].append(duplicate)
                second = copy.deepcopy(commands["observations"][0])
                second["commandId"] = duplicate["commandId"]
                commands["observations"].append(second)

            self.rewrite_coherently(output, mutate)
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(errors)

    def test_complete_command_plan_coherent_forgery_matrix_is_rejected(self) -> None:
        entry = next(
            item for item in self.baseline["knownDebts"]
            if item["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )
        failing_id = f"node-check:{entry['testOrPathScope']}"
        cases = (
            "remove-passing-node",
            "remove-failing-node-and-observation",
            "remove-and-renumber",
            "add-command",
            "duplicate-command",
            "reorder-commands",
            "change-argv",
            "change-target-path",
            "change-target-hash",
            "change-cwd",
            "change-executable-path",
            "change-executable-hash",
            "change-required",
            "change-command-class",
            "change-allowed-exit",
            "replace-node-with-another-file",
            "preserve-count-change-command-identity",
        )

        with tempfile.TemporaryDirectory(prefix="ci-command-plan-forgery-") as temp_dir:
            root = Path(temp_dir)
            base_repo = root / "base"
            base_repo.mkdir()
            base_output, _ = self.create_evidence(
                base_repo,
                [self.observation_for_entry(entry)],
            )

            for case in cases:
                with self.subTest(case=case):
                    repo = root / case
                    repo.mkdir()
                    output = repo / ".ci-results"
                    shutil.copytree(base_output, output)

                    def mutate(summary, observed, _resolved, commands, *, mode=case):
                        records = commands["records"]
                        authority = commands["commandAuthority"]
                        record_by_id = {item["commandId"]: index for index, item in enumerate(records)}
                        passing_index = next(
                            index for index, item in enumerate(records)
                            if item["commandId"].startswith("node-check:")
                            and item["commandId"] != failing_id
                            and item["exitCode"] == 0
                        )
                        failing_index = record_by_id[failing_id]

                        def set_both(index: int, key: str, value) -> None:
                            records[index][key] = copy.deepcopy(value)
                            authority[index][key] = copy.deepcopy(value)

                        if mode in {"remove-passing-node", "remove-and-renumber"}:
                            records.pop(passing_index)
                            authority.pop(passing_index)
                            if mode == "remove-and-renumber":
                                for ordinal, (record, specification) in enumerate(zip(records, authority)):
                                    record["ordinal"] = ordinal
                                    specification["ordinal"] = ordinal
                        elif mode == "remove-failing-node-and-observation":
                            records.pop(failing_index)
                            authority.pop(failing_index)
                            commands["observations"] = [
                                item for item in commands["observations"]
                                if item.get("commandId") != failing_id
                            ]
                            summary["knownDebtsObserved"] = []
                            summary["counts"]["knownDebtsObserved"] = 0
                            observed["records"] = []
                        elif mode == "add-command":
                            added_record = copy.deepcopy(records[passing_index])
                            added_authority = copy.deepcopy(authority[passing_index])
                            for item in (added_record, added_authority):
                                item["commandId"] = "node-check:forged-added-file.js"
                                item["ordinal"] = len(records)
                            records.append(added_record)
                            authority.append(added_authority)
                        elif mode == "duplicate-command":
                            duplicate_record = copy.deepcopy(records[passing_index])
                            duplicate_authority = copy.deepcopy(authority[passing_index])
                            duplicate_record["ordinal"] = len(records)
                            duplicate_authority["ordinal"] = len(authority)
                            records.append(duplicate_record)
                            authority.append(duplicate_authority)
                        elif mode == "reorder-commands":
                            records[passing_index], records[passing_index + 1] = (
                                records[passing_index + 1], records[passing_index]
                            )
                            authority[passing_index], authority[passing_index + 1] = (
                                authority[passing_index + 1], authority[passing_index]
                            )
                        elif mode == "change-argv":
                            set_both(passing_index, "argv", records[passing_index]["argv"] + ["--forged"])
                        elif mode == "change-target-path":
                            forged_targets = copy.deepcopy(records[passing_index]["targets"])
                            forged_targets[0]["path"] = "developer/tests/js/forged-target.js"
                            forged_argv = copy.deepcopy(records[passing_index]["argv"])
                            forged_argv[-1] = forged_targets[0]["path"]
                            set_both(passing_index, "targets", forged_targets)
                            set_both(passing_index, "argv", forged_argv)
                        elif mode == "change-target-hash":
                            forged_targets = copy.deepcopy(records[passing_index]["targets"])
                            forged_targets[0]["sha256"] = "0" * 64
                            set_both(passing_index, "targets", forged_targets)
                        elif mode == "change-cwd":
                            set_both(passing_index, "cwd", "developer")
                        elif mode == "change-executable-path":
                            forged_path = str(Path(sys.executable).with_name("forged-node.exe"))
                            forged_argv = copy.deepcopy(records[passing_index]["argv"])
                            forged_argv[0] = forged_path
                            set_both(passing_index, "resolvedExecutablePath", forged_path)
                            set_both(passing_index, "argv", forged_argv)
                        elif mode == "change-executable-hash":
                            set_both(passing_index, "resolvedExecutableSha256", "f" * 64)
                        elif mode == "change-required":
                            set_both(passing_index, "required", False)
                        elif mode == "change-command-class":
                            set_both(passing_index, "commandClass", "forged-direct-syntax")
                        elif mode == "change-allowed-exit":
                            set_both(passing_index, "allowedExecutionExits", [0, 1, 7])
                        elif mode == "replace-node-with-another-file":
                            replacement_index = next(
                                index for index in range(passing_index + 1, len(records))
                                if records[index]["commandId"].startswith("node-check:")
                            )
                            ordinal = records[passing_index]["ordinal"]
                            records[passing_index] = copy.deepcopy(records[replacement_index])
                            authority[passing_index] = copy.deepcopy(authority[replacement_index])
                            records[passing_index]["ordinal"] = ordinal
                            authority[passing_index]["ordinal"] = ordinal
                        elif mode == "preserve-count-change-command-identity":
                            set_both(passing_index, "commandId", "node-check:forged-identity.js")
                        else:  # pragma: no cover - fixed matrix exhaustiveness
                            self.fail(f"unimplemented forgery case: {mode}")

                        summary["counts"]["commands"] = len(records)
                        commands["commandPlanDigest"] = ci.command_plan_digest(authority)

                    self.rewrite_coherently(output, mutate)
                    errors = ci.verify_evidence_file_set(output, repo_root=repo)
                    self.assertTrue(errors, case)
                    self.assertTrue(
                        any("command" in error.casefold() or "derived" in error.casefold() for error in errors),
                        (case, errors),
                    )


class WorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = ci.WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.policy = (ci.REPO_ROOT / "docs" / "CI_POLICY.md").read_text(encoding="utf-8")

    def test_current_workflow_passes_narrow_policy(self) -> None:
        self.assertEqual(ci.check_workflow_text(self.workflow), [])

    def test_write_permission_is_rejected(self) -> None:
        candidate = self.workflow.replace("contents: read", "contents: write", 1)
        errors = ci.check_workflow_text(candidate)
        self.assertTrue(any("permission" in error for error in errors), errors)

    def test_moving_action_reference_is_rejected(self) -> None:
        sha = ci.APPROVED_ACTIONS["actions/checkout"]["sha"]
        candidate = self.workflow.replace(f"actions/checkout@{sha}", "actions/checkout@v7", 1)
        errors = ci.check_workflow_text(candidate)
        self.assertTrue(any("40-character" in error for error in errors), errors)

    def test_unpersisted_checkout_is_rejected(self) -> None:
        candidate = self.workflow.replace("          persist-credentials: false\n", "", 1)
        errors = ci.check_workflow_text(candidate)
        self.assertTrue(any("checkout" in error for error in errors), errors)

    def test_secret_expression_is_rejected(self) -> None:
        candidate = self.workflow.replace(
            "run: python -B developer/tests/ci/test_ci_foundation.py",
            "run: echo \"${{ secrets.NOT_ALLOWED }}\"",
            1,
        )
        errors = ci.check_workflow_text(candidate)
        self.assertTrue(any("secret" in error.lower() for error in errors), errors)

    def test_missing_ci_self_test_command_is_rejected(self) -> None:
        candidate = self.workflow.replace(
            "      - name: Run CI foundation self-tests\n"
            "        run: python -B developer/tests/ci/test_ci_foundation.py\n\n",
            "",
            1,
        )
        errors = ci.check_workflow_text(candidate)
        self.assertTrue(errors)

    def assert_workflow_rejected(self, candidate: str) -> None:
        self.assertTrue(ci.check_workflow_text(candidate))

    def test_job_level_write_all_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "  repository-policy:\n    name:",
                "  repository-policy:\n    permissions: write-all\n    name:",
                1,
            )
        )

    def test_read_all_permission_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("contents: read", "read-all", 1))

    def test_inline_contents_write_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("permissions:\n  contents: read", "permissions: {contents: write}", 1)
        )

    def test_quoted_environment_key_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "    runs-on: ubuntu-latest",
                "    'environment': production\n    runs-on: ubuntu-latest",
                1,
            )
        )

    def test_github_token_dot_form_is_rejected(self) -> None:
        marker = 'echo "Fresh candidate-local verifier jobs succeeded; merge authorization is not provided."'
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(
            self.workflow.replace(marker, 'echo "${{ github.token }}"', 1)
        )

    def test_github_token_single_index_form_is_rejected(self) -> None:
        marker = 'echo "Fresh candidate-local verifier jobs succeeded; merge authorization is not provided."'
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(
            self.workflow.replace(marker, 'echo "${{ github[\'token\'] }}"', 1)
        )

    def test_github_token_double_index_form_is_rejected(self) -> None:
        marker = 'echo "Fresh candidate-local verifier jobs succeeded; merge authorization is not provided."'
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(
            self.workflow.replace(marker, 'echo "${{ github[\"token\"] }}"', 1)
        )

    def test_folded_forbidden_command_is_rejected_before_semantics(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "        run: npm --prefix developer ci --ignore-scripts --no-audit --no-fund",
                "        run: >\n          git push origin main",
                1,
            )
        )

    def test_environment_variable_command_indirection_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "        run: npm --prefix developer ci --ignore-scripts --no-audit --no-fund",
                "        run: |\n          CMD=\"git push origin main\"\n          $CMD",
                1,
            )
        )

    def test_final_always_removed_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("    if: ${{ always() }}\n", "", 1))

    def test_final_need_removed_is_rejected(self) -> None:
        marker = "      - windows-compatibility\n    runs-on: ubuntu-latest"
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(self.workflow.replace(marker, "    runs-on: ubuntu-latest", 1))

    def test_final_failure_exit_neutralized_with_colon_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("          exit 1", "          :", 1))

    def test_final_failure_exit_zero_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("          exit 1", "          exit 0", 1))

    def test_final_conditional_neutralized_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                'if [[ "${{ needs.repository-policy.result }}" != "success" ]]; then',
                "if false; then",
                1,
            )
        )

    def test_unknown_yaml_construct_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow + "\n? unsupported\n")

    def test_yaml_anchor_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("name: Baseline-aware CI", "name: Baseline-aware CI &defaults", 1)
        )

    def test_yaml_alias_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "  cancel-in-progress: true",
                "  cancel-in-progress: *defaults",
                1,
            )
        )

    def test_yaml_merge_key_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "  repository-policy:\n",
                "  repository-policy:\n    <<: *defaults\n",
                1,
            )
        )

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow + "\nname: Duplicate\n")

    def test_custom_yaml_tag_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("name: Baseline-aware CI", "name: !unsafe Baseline-aware CI", 1)
        )

    def test_tab_indentation_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("  contents: read", "\tcontents: read", 1))

    def test_quoted_mapping_key_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("permissions:", "'permissions':", 1))

    def test_artifact_glob_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(".ci-results/summary.json", ".ci-results/*.json", 1)
        )

    def test_unexpected_artifact_file_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                ".ci-results/command-results.json",
                ".ci-results/command-results.json\n            .ci-results/unexpected.json",
                1,
            )
        )

    def test_missing_expected_artifact_file_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("            .ci-results/resolved-candidates.json\n", "", 1)
        )

    def test_if_no_files_found_change_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("if-no-files-found: error", "if-no-files-found: warn", 1)
        )

    def test_removing_untrusted_producer_upload_is_rejected(self) -> None:
        block = (
            "      - name: Upload untrusted policy evidence\n"
            "        if: ${{ always() }}\n"
            f"        uses: actions/upload-artifact@{ci.APPROVED_ACTIONS['actions/upload-artifact']['sha']} # v7.0.1\n"
        )
        self.assertIn(block, self.workflow)
        self.assert_workflow_rejected(self.workflow.replace(block, "      - name: Missing producer upload\n        run: exit 1\n", 1))

    def test_producer_preupload_verifier_is_rejected(self) -> None:
        marker = (
            "      - name: Upload untrusted policy evidence"
        )
        replacement = (
            "      - name: Verify evidence inside producer\n"
            "        run: python -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile policy\n\n"
            "      - name: Upload untrusted policy evidence"
        )
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(self.workflow.replace(marker, replacement, 1))

    def test_producer_upload_remains_explicitly_untrusted_and_always_runs(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "      - name: Upload untrusted policy evidence\n        if: ${{ always() }}",
                "      - name: Upload trusted policy evidence\n        if: ${{ success() }}",
                1,
            )
        )

    def test_documentation_contains_explicit_bootstrap_warning(self) -> None:
        self.assertEqual(ci.check_governance_language(self.workflow, self.policy), [])
        for warning in ci.TRUST_WARNING_LINES:
            self.assertIn(warning, self.policy)

    def test_final_result_output_contains_candidate_control_warning(self) -> None:
        for warning in ci.TRUST_WARNING_LINES:
            self.assertIn(warning, ci.FINAL_RESULT_SCRIPT)
            self.assertIn(warning, self.workflow)

    def test_prohibited_authority_overclaim_is_rejected(self) -> None:
        candidate = self.policy + "\nThis candidate is safe to merge.\n"
        errors = ci.check_governance_language(self.workflow, candidate)
        self.assertTrue(any("overclaim" in error for error in errors), errors)

    def test_removing_bootstrap_warning_fails_policy(self) -> None:
        warning = ci.TRUST_WARNING_LINES[0]
        errors = ci.check_governance_language(self.workflow, self.policy.replace(warning, "", 1))
        self.assertTrue(errors)

    def test_claiming_merge_authorization_is_rejected(self) -> None:
        candidate = self.workflow.replace(
            "MERGE AUTHORIZATION: not provided by this workflow",
            "MERGE AUTHORIZ" + "ATION: merge authorized",
            1,
        )
        self.assert_workflow_rejected(candidate)

    def test_absent_codeowners_or_branch_protection_is_not_treated_as_protected(self) -> None:
        self.assertEqual(ci.check_governance_language(self.workflow, self.policy), [])
        self.assertIn(
            "This document does not assert that CODEOWNERS, required-reviewer rules,\n"
            "or branch protection currently exist.",
            self.policy,
        )

    def test_preinstall_execution_before_verifier_is_rejected(self) -> None:
        marker = "      - name: Download untrusted policy evidence"
        self.assertIn(marker, self.workflow)
        insertion = (
            "      - name: Malicious root preinstall\n"
            "        run: npm ci\n\n"
            + marker
        )
        self.assert_workflow_rejected(
            self.workflow.replace(marker, insertion, 1)
        )

    def test_developer_lifecycle_scripts_are_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(
                "npm --prefix developer ci --ignore-scripts --no-audit --no-fund",
                "npm --prefix developer ci --no-audit --no-fund",
                1,
            )
        )

    def test_tool_environment_override_is_rejected(self) -> None:
        marker = "      - name: Install fresh locked developer dependencies\n        shell: bash\n"
        self.assertIn(marker, self.workflow)
        self.assert_workflow_rejected(
            self.workflow.replace(
                marker,
                "      - name: Install fresh locked developer dependencies\n"
                "        env:\n"
                "          NODE_EXE: ./node.exe\n"
                "        shell: bash\n",
                1,
            )
        )

    def test_direct_git_push_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(ci.SELF_TEST_COMMAND, "git push origin main", 1)
        )

    def test_curl_command_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace(ci.SELF_TEST_COMMAND, "curl https://attacker.invalid", 1)
        )

    def test_self_hosted_runner_is_rejected(self) -> None:
        self.assert_workflow_rejected(self.workflow.replace("runs-on: ubuntu-latest", "runs-on: self-hosted", 1))

    def test_container_block_is_rejected(self) -> None:
        self.assert_workflow_rejected(
            self.workflow.replace("    runs-on: ubuntu-latest", "    container: node:24\n    runs-on: ubuntu-latest", 1)
        )

    def test_reusable_workflow_call_is_rejected(self) -> None:
        sha = ci.APPROVED_ACTIONS["actions/checkout"]["sha"]
        self.assert_workflow_rejected(
            self.workflow.replace(f"actions/checkout@{sha}", "./.github/workflows/reusable.yml", 1)
        )


class SanitizationAndEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_fixture_plan = compact_policy_fixture_plan()
        authority = mock.patch.object(
            ci,
            "expected_command_authority",
            return_value=self.policy_fixture_plan,
        )
        authority.start()
        self.addCleanup(authority.stop)

    def create_valid_evidence(
        self,
        repo: Path,
        *,
        command_results: list[dict] | None = None,
        comparison: dict | None = None,
    ) -> tuple[Path, dict]:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        runner = fake_runner(baseline)
        if command_results is not None:
            runner.command_results = list(command_results)
        output = repo / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=repo)
        with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
            summary = ci.write_evidence(runner, comparison or empty_comparison())
        return output, summary

    def rewrite_manifested_json(self, output: Path, name: str, value: dict) -> None:
        data = ci._json_bytes(value)
        self.rewrite_manifested_raw_json(output, name, data)

    def rewrite_manifested_raw_json(self, output: Path, name: str, data: bytes) -> None:
        (output / name).write_bytes(data)
        summary_path = output / "summary.json"
        summary = ci.strict_json_load_file(summary_path)
        entry = next(
            item for item in summary["evidenceManifest"] if item["relativeFilename"] == name
        )
        entry["byteLength"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        summary_path.write_bytes(ci._json_bytes(summary))

    def test_child_environment_is_allowlisted(self) -> None:
        source = {
            "HOME": "home",
            "TEMP": "temp",
            "GITHUB_TOKEN": "forbidden",
            "HTTPS_PROXY": "forbidden",
            "NODE_EXE": "forbidden",
        }
        environment = ci.child_process_environment(
            {"python": sys.executable},
            source_environment=source,
        )
        self.assertEqual(environment["HOME"], "home")
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("NODE_EXE", environment)

    def test_secret_values_and_platform_paths_are_sanitized(self) -> None:
        synthetic_token = "github_" + "pat_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        source = (
            "author" + f"ization={synthetic_token} "
            "C:\\private\\runner\\file.js:123:9\r\n"
        )
        sanitized = ci.sanitize_text(source)
        self.assertNotIn(synthetic_token, sanitized)
        self.assertNotIn("C:/private", sanitized)
        self.assertNotIn("\r", sanitized)

    def test_private_path_policy_is_exact(self) -> None:
        self.assertIsNotNone(ci.private_or_operational_path_reason("ListeningPractice/P1/private.html"))
        self.assertIsNone(
            ci.private_or_operational_path_reason(
                "ListeningPractice/vip special/assets/data/path-map.json"
            )
        )

    def test_required_evidence_file_set_is_written(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        runner = fake_runner(baseline)
        comparison = {
            "observedDebts": [],
            "resolvedCandidates": [],
            "expectedOmissions": [],
            "releaseOnlySkips": [],
            "violations": [],
        }
        with tempfile.TemporaryDirectory(prefix="ci-foundation-test-") as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=repo)
            with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
                summary = ci.write_evidence(runner, comparison)
            self.assertEqual(summary["status"], "PASS")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "summary.json",
                    "summary.md",
                    "observed-debt.json",
                    "resolved-candidates.json",
                    "command-results.json",
                },
            )
            self.assertEqual(ci.verify_evidence_file_set(output, repo_root=repo), [])
            markdown = (output / "summary.md").read_text(encoding="utf-8")
            for warning in ci.TRUST_WARNING_LINES:
                self.assertIn(warning, markdown)
            self.assertEqual(
                [item["relativeFilename"] for item in summary["evidenceManifest"]],
                list(ci.EVIDENCE_MANIFEST_FILE_NAMES),
            )

    def test_five_expected_filenames_with_arbitrary_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-bytes-") as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            for name in ci.EVIDENCE_FILE_NAMES:
                (output / name).write_bytes(b"\xffarbitrary")
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(errors)
        self.assertTrue(any("invalid UTF-8 JSON" in error for error in errors), errors)

    def test_valid_json_with_wrong_document_kind_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-kind-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            document = ci.strict_json_load_file(output / "observed-debt.json")
            document["documentKind"] = "wrong-kind"
            self.rewrite_manifested_json(output, "observed-debt.json", document)
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("document kind" in error for error in errors), errors)

    def test_contradictory_command_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-count-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["counts"]["commands"] += 1
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("counts contradict" in error for error in errors), errors)

    def test_summary_pass_with_command_execution_failure_is_rejected(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        command_results = fake_runner(baseline).command_results
        with tempfile.TemporaryDirectory(prefix="ci-evidence-command-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo, command_results=command_results)
            document = ci.strict_json_load_file(output / "command-results.json")
            record = document["records"][0]
            record["executed"] = False
            record["setupFailure"] = True
            record["exitCode"] = None
            record["processTreeStatus"] = "not-started"
            self.rewrite_manifested_json(output, "command-results.json", document)
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("reports PASS" in error for error in errors), errors)

    def test_required_command_nonzero_and_invalid_exit_matrix_is_rejected(self) -> None:
        exit_values = [1, 2, 7, 124, 125, 255, -1, 1.5, None]
        for exit_value in exit_values:
            with self.subTest(exitCode=exit_value), tempfile.TemporaryDirectory(
                prefix="ci-evidence-exit-matrix-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_valid_evidence(repo)
                document = ci.strict_json_load_file(output / "command-results.json")
                document["records"][0]["exitCode"] = exit_value
                self.rewrite_manifested_json(output, "command-results.json", document)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(errors, exit_value)
            self.assertTrue(
                any("execution failure" in error or "exitCode" in error or "derived" in error for error in errors),
                (exit_value, errors),
            )

    def test_command_set_missing_extra_duplicate_order_and_classification_are_rejected(self) -> None:
        mutations = {
            "missing": lambda records: records.pop(),
            "extra": lambda records: records.append(copy.deepcopy(records[-1]) | {"commandId": "extra"}),
            "duplicate": lambda records: records.__setitem__(1, copy.deepcopy(records[0])),
            "order": lambda records: records.__setitem__(slice(0, 2), list(reversed(records[:2]))),
            "required": lambda records: records[0].__setitem__("required", False),
            "started": lambda records: records[0].__setitem__("started", False),
            "class": lambda records: records[0].__setitem__("commandClass", "forged-class"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="ci-evidence-command-authority-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_valid_evidence(repo)
                document = ci.strict_json_load_file(output / "command-results.json")
                mutate(document["records"])
                self.rewrite_manifested_json(output, "command-results.json", document)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(any("command" in error.casefold() for error in errors), (name, errors))

    def test_duplicate_summary_and_manifested_nested_keys_fail_at_parser_boundary(self) -> None:
        summary_replacements = {
            "pass-then-fail": (b'"status": "PASS"', b'"status": "PASS",\n  "status": "FAIL"'),
            "fail-then-pass": (b'"status": "PASS"', b'"status": "FAIL",\n  "status": "PASS"'),
            "manifest-identical-hash": (b'"sha256": "', b'"sha256": "duplicate",\n      "sha256": "'),
        }
        for name, (needle, replacement) in summary_replacements.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="ci-evidence-duplicate-summary-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_valid_evidence(repo)
                raw = (output / "summary.json").read_bytes()
                self.assertIn(needle, raw)
                (output / "summary.json").write_bytes(raw.replace(needle, replacement, 1))
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(any("DuplicateJsonKeyError" in error for error in errors), errors)

        nested_replacements = {
            "exit-code": (b'"exitCode": 0,', b'"exitCode": 0,\n      "exitCode": 0,'),
            "executed": (b'"executed": true,', b'"executed": true,\n      "executed": true,'),
        }
        for name, (needle, replacement) in nested_replacements.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="ci-evidence-duplicate-command-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_valid_evidence(repo)
                raw = (output / "command-results.json").read_bytes()
                self.assertIn(needle, raw)
                forged = raw.replace(needle, replacement, 1)
                self.rewrite_manifested_raw_json(output, "command-results.json", forged)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(any("DuplicateJsonKeyError" in error for error in errors), errors)

    def test_nonfinite_json_constants_and_overflow_are_rejected(self) -> None:
        for literal in ("NaN", "Infinity", "-Infinity", "1e309", "-1e309"):
            with self.subTest(literal=literal):
                document, errors = ci._decode_evidence_json(
                    "fixture.json",
                    ('{"value":' + literal + '}\n').encode("ascii"),
                )
                self.assertTrue(errors, document)

    def test_finite_numeric_bounds_matrix_is_rejected(self) -> None:
        mutations = {
            "negative-duration": lambda record: record.__setitem__("durationSeconds", -1),
            "excessive-duration": lambda record: record.__setitem__(
                "durationSeconds", ci.MAX_JOB_TIMEOUT_SECONDS + 0.001
            ),
            "infinite-duration": lambda record: record.__setitem__("durationSeconds", math.inf),
            "fractional-byte-count": lambda record: record.__setitem__("stdoutBytesObserved", 1.5),
            "overflow-byte-count": lambda record: record.__setitem__(
                "stdoutBytesObserved", ci.MAX_RECORDED_STREAM_BYTES + 1
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="ci-evidence-number-"
            ) as temp_dir:
                repo = Path(temp_dir)
                output, _ = self.create_valid_evidence(repo)
                document = ci.strict_json_load_file(output / "command-results.json")
                mutate(document["records"][0])
                if name == "infinite-duration":
                    data = json.dumps(document, allow_nan=True, sort_keys=True).encode("utf-8") + b"\n"
                    (output / "command-results.json").write_bytes(data)
                    summary = ci.strict_json_load_file(output / "summary.json")
                    manifest = next(
                        item for item in summary["evidenceManifest"]
                        if item["relativeFilename"] == "command-results.json"
                    )
                    manifest["byteLength"] = len(data)
                    manifest["sha256"] = hashlib.sha256(data).hexdigest()
                    (output / "summary.json").write_bytes(ci._json_bytes(summary))
                else:
                    self.rewrite_manifested_json(output, "command-results.json", document)
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
            self.assertTrue(errors, name)

    def test_fractional_command_count_and_invalid_timestamp_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-count-number-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["counts"]["commands"] = 1.5
            summary["generatedAt"] = "not-a-timestamp"
            summary["invocation"]["startedAt"] = "not-a-timestamp"
            for name in ("observed-debt.json", "resolved-candidates.json", "command-results.json"):
                document = ci.strict_json_load_file(output / name)
                document["invocation"] = summary["invocation"]
                self.rewrite_manifested_json(output, name, document)
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("timestamp" in error or "counts" in error for error in errors), errors)

    def test_modified_observed_debt_set_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-debt-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            forged = [{"id": "KNOWN", "observedOutcome": "fail"}]
            document = ci.strict_json_load_file(output / "observed-debt.json")
            document["records"] = forged
            data = ci._json_bytes(document)
            (output / "observed-debt.json").write_bytes(data)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["knownDebtsObserved"] = forged
            summary["counts"]["knownDebtsObserved"] = 1
            manifest = next(
                item for item in summary["evidenceManifest"]
                if item["relativeFilename"] == "observed-debt.json"
            )
            manifest["byteLength"] = len(data)
            manifest["sha256"] = hashlib.sha256(data).hexdigest()
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("baseline-bound command observations" in error for error in errors), errors)

    def test_modified_resolved_candidate_set_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-resolved-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            forged = [{"id": "RESOLVED", "status": "RESOLVED-CANDIDATE"}]
            document = ci.strict_json_load_file(output / "resolved-candidates.json")
            document["records"] = forged
            data = ci._json_bytes(document)
            (output / "resolved-candidates.json").write_bytes(data)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["resolvedCandidates"] = forged
            summary["counts"]["resolvedCandidates"] = 1
            manifest = next(
                item for item in summary["evidenceManifest"]
                if item["relativeFilename"] == "resolved-candidates.json"
            )
            manifest["byteLength"] = len(data)
            manifest["sha256"] = hashlib.sha256(data).hexdigest()
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("baseline-bound command observations" in error for error in errors), errors)

    def test_arbitrary_summary_markdown_is_rejected_even_with_updated_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-markdown-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            data = b"# arbitrary\n"
            (output / "summary.md").write_bytes(data)
            summary = ci.strict_json_load_file(output / "summary.json")
            entry = next(item for item in summary["evidenceManifest"] if item["relativeFilename"] == "summary.md")
            entry["byteLength"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("canonical rendering" in error for error in errors), errors)

    def test_markdown_injection_matrix_is_neutralized_and_round_trips(self) -> None:
        payloads = [
            "<h1>FORGED PASS</h1>",
            "<script>alert(1)</script>",
            "`forged`",
            "```fence",
            "[PASS](javascript:alert(1))",
            "![image](https://example.invalid)",
            "| forged | table |",
            "# forged heading",
            "> forged quote",
            "line one\n## Status: PASS",
            "\u202ePASS\u2066FAIL",
        ]
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory(
                prefix="ci-markdown-injection-"
            ) as temp_dir:
                repo = Path(temp_dir)
                runner = fake_runner(baseline)
                runner.runtime["os"] = payload
                runner.violations.append({"id": "INJECTION", "detail": payload})
                output = repo / ".ci-results"
                ci.create_fresh_evidence_root(output, repo_root=repo)
                with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
                    summary = ci.write_evidence(runner, empty_comparison())
                markdown = (output / "summary.md").read_text(encoding="utf-8")
                encoded = json.dumps(
                    summary["policyViolations"][0],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                self.assertIn(
                    f"- INJECTION: {ci.render_markdown_text(encoded)}",
                    markdown.splitlines(),
                )
                self.assertEqual(markdown, ci.render_summary_markdown(summary))
                self.assertEqual(ci.verify_evidence_file_set(output, repo_root=repo), [])

    def test_unescaped_injected_markdown_is_rejected_after_manifest_rewrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-markdown-mutated-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            data = b"# Baseline-aware CI summary\n\n<h1>FORGED PASS</h1>\n"
            (output / "summary.md").write_bytes(data)
            summary = ci.strict_json_load_file(output / "summary.json")
            manifest = next(
                item for item in summary["evidenceManifest"]
                if item["relativeFilename"] == "summary.md"
            )
            manifest["byteLength"] = len(data)
            manifest["sha256"] = hashlib.sha256(data).hexdigest()
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("canonical rendering" in error for error in errors), errors)

    def test_single_byte_mutation_after_generation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-mutation-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            path = output / "resolved-candidates.json"
            data = bytearray(path.read_bytes())
            data[0] ^= 1
            path.write_bytes(data)
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(errors)

    def test_file_replaced_after_initial_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-replace-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            original = ci._read_evidence_file_snapshot

            def replacing_reader(path: Path, **kwargs):
                snapshot, errors = original(path, **kwargs)
                if path.name == "summary.md" and snapshot is not None:
                    path.write_bytes(snapshot.data + b"changed")
                return snapshot, errors

            with mock.patch.object(ci, "_read_evidence_file_snapshot", side_effect=replacing_reader):
                errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("changed after validation" in error for error in errors), errors)

    def test_manifest_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-hash-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["evidenceManifest"][0]["sha256"] = "0" * 64
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("SHA-256" in error for error in errors), errors)

    def test_manifest_length_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-length-") as temp_dir:
            repo = Path(temp_dir)
            output, _ = self.create_valid_evidence(repo)
            summary = ci.strict_json_load_file(output / "summary.json")
            summary["evidenceManifest"][0]["byteLength"] += 1
            (output / "summary.json").write_bytes(ci._json_bytes(summary))
            errors = ci.verify_evidence_file_set(output, repo_root=repo)
        self.assertTrue(any("byte length" in error for error in errors), errors)

    def test_verification_only_mode_does_not_modify_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-evidence-mode-") as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
            with mock.patch.object(ci, "REPO_ROOT", repo):
                runner = fake_runner(baseline)
                ci.create_fresh_evidence_root(output, repo_root=repo)
                with mock.patch.object(ci, "OUTPUT_DIR", output):
                    ci.write_evidence(runner, empty_comparison())
                before = {
                    name: (
                        hashlib.sha256((output / name).read_bytes()).hexdigest(),
                        (output / name).stat().st_mtime_ns,
                    )
                    for name in ci.EVIDENCE_FILE_NAMES
                }
                context = synthetic_external_context(runner.execution_binding)
                verification_runner = mock.Mock()
                with mock.patch.object(ci, "OUTPUT_DIR", output), mock.patch.object(
                    ci,
                    "prepare_verification_authority",
                    return_value=(context, verification_runner),
                ), mock.patch.object(
                    ci,
                    "verify_evidence_with_replay",
                    return_value=([], {"kind": "VerificationReplayTranscript"}),
                ) as replay:
                    exit_code = ci.main(
                        [
                            "--verify-evidence",
                            "--expected-profile",
                            "policy",
                            "--expected-invocation-id",
                            runner.execution_binding["producerInvocationId"],
                        ]
                    )
                after = {
                    name: (
                        hashlib.sha256((output / name).read_bytes()).hexdigest(),
                        (output / name).stat().st_mtime_ns,
                    )
                    for name in ci.EVIDENCE_FILE_NAMES
                }
        self.assertEqual(exit_code, ci.EXIT_SUCCESS)
        self.assertEqual(after, before)
        replay.assert_called_once_with(
            output,
            expected_context=context,
            verification_runner=verification_runner,
            repo_root=repo,
        )

    def assert_redacted(self, source: str, *forbidden: str) -> str:
        sanitized = ci.sanitize_text(source)
        self.assertIn("[REDACTED]", sanitized)
        for value in forbidden:
            self.assertNotIn(value, sanitized)
        return sanitized

    def test_credential_bearing_url_is_redacted(self) -> None:
        self.assert_redacted(
            "fetch https://" + "alice:super-secret-password" + "@example.invalid/path",
            "alice",
            "super-secret-password",
        )

    def test_bearer_authorization_header_is_redacted(self) -> None:
        self.assert_redacted(
            "Author" + "ization: " + "Bear" + "er abcdefghijklmnopqrstuvwxyz012345",
            "abcdefghijklmnopqrstuvwxyz012345",
        )

    def test_basic_authorization_value_is_redacted(self) -> None:
        self.assert_redacted("proxy=" + "Bas" + "ic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA")

    def test_cookie_and_set_cookie_values_are_redacted(self) -> None:
        sanitized = self.assert_redacted(
            "Cook" + "ie: session=private-session-value\nSet-" + "Cookie: sid=another-private-value",
            "private-session-value",
            "another-private-value",
        )
        self.assertNotIn("session=", sanitized)

    def test_multiline_generic_secret_is_redacted(self) -> None:
        self.assert_redacted("to" + "ken=\nabcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnopqrstuvwxyz012345")

    def test_private_key_block_is_redacted(self) -> None:
        key_label = "PRIVATE " + "KEY"
        source = f"-----BEGIN {key_label}-----\nprivate-body\n-----END {key_label}-----"
        self.assert_redacted(source, "private-body", "BEGIN " + key_label, "END " + key_label)

    def test_isolated_private_key_marker_is_redacted(self) -> None:
        key_label = "OPENSSH PRIVATE " + "KEY"
        self.assert_redacted(f"failure: -----BEGIN {key_label}-----", "BEGIN " + key_label)

    def test_ansi_csi_and_osc_are_removed(self) -> None:
        source = "\x1b[31mred\x1b[0m\x1b]8;;https://spoof.invalid\x07click\x1b]8;;\x07"
        sanitized = ci.sanitize_text(source)
        self.assertNotIn("\x1b", sanitized)
        self.assertNotIn("spoof.invalid", sanitized)

    def test_c0_del_and_unicode_bidi_controls_are_removed(self) -> None:
        sanitized = ci.sanitize_text("safe\x00\x08\x7f\u202e\u2066text\n")
        for value in ("\x00", "\x08", "\x7f", "\u202e", "\u2066"):
            self.assertNotIn(value, sanitized)

    def test_existing_evidence_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            with self.assertRaises(RuntimeError):
                ci.create_fresh_evidence_root(output, repo_root=repo)

    def test_evidence_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            target = repo / "target"
            target.mkdir()
            output = repo / ".ci-results"
            try:
                os.symlink(target, output, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {exc}")
            self.assertTrue(ci.validate_evidence_root_absent(output, repo_root=repo))

    def test_individual_evidence_file_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=repo)
            target = repo / "target.json"
            target.write_text("{}", encoding="utf-8")
            try:
                os.symlink(target, output / "summary.json")
            except OSError as exc:
                self.skipTest(f"file symlink unavailable: {exc}")
            with self.assertRaises(FileExistsError):
                ci.write_json(output / "summary.json", {}, repo_root=repo)

    def test_reparse_point_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            with mock.patch.object(ci, "_is_reparse_point", return_value=True):
                self.assertTrue(ci.validate_evidence_root(output, repo_root=repo))

    def test_unexpected_json_evidence_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            for name in ci.EVIDENCE_FILE_NAMES:
                (output / name).write_text("x", encoding="utf-8")
            (output / "unexpected.json").write_text("x", encoding="utf-8")
            self.assertTrue(ci.verify_evidence_file_set(output, repo_root=repo))

    def test_unexpected_markdown_evidence_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            for name in ci.EVIDENCE_FILE_NAMES:
                (output / name).write_text("x", encoding="utf-8")
            (output / "unexpected.md").write_text("x", encoding="utf-8")
            self.assertTrue(ci.verify_evidence_file_set(output, repo_root=repo))

    def test_missing_expected_evidence_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            output.mkdir()
            for name in ci.EVIDENCE_FILE_NAMES[:-1]:
                (output / name).write_text("x", encoding="utf-8")
            self.assertTrue(ci.verify_evidence_file_set(output, repo_root=repo))

    def test_command_result_json_limit_fails_with_bounded_record(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        runner = fake_runner(baseline)
        runner.command_results = [{"commandId": "x", "diagnosticPreview": "z" * 1000}]
        comparison = {
            "observedDebts": [], "resolvedCandidates": [], "expectedOmissions": [],
            "releaseOnlySkips": [], "violations": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=repo)
            with mock.patch.multiple(
                ci,
                OUTPUT_DIR=output,
                REPO_ROOT=repo,
                MAX_COMMAND_RESULTS_JSON_BYTES=256,
            ):
                summary = ci.write_evidence(runner, comparison)
            self.assertEqual(summary["status"], "FAIL")
            command_results = ci.strict_json_load_file(output / "command-results.json")
            self.assertEqual(command_results["records"][0]["outputLimitStatus"], "OUTPUT-LIMIT-EXCEEDED")


class StaticProducerProtocolTest(unittest.TestCase):
    INVOCATION_ID = "12345678-1234-4234-9234-1234567890ab"

    def invoke(self, *, passed: bool, argv: list[str]) -> tuple[int, str, str, bool]:
        results = [
            {
                "name": "fixture",
                "status": "pass" if passed else "fail",
                "detail": {"passed": passed},
            }
        ]
        with tempfile.TemporaryDirectory(prefix="ci-static-producer-") as temp_dir:
            root = Path(temp_dir)
            target = root / static_suite.STATIC_SUITE_RELATIVE_PATH
            target.parent.mkdir(parents=True)
            target.write_text("# machine-plan fixture\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(static_suite, "REPO_ROOT", root),
                mock.patch.object(static_suite, "run_checks", return_value=(results, passed)),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = static_suite.main(argv)
            report_exists = (
                root / "developer" / "tests" / "e2e" / "reports" / "static-ci-report.json"
            ).exists()
        return exit_code, stdout.getvalue(), stderr.getvalue(), report_exists

    def test_legacy_default_invocation_preserves_human_and_file_behavior(self) -> None:
        exit_code, stdout, stderr, report_exists = self.invoke(passed=True, argv=[])
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(report_exists)
        document = ci.strict_json_loads(stdout)
        self.assertEqual(set(document), {"generatedAt", "status", "results"})
        self.assertNotIn("documentKind", document)

    def test_legacy_default_failure_exit_is_unchanged(self) -> None:
        exit_code, stdout, _stderr, report_exists = self.invoke(passed=False, argv=[])
        self.assertEqual(exit_code, 1)
        self.assertEqual(ci.strict_json_loads(stdout)["status"], "fail")
        self.assertTrue(report_exists)

    def test_machine_mode_stdout_is_one_framed_document_and_uses_no_report_file(self) -> None:
        exit_code, stdout, stderr, report_exists = self.invoke(
            passed=False,
            argv=[
                "--ci-machine-json-stdout",
                "--ci-invocation-id",
                self.INVOCATION_ID,
            ],
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(stdout.endswith("\n"))
        self.assertFalse(stdout.endswith("\n\n"))
        document = ci.strict_json_loads(stdout)
        self.assertEqual(document["documentKind"], ci.STATIC_MACHINE_DOCUMENT_KIND)
        self.assertEqual(document["invocationId"], self.INVOCATION_ID)
        self.assertEqual(document["executionStatus"], "COMPLETE")
        self.assertEqual(document["nativeNonPassCount"], 1)
        self.assertEqual(document["internalRunnerFailures"], [])
        self.assertEqual(len(document["commandResults"]), 1)
        self.assertFalse(report_exists)

    def test_machine_invalid_uuid_is_nonzero_with_empty_stdout(self) -> None:
        exit_code, stdout, _stderr, report_exists = self.invoke(
            passed=True,
            argv=["--ci-machine-json-stdout", "--ci-invocation-id", "not-a-uuid"],
        )
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(stdout, "")
        self.assertFalse(report_exists)

    def test_duplicate_machine_flags_are_nonzero(self) -> None:
        exit_code, stdout, _stderr, report_exists = self.invoke(
            passed=True,
            argv=[
                "--ci-machine-json-stdout",
                "--ci-machine-json-stdout",
                "--ci-invocation-id",
                self.INVOCATION_ID,
            ],
        )
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(stdout, "")
        self.assertFalse(report_exists)

    def test_invocation_id_without_machine_flag_is_nonzero(self) -> None:
        exit_code, stdout, _stderr, _report_exists = self.invoke(
            passed=True,
            argv=["--ci-invocation-id", self.INVOCATION_ID],
        )
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(stdout, "")


class StaticExecutionAuthorityTest(unittest.TestCase):
    INVOCATION_UUID = uuid.UUID("12345678-1234-4234-9234-1234567890ab")
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)

    def exercise(
        self,
        capture: ci.CommandCapture,
        *,
        report: dict | bytes | None,
        stale_report: dict | None = None,
    ) -> tuple[ci.FoundationRunner, bool]:
        with tempfile.TemporaryDirectory(prefix="ci-static-authority-") as temp_dir:
            repo = Path(temp_dir)
            static_target = repo / ci.STATIC_SUITE_RELATIVE_PATH
            static_target.parent.mkdir(parents=True)
            static_target.write_text("# static authority fixture\n", encoding="utf-8")
            report_path = repo / "developer" / "tests" / "e2e" / "reports" / "static-ci-report.json"
            report_path.parent.mkdir(parents=True)
            if stale_report is not None:
                report_path.write_text(json.dumps(stale_report), encoding="utf-8")

            def fake_execute(_command_id, _command_class, argv, **_kwargs):
                capture.argv = list(argv)
                if isinstance(report, dict):
                    document = copy.deepcopy(report)
                    document["invocationId"] = argv[-1]
                    plan = ci.build_expected_static_machine_command_plan(
                        argv[-1],
                        python_executable=argv[0],
                        repo_root=repo,
                        current_platform=ci.platform_key(),
                    )
                    document["commandPlanDigest"] = ci.static_machine_command_plan_digest(plan)
                    document["commandResults"] = [
                        {
                            **plan[0],
                            "started": True,
                            "executed": True,
                            "exitCode": 0,
                            "timeoutStatus": "within-limit",
                            "outputLimitStatus": "within-limit",
                            "containmentStatus": "parent-contained",
                        }
                    ]
                    data = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
                elif isinstance(report, bytes):
                    data = report
                else:
                    data = b""
                capture.stdout_raw = data
                capture.stdout = data.decode("utf-8", errors="replace")
                capture.stdout_bytes = len(data)
                return capture

            def fake_snapshot(plan_record, **_kwargs):
                result = fake_execute(
                    plan_record["commandId"],
                    plan_record["commandClass"],
                    plan_record["executionArgv"],
                )
                result.logical_argv = list(plan_record["logicalArgv"])
                result.execution_input_mode = plan_record["executionInputMode"]
                targets = plan_record.get("targets", [])
                inputs = [
                    {
                        "logicalPath": target.get("path"),
                        "canonicalSourcePath": target.get("canonicalSourcePath"),
                        "plannedByteLength": target.get("size"),
                        "plannedSha256": target.get("sha256"),
                        "plannedStableIdentity": target.get("fileIdentity"),
                        "actualByteLength": target.get("size"),
                        "actualSha256": target.get("sha256"),
                        "inputMode": plan_record["executionInputMode"],
                    }
                    for target in targets
                ]
                bundle_digest = ci.execution_input_bundle_digest(inputs) if inputs else None
                bundle = {
                    "bundleVersion": ci.PROTECTED_TARGET_BUNDLE_VERSION,
                    "executionAdapter": plan_record["executionInputMode"],
                    "orderedLogicalTargetPaths": [target.get("path") for target in targets],
                    "canonicalSourcePaths": [target.get("canonicalSourcePath") for target in targets],
                    "plannedByteLengths": [target.get("size") for target in targets],
                    "plannedSha256Values": [target.get("sha256") for target in targets],
                    "plannedStableIdentities": [target.get("fileIdentity") for target in targets],
                    "executionInputs": inputs,
                    "executionInputBundleDigest": bundle_digest,
                    "preExecutionIdentities": [{} for _target in targets],
                    "postExecutionIdentities": [{} for _target in targets],
                    "mutationDetected": False,
                    "cleanupState": "closed",
                }
                return result, bundle

            with (
                mock.patch.multiple(ci, REPO_ROOT=repo),
                mock.patch.object(ci.uuid, "uuid4", return_value=self.INVOCATION_UUID),
                mock.patch.object(ci, "execute_planned_static_suite", side_effect=fake_snapshot),
                mock.patch.object(ci.FoundationRunner, "run_direct_syntax", autospec=True),
            ):
                runner = ci.FoundationRunner(
                    "static",
                    copy.deepcopy(self.baseline),
                    tools={"python": sys.executable},
                    source_environment=os.environ,
                )
                runner.run_static_profile()
            return runner, report_path.exists()

    @staticmethod
    def passing_report() -> dict:
        return {
            "documentKind": ci.STATIC_MACHINE_DOCUMENT_KIND,
            "schemaVersion": 2,
            "invocationId": "replaced-by-fixture",
            "executionStatus": "COMPLETE",
            "commandPlanDigest": "0" * 64,
            "commandResults": [],
            "observations": [{"name": "fixture", "status": "pass", "detail": {"ok": True}}],
            "nativeNonPassCount": 0,
            "internalRunnerFailures": [],
        }

    @staticmethod
    def failing_report() -> dict:
        report = StaticExecutionAuthorityTest.passing_report()
        report["observations"] = [{"name": "fixture", "status": "fail", "detail": {"ok": False}}]
        report["nativeNonPassCount"] = 1
        return report

    @staticmethod
    def gate(runner: ci.FoundationRunner, gate_id: str) -> dict:
        return next(item for item in runner.hard_gate_results if item["id"] == gate_id)

    @classmethod
    def framed(cls, report: dict) -> bytes:
        document = copy.deepcopy(report)
        document["invocationId"] = str(cls.INVOCATION_UUID)
        return (json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")

    def test_real_static_machine_producer_source_compiles(self) -> None:
        source = (ci.REPO_ROOT / ci.STATIC_SUITE_RELATIVE_PATH).read_bytes()
        compile(source, ci.STATIC_SUITE_RELATIVE_PATH, "exec")

    def test_exit_zero_with_passing_json_passes_execution(self) -> None:
        runner, report_exists = self.exercise(contained_capture(), report=self.passing_report())
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "pass")
        self.assertEqual(runner.observations[0]["outcome"], "pass")
        self.assertFalse(report_exists)

    def test_exit_zero_with_failing_json_records_semantic_failure(self) -> None:
        runner, _ = self.exercise(contained_capture(), report=self.failing_report())
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "pass")
        self.assertEqual(runner.observations[0]["outcome"], "fail")
        self.assertEqual(runner.static_machine_report["executionStatus"], "COMPLETE")

    def test_exit_zero_with_malformed_json_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(contained_capture(), report=b"not-json\n")
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_exit_seven_with_passing_json_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(contained_capture(exit_code=7), report=self.passing_report())
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_timeout_124_with_passing_json_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(
            contained_capture(exit_code=124, timed_out=True),
            report=self.passing_report(),
        )
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_output_limit_125_with_passing_json_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(
            contained_capture(exit_code=125, output_limited=True),
            report=self.passing_report(),
        )
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_process_tree_cleanup_failure_with_passing_json_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(
            contained_capture(process_tree_status="cleanup-failed"),
            report=self.passing_report(),
        )
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_stale_passing_report_and_child_failure_is_a_hard_failure(self) -> None:
        runner, report_exists = self.exercise(
            contained_capture(exit_code=7),
            report=None,
            stale_report=self.passing_report(),
        )
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])
        self.assertTrue(report_exists)

    def test_exit_zero_without_new_report_is_a_hard_failure(self) -> None:
        runner, _ = self.exercise(contained_capture(), report=None)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")
        self.assertEqual(runner.observations, [])

    def test_machine_invocation_id_mismatch_fails_execution(self) -> None:
        report = self.passing_report()
        report["invocationId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        data = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        runner, _ = self.exercise(contained_capture(), report=data)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_machine_document_kind_mismatch_fails_execution(self) -> None:
        report = self.passing_report()
        report["documentKind"] = "forged-kind"
        runner, _ = self.exercise(contained_capture(), report=report)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_two_json_documents_fail_execution(self) -> None:
        data = self.framed(self.passing_report()) + self.framed(self.passing_report())
        runner, _ = self.exercise(contained_capture(), report=data)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_valid_json_plus_trailing_text_fails_execution(self) -> None:
        data = self.framed(self.passing_report())[:-1] + b"forged\n"
        runner, _ = self.exercise(contained_capture(), report=data)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_incomplete_json_fails_execution(self) -> None:
        data = self.framed(self.passing_report())[:40] + b"\n"
        runner, _ = self.exercise(contained_capture(), report=data)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_bom_and_invalid_utf8_fail_execution(self) -> None:
        for data in (b"\xef\xbb\xbf" + self.framed(self.passing_report()), b"\xff\n"):
            with self.subTest(data=data[:4]):
                runner, _ = self.exercise(contained_capture(), report=data)
                self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_complete_report_cannot_contain_internal_runner_failures(self) -> None:
        report = self.passing_report()
        report["internalRunnerFailures"] = ["forged internal failure"]
        runner, _ = self.exercise(contained_capture(), report=report)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_contradictory_native_nonpass_count_fails_closed(self) -> None:
        report = self.failing_report()
        report["nativeNonPassCount"] = 0
        runner, _ = self.exercise(contained_capture(), report=report)
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "fail")

    def test_preexisting_or_replaced_report_file_cannot_override_pipe(self) -> None:
        runner, report_exists = self.exercise(
            contained_capture(),
            report=self.passing_report(),
            stale_report=self.failing_report(),
        )
        self.assertEqual(self.gate(runner, "STATIC-SUITE-EXECUTION")["status"], "pass")
        self.assertTrue(report_exists)


class TrustedExecutionTest(unittest.TestCase):
    def test_caller_executable_overrides_are_rejected(self) -> None:
        source = {
            "PATH": os.environ.get("PATH", ""),
            "NODE_EXE": "C:/workspace/node.exe",
            "NPM_EXE": "C:/workspace/npm.cmd",
            "PYTHON_EXE": "C:/workspace/python.exe",
            "GIT_EXE": "C:/workspace/git.exe",
            "POWERSHELL_EXE": "C:/workspace/powershell.exe",
            "BASH_EXE": "C:/workspace/bash.exe",
        }
        _tools, errors = ci.resolve_trusted_tools({"python"}, source_environment=source)
        for override in source.keys() - {"PATH"}:
            self.assertTrue(any(override in error for error in errors), (override, errors))

    def test_workspace_first_path_and_fake_tools_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            fake_bin = repo / "bin"
            fake_bin.mkdir()
            names = ("node.exe", "npm.cmd", "python.exe", "git.exe") if os.name == "nt" else ("node", "npm", "python", "git")
            for name in names:
                path = fake_bin / name
                path.write_text("fake", encoding="utf-8")
                path.chmod(0o755)
            source = {"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")}
            _tools, errors = ci.resolve_trusted_tools(
                {"python", "node", "npm", "git"},
                source_environment=source,
                repo_root=repo,
            )
            self.assertTrue(errors)
            self.assertTrue(any("precedes" in error or "unavailable" in error for error in errors), errors)

    def test_minimal_child_does_not_inherit_credentials(self) -> None:
        source = {
            "PATH": str(Path(sys.executable).parent),
            "HOME": "home",
            "EXAMPLE_TOKEN": "private-token",
            "AUTHORIZATION": "Bear" + "er private",
            "NODE_OPTIONS": "--require ./attacker.js",
            "POWERSHELL_EXE": "attacker-shell",
            "BASH_EXE": "attacker-bash",
            "GIT_CONFIG_COUNT": "99",
            "GIT_CONFIG_KEY_0": "include.path",
            "GIT_CONFIG_VALUE_0": "attacker-config",
        }
        environment = ci.child_process_environment(
            {
                "python": sys.executable,
                "git": sys.executable,
                "powershell": sys.executable,
                "bash": sys.executable,
            },
            source_environment=source,
        )
        capture = ci.execute_command(
            "credential-inheritance",
            "unit",
            [sys.executable, "-c", "import os; print('present' if 'EXAMPLE_TOKEN' in os.environ else 'absent')"],
            timeout=10,
            env=environment,
        )
        self.assertEqual(capture.exit_code, 0)
        self.assertEqual(capture.stdout.strip(), "absent")
        self.assertEqual(environment["POWERSHELL_EXE"], str(Path(sys.executable).resolve()))
        self.assertEqual(environment["BASH_EXE"], str(Path(sys.executable).resolve()))
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "safe.directory")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], str(ci.REPO_ROOT.resolve()))

    def test_trusted_file_mutation_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "trusted.txt"
            path.write_text("before", encoding="utf-8")
            before, errors = ci.snapshot_trusted_files(repo_root=root, paths=("trusted.txt",))
            self.assertEqual(errors, [])
            path.write_text("after", encoding="utf-8")
            after, errors = ci.snapshot_trusted_files(repo_root=root, paths=("trusted.txt",))
            self.assertEqual(errors, [])
            self.assertTrue(ci.compare_trusted_snapshots(before, after))

    def test_unbounded_child_stdout_is_terminated(self) -> None:
        environment = ci.child_process_environment({"python": sys.executable}, source_environment=os.environ)
        capture = ci.execute_command(
            "large-output",
            "unit",
            [sys.executable, "-c", "for _ in range(100000): print('x' * 100)"],
            timeout=20,
            env=environment,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            max_line_bytes=1024,
        )
        self.assertTrue(capture.output_limited)
        self.assertEqual(capture.exit_code, 125)
        evidence = capture.evidence()
        self.assertEqual(evidence["outputLimitStatus"], "OUTPUT-LIMIT-EXCEEDED")
        self.assertLessEqual(
            len(evidence.get("diagnosticPreview", "").encode("utf-8")),
            ci.MAX_EVIDENCE_PREVIEW_BYTES,
        )

    def test_excessive_output_line_is_terminated(self) -> None:
        environment = ci.child_process_environment({"python": sys.executable}, source_environment=os.environ)
        capture = ci.execute_command(
            "long-line",
            "unit",
            [sys.executable, "-c", "print('y' * 5000, end='')"],
            timeout=10,
            env=environment,
            max_stdout_bytes=8192,
            max_stderr_bytes=8192,
            max_line_bytes=128,
        )
        self.assertTrue(capture.output_limited)
        self.assertIn("line length", capture.limit_reason or "")

    def test_nul_delimited_records_respect_line_limit(self) -> None:
        environment = ci.child_process_environment({"python": sys.executable}, source_environment=os.environ)
        capture = ci.execute_command(
            "nul-records",
            "unit",
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write((b'x' * 64 + b'\\0') * 100)",
            ],
            timeout=10,
            env=environment,
            max_stdout_bytes=8192,
            max_stderr_bytes=8192,
            max_line_bytes=128,
        )
        self.assertEqual(capture.exit_code, 0)
        self.assertFalse(capture.output_limited)
        self.assertEqual(capture.stdout.count("\0"), 100)

    def test_command_evidence_records_actual_argv_but_not_full_output(self) -> None:
        capture = ci.CommandCapture(
            command_id="evidence-shape",
            command_class="unit",
            argv=["tool", "private-argument"],
            executed=True,
            exit_code=1,
            duration_seconds=0.1,
            stdout="bounded diagnostic",
            stderr="",
            stdout_bytes=18,
        )
        evidence = capture.evidence()
        self.assertNotIn("argv", evidence)
        self.assertNotIn("stdout", evidence)
        self.assertNotIn("stderr", evidence)
        self.assertEqual(evidence["actualExecutionArgv"], ["tool", "private-argument"])
        self.assertRegex(evidence["stdoutSha256"], r"^[0-9a-f]{64}$")


@unittest.skipUnless(os.name == "nt", "Windows Git Bash policy")
class WindowsGitBashResolutionTest(unittest.TestCase):
    def make_git_install(self, root: Path, *, bin_bash: bool = True, usr_bash: bool = False) -> Path:
        git = root / "cmd" / "git.exe"
        git.parent.mkdir(parents=True)
        git.write_bytes(b"git")
        if bin_bash:
            bash = root / "bin" / "bash.exe"
            bash.parent.mkdir(parents=True)
            bash.write_bytes(b"bash")
        if usr_bash:
            bash = root / "usr" / "bin" / "bash.exe"
            bash.parent.mkdir(parents=True)
            bash.write_bytes(b"bash")
        return git

    def resolve_fixture(self, git: Path, repo: Path) -> tuple[str | None, list[str]]:
        with (
            mock.patch.object(ci, "_unsafe_tool_path_reason", return_value=None),
            mock.patch.object(ci, "_tool_location_is_allowlisted", return_value=True),
        ):
            return ci.resolve_trusted_git_bash(
                str(git),
                source_environment={"SystemRoot": r"C:\Windows"},
                repo_root=repo,
            )

    def make_executable_lease_install(self, root: Path) -> tuple[Path, Path]:
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        command_processor = system_root / "System32" / "cmd.exe"
        self.assertTrue(command_processor.is_file())
        git = root / "cmd" / "git.exe"
        bash = root / "bin" / "bash.exe"
        git.parent.mkdir(parents=True)
        bash.parent.mkdir(parents=True)
        shutil.copy2(command_processor, git)
        shutil.copy2(command_processor, bash)
        return git, bash

    def test_trusted_git_root_prefers_bin_bash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-git-bash-valid-") as temp_dir:
            root = Path(temp_dir) / "Git"
            git = self.make_git_install(root, bin_bash=True, usr_bash=True)
            bash, errors = self.resolve_fixture(git, Path(temp_dir) / "repo")
        self.assertEqual(errors, [])
        self.assertTrue(str(bash).casefold().endswith("/bin/bash.exe") or str(bash).casefold().endswith("\\bin\\bash.exe"))

    def test_program_files_style_git_bash_is_accepted_when_trusted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-program-files-") as temp_dir:
            root = Path(temp_dir) / "Program Files" / "Git"
            git = self.make_git_install(root)
            bash, errors = self.resolve_fixture(git, Path(temp_dir) / "repo")
        self.assertIsNotNone(bash)
        self.assertEqual(errors, [])

    def test_workspace_and_node_modules_fake_bash_are_rejected(self) -> None:
        for relative in (Path("repo") / "Git", Path("node_modules") / "Git"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory(
                prefix="ci-git-bash-reject-"
            ) as temp_dir:
                root = Path(temp_dir) / relative
                git = self.make_git_install(root)
                (Path(temp_dir) / "repo").mkdir(exist_ok=True)
                bash, errors = ci.resolve_trusted_git_bash(
                    str(git),
                    source_environment={"SystemRoot": r"C:\Windows"},
                    repo_root=Path(temp_dir) / "repo",
                )
            self.assertIsNone(bash)
            self.assertTrue(errors)

    def test_reparse_chain_and_git_root_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-git-bash-chain-") as temp_dir:
            root = Path(temp_dir) / "GitA"
            git = self.make_git_install(root, bin_bash=True)
            with (
                mock.patch.object(ci, "_unsafe_tool_path_reason", return_value=None),
                mock.patch.object(ci, "_tool_location_is_allowlisted", return_value=True),
                mock.patch.object(ci, "_non_reparse_directory_chain", return_value=False),
            ):
                bash, errors = ci.resolve_trusted_git_bash(
                    str(git), source_environment={"SystemRoot": r"C:\Windows"}
                )
            self.assertIsNone(bash)
            self.assertTrue(any("reparse" in error for error in errors), errors)

            (root / "bin" / "bash.exe").unlink()
            other = Path(temp_dir) / "GitB" / "bin" / "bash.exe"
            other.parent.mkdir(parents=True)
            other.write_bytes(b"bash")
            bash, errors = self.resolve_fixture(git, Path(temp_dir) / "repo")
            self.assertIsNone(bash)
            self.assertTrue(any("unavailable" in error for error in errors), errors)

    def test_system32_first_never_drives_bash_selection(self) -> None:
        git_cmd = Path(r"D:\Git\cmd")
        git_bash = Path(r"D:\Git\bin\bash.exe")
        if not git_cmd.is_dir() or not git_bash.is_file():
            self.skipTest("trusted D:\\Git fixture is unavailable")
        source = {
            "PATH": os.pathsep.join([r"C:\Windows\System32", str(git_cmd)]),
            "SystemRoot": r"C:\Windows",
            "WINDIR": r"C:\Windows",
        }
        original_which = shutil.which
        calls: list[str] = []

        def recording_which(name: str, **kwargs):
            calls.append(name)
            return original_which(name, **kwargs)

        with mock.patch.object(ci.shutil, "which", side_effect=recording_which):
            tools, errors = ci.resolve_trusted_tools(
                {"git", "bash"}, source_environment=source
            )
        self.assertEqual(errors, [])
        self.assertEqual(Path(tools["bash"]).resolve(), git_bash.resolve())
        self.assertNotIn("bash", calls)
        self.assertNotIn("wsl", calls)

    def test_system32_only_fails_without_wsl_or_bash_lookup(self) -> None:
        source = {
            "PATH": r"C:\Windows\System32",
            "SystemRoot": r"C:\Windows",
            "WINDIR": r"C:\Windows",
        }
        calls: list[str] = []

        def no_tools(name: str, **_kwargs):
            calls.append(name)
            return None

        with mock.patch.object(ci.shutil, "which", side_effect=no_tools):
            tools, errors = ci.resolve_trusted_tools(
                {"git", "bash"}, source_environment=source
            )
        self.assertNotIn("bash", tools)
        self.assertTrue(errors)
        self.assertEqual(calls, ["git"])

    def test_git_bash_product_verification_uses_absolute_candidate(self) -> None:
        bash = Path(r"D:\Git\bin\bash.exe")
        if not bash.is_file():
            self.skipTest("trusted D:\\Git Bash is unavailable")
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        invoked: list[list[str]] = []

        def fake_execute(command_id, command_class, argv, **_kwargs):
            invoked.append(list(argv))
            output = {
                "node-version": "v24.0.0\n",
                "npm-version": "11.0.0\n",
                "git-bash-version": "GNU bash, version 5.2.37(1)-release\n",
            }[command_id]
            capture = contained_capture()
            capture.command_id = command_id
            capture.command_class = command_class
            capture.argv = list(argv)
            capture.stdout = output
            capture.stdout_raw = output.encode("utf-8")
            capture.stdout_bytes = len(capture.stdout_raw)
            return capture

        runner = ci.FoundationRunner(
            "static",
            baseline,
            tools={
                "python": sys.executable,
                "node": sys.executable,
                "npm": sys.executable,
                "git": r"D:\Git\cmd\git.exe",
                "bash": str(bash.resolve()),
            },
            source_environment=os.environ,
        )
        try:
            with mock.patch.object(ci, "execute_command", side_effect=fake_execute):
                runner.run_runtime_policy()
            gate = next(
                item for item in runner.hard_gate_results
                if item["id"] == "GIT-BASH-TRUSTED-RUNTIME"
            )
            self.assertEqual(gate["status"], "pass")
            bash_argv = next(
                argv for argv in invoked
                if argv[-1] == "--version" and argv[0] == str(bash.resolve())
            )
            self.assertTrue(Path(bash_argv[0]).is_absolute())
            self.assertNotIn("system32", bash_argv[0].casefold())
            self.assertNotIn("wsl", bash_argv[0].casefold())
        finally:
            runner.cleanup_task_resources()

    def test_bash_identity_lease_denies_complete_replacement_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-bash-lease-") as temp_dir:
            root = Path(temp_dir) / "Git"
            git, bash = self.make_executable_lease_install(root)
            original_hash = ci._sha256_file(bash)
            replacement = Path(temp_dir) / "replacement.exe"
            replacement_bytes = bytearray(bash.read_bytes())
            replacement_bytes[-1] ^= 1
            replacement.write_bytes(replacement_bytes)
            self.assertEqual(replacement.stat().st_size, bash.stat().st_size)
            self.assertNotEqual(ci._sha256_file(replacement), original_hash)

            lease = ci.TrustedBashLease(str(bash), str(git))
            try:
                # Replacement after resolution but before product verification.
                with self.assertRaises(OSError):
                    bash.write_bytes(replacement_bytes)
                self.assertEqual(lease.verify(), (True, None))

                product = ci.execute_command(
                    "lease-product-verification",
                    "runtime-identity",
                    [lease.path, "/d", "/c", "echo GNU bash version 5.2.37"],
                    timeout=10,
                    executable_lease=lease,
                )
                self.assertTrue(product.execution_passed(), product.error)
                self.assertIn("GNU bash version 5.2.37", product.stdout)

                # Rename replacement after verification but before execution.
                with self.assertRaises(OSError):
                    os.replace(replacement, bash)
                with self.assertRaises(OSError):
                    bash.rename(Path(temp_dir) / "renamed-bash.exe")
                with self.assertRaises(OSError):
                    bash.unlink()
                self.assertEqual(lease.verify(), (True, None))

                hardlink = Path(temp_dir) / "bash-hardlink.exe"
                try:
                    os.link(bash, hardlink)
                except OSError:
                    hardlink = None
                if hardlink is not None:
                    with self.assertRaises(OSError):
                        hardlink.write_bytes(replacement_bytes)

                sentinel = Path(temp_dir) / "original-executed.txt"
                sleeper = Path(temp_dir) / "lease-sleeper.py"
                sleeper.write_text(
                    "import pathlib,time\n"
                    "time.sleep(1)\n"
                    f"pathlib.Path({str(sentinel)!r}).write_text('original', encoding='utf-8')\n",
                    encoding="utf-8",
                )
                command = f"{Path(sys.executable).resolve()} -B {sleeper}"
                captures: list[ci.CommandCapture] = []
                worker = threading.Thread(
                    target=lambda: captures.append(
                        ci.execute_command(
                            "lease-real-execution",
                            "unit",
                            [lease.path, "/d", "/c", command],
                            timeout=10,
                            executable_lease=lease,
                        )
                    )
                )
                worker.start()
                time.sleep(0.2)
                # Replacement during a contained execution remains denied.
                with self.assertRaises(OSError):
                    bash.write_bytes(replacement_bytes)
                worker.join(timeout=15)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(captures), 1)
                self.assertTrue(
                    captures[0].execution_passed(),
                    (
                        captures[0].exit_code,
                        captures[0].error,
                        captures[0].stdout,
                        captures[0].stderr,
                        captures[0].process_tree_status,
                    ),
                )
                self.assertEqual(sentinel.read_text(encoding="utf-8").strip(), "original")
                self.assertEqual(ci._sha256_file(bash), original_hash)
                self.assertEqual(lease.verify(), (True, None))
            finally:
                lease.close()

            # Closing the lease releases the fixture lock; no executable handle leaks.
            os.replace(replacement, bash)
            self.assertNotEqual(ci._sha256_file(bash), original_hash)

    def test_junction_substitution_cannot_redirect_a_canonical_bash_lease(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-bash-junction-") as temp_dir:
            root = Path(temp_dir)
            target = root / "TargetGit"
            alternate = root / "AlternateGit"
            target_git, target_bash = self.make_executable_lease_install(target)
            _alternate_git, alternate_bash = self.make_executable_lease_install(alternate)
            alternate_bytes = bytearray(alternate_bash.read_bytes())
            alternate_bytes[-1] ^= 1
            alternate_bash.write_bytes(alternate_bytes)
            self.assertNotEqual(ci._sha256_file(target_bash), ci._sha256_file(alternate_bash))

            alias = root / "GitAlias"
            command_processor = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")

            def create_junction(destination: Path) -> None:
                completed = subprocess.run(
                    [command_processor, "/d", "/c", "mklink", "/J", str(alias), str(destination)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

            create_junction(target)
            lease = ci.TrustedBashLease(
                str(alias / "bin" / "bash.exe"),
                str(alias / "cmd" / "git.exe"),
            )
            try:
                self.assertEqual(Path(lease.path), target_bash.resolve())
                os.rmdir(alias)
                create_junction(alternate)
                self.assertEqual((alias / "bin" / "bash.exe").resolve(), alternate_bash.resolve())
                self.assertEqual(lease.verify(), (True, None))
                capture = ci.execute_command(
                    "junction-substitution",
                    "unit",
                    [lease.path, "/d", "/c", "echo GNU bash version 5.2.37"],
                    timeout=10,
                    executable_lease=lease,
                )
                self.assertTrue(capture.execution_passed(), capture.error)
                self.assertEqual(Path(capture.argv[0]), target_bash.resolve())
                self.assertNotEqual(Path(capture.argv[0]), alternate_bash.resolve())
            finally:
                lease.close()


class ProcessTreeContainmentTest(unittest.TestCase):
    def execute_python(
        self,
        source: str,
        *,
        timeout: int = 10,
        max_stdout_bytes: int = 4096,
        max_stderr_bytes: int = 4096,
        max_line_bytes: int = 1024,
    ) -> ci.CommandCapture:
        environment = ci.child_process_environment(
            {"python": sys.executable},
            source_environment=os.environ,
        )
        return ci.execute_command(
            "process-tree-probe",
            "unit",
            [sys.executable, "-c", source],
            timeout=timeout,
            env=environment,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            max_line_bytes=max_line_bytes,
        )

    def test_output_limit_kills_sleeping_child_before_sentinel(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-tree-child-") as temp_dir:
            sentinel = Path(temp_dir) / "child-survived.txt"
            child_source = f"import time,pathlib; time.sleep(1); pathlib.Path({str(sentinel)!r}).write_text('bad')"
            parent_source = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child_source!r}]); "
                "sys.stdout.write('x'*200000); sys.stdout.flush(); time.sleep(20)"
            )
            capture = self.execute_python(parent_source)
            time.sleep(1.3)
            self.assertTrue(capture.output_limited)
            self.assertEqual(capture.exit_code, 125)
            self.assertEqual(capture.process_tree_status, "contained-clean")
            self.assertFalse(sentinel.exists())

    def test_output_limit_kills_grandchild_through_intermediate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-tree-grandchild-") as temp_dir:
            sentinel = Path(temp_dir) / "grandchild-survived.txt"
            grandchild = f"import time,pathlib; time.sleep(1); pathlib.Path({str(sentinel)!r}).write_text('bad')"
            intermediate = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]); time.sleep(20)"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{intermediate!r}]); "
                "sys.stdout.write('g'*200000); sys.stdout.flush(); time.sleep(20)"
            )
            capture = self.execute_python(parent)
            time.sleep(1.3)
            self.assertEqual(capture.exit_code, 125)
            self.assertEqual(capture.process_tree_status, "contained-clean")
            self.assertFalse(sentinel.exists())

    def test_successful_parent_cannot_leave_daemon_child_alive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-tree-success-") as temp_dir:
            sentinel = Path(temp_dir) / "daemon-survived.txt"
            child = f"import time,pathlib; time.sleep(1); pathlib.Path({str(sentinel)!r}).write_text('bad')"
            parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}])"
            capture = self.execute_python(parent)
            time.sleep(1.3)
            self.assertEqual(capture.exit_code, 0)
            self.assertTrue(capture.execution_passed())
            self.assertGreaterEqual(capture.descendants_terminated, 1)
            self.assertFalse(sentinel.exists())

    def test_timeout_escalation_kills_child_that_ignores_sigterm(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-tree-ignore-") as temp_dir:
            sentinel = Path(temp_dir) / "ignored-termination.txt"
            child = (
                "import signal,time,pathlib; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"time.sleep(2); pathlib.Path({str(sentinel)!r}).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(20)"
            )
            capture = self.execute_python(parent, timeout=1)
            time.sleep(2.2)
            self.assertEqual(capture.exit_code, 124)
            self.assertTrue(capture.timed_out)
            self.assertEqual(capture.process_tree_status, "contained-clean")
            self.assertFalse(sentinel.exists())

    def test_concurrent_stdout_and_stderr_descendants_are_contained(self) -> None:
        writer_out = "import sys,time; [sys.stdout.write('o'*200+'\\n') for _ in range(2000)]; sys.stdout.flush(); time.sleep(20)"
        writer_err = "import sys,time; [sys.stderr.write('e'*200+'\\n') for _ in range(2000)]; sys.stderr.flush(); time.sleep(20)"
        parent = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable,'-c',{writer_out!r}]); "
            f"subprocess.Popen([sys.executable,'-c',{writer_err!r}]); time.sleep(20)"
        )
        capture = self.execute_python(parent, max_line_bytes=512)
        self.assertEqual(capture.exit_code, 125)
        self.assertTrue(capture.output_limited)
        self.assertEqual(capture.process_tree_status, "contained-clean")

    def test_cleanup_failure_marks_required_command_failed(self) -> None:
        capture = contained_capture(process_tree_status="cleanup-failed")
        runner = object.__new__(ci.FoundationRunner)
        runner.captures = []
        runner.command_results = []
        runner.hard_gate_results = []
        runner.violations = []
        self.assertFalse(runner.require_command_success(capture, "TREE-CLEANUP"))
        self.assertEqual(runner.hard_gate_results[-1]["status"], "fail")

    @unittest.skipUnless(os.name == "nt", "Windows Job Object assertion")
    def test_windows_commands_use_kill_on_close_job_object(self) -> None:
        capture = self.execute_python("print('ok')")
        self.assertEqual(capture.exit_code, 0)
        self.assertEqual(capture.containment, "windows-job-object")
        self.assertEqual(capture.process_tree_status, "contained-clean")


class StreamedSecretScanTest(unittest.TestCase):
    def scan_bytes(self, content: bytes, name: str = "fixture.bin") -> dict:
        with tempfile.TemporaryDirectory(prefix="ci-secret-encoding-") as temp_dir:
            path = Path(temp_dir) / name
            path.write_bytes(content)
            return ci.scan_file_for_secrets(path)

    def test_utf16le_and_utf16be_credential_matrix_fails(self) -> None:
        github = "github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        credentials = {
            "github": github,
            "bearer": "Authorization:" + " Bearer " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            "basic": "Proxy-Authorization:" + " Basic " + "dXNlcjpwYXNzd29yZA==",
            "url": "https://" + "alice:" + "RealPassword987@example.invalid/path",
            "cookie": "Cookie:" + " session=" + "PrivateCookieValue987654321",
            "session": "session_" + "id=" + "SessionIdentifierABC987654321",
            "private-key": "-----BEGIN OPENSSH PRIVATE " + "KEY-----",
        }
        encodings = {
            "le-bom": lambda value: b"\xff\xfe" + value.encode("utf-16le"),
            "be-bom": lambda value: b"\xfe\xff" + value.encode("utf-16be"),
            "le-no-bom": lambda value: value.encode("utf-16le"),
            "be-no-bom": lambda value: value.encode("utf-16be"),
        }
        for credential_name, value in credentials.items():
            for encoding_name, encode in encodings.items():
                with self.subTest(credential=credential_name, encoding=encoding_name):
                    result = self.scan_bytes(encode("safe prefix\r\n" + value + "\r\nsafe suffix"))
                    self.assertFalse(result["passed"], result)
                    self.assertEqual(result["rawBytesScanned"], result["fileSize"])
                    self.assertEqual(
                        result["encodingViewsApplied"],
                        ["raw-bytes", *ci.UTF16_ASCII_CREDENTIAL_VIEWS],
                    )

    def test_ascii_prefix_cannot_gate_full_file_utf16_scanning(self) -> None:
        token = "github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        fixtures = {
            "le-after-8192": b"a" * 8192 + token.encode("utf-16le"),
            "be-after-8192": b"a" * 8192 + token.encode("utf-16be"),
            "le-after-64k": b"a" * 65_536 + token.encode("utf-16le"),
            "be-after-2m": b"a" * (2 * 1024 * 1024) + token.encode("utf-16be"),
        }
        for name, content in fixtures.items():
            with self.subTest(name=name):
                result = self.scan_bytes(content)
            self.assertFalse(result["passed"], result)
            self.assertIn("github-token", result["hits"])
            self.assertEqual(result["rawBytesScanned"], len(content))

    def test_utf16_odd_offset_and_final_chunk_boundaries_fail(self) -> None:
        credential = "Author" + "ization: Bear" + "er ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        fixtures = (
            b"x" + credential.encode("utf-16le"),
            b"x" + credential.encode("utf-16be"),
            b"safe" * 17 + credential.encode("utf-16le") + b"z",
            b"safe" * 17 + credential.encode("utf-16be") + b"z",
        )
        for content in fixtures:
            with self.subTest(size=len(content)), mock.patch.object(
                ci, "SECRET_SCAN_CHUNK_BYTES", 13
            ):
                result = self.scan_bytes(content)
            self.assertFalse(result["passed"], result)
            self.assertTrue(
                {"authorization-header", "authorization-credential"} & set(result["hits"]),
                result,
            )

    def test_exact_94_byte_utf16le_review_fixture_fails(self) -> None:
        fixture = ("github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").encode("utf-16le")
        self.assertEqual(len(fixture), 94)
        result = self.scan_bytes(fixture)
        self.assertFalse(result["passed"], result)
        self.assertIn("github-token", result["hits"])

    def test_utf16_bom_and_code_unit_split_across_reads_still_fail(self) -> None:
        token = "github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        content = b"\xff\xfe" + ("safe " + token).encode("utf-16le")
        with mock.patch.object(ci, "SECRET_SCAN_CHUNK_BYTES", 1):
            result = self.scan_bytes(content)
        self.assertFalse(result["passed"], result)
        self.assertIn("github-token", result["hits"])

    def test_utf16_token_chunk_final_and_large_file_boundaries_fail(self) -> None:
        token = "github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        fixtures = {
            "chunk-split": ("a" * 31 + " " + token + " tail").encode("utf-16le"),
            "final-chunk": ("safe text " + token).encode("utf-16be"),
            "after-two-mib": ("a" * 1_050_000 + " " + token).encode("utf-16le"),
        }
        for name, content in fixtures.items():
            chunk_size = 17 if name == "chunk-split" else ci.SECRET_SCAN_CHUNK_BYTES
            with self.subTest(name=name), mock.patch.object(ci, "SECRET_SCAN_CHUNK_BYTES", chunk_size):
                result = self.scan_bytes(content)
            self.assertFalse(result["passed"], result)
            self.assertIn("github-token", result["hits"])
            self.assertEqual(result["rawBytesScanned"], len(content))

    def test_safe_utf16_and_incidental_nul_binary_do_not_false_positive(self) -> None:
        for content in (
            b"\xff\xfe" + "This is safe UTF-16 text.\r\nNo credentials here.".encode("utf-16le"),
            b"\xfe\xff" + "This is safe UTF-16 text.\r\nNo credentials here.".encode("utf-16be"),
        ):
            result = self.scan_bytes(content)
            self.assertTrue(result["passed"], result)
        binary = self.scan_bytes(b"\x89PNG\r\n\x1a\n\x00safe-binary\x01\x02")
        self.assertTrue(binary["passed"], binary)
        self.assertEqual(
            binary["encodingViewsApplied"],
            ["raw-bytes", *ci.UTF16_ASCII_CREDENTIAL_VIEWS],
        )

    def test_large_secret_after_two_megabytes_crossing_chunk_boundary_fails(self) -> None:
        token = b"github_" + b"pat_" + b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        prefix_length = ci.SECRET_SCAN_CHUNK_BYTES * 31 - 5
        prefix = b"a" * (prefix_length - 1) + b" "
        content = prefix + token + b" " + b"b" * (2_100_000 - prefix_length - len(token) - 1)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "large.txt"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertIn("github-token", result["hits"])
        self.assertGreater(result["scannedBytes"], 2_000_046)

    def test_large_safe_text_file_passes_and_is_fully_scanned(self) -> None:
        content = (b"safe text line\n" * 150_000) + b"end"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "large-safe.txt"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"])
        self.assertEqual(result["scannedBytes"], len(content))

    def test_safe_unrecognized_binary_is_fully_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unknown.bin"
            path.write_bytes(b"unknown\x00binary")
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"])
        self.assertEqual(result["classification"], "binary-scanned")
        self.assertEqual(result["scannedBytes"], result["fileSize"])

    def test_safe_magic_verified_binary_is_scanned_not_exempted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "image.png"
            content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"])
        self.assertEqual(result["classification"], "binary-scanned")
        self.assertEqual(result["scannedBytes"], len(content))
        self.assertEqual(result["patternFamiliesApplied"], list(ci.SECRET_SCAN_PATTERN_FAMILIES))

    def test_png_with_nuls_and_github_token_fails(self) -> None:
        token = b"github_" + b"pat_" + b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "review-fixture.png"
            content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + token
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertEqual(result["classification"], "binary-scanned")
        self.assertEqual(result["scannedBytes"], len(content))
        self.assertIn("github-token", result["hits"])

    def test_png_token_crossing_scan_chunk_boundary_fails(self) -> None:
        token = b"github_" + b"pat_" + b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        magic = b"\x89PNG\r\n\x1a\n"
        prefix = magic + b"\x00" * (ci.SECRET_SCAN_CHUNK_BYTES - 5 - len(magic))
        content = prefix + token + b"tail"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "boundary.png"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertIn("github-token", result["hits"])
        self.assertEqual(result["scannedBytes"], len(content))

    def test_zip_binary_with_authorization_bearer_fails(self) -> None:
        credential = b"Author" + b"ization: " + b"Bearer " + b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        content = b"PK\x03\x04" + b"\x00" * 16 + credential + b"\x00" * 16
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.zip"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertEqual(result["classification"], "binary-scanned")
        self.assertTrue(
            {"authorization-header", "authorization-credential"} & set(result["hits"]),
            result,
        )

    def test_binary_generic_credential_assignment_fails(self) -> None:
        assignment = b"pass" + b"word=CorrectHorseBattery9"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "credential.bin"
            content = b"\x00binary-prefix\x00" + assignment + b"\x00suffix"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertIn("generic-credential-assignment", result["hits"])
        self.assertEqual(result["scannedBytes"], len(content))

    def test_binary_database_credential_url_fails(self) -> None:
        database_url = b"post" + b"gres://app:RealDatabasePassword9@db.example.test/app"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "database.bin"
            content = b"\x00binary-prefix\x00" + database_url + b"\x00suffix"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertIn("credential-database-url", result["hits"])

    def test_database_url_placeholders_are_not_credentials(self) -> None:
        content = (
            b"postgres://postgres:postgres@postgres/test\n"
            b"postgres://postgres:replace-with-a-strong-local-password@localhost/test\n"
            b"postgres://postgres:${DATABASE_PASSWORD}@localhost/test\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / ".env.example"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"], result)

    def test_license_basic_permissions_prose_is_not_a_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "LICENSE.txt"
            path.write_bytes(b"2. Basic Permissions.\n")
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"], result)

    def test_source_identifier_assignments_are_not_credentials(self) -> None:
        content = (
            b"var token = normalizeQuestionTypeToken(value);\n"
            b"const sessionId = state.sessionId;\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "app.js"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"], result)

    def test_short_documented_test_password_is_not_a_secret_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "fixture.js"
            path.write_bytes(b"const body = { password: 'StrongerPass2' };\n")
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"], result)

    def test_binary_private_key_marker_fails(self) -> None:
        marker = b"-----BEGIN OPENSSH PRIVATE " + b"KEY-----"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "key-material.bin"
            content = b"\x00\x01binary" + marker + b"\x00tail"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertIn("private-key-marker", result["hits"])
        self.assertEqual(result["scannedBytes"], len(content))

    def test_large_safe_binary_has_no_size_skip(self) -> None:
        content = b"\x89PNG\r\n\x1a\n" + b"\x00safe-binary-byte" * 150_000
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "large-safe.png"
            path.write_bytes(content)
            result = ci.scan_file_for_secrets(path)
        self.assertTrue(result["passed"])
        self.assertEqual(result["classification"], "binary-scanned")
        self.assertEqual(result["scannedBytes"], len(content))

    def test_binary_read_failure_is_a_hard_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unreadable.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00safe")
            with mock.patch.object(ci.os, "open", side_effect=PermissionError("denied")):
                result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertEqual(result["classification"], "read-error")
        self.assertEqual(result["scannedBytes"], 0)

    def test_binary_reparse_or_link_classification_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "linked.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\n\x00safe")
            with mock.patch.object(ci, "_is_reparse_point", return_value=True):
                result = ci.scan_file_for_secrets(path)
        self.assertFalse(result["passed"])
        self.assertEqual(result["classification"], "rejected-special-file")
        self.assertEqual(result["scannedBytes"], 0)


class CI5DerivedFailureIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls.omission = cls.baseline["expectedOmissions"][0]
        cls.performance = next(
            entry
            for entry in cls.baseline["knownDebts"]
            if entry["id"] == "B-SYNTAX-PERFORMANCE-BASELINE"
        )

    def unknown_static_observation(self, entry: dict | None = None) -> dict:
        selected = entry or self.omission
        name = selected["testOrPathScope"].removeprefix("result:")
        result = {
            "name": name,
            "status": "fail",
            "detail": {
                "assertions": ["unfrozen authorization assertion"],
                "testIds": ["developer/tests/js/unfrozenSecurity.test.js"],
            },
        }
        raw = ci.make_raw_observation(
            "static-suite",
            0,
            0,
            "static-producer-v1",
            name,
            ci.STATIC_SUITE_RELATIVE_PATH,
            result,
            ci.canonical_failure_digest(result),
        )
        return ci.observation(
            "static-suite",
            selected["testOrPathScope"],
            "fail",
            "ignored",
            "static-suite",
            raw_observation=raw,
        )

    def derive_ids(
        self,
        baseline: dict,
        spec: dict,
        records: list[dict],
        observations: list[dict],
        *,
        completed: set[str] | None = None,
        platform_name: str = "ubuntu",
    ) -> list[str]:
        result = ci.derive_authoritative_evidence(
            "static",
            observations,
            completed or set(),
            records,
            baseline,
            platform_name,
            [spec],
        )
        return [item["id"] for item in result["violations"]]

    def test_canonical_encoding_is_stable_type_aware_and_length_framed(self) -> None:
        left = {"beta": [1, "1", None], "alpha": {"flag": True}}
        right = {"alpha": {"flag": True}, "beta": [1, "1", None]}
        self.assertEqual(ci.canonical_failure_digest(left), ci.canonical_failure_digest(right))
        self.assertNotEqual(ci.canonical_failure_digest(1), ci.canonical_failure_digest("1"))
        self.assertNotEqual(
            ci.canonical_failure_digest(["ab", "c"]),
            ci.canonical_failure_digest(["a", "bc"]),
        )
        with self.assertRaises((TypeError, ValueError)):
            ci.canonical_failure_digest({1: "integer", "1": "string"})

    def test_raw_observation_rejects_claimed_derived_authority_fields(self) -> None:
        raw = copy.deepcopy(self.unknown_static_observation()["rawObservation"])
        raw["rawStructuredFields"]["detail"]["structuredFailureSet"] = (
            self.omission["allowedNormalizedSignature"][0]
        )
        raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in raw.items() if key != "producerRecordDigest"}
        )
        errors = ci._validate_raw_observation(raw, label="fixture", source=None)
        self.assertTrue(any("derived or baseline-authority" in error for error in errors), errors)

    def test_self_authorizing_structured_failure_set_is_rejected(self) -> None:
        item = self.unknown_static_observation()
        known = self.omission["allowedNormalizedSignature"][0]
        item["signature"] = known
        item["failureIdentity"] = {
            "scope": self.omission["testOrPathScope"],
            "structuredFailureSet": known,
        }
        item["failureIdentityHash"] = ci.failure_identity_hash(item["failureIdentity"])
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            [item],
            {"static-suite"},
            "ubuntu",
        )
        self.assertIn("UNKNOWN-NONPASS", [value["id"] for value in result["violations"]])

    def test_self_authorizing_failure_identity_digest_is_rejected(self) -> None:
        item = self.unknown_static_observation()
        known = self.omission["allowedNormalizedSignature"][0]
        item["signature"] = known
        item["failureIdentity"] = {"scope": self.omission["testOrPathScope"], "digest": known}
        item["failureIdentityHash"] = ci.failure_identity_hash(item["failureIdentity"])
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            [item],
            {"static-suite"},
            "ubuntu",
        )
        self.assertIn("UNKNOWN-NONPASS", [value["id"] for value in result["violations"]])

    def test_all_claimed_derived_fields_rewritten_to_known_values_are_rejected(self) -> None:
        exact = exact_static_observation(self.omission)
        forged = self.unknown_static_observation()
        for key in (
            "signature",
            "legacyBaselineComparisonDigest",
            "failureIdentity",
            "failureIdentityHash",
            "derivedFailureMembers",
            "derivedFailureDigest",
            "currentFullContextDigest",
            "canonicalFailureMaterialVersion",
        ):
            forged[key] = copy.deepcopy(exact[key])
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            [forged],
            {"static-suite"},
            "ubuntu",
        )
        self.assertIn("UNKNOWN-NONPASS", [value["id"] for value in result["violations"]])

    def test_known_signature_copied_to_another_debt_scope_is_rejected(self) -> None:
        other = next(
            entry
            for entry in self.baseline["knownDebts"]
            if entry["id"] == "B-SYNTAX-STATE-SERIALIZER-TEST"
        )
        item = ci.observation(
            "direct-syntax",
            self.performance["testOrPathScope"],
            self.performance["expectedOutcome"],
            self.performance["allowedNormalizedSignature"][0],
            source_command_id(self.performance),
            failure_identity=structured_identity(self.performance),
        )
        item["testOrPathScope"] = other["testOrPathScope"]
        item["signature"] = other["allowedNormalizedSignature"][0]
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "knownDebts", other),
            [item],
            {"direct-syntax"},
            "windows",
        )
        self.assertIn("UNKNOWN-NONPASS", [value["id"] for value in result["violations"]])

    def test_known_signature_attached_to_wrong_command_is_rejected(self) -> None:
        item = ci.observation(
            "direct-syntax",
            self.performance["testOrPathScope"],
            self.performance["expectedOutcome"],
            self.performance["allowedNormalizedSignature"][0],
            "node-check:developer/tests/js/unrelated.js",
            failure_identity=structured_identity(self.performance),
        )
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "knownDebts", self.performance),
            [item],
            {"direct-syntax"},
            "windows",
        )
        self.assertIn("UNKNOWN-NONPASS", [value["id"] for value in result["violations"]])

    def test_wrong_raw_source_path_is_rejected_after_coherent_rederivation(self) -> None:
        item = exact_static_observation(self.omission)
        spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        raw = copy.deepcopy(bound["rawObservation"])
        raw["sourcePath"] = "developer/tests/ci/unrelated-producer.py"
        raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in raw.items() if key != "producerRecordDigest"}
        )
        record["producerObservations"] = [raw]
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
        forged = ci._rederive_observation_record({"rawObservation": raw}, record)
        ids = self.derive_ids(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            spec,
            [record],
            [forged],
            completed={"static-suite"},
        )
        self.assertIn("MALFORMED-COMMAND-OBSERVATION", ids)

    def test_wrong_target_and_wrong_platform_are_command_authority_failures(self) -> None:
        item = exact_static_observation(self.omission)
        for mode in ("target", "platform"):
            with self.subTest(mode=mode):
                spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
                if mode == "target":
                    record["targets"][0]["sha256"] = "0" * 64
                else:
                    record["platform"] = "windows"
                rebound = ci._rederive_observation_record(bound, record)
                ids = self.derive_ids(
                    one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
                    spec,
                    [record],
                    [rebound],
                    completed={"static-suite"},
                )
                self.assertIn("COMMAND-AUTHORITY-MISMATCH", ids)

    def test_extra_assertion_and_test_id_are_expanded_failures(self) -> None:
        baseline = one_entry_baseline(self.baseline, "knownDebts", self.performance)
        expected = structured_identity(self.performance)
        for key, value in (
            ("assertionNames", "unrelated authorization assertion"),
            ("testIds", "developer/tests/js/unrelatedSecurity.test.js"),
        ):
            with self.subTest(member=key):
                identity = copy.deepcopy(expected)
                identity[key].append(value)
                item = ci.observation(
                    "direct-syntax",
                    self.performance["testOrPathScope"],
                    self.performance["expectedOutcome"],
                    self.performance["allowedNormalizedSignature"][0],
                    source_command_id(self.performance),
                    failure_identity=identity,
                )
                result = ci.compare_observations(
                    baseline, [item], {"direct-syntax"}, "windows"
                )
                self.assertIn(
                    "UNKNOWN-NONPASS", [value["id"] for value in result["violations"]]
                )

    def test_omitted_or_reordered_derived_members_fail_rederivation(self) -> None:
        item = exact_static_observation(self.omission)
        spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        for mode in ("omitted", "reordered"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(bound)
                if mode == "omitted":
                    forged["derivedFailureMembers"].pop()
                else:
                    forged["derivedFailureMembers"].reverse()
                errors = ci._validate_observation_record(
                    forged, 0, {record["commandId"]: record}
                )
                self.assertTrue(any("independently derived" in error for error in errors), errors)

    def test_raw_change_with_claimed_old_digest_fails_rederivation(self) -> None:
        item = exact_static_observation(self.omission)
        _spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        raw = copy.deepcopy(bound["rawObservation"])
        raw["rawStructuredFields"]["detail"]["missingAudio"].append(
            "P1/unfrozen-extra/audio.mp3"
        )
        raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in raw.items() if key != "producerRecordDigest"}
        )
        record["producerObservations"] = [raw]
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
        forged = copy.deepcopy(bound)
        forged["rawObservation"] = raw
        errors = ci._validate_observation_record(forged, 0, {"static-suite": record})
        self.assertTrue(any("independently derived" in error for error in errors), errors)

    def test_coherently_rederived_unknown_raw_change_remains_blocking(self) -> None:
        unknown = self.unknown_static_observation()
        spec, record, bound = minimal_static_evidence_fixture(unknown, platform_name="ubuntu")
        ids = self.derive_ids(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            spec,
            [record],
            [bound],
            completed={"static-suite"},
        )
        self.assertIn("UNKNOWN-NONPASS", ids)

    def test_evidence_observation_without_producer_observation_is_rejected(self) -> None:
        item = exact_static_observation(self.omission)
        spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        record["producerObservations"] = []
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest([])
        ids = self.derive_ids(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            spec,
            [record],
            [bound],
        )
        self.assertIn("MALFORMED-COMMAND-OBSERVATION", ids)

    def test_producer_observation_omitted_from_evidence_is_rejected(self) -> None:
        item = exact_static_observation(self.omission)
        spec, record, _bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        ids = self.derive_ids(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            spec,
            [record],
            [],
        )
        self.assertIn("PRODUCER-OBSERVATION-COMPLETENESS", ids)

    def test_duplicate_producer_observation_split_across_records_is_rejected(self) -> None:
        item = exact_static_observation(self.omission)
        spec, record, bound = minimal_static_evidence_fixture(item, platform_name="ubuntu")
        duplicate = copy.deepcopy(record)
        result = ci.derive_authoritative_evidence(
            "static",
            [bound],
            set(),
            [record, duplicate],
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            "ubuntu",
            [spec, copy.deepcopy(spec)],
        )
        ids = [value["id"] for value in result["violations"]]
        self.assertIn("DUPLICATE-PRODUCER-OBSERVATION", ids)

    def test_exact_current_known_failure_omission_release_and_resolution_survive(self) -> None:
        direct = ci.observation(
            "direct-syntax",
            self.performance["testOrPathScope"],
            self.performance["expectedOutcome"],
            self.performance["allowedNormalizedSignature"][0],
            source_command_id(self.performance),
            failure_identity=structured_identity(self.performance),
        )
        debt_result = ci.compare_observations(
            one_entry_baseline(self.baseline, "knownDebts", self.performance),
            [direct],
            {"direct-syntax"},
            "windows",
        )
        self.assertFalse(debt_result["violations"])
        omission_result = ci.compare_observations(
            one_entry_baseline(self.baseline, "expectedOmissions", self.omission),
            [exact_static_observation(self.omission)],
            {"static-suite"},
            "ubuntu",
        )
        self.assertFalse(omission_result["violations"])
        release = self.baseline["releaseOnlySkips"][0]
        release_result = ci.compare_observations(
            one_entry_baseline(self.baseline, "releaseOnlySkips", release),
            [exact_static_observation(release)],
            {"static-suite"},
            "windows",
        )
        self.assertFalse(release_result["violations"])
        passing = ci.observation(
            "direct-syntax",
            self.performance["testOrPathScope"],
            "pass",
            "pass",
            source_command_id(self.performance),
        )
        resolution = ci.compare_observations(
            one_entry_baseline(self.baseline, "knownDebts", self.performance),
            [passing],
            {"direct-syntax"},
            "windows",
        )
        self.assertEqual(len(resolution["resolvedCandidates"]), 1)


class CI9FrozenReleaseSkipDualSignatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls.entries = {
            entry["id"]: entry for entry in cls.baseline["releaseOnlySkips"]
        }

    def raw(self, entry_id: str, *, observation_ordinal: int = 0) -> dict:
        return frozen_v1_release_skip_raw_observation(
            self.entries[entry_id],
            observation_ordinal=observation_ordinal,
        )

    def item(self, entry_id: str, *, observation_ordinal: int = 0) -> dict:
        entry = self.entries[entry_id]
        raw = self.raw(entry_id, observation_ordinal=observation_ordinal)
        return ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            entry["allowedNormalizedSignature"][0],
            "static-suite",
            raw_observation=raw,
        )

    def fixture(self, *entry_ids: str) -> tuple[dict, dict, list[dict]]:
        items = [
            self.item(entry_id, observation_ordinal=index)
            for index, entry_id in enumerate(entry_ids)
        ]
        return ci9_static_evidence_fixture(items)

    def assert_exact_positive(self, entry_id: str) -> dict:
        entry = self.entries[entry_id]
        _spec, record, observations = self.fixture(entry_id)
        result = ci.compare_observations(
            one_entry_baseline(self.baseline, "releaseOnlySkips", entry),
            observations,
            {"static-suite"},
            "windows",
            command_records=[record],
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual(len(result["releaseOnlySkips"]), 1)
        release = result["releaseOnlySkips"][0]
        expected = entry["allowedNormalizedSignature"][0]
        self.assertEqual(release["legacyBaselineComparisonDigest"], expected)
        self.assertEqual(release["observedSignature"], expected)
        self.assertEqual(
            release["currentFullContextDigest"], release["derivedFailureDigest"]
        )
        self.assertRegex(release["currentFullContextDigest"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(
            release["legacyBaselineComparisonDigest"],
            release["currentFullContextDigest"],
        )
        return release

    def assert_material_split(self, entry_id: str) -> None:
        entry = self.entries[entry_id]
        _spec, record, observations = self.fixture(entry_id)
        item = observations[0]
        raw = item["rawObservation"]
        outputs = ci._raw_failure_outputs(raw, record)
        legacy_material = ci.frozen_v1_release_skip_comparison_material(raw)
        full_material = ci.derive_canonical_failure_material(
            record,
            raw,
            outputs["parserSemantics"],
            outputs["derivedFailureMembers"],
            outputs["signature"],
            outputs["outcome"],
            {
                "producerObservationUniverseDigest": item[
                    "producerObservationUniverseDigest"
                ],
                "producerTranscriptDigest": item["producerTranscriptDigest"],
                "profileCompletedCommandClassSetDigest": item[
                    "profileCompletedCommandClassSetDigest"
                ],
            },
        )
        self.assertEqual(
            ci.derive_frozen_v1_release_skip_signature(raw),
            entry["allowedNormalizedSignature"][0],
        )
        self.assertEqual(
            ci.canonical_failure_digest(full_material), item["currentFullContextDigest"]
        )
        self.assertEqual(next(iter(full_material)), "version")
        self.assertIn("command", full_material)
        self.assertIn("producerObservationUniverseDigest", full_material)
        self.assertIn("producerTranscriptDigest", full_material)
        self.assertNotIn("command", legacy_material["historicalCanonicalDetail"])
        self.assertNotIn(
            "producerTranscriptDigest", legacy_material["historicalCanonicalDetail"]
        )

    def test_pdf_canonical_material_diff_keeps_frozen_v1_stable(self) -> None:
        self.assert_material_split("B-SKIP-PDF-RECONCILIATION")

    def test_checklist_canonical_material_diff_keeps_frozen_v1_stable(self) -> None:
        self.assert_material_split("B-SKIP-CHECKLIST-CONSISTENCY")

    def test_exact_pdf_observation_has_both_independent_digests_and_skips(self) -> None:
        self.assert_exact_positive("B-SKIP-PDF-RECONCILIATION")

    def test_exact_checklist_observation_has_both_independent_digests_and_skips(self) -> None:
        self.assert_exact_positive("B-SKIP-CHECKLIST-CONSISTENCY")

    def test_exact_release_zip_skip_is_preserved(self) -> None:
        self.assert_exact_positive("B-SKIP-RELEASE-ZIP")

    def test_all_three_exact_release_skips_are_nonblocking_in_static(self) -> None:
        ids = (
            "B-SKIP-RELEASE-ZIP",
            "B-SKIP-PDF-RECONCILIATION",
            "B-SKIP-CHECKLIST-CONSISTENCY",
        )
        _spec, record, observations = self.fixture(*ids)
        baseline = copy.deepcopy(self.baseline)
        baseline["knownDebts"] = []
        baseline["expectedOmissions"] = []
        result = ci.compare_observations(
            baseline,
            observations,
            {"static-suite"},
            "windows",
            command_records=[record],
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual(len(result["releaseOnlySkips"]), 3)
        self.assertEqual(
            {record["baselineId"] for record in result["releaseOnlySkips"]}, set(ids)
        )

    def test_raw_signature_drift_matrix_never_reproduces_pdf_authority(self) -> None:
        expected = self.entries["B-SKIP-PDF-RECONCILIATION"][
            "allowedNormalizedSignature"
        ][0]
        base = self.raw("B-SKIP-PDF-RECONCILIATION")
        mutations = {}

        changed_message = copy.deepcopy(base)
        changed_message["rawStructuredFields"]["detail"]["reason"] += "!"
        mutations["message-one-character"] = changed_message

        wrong_command = copy.deepcopy(base)
        wrong_command["commandId"] = "static-suite-copy"
        mutations["wrong-command-id"] = wrong_command

        wrong_kind = copy.deepcopy(base)
        wrong_kind["observationKind"] = "normalized-fields-v1"
        mutations["wrong-observation-kind"] = wrong_kind

        wrong_source_path = copy.deepcopy(base)
        wrong_source_path["sourcePath"] = "developer/tests/ci/unrelated.py"
        mutations["wrong-source-path"] = wrong_source_path

        wrong_name = copy.deepcopy(base)
        wrong_name["rawStructuredFields"]["name"] += "!"
        mutations["wrong-source-test-id"] = wrong_name

        additional = copy.deepcopy(base)
        additional["rawStructuredFields"]["detail"]["extraFailure"] = "visible"
        mutations["additional-failure-member"] = additional

        omitted = copy.deepcopy(base)
        omitted["rawStructuredFields"]["detail"].pop("monaCoverageOk")
        mutations["omitted-failure-member"] = omitted

        for name, raw in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(
                    ci.derive_frozen_v1_release_skip_signature(raw), expected
                )

        duplicate = copy.deepcopy(base)
        duplicate["rawStructuredFields"]["detail"]["invalidStatusRows"] = [
            "same",
            "same",
        ]
        with self.assertRaises(ValueError):
            ci.derive_frozen_v1_release_skip_signature(duplicate)

        ordered = copy.deepcopy(base)
        ordered["rawStructuredFields"]["detail"]["invalidStatusRows"] = ["a", "b"]
        reordered = copy.deepcopy(ordered)
        reordered["rawStructuredFields"]["detail"]["invalidStatusRows"].reverse()
        self.assertNotEqual(
            ci.derive_frozen_v1_release_skip_signature(ordered),
            ci.derive_frozen_v1_release_skip_signature(reordered),
        )

    def test_command_and_current_context_drift_matrix_is_blocking(self) -> None:
        entry = self.entries["B-SKIP-CHECKLIST-CONSISTENCY"]
        spec, record, observations = self.fixture(entry["id"])

        def violations(
            changed_record: dict,
            changed_observations: list[dict],
        ) -> list[dict]:
            result = ci.derive_authoritative_evidence(
                "static",
                changed_observations,
                {"static-suite"},
                [changed_record],
                one_entry_baseline(self.baseline, "releaseOnlySkips", entry),
                "windows",
                [spec],
            )
            return result["violations"]

        record_mutations = {
            "wrong-ordinal": ("ordinal", record["ordinal"] + 1),
            "wrong-command-class": ("commandClass", "direct-syntax"),
            "wrong-profile": ("profile", "all"),
            "wrong-platform": ("platform", "ubuntu"),
            "raw-exit": ("exitCode", 1),
            "execution-input-hash": ("actualExecutionInputSha256", "0" * 64),
            "producer-set-digest": ("producerObservationSetDigest", "1" * 64),
            "completed-command-class": ("completedCommandClass", "direct-syntax"),
        }
        for name, (field, value) in record_mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(record)
                changed[field] = value
                self.assertTrue(violations(changed, copy.deepcopy(observations)), name)

        observation_mutations = {
            "wrong-scope": ("testOrPathScope", "result:wrong"),
            "wrong-command-id": ("commandId", "static-suite-copy"),
            "producer-universe": ("producerObservationUniverseDigest", "2" * 64),
            "producer-transcript": ("producerTranscriptDigest", "3" * 64),
            "completed-class-set": (
                "profileCompletedCommandClassSetDigest",
                "4" * 64,
            ),
        }
        for name, (field, value) in observation_mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(observations)
                changed[0][field] = value
                self.assertTrue(violations(copy.deepcopy(record), changed), name)

    def test_occurrence_ceiling_and_mandatory_release_gate_both_block(self) -> None:
        entry = self.entries["B-SKIP-PDF-RECONCILIATION"]
        raw = self.raw(entry["id"])
        raw["occurrences"] = 2
        raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in raw.items() if key != "producerRecordDigest"}
        )
        item = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            entry["allowedNormalizedSignature"][0],
            "static-suite",
            raw_observation=raw,
        )
        _spec, record, observations = ci9_static_evidence_fixture([item])
        over_ceiling = ci.compare_observations(
            one_entry_baseline(self.baseline, "releaseOnlySkips", entry),
            observations,
            {"static-suite"},
            "windows",
            command_records=[record],
        )
        self.assertIn(
            "BASELINE-OCCURRENCE-LIMIT",
            [violation["id"] for violation in over_ceiling["violations"]],
        )

        _spec, record, observations = self.fixture(entry["id"])
        release_gate = ci.compare_observations(
            one_entry_baseline(self.baseline, "releaseOnlySkips", entry),
            observations,
            {"static-suite"},
            "windows",
            release_gate_required=True,
            command_records=[record],
        )
        self.assertIn(
            "RELEASE-ONLY-SKIP-IN-REQUIRED-GATE",
            [violation["id"] for violation in release_gate["violations"]],
        )

    def test_claimed_signature_and_full_context_forgery_matrix_is_rejected(self) -> None:
        pdf = self.entries["B-SKIP-PDF-RECONCILIATION"]
        checklist = self.entries["B-SKIP-CHECKLIST-CONSISTENCY"]
        exact_pdf = self.item(pdf["id"])
        cases: list[tuple[str, dict, dict]] = []

        changed_raw = self.raw(pdf["id"])
        changed_raw["rawStructuredFields"]["detail"]["reason"] += "!"
        changed_raw["producerRecordDigest"] = ci._producer_record_digest(
            {key: value for key, value in changed_raw.items() if key != "producerRecordDigest"}
        )
        unknown = ci.observation(
            pdf["commandClass"],
            pdf["testOrPathScope"],
            pdf["expectedOutcome"],
            "ignored-claim",
            "static-suite",
            raw_observation=changed_raw,
        )
        for key in (
            "signature",
            "legacyBaselineComparisonDigest",
            "derivedFailureDigest",
            "currentFullContextDigest",
            "derivedFailureMembers",
            "failureIdentity",
            "failureIdentityHash",
            "canonicalFailureMaterialVersion",
        ):
            unknown[key] = copy.deepcopy(exact_pdf[key])
        cases.append(("unknown-claims-pdf", pdf, unknown))

        copied = self.item(checklist["id"])
        copied["signature"] = pdf["allowedNormalizedSignature"][0]
        copied["legacyBaselineComparisonDigest"] = pdf["allowedNormalizedSignature"][0]
        cases.append(("pdf-signature-copied-to-checklist", checklist, copied))

        extra = copy.deepcopy(unknown)
        extra["rawObservation"]["rawStructuredFields"]["detail"][
            "additionalAssertion"
        ] = "must remain visible"
        extra["rawObservation"]["producerRecordDigest"] = ci._producer_record_digest(
            {
                key: value
                for key, value in extra["rawObservation"].items()
                if key != "producerRecordDigest"
            }
        )
        cases.append(("known-signature-on-extra-assertion", pdf, extra))

        for name, entry, forged in cases:
            with self.subTest(name=name):
                result = ci.compare_observations(
                    one_entry_baseline(self.baseline, "releaseOnlySkips", entry),
                    [forged],
                    {"static-suite"},
                    "windows",
                )
                self.assertIn(
                    "UNKNOWN-NONPASS",
                    [violation["id"] for violation in result["violations"]],
                )

    def test_baseline_signature_mutation_fixture_fails_identity_and_authority(self) -> None:
        original = ci.BASELINE_PATH.read_bytes()
        workflow = ci.WORKFLOW_PATH.read_bytes()
        policy = (ci.REPO_ROOT / "docs/CI_POLICY.md").read_bytes()
        targets = [
            ci._target_authority(ci.REPO_ROOT, relative)
            for relative in (
                ".github/workflows/ci.yml",
                "docs/CI_POLICY.md",
                "developer/tests/ci/phase1-ci-baseline.json",
            )
        ]
        for entry_id in (
            "B-SKIP-PDF-RECONCILIATION",
            "B-SKIP-CHECKLIST-CONSISTENCY",
        ):
            with self.subTest(entry_id=entry_id), tempfile.TemporaryDirectory(
                prefix="ci9-baseline-copy-"
            ) as temp_dir:
                candidate = ci.strict_json_loads(original, label="baseline fixture")
                entry = next(
                    item for item in candidate["releaseOnlySkips"] if item["id"] == entry_id
                )
                entry["allowedNormalizedSignature"] = ["sha256:" + "0" * 64]
                fixture = Path(temp_dir) / "phase1-ci-baseline.json"
                fixture.write_text(
                    json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.assertTrue(ci.validate_baseline_document(candidate))
                errors = ci.run_workflow_policy(
                    workflow,
                    policy,
                    fixture.read_bytes(),
                    targets,
                )
                self.assertTrue(
                    any("identity differs" in error for error in errors), errors
                )

    def test_explicit_full_context_digest_binds_every_required_context(self) -> None:
        entry = self.entries["B-SKIP-CHECKLIST-CONSISTENCY"]
        _spec, record, observations = self.fixture(entry["id"])
        item = observations[0]
        raw = item["rawObservation"]
        outputs = ci._raw_failure_outputs(raw, record)
        context = {
            "producerObservationUniverseDigest": item[
                "producerObservationUniverseDigest"
            ],
            "producerTranscriptDigest": item["producerTranscriptDigest"],
            "profileCompletedCommandClassSetDigest": item[
                "profileCompletedCommandClassSetDigest"
            ],
        }

        def full_digest(selected_record: dict, selected_context: dict) -> str:
            return ci.canonical_failure_digest(
                ci.derive_canonical_failure_material(
                    selected_record,
                    raw,
                    outputs["parserSemantics"],
                    outputs["derivedFailureMembers"],
                    outputs["signature"],
                    outputs["outcome"],
                    selected_context,
                )
            )

        original = full_digest(record, context)
        self.assertEqual(original, item["currentFullContextDigest"])
        record_mutations = {
            "command-id": ("commandId", "other"),
            "ordinal": ("ordinal", 99),
            "class": ("commandClass", "other"),
            "profile": ("profile", "all"),
            "platform": ("platform", "ubuntu"),
            "logical-argv": ("logicalArgv", ["other"]),
            "execution-argv": ("executionArgv", ["other"]),
            "cwd": ("cwd", "other"),
            "execution-input": ("actualExecutionInputSha256", "5" * 64),
            "producer-set": ("producerObservationSetDigest", "6" * 64),
            "completed-class": ("completedCommandClass", "other"),
            "targets": ("targets", []),
        }
        for name, (field, value) in record_mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(record)
                changed[field] = value
                self.assertNotEqual(original, full_digest(changed, context))
        for field in context:
            with self.subTest(name=field):
                changed_context = copy.deepcopy(context)
                changed_context[field] = "7" * 64
                self.assertNotEqual(original, full_digest(record, changed_context))
        self.assertEqual(
            ci.derive_frozen_v1_release_skip_signature(raw),
            entry["allowedNormalizedSignature"][0],
        )

    def test_static_profile_command_count_remains_exact(self) -> None:
        runner = ci.FoundationRunner("static", self.baseline)
        try:
            self.assertEqual(runner.command_plan_errors, [])
            self.assertEqual(runner.tool_resolution_errors, [])
            self.assertEqual(len(runner.command_plan), 677)
        finally:
            runner.cleanup_task_resources()


class CI5TargetExecutionLeaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tools, errors = ci.resolve_trusted_tools({"python", "node"})
        if errors or "node" not in tools:
            raise AssertionError(f"trusted Node is required for CI5 target tests: {errors}")
        cls.node = tools["node"]
        cls.environment = ci.child_process_environment(
            {"python": tools.get("python", sys.executable), "node": cls.node}
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ci5-target-lease-")
        self.root = Path(self.temporary.name)
        (self.root / "js").mkdir()
        self.relative = "js/siteContent.js"
        self.target = self.root / "js" / "siteContent.js"
        self.valid_bytes = b"const plannedValue = 1;\n"
        self.invalid_bytes = b"const plannedValue = ;\n".ljust(
            len(self.valid_bytes), b" "
        )
        self.target.write_bytes(self.valid_bytes)
        self.leases: list[ci.TargetExecutionLease] = []

    def tearDown(self) -> None:
        for lease in self.leases:
            lease.close()
        self.temporary.cleanup()

    def plan(self, relative: str | None = None) -> dict:
        selected = relative or self.relative
        target = ci._target_authority(self.root, selected)
        parser_mode = ci._node_stdin_parser_mode(self.root, selected)
        logical = [self.node, "--check", selected]
        execution = [self.node, "--check", f"--input-type={parser_mode}", "-"]
        executable_size, executable_hash, executable_identity = ci._measured_file_authority(
            Path(self.node)
        )
        return {
            "commandId": f"node-check:{selected}",
            "ordinal": 0,
            "commandClass": "direct-syntax",
            "commandRole": "observation-producing",
            "required": True,
            "profile": "static",
            "platform": ci.platform_key(),
            "argv": logical,
            "logicalArgv": logical,
            "executionArgv": execution,
            "executionInputMode": "TARGET-BYTES-STDIN",
            "executionInputSize": target["size"],
            "executionInputSha256": target["sha256"],
            "cwd": ".",
            "toolRole": "node-syntax-check",
            "resolvedExecutablePath": str(Path(self.node).resolve(strict=True)),
            "resolvedExecutableSize": executable_size,
            "resolvedExecutableSha256": executable_hash,
            "resolvedExecutableFileIdentity": executable_identity,
            "executionLease": None,
            "targets": [target],
            "resultSemantics": "exit-zero-pass-exit-one-classified-observation",
            "allowedExecutionExits": [0, 1],
        }

    def execute(self, plan: dict, hook=None) -> tuple[ci.CommandCapture, ci.TargetExecutionLease | None]:
        capture, lease = ci.execute_planned_node_check(
            plan,
            repo_root=self.root,
            env=self.environment,
            timeout=30,
            phase_hook=hook,
        )
        if lease is not None:
            self.leases.append(lease)
        return capture, lease

    def final_record(
        self,
        plan: dict,
        capture: ci.CommandCapture,
        lease: ci.TargetExecutionLease,
    ) -> dict:
        okay, error = lease.verify()
        self.assertTrue(okay, error)
        lease.close()
        capture.target_execution_lease = lease.evidence()
        record = {**copy.deepcopy(plan), **capture.evidence()}
        record["completedCommandClass"] = plan["commandClass"]
        return record

    def try_replace_bytes(self, data: bytes) -> bool:
        try:
            self.target.write_bytes(data)
        except OSError:
            return False
        return True

    def test_node_24_stdin_syntax_exit_stderr_and_empty_input_semantics(self) -> None:
        cases = (
            (b"const value = 1;\n", "commonjs", 0, False),
            (b"const value = ;\n", "commonjs", 1, True),
            (b"", "commonjs", 0, False),
            (b"export const value = 1;\n", "module", 0, False),
        )
        for data, mode, expected_exit, expects_stderr in cases:
            with self.subTest(mode=mode, data=data):
                capture = ci.execute_command(
                    "node-stdin-semantics",
                    "direct-syntax",
                    [self.node, "--check", f"--input-type={mode}", "-"],
                    timeout=30,
                    env=self.environment,
                    stdin_data=data,
                    logical_argv=[self.node, "--check", "fixture.js"],
                    execution_input_mode="TARGET-BYTES-STDIN",
                )
                self.assertEqual(capture.exit_code, expected_exit, capture.error)
                self.assertEqual(bool(capture.stderr.strip()), expects_stderr)
                self.assertEqual(capture.stdout, "")

    def test_unchanged_target_executes_exact_planned_bytes(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        self.assertIsNotNone(lease)
        self.assertTrue(capture.executed)
        self.assertEqual(capture.exit_code, 0)
        self.assertEqual(capture.execution_input_size, plan["executionInputSize"])
        self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])
        self.assertNotIn(self.relative, capture.argv)

    def test_invalid_planned_bytes_remain_invalid(self) -> None:
        self.target.write_bytes(self.invalid_bytes)
        plan = self.plan()
        capture, lease = self.execute(plan)
        self.assertIsNotNone(lease)
        self.assertTrue(capture.executed)
        self.assertEqual(capture.exit_code, 1)
        self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])
        self.assertIn("SyntaxError", capture.stderr)

    def test_valid_plan_then_invalid_replacement_before_lease_never_executes(self) -> None:
        plan = self.plan()

        def hook(phase, _lease):
            if phase == "after-plan-before-target-lease":
                self.target.write_bytes(self.invalid_bytes)

        capture, lease = self.execute(plan, hook)
        self.assertIsNone(lease)
        self.assertFalse(capture.executed)
        self.assertIn("TARGET-LEASE-ERROR", capture.error or "")

    def test_invalid_plan_then_valid_replacement_cannot_convert_result_to_pass(self) -> None:
        self.target.write_bytes(self.invalid_bytes)
        plan = self.plan()

        def hook(phase, _lease):
            if phase == "after-plan-before-target-lease":
                self.target.write_bytes(self.valid_bytes)

        capture, lease = self.execute(plan, hook)
        self.assertIsNone(lease)
        self.assertFalse(capture.executed)

    def test_delete_recreate_same_size_before_lease_is_rejected(self) -> None:
        plan = self.plan()

        def hook(phase, _lease):
            if phase == "after-plan-before-target-lease":
                self.target.unlink()
                self.target.write_bytes(self.valid_bytes)

        capture, lease = self.execute(plan, hook)
        self.assertIsNone(lease)
        self.assertFalse(capture.executed)

    def test_different_size_and_same_size_hash_replacements_are_rejected(self) -> None:
        for replacement in (b"const changed = 200;\n", self.invalid_bytes):
            with self.subTest(size=len(replacement)):
                self.target.write_bytes(self.valid_bytes)
                plan = self.plan()

                def hook(phase, _lease, data=replacement):
                    if phase == "after-plan-before-target-lease":
                        self.target.write_bytes(data)

                capture, lease = self.execute(plan, hook)
                self.assertIsNone(lease)
                self.assertFalse(capture.executed)

    def test_mutation_after_lease_before_materialization_is_denied_or_hard_fails(self) -> None:
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "after-target-lease-before-materialization":
                mutation["succeeded"] = self.try_replace_bytes(self.invalid_bytes)

        capture, lease = self.execute(plan, hook)
        if mutation["succeeded"]:
            self.assertFalse(capture.executed)
            self.assertIsNone(lease)
        else:
            self.assertTrue(capture.executed)
            self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])

    def test_mutation_after_materialization_before_launch_is_denied_or_hard_fails(self) -> None:
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "after-materialization-before-process-launch":
                mutation["succeeded"] = self.try_replace_bytes(self.invalid_bytes)

        capture, lease = self.execute(plan, hook)
        if mutation["succeeded"]:
            self.assertFalse(capture.executed)
            self.assertIsNone(lease)
        else:
            self.assertTrue(capture.executed)
            self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])

    def test_mutation_during_execution_is_denied_or_reports_hard_failure(self) -> None:
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "during-process-execution":
                mutation["succeeded"] = self.try_replace_bytes(self.invalid_bytes)

        capture, lease = self.execute(plan, hook)
        self.assertIsNotNone(lease)
        self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])
        if mutation["succeeded"]:
            self.assertEqual(capture.exit_code, ci.PROCESS_TREE_FAILURE_EXIT)
            self.assertTrue(lease.evidence()["mutationDetected"])
        else:
            self.assertEqual(capture.exit_code, 0)

    def test_mutation_after_process_exit_is_denied_or_reports_hard_failure(self) -> None:
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "after-process-exit-before-evidence":
                mutation["succeeded"] = self.try_replace_bytes(self.invalid_bytes)

        capture, lease = self.execute(plan, hook)
        self.assertIsNotNone(lease)
        self.assertEqual(capture.execution_input_sha256, plan["executionInputSha256"])
        if mutation["succeeded"]:
            self.assertEqual(capture.exit_code, ci.PROCESS_TREE_FAILURE_EXIT)
            self.assertTrue(lease.evidence()["mutationDetected"])
        else:
            self.assertEqual(capture.exit_code, 0)

    def test_change_and_restore_does_not_erase_recorded_source_drift(self) -> None:
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "after-materialization-before-process-launch":
                first = self.try_replace_bytes(self.invalid_bytes)
                if first:
                    self.target.write_bytes(self.valid_bytes)
                    mutation["succeeded"] = True

        capture, lease = self.execute(plan, hook)
        if mutation["succeeded"]:
            self.assertFalse(capture.executed)
            self.assertIsNone(lease)
            self.assertTrue(capture.target_execution_lease["mutationDetected"])
        else:
            self.assertEqual(capture.exit_code, 0)

    def test_hardlink_mutation_is_denied_or_detected(self) -> None:
        alias = self.root / "js" / "hardlink-alias.js"
        os.link(self.target, alias)
        plan = self.plan()
        mutation = {"succeeded": False}

        def hook(phase, _lease):
            if phase == "after-target-lease-before-materialization":
                try:
                    alias.write_bytes(self.invalid_bytes)
                except OSError:
                    return
                mutation["succeeded"] = True

        capture, lease = self.execute(plan, hook)
        if mutation["succeeded"]:
            self.assertFalse(capture.executed)
            self.assertIsNone(lease)
        else:
            self.assertEqual(capture.exit_code, 0)

    def test_rename_replace_and_symlink_substitution_before_lease_are_rejected(self) -> None:
        for mode in ("rename", "symlink"):
            with self.subTest(mode=mode):
                self.target.write_bytes(self.valid_bytes)
                plan = self.plan()

                def hook(phase, _lease, substitution=mode):
                    if phase != "after-plan-before-target-lease":
                        return
                    replacement = self.root / "js" / f"{substitution}-replacement.js"
                    replacement.write_bytes(self.invalid_bytes)
                    self.target.unlink()
                    if substitution == "rename":
                        replacement.replace(self.target)
                    else:
                        try:
                            os.symlink(replacement, self.target)
                        except OSError:
                            pass

                capture, lease = self.execute(plan, hook)
                self.assertIsNone(lease)
                self.assertFalse(capture.executed)

    def test_reparse_parent_and_case_alias_are_rejected(self) -> None:
        target = ci._target_authority(self.root, self.relative)
        with mock.patch.object(ci, "_is_reparse_point", return_value=True):
            with self.assertRaises(OSError):
                ci.TargetExecutionLease(
                    target,
                    repo_root=self.root,
                    execution_adapter="TARGET-BYTES-STDIN",
                )
        alias_target = copy.deepcopy(target)
        alias_target["path"] = "JS/siteContent.js"
        with self.assertRaises(OSError):
            lease = ci.TargetExecutionLease(
                alias_target,
                repo_root=self.root,
                execution_adapter="TARGET-BYTES-STDIN",
            )
            lease.close()

    def test_closed_lease_evidence_validates_exact_execution_input_identity(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        self.assertIsNotNone(lease)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        errors: list[str] = []
        hard_failure = ci._validate_command_record(record, 0, errors)
        self.assertFalse(hard_failure)
        self.assertEqual(errors, [])
        lease_evidence = record["targetExecutionLease"]
        self.assertEqual(
            lease_evidence["executedInputSha256"],
            lease_evidence["plannedSha256"],
        )

    def test_execution_input_omission_and_forgery_are_rejected(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        for field, value in (
            ("actualExecutionInputSha256", "0" * 64),
            ("actualExecutionInputSha256", None),
            ("actualExecutionInputSize", None),
        ):
            with self.subTest(field=field, value=value):
                forged = copy.deepcopy(record)
                forged[field] = value
                errors: list[str] = []
                ci._validate_command_record(forged, 0, errors)
                self.assertTrue(errors)

    def test_logical_or_execution_argv_forgery_is_rejected_by_rebuilt_plan(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        for mode in ("logical", "execution-live-path"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(record)
                if mode == "logical":
                    forged["logicalArgv"][-1] = "js/unrelated.js"
                    forged["argv"] = list(forged["logicalArgv"])
                else:
                    forged["executionArgv"] = [self.node, "--check", self.relative]
                    forged["actualExecutionArgv"] = list(forged["executionArgv"])
                ids = [
                    value["id"]
                    for value in ci._command_authority_violations(
                        "static", [forged], [], expected_plan=[plan]
                    )
                ]
                self.assertIn("COMMAND-AUTHORITY-MISMATCH", ids)

    def test_post_evidence_target_change_is_caught_by_independent_plan_rebuild(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        self.target.write_bytes(self.invalid_bytes)
        rebuilt = self.plan()
        ids = [
            value["id"]
            for value in ci._command_authority_violations(
                "static", [record], [], expected_plan=[rebuilt]
            )
        ]
        self.assertIn("COMMAND-AUTHORITY-MISMATCH", ids)

    def test_plan_records_logical_and_execution_argv_without_live_target_execution(self) -> None:
        plan = self.plan()
        self.assertEqual(plan["logicalArgv"][-1], self.relative)
        self.assertEqual(plan["executionArgv"][-1], "-")
        self.assertNotIn(self.relative, plan["executionArgv"])
        self.assertEqual(plan["executionInputMode"], "TARGET-BYTES-STDIN")
        self.assertEqual(plan["executionInputSha256"], plan["targets"][0]["sha256"])


class CI6ReplayVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner, cls.documents, cls.comparison = sixth_review_replay_fixture()

    def compare(self, documents: dict | None = None, runner=None) -> list[str]:
        _transcript, errors = ci.compare_verification_replay_claims(
            copy.deepcopy(documents or self.documents),
            runner or self.runner,
            self.comparison,
        )
        return errors

    def test_legitimate_claims_match_independent_replay(self) -> None:
        self.assertEqual(self.compare(), [])
        commands = self.documents["command-results.json"]
        self.assertEqual(commands["producerObservationCount"], 787)
        self.assertTrue(commands["completedCommandClasses"])

    def test_forged_pass_observation_and_exit_matrix_is_rejected(self) -> None:
        modes = (
            "strip-all-787",
            "clear-producer-lists",
            "empty-set-digest",
            "rewrite-four-exits",
            "pass-summary-zero-counts",
            "complete-sixth-review-forgery",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                forged = copy.deepcopy(self.documents)
                commands = forged["command-results.json"]
                if mode in {
                    "strip-all-787",
                    "clear-producer-lists",
                    "complete-sixth-review-forgery",
                }:
                    for record in commands["records"]:
                        record["producerObservations"] = []
                    commands["observations"] = []
                if mode == "empty-set-digest":
                    commands["records"][1]["producerObservationSetDigest"] = (
                        ci.producer_observation_set_digest([])
                    )
                if mode in {"rewrite-four-exits", "complete-sixth-review-forgery"}:
                    for record in commands["records"]:
                        if record["commandClass"] == "direct-syntax":
                            record["exitCode"] = 0
                            record["parsedFailureSummary"] = {
                                "status": "pass",
                                "diagnostic": "forged PASS",
                            }
                if mode in {"pass-summary-zero-counts", "complete-sixth-review-forgery"}:
                    forged["summary.json"]["status"] = "PASS"
                    forged["summary.json"]["counts"] = {
                        "hardGateFailures": 0,
                        "policyViolations": 0,
                    }
                    commands["completedCommandClasses"] = []
                if mode != "empty-set-digest":
                    coherently_rebind_claimed_transcript(forged)
                if mode == "pass-summary-zero-counts":
                    commands["completedCommandClasses"] = []
                    commands["actualCompletedCommandClasses"] = []
                    commands["completedCommandClassSetDigest"] = (
                        ci.completed_command_class_set_digest([])
                    )
                errors = self.compare(forged)
                self.assertTrue(errors, mode)
                self.assertTrue(
                    any(
                        token in " ".join(errors)
                        for token in (
                            "transcript",
                            "observations",
                            "completedCommandClasses",
                            "producerObservation",
                        )
                    ),
                    errors,
                )

    def test_empty_and_subset_completed_command_classes_are_rejected(self) -> None:
        expected = self.documents["command-results.json"]["completedCommandClasses"]
        self.assertGreaterEqual(len(expected), 2)
        for claimed in ([], expected[:-1]):
            with self.subTest(claimed=claimed):
                forged = copy.deepcopy(self.documents)
                commands = forged["command-results.json"]
                commands["completedCommandClasses"] = copy.deepcopy(claimed)
                commands["actualCompletedCommandClasses"] = copy.deepcopy(claimed)
                commands["completedCommandClassSetDigest"] = (
                    ci.completed_command_class_set_digest(claimed)
                )
                commands["producerTranscriptDigest"] = ci.producer_transcript_digest(
                    commands["commandPlanDigest"], commands["records"], claimed
                )
                errors = self.compare(forged)
                self.assertTrue(any("completedCommand" in error for error in errors), errors)

    def test_missing_extra_duplicate_and_renumbered_commands_are_rejected(self) -> None:
        for mode in ("missing-observation-producer", "missing-required", "duplicate", "renumber"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(self.documents)
                commands = forged["command-results.json"]
                if mode == "missing-observation-producer":
                    commands["records"].pop(1)
                elif mode == "missing-required":
                    commands["records"].pop(0)
                elif mode == "duplicate":
                    commands["records"].append(copy.deepcopy(commands["records"][-1]))
                else:
                    commands["records"].pop(2)
                    commands["commandAuthority"].pop(2)
                    for ordinal, (planned, record) in enumerate(
                        zip(commands["commandAuthority"], commands["records"])
                    ):
                        planned["ordinal"] = ordinal
                        record["ordinal"] = ordinal
                        for raw in record.get("producerObservations", []):
                            raw["commandOrdinal"] = ordinal
                            raw["producerRecordDigest"] = ci._producer_record_digest(
                                {
                                    key: value
                                    for key, value in raw.items()
                                    if key != "producerRecordDigest"
                                }
                            )
                coherently_rebind_claimed_transcript(forged)
                errors = self.compare(forged)
                self.assertTrue(errors, mode)
                self.assertTrue(any("command" in error.lower() for error in errors), errors)

    def test_fake_evidence_replay_fields_do_not_authorize_execution(self) -> None:
        forged = copy.deepcopy(self.documents)
        forged["summary.json"]["replayStatus"] = "PASS"
        forged["command-results.json"]["verificationReplayTranscript"] = {
            "status": "PASS",
            "producerTranscriptDigest": "0" * 64,
        }
        errors = self.compare(forged)
        self.assertTrue(any("cannot authorize" in error for error in errors), errors)

    def test_producer_transcript_and_universe_digest_forgeries_are_rejected(self) -> None:
        for field in (
            "producerTranscriptDigest",
            "producerObservationUniverseDigest",
        ):
            with self.subTest(field=field):
                forged = copy.deepcopy(self.documents)
                forged["command-results.json"][field] = "0" * 64
                errors = self.compare(forged)
                self.assertTrue(any(field in error for error in errors), errors)

    def test_zero_observation_command_is_valid_only_when_replay_matches_clean_exit(self) -> None:
        replay_runner = copy.deepcopy(self.runner)
        static_record = next(
            record
            for record in replay_runner.command_results
            if record["commandId"] == "static-suite"
        )
        static_record["producerObservations"] = []
        replay_runner.observations = [
            item
            for item in replay_runner.observations
            if item["commandId"] != "static-suite"
        ]
        ci.finalize_evidence_transcript(replay_runner)
        transcript = ci.verification_replay_transcript(replay_runner)
        claims = copy.deepcopy(self.documents)
        commands = claims["command-results.json"]
        commands["commandAuthority"] = copy.deepcopy(replay_runner.command_plan)
        commands["records"] = copy.deepcopy(replay_runner.command_results)
        commands["observations"] = copy.deepcopy(replay_runner.observations)
        commands["commandCount"] = transcript["commandCount"]
        commands["commandPlanDigest"] = transcript["commandPlanDigest"]
        commands["completedCommandClasses"] = transcript[
            "actualCompletedCommandClasses"
        ]
        for key in (
            "expectedCompletedCommandClasses",
            "actualCompletedCommandClasses",
            "expectedCompletedCommandClassSetDigest",
            "completedCommandClassSetDigest",
            "producerObservationCount",
            "producerObservationUniverseDigest",
            "producerTranscriptDigest",
            "missingCommandIds",
            "extraCommandIds",
            "duplicateCommandIds",
        ):
            commands[key] = copy.deepcopy(transcript[key])
        _transcript, errors = ci.compare_verification_replay_claims(
            claims, replay_runner, self.comparison
        )
        self.assertEqual(errors, [])
        commands["records"][1]["exitCode"] = 1
        coherently_rebind_claimed_transcript(claims)
        self.assertTrue(
            ci.compare_verification_replay_claims(
                claims, replay_runner, self.comparison
            )[1]
        )

    def test_pass_replay_unavailable_or_nonpass_fails_closed(self) -> None:
        runner = copy.deepcopy(self.runner)
        runner.run = mock.Mock(side_effect=OSError("fixture unavailable"))
        runner.close_execution_leases = mock.Mock()
        context = synthetic_external_context(runner.execution_binding)
        transcript, errors = ci.run_verification_replay(
            self.documents,
            expected_context=context,
            verification_runner=runner,
            repo_root=ci.REPO_ROOT,
        )
        self.assertIsNone(transcript)
        self.assertTrue(any("unavailable" in error for error in errors), errors)

    def test_coherent_five_file_rewrite_remains_read_only_and_nonpassing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci6-five-file-forgery-") as temp_dir:
            output = Path(temp_dir)
            snapshots = {}
            for name in ci.EVIDENCE_FILE_NAMES:
                data = (
                    ci._json_bytes(self.documents["summary.json"])
                    if name == "summary.json"
                    else b"{}\n" if name.endswith(".json") else b"forged PASS\n"
                )
                (output / name).write_bytes(data)
                snapshot, errors = ci._read_evidence_file_snapshot(
                    output / name,
                    output_dir=output,
                    byte_limit=ci.EVIDENCE_FILE_BYTE_LIMITS[name],
                )
                self.assertEqual(errors, [])
                assert snapshot is not None
                snapshots[name] = snapshot
            before = {name: snapshot.data for name, snapshot in snapshots.items()}
            with mock.patch.object(ci, "verify_evidence_file_set", return_value=[]), mock.patch.object(
                ci,
                "_read_evidence_documents_for_replay",
                return_value=(copy.deepcopy(self.documents), snapshots, []),
            ), mock.patch.object(
                ci,
                "run_verification_replay",
                return_value=(None, ["verification replay producer observations mismatch"]),
            ), mock.patch.object(
                ci,
                "rebuild_external_verification_context",
                return_value=synthetic_external_context(self.runner.execution_binding),
            ):
                context = synthetic_external_context(self.runner.execution_binding)
                errors, transcript = ci.verify_evidence_with_replay(
                    output,
                    expected_context=context,
                    verification_runner=self.runner,
                    repo_root=ci.REPO_ROOT,
                )
            after = {name: (output / name).read_bytes() for name in ci.EVIDENCE_FILE_NAMES}
        self.assertIsNone(transcript)
        self.assertTrue(errors)
        self.assertEqual(after, before)

    def test_replay_transcript_schema_contains_complete_execution_authority(self) -> None:
        transcript = ci.verification_replay_transcript(self.runner)
        self.assertEqual(transcript["documentKind"], "VerificationReplayTranscript")
        self.assertEqual(transcript["producerObservationCount"], 787)
        required_top = {
            "profile",
            "commandPlanDigest",
            "commandCount",
            "records",
            "expectedCompletedCommandClasses",
            "actualCompletedCommandClasses",
            "producerTranscriptDigest",
            "producerObservationUniverseDigest",
            "missingCommandIds",
            "extraCommandIds",
            "duplicateCommandIds",
        }
        self.assertTrue(required_top.issubset(transcript))
        required_record = {
            "commandId",
            "ordinal",
            "commandClass",
            "required",
            "completedCommandClass",
            "logicalArgv",
            "executionArgv",
            "cwd",
            "toolRole",
            "targets",
            "executionInputs",
            "started",
            "executed",
            "setupFailure",
            "exitCode",
            "timeoutStatus",
            "outputLimitStatus",
            "producerObservations",
            "producerObservationSetDigest",
            "executionDurationClass",
            "processTreeStatus",
        }
        self.assertTrue(required_record.issubset(transcript["records"][0]))


class CI6ProtectedPolicyInputTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ci6-protected-policy-")
        self.root = Path(self.temporary.name)
        self.paths = [
            ".github/workflows/ci.yml",
            "docs/CI_POLICY.md",
            "developer/tests/ci/phase1-ci-baseline.json",
        ]
        for relative in self.paths:
            source = ci.REPO_ROOT.joinpath(*relative.split("/"))
            target = self.root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        self.targets = [ci._target_authority(self.root, relative) for relative in self.paths]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_workflow_policy_plan_binds_three_ordered_targets(self) -> None:
        plan = ci.build_profile_command_plan(
            "policy",
            tools={"python": sys.executable, "node": sys.executable, "git": sys.executable},
            candidate_paths=self.paths,
            baseline=ci.strict_json_load_file(ci.BASELINE_PATH),
            current_platform=ci.platform_key(),
            static_invocation_id=str(uuid.uuid4()),
            repo_root=self.root,
        )
        workflow = next(item for item in plan if item["commandId"] == "workflow-self-policy")
        self.assertEqual(workflow["executionInputMode"], "PROTECTED-TARGET-BUNDLE")
        self.assertEqual([target["path"] for target in workflow["targets"]], self.paths)

    def test_workflow_policy_protected_bytes_api_never_reopens_paths(self) -> None:
        inputs = [self.root.joinpath(*relative.split("/")).read_bytes() for relative in self.paths]
        with mock.patch.object(Path, "open", side_effect=AssertionError("live open")), mock.patch.object(
            Path, "read_bytes", side_effect=AssertionError("live read_bytes")
        ), mock.patch.object(Path, "read_text", side_effect=AssertionError("live read_text")):
            errors = ci.run_workflow_policy(*inputs, self.targets)
        self.assertEqual(errors, [])

    def test_target_bound_execution_methods_contain_no_live_read_api(self) -> None:
        methods = (
            ci.FoundationRunner.run_baseline_policy,
            ci.FoundationRunner.run_private_and_secret_policy,
            ci.FoundationRunner.run_license_policy,
            ci.FoundationRunner.run_workflow_policy,
            ci.FoundationRunner.run_direct_syntax,
            ci.FoundationRunner.run_frontend_profile,
            ci.FoundationRunner.run_backend_profile,
            ci.FoundationRunner.run_standalone_profile,
            ci.FoundationRunner.run_lockfile_integrity,
            ci.FoundationRunner.execute_protected_external,
        )
        for method in methods:
            with self.subTest(method=method.__name__):
                source = inspect.getsource(method)
                self.assertNotIn(".read_text(", source)
                self.assertNotIn(".read_bytes(", source)
                self.assertNotIn("open(REPO_ROOT", source)

    def test_mutation_after_plan_before_bundle_capture_is_rejected(self) -> None:
        workflow = self.root / ".github/workflows/ci.yml"
        original = workflow.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), self.targets[0]["sha256"])
        workflow.write_bytes(b"# same-size-forgery\n".ljust(len(original), b"x"))
        try:
            with self.assertRaises(OSError):
                bundle = ci.ProtectedTargetBundle(
                    self.targets,
                    repo_root=self.root,
                )
                bundle.close()
        finally:
            workflow.write_bytes(original)

    def test_multi_target_mutation_after_capture_is_denied_or_sticky(self) -> None:
        mutations = ("same-size-hash", "delete-recreate-same", "delete-recreate-different")
        for mode in mutations:
            with self.subTest(mode=mode):
                target = self.root / "docs/CI_POLICY.md"
                original = target.read_bytes()
                authority = [ci._target_authority(self.root, path) for path in self.paths]
                bundle = ci.ProtectedTargetBundle(authority, repo_root=self.root)
                bundle.materialize()
                changed = False
                try:
                    try:
                        if mode == "same-size-hash":
                            target.write_bytes(b"z" * len(original))
                        else:
                            target.unlink()
                            target.write_bytes(
                                original if mode == "delete-recreate-same" else b"different\n"
                            )
                        changed = True
                    except OSError:
                        changed = False
                    okay, _error = bundle.verify()
                    if okay:
                        self.assertFalse(changed)
                    else:
                        self.assertTrue(bundle.evidence()["mutationDetected"])
                finally:
                    bundle.close()
                    if target.exists():
                        try:
                            target.write_bytes(original)
                        except OSError:
                            pass
                    else:
                        target.write_bytes(original)

    def test_multi_target_input_reorder_omission_and_extra_are_rejected(self) -> None:
        spec = synthetic_command_spec(
            "workflow-self-policy",
            "workflow-policy",
            0,
            targets=self.targets,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        record = synthetic_record_from_spec(spec)
        record["completedCommandClass"] = record["commandClass"]
        errors: list[str] = []
        self.assertFalse(ci._validate_command_record(record, 0, errors))
        self.assertEqual(errors, [])
        for mode in ("reorder", "omit", "extra"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(record)
                if mode == "reorder":
                    forged["executionInputs"][0], forged["executionInputs"][1] = (
                        forged["executionInputs"][1],
                        forged["executionInputs"][0],
                    )
                elif mode == "omit":
                    forged["executionInputs"].pop()
                else:
                    forged["executionInputs"].append(copy.deepcopy(forged["executionInputs"][0]))
                forged["executionInputBundleDigest"] = ci.execution_input_bundle_digest(
                    forged["executionInputs"]
                )
                forged["protectedTargetBundle"]["executionInputs"] = copy.deepcopy(
                    forged["executionInputs"]
                )
                forged["protectedTargetBundle"]["executionInputBundleDigest"] = forged[
                    "executionInputBundleDigest"
                ]
                errors = []
                ci._validate_command_record(forged, 0, errors)
                self.assertTrue(errors, mode)

    def test_all_target_bound_plans_use_protected_execution_inputs(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        tools = {
            "python": sys.executable,
            "node": sys.executable,
            "git": sys.executable,
            "bash": sys.executable,
            "powershell": sys.executable,
        }
        candidates = [
            "developer/tests/ci/run_static_suite.py",
            "developer/tests/ci/test_standalone_packaging.py",
        ]
        expected_external = {
            "policy": {
                "baseline-schema",
                "tracked-private-resource-scan",
                "tracked-secret-scan",
                "license-governance-consistency",
                "workflow-self-policy",
                "lockfile-integrity",
            },
            "static": {"static-suite"},
            "standalone": {"standalone-packaging"},
            "frontend": {
                "bundle-normalization",
                "learner-focused",
                *(f"frontend-security:{Path(relative).name}" for relative in ci.SECURITY_GUARD_FILES),
                "frontend-security:messageOriginGuard.test.js",
            },
            "backend": {"backend-canonical"},
        }
        complete_candidate_commands = {
            "tracked-private-resource-scan",
            "tracked-secret-scan",
            "static-suite",
            "standalone-packaging",
            "bundle-normalization",
            "learner-focused",
            *(f"frontend-security:{Path(relative).name}" for relative in ci.SECURITY_GUARD_FILES),
            "frontend-security:messageOriginGuard.test.js",
            "backend-canonical",
        }
        for profile, command_ids in expected_external.items():
            with self.subTest(profile=profile):
                plan = ci.build_profile_command_plan(
                    profile,
                    tools=tools,
                    candidate_paths=candidates,
                    baseline=baseline,
                    current_platform=ci.platform_key(),
                    static_invocation_id=ci.deterministic_static_invocation_id(),
                )
                commands = {item["commandId"]: item for item in plan}
                self.assertTrue(command_ids.issubset(commands))
                for command_id in command_ids:
                    command = commands[command_id]
                    self.assertEqual(
                        command["executionInputMode"],
                        "PROTECTED-TARGET-BUNDLE",
                        command_id,
                    )
                    if command_id in complete_candidate_commands:
                        self.assertEqual(
                            [item["path"] for item in command["targets"]],
                            candidates,
                            command_id,
                        )
                for command in plan:
                    if command["targets"]:
                        self.assertIn(
                            command["executionInputMode"],
                            {"PROTECTED-TARGET-BUNDLE", "TARGET-BYTES-STDIN"},
                            command["commandId"],
                        )

    def test_protected_snapshot_process_consumes_only_materialized_planned_bytes(self) -> None:
        script = self.root / "check.py"
        data = self.root / "data.txt"
        script.write_text(
            "import json, os, pathlib\n"
            "print(pathlib.Path('data.txt').read_text(encoding='utf-8').strip())\n"
            "print(os.environ.get('CI_PROTECTED_TARGET_SNAPSHOT', 'missing'))\n"
            "print(pathlib.Path.cwd())\n"
            "print(json.dumps({'root': str(pathlib.Path.cwd())}, sort_keys=True))\n",
            encoding="utf-8",
        )
        data.write_text("planned\n", encoding="utf-8")
        targets = [
            ci._target_authority(self.root, "check.py"),
            ci._target_authority(self.root, "data.txt"),
        ]
        spec = synthetic_command_spec(
            "static-suite",
            "static-suite",
            0,
            command_role="observation-producing",
            targets=targets,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        argv = [sys.executable, "-B", "check.py"]
        spec["argv"] = argv
        spec["logicalArgv"] = argv
        spec["executionArgv"] = argv
        capture, evidence = ci.execute_planned_static_suite(
            spec,
            repo_root=self.root,
            env=ci.child_process_environment({"python": sys.executable}),
            timeout=30,
        )
        self.assertTrue(capture.execution_passed(), capture.error)
        self.assertEqual(
            capture.stdout.splitlines(),
            [
                "planned",
                "1",
                str(self.root.resolve()),
                json.dumps({"root": str(self.root.resolve())}, sort_keys=True),
            ],
        )
        self.assertEqual(capture.stdout_raw, capture.stdout.encode("utf-8"))
        self.assertEqual(capture.stdout_bytes, len(capture.stdout.encode("utf-8")))
        first_capture = contained_capture()
        second_capture = contained_capture()
        first_report = {
            "observations": [
                {"detail": {"duration": 1.25, "outputTail": ["Ran 18 tests in 1.250s"]}}
            ]
        }
        second_report = {
            "observations": [
                {"detail": {"duration": 99.0, "outputTail": ["Ran 18 tests in 99.000s"]}}
            ]
        }
        ci._canonicalize_static_machine_capture(first_capture, first_report)
        ci._canonicalize_static_machine_capture(second_capture, second_report)
        self.assertEqual(first_capture.stdout_raw, second_capture.stdout_raw)
        self.assertIn("Ran 18 tests in <duration>s", first_capture.stdout)
        self.assertEqual(evidence["cleanupState"], "closed")
        self.assertFalse(evidence["mutationDetected"])
        self.assertEqual(
            [item["actualSha256"] for item in evidence["executionInputs"]],
            [item["plannedSha256"] for item in evidence["executionInputs"]],
        )


class CI6LocaleJunctionTest(unittest.TestCase):
    def test_oem_chinese_invalid_utf8_and_replacement_decode_matrix(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            clear=False,
        ):
            samples = (
                "已创建联接".encode("gbk"),
                b"\xff\xfe\x80invalid-utf8",
                b"junction created\r\n",
            )
            for sample in samples:
                with self.subTest(sample=sample[:8]):
                    decoded = standalone_packaging._decode_cmd_diagnostics(sample)
                    self.assertIsInstance(decoded, str)
                    self.assertTrue(decoded)

    def test_failed_mklink_decode_anomaly_and_timeout_always_clean(self) -> None:
        modes = ("nonzero", "decode-anomaly", "timeout")
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="ci6-junction-failure-"
            ) as temp_dir:
                root = Path(temp_dir)
                link = root / "link"
                target = root / "target"
                target.mkdir()

                def invoke(*_args, **_kwargs):
                    if mode != "nonzero":
                        link.mkdir()
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired("mklink", 1, output=b"\xff")
                    return SimpleNamespace(
                        returncode=1 if mode == "nonzero" else 0,
                        stdout=b"\xff\xfe",
                    )

                name_patch = (
                    mock.patch.object(standalone_packaging.os, "name", "nt")
                    if standalone_packaging.os.name != "nt"
                    else contextlib.nullcontext()
                )
                decode_patch = (
                    mock.patch.object(
                        standalone_packaging,
                        "_decode_cmd_diagnostics",
                        side_effect=UnicodeError("fixture decode anomaly"),
                    )
                    if mode == "decode-anomaly"
                    else contextlib.nullcontext()
                )
                with name_patch, decode_patch, mock.patch.object(
                    standalone_packaging.subprocess, "run", side_effect=invoke
                ):
                    with self.assertRaises((AssertionError, UnicodeError, subprocess.TimeoutExpired)):
                        with standalone_packaging.StandalonePackagingTest._directory_link(
                            link, target
                        ):
                            pass
                self.assertFalse(os.path.lexists(link))

    def test_success_and_later_validation_failure_remove_real_link(self) -> None:
        temporary_path: Path | None = None
        with tempfile.TemporaryDirectory(prefix="ci6-junction-success-") as temp_dir:
            temporary_path = Path(temp_dir)
            target = temporary_path / "target"
            target.mkdir()
            for fail_after_creation in (False, True):
                link = temporary_path / ("link-fail" if fail_after_creation else "link-pass")
                try:
                    with standalone_packaging.StandalonePackagingTest._directory_link(
                        link, target
                    ):
                        self.assertTrue(link.exists())
                        if fail_after_creation:
                            raise AssertionError("later validation failure")
                except AssertionError:
                    self.assertTrue(fail_after_creation)
                self.assertFalse(os.path.lexists(link))
        assert temporary_path is not None
        self.assertFalse(temporary_path.exists())


class CI6ProducerDigestBindingTest(unittest.TestCase):
    def test_each_producer_context_digest_changes_full_context_failure_digest(self) -> None:
        spec = synthetic_command_spec("producer", "static-suite", 0)
        record = synthetic_record_from_spec(spec)
        record["completedCommandClass"] = record["commandClass"]
        raw = ci.make_raw_observation(
            "producer",
            0,
            0,
            "normalized-fields-v1",
            "result:fixture",
            ci.STATIC_SUITE_RELATIVE_PATH,
            {"scope": "result:fixture", "outcome": "fail", "message": "fixture"},
            ci.command_output_digest(record),
        )
        record["producerObservations"] = [raw]
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
        outputs = ci._raw_failure_outputs(raw, record)
        context = {
            "producerObservationUniverseDigest": "1" * 64,
            "producerTranscriptDigest": "2" * 64,
            "profileCompletedCommandClassSetDigest": "3" * 64,
        }

        def digest(selected_record: dict, selected_context: dict) -> str:
            material = ci.derive_canonical_failure_material(
                selected_record,
                raw,
                outputs["parserSemantics"],
                outputs["derivedFailureMembers"],
                outputs["signature"],
                outputs["outcome"],
                selected_context,
            )
            return ci.canonical_failure_digest(material)

        original = digest(record, context)
        changed_record = copy.deepcopy(record)
        changed_record["producerObservationSetDigest"] = "4" * 64
        self.assertNotEqual(original, digest(changed_record, context))
        for field in (
            "producerObservationUniverseDigest",
            "producerTranscriptDigest",
            "profileCompletedCommandClassSetDigest",
        ):
            changed = copy.deepcopy(context)
            changed[field] = "5" * 64
            self.assertNotEqual(original, digest(record, changed), field)

    def test_moving_same_observation_and_command_order_change_transcript_digest(self) -> None:
        specs = [
            synthetic_command_spec("one", "class-one", 0),
            synthetic_command_spec("two", "class-two", 1),
        ]
        records = [synthetic_record_from_spec(spec) for spec in specs]
        raw = ci.make_raw_observation(
            "one",
            0,
            0,
            "normalized-fields-v1",
            "scope",
            None,
            {"scope": "scope", "outcome": "pass"},
            ci.command_output_digest(records[0]),
        )
        records[0]["producerObservations"] = [raw]
        for record in records:
            record["producerObservationSetDigest"] = ci.producer_observation_set_digest(
                record["producerObservations"]
            )
            record["completedCommandClass"] = record["commandClass"]
        plan_digest = ci.command_plan_digest(specs)
        original = ci.producer_transcript_digest(
            plan_digest, records, ["class-one", "class-two"]
        )
        moved = copy.deepcopy(records)
        moved[0]["producerObservations"] = []
        moved[1]["producerObservations"] = [copy.deepcopy(raw)]
        for record in moved:
            record["producerObservationSetDigest"] = ci.producer_observation_set_digest(
                record["producerObservations"]
            )
        self.assertNotEqual(
            original,
            ci.producer_transcript_digest(plan_digest, moved, ["class-one", "class-two"]),
        )
        self.assertNotEqual(
            original,
            ci.producer_transcript_digest(
                plan_digest, list(reversed(records)), ["class-one", "class-two"]
            ),
        )

    def test_observation_context_digest_tamper_matrix_is_rejected(self) -> None:
        runner, _documents, _comparison = sixth_review_replay_fixture()
        item = runner.observations[0]
        source = next(
            record
            for record in runner.command_results
            if record["commandId"] == item["commandId"]
        )
        for field in (
            "producerObservationSetDigest",
            "producerObservationUniverseDigest",
            "producerTranscriptDigest",
        ):
            with self.subTest(field=field):
                forged = copy.deepcopy(item)
                forged[field] = "f" * 64
                errors = ci._validate_observation_record(
                    forged,
                    0,
                    {source["commandId"]: source},
                )
                self.assertTrue(errors, field)


class CI7ExternalAuthorityBindingTest(unittest.TestCase):
    def github_binding(
        self,
        job_id: str,
        *,
        run_id: str = "999999999",
        run_attempt: str = "7",
        event_name: str = "push",
        repository: str = "owner/repository",
        checkout_commit: str = ci.BASELINE_COMMIT,
        checkout_tree: str = ci.BASELINE_TREE,
        trust_digest: str = "4" * 64,
        command_plan_digest: str = "5" * 64,
    ) -> dict:
        authority = ci.WORKFLOW_JOB_PROFILE_AUTHORITY[job_id]
        binding = {
            "bindingSchemaVersion": ci.EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
            "bindingKind": "ProducerExecutionBinding",
            "bindingMode": "github-actions",
            "producerJobId": authority["producerJobId"],
            "producerRunnerOS": authority["runnerOS"],
            "producerProfile": authority["verificationProfile"],
            "runId": run_id,
            "runAttempt": run_attempt,
            "eventName": event_name,
            "repository": repository,
            "checkoutCommit": checkout_commit,
            "checkoutTree": checkout_tree,
            "baselineCommit": ci.BASELINE_COMMIT,
            "baselineTree": ci.BASELINE_TREE,
            "trustFileDigest": trust_digest,
            "commandPlanDigest": command_plan_digest,
        }
        binding["producerInvocationId"] = ci._github_binding_invocation_id(binding)
        return binding

    def test_missing_expected_profile_and_invalid_cli_matrix_fails_before_authority(self) -> None:
        with mock.patch.object(ci, "prepare_verification_authority") as prepare, mock.patch.object(
            ci, "verify_evidence_with_replay"
        ) as replay:
            self.assertEqual(ci.main(["--verify-evidence"]), ci.EXIT_CONFIGURATION_ERROR)
        prepare.assert_not_called()
        replay.assert_not_called()

        invalid_argv = (
            ["--verify-evidence", "--expected-profile", ""],
            ["--verify-evidence", "--expected-profile", "unknown"],
            ["--verify-evidence", "--expected-profile", "Policy"],
            ["--verify-evidence", "--expected-profile", " policy"],
            ["--verify-evidence", "--expected-profile", "../policy"],
            [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-profile",
                "static",
            ],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), self.assertRaises((ValueError, SystemExit)):
                ci.parse_args(argv)

        with mock.patch.object(ci, "current_checkout_identity", return_value=(ci.BASELINE_COMMIT, ci.BASELINE_TREE)), mock.patch.object(
            ci, "ci_trust_file_set_authority", return_value=([], "6" * 64)
        ):
            with self.assertRaisesRegex(ValueError, "external invocation identity"):
                ci.build_externally_expected_verification_context(
                    expected_profile="policy",
                    expected_producer_job=None,
                    expected_verifier_job=None,
                    expected_runner_os=None,
                    expected_invocation_id=None,
                    command_plan_digest_value="7" * 64,
                    fresh_runtime_closure_digest="8" * 64,
                    baseline=ci.strict_json_load_file(ci.BASELINE_PATH),
                    git=sys.executable,
                    child_environment={},
                    source_environment={},
                )

    def test_cross_profile_substitution_matrix_is_rejected(self) -> None:
        substitutions = (
            ("policy", "static"),
            ("static", "policy"),
            ("frontend", "backend"),
            ("backend", "standalone"),
            ("standalone", "all"),
            ("all", "policy"),
        )
        for source_profile, expected_profile in substitutions:
            with self.subTest(source=source_profile, expected=expected_profile):
                source = synthetic_execution_binding(
                    source_profile,
                    hashlib.sha256(source_profile.encode("ascii")).hexdigest(),
                )
                expected = synthetic_execution_binding(
                    expected_profile,
                    hashlib.sha256(expected_profile.encode("ascii")).hexdigest(),
                )
                errors = ci.execution_binding_external_context_errors(
                    source,
                    ci.execution_binding_digest(source),
                    synthetic_external_context(expected),
                )
                self.assertTrue(any("external" in error for error in errors), errors)

    def test_cross_job_and_cross_os_substitution_matrix_is_rejected(self) -> None:
        slot_substitutions = (
            ("repository-policy", "ubuntu-canonical"),
            ("repository-policy", "windows-compatibility"),
            ("ubuntu-canonical", "repository-policy"),
            ("ubuntu-canonical", "windows-compatibility"),
            ("windows-compatibility", "repository-policy"),
            ("windows-compatibility", "ubuntu-canonical"),
        )
        for source_job, expected_job in slot_substitutions:
            with self.subTest(source=source_job, expected=expected_job):
                evidence = self.github_binding(source_job)
                expected = self.github_binding(expected_job)
                errors = ci.execution_binding_external_context_errors(
                    evidence,
                    ci.execution_binding_digest(evidence),
                    synthetic_external_context(expected),
                )
                self.assertTrue(errors, (source_job, expected_job))

        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        base_environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_JOB": "windows-compatibility",
            "RUNNER_OS": "Windows",
            "GITHUB_RUN_ID": "999999999",
            "GITHUB_RUN_ATTEMPT": "7",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REPOSITORY": "owner/repository",
            "GITHUB_SHA": ci.BASELINE_COMMIT,
        }
        cases = (
            ("ubuntu-canonical", "Windows", "all", base_environment),
            ("windows-compatibility", "Linux", "all", base_environment),
            (
                "windows-compatibility",
                "Windows",
                "policy",
                base_environment,
            ),
            (
                "windows-compatibility",
                "Windows",
                "all",
                {**base_environment, "RUNNER_OS": "Linux"},
            ),
        )
        with mock.patch.object(ci, "current_checkout_identity", return_value=(ci.BASELINE_COMMIT, ci.BASELINE_TREE)), mock.patch.object(
            ci, "ci_trust_file_set_authority", return_value=([], "8" * 64)
        ), mock.patch.object(ci, "_canonical_runner_os", return_value="Windows"):
            for expected_job, expected_os, expected_profile, environment in cases:
                with self.subTest(job=expected_job, os=expected_os, profile=expected_profile):
                    with self.assertRaises(ValueError):
                        ci.build_externally_expected_verification_context(
                            expected_profile=expected_profile,
                            expected_producer_job=ci.WORKFLOW_JOB_PROFILE_AUTHORITY[
                                expected_job
                            ]["producerJobId"],
                            expected_verifier_job=expected_job,
                            expected_runner_os=expected_os,
                            expected_invocation_id=None,
                            command_plan_digest_value="9" * 64,
                            fresh_runtime_closure_digest="a" * 64,
                            baseline=baseline,
                            git=sys.executable,
                            child_environment={},
                            source_environment=environment,
                        )

    def test_cross_run_attempt_event_and_repository_substitution_matrix_is_rejected(self) -> None:
        evidence = self.github_binding("ubuntu-canonical")
        mutations = {
            "different-run": {"runId": "999999998"},
            "different-attempt": {"runAttempt": "6"},
            "different-event": {"eventName": "pull_request"},
            "different-repository": {"repository": "other/repository"},
        }
        for name, fields in mutations.items():
            with self.subTest(name=name):
                expected = copy.deepcopy(evidence)
                expected.update(fields)
                expected["producerInvocationId"] = ci._github_binding_invocation_id(
                    {
                        key: value
                        for key, value in expected.items()
                        if key != "producerInvocationId"
                    }
                )
                errors = ci.execution_binding_external_context_errors(
                    evidence,
                    ci.execution_binding_digest(evidence),
                    synthetic_external_context(expected),
                )
                self.assertTrue(errors, name)

    def test_cross_commit_tree_and_trust_file_substitution_matrix_is_rejected(self) -> None:
        evidence = self.github_binding("windows-compatibility")
        mutations = {
            "different-commit": {"checkoutCommit": "a" * 40},
            "different-tree": {"checkoutTree": "b" * 40},
            "same-commit-different-trust-bytes": {"trustFileDigest": "c" * 64},
            "different-command-plan": {"commandPlanDigest": "d" * 64},
        }
        for name, fields in mutations.items():
            with self.subTest(name=name):
                expected = copy.deepcopy(evidence)
                expected.update(fields)
                expected["producerInvocationId"] = ci._github_binding_invocation_id(
                    {
                        key: value
                        for key, value in expected.items()
                        if key != "producerInvocationId"
                    }
                )
                self.assertTrue(
                    ci.execution_binding_external_context_errors(
                        evidence,
                        ci.execution_binding_digest(evidence),
                        synthetic_external_context(expected),
                    )
                )

        runner = ci.FoundationRunner("policy", ci.strict_json_load_file(ci.BASELINE_PATH))
        try:
            records, digest = ci.ci_trust_file_set_authority(
                git=runner.tools["git"],
                environment=runner.child_environment,
            )
        finally:
            runner.cleanup_task_resources()
        self.assertEqual([record["relativePath"] for record in records], list(ci.CI_TRUST_FILE_PATHS))
        self.assertTrue(all(record["gitMode"] in {"100644", "100755"} for record in records))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        changed = copy.deepcopy(records)
        changed[0]["sha256"] = "e" * 64
        changed_digest = hashlib.sha256(
            ci._canonical_frame(
                {"schemaVersion": ci.CI_TRUST_FILE_SET_SCHEMA_VERSION, "files": changed}
            )
        ).hexdigest()
        self.assertNotEqual(changed_digest, digest)

    def test_seventh_review_exact_policy_in_ubuntu_slot_fails_before_replay(self) -> None:
        policy_evidence = self.github_binding("repository-policy")
        ubuntu_expected = self.github_binding("ubuntu-canonical")
        errors = ci.execution_binding_external_context_errors(
            policy_evidence,
            ci.execution_binding_digest(policy_evidence),
            synthetic_external_context(ubuntu_expected),
        )
        self.assertTrue(any("external" in error or "authority" in error for error in errors), errors)

        runner = SimpleNamespace(
            profile="all",
            command_plan=[],
            command_plan_digest=ubuntu_expected["commandPlanDigest"],
        )
        with mock.patch.object(ci, "verify_evidence_file_set", return_value=errors), mock.patch.object(
            ci, "_read_evidence_documents_for_replay"
        ) as read_evidence, mock.patch.object(ci, "run_verification_replay") as replay:
            result_errors, transcript = ci.verify_evidence_with_replay(
                Path("unused-evidence-root"),
                expected_context=synthetic_external_context(ubuntu_expected),
                verification_runner=runner,
            )
        self.assertIsNone(transcript)
        self.assertTrue(result_errors)
        read_evidence.assert_not_called()
        replay.assert_not_called()

    def test_workflow_verifier_command_mutation_matrix_is_rejected(self) -> None:
        workflow = ci.WORKFLOW_PATH.read_text(encoding="utf-8")
        policy_command = ci.FINAL_VERIFIER_COMMANDS["repository-policy"]
        ubuntu_command = ci.FINAL_VERIFIER_COMMANDS["ubuntu-canonical"]
        windows_command = ci.FINAL_VERIFIER_COMMANDS["windows-compatibility"]
        terminal = f"        run: '{policy_command}'\n\n  ubuntu-canonical:"
        self.assertIn(terminal, workflow)
        intervening_step = workflow.replace(
            terminal,
            f"        run: '{policy_command}'\n\n"
            "      - name: Candidate-controlled step after verifier\n"
            "        run: echo unsafe\n\n  ubuntu-canonical:",
            1,
        )
        mutations = {
            "missing-profile": workflow.replace(" --expected-profile policy", "", 1),
            "policy-to-static": workflow.replace(policy_command, policy_command.replace("policy", "static", 1), 1),
            "ubuntu-to-policy": workflow.replace(ubuntu_command, ubuntu_command.replace("all", "policy", 1), 1),
            "windows-to-policy": workflow.replace(windows_command, windows_command.replace("all", "policy", 1), 1),
            "evidence-variable": workflow.replace("--expected-profile policy", "--expected-profile $PROFILE_FROM_SUMMARY", 1),
            "repository-file": workflow.replace("--expected-profile policy", "--expected-profile $(Get-Content profile.txt)", 1),
            "repository-environment": workflow.replace("--expected-profile policy", "--expected-profile $CI_PROFILE", 1),
            "missing-producer-job": workflow.replace(" --expected-producer-job repository-policy-producer", "", 1),
            "missing-verifier-job": workflow.replace(" --expected-verifier-job repository-policy", "", 1),
            "missing-os": workflow.replace(" --expected-runner-os Linux", "", 1),
            "wrong-producer": workflow.replace("--expected-producer-job repository-policy-producer", "--expected-producer-job ubuntu-canonical-producer", 1),
            "wrong-verifier": workflow.replace("--expected-verifier-job repository-policy", "--expected-verifier-job ubuntu-canonical", 1),
            "evidence-job-field": workflow.replace("--expected-verifier-job repository-policy", "--expected-verifier-job $JOB_FROM_SUMMARY", 1),
            "removed-run-attempt-sha-binding": workflow.replace(
                policy_command,
                "GITHUB_RUN_ID= GITHUB_RUN_ATTEMPT= GITHUB_SHA= " + policy_command,
                1,
            ),
            "untrusted-intervening-step": intervening_step,
            "continue-on-error": workflow.replace(
                "      - name: Verify untrusted policy evidence by fresh replay\n",
                "      - name: Verify untrusted policy evidence by fresh replay\n        continue-on-error: true\n",
                1,
            ),
            "neutralized-exit": workflow.replace(policy_command, policy_command + " || true", 1),
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(candidate, workflow, name)
                self.assertTrue(ci.check_workflow_text(candidate), name)

    def test_cross_file_binding_and_coherent_forgery_are_rejected(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        plan = compact_policy_fixture_plan()
        with tempfile.TemporaryDirectory(prefix="ci7-cross-file-binding-") as temp_dir, mock.patch.object(
            ci, "expected_command_authority", return_value=plan
        ):
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            runner = fake_runner(baseline)
            ci.create_fresh_evidence_root(output, repo_root=repo)
            with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
                ci.write_evidence(runner, empty_comparison())
            expected_context = synthetic_external_context(runner.execution_binding)

            documents = {
                name: ci.strict_json_load_file(output / name)
                for name in (
                    "summary.json",
                    "observed-debt.json",
                    "resolved-candidates.json",
                    "command-results.json",
                )
            }
            forged_binding = copy.deepcopy(runner.execution_binding)
            forged_binding["trustFileDigest"] = "f" * 64
            forged_digest = ci.execution_binding_digest(forged_binding)
            for document in documents.values():
                document["executionBinding"] = copy.deepcopy(forged_binding)
                document["executionBindingDigest"] = forged_digest
            payloads = {
                "observed-debt.json": ci._json_bytes(documents["observed-debt.json"]),
                "resolved-candidates.json": ci._json_bytes(documents["resolved-candidates.json"]),
                "command-results.json": ci._json_bytes(documents["command-results.json"]),
            }
            payloads["summary.md"] = ci.render_summary_markdown(
                documents["summary.json"]
            ).encode("utf-8")
            documents["summary.json"]["evidenceManifest"] = [
                {
                    "relativeFilename": name,
                    "byteLength": len(payloads[name]),
                    "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                    "documentKind": ci.EVIDENCE_DOCUMENT_KINDS[name],
                }
                for name in ci.EVIDENCE_MANIFEST_FILE_NAMES
            ]
            payloads["summary.json"] = ci._json_bytes(documents["summary.json"])
            for name, data in payloads.items():
                (output / name).write_bytes(data)
            errors = ci.verify_evidence_file_set(
                output,
                repo_root=repo,
                expected_command_plan=plan,
                expected_context=expected_context,
            )
        self.assertTrue(any("external" in error for error in errors), errors)

    def test_evidence_profile_monkeypatch_never_selects_replay_profile(self) -> None:
        runner, documents, comparison = sixth_review_replay_fixture()
        expected_context = synthetic_external_context(runner.execution_binding)
        forged = copy.deepcopy(documents)
        forged["summary.json"]["profile"] = "policy"
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()
        transcript, errors = ci.run_verification_replay(
            forged,
            expected_context=expected_context,
            verification_runner=runner,
        )
        runner.run.assert_called_once_with()
        self.assertEqual(runner.profile, "static")
        self.assertEqual(transcript["profile"], "static")
        self.assertTrue(any("profile" in error for error in errors), errors)
        source = inspect.getsource(ci.run_verification_replay)
        self.assertNotIn('summary.get("profile"', source)
        self.assertNotIn("FoundationRunner(", source)

    def test_forged_pass_regression_remains_rejected_with_external_binding(self) -> None:
        runner, documents, comparison = sixth_review_replay_fixture()
        forged = copy.deepcopy(documents)
        commands = forged["command-results.json"]
        for record in commands["records"]:
            record["producerObservations"] = []
            if record["commandClass"] == "direct-syntax":
                record["exitCode"] = 0
                record["parsedFailureSummary"] = {
                    "status": "pass",
                    "diagnostic": "forged PASS",
                }
        commands["observations"] = []
        coherently_rebind_claimed_transcript(forged)
        _transcript, errors = ci.compare_verification_replay_claims(
            forged,
            runner,
            comparison,
        )
        self.assertTrue(errors)
        self.assertTrue(
            any(
                token in " ".join(errors)
                for token in ("transcript", "observations", "producerObservation")
            ),
            errors,
        )


class CI8FreshVerifierTrustDomainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = ci.WORKFLOW_PATH.read_text(encoding="utf-8")

    def assert_rejected(self, candidate: str, label: str) -> None:
        self.assertNotEqual(candidate, self.workflow, label)
        self.assertTrue(ci.check_workflow_text(candidate), label)

    def test_fresh_producer_verifier_job_policy_matrix(self) -> None:
        parsed = ci.parse_canonical_workflow_yaml(self.workflow)
        jobs = parsed["jobs"]
        expected = {
            "repository-policy": "repository-policy-producer",
            "ubuntu-canonical": "ubuntu-canonical-producer",
            "windows-compatibility": "windows-compatibility-producer",
        }
        for verifier, producer in expected.items():
            with self.subTest(verifier=verifier):
                self.assertEqual(jobs[verifier]["needs"], [producer])
                self.assertNotIn("needs", jobs[producer])
                self.assertEqual(jobs[verifier]["steps"][-1]["run"], ci.FINAL_VERIFIER_COMMANDS[verifier])
                self.assertNotIn("--verify-evidence", "\n".join(
                    str(step.get("run", "")) for step in jobs[producer]["steps"]
                ))
        self.assertEqual(jobs["final-result"]["needs"], list(expected))

    def test_artifact_upload_download_boundary_is_one_to_one(self) -> None:
        parsed = ci.parse_canonical_workflow_yaml(self.workflow)
        jobs = parsed["jobs"]
        names: list[str] = []
        for verifier, authority in ci.WORKFLOW_JOB_PROFILE_AUTHORITY.items():
            producer = authority["producerJobId"]
            uploads = [
                step for step in jobs[producer]["steps"]
                if str(step.get("uses", "")).startswith("actions/upload-artifact@")
            ]
            downloads = [
                step for step in jobs[verifier]["steps"]
                if str(step.get("uses", "")).startswith("actions/download-artifact@")
            ]
            self.assertEqual(len(uploads), 1)
            self.assertEqual(len(downloads), 1)
            self.assertEqual(uploads[0]["with"]["name"], authority["artifactIdentity"])
            self.assertEqual(downloads[0]["with"]["name"], authority["artifactIdentity"])
            self.assertEqual(downloads[0]["with"]["path"], authority["evidenceRoot"])
            self.assertEqual(uploads[0]["with"]["path"].splitlines(), [
                f".ci-results/{name}" for name in ci.EVIDENCE_FILE_NAMES
            ])
            names.append(authority["artifactIdentity"])
        self.assertEqual(len(names), len(set(names)))

    def test_same_job_verification_and_verify_then_upload_are_rejected(self) -> None:
        marker = "      - name: Upload untrusted policy evidence"
        injected = (
            "      - name: Same-job verifier\n"
            "        run: python -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile policy\n\n"
            + marker
        )
        self.assert_rejected(self.workflow.replace(marker, injected, 1), "same-job-verifier")
        self.assert_rejected(
            self.workflow.replace(
                "      - name: Generate untrusted policy evidence",
                "      - name: Verify evidence then upload\n"
                "        run: python -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile policy\n\n"
                "      - name: Generate untrusted policy evidence",
                1,
            ),
            "verify-then-upload",
        )

    def test_unqualified_interpreter_rejection_matrix(self) -> None:
        substitutions = {
            "python": ('"$CI_TRUSTED_PYTHON" -B', "python -B"),
            "python3": ('"$CI_TRUSTED_PYTHON" -B', "python3 -B"),
            "py": ('"$CI_TRUSTED_PYTHON" -B', "py -3.12 -B"),
            "path-resolved": ('"$CI_TRUSTED_PYTHON" -B', '"$(command -v python)" -B'),
            "windows-path-resolved": (
                "& $env:CI_TRUSTED_PYTHON -B",
                "& (Get-Command python.exe).Source -B",
            ),
        }
        for label, (source, replacement) in substitutions.items():
            with self.subTest(label=label):
                self.assert_rejected(self.workflow.replace(source, replacement, 1), label)

    def test_terminal_verifier_step_matrix(self) -> None:
        following_jobs = {
            "repository-policy": "ubuntu-canonical:",
            "ubuntu-canonical": "windows-compatibility:",
            "windows-compatibility": "final-result:",
        }
        for verifier, following_job in following_jobs.items():
            command = ci.FINAL_VERIFIER_COMMANDS[verifier]
            marker = f"        run: '{command}'\n\n  {following_job}"
            self.assertIn(marker, self.workflow)
            for suffix, body in (
                ("upload", "uses: actions/upload-artifact@" + ci.APPROVED_ACTIONS["actions/upload-artifact"]["sha"]),
                ("repository-run", "run: python -B candidate.py"),
                ("cleanup", "run: echo cleanup"),
            ):
                replacement = (
                    f"        run: '{command}'\n\n"
                    f"      - name: Forbidden post-verifier {suffix}\n"
                    f"        {body}\n\n  {following_job}"
                )
                with self.subTest(verifier=verifier, suffix=suffix):
                    self.assert_rejected(self.workflow.replace(marker, replacement, 1), f"{verifier}-{suffix}")

    def test_producer_material_reuse_matrix_is_rejected(self) -> None:
        cases = {
            "producer-node-modules-artifact": self.workflow.replace(
                "            .ci-results/command-results.json",
                "            .ci-results/command-results.json\n            developer/node_modules",
                1,
            ),
            "producer-path": self.workflow.replace(
                "  repository-policy:\n",
                "  repository-policy:\n    env:\n      PATH: ${{ needs.repository-policy-producer.outputs.path }}\n",
                1,
            ),
            "producer-temp": self.workflow.replace(
                "  repository-policy:\n",
                "  repository-policy:\n    env:\n      TEMP: ${{ needs.repository-policy-producer.outputs.temp }}\n",
                1,
            ),
            "restore-node-modules": self.workflow.replace(
                "      - name: Download untrusted Ubuntu evidence",
                "      - name: Restore producer node_modules\n"
                "        uses: actions/download-artifact@"
                + ci.APPROVED_ACTIONS["actions/download-artifact"]["sha"]
                + "\n\n      - name: Download untrusted Ubuntu evidence",
                1,
            ),
        }
        for label, candidate in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(candidate, label)

    def test_github_command_file_child_environment_isolation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-command-file-isolation-") as temp_dir:
            private_temp = Path(temp_dir)
            source = {
                "PATH": str(Path(sys.executable).parent),
                "GITHUB_PATH": str(private_temp / "add_path_123"),
                "GITHUB_ENV": str(private_temp / "set_env_123"),
                "GITHUB_OUTPUT": str(private_temp / "set_output_123"),
                "GITHUB_STATE": str(private_temp / "save_state_123"),
                "ACTIONS_RUNTIME_TOKEN": "secret",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret",
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://attacker.invalid",
                "RUNNER_TEMP": str(private_temp / "runner-temp"),
                "RUNNER_TOOL_CACHE": str(private_temp / "toolcache"),
                "TEMP": str(private_temp / "producer-temp"),
                "TMP": str(private_temp / "producer-tmp"),
            }
            child = ci.child_process_environment(
                {"python": sys.executable},
                source_environment=source,
                private_temp_root=private_temp,
            )
            for name in (
                "GITHUB_PATH", "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STATE",
                "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL", "RUNNER_TEMP", "RUNNER_TOOL_CACHE",
            ):
                self.assertNotIn(name, child)
            for name in ("TEMP", "TMP", "TMPDIR"):
                self.assertEqual(Path(child[name]), private_temp.resolve(strict=True))

    def test_github_command_file_poisoning_regression_keeps_fake_python_inert(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-command-file-poison-") as temp_dir:
            root = Path(temp_dir)
            producer_temp = root / "producer-temp"
            verifier_temp = root / "verifier-temp"
            attacker = root / "attacker-bin"
            producer_temp.mkdir()
            verifier_temp.mkdir()
            attacker.mkdir()
            command_file = producer_temp / "add_path_fixture"
            command_file.write_text(str(attacker), encoding="utf-8")
            sentinel = root / "fake-python-ran"
            fake_python = attacker / ("python.exe" if os.name == "nt" else "python")
            fake_python.write_text(str(sentinel), encoding="utf-8")
            child = ci.child_process_environment(
                {"python": sys.executable},
                source_environment={
                    "PATH": str(attacker),
                    "GITHUB_PATH": str(command_file),
                    "TEMP": str(producer_temp),
                },
                private_temp_root=verifier_temp,
            )
            self.assertNotIn(str(attacker), child["PATH"])
            self.assertNotIn("GITHUB_PATH", child)
            self.assertEqual(Path(child["TEMP"]), verifier_temp.resolve(strict=True))
            self.assertEqual(Path(sys.executable).resolve(strict=True), Path(child["PATH"].split(os.pathsep)[0]) / Path(sys.executable).name)
            self.assertFalse(sentinel.exists())

    def test_artifact_source_and_job_substitution_matrix(self) -> None:
        substitutions = {
            "policy-in-ubuntu": (
                "untrusted-ubuntu-canonical-${{ runner.os }}-${{ github.run_attempt }}",
                "untrusted-repository-policy-${{ runner.os }}-${{ github.run_attempt }}",
            ),
            "ubuntu-in-windows": (
                "untrusted-windows-compatibility-${{ runner.os }}-${{ github.run_attempt }}",
                "untrusted-ubuntu-canonical-${{ runner.os }}-${{ github.run_attempt }}",
            ),
            "wrong-producer-job": (
                "--expected-producer-job ubuntu-canonical-producer",
                "--expected-producer-job windows-compatibility-producer",
            ),
            "wrong-untrusted-root": (
                "--untrusted-evidence-root .ci-untrusted/ubuntu-canonical",
                "--untrusted-evidence-root .ci-untrusted/windows-compatibility",
            ),
        }
        for label, (source, replacement) in substitutions.items():
            with self.subTest(label=label):
                self.assert_rejected(self.workflow.replace(source, replacement, 1), label)

    def test_linux_live_gate_and_fresh_closure_flags_are_mandatory(self) -> None:
        cases = {
            "policy-live-gate": self.workflow.replace(" --require-linux-containment-self-test", "", 1),
            "ubuntu-live-gate": self.workflow.replace(
                " --require-linux-containment-self-test --require-fresh-runtime-closure",
                " --require-fresh-runtime-closure",
                1,
            ),
            "ubuntu-closure": self.workflow.replace(" --require-fresh-runtime-closure", "", 1),
            "windows-closure": self.workflow.replace(" --require-fresh-runtime-closure", "", 1).replace(" --require-fresh-runtime-closure", "", 1),
        }
        for label, candidate in cases.items():
            with self.subTest(label=label):
                self.assert_rejected(candidate, label)


class CI8PosixContainmentStateMachineTest(unittest.TestCase):
    @staticmethod
    def identity(
        pid: int,
        parent: int,
        *,
        start: int | None = None,
        group: int | None = None,
        session: int | None = None,
        generation: int = 1,
    ) -> ci.PosixProcessIdentity:
        return ci.PosixProcessIdentity(
            pid=pid,
            starttime=pid * 100 if start is None else start,
            parent_pid=parent,
            process_group=pid if group is None else group,
            session_id=pid if session is None else session,
            discovery_generation=generation,
        )

    def test_setsid_escape_model_remains_in_descendant_registry(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        child = self.identity(20, 10, group=20, session=20)
        discovered = state.observe({20: child})
        self.assertEqual(discovered, [child])
        changed_session = self.identity(20, 10, start=child.starttime, group=99, session=99, generation=2)
        state.observe({20: changed_session})
        self.assertEqual([item.key() for item in state.active_identities()], [child.key()])

    def test_double_fork_model_tracks_grandchild_across_parent_exit(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        parent = self.identity(20, 10)
        daemon = self.identity(30, 20, group=30, session=30)
        state.observe({20: parent, 30: daemon})
        state.mark_reaped(20)
        reparented = self.identity(30, 10, start=daemon.starttime, group=30, session=30, generation=2)
        state.observe({30: reparented})
        self.assertEqual([item.key() for item in state.active_identities()], [daemon.key()])
        self.assertFalse(state.clean())

    def test_orphan_reparent_model_requires_explicit_reap(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        orphan = self.identity(40, 10)
        state.observe({40: orphan})
        state.observe({})
        self.assertFalse(state.clean())
        state.mark_reaped(40)
        state.observe({})
        self.assertTrue(state.clean())

    def test_pid_reuse_model_fails_closed(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        state.observe({20: self.identity(20, 10, start=100)})
        state.observe({20: self.identity(20, 10, start=200, generation=2)})
        self.assertTrue(any("PID reuse" in error for error in state.failures), state.failures)
        self.assertFalse(state.clean())

    def test_proc_and_pidfd_failure_model_is_sticky(self) -> None:
        for reason in (
            "/proc enumeration failed",
            "/proc/20/stat read failed",
            "pidfd_open failed for PID 20",
            "pidfd signal failed for PID 20",
            "unexpected concurrent child exists in supervisor domain",
        ):
            with self.subTest(reason=reason):
                state = ci.PosixContainmentStateMachine(10)
                state.fail(reason)
                state.observe({})
                self.assertFalse(state.clean())
                self.assertIn(reason, state.failures)

    def test_settle_timeout_and_registry_overflow_model_fail_closed(self) -> None:
        timed_out = ci.PosixContainmentStateMachine(10)
        timed_out.fail("descendant cleanup settle timeout")
        self.assertFalse(timed_out.clean())
        overflow = ci.PosixContainmentStateMachine(10)
        snapshot = {
            pid: self.identity(pid, 10, start=pid + 100_000)
            for pid in range(100, 4197)
        }
        overflow.observe(snapshot)
        self.assertIn("descendant registry overflow", overflow.failures)

    def test_known_descendant_ancestry_escape_is_not_treated_as_clean(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        child = self.identity(20, 10)
        state.observe({20: child})
        escaped = self.identity(20, 1, start=child.starttime, generation=2)
        state.observe({20: escaped})
        self.assertTrue(any("escaped supervisor ancestry" in error for error in state.failures))
        self.assertEqual([item.key() for item in state.active_identities()], [child.key()])


class _CI8FixtureLease:
    def __init__(self, path: Path) -> None:
        self.path = str(path.resolve(strict=True))
        self.expected_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        self.drifted = False
        self.closed = False

    def verify(self) -> tuple[bool, str | None]:
        if self.closed or self.drifted:
            return False, "fixture executable identity drifted"
        return True, None

    def close(self) -> None:
        self.closed = True


class CI8RuntimeDependencyClosureTest(unittest.TestCase):
    def make_guard(
        self, root: Path
    ) -> tuple[ci.RuntimeDependencyClosure, ci.RuntimeDependencyClosureGuard, Path]:
        developer = root / "developer"
        backend = root / "backend"
        node_modules = developer / "node_modules"
        vitest = node_modules / "vitest"
        bin_root = node_modules / ".bin"
        vitest.mkdir(parents=True)
        bin_root.mkdir()
        backend.mkdir()
        (developer / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
        (backend / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
        (vitest / "vitest.mjs").write_bytes(b"export default 1;\n")
        (vitest / "package.json").write_text(
            '{"name":"vitest","version":"1.0.0"}\n', encoding="utf-8"
        )
        helper = bin_root / "helper"
        helper.write_bytes(b"AAAA")
        tool = root / "trusted-node"
        tool.write_bytes(b"trusted-tool")
        vitest_record = {
            "resolvedEntrypoint": "developer/node_modules/vitest/vitest.mjs",
            "packageVersion": "1.0.0",
            "entrypointSha256": hashlib.sha256((vitest / "vitest.mjs").read_bytes()).hexdigest(),
        }
        document = {
            "dependencyRoots": [{"logicalRoot": "developer/node_modules"}],
            "lockfiles": [
                {"relativePath": "developer/package-lock.json"},
                {"relativePath": "backend/package-lock.json"},
            ],
            "vitest": vitest_record,
        }
        placeholder = SimpleNamespace(document=document)
        digest, count = ci._remeasure_dependency_semantics(placeholder, repo_root=root)
        lease = _CI8FixtureLease(tool)
        closure = ci.RuntimeDependencyClosure(
            document=document,
            runtime_digest="1" * 64,
            dependency_digest=digest,
            member_count=count,
            dependency_roots=(node_modules.resolve(strict=True),),
            leases={"node": lease},
        )
        guard = ci.RuntimeDependencyClosureGuard(
            closure,
            repo_root=root,
            watcher_factory=ci._ModelMutationWatcher,
        )
        return closure, guard, helper

    def test_runtime_dependency_closure_schema_and_digest(self) -> None:
        runner = ci.FoundationRunner(
            "policy",
            ci.strict_json_load_file(ci.BASELINE_PATH),
            enable_runtime_closure=True,
        )
        try:
            document = runner.runtime_closure_document
            self.assertIn(document["measurementStatus"], {
                "measured-complete", "local-nondependency-npm-unavailable"
            })
            self.assertEqual(document["closureSchemaVersion"], ci.RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION)
            self.assertEqual(document["profile"], "policy")
            self.assertEqual(document["nodePath"], [])
            self.assertEqual(document["dependencyMemberCount"], 0)
            self.assertEqual(
                document["closureDigest"],
                hashlib.sha256(ci._canonical_frame({
                    key: value for key, value in document.items() if key != "closureDigest"
                })).hexdigest(),
            )
            for key in ("pythonExecutable", "nodeExecutable", "npmEntrypoint", "lockfiles", "dependencyRoots"):
                self.assertIn(key, document)
        finally:
            runner.cleanup_task_resources()

    def test_unplanned_node_path_and_workspace_runtime_shadowing_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-node-path-") as temp_dir:
            root = Path(temp_dir)
            with self.assertRaisesRegex(ValueError, "NODE_PATH"):
                ci.RuntimeDependencyClosure.build(
                    "policy",
                    {},
                    {},
                    repo_root=root,
                    source_environment={"NODE_PATH": str(root / "shadow")},
                )
            fake_node = root / ("node.exe" if os.name == "nt" else "node")
            fake_node.write_bytes(b"fake-node")
            tools, errors = ci.resolve_trusted_tools(
                {"node"},
                source_environment={"PATH": str(root)},
                repo_root=root,
            )
            self.assertIn("node", tools)
            self.assertNotEqual(Path(tools["node"]), fake_node)
            self.assertFalse(ci._path_is_within(Path(tools["node"]), root))
            fake_npm = root / ("npm.cmd" if os.name == "nt" else "npm")
            fake_npm.write_bytes(b"fake-npm")
            npm_tools, npm_errors = ci.resolve_trusted_tools(
                {"npm"},
                source_environment={"PATH": str(root)},
                repo_root=root,
            )
            self.assertNotIn("npm", npm_tools)
            self.assertTrue(npm_errors)

    def test_vitest_change_and_restore_is_sticky(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-closure-restore-") as temp_dir:
            closure, guard, helper = self.make_guard(Path(temp_dir))
            original = helper.read_bytes()
            try:
                helper.write_bytes(b"BBBB")
                helper.write_bytes(original)
                guard.watcher.emit("Vitest/node_modules helper write and restore")
                errors = guard.verify("change-and-restore")
                self.assertTrue(guard.mutated)
                self.assertTrue(any("sticky" in error for error in errors), errors)
            finally:
                guard.close()
                closure.close()

    def test_same_size_replacement_is_found_by_pre_post_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-closure-same-size-") as temp_dir:
            closure, guard, helper = self.make_guard(Path(temp_dir))
            original = helper.read_bytes()
            try:
                helper.write_bytes(b"BBBB")
                errors = guard.verify("same-size-replacement")
                self.assertTrue(any("manifest drift" in error or "sticky" in error for error in errors), errors)
                helper.write_bytes(original)
                self.assertTrue(guard.verify("restored"))
                self.assertTrue(guard.mutated)
            finally:
                guard.close()
                closure.close()

    def test_rename_delete_recreate_mutation_matrix_is_sticky(self) -> None:
        for operation in ("rename replacement", "delete/recreate", "mode change", "attribute change"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                prefix="ci8-closure-name-mutation-"
            ) as temp_dir:
                closure, guard, _helper = self.make_guard(Path(temp_dir))
                try:
                    guard.watcher.emit(operation)
                    self.assertTrue(guard.verify(operation))
                    self.assertEqual(guard.evidence()["mutationState"], "mutated")
                finally:
                    guard.close()
                    closure.close()

    def test_watcher_queue_overflow_is_a_hard_sticky_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-closure-overflow-") as temp_dir:
            closure, guard, _helper = self.make_guard(Path(temp_dir))
            try:
                guard.watcher.emit("IN_Q_OVERFLOW", overflow=True)
                errors = guard.verify("queue-overflow")
                self.assertTrue(any("overflow" in error for error in errors), errors)
                self.assertTrue(guard.evidence()["queueOverflow"])
            finally:
                guard.close()
                closure.close()

    def test_tool_executable_drift_is_a_hard_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-tool-drift-") as temp_dir:
            closure, guard, _helper = self.make_guard(Path(temp_dir))
            try:
                closure.leases["node"].drifted = True
                errors = guard.verify("tool-drift")
                self.assertTrue(any("executable identity drifted" in error for error in errors), errors)
            finally:
                guard.close()
                closure.close()

    def test_hardlink_symlink_and_bin_shadow_events_are_sticky(self) -> None:
        for operation in ("hardlink substitution", "symlink substitution", "workspace .bin shadowing"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                prefix="ci8-closure-link-mutation-"
            ) as temp_dir:
                closure, guard, _helper = self.make_guard(Path(temp_dir))
                try:
                    guard.watcher.emit(operation)
                    errors = guard.verify(operation)
                    self.assertTrue(errors)
                    self.assertTrue(guard.mutated)
                finally:
                    guard.close()
                    closure.close()

    def test_dependency_backed_command_records_bind_the_full_closure_guard(self) -> None:
        spec = synthetic_command_spec("dependency-command", "frontend-security", 0)
        spec["profile"] = "frontend"
        spec["toolRole"] = "node-test"
        runner = object.__new__(ci.FoundationRunner)
        runner.command_plan_by_id = {spec["commandId"]: spec}
        runner.runtime_closure_digest = "a" * 64
        runner.dependency_closure_digest = "b" * 64
        runner.runtime_dependency_closure = SimpleNamespace(leases={})
        runner.runtime_dependency_guard = SimpleNamespace(
            evidence=lambda: {
                "guardSchemaVersion": ci.RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
                "watcherBackend": "fixture",
                "active": True,
                "activeDuringReplay": True,
                "mutationState": "clean",
                "queueOverflow": False,
                "mutationEventCount": 0,
            }
        )
        record = ci.FoundationRunner._bind_command_record(
            runner,
            synthetic_record_from_spec(spec),
            actual_argv=spec["executionArgv"],
        )
        for key in (
            "runtimeClosureDigest", "dependencyClosureDigest", "nodePath",
            "resolvedTestRunnerEntrypoint", "resolvedTestRunnerSha256",
            "closureWatcherActive", "closureMutationState", "runtimeClosureGuard",
        ):
            self.assertIn(key, record)
        self.assertEqual(record["nodePath"], [])
        self.assertTrue(record["closureWatcherActive"])
        forged = copy.deepcopy(record)
        forged["closureWatcherActive"] = False
        errors: list[str] = []
        ci._validate_command_record(forged, 0, errors)
        self.assertTrue(any("watcher" in error for error in errors), errors)


class CI10PathAndAuthorizationContextTest(unittest.TestCase):
    FROZEN_EXPECTED = {
        "B-SKIP-PDF-RECONCILIATION": (
            "sha256:33bc9b849164b41e15815b3b0db644c6b5bb44620715cd08b26852dda0a22a2d"
        ),
        "B-SKIP-CHECKLIST-CONSISTENCY": (
            "sha256:6817f608de514acb77d92038f93328ef15d0c8da44cf377126984efb1d2cee07"
        ),
        "B-SKIP-RELEASE-ZIP": (
            "sha256:8ae895e21db520d968113c11eac0e2df73ed14d70521c5ac5957bb3f92f0da7f"
        ),
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls.entries = {
            entry["id"]: entry for entry in cls.baseline["releaseOnlySkips"]
        }
        entry = cls.entries["B-SKIP-CHECKLIST-CONSISTENCY"]
        raw = frozen_v1_release_skip_raw_observation(entry)
        item = ci.observation(
            entry["commandClass"],
            entry["testOrPathScope"],
            entry["expectedOutcome"],
            entry["allowedNormalizedSignature"][0],
            "static-suite",
            raw_observation=raw,
        )
        spec, cls.context_record, observations = ci9_static_evidence_fixture([item])
        cls.context_item = observations[0]
        cls.context_raw = cls.context_item["rawObservation"]
        cls.context_outputs = ci._raw_failure_outputs(
            cls.context_raw, cls.context_record
        )
        cls.producer_context = {
            "producerObservationUniverseDigest": cls.context_item[
                "producerObservationUniverseDigest"
            ],
            "producerTranscriptDigest": cls.context_item["producerTranscriptDigest"],
            "profileCompletedCommandClassSetDigest": cls.context_item[
                "profileCompletedCommandClassSetDigest"
            ],
        }
        cls.base_execution_binding = synthetic_execution_binding(
            "static", ci.command_plan_digest([spec])
        )
        cls.base_authorization_binding = (
            ci.authorization_context_binding_from_execution_binding(
                cls.base_execution_binding
            )
        )
        cls.base_authorization_digest = ci.authorization_context_binding_digest(
            cls.base_authorization_binding
        )

    @staticmethod
    def windows_root_cases() -> list[tuple[str, str, str]]:
        base = "D:\\ci10-matrix"
        cases = [
            (
                "safe",
                base + "\\safe-root\\ci-phase2-foundation",
                base + "\\safe-root\\ci-phase2-foundation",
            )
        ]
        for segment in (
            "repo",
            "temp-case",
            "new-root",
            "back-root",
            "form-root",
            "u1234",
            "r",
            "t",
            "n",
            "b",
            "f",
            "root with spaces",
            "非ASCII目录",
        ):
            cases.append((segment, base + "\\" + segment, base + "\\" + segment))
        cases.extend(
            [
                ("lower-drive", base + "\\repo", "d:\\CI10-MATRIX\\REPO"),
                ("forward-slash", base + "\\repo", "D:/ci10-matrix/repo"),
                ("mixed-separator", base + "\\repo", "d:/CI10-MATRIX\\repo"),
            ]
        )
        return cases

    @classmethod
    def raw_for_root(
        cls,
        entry_id: str,
        repository_root: str,
        observed_root: str | None = None,
        *,
        observation_ordinal: int = 0,
    ) -> dict:
        entry = cls.entries[entry_id]
        name = entry["testOrPathScope"].removeprefix("result:")
        detail = copy.deepcopy(FROZEN_V1_RELEASE_SKIP_DETAILS[name])
        root_in_output = observed_root or repository_root
        if isinstance(detail.get("reason"), str):
            detail["reason"] = detail["reason"].replace("<repo>", root_in_output)
        result = {"name": name, "status": "pass", "detail": detail}
        with mock.patch.object(ci, "REPO_ROOT", Path(repository_root)):
            return ci.make_raw_observation(
                "static-suite",
                4,
                observation_ordinal,
                "static-producer-v1",
                name,
                ci.STATIC_SUITE_RELATIVE_PATH,
                result,
                ci.canonical_failure_digest(result),
            )

    def full_context_digest(self, authorization_digest: str) -> str:
        context = {
            **self.producer_context,
            "authorizationContextBindingDigest": authorization_digest,
        }
        material = ci.derive_canonical_failure_material(
            self.context_record,
            self.context_raw,
            self.context_outputs["parserSemantics"],
            self.context_outputs["derivedFailureMembers"],
            self.context_outputs["signature"],
            self.context_outputs["outcome"],
            context,
        )
        self.assertEqual(
            material["authorizationContextBindingDigest"], authorization_digest
        )
        return ci.canonical_failure_digest(material)

    @staticmethod
    def verifier_binding() -> dict:
        return {
            "bindingSchemaVersion": ci.VERIFIER_REPLAY_CONTEXT_BINDING_SCHEMA_VERSION,
            "bindingKind": "VerifierReplayContextBinding",
            "actualVerifierJobId": "local-verifier",
            "actualVerifierRunnerOS": "Windows",
            "verifierInvocationId": "5" * 64,
            "freshRuntimeClosureDigest": "4" * 64,
            "freshDependencyClosureDigest": "6" * 64,
            "linuxContainmentLiveTestResultDigest": "sha256:" + "7" * 64,
            "replayTranscriptDigest": "sha256:" + "8" * 64,
            "cleanupResult": "closed-clean",
        }

    def test_path_aware_windows_root_matrix(self) -> None:
        for label, root, observed in self.windows_root_cases():
            with self.subTest(label=label):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        observed, repository_root=root, task_roots=[]
                    ),
                    "<repo>",
                )
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        observed + "\\artifact/checklist.md",
                        repository_root=root,
                        task_roots=[],
                    ),
                    "<repo>/artifact/checklist.md",
                )

        repository_root = "C:\\repo"
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "C:\\repo2\\file.txt",
                repository_root=repository_root,
                task_roots=[],
            ),
            "<abs-path>",
        )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "repo is an ordinary word in this prose",
                repository_root=repository_root,
                task_roots=[],
            ),
            "repo is an ordinary word in this prose",
        )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "C:\\repo\\task\\file.txt",
                repository_root="C:\\repo",
                task_roots=["C:\\repo\\task"],
            ),
            "<task-root>/file.txt",
        )
        uri_cases = (
            (
                "D:\\ci10-matrix\\非ASCII目录",
                "file:///D:/ci10-matrix/%E9%9D%9EASCII%E7%9B%AE%E5%BD%95/"
                "developer/tests/js/example.js:1:2",
            ),
            (
                "D:\\ci10-matrix\\root with spaces",
                "file:///D:/ci10-matrix/root%20with%20spaces/"
                "developer/tests/js/example.js:1:2",
            ),
        )
        for root, value in uri_cases:
            with self.subTest(file_uri=root):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value, repository_root=root, task_roots=[]
                    ),
                    "<repo>/developer/tests/js/example.js:1:2",
                )

    def test_path_aware_posix_boundary_and_prose_matrix(self) -> None:
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "/tmp/CI10-Repo/file.txt",
                repository_root="/tmp/CI10-Repo",
                task_roots=[],
            ),
            "<repo>/file.txt",
        )
        for value in ("/tmp/ci10-repo/file.txt", "/tmp/CI10-Repo2/file.txt"):
            with self.subTest(value=value):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value,
                        repository_root="/tmp/CI10-Repo",
                        task_roots=[],
                    ),
                    "<abs-path>",
                )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "the repo remains ordinary prose",
                repository_root="/tmp/repo",
                task_roots=[],
            ),
            "the repo remains ordinary prose",
        )

    def test_escape_looking_segments_are_path_components(self) -> None:
        for segment in (
            "repo",
            "temp-case",
            "new-root",
            "back-root",
            "form-root",
            "u1234",
            "r",
            "t",
            "n",
            "b",
            "f",
        ):
            root = "D:\\ci10-segments\\" + segment
            with self.subTest(segment=segment):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        root + "\\child\\artifact.json",
                        repository_root=root,
                        task_roots=[],
                    ),
                    "<repo>/child/artifact.json",
                )

    def test_decoded_backslashes_and_actual_control_characters_are_distinct(self) -> None:
        root = "D:\\ci10\\repo"
        path_value = root + (
            "\\repo\\temp-case\\new-root\\back-root\\form-root"
            "\\u1234\\r\\t\\n\\b\\f\\artifact.json"
        )
        with mock.patch.object(ci, "REPO_ROOT", Path(root)):
            normalized_path = ci.raw_observation_json_value(path_value)
        self.assertEqual(
            normalized_path,
            (
                "<repo>/repo/temp-case/new-root/back-root/form-root/"
                "u1234/r/t/n/b/f/artifact.json"
            ),
        )
        literal_escapes = r"literal \r \t \n \b \f \u1234"
        self.assertEqual(ci.raw_observation_json_value(literal_escapes), literal_escapes)
        actual_controls = "actual\rreturn\bback\fform\x1b[31mred\x1b[0m\u202ebidi"
        safe = ci.raw_observation_json_value(actual_controls)
        for forbidden in ("\r", "\b", "\f", "\x1b", "\u202e"):
            self.assertNotIn(forbidden, safe)
        source = inspect.getsource(ci.normalize_authorized_path_text) + inspect.getsource(
            ci.raw_observation_json_value
        )
        self.assertNotIn("unicode_escape", source)
        self.assertNotIn("raw_unicode_escape", source)
        self.assertNotIn('.decode("unicode', source)

    def test_raw_observation_path_tokenization_precedes_escape_protection(self) -> None:
        root = "D:\\ci10\\u1234"
        value = root + r"\repo\u1234\r\t\n\b\f\evidence.json"
        with mock.patch.object(ci, "REPO_ROOT", Path(root)):
            normalized = ci.raw_observation_json_value(value)
        self.assertEqual(
            normalized,
            "<repo>/repo/u1234/r/t/n/b/f/evidence.json",
        )
        self.assertNotRegex(normalized, r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    def test_three_frozen_v1_digests_are_root_spelling_independent(self) -> None:
        for label, root, observed in self.windows_root_cases():
            for entry_id, expected in self.FROZEN_EXPECTED.items():
                with self.subTest(root=label, entry=entry_id):
                    raw = self.raw_for_root(entry_id, root, observed)
                    detail = raw["rawStructuredFields"]["detail"]
                    if entry_id != "B-SKIP-RELEASE-ZIP":
                        self.assertEqual(
                            detail["reason"], "missing_checklist:<repo>/checklist.md"
                        )
                    self.assertEqual(
                        ci.derive_frozen_v1_release_skip_signature(raw), expected
                    )

    def test_authorization_context_binding_schema_is_strict_and_non_circular(self) -> None:
        binding = copy.deepcopy(self.base_authorization_binding)
        digest = ci.authorization_context_binding_digest(binding)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(set(binding), ci.AUTHORIZATION_CONTEXT_BINDING_KEYS)
        self.assertEqual(
            ci.authorization_context_binding_errors(
                binding,
                digest,
                execution_binding=self.base_execution_binding,
                expected_context=synthetic_external_context(
                    self.base_execution_binding
                ),
            ),
            [],
        )
        for key in binding:
            with self.subTest(missing=key):
                candidate = copy.deepcopy(binding)
                candidate.pop(key)
                with self.assertRaises(ValueError):
                    ci.authorization_context_binding_digest(candidate)
        for forbidden in (
            "currentFullContextDigest",
            "derivedFailureDigest",
            "evidenceManifestDigest",
            "summaryDigest",
            "authorizationContextBindingDigest",
        ):
            with self.subTest(forbidden=forbidden):
                candidate = {**binding, forbidden: "sha256:" + "0" * 64}
                with self.assertRaises(ValueError):
                    ci.authorization_context_binding_digest(candidate)
        wrong_type = copy.deepcopy(binding)
        wrong_type["runId"] = 1
        with self.assertRaises(ValueError):
            ci.authorization_context_binding_digest(wrong_type)

    def test_stable_authorization_binding_mutation_matrix_changes_full_context(self) -> None:
        base = self.base_authorization_binding
        base_binding_digest = self.base_authorization_digest
        base_full_digest = self.full_context_digest(base_binding_digest)
        expected_context = synthetic_external_context(self.base_execution_binding)
        mutations = {
            "binding-mode": ("bindingMode", "github-actions"),
            "expected-profile": ("expectedProfile", "policy"),
            "producer-job": ("producerJobId", "other-producer"),
            "expected-verifier-job": (
                "expectedVerifierJobId",
                "other-verifier",
            ),
            "runner-os": ("runnerOS", "Linux"),
            "run-id": ("runId", "999"),
            "run-attempt": ("runAttempt", "2"),
            "event": ("eventName", "push"),
            "repository": ("repository", "owner/other"),
            "checkout-commit": ("checkoutCommit", "a" * 40),
            "checkout-tree": ("checkoutTree", "b" * 40),
            "baseline-commit": ("baselineCommit", "c" * 40),
            "baseline-tree": ("baselineTree", "d" * 40),
            "trust-file": ("trustFileDigest", "e" * 64),
            "command-plan": ("commandPlanDigest", "f" * 64),
            "producer-invocation": ("producerInvocationId", "9" * 64),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(base)
                changed[field] = value
                changed_binding_digest = ci.authorization_context_binding_digest(
                    changed
                )
                changed_full_digest = self.full_context_digest(
                    changed_binding_digest
                )
                self.assertNotEqual(changed_binding_digest, base_binding_digest)
                self.assertNotEqual(changed_full_digest, base_full_digest)
                self.assertTrue(
                    ci.authorization_context_binding_errors(
                        changed,
                        changed_binding_digest,
                        execution_binding=self.base_execution_binding,
                        expected_context=expected_context,
                    )
                )
        self.assertEqual(
            ci.derive_frozen_v1_release_skip_signature(self.context_raw),
            self.FROZEN_EXPECTED["B-SKIP-CHECKLIST-CONSISTENCY"],
        )

    def test_verifier_replay_binding_mutation_matrix_changes_envelope_only(self) -> None:
        producer_full_digest = self.full_context_digest(
            self.base_authorization_digest
        )
        full_set_digest = ci.current_full_context_digest_set_digest(
            [
                {
                    "commandId": "static-suite",
                    "testOrPathScope": self.context_item["testOrPathScope"],
                    "currentFullContextDigest": producer_full_digest,
                }
            ]
        )
        base = self.verifier_binding()
        base_replay_digest = ci.verifier_replay_context_digest(base)
        base_envelope = ci.replay_authorization_envelope_digest(
            current_full_context_set_digest=full_set_digest,
            authorization_context_binding_digest_value=(
                self.base_authorization_digest
            ),
            verifier_replay_context_digest_value=base_replay_digest,
        )
        mutations = {
            "verifier-job": ("actualVerifierJobId", "other-verifier"),
            "verifier-os": ("actualVerifierRunnerOS", "Linux"),
            "verifier-invocation": ("verifierInvocationId", "a" * 64),
            "runtime-closure": ("freshRuntimeClosureDigest", "b" * 64),
            "dependency-closure": ("freshDependencyClosureDigest", "c" * 64),
            "linux-live-result": (
                "linuxContainmentLiveTestResultDigest",
                "sha256:" + "d" * 64,
            ),
            "replay-transcript": (
                "replayTranscriptDigest",
                "sha256:" + "e" * 64,
            ),
            "cleanup": ("cleanupResult", "cleanup-incomplete"),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(base)
                changed[field] = value
                changed_replay_digest = ci.verifier_replay_context_digest(changed)
                changed_envelope = ci.replay_authorization_envelope_digest(
                    current_full_context_set_digest=full_set_digest,
                    authorization_context_binding_digest_value=(
                        self.base_authorization_digest
                    ),
                    verifier_replay_context_digest_value=changed_replay_digest,
                )
                self.assertNotEqual(changed_replay_digest, base_replay_digest)
                self.assertNotEqual(changed_envelope, base_envelope)
                self.assertEqual(
                    self.full_context_digest(self.base_authorization_digest),
                    producer_full_digest,
                )
                self.assertEqual(
                    "REJECT" if changed_envelope != base_envelope else "PASS",
                    "REJECT",
                )

    def test_digest_dependency_graph_is_acyclic(self) -> None:
        graph = {
            "raw-observation": {"current-full-context"},
            "command-authority": {"current-full-context"},
            "producer-transcript": {"current-full-context"},
            "authorization-context": {"authorization-digest"},
            "authorization-digest": {
                "current-full-context",
                "replay-envelope",
            },
            "verifier-only-context": {"verifier-replay-digest"},
            "replay-transcript": {"verifier-replay-digest"},
            "runtime-live-results": {"verifier-replay-digest"},
            "verifier-replay-digest": {"replay-envelope"},
            "current-full-context": {"replay-envelope"},
            "replay-envelope": {"final-acceptance"},
            "final-acceptance": set(),
        }
        visited: set[str] = set()
        active: set[str] = set()

        def visit(node: str) -> None:
            self.assertNotIn(node, active, f"digest cycle reaches {node}")
            if node in visited:
                return
            active.add(node)
            for successor in graph[node]:
                visit(successor)
            active.remove(node)
            visited.add(node)

        for node in graph:
            visit(node)
        self.assertEqual(visited, set(graph))

        replay = self.verifier_binding()
        for forbidden in (
            "currentFullContextDigest",
            "authorizationContextBindingDigest",
            "verifierReplayContextDigest",
            "replayAuthorizationEnvelopeDigest",
        ):
            with self.subTest(forbidden=forbidden):
                candidate = {**replay, forbidden: "sha256:" + "0" * 64}
                with self.assertRaises(ValueError):
                    ci.verifier_replay_context_digest(candidate)
        source = inspect.getsource(ci.derive_canonical_failure_material)
        self.assertIn('"authorizationContextBindingDigest"', source)
        self.assertNotIn(
            "replayAuthorizationEnvelopeDigest",
            inspect.getsource(ci.replay_authorization_envelope_digest),
        )

    def test_claimed_binding_and_replay_forgery_matrix_is_rejected(self) -> None:
        runner, documents, comparison = sixth_review_replay_fixture()
        forged = copy.deepcopy(documents)
        forged_execution = copy.deepcopy(runner.execution_binding)
        forged_execution["trustFileDigest"] = "f" * 64
        forged_authorization = (
            ci.authorization_context_binding_from_execution_binding(
                forged_execution
            )
        )
        forged_authorization_digest = ci.authorization_context_binding_digest(
            forged_authorization
        )
        for document in (
            forged["summary.json"],
            forged["command-results.json"],
        ):
            document["executionBinding"] = copy.deepcopy(forged_execution)
            document["executionBindingDigest"] = ci.execution_binding_digest(
                forged_execution
            )
            document["authorizationContextBinding"] = copy.deepcopy(
                forged_authorization
            )
            document["authorizationContextBindingDigest"] = (
                forged_authorization_digest
            )
        original_current = forged["command-results.json"]["observations"][0][
            "currentFullContextDigest"
        ]
        coherently_rebind_claimed_transcript(forged)
        self.assertNotEqual(
            forged["command-results.json"]["observations"][0][
                "currentFullContextDigest"
            ],
            original_current,
        )
        replay_binding = self.verifier_binding()
        replay_digest = ci.verifier_replay_context_digest(replay_binding)
        for document in (
            forged["summary.json"],
            forged["command-results.json"],
        ):
            document["verifierReplayContextBinding"] = copy.deepcopy(
                replay_binding
            )
            document["verifierReplayContextDigest"] = replay_digest
            document["replayAuthorizationEnvelopeDigest"] = "0" * 64
        _transcript, errors = ci.compare_verification_replay_claims(
            forged, runner, comparison
        )
        self.assertTrue(
            any("replay fields cannot authorize" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("binding mismatch" in error or "context mismatch" in error for error in errors),
            errors,
        )
        self.assertTrue(
            ci.authorization_context_binding_errors(
                forged_authorization,
                forged_authorization_digest,
                expected_context=synthetic_external_context(
                    runner.execution_binding
                ),
            )
        )

    def test_three_skip_positive_matrix_across_root_categories(self) -> None:
        selected_roots = (
            self.windows_root_cases()[0],
            self.windows_root_cases()[1],
            self.windows_root_cases()[2],
            next(
                item
                for item in self.windows_root_cases()
                if item[0] == "非ASCII目录"
            ),
        )
        entry_ids = tuple(self.FROZEN_EXPECTED)
        selected_baseline = copy.deepcopy(self.baseline)
        selected_baseline["knownDebts"] = []
        selected_baseline["expectedOmissions"] = []
        for label, root, observed in selected_roots:
            with self.subTest(root=label):
                items = []
                for index, entry_id in enumerate(entry_ids):
                    entry = self.entries[entry_id]
                    raw = self.raw_for_root(
                        entry_id,
                        root,
                        observed,
                        observation_ordinal=index,
                    )
                    items.append(
                        ci.observation(
                            entry["commandClass"],
                            entry["testOrPathScope"],
                            entry["expectedOutcome"],
                            entry["allowedNormalizedSignature"][0],
                            "static-suite",
                            raw_observation=raw,
                        )
                    )
                _spec, record, observations = ci9_static_evidence_fixture(items)
                context = {
                    "producerObservationUniverseDigest": observations[0][
                        "producerObservationUniverseDigest"
                    ],
                    "producerTranscriptDigest": observations[0][
                        "producerTranscriptDigest"
                    ],
                    "profileCompletedCommandClassSetDigest": observations[0][
                        "profileCompletedCommandClassSetDigest"
                    ],
                    "authorizationContextBindingDigest": (
                        self.base_authorization_digest
                    ),
                }
                observations = [
                    ci._rederive_observation_record(
                        item, record, profile_context=context
                    )
                    for item in observations
                ]
                result = ci.compare_observations(
                    selected_baseline,
                    observations,
                    {"static-suite"},
                    "windows",
                    command_records=[record],
                    authorization_context_binding_digest_value=(
                        self.base_authorization_digest
                    ),
                )
                self.assertEqual(result["violations"], [])
                self.assertEqual(len(result["releaseOnlySkips"]), 3)
                for release in result["releaseOnlySkips"]:
                    self.assertEqual(release["occurrences"], 1)
                    self.assertEqual(release["gate"], "release-input-not-authorized")
                    self.assertRegex(
                        release["currentFullContextDigest"],
                        r"^sha256:[0-9a-f]{64}$",
                    )
                    self.assertEqual(
                        release["legacyBaselineComparisonDigest"],
                        self.FROZEN_EXPECTED[release["baselineId"]],
                    )

    def test_frozen_v1_negative_matrix_remains_closed(self) -> None:
        entry_id = "B-SKIP-PDF-RECONCILIATION"
        expected = self.FROZEN_EXPECTED[entry_id]
        base = self.raw_for_root(entry_id, "D:\\ci10\\repo")
        semantic_mutations: dict[str, dict] = {}

        changed_reason = copy.deepcopy(base)
        changed_reason["rawStructuredFields"]["detail"]["reason"] += "!"
        semantic_mutations["reason-changed"] = changed_reason

        unknown_detail = copy.deepcopy(base)
        unknown_detail["rawStructuredFields"]["detail"]["unknown"] = True
        semantic_mutations["unknown-detail-field"] = unknown_detail

        missing_detail = copy.deepcopy(base)
        missing_detail["rawStructuredFields"]["detail"].pop("monaCoverageOk")
        semantic_mutations["missing-detail-field"] = missing_detail

        extra_array = copy.deepcopy(base)
        extra_array["rawStructuredFields"]["detail"]["invalidStatusRows"] = [
            "unexpected"
        ]
        semantic_mutations["extra-array-member"] = extra_array

        wrong_command = copy.deepcopy(base)
        wrong_command["commandId"] = "static-suite-copy"
        semantic_mutations["wrong-command"] = wrong_command

        wrong_source = copy.deepcopy(base)
        wrong_source["sourcePath"] = "developer/tests/ci/other.py"
        semantic_mutations["wrong-source"] = wrong_source

        wrong_scope = copy.deepcopy(base)
        wrong_scope["rawStructuredFields"]["name"] += "!"
        semantic_mutations["wrong-scope"] = wrong_scope

        for label, candidate in semantic_mutations.items():
            with self.subTest(label=label):
                candidate["producerRecordDigest"] = ci._producer_record_digest(
                    {
                        key: value
                        for key, value in candidate.items()
                        if key != "producerRecordDigest"
                    }
                )
                try:
                    actual = ci.derive_frozen_v1_release_skip_signature(candidate)
                except (TypeError, ValueError):
                    continue
                self.assertNotEqual(actual, expected)

        for label, candidate in (
            ("unknown-raw-field", {**base, "unknown": True}),
            (
                "missing-raw-field",
                {key: value for key, value in base.items() if key != "sourcePath"},
            ),
        ):
            with self.subTest(label=label):
                self.assertTrue(
                    ci._validate_raw_observation(
                        candidate, label=label, source=None
                    )
                )

    def test_historical_traceability_and_future_receipts_are_documented(self) -> None:
        policy = (ci.REPO_ROOT / "docs/CI_POLICY.md").read_text(encoding="utf-8")
        self.assertIn(
            "HISTORICAL-TRACEABILITY:\n"
            "UNRESOLVED — EXACT OLD EXECUTION ARTIFACTS NOT AVAILABLE",
            policy,
        )
        self.assertIn(
            "CURRENT ROOT CAUSE:\n"
            "independently reproduced path-normalization nondeterminism",
            policy,
        )
        for receipt in (
            "sealed candidate aggregate",
            "generation stdout receipt",
            "command-results.json",
            "observed-debt.json",
            "summary.json",
            "summary.md",
            "invocation identity",
            "disposable-root shape",
        ):
            self.assertIn(receipt, policy)
        for architecture in (
            "AuthorizationContextBinding",
            "VerifierReplayContextBinding",
            "ReplayAuthorizationEnvelopeDigest",
            "currentFullContextDigest",
            "version-4",
        ):
            self.assertIn(architecture, policy)


class CI11AuthorityAndCanonicalSpecificationTest(unittest.TestCase):
    def test_ci11_real_ntfs_unicode_authority_fixture_matrix(self) -> None:
        pairs = (
            ("kelvin", "K", "\u212a"),
            ("long-s", "S", "\u017f"),
            ("i-dot", "I", "\u0130"),
            ("i-dotless", "I", "\u0131"),
            ("nfc-nfd", "\u00e9", "e\u0301"),
        )
        if os.name != "nt":
            for label, authorized, sibling in pairs:
                with self.subTest(label=label, platform="non-windows"):
                    self.assertFalse(
                        ci.windows_authority_component_equal(authorized, sibling)
                    )
            return

        task_temp = _explicit_security_task_temp()
        if os.environ.get("CI_SECURITY_EXPECT_GETTEMPDIR_DIFFERENT") == "1":
            self.assertNotEqual(
                task_temp,
                Path(tempfile.gettempdir()).resolve(strict=True),
            )
        usable: list[str] = []
        unavailable: list[str] = []
        repository_identities: set[str] = set()
        authorization_digests: set[str] = set()
        full_context_digests: set[str] = set()
        with make_task_owned_tempdir(task_temp, "n-") as fixture_root:
            self.assertTrue(fixture_root.is_relative_to(task_temp))
            for label, authorized, sibling in pairs:
                parent = fixture_root / label
                parent.mkdir()
                authorized_path = parent / authorized
                sibling_path = parent / sibling
                authorized_path.mkdir()
                try:
                    sibling_path.mkdir()
                except OSError as exc:
                    unavailable.append(f"{label}:{type(exc).__name__}")
                    continue
                usable.append(label)
                with self.subTest(label=label, platform="ntfs"):
                    authorized_identity = (
                        authorized_path.stat().st_dev,
                        authorized_path.stat().st_ino,
                    )
                    sibling_identity = (
                        sibling_path.stat().st_dev,
                        sibling_path.stat().st_ino,
                    )
                    self.assertNotEqual(authorized_identity, sibling_identity)
                    self.assertFalse(os.path.samefile(authorized_path, sibling_path))
                    self.assertEqual(
                        ci.normalize_authorized_path_text(
                            str(sibling_path / "identity.txt"),
                            repository_root=authorized_path,
                            task_roots=[],
                        ),
                        "<abs-path>",
                    )
                    self.assertEqual(
                        ci.normalize_authorized_path_text(
                            str(authorized_path / "identity.txt"),
                            repository_root=authorized_path,
                            task_roots=[],
                        ),
                        "<repo>/identity.txt",
                    )
                    self.assertEqual(
                        ci.normalize_authorized_path_text(
                            str(sibling_path / "identity.txt"),
                            repository_root=sibling_path,
                            task_roots=[],
                        ),
                        "<repo>/identity.txt",
                    )
                    authorized_repository = ci._local_repository_identity(
                        authorized_path
                    )
                    sibling_repository = ci._local_repository_identity(sibling_path)
                    authorized_binding_digest = (
                        ci.authorization_context_binding_digest(
                            _ci12_local_binding(authorized_repository)
                        )
                    )
                    sibling_binding_digest = ci.authorization_context_binding_digest(
                        _ci12_local_binding(sibling_repository)
                    )
                    self.assertNotEqual(authorized_repository, sibling_repository)
                    self.assertNotEqual(
                        authorized_binding_digest,
                        sibling_binding_digest,
                    )
                    repository_identities.update(
                        {authorized_repository, sibling_repository}
                    )
                    authorization_digests.update(
                        {authorized_binding_digest, sibling_binding_digest}
                    )
                    full_context_digests.update(
                        {
                            _ci12_full_context_digest(
                                authorized_repository, authorized_binding_digest
                            ),
                            _ci12_full_context_digest(
                                sibling_repository, sibling_binding_digest
                            ),
                        }
                    )
        self.assertEqual(len(usable), len(pairs), unavailable)
        self.assertEqual(len(repository_identities), len(usable) * 2)
        self.assertEqual(len(authorization_digests), len(usable) * 2)
        self.assertEqual(len(full_context_digests), len(usable) * 2)

    def test_ci11_ascii_authority_compatibility_matrix(self) -> None:
        cases = (
            ("C:\\Repo", "c:\\repo"),
            ("C:/Repo", "c:\\repo"),
            ("C:\\Repo\\Child", "c:/repo\\child"),
            ("D:\\ASCII-ROOT", "d:/ascii-root"),
        )
        for root, observed in cases:
            with self.subTest(root=root, observed=observed):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        observed + "\\artifact.json",
                        repository_root=root,
                        task_roots=[],
                    ),
                    "<repo>/artifact.json",
                )
        self.assertTrue(ci.windows_authority_component_equal("Repo-9", "rEPO-9"))
        self.assertEqual(
            ci.normalize_authorized_path_text(
                "C:\\é\\artifact.json",
                repository_root="C:\\é",
                task_roots=[],
            ),
            "<repo>/artifact.json",
        )

    def test_ci11_unicode_authority_collision_string_matrix(self) -> None:
        pairs = (
            ("K", "\u212a"),
            ("S", "\u017f"),
            ("I", "\u0130"),
            ("I", "\u0131"),
            ("\u00e9", "e\u0301"),
        )
        for authorized, sibling in pairs:
            with self.subTest(
                authorized=authorized.encode("unicode_escape"),
                sibling=sibling.encode("unicode_escape"),
            ):
                self.assertFalse(
                    ci.windows_authority_component_equal(authorized, sibling)
                )
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        f"C:\\{sibling}\\artifact.json",
                        repository_root=f"C:\\{authorized}",
                        task_roots=[],
                    ),
                    "<abs-path>",
                )
        self.assertTrue(ci.windows_authority_component_equal("\u212a", "\u212a"))
        self.assertTrue(ci.windows_authority_component_equal("\u00e9", "\u00e9"))

    def test_ci11_authority_matcher_source_forbids_unicode_folding(self) -> None:
        functions = (
            ci._ascii_authority_fold,
            ci._ascii_authority_text_equal,
            ci._ascii_authority_startswith,
            ci._ascii_lower_authority_text,
            ci.windows_authority_component_equal,
            ci._has_invalid_percent_escape,
            ci._has_encoded_separator,
            ci._file_uri_decoded_text,
            ci._strict_file_uri_reference,
            ci.classify_windows_absolute_reference,
            ci._windows_authority_path_form,
            ci._windows_authority_path_parts,
            ci.windows_authority_path_prefix,
            ci._normalization_root_record,
            ci._normalization_root_records,
            ci._replace_windows_authorized_root,
            ci.redact_windows_absolute_references,
            ci.normalize_authorized_path_text,
            ci._local_repository_identity_projection,
            ci._local_repository_identity,
        )
        source = "\n".join(inspect.getsource(function) for function in functions)
        tree = ast.parse(source)
        forbidden_calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"casefold", "lower", "normcase", "normalize"}:
                    forbidden_calls.append(node.func.attr)
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "IGNORECASE"
            ):
                forbidden_calls.append("IGNORECASE")
        self.assertEqual(forbidden_calls, [])
        for spelling in (
            "casefold(",
            ".lower(",
            "re.IGNORECASE",
            "ntpath.normcase",
            "unicodedata.normalize",
        ):
            self.assertNotIn(spelling, source)
        self.assertIn("windows_authority_path_prefix", source)
        self.assertIn("ord(character)", inspect.getsource(ci._ascii_authority_fold))

    def test_ci11_unknown_unc_and_device_redaction_matrix(self) -> None:
        unknown = (
            r"\\server\share\file",
            r"//server/share/file",
            r"\\?\UNC\server\share\file",
            r"\\?\C:\directory\file",
            r"\\.\C:\directory\file",
            r"\??\C:\directory\file",
        )
        for value in unknown:
            with self.subTest(value=value):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value, repository_root=r"C:\repo", task_roots=[]
                    ),
                    "<abs-path>",
                )
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        f"failure at {value}",
                        repository_root=r"C:\repo",
                        task_roots=[],
                    ),
                    "failure at <abs-path>",
                )
        prose = "server and share are ordinary words"
        self.assertEqual(
            ci.normalize_authorized_path_text(
                prose, repository_root=r"C:\repo", task_roots=[]
            ),
            prose,
        )
        credential_url = (
            "https://" + "user" + ":" + ("v" * 20) + "@server/share"
        )
        self.assertEqual(ci.sanitize_text(credential_url), "[REDACTED]")

    def test_ci11_authorized_unc_root_matrix(self) -> None:
        root = r"\\server\share\repo"
        positives = (
            (r"\\server\share\repo", "<repo>"),
            (r"//SERVER/share/REPO", "<repo>"),
            (r"\\server\share\repo\nested\file", "<repo>/nested/file"),
        )
        for value, expected in positives:
            with self.subTest(value=value):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value, repository_root=root, task_roots=[]
                    ),
                    expected,
                )
        negatives = (
            r"\\server\share\repo2\file",
            r"\\other\share\repo\file",
            r"\\server\other\repo\file",
            "\\\\server\\share\\\u212a\\file",
        )
        unicode_root = r"\\server\share\K"
        for index, value in enumerate(negatives):
            with self.subTest(value=value):
                selected_root = unicode_root if index == 3 else root
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value, repository_root=selected_root, task_roots=[]
                    ),
                    "<abs-path>",
                )
        extended_root = r"\\?\UNC\server\share\repo"
        self.assertEqual(
            ci.normalize_authorized_path_text(
                r"\\?\unc\SERVER\share\REPO\file",
                repository_root=extended_root,
                task_roots=[],
            ),
            "<repo>/file",
        )
        credential_url = (
            "https://" + "user" + ":" + ("v" * 20) + "@server/share/repo"
        )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                credential_url, repository_root=root, task_roots=[]
            ),
            credential_url,
        )

    def test_ci12_local_repository_identity_ascii_compatibility(self) -> None:
        if os.name != "nt":
            with make_task_owned_tempdir(_explicit_security_task_temp(), "i-") as root:
                candidate = root / "CaseSensitive"
                candidate.mkdir()
                sibling = root / "casesensitive"
                sibling.mkdir()
                self.assertNotEqual(
                    ci._local_repository_identity(candidate),
                    ci._local_repository_identity(sibling),
                )
            return

        with make_task_owned_tempdir(_explicit_security_task_temp(), "i-") as root:
            ascii_root = root / "ASCII-Root"
            ascii_root.mkdir()
            variants = [
                str(ascii_root),
                str(ascii_root).replace("\\", "/"),
                str(ascii_root).swapcase(),
            ]
            identities = {ci._local_repository_identity(Path(value)) for value in variants}
            self.assertEqual(len(identities), 1)
            identity = next(iter(identities))
            self.assertRegex(identity, r"^local-root-sha256:[0-9a-f]{64}$")

            non_ascii = root / "\u00e9"
            non_ascii.mkdir()
            self.assertEqual(
                ci._local_repository_identity(non_ascii),
                ci._local_repository_identity(Path(str(non_ascii))),
            )

    def test_ci12_closed_windows_namespace_classifier_matrix(self) -> None:
        cases = (
            (r"C:\directory\file", "drive"),
            ("C:/directory/file", "drive"),
            (r"\\server\share\file", "unc"),
            ("//server/share/file", "unc"),
            (r"\\?\UNC\server\share\file", "extended-unc"),
            (r"\\?\C:\directory\file", "extended-drive"),
            (r"\\.\C:\directory\file", "device-drive"),
            (r"\\.\PhysicalDrive0", "win32-device-path"),
            (r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\directory\file", "globalroot"),
            (r"\\?\Volume{GUID}\directory\file", "volume-guid"),
            (r"\Device\HarddiskVolume1\directory\file", "nt-device-path"),
            (r"\??\C:\directory\file", "nt-dos-device-path"),
            (r"\??\UNC\server\share\directory\file", "nt-unc-path"),
            ("file:///C:/directory/file", "file-drive-uri"),
            ("file://server/share/directory/file", "file-unc-uri"),
            ("file:////server/share/directory/file", "file-unc-uri"),
            ("file://server/share/%GG", "unsupported-absolute-windows-namespace"),
            ("repo server/share file:", None),
        )
        for value, expected_form in cases:
            with self.subTest(value=value):
                self.assertEqual(ci._windows_authority_path_form(value), expected_form)

        leak_cases = (
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\directory\file",
            r"\\?\Volume{GUID}\directory\file",
            r"\Device\HarddiskVolume1\directory\file",
            r"\??\UNC\server\share\directory\file",
            "file://server/share/directory/file",
            "file:////server/share/directory/file",
        )
        for value in leak_cases:
            with self.subTest(leak=value):
                sanitized = ci.normalize_authorized_path_text(
                    value,
                    repository_root=r"C:\repo",
                    task_roots=[],
                )
                self.assertEqual(sanitized, "<abs-path>")
                for leaked in ("server", "share", "Device", "PhysicalDrive", "directory"):
                    self.assertNotIn(leaked, sanitized)

    def test_ci12_file_uri_authorization_and_fail_closed_matrix(self) -> None:
        positives = (
            ("file:///C:/repo/child/file.txt", r"C:\repo", "<repo>/child/file.txt"),
            ("file://server/share/repo/child/file.txt", r"\\server\share\repo", "<repo>/child/file.txt"),
            ("file:////server/share/repo/child/file.txt", r"\\server\share\repo", "<repo>/child/file.txt"),
        )
        for value, root, expected in positives:
            with self.subTest(value=value):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value,
                        repository_root=root,
                        task_roots=[],
                    ),
                    expected,
                )

        negatives = (
            ("file:///C:/repo2/child/file.txt", r"C:\repo"),
            ("file://other/share/repo/child/file.txt", r"\\server\share\repo"),
            ("file://server/other/repo/child/file.txt", r"\\server\share\repo"),
            ("file://server/share/%GG", r"\\server\share"),
            ("file://server/share/%00", r"\\server\share"),
            ("file://server/share/%2Fambiguous", r"\\server\share"),
            ("file://server/share/path?query=1", r"\\server\share"),
            ("file://server/share/path#fragment", r"\\server\share"),
            ("file://user:secret@server/share/path", r"\\server\share"),
            ("file:///C:/\u212a/file.txt", r"C:\K"),
        )
        for value, root in negatives:
            with self.subTest(value=value):
                self.assertEqual(
                    ci.normalize_authorized_path_text(
                        value,
                        repository_root=root,
                        task_roots=[],
                    ),
                    "<abs-path>",
                )

    def test_ci12_embedded_path_prose_and_credential_safety_matrix(self) -> None:
        prose = "ordinary file: repo and server/share text"
        self.assertEqual(
            ci.normalize_authorized_path_text(
                prose,
                repository_root=r"C:\repo",
                task_roots=[],
            ),
            prose,
        )
        embedded = (
            r"failure at \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\directory\file"
        )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                embedded,
                repository_root=r"C:\repo",
                task_roots=[],
            ),
            "failure at <abs-path>",
        )
        credential_url = "https://user:" + ("v" * 20) + "@server/share/path"
        self.assertEqual(ci.sanitize_text(credential_url), "[REDACTED]")
        noisy = (
            "\x1b]0;title\x07"
            + r"trace \\?\Volume{GUID}\directory\file"
            + "\u202e"
        )
        sanitized = ci.sanitize_text(noisy)
        self.assertEqual(sanitized, "trace <abs-path>")
        for leaked in ("Volume", "GUID", "directory", "\u202e", "\x1b"):
            self.assertNotIn(leaked, sanitized)

    def _run_ci11_ntfs_fixture_subprocess(
        self,
        *,
        temp_value: Path,
        tmp_value: Path,
        tmpdir_value: Path,
        expect_gettempdir_different: bool,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "TEMP": str(temp_value),
                "TMP": str(tmp_value),
                "TMPDIR": str(tmpdir_value),
                "CI_SECURITY_TASK_TEMP": str(temp_value),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
            }
        )
        if expect_gettempdir_different:
            env["CI_SECURITY_EXPECT_GETTEMPDIR_DIFFERENT"] = "1"
        else:
            env.pop("CI_SECURITY_EXPECT_GETTEMPDIR_DIFFERENT", None)
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "CI11AuthorityAndCanonicalSpecificationTest.test_ci11_real_ntfs_unicode_authority_fixture_matrix",
            ],
            cwd=ci.REPO_ROOT,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=120,
        )

    def test_ci12_distinct_temp_subprocess_uses_explicit_task_temp(self) -> None:
        with make_task_owned_tempdir(_explicit_security_task_temp(), "ta-") as root:
            temp_a = root / "a"
            temp_b = root / "b"
            temp_c = root / "c"
            for path in (temp_a, temp_b, temp_c):
                path.mkdir()
            result = self._run_ci11_ntfs_fixture_subprocess(
                temp_value=temp_a,
                tmp_value=temp_b,
                tmpdir_value=temp_c,
                expect_gettempdir_different=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            for path in (temp_a, temp_b, temp_c):
                self.assertEqual(list(path.iterdir()), [])

    def test_ci12_coalesced_temp_subprocess_uses_explicit_task_temp(self) -> None:
        with make_task_owned_tempdir(_explicit_security_task_temp(), "tb-") as root:
            temp_all = root / "all"
            temp_all.mkdir()
            result = self._run_ci11_ntfs_fixture_subprocess(
                temp_value=temp_all,
                tmp_value=temp_all,
                tmpdir_value=temp_all,
                expect_gettempdir_different=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(list(temp_all.iterdir()), [])

    def test_ci12_explicit_task_temp_overrides_gettempdir_cache(self) -> None:
        with make_task_owned_tempdir(_explicit_security_task_temp(), "tc-") as root:
            explicit_parent = root / "explicit"
            cached_parent = root / "cached"
            explicit_parent.mkdir()
            cached_parent.mkdir()
            original_tempdir = tempfile.tempdir
            tempfile.tempdir = str(cached_parent)
            try:
                self.assertEqual(
                    Path(tempfile.gettempdir()).resolve(strict=True),
                    cached_parent.resolve(strict=True),
                )
                with make_task_owned_tempdir(explicit_parent, "td-") as fixture:
                    self.assertTrue(fixture.is_relative_to(explicit_parent))
                    self.assertFalse(fixture.is_relative_to(cached_parent))
            finally:
                tempfile.tempdir = original_tempdir

    def test_ci12_fixture_git_longpath_boundary_matrix(self) -> None:
        if os.name != "nt":
            return
        git = standalone_packaging._trusted_git_command()
        lengths = (220, 248, 259, 260, 264, 280)
        with make_task_owned_tempdir(_explicit_security_task_temp(), "lg-") as root:
            for target_length in lengths:
                with self.subTest(target_length=target_length):
                    repo = root / f"r{target_length}"
                    repo.mkdir()
                    standalone_packaging.run_fixture_git(git, "init", "-q", cwd=repo)
                    base = repo / "src" / "styles"
                    filename = "local.css"
                    padding_length = target_length - len(str(base)) - 2 - len(filename)
                    self.assertGreaterEqual(padding_length, 8)
                    target = base / ("p" * padding_length) / filename
                    target.parent.mkdir(parents=True)
                    target.write_text(
                        standalone_packaging.SAFE_SENTINEL,
                        encoding="utf-8",
                        newline="\n",
                    )
                    self.assertEqual(len(str(target)), target_length)
                    relative = target.relative_to(repo)
                    result = standalone_packaging.run_fixture_git(
                        git,
                        "add",
                        "--",
                        relative,
                        cwd=repo,
                        check=False,
                    )
                    self.assertIn("core.longpaths=true", result.args)
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stderr.decode("utf-8", errors="replace"),
                    )

            negative_repo = root / "neg"
            negative_repo.mkdir()
            standalone_packaging.run_fixture_git(git, "init", "-q", cwd=negative_repo)
            base = negative_repo / "src" / "styles"
            filename = "local.css"
            padding_length = 264 - len(str(base)) - 2 - len(filename)
            self.assertGreaterEqual(padding_length, 8)
            target = base / ("q" * padding_length) / filename
            target.parent.mkdir(parents=True)
            target.write_text(
                standalone_packaging.SAFE_SENTINEL,
                encoding="utf-8",
                newline="\n",
            )
            isolated_env = os.environ.copy()
            isolated_env["GIT_CONFIG_NOSYSTEM"] = "1"
            isolated_env["GIT_CONFIG_GLOBAL"] = "NUL"
            disabled = subprocess.run(
                [
                    str(git),
                    "-c",
                    "core.longpaths=false",
                    "add",
                    "--",
                    str(target.relative_to(negative_repo)),
                ],
                cwd=negative_repo,
                env=isolated_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(disabled.returncode, 128)
            self.assertIn(
                "Filename too long",
                disabled.stderr.decode("utf-8", errors="replace"),
            )

    def test_ci11_normative_grammar_constants_match_source(self) -> None:
        specification = ci11_policy_json_block(
            "CI_CANONICAL_FRAMING_CONSTANTS_V1"
        )
        self.assertEqual(specification["specificationVersion"], 1)
        self.assertEqual(
            specification["typeTags"],
            {key: value.hex() for key, value in CI11_REFERENCE_TAGS.items()},
        )
        self.assertEqual(
            specification["typeTags"],
            {key: value.hex() for key, value in ci.CANONICAL_FRAME_TAGS.items()},
        )
        self.assertEqual(
            specification["textEncoding"], ci.CANONICAL_FRAME_TEXT_ENCODING
        )
        self.assertEqual(
            specification["unicodeNormalization"],
            ci.CANONICAL_FRAME_UNICODE_NORMALIZATION,
        )
        self.assertEqual(
            specification["lengthWidthBytes"],
            ci.CANONICAL_FRAME_LENGTH_WIDTH_BYTES,
        )
        self.assertEqual(
            specification["countWidthBytes"],
            ci.CANONICAL_FRAME_COUNT_WIDTH_BYTES,
        )
        self.assertEqual(
            specification["byteOrder"], ci.CANONICAL_FRAME_BYTE_ORDER
        )
        self.assertEqual(
            specification["mapKeyOrdering"], ci.CANONICAL_FRAME_MAP_KEY_ORDER
        )
        self.assertEqual(
            specification["arrayOrdering"], ci.CANONICAL_FRAME_ARRAY_ORDER
        )
        self.assertEqual(
            specification["domains"],
            {
                "AuthorizationContextBindingDigest": (
                    ci.AUTHORIZATION_CONTEXT_BINDING_DIGEST_DOMAIN
                ),
                "VerifierReplayContextDigest": (
                    ci.VERIFIER_REPLAY_CONTEXT_BINDING_DIGEST_DOMAIN
                ),
                "ReplayAuthorizationEnvelopeDigest": (
                    ci.REPLAY_AUTHORIZATION_ENVELOPE_DIGEST_DOMAIN
                ),
            },
        )
        self.assertEqual(
            specification["schemaVersions"],
            {
                "AuthorizationContextBinding": (
                    ci.AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION
                ),
                "VerifierReplayContextBinding": (
                    ci.VERIFIER_REPLAY_CONTEXT_BINDING_SCHEMA_VERSION
                ),
                "ReplayAuthorizationEnvelope": (
                    ci.REPLAY_AUTHORIZATION_ENVELOPE_SCHEMA_VERSION
                ),
            },
        )

    def test_ci11_three_normative_vectors_match_reference_and_production(self) -> None:
        vectors = tuple(
            ci11_policy_json_block(f"CI_CANONICAL_VECTOR_{letter}_V1")
            for letter in ("A", "B", "C")
        )
        for vector in vectors:
            documented_preimage = bytes.fromhex(vector["canonicalPreimageHex"])
            self.assertEqual(
                len(documented_preimage), vector["canonicalPreimageByteLength"]
            )
            self.assertEqual(
                hashlib.sha256(documented_preimage).hexdigest(), vector["sha256"]
            )
            if vector["vector"] == "A":
                reference_preimage = ci11_reference_authorization_preimage(
                    vector["structuredInput"]
                )
                production_digest = ci.authorization_context_binding_digest(
                    vector["structuredInput"]
                )
            elif vector["vector"] == "B":
                reference_preimage = ci11_reference_verifier_preimage(
                    vector["structuredInput"]
                )
                production_digest = ci.verifier_replay_context_digest(
                    vector["structuredInput"]
                )
            else:
                reference_preimage = ci11_reference_envelope_preimage(
                    vector["structuredInput"]
                )
                envelope = vector["structuredInput"]
                production_digest = ci.replay_authorization_envelope_digest(
                    current_full_context_set_digest=envelope[
                        "currentFullContextDigestSetDigest"
                    ],
                    authorization_context_binding_digest_value=envelope[
                        "authorizationContextBindingDigest"
                    ],
                    verifier_replay_context_digest_value=envelope[
                        "verifierReplayContextDigest"
                    ],
                )
            production_preimage = ci._canonical_frame(
                vector["canonicalNormalizedProjection"]
            )
            with self.subTest(vector=vector["vector"]):
                self.assertEqual(reference_preimage, documented_preimage)
                self.assertEqual(production_preimage, documented_preimage)
                self.assertEqual(reference_preimage, production_preimage)
                self.assertEqual(production_digest, vector["sha256"])
                self.assertEqual(
                    vector["expectedTextualDigest"], vector["sha256"]
                )

    def test_ci11_negative_framing_vector_matrix(self) -> None:
        vector = ci11_policy_json_block("CI_CANONICAL_VECTOR_A_V1")
        canonical = bytes.fromhex(vector["canonicalPreimageHex"])
        canonical_digest = hashlib.sha256(canonical).hexdigest()
        candidates: dict[str, bytes] = {
            "wrong-type-tag": b"x" + canonical[1:],
            "little-endian-length": canonical[:1]
            + canonical[1:9][::-1]
            + canonical[9:],
            "four-byte-length": canonical[:1]
            + (len(canonical) - 9).to_bytes(4, "big")
            + canonical[9:],
        }
        wrong_domain = copy.deepcopy(vector["canonicalNormalizedProjection"])
        wrong_domain["digestDomain"] += "-wrong"
        candidates["wrong-domain"] = ci11_reference_frame(wrong_domain)
        candidates["insertion-order-map"] = ci11_insertion_order_frame(
            vector["canonicalNormalizedProjection"]
        )
        candidates["locale-sorted-map"] = ci11_insertion_order_frame(
            {"a": 2, "Z": 1}
        )
        canonical_locale_probe = ci11_reference_frame({"Z": 1, "a": 2})
        self.assertNotEqual(candidates["locale-sorted-map"], canonical_locale_probe)
        decomposed = "e\u0301".encode("utf-8")
        candidates["non-nfc-text"] = (
            b"s" + len(decomposed).to_bytes(8, "big") + decomposed
        )
        self.assertNotEqual(
            candidates["non-nfc-text"], ci11_reference_frame("\u00e9")
        )
        for label, candidate in candidates.items():
            with self.subTest(label=label):
                self.assertNotEqual(candidate, canonical)
                self.assertNotEqual(
                    hashlib.sha256(candidate).hexdigest(), canonical_digest
                )
        self.assertNotEqual(
            ci11_reference_frame({"value": None}),
            ci11_reference_frame({}),
        )
        self.assertNotEqual(ci11_reference_frame(True), ci11_reference_frame(1))

    def test_ci11_reference_schema_rejects_absent_null_duplicate_and_unknown(self) -> None:
        vector = ci11_policy_json_block("CI_CANONICAL_VECTOR_A_V1")
        binding = vector["structuredInput"]
        missing = copy.deepcopy(binding)
        missing.pop("runId")
        null_value = copy.deepcopy(binding)
        null_value["runId"] = None
        unknown = {**binding, "unknown": "field"}
        for label, candidate in (
            ("absent", missing),
            ("null", null_value),
            ("unknown", unknown),
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    ci11_reference_authorization_preimage(candidate)
                with self.assertRaises(ValueError):
                    ci.authorization_context_binding_digest(candidate)
        duplicate_normalized_key = {"\u00e9": 1, "e\u0301": 2}
        with self.assertRaises(ValueError):
            ci11_reference_frame(duplicate_normalized_key)
        with self.assertRaises(ValueError):
            ci._canonical_frame(duplicate_normalized_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
