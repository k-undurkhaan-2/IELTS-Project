#!/usr/bin/env python3
"""Focused regression tests for the baseline-aware CI policy runner."""

from __future__ import annotations

import collections
import copy
import contextlib
import ast
import hashlib
import io
import inspect
import itertools
import json
import math
import os
import re
import shutil
import subprocess
import stat
import struct
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


def _process_is_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return int(kernel32.WaitForSingleObject(handle, 0)) == 258
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _candidate_worktree_roots() -> tuple[Path, ...]:
    try:
        git_candidates = [Path(_explicit_local_test_tool_map("git")["git"])]
    except AssertionError:
        git_candidates = []

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


def _explicit_local_test_tool_map(*roles: str) -> dict[str, str]:
    """Bind local fixtures through the same fail-closed production resolver."""

    _policy, tools = _resolved_local_test_authority(*roles)
    return tools


def _explicit_local_test_environment() -> dict[str, str]:
    """Return a local fixture source isolated from ambient hosted-job claims."""

    source = dict(os.environ)
    source["GITHUB_ACTIONS"] = "false"
    for name in (
        "GITHUB_JOB",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "RUNNER_OS",
        "RUNNER_ENVIRONMENT",
    ):
        source.pop(name, None)
    return source


def _resolved_local_test_authority(
    *roles: str,
) -> tuple[ci.ToolAuthorityPolicy, dict[str, str]]:
    """Use the production resolver for every executable self-test authority."""

    requested = set(roles)
    source = _explicit_local_test_environment()
    try:
        policy = ci.default_tool_authority_policy(source, repo_root=ci.REPO_ROOT)
        tools, errors = ci.resolve_trusted_tools(
            requested,
            source_environment=source,
            repo_root=ci.REPO_ROOT,
            policy=policy,
        )
        authoritative = ci.require_tool_set(
            tools,
            requested,
            phase="SELF_TEST_CAPTURE",
            resolution_errors=errors,
        )
    except (OSError, ValueError, ci.ToolAuthorityUnavailable) as exc:
        raise AssertionError(
            f"TEST-TOOL-AUTHORITY-UNAVAILABLE: {type(exc).__name__}: {exc}"
        ) from exc
    return policy, authoritative


def _explicit_live_local_external_authority() -> ci.ExecutionExternalAuthority:
    return ci.ExecutionExternalAuthority(
        source_kind="live",
        binding_mode="local",
        runner_os=ci._canonical_runner_os(),
        job_id="",
        run_id="local",
        run_attempt="1",
        event_name="local",
        repository="",
        checkout_sha="",
    )


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
        "releaseGateRequired": False,
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
        "releaseGateRequired",
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
    *,
    schema_version: int = 1,
    boolean_fields: frozenset[str] = frozenset(),
) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("reference schema field set is not exact")
    if (
        type(value.get(version_field)) is not int
        or value[version_field] != schema_version
    ):
        raise ValueError("reference schema version is invalid")
    if value.get("bindingKind") != kind:
        raise ValueError("reference schema kind is invalid")
    for field_name, field_value in value.items():
        if field_name in boolean_fields:
            if type(field_value) is not bool:
                raise ValueError(f"reference schema {field_name} is not boolean")
        elif field_name != version_field and not isinstance(field_value, str):
            raise ValueError(f"reference schema {field_name} is not text")
    return copy.deepcopy(value)


def ci11_reference_authorization_preimage(binding: object) -> bytes:
    value = _ci11_reference_schema(
        binding,
        CI11_AUTHORIZATION_FIELDS,
        "bindingSchemaVersion",
        "AuthorizationContextBinding",
        schema_version=2,
        boolean_fields=frozenset({"releaseGateRequired"}),
    )
    return ci11_reference_frame(
        {
            "digestDomain": "ieltmps-authorization-context-binding-v2",
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


def frozen_release_skip_path_binding(entry: dict) -> dict | None:
    target = ci.RELEASE_ONLY_SKIP_FAILURE_TARGETS.get(entry["testOrPathScope"])
    if target is None:
        return None
    return {
        "schemaVersion": 1,
        "canonicalizationKind": "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1",
        "authorizedTargetPaths": [target],
        "authorizedToolRoles": [],
        "unmappedAbsolutePathDigests": [],
        "literalPlaceholderDigests": [],
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
        failure_path_authority=frozen_release_skip_path_binding(entry),
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
        failure_path_authority=frozen_release_skip_path_binding(entry),
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
    release_gate_required: bool | None = None,
) -> dict:
    if release_gate_required is None:
        release_gate_required = ci.resolve_release_gate_required(profile)
    return {
        "bindingSchemaVersion": ci.EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
        "bindingKind": "ProducerExecutionBinding",
        "bindingMode": "local",
        "producerJobId": "local-producer",
        "producerRunnerOS": "Windows" if platform_name == "windows" else "Linux",
        "producerProfile": profile,
        "releaseGateRequired": release_gate_required,
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
        release_gate_required=binding["releaseGateRequired"],
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
    executable = Path(sys.executable).resolve(strict=True)
    executable_record = {
        "role": "synthetic-test-runtime",
        "canonicalPath": str(executable),
        "size": executable.stat().st_size,
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "stableIdentity": ci._stable_file_identity(executable.stat()),
        "leaseHeld": True,
    }
    lockfiles = [
        {
            "relativePath": relative,
            "mode": "100644",
            "size": 1,
            "sha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
        }
        for relative in ("developer/package-lock.json", "backend/package-lock.json")
    ]
    dependency_semantic = {
        "lockfiles": lockfiles,
        "dependencyRoots": [],
        "vitest": None,
        "nodePath": [],
    }
    dependency_digest = hashlib.sha256(
        ci._canonical_frame(dependency_semantic)
    ).hexdigest()
    runtime_closure_document = {
        "closureSchemaVersion": ci.RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
        "measurementStatus": "measured-complete",
        "profile": "policy",
        "runnerOS": ci._canonical_runner_os(),
        "pythonExecutable": copy.deepcopy(executable_record),
        "nodeExecutable": copy.deepcopy(executable_record),
        "npmEntrypoint": {**copy.deepcopy(executable_record), "available": True},
        "gitExecutable": None,
        "lockfiles": lockfiles,
        "dependencyRoots": [],
        "vitest": None,
        "nodePath": [],
        "dependencyClosureDigest": dependency_digest,
        "dependencyMemberCount": 0,
    }
    runtime_digest = hashlib.sha256(
        ci._canonical_frame(runtime_closure_document)
    ).hexdigest()
    runtime_closure_document["closureDigest"] = runtime_digest
    runner = SimpleNamespace(
        profile="policy",
        release_gate_required=False,
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
            "runtimeClosureDigest": runtime_digest,
            "dependencyClosureDigest": dependency_digest,
            "dependencyMemberCount": "0",
        },
        command_results=[],
        observations=[],
        completed_classes=set(),
        command_plan=command_plan,
        command_plan_digest=ci.command_plan_digest(command_plan),
        runtime_closure_document=runtime_closure_document,
        runtime_closure_errors=[],
        runtime_closure_guard_evidence={
            "guardSchemaVersion": ci.RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
            "watcherBackend": "synthetic-test-fixture",
            "active": True,
            "activeDuringReplay": True,
            "mutationState": "clean",
            "queueOverflow": False,
            "mutationEventCount": 0,
        },
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
        release_gate_required=False,
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


def p52_compact_replay_fixture() -> tuple[SimpleNamespace, dict, dict]:
    target_a = ci._target_authority(ci.REPO_ROOT, ci.STATIC_SUITE_RELATIVE_PATH)
    target_b = ci._target_authority(ci.REPO_ROOT, ".github/workflows/ci.yml")
    target_c = ci._target_authority(
        ci.REPO_ROOT,
        "developer/tests/ci/phase1-ci-baseline.json",
    )
    specs = [
        synthetic_command_spec(
            "p52-compact-alpha",
            "p52-compact-class-alpha",
            0,
            targets=[target_a, target_b],
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        ),
        synthetic_command_spec(
            "p52-compact-beta",
            "p52-compact-class-beta",
            1,
            targets=[target_b, target_c],
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        ),
    ]
    records = [synthetic_record_from_spec(spec) for spec in specs]
    runner = SimpleNamespace(
        profile="static",
        release_gate_required=False,
        platform=ci.platform_key(),
        command_plan=specs,
        command_results=records,
        observations=[],
        completed_classes=set(),
        hard_gate_results=[],
        violations=[],
    )
    runner.execution_binding = synthetic_execution_binding(
        runner.profile,
        ci.command_plan_digest(specs),
        platform_name=runner.platform,
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
        "records": [
            ci._compact_command_record_for_evidence(record)
            for record in runner.command_results
        ],
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
        "profile": runner.profile,
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
    return (
        runner,
        {"summary.json": summary, "command-results.json": commands},
        comparison,
    )


def p52_execution_input_from_target(target: Mapping[str, object]) -> dict:
    return {
        "logicalPath": target["path"],
        "canonicalSourcePath": target["canonicalSourcePath"],
        "plannedByteLength": target["size"],
        "plannedSha256": target["sha256"],
        "plannedStableIdentity": target["fileIdentity"],
        "actualByteLength": target["size"],
        "actualSha256": target["sha256"],
        "inputMode": "PROTECTED-TARGET-BUNDLE",
    }


def coherently_refresh_p52_compact_record(record: dict) -> None:
    inputs = [
        p52_execution_input_from_target(target) for target in record["targets"]
    ]
    record["executionInputs"] = []
    record["executionInputBundleDigest"] = ci.execution_input_bundle_digest(inputs)
    bundle = record["protectedTargetBundle"]
    bundle["executionInputBundleDigest"] = record["executionInputBundleDigest"]
    bundle["preExecutionIdentities"] = (
        ci._protected_bundle_compact_identity_digests(record, phase="pre")
    )
    bundle["postExecutionIdentities"] = (
        ci._protected_bundle_compact_identity_digests(record, phase="post")
    )


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


def r03_static_failure_detail(
    logical_target: str,
    physical_root: str,
    executable: str,
) -> str:
    separator = "\\" if re.match(r"^[A-Za-z]:", physical_root) else "/"
    physical_target = physical_root.rstrip("/\\") + separator + logical_target.replace(
        "/",
        separator,
    )

    def failed_command(arguments: list[str], exit_code: int) -> str:
        return (
            f"Command '{arguments!r}' returned non-zero exit status {exit_code}."
        )

    if logical_target.endswith(
        (
            "simulation_nb_drag_regression.py",
            "simulation_roundtrip_restore_regression.py",
            "unified_submit_readonly_regression.py",
        )
    ):
        return (
            '执行失败: {"status": "fail", "detail": "playwright_python_missing"}\n'
            + failed_command([executable, physical_target], 1)
        )
    if logical_target.endswith("reading_question_audit.py"):
        return (
            "执行失败: Playwright Python 未安装且无法切换到 .venv，审计无法执行。\n"
            + failed_command(
                [executable, physical_target, "--mode", "quick"],
                2,
            )
        )
    if logical_target.endswith("practiceCustomCard.test.js"):
        payload = {
            "status": "fail",
            "detail": "背面组件选择区应使用单列 grid，避免横向挤压",
            "checks": [{"name": "自定义卡片 DOM 结构守卫", "detail": {}}],
        }
    elif logical_target.endswith("onDemandEntrypoints.test.js"):
        payload = {
            "status": "fail",
            "detail": "document.querySelectorAll is not a function",
            "results": [
                {
                    "name": "on-demand 入口测试执行失败",
                    "passed": False,
                    "detail": {"error": "document.querySelectorAll is not a function"},
                    "timestamp": "2026-08-12T11:05:12.899Z",
                }
            ],
        }
    else:  # pragma: no cover - closed fixture inventory
        raise AssertionError(logical_target)
    return (
        "执行失败: "
        + json.dumps(payload, ensure_ascii=False, indent=2)
        + "\n"
        + failed_command(["node", physical_target], 1)
    )


def r03_node_failure_output(logical_target: str, physical_root: str) -> str:
    root = physical_root.rstrip("/\\").replace("\\", "/")
    physical_uri = "file:///" + root.lstrip("/") + "/" + logical_target
    if logical_target.endswith("adminFrontendGuard.test.js"):
        return f"""backend/admin/admin.js:83
        exportButtons: Array.from(document.querySelectorAll('[data-export-dataset]')),
                                           ^

TypeError: document.querySelectorAll is not a function
    at backend/admin/admin.js:83:44
    at backend/admin/admin.js:874:3
    at Script.runInContext (node:vm:149:12)
    at Object.runInContext (node:vm:301:6)
    at {physical_uri}:113:4
    at ModuleJob.run (node:internal/modules/esm/module_job:430:25)

Node.js v24.14.0
✖ developer\\tests\\js\\adminFrontendGuard.test.js (258.6937ms)
ℹ tests 1
ℹ suites 0
ℹ pass 0
ℹ fail 1
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 273.5459

✖ failing tests:

test at developer\\tests\\js\\adminFrontendGuard.test.js:1:1
✖ developer\\tests\\js\\adminFrontendGuard.test.js (258.6937ms)
  'test failed'
"""
    if logical_target.endswith("localDataRenderingGuard.test.js"):
        message = (
            "vocab store must cap stored list size, normalize long imported word "
            "fields, and return defensive clones"
        )
        return f"""node:internal/modules/run_main:107
    triggerUncaughtException(
    ^

AssertionError [ERR_ASSERTION]: {message}
    at {physical_uri}:566:1
    at ModuleJob.run (node:internal/modules/esm/module_job:430:25)
    at async onImport.tracePromise.__proto__ (node:internal/modules/esm/loader:661:26)
    at async asyncRunEntryPointWithESMLoader (node:internal/modules/run_main:101:5) {{
  generatedMessage: false,
  code: 'ERR_ASSERTION',
  actual: false,
  expected: true,
  operator: '==',
  diff: 'simple'
}}

Node.js v24.14.0
✖ developer\\tests\\js\\localDataRenderingGuard.test.js (151.5622ms)
ℹ tests 1
ℹ suites 0
ℹ pass 0
ℹ fail 1
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 159.7374

✖ failing tests:

test at developer\\tests\\js\\localDataRenderingGuard.test.js:1:1
✖ developer\\tests\\js\\localDataRenderingGuard.test.js (151.5622ms)
  'test failed'
"""
    raise AssertionError(logical_target)  # pragma: no cover - closed fixture inventory


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
        entry_ids = {
            "B-STATIC-PY-PLAYWRIGHT-READING-QUICK-AUDIT",
            "B-STATIC-PY-PLAYWRIGHT-NB-DRAG",
            "B-STATIC-PY-PLAYWRIGHT-ROUNDTRIP",
            "B-STATIC-PY-PLAYWRIGHT-UNIFIED-SUBMIT",
            "B-STATIC-PRACTICE-CUSTOM-CARD-LAYOUT",
            "B-STATIC-ON-DEMAND-HARNESS-DOM-STUB",
            "E-ADMIN-FRONTEND-DOM-STUB",
            "E-WINDOWS-LOCAL-DATA-CRLF-ASSERTION",
        }
        entries = {
            entry["id"]: entry
            for entry in self.full_baseline["knownDebts"]
            if entry["id"] in entry_ids
        }
        self.assertEqual(set(entries), entry_ids)

        def baseline_for(entry: Mapping) -> dict:
            baseline = copy.deepcopy(self.full_baseline)
            baseline["knownDebts"] = [copy.deepcopy(entry)]
            baseline["expectedOmissions"] = []
            baseline["releaseOnlySkips"] = []
            return baseline

        def source_record(
            entry: Mapping,
            targets: list[str],
            *,
            tool_role: str,
            platform_name: str,
        ) -> dict:
            authorities = [ci._target_authority(ci.REPO_ROOT, target) for target in targets]
            specification = synthetic_command_spec(
                source_command_id(entry),
                str(entry["commandClass"]),
                0,
                command_role="observation-producing",
                allowed_exits=[0, 1, 2],
                targets=authorities,
                execution_input_mode="PROTECTED-TARGET-BUNDLE",
            )
            specification["toolRole"] = tool_role
            specification["profile"] = (
                "static" if entry["commandClass"] == "static-suite" else "frontend"
            )
            specification["platform"] = platform_name
            return synthetic_record_from_spec(specification, passed=False)

        def derived_observation(
            entry: Mapping,
            record: dict,
            raw_fields: Mapping,
            binding: Mapping,
            *,
            source_path: str,
            occurrences: int = 1,
        ) -> tuple[dict, dict]:
            scope = str(entry["testOrPathScope"])
            source_result = scope.removeprefix("result:")
            raw = ci.make_raw_observation(
                str(record["commandId"]),
                int(record["ordinal"]),
                0,
                (
                    "static-producer-v1"
                    if entry["commandClass"] == "static-suite"
                    else "process-output-v1"
                ),
                source_result,
                source_path,
                raw_fields,
                ci.command_output_digest(record),
                occurrences,
                failure_path_authority=binding,
            )
            self.assertEqual(
                ci._validate_raw_observation(raw, label="r03-fixture", source=record),
                [],
            )
            record = copy.deepcopy(record)
            record["producerObservations"] = [raw]
            record["producerObservationSetDigest"] = ci.producer_observation_set_digest(
                record["producerObservations"]
            )
            observed = ci._rederive_observation_record(
                {"rawObservation": raw},
                record,
            )
            return observed, record

        def assert_classification(
            entry: Mapping,
            observed: Mapping,
            record: Mapping,
            *,
            platform_name: str,
            known: bool,
        ) -> dict:
            result = ci.compare_observations(
                baseline_for(entry),
                [observed],
                {str(entry["commandClass"])},
                platform_name,
                command_records=[record],
            )
            violation_ids = [item["id"] for item in result["violations"]]
            if known:
                self.assertEqual(violation_ids, [])
                self.assertEqual(result["observedDebts"][0]["id"], entry["id"])
            else:
                self.assertIn("UNKNOWN-NONPASS", violation_ids)
            return result

        ubuntu_repository = "/home/runner/work/IELTS-practice/IELTS-practice"
        ubuntu_snapshot = "/tmp/cs-r03"
        ubuntu_python = "/opt/hostedtoolcache/Python/3.14.0/x64/python"
        static_entries = [
            entries[entry_id]
            for entry_id in (
                "B-STATIC-PY-PLAYWRIGHT-READING-QUICK-AUDIT",
                "B-STATIC-PY-PLAYWRIGHT-NB-DRAG",
                "B-STATIC-PY-PLAYWRIGHT-ROUNDTRIP",
                "B-STATIC-PY-PLAYWRIGHT-UNIFIED-SUBMIT",
                "B-STATIC-PRACTICE-CUSTOM-CARD-LAYOUT",
                "B-STATIC-ON-DEMAND-HARNESS-DOM-STUB",
            )
        ]
        for entry in static_entries:
            scope = str(entry["testOrPathScope"])
            logical_target = ci.R03_FAILURE_TARGETS[scope]
            authority = ci._coerce_failure_path_authority(
                ubuntu_repository,
                ubuntu_snapshot,
                [logical_target],
                trusted_executables=[("python-static-producer", ubuntu_python)],
            )
            canonical_variants: list[tuple[dict, dict]] = []
            for representation, physical_root in (
                ("ubuntu-live", ubuntu_repository),
                ("ubuntu-snapshot", ubuntu_snapshot),
            ):
                with self.subTest(entry=entry["id"], representation=representation):
                    result_fields = {
                        "name": scope.removeprefix("result:"),
                        "status": "fail",
                        "detail": r03_static_failure_detail(
                            logical_target,
                            physical_root,
                            ubuntu_python,
                        ),
                    }
                    canonical_result, binding = ci.canonicalize_failure_identity_value(
                        result_fields,
                        authority,
                    )
                    canonical_variants.append((canonical_result, binding))
                    identity = ci.structured_failure_identity(
                        scope,
                        canonical_result["detail"],
                        path_authority=binding,
                    )
                    self.assertEqual(
                        ci.static_failure_signature(
                            scope,
                            canonical_result["detail"],
                            identity,
                        ),
                        entry["allowedNormalizedSignature"][0],
                    )
                    record = source_record(
                        entry,
                        [logical_target],
                        tool_role="python-static-producer",
                        platform_name="ubuntu",
                    )
                    observed, bound_record = derived_observation(
                        entry,
                        record,
                        canonical_result,
                        binding,
                        source_path=ci.STATIC_SUITE_RELATIVE_PATH,
                    )
                    assert_classification(
                        entry,
                        observed,
                        bound_record,
                        platform_name="ubuntu",
                        known=True,
                    )
            self.assertEqual(canonical_variants[0], canonical_variants[1])

            mutated_result = copy.deepcopy(canonical_variants[0][0])
            mutated_result["detail"] += "\nR03 non-path mutation"
            mutation_record = source_record(
                entry,
                [logical_target],
                tool_role="python-static-producer",
                platform_name="ubuntu",
            )
            mutated, mutated_record = derived_observation(
                entry,
                mutation_record,
                mutated_result,
                canonical_variants[0][1],
                source_path=ci.STATIC_SUITE_RELATIVE_PATH,
            )
            with self.subTest(entry=entry["id"], mutation="non-path-message"):
                assert_classification(
                    entry,
                    mutated,
                    mutated_record,
                    platform_name="ubuntu",
                    known=False,
                )

        windows_repository = r"D:\a\IELTS-practice\IELTS-practice"
        windows_snapshot = r"C:\Users\RUNNER~1\AppData\Local\Temp\cs-r03"
        node_entries = [
            entries["E-ADMIN-FRONTEND-DOM-STUB"],
            entries["E-WINDOWS-LOCAL-DATA-CRLF-ASSERTION"],
        ]
        for entry in node_entries:
            scope = str(entry["testOrPathScope"])
            logical_target = ci.R03_FAILURE_TARGETS[scope]
            source_targets = [logical_target]
            if logical_target.endswith("adminFrontendGuard.test.js"):
                source_targets.append("backend/admin/admin.js")
            authority = ci._coerce_failure_path_authority(
                windows_repository,
                windows_snapshot,
                source_targets,
            )
            canonical_variants = []
            for representation, physical_root in (
                ("windows-live", windows_repository),
                ("windows-snapshot", windows_snapshot),
            ):
                with self.subTest(entry=entry["id"], representation=representation):
                    fields = {
                        "executed": True,
                        "exitCode": 1,
                        "stdout": r03_node_failure_output(
                            logical_target,
                            physical_root,
                        ),
                        "stderr": "",
                        "error": None,
                    }
                    canonical_fields, binding = ci.canonicalize_failure_identity_value(
                        fields,
                        authority,
                    )
                    canonical_variants.append((canonical_fields, binding))
                    self.assertEqual(
                        ci.node_failure_signature(
                            scope,
                            canonical_fields["stdout"],
                            path_authority=binding,
                        ),
                        entry["allowedNormalizedSignature"][0],
                    )
                    record = source_record(
                        entry,
                        source_targets,
                        tool_role="node-security-test",
                        platform_name="windows",
                    )
                    observed, bound_record = derived_observation(
                        entry,
                        record,
                        canonical_fields,
                        binding,
                        source_path=logical_target,
                    )
                    assert_classification(
                        entry,
                        observed,
                        bound_record,
                        platform_name="windows",
                        known=True,
                    )
            self.assertEqual(canonical_variants[0], canonical_variants[1])

            mutated_fields = copy.deepcopy(canonical_variants[0][0])
            mutated_fields["stdout"] = mutated_fields["stdout"].replace(
                next(iter(ci.KNOWN_NODE_FAILURES[scope]["errorMessages"])),
                "R03 non-path mutation",
            )
            mutation_record = source_record(
                entry,
                source_targets,
                tool_role="node-security-test",
                platform_name="windows",
            )
            mutated, mutated_record = derived_observation(
                entry,
                mutation_record,
                mutated_fields,
                canonical_variants[0][1],
                source_path=logical_target,
            )
            with self.subTest(entry=entry["id"], mutation="non-path-message"):
                assert_classification(
                    entry,
                    mutated,
                    mutated_record,
                    platform_name="windows",
                    known=False,
                )

        count_entry = static_entries[0]
        count_scope = str(count_entry["testOrPathScope"])
        count_target = ci.R03_FAILURE_TARGETS[count_scope]
        count_authority = ci._coerce_failure_path_authority(
            ubuntu_repository,
            ubuntu_snapshot,
            [count_target],
            trusted_executables=[("python-static-producer", ubuntu_python)],
        )
        count_fields, count_binding = ci.canonicalize_failure_identity_value(
            {
                "name": count_scope.removeprefix("result:"),
                "status": "fail",
                "detail": r03_static_failure_detail(
                    count_target,
                    ubuntu_snapshot,
                    ubuntu_python,
                ),
            },
            count_authority,
        )
        count_record = source_record(
            count_entry,
            [count_target],
            tool_role="python-static-producer",
            platform_name="ubuntu",
        )
        counted, counted_record = derived_observation(
            count_entry,
            count_record,
            count_fields,
            count_binding,
            source_path=ci.STATIC_SUITE_RELATIVE_PATH,
            occurrences=2,
        )
        count_result = ci.compare_observations(
            baseline_for(count_entry),
            [counted],
            {"static-suite"},
            "ubuntu",
            command_records=[counted_record],
        )
        self.assertIn(
            "BASELINE-OCCURRENCE-LIMIT",
            [item["id"] for item in count_result["violations"]],
        )

        wrong_static_target = ci.R03_FAILURE_TARGETS[
            "result:模拟模式 NB 拖拽回灌回归测试"
        ]
        exact_static_detail = r03_static_failure_detail(
            count_target,
            ubuntu_snapshot,
            ubuntu_python,
        )
        wrong_static_detail = exact_static_detail.replace(
            count_target,
            wrong_static_target,
        )
        self.assertNotEqual(exact_static_detail, wrong_static_detail)
        wrong_static_fields, wrong_static_binding = (
            ci.canonicalize_failure_identity_value(
                {
                    "name": count_scope.removeprefix("result:"),
                    "status": "fail",
                    "detail": wrong_static_detail,
                },
                count_authority,
            )
        )
        self.assertEqual(wrong_static_binding["authorizedTargetPaths"], [])
        self.assertTrue(wrong_static_binding["unmappedAbsolutePathDigests"])
        wrong_static, wrong_static_record = derived_observation(
            count_entry,
            count_record,
            wrong_static_fields,
            wrong_static_binding,
            source_path=ci.STATIC_SUITE_RELATIVE_PATH,
        )
        with self.subTest(family="static", mutation="path-target"):
            assert_classification(
                count_entry,
                wrong_static,
                wrong_static_record,
                platform_name="ubuntu",
                known=False,
            )

        node_count_entry = node_entries[0]
        node_count_scope = str(node_count_entry["testOrPathScope"])
        node_count_target = ci.R03_FAILURE_TARGETS[node_count_scope]
        node_count_targets = [node_count_target, "backend/admin/admin.js"]
        node_count_authority = ci._coerce_failure_path_authority(
            windows_repository,
            windows_snapshot,
            node_count_targets,
        )
        exact_node_output = r03_node_failure_output(
            node_count_target,
            windows_snapshot,
        )
        node_count_fields, node_count_binding = (
            ci.canonicalize_failure_identity_value(
                {
                    "executed": True,
                    "exitCode": 1,
                    "stdout": exact_node_output,
                    "stderr": "",
                    "error": None,
                },
                node_count_authority,
            )
        )
        node_count_record = source_record(
            node_count_entry,
            node_count_targets,
            tool_role="node-security-test",
            platform_name="windows",
        )
        node_counted, node_counted_record = derived_observation(
            node_count_entry,
            node_count_record,
            node_count_fields,
            node_count_binding,
            source_path=node_count_target,
            occurrences=2,
        )
        node_count_result = ci.compare_observations(
            baseline_for(node_count_entry),
            [node_counted],
            {"frontend"},
            "windows",
            command_records=[node_counted_record],
        )
        self.assertIn(
            "BASELINE-OCCURRENCE-LIMIT",
            [item["id"] for item in node_count_result["violations"]],
        )

        wrong_node_target = "developer/tests/js/localDataRenderingGuard.test.js"
        exact_node_uri = (
            "file:///"
            + windows_snapshot.replace("\\", "/").lstrip("/")
            + "/"
            + node_count_target
        )
        wrong_node_uri = (
            "file:///"
            + windows_snapshot.replace("\\", "/").lstrip("/")
            + "/"
            + wrong_node_target
        )
        wrong_node_output = exact_node_output.replace(exact_node_uri, wrong_node_uri)
        self.assertNotEqual(exact_node_output, wrong_node_output)
        wrong_node_fields, wrong_node_binding = (
            ci.canonicalize_failure_identity_value(
                {
                    "executed": True,
                    "exitCode": 1,
                    "stdout": wrong_node_output,
                    "stderr": "",
                    "error": None,
                },
                node_count_authority,
            )
        )
        self.assertTrue(wrong_node_binding["unmappedAbsolutePathDigests"])
        wrong_node, wrong_node_record = derived_observation(
            node_count_entry,
            node_count_record,
            wrong_node_fields,
            wrong_node_binding,
            source_path=node_count_target,
        )
        with self.subTest(family="node", mutation="path-target"):
            assert_classification(
                node_count_entry,
                wrong_node,
                wrong_node_record,
                platform_name="windows",
                known=False,
            )

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

    def test_static_session_failure_without_path_authority_fails_closed(self) -> None:
        baseline, entry = self.baseline_with_known_id("B-STATIC-SUITE-SESSION-ROUTING")
        detail = self.static_session_detail()
        identity = ci.structured_failure_identity(entry["testOrPathScope"], detail)
        signature = ci.static_failure_signature(entry["testOrPathScope"], detail, identity)
        observed = ci.observation(
            entry["commandClass"], entry["testOrPathScope"], "fail",
            signature, source_command_id(entry), failure_identity=identity,
        )
        result = ci.compare_observations(baseline, [observed], {entry["commandClass"]}, "windows")
        self.assertIn(
            "UNKNOWN-NONPASS",
            [item["id"] for item in result["violations"]],
        )

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


class R11KnownDebtSignatureBindingTest(unittest.TestCase):
    ADMIN_ID = "E-ADMIN-FRONTEND-DOM-STUB"
    ADMIN_SCOPE = "file:developer/tests/js/adminFrontendGuard.test.js"
    ADMIN_TARGET = "developer/tests/js/adminFrontendGuard.test.js"
    ADMIN_PRODUCT_TARGET = "backend/admin/admin.js"

    SUITE_ID = "B-STATIC-SUITE-SESSION-ROUTING"
    SUITE_SCOPE = "result:套题模式状态机回归测试"
    SUITE_TARGET = "developer/tests/js/suiteModeRegression.test.js"

    LOCAL_ID = "E-WINDOWS-LOCAL-DATA-CRLF-ASSERTION"
    LOCAL_SCOPE = "file:developer/tests/js/localDataRenderingGuard.test.js"
    LOCAL_TARGET = "developer/tests/js/localDataRenderingGuard.test.js"

    POSIX_REPOSITORY = "/home/runner/work/IELTS-practice/IELTS-practice"
    POSIX_SNAPSHOT = "/tmp/cs-r11-known-debt"
    WINDOWS_REPOSITORY = r"D:\a\IELTS-practice\IELTS-practice"
    WINDOWS_SNAPSHOT = (
        r"C:\Users\RUNNER~1\AppData\Local\Temp\cs-r11-known-debt"
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.full_baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        requested = {cls.ADMIN_ID, cls.SUITE_ID, cls.LOCAL_ID}
        cls.entries = {
            entry["id"]: entry
            for entry in cls.full_baseline["knownDebts"]
            if entry["id"] in requested
        }
        if set(cls.entries) != requested:
            raise AssertionError("R11 known-debt fixture inventory is incomplete")

    @classmethod
    def targets_for(cls, entry: Mapping) -> list[str]:
        target = ci.R11_KNOWN_DEBT_FAILURE_TARGETS[
            str(entry["testOrPathScope"])
        ]
        if entry["id"] == cls.ADMIN_ID:
            return [target, cls.ADMIN_PRODUCT_TARGET]
        return [target]

    @classmethod
    def baseline_for(cls, entry: Mapping) -> dict:
        baseline = copy.deepcopy(cls.full_baseline)
        baseline["knownDebts"] = [copy.deepcopy(entry)]
        baseline["expectedOmissions"] = []
        baseline["releaseOnlySkips"] = []
        return baseline

    @staticmethod
    def physical_uri(root: str, logical_target: str) -> str:
        normalized = root.rstrip("/\\").replace("\\", "/")
        return "file:///" + normalized.lstrip("/") + "/" + logical_target

    @staticmethod
    def physical_native(root: str, logical_target: str) -> str:
        if re.match(r"^[A-Za-z]:", root):
            return root.rstrip("/\\") + "\\" + logical_target.replace("/", "\\")
        return root.rstrip("/") + "/" + logical_target

    @classmethod
    def node_fields(
        cls,
        entry: Mapping,
        physical_root: str,
        representation: str,
    ) -> dict:
        target = ci.R11_KNOWN_DEBT_FAILURE_TARGETS[
            str(entry["testOrPathScope"])
        ]
        output = r03_node_failure_output(target, physical_root)
        uri = cls.physical_uri(physical_root, target)
        if representation == "native":
            output = output.replace(
                uri,
                cls.physical_native(physical_root, target),
            )
        elif representation == "encoded-short-uri":
            output = output.replace(uri, uri.replace("RUNNER~1", "RUNNER%7E1"))
        elif representation != "file-uri":
            raise AssertionError(f"unsupported node representation: {representation}")
        return {
            "executed": True,
            "exitCode": 1,
            "stdout": output,
            "stderr": "",
            "error": None,
        }

    @classmethod
    def suite_fields(cls, physical_root: str, representation: str) -> dict:
        assertion = "sessionId 不一致时仍应路由模拟导航"
        native_target = cls.physical_native(physical_root, cls.SUITE_TARGET)
        if representation == "native":
            location = native_target
        elif representation == "file-uri":
            location = cls.physical_uri(physical_root, cls.SUITE_TARGET)
        else:
            raise AssertionError(f"unsupported suite representation: {representation}")
        inner = {
            "status": "fail",
            "detail": (
                f"AssertionError [ERR_ASSERTION]: {assertion}\n\n"
                f"0 !== 1\n\n    at run ({location}:667:16)"
            ),
        }
        detail = (
            "执行失败: "
            + json.dumps(inner, ensure_ascii=False, separators=(",", ":"))
            + f"Command ['node', {native_target!r}] returned non-zero exit status 1."
        )
        return {
            "name": cls.SUITE_SCOPE.removeprefix("result:"),
            "status": "fail",
            "detail": detail,
        }

    @classmethod
    def canonical_fields(
        cls,
        entry: Mapping,
        fields: Mapping,
        repository_root: str,
        snapshot_root: str,
    ) -> tuple[dict, dict]:
        authority = ci._coerce_failure_path_authority(
            repository_root,
            snapshot_root,
            cls.targets_for(entry),
        )
        canonical, binding = ci.canonicalize_failure_identity_value(
            fields,
            authority,
        )
        return canonical, binding

    @classmethod
    def source_record(cls, entry: Mapping, platform_name: str) -> dict:
        authorities = [
            ci._target_authority(ci.REPO_ROOT, target)
            for target in cls.targets_for(entry)
        ]
        specification = synthetic_command_spec(
            source_command_id(entry),
            str(entry["commandClass"]),
            0,
            command_role="observation-producing",
            allowed_exits=[0, 1],
            targets=authorities,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        specification["toolRole"] = (
            "python-static-producer"
            if entry["commandClass"] == "static-suite"
            else "node-security-test"
        )
        specification["profile"] = (
            "static" if entry["commandClass"] == "static-suite" else "frontend"
        )
        specification["platform"] = platform_name
        return synthetic_record_from_spec(specification, passed=False)

    @classmethod
    def observed_record(
        cls,
        entry: Mapping,
        fields: Mapping,
        binding: Mapping,
        platform_name: str,
        *,
        occurrences: int = 1,
    ) -> tuple[dict, dict]:
        record = cls.source_record(entry, platform_name)
        scope = str(entry["testOrPathScope"])
        raw = ci.make_raw_observation(
            str(record["commandId"]),
            int(record["ordinal"]),
            0,
            (
                "static-producer-v1"
                if entry["commandClass"] == "static-suite"
                else "process-output-v1"
            ),
            scope.removeprefix("result:"),
            (
                ci.STATIC_SUITE_RELATIVE_PATH
                if entry["commandClass"] == "static-suite"
                else ci.R11_KNOWN_DEBT_FAILURE_TARGETS[scope]
            ),
            fields,
            ci.command_output_digest(record),
            occurrences,
            failure_path_authority=binding,
        )
        validation_errors = ci._validate_raw_observation(
            raw,
            label="r11-known-debt-fixture",
            source=record,
        )
        if validation_errors:
            raise AssertionError(validation_errors)
        record = copy.deepcopy(record)
        record["producerObservations"] = [raw]
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest(
            record["producerObservations"]
        )
        observed = ci._rederive_observation_record(
            {"rawObservation": raw},
            record,
        )
        return observed, record

    def classify(
        self,
        entry: Mapping,
        fields: Mapping,
        binding: Mapping,
        platform_name: str,
        *,
        occurrences: int = 1,
    ) -> tuple[dict, dict, dict]:
        observed, record = self.observed_record(
            entry,
            fields,
            binding,
            platform_name,
            occurrences=occurrences,
        )
        result = ci.compare_observations(
            self.baseline_for(entry),
            [observed],
            {str(entry["commandClass"])},
            platform_name,
            command_records=[record],
        )
        return result, observed, record

    def assert_known(self, result: Mapping, entry: Mapping) -> None:
        self.assertEqual(result["violations"], [])
        self.assertEqual(
            [item["id"] for item in result["observedDebts"]],
            [entry["id"]],
        )

    def assert_blocking(self, result: Mapping) -> None:
        self.assertTrue(result["violations"], result)
        self.assertEqual(result["observedDebts"], [])

    def test_exact_r11_authority_inventory_is_three_existing_debts(self) -> None:
        self.assertEqual(
            dict(ci.R11_KNOWN_DEBT_FAILURE_TARGETS),
            {
                self.SUITE_SCOPE: self.SUITE_TARGET,
                self.ADMIN_SCOPE: self.ADMIN_TARGET,
                self.LOCAL_SCOPE: self.LOCAL_TARGET,
            },
        )
        self.assertEqual(len(ci.R11_KNOWN_DEBT_FAILURE_TARGETS), 3)
        self.assertEqual(
            ci.R11_POSIX_FILE_URI_TARGETS,
            frozenset({self.ADMIN_TARGET, self.SUITE_TARGET}),
        )
        self.assertEqual(
            ci.R11_WINDOWS_ENCODED_SHORT_NAME_URI_TARGETS,
            frozenset({self.ADMIN_TARGET, self.LOCAL_TARGET}),
        )

    def test_admin_native_and_exact_posix_file_uri_bind_existing_debt(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        canonical_variants = []
        for root, representation in (
            (self.POSIX_REPOSITORY, "native"),
            (self.POSIX_SNAPSHOT, "native"),
            (self.POSIX_REPOSITORY, "file-uri"),
            (self.POSIX_SNAPSHOT, "file-uri"),
        ):
            with self.subTest(root=root, representation=representation):
                fields, binding = self.canonical_fields(
                    entry,
                    self.node_fields(entry, root, representation),
                    self.POSIX_REPOSITORY,
                    self.POSIX_SNAPSHOT,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [self.ADMIN_TARGET])
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                result, observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assertEqual(
                    observed["legacyBaselineComparisonDigest"],
                    entry["allowedNormalizedSignature"][0],
                )
                self.assert_known(result, entry)
                canonical_variants.append((fields, binding))
        self.assertEqual(len({ci.canonical_failure_digest(item) for item in canonical_variants}), 1)

    def test_suite_native_root_descendant_and_posix_file_uri_bind_existing_debt(self) -> None:
        entry = self.entries[self.SUITE_ID]
        canonical_variants = []
        for root, representation in (
            (self.POSIX_REPOSITORY, "native"),
            (self.POSIX_SNAPSHOT, "native"),
            (self.POSIX_REPOSITORY, "file-uri"),
            (self.POSIX_SNAPSHOT, "file-uri"),
        ):
            with self.subTest(root=root, representation=representation):
                fields, binding = self.canonical_fields(
                    entry,
                    self.suite_fields(root, representation),
                    self.POSIX_REPOSITORY,
                    self.POSIX_SNAPSHOT,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [self.SUITE_TARGET])
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                result, observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assertEqual(
                    observed["legacyBaselineComparisonDigest"],
                    entry["allowedNormalizedSignature"][0],
                )
                self.assert_known(result, entry)
                canonical_variants.append((fields, binding))
        self.assertEqual(len({ci.canonical_failure_digest(item) for item in canonical_variants}), 1)

    def test_local_data_native_uri_and_encoded_short_name_bind_on_windows(self) -> None:
        entry = self.entries[self.LOCAL_ID]
        canonical_variants = []
        for root, representation in (
            (self.WINDOWS_REPOSITORY, "native"),
            (self.WINDOWS_SNAPSHOT, "native"),
            (self.WINDOWS_SNAPSHOT, "file-uri"),
            (self.WINDOWS_SNAPSHOT, "encoded-short-uri"),
        ):
            with self.subTest(root=root, representation=representation):
                fields, binding = self.canonical_fields(
                    entry,
                    self.node_fields(entry, root, representation),
                    self.WINDOWS_REPOSITORY,
                    self.WINDOWS_SNAPSHOT,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [self.LOCAL_TARGET])
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                result, observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "windows",
                )
                self.assertEqual(
                    observed["legacyBaselineComparisonDigest"],
                    entry["allowedNormalizedSignature"][0],
                )
                self.assert_known(result, entry)
                canonical_variants.append((fields, binding))
        self.assertEqual(len({ci.canonical_failure_digest(item) for item in canonical_variants}), 1)

    def test_admin_wrong_location_message_and_extra_failure_block(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        exact = self.node_fields(entry, self.POSIX_SNAPSHOT, "file-uri")
        exact_uri = self.physical_uri(self.POSIX_SNAPSHOT, self.ADMIN_TARGET)
        variants = {
            "wrong-location": exact["stdout"].replace(
                exact_uri,
                self.physical_uri(
                    self.POSIX_SNAPSHOT,
                    "other/adminFrontendGuard.test.js",
                ),
            ),
            "altered-type-error": exact["stdout"].replace(
                "document.querySelectorAll is not a function",
                "document.querySelector is not a function",
            ),
            "extra-failure": (
                exact["stdout"].replace("ℹ fail 1", "ℹ fail 2")
                + "\nAssertionError: unrelated authorization failure"
            ),
        }
        for label, stdout in variants.items():
            with self.subTest(label=label):
                candidate = {**exact, "stdout": stdout}
                fields, binding = self.canonical_fields(
                    entry,
                    candidate,
                    self.POSIX_REPOSITORY,
                    self.POSIX_SNAPSHOT,
                )
                result, _observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assert_blocking(result)

    def test_suite_wrong_location_near_prefix_message_values_and_count_block(self) -> None:
        entry = self.entries[self.SUITE_ID]
        exact = self.suite_fields(self.POSIX_SNAPSHOT, "file-uri")
        exact_target = f"{self.POSIX_SNAPSHOT}/{self.SUITE_TARGET}"
        wrong_location = copy.deepcopy(exact)
        wrong_location["detail"] = wrong_location["detail"].replace(
            exact_target,
            f"{self.POSIX_SNAPSHOT}/other/suiteModeRegression.test.js",
        )
        near_prefix = self.suite_fields(
            self.POSIX_SNAPSHOT + "-evil",
            "file-uri",
        )
        altered_message = copy.deepcopy(exact)
        altered_message["detail"] = altered_message["detail"].replace(
            "sessionId 不一致时仍应路由模拟导航",
            "sessionId 不一致时应拒绝导航",
        )
        altered_values = copy.deepcopy(exact)
        altered_values["detail"] = altered_values["detail"].replace(
            "0 !== 1",
            "1 !== 2",
        )
        for label, candidate in (
            ("wrong-location", wrong_location),
            ("near-prefix", near_prefix),
            ("altered-message", altered_message),
            ("altered-values", altered_values),
        ):
            with self.subTest(label=label):
                fields, binding = self.canonical_fields(
                    entry,
                    candidate,
                    self.POSIX_REPOSITORY,
                    self.POSIX_SNAPSHOT,
                )
                result, _observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assert_blocking(result)

        fields, binding = self.canonical_fields(
            entry,
            exact,
            self.POSIX_REPOSITORY,
            self.POSIX_SNAPSHOT,
        )
        counted, _observed, _record = self.classify(
            entry,
            fields,
            binding,
            "ubuntu",
            occurrences=2,
        )
        self.assertIn(
            "BASELINE-OCCURRENCE-LIMIT",
            [item["id"] for item in counted["violations"]],
        )
        self.assertEqual(counted["observedDebts"], [])

    def test_local_data_wrong_file_unrelated_7e_values_and_count_block(self) -> None:
        entry = self.entries[self.LOCAL_ID]
        exact = self.node_fields(
            entry,
            self.WINDOWS_SNAPSHOT,
            "encoded-short-uri",
        )
        encoded_uri = self.physical_uri(
            self.WINDOWS_SNAPSHOT,
            self.LOCAL_TARGET,
        ).replace("RUNNER~1", "RUNNER%7E1")
        wrong_file = exact["stdout"].replace(
            encoded_uri,
            encoded_uri.replace(
                "/developer/tests/js/localDataRenderingGuard.test.js",
                "/other/localDataRenderingGuard.test.js",
            ),
        )
        unrelated_7e = exact["stdout"].replace(
            encoded_uri,
            "file:///C:/Unrelated/RUNNER%7E1/"
            + self.LOCAL_TARGET,
        )
        changed_values = exact["stdout"].replace(
            "actual: false",
            "actual: true",
        )
        reversed_values = (
            exact["stdout"]
            .replace("actual: false", "actual: true")
            .replace("expected: true", "expected: false")
        )
        for label, stdout in (
            ("wrong-file", wrong_file),
            ("unrelated-7e", unrelated_7e),
            ("changed-values", changed_values),
            ("reversed-values", reversed_values),
        ):
            with self.subTest(label=label):
                fields, binding = self.canonical_fields(
                    entry,
                    {**exact, "stdout": stdout},
                    self.WINDOWS_REPOSITORY,
                    self.WINDOWS_SNAPSHOT,
                )
                result, _observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "windows",
                )
                self.assert_blocking(result)

        fields, binding = self.canonical_fields(
            entry,
            exact,
            self.WINDOWS_REPOSITORY,
            self.WINDOWS_SNAPSHOT,
        )
        counted, _observed, _record = self.classify(
            entry,
            fields,
            binding,
            "windows",
            occurrences=2,
        )
        self.assertIn(
            "BASELINE-OCCURRENCE-LIMIT",
            [item["id"] for item in counted["violations"]],
        )
        self.assertEqual(counted["observedDebts"], [])

    def test_local_data_exact_identity_does_not_bind_on_posix(self) -> None:
        entry = self.entries[self.LOCAL_ID]
        fields, binding = self.canonical_fields(
            entry,
            self.node_fields(entry, self.POSIX_SNAPSHOT, "native"),
            self.POSIX_REPOSITORY,
            self.POSIX_SNAPSHOT,
        )
        self.assertEqual(binding["authorizedTargetPaths"], [self.LOCAL_TARGET])
        result, observed, _record = self.classify(
            entry,
            fields,
            binding,
            "ubuntu",
        )
        self.assertEqual(
            observed["legacyBaselineComparisonDigest"],
            entry["allowedNormalizedSignature"][0],
        )
        self.assert_blocking(result)

    def test_arbitrary_file_uri_traversal_malformed_and_unmapped_target_block(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        exact = self.node_fields(entry, self.POSIX_SNAPSHOT, "file-uri")
        exact_uri = self.physical_uri(self.POSIX_SNAPSHOT, self.ADMIN_TARGET)
        replacements = {
            "arbitrary-uri": "file:///opt/unrelated/" + self.ADMIN_TARGET,
            "traversal": (
                "file:///tmp/cs-r11-known-debt/../outside/"
                "adminFrontendGuard.test.js"
            ),
            "malformed-uri": (
                "file:///tmp/cs-r11-known-debt/%GG/"
                "adminFrontendGuard.test.js"
            ),
            "unrelated-unmapped-target": (
                "file:///tmp/cs-r11-known-debt/developer/tests/js/"
                "unrelatedSecurity.test.js"
            ),
        }
        for label, replacement in replacements.items():
            with self.subTest(label=label):
                candidate = {
                    **exact,
                    "stdout": exact["stdout"].replace(exact_uri, replacement),
                }
                fields, binding = self.canonical_fields(
                    entry,
                    candidate,
                    self.POSIX_REPOSITORY,
                    self.POSIX_SNAPSHOT,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [])
                self.assertTrue(binding["unmappedAbsolutePathDigests"])
                result, _observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assert_blocking(result)

    def test_exact_debt_plus_one_novel_failure_remains_blocking(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        fields, binding = self.canonical_fields(
            entry,
            self.node_fields(entry, self.POSIX_SNAPSHOT, "file-uri"),
            self.POSIX_REPOSITORY,
            self.POSIX_SNAPSHOT,
        )
        exact, record = self.observed_record(
            entry,
            fields,
            binding,
            "ubuntu",
        )
        novel = ci.observation(
            "frontend-security",
            "file:developer/tests/js/unrelatedSecurity.test.js",
            "fail",
            "sha256:" + "9" * 64,
            "frontend-security:unrelatedSecurity.test.js",
            failure_identity={
                "scope": "file:developer/tests/js/unrelatedSecurity.test.js",
                "structuredFailureSet": "sha256:" + "8" * 64,
            },
        )
        result = ci.compare_observations(
            self.baseline_for(entry),
            [exact, novel],
            {"frontend-security"},
            "ubuntu",
            command_records=[record],
        )
        self.assertIn(
            "UNKNOWN-NONPASS",
            [item["id"] for item in result["violations"]],
        )
        self.assertEqual(
            [item["id"] for item in result["observedDebts"]],
            [entry["id"]],
        )

    def test_same_basename_outside_each_authorized_root_never_binds(self) -> None:
        cases = (
            (
                self.entries[self.ADMIN_ID],
                self.node_fields(
                    self.entries[self.ADMIN_ID],
                    "/tmp/unrelated-r11",
                    "file-uri",
                ),
                self.POSIX_REPOSITORY,
                self.POSIX_SNAPSHOT,
                "ubuntu",
            ),
            (
                self.entries[self.SUITE_ID],
                self.suite_fields("/tmp/unrelated-r11", "file-uri"),
                self.POSIX_REPOSITORY,
                self.POSIX_SNAPSHOT,
                "ubuntu",
            ),
            (
                self.entries[self.LOCAL_ID],
                self.node_fields(
                    self.entries[self.LOCAL_ID],
                    r"C:\Unrelated\RUNNER~1\cs-r11",
                    "encoded-short-uri",
                ),
                self.WINDOWS_REPOSITORY,
                self.WINDOWS_SNAPSHOT,
                "windows",
            ),
        )
        for entry, candidate, repository, snapshot, platform_name in cases:
            with self.subTest(entry=entry["id"]):
                fields, binding = self.canonical_fields(
                    entry,
                    candidate,
                    repository,
                    snapshot,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [])
                self.assertTrue(binding["unmappedAbsolutePathDigests"])
                result, _observed, _record = self.classify(
                    entry,
                    fields,
                    binding,
                    platform_name,
                )
                self.assert_blocking(result)


class R11WindowsKnownDebtRecurrenceTest(unittest.TestCase):
    ADMIN_ID = R11KnownDebtSignatureBindingTest.ADMIN_ID
    ADMIN_TARGET = R11KnownDebtSignatureBindingTest.ADMIN_TARGET
    LOCAL_ID = R11KnownDebtSignatureBindingTest.LOCAL_ID
    SUITE_ID = R11KnownDebtSignatureBindingTest.SUITE_ID
    RUN8_WINDOWS_SNAPSHOT = (
        r"C:\Users\RUNNER~1\AppData\Local\Temp\cs-ro3gvaro"
    )
    RUN8_ENCODED_URI = (
        "file:///C:/Users/RUNNER%7E1/AppData/Local/Temp/cs-ro3gvaro/"
        "developer/tests/js/adminFrontendGuard.test.js"
    )

    @classmethod
    def setUpClass(cls) -> None:
        R11KnownDebtSignatureBindingTest.setUpClass()
        cls.fixture = R11KnownDebtSignatureBindingTest(
            "test_exact_r11_authority_inventory_is_three_existing_debts"
        )
        cls.entries = R11KnownDebtSignatureBindingTest.entries

    def assert_known(self, result: Mapping, entry: Mapping) -> None:
        self.assertEqual(result["violations"], [])
        self.assertEqual(
            [item["id"] for item in result["observedDebts"]],
            [entry["id"]],
        )

    def assert_blocking(self, result: Mapping) -> None:
        self.assertTrue(result["violations"], result)
        self.assertEqual(result["observedDebts"], [])

    def exact_run8_fields(self) -> dict:
        entry = self.entries[self.ADMIN_ID]
        fields = R11KnownDebtSignatureBindingTest.node_fields(
            entry,
            self.RUN8_WINDOWS_SNAPSHOT,
            "encoded-short-uri",
        )
        self.assertEqual(fields["stdout"].count(self.RUN8_ENCODED_URI), 1)
        return fields

    def canonical_admin(
        self,
        fields: Mapping,
        repository_root: str | None = None,
        snapshot_root: str | None = None,
    ) -> tuple[dict, dict]:
        fixture = R11KnownDebtSignatureBindingTest
        return fixture.canonical_fields(
            self.entries[self.ADMIN_ID],
            fields,
            repository_root or fixture.WINDOWS_REPOSITORY,
            snapshot_root or self.RUN8_WINDOWS_SNAPSHOT,
        )

    def test_recurrence_authority_is_target_scoped_and_existing_debt_is_unchanged(
        self,
    ) -> None:
        fixture = R11KnownDebtSignatureBindingTest
        entry = self.entries[self.ADMIN_ID]
        self.assertEqual(
            ci.R11_WINDOWS_ENCODED_SHORT_NAME_URI_TARGETS,
            frozenset({fixture.ADMIN_TARGET, fixture.LOCAL_TARGET}),
        )
        self.assertNotIn(
            fixture.SUITE_TARGET,
            ci.R11_WINDOWS_ENCODED_SHORT_NAME_URI_TARGETS,
        )
        self.assertEqual(entry["id"], "E-ADMIN-FRONTEND-DOM-STUB")
        self.assertEqual(entry["testOrPathScope"], fixture.ADMIN_SCOPE)
        self.assertEqual(entry["maximumOccurrences"], 1)
        self.assertEqual(len(entry["allowedNormalizedSignature"]), 1)

    def test_exact_run8_encoded_short_name_uri_binds_only_admin_debt(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        fields, binding = self.canonical_admin(self.exact_run8_fields())
        self.assertEqual(binding["authorizedTargetPaths"], [self.ADMIN_TARGET])
        self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
        self.assertNotIn("cs-ro3gvaro", json.dumps(fields, sort_keys=True))
        result, observed, _record = self.fixture.classify(
            entry,
            fields,
            binding,
            "windows",
        )
        self.assertEqual(
            observed["legacyBaselineComparisonDigest"],
            entry["allowedNormalizedSignature"][0],
        )
        self.assert_known(result, entry)

    def test_ubuntu_native_and_posix_uri_behavior_remains_unchanged(self) -> None:
        fixture = R11KnownDebtSignatureBindingTest
        entry = self.entries[self.ADMIN_ID]
        for root, representation in (
            (fixture.POSIX_REPOSITORY, "native"),
            (fixture.POSIX_SNAPSHOT, "file-uri"),
        ):
            with self.subTest(root=root, representation=representation):
                fields, binding = fixture.canonical_fields(
                    entry,
                    fixture.node_fields(entry, root, representation),
                    fixture.POSIX_REPOSITORY,
                    fixture.POSIX_SNAPSHOT,
                )
                self.assertEqual(
                    binding["authorizedTargetPaths"],
                    [self.ADMIN_TARGET],
                )
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                result, _observed, _record = self.fixture.classify(
                    entry,
                    fields,
                    binding,
                    "ubuntu",
                )
                self.assert_known(result, entry)

    def test_existing_suite_and_local_data_bindings_are_preserved(self) -> None:
        fixture = R11KnownDebtSignatureBindingTest
        cases = (
            (
                self.entries[self.SUITE_ID],
                fixture.suite_fields(fixture.POSIX_SNAPSHOT, "file-uri"),
                fixture.POSIX_REPOSITORY,
                fixture.POSIX_SNAPSHOT,
                "ubuntu",
                fixture.SUITE_TARGET,
            ),
            (
                self.entries[self.LOCAL_ID],
                fixture.node_fields(
                    self.entries[self.LOCAL_ID],
                    fixture.WINDOWS_SNAPSHOT,
                    "encoded-short-uri",
                ),
                fixture.WINDOWS_REPOSITORY,
                fixture.WINDOWS_SNAPSHOT,
                "windows",
                fixture.LOCAL_TARGET,
            ),
        )
        for entry, raw, repository, snapshot, platform_name, target in cases:
            with self.subTest(entry=entry["id"]):
                fields, binding = fixture.canonical_fields(
                    entry,
                    raw,
                    repository,
                    snapshot,
                )
                self.assertEqual(binding["authorizedTargetPaths"], [target])
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                result, _observed, _record = self.fixture.classify(
                    entry,
                    fields,
                    binding,
                    platform_name,
                )
                self.assert_known(result, entry)

    def test_run8_path_uri_and_short_name_near_misses_fail_closed(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        exact = self.exact_run8_fields()
        replacements = {
            "wrong-test-target": self.RUN8_ENCODED_URI.replace(
                "adminFrontendGuard.test.js",
                "otherFrontendGuard.test.js",
            ),
            "same-basename-outside-root": (
                "file:///C:/outside/adminFrontendGuard.test.js"
            ),
            "unrelated-absolute-root": (
                "file:///D:/unrelated/developer/tests/js/"
                "adminFrontendGuard.test.js"
            ),
            "arbitrary-file-uri": (
                "file:///opt/unrelated/developer/tests/js/"
                "adminFrontendGuard.test.js"
            ),
            "malformed-percent-escape": self.RUN8_ENCODED_URI.replace(
                "RUNNER%7E1",
                "RUNNER%GG1",
            ),
            "traversal": self.RUN8_ENCODED_URI.replace(
                "cs-ro3gvaro/developer",
                "cs-ro3gvaro/../outside/developer",
            ),
            "unrelated-user-short-name": self.RUN8_ENCODED_URI.replace(
                "RUNNER%7E1",
                "OTHER%7E1",
            ),
            "wrong-short-name-ordinal": self.RUN8_ENCODED_URI.replace(
                "RUNNER%7E1",
                "RUNNER%7E2",
            ),
            "unrelated-short-name-component": self.RUN8_ENCODED_URI.replace(
                "Temp/cs-ro3gvaro",
                "Temp/OTHER%7E1/cs-ro3gvaro",
            ),
            "unrelated-temp-root": self.RUN8_ENCODED_URI.replace(
                "cs-ro3gvaro",
                "cs-unrelated",
            ),
            "generic-suffix-match": self.RUN8_ENCODED_URI.replace(
                "developer/tests/js/adminFrontendGuard.test.js",
                "unrelated/adminFrontendGuard.test.js",
            ),
        }
        for label, replacement in replacements.items():
            with self.subTest(label=label):
                candidate = {
                    **exact,
                    "stdout": exact["stdout"].replace(
                        self.RUN8_ENCODED_URI,
                        replacement,
                    ),
                }
                fields, binding = self.canonical_admin(candidate)
                self.assertEqual(binding["authorizedTargetPaths"], [])
                self.assertTrue(binding["unmappedAbsolutePathDigests"])
                result, _observed, _record = self.fixture.classify(
                    entry,
                    fields,
                    binding,
                    "windows",
                )
                self.assert_blocking(result)

    def test_wrong_identity_count_source_target_and_platform_fail_closed(
        self,
    ) -> None:
        fixture = R11KnownDebtSignatureBindingTest
        entry = self.entries[self.ADMIN_ID]
        exact = self.exact_run8_fields()
        variants = {
            "wrong-source-location": exact["stdout"].replace(
                "backend/admin/admin.js:83:44",
                "backend/admin/admin.js:84:44",
            ),
            "wrong-test-location": exact["stdout"].replace(
                self.RUN8_ENCODED_URI + ":113:4",
                self.RUN8_ENCODED_URI + ":114:4",
            ),
            "wrong-message": exact["stdout"].replace(
                "document.querySelectorAll is not a function",
                "document.querySelector is not a function",
            ),
            "wrong-exception-type": exact["stdout"].replace(
                "TypeError: document.querySelectorAll is not a function",
                "RangeError: document.querySelectorAll is not a function",
            ),
        }
        for label, candidate in variants.items():
            with self.subTest(label=label):
                fields, binding = self.canonical_admin(
                    {**exact, "stdout": candidate}
                )
                result, _observed, _record = self.fixture.classify(
                    entry,
                    fields,
                    binding,
                    "windows",
                )
                self.assert_blocking(result)

        fields, binding = self.canonical_admin(exact)
        result, _observed, _record = self.fixture.classify(
            entry,
            fields,
            binding,
            "windows",
            occurrences=2,
        )
        self.assert_blocking(result)

        posix_fields, posix_binding = fixture.canonical_fields(
            entry,
            exact,
            fixture.POSIX_REPOSITORY,
            fixture.POSIX_SNAPSHOT,
        )
        self.assertEqual(posix_binding["authorizedTargetPaths"], [])
        self.assertTrue(posix_binding["unmappedAbsolutePathDigests"])
        result, _observed, _record = self.fixture.classify(
            entry,
            posix_fields,
            posix_binding,
            "ubuntu",
        )
        self.assert_blocking(result)

        record = fixture.source_record(entry, "windows")
        wrong_source = ci.make_raw_observation(
            str(record["commandId"]),
            int(record["ordinal"]),
            0,
            "process-output-v1",
            fixture.ADMIN_SCOPE.removeprefix("file:"),
            "developer/tests/js/unrelatedSecurity.test.js",
            fields,
            ci.command_output_digest(record),
            1,
            failure_path_authority=binding,
        )
        source_errors = ci._validate_raw_observation(
            wrong_source,
            label="r11-windows-wrong-source-target",
            source=record,
        )
        self.assertEqual(source_errors, [])
        wrong_record = copy.deepcopy(record)
        wrong_record["producerObservations"] = [wrong_source]
        wrong_record["producerObservationSetDigest"] = (
            ci.producer_observation_set_digest(
                wrong_record["producerObservations"]
            )
        )
        wrong_observed = ci._rederive_observation_record(
            {"rawObservation": wrong_source},
            wrong_record,
        )
        result = ci.compare_observations(
            self.fixture.baseline_for(entry),
            [wrong_observed],
            {"frontend-security"},
            "windows",
            command_records=[wrong_record],
        )
        self.assert_blocking(result)

    def test_exact_debt_plus_novel_failure_cannot_mask_blocker(self) -> None:
        entry = self.entries[self.ADMIN_ID]
        fields, binding = self.canonical_admin(self.exact_run8_fields())
        exact, record = self.fixture.observed_record(
            entry,
            fields,
            binding,
            "windows",
        )
        novel = ci.observation(
            "frontend-security",
            "file:developer/tests/js/unrelatedSecurity.test.js",
            "fail",
            "sha256:" + "9" * 64,
            "frontend-security:unrelatedSecurity.test.js",
            failure_identity={
                "scope": "file:developer/tests/js/unrelatedSecurity.test.js",
                "structuredFailureSet": "sha256:" + "8" * 64,
            },
        )
        result = ci.compare_observations(
            self.fixture.baseline_for(entry),
            [exact, novel],
            {"frontend-security"},
            "windows",
            command_records=[record],
        )
        self.assertIn(
            "UNKNOWN-NONPASS",
            [item["id"] for item in result["violations"]],
        )
        self.assertEqual(
            [item["id"] for item in result["observedDebts"]],
            [entry["id"]],
        )


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
            release_gate_required=False,
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
        self.fixture_expected_context = synthetic_external_context(
            copy.deepcopy(runner.execution_binding)
        )
        output = repo / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=repo)
        with mock.patch.multiple(ci, OUTPUT_DIR=output, REPO_ROOT=repo):
            summary = ci.write_evidence(runner, empty_comparison())
        return output, summary

    def verify_fixture(self, output: Path, repo: Path) -> list[str]:
        try:
            return ci.verify_evidence_file_set(
                output,
                repo_root=repo,
                expected_command_plan=self.static_plan,
                expected_context=self.fixture_expected_context,
            )
        except ci.ToolAuthorityUnavailable as exc:
            self.fail(f"fixture unexpectedly rediscovered tool authority: {exc}")

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
                        source = next(
                            record
                            for record in commands["records"]
                            if record["commandId"] == self.observation_for_entry(entry)["commandId"]
                        )
                        source["producerObservations"][0]["commandId"] = forged_value
                        source["producerObservationSetDigest"] = (
                            ci.producer_observation_set_digest(
                                source["producerObservations"]
                            )
                        )

                self.rewrite_coherently(output, mutate)
                errors = self.verify_fixture(output, repo)
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
                errors = self.verify_fixture(output, repo)
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
                        raw = copy.deepcopy(
                            self.observation_for_entry(entry)["rawObservation"]
                        )
                        raw["observationOrdinal"] = len(
                            source["producerObservations"]
                        )
                        source["producerObservations"].append(raw)
                        source["producerObservationSetDigest"] = (
                            ci.producer_observation_set_digest(
                                source["producerObservations"]
                            )
                        )

                self.rewrite_coherently(output, mutate)
                errors = self.verify_fixture(output, repo)
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
                source = next(
                    record
                    for record in commands["records"]
                    if record["commandId"] == observation["commandId"]
                )
                duplicate = copy.deepcopy(source)
                duplicate["commandId"] = "node-check:forged-second-source.js"
                duplicate["ordinal"] = len(commands["records"])
                second = copy.deepcopy(duplicate["producerObservations"][0])
                second["commandId"] = duplicate["commandId"]
                duplicate["producerObservations"] = [second]
                duplicate["producerObservationSetDigest"] = (
                    ci.producer_observation_set_digest(
                        duplicate["producerObservations"]
                    )
                )
                commands["records"].append(duplicate)

            self.rewrite_coherently(output, mutate)
            errors = self.verify_fixture(output, repo)
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
                    errors = self.verify_fixture(output, repo)
                    self.assertTrue(errors, case)
                    self.assertTrue(
                        any("command" in error.casefold() or "derived" in error.casefold() for error in errors),
                        (case, errors),
                    )


def _assert_windows_runtime_capture(test: unittest.TestCase, fixture_factory) -> None:
    """Keep these regression subtests in the existing focused CI test inventory."""

    capture = ci.WINDOWS_RUNTIME_CAPTURE
    script = capture.split("$runtimeCapture = @'\n", 1)[1].split("\n'@", 1)[0]
    original_resolver = ci.resolve_trusted_tools

    def execute(fixture):
        def resolve(required, **kwargs):
            return original_resolver(
                required, **kwargs, policy=fixture.policy, repo_root=fixture.workspace
            )

        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, fixture.source, clear=True),
            mock.patch.object(sys, "path", list(sys.path)),
            mock.patch.object(ci, "resolve_trusted_tools", side_effect=resolve),
            contextlib.redirect_stdout(output),
        ):
            try:
                exec(compile(script, "<workflow-runtime-capture>", "exec"), {})
            except SystemExit:
                test.assertEqual(output.getvalue(), "")
                raise
        return ci.strict_json_loads(output.getvalue())

    for scenario in (
        "duplicate-lower-priority-node",
        "higher-priority-workspace-node",
        "higher-priority-unknown-node",
        "higher-priority-npm-shadow",
        "missing-exact-root-npm",
    ):
        with test.subTest(windows_runtime_capture=scenario):
            fixture = fixture_factory("Windows")
            try:
                node = fixture.paths["node"]
                node_root = node.parent
                npm = fixture._write(
                    node_root / "node_modules" / "npm" / "bin" / "npm-cli.js",
                    b"synthetic-npm-entry",
                )
                fixture._write(node_root / "npm.cmd", b"synthetic-npm-launcher")
                fixture.policy = ci.synthetic_tool_authority_policy(
                    "Windows",
                    running_python=fixture.paths["python"],
                    role_roots={
                        **dict(fixture.policy.role_roots),
                        "npm": (("github-hosted-node-toolcache", node_root),),
                    },
                    minimal_system_directories=(fixture.paths["system"],),
                )
                secondary = fixture._write(
                    fixture.root / "Program Files" / "nodejs" / "node.exe",
                    b"synthetic-lower-priority-node",
                )
                fixture.source["PATH"] += os.pathsep + str(secondary.parent)

                if scenario == "duplicate-lower-priority-node":
                    if os.name == "nt":
                        shell = shutil.which("pwsh") or shutil.which("powershell")
                        test.assertIsNotNone(shell, "Windows regression requires PowerShell")
                        discovery = subprocess.run(
                            [shell, "-NoProfile", "-NonInteractive", "-Command",
                             "$items = @(Get-Command node.exe -CommandType Application); "
                             "ConvertTo-Json -Compress -InputObject @($items.Source)"],
                            env={**os.environ, "PATH": fixture.source["PATH"]},
                            capture_output=True, text=True, timeout=30, check=True,
                        )
                        # Native discovery reproduces the original array-valued Source.
                        test.assertEqual(
                            ci.strict_json_loads(discovery.stdout), [str(node), str(secondary)]
                        )
                    first = execute(fixture)
                    second = execute(fixture)
                    test.assertEqual(first, second)
                    test.assertEqual(first, {"node": str(node), "npmEntry": str(npm)})
                    test.assertIs(type(first["node"]), str)
                    test.assertEqual(Path(first["npmEntry"]).parents[3], Path(first["node"]).parent)
                    continue

                if scenario == "higher-priority-workspace-node":
                    fixture._write(fixture.workspace / "node.exe", b"workspace-shadow")
                elif scenario == "higher-priority-unknown-node":
                    fixture.source["PATH"] = (
                        str(secondary.parent) + os.pathsep + fixture.source["PATH"]
                    )
                elif scenario == "higher-priority-npm-shadow":
                    fixture._write(fixture.workspace / "npm.cmd", b"npm-shadow")
                    fixture._write(
                        fixture.workspace / "node_modules" / "npm" / "bin" / "npm-cli.js",
                        b"workspace-npm-entry",
                    )
                elif scenario == "missing-exact-root-npm":
                    npm.unlink()
                    fixture._write(
                        secondary.parent / "node_modules" / "npm" / "bin" / "npm-cli.js",
                        b"unrelated-npm-entry",
                    )
                with test.assertRaisesRegex(SystemExit, "rejected by tool authority"):
                    execute(fixture)
            finally:
                fixture.temporary.cleanup()



class WorkflowPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = ci.WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.policy = (ci.REPO_ROOT / "docs" / "CI_POLICY.md").read_text(encoding="utf-8")

    def test_current_workflow_passes_narrow_policy(self) -> None:
        self.assertEqual(ci.check_workflow_text(self.workflow), [])
        exact_node_selector = 'node-version: "24.20.0"'
        selectors = list(re.finditer(re.escape(exact_node_selector), self.workflow))
        self.assertEqual(len(selectors), 6)
        for index, selector in enumerate(selectors):
            with self.subTest(floating_node_selector=index):
                candidate = (
                    self.workflow[:selector.start()]
                    + 'node-version: "24.x"'
                    + self.workflow[selector.end():]
                )
                errors = ci.check_workflow_text(candidate)
                self.assertTrue(any("Node setup is not exact" in error for error in errors), errors)
        _assert_windows_runtime_capture(self, _HostedToolFixture)

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

        violation = {
            "id": "EXECUTION-ARGV-MISMATCH",
            "commandId": "npm-version",
            "detail": source,
            "observation": {"privatePath": "/private/runner/secret", "output": source},
        }
        rendered = ci.missing_derived_violation_diagnostic(violation)
        diagnostic = ci.strict_json_loads(rendered)
        self.assertEqual(set(diagnostic), {"commandId", "violationType", "violationDigest"})
        self.assertEqual(diagnostic["commandId"], "npm-version")
        self.assertEqual(diagnostic["violationType"], "EXECUTION-ARGV-MISMATCH")
        canonical = json.dumps(violation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            diagnostic["violationDigest"],
            "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            rendered,
            ci.missing_derived_violation_diagnostic(dict(reversed(list(violation.items())))),
        )
        self.assertNotEqual(
            diagnostic["violationDigest"],
            ci.strict_json_loads(ci.missing_derived_violation_diagnostic(violation | {"detail": "changed"}))["violationDigest"],
        )
        for hostile_identity in (
            source, "/private/runner/secret", "node-check:/private/runner/secret",
            "npm-version\n" + source, "x" * 100_000, "\ud800", {"output": source}, None,
        ):
            with self.subTest(identityType=type(hostile_identity).__name__):
                projected = ci.missing_derived_violation_diagnostic(
                    violation | {"id": hostile_identity, "commandId": hostile_identity}
                )
                bounded = ci.strict_json_loads(projected)
                self.assertLessEqual(len(projected), 300)
                self.assertEqual(bounded["violationType"], "OTHER")
                if isinstance(hostile_identity, str):
                    self.assertRegex(bounded["commandId"], r"^sha256:[0-9a-f]{64}$")
                else:
                    self.assertIsNone(bounded["commandId"])
                self.assertRegex(bounded["violationDigest"], r"^sha256:[0-9a-f]{64}$")
                for forbidden in (synthetic_token, "/private/", "C:\\private", "\r", "\n"):
                    self.assertNotIn(forbidden, projected)
        for forbidden in (synthetic_token, "/private/", "C:\\private", "output", "\r", "\n"):
            self.assertNotIn(forbidden, rendered)

        aggregate = {"id": "COMMAND-AUTHORITY-MISMATCH", "expectedCommandIds": [source], "observedCommandIds": [source]}
        expected = {field: 0 for field in ci._DIAGNOSTIC_AUTHORITY_FIELDS}
        expected["commandId"] = source
        actual = {field: source for field in expected}
        projected = ci.missing_derived_violation_diagnostic(
            aggregate, command_records=[actual], expected_authority=[expected]
        )
        bounded = ci.strict_json_loads(projected)
        self.assertEqual(len(bounded["authorityFields"]), ci._MAX_DIAGNOSTIC_AUTHORITY_FIELDS)
        self.assertEqual(bounded["authorityFields"][-1], "additional-fields")
        self.assertRegex(bounded["commandId"], r"^sha256:[0-9a-f]{64}$")
        self.assertLessEqual(len(projected), 500)
        self.assertNotIn(synthetic_token, projected)
        self.assertEqual(
            bounded["violationDigest"],
            ci.strict_json_loads(ci.missing_derived_violation_diagnostic(aggregate))["violationDigest"],
        )
        for observed_plan, expected_plan, categories in (
            ([{"commandId": source, source: 1}], [{"commandId": source, source: 0}], ["OTHER"]),
            ([], [{"commandId": source}], ["command-membership"]),
            ([{"commandId": source}], [], ["command-membership"]),
            ([{"commandId": source}], [{"commandId": source}], ["OTHER"]),
        ):
            with self.subTest(categories=categories):
                projected = ci.missing_derived_violation_diagnostic(
                    aggregate, command_records=observed_plan, expected_authority=expected_plan
                )
                self.assertEqual(ci.strict_json_loads(projected)["authorityFields"], categories)
                self.assertNotIn(synthetic_token, projected)

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
        prefix = "summary.json: derived command/baseline violation is missing: "
        diagnostics = [ci.strict_json_loads(error[len(prefix):]) for error in errors if error.startswith(prefix)]
        expected_violation = {
            "id": "REQUIRED-COMMAND-EXECUTION",
            "commandId": record["commandId"],
            "exitCode": None,
        }
        self.assertIn(
            ci.strict_json_loads(ci.missing_derived_violation_diagnostic(expected_violation)),
            diagnostics,
        )

        # Producer and verifier independently retain their local identities;
        # cross-job evidence authority binds their portable execution semantics.
        plan = [synthetic_command_spec(
            "baseline-schema", "baseline-policy", 0,
            targets=[ci._target_authority(ci.REPO_ROOT, "developer/tests/ci/phase1-ci-baseline.json")],
        ), synthetic_command_spec("fixture-boundary", "repository-boundary", 1)]
        for spec in plan:
            spec["profile"] = "policy"
        with tempfile.TemporaryDirectory(prefix="ci-evidence-fresh-identity-") as temp_dir:
            repo = Path(temp_dir)
            with mock.patch.object(ci, "expected_command_authority", return_value=plan):
                output, summary = self.create_valid_evidence(repo)
                self.assertEqual(summary["policyViolations"], [])
                self.assertEqual(ci.verify_evidence_file_set(output, repo_root=repo), [])
                fresh_plan = copy.deepcopy(plan)
                identity = fresh_plan[0]["targets"][0]["fileIdentity"]
                self.assertIsInstance(identity, dict)
                identity["inodeOrFileIndex"] = str(int(identity["inodeOrFileIndex"]) + 1)
                self.assertEqual(
                    ci._portable_command_plan_value(plan),
                    ci._portable_command_plan_value(fresh_plan),
                )
                self.assertEqual(ci.verify_evidence_file_set(
                    output, repo_root=repo, expected_command_plan=fresh_plan
                ), [])
                document = ci.strict_json_load_file(output / "command-results.json")
                records = document["records"]
                raw_violations = ci._command_authority_violations(
                    "policy", records, [], expected_plan=fresh_plan
                )
                self.assertEqual([v["id"] for v in raw_violations], ["COMMAND-AUTHORITY-MISMATCH"])
                diagnostic = ci.strict_json_loads(ci.missing_derived_violation_diagnostic(
                    raw_violations[0], command_records=records, expected_authority=fresh_plan
                ))
                self.assertEqual(diagnostic["authorityFields"], ["targets.fileIdentity"])

                executable_plan = copy.deepcopy(plan)
                executable_plan[0]["resolvedExecutableFileIdentity"]["inodeOrFileIndex"] = "fresh-verifier"
                self.assertEqual(ci._portable_command_plan_value(plan), ci._portable_command_plan_value(executable_plan))
                self.assertEqual(ci.verify_evidence_file_set(
                    output, repo_root=repo, expected_command_plan=executable_plan
                ), [])
                # Tool installation paths are explicitly portable too. Actual
                # producer execution argv must still equal its own local plan.
                for field in ("argv", "logicalArgv", "executionArgv"):
                    executable_plan[0][field] = ["/verifier/python", *plan[0][field][1:]]
                executable_plan[0]["resolvedExecutablePath"] = "/verifier/python"
                self.assertEqual(ci.verify_evidence_file_set(
                    output, repo_root=repo, expected_command_plan=executable_plan
                ), [])
                forged_records = copy.deepcopy(records)
                forged_records[0]["actualExecutionArgv"][0] = "/unplanned/python"
                self.assertIn("EXECUTION-ARGV-MISMATCH", [v["id"] for v in ci._command_authority_violations(
                    "policy", forged_records, [], expected_plan=executable_plan, cross_job=True
                )])

                mutations = (
                    ("target-sha256", "targets", "sha256", "0" * 64),
                    ("target-mode", "targets", "modeType", "other"),
                    ("target-path", "targets", "path", "unrelated.json"),
                    ("target-size", "targets", "size", 0),
                    ("target-reparse", "targets", "reparsePoint", True),
                    ("command-id", None, "commandId", "unrelated-command"),
                    ("command-ordinal", None, "ordinal", 7),
                    ("command-class", None, "commandClass", "unrelated-class"),
                    ("command-role", None, "commandRole", "observation-producing"),
                    ("requiredness", None, "required", False),
                    ("allowed-exits", None, "allowedExecutionExits", [0, 1]),
                    ("logical-argv", None, "logicalArgv", [sys.executable, "changed"]),
                    ("execution-argv", None, "executionArgv", [sys.executable, "changed"]),
                    ("input-mode", None, "executionInputMode", "TARGET-BYTES-STDIN"),
                    ("input-size", None, "executionInputSize", 1),
                    ("input-digest", None, "executionInputSha256", "0" * 64),
                    ("tool-role", None, "toolRole", "unrelated-tool"),
                )
                for scenario, nested, field, value in mutations:
                    with self.subTest(cross_job_semantic_mutation=scenario):
                        changed = copy.deepcopy(fresh_plan)
                        destination = changed[0][nested][0] if nested else changed[1]
                        destination[field] = value
                        errors = ci.verify_evidence_file_set(
                            output, repo_root=repo, expected_command_plan=changed
                        )
                        diagnostics = [ci.strict_json_loads(error[len(prefix):]) for error in errors if error.startswith(prefix)]
                        mismatch = next(d for d in diagnostics if d["violationType"] == "COMMAND-AUTHORITY-MISMATCH")
                        expected_fields = (
                            ["argv", "executionArgv", "logicalArgv", "additional-fields"]
                            if field == "toolRole" else [nested or field]
                        )
                        self.assertEqual(mismatch["authorityFields"], expected_fields)

                for scenario in ("order", "missing-command", "extra-command"):
                    with self.subTest(cross_job_semantic_mutation=scenario):
                        changed = copy.deepcopy(fresh_plan)
                        if scenario == "order":
                            changed.reverse()
                        elif scenario == "missing-command":
                            changed.pop()
                        else:
                            extra = copy.deepcopy(changed[-1])
                            extra.update(commandId="extra-command", ordinal=len(changed))
                            changed.append(extra)
                        self.assertIn("COMMAND-AUTHORITY-MISMATCH", [v["id"] for v in ci._command_authority_violations(
                            "policy", records, [], expected_plan=changed, cross_job=True
                        )])

                # Literal Git mode, where present in authority (such as static
                # target inventory), must survive the existing projection.
                git_plan = copy.deepcopy(plan)
                git_records = copy.deepcopy(records)
                git_plan[0]["targets"][0]["gitMode"] = "100644"
                git_records[0]["targets"][0]["gitMode"] = "100644"
                self.assertEqual(ci._command_authority_violations(
                    "policy", git_records, [], expected_plan=git_plan, cross_job=True
                ), [])
                git_plan[0]["targets"][0]["gitMode"] = "100755"
                self.assertIn("COMMAND-AUTHORITY-MISMATCH", [v["id"] for v in ci._command_authority_violations(
                    "policy", git_records, [], expected_plan=git_plan, cross_job=True
                )])

                # A coherent raw producer transcript cannot authorize a forged
                # artifact plan, even if it has a self-consistent portable form.
                for field, value in (("required", False), ("resolvedExecutableFileIdentity", {"inodeOrFileIndex": "forged"})):
                    with self.subTest(artifact_command_authority=field):
                        forged = copy.deepcopy(document)
                        forged["commandAuthority"][0][field] = value
                        self.assertEqual(forged["records"], records)
                        self.rewrite_manifested_json(output, "command-results.json", forged)
                        errors = ci.verify_evidence_file_set(
                            output, repo_root=repo, expected_command_plan=fresh_plan
                        )
                        self.assertEqual(errors, ["command-results.json: command authority does not match the immutable profile plan"])

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
                self.assertTrue(
                    any("DuplicateJsonKeyError" in error for error in errors),
                    errors,
                )

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
                self.assertTrue(
                    any("DuplicateJsonKeyError" in error for error in errors),
                    errors,
                )

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
            workspace = Path(temp_dir).resolve(strict=True)
            repo = workspace / "checkout"
            repo.mkdir()
            producer_output = repo / ".ci-results"
            baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
            with mock.patch.object(ci, "REPO_ROOT", repo):
                runner = fake_runner(baseline)
                ci.create_fresh_evidence_root(producer_output, repo_root=repo)
                with mock.patch.object(ci, "OUTPUT_DIR", producer_output):
                    ci.write_evidence(runner, empty_comparison())
                external_output = workspace / "runner temp" / "ci-untrusted" / "repository-policy"
                shutil.copytree(producer_output, external_output)
                for output in (producer_output, external_output):
                    with self.subTest(evidence_root=output.relative_to(workspace).as_posix()):
                        arguments = [
                            "--verify-evidence",
                            "--expected-profile",
                            "policy",
                            "--expected-invocation-id",
                            runner.execution_binding["producerInvocationId"],
                        ]
                        if output == external_output:
                            self.assertTrue(output.is_absolute())
                            self.assertFalse(_path_is_relative_to(output, repo))
                            arguments.extend(["--untrusted-evidence-root", str(output)])
                        before = {
                            name: (
                                hashlib.sha256((output / name).read_bytes()).hexdigest(),
                                (output / name).stat().st_mtime_ns,
                            )
                            for name in ci.EVIDENCE_FILE_NAMES
                        }
                        context = synthetic_external_context(runner.execution_binding)
                        verification_runner = mock.Mock()
                        with mock.patch.object(ci, "OUTPUT_DIR", producer_output), mock.patch.object(
                            ci,
                            "prepare_verification_authority",
                            return_value=(context, verification_runner),
                        ), mock.patch.object(
                            ci,
                            "capture_live_external_authority",
                            return_value=_explicit_live_local_external_authority(),
                        ), mock.patch.object(
                            ci,
                            "verify_evidence_with_replay",
                            return_value=([], {"kind": "VerificationReplayTranscript"}),
                        ) as replay:
                            exit_code = ci.main(arguments)
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
                            evidence_authority_root=output.parent,
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
        with tempfile.TemporaryDirectory(prefix="ci-external-evidence-bounds-") as temp_dir:
            workspace = Path(temp_dir).resolve(strict=True)
            checkout = workspace / "checkout"
            parent = workspace / "runner temp" / "ci-untrusted"
            checkout.mkdir()
            parent.mkdir(parents=True)
            source, _summary = self.create_valid_evidence(checkout)
            output = parent / "repository-policy"
            shutil.copytree(source, output)
            self.assertTrue(output.is_absolute())
            self.assertFalse(_path_is_relative_to(output, checkout))
            self.assertEqual(ci.validate_evidence_root(output, repo_root=parent), [])
            self.assertEqual(ci.verify_evidence_file_set(output, repo_root=parent), [])
            for wrong_parent in (checkout, parent.parent, output):
                with self.subTest(external_evidence_wrong_parent=wrong_parent.name):
                    errors = ci.validate_evidence_root(output, repo_root=wrong_parent)
                    self.assertTrue(any("parent resolves outside" in error for error in errors), errors)
                    self.assertTrue(ci.verify_evidence_file_set(output, repo_root=wrong_parent))
            sibling_parent = parent.with_name(parent.name + "-other")
            sibling_output = sibling_parent / output.name
            nested_output = parent / "nested" / output.name
            sibling_output.mkdir(parents=True)
            nested_output.mkdir(parents=True)
            for wrong_root in (sibling_output, nested_output, parent / ".." / sibling_parent.name / output.name):
                with self.subTest(external_evidence_wrong_root=str(wrong_root.relative_to(workspace))):
                    self.assertTrue(ci.validate_evidence_root(wrong_root, repo_root=parent))
            with mock.patch.object(ci, "_is_reparse_point", return_value=True):
                self.assertTrue(ci.validate_evidence_root(output, repo_root=parent))
            root_resolve = Path.resolve

            def redirected_root(path, *args, **kwargs):
                if path == output:
                    return sibling_output
                return root_resolve(path, *args, **kwargs)

            with mock.patch.object(Path, "resolve", redirected_root):
                errors = ci.validate_evidence_root(output, repo_root=parent)
                self.assertTrue(any("outside its exact workspace path" in error for error in errors), errors)
            leaf = output / "summary.json"
            snapshot, errors = ci._read_evidence_file_snapshot(
                leaf, output_dir=output, byte_limit=ci.EVIDENCE_FILE_BYTE_LIMITS[leaf.name]
            )
            self.assertEqual(errors, [])
            self.assertIsNotNone(snapshot)
            for escaped_leaf in (source / leaf.name, sibling_output / leaf.name, output / "nested" / leaf.name):
                if not escaped_leaf.exists():
                    escaped_leaf.parent.mkdir(parents=True, exist_ok=True)
                    escaped_leaf.write_bytes(leaf.read_bytes())
                with self.subTest(external_evidence_escaped_leaf=str(escaped_leaf.relative_to(workspace))):
                    snapshot, errors = ci._read_evidence_file_snapshot(
                        escaped_leaf, output_dir=output, byte_limit=ci.EVIDENCE_FILE_BYTE_LIMITS[leaf.name]
                    )
                    self.assertIsNone(snapshot)
                    self.assertIn("evidence parent resolution escaped", errors)

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
            self.assertEqual(len(command_results["records"]), 1)
            self.assertEqual(
                command_results["records"][0]["commandId"],
                "command-results-size-limit",
            )
            self.assertTrue(
                any(
                    item.get("id") == "COMMAND-RESULT-JSON-LIMIT"
                    for item in summary["policyViolations"]
                )
            )
            violation = next(
                item
                for item in summary["policyViolations"]
                if item.get("id") == "COMMAND-RESULT-JSON-LIMIT"
            )
            detail = violation["detail"]
            self.assertIn("total_bytes=", detail)
            self.assertIn("limit_bytes=256", detail)
            self.assertIn("approx_contributions=", detail)
            self.assertLessEqual(len(detail.encode("utf-8")), 512)
            self.assertNotIn(str(repo), detail)
            self.assertIn(
                "approx_contributions=",
                command_results["records"][0]["parsedFailureSummary"][
                    "diagnostic"
                ],
            )

    def test_full_scale_command_results_retain_705_records_under_fixed_limit(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        candidate_paths, path_errors = ci.deterministic_candidate_paths(ci.REPO_ROOT)
        self.assertEqual(path_errors, [])
        tools = {
            role: str(Path(sys.executable).resolve(strict=True))
            for role in ci.required_tool_names("all")
        }
        tools["node"] = _explicit_local_test_tool_map("node")["node"]
        self.assertNotEqual(
            Path(tools["node"]).resolve(strict=True),
            Path(sys.executable).resolve(strict=True),
        )
        plan = ci.build_profile_command_plan(
            "all",
            tools=tools,
            candidate_paths=candidate_paths,
            baseline=baseline,
            current_platform="ubuntu",
            static_invocation_id=ci.deterministic_static_invocation_id(ci.REPO_ROOT),
            repo_root=ci.REPO_ROOT,
        )
        command_classes = sorted({spec["commandClass"] for spec in plan})
        target_universe = {
            target["path"] for spec in plan for target in spec["targets"]
        }
        target_reference_count = sum(len(spec["targets"]) for spec in plan)
        self.assertEqual(len(plan), 705)
        self.assertEqual(len(command_classes), 16)
        # Four governance files add four targets and 86 plan references.
        self.assertEqual(len(target_universe), 908)
        self.assertEqual(target_reference_count, 19811)
        self.assertNotIn(
            "node-vitest-security-test",
            {spec["toolRole"] for spec in plan},
        )
        message_origin_commands = [
            spec
            for spec in plan
            if spec["commandId"]
            == "frontend-security:messageOriginGuard.test.js"
        ]
        self.assertEqual(len(message_origin_commands), 1)
        message_origin_command = message_origin_commands[0]
        trusted_node = tools["node"]
        expected_message_origin_argv = [
            trusted_node,
            "--test",
            ci.MESSAGE_ORIGIN_SECURITY_GUARD,
        ]
        self.assertEqual(message_origin_command["ordinal"], 700)
        self.assertEqual(message_origin_command["commandClass"], "frontend-security")
        self.assertEqual(message_origin_command["commandRole"], "observation-producing")
        self.assertTrue(message_origin_command["required"])
        self.assertEqual(message_origin_command["cwd"], ".")
        self.assertEqual(
            message_origin_command["toolRole"], "node-builtin-security-test"
        )
        self.assertNotIn(
            message_origin_command["toolRole"], ci.DEPENDENCY_BACKED_TOOL_ROLES
        )
        for argv_field in ("argv", "logicalArgv", "executionArgv"):
            self.assertEqual(
                message_origin_command[argv_field],
                expected_message_origin_argv,
            )
        self.assertEqual(
            message_origin_command["executionInputMode"],
            "PROTECTED-TARGET-BUNDLE",
        )
        self.assertEqual(message_origin_command["allowedExecutionExits"], [0, 1])
        self.assertEqual(
            message_origin_command["resultSemantics"],
            "exit-zero-pass-exit-one-classified-observation",
        )
        message_origin_targets = [
            target["path"] for target in message_origin_command["targets"]
        ]
        self.assertEqual(message_origin_targets, candidate_paths)
        self.assertIn(ci.MESSAGE_ORIGIN_SECURITY_GUARD, message_origin_targets)
        self.assertIn("developer/package.json", message_origin_targets)
        self.assertFalse(
            any("node_modules" in Path(target).parts for target in message_origin_targets)
        )
        forbidden_route_tokens = (
            "vitest",
            "node_modules",
            "npm",
            "npx",
            "pnpm",
            "yarn",
            ".bin",
            "cmd.exe",
            "powershell",
        )
        message_origin_route = " ".join(expected_message_origin_argv[1:]).casefold()
        for token in forbidden_route_tokens:
            self.assertNotIn(token, message_origin_route)
        self.assertEqual(plan[699]["commandId"], "frontend-security:vocabSessionExportGuard.test.js")
        self.assertEqual(plan[701]["commandId"], "backend-canonical")
        records = [synthetic_record_from_spec(spec) for spec in plan]
        backend_command = plan[701]
        self.assertEqual(backend_command["commandClass"], "backend-canonical")
        self.assertEqual(backend_command["profile"], "all")
        self.assertEqual(backend_command["platform"], "ubuntu")
        self.assertEqual(backend_command["commandRole"], "required-execution")
        self.assertEqual(backend_command["allowedExecutionExits"], [0])
        self.assertEqual(backend_command["toolRole"], "npm-backend-test")
        self.assertEqual(
            ci._source_observation_kinds(backend_command),
            frozenset({"process-output-v1"}),
        )

        backend_record = copy.deepcopy(records[backend_command["ordinal"]])
        backend_scope = "command:npm --prefix backend test"
        backend_raw_fields = {
            "executed": True,
            "exitCode": 0,
            "stdout": "backend canonical observation passed",
            "stderr": "",
            "error": None,
        }
        backend_raw = ci.make_raw_observation(
            backend_command["commandId"],
            backend_command["ordinal"],
            0,
            "process-output-v1",
            backend_scope,
            "backend/package.json",
            backend_raw_fields,
            ci.command_output_digest(backend_record),
        )
        backend_record["producerObservations"] = [backend_raw]
        backend_record["producerObservationSetDigest"] = (
            ci.producer_observation_set_digest([backend_raw])
        )
        backend_runner = SimpleNamespace(
            command_plan=[backend_command],
            command_results=[backend_record],
            observations=[
                {
                    "commandId": backend_command["commandId"],
                    "rawObservation": backend_raw,
                }
            ],
            completed_classes=set(),
        )
        ci.finalize_evidence_transcript(backend_runner)
        backend_baseline = copy.deepcopy(baseline)
        backend_baseline["knownDebts"] = []
        backend_baseline["expectedOmissions"] = []
        backend_baseline["releaseOnlySkips"] = []

        def backend_result(
            *,
            record_change=None,
            raw_change=None,
            expected_plan=None,
            duplicate_record: bool = False,
        ):
            selected_record = copy.deepcopy(backend_runner.command_results[0])
            selected_observation = copy.deepcopy(backend_runner.observations[0])
            selected_raw = copy.deepcopy(selected_observation["rawObservation"])
            if record_change is not None:
                record_change(selected_record)
            if raw_change is not None:
                raw_change(selected_raw)
                selected_raw["producerRecordDigest"] = ci._producer_record_digest(
                    {
                        key: value
                        for key, value in selected_raw.items()
                        if key != "producerRecordDigest"
                    }
                )
            selected_record["producerObservations"] = [selected_raw]
            selected_record["producerObservationSetDigest"] = (
                ci.producer_observation_set_digest([selected_raw])
            )
            selected_observation["rawObservation"] = selected_raw
            selected_records = [selected_record]
            if duplicate_record:
                selected_records.append(copy.deepcopy(selected_record))
            return ci.derive_authoritative_evidence(
                "all",
                [selected_observation],
                backend_runner.completed_classes,
                selected_records,
                backend_baseline,
                "ubuntu",
                [copy.deepcopy(expected_plan or backend_command)],
                release_gate_required=False,
            )

        legitimate_backend = backend_result()
        self.assertEqual(legitimate_backend["violations"], [])
        self.assertEqual(
            backend_runner.observations[0]["rawObservation"]["rawStructuredFields"],
            backend_raw_fields,
        )

        plan_role_forgery = backend_result(
            record_change=lambda record: record.__setitem__(
                "commandRole", "observation-producing"
            )
        )
        self.assertIn(
            "COMMAND-AUTHORITY-MISMATCH",
            {item["id"] for item in plan_role_forgery["violations"]},
        )

        raw_role_cases = {
            "forged-observation-role": "normalized-fields-v1",
            "cross-domain-command-role": backend_command["commandRole"],
            "unknown-observation-role": "unknown-observation-role",
            "malformed-observation-role": 7,
        }
        for name, value in raw_role_cases.items():
            with self.subTest(r05=name):
                result = backend_result(
                    raw_change=lambda raw, selected=value: raw.__setitem__(
                        "observationKind", selected
                    )
                )
                self.assertTrue(result["violations"], name)
                details = " ".join(
                    str(item.get("detail", "")) for item in result["violations"]
                )
                self.assertIn("observation", details.casefold())

        missing_role = backend_result(
            raw_change=lambda raw: raw.pop("observationKind")
        )
        self.assertTrue(missing_role["violations"])
        swapped_roles = backend_result(
            record_change=lambda record: record.__setitem__(
                "commandRole", "process-output-v1"
            ),
            raw_change=lambda raw: raw.__setitem__(
                "observationKind", "required-execution"
            ),
        )
        self.assertTrue(swapped_roles["violations"])

        binding_cases = {
            "wrong-command-id": (
                None,
                lambda raw: raw.__setitem__("commandId", "static-suite"),
            ),
            "wrong-target": (
                lambda record: record["targets"][0].__setitem__("sha256", "0" * 64),
                None,
            ),
            "wrong-command-class": (
                lambda record: record.__setitem__("commandClass", "frontend-security"),
                None,
            ),
            "wrong-profile": (
                lambda record: record.__setitem__("profile", "backend"),
                None,
            ),
        }
        for name, (record_change, raw_change) in binding_cases.items():
            with self.subTest(r05=name):
                result = backend_result(
                    record_change=record_change,
                    raw_change=raw_change,
                )
                self.assertTrue(result["violations"], name)
        duplicate_backend = backend_result(duplicate_record=True)
        self.assertTrue(duplicate_backend["violations"])
        wrong_plan = copy.deepcopy(backend_command)
        wrong_plan["profile"] = "backend"
        wrong_plan_instance = backend_result(expected_plan=wrong_plan)
        self.assertTrue(wrong_plan_instance["violations"])

        windows_backend = copy.deepcopy(backend_command)
        windows_backend["platform"] = "windows"
        windows_backend["commandRole"] = "observation-producing"
        windows_backend["allowedExecutionExits"] = [0, 1]
        self.assertEqual(
            ci._source_observation_kinds(windows_backend),
            frozenset({"process-output-v1"}),
        )
        self.assertEqual(
            ci._source_observation_kinds(message_origin_command),
            frozenset({"process-output-v1"}),
        )
        self.assertEqual(
            ci._source_observation_kinds(
                next(item for item in plan if item["commandId"] == "static-suite")
            ),
            frozenset({"static-producer-v1"}),
        )
        self.assertEqual(ci._source_observation_kinds(plan[0]), frozenset())

        message_origin_template = records[message_origin_command["ordinal"]]
        message_origin_stdout = (
            "TAP version 13\n"
            "# Subtest: postMessage origin guard tests pass\n"
            "ok 1 - postMessage origin guard tests pass\n"
            "1..1\n"
        )
        message_origin_stdout_raw = message_origin_stdout.encode("utf-8")
        message_origin_capture = ci.CommandCapture(
            command_id=message_origin_command["commandId"],
            command_class=message_origin_command["commandClass"],
            argv=list(expected_message_origin_argv),
            executed=True,
            exit_code=0,
            duration_seconds=0.01,
            stdout=message_origin_stdout,
            stderr="",
            required=True,
            cwd=".",
            stdout_raw=message_origin_stdout_raw,
            stderr_raw=b"",
            stdout_byte_limit=ci.MAX_STATIC_MACHINE_STDOUT_BYTES,
            stderr_byte_limit=ci.MAX_STATIC_MACHINE_STDERR_BYTES,
            stdout_bytes=len(message_origin_stdout_raw),
            stderr_bytes=0,
            include_preview=False,
            containment=(
                "windows-job-object"
                if os.name == "nt"
                else "linux-subreaper-pidfd-proc-supervisor"
            ),
            process_tree_status="contained-clean",
            containment_disposition="no-descendants",
            logical_argv=list(expected_message_origin_argv),
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        message_origin_binder = object.__new__(ci.FoundationRunner)
        message_origin_binder.command_plan_by_id = {
            message_origin_command["commandId"]: message_origin_command
        }
        message_origin_record = ci.FoundationRunner._bind_command_record(
            message_origin_binder,
            message_origin_capture.evidence(),
            actual_argv=expected_message_origin_argv,
        )
        for field_name in (
            "executionInputs",
            "executionInputBundleDigest",
            "protectedTargetBundle",
        ):
            message_origin_record[field_name] = copy.deepcopy(
                message_origin_template[field_name]
            )
        records[message_origin_command["ordinal"]] = message_origin_record
        message_origin_binder.command_results = [message_origin_record]
        message_origin_binder.observations = []
        message_origin_binder.add_process_observation(
            message_origin_record,
            message_origin_capture,
            source_result_id=f"file:{ci.MESSAGE_ORIGIN_SECURITY_GUARD}",
            source_path=ci.MESSAGE_ORIGIN_SECURITY_GUARD,
        )
        message_origin_observation = message_origin_binder.observations[0]
        observations: list[dict] = []
        closure_guard = {
            "guardSchemaVersion": ci.RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
            "watcherBackend": "live-shaped-fixture",
            "active": True,
            "activeDuringReplay": True,
            "mutationState": "clean",
            "queueOverflow": False,
            "mutationEventCount": 0,
        }
        for spec, record in zip(plan, records):
            if spec["commandId"] == "tracked-secret-scan":
                record["fileScans"] = [
                    {
                        "path": target["path"],
                        "fileSize": int(target["size"] or 0),
                        "classification": "text-scanned",
                        "scannedBytes": int(target["size"] or 0),
                        "rawBytesScanned": int(target["size"] or 0),
                        "encodingViewsApplied": [
                            "raw-bytes",
                            *ci.UTF16_ASCII_CREDENTIAL_VIEWS,
                        ],
                        "utf16LeDecodedUnits": 0,
                        "utf16BeDecodedUnits": 0,
                        "patternFamiliesApplied": list(
                            ci.SECRET_SCAN_PATTERN_FAMILIES
                        ),
                        "hitCount": 0,
                    }
                    for target in spec["targets"]
                ]
            if spec["toolRole"] in ci.DEPENDENCY_BACKED_TOOL_ROLES:
                record.update(
                    {
                        "dependencyBacked": True,
                        "runtimeClosureDigest": "4" * 64,
                        "dependencyClosureDigest": "5" * 64,
                        "nodePath": [],
                        "resolvedTestRunnerEntrypoint": record[
                            "resolvedExecutablePath"
                        ],
                        "resolvedTestRunnerSha256": record[
                            "resolvedExecutableSha256"
                        ],
                        "closureWatcherActive": True,
                        "closureMutationState": "clean",
                        "runtimeClosureGuard": copy.deepcopy(closure_guard),
                    }
                )
            elif (
                spec["commandId"]
                == "frontend-security:messageOriginGuard.test.js"
            ):
                record["dependencyBacked"] = False
            observation_kinds = ci._source_observation_kinds(spec)
            self.assertLessEqual(len(observation_kinds), 1)
            if observation_kinds and record is not message_origin_record:
                record["diagnosticPreview"] = "live-shaped bounded diagnostic" * 8
            if not observation_kinds:
                continue
            if record is message_origin_record:
                observations.append(copy.deepcopy(message_origin_observation))
                continue
            observation_kind = next(iter(observation_kinds))
            if observation_kind == "static-producer-v1":
                result_name = "live-shaped-static-suite"
                source_result_id = result_name
                source_path = ci.STATIC_SUITE_RELATIVE_PATH
                raw_fields = {
                    "name": result_name,
                    "status": "pass",
                    "detail": {"fixture": "live-shaped"},
                }
            elif observation_kind == "process-output-v1":
                if spec["commandClass"] == "direct-syntax":
                    source_result_id = spec["commandId"].removeprefix("node-check:")
                    source_path = source_result_id
                elif spec["commandClass"] == "learner-focused":
                    source_result_id = "command:learner-focused-runtime"
                    source_path = "developer/tests/js/learnerPalette.test.js"
                elif spec["commandClass"] == "frontend-security":
                    source_path = next(
                        relative
                        for relative in (
                            *ci.SECURITY_GUARD_FILES,
                            ci.MESSAGE_ORIGIN_SECURITY_GUARD,
                        )
                        if Path(relative).name
                        == spec["commandId"].removeprefix("frontend-security:")
                    )
                    source_result_id = f"file:{source_path}"
                elif spec["commandClass"] == "backend-canonical":
                    source_result_id = backend_scope
                    source_path = "backend/package.json"
                else:
                    self.fail(
                        f"unexpected process observation class: {spec['commandClass']}"
                    )
                raw_fields = {
                    "executed": True,
                    "exitCode": 0,
                    "stdout": "live-shaped process observation",
                    "stderr": "",
                    "error": None,
                }
            elif observation_kind == "standalone-membership-v1":
                source_path = "js/siteContent.js"
                source_result_id = f"membership:index.html::{source_path}"
                raw_fields = {"relative": source_path, "missing": False}
            else:
                self.fail(f"unexpected observation kind: {observation_kind}")
            raw = ci.make_raw_observation(
                spec["commandId"],
                spec["ordinal"],
                0,
                observation_kind,
                source_result_id,
                source_path,
                raw_fields,
                ci.command_output_digest(record),
            )
            record["producerObservations"].append(raw)
            observations.append(
                {"commandId": spec["commandId"], "rawObservation": raw}
            )
        runner = fake_runner(baseline)
        runner.profile = "all"
        runner.platform = "ubuntu"
        runner.command_plan = plan
        runner.command_results = records
        runner.observations = observations
        runner.completed_classes = set()
        runner.command_plan_digest = ci.command_plan_digest(plan)
        empty_member_digest = hashlib.sha256(
            ci._canonical_frame([])
        ).hexdigest()
        dependency_roots = [
            {
                "logicalRoot": logical_root,
                "memberCount": 0,
                "members": [],
                "memberManifestDigest": empty_member_digest,
            }
            for logical_root in (
                "developer/node_modules",
                "backend/node_modules",
            )
        ]
        dependency_semantic = {
            "lockfiles": runner.runtime_closure_document["lockfiles"],
            "dependencyRoots": dependency_roots,
            "vitest": None,
            "nodePath": [],
        }
        dependency_digest = hashlib.sha256(
            ci._canonical_frame(dependency_semantic)
        ).hexdigest()
        runner.runtime_closure_document.update(
            {
                "profile": "all",
                "runnerOS": "Linux",
                "nodeExecutable": {
                    "role": "node-runtime",
                    "canonicalPath": str(Path(trusted_node).resolve(strict=True)),
                    "size": message_origin_command["resolvedExecutableSize"],
                    "sha256": message_origin_command[
                        "resolvedExecutableSha256"
                    ],
                    "stableIdentity": message_origin_command[
                        "resolvedExecutableFileIdentity"
                    ],
                    "leaseHeld": True,
                },
                "dependencyRoots": dependency_roots,
                "vitest": None,
                "nodePath": [],
                "dependencyClosureDigest": dependency_digest,
                "dependencyMemberCount": 0,
            }
        )
        runner.runtime_closure_document.pop("closureDigest", None)
        runtime_digest = hashlib.sha256(
            ci._canonical_frame(runner.runtime_closure_document)
        ).hexdigest()
        runner.runtime_closure_document["closureDigest"] = runtime_digest
        runner.runtime.update(
            {
                "platform": "ubuntu",
                "os": "synthetic-github-hosted-linux",
                "runtimeClosureDigest": runtime_digest,
                "dependencyClosureDigest": dependency_digest,
                "dependencyMemberCount": "0",
            }
        )
        for record in records:
            if record.get("dependencyBacked") is True:
                record["runtimeClosureDigest"] = runtime_digest
                record["dependencyClosureDigest"] = dependency_digest
        runner.execution_binding = synthetic_execution_binding(
            "all",
            runner.command_plan_digest,
            platform_name="ubuntu",
        )
        with tempfile.TemporaryDirectory(prefix="ci-scale-evidence-") as temp_dir:
            repo = Path(temp_dir)
            output = repo / ".ci-results"
            ci.create_fresh_evidence_root(output, repo_root=repo)
            independent_results: list[list[str]] = []
            independent_verify = ci.verify_evidence_file_set

            def tracked_independent_verify(*args, **kwargs):
                result = independent_verify(*args, **kwargs)
                independent_results.append(result)
                return result

            with mock.patch.object(
                ci,
                "verify_evidence_file_set",
                side_effect=tracked_independent_verify,
            ):
                ci.write_evidence(
                    runner,
                    empty_comparison(),
                    output_dir=output,
                    evidence_authority_root=repo,
                )
            self.assertEqual(independent_results, [[]])
            data = (output / "command-results.json").read_bytes()
            self.assertLess(len(data), ci.MAX_COMMAND_RESULTS_JSON_BYTES)
            document = ci.strict_json_loads(data)
            if document["records"][0]["commandId"] == "command-results-size-limit":
                self.fail(
                    next(
                        item["detail"]
                        for item in ci.strict_json_load_file(
                            output / "summary.json"
                        )["policyViolations"]
                        if item.get("id") == "COMMAND-RESULT-JSON-LIMIT"
                    )
                )
            self.assertEqual(
                [record["commandId"] for record in document["records"]],
                [spec["commandId"] for spec in plan],
            )
            self.assertIsNone(document["runtimeDependencyClosure"]["vitest"])
            self.assertEqual(len(document["records"]), 705)
            persisted_message_origin = next(
                record
                for record in document["records"]
                if record["commandId"]
                == "frontend-security:messageOriginGuard.test.js"
            )
            self.assertEqual(
                persisted_message_origin["actualExecutionArgv"],
                expected_message_origin_argv,
            )
            self.assertEqual(
                persisted_message_origin["resolvedExecutablePath"],
                str(Path(trusted_node).resolve(strict=True)),
            )
            self.assertEqual(
                persisted_message_origin["executable"], Path(trusted_node).name
            )
            self.assertNotEqual(persisted_message_origin["executable"], "internal")
            for field_name in (
                "resolvedExecutableSize",
                "resolvedExecutableSha256",
                "resolvedExecutableFileIdentity",
            ):
                self.assertEqual(
                    persisted_message_origin[field_name],
                    message_origin_command[field_name],
                )
            self.assertEqual(
                persisted_message_origin["containment"],
                (
                    "windows-job-object"
                    if os.name == "nt"
                    else "linux-subreaper-pidfd-proc-supervisor"
                ),
            )
            self.assertEqual(
                persisted_message_origin["processTreeStatus"], "contained-clean"
            )
            self.assertEqual(
                persisted_message_origin["containmentDisposition"], "no-descendants"
            )
            self.assertEqual(
                persisted_message_origin["stdoutBytesObserved"],
                len(message_origin_stdout_raw),
            )
            self.assertIs(persisted_message_origin["dependencyBacked"], False)
            for field_name in (
                "runtimeClosureDigest",
                "dependencyClosureDigest",
                "nodePath",
                "resolvedTestRunnerEntrypoint",
                "resolvedTestRunnerSha256",
                "closureWatcherActive",
                "closureMutationState",
                "runtimeClosureGuard",
            ):
                self.assertNotIn(field_name, persisted_message_origin)
            self.assertEqual(
                len(persisted_message_origin["producerObservations"]), 1
            )
            self.assertEqual(
                persisted_message_origin["producerObservations"][0]["commandId"],
                persisted_message_origin["commandId"],
            )
            persisted_message_origin_observation = (
                persisted_message_origin["producerObservations"][0]
            )
            self.assertEqual(
                persisted_message_origin_observation["observationKind"],
                "process-output-v1",
            )
            self.assertEqual(
                persisted_message_origin_observation["sourceResultId"],
                f"file:{ci.MESSAGE_ORIGIN_SECURITY_GUARD}",
            )
            self.assertEqual(
                persisted_message_origin_observation["sourcePath"],
                ci.MESSAGE_ORIGIN_SECURITY_GUARD,
            )
            self.assertEqual(
                persisted_message_origin_observation["sourceOutputDigest"],
                ci.command_output_digest(persisted_message_origin),
            )
            self.assertEqual(
                persisted_message_origin_observation["rawStructuredFields"],
                {
                    "executed": True,
                    "exitCode": 0,
                    "stdout": message_origin_stdout.rstrip("\n"),
                    "stderr": "",
                    "error": None,
                },
            )
            record_errors: list[str] = []
            self.assertFalse(
                ci._validate_command_record(
                    persisted_message_origin,
                    message_origin_command["ordinal"],
                    record_errors,
                    expected_record=message_origin_command,
                ),
                record_errors,
            )
            self.assertEqual(record_errors, [])
            self.assertEqual(
                document["completedCommandClasses"], sorted(command_classes)
            )
            self.assertEqual(
                document["commandAuthority"], ci._portable_command_plan_value(plan)
            )
            self.assertEqual(document["missingCommandIds"], [])
            self.assertEqual(document["extraCommandIds"], [])
            self.assertEqual(document["duplicateCommandIds"], [])
            self.assertNotIn(
                "command-results-size-limit",
                {record["commandId"] for record in document["records"]},
            )
            self.assertGreaterEqual(document["producerObservationCount"], 670)
            protected_records = [
                record
                for record in document["records"]
                if record["executionInputMode"] == "PROTECTED-TARGET-BUNDLE"
            ]
            self.assertTrue(protected_records)
            for record in protected_records:
                expected_target_count = len(record["targets"])
                self.assertEqual(len(record["targets"]), expected_target_count)
                self.assertEqual(record["executionInputs"], [])
                reconstructed_inputs = (
                    ci._reconstructed_protected_execution_inputs(record)
                )
                self.assertEqual(len(reconstructed_inputs), expected_target_count)
                self.assertEqual(
                    record["executionInputBundleDigest"],
                    ci.execution_input_bundle_digest(reconstructed_inputs),
                )
                bundle = record["protectedTargetBundle"]
                for key in ci._PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS:
                    self.assertEqual(bundle[key], [])
                self.assertEqual(record["executionInputs"], [])
                reconstructed_inputs = (
                    ci._reconstructed_protected_execution_inputs(record)
                )
                self.assertEqual(
                    record["executionInputBundleDigest"],
                    ci.execution_input_bundle_digest(reconstructed_inputs),
                )
                self.assertEqual(
                    len(bundle["preExecutionIdentities"]),
                    expected_target_count,
                )
            field_units: collections.Counter[str] = collections.Counter()
            largest_record = max(
                (
                    len(ci._json_bytes(record)),
                    record["commandId"],
                    record["commandClass"],
                )
                for record in document["records"]
            )
            for record in document["records"]:
                for key, value in record.items():
                    field_units[key] += ci._bounded_json_contribution_units(value)
            largest_field, largest_field_units = field_units.most_common(1)[0]
            print(
                "LIVE_SHAPED_COMMAND_RESULTS "
                f"BYTES={len(data)} "
                f"HEADROOM={ci.MAX_COMMAND_RESULTS_JSON_BYTES - len(data)} "
                f"RECORDS={len(document['records'])} "
                f"CLASSES={len(document['completedCommandClasses'])} "
                f"TARGETS={len(target_universe)} "
                f"TARGET_REFERENCES={target_reference_count} "
                f"LARGEST_RECORD_BYTES={largest_record[0]} "
                f"LARGEST_RECORD_ID={largest_record[1]} "
                f"LARGEST_FIELD={largest_field} "
                f"LARGEST_FIELD_UNITS={largest_field_units}"
            )


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
                trusted_tools = _explicit_local_test_tool_map(
                    *sorted(ci.required_tool_names("static"))
                )
                runner = ci.FoundationRunner(
                    "static",
                    copy.deepcopy(self.baseline),
                    tools=trusted_tools,
                    source_environment=os.environ,
                )
                self.addCleanup(runner.cleanup_task_resources)
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


class _HostedToolFixture:
    """Inspected, non-executed hosted-runner filesystem model under task temp."""

    def __init__(self, platform_name: str) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=f"ci-hosted-{platform_name.casefold()}-"
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.platform_name = platform_name
        self.runner_temp = self.root / "runner-temp"
        self.workspace = self.root / "workspace" / "IELTS-Project"
        self.runner_temp.mkdir(parents=True)
        self.workspace.mkdir(parents=True)
        toolcache = self.root / "hostedtoolcache"

        if platform_name == "Windows":
            python_dir = toolcache / "windows" / "Python" / "3.12.13" / "x64"
            node_dir = toolcache / "windows" / "node" / "24.18.0" / "x64"
            git_root = self.root / "Program Files" / "Git"
            system_root = self.root / "Windows"
            system_bin = system_root / "System32"
            powershell_dir = system_bin / "WindowsPowerShell" / "v1.0"
            python = self._write(python_dir / "python.exe", b"synthetic-python")
            node = self._write(node_dir / "node.exe", b"synthetic-node")
            git = self._write(git_root / "cmd" / "git.exe", b"synthetic-git")
            bash = self._write(git_root / "bin" / "bash.exe", b"synthetic-bash")
            powershell = self._write(
                powershell_dir / "powershell.exe", b"synthetic-powershell"
            )
            system_bin.mkdir(parents=True, exist_ok=True)
            path_entries = [
                self.runner_temp,
                self.workspace,
                python_dir,
                node_dir,
                git_root / "cmd",
                git_root / "bin",
                powershell_dir,
                system_bin,
            ]
            role_roots = {
                "python": (("github-hosted-python-toolcache", python_dir),),
                "node": (("github-hosted-node-toolcache", node_dir),),
                "git": (("program-files-git", git_root),),
                "bash": (("program-files-git-bash", git_root),),
                "powershell": (("windows-system-powershell", system_bin / "WindowsPowerShell"),),
            }
            extra_source = {
                "SystemRoot": str(system_root),
                "WINDIR": str(system_root),
                "ProgramFiles": str(self.root / "Program Files"),
            }
        else:
            python_dir = toolcache / "Python" / "3.12.13" / "x64" / "bin"
            node_dir = toolcache / "node" / "24.18.0" / "x64" / "bin"
            system_bin = self.root / "usr" / "bin"
            usr_local = self.root / "usr" / "local" / "bin"
            usr_local.mkdir(parents=True)
            python = self._write(python_dir / "python3.12", b"synthetic-python")
            os.link(python, python_dir / "python")
            os.link(python, python_dir / "python3")
            node = self._write(node_dir / "node", b"synthetic-node")
            git = self._write(system_bin / "git", b"synthetic-git")
            bash = self._write(system_bin / "bash", b"synthetic-bash")
            powershell = self._write(system_bin / "pwsh", b"synthetic-powershell")
            path_entries = [
                self.runner_temp,
                self.workspace,
                usr_local,
                python_dir,
                node_dir,
                system_bin,
            ]
            role_roots = {
                "python": (("github-hosted-python-toolcache", python_dir),),
                "node": (("github-hosted-node-toolcache", node_dir),),
                "git": (("posix-system-git", system_bin),),
                "bash": (("posix-system-bash", system_bin),),
                "powershell": (("posix-system-pwsh", system_bin),),
            }
            extra_source = {}

        self.paths = {
            "python": python.resolve(strict=True),
            "node": node.resolve(strict=True),
            "git": git.resolve(strict=True),
            "bash": bash.resolve(strict=True),
            "powershell": powershell.resolve(strict=True),
            "system": system_bin.resolve(strict=True),
        }
        self.policy = ci.synthetic_tool_authority_policy(
            platform_name,
            running_python=python,
            role_roots=role_roots,
            minimal_system_directories=(system_bin,),
            path_separator=os.pathsep,
        )
        self.source = {
            "PATH": os.pathsep.join(str(path) for path in path_entries),
            "RUNNER_TOOL_CACHE": str(toolcache),
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_WORKSPACE": str(self.workspace),
            **extra_source,
        }

    @staticmethod
    def _write(path: Path, content: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def npm_launcher(self, directory: Path, npm_entry: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        if self.platform_name == "Windows":
            launcher = self._write(directory / "npm.cmd", b"synthetic-npm-launcher")
            derived_entry = (
                directory / "node_modules" / "npm" / "bin" / "npm-cli.js"
            )
            derived_entry.parent.mkdir(parents=True, exist_ok=True)
            os.link(npm_entry, derived_entry)
            return launcher
        launcher = directory / "npm"
        os.link(npm_entry, launcher)
        return launcher

    def authorize_npm_roots(self, *roots: Path) -> None:
        role_roots = {
            role: tuple(values) for role, values in self.policy.role_roots.items()
        }
        role_roots["npm"] = tuple(
            (f"synthetic-npm-root-{index}", root)
            for index, root in enumerate(roots)
        )
        self.policy = ci.synthetic_tool_authority_policy(
            self.platform_name,
            running_python=self.paths["python"],
            role_roots=role_roots,
            minimal_system_directories=self.policy.minimal_system_directories,
            path_separator=self.policy.path_separator,
        )

    def shadow(self, role: str, *, directory: Path | None = None) -> Path:
        names = {
            "Windows": {
                "python": "python.exe",
                "node": "node.exe",
                "git": "git.exe",
                "bash": "bash.exe",
                "powershell": "powershell.exe",
            },
            "Ubuntu": {
                "python": "python",
                "node": "node",
                "git": "git",
                "bash": "bash",
                "powershell": "pwsh",
            },
        }
        target = (directory or self.runner_temp) / names[self.platform_name][role]
        return self._write(target, b"untrusted-shadow")

    def resolve(
        self, required: set[str] | frozenset[str] = frozenset({"python", "node", "git", "bash"})
    ) -> tuple[dict[str, str], list[str]]:
        return ci.resolve_trusted_tools(
            required,
            source_environment=self.source,
            policy=self.policy,
        )

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def use_run5_production_toolcache_roots(self) -> None:
        """Mirror default Linux policy roots for the exact Run-5 tool topology."""

        if self.platform_name != "Ubuntu":
            raise ValueError("Run-5 repository-policy topology is Ubuntu-only")
        toolcache = self.root / "hostedtoolcache"
        python = self.paths["python"]
        system = self.paths["system"]
        self.policy = ci.synthetic_tool_authority_policy(
            "Ubuntu",
            running_python=python,
            role_roots={
                "python": (("github-hosted-toolcache", toolcache),),
                "node": (
                    ("github-hosted-toolcache", toolcache),
                    ("approved-local-runtime", python.parents[1]),
                ),
                "npm": (
                    ("github-hosted-toolcache", toolcache),
                    ("approved-local-runtime", python.parents[1]),
                ),
                "git": (("posix-system-git", system),),
                "bash": (("posix-system-bash", system),),
                "powershell": (("posix-system-pwsh", system),),
                "pwsh": (("posix-system-pwsh", system),),
            },
            minimal_system_directories=(system,),
            path_separator=os.pathsep,
        )
        self.source.update(
            {
                "GITHUB_ACTIONS": "true",
                "RUNNER_OS": "Linux",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_TOOL_CACHE": str(toolcache),
            }
        )


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
        for role in ("node", "npm", "python", "git", "powershell", "bash"):
            self.assertTrue(
                any(
                    ci.TOOL_CANDIDATE_INVALID in error and f"tool={role}" in error
                    for error in errors
                ),
                (role, errors),
            )

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
            self.assertTrue(
                any(ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error for error in errors),
                errors,
            )

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


class CanonicalLockedGitIdentityTest(unittest.TestCase):
    @staticmethod
    def git_run(git: str, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            [
                git,
                "-c",
                f"safe.directory={root.resolve(strict=True)}",
                "-c",
                "commit.gpgSign=false",
                "-C",
                str(root.resolve(strict=True)),
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"fixture Git command failed: {arguments!r} rc={result.returncode}"
            )
        return result.stdout.decode("utf-8", errors="strict").strip()

    def make_repository(
        self, root: Path
    ) -> tuple[str, ci.ToolAuthorityPolicy, dict[str, str], str, bytes, dict[str, str], dict[str, str]]:
        policy, tools = _resolved_local_test_authority("git")
        git = tools["git"]
        self.git_run(git, root, "init", "--quiet")
        self.git_run(git, root, "config", "user.name", "CI Fixture")
        self.git_run(git, root, "config", "user.email", "ci@example.invalid")
        self.git_run(git, root, "config", "core.autocrlf", "false")
        relative = "developer/package.json"
        canonical = (
            b'{"name":"fixture","dependencies":{"alpha":"1.0.0"}}\n'
            b'{"integrity":"sha512-fixture"}\n'
        )
        path = root / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(canonical)
        self.git_run(git, root, "add", "--", relative)
        self.git_run(git, root, "commit", "--quiet", "-m", "fixture")
        object_id = self.git_run(git, root, "rev-parse", f"HEAD:{relative}")
        expected_sha = {relative: hashlib.sha256(canonical).hexdigest()}
        expected_oids = {relative: object_id}
        environment = ci.child_process_environment(
            tools,
            source_environment=_explicit_local_test_environment(),
            repo_root=root,
            policy=policy,
        )
        return (
            git,
            policy,
            environment,
            relative,
            canonical,
            expected_sha,
            expected_oids,
        )

    def capture(
        self,
        *,
        git: str,
        environment: Mapping[str, str],
        root: Path,
        expected_sha: Mapping[str, str],
        expected_oids: Mapping[str, str],
    ) -> tuple[dict[str, dict], list[str]]:
        return ci.capture_locked_file_git_identities(
            git=git,
            environment=environment,
            repo_root=root,
            expected_sha256=expected_sha,
            expected_blob_oids=expected_oids,
        )

    def test_lf_crlf_and_semantic_mutation_matrix_uses_git_blob_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-locked-git-") as temp_dir:
            root = Path(temp_dir)
            (
                git,
                _policy,
                environment,
                relative,
                canonical,
                expected_sha,
                expected_oids,
            ) = self.make_repository(root)
            path = root / relative

            identities, errors = self.capture(
                git=git,
                environment=environment,
                root=root,
                expected_sha=expected_sha,
                expected_oids=expected_oids,
            )
            self.assertEqual(errors, [])
            lf_snapshot, errors = ci.snapshot_trusted_files(
                repo_root=root,
                paths=(relative,),
                locked_identities=identities,
                locked_sha256=expected_sha,
                locked_blob_oids=expected_oids,
            )
            self.assertEqual(errors, [])

            crlf = canonical.replace(b"\n", b"\r\n")
            path.write_bytes(crlf)
            crlf_identities, errors = self.capture(
                git=git,
                environment=environment,
                root=root,
                expected_sha=expected_sha,
                expected_oids=expected_oids,
            )
            self.assertEqual(errors, [])
            crlf_snapshot, errors = ci.snapshot_trusted_files(
                repo_root=root,
                paths=(relative,),
                locked_identities=crlf_identities,
                locked_sha256=expected_sha,
                locked_blob_oids=expected_oids,
            )
            self.assertEqual(errors, [])
            self.assertEqual(lf_snapshot, crlf_snapshot)

            invalid_presentations = {
                "mixed-line-endings": canonical.splitlines(keepends=True)[0].replace(
                    b"\n", b"\r\n"
                )
                + canonical.splitlines(keepends=True)[1],
                "single-byte": canonical.replace(b"fixture", b"fixturf", 1),
                "dependency": canonical.replace(b'"alpha":"1.0.0"', b'"beta":"2.0.0"'),
                "same-size": canonical.replace(b'"1.0.0"', b'"2.0.0"'),
            }
            for name, presented in invalid_presentations.items():
                with self.subTest(name=name):
                    path.write_bytes(presented)
                    _identities, errors = self.capture(
                        git=git,
                        environment=environment,
                        root=root,
                        expected_sha=expected_sha,
                        expected_oids=expected_oids,
                    )
                    self.assertTrue(errors)

            path.write_bytes(canonical)
            self.git_run(git, root, "rm", "--cached", "--quiet", "--", relative)
            _identities, errors = self.capture(
                git=git,
                environment=environment,
                root=root,
                expected_sha=expected_sha,
                expected_oids=expected_oids,
            )
            self.assertTrue(errors, "an untracked look-alike must not authorize itself")
            self.git_run(git, root, "add", "--", relative)

            lf_target = ci._target_authority(root, relative)
            lf_lease = ci.TargetExecutionLease(
                lf_target,
                repo_root=root,
                execution_adapter="TARGET-BYTES-STDIN",
            )
            try:
                lf_lease.materialize()
                lf_raw_hash = lf_lease.evidence()["executedInputSha256"]
            finally:
                lf_lease.close()
            path.write_bytes(crlf)
            crlf_target = ci._target_authority(root, relative)
            crlf_lease = ci.TargetExecutionLease(
                crlf_target,
                repo_root=root,
                execution_adapter="TARGET-BYTES-STDIN",
            )
            try:
                crlf_lease.materialize()
                crlf_raw_hash = crlf_lease.evidence()["executedInputSha256"]
            finally:
                crlf_lease.close()
            self.assertNotEqual(lf_raw_hash, crlf_raw_hash)

            path.write_bytes(canonical.replace(b"alpha", b"omega"))
            self.git_run(git, root, "add", "--", relative)
            self.git_run(git, root, "commit", "--quiet", "-m", "different blob")
            _identities, errors = self.capture(
                git=git,
                environment=environment,
                root=root,
                expected_sha=expected_sha,
                expected_oids=expected_oids,
            )
            self.assertTrue(errors, "a different HEAD/index blob must fail closed")

    def test_symlink_or_reparse_substitution_is_rejected_before_blob_credit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-locked-link-") as temp_dir:
            root = Path(temp_dir)
            (
                git,
                _policy,
                environment,
                relative,
                _canonical,
                expected_sha,
                expected_oids,
            ) = self.make_repository(root)
            target_path = (root / relative).resolve(strict=True)
            original_secure = ci._secure_regular_file

            def reject_substitution(path: Path, *args, **kwargs):
                if Path(path).resolve() == target_path:
                    return False, "path is a symbolic link or reparse point"
                return original_secure(path, *args, **kwargs)

            with mock.patch.object(
                ci, "_secure_regular_file", side_effect=reject_substitution
            ):
                _identities, errors = self.capture(
                    git=git,
                    environment=environment,
                    root=root,
                    expected_sha=expected_sha,
                    expected_oids=expected_oids,
                )
            self.assertTrue(
                any("symbolic link or reparse" in error for error in errors), errors
            )


class InternalPythonExecutionAuthorityTest(unittest.TestCase):
    def test_canonical_and_same_file_alias_normalize_to_approved_python(self) -> None:
        approved = Path(sys.executable).resolve(strict=True)
        expected = [str(approved), "<internal>", "internal-fixture"]
        self.assertEqual(
            ci.canonical_internal_execution_argv(
                approved, approved, "internal-fixture"
            ),
            expected,
        )
        with tempfile.TemporaryDirectory(prefix="ci-python-alias-") as temp_dir:
            approved_fixture = Path(temp_dir) / "approved-python.exe"
            approved_fixture.write_bytes(b"same-file-identity-fixture")
            alias = Path(temp_dir) / "python-alias.exe"
            os.link(approved_fixture, alias)
            fixture_expected = [
                str(approved_fixture.resolve(strict=True)),
                "<internal>",
                "internal-fixture",
            ]
            self.assertEqual(
                ci.canonical_internal_execution_argv(
                    approved_fixture, alias, "internal-fixture"
                ),
                fixture_expected,
            )
            result = ci.make_internal_result(
                "internal-fixture",
                "unit",
                True,
                "ok",
                execution_authority=approved_fixture,
                observed_execution_authority=alias,
            )
            self.assertEqual(result["actualExecutionArgv"], fixture_expected)

    def test_distinct_binary_and_workspace_same_basename_are_rejected(self) -> None:
        approved = Path(sys.executable).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="ci-python-substitution-") as temp_dir:
            distinct = Path(temp_dir) / "distinct-python.exe"
            distinct.write_bytes(approved.read_bytes()[:4096] or b"distinct")
            workspace_alias = Path(temp_dir) / "workspace" / approved.name
            workspace_alias.parent.mkdir()
            workspace_alias.write_bytes(b"not-the-approved-python")
            for candidate in (distinct, workspace_alias):
                with self.subTest(candidate=candidate.name):
                    with self.assertRaisesRegex(
                        ValueError, "differs from approved file identity"
                    ):
                        ci.canonical_internal_execution_argv(
                            approved, candidate, "internal-fixture"
                        )

    def test_internal_argument_mutation_remains_strictly_rejected(self) -> None:
        spec = synthetic_command_spec("internal-fixture", "unit", 0)
        record = synthetic_record_from_spec(spec)
        record["actualExecutionArgv"] = [
            record["executionArgv"][0],
            "<internal>",
            "mutated-argument",
        ]
        errors: list[str] = []
        ci._validate_command_record(record, 0, errors)
        self.assertTrue(
            any("actualExecutionArgv" in error for error in errors), errors
        )


class HostedRunnerToolResolutionTest(unittest.TestCase):
    REQUIRED = frozenset({"python", "node", "git", "bash", "powershell"})
    ROOT_B_FAILURE_SIGNATURE = (
        "CI_TOOL_AUTHORITY_UNAVAILABLE tool=npm phase=VERIFICATION_PREPARATION "
        "reason=PATH_EXECUTABLE_SHADOW path_index=11 candidate=parent-path "
        "root_category=other"
    )

    def _npm_path_topology(self, fixture: _HostedToolFixture) -> SimpleNamespace:
        authority_root = (
            fixture.root / "hostedtoolcache" / "node" / "24.19.0" / "x64"
        )
        canonical = fixture._write(
            authority_root
            / "lib"
            / "node_modules"
            / "npm"
            / "bin"
            / "npm-cli.js",
            b"synthetic-canonical-npm-cli",
        ).resolve(strict=True)
        launcher = fixture.npm_launcher(authority_root / "bin", canonical)
        inert = []
        for index in range(1, 11):
            entry = fixture.root / "inert-path" / f"{index:02d}"
            entry.mkdir(parents=True)
            inert.append(entry)
        unrelated_root = fixture.root / "unrelated-npm-bin"
        unrelated = fixture._write(
            unrelated_root
            / ("npm.cmd" if fixture.platform_name == "Windows" else "npm"),
            b"unrelated-later-npm",
        )
        fixture.authorize_npm_roots(authority_root)
        source = dict(fixture.source)
        source["CI_TRUSTED_NPM_ENTRY"] = str(canonical)
        source["PATH"] = fixture.policy.path_separator.join(
            str(path)
            for path in (launcher.parent, *inert, unrelated.parent)
        )
        return SimpleNamespace(
            authority_root=authority_root,
            canonical=canonical,
            launcher=launcher,
            inert=tuple(inert),
            unrelated=unrelated,
            source=source,
        )

    def _assert_npm_blocked(
        self,
        fixture: _HostedToolFixture,
        source: Mapping[str, str],
    ) -> list[str]:
        tools, errors = ci.resolve_trusted_tools(
            {"npm"},
            source_environment=source,
            policy=fixture.policy,
        )
        self.assertNotIn("npm", tools)
        self.assertTrue(any("tool=npm" in error for error in errors), errors)
        return errors

    def test_npm_path_launcher_anchor_repairs_run8_topology_on_posix_and_windows(
        self,
    ) -> None:
        for platform_name in ("Ubuntu", "Windows"):
            with self.subTest(platform=platform_name):
                fixture = _HostedToolFixture(platform_name)
                try:
                    topology = self._npm_path_topology(fixture)
                    path_entries = topology.source["PATH"].split(
                        fixture.policy.path_separator
                    )
                    self.assertEqual(len(path_entries), 12)
                    self.assertEqual(Path(path_entries[0]), topology.launcher.parent)
                    self.assertEqual(Path(path_entries[11]), topology.unrelated.parent)
                    self.assertTrue(
                        ci._same_file_identity(
                            ci._npm_entry_from_launcher(topology.launcher),
                            topology.canonical,
                        )
                    )
                    tools, errors = ci.resolve_trusted_tools(
                        {"npm"},
                        source_environment=topology.source,
                        policy=fixture.policy,
                    )
                    self.assertEqual(errors, [])
                    self.assertEqual(
                        Path(
                            ci.require_tool(
                                tools,
                                "npm",
                                phase="VERIFICATION_PREPARATION",
                            )
                        ),
                        topology.canonical,
                    )
                    self.assertNotIn(
                        self.ROOT_B_FAILURE_SIGNATURE,
                        "\n".join(errors),
                    )

                    duplicate_root = topology.authority_root / "duplicate-bin"
                    duplicate = fixture.npm_launcher(
                        duplicate_root, topology.canonical
                    )
                    duplicate_source = dict(topology.source)
                    duplicate_source["PATH"] = fixture.policy.path_separator.join(
                        (str(duplicate.parent), topology.source["PATH"])
                    )
                    duplicate_tools, duplicate_errors = ci.resolve_trusted_tools(
                        {"npm"},
                        source_environment=duplicate_source,
                        policy=fixture.policy,
                    )
                    self.assertEqual(duplicate_errors, [])
                    self.assertEqual(
                        Path(duplicate_tools["npm"]), topology.canonical
                    )
                finally:
                    fixture.cleanup()

    def test_npm_path_launcher_anchor_negative_identity_and_order_matrix(
        self,
    ) -> None:
        for label in (
            "earlier-hostile",
            "same-basename-outside-root",
            "near-prefix-root",
            "sibling-untrusted-root",
            "ambiguous-non-equivalent",
        ):
            with self.subTest(case=label):
                fixture = _HostedToolFixture("Ubuntu")
                try:
                    topology = self._npm_path_topology(fixture)
                    if label == "near-prefix-root":
                        hostile_root = Path(f"{topology.authority_root}-evil") / "bin"
                    elif label == "sibling-untrusted-root":
                        hostile_root = (
                            topology.authority_root.parent / "24.19.0-sibling" / "bin"
                        )
                    elif label == "ambiguous-non-equivalent":
                        hostile_root = topology.authority_root / "alternate-bin"
                    else:
                        hostile_root = fixture.root / label / "bin"
                    fixture._write(hostile_root / "npm", label.encode("utf-8"))
                    source = dict(topology.source)
                    source["PATH"] = fixture.policy.path_separator.join(
                        (str(hostile_root), topology.source["PATH"])
                    )
                    errors = self._assert_npm_blocked(fixture, source)
                    self.assertTrue(
                        any(
                            reason in error
                            for error in errors
                            for reason in (
                                ci.PATH_EXECUTABLE_SHADOW,
                                ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY,
                            )
                        ),
                        errors,
                    )
                finally:
                    fixture.cleanup()

        for label in (
            "missing-anchor",
            "wrong-launcher-identity",
            "wrong-npm-cli-identity",
            "launcher-root-mismatch",
            "missing-npm",
        ):
            with self.subTest(case=label):
                fixture = _HostedToolFixture("Ubuntu")
                try:
                    topology = self._npm_path_topology(fixture)
                    source = dict(topology.source)
                    if label == "missing-anchor":
                        source["PATH"] = fixture.policy.path_separator.join(
                            str(path) for path in topology.inert
                        )
                    elif label == "wrong-launcher-identity":
                        wrong_entry = fixture._write(
                            topology.authority_root / "wrong-npm-cli.js",
                            b"wrong-launcher-target",
                        )
                        wrong_launcher = fixture.npm_launcher(
                            topology.authority_root / "wrong-bin", wrong_entry
                        )
                        source["PATH"] = str(wrong_launcher.parent)
                    elif label == "wrong-npm-cli-identity":
                        wrong_canonical = fixture._write(
                            topology.authority_root / "wrong-canonical-npm-cli.js",
                            b"wrong-canonical",
                        ).resolve(strict=True)
                        source["CI_TRUSTED_NPM_ENTRY"] = str(wrong_canonical)
                        source["PATH"] = str(topology.launcher.parent)
                    elif label == "launcher-root-mismatch":
                        launcher_root = fixture.root / "approved-launcher-root"
                        mismatch_launcher = fixture.npm_launcher(
                            launcher_root / "bin", topology.canonical
                        )
                        fixture.authorize_npm_roots(
                            topology.authority_root, launcher_root
                        )
                        source["PATH"] = str(mismatch_launcher.parent)
                    else:
                        source.pop("CI_TRUSTED_NPM_ENTRY")
                        source["PATH"] = fixture.policy.path_separator.join(
                            str(path) for path in topology.inert
                        )
                    self._assert_npm_blocked(fixture, source)
                finally:
                    fixture.cleanup()

    def test_npm_path_launcher_anchor_malformed_unreadable_and_uninspectable_fail_closed(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            topology = self._npm_path_topology(fixture)
            malformed = dict(topology.source)
            malformed["CI_TRUSTED_NPM_ENTRY"] = "npm-cli.js"
            self.assertTrue(
                any(
                    ci.TOOL_CANDIDATE_INVALID in error
                    for error in self._assert_npm_blocked(fixture, malformed)
                )
            )

            original_resolve = Path.resolve

            def unreadable(path: Path, *args, **kwargs):
                if path == topology.canonical:
                    raise PermissionError("synthetic unreadable npm authority")
                return original_resolve(path, *args, **kwargs)

            with mock.patch.object(Path, "resolve", unreadable):
                unreadable_errors = self._assert_npm_blocked(
                    fixture, topology.source
                )
            self.assertTrue(
                any(ci.TOOL_CANDIDATE_UNREADABLE in error for error in unreadable_errors),
                unreadable_errors,
            )

            blocked_entry = fixture.root / "uninspectable-predecessor"
            blocked_entry.mkdir()
            uninspectable_source = dict(topology.source)
            uninspectable_source["PATH"] = fixture.policy.path_separator.join(
                (str(blocked_entry), topology.source["PATH"])
            )
            original_lstat = Path.lstat

            def uninspectable(path: Path, *args, **kwargs):
                if path == blocked_entry:
                    raise PermissionError("synthetic uninspectable PATH entry")
                return original_lstat(path, *args, **kwargs)

            with mock.patch.object(Path, "lstat", uninspectable):
                uninspectable_errors = self._assert_npm_blocked(
                    fixture, uninspectable_source
                )
            self.assertTrue(
                any(
                    ci.PATH_PREDECESSOR_UNINSPECTABLE in error
                    for error in uninspectable_errors
                ),
                uninspectable_errors,
            )
        finally:
            fixture.cleanup()

    def test_npm_path_launcher_anchor_rejects_novel_generic_authority(self) -> None:
        controls = (
            "basename-only",
            "directory-prefix-only",
            "ambient-path-winner",
            "unverified-parent",
            "arbitrary-npm-cli",
            "generic-shell-launcher",
            "wildcard-tool-root",
        )
        for label in controls:
            with self.subTest(control=label):
                fixture = _HostedToolFixture("Ubuntu")
                try:
                    topology = self._npm_path_topology(fixture)
                    source = dict(topology.source)
                    if label in {
                        "basename-only",
                        "directory-prefix-only",
                        "wildcard-tool-root",
                    }:
                        if label == "basename-only":
                            root = fixture.root / "basename-authority"
                        else:
                            root = Path(
                                f"{topology.authority_root}-{label}"
                            )
                        arbitrary = fixture._write(
                            root / "lib" / "npm-cli.js", b"arbitrary-npm-cli"
                        ).resolve(strict=True)
                        launcher = fixture.npm_launcher(root / "bin", arbitrary)
                        source["CI_TRUSTED_NPM_ENTRY"] = str(arbitrary)
                        source["PATH"] = str(launcher.parent)
                    elif label == "ambient-path-winner":
                        ambient = fixture.root / "ambient-bin"
                        fixture._write(ambient / "npm", b"ambient-npm")
                        source.pop("CI_TRUSTED_NPM_ENTRY")
                        source["PATH"] = str(ambient)
                    elif label == "unverified-parent":
                        parent = fixture.root / "unverified-parent"
                        launcher = fixture.npm_launcher(parent, topology.canonical)
                        source["PATH"] = str(launcher.parent)
                    elif label == "arbitrary-npm-cli":
                        arbitrary = fixture._write(
                            topology.authority_root / "arbitrary-npm-cli.js",
                            b"arbitrary-npm-cli",
                        ).resolve(strict=True)
                        source["CI_TRUSTED_NPM_ENTRY"] = str(arbitrary)
                        source["PATH"] = fixture.policy.path_separator.join(
                            str(path) for path in topology.inert
                        )
                    else:
                        shell_root = topology.authority_root / "generic-shell-bin"
                        shell_root.mkdir(parents=True)
                        os.link(topology.canonical, shell_root / "sh")
                        source["PATH"] = str(shell_root)
                    self._assert_npm_blocked(fixture, source)
                finally:
                    fixture.cleanup()

    def run5_repository_policy_helper(
        self,
        fixture: _HostedToolFixture,
        *roles: str,
        source: dict[str, str] | None = None,
    ) -> tuple[ci.ToolAuthorityPolicy, dict[str, str]]:
        selected_source = dict(fixture.source if source is None else source)
        with (
            mock.patch.dict(os.environ, selected_source, clear=True),
            mock.patch.object(
                ci, "default_tool_authority_policy", return_value=fixture.policy
            ),
        ):
            return _resolved_local_test_authority(*roles)

    def test_run5_repository_policy_helper_binds_exact_setup_node_topology_and_selected_sibling(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            fixture.use_run5_production_toolcache_roots()
            self.assertEqual(
                fixture.paths["node"].relative_to(
                    fixture.root / "hostedtoolcache"
                ).as_posix(),
                "node/24.18.0/x64/bin/node",
            )
            with mock.patch.object(
                ci,
                "_fallback_tool_candidate",
                side_effect=AssertionError("selected hosted Node must not use fallback"),
            ):
                policy, tools = self.run5_repository_policy_helper(
                    fixture, "python", "node"
                )
            self.assertEqual(Path(tools["python"]), fixture.paths["python"])
            self.assertEqual(Path(tools["node"]), fixture.paths["node"])
            self.assertIsNotNone(
                ci._tool_root_classification(Path(tools["node"]), "node", policy)
            )

            sibling = fixture._write(
                fixture.root
                / "hostedtoolcache"
                / "node"
                / "24.17.0"
                / "x64"
                / "bin"
                / "node",
                b"synthetic-selected-sibling-node",
            ).resolve(strict=True)
            sibling_source = dict(fixture.source)
            sibling_source["PATH"] = fixture.policy.path_separator.join(
                (
                    str(sibling.parent),
                    *(
                        entry
                        for entry in fixture.source["PATH"].split(
                            fixture.policy.path_separator
                        )
                        if Path(entry) != fixture.paths["node"].parent
                    ),
                )
            )
            _sibling_policy, sibling_tools = self.run5_repository_policy_helper(
                fixture, "python", "node", source=sibling_source
            )
            self.assertEqual(Path(sibling_tools["node"]), sibling)
        finally:
            fixture.cleanup()

    def test_run5_repository_policy_helper_rejects_untrusted_node_path_matrix(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            fixture.use_run5_production_toolcache_roots()
            fake_directories = {
                "workspace": fixture.workspace / "fake-bin",
                "runner-temp": fixture.runner_temp / "fake-bin",
                "node-modules": fixture.root / "node_modules" / ".bin",
                "near-prefix-toolcache": fixture.root / "hostedtoolcache-evil" / "bin",
            }
            for label, directory in fake_directories.items():
                with self.subTest(label=label):
                    fixture._write(directory / "node", b"untrusted-node")
                    source = dict(fixture.source)
                    source["PATH"] = fixture.policy.path_separator.join(
                        (str(directory), source["PATH"])
                    )
                    with self.assertRaises(AssertionError) as raised:
                        self.run5_repository_policy_helper(
                            fixture, "python", "node", source=source
                        )
                    rendered = str(raised.exception)
                    self.assertIn("TEST-TOOL-AUTHORITY-UNAVAILABLE", rendered)
                    self.assertIn("tool=node", rendered)
                    self.assertTrue(
                        ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in rendered
                        or ci.PATH_EXECUTABLE_SHADOW in rendered,
                        rendered,
                    )
        finally:
            fixture.cleanup()

    def test_run5_repository_policy_helper_rejects_reparse_escape_and_post_capture_replacement(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        lease: ci.ExecutableIdentityLease | None = None
        try:
            fixture.use_run5_production_toolcache_roots()
            outside = fixture.root / "reparse-target"
            fixture._write(outside / "node", b"reparse-escape-node")
            link = fixture.root / "hostedtoolcache" / "reparse-bin"
            lstat_patch = contextlib.nullcontext()
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                link.mkdir()
                fixture._write(link / "node", b"simulated-reparse-node")
                original_lstat = Path.lstat
                metadata = original_lstat(link)
                reparse_metadata = SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_size=metadata.st_size,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=(
                        getattr(metadata, "st_file_attributes", 0)
                        | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    ),
                )

                def simulated_reparse(path: Path, *args, **kwargs):
                    if path == link:
                        return reparse_metadata
                    return original_lstat(path, *args, **kwargs)

                lstat_patch = mock.patch.object(Path, "lstat", simulated_reparse)
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (str(link), source["PATH"])
            )
            with lstat_patch, self.assertRaises(AssertionError) as raised:
                self.run5_repository_policy_helper(
                    fixture, "python", "node", source=source
                )
            self.assertIn("tool=node", str(raised.exception))

            _policy, tools = self.run5_repository_policy_helper(
                fixture, "python", "node"
            )
            node = Path(tools["node"])
            lease = ci.ExecutableIdentityLease(node, "run5-hosted-node")
            try:
                node.write_bytes(b"post-capture-replacement")
            except OSError:
                self.assertEqual(lease.verify(), (True, None))
            else:
                okay, error = lease.verify()
                self.assertFalse(okay)
                self.assertIsNotNone(error)
        finally:
            if lease is not None:
                lease.close()
            fixture.cleanup()

    def test_run5_repository_policy_helper_absent_and_partial_authority_fail_typed(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            fixture.use_run5_production_toolcache_roots()
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                entry
                for entry in source["PATH"].split(fixture.policy.path_separator)
                if Path(entry) != fixture.paths["node"].parent
            )
            with self.assertRaises(AssertionError) as absent:
                self.run5_repository_policy_helper(
                    fixture, "python", "node", source=source
                )
            self.assertIsInstance(
                absent.exception.__cause__, ci.ToolAuthorityUnavailable
            )
            self.assertEqual(absent.exception.__cause__.tool, "node")
            self.assertIn(ci.REQUIRED_TOOL_MISSING, str(absent.exception))

            with mock.patch.object(
                ci,
                "resolve_trusted_tools",
                return_value=({"python": str(fixture.paths["python"])}, []),
            ):
                with self.assertRaises(AssertionError) as partial:
                    self.run5_repository_policy_helper(fixture, "python", "node")
            self.assertIsInstance(
                partial.exception.__cause__, ci.ToolAuthorityUnavailable
            )
            self.assertNotIsInstance(partial.exception.__cause__, KeyError)
            self.assertEqual(partial.exception.__cause__.tool, "node")
        finally:
            fixture.cleanup()

    def test_policy_root_fallback_models_hosted_sibling_products_and_local_host(self) -> None:
        for platform_name in ("Ubuntu", "Windows"):
            with self.subTest(platform=platform_name):
                fixture = _HostedToolFixture(platform_name)
                try:
                    self.assertEqual(
                        ci._fallback_tool_candidate("node", fixture.policy),
                        fixture.paths["node"],
                    )
                    self.assertEqual(
                        ci._fallback_tool_candidate("git", fixture.policy),
                        fixture.paths["git"],
                    )
                finally:
                    fixture.cleanup()
        policy, tools = _resolved_local_test_authority("python", "node", "git")
        self.assertEqual(set(tools), {"python", "node", "git"})
        for role, path in tools.items():
            self.assertIsNotNone(ci._tool_root_classification(Path(path), role, policy))

    def test_local_authority_absence_is_typed_and_explainable(self) -> None:
        with mock.patch.object(
            ci,
            "resolve_trusted_tools",
            return_value=({}, ["REQUIRED_TOOL_MISSING tool=node"]),
        ):
            with self.assertRaisesRegex(
                AssertionError, "TEST-TOOL-AUTHORITY-UNAVAILABLE.*node"
            ):
                _resolved_local_test_authority("node")

    def test_windows_environment_case_variants_and_collision_semantics(self) -> None:
        fixture = _HostedToolFixture("Windows")
        try:
            program_files = fixture.root / "Program Files"
            program_files_x86 = fixture.root / "Program Files (x86)"
            (program_files_x86 / "Git").mkdir(parents=True)
            for spelling in ("PROGRAMFILES", "ProgramFiles", "pRoGrAmFiLeS"):
                with self.subTest(key=spelling):
                    source = {
                        key: value
                        for key, value in fixture.source.items()
                        if ci._ascii_lower_authority_text(key) != "programfiles"
                    }
                    source[spelling] = str(program_files)
                    policy = ci.default_tool_authority_policy(
                        source,
                        repo_root=fixture.workspace,
                        platform_name="Windows",
                    )
                    self.assertIn(
                        program_files / "Git",
                        [root for _label, root in policy.roots_for("git")],
                    )
            for spelling in (
                "PROGRAMFILES(X86)",
                "ProgramFiles(x86)",
                "pRoGrAmFiLeS(X86)",
            ):
                with self.subTest(key=spelling):
                    source = dict(fixture.source)
                    source[spelling] = str(program_files_x86)
                    policy = ci.default_tool_authority_policy(
                        source,
                        repo_root=fixture.workspace,
                        platform_name="Windows",
                    )
                    self.assertIn(
                        program_files_x86 / "Git",
                        [root for _label, root in policy.roots_for("git")],
                    )
            collision = dict(fixture.source)
            collision["PROGRAMFILES"] = str(program_files)
            collision["ProgramFiles"] = str(program_files_x86)
            with self.assertRaises(ci.EnvironmentAuthorityConflict):
                ci.default_tool_authority_policy(
                    collision,
                    repo_root=fixture.workspace,
                    platform_name="Windows",
                )
            tools, errors = ci.resolve_trusted_tools(
                {"git"},
                source_environment=collision,
                policy=fixture.policy,
            )
            self.assertEqual(tools, {})
            self.assertEqual(errors, ["ENVIRONMENT-AUTHORITY-CONFLICT key=ProgramFiles"])

            mixed_path = dict(fixture.source)
            mixed_path["pAtH"] = mixed_path.pop("PATH")
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=mixed_path,
                policy=fixture.policy,
            )
            self.assertEqual(errors, [])
            self.assertEqual(set(tools), set(self.REQUIRED))
            self.assertEqual(
                ci._environment_authority_value(
                    {"PATH": "upper", "Path": "mixed"},
                    "PATH",
                    windows=False,
                ),
                "upper",
            )
        finally:
            fixture.cleanup()

    def test_windows_child_environment_collision_authority_is_deterministic(
        self,
    ) -> None:
        with make_task_owned_tempdir(
            _explicit_security_task_temp(),
            "p52-env-",
        ) as root:
            private_temp = root / "private"
            private_temp.mkdir()
            executable = Path(sys.executable).resolve(strict=True)
            windows_policy = ci.synthetic_tool_authority_policy(
                "Windows",
                running_python=executable,
                role_roots={
                    "python": (("fixture-python", executable.parent),),
                },
                minimal_system_directories=(),
                path_separator=";",
            )
            tools = {"python": str(executable)}
            base = {
                "HOME": str(root),
                "LANG": "C.UTF-8",
                "PATH": str(executable.parent),
            }

            private_collision = {
                **base,
                "TEMP": "parent-temp",
                "Temp": "attacker-temp",
                "TMP": "parent-tmp",
                "tmp": "attacker-tmp",
            }
            environment = ci.child_process_environment(
                tools,
                source_environment=private_collision,
                private_temp_root=private_temp,
                policy=windows_policy,
            )
            self.assertEqual(
                [
                    key
                    for key in environment
                    if ci._ascii_lower_authority_text(key) == "temp"
                ],
                ["TEMP"],
            )
            self.assertEqual(
                [
                    key
                    for key in environment
                    if ci._ascii_lower_authority_text(key) == "tmp"
                ],
                ["TMP"],
            )
            self.assertEqual(environment["TEMP"], str(private_temp.resolve()))
            self.assertEqual(environment["TMP"], str(private_temp.resolve()))
            self.assertEqual(environment["HOME"], str(root))
            self.assertEqual(environment["LANG"], "C.UTF-8")

            equal_aliases = {**base, "TEMP": "same", "Temp": "same"}
            coalesced = ci.child_process_environment(
                tools,
                source_environment=equal_aliases,
                policy=windows_policy,
            )
            self.assertEqual(coalesced["TEMP"], "same")
            self.assertNotIn("Temp", coalesced)

            collision_matrices = (
                ("TEMP", "Temp", "TEMP"),
                ("TMP", "tmp", "TMP"),
                ("PATH", "Path", "PATH"),
                ("ProgramFiles", "PROGRAMFILES", "ProgramFiles"),
            )
            for first_key, second_key, expected_key in collision_matrices:
                for reverse in (False, True):
                    with self.subTest(
                        first=first_key,
                        second=second_key,
                        reverse=reverse,
                    ):
                        pairs = [(first_key, "A"), (second_key, "B")]
                        if reverse:
                            pairs.reverse()
                        source = dict(base)
                        for key, value in pairs:
                            source[key] = value
                        with self.assertRaisesRegex(
                            ci.EnvironmentAuthorityConflict,
                            rf"key={re.escape(expected_key)}$",
                        ):
                            ci.child_process_environment(
                                tools,
                                source_environment=source,
                                policy=windows_policy,
                            )

            posix_policy = ci.synthetic_tool_authority_policy(
                "Ubuntu",
                running_python=executable,
                role_roots={
                    "python": (("fixture-python", executable.parent),),
                },
                minimal_system_directories=(),
                path_separator=os.pathsep,
            )
            posix_environment = ci.child_process_environment(
                tools,
                source_environment={
                    **base,
                    "TEMP": "posix-upper-temp",
                    "Temp": "posix-mixed-temp",
                    "TMP": "posix-upper-tmp",
                    "tmp": "posix-lower-tmp",
                },
                policy=posix_policy,
            )
            self.assertEqual(posix_environment["TEMP"], "posix-upper-temp")
            self.assertEqual(posix_environment["TMP"], "posix-upper-tmp")
            self.assertNotIn("Temp", posix_environment)
            self.assertNotIn("tmp", posix_environment)

    def test_windows_private_temp_is_single_authority_observed_by_real_child(
        self,
    ) -> None:
        with make_task_owned_tempdir(
            _explicit_security_task_temp(),
            "p52-child-",
        ) as root:
            private_temp = root / "private"
            parent_temp = root / "parent"
            attacker_temp = root / "attacker"
            for path in (private_temp, parent_temp, attacker_temp):
                path.mkdir()
            executable = Path(sys.executable).resolve(strict=True)
            policy = ci.synthetic_tool_authority_policy(
                "Windows",
                running_python=executable,
                role_roots={
                    "python": (("fixture-python", executable.parent),),
                },
                minimal_system_directories=(),
                path_separator=";",
            )
            environment = ci.child_process_environment(
                {"python": str(executable)},
                source_environment={
                    "PATH": str(executable.parent),
                    "HOME": str(root),
                    "TEMP": str(parent_temp),
                    "Temp": str(attacker_temp),
                    "TMP": str(parent_temp),
                    "tmp": str(attacker_temp),
                },
                private_temp_root=private_temp,
                policy=policy,
            )
            child_code = """import json, os, tempfile
print(json.dumps({
    "entries": [[key, value] for key, value in os.environ.items()
                if key.upper() in {"TEMP", "TMP"}],
    "TEMP": os.environ.get("TEMP"),
    "TMP": os.environ.get("TMP"),
    "runtimeTemp": tempfile.gettempdir(),
}))
"""
            completed = subprocess.run(
                [str(executable), "-B", "-c", child_code],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = ci.strict_json_loads(
                completed.stdout,
                label="P52 child environment observation",
            )
            entries = observed["entries"]
            self.assertEqual(
                sum(key.casefold() == "temp" for key, _value in entries),
                1,
            )
            self.assertEqual(
                sum(key.casefold() == "tmp" for key, _value in entries),
                1,
            )
            expected = private_temp.resolve()
            self.assertEqual(Path(observed["TEMP"]).resolve(), expected)
            self.assertEqual(Path(observed["TMP"]).resolve(), expected)
            self.assertEqual(Path(observed["runtimeTemp"]).resolve(), expected)
            self.assertNotIn(str(attacker_temp.resolve()), json.dumps(observed))

    def test_windows_trusted_git_alternates_and_predecessor_ordering(self) -> None:
        fixture = _HostedToolFixture("Windows")
        try:
            git_root = fixture.paths["git"].parents[1]
            bin_git = fixture._write(git_root / "bin" / "git.exe", b"alternate-git")
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            self.assertEqual(Path(tools["git"]), fixture.paths["git"])

            entries = fixture.source["PATH"].split(fixture.policy.path_separator)
            cmd_root = str(git_root / "cmd")
            bin_root = str(git_root / "bin")
            bin_first = [entry for entry in entries if entry != cmd_root]
            bin_first.remove(bin_root)
            bin_first.insert(4, bin_root)
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(bin_first)
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=source,
                policy=fixture.policy,
            )
            self.assertEqual(errors, [])
            self.assertEqual(Path(tools["git"]), bin_git.resolve(strict=True))

            successor = fixture.root / "foreign-successor"
            fixture.shadow("git", directory=successor)
            source = dict(fixture.source)
            source["PATH"] += fixture.policy.path_separator + str(successor)
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=source,
                policy=fixture.policy,
            )
            self.assertIn("git", tools)
            self.assertFalse(any("tool=git" in error for error in errors), errors)

            near_prefix = fixture.root / "Program Files" / "Git-Evil" / "cmd"
            fixture.shadow("git", directory=near_prefix)
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (str(near_prefix), fixture.source["PATH"])
            )
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=source,
                policy=fixture.policy,
            )
            self.assertNotIn("git", tools)
            self.assertTrue(
                any(
                    reason in error
                    for reason in (
                        ci.PATH_EXECUTABLE_SHADOW,
                        ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY,
                    )
                    for error in errors
                ),
                errors,
            )
        finally:
            fixture.cleanup()

    def test_github_ubuntu_hosted_path_resolves_role_specific_tools(self) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            for role in self.REQUIRED:
                captured = ci.require_tool(tools, role, phase="CAPTURE")
                self.assertEqual(Path(captured), fixture.paths[role])
            self.assertTrue(
                ci._same_file_identity(
                    Path(ci.require_tool(tools, "python", phase="CAPTURE")),
                    fixture.root
                    / "hostedtoolcache"
                    / "Python"
                    / "3.12.13"
                    / "x64"
                    / "bin"
                    / "python",
                )
            )
            self.assertEqual(
                Path(ci.require_tool(tools, "python", phase="CAPTURE")).name,
                "python3.12",
            )
        finally:
            fixture.cleanup()

    def test_github_windows_hosted_path_resolves_git_bash_from_captured_git(self) -> None:
        fixture = _HostedToolFixture("Windows")
        try:
            fixture.shadow("bash", directory=fixture.paths["system"])
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            for role in self.REQUIRED:
                self.assertEqual(
                    Path(ci.require_tool(tools, role, phase="CAPTURE")),
                    fixture.paths[role],
                )
            bash = Path(ci.require_tool(tools, "bash", phase="CAPTURE"))
            git = Path(ci.require_tool(tools, "git", phase="CAPTURE"))
            self.assertEqual(bash.parents[1], git.parents[1])
            self.assertFalse(ci._windows_system_launcher_path(bash, fixture.source))
        finally:
            fixture.cleanup()

    def test_unsafe_empty_prefix_is_accepted_and_actual_shadow_matrix_is_rejected(self) -> None:
        for platform_name in ("Ubuntu", "Windows"):
            with self.subTest(platform=platform_name, case="empty-prefix"):
                fixture = _HostedToolFixture(platform_name)
                try:
                    tools, errors = fixture.resolve(self.REQUIRED)
                    self.assertEqual(errors, [])
                    self.assertEqual(set(tools), set(self.REQUIRED))
                finally:
                    fixture.cleanup()
            for role in self.REQUIRED:
                with self.subTest(platform=platform_name, case="shadow", role=role):
                    fixture = _HostedToolFixture(platform_name)
                    try:
                        fixture.shadow(role)
                        diagnostics: list[dict[str, object]] = []
                        tools, errors = ci.resolve_trusted_tools(
                            self.REQUIRED,
                            source_environment=fixture.source,
                            policy=fixture.policy,
                            diagnostics=diagnostics,
                        )
                        self.assertNotIn(role, tools)
                        self.assertTrue(
                            any(
                                f"tool={role}" in error
                                and (
                                    ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error
                                    or ci.PATH_EXECUTABLE_SHADOW in error
                                )
                                for error in errors
                            ),
                            errors,
                        )
                        self.assertFalse(
                            any(str(fixture.root) in json.dumps(item) for item in diagnostics),
                            diagnostics,
                        )
                    finally:
                        fixture.cleanup()

    def test_ubuntu_style_safe_symlink_broken_non_directory_and_empty_entry_matrix(self) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            safe_link = fixture.root / "standard-bin-link"
            os.symlink(fixture.paths["system"], safe_link, target_is_directory=True)
            broken_link = fixture.root / "broken-standard-link"
            os.symlink(
                fixture.root / "absent-standard-target",
                broken_link,
                target_is_directory=True,
            )
            non_directory = fixture._write(
                fixture.root / "path-entry-file", b"not-a-directory"
            )
            empty_directory = fixture.root / "safe-empty-directory"
            empty_directory.mkdir()
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (
                    str(safe_link),
                    str(broken_link),
                    str(non_directory),
                    str(empty_directory),
                    source["PATH"],
                )
            )
            diagnostics: list[dict[str, object]] = []
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=source,
                policy=fixture.policy,
                diagnostics=diagnostics,
            )
            self.assertEqual(errors, [])
            self.assertEqual(set(tools), set(self.REQUIRED))
            classifications = {
                item.get("pathIndex"): item.get("classification")
                for item in diagnostics
                if item.get("kind") == "path-entry"
            }
            self.assertEqual(
                classifications[0], ci.SAFE_CANONICAL_SYMLINK_DIRECTORY
            )
            self.assertEqual(classifications[1], ci.INERT_MISSING_ENTRY)
            self.assertEqual(classifications[2], ci.INERT_NON_DIRECTORY)
            self.assertEqual(
                classifications[3], ci.INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE
            )
            self.assertIn(ci.SAFE_CANONICAL_DIRECTORY, classifications.values())
        finally:
            fixture.cleanup()

    def test_ubuntu_style_uninspectable_predecessor_is_typed_and_blocking(self) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            ambiguous = fixture.root / "ambiguous-predecessor"
            ambiguous.mkdir()
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (str(ambiguous), source["PATH"])
            )
            original_lstat = Path.lstat

            def deny_candidate_inspection(path: Path, *args, **kwargs):
                if path.parent == ambiguous:
                    raise PermissionError("private absolute fixture path")
                return original_lstat(path, *args, **kwargs)

            diagnostics: list[dict[str, object]] = []
            with mock.patch.object(Path, "lstat", deny_candidate_inspection):
                tools, errors = ci.resolve_trusted_tools(
                    self.REQUIRED,
                    source_environment=source,
                    policy=fixture.policy,
                    diagnostics=diagnostics,
                )
            for role in self.REQUIRED:
                self.assertNotIn(role, tools)
                self.assertTrue(
                    any(
                        ci.PATH_PREDECESSOR_UNINSPECTABLE in error
                        and f"tool={role}" in error
                        and "path_index=0" in error
                        for error in errors
                    ),
                    (role, errors),
                )
            serialized = json.dumps(diagnostics, sort_keys=True)
            self.assertNotIn(str(fixture.root), serialized)
            self.assertNotIn("private absolute fixture path", serialized)
        finally:
            fixture.cleanup()

    def test_uninspectable_windows_app_alias_is_typed_path_free_and_fail_closed(
        self,
    ) -> None:
        fixture = _HostedToolFixture("Windows")
        try:
            alias_directory = fixture.root / "WindowsApps"
            alias_directory.mkdir()
            alias = fixture.shadow("python", directory=alias_directory)
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (str(alias_directory), source["PATH"])
            )
            original_resolve = Path.resolve

            failure_cases = (
                (
                    "winerror-1920",
                    lambda path: OSError(
                        5,
                        "private alias resolution failure",
                        str(path),
                        1920,
                    ),
                ),
                (
                    "deletion-race",
                    lambda path: FileNotFoundError(
                        2, "private alias deleted after lstat", str(path)
                    ),
                ),
                (
                    "target-inaccessible",
                    lambda path: PermissionError(
                        13, "private alias target inaccessible", str(path)
                    ),
                ),
            )
            for case_name, exception_factory in failure_cases:
                with self.subTest(case=case_name):
                    observed_lstat: list[os.stat_result] = []

                    def fail_alias_resolution(path: Path, *args, **kwargs):
                        if path == alias:
                            observed_lstat.append(path.lstat())
                            raise exception_factory(path)
                        return original_resolve(path, *args, **kwargs)

                    diagnostics: list[dict[str, object]] = []
                    with mock.patch.object(Path, "resolve", fail_alias_resolution):
                        root_result = ci._tool_root_classification_result(
                            alias, "python", fixture.policy
                        )
                        self.assertTrue(root_result.inspection_failed)
                        self.assertIsNone(
                            ci._tool_root_classification(
                                alias, "python", fixture.policy
                            )
                        )
                        classified = ci._classify_path_entry(
                            0,
                            alias_directory,
                            required={"python", "git"},
                            repo_root=fixture.workspace,
                            source=source,
                            policy=fixture.policy,
                        )
                        tools, errors = ci.resolve_trusted_tools(
                            {"python", "git"},
                            source_environment=source,
                            repo_root=fixture.workspace,
                            policy=fixture.policy,
                            diagnostics=diagnostics,
                        )

                    self.assertTrue(observed_lstat)
                    self.assertEqual(
                        classified.classification,
                        ci.UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
                    )
                    self.assertEqual(classified.uninspectable_roles, {"python"})
                    self.assertIn("python", classified.aliases)
                    self.assertNotIn("python", tools)
                    self.assertIn("git", tools)
                    self.assertFalse(
                        any("tool=git" in error for error in errors), errors
                    )
                    matching = [
                        error
                        for error in errors
                        if ci.PATH_PREDECESSOR_UNINSPECTABLE in error
                        and "tool=python" in error
                        and "path_index=0" in error
                    ]
                    self.assertEqual(len(matching), 1, errors)
                    with self.assertRaises(ci.ToolAuthorityUnavailable) as raised:
                        ci.require_tool(
                            tools,
                            "python",
                            phase="DISCOVERY",
                            resolution_errors=errors,
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        ci.PATH_PREDECESSOR_UNINSPECTABLE,
                    )
                    self.assertEqual(raised.exception.tool, "python")
                    rendered = "\n".join(
                        (
                            *errors,
                            json.dumps(diagnostics, sort_keys=True),
                            str(raised.exception),
                        )
                    )
                    for forbidden in (
                        str(fixture.root),
                        str(fixture.root).replace("\\", "\\\\"),
                        "private alias",
                        "WinError",
                        "Traceback",
                    ):
                        self.assertNotIn(forbidden, rendered)
                    self.assertFalse(ci.OUTPUT_DIR.exists())

            entry = fixture.root / "entry-resolution-race"
            entry.mkdir()
            entry_metadata = entry.lstat()
            reparse_metadata = SimpleNamespace(
                st_mode=entry_metadata.st_mode,
                st_dev=entry_metadata.st_dev,
                st_ino=entry_metadata.st_ino,
                st_size=entry_metadata.st_size,
                st_mtime_ns=entry_metadata.st_mtime_ns,
                st_ctime_ns=entry_metadata.st_ctime_ns,
                st_file_attributes=(
                    getattr(entry_metadata, "st_file_attributes", 0)
                    | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                ),
            )
            original_lstat = Path.lstat
            entry_cases = (
                (
                    "present-entry-oserror",
                    entry_metadata,
                    lambda path: OSError(
                        5, "private entry resolution failure", str(path), 1920
                    ),
                ),
                (
                    "present-entry-deletion-race",
                    entry_metadata,
                    lambda path: FileNotFoundError(
                        2, "private entry deleted after lstat", str(path)
                    ),
                ),
                (
                    "reparse-like-entry-resolution-failure",
                    reparse_metadata,
                    lambda path: PermissionError(
                        13, "private reparse target inaccessible", str(path)
                    ),
                ),
            )
            for case_name, metadata, exception_factory in entry_cases:
                with self.subTest(case=case_name):
                    lstat_calls = 0

                    def controlled_lstat(path: Path, *args, **kwargs):
                        nonlocal lstat_calls
                        if path == entry:
                            lstat_calls += 1
                            return metadata
                        return original_lstat(path, *args, **kwargs)

                    def fail_entry_resolution(path: Path, *args, **kwargs):
                        if path == entry:
                            raise exception_factory(path)
                        return original_resolve(path, *args, **kwargs)

                    with (
                        mock.patch.object(Path, "lstat", controlled_lstat),
                        mock.patch.object(Path, "resolve", fail_entry_resolution),
                    ):
                        classified = ci._classify_path_entry(
                            0,
                            entry,
                            required={"python", "git"},
                            repo_root=fixture.workspace,
                            source={"PATH": str(entry)},
                            policy=fixture.policy,
                        )
                    self.assertEqual(lstat_calls, 1)
                    self.assertEqual(
                        classified.classification,
                        ci.UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
                    )
                    self.assertEqual(
                        classified.uninspectable_roles, {"python", "git"}
                    )

            def raise_programmer_error(path: Path, *args, **kwargs):
                if path == alias:
                    raise TypeError("programmer error remains visible")
                return original_resolve(path, *args, **kwargs)

            with mock.patch.object(Path, "resolve", raise_programmer_error):
                with self.assertRaisesRegex(TypeError, "programmer error"):
                    ci._tool_root_classification(alias, "python", fixture.policy)

            git_root = fixture.paths["git"].parents[1]

            def fail_git_root_resolution(path: Path, *args, **kwargs):
                if path == git_root:
                    raise OSError(
                        5, "private Git root resolution failure", str(path), 1920
                    )
                return original_resolve(path, *args, **kwargs)

            with (
                mock.patch.object(
                    ci,
                    "_trusted_git_installation_root",
                    return_value=(git_root, None),
                ),
                mock.patch.object(Path, "resolve", fail_git_root_resolution),
            ):
                bash, bash_errors = ci.resolve_trusted_git_bash(
                    str(fixture.paths["git"]),
                    source_environment=fixture.source,
                    repo_root=fixture.workspace,
                    policy=fixture.policy,
                )
            self.assertIsNone(bash)
            self.assertEqual(len(bash_errors), 1)
            self.assertIn(ci.GIT_INSTALL_ROOT_UNRECOGNIZED, bash_errors[0])
            self.assertIn("tool=bash", bash_errors[0])
            self.assertNotIn(str(fixture.root), bash_errors[0])
            self.assertNotIn("private Git root", bash_errors[0])
        finally:
            fixture.cleanup()

    def test_path_shadow_root_and_reason_matrix_is_fail_closed(self) -> None:
        cases = (
            ("node", "workspace", ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY),
            ("python", "runner-temp", ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY),
            ("npm", "node-modules", ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY),
            ("git", "other", ci.PATH_EXECUTABLE_SHADOW),
        )
        for role, root_kind, expected_reason in cases:
            with self.subTest(role=role, root=root_kind):
                fixture = _HostedToolFixture("Ubuntu")
                try:
                    directory = {
                        "workspace": fixture.workspace,
                        "runner-temp": fixture.runner_temp,
                        "node-modules": fixture.root / "node_modules" / ".bin",
                        "other": fixture.root / "untrusted-standard-bin",
                    }[root_kind]
                    if role == "npm":
                        fixture._write(directory / "npm", b"untrusted-npm-shadow")
                    else:
                        fixture.shadow(role, directory=directory)
                    source = dict(fixture.source)
                    source["PATH"] = fixture.policy.path_separator.join(
                        (str(directory), source["PATH"])
                    )
                    if root_kind == "other":
                        original_category = ci._path_root_category

                        def category(path: Path, **kwargs):
                            if path.resolve(strict=True) == directory.resolve(strict=True):
                                return "other"
                            return original_category(path, **kwargs)

                        category_patch = mock.patch.object(
                            ci, "_path_root_category", side_effect=category
                        )
                    else:
                        category_patch = contextlib.nullcontext()
                    with category_patch:
                        tools, errors = ci.resolve_trusted_tools(
                            self.REQUIRED | {role},
                            source_environment=source,
                            policy=fixture.policy,
                        )
                    self.assertNotIn(role, tools)
                    self.assertTrue(
                        any(
                            expected_reason in error and f"tool={role}" in error
                            for error in errors
                        ),
                        errors,
                    )
                finally:
                    fixture.cleanup()

    def test_closed_diagnostic_reason_grammar_and_path_privacy(self) -> None:
        forbidden_paths = (
            r"C:\Program Files\Git\bin\bash.exe",
            r"D:\a\IELTS-Project\attacker.exe",
            "/home/runner/work/IELTS-Project/attacker",
            "/opt/hostedtoolcache/Python/3.12/bin/python",
        )
        for reason in sorted(ci.TOOL_AUTHORITY_REASON_CODES):
            with self.subTest(reason=reason):
                diagnostic = str(
                    ci.ToolAuthorityUnavailable(
                        "bash" if reason.startswith("BASH_") else "node",
                        "EXECUTION_BINDING",
                        reason_code=reason,
                        path_index=3,
                        candidate_class=(
                            "git-bin" if reason.startswith("BASH_") else "parent-path"
                        ),
                        root_category="other",
                    )
                )
                self.assertRegex(
                    diagnostic,
                    r"^CI_TOOL_AUTHORITY_UNAVAILABLE tool=(?:bash|node) "
                    r"phase=EXECUTION_BINDING reason=[A-Z][A-Z0-9_]+ "
                    r"path_index=3 candidate=(?:git-bin|parent-path) "
                    r"root_category=other$",
                )
                self.assertIn(f"reason={reason}", diagnostic)
                for forbidden in forbidden_paths:
                    self.assertNotIn(forbidden, diagnostic)

    def test_minimal_child_path_and_post_capture_shadow_race_remain_inert(self) -> None:
        for platform_name in ("Ubuntu", "Windows"):
            with self.subTest(platform=platform_name):
                fixture = _HostedToolFixture(platform_name)
                try:
                    tools, errors = fixture.resolve(self.REQUIRED)
                    self.assertEqual(errors, [])
                    child = ci.child_process_environment(
                        tools,
                        source_environment=fixture.source,
                        private_temp_root=fixture.runner_temp,
                        policy=fixture.policy,
                    )
                    child_entries = {
                        str(Path(entry).resolve(strict=True)).casefold()
                        for entry in child["PATH"].split(fixture.policy.path_separator)
                        if entry
                    }
                    for rejected in (fixture.runner_temp, fixture.workspace):
                        self.assertNotIn(str(rejected.resolve(strict=True)).casefold(), child_entries)
                    self.assertFalse(
                        any("node_modules" in entry.casefold() for entry in child_entries)
                    )
                    captured_git = ci.require_tool(tools, "git", phase="CAPTURE")
                    lease = ci.ExecutableIdentityLease(captured_git, "hosted-fixture-git")
                    try:
                        fixture.shadow("git")
                        self.assertEqual(
                            ci.require_tool(tools, "git", phase="EXECUTION"),
                            captured_git,
                        )
                        self.assertEqual(lease.verify(), (True, None))
                        self.assertNotIn(
                            str(fixture.runner_temp.resolve(strict=True)).casefold(),
                            child_entries,
                        )
                    finally:
                        lease.close()
                finally:
                    fixture.cleanup()

    def test_python_alias_file_identity_and_command_path_poisoning_matrix(self) -> None:
        for platform_name in ("Ubuntu", "Windows"):
            with self.subTest(platform=platform_name):
                fixture = _HostedToolFixture(platform_name)
                try:
                    approved = fixture.paths["python"]
                    alias_dir = fixture.root / "command-file-alias"
                    alias_dir.mkdir()
                    alias_name = "python.exe" if platform_name == "Windows" else "python"
                    alias = alias_dir / alias_name
                    try:
                        alias.symlink_to(approved)
                    except OSError:
                        os.link(approved, alias)
                    source = dict(fixture.source)
                    source["PATH"] = fixture.policy.path_separator.join(
                        [str(alias_dir), source["PATH"]]
                    )
                    source["GITHUB_PATH"] = str(fixture.root / "github-path-command")
                    tools, errors = ci.resolve_trusted_tools(
                        self.REQUIRED,
                        source_environment=source,
                        policy=fixture.policy,
                    )
                    self.assertEqual(errors, [])
                    captured = Path(ci.require_tool(tools, "python", phase="CAPTURE"))
                    self.assertEqual(captured, approved)
                    self.assertTrue(ci._same_file_identity(alias, approved))
                    child = ci.child_process_environment(
                        tools,
                        source_environment=source,
                        policy=fixture.policy,
                    )
                    self.assertNotIn(str(alias_dir), child["PATH"])
                    self.assertNotIn("GITHUB_PATH", child)
                finally:
                    fixture.cleanup()

    def test_python_wildcard_spelling_does_not_gain_executable_authority(self) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            wildcard_dir = fixture.root / "wildcard-python-name"
            wildcard = fixture._write(
                wildcard_dir / "python3.999",
                b"different-python-file",
            )
            source = dict(fixture.source)
            source["PATH"] = fixture.policy.path_separator.join(
                (str(wildcard_dir), source["PATH"])
            )
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=source,
                policy=fixture.policy,
            )
            self.assertEqual(errors, [])
            captured = Path(ci.require_tool(tools, "python", phase="CAPTURE"))
            self.assertEqual(captured, fixture.paths["python"])
            self.assertFalse(ci._same_file_identity(wildcard, captured))
        finally:
            fixture.cleanup()

    def test_missing_tool_and_partial_map_failures_are_typed_and_keyerror_free(self) -> None:
        for role in ("git", "bash", "node", "python"):
            with self.subTest(role=role):
                with self.assertRaises(ci.ToolAuthorityUnavailable) as raised:
                    ci.require_tool({}, role, phase="EXECUTION_BINDING")
                self.assertEqual(
                    str(raised.exception),
                    f"CI_TOOL_AUTHORITY_UNAVAILABLE tool={role} phase=EXECUTION_BINDING "
                    "reason=REQUIRED_TOOL_MISSING",
                )
                self.assertNotIsInstance(raised.exception, KeyError)

        fixture = _HostedToolFixture("Ubuntu")
        try:
            complete, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            for profile, missing in (
                ("policy", "git"),
                ("policy", "node"),
                ("policy", "python"),
                ("static", "bash"),
            ):
                with self.subTest(profile=profile, missing=missing):
                    partial = {key: value for key, value in complete.items() if key != missing}
                    runner = ci.FoundationRunner(
                        profile,
                        ci.strict_json_load_file(ci.BASELINE_PATH),
                        tools=partial,
                        tool_policy=fixture.policy,
                        source_environment=fixture.source,
                    )
                    try:
                        self.assertEqual(runner.command_plan, [])
                        with self.assertRaises(ci.ToolAuthorityUnavailable) as raised:
                            runner.require_all_tools(phase="EXECUTION_BINDING")
                        self.assertNotIsInstance(raised.exception, KeyError)
                    finally:
                        runner.cleanup_task_resources()
        finally:
            fixture.cleanup()

    def test_resolution_errors_and_post_capture_lease_drift_are_sticky(self) -> None:
        fixture = _HostedToolFixture("Ubuntu")
        try:
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            with self.assertRaises(ci.ToolAuthorityUnavailable) as raised:
                ci.require_tool_set(
                    {"git": ci.require_tool(tools, "git", phase="CAPTURE")},
                    {"git", "node"},
                    phase="EXECUTION_BINDING",
                    resolution_errors=("captured resolver failure",),
                )
            self.assertEqual(raised.exception.tool, "node")

            runner = ci.FoundationRunner(
                "policy",
                ci.strict_json_load_file(ci.BASELINE_PATH),
                tool_policy=fixture.policy,
                source_environment=fixture.source,
            )
            try:
                with mock.patch.object(
                    runner.tool_leases["git"],
                    "verify",
                    return_value=(False, "fixture identity drifted"),
                ):
                    with self.assertRaises(ci.ToolAuthorityUnavailable) as drifted:
                        runner.require_tool("git", phase="EXECUTION")
                self.assertEqual(drifted.exception.phase, "EXECUTION")
                self.assertFalse(runner.tool_authority_frozen)
                with self.assertRaises(ci.ToolAuthorityUnavailable):
                    runner.require_tool("node", phase="POST_EXECUTION")
            finally:
                runner.cleanup_task_resources()
        finally:
            fixture.cleanup()

    def test_missing_authority_cli_is_nonzero_path_free_and_has_no_traceback(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()
        with (
            mock.patch.object(
                ci,
                "resolve_trusted_tools",
                return_value=({}, ["fixture resolver failure with a private path"]),
            ),
            mock.patch.object(
                ci,
                "capture_live_external_authority",
                return_value=_explicit_live_local_external_authority(),
            ),
            contextlib.redirect_stderr(stderr),
            contextlib.redirect_stdout(stdout),
        ):
            result = ci.main(["--profile", "policy"])
        self.assertNotEqual(result, 0)
        diagnostic = stderr.getvalue()
        self.assertIn("CI_TOOL_AUTHORITY_UNAVAILABLE", diagnostic)
        self.assertIn("phase=EXECUTION_BINDING", diagnostic)
        self.assertNotIn("Traceback", diagnostic)
        self.assertNotIn("KeyError", diagnostic)
        self.assertNotIn("private path", diagnostic)
        self.assertFalse(ci.OUTPUT_DIR.exists())

    def test_synthetic_hosted_profiles_initialize_bind_and_preserve_static_count(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        for platform_name, canonical_os in (("Ubuntu", "Linux"), ("Windows", "Windows")):
            with self.subTest(platform=platform_name):
                fixture = _HostedToolFixture(platform_name)
                runner: ci.FoundationRunner | None = None
                try:
                    with mock.patch.object(
                        ci,
                        "execute_command",
                        side_effect=AssertionError("synthetic executable must never run"),
                    ):
                        runner = ci.FoundationRunner(
                            "static",
                            baseline,
                            tool_policy=fixture.policy,
                            source_environment=fixture.source,
                        )
                        self.assertEqual(runner.tool_resolution_errors, [])
                        self.assertEqual(set(runner.require_all_tools(phase="CAPTURE")), set(self.REQUIRED))
                        self.assertEqual(len(runner.command_plan), 677)
                        with (
                            mock.patch.object(
                                ci,
                                "current_checkout_identity",
                                return_value=(
                                    "e50540eb20a7a1bd6906add22a24198e8da70c7f",
                                    "3b4935101110851675be04f30db340b37b06129f",
                                ),
                            ),
                            mock.patch.object(
                                ci,
                                "ci_trust_file_set_authority",
                                return_value=([], "a" * 64),
                            ),
                            mock.patch.object(ci, "_canonical_runner_os", return_value=canonical_os),
                        ):
                            binding = ci.build_synthetic_generation_execution_binding(
                                runner,
                                external_authority=(
                                    ci.synthetic_local_execution_external_authority(
                                        runner_os=canonical_os
                                    )
                                ),
                            )
                        self.assertEqual(binding.get("producerProfile"), "static")
                        self.assertRegex(
                            str(binding.get("producerInvocationId", "")),
                            r"^[0-9a-f]{64}$",
                        )
                        child_entries = runner.child_environment["PATH"].split(
                            fixture.policy.path_separator
                        )
                        self.assertNotIn(str(fixture.runner_temp), child_entries)
                        self.assertNotIn(str(fixture.workspace), child_entries)
                finally:
                    if runner is not None:
                        runner.cleanup_task_resources()
                    fixture.cleanup()

class RunWideOSCoverageAccountingTest(unittest.TestCase):
    REQUIREMENTS = (
        {"familyId": "windows-job-object", "requiredLivePlatforms": ["windows"]},
        {
            "familyId": "cross-platform-tool-authority",
            "requiredLivePlatforms": ["ubuntu", "windows"],
        },
        {"familyId": "posix-containment-live", "requiredLivePlatforms": ["ubuntu"]},
    )

    @staticmethod
    def fact(
        family: str,
        platform_name: str,
        *,
        passed: int,
        skipped: int,
        mode: str = "live",
    ) -> dict[str, object]:
        return {
            "familyId": family,
            "jobId": f"{platform_name}-{family}-{mode}",
            "platform": platform_name,
            "executionMode": mode,
            "discovered": passed + skipped,
            "passed": passed,
            "failed": 0,
            "skippedByPlatform": skipped,
        }

    def passing_facts(self) -> list[dict[str, object]]:
        return [
            self.fact("windows-job-object", "ubuntu", passed=0, skipped=10),
            self.fact("windows-job-object", "windows", passed=10, skipped=0),
            self.fact("cross-platform-tool-authority", "ubuntu", passed=8, skipped=0),
            self.fact("cross-platform-tool-authority", "windows", passed=8, skipped=0),
            self.fact("posix-containment-live", "windows", passed=9, skipped=0, mode="model"),
            self.fact("posix-containment-live", "ubuntu", passed=4, skipped=0),
        ]

    def test_windows_only_skips_on_ubuntu_are_covered_by_live_windows_passes(self) -> None:
        records, errors = ci.evaluate_run_wide_os_coverage(
            self.REQUIREMENTS,
            self.passing_facts(),
        )
        self.assertEqual(errors, [])
        self.assertTrue(all(record["runWideCovered"] for record in records))
        windows = next(
            record
            for record in records
            if record["familyId"] == "windows-job-object"
        )
        self.assertEqual(windows["requiredLivePlatform"], "windows")
        self.assertEqual(windows["jobLocalPassed"], 10)

    def test_windows_only_family_skipped_on_every_job_is_blocking(self) -> None:
        facts = [
            fact
            for fact in self.passing_facts()
            if not (
                fact["familyId"] == "windows-job-object"
                and fact["platform"] == "windows"
            )
        ]
        facts.append(self.fact("windows-job-object", "windows", passed=0, skipped=10))
        _records, errors = ci.evaluate_run_wide_os_coverage(self.REQUIREMENTS, facts)
        self.assertTrue(
            any("family=windows-job-object platform=windows" in error for error in errors),
            errors,
        )

    def test_required_cross_platform_family_skipped_on_one_platform_is_blocking(self) -> None:
        facts = [
            fact
            for fact in self.passing_facts()
            if not (
                fact["familyId"] == "cross-platform-tool-authority"
                and fact["platform"] == "ubuntu"
            )
        ]
        facts.append(
            self.fact("cross-platform-tool-authority", "ubuntu", passed=0, skipped=8)
        )
        _records, errors = ci.evaluate_run_wide_os_coverage(self.REQUIREMENTS, facts)
        self.assertTrue(
            any(
                "family=cross-platform-tool-authority platform=ubuntu" in error
                for error in errors
            ),
            errors,
        )

    def test_windows_posix_model_is_supporting_not_a_live_ubuntu_substitute(self) -> None:
        facts = [
            fact
            for fact in self.passing_facts()
            if not (
                fact["familyId"] == "posix-containment-live"
                and fact["platform"] == "ubuntu"
            )
        ]
        _records, errors = ci.evaluate_run_wide_os_coverage(self.REQUIREMENTS, facts)
        self.assertTrue(
            any("family=posix-containment-live platform=ubuntu" in error for error in errors),
            errors,
        )


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
            original_chain = ci._non_reparse_directory_chain

            def reject_bash_chain(path: Path, stop: Path) -> bool:
                if path == root / "bin":
                    return False
                return original_chain(path, stop)

            with (
                mock.patch.object(ci, "_unsafe_tool_path_reason", return_value=None),
                mock.patch.object(ci, "_tool_location_is_allowlisted", return_value=True),
                mock.patch.object(
                    ci,
                    "_non_reparse_directory_chain",
                    side_effect=reject_bash_chain,
                ),
            ):
                bash, errors = ci.resolve_trusted_git_bash(
                    str(git), source_environment={"SystemRoot": r"C:\Windows"}
            )
            self.assertIsNone(bash)
            self.assertTrue(any(ci.BASH_CANDIDATE_REPARSE in error for error in errors), errors)

            (root / "bin" / "bash.exe").unlink()
            other = Path(temp_dir) / "GitB" / "bin" / "bash.exe"
            other.parent.mkdir(parents=True)
            other.write_bytes(b"bash")
            bash, errors = self.resolve_fixture(git, Path(temp_dir) / "repo")
            self.assertIsNone(bash)
            self.assertTrue(any(ci.BASH_CANDIDATE_ABSENT in error for error in errors), errors)

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
        bash = ci.require_tool(tools, "bash", phase="CAPTURE")
        self.assertEqual(Path(bash).resolve(), git_bash.resolve())
        self.assertNotIn("bash", calls)
        self.assertNotIn("wsl", calls)

    def test_system32_only_uses_captured_local_git_without_wsl_or_path_bash_lookup(self) -> None:
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
        if "git" in tools:
            self.assertEqual(errors, [])
            git = Path(ci.require_tool(tools, "git", phase="CAPTURE"))
            bash = Path(ci.require_tool(tools, "bash", phase="CAPTURE"))
            self.assertEqual(git.parents[1], bash.parents[1])
            self.assertFalse(ci._windows_system_launcher_path(bash, source))
        else:
            self.assertNotIn("bash", tools)
            self.assertTrue(errors)
        self.assertEqual(calls, [])

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
                "powershell": str(
                    Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe").resolve(
                        strict=True
                    )
                ),
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

                sentinel = Path(temp_dir) / "hardlink-executed.txt"
                command = (
                    f"{Path(sys.executable).resolve()} -B -c \"from pathlib import Path; "
                    f"Path({str(sentinel)!r}).write_text('bad')\""
                )
                self.assertEqual(
                    lease.verify(),
                    (False, "trusted Git Bash stable file identity drifted"),
                )
                capture = ci.execute_command(
                    "hardlink-alias-preexecution",
                    "unit",
                    [lease.path, "/d", "/c", command],
                    timeout=10,
                    executable_lease=lease,
                )
                self.assertFalse(capture.executed)
                self.assertEqual(capture.process_tree_status, "setup-failed")
                self.assertFalse(sentinel.exists())
                self.assertEqual(ci._sha256_file(bash), original_hash)
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
            with self.assertRaisesRegex(OSError, "reparse"):
                ci.TrustedBashLease(
                    str(alias / "bin" / "bash.exe"),
                    str(alias / "cmd" / "git.exe"),
                )
            os.rmdir(alias)
            create_junction(alternate)
            self.assertEqual((alias / "bin" / "bash.exe").resolve(), alternate_bash.resolve())
            with self.assertRaisesRegex(OSError, "reparse"):
                ci.TrustedBashLease(
                    str(alias / "bin" / "bash.exe"),
                    str(alias / "cmd" / "git.exe"),
                )
            os.rmdir(alias)


@unittest.skipUnless(os.name == "nt", "Windows Git installation authority")
class WindowsGitInstallationAuthorityRegressionTest(unittest.TestCase):
    REQUIRED = frozenset({"python", "node", "git", "bash", "powershell"})

    def hosted_layout(
        self,
        *,
        git_directory: str,
        bash_position: str,
        both_bash_candidates: bool = False,
    ) -> tuple[_HostedToolFixture, Path]:
        fixture = _HostedToolFixture("Windows")
        git_root = fixture.root / "Program Files" / "Git"
        git_target = git_root / git_directory / "git.exe"
        git_target.parent.mkdir(parents=True, exist_ok=True)
        if fixture.paths["git"] != git_target.resolve():
            os.replace(fixture.paths["git"], git_target)
        fixture.paths["git"] = git_target.resolve(strict=True)

        bash_target = git_root.joinpath(*bash_position.split("/"))
        bash_target.parent.mkdir(parents=True, exist_ok=True)
        if fixture.paths["bash"] != bash_target.resolve():
            os.replace(fixture.paths["bash"], bash_target)
        fixture.paths["bash"] = bash_target.resolve(strict=True)
        if both_bash_candidates:
            for suffix in ci.WINDOWS_GIT_BASH_CANDIDATE_SUFFIXES:
                candidate = git_root.joinpath(*suffix)
                if not candidate.exists():
                    fixture._write(candidate, b"synthetic-bash-secondary")
        return fixture, git_root

    def assert_layout_binds(self, git_directory: str, bash_position: str) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory=git_directory,
            bash_position=bash_position,
        )
        try:
            diagnostics: list[dict[str, object]] = []
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=fixture.source,
                policy=fixture.policy,
                diagnostics=diagnostics,
            )
            self.assertEqual(errors, [])
            self.assertEqual(Path(tools["git"]), fixture.paths["git"])
            self.assertEqual(Path(tools["bash"]), fixture.paths["bash"])
            root, root_error = ci._trusted_git_installation_root(fixture.paths["git"])
            self.assertIsNone(root_error)
            self.assertTrue(os.path.samefile(root, git_root))
            self.assertEqual(
                ci._trusted_git_bash_candidate_position(
                    Path(tools["bash"]),
                    root,
                    windows=True,
                ),
                bash_position.replace("/", "\\"),
            )
            self.assertTrue(
                any(item.get("disposition") == "accepted" for item in diagnostics),
                diagnostics,
            )
        finally:
            fixture.cleanup()

    def test_bin_git_bin_bash_hosted_layout_binds(self) -> None:
        self.assert_layout_binds("bin", "bin/bash.exe")

    def test_bin_git_usr_bin_bash_hosted_layout_binds(self) -> None:
        self.assert_layout_binds("bin", "usr/bin/bash.exe")

    def test_cmd_git_bin_bash_hosted_layout_binds(self) -> None:
        self.assert_layout_binds("cmd", "bin/bash.exe")

    def test_cmd_git_usr_bin_bash_hosted_layout_binds(self) -> None:
        self.assert_layout_binds("cmd", "usr/bin/bash.exe")

    def test_fixed_candidate_priority_is_path_and_pathex_independent(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
            both_bash_candidates=True,
        )
        try:
            windows_apps = fixture.root / "Users" / "runneradmin" / "AppData" / "Local" / "Microsoft" / "WindowsApps"
            fixture._write(windows_apps / "bash.exe", b"windows-app-alias")
            fixture.source["PATH"] = fixture.policy.path_separator.join(
                (
                    str(git_root / "usr" / "bin"),
                    str(windows_apps),
                    fixture.source["PATH"],
                )
            )
            fixture.source["PATHEXT"] = ".CMD;.UNSAFE;.EXE"
            diagnostics: list[dict[str, object]] = []
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=fixture.source,
                policy=fixture.policy,
                diagnostics=diagnostics,
            )
            self.assertNotIn("bash", tools)
            self.assertTrue(
                any(
                    item.get("reasonCode") == ci.PATH_EXECUTABLE_SHADOW
                    and item.get("disposition") == "rejected"
                    for item in diagnostics
                ),
                diagnostics,
            )
            self.assertTrue(
                any(
                    ci.PATH_EXECUTABLE_SHADOW in error and "tool=bash" in error
                    for error in errors
                ),
                errors,
            )
            self.assertFalse(any(str(fixture.root) in json.dumps(item) for item in diagnostics))
        finally:
            fixture.cleanup()

    def test_existing_invalid_priority_candidate_never_falls_back_to_usr_bin(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="cmd",
            bash_position="bin/bash.exe",
            both_bash_candidates=True,
        )
        try:
            priority = git_root / "bin" / "bash.exe"
            secondary = git_root / "usr" / "bin" / "bash.exe"
            hardlink = fixture.root / "priority-bash-hardlink.exe"
            os.link(priority, hardlink)
            diagnostics: list[dict[str, object]] = []
            tools, errors = ci.resolve_trusted_tools(
                self.REQUIRED,
                source_environment=fixture.source,
                policy=fixture.policy,
                diagnostics=diagnostics,
            )
            self.assertNotIn("bash", tools)
            self.assertTrue(
                any(ci.BASH_CANDIDATE_HARDLINK in error for error in errors), errors
            )
            self.assertTrue(secondary.is_file())
            bash_diagnostics = [
                item for item in diagnostics if item.get("kind") == "bash-candidate"
            ]
            self.assertEqual(len(bash_diagnostics), 1)
            self.assertEqual(
                bash_diagnostics[0]["candidateLocationClass"], "git-bin"
            )
            self.assertEqual(
                bash_diagnostics[0]["reasonCode"], ci.BASH_CANDIDATE_HARDLINK
            )
            self.assertEqual(bash_diagnostics[0]["disposition"], "rejected")
        finally:
            fixture.cleanup()

    def test_git_suffix_namespace_case_and_space_matrix(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        try:
            mixed_case_git = Path(str(fixture.paths["git"]).swapcase())
            root, error = ci._trusted_git_installation_root(mixed_case_git)
            self.assertIsNone(error)
            self.assertTrue(os.path.samefile(root, git_root))

            unsupported = (
                git_root / "portable" / "git.exe",
                git_root / "mingw64" / "bin" / "git.exe",
                git_root / "bin" / "git.cmd",
            )
            for candidate in unsupported:
                with self.subTest(candidate=candidate.relative_to(git_root)):
                    fixture._write(candidate, b"unsupported-git")
                    derived, reason = ci._trusted_git_installation_root(candidate)
                    self.assertIsNone(derived)
                    self.assertIn(ci.GIT_INSTALL_ROOT_UNRECOGNIZED, reason or "")

            forbidden_references = (
                Path("Program Files/Git/bin/git.exe"),
                Path(r"\\server\share\Git\bin\git.exe"),
                Path(r"\\?\D:\Git\bin\git.exe"),
                Path(r"\\.\D:\Git\bin\git.exe"),
                Path(r"\??\D:\Git\bin\git.exe"),
            )
            for candidate in forbidden_references:
                with self.subTest(reference=str(candidate)):
                    derived, reason = ci._trusted_git_installation_root(candidate)
                    self.assertIsNone(derived)
                    self.assertIn(ci.GIT_INSTALL_ROOT_UNRECOGNIZED, reason or "")
        finally:
            fixture.cleanup()

    def test_other_installation_system_workspace_temp_and_node_modules_bash_fail_closed(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        try:
            fixture.paths["bash"].unlink()
            fake_directories = (
                fixture.root / "Program Files" / "Git-Other" / "bin",
                fixture.root / "Windows" / "System32",
                fixture.workspace,
                fixture.runner_temp,
                fixture.root / "node_modules" / ".bin",
            )
            for directory in fake_directories:
                fixture._write(directory / "bash.exe", b"unapproved-bash")
            fixture.source["PATH"] = fixture.policy.path_separator.join(
                (*map(str, fake_directories), fixture.source["PATH"])
            )
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertIn("git", tools)
            self.assertNotIn("bash", tools)
            self.assertTrue(any(ci.BASH_CANDIDATE_ABSENT in error for error in errors), errors)
            with self.assertRaisesRegex(
                ci.ToolAuthorityUnavailable,
                r"^CI_TOOL_AUTHORITY_UNAVAILABLE tool=bash phase=EXECUTION_BINDING "
                r"reason=BASH_CANDIDATE_ABSENT candidate=git-usr-bin$",
            ):
                ci.require_tool_set(
                    tools,
                    self.REQUIRED,
                    phase="EXECUTION_BINDING",
                    resolution_errors=errors,
                )
            self.assertFalse((git_root / "usr" / "bin" / "bash.exe").exists())
        finally:
            fixture.cleanup()

    def test_near_prefix_and_noncandidate_inside_root_do_not_bind(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="cmd",
            bash_position="bin/bash.exe",
        )
        try:
            near_prefix = fixture._write(
                fixture.root / "Program Files" / "Git-Evil" / "bin" / "bash.exe",
                b"near-prefix-bash",
            )
            arbitrary_inside = fixture._write(
                git_root / "tools" / "bash.exe",
                b"arbitrary-inside-bash",
            )
            self.assertIsNone(ci._tool_root_classification(near_prefix, "bash", fixture.policy))
            self.assertFalse(
                ci._authority_path_is_within(
                    near_prefix.resolve(),
                    git_root.resolve(),
                    windows=True,
                )
            )
            self.assertIsNone(
                ci._trusted_git_bash_candidate_position(
                    arbitrary_inside,
                    git_root,
                    windows=True,
                )
            )
        finally:
            fixture.cleanup()

    def test_symlink_reparse_parent_and_hardlink_alias_matrix_fails_closed(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="cmd",
            bash_position="bin/bash.exe",
        )
        try:
            bash = fixture.paths["bash"]
            other = fixture._write(
                fixture.root / "Program Files" / "Git-Other" / "bin" / "bash.exe",
                b"other-installation-bash",
            )
            bash.unlink()
            os.link(other, bash)
            _tools, errors = fixture.resolve(self.REQUIRED)
            self.assertTrue(any(ci.BASH_CANDIDATE_HARDLINK in error for error in errors), errors)
        finally:
            fixture.cleanup()

        fixture, _git_root = self.hosted_layout(
            git_directory="cmd",
            bash_position="bin/bash.exe",
        )
        try:
            bash = fixture.paths["bash"]
            target = fixture._write(fixture.root / "symlink-target" / "bash.exe", b"target")
            bash.unlink()
            os.symlink(target, bash)
            _tools, errors = fixture.resolve(self.REQUIRED)
            self.assertTrue(any(ci.BASH_CANDIDATE_REPARSE in error for error in errors), errors)

            bash.unlink()
            fixture._write(bash, b"synthetic-bash")
            original_chain = ci._non_reparse_directory_chain

            def reparse_bin(path: Path, stop: Path) -> bool:
                if path == bash.parent:
                    return False
                return original_chain(path, stop)

            with mock.patch.object(ci, "_non_reparse_directory_chain", side_effect=reparse_bin):
                _tools, errors = fixture.resolve(self.REQUIRED)
            self.assertTrue(any(ci.BASH_CANDIDATE_REPARSE in error for error in errors), errors)
        finally:
            fixture.cleanup()

    def test_absent_and_unreadable_candidate_reason_schema_is_path_free(self) -> None:
        fixture, _git_root = self.hosted_layout(
            git_directory="cmd",
            bash_position="bin/bash.exe",
        )
        try:
            bash = fixture.paths["bash"]
            bash.unlink()
            diagnostics: list[dict[str, object]] = []
            resolved, errors = ci.resolve_trusted_git_bash(
                str(fixture.paths["git"]),
                source_environment=fixture.source,
                policy=fixture.policy,
                diagnostics=diagnostics,
            )
            self.assertIsNone(resolved)
            self.assertTrue(any(ci.BASH_CANDIDATE_ABSENT in error for error in errors), errors)
            self.assertEqual(
                [item["candidateLocationClass"] for item in diagnostics],
                ["git-bin", "git-usr-bin"],
            )
            self.assertNotIn(str(fixture.root), json.dumps(diagnostics))

            fixture._write(bash, b"synthetic-bash")
            original_lstat = Path.lstat

            def unreadable_file(path: Path, *args, **kwargs):
                if path == bash:
                    raise PermissionError("synthetic unreadable file")
                return original_lstat(path, *args, **kwargs)

            with mock.patch.object(Path, "lstat", unreadable_file):
                resolved, errors = ci.resolve_trusted_git_bash(
                    str(fixture.paths["git"]),
                    source_environment=fixture.source,
                    policy=fixture.policy,
                )
            self.assertIsNone(resolved)
            self.assertTrue(any(ci.BASH_CANDIDATE_UNREADABLE in error for error in errors), errors)

            def unreadable_directory(path: Path, *args, **kwargs):
                if path == bash.parent:
                    raise PermissionError("synthetic unreadable directory")
                return original_lstat(path, *args, **kwargs)

            with mock.patch.object(Path, "lstat", unreadable_directory):
                resolved, errors = ci.resolve_trusted_git_bash(
                    str(fixture.paths["git"]),
                    source_environment=fixture.source,
                    policy=fixture.policy,
                )
            self.assertIsNone(resolved)
            self.assertTrue(any(ci.BASH_CANDIDATE_UNREADABLE in error for error in errors), errors)
        finally:
            fixture.cleanup()

    def test_pathex_and_alias_extension_matrix_cannot_redirect_bash(self) -> None:
        pathext_values = (".CMD;.EXE", ".UNSAFE;.CMD;.EXE", "", ".Exe;.Cmd")
        aliases = ("bash.cmd", "bash", "BASH.EXE", "bash.unsafe")
        for pathext, alias_name in itertools.product(pathext_values, aliases):
            with self.subTest(pathext=pathext, alias=alias_name):
                fixture, _git_root = self.hosted_layout(
                    git_directory="bin",
                    bash_position="bin/bash.exe",
                )
                try:
                    alias_dir = fixture.root / "Users" / "runneradmin" / "AppData" / "Local" / "Microsoft" / "WindowsApps"
                    fixture._write(alias_dir / alias_name, b"fake-alias")
                    fixture.source["PATH"] = fixture.policy.path_separator.join(
                        (str(alias_dir), fixture.source["PATH"])
                    )
                    fixture.source["PATHEXT"] = pathext
                    tools, errors = fixture.resolve(self.REQUIRED)
                    if alias_name == "bash.unsafe":
                        self.assertEqual(errors, [])
                        self.assertEqual(Path(tools["bash"]), fixture.paths["bash"])
                    else:
                        self.assertNotIn("bash", tools)
                        self.assertTrue(
                            any(
                                ci.PATH_EXECUTABLE_SHADOW in error
                                and "tool=bash" in error
                                for error in errors
                            ),
                            errors,
                        )
                finally:
                    fixture.cleanup()

        fixture, _git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        try:
            alias_dir = fixture.root / "git-command-alias"
            fixture._write(alias_dir / "git.cmd", b"fake-git-command")
            fixture.source["PATH"] = fixture.policy.path_separator.join(
                (str(alias_dir), fixture.source["PATH"])
            )
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertNotIn("git", tools)
            self.assertTrue(
                any(
                    ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error
                    and "tool=git" in error
                    for error in errors
                ),
                errors,
            )
            bash, bash_errors = ci.resolve_trusted_git_bash(
                str(fixture.paths["git"]),
                source_environment=fixture.source,
                policy=fixture.policy,
            )
            self.assertEqual(bash_errors, [])
            self.assertEqual(Path(bash), fixture.paths["bash"])
        finally:
            fixture.cleanup()

    def test_missing_bash_has_typed_error_no_partial_binding_or_success_artifact(self) -> None:
        fixture, _git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        try:
            fixture.paths["bash"].unlink()
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(set(tools), set(self.REQUIRED) - {"bash"})
            with self.assertRaises(ci.ToolAuthorityUnavailable) as captured:
                ci.require_tool_set(
                    tools,
                    self.REQUIRED,
                    phase="EXECUTION_BINDING",
                    resolution_errors=errors,
                )
            self.assertEqual(
                captured.exception.reason_code,
                ci.BASH_CANDIDATE_ABSENT,
            )
            self.assertFalse(ci.OUTPUT_DIR.exists())
        finally:
            fixture.cleanup()

    def test_candidate_created_after_failed_capture_does_not_complete_frozen_map(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        try:
            fixture.paths["bash"].unlink()
            frozen_tools, frozen_errors = fixture.resolve(self.REQUIRED)
            fixture._write(git_root / "bin" / "bash.exe", b"late-bash")
            self.assertNotIn("bash", frozen_tools)
            with self.assertRaises(ci.ToolAuthorityUnavailable):
                ci.require_tool_set(
                    frozen_tools,
                    self.REQUIRED,
                    phase="EXECUTION_BINDING",
                    resolution_errors=frozen_errors,
                )
            fresh_tools, fresh_errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(fresh_errors, [])
            self.assertIn("bash", fresh_tools)
        finally:
            fixture.cleanup()

    def test_child_path_inventory_contains_only_approved_directories(self) -> None:
        fixture, git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="usr/bin/bash.exe",
        )
        try:
            windows_apps = fixture.root / "Users" / "runneradmin" / "AppData" / "Local" / "Microsoft" / "WindowsApps"
            windows_apps.mkdir(parents=True)
            fixture.source["PATH"] = fixture.policy.path_separator.join(
                (str(windows_apps), fixture.source["PATH"])
            )
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            child = ci.child_process_environment(
                tools,
                source_environment=fixture.source,
                private_temp_root=fixture.runner_temp,
                policy=fixture.policy,
            )
            entries = [
                Path(value).resolve(strict=True)
                for value in child["PATH"].split(fixture.policy.path_separator)
                if value
            ]
            expected = {
                Path(tools[role]).resolve(strict=True).parent
                for role in self.REQUIRED
            } | {fixture.paths["system"]}
            self.assertEqual(set(entries), expected)
            self.assertNotIn(fixture.runner_temp, entries)
            self.assertNotIn(fixture.workspace, entries)
            self.assertNotIn(windows_apps, entries)
            self.assertNotIn(fixture.root, entries)
            self.assertTrue(all(path.is_absolute() for path in entries))
            self.assertFalse(any("node_modules" in str(path).casefold() for path in entries))
            self.assertIn(git_root / "bin", entries)
            self.assertIn(git_root / "usr" / "bin", entries)
        finally:
            fixture.cleanup()

    def test_hosted_all_profile_binds_and_static_plan_remains_677_without_execution(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        fixture, _git_root = self.hosted_layout(
            git_directory="bin",
            bash_position="bin/bash.exe",
        )
        all_runner: ci.FoundationRunner | None = None
        release_all_runner: ci.FoundationRunner | None = None
        static_runner: ci.FoundationRunner | None = None
        try:
            tools, errors = fixture.resolve(self.REQUIRED)
            self.assertEqual(errors, [])
            all_tools = {**tools, "npm": tools["node"]}
            with mock.patch.object(
                ci,
                "execute_command",
                side_effect=AssertionError("synthetic executable must never run"),
            ):
                all_runner = ci.FoundationRunner(
                    "all",
                    baseline,
                    tools=all_tools,
                    tool_policy=fixture.policy,
                    source_environment=fixture.source,
                )
                release_all_runner = ci.FoundationRunner(
                    "all",
                    baseline,
                    release_authoritative=True,
                    tools=all_tools,
                    tool_policy=fixture.policy,
                    source_environment=fixture.source,
                )
                static_runner = ci.FoundationRunner(
                    "static",
                    baseline,
                    tools=tools,
                    tool_policy=fixture.policy,
                    source_environment=fixture.source,
                )
            self.assertTrue(all_runner.tool_authority_frozen)
            self.assertFalse(all_runner.release_gate_required)
            self.assertTrue(release_all_runner.release_gate_required)
            self.assertEqual(
                release_all_runner.command_plan_digest,
                all_runner.command_plan_digest,
            )
            self.assertEqual(
                release_all_runner.command_plan,
                all_runner.command_plan,
            )
            self.assertEqual(
                set(all_runner.require_all_tools(phase="EXECUTION_BINDING")),
                {"bash", "git", "node", "npm", "powershell", "python"},
            )
            self.assertTrue(all_runner.command_plan)
            self.assertEqual(all_runner.command_plan_errors, [])
            self.assertEqual(len(static_runner.command_plan), 677)
            self.assertEqual(static_runner.command_plan_errors, [])
            bash_spec = copy.deepcopy(next(
                item
                for item in static_runner.command_plan
                if item["commandId"] == "git-bash-version"
            ))
            bash_spec["executionLease"] = {
                "canonicalPath": bash_spec["resolvedExecutablePath"],
                "trustedGitRoot": str(Path(tools["git"]).resolve(strict=True).parent.parent),
                "size": bash_spec["resolvedExecutableSize"],
                "volumeSerial": "1",
                "fileIndex": "2",
                "links": 1,
                "creationTime": "3",
                "writeTime": "4",
                "reparsePoint": False,
                "sha256": bash_spec["resolvedExecutableSha256"],
            }
            bash_record = synthetic_record_from_spec(bash_spec)
            lease_errors: list[str] = []
            ci._validate_command_record(bash_record, 0, lease_errors)
            self.assertFalse(
                any("trusted Bash execution lease is invalid" in error for error in lease_errors)
            )
            forged_record = copy.deepcopy(bash_record)
            forged_record["executionLease"]["links"] = 2
            forged_errors: list[str] = []
            ci._validate_command_record(forged_record, 0, forged_errors)
            self.assertTrue(
                any("trusted Bash execution lease is invalid" in error for error in forged_errors)
            )
        finally:
            if all_runner is not None:
                all_runner.cleanup_task_resources()
            if release_all_runner is not None:
                release_all_runner.cleanup_task_resources()
            if static_runner is not None:
                static_runner.cleanup_task_resources()
            fixture.cleanup()

    def test_trusted_bash_lease_rejects_arbitrary_same_root_position(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci-p36-fixed-position-") as temp_dir:
            git_root = Path(temp_dir) / "Git"
            git = git_root / "cmd" / "git.exe"
            arbitrary = git_root / "tools" / "bash.exe"
            command_processor = Path(
                os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
            ).resolve(strict=True)
            git.parent.mkdir(parents=True)
            arbitrary.parent.mkdir(parents=True)
            shutil.copy2(command_processor, git)
            shutil.copy2(command_processor, arbitrary)
            with self.assertRaisesRegex(OSError, "fixed installation candidate"):
                ci.TrustedBashLease(str(arbitrary), str(git))


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
            root = Path(temp_dir)
            pid_file = root / "daemon.pid"
            ready = root / "daemon.ready"
            sentinel = root / "daemon-survived.txt"
            child = (
                "import os,time,pathlib; "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                f"pathlib.Path({str(ready)!r}).write_text('ready'); "
                "time.sleep(2.5); "
                f"pathlib.Path({str(sentinel)!r}).write_text('bad')"
            )
            parent = (
                "import subprocess,sys,time,pathlib; "
                f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
                f"p=pathlib.Path({str(ready)!r}); d=time.monotonic()+2; "
                "\nwhile not p.exists() and time.monotonic()<d: time.sleep(.01)\n"
                "\nif not p.exists(): raise SystemExit(4)\n"
            )
            capture = self.execute_python(parent)
            self.assertTrue(ready.is_file())
            daemon_pid = int(pid_file.read_text(encoding="utf-8"))
            self.assertEqual(capture.exit_code, 0)
            self.assertTrue(capture.execution_passed())
            self.assertGreaterEqual(capture.descendants_observed, 1)
            self.assertEqual(capture.descendants_surviving, 0)
            self.assertIn(
                capture.containment_disposition,
                {"natural-exit-reaped", "forced-terminated"},
            )
            self.assertFalse(_process_is_alive(daemon_pid))
            time.sleep(2.8)
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

    def test_cookie_header_requires_a_cookie_pair_not_a_bare_source_identifier(self) -> None:
        benign = (
            b"const options = {\n  cookie: sessionCookieOptions\n};\n",
            b"const options = {\r\n  cookie: sessionCookieOptions\r\n};\r\n",
            b"const options: Config = { cookie: sessionCookieOptions };\n",
            b'{"cookie": "sessionCookieOptions"}\n',
        )
        for content in benign:
            with self.subTest(content=content[:24]):
                result = self.scan_bytes(content, "benign-source.ts")
                self.assertTrue(result["passed"], result)
                self.assertNotIn("cookie-header", result["hits"])

    def test_real_cookie_header_line_endings_pairs_and_authorization_remain_detected(self) -> None:
        credentials = (
            b"Cookie: session=private-value\n",
            b"cookie: session=private-value\r\n",
            b"Set-Cookie: session=private-value; HttpOnly\n",
            b"Cookie: first=one; second=two\r\n",
            b"Cookie: author" + b"ization=BearerPrivateValue123\n",
        )
        for content in credentials:
            with self.subTest(content=content):
                result = self.scan_bytes(content, "headers.txt")
                self.assertFalse(result["passed"], result)
                self.assertIn("cookie-header", result["hits"])

    def test_real_cookie_headers_survive_utf16_and_raw_chunk_boundaries(self) -> None:
        header = "Cookie: sess" + "ion=PrivateCookieValue987654321"
        for encoding in ("utf-16le", "utf-16be"):
            with self.subTest(encoding=encoding):
                result = self.scan_bytes(("safe\r\n" + header).encode(encoding))
                self.assertFalse(result["passed"], result)
                self.assertIn("cookie-header", result["hits"])
        prefix = b"x" * (ci.SECRET_SCAN_CHUNK_BYTES - len(b"Cookie: ses"))
        content = prefix + b"\nCookie: session=chunk-boundary-private\n"
        result = self.scan_bytes(content, "boundary.txt")
        self.assertFalse(result["passed"], result)
        self.assertIn("cookie-header", result["hits"])

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
            release_gate_required=False,
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
            release_gate_required=False,
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
                release_gate_required=False,
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
        runner = ci.FoundationRunner(
            "static",
            self.baseline,
            tools=_explicit_local_test_tool_map(
                *sorted(ci.required_tool_names("static"))
            ),
        )
        try:
            self.assertEqual(runner.command_plan_errors, [])
            self.assertEqual(runner.tool_resolution_errors, [])
            self.assertEqual(len(runner.command_plan), 677)
        finally:
            runner.cleanup_task_resources()


class CI5TargetExecutionLeaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tools = _explicit_local_test_tool_map("python", "node")
        cls.node = ci.require_tool(tools, "node", phase="CAPTURE")
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
        for identity_field in ("target", "executable", "both"):
            with self.subTest(identity_field=identity_field):
                verifier_plan = copy.deepcopy(self.plan())
                if identity_field in {"target", "both"}:
                    identity = verifier_plan["targets"][0]["fileIdentity"]
                    identity["inodeOrFileIndex"] = str(int(identity["inodeOrFileIndex"]) + 1)
                if identity_field in {"executable", "both"}:
                    identity = verifier_plan["resolvedExecutableFileIdentity"]
                    identity["inodeOrFileIndex"] = str(int(identity["inodeOrFileIndex"]) + 1)
                self.assertEqual(
                    ci._portable_command_plan_value([plan]),
                    ci._portable_command_plan_value([verifier_plan]),
                )
                self.assertIn(
                    "COMMAND-AUTHORITY-MISMATCH",
                    [
                        value["id"]
                        for value in ci._command_authority_violations(
                            "static", [record], [], expected_plan=[verifier_plan]
                        )
                    ],
                )
                self.assertEqual(
                    ci._command_authority_violations(
                        "static", [record], [], expected_plan=[verifier_plan],
                        cross_job=True,
                    ),
                    [],
                )
        for mutation in ("target-identity", "lease-identity", "detected-mutation"):
            with self.subTest(local_mutation=mutation):
                forged = copy.deepcopy(record)
                if mutation == "target-identity":
                    identity = forged["targets"][0]["fileIdentity"]
                    identity["inodeOrFileIndex"] = str(int(identity["inodeOrFileIndex"]) + 1)
                elif mutation == "lease-identity":
                    identity = forged["targetExecutionLease"]["plannedStableFileIdentity"]
                    identity["inodeOrFileIndex"] = str(int(identity["inodeOrFileIndex"]) + 1)
                else:
                    forged["targetExecutionLease"]["mutationDetected"] = True
                errors = []
                ci._validate_command_record(forged, 0, errors)
                self.assertTrue(errors)

    def test_execution_input_omission_and_forgery_are_rejected(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        for field, value in (
            ("actualExecutionInputSha256", "0" * 64),
            ("actualExecutionInputSha256", None),
            ("actualExecutionInputSize", None),
            ("executionInputSha256", "0" * 64),
        ):
            with self.subTest(field=field, value=value):
                forged = copy.deepcopy(record)
                forged[field] = value
                errors: list[str] = []
                ci._validate_command_record(forged, 0, errors)
                self.assertTrue(errors)
                for cross_job in (False, True):
                    with self.subTest(cross_job=cross_job):
                        ids = [
                            value["id"]
                            for value in ci._command_authority_violations(
                                "static", [forged], [], expected_plan=[plan],
                                cross_job=cross_job,
                            )
                        ]
                        self.assertIn(
                            "COMMAND-AUTHORITY-MISMATCH"
                            if field == "executionInputSha256"
                            else "EXECUTION-INPUT-IDENTITY-MISMATCH",
                            ids,
                        )

    def test_logical_or_execution_argv_forgery_is_rejected_by_rebuilt_plan(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        for mode in ("logical", "execution-live-path", "actual-only"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(record)
                if mode == "logical":
                    forged["logicalArgv"][-1] = "js/unrelated.js"
                    forged["argv"] = list(forged["logicalArgv"])
                elif mode == "execution-live-path":
                    forged["executionArgv"] = [self.node, "--check", self.relative]
                    forged["actualExecutionArgv"] = list(forged["executionArgv"])
                else:
                    forged["actualExecutionArgv"] = [self.node, "--check", self.relative]
                for cross_job in (False, True):
                    with self.subTest(cross_job=cross_job):
                        ids = [
                            value["id"]
                            for value in ci._command_authority_violations(
                                "static", [forged], [], expected_plan=[plan],
                                cross_job=cross_job,
                            )
                        ]
                        self.assertIn(
                            "EXECUTION-ARGV-MISMATCH"
                            if mode == "actual-only"
                            else "COMMAND-AUTHORITY-MISMATCH",
                            ids,
                        )

    def test_post_evidence_target_change_is_caught_by_independent_plan_rebuild(self) -> None:
        plan = self.plan()
        capture, lease = self.execute(plan)
        assert lease is not None
        record = self.final_record(plan, capture, lease)
        self.target.write_bytes(self.invalid_bytes)
        rebuilt = self.plan()
        for cross_job in (False, True):
            with self.subTest(cross_job=cross_job):
                ids = [
                    value["id"]
                    for value in ci._command_authority_violations(
                        "static", [record], [], expected_plan=[rebuilt],
                        cross_job=cross_job,
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
        canonical_records = [
            ci._canonical_transcript_record(record) for record in commands["records"]
        ]
        self.assertIsNone(
            ci.first_replay_transcript_difference_diagnostic(
                canonical_records, copy.deepcopy(canonical_records)
            )
        )
        self.assertIsNone(ci.first_replay_transcript_difference_diagnostic([], []))
        self.assertEqual(ci.replay_failure_diagnostics([], []), [])

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

        fixed_record = {"commandId": "baseline-schema", "exitCode": 0}
        for producer, replay in (([fixed_record], []), ([], [fixed_record])):
            with self.subTest(missing_side="replay" if producer else "producer"):
                diagnostic = ci.strict_json_loads(
                    ci.first_replay_transcript_difference_diagnostic(producer, replay)
                )
                self.assertEqual(diagnostic["commandId"], "baseline-schema")
                self.assertEqual(diagnostic["changedFieldCategories"], ["command-membership"])
                self.assertEqual(
                    diagnostic["producerRecordDigest"],
                    ci.canonical_failure_digest(producer[0] if producer else None),
                )
                self.assertEqual(
                    diagnostic["replayRecordDigest"],
                    ci.canonical_failure_digest(replay[0] if replay else None),
                )

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

        unsafe = "PRIVATE-CANARY:/tmp/private/token-output?credential=secret"
        failures = [
            {
                "id": ci.HARD_GATE_AUTHORITY[index % len(ci.HARD_GATE_AUTHORITY)],
                "status": "fail",
                "detail": {"path": unsafe, "stdout": unsafe, "environment": {unsafe: unsafe}},
                "sequence": index,
            }
            for index in range(10)
        ]
        violations = [
            {
                "id": "UNKNOWN-NONPASS",
                "commandId": "static-suite",
                "detail": {"stderr": unsafe, "observations": [unsafe]},
                "sequence": index,
            }
            for index in range(10)
        ]
        failures[1]["id"] = unsafe
        violations[1]["id"] = unsafe
        violations[1]["commandId"] = unsafe
        violations[2].pop("commandId")
        violations[3]["id"] = "CI-RUNNER-ERROR"
        violations[4]["id"] = ci.HARD_GATE_AUTHORITY[0]
        hard_prefix = "verification replay failed hard gate: "
        violation_prefix = "verification replay violation: "
        diagnostics = ci.replay_failure_diagnostics(failures, violations)
        self.assertEqual(diagnostics, ci.replay_failure_diagnostics(
            copy.deepcopy(failures), copy.deepcopy(violations)
        ))
        self.assertEqual(len(diagnostics), 16)
        self.assertNotIn(unsafe, "\n".join(diagnostics))
        hard_diagnostics = [ci.strict_json_loads(line.removeprefix(hard_prefix))
                            for line in diagnostics if line.startswith(hard_prefix)]
        violation_diagnostics = [ci.strict_json_loads(line.removeprefix(violation_prefix))
                                 for line in diagnostics if line.startswith(violation_prefix)]
        self.assertEqual(len(hard_diagnostics), 8)
        self.assertEqual(len(violation_diagnostics), 8)
        for index, diagnostic in enumerate(hard_diagnostics):
            self.assertEqual(set(diagnostic), {"hardGateId", "diagnosticDigest"})
            self.assertEqual(diagnostic["hardGateId"],
                             "OTHER" if index == 1 else failures[index]["id"])
            self.assertEqual(diagnostic["diagnosticDigest"],
                             ci.canonical_failure_digest(failures[index]))
        for index, diagnostic in enumerate(violation_diagnostics):
            expected_keys = {"violationId", "diagnosticDigest"}
            if index not in {1, 2}:
                expected_keys.add("commandId")
                self.assertEqual(diagnostic["commandId"], "static-suite")
            self.assertEqual(set(diagnostic), expected_keys)
            self.assertEqual(diagnostic["violationId"],
                             "OTHER" if index == 1 else violations[index]["id"])
            self.assertEqual(diagnostic["diagnosticDigest"],
                             ci.canonical_failure_digest(violations[index]))
        changed_failures = copy.deepcopy(failures)
        changed_failures[0]["detail"]["path"] += "-changed"
        changed_diagnostics = ci.replay_failure_diagnostics(changed_failures, violations)
        self.assertNotEqual(diagnostics[0], changed_diagnostics[0])
        self.assertEqual(diagnostics[1:], changed_diagnostics[1:])
        for gate_id in sorted(ci._REPLAY_DIAGNOSTIC_HARD_GATE_IDS):
            with self.subTest(allowlisted_gate=gate_id):
                record = {"id": gate_id, "status": "fail", "detail": unsafe}
                hard_line, violation_line = ci.replay_failure_diagnostics([record], [record])
                self.assertEqual(ci.strict_json_loads(hard_line.removeprefix(hard_prefix))["hardGateId"],
                                 gate_id)
                self.assertEqual(ci.strict_json_loads(violation_line.removeprefix(violation_prefix))["violationId"],
                                 gate_id)
        for invalid_id in (None, 7, [unsafe], {unsafe: unsafe}):
            with self.subTest(nonstring_identity=type(invalid_id).__name__):
                record = {"id": invalid_id, "commandId": invalid_id, "detail": unsafe}
                hard_line, violation_line = ci.replay_failure_diagnostics([record], [record])
                self.assertEqual(ci.strict_json_loads(hard_line.removeprefix(hard_prefix))["hardGateId"],
                                 "OTHER")
                violation = ci.strict_json_loads(violation_line.removeprefix(violation_prefix))
                self.assertEqual(set(violation), {"violationId", "diagnosticDigest"})
                self.assertEqual(violation["violationId"], "OTHER")
                self.assertNotIn(unsafe, hard_line + violation_line)

        nonpass_runner = copy.deepcopy(self.runner)
        nonpass_runner.hard_gate_results = failures[:3] + [
            {"id": ci.HARD_GATE_AUTHORITY[3], "status": "pass", "detail": unsafe}
        ]
        nonpass_runner.violations = violations[:4]
        transcript, errors = ci.compare_verification_replay_claims(
            self.documents, nonpass_runner, self.comparison
        )
        self.assertIn(
            "verification replay profile is non-PASS: hardFailures=3 violations=4", errors
        )
        self.assertEqual(sum(line.startswith(hard_prefix) for line in errors), 3)
        self.assertEqual(sum(line.startswith(violation_prefix) for line in errors), 4)
        self.assertNotIn(unsafe, "\n".join(errors))
        self.assertNotIn("replayAuthorizationEnvelope", transcript)

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

        # Diagnostics inspect the compared record without changing its canonical
        # acceptance projection, including the still-authoritative duration class.
        source = copy.deepcopy(self.documents["command-results.json"]["records"][0])
        source["executionDurationClass"] = "bounded"
        source["durationSeconds"] = 0.125
        canonical = ci._canonical_transcript_record(source)
        duration_only = copy.deepcopy(source)
        duration_only["durationSeconds"] = 9.875
        self.assertEqual(canonical, ci._canonical_transcript_record(duration_only))
        duration_only["executionDurationClass"] = "not-started"
        self.assertNotEqual(canonical, ci._canonical_transcript_record(duration_only))
        self.assertEqual(canonical["executionDurationClass"], "bounded")

        categories = {
            "executionDurationClass", "stdout-identity", "stderr-identity",
            "execution-status", "process-containment", "target-input-authority",
            "executionInputBundleDigest", "protectedTargetBundle.executionInputBundleDigest",
            "runtime-closure", "producer-observation-context", "command-membership",
            "other-authorized-fixed-category",
        }
        unsafe = "PRIVATE-CANARY:C:\\private\\secret.txt?credential=token"
        matrix = (
            (("executionDurationClass",), "executionDurationClass"),
            (("stdoutSha256",), "stdout-identity"),
            (("stderrSha256",), "stderr-identity"),
            (("exitCode",), "execution-status"),
            (("parsedFailureSummary", "status"), "execution-status"),
            (("parsedFailureSummary", "diagnostic"), "producer-observation-context"),
            (("processTreeStatus",), "process-containment"),
            (("protectedTargetBundle", "cleanupState"), "process-containment"),
            (("protectedTargetBundle", "mutationDetected"), "process-containment"),
            (("executionInputBundleDigest",), "executionInputBundleDigest"),
            (("protectedTargetBundle", "executionInputBundleDigest"),
             "protectedTargetBundle.executionInputBundleDigest"),
            (("targets",), "target-input-authority"),
            (("executionInputs",), "target-input-authority"),
            (("executionLease",), "target-input-authority"),
            (("runtimeClosureDigest",), "runtime-closure"),
            (("producerObservationSetDigest",), "producer-observation-context"),
            ((unsafe,), "other-authorized-fixed-category"),
        )
        combined_producer = {"commandId": "baseline-schema"}
        combined_replay = {"commandId": "static-suite"}
        for keys, category in matrix:
            with self.subTest(category=category, field=keys):
                producer = {"commandId": "baseline-schema"}
                replay = copy.deepcopy(producer)
                left, right = producer, replay
                for key in keys[:-1]:
                    left[key], right[key] = {}, {}
                    left, right = left[key], right[key]
                left[keys[-1]] = "unchanged-identity"
                right[keys[-1]] = {"stdout": unsafe, "environment": {unsafe: [unsafe]}}
                rendered = ci.first_replay_transcript_difference_diagnostic([producer], [replay])
                diagnostic = ci.strict_json_loads(rendered)
                self.assertEqual(set(diagnostic), {
                    "commandId", "changedFieldCategories",
                    "producerRecordDigest", "replayRecordDigest",
                })
                self.assertEqual(diagnostic["commandId"], "baseline-schema")
                self.assertEqual(diagnostic["changedFieldCategories"], [category])
                self.assertTrue(set(diagnostic["changedFieldCategories"]).issubset(categories))
                self.assertEqual(diagnostic["producerRecordDigest"],
                                 ci.canonical_failure_digest(producer))
                self.assertEqual(diagnostic["replayRecordDigest"],
                                 ci.canonical_failure_digest(replay))
                self.assertNotEqual(diagnostic["producerRecordDigest"], diagnostic["replayRecordDigest"])
                self.assertNotIn(unsafe, rendered)
                self.assertLess(len(rendered), 600)
                self.assertEqual(rendered, ci.first_replay_transcript_difference_diagnostic(
                    [dict(reversed(list(producer.items())))], [copy.deepcopy(replay)]
                ))
                left, right = combined_producer, combined_replay
                for key in keys[:-1]:
                    left, right = left.setdefault(key, {}), right.setdefault(key, {})
                left[keys[-1]] = "unchanged-identity"
                right[keys[-1]] = {"stdout": unsafe, "environment": {unsafe: [unsafe]}}
        # An arbitrarily broad record still yields only one finite category set.
        for index in range(100):
            combined_replay[f"{unsafe}:{index}"] = {"content": unsafe}
        rendered = ci.first_replay_transcript_difference_diagnostic(
            [combined_producer], [combined_replay]
        )
        combined_diagnostic = ci.strict_json_loads(rendered)
        self.assertEqual(combined_diagnostic["changedFieldCategories"], sorted(categories))
        self.assertLess(len(rendered), 900)
        self.assertNotIn(unsafe, rendered)

        producer = {"commandId": unsafe, "executionDurationClass": "bounded"}
        replay = {"commandId": unsafe, "executionDurationClass": "not-started"}
        second_producer = {"commandId": "static-suite", "stdoutSha256": "a" * 64}
        second_replay = {"commandId": "static-suite", "stdoutSha256": "b" * 64}
        diagnostic = ci.strict_json_loads(ci.first_replay_transcript_difference_diagnostic(
            [producer, second_producer], [replay, second_replay]
        ))
        self.assertEqual(diagnostic["commandId"], "OTHER")
        self.assertEqual(diagnostic["changedFieldCategories"], ["executionDurationClass"])
        self.assertNotIn(unsafe, json.dumps(diagnostic))
        self.assertEqual(diagnostic["producerRecordDigest"], ci.canonical_failure_digest(producer))
        equal_prefix = {"commandId": "node-version", "exitCode": 0}
        self.assertEqual(diagnostic, ci.strict_json_loads(
            ci.first_replay_transcript_difference_diagnostic(
                [equal_prefix, producer, second_producer],
                [copy.deepcopy(equal_prefix), replay, second_replay],
            )
        ))

        forged = copy.deepcopy(self.documents)
        forged["command-results.json"]["records"][0]["executionDurationClass"] = unsafe
        forged["command-results.json"]["records"][1]["exitCode"] = -99
        errors = self.compare(forged)
        self.assertIn("verification replay command execution transcript mismatch", errors)
        prefix = "verification replay first command difference: "
        differences = [ci.strict_json_loads(error.removeprefix(prefix))
                       for error in errors if error.startswith(prefix)]
        self.assertEqual(len(differences), 1)
        self.assertEqual(differences[0]["commandId"], "baseline-schema")
        self.assertEqual(differences[0]["changedFieldCategories"], ["executionDurationClass"])
        self.assertNotIn(unsafe, "\n".join(errors))


class P52CompactIdentitySecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner, cls.documents, cls.comparison = p52_compact_replay_fixture()

    def compare(self, documents: dict | None = None) -> list[str]:
        return ci.compare_verification_replay_claims(
            copy.deepcopy(documents or self.documents),
            self.runner,
            self.comparison,
        )[1]

    def test_compact_protected_bundle_identity_is_recomputed_from_independent_authority(
        self,
    ) -> None:
        self.assertEqual(self.compare(), [])
        records = self.documents["command-results.json"]["records"]
        for index, (record, expected_command) in enumerate(
            zip(records, self.runner.command_plan)
        ):
            with self.subTest(command=index):
                bundle = record["protectedTargetBundle"]
                for key in ci._PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS:
                    self.assertEqual(bundle[key], [])
                independently_expected_pre = (
                    ci._protected_bundle_compact_identity_digests(
                        expected_command,
                        phase="pre",
                    )
                )
                independently_expected_post = (
                    ci._protected_bundle_compact_identity_digests(
                        expected_command,
                        phase="post",
                    )
                )
                self.assertEqual(
                    bundle["preExecutionIdentities"],
                    independently_expected_pre,
                )
                self.assertEqual(
                    bundle["postExecutionIdentities"],
                    independently_expected_post,
                )
                self.assertNotEqual(
                    bundle["preExecutionIdentities"],
                    bundle["postExecutionIdentities"],
                )
                self.assertEqual(
                    ci._canonical_transcript_record(record),
                    ci._canonical_transcript_record(
                        self.runner.command_results[index]
                    ),
                )

    def test_compact_bundle_digest_forgery_cannot_self_authorize(self) -> None:
        modes = (
            "zero-all",
            "single-pre",
            "single-post",
            "cross-command-digest-swap",
            "pre-post-swap",
            "target-omission",
            "target-reorder",
            "target-duplicate",
            "foreign-target-substitution",
            "reuse-other-command-bundle",
            "execution-input-substitution",
            "manifest-preserving-compact-change",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                forged = copy.deepcopy(self.documents)
                commands = forged["command-results.json"]
                first, second = commands["records"]
                first_bundle = first["protectedTargetBundle"]
                second_bundle = second["protectedTargetBundle"]
                zero = "0" * 64
                if mode == "zero-all":
                    for record in commands["records"]:
                        bundle = record["protectedTargetBundle"]
                        bundle["preExecutionIdentities"] = [
                            zero for _item in bundle["preExecutionIdentities"]
                        ]
                        bundle["postExecutionIdentities"] = [
                            zero for _item in bundle["postExecutionIdentities"]
                        ]
                elif mode == "single-pre":
                    first_bundle["preExecutionIdentities"][0] = zero
                elif mode == "single-post":
                    first_bundle["postExecutionIdentities"][0] = zero
                elif mode == "cross-command-digest-swap":
                    (
                        first_bundle["preExecutionIdentities"][0],
                        second_bundle["preExecutionIdentities"][0],
                    ) = (
                        second_bundle["preExecutionIdentities"][0],
                        first_bundle["preExecutionIdentities"][0],
                    )
                elif mode == "pre-post-swap":
                    (
                        first_bundle["preExecutionIdentities"],
                        first_bundle["postExecutionIdentities"],
                    ) = (
                        first_bundle["postExecutionIdentities"],
                        first_bundle["preExecutionIdentities"],
                    )
                elif mode == "target-omission":
                    first["targets"] = first["targets"][:-1]
                    coherently_refresh_p52_compact_record(first)
                elif mode == "target-reorder":
                    first["targets"] = list(reversed(first["targets"]))
                    coherently_refresh_p52_compact_record(first)
                elif mode == "target-duplicate":
                    first["targets"] = [
                        copy.deepcopy(first["targets"][0]),
                        copy.deepcopy(first["targets"][0]),
                    ]
                    coherently_refresh_p52_compact_record(first)
                elif mode == "foreign-target-substitution":
                    first["targets"][1] = copy.deepcopy(second["targets"][1])
                    coherently_refresh_p52_compact_record(first)
                elif mode == "reuse-other-command-bundle":
                    first_bundle["preExecutionIdentities"] = copy.deepcopy(
                        second_bundle["preExecutionIdentities"]
                    )
                    first_bundle["postExecutionIdentities"] = copy.deepcopy(
                        second_bundle["postExecutionIdentities"]
                    )
                elif mode == "execution-input-substitution":
                    first["executionInputs"] = [
                        p52_execution_input_from_target(target)
                        for target in first["targets"]
                    ]
                    first["executionInputs"][0]["plannedSha256"] = "f" * 64
                    first["executionInputs"][0]["actualSha256"] = "f" * 64
                    first["executionInputBundleDigest"] = (
                        ci.execution_input_bundle_digest(first["executionInputs"])
                    )
                    first_bundle["executionInputBundleDigest"] = first[
                        "executionInputBundleDigest"
                    ]
                else:
                    first_bundle["preExecutionIdentities"][0] = zero
                if mode != "manifest-preserving-compact-change":
                    coherently_rebind_claimed_transcript(forged)
                errors = self.compare(forged)
                self.assertTrue(errors, mode)
                self.assertTrue(
                    any("transcript" in error.casefold() for error in errors),
                    errors,
                )

    def test_compact_execution_input_reference_rejects_digest_and_expansion_forgery(
        self,
    ) -> None:
        self.assertEqual(self.compare(), [])
        for mode in ("digest", "forged-expansion", "coherent-target-content"):
            with self.subTest(mode=mode):
                forged = copy.deepcopy(self.documents)
                record = forged["command-results.json"]["records"][0]
                self.assertEqual(record["executionInputs"], [])
                if mode == "digest":
                    record["executionInputBundleDigest"] = "f" * 64
                    record["protectedTargetBundle"][
                        "executionInputBundleDigest"
                    ] = "f" * 64
                elif mode == "forged-expansion":
                    record["executionInputs"] = [
                        p52_execution_input_from_target(target)
                        for target in record["targets"]
                    ]
                    record["executionInputs"][0]["actualSha256"] = "f" * 64
                    record["executionInputBundleDigest"] = (
                        ci.execution_input_bundle_digest(record["executionInputs"])
                    )
                    record["protectedTargetBundle"][
                        "executionInputBundleDigest"
                    ] = record["executionInputBundleDigest"]
                else:
                    record["targets"][0]["sha256"] = "f" * 64
                    coherently_refresh_p52_compact_record(record)
                coherently_rebind_claimed_transcript(forged)
                errors = self.compare(forged)
                self.assertTrue(errors, mode)
                self.assertTrue(
                    any("transcript" in error.casefold() for error in errors),
                    errors,
                )


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
        canonical_fixture_executable = ci.require_tool(
            {"python": sys.executable},
            "python",
            phase="SELF_TEST_PLAN_FIXTURE",
        )
        self.assertEqual(
            Path(canonical_fixture_executable),
            Path(sys.executable).resolve(strict=True),
        )
        self.assertTrue(
            ci._same_file_identity(
                Path(canonical_fixture_executable),
                Path(sys.executable),
            )
        )
        tools = {
            "python": canonical_fixture_executable,
            "node": canonical_fixture_executable,
            "npm": canonical_fixture_executable,
            "git": canonical_fixture_executable,
            "bash": canonical_fixture_executable,
            "powershell": canonical_fixture_executable,
        }
        candidates = [
            "developer/tests/ci/run_static_suite.py",
            "developer/tests/ci/test_standalone_packaging.py",
            ci.MESSAGE_ORIGIN_SECURITY_GUARD,
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
                    if command_id == "frontend-security:messageOriginGuard.test.js":
                        trusted_node = ci.require_tool(
                            tools,
                            "node",
                            phase="SELF_TEST_PLAN_EXPECTATION",
                        )
                        expected_argv = [
                            trusted_node,
                            "--test",
                            ci.MESSAGE_ORIGIN_SECURITY_GUARD,
                        ]
                        self.assertEqual(command["argv"], expected_argv)
                        self.assertEqual(command["logicalArgv"], expected_argv)
                        self.assertEqual(command["executionArgv"], expected_argv)
                        self.assertEqual(
                            command["toolRole"], "node-builtin-security-test"
                        )
                        self.assertNotIn(
                            command["toolRole"], ci.DEPENDENCY_BACKED_TOOL_ROLES
                        )
                        self.assertTrue(command["required"])
                        self.assertEqual(command["commandRole"], "observation-producing")
                        self.assertEqual(
                            [
                                target["path"]
                                for target in command["targets"]
                                if target["path"] == ci.MESSAGE_ORIGIN_SECURITY_GUARD
                            ],
                            [ci.MESSAGE_ORIGIN_SECURITY_GUARD],
                        )
                        self.assertFalse(
                            any(
                                "node_modules" in Path(target["path"]).parts
                                for target in command["targets"]
                            )
                        )
                for command in plan:
                    if command["targets"]:
                        self.assertIn(
                            command["executionInputMode"],
                            {"PROTECTED-TARGET-BUNDLE", "TARGET-BYTES-STDIN"},
                            command["commandId"],
                        )
        guard_source = ci.REPO_ROOT.joinpath(
            *ci.MESSAGE_ORIGIN_SECURITY_GUARD.split("/")
        ).read_text(encoding="utf-8")
        self.assertIn("from 'node:test'", guard_source)
        self.assertIn("from 'node:assert/strict'", guard_source)
        self.assertNotIn("vitest", guard_source.casefold())
        self.assertNotRegex(guard_source, r"\.(?:skip|todo|only)\b")

    def test_posix_snapshot_root_and_descendant_translation_is_exactly_bounded(
        self,
    ) -> None:
        snapshot_root = "/tmp/cs-abc"
        repository_root = "/srv/IELTS/Repo"
        positive_cases = {
            "bare-root": (snapshot_root, repository_root),
            "direct-child": (
                f"{snapshot_root}/result.json",
                f"{repository_root}/result.json",
            ),
            "deeper-descendant": (
                f"{snapshot_root}/reports/static/result.json",
                f"{repository_root}/reports/static/result.json",
            ),
        }
        for label, (observed, expected) in positive_cases.items():
            with self.subTest(positive=label):
                self.assertEqual(
                    ci._translate_snapshot_output_paths(
                        observed,
                        snapshot_root,
                        repository_root,
                    ),
                    expected,
                )
                self.assertEqual(
                    ci._translate_snapshot_output_bytes(
                        observed.encode("utf-8"),
                        snapshot_root,
                        repository_root,
                    ),
                    expected.encode("utf-8"),
                )

        negative_cases = {
            "near-prefix": f"{snapshot_root}d/result.json",
            "unrelated-root": "/tmp/cs-unrelated/result.json",
            "parent-directory": "/tmp",
            "generic-temp-descendant": "/tmp/arbitrary/result.json",
        }
        for label, observed in negative_cases.items():
            with self.subTest(negative=label):
                self.assertEqual(
                    ci._translate_snapshot_output_paths(
                        observed,
                        snapshot_root,
                        repository_root,
                    ),
                    observed,
                )
                self.assertEqual(
                    ci._translate_snapshot_output_bytes(
                        observed.encode("utf-8"),
                        snapshot_root,
                        repository_root,
                    ),
                    observed.encode("utf-8"),
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
        raw_lines = capture.stdout.splitlines()
        identity_lines = capture.identity_stdout.splitlines()
        self.assertEqual(raw_lines[:2], ["planned", "1"])
        self.assertNotEqual(raw_lines[2], str(self.root.resolve()))
        self.assertEqual(identity_lines[:2], ["planned", "1"])
        self.assertEqual(identity_lines[2], str(self.root.resolve()))
        self.assertEqual(
            identity_lines[3],
            json.dumps({"root": str(self.root.resolve())}, sort_keys=True),
        )
        self.assertEqual(capture.stdout_raw, capture.stdout.encode("utf-8"))
        self.assertEqual(capture.stdout_bytes, len(capture.stdout.encode("utf-8")))
        self.assertEqual(
            capture.identity_stdout_raw,
            capture.identity_stdout.encode("utf-8"),
        )
        self.assertNotEqual(capture.stdout_raw, capture.identity_stdout_raw)
        first_capture = contained_capture()
        second_capture = contained_capture()
        first_capture.stdout = "raw-first"
        first_capture.stdout_raw = b"raw-first"
        first_capture.stdout_bytes = len(first_capture.stdout_raw)
        second_capture.stdout = "raw-second"
        second_capture.stdout_raw = b"raw-second"
        second_capture.stdout_bytes = len(second_capture.stdout_raw)
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
        self.assertEqual(first_capture.stdout_raw, b"raw-first")
        self.assertEqual(second_capture.stdout_raw, b"raw-second")
        self.assertEqual(
            first_capture.identity_stdout_raw,
            second_capture.identity_stdout_raw,
        )
        self.assertIn(
            "Ran 18 tests in <duration>s",
            first_capture.identity_stdout,
        )
        self.assertEqual(evidence["cleanupState"], "closed")
        self.assertFalse(evidence["mutationDetected"])
        self.assertEqual(
            [item["actualSha256"] for item in evidence["executionInputs"]],
            [item["plannedSha256"] for item in evidence["executionInputs"]],
        )

        with self.subTest(command="message-origin-node-builtin"):
            policy, tools = _resolved_local_test_authority("python", "git", "node")
            source_environment = _explicit_local_test_environment()
            source_environment.pop("NODE_PATH", None)
            source_environment.pop("NODE_OPTIONS", None)
            candidate_paths, candidate_errors = ci.deterministic_candidate_paths(
                ci.REPO_ROOT
            )
            self.assertEqual(candidate_errors, [])
            protected_root = self.root / "message-origin-projection"
            protected_root.mkdir()
            for relative in candidate_paths:
                source = ci.REPO_ROOT.joinpath(*relative.split("/"))
                destination = protected_root.joinpath(*relative.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            self.assertFalse((protected_root / "developer" / "node_modules").exists())
            self.assertFalse(
                (
                    protected_root
                    / "developer"
                    / "node_modules"
                    / "vitest"
                    / "vitest.mjs"
                ).exists()
            )
            plan = ci.build_profile_command_plan(
                "frontend",
                tools=tools,
                candidate_paths=candidate_paths,
                baseline=ci.strict_json_load_file(ci.BASELINE_PATH),
                current_platform=ci.platform_key(),
                static_invocation_id=ci.deterministic_static_invocation_id(
                    protected_root
                ),
                repo_root=protected_root,
            )
            command = next(
                item
                for item in plan
                if item["commandId"]
                == "frontend-security:messageOriginGuard.test.js"
            )
            child_environment = ci.child_process_environment(
                tools,
                source_environment=source_environment,
                repo_root=protected_root,
                policy=policy,
            )
            child_environment["NODE_PATH"] = str(
                protected_root / "unauthorized-node-path"
            )
            child_environment["NODE_OPTIONS"] = (
                "--require=./unauthorized-node-loader.cjs"
            )
            observed_environment: dict[str, str] = {}
            original_execute_command = ci.execute_command

            def observe_execute_command(*args, **kwargs):
                observed_environment.update(kwargs.get("env") or {})
                return original_execute_command(*args, **kwargs)

            node_lease = ci.ExecutableIdentityLease(
                tools["node"], "r04-trusted-node"
            )
            try:
                with mock.patch.object(
                    ci,
                    "execute_command",
                    side_effect=observe_execute_command,
                ):
                    capture, bundle = ci.execute_planned_static_suite(
                        command,
                        repo_root=protected_root,
                        env=child_environment,
                        timeout=180,
                        executable_lease=node_lease,
                    )
            finally:
                node_lease.close()
            self.assertTrue(
                capture.execution_passed(), capture.stdout + capture.stderr
            )
            self.assertEqual(
                capture.argv,
                [tools["node"], "--test", ci.MESSAGE_ORIGIN_SECURITY_GUARD],
            )
            self.assertNotIn("NODE_PATH", observed_environment)
            self.assertNotIn("NODE_OPTIONS", observed_environment)
            self.assertEqual(bundle["cleanupState"], "closed")
            self.assertFalse(bundle["mutationDetected"])
            self.assertEqual(
                [item["actualSha256"] for item in bundle["executionInputs"]],
                [item["plannedSha256"] for item in bundle["executionInputs"]],
            )
            self.assertFalse((protected_root / "developer" / "node_modules").exists())

    def test_bundle_snapshot_gets_only_derived_git_membership_ignore_and_attribute_authority(
        self,
    ) -> None:
        git = _explicit_local_test_tool_map("git")["git"]
        fixture_files = {
            ".gitattributes": "*.txt text eol=lf\n",
            ".gitignore": "*.tmp\n",
            "tracked.txt": "protected bytes\n",
            "check_git.py": (
                "import os, subprocess\n"
                "def run(*args):\n"
                "    return subprocess.run(['git', *args], text=True, encoding='utf-8', "
                "errors='replace', stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
                "tracked = run('ls-files', '--error-unmatch', '--', 'tracked.txt')\n"
                "ignored = run('check-ignore', '--quiet', '--no-index', '--', 'tracked.txt')\n"
                "attribute = run('-c', 'core.autocrlf=true', 'check-attr', 'eol', '--', 'tracked.txt')\n"
                "inventory = run('ls-files')\n"
                "assert tracked.returncode == 0, tracked.stderr\n"
                "assert ignored.returncode == 1, ignored.stderr\n"
                "assert attribute.returncode == 0 and attribute.stdout.endswith(': eol: lf\\n'), "
                "attribute.stderr + attribute.stdout\n"
                "assert '.git/' not in inventory.stdout\n"
                "assert os.environ['GIT_CONFIG_NOSYSTEM'] == '1'\n"
                "assert os.environ['GIT_ATTR_NOSYSTEM'] == '1'\n"
                "assert run('config', '--global', '--list').stdout == ''\n"
                "print('protected-git-projection-ok')\n"
            ),
        }
        for relative, value in fixture_files.items():
            (self.root / relative).write_text(value, encoding="utf-8", newline="")
        targets = [
            ci._target_authority(self.root, relative)
            for relative in fixture_files
        ]
        spec = synthetic_command_spec(
            "bundle-normalization",
            "bundle-parity",
            0,
            targets=targets,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        argv = [sys.executable, "-B", "check_git.py"]
        spec["argv"] = argv
        spec["logicalArgv"] = argv
        spec["executionArgv"] = argv
        environment = ci.child_process_environment(
            {"python": sys.executable, "git": git},
            source_environment=_explicit_local_test_environment(),
        )
        capture, evidence = ci.execute_planned_static_suite(
            spec,
            repo_root=self.root,
            env=environment,
            timeout=30,
        )
        self.assertTrue(capture.execution_passed(), capture.stdout + capture.stderr)
        self.assertEqual(capture.stdout.strip(), "protected-git-projection-ok")
        self.assertEqual(evidence["cleanupState"], "closed")
        self.assertFalse(evidence["mutationDetected"])
        self.assertEqual(len(evidence["executionInputs"]), len(fixture_files))


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
        release_gate_required: bool | None = None,
    ) -> dict:
        authority = ci.WORKFLOW_JOB_PROFILE_AUTHORITY[job_id]
        if release_gate_required is None:
            release_gate_required = ci.resolve_release_gate_required(
                str(authority["verificationProfile"])
            )
        binding = {
            "bindingSchemaVersion": ci.EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
            "bindingKind": "ProducerExecutionBinding",
            "bindingMode": "github-actions",
            "producerJobId": authority["producerJobId"],
            "producerRunnerOS": authority["runnerOS"],
            "producerProfile": authority["verificationProfile"],
            "releaseGateRequired": release_gate_required,
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

    def binding_runner(self, profile: str) -> SimpleNamespace:
        return SimpleNamespace(
            profile=profile,
            release_gate_required=ci.resolve_release_gate_required(profile),
            baseline={
                "baselineCommit": ci.BASELINE_COMMIT,
                "baselineTree": ci.BASELINE_TREE,
            },
            command_plan_digest="9" * 64,
            child_environment={},
            tools={"git": sys.executable},
            tool_resolution_errors=[],
        )

    def test_explicit_synthetic_authority_isolated_from_opposite_ambient_github_os(self) -> None:
        cases = (
            (
                "Windows",
                "windows-compatibility-producer",
                {
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_JOB": "ubuntu-canonical-producer",
                    "RUNNER_OS": "Linux",
                    "GITHUB_RUN_ID": "7001",
                    "GITHUB_RUN_ATTEMPT": "3",
                    "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REPOSITORY": "ambient/linux",
                    "GITHUB_SHA": "a" * 40,
                },
            ),
            (
                "Linux",
                "ubuntu-canonical-producer",
                {
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_JOB": "windows-compatibility-producer",
                    "RUNNER_OS": "Windows",
                    "GITHUB_RUN_ID": "8001",
                    "GITHUB_RUN_ATTEMPT": "4",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REPOSITORY": "ambient/windows",
                    "GITHUB_SHA": "b" * 40,
                },
            ),
        )
        with mock.patch.object(
            ci,
            "current_checkout_identity",
            return_value=(ci.BASELINE_COMMIT, ci.BASELINE_TREE),
        ), mock.patch.object(
            ci, "ci_trust_file_set_authority", return_value=([], "8" * 64)
        ):
            for runner_os, producer_job, ambient in cases:
                with self.subTest(runner_os=runner_os), mock.patch.dict(
                    os.environ, ambient, clear=False
                ):
                    authority = ci.synthetic_execution_external_authority(
                        runner_os=runner_os,
                        job_id=producer_job,
                        run_id="999999999",
                        run_attempt="7",
                        event_name="push",
                        repository="synthetic/fixture",
                        checkout_sha=ci.BASELINE_COMMIT,
                    )
                    binding = ci.build_synthetic_generation_execution_binding(
                        self.binding_runner("all"),
                        external_authority=authority,
                    )
                    self.assertEqual(binding["producerRunnerOS"], runner_os)
                    self.assertEqual(binding["producerJobId"], producer_job)
                    self.assertEqual(binding["repository"], "synthetic/fixture")
                    self.assertNotEqual(binding["repository"], ambient["GITHUB_REPOSITORY"])

    def test_production_binding_rejects_synthetic_authority_and_has_no_override_flag(self) -> None:
        synthetic = ci.synthetic_execution_external_authority(
            runner_os="Windows",
            job_id="windows-compatibility-producer",
            checkout_sha=ci.BASELINE_COMMIT,
        )
        with self.assertRaisesRegex(ValueError, "forbidden in production"):
            ci.build_generation_execution_binding(
                self.binding_runner("all"),
                external_authority=synthetic,
            )
        for option in ("--runner-os", "--github-job", "--external-authority-json"):
            with self.subTest(option=option), self.assertRaises((ValueError, SystemExit)):
                ci.parse_args(["--profile", "policy", option, "attacker-value"])
        source = {
            "CI_SYNTHETIC_EXTERNAL_AUTHORITY": "attacker",
            "GITHUB_ACTIONS": "false",
        }
        captured = ci.capture_live_external_authority(source)
        self.assertEqual(captured.source_kind, "live")
        self.assertEqual(captured.binding_mode, "local")

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
                    release_gate_required=False,
                    expected_producer_job=None,
                    expected_verifier_job=None,
                    expected_runner_os=None,
                    expected_invocation_id=None,
                    command_plan_digest_value="7" * 64,
                    fresh_runtime_closure_digest="8" * 64,
                    baseline=ci.strict_json_load_file(ci.BASELINE_PATH),
                    git=sys.executable,
                    child_environment={},
                    external_authority=ci.capture_live_external_authority({}),
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
                            release_gate_required=ci.resolve_release_gate_required(
                                expected_profile
                            ),
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
                            external_authority=ci.capture_live_external_authority(
                                environment
                            ),
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

        policy, tools = _resolved_local_test_authority("python", "node", "git")
        local_source = _explicit_local_test_environment()
        runner = ci.FoundationRunner(
            "policy",
            ci.strict_json_load_file(ci.BASELINE_PATH),
            tools=tools,
            tool_policy=policy,
            source_environment=local_source,
        )
        try:
            records, digest = ci.ci_trust_file_set_authority(
                git=runner.require_tool("git", phase="EXECUTION_BINDING"),
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
            release_gate_required=False,
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
            self.assertEqual(
                downloads[0]["with"]["path"],
                "${{ runner.temp }}/ci-untrusted/" + verifier,
            )
            shell_root = "$env:RUNNER_TEMP" if verifier == "windows-compatibility" else "$RUNNER_TEMP"
            self.assertIn(
                f'--untrusted-evidence-root "{shell_root}/ci-untrusted/{verifier}"',
                jobs[verifier]["steps"][-1]["run"],
            )
            self.assertEqual(uploads[0]["with"]["path"].splitlines(), [
                f".ci-results/{name}" for name in ci.EVIDENCE_FILE_NAMES
            ])
            names.append(authority["artifactIdentity"])
        self.assertEqual(len(names), len(set(names)))
        self.assert_external_download_preserves_candidate_authority(parsed)

    def assert_external_download_preserves_candidate_authority(self, parsed: dict) -> None:
        policy, tools = _resolved_local_test_authority("python", "git")
        with tempfile.TemporaryDirectory(prefix="ci-verifier-isolation-") as temp_dir:
            workspace = Path(temp_dir).resolve(strict=True)
            checkout = workspace / "checkout"
            runner_temp = workspace / "runner temp"
            checkout.mkdir()
            runner_temp.mkdir()
            (checkout / "tracked.txt").write_bytes(b"public fixture\n")
            environment = ci.child_process_environment(
                tools,
                source_environment=_explicit_local_test_environment(),
                repo_root=checkout,
                policy=policy,
            )
            for arguments in (("init", "--quiet"), ("add", "--", "tracked.txt")):
                completed = subprocess.run(
                    [tools["git"], "-c", f"safe.directory={checkout}", *arguments],
                    cwd=checkout,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            planned_paths, errors = ci.deterministic_candidate_paths(checkout)
            self.assertEqual(errors, [])
            self.assertEqual(planned_paths, ["tracked.txt"])
            original_execute = ci.execute_command

            def execute_in_checkout(*args, **kwargs):
                kwargs["cwd"] = checkout
                return original_execute(*args, **kwargs)

            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(ci, "REPO_ROOT", checkout))
                stack.enter_context(mock.patch.object(ci, "execute_command", side_effect=execute_in_checkout))
                leases = {
                    name: ci.ExecutableIdentityLease(path, f"isolation-{name}")
                    for name, path in tools.items()
                }
                for lease in leases.values():
                    stack.callback(lease.close)
                plan = ci.build_profile_command_plan(
                    "policy",
                    tools={**tools, "node": tools["python"]},
                    candidate_paths=planned_paths,
                    baseline=ci.strict_json_load_file(ci.BASELINE_PATH),
                    current_platform=ci.platform_key(),
                    static_invocation_id=str(uuid.uuid4()),
                    repo_root=checkout,
                )
                scan_ids = {"tracked-private-resource-scan", "tracked-secret-scan"}
                scan_plan = {
                    item["commandId"]: item for item in plan if item["commandId"] in scan_ids
                }

                def fresh_runner():
                    runner = object.__new__(ci.FoundationRunner)
                    runner.tools = tools
                    runner.tool_policy = policy
                    runner.tool_leases = leases
                    runner.tool_authority_frozen = True
                    runner.tool_resolution_errors = []
                    runner.child_environment = environment
                    runner.planned_candidate_paths = planned_paths
                    runner.candidate_paths = None
                    runner.command_plan_by_id = scan_plan
                    runner.target_phase_hook = None
                    runner.captures = []
                    runner.command_results = []
                    runner.hard_gate_results = []
                    runner.violations = []
                    return runner

                before = fresh_runner()
                self.assertEqual(before.ensure_candidate_paths(), planned_paths)
                self.assertEqual(before.violations, [])
                for verifier in ci.WORKFLOW_JOB_PROFILE_AUTHORITY:
                    with self.subTest(external_download=verifier):
                        download = next(
                            step for step in parsed["jobs"][verifier]["steps"]
                            if str(step.get("uses", "")).startswith("actions/download-artifact@")
                        )
                        evidence_root = Path(download["with"]["path"].replace(
                            "${{ runner.temp }}", str(runner_temp)
                        ))
                        evidence_root.mkdir(parents=True)
                        self.assertTrue(evidence_root.is_absolute())
                        self.assertFalse(_path_is_relative_to(evidence_root.resolve(), checkout))
                        for name in ci.EVIDENCE_FILE_NAMES:
                            (evidence_root / name).write_bytes(b"downloaded untrusted evidence\n")
                        self.assertEqual(
                            ci.deterministic_candidate_paths(checkout), (planned_paths, [])
                        )
                        replay = fresh_runner()
                        self.assertEqual(replay.ensure_candidate_paths(), planned_paths)
                        replay.run_private_and_secret_policy()
                        self.assertEqual(replay.violations, [])
                        self.assertEqual({
                            record["commandId"] for record in replay.command_results
                            if record["commandId"] in scan_ids
                        }, scan_ids)
                        for record in replay.command_results:
                            if record["commandId"] in scan_ids:
                                self.assertEqual(record["exitCode"], 0, record)
                                self.assertFalse(record["protectedTargetBundle"]["mutationDetected"])
                clean = fresh_runner()
                clean.run_repository_boundary()
                self.assertEqual(clean.violations, [])

                for relative in (".ci-untrusted/unexpected.json", "unexpected-candidate.txt"):
                    with self.subTest(in_repository_mutation=relative):
                        unexpected = checkout.joinpath(*relative.split("/"))
                        unexpected.parent.mkdir(parents=True, exist_ok=True)
                        unexpected.write_bytes(b"unexpected candidate\n")
                        try:
                            replay = fresh_runner()
                            replay.run_repository_boundary()
                            self.assertIn(relative, replay.candidate_paths)
                            boundary_failures = [
                                gate["detail"] for gate in replay.hard_gate_results
                                if gate["id"] == "REPOSITORY-GIT-BOUNDARY" and gate["status"] == "fail"
                            ]
                            self.assertTrue(any("precomputed index authority" in detail for detail in boundary_failures))
                            self.assertTrue(any("unexpected untracked paths" in detail for detail in boundary_failures))
                            replay.run_private_and_secret_policy()
                            self.assert_protected_scans_fail_closed(replay, scan_ids)
                            self.assertEqual(
                                ci.deterministic_candidate_paths(checkout), (planned_paths, [])
                            )
                        finally:
                            unexpected.unlink()
                with self.subTest(tracked_bytes_mutation=True):
                    tracked = checkout / "tracked.txt"
                    tracked.write_bytes(b"mutate fixture\n")
                    replay = fresh_runner()
                    replay.run_private_and_secret_policy()
                    self.assertEqual(replay.candidate_paths, planned_paths)
                    self.assert_protected_scans_fail_closed(replay, scan_ids)

    def assert_protected_scans_fail_closed(self, runner, scan_ids: set[str]) -> None:
        scans = {
            record["commandId"]: record for record in runner.command_results
            if record["commandId"] in scan_ids
        }
        self.assertEqual(set(scans), scan_ids)
        for command_id, record in scans.items():
            self.assertNotEqual(record["exitCode"], 0, command_id)
            self.assertIn(
                "PROTECTED-TARGET-BUNDLE-ERROR",
                record["parsedFailureSummary"]["diagnostic"],
            )
        failed_gates = {
            gate["id"] for gate in runner.hard_gate_results if gate["status"] == "fail"
        }
        self.assertTrue({
            "TRACKED-PRIVATE-RESOURCE-EXCLUSION",
            "SECRET-OPERATIONAL-ARTIFACT-EXCLUSION",
        }.issubset(failed_gates))

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
            approved_python = ci.require_tool(
                {"python": sys.executable},
                "python",
                phase="VERIFICATION_PREPARATION",
            )
            terminal_verifier_argv = [
                approved_python,
                "-B",
                str(Path(ci.__file__).resolve(strict=True)),
                "--verify-evidence",
            ]
            self.assertTrue(Path(terminal_verifier_argv[0]).is_absolute())
            self.assertTrue(
                ci._same_file_identity(
                    Path(terminal_verifier_argv[0]), Path(sys.executable)
                )
            )
            self.assertIn(
                str(Path(approved_python).parent.resolve(strict=True)),
                child["PATH"].split(os.pathsep),
            )
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
                '--untrusted-evidence-root "$RUNNER_TEMP/ci-untrusted/ubuntu-canonical"',
                '--untrusted-evidence-root "$RUNNER_TEMP/ci-untrusted/windows-compatibility"',
            ),
        }
        for label, (source, replacement) in substitutions.items():
            with self.subTest(label=label):
                self.assert_rejected(self.workflow.replace(source, replacement, 1), label)
        for verifier in ci.WORKFLOW_JOB_PROFILE_AUTHORITY:
            download_root = "${{ runner.temp }}/ci-untrusted/" + verifier
            shell_root = "$env:RUNNER_TEMP" if verifier == "windows-compatibility" else "$RUNNER_TEMP"
            invocation_root = f'"{shell_root}/ci-untrusted/{verifier}"'
            for label, download_replacement, invocation_replacement in (
                ("relative-checkout", f".ci-untrusted/{verifier}", f".ci-untrusted/{verifier}"),
                ("absolute-checkout", "${{ github.workspace }}/.ci-untrusted/" + verifier,
                 f'"{shell_root.replace("RUNNER_TEMP", "GITHUB_WORKSPACE")}/.ci-untrusted/{verifier}"'),
                ("external-parent", "${{ runner.temp }}/ci-untrusted", f'"{shell_root}/ci-untrusted"'),
                ("external-sibling", download_root + "-other", invocation_root[:-1] + '-other"'),
            ):
                with self.subTest(verifier=verifier, root_mutation=label):
                    self.assert_rejected(
                        self.workflow.replace(download_root, download_replacement, 1),
                        f"{verifier}-{label}-download",
                    )
                    self.assert_rejected(
                        self.workflow.replace(invocation_root, invocation_replacement, 1),
                        f"{verifier}-{label}-invocation",
                    )

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

    def test_parent_reaped_grandchild_retires_only_after_exact_death_proof(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        parent = self.identity(20, 10)
        grandchild = self.identity(30, 20)
        state.observe({20: parent, 30: grandchild})
        state.observe({20: parent})
        self.assertIn(grandchild.key(), state.active_keys)
        state.retire_proven_dead_non_children({20: parent})
        self.assertNotIn(grandchild.key(), state.active_keys)
        self.assertIn(grandchild.key(), state.proven_dead_keys)
        state.mark_reaped(parent.pid)
        self.assertTrue(state.clean(), state.failures)

    def test_direct_child_disappearance_requires_supervisor_reap(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        child = self.identity(20, 10)
        state.observe({20: child})
        state.observe({})
        state.retire_proven_dead_non_children({})
        self.assertIn(child.key(), state.active_keys)
        self.assertFalse(state.clean())
        state.mark_reaped(child.pid)
        self.assertTrue(state.clean(), state.failures)

    def test_pidfd_exit_retires_non_child_but_never_direct_child(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        parent = self.identity(20, 10)
        grandchild = self.identity(30, 20)
        state.observe({20: parent, 30: grandchild})
        state.retire_proven_dead_non_children(
            {20: parent, 30: grandchild},
            pidfd_exited={grandchild.key(), parent.key()},
        )
        self.assertNotIn(grandchild.key(), state.active_keys)
        self.assertIn(parent.key(), state.active_keys)

    def test_live_daemon_setsid_and_parent_first_exit_remain_blocking(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        parent = self.identity(20, 10)
        daemon = self.identity(30, 20, group=30, session=30)
        state.observe({20: parent, 30: daemon})
        state.mark_reaped(parent.pid)
        reparented = self.identity(
            30,
            10,
            start=daemon.starttime,
            group=99,
            session=99,
            generation=2,
        )
        state.observe({30: reparented})
        state.retire_proven_dead_non_children({30: reparented})
        self.assertIn(daemon.key(), state.active_keys)
        self.assertFalse(state.clean())

    def test_pid_reuse_and_unavailable_proc_evidence_fail_closed(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        parent = self.identity(20, 10)
        grandchild = self.identity(30, 20, start=3000)
        state.observe({20: parent, 30: grandchild})
        reused = self.identity(30, 1, start=3001, generation=2)
        state.observe({20: parent, 30: reused})
        state.retire_proven_dead_non_children({20: parent, 30: reused})
        self.assertIn(grandchild.key(), state.active_keys)
        self.assertTrue(any("PID reuse" in error for error in state.failures))

        unavailable = ci.PosixContainmentStateMachine(10)
        parent = self.identity(40, 10)
        grandchild = self.identity(50, 40)
        unavailable.observe({40: parent, 50: grandchild})
        unavailable.retire_proven_dead_non_children(None)
        self.assertIn(grandchild.key(), unavailable.active_keys)
        self.assertTrue(
            any("evidence is unavailable" in error for error in unavailable.failures),
            unavailable.failures,
        )

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

    def test_truth_outcome_distinguishes_natural_exit_and_reap(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        child = self.identity(20, 10)
        state.observe({20: child})
        state.mark_reaped(20)
        outcome = state.outcome()
        self.assertTrue(outcome["cleanupComplete"])
        self.assertEqual(outcome["descendantsObserved"], 1)
        self.assertEqual(outcome["descendantsReaped"], 1)
        self.assertEqual(outcome["descendantsSurviving"], 0)
        self.assertEqual(outcome["containmentDisposition"], "natural-exit-reaped")

    def test_truth_outcome_distinguishes_forced_termination(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        child = self.identity(20, 10)
        state.observe({20: child})
        state.mark_reaped(20)
        outcome = state.outcome(cleanup_signal_sent=True, forced_terminated=1)
        self.assertTrue(outcome["cleanupComplete"])
        self.assertEqual(outcome["descendantsSurviving"], 0)
        self.assertEqual(outcome["containmentDisposition"], "forced-terminated")

    def test_truth_outcome_rejects_survivor_and_unknown_ancestry(self) -> None:
        state = ci.PosixContainmentStateMachine(10)
        state.observe({20: self.identity(20, 10)})
        survivor = state.outcome()
        self.assertFalse(survivor["cleanupComplete"])
        self.assertEqual(survivor["descendantsSurviving"], 1)
        self.assertEqual(survivor["containmentDisposition"], "survivor")
        state.fail("unprovable descendant ancestry")
        unknown = state.outcome()
        self.assertFalse(unknown["cleanupComplete"])
        self.assertEqual(unknown["containmentDisposition"], "unknown-ancestry")


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
    def local_tool_authority(self) -> tuple[ci.ToolAuthorityPolicy, dict[str, str]]:
        return _resolved_local_test_authority("python", "node", "git")

    @staticmethod
    def make_hostile_path_fixture_executable(path: Path) -> None:
        if os.name != "nt":
            path.chmod(stat.S_IMODE(path.stat().st_mode) | 0o111)

    def make_guard(
        self,
        root: Path,
        *,
        watcher_factory=ci._ModelMutationWatcher,
        lease_path: Path | None = None,
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
        tool = root / "trusted-node" if lease_path is None else lease_path
        if lease_path is None:
            tool.write_bytes(b"trusted-tool")
        document = {
            "dependencyRoots": [{"logicalRoot": "developer/node_modules"}],
            "lockfiles": [
                {"relativePath": "developer/package-lock.json"},
                {"relativePath": "backend/package-lock.json"},
            ],
            "vitest": None,
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
            watcher_factory=watcher_factory,
        )
        return closure, guard, helper

    def wait_for_guard(self, predicate, label: str, *, timeout: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail(f"timed out waiting for runtime dependency watcher: {label}")

    def test_runtime_dependency_closure_schema_and_digest(self) -> None:
        policy, tools = self.local_tool_authority()
        local_source = _explicit_local_test_environment()
        runner = ci.FoundationRunner(
            "policy",
            ci.strict_json_load_file(ci.BASELINE_PATH),
            tools=tools,
            tool_policy=policy,
            source_environment=local_source,
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
            self.assertIsNone(document["vitest"])
            self.assertIsNotNone(runner.runtime_dependency_closure)
            self.assertNotIn("vitest", runner.runtime_dependency_closure.leases)
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

    def test_tool_authority_failure_is_a_typed_unmeasured_precondition(self) -> None:
        runner = ci.FoundationRunner(
            "policy",
            ci.strict_json_load_file(ci.BASELINE_PATH),
            tools={},
            enable_runtime_closure=True,
        )
        try:
            self.assertIsNone(runner.runtime_dependency_closure)
            self.assertEqual(
                runner.runtime_closure_document["measurementStatus"],
                ci.RUNTIME_CLOSURE_PRECONDITION_STATUS,
            )
            self.assertEqual(
                runner.runtime_closure_document["preconditionReason"],
                "TOOL_AUTHORITY_NOT_FROZEN",
            )
            self.assertEqual(
                runner.runtime_closure_errors,
                ["PRECONDITION_NOT_MET reason=TOOL_AUTHORITY_NOT_FROZEN"],
            )
            runner.run_runtime_policy()
            gate = next(
                item
                for item in runner.hard_gate_results
                if item["id"] == "RUNTIME-DEPENDENCY-CLOSURE-SETUP"
            )
            self.assertEqual(gate["status"], "fail")
        finally:
            runner.cleanup_task_resources()

    def test_local_nondependency_and_full_measurement_status_matrix(self) -> None:
        baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        policy, tools = self.local_tool_authority()
        local_source = _explicit_local_test_environment()
        local_runner = ci.FoundationRunner(
            "policy",
            baseline,
            tools=tools,
            tool_policy=policy,
            source_environment=local_source,
            enable_runtime_closure=True,
        )
        try:
            self.assertEqual(
                local_runner.runtime_closure_document["measurementStatus"],
                "local-nondependency-npm-unavailable",
            )
            with tempfile.TemporaryDirectory(prefix="ci8-measured-npm-") as temp_dir:
                npm_entry = Path(temp_dir) / "npm-fixture.js"
                npm_entry.write_text(
                    "console.log('11.0.0');\n", encoding="utf-8"
                )
                measured_tools = {**tools, "npm": str(npm_entry)}
                measurement_environment = ci.child_process_environment(
                    measured_tools,
                    source_environment=local_source,
                    policy=policy,
                )
                closure = ci.RuntimeDependencyClosure.build(
                    "policy",
                    measured_tools,
                    measurement_environment,
                    repo_root=ci.REPO_ROOT,
                    source_environment={},
                )
                try:
                    self.assertEqual(
                        closure.document["measurementStatus"],
                        "measured-complete",
                    )
                    self.assertIsNone(closure.document["vitest"])
                    self.assertNotIn("vitest", closure.leases)
                    forged_closure = SimpleNamespace(
                        document={
                            **copy.deepcopy(closure.document),
                            "vitest": {
                                "resolvedEntrypoint": (
                                    "developer/node_modules/vitest/vitest.mjs"
                                )
                            },
                        }
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Vitest identity is not authorized"
                    ):
                        ci._remeasure_dependency_semantics(
                            forged_closure,
                            repo_root=ci.REPO_ROOT,
                        )
                    missing_sentinel = SimpleNamespace(
                        document={
                            key: copy.deepcopy(value)
                            for key, value in closure.document.items()
                            if key != "vitest"
                        }
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Vitest identity is not authorized"
                    ):
                        ci._remeasure_dependency_semantics(
                            missing_sentinel,
                            repo_root=ci.REPO_ROOT,
                        )
                    forged_document = copy.deepcopy(closure.document)
                    forged_document["vitest"] = {
                        "resolvedEntrypoint": (
                            "developer/node_modules/vitest/vitest.mjs"
                        )
                    }
                    forged_document_without_digest = {
                        key: value
                        for key, value in forged_document.items()
                        if key != "closureDigest"
                    }
                    forged_document["closureDigest"] = hashlib.sha256(
                        ci._canonical_frame(forged_document_without_digest)
                    ).hexdigest()
                    forged_errors: list[str] = []
                    ci._validate_runtime_dependency_closure(
                        forged_document,
                        local_runner.runtime_closure_guard_evidence,
                        local_runner.runtime,
                        profile="policy",
                        status="FAIL",
                        errors=forged_errors,
                    )
                    self.assertTrue(
                        any(
                            "Vitest identity is unexpected" in error
                            for error in forged_errors
                        ),
                        forged_errors,
                    )
                finally:
                    closure.close()

                dependency_repo = Path(temp_dir) / "dependency-repo"
                developer_modules = dependency_repo / "developer" / "node_modules"
                backend_modules = dependency_repo / "backend" / "node_modules"
                (developer_modules / "playwright").mkdir(parents=True)
                (backend_modules / "backend-fixture").mkdir(parents=True)
                (developer_modules / "playwright" / "package.json").write_text(
                    '{"name":"playwright","version":"fixture"}\n',
                    encoding="utf-8",
                )
                (backend_modules / "backend-fixture" / "package.json").write_text(
                    '{"name":"backend-fixture","version":"fixture"}\n',
                    encoding="utf-8",
                )
                for relative in (
                    "developer/package-lock.json",
                    "backend/package-lock.json",
                ):
                    lockfile = dependency_repo.joinpath(*relative.split("/"))
                    lockfile.parent.mkdir(parents=True, exist_ok=True)
                    lockfile.write_text('{"lockfileVersion":3}\n', encoding="utf-8")
                self.assertFalse(
                    (developer_modules / "vitest" / "vitest.mjs").exists()
                )
                for profile, expected_roots in (
                    ("frontend", ["developer/node_modules"]),
                    (
                        "all",
                        ["developer/node_modules", "backend/node_modules"],
                    ),
                ):
                    with self.subTest(profile=profile, dependency="vitest-absent"):
                        profile_closure = ci.RuntimeDependencyClosure.build(
                            profile,
                            measured_tools,
                            measurement_environment,
                            repo_root=dependency_repo,
                            source_environment={},
                        )
                        try:
                            self.assertEqual(
                                profile_closure.document["measurementStatus"],
                                "measured-complete",
                            )
                            self.assertEqual(
                                [
                                    item["logicalRoot"]
                                    for item in profile_closure.document[
                                        "dependencyRoots"
                                    ]
                                ],
                                expected_roots,
                            )
                            self.assertIsNone(
                                profile_closure.document["vitest"]
                            )
                            self.assertNotIn("vitest", profile_closure.leases)
                            dependency_digest, dependency_members = (
                                ci._remeasure_dependency_semantics(
                                    profile_closure,
                                    repo_root=dependency_repo,
                                )
                            )
                            self.assertEqual(
                                dependency_digest,
                                profile_closure.dependency_digest,
                            )
                            self.assertEqual(
                                dependency_members,
                                profile_closure.member_count,
                            )
                        finally:
                            profile_closure.close()
        finally:
            local_runner.cleanup_task_resources()

    def test_unplanned_node_path_and_workspace_runtime_shadowing_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-node-path-") as temp_dir:
            root = Path(temp_dir)
            _policy, approved_tools = self.local_tool_authority()
            approved_node = approved_tools["node"]
            with self.assertRaisesRegex(ValueError, "NODE_PATH"):
                ci.RuntimeDependencyClosure.build(
                    "policy",
                    {"node": approved_node},
                    {},
                    repo_root=root,
                    source_environment={"NODE_PATH": str(root / "shadow")},
                )
            with self.assertRaisesRegex(ValueError, "NODE_OPTIONS"):
                ci.RuntimeDependencyClosure.build(
                    "policy",
                    {"node": approved_node},
                    {},
                    repo_root=root,
                    source_environment={"NODE_OPTIONS": "--require=./untrusted-loader.js"},
                )
            workspace = root / "workspace"
            workspace.mkdir()
            fake_node = workspace / ("node.exe" if os.name == "nt" else "node")
            fake_node.write_bytes(b"fake-node")
            shadow_source = dict(os.environ)
            shadow_source["PATH"] = os.pathsep.join(
                [str(workspace), str(Path(approved_node).parent)]
            )
            shadow_source["GITHUB_WORKSPACE"] = str(workspace)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(fake_node.stat().st_mode) & 0o111, 0)
                non_executable_tools, non_executable_errors = ci.resolve_trusted_tools(
                    {"node"},
                    source_environment=shadow_source,
                    repo_root=workspace,
                )
                self.assertEqual(
                    Path(non_executable_tools["node"]),
                    Path(approved_node).resolve(strict=True),
                )
                self.assertFalse(
                    any("tool=node" in error for error in non_executable_errors),
                    non_executable_errors,
                )
            self.make_hostile_path_fixture_executable(fake_node)
            tools, errors = ci.resolve_trusted_tools(
                {"node"},
                source_environment=shadow_source,
                repo_root=workspace,
            )
            self.assertNotIn("node", tools)
            self.assertTrue(
                any(ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error for error in errors),
                errors,
            )
            fake_npm = workspace / ("npm.cmd" if os.name == "nt" else "npm")
            fake_npm.write_bytes(b"fake-npm")
            self.make_hostile_path_fixture_executable(fake_npm)
            npm_tools, npm_errors = ci.resolve_trusted_tools(
                {"npm"},
                source_environment=shadow_source,
                repo_root=workspace,
            )
            self.assertNotIn("npm", npm_tools)
            self.assertTrue(
                any(
                    ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error
                    for error in npm_errors
                ),
                npm_errors,
            )

    def test_runtime_node_shadow_matrix_rejects_workspace_temp_and_node_modules_bin(self) -> None:
        _policy, approved_tools = self.local_tool_authority()
        approved_node = approved_tools["node"]
        with tempfile.TemporaryDirectory(prefix="ci8-node-shadow-matrix-") as temp_dir:
            root = Path(temp_dir)
            workspace = root / "workspace"
            runner_temp = root / "runner-temp"
            module_bin = workspace / "developer" / "node_modules" / ".bin"
            for directory in (workspace, runner_temp, module_bin):
                directory.mkdir(parents=True, exist_ok=True)
            for label, directory in (
                ("workspace", workspace),
                ("runner-temp", runner_temp),
                ("node-modules-bin", module_bin),
            ):
                with self.subTest(label=label):
                    fake = directory / ("node.exe" if os.name == "nt" else "node")
                    fake.write_bytes(b"untrusted-node-shadow")
                    self.make_hostile_path_fixture_executable(fake)
                    source = dict(os.environ)
                    source["PATH"] = os.pathsep.join(
                        [str(directory), str(Path(approved_node).parent)]
                    )
                    source["GITHUB_WORKSPACE"] = str(workspace)
                    source["RUNNER_TEMP"] = str(runner_temp)
                    tools, errors = ci.resolve_trusted_tools(
                        {"node"},
                        source_environment=source,
                        repo_root=workspace,
                    )
                    self.assertNotIn("node", tools)
                    self.assertTrue(
                        any(
                            ci.PATH_WORKSPACE_OR_TEMP_AUTHORITY in error
                            for error in errors
                        ),
                        errors,
                    )
                    fake.unlink()

    def test_vitest_change_and_restore_is_sticky(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-closure-restore-") as temp_dir:
            root = Path(temp_dir)
            closure, guard, _helper = self.make_guard(root)
            vitest_entrypoint = (
                root / "developer" / "node_modules" / "vitest" / "vitest.mjs"
            )
            original = vitest_entrypoint.read_bytes()
            try:
                vitest_entrypoint.write_bytes(b"export default 2;\n")
                vitest_entrypoint.write_bytes(original)
                guard.watcher.emit("Vitest file write and restore under generic manifest")
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

    def test_windows_notification_buffer_preserves_action_root_and_relative_path(self) -> None:
        first_name = "tool.tmp".encode("utf-16-le")
        first_size = 12 + len(first_name)
        first_offset = (first_size + 3) & ~3
        second_name = "nested\\tool.exe".encode("utf-16-le")
        payload = (
            struct.pack("<III", first_offset, 1, len(first_name))
            + first_name
            + (b"\x00" * (first_offset - first_size))
            + struct.pack("<III", 0, 5, len(second_name))
            + second_name
        )
        events = ci._windows_directory_change_events(payload, r"D:\trusted-root")
        self.assertEqual(
            [(event["action"], event["relativePath"]) for event in events],
            [("added", "tool.tmp"), ("renamed-new-name", "nested/tool.exe")],
        )
        self.assertEqual({event["root"] for event in events}, {r"D:\trusted-root"})
        unknown_name = "unknown.bin".encode("utf-16-le")
        unknown = ci._windows_directory_change_events(
            struct.pack("<III", 0, 99, len(unknown_name)) + unknown_name,
            r"D:\trusted-root",
        )
        self.assertEqual(unknown[0]["action"], "unknown-99")
        with self.assertRaisesRegex(ValueError, "truncated"):
            ci._windows_directory_change_events(b"\x00" * 8, r"D:\trusted-root")

    @unittest.skipUnless(os.name == "nt", "requires the real ReadDirectoryChangesW backend")
    def test_windows_real_watcher_read_only_enumeration_process_startup_and_private_temp_are_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="ci8-rdcw-benign-") as temp_dir:
            root = Path(temp_dir)
            closure, guard, helper = self.make_guard(
                root,
                watcher_factory=ci._WindowsDirectoryMutationWatcher,
            )
            closed = False
            try:
                self.assertEqual(helper.read_bytes(), b"AAAA")
                self.assertIn(helper.name, {path.name for path in helper.parent.iterdir()})
                subprocess.run(
                    [sys.executable, "-B", "-c", "pass"],
                    cwd=root,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                )
                (root / "private-output.tmp").write_bytes(b"unprotected output")
                self.wait_for_guard(
                    lambda: guard.ignored_event_count > 0,
                    "unprotected sibling event classification",
                )
                self.assertFalse(guard.mutated)
                self.assertEqual(guard.verify("benign-read-enumerate-process-temp"), [])
                self.assertTrue(
                    all(
                        event["protectedClass"] == "unprotected-watched-sibling"
                        for event in guard.ignored_events
                    ),
                    guard.ignored_events,
                )
                self.assertTrue(
                    any(event["temporaryOrGenerated"] for event in guard.ignored_events),
                    guard.ignored_events,
                )
                self.assertEqual(guard.close(), [])
                closed = True
            finally:
                if not closed:
                    guard.close()
                closure.close()
            process_root = root / "leased-process-startup"
            process_closure, process_guard, _process_helper = self.make_guard(
                process_root,
                watcher_factory=ci._WindowsDirectoryMutationWatcher,
                lease_path=Path(sys.executable),
            )
            process_closed = False
            try:
                subprocess.run(
                    [sys.executable, "-B", "-c", "pass"],
                    cwd=process_root,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                )
                time.sleep(0.2)
                self.assertFalse(process_guard.mutated)
                self.assertEqual(process_guard.verify("leased-process-startup"), [])
                self.assertEqual(process_guard.close(), [])
                process_closed = True
            finally:
                if not process_closed:
                    process_guard.close()
                process_closure.close()

    @unittest.skipUnless(os.name == "nt", "requires the real ReadDirectoryChangesW backend")
    def test_windows_real_watcher_protected_write_restore_and_same_size_are_sticky(
        self,
    ) -> None:
        for operation in ("content-write", "change-and-restore", "same-size-replacement"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                prefix=f"ci8-rdcw-{operation}-"
            ) as temp_dir:
                closure, guard, helper = self.make_guard(
                    Path(temp_dir),
                    watcher_factory=ci._WindowsDirectoryMutationWatcher,
                )
                original = helper.read_bytes()
                try:
                    if operation == "content-write":
                        helper.write_bytes(b"protected-content-changed")
                    elif operation == "change-and-restore":
                        helper.write_bytes(b"BBBB")
                        helper.write_bytes(original)
                    else:
                        self.assertEqual(len(original), len(b"CCCC"))
                        helper.write_bytes(b"CCCC")
                    self.wait_for_guard(lambda: guard.mutated, operation)
                    errors = guard.verify(operation)
                    self.assertTrue(any("sticky" in error for error in errors), errors)
                    self.assertTrue(
                        any(
                            event["protectedClass"] == "dependency-tree"
                            and event["action"] == "modified"
                            for event in guard.mutation_events
                        ),
                        guard.mutation_events,
                    )
                finally:
                    guard.close()
                    closure.close()

    @unittest.skipUnless(os.name == "nt", "requires the real ReadDirectoryChangesW backend")
    def test_windows_real_watcher_rename_delete_recreate_and_link_mutations_are_sticky(
        self,
    ) -> None:
        for operation in ("rename-and-restore", "delete-recreate", "hardlink", "symlink-if-available"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                prefix=f"ci8-rdcw-{operation}-"
            ) as temp_dir:
                closure, guard, helper = self.make_guard(
                    Path(temp_dir),
                    watcher_factory=ci._WindowsDirectoryMutationWatcher,
                )
                original = helper.read_bytes()
                attempted = True
                try:
                    alternate = helper.with_name(f"{helper.name}.alternate")
                    if operation == "rename-and-restore":
                        helper.rename(alternate)
                        alternate.rename(helper)
                    elif operation == "delete-recreate":
                        helper.unlink()
                        helper.write_bytes(original)
                    elif operation == "hardlink":
                        os.link(helper, alternate)
                        alternate.write_bytes(b"BBBB")
                    else:
                        try:
                            os.symlink(helper.name, alternate)
                        except OSError:
                            attempted = False
                    if not attempted:
                        self.assertFalse(alternate.exists())
                        continue
                    self.wait_for_guard(lambda: guard.mutated, operation)
                    self.assertTrue(guard.verify(operation))
                    actions = {event["action"] for event in guard.mutation_events}
                    if operation == "rename-and-restore":
                        self.assertTrue(
                            {"renamed-old-name", "renamed-new-name"} & actions,
                            guard.mutation_events,
                        )
                    elif operation == "delete-recreate":
                        self.assertTrue({"removed", "added"} & actions, guard.mutation_events)
                    self.assertTrue(
                        all(event["protected"] for event in guard.mutation_events),
                        guard.mutation_events,
                    )
                finally:
                    guard.close()
                    closure.close()

    def test_windows_watcher_read_failure_unknown_event_and_overflow_fail_closed(self) -> None:
        event_cases = (
            ("read-failure", "ReadDirectoryChangesW failure=5 root=fixture", False),
            (
                "unknown-event",
                {
                    "backend": "ReadDirectoryChangesW",
                    "kind": "filesystem-notification",
                    "action": "unknown-99",
                    "actionCode": 99,
                    "root": "fixture",
                    "relativePath": "member.bin",
                },
                False,
            ),
            ("overflow", "ReadDirectoryChangesW queue overflow root=fixture", True),
        )
        for label, event, overflow in event_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix=f"ci8-rdcw-failure-{label}-"
            ) as temp_dir:
                closure, guard, _helper = self.make_guard(Path(temp_dir))
                try:
                    guard.watcher.emit(event, overflow=overflow)
                    errors = guard.verify(label)
                    self.assertTrue(errors)
                    self.assertTrue(guard.mutated)
                    if overflow:
                        self.assertTrue(guard.evidence()["queueOverflow"])
                    if label == "unknown-event":
                        self.assertTrue(
                            any(
                                item.get("failClosedReason") == "unknown watcher action"
                                for item in guard.mutation_events
                            ),
                            guard.mutation_events,
                        )
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
                failure_path_authority=frozen_release_skip_path_binding(entry),
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

        logical = "developer/tests/js/adminFrontendGuard.test.js"
        source_root = r"D:\CI-R03\Repo Root"
        snapshot_root = r"C:\Temp\cs-r03"
        authority = ci._coerce_failure_path_authority(
            source_root,
            snapshot_root,
            [logical],
        )

        def canonical(value: str) -> tuple[tuple[str, ...], dict]:
            translated, binding = ci.canonicalize_failure_identity_text(
                value,
                authority,
            )
            with mock.patch.object(ci, "REPO_ROOT", Path(source_root)):
                identity = ci.extract_failure_identity(
                    "fixture:r03-windows",
                    stdout=translated,
                    path_authority=binding,
                )
            return tuple(identity["fileLocations"]), binding

        windows_equivalents = (
            source_root + "\\" + logical.replace("/", "\\"),
            snapshot_root + "\\" + logical.replace("/", "\\"),
            snapshot_root.replace("C:", "c:") + "/" + logical,
            (snapshot_root + "\\" + logical.replace("/", "\\")).replace(
                "\\",
                "\\\\",
            ),
        )
        canonical_values: list[tuple[str, ...]] = []
        for value in windows_equivalents:
            with self.subTest(r03_windows_equivalent=value):
                normalized, binding = canonical(value)
                canonical_values.append(normalized)
                self.assertEqual(
                    binding["authorizedTargetPaths"],
                    [logical],
                )
                self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
                self.assertEqual(binding["literalPlaceholderDigests"], [])
        self.assertEqual(len(set(canonical_values)), 1)
        self.assertEqual(canonical_values[0], (logical,))

        translated = ci._translate_snapshot_output_paths(
            snapshot_root + "\\" + logical.replace("/", "\\"),
            snapshot_root,
            source_root,
            [logical],
        )
        self.assertEqual(
            ci.normalize_authorized_path_text(
                translated,
                repository_root=source_root,
                task_roots=[],
            ),
            f"<repo>/{logical}",
        )
        binary = (
            b"\xff"
            + (snapshot_root + "\\" + logical.replace("/", "\\")).encode("utf-8")
            + b"\xfe"
        )
        translated_binary = ci._translate_snapshot_output_bytes(
            binary,
            snapshot_root,
            source_root,
            [logical],
        )
        self.assertTrue(translated_binary.startswith(b"\xff"))
        self.assertTrue(translated_binary.endswith(b"\xfe"))
        self.assertIn(source_root.encode("utf-8"), translated_binary)

        negative_values = {
            "near-prefix": snapshot_root + "-evil\\" + logical.replace("/", "\\"),
            "same-basename-wrong-directory": (
                snapshot_root + r"\other\adminFrontendGuard.test.js"
            ),
            "relative-case-drift": (
                snapshot_root + r"\developer\tests\js\AdminFrontendGuard.test.js"
            ),
            "traversal": snapshot_root + r"\..\outside\adminFrontendGuard.test.js",
            "literal-placeholder": f"<repo>/{logical}",
        }
        for label, value in negative_values.items():
            with self.subTest(r03_windows_negative=label):
                normalized, binding = canonical(value)
                self.assertNotEqual(normalized, (logical,))
                self.assertNotEqual(
                    binding["unmappedAbsolutePathDigests"]
                    or binding["literalPlaceholderDigests"],
                    [],
                )
                self.assertEqual(binding["authorizedTargetPaths"], [])
        unknown_a = canonical(r"E:\other\same\adminFrontendGuard.test.js")[1]
        unknown_b = canonical(r"F:\other\same\adminFrontendGuard.test.js")[1]
        self.assertNotEqual(
            unknown_a["unmappedAbsolutePathDigests"],
            unknown_b["unmappedAbsolutePathDigests"],
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

        logical = "developer/tests/e2e/reading_question_audit.py"
        source_root = "/srv/IELTS/Repo"
        snapshot_root = "/tmp/cs-r03"
        authority = ci._coerce_failure_path_authority(
            source_root,
            snapshot_root,
            [logical],
        )

        def canonical(value: str) -> tuple[tuple[str, ...], dict]:
            translated, binding = ci.canonicalize_failure_identity_text(
                value,
                authority,
            )
            identity = ci.extract_failure_identity(
                "fixture:r03-posix",
                stdout=translated,
                path_authority=binding,
            )
            return tuple(identity["fileLocations"]), binding

        source_value, source_binding = canonical(f"{source_root}/{logical}")
        snapshot_value, snapshot_binding = canonical(f"{snapshot_root}/{logical}")
        self.assertEqual(source_value, snapshot_value)
        self.assertTrue(source_value[0].endswith(logical))
        self.assertEqual(source_binding, snapshot_binding)
        self.assertEqual(source_binding["authorizedTargetPaths"], [logical])

        translated = ci._translate_snapshot_output_paths(
            f"{snapshot_root}/{logical}",
            snapshot_root,
            source_root,
            [logical],
        )
        self.assertEqual(translated, f"{source_root}/{logical}")
        binary = b"\xff" + f"{snapshot_root}/{logical}".encode("utf-8") + b"\xfe"
        translated_binary = ci._translate_snapshot_output_bytes(
            binary,
            snapshot_root,
            source_root,
            [logical],
        )
        self.assertEqual(
            translated_binary,
            b"\xff" + f"{source_root}/{logical}".encode("utf-8") + b"\xfe",
        )

        negative_values = {
            "near-prefix": f"{snapshot_root}-evil/{logical}",
            "same-basename-wrong-directory": (
                f"{snapshot_root}/other/reading_question_audit.py"
            ),
            "relative-case-drift": (
                f"{snapshot_root}/developer/tests/e2e/Reading_question_audit.py"
            ),
            "traversal": f"{snapshot_root}/../outside/reading_question_audit.py",
            "literal-repo": f"<repo>/{logical}",
            "literal-task-root": f"<task-root>/{logical}",
            "literal-abs-path": f"<abs-path>/{logical}",
        }
        for label, value in negative_values.items():
            with self.subTest(r03_posix_negative=label):
                normalized, binding = canonical(value)
                self.assertNotEqual(normalized, source_value)
                self.assertEqual(binding["authorizedTargetPaths"], [])
                self.assertNotEqual(
                    binding["unmappedAbsolutePathDigests"]
                    or binding["literalPlaceholderDigests"],
                    [],
                )
        unknown_a = canonical("/tmp/unrelated-a/reading_question_audit.py")[1]
        unknown_b = canonical("/tmp/unrelated-b/reading_question_audit.py")[1]
        self.assertNotEqual(
            unknown_a["unmappedAbsolutePathDigests"],
            unknown_b["unmappedAbsolutePathDigests"],
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


class R08OptionBReleaseAuthorityTest(unittest.TestCase):
    RELEASE_IDS = (
        "B-SKIP-RELEASE-ZIP",
        "B-SKIP-PDF-RECONCILIATION",
        "B-SKIP-CHECKLIST-CONSISTENCY",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls.entries = {
            entry["id"]: entry for entry in cls.baseline["releaseOnlySkips"]
        }

    def assert_cli_rejected(self, argv: list[str]) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises((ValueError, SystemExit)):
                ci.parse_args(argv)

    def test_release_authority_selector_requires_exact_long_option(self) -> None:
        rejected_argv = (
            ["--profile", "all", "--release-auth"],
            ["--profile", "all", "--release-author"],
            [
                "--profile",
                "all",
                "--release-authoritative",
                "--release-auth",
            ],
            [
                "--profile",
                "all",
                "--release-auth",
                "--release-authoritative",
            ],
            [
                "--profile",
                "all",
                "--release-authoritative",
                "--release-authoritative",
            ],
            ["--profile", "all", "--release-authoritative=true"],
        )
        for argv in rejected_argv:
            with self.subTest(argv=argv):
                self.assert_cli_rejected(argv)

        exact_release = ci.parse_args(
            ["--profile", "all", "--release-authoritative"]
        )
        engineering_all = ci.parse_args(["--profile", "all"])
        self.assertTrue(exact_release.release_authoritative)
        self.assertFalse(engineering_all.release_authoritative)

    def test_security_relevant_long_options_require_exact_spelling(self) -> None:
        rejected_argv = {
            "profile": ["--prof", "all"],
            "verify-evidence": [
                "--verify-evid",
                "--expected-profile",
                "policy",
            ],
            "verify-only": ["--profile", "policy", "--verify-onl"],
            "require-install-tools": [
                "--profile",
                "policy",
                "--verify-only",
                "--require-install",
            ],
            "expected-profile": [
                "--verify-evidence",
                "--expected-prof",
                "policy",
            ],
            "expected-producer-job": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-producer",
                "repository-policy-producer",
            ],
            "expected-verifier-job": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-verifier",
                "repository-policy",
            ],
            "expected-runner-os": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-runner",
                "Linux",
            ],
            "expected-invocation-id": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-invocation",
                "r08-probe",
            ],
            "untrusted-evidence-root": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--untrusted-evidence",
                "r08-probe",
            ],
            "require-linux-containment-self-test": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--require-linux-containment",
            ],
            "require-fresh-runtime-closure": [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--require-fresh-runtime",
            ],
        }
        for option, argv in rejected_argv.items():
            with self.subTest(option=option):
                self.assert_cli_rejected(argv)

        exact_context = ci.parse_args(
            [
                "--verify-evidence",
                "--expected-profile",
                "policy",
                "--expected-producer-job",
                "repository-policy-producer",
                "--expected-verifier-job",
                "repository-policy",
                "--expected-runner-os",
                "Linux",
                "--expected-invocation-id",
                "r08-probe",
                "--untrusted-evidence-root",
                "r08-probe",
                "--require-linux-containment-self-test",
                "--require-fresh-runtime-closure",
            ]
        )
        self.assertTrue(exact_context.verify_evidence)
        self.assertEqual(exact_context.expected_profile, "policy")
        self.assertEqual(
            exact_context.expected_producer_job,
            "repository-policy-producer",
        )
        self.assertEqual(exact_context.expected_verifier_job, "repository-policy")
        self.assertEqual(exact_context.expected_runner_os, "Linux")
        self.assertEqual(exact_context.expected_invocation_id, "r08-probe")
        self.assertEqual(exact_context.untrusted_evidence_root, "r08-probe")
        self.assertTrue(exact_context.require_linux_containment_self_test)
        self.assertTrue(exact_context.require_fresh_runtime_closure)

    def three_release_skips(self) -> tuple[dict, dict, list[dict]]:
        items = []
        for index, entry_id in enumerate(self.RELEASE_IDS):
            entry = self.entries[entry_id]
            raw = frozen_v1_release_skip_raw_observation(
                entry,
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
        baseline = copy.deepcopy(self.baseline)
        baseline["knownDebts"] = []
        baseline["expectedOmissions"] = []
        return baseline, record, observations

    def compare_three_skips(self, *, release_gate_required: bool) -> dict:
        baseline, record, observations = self.three_release_skips()
        return ci.compare_observations(
            baseline,
            observations,
            {"static-suite"},
            "windows",
            release_gate_required=release_gate_required,
            command_records=[record],
        )

    def test_resolved_requiredness_matrix_separates_all_breadth_from_authority(self) -> None:
        expected = {
            "policy": False,
            "static": False,
            "frontend": False,
            "backend": False,
            "standalone": True,
            "all": False,
        }
        self.assertEqual(
            {
                profile: ci.resolve_release_gate_required(profile)
                for profile in ci.PROFILES
            },
            expected,
        )
        self.assertTrue(
            ci.resolve_release_gate_required(
                "all",
                release_authoritative=True,
            )
        )
        for invalid in (None, 0, 1, "true"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ci.resolve_release_gate_required(
                    "all",
                    release_authoritative=invalid,
                )
        for profile in ("policy", "static", "frontend", "backend", "standalone"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                ci.resolve_release_gate_required(
                    profile,
                    release_authoritative=True,
                )

    def test_engineering_and_explicit_release_all_have_exact_three_skip_exit_contract(self) -> None:
        engineering = self.compare_three_skips(release_gate_required=False)
        explicit_release = self.compare_three_skips(release_gate_required=True)

        self.assertEqual(len(engineering["releaseOnlySkips"]), 3)
        self.assertEqual(engineering["violations"], [])
        engineering_status = "PASS" if not engineering["violations"] else "FAIL"
        self.assertEqual(engineering_status, "PASS")
        self.assertEqual(ci.policy_status_exit_code(engineering_status), 0)

        self.assertEqual(len(explicit_release["releaseOnlySkips"]), 3)
        self.assertEqual(len(explicit_release["violations"]), 3)
        self.assertEqual(
            {item["id"] for item in explicit_release["violations"]},
            {"RELEASE-ONLY-SKIP-IN-REQUIRED-GATE"},
        )
        release_status = "PASS" if not explicit_release["violations"] else "FAIL"
        self.assertEqual(release_status, "FAIL")
        self.assertEqual(ci.policy_status_exit_code(release_status), 2)

    def test_static_and_standalone_release_skip_semantics_are_preserved(self) -> None:
        static = self.compare_three_skips(
            release_gate_required=ci.resolve_release_gate_required("static")
        )
        standalone = self.compare_three_skips(
            release_gate_required=ci.resolve_release_gate_required("standalone")
        )
        self.assertEqual(len(static["releaseOnlySkips"]), 3)
        self.assertEqual(static["violations"], [])
        self.assertEqual(len(standalone["releaseOnlySkips"]), 3)
        self.assertEqual(len(standalone["violations"]), 3)

    def test_release_authority_is_bound_in_producer_verifier_and_digest_context(self) -> None:
        engineering = synthetic_execution_binding(
            "all",
            "a" * 64,
            release_gate_required=False,
        )
        release = synthetic_execution_binding(
            "all",
            "a" * 64,
            release_gate_required=True,
        )
        engineering_context = ci.authorization_context_binding_from_execution_binding(
            engineering
        )
        release_context = ci.authorization_context_binding_from_execution_binding(
            release
        )
        self.assertFalse(engineering_context["releaseGateRequired"])
        self.assertTrue(release_context["releaseGateRequired"])
        self.assertEqual(
            {
                key: value
                for key, value in engineering_context.items()
                if key != "releaseGateRequired"
            },
            {
                key: value
                for key, value in release_context.items()
                if key != "releaseGateRequired"
            },
        )
        self.assertNotEqual(
            ci.authorization_context_binding_digest(engineering_context),
            ci.authorization_context_binding_digest(release_context),
        )
        self.assertFalse(
            synthetic_external_context(engineering)
            .verifier_binding()["releaseGateRequired"]
        )
        self.assertTrue(
            synthetic_external_context(release)
            .verifier_binding()["releaseGateRequired"]
        )

    def test_producer_verifier_release_authority_match_and_mismatch_matrix(self) -> None:
        bindings = {
            required: synthetic_execution_binding(
                "all",
                "b" * 64,
                release_gate_required=required,
            )
            for required in (False, True)
        }
        for required, binding in bindings.items():
            with self.subTest(match=required):
                authorization = ci.authorization_context_binding_from_execution_binding(
                    binding
                )
                self.assertEqual(
                    ci.authorization_context_binding_errors(
                        authorization,
                        ci.authorization_context_binding_digest(authorization),
                        execution_binding=binding,
                        expected_context=synthetic_external_context(binding),
                    ),
                    [],
                )
        for producer_required, verifier_required in ((False, True), (True, False)):
            with self.subTest(
                producer=producer_required,
                verifier=verifier_required,
            ):
                producer = bindings[producer_required]
                authorization = ci.authorization_context_binding_from_execution_binding(
                    producer
                )
                errors = ci.authorization_context_binding_errors(
                    authorization,
                    ci.authorization_context_binding_digest(authorization),
                    execution_binding=producer,
                    expected_context=synthetic_external_context(
                        bindings[verifier_required]
                    ),
                )
                self.assertTrue(any("external" in error for error in errors), errors)
                self.assertTrue(
                    ci.execution_binding_external_context_errors(
                        producer,
                        ci.execution_binding_digest(producer),
                        synthetic_external_context(bindings[verifier_required]),
                    )
                )

    def test_missing_invalid_duplicate_and_substituted_release_context_fails_closed(self) -> None:
        binding = synthetic_execution_binding(
            "all",
            "c" * 64,
            release_gate_required=True,
        )
        authorization = ci.authorization_context_binding_from_execution_binding(binding)

        missing_authorization = copy.deepcopy(authorization)
        missing_authorization.pop("releaseGateRequired")
        with self.assertRaises(ValueError):
            ci.authorization_context_binding_digest(missing_authorization)

        missing_execution = copy.deepcopy(binding)
        missing_execution.pop("releaseGateRequired")
        with self.assertRaises(ValueError):
            ci.authorization_context_binding_from_execution_binding(missing_execution)
        execution_errors: list[str] = []
        ci._validate_execution_binding(
            missing_execution,
            ci.execution_binding_digest(missing_execution),
            label="r08-missing",
            errors=execution_errors,
        )
        self.assertTrue(execution_errors)

        for invalid in (None, 0, 1, "true", [], {}):
            with self.subTest(invalid=invalid):
                invalid_authorization = copy.deepcopy(authorization)
                invalid_authorization["releaseGateRequired"] = invalid
                with self.assertRaises(ValueError):
                    ci.authorization_context_binding_digest(invalid_authorization)
                invalid_execution = copy.deepcopy(binding)
                invalid_execution["releaseGateRequired"] = invalid
                errors: list[str] = []
                ci._validate_execution_binding(
                    invalid_execution,
                    ci.execution_binding_digest(invalid_execution),
                    label="r08-invalid",
                    errors=errors,
                )
                self.assertTrue(errors)

        with self.assertRaises(ci.DuplicateJsonKeyError):
            ci.strict_json_loads(
                '{"releaseGateRequired":false,"releaseGateRequired":true}',
                label="r08-duplicate-release-authority",
            )

        substituted = copy.deepcopy(binding)
        substituted["releaseGateRequired"] = False
        substituted_authorization = (
            ci.authorization_context_binding_from_execution_binding(substituted)
        )
        self.assertTrue(
            ci.authorization_context_binding_errors(
                substituted_authorization,
                ci.authorization_context_binding_digest(substituted_authorization),
                execution_binding=substituted,
                expected_context=synthetic_external_context(binding),
            )
        )

    def test_cli_and_unchanged_hosted_all_resolve_engineering_by_default(self) -> None:
        engineering = ci.parse_args(["--profile", "all"])
        explicit_release = ci.parse_args(
            ["--profile", "all", "--release-authoritative"]
        )
        verifier_release = ci.parse_args(
            [
                "--verify-evidence",
                "--expected-profile",
                "all",
                "--release-authoritative",
            ]
        )
        self.assertFalse(engineering.release_authoritative)
        self.assertTrue(explicit_release.release_authoritative)
        self.assertTrue(verifier_release.release_authoritative)
        for argv in (
            ["--profile", "static", "--release-authoritative"],
            ["--profile", "standalone", "--release-authoritative"],
            [
                "--profile",
                "all",
                "--release-authoritative",
                "--release-authoritative",
            ],
            ["--profile", "all", "--release-authoritative=true"],
        ):
            with self.subTest(argv=argv), self.assertRaises((ValueError, SystemExit)):
                ci.parse_args(argv)

        workflow_text = ci.WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(ci.check_workflow_text(workflow_text), [])
        self.assertNotIn("--release-authoritative", workflow_text)
        self.assertGreaterEqual(
            workflow_text.count(
                "developer/tests/ci/run_ci_foundation.py --profile all"
            ),
            2,
        )
        self.assertFalse(ci.resolve_release_gate_required("all"))


class R10ReleaseSkipSignatureBindingTest(unittest.TestCase):
    PATH_IDS = (
        "B-SKIP-PDF-RECONCILIATION",
        "B-SKIP-CHECKLIST-CONSISTENCY",
    )
    RELEASE_IDS = (
        "B-SKIP-RELEASE-ZIP",
        *PATH_IDS,
    )
    FROZEN_SIGNATURES = {
        "B-SKIP-RELEASE-ZIP": (
            "sha256:8ae895e21db520d968113c11eac0e2df73ed14d70521c5ac5957bb3f92f0da7f"
        ),
        "B-SKIP-PDF-RECONCILIATION": (
            "sha256:33bc9b849164b41e15815b3b0db644c6b5bb44620715cd08b26852dda0a22a2d"
        ),
        "B-SKIP-CHECKLIST-CONSISTENCY": (
            "sha256:6817f608de514acb77d92038f93328ef15d0c8da44cf377126984efb1d2cee07"
        ),
    }
    POSIX_ROOT = "/srv/IELTS-practice"
    POSIX_SNAPSHOT = "/tmp/cs-r10-release"
    WINDOWS_ROOT = r"D:\a\IELTS-practice\IELTS-practice"
    WINDOWS_SNAPSHOT = r"C:\Users\RUNNER~1\AppData\Local\Temp\cs-r10-release"

    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        cls.entries = {
            entry["id"]: entry for entry in cls.baseline["releaseOnlySkips"]
        }

    @staticmethod
    def joined(root: str, relative: str) -> str:
        reference = ci.classify_windows_absolute_reference(root)
        separator = "\\" if reference.authorizable else "/"
        return root.rstrip("/\\") + separator + relative.replace("/", separator)

    def physical_item(
        self,
        entry_id: str,
        repository_root: str,
        snapshot_root: str,
        *,
        observed_path: str | None = None,
        reason_prefix: str = "missing_checklist:",
        result_name: str | None = None,
        observation_ordinal: int = 0,
    ) -> tuple[dict, dict | None, dict]:
        entry = self.entries[entry_id]
        expected_name = entry["testOrPathScope"].removeprefix("result:")
        detail = copy.deepcopy(FROZEN_V1_RELEASE_SKIP_DETAILS[expected_name])
        detail["reason"] = reason_prefix + (
            observed_path or self.joined(snapshot_root, "checklist.md")
        )
        result = {
            "name": result_name or expected_name,
            "status": "pass",
            "detail": detail,
        }
        authority = ci._coerce_failure_path_authority(
            repository_root,
            snapshot_root,
            [ci.STATIC_SUITE_RELATIVE_PATH],
        )
        canonical, binding = ci._canonicalize_static_result_failure_paths(
            result,
            authority,
        )
        raw = ci.make_raw_observation(
            "static-suite",
            4,
            observation_ordinal,
            "static-producer-v1",
            str(canonical["name"]),
            ci.STATIC_SUITE_RELATIVE_PATH,
            canonical,
            ci.canonical_failure_digest(canonical),
            failure_path_authority=binding,
        )
        item = ci.observation(
            "static-suite",
            entry["testOrPathScope"],
            "skip",
            entry["allowedNormalizedSignature"][0],
            "static-suite",
            raw_observation=raw,
        )
        return canonical, binding, item

    def selected_baseline(self, *entry_ids: str) -> dict:
        selected = copy.deepcopy(self.baseline)
        selected["knownDebts"] = []
        selected["expectedOmissions"] = []
        selected["releaseOnlySkips"] = [
            copy.deepcopy(self.entries[entry_id]) for entry_id in entry_ids
        ]
        return selected

    def compare_bound(
        self,
        entry_ids: tuple[str, ...],
        items: list[dict],
        *,
        release_gate_required: bool = False,
        platform_name: str = "windows",
    ) -> tuple[dict, dict, list[dict]]:
        _spec, record, observations = ci9_static_evidence_fixture(
            items,
            platform_name=platform_name,
        )
        result = ci.compare_observations(
            self.selected_baseline(*entry_ids),
            observations,
            {"static-suite"},
            platform_name,
            release_gate_required=release_gate_required,
            command_records=[record],
        )
        return result, record, observations

    def assert_path_positive(
        self,
        entry_id: str,
        repository_root: str,
        snapshot_root: str,
        *,
        platform_name: str,
    ) -> tuple[dict, dict, dict]:
        canonical, binding, item = self.physical_item(
            entry_id,
            repository_root,
            snapshot_root,
        )
        self.assertEqual(
            canonical["detail"]["reason"],
            "missing_checklist:<repo>/checklist.md",
        )
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding["authorizedTargetPaths"], ["checklist.md"])
        self.assertEqual(binding["unmappedAbsolutePathDigests"], [])
        self.assertEqual(binding["literalPlaceholderDigests"], [])
        self.assertEqual(
            ci.derive_frozen_v1_release_skip_signature(item["rawObservation"]),
            self.FROZEN_SIGNATURES[entry_id],
        )
        result, record, observations = self.compare_bound(
            (entry_id,),
            [item],
            platform_name=platform_name,
        )
        self.assertEqual(
            ci._validate_raw_observation(
                observations[0]["rawObservation"],
                label="r10-positive",
                source=record,
            ),
            [],
        )
        self.assertEqual(result["violations"], [])
        self.assertEqual(
            [release["baselineId"] for release in result["releaseOnlySkips"]],
            [entry_id],
        )
        self.assertEqual(
            result["releaseOnlySkips"][0]["legacyBaselineComparisonDigest"],
            self.FROZEN_SIGNATURES[entry_id],
        )
        return canonical, binding, observations[0]

    def assert_path_negative(
        self,
        entry_id: str,
        repository_root: str,
        snapshot_root: str,
        *,
        observed_path: str | None = None,
        reason_prefix: str = "missing_checklist:",
        result_name: str | None = None,
    ) -> tuple[dict, dict | None, dict]:
        canonical, binding, item = self.physical_item(
            entry_id,
            repository_root,
            snapshot_root,
            observed_path=observed_path,
            reason_prefix=reason_prefix,
            result_name=result_name,
        )
        result, _record, observations = self.compare_bound(
            (entry_id,),
            [item],
            platform_name="windows",
        )
        self.assertEqual(result["releaseOnlySkips"], [])
        self.assertIn(
            "UNKNOWN-NONPASS",
            {violation["id"] for violation in result["violations"]},
        )
        return canonical, binding, observations[0]

    def three_physical_items(self) -> list[dict]:
        zip_entry = self.entries["B-SKIP-RELEASE-ZIP"]
        zip_raw = frozen_v1_release_skip_raw_observation(
            zip_entry,
            observation_ordinal=0,
        )
        items = [
            ci.observation(
                "static-suite",
                zip_entry["testOrPathScope"],
                "skip",
                self.FROZEN_SIGNATURES[zip_entry["id"]],
                "static-suite",
                raw_observation=zip_raw,
            )
        ]
        for ordinal, entry_id in enumerate(self.PATH_IDS, start=1):
            _canonical, _binding, item = self.physical_item(
                entry_id,
                self.WINDOWS_ROOT,
                self.WINDOWS_SNAPSHOT,
                observation_ordinal=ordinal,
            )
            items.append(item)
        return items

    def test_pdf_posix_physical_snapshot_binds_exactly(self) -> None:
        self.assert_path_positive(
            "B-SKIP-PDF-RECONCILIATION",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            platform_name="linux",
        )

    def test_checklist_posix_physical_snapshot_binds_exactly(self) -> None:
        self.assert_path_positive(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            platform_name="linux",
        )

    def test_pdf_windows_physical_snapshot_binds_exactly(self) -> None:
        self.assert_path_positive(
            "B-SKIP-PDF-RECONCILIATION",
            self.WINDOWS_ROOT,
            self.WINDOWS_SNAPSHOT,
            platform_name="windows",
        )

    def test_checklist_windows_physical_snapshot_binds_exactly(self) -> None:
        self.assert_path_positive(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.WINDOWS_ROOT,
            self.WINDOWS_SNAPSHOT,
            platform_name="windows",
        )

    def test_release_zip_exact_binding_is_unchanged(self) -> None:
        entry_id = "B-SKIP-RELEASE-ZIP"
        entry = self.entries[entry_id]
        raw = frozen_v1_release_skip_raw_observation(entry)
        self.assertIsNone(raw["failurePathAuthority"])
        self.assertEqual(
            raw["rawStructuredFields"]["detail"],
            FROZEN_V1_RELEASE_SKIP_DETAILS["Release ZIP 运行时内容守卫"],
        )
        item = ci.observation(
            "static-suite",
            entry["testOrPathScope"],
            "skip",
            self.FROZEN_SIGNATURES[entry_id],
            "static-suite",
            raw_observation=raw,
        )
        result, _record, observations = self.compare_bound((entry_id,), [item])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["releaseOnlySkips"][0]["baselineId"], entry_id)
        self.assertEqual(
            observations[0]["legacyBaselineComparisonDigest"],
            self.FROZEN_SIGNATURES[entry_id],
        )

    def test_physical_snapshot_root_variation_preserves_frozen_identity(self) -> None:
        cases = (
            (self.POSIX_ROOT, "/tmp/cs-r10-a"),
            (self.POSIX_ROOT, "/private/tmp/cs-r10-b"),
            (self.WINDOWS_ROOT, r"C:\Temp\cs-r10-a"),
            (self.WINDOWS_ROOT, r"E:\Build Temp\cs-r10-b"),
        )
        for entry_id in self.PATH_IDS:
            signatures = set()
            canonical_reasons = set()
            for repository_root, snapshot_root in cases:
                canonical, binding, item = self.physical_item(
                    entry_id,
                    repository_root,
                    snapshot_root,
                )
                canonical_reasons.add(canonical["detail"]["reason"])
                signatures.add(
                    ci.derive_frozen_v1_release_skip_signature(
                        item["rawObservation"]
                    )
                )
                self.assertEqual(binding["authorizedTargetPaths"], ["checklist.md"])
            self.assertEqual(
                canonical_reasons,
                {"missing_checklist:<repo>/checklist.md"},
            )
            self.assertEqual(signatures, {self.FROZEN_SIGNATURES[entry_id]})

    def test_exact_repository_reason_and_all_three_frozen_digests_are_reproduced(self) -> None:
        expected_scopes = {
            "B-SKIP-RELEASE-ZIP": "result:Release ZIP 运行时内容守卫",
            "B-SKIP-PDF-RECONCILIATION": "result:PDF 对账与回归审计",
            "B-SKIP-CHECKLIST-CONSISTENCY": "result:Checklist 对账一致性校验",
        }
        for entry_id in self.RELEASE_IDS:
            entry = self.entries[entry_id]
            self.assertEqual(entry["testOrPathScope"], expected_scopes[entry_id])
            self.assertEqual(
                entry["allowedNormalizedSignature"],
                [self.FROZEN_SIGNATURES[entry_id]],
            )
            self.assertEqual(entry["category"], "release-only-skip")
            self.assertEqual(entry["expectedOutcome"], "skip")
            raw = frozen_v1_release_skip_raw_observation(entry)
            if entry_id in self.PATH_IDS:
                self.assertEqual(
                    raw["rawStructuredFields"]["detail"]["reason"],
                    "missing_checklist:<repo>/checklist.md",
                )
            self.assertEqual(
                ci.derive_frozen_v1_release_skip_signature(raw),
                self.FROZEN_SIGNATURES[entry_id],
            )

    def test_near_prefix_physical_root_does_not_bind(self) -> None:
        canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-PDF-RECONCILIATION",
            self.WINDOWS_ROOT,
            self.WINDOWS_SNAPSHOT,
            observed_path=self.WINDOWS_SNAPSHOT + r"-evil\checklist.md",
        )
        self.assertNotEqual(
            canonical["detail"]["reason"],
            "missing_checklist:<repo>/checklist.md",
        )
        self.assertTrue(binding["unmappedAbsolutePathDigests"])

    def test_unrelated_physical_root_does_not_bind(self) -> None:
        _canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.WINDOWS_ROOT,
            self.WINDOWS_SNAPSHOT,
            observed_path=r"E:\unrelated\checklist.md",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])

    def test_path_traversal_does_not_bind(self) -> None:
        _canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-PDF-RECONCILIATION",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            observed_path=self.POSIX_SNAPSHOT + "/../outside/checklist.md",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])
        self.assertTrue(binding["unmappedAbsolutePathDigests"])

    def test_wrong_checklist_filename_does_not_bind(self) -> None:
        _canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            observed_path=self.POSIX_SNAPSHOT + "/release-checklist.md",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])

    def test_wrong_repository_relative_target_does_not_bind(self) -> None:
        _canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-PDF-RECONCILIATION",
            self.WINDOWS_ROOT,
            self.WINDOWS_SNAPSHOT,
            observed_path=self.WINDOWS_SNAPSHOT + r"\artifact\checklist.md",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])
        self.assertTrue(binding["unmappedAbsolutePathDigests"])

    def test_altered_reason_text_does_not_bind(self) -> None:
        _canonical, binding, _item = self.assert_path_negative(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            reason_prefix="missing_checklist_extra:",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])

    def test_generic_absolute_or_literal_path_stripping_is_not_accepted(self) -> None:
        cases = (
            r"F:\outside\checklist.md",
            "<abs-path>/checklist.md",
            "<task-root>/checklist.md",
            "<repo>/checklist.md",
        )
        for observed_path in cases:
            with self.subTest(observed_path=observed_path):
                canonical, binding, _item = self.assert_path_negative(
                    "B-SKIP-PDF-RECONCILIATION",
                    self.WINDOWS_ROOT,
                    self.WINDOWS_SNAPSHOT,
                    observed_path=observed_path,
                )
                self.assertNotEqual(
                    canonical["detail"]["reason"],
                    "missing_checklist:<repo>/checklist.md",
                )
                self.assertEqual(binding["authorizedTargetPaths"], [])
                self.assertTrue(
                    binding["unmappedAbsolutePathDigests"]
                    or binding["literalPlaceholderDigests"]
                )

    def test_arbitrary_unknown_nonpass_remains_blocking(self) -> None:
        _canonical, binding, observation = self.assert_path_negative(
            "B-SKIP-CHECKLIST-CONSISTENCY",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            observed_path="producer_failure_without_authorized_path",
            reason_prefix="",
        )
        self.assertEqual(binding["authorizedTargetPaths"], [])
        self.assertNotEqual(
            observation["legacyBaselineComparisonDigest"],
            self.FROZEN_SIGNATURES["B-SKIP-CHECKLIST-CONSISTENCY"],
        )

    def test_unrelated_nonpass_cannot_be_absorbed_by_release_classification(self) -> None:
        _canonical, binding, observation = self.assert_path_negative(
            "B-SKIP-PDF-RECONCILIATION",
            self.POSIX_ROOT,
            self.POSIX_SNAPSHOT,
            result_name="Unrelated producer failure",
        )
        self.assertIsNone(binding)
        self.assertEqual(
            observation["testOrPathScope"],
            "result:Unrelated producer failure",
        )

    def test_engineering_all_keeps_three_exact_release_skips_visible_nonblocking(self) -> None:
        result, _record, observations = self.compare_bound(
            self.RELEASE_IDS,
            self.three_physical_items(),
            release_gate_required=ci.resolve_release_gate_required("all"),
        )
        self.assertFalse(ci.resolve_release_gate_required("all"))
        self.assertEqual(result["violations"], [])
        self.assertEqual(
            {release["baselineId"] for release in result["releaseOnlySkips"]},
            set(self.RELEASE_IDS),
        )
        self.assertEqual(
            {item["legacyBaselineComparisonDigest"] for item in observations},
            set(self.FROZEN_SIGNATURES.values()),
        )

    def test_explicit_release_all_keeps_same_skips_and_fails_closed(self) -> None:
        required = ci.resolve_release_gate_required(
            "all",
            release_authoritative=True,
        )
        result, _record, _observations = self.compare_bound(
            self.RELEASE_IDS,
            self.three_physical_items(),
            release_gate_required=required,
        )
        self.assertTrue(required)
        self.assertEqual(
            {release["baselineId"] for release in result["releaseOnlySkips"]},
            set(self.RELEASE_IDS),
        )
        self.assertEqual(len(result["violations"]), 3)
        self.assertEqual(
            {violation["id"] for violation in result["violations"]},
            {"RELEASE-ONLY-SKIP-IN-REQUIRED-GATE"},
        )


def _flatten_test_suite(test: unittest.TestSuite | unittest.TestCase) -> list[unittest.TestCase]:
    flattened: list[unittest.TestCase] = []
    if isinstance(test, unittest.TestSuite):
        for child in test:
            flattened.extend(_flatten_test_suite(child))
    else:
        flattened.append(test)
    return flattened


def _test_inventory(
    test: unittest.TestSuite | unittest.TestCase,
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]], str]:
    identifiers = tuple(sorted(item.id() for item in _flatten_test_suite(test)))
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("test inventory contains duplicate IDs")
    by_class: dict[str, list[str]] = {}
    for identifier in identifiers:
        by_class.setdefault(identifier.rsplit(".", 1)[0], []).append(identifier)
    frozen_by_class = {
        class_name: tuple(class_ids)
        for class_name, class_ids in sorted(by_class.items())
    }
    digest = hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()
    return identifiers, frozen_by_class, digest


class InventoryTextTestResult(unittest.TextTestResult):
    def __init__(
        self,
        *args,
        inventory_ids: tuple[str, ...],
        inventory_by_class: dict[str, tuple[str, ...]],
        inventory_digest: str,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.inventory_ids = inventory_ids
        self.inventory_by_class = inventory_by_class
        self.inventory_digest = inventory_digest
        self.executed_test_ids: set[str] = set()
        self.successful_test_ids: set[str] = set()
        self.class_setup_error_classes: set[str] = set()
        self.blocked_test_ids: tuple[str, ...] = ()

    def startTest(self, test: unittest.TestCase) -> None:
        self.executed_test_ids.add(test.id())
        super().startTest(test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        self.successful_test_ids.add(test.id())
        super().addSuccess(test)

    def addError(self, test: unittest.TestCase, err) -> None:
        match = re.fullmatch(r"setUpClass \((?P<class_name>[^)]+)\)", test.id())
        if match is not None:
            self.class_setup_error_classes.add(match.group("class_name"))
        super().addError(test, err)

    def finalize_inventory_accounting(self) -> None:
        blocked = {
            identifier
            for class_name in self.class_setup_error_classes
            for identifier in self.inventory_by_class.get(class_name, ())
            if identifier not in self.executed_test_ids
        }
        self.blocked_test_ids = tuple(sorted(blocked))


class InventoryTextTestRunner(unittest.TextTestRunner):
    resultclass = InventoryTextTestResult

    def _makeResult(self) -> InventoryTextTestResult:
        return self.resultclass(
            self.stream,
            self.descriptions,
            self.verbosity,
            inventory_ids=self._inventory_ids,
            inventory_by_class=self._inventory_by_class,
            inventory_digest=self._inventory_digest,
        )

    def run(self, test):
        (
            self._inventory_ids,
            self._inventory_by_class,
            self._inventory_digest,
        ) = _test_inventory(test)
        self.stream.writeln(
            f"TEST_INVENTORY TOTAL_DISCOVERED_IDS={len(self._inventory_ids)}"
        )
        self.stream.writeln(
            f"TEST_INVENTORY SORTED_ID_SHA256={self._inventory_digest}"
        )
        for class_name, identifiers in self._inventory_by_class.items():
            self.stream.writeln(
                f"TEST_INVENTORY CLASS={class_name} COUNT={len(identifiers)}"
            )
        result = super().run(test)
        result.finalize_inventory_accounting()
        actual_test_errors = sum(
            1
            for error_test, _traceback in result.errors
            if not error_test.id().startswith("setUpClass (")
        )
        verdict = (
            "BLOCKING"
            if result.failures
            or result.errors
            or result.unexpectedSuccesses
            or result.blocked_test_ids
            else "PASS"
        )
        self.stream.writeln(
            "TEST_ACCOUNTING "
            f"DISCOVERED={len(result.inventory_ids)} "
            f"EXECUTED={len(result.executed_test_ids)} "
            f"PASSED={len(result.successful_test_ids)} "
            f"FAILED={len(result.failures)} "
            f"ERRORS={actual_test_errors} "
            f"SKIPPED={len(result.skipped)} "
            f"CLASS_SETUP_ERRORS={len(result.class_setup_error_classes)} "
            f"CLASS_SETUP_BLOCKED_METHODS={len(result.blocked_test_ids)} "
            f"VERDICT={verdict}"
        )
        for identifier in result.blocked_test_ids:
            self.stream.writeln(f"TEST_ACCOUNTING BLOCKED_ID={identifier}")
        return result


class TestInventoryAccountingTest(unittest.TestCase):
    def test_class_setup_abort_accounts_for_every_blocked_method(self) -> None:
        class BlockedFixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls) -> None:
                raise RuntimeError("intentional class setup failure")

            def test_alpha(self) -> None:
                self.fail("blocked test executed")

            def test_beta(self) -> None:
                self.fail("blocked test executed")

            def test_gamma(self) -> None:
                self.fail("blocked test executed")

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BlockedFixture)
        stream = io.StringIO()
        result = InventoryTextTestRunner(stream=stream, verbosity=0).run(suite)
        self.assertEqual(len(result.inventory_ids), 3)
        self.assertEqual(len(result.executed_test_ids), 0)
        self.assertEqual(len(result.class_setup_error_classes), 1)
        self.assertEqual(len(result.blocked_test_ids), 3)
        self.assertIn("CLASS_SETUP_BLOCKED_METHODS=3", stream.getvalue())
        self.assertIn("VERDICT=BLOCKING", stream.getvalue())


def run_with_receipt(argv: list[str]) -> int:
    """Opt-in local full-suite reuse; hosted and selected-test runs stay unchanged."""
    import argparse
    import governance_state as gs

    parser = argparse.ArgumentParser(description=run_with_receipt.__doc__, allow_abbrev=False)
    parser.add_argument("--reuse-receipt-dir", required=True)
    parser.add_argument("--environment-contract", required=True)
    parser.add_argument("--fixtures-digest", required=True, type=lambda value: None if value == "null" else value)
    args = parser.parse_args(argv)
    if any(key.upper() == "GITHUB_ACTIONS" and value.lower() not in {"", "false"}
           for key, value in os.environ.items()):
        parser.error("receipt reuse is local only")
    try:
        receipt_dir = gs.external_path(args.reuse_receipt_dir, ci.REPO_ROOT)
        environment = gs.external_path(args.environment_contract, ci.REPO_ROOT)
        receipt_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))

    before = None
    decision = {"decision": "REVALIDATE", "reason": "RECEIPT_MISSING", "candidate_tree": None}
    try:
        before = gs.frozen_context(ci.REPO_ROOT, environment, args.fixtures_digest)
        decision["candidate_tree"] = before["candidate_tree"]
        for path in sorted(receipt_dir.glob(gs.digest(before) + "-*.json")):
            try:
                decision = gs.check_evidence(gs.read_document(path), before)
            except (OSError, ValueError, subprocess.SubprocessError):
                decision["reason"] = "RECEIPT_INVALID"
                continue
            if decision["decision"] == "REUSE_ALLOWED":
                if gs.frozen_context(ci.REPO_ROOT, environment, args.fixtures_digest) == before:
                    print(json.dumps(decision, sort_keys=True))
                    return 0
                before = None
                decision = {"decision": "REVALIDATE", "reason": "STATE_CHANGED",
                            "candidate_tree": decision["candidate_tree"]}
                break
    except (OSError, ValueError, subprocess.SubprocessError):
        before = None
        decision = {"decision": "REVALIDATE", "reason": "STATE_UNKNOWN", "candidate_tree": None}
    print(json.dumps(decision, sort_keys=True))

    result = unittest.main(module=__name__, argv=[sys.argv[0]], verbosity=2,
                           testRunner=InventoryTextTestRunner, exit=False).result
    complete = (result.wasSuccessful() and result.testsRun == 476
                and len(result.inventory_ids) == 476
                and set(result.inventory_ids) == result.executed_test_ids == result.successful_test_ids)
    if before is not None and complete:
        try:
            if gs.frozen_context(ci.REPO_ROOT, environment, args.fixtures_digest) != before:
                print(json.dumps({"decision": "REVALIDATE", "reason": "STATE_CHANGED",
                                  "candidate_tree": before["candidate_tree"]}, sort_keys=True))
            else:
                receipt = gs.make_receipt(before)
                path = receipt_dir / (gs.digest(before) + "-" + uuid.uuid4().hex + ".json")
                with path.open("xb") as output:
                    output.write(gs.canonical(receipt))
                print(json.dumps({"decision": "EVIDENCE_RECORDED", "reason": "FULL_VALIDATION_PASS",
                                  "candidate_tree": before["candidate_tree"],
                                  "receipt_id": receipt["receipt_id"],
                                  "validation_fingerprint": receipt["validation_fingerprint"]},
                                 sort_keys=True))
        except (OSError, ValueError, subprocess.SubprocessError):
            print(json.dumps({"decision": "REVALIDATE", "reason": "RECEIPT_NOT_RECORDED",
                              "candidate_tree": before["candidate_tree"]}, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if any(arg.split("=", 1)[0] in {"--reuse-receipt-dir", "--environment-contract", "--fixtures-digest"}
           for arg in sys.argv[1:]):
        sys.exit(run_with_receipt(sys.argv[1:]))
    unittest.main(verbosity=2, testRunner=InventoryTextTestRunner)
