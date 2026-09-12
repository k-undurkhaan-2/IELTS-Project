#!/usr/bin/env python3
"""Baseline-aware, cross-platform CI policy runner.

The runner intentionally uses only Python's standard library.  It invokes a
small allowlist of repository validation commands, converts their output into
scoped observations, and compares every non-pass observation with the frozen
Phase 1 baseline. Raw output is excluded from public diagnostics. Eligible
direct Node successes retain bounded exact streams in locally validated evidence.
"""

from __future__ import annotations

import argparse
import copy
import concurrent.futures
import ctypes
import errno
import hashlib
import html
import io
import json
import math
import os
import platform
import re
import select
import signal
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tokenize
import unicodedata
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote, unquote_to_bytes, urlsplit


REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE_PATH = REPO_ROOT / "developer" / "tests" / "ci" / "phase1-ci-baseline.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
OUTPUT_DIR = REPO_ROOT / ".ci-results"

PROFILES = ("policy", "static", "frontend", "backend", "standalone", "all")
EXIT_SUCCESS = 0
EXIT_POLICY_VIOLATION = 2
EXIT_CONFIGURATION_ERROR = 3
EXIT_RUNNER_ERROR = 4


def _require_resolved_release_gate_required(
    profile: str,
    value: Any,
) -> bool:
    if profile not in PROFILES:
        raise ValueError("release-gate profile is outside the fixed profile registry")
    if type(value) is not bool:
        raise ValueError("resolved release-gate authority must be a boolean")
    if profile == "standalone" and value is not True:
        raise ValueError("standalone requires release-gate authority")
    if profile not in {"standalone", "all"} and value is not False:
        raise ValueError("release-gate authority is unsupported for this profile")
    return value


def resolve_release_gate_required(
    profile: str,
    *,
    release_authoritative: bool = False,
) -> bool:
    """Resolve suite breadth separately from release authorization."""

    if type(release_authoritative) is not bool:
        raise ValueError("explicit release authority must be a boolean")
    if release_authoritative and profile != "all":
        raise ValueError("explicit release authority is supported only with profile all")
    return _require_resolved_release_gate_required(
        profile,
        profile == "standalone" or release_authoritative,
    )


def policy_status_exit_code(status: str) -> int:
    if status == "PASS":
        return EXIT_SUCCESS
    if status == "FAIL":
        return EXIT_POLICY_VIOLATION
    raise ValueError("CI policy status is invalid")


BASELINE_COMMIT = "db743cc625daded38442834731cbf35db024e10f"
BASELINE_TREE = "c3f3825ecc4523a6e39da1164df41d6d59e3527a"
CHECKPOINT_TAG = "checkpoint-phase1-20260730"
POLICY_VERSION = "1.0.0"
STATIC_MACHINE_DOCUMENT_KIND = "ieltmps-static-suite-machine-report-v2"
STATIC_MACHINE_SCHEMA_VERSION = 2
CANONICAL_FAILURE_MATERIAL_VERSION = 4
FROZEN_V1_RELEASE_SKIP_SIGNATURE_SCHEMA_VERSION = 1
RAW_OBSERVATION_SCHEMA_VERSION = 2
RAW_OBSERVATION_KINDS = frozenset(
    {
        "static-producer-v1",
        "process-output-v1",
        "standalone-membership-v1",
        "normalized-fields-v1",
    }
)
TARGET_EXECUTION_LEASE_VERSION = 1
PROTECTED_TARGET_BUNDLE_VERSION = 1
VERIFICATION_REPLAY_TRANSCRIPT_VERSION = 1
EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION = 3
EXTERNALLY_EXPECTED_VERIFICATION_CONTEXT_SCHEMA_VERSION = 3
AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION = 2
VERIFIER_REPLAY_CONTEXT_BINDING_SCHEMA_VERSION = 1
REPLAY_AUTHORIZATION_ENVELOPE_SCHEMA_VERSION = 1
CI_TRUST_FILE_SET_SCHEMA_VERSION = 1
RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION = 1
RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION = 1
RUNTIME_CLOSURE_PRECONDITION_STATUS = "PRECONDITION_NOT_MET"
RUNTIME_CLOSURE_PRECONDITION_REASONS = frozenset(
    {
        "TOOL_AUTHORITY_NOT_FROZEN",
        "COMMAND_AUTHORITY_INVALID",
        "DEPENDENCY_ENVIRONMENT_UNAVAILABLE",
        "MEASUREMENT_NOT_REQUESTED",
        "MEASUREMENT_FAILED",
    }
)
LINUX_CONTAINMENT_PROTOCOL_VERSION = 1
POSIX_PROCESS_IDENTITY_SCHEMA_VERSION = 1

# Normative Canonical Framing Grammar, version 1.  These byte constants are
# mirrored exactly in docs/CI_POLICY.md and in an independent test encoder.
CANONICAL_FRAME_SPECIFICATION_VERSION = 1
CANONICAL_FRAME_TEXT_ENCODING = "utf-8"
CANONICAL_FRAME_UNICODE_NORMALIZATION = "NFC"
CANONICAL_FRAME_LENGTH_WIDTH_BYTES = 8
CANONICAL_FRAME_COUNT_WIDTH_BYTES = 8
CANONICAL_FRAME_BYTE_ORDER = "big"
CANONICAL_FRAME_MAP_KEY_ORDER = "nfc-utf8-byte-lexicographic"
CANONICAL_FRAME_ARRAY_ORDER = "input-order"
CANONICAL_FRAME_TAGS = MappingProxyType(
    {
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
)
AUTHORIZATION_CONTEXT_BINDING_DIGEST_DOMAIN = (
    "ieltmps-authorization-context-binding-v2"
)
VERIFIER_REPLAY_CONTEXT_BINDING_DIGEST_DOMAIN = (
    "ieltmps-verifier-replay-context-binding-v1"
)
REPLAY_AUTHORIZATION_ENVELOPE_DIGEST_DOMAIN = (
    "ieltmps-replay-authorization-envelope-v1"
)
LOCAL_REPOSITORY_IDENTITY_PROJECTION_DOMAIN = (
    "ieltmps-local-repository-identity-v1"
)

MAX_STDOUT_BYTES = 1_048_576
MAX_STDERR_BYTES = 1_048_576
MAX_OUTPUT_LINE_BYTES = 16_384
MAX_EVIDENCE_PREVIEW_BYTES = 4_096
MAX_COMMAND_RESULTS_JSON_BYTES = 33_554_432
MAX_STATIC_MACHINE_STDOUT_BYTES = 8_388_608
MAX_STATIC_MACHINE_STDERR_BYTES = 1_048_576
OUTPUT_READ_CHUNK_BYTES = 16_384
SECRET_SCAN_CHUNK_BYTES = 65_536
SECRET_SCAN_MAX_PATTERN_BYTES = 8_192
SECRET_SCAN_OVERLAP_BYTES = SECRET_SCAN_MAX_PATTERN_BYTES - 1
SECRET_SCAN_CLASSIFICATION_SAMPLE_BYTES = 8_192
UTF16_ASCII_CREDENTIAL_VIEWS = (
    "utf-16le-offset-0",
    "utf-16le-offset-1",
    "utf-16be-offset-0",
    "utf-16be-offset-1",
)
MAX_JOB_TIMEOUT_SECONDS = 3_600
MAX_RECORDED_STREAM_BYTES = MAX_STATIC_MACHINE_STDOUT_BYTES + OUTPUT_READ_CHUNK_BYTES
MAX_SCANNED_FILE_BYTES = 1_099_511_627_776
MAX_PROFILE_COMMANDS = 50_000
PROCESS_TREE_GRACE_SECONDS = 1.0
PROCESS_TREE_KILL_SECONDS = 5.0
PROCESS_TREE_FAILURE_EXIT = 126
LINUX_CONTAINMENT_SETTLE_SECONDS = 8.0
LINUX_CONTAINMENT_SCAN_SECONDS = 0.01
LINUX_CONTAINMENT_STABLE_SCANS = 3

EVIDENCE_FILE_NAMES = (
    "summary.json",
    "summary.md",
    "observed-debt.json",
    "resolved-candidates.json",
    "command-results.json",
)
EVIDENCE_MANIFEST_FILE_NAMES = EVIDENCE_FILE_NAMES[1:]
EVIDENCE_DOCUMENT_KINDS = MappingProxyType(
    {
        "summary.json": "ieltmps-ci-foundation-summary-v2",
        "summary.md": "ieltmps-ci-summary-markdown-v2",
        "observed-debt.json": "ieltmps-ci-observed-debt-v2",
        "resolved-candidates.json": "ieltmps-ci-resolved-candidates-v2",
        "command-results.json": "ieltmps-ci-command-results-v2",
    }
)
EVIDENCE_FILE_BYTE_LIMITS = MappingProxyType(
    {
        "summary.json": 4_194_304,
        "summary.md": 2_097_152,
        "observed-debt.json": 4_194_304,
        "resolved-candidates.json": 4_194_304,
        "command-results.json": MAX_COMMAND_RESULTS_JSON_BYTES,
    }
)
MAX_EVIDENCE_COLLECTION_ITEMS = 20_000
MAX_EVIDENCE_JSON_DEPTH = 20
MAX_EVIDENCE_STRING_BYTES = 65_536

CI_TRUST_FILE_PATHS = (
    ".github/workflows/ci.yml",
    "developer/tests/ci/phase1-ci-baseline.json",
    "developer/tests/ci/run_ci_foundation.py",
    "developer/tests/ci/run_static_suite.py",
    "developer/tests/ci/test_ci_foundation.py",
    "developer/tests/ci/test_standalone_packaging.py",
    "docs/CI_POLICY.md",
    ".gitignore",
)

WORKFLOW_JOB_PROFILE_AUTHORITY = MappingProxyType(
    {
        "repository-policy": MappingProxyType(
            {
                "jobId": "repository-policy",
                "producerJobId": "repository-policy-producer",
                "verifierJobId": "repository-policy",
                "runnerOS": "Linux",
                "profile": "policy",
                "verificationProfile": "policy",
                "artifactIdentity": "untrusted-repository-policy-${{ runner.os }}-${{ github.run_attempt }}",
                "evidenceRoot": "${{ runner.temp }}/ci-untrusted/repository-policy",
                "evidencePaths": EVIDENCE_FILE_NAMES,
            }
        ),
        "ubuntu-canonical": MappingProxyType(
            {
                "jobId": "ubuntu-canonical",
                "producerJobId": "ubuntu-canonical-producer",
                "verifierJobId": "ubuntu-canonical",
                "runnerOS": "Linux",
                "profile": "all",
                "verificationProfile": "all",
                "artifactIdentity": "untrusted-ubuntu-canonical-${{ runner.os }}-${{ github.run_attempt }}",
                "evidenceRoot": "${{ runner.temp }}/ci-untrusted/ubuntu-canonical",
                "evidencePaths": EVIDENCE_FILE_NAMES,
            }
        ),
        "windows-compatibility": MappingProxyType(
            {
                "jobId": "windows-compatibility",
                "producerJobId": "windows-compatibility-producer",
                "verifierJobId": "windows-compatibility",
                "runnerOS": "Windows",
                "profile": "all",
                "verificationProfile": "all",
                "artifactIdentity": "untrusted-windows-compatibility-${{ runner.os }}-${{ github.run_attempt }}",
                "evidenceRoot": "${{ runner.temp }}/ci-untrusted/windows-compatibility",
                "evidencePaths": EVIDENCE_FILE_NAMES,
            }
        ),
    }
)


@dataclass(frozen=True)
class ExecutionExternalAuthority:
    """Frozen job context captured outside command planning and evidence parsing."""

    source_kind: str
    binding_mode: str
    runner_os: str
    job_id: str
    run_id: str
    run_attempt: str
    event_name: str
    repository: str
    checkout_sha: str

    def __post_init__(self) -> None:
        if self.source_kind not in {"live", "synthetic-test"}:
            raise ValueError("external authority source kind is invalid")
        if self.binding_mode not in {"github-actions", "local"}:
            raise ValueError("external authority binding mode is invalid")
        if self.runner_os not in {"Linux", "Windows"}:
            raise ValueError("external authority runner OS is invalid")
        values = (
            self.job_id,
            self.run_id,
            self.run_attempt,
            self.event_name,
            self.repository,
            self.checkout_sha,
        )
        if any(not isinstance(value, str) for value in values):
            raise ValueError("external authority field type is invalid")
        if self.binding_mode == "github-actions":
            if not self.job_id or self.job_id != self.job_id.strip():
                raise ValueError("external authority job is invalid")
            if not re.fullmatch(r"[1-9][0-9]*", self.run_id):
                raise ValueError("external authority run ID is invalid")
            if not re.fullmatch(r"[1-9][0-9]*", self.run_attempt):
                raise ValueError("external authority run attempt is invalid")
            if not re.fullmatch(r"[A-Za-z0-9_]+", self.event_name):
                raise ValueError("external authority event is invalid")
            if not re.fullmatch(r"[^/\s]+/[^/\s]+", self.repository):
                raise ValueError("external authority repository is invalid")
            if not re.fullmatch(r"[0-9a-f]{40}", self.checkout_sha):
                raise ValueError("external authority checkout SHA is invalid")
        elif (
            self.job_id
            or self.run_id != "local"
            or self.run_attempt != "1"
            or self.event_name != "local"
            or self.repository
            or self.checkout_sha
        ):
            raise ValueError("local external authority contains hosted-job fields")


@dataclass(frozen=True)
class ExternallyExpectedVerificationContext:
    """Producer and verifier authority built before any artifact byte is read."""

    binding_mode: str
    expected_profile: str
    release_gate_required: bool
    producer_job_id: str
    verifier_job_id: str
    runner_os: str
    run_id: str
    run_attempt: str
    event_name: str
    repository: str
    checkout_commit: str
    checkout_tree: str
    baseline_commit: str
    baseline_tree: str
    trust_file_digest: str
    command_plan_digest: str
    producer_invocation_id: str
    fresh_runtime_closure_digest: str
    verifier_invocation_id: str

    def __post_init__(self) -> None:
        _require_resolved_release_gate_required(
            self.expected_profile,
            self.release_gate_required,
        )

    def evidence_binding(self) -> dict[str, Any]:
        return {
            "bindingSchemaVersion": EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
            "bindingKind": "ProducerExecutionBinding",
            "bindingMode": self.binding_mode,
            "producerJobId": self.producer_job_id,
            "producerRunnerOS": self.runner_os,
            "producerProfile": self.expected_profile,
            "releaseGateRequired": self.release_gate_required,
            "runId": self.run_id,
            "runAttempt": self.run_attempt,
            "eventName": self.event_name,
            "repository": self.repository,
            "checkoutCommit": self.checkout_commit,
            "checkoutTree": self.checkout_tree,
            "baselineCommit": self.baseline_commit,
            "baselineTree": self.baseline_tree,
            "trustFileDigest": self.trust_file_digest,
            "commandPlanDigest": self.command_plan_digest,
            "producerInvocationId": self.producer_invocation_id,
        }

    def authorization_context_binding(self) -> dict[str, Any]:
        """Return the stable producer/verifier authorization projection."""

        return {
            "bindingSchemaVersion": AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION,
            "bindingKind": "AuthorizationContextBinding",
            "bindingMode": self.binding_mode,
            "expectedProfile": self.expected_profile,
            "releaseGateRequired": self.release_gate_required,
            "producerJobId": self.producer_job_id,
            "expectedVerifierJobId": self.verifier_job_id,
            "runnerOS": self.runner_os,
            "runId": self.run_id,
            "runAttempt": self.run_attempt,
            "eventName": self.event_name,
            "repository": self.repository,
            "checkoutCommit": self.checkout_commit,
            "checkoutTree": self.checkout_tree,
            "baselineCommit": self.baseline_commit,
            "baselineTree": self.baseline_tree,
            "trustFileDigest": self.trust_file_digest,
            "commandPlanDigest": self.command_plan_digest,
            "producerInvocationId": self.producer_invocation_id,
        }

    def verifier_binding(self) -> dict[str, Any]:
        return {
            "bindingSchemaVersion": EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
            "bindingKind": "VerifierExecutionBinding",
            "bindingMode": self.binding_mode,
            "verifierJobId": self.verifier_job_id,
            "verifierRunnerOS": self.runner_os,
            "expectedProfile": self.expected_profile,
            "releaseGateRequired": self.release_gate_required,
            "expectedProducerJobId": self.producer_job_id,
            "runId": self.run_id,
            "runAttempt": self.run_attempt,
            "eventName": self.event_name,
            "repository": self.repository,
            "checkoutCommit": self.checkout_commit,
            "checkoutTree": self.checkout_tree,
            "baselineCommit": self.baseline_commit,
            "baselineTree": self.baseline_tree,
            "trustFileDigest": self.trust_file_digest,
            "independentlyRebuiltCommandPlanDigest": self.command_plan_digest,
            "freshRuntimeClosureDigest": self.fresh_runtime_closure_digest,
            "verifierInvocationId": self.verifier_invocation_id,
        }

    @property
    def workflow_job_id(self) -> str:
        return self.verifier_job_id

    @property
    def ci_trust_file_set_digest(self) -> str:
        return self.trust_file_digest

    @property
    def invocation_id(self) -> str:
        return self.producer_invocation_id

TRUST_BOUNDARY = MappingProxyType(
    {
        "selfValidatorTrust": "candidate-controlled",
        "mergeAuthorization": "not provided by this workflow",
        "independentReview": "required for CI trust-file changes",
    }
)
TRUST_WARNING_LINES = (
    "SELF-VALIDATOR TRUST: candidate-controlled",
    "MERGE AUTHORIZATION: not provided by this workflow",
    "INDEPENDENT REVIEW: required for CI trust-file changes",
)
PROHIBITED_AUTHORITY_PHRASES = (
    "immutable authority",
    "independent security approval",
    "tamper-proof policy authority",
    "provides sufficient merge authorization",
    "is sufficient merge authorization",
    "externally authenticated policy",
    "security approved",
    "safe to merge",
    "policy independently verified",
    "merge authorized",
)

TRUSTED_FILE_PATHS = (
    ".github/workflows/ci.yml",
    "developer/tests/ci/phase1-ci-baseline.json",
    "developer/tests/ci/run_ci_foundation.py",
    "developer/tests/ci/run_static_suite.py",
    "developer/tests/ci/test_ci_foundation.py",
    "developer/tests/ci/test_standalone_packaging.py",
    "developer/package.json",
    "developer/package-lock.json",
    "backend/package.json",
    "backend/package-lock.json",
)

LOCKED_FILE_SHA256 = MappingProxyType(
    {
        "developer/package.json": "dab60726da59723c6579fde313e7f7de4eb3f1edcbb74ce1df5e0296b1b0f287",
        "developer/package-lock.json": "f63dd2bdb95943d6758fff92dcfdd46652c4dbdf74b904855e76b7caecc17fed",
        "backend/package.json": "64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c",
        "backend/package-lock.json": "bec82fc24a8ae667a8ecc76712244c00929f558a85a3638ef55549c6b8e325db",
    }
)

LOCKED_FILE_GIT_BLOB_OIDS = MappingProxyType(
    {
        "developer/package.json": "201e47b52ce92504b6cbbe298ff0ae81bf171123",
        "developer/package-lock.json": "12adc3250fed7a6944c928641e0c503ce9aef2f0",
        "backend/package.json": "98de1aeca0ada9aa3dff4127bb2baf5bb84ae1b5",
        "backend/package-lock.json": "3a0a9400f4a5bb57fa08fef16ab5f092d7566f49",
    }
)

ESBUILD_VERSION = "0.27.1"
ESBUILD_LOCK_INTEGRITY = "sha512-yY35KZckJJuVVPXpvjgxiCuVEJT67F6zDeVTv4rizyPrfGBUpZQsvmxnN+C371c2esD/hNMjj4tpBhuueLN7aA=="

APPROVED_ACTIONS = {
    "actions/checkout": {
        "tag": "v7.0.1",
        "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    },
    "actions/setup-node": {
        "tag": "v7.0.0",
        "sha": "820762786026740c76f36085b0efc47a31fe5020",
    },
    "actions/setup-python": {
        "tag": "v7.0.0",
        "sha": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    },
    "actions/upload-artifact": {
        "tag": "v7.0.1",
        "sha": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    },
    "actions/download-artifact": {
        "tag": "v4.3.0",
        "sha": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    },
}

SECURITY_GUARD_FILES = (
    "developer/tests/js/adminFrontendGuard.test.js",
    "developer/tests/js/appActionsExportGuard.test.js",
    "developer/tests/js/dataManagementPanel.test.js",
    "developer/tests/js/examActionsExportGuard.test.js",
    "developer/tests/js/examSessionReplayCloneGuard.test.js",
    "developer/tests/js/localDataRenderingGuard.test.js",
    "developer/tests/js/practiceRecordExportServerGuard.test.js",
    "developer/tests/js/privacyLoggingGuard.test.js",
    "developer/tests/js/remotePracticeDataSource.test.js",
    "developer/tests/js/resourceCoreProbeBypassGuard.test.js",
    "developer/tests/js/secureIdentifierGuard.test.js",
    "developer/tests/js/suiteBackGuardSecurity.test.js",
    "developer/tests/js/vocabSessionExportGuard.test.js",
)

MESSAGE_ORIGIN_SECURITY_GUARD = "developer/tests/js/messageOriginGuard.test.js"
DEPENDENCY_BACKED_TOOL_ROLES = frozenset(
    {
        "node-test",
        "node-security-test",
        "npm-backend-test",
    }
)


def expected_command_authority(
    profile: str,
    observations: Sequence[Mapping[str, Any]] = (),
    *,
    tools: Mapping[str, str] | None = None,
    candidate_paths: Sequence[str] | None = None,
    baseline: Mapping[str, Any] | None = None,
    current_platform: str | None = None,
    static_invocation_id: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Return authority reconstructed without consulting observations/evidence."""

    del observations  # Observed results are facts, never command authority.
    root = REPO_ROOT if repo_root is None else repo_root
    if candidate_paths is None:
        candidate_paths, path_errors = deterministic_candidate_paths(root)
        if path_errors:
            candidate_paths = []
    if baseline is None:
        baseline = read_json(BASELINE_PATH)
    resolution_errors: list[str] = []
    required_tools = required_tool_names(profile)
    if tools is None:
        tools, resolution_errors = resolve_trusted_tools(required_tools, repo_root=root)
    tools = require_tool_set(
        tools,
        required_tools,
        phase="COMMAND_PLAN",
        resolution_errors=resolution_errors,
    )
    bash_lease: TrustedBashLease | None = None
    try:
        bash = tools.get("bash")
        git = tools.get("git")
        if os.name == "nt" and bash and git:
            bash_lease = TrustedBashLease(bash, git)
        return build_profile_command_plan(
            profile,
            tools=tools,
            candidate_paths=candidate_paths,
            baseline=baseline,
            current_platform=current_platform or platform_key(),
            static_invocation_id=static_invocation_id or deterministic_static_invocation_id(root),
            repo_root=root,
            bash_lease=bash_lease,
        )
    finally:
        if bash_lease is not None:
            bash_lease.close()

LOCAL_IMPLEMENTATION_ALLOWLIST = {
    ".github/workflows/ci.yml",
    "developer/tests/ci/phase1-ci-baseline.json",
    "developer/tests/ci/run_ci_foundation.py",
    "developer/tests/ci/run_static_suite.py",
    "developer/tests/ci/test_ci_foundation.py",
    "developer/tests/ci/test_standalone_packaging.py",
    "docs/CI_POLICY.md",
}

# Each digest canonically frames the collection plus every security-relevant
# field listed in BASELINE_SEMANTIC_FIELDS. The candidate-local map is read-only
# during one invocation and is stored separately from the JSON it validates.
BASELINE_SEMANTIC_FIELDS = (
    "category",
    "gate",
    "commandClass",
    "testOrPathScope",
    "expectedOutcome",
    "allowedNormalizedSignature",
    "maximumOccurrences",
    "platforms",
    "checkpointDisposition",
    "targetStage",
    "securityImpact",
)

BASELINE_SEMANTIC_AUTHORITY = MappingProxyType(
    {
        "B-SKIP-CHECKLIST-CONSISTENCY": "c395052b382f7a7a8ef95670fa59d4b5e3876ba608c5758df38a8d6a9e8f6131",
        "B-SKIP-PDF-RECONCILIATION": "454f4b92f1b32087b5a9d826c7b6621468a14b3863af5cef8b7e0c1716c48097",
        "B-SKIP-RELEASE-ZIP": "86031c7887a5adcf3a21aa1998494b255da4f952395c9c056f68b346891a884f",
        "B-STATIC-E2E-SNAPSHOT-SCRIPT-DRIFT": "1aa50ddd4ad9d0abd6f7d465a3a25df2ec1efec6062e1b1127435d42c91d6203",
        "B-STATIC-NAVIGATION-VIEW-COVERAGE": "3682457a705f80e911caa7230028e31588f412d53a192f1c882d3a9afca2fc1e",
        "B-STATIC-ON-DEMAND-HARNESS-DOM-STUB": "e2a408f09d46ce79a22bb1b3849df252bf00d26e4f35a0088a5352f9c8f0a62e",
        "B-STATIC-PRACTICE-CUSTOM-CARD-LAYOUT": "a50835a93cdfd1a8d5d4dcd5148c2c6aa4315cc14f7caf86dac7b592297fc79d",
        "B-STATIC-PRACTICE-RECORDER-SYNTHETIC-GUARD": "f67cd7a45855d3b2978da157d6910edfa2d00bb6bd529e190efe783505cadb2f",
        "B-STATIC-PRIVATE-LISTENING-BRIDGE-OMISSION": "fd481f951a2a47ba4b114f2c2126f7bd7c95af28c9d50af6e627f36c6934ac3c",
        "B-STATIC-PRIVATE-LISTENING-INDEX-OMISSION": "603332443e032cafb4042d07a48a5a16eb4ed954c8043fe99cec310bc91f1dbc",
        "B-STATIC-PY-PLAYWRIGHT-NB-DRAG": "60246ac1dc5c1a839209019653e454a7de6cb1e588c431b148092b4a40e74943",
        "B-STATIC-PY-PLAYWRIGHT-READING-QUICK-AUDIT": "91ee4036a46606b66cd560f7b33578c6cc89ad9595ffe7a246f6a838b41f237f",
        "B-STATIC-PY-PLAYWRIGHT-ROUNDTRIP": "85cefb0808ba5145d6c51f21fbc192f98e2b16bf40088b5b77ab05036f2f420c",
        "B-STATIC-PY-PLAYWRIGHT-UNIFIED-SUBMIT": "869e12a1cb975eef1966a6846ebc1c485efab440bbeadcb05849371c83b6ca3d",
        "B-STATIC-SETTINGS-BUTTON-COVERAGE": "1c4050f1df40a540b163382e32155d30d9312c561606a83c9b203715bf0d94a9",
        "B-STATIC-SUITE-SESSION-ROUTING": "20d6d8c714d905dc71b54d71a326ff750680d89a60239d13c19565001b7743b3",
        "B-SYNTAX-PERFORMANCE-BASELINE": "d9060340e9ac79de7ac3459c7096e441c280659b9bba46bcc220f351122d35ea",
        "B-SYNTAX-READING-EXPLANATION-P1-HIGH-194": "216d29cb8c043474718e30cd9bd82309f28c07e0233b09eb3e73a751ea7359c4",
        "B-SYNTAX-READING-EXPLANATION-P3-LOW-151": "eb9b387da577ec938fe47fde088404664338226821b1701782ab4d48ecc86adc",
        "B-SYNTAX-STATE-SERIALIZER-TEST": "181163c1483202f4fe422df3b70620f006cb43d9ffef2b5624a441ffd9c738f6",
        "D-WSL-PLAYWRIGHT-BROWSER-UNAVAILABLE": "9162c7c2ec105c0fc4622a915149602f1e338e0ccc37f2138922b95201b5f389",
        "E-ADMIN-FRONTEND-DOM-STUB": "5155f7bc31dee8e14716778a7313146fbacd8c070c48c947e4f72822fe1e0570",
        "E-REMOTE-PRACTICE-DISABLE-TOTP-TEST-DRIFT": "62fafd3fd260b069e3d0952a518ecfc4222a45fa3fd8d506ed064e430a15823f",
        "E-WINDOWS-LOCAL-DATA-CRLF-ASSERTION": "da99e7895af9a5012803b11d96c91592cd0e0d39f766aefafb3f604f596ccb8f",
        "F-WINDOWS-BACKEND-COMPATIBILITY-RUNNER": "9d59e9e9e57e41fe38105e321c2b4e5572beb375c6f3453e14cf1ff7e9701af3",
        "G-STANDALONE-SITE-CONTENT-MEMBERSHIP": "a5047505fc1d6fc3f603aec02ac90360ad614bba14a770306b606d75fd6e817e",
    }
)

RATIFIED_COUNTS = MappingProxyType(
    {
        "productOrPackagingObligations": 4,
        "validationInfrastructureObligations": 14,
        "acceptedCheckpointNonblockingDebts": 3,
        "expectedPrivateResourceOmissions": 2,
        "releaseOnlySkips": 3,
        "confirmedSecurityProductDefects": 0,
        "unresolvedClassifications": 0,
    }
)

HARD_GATE_AUTHORITY = (
    "BASELINE-POLICY-ENFORCEMENT",
    "REPOSITORY-GIT-BOUNDARY",
    "TRACKED-PRIVATE-RESOURCE-EXCLUSION",
    "SECRET-OPERATIONAL-ARTIFACT-EXCLUSION",
    "LICENSE-GOVERNANCE-CONSISTENCY",
    "WORKFLOW-SELF-POLICY",
    "DIRECT-SYNTAX-EXECUTION",
    "BUNDLE-MANIFEST-GENERATED-BYTE-PARITY",
    "FOCUSED-LEARNER-RUNTIME-EXECUTION",
    "FRONTEND-SECURITY-GUARD-EXECUTION",
    "BACKEND-CANONICAL-EXECUTION",
    "STANDALONE-PACKAGE-INTEGRITY",
    "STANDALONE-MEMBERSHIP-AUDIT-EXECUTION",
    "LOCKFILE-BYTE-INTEGRITY",
    "UNKNOWN-NONPASS-FAIL-CLOSED",
)

REQUIRED_BASELINE_FIELDS = {
    "documentKind",
    "schemaVersion",
    "baselineCommit",
    "baselineTree",
    "checkpointTag",
    "policyVersion",
    "ratifiedCounts",
    "approvedActions",
    "hardGates",
    "knownDebts",
    "expectedOmissions",
    "releaseOnlySkips",
    "observationalChecks",
}

REQUIRED_DEBT_FIELDS = {
    "id",
    "category",
    "gate",
    "commandClass",
    "testOrPathScope",
    "expectedOutcome",
    "allowedNormalizedSignature",
    "maximumOccurrences",
    "platforms",
    "checkpointDisposition",
    "targetStage",
    "securityImpact",
    "notes",
}

TEXT_SCAN_SUFFIXES = {
    ".cjs",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
}

ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
ISO_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")
DURATION_VALUE = re.compile(r"(?i)(duration(?:_ms|Milliseconds)?\s*[:=]\s*)\d+(?:\.\d+)?")
UNITTEST_DURATION = re.compile(r"(?i)(\bRan\s+\d+\s+tests?\s+in\s+)\d+(?:\.\d+)?s\b")
WINDOWS_ABSOLUTE_PATH = re.compile(
    r"(?:"
    r"(?<![A-Za-z0-9_.-])[A-Za-z]:[\\/]"
    r"|(?<![A-Za-z0-9_.:/-])(?:"
    r"[\\/]{2}(?:"
    r"[?][\\/](?:[Uu][Nn][Cc][\\/]"
    r"[^\s\x00-\x1f\"'<>|\\/]+[\\/]"
    r"[^\s\x00-\x1f\"'<>|\\/]+|[A-Za-z]:[\\/])"
    r"|[.][\\/][A-Za-z]:[\\/]"
    r"|(?!(?:[?.])[\\/])"
    r"[^\s\x00-\x1f\"'<>|\\/]+[\\/]"
    r"[^\s\x00-\x1f\"'<>|\\/]+"
    r")"
    r"|[\\/][?][?][\\/][A-Za-z]:[\\/]"
    r")"
    r")[^\s\x00-\x1f\"'<>|]*"
)
KNOWN_UNIX_ABSOLUTE_PATH = re.compile(r"(?<![:\w])/(?:home|opt|private|tmp|usr|__w)/[^\s\"'<>|]+")
REPO_SOURCE_LOCATION = re.compile(
    r"(?i)(?:file:///)?(?:[A-Z]:[/\\])?[A-Za-z0-9_ .@()\-+:/\\]+\.(?:cjs|js|mjs|py|ps1|sh)"
    r"(?::\d+(?::\d+)?)?"
)

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    re.IGNORECASE,
)
PRIVATE_KEY_MARKER = re.compile(
    r"-----(?:BEGIN|END) (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    re.IGNORECASE,
)

REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    PRIVATE_KEY_BLOCK,
    PRIVATE_KEY_MARKER,
    re.compile(r"(?i)\bhttps?://[^\s/@:]+:[^\s/@]+@[^\s]+"),
    re.compile(r"(?im)^\s*(?:authorization|proxy-authorization)\s*:\s*[^\n]*$"),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]{4,}"),
    re.compile(r"(?im)^\s*(?:Cookie|Set-Cookie)\s*:\s*[^\n]*$"),
    re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"(?i)\bsk_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(
        r"(?i)\b(?:authorization|password|passwd|secret|token|session(?:id|_id|token)?|cookie)\b"
        r"[ \t\n]*[:=][ \t\n]*(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s]+"),
)

HIGH_CONFIDENCE_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (PRIVATE_KEY_MARKER, "private-key-marker"),
    (re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github-token"),
    (re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "github-token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key"),
    (re.compile(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "slack-token"),
    (re.compile(r"(?i)\bsk_live_[A-Za-z0-9]{16,}\b"), "live-secret-key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "api-key"),
)

SECRET_SCAN_BYTE_PATTERNS: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.I), "private-key-marker"),
    (re.compile(rb"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.I), "private-key-marker"),
    (re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b", re.I), "github-token"),
    (re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b", re.I), "github-token"),
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key"),
    (re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", re.I), "slack-token"),
    (re.compile(rb"\bsk_live_[A-Za-z0-9]{16,}\b", re.I), "live-secret-key"),
    (re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"), "api-key"),
    (
        re.compile(
            rb"(?i)\bhttps?://[^\s/@:\x00]{1,512}:[^\s/@\x00]{1,2048}@[^\s\x00]{1,4096}"
        ),
        "credential-bearing-url",
    ),
    (
        re.compile(
            rb"(?im)^[ \t]*(?:authorization|proxy-authorization)[ \t]*:[^\r\n\x00]{4,4096}$"
        ),
        "authorization-header",
    ),
    (
        re.compile(rb"(?i)\b(?:Bearer|Basic)[ \t]+[A-Za-z0-9+/=_\-.]{16,4096}"),
        "authorization-credential",
    ),
    (
        re.compile(
            rb"(?im)^[ \t]*(?:Cookie|Set-Cookie)[ \t]*:[ \t]*"
            rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+[ \t]*=[^\r\n\x00]{1,4096}\r?$"
        ),
        "cookie-header",
    ),
    (
        re.compile(
            rb"(?i:\b(?:authorization|password|passwd|secret|token|session(?:id|_id|token)?|cookie)\b)"
            rb"[ \t\r\n]{0,64}[:=][ \t\r\n]{0,64}"
            rb"(?:"
            rb"\"(?=[A-Za-z0-9+/=_\-.]{20,4096}\")(?=[A-Za-z0-9+/=_\-.]*[A-Z])"
            rb"(?=[A-Za-z0-9+/=_\-.]*[a-z])(?=[A-Za-z0-9+/=_\-.]*[0-9])"
            rb"[A-Za-z0-9+/=_\-.]{20,4096}\"|"
            rb"'(?=[A-Za-z0-9+/=_\-.]{20,4096}')(?=[A-Za-z0-9+/=_\-.]*[A-Z])"
            rb"(?=[A-Za-z0-9+/=_\-.]*[a-z])(?=[A-Za-z0-9+/=_\-.]*[0-9])"
            rb"[A-Za-z0-9+/=_\-.]{20,4096}'|"
            rb"(?=[A-Za-z0-9+/=_-]{20,4096}(?![A-Za-z0-9+/=_-]))"
            rb"(?=[A-Za-z0-9+/=_-]*[A-Z])(?=[A-Za-z0-9+/=_-]*[a-z])"
            rb"(?=[A-Za-z0-9+/=_-]*[0-9])[A-Za-z0-9+/=_-]{20,4096}"
            rb")"
        ),
        "generic-credential-assignment",
    ),
    (
        re.compile(
            rb"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://"
            rb"[^\s/@:\x00]{1,512}:"
            rb"(?!(?:\$\{?|\{\{|postgres@|password@|changeme@|replace-with-[^@\x00]{0,512}@))"
            rb"[^\s/@\x00]{8,2048}@[^\s\x00]{1,4096}"
        ),
        "credential-database-url",
    ),
)

SECRET_SCAN_PATTERN_FAMILIES = tuple(
    sorted(
        {label for _pattern, label in SECRET_SCAN_BYTE_PATTERNS}
        | {"operational-obfs4-bridge", "operational-onion-hostname"}
    )
)

# The UTF-16 views use the same credential families as the raw-byte pass.  The
# regular-expression sources are ASCII-only, so converting the compiled byte
# patterns preserves their exact matching semantics without maintaining a
# second, weaker pattern list.
SECRET_SCAN_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern.pattern.decode("ascii"), pattern.flags), label)
    for pattern, label in SECRET_SCAN_BYTE_PATTERNS
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def platform_key() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "ubuntu"
    return "other"


RUN_WIDE_COVERAGE_PLATFORMS = frozenset({"ubuntu", "windows"})


def evaluate_run_wide_os_coverage(
    requirements: Sequence[Mapping[str, Any]],
    job_facts: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Separate truthful job-local skips from required live run-wide coverage."""

    errors: list[str] = []
    requirement_map: dict[str, tuple[str, ...]] = {}
    for requirement in requirements:
        family = requirement.get("familyId")
        platforms = requirement.get("requiredLivePlatforms")
        if (
            not isinstance(family, str)
            or not family
            or family in requirement_map
            or not isinstance(platforms, list)
            or not platforms
            or any(platform not in RUN_WIDE_COVERAGE_PLATFORMS for platform in platforms)
            or len(set(platforms)) != len(platforms)
        ):
            errors.append("run-wide coverage requirement schema is invalid")
            continue
        requirement_map[family] = tuple(platforms)

    normalized_facts: list[dict[str, Any]] = []
    for fact in job_facts:
        family = fact.get("familyId")
        job_id = fact.get("jobId")
        platform_name = fact.get("platform")
        mode = fact.get("executionMode")
        counts = {
            key: fact.get(key)
            for key in ("discovered", "passed", "failed", "skippedByPlatform")
        }
        if (
            not isinstance(family, str)
            or family not in requirement_map
            or not isinstance(job_id, str)
            or not job_id
            or platform_name not in RUN_WIDE_COVERAGE_PLATFORMS
            or mode not in {"live", "model"}
            or any(type(value) is not int or value < 0 for value in counts.values())
            or counts["discovered"]
            != counts["passed"] + counts["failed"] + counts["skippedByPlatform"]
        ):
            errors.append("job-local coverage fact schema or totals are invalid")
            continue
        normalized_facts.append(
            {
                "familyId": family,
                "jobId": job_id,
                "platform": platform_name,
                "executionMode": mode,
                **counts,
            }
        )

    records: list[dict[str, Any]] = []
    for family, platforms in sorted(requirement_map.items()):
        for required_platform in platforms:
            matching = [
                fact
                for fact in normalized_facts
                if fact["familyId"] == family
                and fact["platform"] == required_platform
                and fact["executionMode"] == "live"
            ]
            discovered = sum(fact["discovered"] for fact in matching)
            passed = sum(fact["passed"] for fact in matching)
            failed = sum(fact["failed"] for fact in matching)
            skipped = sum(fact["skippedByPlatform"] for fact in matching)
            covered = discovered > 0 and passed > 0 and failed == 0
            records.append(
                {
                    "familyId": family,
                    "requiredLivePlatform": required_platform,
                    "jobLocalDiscovered": discovered,
                    "jobLocalPassed": passed,
                    "jobLocalFailed": failed,
                    "jobLocalSkippedByPlatform": skipped,
                    "runWideCovered": covered,
                }
            )
            if not covered:
                errors.append(
                    f"required live coverage missing: family={family} platform={required_platform}"
                )
    return records, sorted(set(errors))


def strip_terminal_controls(value: str) -> str:
    """Remove terminal escape/control characters before any redaction pass."""

    text = ANSI_OSC.sub("", ANSI_CSI.sub("", value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in {"\n", "\t"}:
            cleaned.append(character)
        elif codepoint < 0x20 or codepoint == 0x7F:
            continue
        elif unicodedata.category(character) == "Cf":
            continue
        else:
            cleaned.append(character)
    return "".join(cleaned)


def _ascii_authority_fold(character: str) -> str:
    """Fold one ASCII capital without applying any Unicode case mapping."""

    if "A" <= character <= "Z":
        return chr(ord(character) + (ord("a") - ord("A")))
    return character


def _ascii_authority_text_equal(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    return all(
        _ascii_authority_fold(left_character)
        == _ascii_authority_fold(right_character)
        for left_character, right_character in zip(left, right)
    )


def _ascii_authority_startswith(value: str, prefix: str) -> bool:
    if len(value) < len(prefix):
        return False
    return _ascii_authority_text_equal(value[: len(prefix)], prefix)


def _ascii_lower_authority_text(value: str) -> str:
    return "".join(_ascii_authority_fold(character) for character in value)


class EnvironmentAuthorityConflict(ValueError):
    """A Windows environment contains conflicting spellings of one key."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"ENVIRONMENT-AUTHORITY-CONFLICT key={key}")


_WINDOWS_ENVIRONMENT_PREFERRED_KEYS = {
    _ascii_lower_authority_text(key): key
    for key in (
        "PATH",
        "SystemRoot",
        "WINDIR",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "CI",
        "GITHUB_ACTIONS",
        "GITHUB_WORKSPACE",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "RUNNER_TEMP",
        "RUNNER_TOOL_CACHE",
        "LANG",
        "LC_ALL",
        "COMSPEC",
        "PATHEXT",
        "NODE_EXE",
        "NPM_EXE",
        "PYTHON_EXE",
        "GIT_EXE",
        "POWERSHELL_EXE",
        "BASH_EXE",
        "CI_TRUSTED_PYTHON",
        "CI_TRUSTED_NODE",
        "CI_TRUSTED_NPM_ENTRY",
    )
}


class _EnvironmentKeyAuthority:
    """Apply one deterministic environment-key authority model per platform."""

    def __init__(
        self,
        source: Mapping[str, str],
        *,
        windows: bool,
        excluded_keys: Iterable[str] = (),
    ) -> None:
        self.windows = windows
        self.source = {str(key): value for key, value in source.items()}
        self.excluded = {
            _ascii_lower_authority_text(key) if windows else key
            for key in excluded_keys
        }
        self.groups: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for key, value in self.source.items():
            authority_key = _ascii_lower_authority_text(key) if windows else key
            if authority_key in self.excluded:
                continue
            self.groups[authority_key].append((key, value))

    @staticmethod
    def _raw_utf8_sort_key(value: str) -> bytes:
        return value.encode("utf-8", errors="strict")

    def _canonical_key(self, authority_key: str) -> str:
        preferred = _WINDOWS_ENVIRONMENT_PREFERRED_KEYS.get(authority_key)
        if preferred is not None:
            return preferred
        return min(
            (key for key, _value in self.groups[authority_key]),
            key=self._raw_utf8_sort_key,
        )

    def _coalesced_value(
        self,
        authority_key: str,
        *,
        display_key: str | None = None,
    ) -> str | None:
        matches = self.groups.get(authority_key, [])
        if not matches:
            return None
        first_value = matches[0][1]
        if any(value != first_value for _key, value in matches[1:]):
            raise EnvironmentAuthorityConflict(
                display_key or self._canonical_key(authority_key)
            )
        return first_value

    def value(self, key: str, default: str | None = None) -> str | None:
        authority_key = (
            _ascii_lower_authority_text(key) if self.windows else key
        )
        value = self._coalesced_value(authority_key, display_key=key)
        return default if value is None else value

    def canonical_subset(self, allowlist: Iterable[str]) -> dict[str, str]:
        if not self.windows:
            allowed = set(allowlist)
            return {
                key: value
                for key, value in self.source.items()
                if key in allowed and key not in self.excluded
            }

        # Validate every non-excluded parent key before constructing any child
        # environment so an unrelated collision cannot choose authority by
        # insertion order.  Equal aliases are emitted once under the explicit
        # allowlist spelling.
        for authority_key in sorted(self.groups, key=self._raw_utf8_sort_key):
            self._coalesced_value(authority_key)
        result: dict[str, str] = {}
        for key in sorted(set(allowlist), key=self._raw_utf8_sort_key):
            authority_key = _ascii_lower_authority_text(key)
            if authority_key in self.excluded:
                continue
            value = self._coalesced_value(authority_key, display_key=key)
            if value is not None:
                result[key] = value
        return result


def _environment_authority_value(
    source: Mapping[str, str],
    key: str,
    *,
    windows: bool,
    default: str | None = None,
) -> str | None:
    """Read one environment authority with Windows' ASCII key semantics.

    POSIX keys remain byte-for-byte case-sensitive.  On Windows, duplicate
    ASCII-case spellings are accepted only when every spelling has the same
    value; a conflicting collision cannot select authority by insertion order.
    """

    return _EnvironmentKeyAuthority(source, windows=windows).value(key, default)


def windows_authority_component_equal(left: str, right: str) -> bool:
    """Compare a Windows authority component with conservative equivalence.

    ASCII capitals compare with their ASCII lowercase spelling.  Every
    non-ASCII scalar, punctuation character, and component boundary remains
    exact.  This is security authorization equivalence, not an emulation of
    every Windows filesystem collation rule.
    """

    return _ascii_authority_text_equal(left, right)


@dataclass(frozen=True)
class WindowsAbsoluteReference:
    kind: str
    authority_path: str | None = None
    authorizable: bool = False


def _windows_separator(value: str, index: int) -> bool:
    return index < len(value) and value[index] in "/\\"


def _windows_drive_at(value: str, index: int) -> bool:
    return (
        index + 2 < len(value)
        and ("A" <= value[index] <= "Z" or "a" <= value[index] <= "z")
        and value[index + 1] == ":"
        and _windows_separator(value, index + 2)
    )


def _has_invalid_percent_escape(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or not re.fullmatch(
            r"[0-9A-Fa-f]{2}", value[index + 1 : index + 3]
        ):
            return True
        index += 3
    return False


def _has_encoded_separator(value: str) -> bool:
    for match in re.finditer(r"%([0-9A-Fa-f]{2})", value):
        codepoint = int(match.group(1), 16)
        if codepoint in {ord("/"), ord("\\")}:
            return True
    return False


def _file_uri_decoded_text(value: str) -> str | None:
    if _has_invalid_percent_escape(value) or _has_encoded_separator(value):
        return None
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
        return None
    return decoded


def _strict_file_uri_reference(value: str) -> WindowsAbsoluteReference | None:
    if not _ascii_authority_startswith(value, "file:"):
        return None
    parsed = urlsplit(value)
    if not _ascii_authority_text_equal(parsed.scheme, "file"):
        return None
    if parsed.query or parsed.fragment:
        return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")
    if "@" in parsed.netloc or parsed.username or parsed.password:
        return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")

    netloc = _file_uri_decoded_text(parsed.netloc)
    path = _file_uri_decoded_text(parsed.path)
    if netloc is None or path is None:
        return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")

    if netloc:
        if not path.startswith("/") or path == "/":
            return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")
        authority_path = "//" + netloc + path
        if _windows_authority_path_parts(authority_path) is None:
            return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")
        return WindowsAbsoluteReference(
            "file-unc-uri",
            authority_path.replace("\\", "/"),
            True,
        )

    if path.startswith("//"):
        authority_path = path
        if _windows_authority_path_parts(authority_path) is None:
            return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")
        return WindowsAbsoluteReference(
            "file-unc-uri",
            authority_path.replace("\\", "/"),
            True,
        )

    if len(path) >= 4 and path[0] == "/" and _windows_drive_at(path, 1):
        return WindowsAbsoluteReference(
            "file-drive-uri",
            path[1:].replace("\\", "/"),
            True,
        )

    if path.startswith("/"):
        return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")
    return WindowsAbsoluteReference("ordinary-prose")


def classify_windows_absolute_reference(value: str) -> WindowsAbsoluteReference:
    """Classify a complete Windows absolute reference span.

    The classifier is closed: recognized, suspicious, or malformed absolute
    namespaces are distinguishable from ordinary prose and can be redacted
    even when they are not valid authorizable drive/UNC roots.
    """

    if not value:
        return WindowsAbsoluteReference("ordinary-prose")

    file_uri = _strict_file_uri_reference(value)
    if file_uri is not None:
        return file_uri

    if _windows_drive_at(value, 0):
        return WindowsAbsoluteReference("drive-absolute", value.replace("\\", "/"), True)

    if _windows_separator(value, 0) and _windows_separator(value, 1):
        if len(value) > 3 and value[2] == "?" and _windows_separator(value, 3):
            if (
                len(value) > 7
                and _ascii_authority_text_equal(value[4:7], "UNC")
                and _windows_separator(value, 7)
            ):
                return WindowsAbsoluteReference(
                    "extended-unc",
                    "//" + value[8:].replace("\\", "/"),
                    True,
                )
            if _windows_drive_at(value, 4):
                return WindowsAbsoluteReference(
                    "extended-drive",
                    value[4:].replace("\\", "/"),
                    True,
                )
            if (
                len(value) > 15
                and _ascii_authority_text_equal(value[4:14], "GLOBALROOT")
                and _windows_separator(value, 14)
            ):
                return WindowsAbsoluteReference("globalroot")
            if (
                len(value) > 12
                and _ascii_authority_startswith(value[4:], "Volume{")
                and "}" in value[11:]
            ):
                return WindowsAbsoluteReference("volume-guid")
            return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")

        if len(value) > 3 and value[2] == "." and _windows_separator(value, 3):
            if _windows_drive_at(value, 4):
                return WindowsAbsoluteReference("win32-device-drive")
            return WindowsAbsoluteReference("win32-device-path")

        return WindowsAbsoluteReference("unc", value.replace("\\", "/"), True)

    if (
        _windows_separator(value, 0)
        and len(value) > 3
        and value[1:3] == "??"
        and _windows_separator(value, 3)
    ):
        if _windows_drive_at(value, 4):
            return WindowsAbsoluteReference("nt-dos-device-path")
        if (
            len(value) > 7
            and _ascii_authority_text_equal(value[4:7], "UNC")
            and _windows_separator(value, 7)
        ):
            return WindowsAbsoluteReference("nt-unc-path")
        return WindowsAbsoluteReference("unsupported-absolute-windows-namespace")

    if (
        _windows_separator(value, 0)
        and len(value) > 8
        and _ascii_authority_text_equal(value[1:7], "Device")
        and _windows_separator(value, 7)
    ):
        return WindowsAbsoluteReference("nt-device-path")

    if _windows_separator(value, 0):
        return WindowsAbsoluteReference("relative-path")
    return WindowsAbsoluteReference("ordinary-prose")


def _windows_authority_path_form(value: str) -> str | None:
    """Identify an absolute Windows namespace without rewriting its text."""

    reference = classify_windows_absolute_reference(value)
    aliases = {
        "drive-absolute": "drive",
        "unc": "unc",
        "extended-unc": "extended-unc",
        "extended-drive": "extended-drive",
        "win32-device-drive": "device-drive",
        "win32-device-path": "win32-device-path",
        "globalroot": "globalroot",
        "volume-guid": "volume-guid",
        "nt-device-path": "nt-device-path",
        "nt-dos-device-path": "nt-dos-device-path",
        "nt-unc-path": "nt-unc-path",
        "file-drive-uri": "file-drive-uri",
        "file-unc-uri": "file-unc-uri",
        "unsupported-absolute-windows-namespace": "unsupported-absolute-windows-namespace",
    }
    return aliases.get(reference.kind)


def _windows_authority_path_parts(value: str) -> tuple[str, tuple[str, ...]] | None:
    """Identify form, then parse after separator-only normalization."""

    reference = classify_windows_absolute_reference(value)
    if not reference.authorizable or reference.authority_path is None:
        return None
    form = _windows_authority_path_form(value)
    if form is None:
        return None
    text = reference.authority_path.replace("\\", "/")
    while len(text) > 3 and text.endswith("/"):
        text = text[:-1]

    def drive_component(component: str) -> bool:
        return (
            len(component) == 2
            and ("A" <= component[0] <= "Z" or "a" <= component[0] <= "z")
            and component[1] == ":"
        )

    if form == "drive":
        tail = text[3:]
        components = (text[:2], *(tail.split("/") if tail else ()))
        if any(not component for component in components):
            return None
        return form, components

    if form in {"unc", "extended-unc", "extended-drive", "file-unc-uri", "file-drive-uri"}:
        if form in {"extended-drive", "file-drive-uri"}:
            components = text.split("/")
        else:
            components = text[2:].split("/")
        if any(not component for component in components):
            return None
        if form in {"unc", "extended-unc", "file-unc-uri"} and len(components) >= 2:
            return form, tuple(components)
        if form in {"extended-drive", "file-drive-uri"} and drive_component(components[0]):
            return form, tuple(components)
        return None
    return None


def windows_authority_path_prefix(candidate: str, authorized_root: str) -> bool:
    """Return whether two complete Windows root spellings authorize equally."""

    candidate_parts = _windows_authority_path_parts(candidate)
    root_parts = _windows_authority_path_parts(authorized_root)
    if candidate_parts is None or root_parts is None:
        return False
    candidate_form, candidate_components = candidate_parts
    root_form, root_components = root_parts
    return (
        candidate_form == root_form
        and len(candidate_components) == len(root_components)
        and all(
            windows_authority_component_equal(candidate_component, root_component)
            for candidate_component, root_component in zip(
                candidate_components, root_components
            )
        )
    )


def windows_authority_path_is_within(candidate: str, authorized_root: str) -> bool:
    """Compare canonical drive paths by complete ASCII-folded components."""

    candidate_parts = _windows_authority_path_parts(candidate)
    root_parts = _windows_authority_path_parts(authorized_root)
    if candidate_parts is None or root_parts is None:
        return False
    candidate_form, candidate_components = candidate_parts
    root_form, root_components = root_parts
    return (
        candidate_form == root_form == "drive"
        and len(candidate_components) >= len(root_components)
        and all(
            windows_authority_component_equal(candidate_component, root_component)
            for candidate_component, root_component in zip(
                candidate_components,
                root_components,
            )
        )
    )


def _normalization_root_record(value: str | Path, token: str) -> tuple[str, str, bool]:
    text = str(value)
    windows = _windows_authority_path_parts(text) is not None
    if windows:
        normalized = text.replace("\\", "/")
        while len(normalized) > 3 and normalized.endswith("/"):
            normalized = normalized[:-1]
    else:
        normalized = text
        while len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized[:-1]
    return normalized, token, windows


def _normalization_root_records(
    value: str | Path, token: str
) -> list[tuple[str, str, bool]]:
    """Return native and narrowly derived file-URI path spellings for one root."""

    native = _normalization_root_record(value, token)
    records = [native]
    root, _token, windows = native
    if not windows:
        return records
    reference = classify_windows_absolute_reference(root)
    authority_path = reference.authority_path
    if authority_path is None:
        return records
    normalized_authority = authority_path.replace("\\", "/")
    parts = _windows_authority_path_parts(root)
    if parts is None:
        return records
    form = parts[0]
    if form in {"drive", "extended-drive"}:
        try:
            uri_path = quote(
                normalized_authority,
                safe="/:",
                encoding="utf-8",
                errors="strict",
            )
        except UnicodeEncodeError:
            return records
        records.append(("file:///" + uri_path, token, windows))
    if form in {"unc", "extended-unc"} and normalized_authority.startswith("//"):
        try:
            uri_path = quote(
                normalized_authority[2:],
                safe="/:",
                encoding="utf-8",
                errors="strict",
            )
        except UnicodeEncodeError:
            return records
        records.append(("file://" + uri_path, token, windows))
        records.append(("file:////" + uri_path, token, windows))
    return records


def _authorized_root_pattern(root: str, *, windows: bool) -> re.Pattern[str]:
    """Match one POSIX root only at exact path-component boundaries."""

    if windows:
        raise ValueError("Windows authority roots use the conservative comparator")
    if not root.startswith("/"):
        raise ValueError("POSIX normalization roots must be absolute")
    components = [part for part in root.split("/") if part]
    body = "/" + "/".join(re.escape(part) for part in components)
    return re.compile(r"(?<![A-Za-z0-9_.-])" + body + r"(?=$|/)")


TOKENIZED_AUTHORIZED_PATH = re.compile(
    r"(?P<token><(?:repo|task-root)>)"
    r"(?P<suffix>(?:[\\/][^\s\x00-\x1f\"'<>|]+)*)"
)


def _replace_windows_authorized_root(text: str, root: str, token: str) -> str:
    """Replace conservative, component-bounded Windows authority matches."""

    if not root:
        return text
    output: list[str] = []
    cursor = 0
    index = 0
    root_length = len(root)
    root_parts = _windows_authority_path_parts(root)
    if root_parts is None:
        return text
    root_form = root_parts[0]
    while index + root_length <= len(text):
        previous = text[index - 1] if index else ""
        if previous and (
            "A" <= previous <= "Z"
            or "a" <= previous <= "z"
            or "0" <= previous <= "9"
            or previous in "_.-"
        ):
            index += 1
            continue
        if previous and previous in ":/\\" and root_form != "drive":
            index += 1
            continue
        end = index + root_length
        following = text[end] if end < len(text) else ""
        if following and following not in "/\\":
            index += 1
            continue
        if root_form in {"file-drive-uri", "file-unc-uri"}:
            span_end = _windows_reference_span_end(text, index)
            reference = classify_windows_absolute_reference(text[index:span_end])
            if reference.kind != root_form or not reference.authorizable:
                index += 1
                continue
        if windows_authority_path_prefix(text[index:end], root):
            output.append(text[cursor:index])
            output.append(token)
            cursor = end
            index = end
            continue
        index += 1
    output.append(text[cursor:])
    return "".join(output)


def _windows_reference_start(text: str, index: int) -> bool:
    previous = text[index - 1] if index else ""
    if _ascii_authority_startswith(text[index:], "file:"):
        return not previous or not (
            "A" <= previous <= "Z"
            or "a" <= previous <= "z"
            or "0" <= previous <= "9"
            or previous in "_.-"
        )
    if _windows_drive_at(text, index):
        return not previous or not (
            "A" <= previous <= "Z"
            or "a" <= previous <= "z"
            or "0" <= previous <= "9"
            or previous in "_.-"
        )
    if _windows_separator(text, index) and _windows_separator(text, index + 1):
        if previous and previous in ":/\\._-":
            return False
        return True
    if _windows_separator(text, index):
        if previous and (
            "A" <= previous <= "Z"
            or "a" <= previous <= "z"
            or "0" <= previous <= "9"
            or previous in "_.:/\\-"
        ):
            return False
        tail = text[index:]
        return (
            len(tail) > 7
            and _ascii_authority_text_equal(tail[1:7], "Device")
            and _windows_separator(tail, 7)
        ) or (
            len(tail) > 3
            and tail[1:3] == "??"
            and _windows_separator(tail, 3)
        )
    return False


def _windows_reference_span_end(text: str, index: int) -> int:
    end = index
    while end < len(text):
        character = text[end]
        if character.isspace() or ord(character) < 0x20 or character in "\"'<>|":
            break
        end += 1
    while end > index and text[end - 1] in ".,;":
        end -= 1
    return end


def redact_windows_absolute_references(text: str) -> str:
    output: list[str] = []
    cursor = 0
    index = 0
    while index < len(text):
        if not _windows_reference_start(text, index):
            index += 1
            continue
        end = _windows_reference_span_end(text, index)
        if end <= index:
            index += 1
            continue
        reference = classify_windows_absolute_reference(text[index:end])
        if reference.kind in {"ordinary-prose", "relative-path"}:
            index += 1
            continue
        output.append(text[cursor:index])
        output.append("<abs-path>")
        cursor = end
        index = end
    output.append(text[cursor:])
    return "".join(output)


def normalize_authorized_path_text(
    value: str,
    *,
    repository_root: str | Path | None = None,
    task_roots: Sequence[str | Path] | None = None,
) -> str:
    """Tokenize recognized roots before any decoded backslash can look like an escape.

    Windows roots use explicit ASCII-only case equivalence and accept either
    separator; non-ASCII scalars remain exact.  POSIX roots compare
    case-sensitively.  Every match is component-bounded, and the longest
    authorized root wins.  Other drive, UNC, and device absolute paths are
    reduced to the closed absolute-path token.
    """

    selected_repository_root = REPO_ROOT if repository_root is None else repository_root
    selected_task_roots: list[str | Path] = []
    if task_roots is None:
        for name in ("TEMP", "TMP", "TMPDIR"):
            candidate = os.environ.get(name)
            if candidate:
                selected_task_roots.append(candidate)
        try:
            selected_task_roots.append(tempfile.gettempdir())
        except (OSError, RuntimeError):
            pass
    else:
        selected_task_roots.extend(task_roots)

    records = _normalization_root_records(selected_repository_root, "<repo>")
    for candidate in selected_task_roots:
        if str(candidate):
            records.extend(
                _normalization_root_records(candidate, "<task-root>")
            )
    unique: list[tuple[str, str, bool]] = []
    for root, token, windows in records:
        if not root or (not windows and not root.startswith("/")):
            continue
        root_parts = _windows_authority_path_parts(root) if windows else None
        duplicate = any(
            existing_windows == windows
            and (
                (
                    root == existing_root
                    if (
                        root_parts is not None
                        and root_parts[0] in {"file-drive-uri", "file-unc-uri"}
                    )
                    else windows_authority_path_prefix(root, existing_root)
                )
                if windows
                else root == existing_root
            )
            for existing_root, _existing_token, existing_windows in unique
        )
        if duplicate:
            continue
        unique.append((root, token, windows))
    unique.sort(
        key=lambda item: (len(item[0]), item[1] == "<repo>"),
        reverse=True,
    )

    text = value
    for root, token, windows in unique:
        if windows:
            text = _replace_windows_authorized_root(text, root, token)
        else:
            text = _authorized_root_pattern(root, windows=False).sub(token, text)
    # Once an authorized root has been recognized, every following separator
    # in that path is unambiguously path syntax.  Normalize that relative
    # suffix here, before JSON-looking sequences such as ``\repo`` or
    # ``\u1234`` can be protected as text escapes by the raw-observation pass.
    text = TOKENIZED_AUTHORIZED_PATH.sub(
        lambda match: match.group("token")
        + match.group("suffix").replace("\\", "/"),
        text,
    )
    text = redact_windows_absolute_references(text)
    text = KNOWN_UNIX_ABSOLUTE_PATH.sub("<abs-path>", text)
    return text


def normalize_text(value: str) -> str:
    """Narrowly normalize platform paths, line endings, timestamps, and timings."""

    text = normalize_authorized_path_text(value)
    text = strip_terminal_controls(text)
    text = text.replace("\\", "/")
    text = redact_windows_absolute_references(text)
    text = KNOWN_UNIX_ABSOLUTE_PATH.sub("<abs-path>", text)
    text = ISO_TIMESTAMP.sub("<timestamp>", text)
    text = DURATION_VALUE.sub(r"\1<duration>", text)
    text = UNITTEST_DURATION.sub(r"\1<duration>s", text)
    text = re.sub(r"Node\.js v\d+\.\d+\.\d+", "Node.js v<version>", text)
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def sanitize_text(value: str) -> str:
    text = normalize_text(value)
    for pattern in REDACTION_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def contains_high_confidence_secret(value: str) -> list[str]:
    hits: list[str] = []
    for pattern, label in HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.search(value):
            hits.append(label)
    bridge_pattern = re.compile(
        r"(?im)^\s*obfs4\s+\S+:\d+\s+[A-F0-9]{40}\s+cert=\S+\s+iat-mode=\d+\s*$"
    )
    if bridge_pattern.search(value):
        hits.append("operational-obfs4-bridge")
    onion_pattern = re.compile(r"(?i)\b[a-z2-7]{56}\.onion\b")
    if onion_pattern.search(value):
        hits.append("operational-onion-hostname")
    return sorted(set(hits))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalized_json_value(value: Any) -> Any:
    volatile_keys = {
        "generatedAt",
        "generated_at",
        "timestamp",
        "duration",
        "durationMs",
        "durationMilliseconds",
        "duration_ms",
    }
    if isinstance(value, Mapping):
        return {
            str(key): normalized_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in volatile_keys
        }
    if isinstance(value, list):
        return [normalized_json_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def raw_observation_json_value(value: Any) -> Any:
    """Normalize producer text without corrupting JSON escapes embedded in it."""

    volatile_keys = {
        "generatedAt",
        "generated_at",
        "timestamp",
        "duration",
        "durationMs",
        "durationMilliseconds",
        "duration_ms",
    }
    if isinstance(value, Mapping):
        return {
            str(key): raw_observation_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in volatile_keys
        }
    if isinstance(value, list):
        return [raw_observation_json_value(item) for item in value]
    if not isinstance(value, str):
        return value

    # Root tokenization deliberately precedes protection of JSON-looking text.
    # A decoded ``\\repo`` or ``\\u1234`` path component is therefore a path,
    # never a second opportunity to interpret JSON/Python escape syntax.
    text = strip_terminal_controls(normalize_authorized_path_text(value))
    prefix = "__CI_RAW_JSON_ESCAPE__"
    while prefix in text:
        prefix += "_"
    escapes: list[str] = []

    def protect(match: re.Match[str]) -> str:
        escapes.append(match.group(0))
        return f"{prefix}{len(escapes) - 1}__"

    protected = re.sub(
        r'(?<!\\)\\(?:["/bfnrt]|u[0-9A-Fa-f]{4})',
        protect,
        text,
    )
    normalized = normalize_text(protected)
    for index, escaped in enumerate(escapes):
        normalized = normalized.replace(f"{prefix}{index}__", escaped)
    for pattern in REDACTION_PATTERNS:
        normalized = pattern.sub("[REDACTED]", normalized)
    return normalized


def structured_signature(value: Any) -> str:
    canonical = json.dumps(
        normalized_json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{sha256_text(canonical)}"


def _canonical_frame(value: Any) -> bytes:
    """Encode JSON-compatible values with stable, type-aware length framing."""

    def frame(tag: bytes, payload: bytes) -> bytes:
        return tag + len(payload).to_bytes(
            CANONICAL_FRAME_LENGTH_WIDTH_BYTES,
            CANONICAL_FRAME_BYTE_ORDER,
            signed=False,
        ) + payload

    def count(value: int) -> bytes:
        return value.to_bytes(
            CANONICAL_FRAME_COUNT_WIDTH_BYTES,
            CANONICAL_FRAME_BYTE_ORDER,
            signed=False,
        )

    if value is None:
        return frame(CANONICAL_FRAME_TAGS["null"], b"")
    if type(value) is bool:
        return frame(CANONICAL_FRAME_TAGS["boolean"], b"1" if value else b"0")
    if type(value) is int:
        return frame(CANONICAL_FRAME_TAGS["integer"], str(value).encode("ascii"))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical failure material forbids non-finite numbers")
        return frame(CANONICAL_FRAME_TAGS["float"], value.hex().encode("ascii"))
    if isinstance(value, str):
        normalized = unicodedata.normalize(CANONICAL_FRAME_UNICODE_NORMALIZATION, value)
        return frame(
            CANONICAL_FRAME_TAGS["text"],
            normalized.encode(CANONICAL_FRAME_TEXT_ENCODING, errors="strict"),
        )
    if isinstance(value, bytes):
        return frame(CANONICAL_FRAME_TAGS["bytes"], value)
    if isinstance(value, (list, tuple)):
        payload = count(len(value)) + b"".join(
            _canonical_frame(item) for item in value
        )
        return frame(CANONICAL_FRAME_TAGS["list"], payload)
    if isinstance(value, Mapping):
        items: list[tuple[bytes, Any]] = []
        seen: set[bytes] = set()
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError("canonical failure material object keys must be strings")
            key = unicodedata.normalize(
                CANONICAL_FRAME_UNICODE_NORMALIZATION, raw_key
            ).encode(CANONICAL_FRAME_TEXT_ENCODING, errors="strict")
            if key in seen:
                raise ValueError("canonical failure material contains a duplicate normalized key")
            seen.add(key)
            items.append((key, item))
        items.sort(key=lambda pair: pair[0])
        payload = count(len(items))
        for key, item in items:
            payload += frame(CANONICAL_FRAME_TAGS["map-key"], key) + _canonical_frame(
                item
            )
        return frame(CANONICAL_FRAME_TAGS["map"], payload)
    raise TypeError(f"unsupported canonical failure material type: {type(value).__name__}")


def canonical_failure_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_frame(value)).hexdigest()


FROZEN_V1_RELEASE_SKIP_DETAIL_FIELDS = MappingProxyType(
    {
        "Release ZIP 运行时内容守卫": frozenset({"reason", "skipped"}),
        "PDF 对账与回归审计": frozenset(
            {
                "invalidStatusRows",
                "missingEvidenceForVerified",
                "monaAnswerMismatches",
                "monaBannedPatternHits",
                "monaCoverageOk",
                "onlyInChecklist",
                "onlyInMapping",
                "reason",
                "status",
            }
        ),
        "Checklist 对账一致性校验": frozenset(
            {
                "claimMismatches",
                "claims",
                "freshnessMismatches",
                "issueStatusCount",
                "reason",
                "reportFreshness",
                "status",
                "summaryMismatches",
                "summaryStatusCount",
            }
        ),
    }
)


def _frozen_v1_normalized_value(value: Any, *, path: str) -> Any:
    """Normalize one frozen-v1 value without accepting ambiguous JSON shapes."""

    if value is None or type(value) in {bool, int}:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", normalize_text(value))
    if isinstance(value, list):
        normalized = [
            _frozen_v1_normalized_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
        framed_members: set[bytes] = set()
        for item in normalized:
            framed = _canonical_frame(item)
            if framed in framed_members:
                raise ValueError(f"{path} contains a duplicate normalized member")
            framed_members.add(framed)
        return normalized
    if isinstance(value, Mapping):
        normalized_items: list[tuple[bytes, str, Any]] = []
        normalized_keys: set[bytes] = set()
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise TypeError(f"{path} contains a non-string object key")
            key_text = unicodedata.normalize("NFC", raw_key)
            key_bytes = key_text.encode("utf-8", errors="strict")
            if key_bytes in normalized_keys:
                raise ValueError(f"{path} contains a duplicate normalized key")
            normalized_keys.add(key_bytes)
            normalized_items.append(
                (
                    key_bytes,
                    key_text,
                    _frozen_v1_normalized_value(item, path=f"{path}.{key_text}"),
                )
            )
        normalized_items.sort(key=lambda item: item[0])
        return {key: item for _key_bytes, key, item in normalized_items}
    raise TypeError(f"{path} contains unsupported type {type(value).__name__}")


def frozen_v1_release_skip_comparison_material(
    validated_raw_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fixed frozen-v1 release-skip schema from validated raw facts."""

    source_result_id = validated_raw_observation.get("sourceResultId")
    expected_fields = FROZEN_V1_RELEASE_SKIP_DETAIL_FIELDS.get(str(source_result_id))
    if expected_fields is None:
        raise ValueError("raw observation is not a frozen-v1 release-only skip")
    raw_fields = validated_raw_observation.get("rawStructuredFields")
    if not isinstance(raw_fields, Mapping):
        raise TypeError("frozen-v1 release-only skip fields must be an object")
    detail = raw_fields.get("detail")
    if not isinstance(detail, Mapping):
        raise TypeError("frozen-v1 release-only skip detail must be an object")
    normalized_detail = _frozen_v1_normalized_value(
        detail,
        path=f"releaseSkip:{source_result_id}.detail",
    )
    assert isinstance(normalized_detail, dict)
    detail_members = [
        {
            "field": field_name,
            "presence": "present" if field_name in normalized_detail else "absent",
            "value": normalized_detail.get(field_name),
        }
        for field_name in sorted(expected_fields)
    ]
    unexpected_detail_members = [
        {"field": field_name, "value": normalized_detail[field_name]}
        for field_name in sorted(set(normalized_detail) - set(expected_fields))
    ]
    unexpected_outer_members = [
        {
            "field": field_name,
            "value": _frozen_v1_normalized_value(
                raw_fields[field_name],
                path=f"releaseSkip:{source_result_id}.{field_name}",
            ),
        }
        for field_name in sorted(set(raw_fields) - {"name", "status", "detail"})
    ]
    material = {
        "schemaVersion": FROZEN_V1_RELEASE_SKIP_SIGNATURE_SCHEMA_VERSION,
        "wireEncoding": "phase1-normalized-json-v1",
        "commandId": validated_raw_observation.get("commandId"),
        "observationKind": validated_raw_observation.get("observationKind"),
        "sourceResultId": source_result_id,
        "sourcePath": validated_raw_observation.get("sourcePath"),
        "outerName": _frozen_v1_normalized_value(
            raw_fields.get("name"),
            path=f"releaseSkip:{source_result_id}.name",
        ),
        "outerStatus": _frozen_v1_normalized_value(
            raw_fields.get("status"),
            path=f"releaseSkip:{source_result_id}.status",
        ),
        "detailMembers": detail_members,
        "unexpectedDetailMembers": unexpected_detail_members,
        "unexpectedOuterMembers": unexpected_outer_members,
        "historicalCanonicalDetail": normalized_detail,
    }
    # This validation frame is the unambiguous, type-aware representation used
    # to reject duplicate/ambiguous material. The returned comparison digest
    # below retains the Phase 1 JSON wire bytes because those bytes are frozen.
    _canonical_frame(material)
    return material


def derive_frozen_v1_release_skip_signature(
    validated_raw_observation: Mapping[str, Any],
) -> str:
    """Reproduce a frozen Phase 1 release-skip signature from raw facts only."""

    material = frozen_v1_release_skip_comparison_material(validated_raw_observation)
    exact_shape = (
        material["commandId"] == "static-suite"
        and material["observationKind"] == "static-producer-v1"
        and material["sourcePath"] == STATIC_SUITE_RELATIVE_PATH
        and material["outerName"] == material["sourceResultId"]
        and material["outerStatus"] == "pass"
        and not material["unexpectedDetailMembers"]
        and not material["unexpectedOuterMembers"]
        and all(member["presence"] == "present" for member in material["detailMembers"])
    )
    if not exact_shape:
        # Invalid, omitted, expanded, or misplaced material gets a deterministic
        # non-baseline digest so comparison fails closed without hiding members.
        return canonical_failure_digest(material)
    canonical = json.dumps(
        material["historicalCanonicalDetail"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return f"sha256:{sha256_text(canonical)}"


_DERIVED_FAILURE_FIELD_NAMES = frozenset(
    {
        "allowedNormalizedSignature",
        "baselineId",
        "baselineSignature",
        "canonicalFailureMaterialVersion",
        "derivedFailureDigest",
        "derivedFailureMembers",
        "expectedDisposition",
        "failureDigest",
        "failureIdentity",
        "failureIdentityHash",
        "legacyBaselineComparisonDigest",
        "normalizedSignature",
        "pathAuthority",
        "signature",
        "structuredFailureSet",
        "currentFullContextDigest",
    }
)


def _raw_observation_forbidden_fields(value: Any, *, path: str = "rawStructuredFields") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text in _DERIVED_FAILURE_FIELD_NAMES:
                errors.append(f"{path}.{key_text} is a derived or baseline-authority field")
            errors.extend(_raw_observation_forbidden_fields(child, path=f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_raw_observation_forbidden_fields(child, path=f"{path}[{index}]"))
    return errors


def _producer_record_digest(record_without_digest: Mapping[str, Any]) -> str:
    return canonical_failure_digest(record_without_digest)


def make_raw_observation(
    command_id: str,
    command_ordinal: int,
    observation_ordinal: int,
    observation_kind: str,
    source_result_id: str,
    source_path: str | None,
    raw_structured_fields: Any,
    source_output_digest: str,
    occurrences: int = 1,
    failure_path_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one baseline-blind producer observation with a self-checking frame."""

    record = {
        "schemaVersion": RAW_OBSERVATION_SCHEMA_VERSION,
        "commandId": command_id,
        "commandOrdinal": command_ordinal,
        "observationOrdinal": observation_ordinal,
        "observationKind": observation_kind,
        "sourceResultId": source_result_id,
        "sourcePath": source_path,
        "rawStructuredFields": raw_observation_json_value(raw_structured_fields),
        "failurePathAuthority": (
            normalized_json_value(copy.deepcopy(failure_path_authority))
            if failure_path_authority is not None
            else None
        ),
        "sourceOutputDigest": source_output_digest,
        "occurrences": occurrences,
    }
    record["producerRecordDigest"] = _producer_record_digest(record)
    return record


def producer_observation_set_digest(observations: Sequence[Mapping[str, Any]]) -> str:
    return canonical_failure_digest(list(observations))


def _truncate_utf8(value: str, byte_limit: int, *, keep_tail: bool = False) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= byte_limit:
        return value
    selected = encoded[-byte_limit:] if keep_tail else encoded[:byte_limit]
    return selected.decode("utf-8", errors="ignore")


def bounded_preview(
    value: str,
    *,
    max_lines: int = 24,
    max_bytes: int = MAX_EVIDENCE_PREVIEW_BYTES,
) -> str:
    safe_lines = [
        _truncate_utf8(line, MAX_OUTPUT_LINE_BYTES)
        for line in sanitize_text(value).splitlines()
    ]
    if len(safe_lines) > max_lines:
        head_count = max(1, max_lines // 2)
        tail_count = max(1, max_lines - head_count - 1)
        safe_lines = safe_lines[:head_count] + ["[DIAGNOSTIC-TRUNCATED]"] + safe_lines[-tail_count:]
    preview = "\n".join(safe_lines)
    if len(preview.encode("utf-8", errors="replace")) > max_bytes:
        half = max(1, (max_bytes - 32) // 2)
        preview = (
            _truncate_utf8(preview, half)
            + "\n[DIAGNOSTIC-TRUNCATED]\n"
            + _truncate_utf8(preview, half, keep_tail=True)
        )
        preview = _truncate_utf8(preview, max_bytes)
    return preview


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _authority_path_is_within(path: Path, parent: Path, *, windows: bool) -> bool:
    if windows and os.name == "nt":
        return windows_authority_path_is_within(str(path), str(parent))
    return _path_is_within(path, parent)


def _authority_paths_equal(left: Path, right: Path, *, windows: bool) -> bool:
    if windows and os.name == "nt":
        return windows_authority_path_prefix(str(left), str(right))
    return left == right


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _secure_regular_file(path: Path) -> tuple[bool, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        return False, f"{type(exc).__name__}: cannot stat executable"
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        return False, "symbolic links and reparse points are not trusted"
    if not stat.S_ISREG(metadata.st_mode):
        return False, "tool is not a regular file"
    return True, ""


TOOL_AUTHORITY_UNAVAILABLE_CODE = "CI_TOOL_AUTHORITY_UNAVAILABLE"
WINDOWS_GIT_EXECUTABLE_SUFFIXES = (
    ("bin", "git.exe"),
    ("cmd", "git.exe"),
)
WINDOWS_GIT_BASH_CANDIDATE_SUFFIXES = (
    ("bin", "bash.exe"),
    ("usr", "bin", "bash.exe"),
)
GIT_INSTALL_ROOT_UNRECOGNIZED = "GIT_INSTALL_ROOT_UNRECOGNIZED"
BASH_CANDIDATE_ABSENT = "BASH_CANDIDATE_ABSENT"
BASH_CANDIDATE_UNREADABLE = "BASH_CANDIDATE_UNREADABLE"
BASH_CANDIDATE_OUTSIDE_GIT_ROOT = "BASH_CANDIDATE_OUTSIDE_GIT_ROOT"
BASH_CANDIDATE_REPARSE = "BASH_CANDIDATE_REPARSE"
BASH_CANDIDATE_NONREGULAR = "BASH_CANDIDATE_NONREGULAR"
BASH_CANDIDATE_HARDLINK = "BASH_CANDIDATE_HARDLINK"
BASH_CANDIDATE_UNSAFE_ROOT = "BASH_CANDIDATE_UNSAFE_ROOT"
BASH_CANDIDATE_IDENTITY_DRIFT = "BASH_CANDIDATE_IDENTITY_DRIFT"
BASH_CANDIDATE_VERSION_FAILURE = "BASH_CANDIDATE_VERSION_FAILURE"
BASH_CANDIDATE_LEASE_FAILURE = "BASH_CANDIDATE_LEASE_FAILURE"
BASH_CANDIDATE_ACCEPTED = "BASH_CANDIDATE_ACCEPTED"
PATH_PREDECESSOR_UNINSPECTABLE = "PATH_PREDECESSOR_UNINSPECTABLE"
PATH_EXECUTABLE_SHADOW = "PATH_EXECUTABLE_SHADOW"
PATH_REPARSE_ESCAPE = "PATH_REPARSE_ESCAPE"
PATH_WORKSPACE_OR_TEMP_AUTHORITY = "PATH_WORKSPACE_OR_TEMP_AUTHORITY"
PATH_ENTRY_UNKNOWN = "PATH_ENTRY_UNKNOWN"
REQUIRED_TOOL_MISSING = "REQUIRED_TOOL_MISSING"
TOOL_CANDIDATE_UNREADABLE = "TOOL_CANDIDATE_UNREADABLE"
TOOL_CANDIDATE_INVALID = "TOOL_CANDIDATE_INVALID"
TOOL_IDENTITY_DRIFT = "TOOL_IDENTITY_DRIFT"
UNKNOWN_FAIL_CLOSED = "UNKNOWN_FAIL_CLOSED"
SAFE_CANONICAL_DIRECTORY = "SAFE_CANONICAL_DIRECTORY"
SAFE_CANONICAL_SYMLINK_DIRECTORY = "SAFE_CANONICAL_SYMLINK_DIRECTORY"
INERT_NON_DIRECTORY = "INERT_NON_DIRECTORY"
INERT_MISSING_ENTRY = "INERT_MISSING_ENTRY"
INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE = "INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE"
UNSAFE_EXECUTABLE_SHADOW = "UNSAFE_EXECUTABLE_SHADOW"
UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY = (
    "UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY"
)
UNSAFE_REPARSE_ESCAPE = "UNSAFE_REPARSE_ESCAPE"
UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY = "UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY"
TOOL_AUTHORITY_TOOLS = frozenset(
    {"git", "bash", "node", "npm", "python", "powershell", "authority-set"}
)
PATH_ENTRY_CLASSIFICATIONS = frozenset(
    {
        SAFE_CANONICAL_DIRECTORY,
        SAFE_CANONICAL_SYMLINK_DIRECTORY,
        INERT_NON_DIRECTORY,
        INERT_MISSING_ENTRY,
        INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE,
        UNSAFE_EXECUTABLE_SHADOW,
        UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
        UNSAFE_REPARSE_ESCAPE,
        UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY,
        UNKNOWN_FAIL_CLOSED,
    }
)
TOOL_AUTHORITY_REASON_CODES = frozenset(
    {
        PATH_PREDECESSOR_UNINSPECTABLE,
        PATH_EXECUTABLE_SHADOW,
        PATH_REPARSE_ESCAPE,
        PATH_WORKSPACE_OR_TEMP_AUTHORITY,
        PATH_ENTRY_UNKNOWN,
        REQUIRED_TOOL_MISSING,
        TOOL_CANDIDATE_UNREADABLE,
        TOOL_CANDIDATE_INVALID,
        TOOL_IDENTITY_DRIFT,
        GIT_INSTALL_ROOT_UNRECOGNIZED,
        BASH_CANDIDATE_ABSENT,
        BASH_CANDIDATE_UNREADABLE,
        BASH_CANDIDATE_OUTSIDE_GIT_ROOT,
        BASH_CANDIDATE_REPARSE,
        BASH_CANDIDATE_NONREGULAR,
        BASH_CANDIDATE_HARDLINK,
        BASH_CANDIDATE_UNSAFE_ROOT,
        BASH_CANDIDATE_IDENTITY_DRIFT,
        BASH_CANDIDATE_VERSION_FAILURE,
        BASH_CANDIDATE_LEASE_FAILURE,
        UNKNOWN_FAIL_CLOSED,
    }
)
TOOL_AUTHORITY_CANDIDATE_CLASSES = frozenset(
    {"git-bin", "git-usr-bin", "parent-path", "tool-candidate"}
)
TOOL_AUTHORITY_ROOT_CATEGORIES = frozenset(
    {
        "approved",
        "system",
        "workspace",
        "runner-temp",
        "task-temp",
        "node-modules",
        "other",
        "unknown",
    }
)
TOOL_AUTHORITY_PHASES = frozenset(
    {
        "DISCOVERY",
        "CAPTURE",
        "COMMAND_PLAN",
        "EXECUTION_BINDING",
        "EXECUTION",
        "POST_EXECUTION",
        "RUNTIME_CLOSURE",
        "VERIFICATION_PREPARATION",
    }
)


class ToolAuthorityUnavailable(ValueError):
    """Stable, path-free required-tool failure used at every authority boundary."""

    def __init__(
        self,
        tool: str,
        phase: str,
        *,
        reason_code: str | None = None,
        path_index: int | None = None,
        candidate_class: str | None = None,
        root_category: str | None = None,
    ) -> None:
        normalized_tool = str(tool).strip().casefold()
        normalized_phase = str(phase).strip().upper()
        if normalized_tool not in TOOL_AUTHORITY_TOOLS:
            normalized_tool = "authority-set"
        if normalized_phase not in TOOL_AUTHORITY_PHASES:
            normalized_phase = "EXECUTION"
        normalized_reason = (
            str(reason_code).strip().upper() if reason_code is not None else None
        )
        if normalized_reason is not None and normalized_reason not in TOOL_AUTHORITY_REASON_CODES:
            normalized_reason = UNKNOWN_FAIL_CLOSED
        normalized_index = (
            path_index
            if type(path_index) is int and 0 <= path_index <= 1_000_000
            else None
        )
        normalized_candidate = (
            candidate_class
            if candidate_class in TOOL_AUTHORITY_CANDIDATE_CLASSES
            else None
        )
        normalized_root = (
            root_category
            if root_category in TOOL_AUTHORITY_ROOT_CATEGORIES
            else None
        )
        self.tool = normalized_tool
        self.phase = normalized_phase
        self.reason_code = normalized_reason
        self.path_index = normalized_index
        self.candidate_class = normalized_candidate
        self.root_category = normalized_root
        fields = [
            TOOL_AUTHORITY_UNAVAILABLE_CODE,
            f"tool={normalized_tool}",
            f"phase={normalized_phase}",
        ]
        if normalized_reason is not None:
            fields.append(f"reason={normalized_reason}")
        if normalized_index is not None:
            fields.append(f"path_index={normalized_index}")
        if normalized_candidate is not None:
            fields.append(f"candidate={normalized_candidate}")
        if normalized_root is not None:
            fields.append(f"root_category={normalized_root}")
        super().__init__(" ".join(fields))


@dataclass(frozen=True)
class ToolAuthorityIssue:
    """One closed, path-free resolver issue that can cross the CLI boundary."""

    tool: str
    reason_code: str
    path_index: int | None = None
    candidate_class: str | None = None
    root_category: str | None = None

    def __post_init__(self) -> None:
        if self.tool not in TOOL_AUTHORITY_TOOLS - {"authority-set"}:
            raise ValueError("tool-authority issue has an invalid tool")
        if self.reason_code not in TOOL_AUTHORITY_REASON_CODES:
            raise ValueError("tool-authority issue has an invalid reason")
        if self.path_index is not None and (
            type(self.path_index) is not int or self.path_index < 0
        ):
            raise ValueError("tool-authority issue has an invalid PATH ordinal")
        if (
            self.candidate_class is not None
            and self.candidate_class not in TOOL_AUTHORITY_CANDIDATE_CLASSES
        ):
            raise ValueError("tool-authority issue has an invalid candidate class")
        if (
            self.root_category is not None
            and self.root_category not in TOOL_AUTHORITY_ROOT_CATEGORIES
        ):
            raise ValueError("tool-authority issue has an invalid root category")

    def error_text(self) -> str:
        fields = [self.reason_code, f"tool={self.tool}"]
        if self.path_index is not None:
            fields.append(f"path_index={self.path_index}")
        if self.candidate_class is not None:
            fields.append(f"candidate={self.candidate_class}")
        if self.root_category is not None:
            fields.append(f"root_category={self.root_category}")
        return " ".join(fields)

    def exception(self, phase: str) -> ToolAuthorityUnavailable:
        return ToolAuthorityUnavailable(
            self.tool,
            phase,
            reason_code=self.reason_code,
            path_index=self.path_index,
            candidate_class=self.candidate_class,
            root_category=self.root_category,
        )


def _tool_authority_issue_from_error(value: str) -> ToolAuthorityIssue | None:
    match = re.fullmatch(
        r"(?P<reason>[A-Z][A-Z0-9_]+) tool=(?P<tool>[a-z]+)"
        r"(?: path_index=(?P<index>[0-9]+))?"
        r"(?: candidate=(?P<candidate>[a-z-]+))?"
        r"(?: root_category=(?P<root>[a-z-]+))?",
        str(value),
    )
    if match is None:
        return None
    try:
        return ToolAuthorityIssue(
            tool=match.group("tool"),
            reason_code=match.group("reason"),
            path_index=(int(match.group("index")) if match.group("index") else None),
            candidate_class=match.group("candidate"),
            root_category=match.group("root"),
        )
    except ValueError:
        return None


def require_tool(
    tools: Mapping[str, str],
    name: str,
    *,
    phase: str,
    resolution_errors: Sequence[str] = (),
) -> str:
    """Return one canonical absolute tool or fail with a stable typed result."""

    value = tools.get(name)
    if resolution_errors:
        issue = next(
            (
                parsed
                for error in resolution_errors
                if (parsed := _tool_authority_issue_from_error(error)) is not None
                and parsed.tool == name
            ),
            None,
        )
        if issue is not None:
            raise issue.exception(phase)
        raise ToolAuthorityUnavailable(
            name,
            phase,
            reason_code=UNKNOWN_FAIL_CLOSED,
        )
    if not isinstance(value, str) or not value:
        raise ToolAuthorityUnavailable(name, phase, reason_code=REQUIRED_TOOL_MISSING)
    candidate = Path(value)
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as exc:
        raise ToolAuthorityUnavailable(
            name, phase, reason_code=TOOL_CANDIDATE_UNREADABLE
        ) from exc
    okay, _reason = _secure_regular_file(canonical)
    if not candidate.is_absolute() or not okay:
        raise ToolAuthorityUnavailable(name, phase, reason_code=TOOL_CANDIDATE_INVALID)
    return str(canonical)


def require_tool_set(
    tools: Mapping[str, str],
    required: Iterable[str],
    *,
    phase: str,
    resolution_errors: Sequence[str] = (),
) -> dict[str, str]:
    """Narrow a complete required-tool map before planning or binding."""

    names = sorted(set(required))
    missing = [name for name in names if not isinstance(tools.get(name), str) or not tools.get(name)]
    if resolution_errors or missing:
        parsed_issues = [
            parsed
            for error in resolution_errors
            if (parsed := _tool_authority_issue_from_error(error)) is not None
            and parsed.tool in names
        ]
        issue = next(
            (
                parsed
                for parsed in parsed_issues
                if parsed.reason_code != REQUIRED_TOOL_MISSING
            ),
            parsed_issues[0] if parsed_issues else None,
        )
        if issue is not None:
            raise issue.exception(phase)
        if missing:
            raise ToolAuthorityUnavailable(
                missing[0], phase, reason_code=REQUIRED_TOOL_MISSING
            )
        raise ToolAuthorityUnavailable(
            "authority-set", phase, reason_code=UNKNOWN_FAIL_CLOSED
        )
    return {name: require_tool(tools, name, phase=phase) for name in names}


@dataclass(frozen=True)
class ToolAuthorityPolicy:
    """Role-specific trusted roots plus a test-only hosted-runner filesystem model."""

    platform_name: str
    path_separator: str
    role_roots: Mapping[str, tuple[tuple[str, Path], ...]]
    minimal_system_directories: tuple[Path, ...]
    running_python: Path
    synthetic: bool = False

    def roots_for(self, role: str) -> tuple[tuple[str, Path], ...]:
        return self.role_roots.get(role, ())


@dataclass(frozen=True)
class _ToolRootClassificationResult:
    """Closed result for one executable's trusted-root inspection."""

    root_label: str | None
    inspection_failed: bool


def _resolved_non_reparse_directory(path: Path) -> Path | None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
        return None
    return resolved


def _deduplicated_roots(values: Iterable[tuple[str, Path]]) -> tuple[tuple[str, Path], ...]:
    result: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for label, value in values:
        resolved = _resolved_non_reparse_directory(value)
        if resolved is None:
            continue
        key = str(resolved).casefold() if os.name == "nt" else str(resolved)
        if key in seen:
            continue
        seen.add(key)
        result.append((label, resolved))
    return tuple(result)


def default_tool_authority_policy(
    source_environment: Mapping[str, str],
    *,
    repo_root: Path = REPO_ROOT,
    platform_name: str | None = None,
) -> ToolAuthorityPolicy:
    """Construct production authority without accepting caller-selected role roots."""

    running_python = Path(sys.executable).resolve(strict=True)
    windows = (
        platform_name.casefold().startswith("win")
        if platform_name is not None
        else os.name == "nt"
    )
    runtime_roots: list[tuple[str, Path]] = []
    if len(running_python.parents) >= 2:
        runtime_roots.append(("approved-local-runtime", running_python.parents[1]))
    toolcache_roots: list[tuple[str, Path]] = []
    runner_tool_cache = _environment_authority_value(
        source_environment, "RUNNER_TOOL_CACHE", windows=windows
    )
    if runner_tool_cache:
        toolcache_roots.append(
            ("github-hosted-toolcache", Path(runner_tool_cache))
        )

    system_directories: list[Path] = []
    git_roots: list[tuple[str, Path]] = []
    bash_roots: list[tuple[str, Path]] = []
    powershell_roots: list[tuple[str, Path]] = []
    if windows:
        for key in ("SystemRoot", "WINDIR"):
            if value := _environment_authority_value(
                source_environment, key, windows=True
            ):
                root = Path(value)
                system_directories.extend((root / "System32", root))
                powershell_roots.append(
                    ("windows-system-powershell", root / "System32" / "WindowsPowerShell")
                )
        for key in ("ProgramFiles", "ProgramFiles(x86)"):
            if value := _environment_authority_value(
                source_environment, key, windows=True
            ):
                root = Path(value)
                git_roots.append(("program-files-git", root / "Git"))
                powershell_roots.append(("program-files-powershell", root / "PowerShell"))
        approved_local_git = Path("D:/Git")
        if approved_local_git.is_dir():
            git_roots.append(("approved-local-git", approved_local_git))
        bash_roots.extend(
            (label.replace("git", "git-bash"), root)
            for label, root in git_roots
        )
    else:
        system_directories.extend((Path("/usr/bin"), Path("/bin")))
        git_roots.extend(
            (("posix-system-git", Path("/usr/bin")), ("posix-system-git", Path("/bin")))
        )
        bash_roots.extend(
            (("posix-system-bash", Path("/usr/bin")), ("posix-system-bash", Path("/bin")))
        )
        powershell_roots.extend(
            (
                ("posix-system-pwsh", Path("/usr/bin")),
                ("microsoft-pwsh", Path("/opt/microsoft/powershell")),
            )
        )

    role_roots = {
        "python": _deduplicated_roots(toolcache_roots),
        "node": _deduplicated_roots([*toolcache_roots, *runtime_roots]),
        "npm": _deduplicated_roots([*toolcache_roots, *runtime_roots]),
        "git": _deduplicated_roots(git_roots),
        "bash": _deduplicated_roots(bash_roots),
        "powershell": _deduplicated_roots(powershell_roots),
        "pwsh": _deduplicated_roots(powershell_roots),
    }
    minimal = tuple(
        value
        for _label, value in _deduplicated_roots(
            ("minimal-system", path) for path in system_directories
        )
    )
    return ToolAuthorityPolicy(
        platform_name="Windows" if windows else "Linux",
        path_separator=os.pathsep,
        role_roots=MappingProxyType(role_roots),
        minimal_system_directories=minimal,
        running_python=running_python,
    )


def synthetic_tool_authority_policy(
    platform_name: str,
    *,
    running_python: Path,
    role_roots: Mapping[str, Sequence[tuple[str, Path]]],
    minimal_system_directories: Sequence[Path],
    path_separator: str = os.pathsep,
) -> ToolAuthorityPolicy:
    """Build a non-executable test model backed by inspected task-owned files."""

    normalized_platform = "Windows" if platform_name.casefold().startswith("win") else "Linux"
    normalized_roots = {
        role: _deduplicated_roots(values)
        for role, values in role_roots.items()
    }
    minimal = tuple(
        value
        for _label, value in _deduplicated_roots(
            ("synthetic-minimal-system", path) for path in minimal_system_directories
        )
    )
    running = running_python.resolve(strict=True)
    okay, reason = _secure_regular_file(running)
    if not okay:
        raise ValueError(f"synthetic Python identity is invalid: {reason}")
    return ToolAuthorityPolicy(
        platform_name=normalized_platform,
        path_separator=path_separator,
        role_roots=MappingProxyType(normalized_roots),
        minimal_system_directories=minimal,
        running_python=running,
        synthetic=True,
    )


def _unsafe_tool_path_reason(
    path: Path,
    repo_root: Path,
    source_environment: Mapping[str, str] | None = None,
    *,
    windows: bool = os.name == "nt",
) -> str | None:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return "path does not resolve"
    try:
        metadata = path.lstat()
    except OSError:
        return "path cannot be inspected"
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        return "path is a symbolic link or reparse point"
    repo_resolved = repo_root.resolve(strict=True)
    if _path_is_within(resolved, repo_resolved):
        return "path is controlled by the repository workspace"
    if any(part.casefold() == "node_modules" for part in resolved.parts):
        return "path is beneath node_modules"
    try:
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except OSError:
        temp_root = Path(tempfile.gettempdir()).resolve()
    if _path_is_within(resolved, temp_root):
        return "path is beneath the task temporary directory"
    source = {} if source_environment is None else source_environment
    for variable, description in (
        ("GITHUB_WORKSPACE", "GitHub workspace"),
        ("RUNNER_TEMP", "runner temporary directory"),
    ):
        value = _environment_authority_value(source, variable, windows=windows)
        if not value:
            continue
        try:
            forbidden_root = Path(value).resolve(strict=True)
        except OSError:
            continue
        if _path_is_within(resolved, forbidden_root):
            return f"path is beneath the {description}"
    return None


def _same_file_identity(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _tool_root_classification_result(
    path: Path,
    role: str,
    policy: ToolAuthorityPolicy,
) -> _ToolRootClassificationResult:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return _ToolRootClassificationResult(None, True)
    if role == "python" and _same_file_identity(resolved, policy.running_python):
        return _ToolRootClassificationResult("running-python-file-identity", False)
    for label, root in policy.roots_for(role):
        if not _authority_path_is_within(
            resolved,
            root,
            windows=policy.platform_name == "Windows",
        ):
            continue
        try:
            if not _non_reparse_directory_chain(resolved.parent, root):
                continue
        except OSError:
            return _ToolRootClassificationResult(None, True)
        return _ToolRootClassificationResult(label, False)
    return _ToolRootClassificationResult(None, False)


def _tool_root_classification(
    path: Path,
    role: str,
    policy: ToolAuthorityPolicy,
) -> str | None:
    return _tool_root_classification_result(path, role, policy).root_label


def _tool_location_is_allowlisted(
    path: Path,
    source_environment: Mapping[str, str],
    *,
    role: str | None = None,
    policy: ToolAuthorityPolicy | None = None,
    repo_root: Path = REPO_ROOT,
) -> bool:
    selected = policy or default_tool_authority_policy(source_environment, repo_root=repo_root)
    if role is not None:
        return _tool_root_classification(path, role, selected) is not None
    return any(
        _tool_root_classification(path, candidate_role, selected) is not None
        for candidate_role in selected.role_roots
    ) or _same_file_identity(path, selected.running_python)


def _windows_system_launcher_path(path: Path, source_environment: Mapping[str, str]) -> bool:
    """Return whether *path* is beneath a Windows WSL-launcher directory."""

    normalized = str(path.resolve(strict=True)).replace("\\", "/").casefold()
    roots = {
        str(Path(value).resolve(strict=True)).replace("\\", "/").casefold()
        for key in ("SystemRoot", "WINDIR")
        if (
            value := _environment_authority_value(
                source_environment, key, windows=True
            )
        )
    }
    if any(
        normalized.startswith(root.rstrip("/") + suffix)
        for root in roots
        for suffix in ("/system32/", "/sysnative/")
    ):
        return True
    return bool(re.search(r"(?i)/(?:windows/)?(?:system32|sysnative)/", normalized + "/"))


def _windows_component_suffix_matches(path: Path, suffix: Sequence[str]) -> bool:
    parts = path.parts
    return len(parts) >= len(suffix) and all(
        windows_authority_component_equal(component, expected)
        for component, expected in zip(parts[-len(suffix) :], suffix)
    )


def _trusted_git_installation_root(
    git: Path,
    *,
    require_windows_drive: bool | None = None,
) -> tuple[Path | None, str | None]:
    """Derive one Git-for-Windows root from an exact executable suffix."""

    strict_windows_namespace = os.name == "nt" if require_windows_drive is None else require_windows_drive
    if not git.is_absolute():
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: trusted Git path is relative"
    if (
        strict_windows_namespace
        and classify_windows_absolute_reference(str(git)).kind != "drive-absolute"
    ):
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: trusted Git namespace is forbidden"
    okay, _reason = _secure_regular_file(git)
    if not okay:
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: trusted Git is not a regular file"
    try:
        resolved = git.resolve(strict=True)
    except OSError:
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: trusted Git path does not resolve"
    if (
        not resolved.is_absolute()
        or (
            strict_windows_namespace
            and classify_windows_absolute_reference(str(resolved)).kind != "drive-absolute"
        )
    ):
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: canonical Git namespace is forbidden"
    suffix = next(
        (
            candidate_suffix
            for candidate_suffix in WINDOWS_GIT_EXECUTABLE_SUFFIXES
            if _windows_component_suffix_matches(resolved, candidate_suffix)
        ),
        None,
    )
    if suffix is None:
        return None, (
            f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: trusted Git executable suffix is unsupported"
        )
    if (
        suffix == ("bin", "git.exe")
        and len(resolved.parts) >= 3
        and any(
            windows_authority_component_equal(resolved.parts[-3], internal_component)
            for internal_component in ("mingw32", "mingw64", "usr")
        )
    ):
        return None, (
            f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: internal Git executable suffix is unsupported"
        )
    original_suffix = next(
        (
            candidate_suffix
            for candidate_suffix in WINDOWS_GIT_EXECUTABLE_SUFFIXES
            if _windows_component_suffix_matches(git, candidate_suffix)
        ),
        None,
    )
    if original_suffix != suffix:
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: Git path crossed a reparse boundary"
    root = resolved
    original_root = git
    for _component in suffix:
        root = root.parent
        original_root = original_root.parent
    try:
        metadata = root.lstat()
        original_chain_ok = _non_reparse_directory_chain(git.parent, original_root)
        canonical_chain_ok = _non_reparse_directory_chain(resolved.parent, root)
    except OSError:
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: Git installation cannot be inspected"
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or not original_chain_ok
        or not canonical_chain_ok
    ):
        return None, f"{GIT_INSTALL_ROOT_UNRECOGNIZED}: Git installation contains a reparse boundary"
    return root, None


def _non_reparse_directory_chain(path: Path, stop: Path) -> bool:
    current = path
    stop_resolved = stop.resolve(strict=True)
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
            return False
        if current.resolve(strict=True) == stop_resolved:
            return True
        if current.parent == current:
            return False
        current = current.parent


@dataclass(frozen=True)
class BashCandidateResult:
    """Internal fixed-candidate audit without an absolute-path disclosure."""

    candidate_location_class: str
    exists: bool
    regular_file: bool | None
    reparse_safe: bool | None
    same_installation_root: bool | None
    link_count: int | None
    file_identity: tuple[int, int, int, int, int] | None
    sha256: str | None
    version_probe: str
    lease_precheck: str
    selection_priority: int
    path_shadow_disposition: str
    failure_reason: str | None
    disposition: str

    def diagnostic(self) -> dict[str, Any]:
        return {
            "kind": "bash-candidate",
            "candidateLocationClass": self.candidate_location_class,
            "exists": self.exists,
            "regularFile": self.regular_file,
            "reparseSafe": self.reparse_safe,
            "sameInstallationRoot": self.same_installation_root,
            "linkCount": self.link_count,
            "fileIdentity": (
                list(self.file_identity) if self.file_identity is not None else None
            ),
            "sha256": self.sha256,
            "versionProbe": self.version_probe,
            "leasePrecheck": self.lease_precheck,
            "selectionPriority": self.selection_priority,
            "pathShadowDisposition": self.path_shadow_disposition,
            "failureReason": self.failure_reason,
            "reasonCode": self.failure_reason,
            "disposition": self.disposition,
        }


def _bash_candidate_location_class(suffix: Sequence[str]) -> str:
    return "git-bin" if tuple(suffix) == ("bin", "bash.exe") else "git-usr-bin"


def resolve_trusted_git_bash(
    git: str,
    *,
    source_environment: Mapping[str, str] | None = None,
    repo_root: Path = REPO_ROOT,
    policy: ToolAuthorityPolicy | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> tuple[str | None, list[str]]:
    """Derive Git Bash from the already trusted Git for Windows installation."""

    source = dict(os.environ if source_environment is None else source_environment)
    try:
        selected_policy = policy or default_tool_authority_policy(
            source, repo_root=repo_root
        )
        for authority_key in (
            "SystemRoot",
            "WINDIR",
            "GITHUB_WORKSPACE",
            "RUNNER_TEMP",
        ):
            _environment_authority_value(
                source,
                authority_key,
                windows=selected_policy.platform_name == "Windows",
            )
    except EnvironmentAuthorityConflict as exc:
        return None, [str(exc)]
    git_path = Path(git)
    okay, _reason = _secure_regular_file(git_path)
    if not okay:
        return None, [
            ToolAuthorityIssue(
                "bash",
                GIT_INSTALL_ROOT_UNRECOGNIZED,
                candidate_class="tool-candidate",
            ).error_text()
        ]
    git_root, root_error = _trusted_git_installation_root(
        git_path,
        require_windows_drive=(
            selected_policy.platform_name == "Windows" and not selected_policy.synthetic
        ),
    )
    if git_root is None:
        return None, [
            ToolAuthorityIssue(
                "bash",
                GIT_INSTALL_ROOT_UNRECOGNIZED,
                candidate_class="tool-candidate",
            ).error_text()
        ]
    try:
        git_root_resolved = git_root.resolve(strict=True)
        approved_git_roots = tuple(
            approved_root.resolve(strict=True)
            for _label, approved_root in selected_policy.roots_for("git")
        )
    except OSError:
        return None, [
            ToolAuthorityIssue(
                "bash",
                GIT_INSTALL_ROOT_UNRECOGNIZED,
                candidate_class="tool-candidate",
            ).error_text()
        ]
    if policy is not None and not any(
        _authority_paths_equal(
            git_root_resolved,
            approved_root,
            windows=selected_policy.platform_name == "Windows",
        )
        for approved_root in approved_git_roots
    ):
        return None, [
            ToolAuthorityIssue(
                "bash",
                GIT_INSTALL_ROOT_UNRECOGNIZED,
                candidate_class="tool-candidate",
            ).error_text()
        ]

    def reject(
        *,
        candidate_class: str,
        priority: int,
        reason_code: str,
        exists: bool,
        metadata: os.stat_result | None = None,
        regular_file: bool | None = None,
        reparse_safe: bool | None = None,
        same_root: bool | None = None,
        digest: str | None = None,
        disposition: str = "rejected",
    ) -> str:
        result = BashCandidateResult(
            candidate_location_class=candidate_class,
            exists=exists,
            regular_file=regular_file,
            reparse_safe=reparse_safe,
            same_installation_root=same_root,
            link_count=(
                int(getattr(metadata, "st_nlink", 1)) if metadata is not None else None
            ),
            file_identity=(_stat_identity(metadata) if metadata is not None else None),
            sha256=digest,
            version_probe="not-run",
            lease_precheck="not-run",
            selection_priority=priority,
            path_shadow_disposition="not-evaluated",
            failure_reason=reason_code,
            disposition=disposition,
        )
        if diagnostics is not None:
            diagnostics.append(result.diagnostic())
        return ToolAuthorityIssue(
            "bash",
            reason_code,
            candidate_class=candidate_class,
        ).error_text()

    absent_results: list[str] = []
    for priority, suffix in enumerate(WINDOWS_GIT_BASH_CANDIDATE_SUFFIXES):
        candidate = git_root.joinpath(*suffix)
        candidate_class = _bash_candidate_location_class(suffix)

        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            absent_results.append(
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_ABSENT,
                    exists=False,
                    disposition="absent-continue",
                )
            )
            continue
        except OSError:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                )
            ]
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_REPARSE,
                    exists=True,
                    metadata=metadata,
                    regular_file=stat.S_ISREG(metadata.st_mode),
                    reparse_safe=False,
                )
            ]
        if not stat.S_ISREG(metadata.st_mode):
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_NONREGULAR,
                    exists=True,
                    metadata=metadata,
                    regular_file=False,
                    reparse_safe=True,
                )
            ]
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_HARDLINK,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                )
            ]
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                )
            ]
        if not _authority_path_is_within(
            resolved,
            git_root_resolved,
            windows=selected_policy.platform_name == "Windows",
        ):
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_OUTSIDE_GIT_ROOT,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=False,
                )
            ]
        try:
            chain_ok = _non_reparse_directory_chain(candidate.parent, git_root)
        except OSError:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=None,
                    same_root=True,
                )
            ]
        if not chain_ok:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_REPARSE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=False,
                    same_root=True,
                )
            ]
        unsafe_reason = _unsafe_tool_path_reason(
            candidate,
            repo_root,
            source,
            windows=selected_policy.platform_name == "Windows",
        )
        root_result = _tool_root_classification_result(
            candidate, "bash", selected_policy
        )
        if root_result.inspection_failed:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=True,
                )
            ]
        classification = root_result.root_label
        if unsafe_reason and not (selected_policy.synthetic and classification):
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNSAFE_ROOT,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=True,
                )
            ]
        try:
            windows_system_launcher = _windows_system_launcher_path(candidate, source)
        except OSError:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=True,
                )
            ]
        if windows_system_launcher:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_OUTSIDE_GIT_ROOT,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=False,
                )
            ]
        if classification is None and not _tool_location_is_allowlisted(
            candidate,
            source,
            role="bash",
            policy=selected_policy,
            repo_root=repo_root,
        ):
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_OUTSIDE_GIT_ROOT,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=True,
                )
            ]
        try:
            digest = _sha256_file(resolved)
        except OSError:
            return None, [
                reject(
                    candidate_class=candidate_class,
                    priority=priority,
                    reason_code=BASH_CANDIDATE_UNREADABLE,
                    exists=True,
                    metadata=metadata,
                    regular_file=True,
                    reparse_safe=True,
                    same_root=True,
                )
            ]
        if diagnostics is not None:
            diagnostics.append(
                BashCandidateResult(
                    candidate_location_class=candidate_class,
                    exists=True,
                    regular_file=True,
                    reparse_safe=True,
                    same_installation_root=True,
                    link_count=int(getattr(metadata, "st_nlink", 1)),
                    file_identity=_stat_identity(metadata),
                    sha256=digest,
                    version_probe="deferred-to-capture",
                    lease_precheck="eligible",
                    selection_priority=priority,
                    path_shadow_disposition="pending",
                    failure_reason=None,
                    disposition="accepted",
                ).diagnostic()
            )
        return str(resolved), []
    return None, [
        absent_results[-1]
        if absent_results
        else ToolAuthorityIssue(
            "bash", BASH_CANDIDATE_ABSENT, candidate_class="git-bin"
        ).error_text()
    ]


def _trusted_git_bash_candidate_position(
    bash: Path,
    git_root: Path,
    *,
    windows: bool,
) -> str | None:
    canonical = bash.resolve(strict=True)
    canonical_root = git_root.resolve(strict=True)
    for suffix in WINDOWS_GIT_BASH_CANDIDATE_SUFFIXES:
        expected = canonical_root.joinpath(*suffix)
        try:
            expected_canonical = expected.resolve(strict=True)
        except OSError:
            continue
        equal = (
            windows_authority_path_prefix(str(canonical), str(expected_canonical))
            if windows and os.name == "nt"
            else canonical == expected_canonical
        )
        if equal:
            return "\\".join(suffix)
    return None


@dataclass(frozen=True)
class _TrustedPathEntry:
    index: int
    original: Path
    resolved: Path | None
    classification: str
    root_category: str
    aliases: Mapping[str, Path]
    uninspectable_roles: frozenset[str]
    original_identity: tuple[int, int, int, int, int] | None
    target_identity: tuple[int, int, int, int, int] | None

    def alias_for(self, role: str) -> Path | None:
        return self.aliases.get(role)


def _tool_alias_names(role: str, policy: ToolAuthorityPolicy) -> tuple[str, ...]:
    stems: list[str]
    if role == "python":
        running_name = policy.running_python.name.casefold()
        if running_name.endswith(".exe"):
            running_name = running_name[:-4]
        stems = ["python", "python3", running_name]
        stems.extend(f"python3.{minor}" for minor in range(0, 21))
    elif role in {"powershell", "pwsh"}:
        stems = ["powershell", "pwsh"]
    else:
        stems = [role]
    stems = list(dict.fromkeys(stem for stem in stems if stem))
    if policy.platform_name == "Windows":
        suffixes = (".exe", ".cmd", ".bat", ".ps1", "")
        return tuple(dict.fromkeys(stem + suffix for stem in stems for suffix in suffixes))
    return tuple(stems)


def _first_tool_alias(
    directory: Path,
    role: str,
    policy: ToolAuthorityPolicy,
) -> tuple[Path | None, str | None]:
    for alias in _tool_alias_names(role, policy):
        candidate = directory / alias
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None, PATH_PREDECESSOR_UNINSPECTABLE
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not (
            stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            return None, PATH_PREDECESSOR_UNINSPECTABLE
        if (
            policy.platform_name != "Windows"
            and not policy.synthetic
            and stat.S_ISREG(metadata.st_mode)
            and not (stat.S_IMODE(metadata.st_mode) & 0o111)
        ):
            continue
        return candidate, None
    return None, None


def _path_root_category(
    path: Path,
    *,
    repo_root: Path,
    source: Mapping[str, str],
    policy: ToolAuthorityPolicy,
) -> str:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return "unknown"
    try:
        repo = repo_root.resolve(strict=True)
    except OSError:
        repo = repo_root.resolve()
    if _path_is_within(resolved, repo):
        return "workspace"
    for variable, category in (
        ("GITHUB_WORKSPACE", "workspace"),
        ("RUNNER_TEMP", "runner-temp"),
    ):
        value = _environment_authority_value(
            source,
            variable,
            windows=policy.platform_name == "Windows",
        )
        if not value:
            continue
        try:
            root = Path(value).resolve(strict=True)
        except OSError:
            continue
        if _path_is_within(resolved, root):
            return category
    if any(part.casefold() == "node_modules" for part in resolved.parts):
        return "node-modules"
    if any(
        _path_is_within(resolved, root)
        for role_roots in policy.role_roots.values()
        for _label, root in role_roots
    ):
        return "approved"
    if any(
        _path_is_within(resolved, root)
        for root in policy.minimal_system_directories
    ):
        return "system"
    if (
        policy.platform_name == "Windows"
        and resolved.name.casefold() == "windowsapps"
    ):
        return "other"
    try:
        task_temp = Path(tempfile.gettempdir()).resolve(strict=True)
    except OSError:
        task_temp = Path(tempfile.gettempdir()).resolve()
    if _path_is_within(resolved, task_temp):
        return "task-temp"
    return "other"


def _path_entry_aliases(
    directory: Path,
    required: Iterable[str],
    policy: ToolAuthorityPolicy,
) -> tuple[Mapping[str, Path], frozenset[str]]:
    aliases: dict[str, Path] = {}
    uninspectable: set[str] = set()
    for role in sorted(set(required)):
        alias, inspection_error = _first_tool_alias(directory, role, policy)
        if inspection_error:
            uninspectable.add(role)
        elif alias is not None:
            aliases[role] = alias
    return MappingProxyType(aliases), frozenset(uninspectable)


def _classify_path_entry(
    index: int,
    entry: Path,
    *,
    required: Iterable[str],
    repo_root: Path,
    source: Mapping[str, str],
    policy: ToolAuthorityPolicy,
) -> _TrustedPathEntry:
    roles = frozenset(required)
    try:
        original_metadata = entry.lstat()
    except FileNotFoundError:
        return _TrustedPathEntry(
            index,
            entry,
            None,
            INERT_MISSING_ENTRY,
            "unknown",
            MappingProxyType({}),
            frozenset(),
            None,
            None,
        )
    except OSError:
        return _TrustedPathEntry(
            index,
            entry,
            None,
            UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
            "unknown",
            MappingProxyType({}),
            roles,
            None,
            None,
        )

    original_identity = _stat_identity(original_metadata)
    is_link = stat.S_ISLNK(original_metadata.st_mode) or _is_reparse_point(
        original_metadata
    )
    if not is_link and not stat.S_ISDIR(original_metadata.st_mode):
        return _TrustedPathEntry(
            index,
            entry,
            None,
            INERT_NON_DIRECTORY,
            "other",
            MappingProxyType({}),
            frozenset(),
            original_identity,
            None,
        )
    try:
        resolved = entry.resolve(strict=True)
    except FileNotFoundError:
        if is_link:
            return _TrustedPathEntry(
                index,
                entry,
                None,
                INERT_MISSING_ENTRY,
                "unknown",
                MappingProxyType({}),
                frozenset(),
                original_identity,
                None,
            )
        return _TrustedPathEntry(
            index,
            entry,
            None,
            UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
            "unknown",
            MappingProxyType({}),
            roles,
            original_identity,
            None,
        )
    except OSError:
        return _TrustedPathEntry(
            index,
            entry,
            None,
            UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
            "unknown",
            MappingProxyType({}),
            roles,
            original_identity,
            None,
        )
    try:
        target_metadata = resolved.lstat()
    except OSError:
        return _TrustedPathEntry(
            index,
            entry,
            resolved,
            UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
            "unknown",
            MappingProxyType({}),
            roles,
            original_identity,
            None,
        )
    target_identity = _stat_identity(target_metadata)
    if (
        stat.S_ISLNK(target_metadata.st_mode)
        or _is_reparse_point(target_metadata)
        or not stat.S_ISDIR(target_metadata.st_mode)
    ):
        return _TrustedPathEntry(
            index,
            entry,
            resolved,
            INERT_NON_DIRECTORY if not stat.S_ISDIR(target_metadata.st_mode) else UNSAFE_REPARSE_ESCAPE,
            "unknown",
            MappingProxyType({}),
            frozenset() if not stat.S_ISDIR(target_metadata.st_mode) else roles,
            original_identity,
            target_identity,
        )
    aliases, uninspectable = _path_entry_aliases(resolved, roles, policy)
    root_results = {
        role: _tool_root_classification_result(alias, role, policy)
        for role, alias in aliases.items()
    }
    uninspectable = frozenset(
        {
            *uninspectable,
            *(
                role
                for role, result in root_results.items()
                if result.inspection_failed
            ),
        }
    )
    root_category = _path_root_category(
        resolved,
        repo_root=repo_root,
        source=source,
        policy=policy,
    )
    if uninspectable:
        classification = UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY
    elif not aliases:
        classification = (
            SAFE_CANONICAL_SYMLINK_DIRECTORY
            if is_link
            and root_category
            not in {"workspace", "runner-temp", "task-temp", "node-modules"}
            else INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE
        )
    elif root_category in {"workspace", "runner-temp", "task-temp", "node-modules"}:
        classification = (
            UNSAFE_REPARSE_ESCAPE if is_link else UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY
        )
    elif any(result.root_label is None for result in root_results.values()):
        classification = UNSAFE_REPARSE_ESCAPE if is_link else UNSAFE_EXECUTABLE_SHADOW
    else:
        classification = (
            SAFE_CANONICAL_SYMLINK_DIRECTORY if is_link else SAFE_CANONICAL_DIRECTORY
        )
    return _TrustedPathEntry(
        index,
        entry,
        resolved,
        classification,
        root_category,
        aliases,
        uninspectable,
        original_identity,
        target_identity,
    )


def _path_entries(
    source: Mapping[str, str],
    *,
    required: Iterable[str],
    repo_root: Path,
    policy: ToolAuthorityPolicy,
    diagnostics: list[dict[str, Any]] | None = None,
) -> tuple[list[_TrustedPathEntry], list[str]]:
    raw_path = _environment_authority_value(
        source,
        "PATH",
        windows=policy.platform_name == "Windows",
        default="",
    )
    raw_entries = raw_path.split(policy.path_separator) if raw_path else []
    entries: list[_TrustedPathEntry] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        if not raw_entry or not Path(raw_entry).is_absolute():
            # Empty/current/relative entries are removed and never inherited.
            if diagnostics is not None:
                diagnostics.append(
                    {
                        "kind": "path-entry",
                        "pathIndex": index,
                        "classification": INERT_ENTRY_WITH_NO_REQUIRED_EXECUTABLE,
                        "rootCategory": "unknown",
                        "candidateRoles": [],
                    }
                )
            continue
        entry = Path(raw_entry)
        classified = _classify_path_entry(
            index,
            entry,
            required=required,
            repo_root=repo_root,
            source=source,
            policy=policy,
        )
        key_path = classified.resolved or classified.original
        key = str(key_path).casefold() if policy.platform_name == "Windows" else str(key_path)
        if key in seen:
            continue
        seen.add(key)
        entries.append(classified)
        if diagnostics is not None:
            diagnostics.append(
                {
                    "kind": "path-entry",
                    "pathIndex": index,
                    "classification": classified.classification,
                    "rootCategory": classified.root_category,
                    "candidateRoles": sorted(classified.aliases),
                    "uninspectableRoles": sorted(classified.uninspectable_roles),
                }
            )
    return entries, sorted(set(errors))


def _npm_entry_from_launcher(candidate: Path) -> Path:
    if candidate.suffix.casefold() not in {".cmd", ".ps1", ".bat"}:
        return candidate
    npm_entry = candidate.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
    return npm_entry if npm_entry.is_file() else candidate


def _fallback_tool_candidate(role: str, policy: ToolAuthorityPolicy) -> Path | None:
    windows = policy.platform_name == "Windows"
    candidates: list[Path] = []
    for _label, root in policy.roots_for(role):
        if role == "node":
            executable = "node.exe" if windows else "node"
            candidates.extend(
                (
                    root / executable,
                    root / "bin" / executable,
                    root / "node" / executable,
                    root / "node" / "bin" / executable,
                )
            )
        elif role == "npm":
            candidates.extend(
                (
                    root / "node_modules" / "npm" / "bin" / "npm-cli.js",
                    root / "bin" / "node_modules" / "npm" / "bin" / "npm-cli.js",
                    root / "node" / "node_modules" / "npm" / "bin" / "npm-cli.js",
                    root
                    / "node"
                    / "bin"
                    / "node_modules"
                    / "npm"
                    / "bin"
                    / "npm-cli.js",
                )
            )
        elif role == "git":
            candidates.extend(
                (
                    root / ("git.exe" if windows else "git"),
                    root / "cmd" / "git.exe",
                    root / "bin" / ("git.exe" if windows else "git"),
                )
            )
        elif role in {"powershell", "pwsh"}:
            candidates.extend(
                (
                    root / "powershell.exe",
                    root / "pwsh.exe",
                    root / "v1.0" / "powershell.exe",
                    root / "7" / "pwsh.exe",
                    root / "pwsh",
                    root / "7" / "pwsh",
                )
            )
    return next((path for path in candidates if path.is_file()), None)


def _trusted_fixed_bash_alias(
    alias: Path,
    candidate: Path,
    policy: ToolAuthorityPolicy,
) -> bool:
    if policy.platform_name != "Windows":
        return False
    for _label, root in policy.roots_for("bash"):
        try:
            if (
                _trusted_git_bash_candidate_position(alias, root, windows=True) is not None
                and _trusted_git_bash_candidate_position(candidate, root, windows=True) is not None
            ):
                return True
        except OSError:
            continue
    return False


def _preceding_shadow_issue(
    entries: Sequence[_TrustedPathEntry],
    candidate: Path,
    role: str,
    policy: ToolAuthorityPolicy,
    *,
    scan_all_if_absent: bool = True,
) -> ToolAuthorityIssue | None:
    try:
        canonical = candidate.resolve(strict=True)
    except OSError:
        return ToolAuthorityIssue(
            role,
            TOOL_CANDIDATE_UNREADABLE,
            candidate_class="tool-candidate",
        )
    if role == "npm":
        candidate_position = None
        launcher_alias = None
        launcher_entry = None
        for offset, entry in enumerate(entries):
            alias = entry.alias_for(role)
            if alias is None or not _same_file_identity(
                _npm_entry_from_launcher(alias), canonical
            ):
                continue
            candidate_position = offset
            launcher_alias = alias
            launcher_entry = entry
            break
        if (
            candidate_position is None
            or launcher_alias is None
            or launcher_entry is None
        ):
            return ToolAuthorityIssue(
                role,
                TOOL_CANDIDATE_INVALID,
                candidate_class="tool-candidate",
            )
        launcher_root = _tool_root_classification_result(
            launcher_alias, role, policy
        )
        candidate_root = _tool_root_classification_result(canonical, role, policy)
        if launcher_root.inspection_failed or candidate_root.inspection_failed:
            return ToolAuthorityIssue(
                role,
                PATH_PREDECESSOR_UNINSPECTABLE,
                path_index=launcher_entry.index,
                candidate_class="parent-path",
                root_category=launcher_entry.root_category,
            )
        if (
            launcher_root.root_label is None
            or candidate_root.root_label is None
            or launcher_root.root_label != candidate_root.root_label
        ):
            reason_code = {
                UNSAFE_REPARSE_ESCAPE: PATH_REPARSE_ESCAPE,
                UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY: PATH_WORKSPACE_OR_TEMP_AUTHORITY,
                UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY: PATH_PREDECESSOR_UNINSPECTABLE,
                UNKNOWN_FAIL_CLOSED: PATH_ENTRY_UNKNOWN,
            }.get(launcher_entry.classification, PATH_EXECUTABLE_SHADOW)
            return ToolAuthorityIssue(
                role,
                reason_code,
                path_index=launcher_entry.index,
                candidate_class="parent-path",
                root_category=launcher_entry.root_category,
            )
    else:
        candidate_parent = canonical.parent
        candidate_position = next(
            (
                offset
                for offset, entry in enumerate(entries)
                if entry.resolved == candidate_parent
            ),
            len(entries) if scan_all_if_absent else 0,
        )
    for entry in entries[:candidate_position]:
        if role in entry.uninspectable_roles:
            return ToolAuthorityIssue(
                role,
                PATH_PREDECESSOR_UNINSPECTABLE,
                path_index=entry.index,
                candidate_class="parent-path",
                root_category=entry.root_category,
            )
        if (
            role == "bash"
            and policy.platform_name == "Windows"
            and any(
                entry.resolved is not None
                and _path_is_within(entry.resolved, system_root)
                for system_root in policy.minimal_system_directories
            )
        ):
            # System32/Sysnative WSL launchers are never Bash candidates;
            # execution is bound to Git Bash derived from trusted Git.
            continue
        alias = entry.alias_for(role)
        if alias is None:
            continue
        comparable_alias = _npm_entry_from_launcher(alias) if role == "npm" else alias
        if _same_file_identity(comparable_alias, canonical):
            continue
        if role == "bash" and _trusted_fixed_bash_alias(
            comparable_alias, canonical, policy
        ):
            continue
        reason_code = {
            UNSAFE_REPARSE_ESCAPE: PATH_REPARSE_ESCAPE,
            UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY: PATH_WORKSPACE_OR_TEMP_AUTHORITY,
            UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY: PATH_PREDECESSOR_UNINSPECTABLE,
            UNKNOWN_FAIL_CLOSED: PATH_ENTRY_UNKNOWN,
        }.get(entry.classification, PATH_EXECUTABLE_SHADOW)
        return ToolAuthorityIssue(
            role,
            reason_code,
            path_index=entry.index,
            candidate_class="parent-path",
            root_category=entry.root_category,
        )
    return None


def _preceding_shadow_error(
    entries: Sequence[_TrustedPathEntry],
    candidate: Path,
    role: str,
    policy: ToolAuthorityPolicy,
    *,
    scan_all_if_absent: bool = True,
) -> str | None:
    issue = _preceding_shadow_issue(
        entries,
        candidate,
        role,
        policy,
        scan_all_if_absent=scan_all_if_absent,
    )
    return issue.error_text() if issue is not None else None


def resolve_trusted_tools(
    required: Iterable[str],
    *,
    source_environment: Mapping[str, str] | None = None,
    repo_root: Path = REPO_ROOT,
    policy: ToolAuthorityPolicy | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Resolve role-specific tools and reject only real preceding executable shadows."""

    source = dict(os.environ if source_environment is None else source_environment)
    try:
        selected_policy = policy or default_tool_authority_policy(
            source, repo_root=repo_root
        )
    except EnvironmentAuthorityConflict as exc:
        return {}, [str(exc)]
    requested = set(required)
    errors: list[str] = []
    windows_environment = selected_policy.platform_name == "Windows"
    try:
        for authority_key in (
            "PATH",
            "RUNNER_TOOL_CACHE",
            "SystemRoot",
            "WINDIR",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "GITHUB_WORKSPACE",
            "RUNNER_TEMP",
            "NODE_EXE",
            "NPM_EXE",
            "PYTHON_EXE",
            "GIT_EXE",
            "POWERSHELL_EXE",
            "BASH_EXE",
            "CI_TRUSTED_PYTHON",
            "CI_TRUSTED_NODE",
            "CI_TRUSTED_NPM_ENTRY",
        ):
            _environment_authority_value(
                source, authority_key, windows=windows_environment
            )
    except EnvironmentAuthorityConflict as exc:
        return {}, [str(exc)]

    def record_issue(
        issue: ToolAuthorityIssue,
        *,
        kind: str = "tool-authority",
        classification: str | None = None,
    ) -> None:
        errors.append(issue.error_text())
        if diagnostics is not None:
            entry: dict[str, Any] = {
                "kind": kind,
                "tool": issue.tool,
                "reasonCode": issue.reason_code,
                "disposition": "rejected",
            }
            if issue.path_index is not None:
                entry["pathIndex"] = issue.path_index
            if issue.candidate_class is not None:
                entry["candidateLocationClass"] = issue.candidate_class
            if issue.root_category is not None:
                entry["rootCategory"] = issue.root_category
            if classification is not None:
                entry["classification"] = classification
            diagnostics.append(entry)

    for override in (
        "NODE_EXE",
        "NPM_EXE",
        "PYTHON_EXE",
        "GIT_EXE",
        "POWERSHELL_EXE",
        "BASH_EXE",
    ):
        if _environment_authority_value(
            source, override, windows=windows_environment
        ):
            override_role = override.removesuffix("_EXE").casefold()
            record_issue(
                ToolAuthorityIssue(
                    override_role,
                    TOOL_CANDIDATE_INVALID,
                    candidate_class="tool-candidate",
                )
            )

    entries, path_errors = _path_entries(
        source,
        required=requested,
        repo_root=repo_root,
        policy=selected_policy,
        diagnostics=diagnostics,
    )
    errors.extend(path_errors)
    windows_git_bash = selected_policy.platform_name == "Windows" and "bash" in requested
    path_resolved_names = requested - ({"bash"} if windows_git_bash else set())
    captured_runtime_variables = {
        "python": "CI_TRUSTED_PYTHON",
        "node": "CI_TRUSTED_NODE",
        "npm": "CI_TRUSTED_NPM_ENTRY",
    }
    resolved_tools: dict[str, str] = {}
    for name in sorted(path_resolved_names):
        candidate_entry: _TrustedPathEntry | None = None
        candidate_blocked = False
        captured_name = captured_runtime_variables.get(name)
        captured_value = (
            _environment_authority_value(
                source,
                captured_name,
                windows=windows_environment,
                default="",
            )
            if captured_name
            else ""
        )
        candidate: str | None = captured_value or None
        if candidate is None and name == "python":
            candidate = str(selected_policy.running_python)
        if candidate is None:
            for entry in entries:
                if name in entry.uninspectable_roles:
                    record_issue(
                        ToolAuthorityIssue(
                            name,
                            PATH_PREDECESSOR_UNINSPECTABLE,
                            path_index=entry.index,
                            candidate_class="parent-path",
                            root_category=entry.root_category,
                        ),
                        kind="path-shadow",
                        classification=entry.classification,
                    )
                    candidate_blocked = True
                    break
                alias = entry.alias_for(name)
                if alias is None:
                    continue
                alias = _npm_entry_from_launcher(alias) if name == "npm" else alias
                try:
                    alias_canonical = alias.resolve(strict=True)
                except OSError:
                    record_issue(
                        ToolAuthorityIssue(
                            name,
                            PATH_PREDECESSOR_UNINSPECTABLE,
                            path_index=entry.index,
                            candidate_class="parent-path",
                            root_category=entry.root_category,
                        ),
                        kind="path-shadow",
                        classification=UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
                    )
                    candidate_blocked = True
                    break
                root_result = _tool_root_classification_result(
                    alias_canonical, name, selected_policy
                )
                if root_result.inspection_failed:
                    record_issue(
                        ToolAuthorityIssue(
                            name,
                            PATH_PREDECESSOR_UNINSPECTABLE,
                            path_index=entry.index,
                            candidate_class="parent-path",
                            root_category=entry.root_category,
                        ),
                        kind="path-shadow",
                        classification=UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY,
                    )
                    candidate_blocked = True
                    break
                if root_result.root_label is None:
                    reason_code = {
                        UNSAFE_REPARSE_ESCAPE: PATH_REPARSE_ESCAPE,
                        UNSAFE_WORKSPACE_OR_TEMP_AUTHORITY: PATH_WORKSPACE_OR_TEMP_AUTHORITY,
                        UNSAFE_UNINSPECTABLE_SHADOW_CAPABLE_ENTRY: PATH_PREDECESSOR_UNINSPECTABLE,
                        UNKNOWN_FAIL_CLOSED: PATH_ENTRY_UNKNOWN,
                    }.get(entry.classification, PATH_EXECUTABLE_SHADOW)
                    record_issue(
                        ToolAuthorityIssue(
                            name,
                            reason_code,
                            path_index=entry.index,
                            candidate_class="parent-path",
                            root_category=entry.root_category,
                        ),
                        kind="path-shadow",
                        classification=entry.classification,
                    )
                    candidate_blocked = True
                    break
                candidate = str(alias_canonical)
                candidate_entry = entry
                break
        if candidate is None and not candidate_blocked:
            fallback = _fallback_tool_candidate(name, selected_policy)
            if fallback is not None:
                candidate = str(fallback)
        if candidate_blocked:
            continue
        if not candidate:
            record_issue(ToolAuthorityIssue(name, REQUIRED_TOOL_MISSING))
            continue
        candidate_path = Path(candidate)
        if not candidate_path.is_absolute():
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_CANDIDATE_INVALID,
                    candidate_class="tool-candidate",
                )
            )
            continue
        try:
            canonical_candidate = candidate_path.resolve(strict=True)
        except OSError:
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_CANDIDATE_UNREADABLE,
                    candidate_class="tool-candidate",
                )
            )
            continue
        okay, _reason = _secure_regular_file(canonical_candidate)
        if not okay:
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_CANDIDATE_INVALID,
                    path_index=(candidate_entry.index if candidate_entry else None),
                    candidate_class=(
                        "parent-path" if candidate_entry else "tool-candidate"
                    ),
                    root_category=(
                        candidate_entry.root_category if candidate_entry else None
                    ),
                )
            )
            continue
        root_result = _tool_root_classification_result(
            canonical_candidate, name, selected_policy
        )
        if root_result.inspection_failed:
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_CANDIDATE_UNREADABLE,
                    path_index=(candidate_entry.index if candidate_entry else None),
                    candidate_class=(
                        "parent-path" if candidate_entry else "tool-candidate"
                    ),
                    root_category=(
                        candidate_entry.root_category if candidate_entry else None
                    ),
                )
            )
            continue
        classification = root_result.root_label
        unsafe_reason = _unsafe_tool_path_reason(
            canonical_candidate,
            repo_root,
            source,
            windows=selected_policy.platform_name == "Windows",
        )
        if (
            name == "npm"
            and unsafe_reason == "path is beneath node_modules"
            and not _path_is_within(canonical_candidate, repo_root.resolve(strict=True))
            and classification is not None
        ):
            unsafe_reason = None
        if unsafe_reason and not (selected_policy.synthetic and classification is not None):
            unsafe_code = (
                PATH_WORKSPACE_OR_TEMP_AUTHORITY
                if unsafe_reason
                in {
                    "path is beneath the repository workspace",
                    "path is beneath runner-controlled temporary storage",
                    "path is beneath node_modules",
                }
                else TOOL_CANDIDATE_INVALID
            )
            record_issue(
                ToolAuthorityIssue(
                    name,
                    unsafe_code,
                    path_index=(candidate_entry.index if candidate_entry else None),
                    candidate_class=(
                        "parent-path" if candidate_entry else "tool-candidate"
                    ),
                    root_category=(
                        candidate_entry.root_category if candidate_entry else None
                    ),
                )
            )
            continue
        if classification is None:
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_CANDIDATE_INVALID,
                    path_index=(candidate_entry.index if candidate_entry else None),
                    candidate_class=(
                        "parent-path" if candidate_entry else "tool-candidate"
                    ),
                    root_category=(
                        candidate_entry.root_category if candidate_entry else None
                    ),
                )
            )
            continue
        shadow_issue = _preceding_shadow_issue(
            entries,
            canonical_candidate,
            name,
            selected_policy,
            scan_all_if_absent=bool(captured_value),
        )
        if shadow_issue:
            record_issue(shadow_issue, kind="path-shadow")
            continue
        if name == "python" and captured_value and not _same_file_identity(
            candidate_path, selected_policy.running_python
        ):
            record_issue(
                ToolAuthorityIssue(
                    name,
                    TOOL_IDENTITY_DRIFT,
                    candidate_class="tool-candidate",
                )
            )
            continue
        resolved_tools[name] = str(canonical_candidate)
    if windows_git_bash:
        git = resolved_tools.get("git")
        if git is None:
            record_issue(ToolAuthorityIssue("bash", REQUIRED_TOOL_MISSING))
        else:
            bash, bash_errors = resolve_trusted_git_bash(
                git,
                source_environment=source,
                repo_root=repo_root,
                policy=selected_policy,
                diagnostics=diagnostics,
            )
            errors.extend(bash_errors)
            if bash is not None:
                shadow_issue = _preceding_shadow_issue(
                    entries,
                    Path(bash),
                    "bash",
                    selected_policy,
                )
                if shadow_issue:
                    errors.append(shadow_issue.error_text())
                    if diagnostics is not None:
                        for entry in reversed(diagnostics):
                            if (
                                entry.get("kind") == "bash-candidate"
                                and entry.get("disposition") == "accepted"
                            ):
                                entry["pathShadowDisposition"] = "rejected"
                                entry["failureReason"] = shadow_issue.reason_code
                                entry["reasonCode"] = shadow_issue.reason_code
                                entry["disposition"] = "rejected"
                                break
                        record = {
                            "kind": "path-shadow",
                            "tool": "bash",
                            "reasonCode": shadow_issue.reason_code,
                            "disposition": "rejected",
                        }
                        if shadow_issue.path_index is not None:
                            record["pathIndex"] = shadow_issue.path_index
                        if shadow_issue.candidate_class is not None:
                            record["candidateLocationClass"] = (
                                shadow_issue.candidate_class
                            )
                        if shadow_issue.root_category is not None:
                            record["rootCategory"] = shadow_issue.root_category
                        diagnostics.append(record)
                else:
                    if diagnostics is not None:
                        for entry in reversed(diagnostics):
                            if (
                                entry.get("kind") == "bash-candidate"
                                and entry.get("disposition") == "accepted"
                            ):
                                entry["pathShadowDisposition"] = "accepted"
                                break
                    resolved_tools["bash"] = bash
    return resolved_tools, sorted(set(errors))


CHILD_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "CI",
        "GITHUB_ACTIONS",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "LANG",
        "LC_ALL",
        "COMSPEC",
        "PATHEXT",
    }
)


def child_process_environment(
    tools: Mapping[str, str],
    *,
    source_environment: Mapping[str, str] | None = None,
    private_temp_root: Path | None = None,
    repo_root: Path = REPO_ROOT,
    policy: ToolAuthorityPolicy | None = None,
) -> dict[str, str]:
    source = os.environ if source_environment is None else source_environment
    selected_policy = policy or default_tool_authority_policy(source, repo_root=repo_root)
    windows_environment = selected_policy.platform_name == "Windows"
    private_temp_keys = ("TEMP", "TMP", "TMPDIR") if private_temp_root is not None else ()
    source_authority = _EnvironmentKeyAuthority(
        source,
        windows=windows_environment,
        excluded_keys=private_temp_keys,
    )
    environment = source_authority.canonical_subset(CHILD_ENVIRONMENT_ALLOWLIST)
    tool_directories: list[str] = []
    seen_directories: set[str] = set()

    def add_directory(directory: Path, *, synthetic_authority: bool = False) -> None:
        try:
            resolved = directory.resolve(strict=True)
        except OSError:
            return
        reason = _unsafe_tool_path_reason(
            resolved,
            repo_root,
            source,
            windows=selected_policy.platform_name == "Windows",
        )
        if reason and not (selected_policy.synthetic and synthetic_authority):
            return
        key = str(resolved).casefold() if selected_policy.platform_name == "Windows" else str(resolved)
        if key in seen_directories:
            return
        seen_directories.add(key)
        tool_directories.append(str(resolved))

    for role, executable in tools.items():
        # npm is an entrypoint executed by captured Node, never a PATH authority.
        if role == "npm":
            continue
        try:
            resolved_executable = Path(executable).resolve(strict=True)
        except OSError:
            continue
        root_result = _tool_root_classification_result(
            resolved_executable, role, selected_policy
        )
        if root_result.inspection_failed:
            continue
        classification = root_result.root_label
        add_directory(
            resolved_executable.parent,
            synthetic_authority=classification is not None,
        )
    for directory in selected_policy.minimal_system_directories:
        add_directory(directory, synthetic_authority=selected_policy.synthetic)
    environment["PATH"] = selected_policy.path_separator.join(tool_directories)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    if private_temp_root is not None:
        private_temp = private_temp_root.resolve(strict=True)
        for name in ("TEMP", "TMP", "TMPDIR"):
            environment[name] = str(private_temp)
    powershell = tools.get("powershell") or tools.get("pwsh")
    if powershell:
        environment["POWERSHELL_EXE"] = str(Path(powershell).resolve(strict=True))
    bash = tools.get("bash")
    if bash:
        environment["BASH_EXE"] = str(Path(bash).resolve(strict=True))
    if tools.get("git"):
        environment["GIT_CONFIG_COUNT"] = "1"
        environment["GIT_CONFIG_KEY_0"] = "safe.directory"
        environment["GIT_CONFIG_VALUE_0"] = str(repo_root.resolve())
    return environment


def trusted_git_arguments(git: str, *arguments: str) -> list[str]:
    """Use only the exact repository as safe, independent of mutable user Git config."""

    return [git, "-c", f"safe.directory={REPO_ROOT.resolve()}", *arguments]


@dataclass
class _BoundedStream:
    byte_limit: int
    line_limit: int
    buffer: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    total_bytes: int = 0
    current_line_bytes: int = 0
    limit_reason: str | None = None

    def feed(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        for byte in chunk:
            self.current_line_bytes = 0 if byte in (0x00, 0x0A, 0x0D) else self.current_line_bytes + 1
            if self.current_line_bytes > self.line_limit and self.limit_reason is None:
                self.limit_reason = "maximum line length exceeded"
        if len(self.buffer) < self.byte_limit:
            remaining = self.byte_limit - len(self.buffer)
            self.buffer.extend(chunk[:remaining])
        tail_limit = max(1, self.byte_limit // 2)
        self.tail.extend(chunk)
        if len(self.tail) > tail_limit:
            del self.tail[:-tail_limit]
        if self.total_bytes > self.byte_limit and self.limit_reason is None:
            self.limit_reason = "maximum stream bytes exceeded"

    def text(self) -> str:
        if self.total_bytes <= self.byte_limit:
            data = bytes(self.buffer)
        else:
            head_limit = max(1, self.byte_limit // 2)
            data = bytes(self.buffer[:head_limit]) + b"\n[OUTPUT-LIMIT-EXCEEDED]\n" + bytes(self.tail)
        return data.decode("utf-8", errors="replace")

    def data(self) -> bytes:
        """Return exact captured bytes when the stream remained within bounds."""

        if self.total_bytes > self.byte_limit:
            raise ValueError("bounded stream data is unavailable after an output-limit failure")
        return bytes(self.buffer)


@dataclass
class CommandCapture:
    command_id: str
    command_class: str
    argv: list[str]
    executed: bool
    exit_code: int | None
    duration_seconds: float
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    required: bool = True
    cwd: str = "."
    stdout_raw: bytes | None = field(default=None, repr=False)
    stderr_raw: bytes | None = field(default=None, repr=False)
    stdout_byte_limit: int = MAX_STDOUT_BYTES
    stderr_byte_limit: int = MAX_STDERR_BYTES
    error: str | None = None
    include_preview: bool = True
    timed_out: bool = False
    output_limited: bool = False
    limit_reason: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    failure_summary: dict[str, Any] | None = None
    containment: str = "not-started"
    process_tree_status: str = "not-started"
    descendants_terminated: int = 0
    descendants_observed: int = 0
    descendants_reaped: int = 0
    descendants_surviving: int = 0
    containment_disposition: str = "not-applicable"
    process_tree_error: str | None = None
    logical_argv: list[str] | None = None
    execution_input_mode: str = "NONE"
    execution_input_size: int | None = None
    execution_input_sha256: str | None = None
    producer_observations: list[dict[str, Any]] = field(default_factory=list, repr=False)
    target_execution_lease: dict[str, Any] | None = None
    # Physical command streams remain authoritative.  These parallel fields are
    # derived, authority-bound inputs for failure parsing only and are never used
    # to replace or hash the raw diagnostic bytes.
    identity_stdout: str | None = field(default=None, repr=False)
    identity_stderr: str | None = field(default=None, repr=False)
    identity_error: str | None = field(default=None, repr=False)
    identity_stdout_raw: bytes | None = field(default=None, repr=False)
    identity_stderr_raw: bytes | None = field(default=None, repr=False)
    failure_path_authority: Any | None = field(default=None, repr=False)
    validated_static_machine_report: dict[str, Any] | None = field(default=None, repr=False)

    def execution_passed(self) -> bool:
        return (
            self.executed
            and self.exit_code == 0
            and not self.timed_out
            and not self.output_limited
            and self.process_tree_status == "contained-clean"
            and self.process_tree_error is None
        )

    def evidence(self) -> dict[str, Any]:
        stdout_bytes = (
            self.stdout_raw
            if self.stdout_raw is not None
            else self.stdout.encode("utf-8", errors="strict")
        )
        stderr_bytes = (
            self.stderr_raw
            if self.stderr_raw is not None
            else self.stderr.encode("utf-8", errors="strict")
        )
        target_lease = (
            copy.deepcopy(self.target_execution_lease)
            if self.target_execution_lease is not None
            else None
        )
        execution_inputs = []
        if target_lease is not None:
            execution_inputs = [
                {
                    "logicalPath": target_lease.get("logicalTargetPath"),
                    "canonicalSourcePath": target_lease.get("canonicalSourcePath"),
                    "plannedByteLength": target_lease.get("plannedByteLength"),
                    "plannedSha256": target_lease.get("plannedSha256"),
                    "plannedStableIdentity": target_lease.get("plannedStableFileIdentity"),
                    "actualByteLength": target_lease.get("executedInputByteLength"),
                    "actualSha256": target_lease.get("executedInputSha256"),
                    "inputMode": target_lease.get("executionAdapter"),
                }
            ]
        record: dict[str, Any] = {
            "commandId": self.command_id,
            "commandClass": self.command_class,
            "executable": Path(self.argv[0]).name if self.argv else "internal",
            "required": self.required,
            "executed": self.executed,
            "started": self.executed,
            "setupFailure": not self.executed or self.process_tree_status == "setup-failed",
            "exitCode": self.exit_code,
            "durationSeconds": round(self.duration_seconds, 3),
            "executionDurationClass": "bounded" if self.executed else "not-started",
            "timeoutStatus": "TIMED-OUT" if self.timed_out else "within-limit",
            "outputLimitStatus": "OUTPUT-LIMIT-EXCEEDED" if self.output_limited else "within-limit",
            "stdoutBytesObserved": self.stdout_bytes,
            "stderrBytesObserved": self.stderr_bytes,
            "stdoutByteLimit": self.stdout_byte_limit,
            "stderrByteLimit": self.stderr_byte_limit,
            "containment": self.containment,
            "processTreeStatus": self.process_tree_status,
            "descendantsTerminated": self.descendants_terminated,
            "descendantsObserved": self.descendants_observed,
            "descendantsReaped": self.descendants_reaped,
            "descendantsSurviving": self.descendants_surviving,
            "containmentDisposition": self.containment_disposition,
            "actualExecutionArgv": list(self.argv),
            "actualExecutionInputMode": self.execution_input_mode,
            "actualExecutionInputSize": self.execution_input_size,
            "actualExecutionInputSha256": self.execution_input_sha256,
            "stdoutSha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
            "producerObservations": normalized_json_value(self.producer_observations),
            "producerObservationSetDigest": producer_observation_set_digest(
                self.producer_observations
            ),
            "completedCommandClass": None,
            "executionInputs": execution_inputs,
            "executionInputBundleDigest": (
                execution_input_bundle_digest(execution_inputs) if execution_inputs else None
            ),
            "targetExecutionLease": target_lease,
            "protectedTargetBundle": None,
        }
        if self.error:
            record["error"] = sanitize_text(self.error)
        if self.limit_reason:
            record["limitReason"] = sanitize_text(self.limit_reason)
        if self.process_tree_error:
            record["processTreeError"] = sanitize_text(self.process_tree_error)
        if self.include_preview and (self.exit_code not in (0, None) or self.output_limited or self.timed_out):
            record["diagnosticPreview"] = bounded_preview(
                "\n".join(part for part in (self.stdout, self.stderr) if part)
            )
        failure_summary = self.failure_summary
        if failure_summary is None and self.executed and self.exit_code not in (0, None):
            failure_summary = extract_failure_identity(
                f"command:{self.command_id}",
                stdout=(self.identity_stdout if self.identity_stdout is not None else self.stdout),
                stderr=(self.identity_stderr if self.identity_stderr is not None else self.stderr),
            )
        if failure_summary:
            record["parsedFailureSummary"] = normalized_json_value(failure_summary)
        if self.validated_static_machine_report is not None:
            # Preserve local machine-plan authority for independent validation;
            # the physical stdout hash above remains exact local evidence.
            record["validatedStaticMachineReport"] = copy.deepcopy(
                self.validated_static_machine_report
            )
        return record

    def authoritative_stdout_bytes(self) -> bytes:
        if self.stdout_raw is not None:
            return self.stdout_raw
        return self.stdout.encode("utf-8", errors="strict")

    def failure_identity_stdout_bytes(self) -> bytes:
        if self.identity_stdout_raw is not None:
            return self.identity_stdout_raw
        if self.identity_stdout is not None:
            return self.identity_stdout.encode("utf-8", errors="strict")
        return self.authoritative_stdout_bytes()


_ACTIVE_CONTAINMENTS: set[str] = set()
_ACTIVE_CONTAINMENTS_LOCK = threading.Lock()


def _register_containment(identity: str) -> None:
    with _ACTIVE_CONTAINMENTS_LOCK:
        _ACTIVE_CONTAINMENTS.add(identity)


def _unregister_containment(identity: str) -> None:
    with _ACTIVE_CONTAINMENTS_LOCK:
        _ACTIVE_CONTAINMENTS.discard(identity)


def active_containment_count() -> int:
    with _ACTIVE_CONTAINMENTS_LOCK:
        return len(_ACTIVE_CONTAINMENTS)


@dataclass(frozen=True)
class PosixProcessIdentity:
    pid: int
    starttime: int
    parent_pid: int
    process_group: int
    session_id: int
    discovery_generation: int

    def key(self) -> tuple[int, int]:
        return self.pid, self.starttime


class PosixContainmentStateMachine:
    """Pure descendant-registry model shared by live and simulated backends."""

    def __init__(self, supervisor_pid: int) -> None:
        self.supervisor_pid = supervisor_pid
        self.generation = 0
        self.registry: dict[tuple[int, int], PosixProcessIdentity] = {}
        self.active_keys: set[tuple[int, int]] = set()
        self.direct_child_keys: set[tuple[int, int]] = set()
        self.reaped_keys: set[tuple[int, int]] = set()
        self.proven_dead_keys: set[tuple[int, int]] = set()
        self.failures: list[str] = []

    def fail(self, reason: str) -> None:
        if reason not in self.failures:
            self.failures.append(reason)

    def observe(self, snapshot: Mapping[int, PosixProcessIdentity]) -> list[PosixProcessIdentity]:
        self.generation += 1
        by_pid = dict(snapshot)
        domain_pids = {self.supervisor_pid}
        changed = True
        while changed:
            changed = False
            for identity in by_pid.values():
                if identity.parent_pid in domain_pids and identity.pid not in domain_pids:
                    domain_pids.add(identity.pid)
                    changed = True
        discovered: list[PosixProcessIdentity] = []
        active: set[tuple[int, int]] = set()
        for pid in sorted(domain_pids - {self.supervisor_pid}):
            identity = by_pid[pid]
            prior_keys = [key for key in self.registry if key[0] == pid]
            if prior_keys and identity.key() not in prior_keys and any(
                key in self.active_keys for key in prior_keys
            ):
                self.fail(f"PID reuse ambiguity for active PID {pid}")
            if identity.key() not in self.registry:
                self.registry[identity.key()] = identity
                discovered.append(identity)
            if identity.parent_pid == self.supervisor_pid:
                self.direct_child_keys.add(identity.key())
            active.add(identity.key())
        # A known descendant is not allowed to become "clean" merely by
        # changing session/parent or racing between proc scans.  Missing
        # identities remain active until a separate complete snapshot or
        # pidfd observation proves death; direct children require waitpid.
        for key in self.active_keys:
            if key in self.reaped_keys or key in self.proven_dead_keys or key in active:
                continue
            known = self.registry[key]
            current = by_pid.get(known.pid)
            if current is None:
                active.add(key)
                continue
            if current.key() != key:
                self.fail(f"PID reuse ambiguity for active PID {known.pid}")
                active.add(key)
                continue
            self.fail(f"known descendant escaped supervisor ancestry: PID {known.pid}")
            active.add(key)
        if len(self.registry) > 4096:
            self.fail("descendant registry overflow")
        self.active_keys = active
        return discovered

    def retire_proven_dead_non_children(
        self,
        snapshot: Mapping[int, PosixProcessIdentity] | None,
        *,
        pidfd_exited: Iterable[tuple[int, int]] = (),
    ) -> None:
        """Retire only frozen non-child identities with positive death evidence."""

        exited = set(pidfd_exited)
        if snapshot is None and not exited:
            self.fail("non-child descendant death evidence is unavailable")
            return
        for key in tuple(self.active_keys):
            if key in self.direct_child_keys:
                continue
            known = self.registry[key]
            current = snapshot.get(known.pid) if snapshot is not None else None
            if key in exited or (snapshot is not None and current is None):
                self.proven_dead_keys.add(key)
                self.active_keys.discard(key)
                continue
            if current is not None and current.key() != key:
                self.fail(f"PID reuse ambiguity for active PID {known.pid}")

    def mark_reaped(self, pid: int) -> None:
        candidates = [key for key in self.active_keys if key[0] == pid]
        if len(candidates) > 1:
            self.fail(f"reap identity ambiguity for PID {pid}")
            return
        if candidates:
            self.reaped_keys.add(candidates[0])
            self.active_keys.discard(candidates[0])

    def active_identities(self) -> list[PosixProcessIdentity]:
        return [self.registry[key] for key in sorted(self.active_keys)]

    def clean(self) -> bool:
        return not self.failures and not self.active_keys

    def outcome(
        self,
        *,
        root_key: tuple[int, int] | None = None,
        cleanup_signal_sent: bool = False,
        forced_terminated: int = 0,
    ) -> dict[str, Any]:
        """Report the security truth condition independently of cleanup counters."""

        excluded = {root_key} if root_key is not None else set()
        observed = set(self.registry) - excluded
        reaped = (self.reaped_keys | self.proven_dead_keys) & observed
        surviving = self.active_keys & observed
        cleanup_complete = not self.failures and not self.active_keys
        if self.failures:
            disposition = "unknown-ancestry"
        elif surviving:
            disposition = "survivor"
        elif cleanup_signal_sent or forced_terminated:
            disposition = "forced-terminated"
        elif observed:
            disposition = "natural-exit-reaped"
        else:
            disposition = "no-descendants"
        return {
            "cleanupComplete": cleanup_complete,
            "descendantsObserved": len(observed),
            "descendantsReaped": len(reaped),
            "descendantsSurviving": len(surviving),
            "containmentDisposition": disposition,
        }


_MAIN_SUBREAPER_CONFIGURED = False
_MAIN_SUBREAPER_LOCK = threading.Lock()


def _set_linux_child_subreaper() -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("PR_SET_CHILD_SUBREAPER is available only on Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    value = ctypes.c_ulong()
    if prctl(37, ctypes.addressof(value), 0, 0, 0) != 0 or value.value != 1:
        raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER verification failed")


def ensure_main_linux_subreaper() -> None:
    global _MAIN_SUBREAPER_CONFIGURED
    if not sys.platform.startswith("linux"):
        return
    with _MAIN_SUBREAPER_LOCK:
        if not _MAIN_SUBREAPER_CONFIGURED:
            _set_linux_child_subreaper()
            _MAIN_SUBREAPER_CONFIGURED = True


def _read_linux_process_identity(pid: int, generation: int) -> PosixProcessIdentity:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="strict")
    close_paren = raw.rfind(")")
    if close_paren <= 0:
        raise ValueError("/proc stat command name framing is invalid")
    fields = raw[close_paren + 2 :].split()
    if len(fields) < 20:
        raise ValueError("/proc stat record is truncated")
    return PosixProcessIdentity(
        pid=pid,
        starttime=int(fields[19]),
        parent_pid=int(fields[1]),
        process_group=int(fields[2]),
        session_id=int(fields[3]),
        discovery_generation=generation,
    )


def _read_linux_proc_snapshot(generation: int) -> dict[int, PosixProcessIdentity]:
    snapshot: dict[int, PosixProcessIdentity] = {}
    try:
        entries = list(os.scandir("/proc"))
    except OSError as exc:
        raise OSError(f"/proc enumeration failed: {type(exc).__name__}") from exc
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            snapshot[pid] = _read_linux_process_identity(pid, generation)
        except FileNotFoundError:
            continue
        except ProcessLookupError:
            continue
        except (OSError, UnicodeError, ValueError) as exc:
            raise OSError(f"/proc/{pid}/stat read failed: {type(exc).__name__}") from exc
    return snapshot


def _pidfd_capability_check() -> None:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise OSError("pidfd_open/pidfd_send_signal capability is unavailable")


def _pidfd_reports_exit(pidfd: int) -> bool:
    watcher = select.poll()
    watcher.register(
        pidfd,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    events = watcher.poll(0)
    for _descriptor, mask in events:
        if mask & select.POLLNVAL:
            raise OSError("pidfd became invalid during containment")
        if mask & select.POLLERR:
            raise OSError("pidfd reported an uninspectable containment error")
        if mask & (select.POLLIN | select.POLLHUP):
            return True
    return False


def _retire_linux_non_child_exits(
    state: PosixContainmentStateMachine,
    snapshot: Mapping[int, PosixProcessIdentity],
    pidfds: Mapping[tuple[int, int], int],
) -> None:
    exited = {
        key
        for key in state.active_keys - state.direct_child_keys
        if (pidfd := pidfds.get(key)) is not None and _pidfd_reports_exit(pidfd)
    }
    state.retire_proven_dead_non_children(snapshot, pidfd_exited=exited)


def _pidfd_send_checked(
    identity: PosixProcessIdentity,
    pidfd: int,
    signal_number: int,
) -> None:
    try:
        current = _read_linux_process_identity(identity.pid, identity.discovery_generation)
    except FileNotFoundError:
        return
    if current.starttime != identity.starttime:
        raise OSError(f"PID/starttime identity changed before signal: {identity.pid}")
    try:
        signal.pidfd_send_signal(pidfd, signal_number, None, 0)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise OSError(f"pidfd signal failed for PID {identity.pid}: {type(exc).__name__}") from exc


def _wait_status_exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return PROCESS_TREE_FAILURE_EXIT


def _linux_supervisor_write(fd: int, value: Mapping[str, Any]) -> None:
    data = json.dumps(
        dict(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii") + b"\n"
    os.write(fd, data)


def _linux_containment_supervisor_entrypoint(arguments: Sequence[str]) -> int:
    """Run in a dedicated trusted Python process; never called on Windows."""

    if len(arguments) != 5 or any(not re.fullmatch(r"-?[0-9]+", item) for item in arguments):
        return PROCESS_TREE_FAILURE_EXIT
    stdin_fd, stdout_fd, stderr_fd, result_fd, control_fd = map(int, arguments)
    root_pid: int | None = None
    root_key: tuple[int, int] | None = None
    pidfds: dict[tuple[int, int], int] = {}
    state = PosixContainmentStateMachine(os.getpid())
    root_exit_code: int | None = None
    command_started = False
    terminated_count = 0
    error_text: str | None = None
    try:
        _set_linux_child_subreaper()
        _pidfd_capability_check()
        config_text = os.environ.pop("CI_LINUX_SUPERVISOR_CONFIG", "")
        config = strict_json_loads(config_text, label="Linux containment supervisor config")
        if not isinstance(config, dict) or set(config) != {"argv", "cwd", "environment"}:
            raise ValueError("Linux supervisor configuration schema is invalid")
        argv = config["argv"]
        cwd = config["cwd"]
        environment = config["environment"]
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(item, str) or not item for item in argv)
            or not isinstance(cwd, str)
            or not Path(cwd).is_absolute()
            or not isinstance(environment, dict)
            or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items())
        ):
            raise ValueError("Linux supervisor command authority is invalid")
        initial = _read_linux_proc_snapshot(0)
        preexisting_children = [
            item for item in initial.values() if item.parent_pid == os.getpid()
        ]
        if preexisting_children:
            raise OSError("unexpected concurrent child exists in supervisor domain")
        gate_r, gate_w = os.pipe()
        root_pid = os.fork()
        if root_pid == 0:
            try:
                os.close(gate_w)
                os.close(result_fd)
                os.close(control_fd)
                os.setsid()
                if os.read(gate_r, 1) != b"G":
                    os._exit(PROCESS_TREE_FAILURE_EXIT)
                os.close(gate_r)
                if stdin_fd >= 0:
                    os.dup2(stdin_fd, 0)
                else:
                    devnull = os.open(os.devnull, os.O_RDONLY)
                    os.dup2(devnull, 0)
                    os.close(devnull)
                os.dup2(stdout_fd, 1)
                os.dup2(stderr_fd, 2)
                for fd in (stdin_fd, stdout_fd, stderr_fd):
                    if fd > 2:
                        os.close(fd)
                os.chdir(cwd)
                os.execve(argv[0], argv, environment)
            except BaseException as exc:
                try:
                    os.write(2, f"containment exec failed: {type(exc).__name__}\n".encode("ascii"))
                except OSError:
                    pass
                os._exit(127)
        os.close(gate_r)
        for fd in (stdin_fd, stdout_fd, stderr_fd):
            if fd >= 0:
                os.close(fd)
        root_identity = _read_linux_process_identity(root_pid, 1)
        root_key = root_identity.key()
        root_pidfd = os.pidfd_open(root_pid, 0)
        pidfds[root_identity.key()] = root_pidfd
        state.registry[root_identity.key()] = root_identity
        state.active_keys.add(root_identity.key())
        state.direct_child_keys.add(root_identity.key())
        _linux_supervisor_write(
            result_fd,
            {
                "event": "started",
                "pid": root_pid,
                "starttime": root_identity.starttime,
                "supervisorPid": os.getpid(),
            },
        )
        os.write(gate_w, b"G")
        os.close(gate_w)
        command_started = True
        os.set_blocking(control_fd, False)
        cancellation_requested = False
        while not cancellation_requested and root_exit_code is None:
            try:
                if os.read(control_fd, 1):
                    cancellation_requested = True
            except BlockingIOError:
                pass
            except OSError as exc:
                if exc.errno != errno.EINTR:
                    raise
            snapshot = _read_linux_proc_snapshot(state.generation + 1)
            for identity in state.observe(snapshot):
                try:
                    pidfds[identity.key()] = os.pidfd_open(identity.pid, 0)
                except OSError as exc:
                    if exc.errno not in {errno.ESRCH, errno.ENOENT}:
                        state.fail(
                            f"pidfd_open failed for PID {identity.pid}: {type(exc).__name__}"
                        )
            _retire_linux_non_child_exits(state, snapshot, pidfds)
            while True:
                try:
                    reaped_pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if reaped_pid == 0:
                    break
                if reaped_pid == root_pid:
                    root_exit_code = _wait_status_exit_code(status)
                state.mark_reaped(reaped_pid)
            if state.failures:
                cancellation_requested = True
            if not cancellation_requested and root_exit_code is None:
                time.sleep(LINUX_CONTAINMENT_SCAN_SECONDS)

        cleanup_deadline = time.monotonic() + LINUX_CONTAINMENT_SETTLE_SECONDS
        stable_count = 0
        term_sent = False
        kill_sent = False
        phase_started = time.monotonic()
        while time.monotonic() < cleanup_deadline:
            snapshot = _read_linux_proc_snapshot(state.generation + 1)
            for identity in state.observe(snapshot):
                try:
                    pidfds[identity.key()] = os.pidfd_open(identity.pid, 0)
                except OSError as exc:
                    if exc.errno not in {errno.ESRCH, errno.ENOENT}:
                        state.fail(
                            f"pidfd_open failed for PID {identity.pid}: {type(exc).__name__}"
                        )
            _retire_linux_non_child_exits(state, snapshot, pidfds)
            active = state.active_identities()
            if active:
                stable_count = 0
                for identity in active:
                    pidfd = pidfds.get(identity.key())
                    if pidfd is None:
                        if identity.key() in state.direct_child_keys:
                            state.fail(f"active direct child lacks pidfd: {identity.pid}")
                        continue
                    _pidfd_send_checked(identity, pidfd, signal.SIGSTOP)
                if not term_sent:
                    for identity in active:
                        pidfd = pidfds.get(identity.key())
                        if pidfd is not None:
                            _pidfd_send_checked(identity, pidfd, signal.SIGTERM)
                            _pidfd_send_checked(identity, pidfd, signal.SIGCONT)
                    term_sent = True
                if time.monotonic() - phase_started >= PROCESS_TREE_GRACE_SECONDS:
                    for identity in active:
                        pidfd = pidfds.get(identity.key())
                        if pidfd is not None:
                            _pidfd_send_checked(identity, pidfd, signal.SIGKILL)
                    kill_sent = True
                    terminated_count = max(terminated_count, len(active))
            else:
                stable_count += 1
            while True:
                try:
                    reaped_pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if reaped_pid == 0:
                    break
                if reaped_pid == root_pid and root_exit_code is None:
                    root_exit_code = _wait_status_exit_code(status)
                state.mark_reaped(reaped_pid)
            if stable_count >= LINUX_CONTAINMENT_STABLE_SCANS:
                break
            time.sleep(LINUX_CONTAINMENT_SCAN_SECONDS)
        if stable_count < LINUX_CONTAINMENT_STABLE_SCANS:
            state.fail("descendant cleanup settle timeout")
        final_snapshot = _read_linux_proc_snapshot(state.generation + 1)
        state.observe(final_snapshot)
        _retire_linux_non_child_exits(state, final_snapshot, pidfds)
        if state.active_keys:
            state.fail("command-domain descendant registry is not empty")
        if root_exit_code is None:
            state.fail("root process was not reaped")
        if state.failures:
            error_text = "; ".join(state.failures)
        containment_outcome = state.outcome(
            root_key=root_key,
            cleanup_signal_sent=term_sent or kill_sent,
            forced_terminated=terminated_count,
        )
        _linux_supervisor_write(
            result_fd,
            {
                "event": "final",
                "commandStarted": command_started,
                "rootExitCode": root_exit_code,
                "cleanupOk": not state.failures and state.clean(),
                **containment_outcome,
                "descendantsTerminated": terminated_count,
                "registrySize": len(state.registry),
                "discoveryGenerations": state.generation,
                "termSent": term_sent,
                "killSent": kill_sent,
                "error": error_text,
            },
        )
        return EXIT_SUCCESS if not state.failures else PROCESS_TREE_FAILURE_EXIT
    except BaseException as exc:
        error_text = f"Linux containment supervisor failure: {type(exc).__name__}: {exc}"
        containment_outcome = state.outcome(
            root_key=root_key,
            forced_terminated=terminated_count,
        )
        try:
            _linux_supervisor_write(
                result_fd,
                {
                    "event": "final",
                    "commandStarted": command_started,
                    "rootExitCode": root_exit_code,
                    "cleanupOk": False,
                    **containment_outcome,
                    "descendantsTerminated": terminated_count,
                    "registrySize": len(state.registry),
                    "discoveryGenerations": state.generation,
                    "termSent": False,
                    "killSent": False,
                    "error": error_text,
                },
            )
        except OSError:
            pass
        return PROCESS_TREE_FAILURE_EXIT
    finally:
        for pidfd in pidfds.values():
            try:
                os.close(pidfd)
            except OSError:
                pass
        for fd in (result_fd, control_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class _WindowsJob:
    """Minimal kill-on-close Windows Job Object wrapper using only ctypes."""

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    CREATE_SUSPENDED = 0x00000004
    ERROR_MORE_DATA = 234
    SYNCHRONIZE = 0x00100000
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are available only on Windows")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self.kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        self.ntdll.NtResumeProcess.restype = ctypes.c_long

        self.handle = self.kernel32.CreateJobObjectW(None, None)
        self.root_pid: int | None = None
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        information.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel32.SetInformationJobObject(
            self.handle,
            self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.kernel32.CloseHandle(self.handle)
            self.handle = None
            raise error

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        process_handle = self.wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
        if not self.kernel32.AssignProcessToJobObject(self.handle, process_handle):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        self.root_pid = int(process.pid)
        status = int(self.ntdll.NtResumeProcess(process_handle))
        if status != 0:
            raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")

    def active_process_ids(self) -> list[int]:
        pointer_size = self.ctypes.sizeof(self.ctypes.c_size_t)
        capacity = 64
        while capacity <= 4096:
            size = 8 + pointer_size * capacity
            buffer = self.ctypes.create_string_buffer(size)
            returned = self.wintypes.DWORD()
            okay = self.kernel32.QueryInformationJobObject(
                self.handle,
                self.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                buffer,
                size,
                self.ctypes.byref(returned),
            )
            if okay:
                count = self.ctypes.c_uint32.from_buffer_copy(buffer.raw[4:8]).value
                array_type = self.ctypes.c_size_t * count
                values = array_type.from_buffer_copy(buffer.raw[8 : 8 + pointer_size * count])
                return [int(value) for value in values]
            error = self.ctypes.get_last_error()
            if error != self.ERROR_MORE_DATA:
                raise self.ctypes.WinError(error)
            capacity *= 2
        raise OSError("Windows Job Object process list exceeded the fixed safety bound")

    def _wait_for_pids(self, process_ids: Sequence[int]) -> tuple[bool, str | None]:
        deadline = time.monotonic() + PROCESS_TREE_KILL_SECONDS
        for process_id in process_ids:
            handle = self.kernel32.OpenProcess(
                self.SYNCHRONIZE | self.PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                process_id,
            )
            if not handle:
                continue
            try:
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                result = int(self.kernel32.WaitForSingleObject(handle, remaining_ms))
                if result == self.WAIT_TIMEOUT:
                    return False, "Windows Job Object member remained alive after kill-on-close"
                if result != self.WAIT_OBJECT_0:
                    return False, f"Windows process wait failed with result={result}"
            finally:
                self.kernel32.CloseHandle(handle)
        return True, None

    def close_and_kill(self) -> tuple[bool, int, str | None]:
        if not self.handle:
            return False, 0, "Windows Job Object handle was already closed"
        try:
            process_ids = self.active_process_ids()
        except OSError as exc:
            process_ids = []
            query_error = f"Windows Job Object membership query failed: {type(exc).__name__}"
        else:
            query_error = None
        descendant_count = len(
            [process_id for process_id in process_ids if process_id != self.root_pid]
        )
        handle = self.handle
        self.handle = None
        if not self.kernel32.CloseHandle(handle):
            return False, descendant_count, "Windows Job Object close failed"
        wait_ok, wait_error = self._wait_for_pids(process_ids)
        if query_error:
            return False, descendant_count, query_error
        if not wait_ok:
            return False, descendant_count, wait_error
        return True, descendant_count, None

    def close_without_members(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


class TrustedBashLease:
    """Hold a non-write/non-delete-shared handle to one trusted Git Bash file."""

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

    def __init__(
        self,
        bash_path: str,
        git_path: str,
        *,
        approved_git_roots: Sequence[Path] = (),
    ) -> None:
        if os.name != "nt":
            raise OSError("trusted Bash leases are Windows-only")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        self.info_type = BY_HANDLE_FILE_INFORMATION
        self.kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.GetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        )
        self.kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.invalid_handle_value = ctypes.c_void_p(-1).value

        path = Path(bash_path)
        okay, reason = _secure_regular_file(path)
        if not okay:
            raise OSError(f"trusted Git Bash lease rejected the executable: {reason}")
        git_root, root_error = _trusted_git_installation_root(Path(git_path))
        if git_root is None:
            raise OSError(root_error or "trusted Git root is unavailable")
        if approved_git_roots and not any(
            _authority_paths_equal(
                git_root.resolve(strict=True),
                approved_root.resolve(strict=True),
                windows=True,
            )
            for approved_root in approved_git_roots
        ):
            raise OSError("trusted Git root is not the approved installation root")
        canonical = path.resolve(strict=True)
        if not _authority_path_is_within(canonical, git_root.resolve(strict=True), windows=True):
            raise OSError("trusted Git Bash escapes its Git installation root")
        if _trusted_git_bash_candidate_position(canonical, git_root, windows=True) is None:
            raise OSError("trusted Git Bash is not at a fixed installation candidate position")
        if int(getattr(path.lstat(), "st_nlink", 1)) != 1:
            raise OSError("trusted Git Bash has another hardlink name")
        if not _non_reparse_directory_chain(canonical.parent, git_root):
            raise OSError("trusted Git Bash directory chain contains a reparse point")

        handle = self.kernel32.CreateFileW(
            str(canonical),
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if not handle or int(handle) == self.invalid_handle_value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = handle
        self.path = str(canonical)
        self.git_path = str(Path(git_path).resolve(strict=True))
        self.trusted_git_root = str(git_root.resolve(strict=True))
        try:
            self._initial_info = self._information(self.handle)
            if self._initial_info["reparsePoint"]:
                raise OSError("trusted Git Bash handle resolves to a reparse point")
            if self._initial_info["links"] != 1:
                raise OSError("trusted Git Bash handle has another hardlink name")
            self.expected_sha256 = _sha256_file(canonical)
            self.identity = {
                "canonicalPath": self.path,
                "trustedGitRoot": self.trusted_git_root,
                **self._initial_info,
                "sha256": self.expected_sha256,
            }
            okay, verify_error = self.verify()
            if not okay:
                raise OSError(verify_error or "trusted Git Bash lease verification failed")
        except Exception:
            self.close()
            raise

    @staticmethod
    def _filetime(value: Any) -> str:
        return str((int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime))

    def _information(self, handle: Any) -> dict[str, Any]:
        information = self.info_type()
        if not self.kernel32.GetFileInformationByHandle(handle, self.ctypes.byref(information)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        attributes = int(information.dwFileAttributes)
        return {
            "size": (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow),
            "volumeSerial": str(int(information.dwVolumeSerialNumber)),
            "fileIndex": str((int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)),
            "links": int(information.nNumberOfLinks),
            "creationTime": self._filetime(information.ftCreationTime),
            "writeTime": self._filetime(information.ftLastWriteTime),
            "reparsePoint": bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)),
        }

    def _open_path_identity(self) -> dict[str, Any]:
        handle = self.kernel32.CreateFileW(
            self.path,
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if not handle or int(handle) == self.invalid_handle_value:
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        try:
            return self._information(handle)
        finally:
            self.kernel32.CloseHandle(handle)

    def verify(self) -> tuple[bool, str | None]:
        if not getattr(self, "handle", None):
            return False, "trusted Git Bash lease handle is closed"
        try:
            path = Path(self.path)
            okay, reason = _secure_regular_file(path)
            if not okay:
                return False, f"trusted Git Bash path drifted: {reason}"
            if str(path.resolve(strict=True)) != self.path:
                return False, "trusted Git Bash canonical path drifted"
            git_root, root_error = _trusted_git_installation_root(Path(self.git_path))
            if git_root is None or str(git_root.resolve(strict=True)) != self.trusted_git_root:
                return False, root_error or "trusted Git Bash installation relationship drifted"
            if (
                _trusted_git_bash_candidate_position(path, git_root, windows=True) is None
                or not _non_reparse_directory_chain(path.parent, git_root)
            ):
                return False, "trusted Git Bash installation topology drifted"
            handle_info = self._information(self.handle)
            path_info = self._open_path_identity()
            if handle_info != self._initial_info or path_info != self._initial_info:
                return False, "trusted Git Bash stable file identity drifted"
            if _sha256_file(path) != self.expected_sha256:
                return False, "trusted Git Bash SHA-256 drifted"
            if self.identity != {
                "canonicalPath": self.path,
                "trustedGitRoot": self.trusted_git_root,
                **self._initial_info,
                "sha256": self.expected_sha256,
            }:
                return False, "trusted Git Bash recorded lease identity drifted"
        except OSError as exc:
            return False, f"trusted Git Bash lease verification failed: {type(exc).__name__}"
        return True, None

    def validated_identity(self) -> dict[str, Any]:
        """Snapshot physical authority only while the locally held lease verifies."""

        okay, error = self.verify()
        if not okay:
            raise OSError(error or "trusted Git Bash lease verification failed")
        return dict(self.identity)

    def close(self) -> None:
        handle = getattr(self, "handle", None)
        if handle:
            self.kernel32.CloseHandle(handle)
            self.handle = None

    def __del__(self) -> None:  # pragma: no cover - last-resort OS handle cleanup
        try:
            self.close()
        except Exception:
            pass


def _execute_linux_supervised(
    command_id: str,
    command_class: str,
    argv: Sequence[str],
    *,
    timeout: int,
    env: Mapping[str, str],
    include_preview: bool,
    required: bool,
    cwd: Path,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    max_line_bytes: int,
    executable_lease: Any | None,
    stdin_data: bytes | None,
    logical_argv: Sequence[str] | None,
    execution_input_mode: str,
    process_started_hook: Any | None,
) -> CommandCapture:
    start = time.monotonic()
    containment = "linux-subreaper-pidfd-proc-supervisor"
    try:
        ensure_main_linux_subreaper()
        _pidfd_capability_check()
    except OSError as exc:
        return CommandCapture(
            command_id=command_id,
            command_class=command_class,
            argv=list(argv),
            executed=False,
            exit_code=None,
            duration_seconds=time.monotonic() - start,
            stdout="",
            stderr="",
            required=required,
            error=f"process containment unavailable: {type(exc).__name__}: {exc}",
            containment=containment,
            process_tree_status="setup-failed",
            process_tree_error="Linux subreaper/pidfd/proc setup failed",
        )
    if executable_lease is not None:
        lease_ok, lease_error = executable_lease.verify()
        if not lease_ok:
            return CommandCapture(
                command_id=command_id,
                command_class=command_class,
                argv=list(argv),
                executed=False,
                exit_code=None,
                duration_seconds=time.monotonic() - start,
                stdout="",
                stderr="",
                required=required,
                error=lease_error or "trusted executable lease verification failed",
                containment=containment,
                process_tree_status="setup-failed",
            )
    stdout_sink = _BoundedStream(max_stdout_bytes, max_line_bytes)
    stderr_sink = _BoundedStream(max_stderr_bytes, max_line_bytes)
    limit_event = threading.Event()
    result_buffer = bytearray()
    result_error: list[str] = []
    stdin_error: list[str] = []

    stdin_r = stdin_w = -1
    if stdin_data is not None:
        stdin_r, stdin_w = os.pipe()
    stdout_r, stdout_w = os.pipe()
    stderr_r, stderr_w = os.pipe()
    result_r, result_w = os.pipe()
    control_r, control_w = os.pipe()
    config = {
        "argv": [str(value) for value in argv],
        "cwd": str(cwd.resolve(strict=True)),
        "environment": dict(env),
    }
    supervisor_environment = dict(env)
    supervisor_environment["CI_LINUX_SUPERVISOR_CONFIG"] = json.dumps(
        config,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    pass_fds = [stdout_w, stderr_w, result_w, control_r]
    if stdin_r >= 0:
        pass_fds.append(stdin_r)
    supervisor_argv = [
        str(Path(sys.executable).resolve(strict=True)),
        "-B",
        str(Path(__file__).resolve(strict=True)),
        "--internal-linux-containment-supervisor",
        str(stdin_r),
        str(stdout_w),
        str(stderr_w),
        str(result_w),
        str(control_r),
    ]
    try:
        supervisor = subprocess.Popen(
            supervisor_argv,
            cwd=cwd,
            env=supervisor_environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=tuple(pass_fds),
        )
    except (OSError, ValueError) as exc:
        for fd in {stdin_r, stdin_w, stdout_r, stdout_w, stderr_r, stderr_w, result_r, result_w, control_r, control_w}:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        return CommandCapture(
            command_id=command_id,
            command_class=command_class,
            argv=list(argv),
            executed=False,
            exit_code=None,
            duration_seconds=time.monotonic() - start,
            stdout="",
            stderr="",
            required=required,
            error=f"Linux containment supervisor launch failed: {type(exc).__name__}: {exc}",
            containment=containment,
            process_tree_status="setup-failed",
        )
    for fd in (stdin_r, stdout_w, stderr_w, result_w, control_r):
        if fd >= 0:
            os.close(fd)
    containment_identity = f"{containment}:{supervisor.pid}:{time.monotonic_ns()}"
    _register_containment(containment_identity)

    def consume(fd: int, sink: _BoundedStream) -> None:
        try:
            while True:
                chunk = os.read(fd, OUTPUT_READ_CHUNK_BYTES)
                if not chunk:
                    break
                sink.feed(chunk)
                if sink.limit_reason:
                    limit_event.set()
                    break
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def read_result() -> None:
        try:
            while len(result_buffer) <= 1_048_576:
                chunk = os.read(result_r, 16_384)
                if not chunk:
                    return
                result_buffer.extend(chunk)
            result_error.append("Linux supervisor result protocol exceeded its byte limit")
        except OSError as exc:
            result_error.append(f"Linux supervisor result read failed: {type(exc).__name__}")
        finally:
            try:
                os.close(result_r)
            except OSError:
                pass

    def write_stdin() -> None:
        assert stdin_data is not None and stdin_w >= 0
        try:
            view = memoryview(stdin_data)
            offset = 0
            while offset < len(view):
                written = os.write(stdin_w, view[offset : offset + OUTPUT_READ_CHUNK_BYTES])
                if written <= 0:
                    raise OSError("supervised stdin accepted no bytes")
                offset += written
        except (BrokenPipeError, OSError) as exc:
            stdin_error.append(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                os.close(stdin_w)
            except OSError:
                pass

    threads = [
        threading.Thread(target=consume, args=(stdout_r, stdout_sink), daemon=True),
        threading.Thread(target=consume, args=(stderr_r, stderr_sink), daemon=True),
        threading.Thread(target=read_result, daemon=True),
    ]
    if stdin_data is not None:
        threads.append(threading.Thread(target=write_stdin, daemon=True))
    for thread in threads:
        thread.start()
    hook_error: str | None = None
    if process_started_hook is not None:
        try:
            process_started_hook(supervisor)
        except Exception as exc:
            hook_error = f"process-start hook failed: {type(exc).__name__}: {exc}"
    deadline = start + timeout
    timed_out = False
    output_limited = False
    cancellation_sent = False
    try:
        while supervisor.poll() is None:
            if hook_error is not None:
                break
            if limit_event.wait(0.02):
                output_limited = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
        if supervisor.poll() is None:
            try:
                os.write(control_w, b"X")
                cancellation_sent = True
            except OSError:
                pass
        try:
            supervisor.wait(timeout=LINUX_CONTAINMENT_SETTLE_SECONDS + PROCESS_TREE_KILL_SECONDS)
        except subprocess.TimeoutExpired:
            supervisor.kill()
            supervisor.wait(timeout=PROCESS_TREE_KILL_SECONDS)
            result_error.append("Linux containment supervisor did not reach its cleanup fixed point")
    finally:
        try:
            os.close(control_w)
        except OSError:
            pass
        _unregister_containment(containment_identity)
    for thread in threads:
        thread.join(timeout=PROCESS_TREE_KILL_SECONDS)
    if any(thread.is_alive() for thread in threads):
        result_error.append("supervisor pipe worker did not terminate")
    messages: list[dict[str, Any]] = []
    if not result_error:
        try:
            for line in bytes(result_buffer).splitlines():
                value = strict_json_loads(line, label="Linux supervisor result")
                if not isinstance(value, dict):
                    raise ValueError("result record is not an object")
                messages.append(value)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            result_error.append(f"Linux supervisor result protocol is invalid: {type(exc).__name__}")
    started = next((item for item in messages if item.get("event") == "started"), None)
    final = next((item for item in reversed(messages) if item.get("event") == "final"), None)
    if final is None:
        result_error.append("Linux containment supervisor omitted its final record")
        final = {}
    for key in (
        "descendantsObserved",
        "descendantsReaped",
        "descendantsSurviving",
    ):
        if type(final.get(key)) is not int or not 0 <= int(final.get(key, -1)) <= 4096:
            result_error.append(f"Linux containment supervisor returned invalid {key}")
    disposition = final.get("containmentDisposition")
    if disposition not in {
        "no-descendants",
        "natural-exit-reaped",
        "forced-terminated",
        "survivor",
        "unknown-ancestry",
    }:
        result_error.append("Linux containment supervisor returned invalid containmentDisposition")
    cleanup_ok = (
        bool(final.get("cleanupOk"))
        and final.get("cleanupComplete") is True
        and final.get("descendantsSurviving") == 0
        and disposition not in {"survivor", "unknown-ancestry"}
        and not result_error
        and not stdin_error
        and hook_error is None
    )
    process_tree_error = str(final.get("error") or "") or None
    if result_error or stdin_error or hook_error:
        extra = "; ".join([*result_error, *stdin_error, *([hook_error] if hook_error else [])])
        process_tree_error = ((process_tree_error + "; ") if process_tree_error else "") + extra
    output_limited = output_limited or bool(stdout_sink.limit_reason or stderr_sink.limit_reason)
    if timed_out:
        exit_code = 124
        error = f"command timed out after {timeout} seconds"
    elif output_limited:
        exit_code = 125
        reason_parts = [part for part in (stdout_sink.limit_reason, stderr_sink.limit_reason) if part]
        error = "OUTPUT-LIMIT-EXCEEDED: " + "; ".join(reason_parts)
    else:
        root_exit = final.get("rootExitCode")
        exit_code = root_exit if type(root_exit) is int else PROCESS_TREE_FAILURE_EXIT
        error = None
    if not cleanup_ok:
        if not timed_out and not output_limited:
            exit_code = PROCESS_TREE_FAILURE_EXIT
        error = ((error + "; ") if error else "") + "PROCESS-TREE-ERROR: " + (
            process_tree_error or "unknown Linux supervisor failure"
        )
    if executable_lease is not None:
        lease_ok, lease_error = executable_lease.verify()
        if not lease_ok:
            cleanup_ok = False
            exit_code = PROCESS_TREE_FAILURE_EXIT
            process_tree_error = lease_error or "trusted executable lease identity drifted"
            error = ((error + "; ") if error else "") + f"EXECUTABLE-LEASE-ERROR: {process_tree_error}"
    return CommandCapture(
        command_id=command_id,
        command_class=command_class,
        argv=list(argv),
        executed=bool(final.get("commandStarted")) or started is not None,
        exit_code=exit_code,
        duration_seconds=time.monotonic() - start,
        stdout=stdout_sink.text(),
        stderr=stderr_sink.text(),
        required=required,
        stdout_raw=None if output_limited else stdout_sink.data(),
        stderr_raw=None if output_limited else stderr_sink.data(),
        stdout_byte_limit=max_stdout_bytes,
        stderr_byte_limit=max_stderr_bytes,
        error=error,
        include_preview=include_preview,
        timed_out=timed_out,
        output_limited=output_limited,
        limit_reason="; ".join(
            part for part in (stdout_sink.limit_reason, stderr_sink.limit_reason) if part
        ) or None,
        stdout_bytes=stdout_sink.total_bytes,
        stderr_bytes=stderr_sink.total_bytes,
        containment=containment,
        process_tree_status="contained-clean" if cleanup_ok else "cleanup-failed",
        descendants_terminated=int(final.get("descendantsTerminated", 0) or 0),
        descendants_observed=int(final.get("descendantsObserved", 0) or 0),
        descendants_reaped=int(final.get("descendantsReaped", 0) or 0),
        descendants_surviving=int(final.get("descendantsSurviving", 0) or 0),
        containment_disposition=(
            str(disposition) if isinstance(disposition, str) else "unknown-ancestry"
        ),
        process_tree_error=process_tree_error,
        logical_argv=list(logical_argv) if logical_argv is not None else list(argv),
        execution_input_mode=execution_input_mode,
        execution_input_size=len(stdin_data) if stdin_data is not None else None,
        execution_input_sha256=(
            hashlib.sha256(stdin_data).hexdigest() if stdin_data is not None else None
        ),
    )


def run_linux_containment_live_self_test(
    *,
    python_executable: str,
    environment: Mapping[str, str],
    temp_root: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Exercise setsid/double-fork/orphan escapes before artifact acceptance."""

    if not sys.platform.startswith("linux"):
        return [], ["Linux live containment self-test requested on a non-Linux platform"]
    normal_codes = {
        "setsid-escape": "import os,sys,time\np=os.fork()\nif p==0:\n os.setsid(); time.sleep(.6); open(sys.argv[1],'w').write('escape'); os._exit(0)\nos._exit(0)",
        "double-fork-escape": "import os,sys,time\np=os.fork()\nif p==0:\n q=os.fork()\n if q==0:\n  os.setsid(); time.sleep(.6); open(sys.argv[1],'w').write('double'); os._exit(0)\n os._exit(0)\nos._exit(0)",
        "setsid-sleeping-grandchild": "import os,sys,time\np=os.fork()\nif p==0:\n os.setsid(); q=os.fork()\n if q==0:\n  time.sleep(.6); open(sys.argv[1],'w').write('grandchild'); os._exit(0)\n os._exit(0)\nos._exit(0)",
        "double-fork-sentinel": "import os,sys,time\nif os.fork()==0:\n if os.fork()==0:\n  time.sleep(.6); open(sys.argv[1],'w').write('sentinel'); os._exit(0)\n os._exit(0)\nos._exit(0)",
        "parent-exits-first": "import os,sys,time\nif os.fork()==0:\n time.sleep(.6); open(sys.argv[1],'w').write('orphan'); os._exit(0)\nos._exit(0)",
        "sigterm-ignored": "import os,signal,sys,time\nif os.fork()==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(.6); open(sys.argv[1],'w').write('ignored'); os._exit(0)\nos._exit(0)",
        "rapid-fork-exit": "import os\nfor _ in range(32):\n p=os.fork()\n if p==0: os._exit(0)\nos._exit(0)",
        "normal-success-daemon": "import os,sys,time\nif os.fork()==0:\n time.sleep(.6); open(sys.argv[1],'w').write('daemon'); os._exit(0)\nos._exit(0)",
    }
    scenarios: list[tuple[str, str, int, int, int]] = [
        (name, code, 5, MAX_STDOUT_BYTES, MAX_STDERR_BYTES)
        for name, code in normal_codes.items()
    ]
    timeout_code = "import os,signal,time\nif os.fork()==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30); os._exit(0)\ntime.sleep(30)"
    scenarios.append(("timeout-daemon", timeout_code, 1, MAX_STDOUT_BYTES, MAX_STDERR_BYTES))
    stdout_code = "import os,sys,time\nif os.fork()==0:\n time.sleep(.6); open(sys.argv[1],'w').write('stdout'); os._exit(0)\nwhile True: os.write(1,b'x'*4096)"
    stderr_code = stdout_code.replace("os.write(1", "os.write(2").replace("'stdout'", "'stderr'")
    scenarios.append(("stdout-limit-daemon", stdout_code, 5, 4096, MAX_STDERR_BYTES))
    scenarios.append(("stderr-limit-daemon", stderr_code, 5, MAX_STDOUT_BYTES, 4096))
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    sentinels: list[Path] = []
    for name, code, timeout, stdout_limit, stderr_limit in scenarios:
        sentinel = temp_root / f"linux-containment-{name}.sentinel"
        sentinels.append(sentinel)
        capture = execute_command(
            f"linux-containment-self-test:{name}",
            "linux-containment-live-self-test",
            [python_executable, "-B", "-c", code, str(sentinel)],
            timeout=timeout,
            env=environment,
            include_preview=False,
            required=True,
            cwd=temp_root,
            max_stdout_bytes=stdout_limit,
            max_stderr_bytes=stderr_limit,
        )
        expected_exit = 124 if name == "timeout-daemon" else 125 if name in {"stdout-limit-daemon", "stderr-limit-daemon"} else 0
        passed = (
            capture.executed
            and capture.exit_code == expected_exit
            and capture.process_tree_status == "contained-clean"
            and capture.containment == "linux-subreaper-pidfd-proc-supervisor"
        )
        results.append(
            {
                "scenario": name,
                "status": "pass" if passed else "fail",
                "exitCode": capture.exit_code,
                "processTreeStatus": capture.process_tree_status,
                "descendantsTerminated": capture.descendants_terminated,
                "descendantsObserved": capture.descendants_observed,
                "descendantsReaped": capture.descendants_reaped,
                "descendantsSurviving": capture.descendants_surviving,
                "containmentDisposition": capture.containment_disposition,
            }
        )
        if not passed:
            errors.append(
                f"Linux containment scenario failed: {name} exit={capture.exit_code} "
                f"tree={capture.process_tree_status}"
            )
    time.sleep(0.8)
    for sentinel in sentinels:
        if sentinel.exists():
            errors.append(f"Linux containment survivor wrote sentinel: {sentinel.name}")
            try:
                sentinel.unlink()
            except OSError:
                pass
    if active_containment_count() != 0:
        errors.append("Linux containment active count did not return to zero")
    return results, sorted(set(errors))


def execute_command(
    command_id: str,
    command_class: str,
    argv: Sequence[str],
    *,
    timeout: int,
    env: Mapping[str, str] | None = None,
    include_preview: bool = True,
    required: bool = True,
    cwd: Path = REPO_ROOT,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_STDERR_BYTES,
    max_line_bytes: int = MAX_OUTPUT_LINE_BYTES,
    executable_lease: Any | None = None,
    stdin_data: bytes | None = None,
    logical_argv: Sequence[str] | None = None,
    execution_input_mode: str = "NONE",
    process_started_hook: Any | None = None,
) -> CommandCapture:
    """Execute without a shell inside an independently terminable process tree."""

    start = time.monotonic()
    stdout_sink = _BoundedStream(max_stdout_bytes, max_line_bytes)
    stderr_sink = _BoundedStream(max_stderr_bytes, max_line_bytes)
    limit_event = threading.Event()
    stdin_error: list[str] = []

    if executable_lease is not None:
        if not argv or str(Path(argv[0]).resolve()) != executable_lease.path:
            return CommandCapture(
                command_id=command_id,
                command_class=command_class,
                argv=list(argv),
                executed=False,
                exit_code=None,
                duration_seconds=time.monotonic() - start,
                stdout="",
                stderr="",
                required=required,
                error="trusted executable lease does not authorize argv[0]",
                containment="not-started",
                process_tree_status="setup-failed",
            )
        lease_ok, lease_error = executable_lease.verify()
        if not lease_ok:
            return CommandCapture(
                command_id=command_id,
                command_class=command_class,
                argv=list(argv),
                executed=False,
                exit_code=None,
                duration_seconds=time.monotonic() - start,
                stdout="",
                stderr="",
                required=required,
                error=lease_error or "trusted executable lease verification failed",
                containment="not-started",
                process_tree_status="setup-failed",
            )

    if sys.platform.startswith("linux"):
        effective_environment = (
            dict(env)
            if env is not None
            else child_process_environment(
                {"command": str(Path(argv[0]).resolve(strict=True))}
            )
        )
        return _execute_linux_supervised(
            command_id,
            command_class,
            argv,
            timeout=timeout,
            env=effective_environment,
            include_preview=include_preview,
            required=required,
            cwd=cwd,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            max_line_bytes=max_line_bytes,
            executable_lease=executable_lease,
            stdin_data=stdin_data,
            logical_argv=logical_argv,
            execution_input_mode=execution_input_mode,
            process_started_hook=process_started_hook,
        )
    if os.name != "nt":
        return CommandCapture(
            command_id=command_id,
            command_class=command_class,
            argv=list(argv),
            executed=False,
            exit_code=None,
            duration_seconds=time.monotonic() - start,
            stdout="",
            stderr="",
            required=required,
            error="process containment is unsupported on this platform",
            containment="not-started",
            process_tree_status="setup-failed",
        )

    def consume(pipe: Any, sink: _BoundedStream) -> None:
        try:
            while True:
                chunk = pipe.read(OUTPUT_READ_CHUNK_BYTES)
                if not chunk:
                    break
                sink.feed(chunk)
                if sink.limit_reason:
                    limit_event.set()
                    break
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def write_stdin(pipe: Any, data: bytes) -> None:
        try:
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                written = pipe.write(view[offset : offset + OUTPUT_READ_CHUNK_BYTES])
                if written is None:
                    written = 0
                if written <= 0:
                    raise OSError("child stdin accepted no bytes")
                offset += written
            pipe.flush()
        except (BrokenPipeError, OSError) as exc:
            stdin_error.append(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    windows_job: _WindowsJob | None = None
    containment = "windows-job-object" if os.name == "nt" else "unsupported-posix"
    if os.name == "nt":
        try:
            windows_job = _WindowsJob()
        except OSError as exc:
            return CommandCapture(
                command_id=command_id,
                command_class=command_class,
                argv=list(argv),
                executed=False,
                exit_code=None,
                duration_seconds=time.monotonic() - start,
                stdout="",
                stderr="",
                required=required,
                error=f"process containment unavailable: {type(exc).__name__}: {exc}",
                include_preview=include_preview,
                stdout_byte_limit=max_stdout_bytes,
                stderr_byte_limit=max_stderr_bytes,
                containment=containment,
                process_tree_status="setup-failed",
                process_tree_error=f"Windows Job Object setup failed: {type(exc).__name__}",
            )

    try:
        popen_kwargs: dict[str, Any] = {}
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | _WindowsJob.CREATE_SUSPENDED
        )
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else child_process_environment(
                {"command": str(Path(argv[0]).resolve(strict=True))}
            ),
            shell=False,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            **popen_kwargs,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        if windows_job is not None:
            windows_job.close_without_members()
        return CommandCapture(
            command_id=command_id,
            command_class=command_class,
            argv=list(argv),
            executed=False,
            exit_code=None,
            duration_seconds=time.monotonic() - start,
            stdout="",
            stderr="",
            required=required,
            error=f"{type(exc).__name__}: {exc}",
            include_preview=include_preview,
            stdout_byte_limit=max_stdout_bytes,
            stderr_byte_limit=max_stderr_bytes,
            containment=containment,
            process_tree_status="not-started",
        )

    if windows_job is not None:
        try:
            windows_job.assign_and_resume(process)
        except OSError as exc:
            try:
                process.kill()
                process.wait(timeout=PROCESS_TREE_KILL_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
            cleanup_ok, _terminated, cleanup_error = windows_job.close_and_kill()
            detail = f"Windows Job Object assignment/resume failed: {type(exc).__name__}"
            if not cleanup_ok and cleanup_error:
                detail += f"; {cleanup_error}"
            return CommandCapture(
                command_id=command_id,
                command_class=command_class,
                argv=list(argv),
                executed=False,
                exit_code=None,
                duration_seconds=time.monotonic() - start,
                stdout="",
                stderr="",
                required=required,
                error=detail,
                include_preview=include_preview,
                stdout_byte_limit=max_stdout_bytes,
                stderr_byte_limit=max_stderr_bytes,
                containment=containment,
                process_tree_status="setup-failed",
                process_tree_error=detail,
            )

    containment_identity = f"{containment}:{process.pid}:{time.monotonic_ns()}"
    _register_containment(containment_identity)

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=consume, args=(process.stdout, stdout_sink), daemon=True),
        threading.Thread(target=consume, args=(process.stderr, stderr_sink), daemon=True),
    )
    for reader in readers:
        reader.start()
    stdin_writer: threading.Thread | None = None
    if stdin_data is not None:
        assert process.stdin is not None
        stdin_writer = threading.Thread(
            target=write_stdin,
            args=(process.stdin, stdin_data),
            daemon=True,
        )
        stdin_writer.start()
    hook_error: str | None = None
    if process_started_hook is not None:
        try:
            process_started_hook(process)
        except Exception as exc:  # test/lease hooks must fail the command closed
            hook_error = f"process-start hook failed: {type(exc).__name__}: {exc}"

    deadline = start + timeout
    timed_out = False
    output_limited = False
    try:
        while process.poll() is None:
            if hook_error is not None:
                break
            if limit_event.wait(0.02):
                output_limited = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break

        assert windows_job is not None
        cleanup_ok, descendants_terminated, process_tree_error = windows_job.close_and_kill()
    finally:
        _unregister_containment(containment_identity)

    try:
        process.wait(timeout=PROCESS_TREE_KILL_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=PROCESS_TREE_KILL_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as exc:
            cleanup_ok = False
            process_tree_error = (
                (process_tree_error + "; ") if process_tree_error else ""
            ) + f"direct parent reap failed: {type(exc).__name__}"
    for reader in readers:
        reader.join(timeout=PROCESS_TREE_KILL_SECONDS)
    if any(reader.is_alive() for reader in readers):
        cleanup_ok = False
        process_tree_error = (
            (process_tree_error + "; ") if process_tree_error else ""
        ) + "bounded output reader did not reach EOF after process-tree cleanup"
    if stdin_writer is not None:
        stdin_writer.join(timeout=PROCESS_TREE_KILL_SECONDS)
        if stdin_writer.is_alive():
            cleanup_ok = False
            stdin_error.append("bounded stdin writer did not finish")
    if hook_error is not None:
        cleanup_ok = False
        process_tree_error = ((process_tree_error + "; ") if process_tree_error else "") + hook_error
    if stdin_error:
        cleanup_ok = False
        process_tree_error = (
            (process_tree_error + "; ") if process_tree_error else ""
        ) + "STDIN-ERROR: " + "; ".join(stdin_error)

    output_limited = output_limited or bool(stdout_sink.limit_reason or stderr_sink.limit_reason)
    if timed_out:
        exit_code = 124
        error = f"command timed out after {timeout} seconds"
    elif output_limited:
        exit_code = 125
        reason_parts = [part for part in (stdout_sink.limit_reason, stderr_sink.limit_reason) if part]
        error = "OUTPUT-LIMIT-EXCEEDED: " + "; ".join(reason_parts)
    else:
        exit_code = process.returncode
        error = None
    if not cleanup_ok:
        if not timed_out and not output_limited:
            exit_code = PROCESS_TREE_FAILURE_EXIT
        cleanup_detail = process_tree_error or "unknown process-tree cleanup failure"
        error = ((error + "; ") if error else "") + f"PROCESS-TREE-ERROR: {cleanup_detail}"
    if executable_lease is not None:
        lease_ok, lease_error = executable_lease.verify()
        if not lease_ok:
            cleanup_ok = False
            exit_code = PROCESS_TREE_FAILURE_EXIT
            process_tree_error = lease_error or "trusted executable lease identity drifted"
            error = ((error + "; ") if error else "") + f"EXECUTABLE-LEASE-ERROR: {process_tree_error}"
    return CommandCapture(
        command_id=command_id,
        command_class=command_class,
        argv=list(argv),
        executed=True,
        exit_code=exit_code,
        duration_seconds=time.monotonic() - start,
        stdout=stdout_sink.text(),
        stderr=stderr_sink.text(),
        required=required,
        stdout_raw=None if output_limited else stdout_sink.data(),
        stderr_raw=None if output_limited else stderr_sink.data(),
        stdout_byte_limit=max_stdout_bytes,
        stderr_byte_limit=max_stderr_bytes,
        error=error,
        include_preview=include_preview,
        timed_out=timed_out,
        output_limited=output_limited,
        limit_reason="; ".join(
            part for part in (stdout_sink.limit_reason, stderr_sink.limit_reason) if part
        ) or None,
        stdout_bytes=stdout_sink.total_bytes,
        stderr_bytes=stderr_sink.total_bytes,
        containment=containment,
        process_tree_status="contained-clean" if cleanup_ok else "cleanup-failed",
        descendants_terminated=descendants_terminated,
        descendants_observed=descendants_terminated,
        descendants_reaped=descendants_terminated if cleanup_ok else 0,
        descendants_surviving=0 if cleanup_ok else descendants_terminated,
        containment_disposition=(
            "forced-terminated"
            if cleanup_ok and descendants_terminated
            else "no-descendants"
            if cleanup_ok
            else "unknown-ancestry"
        ),
        process_tree_error=process_tree_error,
        logical_argv=list(logical_argv) if logical_argv is not None else list(argv),
        execution_input_mode=execution_input_mode,
        execution_input_size=len(stdin_data) if stdin_data is not None else None,
        execution_input_sha256=(
            hashlib.sha256(stdin_data).hexdigest() if stdin_data is not None else None
        ),
    )


def canonical_internal_execution_argv(
    approved_python: str | Path,
    observed_python: str | Path,
    command_id: str,
) -> list[str]:
    """Bind in-process execution to the approved Python file identity."""

    try:
        approved = Path(approved_python).resolve(strict=True)
        observed = Path(observed_python).resolve(strict=True)
    except OSError as exc:
        raise ValueError("internal Python execution authority does not resolve") from exc
    for label, candidate in (("approved", approved), ("observed", observed)):
        okay, reason = _secure_regular_file(candidate)
        if not okay:
            raise ValueError(f"{label} internal Python authority is invalid: {reason}")
    if not _same_file_identity(approved, observed):
        raise ValueError("observed internal Python differs from approved file identity")
    return [str(approved), "<internal>", command_id]


def make_internal_result(
    command_id: str,
    command_class: str,
    passed: bool,
    detail: str,
    *,
    required: bool = True,
    execution_authority: str | Path = sys.executable,
    observed_execution_authority: str | Path = sys.executable,
) -> dict[str, Any]:
    safe_detail = sanitize_text(detail)
    empty_digest = hashlib.sha256(b"").hexdigest()
    actual_execution_argv = canonical_internal_execution_argv(
        execution_authority,
        observed_execution_authority,
        command_id,
    )
    return {
        "commandId": command_id,
        "commandClass": command_class,
        "executable": "internal",
        "required": required,
        "executed": True,
        "started": True,
        "setupFailure": False,
        "exitCode": 0 if passed else 1,
        "durationSeconds": 0.0,
        "executionDurationClass": "bounded",
        "timeoutStatus": "within-limit",
        "outputLimitStatus": "within-limit",
        "stdoutBytesObserved": len(detail.encode("utf-8", errors="replace")),
        "stderrBytesObserved": 0,
        "stdoutByteLimit": MAX_RECORDED_STREAM_BYTES,
        "stderrByteLimit": MAX_RECORDED_STREAM_BYTES,
        "containment": "internal",
        "processTreeStatus": "not-applicable",
        "descendantsTerminated": 0,
        "descendantsObserved": 0,
        "descendantsReaped": 0,
        "descendantsSurviving": 0,
        "containmentDisposition": "not-applicable",
        "actualExecutionArgv": actual_execution_argv,
        "actualExecutionInputMode": "NONE",
        "actualExecutionInputSize": None,
        "actualExecutionInputSha256": None,
        "stdoutSha256": empty_digest,
        "stderrSha256": empty_digest,
        "producerObservations": [],
        "producerObservationSetDigest": producer_observation_set_digest([]),
        "completedCommandClass": None,
        "executionInputs": [],
        "executionInputBundleDigest": None,
        "targetExecutionLease": None,
        "protectedTargetBundle": None,
        "parsedFailureSummary": {
            "status": "pass" if passed else "fail",
            "diagnostic": bounded_preview(safe_detail, max_lines=4, max_bytes=512),
        },
    }


class DuplicateJsonKeyError(ValueError):
    """Raised when a JSON object repeats a decoded member name."""


def _reject_duplicate_json_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _strict_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def strict_json_loads(
    source: str | bytes | bytearray,
    *,
    label: str = "JSON document",
    enforce_bounds: bool = True,
) -> Any:
    """Decode strict JSON, rejecting duplicate keys and non-finite numbers."""

    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
        if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            raise ValueError(f"{label}: JSON must not contain a BOM")
        text = raw.decode("utf-8", errors="strict")
    elif isinstance(source, str):
        if source.startswith("\ufeff"):
            raise ValueError(f"{label}: JSON must not contain a BOM")
        text = source
    else:
        raise TypeError(f"{label}: JSON source must be text or bytes")
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_json_pairs,
        parse_constant=_reject_json_constant,
        parse_float=_strict_json_float,
    )
    if enforce_bounds:
        numeric_errors = _bounded_evidence_json(value, label=label)
        if numeric_errors:
            raise ValueError("; ".join(numeric_errors))
    return value


def strict_json_load_file(path: Path, *, enforce_bounds: bool = True) -> Any:
    return strict_json_loads(
        path.read_bytes(),
        label=str(path),
        enforce_bounds=enforce_bounds,
    )


def read_json(path: Path) -> Any:
    """Compatibility name for the sole security-critical JSON file loader."""

    return strict_json_load_file(path)


def baseline_semantic_digest(collection: str, entry: Mapping[str, Any]) -> str:
    semantic = {"collection": collection}
    for field_name in BASELINE_SEMANTIC_FIELDS:
        semantic[field_name] = entry.get(field_name)
    canonical = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_text(canonical)


def validate_baseline_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["baseline root must be an object"]
    actual_top_level = set(document)
    missing = sorted(REQUIRED_BASELINE_FIELDS - actual_top_level)
    extra = sorted(actual_top_level - REQUIRED_BASELINE_FIELDS)
    if missing:
        errors.append(f"baseline missing top-level fields: {', '.join(missing)}")
    if extra:
        errors.append(f"baseline contains unknown top-level fields: {', '.join(extra)}")
    if document.get("documentKind") != "ieltmps-phase1-ci-baseline-v1":
        errors.append("unexpected baseline documentKind")
    if document.get("schemaVersion") != 1:
        errors.append("unsupported baseline schemaVersion")
    if document.get("baselineCommit") != BASELINE_COMMIT:
        errors.append("baselineCommit does not match the frozen checkpoint")
    if document.get("baselineTree") != BASELINE_TREE:
        errors.append("baselineTree does not match the frozen checkpoint")
    if document.get("checkpointTag") != CHECKPOINT_TAG:
        errors.append("checkpointTag does not match the frozen checkpoint")
    if document.get("policyVersion") != POLICY_VERSION:
        errors.append("policyVersion does not match the candidate-local policy map")
    if document.get("ratifiedCounts") != dict(RATIFIED_COUNTS):
        errors.append("ratifiedCounts do not match the exact 4/14/3/2/3 authority")
    # The ratified Phase 1 baseline predates the CI8 verifier-only download
    # boundary and is an immutable task input.  It must still match every
    # ratified pin exactly; the additional candidate-local download pin is
    # enforced by the exact workflow grammar and remains subject to the next
    # independent review.
    ratified_action_pins = {
        name: value
        for name, value in APPROVED_ACTIONS.items()
        if name != "actions/download-artifact"
    }
    if document.get("approvedActions") != ratified_action_pins:
        errors.append("approvedActions must exactly match the ratified Phase 1 action pins")

    hard_gates = document.get("hardGates")
    if not isinstance(hard_gates, list) or not hard_gates:
        errors.append("hardGates must be a non-empty array")
    else:
        gate_ids: list[Any] = []
        for index, item in enumerate(hard_gates):
            if not isinstance(item, dict) or set(item) != {"id", "description"}:
                errors.append(f"hardGates[{index}] must contain only id and description")
                continue
            gate_ids.append(item.get("id"))
            if not isinstance(item.get("description"), str) or not item["description"].strip():
                errors.append(f"hardGates[{index}].description must be a non-empty string")
        if tuple(gate_ids) != HARD_GATE_AUTHORITY:
            errors.append("hardGates must exactly match the candidate-local hard-gate map")

    collections = ("knownDebts", "expectedOmissions", "releaseOnlySkips")
    all_ids: list[str] = []
    for collection_name in collections:
        entries = document.get(collection_name)
        if not isinstance(entries, list):
            errors.append(f"{collection_name} must be an array")
            continue
        for index, entry in enumerate(entries):
            label = f"{collection_name}[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{label} must be an object")
                continue
            allowed_fields = REQUIRED_DEBT_FIELDS | {"currentCiDisposition"}
            unknown_fields = sorted(set(entry) - allowed_fields)
            if unknown_fields:
                errors.append(f"{label} contains unknown fields: {', '.join(unknown_fields)}")
            entry_missing = sorted(REQUIRED_DEBT_FIELDS - set(entry))
            if entry_missing:
                errors.append(f"{label} missing fields: {', '.join(entry_missing)}")
            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id:
                errors.append(f"{label}.id must be a non-empty string")
            else:
                all_ids.append(entry_id)
                expected_digest = BASELINE_SEMANTIC_AUTHORITY.get(entry_id)
                if expected_digest is None:
                    errors.append(f"{label}.id is not approved: {entry_id}")
                elif baseline_semantic_digest(collection_name, entry) != expected_digest:
                    errors.append(
                        f"{label} changes exact candidate-local collection/category/gate/class/scope/outcome/"
                        "signature/occurrence/platform/disposition/stage/security semantics"
                    )
            if not isinstance(entry.get("testOrPathScope"), str) or not entry.get("testOrPathScope"):
                errors.append(f"{label}.testOrPathScope must be a non-empty string")
            signatures = entry.get("allowedNormalizedSignature")
            if not isinstance(signatures, list) or not signatures:
                errors.append(f"{label}.allowedNormalizedSignature must be a non-empty array")
            else:
                for signature in signatures:
                    if not isinstance(signature, str) or not signature:
                        errors.append(f"{label} has an empty or non-string signature")
                    elif ".*" in signature or len(signature) > 256:
                        errors.append(f"{label} contains an unrestricted or oversized signature")
            maximum = entry.get("maximumOccurrences")
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
                errors.append(f"{label}.maximumOccurrences must be a positive integer")
            platforms = entry.get("platforms")
            if (
                not isinstance(platforms, list)
                or not platforms
                or any(value not in {"windows", "ubuntu", "all"} for value in platforms)
            ):
                errors.append(f"{label}.platforms contains an unsupported value")
            if not isinstance(entry.get("notes"), str) or not entry.get("notes", "").strip():
                errors.append(f"{label}.notes must be a non-empty string")
            expected_current = (
                "must-execute" if entry_id == "F-WINDOWS-BACKEND-COMPATIBILITY-RUNNER" else None
            )
            if entry.get("currentCiDisposition") != expected_current:
                errors.append(f"{label}.currentCiDisposition does not match the candidate-local disposition map")
    if len(all_ids) != len(set(all_ids)):
        errors.append("debt, omission, and release-only IDs must be globally unique")
    if set(all_ids) != set(BASELINE_SEMANTIC_AUTHORITY):
        missing_ids = sorted(set(BASELINE_SEMANTIC_AUTHORITY) - set(all_ids))
        extra_ids = sorted(set(all_ids) - set(BASELINE_SEMANTIC_AUTHORITY))
        errors.append(f"baseline ID set is not exact; missing={missing_ids} additional={extra_ids}")

    known_debts = document.get("knownDebts", [])
    category_counts: dict[str, int] = {}
    if isinstance(known_debts, list):
        for entry in known_debts:
            if isinstance(entry, dict):
                category = str(entry.get("category", ""))
                category_counts[category] = category_counts.get(category, 0) + 1
    expected_counts = {
        "product-or-packaging": 4,
        "validation-infrastructure": 14,
        "accepted-checkpoint-nonblocking": 3,
    }
    if category_counts != expected_counts:
        errors.append(
            "known-debt category counts must be exactly "
            "product-or-packaging=4, validation-infrastructure=14, "
            "accepted-checkpoint-nonblocking=3"
        )
    if isinstance(document.get("expectedOmissions"), list) and len(document["expectedOmissions"]) != 2:
        errors.append("expectedOmissions must contain exactly two entries")
    if isinstance(document.get("releaseOnlySkips"), list) and len(document["releaseOnlySkips"]) != 3:
        errors.append("releaseOnlySkips must contain exactly three entries")
    if document.get("observationalChecks") != []:
        errors.append("observationalChecks must be exactly empty in policy version 1.0.0")
    return sorted(set(errors))


class CanonicalYamlError(ValueError):
    pass


@dataclass(frozen=True)
class _YamlToken:
    line_number: int
    indent: int
    text: str
    block_value: str | None = None


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def _tokenize_canonical_yaml(text: str) -> list[_YamlToken]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if normalized.startswith("\ufeff"):
        raise CanonicalYamlError("UTF-8 BOM is unsupported")
    if "\x00" in normalized:
        raise CanonicalYamlError("NUL bytes are unsupported")
    raw_lines = normalized.split("\n")
    tokens: list[_YamlToken] = []
    index = 0
    while index < len(raw_lines):
        raw_line = raw_lines[index]
        line_number = index + 1
        prefix = raw_line[: len(raw_line) - len(raw_line.lstrip(" \t"))]
        if "\t" in prefix:
            raise CanonicalYamlError(f"line {line_number}: tabs may not be used for indentation")
        if "\t" in raw_line:
            raise CanonicalYamlError(f"line {line_number}: tabs are unsupported in the canonical subset")
        indent = len(prefix)
        if indent % 2:
            raise CanonicalYamlError(f"line {line_number}: indentation must use two-space increments")
        content = _strip_yaml_comment(raw_line[indent:])
        if not content:
            index += 1
            continue
        if re.search(r"(?:^|\s)(?:&|\*)[A-Za-z0-9_-]+(?:\s|$)", content) or content.startswith("<<:"):
            raise CanonicalYamlError(f"line {line_number}: anchors, aliases, and merge keys are forbidden")
        block_match = re.fullmatch(r"([^:]+):\s*\|", content)
        if block_match:
            block_lines: list[str] = []
            index += 1
            while index < len(raw_lines):
                candidate = raw_lines[index]
                candidate_prefix = candidate[: len(candidate) - len(candidate.lstrip(" \t"))]
                if "\t" in candidate_prefix:
                    raise CanonicalYamlError(f"line {index + 1}: tabs may not be used for indentation")
                candidate_indent = len(candidate_prefix)
                if candidate.strip() and candidate_indent <= indent:
                    break
                if candidate.strip() and candidate_indent < indent + 2:
                    raise CanonicalYamlError(f"line {index + 1}: malformed literal scalar indentation")
                block_lines.append(candidate[indent + 2 :] if len(candidate) >= indent + 2 else "")
                index += 1
            tokens.append(
                _YamlToken(
                    line_number=line_number,
                    indent=indent,
                    text=f"{block_match.group(1)}: |",
                    block_value="\n".join(block_lines).rstrip("\n"),
                )
            )
            continue
        tokens.append(_YamlToken(line_number, indent, content))
        index += 1
    return tokens


def _split_mapping_token(token: _YamlToken, text: str | None = None) -> tuple[str, str, str | None]:
    value = token.text if text is None else text
    if not value or value[0] in {'"', "'"}:
        raise CanonicalYamlError(f"line {token.line_number}: quoted mapping keys are forbidden")
    quote: str | None = None
    escaped = False
    colon_index = -1
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            quote = None if quote == character else character if quote is None else quote
            continue
        if character == ":" and quote is None:
            colon_index = index
            break
    if colon_index < 1:
        raise CanonicalYamlError(f"line {token.line_number}: expected a plain mapping key")
    key = value[:colon_index].strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
        raise CanonicalYamlError(f"line {token.line_number}: unsupported mapping key syntax: {key}")
    remainder = value[colon_index + 1 :].strip()
    block_value = token.block_value if remainder == "|" else None
    return key, remainder, block_value


def _parse_yaml_scalar(value: str, token: _YamlToken) -> str:
    if value.startswith(("[", "{")):
        raise CanonicalYamlError(f"line {token.line_number}: inline maps and sequences are forbidden")
    if value.startswith((">", "|")):
        raise CanonicalYamlError(f"line {token.line_number}: unsupported folded or literal scalar")
    if value.startswith("!"):
        raise CanonicalYamlError(f"line {token.line_number}: custom tags are forbidden")
    if re.search(r"(?:^|\s)(?:&|\*)[A-Za-z0-9_-]+(?:\s|$)", value):
        raise CanonicalYamlError(f"line {token.line_number}: anchors and aliases are forbidden")
    if value.startswith('"'):
        try:
            decoded = strict_json_loads(
                value,
                label=f"workflow scalar at line {token.line_number}",
            )
        except json.JSONDecodeError as exc:
            raise CanonicalYamlError(f"line {token.line_number}: invalid double-quoted scalar") from exc
        if not isinstance(decoded, str):
            raise CanonicalYamlError(f"line {token.line_number}: quoted scalar must decode to text")
        return decoded
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise CanonicalYamlError(f"line {token.line_number}: invalid single-quoted scalar")
        return value[1:-1].replace("''", "'")
    return value


def _parse_canonical_yaml_node(
    tokens: Sequence[_YamlToken], index: int, indent: int
) -> tuple[Any, int]:
    if index >= len(tokens) or tokens[index].indent != indent:
        line = tokens[index].line_number if index < len(tokens) else "EOF"
        raise CanonicalYamlError(f"line {line}: unexpected indentation")
    if tokens[index].text.startswith("- "):
        result_list: list[Any] = []
        while index < len(tokens) and tokens[index].indent == indent:
            token = tokens[index]
            if not token.text.startswith("- "):
                raise CanonicalYamlError(f"line {token.line_number}: mixed mapping and sequence")
            remainder = token.text[2:].strip()
            if not remainder:
                raise CanonicalYamlError(f"line {token.line_number}: empty sequence items are unsupported")
            if re.match(r"[A-Za-z_][A-Za-z0-9_-]*\s*:", remainder):
                key, scalar_text, block_value = _split_mapping_token(token, remainder)
                item: dict[str, Any] = {}
                if block_value is not None:
                    if key not in {"run", "path"}:
                        raise CanonicalYamlError(f"line {token.line_number}: literal scalar is not allowed for {key}")
                    item[key] = block_value
                    index += 1
                elif scalar_text:
                    item[key] = _parse_yaml_scalar(scalar_text, token)
                    index += 1
                else:
                    index += 1
                    if index < len(tokens) and tokens[index].indent > indent:
                        if tokens[index].indent != indent + 4:
                            raise CanonicalYamlError(f"line {tokens[index].line_number}: invalid nested sequence mapping")
                        item[key], index = _parse_canonical_yaml_node(tokens, index, indent + 4)
                    else:
                        item[key] = None
                if index < len(tokens) and tokens[index].indent == indent + 2:
                    continuation, index = _parse_canonical_yaml_node(tokens, index, indent + 2)
                    if not isinstance(continuation, dict):
                        raise CanonicalYamlError(f"line {tokens[index - 1].line_number}: sequence mapping continuation must be a mapping")
                    duplicates = set(item) & set(continuation)
                    if duplicates:
                        raise CanonicalYamlError(f"line {token.line_number}: duplicate key {sorted(duplicates)[0]}")
                    item.update(continuation)
                result_list.append(item)
            else:
                result_list.append(_parse_yaml_scalar(remainder, token))
                index += 1
            if index < len(tokens) and tokens[index].indent > indent:
                raise CanonicalYamlError(f"line {tokens[index].line_number}: unexpected sequence indentation")
        return result_list, index

    result: dict[str, Any] = {}
    while index < len(tokens) and tokens[index].indent == indent:
        token = tokens[index]
        if token.text.startswith("- "):
            raise CanonicalYamlError(f"line {token.line_number}: mixed sequence and mapping")
        key, scalar_text, block_value = _split_mapping_token(token)
        if key in result:
            raise CanonicalYamlError(f"line {token.line_number}: duplicate key {key}")
        if block_value is not None:
            if key not in {"run", "path"}:
                raise CanonicalYamlError(f"line {token.line_number}: literal scalar is not allowed for {key}")
            result[key] = block_value
            index += 1
        elif scalar_text:
            result[key] = _parse_yaml_scalar(scalar_text, token)
            index += 1
        else:
            index += 1
            if index < len(tokens) and tokens[index].indent > indent:
                if tokens[index].indent != indent + 2:
                    raise CanonicalYamlError(f"line {tokens[index].line_number}: invalid nested mapping indentation")
                result[key], index = _parse_canonical_yaml_node(tokens, index, indent + 2)
            else:
                result[key] = None
        if index < len(tokens) and tokens[index].indent > indent:
            raise CanonicalYamlError(f"line {tokens[index].line_number}: unexpected mapping indentation")
    return result, index


def parse_canonical_workflow_yaml(text: str) -> dict[str, Any]:
    tokens = _tokenize_canonical_yaml(text)
    if not tokens:
        raise CanonicalYamlError("workflow is empty")
    if tokens[0].indent != 0:
        raise CanonicalYamlError("top-level mapping must start at column zero")
    result, index = _parse_canonical_yaml_node(tokens, 0, 0)
    if index != len(tokens):
        raise CanonicalYamlError(f"line {tokens[index].line_number}: trailing unsupported syntax")
    if not isinstance(result, dict):
        raise CanonicalYamlError("workflow root must be a mapping")
    return result


EXACT_EVIDENCE_PATH_BLOCK = "\n".join(f".ci-results/{name}" for name in EVIDENCE_FILE_NAMES)
POLICY_COMMAND = "python -B developer/tests/ci/run_ci_foundation.py --profile policy"
SELF_TEST_COMMAND = "python -B developer/tests/ci/test_ci_foundation.py"
ALL_COMMAND = "python -B developer/tests/ci/run_ci_foundation.py --profile all"
PRODUCER_DEVELOPER_INSTALL_COMMAND = (
    "npm --prefix developer ci --ignore-scripts --no-audit --no-fund"
)
PRODUCER_BACKEND_INSTALL_COMMAND = (
    "npm --prefix backend ci --ignore-scripts --no-audit --no-fund"
)
LINUX_FRESH_DEVELOPER_INSTALL_COMMAND = (
    '"$CI_TRUSTED_NODE" "$CI_TRUSTED_NPM_ENTRY" --prefix developer ci '
    "--ignore-scripts --no-audit --no-fund"
)
LINUX_FRESH_BACKEND_INSTALL_COMMAND = (
    '"$CI_TRUSTED_NODE" "$CI_TRUSTED_NPM_ENTRY" --prefix backend ci '
    "--ignore-scripts --no-audit --no-fund"
)
WINDOWS_FRESH_DEVELOPER_INSTALL_COMMAND = (
    "& $env:CI_TRUSTED_NODE $env:CI_TRUSTED_NPM_ENTRY --prefix developer ci "
    "--ignore-scripts --no-audit --no-fund"
)
WINDOWS_FRESH_BACKEND_INSTALL_COMMAND = (
    "& $env:CI_TRUSTED_NODE $env:CI_TRUSTED_NPM_ENTRY --prefix backend ci "
    "--ignore-scripts --no-audit --no-fund"
)
LINUX_RUNTIME_CAPTURE = '''python_path="$pythonLocation/bin/python"
node_path="$(command -v node)"
npm_path="$(command -v npm)"
test -x "$python_path"
test -x "$node_path"
test -e "$npm_path"
printf 'CI_TRUSTED_PYTHON=%s\\n' "$(realpath "$python_path")" >> "$GITHUB_ENV"
printf 'CI_TRUSTED_NODE=%s\\n' "$(realpath "$node_path")" >> "$GITHUB_ENV"
printf 'CI_TRUSTED_NPM_ENTRY=%s\\n' "$(realpath "$npm_path")" >> "$GITHUB_ENV"'''
LINUX_RUNTIME_CAPTURE_FRESH = LINUX_RUNTIME_CAPTURE + '''
printf 'CI_FRESH_DEPENDENCY_INSTALL=1\\n' >> "$GITHUB_ENV"'''
WINDOWS_RUNTIME_CAPTURE = '''$pythonPath = (Resolve-Path -LiteralPath (Join-Path $env:pythonLocation 'python.exe')).Path
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw 'trusted Python is unavailable' }
$runtimeCapture = @'
import json, os, sys
from pathlib import Path
sys.path.insert(0, 'developer/tests/ci')
import run_ci_foundation as ci
source = dict(os.environ)
tools, errors = ci.resolve_trusted_tools({'node'}, source_environment=source)
if errors:
    raise SystemExit('trusted Node capture rejected by tool authority')
source['CI_TRUSTED_NODE'] = tools['node']
source['CI_TRUSTED_NPM_ENTRY'] = str(Path(tools['node']).parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js')
tools, errors = ci.resolve_trusted_tools({'node', 'npm'}, source_environment=source)
if errors:
    raise SystemExit('trusted Node/npm capture rejected by tool authority')
print(json.dumps({'node': tools['node'], 'npmEntry': tools['npm']}))
'@
$runtimeJson = & $pythonPath -B -c $runtimeCapture
if ($LASTEXITCODE -ne 0) { throw 'trusted Node/npm capture failed' }
$runtimePaths = $runtimeJson | ConvertFrom-Json
$nodePath = [string]$runtimePaths.node
$npmEntry = [string]$runtimePaths.npmEntry
if (-not (Test-Path -LiteralPath $nodePath -PathType Leaf)) { throw 'trusted Node is unavailable' }
if (-not (Test-Path -LiteralPath $npmEntry -PathType Leaf)) { throw 'trusted npm entry is unavailable' }
"CI_TRUSTED_PYTHON=$pythonPath" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"CI_TRUSTED_NODE=$nodePath" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"CI_TRUSTED_NPM_ENTRY=$npmEntry" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"CI_FRESH_DEPENDENCY_INSTALL=1" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8'''
LINUX_ABSENT_DEPENDENCY_ROOTS = '''test ! -e developer/node_modules
test ! -e backend/node_modules'''
WINDOWS_ABSENT_DEPENDENCY_ROOTS = '''if (Test-Path -LiteralPath 'developer/node_modules') { throw 'developer/node_modules was not fresh' }
if (Test-Path -LiteralPath 'backend/node_modules') { throw 'backend/node_modules was not fresh' }'''
FINAL_VERIFIER_COMMANDS = MappingProxyType(
    {
        "repository-policy": (
            '"$CI_TRUSTED_PYTHON" -B developer/tests/ci/run_ci_foundation.py '
            "--verify-evidence --expected-profile policy "
            "--expected-producer-job repository-policy-producer "
            "--expected-verifier-job repository-policy --expected-runner-os Linux "
            '--untrusted-evidence-root "$RUNNER_TEMP/ci-untrusted/repository-policy" '
            "--require-linux-containment-self-test"
        ),
        "ubuntu-canonical": (
            '"$CI_TRUSTED_PYTHON" -B developer/tests/ci/run_ci_foundation.py '
            "--verify-evidence --expected-profile all "
            "--expected-producer-job ubuntu-canonical-producer "
            "--expected-verifier-job ubuntu-canonical --expected-runner-os Linux "
            '--untrusted-evidence-root "$RUNNER_TEMP/ci-untrusted/ubuntu-canonical" '
            "--require-linux-containment-self-test --require-fresh-runtime-closure"
        ),
        "windows-compatibility": (
            "& $env:CI_TRUSTED_PYTHON -B developer/tests/ci/run_ci_foundation.py "
            "--verify-evidence --expected-profile all "
            "--expected-producer-job windows-compatibility-producer "
            "--expected-verifier-job windows-compatibility --expected-runner-os Windows "
            '--untrusted-evidence-root "$env:RUNNER_TEMP/ci-untrusted/windows-compatibility" '
            "--require-fresh-runtime-closure"
        ),
    }
)

STATIC_SUITE_RELATIVE_PATH = "developer/tests/ci/run_static_suite.py"

FINAL_RESULT_SCRIPT = '''echo "SELF-VALIDATOR TRUST: candidate-controlled" | tee -a "$GITHUB_STEP_SUMMARY"
echo "MERGE AUTHORIZATION: not provided by this workflow" | tee -a "$GITHUB_STEP_SUMMARY"
echo "INDEPENDENT REVIEW: required for CI trust-file changes" | tee -a "$GITHUB_STEP_SUMMARY"
if [[ "${{ needs.repository-policy.result }}" != "success" ]]; then
  echo "Repository policy verifier did not succeed."
  exit 1
fi
if [[ "${{ needs.ubuntu-canonical.result }}" != "success" ]]; then
  echo "Ubuntu canonical verifier did not succeed."
  exit 1
fi
if [[ "${{ needs.windows-compatibility.result }}" != "success" ]]; then
  echo "Windows compatibility verifier did not succeed."
  exit 1
fi
echo "Fresh candidate-local verifier jobs succeeded; merge authorization is not provided." >> "$GITHUB_STEP_SUMMARY"'''


def _walk_workflow_scalars(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_workflow_scalars(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_workflow_scalars(child, path + (str(index),))
    elif isinstance(value, str):
        yield path, value


def _canonical_expression(value: str) -> str:
    normalized = value.casefold()
    normalized = re.sub(r"\[\s*['\"]([a-z0-9_-]+)['\"]\s*\]", r".\1", normalized)
    return re.sub(r"\s+", "", normalized)


def _validate_scalar_token_policy(workflow: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    forbidden_environment_tokens = (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
    )
    for path, scalar in _walk_workflow_scalars(workflow):
        canonical = _canonical_expression(scalar)
        if "secrets." in canonical or "github.token" in canonical:
            errors.append(f"secret or GitHub token expression is forbidden at {'.'.join(path)}")
        for token in forbidden_environment_tokens:
            if re.search(rf"(?i)(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", scalar):
                errors.append(f"credential/control token {token} is forbidden at {'.'.join(path)}")
        if path and path[-1] == "run":
            for expression in re.findall(r"\$\{\{([\s\S]*?)\}\}", scalar):
                if _canonical_expression(expression).startswith("github."):
                    errors.append(f"attacker-controlled github context is forbidden in shell source at {'.'.join(path)}")
            for match in re.findall(r"(?i)\$env:GITHUB_[A-Z0-9_]+|\$GITHUB_[A-Z0-9_]+", scalar):
                if match.casefold() not in {
                    "$github_step_summary",
                    "$env:github_step_summary",
                    "$github_env",
                    "$env:github_env",
                }:
                    errors.append(f"GitHub control environment is forbidden in shell source: {match}")
    return errors


def _validate_run_command_policy(script: str, label: str) -> list[str]:
    errors: list[str] = []
    assigned_forbidden: set[str] = set()
    forbidden_command = re.compile(
        r"(?i)(?:^|\s)(?:git\s+push|docker(?:-compose)?\b|ssh\b|gpg\b|curl\b|wget\b|"
        r"npm\s+publish|npx\b|npm\s+install\b|gh\s+(?:release|repo|pr|issue|api)\b|"
        r"deploy(?:ment)?\b|release\s+publish|--force(?:-with-lease)?\b)"
    )
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        assignment = re.match(r"(?:\$)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?(.+?)['\"]?$", line)
        if assignment and forbidden_command.search(assignment.group(2)):
            assigned_forbidden.add(assignment.group(1).casefold())
        if re.match(r"(?i)^(?:&\s*)?(?:\$\{?[A-Za-z_]|%[A-Za-z_])", line):
            errors.append(f"environment-variable command indirection is forbidden in {label}")
        if re.search(r"(?i)\b(?:eval|invoke-expression|iex)\b", line):
            errors.append(f"dynamic command evaluation is forbidden in {label}")
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            errors.append(f"shell command cannot be canonically tokenized in {label}")
            continue
        if tokens and tokens[0].casefold() not in {"echo", "if", "fi", "}"}:
            if forbidden_command.search(" ".join(tokens)):
                errors.append(f"forbidden command in {label}: {tokens[0]}")
        for variable in assigned_forbidden:
            if re.search(rf"(?i)(?:^|[;&|]\s*)(?:&\s*)?\$\{{?{re.escape(variable)}\}}?\b", line):
                errors.append(f"forbidden command assigned and later executed through {variable} in {label}")
    return errors


def _require_exact_keys(mapping: Any, expected: Sequence[str], label: str, errors: list[str]) -> bool:
    if not isinstance(mapping, dict):
        errors.append(f"{label} must be a mapping")
        return False
    if tuple(mapping) != tuple(expected):
        errors.append(f"{label} keys/order must be exactly {list(expected)}")
        return False
    return True


def _validate_action_step(step: Mapping[str, Any], label: str, errors: list[str]) -> str | None:
    uses = step.get("uses")
    if not isinstance(uses, str) or "@" not in uses:
        return None
    repository, reference = uses.split("@", 1)
    approved = APPROVED_ACTIONS.get(repository)
    if approved is None:
        errors.append(f"unapproved action repository in {label}: {repository}")
        return repository
    if not re.fullmatch(r"[0-9a-f]{40}", reference):
        errors.append(f"action reference is not a 40-character lowercase SHA in {label}")
    elif reference != approved["sha"]:
        errors.append(f"action SHA does not match the approved pin in {label}")
    return repository


def _validate_workflow_steps(job_name: str, steps: Any, errors: list[str]) -> None:
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        errors.append(f"{job_name}.steps must be a sequence of mappings")
        return
    expected_names = {
        "repository-policy-producer": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Run CI foundation self-tests",
            "Generate untrusted policy evidence",
            "Upload untrusted policy evidence",
        ],
        "ubuntu-canonical-producer": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Install locked developer dependencies for untrusted production",
            "Install locked backend dependencies for untrusted production",
            "Generate untrusted Ubuntu evidence",
            "Upload untrusted Ubuntu evidence",
        ],
        "windows-compatibility-producer": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Install locked developer dependencies for untrusted production",
            "Install locked backend dependencies for untrusted production",
            "Generate untrusted Windows evidence",
            "Upload untrusted Windows evidence",
        ],
        "repository-policy": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Capture trusted runtime paths",
            "Download untrusted policy evidence",
            "Verify untrusted policy evidence by fresh replay",
        ],
        "ubuntu-canonical": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Capture trusted runtime paths",
            "Require initially absent dependency roots",
            "Install fresh locked developer dependencies",
            "Install fresh locked backend dependencies",
            "Download untrusted Ubuntu evidence",
            "Verify untrusted Ubuntu evidence by fresh replay",
        ],
        "windows-compatibility": [
            "Check out repository",
            "Set up Python",
            "Set up Node.js",
            "Capture trusted runtime paths",
            "Require initially absent dependency roots",
            "Install fresh locked developer dependencies",
            "Install fresh locked backend dependencies",
            "Download untrusted Windows evidence",
            "Verify untrusted Windows evidence by fresh replay",
        ],
        "final-result": [
            "Require every fresh verifier to succeed",
        ],
    }[job_name]
    names = [step.get("name") for step in steps]
    if names != expected_names:
        errors.append(f"{job_name} step graph/order is not exact")
    trusted_scripts = {
        LINUX_RUNTIME_CAPTURE,
        LINUX_RUNTIME_CAPTURE_FRESH,
        WINDOWS_RUNTIME_CAPTURE,
        LINUX_ABSENT_DEPENDENCY_ROOTS,
        WINDOWS_ABSENT_DEPENDENCY_ROOTS,
        LINUX_FRESH_DEVELOPER_INSTALL_COMMAND,
        LINUX_FRESH_BACKEND_INSTALL_COMMAND,
        WINDOWS_FRESH_DEVELOPER_INSTALL_COMMAND,
        WINDOWS_FRESH_BACKEND_INSTALL_COMMAND,
        *FINAL_VERIFIER_COMMANDS.values(),
        FINAL_RESULT_SCRIPT,
    }
    for index, step in enumerate(steps):
        unknown = set(step) - {"name", "id", "if", "shell", "uses", "with", "run"}
        if unknown:
            errors.append(f"{job_name} step contains unsupported keys: {sorted(unknown)}")
        if "run" in step:
            if not isinstance(step["run"], str):
                errors.append(f"{job_name} run step must be a scalar")
            elif step["run"] not in trusted_scripts:
                errors.extend(_validate_run_command_policy(step["run"], f"{job_name}:{step.get('name')}"))
        if "uses" in step:
            _validate_action_step(step, f"{job_name}:{step.get('name')}", errors)

    by_name = {str(step.get("name")): step for step in steps}
    if len(by_name) != len(steps):
        errors.append(f"{job_name} contains duplicate step names")
    checkout = by_name.get("Check out repository", {})
    if job_name != "final-result":
        if tuple(checkout) != ("name", "uses", "with") or checkout.get("with") != {
            "persist-credentials": "false",
            "fetch-depth": "1",
            "ref": "${{ github.sha }}",
        }:
            errors.append(f"{job_name} checkout must bind the exact github.sha without credentials")
        if checkout.get("uses") != f"actions/checkout@{APPROVED_ACTIONS['actions/checkout']['sha']}":
            errors.append(f"{job_name} checkout action is not exact")

    setup_python = by_name.get("Set up Python", {})
    if job_name != "final-result":
        if tuple(setup_python) != ("name", "uses", "with") or setup_python.get("with") != {"python-version": "3.12"}:
            errors.append(f"{job_name} Python setup is not exact")
        if setup_python.get("uses") != f"actions/setup-python@{APPROVED_ACTIONS['actions/setup-python']['sha']}":
            errors.append(f"{job_name} Python action pin is not exact")

    setup_node = by_name.get("Set up Node.js", {})
    if job_name != "final-result":
        if tuple(setup_node) != ("name", "uses", "with") or setup_node.get("with") != {"node-version": "24.20.0"}:
            errors.append(f"{job_name} Node setup is not exact")
        if setup_node.get("uses") != f"actions/setup-node@{APPROVED_ACTIONS['actions/setup-node']['sha']}":
            errors.append(f"{job_name} Node action pin is not exact")

    exact_simple_runs = {
        "Run CI foundation self-tests": SELF_TEST_COMMAND,
        "Generate untrusted policy evidence": POLICY_COMMAND,
        "Install locked developer dependencies for untrusted production": PRODUCER_DEVELOPER_INSTALL_COMMAND,
        "Install locked backend dependencies for untrusted production": PRODUCER_BACKEND_INSTALL_COMMAND,
        "Generate untrusted Ubuntu evidence": ALL_COMMAND,
        "Generate untrusted Windows evidence": ALL_COMMAND,
    }
    for name, run in exact_simple_runs.items():
        if name in by_name and by_name[name] != {"name": name, "run": run}:
            errors.append(f"{job_name}:{name} command/schema is not exact")

    upload_names = {
        "repository-policy-producer": ("Upload untrusted policy evidence", "repository-policy"),
        "ubuntu-canonical-producer": ("Upload untrusted Ubuntu evidence", "ubuntu-canonical"),
        "windows-compatibility-producer": ("Upload untrusted Windows evidence", "windows-compatibility"),
    }
    if job_name in upload_names:
        step_name, authority_name = upload_names[job_name]
        artifact_name = WORKFLOW_JOB_PROFILE_AUTHORITY[authority_name]["artifactIdentity"]
        expected_upload = {
            "name": step_name,
            "if": "${{ always() }}",
            "uses": f"actions/upload-artifact@{APPROVED_ACTIONS['actions/upload-artifact']['sha']}",
            "with": {
                "name": artifact_name,
                "path": EXACT_EVIDENCE_PATH_BLOCK,
                "if-no-files-found": "error",
                "retention-days": "7",
            },
        }
        if by_name.get(step_name) != expected_upload:
            errors.append(f"{job_name} untrusted artifact upload must name exactly five evidence files")
        if any("verify" in str(name).casefold() for name in names):
            errors.append(f"{job_name} producer must not verify evidence before upload")

    verifier_downloads = {
        "repository-policy": "Download untrusted policy evidence",
        "ubuntu-canonical": "Download untrusted Ubuntu evidence",
        "windows-compatibility": "Download untrusted Windows evidence",
    }
    if job_name in verifier_downloads:
        authority = WORKFLOW_JOB_PROFILE_AUTHORITY[job_name]
        download_name = verifier_downloads[job_name]
        expected_download = {
            "name": download_name,
            "uses": f"actions/download-artifact@{APPROVED_ACTIONS['actions/download-artifact']['sha']}",
            "with": {
                "name": authority["artifactIdentity"],
                "path": authority["evidenceRoot"],
            },
        }
        if by_name.get(download_name) != expected_download:
            errors.append(f"{job_name} untrusted artifact source/name/path is not exact")
        expected_capture = (
            WINDOWS_RUNTIME_CAPTURE
            if job_name == "windows-compatibility"
            else LINUX_RUNTIME_CAPTURE_FRESH
            if job_name == "ubuntu-canonical"
            else LINUX_RUNTIME_CAPTURE
        )
        expected_shell = "pwsh" if job_name == "windows-compatibility" else "bash"
        if by_name.get("Capture trusted runtime paths") != {
            "name": "Capture trusted runtime paths",
            "shell": expected_shell,
            "run": expected_capture,
        }:
            errors.append(f"{job_name} trusted runtime-path capture is not exact")
        if job_name in {"ubuntu-canonical", "windows-compatibility"}:
            absent = WINDOWS_ABSENT_DEPENDENCY_ROOTS if job_name == "windows-compatibility" else LINUX_ABSENT_DEPENDENCY_ROOTS
            developer_install = WINDOWS_FRESH_DEVELOPER_INSTALL_COMMAND if job_name == "windows-compatibility" else LINUX_FRESH_DEVELOPER_INSTALL_COMMAND
            backend_install = WINDOWS_FRESH_BACKEND_INSTALL_COMMAND if job_name == "windows-compatibility" else LINUX_FRESH_BACKEND_INSTALL_COMMAND
            for step_name, script in (
                ("Require initially absent dependency roots", absent),
                ("Install fresh locked developer dependencies", developer_install),
                ("Install fresh locked backend dependencies", backend_install),
            ):
                if by_name.get(step_name) != {
                    "name": step_name,
                    "shell": expected_shell,
                    "run": script,
                }:
                    errors.append(f"{job_name}:{step_name} is not exact")
        final_name = expected_names[-1]
        if by_name.get(final_name) != {
            "name": final_name,
            "shell": expected_shell,
            "run": FINAL_VERIFIER_COMMANDS[job_name],
        }:
            errors.append(f"{job_name} absolute trusted verifier command is not exact")
        if not steps or steps[-1].get("name") != final_name:
            errors.append(f"{job_name} authoritative verifier must be the terminal workflow step")
        if any(step.get("uses", "").startswith("actions/upload-artifact@") for step in steps):
            errors.append(f"{job_name} verifier must not upload artifacts")

    if job_name == "final-result" and by_name.get("Require every fresh verifier to succeed") != {
        "name": "Require every fresh verifier to succeed",
        "shell": "bash",
        "run": FINAL_RESULT_SCRIPT,
    }:
        errors.append("final-result exact fail-closed script is missing")


def _validate_final_result_semantics(job: Mapping[str, Any], errors: list[str]) -> None:
    if _canonical_expression(str(job.get("if", ""))).replace("${{", "").replace("}}", "") != "always()":
        errors.append("final-result must use exact always() semantics")
    required_needs = ["repository-policy", "ubuntu-canonical", "windows-compatibility"]
    if job.get("needs") != required_needs:
        errors.append("final-result needs set/order is not exact")
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    final_step = next(
        (
            step
            for step in steps
            if isinstance(step, dict)
            and step.get("name") == "Require every fresh verifier to succeed"
        ),
        None,
    )
    script = final_step.get("run", "") if isinstance(final_step, dict) else ""
    if script != FINAL_RESULT_SCRIPT:
        errors.append("final-result script is not the exact fail-closed script")
    for dependency in required_needs:
        expression = f"${{{{ needs.{dependency}.result }}}}"
        if script.count(expression) != 1:
            errors.append(f"final-result must inspect {dependency} exactly once")
        pattern = re.compile(
            rf'if \[\[ "\$\{{\{{ needs\.{re.escape(dependency)}\.result \}}\}}" != "success" \]\]; then\n'
            rf'  echo "[^"]+"\n  exit 1\nfi'
        )
        if not pattern.search(script):
            errors.append(f"final-result does not fail closed for {dependency}")
    if re.search(r"(?m)^\s*(?:exit\s+0|:)\s*$", script):
        errors.append("final-result contains an always-success neutralizer")


def check_workflow_text(text: str) -> list[str]:
    """Parse and validate the deliberately limited canonical YAML subset."""

    try:
        workflow = parse_canonical_workflow_yaml(text)
    except CanonicalYamlError as exc:
        return [f"workflow syntax rejected: {exc}"]
    errors: list[str] = []
    if not _require_exact_keys(workflow, ("name", "on", "permissions", "concurrency", "jobs"), "workflow", errors):
        return sorted(set(errors + _validate_scalar_token_policy(workflow)))
    if workflow.get("name") != "Baseline-aware CI":
        errors.append("workflow name is not exact")
    triggers = workflow.get("on")
    if not _require_exact_keys(triggers, ("pull_request", "push", "workflow_dispatch"), "workflow.on", errors):
        pass
    elif triggers != {
        "pull_request": {"branches": ["main"]},
        "push": {"branches": ["main", "ci/phase2-foundation"]},
        "workflow_dispatch": None,
    }:
        errors.append("workflow triggers are not the exact approved trigger set")
    if workflow.get("permissions") != {"contents": "read"}:
        errors.append("top-level permissions must contain only contents: read")
    if workflow.get("concurrency") != {
        "group": "ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": "true",
    }:
        errors.append("workflow concurrency block is not exact")
    jobs = workflow.get("jobs")
    if not _require_exact_keys(
        jobs,
        (
            "repository-policy-producer",
            "ubuntu-canonical-producer",
            "windows-compatibility-producer",
            "repository-policy",
            "ubuntu-canonical",
            "windows-compatibility",
            "final-result",
        ),
        "workflow.jobs",
        errors,
    ):
        return sorted(set(errors + _validate_scalar_token_policy(workflow)))

    job_schemas = {
        "repository-policy-producer": (("name", "runs-on", "timeout-minutes", "steps"), "Repository policy producer (untrusted evidence)", None, "ubuntu-latest", "20"),
        "ubuntu-canonical-producer": (("name", "runs-on", "timeout-minutes", "steps"), "Ubuntu canonical producer (untrusted evidence)", None, "ubuntu-latest", "45"),
        "windows-compatibility-producer": (("name", "runs-on", "timeout-minutes", "steps"), "Windows compatibility producer (untrusted evidence)", None, "windows-latest", "45"),
        "repository-policy": (("name", "needs", "runs-on", "timeout-minutes", "steps"), "Repository policy", ["repository-policy-producer"], "ubuntu-latest", "25"),
        "ubuntu-canonical": (("name", "needs", "runs-on", "timeout-minutes", "steps"), "Ubuntu canonical validation", ["ubuntu-canonical-producer"], "ubuntu-latest", "55"),
        "windows-compatibility": (("name", "needs", "runs-on", "timeout-minutes", "steps"), "Windows compatibility validation", ["windows-compatibility-producer"], "windows-latest", "55"),
        "final-result": (("name", "if", "needs", "runs-on", "timeout-minutes", "steps"), "Final result", ["repository-policy", "ubuntu-canonical", "windows-compatibility"], "ubuntu-latest", "10"),
    }
    for job_name, (keys, display_name, needs, runner_name, timeout_value) in job_schemas.items():
        job = jobs.get(job_name)
        if not _require_exact_keys(job, keys, f"job {job_name}", errors):
            continue
        if job.get("name") != display_name or job.get("runs-on") != runner_name or job.get("timeout-minutes") != timeout_value:
            errors.append(f"job {job_name} metadata is not exact")
        if needs is not None and job.get("needs") != needs:
            errors.append(f"job {job_name} needs graph is not exact")
        _validate_workflow_steps(job_name, job.get("steps"), errors)
    _validate_final_result_semantics(jobs["final-result"], errors)
    errors.extend(_validate_scalar_token_policy(workflow))
    for warning in TRUST_WARNING_LINES:
        if warning not in text:
            errors.append(f"workflow final result is missing bootstrap warning: {warning}")
    lowered = text.casefold()
    for phrase in PROHIBITED_AUTHORITY_PHRASES:
        if phrase.casefold() in lowered:
            errors.append(f"workflow contains prohibited authority overclaim: {phrase}")
    return sorted(set(errors))


def check_governance_language(workflow_text: str, policy_text: str) -> list[str]:
    errors: list[str] = []
    for warning in TRUST_WARNING_LINES:
        if warning not in workflow_text:
            errors.append(f"workflow is missing trust warning: {warning}")
        if warning not in policy_text:
            errors.append(f"CI policy is missing trust warning: {warning}")
    required_policy_statements = (
        "ACCEPTED-INHERENT-LIMITATION-WITH-EXPLICIT-EXTERNAL-REVIEW-BOUNDARY",
        "A pull request can modify the workflow, validator, baseline, and validator tests together.",
        "A successful run proves only the behavior of the exact candidate bytes that ran.",
        "Changes to any CI trust file require independent review outside the candidate implementation worktree.",
        "Until CODEOWNERS, required reviewer rules, and branch protection are separately configured and verified, CI success is not sufficient merge authorization.",
        "Even after repository governance is configured, those controls—not this self-validator—provide the external bootstrap boundary.",
        ".gitignore changes affecting CI evidence must also receive review.",
        "`--verify-evidence` without `--expected-profile` is a configuration error",
        "`ExternallyExpectedVerificationContext`",
        "`ProducerExecutionBinding`",
        "`VerifierExecutionBinding`",
        "`WORKFLOW_JOB_PROFILE_AUTHORITY`",
        "`CITrustFileSetDigest`",
        "`RuntimeDependencyClosure`",
        "`RuntimeDependencyClosureGuard`",
        "`linux-subreaper-pidfd-proc-supervisor`",
        "`REMOTE-LIVE-VALIDATION-PENDING`",
        "The full producer closure claim is stored in `command-results.json`, but it is untrusted",
        "There is no workflow step after it.",
    )
    for statement in required_policy_statements:
        if statement not in policy_text:
            errors.append(f"CI policy is missing bootstrap-boundary statement: {statement}")
    for relative in CI_TRUST_FILE_PATHS:
        if f"`{relative}`" not in policy_text:
            errors.append(f"CI policy is missing trust-file inventory entry: {relative}")
    for label, source in (("workflow", workflow_text), ("CI policy", policy_text)):
        lowered = source.casefold()
        for phrase in PROHIBITED_AUTHORITY_PHRASES:
            if phrase.casefold() in lowered:
                errors.append(f"{label} contains prohibited authority overclaim: {phrase}")
    return sorted(set(errors))


def git_candidate_paths(
    *,
    git: str,
    env: Mapping[str, str],
    executable_lease: Any | None = None,
) -> tuple[list[str], list[str], CommandCapture]:
    capture = execute_command(
        "git-candidate-paths",
        "repository-boundary",
        trusted_git_arguments(git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"),
        timeout=60,
        env=env,
        include_preview=False,
        executable_lease=executable_lease,
    )
    if not capture.executed or capture.exit_code != 0:
        return [], ["git ls-files did not execute successfully"], capture
    paths = sorted(path for path in capture.stdout.split("\0") if path)
    return paths, [], capture


def private_or_operational_path_reason(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    name = Path(normalized).name.lower()
    if lower.startswith(".codex/"):
        return "tracked local Codex state"
    if lower.startswith("readingpractice/"):
        return "tracked private Reading resource"
    if re.match(r"(?i)^ListeningPractice/P[1-4](?:/|$)", normalized):
        return "tracked private Listening resource"
    if lower.startswith("deploy-artifacts/") or lower.startswith("dist/"):
        return "tracked release or deployment artifact"
    if name == ".env" or (name.startswith(".env.") and not name.endswith(".example")):
        return "tracked secret environment file"
    if lower.startswith("backend/tor/") and (
        name.endswith((".auth", ".age", ".agekey", ".identity", ".key", ".pem", ".pub"))
        or any(
            fragment in lower
            for fragment in (
                "hidden_service/",
                "admin_hidden_service/",
                "auth_hidden_service/",
                "transports/",
                "volume-backups/",
                "bridges.local",
                "webtunnel.local",
                "bridges.decrypted",
            )
        )
    ):
        return "tracked Tor/client-auth operational artifact"
    if name.endswith((".dump", ".sql.gz")):
        return "tracked database or backup artifact"
    if name.endswith(".sql") and not lower.startswith("backend/migrations/"):
        return "tracked database artifact outside migrations"
    return None


BINARY_MAGIC_ALLOWLIST: Mapping[str, tuple[bytes, ...]] = MappingProxyType(
    {
        ".gif": (b"GIF87a", b"GIF89a"),
        ".gz": (b"\x1f\x8b",),
        ".ico": (b"\x00\x00\x01\x00",),
        ".jpeg": (b"\xff\xd8\xff",),
        ".jpg": (b"\xff\xd8\xff",),
        ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
        ".ogg": (b"OggS",),
        ".otf": (b"OTTO",),
        ".pdf": (b"%PDF-",),
        ".png": (b"\x89PNG\r\n\x1a\n",),
        ".ttf": (b"\x00\x01\x00\x00",),
        ".webm": (b"\x1a\x45\xdf\xa3",),
        ".woff": (b"wOFF",),
        ".woff2": (b"wOF2",),
        ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    }
)


def _recognized_binary_magic(path: Path, sample: bytes) -> bool:
    suffix = path.suffix.casefold()
    if suffix == ".webp":
        return sample.startswith(b"RIFF") and sample[8:12] == b"WEBP"
    if suffix == ".wav":
        return sample.startswith(b"RIFF") and sample[8:12] == b"WAVE"
    if suffix in {".mp4", ".m4a"}:
        return len(sample) >= 12 and sample[4:8] == b"ftyp"
    return any(sample.startswith(magic) for magic in BINARY_MAGIC_ALLOWLIST.get(suffix, ()))


def _secret_scan_record(
    *,
    passed: bool,
    file_size: int | None,
    raw_bytes_scanned: int,
    classification: str,
    hits: Iterable[str],
    encoding_views: Sequence[str] = ("raw-bytes",),
    utf16le_units: int = 0,
    utf16be_units: int = 0,
) -> dict[str, Any]:
    normalized_hits = sorted(set(hits))
    return {
        "passed": passed,
        "fileSize": file_size,
        "scannedBytes": raw_bytes_scanned,
        "rawBytesScanned": raw_bytes_scanned,
        "classification": classification,
        "encodingViewsApplied": list(encoding_views),
        "utf16LeDecodedUnits": utf16le_units,
        "utf16BeDecodedUnits": utf16be_units,
        "patternFamiliesApplied": list(SECRET_SCAN_PATTERN_FAMILIES),
        "hitCount": len(normalized_hits),
        "hits": normalized_hits,
    }


def _scan_decoded_secret_window(window: str, hits: set[str]) -> None:
    for pattern, label in SECRET_SCAN_TEXT_PATTERNS:
        if pattern.search(window):
            hits.add(label)
    if re.search(
        r"(?im)^\s*obfs4\s+\S{1,2048}:\d{1,5}\s+[A-F0-9]{40}\s+cert=\S{1,4096}\s+iat-mode=\d+\s*$",
        window,
    ):
        hits.add("operational-obfs4-bridge")
    if re.search(r"(?i)\b[a-z2-7]{56}\.onion\b", window):
        hits.add("operational-onion-hostname")


@dataclass
class _Utf16AsciiViewScanner:
    """Stream one endian/alignment view without decoding arbitrary binary text."""

    endian: str
    alignment: int
    carry: bytes = b""
    overlap: str = ""
    decoded_units: int = 0
    raw_bytes_seen: int = 0
    first_chunk: bool = True
    hits: set[str] = field(default_factory=set)

    @property
    def name(self) -> str:
        return f"utf-16{self.endian}-offset-{self.alignment}"

    def feed(self, chunk: bytes) -> None:
        self.raw_bytes_seen += len(chunk)
        if self.first_chunk:
            data = chunk[self.alignment :]
            self.first_chunk = False
        else:
            data = self.carry + chunk
        paired_length = len(data) - (len(data) % 2)
        paired = data[:paired_length]
        self.carry = data[paired_length:]
        characters: list[str] = []
        little_endian = self.endian == "le"
        for index in range(0, paired_length, 2):
            first, second = paired[index], paired[index + 1]
            code_unit = first | (second << 8) if little_endian else (first << 8) | second
            if code_unit in (0x09, 0x0A, 0x0D) or 0x20 <= code_unit <= 0x7E:
                characters.append(chr(code_unit))
            else:
                # A separator prevents ASCII tokens on opposite sides of an
                # unrelated code unit from being concatenated into a finding.
                characters.append("\uffff")
        self.decoded_units += len(characters)
        window = self.overlap + "".join(characters)
        _scan_decoded_secret_window(window, self.hits)
        self.overlap = window[-SECRET_SCAN_OVERLAP_BYTES:]

    def finish(self) -> None:
        # An unmatched final byte cannot form a UTF-16 code unit. Every
        # complete unit in the final raw chunk has already been scanned.
        _scan_decoded_secret_window(self.overlap, self.hits)


def scan_file_for_secrets(path: Path) -> dict[str, Any]:
    """Stream raw bytes plus all LE/BE UTF-16 ASCII views for the full file."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        return _secret_scan_record(
            passed=False,
            file_size=None,
            raw_bytes_scanned=0,
            classification="read-error",
            hits=[f"read-error:{type(exc).__name__}"],
        )
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        return _secret_scan_record(
            passed=False,
            file_size=int(metadata.st_size),
            raw_bytes_scanned=0,
            classification="rejected-special-file",
            hits=["tracked-link-or-reparse"],
        )
    if not stat.S_ISREG(metadata.st_mode):
        return _secret_scan_record(
            passed=False,
            file_size=int(metadata.st_size),
            raw_bytes_scanned=0,
            classification="rejected-special-file",
            hits=["tracked-special-file"],
        )

    hits: set[str] = set()
    scanned_bytes = 0
    overlap = b""
    sample = bytearray()
    utf16_scanners = tuple(
        _Utf16AsciiViewScanner(endian, alignment)
        for endian in ("le", "be")
        for alignment in (0, 1)
    )
    classification = "text-scanned"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
        )
        if _stat_identity(os.fstat(descriptor)) != _stat_identity(metadata):
            raise OSError("file changed between lstat and open")
        while True:
            chunk = os.read(descriptor, SECRET_SCAN_CHUNK_BYTES)
            if not chunk:
                break
            scanned_bytes += len(chunk)
            if len(sample) < SECRET_SCAN_CLASSIFICATION_SAMPLE_BYTES:
                sample.extend(chunk[: SECRET_SCAN_CLASSIFICATION_SAMPLE_BYTES - len(sample)])
            window = overlap + chunk
            for pattern, label in SECRET_SCAN_BYTE_PATTERNS:
                if pattern.search(window):
                    hits.add(label)
            if re.search(
                rb"(?im)^\s*obfs4\s+\S{1,2048}:\d{1,5}\s+[A-F0-9]{40}\s+cert=\S{1,4096}\s+iat-mode=\d+\s*$",
                window,
            ):
                hits.add("operational-obfs4-bridge")
            if re.search(rb"(?i)\b[a-z2-7]{56}\.onion\b", window):
                hits.add("operational-onion-hostname")
            overlap = window[-SECRET_SCAN_OVERLAP_BYTES:]
            for scanner in utf16_scanners:
                scanner.feed(chunk)
    except OSError as exc:
        hits.add(f"read-error:{type(exc).__name__}")
        return _secret_scan_record(
            passed=False,
            file_size=int(metadata.st_size),
            raw_bytes_scanned=scanned_bytes,
            classification="read-error",
            hits=hits,
            encoding_views=("raw-bytes", *UTF16_ASCII_CREDENTIAL_VIEWS),
            utf16le_units=sum(
                scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "le"
            ),
            utf16be_units=sum(
                scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "be"
            ),
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    sample_bytes = bytes(sample)
    if b"\x00" in sample_bytes or _recognized_binary_magic(path, sample_bytes):
        classification = "binary-scanned"
    try:
        after = path.lstat()
    except OSError as exc:
        hits.add(f"read-error:{type(exc).__name__}")
        classification = "read-error"
    else:
        if _stat_identity(after) != _stat_identity(metadata) or scanned_bytes != metadata.st_size:
            hits.add("file-changed-or-short-read")
            classification = "read-error"

    for scanner in utf16_scanners:
        scanner.finish()
        hits.update(scanner.hits)
        if scanner.raw_bytes_seen != scanned_bytes:
            hits.add(f"{scanner.name}-short-read")
            classification = "read-error"
    utf16le_units = sum(
        scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "le"
    )
    utf16be_units = sum(
        scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "be"
    )
    encoding_views = ("raw-bytes", *UTF16_ASCII_CREDENTIAL_VIEWS)
    return _secret_scan_record(
        passed=not hits,
        file_size=int(metadata.st_size),
        raw_bytes_scanned=scanned_bytes,
        classification=classification,
        hits=hits,
        encoding_views=encoding_views,
        utf16le_units=utf16le_units,
        utf16be_units=utf16be_units,
    )


def scan_bytes_for_secrets(logical_path: str, data: bytes) -> dict[str, Any]:
    """Apply the complete secret scanner to already protected immutable bytes."""

    path = Path(logical_path)
    hits: set[str] = set()
    overlap = b""
    sample = bytearray()
    utf16_scanners = tuple(
        _Utf16AsciiViewScanner(endian, alignment)
        for endian in ("le", "be")
        for alignment in (0, 1)
    )
    for offset in range(0, len(data), SECRET_SCAN_CHUNK_BYTES):
        chunk = data[offset : offset + SECRET_SCAN_CHUNK_BYTES]
        if len(sample) < SECRET_SCAN_CLASSIFICATION_SAMPLE_BYTES:
            sample.extend(chunk[: SECRET_SCAN_CLASSIFICATION_SAMPLE_BYTES - len(sample)])
        window = overlap + chunk
        for pattern, label in SECRET_SCAN_BYTE_PATTERNS:
            if pattern.search(window):
                hits.add(label)
        if re.search(
            rb"(?im)^\s*obfs4\s+\S{1,2048}:\d{1,5}\s+[A-F0-9]{40}\s+cert=\S{1,4096}\s+iat-mode=\d+\s*$",
            window,
        ):
            hits.add("operational-obfs4-bridge")
        if re.search(rb"(?i)\b[a-z2-7]{56}\.onion\b", window):
            hits.add("operational-onion-hostname")
        overlap = window[-SECRET_SCAN_OVERLAP_BYTES:]
        for scanner in utf16_scanners:
            scanner.feed(chunk)
    for scanner in utf16_scanners:
        scanner.finish()
        hits.update(scanner.hits)
        if scanner.raw_bytes_seen != len(data):
            hits.add(f"{scanner.name}-short-read")
    sample_bytes = bytes(sample)
    classification = (
        "binary-scanned"
        if b"\x00" in sample_bytes or _recognized_binary_magic(path, sample_bytes)
        else "text-scanned"
    )
    return _secret_scan_record(
        passed=not hits,
        file_size=len(data),
        raw_bytes_scanned=len(data),
        classification=classification,
        hits=hits,
        encoding_views=("raw-bytes", *UTF16_ASCII_CREDENTIAL_VIEWS),
        utf16le_units=sum(
            scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "le"
        ),
        utf16be_units=sum(
            scanner.decoded_units for scanner in utf16_scanners if scanner.endian == "be"
        ),
    )


def build_expected_static_machine_command_plan(
    invocation_id: str,
    *,
    python_executable: str | Path,
    repo_root: Path | None = None,
    current_platform: str | None = None,
) -> list[dict[str, Any]]:
    """Independently reconstruct the static producer's immutable self-plan."""

    executable = Path(python_executable).resolve(strict=True)
    root = REPO_ROOT if repo_root is None else repo_root
    target = (root / STATIC_SUITE_RELATIVE_PATH).resolve(strict=True)
    return [
        {
            "commandId": "static-check-registry",
            "ordinal": 0,
            "commandClass": "static-machine-producer",
            "required": True,
            "profile": "static",
            "platform": current_platform or platform_key(),
            "argv": [
                str(executable),
                "-B",
                STATIC_SUITE_RELATIVE_PATH,
                "--ci-machine-json-stdout",
                "--ci-invocation-id",
                invocation_id,
            ],
            "cwd": ".",
            "toolRole": "python-static-producer",
            "resolvedExecutablePath": str(executable),
            "resolvedExecutableSize": executable.stat().st_size,
            "resolvedExecutableSha256": _sha256_file(executable),
            "targets": [
                {
                    "path": STATIC_SUITE_RELATIVE_PATH,
                    "size": target.stat().st_size,
                    "sha256": _sha256_file(target),
                }
            ],
            "resultSemantics": "complete-registry-execution-with-native-observations",
            "allowedExecutionExits": [0],
        }
    ]


def _portable_command_plan_value(plan: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    portable: list[dict[str, Any]] = []
    repo_spellings = {
        str(REPO_ROOT.resolve()),
        str(REPO_ROOT.resolve()).replace("\\", "/"),
    }
    for source in plan:
        record = copy.deepcopy(dict(source))
        tool_role = str(record.get("toolRole", "unknown"))
        for field_name in ("argv", "logicalArgv", "executionArgv"):
            values = record.get(field_name)
            if not isinstance(values, list):
                continue
            normalized: list[Any] = []
            for index, value in enumerate(values):
                if index == 0:
                    normalized.append(f"<TRUSTED-TOOL:{tool_role}>")
                    continue
                if not isinstance(value, str):
                    normalized.append(value)
                    continue
                item = value
                for spelling in repo_spellings:
                    item = item.replace(spelling, "<REPO>")
                normalized.append(item.replace("\\", "/"))
            record[field_name] = normalized
        record["resolvedExecutablePath"] = f"<TRUSTED-TOOL:{tool_role}>"
        record["resolvedExecutableFileIdentity"] = None
        lease = record.get("executionLease")
        if isinstance(lease, dict):
            record["executionLease"] = {
                "sha256": lease.get("sha256"),
                "size": lease.get("size"),
            }
        targets = record.get("targets")
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict):
                    target["canonicalSourcePath"] = None
                    target["fileIdentity"] = None
        portable.append(record)
    return portable


def command_plan_digest(plan: Sequence[Mapping[str, Any]]) -> str:
    canonical = json.dumps(
        _portable_command_plan_value(plan),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def static_machine_command_plan_digest(plan: Sequence[Mapping[str, Any]]) -> str:
    """Match the immutable static producer's exact, non-portable plan digest."""

    canonical = json.dumps(
        list(plan),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def execution_binding_digest(binding: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_frame(binding)).hexdigest()


AUTHORIZATION_CONTEXT_BINDING_KEYS = frozenset(
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

VERIFIER_REPLAY_CONTEXT_BINDING_KEYS = frozenset(
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


def _require_authorization_context_binding(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != AUTHORIZATION_CONTEXT_BINDING_KEYS:
        raise ValueError("AuthorizationContextBinding field set is not exact")
    value = dict(binding)
    if value.get("bindingSchemaVersion") != AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION:
        raise ValueError("AuthorizationContextBinding schema version is invalid")
    if value.get("bindingKind") != "AuthorizationContextBinding":
        raise ValueError("AuthorizationContextBinding kind is invalid")
    if value.get("bindingMode") not in {"github-actions", "local"}:
        raise ValueError("AuthorizationContextBinding mode is invalid")
    if value.get("expectedProfile") not in PROFILES:
        raise ValueError("AuthorizationContextBinding profile is invalid")
    _require_resolved_release_gate_required(
        str(value.get("expectedProfile", "")),
        value.get("releaseGateRequired"),
    )
    if value.get("runnerOS") not in {"Linux", "Windows"}:
        raise ValueError("AuthorizationContextBinding runner OS is invalid")
    for key in (
        "producerJobId",
        "expectedVerifierJobId",
        "runId",
        "runAttempt",
        "eventName",
        "repository",
    ):
        item = value.get(key)
        if (
            not isinstance(item, str)
            or not item
            or item != item.strip()
            or len(item.encode("utf-8", errors="strict")) > 512
        ):
            raise ValueError(f"AuthorizationContextBinding {key} is invalid")
    for key in ("checkoutCommit", "checkoutTree", "baselineCommit", "baselineTree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(value.get(key, ""))):
            raise ValueError(f"AuthorizationContextBinding {key} is invalid")
    for key in ("trustFileDigest", "commandPlanDigest", "producerInvocationId"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(key, ""))):
            raise ValueError(f"AuthorizationContextBinding {key} is invalid")
    # Framing here also rejects duplicate NFC-normalized object keys.
    _canonical_frame(value)
    return value


def authorization_context_binding_digest(binding: Mapping[str, Any]) -> str:
    value = _require_authorization_context_binding(binding)
    return hashlib.sha256(
        _canonical_frame(
            {
                "digestDomain": AUTHORIZATION_CONTEXT_BINDING_DIGEST_DOMAIN,
                "binding": value,
            }
        )
    ).hexdigest()


def authorization_context_binding_from_execution_binding(
    execution_binding: Mapping[str, Any],
    *,
    expected_verifier_job_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(execution_binding, Mapping):
        raise ValueError("producer execution binding is unavailable")
    binding_mode = str(execution_binding.get("bindingMode", ""))
    producer_job_id = str(execution_binding.get("producerJobId", ""))
    if expected_verifier_job_id is None:
        if binding_mode == "local":
            expected_verifier_job_id = "local-verifier"
        else:
            authority = _workflow_authority_for_producer(producer_job_id)
            if authority is None:
                raise ValueError("producer job cannot derive fixed verifier authority")
            expected_verifier_job_id = str(authority["verifierJobId"])
    binding = {
        "bindingSchemaVersion": AUTHORIZATION_CONTEXT_BINDING_SCHEMA_VERSION,
        "bindingKind": "AuthorizationContextBinding",
        "bindingMode": binding_mode,
        "expectedProfile": execution_binding.get("producerProfile"),
        "releaseGateRequired": execution_binding.get("releaseGateRequired"),
        "producerJobId": producer_job_id,
        "expectedVerifierJobId": expected_verifier_job_id,
        "runnerOS": execution_binding.get("producerRunnerOS"),
        "runId": execution_binding.get("runId"),
        "runAttempt": execution_binding.get("runAttempt"),
        "eventName": execution_binding.get("eventName"),
        "repository": execution_binding.get("repository"),
        "checkoutCommit": execution_binding.get("checkoutCommit"),
        "checkoutTree": execution_binding.get("checkoutTree"),
        "baselineCommit": execution_binding.get("baselineCommit"),
        "baselineTree": execution_binding.get("baselineTree"),
        "trustFileDigest": execution_binding.get("trustFileDigest"),
        "commandPlanDigest": execution_binding.get("commandPlanDigest"),
        "producerInvocationId": execution_binding.get("producerInvocationId"),
    }
    return _require_authorization_context_binding(binding)


def authorization_context_binding_errors(
    binding: Any,
    digest: Any,
    *,
    execution_binding: Mapping[str, Any] | None = None,
    expected_context: ExternallyExpectedVerificationContext | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        value = _require_authorization_context_binding(binding)
        expected_digest = authorization_context_binding_digest(value)
    except (TypeError, ValueError) as exc:
        return [f"authorization context binding is invalid: {exc}"]
    if digest != expected_digest:
        errors.append("authorizationContextBindingDigest is invalid")
    if execution_binding is not None:
        try:
            derived = authorization_context_binding_from_execution_binding(
                execution_binding
            )
        except (TypeError, ValueError) as exc:
            errors.append(
                f"producer execution binding cannot derive authorization context: {exc}"
            )
        else:
            if value != derived:
                errors.append(
                    "authorization context differs from fixed producer/verifier authority"
                )
    if expected_context is not None:
        externally_expected = expected_context.authorization_context_binding()
        if value != externally_expected:
            errors.append(
                "authorization context differs from externally reconstructed authority"
            )
        if digest != authorization_context_binding_digest(externally_expected):
            errors.append(
                "authorization-context digest differs from external authority"
            )
    return sorted(set(errors))


def _require_verifier_replay_context_binding(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != VERIFIER_REPLAY_CONTEXT_BINDING_KEYS:
        raise ValueError("VerifierReplayContextBinding field set is not exact")
    value = dict(binding)
    if value.get("bindingSchemaVersion") != VERIFIER_REPLAY_CONTEXT_BINDING_SCHEMA_VERSION:
        raise ValueError("VerifierReplayContextBinding schema version is invalid")
    if value.get("bindingKind") != "VerifierReplayContextBinding":
        raise ValueError("VerifierReplayContextBinding kind is invalid")
    if value.get("actualVerifierRunnerOS") not in {"Linux", "Windows"}:
        raise ValueError("VerifierReplayContextBinding runner OS is invalid")
    for key in ("actualVerifierJobId",):
        item = value.get(key)
        if not isinstance(item, str) or not item or item != item.strip():
            raise ValueError(f"VerifierReplayContextBinding {key} is invalid")
    for key in (
        "verifierInvocationId",
        "freshRuntimeClosureDigest",
        "freshDependencyClosureDigest",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(key, ""))):
            raise ValueError(f"VerifierReplayContextBinding {key} is invalid")
    for key in (
        "linuxContainmentLiveTestResultDigest",
        "replayTranscriptDigest",
    ):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get(key, ""))):
            raise ValueError(f"VerifierReplayContextBinding {key} is invalid")
    if value.get("cleanupResult") not in {"closed-clean", "cleanup-incomplete"}:
        raise ValueError("VerifierReplayContextBinding cleanup result is invalid")
    _canonical_frame(value)
    return value


def verifier_replay_context_digest(binding: Mapping[str, Any]) -> str:
    value = _require_verifier_replay_context_binding(binding)
    return hashlib.sha256(
        _canonical_frame(
            {
                "digestDomain": VERIFIER_REPLAY_CONTEXT_BINDING_DIGEST_DOMAIN,
                "binding": value,
            }
        )
    ).hexdigest()


def current_full_context_digest_set_digest(
    observations: Sequence[Mapping[str, Any]],
) -> str:
    projection: list[dict[str, str]] = []
    for item in observations:
        digest = str(item.get("currentFullContextDigest", ""))
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("replay observation has an invalid currentFullContextDigest")
        projection.append(
            {
                "commandId": str(item.get("commandId", "")),
                "testOrPathScope": str(item.get("testOrPathScope", "")),
                "currentFullContextDigest": digest,
            }
        )
    return canonical_failure_digest(
        {
            "schemaVersion": REPLAY_AUTHORIZATION_ENVELOPE_SCHEMA_VERSION,
            "orderedCurrentFullContexts": projection,
        }
    )


def replay_authorization_envelope_digest(
    *,
    current_full_context_set_digest: str,
    authorization_context_binding_digest_value: str,
    verifier_replay_context_digest_value: str,
) -> str:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", current_full_context_set_digest):
        raise ValueError("current full-context set digest is invalid")
    for label, value in (
        ("authorization context", authorization_context_binding_digest_value),
        ("verifier replay context", verifier_replay_context_digest_value),
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"{label} digest is invalid")
    material = {
        "schemaVersion": REPLAY_AUTHORIZATION_ENVELOPE_SCHEMA_VERSION,
        "bindingKind": "ReplayAuthorizationEnvelope",
        "currentFullContextDigestSetDigest": current_full_context_set_digest,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
        "verifierReplayContextDigest": verifier_replay_context_digest_value,
    }
    return hashlib.sha256(
        _canonical_frame(
            {
                "digestDomain": REPLAY_AUTHORIZATION_ENVELOPE_DIGEST_DOMAIN,
                "envelope": material,
            }
        )
    ).hexdigest()


def _canonical_runner_os() -> str:
    if sys.platform.startswith("win"):
        return "Windows"
    if sys.platform.startswith("linux"):
        return "Linux"
    raise ValueError("execution binding supports only Linux and Windows runners")


def capture_live_external_authority(
    source_environment: Mapping[str, str] | None = None,
) -> ExecutionExternalAuthority:
    """Capture the process-owned external job context exactly once."""

    source = dict(os.environ if source_environment is None else source_environment)
    github_actions_value = source.get("GITHUB_ACTIONS")
    if github_actions_value not in {None, "", "false", "true"}:
        raise ValueError("GITHUB_ACTIONS has an invalid external-authority value")
    if github_actions_value != "true":
        return ExecutionExternalAuthority(
            source_kind="live",
            binding_mode="local",
            runner_os=_canonical_runner_os(),
            job_id="",
            run_id="local",
            run_attempt="1",
            event_name="local",
            repository="",
            checkout_sha="",
        )
    required = (
        "GITHUB_JOB",
        "RUNNER_OS",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
    )
    values: dict[str, str] = {}
    for name in required:
        value = source.get(name)
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError(f"live external authority is missing {name}")
        values[name] = value
    if values["RUNNER_OS"] != _canonical_runner_os():
        raise ValueError("live external authority runner OS differs from the process platform")
    return ExecutionExternalAuthority(
        source_kind="live",
        binding_mode="github-actions",
        runner_os=values["RUNNER_OS"],
        job_id=values["GITHUB_JOB"],
        run_id=values["GITHUB_RUN_ID"],
        run_attempt=values["GITHUB_RUN_ATTEMPT"],
        event_name=values["GITHUB_EVENT_NAME"],
        repository=values["GITHUB_REPOSITORY"],
        checkout_sha=values["GITHUB_SHA"],
    )


def select_generation_evidence_output(
    source_environment: Mapping[str, str],
    external_authority: ExecutionExternalAuthority,
    *,
    repo_root: Path = REPO_ROOT,
) -> tuple[Path, Path]:
    """Select the fixed workspace output or a guarded local task-owned root."""

    raw_output = source_environment.get("CI_FOUNDATION_TASK_OUTPUT_ROOT", "")
    if not raw_output:
        return repo_root / ".ci-results", repo_root
    if external_authority.binding_mode == "github-actions":
        raise ValueError("external evidence output is forbidden in GitHub Actions")
    raw_task_root = source_environment.get("CI_SECURITY_TASK_TEMP", "")
    output = Path(raw_output)
    task_root = Path(raw_task_root)
    if not output.is_absolute() or not task_root.is_absolute():
        raise ValueError("external evidence output requires absolute task-owned paths")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", output.name):
        raise ValueError("external evidence output name is invalid")
    try:
        task_metadata = task_root.lstat()
        task_resolved = task_root.resolve(strict=True)
        output_parent = output.parent.resolve(strict=True)
        repo_resolved = repo_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"external evidence authority cannot be inspected: {type(exc).__name__}"
        ) from exc
    if (
        not stat.S_ISDIR(task_metadata.st_mode)
        or stat.S_ISLNK(task_metadata.st_mode)
        or _is_reparse_point(task_metadata)
        or output_parent != task_resolved
        or _path_is_within(task_resolved, repo_resolved)
    ):
        raise ValueError("external evidence output is outside the guarded task root")
    return output, task_root


def synthetic_execution_external_authority(
    *,
    runner_os: str,
    job_id: str,
    run_id: str = "999999999",
    run_attempt: str = "1",
    event_name: str = "push",
    repository: str = "synthetic/repository",
    checkout_sha: str = BASELINE_COMMIT,
) -> ExecutionExternalAuthority:
    """Build an explicit test-only hosted authority without reading os.environ."""

    return ExecutionExternalAuthority(
        source_kind="synthetic-test",
        binding_mode="github-actions",
        runner_os=runner_os,
        job_id=job_id,
        run_id=run_id,
        run_attempt=run_attempt,
        event_name=event_name,
        repository=repository,
        checkout_sha=checkout_sha,
    )


def synthetic_local_execution_external_authority(
    *, runner_os: str
) -> ExecutionExternalAuthority:
    """Build an explicit test-only local authority for synthetic topology tests."""

    return ExecutionExternalAuthority(
        source_kind="synthetic-test",
        binding_mode="local",
        runner_os=runner_os,
        job_id="",
        run_id="local",
        run_attempt="1",
        event_name="local",
        repository="",
        checkout_sha="",
    )


def _local_repository_identity_projection(repo_root: Path) -> bytes:
    resolved = str(repo_root.resolve(strict=True))
    if os.name == "nt":
        resolved = _ascii_lower_authority_text(resolved.replace("\\", "/"))
    return (
        LOCAL_REPOSITORY_IDENTITY_PROJECTION_DOMAIN.encode("ascii")
        + b"\0"
        + resolved.encode("utf-8", errors="strict")
    )


def _local_repository_identity(repo_root: Path) -> str:
    return "local-root-sha256:" + hashlib.sha256(
        _local_repository_identity_projection(repo_root)
    ).hexdigest()


def _binding_git_stdout(
    git: str,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    repo_root: Path,
) -> str:
    capture = execute_command(
        "execution-binding-git",
        "execution-binding-authority",
        [
            git,
            "-c",
            f"safe.directory={repo_root.resolve(strict=True)}",
            "-C",
            str(repo_root.resolve(strict=True)),
            *arguments,
        ],
        timeout=60,
        env=environment,
        include_preview=False,
        cwd=repo_root,
    )
    if not capture.execution_passed():
        raise ValueError("trusted Git could not construct execution-binding authority")
    return capture.stdout


def current_checkout_identity(
    *,
    git: str,
    environment: Mapping[str, str],
    repo_root: Path = REPO_ROOT,
) -> tuple[str, str]:
    output = _binding_git_stdout(
        git,
        ("rev-parse", "HEAD", "HEAD^{tree}"),
        environment=environment,
        repo_root=repo_root,
    )
    values = output.replace("\r\n", "\n").splitlines()
    if len(values) != 2 or any(not re.fullmatch(r"[0-9a-f]{40}", value) for value in values):
        raise ValueError("checkout commit/tree authority is not exact")
    return values[0], values[1]


def ci_trust_file_set_authority(
    *,
    git: str,
    environment: Mapping[str, str],
    repo_root: Path = REPO_ROOT,
) -> tuple[list[dict[str, Any]], str]:
    output = _binding_git_stdout(
        git,
        ("ls-files", "--stage", "-z", "--", *CI_TRUST_FILE_PATHS),
        environment=environment,
        repo_root=repo_root,
    )
    indexed_modes: dict[str, str] = {}
    for raw_record in output.split("\0"):
        if not raw_record:
            continue
        try:
            header, relative = raw_record.split("\t", 1)
            mode, object_id, stage = header.split(" ", 2)
        except ValueError as exc:
            raise ValueError("CI trust-file Git mode authority is malformed") from exc
        if (
            relative not in CI_TRUST_FILE_PATHS
            or mode not in {"100644", "100755"}
            or not re.fullmatch(r"[0-9a-f]{40,64}", object_id)
            or stage != "0"
            or relative in indexed_modes
        ):
            raise ValueError("CI trust-file Git mode authority is invalid")
        indexed_modes[relative] = mode

    root_resolved = repo_root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    for relative in CI_TRUST_FILE_PATHS:
        path = repo_root.joinpath(*relative.split("/"))
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"CI trust file is unavailable: {relative}") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or not _path_is_within(resolved, root_resolved)
        ):
            raise ValueError(f"CI trust file is not a repository regular file: {relative}")
        before = _stat_identity(metadata)
        digest = _sha256_file(path)
        after = path.lstat()
        if _stat_identity(after) != before:
            raise ValueError(f"CI trust file changed during digest construction: {relative}")
        git_mode = indexed_modes.get(relative)
        if git_mode is None:
            git_mode = "100755" if os.name != "nt" and bool(metadata.st_mode & stat.S_IXUSR) else "100644"
        records.append(
            {
                "relativePath": relative,
                "gitMode": git_mode,
                "byteLength": int(metadata.st_size),
                "sha256": digest,
            }
        )
    digest = hashlib.sha256(
        _canonical_frame(
            {
                "schemaVersion": CI_TRUST_FILE_SET_SCHEMA_VERSION,
                "files": records,
            }
        )
    ).hexdigest()
    return records, digest


def _github_binding_invocation_id(
    binding_without_invocation: Mapping[str, Any],
    *,
    role: str = "producer",
) -> str:
    return hashlib.sha256(
        _canonical_frame(
            {
                "purpose": f"github-actions-{role}-execution-binding-v3",
                "binding": binding_without_invocation,
            }
        )
    ).hexdigest()


def _workflow_authority_for_producer(producer_job_id: str) -> Mapping[str, Any] | None:
    return next(
        (
            authority
            for authority in WORKFLOW_JOB_PROFILE_AUTHORITY.values()
            if authority["producerJobId"] == producer_job_id
        ),
        None,
    )


def _producer_binding_without_invocation(
    *,
    binding_mode: str,
    producer_job_id: str,
    runner_os: str,
    profile: str,
    release_gate_required: bool,
    run_id: str,
    run_attempt: str,
    event_name: str,
    repository: str,
    checkout_commit: str,
    checkout_tree: str,
    baseline_commit: str,
    baseline_tree: str,
    trust_file_digest: str,
    command_plan_digest_value: str,
) -> dict[str, Any]:
    release_gate_required = _require_resolved_release_gate_required(
        profile,
        release_gate_required,
    )
    return {
        "bindingSchemaVersion": EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
        "bindingKind": "ProducerExecutionBinding",
        "bindingMode": binding_mode,
        "producerJobId": producer_job_id,
        "producerRunnerOS": runner_os,
        "producerProfile": profile,
        "releaseGateRequired": release_gate_required,
        "runId": run_id,
        "runAttempt": run_attempt,
        "eventName": event_name,
        "repository": repository,
        "checkoutCommit": checkout_commit,
        "checkoutTree": checkout_tree,
        "baselineCommit": baseline_commit,
        "baselineTree": baseline_tree,
        "trustFileDigest": trust_file_digest,
        "commandPlanDigest": command_plan_digest_value,
    }


def build_externally_expected_verification_context(
    *,
    expected_profile: str,
    release_gate_required: bool,
    expected_producer_job: str | None,
    expected_verifier_job: str | None,
    expected_runner_os: str | None,
    expected_invocation_id: str | None,
    command_plan_digest_value: str,
    fresh_runtime_closure_digest: str,
    baseline: Mapping[str, Any],
    git: str,
    child_environment: Mapping[str, str],
    external_authority: ExecutionExternalAuthority,
    repo_root: Path = REPO_ROOT,
) -> ExternallyExpectedVerificationContext:
    """Construct all replay selectors without consulting the evidence root."""

    if not isinstance(external_authority, ExecutionExternalAuthority):
        raise ValueError("explicit external authority is required")
    if expected_profile not in PROFILES:
        raise ValueError("expected profile is not in the fixed profile registry")
    release_gate_required = _require_resolved_release_gate_required(
        expected_profile,
        release_gate_required,
    )
    if not re.fullmatch(r"[0-9a-f]{64}", command_plan_digest_value):
        raise ValueError("expected command-plan digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", fresh_runtime_closure_digest):
        raise ValueError("fresh runtime-closure digest is invalid")
    checkout_commit, checkout_tree = current_checkout_identity(
        git=git,
        environment=child_environment,
        repo_root=repo_root,
    )
    _trust_manifest, trust_digest = ci_trust_file_set_authority(
        git=git,
        environment=child_environment,
        repo_root=repo_root,
    )
    baseline_commit = str(baseline.get("baselineCommit", ""))
    baseline_tree = str(baseline.get("baselineTree", ""))
    if baseline_commit != BASELINE_COMMIT or baseline_tree != BASELINE_TREE:
        raise ValueError("baseline commit/tree cannot construct execution-binding authority")

    github_actions = external_authority.binding_mode == "github-actions"
    if github_actions:
        if (
            expected_producer_job is None
            or expected_verifier_job is None
            or expected_runner_os is None
        ):
            raise ValueError(
                "GitHub Actions verification requires literal producer job, verifier job, and runner OS"
            )
        if expected_invocation_id is not None:
            raise ValueError("GitHub Actions run identity must come from GitHub-controlled context")
        values = {
            "GITHUB_JOB": external_authority.job_id,
            "RUNNER_OS": external_authority.runner_os,
            "GITHUB_RUN_ID": external_authority.run_id,
            "GITHUB_RUN_ATTEMPT": external_authority.run_attempt,
            "GITHUB_EVENT_NAME": external_authority.event_name,
            "GITHUB_REPOSITORY": external_authority.repository,
            "GITHUB_SHA": external_authority.checkout_sha,
        }
        authority = WORKFLOW_JOB_PROFILE_AUTHORITY.get(expected_verifier_job)
        if authority is None:
            raise ValueError("expected verifier workflow job is outside fixed authority")
        if authority["producerJobId"] != expected_producer_job:
            raise ValueError("producer/verifier workflow authority mismatch")
        if values["GITHUB_JOB"] != expected_verifier_job:
            raise ValueError("external expected verifier job does not equal GITHUB_JOB")
        if values["RUNNER_OS"] != expected_runner_os:
            raise ValueError("external expected runner OS does not equal RUNNER_OS")
        if (
            external_authority.source_kind == "live"
            and _canonical_runner_os() != expected_runner_os
        ):
            raise ValueError("external expected runner OS does not equal the current platform")
        if authority["verifierJobId"] != expected_verifier_job:
            raise ValueError("verifier workflow job authority identity mismatch")
        if authority["runnerOS"] != expected_runner_os:
            raise ValueError("job/runner-OS authority mismatch")
        if authority["verificationProfile"] != expected_profile:
            raise ValueError("job/profile authority mismatch")
        if not re.fullmatch(r"[1-9][0-9]*", values["GITHUB_RUN_ID"]):
            raise ValueError("GITHUB_RUN_ID is invalid")
        if not re.fullmatch(r"[1-9][0-9]*", values["GITHUB_RUN_ATTEMPT"]):
            raise ValueError("GITHUB_RUN_ATTEMPT is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_]+", values["GITHUB_EVENT_NAME"]):
            raise ValueError("GITHUB_EVENT_NAME is invalid")
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", values["GITHUB_REPOSITORY"]):
            raise ValueError("GITHUB_REPOSITORY is invalid")
        if values["GITHUB_SHA"] != checkout_commit:
            raise ValueError("GITHUB_SHA does not equal the current checkout commit")
        producer_partial = _producer_binding_without_invocation(
            binding_mode="github-actions",
            producer_job_id=expected_producer_job,
            runner_os=expected_runner_os,
            profile=expected_profile,
            release_gate_required=release_gate_required,
            run_id=values["GITHUB_RUN_ID"],
            run_attempt=values["GITHUB_RUN_ATTEMPT"],
            event_name=values["GITHUB_EVENT_NAME"],
            repository=values["GITHUB_REPOSITORY"],
            checkout_commit=checkout_commit,
            checkout_tree=checkout_tree,
            baseline_commit=baseline_commit,
            baseline_tree=baseline_tree,
            trust_file_digest=trust_digest,
            command_plan_digest_value=command_plan_digest_value,
        )
        producer_invocation_id = _github_binding_invocation_id(producer_partial)
        verifier_partial = {
            "bindingSchemaVersion": EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION,
            "bindingKind": "VerifierExecutionBinding",
            "bindingMode": "github-actions",
            "verifierJobId": expected_verifier_job,
            "verifierRunnerOS": expected_runner_os,
            "expectedProfile": expected_profile,
            "releaseGateRequired": release_gate_required,
            "expectedProducerJobId": expected_producer_job,
            "runId": values["GITHUB_RUN_ID"],
            "runAttempt": values["GITHUB_RUN_ATTEMPT"],
            "eventName": values["GITHUB_EVENT_NAME"],
            "repository": values["GITHUB_REPOSITORY"],
            "checkoutCommit": checkout_commit,
            "checkoutTree": checkout_tree,
            "baselineCommit": baseline_commit,
            "baselineTree": baseline_tree,
            "trustFileDigest": trust_digest,
            "independentlyRebuiltCommandPlanDigest": command_plan_digest_value,
            "freshRuntimeClosureDigest": fresh_runtime_closure_digest,
        }
        verifier_invocation_id = _github_binding_invocation_id(
            verifier_partial,
            role="verifier",
        )
        binding_mode = "github-actions"
        producer_job_id = expected_producer_job
        verifier_job_id = expected_verifier_job
        runner_os = expected_runner_os
        run_id = values["GITHUB_RUN_ID"]
        run_attempt = values["GITHUB_RUN_ATTEMPT"]
        event_name = values["GITHUB_EVENT_NAME"]
        repository = values["GITHUB_REPOSITORY"]
    else:
        if external_authority.source_kind != "live":
            raise ValueError("synthetic authority cannot construct local production verification")
        if (
            expected_producer_job is not None
            or expected_verifier_job is not None
            or expected_runner_os is not None
        ):
            raise ValueError("local verification cannot claim GitHub workflow jobs or runner OS")
        if not isinstance(expected_invocation_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_invocation_id
        ):
            raise ValueError("local verification requires a 64-hex external invocation identity")
        binding_mode = "local"
        producer_job_id = "local-producer"
        verifier_job_id = "local-verifier"
        runner_os = _canonical_runner_os()
        run_id = "local"
        run_attempt = "1"
        event_name = "local"
        repository = _local_repository_identity(repo_root)
        producer_invocation_id = expected_invocation_id
        verifier_invocation_id = _github_binding_invocation_id(
            {
                "bindingMode": "local",
                "expectedProfile": expected_profile,
                "releaseGateRequired": release_gate_required,
                "producerInvocationId": producer_invocation_id,
                "commandPlanDigest": command_plan_digest_value,
                "freshRuntimeClosureDigest": fresh_runtime_closure_digest,
            },
            role="verifier",
        )

    return ExternallyExpectedVerificationContext(
        binding_mode=binding_mode,
        expected_profile=expected_profile,
        release_gate_required=release_gate_required,
        producer_job_id=producer_job_id,
        verifier_job_id=verifier_job_id,
        runner_os=runner_os,
        run_id=run_id,
        run_attempt=run_attempt,
        event_name=event_name,
        repository=repository,
        checkout_commit=checkout_commit,
        checkout_tree=checkout_tree,
        baseline_commit=baseline_commit,
        baseline_tree=baseline_tree,
        trust_file_digest=trust_digest,
        command_plan_digest=command_plan_digest_value,
        producer_invocation_id=producer_invocation_id,
        fresh_runtime_closure_digest=fresh_runtime_closure_digest,
        verifier_invocation_id=verifier_invocation_id,
    )


def _runner_required_tool(runner: Any, name: str, *, phase: str) -> str:
    narrowed = getattr(runner, "require_tool", None)
    if callable(narrowed):
        return str(narrowed(name, phase=phase))
    tools = getattr(runner, "tools", {})
    errors = getattr(runner, "tool_resolution_errors", ())
    if not isinstance(tools, Mapping):
        raise ToolAuthorityUnavailable(name, phase)
    return require_tool(tools, name, phase=phase, resolution_errors=errors)


def _build_generation_execution_binding(
    runner: Any,
    *,
    external_authority: ExecutionExternalAuthority,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    if not isinstance(external_authority, ExecutionExternalAuthority):
        raise ValueError("explicit external authority is required")
    git = _runner_required_tool(runner, "git", phase="EXECUTION_BINDING")
    checkout_commit, checkout_tree = current_checkout_identity(
        git=git,
        environment=runner.child_environment,
        repo_root=repo_root,
    )
    _manifest, trust_digest = ci_trust_file_set_authority(
        git=git,
        environment=runner.child_environment,
        repo_root=repo_root,
    )
    if external_authority.binding_mode == "github-actions":
        producer_job_id = external_authority.job_id
        authority = _workflow_authority_for_producer(producer_job_id)
        if authority is None:
            raise ValueError("generation job is outside fixed producer authority")
        runner_os = external_authority.runner_os
        if authority["runnerOS"] != runner_os or authority["profile"] != runner.profile:
            raise ValueError("producer job/profile/OS authority mismatch")
        values = {
            "GITHUB_RUN_ID": external_authority.run_id,
            "GITHUB_RUN_ATTEMPT": external_authority.run_attempt,
            "GITHUB_EVENT_NAME": external_authority.event_name,
            "GITHUB_REPOSITORY": external_authority.repository,
            "GITHUB_SHA": external_authority.checkout_sha,
        }
        if values["GITHUB_SHA"] != checkout_commit:
            raise ValueError("producer GITHUB_SHA does not equal checkout commit")
        binding_mode = "github-actions"
        run_id = values["GITHUB_RUN_ID"]
        run_attempt = values["GITHUB_RUN_ATTEMPT"]
        event_name = values["GITHUB_EVENT_NAME"]
        repository = values["GITHUB_REPOSITORY"]
    else:
        producer_job_id = "local-producer"
        runner_os = _canonical_runner_os()
        binding_mode = "local"
        run_id = "local"
        run_attempt = "1"
        event_name = "local"
        repository = _local_repository_identity(repo_root)
    partial = _producer_binding_without_invocation(
        binding_mode=binding_mode,
        producer_job_id=producer_job_id,
        runner_os=runner_os,
        profile=str(runner.profile),
        release_gate_required=getattr(runner, "release_gate_required", None),
        run_id=run_id,
        run_attempt=run_attempt,
        event_name=event_name,
        repository=repository,
        checkout_commit=checkout_commit,
        checkout_tree=checkout_tree,
        baseline_commit=str(runner.baseline["baselineCommit"]),
        baseline_tree=str(runner.baseline["baselineTree"]),
        trust_file_digest=trust_digest,
        command_plan_digest_value=str(runner.command_plan_digest),
    )
    partial["producerInvocationId"] = (
        _github_binding_invocation_id(partial)
        if binding_mode == "github-actions"
        else hashlib.sha256(uuid.uuid4().bytes + os.urandom(32)).hexdigest()
    )
    return partial


def build_generation_execution_binding(
    runner: Any,
    *,
    external_authority: ExecutionExternalAuthority,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    """Build a production binding only from a once-captured live authority."""

    if external_authority.source_kind != "live":
        raise ValueError("synthetic external authority is forbidden in production binding")
    return _build_generation_execution_binding(
        runner,
        external_authority=external_authority,
        repo_root=repo_root,
    )


def build_synthetic_generation_execution_binding(
    runner: Any,
    *,
    external_authority: ExecutionExternalAuthority,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    """Test-only binding path; production CLI never calls this function."""

    if external_authority.source_kind != "synthetic-test":
        raise ValueError("synthetic binding requires test-only external authority")
    return _build_generation_execution_binding(
        runner,
        external_authority=external_authority,
        repo_root=repo_root,
    )


def rebuild_external_verification_context(
    context: ExternallyExpectedVerificationContext,
    runner: Any,
    *,
    repo_root: Path = REPO_ROOT,
) -> ExternallyExpectedVerificationContext:
    external_authority = getattr(runner, "execution_external_authority", None)
    if not isinstance(external_authority, ExecutionExternalAuthority):
        raise ValueError("verification runner lacks frozen external authority")
    return build_externally_expected_verification_context(
        expected_profile=context.expected_profile,
        release_gate_required=context.release_gate_required,
        expected_producer_job=(
            context.producer_job_id if context.binding_mode == "github-actions" else None
        ),
        expected_verifier_job=(
            context.verifier_job_id if context.binding_mode == "github-actions" else None
        ),
        expected_runner_os=(context.runner_os if context.binding_mode == "github-actions" else None),
        expected_invocation_id=(
            context.producer_invocation_id if context.binding_mode == "local" else None
        ),
        command_plan_digest_value=str(runner.command_plan_digest),
        fresh_runtime_closure_digest=str(runner.runtime_closure_digest),
        baseline=runner.baseline,
        git=_runner_required_tool(runner, "git", phase="EXECUTION_BINDING"),
        child_environment=runner.child_environment,
        external_authority=external_authority,
        repo_root=repo_root,
    )


def parse_static_machine_report(
    data: bytes,
    *,
    expected_invocation_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Parse one producer-bound UTF-8 JSON document with exact framing."""

    errors: list[str] = []
    if data.startswith(b"\xef\xbb\xbf"):
        return None, ["static machine stdout must not contain a BOM"]
    if not data.endswith(b"\n") or data.endswith(b"\r\n"):
        return None, ["static machine stdout must end in exactly one LF"]
    body = data[:-1]
    if not body or body[:1] != b"{" or body.endswith((b" ", b"\t", b"\r", b"\n")):
        return None, ["static machine stdout has a prefix or suffix outside the JSON document"]
    try:
        value = strict_json_loads(body, label="static machine stdout")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return None, [f"static machine stdout is not strict UTF-8 JSON: {type(exc).__name__}"]
    expected_keys = {
        "documentKind",
        "schemaVersion",
        "invocationId",
        "executionStatus",
        "commandPlanDigest",
        "commandResults",
        "observations",
        "nativeNonPassCount",
        "internalRunnerFailures",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        return None, ["static machine report top-level schema is not exact"]
    if value.get("documentKind") != STATIC_MACHINE_DOCUMENT_KIND:
        errors.append("static machine report documentKind is invalid")
    if type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != STATIC_MACHINE_SCHEMA_VERSION:
        errors.append("static machine report schemaVersion is invalid")
    if value.get("invocationId") != expected_invocation_id:
        errors.append("static machine report invocationId does not match the parent invocation")
    if value.get("executionStatus") != "COMPLETE":
        errors.append("static machine report executionStatus is not COMPLETE")
    digest = value.get("commandPlanDigest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        errors.append("static machine report commandPlanDigest is invalid")
    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) > 10_000:
        errors.append("static machine report observations must be a bounded array")
        observations = []
    malformed: list[int] = []
    for index, result in enumerate(observations):
        if (
            not isinstance(result, dict)
            or set(result) != {"name", "status", "detail"}
            or not isinstance(result.get("name"), str)
            or result.get("status") not in {"pass", "fail"}
        ):
            malformed.append(index)
    if malformed:
        errors.append(f"static machine report contains malformed observations: {malformed[:10]}")
    native_non_pass_count = value.get("nativeNonPassCount")
    if type(native_non_pass_count) is not int or not 0 <= native_non_pass_count <= 10_000:
        errors.append("static machine report nativeNonPassCount is invalid")
        native_non_pass_count = -1
    internal_failures = value.get("internalRunnerFailures")
    if not isinstance(internal_failures, list) or internal_failures:
        errors.append("COMPLETE static machine report must have no internalRunnerFailures")
    command_results = value.get("commandResults")
    command_required = {
        "commandId",
        "ordinal",
        "commandClass",
        "required",
        "profile",
        "platform",
        "argv",
        "cwd",
        "toolRole",
        "resolvedExecutablePath",
        "resolvedExecutableSize",
        "resolvedExecutableSha256",
        "targets",
        "resultSemantics",
        "allowedExecutionExits",
        "started",
        "executed",
        "exitCode",
        "timeoutStatus",
        "outputLimitStatus",
        "containmentStatus",
    }
    if not isinstance(command_results, list) or not 1 <= len(command_results) <= MAX_PROFILE_COMMANDS:
        errors.append("static machine report commandResults must be a non-empty bounded array")
        command_results = []
    for index, record in enumerate(command_results):
        label = f"static machine commandResults[{index}]"
        if not isinstance(record, dict) or set(record) != command_required:
            errors.append(f"{label} schema is not exact")
            continue
        if type(record.get("ordinal")) is not int or record.get("ordinal") != index:
            errors.append(f"{label} ordinal is invalid")
        if record.get("required") is not True or record.get("started") is not True or record.get("executed") is not True:
            errors.append(f"{label} did not execute as required")
        allowed_exits = record.get("allowedExecutionExits")
        if (
            not isinstance(allowed_exits, list)
            or not allowed_exits
            or any(type(exit_code) is not int for exit_code in allowed_exits)
            or type(record.get("exitCode")) is not int
            or record.get("exitCode") not in allowed_exits
        ):
            errors.append(f"{label} exitCode is outside immutable authority")
        if record.get("timeoutStatus") != "within-limit" or record.get("outputLimitStatus") != "within-limit":
            errors.append(f"{label} has an execution-limit failure")
        if record.get("containmentStatus") != "parent-contained":
            errors.append(f"{label} containment state is invalid")
    errors.extend(_bounded_evidence_json(value, label="static-machine-report"))
    if not malformed:
        result_failures = sum(result.get("status") != "pass" for result in observations)
        if native_non_pass_count != result_failures:
            errors.append("static machine nativeNonPassCount contradicts observations")
    return (value if not errors else None), sorted(set(errors))


def nested_skip(detail: Any) -> bool:
    if isinstance(detail, Mapping):
        if detail.get("skipped") is True or str(detail.get("status", "")).lower() == "skipped":
            return True
        return any(nested_skip(value) for value in detail.values())
    if isinstance(detail, list):
        return any(nested_skip(value) for value in detail)
    return False


def node_failure_count(text: str) -> int | None:
    normalized = normalize_text(text)
    matches = re.findall(r"(?im)^[#ℹ]\s*fail\s+(\d+)\s*$", normalized)
    if matches:
        return int(matches[-1])
    return None


def _normalize_failure_path(value: str) -> str:
    normalized = strip_terminal_controls(value).replace("\\", "/").strip()
    normalized = re.sub(r"(?i)^.*?\((?=(?:file:///)?(?:[A-Z]:/|/))", "", normalized)
    normalized = re.sub(r"(?i)^(?:test\s+at|at)\s+", "", normalized)
    normalized = re.sub(r"(?i)^file:///", "", normalized)
    if normalized.startswith("<repo>/"):
        normalized = normalized[len("<repo>/") :]
    normalized = re.sub(r"(?i)^([A-Z]):/+", r"\1:/", normalized)
    normalized = re.sub(r"/+", "/", normalized)
    repo = str(REPO_ROOT.resolve()).replace("\\", "/")
    normalized = re.sub(rf"(?i)^{re.escape(repo)}/?", "", normalized)
    normalized = normalized.lstrip("./")
    if normalized.casefold() == "node.js":
        return ""
    if re.match(r"(?i)^[A-Z]:/", normalized):
        drive_removed = normalized[3:]
        normalized = f"<external>/{drive_removed}"
    return normalized


def _deduplicate_locations(values: Iterable[str]) -> list[str]:
    unique = sorted(set(values))
    result: list[str] = []
    for value in unique:
        if ":" not in value and any(candidate.startswith(value + ":") for candidate in unique):
            continue
        if re.search(r":\d+$", value) and any(candidate.startswith(value + ":") for candidate in unique):
            continue
        result.append(value)
    return result


def extract_failure_identity(
    scope: str,
    *,
    stdout: str = "",
    stderr: str = "",
    structured: Any | None = None,
    path_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if structured is not None:
        identity = {
            "scope": scope,
            "structuredFailureSet": structured_signature(structured),
        }
        if path_authority is not None:
            identity["pathAuthority"] = copy.deepcopy(path_authority)
        return identity

    source = strip_terminal_controls("\n".join(part for part in (stdout, stderr) if part))
    source = source.replace("\\", "/")
    test_ids: set[str] = set()
    locations: list[str] = []
    assertion_names: set[str] = set()
    expected_values: set[str] = set()
    observed_values: set[str] = set()
    error_classes: set[str] = set()
    error_messages: set[str] = set()

    for match in REPO_SOURCE_LOCATION.finditer(source):
        normalized = _normalize_failure_path(match.group(0))
        if normalized:
            locations.append(normalized)
    for match in re.finditer(
        r"(?im)^[✖x]\s+([^\n(]+\.(?:cjs|js|mjs|py|ps1|sh))(?:\s+\(|\s*$)",
        source,
    ):
        test_ids.add(_normalize_failure_path(match.group(1)))
    for match in re.finditer(r"(?im)^not ok\s+\d+\s+-\s+(.+?)\s*$", source):
        test_ids.add(sanitize_text(match.group(1)).strip())

    for match in re.finditer(
        r"(?m)\b([A-Za-z][A-Za-z0-9_]*(?:Error|Exception))(?:\s*\[([A-Z0-9_]+)\])?\s*:\s*([^\n]+)",
        source,
    ):
        class_name = match.group(1)
        if match.group(2):
            class_name += f"[{match.group(2)}]"
        error_classes.add(class_name)
        message = sanitize_text(match.group(3)).strip()
        if message:
            error_messages.add(message)
            assertion_names.add(message)
    for match in re.finditer(r'(?i)"detail"\s*:\s*"([^"\n]+)"', source):
        detail = sanitize_text(match.group(1)).strip()
        if detail:
            error_messages.add(detail)
            assertion_names.add(detail)
    for match in re.finditer(r"(?im)^\s*(?:assertion|assertion name)\s*[:=]\s*(.+?)\s*$", source):
        assertion_names.add(sanitize_text(match.group(1)).strip())
    for label, target in (
        (r"actual|observed|received", observed_values),
        (r"expected", expected_values),
    ):
        for match in re.finditer(rf"(?im)^\s*(?:{label})\s*:\s*(.+?)\s*,?\s*$", source):
            target.add(sanitize_text(match.group(1)).strip().strip("',\""))
    for match in re.finditer(r"(?m)^\s*(.+?)\s*!==\s*(.+?)\s*$", source):
        observed_values.add(sanitize_text(match.group(1)).strip().strip("',\""))
        expected_values.add(sanitize_text(match.group(2)).strip().strip("',\""))

    identity = {
        "scope": scope,
        "testIds": sorted(value for value in test_ids if value),
        "fileLocations": _deduplicate_locations(locations),
        "assertionNames": sorted(value for value in assertion_names if value),
        "expectedValues": sorted(value for value in expected_values if value),
        "observedValues": sorted(value for value in observed_values if value),
        "errorClasses": sorted(error_classes),
        "errorMessages": sorted(error_messages),
    }
    if path_authority is not None:
        identity["pathAuthority"] = copy.deepcopy(path_authority)
    return identity


def _structured_failure_fragments(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [
            fragment
            for key in sorted(value, key=lambda item: str(item))
            for fragment in _structured_failure_fragments(value[key])
        ]
    if isinstance(value, list):
        return [fragment for item in value for fragment in _structured_failure_fragments(item)]
    if not isinstance(value, str):
        return [str(value)]

    decoder = json.JSONDecoder()
    for index, character in enumerate(value):
        if character not in "[{":
            continue
        try:
            decoded, end = decoder.raw_decode(value[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(decoded, (Mapping, list)):
            continue
        outer = (value[:index] + value[index + end :]).strip()
        fragments = _structured_failure_fragments(decoded)
        if outer:
            fragments.append(outer)
        return fragments
    return [value]


def structured_failure_identity(
    scope: str,
    detail: Any,
    *,
    path_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    identity = extract_failure_identity(
        scope,
        stdout="\n".join(_structured_failure_fragments(detail)),
        path_authority=path_authority,
    )
    test_ids = set(identity["testIds"])
    for location in identity["fileLocations"]:
        path = re.sub(r":\d+(?::\d+)?$", "", location)
        if re.search(r"(?i)(?:^|/)tests?/.*(?:test|spec)\.(?:cjs|js|mjs|py)$", path):
            test_ids.add(path)
    identity["testIds"] = sorted(test_ids)
    identity["structuredFailureSet"] = structured_signature(detail)
    return identity


def failure_identity_hash(identity: Mapping[str, Any]) -> str:
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"sha256:{sha256_text(canonical)}"


KNOWN_SYNTAX_FAILURES = MappingProxyType(
    {
        "assets/generated/reading-explanations/p1-high-194.js": (
            24,
            "SyntaxError",
            "Unexpected identifier '行会'",
            "SyntaxError: Unexpected identifier '行会'",
        ),
        "assets/generated/reading-explanations/p3-low-151.js": (
            125,
            "SyntaxError",
            "Unexpected identifier 'Ice'",
            "SyntaxError: Unexpected identifier 'Ice'",
        ),
        "developer/tests/js/performanceBaseline.js": (
            426,
            "SyntaxError",
            "Unexpected identifier 'testDataProcessingPerformance'",
            "SyntaxError: Unexpected identifier 'testDataProcessingPerformance'",
        ),
        "developer/tests/js/stateSerializerTest.js": (
            443,
            "SyntaxError",
            "Unexpected token 'class'",
            "SyntaxError: Unexpected token 'class'",
        ),
    }
)


KNOWN_STATIC_FAILURES = MappingProxyType(
    {
        "result:套题模式状态机回归测试": {
            "testIds": ["developer/tests/js/suiteModeRegression.test.js"],
            "fileLocations": ["developer/tests/js/suiteModeRegression.test.js:667:16"],
            "assertionNames": ["sessionId 不一致时仍应路由模拟导航"],
            "expectedValues": ["1"],
            "observedValues": ["0"],
            "errorClasses": ["AssertionError[ERR_ASSERTION]"],
            "errorMessages": ["sessionId 不一致时仍应路由模拟导航"],
            "signature": "sha256:238122c8a9d7f99eb1767d2656038644234a3d0f8d2492a573740eadbb635817",
        }
    }
)


KNOWN_NODE_FAILURES = MappingProxyType(
    {
        "file:developer/tests/js/adminFrontendGuard.test.js": {
            "testIds": ["developer/tests/js/adminFrontendGuard.test.js"],
            "fileLocations": [
                "backend/admin/admin.js:83:44",
                "backend/admin/admin.js:874:3",
                "developer/tests/js/adminFrontendGuard.test.js:113:4",
                "developer/tests/js/adminFrontendGuard.test.js:1:1",
            ],
            "assertionNames": ["document.querySelectorAll is not a function"],
            "expectedValues": [],
            "observedValues": [],
            "errorClasses": ["TypeError"],
            "errorMessages": ["document.querySelectorAll is not a function"],
            "signature": "TypeError:document.querySelectorAll-is-not-a-function",
        },
        "file:developer/tests/js/remotePracticeDataSource.test.js": {
            "testIds": ["developer/tests/js/remotePracticeDataSource.test.js"],
            "fileLocations": ["developer/tests/js/remotePracticeDataSource.test.js:1:1"],
            "assertionNames": ["apiClient.disableTotp is not a function"],
            "expectedValues": [],
            "observedValues": [],
            "errorClasses": [],
            "errorMessages": ["apiClient.disableTotp is not a function"],
            "signature": "TypeError:apiClient.disableTotp-is-not-a-function",
        },
        "file:developer/tests/js/localDataRenderingGuard.test.js": {
            "testIds": ["developer/tests/js/localDataRenderingGuard.test.js"],
            "fileLocations": [
                "developer/tests/js/localDataRenderingGuard.test.js:1:1",
                "developer/tests/js/localDataRenderingGuard.test.js:566:1",
            ],
            "assertionNames": [
                "vocab store must cap stored list size, normalize long imported word fields, and return defensive clones"
            ],
            "expectedValues": ["true"],
            "observedValues": ["false"],
            "errorClasses": ["AssertionError[ERR_ASSERTION]"],
            "errorMessages": [
                "vocab store must cap stored list size, normalize long imported word fields, and return defensive clones"
            ],
            "signature": "AssertionError:vocab-store-source-CRLF-assertion",
        },
    }
)

# Run-6 R03 adjudication binds each affected frozen scope to one exact
# repository-relative producer target.  This is deliberately separate from
# the baseline signature: a privacy token or matching message cannot prove
# that the observed path referred to this target.
R03_FAILURE_TARGETS = MappingProxyType(
    {
        "result:Reading 逐题自动排查（quick）": (
            "developer/tests/e2e/reading_question_audit.py"
        ),
        "result:模拟模式 NB 拖拽回灌回归测试": (
            "developer/tests/e2e/simulation_nb_drag_regression.py"
        ),
        "result:模拟模式切题回灌回归测试": (
            "developer/tests/e2e/simulation_roundtrip_restore_regression.py"
        ),
        "result:统一阅读提交只读高亮回归测试": (
            "developer/tests/e2e/unified_submit_readonly_regression.py"
        ),
        "result:Practice 自定义卡片守卫": (
            "developer/tests/js/practiceCustomCard.test.js"
        ),
        "result:按需入口回归测试": (
            "developer/tests/js/onDemandEntrypoints.test.js"
        ),
        "file:developer/tests/js/adminFrontendGuard.test.js": (
            "developer/tests/js/adminFrontendGuard.test.js"
        ),
        "file:developer/tests/js/localDataRenderingGuard.test.js": (
            "developer/tests/js/localDataRenderingGuard.test.js"
        ),
    }
)

# Release-only producers report an absent repository-root checklist by its
# physical snapshot path.  The missing path is intentionally not part of the
# materialized target bundle, so it needs a separate, exact scope-to-path
# authority before frozen-v1 signature derivation.  This must remain a closed
# map: it is not authority to translate arbitrary snapshot descendants.
RELEASE_ONLY_SKIP_FAILURE_TARGETS = MappingProxyType(
    {
        "result:PDF 对账与回归审计": "checklist.md",
        "result:Checklist 对账一致性校验": "checklist.md",
    }
)

# Run-7 R11 binds only the three P144 known-debt manifestations to their
# already-frozen targets.  These entries do not authorize a new debt or a
# basename/root heuristic: every path canonicalization below still requires
# the complete authority root plus the complete repository-relative target.
R11_KNOWN_DEBT_FAILURE_TARGETS = MappingProxyType(
    {
        "result:套题模式状态机回归测试": (
            "developer/tests/js/suiteModeRegression.test.js"
        ),
        "file:developer/tests/js/adminFrontendGuard.test.js": (
            "developer/tests/js/adminFrontendGuard.test.js"
        ),
        "file:developer/tests/js/localDataRenderingGuard.test.js": (
            "developer/tests/js/localDataRenderingGuard.test.js"
        ),
    }
)

R11_POSIX_FILE_URI_TARGETS = frozenset(
    {
        "developer/tests/js/adminFrontendGuard.test.js",
        "developer/tests/js/suiteModeRegression.test.js",
    }
)

R11_WINDOWS_ENCODED_SHORT_NAME_URI_TARGETS = frozenset(
    {
        "developer/tests/js/adminFrontendGuard.test.js",
        "developer/tests/js/localDataRenderingGuard.test.js",
    }
)


def _r03_legacy_static_signature_projection(value: Any, logical_target: str) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _r03_legacy_static_signature_projection(child, logical_target)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _r03_legacy_static_signature_projection(child, logical_target)
            for child in value
        ]
    if not isinstance(value, str):
        return value
    token = f"<repo>/{logical_target}"
    return re.sub(
        re.escape(token) + r"(?![A-Za-z0-9_.%+@~/?#\\-])",
        "<abs-path>",
        value,
    )


def static_failure_signature(
    scope: str,
    detail: Any,
    identity: Mapping[str, Any],
) -> str:
    known = KNOWN_STATIC_FAILURES.get(scope)
    if known is not None:
        comparable = {
            key: value
            for key, value in identity.items()
            if key not in {"structuredFailureSet", "pathAuthority"}
        }
        expected = {"scope": scope, **{key: value for key, value in known.items() if key != "signature"}}
        if comparable == expected:
            return str(known["signature"])
    expected_target = R03_FAILURE_TARGETS.get(scope)
    path_binding = identity.get("pathAuthority")
    if (
        expected_target is not None
        and isinstance(path_binding, Mapping)
        and path_binding.get("authorizedTargetPaths") == [expected_target]
        and not path_binding.get("unmappedAbsolutePathDigests")
        and not path_binding.get("literalPlaceholderDigests")
    ):
        return structured_signature(
            _r03_legacy_static_signature_projection(detail, expected_target)
        )
    return structured_signature(detail)


def node_failure_signature(
    scope: str,
    output: str,
    *,
    path_authority: Mapping[str, Any] | None = None,
) -> str:
    identity = extract_failure_identity(
        scope,
        stdout=output,
        path_authority=path_authority,
    )
    known = KNOWN_NODE_FAILURES.get(scope)
    if known is not None and node_failure_count(output) == 1:
        expected_identity = {"scope": scope, **{key: value for key, value in known.items() if key != "signature"}}
        comparable = {key: value for key, value in identity.items() if key != "pathAuthority"}
        if comparable == expected_identity:
            return str(known["signature"])
    return failure_identity_hash(identity)


def learner_failure_signature(output: str) -> str:
    normalized = sanitize_text(output)
    lower = normalized.lower()
    identity = extract_failure_identity("command:learner-focused-runtime", stdout=output)
    fail_count = node_failure_count(normalized)
    if (
        "executable doesn't exist" in lower
        or "browser executable" in lower
        or ("playwright install" in lower and "browsertype.launch" in lower)
    ) and fail_count in (None, 1) and len(identity["testIds"]) <= 1 and len(identity["errorMessages"]) <= 1:
        return "learner-browser-executable-unavailable"
    return failure_identity_hash(identity)


def syntax_failure_signature(scope: str, stderr: str, stdout: str) -> str:
    identity = extract_failure_identity(scope, stdout=stdout, stderr=stderr)
    known = KNOWN_SYNTAX_FAILURES.get(scope)
    if known is not None:
        line_number, error_class, message, signature = known
        expected = {
            "scope": scope,
            "testIds": [],
            "fileLocations": [f"{scope}:{line_number}"],
            "assertionNames": [message],
            "expectedValues": [],
            "observedValues": [],
            "errorClasses": [error_class],
            "errorMessages": [message],
        }
        if identity == expected:
            return signature
    return failure_identity_hash(identity)


def command_output_digest(record: Mapping[str, Any]) -> str:
    static_identity = _validated_static_machine_output_identity(record)
    stdout_identity = static_identity if static_identity is not None else record
    return canonical_failure_digest(
        {
            "stdoutSha256": stdout_identity.get("stdoutSha256"),
            "stderrSha256": record.get("stderrSha256"),
            "stdoutBytesObserved": stdout_identity.get("stdoutBytesObserved"),
            "stderrBytesObserved": record.get("stderrBytesObserved"),
        }
    )


def _validated_static_machine_output_identity(
    record: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project only a completed static machine report bound to local authority.

    Raw stream hashes remain in execution evidence. A report cannot authorize
    semantic stream identity merely by supplying a digest: reconstruct its
    exact local producer plan from the independently verified parent command.
    """

    report = record.get("validatedStaticMachineReport")
    if (
        not isinstance(report, Mapping)
        or record.get("commandId") != "static-suite"
        or record.get("commandClass") != "static-suite"
        or record.get("resultSemantics") != "machine-v2-complete-execution"
        or record.get("executed") is not True
        or record.get("started") is not True
        or record.get("setupFailure") is not False
        or record.get("exitCode") != 0
        or record.get("timeoutStatus") != "within-limit"
        or record.get("outputLimitStatus") != "within-limit"
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("processTreeError") is not None
        or record.get("descendantsSurviving") != 0
    ):
        return None
    invocation_id = report.get("invocationId")
    argv = [
        record.get("resolvedExecutablePath"), "-B", STATIC_SUITE_RELATIVE_PATH,
        "--ci-machine-json-stdout", "--ci-invocation-id", invocation_id,
    ]
    if (
        not isinstance(invocation_id, str)
        or any(record.get(key) != argv for key in (
            "argv", "logicalArgv", "executionArgv", "actualExecutionArgv",
        ))
        or record.get("toolRole") != "python-static-producer"
    ):
        return None
    targets = record.get("targets")
    if not isinstance(targets, list):
        return None
    protected = record.get("protectedTargetBundle")
    if (
        record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or not isinstance(protected, Mapping)
        or protected.get("mutationDetected") is not False
        or protected.get("cleanupState") != "closed"
    ):
        return None
    pre = protected.get("preExecutionIdentities")
    post = protected.get("postExecutionIdentities")
    valid_full_identities = (
        pre == post
        and _full_protected_identity_array_matches_authority(record, pre)
        and _full_protected_identity_array_matches_authority(record, post)
    )
    valid_compact_identities = (
        bool(targets)
        and all(protected.get(key) == [] for key in _PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS)
        and pre == _protected_bundle_compact_identity_digests(record, phase="pre")
        and post == _protected_bundle_compact_identity_digests(record, phase="post")
    )
    if not valid_full_identities and not valid_compact_identities:
        return None
    static_targets = [
        target for target in targets
        if isinstance(target, Mapping) and target.get("path") == STATIC_SUITE_RELATIVE_PATH
    ]
    if len(static_targets) != 1:
        return None
    static_target = static_targets[0]
    expected_plan = [{
        "commandId": "static-check-registry",
        "ordinal": 0,
        "commandClass": "static-machine-producer",
        "required": True,
        "profile": "static",
        "platform": record.get("platform"),
        "argv": argv,
        "cwd": ".",
        "toolRole": "python-static-producer",
        "resolvedExecutablePath": record.get("resolvedExecutablePath"),
        "resolvedExecutableSize": record.get("resolvedExecutableSize"),
        "resolvedExecutableSha256": record.get("resolvedExecutableSha256"),
        "targets": [{key: static_target.get(key) for key in ("path", "size", "sha256")}],
        "resultSemantics": "complete-registry-execution-with-native-observations",
        "allowedExecutionExits": [0],
    }]
    try:
        validated, errors = parse_static_machine_report(
            _json_bytes(report), expected_invocation_id=invocation_id,
        )
        if validated is None or errors:
            return None
        authority_keys = set(expected_plan[0])
        reported_plan = [
            {key: value for key, value in result.items() if key in authority_keys}
            for result in validated["commandResults"]
        ]
        if (
            reported_plan != expected_plan
            or validated["commandPlanDigest"] != static_machine_command_plan_digest(expected_plan)
        ):
            return None
        semantic_report = copy.deepcopy(validated)
        # The local nested plan was checked exactly above. Bind the same tool
        # bytes/targets/argv through the established portable plan projection.
        semantic_report["commandResults"] = _portable_command_plan_value(
            validated["commandResults"]
        )
        semantic_report["commandPlanDigest"] = command_plan_digest(expected_plan)
        semantic_report = normalized_json_value(semantic_report)
        canonical = _json_bytes(semantic_report)
    except (TypeError, ValueError, UnicodeError):
        return None
    return {
        "stdoutSha256": hashlib.sha256(canonical).hexdigest(),
        "stdoutBytesObserved": len(canonical),
        "validatedStaticMachineReport": semantic_report,
    }


def command_capture_output_digest(capture: CommandCapture) -> str:
    return command_output_digest(capture.evidence())


def _normalize_node_stdin_diagnostics(scope: str, value: str) -> str:
    normalized = strip_terminal_controls(value)
    return normalized.replace("[stdin]", scope).replace("file:///[stdin]", scope)


def _failure_members(identity: Mapping[str, Any]) -> list[dict[str, Any]]:
    fixed_kinds = (
        "scope",
        "testIds",
        "fileLocations",
        "assertionNames",
        "expectedValues",
        "observedValues",
        "errorClasses",
        "errorMessages",
        "structuredFailureSet",
        "resultStatus",
        "missingIndexScripts",
    )
    members: list[dict[str, Any]] = []
    member_kinds = [*fixed_kinds, *sorted(set(identity) - set(fixed_kinds))]
    for member_kind in member_kinds:
        if member_kind not in identity:
            members.append(
                {
                    "memberKind": member_kind,
                    "memberOrdinal": 0,
                    "presence": "absent",
                    "value": None,
                }
            )
            continue
        raw_value = identity[member_kind]
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        if not values:
            members.append(
                {
                    "memberKind": member_kind,
                    "memberOrdinal": 0,
                    "presence": "absent",
                    "value": None,
                }
            )
            continue
        for ordinal, value in enumerate(values):
            members.append(
                {
                    "memberKind": member_kind,
                    "memberOrdinal": ordinal,
                    "presence": "present",
                    "value": normalized_json_value(value),
                }
            )
    return members


def _raw_failure_outputs(
    raw: Mapping[str, Any],
    command_record: Mapping[str, Any],
) -> dict[str, Any]:
    kind = str(raw.get("observationKind", ""))
    fields = raw.get("rawStructuredFields")
    command_class = str(command_record.get("commandClass", ""))
    source_result_id = str(raw.get("sourceResultId", ""))
    path_authority = raw.get("failurePathAuthority")
    if not isinstance(path_authority, Mapping):
        path_authority = None
    parser_semantics = ""
    identity: dict[str, Any] | None = None

    if kind == "static-producer-v1" and isinstance(fields, Mapping):
        parser_semantics = "static-machine-result-v1"
        name = str(fields.get("name", ""))
        scope = f"result:{name}"
        status = fields.get("status")
        detail = fields.get("detail")
        if status == "pass" and nested_skip(detail):
            outcome = "skip"
        else:
            outcome = "pass" if status == "pass" else "fail"
        if outcome == "pass":
            identity = {"scope": scope, "resultStatus": "pass"}
            signature = "pass"
        else:
            identity = structured_failure_identity(
                scope,
                detail,
                path_authority=path_authority,
            )
            if outcome == "skip" and source_result_id in FROZEN_V1_RELEASE_SKIP_DETAIL_FIELDS:
                signature = derive_frozen_v1_release_skip_signature(raw)
            else:
                signature = static_failure_signature(scope, detail, identity)
    elif kind == "process-output-v1" and isinstance(fields, Mapping):
        parser_semantics = f"{command_class}-process-result-v1"
        scope = source_result_id
        stdout = str(fields.get("stdout", ""))
        stderr = str(fields.get("stderr", ""))
        executed = fields.get("executed") is True
        exit_code = fields.get("exitCode")
        if command_class == "direct-syntax":
            stdout = _normalize_node_stdin_diagnostics(scope, stdout)
            stderr = _normalize_node_stdin_diagnostics(scope, stderr)
            if not executed:
                outcome = "unavailable"
                signature = "required-executable-unavailable:node"
            elif exit_code == 0:
                outcome = "pass"
                signature = "pass"
            else:
                outcome = "syntax-error"
                signature = syntax_failure_signature(scope, stderr, stdout)
        elif command_class == "frontend-security":
            if not executed:
                outcome = "unavailable"
                signature = "required-executable-unavailable:node"
            elif exit_code == 0:
                outcome = "pass"
                signature = "pass"
            else:
                outcome = "fail"
                signature = node_failure_signature(
                    scope,
                    stdout + "\n" + stderr,
                    path_authority=path_authority,
                )
        elif command_class == "learner-focused":
            if not executed:
                outcome = "unavailable"
                signature = "required-executable-unavailable:node"
            elif exit_code == 0:
                outcome = "pass"
                signature = "pass"
            else:
                signature = learner_failure_signature(stdout + "\n" + stderr)
                outcome = "unavailable" if signature == "learner-browser-executable-unavailable" else "fail"
        elif command_class == "backend-canonical":
            if not executed:
                outcome = "unavailable"
                signature = "required-executable-unavailable:npm"
            elif exit_code == 0:
                outcome = "pass"
                signature = "pass"
            else:
                outcome = "fail"
                identity = extract_failure_identity(
                    scope,
                    stdout=stdout,
                    stderr=stderr,
                    path_authority=path_authority,
                )
                signature = failure_identity_hash(identity)
        else:
            outcome = "pass" if executed and exit_code == 0 else "fail"
            identity = extract_failure_identity(
                scope,
                stdout=stdout,
                stderr=stderr,
                path_authority=path_authority,
            )
            signature = "pass" if outcome == "pass" else failure_identity_hash(identity)
        if identity is None:
            identity = (
                {"scope": scope, "resultStatus": "pass"}
                if outcome == "pass"
                else extract_failure_identity(
                    scope,
                    stdout=stdout,
                    stderr=stderr,
                    path_authority=path_authority,
                )
            )
    elif kind == "standalone-membership-v1" and isinstance(fields, Mapping):
        parser_semantics = "standalone-positive-membership-v1"
        relative = str(fields.get("relative", ""))
        missing = fields.get("missing") is True
        scope = f"membership:index.html::{relative}"
        outcome = "fail" if missing else "pass"
        signature = f"missing:index-script:{relative}" if missing else "pass"
        identity = {
            "scope": scope,
            "missingIndexScripts": [relative] if missing else [],
        }
    elif kind == "normalized-fields-v1" and isinstance(fields, Mapping):
        parser_semantics = "normalized-test-fields-v1"
        scope = source_result_id
        outcome = str(fields.get("outcome", "fail"))
        if outcome == "pass":
            identity = {"scope": scope, "resultStatus": "pass"}
            signature = "pass"
        else:
            identity = {
                str(key): normalized_json_value(value)
                for key, value in fields.items()
                if key not in {"outcome", "message"}
            }
            identity["scope"] = scope
            if path_authority is not None:
                identity["pathAuthority"] = copy.deepcopy(path_authority)
            known_static = KNOWN_STATIC_FAILURES.get(scope)
            known_expected = _known_identity_expected(scope)
            if known_static is not None:
                comparable = {
                    key: value for key, value in identity.items()
                    if key not in {"structuredFailureSet", "pathAuthority"}
                }
                expected = {
                    "scope": scope,
                    **{key: value for key, value in known_static.items() if key != "signature"},
                }
                signature = (
                    str(known_static["signature"])
                    if comparable == expected
                    else failure_identity_hash(identity)
                )
            elif known_expected is not None and identity == known_expected:
                known_syntax = KNOWN_SYNTAX_FAILURES.get(scope)
                if known_syntax is not None:
                    signature = str(known_syntax[3])
                else:
                    known_node = KNOWN_NODE_FAILURES.get(scope)
                    signature = str(known_node["signature"]) if known_node else failure_identity_hash(identity)
            else:
                message = fields.get("message")
                signature = str(message) if isinstance(message, str) and not message.startswith("sha256:") else failure_identity_hash(identity)
    else:
        raise ValueError("raw observation kind or structured fields are invalid")

    if identity is None:
        raise ValueError("raw observation parser did not derive a failure identity")
    members = _failure_members(identity)
    return {
        "commandClass": command_class,
        "testOrPathScope": scope,
        "outcome": outcome,
        "signature": signature,
        "failureIdentity": identity,
        "failureIdentityHash": failure_identity_hash(identity),
        "parserSemantics": parser_semantics,
        "derivedFailureMembers": members,
    }


def derive_canonical_failure_material(
    validated_command_record: Mapping[str, Any],
    validated_raw_observation: Mapping[str, Any],
    parser_semantics: str,
    derived_failure_members: Sequence[Mapping[str, Any]],
    derived_signature: str,
    derived_outcome: str,
    profile_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build baseline-blind failure material from command facts and one raw observation."""

    portable_source = _portable_node_test_observation_source(validated_command_record)
    if portable_source is not validated_command_record:
        raw_set = validated_command_record.get("producerObservations", [])
        if any(validated_raw_observation == raw for raw in raw_set):
            validated_raw_observation = portable_source["producerObservations"][0]
            validated_command_record = _canonical_transcript_record(validated_command_record)
    targets = []
    for target in validated_command_record.get("targets", []):
        if isinstance(target, Mapping):
            targets.append(
                {
                    "path": target.get("path"),
                    "canonicalSourcePath": target.get("canonicalSourcePath"),
                    "size": target.get("size"),
                    "sha256": target.get("sha256"),
                    "fileIdentity": target.get("fileIdentity"),
                    "modeType": target.get("modeType"),
                    "reparsePoint": target.get("reparsePoint"),
                }
            )
    context = dict(profile_context or {})
    return {
        "version": CANONICAL_FAILURE_MATERIAL_VERSION,
        "command": {
            "commandId": validated_command_record.get("commandId"),
            "commandClass": validated_command_record.get("commandClass"),
            "ordinal": validated_command_record.get("ordinal"),
            "platform": validated_command_record.get("platform"),
            "profile": validated_command_record.get("profile"),
            "logicalArgv": validated_command_record.get(
                "logicalArgv", validated_command_record.get("argv")
            ),
            "executionArgv": validated_command_record.get("executionArgv"),
            "cwd": validated_command_record.get("cwd"),
            "toolRole": validated_command_record.get("toolRole"),
            "rawExitCode": validated_command_record.get("exitCode"),
            "resultSemantics": validated_command_record.get("resultSemantics"),
            "executionInputMode": validated_command_record.get("actualExecutionInputMode"),
            "executionInputSize": validated_command_record.get("actualExecutionInputSize"),
            "executionInputSha256": validated_command_record.get("actualExecutionInputSha256"),
            "executionInputs": _canonical_protected_execution_inputs(
                validated_command_record
            ),
            "executionInputBundleDigest": validated_command_record.get(
                "executionInputBundleDigest"
            ),
            "producerObservationSetDigest": validated_command_record.get(
                "producerObservationSetDigest"
            ),
            "completedCommandClass": validated_command_record.get(
                "completedCommandClass"
            ),
            "targets": targets,
        },
        "observation": dict(validated_raw_observation),
        "producerObservationUniverseDigest": context.get(
            "producerObservationUniverseDigest"
        ),
        "producerTranscriptDigest": context.get("producerTranscriptDigest"),
        "profileCompletedCommandClassSetDigest": context.get(
            "profileCompletedCommandClassSetDigest"
        ),
        "authorizationContextBindingDigest": context.get(
            "authorizationContextBindingDigest"
        ),
        "parserSemantics": parser_semantics,
        "derivedOutcome": derived_outcome,
        "legacyBaselineComparisonDigest": derived_signature,
        "derivedFailureMembers": list(derived_failure_members),
    }


def _rederive_observation_record(
    item: Mapping[str, Any],
    command_record: Mapping[str, Any],
    *,
    profile_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    raw = item.get("rawObservation")
    if not isinstance(raw, Mapping):
        raise ValueError("observation lacks a raw producer observation")
    outputs = _raw_failure_outputs(raw, command_record)
    context = dict(
        profile_context
        or {
            "producerObservationUniverseDigest": item.get(
                "producerObservationUniverseDigest"
            ),
            "producerTranscriptDigest": item.get("producerTranscriptDigest"),
            "profileCompletedCommandClassSetDigest": item.get(
                "profileCompletedCommandClassSetDigest"
            ),
        }
    )
    material = derive_canonical_failure_material(
        command_record,
        raw,
        str(outputs["parserSemantics"]),
        outputs["derivedFailureMembers"],
        str(outputs["signature"]),
        str(outputs["outcome"]),
        context,
    )
    current_full_context_digest = canonical_failure_digest(material)
    return {
        "commandClass": outputs["commandClass"],
        "testOrPathScope": outputs["testOrPathScope"],
        "outcome": outputs["outcome"],
        "signature": outputs["signature"],
        "legacyBaselineComparisonDigest": outputs["signature"],
        "commandId": raw.get("commandId"),
        "occurrences": raw.get("occurrences"),
        "rawObservation": dict(raw),
        "producerObservationSetDigest": command_record.get(
            "producerObservationSetDigest"
        ),
        "producerObservationUniverseDigest": context.get(
            "producerObservationUniverseDigest"
        ),
        "producerTranscriptDigest": context.get("producerTranscriptDigest"),
        "completedCommandClass": command_record.get("completedCommandClass"),
        "profileCompletedCommandClassSetDigest": context.get(
            "profileCompletedCommandClassSetDigest"
        ),
        "canonicalFailureMaterialVersion": CANONICAL_FAILURE_MATERIAL_VERSION,
        "derivedFailureDigest": current_full_context_digest,
        "currentFullContextDigest": current_full_context_digest,
        "derivedFailureMembers": outputs["derivedFailureMembers"],
        "failureIdentity": outputs["failureIdentity"],
        "failureIdentityHash": outputs["failureIdentityHash"],
    }


def observation(
    command_class: str,
    scope: str,
    outcome: str,
    signature: str,
    command_id: str,
    *,
    occurrences: int = 1,
    failure_identity: Mapping[str, Any] | None = None,
    raw_observation: Mapping[str, Any] | None = None,
    observation_kind: str = "normalized-fields-v1",
    raw_structured_fields: Any | None = None,
    source_result_id: str | None = None,
    source_path: str | None = None,
    source_output_digest: str | None = None,
    command_ordinal: int = 0,
    observation_ordinal: int = 0,
    command_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if raw_observation is None:
        if raw_structured_fields is None:
            identity = dict(failure_identity or {"scope": scope})
            raw_structured_fields = {
                key: value
                for key, value in identity.items()
                if key not in _DERIVED_FAILURE_FIELD_NAMES
            }
            raw_structured_fields["scope"] = scope
            raw_structured_fields["outcome"] = outcome
            if not signature.startswith("sha256:") and signature not in {"pass", ""}:
                raw_structured_fields["message"] = signature
        if source_output_digest is None:
            source_output_digest = canonical_failure_digest(raw_structured_fields)
        raw_observation = make_raw_observation(
            command_id,
            command_ordinal,
            observation_ordinal,
            observation_kind,
            source_result_id or scope,
            source_path,
            raw_structured_fields,
            source_output_digest,
            occurrences,
        )
    source = dict(command_record or {})
    source.setdefault("commandId", command_id)
    source.setdefault("commandClass", command_class)
    source.setdefault("ordinal", command_ordinal)
    source.setdefault("profile", "static" if command_class in {"static-suite", "direct-syntax"} else "all")
    source.setdefault("platform", platform_key())
    source.setdefault("argv", ["<unknown>"])
    source.setdefault("logicalArgv", source["argv"])
    source.setdefault("executionArgv", source["argv"])
    source.setdefault("cwd", ".")
    source.setdefault("toolRole", "unit-observation")
    source.setdefault("exitCode", 0 if outcome == "pass" else 1)
    source.setdefault("resultSemantics", "fixed-parser-observation")
    source.setdefault("actualExecutionInputMode", "NONE")
    source.setdefault("actualExecutionInputSize", None)
    source.setdefault("actualExecutionInputSha256", None)
    source.setdefault("targets", [])
    return _rederive_observation_record({"rawObservation": dict(raw_observation)}, source)


def entry_applies(entry: Mapping[str, Any], current_platform: str) -> bool:
    platforms = entry.get("platforms", [])
    return "all" in platforms or current_platform in platforms


def _known_identity_expected(scope: str) -> dict[str, Any] | None:
    known_node = KNOWN_NODE_FAILURES.get(scope)
    if known_node is not None:
        return {"scope": scope, **{key: value for key, value in known_node.items() if key != "signature"}}
    known_syntax = KNOWN_SYNTAX_FAILURES.get(scope)
    if known_syntax is not None:
        line_number, error_class, message, _signature = known_syntax
        return {
            "scope": scope,
            "testIds": [],
            "fileLocations": [f"{scope}:{line_number}"],
            "assertionNames": [message],
            "expectedValues": [],
            "observedValues": [],
            "errorClasses": [error_class],
            "errorMessages": [message],
        }
    return None


def _failure_path_authority_matches(
    scope: str,
    identity: Mapping[str, Any],
    *,
    raw_fields: Any,
    source: Mapping[str, Any] | None,
) -> bool:
    expected_target = R03_FAILURE_TARGETS.get(scope)
    release_target = RELEASE_ONLY_SKIP_FAILURE_TARGETS.get(scope)
    if expected_target is None and release_target is None:
        return True
    binding = identity.get("pathAuthority")
    if not isinstance(binding, dict) or set(binding) != FAILURE_PATH_AUTHORITY_KEYS:
        return False
    target_paths = binding.get("authorizedTargetPaths")
    required_target = expected_target or release_target
    if not isinstance(target_paths, list) or required_target not in target_paths:
        return False
    if binding.get("unmappedAbsolutePathDigests") or binding.get(
        "literalPlaceholderDigests"
    ):
        return False
    if release_target is not None:
        return (
            target_paths == [release_target]
            and binding.get("authorizedToolRoles") == []
            and (
                source is None
                or _release_skip_missing_target_is_authorized(
                    source,
                    raw_fields,
                    release_target,
                )
            )
        )
    assert expected_target is not None
    allowed_targets = {expected_target}
    known_node = KNOWN_NODE_FAILURES.get(scope)
    if known_node is not None:
        for key in ("testIds", "fileLocations"):
            for value in known_node.get(key, []):
                if isinstance(value, str):
                    allowed_targets.add(re.sub(r":\d+(?::\d+)?$", "", value))
    return set(target_paths).issubset(allowed_targets)


def _r11_known_debt_path_authority_matches(
    scope: str,
    identity: Mapping[str, Any],
) -> bool:
    expected_target = R11_KNOWN_DEBT_FAILURE_TARGETS.get(scope)
    if expected_target is None:
        return True
    binding = identity.get("pathAuthority")
    if not isinstance(binding, dict) or set(binding) != FAILURE_PATH_AUTHORITY_KEYS:
        return False
    target_paths = binding.get("authorizedTargetPaths")
    if not isinstance(target_paths, list) or expected_target not in target_paths:
        return False
    if binding.get("unmappedAbsolutePathDigests") or binding.get(
        "literalPlaceholderDigests"
    ):
        return False

    allowed_targets = {expected_target}
    known = KNOWN_NODE_FAILURES.get(scope) or KNOWN_STATIC_FAILURES.get(scope)
    if known is not None:
        for key in ("testIds", "fileLocations"):
            for value in known.get(key, []):
                if isinstance(value, str):
                    allowed_targets.add(re.sub(r":\d+(?::\d+)?$", "", value))
    return set(target_paths).issubset(allowed_targets)


def _failure_identity_authorizes(
    entry: Mapping[str, Any],
    item: Mapping[str, Any],
    source_command: Mapping[str, Any] | None = None,
    *,
    authorization_context_binding_digest_value: str | None = None,
) -> bool:
    raw = item.get("rawObservation")
    if not isinstance(raw, dict):
        return False
    baseline_scope = str(entry.get("testOrPathScope", ""))
    if (
        baseline_scope in R03_FAILURE_TARGETS
        or baseline_scope in R11_KNOWN_DEBT_FAILURE_TARGETS
    ) and source_command is None:
        return False
    expected_source = _baseline_source_command_id(entry)
    if expected_source is not None and item.get("commandId") != expected_source:
        return False
    synthetic_source: Mapping[str, Any] = source_command or {
        "commandId": item.get("commandId"),
        "commandClass": item.get("commandClass"),
        "ordinal": raw.get("commandOrdinal"),
        "profile": "static" if item.get("commandClass") in {"static-suite", "direct-syntax"} else "all",
        "platform": "unknown",
        "argv": ["<unknown>"],
        "logicalArgv": ["<unknown>"],
        "executionArgv": ["<unknown>"],
        "cwd": ".",
        "toolRole": "baseline-comparison",
        "exitCode": 0 if item.get("outcome") == "pass" else 1,
        "resultSemantics": "fixed-parser-observation",
        "actualExecutionInputMode": "NONE",
        "actualExecutionInputSize": None,
        "actualExecutionInputSha256": None,
        "targets": [],
    }
    try:
        derived = _rederive_observation_record(
            item,
            synthetic_source,
            profile_context={
                "producerObservationUniverseDigest": item.get(
                    "producerObservationUniverseDigest"
                ),
                "producerTranscriptDigest": item.get("producerTranscriptDigest"),
                "profileCompletedCommandClassSetDigest": item.get(
                    "profileCompletedCommandClassSetDigest"
                ),
                "authorizationContextBindingDigest": (
                    authorization_context_binding_digest_value
                ),
            },
        )
    except (TypeError, ValueError):
        return False
    for field_name in (
        "commandClass",
        "testOrPathScope",
        "outcome",
        "signature",
        "legacyBaselineComparisonDigest",
        "commandId",
        "occurrences",
        "failureIdentity",
        "failureIdentityHash",
        "canonicalFailureMaterialVersion",
        "derivedFailureMembers",
    ):
        if item.get(field_name) != derived.get(field_name):
            return False
    if source_command is not None:
        if item.get("derivedFailureDigest") != derived.get("derivedFailureDigest"):
            return False
        if item.get("currentFullContextDigest") != derived.get("currentFullContextDigest"):
            return False
    if item.get("signature") != item.get("legacyBaselineComparisonDigest"):
        return False
    identity = derived["failureIdentity"]
    scope = baseline_scope
    if not _failure_path_authority_matches(
        scope,
        identity,
        raw_fields=raw.get("rawStructuredFields"),
        source=source_command,
    ):
        return False
    expected_r11_target = R11_KNOWN_DEBT_FAILURE_TARGETS.get(scope)
    if expected_r11_target is not None:
        source_targets = {
            str(target.get("path"))
            for target in source_command.get("targets", [])
            if isinstance(target, Mapping) and isinstance(target.get("path"), str)
        }
        if expected_r11_target not in source_targets:
            return False
        if not _r11_known_debt_path_authority_matches(scope, identity):
            return False
    known_static = KNOWN_STATIC_FAILURES.get(scope)
    if known_static is not None:
        comparable = {
            key: value
            for key, value in identity.items()
            if key not in {"structuredFailureSet", "pathAuthority"}
        }
        expected = {
            "scope": entry.get("testOrPathScope"),
            **{key: value for key, value in known_static.items() if key != "signature"},
        }
        return (
            derived.get("legacyBaselineComparisonDigest") == known_static["signature"]
            and comparable == expected
        )
    expected = _known_identity_expected(scope)
    if expected is not None:
        comparable = {key: value for key, value in identity.items() if key != "pathAuthority"}
        return comparable == expected
    signature = str(item.get("legacyBaselineComparisonDigest", ""))
    if signature.startswith("sha256:"):
        return (
            raw.get("observationKind") == "static-producer-v1"
            and derived.get("legacyBaselineComparisonDigest") == signature
        )
    if signature == "learner-browser-executable-unavailable":
        messages = " ".join(
            str(value)
            for key in ("assertionNames", "errorMessages")
            for value in identity.get(key, [])
        ).casefold()
        return (
            identity.get("scope") == "command:learner-focused-runtime"
            and len(identity.get("testIds", [])) <= 1
            and any(marker in messages for marker in ("browser executable", "executable doesn't exist", "playwright install"))
        )
    return (
        raw.get("observationKind")
        in {"process-output-v1", "standalone-membership-v1"}
        and derived.get("legacyBaselineComparisonDigest") == signature
        and derived.get("testOrPathScope") == entry.get("testOrPathScope")
    )


def _baseline_bound_record(
    collection: str,
    entry: Mapping[str, Any],
    *,
    current_platform: str,
    source_command_id: str,
    observed_outcome: str,
    observed_signature: str,
    failure_identity_hash_value: str,
    derived_failure_digest: str,
    derived_failure_members: Sequence[Mapping[str, Any]],
    occurrences: int,
    status: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "baselineId": entry["id"],
        "id": entry["id"],
        "collection": collection,
        "category": entry["category"],
        "gate": entry["gate"],
        "commandClass": entry["commandClass"],
        "testOrPathScope": entry["testOrPathScope"],
        "expectedOutcome": entry["expectedOutcome"],
        "allowedNormalizedSignature": list(entry["allowedNormalizedSignature"]),
        "maximumOccurrences": entry["maximumOccurrences"],
        "platforms": list(entry["platforms"]),
        "checkpointDisposition": entry["checkpointDisposition"],
        "targetStage": entry["targetStage"],
        "securityImpact": entry["securityImpact"],
        "platform": current_platform,
        "sourceCommandId": source_command_id,
        "observedOutcome": observed_outcome,
        "observedSignature": observed_signature,
        "legacyBaselineComparisonDigest": observed_signature,
        "failureIdentityHash": failure_identity_hash_value,
        "canonicalFailureMaterialVersion": CANONICAL_FAILURE_MATERIAL_VERSION,
        "derivedFailureDigest": derived_failure_digest,
        "currentFullContextDigest": derived_failure_digest,
        "derivedFailureMembers": list(derived_failure_members),
        "occurrences": occurrences,
    }
    if status is not None:
        record["status"] = status
    return record


def compare_observations(
    baseline: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    completed_classes: set[str],
    current_platform: str,
    *,
    release_gate_required: bool = False,
    command_records: Sequence[Mapping[str, Any]] | None = None,
    authorization_context_binding_digest_value: str | None = None,
) -> dict[str, Any]:
    collections = {
        "knownDebts": baseline.get("knownDebts", []),
        "expectedOmissions": baseline.get("expectedOmissions", []),
        "releaseOnlySkips": baseline.get("releaseOnlySkips", []),
    }
    indexed: dict[tuple[str, str], list[tuple[str, Mapping[str, Any]]]] = {}
    for collection_name, entries in collections.items():
        for entry in entries:
            if not entry_applies(entry, current_platform):
                continue
            key = (entry["commandClass"], entry["testOrPathScope"])
            indexed.setdefault(key, []).append((collection_name, entry))

    result: dict[str, Any] = {
        "observedDebts": [],
        "resolvedCandidates": [],
        "expectedOmissions": [],
        "releaseOnlySkips": [],
        "violations": [],
    }
    command_by_id = {
        str(record.get("commandId", "")): record
        for record in (command_records or [])
        if isinstance(record, Mapping) and record.get("commandId")
    }
    observations_by_key: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    aggregates: dict[
        tuple[str, str, str, str, str, str, str, str, str],
        dict[str, Any],
    ] = {}
    for item in observations:
        try:
            key = (str(item["commandClass"]), str(item["testOrPathScope"]))
            raw_occurrences = item.get("occurrences", 1)
            if type(raw_occurrences) is not int:
                raise TypeError("occurrences is not an integer")
            occurrences = raw_occurrences
        except (KeyError, TypeError, ValueError):
            result["violations"].append({"id": "MALFORMED-OBSERVATION"})
            continue
        observations_by_key.setdefault(key, []).append(item)
        if item["outcome"] == "pass":
            continue
        if occurrences < 1:
            result["violations"].append(
                {"id": "MALFORMED-OBSERVATION", "commandClass": key[0], "scope": key[1]}
            )
            continue
        candidates = indexed.get(key, [])
        matched: tuple[str, Mapping[str, Any]] | None = None
        for collection_name, entry in candidates:
            if (
                item["outcome"] == entry["expectedOutcome"]
                and item["legacyBaselineComparisonDigest"]
                in entry["allowedNormalizedSignature"]
                and _failure_identity_authorizes(
                    entry,
                    item,
                    command_by_id.get(str(item.get("commandId", ""))),
                    authorization_context_binding_digest_value=(
                        authorization_context_binding_digest_value
                    ),
                )
            ):
                matched = (collection_name, entry)
                break
        if matched is None:
            result["violations"].append(
                {
                    "id": "UNKNOWN-NONPASS",
                    "commandClass": key[0],
                    "scope": key[1],
                    "outcome": item["outcome"],
                    "signature": item["signature"],
                    "failureIdentityHash": item.get("failureIdentityHash"),
                }
            )
            continue
        collection_name, entry = matched
        aggregate_key = (
            str(entry["id"]),
            key[0],
            key[1],
            current_platform,
            str(item["failureIdentityHash"]),
            str(item["outcome"]),
            str(item["legacyBaselineComparisonDigest"]),
            str(item.get("commandId", "")),
            str(item.get("currentFullContextDigest", "")),
        )
        aggregate = aggregates.setdefault(
            aggregate_key,
            {
                "collection": collection_name,
                "entry": entry,
                "occurrences": 0,
                "derivedFailureMembers": item.get("derivedFailureMembers", []),
            },
        )
        aggregate["occurrences"] += occurrences

    entry_totals: dict[str, int] = defaultdict(int)
    for aggregate_key, aggregate in aggregates.items():
        entry = aggregate["entry"]
        occurrences = int(aggregate["occurrences"])
        entry_totals[str(entry["id"])] += occurrences
        if occurrences > int(entry["maximumOccurrences"]):
            result["violations"].append(
                {
                    "id": "BASELINE-OCCURRENCE-LIMIT",
                    "debtId": entry["id"],
                    "scope": aggregate_key[2],
                    "occurrences": occurrences,
                    "maximumOccurrences": entry["maximumOccurrences"],
                }
            )
            continue
        record = _baseline_bound_record(
            aggregate["collection"],
            entry,
            current_platform=aggregate_key[3],
            source_command_id=aggregate_key[7],
            observed_outcome=aggregate_key[5],
            observed_signature=aggregate_key[6],
            failure_identity_hash_value=aggregate_key[4],
            derived_failure_digest=aggregate_key[8],
            derived_failure_members=aggregate["derivedFailureMembers"],
            occurrences=occurrences,
        )
        if entry.get("currentCiDisposition") == "must-execute" and record["observedOutcome"] == "unavailable":
            result["violations"].append(
                {
                    "id": "REQUIRED-COMMAND-UNAVAILABLE",
                    "debtId": entry["id"],
                    "commandClass": aggregate_key[1],
                    "scope": aggregate_key[2],
                }
            )
        elif aggregate["collection"] == "knownDebts":
            result["observedDebts"].append(record)
        elif aggregate["collection"] == "expectedOmissions":
            result["expectedOmissions"].append(record)
        else:
            result["releaseOnlySkips"].append(record)
            if release_gate_required:
                result["violations"].append(
                    {
                        "id": "RELEASE-ONLY-SKIP-IN-REQUIRED-GATE",
                        "baselineId": entry["id"],
                        "commandClass": aggregate_key[1],
                        "scope": aggregate_key[2],
                    }
                )

    source_ids_by_entry: dict[str, set[str]] = defaultdict(set)
    for aggregate_key in aggregates:
        source_ids_by_entry[aggregate_key[0]].add(aggregate_key[7])
    for entry_id, source_ids in source_ids_by_entry.items():
        if len(source_ids) > 1:
            result["violations"].append(
                {
                    "id": "BASELINE-SOURCE-COMMAND-SPLIT",
                    "baselineId": entry_id,
                    "sourceCommandIds": sorted(source_ids),
                }
            )

    for entry_id, total in entry_totals.items():
        maximum = next(
            int(entry["maximumOccurrences"])
            for entries in collections.values()
            for entry in entries
            if entry["id"] == entry_id
        )
        if total > maximum and not any(
            violation.get("id") == "BASELINE-OCCURRENCE-LIMIT" and violation.get("debtId") == entry_id
            for violation in result["violations"]
        ):
            result["violations"].append(
                {
                    "id": "BASELINE-OCCURRENCE-LIMIT",
                    "debtId": entry_id,
                    "occurrences": total,
                    "maximumOccurrences": maximum,
                }
            )

    for entry in baseline.get("knownDebts", []):
        if not entry_applies(entry, current_platform):
            continue
        command_class = entry["commandClass"]
        if command_class not in completed_classes:
            continue
        key = (command_class, entry["testOrPathScope"])
        scoped = observations_by_key.get(key, [])
        if not scoped:
            result["violations"].append(
                {
                    "id": "KNOWN-SCOPE-NOT-OBSERVED",
                    "debtId": entry["id"],
                    "commandClass": command_class,
                    "scope": entry["testOrPathScope"],
                }
            )
        elif all(item["outcome"] == "pass" for item in scoped):
            source_ids = {str(item.get("commandId", "")) for item in scoped}
            if len(source_ids) != 1 or "" in source_ids:
                result["violations"].append(
                    {
                        "id": "RESOLVED-CANDIDATE-SOURCE-INVALID",
                        "baselineId": entry["id"],
                    }
                )
            else:
                result["resolvedCandidates"].append(
                    _baseline_bound_record(
                        "knownDebts",
                        entry,
                        current_platform=current_platform,
                        source_command_id=next(iter(source_ids)),
                        observed_outcome="pass",
                        observed_signature="pass",
                        failure_identity_hash_value=str(scoped[0].get("failureIdentityHash", "")),
                        derived_failure_digest=str(scoped[0].get("derivedFailureDigest", "")),
                        derived_failure_members=scoped[0].get("derivedFailureMembers", []),
                        occurrences=sum(int(item.get("occurrences", 1)) for item in scoped),
                        status="RESOLVED-CANDIDATE",
                    )
                )

    for collection_name, result_name in (
        ("expectedOmissions", "expectedOmissions"),
        ("releaseOnlySkips", "releaseOnlySkips"),
    ):
        for entry in baseline.get(collection_name, []):
            if not entry_applies(entry, current_platform):
                continue
            if entry["commandClass"] not in completed_classes:
                continue
            key = (entry["commandClass"], entry["testOrPathScope"])
            if key not in observations_by_key:
                result["violations"].append(
                    {
                        "id": "REQUIRED-POLICY-SCOPE-NOT-OBSERVED",
                        "recordId": entry["id"],
                        "commandClass": key[0],
                        "scope": key[1],
                    }
                )
    for key in ("observedDebts", "resolvedCandidates", "expectedOmissions", "releaseOnlySkips"):
        result[key] = sorted(result[key], key=lambda item: item["id"])
    return result


def _required_command_execution_passed(record: Mapping[str, Any]) -> bool:
    return _command_execution_completed(record) and record.get("exitCode") == 0


def _command_execution_completed(record: Mapping[str, Any]) -> bool:
    return (
        record.get("executed") is True
        and record.get("started") is True
        and record.get("setupFailure") is False
        and record.get("timeoutStatus") == "within-limit"
        and record.get("outputLimitStatus") == "within-limit"
        and record.get("processTreeStatus") in {"contained-clean", "not-applicable"}
    )


def _validated_portable_static_containment(
    record: Mapping[str, Any],
    *,
    protected_bundle_valid: bool,
) -> dict[str, str] | None:
    """Project only proven Linux static-suite natural-reap count telemetry.

    The supervisor's sampled registry can observe different numbers of transient
    children in independent executions. Its exact local reap/death proof remains
    mandatory. The bounded projection preserves the backend, disposition, zero
    survivors/terminations, and every execution/cleanup/watcher fact in the
    surrounding record; no other command or successful disposition is changed.
    """

    if (
        protected_bundle_valid is not True
        or record.get("commandId") != "static-suite"
        or record.get("commandClass") != "static-suite"
        or record.get("commandRole") != "observation-producing"
        or record.get("toolRole") != "python-static-producer"
        or record.get("profile") not in ("static", "all")
        or record.get("platform") != "ubuntu"
        or record.get("resultSemantics") != "machine-v2-complete-execution"
        or record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or record.get("required") is not True
        or record.get("executed") is not True
        or record.get("started") is not True
        or record.get("setupFailure") is not False
        or type(record.get("exitCode")) is not int
        or record.get("exitCode") != 0
        or record.get("allowedExecutionExits") != [0]
        or record.get("timeoutStatus") != "within-limit"
        or record.get("outputLimitStatus") != "within-limit"
        or record.get("containment") != "linux-subreaper-pidfd-proc-supervisor"
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("containmentDisposition") != "natural-exit-reaped"
        or any(record.get(key) not in (None, "") for key in (
            "error", "processTreeError", "limitReason",
        ))
        # Static-suite currently has no dependency watcher. Retain any future
        # watcher evidence exactly until its successful projection is justified.
        or record.get("dependencyBacked") is not False
        or any(record.get(key) is not None for key in (
            "runtimeClosureGuard", "closureWatcherActive", "closureMutationState",
        ))
    ):
        return None
    counts = {
        key: record.get(key)
        for key in (
            "descendantsObserved", "descendantsReaped",
            "descendantsTerminated", "descendantsSurviving",
        )
    }
    if (
        any(type(value) is not int or not 0 <= value <= 4096 for value in counts.values())
        or counts["descendantsObserved"] == 0
        or counts["descendantsObserved"] != counts["descendantsReaped"]
        or counts["descendantsTerminated"] != 0
        or counts["descendantsSurviving"] != 0
    ):
        return None
    return {
        "descendantsObserved": "<VALIDATED-NATURALLY-REAPED-COUNT>",
        "descendantsReaped": "<VALIDATED-NATURALLY-REAPED-COUNT>",
    }


def _validated_portable_successful_external_test_containment(
    record: Mapping[str, Any],
    *,
    protected_bundle_valid: bool,
    node_test_semantics_valid: bool,
) -> dict[str, str] | None:
    """Project only natural-reap counts after independent Node success proof.

    The caller derives ``node_test_semantics_valid`` from the validated raw
    reporter and immutable direct-Node authority, never from a producer claim.
    All containment and applicable dependency-guard evidence remains exact;
    these two counts alone describe non-authoritative supervisor sampling.
    Existing static-suite projection is deliberately kept separate and intact.
    """

    command_id = record.get("commandId")
    if not isinstance(command_id, str):
        return None
    security_ids = {
        f"frontend-security:{Path(relative).name}" for relative in SECURITY_GUARD_FILES
    }
    approved_command = (
        command_id == "learner-focused"
        and record.get("commandClass") == "learner-focused"
        and record.get("toolRole") == "node-test"
    ) or (
        command_id in security_ids
        and record.get("commandClass") == "frontend-security"
        and record.get("toolRole") == "node-security-test"
    ) or (
        command_id == "frontend-security:messageOriginGuard.test.js"
        and record.get("commandClass") == "frontend-security"
        and record.get("toolRole") == "node-builtin-security-test"
    )
    if (
        node_test_semantics_valid is not True
        or protected_bundle_valid is not True
        or not approved_command
        or record.get("commandRole") != "observation-producing"
        or record.get("profile") not in ("frontend", "all")
        or record.get("platform") != "ubuntu"
        or record.get("resultSemantics") != "exit-zero-pass-exit-one-classified-observation"
        or record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or record.get("required") is not True
        or not _command_execution_completed(record)
        or type(record.get("exitCode")) is not int
        or record.get("exitCode") != 0
        or record.get("allowedExecutionExits") != [0, 1]
        or record.get("containment") != "linux-subreaper-pidfd-proc-supervisor"
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("containmentDisposition") != "natural-exit-reaped"
        or any(record.get(key) not in (None, "") for key in (
            "error", "processTreeError", "limitReason",
        ))
    ):
        return None
    counts = {
        key: record.get(key)
        for key in (
            "descendantsObserved", "descendantsReaped",
            "descendantsTerminated", "descendantsSurviving",
        )
    }
    if (
        any(type(value) is not int or not 0 <= value <= 4096 for value in counts.values())
        or counts["descendantsObserved"] == 0
        or counts["descendantsObserved"] != counts["descendantsReaped"]
        or counts["descendantsTerminated"] != 0
        or counts["descendantsSurviving"] != 0
    ):
        return None
    dependency_backed = record.get("toolRole") != "node-builtin-security-test"
    if record.get("dependencyBacked") is not dependency_backed:
        return None
    guard = record.get("runtimeClosureGuard")
    if dependency_backed:
        if (
            not isinstance(guard, dict)
            or guard.get("active") is not False
            or type(guard.get("guardSchemaVersion")) is not int
            or guard.get("watcherBackend") != "_InotifyMutationWatcher"
            or guard.get("activeDuringReplay") is not True
            or guard.get("mutationState") != "clean"
            or guard.get("queueOverflow") is not False
            or type(guard.get("mutationEventCount")) is not int
            or guard.get("mutationEventCount") != 0
            or record.get("closureWatcherActive") is not True
            or record.get("closureMutationState") != "clean"
        ):
            return None
    elif any(record.get(key) is not None for key in (
        "runtimeClosureGuard", "closureWatcherActive", "closureMutationState",
    )):
        return None
    errors: list[str] = []
    try:
        if _validated_portable_protected_input_bundle_digest(record) is None:
            return None
        hard_failure = _validate_command_record(dict(record), 0, errors, expected_record=record)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return None
    if errors or hard_failure:
        return None
    return {
        "descendantsObserved": "<VALIDATED-NATURALLY-REAPED-COUNT>",
        "descendantsReaped": "<VALIDATED-NATURALLY-REAPED-COUNT>",
    }


def _plan_command_requires_completion(record: Mapping[str, Any]) -> bool:
    return bool(record.get("required")) or record.get("commandRole") == "observation-producing"


def _command_completed_for_class(record: Mapping[str, Any]) -> bool:
    if not _command_execution_completed(record):
        return False
    allowed = record.get("allowedExecutionExits")
    if not isinstance(allowed, list) or record.get("exitCode") not in allowed:
        return False
    if record.get("commandRole") == "required-execution" and record.get("exitCode") != 0:
        return False
    return True


def expected_completed_command_classes(
    command_plan: Sequence[Mapping[str, Any]],
) -> list[str]:
    return sorted(
        {
            str(record.get("commandClass"))
            for record in command_plan
            if _plan_command_requires_completion(record) and record.get("commandClass")
        }
    )


def actual_completed_command_classes(
    command_plan: Sequence[Mapping[str, Any]],
    command_records: Sequence[Mapping[str, Any]],
) -> list[str]:
    records_by_id: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in command_records:
        records_by_id[str(record.get("commandId", ""))].append(record)
    completed: list[str] = []
    for command_class in expected_completed_command_classes(command_plan):
        relevant = [
            planned
            for planned in command_plan
            if planned.get("commandClass") == command_class
            and _plan_command_requires_completion(planned)
        ]
        if relevant and all(
            len(records_by_id[str(planned.get("commandId", ""))]) == 1
            and _command_completed_for_class(
                records_by_id[str(planned.get("commandId", ""))][0]
            )
            for planned in relevant
        ):
            completed.append(command_class)
    return completed


def completed_command_class_set_digest(classes: Sequence[str]) -> str:
    return canonical_failure_digest(sorted(set(classes)))


def producer_observation_universe(
    command_records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "commandId": record.get("commandId"),
            "ordinal": record.get("ordinal"),
            "commandClass": record.get("commandClass"),
            "producerObservations": copy.deepcopy(record.get("producerObservations", [])),
            "producerObservationSetDigest": record.get("producerObservationSetDigest"),
        }
        for raw_record in command_records
        for record in (_portable_node_test_observation_source(raw_record),)
    ]


def producer_observation_universe_digest(
    command_records: Sequence[Mapping[str, Any]],
) -> str:
    return canonical_failure_digest(producer_observation_universe(command_records))


def _canonical_replay_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical_replay_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_replay_value(item) for item in value]
    if isinstance(value, str):
        temporary_root = str(Path(tempfile.gettempdir()).resolve())
        normalized = value
        for spelling in {
            temporary_root,
            temporary_root.replace("\\", "/"),
            temporary_root.replace("/", "\\"),
        }:
            if spelling:
                normalized = re.sub(
                    re.escape(spelling),
                    "<TASK-TEMP>",
                    normalized,
                    flags=re.IGNORECASE if os.name == "nt" else 0,
                )
        repository_root = str(REPO_ROOT.resolve())
        for spelling in {
            repository_root,
            repository_root.replace("\\", "/"),
            repository_root.replace("/", "\\"),
        }:
            if spelling:
                normalized = re.sub(
                    re.escape(spelling),
                    "<REPO>",
                    normalized,
                    flags=re.IGNORECASE if os.name == "nt" else 0,
                )
        return normalized
    return value


def _git_bash_execution_lease_valid(record: Mapping[str, Any]) -> bool:
    """Validate portable evidence without resolving another runner's local paths."""

    lease = record.get("executionLease")
    if (
        record.get("commandId") != "git-bash-version"
        or record.get("toolRole") != "git-bash-runtime"
        or record.get("platform") != "windows"
        or not isinstance(lease, dict)
        or set(lease) != {
            "canonicalPath", "trustedGitRoot", "size", "volumeSerial", "fileIndex",
            "links", "creationTime", "writeTime", "reparsePoint", "sha256",
        }
        or lease.get("reparsePoint") is not False
        or type(lease.get("links")) is not int
        or lease["links"] != 1
        or type(lease.get("size")) is not int
        or not 0 <= lease["size"] < 2**64
        or lease["size"] != record.get("resolvedExecutableSize")
        or not isinstance(lease.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", lease["sha256"])
        or lease["sha256"] != record.get("resolvedExecutableSha256")
        or lease.get("canonicalPath") != record.get("resolvedExecutablePath")
        or any(
            not isinstance(lease.get(key), str)
            or not re.fullmatch(r"[0-9]{1,20}", lease[key])
            or int(lease[key]) >= 2**64
            for key in ("volumeSerial", "fileIndex", "creationTime", "writeTime")
        )
        or any(
            not isinstance(lease.get(key), str) or not lease[key] or "\x00" in lease[key]
            for key in ("canonicalPath", "trustedGitRoot")
        )
    ):
        return False
    executable = PureWindowsPath(lease["canonicalPath"])
    git_root = PureWindowsPath(lease["trustedGitRoot"])
    if (
        not executable.is_absolute()
        or not git_root.is_absolute()
        or ".." in executable.parts
        or ".." in git_root.parts
    ):
        return False
    try:
        candidate = tuple(part.casefold() for part in executable.relative_to(git_root).parts)
    except ValueError:
        return False
    return candidate in WINDOWS_GIT_BASH_CANDIDATE_SUFFIXES


def _validated_portable_git_bash_execution_lease(
    record: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project a locally verified successful lease; failed physical evidence stays exact.

    TrustedBashLease constructs the held identity and verifies it before the plan
    snapshot and both sides of execution. Those checks remain local authority;
    this projection is only the cross-job identity of their successful record.
    """

    if (
        not _git_bash_execution_lease_valid(record)
        or not _required_command_execution_passed(record)
        or record.get("containment") != "windows-job-object"
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("descendantsSurviving") != 0
        or any(record.get(key) is not None for key in ("error", "processTreeError", "limitReason"))
    ):
        return None
    errors: list[str] = []
    _validate_command_record(dict(record), 0, errors, expected_record=record)
    if errors:
        return None
    lease = record["executionLease"]
    return {
        "leaseKind": "windows-git-bash-executable-v1",
        "tool": "git-bash",
        "size": lease["size"],
        "sha256": lease["sha256"],
        "reparsePoint": False,
        "links": 1,
        "trustedProductRelationship": "fixed-candidate-in-trusted-git-installation",
        "nonReparseDirectoryChain": True,
    }


_PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS = (
    "orderedLogicalTargetPaths",
    "canonicalSourcePaths",
    "plannedByteLengths",
    "plannedSha256Values",
    "plannedStableIdentities",
    "executionInputs",
)


_PROTECTED_BUNDLE_COMPACT_IDENTITY_DOMAIN = (
    "ieltmps-protected-target-bundle-compact-identity-v1"
)


def _portable_protected_target_authority(
    target: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the cross-checkout target identity independently rebuilt by replay."""

    return {
        "logicalPath": target.get("path"),
        "byteLength": target.get("size"),
        "sha256": target.get("sha256"),
        "modeType": target.get("modeType"),
        "reparsePoint": target.get("reparsePoint"),
    }


def _portable_protected_execution_input_authority(
    target: Mapping[str, Any],
    execution_adapter: Any,
) -> dict[str, Any]:
    """Derive successful input authority without producer filesystem aliases."""

    return {
        "logicalPath": target.get("path"),
        "plannedByteLength": target.get("size"),
        "plannedSha256": target.get("sha256"),
        "actualByteLength": target.get("size"),
        "actualSha256": target.get("sha256"),
        "inputMode": execution_adapter,
    }


def _reconstructed_protected_execution_inputs(
    command: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Rebuild successful bundle inputs from retained ordered target authority."""

    if command.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE":
        return []
    targets = command.get("targets")
    if not isinstance(targets, list) or not targets or any(
        not isinstance(target, Mapping) for target in targets
    ):
        return []
    return [
        {
            "logicalPath": target.get("path"),
            "canonicalSourcePath": target.get("canonicalSourcePath"),
            "plannedByteLength": target.get("size"),
            "plannedSha256": target.get("sha256"),
            "plannedStableIdentity": copy.deepcopy(target.get("fileIdentity")),
            "actualByteLength": target.get("size"),
            "actualSha256": target.get("sha256"),
            "inputMode": command.get("executionInputMode"),
        }
        for target in targets
    ]


def _canonical_protected_execution_inputs(
    command: Mapping[str, Any],
) -> Any:
    """Normalize full and compact valid bundle inputs to one replay value."""

    inputs = command.get("executionInputs")
    reconstructed = _reconstructed_protected_execution_inputs(command)
    if reconstructed and (
        inputs == reconstructed
        or (
            inputs == []
            and command.get("executionInputBundleDigest")
            == execution_input_bundle_digest(reconstructed)
        )
    ):
        return []
    return copy.deepcopy(inputs)


def _portable_protected_bundle_authority(
    command: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Derive the shared portable bundle authority from the ordered target plan.

    The preimage deliberately excludes checkout-local canonical paths, inode/file
    indexes, and timestamps: a fresh verifier checkout has different values.
    Those values remain protected by each producer/replay TargetExecutionLease.
    The portable semantic identity instead binds the ordered path/content/input
    plan, the command association, the bundle version/adapter, and the pre/post
    phase for compact leaves, all reconstructed without trusting these digests.
    """

    targets = command.get("targets")
    if not isinstance(targets, list) or not targets:
        return None
    execution_adapter = command.get("executionInputMode")
    ordered_authority = [
        {
            "targetIndex": index,
            "target": _portable_protected_target_authority(target),
            "executionInput": _portable_protected_execution_input_authority(
                target,
                execution_adapter,
            ),
        }
        for index, target in enumerate(targets)
        if isinstance(target, Mapping)
    ]
    if len(ordered_authority) != len(targets):
        return None
    portable_input_digest = hashlib.sha256(
        _canonical_frame(
            {
                "digestDomain": (
                    "ieltmps-protected-target-bundle-portable-input-v1"
                ),
                "orderedExecutionInputs": [
                    item["executionInput"] for item in ordered_authority
                ],
            }
        )
    ).hexdigest()
    return {
        "digestDomain": _PROTECTED_BUNDLE_COMPACT_IDENTITY_DOMAIN,
        "bundleVersion": PROTECTED_TARGET_BUNDLE_VERSION,
        "executionAdapter": execution_adapter,
        "commandAssociation": {
            "commandId": command.get("commandId"),
            "ordinal": command.get("ordinal"),
            "commandClass": command.get("commandClass"),
            "profile": command.get("profile"),
            "toolRole": command.get("toolRole"),
        },
        "targetCount": len(targets),
        "orderedTargetAndInputAuthority": ordered_authority,
        "portableExecutionInputBundleDigest": portable_input_digest,
    }


def _protected_bundle_compact_identity_digests(
    command: Mapping[str, Any],
    *,
    phase: str,
) -> list[str]:
    """Bind each phase and target to the shared portable bundle authority."""

    bundle_authority = _portable_protected_bundle_authority(command)
    if bundle_authority is None:
        return []
    ordered_authority = bundle_authority["orderedTargetAndInputAuthority"]
    bundle_authority_digest = hashlib.sha256(
        _canonical_frame(bundle_authority)
    ).hexdigest()
    return [
        hashlib.sha256(
            _canonical_frame(
                {
                    "digestDomain": (
                        "ieltmps-protected-target-bundle-compact-identity-leaf-v1"
                    ),
                    "bundleAuthorityDigest": bundle_authority_digest,
                    "phase": phase,
                    "identityTargetIndex": index,
                    "targetAuthority": ordered_authority[index],
                }
            )
        ).hexdigest()
        for index in range(len(ordered_authority))
    ]


def _protected_source_identity_matches_target(
    identity: Any,
    target: Mapping[str, Any],
) -> bool:
    if not isinstance(identity, Mapping) or set(identity) != {
        "pathStableIdentity",
        "heldStableIdentity",
        "canonicalPath",
    }:
        return False
    held = identity.get("heldStableIdentity")
    return (
        identity.get("pathStableIdentity") == target.get("fileIdentity")
        and identity.get("canonicalPath") == target.get("canonicalSourcePath")
        and isinstance(held, Mapping)
        and held.get("reparsePoint") is False
    )


def _full_protected_identity_array_matches_authority(
    command: Mapping[str, Any],
    identities: Any,
) -> bool:
    targets = command.get("targets")
    return (
        isinstance(targets, list)
        and bool(targets)
        and isinstance(identities, list)
        and len(identities) == len(targets)
        and all(
            isinstance(target, Mapping)
            and _protected_source_identity_matches_target(identity, target)
            for identity, target in zip(identities, targets)
        )
    )


def _canonical_protected_identity_array(
    command: Mapping[str, Any],
    identities: Any,
    *,
    phase: str,
) -> Any:
    if _full_protected_identity_array_matches_authority(command, identities):
        return _protected_bundle_compact_identity_digests(command, phase=phase)
    return copy.deepcopy(identities)


def _compact_command_record_for_evidence(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Replace only validated protected-bundle duplication with digest references."""

    source = dict(record)
    if source.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE":
        return copy.deepcopy(source)
    bundle = source.get("protectedTargetBundle")
    targets = source.get("targets")
    inputs = source.get("executionInputs")
    if not isinstance(bundle, dict) or not isinstance(targets, list) or not targets:
        return copy.deepcopy(source)
    if not isinstance(inputs, list) or len(inputs) != len(targets):
        return copy.deepcopy(source)
    reconstructed_inputs = _reconstructed_protected_execution_inputs(source)
    if inputs != reconstructed_inputs:
        return copy.deepcopy(source)
    pre = bundle.get("preExecutionIdentities")
    post = bundle.get("postExecutionIdentities")
    expected_duplicates = {
        "orderedLogicalTargetPaths": [target.get("path") for target in targets],
        "canonicalSourcePaths": [
            target.get("canonicalSourcePath") for target in targets
        ],
        "plannedByteLengths": [target.get("size") for target in targets],
        "plannedSha256Values": [target.get("sha256") for target in targets],
        "plannedStableIdentities": [
            target.get("fileIdentity") for target in targets
        ],
        "executionInputs": inputs,
    }
    if (
        bundle.get("bundleVersion") != PROTECTED_TARGET_BUNDLE_VERSION
        or bundle.get("executionAdapter") != "PROTECTED-TARGET-BUNDLE"
        or bundle.get("executionInputBundleDigest")
        != source.get("executionInputBundleDigest")
        or source.get("executionInputBundleDigest")
        != execution_input_bundle_digest(inputs)
        or bundle.get("mutationDetected") is not False
        or bundle.get("cleanupState") != "closed"
        or not isinstance(pre, list)
        or not isinstance(post, list)
        or len(pre) != len(targets)
        or len(post) != len(targets)
        or any(item is None for item in pre)
        or any(item is None for item in post)
        or any(bundle.get(key) != value for key, value in expected_duplicates.items())
        or not _full_protected_identity_array_matches_authority(source, pre)
        or not _full_protected_identity_array_matches_authority(source, post)
    ):
        return copy.deepcopy(source)
    if pre != post:
        return copy.deepcopy(source)
    if _validated_portable_protected_input_bundle_digest(source) is None:
        return copy.deepcopy(source)
    pre_digests = _protected_bundle_compact_identity_digests(source, phase="pre")
    post_digests = _protected_bundle_compact_identity_digests(source, phase="post")
    compact = {
        key: copy.deepcopy(value)
        for key, value in source.items()
        if key != "protectedTargetBundle"
    }
    compact_bundle = {
        key: copy.deepcopy(value)
        for key, value in bundle.items()
        if key
        not in {
            *_PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS,
            "preExecutionIdentities",
            "postExecutionIdentities",
        }
    }
    for key in _PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS:
        compact_bundle[key] = []
    compact_bundle["preExecutionIdentities"] = pre_digests
    compact_bundle["postExecutionIdentities"] = post_digests
    compact["executionInputs"] = []
    compact["protectedTargetBundle"] = compact_bundle
    return compact


def _validated_portable_protected_input_bundle_digest(
    record: Mapping[str, Any],
) -> str | None:
    """Portableize only after raw evidence passes this job's local authority.

    The ordinary validator checks full physical evidence or reconstructs compact
    references, including the raw input digest, before any fields are removed.
    Using the retained record here checks local consistency only: verification
    still independently compares it with the freshly rebuilt command plan.
    """

    targets = record.get("targets")
    if (
        record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or record.get("executed") is not True
        or not isinstance(targets, list)
        or not targets
        or any(
            not isinstance(target, dict)
            or target.get("modeType") != "regular-file"
            or target.get("reparsePoint") is not False
            for target in targets
        )
    ):
        return None
    errors: list[str] = []
    _validate_command_record(dict(record), 0, errors, expected_record=record)
    if errors:
        return None
    for target in targets:
        stable = target.get("fileIdentity")
        if (
            type(target.get("size")) is not int
            or not 0 <= target["size"] <= MAX_SCANNED_FILE_BYTES
            or not isinstance(target.get("sha256"), str)
            or not isinstance(target.get("canonicalSourcePath"), str)
            or not isinstance(stable, Mapping)
            or set(stable) != {
                "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs",
                "writeTimeNs", "reparsePoint",
            }
            or stable.get("reparsePoint") is not False
            or any(
                not isinstance(stable.get(key), str)
                or not re.fullmatch(r"-?[0-9]+", stable[key])
                for key in (
                    "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs",
                    "writeTimeNs",
                )
            )
        ):
            return None
    # Full evidence retains the held lease identity. POSIX uses the same stable
    # identity as the path; Windows captures a separate handle-information shape.
    bundle = record["protectedTargetBundle"]
    for target, identity in zip(targets, bundle["preExecutionIdentities"]):
        if not isinstance(identity, Mapping):
            continue  # Compact phase digests were independently checked above.
        held = identity["heldStableIdentity"]
        if held == target.get("fileIdentity"):
            continue
        if (
            set(held) != {
                "volumeSerial", "fileIndex", "size", "creationTime", "writeTime",
                "linkCount", "reparsePoint",
            }
            or type(held.get("size")) is not int
            or held.get("size") != target.get("size")
            or type(held.get("linkCount")) is not int
            or held["linkCount"] < 1
            or any(
                not isinstance(held.get(key), str)
                or not re.fullmatch(r"[0-9]+", held[key])
                for key in ("volumeSerial", "fileIndex", "creationTime", "writeTime")
            )
        ):
            return None
    authority = _portable_protected_bundle_authority(record)
    if authority is None:
        return None
    return hashlib.sha256(_canonical_frame(authority)).hexdigest()


def _validated_portable_target_stdin_input_authority(
    record: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project a single immutable stdin input only after complete local validation.

    Retain all physical evidence in the raw record. The successful projection
    shares the protected-bundle byte representation and binds the closed lease,
    command association, and target ordering in a distinct digest domain.
    """

    if record.get("executionInputMode") != "TARGET-BYTES-STDIN":
        return None
    errors: list[str] = []
    try:
        hard_failure = _validate_command_record(dict(record), 0, errors, expected_record=record)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return None
    if (
        errors or hard_failure or not _command_execution_completed(record)
        or (record.get("platform"), record.get("containment")) not in {
            ("windows", "windows-job-object"), ("ubuntu", "linux-subreaper-pidfd-proc-supervisor"),
        }
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("descendantsSurviving") != 0
        or any(record.get(key) is not None for key in ("error", "processTreeError", "limitReason"))
    ):
        return None
    target = record["targets"][0]
    lease = record["targetExecutionLease"]
    execution_input = record["executionInputs"][0]
    stable = target.get("fileIdentity")
    if (
        type(target.get("size")) is not int
        or not 0 <= target["size"] <= MAX_SCANNED_FILE_BYTES
        or not isinstance(target.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", target["sha256"]) is None
        or not isinstance(target.get("canonicalSourcePath"), str)
        or not Path(target["canonicalSourcePath"]).is_absolute()
        or target.get("modeType") != "regular-file"
        or target.get("reparsePoint") is not False
        or lease.get("reparsePoint") is not False
        or type(lease.get("leaseVersion")) is not int
        or lease["leaseVersion"] != TARGET_EXECUTION_LEASE_VERSION
        or any(
            type(value) is not int or value != target["size"]
            for value in (
                record.get("executionInputSize"), record.get("actualExecutionInputSize"),
                lease.get("plannedByteLength"), lease.get("executedInputByteLength"),
                execution_input.get("plannedByteLength"), execution_input.get("actualByteLength"),
            )
        )
        or not isinstance(stable, Mapping)
        or set(stable) != {
            "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs", "reparsePoint",
        }
        or stable.get("reparsePoint") is not False
        or any(
            not isinstance(stable.get(key), str) or re.fullmatch(r"-?[0-9]+", stable[key]) is None
            for key in ("deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs")
        )
    ):
        return None
    relative = target["path"]
    if (
        Path(relative).is_absolute() or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        return None
    pre = lease["preExecutionSourceIdentity"]
    post = lease["postExecutionSourceIdentity"]
    # The ordinary stdin validator requires snapshots to exist; this projection
    # additionally proves their full physical content before discarding it.
    try:
        snapshots_match = (
            _protected_source_identity_matches_target(pre, target)
            and _protected_source_identity_matches_target(post, target)
            and _json_bytes(pre) == _json_bytes(post)
            and _json_bytes(pre["pathStableIdentity"]) == _json_bytes(stable)
            and _json_bytes(lease["plannedStableFileIdentity"]) == _json_bytes(stable)
            and _json_bytes(execution_input["plannedStableIdentity"]) == _json_bytes(stable)
        )
    except (KeyError, TypeError, ValueError, UnicodeError):
        return None
    if not snapshots_match:
        return None
    held = pre["heldStableIdentity"]
    if record["platform"] == "windows":
        if (
            set(held) != {
                "volumeSerial", "fileIndex", "size", "creationTime", "writeTime", "linkCount", "reparsePoint",
            }
            or type(held.get("size")) is not int or held["size"] != target["size"]
            or type(held.get("linkCount")) is not int or not 1 <= held["linkCount"] < 2**32
            or held.get("reparsePoint") is not False
            or any(
                not isinstance(held.get(key), str)
                or re.fullmatch(r"[0-9]{1,20}", held[key]) is None
                or int(held[key]) >= 2**width
                for key, width in (
                    ("volumeSerial", 32), ("fileIndex", 64), ("creationTime", 64), ("writeTime", 64),
                )
            )
        ):
            return None
    elif _json_bytes(held) != _json_bytes(stable):
        return None
    portable_input = _portable_protected_execution_input_authority(target, "TARGET-BYTES-STDIN")
    portable_lease = {
        "leaseVersion": lease["leaseVersion"],
        "logicalTargetPath": portable_input["logicalPath"],
        "executionAdapter": portable_input["inputMode"],
        "plannedByteLength": portable_input["plannedByteLength"],
        "plannedSha256": portable_input["plannedSha256"],
        "executedInputByteLength": portable_input["actualByteLength"],
        "executedInputSha256": portable_input["actualSha256"],
        "modeType": target["modeType"],
        "reparsePoint": False,
        "mutationDetected": False,
        "cleanupState": "closed",
        "targetIndex": 0,
        "commandAssociation": {
            key: record[key] for key in ("commandId", "ordinal", "commandClass", "profile", "toolRole")
        },
    }
    portable_digest = hashlib.sha256(_canonical_frame({
        "digestDomain": "ieltmps-target-bytes-stdin-portable-input-v1",
        "targetExecutionLease": portable_lease,
        "orderedExecutionInputs": [portable_input],
    })).hexdigest()
    return {
        "executionInputs": [portable_input],
        "executionInputBundleDigest": portable_digest,
        "targetExecutionLease": portable_lease,
    }


def _validated_bundle_normalization_success_output_identity(
    record: Mapping[str, Any],
    *,
    protected_bundle_valid: bool,
) -> dict[str, Any] | None:
    """Project this one exit-zero contract after its local evidence validates.

    Node's successful test reporter is telemetry for bundle-normalization. Its
    raw streams, hashes, and lengths remain local evidence; only the cross-job
    transcript receives a freshly derived semantic stdout identity. Immutable
    plan/trusted-tool comparison still binds the surrounding command authority.
    """

    if (
        protected_bundle_valid is not True
        or record.get("commandId") != "bundle-normalization"
        or record.get("commandClass") != "bundle-parity"
        or record.get("commandRole") != "required-execution"
        or record.get("resultSemantics") != "exit-zero-required"
        or record.get("toolRole") != "node-test"
        or record.get("profile") not in ("frontend", "all")
        or record.get("required") is not True
        or not _command_execution_completed(record)
        or type(record.get("exitCode")) is not int
        or record.get("exitCode") != 0
        or record.get("allowedExecutionExits") != [0]
        or record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or (record.get("platform"), record.get("containment")) not in {
            ("ubuntu", "linux-subreaper-pidfd-proc-supervisor"),
            ("windows", "windows-job-object"),
        }
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("descendantsSurviving") != 0
        or any(record.get(key) is not None for key in (
            "error", "processTreeError", "limitReason",
        ))
        or record.get("producerObservations") != []
        or record.get("dependencyBacked") is not True
    ):
        return None
    errors: list[str] = []
    try:
        hard_failure = _validate_command_record(dict(record), 0, errors, expected_record=record)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return None
    if errors or hard_failure:
        return None
    guard = record["runtimeClosureGuard"]
    if (
        guard.get("active") is not False
        or type(guard.get("guardSchemaVersion")) is not int
        or type(guard.get("mutationEventCount")) is not int
        or (record["platform"], guard.get("watcherBackend")) not in {
            ("ubuntu", "_InotifyMutationWatcher"),
            ("windows", "_WindowsDirectoryMutationWatcher"),
        }
    ):
        return None
    executable = record.get("resolvedExecutablePath")
    stable = record.get("resolvedExecutableFileIdentity")
    target_path = "developer/tests/js/bundleNormalization.test.js"
    argv = [executable, "--test", target_path]
    if (
        not isinstance(executable, str)
        or not Path(executable).is_absolute()
        or record["resolvedExecutableSize"] <= 0
        or record.get("resolvedTestRunnerEntrypoint") != executable
        or record.get("resolvedTestRunnerSha256") != record.get("resolvedExecutableSha256")
        or any(record.get(key) != argv for key in (
            "argv", "logicalArgv", "executionArgv", "actualExecutionArgv",
        ))
        or sum(target.get("path") == target_path for target in record["targets"]) != 1
        or record.get("cwd") != "."
        or not isinstance(stable, Mapping)
        or stable.get("reparsePoint") is not False
        or any(
            not isinstance(stable.get(key), str)
            or re.fullmatch(r"-?[0-9]+", stable[key]) is None
            for key in (
                "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs",
            )
        )
    ):
        return None
    canonical = _canonical_frame({
        "digestDomain": "ieltmps-exit-zero-required-success-output-v1",
        "commandId": record["commandId"],
        "resultSemantics": record["resultSemantics"],
        "exitCode": record["exitCode"],
    })
    return {
        "stdoutSha256": hashlib.sha256(canonical).hexdigest(),
        "stdoutBytesObserved": len(canonical),
    }


_NODE_TEST_MAX_STDOUT_BYTES = 256 * 1024
_NODE_TEST_MAX_TESTS = 1024
_NODE_TEST_MAX_NAME_LENGTH = 2048
_NODE_TEST_MAX_PAYLOAD_BYTES = 16 * 1024
_NODE_TEST_DURATION_PATTERN = r"(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,9})?"
_NODE_TEST_SUMMARY_KEYS = (
    "tests", "suites", "pass", "fail", "cancelled", "skipped", "todo",
)
_NODE_TEST_LEARNER_PATHS = (
    "developer/tests/js/learnerPalette.test.js",
    "developer/tests/js/learnerUiRuntimeStabilization.test.js",
)
_NODE_TEST_SECURITY_JSON_DETAILS = {
    "appActionsExportGuard.test.js": "app actions markdown export step-up guard passed",
    "dataManagementPanel.test.js": "data management panel export and stale file read guard tests passed",
    "examActionsExportGuard.test.js": "exam actions fallback export guard passed",
    "examSessionReplayCloneGuard.test.js": "exam session replay clone guard passed",
    "localDataRenderingGuard.test.js": "local data rendering guard tests passed",
    "practiceRecordExportServerGuard.test.js": "server-owned practice-record export guard tests passed",
    "remotePracticeDataSource.test.js": "remote practice data source tests passed",
    "resourceCoreProbeBypassGuard.test.js": "resource core probe bypass guard passed",
    "secureIdentifierGuard.test.js": "secure identifier guard tests passed",
    "suiteBackGuardSecurity.test.js": "suite back guard history state sanitization tests passed",
    "vocabSessionExportGuard.test.js": "vocab session export step-up guard passed",
}


def _node_test_geometry_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"left", "top", "width", "height"}
        and all(
            type(number) in (int, float)
            and abs(number) <= 1_000_000_000
            and math.isfinite(number)
            for number in value.values()
        )
        and value["width"] >= 0
        and value["height"] >= 0
    )


def _node_test_learner_payload_valid(payload: Any) -> bool:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"status", "detail", "tests", "evidence"}
        or payload["status"] != "pass"
        or payload["detail"] != "learner UI runtime stabilization regression tests passed"
        or payload["tests"] != {
            "practiceSummaryToggle": "pass",
            "practiceBeforeBrowse": "pass",
            "paletteLayoutStability": "pass",
        }
    ):
        return False
    evidence = payload["evidence"]
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {
            "expandedToggle", "collapsedToggle", "practiceFirstCalls", "widgetClicks",
        }
        or not _node_test_geometry_valid(evidence["expandedToggle"])
        or not _node_test_geometry_valid(evidence["collapsedToggle"])
        or type(evidence["widgetClicks"]) is not int
        or not 0 <= evidence["widgetClicks"] <= 1_000_000
    ):
        return False
    calls = evidence["practiceFirstCalls"]
    return (
        isinstance(calls, list)
        and 1 <= len(calls) <= 128
        and all(
            isinstance(call, str)
            and re.fullmatch(
                r"ensure-browse|ensure-practice-suite|update:(?:true|false):(?:true|false)",
                call,
            ) is not None
            for call in calls
        )
    )


def _node_test_payload_valid(payload: Any, command_id: str) -> bool:
    if command_id == "learner-focused":
        return _node_test_learner_payload_valid(payload)
    basename = command_id.removeprefix("frontend-security:")
    detail = _NODE_TEST_SECURITY_JSON_DETAILS.get(basename)
    return (
        detail is not None
        and isinstance(payload, dict)
        and set(payload) == {"status", "detail"}
        and payload["status"] == "pass"
        and payload["detail"] == detail
    )


def _node_test_authorized_reporter_path(name: str, paths: tuple[str, ...]) -> str | None:
    for path in paths:
        if re.fullmatch(re.escape(path).replace("/", r"[/\\]"), name) is not None:
            return path
    return None


def parse_node_test_semantic_result(
    stdout: str,
    *,
    command_id: str,
    authorized_test_paths: Sequence[str],
) -> dict[str, Any] | None:
    """Derive NodeTestSemanticResultV1, never accepting a producer digest.

    Exact repository identifiers come solely from caller-validated immutable
    argv/target authority. A slash or backslash spelling is normalized only
    when an entire reporter test name equals that identifier. All other test
    names and all structured payload values retain their semantic content.
    """
    if (
        not isinstance(stdout, str)
        or not stdout
        or len(stdout) > _NODE_TEST_MAX_STDOUT_BYTES
        or not isinstance(command_id, str)
        or isinstance(authorized_test_paths, (str, bytes))
        or not isinstance(authorized_test_paths, Sequence)
        or not 1 <= len(authorized_test_paths) <= 2
    ):
        return None
    try:
        if len(stdout.encode("utf-8")) > _NODE_TEST_MAX_STDOUT_BYTES:
            return None
    except UnicodeError:
        return None
    # Node's captured spec reporter writes LF on both authorized platforms.
    # Do not broaden normalization to ANSI escapes or arbitrary whitespace.
    if not stdout.endswith("\n") or any(
        ord(character) < 32 and character != "\n" or ord(character) == 127
        for character in stdout
    ):
        return None
    paths = tuple(authorized_test_paths)
    if any(
        not isinstance(path, str)
        or re.fullmatch(r"developer/tests/js/[A-Za-z0-9_-]+\.test\.js", path) is None
        for path in paths
    ) or len(set(paths)) != len(paths):
        return None
    if command_id == "learner-focused":
        if paths != _NODE_TEST_LEARNER_PATHS:
            return None
        payload_kind = "learner-runtime"
        payload_path = paths[1]
    elif command_id.startswith("frontend-security:"):
        basename = command_id.removeprefix("frontend-security:")
        if len(paths) != 1 or basename != paths[0].rsplit("/", 1)[1]:
            return None
        payload_path = paths[0]
        if basename in _NODE_TEST_SECURITY_JSON_DETAILS:
            payload_kind = "security-result"
        elif basename == "adminFrontendGuard.test.js":
            payload_kind = "security-success-line"
        else:
            payload_kind = None
    else:
        return None
    lines = stdout[:-1].split("\n")
    if not 9 <= len(lines) <= _NODE_TEST_MAX_TESTS + 256:
        return None
    summary_lines = lines[-8:]
    counts: dict[str, int] = {}
    for key, line in zip(_NODE_TEST_SUMMARY_KEYS, summary_lines[:7]):
        match = re.fullmatch(rf"ℹ {key} (0|[1-9][0-9]{{0,3}})", line)
        if match is None:
            return None
        counts[key] = int(match[1])
    if (
        re.fullmatch(rf"ℹ duration_ms {_NODE_TEST_DURATION_PATTERN}", summary_lines[-1]) is None
        or not 1 <= counts["tests"] <= _NODE_TEST_MAX_TESTS
        or counts["pass"] != counts["tests"]
        or any(counts[key] != 0 for key in ("suites", "fail", "cancelled", "skipped", "todo"))
    ):
        return None
    body = lines[:-8]
    tests: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    index = 0
    while index < len(body):
        line = body[index]
        test_match = re.fullmatch(rf"✔ (.+) \({_NODE_TEST_DURATION_PATTERN}ms\)", line)
        if test_match is not None:
            name = test_match[1]
            if (
                len(name) > _NODE_TEST_MAX_NAME_LENGTH
                or name != name.strip()
                or len(tests) >= _NODE_TEST_MAX_TESTS
            ):
                return None
            normalized_name = _node_test_authorized_reporter_path(name, paths) or name
            tests.append({"ordinal": len(tests) + 1, "name": normalized_name, "status": "pass"})
            index += 1
            continue
        if payload_kind is None or payloads:
            return None
        if payload_kind == "security-success-line":
            if line != "adminFrontendGuard.test.js passed":
                return None
            payload: Any = {"status": "pass", "detail": line}
            index += 1
        else:
            if line != "{":
                return None
            # JSON.stringify(..., null, 2) emits one top-level closing brace
            # on a line of its own. No arbitrary leading/trailing text passes.
            closing = next((i for i in range(index + 1, len(body)) if body[i] == "}"), None)
            if closing is None:
                return None
            payload_text = "\n".join(body[index:closing + 1])
            if len(payload_text.encode("utf-8")) > _NODE_TEST_MAX_PAYLOAD_BYTES:
                return None
            try:
                payload = strict_json_loads(payload_text, label="direct Node test payload")
            except (ValueError, RecursionError, OverflowError):
                return None
            if not _node_test_payload_valid(payload, command_id):
                return None
            index = closing + 1
        # Payload is emitted by the script whose immediately following file
        # result closes the reporter body. Association and placement matter.
        if index != len(body) - 1:
            return None
        associated_test = re.fullmatch(
            rf"✔ (.+) \({_NODE_TEST_DURATION_PATTERN}ms\)", body[index],
        )
        if (
            associated_test is None
            or _node_test_authorized_reporter_path(associated_test[1], paths) != payload_path
        ):
            return None
        payloads.append({"testOrdinal": len(tests) + 1, "kind": payload_kind, "value": payload})
    if (
        len(tests) != counts["tests"]
        or bool(payloads) != (payload_kind is not None)
        or (payload_kind is not None and command_id != "learner-focused" and len(tests) != 1)
    ):
        return None
    return {
        "schema": "NodeTestSemanticResultV1",
        "commandId": command_id,
        "authorizedTestPaths": list(paths),
        "tests": tests,
        "counts": counts,
        "payloads": payloads,
    }


def _direct_node_test_authorized_paths(record: Mapping[str, Any]) -> tuple[str, ...] | None:
    """Recognize only the immutable direct-test adapters in the frontend plan."""
    command_id = record.get("commandId")
    if command_id == "learner-focused":
        command_class, role = "learner-focused", "node-test"
        paths = (
            "developer/tests/js/learnerPalette.test.js",
            "developer/tests/js/learnerUiRuntimeStabilization.test.js",
        )
    elif command_id == "frontend-security:messageOriginGuard.test.js":
        command_class, role = "frontend-security", "node-builtin-security-test"
        paths = (MESSAGE_ORIGIN_SECURITY_GUARD,)
    else:
        matching = [path for path in SECURITY_GUARD_FILES
                    if command_id == f"frontend-security:{Path(path).name}"]
        if len(matching) != 1:
            return None
        command_class, role = "frontend-security", "node-security-test"
        paths = tuple(matching)
    executable = record.get("resolvedExecutablePath")
    argv = [executable, "--test", *paths]
    if (
        record.get("commandClass") != command_class
        or record.get("toolRole") != role
        or record.get("commandRole") != "observation-producing"
        or record.get("resultSemantics") != "exit-zero-pass-exit-one-classified-observation"
        or record.get("profile") not in {"frontend", "all"}
        or record.get("allowedExecutionExits") != [0, 1]
        or record.get("executionInputMode") != "PROTECTED-TARGET-BUNDLE"
        or record.get("required") is not True
        or record.get("cwd") != "."
        or not isinstance(executable, str) or not Path(executable).is_absolute()
        or any(record.get(key) != argv for key in ("argv", "logicalArgv", "executionArgv"))
    ):
        return None
    return paths


def _direct_node_test_raw_stream_errors(record: Mapping[str, Any]) -> list[str]:
    """Validate exact retained streams independently of sanitized observations."""
    streams = record.get("directNodeTestRawStreams")
    if (
        _direct_node_test_authorized_paths(record) is None
        or type(record.get("exitCode")) is not int or record.get("exitCode") != 0
        or not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}
    ):
        return ["direct Node test raw stream authority/schema is invalid"]
    for name in ("stdout", "stderr"):
        value = streams[name]
        if not isinstance(value, str):
            return ["direct Node test raw stream must be UTF-8 text"]
        try:
            data = value.encode("utf-8", errors="strict")
        except UnicodeError:
            return ["direct Node test raw stream must be UTF-8 text"]
        if (len(data) > MAX_RECORDED_STREAM_BYTES
            or len(data) != record.get(name + "BytesObserved")
            or hashlib.sha256(data).hexdigest() != record.get(name + "Sha256")):
            return ["direct Node test raw stream differs from observed bytes"]
    return []


def _validated_direct_node_test_semantic_projection(
    record: Mapping[str, Any], *, protected_bundle_valid: bool,
) -> dict[str, Any] | None:
    """Derive a portable result only after the complete raw success proof."""
    paths = _direct_node_test_authorized_paths(record)
    if (
        paths is None or protected_bundle_valid is not True
        or not _command_execution_completed(record)
        or type(record.get("exitCode")) is not int or record.get("exitCode") != 0
        or record.get("processTreeStatus") != "contained-clean"
        or record.get("descendantsSurviving") != 0
        or record.get("descendantsTerminated") != 0
        or record.get("containmentDisposition") not in {"no-descendants", "natural-exit-reaped"}
        or any(record.get(key) is not None for key in ("error", "processTreeError", "limitReason"))
        or (record.get("platform"), record.get("containment")) not in {
            ("ubuntu", "linux-subreaper-pidfd-proc-supervisor"),
            ("windows", "windows-job-object"),
        }
        or _direct_node_test_raw_stream_errors(record)
    ):
        return None
    try:
        errors: list[str] = []
        if _validate_command_record(dict(record), 0, errors, expected_record=record) or errors:
            return None
        if _validated_portable_protected_input_bundle_digest(record) is None:
            return None
        if any(sum(target.get("path") == path for target in record["targets"]) != 1 for path in paths):
            return None
        if record["actualExecutionArgv"] != record["logicalArgv"]:
            return None
        if record["resolvedExecutableSize"] <= 0:
            return None
        stable = record["resolvedExecutableFileIdentity"]
        if stable.get("reparsePoint") is not False or any(
            not isinstance(stable.get(key), str) or re.fullmatch(r"-?[0-9]+", stable[key]) is None
            for key in ("deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs")
        ):
            return None
        if record.get("dependencyBacked") is True:
            guard = record["runtimeClosureGuard"]
            if (
                record.get("resolvedTestRunnerEntrypoint") != record["resolvedExecutablePath"]
                or record.get("resolvedTestRunnerSha256") != record["resolvedExecutableSha256"]
                or guard.get("active") is not False
                or type(guard.get("guardSchemaVersion")) is not int
                or type(guard.get("mutationEventCount")) is not int
                or (record["platform"], guard.get("watcherBackend")) not in {
                    ("ubuntu", "_InotifyMutationWatcher"),
                    ("windows", "_WindowsDirectoryMutationWatcher"),
                }
            ):
                return None
        elif (record.get("toolRole") != "node-builtin-security-test"
              or record.get("dependencyBacked") is not False
              or any(record.get(key) is not None for key in (
                  "runtimeClosureGuard", "closureWatcherActive", "closureMutationState"))):
            return None
        observed, reaped = record["descendantsObserved"], record["descendantsReaped"]
        if (record["containmentDisposition"] == "no-descendants" and (observed or reaped)
            or record["containmentDisposition"] == "natural-exit-reaped"
            and (observed <= 0 or observed != reaped)):
            return None
        producer = record["producerObservations"]
        if len(producer) != 1:
            return None
        raw = producer[0]
        if _validate_raw_observation(raw, label="direct-node-test", source=record):
            return None
        expected_scope = ("command:learner-focused-runtime" if record["commandId"] == "learner-focused"
                          else f"file:{paths[0]}")
        streams = record["directNodeTestRawStreams"]
        expected_fields = raw_observation_json_value({
            "executed": True, "exitCode": 0, "stdout": streams["stdout"],
            "stderr": streams["stderr"], "error": None,
        })
        if (raw["observationOrdinal"] != 0 or raw["occurrences"] != 1
            or raw["sourceResultId"] != expected_scope or raw["sourcePath"] != paths[0]
            or raw["rawStructuredFields"] != expected_fields):
            return None
        semantic = parse_node_test_semantic_result(
            streams["stdout"], command_id=record["commandId"], authorized_test_paths=paths,
        )
        if semantic is None:
            return None
        # Preserve exact test-name/payload Unicode too: the general frame's NFC
        # string normalization is not an authorized reporter transformation.
        semantic_bytes = json.dumps(
            semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8", errors="strict")
        canonical = _canonical_frame({
            "digestDomain": "ieltmps-direct-node-test-semantic-result-v1", "resultUtf8": semantic_bytes,
        })
        output_identity = {
            "stdoutSha256": hashlib.sha256(canonical).hexdigest(),
            "stdoutBytesObserved": len(canonical),
        }
        semantic_source_digest = canonical_failure_digest({
            "digestDomain": "ieltmps-direct-node-test-semantic-source-output-v1",
            "resultUtf8": semantic_bytes, "stderrSha256": record["stderrSha256"],
            "stderrBytesObserved": record["stderrBytesObserved"],
        })
        portable_raw = copy.deepcopy(raw)
        portable_raw["rawStructuredFields"]["stdout"] = semantic
        portable_raw["sourceOutputDigest"] = semantic_source_digest
        portable_raw["producerRecordDigest"] = _producer_record_digest({
            key: value for key, value in portable_raw.items() if key != "producerRecordDigest"
        })
        return {
            **output_identity, "semanticSourceOutputDigest": semantic_source_digest,
            "producerObservations": [portable_raw],
            "producerObservationSetDigest": producer_observation_set_digest([portable_raw]),
        }
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return None


def _portable_node_test_observation_source(record: Mapping[str, Any]) -> Mapping[str, Any]:
    if _direct_node_test_authorized_paths(record) is None or record.get("exitCode") != 0:
        return record
    projection = _validated_direct_node_test_semantic_projection(
        record, protected_bundle_valid=_validated_portable_protected_input_bundle_digest(record) is not None,
    )
    return {**record, **projection} if projection is not None else record


def _canonical_transcript_record(record: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(record)
    portable_stdin_authority = _validated_portable_target_stdin_input_authority(record)
    invalid_stdin_authority = (
        record.get("executionInputMode") == "TARGET-BYTES-STDIN"
        or record.get("targetExecutionLease") is not None
    ) and portable_stdin_authority is None
    if invalid_stdin_authority:
        source["invalidTargetStdinLocalEvidence"] = True
    if source.get("executionLease") is not None:
        portable_bash_lease = _validated_portable_git_bash_execution_lease(record)
        if portable_bash_lease is None:
            source["invalidGitBashLeaseLocalEvidence"] = True
        else:
            source["executionLease"] = portable_bash_lease
    portable_bundle_digest = _validated_portable_protected_input_bundle_digest(source)
    portable_containment = _validated_portable_static_containment(
        record, protected_bundle_valid=portable_bundle_digest is not None,
    )
    if portable_containment is not None:
        source.update(portable_containment)
    invalid_protected_bundle = (
        source.get("executionInputMode") == "PROTECTED-TARGET-BUNDLE"
        or source.get("protectedTargetBundle") is not None
    ) and portable_bundle_digest is None
    bundle_output_identity = _validated_bundle_normalization_success_output_identity(
        record, protected_bundle_valid=portable_bundle_digest is not None,
    )
    if bundle_output_identity is not None:
        source.update(bundle_output_identity)
    node_projection = _validated_direct_node_test_semantic_projection(
        record, protected_bundle_valid=portable_bundle_digest is not None,
    )
    if node_projection is not None:
        source.update(node_projection)
        source.pop("directNodeTestRawStreams", None)
        external_containment = _validated_portable_successful_external_test_containment(
            record, protected_bundle_valid=True, node_test_semantics_valid=True,
        )
        if external_containment is not None:
            source.update(external_containment)
    if "validatedStaticMachineReport" in source:
        static_output_identity = (
            _validated_static_machine_output_identity(record)
            if portable_bundle_digest is not None else None
        )
        if static_output_identity is None:
            source["invalidStaticMachineLocalEvidence"] = True
        else:
            source.update(static_output_identity)
    if invalid_protected_bundle:
        # Even a forged raw digest equal to the portable digest cannot make
        # invalid physical evidence indistinguishable from a valid transcript.
        source["invalidProtectedBundleLocalEvidence"] = True
    if "executionInputs" in source and not (invalid_protected_bundle or invalid_stdin_authority):
        source["executionInputs"] = _canonical_protected_execution_inputs(source)
    protected_source = source.get("protectedTargetBundle")
    if isinstance(protected_source, Mapping) and not invalid_protected_bundle:
        source = {
            key: copy.deepcopy(value)
            for key, value in source.items()
            if key != "protectedTargetBundle"
        }
        protected_projection = {
            key: copy.deepcopy(value)
            for key, value in protected_source.items()
            if key
            not in {
                *_PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS,
                "preExecutionIdentities",
                "postExecutionIdentities",
            }
        }
        for key in _PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS:
            protected_projection[key] = []
        protected_projection["preExecutionIdentities"] = (
            _canonical_protected_identity_array(
                source,
                protected_source.get("preExecutionIdentities"),
                phase="pre",
            )
        )
        protected_projection["postExecutionIdentities"] = (
            _canonical_protected_identity_array(
                source,
                protected_source.get("postExecutionIdentities"),
                phase="post",
            )
        )
        source["executionInputBundleDigest"] = portable_bundle_digest
        protected_projection["executionInputBundleDigest"] = portable_bundle_digest
        source["protectedTargetBundle"] = protected_projection
    if portable_stdin_authority is not None:
        source.update(portable_stdin_authority)
    invalid_input_authority = invalid_protected_bundle or invalid_stdin_authority
    canonical = _canonical_replay_value(source)
    canonical.pop("durationSeconds", None)
    tool_role = str(canonical.get("toolRole", "unknown"))
    for field_name in (
        "argv",
        "logicalArgv",
        "executionArgv",
        "actualExecutionArgv",
    ):
        values = canonical.get(field_name)
        if isinstance(values, list) and values:
            values[0] = f"<TRUSTED-TOOL:{tool_role}>"
    canonical["resolvedExecutablePath"] = f"<TRUSTED-TOOL:{tool_role}>"
    canonical["resolvedExecutableFileIdentity"] = None
    if canonical.get("dependencyBacked"):
        canonical["runtimeClosureDigest"] = "<FRESH-RUNTIME-CLOSURE>"
        canonical["resolvedTestRunnerEntrypoint"] = (
            f"<TRUSTED-TOOL:{tool_role}>"
        )
    for target in ([] if invalid_input_authority else canonical.get("targets", [])):
        if isinstance(target, dict):
            target["canonicalSourcePath"] = None
            target["fileIdentity"] = None
    for execution_input in (
        [] if invalid_input_authority or portable_stdin_authority is not None
        else canonical.get("executionInputs", [])
    ):
        if isinstance(execution_input, dict):
            execution_input["canonicalSourcePath"] = None
            execution_input["plannedStableIdentity"] = None
    lease = canonical.get("targetExecutionLease")
    if isinstance(lease, dict) and not invalid_input_authority and portable_stdin_authority is None:
        for key in (
            "canonicalSourcePath",
            "plannedStableFileIdentity",
            "heldStableFileIdentity",
        ):
            if key in lease:
                lease[key] = None
    protected = canonical.get("protectedTargetBundle")
    if isinstance(protected, dict) and not invalid_protected_bundle:
        for key in _PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS:
            protected[key] = []
    canonical["executionDurationClass"] = record.get("executionDurationClass")
    return canonical


def producer_transcript_digest(
    command_plan_digest_value: str,
    command_records: Sequence[Mapping[str, Any]],
    completed_classes: Sequence[str],
) -> str:
    universe = producer_observation_universe(command_records)
    return canonical_failure_digest(
        {
            "commandPlanDigest": command_plan_digest_value,
            "orderedCommandTranscript": [
                _canonical_transcript_record(record) for record in command_records
            ],
            "orderedProducerObservationUniverse": universe,
            "producerObservationUniverseDigest": canonical_failure_digest(universe),
            "completedCommandClasses": sorted(set(completed_classes)),
            "completedCommandClassSetDigest": completed_command_class_set_digest(
                completed_classes
            ),
        }
    )


def command_id_set_differences(
    command_plan: Sequence[Mapping[str, Any]],
    command_records: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    planned_ids = [str(record.get("commandId", "")) for record in command_plan]
    actual_ids = [str(record.get("commandId", "")) for record in command_records]
    counts: dict[str, int] = defaultdict(int)
    for command_id in actual_ids:
        counts[command_id] += 1
    return (
        sorted(set(planned_ids) - set(actual_ids)),
        sorted(set(actual_ids) - set(planned_ids)),
        sorted(command_id for command_id, count in counts.items() if count > 1),
    )


def _ensure_runner_authorization_context_binding(
    runner: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    execution_binding = getattr(runner, "execution_binding", None)
    if not isinstance(execution_binding, Mapping):
        return None, None
    expected_verifier_job_id: str | None = None
    external_context = getattr(runner, "external_verification_context", None)
    if isinstance(external_context, ExternallyExpectedVerificationContext):
        expected_verifier_job_id = external_context.verifier_job_id
    derived = authorization_context_binding_from_execution_binding(
        execution_binding,
        expected_verifier_job_id=expected_verifier_job_id,
    )
    runner_release_gate_required = getattr(
        runner,
        "release_gate_required",
        None,
    )
    if derived["releaseGateRequired"] is not runner_release_gate_required:
        raise ValueError(
            "runner release authority differs from producer execution binding"
        )
    existing = getattr(runner, "authorization_context_binding", None)
    if existing is not None and existing != derived:
        raise ValueError(
            "runner authorization context differs from producer/verifier authority"
        )
    digest = authorization_context_binding_digest(derived)
    runner.authorization_context_binding = copy.deepcopy(derived)
    runner.authorization_context_binding_digest = digest
    return derived, digest


def finalize_evidence_transcript(runner: Any) -> dict[str, Any]:
    """Bind raw producer facts before any baseline-derived evidence is persisted."""

    _authorization_binding, authorization_digest = (
        _ensure_runner_authorization_context_binding(runner)
    )
    records = list(getattr(runner, "command_results", []))
    plan = list(getattr(runner, "command_plan", []))
    plan_digest = command_plan_digest(plan)
    for record in records:
        producer = record.get("producerObservations", [])
        if not isinstance(producer, list):
            producer = []
            record["producerObservations"] = producer
        record["producerObservationSetDigest"] = producer_observation_set_digest(producer)
    expected_classes = expected_completed_command_classes(plan)
    actual_classes = actual_completed_command_classes(plan, records)
    for record in records:
        record["completedCommandClass"] = (
            record.get("commandClass") if _command_completed_for_class(record) else None
        )
    universe_digest = producer_observation_universe_digest(records)
    transcript_digest = producer_transcript_digest(plan_digest, records, actual_classes)
    class_digest = completed_command_class_set_digest(actual_classes)
    expected_class_digest = completed_command_class_set_digest(expected_classes)
    missing_ids, extra_ids, duplicate_ids = command_id_set_differences(plan, records)
    context = {
        "producerObservationUniverseDigest": universe_digest,
        "producerTranscriptDigest": transcript_digest,
        "profileCompletedCommandClassSetDigest": class_digest,
        "authorizationContextBindingDigest": authorization_digest,
    }
    rebound: list[dict[str, Any]] = []
    by_id = {
        str(record.get("commandId", "")): record
        for record in records
        if isinstance(record, Mapping)
    }
    for item in list(getattr(runner, "observations", [])):
        raw = item.get("rawObservation") if isinstance(item, Mapping) else None
        command_id = str(
            item.get("commandId", "")
            if isinstance(item, Mapping)
            else ""
        ) or str(raw.get("commandId", "") if isinstance(raw, Mapping) else "")
        source = by_id.get(command_id)
        rebound.append(
            _rederive_observation_record(item, source, profile_context=context)
            if source is not None and isinstance(item, Mapping)
            else copy.deepcopy(dict(item))
        )
    runner.observations = rebound
    runner.completed_classes = set(actual_classes)
    runner.command_plan_digest = plan_digest
    runner.expected_completed_command_classes = expected_classes
    runner.actual_completed_command_classes = actual_classes
    runner.expected_completed_command_class_set_digest = expected_class_digest
    runner.completed_command_class_set_digest = class_digest
    runner.producer_observation_universe_digest = universe_digest
    runner.producer_transcript_digest = transcript_digest
    runner.producer_observation_count = sum(
        len(record.get("producerObservations", []))
        for record in records
        if isinstance(record.get("producerObservations", []), list)
    )
    runner.missing_command_ids = missing_ids
    runner.extra_command_ids = extra_ids
    runner.duplicate_command_ids = duplicate_ids
    return context


def _command_authority_violations(
    profile: str,
    command_records: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    *,
    expected_plan: Sequence[Mapping[str, Any]] | None = None,
    cross_job: bool = False,
) -> list[dict[str, Any]]:
    if (
        len(command_records) == 1
        and command_records[0].get("commandId") == "command-results-size-limit"
    ):
        parsed = command_records[0].get("parsedFailureSummary")
        bounded_detail = (
            parsed.get("diagnostic")
            if isinstance(parsed, Mapping)
            and isinstance(parsed.get("diagnostic"), str)
            and parsed.get("diagnostic", "").startswith(
                "OUTPUT-LIMIT-EXCEEDED for command-results.json "
            )
            else "OUTPUT-LIMIT-EXCEEDED for command-results.json"
        )
        return [
            {
                "id": "COMMAND-RESULT-JSON-LIMIT",
                "detail": bounded_detail,
            }
        ]
    expected = list(expected_plan or expected_command_authority(profile))
    authority_fields = set(expected[0]) if expected else set()
    actual = [
        {key: record.get(key) for key in authority_fields}
        for record in command_records
    ]
    violations: list[dict[str, Any]] = []
    # Physical identities are exact within an execution domain. Across jobs,
    # bind producer records to the independently rebuilt verifier plan through
    # the same portable projection used for commandAuthority and plan digests.
    authority_matches = (
        _portable_command_plan_value(actual) == _portable_command_plan_value(expected)
        if cross_job else actual == expected
    )
    if not authority_matches:
        violations.append(
            {
                "id": "COMMAND-AUTHORITY-MISMATCH",
                "expectedCommandIds": [item["commandId"] for item in expected],
                "observedCommandIds": [item.get("commandId") for item in actual],
            }
        )
    command_ids = [str(record.get("commandId", "")) for record in command_records]
    if len(command_ids) != len(set(command_ids)):
        violations.append({"id": "DUPLICATE-COMMAND-ID"})
    expected_by_id = {item["commandId"]: item for item in expected}
    observations_by_command: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in observations:
        observations_by_command[str(item.get("commandId", ""))].append(item)
    for record in command_records:
        command_id = str(record.get("commandId", ""))
        authority = expected_by_id.get(command_id)
        if authority is None:
            continue
        # Cross-job semantic equality above binds executionArgv to the verifier.
        # Actual argv must still exactly match the producer's own local argv.
        execution_argv = (
            record.get("executionArgv") if cross_job else authority.get("executionArgv")
        )
        if record.get("actualExecutionArgv") != execution_argv:
            violations.append(
                {"id": "EXECUTION-ARGV-MISMATCH", "commandId": command_id}
            )
        if record.get("actualExecutionInputMode") != authority.get("executionInputMode"):
            violations.append(
                {"id": "EXECUTION-INPUT-MODE-MISMATCH", "commandId": command_id}
            )
        if authority.get("executionInputMode") == "TARGET-BYTES-STDIN" and (
            record.get("actualExecutionInputSize") != authority.get("executionInputSize")
            or record.get("actualExecutionInputSha256") != authority.get("executionInputSha256")
            or not isinstance(record.get("targetExecutionLease"), Mapping)
            or record.get("targetExecutionLease", {}).get("mutationDetected") is not False
        ):
            violations.append(
                {"id": "EXECUTION-INPUT-IDENTITY-MISMATCH", "commandId": command_id}
            )
        execution_completed = _command_execution_completed(record)
        if not execution_completed:
            if authority["required"]:
                violations.append(
                    {
                        "id": "REQUIRED-COMMAND-EXECUTION",
                        "commandId": command_id,
                        "exitCode": record.get("exitCode"),
                    }
                )
            continue
        exit_code = record.get("exitCode")
        if exit_code not in authority.get("allowedExecutionExits", []):
            violations.append(
                {
                    "id": "COMMAND-EXIT-OUTSIDE-AUTHORITY",
                    "commandId": command_id,
                    "exitCode": exit_code,
                }
            )
            continue
        if authority.get("commandRole") == "required-execution" and exit_code != 0:
            violations.append(
                {
                    "id": "REQUIRED-COMMAND-NONZERO",
                    "commandId": command_id,
                    "exitCode": exit_code,
                }
            )
        if authority.get("commandRole") == "observation-producing" and exit_code != 0:
            sourced = observations_by_command.get(command_id, [])
            if not sourced or not any(item.get("outcome") not in {"pass", "skip"} for item in sourced):
                violations.append(
                    {
                        "id": "NONZERO-COMMAND-WITHOUT-OBSERVATION",
                        "commandId": command_id,
                    }
                )
    return violations


def _canonical_target_occurs_in_raw_fields(value: Any, logical_target: str) -> bool:
    if isinstance(value, Mapping):
        return any(
            _canonical_target_occurs_in_raw_fields(child, logical_target)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(
            _canonical_target_occurs_in_raw_fields(child, logical_target)
            for child in value
        )
    if not isinstance(value, str):
        return False
    token = f"<repo>/{logical_target}"
    return re.search(
        re.escape(token) + r"(?![A-Za-z0-9_.%+@~/?#\\-])",
        value,
    ) is not None


def _release_skip_missing_target_is_authorized(
    source: Mapping[str, Any],
    raw_fields: Any,
    logical_target: str,
) -> bool:
    """Authorize one exact absent release input from a protected static snapshot."""

    if not isinstance(raw_fields, Mapping):
        return False
    scope = f"result:{raw_fields.get('name', '')}"
    if RELEASE_ONLY_SKIP_FAILURE_TARGETS.get(scope) != logical_target:
        return False
    detail = raw_fields.get("detail")
    if not isinstance(detail, Mapping):
        return False
    source_targets = {
        str(target.get("path"))
        for target in source.get("targets", [])
        if isinstance(target, Mapping) and isinstance(target.get("path"), str)
    }
    return (
        source.get("commandId") == "static-suite"
        and source.get("commandClass") == "static-suite"
        and source.get("toolRole") == "python-static-producer"
        and source.get("resultSemantics") == "machine-v2-complete-execution"
        and source.get("actualExecutionInputMode") == "PROTECTED-TARGET-BUNDLE"
        and raw_fields.get("status") == "pass"
        and nested_skip(detail)
        and detail.get("reason")
        == f"missing_checklist:<repo>/{logical_target}"
        and logical_target not in source_targets
    )


def _validate_failure_path_authority(
    value: Any,
    *,
    label: str,
    source: Mapping[str, Any] | None,
    raw_fields: Any,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict) or set(value) != FAILURE_PATH_AUTHORITY_KEYS:
        return [f"{label}: failure-path authority schema is not exact"]
    errors: list[str] = []
    if value.get("schemaVersion") != 1:
        errors.append(f"{label}: failure-path authority schema version is invalid")
    if value.get("canonicalizationKind") != "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1":
        errors.append(f"{label}: failure-path authority kind is invalid")

    sequence_keys = (
        "authorizedTargetPaths",
        "authorizedToolRoles",
        "unmappedAbsolutePathDigests",
        "literalPlaceholderDigests",
    )
    for key in sequence_keys:
        items = value.get(key)
        if (
            not isinstance(items, list)
            or any(not isinstance(item, str) or not item for item in items)
            or items != sorted(set(items))
        ):
            errors.append(f"{label}: {key} must be a sorted unique string array")

    target_paths = value.get("authorizedTargetPaths")
    if isinstance(target_paths, list):
        for target in target_paths:
            if isinstance(target, str) and not _safe_failure_logical_target(target):
                errors.append(f"{label}: authorized target path is unsafe")
            elif isinstance(target, str) and not _canonical_target_occurs_in_raw_fields(
                raw_fields,
                target,
            ):
                errors.append(
                    f"{label}: authorized target path is absent from canonical identity input"
                )

    for key in ("unmappedAbsolutePathDigests", "literalPlaceholderDigests"):
        items = value.get(key)
        if isinstance(items, list) and any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
            for item in items
            if isinstance(item, str)
        ):
            errors.append(f"{label}: {key} contains an invalid digest")

    if source is not None:
        source_targets = {
            str(target.get("path"))
            for target in source.get("targets", [])
            if isinstance(target, Mapping) and isinstance(target.get("path"), str)
        }
        if isinstance(target_paths, list) and any(
            target not in source_targets
            and not _release_skip_missing_target_is_authorized(
                source,
                raw_fields,
                target,
            )
            for target in target_paths
        ):
            errors.append(f"{label}: target path is outside source command authority")
        roles = value.get("authorizedToolRoles")
        source_role = source.get("toolRole")
        if isinstance(roles, list) and any(role != source_role for role in roles):
            errors.append(f"{label}: tool role is outside source command authority")
    return errors


def _source_observation_kinds(source: Mapping[str, Any]) -> frozenset[str]:
    """Return parser roles authorized by immutable source-command identity."""

    command_id = str(source.get("commandId", ""))
    command_class = str(source.get("commandClass", ""))
    if source.get("resultSemantics") == "synthetic-replay-fixture":
        return RAW_OBSERVATION_KINDS
    if command_id == "static-suite" and command_class == "static-suite":
        return frozenset({"static-producer-v1"})
    if (
        command_class == "direct-syntax"
        and command_id.startswith("node-check:")
        and command_id != "node-check:"
    ):
        return frozenset({"process-output-v1"})
    if command_id == "learner-focused" and command_class == "learner-focused":
        return frozenset({"process-output-v1"})
    if (
        command_class == "frontend-security"
        and command_id.startswith("frontend-security:")
        and command_id != "frontend-security:"
    ):
        return frozenset({"process-output-v1"})
    if command_id == "backend-canonical" and command_class == "backend-canonical":
        return frozenset({"process-output-v1"})
    if (
        command_id == "standalone-membership-audit"
        and command_class == "standalone-membership"
    ):
        return frozenset({"standalone-membership-v1"})
    return frozenset()


def _validate_raw_observation(
    raw: Any,
    *,
    label: str,
    source: Mapping[str, Any] | None,
    source_output_digest: str | None = None,
) -> list[str]:
    expected_keys = {
        "schemaVersion",
        "commandId",
        "commandOrdinal",
        "observationOrdinal",
        "observationKind",
        "sourceResultId",
        "sourcePath",
        "rawStructuredFields",
        "failurePathAuthority",
        "sourceOutputDigest",
        "occurrences",
        "producerRecordDigest",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        return [f"{label}: raw observation schema is not exact"]
    errors: list[str] = []
    if raw.get("schemaVersion") != RAW_OBSERVATION_SCHEMA_VERSION:
        errors.append(f"{label}: raw observation schema version is invalid")
    for key in ("commandId", "observationKind", "sourceResultId", "sourceOutputDigest", "producerRecordDigest"):
        if not isinstance(raw.get(key), str) or not raw.get(key):
            errors.append(f"{label}: {key} must be a non-empty string")
    if raw.get("observationKind") not in RAW_OBSERVATION_KINDS:
        errors.append(f"{label}: observationKind is not authorized")
    if (
        source is not None
        and raw.get("observationKind") not in _source_observation_kinds(source)
    ):
        errors.append(
            f"{label}: observationKind is outside source command observation authority"
        )
    for key in ("commandOrdinal", "observationOrdinal"):
        if type(raw.get(key)) is not int or not 0 <= raw.get(key, -1) < MAX_EVIDENCE_COLLECTION_ITEMS:
            errors.append(f"{label}: {key} must be a bounded non-negative integer")
    if type(raw.get("occurrences")) is not int or not 1 <= raw.get("occurrences", 0) <= MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: occurrences must be a bounded positive integer")
    source_path = raw.get("sourcePath")
    if source_path is not None and (
        not isinstance(source_path, str)
        or not source_path
        or Path(source_path).is_absolute()
        or "\\" in source_path
        or any(part in {"", ".", ".."} for part in source_path.split("/"))
    ):
        errors.append(f"{label}: sourcePath must be null or a safe repository-relative path")
    errors.extend(
        f"{label}: {error}"
        for error in _raw_observation_forbidden_fields(raw.get("rawStructuredFields"))
    )
    errors.extend(
        _validate_failure_path_authority(
            raw.get("failurePathAuthority"),
            label=label,
            source=source,
            raw_fields=raw.get("rawStructuredFields"),
        )
    )
    digest_source = {key: value for key, value in raw.items() if key != "producerRecordDigest"}
    try:
        expected_digest = _producer_record_digest(digest_source)
    except (TypeError, ValueError) as exc:
        errors.append(f"{label}: raw observation cannot be canonically framed ({type(exc).__name__})")
    else:
        if raw.get("producerRecordDigest") != expected_digest:
            errors.append(f"{label}: producerRecordDigest is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(raw.get("sourceOutputDigest", ""))):
        errors.append(f"{label}: sourceOutputDigest is invalid")
    if source is not None:
        if raw.get("commandId") != source.get("commandId"):
            errors.append(f"{label}: commandId does not bind the source command")
        if raw.get("commandOrdinal") != source.get("ordinal"):
            errors.append(f"{label}: commandOrdinal does not bind the source command")
        expected_output_digest = (
            source_output_digest
            if source_output_digest is not None
            else command_output_digest(source)
        )
        if raw.get("sourceOutputDigest") != expected_output_digest:
            errors.append(f"{label}: sourceOutputDigest does not bind the producer command streams")
    return errors


def _decode_protected_utf8(data: bytes, logical_path: str) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        raise UnicodeError(f"{logical_path} must be UTF-8 without BOM")
    return data.decode("utf-8", errors="strict")


def run_workflow_policy(
    workflow_bytes: bytes,
    ci_policy_bytes: bytes,
    baseline_bytes: bytes,
    expected_target_authority: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Validate workflow governance from protected bytes without reopening paths."""

    logical_inputs = (
        (".github/workflows/ci.yml", workflow_bytes),
        ("docs/CI_POLICY.md", ci_policy_bytes),
        ("developer/tests/ci/phase1-ci-baseline.json", baseline_bytes),
    )
    errors: list[str] = []
    if [target.get("path") for target in expected_target_authority] != [
        logical_path for logical_path, _data in logical_inputs
    ]:
        return ["workflow policy protected target order is not exact"]
    for (logical_path, data), target in zip(logical_inputs, expected_target_authority):
        if not isinstance(data, bytes):
            errors.append(f"{logical_path}: protected input is not bytes")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != target.get("size") or digest != target.get("sha256"):
            errors.append(f"{logical_path}: protected input identity differs from the command plan")
    if errors:
        return errors
    try:
        workflow_text = _decode_protected_utf8(workflow_bytes, logical_inputs[0][0])
        policy_text = _decode_protected_utf8(ci_policy_bytes, logical_inputs[1][0])
        baseline_text = _decode_protected_utf8(baseline_bytes, logical_inputs[2][0])
        baseline = strict_json_loads(baseline_text, label=logical_inputs[2][0])
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"protected workflow-policy input cannot be decoded: {type(exc).__name__}: {exc}"]
    errors.extend(validate_baseline_document(baseline))
    errors.extend(check_workflow_text(workflow_text))
    errors.extend(check_governance_language(workflow_text, policy_text))
    return sorted(set(errors))


def _validate_observation_record(
    item: Any,
    index: int,
    command_by_id: Mapping[str, Mapping[str, Any]],
    *,
    authorization_context_binding_digest_value: str | None = None,
    source_output_digests: Mapping[int, str] | None = None,
) -> list[str]:
    label = f"command-results.json.observations[{index}]"
    expected_keys = {
        "commandClass",
        "testOrPathScope",
        "outcome",
        "signature",
        "legacyBaselineComparisonDigest",
        "commandId",
        "occurrences",
        "rawObservation",
        "producerObservationSetDigest",
        "producerObservationUniverseDigest",
        "producerTranscriptDigest",
        "completedCommandClass",
        "profileCompletedCommandClassSetDigest",
        "canonicalFailureMaterialVersion",
        "derivedFailureDigest",
        "currentFullContextDigest",
        "derivedFailureMembers",
        "failureIdentity",
        "failureIdentityHash",
    }
    if not isinstance(item, dict) or set(item) != expected_keys:
        return [f"{label}: schema is not exact"]
    errors: list[str] = []
    for key in (
        "commandClass",
        "testOrPathScope",
        "outcome",
        "signature",
        "legacyBaselineComparisonDigest",
        "commandId",
        "failureIdentityHash",
        "derivedFailureDigest",
        "currentFullContextDigest",
        "producerObservationSetDigest",
        "producerObservationUniverseDigest",
        "producerTranscriptDigest",
        "profileCompletedCommandClassSetDigest",
    ):
        if not isinstance(item.get(key), str) or not item.get(key):
            errors.append(f"{label}: {key} must be a non-empty string")
    if type(item.get("occurrences")) is not int or not 1 <= item.get("occurrences", 0) <= MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: occurrences must be a bounded positive integer")
    identity = item.get("failureIdentity")
    if not isinstance(identity, dict):
        errors.append(f"{label}: failureIdentity must be an object")
    elif item.get("failureIdentityHash") != failure_identity_hash(identity):
        errors.append(f"{label}: failureIdentityHash is invalid")
    members = item.get("derivedFailureMembers")
    if not isinstance(members, list) or not members or len(members) > MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: derivedFailureMembers must be a bounded non-empty array")
    if item.get("canonicalFailureMaterialVersion") != CANONICAL_FAILURE_MATERIAL_VERSION:
        errors.append(f"{label}: canonicalFailureMaterialVersion is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("derivedFailureDigest", ""))):
        errors.append(f"{label}: derivedFailureDigest is invalid")
    if item.get("legacyBaselineComparisonDigest") != item.get("signature"):
        errors.append(f"{label}: legacy comparison digest alias is inconsistent")
    if item.get("currentFullContextDigest") != item.get("derivedFailureDigest"):
        errors.append(f"{label}: current full-context digest alias is inconsistent")
    source = command_by_id.get(str(item.get("commandId", "")))
    if source is None:
        errors.append(f"{label}: source command is missing")
    elif source.get("commandClass") != item.get("commandClass"):
        errors.append(f"{label}: source command class is inconsistent")
    elif (
        source.get("producerObservationSetDigest")
        != item.get("producerObservationSetDigest")
        or source.get("completedCommandClass") != item.get("completedCommandClass")
    ):
        errors.append(
            f"{label}: producer/completed-command context is not independently derived"
        )
    elif source.get("executed") is not True or source.get("setupFailure") is not False:
        errors.append(f"{label}: source command did not execute successfully enough to emit observations")
    else:
        raw = item.get("rawObservation")
        errors.extend(_validate_raw_observation(
            raw,
            label=f"{label}.rawObservation",
            source=source,
            source_output_digest=(
                source_output_digests.get(id(source))
                if source_output_digests is not None else None
            ),
        ))
        if isinstance(raw, dict):
            command_class = str(item.get("commandClass", ""))
            scope = str(item.get("testOrPathScope", ""))
            expected_raw_path: str | None = None
            expected_result_id = scope
            if command_class == "static-suite" and scope.startswith("result:"):
                expected_raw_path = STATIC_SUITE_RELATIVE_PATH
                expected_result_id = scope[len("result:") :]
            elif command_class == "direct-syntax":
                expected_raw_path = scope
            elif command_class == "learner-focused":
                expected_raw_path = "developer/tests/js/learnerPalette.test.js"
            elif command_class == "frontend-security" and scope.startswith("file:"):
                expected_raw_path = scope[len("file:") :]
            elif command_class == "backend-canonical":
                expected_raw_path = "backend/package.json"
            elif command_class == "standalone-membership" and scope.startswith(
                "membership:index.html::"
            ):
                expected_raw_path = scope[len("membership:index.html::") :]
            if raw.get("sourceResultId") != expected_result_id:
                errors.append(f"{label}: raw sourceResultId does not match the immutable scope")
            if expected_raw_path is not None and raw.get("sourcePath") != expected_raw_path:
                errors.append(f"{label}: raw sourcePath does not match the immutable scope")
            producer = source.get("producerObservations")
            matches = (
                [candidate for candidate in producer if candidate == raw]
                if isinstance(producer, list)
                else []
            )
            if len(matches) != 1:
                errors.append(f"{label}: raw observation is not bound exactly once to the producer command")
            try:
                derived = _rederive_observation_record(
                    item,
                    source,
                    profile_context={
                        "producerObservationUniverseDigest": item.get(
                            "producerObservationUniverseDigest"
                        ),
                        "producerTranscriptDigest": item.get(
                            "producerTranscriptDigest"
                        ),
                        "profileCompletedCommandClassSetDigest": item.get(
                            "profileCompletedCommandClassSetDigest"
                        ),
                        "authorizationContextBindingDigest": (
                            authorization_context_binding_digest_value
                        ),
                    },
                )
            except (TypeError, ValueError) as exc:
                errors.append(f"{label}: canonical failure derivation failed ({type(exc).__name__})")
            else:
                for derived_key in expected_keys:
                    if item.get(derived_key) != derived.get(derived_key):
                        errors.append(f"{label}: {derived_key} does not equal the independently derived value")
        command_class = str(item.get("commandClass", ""))
        scope = str(item.get("testOrPathScope", ""))
        expected_source: str | None = None
        if command_class == "static-suite":
            expected_source = "static-suite"
        elif command_class == "direct-syntax":
            expected_source = f"node-check:{scope}"
        elif command_class == "learner-focused":
            expected_source = "learner-focused"
        elif command_class == "frontend-security" and scope.startswith("file:"):
            expected_source = f"frontend-security:{Path(scope[5:]).name}"
        elif command_class == "backend-canonical":
            expected_source = "backend-canonical"
        elif command_class == "standalone-membership":
            expected_source = "standalone-membership-audit"
        if expected_source is not None and item.get("commandId") != expected_source:
            errors.append(f"{label}: source command does not match the immutable scope binding")
        outcome = item.get("outcome")
        if outcome == "pass" and not _required_command_execution_passed(source):
            errors.append(f"{label}: passing observation came from a non-passing command")
        if (
            outcome not in {"pass", "skip"}
            and command_class != "static-suite"
            and source.get("exitCode") == 0
        ):
            errors.append(f"{label}: non-pass observation contradicts a zero-exit source command")
    return errors


def derive_authoritative_evidence(
    profile: str,
    observations: Sequence[Mapping[str, Any]],
    completed_command_classes: Iterable[str],
    command_records: Sequence[Mapping[str, Any]],
    immutable_baseline_authority: Mapping[str, Any],
    current_platform: str,
    command_plan: Sequence[Mapping[str, Any]] | None = None,
    authorization_context_binding_digest_value: str | None = None,
    *,
    release_gate_required: bool,
    cross_job: bool = False,
) -> dict[str, Any]:
    """Recompute all semantic evidence from commands and the frozen baseline map."""

    release_gate_required = _require_resolved_release_gate_required(
        profile,
        release_gate_required,
    )

    command_by_id: dict[str, Mapping[str, Any]] = {}
    derivation_violations: list[dict[str, Any]] = []
    for record in command_records:
        command_id = str(record.get("commandId", ""))
        if not command_id or command_id in command_by_id:
            continue
        command_by_id[command_id] = record
    # This operation does not mutate command evidence. Validate structured
    # source-output authority once per command, then reuse it for its records.
    source_output_digests = {
        id(record): command_output_digest(record)
        for record in command_records
    }
    valid_observations: list[Mapping[str, Any]] = []
    for index, item in enumerate(observations):
        item_errors = _validate_observation_record(
            item,
            index,
            command_by_id,
            authorization_context_binding_digest_value=(
                authorization_context_binding_digest_value
            ),
            source_output_digests=source_output_digests,
        )
        if item_errors:
            derivation_violations.extend(
                {"id": "MALFORMED-COMMAND-OBSERVATION", "detail": error}
                for error in item_errors
            )
        else:
            valid_observations.append(item)
    evidence_raw = [
        item.get("rawObservation")
        for item in valid_observations
        if isinstance(item.get("rawObservation"), dict)
    ]
    producer_raw: list[Mapping[str, Any]] = []
    producer_identities: set[tuple[str, int]] = set()
    producer_digests: set[str] = set()
    for record in command_records:
        command_id = str(record.get("commandId", ""))
        records = record.get("producerObservations")
        if not isinstance(records, list):
            derivation_violations.append(
                {"id": "MALFORMED-PRODUCER-OBSERVATION-SET", "commandId": command_id}
            )
            continue
        if record.get("producerObservationSetDigest") != producer_observation_set_digest(records):
            derivation_violations.append(
                {"id": "PRODUCER-OBSERVATION-SET-DIGEST-MISMATCH", "commandId": command_id}
            )
        observed_ordinals: list[int] = []
        for index, raw in enumerate(records):
            raw_errors = _validate_raw_observation(
                raw,
                label=f"command:{command_id}.producerObservations[{index}]",
                source=record,
                source_output_digest=source_output_digests.get(id(record)),
            )
            if raw_errors:
                derivation_violations.extend(
                    {"id": "MALFORMED-PRODUCER-OBSERVATION", "detail": error}
                    for error in raw_errors
                )
                continue
            assert isinstance(raw, dict)
            identity = (command_id, int(raw["observationOrdinal"]))
            digest = str(raw["producerRecordDigest"])
            if identity in producer_identities or digest in producer_digests:
                derivation_violations.append(
                    {
                        "id": "DUPLICATE-PRODUCER-OBSERVATION",
                        "commandId": command_id,
                        "observationOrdinal": raw["observationOrdinal"],
                    }
                )
            producer_identities.add(identity)
            producer_digests.add(digest)
            observed_ordinals.append(int(raw["observationOrdinal"]))
            producer_raw.append(raw)
        if observed_ordinals != list(range(len(observed_ordinals))):
            derivation_violations.append(
                {"id": "PRODUCER-OBSERVATION-ORDINAL-GAP", "commandId": command_id}
            )
        if not _source_observation_kinds(record) and records:
            derivation_violations.append(
                {"id": "UNAUTHORIZED-PRODUCER-OBSERVATION", "commandId": command_id}
            )
    evidence_keys = sorted(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for value in evidence_raw
    )
    producer_keys = sorted(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for value in producer_raw
    )
    if evidence_keys != producer_keys:
        missing = len([value for value in producer_keys if value not in evidence_keys])
        additional = len([value for value in evidence_keys if value not in producer_keys])
        derivation_violations.append(
            {
                "id": "PRODUCER-OBSERVATION-COMPLETENESS",
                "missingFromEvidence": missing,
                "additionalInEvidence": additional,
            }
        )
    completed = set(completed_command_classes)
    if any(not isinstance(value, str) or not value for value in completed):
        derivation_violations.append({"id": "MALFORMED-COMPLETED-COMMAND-CLASS"})
    comparison = compare_observations(
        immutable_baseline_authority,
        valid_observations,
        completed,
        current_platform,
        release_gate_required=release_gate_required,
        command_records=command_records,
        authorization_context_binding_digest_value=(
            authorization_context_binding_digest_value
        ),
    )
    comparison["violations"].extend(
        _command_authority_violations(
            profile,
            command_records,
            valid_observations,
            expected_plan=command_plan,
            cross_job=cross_job,
        )
    )
    comparison["violations"].extend(derivation_violations)

    valid_resolved: list[dict[str, Any]] = []
    for record in comparison["resolvedCandidates"]:
        source = command_by_id.get(str(record.get("sourceCommandId", "")))
        if source is None or not _required_command_execution_passed(source):
            comparison["violations"].append(
                {
                    "id": "RESOLVED-CANDIDATE-WITHOUT-SUCCESSFUL-SCOPE",
                    "baselineId": record.get("baselineId"),
                }
            )
        else:
            valid_resolved.append(record)
    comparison["resolvedCandidates"] = valid_resolved
    comparison["violations"] = sorted(
        comparison["violations"],
        key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )
    return comparison


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as source:
        while True:
            chunk = source.read(65_536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class ExecutableIdentityLease:
    """Hold and revalidate one security-critical executable or entrypoint."""

    def __init__(
        self,
        path: str | Path,
        role: str,
        *,
        repo_root: Path = REPO_ROOT,
        allow_dependency_root: bool = False,
    ) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise OSError(f"{role} path is not absolute")
        okay, reason = _secure_regular_file(candidate)
        if not okay:
            raise OSError(f"{role} is not a trusted regular file: {reason}")
        canonical = candidate.resolve(strict=True)
        if _path_is_within(canonical, repo_root.resolve(strict=True)) and not allow_dependency_root:
            raise OSError(f"{role} is inside the repository workspace")
        if any(part.casefold() == "node_modules" for part in canonical.parts) and not allow_dependency_root:
            raise OSError(f"{role} is inside node_modules")
        self.path = str(canonical)
        self.role = role
        self.closed = False
        self._handle: Any | None = None
        self._fd: int | None = None
        if os.name == "nt":
            from ctypes import wintypes

            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("dwFileAttributes", wintypes.DWORD),
                    ("ftCreationTime", wintypes.FILETIME),
                    ("ftLastAccessTime", wintypes.FILETIME),
                    ("ftLastWriteTime", wintypes.FILETIME),
                    ("dwVolumeSerialNumber", wintypes.DWORD),
                    ("nFileSizeHigh", wintypes.DWORD),
                    ("nFileSizeLow", wintypes.DWORD),
                    ("nNumberOfLinks", wintypes.DWORD),
                    ("nFileIndexHigh", wintypes.DWORD),
                    ("nFileIndexLow", wintypes.DWORD),
                ]

            self._info_type = BY_HANDLE_FILE_INFORMATION
            self._kernel32.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            self._kernel32.CreateFileW.restype = wintypes.HANDLE
            self._kernel32.GetFileInformationByHandle.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
            )
            self._kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
            self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            self._kernel32.CloseHandle.restype = wintypes.BOOL
            handle = self._kernel32.CreateFileW(
                self.path,
                0x80000000,
                0x00000001,
                None,
                3,
                0x00200000 | 0x00000080,
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if not handle or int(handle) == invalid:
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = handle
            self._initial_identity = self._windows_identity(handle)
        else:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            self._fd = os.open(self.path, flags)
            self._initial_identity = _stable_file_identity(os.fstat(self._fd))
        self.expected_sha256 = self._hash_open_identity()
        self.expected_size = int(Path(self.path).stat().st_size)
        okay, error = self.verify()
        if not okay:
            self.close()
            raise OSError(error or f"{role} lease verification failed")

    def _windows_identity(self, handle: Any) -> dict[str, Any]:
        info = self._info_type()
        if not self._kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "volumeSerial": str(int(info.dwVolumeSerialNumber)),
            "fileIndex": str((int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)),
            "size": (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
            "links": int(info.nNumberOfLinks),
            "writeTime": str(
                (int(info.ftLastWriteTime.dwHighDateTime) << 32)
                | int(info.ftLastWriteTime.dwLowDateTime)
            ),
            "reparsePoint": bool(int(info.dwFileAttributes) & 0x400),
        }

    def _hash_open_identity(self) -> str:
        if self._fd is None:
            return _sha256_file(Path(self.path))
        digest = hashlib.sha256()
        position = 0
        while True:
            chunk = os.pread(self._fd, 65_536, position)
            if not chunk:
                break
            digest.update(chunk)
            position += len(chunk)
        return digest.hexdigest()

    def verify(self) -> tuple[bool, str | None]:
        if self.closed:
            return False, f"{self.role} lease is closed"
        try:
            path = Path(self.path)
            okay, reason = _secure_regular_file(path)
            if not okay or str(path.resolve(strict=True)) != self.path:
                return False, f"{self.role} path drifted: {reason or 'canonical path changed'}"
            if self._handle is not None:
                identity = self._windows_identity(self._handle)
                if identity != self._initial_identity:
                    return False, f"{self.role} held identity drifted"
            else:
                assert self._fd is not None
                if _stable_file_identity(os.fstat(self._fd)) != self._initial_identity:
                    return False, f"{self.role} descriptor identity drifted"
                if _stable_file_identity(path.lstat()) != self._initial_identity:
                    return False, f"{self.role} path identity drifted"
            if self._hash_open_identity() != self.expected_sha256:
                return False, f"{self.role} SHA-256 drifted"
        except OSError as exc:
            return False, f"{self.role} lease verification failed: {type(exc).__name__}"
        return True, None

    def evidence(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "canonicalPath": self.path,
            "size": self.expected_size,
            "sha256": self.expected_sha256,
            "stableIdentity": copy.deepcopy(self._initial_identity),
            "leaseHeld": not self.closed,
        }

    def close(self) -> None:
        if self.closed:
            return
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        self.closed = True

    def __del__(self) -> None:  # pragma: no cover - last-resort handle cleanup
        try:
            self.close()
        except Exception:
            pass


_TRUSTED_TOOL_VERSION_CACHE: dict[tuple[str, str, str], str] = {}
_TRUSTED_TOOL_VERSION_CACHE_LOCK = threading.Lock()


def _captured_tool_version(
    role: str,
    tools: Mapping[str, str],
    environment: Mapping[str, str],
    lease: ExecutableIdentityLease,
) -> str:
    key = (role, lease.path, lease.expected_sha256)
    with _TRUSTED_TOOL_VERSION_CACHE_LOCK:
        cached = _TRUSTED_TOOL_VERSION_CACHE.get(key)
    if cached is not None:
        return cached
    if role == "python":
        value = f"Python {platform.python_version()}"
    else:
        if role == "npm":
            argv = [
                require_tool(tools, "node", phase="CAPTURE"),
                lease.path,
                "--version",
            ]
        elif role in {"powershell", "pwsh"}:
            argv = [
                lease.path,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ]
        else:
            argv = [lease.path, "--version"]
        completed = subprocess.run(
            argv,
            cwd=tempfile.gettempdir(),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=30,
            check=False,
        )
        output = completed.stdout + completed.stderr
        if completed.returncode != 0 or not output or len(output) > 16_384:
            raise OSError(f"trusted {role} version capture failed")
        text = output.decode("utf-8", errors="strict")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise OSError(f"trusted {role} version output is empty")
        value = lines[0]
    if not value or len(value.encode("utf-8")) > 512:
        raise OSError(f"trusted {role} version output is invalid")
    okay, error = lease.verify()
    if not okay:
        raise OSError(error or f"trusted {role} identity drifted during version capture")
    with _TRUSTED_TOOL_VERSION_CACHE_LOCK:
        _TRUSTED_TOOL_VERSION_CACHE[key] = value
    return value


def _portable_file_mode(metadata: os.stat_result) -> str:
    return format(stat.S_IMODE(metadata.st_mode), "04o")


def _dependency_member_manifest(root: Path) -> list[dict[str, Any]]:
    root_resolved = root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ValueError(
                f"dependency directory cannot be enumerated: {type(exc).__name__}"
            ) from exc
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                if Path(target).is_absolute():
                    raise ValueError(f"dependency symlink target is absolute: {relative}")
                resolved_target = path.resolve(strict=True)
                if not _path_is_within(resolved_target, root_resolved):
                    raise ValueError(f"dependency symlink escapes its root: {relative}")
                record = {
                    "relativePath": relative,
                    "fileType": "symlink",
                    "mode": _portable_file_mode(metadata),
                    "size": int(metadata.st_size),
                    "sha256": None,
                    "symlinkTarget": target.replace("\\", "/"),
                }
            elif _is_reparse_point(metadata):
                raise ValueError(f"dependency member is a reparse point: {relative}")
            elif stat.S_ISDIR(metadata.st_mode):
                record = {
                    "relativePath": relative,
                    "fileType": "directory",
                    "mode": _portable_file_mode(metadata),
                    "size": 0,
                    "sha256": None,
                    "symlinkTarget": None,
                }
                child_directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                before = _stat_identity(metadata)
                digest = _sha256_file(path)
                if _stat_identity(path.lstat()) != before:
                    raise ValueError(f"dependency member changed during measurement: {relative}")
                record = {
                    "relativePath": relative,
                    "fileType": "regular-file",
                    "mode": _portable_file_mode(metadata),
                    "size": int(metadata.st_size),
                    "sha256": digest,
                    "symlinkTarget": None,
                }
            else:
                raise ValueError(f"dependency member has an unsupported file type: {relative}")
            records.append(record)
        pending.extend(reversed(child_directories))
    return sorted(records, key=lambda item: item["relativePath"])


def _runtime_version(argv: Sequence[str], environment: Mapping[str, str]) -> str:
    completed = subprocess.run(
        list(argv),
        cwd=tempfile.gettempdir(),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stdout) > 4096 or completed.stderr:
        raise ValueError("trusted runtime product/version verification failed")
    value = completed.stdout.decode("utf-8", errors="strict").strip()
    if not value or len(value) > 256:
        raise ValueError("trusted runtime returned an invalid version")
    return value


class RuntimeClosurePreconditionError(ValueError):
    """Typed indication that no runtime-closure measurement was attempted."""

    def __init__(self, reason: str) -> None:
        normalized = str(reason).strip().upper()
        if normalized not in RUNTIME_CLOSURE_PRECONDITION_REASONS:
            normalized = "MEASUREMENT_FAILED"
        self.code = RUNTIME_CLOSURE_PRECONDITION_STATUS
        self.reason = normalized
        super().__init__(f"{self.code} reason={self.reason}")


def _runtime_precondition_document(
    profile: str,
    reason: str,
) -> tuple[dict[str, Any], str, str]:
    error = RuntimeClosurePreconditionError(reason)
    dependency_digest = hashlib.sha256(
        _canonical_frame(
            {
                "state": RUNTIME_CLOSURE_PRECONDITION_STATUS,
                "dependencyRoots": [],
                "profile": profile,
            }
        )
    ).hexdigest()
    document = {
        "closureSchemaVersion": RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
        "measurementStatus": RUNTIME_CLOSURE_PRECONDITION_STATUS,
        "preconditionReason": error.reason,
        "profile": profile,
        "runnerOS": _canonical_runner_os(),
        "dependencyClosureDigest": dependency_digest,
        "dependencyMemberCount": 0,
    }
    closure_digest = hashlib.sha256(_canonical_frame(document)).hexdigest()
    document["closureDigest"] = closure_digest
    return document, closure_digest, dependency_digest


@dataclass
class RuntimeDependencyClosure:
    document: dict[str, Any]
    runtime_digest: str
    dependency_digest: str
    member_count: int
    dependency_roots: tuple[Path, ...]
    leases: dict[str, ExecutableIdentityLease]

    @classmethod
    def build(
        cls,
        profile: str,
        tools: Mapping[str, str],
        environment: Mapping[str, str],
        *,
        repo_root: Path = REPO_ROOT,
        require_fresh_dependencies: bool = False,
        source_environment: Mapping[str, str] | None = None,
    ) -> "RuntimeDependencyClosure":
        source = os.environ if source_environment is None else source_environment
        if source.get("NODE_PATH"):
            raise ValueError("unplanned NODE_PATH is forbidden")
        if source.get("NODE_OPTIONS"):
            raise ValueError("unplanned NODE_OPTIONS is forbidden")
        python_path = Path(require_tool(tools, "python", phase="RUNTIME_CLOSURE"))
        node_value = require_tool(tools, "node", phase="RUNTIME_CLOSURE")
        npm_candidate = tools.get("npm")
        local_npm_omission = (
            npm_candidate is None
            and source.get("GITHUB_ACTIONS") != "true"
            and not require_fresh_dependencies
            and profile in {"policy", "static", "standalone"}
        )
        npm_value = (
            None
            if local_npm_omission
            else require_tool(tools, "npm", phase="RUNTIME_CLOSURE")
        )
        node_path = Path(node_value).resolve(strict=True)
        npm_path = Path(npm_value).resolve(strict=True) if npm_value is not None else None
        dependency_logical_roots: list[str] = []
        if profile in {"frontend", "all"}:
            dependency_logical_roots.append("developer/node_modules")
        if profile in {"backend", "all"}:
            dependency_logical_roots.append("backend/node_modules")
        dependency_roots: list[Path] = []
        root_records: list[dict[str, Any]] = []
        member_count = 0
        for logical in dependency_logical_roots:
            root = repo_root.joinpath(*logical.split("/"))
            if not root.is_dir():
                raise ValueError(f"required dependency root is missing: {logical}")
            metadata = root.lstat()
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ValueError(f"dependency root is a link/reparse point: {logical}")
            members = _dependency_member_manifest(root)
            member_count += len(members)
            root_records.append(
                {
                    "logicalRoot": logical,
                    "memberCount": len(members),
                    "members": members,
                    "memberManifestDigest": hashlib.sha256(_canonical_frame(members)).hexdigest(),
                }
            )
            dependency_roots.append(root.resolve(strict=True))
        if require_fresh_dependencies and source.get("CI_FRESH_DEPENDENCY_INSTALL") != "1":
            raise ValueError("fresh dependency installation marker is absent")

        lockfiles: list[dict[str, Any]] = []
        for relative in ("developer/package-lock.json", "backend/package-lock.json"):
            path = repo_root.joinpath(*relative.split("/"))
            metadata = path.lstat()
            lockfiles.append(
                {
                    "relativePath": relative,
                    "mode": _portable_file_mode(metadata),
                    "size": int(metadata.st_size),
                    "sha256": _sha256_file(path),
                }
            )

        leases: dict[str, ExecutableIdentityLease] = {}
        try:
            leases["python"] = ExecutableIdentityLease(python_path, "python-verifier")
            leases["node"] = ExecutableIdentityLease(node_path, "node-runtime")
            if npm_path is not None:
                leases["npm"] = ExecutableIdentityLease(
                    npm_path,
                    "npm-entrypoint",
                    allow_dependency_root=True,
                )
            git_value = tools.get("git")
            if git_value:
                leases["git"] = ExecutableIdentityLease(git_value, "git-authority")
            # Keep the schema-v1 field as an explicit null sentinel.  No
            # production profile resolves or leases Vitest after the
            # message-origin guard moved to Node's built-in test runner.
            vitest_record = None
            python_record = {
                **leases["python"].evidence(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
            }
            node_record = {
                **leases["node"].evidence(),
                "version": _runtime_version([str(node_path), "--version"], environment),
            }
            npm_record = (
                {
                    **leases["npm"].evidence(),
                    "available": True,
                    "version": _runtime_version(
                        [str(node_path), str(npm_path), "--version"], environment
                    ),
                }
                if npm_path is not None
                else {
                    "role": "npm-entrypoint",
                    "canonicalPath": None,
                    "size": None,
                    "sha256": None,
                    "stableIdentity": None,
                    "leaseHeld": False,
                    "available": False,
                    "version": "unavailable-local-nondependency-profile",
                }
            )
            git_record = (
                leases["git"].evidence() if "git" in leases else None
            )
            semantic_dependency = {
                "lockfiles": lockfiles,
                "dependencyRoots": root_records,
                "vitest": vitest_record,
                "nodePath": [],
            }
            dependency_digest = hashlib.sha256(
                _canonical_frame(semantic_dependency)
            ).hexdigest()
            document = {
                "closureSchemaVersion": RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
                "measurementStatus": (
                    "measured-complete"
                    if npm_path is not None
                    else "local-nondependency-npm-unavailable"
                ),
                "profile": profile,
                "runnerOS": _canonical_runner_os(),
                "pythonExecutable": python_record,
                "nodeExecutable": node_record,
                "npmEntrypoint": npm_record,
                "gitExecutable": git_record,
                "lockfiles": lockfiles,
                "dependencyRoots": root_records,
                "vitest": vitest_record,
                "nodePath": [],
                "dependencyClosureDigest": dependency_digest,
                "dependencyMemberCount": member_count,
            }
            runtime_digest = hashlib.sha256(_canonical_frame(document)).hexdigest()
            document["closureDigest"] = runtime_digest
            return cls(
                document=document,
                runtime_digest=runtime_digest,
                dependency_digest=dependency_digest,
                member_count=member_count,
                dependency_roots=tuple(dependency_roots),
                leases=leases,
            )
        except Exception:
            for lease in leases.values():
                lease.close()
            raise

    def verify_executables(self) -> list[str]:
        errors: list[str] = []
        for role, lease in self.leases.items():
            okay, error = lease.verify()
            if not okay:
                errors.append(error or f"{role} executable identity drifted")
        return errors

    def close(self) -> None:
        for lease in self.leases.values():
            lease.close()


class _MutationWatcher:
    def close(self) -> None:
        raise NotImplementedError


class _InotifyMutationWatcher(_MutationWatcher):
    IN_MODIFY = 0x00000002
    IN_ATTRIB = 0x00000004
    IN_CLOSE_WRITE = 0x00000008
    IN_MOVED_FROM = 0x00000040
    IN_MOVED_TO = 0x00000080
    IN_CREATE = 0x00000100
    IN_DELETE = 0x00000200
    IN_DELETE_SELF = 0x00000400
    IN_MOVE_SELF = 0x00000800
    IN_Q_OVERFLOW = 0x00004000
    MASK = (
        IN_MODIFY
        | IN_ATTRIB
        | IN_CLOSE_WRITE
        | IN_MOVED_FROM
        | IN_MOVED_TO
        | IN_CREATE
        | IN_DELETE
        | IN_DELETE_SELF
        | IN_MOVE_SELF
        | IN_Q_OVERFLOW
    )

    def __init__(self, roots: Sequence[Path], callback: Any) -> None:
        self.callback = callback
        self.stop_event = threading.Event()
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.inotify_init1.argtypes = (ctypes.c_int,)
        self.libc.inotify_init1.restype = ctypes.c_int
        self.libc.inotify_add_watch.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        self.libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.watch_paths: dict[int, str] = {}
        try:
            directories: set[Path] = set()
            for root in roots:
                resolved = root.resolve(strict=True)
                if resolved.is_file():
                    resolved = resolved.parent
                directories.add(resolved)
                for current, child_dirs, _files in os.walk(resolved, followlinks=False):
                    current_path = Path(current)
                    directories.add(current_path)
                    child_dirs[:] = [
                        name
                        for name in child_dirs
                        if not (current_path / name).is_symlink()
                    ]
            for directory in sorted(directories, key=lambda value: str(value)):
                wd = self.libc.inotify_add_watch(
                    self.fd,
                    os.fsencode(directory),
                    self.MASK,
                )
                if wd < 0:
                    raise OSError(ctypes.get_errno(), f"inotify_add_watch failed: {directory}")
                self.watch_paths[int(wd)] = str(directory)
            if not self.watch_paths:
                raise OSError("inotify watcher set is empty")
            self.thread = threading.Thread(target=self._run, name="ci-inotify-closure", daemon=True)
            self.thread.start()
        except Exception:
            os.close(self.fd)
            raise

    def _run(self) -> None:
        event_header = struct.Struct("iIII")
        while not self.stop_event.is_set():
            try:
                readable, _writable, _exceptional = select.select([self.fd], [], [], 0.05)
                if not readable:
                    continue
                data = os.read(self.fd, 262_144)
            except OSError as exc:
                if self.stop_event.is_set() or exc.errno in {errno.EBADF, errno.EINTR}:
                    continue
                self.callback(f"inotify read failure: {type(exc).__name__}", True)
                return
            offset = 0
            while offset + event_header.size <= len(data):
                wd, mask, _cookie, name_length = event_header.unpack_from(data, offset)
                offset += event_header.size
                name_bytes = data[offset : offset + name_length]
                offset += name_length
                name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
                if mask & self.IN_Q_OVERFLOW:
                    self.callback("IN_Q_OVERFLOW", True)
                else:
                    root = self.watch_paths.get(wd, "<unknown-watch>")
                    self.callback(f"inotify mutation mask=0x{mask:x} path={root}/{name}", False)

    def close(self) -> None:
        self.stop_event.set()
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.thread.join(timeout=2.0)
        if self.thread.is_alive():
            self.callback("inotify watcher did not stop", True)


_WINDOWS_DIRECTORY_CHANGE_ACTIONS = MappingProxyType(
    {
        1: "added",
        2: "removed",
        3: "modified",
        4: "renamed-old-name",
        5: "renamed-new-name",
    }
)


def _windows_directory_change_events(data: bytes, root: str) -> list[dict[str, Any]]:
    """Parse a bounded ReadDirectoryChangesW FILE_NOTIFY_INFORMATION buffer."""

    events: list[dict[str, Any]] = []
    offset = 0
    while True:
        if offset + 12 > len(data):
            raise ValueError("FILE_NOTIFY_INFORMATION header is truncated")
        next_offset, action_code, name_length = struct.unpack_from("<III", data, offset)
        if name_length == 0 or name_length % 2:
            raise ValueError("FILE_NOTIFY_INFORMATION name length is invalid")
        name_start = offset + 12
        name_end = name_start + name_length
        if name_end > len(data):
            raise ValueError("FILE_NOTIFY_INFORMATION name is truncated")
        try:
            relative_path = data[name_start:name_end].decode("utf-16-le", errors="strict")
        except UnicodeError as exc:
            raise ValueError("FILE_NOTIFY_INFORMATION name is not valid UTF-16LE") from exc
        events.append(
            {
                "backend": "ReadDirectoryChangesW",
                "kind": "filesystem-notification",
                "action": _WINDOWS_DIRECTORY_CHANGE_ACTIONS.get(
                    int(action_code), f"unknown-{int(action_code)}"
                ),
                "actionCode": int(action_code),
                "root": root,
                "relativePath": relative_path.replace("\\", "/"),
            }
        )
        if next_offset == 0:
            if name_end != len(data):
                trailing = data[name_end:]
                if any(trailing):
                    raise ValueError("FILE_NOTIFY_INFORMATION has nonzero trailing bytes")
            return events
        if next_offset % 4 or next_offset < 12 + name_length:
            raise ValueError("FILE_NOTIFY_INFORMATION next offset is invalid")
        offset += next_offset
        if offset >= len(data):
            raise ValueError("FILE_NOTIFY_INFORMATION next offset leaves the buffer")


class _WindowsDirectoryMutationWatcher(_MutationWatcher):
    def __init__(self, roots: Sequence[Path], callback: Any) -> None:
        from ctypes import wintypes

        self.callback = callback
        self.stop_event = threading.Event()
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.ReadDirectoryChangesW.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        self.kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
        self.kernel32.CancelIoEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
        self.kernel32.CancelIoEx.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.handles: list[tuple[Any, str]] = []
        self.threads: list[threading.Thread] = []
        invalid = ctypes.c_void_p(-1).value
        normalized_roots: set[Path] = set()
        for root in roots:
            resolved = root.resolve(strict=True)
            normalized_roots.add(resolved if resolved.is_dir() else resolved.parent)
        try:
            for root in sorted(normalized_roots, key=lambda value: str(value).casefold()):
                handle = self.kernel32.CreateFileW(
                    str(root),
                    0x0001,
                    0x00000001 | 0x00000002 | 0x00000004,
                    None,
                    3,
                    0x02000000 | 0x40000000,
                    None,
                )
                if not handle or int(handle) == invalid:
                    raise ctypes.WinError(ctypes.get_last_error())
                self.handles.append((handle, str(root)))
            if not self.handles:
                raise OSError("ReadDirectoryChangesW watcher set is empty")
            for handle, root in self.handles:
                thread = threading.Thread(
                    target=self._run_one,
                    args=(handle, root),
                    name="ci-rdcw-closure",
                    daemon=True,
                )
                self.threads.append(thread)
                thread.start()
        except Exception:
            self.close()
            raise

    def _run_one(self, handle: Any, root: str) -> None:
        from ctypes import wintypes

        notify_filter = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000100
        while not self.stop_event.is_set():
            buffer = ctypes.create_string_buffer(65_536)
            returned = wintypes.DWORD()
            okay = self.kernel32.ReadDirectoryChangesW(
                handle,
                buffer,
                len(buffer),
                True,
                notify_filter,
                ctypes.byref(returned),
                None,
                None,
            )
            if not okay:
                error_code = ctypes.get_last_error()
                if self.stop_event.is_set() and error_code in {6, 995}:
                    return
                self.callback(
                    f"ReadDirectoryChangesW failure={error_code} root={root}",
                    error_code in {1022, 234},
                )
                return
            if returned.value == 0:
                self.callback(f"ReadDirectoryChangesW queue overflow root={root}", True)
            else:
                try:
                    events = _windows_directory_change_events(
                        bytes(buffer.raw[: returned.value]),
                        root,
                    )
                except ValueError as exc:
                    self.callback(
                        "ReadDirectoryChangesW malformed notification "
                        f"root={root} reason={type(exc).__name__}",
                        False,
                    )
                    return
                for event in events:
                    self.callback(event, False)

    def close(self) -> None:
        if not hasattr(self, "stop_event"):
            return
        self.stop_event.set()
        for handle, _root in getattr(self, "handles", []):
            self.kernel32.CancelIoEx(handle, None)
        for thread in getattr(self, "threads", []):
            thread.join(timeout=2.0)
        for handle, _root in getattr(self, "handles", []):
            self.kernel32.CloseHandle(handle)
        for thread in getattr(self, "threads", []):
            if thread.is_alive():
                self.callback("ReadDirectoryChangesW watcher did not stop", True)
        self.handles = []


class _ModelMutationWatcher(_MutationWatcher):
    """Deterministic watcher backend used by cross-platform state-machine tests."""

    def __init__(self, roots: Sequence[Path], callback: Any) -> None:
        self.roots = tuple(roots)
        self.callback = callback
        self.closed = False

    def emit(self, reason: str, *, overflow: bool = False) -> None:
        self.callback(reason, overflow)

    def close(self) -> None:
        self.closed = True


def _remeasure_dependency_semantics(
    closure: RuntimeDependencyClosure,
    *,
    repo_root: Path = REPO_ROOT,
) -> tuple[str, int]:
    root_records: list[dict[str, Any]] = []
    member_count = 0
    for original in closure.document["dependencyRoots"]:
        logical = str(original["logicalRoot"])
        root = repo_root.joinpath(*logical.split("/"))
        members = _dependency_member_manifest(root)
        member_count += len(members)
        root_records.append(
            {
                "logicalRoot": logical,
                "memberCount": len(members),
                "members": members,
                "memberManifestDigest": hashlib.sha256(_canonical_frame(members)).hexdigest(),
            }
        )
    lockfiles: list[dict[str, Any]] = []
    for original in closure.document["lockfiles"]:
        relative = str(original["relativePath"])
        path = repo_root.joinpath(*relative.split("/"))
        metadata = path.lstat()
        lockfiles.append(
            {
                "relativePath": relative,
                "mode": _portable_file_mode(metadata),
                "size": int(metadata.st_size),
                "sha256": _sha256_file(path),
            }
        )
    if "vitest" not in closure.document or closure.document["vitest"] is not None:
        raise ValueError("Vitest identity is not authorized")
    vitest = None
    semantic = {
        "lockfiles": lockfiles,
        "dependencyRoots": root_records,
        "vitest": vitest,
        "nodePath": [],
    }
    return hashlib.sha256(_canonical_frame(semantic)).hexdigest(), member_count


def _runtime_guard_path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _runtime_guard_path_is_within(path_key: str, parent_key: str) -> bool:
    try:
        return os.path.commonpath((path_key, parent_key)) == parent_key
    except ValueError:
        return False


def _runtime_guard_path_state(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"state": "absent"}
    except OSError as exc:
        return {"state": "unreadable", "errorClass": type(exc).__name__}
    if stat.S_ISLNK(metadata.st_mode):
        file_type = "symlink"
    elif _is_reparse_point(metadata):
        file_type = "reparse-point"
    elif stat.S_ISDIR(metadata.st_mode):
        file_type = "directory"
    elif stat.S_ISREG(metadata.st_mode):
        file_type = "regular-file"
    else:
        file_type = "other"
    return {
        "state": "present",
        "fileType": file_type,
        "mode": _portable_file_mode(metadata),
        "size": int(metadata.st_size),
        "objectIdentity": hashlib.sha256(
            _canonical_frame(
                {
                    "deviceOrVolume": str(int(metadata.st_dev)),
                    "inodeOrFileIndex": str(int(metadata.st_ino)),
                }
            )
        ).hexdigest(),
        "stableIdentityDigest": hashlib.sha256(
            _canonical_frame(_stable_file_identity(metadata))
        ).hexdigest(),
    }


def _runtime_guard_temporary_or_generated(relative_path: str) -> bool:
    parts = [part.casefold() for part in relative_path.replace("\\", "/").split("/")]
    leaf = parts[-1] if parts else ""
    return bool(
        any(part in {"tmp", "temp", "__pycache__", ".cache"} for part in parts)
        or leaf.endswith((".tmp", ".temp", ".pyc", ".swp", "~"))
    )


class RuntimeDependencyClosureGuard:
    """Sticky native mutation guard for the verifier's fresh runtime closure."""

    def __init__(
        self,
        closure: RuntimeDependencyClosure,
        *,
        repo_root: Path = REPO_ROOT,
        watcher_factory: Any | None = None,
    ) -> None:
        self.closure = closure
        self.repo_root = repo_root
        self.lock = threading.Lock()
        self.mutation_reasons: list[str] = []
        self.mutation_events: list[dict[str, Any]] = []
        self.ignored_events: list[dict[str, Any]] = []
        self.ignored_event_count = 0
        self.queue_overflow = False
        self.dependency_root_keys: dict[str, str] = {}
        self.exact_protected_paths: dict[str, str] = {}
        self.initial_authority: dict[str, dict[str, Any]] = {}
        for index, dependency_root in enumerate(closure.dependency_roots):
            resolved_root = dependency_root.resolve(strict=True)
            root_key = _runtime_guard_path_key(resolved_root)
            self.dependency_root_keys[root_key] = "dependency-tree"
            self.initial_authority[root_key] = {
                "state": "present",
                "fileType": "directory",
            }
            dependency_documents = closure.document.get("dependencyRoots", [])
            if index >= len(dependency_documents):
                continue
            root_document = dependency_documents[index]
            if not isinstance(root_document, Mapping):
                continue
            members = root_document.get("members", [])
            if not isinstance(members, list):
                continue
            for member in members:
                if not isinstance(member, Mapping):
                    continue
                relative = member.get("relativePath")
                if not isinstance(relative, str) or not relative:
                    continue
                member_path = resolved_root.joinpath(*relative.split("/"))
                self.initial_authority[_runtime_guard_path_key(member_path)] = {
                    key: copy.deepcopy(member.get(key))
                    for key in ("fileType", "mode", "size", "sha256", "symlinkTarget")
                }
        self.exact_protected_object_identities: set[str] = set()
        for role, lease in closure.leases.items():
            lease_path = Path(lease.path).resolve(strict=True)
            lease_key = _runtime_guard_path_key(lease_path)
            self.exact_protected_paths[lease_key] = f"leased-executable:{role}"
            initial_state = _runtime_guard_path_state(lease_path)
            self.initial_authority[lease_key] = initial_state
            object_identity = initial_state.get("objectIdentity")
            if isinstance(object_identity, str):
                self.exact_protected_object_identities.add(object_identity)
        roots = list(closure.dependency_roots)
        roots.extend(Path(lease.path).parent for lease in closure.leases.values())
        roots = sorted(set(roots), key=lambda value: str(value).casefold())
        self.watched_root_classes: dict[str, str] = {}
        for root in roots:
            resolved_root = root.resolve(strict=True)
            root_key = _runtime_guard_path_key(resolved_root)
            classes: list[str] = []
            if root_key in self.dependency_root_keys:
                classes.append("dependency-root")
            if any(
                _runtime_guard_path_key(Path(lease.path).parent) == root_key
                for lease in closure.leases.values()
            ):
                classes.append("leased-executable-parent")
            self.watched_root_classes[root_key] = "+".join(classes) or "closure-watch-root"
        if watcher_factory is None:
            watcher_factory = (
                _WindowsDirectoryMutationWatcher
                if os.name == "nt"
                else _InotifyMutationWatcher
            )
        self.watcher = watcher_factory(roots, self._record_event)
        self.active = True
        self.initial_dependency_digest = closure.dependency_digest
        self.initial_member_count = closure.member_count

    def _classify_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        classified = {
            "backend": event.get("backend"),
            "kind": event.get("kind"),
            "action": event.get("action"),
            "actionCode": event.get("actionCode"),
            "root": event.get("root"),
            "relativePath": event.get("relativePath"),
            "protected": True,
            "protectedClass": "ambiguous-event",
            "rootClass": "unknown",
            "temporaryOrGenerated": False,
            "directoryPathNotification": False,
            "monitorSelfNoise": False,
            "preIdentityState": "unknown",
            "postIdentityState": "unknown",
            "identityComparison": "unknown",
            "failClosedReason": None,
        }
        if event.get("backend") != "ReadDirectoryChangesW" or event.get("kind") != "filesystem-notification":
            classified["failClosedReason"] = "unknown watcher event kind"
            return classified
        action = event.get("action")
        if action not in set(_WINDOWS_DIRECTORY_CHANGE_ACTIONS.values()):
            classified["failClosedReason"] = "unknown watcher action"
            return classified
        root_text = event.get("root")
        relative_text = event.get("relativePath")
        if not isinstance(root_text, str) or not root_text or not isinstance(relative_text, str):
            classified["failClosedReason"] = "watcher event path is unavailable"
            return classified
        normalized_relative = relative_text.replace("\\", "/")
        relative_parts = normalized_relative.split("/")
        relative_path = Path(normalized_relative.replace("/", os.sep))
        if (
            not normalized_relative
            or relative_path.is_absolute()
            or relative_path.drive
            or any(part in {"", ".", ".."} for part in relative_parts)
        ):
            classified["failClosedReason"] = "watcher event relative path is unsafe"
            return classified
        root = Path(root_text)
        root_key = _runtime_guard_path_key(root)
        root_class = self.watched_root_classes.get(root_key)
        if root_class is None:
            classified["failClosedReason"] = "watcher event root is outside the armed set"
            return classified
        affected_path = Path(os.path.abspath(os.path.join(root_text, *relative_parts)))
        affected_key = _runtime_guard_path_key(affected_path)
        if not _runtime_guard_path_is_within(affected_key, root_key):
            classified["failClosedReason"] = "watcher event escapes its root"
            return classified
        post_state = _runtime_guard_path_state(affected_path)
        classified["rootClass"] = root_class
        classified["temporaryOrGenerated"] = _runtime_guard_temporary_or_generated(
            normalized_relative
        )
        classified["directoryPathNotification"] = bool(
            action == "modified" and post_state.get("fileType") == "directory"
        )
        classified["postIdentityState"] = post_state.get("state", "unknown")
        initial = self.initial_authority.get(affected_key)
        classified["preIdentityState"] = "known" if initial is not None else "absent"
        if initial is None:
            classified["identityComparison"] = "initial-authority-absent"
        elif post_state.get("state") != "present":
            classified["identityComparison"] = "changed-or-unreadable"
        else:
            comparable = ("fileType", "mode", "size")
            known_fields = [field for field in comparable if field in initial]
            classified["identityComparison"] = (
                "metadata-changed"
                if any(initial.get(field) != post_state.get(field) for field in known_fields)
                else "metadata-equal-content-unmeasured"
            )
        protected_class: str | None = self.exact_protected_paths.get(affected_key)
        if protected_class is None:
            for dependency_key, candidate_class in self.dependency_root_keys.items():
                if _runtime_guard_path_is_within(affected_key, dependency_key):
                    protected_class = candidate_class
                    break
        if protected_class is None and post_state.get("state") == "present":
            object_identity = post_state.get("objectIdentity")
            if object_identity in self.exact_protected_object_identities:
                protected_class = "leased-executable-hardlink-alias"
        if protected_class is None:
            classified["protected"] = False
            classified["protectedClass"] = "unprotected-watched-sibling"
        else:
            classified["protectedClass"] = protected_class
        return classified

    @staticmethod
    def _event_reason(classified: Mapping[str, Any]) -> str:
        reason = (
            f"ReadDirectoryChangesW action={classified.get('action')} "
            f"relativePath={classified.get('relativePath')} "
            f"root={classified.get('root')} rootClass={classified.get('rootClass')} "
            f"protectedClass={classified.get('protectedClass')} "
            f"directoryPathNotification={str(bool(classified.get('directoryPathNotification'))).lower()} "
            f"temporaryOrGenerated={str(bool(classified.get('temporaryOrGenerated'))).lower()} "
            f"preIdentity={classified.get('preIdentityState')} "
            f"postIdentity={classified.get('postIdentityState')} "
            f"identityComparison={classified.get('identityComparison')}"
        )
        failure = classified.get("failClosedReason")
        if failure:
            reason += f" failClosed={failure}"
        return _truncate_utf8(sanitize_text(reason), 2_048)

    def _record_event(self, reason: Any, overflow: bool) -> None:
        classified: dict[str, Any] | None = None
        if isinstance(reason, Mapping):
            classified = self._classify_event(reason)
        with self.lock:
            if overflow:
                self.queue_overflow = True
            if classified is not None and not overflow and not classified["protected"]:
                self.ignored_event_count += 1
                if len(self.ignored_events) < 256:
                    self.ignored_events.append(copy.deepcopy(classified))
                return
            if classified is not None and len(self.mutation_events) < 256:
                self.mutation_events.append(copy.deepcopy(classified))
            if len(self.mutation_reasons) < 256:
                event_reason = (
                    self._event_reason(classified)
                    if classified is not None
                    else _truncate_utf8(sanitize_text(str(reason)), 2_048)
                )
                self.mutation_reasons.append(event_reason)

    @property
    def mutated(self) -> bool:
        with self.lock:
            return bool(self.mutation_reasons) or self.queue_overflow

    def verify(self, phase: str) -> list[str]:
        errors = self.closure.verify_executables()
        try:
            digest, member_count = _remeasure_dependency_semantics(
                self.closure,
                repo_root=self.repo_root,
            )
        except Exception as exc:
            errors.append(
                f"runtime dependency closure cannot be remeasured after {phase}: {type(exc).__name__}"
            )
        else:
            if digest != self.initial_dependency_digest or member_count != self.initial_member_count:
                self._record_event(f"pre/post closure manifest drift after {phase}", False)
        with self.lock:
            if self.queue_overflow:
                errors.append("runtime dependency watcher queue overflowed")
            if self.mutation_reasons:
                errors.append(
                    "runtime dependency closure mutation is sticky: "
                    + "; ".join(self.mutation_reasons[:8])
                )
        return sorted(set(errors))

    def evidence(self) -> dict[str, Any]:
        with self.lock:
            return {
                "guardSchemaVersion": RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
                "watcherBackend": type(self.watcher).__name__,
                "active": self.active,
                "activeDuringReplay": True,
                "mutationState": "mutated" if self.mutation_reasons or self.queue_overflow else "clean",
                "queueOverflow": self.queue_overflow,
                "mutationEventCount": len(self.mutation_reasons),
            }

    def close(self) -> list[str]:
        if not self.active:
            return []
        errors = self.verify("verifier-completion")
        self.watcher.close()
        self.active = False
        errors.extend(self.verify("watcher-closed"))
        return sorted(set(errors))


def required_tool_names(profile: str, *, require_install_tools: bool = False) -> set[str]:
    required = {"python", "git", "node"}
    if profile in {"backend", "all"} or require_install_tools:
        required.add("npm")
    if profile in {"static", "standalone", "all"}:
        required.update({"bash", "powershell"})
    return required


def _repository_git_index_path(repo_root: Path) -> Path:
    marker = repo_root / ".git"
    metadata = marker.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        return marker / "index"
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("repository .git marker is not a regular file or directory")
    raw = marker.read_bytes()
    if len(raw) > 4096 or b"\x00" in raw:
        raise ValueError("repository .git marker is not a bounded gitdir record")
    text = raw.decode("utf-8", errors="strict").strip()
    if not text.casefold().startswith("gitdir: "):
        raise ValueError("repository .git marker has an invalid gitdir record")
    git_dir = Path(text[8:])
    if not git_dir.is_absolute():
        git_dir = marker.parent / git_dir
    return git_dir.resolve(strict=True) / "index"


def deterministic_candidate_paths(repo_root: Path = REPO_ROOT) -> tuple[list[str], list[str]]:
    """Read the Git index directly, then add only the fixed CI untracked allowlist."""

    errors: list[str] = []
    paths: list[str] = []
    try:
        index_path = _repository_git_index_path(repo_root)
        metadata = index_path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Git index is not a non-reparse regular file")
        if not 12 <= metadata.st_size <= 128 * 1024 * 1024:
            raise ValueError("Git index size is outside the fixed authority bound")
        data = index_path.read_bytes()
        if len(data) != metadata.st_size or data[:4] != b"DIRC":
            raise ValueError("Git index framing is invalid")
        version, entry_count = struct.unpack(">II", data[4:12])
        if version not in {2, 3} or entry_count > MAX_PROFILE_COMMANDS:
            raise ValueError("Git index version/count is outside the supported authority contract")
        offset = 12
        for _index in range(entry_count):
            entry_start = offset
            if offset + 62 > len(data) - 20:
                raise ValueError("Git index entry is truncated")
            flags = struct.unpack(">H", data[offset + 60 : offset + 62])[0]
            offset += 62
            if version >= 3 and flags & 0x4000:
                if offset + 2 > len(data) - 20:
                    raise ValueError("Git index extended flags are truncated")
                offset += 2
            name_length = flags & 0x0FFF
            if name_length < 0x0FFF:
                name_end = offset + name_length
                if name_end >= len(data) - 20 or data[name_end] != 0:
                    raise ValueError("Git index pathname framing is invalid")
            else:
                name_end = data.find(b"\x00", offset, len(data) - 20)
                if name_end < 0:
                    raise ValueError("Git index long pathname is unterminated")
            relative = data[offset:name_end].decode("utf-8", errors="strict")
            if (
                not relative
                or relative.startswith(("/", "\\"))
                or "\\" in relative
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise ValueError("Git index contains an unsafe pathname")
            stage = (flags >> 12) & 0x3
            if stage == 0:
                paths.append(relative)
            offset = name_end + 1
            offset += (8 - ((offset - entry_start) % 8)) % 8
        if hashlib.sha1(data[:-20]).digest() != data[-20:]:
            raise ValueError("Git index checksum is invalid")
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        errors.append(f"deterministic Git-index enumeration failed: {type(exc).__name__}: {exc}")
        return [], errors
    for relative in sorted(LOCAL_IMPLEMENTATION_ALLOWLIST):
        if (repo_root / relative).is_file() and relative not in paths:
            paths.append(relative)
    if len(paths) != len(set(paths)):
        errors.append("deterministic candidate path inventory contains duplicates")
    return sorted(paths), sorted(set(errors))


_FILE_AUTHORITY_CACHE: dict[
    tuple[str, int, int, int, int], tuple[int, str, dict[str, Any]]
] = {}
_FILE_AUTHORITY_CACHE_LOCK = threading.Lock()


def _measured_file_authority(
    path: Path,
    *,
    use_cache: bool = True,
) -> tuple[int | None, str | None, dict[str, Any] | None]:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError:
        return None, None, None
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        return None, None, None
    key = (
        str(resolved),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
        int(metadata.st_ino),
    )
    if use_cache:
        with _FILE_AUTHORITY_CACHE_LOCK:
            cached = _FILE_AUTHORITY_CACHE.get(key)
        if cached is not None:
            return cached
    digest = _sha256_file(resolved)
    try:
        after = resolved.lstat()
    except OSError:
        return None, None, None
    if _stat_identity(after) != _stat_identity(metadata):
        return None, None, None
    identity = _stable_file_identity(metadata)
    value = (int(metadata.st_size), digest, identity)
    if use_cache:
        with _FILE_AUTHORITY_CACHE_LOCK:
            _FILE_AUTHORITY_CACHE[key] = value
    return value


def _target_authority(repo_root: Path, relative: str) -> dict[str, Any]:
    source = repo_root.joinpath(*relative.split("/"))
    size, digest, identity = _measured_file_authority(source, use_cache=False)
    try:
        canonical = str(source.resolve(strict=True))
        metadata = source.lstat()
        mode_type = "regular-file" if stat.S_ISREG(metadata.st_mode) else "other"
        reparse_point = _is_reparse_point(metadata) or stat.S_ISLNK(metadata.st_mode)
    except OSError:
        canonical = None
        mode_type = None
        reparse_point = None
    return {
        "path": relative,
        "canonicalSourcePath": canonical,
        "size": size,
        "sha256": digest,
        "fileIdentity": identity,
        "modeType": mode_type,
        "reparsePoint": reparse_point,
    }


def deterministic_static_invocation_id(repo_root: Path = REPO_ROOT) -> str:
    """Derive the producer nonce without accepting evidence-controlled input."""

    authority = _target_authority(repo_root, STATIC_SUITE_RELATIVE_PATH)
    seed = hashlib.sha256(
        _canonical_frame(
            {
                "purpose": "static-machine-invocation-v1",
                "target": {
                    "path": authority.get("path"),
                    "size": authority.get("size"),
                    "sha256": authority.get("sha256"),
                },
            }
        )
    ).digest()
    value = bytearray(seed[:16])
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(value)))


def _node_stdin_parser_mode(repo_root: Path, relative: str) -> str:
    suffix = Path(relative).suffix.casefold()
    if suffix == ".mjs":
        return "module"
    if suffix != ".js":
        raise ValueError("Node stdin syntax adapter supports only .js and .mjs targets")
    current = repo_root.joinpath(*relative.split("/")).parent
    root = repo_root.resolve(strict=True)
    while _path_is_within(current.resolve(strict=True), root):
        package_path = current / "package.json"
        if package_path.is_file():
            try:
                package = strict_json_load_file(package_path)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                return "commonjs"
            return "module" if package.get("type") == "module" else "commonjs"
        if current.resolve(strict=True) == root:
            break
        current = current.parent
    return "commonjs"


def _baseline_source_command_id(entry: Mapping[str, Any]) -> str | None:
    command_class = str(entry.get("commandClass", ""))
    scope = str(entry.get("testOrPathScope", ""))
    if command_class == "static-suite":
        return "static-suite"
    if command_class == "direct-syntax":
        return f"node-check:{scope}"
    if command_class == "learner-focused":
        return "learner-focused"
    if command_class == "frontend-security" and scope.startswith("file:"):
        return f"frontend-security:{Path(scope[5:]).name}"
    if command_class == "backend-canonical":
        return "backend-canonical"
    if command_class == "standalone-membership":
        return "standalone-membership-audit"
    return None


def build_profile_command_plan(
    profile: str,
    *,
    tools: Mapping[str, str],
    candidate_paths: Sequence[str],
    baseline: Mapping[str, Any],
    current_platform: str,
    static_invocation_id: str,
    repo_root: Path = REPO_ROOT,
    bash_lease: TrustedBashLease | None = None,
) -> list[dict[str, Any]]:
    """Build the complete ordered plan before profile execution begins."""

    plan: list[dict[str, Any]] = []
    python = require_tool(tools, "python", phase="COMMAND_PLAN")
    git = require_tool(tools, "git", phase="COMMAND_PLAN")
    node = require_tool(tools, "node", phase="COMMAND_PLAN")
    npm = (
        require_tool(tools, "npm", phase="COMMAND_PLAN")
        if tools.get("npm")
        else None
    )
    bash = (
        require_tool(tools, "bash", phase="COMMAND_PLAN")
        if profile in {"static", "standalone", "all"}
        else None
    )
    if profile in {"static", "standalone", "all"}:
        require_tool(tools, "powershell", phase="COMMAND_PLAN")
    baseline_nonpass_commands = {
        command_id
        for collection in ("knownDebts", "expectedOmissions", "releaseOnlySkips")
        for entry in baseline.get(collection, [])
        if entry_applies(entry, current_platform)
        if (command_id := _baseline_source_command_id(entry)) is not None
    }
    target_authority_cache: dict[str, dict[str, Any]] = {}

    def add(
        command_id: str,
        command_class: str,
        argv: Sequence[str],
        *,
        required: bool = True,
        tool_role: str,
        targets: Sequence[str] = (),
        command_role: str = "required-execution",
        allowed_exits: Sequence[int] = (0,),
        result_semantics: str = "exit-zero-required",
        execution_argv: Sequence[str] | None = None,
        execution_input_mode: str = "NONE",
    ) -> None:
        actual_execution_argv = [
            str(value) for value in (argv if execution_argv is None else execution_argv)
        ]
        executable_value = actual_execution_argv[0] if actual_execution_argv else str(python)
        executable_path = Path(executable_value)
        try:
            resolved_executable = str(executable_path.resolve(strict=True))
        except OSError:
            resolved_executable = executable_value
        executable_size, executable_hash, executable_identity = _measured_file_authority(
            Path(resolved_executable)
        )
        target_authorities = []
        for relative in targets:
            if relative not in target_authority_cache:
                target_authority_cache[relative] = _target_authority(repo_root, relative)
            target_authorities.append(copy.deepcopy(target_authority_cache[relative]))
        if execution_input_mode == "TARGET-BYTES-STDIN":
            if len(target_authorities) != 1:
                raise ValueError("TARGET-BYTES-STDIN commands require exactly one target")
            execution_input_size = target_authorities[0]["size"]
            execution_input_sha256 = target_authorities[0]["sha256"]
        else:
            execution_input_size = None
            execution_input_sha256 = None
        logical_argv = [str(value) for value in argv]
        plan.append(
            {
                "commandId": command_id,
                "ordinal": len(plan),
                "commandClass": command_class,
                "commandRole": command_role,
                "required": required,
                "profile": profile,
                "platform": current_platform,
                "argv": logical_argv,
                "logicalArgv": logical_argv,
                "executionArgv": actual_execution_argv,
                "executionInputMode": execution_input_mode,
                "executionInputSize": execution_input_size,
                "executionInputSha256": execution_input_sha256,
                "cwd": ".",
                "toolRole": tool_role,
                "resolvedExecutablePath": resolved_executable,
                "resolvedExecutableSize": executable_size,
                "resolvedExecutableSha256": executable_hash,
                "resolvedExecutableFileIdentity": executable_identity,
                "executionLease": (
                    bash_lease.validated_identity()
                    if command_id == "git-bash-version" and bash_lease is not None
                    else None
                ),
                "targets": target_authorities,
                "resultSemantics": result_semantics,
                "allowedExecutionExits": list(allowed_exits),
            }
        )

    def add_internal(
        command_id: str,
        command_class: str,
        *,
        targets: Sequence[str] = (),
        command_role: str = "required-execution",
        allowed_exits: Sequence[int] = (0,),
        result_semantics: str = "deterministic-in-process-check",
    ) -> None:
        add(
            command_id,
            command_class,
            [python, "<internal>", command_id],
            tool_role="python-in-process",
            targets=targets,
            command_role=command_role,
            allowed_exits=allowed_exits,
            result_semantics=result_semantics,
            execution_input_mode=("PROTECTED-TARGET-BUNDLE" if targets else "NONE"),
        )

    add_internal(
        "baseline-schema",
        "baseline-policy",
        targets=["developer/tests/ci/phase1-ci-baseline.json"],
    )
    add("node-version", "runtime-identity", [node, "--version"], tool_role="node-runtime")
    add(
        "npm-version",
        "runtime-identity",
        [npm or "<unavailable-npm>", "--version"],
        required=profile in {"backend", "all"},
        tool_role="npm-runtime",
        execution_argv=(
            [node, npm, "--version"]
            if npm is not None
            else [node, "<unavailable-npm>"]
        ),
    )
    if profile in {"static", "standalone", "all"}:
        assert bash is not None
        add("git-bash-version", "runtime-identity", [bash, "--version"], tool_role="git-bash-runtime")
    if profile in {"policy", "all"}:
        add(
            "git-candidate-paths",
            "repository-boundary",
            trusted_git_arguments(git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"),
            tool_role="git-candidate-enumerator",
        )
        add("git-tracked-paths", "repository-boundary", trusted_git_arguments(git, "ls-files", "-z", "--cached"), tool_role="git-tracked-enumerator")
        add("git-diff-check", "repository-boundary", trusted_git_arguments(git, "diff", "--check"), tool_role="git-worktree-validator")
        add("git-cached-diff-check", "repository-boundary", trusted_git_arguments(git, "diff", "--cached", "--check"), tool_role="git-index-validator")
        add("git-stage-modes", "repository-boundary", trusted_git_arguments(git, "ls-files", "-s", "-z"), tool_role="git-mode-enumerator")
        add("git-dir", "repository-boundary", trusted_git_arguments(git, "rev-parse", "--absolute-git-dir"), tool_role="git-operation-validator")
        add_internal("tracked-private-resource-scan", "private-resource-exclusion", targets=candidate_paths)
        add_internal("tracked-secret-scan", "secret-operational-artifact-exclusion", targets=candidate_paths)
        license_targets = [
            "LICENSE", "LICENSE.md", "NOTICE.md", "LICENSES/AGPL-3.0-only.txt",
            "README.md", "docs/CONTENT_POLICY.md", "docs/STATUS.md", "api-contract/README.md",
            "backend/package.json",
        ]
        license_targets.extend(
            path
            for path in candidate_paths
            if (
                (
                    path.startswith("backend/src/")
                    or path.startswith("backend/scripts/")
                    or path.startswith("backend/test/")
                )
                and Path(path).suffix.lower() in {".js", ".mjs"}
            )
            or path == "api-contract/README.md"
        )
        license_targets = list(dict.fromkeys(license_targets))
        add_internal("license-governance-consistency", "license-governance", targets=license_targets)
        add_internal(
            "workflow-self-policy",
            "workflow-policy",
            targets=[
                ".github/workflows/ci.yml",
                "docs/CI_POLICY.md",
                "developer/tests/ci/phase1-ci-baseline.json",
            ],
        )
    if profile in {"static", "all"}:
        add(
            "static-suite",
            "static-suite",
            [python, "-B", STATIC_SUITE_RELATIVE_PATH, "--ci-machine-json-stdout", "--ci-invocation-id", static_invocation_id],
            tool_role="python-static-producer",
            targets=candidate_paths,
            command_role="observation-producing",
            result_semantics="machine-v2-complete-execution",
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        if profile == "static":
            add(
                "git-candidate-paths",
                "repository-boundary",
                trusted_git_arguments(git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"),
                tool_role="git-candidate-enumerator",
            )
        javascript_paths = sorted(
            path for path in candidate_paths if Path(path).suffix.casefold() in {".js", ".mjs"}
        )
        for relative in javascript_paths:
            parser_mode = _node_stdin_parser_mode(repo_root, relative)
            add(
                f"node-check:{relative}",
                "direct-syntax",
                [node, "--check", relative],
                tool_role="node-syntax-check",
                targets=[relative],
                command_role="observation-producing",
                allowed_exits=(0, 1),
                result_semantics="exit-zero-pass-exit-one-classified-observation",
                execution_argv=[node, "--check", f"--input-type={parser_mode}", "-"],
                execution_input_mode="TARGET-BYTES-STDIN",
            )
        python_paths = sorted(path for path in candidate_paths if Path(path).suffix.casefold() == ".py")
        add_internal("python-source-syntax", "direct-syntax", targets=python_paths)
    if profile in {"frontend", "all"}:
        add(
            "bundle-normalization",
            "bundle-parity",
            [node, "--test", "developer/tests/js/bundleNormalization.test.js"],
            tool_role="node-test",
            targets=candidate_paths,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        add(
            "learner-focused",
            "learner-focused",
            [node, "--test", "developer/tests/js/learnerPalette.test.js", "developer/tests/js/learnerUiRuntimeStabilization.test.js"],
            tool_role="node-test",
            targets=candidate_paths,
            command_role="observation-producing",
            allowed_exits=(0, 1),
            result_semantics="exit-zero-pass-exit-one-classified-observation",
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        for relative in SECURITY_GUARD_FILES:
            command_id = f"frontend-security:{Path(relative).name}"
            add(
                command_id,
                "frontend-security",
                [node, "--test", relative],
                tool_role="node-security-test",
                targets=candidate_paths,
                command_role="observation-producing",
                allowed_exits=(0, 1),
                result_semantics="exit-zero-pass-exit-one-classified-observation",
                execution_input_mode="PROTECTED-TARGET-BUNDLE",
            )
        add(
            "frontend-security:messageOriginGuard.test.js",
            "frontend-security",
            [node, "--test", MESSAGE_ORIGIN_SECURITY_GUARD],
            tool_role="node-builtin-security-test",
            targets=candidate_paths,
            command_role="observation-producing",
            allowed_exits=(0, 1),
            result_semantics="exit-zero-pass-exit-one-classified-observation",
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
    if profile in {"backend", "all"}:
        assert npm is not None
        add(
            "backend-canonical",
            "backend-canonical",
            [npm, "--prefix", "backend", "test"],
            tool_role="npm-backend-test",
            execution_argv=[node, npm, "--prefix", "backend", "test"],
            targets=candidate_paths,
            command_role="observation-producing" if "backend-canonical" in baseline_nonpass_commands else "required-execution",
            allowed_exits=(0, 1) if "backend-canonical" in baseline_nonpass_commands else (0,),
            result_semantics="baseline-classified-test-result",
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
    if profile in {"standalone", "all"}:
        add(
            "standalone-packaging",
            "standalone-packaging",
            [python, "-B", "developer/tests/ci/test_standalone_packaging.py"],
            tool_role="python-standalone-test",
            targets=candidate_paths,
            execution_input_mode="PROTECTED-TARGET-BUNDLE",
        )
        add_internal(
            "standalone-membership-audit",
            "standalone-membership",
            targets=["developer/standalone-release-manifest.json", "index.html"],
            command_role="observation-producing",
            allowed_exits=(0, 1),
            result_semantics="exact-membership-observation",
        )
    add_internal(
        "lockfile-integrity",
        "lockfile-integrity",
        targets=list(LOCKED_FILE_SHA256),
    )
    if len(plan) > MAX_PROFILE_COMMANDS:
        raise ValueError("immutable command plan exceeds the fixed command bound")
    return plan


def _locked_checkout_presentation_matches(
    canonical_blob: bytes,
    checkout_bytes: bytes,
) -> bool:
    """Accept only Git's exact bytes or a complete LF-to-CRLF presentation."""

    if checkout_bytes == canonical_blob:
        return True
    if b"\r" in canonical_blob:
        return False
    return checkout_bytes == canonical_blob.replace(b"\n", b"\r\n")


def capture_locked_file_git_identities(
    *,
    git: str,
    environment: Mapping[str, str],
    repo_root: Path = REPO_ROOT,
    expected_sha256: Mapping[str, str] = LOCKED_FILE_SHA256,
    expected_blob_oids: Mapping[str, str] = LOCKED_FILE_GIT_BLOB_OIDS,
    executable_lease: Any | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Capture package authorities from HEAD, index stage 0, and Git blobs."""

    identities: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    paths = tuple(expected_sha256)
    if set(paths) != set(expected_blob_oids):
        return {}, ["locked Git blob authority key set is inconsistent"]

    def git_bytes(command_id: str, arguments: Sequence[str]) -> bytes:
        capture = execute_command(
            command_id,
            "locked-git-blob-authority",
            [
                git,
                "-c",
                f"safe.directory={repo_root.resolve(strict=True)}",
                "-C",
                str(repo_root.resolve(strict=True)),
                *arguments,
            ],
            timeout=60,
            env=environment,
            include_preview=False,
            cwd=repo_root,
            max_stdout_bytes=1_048_576,
            executable_lease=executable_lease,
        )
        if not capture.execution_passed() or capture.stdout_raw is None:
            raise ValueError(
                f"trusted Git could not capture {command_id} authority"
            )
        return capture.stdout_raw

    try:
        tree_raw = git_bytes(
            "locked-files-head-tree",
            ("ls-tree", "-z", "HEAD", "--", *paths),
        )
        index_raw = git_bytes(
            "locked-files-index-stage-zero",
            ("ls-files", "--stage", "-z", "--", *paths),
        )
    except (OSError, ValueError) as exc:
        return {}, [f"locked Git authority capture failed: {type(exc).__name__}: {exc}"]

    tree: dict[str, tuple[str, str]] = {}
    index: dict[str, tuple[str, str]] = {}
    try:
        for raw_record in tree_raw.split(b"\0"):
            if not raw_record:
                continue
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ", 2)
            relative = raw_path.decode("utf-8", errors="strict")
            if (
                relative not in expected_sha256
                or relative in tree
                or object_type != "blob"
                or mode not in {"100644", "100755"}
                or not re.fullmatch(r"[0-9a-f]{40,64}", object_id)
            ):
                raise ValueError("HEAD tree record is not exact")
            tree[relative] = (mode, object_id)
        for raw_record in index_raw.split(b"\0"):
            if not raw_record:
                continue
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_id, stage = header.decode("ascii").split(" ", 2)
            relative = raw_path.decode("utf-8", errors="strict")
            if (
                relative not in expected_sha256
                or relative in index
                or stage != "0"
                or mode not in {"100644", "100755"}
                or not re.fullmatch(r"[0-9a-f]{40,64}", object_id)
            ):
                raise ValueError("index stage-zero record is not exact")
            index[relative] = (mode, object_id)
    except (UnicodeError, ValueError) as exc:
        return {}, [f"locked Git authority framing failed: {type(exc).__name__}: {exc}"]

    for relative in paths:
        path = repo_root / relative
        okay, reason = _secure_regular_file(path)
        if not okay:
            errors.append(f"{relative}: {reason}")
            continue
        tree_identity = tree.get(relative)
        index_identity = index.get(relative)
        expected_oid = expected_blob_oids[relative]
        if (
            tree_identity is None
            or index_identity is None
            or tree_identity != index_identity
            or tree_identity[1] != expected_oid
        ):
            errors.append(
                f"{relative}: HEAD/index Git blob authority differs from the frozen identity"
            )
            continue
        try:
            canonical = git_bytes(
                f"locked-file-blob-{len(identities)}",
                ("cat-file", "blob", expected_oid),
            )
            checkout = path.read_bytes()
        except (OSError, ValueError) as exc:
            errors.append(
                f"{relative}: Git blob materialization failed ({type(exc).__name__})"
            )
            continue
        canonical_sha = hashlib.sha256(canonical).hexdigest()
        if canonical_sha != expected_sha256[relative]:
            errors.append(f"{relative}: canonical Git blob SHA-256 is not frozen")
            continue
        if not _locked_checkout_presentation_matches(canonical, checkout):
            errors.append(
                f"{relative}: checkout bytes are neither the Git blob nor its complete CRLF presentation"
            )
            continue
        identities[relative] = {
            "mode": tree_identity[0],
            "objectId": expected_oid,
            "sha256": canonical_sha,
            "canonicalBytes": canonical,
        }
    return identities, sorted(set(errors))


def snapshot_trusted_files(
    *,
    repo_root: Path = REPO_ROOT,
    paths: Sequence[str] = TRUSTED_FILE_PATHS,
    locked_identities: Mapping[str, Mapping[str, Any]] | None = None,
    locked_sha256: Mapping[str, str] = LOCKED_FILE_SHA256,
    locked_blob_oids: Mapping[str, str] = LOCKED_FILE_GIT_BLOB_OIDS,
) -> tuple[dict[str, str], list[str]]:
    snapshot: dict[str, str] = {}
    errors: list[str] = []
    for relative in paths:
        path = repo_root / relative
        okay, reason = _secure_regular_file(path)
        if not okay:
            errors.append(f"{relative}: {reason}")
            continue
        if relative in locked_sha256:
            identity = (
                locked_identities.get(relative)
                if locked_identities is not None
                else None
            )
            canonical = identity.get("canonicalBytes") if identity is not None else None
            if (
                not isinstance(identity, Mapping)
                or identity.get("objectId") != locked_blob_oids.get(relative)
                or identity.get("sha256") != locked_sha256[relative]
                or not isinstance(canonical, bytes)
            ):
                errors.append(f"{relative}: canonical Git blob authority is unavailable")
                continue
            try:
                checkout = path.read_bytes()
            except OSError as exc:
                errors.append(f"{relative}: could not read ({type(exc).__name__})")
                continue
            if not _locked_checkout_presentation_matches(canonical, checkout):
                errors.append(f"{relative}: candidate-local package/lockfile identity changed")
                continue
            snapshot[relative] = str(identity["sha256"])
            continue
        try:
            snapshot[relative] = _sha256_file(path)
        except OSError as exc:
            errors.append(f"{relative}: could not hash ({type(exc).__name__})")
    return snapshot, errors


def compare_trusted_snapshots(
    before: Mapping[str, str],
    after: Mapping[str, str],
) -> list[str]:
    errors: list[str] = []
    if set(before) != set(after):
        errors.append(
            f"trusted-file set changed: missing={sorted(set(before) - set(after))} "
            f"additional={sorted(set(after) - set(before))}"
        )
    for path in sorted(set(before) & set(after)):
        if before[path] != after[path]:
            errors.append(f"trusted file changed: {path}")
    return errors


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes
    identity: tuple[int, int, int, int, int]


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        0 if os.name == "nt" else int(metadata.st_ctime_ns),
    )


def _stable_file_identity(metadata: os.stat_result) -> dict[str, Any]:
    return {
        "deviceOrVolume": str(int(metadata.st_dev)),
        "inodeOrFileIndex": str(int(metadata.st_ino)),
        "creationOrChangeTimeNs": str(int(metadata.st_ctime_ns)),
        "writeTimeNs": str(int(metadata.st_mtime_ns)),
        "reparsePoint": _is_reparse_point(metadata),
    }


class TargetExecutionLease:
    """Hold one planned target identity and materialize only its planned bytes."""

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_BEGIN = 0

    def __init__(
        self,
        target_authority: Mapping[str, Any],
        *,
        repo_root: Path,
        execution_adapter: str,
    ) -> None:
        self.repo_root = repo_root.resolve(strict=True)
        self.target_authority = dict(target_authority)
        self.execution_adapter = execution_adapter
        self.handle: Any | None = None
        self.descriptor = -1
        self._closed = False
        self._materialized = False
        self._mutation_detected = False
        self._pre_execution_identity: dict[str, Any] | None = None
        self._post_execution_identity: dict[str, Any] | None = None
        self._opened_held_identity: dict[str, Any] | None = None
        self._executed_input_size: int | None = None
        self._executed_input_sha256: str | None = None

        relative = str(target_authority.get("path", ""))
        relative_path = Path(relative)
        if (
            not relative
            or relative_path.is_absolute()
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise OSError("target execution lease rejected an unsafe logical target path")
        self.relative_path = relative
        self.source_path = self.repo_root.joinpath(*relative.split("/"))
        self._validate_parent_chain()
        self._validate_exact_path_spelling()
        try:
            canonical = self.source_path.resolve(strict=True)
            metadata = self.source_path.lstat()
        except OSError as exc:
            raise OSError(f"target source cannot be resolved: {type(exc).__name__}") from exc
        if canonical != self.source_path.absolute() or not _path_is_within(canonical, self.repo_root):
            raise OSError("target source canonical path escaped or used an alias")
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("target source is not a non-reparse regular file")
        self.canonical_source_path = str(canonical)
        self.mode_type = "regular-file"
        self._initial_path_identity = _stable_file_identity(metadata)
        self._initial_size = int(metadata.st_size)
        try:
            self._open_source()
            self._opened_held_identity = (
                _stable_file_identity(os.fstat(self.descriptor))
                if os.name != "nt"
                else self._windows_information()
            )
            self._pre_execution_identity = self._current_source_identity()
            self._require_planned_identity(self._pre_execution_identity)
        except Exception:
            self.close()
            raise

    def _validate_parent_chain(self) -> None:
        current = self.source_path.parent
        while True:
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise OSError(f"target parent cannot be inspected: {type(exc).__name__}") from exc
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise OSError("target parent chain contains a link, reparse point, or non-directory")
            if current.resolve(strict=True) == self.repo_root:
                return
            if current.parent == current or not _path_is_within(current.resolve(strict=True), self.repo_root):
                raise OSError("target parent chain did not terminate at the repository root")
            current = current.parent

    def _validate_exact_path_spelling(self) -> None:
        current = self.repo_root
        for part in self.relative_path.split("/"):
            try:
                exact_names = {entry.name for entry in current.iterdir()}
            except OSError as exc:
                raise OSError(
                    f"target path spelling cannot be enumerated: {type(exc).__name__}"
                ) from exc
            if part not in exact_names:
                raise OSError("target logical path uses a case or normalization alias")
            current = current / part

    def _open_source(self) -> None:
        if os.name != "nt":
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            self.descriptor = os.open(self.source_path, flags)
            opened = os.fstat(self.descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise OSError("opened target source is not a regular file")
            return

        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        self._windows_info_type = BY_HANDLE_FILE_INFORMATION
        self.kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.GetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        )
        self.kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel32.SetFilePointerEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        )
        self.kernel32.SetFilePointerEx.restype = wintypes.BOOL
        self.kernel32.ReadFile.argtypes = (
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        self.kernel32.ReadFile.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        invalid = ctypes.c_void_p(-1).value
        handle = self.kernel32.CreateFileW(
            self.canonical_source_path,
            self.GENERIC_READ,
            self.FILE_SHARE_READ,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if not handle or int(handle) == invalid:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = handle
        information = self._windows_information()
        if information["reparsePoint"]:
            raise OSError("target source handle resolves to a reparse point")

    @staticmethod
    def _filetime(value: Any) -> str:
        return str((int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime))

    def _windows_information(self) -> dict[str, Any]:
        information = self._windows_info_type()
        if not self.kernel32.GetFileInformationByHandle(
            self.handle, self.ctypes.byref(information)
        ):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        attributes = int(information.dwFileAttributes)
        return {
            "volumeSerial": str(int(information.dwVolumeSerialNumber)),
            "fileIndex": str(
                (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
            ),
            "size": (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow),
            "creationTime": self._filetime(information.ftCreationTime),
            "writeTime": self._filetime(information.ftLastWriteTime),
            "linkCount": int(information.nNumberOfLinks),
            "reparsePoint": bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)),
        }

    def _read_held_bytes(self) -> bytes:
        if os.name != "nt":
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(self.descriptor, 65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SCANNED_FILE_BYTES:
                    raise OSError("target source exceeds the fixed byte bound")
                chunks.append(chunk)
            return b"".join(chunks)

        position = self.ctypes.c_longlong()
        if not self.kernel32.SetFilePointerEx(
            self.handle, 0, self.ctypes.byref(position), self.FILE_BEGIN
        ):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        chunks = []
        total = 0
        while True:
            buffer = self.ctypes.create_string_buffer(65_536)
            read = self.wintypes.DWORD()
            if not self.kernel32.ReadFile(
                self.handle, buffer, len(buffer), self.ctypes.byref(read), None
            ):
                raise self.ctypes.WinError(self.ctypes.get_last_error())
            count = int(read.value)
            if count == 0:
                break
            total += count
            if total > MAX_SCANNED_FILE_BYTES:
                raise OSError("target source exceeds the fixed byte bound")
            chunks.append(buffer.raw[:count])
        return b"".join(chunks)

    def _current_source_identity(self) -> dict[str, Any]:
        self._validate_parent_chain()
        canonical = self.source_path.resolve(strict=True)
        if str(canonical) != self.canonical_source_path:
            raise OSError("target source canonical path drifted")
        path_metadata = self.source_path.lstat()
        if stat.S_ISLNK(path_metadata.st_mode) or _is_reparse_point(path_metadata):
            raise OSError("target source became a link or reparse point")
        held_metadata = (
            _stable_file_identity(os.fstat(self.descriptor))
            if os.name != "nt"
            else self._windows_information()
        )
        return {
            "pathStableIdentity": _stable_file_identity(path_metadata),
            "heldStableIdentity": held_metadata,
            "canonicalPath": str(canonical),
        }

    def _require_planned_identity(self, current: Mapping[str, Any]) -> None:
        planned_identity = self.target_authority.get("fileIdentity")
        if current.get("pathStableIdentity") != planned_identity:
            self._mutation_detected = True
            raise OSError("target source stable identity differs from the command plan")
        held_identity = current.get("heldStableIdentity")
        if held_identity != self._opened_held_identity:
            self._mutation_detected = True
            raise OSError("held target identity drifted after lease acquisition")
        if os.name != "nt" and held_identity != current.get("pathStableIdentity"):
            self._mutation_detected = True
            raise OSError("held target identity does not equal the planned path identity")
        if self.target_authority.get("size") != self._initial_size:
            self._mutation_detected = True
            raise OSError("target source byte length differs from the command plan")
        expected_canonical = self.target_authority.get("canonicalSourcePath")
        if expected_canonical is not None and current.get("canonicalPath") != expected_canonical:
            self._mutation_detected = True
            raise OSError("target source canonical path differs from the command plan")

    def materialize(self) -> bytes:
        if self._closed:
            raise OSError("target execution lease is closed")
        self._pre_execution_identity = self._current_source_identity()
        self._require_planned_identity(self._pre_execution_identity)
        data = self._read_held_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != self.target_authority.get("size") or digest != self.target_authority.get("sha256"):
            self._mutation_detected = True
            raise OSError("held target bytes differ from the command plan")
        self._materialized = True
        self._executed_input_size = len(data)
        self._executed_input_sha256 = digest
        return data

    def verify(self) -> tuple[bool, str | None]:
        if self._closed:
            return False, "target execution lease is closed"
        try:
            current = self._current_source_identity()
            self._require_planned_identity(current)
            data = self._read_held_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != self.target_authority.get("size") or digest != self.target_authority.get("sha256"):
                raise OSError("held target bytes drifted from the command plan")
            self._post_execution_identity = current
        except OSError as exc:
            self._mutation_detected = True
            return False, f"target execution lease verification failed: {exc}"
        return True, None

    def evidence(self) -> dict[str, Any]:
        return {
            "leaseVersion": TARGET_EXECUTION_LEASE_VERSION,
            "logicalTargetPath": self.relative_path,
            "canonicalSourcePath": self.canonical_source_path,
            "plannedByteLength": self.target_authority.get("size"),
            "plannedSha256": self.target_authority.get("sha256"),
            "plannedStableFileIdentity": self.target_authority.get("fileIdentity"),
            "modeType": self.mode_type,
            "reparsePoint": False,
            "executionAdapter": self.execution_adapter,
            "executedInputByteLength": self._executed_input_size,
            "executedInputSha256": self._executed_input_sha256,
            "preExecutionSourceIdentity": self._pre_execution_identity,
            "postExecutionSourceIdentity": self._post_execution_identity,
            "mutationDetected": self._mutation_detected,
            "cleanupState": "closed" if self._closed else "open",
        }

    def close(self) -> None:
        if self._closed:
            return
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        handle = getattr(self, "handle", None)
        if handle:
            self.kernel32.CloseHandle(handle)
            self.handle = None
        self._closed = True

    def __del__(self) -> None:  # pragma: no cover - last-resort handle cleanup
        try:
            self.close()
        except Exception:
            pass


def execution_input_bundle_digest(inputs: Sequence[Mapping[str, Any]]) -> str:
    return canonical_failure_digest(list(inputs))


class ProtectedTargetBundle:
    """Capture an ordered multi-target command input from hardened held handles."""

    def __init__(
        self,
        targets: Sequence[Mapping[str, Any]],
        *,
        repo_root: Path,
        execution_adapter: str = "PROTECTED-TARGET-BUNDLE",
    ) -> None:
        if not targets:
            raise OSError("protected target bundle requires at least one target")
        logical_paths = [str(target.get("path", "")) for target in targets]
        if len(logical_paths) != len(set(logical_paths)):
            raise OSError("protected target bundle contains duplicate logical targets")
        self.execution_adapter = execution_adapter
        self.targets = [dict(target) for target in targets]
        self.leases: list[TargetExecutionLease] = []
        self._bytes: dict[str, bytes] = {}
        self._execution_inputs: list[dict[str, Any]] = []
        self._mutation_detected = False
        self._closed = False
        self._materialized = False
        try:
            for target in self.targets:
                self.leases.append(
                    TargetExecutionLease(
                        target,
                        repo_root=repo_root,
                        execution_adapter=execution_adapter,
                    )
                )
        except Exception:
            self._mutation_detected = True
            self.close()
            raise

    @staticmethod
    def _execution_input(lease: TargetExecutionLease) -> dict[str, Any]:
        evidence = lease.evidence()
        return {
            "logicalPath": evidence["logicalTargetPath"],
            "canonicalSourcePath": evidence["canonicalSourcePath"],
            "plannedByteLength": evidence["plannedByteLength"],
            "plannedSha256": evidence["plannedSha256"],
            "plannedStableIdentity": evidence["plannedStableFileIdentity"],
            "actualByteLength": evidence["executedInputByteLength"],
            "actualSha256": evidence["executedInputSha256"],
            "inputMode": evidence["executionAdapter"],
        }

    def materialize(self) -> Mapping[str, bytes]:
        if self._closed:
            raise OSError("protected target bundle is closed")
        captured: dict[str, bytes] = {}
        try:
            for lease in self.leases:
                captured[lease.relative_path] = lease.materialize()
            okay, error = self.verify()
            if not okay:
                raise OSError(error or "protected target bundle source drifted")
        except OSError:
            self._mutation_detected = True
            raise
        self._bytes = captured
        self._execution_inputs = [self._execution_input(lease) for lease in self.leases]
        self._materialized = True
        return MappingProxyType(self._bytes)

    def bytes_for(self, relative: str) -> bytes:
        if not self._materialized or relative not in self._bytes:
            raise KeyError(f"protected target bytes are unavailable: {relative}")
        return self._bytes[relative]

    def text_for(self, relative: str) -> str:
        data = self.bytes_for(relative)
        if data.startswith(b"\xef\xbb\xbf"):
            raise UnicodeError(f"protected target must be UTF-8 without BOM: {relative}")
        return data.decode("utf-8", errors="strict")

    def verify(self) -> tuple[bool, str | None]:
        if self._closed:
            return False, "protected target bundle is closed"
        failures: list[str] = []
        for lease in self.leases:
            okay, error = lease.verify()
            if not okay:
                failures.append(f"{lease.relative_path}: {error or 'source identity drifted'}")
        if failures:
            self._mutation_detected = True
            return False, "; ".join(failures)
        if self._materialized:
            self._execution_inputs = [self._execution_input(lease) for lease in self.leases]
        return True, None

    @property
    def execution_inputs(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._execution_inputs)

    @property
    def bundle_digest(self) -> str | None:
        return (
            execution_input_bundle_digest(self._execution_inputs)
            if self._materialized and self._execution_inputs
            else None
        )

    def evidence(self) -> dict[str, Any]:
        lease_evidence = [lease.evidence() for lease in self.leases]
        inputs = (
            [self._execution_input(lease) for lease in self.leases]
            if self._materialized
            else copy.deepcopy(self._execution_inputs)
        )
        mutation_detected = self._mutation_detected or any(
            item.get("mutationDetected") is True for item in lease_evidence
        )
        return {
            "bundleVersion": PROTECTED_TARGET_BUNDLE_VERSION,
            "executionAdapter": self.execution_adapter,
            "orderedLogicalTargetPaths": [item.get("logicalTargetPath") for item in lease_evidence],
            "canonicalSourcePaths": [item.get("canonicalSourcePath") for item in lease_evidence],
            "plannedByteLengths": [item.get("plannedByteLength") for item in lease_evidence],
            "plannedSha256Values": [item.get("plannedSha256") for item in lease_evidence],
            "plannedStableIdentities": [item.get("plannedStableFileIdentity") for item in lease_evidence],
            "executionInputs": inputs,
            "executionInputBundleDigest": (
                execution_input_bundle_digest(inputs) if inputs else None
            ),
            "preExecutionIdentities": [item.get("preExecutionSourceIdentity") for item in lease_evidence],
            "postExecutionIdentities": [item.get("postExecutionSourceIdentity") for item in lease_evidence],
            "mutationDetected": mutation_detected,
            "cleanupState": "closed" if self._closed else "open",
        }

    def close(self) -> None:
        if self._closed:
            return
        for lease in reversed(self.leases):
            lease.close()
        self._closed = True

    def __del__(self) -> None:  # pragma: no cover - last-resort OS handle cleanup
        try:
            self.close()
        except Exception:
            pass


def _failed_protected_target_bundle(
    targets: Sequence[Mapping[str, Any]],
    execution_adapter: str,
) -> dict[str, Any]:
    return {
        "bundleVersion": PROTECTED_TARGET_BUNDLE_VERSION,
        "executionAdapter": execution_adapter,
        "orderedLogicalTargetPaths": [target.get("path") for target in targets],
        "canonicalSourcePaths": [target.get("canonicalSourcePath") for target in targets],
        "plannedByteLengths": [target.get("size") for target in targets],
        "plannedSha256Values": [target.get("sha256") for target in targets],
        "plannedStableIdentities": [target.get("fileIdentity") for target in targets],
        "executionInputs": [],
        "executionInputBundleDigest": None,
        "preExecutionIdentities": [],
        "postExecutionIdentities": [],
        "mutationDetected": True,
        "cleanupState": "closed",
    }


@dataclass(frozen=True)
class FailurePathAuthority:
    """Ephemeral source/snapshot authority used only for failure identity."""

    repository_root: str
    snapshot_root: str
    targets: tuple[tuple[str, str], ...]
    trusted_executables: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _AuthorizedPathPattern:
    pattern: str
    logical_target: str | None
    slash_replacement: str
    backslash_replacement: str
    escaped_replacement: str
    uri_replacement: str | None = None

    def replacement_for_text(self, observed: str) -> str:
        if self.uri_replacement is not None:
            return self.uri_replacement
        if "\\\\" in observed:
            return self.escaped_replacement
        if "\\" in observed:
            return self.backslash_replacement
        return self.slash_replacement

    def replacement_for_bytes(self, observed: bytes) -> bytes:
        if self.uri_replacement is not None:
            return self.uri_replacement.encode("utf-8")
        if b"\\\\" in observed:
            return self.escaped_replacement.encode("utf-8")
        if b"\\" in observed:
            return self.backslash_replacement.encode("utf-8")
        return self.slash_replacement.encode("utf-8")


def _safe_failure_logical_target(value: str) -> bool:
    return bool(value) and not value.startswith(("/", "\\")) and "\\" not in value and all(
        part not in {"", ".", ".."} for part in value.split("/")
    )


def _coerce_failure_path_authority(
    repository_root: str | Path,
    snapshot_root: str | Path,
    targets: Sequence[Mapping[str, Any] | str],
    *,
    trusted_executables: Sequence[tuple[str, str]] = (),
) -> FailurePathAuthority:
    repository = str(repository_root)
    snapshot = str(snapshot_root)
    authorized_targets: list[tuple[str, str]] = []
    for target in targets:
        logical = str(target.get("path", "")) if isinstance(target, Mapping) else str(target)
        if not _safe_failure_logical_target(logical):
            raise ValueError("failure path authority contains an unsafe logical target")
        if isinstance(target, Mapping) and isinstance(target.get("canonicalSourcePath"), str):
            canonical_source = str(target["canonicalSourcePath"])
        else:
            canonical_source = str(Path(repository).joinpath(*logical.split("/")))
        authorized_targets.append((logical, canonical_source))
    if len({logical for logical, _canonical in authorized_targets}) != len(authorized_targets):
        raise ValueError("failure path authority contains duplicate logical targets")
    return FailurePathAuthority(
        repository_root=repository,
        snapshot_root=snapshot,
        targets=tuple(sorted(authorized_targets)),
        trusted_executables=tuple(sorted(set(trusted_executables))),
    )


def _failure_path_authority_from_plan(
    plan_record: Mapping[str, Any],
    *,
    snapshot_root: Path,
    repo_root: Path,
) -> FailurePathAuthority:
    resolved_repository = repo_root.resolve(strict=True)
    targets = plan_record.get("targets")
    if not isinstance(targets, list) or not targets:
        raise OSError("protected command has no failure-path target authority")
    for target in targets:
        if not isinstance(target, Mapping):
            raise OSError("protected command target authority is malformed")
        logical = str(target.get("path", ""))
        if not _safe_failure_logical_target(logical):
            raise OSError("protected command target path is unsafe")
        expected = resolved_repository.joinpath(*logical.split("/")).resolve(strict=True)
        if str(target.get("canonicalSourcePath", "")) != str(expected):
            raise OSError("protected command target canonical source is inconsistent")
    trusted_executables: list[tuple[str, str]] = []
    executable = plan_record.get("resolvedExecutablePath")
    role = str(plan_record.get("toolRole", ""))
    if isinstance(executable, str) and executable and Path(executable).is_absolute() and role:
        trusted_executables.append((role, executable))
    return _coerce_failure_path_authority(
        str(resolved_repository),
        str(snapshot_root.resolve(strict=True)),
        targets,
        trusted_executables=trusted_executables,
    )


def _authority_literal_pattern(
    value: str,
    *,
    ascii_fold: bool,
    flexible_separators: bool,
) -> str:
    pattern: list[str] = []
    for character in value:
        if flexible_separators and character in "/\\":
            pattern.append(r"(?:/|\\{1,2})")
        elif ascii_fold and ("A" <= character <= "Z" or "a" <= character <= "z"):
            lower = chr(ord(character) + 32) if "A" <= character <= "Z" else character
            upper = chr(ord(lower) - 32)
            pattern.append(f"[{re.escape(lower)}{re.escape(upper)}]")
        else:
            pattern.append(re.escape(character))
    return "".join(pattern)


def _failure_root_uri_spellings(value: str) -> list[str]:
    return [
        root
        for root, _token, _windows in _normalization_root_records(value, "<unused>")
        if root.startswith("file:")
    ]


def _r11_posix_file_uri_spelling(value: str) -> str | None:
    """Return one canonical URI for an exact absolute POSIX authority root."""

    root = value.rstrip("/") or "/"
    if not root.startswith("/") or "\\" in root:
        return None
    try:
        encoded = quote(
            root,
            safe="/:@()+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    except UnicodeEncodeError:
        return None
    return "file://" + encoded


def _r11_windows_encoded_short_name_uri_spellings(value: str) -> list[str]:
    """Derive only the hosted ``NAME%7E1`` spelling of an exact root."""

    spellings: list[str] = []
    for uri in _failure_root_uri_spellings(value):
        components = uri.split("/")
        short_name_indexes = [
            index
            for index, component in enumerate(components)
            if re.fullmatch(r"[A-Za-z0-9]{1,6}~1", component)
        ]
        if len(short_name_indexes) != 1:
            continue
        index = short_name_indexes[0]
        encoded_components = list(components)
        encoded_components[index] = components[index].replace("~", "%7E")
        spellings.append("/".join(encoded_components))
    return sorted(set(spellings))


def _failure_path_patterns(
    candidate_root: str,
    repository_root: str,
    logical_target: str | None,
    *,
    include_root_descendants: bool = False,
) -> list[_AuthorizedPathPattern]:
    candidate_reference = classify_windows_absolute_reference(candidate_root)
    repository_reference = classify_windows_absolute_reference(repository_root)
    windows = (
        candidate_reference.authorizable
        and candidate_reference.authority_path is not None
        and repository_reference.authorizable
        and repository_reference.authority_path is not None
    )
    logical_suffix = "" if logical_target is None else "/" + logical_target
    before = r"(?<![A-Za-z0-9_.:/\\-])"
    after = r"(?![A-Za-z0-9_.%+@~/?#\\-])"
    patterns: list[_AuthorizedPathPattern] = []

    if windows:
        candidate_native = candidate_reference.authority_path.replace("\\", "/").rstrip("/")
        repository_native = repository_reference.authority_path.replace("\\", "/").rstrip("/")
        native_pattern = (
            before
            + _authority_literal_pattern(
                candidate_native,
                ascii_fold=True,
                flexible_separators=True,
            )
            + _authority_literal_pattern(
                logical_suffix,
                ascii_fold=False,
                flexible_separators=True,
            )
            + after
        )
        slash_replacement = repository_native + logical_suffix
        backslash_replacement = slash_replacement.replace("/", "\\")
        patterns.append(
            _AuthorizedPathPattern(
                native_pattern,
                logical_target,
                slash_replacement,
                backslash_replacement,
                backslash_replacement.replace("\\", "\\\\"),
            )
        )
        candidate_uris = _failure_root_uri_spellings(candidate_root)
        repository_uris = _failure_root_uri_spellings(repository_root)
        encoded_suffix = "" if logical_target is None else "/" + quote(
            logical_target,
            safe="/:@()+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
        for index, candidate_uri in enumerate(candidate_uris):
            if not repository_uris:
                break
            repository_uri = repository_uris[min(index, len(repository_uris) - 1)]
            uri_pattern = (
                before
                + _authority_literal_pattern(
                    candidate_uri.rstrip("/"),
                    ascii_fold=True,
                    flexible_separators=False,
                )
                + _authority_literal_pattern(
                    encoded_suffix,
                    ascii_fold=False,
                    flexible_separators=False,
                )
                + after
            )
            replacement = repository_uri.rstrip("/") + encoded_suffix
            patterns.append(
                _AuthorizedPathPattern(
                    uri_pattern,
                    logical_target,
                    replacement,
                    replacement,
                    replacement,
                    replacement,
                )
            )
        if logical_target in R11_WINDOWS_ENCODED_SHORT_NAME_URI_TARGETS:
            encoded_candidate_uris = (
                _r11_windows_encoded_short_name_uri_spellings(candidate_root)
            )
            for index, candidate_uri in enumerate(encoded_candidate_uris):
                if not repository_uris:
                    break
                repository_uri = repository_uris[
                    min(index, len(repository_uris) - 1)
                ]
                uri_pattern = (
                    before
                    + _authority_literal_pattern(
                        candidate_uri.rstrip("/"),
                        ascii_fold=True,
                        flexible_separators=False,
                    )
                    + _authority_literal_pattern(
                        encoded_suffix,
                        ascii_fold=False,
                        flexible_separators=False,
                    )
                    + after
                )
                replacement = repository_uri.rstrip("/") + encoded_suffix
                patterns.append(
                    _AuthorizedPathPattern(
                        uri_pattern,
                        logical_target,
                        replacement,
                        replacement,
                        replacement,
                        replacement,
                    )
                )
        return patterns

    candidate = candidate_root.rstrip("/") or "/"
    repository = repository_root.rstrip("/") or "/"
    if candidate.startswith("/") and repository.startswith("/"):
        separator = "" if candidate == "/" else "/"
        repository_separator = "" if repository == "/" else "/"
        source = candidate + separator + (logical_target or "")
        replacement = repository + repository_separator + (logical_target or "")
        path_boundary = after
        if logical_target is None and candidate != "/":
            source = candidate
            replacement = repository
            if include_root_descendants:
                path_boundary = r"(?=/|(?![A-Za-z0-9_.%+@~/?#\\-]))"
        patterns.append(
            _AuthorizedPathPattern(
                before + re.escape(source) + path_boundary,
                logical_target,
                replacement,
                replacement,
                replacement,
            )
        )
        if logical_target in R11_POSIX_FILE_URI_TARGETS:
            candidate_uri = _r11_posix_file_uri_spelling(candidate)
            repository_uri = _r11_posix_file_uri_spelling(repository)
            if candidate_uri is not None and repository_uri is not None:
                encoded_suffix = "/" + quote(
                    logical_target,
                    safe="/:@()+,;=-._~",
                    encoding="utf-8",
                    errors="strict",
                )
                uri_pattern = (
                    before
                    + _authority_literal_pattern(
                        "file://",
                        ascii_fold=True,
                        flexible_separators=False,
                    )
                    + re.escape(candidate_uri[len("file://") :].rstrip("/"))
                    + re.escape(encoded_suffix)
                    + after
                )
                uri_replacement = repository_uri.rstrip("/") + encoded_suffix
                patterns.append(
                    _AuthorizedPathPattern(
                        uri_pattern,
                        logical_target,
                        uri_replacement,
                        uri_replacement,
                        uri_replacement,
                        uri_replacement,
                    )
                )
    return patterns


def _selected_failure_targets(
    value: str | bytes,
    authority: FailurePathAuthority,
) -> list[tuple[str, str]]:
    selected: list[tuple[str, str]] = []
    for logical, canonical in authority.targets:
        basename = logical.rsplit("/", 1)[-1]
        needle = basename.encode("utf-8") if isinstance(value, bytes) else basename
        if needle in value:
            selected.append((logical, canonical))
    return selected


def _translate_authorized_paths_text(
    value: str,
    authority: FailurePathAuthority,
    *,
    include_repository_root: bool,
) -> str:
    translated = value
    roots = [authority.snapshot_root]
    if include_repository_root:
        roots.append(authority.repository_root)
    for logical, _canonical in _selected_failure_targets(value, authority):
        for candidate_root in roots:
            for specification in _failure_path_patterns(
                candidate_root,
                authority.repository_root,
                logical,
            ):
                pattern = re.compile(specification.pattern)
                translated = pattern.sub(
                    lambda match, item=specification: item.replacement_for_text(match.group(0)),
                    translated,
                )
    for candidate_root in roots:
        for specification in _failure_path_patterns(
            candidate_root,
            authority.repository_root,
            None,
            include_root_descendants=True,
        ):
            pattern = re.compile(specification.pattern)
            translated = pattern.sub(
                lambda match, item=specification: item.replacement_for_text(match.group(0)),
                translated,
            )
    return translated


def _translate_authorized_paths_bytes(
    value: bytes,
    authority: FailurePathAuthority,
    *,
    include_repository_root: bool,
) -> bytes:
    translated = value
    roots = [authority.snapshot_root]
    if include_repository_root:
        roots.append(authority.repository_root)
    for logical, _canonical in _selected_failure_targets(value, authority):
        for candidate_root in roots:
            for specification in _failure_path_patterns(
                candidate_root,
                authority.repository_root,
                logical,
            ):
                pattern = re.compile(specification.pattern.encode("utf-8"))
                translated = pattern.sub(
                    lambda match, item=specification: item.replacement_for_bytes(match.group(0)),
                    translated,
                )
    for candidate_root in roots:
        for specification in _failure_path_patterns(
            candidate_root,
            authority.repository_root,
            None,
            include_root_descendants=True,
        ):
            pattern = re.compile(specification.pattern.encode("utf-8"))
            translated = pattern.sub(
                lambda match, item=specification: item.replacement_for_bytes(match.group(0)),
                translated,
            )
    return translated


def _translate_snapshot_output_paths(
    value: str,
    snapshot_root: str | Path,
    repo_root: str | Path,
    authorized_targets: Sequence[Mapping[str, Any] | str] = (),
) -> str:
    """Translate only exact snapshot-root boundaries and authority-bound targets."""

    authority = _coerce_failure_path_authority(repo_root, snapshot_root, authorized_targets)
    return _translate_authorized_paths_text(
        value,
        authority,
        include_repository_root=False,
    )


def _translate_snapshot_output_bytes(
    value: bytes,
    snapshot_root: str | Path,
    repo_root: str | Path,
    authorized_targets: Sequence[Mapping[str, Any] | str] = (),
) -> bytes:
    """Byte-preserving counterpart to ``_translate_snapshot_output_paths``."""

    authority = _coerce_failure_path_authority(repo_root, snapshot_root, authorized_targets)
    return _translate_authorized_paths_bytes(
        value,
        authority,
        include_repository_root=False,
    )


FAILURE_PATH_AUTHORITY_KEYS = frozenset(
    {
        "schemaVersion",
        "canonicalizationKind",
        "authorizedTargetPaths",
        "authorizedToolRoles",
        "unmappedAbsolutePathDigests",
        "literalPlaceholderDigests",
    }
)


def _failure_path_digest_token(value: str) -> tuple[str, str]:
    digest = f"sha256:{sha256_text(value)}"
    return f"<unmapped-abs-{digest}>", digest


def _literal_path_token_pattern() -> re.Pattern[str]:
    return re.compile(
        r"<(?:repo|task-root|abs-path)>"
        r"(?:[\\/][^\s\x00-\x1f\"'<>|]+)*"
    )


def _fingerprint_windows_absolute_references(
    text: str,
    digests: set[str],
) -> str:
    output: list[str] = []
    cursor = 0
    index = 0
    while index < len(text):
        if not _windows_reference_start(text, index):
            index += 1
            continue
        end = _windows_reference_span_end(text, index)
        if end <= index:
            index += 1
            continue
        reference = classify_windows_absolute_reference(text[index:end])
        if reference.kind in {"ordinary-prose", "relative-path"}:
            index += 1
            continue
        token, digest = _failure_path_digest_token(text[index:end])
        digests.add(digest)
        output.append(text[cursor:index])
        output.append(token)
        cursor = end
        index = end
    output.append(text[cursor:])
    return "".join(output)


def _mask_authorized_failure_paths(
    text: str,
    authority: FailurePathAuthority,
    *,
    authorized_targets: set[str],
    authorized_tools: set[str],
) -> tuple[str, list[tuple[str, str]]]:
    masked = text
    restorations: list[tuple[str, str]] = []
    sentinel_prefix = "__CI_AUTHORIZED_FAILURE_PATH__"
    while sentinel_prefix in masked:
        sentinel_prefix += "_"

    def reserve(replacement: str) -> str:
        sentinel = f"{sentinel_prefix}{len(restorations)}__"
        restorations.append((sentinel, replacement))
        return sentinel

    roots = (authority.snapshot_root, authority.repository_root)
    for logical, _canonical in _selected_failure_targets(masked, authority):
        for candidate_root in roots:
            for specification in _failure_path_patterns(
                candidate_root,
                authority.repository_root,
                logical,
            ):
                pattern = re.compile(specification.pattern)

                def replace_target(
                    match: re.Match[str],
                    *,
                    item: _AuthorizedPathPattern = specification,
                    target: str = logical,
                ) -> str:
                    authorized_targets.add(target)
                    return reserve(f"<repo>/{target}")

                masked = pattern.sub(replace_target, masked)

    for role, executable in authority.trusted_executables:
        basename = executable.replace("\\", "/").rsplit("/", 1)[-1]
        if basename not in masked:
            continue
        parent_text = executable[: -len(basename)].rstrip("/\\")
        if not parent_text:
            continue
        for specification in _failure_path_patterns(parent_text, parent_text, basename):
            pattern = re.compile(specification.pattern)

            def replace_tool(
                match: re.Match[str],
                *,
                tool_role: str = role,
            ) -> str:
                authorized_tools.add(tool_role)
                return reserve(match.group(0))

            masked = pattern.sub(replace_tool, masked)

    for candidate_root in roots:
        for specification in _failure_path_patterns(
            candidate_root,
            authority.repository_root,
            None,
        ):
            pattern = re.compile(specification.pattern)
            masked = pattern.sub(
                lambda match, item=specification: reserve(
                    item.replacement_for_text(match.group(0))
                ),
                masked,
            )
    return masked, restorations


def _fingerprint_authority_root_descendants(
    text: str,
    authority: FailurePathAuthority,
    digests: set[str],
) -> str:
    fingerprinted = text
    before = r"(?<![A-Za-z0-9_.:/\\-])"
    for root in (authority.snapshot_root, authority.repository_root):
        reference = classify_windows_absolute_reference(root)
        if reference.authorizable and reference.authority_path is not None:
            normalized = reference.authority_path.replace("\\", "/").rstrip("/")
            root_pattern = _authority_literal_pattern(
                normalized,
                ascii_fold=True,
                flexible_separators=True,
            )
            tail = r"(?:/|\\{1,2})[^\s\x00-\x1f\"'<>|]+"
        else:
            normalized = root.rstrip("/") or "/"
            if not normalized.startswith("/"):
                continue
            separator = "" if normalized == "/" else "/"
            root_pattern = re.escape(normalized) + re.escape(separator)
            tail = r"[^\s\x00-\x1f\"'<>|]+"
        pattern = re.compile(before + root_pattern + tail)

        def replace(match: re.Match[str]) -> str:
            token, digest = _failure_path_digest_token(match.group(0))
            digests.add(digest)
            return token

        fingerprinted = pattern.sub(replace, fingerprinted)
    return fingerprinted


def canonicalize_failure_identity_text(
    value: str,
    authority: FailurePathAuthority,
) -> tuple[str, dict[str, Any]]:
    """Canonicalize only proven paths and fingerprint every other absolute origin."""

    literal_digests: set[str] = set()

    def replace_literal(match: re.Match[str]) -> str:
        token, digest = _failure_path_digest_token("literal:" + match.group(0))
        literal_digests.add(digest)
        return token.replace("unmapped-abs", "literal-path-token")

    text = _literal_path_token_pattern().sub(replace_literal, value)
    authorized_targets: set[str] = set()
    authorized_tools: set[str] = set()
    text, restorations = _mask_authorized_failure_paths(
        text,
        authority,
        authorized_targets=authorized_targets,
        authorized_tools=authorized_tools,
    )
    unmapped_digests: set[str] = set()
    text = _fingerprint_authority_root_descendants(text, authority, unmapped_digests)
    text = _fingerprint_windows_absolute_references(text, unmapped_digests)

    def replace_posix(match: re.Match[str]) -> str:
        token, digest = _failure_path_digest_token(match.group(0))
        unmapped_digests.add(digest)
        return token

    text = KNOWN_UNIX_ABSOLUTE_PATH.sub(replace_posix, text)
    for sentinel, replacement in restorations:
        text = text.replace(sentinel, replacement)
    binding = {
        "schemaVersion": 1,
        "canonicalizationKind": "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1",
        "authorizedTargetPaths": sorted(authorized_targets),
        "authorizedToolRoles": sorted(authorized_tools),
        "unmappedAbsolutePathDigests": sorted(unmapped_digests),
        "literalPlaceholderDigests": sorted(literal_digests),
    }
    return text, binding


def canonicalize_failure_identity_value(
    value: Any,
    authority: FailurePathAuthority,
) -> tuple[Any, dict[str, Any]]:
    target_paths: set[str] = set()
    tool_roles: set[str] = set()
    unmapped: set[str] = set()
    literals: set[str] = set()

    def visit(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(key): visit(child) for key, child in item.items()}
        if isinstance(item, list):
            return [visit(child) for child in item]
        if not isinstance(item, str):
            return item
        canonical, binding = canonicalize_failure_identity_text(item, authority)
        target_paths.update(binding["authorizedTargetPaths"])
        tool_roles.update(binding["authorizedToolRoles"])
        unmapped.update(binding["unmappedAbsolutePathDigests"])
        literals.update(binding["literalPlaceholderDigests"])
        return canonical

    canonical_value = visit(value)
    return canonical_value, {
        "schemaVersion": 1,
        "canonicalizationKind": "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1",
        "authorizedTargetPaths": sorted(target_paths),
        "authorizedToolRoles": sorted(tool_roles),
        "unmappedAbsolutePathDigests": sorted(unmapped),
        "literalPlaceholderDigests": sorted(literals),
    }


def _canonicalize_static_result_failure_paths(
    result: Mapping[str, Any],
    authority: FailurePathAuthority,
) -> tuple[Any, dict[str, Any] | None]:
    """Bind only approved static failure paths, including exact missing release input."""

    scope = f"result:{result.get('name', '')}"
    selected_authority = authority
    if scope in RELEASE_ONLY_SKIP_FAILURE_TARGETS:
        detail = result.get("detail")
        if (
            result.get("status") != "pass"
            or not nested_skip(detail)
            or not isinstance(detail, Mapping)
        ):
            return copy.deepcopy(result), None
        logical_target = RELEASE_ONLY_SKIP_FAILURE_TARGETS[scope]
        if logical_target not in {logical for logical, _canonical in authority.targets}:
            canonical_target = str(
                Path(authority.repository_root).joinpath(
                    *logical_target.split("/")
                )
            )
            selected_authority = FailurePathAuthority(
                repository_root=authority.repository_root,
                snapshot_root=authority.snapshot_root,
                targets=tuple(
                    sorted(
                        (*authority.targets, (logical_target, canonical_target))
                    )
                ),
                trusted_executables=authority.trusted_executables,
            )
        reason = detail.get("reason")
        if not isinstance(reason, str):
            return canonicalize_failure_identity_value(result, selected_authority)
        release_prefix = "missing_checklist:"
        result_without_reason = copy.deepcopy(result)
        del result_without_reason["detail"]["reason"]
        canonical_result, outer_binding = canonicalize_failure_identity_value(
            result_without_reason,
            selected_authority,
        )
        if reason.startswith(release_prefix):
            canonical_reason_path, reason_binding = canonicalize_failure_identity_text(
                reason[len(release_prefix) :],
                selected_authority,
            )
            canonical_reason = release_prefix + canonical_reason_path
        else:
            canonical_reason, reason_binding = canonicalize_failure_identity_text(
                reason,
                selected_authority,
            )
        canonical_result["detail"]["reason"] = canonical_reason
        return canonical_result, {
            "schemaVersion": 1,
            "canonicalizationKind": "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1",
            "authorizedTargetPaths": sorted(
                set(outer_binding["authorizedTargetPaths"])
                | set(reason_binding["authorizedTargetPaths"])
            ),
            "authorizedToolRoles": sorted(
                set(outer_binding["authorizedToolRoles"])
                | set(reason_binding["authorizedToolRoles"])
            ),
            "unmappedAbsolutePathDigests": sorted(
                set(outer_binding["unmappedAbsolutePathDigests"])
                | set(reason_binding["unmappedAbsolutePathDigests"])
            ),
            "literalPlaceholderDigests": sorted(
                set(outer_binding["literalPlaceholderDigests"])
                | set(reason_binding["literalPlaceholderDigests"])
            ),
        }
    elif scope not in R03_FAILURE_TARGETS:
        return copy.deepcopy(result), None
    return canonicalize_failure_identity_value(result, selected_authority)


def _canonicalize_static_machine_capture(
    capture: CommandCapture,
    report: Mapping[str, Any],
) -> None:
    """Bind a validated machine document after removing only replay-volatile values."""

    canonical = _json_bytes(normalized_json_value(report))
    capture.identity_stdout_raw = canonical
    capture.identity_stdout = canonical.decode("utf-8", errors="strict")


def _protected_snapshot_environment(
    env: Mapping[str, str],
    *,
    repo_root: Path,
    include_dependency_roots: bool = True,
) -> dict[str, str]:
    snapshot_environment = dict(env)
    snapshot_environment["CI_PROTECTED_TARGET_SNAPSHOT"] = "1"
    if not include_dependency_roots:
        snapshot_environment.pop("NODE_PATH", None)
        snapshot_environment.pop("NODE_OPTIONS", None)
        return snapshot_environment
    dependency_roots: list[str] = []
    for relative in ("developer/node_modules", "backend/node_modules"):
        candidate = repo_root.joinpath(*relative.split("/"))
        if not candidate.exists():
            continue
        resolved = candidate.resolve(strict=True)
        if not _path_is_within(resolved, repo_root.resolve(strict=True)):
            raise OSError(f"runtime dependency root escapes repository: {relative}")
        if not _non_reparse_directory_chain(candidate, repo_root):
            raise OSError(f"runtime dependency root contains a reparse or link: {relative}")
        dependency_roots.append(str(resolved))
    if dependency_roots:
        snapshot_environment["NODE_PATH"] = os.pathsep.join(dependency_roots)
    return snapshot_environment


def _write_exclusive_private_file(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(data)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _materialize_protected_git_projection(
    snapshot_root: Path,
    bundle: ProtectedTargetBundle,
) -> None:
    """Create a read-only semantic Git projection from held target bytes.

    The bundle-normalization suite asks Git only about tracked membership,
    ignore rules, and attributes.  Copying live repository metadata into the
    isolated snapshot would cross the protected-input boundary, so construct
    the minimal index directly from the already-authorized target set.
    """

    evidence = bundle.evidence()
    logical_paths = evidence.get("orderedLogicalTargetPaths")
    if not isinstance(logical_paths, list) or not logical_paths:
        raise OSError("protected Git projection target set is unavailable")
    records: list[tuple[bytes, bytes, int]] = []
    seen: set[bytes] = set()
    for value in logical_paths:
        if not isinstance(value, str) or not value:
            raise OSError("protected Git projection path is invalid")
        parts = value.split("/")
        if (
            value.startswith(("/", "\\"))
            or "\\" in value
            or any(part in {"", ".", "..", ".git"} for part in parts)
        ):
            raise OSError("protected Git projection path is unsafe")
        encoded = value.encode("utf-8", errors="strict")
        if b"\x00" in encoded or encoded in seen:
            raise OSError("protected Git projection path is duplicated or malformed")
        seen.add(encoded)
        data = bundle.bytes_for(value)
        object_header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
        object_id = hashlib.sha1(object_header + data).digest()
        records.append((encoded, object_id, len(data)))
    records.sort(key=lambda item: item[0])
    index = bytearray(struct.pack(">4sII", b"DIRC", 2, len(records)))
    for encoded, object_id, data_length in records:
        flags = min(len(encoded), 0x0FFF)
        entry = bytearray(
            struct.pack(
                ">10I20sH",
                0,
                0,
                0,
                0,
                0,
                0,
                0o100644,
                0,
                0,
                data_length,
                object_id,
                flags,
            )
        )
        entry.extend(encoded)
        entry.append(0)
        entry.extend(b"\x00" * ((8 - (len(entry) % 8)) % 8))
        index.extend(entry)
    index.extend(hashlib.sha1(index).digest())

    git_directory = snapshot_root / ".git"
    git_directory.mkdir(mode=0o700)
    (git_directory / "objects").mkdir(mode=0o700)
    (git_directory / "refs").mkdir(mode=0o700)
    (git_directory / "refs" / "heads").mkdir(mode=0o700)
    _write_exclusive_private_file(
        git_directory / "HEAD",
        b"ref: refs/heads/protected-snapshot\n",
    )
    _write_exclusive_private_file(
        git_directory / "config",
        (
            b"[core]\n"
            b"\trepositoryformatversion = 0\n"
            b"\tfilemode = false\n"
            b"\tbare = false\n"
            b"\tlogallrefupdates = false\n"
        ),
    )
    _write_exclusive_private_file(git_directory / "index", bytes(index))
    runtime_home = git_directory / "runtime-home"
    runtime_home.mkdir(mode=0o700)
    (runtime_home / "xdg").mkdir(mode=0o700)
    _write_exclusive_private_file(runtime_home / "global.gitconfig", b"")


def _protected_snapshot_git_environment(
    environment: Mapping[str, str],
    snapshot_root: Path,
) -> dict[str, str]:
    isolated = dict(environment)
    runtime_home = snapshot_root / ".git" / "runtime-home"
    global_config = runtime_home / "global.gitconfig"
    if not runtime_home.is_dir() or not global_config.is_file():
        raise OSError("protected Git projection runtime home is unavailable")
    isolated.update(
        {
            "HOME": str(runtime_home),
            "USERPROFILE": str(runtime_home),
            "XDG_CONFIG_HOME": str(runtime_home / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(snapshot_root.parent.resolve(strict=True)),
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(snapshot_root.resolve(strict=True)),
        }
    )
    return isolated


def execute_planned_static_suite(
    plan_record: Mapping[str, Any],
    *,
    repo_root: Path,
    env: Mapping[str, str],
    timeout: int = 1200,
    phase_hook: Any | None = None,
    executable_lease: Any | None = None,
) -> tuple[CommandCapture, dict[str, Any]]:
    """Run one external command from a task-owned snapshot of held planned bytes."""

    targets = plan_record.get("targets")
    adapter = str(plan_record.get("executionInputMode", ""))
    logical_argv = list(plan_record.get("logicalArgv", plan_record.get("argv", [])))
    execution_argv = list(plan_record.get("executionArgv", []))
    if adapter != "PROTECTED-TARGET-BUNDLE" or not isinstance(targets, list) or not targets:
        raise ValueError("static-suite lacks protected workspace-snapshot authority")

    bundle: ProtectedTargetBundle | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    capture: CommandCapture | None = None
    integrity_error: str | None = None
    if phase_hook is not None:
        phase_hook("after-plan-before-target-bundle", None)
    try:
        bundle = ProtectedTargetBundle(
            targets,
            repo_root=repo_root,
            execution_adapter=adapter,
        )
        if phase_hook is not None:
            phase_hook("after-target-bundle-before-materialization", bundle)
        bundle.materialize()
        if phase_hook is not None:
            phase_hook("after-materialization-before-snapshot", bundle)

        temporary = tempfile.TemporaryDirectory(prefix="cs-")
        snapshot_root = Path(temporary.name)
        failure_path_authority = _failure_path_authority_from_plan(
            plan_record,
            snapshot_root=snapshot_root,
            repo_root=repo_root,
        )
        for relative in bundle.evidence()["orderedLogicalTargetPaths"]:
            if not isinstance(relative, str):
                raise OSError("protected static target path is invalid")
            destination = snapshot_root.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as output:
                    output.write(bundle.bytes_for(relative))
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise

        git_projection_enabled = plan_record.get("commandId") == "bundle-normalization"
        if git_projection_enabled:
            _materialize_protected_git_projection(snapshot_root, bundle)

        if phase_hook is not None:
            phase_hook("after-snapshot-before-process-launch", bundle)
        okay, error = bundle.verify()
        if not okay:
            raise OSError(error or "protected static target bundle drifted before launch")
        snapshot_environment = _protected_snapshot_environment(
            env,
            repo_root=repo_root,
            include_dependency_roots=(
                plan_record.get("toolRole") != "node-builtin-security-test"
            ),
        )
        if git_projection_enabled:
            snapshot_environment = _protected_snapshot_git_environment(
                snapshot_environment,
                snapshot_root,
            )
        capture = execute_command(
            str(plan_record.get("commandId", "static-suite")),
            str(plan_record.get("commandClass", "static-suite")),
            execution_argv,
            timeout=timeout,
            env=snapshot_environment,
            include_preview=False,
            required=bool(plan_record.get("required", True)),
            cwd=snapshot_root,
            max_stdout_bytes=MAX_STATIC_MACHINE_STDOUT_BYTES,
            max_stderr_bytes=MAX_STATIC_MACHINE_STDERR_BYTES,
            max_line_bytes=MAX_OUTPUT_LINE_BYTES,
            logical_argv=logical_argv,
            execution_input_mode=adapter,
            executable_lease=executable_lease,
        )
        capture.failure_path_authority = failure_path_authority
        if capture.stdout_raw is not None:
            capture.identity_stdout_raw = _translate_snapshot_output_bytes(
                capture.stdout_raw,
                snapshot_root,
                repo_root,
                targets,
            )
            capture.identity_stdout = capture.identity_stdout_raw.decode(
                "utf-8",
                errors="replace",
            )
        else:
            capture.identity_stdout = _translate_snapshot_output_paths(
                capture.stdout,
                snapshot_root,
                repo_root,
                targets,
            )
        if capture.stderr_raw is not None:
            capture.identity_stderr_raw = _translate_snapshot_output_bytes(
                capture.stderr_raw,
                snapshot_root,
                repo_root,
                targets,
            )
            capture.identity_stderr = capture.identity_stderr_raw.decode(
                "utf-8",
                errors="replace",
            )
        else:
            capture.identity_stderr = _translate_snapshot_output_paths(
                capture.stderr,
                snapshot_root,
                repo_root,
                targets,
            )
        if capture.error is not None:
            capture.identity_error = _translate_snapshot_output_paths(
                capture.error,
                snapshot_root,
                repo_root,
                targets,
            )
        if phase_hook is not None:
            phase_hook("after-process-before-evidence", bundle)
        okay, error = bundle.verify()
        if not okay:
            integrity_error = error or "protected static target bundle drifted during execution"
    except Exception as exc:
        integrity_error = f"PROTECTED-STATIC-SNAPSHOT-ERROR: {type(exc).__name__}: {exc}"
        capture = CommandCapture(
            command_id=str(plan_record.get("commandId", "static-suite")),
            command_class=str(plan_record.get("commandClass", "static-suite")),
            argv=execution_argv,
            logical_argv=logical_argv,
            executed=False,
            exit_code=None,
            duration_seconds=0.0,
            stdout="",
            stderr="",
            required=bool(plan_record.get("required", True)),
            error=integrity_error,
            containment="not-started",
            process_tree_status="setup-failed",
            execution_input_mode=adapter,
        )
    finally:
        if bundle is not None:
            okay, error = bundle.verify()
            if not okay and integrity_error is None:
                integrity_error = error or "protected static target bundle drifted before cleanup"
            bundle.close()
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError as exc:
                if integrity_error is None:
                    integrity_error = (
                        f"protected static snapshot cleanup failed: {type(exc).__name__}: {exc}"
                    )

    assert capture is not None
    if integrity_error is not None:
        capture.exit_code = PROCESS_TREE_FAILURE_EXIT if capture.executed else None
        capture.process_tree_status = "cleanup-failed" if capture.executed else "setup-failed"
        capture.process_tree_error = integrity_error
        capture.error = integrity_error
    bundle_evidence = (
        bundle.evidence()
        if bundle is not None
        else _failed_protected_target_bundle(targets, adapter)
    )
    return capture, bundle_evidence


def _failed_target_execution_record(
    target_authority: Mapping[str, Any],
    execution_adapter: str,
) -> dict[str, Any]:
    return {
        "leaseVersion": TARGET_EXECUTION_LEASE_VERSION,
        "logicalTargetPath": target_authority.get("path"),
        "canonicalSourcePath": target_authority.get("canonicalSourcePath"),
        "plannedByteLength": target_authority.get("size"),
        "plannedSha256": target_authority.get("sha256"),
        "plannedStableFileIdentity": target_authority.get("fileIdentity"),
        "modeType": target_authority.get("modeType", "regular-file"),
        "reparsePoint": target_authority.get("reparsePoint", False),
        "executionAdapter": execution_adapter,
        "executedInputByteLength": None,
        "executedInputSha256": None,
        "preExecutionSourceIdentity": None,
        "postExecutionSourceIdentity": None,
        "mutationDetected": True,
        "cleanupState": "closed",
    }


def execute_planned_node_check(
    plan_record: Mapping[str, Any],
    *,
    repo_root: Path,
    env: Mapping[str, str],
    timeout: int = 30,
    phase_hook: Any | None = None,
    executable_lease: Any | None = None,
) -> tuple[CommandCapture, TargetExecutionLease | None]:
    """Execute one Node syntax plan from held target bytes through stdin."""

    targets = plan_record.get("targets")
    if not isinstance(targets, list) or len(targets) != 1:
        raise ValueError("node-check command plan must contain exactly one target")
    target = targets[0]
    logical_argv = list(plan_record.get("logicalArgv", plan_record.get("argv", [])))
    execution_argv = list(plan_record.get("executionArgv", []))
    adapter = str(plan_record.get("executionInputMode", ""))
    if phase_hook is not None:
        phase_hook("after-plan-before-target-lease", None)
    try:
        lease = TargetExecutionLease(
            target,
            repo_root=repo_root,
            execution_adapter=adapter,
        )
        if phase_hook is not None:
            phase_hook("after-target-lease-before-materialization", lease)
        data = lease.materialize()
        if phase_hook is not None:
            phase_hook("after-materialization-before-process-launch", lease)
        lease_ok, lease_error = lease.verify()
        if not lease_ok:
            raise OSError(lease_error or "target source drifted before process launch")
    except OSError as exc:
        if "lease" in locals():
            lease.close()
        capture = CommandCapture(
            command_id=str(plan_record.get("commandId", "")),
            command_class=str(plan_record.get("commandClass", "direct-syntax")),
            argv=execution_argv,
            executed=False,
            exit_code=None,
            duration_seconds=0.0,
            stdout="",
            stderr="",
            error=f"TARGET-LEASE-ERROR: {type(exc).__name__}: {exc}",
            containment="not-started",
            process_tree_status="setup-failed",
            logical_argv=logical_argv,
            execution_input_mode=adapter,
            target_execution_lease=_failed_target_execution_record(target, adapter),
        )
        return capture, None

    def started_hook(_process: subprocess.Popen[bytes]) -> None:
        if phase_hook is not None:
            phase_hook("during-process-execution", lease)

    capture = execute_command(
        str(plan_record["commandId"]),
        str(plan_record["commandClass"]),
        execution_argv,
        timeout=timeout,
        env=env,
        include_preview=True,
        cwd=repo_root,
        stdin_data=data,
        logical_argv=logical_argv,
        execution_input_mode=adapter,
        process_started_hook=started_hook,
        executable_lease=executable_lease,
    )
    if phase_hook is not None:
        phase_hook("after-process-exit-before-evidence", lease)
    lease_ok, lease_error = lease.verify()
    if not lease_ok:
        capture.exit_code = PROCESS_TREE_FAILURE_EXIT
        capture.process_tree_status = "cleanup-failed"
        capture.process_tree_error = lease_error
        capture.error = ((capture.error + "; ") if capture.error else "") + (
            "TARGET-LEASE-ERROR: " + (lease_error or "source identity drifted")
        )
    capture.target_execution_lease = lease.evidence()
    return capture, lease


class FoundationRunner:
    def __init__(
        self,
        profile: str,
        baseline: dict[str, Any],
        *,
        require_install_tools: bool = False,
        tools: Mapping[str, str] | None = None,
        tool_policy: ToolAuthorityPolicy | None = None,
        source_environment: Mapping[str, str] | None = None,
        static_invocation_id: str | None = None,
        target_phase_hook: Any | None = None,
        enable_runtime_closure: bool = False,
        require_fresh_runtime_closure: bool = False,
        release_authoritative: bool = False,
        execution_external_authority: ExecutionExternalAuthority | None = None,
    ) -> None:
        self.profile = profile
        self.release_gate_required = resolve_release_gate_required(
            profile,
            release_authoritative=release_authoritative,
        )
        self.baseline = baseline
        self.platform = platform_key()
        self.command_results: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.completed_classes: set[str] = set()
        self.hard_gate_results: list[dict[str, Any]] = []
        self.violations: list[dict[str, Any]] = []
        self.runtime = self._runtime_identity()
        self.candidate_paths: list[str] | None = None
        self.target_phase_hook = target_phase_hook
        self.source_environment = dict(
            os.environ if source_environment is None else source_environment
        )
        self.enable_runtime_closure = enable_runtime_closure
        self.require_fresh_runtime_closure = require_fresh_runtime_closure
        self.execution_external_authority = execution_external_authority
        self.private_temp_handle = tempfile.TemporaryDirectory(prefix="cf-")
        self.private_temp_root = Path(self.private_temp_handle.name).resolve(strict=True)
        required_tools = required_tool_names(
            profile,
            require_install_tools=require_install_tools,
        )
        if enable_runtime_closure and (
            self.source_environment.get("GITHUB_ACTIONS") == "true"
            or require_fresh_runtime_closure
            or profile in {"frontend", "backend", "all"}
        ):
            required_tools.add("npm")
        self.required_tools = frozenset(required_tools)
        self.tool_policy = tool_policy or default_tool_authority_policy(
            self.source_environment,
            repo_root=REPO_ROOT,
        )
        if self.tool_policy.synthetic:
            self.platform = (
                "windows" if self.tool_policy.platform_name == "Windows" else "ubuntu"
            )
            self.runtime["platform"] = self.platform
        self.tools_injected = tools is not None or self.tool_policy.synthetic
        self.tool_authority_diagnostics: list[dict[str, Any]] = []
        if tools is None:
            self.tools, self.tool_resolution_errors = resolve_trusted_tools(
                required_tools,
                source_environment=self.source_environment,
                repo_root=REPO_ROOT,
                policy=self.tool_policy,
                diagnostics=self.tool_authority_diagnostics,
            )
        else:
            self.tools = dict(tools)
            self.tool_resolution_errors = []
        self.tool_authority_failure: ToolAuthorityUnavailable | None = None
        self.tool_authority_frozen = False
        try:
            self.tools = require_tool_set(
                self.tools,
                self.required_tools,
                phase="CAPTURE",
                resolution_errors=self.tool_resolution_errors,
            )
        except ToolAuthorityUnavailable as exc:
            self.tool_authority_failure = exc
            if str(exc) not in self.tool_resolution_errors:
                self.tool_resolution_errors.append(str(exc))
        else:
            self.tool_authority_frozen = True
        self.bash_lease: TrustedBashLease | None = None
        if (
            self.tool_authority_frozen
            and self.tool_policy.platform_name == "Windows"
            and not self.tool_policy.synthetic
            and profile in {"static", "standalone", "all"}
        ):
            bash = self.require_tool("bash", phase="CAPTURE")
            git = self.require_tool("git", phase="CAPTURE")
            try:
                self.bash_lease = TrustedBashLease(
                    bash,
                    git,
                    approved_git_roots=tuple(
                        root for _label, root in self.tool_policy.roots_for("git")
                    ),
                )
                for diagnostic in reversed(self.tool_authority_diagnostics):
                    if (
                        diagnostic.get("kind") == "bash-candidate"
                        and diagnostic.get("disposition") == "accepted"
                    ):
                        diagnostic["leasePrecheck"] = "passed"
                        break
            except OSError as exc:
                lease_text = str(exc).casefold()
                lease_reason = (
                    BASH_CANDIDATE_HARDLINK
                    if "hardlink" in lease_text
                    else BASH_CANDIDATE_REPARSE
                    if "reparse" in lease_text
                    else BASH_CANDIDATE_OUTSIDE_GIT_ROOT
                    if "root" in lease_text or "candidate position" in lease_text
                    else BASH_CANDIDATE_IDENTITY_DRIFT
                    if "identity" in lease_text or "drift" in lease_text
                    else BASH_CANDIDATE_LEASE_FAILURE
                )
                self.tool_authority_failure = ToolAuthorityUnavailable(
                    "bash",
                    "CAPTURE",
                    reason_code=lease_reason,
                    candidate_class="tool-candidate",
                )
                self.tool_resolution_errors.append(str(self.tool_authority_failure))
                self.tool_authority_diagnostics.append(
                    {
                        "kind": "bash-candidate",
                        "candidateLocationClass": "tool-candidate",
                        "reasonCode": lease_reason,
                        "disposition": "rejected",
                    }
                )
                for diagnostic in reversed(self.tool_authority_diagnostics[:-1]):
                    if (
                        diagnostic.get("kind") == "bash-candidate"
                        and diagnostic.get("disposition") == "accepted"
                    ):
                        diagnostic["leasePrecheck"] = "failed"
                        diagnostic["failureReason"] = lease_reason
                        diagnostic["reasonCode"] = lease_reason
                        diagnostic["disposition"] = "rejected"
                        break
                self.tool_authority_frozen = False
        self.child_environment = child_process_environment(
            self.tools if self.tool_authority_frozen else {},
            source_environment=self.source_environment,
            private_temp_root=self.private_temp_root,
            repo_root=REPO_ROOT,
            policy=self.tool_policy,
        )
        self.tool_leases: dict[str, ExecutableIdentityLease] = {}
        self.tool_authority_evidence: dict[str, dict[str, Any]] = {}
        if self.tool_authority_frozen:
            try:
                for name in sorted(self.required_tools):
                    path = self.require_tool(name, phase="CAPTURE")
                    lease = ExecutableIdentityLease(
                        path,
                        f"trusted-{name}",
                        allow_dependency_root=name == "npm",
                    )
                    self.tool_leases[name] = lease
                for name, lease in self.tool_leases.items():
                    root_result = _tool_root_classification_result(
                        Path(lease.path), name, self.tool_policy
                    )
                    if root_result.inspection_failed:
                        raise ToolAuthorityUnavailable(
                            name,
                            "CAPTURE",
                            reason_code=TOOL_CANDIDATE_UNREADABLE,
                            candidate_class="tool-candidate",
                        )
                    classification = root_result.root_label
                    try:
                        version_output = (
                            "test-injected-not-executed"
                            if self.tools_injected
                            else _captured_tool_version(
                                name,
                                self.tools,
                                self.child_environment,
                                lease,
                            )
                        )
                    except OSError as exc:
                        if name == "bash":
                            for diagnostic in reversed(
                                self.tool_authority_diagnostics
                            ):
                                if (
                                    diagnostic.get("kind") == "bash-candidate"
                                    and diagnostic.get("disposition") == "accepted"
                                ):
                                    diagnostic["versionProbe"] = "failed"
                                    diagnostic["failureReason"] = (
                                        BASH_CANDIDATE_VERSION_FAILURE
                                    )
                                    diagnostic["reasonCode"] = (
                                        BASH_CANDIDATE_VERSION_FAILURE
                                    )
                                    diagnostic["disposition"] = "rejected"
                                    break
                        raise ToolAuthorityUnavailable(
                            name,
                            "CAPTURE",
                            reason_code=(
                                BASH_CANDIDATE_VERSION_FAILURE if name == "bash" else None
                            ),
                        ) from exc
                    if name == "bash":
                        for diagnostic in reversed(self.tool_authority_diagnostics):
                            if (
                                diagnostic.get("kind") == "bash-candidate"
                                and diagnostic.get("disposition") == "accepted"
                            ):
                                diagnostic["versionProbe"] = "passed"
                                break
                    self.tool_authority_evidence[name] = {
                        **lease.evidence(),
                        "trustedRootClassification": classification
                        or "test-injected-authority",
                        "versionOutput": version_output,
                    }
            except (OSError, ToolAuthorityUnavailable) as exc:
                for lease in self.tool_leases.values():
                    lease.close()
                self.tool_leases.clear()
                if self.bash_lease is not None:
                    self.bash_lease.close()
                    self.bash_lease = None
                if isinstance(exc, ToolAuthorityUnavailable):
                    self.tool_authority_failure = exc
                else:
                    failed_role = getattr(exc, "tool", "authority-set")
                    self.tool_authority_failure = ToolAuthorityUnavailable(
                        failed_role,
                        "CAPTURE",
                        reason_code=UNKNOWN_FAIL_CLOSED,
                    )
                self.tool_resolution_errors.append(str(self.tool_authority_failure))
                self.tool_authority_frozen = False
                self.child_environment = child_process_environment(
                    {},
                    source_environment=self.source_environment,
                    private_temp_root=self.private_temp_root,
                    repo_root=REPO_ROOT,
                    policy=self.tool_policy,
                )
        self.planned_candidate_paths, self.command_plan_errors = deterministic_candidate_paths(
            REPO_ROOT
        )
        self.static_invocation_id = static_invocation_id or deterministic_static_invocation_id(
            REPO_ROOT
        )
        try:
            if not self.tool_authority_frozen:
                raise self.tool_authority_failure or ToolAuthorityUnavailable(
                    "authority-set", "COMMAND_PLAN"
                )
            self.command_plan = build_profile_command_plan(
                profile,
                tools=self.tools,
                candidate_paths=self.planned_candidate_paths,
                baseline=baseline,
                current_platform=self.platform,
                static_invocation_id=self.static_invocation_id,
                repo_root=REPO_ROOT,
                bash_lease=self.bash_lease,
            )
        except (OSError, ValueError) as exc:
            self.command_plan = []
            self.command_plan_errors.append(
                f"immutable command plan construction failed: {type(exc).__name__}: {exc}"
            )
        self.command_plan_digest = command_plan_digest(self.command_plan)
        self.command_plan_by_id = {
            str(record["commandId"]): record for record in self.command_plan
        }
        if len(self.command_plan_by_id) != len(self.command_plan):
            self.command_plan_errors.append("immutable command plan contains duplicate command IDs")
        self.runtime_dependency_closure: RuntimeDependencyClosure | None = None
        self.runtime_dependency_guard: RuntimeDependencyClosureGuard | None = None
        initial_precondition = (
            "MEASUREMENT_NOT_REQUESTED"
            if not enable_runtime_closure
            else "TOOL_AUTHORITY_NOT_FROZEN"
            if not self.tool_authority_frozen
            else "COMMAND_AUTHORITY_INVALID"
            if self.command_plan_errors or not self.command_plan
            else "MEASUREMENT_FAILED"
        )
        (
            self.runtime_closure_document,
            self.runtime_closure_digest,
            self.dependency_closure_digest,
        ) = _runtime_precondition_document(profile, initial_precondition)
        self.dependency_member_count = 0
        self.runtime_closure_errors: list[str] = [
            str(RuntimeClosurePreconditionError(initial_precondition))
        ]
        self.runtime_closure_guard_evidence: dict[str, Any] = {
            "guardSchemaVersion": RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
            "watcherBackend": "not-active",
            "active": False,
            "activeDuringReplay": False,
            "mutationState": "precondition-not-met",
            "queueOverflow": False,
            "mutationEventCount": 0,
        }
        if (
            enable_runtime_closure
            and self.tool_authority_frozen
            and not self.command_plan_errors
            and bool(self.command_plan)
        ):
            try:
                closure = RuntimeDependencyClosure.build(
                    profile,
                    self.tools,
                    self.child_environment,
                    repo_root=REPO_ROOT,
                    require_fresh_dependencies=require_fresh_runtime_closure,
                    source_environment=self.source_environment,
                )
                self.runtime_dependency_closure = closure
                self.runtime_closure_digest = closure.runtime_digest
                self.dependency_closure_digest = closure.dependency_digest
                self.dependency_member_count = closure.member_count
                self.runtime_closure_document = copy.deepcopy(closure.document)
                self.runtime_dependency_guard = RuntimeDependencyClosureGuard(
                    closure,
                    repo_root=REPO_ROOT,
                )
                self.runtime_closure_guard_evidence = (
                    self.runtime_dependency_guard.evidence()
                )
                self.runtime_closure_errors = []
            except Exception as exc:
                if self.runtime_dependency_closure is not None:
                    self.runtime_dependency_closure.close()
                    self.runtime_dependency_closure = None
                failure_reason = (
                    "TOOL_AUTHORITY_NOT_FROZEN"
                    if isinstance(exc, ToolAuthorityUnavailable)
                    else "DEPENDENCY_ENVIRONMENT_UNAVAILABLE"
                    if isinstance(exc, (OSError, ValueError))
                    else "MEASUREMENT_FAILED"
                )
                (
                    self.runtime_closure_document,
                    self.runtime_closure_digest,
                    self.dependency_closure_digest,
                ) = _runtime_precondition_document(profile, failure_reason)
                self.runtime_closure_errors = [
                    str(RuntimeClosurePreconditionError(failure_reason))
                ]
        self.captures: list[CommandCapture] = []
        self.target_execution_leases: list[
            tuple[TargetExecutionLease, dict[str, Any]]
        ] = []
        self.static_machine_report: dict[str, Any] | None = None
        self.locked_file_git_identities: dict[str, dict[str, Any]] = {}
        locked_identity_errors: list[str] = []
        if self.tool_authority_frozen and not self.tool_policy.synthetic:
            self.locked_file_git_identities, locked_identity_errors = (
                capture_locked_file_git_identities(
                    git=self.require_tool("git", phase="CAPTURE"),
                    environment=self.child_environment,
                    repo_root=REPO_ROOT,
                    executable_lease=self.tool_leases.get("git"),
                )
            )
        elif self.tool_policy.synthetic:
            locked_identity_errors.append(
                "locked Git blob authority is intentionally unavailable to synthetic test tools"
            )
        else:
            locked_identity_errors.append(
                "locked Git blob authority is unavailable because tool authority is not frozen"
            )
        (
            self.initial_trusted_snapshot,
            self.initial_trusted_errors,
        ) = snapshot_trusted_files(
            locked_identities=self.locked_file_git_identities
        )
        self.initial_trusted_errors.extend(locked_identity_errors)
        self.runtime.update(
            {
                "runtimeClosureDigest": self.runtime_closure_digest,
                "dependencyClosureDigest": self.dependency_closure_digest,
                "dependencyMemberCount": str(self.dependency_member_count),
            }
        )

    def _runtime_identity(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "os": platform.platform(),
            "python": platform.python_version(),
            "pythonImplementation": platform.python_implementation(),
            "node": "unavailable",
            "npm": "unavailable",
            "runtimeClosureDigest": "unavailable",
            "dependencyClosureDigest": "unavailable",
            "dependencyMemberCount": "0",
        }

    def require_tool(self, name: str, *, phase: str) -> str:
        if not self.tool_authority_frozen:
            if self.tool_authority_failure is not None:
                raise ToolAuthorityUnavailable(
                    name,
                    phase,
                    reason_code=self.tool_authority_failure.reason_code,
                    path_index=self.tool_authority_failure.path_index,
                    candidate_class=self.tool_authority_failure.candidate_class,
                    root_category=self.tool_authority_failure.root_category,
                )
            raise ToolAuthorityUnavailable(
                name, phase, reason_code=UNKNOWN_FAIL_CLOSED
            )
        path = require_tool(
            self.tools,
            name,
            phase=phase,
            resolution_errors=self.tool_resolution_errors,
        )
        lease = getattr(self, "tool_leases", {}).get(name)
        if lease is not None:
            okay, _error = lease.verify()
            if not okay:
                self.tool_authority_frozen = False
                self.tool_authority_failure = ToolAuthorityUnavailable(
                    name,
                    phase,
                    reason_code=(BASH_CANDIDATE_IDENTITY_DRIFT if name == "bash" else None),
                )
                if str(self.tool_authority_failure) not in self.tool_resolution_errors:
                    self.tool_resolution_errors.append(str(self.tool_authority_failure))
                raise self.tool_authority_failure
        return path

    def require_all_tools(self, *, phase: str) -> dict[str, str]:
        if not self.tool_authority_frozen:
            return require_tool_set(
                self.tools,
                self.required_tools,
                phase=phase,
                resolution_errors=self.tool_resolution_errors,
            )
        return {
            name: self.require_tool(name, phase=phase)
            for name in sorted(self.required_tools)
        }

    def require_tool_lease(self, name: str, *, phase: str) -> ExecutableIdentityLease:
        """Revalidate and return the held executable identity for one required role."""

        self.require_tool(name, phase=phase)
        lease = self.tool_leases.get(name)
        if lease is None:
            raise ToolAuthorityUnavailable(name, phase)
        okay, _error = lease.verify()
        if not okay:
            self.tool_authority_frozen = False
            self.tool_authority_failure = ToolAuthorityUnavailable(
                name,
                phase,
                reason_code=(BASH_CANDIDATE_IDENTITY_DRIFT if name == "bash" else None),
            )
            raise self.tool_authority_failure
        return lease

    def add_hard_gate(self, gate_id: str, passed: bool, detail: str) -> None:
        record = {"id": gate_id, "status": "pass" if passed else "fail", "detail": sanitize_text(detail)}
        self.hard_gate_results.append(record)
        if not passed:
            self.violations.append({"id": gate_id, "detail": sanitize_text(detail)})

    def _bind_command_record(
        self,
        record: Mapping[str, Any],
        *,
        actual_argv: Sequence[str] | None = None,
        cwd: str = ".",
    ) -> dict[str, Any]:
        command_id = str(record.get("commandId", ""))
        expected = getattr(self, "command_plan_by_id", {}).get(command_id)
        bound = dict(record)
        if expected is None:
            return bound
        for key, value in expected.items():
            if key not in {"commandId", "commandClass", "required", "argv", "cwd"}:
                bound[key] = value
        if actual_argv is None:
            bound["argv"] = list(expected["argv"])
            bound["cwd"] = expected["cwd"]
            bound["required"] = expected["required"]
            bound["commandClass"] = expected["commandClass"]
            return bound
        argv = [str(value) for value in actual_argv]
        bound["argv"] = list(expected["argv"])
        bound["logicalArgv"] = list(expected.get("logicalArgv", expected["argv"]))
        bound["executionArgv"] = list(expected.get("executionArgv", expected["argv"]))
        bound["cwd"] = expected["cwd"]
        bound["required"] = expected["required"]
        bound["commandClass"] = expected["commandClass"]
        bound["actualExecutionArgv"] = argv
        if argv:
            executable_value = argv[0]
            try:
                resolved = str(Path(executable_value).resolve(strict=True))
            except OSError:
                resolved = executable_value
            size, digest, identity = _measured_file_authority(Path(resolved))
            bound["resolvedExecutablePath"] = resolved
            bound["resolvedExecutableSize"] = size
            bound["resolvedExecutableSha256"] = digest
            bound["resolvedExecutableFileIdentity"] = identity
        dependency_backed = str(bound.get("toolRole", "")) in DEPENDENCY_BACKED_TOOL_ROLES
        bound["dependencyBacked"] = dependency_backed
        if dependency_backed:
            bound["runtimeClosureDigest"] = self.runtime_closure_digest
            bound["dependencyClosureDigest"] = self.dependency_closure_digest
            bound["nodePath"] = []
            bound["resolvedTestRunnerEntrypoint"] = str(
                bound.get("resolvedExecutablePath")
            )
            bound["resolvedTestRunnerSha256"] = bound.get("resolvedExecutableSha256")
            guard_evidence = (
                self.runtime_dependency_guard.evidence()
                if self.runtime_dependency_guard is not None
                else {
                    "guardSchemaVersion": RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
                    "watcherBackend": "unavailable",
                    "active": False,
                    "activeDuringReplay": False,
                    "mutationState": "unknown",
                    "queueOverflow": False,
                    "mutationEventCount": 0,
                }
            )
            bound["closureWatcherActive"] = guard_evidence["active"]
            bound["closureMutationState"] = guard_evidence["mutationState"]
            bound["runtimeClosureGuard"] = guard_evidence
        return bound

    def add_command(self, capture: CommandCapture) -> dict[str, Any]:
        self.captures.append(capture)
        bound = self._bind_command_record(
            capture.evidence(),
            actual_argv=capture.argv,
            cwd=capture.cwd,
        )
        self.command_results.append(bound)
        if bound.get("dependencyBacked"):
            closure_errors = list(self.runtime_closure_errors)
            if self.runtime_dependency_closure is None or self.runtime_dependency_guard is None:
                closure_errors.append("dependency-backed command lacks a fresh runtime closure guard")
            else:
                closure_errors.extend(self.runtime_dependency_closure.verify_executables())
                if self.runtime_dependency_guard.mutated:
                    closure_errors.append("dependency closure mutation is sticky")
                guard_evidence = self.runtime_dependency_guard.evidence()
                bound["closureWatcherActive"] = guard_evidence["active"]
                bound["closureMutationState"] = guard_evidence["mutationState"]
                bound["runtimeClosureGuard"] = guard_evidence
            if closure_errors:
                bound["exitCode"] = PROCESS_TREE_FAILURE_EXIT
                bound["processTreeStatus"] = "cleanup-failed"
                bound["processTreeError"] = "; ".join(sorted(set(closure_errors)))
                bound["error"] = "RUNTIME-CLOSURE-ERROR: " + bound["processTreeError"]
                capture.exit_code = PROCESS_TREE_FAILURE_EXIT
                capture.process_tree_status = "cleanup-failed"
                capture.process_tree_error = bound["processTreeError"]
                capture.error = bound["error"]
                self.add_hard_gate(
                    "RUNTIME-DEPENDENCY-CLOSURE",
                    False,
                    bound["processTreeError"],
                )
        return bound

    def add_internal_command(self, record: Mapping[str, Any]) -> dict[str, Any]:
        bound = self._bind_command_record(record)
        self.command_results.append(bound)
        return bound

    def execute_protected_internal(
        self,
        command_id: str,
        evaluator: Any,
    ) -> tuple[dict[str, Any], Any]:
        """Execute an in-process command exclusively from its frozen target bundle."""

        plan_record = self.command_plan_by_id[command_id]
        targets = plan_record.get("targets")
        adapter = str(plan_record.get("executionInputMode", ""))
        if adapter != "PROTECTED-TARGET-BUNDLE" or not isinstance(targets, list) or not targets:
            raise ValueError(f"{command_id} lacks protected target-bundle authority")
        bundle: ProtectedTargetBundle | None = None
        payload: Any = None
        passed = False
        policy_started = False
        detail = "protected target bundle was not executed"
        if self.target_phase_hook is not None:
            self.target_phase_hook(command_id, "after-plan-before-target-bundle", None)
        try:
            bundle = ProtectedTargetBundle(
                targets,
                repo_root=REPO_ROOT,
                execution_adapter=adapter,
            )
            if self.target_phase_hook is not None:
                self.target_phase_hook(
                    command_id, "after-target-bundle-before-materialization", bundle
                )
            bundle.materialize()
            if self.target_phase_hook is not None:
                self.target_phase_hook(command_id, "after-materialization-before-policy", bundle)
            policy_started = True
            evaluated = evaluator(bundle)
            if (
                not isinstance(evaluated, tuple)
                or len(evaluated) != 3
                or type(evaluated[0]) is not bool
                or not isinstance(evaluated[1], str)
            ):
                raise ValueError("protected policy evaluator returned an invalid result")
            passed, detail, payload = evaluated
            if self.target_phase_hook is not None:
                self.target_phase_hook(command_id, "after-policy-before-evidence", bundle)
            bundle_ok, bundle_error = bundle.verify()
            if not bundle_ok:
                passed = False
                detail = bundle_error or "protected target bundle source drifted"
        except Exception as exc:
            passed = False
            detail = f"PROTECTED-TARGET-BUNDLE-ERROR: {type(exc).__name__}: {exc}"
        finally:
            if bundle is not None:
                bundle.close()
        bundle_evidence = (
            bundle.evidence()
            if bundle is not None
            else _failed_protected_target_bundle(targets, adapter)
        )
        record = make_internal_result(
            command_id,
            str(plan_record["commandClass"]),
            passed,
            detail,
            required=bool(plan_record["required"]),
            execution_authority=self.require_tool("python", phase="EXECUTION"),
            observed_execution_authority=(
                self.require_tool("python", phase="EXECUTION")
                if self.tool_policy.synthetic
                else sys.executable
            ),
        )
        if not policy_started:
            record["executed"] = False
            record["started"] = False
            record["setupFailure"] = True
            record["exitCode"] = None
            record["executionDurationClass"] = "not-started"
            record["containment"] = "not-started"
            record["processTreeStatus"] = "setup-failed"
        record["actualExecutionInputMode"] = adapter
        record["executionInputs"] = copy.deepcopy(bundle_evidence["executionInputs"])
        record["executionInputBundleDigest"] = bundle_evidence[
            "executionInputBundleDigest"
        ]
        record["protectedTargetBundle"] = bundle_evidence
        return self.add_internal_command(record), payload

    def execute_protected_external(
        self,
        command_id: str,
        *,
        timeout: int,
    ) -> tuple[CommandCapture, dict[str, Any]]:
        plan_record = self.command_plan_by_id[command_id]
        execution_argv = list(plan_record.get("executionArgv", []))
        if not execution_argv:
            raise ToolAuthorityUnavailable("authority-set", "EXECUTION")
        executable_lease = None
        for name in sorted(self.required_tools):
            if name == "npm":
                continue
            path = self.require_tool(name, phase="EXECUTION")
            if _same_file_identity(Path(execution_argv[0]), Path(path)):
                executable_lease = self.require_tool_lease(name, phase="EXECUTION")
                break
        if executable_lease is None:
            raise ToolAuthorityUnavailable("authority-set", "EXECUTION")
        capture, protected_bundle = execute_planned_static_suite(
            plan_record,
            repo_root=REPO_ROOT,
            env=self.child_environment,
            timeout=timeout,
            phase_hook=(
                (
                    lambda phase, bundle: self.target_phase_hook(
                        command_id,
                        phase,
                        bundle,
                    )
                )
                if self.target_phase_hook is not None
                else None
            ),
            executable_lease=executable_lease,
        )
        command_record = self.add_command(capture)
        command_record["executionInputs"] = copy.deepcopy(
            protected_bundle["executionInputs"]
        )
        command_record["executionInputBundleDigest"] = protected_bundle[
            "executionInputBundleDigest"
        ]
        command_record["protectedTargetBundle"] = protected_bundle
        return capture, command_record

    def add_observation(self, item: Mapping[str, Any]) -> dict[str, Any]:
        raw_item = item.get("rawObservation")
        command_id = str(
            item.get("commandId", "")
            or (raw_item.get("commandId", "") if isinstance(raw_item, Mapping) else "")
        )
        source = next(
            (record for record in self.command_results if record.get("commandId") == command_id),
            None,
        )
        if source is None:
            derived = dict(item)
        else:
            derived = _rederive_observation_record(item, source)
            raw = derived.get("rawObservation")
            producer = source.setdefault("producerObservations", [])
            if isinstance(raw, dict):
                identity = (raw.get("commandId"), raw.get("observationOrdinal"))
                if any(
                    (existing.get("commandId"), existing.get("observationOrdinal")) == identity
                    for existing in producer
                    if isinstance(existing, dict)
                ):
                    raise ValueError("producer observation identity is duplicated")
                producer.append(raw)
                producer.sort(key=lambda value: int(value.get("observationOrdinal", -1)))
                source["producerObservationSetDigest"] = producer_observation_set_digest(producer)
        self.observations.append(derived)
        return derived

    def add_process_observation(
        self,
        command_record: Mapping[str, Any],
        capture: CommandCapture,
        *,
        source_result_id: str,
        source_path: str | None = None,
        observation_ordinal: int = 0,
    ) -> dict[str, Any]:
        """Bind one process result to its command's raw output identity."""

        if (_direct_node_test_authorized_paths(command_record) is not None
            and capture.exit_code == 0 and capture.stdout_raw is not None
            and capture.stderr_raw is not None and isinstance(command_record, dict)):
            try:
                command_record["directNodeTestRawStreams"] = {
                    "stdout": capture.stdout_raw.decode("utf-8", errors="strict"),
                    "stderr": capture.stderr_raw.decode("utf-8", errors="strict"),
                }
            except UnicodeError:
                # Exact decoding is necessary for this protocol. The ordinary
                # execution/observation evidence still records the raw failure.
                pass
        raw_fields: Any = {
            "executed": capture.executed,
            "exitCode": capture.exit_code,
            "stdout": (
                capture.identity_stdout
                if capture.identity_stdout is not None
                else capture.stdout
            ),
            "stderr": (
                capture.identity_stderr
                if capture.identity_stderr is not None
                else capture.stderr
            ),
            "error": (
                capture.identity_error
                if capture.identity_error is not None
                else capture.error
            ),
        }
        path_binding: Mapping[str, Any] | None = None
        if (
            (
                source_result_id in R03_FAILURE_TARGETS
                or source_result_id in R11_KNOWN_DEBT_FAILURE_TARGETS
            )
            and isinstance(capture.failure_path_authority, FailurePathAuthority)
        ):
            raw_fields, path_binding = canonicalize_failure_identity_value(
                raw_fields,
                capture.failure_path_authority,
            )
        raw = make_raw_observation(
            capture.command_id,
            int(command_record["ordinal"]),
            observation_ordinal,
            "process-output-v1",
            source_result_id,
            source_path,
            raw_fields,
            command_output_digest(command_record),
            failure_path_authority=path_binding,
        )
        return self.add_observation(
            {"commandId": capture.command_id, "rawObservation": raw}
        )

    def require_command_success(self, capture: CommandCapture, gate_id: str) -> bool:
        self.add_command(capture)
        if not capture.executed:
            self.add_hard_gate(gate_id, False, f"required command did not execute: {capture.command_id}")
            return False
        passed = capture.execution_passed()
        self.add_hard_gate(
            gate_id,
            passed,
            f"{capture.command_id} exit={capture.exit_code} processTree={capture.process_tree_status}",
        )
        return passed

    def ensure_candidate_paths(self) -> list[str]:
        if self.candidate_paths is None:
            git = self.require_tool("git", phase="EXECUTION")
            paths, errors, capture = git_candidate_paths(
                git=git,
                env=self.child_environment,
                executable_lease=self.require_tool_lease("git", phase="EXECUTION"),
            )
            self.add_command(capture)
            if paths != self.planned_candidate_paths:
                errors.append(
                    "Git command inventory does not match the precomputed index authority"
                )
            self.candidate_paths = paths
            for error in errors:
                self.add_hard_gate("REPOSITORY-GIT-BOUNDARY", False, error)
        return self.candidate_paths

    def run_baseline_policy(self) -> None:
        def evaluate(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            text = bundle.text_for("developer/tests/ci/phase1-ci-baseline.json")
            parsed = strict_json_loads(
                text,
                label="developer/tests/ci/phase1-ci-baseline.json",
            )
            errors = validate_baseline_document(parsed)
            if parsed != self.baseline:
                errors.append("protected baseline bytes differ from runner baseline authority")
            return (
                not errors,
                "baseline schema and ratified category counts passed"
                if not errors
                else "; ".join(errors),
                parsed,
            )

        record, _parsed = self.execute_protected_internal("baseline-schema", evaluate)
        passed = record.get("exitCode") == 0
        self.add_hard_gate(
            "BASELINE-POLICY-ENFORCEMENT",
            passed,
            "baseline schema passed" if passed else "protected baseline schema failed",
        )

    def run_runtime_policy(self, *, require_npm: bool = False) -> None:
        self.add_hard_gate(
            "RUNTIME-DEPENDENCY-CLOSURE-SETUP",
            not self.runtime_closure_errors,
            (
                f"runtime closure digest={self.runtime_closure_digest} members={self.dependency_member_count}"
                if not self.runtime_closure_errors
                else "; ".join(self.runtime_closure_errors)
            ),
        )
        self.add_hard_gate(
            "IMMUTABLE-COMMAND-AUTHORITY",
            not self.command_plan_errors and bool(self.command_plan),
            (
                f"command plan frozen digest={self.command_plan_digest} commands={len(self.command_plan)}"
                if not self.command_plan_errors and self.command_plan
                else "; ".join(self.command_plan_errors) or "immutable command plan is empty"
            ),
        )
        self.add_hard_gate(
            "TRUSTED-EXECUTABLE-RESOLUTION",
            not self.tool_resolution_errors,
            "trusted tools resolved" if not self.tool_resolution_errors else "; ".join(self.tool_resolution_errors),
        )
        self.add_hard_gate(
            "TRUSTED-FILE-MANIFEST",
            not self.initial_trusted_errors,
            "trusted-file manifest measured" if not self.initial_trusted_errors else "; ".join(self.initial_trusted_errors),
        )
        python_ok = sys.version_info[:2] == (3, 12)
        self.add_hard_gate(
            "PYTHON-CI-FAMILY",
            python_ok,
            f"Python {platform.python_version()} (required family 3.12)",
        )
        if not self.tool_authority_frozen:
            self.add_hard_gate(
                "NODE-CI-FAMILY",
                False,
                "Node execution was blocked by trusted-tool authority",
            )
            if require_npm:
                self.add_hard_gate(
                    "NPM-REQUIRED",
                    False,
                    "npm execution was blocked by trusted-tool authority",
                )
            if self.profile in {"static", "standalone", "all"}:
                self.add_hard_gate(
                    "GIT-BASH-TRUSTED-RUNTIME",
                    False,
                    "Git Bash execution was blocked by trusted-tool authority",
                )
            return
        node = self.require_tool("node", phase="EXECUTION")
        node_lease = self.require_tool_lease("node", phase="EXECUTION")
        capture = execute_command(
            "node-version",
            "runtime-identity",
            [node, "--version"],
            timeout=30,
            env=self.child_environment,
            executable_lease=node_lease,
        )
        self.add_command(capture)
        version = sanitize_text(capture.stdout).strip()
        self.runtime["node"] = version or "unavailable"
        self.add_hard_gate(
            "NODE-CI-FAMILY",
            capture.executed and capture.exit_code == 0 and bool(re.fullmatch(r"v24\.\d+\.\d+", version)),
            f"Node {version or 'unavailable'} (required family 24.x)",
        )
        npm = (
            self.require_tool("npm", phase="EXECUTION")
            if require_npm
            else self.tools.get("npm")
        )
        if npm is not None:
            capture = execute_command(
                "npm-version",
                "runtime-identity",
                [node, npm, "--version"],
                timeout=30,
                env=self.child_environment,
                required=require_npm,
                logical_argv=[npm, "--version"],
                executable_lease=node_lease,
            )
            self.add_command(capture)
            if capture.executed and capture.exit_code == 0:
                self.runtime["npm"] = sanitize_text(capture.stdout).strip()
        else:
            npm_plan = self.command_plan_by_id["npm-version"]
            self.add_command(
                CommandCapture(
                    command_id="npm-version",
                    command_class="runtime-identity",
                    argv=list(npm_plan["executionArgv"]),
                    logical_argv=list(npm_plan["logicalArgv"]),
                    executed=False,
                    exit_code=None,
                    duration_seconds=0.0,
                    stdout="",
                    stderr="",
                    required=require_npm,
                    error="trusted npm executable is unavailable",
                )
            )
            if require_npm:
                self.add_hard_gate("NPM-REQUIRED", False, "required npm executable is unavailable")

        if self.profile in {"static", "standalone", "all"}:
            bash = self.require_tool("bash", phase="EXECUTION")
            bash_lease = (
                self.bash_lease
                if self.tool_policy.platform_name == "Windows"
                and not self.tool_policy.synthetic
                else self.require_tool_lease("bash", phase="EXECUTION")
            )
            if bash_lease is None:
                raise ToolAuthorityUnavailable("bash", "EXECUTION")
            bash_capture = execute_command(
                "git-bash-version",
                "runtime-identity",
                [bash, "--version"],
                timeout=30,
                env=self.child_environment,
                executable_lease=bash_lease,
            )
            self.add_command(bash_capture)
            version_text = sanitize_text(bash_capture.stdout + "\n" + bash_capture.stderr)
            bash_ok = bash_capture.execution_passed() and bool(
                re.search(r"(?i)GNU bash(?:,|\s)+version\s+\d+", version_text)
            )
            self.add_hard_gate(
                "GIT-BASH-TRUSTED-RUNTIME",
                bash_ok,
                "trusted Git Bash product verification passed"
                if bash_ok
                else "trusted Git Bash product verification failed closed",
            )

    def run_repository_boundary(self) -> None:
        paths = self.ensure_candidate_paths()
        git = self.require_tool("git", phase="EXECUTION")
        git_lease = self.require_tool_lease("git", phase="EXECUTION")
        unexpected_untracked: list[str] = []
        tracked_capture = execute_command(
            "git-tracked-paths",
            "repository-boundary",
            trusted_git_arguments(git, "ls-files", "-z", "--cached"),
            timeout=60,
            env=self.child_environment,
            include_preview=False,
            executable_lease=git_lease,
        )
        self.add_command(tracked_capture)
        tracked = set(tracked_capture.stdout.split("\0")) if tracked_capture.exit_code == 0 else set()
        for path in paths:
            if path not in tracked and path not in LOCAL_IMPLEMENTATION_ALLOWLIST:
                unexpected_untracked.append(path)
        boundary_errors: list[str] = []
        if not tracked_capture.executed or tracked_capture.exit_code != 0:
            boundary_errors.append("tracked-file inventory did not execute")
        if unexpected_untracked:
            boundary_errors.append(f"unexpected untracked paths: {unexpected_untracked[:10]}")
        if any(path.startswith(".ci-results/") for path in tracked):
            boundary_errors.append(".ci-results output is tracked")

        for command_id, argv in (
            ("git-diff-check", trusted_git_arguments(git, "diff", "--check")),
            ("git-cached-diff-check", trusted_git_arguments(git, "diff", "--cached", "--check")),
        ):
            capture = execute_command(
                command_id,
                "repository-boundary",
                argv,
                timeout=60,
                env=self.child_environment,
                executable_lease=git_lease,
            )
            self.add_command(capture)
            if not capture.executed or capture.exit_code != 0:
                boundary_errors.append(f"{command_id} failed")

        stage_capture = execute_command(
            "git-stage-modes",
            "repository-boundary",
            trusted_git_arguments(git, "ls-files", "-s", "-z"),
            timeout=60,
            env=self.child_environment,
            include_preview=False,
            executable_lease=git_lease,
        )
        self.add_command(stage_capture)
        if not stage_capture.executed or stage_capture.exit_code != 0:
            boundary_errors.append("Git stage-mode inventory failed")
        elif any(record.startswith("120000 ") for record in stage_capture.stdout.split("\0") if record):
            boundary_errors.append("tracked symbolic links are forbidden by the public boundary gate")

        git_dir_capture = execute_command(
            "git-dir",
            "repository-boundary",
            trusted_git_arguments(git, "rev-parse", "--absolute-git-dir"),
            timeout=30,
            env=self.child_environment,
            include_preview=False,
            executable_lease=git_lease,
        )
        self.add_command(git_dir_capture)
        if git_dir_capture.executed and git_dir_capture.exit_code == 0:
            git_dir = Path(git_dir_capture.stdout.strip())
            markers = (
                "MERGE_HEAD",
                "CHERRY_PICK_HEAD",
                "REVERT_HEAD",
                "BISECT_LOG",
                "rebase-apply",
                "rebase-merge",
                "sequencer",
            )
            active = [marker for marker in markers if (git_dir / marker).exists()]
            if active:
                boundary_errors.append(f"active Git operation markers: {active}")
        else:
            boundary_errors.append("Git directory could not be resolved")
        self.add_hard_gate(
            "REPOSITORY-GIT-BOUNDARY",
            not boundary_errors,
            "repository boundary passed" if not boundary_errors else "; ".join(boundary_errors),
        )

    def run_private_and_secret_policy(self) -> None:
        paths = self.ensure_candidate_paths()
        path_violations = [
            f"{relative}: {reason}"
            for relative in paths
            if (reason := private_or_operational_path_reason(relative)) is not None
        ]

        def evaluate_paths(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            for relative in paths:
                bundle.bytes_for(relative)
            return (
                not path_violations,
                f"scannedPaths={len(paths)} violations={len(path_violations)}",
                None,
            )

        self.execute_protected_internal("tracked-private-resource-scan", evaluate_paths)

        def evaluate_secrets(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            secret_violations: list[str] = []
            scan_records: list[dict[str, Any]] = []
            scanned_bytes = 0
            scanned_text_files = 0
            scanned_binary_files = 0
            for relative in paths:
                scan = scan_bytes_for_secrets(relative, bundle.bytes_for(relative))
                scan_records.append(
                    {
                        "path": relative,
                        "fileSize": scan.get("fileSize"),
                        "classification": scan.get("classification"),
                        "scannedBytes": scan.get("scannedBytes"),
                        "rawBytesScanned": scan.get("rawBytesScanned"),
                        "encodingViewsApplied": scan.get("encodingViewsApplied", []),
                        "utf16LeDecodedUnits": scan.get("utf16LeDecodedUnits", 0),
                        "utf16BeDecodedUnits": scan.get("utf16BeDecodedUnits", 0),
                        "patternFamiliesApplied": scan.get("patternFamiliesApplied", []),
                        "hitCount": scan.get("hitCount", len(scan.get("hits", []))),
                    }
                )
                scanned_bytes += int(scan.get("scannedBytes", 0))
                if scan.get("classification") == "text-scanned":
                    scanned_text_files += 1
                elif scan.get("classification") == "binary-scanned":
                    scanned_binary_files += 1
                if not scan.get("passed"):
                    secret_violations.append(
                        f"{relative}: {', '.join(str(hit) for hit in scan.get('hits', []))}"
                    )
            detail = (
                f"scannedPaths={len(paths)} textFiles={scanned_text_files} "
                f"binaryFiles={scanned_binary_files} scannedBytes={scanned_bytes} "
                f"violations={len(secret_violations)}"
            )
            return not secret_violations, detail, (secret_violations, scan_records)

        secret_record, secret_payload = self.execute_protected_internal(
            "tracked-secret-scan", evaluate_secrets
        )
        if isinstance(secret_payload, tuple) and len(secret_payload) == 2:
            secret_violations, scan_records = secret_payload
            secret_record["fileScans"] = scan_records
        else:
            secret_violations = ["protected secret scan did not produce authoritative results"]
        self.add_hard_gate(
            "TRACKED-PRIVATE-RESOURCE-EXCLUSION",
            not path_violations
            and next(
                record for record in self.command_results
                if record.get("commandId") == "tracked-private-resource-scan"
            ).get("exitCode") == 0,
            "no tracked private resources" if not path_violations else "; ".join(path_violations[:10]),
        )
        self.add_hard_gate(
            "SECRET-OPERATIONAL-ARTIFACT-EXCLUSION",
            not secret_violations and secret_record.get("exitCode") == 0,
            "all regular-file bytes passed credential scanning"
            if not secret_violations
            else "; ".join(secret_violations[:10]),
        )

    def run_license_policy(self) -> None:
        required_files = (
            "LICENSE",
            "LICENSE.md",
            "NOTICE.md",
            "LICENSES/AGPL-3.0-only.txt",
            "README.md",
            "docs/CONTENT_POLICY.md",
            "docs/STATUS.md",
            "api-contract/README.md",
            "backend/package.json",
        )
        spdx_paths = [
            path
            for path in self.ensure_candidate_paths()
            if (
                (path.startswith("backend/src/") or path.startswith("backend/scripts/") or path.startswith("backend/test/"))
                and Path(path).suffix.lower() in {".js", ".mjs"}
            )
            or path == "api-contract/README.md"
        ]
        content_expectations = (
            ("LICENSE.md", "LICENSES/AGPL-3.0-only.txt"),
            ("LICENSE.md", "mixed-license"),
            ("NOTICE.md", "LICENSE.md"),
            ("README.md", "docs/STATUS.md#licensing-and-governance"),
            ("docs/STATUS.md", "## Licensing and governance"),
            ("docs/CONTENT_POLICY.md", "private resource"),
        )

        def evaluate(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            checks: list[tuple[str, bool]] = []
            for relative in required_files:
                checks.append((f"required governance file {relative}", bool(bundle.bytes_for(relative))))
            try:
                backend_package = strict_json_loads(
                    bundle.text_for("backend/package.json"),
                    label="backend/package.json",
                )
                checks.append(
                    (
                        "backend package license is AGPL-3.0-only",
                        backend_package.get("license") == "AGPL-3.0-only",
                    )
                )
            except (UnicodeError, json.JSONDecodeError, ValueError):
                checks.append(("backend package metadata parses", False))
            spdx_missing: list[str] = []
            for relative in spdx_paths:
                source = bundle.bytes_for(relative).decode("utf-8", errors="replace")
                if "SPDX-License-Identifier: AGPL-3.0-only" not in "\n".join(
                    source.splitlines()[:5]
                ):
                    spdx_missing.append(relative)
            checks.append(("authorized server scope has AGPL SPDX headers", not spdx_missing))
            for relative, expected in content_expectations:
                source = bundle.bytes_for(relative).decode("utf-8", errors="replace")
                checks.append(
                    (
                        f"{relative} contains governance marker {expected}",
                        expected.lower() in source.lower(),
                    )
                )
            failures = [name for name, passed in checks if not passed]
            detail = (
                f"checks={len(checks)} failures={len(failures)}"
                if not failures
                else "; ".join(failures + spdx_missing)
            )
            return not failures, detail, failures

        record, failures = self.execute_protected_internal(
            "license-governance-consistency", evaluate
        )
        passed = record.get("exitCode") == 0 and failures == []
        self.add_hard_gate(
            "LICENSE-GOVERNANCE-CONSISTENCY",
            passed,
            "licence/governance consistency passed"
            if passed
            else "protected licence/governance consistency failed",
        )

    def run_workflow_policy(self) -> None:
        plan_record = self.command_plan_by_id["workflow-self-policy"]

        def evaluate(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            errors = run_workflow_policy(
                bundle.bytes_for(".github/workflows/ci.yml"),
                bundle.bytes_for("docs/CI_POLICY.md"),
                bundle.bytes_for("developer/tests/ci/phase1-ci-baseline.json"),
                plan_record["targets"],
            )
            return (
                not errors,
                f"errors={len(errors)}" if not errors else "; ".join(errors),
                errors,
            )

        record, errors = self.execute_protected_internal("workflow-self-policy", evaluate)
        if not isinstance(errors, list):
            errors = ["protected workflow policy did not return an authoritative result"]
        passed = record.get("exitCode") == 0 and not errors
        self.add_hard_gate(
            "WORKFLOW-SELF-POLICY",
            passed,
            "workflow policy passed" if passed else "; ".join(errors),
        )

    def run_policy_profile(self) -> None:
        self.run_repository_boundary()
        self.run_private_and_secret_policy()
        self.run_license_policy()
        self.run_workflow_policy()

    def run_static_profile(self) -> None:
        invocation_id = self.static_invocation_id
        python_executable = self.require_tool("python", phase="EXECUTION")
        argv = [
            python_executable,
            "-B",
            STATIC_SUITE_RELATIVE_PATH,
            "--ci-machine-json-stdout",
            "--ci-invocation-id",
            invocation_id,
        ]
        expected_machine_plan: list[dict[str, Any]] | None = None
        plan_errors: list[str] = []
        try:
            expected_machine_plan = build_expected_static_machine_command_plan(
                invocation_id,
                python_executable=python_executable,
                current_platform=self.platform,
            )
        except (OSError, ValueError) as exc:
            plan_errors.append(f"static machine authority could not be frozen: {type(exc).__name__}")
        static_plan = self.command_plan_by_id["static-suite"]
        capture, protected_bundle = execute_planned_static_suite(
            static_plan,
            repo_root=REPO_ROOT,
            env=self.child_environment,
            timeout=1200,
            phase_hook=(
                (
                    lambda phase, bundle: self.target_phase_hook(
                        "static-suite", phase, bundle
                    )
                )
                if self.target_phase_hook is not None
                else None
            ),
            executable_lease=self.require_tool_lease("python", phase="EXECUTION"),
        )
        report: dict[str, Any] | None = None
        report_errors: list[str] = list(plan_errors)
        if not capture.output_limited:
            try:
                report, parse_errors = parse_static_machine_report(
                    capture.failure_identity_stdout_bytes(),
                    expected_invocation_id=invocation_id,
                )
                report_errors.extend(parse_errors)
            except (UnicodeEncodeError, ValueError) as exc:
                report_errors.append(
                    f"static machine stdout could not be recovered exactly: {type(exc).__name__}"
                )
        if report is not None and expected_machine_plan is not None:
            authority_keys = set(expected_machine_plan[0])
            reported_plan = [
                {key: value for key, value in record.items() if key in authority_keys}
                for record in report["commandResults"]
            ]
            if reported_plan != expected_machine_plan:
                report_errors.append("static machine command plan does not match parent authority")
            if report["commandPlanDigest"] != static_machine_command_plan_digest(
                expected_machine_plan
            ):
                report_errors.append("static machine commandPlanDigest does not match parent authority")
        invocation_exact = capture.argv == argv
        if not invocation_exact:
            report_errors.append("static machine invocation argv identity is not exact")
        canonical_report: dict[str, Any] | None = None
        canonical_observation_bindings: list[Mapping[str, Any] | None] = []
        if report is not None and not report_errors and capture.execution_passed():
            canonical_report = copy.deepcopy(report)
            canonical_results: list[Any] = []
            for result in report["observations"]:
                scope = f"result:{result.get('name', '')}"
                if isinstance(
                    capture.failure_path_authority,
                    FailurePathAuthority,
                ):
                    if (
                        scope in R11_KNOWN_DEBT_FAILURE_TARGETS
                        and scope not in R03_FAILURE_TARGETS
                    ):
                        canonical_result, binding = canonicalize_failure_identity_value(
                            result,
                            capture.failure_path_authority,
                        )
                    else:
                        canonical_result, binding = _canonicalize_static_result_failure_paths(
                            result,
                            capture.failure_path_authority,
                        )
                else:
                    canonical_result = copy.deepcopy(result)
                    binding = None
                canonical_results.append(canonical_result)
                canonical_observation_bindings.append(binding)
            canonical_report["observations"] = canonical_results
            _canonicalize_static_machine_capture(capture, canonical_report)
            capture.validated_static_machine_report = copy.deepcopy(canonical_report)
        static_command_record = self.add_command(capture)
        static_command_record["executionInputs"] = copy.deepcopy(
            protected_bundle["executionInputs"]
        )
        static_command_record["executionInputBundleDigest"] = protected_bundle[
            "executionInputBundleDigest"
        ]
        static_command_record["protectedTargetBundle"] = protected_bundle
        execution_passed = capture.execution_passed() and invocation_exact and report is not None and not report_errors
        self.add_hard_gate(
            "STATIC-SUITE-EXECUTION",
            execution_passed,
            f"static suite exit={capture.exit_code} processTree={capture.process_tree_status} "
            f"machineSchema={'valid' if report is not None and not report_errors else 'invalid'}",
        )
        if not execution_passed:
            detail_parts = ["static suite execution failed; semantic output was not parsed"]
            if capture.stderr:
                detail_parts.append(
                    "sanitized stderr tail: "
                    + bounded_preview(capture.stderr, max_lines=12, max_bytes=1600)
                )
            elif capture.error:
                detail_parts.append(f"runner error: {sanitize_text(capture.error)}")
            detail_parts.extend(report_errors)
            self.add_hard_gate("STATIC-SUITE-RESULT", False, "; ".join(detail_parts))
        else:
            assert canonical_report is not None
            static_source_output_digest = command_output_digest(static_command_record)
            release_scopes = {
                entry["testOrPathScope"] for entry in self.baseline.get("releaseOnlySkips", [])
            }
            for observation_ordinal, result in enumerate(
                canonical_report["observations"]
            ):
                path_binding = canonical_observation_bindings[observation_ordinal]
                scope = f"result:{result['name']}"
                status = result.get("status")
                detail = result.get("detail")
                if scope in release_scopes and status == "pass" and nested_skip(detail):
                    outcome = "skip"
                else:
                    outcome = "pass" if status == "pass" else "fail"
                if outcome == "pass":
                    signature = "pass"
                    identity: Mapping[str, Any] = {"scope": scope, "normalizedSignature": "pass"}
                else:
                    identity = structured_failure_identity(
                        scope,
                        detail,
                        path_authority=path_binding,
                    )
                    signature = static_failure_signature(scope, detail, identity)
                raw = make_raw_observation(
                    "static-suite",
                    int(static_command_record["ordinal"]),
                    observation_ordinal,
                    "static-producer-v1",
                    str(result["name"]),
                    STATIC_SUITE_RELATIVE_PATH,
                    result,
                    static_source_output_digest,
                    failure_path_authority=path_binding,
                )
                self.add_observation(
                    observation(
                        "static-suite",
                        scope,
                        outcome,
                        signature,
                        "static-suite",
                        failure_identity=identity,
                        raw_observation=raw,
                        command_record=static_command_record,
                    )
                )
            self.completed_classes.add("static-suite")
            self.static_machine_report = canonical_report
        self.run_direct_syntax()

    def run_direct_syntax(self) -> None:
        paths = [
            path
            for path in self.ensure_candidate_paths()
            if Path(path).suffix.lower() in {".js", ".mjs"}
        ]
        self.require_tool("node", phase="EXECUTION")
        node_lease = self.require_tool_lease("node", phase="EXECUTION")
        if node_lease is not None:
            execution_failure = False
            def check_one(
                relative: str,
            ) -> tuple[str, CommandCapture, TargetExecutionLease | None]:
                plan_record = self.command_plan_by_id[f"node-check:{relative}"]
                capture, lease = execute_planned_node_check(
                    plan_record,
                    repo_root=REPO_ROOT,
                    env=self.child_environment,
                    timeout=30,
                    executable_lease=node_lease,
                )
                return relative, capture, lease

            worker_count = (
                1
                if sys.platform.startswith("linux")
                else min(16, max(2, os.cpu_count() or 2))
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                syntax_results = list(executor.map(check_one, paths))
            for relative, capture, lease in syntax_results:
                command_record = self.add_command(capture)
                if lease is not None:
                    self.target_execution_leases.append((lease, command_record))
                scope = relative
                if not _command_execution_completed(command_record):
                    execution_failure = True
                    outcome = "unavailable"
                    signature = "required-executable-unavailable:node"
                elif capture.exit_code == 0:
                    outcome = "pass"
                    signature = "pass"
                else:
                    outcome = "syntax-error"
                    signature = syntax_failure_signature(scope, capture.stderr, capture.stdout)
                identity = (
                    {"scope": scope, "normalizedSignature": "pass"}
                    if outcome == "pass"
                    else extract_failure_identity(scope, stdout=capture.stdout, stderr=capture.stderr)
                )
                raw = make_raw_observation(
                    capture.command_id,
                    int(command_record["ordinal"]),
                    0,
                    "process-output-v1",
                    scope,
                    relative,
                    {
                        "executed": capture.executed,
                        "exitCode": capture.exit_code,
                        "stdout": capture.stdout,
                        "stderr": capture.stderr,
                        "error": capture.error,
                    },
                    command_output_digest(command_record),
                )
                self.add_observation(
                    observation(
                        "direct-syntax",
                        scope,
                        outcome,
                        signature,
                        capture.command_id,
                        failure_identity=identity,
                        raw_observation=raw,
                        command_record=command_record,
                    )
                )
            self.completed_classes.add("direct-syntax")
            self.add_hard_gate(
                "DIRECT-JAVASCRIPT-SYNTAX-EXECUTION",
                not execution_failure,
                f"checked JavaScript files={len(paths)}",
            )

        python_paths = [path for path in self.ensure_candidate_paths() if Path(path).suffix.lower() == ".py"]

        def evaluate_python(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            python_failures: list[str] = []
            for relative in python_paths:
                try:
                    data = bundle.bytes_for(relative)
                    encoding, _lines = tokenize.detect_encoding(io.BytesIO(data).readline)
                    source = data.decode(encoding, errors="strict")
                    compile(source, relative, "exec", dont_inherit=True)
                except (LookupError, SyntaxError, UnicodeError, ValueError) as exc:
                    python_failures.append(f"{relative}: {type(exc).__name__}")
            return (
                not python_failures,
                f"checked={len(python_paths)} failures={len(python_failures)}",
                python_failures,
            )

        python_record, python_failures = self.execute_protected_internal(
            "python-source-syntax", evaluate_python
        )
        if not isinstance(python_failures, list):
            python_failures = ["protected Python syntax command did not return results"]
        python_passed = python_record.get("exitCode") == 0 and not python_failures
        self.add_hard_gate(
            "DIRECT-PYTHON-SYNTAX",
            python_passed,
            "Python sources compile" if python_passed else "; ".join(python_failures[:10]),
        )

    def run_frontend_profile(self) -> None:
        self.require_tool("node", phase="EXECUTION")
        bundle, _bundle_record = self.execute_protected_external(
            "bundle-normalization",
            timeout=300,
        )
        self.add_hard_gate(
            "BUNDLE-MANIFEST-GENERATED-BYTE-PARITY",
            bundle.execution_passed(),
            f"bundle-normalization exit={bundle.exit_code} processTree={bundle.process_tree_status}",
        )

        learner, learner_record = self.execute_protected_external(
            "learner-focused",
            timeout=300,
        )
        learner_scope = "command:learner-focused-runtime"
        if not learner.executed:
            learner_outcome = "unavailable"
            learner_signature = "required-executable-unavailable:node"
            self.add_hard_gate("FOCUSED-LEARNER-RUNTIME-EXECUTION", False, "learner command did not execute")
        elif learner.exit_code == 0:
            learner_outcome = "pass"
            learner_signature = "pass"
            self.add_hard_gate("FOCUSED-LEARNER-RUNTIME-EXECUTION", True, "learner command executed")
        else:
            learner_outcome = "unavailable" if "unavailable" in learner_failure_signature(learner.stdout + learner.stderr) else "fail"
            learner_signature = learner_failure_signature(learner.stdout + learner.stderr)
            self.add_hard_gate("FOCUSED-LEARNER-RUNTIME-EXECUTION", True, "learner command executed with a non-pass result")
        self.add_process_observation(
            learner_record,
            learner,
            source_result_id=learner_scope,
            source_path="developer/tests/js/learnerPalette.test.js",
        )
        self.completed_classes.add("learner-focused")

        for relative in SECURITY_GUARD_FILES:
            command_id = f"frontend-security:{Path(relative).name}"
            capture, command_record = self.execute_protected_external(
                command_id,
                timeout=180,
            )
            scope = f"file:{relative}"
            if not capture.executed:
                outcome = "unavailable"
                signature = "required-executable-unavailable:node"
                self.add_hard_gate("FRONTEND-SECURITY-GUARD-EXECUTION", False, f"did not execute: {relative}")
            elif capture.exit_code == 0:
                outcome = "pass"
                signature = "pass"
            else:
                outcome = "fail"
                signature = node_failure_signature(scope, capture.stdout + capture.stderr)
            self.add_process_observation(
                command_record,
                capture,
                source_result_id=scope,
                source_path=relative,
            )

        message_origin_command_id = "frontend-security:messageOriginGuard.test.js"
        message_origin_capture, message_origin_record = self.execute_protected_external(
            message_origin_command_id,
            timeout=180,
        )
        message_origin_scope = f"file:{MESSAGE_ORIGIN_SECURITY_GUARD}"
        if not message_origin_capture.executed:
            message_origin_outcome = "unavailable"
            message_origin_signature = "required-executable-unavailable:node"
            self.add_hard_gate(
                "FRONTEND-SECURITY-GUARD-EXECUTION",
                False,
                "canonical message-origin Node built-in test command did not execute",
            )
        elif message_origin_capture.exit_code == 0:
            message_origin_outcome = "pass"
            message_origin_signature = "pass"
        else:
            message_origin_outcome = "fail"
            message_origin_identity = extract_failure_identity(
                message_origin_scope,
                stdout=message_origin_capture.stdout,
                stderr=message_origin_capture.stderr,
            )
            message_origin_signature = failure_identity_hash(message_origin_identity)
        if message_origin_outcome == "pass":
            message_origin_identity = {
                "scope": message_origin_scope,
                "normalizedSignature": "pass",
            }
        elif not isinstance(locals().get("message_origin_identity"), dict):
            message_origin_identity = extract_failure_identity(
                message_origin_scope,
                stdout=message_origin_capture.stdout,
                stderr=message_origin_capture.stderr,
            )
        self.add_process_observation(
            message_origin_record,
            message_origin_capture,
            source_result_id=message_origin_scope,
            source_path=MESSAGE_ORIGIN_SECURITY_GUARD,
        )
        self.completed_classes.add("frontend-security")
        self.add_hard_gate(
            "FRONTEND-SECURITY-GUARD-EXECUTION",
            all(
                capture.executed and not capture.output_limited and not capture.timed_out
                for capture in self.captures
                if capture.command_class == "frontend-security"
            ),
            f"focused security guard files={len(SECURITY_GUARD_FILES) + 1}",
        )

    def run_backend_profile(self) -> None:
        scope = "command:npm --prefix backend test"
        capture, command_record = self.execute_protected_external(
            "backend-canonical",
            timeout=900,
        )
        if not capture.executed:
            outcome = "unavailable"
            signature = "required-executable-unavailable:npm"
            self.add_hard_gate("BACKEND-CANONICAL-EXECUTION", False, "backend canonical suite did not execute")
        elif capture.exit_code == 0:
            outcome = "pass"
            signature = "pass"
            self.add_hard_gate("BACKEND-CANONICAL-EXECUTION", True, "backend canonical suite executed")
        else:
            outcome = "fail"
            backend_identity = extract_failure_identity(scope, stdout=capture.stdout, stderr=capture.stderr)
            signature = failure_identity_hash(backend_identity)
            self.add_hard_gate("BACKEND-CANONICAL-EXECUTION", True, "backend canonical suite executed with a non-pass result")
        if outcome == "pass":
            backend_identity = {"scope": scope, "normalizedSignature": "pass"}
        elif outcome == "unavailable":
            backend_identity = {"scope": scope, "normalizedSignature": signature}
        self.add_process_observation(
            command_record,
            capture,
            source_result_id=scope,
            source_path="backend/package.json",
        )
        self.completed_classes.add("backend-canonical")

    def run_standalone_profile(self) -> None:
        environment = self.child_environment
        plan_record = self.command_plan_by_id["standalone-packaging"]
        capture, protected_bundle = execute_planned_static_suite(
            plan_record,
            repo_root=REPO_ROOT,
            env=environment,
            timeout=900,
            phase_hook=(
                (
                    lambda phase, bundle: self.target_phase_hook(
                        "standalone-packaging", phase, bundle
                    )
                )
                if self.target_phase_hook is not None
                else None
            ),
        )
        self.require_command_success(capture, "STANDALONE-PACKAGE-INTEGRITY")
        standalone_record = self.command_results[-1]
        standalone_record["executionInputs"] = copy.deepcopy(
            protected_bundle["executionInputs"]
        )
        standalone_record["executionInputBundleDigest"] = protected_bundle[
            "executionInputBundleDigest"
        ]
        standalone_record["protectedTargetBundle"] = protected_bundle

        scope = "membership:index.html::js/siteContent.js"
        def evaluate_membership(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            manifest = strict_json_loads(
                bundle.text_for("developer/standalone-release-manifest.json"),
                label="developer/standalone-release-manifest.json",
            )
            manifest_files = set(manifest["files"])
            index_source = bundle.text_for("index.html")
            script_sources = [
                match.group(1).strip().lstrip("./")
                for match in re.finditer(
                    r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>",
                    index_source,
                    re.IGNORECASE,
                )
                if not re.match(r"(?i)^(?:https?:)?//", match.group(1).strip())
            ]
            missing = sorted(path for path in script_sources if path not in manifest_files)
            return (
                not missing,
                f"indexScripts={len(script_sources)} missing={len(missing)}",
                (script_sources, missing),
            )

        membership_record, membership_payload = self.execute_protected_internal(
            "standalone-membership-audit", evaluate_membership
        )
        if isinstance(membership_payload, tuple) and len(membership_payload) == 2:
            script_sources, missing = membership_payload
            observation_ordinal = 0
            for relative in missing:
                raw = make_raw_observation(
                    "standalone-membership-audit",
                    int(membership_record["ordinal"]),
                    observation_ordinal,
                    "standalone-membership-v1",
                    f"membership:index.html::{relative}",
                    relative,
                    {"relative": relative, "missing": True},
                    command_output_digest(membership_record),
                )
                self.add_observation(
                    {
                        "commandId": "standalone-membership-audit",
                        "rawObservation": raw,
                    }
                )
                observation_ordinal += 1
            if "js/siteContent.js" not in missing:
                raw = make_raw_observation(
                    "standalone-membership-audit",
                    int(membership_record["ordinal"]),
                    observation_ordinal,
                    "standalone-membership-v1",
                    scope,
                    "js/siteContent.js",
                    {"relative": "js/siteContent.js", "missing": False},
                    command_output_digest(membership_record),
                )
                self.add_observation(
                    {
                        "commandId": "standalone-membership-audit",
                        "rawObservation": raw,
                    }
                )
            self.add_hard_gate(
                "STANDALONE-MEMBERSHIP-AUDIT-EXECUTION",
                membership_record.get("exitCode") in (0, 1),
                f"index scripts checked={len(script_sources)}",
            )
        else:
            self.add_hard_gate(
                "STANDALONE-MEMBERSHIP-AUDIT-EXECUTION",
                False,
                "protected standalone membership audit did not execute",
            )

    def run_lockfile_integrity(self) -> None:
        def evaluate(bundle: ProtectedTargetBundle) -> tuple[bool, str, Any]:
            failures: list[str] = []
            for relative, expected in LOCKED_FILE_SHA256.items():
                identity = self.locked_file_git_identities.get(relative)
                canonical = (
                    identity.get("canonicalBytes")
                    if isinstance(identity, Mapping)
                    else None
                )
                if (
                    not isinstance(canonical, bytes)
                    or identity.get("objectId")
                    != LOCKED_FILE_GIT_BLOB_OIDS[relative]
                    or identity.get("sha256") != expected
                    or not _locked_checkout_presentation_matches(
                        canonical, bundle.bytes_for(relative)
                    )
                ):
                    failures.append(relative)
            return (
                not failures,
                f"checked={len(LOCKED_FILE_SHA256)} failures={len(failures)}",
                failures,
            )

        record, failures = self.execute_protected_internal("lockfile-integrity", evaluate)
        if not isinstance(failures, list):
            failures = ["protected lockfile check did not return authoritative results"]
        passed = record.get("exitCode") == 0 and not failures
        self.add_hard_gate(
            "LOCKFILE-BYTE-INTEGRITY",
            passed,
            "locked package manifests match frozen byte identities"
            if passed
            else "; ".join(failures),
        )

    def verify_tool_authority(self, phase: str) -> list[str]:
        errors: list[str] = []
        for name, lease in getattr(self, "tool_leases", {}).items():
            okay, error = lease.verify()
            if not okay:
                errors.append(f"{name}: {error or 'trusted executable identity drifted'}")
                self.tool_authority_frozen = False
                self.tool_authority_failure = ToolAuthorityUnavailable(
                    name, "POST_EXECUTION"
                )
        self.add_hard_gate(
            f"TRUSTED-TOOL-AUTHORITY-{phase.upper()}",
            not errors,
            (
                f"captured tool identities unchanged after {phase}"
                if not errors
                else "; ".join(errors)
            ),
        )
        return errors

    def verify_trusted_integrity(self, phase: str) -> None:
        locked_identities: dict[str, dict[str, Any]] = {}
        identity_errors: list[str] = []
        try:
            locked_identities, identity_errors = capture_locked_file_git_identities(
                git=self.require_tool("git", phase=phase.upper()),
                environment=self.child_environment,
                repo_root=REPO_ROOT,
                executable_lease=self.tool_leases.get("git"),
            )
        except ToolAuthorityUnavailable as exc:
            identity_errors.append(str(exc))
        current, errors = snapshot_trusted_files(
            locked_identities=locked_identities
        )
        errors.extend(identity_errors)
        errors.extend(compare_trusted_snapshots(self.initial_trusted_snapshot, current))
        self.add_hard_gate(
            f"TRUSTED-FILE-INTEGRITY-{phase.upper()}",
            not errors,
            f"trusted files unchanged after {phase}" if not errors else "; ".join(errors),
        )
        self.verify_tool_authority(phase)
        if self.runtime_dependency_guard is not None:
            closure_errors = self.runtime_dependency_guard.verify(phase)
            self.add_hard_gate(
                f"RUNTIME-DEPENDENCY-CLOSURE-{phase.upper()}",
                not closure_errors,
                (
                    f"runtime/dependency closure unchanged after {phase}"
                    if not closure_errors
                    else "; ".join(closure_errors)
                ),
            )

    def close_execution_leases(self) -> None:
        for lease, record in self.target_execution_leases:
            okay, error = lease.verify()
            if not okay:
                record["exitCode"] = PROCESS_TREE_FAILURE_EXIT
                record["processTreeStatus"] = "cleanup-failed"
                record["processTreeError"] = error or "target execution source identity drifted"
                record["error"] = "TARGET-LEASE-ERROR: " + (
                    error or "target execution source identity drifted"
                )
                self.add_hard_gate(
                    "TARGET-EXECUTION-SOURCE-INTEGRITY",
                    False,
                    f"{record.get('commandId')}: {error or 'source identity drifted'}",
                )
            lease.close()
            closed_evidence = lease.evidence()
            record["targetExecutionLease"] = closed_evidence
            record["executionInputs"] = [
                {
                    "logicalPath": closed_evidence.get("logicalTargetPath"),
                    "canonicalSourcePath": closed_evidence.get("canonicalSourcePath"),
                    "plannedByteLength": closed_evidence.get("plannedByteLength"),
                    "plannedSha256": closed_evidence.get("plannedSha256"),
                    "plannedStableIdentity": closed_evidence.get("plannedStableFileIdentity"),
                    "actualByteLength": closed_evidence.get("executedInputByteLength"),
                    "actualSha256": closed_evidence.get("executedInputSha256"),
                    "inputMode": closed_evidence.get("executionAdapter"),
                }
            ]
            record["executionInputBundleDigest"] = execution_input_bundle_digest(
                record["executionInputs"]
            )
        self.target_execution_leases.clear()
        if getattr(self, "tool_leases", None):
            self.verify_tool_authority("post-execution")
            for name, lease in self.tool_leases.items():
                lease.close()
                if name in self.tool_authority_evidence:
                    self.tool_authority_evidence[name]["leaseHeld"] = False
            self.tool_leases.clear()
        if self.bash_lease is not None:
            self.bash_lease.close()
            self.bash_lease = None
        if self.runtime_dependency_guard is not None:
            closure_errors = self.runtime_dependency_guard.close()
            guard_evidence = self.runtime_dependency_guard.evidence()
            self.runtime_closure_guard_evidence = copy.deepcopy(guard_evidence)
            for record in self.command_results:
                if not record.get("dependencyBacked"):
                    continue
                record["closureWatcherActive"] = guard_evidence["activeDuringReplay"]
                record["closureMutationState"] = guard_evidence["mutationState"]
                record["runtimeClosureGuard"] = copy.deepcopy(guard_evidence)
                if closure_errors:
                    record["exitCode"] = PROCESS_TREE_FAILURE_EXIT
                    record["processTreeStatus"] = "cleanup-failed"
                    record["processTreeError"] = "; ".join(closure_errors)
                    record["error"] = "RUNTIME-CLOSURE-ERROR: " + record["processTreeError"]
            self.add_hard_gate(
                "RUNTIME-DEPENDENCY-CLOSURE-FINAL",
                not closure_errors,
                (
                    "runtime/dependency closure watcher closed cleanly"
                    if not closure_errors
                    else "; ".join(closure_errors)
                ),
            )
            self.runtime_dependency_guard = None
        if self.runtime_dependency_closure is not None:
            self.runtime_dependency_closure.close()
            self.runtime_dependency_closure = None
        # The verifier is the terminal workflow step, so every task-owned
        # temporary resource must be released inside this process.  Keeping
        # this cleanup here also makes legacy callers that explicitly close
        # leases satisfy the same lifecycle contract.
        handle = getattr(self, "private_temp_handle", None)
        if handle is not None:
            handle.cleanup()
            self.private_temp_handle = None

    def cleanup_task_resources(self) -> None:
        self.close_execution_leases()

    def run(self) -> dict[str, Any]:
        self.run_baseline_policy()
        self.run_runtime_policy(require_npm=self.profile in {"backend", "all"})
        self.verify_trusted_integrity("runtime")
        if self.profile in {"policy", "all"}:
            self.run_policy_profile()
            self.verify_trusted_integrity("policy")
        if self.profile in {"static", "all"}:
            self.run_static_profile()
            self.verify_trusted_integrity("static")
        if self.profile in {"frontend", "all"}:
            self.run_frontend_profile()
            self.verify_trusted_integrity("frontend")
        if self.profile in {"backend", "all"}:
            self.run_backend_profile()
            self.verify_trusted_integrity("backend")
        if self.profile in {"standalone", "all"}:
            self.run_standalone_profile()
            self.verify_trusted_integrity("standalone")
        self.run_lockfile_integrity()
        self.verify_trusted_integrity("lockfile-check")
        self.close_execution_leases()
        finalize_evidence_transcript(self)
        comparison = derive_authoritative_evidence(
            self.profile,
            self.observations,
            self.completed_classes,
            self.command_results,
            self.baseline,
            self.platform,
            self.command_plan,
            getattr(self, "authorization_context_binding_digest", None),
            release_gate_required=self.release_gate_required,
        )
        self.violations.extend(comparison["violations"])
        if self.profile in {"static", "all"}:
            prior_hard_failures = [
                item for item in self.hard_gate_results if item["status"] != "pass"
            ]
            static_result_passed = not comparison["violations"] and not prior_hard_failures
            self.add_hard_gate(
                "STATIC-SUITE-RESULT",
                static_result_passed,
                (
                    "all static observations were classified by frozen authority"
                    if static_result_passed
                    else "static observations include an unknown, expanded, hard, or policy failure"
                ),
            )
        return comparison


def validate_evidence_root_absent(
    output_dir: Path = OUTPUT_DIR,
    *,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    errors: list[str] = []
    try:
        repo_metadata = repo_root.lstat()
        repo_resolved = repo_root.resolve(strict=True)
    except OSError as exc:
        return [f"repository root cannot be resolved: {type(exc).__name__}"]
    if not stat.S_ISDIR(repo_metadata.st_mode) or stat.S_ISLNK(repo_metadata.st_mode) or _is_reparse_point(repo_metadata):
        errors.append("repository root must be a non-reparse directory")
    try:
        parent_resolved = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        errors.append(f"evidence parent cannot be resolved: {type(exc).__name__}")
    else:
        if parent_resolved != repo_resolved:
            errors.append("evidence root parent resolves outside the repository workspace")
    try:
        output_dir.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        errors.append(f"evidence root cannot be inspected: {type(exc).__name__}")
    else:
        errors.append(".ci-results must be absent before every runner invocation")
    return errors


def validate_evidence_root(
    output_dir: Path = OUTPUT_DIR,
    *,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    errors: list[str] = []
    try:
        metadata = output_dir.lstat()
    except OSError as exc:
        return [f"evidence root cannot be inspected: {type(exc).__name__}"]
    if not stat.S_ISDIR(metadata.st_mode):
        errors.append("evidence root is not a directory")
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        errors.append("evidence root is a symbolic link, junction, or reparse point")
    try:
        parent_resolved = output_dir.parent.resolve(strict=True)
        root_resolved = output_dir.resolve(strict=True)
        repo_resolved = repo_root.resolve(strict=True)
    except OSError as exc:
        errors.append(f"evidence root cannot be resolved: {type(exc).__name__}")
    else:
        if parent_resolved != repo_resolved:
            errors.append("evidence root parent resolves outside the repository workspace")
        if root_resolved.parent != repo_resolved or root_resolved.name != output_dir.name:
            errors.append("evidence root resolves outside its exact workspace path")
    return errors


def create_fresh_evidence_root(
    output_dir: Path = OUTPUT_DIR,
    *,
    repo_root: Path = REPO_ROOT,
) -> None:
    errors = validate_evidence_root_absent(output_dir, repo_root=repo_root)
    if errors:
        raise RuntimeError("; ".join(errors))
    os.mkdir(output_dir, 0o700)
    errors = validate_evidence_root(output_dir, repo_root=repo_root)
    if errors:
        raise RuntimeError("; ".join(errors))


def _exclusive_write(path: Path, data: bytes, *, repo_root: Path = REPO_ROOT) -> None:
    root_errors = validate_evidence_root(path.parent, repo_root=repo_root)
    if root_errors:
        raise RuntimeError("; ".join(root_errors))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"evidence file is not an exclusive single-link regular file: {path.name}")
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"evidence path changed type after write: {path.name}")
    if path.resolve(strict=True).parent != path.parent.resolve(strict=True):
        raise RuntimeError(f"evidence file parent escaped after write: {path.name}")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: Any, *, repo_root: Path = REPO_ROOT) -> None:
    _exclusive_write(path, _json_bytes(value), repo_root=repo_root)


_DIAGNOSTIC_COMMAND_IDS = frozenset({
    "baseline-schema", "node-version", "npm-version", "git-bash-version",
    "git-candidate-paths", "git-tracked-paths", "git-diff-check",
    "git-cached-diff-check", "git-stage-modes", "git-dir",
    "tracked-private-resource-scan", "tracked-secret-scan",
    "license-governance-consistency", "workflow-self-policy", "static-suite",
    "python-source-syntax", "bundle-normalization", "learner-focused",
    "backend-canonical", "standalone-packaging", "standalone-membership-audit",
    "lockfile-integrity", "command-results-size-limit",
})
_DIAGNOSTIC_DERIVED_VIOLATION_TYPES = frozenset({
    "MALFORMED-OBSERVATION", "UNKNOWN-NONPASS", "BASELINE-OCCURRENCE-LIMIT",
    "REQUIRED-COMMAND-UNAVAILABLE", "RELEASE-ONLY-SKIP-IN-REQUIRED-GATE",
    "BASELINE-SOURCE-COMMAND-SPLIT", "KNOWN-SCOPE-NOT-OBSERVED",
    "RESOLVED-CANDIDATE-SOURCE-INVALID", "REQUIRED-POLICY-SCOPE-NOT-OBSERVED",
    "COMMAND-RESULT-JSON-LIMIT", "COMMAND-AUTHORITY-MISMATCH",
    "DUPLICATE-COMMAND-ID", "EXECUTION-ARGV-MISMATCH",
    "EXECUTION-INPUT-MODE-MISMATCH", "EXECUTION-INPUT-IDENTITY-MISMATCH",
    "REQUIRED-COMMAND-EXECUTION", "COMMAND-EXIT-OUTSIDE-AUTHORITY",
    "REQUIRED-COMMAND-NONZERO", "NONZERO-COMMAND-WITHOUT-OBSERVATION",
    "MALFORMED-COMMAND-OBSERVATION", "MALFORMED-PRODUCER-OBSERVATION-SET",
    "PRODUCER-OBSERVATION-SET-DIGEST-MISMATCH", "MALFORMED-PRODUCER-OBSERVATION",
    "DUPLICATE-PRODUCER-OBSERVATION", "PRODUCER-OBSERVATION-ORDINAL-GAP",
    "UNAUTHORIZED-PRODUCER-OBSERVATION", "PRODUCER-OBSERVATION-COMPLETENESS",
    "MALFORMED-COMPLETED-COMMAND-CLASS",
    "RESOLVED-CANDIDATE-WITHOUT-SUCCESSFUL-SCOPE",
})
_DIAGNOSTIC_AUTHORITY_FIELDS = frozenset({
    "commandId", "ordinal", "commandClass", "commandRole", "required",
    "profile", "platform", "argv", "logicalArgv", "executionArgv",
    "executionInputMode", "executionInputSize", "executionInputSha256", "cwd",
    "toolRole", "resolvedExecutablePath", "resolvedExecutableSize",
    "resolvedExecutableSha256", "resolvedExecutableFileIdentity", "executionLease",
    "targets", "resultSemantics", "allowedExecutionExits",
})
_MAX_DIAGNOSTIC_AUTHORITY_FIELDS = 4


# Diagnostic values mirror the immutable build_profile_command_plan registry.
# Only classes registered by trusted runner code can appear in output.
_REPLAY_DIAGNOSTIC_COMMAND_CLASSES = frozenset({
    "baseline-policy", "runtime-identity", "repository-boundary",
    "private-resource-exclusion", "secret-operational-artifact-exclusion",
    "license-governance", "workflow-policy", "static-suite", "direct-syntax",
    "bundle-parity", "learner-focused", "frontend-security", "backend-canonical",
    "standalone-packaging", "standalone-membership", "lockfile-integrity",
    "evidence-size-limit",
})
_REPLAY_DIAGNOSTIC_COMMAND_FAMILIES = frozenset({
    "node-check", "frontend-security", "fixed-command", "other",
})
_REPLAY_DIAGNOSTIC_TARGET_INPUT_FIELDS = {
    "targets": frozenset({"targets"}),
    "executionInputs": frozenset({"executionInputs"}),
    "actualExecutionInputIdentity": frozenset({
        "actualExecutionInputMode", "actualExecutionInputSize", "actualExecutionInputSha256",
    }),
    "targetExecutionLease": frozenset({"targetExecutionLease"}),
    "protectedTargetBundle": frozenset({"protectedTargetBundle"}),
    "executionInputBundleDigest": frozenset({"executionInputBundleDigest"}),
    "other": frozenset({
        "executionLease", "invalidGitBashLeaseLocalEvidence", "executionInputMode",
        "executionInputSize", "executionInputSha256", "fileScans",
    }),
}


def _replay_producer_observation_context_categories(
    producer: Mapping[str, Any], replay: Mapping[str, Any],
    *, producer_source: Mapping[str, Any] | None = None,
    replay_source: Mapping[str, Any] | None = None,
) -> list[str]:
    """Describe context differences without inferring unproved source causality.

    Inputs are canonical command records. Optional original records only supply
    digest preimages after their canonical context is checked against the input.
    This diagnostic neither validates nor changes replay authority. A changed
    self-checking digest is downstream only when it recomputes from both records;
    changed raw facts remain ``other`` and are diagnosed separately in the
    validated machine report. This list alone never proves source-only change.
    """

    profile_fields = frozenset({
        "producerObservationUniverseDigest", "producerTranscriptDigest",
        "profileCompletedCommandClassSetDigest", "authorizationContextBindingDigest",
    })
    failure_fields = frozenset({
        "failureIdentity", "failureIdentityHash", "derivedFailureMembers",
        "canonicalFailureMaterialVersion", "legacyBaselineComparisonDigest",
        "signature",
    })
    # extract_failure_identity supplies these direct parsedFailureSummary keys;
    # make_internal_result instead supplies status/diagnostic. Status already
    # belongs to execution-status; diagnostic and unknown members remain other.
    summary_failure_fields = failure_fields | frozenset({
        "scope", "testIds", "fileLocations", "assertionNames", "expectedValues",
        "observedValues", "errorClasses", "errorMessages", "structuredFailureSet",
        "pathAuthority",
    })
    categories: set[str] = set()

    def member_equal(left: Mapping[str, Any], right: Mapping[str, Any], key: str) -> bool:
        try:
            return _canonical_frame({"present": key in left, "value": left.get(key)}) == _canonical_frame({
                "present": key in right, "value": right.get(key),
            })
        except (TypeError, ValueError, UnicodeError):
            return False

    def record_digest_valid(record: Mapping[str, Any]) -> bool:
        try:
            return record.get("producerRecordDigest") == _producer_record_digest({
                key: value for key, value in record.items() if key != "producerRecordDigest"
            })
        except (TypeError, ValueError, UnicodeError):
            return False

    for key in profile_fields | failure_fields:
        if not member_equal(producer, replay, key):
            categories.add("profileContext" if key in profile_fields else "failureIdentity")
    if not member_equal(producer, replay, "diagnosticPreview"):
        categories.add("other")
    if not member_equal(producer, replay, "parsedFailureSummary"):
        left_summary = producer.get("parsedFailureSummary")
        right_summary = replay.get("parsedFailureSummary")
        if isinstance(left_summary, Mapping) and isinstance(right_summary, Mapping):
            for key in left_summary.keys() | right_summary.keys():
                if key == "status" or member_equal(left_summary, right_summary, key):
                    continue
                categories.add(
                    "profileContext" if key in profile_fields
                    else "failureIdentity" if key in summary_failure_fields
                    else "other"
                )
        else:
            categories.add("other")

    observations_changed = not member_equal(producer, replay, "producerObservations")
    set_digest_changed = not member_equal(producer, replay, "producerObservationSetDigest")
    if set_digest_changed:
        categories.add("producerObservationSetDigest")
    digest_observations: list[list[Any] | None] = [None, None]
    if observations_changed or set_digest_changed:
        for side, (command, original) in enumerate((
            (producer, producer_source), (replay, replay_source),
        )):
            digest_command: Mapping[str, Any] | None = command
            if original is not None:
                # Raw constructor normalization is component-boundary-aware;
                # replay substitution can still alter embedded root literals.
                # Check correspondence before using the original digest bytes.
                context_keys = (
                    "commandId", "commandClass", "ordinal",
                    "producerObservations", "producerObservationSetDigest",
                )
                if isinstance(original, Mapping) and isinstance(original.get("producerObservations"), list):
                    original_context = _canonical_replay_value({
                        key: original[key] for key in context_keys if key in original
                    })
                    if all(member_equal(command, original_context, key) for key in context_keys):
                        digest_command = original
                    else:
                        digest_command = None
                else:
                    digest_command = None
            observations = (
                digest_command.get("producerObservations")
                if digest_command is not None else None
            )
            try:
                valid_set_digest = (
                    isinstance(observations, list)
                    and len(observations) <= MAX_EVIDENCE_COLLECTION_ITEMS
                    and digest_command is not None
                    and digest_command.get("producerObservationSetDigest") == producer_observation_set_digest(observations)
                )
            except (TypeError, ValueError, UnicodeError):
                valid_set_digest = False
            if not valid_set_digest:
                categories.add("other")
            if isinstance(observations, list):
                digest_observations[side] = observations
    if observations_changed:
        left_observations = producer.get("producerObservations")
        right_observations = replay.get("producerObservations")
        if (
            not isinstance(left_observations, list)
            or not isinstance(right_observations, list)
            or max(len(left_observations), len(right_observations)) > MAX_EVIDENCE_COLLECTION_ITEMS
        ):
            categories.add("other")
        else:
            if len(left_observations) != len(right_observations):
                categories.add("other")
            for index, (left_raw, right_raw) in enumerate(zip(left_observations, right_observations)):
                if not isinstance(left_raw, Mapping) or not isinstance(right_raw, Mapping):
                    categories.add("other")
                    continue
                changed = {
                    key for key in left_raw.keys() | right_raw.keys()
                    if not member_equal(left_raw, right_raw, key)
                }
                if not changed:
                    continue
                if "sourceOutputDigest" in changed:
                    categories.add("sourceOutputDigest")
                if changed - {"sourceOutputDigest", "producerRecordDigest"}:
                    categories.add("other")
                for originals in digest_observations:
                    if (
                        originals is None or index >= len(originals)
                        or not isinstance(originals[index], Mapping)
                        or not record_digest_valid(originals[index])
                    ):
                        categories.add("other")
    return sorted(categories)


_REPLAY_DIAGNOSTIC_FIELD_CATEGORIES = {
    "executionDurationClass": frozenset({"executionDurationClass"}),
    "stdout-identity": frozenset({
        "stdoutSha256", "stdoutBytesObserved", "stdoutByteLimit",
        "validatedStaticMachineReport", "invalidStaticMachineLocalEvidence",
        "directNodeTestRawStreams",
    }),
    "stderr-identity": frozenset({
        "stderrSha256", "stderrBytesObserved", "stderrByteLimit",
    }),
    "execution-status": frozenset({
        "executed", "started", "setupFailure", "exitCode", "timeoutStatus",
        "outputLimitStatus", "completedCommandClass", "error", "limitReason",
    }),
    "process-containment": frozenset({
        "containment", "processTreeStatus", "processTreeError",
        "descendantsTerminated", "descendantsObserved", "descendantsReaped",
        "descendantsSurviving", "containmentDisposition",
    }),
    "target-input-authority": frozenset({
        "targets", "executionInputs", "executionLease", "targetExecutionLease",
        "invalidGitBashLeaseLocalEvidence",
        "executionInputMode", "executionInputSize", "executionInputSha256",
        "actualExecutionInputMode", "actualExecutionInputSize",
        "actualExecutionInputSha256", "fileScans",
    }),
    "executionInputBundleDigest": frozenset({"executionInputBundleDigest"}),
    "runtime-closure": frozenset({
        "dependencyBacked", "runtimeClosureDigest", "dependencyClosureDigest",
        "nodePath", "resolvedTestRunnerEntrypoint", "resolvedTestRunnerSha256",
        "closureWatcherActive", "closureMutationState", "runtimeClosureGuard",
        "toolRole", "resolvedExecutablePath", "resolvedExecutableSize",
        "resolvedExecutableSha256", "resolvedExecutableFileIdentity",
    }),
    "producer-observation-context": frozenset({
        "producerObservations", "producerObservationSetDigest", "diagnosticPreview",
        "semanticSourceOutputDigest",
    }),
    "command-membership": frozenset({"commandId", "ordinal"}),
}
_REPLAY_DIAGNOSTIC_NESTED_CATEGORIES = {
    "parsedFailureSummary": (
        "producer-observation-context", {"status": "execution-status"},
    ),
    "protectedTargetBundle": (
        "target-input-authority", {
            "executionInputBundleDigest": "protectedTargetBundle.executionInputBundleDigest",
            "cleanupState": "process-containment",
            "mutationDetected": "process-containment",
        },
    ),
}
_REPLAY_DIAGNOSTIC_CATEGORIES = frozenset({
    *_REPLAY_DIAGNOSTIC_FIELD_CATEGORIES,
    "protectedTargetBundle.executionInputBundleDigest",
    "other-authorized-fixed-category",
})
_REPLAY_DIAGNOSTIC_HARD_GATE_IDS = frozenset({
    *HARD_GATE_AUTHORITY,
    "DIRECT-JAVASCRIPT-SYNTAX-EXECUTION", "DIRECT-PYTHON-SYNTAX",
    "GIT-BASH-TRUSTED-RUNTIME", "IMMUTABLE-COMMAND-AUTHORITY",
    "NODE-CI-FAMILY", "NPM-REQUIRED", "PYTHON-CI-FAMILY",
    "RUNTIME-DEPENDENCY-CLOSURE", "RUNTIME-DEPENDENCY-CLOSURE-FINAL",
    "RUNTIME-DEPENDENCY-CLOSURE-SETUP", "STATIC-SUITE-EXECUTION",
    "STATIC-SUITE-RESULT", "TARGET-EXECUTION-SOURCE-INTEGRITY",
    "TRUSTED-EXECUTABLE-RESOLUTION", "TRUSTED-FILE-MANIFEST",
    *(
        f"{prefix}-{phase}"
        for prefix in (
            "TRUSTED-TOOL-AUTHORITY", "TRUSTED-FILE-INTEGRITY",
            "RUNTIME-DEPENDENCY-CLOSURE",
        )
        for phase in (
            "RUNTIME", "POLICY", "STATIC", "FRONTEND", "BACKEND",
            "STANDALONE", "LOCKFILE-CHECK", "POST-EXECUTION",
        )
    ),
})
_REPLAY_DIAGNOSTIC_VIOLATION_IDS = frozenset({
    *_REPLAY_DIAGNOSTIC_HARD_GATE_IDS, *_DIAGNOSTIC_DERIVED_VIOLATION_TYPES,
    "CI-RUNNER-ERROR", "RUNTIME-CLOSURE-PRECONDITION",
})
_MAX_REPLAY_FAILURE_DIAGNOSTICS = 8
_MAX_REPLAY_TRANSCRIPT_DIAGNOSTICS = 8


def _replay_changed_field_categories(
    producer: Mapping[str, Any], replay: Mapping[str, Any],
) -> list[str]:
    """Classify differences with fixed vocabulary, never record keys or values."""

    categories: set[str] = set()
    missing = object()
    for key in producer.keys() | replay.keys():
        left, right = producer.get(key, missing), replay.get(key, missing)
        if left == right:
            continue
        if key in _REPLAY_DIAGNOSTIC_NESTED_CATEGORIES:
            fallback, nested = _REPLAY_DIAGNOSTIC_NESTED_CATEGORIES[key]
            if isinstance(left, Mapping) and isinstance(right, Mapping):
                for child in left.keys() | right.keys():
                    if left.get(child, missing) != right.get(child, missing):
                        categories.add(nested.get(child, fallback))
            else:
                categories.add(fallback)
        else:
            categories.add(next(
                (category for category, fields in _REPLAY_DIAGNOSTIC_FIELD_CATEGORIES.items()
                 if key in fields),
                "other-authorized-fixed-category",
            ))
    return sorted(categories & _REPLAY_DIAGNOSTIC_CATEGORIES)


def _replay_diagnostic_command_identity(
    record: Mapping[str, Any], *, source_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe the command with fixed labels and its exact UTF-8 identity digest."""

    command_id = record.get("commandId")
    digest_command_id = command_id
    if isinstance(source_record, Mapping) and isinstance(source_record.get("commandId"), str):
        try:
            # Replay may replace root spellings embedded in dynamic IDs. Use
            # exact original UTF-8 bytes only after full canonical correspondence;
            # this must not let a different source record relabel the diagnostic.
            if _json_bytes(_canonical_transcript_record(source_record)) == _json_bytes(dict(record)):
                digest_command_id = source_record["commandId"]
        except (KeyError, TypeError, ValueError, UnicodeError, OSError):
            pass
    command_class = record.get("commandClass")
    ordinal = record.get("ordinal")
    family = "other"
    if isinstance(command_id, str):
        if command_id in _DIAGNOSTIC_COMMAND_IDS:
            family = "fixed-command"
        elif re.fullmatch(r"node-check:[^\x00-\x1f\x7f]+\.(?i:js|mjs)", command_id):
            family = "node-check"
        elif re.fullmatch(r"frontend-security:[^/\\\x00-\x1f\x7f]+\.js", command_id):
            family = "frontend-security"
    return {
        "commandId": command_id if isinstance(command_id, str) and command_id in _DIAGNOSTIC_COMMAND_IDS else "OTHER",
        "ordinal": ordinal if type(ordinal) is int and 0 <= ordinal < MAX_PROFILE_COMMANDS else None,
        "commandClass": (
            command_class if isinstance(command_class, str)
            and command_class in _REPLAY_DIAGNOSTIC_COMMAND_CLASSES else None
        ),
        "commandFamily": family,
        "commandIdDigest": (
            "sha256:" + hashlib.sha256(digest_command_id.encode("utf-8")).hexdigest()
            if isinstance(digest_command_id, str) else None
        ),
    }


def _replay_target_input_difference_subcategories(
    producer: Mapping[str, Any], replay: Mapping[str, Any],
) -> list[str]:
    """Name only differing fixed target/input categories, without their contents."""

    missing = object()
    categories: set[str] = set()
    for category, fields in _REPLAY_DIAGNOSTIC_TARGET_INPUT_FIELDS.items():
        for field in fields:
            if producer.get(field, missing) == replay.get(field, missing):
                continue
            if field == "protectedTargetBundle" and not (
                set(_replay_changed_field_categories(
                    {field: producer[field]} if field in producer else {},
                    {field: replay[field]} if field in replay else {},
                )) & {"target-input-authority", "protectedTargetBundle.executionInputBundleDigest"}
            ):
                continue
            categories.add(category)
    return sorted(categories)


def replay_transcript_difference_diagnostics(
    producer_records: Sequence[Mapping[str, Any]],
    replay_records: Sequence[Mapping[str, Any]],
    *,
    producer_source_records: Sequence[Mapping[str, Any]] | None = None,
    replay_source_records: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Describe at most eight unequal canonical records; never authorize replay."""

    diagnostics: list[dict[str, Any]] = []
    for index in range(max(len(producer_records), len(replay_records))):
        producer = producer_records[index] if index < len(producer_records) else None
        replay = replay_records[index] if index < len(replay_records) else None
        if producer == replay:
            continue
        identity_record = replay if replay is not None else producer
        identity_sources = replay_source_records if replay is not None else producer_source_records
        identity_source = (
            identity_sources[index]
            if identity_sources is not None and index < len(identity_sources) else None
        )
        diagnostic = {
            **_replay_diagnostic_command_identity(identity_record, source_record=identity_source),
            "changedFieldCategories": (
                ["command-membership"] if producer is None or replay is None
                else _replay_changed_field_categories(producer, replay)
            ),
            "producerRecordDigest": canonical_failure_digest(producer),
            "replayRecordDigest": canonical_failure_digest(replay),
        }
        if producer is not None and replay is not None:
            target_categories = _replay_target_input_difference_subcategories(producer, replay)
            if target_categories:
                diagnostic["targetInputSubcategories"] = target_categories
            diagnostic.update(_replay_static_machine_difference_diagnostic(
                producer, replay,
                producer_source=(
                    producer_source_records[index]
                    if producer_source_records is not None and index < len(producer_source_records)
                    else None
                ),
                replay_source=(
                    replay_source_records[index]
                    if replay_source_records is not None and index < len(replay_source_records)
                    else None
                ),
            ))
        diagnostics.append(diagnostic)
        if len(diagnostics) == _MAX_REPLAY_TRANSCRIPT_DIAGNOSTICS:
            break
    return diagnostics


def first_replay_transcript_difference_diagnostic(
    producer_records: Sequence[Mapping[str, Any]],
    replay_records: Sequence[Mapping[str, Any]],
    *,
    producer_source_records: Sequence[Mapping[str, Any]] | None = None,
    replay_source_records: Sequence[Mapping[str, Any]] | None = None,
) -> str | None:
    """Retain the single-record diagnostic interface for existing consumers."""

    diagnostics = replay_transcript_difference_diagnostics(
        producer_records, replay_records,
        producer_source_records=producer_source_records,
        replay_source_records=replay_source_records,
    )
    return json.dumps(diagnostics[0], sort_keys=True, separators=(",", ":")) if diagnostics else None


_STATIC_REPORT_DIAGNOSTIC_FIELDS = {
    "documentKind": "document/schema",
    "schemaVersion": "document/schema",
    "invocationId": "invocation",
    "executionStatus": "execution-status",
    "internalRunnerFailures": "execution-status",
    "commandPlanDigest": "command-plan",
    "commandResults": "command-results",
    "observations": "observations",
    "nativeNonPassCount": "summary/counts",
}
_STATIC_OBSERVATION_DIAGNOSTIC_FIELDS = {
    "name": "identity", "status": "status", "detail": "detail",
}


def _replay_static_changed_categories(
    producer: Mapping[str, Any], replay: Mapping[str, Any],
    field_categories: Mapping[str, str],
) -> list[str]:
    """Compare JSON types and presence exactly; emit only fixed categories."""

    return sorted({
        field_categories.get(key, "other")
        for key in producer.keys() | replay.keys()
        if (key not in producer or key not in replay
            or canonical_failure_digest(producer[key]) != canonical_failure_digest(replay[key]))
    })


def _replay_validated_static_report(
    canonical: Mapping[str, Any], source: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Recheck original local authority before inspecting its existing projection."""

    if not isinstance(source, Mapping) or source.get("commandId") != "static-suite":
        return None
    try:
        if _validated_portable_protected_input_bundle_digest(source) is None:
            return None
        identity = _validated_static_machine_output_identity(source)
        if identity is None:
            return None
        report = identity["validatedStaticMachineReport"]
        if (
            canonical.get("invalidStaticMachineLocalEvidence") is True
            or canonical.get("invalidProtectedBundleLocalEvidence") is True
            or canonical_failure_digest(canonical.get("validatedStaticMachineReport"))
            != canonical_failure_digest(report)
        ):
            return None
    except (KeyError, TypeError, ValueError, UnicodeError):
        return None
    return report


def _replay_static_machine_difference_diagnostic(
    producer: Mapping[str, Any], replay: Mapping[str, Any],
    *, producer_source: Mapping[str, Any] | None = None,
    replay_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe validated static facts without changing comparison or authority."""

    if producer.get("commandId") != "static-suite" or replay.get("commandId") != "static-suite":
        return {}
    diagnostic: dict[str, Any] = {}
    context_categories = _replay_producer_observation_context_categories(
        producer, replay, producer_source=producer_source, replay_source=replay_source,
    )
    if context_categories:
        diagnostic["producerObservationContextCategories"] = context_categories
    if not any("validatedStaticMachineReport" in record for record in (producer, replay)):
        return diagnostic
    left = _replay_validated_static_report(producer, producer_source)
    right = _replay_validated_static_report(replay, replay_source)
    if left is None or right is None:
        diagnostic["staticMachineReport"] = {
            "validationStatus": (
                "both-unavailable" if left is None and right is None
                else "producer-unavailable" if left is None else "replay-unavailable"
            ),
            "changedCategories": ["other"],
        }
        return diagnostic
    report_diagnostic: dict[str, Any] = {
        "validationStatus": "both-validated",
        "changedCategories": _replay_static_changed_categories(
            left, right, _STATIC_REPORT_DIAGNOSTIC_FIELDS,
        ),
    }
    diagnostic["staticMachineReport"] = report_diagnostic
    if "observations" not in report_diagnostic["changedCategories"]:
        return diagnostic
    left_observations, right_observations = left["observations"], right["observations"]
    # Existing report validation bounds each list to 10,000 entries. Keep the
    # diagnostic ordinal independently bounded and include only its first change.
    for index in range(min(10_000, max(len(left_observations), len(right_observations)))):
        left_item = left_observations[index] if index < len(left_observations) else None
        right_item = right_observations[index] if index < len(right_observations) else None
        if canonical_failure_digest(left_item) == canonical_failure_digest(right_item):
            continue
        report_diagnostic["firstObservationDifference"] = {
            "ordinal": index,
            "producerObservationIdentityDigest": (
                "sha256:" + hashlib.sha256(left_item["name"].encode("utf-8")).hexdigest()
                if left_item is not None else None
            ),
            "replayObservationIdentityDigest": (
                "sha256:" + hashlib.sha256(right_item["name"].encode("utf-8")).hexdigest()
                if right_item is not None else None
            ),
            "changedSemanticCategories": (
                ["membership"] if left_item is None or right_item is None
                else _replay_static_changed_categories(
                    left_item, right_item, _STATIC_OBSERVATION_DIAGNOSTIC_FIELDS,
                )
            ),
            "producerObservationDigest": canonical_failure_digest(left_item),
            "replayObservationDigest": canonical_failure_digest(right_item),
        }
        break
    return diagnostic


def replay_failure_diagnostics(
    hard_failures: Sequence[Mapping[str, Any]],
    violations: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Bound rejection details to eight identities per kind and canonical digests."""

    diagnostics: list[str] = []
    for records, id_key, allowed_ids, prefix in (
        (hard_failures, "hardGateId", _REPLAY_DIAGNOSTIC_HARD_GATE_IDS,
         "verification replay failed hard gate: "),
        (violations, "violationId", _REPLAY_DIAGNOSTIC_VIOLATION_IDS,
         "verification replay violation: "),
    ):
        for record in records[:_MAX_REPLAY_FAILURE_DIAGNOSTICS]:
            record_id = record.get("id")
            diagnostic = {
                id_key: (record_id if isinstance(record_id, str) and record_id in allowed_ids
                         else "OTHER"),
                "diagnosticDigest": canonical_failure_digest(record),
            }
            command_id = record.get("commandId")
            if (id_key == "violationId" and isinstance(command_id, str)
                    and command_id in _DIAGNOSTIC_COMMAND_IDS):
                diagnostic["commandId"] = command_id
            diagnostics.append(prefix + json.dumps(
                diagnostic, sort_keys=True, separators=(",", ":"),
            ))
    return diagnostics


def _first_authority_mismatch_diagnostic(
    command_records: Sequence[Mapping[str, Any]],
    expected_authority: Sequence[Mapping[str, Any]],
    *,
    cross_job: bool = False,
) -> tuple[Any, list[str]]:
    """Locate the first unequal authority projection; return no raw values."""

    if expected_authority and not isinstance(expected_authority[0], Mapping):
        return None, ["OTHER"]
    authority_fields = set(expected_authority[0]) if expected_authority else set()
    for index in range(max(len(command_records), len(expected_authority))):
        expected = expected_authority[index] if index < len(expected_authority) else {}
        observed = command_records[index] if index < len(command_records) else {}
        if not isinstance(expected, Mapping) or not isinstance(observed, Mapping):
            return None, ["OTHER"]
        command_id = expected.get("commandId", observed.get("commandId"))
        if index >= len(command_records) or index >= len(expected_authority):
            return command_id, ["command-membership"]
        actual = {key: observed.get(key) for key in authority_fields}
        if cross_job:
            actual = _portable_command_plan_value([actual])[0]
            expected = _portable_command_plan_value([expected])[0]
        if actual == expected:
            continue
        categories: set[str] = set()
        for key in set(actual) | set(expected):
            if key in actual and key in expected and actual[key] == expected[key]:
                continue
            category = key if key in _DIAGNOSTIC_AUTHORITY_FIELDS else "OTHER"
            if key == "targets":
                left, right = actual.get(key), expected.get(key)
                if (
                    isinstance(left, list) and isinstance(right, list)
                    and len(left) == len(right)
                    and all(isinstance(item, Mapping) for item in [*left, *right])
                    and [dict(item, fileIdentity=None) for item in left]
                    == [dict(item, fileIdentity=None) for item in right]
                ):
                    category = "targets.fileIdentity"
            categories.add(category)
        fields = sorted(categories)
        if len(fields) > _MAX_DIAGNOSTIC_AUTHORITY_FIELDS:
            fields = fields[:_MAX_DIAGNOSTIC_AUTHORITY_FIELDS - 1] + ["additional-fields"]
        return command_id, fields or ["OTHER"]
    return None, ["OTHER"]


def missing_derived_violation_diagnostic(
    violation: Mapping[str, Any],
    *,
    command_records: Sequence[Mapping[str, Any]] | None = None,
    expected_authority: Sequence[Mapping[str, Any]] | None = None,
    cross_job: bool = False,
) -> str:
    """Identify a rejected claim without rendering producer-controlled content.

    The digest uses the exact canonical JSON used by the membership check.
    Command IDs with candidate-controlled suffixes (including paths) are hashed;
    only fixed, path-free vocabulary is rendered verbatim. This projection is
    diagnostic only and is never used to compare or authorize evidence.
    """

    canonical = json.dumps(
        violation, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    command_id = violation.get("commandId")
    mismatch_fields: list[str] | None = None
    if (
        violation.get("id") == "COMMAND-AUTHORITY-MISMATCH"
        and command_records is not None and expected_authority is not None
    ):
        command_id, mismatch_fields = _first_authority_mismatch_diagnostic(
            command_records, expected_authority, cross_job=cross_job
        )
    if isinstance(command_id, str) and command_id not in _DIAGNOSTIC_COMMAND_IDS:
        command_id = "sha256:" + hashlib.sha256(
            command_id.encode("utf-8", errors="surrogatepass")
        ).hexdigest()
    elif not isinstance(command_id, str):
        command_id = None
    violation_type = violation.get("id")
    if (
        not isinstance(violation_type, str)
        or violation_type not in _DIAGNOSTIC_DERIVED_VIOLATION_TYPES
    ):
        violation_type = "OTHER"
    return json.dumps(
        {
            "commandId": command_id,
            "violationType": violation_type,
            "violationDigest": "sha256:" + hashlib.sha256(
                canonical.encode("utf-8", errors="surrogatepass")
            ).hexdigest(),
            **({"authorityFields": mismatch_fields} if mismatch_fields is not None else {}),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_evidence_file_set(
    output_dir: Path = OUTPUT_DIR,
    *,
    repo_root: Path = REPO_ROOT,
    expected_command_plan: Sequence[Mapping[str, Any]] | None = None,
    expected_context: ExternallyExpectedVerificationContext | None = None,
) -> list[str]:
    errors = validate_evidence_root(output_dir, repo_root=repo_root)
    if errors:
        return errors
    try:
        entries = list(os.scandir(output_dir))
    except OSError as exc:
        return [f"evidence directory cannot be enumerated: {type(exc).__name__}"]
    names = {entry.name for entry in entries}
    expected = set(EVIDENCE_FILE_NAMES)
    if names != expected:
        errors.append(
            f"evidence file set is not exact; missing={sorted(expected - names)} additional={sorted(names - expected)}"
        )
        return sorted(set(errors))

    snapshots: dict[str, _FileSnapshot] = {}
    for name in EVIDENCE_FILE_NAMES:
        snapshot, snapshot_errors = _read_evidence_file_snapshot(
            output_dir / name,
            output_dir=output_dir,
            byte_limit=EVIDENCE_FILE_BYTE_LIMITS[name],
        )
        errors.extend(f"{name}: {error}" for error in snapshot_errors)
        if snapshot is not None:
            snapshots[name] = snapshot
    if errors:
        return sorted(set(errors))

    documents: dict[str, dict[str, Any]] = {}
    for name in ("summary.json", "observed-debt.json", "resolved-candidates.json", "command-results.json"):
        document, document_errors = _decode_evidence_json(name, snapshots[name].data)
        errors.extend(document_errors)
        if document is not None:
            documents[name] = document
    if errors:
        return sorted(set(errors))
    errors.extend(
        _validate_evidence_semantics(
            documents,
            snapshots,
            expected_command_plan=expected_command_plan,
            expected_context=expected_context,
        )
    )

    try:
        final_entries = list(os.scandir(output_dir))
    except OSError as exc:
        errors.append(f"evidence directory cannot be re-enumerated: {type(exc).__name__}")
    else:
        final_names = {entry.name for entry in final_entries}
        if final_names != expected:
            errors.append("evidence file membership changed during verification")
        for name, snapshot in snapshots.items():
            try:
                metadata = (output_dir / name).lstat()
            except OSError as exc:
                errors.append(f"{name}: changed after validation ({type(exc).__name__})")
                continue
            if _stat_identity(metadata) != snapshot.identity:
                errors.append(f"{name}: changed after validation")
    return sorted(set(errors))


def _read_evidence_file_snapshot(
    path: Path,
    *,
    output_dir: Path,
    byte_limit: int,
) -> tuple[_FileSnapshot | None, list[str]]:
    errors: list[str] = []
    try:
        before = path.lstat()
    except OSError as exc:
        return None, [f"cannot inspect ({type(exc).__name__})"]
    if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before) or not stat.S_ISREG(before.st_mode):
        return None, ["evidence entry is not a non-reparse regular file"]
    acceptable_link_counts = {0, 1} if os.name == "nt" else {1}
    if before.st_nlink not in acceptable_link_counts:
        errors.append("evidence link count is not acceptable")
    if before.st_size <= 0 or before.st_size > byte_limit:
        errors.append("evidence byte length is outside the fixed bound")
    try:
        if path.resolve(strict=True).parent != output_dir.resolve(strict=True):
            errors.append("evidence parent resolution escaped")
    except OSError as exc:
        errors.append(f"cannot resolve ({type(exc).__name__})")
    if errors:
        return None, errors

    descriptor = -1
    data = b""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
        )
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            errors.append("changed between lstat and open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, byte_limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > byte_limit:
                errors.append("exceeded the fixed read bound")
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    except OSError as exc:
        errors.append(f"cannot read safely ({type(exc).__name__})")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        errors.append(f"changed during read ({type(exc).__name__})")
    else:
        if _stat_identity(after) != _stat_identity(before):
            errors.append("changed during read")
    if len(data) != before.st_size:
        errors.append("read length does not match the inspected byte length")
    if errors:
        return None, errors
    return _FileSnapshot(data=data, identity=_stat_identity(before)), []


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _decode_evidence_json(name: str, data: bytes) -> tuple[dict[str, Any] | None, list[str]]:
    if data.startswith(b"\xef\xbb\xbf"):
        return None, [f"{name}: JSON must be UTF-8 without BOM"]
    try:
        text = data.decode("utf-8", errors="strict")
        value = strict_json_loads(text, label=name)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return None, [f"{name}: invalid UTF-8 JSON ({type(exc).__name__})"]
    if not isinstance(value, dict):
        return None, [f"{name}: top-level JSON value must be an object"]
    errors = _bounded_evidence_json(value, label=name)
    return value, errors


def _bounded_evidence_json(value: Any, *, label: str, depth: int = 0) -> list[str]:
    if depth > MAX_EVIDENCE_JSON_DEPTH:
        return [f"{label}: JSON nesting exceeds the fixed bound"]
    errors: list[str] = []
    if isinstance(value, dict):
        if len(value) > MAX_EVIDENCE_COLLECTION_ITEMS:
            errors.append(f"{label}: object exceeds the fixed item bound")
        for key, child in value.items():
            if not isinstance(key, str):
                errors.append(f"{label}: object key is not a string")
                continue
            if len(key.encode("utf-8")) > MAX_EVIDENCE_STRING_BYTES:
                errors.append(f"{label}: object key exceeds the fixed byte bound")
            errors.extend(_bounded_evidence_json(child, label=f"{label}.{key}", depth=depth + 1))
    elif isinstance(value, list):
        if len(value) > MAX_EVIDENCE_COLLECTION_ITEMS:
            errors.append(f"{label}: array exceeds the fixed item bound")
        for index, child in enumerate(value):
            errors.extend(_bounded_evidence_json(child, label=f"{label}[{index}]", depth=depth + 1))
    elif isinstance(value, str) and len(value.encode("utf-8")) > MAX_EVIDENCE_STRING_BYTES:
        errors.append(f"{label}: string exceeds the fixed byte bound")
    elif isinstance(value, float) and not math.isfinite(value):
        errors.append(f"{label}: non-finite number is forbidden")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        errors.append(f"{label}: unsupported JSON value type")
    return errors


def _exact_document_keys(
    document: Mapping[str, Any],
    expected: set[str],
    label: str,
    errors: list[str],
) -> None:
    if set(document) != expected:
        errors.append(
            f"{label}: keys are not exact; missing={sorted(expected - set(document))} "
            f"unknown={sorted(set(document) - expected)}"
        )


def _invocation_identity(invocation_without_id: Mapping[str, Any], runtime: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {"invocation": invocation_without_id, "runtime": runtime},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return sha256_text(canonical)


def _validate_invocation_and_runtime(
    invocation: Any,
    runtime: Any,
    *,
    label: str,
    errors: list[str],
) -> None:
    invocation_keys = {
        "invocationId",
        "startedAt",
        "profile",
        "platform",
        "baselineCommit",
        "baselineTree",
        "checkpointTag",
        "policyVersion",
    }
    runtime_keys = {
        "platform",
        "os",
        "python",
        "pythonImplementation",
        "node",
        "npm",
        "runtimeClosureDigest",
        "dependencyClosureDigest",
        "dependencyMemberCount",
    }
    if not isinstance(invocation, dict):
        errors.append(f"{label}: invocation must be an object")
        return
    if not isinstance(runtime, dict):
        errors.append(f"{label}: runtime must be an object")
        return
    _exact_document_keys(invocation, invocation_keys, f"{label}.invocation", errors)
    _exact_document_keys(runtime, runtime_keys, f"{label}.runtime", errors)
    if any(not isinstance(invocation.get(key), str) for key in invocation_keys):
        errors.append(f"{label}: every invocation value must be a string")
        return
    if any(not isinstance(runtime.get(key), str) for key in runtime_keys):
        errors.append(f"{label}: every runtime value must be a string")
        return
    without_id = {key: invocation[key] for key in invocation_keys - {"invocationId"}}
    expected_id = _invocation_identity(without_id, runtime)
    if invocation.get("invocationId") != expected_id:
        errors.append(f"{label}: invocation identity hash is invalid")
    try:
        started = datetime.fromisoformat(invocation["startedAt"].replace("Z", "+00:00"))
        timestamp_value = started.timestamp()
    except (ValueError, OverflowError, OSError):
        errors.append(f"{label}: startedAt is not a valid finite timestamp")
    else:
        if started.tzinfo is None or not math.isfinite(timestamp_value):
            errors.append(f"{label}: startedAt must include a finite timezone-aware timestamp")


def _validate_runtime_dependency_closure(
    closure: Any,
    guard: Any,
    runtime: Any,
    *,
    profile: Any,
    status: Any,
    errors: list[str],
) -> None:
    """Validate producer closure claims without treating them as verifier authority."""

    label = "command-results.json.runtimeDependencyClosure"
    if not isinstance(closure, dict):
        errors.append(f"{label}: closure must be an object")
        return
    measurement = closure.get("measurementStatus")
    if measurement == RUNTIME_CLOSURE_PRECONDITION_STATUS:
        expected = {
            "closureSchemaVersion",
            "measurementStatus",
            "preconditionReason",
            "profile",
            "runnerOS",
            "dependencyClosureDigest",
            "dependencyMemberCount",
            "closureDigest",
        }
        _exact_document_keys(closure, expected, label, errors)
        if closure.get("dependencyMemberCount") != 0:
            errors.append(f"{label}: precondition failure must have zero members")
        if closure.get("preconditionReason") not in RUNTIME_CLOSURE_PRECONDITION_REASONS:
            errors.append(f"{label}: precondition reason is invalid")
        without_digest = {
            key: value for key, value in closure.items() if key != "closureDigest"
        }
        if closure.get("closureDigest") != hashlib.sha256(
            _canonical_frame(without_digest)
        ).hexdigest():
            errors.append(f"{label}: precondition closure digest is invalid")
        if status == "PASS":
            errors.append(f"{label}: PASS cannot contain a runtime precondition failure")
    elif measurement in {
        "measured-complete",
        "local-nondependency-npm-unavailable",
    }:
        expected = {
            "closureSchemaVersion",
            "measurementStatus",
            "profile",
            "runnerOS",
            "pythonExecutable",
            "nodeExecutable",
            "npmEntrypoint",
            "gitExecutable",
            "lockfiles",
            "dependencyRoots",
            "vitest",
            "nodePath",
            "dependencyClosureDigest",
            "dependencyMemberCount",
            "closureDigest",
        }
        _exact_document_keys(closure, expected, label, errors)
        lockfiles = closure.get("lockfiles")
        roots = closure.get("dependencyRoots")
        node_path = closure.get("nodePath")
        vitest = closure.get("vitest")
        if not isinstance(lockfiles, list) or not isinstance(roots, list):
            errors.append(f"{label}: lockfiles and dependencyRoots must be arrays")
            lockfiles, roots = [], []
        if node_path != []:
            errors.append(f"{label}: NODE_PATH authority must be the exact empty list")
        expected_lockfiles = ["developer/package-lock.json", "backend/package-lock.json"]
        if [item.get("relativePath") for item in lockfiles if isinstance(item, dict)] != expected_lockfiles:
            errors.append(f"{label}: lockfile set/order is not exact")
        for index, item in enumerate(lockfiles):
            if not isinstance(item, dict) or set(item) != {"relativePath", "mode", "size", "sha256"}:
                errors.append(f"{label}.lockfiles[{index}]: schema is not exact")
                continue
            if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
                errors.append(f"{label}.lockfiles[{index}]: SHA-256 is invalid")
        total_members = 0
        root_names: list[str] = []
        for root_index, root in enumerate(roots):
            root_label = f"{label}.dependencyRoots[{root_index}]"
            if not isinstance(root, dict) or set(root) != {
                "logicalRoot",
                "memberCount",
                "members",
                "memberManifestDigest",
            }:
                errors.append(f"{root_label}: schema is not exact")
                continue
            logical_root = root.get("logicalRoot")
            root_names.append(str(logical_root))
            members = root.get("members")
            if not isinstance(members, list):
                errors.append(f"{root_label}: members must be an array")
                continue
            if root.get("memberCount") != len(members):
                errors.append(f"{root_label}: memberCount is invalid")
            total_members += len(members)
            if root.get("memberManifestDigest") != hashlib.sha256(
                _canonical_frame(members)
            ).hexdigest():
                errors.append(f"{root_label}: member manifest digest is invalid")
            paths: list[str] = []
            for member_index, member in enumerate(members):
                member_label = f"{root_label}.members[{member_index}]"
                if not isinstance(member, dict) or set(member) != {
                    "relativePath",
                    "fileType",
                    "mode",
                    "size",
                    "sha256",
                    "symlinkTarget",
                }:
                    errors.append(f"{member_label}: schema is not exact")
                    continue
                relative = member.get("relativePath")
                if not isinstance(relative, str) or not relative or "\\" in relative or any(
                    part in {"", ".", ".."} for part in relative.split("/")
                ):
                    errors.append(f"{member_label}: relative path is invalid")
                else:
                    paths.append(relative)
                file_type = member.get("fileType")
                if file_type not in {"regular-file", "directory", "symlink"}:
                    errors.append(f"{member_label}: file type is invalid")
                if file_type == "regular-file" and not re.fullmatch(
                    r"[0-9a-f]{64}", str(member.get("sha256", ""))
                ):
                    errors.append(f"{member_label}: regular-file SHA-256 is invalid")
                if file_type == "symlink" and not isinstance(member.get("symlinkTarget"), str):
                    errors.append(f"{member_label}: symlink target is invalid")
            if paths != sorted(paths) or len(paths) != len(set(paths)):
                errors.append(f"{root_label}: member ordering/membership is invalid")
        expected_roots = []
        if profile in {"frontend", "all"}:
            expected_roots.append("developer/node_modules")
        if profile in {"backend", "all"}:
            expected_roots.append("backend/node_modules")
        if root_names != expected_roots:
            errors.append(f"{label}: dependency root set/order is not exact for profile")
        if closure.get("dependencyMemberCount") != total_members:
            errors.append(f"{label}: dependencyMemberCount is invalid")
        if vitest is not None:
            errors.append(f"{label}: Vitest identity is unexpected")
        semantic = {
            "lockfiles": lockfiles,
            "dependencyRoots": roots,
            "vitest": vitest,
            "nodePath": node_path,
        }
        if closure.get("dependencyClosureDigest") != hashlib.sha256(
            _canonical_frame(semantic)
        ).hexdigest():
            errors.append(f"{label}: dependency closure digest is invalid")
        without_digest = {
            key: value for key, value in closure.items() if key != "closureDigest"
        }
        if closure.get("closureDigest") != hashlib.sha256(
            _canonical_frame(without_digest)
        ).hexdigest():
            errors.append(f"{label}: runtime closure digest is invalid")
        for executable_name in (
            "pythonExecutable",
            "nodeExecutable",
            "npmEntrypoint",
            "gitExecutable",
        ):
            executable = closure.get(executable_name)
            if executable_name == "gitExecutable" and executable is None:
                continue
            if not isinstance(executable, dict):
                errors.append(f"{label}.{executable_name}: identity is unavailable")
                continue
            if executable_name == "npmEntrypoint" and executable.get("available") is False:
                if measurement != "local-nondependency-npm-unavailable":
                    errors.append(f"{label}: npm may be unavailable only in local nondependency mode")
                continue
            if not Path(str(executable.get("canonicalPath", ""))).is_absolute():
                errors.append(f"{label}.{executable_name}: canonical path is not absolute")
            if not re.fullmatch(r"[0-9a-f]{64}", str(executable.get("sha256", ""))):
                errors.append(f"{label}.{executable_name}: SHA-256 is invalid")
    else:
        errors.append(f"{label}: measurement status is invalid")

    if closure.get("closureSchemaVersion") != RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION:
        errors.append(f"{label}: schema version is invalid")
    if closure.get("profile") != profile:
        errors.append(f"{label}: profile differs from evidence profile")
    if isinstance(runtime, dict):
        if closure.get("closureDigest") != runtime.get("runtimeClosureDigest"):
            errors.append(f"{label}: digest differs from runtime identity")
        if closure.get("dependencyClosureDigest") != runtime.get("dependencyClosureDigest"):
            errors.append(f"{label}: dependency digest differs from runtime identity")
        if str(closure.get("dependencyMemberCount")) != runtime.get("dependencyMemberCount"):
            errors.append(f"{label}: member count differs from runtime identity")

    guard_label = "command-results.json.runtimeDependencyGuard"
    guard_keys = {
        "guardSchemaVersion",
        "watcherBackend",
        "active",
        "activeDuringReplay",
        "mutationState",
        "queueOverflow",
        "mutationEventCount",
    }
    if not isinstance(guard, dict) or set(guard) != guard_keys:
        errors.append(f"{guard_label}: schema is not exact")
    else:
        if guard.get("guardSchemaVersion") != RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION:
            errors.append(f"{guard_label}: schema version is invalid")
        if type(guard.get("active")) is not bool or type(guard.get("activeDuringReplay")) is not bool:
            errors.append(f"{guard_label}: active state is invalid")
        if type(guard.get("queueOverflow")) is not bool or type(guard.get("mutationEventCount")) is not int:
            errors.append(f"{guard_label}: mutation state is invalid")
        if status == "PASS" and (
            guard.get("activeDuringReplay") is not True
            or guard.get("mutationState") != "clean"
            or guard.get("queueOverflow") is not False
            or guard.get("mutationEventCount") != 0
        ):
            errors.append(f"{guard_label}: PASS requires a clean watcher active throughout replay")


def _validate_execution_binding(
    binding: Any,
    digest: Any,
    *,
    label: str,
    errors: list[str],
) -> None:
    keys = {
        "bindingSchemaVersion",
        "bindingKind",
        "bindingMode",
        "producerJobId",
        "producerRunnerOS",
        "producerProfile",
        "releaseGateRequired",
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
    if not isinstance(binding, dict):
        errors.append(f"{label}: executionBinding must be an object")
        return
    _exact_document_keys(binding, keys, f"{label}.executionBinding", errors)
    if binding.get("bindingSchemaVersion") != EVIDENCE_EXECUTION_BINDING_SCHEMA_VERSION:
        errors.append(f"{label}: execution-binding schema version is invalid")
    if binding.get("bindingKind") != "ProducerExecutionBinding":
        errors.append(f"{label}: evidence may contain only a ProducerExecutionBinding")
    if binding.get("bindingMode") not in {"github-actions", "local"}:
        errors.append(f"{label}: execution-binding mode is invalid")
    if binding.get("producerProfile") not in PROFILES:
        errors.append(f"{label}: producer profile is invalid")
    try:
        _require_resolved_release_gate_required(
            str(binding.get("producerProfile", "")),
            binding.get("releaseGateRequired"),
        )
    except ValueError as exc:
        errors.append(f"{label}: execution-binding release authority is invalid: {exc}")
    if binding.get("producerRunnerOS") not in {"Linux", "Windows"}:
        errors.append(f"{label}: execution-binding runner OS is invalid")
    for key in (
        "producerJobId",
        "runId",
        "runAttempt",
        "eventName",
        "repository",
    ):
        value = binding.get(key)
        if not isinstance(value, str) or not value or value != value.strip() or len(value.encode("utf-8")) > 512:
            errors.append(f"{label}: execution-binding {key} is invalid")
    for key in ("checkoutCommit", "checkoutTree", "baselineCommit", "baselineTree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(binding.get(key, ""))):
            errors.append(f"{label}: execution-binding {key} is invalid")
    for key in ("trustFileDigest", "commandPlanDigest", "producerInvocationId"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(binding.get(key, ""))):
            errors.append(f"{label}: execution-binding {key} is invalid")
    if binding.get("baselineCommit") != BASELINE_COMMIT or binding.get("baselineTree") != BASELINE_TREE:
        errors.append(f"{label}: execution-binding baseline identity is invalid")
    if binding.get("bindingMode") == "github-actions":
        authority = _workflow_authority_for_producer(str(binding.get("producerJobId", "")))
        if authority is None:
            errors.append(f"{label}: producer job is outside fixed workflow authority")
        elif (
            authority["runnerOS"] != binding.get("producerRunnerOS")
            or authority["profile"] != binding.get("producerProfile")
        ):
            errors.append(f"{label}: producer job/profile/OS authority mismatch")
        if not re.fullmatch(r"[1-9][0-9]*", str(binding.get("runId", ""))):
            errors.append(f"{label}: execution-binding run ID is invalid")
        if not re.fullmatch(r"[1-9][0-9]*", str(binding.get("runAttempt", ""))):
            errors.append(f"{label}: execution-binding run attempt is invalid")
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", str(binding.get("repository", ""))):
            errors.append(f"{label}: execution-binding repository is invalid")
        partial = {
            key: value
            for key, value in binding.items()
            if key != "producerInvocationId"
        }
        if binding.get("producerInvocationId") != _github_binding_invocation_id(partial):
            errors.append(f"{label}: GitHub producer invocation identity is invalid")
    elif binding.get("bindingMode") == "local":
        if (
            binding.get("producerJobId") != "local-producer"
            or binding.get("runId") != "local"
            or binding.get("runAttempt") != "1"
            or binding.get("eventName") != "local"
            or not re.fullmatch(
                r"local-root-sha256:[0-9a-f]{64}", str(binding.get("repository", ""))
            )
        ):
            errors.append(f"{label}: local execution-binding sentinel authority is invalid")
    expected_digest = execution_binding_digest(binding)
    if digest != expected_digest:
        errors.append(f"{label}: executionBindingDigest is invalid")


def execution_binding_external_context_errors(
    binding: Any,
    digest: Any,
    expected_context: ExternallyExpectedVerificationContext,
) -> list[str]:
    errors: list[str] = []
    _validate_execution_binding(
        binding,
        digest,
        label="external-verification",
        errors=errors,
    )
    expected_binding = expected_context.evidence_binding()
    if binding != expected_binding:
        errors.append("execution binding differs from externally expected verification context")
    if digest != execution_binding_digest(expected_binding):
        errors.append("execution-binding digest differs from external authority")
    return sorted(set(errors))


def _validate_command_record(
    record: Any,
    index: int,
    errors: list[str],
    *,
    expected_record: Mapping[str, Any] | None = None,
) -> bool:
    label = f"command-results.json.records[{index}]"
    required = {
        "commandId",
        "ordinal",
        "commandClass",
        "commandRole",
        "executable",
        "required",
        "profile",
        "platform",
        "argv",
        "logicalArgv",
        "executionArgv",
        "executionInputMode",
        "executionInputSize",
        "executionInputSha256",
        "cwd",
        "toolRole",
        "resolvedExecutablePath",
        "resolvedExecutableSize",
        "resolvedExecutableSha256",
        "resolvedExecutableFileIdentity",
        "executionLease",
        "targets",
        "resultSemantics",
        "allowedExecutionExits",
        "executed",
        "started",
        "setupFailure",
        "exitCode",
        "durationSeconds",
        "executionDurationClass",
        "timeoutStatus",
        "outputLimitStatus",
        "stdoutBytesObserved",
        "stderrBytesObserved",
        "stdoutByteLimit",
        "stderrByteLimit",
        "containment",
        "processTreeStatus",
        "descendantsTerminated",
        "descendantsObserved",
        "descendantsReaped",
        "descendantsSurviving",
        "containmentDisposition",
        "actualExecutionArgv",
        "actualExecutionInputMode",
        "actualExecutionInputSize",
        "actualExecutionInputSha256",
        "stdoutSha256",
        "stderrSha256",
        "producerObservations",
        "producerObservationSetDigest",
        "completedCommandClass",
        "executionInputs",
        "executionInputBundleDigest",
        "targetExecutionLease",
        "protectedTargetBundle",
    }
    optional = {
        "error",
        "limitReason",
        "processTreeError",
        "diagnosticPreview",
        "parsedFailureSummary",
        "fileScans",
        "dependencyBacked",
        "runtimeClosureDigest",
        "dependencyClosureDigest",
        "nodePath",
        "resolvedTestRunnerEntrypoint",
        "resolvedTestRunnerSha256",
        "closureWatcherActive",
        "closureMutationState",
        "runtimeClosureGuard",
        "validatedStaticMachineReport",
        "directNodeTestRawStreams",
    }
    if not isinstance(record, dict):
        errors.append(f"{label}: record must be an object")
        return True
    if not required.issubset(record) or set(record) - required - optional:
        errors.append(f"{label}: command record keys are not valid")
    if "directNodeTestRawStreams" in record:
        stream_errors = _direct_node_test_raw_stream_errors(record)
        errors.extend(f"{label}: {error}" for error in stream_errors)
        if not stream_errors and parse_node_test_semantic_result(
            record["directNodeTestRawStreams"]["stdout"], command_id=record["commandId"],
            authorized_test_paths=_direct_node_test_authorized_paths(record),
        ) is None:
            errors.append(f"{label}: successful direct Node test reporter/payload is invalid")
    if (
        not isinstance(record.get("commandId"), str)
        or not isinstance(record.get("commandClass"), str)
        or not isinstance(record.get("executable"), str)
    ):
        errors.append(f"{label}: command identity values must be strings")
    if type(record.get("ordinal")) is not int or not 0 <= record.get("ordinal", -1) < MAX_PROFILE_COMMANDS:
        errors.append(f"{label}: ordinal must be a bounded non-negative integer")
    if record.get("commandRole") not in {"required-execution", "observation-producing"}:
        errors.append(f"{label}: commandRole is invalid")
    if record.get("profile") not in PROFILES or not isinstance(record.get("platform"), str):
        errors.append(f"{label}: profile/platform authority is invalid")
    if record.get("dependencyBacked") is True:
        for field_name in (
            "runtimeClosureDigest",
            "dependencyClosureDigest",
            "resolvedTestRunnerSha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(record.get(field_name, ""))):
                errors.append(f"{label}: {field_name} is invalid")
        if record.get("nodePath") != []:
            errors.append(f"{label}: dependency-backed command has an unauthorized NODE_PATH")
        if record.get("closureWatcherActive") is not True:
            errors.append(f"{label}: dependency closure watcher was not active")
        if record.get("closureMutationState") != "clean":
            errors.append(f"{label}: dependency closure mutation state is not clean")
        entrypoint = record.get("resolvedTestRunnerEntrypoint")
        if not isinstance(entrypoint, str) or not entrypoint:
            errors.append(f"{label}: resolved test-runner entrypoint is invalid")
        elif not Path(entrypoint).is_absolute():
            errors.append(f"{label}: resolved test-runner entrypoint is not absolute")
        guard = record.get("runtimeClosureGuard")
        guard_keys = {
            "guardSchemaVersion",
            "watcherBackend",
            "active",
            "activeDuringReplay",
            "mutationState",
            "queueOverflow",
            "mutationEventCount",
        }
        if not isinstance(guard, dict) or set(guard) != guard_keys:
            errors.append(f"{label}: runtime closure guard schema is not exact")
        elif (
            guard.get("guardSchemaVersion") != RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION
            or guard.get("activeDuringReplay") is not True
            or guard.get("mutationState") != "clean"
            or guard.get("queueOverflow") is not False
            or guard.get("mutationEventCount") != 0
        ):
            errors.append(f"{label}: runtime closure guard does not authorize clean replay")
    argv = record.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 256
        or any(not isinstance(value, str) or not value for value in argv)
    ):
        errors.append(f"{label}: argv must be a bounded non-empty string array")
    logical_argv = record.get("logicalArgv")
    execution_argv = record.get("executionArgv")
    actual_execution_argv = record.get("actualExecutionArgv")
    for key, value in (
        ("logicalArgv", logical_argv),
        ("executionArgv", execution_argv),
        ("actualExecutionArgv", actual_execution_argv),
    ):
        if (
            not isinstance(value, list)
            or not value
            or len(value) > 256
            or any(not isinstance(item, str) or not item for item in value)
        ):
            errors.append(f"{label}: {key} must be a bounded non-empty string array")
    if argv != logical_argv:
        errors.append(f"{label}: argv legacy alias must equal logicalArgv")
    if actual_execution_argv != execution_argv:
        errors.append(f"{label}: actualExecutionArgv does not equal the authorized executionArgv")
    execution_input_mode = record.get("executionInputMode")
    actual_input_mode = record.get("actualExecutionInputMode")
    if execution_input_mode not in {
        "NONE",
        "TARGET-BYTES-STDIN",
        "PROTECTED-TARGET-BUNDLE",
    }:
        errors.append(f"{label}: executionInputMode is invalid")
    if actual_input_mode != execution_input_mode:
        errors.append(f"{label}: actualExecutionInputMode does not equal command authority")
    for key in ("executionInputSize", "actualExecutionInputSize"):
        value = record.get(key)
        if value is not None and (type(value) is not int or not 0 <= value <= MAX_SCANNED_FILE_BYTES):
            errors.append(f"{label}: {key} is invalid")
    for key in ("executionInputSha256", "actualExecutionInputSha256"):
        value = record.get(key)
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
            errors.append(f"{label}: {key} is invalid")
    for key in ("stdoutSha256", "stderrSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(record.get(key, ""))):
            errors.append(f"{label}: {key} is invalid")
    cwd = record.get("cwd")
    if not isinstance(cwd, str) or not cwd or Path(cwd).is_absolute() or ".." in Path(cwd).parts:
        errors.append(f"{label}: cwd must be repository-relative")
    if not isinstance(record.get("toolRole"), str) or not record.get("toolRole"):
        errors.append(f"{label}: toolRole must be a non-empty string")
    resolved_executable = record.get("resolvedExecutablePath")
    if not isinstance(resolved_executable, str) or not resolved_executable:
        errors.append(f"{label}: resolvedExecutablePath must be a non-empty string")
    executable_size = record.get("resolvedExecutableSize")
    executable_hash = record.get("resolvedExecutableSha256")
    executable_identity = record.get("resolvedExecutableFileIdentity")
    execution_lease = record.get("executionLease")
    if record.get("executed") is True and record.get("containment") != "internal":
        if type(executable_size) is not int or executable_size < 0:
            errors.append(f"{label}: executed command lacks executable size authority")
        if not isinstance(executable_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", executable_hash):
            errors.append(f"{label}: executed command lacks executable hash authority")
        identity_keys = {
            "deviceOrVolume",
            "inodeOrFileIndex",
            "creationOrChangeTimeNs",
            "writeTimeNs",
            "reparsePoint",
        }
        if not isinstance(executable_identity, dict) or set(executable_identity) != identity_keys:
            errors.append(f"{label}: executable stable identity is invalid")
    if execution_lease is not None and not _git_bash_execution_lease_valid(record):
        errors.append(f"{label}: trusted Bash execution lease is invalid")
    targets = record.get("targets")
    if not isinstance(targets, list) or len(targets) > MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: targets must be a bounded array")
        targets = []
    else:
        target_keys = {
            "path",
            "canonicalSourcePath",
            "size",
            "sha256",
            "fileIdentity",
            "modeType",
            "reparsePoint",
        }
        for target_index, target in enumerate(targets):
            target_label = f"{label}.targets[{target_index}]"
            if not isinstance(target, dict) or set(target) != target_keys:
                errors.append(f"{target_label}: schema is not exact")
                continue
            if not isinstance(target.get("path"), str) or not target.get("path"):
                errors.append(f"{target_label}: path is invalid")
            if target.get("canonicalSourcePath") is not None and (
                not isinstance(target.get("canonicalSourcePath"), str)
                or not Path(target.get("canonicalSourcePath", "")).is_absolute()
            ):
                errors.append(f"{target_label}: canonicalSourcePath is invalid")
            if target.get("size") is not None and (
                type(target.get("size")) is not int or target.get("size", -1) < 0
            ):
                errors.append(f"{target_label}: size is invalid")
            if target.get("sha256") is not None and (
                not isinstance(target.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", target.get("sha256", ""))
            ):
                errors.append(f"{target_label}: sha256 is invalid")
            if target.get("modeType") not in {None, "regular-file", "other"}:
                errors.append(f"{target_label}: modeType is invalid")
            if target.get("reparsePoint") not in {None, True, False}:
                errors.append(f"{target_label}: reparsePoint is invalid")
    execution_inputs = record.get("executionInputs")
    execution_input_digest = record.get("executionInputBundleDigest")
    compact_execution_input_reference = False
    validated_execution_inputs: list[Any] = []
    input_keys = {
        "logicalPath",
        "canonicalSourcePath",
        "plannedByteLength",
        "plannedSha256",
        "plannedStableIdentity",
        "actualByteLength",
        "actualSha256",
        "inputMode",
    }
    if not isinstance(execution_inputs, list) or len(execution_inputs) > MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: executionInputs must be a bounded array")
        execution_inputs = []
    else:
        validated_execution_inputs = execution_inputs
        if execution_input_mode == "PROTECTED-TARGET-BUNDLE" and execution_inputs == []:
            reconstructed_inputs = _reconstructed_protected_execution_inputs(record)
            if (
                reconstructed_inputs
                and execution_input_digest
                == execution_input_bundle_digest(reconstructed_inputs)
            ):
                compact_execution_input_reference = True
                validated_execution_inputs = reconstructed_inputs
        for input_index, execution_input in enumerate(validated_execution_inputs):
            input_label = f"{label}.executionInputs[{input_index}]"
            if not isinstance(execution_input, dict) or set(execution_input) != input_keys:
                errors.append(f"{input_label}: schema is not exact")
                continue
            if execution_input.get("inputMode") != execution_input_mode:
                errors.append(f"{input_label}: inputMode does not equal command authority")
            if input_index >= len(targets or []):
                errors.append(f"{input_label}: has no planned target")
                continue
            target = targets[input_index]
            if (
                execution_input.get("logicalPath") != target.get("path")
                or execution_input.get("canonicalSourcePath")
                != target.get("canonicalSourcePath")
                or execution_input.get("plannedByteLength") != target.get("size")
                or execution_input.get("plannedSha256") != target.get("sha256")
                or execution_input.get("plannedStableIdentity")
                != target.get("fileIdentity")
            ):
                errors.append(f"{input_label}: planned identity does not match target authority")
            if record.get("executed") is True and (
                execution_input.get("actualByteLength") != execution_input.get("plannedByteLength")
                or execution_input.get("actualSha256") != execution_input.get("plannedSha256")
            ):
                errors.append(f"{input_label}: actual input identity differs from planned bytes")
    expected_input_digest = (
        execution_input_bundle_digest(validated_execution_inputs)
        if validated_execution_inputs
        else None
    )
    if execution_input_digest != expected_input_digest:
        errors.append(f"{label}: executionInputBundleDigest is invalid")
    target_execution = record.get("targetExecutionLease")
    protected_bundle = record.get("protectedTargetBundle")
    if execution_input_mode == "TARGET-BYTES-STDIN":
        if not isinstance(targets, list) or len(targets) != 1:
            errors.append(f"{label}: TARGET-BYTES-STDIN requires exactly one target")
        else:
            target = targets[0]
            if record.get("executionInputSize") != target.get("size"):
                errors.append(f"{label}: planned execution-input size does not equal target size")
            if record.get("executionInputSha256") != target.get("sha256"):
                errors.append(f"{label}: planned execution-input hash does not equal target hash")
        lease_keys = {
            "leaseVersion",
            "logicalTargetPath",
            "canonicalSourcePath",
            "plannedByteLength",
            "plannedSha256",
            "plannedStableFileIdentity",
            "modeType",
            "reparsePoint",
            "executionAdapter",
            "executedInputByteLength",
            "executedInputSha256",
            "preExecutionSourceIdentity",
            "postExecutionSourceIdentity",
            "mutationDetected",
            "cleanupState",
        }
        if not isinstance(target_execution, dict) or set(target_execution) != lease_keys:
            errors.append(f"{label}: targetExecutionLease schema is not exact")
        elif isinstance(targets, list) and len(targets) == 1:
            target = targets[0]
            if (
                target_execution.get("leaseVersion") != TARGET_EXECUTION_LEASE_VERSION
                or target_execution.get("logicalTargetPath") != target.get("path")
                or target_execution.get("canonicalSourcePath") != target.get("canonicalSourcePath")
                or target_execution.get("plannedByteLength") != target.get("size")
                or target_execution.get("plannedSha256") != target.get("sha256")
                or target_execution.get("plannedStableFileIdentity") != target.get("fileIdentity")
                or target_execution.get("modeType") != target.get("modeType")
                or target_execution.get("reparsePoint") != target.get("reparsePoint")
                or target_execution.get("executionAdapter") != execution_input_mode
            ):
                errors.append(f"{label}: targetExecutionLease does not bind the command plan")
            if record.get("executed") is True and (
                target_execution.get("executedInputByteLength") != record.get("actualExecutionInputSize")
                or target_execution.get("executedInputSha256") != record.get("actualExecutionInputSha256")
                or record.get("actualExecutionInputSize") != record.get("executionInputSize")
                or record.get("actualExecutionInputSha256") != record.get("executionInputSha256")
                or target_execution.get("mutationDetected") is not False
                or target_execution.get("cleanupState") != "closed"
                or target_execution.get("preExecutionSourceIdentity") is None
                or target_execution.get("postExecutionSourceIdentity") is None
            ):
                errors.append(f"{label}: executed target input identity is invalid or source drifted")
        if protected_bundle is not None:
            errors.append(f"{label}: single-target stdin command claims a protectedTargetBundle")
        if record.get("executed") is True and len(execution_inputs) != 1:
            errors.append(f"{label}: executed TARGET-BYTES-STDIN command lacks one execution input")
    elif execution_input_mode == "PROTECTED-TARGET-BUNDLE":
        bundle_keys = {
            "bundleVersion",
            "executionAdapter",
            "orderedLogicalTargetPaths",
            "canonicalSourcePaths",
            "plannedByteLengths",
            "plannedSha256Values",
            "plannedStableIdentities",
            "executionInputs",
            "executionInputBundleDigest",
            "preExecutionIdentities",
            "postExecutionIdentities",
            "mutationDetected",
            "cleanupState",
        }
        if target_execution is not None:
            errors.append(f"{label}: protected bundle command claims a single target lease")
        if not targets:
            errors.append(
                f"{label}: protected target bundle requires nonempty command authority"
            )
        if (
            record.get("executionInputSize") is not None
            or record.get("executionInputSha256") is not None
            or record.get("actualExecutionInputSize") is not None
            or record.get("actualExecutionInputSha256") is not None
        ):
            errors.append(f"{label}: protected multi-target command claims a singular input")
        if not isinstance(protected_bundle, dict) or set(protected_bundle) != bundle_keys:
            errors.append(f"{label}: protectedTargetBundle schema is not exact")
        else:
            pre_identities = protected_bundle.get("preExecutionIdentities")
            post_identities = protected_bundle.get("postExecutionIdentities")
            if not isinstance(pre_identities, list) or not isinstance(post_identities, list):
                errors.append(f"{label}: protectedTargetBundle identity arrays are invalid")
                pre_identities = []
                post_identities = []
            compact_reference = all(
                protected_bundle.get(key) == []
                for key in _PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS
            )
            common_invalid = (
                protected_bundle.get("bundleVersion")
                != PROTECTED_TARGET_BUNDLE_VERSION
                or protected_bundle.get("executionAdapter") != execution_input_mode
                or protected_bundle.get("executionInputBundleDigest")
                != execution_input_digest
                or protected_bundle.get("cleanupState") != "closed"
            )
            if compact_reference:
                independently_expected_pre = (
                    _protected_bundle_compact_identity_digests(
                        expected_record,
                        phase="pre",
                    )
                    if isinstance(expected_record, Mapping)
                    and expected_record.get("executionInputMode")
                    == "PROTECTED-TARGET-BUNDLE"
                    else []
                )
                independently_expected_post = (
                    _protected_bundle_compact_identity_digests(
                        expected_record,
                        phase="post",
                    )
                    if isinstance(expected_record, Mapping)
                    and expected_record.get("executionInputMode")
                    == "PROTECTED-TARGET-BUNDLE"
                    else []
                )
                identity_digests_valid = (
                    len(pre_identities) == len(targets)
                    and len(post_identities) == len(targets)
                    and all(
                        isinstance(identity, str)
                        and re.fullmatch(r"[0-9a-f]{64}", identity)
                        for identity in pre_identities + post_identities
                    )
                    and pre_identities == independently_expected_pre
                    and post_identities == independently_expected_post
                )
                if (
                    common_invalid
                    or record.get("executed") is not True
                    or not targets
                    or not compact_execution_input_reference
                    or len(validated_execution_inputs) != len(targets)
                    or len(
                        {
                            target.get("path")
                            for target in targets
                            if isinstance(target, Mapping)
                        }
                    )
                    != len(targets)
                    or protected_bundle.get("mutationDetected") is not False
                    or not identity_digests_valid
                ):
                    errors.append(
                        f"{label}: protected target digest reference does not match "
                        "independently reconstructed command authority"
                    )
            else:
                if (
                    common_invalid
                    or protected_bundle.get("orderedLogicalTargetPaths")
                    != [target.get("path") for target in targets]
                    or protected_bundle.get("canonicalSourcePaths")
                    != [target.get("canonicalSourcePath") for target in targets]
                    or protected_bundle.get("plannedByteLengths")
                    != [target.get("size") for target in targets]
                    or protected_bundle.get("plannedSha256Values")
                    != [target.get("sha256") for target in targets]
                    or protected_bundle.get("plannedStableIdentities")
                    != [target.get("fileIdentity") for target in targets]
                    or protected_bundle.get("executionInputs") != execution_inputs
                ):
                    errors.append(
                        f"{label}: protectedTargetBundle does not bind the command plan"
                    )
                if record.get("executed") is True and (
                    len(validated_execution_inputs) != len(targets)
                    or protected_bundle.get("mutationDetected") is not False
                    or len(pre_identities) != len(targets)
                    or len(post_identities) != len(targets)
                    or pre_identities != post_identities
                    or any(
                        identity is None
                        for identity in pre_identities + post_identities
                    )
                    or not _full_protected_identity_array_matches_authority(
                        record,
                        pre_identities,
                    )
                    or not _full_protected_identity_array_matches_authority(
                        record,
                        post_identities,
                    )
                ):
                    errors.append(
                        f"{label}: protected target execution drifted or is incomplete"
                    )
    elif (
        record.get("executionInputSize") is not None
        or record.get("executionInputSha256") is not None
        or record.get("actualExecutionInputSize") is not None
        or record.get("actualExecutionInputSha256") is not None
        or target_execution is not None
        or protected_bundle is not None
        or execution_inputs
        or execution_input_digest is not None
    ):
        errors.append(f"{label}: non-target command claims target execution input")
    producer = record.get("producerObservations")
    if not isinstance(producer, list) or len(producer) > MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append(f"{label}: producerObservations must be a bounded array")
    elif record.get("producerObservationSetDigest") != producer_observation_set_digest(producer):
        errors.append(f"{label}: producerObservationSetDigest is invalid")
    if "validatedStaticMachineReport" in record:
        static_identity = _validated_static_machine_output_identity(record)
        if static_identity is None:
            errors.append(f"{label}: validated static machine report does not bind local execution authority")
        elif isinstance(producer, list) and [
            raw.get("rawStructuredFields") if isinstance(raw, Mapping) else None
            for raw in producer
        ] != [
            raw_observation_json_value(result)
            for result in record["validatedStaticMachineReport"]["observations"]
        ]:
            errors.append(f"{label}: static machine observations are incomplete or differ from validated output")
    if not isinstance(record.get("resultSemantics"), str) or not record.get("resultSemantics"):
        errors.append(f"{label}: resultSemantics is invalid")
    allowed_exits = record.get("allowedExecutionExits")
    if (
        not isinstance(allowed_exits, list)
        or not allowed_exits
        or allowed_exits != sorted(set(allowed_exits))
        or any(type(value) is not int or not 0 <= value <= 255 for value in allowed_exits)
    ):
        errors.append(f"{label}: allowedExecutionExits is invalid")
    if record.get("executionDurationClass") not in {"bounded", "not-started"}:
        errors.append(f"{label}: executionDurationClass is invalid")
    elif record.get("executionDurationClass") != (
        "bounded" if record.get("executed") is True else "not-started"
    ):
        errors.append(f"{label}: executionDurationClass contradicts execution state")
    expected_completed_class = (
        record.get("commandClass") if _command_completed_for_class(record) else None
    )
    if record.get("completedCommandClass") != expected_completed_class:
        errors.append(f"{label}: completedCommandClass is not independently derived")
    for key in ("required", "executed", "started", "setupFailure"):
        if type(record.get(key)) is not bool:
            errors.append(f"{label}: {key} must be boolean")
    exit_code = record.get("exitCode")
    if exit_code is not None and (
        type(exit_code) is not int or not 0 <= exit_code <= 255
    ):
        errors.append(f"{label}: exitCode must be null or an integer in [0, 255]")
    duration = record.get("durationSeconds")
    if (
        type(duration) not in {int, float}
        or not math.isfinite(duration)
        or not 0 <= duration <= MAX_JOB_TIMEOUT_SECONDS
    ):
        errors.append(f"{label}: durationSeconds must be finite and within the job timeout")
    for key in (
        "stdoutBytesObserved",
        "stderrBytesObserved",
        "stdoutByteLimit",
        "stderrByteLimit",
    ):
        if (
            type(record.get(key)) is not int
            or not 0 <= record.get(key, -1) <= MAX_RECORDED_STREAM_BYTES
        ):
            errors.append(f"{label}: {key} must be an explicitly bounded non-negative integer")
    for containment_count in (
        "descendantsTerminated",
        "descendantsObserved",
        "descendantsReaped",
        "descendantsSurviving",
    ):
        if (
            type(record.get(containment_count)) is not int
            or not 0 <= record.get(containment_count, -1) <= 4096
        ):
            errors.append(
                f"{label}: {containment_count} must be a bounded non-negative integer"
            )
    if record.get("containmentDisposition") not in {
        "not-applicable",
        "no-descendants",
        "natural-exit-reaped",
        "forced-terminated",
        "survivor",
        "unknown-ancestry",
    }:
        errors.append(f"{label}: containmentDisposition is invalid")
    if record.get("processTreeStatus") == "contained-clean" and (
        record.get("descendantsSurviving") != 0
        or record.get("containmentDisposition") in {"survivor", "unknown-ancestry"}
    ):
        errors.append(f"{label}: contained-clean contradicts descendant truth state")
    for observed_key, limit_key, status_key in (
        ("stdoutBytesObserved", "stdoutByteLimit", "outputLimitStatus"),
        ("stderrBytesObserved", "stderrByteLimit", "outputLimitStatus"),
    ):
        observed_value = record.get(observed_key)
        limit_value = record.get(limit_key)
        if type(observed_value) is int and type(limit_value) is int:
            permitted = limit_value + (OUTPUT_READ_CHUNK_BYTES if record.get(status_key) == "OUTPUT-LIMIT-EXCEEDED" else 0)
            if observed_value > permitted:
                errors.append(f"{label}: {observed_key} exceeds its explicit command cap")
    if record.get("timeoutStatus") not in {"within-limit", "TIMED-OUT"}:
        errors.append(f"{label}: timeoutStatus is invalid")
    if record.get("outputLimitStatus") not in {"within-limit", "OUTPUT-LIMIT-EXCEEDED"}:
        errors.append(f"{label}: outputLimitStatus is invalid")
    if record.get("containment") not in {
        "internal",
        "not-started",
        "linux-subreaper-pidfd-proc-supervisor",
        "windows-job-object",
    }:
        errors.append(f"{label}: containment value is invalid")
    if record.get("processTreeStatus") not in {
        "not-applicable",
        "not-started",
        "setup-failed",
        "contained-clean",
        "cleanup-failed",
    }:
        errors.append(f"{label}: processTreeStatus is invalid")
    expected_setup_failure = record.get("executed") is not True or record.get("processTreeStatus") == "setup-failed"
    if record.get("setupFailure") != expected_setup_failure:
        errors.append(f"{label}: setupFailure contradicts execution/containment state")
    if record.get("started") is not record.get("executed"):
        errors.append(f"{label}: started contradicts executed")
    hard_execution_failure = bool(record.get("required")) and not _command_execution_completed(record)
    if _command_execution_completed(record):
        if exit_code not in (allowed_exits if isinstance(allowed_exits, list) else []):
            hard_execution_failure = True
        elif record.get("commandRole") == "required-execution" and exit_code != 0:
            hard_execution_failure = True
    if record.get("timeoutStatus") == "TIMED-OUT" and exit_code != 124:
        errors.append(f"{label}: timeout status and exit code contradict")
    if record.get("outputLimitStatus") == "OUTPUT-LIMIT-EXCEEDED" and exit_code != 125:
        errors.append(f"{label}: output-limit status and exit code contradict")
    file_scans = record.get("fileScans")
    if file_scans is not None:
        if not isinstance(file_scans, list) or len(file_scans) > MAX_EVIDENCE_COLLECTION_ITEMS:
            errors.append(f"{label}: fileScans must be a bounded array")
            hard_execution_failure = True
        else:
            scan_keys = {
                "path",
                "fileSize",
                "classification",
                "scannedBytes",
                "rawBytesScanned",
                "encodingViewsApplied",
                "utf16LeDecodedUnits",
                "utf16BeDecodedUnits",
                "patternFamiliesApplied",
                "hitCount",
            }
            for scan_index, scan in enumerate(file_scans):
                scan_label = f"{label}.fileScans[{scan_index}]"
                if not isinstance(scan, dict) or set(scan) != scan_keys:
                    errors.append(f"{scan_label}: file-scan record keys are not exact")
                    hard_execution_failure = True
                    continue
                classification = scan.get("classification")
                if classification not in {
                    "text-scanned",
                    "binary-scanned",
                    "rejected-special-file",
                    "read-error",
                }:
                    errors.append(f"{scan_label}: classification is invalid")
                file_size = scan.get("fileSize")
                scanned_bytes = scan.get("scannedBytes")
                raw_bytes = scan.get("rawBytesScanned")
                hit_count = scan.get("hitCount")
                if file_size is not None and (
                    type(file_size) is not int or not 0 <= file_size <= MAX_SCANNED_FILE_BYTES
                ):
                    errors.append(f"{scan_label}: fileSize is invalid")
                if type(scanned_bytes) is not int or not 0 <= scanned_bytes <= MAX_SCANNED_FILE_BYTES:
                    errors.append(f"{scan_label}: scannedBytes is invalid")
                if type(raw_bytes) is not int or not 0 <= raw_bytes <= MAX_SCANNED_FILE_BYTES:
                    errors.append(f"{scan_label}: rawBytesScanned is invalid")
                if type(hit_count) is not int or not 0 <= hit_count <= len(SECRET_SCAN_PATTERN_FAMILIES) + 8:
                    errors.append(f"{scan_label}: hitCount is invalid")
                views = scan.get("encodingViewsApplied")
                full_views = ["raw-bytes", *UTF16_ASCII_CREDENTIAL_VIEWS]
                allowed_views = (
                    (full_views,)
                    if classification in {"text-scanned", "binary-scanned"}
                    else (["raw-bytes"], full_views)
                )
                if not isinstance(views, list) or views not in allowed_views:
                    errors.append(f"{scan_label}: encodingViewsApplied is invalid")
                    views = []
                for key, view_prefix in (
                    ("utf16LeDecodedUnits", "utf-16le-"),
                    ("utf16BeDecodedUnits", "utf-16be-"),
                ):
                    units = scan.get(key)
                    if type(units) is not int or units < 0 or (
                        type(file_size) is int and units > file_size + 1
                    ):
                        errors.append(f"{scan_label}: {key} is invalid")
                    if not any(
                        isinstance(view, str) and view.startswith(view_prefix) for view in views
                    ) and units != 0:
                        errors.append(f"{scan_label}: {key} claims a decoded view that was not applied")
                if scan.get("patternFamiliesApplied") != list(SECRET_SCAN_PATTERN_FAMILIES):
                    errors.append(f"{scan_label}: byte-pattern family set is not exact")
                if classification in {"text-scanned", "binary-scanned"} and (
                    scanned_bytes != file_size or raw_bytes != file_size or scanned_bytes != raw_bytes
                ):
                    errors.append(f"{scan_label}: regular-file rawBytesScanned does not equal fileSize")
                if classification in {"rejected-special-file", "read-error"} or (type(hit_count) is int and hit_count > 0):
                    hard_execution_failure = True
    return hard_execution_failure


def _validate_evidence_semantics(
    documents: Mapping[str, dict[str, Any]],
    snapshots: Mapping[str, _FileSnapshot],
    *,
    expected_command_plan: Sequence[Mapping[str, Any]] | None = None,
    expected_context: ExternallyExpectedVerificationContext | None = None,
) -> list[str]:
    errors: list[str] = []
    summary = documents["summary.json"]
    observed = documents["observed-debt.json"]
    resolved = documents["resolved-candidates.json"]
    commands = documents["command-results.json"]
    summary_keys = {
        "documentKind",
        "schemaVersion",
        "generatedAt",
        "status",
        "profile",
        "platform",
        "baselineCommit",
        "baselineTree",
        "checkpointTag",
        "policyVersion",
        "invocation",
        "runtime",
        "executionBinding",
        "executionBindingDigest",
        "authorizationContextBinding",
        "authorizationContextBindingDigest",
        "trustBoundary",
        "counts",
        "hardGateResults",
        "policyViolations",
        "knownDebtsObserved",
        "resolvedCandidates",
        "expectedOmissions",
        "releaseOnlySkips",
        "observationalChecks",
        "evidenceManifest",
    }
    observed_keys = {
        "documentKind",
        "schemaVersion",
        "invocation",
        "runtime",
        "executionBinding",
        "executionBindingDigest",
        "authorizationContextBinding",
        "authorizationContextBindingDigest",
        "profile",
        "platform",
        "baselineCommit",
        "records",
        "expectedOmissions",
        "releaseOnlySkips",
    }
    resolved_keys = {
        "documentKind",
        "schemaVersion",
        "invocation",
        "runtime",
        "executionBinding",
        "executionBindingDigest",
        "authorizationContextBinding",
        "authorizationContextBindingDigest",
        "profile",
        "platform",
        "baselineCommit",
        "records",
    }
    command_keys = {
        "documentKind",
        "schemaVersion",
        "invocation",
        "runtime",
        "executionBinding",
        "executionBindingDigest",
        "authorizationContextBinding",
        "authorizationContextBindingDigest",
        "profile",
        "platform",
        "records",
        "observations",
        "completedCommandClasses",
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
        "commandPlanDigest",
        "commandAuthority",
        "runtimeDependencyClosure",
        "runtimeDependencyGuard",
    }
    _exact_document_keys(summary, summary_keys, "summary.json", errors)
    _exact_document_keys(observed, observed_keys, "observed-debt.json", errors)
    _exact_document_keys(resolved, resolved_keys, "resolved-candidates.json", errors)
    _exact_document_keys(commands, command_keys, "command-results.json", errors)
    for name, document in documents.items():
        if document.get("documentKind") != EVIDENCE_DOCUMENT_KINDS[name]:
            errors.append(f"{name}: document kind is invalid")
        if document.get("schemaVersion") != 2:
            errors.append(f"{name}: schema version is invalid")
        _validate_invocation_and_runtime(
            document.get("invocation"),
            document.get("runtime"),
            label=name,
            errors=errors,
        )
        _validate_execution_binding(
            document.get("executionBinding"),
            document.get("executionBindingDigest"),
            label=name,
            errors=errors,
        )
        errors.extend(
            f"{name}: {error}"
            for error in authorization_context_binding_errors(
                document.get("authorizationContextBinding"),
                document.get("authorizationContextBindingDigest"),
                execution_binding=document.get("executionBinding"),
                expected_context=expected_context,
            )
        )

    _validate_runtime_dependency_closure(
        commands.get("runtimeDependencyClosure"),
        commands.get("runtimeDependencyGuard"),
        summary.get("runtime"),
        profile=summary.get("profile"),
        status=summary.get("status"),
        errors=errors,
    )

    invocation = summary.get("invocation")
    runtime = summary.get("runtime")
    execution_binding = summary.get("executionBinding")
    execution_binding_digest_value = summary.get("executionBindingDigest")
    authorization_context_binding = summary.get("authorizationContextBinding")
    authorization_context_binding_digest_value = summary.get(
        "authorizationContextBindingDigest"
    )
    bound_release_gate_required = (
        authorization_context_binding.get("releaseGateRequired")
        if isinstance(authorization_context_binding, Mapping)
        and type(authorization_context_binding.get("releaseGateRequired")) is bool
        else True
    )
    authoritative_release_gate_required = (
        expected_context.release_gate_required
        if expected_context is not None
        else bound_release_gate_required
    )
    for name, document in documents.items():
        if document.get("invocation") != invocation:
            errors.append(f"{name}: invocation identity is inconsistent")
        if document.get("runtime") != runtime:
            errors.append(f"{name}: runtime identity is inconsistent")
        if document.get("executionBinding") != execution_binding:
            errors.append(f"{name}: execution binding is inconsistent")
        if document.get("executionBindingDigest") != execution_binding_digest_value:
            errors.append(f"{name}: execution-binding digest is inconsistent")
        if document.get("authorizationContextBinding") != authorization_context_binding:
            errors.append(f"{name}: authorization context binding is inconsistent")
        if (
            document.get("authorizationContextBindingDigest")
            != authorization_context_binding_digest_value
        ):
            errors.append(
                f"{name}: authorization-context digest is inconsistent"
            )
        if document.get("profile") != summary.get("profile"):
            errors.append(f"{name}: profile identity is inconsistent")
        if document.get("platform") != summary.get("platform"):
            errors.append(f"{name}: platform identity is inconsistent")

    if isinstance(execution_binding, dict):
        if execution_binding.get("producerProfile") != summary.get("profile"):
            errors.append("summary.json: profile differs from producer execution binding")
        if execution_binding.get("baselineCommit") != summary.get("baselineCommit"):
            errors.append("summary.json: baseline commit differs from execution binding")
        if execution_binding.get("baselineTree") != summary.get("baselineTree"):
            errors.append("summary.json: baseline tree differs from execution binding")
        expected_platform = (
            "windows"
            if execution_binding.get("producerRunnerOS") == "Windows"
            else "ubuntu"
        )
        if summary.get("platform") != expected_platform:
            errors.append("summary.json: platform differs from execution-binding runner OS")
    if expected_context is not None:
        errors.extend(
            execution_binding_external_context_errors(
                execution_binding,
                execution_binding_digest_value,
                expected_context,
            )
        )
        for name, document in documents.items():
            if document.get("profile") != expected_context.expected_profile:
                errors.append(f"{name}: expected-profile mismatch")

    if summary.get("status") not in {"PASS", "FAIL"}:
        errors.append("summary.json: status is invalid")
    if summary.get("profile") not in PROFILES or not isinstance(summary.get("platform"), str):
        errors.append("summary.json: profile/platform identity is invalid")
    if not isinstance(invocation, dict):
        invocation = {}
    for field_name in ("profile", "platform", "baselineCommit", "baselineTree", "checkpointTag", "policyVersion"):
        if summary.get(field_name) != invocation.get(field_name):
            errors.append(f"summary.json: {field_name} contradicts invocation identity")
    if summary.get("generatedAt") != invocation.get("startedAt"):
        errors.append("summary.json: generatedAt contradicts invocation start identity")
    if summary.get("trustBoundary") != dict(TRUST_BOUNDARY):
        errors.append("summary.json: candidate-controlled trust warning is not exact")

    list_fields = (
        "hardGateResults",
        "policyViolations",
        "knownDebtsObserved",
        "resolvedCandidates",
        "expectedOmissions",
        "releaseOnlySkips",
        "observationalChecks",
    )
    for field_name in list_fields:
        if not isinstance(summary.get(field_name), list):
            errors.append(f"summary.json: {field_name} must be an array")
    if not isinstance(observed.get("records"), list) or not isinstance(resolved.get("records"), list):
        errors.append("debt/candidate evidence records must be arrays")
    if not isinstance(commands.get("records"), list):
        errors.append("command-results.json: records must be an array")
        command_records: list[Any] = []
    else:
        command_records = commands["records"]
    command_observations = commands.get("observations")
    if not isinstance(command_observations, list) or len(command_observations) > MAX_EVIDENCE_COLLECTION_ITEMS:
        errors.append("command-results.json: observations must be a bounded array")
        command_observations = []
    completed_command_classes = commands.get("completedCommandClasses")
    if (
        not isinstance(completed_command_classes, list)
        or any(not isinstance(value, str) or not value for value in completed_command_classes)
        or completed_command_classes != sorted(set(completed_command_classes))
    ):
        errors.append("command-results.json: completedCommandClasses must be a sorted unique string array")
        completed_command_classes = []
    command_authority = commands.get("commandAuthority")
    authority_profile = (
        expected_context.expected_profile
        if expected_context is not None
        else str(summary.get("profile", ""))
    )
    expected_authority = list(expected_command_plan) if expected_command_plan is not None else expected_command_authority(
        authority_profile,
    )
    portable_expected_authority = _portable_command_plan_value(expected_authority)
    if command_authority != portable_expected_authority:
        errors.append("command-results.json: command authority does not match the immutable profile plan")
    expected_plan_digest = command_plan_digest(expected_authority)
    if commands.get("commandPlanDigest") != expected_plan_digest:
        errors.append("command-results.json: commandPlanDigest does not match the immutable profile plan")
    if isinstance(execution_binding, dict) and execution_binding.get("commandPlanDigest") != expected_plan_digest:
        errors.append("execution binding command-plan digest differs from external profile authority")
    valid_command_records = [
        record for record in command_records if isinstance(record, Mapping)
    ]
    independently_expected_classes = expected_completed_command_classes(expected_authority)
    independently_actual_classes = actual_completed_command_classes(
        expected_authority,
        valid_command_records,
    )
    if commands.get("expectedCompletedCommandClasses") != independently_expected_classes:
        errors.append(
            "command-results.json: expectedCompletedCommandClasses does not match the profile plan"
        )
    if commands.get("actualCompletedCommandClasses") != independently_actual_classes:
        errors.append(
            "command-results.json: actualCompletedCommandClasses does not match command execution"
        )
    if completed_command_classes != independently_actual_classes:
        errors.append(
            "command-results.json: completedCommandClasses does not equal independently derived execution"
        )
    if summary.get("profile") in {"policy", "static"} and not independently_expected_classes:
        errors.append(
            "command-results.json: policy/static completed-command-class authority cannot be empty"
        )
    if summary.get("status") == "PASS" and independently_actual_classes != independently_expected_classes:
        errors.append(
            "command-results.json: PASS requires the exact nonempty completed-command-class set"
        )
    expected_class_digest = completed_command_class_set_digest(
        independently_expected_classes
    )
    actual_class_digest = completed_command_class_set_digest(
        independently_actual_classes
    )
    if commands.get("expectedCompletedCommandClassSetDigest") != expected_class_digest:
        errors.append(
            "command-results.json: expected completed-command-class set digest is invalid"
        )
    if commands.get("completedCommandClassSetDigest") != actual_class_digest:
        errors.append(
            "command-results.json: completed-command-class set digest is invalid"
        )
    universe_digest = producer_observation_universe_digest(valid_command_records)
    if commands.get("producerObservationUniverseDigest") != universe_digest:
        errors.append(
            "command-results.json: producerObservationUniverseDigest is invalid"
        )
    producer_count = sum(
        len(record.get("producerObservations", []))
        for record in valid_command_records
        if isinstance(record.get("producerObservations", []), list)
    )
    if commands.get("producerObservationCount") != producer_count:
        errors.append("command-results.json: producerObservationCount is invalid")
    transcript_digest = producer_transcript_digest(
        expected_plan_digest,
        valid_command_records,
        independently_actual_classes,
    )
    if commands.get("producerTranscriptDigest") != transcript_digest:
        errors.append("command-results.json: producerTranscriptDigest is invalid")
    missing_ids, extra_ids, duplicate_ids = command_id_set_differences(
        expected_authority,
        valid_command_records,
    )
    for key, expected_value in (
        ("missingCommandIds", missing_ids),
        ("extraCommandIds", extra_ids),
        ("duplicateCommandIds", duplicate_ids),
    ):
        if commands.get(key) != expected_value:
            errors.append(f"command-results.json: {key} is invalid")
    if summary.get("status") == "PASS" and (missing_ids or extra_ids or duplicate_ids):
        errors.append(
            "command-results.json: PASS transcript has missing, extra, or duplicate command IDs"
        )
    reconstructed_command_observations: list[dict[str, Any]] = []
    observation_context = {
        "producerObservationUniverseDigest": universe_digest,
        "producerTranscriptDigest": transcript_digest,
        "profileCompletedCommandClassSetDigest": actual_class_digest,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
    }
    for record in valid_command_records:
        producer_items = record.get("producerObservations")
        if not isinstance(producer_items, list):
            continue
        for raw in producer_items:
            if not isinstance(raw, Mapping):
                continue
            try:
                reconstructed_command_observations.append(
                    _rederive_observation_record(
                        {"rawObservation": raw},
                        record,
                        profile_context=observation_context,
                    )
                )
            except (TypeError, ValueError) as exc:
                errors.append(
                    "command-results.json: raw producer observation cannot be "
                    f"independently reconstructed ({type(exc).__name__})"
                )
    if command_observations not in ([], reconstructed_command_observations):
        errors.append(
            "command-results.json: derived observation projection differs from "
            "independently reconstructed raw producer authority"
        )
    command_observations = reconstructed_command_observations
    for index, item in enumerate(command_observations):
        if not isinstance(item, Mapping):
            continue
        if (
            item.get("producerObservationUniverseDigest") != universe_digest
            or item.get("producerTranscriptDigest") != transcript_digest
            or item.get("profileCompletedCommandClassSetDigest") != actual_class_digest
        ):
            errors.append(
                f"command-results.json.observations[{index}]: profile producer context is invalid"
            )

    if observed.get("baselineCommit") != summary.get("baselineCommit"):
        errors.append("observed-debt.json: baseline identity is inconsistent")
    if resolved.get("baselineCommit") != summary.get("baselineCommit"):
        errors.append("resolved-candidates.json: baseline identity is inconsistent")
    if observed.get("records") != summary.get("knownDebtsObserved"):
        errors.append("observed-debt.json: known-debt set contradicts summary")
    if observed.get("expectedOmissions") != summary.get("expectedOmissions"):
        errors.append("observed-debt.json: omission set contradicts summary")
    if observed.get("releaseOnlySkips") != summary.get("releaseOnlySkips"):
        errors.append("observed-debt.json: release-skip set contradicts summary")
    if resolved.get("records") != summary.get("resolvedCandidates"):
        errors.append("resolved-candidates.json: resolved-candidate set contradicts summary")

    counts = summary.get("counts")
    count_keys = {
        "hardGateFailures",
        "policyViolations",
        "knownDebtsObserved",
        "resolvedCandidates",
        "expectedOmissions",
        "releaseOnlySkips",
        "commands",
    }
    if not isinstance(counts, dict) or set(counts) != count_keys or any(
        type(counts.get(key)) is not int
        or not 0 <= counts.get(key, -1) <= (
            MAX_PROFILE_COMMANDS if key == "commands" else MAX_EVIDENCE_COLLECTION_ITEMS
        )
        for key in count_keys
    ):
        errors.append("summary.json: counts schema is invalid")
        counts = {}
    hard_results = summary.get("hardGateResults") if isinstance(summary.get("hardGateResults"), list) else []
    hard_failures = 0
    for index, result in enumerate(hard_results):
        if not isinstance(result, dict) or set(result) != {"id", "status", "detail"}:
            errors.append(f"summary.json.hardGateResults[{index}]: schema is not exact")
            continue
        if not isinstance(result.get("id"), str) or not isinstance(result.get("detail"), str) or result.get("status") not in {"pass", "fail"}:
            errors.append(f"summary.json.hardGateResults[{index}]: values are invalid")
        if result.get("status") != "pass":
            hard_failures += 1
    policy_violations = summary.get("policyViolations") if isinstance(summary.get("policyViolations"), list) else []
    expected_counts = {
        "hardGateFailures": hard_failures,
        "policyViolations": len(policy_violations),
        "knownDebtsObserved": len(summary.get("knownDebtsObserved", [])) if isinstance(summary.get("knownDebtsObserved"), list) else 0,
        "resolvedCandidates": len(summary.get("resolvedCandidates", [])) if isinstance(summary.get("resolvedCandidates"), list) else 0,
        "expectedOmissions": len(summary.get("expectedOmissions", [])) if isinstance(summary.get("expectedOmissions"), list) else 0,
        "releaseOnlySkips": len(summary.get("releaseOnlySkips", [])) if isinstance(summary.get("releaseOnlySkips"), list) else 0,
        "commands": len(command_records),
    }
    if counts != expected_counts:
        errors.append("summary.json: counts contradict structured evidence")
    expected_status = "PASS" if hard_failures == 0 and not policy_violations else "FAIL"
    if summary.get("status") != expected_status:
        errors.append("summary.json: status contradicts hard-failure/policy counts")

    command_hard_failure = False
    for index, record in enumerate(command_records):
        independently_expected_record = (
            expected_authority[index]
            if index < len(expected_authority)
            and isinstance(expected_authority[index], Mapping)
            and not (
                isinstance(record, Mapping)
                and record.get("commandId") == "command-results-size-limit"
            )
            else None
        )
        command_hard_failure |= _validate_command_record(
            record,
            index,
            errors,
            expected_record=independently_expected_record,
        )
        if isinstance(record, dict) and record.get("ordinal") != index:
            errors.append(f"command-results.json.records[{index}]: ordinal does not match order")
        if (
            isinstance(record, dict)
            and record.get("commandId") != "command-results-size-limit"
            and index < len(expected_authority)
        ):
            expected_record = expected_authority[index]
            authority_projection = {
                key: record.get(key) for key in expected_record
            }
            if _portable_command_plan_value([authority_projection]) != (
                [portable_expected_authority[index]]
            ):
                errors.append(
                    f"command-results.json.records[{index}]: execution record does not bind the immutable command authority"
                )
    if command_hard_failure and summary.get("status") == "PASS":
        errors.append("summary.json reports PASS while command-results records an execution failure")

    try:
        baseline = read_json(BASELINE_PATH)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"immutable baseline authority could not be loaded: {type(exc).__name__}")
    else:
        baseline_errors = validate_baseline_document(baseline)
        errors.extend(f"immutable baseline authority: {error}" for error in baseline_errors)
        if not baseline_errors:
            derived = derive_authoritative_evidence(
                authority_profile,
                command_observations,
                completed_command_classes,
                command_records,
                baseline,
                str(summary.get("platform", "")),
                expected_authority,
                authorization_context_binding_digest_value,
                release_gate_required=authoritative_release_gate_required,
                cross_job=True,
            )
            derived_sets = {
                "knownDebtsObserved": derived["observedDebts"],
                "resolvedCandidates": derived["resolvedCandidates"],
                "expectedOmissions": derived["expectedOmissions"],
                "releaseOnlySkips": derived["releaseOnlySkips"],
            }
            for field_name, expected_value in derived_sets.items():
                if summary.get(field_name) != expected_value:
                    errors.append(
                        f"summary.json: {field_name} contradicts baseline-bound command observations"
                    )
            policy_keys = {
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for item in policy_violations
                if isinstance(item, dict)
            }
            for violation in derived["violations"]:
                key = json.dumps(violation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                if key not in policy_keys:
                    errors.append(
                        "summary.json: derived command/baseline violation is missing: "
                        + missing_derived_violation_diagnostic(
                            violation,
                            command_records=command_records,
                            expected_authority=expected_authority,
                            cross_job=True,
                        )
                    )

    manifest = summary.get("evidenceManifest")
    if not isinstance(manifest, list) or len(manifest) != len(EVIDENCE_MANIFEST_FILE_NAMES):
        errors.append("summary.json: evidence manifest cardinality is invalid")
        manifest = []
    manifest_names: list[str] = []
    for index, record in enumerate(manifest):
        label = f"summary.json.evidenceManifest[{index}]"
        if not isinstance(record, dict) or set(record) != {
            "relativeFilename",
            "byteLength",
            "sha256",
            "documentKind",
        }:
            errors.append(f"{label}: manifest record schema is not exact")
            continue
        name = record.get("relativeFilename")
        manifest_names.append(name if isinstance(name, str) else "")
        if name not in EVIDENCE_MANIFEST_FILE_NAMES:
            errors.append(f"{label}: relative filename is invalid")
            continue
        data = snapshots[name].data
        if type(record.get("byteLength")) is not int or record.get("byteLength") != len(data):
            errors.append(f"{label}: byte length does not match")
        expected_hash = hashlib.sha256(data).hexdigest()
        if record.get("sha256") != expected_hash:
            errors.append(f"{label}: SHA-256 does not match")
        if record.get("documentKind") != EVIDENCE_DOCUMENT_KINDS[name]:
            errors.append(f"{label}: document kind does not match")
    if manifest_names != list(EVIDENCE_MANIFEST_FILE_NAMES):
        errors.append("summary.json: evidence manifest order/membership is not exact")

    canonical_markdown = render_summary_markdown(summary).encode("utf-8")
    if snapshots["summary.md"].data != canonical_markdown:
        errors.append("summary.md is not the exact canonical rendering of summary.json")
    return errors


def verification_replay_transcript(runner: FoundationRunner) -> dict[str, Any]:
    finalize_evidence_transcript(runner)
    binding = copy.deepcopy(getattr(runner, "execution_binding", None))
    if not isinstance(binding, Mapping):
        raise ValueError("verification replay lacks external execution-binding authority")
    verifier_binding = copy.deepcopy(
        getattr(runner, "verifier_execution_binding", None)
    )
    if not isinstance(verifier_binding, Mapping):
        verifier_binding = {}
    authorization_binding = copy.deepcopy(
        getattr(runner, "authorization_context_binding", None)
    )
    authorization_digest = getattr(
        runner, "authorization_context_binding_digest", None
    )
    return {
        "documentKind": "VerificationReplayTranscript",
        "schemaVersion": VERIFICATION_REPLAY_TRANSCRIPT_VERSION,
        "profile": runner.profile,
        "executionBinding": binding,
        "executionBindingDigest": execution_binding_digest(binding),
        "authorizationContextBinding": authorization_binding,
        "authorizationContextBindingDigest": authorization_digest,
        "verifierExecutionBinding": verifier_binding,
        "verifierExecutionBindingDigest": (
            execution_binding_digest(verifier_binding) if verifier_binding else None
        ),
        "freshRuntimeClosureDigest": runner.runtime_closure_digest,
        "dependencyClosureDigest": runner.dependency_closure_digest,
        "dependencyMemberCount": runner.dependency_member_count,
        "freshRuntimeDependencyClosure": copy.deepcopy(
            getattr(runner, "runtime_closure_document", {})
        ),
        "freshRuntimeDependencyGuard": copy.deepcopy(
            getattr(runner, "runtime_closure_guard_evidence", {})
        ),
        "linuxContainmentSelfTest": copy.deepcopy(
            getattr(
                runner,
                "linux_containment_self_test",
                {"status": "REMOTE-LIVE-VALIDATION-PENDING", "results": []},
            )
        ),
        "commandPlanDigest": runner.command_plan_digest,
        "commandCount": len(runner.command_results),
        "records": [
            _canonical_transcript_record(record) for record in runner.command_results
        ],
        "expectedCompletedCommandClasses": list(
            runner.expected_completed_command_classes
        ),
        "actualCompletedCommandClasses": list(
            runner.actual_completed_command_classes
        ),
        "expectedCompletedCommandClassSetDigest": (
            runner.expected_completed_command_class_set_digest
        ),
        "completedCommandClassSetDigest": runner.completed_command_class_set_digest,
        "producerObservationCount": runner.producer_observation_count,
        "producerObservationUniverseDigest": (
            runner.producer_observation_universe_digest
        ),
        "producerTranscriptDigest": runner.producer_transcript_digest,
        "missingCommandIds": list(runner.missing_command_ids),
        "extraCommandIds": list(runner.extra_command_ids),
        "duplicateCommandIds": list(runner.duplicate_command_ids),
    }


def _read_evidence_documents_for_replay(
    output_dir: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, _FileSnapshot], list[str]]:
    documents: dict[str, dict[str, Any]] = {}
    snapshots: dict[str, _FileSnapshot] = {}
    errors: list[str] = []
    for name in EVIDENCE_FILE_NAMES:
        snapshot, snapshot_errors = _read_evidence_file_snapshot(
            output_dir / name,
            output_dir=output_dir,
            byte_limit=EVIDENCE_FILE_BYTE_LIMITS[name],
        )
        errors.extend(f"{name}: {error}" for error in snapshot_errors)
        if snapshot is not None:
            snapshots[name] = snapshot
    for name in (
        "summary.json",
        "observed-debt.json",
        "resolved-candidates.json",
        "command-results.json",
    ):
        snapshot = snapshots.get(name)
        if snapshot is None:
            continue
        document, document_errors = _decode_evidence_json(name, snapshot.data)
        errors.extend(document_errors)
        if document is not None:
            documents[name] = document
    return documents, snapshots, sorted(set(errors))


def _portable_replay_observations(
    observations: Any, records: Sequence[Mapping[str, Any]],
) -> Any:
    """Project only reconstructed observation sources; keep claimed derived fields."""
    if not isinstance(observations, list):
        return observations
    by_id = {record.get("commandId"): record for record in records}
    result = []
    for item in observations:
        if not isinstance(item, Mapping):
            result.append(item)
            continue
        source = by_id.get(item.get("commandId"))
        portable = _portable_node_test_observation_source(source) if source is not None else source
        if (source is not None and portable is not source
            and item.get("rawObservation") == source["producerObservations"][0]
            and item.get("producerObservationSetDigest") == source["producerObservationSetDigest"]):
            result.append({
                **item, "rawObservation": portable["producerObservations"][0],
                "producerObservationSetDigest": portable["producerObservationSetDigest"],
            })
        else:
            result.append(item)
    return result


def compare_verification_replay_claims(
    documents: Mapping[str, dict[str, Any]],
    runner: FoundationRunner,
    comparison: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    """Compare raw claims only; this public API has no backend portable capability."""
    return _compare_verification_replay_claims(documents, runner, comparison)


def _compare_verification_replay_claims(
    documents: Mapping[str, dict[str, Any]],
    runner: FoundationRunner,
    comparison: Mapping[str, Any] | None,
    *,
    comparison_views: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Compare mutable evidence claims with independently replayed facts."""

    errors: list[str] = []
    summary = documents.get("summary.json", {})
    commands = documents.get("command-results.json", {})
    transcript = verification_replay_transcript(runner)
    for claimed_field in (
        "verificationReplayTranscript",
        "replayTranscript",
        "replayStatus",
        "verifierReplayContextBinding",
        "verifierReplayContextDigest",
        "replayAuthorizationEnvelopeDigest",
    ):
        if claimed_field in summary or claimed_field in commands:
            errors.append(
                "evidence-provided replay fields cannot authorize command execution"
            )
    hard_failures = [
        result
        for result in runner.hard_gate_results
        if result.get("status") != "pass"
    ]
    if hard_failures or runner.violations or comparison is None:
        errors.append(
            "verification replay profile is non-PASS: "
            f"hardFailures={len(hard_failures)} violations={len(runner.violations)}"
        )
        errors.extend(replay_failure_diagnostics(hard_failures, runner.violations))

    if summary.get("profile") != runner.profile or transcript.get("profile") != runner.profile:
        errors.append("verification replay profile selector mismatch")
    if summary.get("executionBinding") != transcript.get("executionBinding"):
        errors.append("verification replay execution binding mismatch")
    if commands.get("executionBinding") != transcript.get("executionBinding"):
        errors.append("verification replay command execution binding mismatch")
    if summary.get("executionBindingDigest") != transcript.get("executionBindingDigest"):
        errors.append("verification replay execution-binding digest mismatch")
    if commands.get("executionBindingDigest") != transcript.get("executionBindingDigest"):
        errors.append("verification replay command execution-binding digest mismatch")
    if summary.get("authorizationContextBinding") != transcript.get(
        "authorizationContextBinding"
    ):
        errors.append("verification replay authorization context mismatch")
    if commands.get("authorizationContextBinding") != transcript.get(
        "authorizationContextBinding"
    ):
        errors.append("verification replay command authorization context mismatch")
    if summary.get("authorizationContextBindingDigest") != transcript.get(
        "authorizationContextBindingDigest"
    ):
        errors.append("verification replay authorization-context digest mismatch")
    if commands.get("authorizationContextBindingDigest") != transcript.get(
        "authorizationContextBindingDigest"
    ):
        errors.append(
            "verification replay command authorization-context digest mismatch"
        )

    if _portable_command_plan_value(commands.get("commandAuthority", [])) != _portable_command_plan_value(runner.command_plan):
        errors.append("verification replay command plan differs from evidence authority")
    if commands.get("commandPlanDigest") != transcript["commandPlanDigest"]:
        errors.append("verification replay commandPlanDigest mismatch")
    evidence_records = commands.get("records")
    replay_records = transcript["records"]
    if not isinstance(evidence_records, list):
        errors.append("verification replay evidence command records are unavailable")
    else:
        comparable_evidence_records = [
            _canonical_transcript_record(record)
            for record in evidence_records
            if isinstance(record, Mapping)
        ]
        if comparison_views is not None:
            comparable_evidence_records = comparison_views["producer"]["records"]
            replay_records = comparison_views["replay"]["records"]
        if comparable_evidence_records != replay_records:
            errors.append("verification replay command execution transcript mismatch")
            diagnostics = replay_transcript_difference_diagnostics(
                comparable_evidence_records, replay_records,
                producer_source_records=[
                    record for record in evidence_records if isinstance(record, Mapping)
                ],
                replay_source_records=runner.command_results,
            )
            if diagnostics:
                errors.append("verification replay first command differences: " + json.dumps(
                    diagnostics, sort_keys=True, separators=(",", ":"),
                ))
    if isinstance(evidence_records, list) and len(evidence_records) != transcript["commandCount"]:
        errors.append("verification replay commandCount mismatch")
    top_level_fields = (
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
    for field_name in top_level_fields:
        claimed_value, replay_value = commands.get(field_name), transcript.get(field_name)
        if comparison_views is not None and field_name in (
            "producerObservationUniverseDigest", "producerTranscriptDigest",
        ):
            claimed_value = comparison_views["producer"][field_name]
            replay_value = comparison_views["replay"][field_name]
        if claimed_value != replay_value:
            errors.append(f"verification replay {field_name} mismatch")
    if commands.get("completedCommandClasses") != transcript.get(
        "actualCompletedCommandClasses"
    ):
        errors.append("verification replay completedCommandClasses mismatch")
    if _portable_replay_observations(
        commands.get("observations"),
        [record for record in evidence_records if isinstance(record, Mapping)]
        if isinstance(evidence_records, list) else [],
    ) not in ([], _portable_replay_observations(runner.observations, runner.command_results)):
        errors.append("verification replay producer observations mismatch")
    if comparison is not None:
        replay_sets = {
            "knownDebtsObserved": comparison.get("observedDebts", []),
            "resolvedCandidates": comparison.get("resolvedCandidates", []),
            "expectedOmissions": comparison.get("expectedOmissions", []),
            "releaseOnlySkips": comparison.get("releaseOnlySkips", []),
        }
        for field_name, replay_value in replay_sets.items():
            if summary.get(field_name) != replay_value:
                errors.append(
                    f"verification replay {field_name} differs from replay-backed facts"
                )
    return transcript, sorted(set(errors))


def build_verifier_replay_context_binding(
    expected_context: ExternallyExpectedVerificationContext,
    runner: Any,
    replay_transcript: Mapping[str, Any],
) -> dict[str, Any]:
    linux_result = copy.deepcopy(
        getattr(
            runner,
            "linux_containment_self_test",
            {"status": "REMOTE-LIVE-VALIDATION-PENDING", "results": []},
        )
    )
    cleanup_incomplete = any(
        (
            bool(getattr(runner, "target_execution_leases", [])),
            getattr(runner, "bash_lease", None) is not None,
            getattr(runner, "runtime_dependency_guard", None) is not None,
            getattr(runner, "runtime_dependency_closure", None) is not None,
            getattr(runner, "private_temp_handle", None) is not None,
            active_containment_count() != 0,
        )
    )
    binding = {
        "bindingSchemaVersion": VERIFIER_REPLAY_CONTEXT_BINDING_SCHEMA_VERSION,
        "bindingKind": "VerifierReplayContextBinding",
        "actualVerifierJobId": expected_context.verifier_job_id,
        "actualVerifierRunnerOS": expected_context.runner_os,
        "verifierInvocationId": expected_context.verifier_invocation_id,
        "freshRuntimeClosureDigest": str(runner.runtime_closure_digest),
        "freshDependencyClosureDigest": str(runner.dependency_closure_digest),
        "linuxContainmentLiveTestResultDigest": canonical_failure_digest(
            linux_result
        ),
        "replayTranscriptDigest": canonical_failure_digest(
            dict(replay_transcript)
        ),
        "cleanupResult": (
            "cleanup-incomplete" if cleanup_incomplete else "closed-clean"
        ),
    }
    return _require_verifier_replay_context_binding(binding)


def run_verification_replay(
    documents: Mapping[str, dict[str, Any]],
    *,
    expected_context: ExternallyExpectedVerificationContext,
    verification_runner: FoundationRunner,
    repo_root: Path = REPO_ROOT,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Re-execute the frozen raw comparison path, without backend portability."""
    comparison, errors = _execute_verification_replay(
        expected_context=expected_context, verification_runner=verification_runner,
        repo_root=repo_root,
    )
    if comparison is None:
        return None, errors
    transcript, comparison_errors = compare_verification_replay_claims(
        documents, verification_runner, comparison,
    )
    errors.extend(comparison_errors)
    return _finish_verification_replay(
        transcript, errors, expected_context=expected_context, runner=verification_runner,
    )


def _execute_verification_replay(
    *,
    expected_context: ExternallyExpectedVerificationContext,
    verification_runner: FoundationRunner,
    repo_root: Path = REPO_ROOT,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Re-execute only the externally selected profile and command plan."""

    errors: list[str] = []
    if repo_root.resolve(strict=True) != REPO_ROOT.resolve(strict=True):
        return None, ["verification replay repository root is not the active runner root"]
    runner = verification_runner
    if runner.profile != expected_context.expected_profile:
        return None, ["verification replay runner profile differs from external authority"]
    if (
        runner.release_gate_required
        is not expected_context.release_gate_required
    ):
        return None, ["verification replay release authority differs from external authority"]
    if runner.command_plan_digest != expected_context.command_plan_digest:
        return None, ["verification replay command plan differs from external authority"]
    if getattr(runner, "execution_binding", None) != expected_context.evidence_binding():
        return None, ["verification replay execution binding differs from external authority"]
    if getattr(runner, "verifier_execution_binding", None) != expected_context.verifier_binding():
        return None, ["verification replay verifier binding differs from external authority"]
    expected_authorization_binding = expected_context.authorization_context_binding()
    expected_authorization_digest = authorization_context_binding_digest(
        expected_authorization_binding
    )
    if (
        getattr(runner, "authorization_context_binding", None)
        != expected_authorization_binding
    ):
        return None, [
            "verification replay authorization context differs from external authority"
        ]
    if (
        getattr(runner, "authorization_context_binding_digest", None)
        != expected_authorization_digest
    ):
        return None, [
            "verification replay authorization-context digest differs from external authority"
        ]
    if runner.runtime_closure_digest != expected_context.fresh_runtime_closure_digest:
        return None, ["verification replay runtime closure differs from external authority"]
    comparison: dict[str, Any] | None = None
    try:
        comparison = runner.run()
    except Exception as exc:
        errors.append(
            f"verification replay execution is unavailable: {type(exc).__name__}: {sanitize_text(str(exc))}"
        )
    finally:
        runner.close_execution_leases()
    if comparison is None:
        return None, errors or ["verification replay did not produce a comparison"]
    return comparison, errors


def _finish_verification_replay(
    transcript: dict[str, Any],
    errors: list[str],
    *,
    expected_context: ExternallyExpectedVerificationContext,
    runner: FoundationRunner,
) -> tuple[dict[str, Any], list[str]]:
    expected_authorization_digest = authorization_context_binding_digest(
        expected_context.authorization_context_binding()
    )
    try:
        replay_binding = build_verifier_replay_context_binding(
            expected_context,
            runner,
            transcript,
        )
        replay_digest = verifier_replay_context_digest(replay_binding)
        full_context_set_digest = current_full_context_digest_set_digest(
            runner.observations
        )
        envelope_digest = replay_authorization_envelope_digest(
            current_full_context_set_digest=full_context_set_digest,
            authorization_context_binding_digest_value=(
                expected_authorization_digest
            ),
            verifier_replay_context_digest_value=replay_digest,
        )
        if replay_binding["cleanupResult"] != "closed-clean":
            errors.append("verification replay cleanup did not close cleanly")
    except (TypeError, ValueError) as exc:
        errors.append(
            "verification replay authorization envelope could not be derived: "
            f"{type(exc).__name__}: {sanitize_text(str(exc))}"
        )
    else:
        transcript = {
            **transcript,
            "currentFullContextDigestSetDigest": full_context_set_digest,
            "verifierReplayContextBinding": replay_binding,
            "verifierReplayContextDigest": replay_digest,
            "replayAuthorizationEnvelopeDigest": envelope_digest,
            "finalAcceptance": "PASS" if not errors else "REJECT",
        }
    return transcript, sorted(set(errors))


def verify_evidence_with_replay(
    output_dir: Path = OUTPUT_DIR,
    *,
    expected_context: ExternallyExpectedVerificationContext,
    verification_runner: FoundationRunner,
    repo_root: Path = REPO_ROOT,
    evidence_authority_root: Path | None = None,
    backend_result_evidence: Mapping[str, Any] | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    if verification_runner.profile != expected_context.expected_profile:
        return ["verification runner profile differs from external expected profile"], None
    if (
        verification_runner.release_gate_required
        is not expected_context.release_gate_required
    ):
        return ["verification runner release authority differs from external expected context"], None
    if verification_runner.command_plan_digest != expected_context.command_plan_digest:
        return ["verification runner command plan differs from external expected context"], None
    errors = verify_evidence_file_set(
        output_dir,
        repo_root=evidence_authority_root or repo_root,
        expected_command_plan=verification_runner.command_plan,
        expected_context=expected_context,
    )
    if errors:
        return errors, None
    documents, snapshots, snapshot_errors = _read_evidence_documents_for_replay(output_dir)
    if snapshot_errors:
        return snapshot_errors, None
    if backend_result_evidence is not None:
        # The replay reader takes a second snapshot. Validate the exact documents
        # used below, not merely the earlier file-set validation's snapshots.
        errors.extend(validate_evidence_root(output_dir, repo_root=evidence_authority_root or repo_root))
        try:
            if {entry.name for entry in os.scandir(output_dir)} != set(EVIDENCE_FILE_NAMES):
                errors.append("evidence file membership changed before backend binding")
        except OSError as exc:
            errors.append(f"evidence directory cannot be enumerated: {type(exc).__name__}")
        errors.extend(_validate_evidence_semantics(
            documents, snapshots, expected_command_plan=verification_runner.command_plan,
            expected_context=expected_context,
        ))
        if errors:
            return sorted(set(errors)), None
    if documents.get("summary.json", {}).get("status") != "PASS":
        return [], None
    bound_pair = None
    if backend_result_evidence is None:
        transcript, replay_errors = run_verification_replay(
            documents, expected_context=expected_context,
            verification_runner=verification_runner, repo_root=repo_root,
        )
    else:
        import backend_canonical_portable_result as backend_portable

        unavailable = "verification replay backend-canonical portable result unavailable or mismatched"
        backend_context = backend_portable._bind_producer(
            sys.modules[__name__], documents["command-results.json"],
            verification_runner.command_plan, backend_result_evidence,
        )
        if backend_context is None:
            return [unavailable], None
        comparison, replay_errors = _execute_verification_replay(
            expected_context=expected_context, verification_runner=verification_runner,
            repo_root=repo_root,
        )
        transcript = None
        if comparison is not None:
            bound_pair = backend_portable._bind_replay(
                sys.modules[__name__], backend_context,
                documents["command-results.json"], verification_runner,
            )
            if bound_pair is None:
                replay_errors.append(unavailable)
            # No reporter parse or result identity exists in the eligibility view.
            # The frozen comparisons still check every unrelated field and gate.
            views = (backend_portable._comparison_views(sys.modules[__name__], bound_pair)
                     if bound_pair is not None else None)
            transcript, comparison_errors = _compare_verification_replay_claims(
                documents, verification_runner, comparison, comparison_views=views,
            )
            replay_errors.extend(comparison_errors)
            transcript, replay_errors = _finish_verification_replay(
                transcript, replay_errors, expected_context=expected_context,
                runner=verification_runner,
            )
    errors.extend(replay_errors)
    if transcript is not None and transcript.get("finalAcceptance") != "PASS":
        errors.append(
            "verification replay lacks a PASS ReplayAuthorizationEnvelope"
        )
    try:
        rebuilt_context = rebuild_external_verification_context(
            expected_context,
            verification_runner,
            repo_root=repo_root,
        )
    except (OSError, ValueError) as exc:
        errors.append(
            f"verification replay external context could not be revalidated: {type(exc).__name__}: {sanitize_text(str(exc))}"
        )
    else:
        if rebuilt_context != expected_context:
            errors.append("verification replay external context changed during replay")
    for name, original in snapshots.items():
        current, current_errors = _read_evidence_file_snapshot(
            output_dir / name,
            output_dir=output_dir,
            byte_limit=EVIDENCE_FILE_BYTE_LIMITS[name],
        )
        errors.extend(f"{name}: {error}" for error in current_errors)
        if current is not None and (
            current.identity != original.identity or current.data != original.data
        ):
            errors.append(f"{name}: evidence changed during verification replay")
    if backend_result_evidence is not None:
        # Evidence/context/cleanup and all unrelated comparisons precede parsing.
        try:
            if {entry.name for entry in os.scandir(output_dir)} != set(EVIDENCE_FILE_NAMES):
                errors.append("evidence file membership changed during verification replay")
        except OSError as exc:
            errors.append(f"evidence directory cannot be re-enumerated: {type(exc).__name__}")
        if not errors and bound_pair is not None:
            rebound = backend_portable._bind_replay(
                sys.modules[__name__], backend_context,
                documents["command-results.json"], verification_runner,
            )
            if rebound != bound_pair:
                errors.append(unavailable)
            else:
                result = backend_portable._derive_equal_result(sys.modules[__name__], rebound)
                if result is None:
                    errors.append(unavailable)
                else:
                    transcript, comparison_errors = _compare_verification_replay_claims(
                        documents, verification_runner, comparison,
                        comparison_views=backend_portable._comparison_views(
                            sys.modules[__name__], rebound, result),
                    )
                    errors.extend(comparison_errors)
                    if not errors:
                        transcript["backendCanonicalPortableResult"] = result
                        transcript, errors = _finish_verification_replay(
                            transcript, errors, expected_context=expected_context,
                            runner=verification_runner,
                        )
        if errors and transcript is not None:
            transcript.pop("backendCanonicalPortableResult", None)
            transcript["finalAcceptance"] = "REJECT"
    return sorted(set(errors)), transcript


def render_markdown_text(value: Any) -> str:
    """Render dynamic evidence text without permitting Markdown or HTML structure."""

    text = sanitize_text(str(value)).replace("\\", "\\\\")
    for character in "`*_{}[]()#+-.!|>~":
        text = text.replace(character, "\\" + character)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    return html.escape(text, quote=True)


def render_summary_markdown(summary: Mapping[str, Any]) -> str:
    status = render_markdown_text(summary["status"])
    binding = summary["executionBinding"]
    authorization_binding = summary["authorizationContextBinding"]
    lines = [
        "# Baseline-aware CI summary",
        "",
        f"- Status: **{status}**",
        f"- Profile: {render_markdown_text(summary['profile'])}",
        f"- Platform: {render_markdown_text(summary['platform'])}",
        f"- Baseline commit: {render_markdown_text(summary['baselineCommit'])}",
        f"- Python: {render_markdown_text(summary['runtime']['python'])}",
        f"- Node: {render_markdown_text(summary['runtime']['node'])}",
        f"- npm: {render_markdown_text(summary['runtime']['npm'])}",
        f"- Runtime closure: {render_markdown_text(summary['runtime']['runtimeClosureDigest'])}",
        f"- Dependency closure: {render_markdown_text(summary['runtime']['dependencyClosureDigest'])}",
        f"- Dependency members: {render_markdown_text(summary['runtime']['dependencyMemberCount'])}",
        "",
        "## Evidence execution binding",
        "",
        f"- Binding mode: {render_markdown_text(binding['bindingMode'])}",
        f"- Binding kind: {render_markdown_text(binding['bindingKind'])}",
        f"- Producer profile: {render_markdown_text(binding['producerProfile'])}",
        f"- Producer job: {render_markdown_text(binding['producerJobId'])}",
        f"- Producer runner OS: {render_markdown_text(binding['producerRunnerOS'])}",
        f"- Run ID: {render_markdown_text(binding['runId'])}",
        f"- Run attempt: {render_markdown_text(binding['runAttempt'])}",
        f"- Event: {render_markdown_text(binding['eventName'])}",
        f"- Repository: {render_markdown_text(binding['repository'])}",
        f"- Checkout commit: {render_markdown_text(binding['checkoutCommit'])}",
        f"- Checkout tree: {render_markdown_text(binding['checkoutTree'])}",
        f"- CI trust-file digest: {render_markdown_text(binding['trustFileDigest'])}",
        f"- Command-plan digest: {render_markdown_text(binding['commandPlanDigest'])}",
        f"- Producer invocation ID: {render_markdown_text(binding['producerInvocationId'])}",
        f"- Binding digest: {render_markdown_text(summary['executionBindingDigest'])}",
        "",
        "## Stable authorization context",
        "",
        f"- Binding kind: {render_markdown_text(authorization_binding['bindingKind'])}",
        f"- Expected profile: {render_markdown_text(authorization_binding['expectedProfile'])}",
        f"- Release gates required: {str(authorization_binding['releaseGateRequired']).lower()}",
        f"- Producer job: {render_markdown_text(authorization_binding['producerJobId'])}",
        f"- Expected verifier job: {render_markdown_text(authorization_binding['expectedVerifierJobId'])}",
        f"- Runner OS: {render_markdown_text(authorization_binding['runnerOS'])}",
        f"- Authorization-context digest: {render_markdown_text(summary['authorizationContextBindingDigest'])}",
        "",
        "## Bootstrap trust boundary",
        "",
        *TRUST_WARNING_LINES,
        "",
        "## Counts",
        "",
        f"- Hard-gate failures: {summary['counts']['hardGateFailures']}",
        f"- Policy violations: {summary['counts']['policyViolations']}",
        f"- Known debts observed: {summary['counts']['knownDebtsObserved']}",
        f"- Resolved candidates: {summary['counts']['resolvedCandidates']}",
        f"- Expected private-resource omissions: {summary['counts']['expectedOmissions']}",
        f"- Release-only skips: {summary['counts']['releaseOnlySkips']}",
        "",
        "## RESOLVED-CANDIDATE",
        "",
    ]
    candidates = summary["resolvedCandidates"]
    if candidates:
        lines.extend(
            f"- **RESOLVED-CANDIDATE** {render_markdown_text(item['id'])}"
            for item in candidates
        )
    else:
        lines.append("- None")
    lines.extend(["", "## Known Phase 1 debt observed", ""])
    debts = summary["knownDebtsObserved"]
    if debts:
        lines.extend(
            f"- {render_markdown_text(item['id'])} "
            f"({render_markdown_text(item['observedOutcome'])})"
            for item in debts
        )
    else:
        lines.append("- None")
    lines.extend(["", "## Intentional public-clone omissions", ""])
    omissions = summary["expectedOmissions"]
    if omissions:
        lines.extend(
            f"- {render_markdown_text(item['id'])} — intentional public-clone omission"
            for item in omissions
        )
    else:
        lines.append("- None")
    lines.extend(["", "## Release-only skips", ""])
    release_skips = summary["releaseOnlySkips"]
    if release_skips:
        lines.extend(
            f"- {render_markdown_text(item['id'])} — release input not authorized for this CI run"
            for item in release_skips
        )
    else:
        lines.append("- None")
    lines.extend(["", "## Policy violations", ""])
    violations = summary["policyViolations"]
    if violations:
        lines.extend(
            f"- {render_markdown_text(item.get('id', 'VIOLATION'))}: "
            + render_markdown_text(
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            )
            for item in violations
        )
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _bounded_json_contribution_units(value: Any, *, depth: int = 0) -> int:
    """Count compact JSON units without materializing another large transcript."""

    if depth > MAX_EVIDENCE_JSON_DEPTH + 4:
        return 0
    if isinstance(value, Mapping):
        items = list(value.items())
        return 2 + max(0, len(items) - 1) + sum(
            _bounded_json_contribution_units(str(key), depth=depth + 1)
            + 1
            + _bounded_json_contribution_units(item, depth=depth + 1)
            for key, item in items
        )
    if isinstance(value, (list, tuple)):
        return 2 + max(0, len(value) - 1) + sum(
            _bounded_json_contribution_units(item, depth=depth + 1)
            for item in value
        )
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _command_result_size_limit_detail(
    document: Mapping[str, Any],
    *,
    total_bytes: int,
) -> str:
    """Return fixed-category, path-free telemetry for a bounded sentinel."""

    records = document.get("records")
    record_list = records if isinstance(records, list) else []
    record_families = {
        "record-targets": ("targets",),
        "record-execution-inputs": ("executionInputs",),
        "record-protected-bundles": ("protectedTargetBundle",),
        "record-producer-observations": ("producerObservations",),
        "record-diagnostics": (
            "error",
            "limitReason",
            "processTreeError",
            "diagnosticPreview",
            "parsedFailureSummary",
        ),
        "record-runtime-containment": (
            "fileScans",
            "runtimeClosureGuard",
            "runtimeClosureDigest",
            "dependencyClosureDigest",
            "nodePath",
        ),
    }
    contributions: dict[str, int] = {}
    claimed_record_units = 0
    for label, fields in record_families.items():
        value = sum(
            _bounded_json_contribution_units(record.get(field))
            for record in record_list
            if isinstance(record, Mapping)
            for field in fields
            if field in record
        )
        contributions[label] = value
        claimed_record_units += value
    total_record_units = _bounded_json_contribution_units(record_list)
    contributions["record-other"] = max(
        0, total_record_units - claimed_record_units
    )
    for label, fields in (
        ("command-authority", ("commandAuthority",)),
        ("observations", ("observations",)),
        (
            "runtime",
            ("runtime", "runtimeDependencyClosure", "runtimeDependencyGuard"),
        ),
        (
            "bindings",
            (
                "executionBinding",
                "authorizationContextBinding",
            ),
        ),
    ):
        contributions[label] = sum(
            _bounded_json_contribution_units(document.get(field))
            for field in fields
        )
    ranked = sorted(
        contributions.items(),
        key=lambda item: (-item[1], item[0]),
    )[:6]
    rendered = ",".join(f"{label}:{value}" for label, value in ranked)
    return (
        "OUTPUT-LIMIT-EXCEEDED for command-results.json "
        f"total_bytes={total_bytes} limit_bytes={MAX_COMMAND_RESULTS_JSON_BYTES} "
        f"approx_contributions={rendered}"
    )


def write_evidence(
    runner: FoundationRunner,
    comparison: Mapping[str, Any],
    *,
    runner_error: str | None = None,
    output_dir: Path | None = None,
    evidence_authority_root: Path | None = None,
) -> dict[str, Any]:
    output_dir = OUTPUT_DIR if output_dir is None else output_dir
    evidence_authority_root = (
        REPO_ROOT if evidence_authority_root is None else evidence_authority_root
    )
    root_errors = validate_evidence_root(
        output_dir, repo_root=evidence_authority_root
    )
    if root_errors:
        raise RuntimeError("; ".join(root_errors))
    if active_containment_count() != 0:
        raise RuntimeError("repository-controlled process containment remains active before evidence generation")
    if runner_error:
        runner.violations.append({"id": "CI-RUNNER-ERROR", "detail": sanitize_text(runner_error)})
    finalize_evidence_transcript(runner)
    execution_binding = copy.deepcopy(getattr(runner, "execution_binding", None))
    execution_binding_digest_value = (
        execution_binding_digest(execution_binding)
        if isinstance(execution_binding, Mapping)
        else None
    )
    authorization_context_binding = copy.deepcopy(
        getattr(runner, "authorization_context_binding", None)
    )
    authorization_context_binding_digest_value = getattr(
        runner, "authorization_context_binding_digest", None
    )
    binding_errors: list[str] = []
    _validate_execution_binding(
        execution_binding,
        execution_binding_digest_value,
        label="evidence-generation",
        errors=binding_errors,
    )
    binding_errors.extend(
        authorization_context_binding_errors(
            authorization_context_binding,
            authorization_context_binding_digest_value,
            execution_binding=execution_binding,
        )
    )
    if isinstance(execution_binding, Mapping):
        if execution_binding.get("producerProfile") != runner.profile:
            binding_errors.append("generation execution binding profile differs from runner profile")
        if (
            execution_binding.get("releaseGateRequired")
            is not getattr(runner, "release_gate_required", None)
        ):
            binding_errors.append(
                "generation execution binding release authority differs from runner"
            )
        if execution_binding.get("commandPlanDigest") != runner.command_plan_digest:
            binding_errors.append("generation execution binding command plan differs from runner plan")
        if execution_binding.get("baselineCommit") != runner.baseline.get("baselineCommit"):
            binding_errors.append("generation execution binding baseline commit differs from runner baseline")
        if execution_binding.get("baselineTree") != runner.baseline.get("baselineTree"):
            binding_errors.append("generation execution binding baseline tree differs from runner baseline")
    if binding_errors:
        raise RuntimeError("; ".join(sorted(set(binding_errors))))
    observations = list(getattr(runner, "observations", []))
    completed_command_classes = sorted(set(getattr(runner, "completed_classes", set())))
    comparison = derive_authoritative_evidence(
        runner.profile,
        observations,
        completed_command_classes,
        runner.command_results,
        runner.baseline,
        runner.platform,
        runner.command_plan,
        getattr(runner, "authorization_context_binding_digest", None),
        release_gate_required=runner.release_gate_required,
    )
    existing_violation_keys = {
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for item in runner.violations
    }
    for violation in comparison["violations"]:
        key = json.dumps(violation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key not in existing_violation_keys:
            runner.violations.append(violation)
            existing_violation_keys.add(key)
    runtime = {key: str(value) for key, value in runner.runtime.items()}
    runtime_closure_document = copy.deepcopy(
        getattr(runner, "runtime_closure_document", None)
    )
    if not isinstance(runtime_closure_document, dict):
        (
            runtime_closure_document,
            fallback_runtime_digest,
            fallback_dependency_digest,
        ) = _runtime_precondition_document(runner.profile, "MEASUREMENT_FAILED")
        runtime["runtimeClosureDigest"] = fallback_runtime_digest
        runtime["dependencyClosureDigest"] = fallback_dependency_digest
        runtime["dependencyMemberCount"] = "0"
    runtime.setdefault(
        "runtimeClosureDigest", str(runtime_closure_document.get("closureDigest", ""))
    )
    runtime.setdefault(
        "dependencyClosureDigest",
        str(runtime_closure_document.get("dependencyClosureDigest", "")),
    )
    runtime.setdefault("dependencyMemberCount", "0")
    if (
        runtime_closure_document.get("measurementStatus")
        == RUNTIME_CLOSURE_PRECONDITION_STATUS
    ):
        precondition_violation = {
            "id": "RUNTIME-CLOSURE-PRECONDITION",
            "detail": str(
                RuntimeClosurePreconditionError(
                    str(runtime_closure_document.get("preconditionReason", ""))
                )
            ),
        }
        key = json.dumps(
            precondition_violation,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if key not in existing_violation_keys:
            runner.violations.append(precondition_violation)
            existing_violation_keys.add(key)
    started_at = utc_now()
    invocation_without_id = {
        "startedAt": started_at,
        "profile": runner.profile,
        "platform": runner.platform,
        "baselineCommit": str(runner.baseline.get("baselineCommit", "")),
        "baselineTree": str(runner.baseline.get("baselineTree", "")),
        "checkpointTag": str(runner.baseline.get("checkpointTag", "")),
        "policyVersion": str(runner.baseline.get("policyVersion", "")),
    }
    invocation = {
        "invocationId": _invocation_identity(invocation_without_id, runtime),
        **invocation_without_id,
    }
    runtime_guard_document = copy.deepcopy(
        getattr(runner, "runtime_closure_guard_evidence", None)
    )
    if not isinstance(runtime_guard_document, dict):
        runtime_guard_document = {
            "guardSchemaVersion": RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
            "watcherBackend": "not-active",
            "active": False,
            "activeDuringReplay": False,
            "mutationState": "precondition-not-met",
            "queueOverflow": False,
            "mutationEventCount": 0,
        }
    evidence_records = [
        _compact_command_record_for_evidence(record)
        for record in runner.command_results
    ]
    portable_command_authority = _portable_command_plan_value(runner.command_plan)
    command_document: dict[str, Any] = {
        "documentKind": EVIDENCE_DOCUMENT_KINDS["command-results.json"],
        "schemaVersion": 2,
        "invocation": invocation,
        "runtime": runtime,
        "executionBinding": execution_binding,
        "executionBindingDigest": execution_binding_digest_value,
        "authorizationContextBinding": authorization_context_binding,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
        "profile": runner.profile,
        "platform": runner.platform,
        "records": evidence_records,
        # Derived observation projections are rebuilt from the retained raw
        # per-record producer observations by every verifier/replay.
        "observations": [],
        "completedCommandClasses": completed_command_classes,
        "expectedCompletedCommandClasses": list(
            runner.expected_completed_command_classes
        ),
        "actualCompletedCommandClasses": list(
            runner.actual_completed_command_classes
        ),
        "expectedCompletedCommandClassSetDigest": (
            runner.expected_completed_command_class_set_digest
        ),
        "completedCommandClassSetDigest": runner.completed_command_class_set_digest,
        "producerObservationCount": runner.producer_observation_count,
        "producerObservationUniverseDigest": (
            runner.producer_observation_universe_digest
        ),
        "producerTranscriptDigest": runner.producer_transcript_digest,
        "missingCommandIds": list(runner.missing_command_ids),
        "extraCommandIds": list(runner.extra_command_ids),
        "duplicateCommandIds": list(runner.duplicate_command_ids),
        "commandPlanDigest": runner.command_plan_digest,
        "commandAuthority": portable_command_authority,
        "runtimeDependencyClosure": runtime_closure_document,
        "runtimeDependencyGuard": runtime_guard_document,
    }
    command_bytes = _json_bytes(command_document)
    if len(command_bytes) > MAX_COMMAND_RESULTS_JSON_BYTES:
        size_limit_detail = _command_result_size_limit_detail(
            command_document,
            total_bytes=len(command_bytes),
        )
        runner.violations.append(
            {
                "id": "COMMAND-RESULT-JSON-LIMIT",
                "detail": size_limit_detail,
            }
        )
        runner_tools = getattr(runner, "tools", {})
        approved_python = (
            runner_tools.get("python", sys.executable)
            if isinstance(runner_tools, Mapping)
            else sys.executable
        )
        observed_python = (
            approved_python
            if getattr(getattr(runner, "tool_policy", None), "synthetic", False)
            else sys.executable
        )
        internal_argv = canonical_internal_execution_argv(
            approved_python,
            observed_python,
            "command-results-size-limit",
        )
        executable_size, executable_hash, executable_identity = _measured_file_authority(
            Path(internal_argv[0])
        )
        limited_record = {
            "ordinal": 0,
            "commandRole": "required-execution",
            "profile": runner.profile,
            "platform": runner.platform,
            "argv": list(internal_argv),
            "logicalArgv": list(internal_argv),
            "executionArgv": list(internal_argv),
            "executionInputMode": "NONE",
            "executionInputSize": None,
            "executionInputSha256": None,
            "cwd": ".",
            "toolRole": "python-in-process",
            "resolvedExecutablePath": internal_argv[0],
            "resolvedExecutableSize": executable_size,
            "resolvedExecutableSha256": executable_hash,
            "resolvedExecutableFileIdentity": executable_identity,
            "executionLease": None,
            "targets": [],
            "resultSemantics": "bounded-evidence-failure-record",
            "allowedExecutionExits": [0],
            **make_internal_result(
                "command-results-size-limit",
                "evidence-size-limit",
                False,
                size_limit_detail,
                execution_authority=approved_python,
                observed_execution_authority=observed_python,
            ),
        }
        limited_record["exitCode"] = 125
        limited_record["outputLimitStatus"] = "OUTPUT-LIMIT-EXCEEDED"
        command_document["records"] = [limited_record]
        command_document["observations"] = []
        command_document["completedCommandClasses"] = []
        command_document["actualCompletedCommandClasses"] = []
        command_document["completedCommandClassSetDigest"] = (
            completed_command_class_set_digest([])
        )
        command_document["commandPlanDigest"] = runner.command_plan_digest
        command_document["commandAuthority"] = portable_command_authority
        command_document["producerObservationCount"] = 0
        command_document["producerObservationUniverseDigest"] = (
            producer_observation_universe_digest(command_document["records"])
        )
        command_document["producerTranscriptDigest"] = producer_transcript_digest(
            runner.command_plan_digest,
            command_document["records"],
            [],
        )
        missing_ids, extra_ids, duplicate_ids = command_id_set_differences(
            runner.command_plan,
            command_document["records"],
        )
        command_document["missingCommandIds"] = missing_ids
        command_document["extraCommandIds"] = extra_ids
        command_document["duplicateCommandIds"] = duplicate_ids
        command_bytes = _json_bytes(command_document)
        comparison = {
            "observedDebts": [],
            "resolvedCandidates": [],
            "expectedOmissions": [],
            "releaseOnlySkips": [],
            "violations": [{"id": "COMMAND-RESULT-JSON-LIMIT"}],
        }
    hard_failures = [item for item in runner.hard_gate_results if item["status"] != "pass"]
    status = "PASS" if not runner.violations and not hard_failures else "FAIL"
    summary = {
        "documentKind": EVIDENCE_DOCUMENT_KINDS["summary.json"],
        "schemaVersion": 2,
        "generatedAt": started_at,
        "status": status,
        "profile": runner.profile,
        "platform": runner.platform,
        "baselineCommit": runner.baseline.get("baselineCommit"),
        "baselineTree": runner.baseline.get("baselineTree"),
        "checkpointTag": runner.baseline.get("checkpointTag"),
        "policyVersion": runner.baseline.get("policyVersion"),
        "invocation": invocation,
        "runtime": runtime,
        "executionBinding": execution_binding,
        "executionBindingDigest": execution_binding_digest_value,
        "authorizationContextBinding": authorization_context_binding,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
        "trustBoundary": dict(TRUST_BOUNDARY),
        "counts": {
            "hardGateFailures": len(hard_failures),
            "policyViolations": len(runner.violations),
            "knownDebtsObserved": len(comparison.get("observedDebts", [])),
            "resolvedCandidates": len(comparison.get("resolvedCandidates", [])),
            "expectedOmissions": len(comparison.get("expectedOmissions", [])),
            "releaseOnlySkips": len(comparison.get("releaseOnlySkips", [])),
            "commands": len(command_document["records"]),
        },
        "hardGateResults": sorted(runner.hard_gate_results, key=lambda item: item["id"]),
        "policyViolations": runner.violations,
        "knownDebtsObserved": comparison.get("observedDebts", []),
        "resolvedCandidates": comparison.get("resolvedCandidates", []),
        "expectedOmissions": comparison.get("expectedOmissions", []),
        "releaseOnlySkips": comparison.get("releaseOnlySkips", []),
        "observationalChecks": runner.baseline.get("observationalChecks", []),
        "evidenceManifest": [],
    }
    observed_document = {
        "documentKind": EVIDENCE_DOCUMENT_KINDS["observed-debt.json"],
        "schemaVersion": 2,
        "invocation": invocation,
        "runtime": runtime,
        "executionBinding": execution_binding,
        "executionBindingDigest": execution_binding_digest_value,
        "authorizationContextBinding": authorization_context_binding,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
        "profile": runner.profile,
        "platform": runner.platform,
        "baselineCommit": runner.baseline.get("baselineCommit"),
        "records": comparison.get("observedDebts", []),
        "expectedOmissions": comparison.get("expectedOmissions", []),
        "releaseOnlySkips": comparison.get("releaseOnlySkips", []),
    }
    resolved_document = {
        "documentKind": EVIDENCE_DOCUMENT_KINDS["resolved-candidates.json"],
        "schemaVersion": 2,
        "invocation": invocation,
        "runtime": runtime,
        "executionBinding": execution_binding,
        "executionBindingDigest": execution_binding_digest_value,
        "authorizationContextBinding": authorization_context_binding,
        "authorizationContextBindingDigest": (
            authorization_context_binding_digest_value
        ),
        "profile": runner.profile,
        "platform": runner.platform,
        "baselineCommit": runner.baseline.get("baselineCommit"),
        "records": comparison.get("resolvedCandidates", []),
    }
    payloads = {
        "summary.md": render_summary_markdown(summary).encode("utf-8"),
        "observed-debt.json": _json_bytes(observed_document),
        "resolved-candidates.json": _json_bytes(resolved_document),
        "command-results.json": _json_bytes(command_document),
    }
    summary["evidenceManifest"] = [
        {
            "relativeFilename": name,
            "byteLength": len(payloads[name]),
            "sha256": hashlib.sha256(payloads[name]).hexdigest(),
            "documentKind": EVIDENCE_DOCUMENT_KINDS[name],
        }
        for name in EVIDENCE_MANIFEST_FILE_NAMES
    ]
    payloads["summary.json"] = _json_bytes(summary)
    for name, payload in payloads.items():
        if len(payload) > EVIDENCE_FILE_BYTE_LIMITS[name]:
            raise RuntimeError(f"{name} exceeds its fixed evidence byte limit")
    for name in EVIDENCE_FILE_NAMES:
        _exclusive_write(
            output_dir / name,
            payloads[name],
            repo_root=evidence_authority_root,
        )
    if active_containment_count() != 0:
        raise RuntimeError("repository-controlled process containment became active before evidence verification")
    verification_errors = verify_evidence_file_set(
        output_dir,
        repo_root=evidence_authority_root,
        expected_command_plan=runner.command_plan,
    )
    if verification_errors:
        raise RuntimeError("; ".join(verification_errors))
    return summary


def _validate_directory_chain(path: Path, *, stop: Path) -> list[str]:
    errors: list[str] = []
    try:
        stop_resolved = stop.resolve(strict=True)
        path_resolved = path.resolve(strict=True)
    except OSError as exc:
        return [f"installed package path cannot be resolved: {type(exc).__name__}"]
    if not _path_is_within(path_resolved, stop_resolved):
        return ["installed package path escapes the exact node_modules root"]
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            errors.append(f"{current}: cannot inspect ({type(exc).__name__})")
            break
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            errors.append(f"{current}: package path component is not a non-reparse directory")
        if current.resolve(strict=True) == stop_resolved:
            break
        if current.parent == current:
            errors.append("installed package path did not reach node_modules root")
            break
        current = current.parent
    return errors


def prepare_developer_esbuild() -> list[str]:
    """Run only the locked esbuild postinstall after ignore-scripts npm ci."""

    errors: list[str] = []
    tools, tool_errors = resolve_trusted_tools({"python", "node", "git"})
    try:
        tools = require_tool_set(
            tools,
            {"python", "node", "git"},
            phase="EXECUTION_BINDING",
            resolution_errors=tool_errors,
        )
    except ToolAuthorityUnavailable as exc:
        return [str(exc)]
    git = require_tool(tools, "git", phase="EXECUTION_BINDING")
    node = require_tool(tools, "node", phase="EXECUTION_BINDING")
    environment = child_process_environment(tools)
    locked_identities, locked_identity_errors = capture_locked_file_git_identities(
        git=git,
        environment=environment,
        repo_root=REPO_ROOT,
    )
    before, snapshot_errors = snapshot_trusted_files(
        locked_identities=locked_identities
    )
    snapshot_errors.extend(locked_identity_errors)
    errors.extend(snapshot_errors)
    lock_path = REPO_ROOT / "developer" / "package-lock.json"
    try:
        lock_document = read_json(lock_path)
        lock_record = lock_document["packages"]["node_modules/esbuild"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"developer lockfile cannot authorize esbuild: {type(exc).__name__}")
        return errors
    if lock_record.get("version") != ESBUILD_VERSION:
        errors.append("developer lockfile esbuild version is not exact")
    if lock_record.get("integrity") != ESBUILD_LOCK_INTEGRITY or lock_record.get("hasInstallScript") is not True:
        errors.append("developer lockfile esbuild integrity/install-script authority is not exact")

    node_modules = REPO_ROOT / "developer" / "node_modules"
    package_root = node_modules / "esbuild"
    errors.extend(_validate_directory_chain(package_root, stop=node_modules))
    package_json_path = package_root / "package.json"
    installer_path = package_root / "install.js"
    for path in (package_json_path, installer_path):
        okay, reason = _secure_regular_file(path)
        if not okay:
            errors.append(f"{path.name}: {reason}")
    try:
        installed_package = read_json(package_json_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"installed esbuild package metadata cannot be read: {type(exc).__name__}")
    else:
        if installed_package.get("name") != "esbuild" or installed_package.get("version") != ESBUILD_VERSION:
            errors.append("installed esbuild package name/version is not exact")
        if installed_package.get("scripts", {}).get("postinstall") != "node install.js":
            errors.append("installed esbuild postinstall command is not exactly node install.js")

    machine = platform.machine().casefold()
    architecture = "x64" if machine in {"amd64", "x86_64"} else "arm64" if machine in {"arm64", "aarch64"} else ""
    operating_system = "win32" if sys.platform.startswith("win") else "linux" if sys.platform.startswith("linux") else ""
    if not architecture or not operating_system:
        errors.append("esbuild preparation supports only the canonical Windows/Linux x64/arm64 runners")
    else:
        platform_package = node_modules / "@esbuild" / f"{operating_system}-{architecture}"
        errors.extend(_validate_directory_chain(platform_package, stop=node_modules))
        platform_package_json = platform_package / "package.json"
        okay, reason = _secure_regular_file(platform_package_json)
        if not okay:
            errors.append(f"installed platform esbuild package: {reason}")
        else:
            try:
                platform_metadata = read_json(platform_package_json)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                errors.append(f"platform esbuild metadata cannot be read: {type(exc).__name__}")
            else:
                if platform_metadata.get("version") != ESBUILD_VERSION:
                    errors.append("installed platform esbuild version is not exact")
        binary = platform_package / ("esbuild.exe" if operating_system == "win32" else "bin/esbuild")
        okay, reason = _secure_regular_file(binary)
        if not okay:
            errors.append(f"installed platform esbuild binary: {reason}")

    if errors:
        return sorted(set(errors))
    trusted_arguments = trusted_git_arguments(
        git, "diff", "--exit-code", "--", *TRUSTED_FILE_PATHS
    )
    before_diff = execute_command(
        "trusted-files-before-esbuild",
        "trusted-file-integrity",
        trusted_arguments,
        timeout=60,
        env=environment,
        include_preview=False,
    )
    if not before_diff.executed or before_diff.exit_code != 0:
        errors.append("tracked trusted bytes changed before the esbuild installer")
        return errors
    capture = execute_command(
        "locked-esbuild-installer",
        "dependency-lifecycle",
        [node, str(installer_path.resolve(strict=True))],
        timeout=180,
        env=environment,
        cwd=package_root,
    )
    if not capture.executed or capture.exit_code != 0 or capture.output_limited or capture.timed_out:
        errors.append(
            "exact locked esbuild installer failed: "
            + bounded_preview("\n".join(part for part in (capture.error or "", capture.stdout, capture.stderr) if part), max_lines=8)
        )
    after_locked_identities, after_identity_errors = (
        capture_locked_file_git_identities(
            git=git,
            environment=environment,
            repo_root=REPO_ROOT,
        )
    )
    after, after_errors = snapshot_trusted_files(
        locked_identities=after_locked_identities
    )
    after_errors.extend(after_identity_errors)
    errors.extend(after_errors)
    errors.extend(compare_trusted_snapshots(before, after))
    after_diff = execute_command(
        "trusted-files-after-esbuild",
        "trusted-file-integrity",
        trusted_arguments,
        timeout=60,
        env=environment,
        include_preview=False,
    )
    if not after_diff.executed or after_diff.exit_code != 0:
        errors.append("tracked trusted bytes changed after the esbuild installer")
    return sorted(set(errors))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    selected_argv = list(sys.argv[1:] if argv is None else argv)
    for option in (
        "--expected-profile",
        "--expected-producer-job",
        "--expected-verifier-job",
        "--expected-runner-os",
        "--expected-invocation-id",
        "--untrusted-evidence-root",
        "--release-authoritative",
    ):
        occurrences = sum(
            token == option or token.startswith(option + "=")
            for token in selected_argv
        )
        if occurrences > 1:
            raise ValueError(f"{option} may be supplied at most once")
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Run the baseline-aware Phase 1 CI foundation policy.",
        exit_on_error=False,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--profile", choices=PROFILES)
    group.add_argument("--list-profiles", action="store_true")
    group.add_argument("--prepare-developer-esbuild", action="store_true")
    group.add_argument("--verify-evidence", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--require-install-tools", action="store_true")
    parser.add_argument("--release-authoritative", action="store_true")
    parser.add_argument("--expected-profile", choices=PROFILES)
    parser.add_argument(
        "--expected-producer-job",
        choices=tuple(
            authority["producerJobId"]
            for authority in WORKFLOW_JOB_PROFILE_AUTHORITY.values()
        ),
    )
    parser.add_argument(
        "--expected-verifier-job",
        choices=tuple(WORKFLOW_JOB_PROFILE_AUTHORITY),
    )
    parser.add_argument("--expected-runner-os", choices=("Linux", "Windows"))
    parser.add_argument("--expected-invocation-id")
    parser.add_argument("--untrusted-evidence-root")
    parser.add_argument("--require-linux-containment-self-test", action="store_true")
    parser.add_argument("--require-fresh-runtime-closure", action="store_true")
    try:
        args = parser.parse_args(selected_argv)
    except argparse.ArgumentError as exc:
        raise ValueError(str(exc)) from exc
    if args.verify_only and args.profile != "policy":
        raise ValueError("--verify-only is supported only with --profile policy")
    if args.require_install_tools and not (args.verify_only and args.profile == "policy"):
        raise ValueError("--require-install-tools requires the policy verify-only pre-install profile")
    selected_profile = args.expected_profile if args.verify_evidence else args.profile
    if args.release_authoritative and selected_profile != "all":
        raise ValueError("--release-authoritative requires profile all")
    expected_options = (
        args.expected_profile,
        args.expected_producer_job,
        args.expected_verifier_job,
        args.expected_runner_os,
        args.expected_invocation_id,
        args.untrusted_evidence_root,
    )
    if args.verify_evidence:
        if args.expected_profile is None:
            raise ValueError("--verify-evidence requires --expected-profile from external authority")
    elif any(value is not None for value in expected_options) or (
        args.require_linux_containment_self_test
        or args.require_fresh_runtime_closure
    ):
        raise ValueError("expected verification context options require --verify-evidence")
    return args


def prepare_verification_authority(
    args: argparse.Namespace,
    *,
    external_authority: ExecutionExternalAuthority,
    repo_root: Path = REPO_ROOT,
    source_environment: Mapping[str, str] | None = None,
) -> tuple[ExternallyExpectedVerificationContext, FoundationRunner]:
    """Build the expected runner and binding before opening the evidence root."""

    baseline_path = repo_root / "developer" / "tests" / "ci" / "phase1-ci-baseline.json"
    try:
        baseline = strict_json_load_file(baseline_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"verification baseline is unavailable: {type(exc).__name__}") from exc
    schema_errors = validate_baseline_document(baseline)
    if schema_errors:
        raise ValueError("verification baseline schema is invalid: " + "; ".join(schema_errors))
    if external_authority.source_kind != "live":
        raise ValueError("production verification requires live external authority")
    source = dict(os.environ if source_environment is None else source_environment)
    github_actions = external_authority.binding_mode == "github-actions"
    if github_actions:
        if not args.untrusted_evidence_root:
            raise ValueError("GitHub verifier requires an explicit untrusted evidence root")
        if args.expected_runner_os == "Linux" and not args.require_linux_containment_self_test:
            raise ValueError("every Linux verifier requires the live containment self-test")
        if args.expected_runner_os == "Windows" and args.require_linux_containment_self_test:
            raise ValueError("Windows verifier cannot claim the Linux live containment self-test")
        if args.expected_profile == "all" and not args.require_fresh_runtime_closure:
            raise ValueError("all-profile verifier requires a fresh runtime/dependency closure")
        captured_python = source.get("CI_TRUSTED_PYTHON", "")
        if (
            not captured_python
            or not Path(captured_python).is_absolute()
            or not _same_file_identity(
                Path(captured_python), Path(sys.executable)
            )
        ):
            raise ValueError("verifier was not invoked through the captured absolute trusted Python")
        for name in ("CI_TRUSTED_NODE", "CI_TRUSTED_NPM_ENTRY"):
            value = source.get(name, "")
            if not value or not Path(value).is_absolute():
                raise ValueError(f"GitHub verifier is missing absolute {name}")
    if sys.platform.startswith("linux"):
        ensure_main_linux_subreaper()
    runner = FoundationRunner(
        str(args.expected_profile),
        baseline,
        source_environment=source_environment,
        enable_runtime_closure=True,
        require_fresh_runtime_closure=bool(args.require_fresh_runtime_closure),
        release_authoritative=bool(args.release_authoritative),
        execution_external_authority=external_authority,
    )
    runner.require_all_tools(phase="VERIFICATION_PREPARATION")
    runner.linux_containment_self_test = {
        "status": "REMOTE-LIVE-VALIDATION-PENDING",
        "results": [],
    }
    if args.require_linux_containment_self_test:
        results, live_errors = run_linux_containment_live_self_test(
            python_executable=runner.require_tool(
                "python", phase="VERIFICATION_PREPARATION"
            ),
            environment=runner.child_environment,
            temp_root=runner.private_temp_root,
        )
        runner.linux_containment_self_test = {
            "status": "PASS" if not live_errors else "FAIL",
            "results": results,
        }
        if live_errors:
            runner.cleanup_task_resources()
            raise ValueError("Linux containment live self-test failed: " + "; ".join(live_errors))
    try:
        context = build_externally_expected_verification_context(
            expected_profile=str(args.expected_profile),
            release_gate_required=runner.release_gate_required,
            expected_producer_job=args.expected_producer_job,
            expected_verifier_job=args.expected_verifier_job,
            expected_runner_os=args.expected_runner_os,
            expected_invocation_id=args.expected_invocation_id,
            command_plan_digest_value=runner.command_plan_digest,
            fresh_runtime_closure_digest=runner.runtime_closure_digest,
            baseline=baseline,
            git=runner.require_tool("git", phase="EXECUTION_BINDING"),
            child_environment=runner.child_environment,
            external_authority=external_authority,
            repo_root=repo_root,
        )
    except Exception:
        runner.close_execution_leases()
        raise
    runner.execution_binding = context.evidence_binding()
    runner.verifier_execution_binding = context.verifier_binding()
    runner.external_verification_context = context
    runner.authorization_context_binding = context.authorization_context_binding()
    runner.authorization_context_binding_digest = authorization_context_binding_digest(
        runner.authorization_context_binding
    )
    return context, runner


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
    except (ValueError, SystemExit) as exc:
        if isinstance(exc, SystemExit) and exc.code == 0:
            return EXIT_SUCCESS
        print(f"CI foundation argument error: {sanitize_text(str(exc))}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR
    if args.list_profiles:
        print("\n".join(PROFILES))
        return EXIT_SUCCESS
    source_environment = dict(os.environ)
    try:
        external_authority = capture_live_external_authority(source_environment)
    except ValueError as exc:
        print(
            "CI foundation external-authority configuration error: "
            + sanitize_text(str(exc)),
            file=sys.stderr,
        )
        return EXIT_CONFIGURATION_ERROR
    local_parent_path = source_environment.get("CI_FOUNDATION_LOCAL_PARENT_PATH", "")
    if local_parent_path:
        if external_authority.binding_mode == "github-actions":
            print(
                "CI foundation external-authority configuration error: "
                "local parent PATH override is forbidden in GitHub Actions",
                file=sys.stderr,
            )
            return EXIT_CONFIGURATION_ERROR
        if (
            "\0" in local_parent_path
            or "\r" in local_parent_path
            or "\n" in local_parent_path
            or len(local_parent_path.encode("utf-8", errors="strict")) > 32_768
        ):
            print(
                "CI foundation external-authority configuration error: "
                "local parent PATH override is malformed",
                file=sys.stderr,
            )
            return EXIT_CONFIGURATION_ERROR
        source_environment["PATH"] = local_parent_path
        source_environment["Path"] = local_parent_path
    if args.verify_evidence:
        evidence_root = (
            REPO_ROOT / args.untrusted_evidence_root
            if args.untrusted_evidence_root
            and not Path(args.untrusted_evidence_root).is_absolute()
            else Path(args.untrusted_evidence_root)
            if args.untrusted_evidence_root
            else OUTPUT_DIR
        )
        try:
            evidence_root = evidence_root.resolve(strict=True)
        except OSError as exc:
            print(
                f"CI foundation untrusted evidence root error: {type(exc).__name__}",
                file=sys.stderr,
            )
            return EXIT_CONFIGURATION_ERROR
        try:
            expected_context, verification_runner = prepare_verification_authority(
                args,
                external_authority=external_authority,
                repo_root=REPO_ROOT,
                source_environment=source_environment,
            )
        except (OSError, KeyError, ValueError) as exc:
            print(
                f"CI foundation verification configuration error: {type(exc).__name__}: {sanitize_text(str(exc))}",
                file=sys.stderr,
            )
            return EXIT_CONFIGURATION_ERROR
        try:
            verification_errors, replay_transcript = verify_evidence_with_replay(
                evidence_root,
                expected_context=expected_context,
                verification_runner=verification_runner,
                repo_root=REPO_ROOT,
                evidence_authority_root=evidence_root.parent,
            )
        finally:
            verification_runner.cleanup_task_resources()
        if verification_errors:
            print("CI foundation evidence verification failed:", file=sys.stderr)
            for error in verification_errors:
                print(f"- {sanitize_text(error)}", file=sys.stderr)
            return EXIT_POLICY_VIOLATION
        replay_status = "PASS" if replay_transcript is not None else "NOT-REQUIRED"
        print(
            "CI foundation evidence verification status=PASS "
            f"replay={replay_status}"
        )
        return EXIT_SUCCESS
    try:
        evidence_output_dir, evidence_authority_root = (
            select_generation_evidence_output(
                source_environment,
                external_authority,
                repo_root=REPO_ROOT,
            )
        )
    except ValueError as exc:
        print(
            "CI foundation evidence-output configuration error: "
            + sanitize_text(str(exc)),
            file=sys.stderr,
        )
        return EXIT_CONFIGURATION_ERROR
    evidence_errors = validate_evidence_root_absent(
        evidence_output_dir, repo_root=evidence_authority_root
    )
    if evidence_errors:
        print(
            "CI foundation evidence-root guard violation: " + sanitize_text("; ".join(evidence_errors)),
            file=sys.stderr,
        )
        return EXIT_RUNNER_ERROR
    try:
        baseline = read_json(BASELINE_PATH)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"CI foundation baseline error: {type(exc).__name__}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR
    schema_errors = validate_baseline_document(baseline)
    if schema_errors:
        print("CI foundation baseline schema violation:", file=sys.stderr)
        for error in schema_errors:
            print(f"- {sanitize_text(error)}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR

    if args.prepare_developer_esbuild:
        preparation_errors = prepare_developer_esbuild()
        if preparation_errors:
            print("CI foundation esbuild preparation violation:", file=sys.stderr)
            for error in preparation_errors:
                print(f"- {sanitize_text(error)}", file=sys.stderr)
            return EXIT_POLICY_VIOLATION
        print("CI foundation locked esbuild preparation status=PASS")
        return EXIT_SUCCESS

    runner = FoundationRunner(
        args.profile,
        baseline,
        require_install_tools=args.require_install_tools,
        source_environment=source_environment,
        enable_runtime_closure=True,
        release_authoritative=bool(args.release_authoritative),
        execution_external_authority=external_authority,
    )
    try:
        runner.require_all_tools(
            phase="EXECUTION_BINDING" if not args.verify_only else "EXECUTION"
        )
    except ToolAuthorityUnavailable as exc:
        runner.cleanup_task_resources()
        print(str(exc), file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR
    if not args.verify_only:
        try:
            runner.execution_binding = build_generation_execution_binding(
                runner,
                external_authority=external_authority,
                repo_root=REPO_ROOT,
            )
        except (OSError, ValueError) as exc:
            runner.close_execution_leases()
            if isinstance(exc, ToolAuthorityUnavailable):
                print(str(exc), file=sys.stderr)
            else:
                print(
                    f"CI foundation execution-binding configuration error: {type(exc).__name__}: {sanitize_text(str(exc))}",
                    file=sys.stderr,
                )
            return EXIT_CONFIGURATION_ERROR
        try:
            create_fresh_evidence_root(
                evidence_output_dir,
                repo_root=evidence_authority_root,
            )
        except Exception as exc:
            runner.close_execution_leases()
            print(
                f"CI foundation evidence-root creation error: {type(exc).__name__}: {sanitize_text(str(exc))}",
                file=sys.stderr,
            )
            return EXIT_RUNNER_ERROR
    comparison: dict[str, Any] = {
        "observedDebts": [],
        "resolvedCandidates": [],
        "expectedOmissions": [],
        "releaseOnlySkips": [],
        "violations": [],
    }
    runner_error: str | None = None
    try:
        comparison = runner.run()
    except Exception as exc:  # pragma: no cover - last-resort evidence path
        runner_error = f"{type(exc).__name__}: {exc}"
    finally:
        runner.close_execution_leases()
    if args.verify_only:
        if runner_error:
            print(
                f"CI foundation verify-only error: {sanitize_text(runner_error)}",
                file=sys.stderr,
            )
            return EXIT_POLICY_VIOLATION
        hard_failures = [item for item in runner.hard_gate_results if item["status"] != "pass"]
        status = "PASS" if not runner.violations and not hard_failures else "FAIL"
        print(f"CI foundation profile={args.profile} verify-only status={status}")
        return policy_status_exit_code(status)
    try:
        summary = write_evidence(
            runner,
            comparison,
            runner_error=runner_error,
            output_dir=evidence_output_dir,
            evidence_authority_root=evidence_authority_root,
        )
    except Exception as exc:  # pragma: no cover - evidence failure must be loud
        print(f"CI foundation evidence error: {type(exc).__name__}: {sanitize_text(str(exc))}", file=sys.stderr)
        return EXIT_RUNNER_ERROR
    finally:
        runner.cleanup_task_resources()
    print(f"CI foundation profile={args.profile} status={summary['status']}")
    if summary["executionBinding"]["bindingMode"] == "local":
        print(
            "Local verification invocation authority: "
            + summary["executionBinding"]["producerInvocationId"]
        )
    print(
        "Sanitized summary: "
        + (
            ".ci-results/summary.md"
            if evidence_output_dir == OUTPUT_DIR
            else "task-authorized-external/summary.md"
        )
    )
    return policy_status_exit_code(str(summary["status"]))


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--internal-linux-containment-supervisor":
        raise SystemExit(_linux_containment_supervisor_entrypoint(sys.argv[2:]))
    raise SystemExit(main())
