#!/usr/bin/env python3
"""Synthetic canonicality, identity, privacy, and release-gate tests for R1.1D."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
CORE = REPO_ROOT / "developer/generated-data-provenance-core.mjs"
VERIFIER = REPO_ROOT / "developer/verify-generated-data-provenance.mjs"
GATE = REPO_ROOT / "developer/verify-generated-data-release-gate.mjs"

RECORD_KIND = "ieltmps-generated-data-provenance"
REGISTRY_KIND = "ieltmps-generated-data-provenance-registry"
RELEASE_REFERENCE_KIND = "ieltmps-generated-data-release-reference"
SCHEMA_VERSION = 1

RECORD_KEYS = (
    "recordKind",
    "schemaVersion",
    "component",
    "preferredSource",
    "inputs",
    "generator",
    "deterministicPolicy",
    "outputs",
    "rights",
    "releaseEligible",
    "publicationBlocked",
)
COMPONENT_KEYS = (
    "componentId",
    "generationSetId",
    "recordId",
    "requiredDistributionScopes",
)
GIT_SOURCE_KEYS = ("kind", "projectId", "objectFormat", "commit", "tree")
COMMIT_SOURCE_KEYS = (*GIT_SOURCE_KEYS, "inputSetSha256")
ARCHIVE_SOURCE_KEYS = (
    "kind",
    "projectId",
    "revision",
    "format",
    "sha256",
    "byteLength",
    "memberManifestSha256",
)
INPUT_KEYS = (
    "role",
    "identifier",
    "sha256",
    "byteLength",
    "gitBlobId",
    "normalization",
)
GENERATOR_KEYS = (
    "projectId",
    "toolingCommit",
    "toolingTree",
    "entryPoint",
    "files",
    "runtime",
    "dependencies",
)
GENERATOR_FILE_KEYS = ("path", "gitBlobId", "sha256", "byteLength")
RUNTIME_KEYS = (
    "implementation",
    "version",
    "distributionSha256",
    "distributionByteLength",
)
DEPENDENCY_KEYS = (
    "role",
    "identifier",
    "version",
    "sha256",
    "byteLength",
    "gitBlobId",
)
POLICY_KEYS = (
    "policyId",
    "encoding",
    "bom",
    "lineEndings",
    "locale",
    "timezone",
    "unicodeNormalization",
    "caseFolding",
    "ordering",
    "sqlOrdering",
    "randomness",
    "timestamp",
    "filesystemEnumeration",
)
OUTPUT_KEYS = ("role", "identifier", "format", "sha256", "byteLength", "gitBlobId")
RIGHTS_KEYS = (
    "reviewStatus",
    "reviewedScope",
    "evidenceReferences",
    "licenseStatus",
    "licenseExpression",
    "sourceDistribution",
    "artifactDistribution",
    "reviewDecisionCommit",
)
EVIDENCE_KEYS = ("evidenceId", "sha256", "byteLength")
REGISTRY_KEYS = ("registryKind", "schemaVersion", "records")
REGISTRY_RECORD_KEYS = ("componentId", "recordId", "recordSha256", "relationship")
RELEASE_KEYS = ("releaseReferenceKind", "schemaVersion", "components")
RELEASE_COMPONENT_KEYS = (
    "componentId",
    "recordSha256",
    "outputSetSha256",
    "requiredEligibility",
)

LOWER_GIT_ID = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$")

CANARIES = {
    "source_repository_path": "CANARY_SOURCE_REPOSITORY_3a91",
    "tooling_repository_path": "CANARY_TOOLING_REPOSITORY_7b42",
    "input_path": "CANARY_INPUT_PATH_15ce",
    "output_path": "CANARY_OUTPUT_PATH_268d",
    "archive_path": "CANARY_ARCHIVE_PATH_39ef",
    "runtime_path": "CANARY_RUNTIME_PATH_4a10",
    "username": "CANARY_USERNAME_5b21",
    "drive": "CANARY_DRIVE_6c32",
    "hostname": "CANARY_HOSTNAME_7d43",
    "environment_variable": "CANARY_ENVIRONMENT_8e54",
    "branch": "CANARY_BRANCH_9f65",
    "remote": "CANARY_REMOTE_a076",
    "private_filename": "CANARY_PRIVATE_FILENAME_b187.private",
    "protected_component": "protected-CANARY-COMPONENT-c298",
}

GIT_REDIRECTION_NAMES = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_REPLACE_REF_BASE",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
}

PARSER_HARNESS = r"""
import { pathToFileURL } from "node:url";
let source = "";
for await (const chunk of process.stdin) source += chunk;
const request = JSON.parse(source);
try {
  const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
  const bytes = Buffer.from(request.bytesBase64, "base64");
  let value;
  if (request.kind === "record") value = core.parseCanonicalProvenanceRecord(bytes);
  else if (request.kind === "registry") value = core.parseCanonicalProvenanceRegistry(bytes);
  else if (request.kind === "release") value = core.parseCanonicalReleaseReference(bytes);
  else throw new Error("unknown parser kind");
  process.stdout.write(JSON.stringify({ ok: true, keys: Object.keys(value) }) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
    reason: typeof error?.reason === "string" ? error.reason : "parser-harness",
  }) + "\n");
}
"""

API_HARNESS = r"""
import { renameSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
let source = "";
for await (const chunk of process.stdin) source += chunk;
const request = JSON.parse(source);
const observations = { checkpoints: 0, contextsFrozen: true, resultFrozen: false };
const hooks = {
  checkpoint(context) {
    observations.checkpoints += 1;
    observations.contextsFrozen = observations.contextsFrozen && Object.isFrozen(context);
    if (
      request.actionKind === context.kind
      && context.checkpoint === "after-file-open"
      && request.mutationPath
    ) {
      renameSync(request.mutationPath, request.mutationPath + ".open-original");
      writeFileSync(request.mutationPath, Buffer.from("synthetic replacement bytes\n", "utf8"));
    }
    return undefined;
  },
};
try {
  const verifier = await import(pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href);
  const result = await verifier.verifyGeneratedDataProvenance({
    ...request.options,
    testHooks: hooks,
  });
  observations.resultFrozen = Object.isFrozen(result);
  process.stdout.write(JSON.stringify({ ok: true, result, observations }) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
    reason: typeof error?.reason === "string" ? error.reason : "api-harness",
    observations,
  }) + "\n");
}
"""

ELIGIBILITY_HARNESS = r"""
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const facts = {
  recordValid: true,
  preferredSourceVerified: true,
  inputsVerified: true,
  generatorVerified: true,
  deterministicPolicyValid: true,
  outputsVerified: true,
  replayVerified: true,
  rightsVerified: true,
};
const eligible = core.deriveEligibility(facts);
const unavailable = core.deriveEligibility({ ...facts, replayVerified: false });
process.stdout.write(JSON.stringify({ eligible, unavailable }) + "\n");
"""


def _find_node() -> Path:
    configured = os.environ.get("IELTMPS_NODE")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file():
            return candidate
        raise unittest.SkipTest("IELTMPS_NODE does not name a file")
    discovered = shutil.which("node")
    if discovered:
        return Path(discovered).resolve()
    raise unittest.SkipTest("node is unavailable")


def _find_git() -> Path:
    discovered = shutil.which("git")
    if discovered:
        return Path(discovered).resolve()
    raise unittest.SkipTest("git is unavailable")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_blob_id(value: bytes) -> str:
    header = f"blob {len(value)}\0".encode("ascii")
    return hashlib.sha1(header + value).hexdigest()


def _compact_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def _unsafe_json_bytes(value: object) -> bytes:
    """Encode deliberately invalid Python-built fixtures without invoking JavaScript."""
    return _compact_bytes(value)


def _assert_keys(value: dict[str, object], expected: tuple[str, ...], label: str) -> None:
    if not isinstance(value, dict) or tuple(value) != expected:
        raise ValueError(f"{label} key order is not canonical")


def _assert_ascii_tree(value: object) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < 0 or value > (2**53 - 1):
            raise ValueError("integer is outside canonical safe range")
        return
    if isinstance(value, str):
        if not value or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ValueError("string is not printable ASCII")
        if "\\" in value or '"' in value:
            raise ValueError("string would require an escape")
        return
    if isinstance(value, list):
        for entry in value:
            _assert_ascii_tree(entry)
        return
    if isinstance(value, dict):
        for key, entry in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError("JSON key is not ASCII")
            _assert_ascii_tree(entry)
        return
    raise ValueError("unsupported JSON scalar")


def _assert_lower_hash(value: object, pattern: re.Pattern[str], label: str) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{label} is not canonical lowercase hexadecimal")


def _validate_record_builder(value: dict[str, object]) -> None:
    _assert_keys(value, RECORD_KEYS, "record")
    if value["recordKind"] != RECORD_KIND or value["schemaVersion"] != SCHEMA_VERSION:
        raise ValueError("record identity is not canonical")
    component = value["component"]
    _assert_keys(component, COMPONENT_KEYS, "component")
    for key in ("componentId", "generationSetId", "recordId"):
        if not SAFE_TOKEN.fullmatch(str(component[key])):
            raise ValueError(f"{key} is not a safe token")
    source = value["preferredSource"]
    source_keys = {
        "git-commit": GIT_SOURCE_KEYS,
        "commit-owned-git-blob-set": COMMIT_SOURCE_KEYS,
        "immutable-upstream-archive": ARCHIVE_SOURCE_KEYS,
    }.get(source.get("kind"))
    if source_keys is None:
        raise ValueError("unknown preferred source kind")
    _assert_keys(source, source_keys, "preferredSource")
    if source["kind"] != "immutable-upstream-archive":
        _assert_lower_hash(source["commit"], LOWER_GIT_ID, "source commit")
        _assert_lower_hash(source["tree"], LOWER_GIT_ID, "source tree")
        if source["kind"] == "commit-owned-git-blob-set":
            _assert_lower_hash(source["inputSetSha256"], LOWER_SHA256, "input set")
    else:
        _assert_lower_hash(source["sha256"], LOWER_SHA256, "archive")
        _assert_lower_hash(source["memberManifestSha256"], LOWER_SHA256, "member manifest")
    inputs = value["inputs"]
    if not inputs:
        raise ValueError("canonical record input set is empty")
    for entry in inputs:
        _assert_keys(entry, INPUT_KEYS, "input")
        _assert_lower_hash(entry["sha256"], LOWER_SHA256, "input")
        if entry["gitBlobId"] is not None:
            _assert_lower_hash(entry["gitBlobId"], LOWER_GIT_ID, "input blob")
    if [(entry["role"], entry["identifier"]) for entry in inputs] != sorted(
        (entry["role"], entry["identifier"]) for entry in inputs
    ):
        raise ValueError("inputs are not canonical")
    generator = value["generator"]
    _assert_keys(generator, GENERATOR_KEYS, "generator")
    _assert_lower_hash(generator["toolingCommit"], LOWER_GIT_ID, "tooling commit")
    _assert_lower_hash(generator["toolingTree"], LOWER_GIT_ID, "tooling tree")
    for entry in generator["files"]:
        _assert_keys(entry, GENERATOR_FILE_KEYS, "generator file")
        _assert_lower_hash(entry["gitBlobId"], LOWER_GIT_ID, "generator blob")
        _assert_lower_hash(entry["sha256"], LOWER_SHA256, "generator file")
    if [entry["path"] for entry in generator["files"]] != sorted(
        entry["path"] for entry in generator["files"]
    ):
        raise ValueError("generator files are not canonical")
    _assert_keys(generator["runtime"], RUNTIME_KEYS, "runtime")
    _assert_lower_hash(
        generator["runtime"]["distributionSha256"], LOWER_SHA256, "runtime"
    )
    for entry in generator["dependencies"]:
        _assert_keys(entry, DEPENDENCY_KEYS, "dependency")
        _assert_lower_hash(entry["sha256"], LOWER_SHA256, "dependency")
        if entry["gitBlobId"] is not None:
            _assert_lower_hash(entry["gitBlobId"], LOWER_GIT_ID, "dependency blob")
    if [
        (entry["role"], entry["identifier"], entry["version"])
        for entry in generator["dependencies"]
    ] != sorted(
        (entry["role"], entry["identifier"], entry["version"])
        for entry in generator["dependencies"]
    ):
        raise ValueError("dependencies are not canonical")
    _assert_keys(value["deterministicPolicy"], POLICY_KEYS, "policy")
    _assert_keys(value["deterministicPolicy"]["randomness"], ("mode", "algorithm", "seedSha256"), "randomness")
    _assert_keys(value["deterministicPolicy"]["timestamp"], ("mode", "sourceIdentifier"), "timestamp")
    outputs = value["outputs"]
    if not outputs:
        raise ValueError("canonical record output set is empty")
    for entry in outputs:
        _assert_keys(entry, OUTPUT_KEYS, "output")
        _assert_lower_hash(entry["sha256"], LOWER_SHA256, "output")
        if entry["gitBlobId"] is not None:
            _assert_lower_hash(entry["gitBlobId"], LOWER_GIT_ID, "output blob")
    if [
        (entry["role"], entry["identifier"], entry["format"])
        for entry in outputs
    ] != sorted(
        (entry["role"], entry["identifier"], entry["format"])
        for entry in outputs
    ):
        raise ValueError("outputs are not canonical")
    rights = value["rights"]
    _assert_keys(rights, RIGHTS_KEYS, "rights")
    for entry in rights["evidenceReferences"]:
        _assert_keys(entry, EVIDENCE_KEYS, "evidence")
        _assert_lower_hash(entry["sha256"], LOWER_SHA256, "evidence")
    if value["releaseEligible"] is not False or value["publicationBlocked"] is not True:
        raise ValueError("foundation records must be stored ineligible")
    _assert_ascii_tree(value)


def _record_bytes(value: dict[str, object]) -> bytes:
    """Independent record encoder; it never calls the JavaScript encoder."""
    _validate_record_builder(value)
    encoded = _compact_bytes(value)
    if encoded.count(b"\n") != 1 or not encoded.endswith(b"\n") or b"\r" in encoded:
        raise ValueError("record framing is not canonical")
    return encoded


def _registry_bytes(value: dict[str, object]) -> bytes:
    _assert_keys(value, REGISTRY_KEYS, "registry")
    if value["registryKind"] != REGISTRY_KIND or value["schemaVersion"] != SCHEMA_VERSION:
        raise ValueError("registry identity is not canonical")
    for entry in value["records"]:
        _assert_keys(entry, REGISTRY_RECORD_KEYS, "registry record")
        _assert_lower_hash(entry["recordSha256"], LOWER_SHA256, "registry record")
    if [entry["componentId"] for entry in value["records"]] != sorted(
        entry["componentId"] for entry in value["records"]
    ):
        raise ValueError("registry records are not canonical")
    _assert_ascii_tree(value)
    return _compact_bytes(value)


def _release_bytes(value: dict[str, object]) -> bytes:
    _assert_keys(value, RELEASE_KEYS, "release reference")
    if (
        value["releaseReferenceKind"] != RELEASE_REFERENCE_KIND
        or value["schemaVersion"] != SCHEMA_VERSION
    ):
        raise ValueError("release reference identity is not canonical")
    for entry in value["components"]:
        _assert_keys(entry, RELEASE_COMPONENT_KEYS, "release component")
        _assert_lower_hash(entry["recordSha256"], LOWER_SHA256, "release record")
        _assert_lower_hash(entry["outputSetSha256"], LOWER_SHA256, "output set")
        if entry["requiredEligibility"] is not True:
            raise ValueError("requiredEligibility must be true")
    if [entry["componentId"] for entry in value["components"]] != sorted(
        entry["componentId"] for entry in value["components"]
    ):
        raise ValueError("release components are not canonical")
    _assert_ascii_tree(value)
    return _compact_bytes(value)


def _input_set_sha256(inputs: list[dict[str, object]]) -> str:
    payload = b"ieltmps-generated-input-set-v1\n" + _compact_bytes(inputs)
    return _sha256(payload)


def _output_set_sha256(outputs: list[dict[str, object]]) -> str:
    payload = b"ieltmps-generated-output-set-v1\n" + _compact_bytes(outputs)
    return _sha256(payload)


def _replace_once(value: bytes, old: bytes, new: bytes) -> bytes:
    if value.count(old) != 1:
        raise AssertionError(f"expected one mutation token, found {value.count(old)}")
    return value.replace(old, new, 1)


class GeneratedDataProvenanceTest(unittest.TestCase):
    """Every mutable provenance fixture and Git repository is synthetic and temporary."""

    maxDiff = None
    malformed_record_subcases = 0
    malformed_registry_subcases = 0
    malformed_release_reference_subcases = 0
    privacy_canary_count = len(CANARIES)

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        cls.git = _find_git()
        if not all(path.is_file() for path in (CORE, VERIFIER, GATE)):
            raise unittest.SkipTest("R1.1D draft source is unavailable")

        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-generated-provenance-template-"
        )
        cls.template_base = Path(cls.template_temp.name).resolve()
        cls.source_template = cls.template_base / CANARIES["source_repository_path"]
        cls.tooling_template = cls.template_base / CANARIES["tooling_repository_path"]
        cls.source_template.mkdir()
        cls.tooling_template.mkdir()

        cls._init_repo(cls.source_template)
        cls._write_at(cls.source_template, "data/a.txt", b"synthetic source alpha\n")
        cls._write_at(cls.source_template, "data/b.txt", b"synthetic source beta\n")
        cls._git_at(cls.source_template, "checkout", "-b", CANARIES["branch"])
        cls._git_at(cls.source_template, "add", "-A")
        cls._git_at(
            cls.source_template,
            "commit",
            "-m",
            "synthetic historical source",
            commit_date="2001-02-03T04:05:06Z",
        )
        cls.source_commit = cls._rev_parse(cls.source_template, "HEAD")
        cls.source_tree = cls._rev_parse(cls.source_template, f"{cls.source_commit}^{{tree}}")
        cls._git_at(
            cls.source_template,
            "remote",
            "add",
            "origin",
            f"https://example.invalid/{CANARIES['remote']}.git",
        )

        cls._init_repo(cls.tooling_template)
        cls._write_at(
            cls.tooling_template,
            "tools/gen.mjs",
            b"export function syntheticGenerator() { return 'not executed'; }\n",
        )
        cls._write_at(
            cls.tooling_template,
            "tools/support.mjs",
            b"export const syntheticSupport = true;\n",
        )
        cls._write_at(
            cls.tooling_template,
            "deps/lock.json",
            b'{"dependency":"synthetic","version":"1.0.0"}\n',
        )
        cls._git_at(cls.tooling_template, "add", "-A")
        cls._git_at(
            cls.tooling_template,
            "commit",
            "-m",
            "synthetic tooling identity",
            commit_date="2002-03-04T05:06:07Z",
        )
        cls.tooling_commit = cls._rev_parse(cls.tooling_template, "HEAD")
        cls.tooling_tree = cls._rev_parse(
            cls.tooling_template, f"{cls.tooling_commit}^{{tree}}"
        )
        if cls.source_commit == cls.tooling_commit:
            raise AssertionError("source and tooling commits must be different")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()
        duration = time.monotonic() - cls.started
        methods = len(unittest.defaultTestLoader.getTestCaseNames(cls))
        print(
            "PROVENANCE_COVERAGE "
            f"test_methods={methods} "
            f"malformed_record_subcases={cls.malformed_record_subcases} "
            f"malformed_registry_subcases={cls.malformed_registry_subcases} "
            "malformed_release_reference_subcases="
            f"{cls.malformed_release_reference_subcases} "
            f"privacy_canaries={cls.privacy_canary_count} "
            f"duration_seconds={duration:.3f}"
        )

    @classmethod
    def _environment(cls, updates: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        path_parts = [str(cls.git.parent), str(cls.node.parent)]
        if environment.get("PATH"):
            path_parts.append(environment["PATH"])
        environment["PATH"] = os.pathsep.join(path_parts)
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        environment["IELTMPS_TEST_VERIFIER"] = str(VERIFIER)
        environment["IELTMPS_TEST_GATE"] = str(GATE)
        environment["IELTMPS_TEST_USERNAME"] = CANARIES["username"]
        environment["IELTMPS_TEST_DRIVE"] = CANARIES["drive"]
        environment["IELTMPS_TEST_HOSTNAME"] = CANARIES["hostname"]
        environment["IELTMPS_TEST_ENV"] = CANARIES["environment_variable"]
        if updates:
            environment.update(updates)
        return environment

    @classmethod
    def _git_at(
        cls,
        root: Path,
        *args: str,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
        commit_date: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = cls._environment()
        for name in GIT_REDIRECTION_NAMES:
            environment.pop(name, None)
        if commit_date is not None:
            environment["GIT_AUTHOR_DATE"] = commit_date
            environment["GIT_COMMITTER_DATE"] = commit_date
        completed = subprocess.run(
            [str(cls.git), "-C", str(root), *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            timeout=60,
        )
        if completed.returncode != 0 and not allow_failure:
            raise AssertionError(completed.stdout.decode("utf-8", errors="replace"))
        return completed

    @classmethod
    def _init_repo(cls, root: Path) -> None:
        cls._git_at(root, "init")
        for key, value in (
            ("user.name", CANARIES["username"]),
            ("user.email", "synthetic-provenance@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git_at(root, "config", key, value)

    @staticmethod
    def _write_at(root: Path, relative: str, value: bytes) -> None:
        target = root / PurePosixPath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)

    @classmethod
    def _rev_parse(cls, root: Path, value: str) -> str:
        return cls._git_at(root, "rev-parse", value).stdout.decode("ascii").strip()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-generated-provenance-case-"
        )
        self.case_base = Path(self.case_temp.name).resolve()
        self.source_repo = self.case_base / CANARIES["source_repository_path"]
        self.tooling_repo = self.case_base / CANARIES["tooling_repository_path"]
        shutil.copytree(self.source_template, self.source_repo)
        shutil.copytree(self.tooling_template, self.tooling_repo)

        self.external_input = self.case_base / f"{CANARIES['input_path']}.txt"
        self.archive_input = self.case_base / "archive-input-a.txt"
        self.external_dependency = (
            self.case_base / CANARIES["private_filename"]
        )
        self.runtime = self.case_base / f"{CANARIES['runtime_path']}.bin"
        self.output_index = self.case_base / f"{CANARIES['output_path']}-index.json"
        self.output_payload = self.case_base / f"{CANARIES['output_path']}-payload.txt"
        self.archive = self.case_base / f"{CANARIES['archive_path']}.bin"
        self.member_manifest = self.case_base / "synthetic-member-manifest.json"

        self.external_input.write_bytes(b"synthetic external input\n")
        self.archive_input.write_bytes(b"synthetic source alpha\n")
        self.external_dependency.write_bytes(b"synthetic external dependency\n")
        self.runtime.write_bytes(b"synthetic immutable runtime distribution\n")
        self.output_index.write_bytes(b'{"synthetic":true}\n')
        self.output_payload.write_bytes(b"synthetic output payload\n")
        self.archive.write_bytes(b"synthetic immutable archive bytes\x00\x01\n")
        self.member_manifest.write_bytes(b'{"members":[]}\n')

        self.record_path = self.case_base / "synthetic-record.json"
        self.registry_path = self.case_base / "synthetic-registry.json"
        self.release_path = self.case_base / "synthetic-release-reference.json"

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    def _git(self, root: Path, *args: str, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return self._git_at(root, *args, **kwargs)

    def _blob_identity(self, root: Path, commit: str, relative: str) -> dict[str, object]:
        record = self._git(root, "ls-tree", commit, "--", relative).stdout.decode(
            "utf-8"
        ).strip()
        match = re.fullmatch(r"(100644|100755) blob ([0-9a-f]{40})\t(.+)", record)
        if not match or match.group(3) != relative:
            raise AssertionError(f"unexpected synthetic tree record: {record}")
        blob_id = match.group(2)
        value = self._git(root, "cat-file", "blob", blob_id).stdout
        return {
            "gitBlobId": blob_id,
            "sha256": _sha256(value),
            "byteLength": len(value),
            "bytes": value,
        }

    @staticmethod
    def _file_identity(path_value: Path, *, git_blob: bool = False) -> dict[str, object]:
        value = path_value.read_bytes()
        return {
            "sha256": _sha256(value),
            "byteLength": len(value),
            "gitBlobId": _git_blob_id(value) if git_blob else None,
        }

    def _rights(self, mode: str = "reviewed") -> dict[str, object]:
        if mode == "unresolved":
            return {
                "reviewStatus": "unresolved",
                "reviewedScope": [],
                "evidenceReferences": [],
                "licenseStatus": "unresolved",
                "licenseExpression": None,
                "sourceDistribution": "unresolved",
                "artifactDistribution": "unresolved",
                "reviewDecisionCommit": None,
            }
        if mode == "blocked":
            return {
                "reviewStatus": "blocked",
                "reviewedScope": [],
                "evidenceReferences": [
                    {
                        "evidenceId": "synthetic-rights-evidence",
                        "sha256": _sha256(b"synthetic rights evidence\n"),
                        "byteLength": len(b"synthetic rights evidence\n"),
                    }
                ],
                "licenseStatus": "identified",
                "licenseExpression": "LicenseRef-Synthetic",
                "sourceDistribution": "denied",
                "artifactDistribution": "denied",
                "reviewDecisionCommit": None,
            }
        return {
            "reviewStatus": "reviewed",
            "reviewedScope": [
                "preferred-source",
                "inputs",
                "generator",
                "outputs",
                "source-distribution",
                "artifact-distribution",
            ],
            "evidenceReferences": [
                {
                    "evidenceId": "synthetic-rights-evidence",
                    "sha256": _sha256(b"synthetic rights evidence\n"),
                    "byteLength": len(b"synthetic rights evidence\n"),
                }
            ],
            "licenseStatus": "identified",
            "licenseExpression": "LicenseRef-Synthetic",
            "sourceDistribution": "approved",
            "artifactDistribution": "approved",
            "reviewDecisionCommit": self.tooling_commit,
        }

    def _policy(
        self,
        *,
        normalization: str = "nfc",
        randomness: str = "forbidden",
        timestamp: str = "forbidden",
    ) -> dict[str, object]:
        randomness_value = (
            {"mode": "forbidden", "algorithm": None, "seedSha256": None}
            if randomness == "forbidden"
            else {
                "mode": "fixed-seed",
                "algorithm": "synthetic-prng-v1",
                "seedSha256": _sha256(b"synthetic fixed seed"),
            }
        )
        timestamp_value = (
            {"mode": "forbidden", "sourceIdentifier": None}
            if timestamp == "forbidden"
            else {"mode": "source-defined", "sourceIdentifier": "source-metadata"}
        )
        return {
            "policyId": "ieltmps-generated-data-determinism-v1",
            "encoding": "utf-8",
            "bom": "forbidden",
            "lineEndings": "lf",
            "locale": "C",
            "timezone": "UTC",
            "unicodeNormalization": normalization,
            "caseFolding": "none",
            "ordering": "unsigned-utf8-byte-order",
            "sqlOrdering": "explicit-complete-order-by",
            "randomness": randomness_value,
            "timestamp": timestamp_value,
            "filesystemEnumeration": "forbidden",
        }

    def _record(
        self,
        *,
        source_kind: str = "git-commit",
        rights: str = "reviewed",
        input_normalization: str = "utf8-nfc-lf-v1",
        policy_normalization: str = "nfc",
        randomness: str = "forbidden",
        timestamp: str = "forbidden",
    ) -> dict[str, object]:
        source_blob = self._blob_identity(
            self.source_repo, self.source_commit, "data/a.txt"
        )
        external_input = self._file_identity(self.external_input)
        archive_input = self._file_identity(self.archive_input)
        if source_kind == "immutable-upstream-archive":
            inputs = [
                {
                    "role": "alpha",
                    "identifier": "archive-input-a",
                    "sha256": archive_input["sha256"],
                    "byteLength": archive_input["byteLength"],
                    "gitBlobId": None,
                    "normalization": input_normalization,
                },
                {
                    "role": "beta",
                    "identifier": "external-input",
                    "sha256": external_input["sha256"],
                    "byteLength": external_input["byteLength"],
                    "gitBlobId": None,
                    "normalization": "raw-bytes-v1",
                },
            ]
            preferred_source = {
                "kind": "immutable-upstream-archive",
                "projectId": "synthetic-upstream",
                "revision": "synthetic-revision-1",
                "format": "synthetic-archive-v1",
                "sha256": _sha256(self.archive.read_bytes()),
                "byteLength": self.archive.stat().st_size,
                "memberManifestSha256": _sha256(self.member_manifest.read_bytes()),
            }
        else:
            inputs = [
                {
                    "role": "alpha",
                    "identifier": "data/a.txt",
                    "sha256": source_blob["sha256"],
                    "byteLength": source_blob["byteLength"],
                    "gitBlobId": source_blob["gitBlobId"],
                    "normalization": input_normalization,
                },
                {
                    "role": "beta",
                    "identifier": "external-input",
                    "sha256": external_input["sha256"],
                    "byteLength": external_input["byteLength"],
                    "gitBlobId": None,
                    "normalization": "raw-bytes-v1",
                },
            ]
            preferred_source = {
                "kind": source_kind,
                "projectId": "synthetic-source",
                "objectFormat": "sha1",
                "commit": self.source_commit,
                "tree": self.source_tree,
            }
            if source_kind == "commit-owned-git-blob-set":
                preferred_source["inputSetSha256"] = _input_set_sha256(inputs)

        generator_files = []
        for relative in ("tools/gen.mjs", "tools/support.mjs"):
            identity = self._blob_identity(
                self.tooling_repo, self.tooling_commit, relative
            )
            generator_files.append(
                {
                    "path": relative,
                    "gitBlobId": identity["gitBlobId"],
                    "sha256": identity["sha256"],
                    "byteLength": identity["byteLength"],
                }
            )
        git_dependency = self._blob_identity(
            self.tooling_repo, self.tooling_commit, "deps/lock.json"
        )
        external_dependency = self._file_identity(self.external_dependency)
        runtime = self._file_identity(self.runtime)
        index_identity = self._file_identity(self.output_index, git_blob=True)
        payload_identity = self._file_identity(self.output_payload)
        return {
            "recordKind": RECORD_KIND,
            "schemaVersion": SCHEMA_VERSION,
            "component": {
                "componentId": "synthetic-component",
                "generationSetId": "synthetic-generation-v1",
                "recordId": "synthetic-record-v1",
                "requiredDistributionScopes": ["source", "artifact"],
            },
            "preferredSource": preferred_source,
            "inputs": inputs,
            "generator": {
                "projectId": "synthetic-tooling",
                "toolingCommit": self.tooling_commit,
                "toolingTree": self.tooling_tree,
                "entryPoint": "tools/gen.mjs",
                "files": generator_files,
                "runtime": {
                    "implementation": "synthetic-runtime",
                    "version": "1.0.0",
                    "distributionSha256": runtime["sha256"],
                    "distributionByteLength": runtime["byteLength"],
                },
                "dependencies": [
                    {
                        "role": "config",
                        "identifier": "deps/lock.json",
                        "version": "1.0.0",
                        "sha256": git_dependency["sha256"],
                        "byteLength": git_dependency["byteLength"],
                        "gitBlobId": git_dependency["gitBlobId"],
                    },
                    {
                        "role": "library",
                        "identifier": "synthetic-lib",
                        "version": "2.0.0",
                        "sha256": external_dependency["sha256"],
                        "byteLength": external_dependency["byteLength"],
                        "gitBlobId": None,
                    },
                ],
            },
            "deterministicPolicy": self._policy(
                normalization=policy_normalization,
                randomness=randomness,
                timestamp=timestamp,
            ),
            "outputs": [
                {
                    "role": "index",
                    "identifier": "out/index.json",
                    "format": "json",
                    "sha256": index_identity["sha256"],
                    "byteLength": index_identity["byteLength"],
                    "gitBlobId": index_identity["gitBlobId"],
                },
                {
                    "role": "payload",
                    "identifier": "out/payload.txt",
                    "format": "text",
                    "sha256": payload_identity["sha256"],
                    "byteLength": payload_identity["byteLength"],
                    "gitBlobId": None,
                },
            ],
            "rights": self._rights(rights),
            "releaseEligible": False,
            "publicationBlocked": True,
        }

    def _record_options(
        self, record: dict[str, object], record_path: Path | None = None
    ) -> dict[str, object]:
        input_paths = {
            "archive-input-a": self.archive_input,
            "external-input": self.external_input,
        }
        options: dict[str, object] = {
            "record": str(record_path or self.record_path),
            "toolingRepo": str(self.tooling_repo),
            "runtimeExecutable": str(self.runtime),
            "inputs": [
                {
                    "role": entry["role"],
                    "identifier": entry["identifier"],
                    "path": str(input_paths[entry["identifier"]]),
                }
                for entry in record["inputs"]
                if entry["gitBlobId"] is None
            ],
            "dependencies": [
                {
                    "role": "library",
                    "identifier": "synthetic-lib",
                    "path": str(self.external_dependency),
                }
            ],
            "outputs": [
                {
                    "role": "index",
                    "identifier": "out/index.json",
                    "format": "json",
                    "path": str(self.output_index),
                },
                {
                    "role": "payload",
                    "identifier": "out/payload.txt",
                    "format": "text",
                    "path": str(self.output_payload),
                },
            ],
        }
        if record["preferredSource"]["kind"] == "immutable-upstream-archive":
            options["sourceArchive"] = str(self.archive)
            options["sourceMemberManifest"] = str(self.member_manifest)
        else:
            options["sourceRepo"] = str(self.source_repo)
        return options

    def _record_arguments(self, record: dict[str, object], record_path: Path | None = None) -> list[str]:
        options = self._record_options(record, record_path)
        arguments = [
            "--record",
            str(options["record"]),
            "--tooling-repo",
            str(options["toolingRepo"]),
            "--runtime-executable",
            str(options["runtimeExecutable"]),
        ]
        if "sourceRepo" in options:
            arguments.extend(["--source-repo", str(options["sourceRepo"])])
        else:
            arguments.extend(
                [
                    "--source-archive",
                    str(options["sourceArchive"]),
                    "--source-member-manifest",
                    str(options["sourceMemberManifest"]),
                ]
            )
        for binding in options["inputs"]:
            arguments.extend(
                ["--input", binding["role"], binding["identifier"], binding["path"]]
            )
        for binding in options["dependencies"]:
            arguments.extend(
                [
                    "--dependency",
                    binding["role"],
                    binding["identifier"],
                    binding["path"],
                ]
            )
        for binding in options["outputs"]:
            arguments.extend(
                [
                    "--output",
                    binding["role"],
                    binding["identifier"],
                    binding["format"],
                    binding["path"],
                ]
            )
        return arguments

    def _run_node(
        self,
        script: Path | str,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        environment_updates: dict[str, str] | None = None,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.node), str(script), *arguments],
            cwd=cwd or self.case_base,
            env=self._environment(environment_updates),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def _run_record_cli(
        self,
        record: dict[str, object],
        *,
        record_path: Path | None = None,
        script: Path | str = VERIFIER,
        cwd: Path | None = None,
        environment_updates: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_node(
            script,
            self._record_arguments(record, record_path),
            cwd=cwd,
            environment_updates=environment_updates,
        )

    def _parse(self, kind: str, value: bytes) -> dict[str, object]:
        request = {
            "kind": kind,
            "bytesBase64": base64.b64encode(value).decode("ascii"),
        }
        completed = subprocess.run(
            [
                str(self.node),
                "--input-type=module",
                "--eval",
                PARSER_HARNESS,
                "synthetic-parser-sentinel",
            ],
            cwd=self.case_base,
            env=self._environment(),
            input=json.dumps(request, separators=(",", ":")),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        return json.loads(completed.stdout)

    def _run_api_race(
        self,
        record: dict[str, object],
        action_kind: str,
        mutation_path: Path,
    ) -> dict[str, object]:
        request = {
            "options": self._record_options(record),
            "actionKind": action_kind,
            "mutationPath": str(mutation_path),
        }
        completed = subprocess.run(
            [
                str(self.node),
                "--input-type=module",
                "--eval",
                API_HARNESS,
                "synthetic-api-sentinel",
            ],
            cwd=self.case_base,
            env=self._environment(),
            input=json.dumps(request, separators=(",", ":")),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        return json.loads(completed.stdout)

    def _assert_cli_success(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout.count("\n"), 1, result.stdout)
        return json.loads(result.stdout)

    def _assert_cli_error(
        self,
        result: subprocess.CompletedProcess[str],
        phase: str,
        reason: str | None = None,
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.count("\n"), 1, result.stderr)
        self.assertTrue(result.stderr.startswith(f"ERROR {phase}: "), result.stderr)
        if reason is not None:
            self.assertEqual(result.stderr, f"ERROR {phase}: {reason}\n")
        self.assertNotIn("\n    at ", result.stderr)

    def _assert_typed_parser_error(
        self, kind: str, value: bytes, phase: str, reason: str
    ) -> None:
        result = self._parse(kind, value)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["phase"], phase, result)
        self.assertEqual(result["reason"], reason, result)

    def _assert_no_canary(self, value: str | bytes) -> None:
        haystack = value if isinstance(value, bytes) else value.encode("utf-8")
        for label, canary in CANARIES.items():
            with self.subTest(canary=label):
                self.assertNotIn(canary.encode("utf-8"), haystack)

    def _write_record(self, record: dict[str, object], path_value: Path | None = None) -> bytes:
        value = _record_bytes(record)
        (path_value or self.record_path).write_bytes(value)
        return value

    def _empty_registry(self) -> dict[str, object]:
        return {"registryKind": REGISTRY_KIND, "schemaVersion": 1, "records": []}

    def _empty_release(self) -> dict[str, object]:
        return {
            "releaseReferenceKind": RELEASE_REFERENCE_KIND,
            "schemaVersion": 1,
            "components": [],
        }

    def _run_gate(
        self,
        registry: dict[str, object],
        release: dict[str, object],
        records: list[tuple[str, Path]] | None = None,
        *,
        registry_path: Path | None = None,
        release_path: Path | None = None,
        script: Path | str = GATE,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_registry = registry_path or self.registry_path
        selected_release = release_path or self.release_path
        selected_registry.write_bytes(_registry_bytes(registry))
        selected_release.write_bytes(_release_bytes(release))
        arguments = [
            "--registry",
            str(selected_registry),
            "--release-reference",
            str(selected_release),
        ]
        for component_id, record_path in records or []:
            arguments.extend(["--record", component_id, str(record_path)])
        return self._run_node(script, arguments, cwd=cwd)

    def test_01_git_sources_full_identity_and_deterministic_results(self) -> None:
        for source_kind in ("git-commit", "commit-owned-git-blob-set"):
            with self.subTest(source_kind=source_kind):
                record = self._record(source_kind=source_kind)
                record_bytes = self._write_record(record)
                first = self._assert_cli_success(self._run_record_cli(record))
                second = self._assert_cli_success(self._run_record_cli(record))
                self.assertEqual(first, second)
                self.assertEqual(first["status"], "ok")
                self.assertEqual(first["mode"], "provenance-verification")
                self.assertEqual(first["recordKind"], RECORD_KIND)
                self.assertEqual(first["schemaVersion"], 1)
                self.assertEqual(first["recordSha256"], _sha256(record_bytes))
                self.assertEqual(first["recordByteLength"], len(record_bytes))
                self.assertEqual(
                    first["outputSetSha256"], _output_set_sha256(record["outputs"])
                )
                self.assertTrue(first["recordValid"])
                self.assertTrue(first["preferredSourceVerified"])
                self.assertTrue(first["inputsVerified"])
                self.assertTrue(first["generatorVerified"])
                self.assertTrue(first["deterministicPolicyValid"])
                self.assertTrue(first["outputsVerified"])
                self.assertTrue(first["rightsVerified"])
                self.assertFalse(first["replayVerified"])
                self.assertFalse(first["releaseEligible"])
                self.assertTrue(first["publicationBlocked"])
                self.assertNotEqual(self.source_commit, self.tooling_commit)

                # A dirty working tree is never used as Git-backed input authority.
                (self.source_repo / "data/a.txt").write_bytes(
                    b"dirty working tree bytes that are not authoritative\n"
                )
                dirty = self._assert_cli_success(self._run_record_cli(record))
                self.assertEqual(dirty, first)
                shutil.copyfile(
                    self.source_template / "data/a.txt", self.source_repo / "data/a.txt"
                )

    def test_02_archive_source_policy_variants_and_unresolved_rights(self) -> None:
        variants = (
            ("reviewed", "utf8-nfc-lf-v1", "nfc", "fixed-seed", "source-defined"),
            ("unresolved", "raw-bytes-v1", "none", "forbidden", "forbidden"),
            ("blocked", "utf8-nfc-lf-v1", "nfc", "forbidden", "forbidden"),
        )
        for index, (rights, input_normalization, policy_normalization, randomness, timestamp) in enumerate(variants):
            with self.subTest(rights=rights):
                record = self._record(
                    source_kind="immutable-upstream-archive",
                    rights=rights,
                    input_normalization=input_normalization,
                    policy_normalization=policy_normalization,
                    randomness=randomness,
                    timestamp=timestamp,
                )
                target = self.case_base / f"archive-record-{index}.json"
                self._write_record(record, target)
                result = self._assert_cli_success(
                    self._run_record_cli(record, record_path=target)
                )
                self.assertTrue(result["preferredSourceVerified"])
                self.assertEqual(result["rightsVerified"], rights == "reviewed")
                self.assertFalse(result["replayVerified"])
                self.assertFalse(result["releaseEligible"])
                self.assertTrue(result["publicationBlocked"])

    def test_03_pure_eligibility_helper_cannot_change_production_replay(self) -> None:
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", ELIGIBILITY_HARNESS],
            cwd=self.case_base,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(
            payload["eligible"],
            {"releaseEligible": True, "publicationBlocked": False},
        )
        self.assertEqual(
            payload["unavailable"],
            {"releaseEligible": False, "publicationBlocked": True},
        )
        record = self._record()
        self._write_record(record)
        production = self._assert_cli_success(self._run_record_cli(record))
        self.assertFalse(production["replayVerified"])
        self.assertNotIn("replay", " ".join(self._record_arguments(record)).lower())

    def test_04_canonical_record_malformed_bytes_have_exact_typed_reasons(self) -> None:
        record = self._record()
        baseline = self._write_record(record)
        output_hash = record["outputs"][0]["sha256"].encode("ascii")
        output_length = str(record["outputs"][0]["byteLength"]).encode("ascii")

        reordered_inputs = copy.deepcopy(record)
        reordered_inputs["inputs"] = list(reversed(reordered_inputs["inputs"]))
        reordered_outputs = copy.deepcopy(record)
        reordered_outputs["outputs"] = list(reversed(reordered_outputs["outputs"]))
        duplicate_input = copy.deepcopy(record)
        duplicate_input["inputs"][1]["role"] = duplicate_input["inputs"][0]["role"]
        duplicate_output = copy.deepcopy(record)
        duplicate_output["outputs"][1]["role"] = duplicate_output["outputs"][0]["role"]
        unknown_source = copy.deepcopy(record)
        unknown_source["preferredSource"] = {
            "kind": "branch",
            "projectId": "synthetic-source",
        }
        unknown_rights = copy.deepcopy(record)
        unknown_rights["rights"]["reviewStatus"] = "assumed"
        stored_eligible = copy.deepcopy(record)
        stored_eligible["releaseEligible"] = True
        stored_unblocked = copy.deepcopy(record)
        stored_unblocked["publicationBlocked"] = False
        mutable_generation_set = copy.deepcopy(record)
        mutable_generation_set["component"]["generationSetId"] = "current"
        mutable_record_id = copy.deepcopy(record)
        mutable_record_id["component"]["recordId"] = "latest"

        cases: list[tuple[str, bytes, str, str]] = [
            (
                "wrong-kind",
                _replace_once(baseline, RECORD_KIND.encode("ascii"), b"wrong-record-kind"),
                "RECORD_SCHEMA",
                "record-kind",
            ),
            (
                "wrong-version",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":2'),
                "RECORD_SCHEMA",
                "schema-version",
            ),
            (
                "unknown-field",
                _replace_once(
                    baseline,
                    b',"releaseEligible":false',
                    b',"unknownField":0,"releaseEligible":false',
                ),
                "RECORD_SCHEMA",
                "top-level-unknown-field",
            ),
            (
                "missing-field",
                _replace_once(baseline, b',"publicationBlocked":true', b""),
                "RECORD_SCHEMA",
                "top-level-missing-field",
            ),
            (
                "reordered-field",
                _replace_once(
                    baseline,
                    b'{"recordKind":"' + RECORD_KIND.encode("ascii") + b'","schemaVersion":1',
                    b'{"schemaVersion":1,"recordKind":"' + RECORD_KIND.encode("ascii") + b'"',
                ),
                "RECORD_SCHEMA",
                "top-level-key-order",
            ),
            (
                "duplicate-key",
                _replace_once(
                    baseline,
                    b'"schemaVersion":1',
                    b'"recordKind":"' + RECORD_KIND.encode("ascii") + b'","schemaVersion":1',
                ),
                "RECORD_SCHEMA",
                "duplicate-key",
            ),
            (
                "extra-whitespace",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion": 1'),
                "RECORD_SCHEMA",
                "noncanonical-whitespace",
            ),
            ("crlf", baseline[:-1] + b"\r\n", "RECORD_SCHEMA", "crlf-or-cr"),
            ("internal-lf", baseline[:1] + b"\n" + baseline[1:], "RECORD_SCHEMA", "internal-lf"),
            ("missing-final-lf", baseline[:-1], "RECORD_SCHEMA", "missing-final-lf"),
            ("extra-final-lf", baseline + b"\n", "RECORD_SCHEMA", "extra-final-lf"),
            ("bom", b"\xef\xbb\xbf" + baseline, "RECORD_SCHEMA", "utf8-bom"),
            (
                "escaped-safe-ascii",
                _replace_once(baseline, b"synthetic-component", b"synthetic\\u002dcomponent"),
                "RECORD_SCHEMA",
                "string-escape",
            ),
            (
                "non-ascii",
                _replace_once(baseline, b"synthetic-component", "synthétic-component".encode("utf-8")),
                "RECORD_SCHEMA",
                "non-ascii-string",
            ),
            (
                "uppercase-hash",
                _replace_once(baseline, output_hash, output_hash.upper()),
                "OUTPUT",
                "output-sha256",
            ),
            (
                "short-hash",
                _replace_once(baseline, output_hash, output_hash[:-1]),
                "OUTPUT",
                "output-sha256",
            ),
            (
                "leading-zero",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":01'),
                "RECORD_SCHEMA",
                "integer-leading-zero",
            ),
            (
                "negative-integer",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":-1'),
                "RECORD_SCHEMA",
                "integer-negative",
            ),
            (
                "floating-integer",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":1.0'),
                "RECORD_SCHEMA",
                "integer-fraction",
            ),
            (
                "exponent-integer",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":1e0'),
                "RECORD_SCHEMA",
                "integer-exponent",
            ),
            (
                "unsafe-integer",
                _replace_once(
                    baseline,
                    b'"byteLength":' + output_length,
                    b'"byteLength":9007199254740992',
                ),
                "RECORD_SCHEMA",
                "integer-range",
            ),
            (
                "unexpected-null",
                _replace_once(baseline, b'"schemaVersion":1', b'"schemaVersion":null'),
                "RECORD_SCHEMA",
                "schema-version",
            ),
            ("reordered-inputs", _unsafe_json_bytes(reordered_inputs), "INPUT", "input-order"),
            ("reordered-outputs", _unsafe_json_bytes(reordered_outputs), "OUTPUT", "output-order"),
            (
                "duplicate-input",
                _unsafe_json_bytes(duplicate_input),
                "INPUT",
                "duplicate-input-role",
            ),
            (
                "duplicate-output",
                _unsafe_json_bytes(duplicate_output),
                "OUTPUT",
                "duplicate-output-role",
            ),
            (
                "unknown-source-kind",
                _unsafe_json_bytes(unknown_source),
                "PREFERRED_SOURCE",
                "unknown-source-kind",
            ),
            (
                "unknown-rights-value",
                _unsafe_json_bytes(unknown_rights),
                "RIGHTS",
                "review-status",
            ),
            (
                "stored-eligibility",
                _unsafe_json_bytes(stored_eligible),
                "RECORD_SCHEMA",
                "stored-release-eligible-mismatch",
            ),
            (
                "stored-publication",
                _unsafe_json_bytes(stored_unblocked),
                "RECORD_SCHEMA",
                "stored-publication-blocked-mismatch",
            ),
            (
                "mutable-generation-set-id",
                _unsafe_json_bytes(mutable_generation_set),
                "RECORD_SCHEMA",
                "generation-set-id",
            ),
            (
                "mutable-record-id",
                _unsafe_json_bytes(mutable_record_id),
                "RECORD_SCHEMA",
                "record-id",
            ),
        ]
        for label, malformed, phase, reason in cases:
            with self.subTest(case=label):
                self.assertNotEqual(malformed, baseline)
                self._assert_typed_parser_error("record", malformed, phase, reason)
        type(self).malformed_record_subcases += len(cases)

    def test_05_deterministic_policy_is_explicit_and_environment_independent(self) -> None:
        record = self._record(randomness="fixed-seed", timestamp="source-defined")
        baseline = self._write_record(record)
        first = self._assert_cli_success(
            self._run_record_cli(
                record,
                environment_updates={"LC_ALL": "synthetic-locale-a", "TZ": "Synthetic/One"},
            )
        )
        second = self._assert_cli_success(
            self._run_record_cli(
                record,
                environment_updates={"LC_ALL": "synthetic-locale-b", "TZ": "Synthetic/Two"},
            )
        )
        self.assertEqual(first, second)
        self.assertTrue(first["deterministicPolicyValid"])

        cases: list[tuple[str, dict[str, object], str]] = []
        mutations = {
            "wrong-encoding": ("encoding", "utf-16", "policy-encoding"),
            "bom-allowed": ("bom", "allowed", "policy-bom"),
            "crlf-policy": ("lineEndings", "crlf", "policy-line-endings"),
            "non-c-locale": ("locale", "en-US", "policy-locale"),
            "non-utc-timezone": ("timezone", "local", "policy-timezone"),
            "implicit-sort": ("ordering", "locale-sort", "policy-ordering"),
            "filesystem-enumeration": (
                "filesystemEnumeration",
                "allowed",
                "policy-filesystem-enumeration",
            ),
            "unknown-normalization": (
                "unicodeNormalization",
                "nfkc",
                "policy-unicode-normalization",
            ),
            "unknown-case-fold": ("caseFolding", "locale", "policy-case-folding"),
            "sql-ordering-absent": ("sqlOrdering", "implicit", "policy-sql-ordering"),
        }
        for label, (key, value, reason) in mutations.items():
            changed = copy.deepcopy(record)
            changed["deterministicPolicy"][key] = value
            cases.append((label, changed, reason))
        current_time = copy.deepcopy(record)
        current_time["deterministicPolicy"]["timestamp"] = {
            "mode": "current-time",
            "sourceIdentifier": None,
        }
        cases.append(("current-time", current_time, "timestamp-mode"))
        random_without_seed = copy.deepcopy(record)
        random_without_seed["deterministicPolicy"]["randomness"] = {
            "mode": "random",
            "algorithm": None,
            "seedSha256": None,
        }
        cases.append(("random-without-seed", random_without_seed, "randomness-mode"))
        fixed_without_algorithm = copy.deepcopy(record)
        fixed_without_algorithm["deterministicPolicy"]["randomness"]["algorithm"] = None
        cases.append(("fixed-without-algorithm", fixed_without_algorithm, "randomness-algorithm"))
        source_without_identifier = copy.deepcopy(record)
        source_without_identifier["deterministicPolicy"]["timestamp"]["sourceIdentifier"] = None
        cases.append(("source-time-without-id", source_without_identifier, "timestamp-source-identifier"))
        missing_sql = copy.deepcopy(record)
        del missing_sql["deterministicPolicy"]["sqlOrdering"]
        cases.append(("missing-sql", missing_sql, "deterministic-policy-missing-field"))
        for label, changed, reason in cases:
            with self.subTest(case=label):
                self._assert_typed_parser_error(
                    "record",
                    _unsafe_json_bytes(changed),
                    "DETERMINISTIC_POLICY",
                    reason,
                )
        type(self).malformed_record_subcases += len(cases)
        self.assertEqual(self.record_path.read_bytes(), baseline)

    def test_06_mutable_source_and_git_object_adversaries_fail_closed(self) -> None:
        baseline_record = self._record(source_kind="commit-owned-git-blob-set")
        self._write_record(baseline_record)
        baseline = self._assert_cli_success(self._run_record_cli(baseline_record))
        self.assertTrue(baseline["preferredSourceVerified"])

        schema_cases: list[tuple[str, dict[str, object], str]] = []
        for label, commit in (
            ("branch-name", CANARIES["branch"]),
            ("floating-tag", "stable"),
            ("latest", "latest"),
            ("abbreviated", self.source_commit[:12]),
        ):
            changed = copy.deepcopy(baseline_record)
            changed["preferredSource"]["commit"] = commit
            schema_cases.append((label, changed, "source-commit"))
        for label, changed, reason in schema_cases:
            with self.subTest(case=label):
                self._assert_typed_parser_error(
                    "record", _unsafe_json_bytes(changed), "PREFERRED_SOURCE", reason
                )
        type(self).malformed_record_subcases += len(schema_cases)

        blob_id = self._rev_parse(self.source_repo, f"{self.source_commit}:data/a.txt")
        non_commit = copy.deepcopy(baseline_record)
        non_commit["preferredSource"]["commit"] = blob_id
        non_commit_path = self.case_base / "non-commit-record.json"
        self._write_record(non_commit, non_commit_path)
        self._assert_cli_error(
            self._run_record_cli(non_commit, record_path=non_commit_path),
            "PREFERRED_SOURCE",
            "commit-object-type",
        )

        wrong_tree = copy.deepcopy(baseline_record)
        wrong_tree["preferredSource"]["tree"] = self.tooling_tree
        wrong_tree_path = self.case_base / "wrong-tree-record.json"
        self._write_record(wrong_tree, wrong_tree_path)
        self._assert_cli_error(
            self._run_record_cli(wrong_tree, record_path=wrong_tree_path),
            "PREFERRED_SOURCE",
            "tree-mismatch",
        )

        identity_variants: list[tuple[str, dict[str, object], str, str]] = []
        missing = copy.deepcopy(baseline_record)
        missing["inputs"][0]["identifier"] = "data/missing.txt"
        identity_variants.append(("missing", missing, "INPUT", "git-path-set"))
        wrong_blob = copy.deepcopy(baseline_record)
        wrong_blob["inputs"][0]["gitBlobId"] = "0" * 40
        identity_variants.append(("blob", wrong_blob, "INPUT", "git-identity-mismatch"))
        wrong_hash = copy.deepcopy(baseline_record)
        wrong_hash["inputs"][0]["sha256"] = "0" * 64
        identity_variants.append(("hash", wrong_hash, "INPUT", "git-identity-mismatch"))
        wrong_length = copy.deepcopy(baseline_record)
        wrong_length["inputs"][0]["byteLength"] += 1
        identity_variants.append(("length", wrong_length, "INPUT", "git-identity-mismatch"))
        wrong_set = copy.deepcopy(baseline_record)
        wrong_set["preferredSource"]["inputSetSha256"] = "0" * 64
        identity_variants.append(
            ("input-set", wrong_set, "PREFERRED_SOURCE", "input-set-sha256-mismatch")
        )
        for index, (label, changed, phase, reason) in enumerate(identity_variants):
            with self.subTest(identity=label):
                target = self.case_base / f"git-identity-{index}.json"
                self._write_record(changed, target)
                self._assert_cli_error(
                    self._run_record_cli(changed, record_path=target), phase, reason
                )

        # Replacement refs are rejected even though every Git command also disables them.
        (self.source_repo / "data/a.txt").write_bytes(b"replacement commit bytes\n")
        self._git(self.source_repo, "add", "data/a.txt")
        self._git(
            self.source_repo,
            "commit",
            "-m",
            "synthetic replacement",
            commit_date="2003-04-05T06:07:08Z",
        )
        replacement_commit = self._rev_parse(self.source_repo, "HEAD")
        self._git(self.source_repo, "replace", self.source_commit, replacement_commit)
        self._assert_cli_error(
            self._run_record_cli(baseline_record),
            "PREFERRED_SOURCE",
            "replacement-object-ref",
        )

    def test_07_symlink_and_submodule_git_modes_are_not_blob_authority(self) -> None:
        baseline = self._record()
        original_blob = baseline["inputs"][0]["gitBlobId"]
        variants = (
            ("symlink", "120000", original_blob),
            ("submodule", "160000", self.source_commit),
        )
        for index, (label, mode, object_id) in enumerate(variants):
            with self.subTest(mode=label):
                self._git(self.source_repo, "read-tree", self.source_commit)
                self._git(
                    self.source_repo,
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"{mode},{object_id},data/a.txt",
                )
                tree = self._git(self.source_repo, "write-tree").stdout.decode("ascii").strip()
                commit = self._git(
                    self.source_repo,
                    "commit-tree",
                    tree,
                    "-p",
                    self.source_commit,
                    input_bytes=f"synthetic {label} input\n".encode("ascii"),
                    commit_date=f"2004-05-0{index + 1}T07:08:09Z",
                ).stdout.decode("ascii").strip()
                changed = copy.deepcopy(baseline)
                changed["preferredSource"]["commit"] = commit
                changed["preferredSource"]["tree"] = tree
                target = self.case_base / f"{label}-record.json"
                self._write_record(changed, target)
                self._assert_cli_error(
                    self._run_record_cli(changed, record_path=target),
                    "INPUT",
                    "git-tree-entry",
                )

    def test_08_input_output_identity_bindings_mutation_and_replacement(self) -> None:
        record = self._record()
        self._write_record(record)
        self._assert_cli_success(self._run_record_cli(record))

        original_input = self.external_input.read_bytes()
        self.external_input.write_bytes(b"X" * len(original_input))
        self._assert_cli_error(self._run_record_cli(record), "INPUT", "external-input-identity")
        self.external_input.write_bytes(original_input[:-1])
        self._assert_cli_error(self._run_record_cli(record), "INPUT", "external-input-identity")
        self.external_input.write_bytes(original_input)
        raced = self._run_api_race(record, "input", self.external_input)
        self.assertFalse(raced["ok"], raced)
        self.assertEqual(raced["phase"], "INPUT")
        self.assertIn(raced["reason"], {"external-input-identity", "file-parent-identity"})
        self.assertTrue(raced["observations"]["contextsFrozen"])
        self.external_input.unlink()
        Path(str(self.external_input) + ".open-original").rename(self.external_input)

        original_output = self.output_index.read_bytes()
        self.output_index.write_bytes(b"Y" * len(original_output))
        self._assert_cli_error(self._run_record_cli(record), "OUTPUT", "output-identity")
        self.output_index.write_bytes(original_output[:-1])
        self._assert_cli_error(self._run_record_cli(record), "OUTPUT", "output-identity")
        self.output_index.write_bytes(original_output)
        raced_output = self._run_api_race(record, "output", self.output_index)
        self.assertFalse(raced_output["ok"], raced_output)
        self.assertEqual(raced_output["phase"], "OUTPUT")
        self.output_index.unlink()
        Path(str(self.output_index) + ".open-original").rename(self.output_index)

        options = self._record_arguments(record)
        missing_input = options[:]
        position = missing_input.index("--input")
        del missing_input[position : position + 4]
        self._assert_cli_error(
            self._run_node(VERIFIER, missing_input), "INPUT", "input-binding-set"
        )
        extra_input = options + [
            "--input",
            "extra",
            "extra-input",
            str(self.external_input),
        ]
        self._assert_cli_error(
            self._run_node(VERIFIER, extra_input), "INPUT", "input-binding-set"
        )
        wrong_output = options[:]
        out_position = wrong_output.index("--output")
        wrong_output[out_position + 1] = "wrong-role"
        self._assert_cli_error(
            self._run_node(VERIFIER, wrong_output), "OUTPUT", "output-binding-set"
        )
        extra_output = options + [
            "--output",
            "extra",
            "out/extra.txt",
            "text",
            str(self.output_payload),
        ]
        self._assert_cli_error(
            self._run_node(VERIFIER, extra_output), "OUTPUT", "output-binding-set"
        )

        symlink = self.case_base / "synthetic-input-alias.txt"
        try:
            symlink.symlink_to(self.external_input)
        except OSError:
            source = CORE.read_text(encoding="utf-8")
            self.assertIn("isSymbolicLink()", source)
            self.assertIn("realpath(targetPath)", source)
        else:
            alias_args = self._record_arguments(record)
            input_position = alias_args.index("--input")
            alias_args[input_position + 3] = str(symlink)
            self._assert_cli_error(
                self._run_node(VERIFIER, alias_args), "INPUT", "external-input-state"
            )

    def test_09_generator_dependency_and_runtime_identities_fail_closed(self) -> None:
        record = self._record()
        self._write_record(record)
        self._assert_cli_success(self._run_record_cli(record))

        variants: list[tuple[str, dict[str, object], str, str]] = []
        wrong_commit = copy.deepcopy(record)
        wrong_commit["generator"]["toolingCommit"] = self.source_commit
        variants.append(("tooling-commit", wrong_commit, "GENERATOR", "commit-object"))
        wrong_tree = copy.deepcopy(record)
        wrong_tree["generator"]["toolingTree"] = self.source_tree
        variants.append(("tooling-tree", wrong_tree, "GENERATOR", "tree-mismatch"))
        missing_file = copy.deepcopy(record)
        missing_file["generator"]["files"][1]["path"] = "tools/missing.mjs"
        variants.append(("missing-generator", missing_file, "GENERATOR", "git-path-set"))
        wrong_blob = copy.deepcopy(record)
        wrong_blob["generator"]["files"][0]["gitBlobId"] = "0" * 40
        variants.append(("generator-blob", wrong_blob, "GENERATOR", "git-identity-mismatch"))
        wrong_dependency = copy.deepcopy(record)
        wrong_dependency["generator"]["dependencies"][0]["sha256"] = "0" * 64
        variants.append(("dependency", wrong_dependency, "DEPENDENCY", "git-identity-mismatch"))
        wrong_runtime_hash = copy.deepcopy(record)
        wrong_runtime_hash["generator"]["runtime"]["distributionSha256"] = "0" * 64
        variants.append(
            ("runtime-hash", wrong_runtime_hash, "GENERATOR", "runtime-distribution-identity")
        )
        wrong_runtime_length = copy.deepcopy(record)
        wrong_runtime_length["generator"]["runtime"]["distributionByteLength"] += 1
        variants.append(
            ("runtime-length", wrong_runtime_length, "GENERATOR", "runtime-distribution-identity")
        )
        for index, (label, changed, phase, reason) in enumerate(variants):
            with self.subTest(case=label):
                target = self.case_base / f"generator-identity-{index}.json"
                self._write_record(changed, target)
                self._assert_cli_error(
                    self._run_record_cli(changed, record_path=target), phase, reason
                )

        arguments = self._record_arguments(record)
        dependency_position = arguments.index("--dependency")
        missing_dependency = arguments[:dependency_position] + arguments[dependency_position + 4 :]
        self._assert_cli_error(
            self._run_node(VERIFIER, missing_dependency),
            "DEPENDENCY",
            "dependency-binding-set",
        )
        extra_dependency = arguments + [
            "--dependency",
            "extra",
            "synthetic-extra",
            str(self.external_dependency),
        ]
        self._assert_cli_error(
            self._run_node(VERIFIER, extra_dependency),
            "DEPENDENCY",
            "dependency-binding-set",
        )

        original_runtime = self.runtime.read_bytes()
        runtime_race = self._run_api_race(record, "runtime", self.runtime)
        self.assertFalse(runtime_race["ok"], runtime_race)
        self.assertEqual(runtime_race["phase"], "GENERATOR")
        self.runtime.unlink()
        Path(str(self.runtime) + ".open-original").rename(self.runtime)
        self.assertEqual(self.runtime.read_bytes(), original_runtime)

        hostile = {
            "GIT_DIR": str(self.case_base / "hostile-dir"),
            "GIT_WORK_TREE": str(self.case_base / "hostile-worktree"),
            "GIT_INDEX_FILE": str(self.case_base / "hostile-index"),
            "GIT_OBJECT_DIRECTORY": str(self.case_base / "hostile-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.case_base / "hostile-alternates"),
            "GIT_REPLACE_REF_BASE": "refs/hostile/",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(self.case_base / "hostile-hooks"),
        }
        hostile_result = self._assert_cli_success(
            self._run_record_cli(record, environment_updates=hostile)
        )
        self.assertTrue(hostile_result["generatorVerified"])

    def test_10_rights_evidence_never_defaults_to_approval(self) -> None:
        for mode in ("unresolved", "blocked"):
            with self.subTest(mode=mode):
                record = self._record(rights=mode)
                target = self.case_base / f"rights-{mode}.json"
                self._write_record(record, target)
                result = self._assert_cli_success(
                    self._run_record_cli(record, record_path=target)
                )
                self.assertFalse(result["rightsVerified"])
                self.assertFalse(result["releaseEligible"])
                self.assertTrue(result["publicationBlocked"])

        baseline = self._record()
        cases: list[tuple[str, dict[str, object], str]] = []
        no_evidence = copy.deepcopy(baseline)
        no_evidence["rights"]["evidenceReferences"] = []
        cases.append(("reviewed-without-evidence", no_evidence, "reviewed-evidence-empty"))
        no_decision = copy.deepcopy(baseline)
        no_decision["rights"]["reviewDecisionCommit"] = None
        cases.append(("reviewed-without-decision", no_decision, "review-decision-commit"))
        identified_without_expression = copy.deepcopy(baseline)
        identified_without_expression["rights"]["licenseExpression"] = None
        cases.append(("identified-without-expression", identified_without_expression, "license-expression"))
        unresolved_with_expression = copy.deepcopy(baseline)
        unresolved_with_expression["rights"]["licenseStatus"] = "unresolved"
        cases.append(("expression-while-unresolved", unresolved_with_expression, "unresolved-license-expression"))
        unreviewed_approval = self._record(rights="unresolved")
        unreviewed_approval["rights"]["sourceDistribution"] = "approved"
        cases.append(("unreviewed-source-approval", unreviewed_approval, "unreviewed-approval"))
        for label, changed, reason in cases:
            with self.subTest(case=label):
                self._assert_typed_parser_error(
                    "record", _unsafe_json_bytes(changed), "RIGHTS", reason
                )
        type(self).malformed_record_subcases += len(cases)

        denied = copy.deepcopy(baseline)
        denied["rights"]["artifactDistribution"] = "denied"
        denied_path = self.case_base / "rights-denied.json"
        self._write_record(denied, denied_path)
        denied_result = self._assert_cli_success(
            self._run_record_cli(denied, record_path=denied_path)
        )
        self.assertFalse(denied_result["rightsVerified"])

        missing_scope = copy.deepcopy(baseline)
        missing_scope["rights"]["reviewedScope"].remove("artifact-distribution")
        missing_scope_path = self.case_base / "rights-missing-scope.json"
        self._write_record(missing_scope, missing_scope_path)
        missing_result = self._assert_cli_success(
            self._run_record_cli(missing_scope, record_path=missing_scope_path)
        )
        self.assertFalse(missing_result["rightsVerified"])

    def test_11_registry_release_schemas_and_empty_gate(self) -> None:
        empty_registry = self._empty_registry()
        empty_release = self._empty_release()
        result = self._assert_cli_success(self._run_gate(empty_registry, empty_release))
        self.assertEqual(
            result,
            {
                "status": "ok",
                "mode": "generated-data-release-gate",
                "registryVerified": True,
                "releaseReferenceVerified": True,
                "generatedComponentCount": 0,
                "gateSatisfied": True,
                "releaseEligible": True,
                "publicationBlocked": False,
                "projectPublicationAuthorized": False,
            },
        )

        record = self._record()
        record_bytes = self._write_record(record)
        optional_registry = {
            "registryKind": REGISTRY_KIND,
            "schemaVersion": 1,
            "records": [
                {
                    "componentId": record["component"]["componentId"],
                    "recordId": record["component"]["recordId"],
                    "recordSha256": _sha256(record_bytes),
                    "relationship": "optional",
                }
            ],
        }
        optional = self._assert_cli_success(
            self._run_gate(optional_registry, empty_release)
        )
        self.assertTrue(optional["gateSatisfied"])
        self.assertFalse(optional["projectPublicationAuthorized"])

        required_registry = copy.deepcopy(optional_registry)
        required_registry["records"][0]["relationship"] = "required"
        self._assert_cli_error(
            self._run_gate(required_registry, empty_release),
            "RELEASE_GATE",
            "required-record-omitted",
        )

    def test_12_release_gate_relationship_and_record_adversaries(self) -> None:
        record = self._record()
        record_bytes = self._write_record(record)
        component_id = record["component"]["componentId"]
        record_hash = _sha256(record_bytes)
        registry = {
            "registryKind": REGISTRY_KIND,
            "schemaVersion": 1,
            "records": [
                {
                    "componentId": component_id,
                    "recordId": record["component"]["recordId"],
                    "recordSha256": record_hash,
                    "relationship": "required",
                }
            ],
        }
        release = {
            "releaseReferenceKind": RELEASE_REFERENCE_KIND,
            "schemaVersion": 1,
            "components": [
                {
                    "componentId": component_id,
                    "recordSha256": record_hash,
                    "outputSetSha256": _output_set_sha256(record["outputs"]),
                    "requiredEligibility": True,
                }
            ],
        }
        self._assert_cli_error(
            self._run_gate(registry, release, [(component_id, self.record_path)]),
            "RELEASE_GATE",
            "referenced-ineligible-record",
        )

        unknown_release = copy.deepcopy(release)
        unknown_release["components"][0]["componentId"] = "unknown-component"
        self._assert_cli_error(
            self._run_gate(self._empty_registry(), unknown_release),
            "RELEASE_GATE",
            "unknown-release-component",
        )

        missing_path = self.case_base / "missing-record.json"
        self._assert_cli_error(
            self._run_gate(registry, release, [(component_id, missing_path)]),
            "RECORD_SCHEMA",
            "canonical-document-state",
        )

        self._assert_cli_error(
            self._run_gate(
                self._empty_registry(),
                self._empty_release(),
                [(component_id, self.record_path)],
            ),
            "RELEASE_GATE",
            "record-binding-set",
        )

        mismatched_registry = copy.deepcopy(registry)
        mismatched_registry["records"][0]["recordSha256"] = "0" * 64
        mismatched_release = copy.deepcopy(release)
        mismatched_release["components"][0]["recordSha256"] = "0" * 64
        self._assert_cli_error(
            self._run_gate(
                mismatched_registry,
                mismatched_release,
                [(component_id, self.record_path)],
            ),
            "RELEASE_GATE",
            "record-hash-mismatch",
        )

        wrong_record_id = copy.deepcopy(registry)
        wrong_record_id["records"][0]["recordId"] = "other-record-v1"
        self._assert_cli_error(
            self._run_gate(wrong_record_id, release, [(component_id, self.record_path)]),
            "RELEASE_GATE",
            "record-id-mismatch",
        )

        wrong_output_set = copy.deepcopy(release)
        wrong_output_set["components"][0]["outputSetSha256"] = "0" * 64
        self._assert_cli_error(
            self._run_gate(registry, wrong_output_set, [(component_id, self.record_path)]),
            "RELEASE_GATE",
            "output-set-hash-mismatch",
        )

        fabricated = copy.deepcopy(record)
        fabricated["releaseEligible"] = True
        fabricated["publicationBlocked"] = False
        fabricated_bytes = _unsafe_json_bytes(fabricated)
        fabricated_path = self.case_base / "fabricated-record.json"
        fabricated_path.write_bytes(fabricated_bytes)
        fabricated_hash = _sha256(fabricated_bytes)
        fabricated_registry = copy.deepcopy(registry)
        fabricated_registry["records"][0]["recordSha256"] = fabricated_hash
        fabricated_release = copy.deepcopy(release)
        fabricated_release["components"][0]["recordSha256"] = fabricated_hash
        self._assert_cli_error(
            self._run_gate(
                fabricated_registry,
                fabricated_release,
                [(component_id, fabricated_path)],
            ),
            "RECORD_SCHEMA",
            "stored-release-eligible-mismatch",
        )

    def test_13_malformed_registry_and_release_reference_reasons_are_typed(self) -> None:
        registry = {
            "registryKind": REGISTRY_KIND,
            "schemaVersion": 1,
            "records": [
                {
                    "componentId": "alpha-component",
                    "recordId": "alpha-record",
                    "recordSha256": "1" * 64,
                    "relationship": "optional",
                },
                {
                    "componentId": "beta-component",
                    "recordId": "beta-record",
                    "recordSha256": "2" * 64,
                    "relationship": "required",
                },
            ],
        }
        release = {
            "releaseReferenceKind": RELEASE_REFERENCE_KIND,
            "schemaVersion": 1,
            "components": [
                {
                    "componentId": "alpha-component",
                    "recordSha256": "1" * 64,
                    "outputSetSha256": "3" * 64,
                    "requiredEligibility": True,
                },
                {
                    "componentId": "beta-component",
                    "recordSha256": "2" * 64,
                    "outputSetSha256": "4" * 64,
                    "requiredEligibility": True,
                },
            ],
        }
        registry_base = _registry_bytes(registry)
        release_base = _release_bytes(release)

        duplicate_registry = copy.deepcopy(registry)
        duplicate_registry["records"][1]["componentId"] = "alpha-component"
        reordered_registry = copy.deepcopy(registry)
        reordered_registry["records"].reverse()
        unknown_relationship = copy.deepcopy(registry)
        unknown_relationship["records"][0]["relationship"] = "transitive"
        mutable_registry_record = copy.deepcopy(registry)
        mutable_registry_record["records"][0]["recordId"] = "current"
        registry_cases = [
            (
                "duplicate",
                _unsafe_json_bytes(duplicate_registry),
                "duplicate-registry-record",
            ),
            (
                "reordered",
                _unsafe_json_bytes(reordered_registry),
                "registry-record-order",
            ),
            (
                "relationship",
                _unsafe_json_bytes(unknown_relationship),
                "registry-relationship",
            ),
            (
                "unknown-field",
                _replace_once(
                    registry_base,
                    b',"records":',
                    b',"unknown":0,"records":',
                ),
                "registry-unknown-field",
            ),
            (
                "mutable-record-id",
                _unsafe_json_bytes(mutable_registry_record),
                "registry-record-id",
            ),
        ]
        for label, malformed, reason in registry_cases:
            with self.subTest(registry=label):
                self._assert_typed_parser_error(
                    "registry", malformed, "REGISTRY_SCHEMA", reason
                )
        type(self).malformed_registry_subcases += len(registry_cases)

        duplicate_release = copy.deepcopy(release)
        duplicate_release["components"][1]["componentId"] = "alpha-component"
        reordered_release = copy.deepcopy(release)
        reordered_release["components"].reverse()
        false_eligibility = copy.deepcopy(release)
        false_eligibility["components"][0]["requiredEligibility"] = False
        release_cases = [
            (
                "duplicate",
                _unsafe_json_bytes(duplicate_release),
                "duplicate-release-component",
            ),
            (
                "reordered",
                _unsafe_json_bytes(reordered_release),
                "release-component-order",
            ),
            (
                "eligibility-false",
                _unsafe_json_bytes(false_eligibility),
                "required-eligibility",
            ),
            (
                "wrong-kind",
                _replace_once(
                    release_base,
                    RELEASE_REFERENCE_KIND.encode("ascii"),
                    b"wrong-release-reference",
                ),
                "release-reference-kind",
            ),
        ]
        for label, malformed, reason in release_cases:
            with self.subTest(release=label):
                self._assert_typed_parser_error(
                    "release", malformed, "RELEASE_REFERENCE_SCHEMA", reason
                )
        type(self).malformed_release_reference_subcases += len(release_cases)

    def test_14_privacy_canaries_are_absent_from_success_and_failure_output(self) -> None:
        self.assertEqual(len(CANARIES), 14)
        self.assertEqual(len(set(CANARIES.values())), 14)
        record = self._record()
        self._write_record(record)
        success = self._run_record_cli(record)
        result = self._assert_cli_success(success)
        self._assert_no_canary(success.stdout)
        self._assert_no_canary(json.dumps(result, separators=(",", ":")))

        gate_registry = self.case_base / f"{CANARIES['archive_path']}-registry.json"
        gate_release = self.case_base / f"{CANARIES['output_path']}-release.json"
        gate_success = self._run_gate(
            self._empty_registry(),
            self._empty_release(),
            registry_path=gate_registry,
            release_path=gate_release,
        )
        gate_result = self._assert_cli_success(gate_success)
        self._assert_no_canary(gate_success.stdout)
        self.assertFalse(gate_result["projectPublicationAuthorized"])

        record_failure = self._run_node(
            VERIFIER,
            ["--record", str(self.record_path), "--rights-override", CANARIES["username"]],
        )
        self._assert_cli_error(record_failure, "CLI")
        self._assert_no_canary(record_failure.stderr)

        protected = copy.deepcopy(record)
        protected["component"]["componentId"] = CANARIES["protected_component"]
        protected_path = self.case_base / "protected-looking-record.json"
        protected_path.write_bytes(_unsafe_json_bytes(protected))
        protected_result = self._run_node(
            VERIFIER,
            [
                "--record",
                str(protected_path),
                "--tooling-repo",
                str(self.tooling_repo),
                "--runtime-executable",
                str(self.runtime),
                "--source-repo",
                str(self.source_repo),
            ],
        )
        self._assert_cli_error(protected_result, "RECORD_SCHEMA", "component-id")
        self._assert_no_canary(protected_result.stderr)

        record_bytes = self.record_path.read_bytes()
        registry = {
            "registryKind": REGISTRY_KIND,
            "schemaVersion": 1,
            "records": [
                {
                    "componentId": "synthetic-component",
                    "recordId": "synthetic-record-v1",
                    "recordSha256": _sha256(record_bytes),
                    "relationship": "required",
                }
            ],
        }
        release = {
            "releaseReferenceKind": RELEASE_REFERENCE_KIND,
            "schemaVersion": 1,
            "components": [
                {
                    "componentId": "synthetic-component",
                    "recordSha256": _sha256(record_bytes),
                    "outputSetSha256": _output_set_sha256(record["outputs"]),
                    "requiredEligibility": True,
                }
            ],
        }
        gate_failure = self._run_gate(
            registry,
            release,
            [("synthetic-component", self.record_path)],
        )
        self._assert_cli_error(
            gate_failure, "RELEASE_GATE", "referenced-ineligible-record"
        )
        self._assert_no_canary(gate_failure.stderr)

    def test_15_imports_direct_paths_and_aliases_execute_with_correct_semantics(self) -> None:
        import_trace = self.case_base / "import-git-trace.json"
        modules = (CORE, VERIFIER, GATE)
        import_script = (
            "import {pathToFileURL} from 'node:url';"
            "const before=process.exitCode;"
            "for(const value of process.argv.slice(2)){await import(pathToFileURL(value).href);}"
            "if(process.exitCode!==before)process.exit(91);"
        )
        imported = subprocess.run(
            [
                str(self.node),
                "--input-type=module",
                "--eval",
                import_script,
                "import-sentinel",
                *map(str, modules),
            ],
            cwd=self.case_base,
            env=self._environment({"GIT_TRACE2_EVENT": str(import_trace)}),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr.decode(errors="replace"))
        self.assertEqual(imported.stdout, b"")
        self.assertEqual(imported.stderr, b"")
        self.assertFalse(import_trace.exists())

        for script in (VERIFIER, GATE):
            spellings = (
                str(script),
                os.path.relpath(script, self.case_base),
                str(script.parent) + os.sep + "." + os.sep + script.name,
            )
            for spelling in spellings:
                with self.subTest(script=script.name, spelling=spelling):
                    invalid = self._run_node(spelling, [], cwd=self.case_base)
                    self._assert_cli_error(invalid, "CLI")

        record = self._record()
        self._write_record(record)
        for spelling in (
            str(VERIFIER),
            os.path.relpath(VERIFIER, self.case_base),
            str(VERIFIER.parent) + os.sep + "." + os.sep + VERIFIER.name,
        ):
            valid = self._run_record_cli(record, script=spelling, cwd=self.case_base)
            self._assert_cli_success(valid)
            self.assertEqual(valid.stdout.count("\n"), 1)

        for spelling in (
            str(GATE),
            os.path.relpath(GATE, self.case_base),
            str(GATE.parent) + os.sep + "." + os.sep + GATE.name,
        ):
            valid_gate = self._run_gate(
                self._empty_registry(), self._empty_release(), script=spelling, cwd=self.case_base
            )
            self._assert_cli_success(valid_gate)
            self.assertEqual(valid_gate.stdout.count("\n"), 1)

        verifier_alias = self.case_base / "verifier-alias.mjs"
        gate_alias = self.case_base / "gate-alias.mjs"
        aliases_supported = True
        try:
            verifier_alias.symlink_to(VERIFIER)
            gate_alias.symlink_to(GATE)
        except OSError:
            aliases_supported = False
        if aliases_supported:
            self._assert_cli_success(
                self._run_record_cli(record, script=verifier_alias)
            )
            self._assert_cli_success(
                self._run_gate(
                    self._empty_registry(), self._empty_release(), script=gate_alias
                )
            )
            alias_import = subprocess.run(
                [
                    str(self.node),
                    "--input-type=module",
                    "--eval",
                    import_script,
                    "alias-import-sentinel",
                    str(verifier_alias),
                    str(gate_alias),
                ],
                cwd=self.case_base,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            self.assertEqual(alias_import.returncode, 0, alias_import.stderr)
            self.assertEqual(alias_import.stdout, b"")
            self.assertEqual(alias_import.stderr, b"")
        else:
            for source in (
                VERIFIER.read_text(encoding="utf-8"),
                GATE.read_text(encoding="utf-8"),
            ):
                self.assertIn("realpathSync.native", source)
                self.assertIn("fileURLToPath(import.meta.url)", source)

    def test_16_synthetic_end_to_end_foundation_flow(self) -> None:
        record = self._record(source_kind="commit-owned-git-blob-set")
        record_bytes = self._write_record(record)
        verified = self._assert_cli_success(self._run_record_cli(record))
        self.assertTrue(verified["rightsVerified"])
        self.assertFalse(verified["replayVerified"])
        self.assertFalse(verified["releaseEligible"])
        self.assertTrue(verified["publicationBlocked"])

        registry = {
            "registryKind": REGISTRY_KIND,
            "schemaVersion": 1,
            "records": [
                {
                    "componentId": record["component"]["componentId"],
                    "recordId": record["component"]["recordId"],
                    "recordSha256": _sha256(record_bytes),
                    "relationship": "optional",
                }
            ],
        }
        empty = self._assert_cli_success(
            self._run_gate(registry, self._empty_release())
        )
        self.assertTrue(empty["gateSatisfied"])
        self.assertFalse(empty["projectPublicationAuthorized"])

        release = {
            "releaseReferenceKind": RELEASE_REFERENCE_KIND,
            "schemaVersion": 1,
            "components": [
                {
                    "componentId": record["component"]["componentId"],
                    "recordSha256": _sha256(record_bytes),
                    "outputSetSha256": _output_set_sha256(record["outputs"]),
                    "requiredEligibility": True,
                }
            ],
        }
        blocked = self._run_gate(
            registry,
            release,
            [(record["component"]["componentId"], self.record_path)],
        )
        self._assert_cli_error(
            blocked, "RELEASE_GATE", "referenced-ineligible-record"
        )

        helper = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", ELIGIBILITY_HARNESS],
            cwd=self.case_base,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(helper.returncode, 0, helper.stderr)
        self.assertTrue(json.loads(helper.stdout)["eligible"]["releaseEligible"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
