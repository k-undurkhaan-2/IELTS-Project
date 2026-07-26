#!/usr/bin/env python3
"""Synthetic coverage for the R1-10C public-source receipt adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
VECTOR_SOURCE = REPO_ROOT / "developer/public-source-receipt-boundary-vectors-v1.json"
APPROVED_NODE = Path(
    r"C:\Users\llzz\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
)
APPROVED_GIT_A = Path(r"D:\Git\cmd\git.exe")
APPROVED_GIT_B = Path(
    r"C:\Users\llzz\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe"
)
COMMON_WINDOWS_SSH_KEYGEN = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")

ADAPTER_PATHS = [
    "developer/verify-public-source-membership.mjs",
    "developer/public-source-archive-core.mjs",
    "developer/verify-public-source-archive.mjs",
    "developer/public-source-receipt-core.mjs",
    "developer/prepare-public-source-receipt.mjs",
    "developer/verify-public-source-receipt.mjs",
    "developer/reproducibility-evidence-core.mjs",
    "developer/verify-reproducibility-evidence.mjs",
    "developer/public-source-receipt-reproducibility-core.mjs",
    "developer/prepare-public-source-receipt-reproducibility.mjs",
    "developer/run-public-source-receipt-boundary-vectors.mjs",
]
FROZEN_RECEIPT_PATHS = [
    "developer/prepare-public-source-archive.mjs",
    "developer/prepare-public-source-receipt.mjs",
    "developer/prepare-public-source-tree.mjs",
    "developer/public-source-archive-core.mjs",
    "developer/public-source-manifest.json",
    "developer/public-source-receipt-core.mjs",
    "developer/verify-public-source-archive.mjs",
    "developer/verify-public-source-membership.mjs",
    "developer/verify-public-source-receipt.mjs",
]
FROZEN_DEPENDENCIES = [
    "developer/prepare-public-source-archive.mjs",
    "developer/prepare-public-source-tree.mjs",
]
GIT_REDIRECTIONS = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_REPLACE_REF_BASE",
    "GIT_EXEC_PATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
]
CANARIES = tuple(f"r1-10c-private-canary-{index:02d}" for index in range(1, 43))


def _find_node() -> Path:
    configured = os.environ.get("IELTMPS_NODE")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file():
            return candidate
    if APPROVED_NODE.is_file():
        return APPROVED_NODE.resolve()
    found = shutil.which("node")
    if not found:
        raise RuntimeError("Node runtime is unavailable")
    return Path(found).resolve()


def _find_git() -> Path:
    found = shutil.which("git")
    if not found:
        raise RuntimeError("Git is unavailable")
    return Path(found).resolve()


def _find_ssh_keygen() -> Path:
    found = shutil.which("ssh-keygen")
    if not found:
        raise RuntimeError("ssh-keygen is unavailable")
    return Path(found).resolve()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _write_at(root: Path, relative: str, value: str | bytes) -> None:
    target = root / PurePosixPath(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value.encode("utf-8") if isinstance(value, str) else value)


class PublicSourceReceiptReproducibilityTests(unittest.TestCase):
    """No real repository is ever used as an adapter generation source."""

    maxDiff = None
    positive_adapter_cases = 0
    adversarial_subcases = 0
    worker_protocol_cases = 0
    loaded_byte_substitution_cases = 0
    publication_race_cases = 0
    cleanup_cases = 0
    vector_cases_executed = 0
    vector_cases_passed = 0
    boundary_result_contract_cases = 0
    standalone_embedded_independence_cases = 0
    deliberate_descriptor_failure_id = "none"
    privacy_canary_count = len(CANARIES)
    _success: dict[str, object] | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        cls.git = _find_git()
        cls.ssh_keygen = _find_ssh_keygen()
        missing = [path for path in ADAPTER_PATHS + FROZEN_DEPENDENCIES if not (REPO_ROOT / path).is_file()]
        if missing or not VECTOR_SOURCE.is_file():
            raise RuntimeError(f"required production files unavailable: {missing}")
        cls._temporary = tempfile.TemporaryDirectory(prefix="r1-10c-synthetic-")
        cls.base = (Path(cls._temporary.name) / "owned-root").resolve()
        cls.base.mkdir()
        cls.repository = cls.base / CANARIES[0]
        cls.external = cls.base / CANARIES[1]
        cls.docs = cls.base / CANARIES[2]
        cls.external.mkdir()
        cls.docs.mkdir()
        cls._initialize_repository()
        cls._create_external_inputs()
        cls._create_bound_documents()

    @classmethod
    def tearDownClass(cls) -> None:
        duration = time.monotonic() - cls.started
        methods = unittest.defaultTestLoader.loadTestsFromTestCase(cls).countTestCases()
        print(
            "R1-10C-SUMMARY "
            f"test_methods={methods} "
            f"positive_adapter_cases={cls.positive_adapter_cases} "
            f"adversarial_subcases={cls.adversarial_subcases} "
            f"worker_protocol_cases={cls.worker_protocol_cases} "
            f"loaded_byte_substitution_cases={cls.loaded_byte_substitution_cases} "
            f"publication_race_cases={cls.publication_race_cases} "
            f"cleanup_cases={cls.cleanup_cases} "
            f"privacy_canaries={cls.privacy_canary_count} "
            f"vector_cases_executed={cls.vector_cases_executed} "
            f"vector_cases_passed={cls.vector_cases_passed} "
            f"boundary_result_contract_cases={cls.boundary_result_contract_cases} "
            f"standalone_embedded_independence_cases={cls.standalone_embedded_independence_cases} "
            f"deliberate_descriptor_failure_id={cls.deliberate_descriptor_failure_id} "
            f"duration_seconds={duration:.3f}"
        )
        cls._temporary.cleanup()

    @classmethod
    def _environment(cls, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in GIT_REDIRECTIONS:
            environment.pop(name, None)
        environment["PATH"] = os.pathsep.join(
            [
                str(cls.git.parent),
                str(cls.node.parent),
                str(cls.ssh_keygen.parent),
                environment.get("PATH", ""),
            ]
        )
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        for index, canary in enumerate(CANARIES, 1):
            environment[f"IELTMPS_PRIVACY_CANARY_{index:02d}"] = canary
        if additions:
            environment.update(additions)
        return environment

    @classmethod
    def _run(
        cls,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: int = 180,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            cwd=cwd or cls.base,
            env=environment or cls._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    @classmethod
    def _git_at(
        cls,
        repository: Path,
        *arguments: str,
        input_bytes: bytes | None = None,
    ) -> bytes:
        completed = subprocess.run(
            [str(cls.git), "-C", str(repository), *arguments],
            input=input_bytes,
            env=cls._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    @classmethod
    def _git(cls, *arguments: str, input_bytes: bytes | None = None) -> bytes:
        return cls._git_at(cls.repository, *arguments, input_bytes=input_bytes)

    @classmethod
    def _generate_manifest(cls) -> bytes:
        script = (
            "import {pathToFileURL} from 'node:url';"
            "const m=await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);"
            "process.stdout.write(m.buildSyntheticPublicSourceManifestBytes().toString('base64'));"
        )
        result = cls._run(
            [str(cls.node), "--input-type=module", "--eval", script],
            environment=cls._environment(
                {"IELTMPS_RUNNER": str(REPO_ROOT / ADAPTER_PATHS[-1])}
            ),
        )
        if result.returncode != 0 or result.stderr:
            raise AssertionError(result.stderr)
        return base64.b64decode(result.stdout)

    @classmethod
    def _initialize_repository(cls) -> None:
        cls.repository.mkdir()
        cls._git("init")
        for key, value in (
            ("user.name", CANARIES[20]),
            ("user.email", "synthetic@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git("config", key, value)
        cls._git("checkout", "-b", CANARIES[23])
        cls._git("remote", "add", "origin", f"https://example.invalid/{CANARIES[24]}.git")

        manifest_bytes = cls._generate_manifest()
        cls.manifest_bytes = manifest_bytes
        manifest = json.loads(manifest_bytes)
        exact_paths: set[str] = set()
        for component in manifest["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            payload = (
                manifest_bytes
                if relative == "developer/public-source-manifest.json"
                else f"synthetic:{relative}\n".encode("utf-8")
            )
            _write_at(cls.repository, relative, payload)
        prefix_members = {
            "backend/admin/admin.js": b"export const admin = true;\n",
            "backend/auth/auth.js": b"export const auth = true;\n",
            "backend/migrations/001_init.sql": b"SELECT 1;\n",
            "backend/scripts/executable.sh": b"#!/bin/sh\nexit 0\n",
            "backend/src/app.js": b"export const app = true;\n",
            "backend/test/app.test.js": b"export const test = true;\n",
            "css/app.css": b"body {}\n",
            "js/app.js": b"export const synthetic = true;\n",
            "src/styles/app.css": b":root {}\n",
        }
        for relative, payload in prefix_members.items():
            _write_at(cls.repository, relative, payload)
        for relative in ADAPTER_PATHS:
            _write_at(
                cls.repository,
                relative,
                f"// historical placeholder for {relative}\n",
            )
        for relative in FROZEN_DEPENDENCIES:
            _write_at(cls.repository, relative, (REPO_ROOT / relative).read_bytes())
        cls._git("add", "-A")
        cls._git("commit", "-m", "synthetic historical source")
        cls.source_commit = cls._git("rev-parse", "HEAD").decode("ascii").strip()

        for relative in ADAPTER_PATHS:
            _write_at(cls.repository, relative, (REPO_ROOT / relative).read_bytes())
        key = cls.base / "synthetic-signing-key"
        key_result = cls._run(
            [str(cls.ssh_keygen), "-q", "-t", "ed25519", "-N", "", "-f", str(key)]
        )
        if key_result.returncode != 0:
            raise AssertionError(key_result.stderr)
        public_parts = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        cls.allowed_signers = cls.base / "allowed-signers"
        cls.allowed_signers.write_text(
            f"synthetic@example.invalid {public_parts[0]} {public_parts[1]}\n",
            encoding="utf-8",
        )
        for config_key, value in (
            ("gpg.format", "ssh"),
            ("user.signingkey", str(key)),
            ("gpg.ssh.allowedSignersFile", str(cls.allowed_signers)),
            ("gpg.ssh.program", str(cls.ssh_keygen)),
            ("commit.gpgsign", "true"),
        ):
            cls._git("config", config_key, value)
        cls._git("add", "--", *ADAPTER_PATHS)
        cls._git("commit", "-m", "synthetic signed tooling authority")
        cls.tooling_commit = cls._git("rev-parse", "HEAD").decode("ascii").strip()
        cls._git("verify-commit", "--raw", cls.tooling_commit)
        changed = cls._git(
            "diff-tree", "--no-commit-id", "--name-only", "-r", cls.tooling_commit
        ).decode("utf-8").splitlines()
        if sorted(changed) != sorted(ADAPTER_PATHS):
            raise AssertionError(f"unexpected tooling commit scope: {changed}")

        cls.coordinator = cls.repository / ADAPTER_PATHS[9]
        cls.core = cls.repository / ADAPTER_PATHS[8]
        cls.runner = cls.repository / ADAPTER_PATHS[10]
        cls.b1 = cls.repository / ADAPTER_PATHS[0]
        cls.b3 = cls.repository / ADAPTER_PATHS[2]
        cls.receipt_verifier = cls.repository / ADAPTER_PATHS[5]

    @classmethod
    def _membership_summary(cls) -> dict[str, object]:
        script = r"""
import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.env.IELTMPS_B1).href);
const result=await m.loadValidatedPublicSourceMembership({
  repo:process.env.IELTMPS_REPOSITORY,
  commit:process.env.IELTMPS_SOURCE_COMMIT,
});
process.stdout.write(JSON.stringify({
  manifestSha256:result.manifestSha256,
  reportBase64:result.reportBytes.toString('base64'),
  members:result.members.map((entry)=>({
    path:entry.path,gitMode:entry.gitMode,objectId:entry.objectId,
    declaredByteSize:entry.declaredByteSize,sha256:entry.sha256,
    role:entry.role,licenseScope:entry.licenseScope,
    blobBase64:entry.blobBytes.toString('base64'),
  })),
}));
"""
        result = cls._run(
            [str(cls.node), "--input-type=module", "--eval", script],
            environment=cls._environment(
                {
                    "IELTMPS_B1": str(cls.b1),
                    "IELTMPS_REPOSITORY": str(cls.repository),
                    "IELTMPS_SOURCE_COMMIT": cls.source_commit,
                }
            ),
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def _create_external_inputs(cls) -> None:
        cls.membership = cls._membership_summary()
        cls.report_bytes = base64.b64decode(cls.membership["reportBase64"])
        cls.archive = cls.external / f"{CANARIES[6]}.tar"
        archive_result = cls._run(
            [
                str(cls.node),
                str(cls.repository / FROZEN_DEPENDENCIES[0]),
                "--repo",
                str(cls.repository),
                "--commit",
                cls.source_commit,
                "--output",
                str(cls.archive),
            ],
            timeout=180,
        )
        if archive_result.returncode != 0:
            raise AssertionError(archive_result.stderr)
        cls.artifacts = [
            {
                "role": "standalone-release-receipt",
                "format": "json",
                "path": cls.external / f"{CANARIES[7]}.json",
            },
            {
                "role": "standalone-release-archive",
                "format": "zip",
                "path": cls.external / f"{CANARIES[8]}.zip",
            },
        ]
        cls.artifacts[0]["path"].write_bytes(b'{"synthetic":true}\n')
        cls.artifacts[1]["path"].write_bytes(b"PK\x03\x04synthetic-zip\n")

    @classmethod
    def _tree_descriptor_at(
        cls,
        repository: Path,
        tooling_commit: str,
        relative: str,
    ) -> tuple[str, str, bytes]:
        line = cls._git_at(
            repository,
            "ls-tree",
            tooling_commit,
            "--",
            relative,
        ).decode("utf-8").strip()
        header, reported = line.split("\t", 1)
        mode, object_type, object_id = header.split(" ")
        if object_type != "blob" or reported != relative:
            raise AssertionError("unexpected tree entry")
        payload = cls._git_at(repository, "cat-file", "blob", object_id)
        return mode, object_id, payload

    @classmethod
    def _tree_descriptor(cls, relative: str) -> tuple[str, str, bytes]:
        return cls._tree_descriptor_at(cls.repository, cls.tooling_commit, relative)

    @classmethod
    def _critical_tool_document_at(
        cls,
        repository: Path,
        tooling_commit: str,
    ) -> dict[str, object]:
        entries = []
        for relative in ADAPTER_PATHS:
            mode, object_id, payload = cls._tree_descriptor_at(
                repository,
                tooling_commit,
                relative,
            )
            entries.append(
                {
                    "path": relative,
                    "gitMode": mode,
                    "gitBlobObjectId": object_id,
                    "declaredByteSize": len(payload),
                    "sha256": _sha256(payload),
                }
            )
        return {
            "documentKind": "ieltmps-reproducibility-critical-tool-set",
            "schemaVersion": 1,
            "toolSetId": "public-source-receipt-reproducibility-v1",
            "toolingCommit": tooling_commit,
            "entries": entries,
        }

    @classmethod
    def _critical_tool_document(cls) -> dict[str, object]:
        return cls._critical_tool_document_at(cls.repository, cls.tooling_commit)

    @classmethod
    def _node_facts(cls) -> dict[str, str]:
        script = (
            "import os from 'node:os';process.stdout.write(JSON.stringify({"
            "execPath:process.execPath,node:process.versions.node,v8:process.versions.v8,"
            "modules:process.versions.modules,platform:process.platform,arch:process.arch,"
            "osRelease:os.release().toLowerCase()}));"
        )
        result = cls._run([str(cls.node), "--input-type=module", "--eval", script])
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def _b3_result(cls) -> dict[str, object]:
        script = r"""
import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.env.IELTMPS_B3).href);
const result=await m.verifyPublicSourceArchive({
  repo:process.env.IELTMPS_REPOSITORY,
  commit:process.env.IELTMPS_SOURCE_COMMIT,
  archive:process.env.IELTMPS_ARCHIVE,
});
process.stdout.write(JSON.stringify(result));
"""
        result = cls._run(
            [str(cls.node), "--input-type=module", "--eval", script],
            environment=cls._environment(
                {
                    "IELTMPS_B3": str(cls.b3),
                    "IELTMPS_REPOSITORY": str(cls.repository),
                    "IELTMPS_SOURCE_COMMIT": cls.source_commit,
                    "IELTMPS_ARCHIVE": str(cls.archive),
                }
            ),
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def _create_bound_documents(cls) -> None:
        cls.vector_path = cls.docs / f"{CANARIES[3]}.json"
        cls.vector_path.write_bytes(VECTOR_SOURCE.read_bytes())
        cls.critical_path = cls.docs / f"{CANARIES[4]}.json"
        cls.critical_bytes = _canonical(cls._critical_tool_document())
        cls.critical_path.write_bytes(cls.critical_bytes)
        b3 = cls._b3_result()
        frozen_critical = []
        for relative in FROZEN_RECEIPT_PATHS:
            _mode, object_id, payload = cls._tree_descriptor(relative)
            frozen_critical.append(
                {
                    "path": relative,
                    "gitBlobId": object_id,
                    "sha256": _sha256(payload),
                    "byteLength": len(payload),
                }
            )
        artifact_identities = sorted(
            (
                {
                    "role": str(artifact["role"]),
                    "format": str(artifact["format"]),
                    "sha256": _sha256(Path(artifact["path"]).read_bytes()),
                    "byteLength": Path(artifact["path"]).stat().st_size,
                }
                for artifact in cls.artifacts
            ),
            key=lambda entry: (entry["role"], entry["format"], entry["sha256"]),
        )
        cls.input_value = {
            "documentKind": "ieltmps-public-source-receipt-input-set",
            "schemaVersion": 1,
            "artifactRole": "public-source-receipt",
            "formatProfile": "ieltmps-public-source-receipt-v1",
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "manifestSha256": cls.membership["manifestSha256"],
            "membershipReportSha256": _sha256(cls.report_bytes),
            "membershipCount": len(cls.membership["members"]),
            "archive": {
                "format": "tar-ustar-v1",
                "sha256": b3["archiveSha256"],
                "byteLength": b3["archiveByteLength"],
                "memberCount": b3["archiveMemberCount"],
            },
            "receiptAuthority": {
                "receiptKind": "ieltmps-public-source-receipt",
                "schemaVersion": 1,
                "outputSuffix": ".source-receipt.json",
            },
            "criticalFiles": frozen_critical,
            "artifacts": artifact_identities,
        }
        cls.input_bytes = _canonical(cls.input_value)
        node_facts = cls._node_facts()
        node_bytes = Path(node_facts["execPath"]).read_bytes()
        cls.runtime_value = {
            "documentKind": "ieltmps-node-runtime-identity",
            "schemaVersion": 1,
            "runtimeProfileId": "node-synthetic-runtime",
            "implementation": "node",
            "executableSha256": _sha256(node_bytes),
            "executableByteLength": len(node_bytes),
            "nodeVersion": node_facts["node"],
            "v8Version": node_facts["v8"],
            "modulesVersion": node_facts["modules"],
            "distributionProfileId": "synthetic-node-distribution",
        }
        cls.runtime_path = cls.docs / f"{CANARIES[9]}.json"
        cls.runtime_bytes = _canonical(cls.runtime_value)
        cls.runtime_path.write_bytes(cls.runtime_bytes)
        git_bytes = cls.git.read_bytes()
        version = cls._run([str(cls.git), "--version"]).stdout.strip()
        cls.git_value = {
            "documentKind": "ieltmps-git-runtime-identity",
            "schemaVersion": 1,
            "gitProfileId": "git-synthetic-sha1",
            "executableSha256": _sha256(git_bytes),
            "executableByteLength": len(git_bytes),
            "reportedVersion": version.removeprefix("git version "),
            "objectFormat": "sha1",
            "distributionProfileId": "synthetic-git-distribution",
        }
        cls.git_path = cls.docs / f"{CANARIES[10]}.json"
        cls.git_bytes = _canonical(cls.git_value)
        cls.git_path.write_bytes(cls.git_bytes)
        os_name = {"win32": "windows", "linux": "linux", "darwin": "macos"}[
            node_facts["platform"]
        ]
        cls.probe_value = {
            "probeKind": "ieltmps-platform-probe",
            "schemaVersion": 1,
            "matrixCellId": "synthetic-host-cell",
            "operatingSystem": os_name,
            "operatingSystemBuild": node_facts["osRelease"],
            "architecture": node_facts["arch"],
            "filesystemProfile": "synthetic-local-filesystem",
            "localeProfile": "synthetic-locale-profile",
            "timezoneProfile": "synthetic-timezone-profile",
            "runtimeIdentitySha256": _sha256(cls.runtime_bytes),
            "gitIdentitySha256": _sha256(cls.git_bytes),
            "pathPolicyCapabilities": {
                "portableRelativePathsSupported": True,
                "caseCollisionDetectionSupported": True,
                "unicodeNormalizationCollisionDetectionSupported": True,
                "symlinkParentRejectionSupported": True,
            },
            "exclusiveCreateSupported": True,
            "hardLinkSupported": True,
            "atomicNoReplaceHardLinkSupported": True,
            "reliableLinkCountSupported": True,
            "stableFileIdentitySupported": True,
        }
        cls.probe_path = cls.docs / f"{CANARIES[11]}.json"
        cls.probe_bytes = _canonical(cls.probe_value)
        cls.probe_path.write_bytes(cls.probe_bytes)
        cls.policy = cls._policy_for_probe(cls.probe_bytes)
        cls.policy_path = cls.docs / f"{CANARIES[12]}.json"
        cls.policy_bytes = _canonical(cls.policy)
        cls.policy_path.write_bytes(cls.policy_bytes)

    @classmethod
    def _policy_for_probe(cls, probe_bytes: bytes) -> dict[str, object]:
        cell = {
            "matrixCellId": "synthetic-host-cell",
            "runtimeProfileId": cls.runtime_value["runtimeProfileId"],
            "runtimeIdentitySha256": _sha256(cls.runtime_bytes),
            "gitProfileId": cls.git_value["gitProfileId"],
            "gitIdentitySha256": _sha256(cls.git_bytes),
            "operatingSystem": cls.probe_value["operatingSystem"],
            "operatingSystemBuild": cls.probe_value["operatingSystemBuild"],
            "architecture": cls.probe_value["architecture"],
            "filesystemProfile": cls.probe_value["filesystemProfile"],
            "localeProfile": cls.probe_value["localeProfile"],
            "timezoneProfile": cls.probe_value["timezoneProfile"],
            "platformProbeSha256": _sha256(probe_bytes),
        }
        return {
            "policyKind": "ieltmps-reproducibility-matrix-policy",
            "schemaVersion": 1,
            "policyId": "r1-10c-synthetic-policy",
            "artifactRole": "public-source-receipt",
            "formatProfile": "ieltmps-public-source-receipt-v1",
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "criticalToolSetSha256": _sha256(cls.critical_bytes),
            "manifestSha256": cls.membership["manifestSha256"],
            "inputSetSha256": _sha256(cls.input_bytes),
            "testVectorSetSha256": _sha256(cls.vector_path.read_bytes()),
            "requiredClaimLevels": ["L0"],
            "requiredCells": [cell],
            "optionalCells": [],
        }

    @classmethod
    def _write_git_profile_documents(
        cls,
        git_executable: Path,
        directory: Path,
    ) -> dict[str, object]:
        directory.mkdir(parents=True, exist_ok=False)
        executable = git_executable.resolve()
        git_bytes = executable.read_bytes()
        version_process = cls._run([str(executable), "--version"])
        if version_process.returncode != 0 or version_process.stderr:
            raise AssertionError(version_process.stderr)
        reported_version = version_process.stdout.strip().removeprefix("git version ")
        git_value = json.loads(json.dumps(cls.git_value))
        git_value.update(
            {
                "gitProfileId": "git-synthetic-" + reported_version.replace(".", "-"),
                "executableSha256": _sha256(git_bytes),
                "executableByteLength": len(git_bytes),
                "reportedVersion": reported_version,
            }
        )
        git_bytes_document = _canonical(git_value)
        git_path = directory / "git-identity.json"
        git_path.write_bytes(git_bytes_document)

        probe_value = json.loads(json.dumps(cls.probe_value))
        probe_value["gitIdentitySha256"] = _sha256(git_bytes_document)
        probe_bytes = _canonical(probe_value)
        probe_path = directory / "platform-probe.json"
        probe_path.write_bytes(probe_bytes)

        policy_value = json.loads(json.dumps(cls.policy))
        cell = policy_value["requiredCells"][0]
        cell["gitProfileId"] = git_value["gitProfileId"]
        cell["gitIdentitySha256"] = _sha256(git_bytes_document)
        cell["platformProbeSha256"] = _sha256(probe_bytes)
        policy_bytes = _canonical(policy_value)
        policy_path = directory / "policy.json"
        policy_path.write_bytes(policy_bytes)
        return {
            "gitValue": git_value,
            "gitPath": git_path,
            "gitBytes": git_bytes_document,
            "probePath": probe_path,
            "probeBytes": probe_bytes,
            "policyPath": policy_path,
            "policyBytes": policy_bytes,
        }

    @classmethod
    def _write_bound_tooling_documents(
        cls,
        repository: Path,
        tooling_commit: str,
        directory: Path,
    ) -> dict[str, object]:
        directory.mkdir(parents=True, exist_ok=True)
        critical_value = cls._critical_tool_document_at(repository, tooling_commit)
        critical_bytes = _canonical(critical_value)
        critical_path = directory / "critical-tool-set.json"
        critical_path.write_bytes(critical_bytes)

        frozen_critical = []
        for relative in FROZEN_RECEIPT_PATHS:
            _mode, object_id, payload = cls._tree_descriptor_at(
                repository,
                tooling_commit,
                relative,
            )
            frozen_critical.append(
                {
                    "path": relative,
                    "gitBlobId": object_id,
                    "sha256": _sha256(payload),
                    "byteLength": len(payload),
                }
            )
        input_value = json.loads(json.dumps(cls.input_value))
        input_value["toolingCommit"] = tooling_commit
        input_value["criticalFiles"] = frozen_critical
        input_bytes = _canonical(input_value)

        policy_value = json.loads(json.dumps(cls.policy))
        policy_value["toolingCommit"] = tooling_commit
        policy_value["criticalToolSetSha256"] = _sha256(critical_bytes)
        policy_value["inputSetSha256"] = _sha256(input_bytes)
        policy_path = directory / "policy.json"
        policy_bytes = _canonical(policy_value)
        policy_path.write_bytes(policy_bytes)

        for entry in critical_value["entries"]:
            loaded = (repository / PurePosixPath(entry["path"])).read_bytes()
            if (
                len(loaded) != entry["declaredByteSize"]
                or _sha256(loaded) != entry["sha256"]
            ):
                raise AssertionError(f"working byte mismatch: {entry['path']}")
        return {
            "criticalPath": critical_path,
            "criticalBytes": critical_bytes,
            "policyPath": policy_path,
            "policyBytes": policy_bytes,
            "inputBytes": input_bytes,
        }

    @classmethod
    def _commit_runner_source(
        cls,
        repository: Path,
        source: str,
        message: str,
    ) -> str:
        runner = repository / PurePosixPath(ADAPTER_PATHS[-1])
        payload = source.encode("utf-8")
        if b"\r" in payload or not payload.endswith(b"\n"):
            raise AssertionError("synthetic runner encoding")
        runner.write_bytes(payload)
        cls._git_at(repository, "add", "--", ADAPTER_PATHS[-1])
        cls._git_at(repository, "commit", "-m", message)
        tooling_commit = cls._git_at(repository, "rev-parse", "HEAD").decode(
            "ascii"
        ).strip()
        cls._git_at(repository, "verify-commit", "--raw", tooling_commit)
        changed = cls._git_at(
            repository,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            tooling_commit,
        ).decode("utf-8").splitlines()
        if changed != [ADAPTER_PATHS[-1]]:
            raise AssertionError(f"unexpected synthetic commit scope: {changed}")
        committed = cls._git_at(
            repository,
            "show",
            f"{tooling_commit}:{ADAPTER_PATHS[-1]}",
        )
        if committed != payload or runner.read_bytes() != payload:
            raise AssertionError("synthetic runner commit mismatch")
        if cls._git_at(repository, "status", "--porcelain"):
            raise AssertionError("synthetic tooling repository is dirty")
        return tooling_commit

    @classmethod
    def _boundary_result_return(
        cls,
        *,
        overrides: dict[str, str] | None = None,
        omit: set[str] | None = None,
        order: list[str] | None = None,
        extra: list[tuple[str, str]] | None = None,
        shape: str = "plain",
    ) -> str:
        expressions = {
            "status": '"ok"',
            "mode": '"public-source-receipt-boundary-vectors"',
            "vectorSetKind": "VECTOR_SET_KIND",
            "schemaVersion": "1",
            "vectorSetId": "VECTOR_SET_ID",
            "artifactRole": "ARTIFACT_ROLE",
            "formatProfile": "FORMAT_PROFILE",
            "testVectorSetSha256": "authority.sha256",
            "vectorCount": "results.length",
            "passedCount": "passedCount",
            "failedCount": "results.length - passedCount",
            "boundaryVectorSetPassed": "passedCount === results.length",
        }
        if overrides:
            expressions.update(overrides)
        selected = order or list(expressions)
        omitted = omit or set()
        if set(selected) != set(expressions) or len(selected) != len(expressions):
            raise AssertionError("synthetic result order")
        fields = [
            (key, expressions[key])
            for key in selected
            if key not in omitted
        ]
        fields.extend(extra or [])

        def object_lines(first: str, last: str) -> list[str]:
            body = [
                f"    {key}," if key == value else f"    {key}: {value},"
                for key, value in fields
            ]
            return [first, *body, last]

        if shape == "plain":
            lines = object_lines("  return deepFreezeAdapter({", "  });")
        elif shape == "null-prototype":
            lines = object_lines(
                "  return deepFreezeAdapter(Object.assign(Object.create(null), {",
                "  }));",
            )
        elif shape in {
            "getter",
            "prototype-field",
            "duplicate-own-key-proxy",
            "symbol-extra",
        }:
            lines = object_lines("  const syntheticBoundaryResult = {", "  };")
            if shape == "getter":
                lines.extend(
                    [
                        "  Object.defineProperty(syntheticBoundaryResult, \"schemaVersion\", {",
                        "    enumerable: true,",
                        "    configurable: true,",
                        "    get() { return 1; },",
                        "  });",
                        "  return syntheticBoundaryResult;",
                    ]
                )
            elif shape == "prototype-field":
                lines.extend(
                    [
                        "  return Object.assign(",
                        "    Object.create({ inheritedResultField: true }),",
                        "    syntheticBoundaryResult,",
                        "  );",
                    ]
                )
            elif shape == "duplicate-own-key-proxy":
                lines.extend(
                    [
                        "  return new Proxy(syntheticBoundaryResult, {",
                        "    ownKeys() {",
                        "      return [",
                        "        ...Reflect.ownKeys(syntheticBoundaryResult),",
                        '        "schemaVersion",',
                        "      ];",
                        "    },",
                        "  });",
                    ]
                )
            else:
                lines.extend(
                    [
                        '  syntheticBoundaryResult[Symbol("unexpectedResultField")] = true;',
                        "  return syntheticBoundaryResult;",
                    ]
                )
        else:
            raise AssertionError(f"unknown synthetic result shape: {shape}")
        return "\n".join(lines)

    @classmethod
    def _replace_boundary_result_return(cls, source: str, replacement: str) -> str:
        approved = cls._boundary_result_return()
        if source.count(approved) != 1:
            raise AssertionError("approved boundary result return identity")
        if replacement == approved:
            raise AssertionError("synthetic result mutation is unchanged")
        mutated = source.replace(approved, replacement, 1)
        if len(mutated) == 0 or mutated == source:
            raise AssertionError("synthetic result mutation failed")
        return mutated

    @classmethod
    def _arguments_for_repository(
        cls,
        repository: Path,
        output: Path,
        *,
        policy: Path,
        critical: Path,
        vectors: Path | None = None,
    ) -> list[str]:
        values = [
            str(cls.node),
            str(repository / PurePosixPath(ADAPTER_PATHS[9])),
            "--repository",
            str(repository),
            "--policy",
            str(policy),
            "--matrix-cell-id",
            "synthetic-host-cell",
            "--critical-tool-set",
            str(critical),
            "--runtime-identity",
            str(cls.runtime_path),
            "--git-identity",
            str(cls.git_path),
            "--platform-probe",
            str(cls.probe_path),
            "--test-vector-set",
            str(vectors or cls.vector_path),
            "--source-archive",
            str(cls.archive),
        ]
        for artifact in cls.artifacts:
            values.extend(
                [
                    "--artifact",
                    str(artifact["role"]),
                    str(artifact["format"]),
                    str(artifact["path"]),
                ]
            )
        values.extend(["--output-directory", str(output)])
        return values

    @classmethod
    def _arguments(
        cls,
        output: Path,
        *,
        policy: Path | None = None,
        probe: Path | None = None,
        git_identity: Path | None = None,
        critical: Path | None = None,
        vectors: Path | None = None,
    ) -> list[str]:
        values = [
            str(cls.node),
            str(cls.coordinator),
            "--repository",
            str(cls.repository),
            "--policy",
            str(policy or cls.policy_path),
            "--matrix-cell-id",
            "synthetic-host-cell",
            "--critical-tool-set",
            str(critical or cls.critical_path),
            "--runtime-identity",
            str(cls.runtime_path),
            "--git-identity",
            str(git_identity or cls.git_path),
            "--platform-probe",
            str(probe or cls.probe_path),
            "--test-vector-set",
            str(vectors or cls.vector_path),
            "--source-archive",
            str(cls.archive),
        ]
        for artifact in cls.artifacts:
            values.extend(
                [
                    "--artifact",
                    str(artifact["role"]),
                    str(artifact["format"]),
                    str(artifact["path"]),
                ]
            )
        values.extend(["--output-directory", str(output)])
        return values

    @classmethod
    def _api_options(cls, output: Path) -> dict[str, object]:
        return {
            "repository": str(cls.repository),
            "policy": str(cls.policy_path),
            "matrixCellId": "synthetic-host-cell",
            "criticalToolSet": str(cls.critical_path),
            "runtimeIdentity": str(cls.runtime_path),
            "gitIdentity": str(cls.git_path),
            "platformProbe": str(cls.probe_path),
            "testVectorSet": str(cls.vector_path),
            "sourceArchive": str(cls.archive),
            "artifacts": [
                {
                    "role": artifact["role"],
                    "format": artifact["format"],
                    "path": str(artifact["path"]),
                }
                for artifact in cls.artifacts
            ],
            "outputDirectory": str(output),
        }

    @classmethod
    def _ensure_success(cls) -> dict[str, object]:
        if cls._success is not None:
            return cls._success
        output = cls.base / CANARIES[13]
        process = cls._run(cls._arguments(output), timeout=900)
        if process.returncode != 0:
            raise AssertionError(f"stdout={process.stdout}\nstderr={process.stderr}")
        if process.stderr or process.stdout.count("\n") != 1:
            raise AssertionError("success diagnostics are not canonical")
        cls._success = {
            "process": process,
            "result": json.loads(process.stdout),
            "output": output,
        }
        return cls._success

    @classmethod
    def _assert_private_absent(cls, value: bytes | str) -> None:
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        for canary in CANARIES:
            if canary in text:
                raise AssertionError(f"privacy canary leaked: {canary}")
        if str(cls.base) in text:
            raise AssertionError("temporary path leaked")

    def _assert_boundary_failure(
        self,
        process: subprocess.CompletedProcess[str],
        output: Path,
    ) -> dict[str, object]:
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(process.stderr, "")
        self.assertEqual(process.stdout.count("\n"), 1)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["runResult"], "fail")
        self.assertEqual(result["failureClass"], "implementation-defect")
        self.assertEqual(result["failureCode"], "boundary-vector-failed")
        self.assertIsNot(result["boundaryVectorSetPassed"], True)
        self.assertIsNone(result["semanticReportSha256"])
        self.assertIsNone(result["artifactSha256"])
        self.assertIsNone(result["artifactByteLength"])
        self.assertTrue(output.is_dir())
        self.assertEqual(
            sorted(path.name for path in output.iterdir()),
            [".complete", "evidence.json", "input-set.json", "verification-result.json"],
        )
        for forbidden in (
            "receipt.source-receipt.json",
            "receipt-verification.json",
            "semantic-report.json",
        ):
            self.assertFalse((output / forbidden).exists())
        self.assertEqual(
            (output / ".complete").read_bytes(),
            b"ieltmps-public-source-receipt-reproducibility-complete-v1\n",
        )
        evidence = json.loads((output / "evidence.json").read_bytes())
        verification = json.loads((output / "verification-result.json").read_bytes())
        self.assertEqual(evidence["result"], "fail")
        self.assertEqual(evidence["failureCode"], "boundary-vector-failed")
        self.assertEqual(verification["evidenceResult"], "fail")
        self.assertIs(verification["comparisonEligible"], False)
        return result

    def test_01_vector_document_and_standalone_runner(self) -> None:
        raw = self.vector_path.read_bytes()
        self.assertEqual(raw, _canonical(json.loads(raw)))
        self.assertEqual(len(json.loads(raw)["vectors"]), 70)
        result = self._run(
            [str(self.node), str(self.runner), "--test-vector-set", str(self.vector_path)],
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual((parsed["vectorCount"], parsed["passedCount"]), (70, 70))
        self.assertTrue(parsed["boundaryVectorSetPassed"])
        self.__class__.vector_cases_executed += parsed["vectorCount"]
        self.__class__.vector_cases_passed += parsed["passedCount"]
        self.__class__.positive_adapter_cases += 3
        self.__class__.adversarial_subcases += 52
        self.__class__.cleanup_cases += 18

    def test_02_silent_imports_and_alias_safe_direct_execution(self) -> None:
        for module in (self.core, self.coordinator, self.runner):
            script = "await import(" + json.dumps(module.as_uri()) + ");"
            result = self._run([str(self.node), "--input-type=module", "--eval", script])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((result.stdout, result.stderr), ("", ""))
        direct = self._run([str(self.node), str(self.core)])
        self.assertNotEqual(direct.returncode, 0)
        self.assertIn("private-worker-unavailable", direct.stderr)
        self.__class__.positive_adapter_cases += 4
        self.__class__.worker_protocol_cases += 3

    def test_03_end_to_end_success_and_fixed_bundle(self) -> None:
        run = self._ensure_success()
        result = run["result"]
        output = run["output"]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["runResult"], "pass")
        self.assertEqual(result["artifactRole"], "public-source-receipt")
        self.assertEqual(
            sorted(path.name for path in output.iterdir()),
            sorted(
                [
                    ".complete",
                    "evidence.json",
                    "input-set.json",
                    "receipt-verification.json",
                    "receipt.source-receipt.json",
                    "semantic-report.json",
                    "verification-result.json",
                ]
            ),
        )
        self.assertEqual(
            (output / ".complete").read_bytes(),
            b"ieltmps-public-source-receipt-reproducibility-complete-v1\n",
        )
        self.assertFalse(any(path.name.startswith("private-") for path in output.iterdir()))
        self.__class__.positive_adapter_cases += 12
        self.__class__.cleanup_cases += 12

    def test_04_receipt_and_full_verifier_transcript(self) -> None:
        run = self._ensure_success()
        output = run["output"]
        receipt = json.loads((output / "receipt.source-receipt.json").read_bytes())
        transcript = json.loads((output / "receipt-verification.json").read_bytes())
        self.assertEqual(receipt["source"]["commit"], self.source_commit)
        self.assertEqual(receipt["tooling"]["commit"], self.tooling_commit)
        self.assertEqual(receipt["artifacts"], self.input_value["artifacts"])
        self.assertTrue(transcript["verificationComplete"])
        self.assertTrue(transcript["sourceArchiveVerified"])
        self.assertTrue(transcript["toolingCommitSignatureValid"])
        self.assertTrue(transcript["artifactsVerified"])
        self.assertEqual(transcript["receiptSha256"], _sha256((output / "receipt.source-receipt.json").read_bytes()))
        self.__class__.positive_adapter_cases += 8

    def test_05_independent_input_set_and_canonical_outputs(self) -> None:
        run = self._ensure_success()
        output = run["output"]
        self.assertEqual((output / "input-set.json").read_bytes(), self.input_bytes)
        for name in (
            "receipt.source-receipt.json",
            "receipt-verification.json",
            "input-set.json",
            "semantic-report.json",
            "evidence.json",
            "verification-result.json",
        ):
            raw = (output / name).read_bytes()
            self.assertEqual(raw[-1:], b"\n")
            self.assertNotIn(b"\r", raw)
            self.assertEqual(raw.count(b"\n"), 1)
        self.__class__.positive_adapter_cases += 7

    def test_06_semantic_and_frozen_r1_10a_claims(self) -> None:
        output = self._ensure_success()["output"]
        semantic = json.loads((output / "semantic-report.json").read_bytes())
        verification = json.loads((output / "verification-result.json").read_bytes())
        for key in (
            "canonicalVerifierPassed",
            "sameProcessRepeatable",
            "sameHostRepeatable",
            "boundaryVectorSetPassed",
        ):
            self.assertIs(semantic[key], True)
        self.assertIs(verification["semanticClaimsIndependentlyReplayed"], False)
        self.assertIs(verification["platformAttestationVerified"], False)
        self.assertIs(verification["evidenceSigningRequired"], True)
        self.assertIs(verification["projectPublicationAuthorized"], False)
        self.assertNotIn("claimLevel", json.dumps(verification))
        self.assertNotIn("comparison", " ".join(path.name for path in output.iterdir()))
        self.__class__.positive_adapter_cases += 10

    def test_07_same_host_worker_isolation_and_first_message_binding(self) -> None:
        result = self._ensure_success()["result"]
        self.assertIs(result["sameProcessRepeatable"], True)
        self.assertIs(result["sameHostRepeatable"], True)
        payloads = ["null", "{}", "[]", '"legacy"'] + [
            json.dumps({"protocol": f"invalid-{index}"}) for index in range(18)
        ]
        harness = r"""
import {fork} from 'node:child_process';
const payloads=JSON.parse(process.env.IELTMPS_PAYLOADS);
        let rejected=0;
        const observations=[];
        for (const payload of payloads) {
          await new Promise((resolve,reject)=>{
            const child=fork(process.env.IELTMPS_CORE,[],{
              cwd:process.env.IELTMPS_CWD,env:process.env,execArgv:[],
              stdio:['ignore','pipe','pipe','ipc'],windowsHide:true,
            });
            const stdout=[];const stderr=[];let responses=0;let forced=false;
            child.stdout.on('data',(chunk)=>stdout.push(Buffer.from(chunk)));
            child.stderr.on('data',(chunk)=>stderr.push(Buffer.from(chunk)));
            child.on('message',()=>{responses+=1;});
            const timer=setTimeout(()=>{forced=true;child.kill();},10000);
            child.on('close',(code,signal)=>{
              clearTimeout(timer);
              const out=Buffer.concat(stdout).toString('utf8');
              const err=Buffer.concat(stderr).toString('utf8');
              if(code!==1||signal!==null||forced||out!==''||responses!==0||!/^ERROR [A-Z_]+: [a-z0-9]+(?:-[a-z0-9]+)*\n$/u.test(err))reject(new Error(JSON.stringify({code,signal,forced,out,err,responses})));
              else{rejected+=1;observations.push({code,signal,forced,responses});resolve();}
            });
            child.send(payload);
          });
        }
        process.stdout.write(JSON.stringify({rejected,observations}));
        """
        process = self._run(
            [str(self.node), "--input-type=module", "--eval", harness],
            timeout=240,
            environment=self._environment(
                {
                    "IELTMPS_PAYLOADS": json.dumps(payloads),
                    "IELTMPS_CORE": str(self.core),
                    "IELTMPS_CWD": str(self.base),
                }
            ),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["rejected"], len(payloads))

        audit_output = self.base / CANARIES[15]
        audit_script = r"""
import {pathToFileURL} from 'node:url';
const module=await import(pathToFileURL(process.env.IELTMPS_COORDINATOR).href);
const options=JSON.parse(process.env.IELTMPS_OPTIONS);
let audit=null;
options[Symbol.for('ieltmps.public-source-receipt-reproducibility.worker-test-hook')]={
  protocolAudit:true,
  onProtocolAudit(value){audit=value;},
};
const adapterResult=await module.preparePublicSourceReceiptReproducibility(options);
process.stdout.write(JSON.stringify({adapterResult,audit})+'\n');
"""
        audit_process = self._run(
            [str(self.node), "--input-type=module", "--eval", audit_script],
            timeout=900,
            environment=self._environment(
                {
                    "IELTMPS_COORDINATOR": str(self.coordinator),
                    "IELTMPS_OPTIONS": json.dumps(self._api_options(audit_output)),
                }
            ),
        )
        self.assertEqual(audit_process.returncode, 0, audit_process.stderr)
        self.assertEqual(audit_process.stderr, "")
        audited = json.loads(audit_process.stdout)
        self.assertEqual(audited["adapterResult"]["runResult"], "pass")
        expected_invalid_first = [
            "legacy-arbitrary-parent",
            "invalid-first-only",
            "invalid-first-valid-second",
            "invalid-first-hostile-second",
            "missing-required-field",
            "extra-output-directory",
            "extra-receipt-path",
            "invalid-lease",
            "invalid-assignment",
            "invalid-nonce",
            "invalid-context",
            "assignment-swap",
            "nonce-swap",
            "context-swap",
        ]
        self.assertEqual(audited["audit"]["invalidFirstCases"], 14)
        self.assertEqual(audited["audit"]["invalidFirstCaseNames"], expected_invalid_first)
        self.assertIs(audited["audit"]["validFirstOnlyPassed"], True)
        self.assertIs(audited["audit"]["assignmentReplayPassed"], True)
        self.assertIs(audited["audit"]["parentIpcOpenExitPassed"], True)
        self.assertIs(audited["audit"]["loadedByteAuthorityPassed"], True)
        self.assertIs(audited["audit"]["legitimateStdioPassed"], True)
        self.assertIs(audited["audit"]["naturalExitPassed"], True)
        self.assertIs(audited["audit"]["immediateHostileSecondPassed"], True)
        self.assertIs(audited["audit"]["postClaimHostileSecondPassed"], True)
        self.assertEqual(audited["audit"]["legitimateWorkers"], 2)
        self.assertEqual(audited["audit"]["requestListenerCount"], 0)
        self.assertTrue((audit_output / ".complete").is_file())
        audit_cases = audited["audit"]["invalidFirstCases"] + 7
        self.__class__.worker_protocol_cases += len(payloads) + 2 + audit_cases
        self.__class__.positive_adapter_cases += 8
        self.__class__.cleanup_cases += len(payloads) + audit_cases

    def test_08_exclusive_output_directory_and_cli_shape(self) -> None:
        existing = self.base / CANARIES[14]
        existing.mkdir()
        process = self._run(self._arguments(existing), timeout=180)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("ERROR CLI: output-directory-exists", process.stderr)
        self.assertEqual(list(existing.iterdir()), [])
        missing = self._run([str(self.node), str(self.coordinator)])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("ERROR CLI: required-options", missing.stderr)
        self.__class__.adversarial_subcases += 2
        self.__class__.cleanup_cases += 2

    def test_09_vector_and_critical_authority_rejections(self) -> None:
        altered_vector = self.docs / "altered-vectors.json"
        vector = json.loads(self.vector_path.read_bytes())
        vector["vectors"][0], vector["vectors"][1] = vector["vectors"][1], vector["vectors"][0]
        altered_vector.write_bytes(_canonical(vector))
        output_a = self.base / "rejected-vector-output"
        process_a = self._run(self._arguments(output_a, vectors=altered_vector))
        self.assertNotEqual(process_a.returncode, 0)
        self.assertFalse(output_a.exists())

        altered_critical = self.docs / "altered-critical.json"
        critical = json.loads(self.critical_bytes)
        critical["entries"][0]["sha256"] = "0" * 64
        altered_critical.write_bytes(_canonical(critical))
        output_b = self.base / "rejected-critical-output"
        process_b = self._run(self._arguments(output_b, critical=altered_critical))
        self.assertNotEqual(process_b.returncode, 0)
        self.assertFalse(output_b.exists())
        self.__class__.adversarial_subcases += 8
        self.__class__.cleanup_cases += 2

    def test_10_canonical_failure_bundle_excludes_receipt_and_semantic(self) -> None:
        probe = json.loads(self.probe_bytes)
        probe["hardLinkSupported"] = False
        probe_bytes = _canonical(probe)
        probe_path = self.docs / "unsupported-probe.json"
        probe_path.write_bytes(probe_bytes)
        policy = self._policy_for_probe(probe_bytes)
        policy["requiredCells"][0]["platformProbeSha256"] = _sha256(probe_bytes)
        policy_path = self.docs / "unsupported-policy.json"
        policy_path.write_bytes(_canonical(policy))
        output = self.base / "canonical-failure-output"
        process = self._run(
            self._arguments(output, policy=policy_path, probe=probe_path),
            timeout=300,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["runResult"], "fail")
        self.assertEqual(
            sorted(path.name for path in output.iterdir()),
            [".complete", "evidence.json", "input-set.json", "verification-result.json"],
        )
        self.assertFalse((output / "receipt.source-receipt.json").exists())
        self.assertFalse((output / "semantic-report.json").exists())
        self.__class__.adversarial_subcases += 4
        self.__class__.cleanup_cases += 4

    def test_11_privacy_canaries_absent_from_all_public_surfaces(self) -> None:
        run = self._ensure_success()
        self._assert_private_absent(run["process"].stdout)
        self._assert_private_absent(run["process"].stderr)
        for path in run["output"].iterdir():
            if path.name == ".complete":
                continue
            self._assert_private_absent(path.read_bytes())
        vector = self._run(
            [str(self.node), str(self.runner), "--test-vector-set", str(self.vector_path)]
        )
        self.assertEqual(vector.returncode, 0, vector.stderr)
        self._assert_private_absent(vector.stdout)
        self.__class__.positive_adapter_cases += self.privacy_canary_count

    def test_12_independent_malformed_receipt_boundaries(self) -> None:
        receipt_path = self._ensure_success()["output"] / "receipt.source-receipt.json"
        original = receipt_path.read_bytes()
        value = json.loads(original)
        malformed = []
        wrong_kind = json.loads(json.dumps(value))
        wrong_kind["receiptKind"] = "wrong-kind"
        malformed.append(_canonical(wrong_kind))
        malformed.append(original[:-1])
        malformed.append(b"\xef\xbb\xbf" + original)
        malformed.append(original + b"\n")
        malformed.append(original.replace(b'"schemaVersion":1,', b'"schemaVersion":1,"schemaVersion":1,', 1))
        script = r"""
import {pathToFileURL} from 'node:url';
const m=await import(pathToFileURL(process.env.IELTMPS_VERIFY).href);
const values=JSON.parse(process.env.IELTMPS_VALUES);
let rejected=0;
for (const value of values) {
  try { m.parsePublicSourceReceiptBytes(Buffer.from(value,'base64')); }
  catch { rejected+=1; }
}
process.stdout.write(String(rejected));
"""
        process = self._run(
            [str(self.node), "--input-type=module", "--eval", script],
            environment=self._environment(
                {
                    "IELTMPS_VERIFY": str(self.receipt_verifier),
                    "IELTMPS_VALUES": json.dumps(
                        [base64.b64encode(item).decode("ascii") for item in malformed]
                    ),
                }
            ),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(int(process.stdout), len(malformed))
        self.__class__.adversarial_subcases += len(malformed)

    def test_13_worker_loaded_bytes_ignore_mutable_repository_substitution(self) -> None:
        harness = r"""
import {createHash} from 'node:crypto';
import {access,readFile,readdir,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const sha=(bytes)=>createHash('sha256').update(bytes).digest('hex');
const module=await import(pathToFileURL(process.env.IELTMPS_COORDINATOR).href);
const options=JSON.parse(process.env.IELTMPS_OPTIONS);
const target=process.env.IELTMPS_REPLACEMENT_TARGET;
const canary=process.env.IELTMPS_MALICIOUS_CANARY;
const original=await readFile(target);
const replacement=Buffer.from(
  "import {writeFile} from 'node:fs/promises';\n"+
  "await writeFile("+JSON.stringify(canary)+",Buffer.from('executed'));\n"+
  "export async function runPrivateReceiptWorker(){if(typeof process.send==='function')process.send(JSON.stringify({status:'ok',runResult:'pass'}));}\n",
  'utf8'
);
let attestation=null;
let restored=false;
options[Symbol.for('ieltmps.public-source-receipt-reproducibility.worker-test-hook')]={
  async afterCapsuleLocked(value){attestation=value;await writeFile(target,replacement);},
  async afterWorkersCompleted(){await writeFile(target,original);restored=true;},
};
let adapterResult;
try{adapterResult=await module.preparePublicSourceReceiptReproducibility(options);}
finally{if(!restored)await writeFile(target,original);}
let canaryPresent=true;
try{await access(canary);}catch{canaryPresent=false;}
const publicValues=[JSON.stringify(adapterResult)];
for(const name of await readdir(options.outputDirectory)){
  if(name!=='.complete')publicValues.push((await readFile(options.outputDirectory+'/'+name)).toString('utf8'));
}
const privateAttestationAbsent=!publicValues.join('').includes(attestation.capsuleSha256)&&!publicValues.join('').includes(attestation.moduleSetSha256);
process.stdout.write(JSON.stringify({
  adapterResult,canaryPresent,privateAttestationAbsent,
  entryMatches:attestation.entryModuleSha256===process.env.IELTMPS_EXPECTED_ENTRY_SHA,
  originalSha256:sha(original),replacementSha256:sha(replacement),restored,
})+'\n');
"""
        cases = [
            (self.core, self.base / CANARIES[16]),
            (self.repository / "developer/prepare-public-source-receipt.mjs", self.base / CANARIES[17]),
        ]
        expected_entry_sha = json.loads(self.critical_bytes)["entries"][8]["sha256"]
        for index, (target, canary) in enumerate(cases):
            output = self.base / f"loaded-byte-replay-{index}"
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", harness],
                timeout=900,
                environment=self._environment(
                    {
                        "IELTMPS_COORDINATOR": str(self.coordinator),
                        "IELTMPS_OPTIONS": json.dumps(self._api_options(output)),
                        "IELTMPS_REPLACEMENT_TARGET": str(target),
                        "IELTMPS_MALICIOUS_CANARY": str(canary),
                        "IELTMPS_EXPECTED_ENTRY_SHA": expected_entry_sha,
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stderr, "")
            replay = json.loads(process.stdout)
            self.assertEqual(replay["adapterResult"]["runResult"], "pass")
            self.assertFalse(replay["canaryPresent"])
            self.assertTrue(replay["restored"])
            self.assertNotEqual(replay["originalSha256"], replay["replacementSha256"])
            self.assertTrue(replay["entryMatches"])
            self.assertTrue(replay["privateAttestationAbsent"])
            public_text = process.stdout + "".join(
                path.read_text(encoding="utf-8")
                for path in output.iterdir()
                if path.name != ".complete"
            )
            self.assertNotIn(str(canary), public_text)
        self.__class__.loaded_byte_substitution_cases += len(cases)
        self.__class__.positive_adapter_cases += len(cases) * 5
        self.__class__.cleanup_cases += len(cases) * 4

    def test_14_capsule_substitution_and_unapproved_import_fail_closed(self) -> None:
        harness = r"""
import {createHash} from 'node:crypto';
import {lstat,mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const core=await import(pathToFileURL(process.env.IELTMPS_CORE).href);
const repository=process.env.IELTMPS_REPOSITORY;
const root=process.env.IELTMPS_CAPSULE_ROOT;
const relativePaths=JSON.parse(process.env.IELTMPS_MODULE_PATHS);
const sha=(bytes)=>createHash('sha256').update(bytes).digest('hex');
const identity=(state)=>Object.freeze({device:state.dev,inode:state.ino,meaningful:true});
const pathSha=(value)=>sha(Buffer.concat([Buffer.from('ieltmps-private-path-v1\0','ascii'),Buffer.from(value,'utf8')]));
const modules=[];
for(const relativePath of relativePaths){
  const source=await readFile(path.join(repository,...relativePath.split('/')));
  modules.push({relativePath,byteLength:source.length,sha256:sha(source),sourceBase64:source.toString('base64')});
}
const moduleSetSha=(values)=>{const hash=createHash('sha256');for(const entry of values){const source=Buffer.from(entry.sourceBase64,'base64');hash.update(Buffer.from(entry.relativePath,'utf8'));hash.update(Buffer.from([0]));hash.update(Buffer.from(String(source.length),'ascii'));hash.update(Buffer.from([0]));hash.update(source);}return hash.digest('hex');};
async function makeCapsule(label,alter){
  const directory=path.join(root,label);
  await mkdir(directory,{recursive:false});
  const selected=modules.map((entry)=>({...entry}));
  if(alter){
    const index=selected.findIndex((entry)=>entry.relativePath==='developer/public-source-archive-core.mjs');
    const source=Buffer.concat([Buffer.from(selected[index].sourceBase64,'base64'),Buffer.from('\nimport "./outside-capsule.mjs";\n','utf8')]);
    selected[index]={relativePath:selected[index].relativePath,byteLength:source.length,sha256:sha(source),sourceBase64:source.toString('base64')};
  }
  const capsuleValue={
    capsuleKind:'ieltmps-public-source-receipt-worker-capsule',schemaVersion:1,
    toolingCommit:process.env.IELTMPS_TOOLING_COMMIT,
    entryModule:'developer/public-source-receipt-reproducibility-core.mjs',
    moduleOrder:relativePaths,modules:selected,moduleSetSha256:moduleSetSha(selected),
  };
  const bytes=Buffer.from(JSON.stringify(capsuleValue)+'\n','utf8');
  const capsulePath=path.join(directory,'worker-modules.capsule.json');
  await writeFile(capsulePath,bytes,{flag:'wx'});
  const fileState=await lstat(capsulePath,{bigint:true});
  const directoryState=await lstat(directory,{bigint:true});
  const entry=selected.find((value)=>value.relativePath===capsuleValue.entryModule);
  return {
    path:capsulePath,pathSha256:pathSha(capsulePath),sha256:sha(bytes),
    moduleSetSha256:capsuleValue.moduleSetSha256,entryModuleSha256:entry.sha256,
    fileIdentity:identity(fileState),parentIdentity:identity(directoryState),
    record:{kind:'file',path:capsulePath,identity:identity(fileState),byteLength:bytes.length},
    directory:{kind:'directory',path:directory,identity:identity(directoryState)},
    originalBytes:bytes,
  };
}
await mkdir(root,{recursive:false});
const work=path.join(root,'worker-cwd');await mkdir(work);
const environment={...process.env};
for(const key of Object.keys(environment)){const upper=key.toUpperCase();if(upper==='NODE_OPTIONS'||upper==='NODE_PATH'||upper.includes('LOADER')||upper.includes('PRELOAD'))delete environment[key];}
const summarize=(observation)=>({
  code:observation.code,signal:observation.signal,timeout:observation.timeout,
  forcedTermination:observation.forcedTermination,stdout:observation.stdout.toString('utf8'),
  stderr:observation.stderr.toString('utf8'),responses:observation.responses.length,
});
const unapproved=await makeCapsule('unapproved',true);
const unapprovedObservation=await core.spawnTrustedWorkerRaw({
  requestMessages:['{}\n'],environment,workingDirectory:work,capsule:unapproved,
});
const substituted=await makeCapsule('substituted',false);
const substitutedObservation=await core.spawnTrustedWorkerRaw({
  requestMessages:['{}\n'],environment,workingDirectory:work,capsule:substituted,
  beforeSpawn:async()=>{await writeFile(substituted.path,Buffer.from('substituted\n','ascii'));},
});
process.stdout.write(JSON.stringify({
  unapproved:summarize(unapprovedObservation),
  substituted:summarize(substitutedObservation),
  workerEntries:await readdir(work),
})+'\n');
"""
        capsule_root = self.base / CANARIES[18]
        process = self._run(
            [str(self.node), "--input-type=module", "--eval", harness],
            timeout=180,
            environment=self._environment(
                {
                    "IELTMPS_CORE": str(self.core),
                    "IELTMPS_REPOSITORY": str(self.repository),
                    "IELTMPS_CAPSULE_ROOT": str(capsule_root),
                    "IELTMPS_MODULE_PATHS": json.dumps(ADAPTER_PATHS),
                    "IELTMPS_TOOLING_COMMIT": self.tooling_commit,
                }
            ),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        result = json.loads(process.stdout)
        for case in (result["unapproved"], result["substituted"]):
            self.assertEqual(case["code"], 1)
            self.assertIsNone(case["signal"])
            self.assertFalse(case["timeout"])
            self.assertFalse(case["forcedTermination"])
            self.assertEqual(case["stdout"], "")
            self.assertEqual(case["responses"], 0)
            self.assertEqual(
                case["stderr"],
                "ERROR TOOL_SET: worker-loaded-bytes-mismatch\n",
            )
        self.assertEqual(result["workerEntries"], [])
        self.assertFalse(any(path.name == ".complete" for path in capsule_root.rglob("*")))
        self.__class__.loaded_byte_substitution_cases += 2
        self.__class__.adversarial_subcases += 8
        self.__class__.cleanup_cases += 4

    def test_15_publication_race_matrix_repeats_without_mode_conversion(self) -> None:
        harness = r"""
import {lstat,mkdir,readFile,readdir,rename,unlink,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const core=await import(pathToFileURL(process.env.IELTMPS_CORE).href);
const root=process.env.IELTMPS_RACE_ROOT;
const repository=process.env.IELTMPS_REPOSITORY;
const repetitions=20;
const successNames=[
  'receipt.source-receipt.json','receipt-verification.json','input-set.json',
  'semantic-report.json','evidence.json','verification-result.json',
];
const failureNames=['input-set.json','evidence.json','verification-result.json'];
const definitions=[
  ['success-target-file-precreation','success'],
  ['failure-target-file-precreation','canonical-post-lock-failure'],
  ['receipt-target-replacement','success'],
  ['json-target-replacement','success'],
  ['final-directory-replacement','success'],
  ['parent-replacement','success'],
  ['unexpected-final-directory-entry','success'],
  ['success-failure-after-first','success'],
  ['success-failure-before-marker','success'],
  ['failure-failure-after-first','canonical-post-lock-failure'],
  ['success-to-failure-conversion','success'],
  ['marker-precreation','success'],
  ['marker-replacement','success'],
  ['post-marker-identity-mismatch','success'],
];
const expectedEntries=new Map([
  ['success-target-file-precreation',['receipt.source-receipt.json']],
  ['failure-target-file-precreation',['input-set.json']],
  ['receipt-target-replacement',['receipt.source-receipt.json']],
  ['json-target-replacement',['receipt-verification.json']],
  ['final-directory-replacement',['replacement-directory-object.txt']],
  ['parent-replacement',[]],
  ['unexpected-final-directory-entry',['unexpected-entry']],
  ['success-failure-after-first',[]],
  ['success-failure-before-marker',[]],
  ['failure-failure-after-first',[]],
  ['success-to-failure-conversion',[]],
  ['marker-precreation',['.complete']],
  ['marker-replacement',['.complete']],
  ['post-marker-identity-mismatch',['input-set.json']],
]);
const expectFinalAbsent=new Set([
  'parent-replacement','success-failure-after-first',
  'success-failure-before-marker','failure-failure-after-first',
  'success-to-failure-conversion',
]);
const expectedPhysicalMarker=new Set(['marker-precreation','marker-replacement']);
const state=async(value)=>{try{return await lstat(value,{bigint:true});}catch{return null;}};
const sameIdentity=(record,actual)=>actual!==null
  &&String(record.identity.device)===String(actual.dev)
  &&String(record.identity.inode)===String(actual.ino);
const stableSignatures=new Map(definitions.map(([name])=>[name,new Set()]));
const prototypes=new Map();
let caseCount=0;
let privateCleanupCount=0;
let finalCleanupCount=0;
let unrelatedPreservedCount=0;
let physicalMarkerCount=0;
let trustedMarkerCount=0;
let modeConversionCount=0;
let cleanupUncertaintyCount=0;
await mkdir(root,{recursive:false});
for(let repetition=0;repetition<repetitions;repetition+=1){
  for(const [name,mode] of definitions){
    caseCount+=1;
    const caseRoot=path.join(root,`repeat-${repetition}-${name}`);
    const outputParent=path.join(caseRoot,'output-parent');
    const targetPath=path.join(outputParent,'bundle');
    const unrelatedPath=path.join(caseRoot,'unrelated-object.txt');
    await mkdir(caseRoot);await mkdir(outputParent);
    await writeFile(unrelatedPath,Buffer.from('preserve-me\n','ascii'),{flag:'wx'});
    const target=await core.validateOutputTarget({
      outputDirectory:targetPath,sourceRepo:repository,toolingRepo:repository,
    });
    const rootLedger=[];const stagingLedger=[];const finalLedger=[];
    const privateRoot=await core.createCoordinatorPrivateRoot({target,ledger:rootLedger});
    const staging=await core.createOwnedDirectory(privateRoot,'bundle-staging',stagingLedger);
    const names=mode==='success'?successNames:failureNames;
    const entries=[];
    for(const entryName of names){
      const bytes=Buffer.from(JSON.stringify({entryName,mode})+'\n','ascii');
      const record=await core.writeOwnedFile(staging,entryName,bytes,stagingLedger);
      entries.push(Object.freeze({name:entryName,bytes,record}));
    }
    await core.validatePrivateBundleStaging(staging,entries);
    const decision=core.selectIrrevocableBundleMode(mode);
    let publication=null;
    let diagnostic='';
    let conversionBlocked=false;
    const attackPaths=[];
    const hooks={async checkpoint({checkpoint}){
      const fail=()=>{throw new core.PublicSourceReceiptReproducibilityError(
        'OUTPUT_PUBLICATION','synthetic-publication-race',
      );};
      if((name==='success-target-file-precreation'||name==='failure-target-file-precreation')
        &&checkpoint==='after-final-directory'){
        const attack=path.join(targetPath,names[0]);
        await writeFile(attack,Buffer.from('attacker-target\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='receipt-target-replacement'
        &&checkpoint==='after-publish-receipt.source-receipt.json'){
        const attack=path.join(targetPath,'receipt.source-receipt.json');
        await unlink(attack);await writeFile(attack,Buffer.from('attacker-receipt\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='json-target-replacement'
        &&checkpoint==='after-publish-receipt-verification.json'){
        const attack=path.join(targetPath,'receipt-verification.json');
        await unlink(attack);await writeFile(attack,Buffer.from('attacker-json\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='final-directory-replacement'
        &&checkpoint==='after-final-directory'){
        const preserved=path.join(caseRoot,'preserved-owned-final-directory');
        await rename(targetPath,preserved);await mkdir(targetPath);
        const attack=path.join(targetPath,'replacement-directory-object.txt');
        await writeFile(attack,Buffer.from('attacker-directory\n','ascii'),{flag:'wx'});
        attackPaths.push(attack,preserved);
      }else if(name==='parent-replacement'&&checkpoint==='before-final-directory'){
        const preserved=path.join(caseRoot,'preserved-original-output-parent');
        await rename(outputParent,preserved);await mkdir(outputParent);
        const attack=path.join(outputParent,'replacement-parent-object.txt');
        await writeFile(attack,Buffer.from('attacker-parent\n','ascii'),{flag:'wx'});
        attackPaths.push(attack,preserved);
      }else if(name==='unexpected-final-directory-entry'
        &&checkpoint==='after-final-directory'){
        const attack=path.join(targetPath,'unexpected-entry');
        await writeFile(attack,Buffer.from('unexpected\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if((name==='success-failure-after-first'||name==='failure-failure-after-first')
        &&checkpoint===`after-publish-${names[0]}`){
        fail();
      }else if(name==='success-to-failure-conversion'
        &&checkpoint===`after-publish-${names[0]}`){
        try{decision.beginPublication('canonical-post-lock-failure');}
        catch(error){conversionBlocked=error?.phase==='OUTPUT_PUBLICATION'
          &&error?.reason==='bundle-mode-immutable';throw error;}
        fail();
      }else if(name==='marker-precreation'&&checkpoint==='before-completion-marker'){
        const attack=path.join(targetPath,'.complete');
        await writeFile(attack,Buffer.from('attacker-marker\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='marker-replacement'&&checkpoint==='after-completion-marker'){
        const attack=path.join(targetPath,'.complete');
        await unlink(attack);await writeFile(attack,Buffer.from('attacker-marker\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='post-marker-identity-mismatch'
        &&checkpoint==='after-completion-marker'){
        const attack=path.join(targetPath,'input-set.json');
        await unlink(attack);await writeFile(attack,Buffer.from('attacker-post-marker\n','ascii'),{flag:'wx'});
        attackPaths.push(attack);
      }else if(name==='success-failure-before-marker'
        &&checkpoint==='before-completion-marker'){
        fail();
      }
    }};
    try{
      publication=await core.publishPrivateBundleNoReplace({
        target,sourceRepo:repository,toolingRepo:repository,staging,entries,
        finalLedger,modeDecision:decision,hooks,
      });
      await core.cleanupOwnedLedger(stagingLedger);
      await core.cleanupOwnedLedger(rootLedger);
      await core.finalizePublishedBundle({
        publication,entries,finalLedger,
        markerBytes:Buffer.from(core.COMPLETION_MARKER,'ascii'),hooks,
      });
      throw new Error('race case unexpectedly completed');
    }catch(error){
      diagnostic=`${error?.phase??'ERROR'}:${error?.reason??'operation-failed'}`;
      if(!publication&&error?.finalDirectory){
        publication=Object.freeze({finalDirectory:error.finalDirectory,mode});
      }
      try{await core.cleanupOwnedLedger(finalLedger);}catch{cleanupUncertaintyCount+=1;}
      if(publication?.finalDirectory){
        try{await core.removeEmptyOutputDirectory(publication.finalDirectory);}
        catch{cleanupUncertaintyCount+=1;}
      }
      try{await core.cleanupOwnedLedger(stagingLedger);}catch{cleanupUncertaintyCount+=1;}
      try{await core.cleanupOwnedLedger(rootLedger);}catch{cleanupUncertaintyCount+=1;}
    }
    if(decision.mode!==mode||decision.publicationStarted!==true)throw new Error('mode state');
    if((name==='success-to-failure-conversion')!==conversionBlocked)throw new Error('conversion state');
    if(conversionBlocked)modeConversionCount+=1;
    const targetState=await state(targetPath);
    const publicEntries=targetState?.isDirectory()?((await readdir(targetPath)).sort()):[];
    const expected=expectedEntries.get(name);
    if(JSON.stringify(publicEntries)!==JSON.stringify([...expected].sort()))throw new Error(
      JSON.stringify({name,publicEntries,expected}),
    );
    const finalAbsent=targetState===null;
    if(finalAbsent!==expectFinalAbsent.has(name))throw new Error(`final cleanup ${name}`);
    if(finalAbsent)finalCleanupCount+=1;
    const markerPath=path.join(targetPath,'.complete');
    const markerState=await state(markerPath);
    const markerRecord=finalLedger.find((record)=>record.path===markerPath);
    const physicalMarker=markerState!==null;
    const trustedMarker=markerRecord!==undefined&&sameIdentity(markerRecord,markerState)
      &&(await readFile(markerPath)).equals(Buffer.from(core.COMPLETION_MARKER,'ascii'));
    if(physicalMarker!==expectedPhysicalMarker.has(name)||trustedMarker)throw new Error(
      `marker authority ${name}`,
    );
    if(physicalMarker)physicalMarkerCount+=1;
    if(trustedMarker)trustedMarkerCount+=1;
    if(await state(privateRoot.path)!==null)throw new Error(`private cleanup ${name}`);
    privateCleanupCount+=1;
    if((await readFile(unrelatedPath,'utf8'))!=='preserve-me\n')throw new Error('unrelated');
    for(const attackPath of attackPaths){if(await state(attackPath)===null)throw new Error(`attack removed ${name}`);}
    unrelatedPreservedCount+=1;
    if(diagnostic.includes(root)||diagnostic.includes('ieltmps-receipt-private'))throw new Error('diagnostic privacy');
    const signature=JSON.stringify({mode,publicEntries,physicalMarker,trustedMarker,finalAbsent,conversionBlocked});
    stableSignatures.get(name).add(signature);
    if(!prototypes.has(name))prototypes.set(name,JSON.parse(signature));
  }
}
if([...stableSignatures.values()].some((values)=>values.size!==1))throw new Error('alternating race result');
process.stdout.write(JSON.stringify({
  repetitions,definitions:definitions.length,caseCount,privateCleanupCount,
  finalCleanupCount,unrelatedPreservedCount,physicalMarkerCount,
  trustedMarkerCount,modeConversionCount,cleanupUncertaintyCount,
  stableCaseCount:[...stableSignatures.values()].filter((values)=>values.size===1).length,
  prototypes:Object.fromEntries(prototypes),
})+'\n');
"""
        race_root = self.base / CANARIES[19]
        process = self._run(
            [str(self.node), "--input-type=module", "--eval", harness],
            timeout=900,
            environment=self._environment(
                {
                    "IELTMPS_CORE": str(self.core),
                    "IELTMPS_RACE_ROOT": str(race_root),
                    "IELTMPS_REPOSITORY": str(self.repository),
                }
            ),
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        result = json.loads(process.stdout)
        self.assertEqual(result["repetitions"], 20)
        self.assertEqual(result["definitions"], 14)
        self.assertEqual(result["caseCount"], 280)
        self.assertEqual(result["privateCleanupCount"], 280)
        self.assertEqual(result["unrelatedPreservedCount"], 280)
        self.assertEqual(result["trustedMarkerCount"], 0)
        self.assertEqual(result["physicalMarkerCount"], 40)
        self.assertEqual(result["modeConversionCount"], 20)
        self.assertEqual(result["stableCaseCount"], 14)
        self.assertEqual(len(result["prototypes"]), 14)
        self.__class__.publication_race_cases += result["caseCount"]
        self.__class__.adversarial_subcases += result["caseCount"]
        self.__class__.cleanup_cases += result["privateCleanupCount"]

    def test_16_vector_implementation_and_authority_mutations_fail(self) -> None:
        document = json.loads(self.vector_path.read_bytes())
        source = self.runner.read_text(encoding="utf-8")
        self.assertEqual(len(document["vectors"]), 70)
        for descriptor in document["vectors"]:
            vector_id = descriptor["vectorId"]
            case_id = descriptor["caseId"]
            if vector_id.startswith("R"):
                marker = f'case "{vector_id}"'
            elif vector_id in {"C01", "C02", "C03", "C04", "C05"}:
                marker = f"{vector_id}: Object.freeze"
            elif vector_id.startswith("C"):
                marker = f'vector.vectorId === "{vector_id}"'
            else:
                marker = f'case "{case_id}"'
            self.assertEqual(source.count(marker), 1, (vector_id, marker))

        reachable = self._run(
            [str(self.node), str(self.runner), "--test-vector-set", str(self.vector_path)],
            timeout=240,
        )
        self.assertEqual(reachable.returncode, 0, reachable.stderr)
        reachable_result = json.loads(reachable.stdout)
        self.assertEqual(
            (
                reachable_result["vectorCount"],
                reachable_result["passedCount"],
                reachable_result["failedCount"],
            ),
            (70, 70, 0),
        )

        mutations = [
            (
                'case "R01": {',
                'case "R01-disabled": {',
                "R01",
            ),
            (
                "actualPhase = implementation[1];",
                'actualPhase = "unrelated-phase";',
                "F01",
            ),
        ]
        original_runner = self.runner.read_bytes()
        for needle, replacement, expected_id in mutations:
            mutated = original_runner.decode("utf-8")
            self.assertEqual(mutated.count(needle), 1 if expected_id == "R01" else 2)
            mutated = mutated.replace(needle, replacement, 1)
            try:
                self.runner.write_text(mutated, encoding="utf-8", newline="\n")
                rejected = self._run(
                    [
                        str(self.node),
                        str(self.runner),
                        "--test-vector-set",
                        str(self.vector_path),
                    ],
                    timeout=240,
                )
            finally:
                self.runner.write_bytes(original_runner)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(expected_id, rejected.stderr)
            self.assertEqual(rejected.stdout, "")

        variants: list[tuple[str, dict[str, object], str | None]] = []
        phase_changed = json.loads(self.vector_path.read_bytes())
        phase_changed["vectors"][18]["expectedPhase"] = "unrelated-phase"
        variants.append(("phase", phase_changed, "F01"))
        reason_changed = json.loads(self.vector_path.read_bytes())
        reason_changed["vectors"][18]["expectedReason"] = "unrelated-reason"
        variants.append(("reason", reason_changed, "F01"))
        duplicated = json.loads(self.vector_path.read_bytes())
        duplicated["vectors"][1] = json.loads(json.dumps(duplicated["vectors"][0]))
        variants.append(("duplicate", duplicated, "R02"))
        reordered = json.loads(self.vector_path.read_bytes())
        reordered["vectors"][0], reordered["vectors"][1] = (
            reordered["vectors"][1],
            reordered["vectors"][0],
        )
        variants.append(("reorder", reordered, "R01"))
        for label, value, expected_id in variants:
            variant_path = self.docs / f"vector-authenticity-{label}.json"
            variant_path.write_bytes(_canonical(value))
            rejected = self._run(
                [str(self.node), str(self.runner), "--test-vector-set", str(variant_path)],
                timeout=60,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, "")
            if expected_id is not None:
                self.assertIn(expected_id, rejected.stderr)
        self.assertEqual(self.runner.read_bytes(), original_runner)
        self.assertEqual(self.vector_path.read_bytes(), VECTOR_SOURCE.read_bytes())
        self.__class__.positive_adapter_cases += 70
        self.__class__.adversarial_subcases += 6
        self.__class__.cleanup_cases += 6

    def test_17_exact_embedded_boundary_result_contract_rejections(self) -> None:
        original_source = self.runner.read_text(encoding="utf-8")
        self.assertEqual(
            original_source.encode("utf-8"),
            (REPO_ROOT / ADAPTER_PATHS[-1]).read_bytes(),
        )
        result_order = [
            "status",
            "mode",
            "vectorSetKind",
            "schemaVersion",
            "vectorSetId",
            "artifactRole",
            "formatProfile",
            "testVectorSetSha256",
            "vectorCount",
            "passedCount",
            "failedCount",
            "boundaryVectorSetPassed",
        ]
        reordered = result_order.copy()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        cases = [
            (
                "wrong-status",
                self._boundary_result_return(overrides={"status": '"failed"'}),
            ),
            (
                "wrong-mode",
                self._boundary_result_return(overrides={"mode": '"other-mode"'}),
            ),
            (
                "wrong-vector-set-kind",
                self._boundary_result_return(
                    overrides={
                        "vectorSetKind": (
                            '"IELTMPS-public-source-receipt-boundary-vector-set"'
                        )
                    }
                ),
            ),
            (
                "wrong-schema-version-type",
                self._boundary_result_return(overrides={"schemaVersion": '"1"'}),
            ),
            (
                "wrong-schema-version-value",
                self._boundary_result_return(overrides={"schemaVersion": "2"}),
            ),
            (
                "wrong-vector-set-id",
                self._boundary_result_return(
                    overrides={
                        "vectorSetId": '"public-source-receipt-v1-boundaries-v2"'
                    }
                ),
            ),
            (
                "wrong-artifact-role",
                self._boundary_result_return(
                    overrides={"artifactRole": '"public-source-archive"'}
                ),
            ),
            (
                "wrong-format-profile",
                self._boundary_result_return(
                    overrides={"formatProfile": '"ieltmps-public-source-receipt-v2"'}
                ),
            ),
            (
                "wrong-vector-sha256",
                self._boundary_result_return(
                    overrides={"testVectorSetSha256": f'"{"0" * 64}"'}
                ),
            ),
            (
                "wrong-vector-count",
                self._boundary_result_return(overrides={"vectorCount": "71"}),
            ),
            (
                "wrong-passed-count",
                self._boundary_result_return(overrides={"passedCount": "69"}),
            ),
            (
                "nonzero-failed-count",
                self._boundary_result_return(overrides={"failedCount": "1"}),
            ),
            (
                "false-boundary-vector-set-passed",
                self._boundary_result_return(
                    overrides={"boundaryVectorSetPassed": "false"}
                ),
            ),
            (
                "missing-result-key",
                self._boundary_result_return(omit={"vectorSetId"}),
            ),
            (
                "extra-result-key",
                self._boundary_result_return(
                    extra=[("unexpectedResultField", "true")]
                ),
            ),
            (
                "reordered-result-keys",
                self._boundary_result_return(order=reordered),
            ),
            (
                "non-plain-result-object",
                self._boundary_result_return(shape="null-prototype"),
            ),
            (
                "getter-result-field",
                self._boundary_result_return(shape="getter"),
            ),
            (
                "inherited-prototype-field",
                self._boundary_result_return(shape="prototype-field"),
            ),
            (
                "duplicate-logical-field",
                self._boundary_result_return(shape="duplicate-own-key-proxy"),
            ),
            (
                "symbol-result-field",
                self._boundary_result_return(shape="symbol-extra"),
            ),
        ]
        with tempfile.TemporaryDirectory(
            dir=self.base,
            prefix="boundary-result-contract-",
        ) as temporary:
            case_root = Path(temporary).resolve()
            tooling_repository = case_root / "synthetic-tooling-repository"
            shutil.copytree(self.repository, tooling_repository)
            self.assertNotEqual(tooling_repository, self.repository)
            self.assertEqual(
                self._git_at(tooling_repository, "status", "--porcelain"),
                b"",
            )
            observed_labels = []
            for index, (label, replacement) in enumerate(cases):
                mutated_source = self._replace_boundary_result_return(
                    original_source,
                    replacement,
                )
                self.assertEqual(original_source.count(self._boundary_result_return()), 1)
                self.assertNotEqual(mutated_source, original_source)
                tooling_commit = self._commit_runner_source(
                    tooling_repository,
                    mutated_source,
                    f"synthetic boundary result {index:02d}",
                )
                documents = self._write_bound_tooling_documents(
                    tooling_repository,
                    tooling_commit,
                    case_root / f"documents-{index:02d}",
                )
                critical = json.loads(documents["criticalBytes"])
                runner_entry = next(
                    entry
                    for entry in critical["entries"]
                    if entry["path"] == ADAPTER_PATHS[-1]
                )
                committed_runner = self._git_at(
                    tooling_repository,
                    "show",
                    f"{tooling_commit}:{ADAPTER_PATHS[-1]}",
                )
                self.assertEqual(runner_entry["sha256"], _sha256(committed_runner))
                self.assertEqual(
                    runner_entry["declaredByteSize"],
                    len(committed_runner),
                )
                output = case_root / f"output-{index:02d}"
                process = self._run(
                    self._arguments_for_repository(
                        tooling_repository,
                        output,
                        policy=documents["policyPath"],
                        critical=documents["criticalPath"],
                    ),
                    timeout=900,
                )
                result = self._assert_boundary_failure(process, output)
                self.assertEqual(result["toolingCommit"], tooling_commit)
                self.assertEqual(
                    json.loads(documents["policyBytes"])["criticalToolSetSha256"],
                    _sha256(documents["criticalBytes"]),
                )
                observed_labels.append(label)
                print(
                    f"R1-10C-BOUNDARY-RESULT-CASE {label}=passed",
                    flush=True,
                )
            self.assertEqual(observed_labels, [label for label, _ in cases])
        self.assertFalse(case_root.exists())
        self.__class__.boundary_result_contract_cases += len(cases)
        self.__class__.adversarial_subcases += len(cases)
        self.__class__.cleanup_cases += len(cases) * 4

    def test_18_standalone_success_cannot_mask_embedded_descriptor_failure(self) -> None:
        real_runner = REPO_ROOT / ADAPTER_PATHS[-1]
        real_runner_bytes = real_runner.read_bytes()
        original_source = self.runner.read_text(encoding="utf-8")
        self.assertEqual(real_runner_bytes, original_source.encode("utf-8"))
        standalone_harness = r"""
import {pathToFileURL} from 'node:url';
const runner=await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);
const result=await runner.runPublicSourceReceiptBoundaryVectors({
  testVectorSet:process.env.IELTMPS_VECTOR_SET,
  temporaryParent:process.env.IELTMPS_TEMPORARY_PARENT,
  expectedSha256:process.env.IELTMPS_VECTOR_SHA256,
});
process.stdout.write(JSON.stringify({
  processId:process.pid,
  temporaryParent:process.env.IELTMPS_TEMPORARY_PARENT,
  resultObjectObserved:typeof result==='object'&&result!==null,
  result,
})+'\n');
"""

        def run_standalone(parent: Path, vector_path: Path) -> dict[str, object]:
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", standalone_harness],
                timeout=300,
                environment=self._environment(
                    {
                        "IELTMPS_RUNNER": str(real_runner),
                        "IELTMPS_VECTOR_SET": str(vector_path),
                        "IELTMPS_TEMPORARY_PARENT": str(parent),
                        "IELTMPS_VECTOR_SHA256": _sha256(vector_path.read_bytes()),
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stderr, "")
            observed = json.loads(process.stdout)
            self.assertTrue(observed["resultObjectObserved"])
            self.assertEqual(observed["temporaryParent"], str(parent))
            self.assertEqual(
                (
                    observed["result"]["vectorCount"],
                    observed["result"]["passedCount"],
                    observed["result"]["failedCount"],
                    observed["result"]["boundaryVectorSetPassed"],
                ),
                (70, 70, 0, True),
            )
            self.assertEqual(
                sorted(path.name for path in parent.iterdir()),
                [vector_path.name],
            )
            return observed

        with tempfile.TemporaryDirectory(
            dir=self.base.parent,
            prefix="i-",
        ) as temporary:
            case_root = Path(temporary).resolve()
            private_parent_length = max(96, len(str(case_root)) + 8)
            long_leaf_length = private_parent_length - len(str(case_root)) - 1
            self.assertGreaterEqual(long_leaf_length, 8)
            long_private_parent = case_root / ("l" * long_leaf_length)
            embedded_output_parent = long_private_parent / "p"
            embedded_output_parent.mkdir(parents=True)
            self.assertEqual(len(str(long_private_parent)), private_parent_length)
            old_nested_repository = (
                long_private_parent
                / (".ieltmps-receipt-private-" + ("0" * 48))
                / "ieltmps-receipt-vectors-000000"
                / "synthetic-repository"
            )
            self.assertGreaterEqual(len(str(old_nested_repository)), 215)
            old_path_controls: list[tuple[str, int, int]] = []
            for label, controlled_git, fill in (
                ("Git A", APPROVED_GIT_A, "a"),
                ("Git B", APPROVED_GIT_B, "b"),
            ):
                old_leaf_length = 215 - len(str(case_root)) - 1
                self.assertGreater(old_leaf_length, 0)
                old_repository = case_root / (fill * old_leaf_length)
                self.assertEqual(len(str(old_repository)), 215)
                old_repository.mkdir()
                (old_repository / "f").write_bytes(b"x\n")
                initialized = self._run(
                    [
                        str(controlled_git),
                        "-c",
                        "core.longpaths=false",
                        "-C",
                        str(old_repository),
                        "init",
                    ],
                    timeout=60,
                )
                self.assertEqual(initialized.returncode, 0, initialized.stderr)
                added = self._run(
                    [
                        str(controlled_git),
                        "-c",
                        "core.longpaths=false",
                        "-c",
                        "core.autocrlf=false",
                        "-C",
                        str(old_repository),
                        "add",
                        "--",
                        "f",
                    ],
                    timeout=60,
                )
                old_object_path = (
                    old_repository
                    / ".git"
                    / "objects"
                    / "ff"
                    / ("0" * 38)
                )
                self.assertEqual(len(str(old_object_path)), 270)
                self.assertNotEqual(added.returncode, 0)
                self.assertIn("Filename too long", added.stderr)
                old_path_controls.append(
                    (label, len(str(old_repository)), len(str(old_object_path)))
                )
                shutil.rmtree(old_repository)
            self.assertEqual(
                old_path_controls,
                [("Git A", 215, 270), ("Git B", 215, 270)],
            )
            standalone_parent_a = case_root / "standalone-parent-a"
            standalone_parent_a.mkdir()
            standalone_vector_a = standalone_parent_a / "vectors-a.json"
            standalone_vector_a.write_bytes(VECTOR_SOURCE.read_bytes())
            standalone_a = run_standalone(
                standalone_parent_a,
                standalone_vector_a,
            )

            tooling_repository = case_root / "embedded-tooling-repository"
            shutil.copytree(self.repository, tooling_repository)
            baseline_documents = self._write_bound_tooling_documents(
                tooling_repository,
                self.tooling_commit,
                case_root / "baseline-documents",
            )
            embedded_success_output = embedded_output_parent / "s"
            embedded_success = self._run(
                self._arguments_for_repository(
                    tooling_repository,
                    embedded_success_output,
                    policy=baseline_documents["policyPath"],
                    critical=baseline_documents["criticalPath"],
                ),
                timeout=900,
            )
            self.assertEqual(embedded_success.returncode, 0, embedded_success.stderr)
            self.assertEqual(embedded_success.stderr, "")
            embedded_success_result = json.loads(embedded_success.stdout)
            self.assertEqual(embedded_success_result["runResult"], "pass")
            self.assertIs(embedded_success_result["boundaryVectorSetPassed"], True)
            self.assertTrue((embedded_success_output / ".complete").is_file())

            audit_path = case_root / "embedded-descriptor-audit.json"
            descriptor_block = (
                "        const result = completedVectorResult(vector, observation, true);\n"
                "        results.push(result);"
            )
            self.assertEqual(original_source.count(descriptor_block), 1)
            audit_literal = json.dumps(str(audit_path))
            altered_block = f"""        const result = completedVectorResult(
          vector,
          vector.vectorId === "R01"
            ? Object.freeze({{ ...observation, actualOutcome: "reject" }})
            : observation,
          true,
        );
        if (vector.vectorId === "R01") {{
          await writeFile(
            {audit_literal},
            Buffer.from(JSON.stringify({{
              processId: process.pid,
              temporaryParent: parent.path,
              temporaryParentIdentity: parent.identity,
              vectorWorkspace: root,
              workspacePlan: syntheticAuthority.workspacePlan,
              parentEntries: await readdir(parent.path),
              testVectorSet: options.testVectorSet,
              descriptorId: vector.vectorId,
              operationCompleted: result.operationCompleted,
              assertionsCompleted: result.assertionsCompleted,
              expectedOutcome: result.expectedOutcome,
              actualOutcome: result.actualOutcome,
              expectedPhase: result.expectedPhase,
              actualPhase: result.actualPhase,
              expectedReason: result.expectedReason,
              actualReason: result.actualReason,
            }}) + "\\n", "utf8"),
            {{ flag: "wx" }},
          );
          if (
            result.operationCompleted === true
            && result.assertionsCompleted === true
            && (
              result.actualOutcome !== result.expectedOutcome
              || result.actualPhase !== result.expectedPhase
              || result.actualReason !== result.expectedReason
            )
          ) failVector(vector.vectorId);
          failVector(vector.vectorId);
        }}
        results.push(result);"""
            altered_source = original_source.replace(descriptor_block, altered_block, 1)
            self.assertNotEqual(altered_source, original_source)
            self.assertEqual(altered_source.count(altered_block), 1)
            altered_commit = self._commit_runner_source(
                tooling_repository,
                altered_source,
                "synthetic embedded descriptor failure",
            )
            self.assertNotEqual(altered_commit, self.tooling_commit)
            altered_documents = self._write_bound_tooling_documents(
                tooling_repository,
                altered_commit,
                case_root / "altered-documents",
            )
            embedded_failure_output = embedded_output_parent / "f"
            embedded_failure = self._run(
                self._arguments_for_repository(
                    tooling_repository,
                    embedded_failure_output,
                    policy=altered_documents["policyPath"],
                    critical=altered_documents["criticalPath"],
                ),
                timeout=900,
            )
            failure_result = self._assert_boundary_failure(
                embedded_failure,
                embedded_failure_output,
            )
            self.assertEqual(failure_result["toolingCommit"], altered_commit)
            self.assertTrue(audit_path.is_file())
            audit = json.loads(audit_path.read_bytes())
            self.assertEqual(audit["descriptorId"], "R01")
            self.assertIs(audit["operationCompleted"], True)
            self.assertIs(audit["assertionsCompleted"], True)
            self.assertEqual(audit["expectedOutcome"], "accept")
            self.assertEqual(audit["actualOutcome"], "reject")
            self.assertEqual(audit["actualPhase"], audit["expectedPhase"])
            self.assertEqual(audit["actualReason"], audit["expectedReason"])
            self.assertNotEqual(audit["temporaryParent"], str(standalone_parent_a))
            self.assertNotEqual(audit["testVectorSet"], str(standalone_vector_a))
            self.assertNotEqual(audit["processId"], standalone_a["processId"])
            embedded_parent = Path(audit["temporaryParent"]).resolve()
            embedded_workspace = Path(audit["vectorWorkspace"]).resolve()
            self.assertEqual(embedded_workspace.parent, embedded_parent)
            self.assertRegex(embedded_workspace.name, r"^rv-[0-9a-f]{12}$")
            private_roots = [
                embedded_parent / name
                for name in audit["parentEntries"]
                if name.startswith(".ieltmps-receipt-private-")
            ]
            self.assertEqual(len(private_roots), 1)
            self.assertEqual(private_roots[0].parent, embedded_parent)
            self.assertFalse(embedded_workspace.is_relative_to(private_roots[0]))
            self.assertEqual(audit["workspacePlan"]["budget"], 240)
            self.assertLess(audit["workspacePlan"]["longestLength"], 240)
            self.assertLess(audit["workspacePlan"]["gitObjectPathLength"], 240)
            self.assertTrue(
                Path(audit["workspacePlan"]["gitObjectPath"]).is_relative_to(
                    embedded_workspace / "r"
                )
            )
            print(
                "R1-10C-PATH-BUDGET "
                "old_repository_length=215 "
                "old_object_path_length=270 "
                f"private_root_length={len(str(private_roots[0]))} "
                f"vector_root_length={len(str(embedded_workspace))} "
                f"longest_kind={audit['workspacePlan']['longestKind']} "
                f"longest_corrected_length={audit['workspacePlan']['longestLength']} "
                f"git_object_length={audit['workspacePlan']['gitObjectPathLength']}",
                flush=True,
            )
            self.assertFalse(embedded_workspace.exists())

            standalone_parent_b = case_root / "standalone-parent-b"
            standalone_parent_b.mkdir()
            standalone_vector_b = standalone_parent_b / "vectors-b.json"
            standalone_vector_b.write_bytes(VECTOR_SOURCE.read_bytes())
            standalone_b = run_standalone(
                standalone_parent_b,
                standalone_vector_b,
            )
            self.assertNotEqual(standalone_b["processId"], audit["processId"])
            self.assertNotEqual(standalone_parent_a, standalone_parent_b)
            self.assertNotEqual(standalone_vector_a, standalone_vector_b)
            self.assertEqual(real_runner.read_bytes(), real_runner_bytes)
            self.assertEqual(self.runner.read_bytes(), real_runner_bytes)
            self.assertEqual(
                self._git_at(tooling_repository, "status", "--porcelain"),
                b"",
            )
        self.__class__.vector_cases_executed += 210
        self.__class__.vector_cases_passed += 210
        self.__class__.standalone_embedded_independence_cases += 1
        self.__class__.deliberate_descriptor_failure_id = "R01"
        self.__class__.positive_adapter_cases += 8
        self.__class__.adversarial_subcases += 3
        self.__class__.cleanup_cases += 11

    def test_19_synthetic_signing_helper_authority_is_bound_and_fail_closed(self) -> None:
        self.assertIn(
            Path(os.path.normcase(str(self.git.resolve()))),
            {
                Path(os.path.normcase(str(APPROVED_GIT_A.resolve()))),
                Path(os.path.normcase(str(APPROVED_GIT_B.resolve()))),
            },
        )
        self.assertTrue(COMMON_WINDOWS_SSH_KEYGEN.is_file())
        harness = r"""
import {
  chmod, copyFile, lstat, mkdir, readFile, readdir, rm, unlink, writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const runner=await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);
const core=await import(pathToFileURL(process.env.IELTMPS_CORE).href);
const root=path.resolve(process.env.IELTMPS_CASE_ROOT);
const gitExecutable=path.resolve(process.env.IELTMPS_GIT);
const gitDirectory=path.dirname(gitExecutable);
const sourceHelper=path.resolve(process.env.IELTMPS_COMMON_HELPER);
const vectorSet=path.resolve(process.env.IELTMPS_VECTOR_SET);
const helperHookSymbol=Symbol.for(
  'ieltmps.public-source-receipt-boundary-vectors.signing-helper-test-hook',
);
if(process.platform!=='win32')throw new Error('windows control required');
const observations=[];
const privatePaths=[];
let caseSequence=0;
const exists=async(value)=>{try{await lstat(value);return true;}catch(error){if(error?.code==='ENOENT')return false;throw error;}};
const setPath=(entries)=>{
  for(const key of Object.keys(process.env))if(key.toUpperCase()==='PATH')delete process.env[key];
  process.env.PATH=entries.join(path.delimiter);
};
const createCase=async(label)=>{
  const caseRoot=path.join(root,String(caseSequence++).padStart(2,'0'));
  const helperDirectory=path.join(caseRoot,process.env.IELTMPS_SOURCE_CANARY);
  const vectorParent=path.join(caseRoot,'vp');
  await mkdir(helperDirectory,{recursive:true});
  await mkdir(vectorParent);
  return {caseRoot,helperDirectory,helperPath:path.join(helperDirectory,'ssh-keygen.exe'),vectorParent};
};
const finishCase=async(caseRoot)=>{
  await rm(caseRoot,{recursive:true,force:false});
  if(await exists(caseRoot))throw new Error('case cleanup');
};
const requireFailure=async(label,error,state)=>{
  if(
    !(error instanceof runner.PublicSourceReceiptBoundaryVectorError)
    ||error.phase!=='BOUNDARY_VECTOR'
    ||error.reason!=='synthetic-signing-helper-invalid'
    ||error.vectorId!==null
  )throw new Error(`classification ${label}`);
  const vectorEntries=await readdir(state.vectorParent);
  if(vectorEntries.length!==0)throw new Error(`descriptor workspace ${label}`);
  const publicSurface=JSON.stringify({phase:error.phase,reason:error.reason,vectorId:error.vectorId});
  if(
    publicSurface.includes(root)
    ||publicSurface.includes(sourceHelper)
    ||publicSurface.includes(process.env.IELTMPS_MALICIOUS_CANARY)
  )throw new Error(`privacy ${label}`);
  observations.push({
    label,phase:error.phase,reason:error.reason,vectorId:error.vectorId,
    vectorDescriptorCount:0,boundaryVectorSetPassed:null,successfulBundle:false,
    cleanup:vectorEntries.length===0,privacy:true,executionStarted:false,
  });
};
const runVectors=async(state,git,authority,hook=null)=>{
  const options={
    testVectorSet:vectorSet,
    temporaryParent:state.vectorParent,
    expectedSha256:process.env.IELTMPS_VECTOR_SHA256,
    syntheticSigningHelperAuthority:authority,
  };
  if(hook!==null)options[helperHookSymbol]=hook;
  core.installControlledGitPath(git);
  return runner.runPublicSourceReceiptBoundaryVectors(options);
};
const findPrivateHelper=async(state)=>{
  const roots=(await readdir(state.vectorParent,{withFileTypes:true}))
    .filter((entry)=>entry.isDirectory()&&/^rv-[0-9a-f]{12}$/u.test(entry.name));
  if(roots.length!==1)throw new Error('private root discovery');
  const helperDirectory=path.join(state.vectorParent,roots[0].name,'h');
  const names=await readdir(helperDirectory);
  if(names.length!==1||!/^k-[0-9a-f]{12}\.exe$/u.test(names[0])){
    throw new Error('private helper discovery');
  }
  const helperPath=path.join(helperDirectory,names[0]);
  privatePaths.push(helperDirectory,helperPath);
  return helperPath;
};
const replacePrivateHelper=async(state,sameSize)=>{
  const helperPath=await findPrivateHelper(state);
  await chmod(helperPath,0o700);
  const original=await readFile(helperPath);
  const replacement=sameSize
    ?Buffer.from(original)
    :Buffer.from(`MZ${process.env.IELTMPS_MALICIOUS_CANARY}\n`,'utf8');
  if(sameSize)replacement[0]^=1;
  await unlink(helperPath);
  await writeFile(helperPath,replacement,{flag:'wx',mode:0o500});
};

const state=await createCase('captured-byte-authority');
await copyFile(sourceHelper,state.helperPath);
setPath([gitDirectory,state.helperDirectory]);
const git=await core.resolveControlledGitExecutable();
const authority=await runner.resolveSyntheticSigningHelperAuthority({git});
const authorityKeys=[
  'authorityKind','schemaVersion','byteLength','sha256','sourceFileIdentity',
  'sourceParentIdentity','sourceBytesBase64','capabilityProfile',
];
if(
  !Object.isFrozen(authority)
  ||JSON.stringify(Object.keys(authority))!==JSON.stringify(authorityKeys)
  ||Object.hasOwn(authority,'absolutePath')
  ||authority.authorityKind!=='ieltmps-synthetic-signing-helper-byte-authority'
  ||authority.schemaVersion!==1
  ||Buffer.from(authority.sourceBytesBase64,'base64').length!==authority.byteLength
  ||Buffer.from(authority.sourceBytesBase64,'base64').toString('base64')!==authority.sourceBytesBase64
)throw new Error('captured authority schema');
const originalBytes=await readFile(state.helperPath);
const base64Prefix=authority.sourceBytesBase64.slice(0,32);
const capturedSha256=authority.sha256;
const successResults=[];
const auditHook=Object.freeze({checkpoint:async({checkpoint})=>{
  if(checkpoint==='before-helper-capability'&&privatePaths.length===0){
    await findPrivateHelper(state);
  }
}});

await unlink(state.helperPath);
await copyFile(gitExecutable,state.helperPath);
const replacedResult=await runVectors(state,git,authority,auditHook);
successResults.push(['source-replaced-after-capture',replacedResult]);

const sameSizeBytes=Buffer.from(originalBytes);sameSizeBytes[0]^=1;
await unlink(state.helperPath);
await writeFile(state.helperPath,sameSizeBytes,{flag:'wx'});
const sameSizeResult=await runVectors(state,git,authority);
successResults.push(['source-same-size-replaced-after-capture',sameSizeResult]);

await unlink(state.helperPath);
const deletedResult=await runVectors(state,git,authority);
successResults.push(['source-deleted-after-capture',deletedResult]);

for(const [label,result] of successResults){
  if(
    result.vectorCount!==70
    ||result.passedCount!==70
    ||result.failedCount!==0
    ||result.boundaryVectorSetPassed!==true
    ||process.env.PATH!==git.directory
    ||(await readdir(state.vectorParent)).length!==0
  )throw new Error(`captured source control ${label}`);
  const publicResult=JSON.stringify(result);
  if(
    publicResult.includes(root)
    ||publicResult.includes(sourceHelper)
    ||publicResult.includes(state.helperPath)
    ||publicResult.includes(base64Prefix)
    ||publicResult.includes(capturedSha256)
    ||publicResult.includes(process.env.IELTMPS_MALICIOUS_CANARY)
    ||privatePaths.some((value)=>publicResult.includes(value))
  )throw new Error(`authority privacy ${label}`);
  observations.push({
    label,phase:null,reason:null,vectorId:null,
    vectorDescriptorCount:70,boundaryVectorSetPassed:true,successfulBundle:false,
    cleanup:(await readdir(state.vectorParent)).length===0,privacy:true,
    executionStarted:true,
  });
}

const authorityMutations=[
  ['authority-base64-mutation',{sourceBytesBase64:authority.sourceBytesBase64.slice(0,-4)+'AAAA'}],
  ['authority-length-mutation',{byteLength:authority.byteLength+1}],
  ['authority-sha256-mutation',{sha256:'0'.repeat(64)}],
];
for(const [label,mutation] of authorityMutations){
  const forged=Object.freeze({...authority,...mutation});
  let error=null;
  try{await runVectors(state,git,forged);}catch(caught){error=caught;}
  await requireFailure(label,error,state);
}

const privateCaseProfiles=[
  ['private-helper-replaced-before-use',false,'before-helper-capability'],
  ['private-helper-same-size-replaced-before-use',true,'before-helper-capability'],
  ['private-helper-replaced-between-git-operations',true,'before-git-verify-commit'],
];
const helperSubstitutionRepetitions=[];
for(let repetition=1;repetition<=10;repetition+=1){
  const repetitionLabels=[];
  for(const [baseLabel,sameSize,mutationCheckpoint] of privateCaseProfiles){
    const label=`${baseLabel}-${String(repetition).padStart(2,'0')}`;
    let signedCommitCheckpoint=false;
    const hook=Object.freeze({checkpoint:async({checkpoint})=>{
      if(checkpoint==='before-git-signed-commit')signedCommitCheckpoint=true;
      if(checkpoint===mutationCheckpoint){
        if(
          mutationCheckpoint==='before-git-verify-commit'
          &&!signedCommitCheckpoint
        )throw new Error('signed Git operation not reached');
        await replacePrivateHelper(state,sameSize);
      }
    }});
    let error=null;
    try{await runVectors(state,git,authority,hook);}catch(caught){error=caught;}
    await requireFailure(label,error,state);
    if(await exists(path.join(state.caseRoot,process.env.IELTMPS_MALICIOUS_CANARY))){
      throw new Error(`malicious canary executed ${label}`);
    }
    repetitionLabels.push(label);
  }
  helperSubstitutionRepetitions.push({repetition,labels:repetitionLabels,passed:true});
}

let callerError=null;
try{
  await runner.resolveSyntheticSigningHelperAuthority({git,absolutePath:sourceHelper});
}catch(caught){callerError=caught;}
await requireFailure('caller-supplied-helper-path',callerError,state);

const publicSurfaces=JSON.stringify({
  observations,
  successResults:successResults.map(([label,result])=>({label,result})),
});
for(const privateValue of [
  root,sourceHelper,state.helperPath,base64Prefix,capturedSha256,
  process.env.IELTMPS_MALICIOUS_CANARY,...privatePaths,
])if(publicSurfaces.includes(privateValue))throw new Error('helper public-surface privacy');

await finishCase(state.caseRoot);
process.stdout.write(JSON.stringify({
  observations,
  successResults:successResults.map(([label,result])=>({label,result})),
  authoritySchema:true,
  sourceBytesCanonical:true,
  originalSourcePathRetained:false,
  maliciousCanaryExecuted:false,
  helperSubstitutionRepetitions,
  finalRootEntries:await readdir(root),
})+'\n');
"""
        with tempfile.TemporaryDirectory(
            dir=self.base,
            prefix="sha-",
        ) as temporary:
            case_root = Path(temporary).resolve()
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", harness],
                timeout=600,
                environment=self._environment(
                    {
                        "IELTMPS_RUNNER": str(REPO_ROOT / ADAPTER_PATHS[-1]),
                        "IELTMPS_CORE": str(REPO_ROOT / ADAPTER_PATHS[-3]),
                        "IELTMPS_CASE_ROOT": str(case_root),
                        "IELTMPS_GIT": str(self.git),
                        "IELTMPS_COMMON_HELPER": str(COMMON_WINDOWS_SSH_KEYGEN),
                        "IELTMPS_VECTOR_SET": str(self.vector_path),
                        "IELTMPS_VECTOR_SHA256": _sha256(self.vector_path.read_bytes()),
                        "IELTMPS_SOURCE_CANARY": CANARIES[36],
                        "IELTMPS_MALICIOUS_CANARY": CANARIES[37],
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stderr, "")
            observed = json.loads(process.stdout)
            labels = [entry["label"] for entry in observed["observations"]]
            expected_failures = [
                "authority-base64-mutation",
                "authority-length-mutation",
                "authority-sha256-mutation",
                *[
                    f"{base}-{repetition:02d}"
                    for repetition in range(1, 11)
                    for base in (
                        "private-helper-replaced-before-use",
                        "private-helper-same-size-replaced-before-use",
                        "private-helper-replaced-between-git-operations",
                    )
                ],
                "caller-supplied-helper-path",
            ]
            expected_successes = [
                "source-replaced-after-capture",
                "source-same-size-replaced-after-capture",
                "source-deleted-after-capture",
            ]
            self.assertEqual(labels, [*expected_successes, *expected_failures])
            for entry in observed["observations"][: len(expected_successes)]:
                self.assertEqual(entry["vectorDescriptorCount"], 70)
                self.assertIs(entry["boundaryVectorSetPassed"], True)
                self.assertTrue(entry["cleanup"])
                self.assertTrue(entry["privacy"])
                self.assertTrue(entry["executionStarted"])
            for entry in observed["observations"][len(expected_successes) :]:
                self.assertEqual(entry["phase"], "BOUNDARY_VECTOR")
                self.assertEqual(entry["reason"], "synthetic-signing-helper-invalid")
                self.assertIsNone(entry["vectorId"])
                self.assertEqual(entry["vectorDescriptorCount"], 0)
                self.assertIsNot(entry["boundaryVectorSetPassed"], True)
                self.assertFalse(entry["successfulBundle"])
                self.assertTrue(entry["cleanup"])
                self.assertTrue(entry["privacy"])
                self.assertFalse(entry["executionStarted"])
            for success in observed["successResults"]:
                self.assertEqual(
                    (
                        success["result"]["vectorCount"],
                        success["result"]["passedCount"],
                        success["result"]["failedCount"],
                        success["result"]["boundaryVectorSetPassed"],
                    ),
                    (70, 70, 0, True),
                )
            self.assertTrue(observed["authoritySchema"])
            self.assertTrue(observed["sourceBytesCanonical"])
            self.assertFalse(observed["originalSourcePathRetained"])
            self.assertFalse(observed["maliciousCanaryExecuted"])
            self.assertEqual(len(observed["helperSubstitutionRepetitions"]), 10)
            self.assertTrue(
                all(
                    entry["passed"]
                    and len(entry["labels"]) == 3
                    for entry in observed["helperSubstitutionRepetitions"]
                )
            )
            self.assertEqual(observed["finalRootEntries"], [])
            self._assert_private_absent(process.stdout)
        self.assertFalse(case_root.exists())

        cli_rejection = self._run(
            [
                str(self.node),
                str(REPO_ROOT / ADAPTER_PATHS[-1]),
                "--synthetic-signing-helper",
                str(COMMON_WINDOWS_SSH_KEYGEN),
            ]
        )
        self.assertNotEqual(cli_rejection.returncode, 0)
        self.assertEqual(cli_rejection.stdout, "")
        self.assertEqual(
            cli_rejection.stderr,
            "ERROR BOUNDARY_VECTOR: boundary-vector-failed\n",
        )
        self.assertNotIn(str(COMMON_WINDOWS_SSH_KEYGEN), cli_rejection.stderr)
        self.__class__.vector_cases_executed += 210
        self.__class__.vector_cases_passed += 210
        self.__class__.positive_adapter_cases += 12
        self.__class__.adversarial_subcases += len(expected_failures)
        self.__class__.cleanup_cases += len(expected_failures) + len(expected_successes) + 2

    def test_20_crossed_git_identity_rejects_before_helper_or_vectors(self) -> None:
        current = Path(os.path.normcase(str(self.git.resolve())))
        git_a = Path(os.path.normcase(str(APPROVED_GIT_A.resolve())))
        git_b = Path(os.path.normcase(str(APPROVED_GIT_B.resolve())))
        if current == git_a:
            crossed_identity = APPROVED_GIT_B
        elif current == git_b:
            crossed_identity = APPROVED_GIT_A
        else:
            self.fail(f"unapproved controlled Git: {self.git}")
        with tempfile.TemporaryDirectory(
            dir=self.base,
            prefix="crossed-git-identity-",
        ) as temporary:
            case_root = Path(temporary).resolve()
            documents = self._write_git_profile_documents(
                crossed_identity,
                case_root / "documents",
            )
            output = case_root / "output"
            process = self._run(
                self._arguments(
                    output,
                    policy=documents["policyPath"],
                    probe=documents["probePath"],
                    git_identity=documents["gitPath"],
                ),
                timeout=180,
            )
            self.assertEqual(process.returncode, 1)
            self.assertEqual(process.stdout, "")
            self.assertEqual(
                process.stderr,
                "ERROR GIT_IDENTITY: git-identity-mismatch\n",
            )
            self.assertFalse(output.exists())
            self.assertNotIn(str(self.base), process.stderr)
        self.assertFalse(case_root.exists())
        self.__class__.adversarial_subcases += 1
        self.__class__.cleanup_cases += 1


if __name__ == "__main__":
    unittest.main(verbosity=2)
