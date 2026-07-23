#!/usr/bin/env python3
"""Synthetic end-to-end tests for the R1-10B TAR reproducibility adapter."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
VECTOR_SOURCE = REPO_ROOT / "developer/public-source-archive-boundary-vectors-v1.json"
PRODUCTION_PATHS = (
    "developer/verify-public-source-membership.mjs",
    "developer/public-source-archive-core.mjs",
    "developer/prepare-public-source-archive.mjs",
    "developer/verify-public-source-archive.mjs",
    "developer/reproducibility-evidence-core.mjs",
    "developer/verify-reproducibility-evidence.mjs",
    "developer/public-source-archive-reproducibility-core.mjs",
    "developer/prepare-public-source-archive-reproducibility.mjs",
    "developer/run-public-source-archive-boundary-vectors.mjs",
)
CANARIES = {
    "source_repo": "canary-source-repository-4f21",
    "tooling_repo": "canary-tooling-repository-9a73",
    "policy": "canary-policy-772e",
    "critical": "canary-critical-tools-15bc",
    "runtime": "canary-runtime-identity-88d4",
    "git": "canary-git-identity-30af",
    "probe": "canary-platform-probe-61ce",
    "vectors": "canary-test-vectors-b902",
    "output": "canary-output-directory-ef45",
    "same_process": "canary-same-process-0c37",
    "same_host": "canary-same-host-a691",
    "archive": "canary-archive-2b58",
    "semantic": "canary-semantic-report-76e0",
    "evidence": "canary-evidence-193d",
    "verification": "canary-verification-542a",
    "username": "canary-user-819f",
    "drive": "canary-drive-q-650b",
    "hostname": "canary-host-41ad",
    "branch": "canary-branch-d35e",
    "remote": "canary-remote-073a",
    "environment": "canary-environment-f84c",
    "protected_member": "css/protected-looking-canary-c904.css",
    "lease_path": "canary-worker-lease-path-4d31",
    "private_root": "canary-worker-private-root-732f",
    "assignment_directory": "canary-worker-assignment-directory-51ba",
    "assignment_nonce": "canary-worker-assignment-nonce-800d",
    "run_id": "canary-worker-run-id-26c4",
    "context_digest_input": "canary-worker-context-input-9ee7",
    "claim_marker": "canary-worker-claim-marker-c013",
    "coordinator_pid": "canary-worker-coordinator-pid-674a",
    "worker_pid": "canary-worker-pid-2b9c",
}
GIT_REDIRECTIONS = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_REPLACE_REF_BASE",
}
BLOCK_SIZE = 512


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def _find_node() -> Path:
    configured = os.environ.get("IELTMPS_NODE")
    candidate = Path(configured).resolve() if configured else None
    if candidate and candidate.is_file():
        return candidate
    discovered = shutil.which("node")
    if discovered:
        return Path(discovered).resolve()
    raise RuntimeError("IELTMPS_NODE or node on PATH is required")


def _find_git() -> Path:
    discovered = shutil.which("git")
    if discovered:
        return Path(discovered).resolve()
    raise RuntimeError("git on PATH is required")


def _octal(value: int, width: int) -> bytes:
    encoded = format(value, "o")
    if value < 0 or len(encoded) > width - 1:
        raise ValueError("octal field overflow")
    return encoded.rjust(width - 1, "0").encode("ascii") + b"\0"


def _checksum(header: bytes | bytearray) -> int:
    copy_value = bytearray(header)
    copy_value[148:156] = b" " * 8
    return sum(copy_value)


def _checksum_field(value: int) -> bytes:
    return format(value, "o").rjust(6, "0").encode("ascii") + b"\0 "


def _split_ustar(archive_path: str) -> tuple[bytes, bytes]:
    raw = archive_path.encode("utf-8")
    if len(raw) <= 100:
        return raw, b""
    separator = archive_path.rfind("/")
    while separator > 0:
        prefix = archive_path[:separator].encode("utf-8")
        name = archive_path[separator + 1 :].encode("utf-8")
        if len(prefix) <= 155 and len(name) <= 100:
            return name, prefix
        separator = archive_path.rfind("/", 0, separator)
    raise ValueError("unrepresentable USTAR path")


def _header(archive_path: str, mode: int, size: int) -> bytes:
    name, prefix = _split_ustar(archive_path)
    header = bytearray(BLOCK_SIZE)
    header[: len(name)] = name
    header[100:108] = _octal(mode, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    header[148:156] = _checksum_field(_checksum(header))
    return bytes(header)


class PublicSourceArchiveReproducibilityTests(unittest.TestCase):
    """Every repository, policy, archive, report and probe is synthetic."""

    maxDiff = None
    positive_adapter_cases = 0
    adversarial_subcases = 0
    worker_protocol_cases = 0
    cleanup_cases = 0
    vector_cases = 52
    privacy_canary_count = len(CANARIES)
    _success_run: dict[str, object] | None = None
    _worker_private_values: tuple[str, ...] = ()

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        cls.git = _find_git()
        missing = [relative for relative in PRODUCTION_PATHS if not (REPO_ROOT / relative).is_file()]
        if missing or not VECTOR_SOURCE.is_file():
            raise RuntimeError("required R1-10B or frozen production source is unavailable")
        cls._temporary = tempfile.TemporaryDirectory(prefix="r1-10b-synthetic-")
        cls.base = Path(cls._temporary.name).resolve()
        cls.code_marker = cls.base / "selected-source-code-executed"
        cls.tooling_repo = cls.base / CANARIES["tooling_repo"]
        cls.source_repo = cls.base / CANARIES["source_repo"]
        cls.docs = cls.base / "canonical-documents"
        cls.docs.mkdir()
        cls._create_tooling_repository()
        cls._create_source_repository()
        cls._create_bound_documents()

    @classmethod
    def tearDownClass(cls) -> None:
        duration = time.monotonic() - cls.started
        methods = unittest.defaultTestLoader.loadTestsFromTestCase(cls).countTestCases()
        print(
            "R1-10B-SUMMARY "
            f"test_methods={methods} "
            f"positive_adapter_cases={cls.positive_adapter_cases} "
            f"adversarial_subcases={cls.adversarial_subcases} "
            f"worker_protocol_cases={cls.worker_protocol_cases} "
            f"cleanup_cases={cls.cleanup_cases} "
            f"privacy_canaries={cls.privacy_canary_count} "
            f"vector_cases_executed={cls.vector_cases} "
            f"vector_cases_passed={cls.vector_cases} "
            f"duration_seconds={duration:.3f}"
        )
        cls._temporary.cleanup()

    @classmethod
    def _environment(cls, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in GIT_REDIRECTIONS:
            environment.pop(name, None)
        environment["PATH"] = os.pathsep.join(
            [str(cls.git.parent), str(cls.node.parent), environment.get("PATH", "")]
        )
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["IELTMPS_PRIVACY_ENV"] = CANARIES["environment"]
        environment["IELTMPS_PRIVACY_USERNAME"] = CANARIES["username"]
        environment["IELTMPS_PRIVACY_DRIVE"] = CANARIES["drive"]
        environment["IELTMPS_PRIVACY_HOSTNAME"] = CANARIES["hostname"]
        for name in (
            "lease_path",
            "private_root",
            "assignment_directory",
            "assignment_nonce",
            "run_id",
            "context_digest_input",
            "claim_marker",
            "coordinator_pid",
            "worker_pid",
        ):
            environment[f"IELTMPS_PRIVACY_{name.upper()}"] = CANARIES[name]
        environment["IELTMPS_SELECTED_CODE_MARKER"] = str(cls.code_marker)
        if additions:
            environment.update(additions)
        return environment

    @classmethod
    def _run(
        cls,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: int = 120,
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
    def _git(cls, repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
        completed = subprocess.run(
            [str(cls.git), "-C", str(repo), *arguments],
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
    def _initialize_git(cls, repo: Path, label: str) -> None:
        repo.mkdir(parents=True)
        cls._git(repo, "init")
        for key, value in (
            ("user.name", CANARIES["username"]),
            ("user.email", f"{label}@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git(repo, "config", key, value)
        cls._git(repo, "checkout", "-b", CANARIES["branch"])
        cls._git(
            repo,
            "remote",
            "add",
            "origin",
            f"https://example.invalid/{CANARIES['remote']}.git",
        )

    @classmethod
    def _write_relative(cls, root: Path, relative: str, data: bytes) -> None:
        target = root / PurePosixPath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    @classmethod
    def _create_tooling_repository(cls) -> None:
        cls._initialize_git(cls.tooling_repo, "tooling")
        for relative in PRODUCTION_PATHS:
            cls._write_relative(cls.tooling_repo, relative, (REPO_ROOT / relative).read_bytes())
        cls._git(cls.tooling_repo, "add", "--", *PRODUCTION_PATHS)
        cls._git(cls.tooling_repo, "commit", "-m", "synthetic tooling authority")
        cls.tooling_commit = cls._git(
            cls.tooling_repo, "rev-parse", "HEAD"
        ).decode("ascii").strip()
        cls.coordinator = cls.tooling_repo / PRODUCTION_PATHS[7]
        cls.core = cls.tooling_repo / PRODUCTION_PATHS[6]
        cls.runner = cls.tooling_repo / PRODUCTION_PATHS[8]
        cls.b1 = cls.tooling_repo / PRODUCTION_PATHS[0]
        cls.b3_verifier = cls.tooling_repo / PRODUCTION_PATHS[3]

    @classmethod
    def _manifest_bytes(cls) -> bytes:
        script = (
            "import {pathToFileURL} from 'node:url';"
            "const m=await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);"
            "process.stdout.write(m.buildSyntheticPublicSourceManifestBytes().toString('base64'));"
        )
        result = cls._run(
            [str(cls.node), "--input-type=module", "--eval", script],
            environment=cls._environment({"IELTMPS_RUNNER": str(cls.runner)}),
        )
        if result.returncode != 0 or result.stderr:
            raise AssertionError(result.stderr)
        return base64.b64decode(result.stdout)

    @classmethod
    def _create_source_repository(cls) -> None:
        cls._initialize_git(cls.source_repo, "source")
        manifest_bytes = cls._manifest_bytes()
        manifest = json.loads(manifest_bytes)
        exact_paths: set[str] = set()
        for component in manifest["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            data = (
                manifest_bytes
                if relative == "developer/public-source-manifest.json"
                else f"synthetic:{relative}\n".encode("utf-8")
            )
            cls._write_relative(cls.source_repo, relative, data)
        prefix_members = {
            "backend/admin/admin.js": b"export const admin = true;\n",
            "backend/auth/auth.js": b"export const auth = true;\n",
            "backend/migrations/001_init.sql": b"SELECT 1;\n",
            "backend/scripts/executable.sh": b"#!/bin/sh\nexit 0\n",
            "backend/src/app.js": b"export const app = true;\n",
            "backend/test/app.test.js": b"export const test = true;\n",
            "css/app.css": b"body {}\n",
            "js/app.js": (
                b"import {writeFileSync} from 'node:fs';\n"
                b"writeFileSync(process.env.IELTMPS_SELECTED_CODE_MARKER, 'executed');\n"
            ),
            "src/styles/app.css": b":root {}\n",
            CANARIES["protected_member"]: b"synthetic protected-looking name only\n",
        }
        for relative, data in prefix_members.items():
            cls._write_relative(cls.source_repo, relative, data)
        cls._git(cls.source_repo, "add", "-A")
        cls._git(
            cls.source_repo,
            "update-index",
            "--chmod=+x",
            "--",
            "backend/scripts/executable.sh",
        )
        cls._git(cls.source_repo, "commit", "-m", "synthetic historical source")
        cls.source_commit = cls._git(
            cls.source_repo, "rev-parse", "HEAD"
        ).decode("ascii").strip()
        (cls.source_repo / "css/app.css").write_bytes(b"dirty working tree cannot influence commit\n")

    @classmethod
    def _membership_summary(cls) -> dict[str, object]:
        script = r"""
import {pathToFileURL} from 'node:url';
const module = await import(pathToFileURL(process.env.IELTMPS_B1).href);
const result = await module.loadValidatedPublicSourceMembership({
  repo: process.env.IELTMPS_SOURCE_REPO,
  commit: process.env.IELTMPS_SOURCE_COMMIT,
});
process.stdout.write(JSON.stringify({
  manifestSha256: result.manifestSha256,
  reportBase64: result.reportBytes.toString('base64'),
  members: result.members.map((member) => ({
    path: member.path,
    gitMode: member.gitMode,
    objectId: member.objectId,
    declaredByteSize: member.declaredByteSize,
    sha256: member.sha256,
    role: member.role,
    licenseScope: member.licenseScope,
    blobBase64: member.blobBytes.toString('base64'),
  })),
}));
"""
        result = cls._run(
            [str(cls.node), "--input-type=module", "--eval", script],
            environment=cls._environment(
                {
                    "IELTMPS_B1": str(cls.b1),
                    "IELTMPS_SOURCE_REPO": str(cls.source_repo),
                    "IELTMPS_SOURCE_COMMIT": cls.source_commit,
                }
            ),
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def _critical_tool_document(cls) -> dict[str, object]:
        entries = []
        for relative in PRODUCTION_PATHS:
            line = cls._git(
                cls.tooling_repo,
                "ls-tree",
                cls.tooling_commit,
                "--",
                relative,
            ).decode("utf-8").strip()
            header, reported_path = line.split("\t", 1)
            mode, object_type, object_id = header.split(" ")
            if reported_path != relative or object_type != "blob":
                raise AssertionError("unexpected synthetic tooling tree entry")
            data = (cls.tooling_repo / PurePosixPath(relative)).read_bytes()
            entries.append(
                {
                    "path": relative,
                    "gitMode": mode,
                    "gitBlobObjectId": object_id,
                    "declaredByteSize": len(data),
                    "sha256": _sha256(data),
                }
            )
        return {
            "documentKind": "ieltmps-reproducibility-critical-tool-set",
            "schemaVersion": 1,
            "toolSetId": "public-source-archive-reproducibility-v1",
            "toolingCommit": cls.tooling_commit,
            "entries": entries,
        }

    @classmethod
    def _node_facts(cls) -> dict[str, str]:
        script = (
            "import os from 'node:os';"
            "process.stdout.write(JSON.stringify({"
            "execPath:process.execPath,node:process.versions.node,v8:process.versions.v8,"
            "modules:process.versions.modules,platform:process.platform,arch:process.arch,"
            "osRelease:os.release().toLowerCase()}));"
        )
        result = cls._run([str(cls.node), "--input-type=module", "--eval", script])
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def _create_bound_documents(cls) -> None:
        cls.membership = cls._membership_summary()
        cls.report_bytes = base64.b64decode(cls.membership["reportBase64"])
        input_members = [
            {
                "pathUtf8Hex": member["path"].encode("utf-8").hex(),
                "gitMode": member["gitMode"],
                "gitBlobObjectId": member["objectId"],
                "declaredByteSize": member["declaredByteSize"],
                "contentSha256": member["sha256"],
                "role": member["role"],
                "licenseScope": member["licenseScope"],
            }
            for member in cls.membership["members"]
        ]
        cls.input_value = {
            "documentKind": "ieltmps-public-source-archive-input-set",
            "schemaVersion": 1,
            "sourceRepositoryProfileId": "git-sha1-b1-membership-v1",
            "sourceCommit": cls.source_commit,
            "sourceManifestSha256": cls.membership["manifestSha256"],
            "membershipReportSha256": _sha256(cls.report_bytes),
            "membershipCount": len(input_members),
            "members": input_members,
        }
        cls.input_bytes = _canonical(cls.input_value)

        cls.vector_path = cls.docs / f"{CANARIES['vectors']}.json"
        cls.vector_path.write_bytes(VECTOR_SOURCE.read_bytes())
        cls.critical_path = cls.docs / f"{CANARIES['critical']}.json"
        cls.critical_bytes = _canonical(cls._critical_tool_document())
        cls.critical_path.write_bytes(cls.critical_bytes)

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
        cls.runtime_path = cls.docs / f"{CANARIES['runtime']}.json"
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
        cls.git_path = cls.docs / f"{CANARIES['git']}.json"
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
        cls.probe_path = cls.docs / f"{CANARIES['probe']}.json"
        cls.probe_bytes = _canonical(cls.probe_value)
        cls.probe_path.write_bytes(cls.probe_bytes)
        cls.policy = cls._policy_for_probe_bytes(cls.probe_bytes)
        cls.policy_path = cls.docs / f"{CANARIES['policy']}.json"
        cls.policy_bytes = _canonical(cls.policy)
        cls.policy_path.write_bytes(cls.policy_bytes)

    @classmethod
    def _policy_for_probe_bytes(cls, probe_bytes: bytes) -> dict[str, object]:
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
            "policyId": "r1-10b-synthetic-policy",
            "artifactRole": "public-source-archive",
            "formatProfile": "tar-ustar-v1",
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "criticalToolSetSha256": _sha256(cls.critical_bytes),
            "manifestSha256": _sha256(cls.report_bytes),
            "inputSetSha256": _sha256(cls.input_bytes),
            "testVectorSetSha256": _sha256(cls.vector_path.read_bytes()),
            "requiredClaimLevels": ["L0"],
            "requiredCells": [cell],
            "optionalCells": [],
        }

    @classmethod
    def _adapter_arguments(
        cls,
        output: Path,
        *,
        policy: Path | None = None,
        probe: Path | None = None,
        critical: Path | None = None,
    ) -> list[str]:
        return [
            str(cls.node),
            str(cls.coordinator),
            "--source-repo",
            str(cls.source_repo),
            "--tooling-repo",
            str(cls.tooling_repo),
            "--policy",
            str(policy or cls.policy_path),
            "--matrix-cell-id",
            "synthetic-host-cell",
            "--critical-tool-set",
            str(critical or cls.critical_path),
            "--runtime-identity",
            str(cls.runtime_path),
            "--git-identity",
            str(cls.git_path),
            "--platform-probe",
            str(probe or cls.probe_path),
            "--test-vector-set",
            str(cls.vector_path),
            "--output-directory",
            str(output),
        ]

    @classmethod
    def _ensure_success(cls) -> dict[str, object]:
        if cls._success_run is not None:
            return cls._success_run
        output = cls.base / CANARIES["output"]
        process = cls._run(cls._adapter_arguments(output), timeout=600)
        if process.returncode != 0:
            raise AssertionError(f"stdout={process.stdout}\nstderr={process.stderr}")
        if process.stderr or process.stdout.count("\n") != 1:
            raise AssertionError("adapter success diagnostics are not canonical")
        result = json.loads(process.stdout)
        cls._success_run = {"process": process, "result": result, "output": output}
        return cls._success_run

    @classmethod
    def _independent_archive(cls) -> bytes:
        chunks: list[bytes] = []
        for member in cls.membership["members"]:
            payload = base64.b64decode(member["blobBase64"])
            mode = 0o755 if member["gitMode"] == "100755" else 0o644
            chunks.append(_header("ieltmps-source/" + member["path"], mode, len(payload)))
            chunks.append(payload)
            chunks.append(bytes((-len(payload)) % BLOCK_SIZE))
        chunks.append(bytes(2 * BLOCK_SIZE))
        return b"".join(chunks)

    def test_01_vector_document_is_exact_canonical_authority(self) -> None:
        raw = self.vector_path.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertNotIn(b"\r", raw)
        self.assertTrue(all(byte < 0x80 for byte in raw))
        value = json.loads(raw)
        self.assertEqual(len(value["vectors"]), 52)
        self.assertEqual(value["vectors"][0]["vectorId"], "W01")
        self.assertEqual(value["vectors"][-1]["vectorId"], "M22")
        altered = self.base / "altered-vector-set.json"
        changed = copy.deepcopy(value)
        changed["vectors"].pop()
        altered.write_bytes(_canonical(changed))
        script = (
            "import {pathToFileURL} from 'node:url';"
            "const m=await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);"
            "try{await m.validatePublicSourceArchiveBoundaryVectorSet({testVectorSet:process.env.IELTMPS_VECTOR});"
            "process.stdout.write('accepted');}catch{process.stdout.write('rejected');}"
        )
        process = self._run(
            [str(self.node), "--input-type=module", "--eval", script],
            environment=self._environment(
                {"IELTMPS_RUNNER": str(self.runner), "IELTMPS_VECTOR": str(altered)}
            ),
        )
        self.assertEqual(process.stdout, "rejected")
        type(self).adversarial_subcases += 4

    def test_02_independent_python_ustar_authority(self) -> None:
        archive = self._independent_archive()
        valid_path = self.base / "python-independent-valid.tar"
        invalid_path = self.base / "python-independent-invalid.tar"
        valid_path.write_bytes(archive)
        invalid = bytearray(archive)
        invalid[0] ^= 1
        invalid_path.write_bytes(invalid)
        base_args = [
            str(self.node),
            str(self.b3_verifier),
            "--repo",
            str(self.source_repo),
            "--commit",
            self.source_commit,
            "--archive",
        ]
        valid = self._run([*base_args, str(valid_path)])
        malformed = self._run([*base_args, str(invalid_path)])
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertNotEqual(malformed.returncode, 0)
        self.assertEqual(_sha256(archive), json.loads(valid.stdout)["archiveSha256"])
        valid_path.unlink()
        invalid_path.unlink()
        type(self).positive_adapter_cases += 3
        type(self).adversarial_subcases += 1
        type(self).cleanup_cases += 2

    def test_03_successful_adapter_flow_is_canonical_and_non_overstated(self) -> None:
        run = self._ensure_success()
        result = run["result"]
        output: Path = run["output"]
        self.assertEqual(result["runResult"], "pass")
        self.assertTrue(result["canonicalVerifierPassed"])
        self.assertTrue(result["sameProcessRepeatable"])
        self.assertTrue(result["sameHostRepeatable"])
        self.assertTrue(result["boundaryVectorSetPassed"])
        self.assertFalse(result["semanticClaimsIndependentlyReplayed"])
        self.assertFalse(result["platformAttestationVerified"])
        self.assertTrue(result["evidenceSigningRequired"])
        self.assertFalse(result["projectPublicationAuthorized"])
        expected_names = {
            "artifact.tar",
            "b1-membership-report.json",
            "input-set.json",
            "b3-verification.json",
            "semantic-report.json",
            "evidence.json",
            "verification-result.json",
            ".complete",
        }
        self.assertEqual({item.name for item in output.iterdir()}, expected_names)
        self.assertFalse((output / "comparison-report.json").exists())
        self.assertEqual(
            (output / ".complete").read_bytes(),
            b"ieltmps-public-source-archive-reproducibility-complete-v1\n",
        )
        self.assertEqual(
            (output / "b1-membership-report.json").read_bytes(), self.report_bytes
        )
        self.assertEqual((output / "input-set.json").read_bytes(), self.input_bytes)
        artifact = (output / "artifact.tar").read_bytes()
        self.assertEqual(artifact, self._independent_archive())
        self.assertEqual(_sha256(artifact), result["artifactSha256"])
        self.assertEqual(len(artifact), result["artifactByteLength"])
        semantic_bytes = (output / "semantic-report.json").read_bytes()
        evidence_bytes = (output / "evidence.json").read_bytes()
        verification_bytes = (output / "verification-result.json").read_bytes()
        semantic = json.loads(semantic_bytes)
        evidence = json.loads(evidence_bytes)
        verification = json.loads(verification_bytes)
        self.assertEqual(_sha256(semantic_bytes), result["semanticReportSha256"])
        self.assertEqual(_sha256(evidence_bytes), result["evidenceSha256"])
        self.assertEqual(_sha256(verification_bytes), result["verificationResultSha256"])
        self.assertEqual(
            [
                semantic["canonicalVerifierPassed"],
                semantic["sameProcessRepeatable"],
                semantic["sameHostRepeatable"],
                semantic["boundaryVectorSetPassed"],
            ],
            [True, True, True, True],
        )
        self.assertTrue(verification["comparisonEligible"])
        self.assertFalse(verification["platformAttestationVerified"])
        self.assertFalse(verification["projectPublicationAuthorized"])
        self.assertEqual(evidence["result"], "pass")
        transcript = json.loads((output / "b3-verification.json").read_bytes())
        self.assertTrue(transcript["archiveVerified"])
        self.assertEqual(transcript["archiveSha256"], result["artifactSha256"])
        marker_time = (output / ".complete").stat().st_mtime_ns
        self.assertGreaterEqual(
            marker_time,
            max((output / name).stat().st_mtime_ns for name in expected_names - {".complete"}),
        )
        forbidden_claim_text = semantic_bytes + evidence_bytes + verification_bytes
        for claim in (b'"L3"', b'"L4"', b'"L5"', b'"L6"'):
            self.assertNotIn(claim, forbidden_claim_text)
        self.assertEqual(
            self._git(self.source_repo, "rev-parse", "HEAD").decode().strip(),
            self.source_commit,
        )
        self.assertNotEqual(self.source_commit, self.tooling_commit)
        self.assertFalse(self.code_marker.exists())
        type(self).positive_adapter_cases += 32
        type(self).cleanup_cases += 5

    def test_04_canonical_failure_bundle_has_no_artifact_or_semantic_report(self) -> None:
        probe = copy.deepcopy(self.probe_value)
        probe["pathPolicyCapabilities"]["portableRelativePathsSupported"] = False
        probe_bytes = _canonical(probe)
        probe_path = self.docs / "unsupported-platform-probe.json"
        probe_path.write_bytes(probe_bytes)
        policy = self._policy_for_probe_bytes(probe_bytes)
        policy_path = self.docs / "unsupported-platform-policy.json"
        policy_path.write_bytes(_canonical(policy))
        output = self.base / "canonical-failure-output"
        process = self._run(
            self._adapter_arguments(output, policy=policy_path, probe=probe_path),
            timeout=180,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(process.stderr, "")
        result = json.loads(process.stdout)
        self.assertEqual(result["runResult"], "fail")
        self.assertEqual(result["failureClass"], "unsupported-platform")
        self.assertEqual(result["failureCode"], "unsupported-host-capability")
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {
                "b1-membership-report.json",
                "input-set.json",
                "evidence.json",
                "verification-result.json",
                ".complete",
            },
        )
        self.assertFalse((output / "artifact.tar").exists())
        self.assertFalse((output / "semantic-report.json").exists())
        verification = json.loads((output / "verification-result.json").read_bytes())
        self.assertFalse(verification["comparisonEligible"])
        self.assertIsNone(verification["canonicalVerifierPassed"])
        type(self)._failure_output = output
        type(self).adversarial_subcases += 8
        type(self).cleanup_cases += 3

    def test_05_authority_cli_and_no_replace_adversarial_cases(self) -> None:
        unknown = self._run([str(self.node), str(self.coordinator), "--worker-command", "x"])
        self.assertEqual(unknown.returncode, 1)
        self.assertEqual(unknown.stdout, "")
        self.assertEqual(unknown.stderr.count("\n"), 1)
        self.assertNotIn(str(self.base), unknown.stderr)

        wrong_critical_value = json.loads(self.critical_bytes)
        wrong_critical_value["entries"][0]["sha256"] = "0" * 64
        wrong_critical = self.docs / "wrong-critical.json"
        wrong_critical.write_bytes(_canonical(wrong_critical_value))
        wrong_output = self.base / "wrong-critical-output"
        wrong = self._run(
            self._adapter_arguments(wrong_output, critical=wrong_critical), timeout=120
        )
        self.assertEqual(wrong.returncode, 1)
        self.assertFalse(wrong_output.exists())
        self.assertIn("POLICY_BINDING", wrong.stderr)

        existing = self.base / "already-existing-output"
        existing.mkdir()
        existing_run = self._run(self._adapter_arguments(existing), timeout=180)
        self.assertEqual(existing_run.returncode, 1)
        self.assertEqual(list(existing.iterdir()), [])

        loaded_path = self.tooling_repo / PRODUCTION_PATHS[3]
        original = loaded_path.read_bytes()
        loaded_path.write_bytes(original + b"\n// synthetic working-tree mutation\n")
        try:
            actual_output = self.base / "wrong-loaded-tool-output"
            actual = self._run(self._adapter_arguments(actual_output), timeout=180)
            self.assertEqual(actual.returncode, 1)
            self.assertFalse(actual_output.exists())
            self.assertIn("TOOLING_BINDING", actual.stderr)
        finally:
            loaded_path.write_bytes(original)

        for spelling in (
            str(self.core),
            str(PurePosixPath("developer") / self.core.name),
            str(Path("developer") / "." / self.core.name),
        ):
            direct = self._run(
                [str(self.node), spelling],
                cwd=self.tooling_repo,
                timeout=10,
            )
            self.assertEqual(direct.returncode, 1)
            self.assertEqual(direct.stdout, "")
            self.assertEqual(direct.stderr, "ERROR CLI: private-worker-unavailable\n")
        type(self).adversarial_subcases += 10
        type(self).cleanup_cases += 4

    def test_06_imports_are_side_effect_free_and_worker_protocol_is_isolated(self) -> None:
        script = (
            "const initialExitCode = process.exitCode;"
            "await import(process.env.IELTMPS_COORDINATOR_URL);"
            "await import(process.env.IELTMPS_CORE_URL);"
            "await import(process.env.IELTMPS_RUNNER_URL);"
            "if (process.exitCode !== initialExitCode) "
            "throw new Error('import changed process.exitCode');"
        )
        imported = self._run(
            [str(self.node), "--input-type=module", "--eval", script],
            environment=self._environment(
                {
                    "IELTMPS_COORDINATOR_URL": self.coordinator.as_uri(),
                    "IELTMPS_CORE_URL": self.core.as_uri(),
                    "IELTMPS_RUNNER_URL": self.runner.as_uri(),
                }
            ),
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(imported.stdout, "")
        self.assertEqual(imported.stderr, "")

        completed_protocol_cases = 0
        direct = self._run([str(self.node), str(self.core)], timeout=10)
        self.assertEqual(direct.returncode, 1)
        self.assertEqual(direct.stdout, "")
        self.assertEqual(direct.stderr, "ERROR CLI: private-worker-unavailable\n")
        completed_protocol_cases += 1

        legacy_token = "c" * 64
        legacy_token_json = json.dumps(legacy_token)
        reviewer_harness = r"""
import {fork} from 'node:child_process';
const token = %s;
const env = {...process.env, IELTMPS_REPRODUCIBILITY_WORKER_TOKEN: token};
const child = fork(process.env.IELTMPS_CORE, [], {
  env, execArgv: [], serialization: 'json',
  stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true,
});
let stderr = '';
const messages = [];
let exitObserved = false;
let exitCode = null;
let exitSignal = null;
let timedOut = false;
let forcedTermination = false;
let harnessError = null;
const parentDisconnected = false;
let secondMessageAttempted = false;
child.stderr.setEncoding('utf8');
child.stderr.on('data', (chunk) => { stderr += chunk; });
child.on('message', (message) => { messages.push(message); });
const timeout = setTimeout(() => {
  timedOut = true;
  forcedTermination = true;
  child.kill();
}, 5000);
child.on('error', (error) => { harnessError = error?.code ?? 'child-error'; });
child.on('exit', (code, signal) => {
  exitObserved = true;
  exitCode = code;
  exitSignal = signal;
  clearTimeout(timeout);
});
child.on('close', () => process.stdout.write(JSON.stringify({
  code: exitCode, signal: exitSignal, stderr, messages, exitObserved,
  timedOut, forcedTermination, harnessError, parentDisconnected,
  secondMessageAttempted,
})));
const request = {
  protocol: 'ieltmps-public-source-archive-worker-v1', token,
  sourceRepo: process.env.IELTMPS_SOURCE_REPO,
  sourceCommit: process.env.IELTMPS_SOURCE_COMMIT,
  outputDirectory: process.env.IELTMPS_FORGED_OUTPUT,
  expectedGitSha256: process.env.IELTMPS_GIT_SHA256,
  expectedGitByteLength: Number(process.env.IELTMPS_GIT_LENGTH),
};
child.send(request, () => {});
secondMessageAttempted = true;
child.send({...request, outputDirectory: process.env.IELTMPS_SECOND_FORGED_OUTPUT}, () => {});
""" % legacy_token_json
        reviewer_output = self.base / "reviewer-chosen-worker-output"
        second_reviewer_output = self.base / "reviewer-second-worker-output"
        reviewer = self._run(
            [str(self.node), "--input-type=module", "--eval", reviewer_harness],
            environment=self._environment(
                {
                    "IELTMPS_CORE": str(self.core),
                    "IELTMPS_SOURCE_REPO": str(self.source_repo),
                    "IELTMPS_SOURCE_COMMIT": self.source_commit,
                    "IELTMPS_GIT_SHA256": self.git_value["executableSha256"],
                    "IELTMPS_GIT_LENGTH": str(self.git_value["executableByteLength"]),
                    "IELTMPS_FORGED_OUTPUT": str(reviewer_output),
                    "IELTMPS_SECOND_FORGED_OUTPUT": str(second_reviewer_output),
                }
            ),
            timeout=15,
        )
        self.assertEqual(reviewer.returncode, 0, reviewer.stderr)
        replay = json.loads(reviewer.stdout)
        self.assertTrue(replay["exitObserved"])
        self.assertFalse(replay["timedOut"])
        self.assertFalse(replay["forcedTermination"])
        self.assertIsNone(replay["harnessError"])
        self.assertFalse(replay["parentDisconnected"])
        self.assertTrue(replay["secondMessageAttempted"])
        self.assertEqual(replay["code"], 1)
        self.assertIsNone(replay["signal"])
        self.assertFalse(replay["messages"])
        self.assertEqual(
            replay["stderr"],
            "ERROR SAME_HOST: private-worker-request-invalid\n",
        )
        self.assertNotIn(legacy_token, replay["stderr"])
        self.assertNotIn(str(self.base), replay["stderr"])
        for forged_output in (reviewer_output, second_reviewer_output):
            self.assertFalse(forged_output.exists())
            self.assertFalse((forged_output / "artifact.tar").exists())
            self.assertFalse((forged_output / ".complete").exists())
        completed_protocol_cases += 1

        lease_harness = r"""
import {fork} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync,
  realpathSync, renameSync, rmdirSync, rmSync, symlinkSync, unlinkSync, watch,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

const protocol = 'ieltmps-public-source-archive-worker-v2';
const leaseProtocol = 'ieltmps-public-source-archive-worker-lease-v1';
const leaseName = '.worker-lease.json';
const claimName = '.worker-claim.json';
const archiveName = 'artifact.tar';
const scenario = process.env.IELTMPS_SCENARIO;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const pathHash = (value) => sha256(Buffer.concat([
  Buffer.from('ieltmps-private-path-v1\0', 'ascii'), Buffer.from(value, 'utf8'),
]));
const privateBytes = (value) => Buffer.from(JSON.stringify(value) + '\n', 'utf8');
const contextHash = (value) => sha256(Buffer.concat([
  Buffer.from('ieltmps-worker-locked-context-v1\0', 'ascii'), privateBytes(value),
]));
const identity = (state) => ({
  device: state.dev.toString(10), inode: state.ino.toString(10),
  meaningful: state.dev !== 0n || state.ino !== 0n,
});
const inspect = (value) => {
  const resolved = path.resolve(realpathSync.native(value));
  if (resolved !== value) throw new Error('test path is not exact');
  const state = lstatSync(value, {bigint: true});
  return {path: value, pathSha256: pathHash(value), identity: identity(state)};
};
const makeDirectory = (value) => mkdirSync(value, {mode: 0o700});

const caseParent = path.resolve(process.env.IELTMPS_CASE_ROOT);
makeDirectory(caseParent);
let root = path.join(caseParent, 'same-host-workers');
makeDirectory(root);
let workerA = path.join(root, 'worker-a');
let workerB = path.join(root, 'worker-b');
makeDirectory(workerA); makeDirectory(workerB);
let leasePath = path.join(root, leaseName);
const source = inspect(path.resolve(process.env.IELTMPS_SOURCE_REPO));
const tooling = inspect(path.resolve(process.env.IELTMPS_TOOLING_REPO));
const rootInfo = inspect(root);
const parentInfo = inspect(caseParent);
const aInfo = inspect(workerA);
const bInfo = inspect(workerB);
const context = {
  sourceRepository: {pathSha256: source.pathSha256, identity: source.identity},
  toolingRepository: {pathSha256: tooling.pathSha256, identity: tooling.identity},
  sourceCommit: process.env.IELTMPS_SOURCE_COMMIT,
  toolingCommit: process.env.IELTMPS_TOOLING_COMMIT,
  policySha256: process.env.IELTMPS_POLICY_SHA256,
  matrixCellId: 'synthetic-host-cell',
  criticalToolSetSha256: process.env.IELTMPS_CRITICAL_SHA256,
  runtimeIdentitySha256: process.env.IELTMPS_RUNTIME_SHA256,
  gitIdentitySha256: process.env.IELTMPS_GIT_IDENTITY_SHA256,
  platformProbeSha256: process.env.IELTMPS_PROBE_SHA256,
  testVectorSetSha256: process.env.IELTMPS_VECTOR_SHA256,
  membershipReportSha256: process.env.IELTMPS_MEMBERSHIP_SHA256,
  inputSetSha256: process.env.IELTMPS_INPUT_SHA256,
  artifactRole: 'public-source-archive',
  formatProfile: 'tar-ustar-v1',
  gitExecutableSha256: process.env.IELTMPS_GIT_EXECUTABLE_SHA256,
  gitExecutableByteLength: Number(process.env.IELTMPS_GIT_EXECUTABLE_LENGTH),
};
const digest = contextHash(context);
const nonceA = sha256(Buffer.from('assignment-a-' + scenario));
const nonceB = sha256(Buffer.from('assignment-b-' + scenario));
const assignment = (id, nonce, directory) => ({
  assignmentId: id,
  assignmentNonce: nonce,
  directoryPathSha256: directory.pathSha256,
  directoryParentIdentity: rootInfo.identity,
  directoryIdentity: directory.identity,
  archiveFilename: archiveName,
  lockedContextDigest: digest,
  state: 'unused',
});
let lease = {
  protocol: leaseProtocol,
  schemaVersion: 1,
  runId: sha256(Buffer.from('run-' + scenario)),
  coordinatorPid: process.pid,
  coordinatorModuleRealpathSha256: pathHash(path.resolve(
    realpathSync.native(process.env.IELTMPS_COORDINATOR),
  )),
  privateRootPathSha256: rootInfo.pathSha256,
  privateRootIdentity: rootInfo.identity,
  privateRootParentIdentity: parentInfo.identity,
  lockedContext: context,
  lockedContextDigest: digest,
  assignments: [assignment('worker-a', nonceA, aInfo), assignment('worker-b', nonceB, bInfo)],
};
const writeLease = (target = leasePath) => writeFileSync(target, privateBytes(lease), {mode: 0o600});
writeLease();
const pristineRequest = () => ({
  protocol,
  leaseReference: leasePath,
  assignmentId: 'worker-a',
  assignmentNonce: nonceA,
  sourceRepositoryPath: source.path,
  toolingRepositoryPath: tooling.path,
  lockedContext: context,
});
let request = pristineRequest();
let rawRequest = null;
const rewriteLease = () => writeFileSync(leasePath, privateBytes(lease));
const bumpIdentity = (value) => ({
  ...value, inode: (BigInt(value.inode) + 1n).toString(10), meaningful: true,
});

if (scenario === 'no-lease') {
  const missing = path.join(caseParent, 'missing-root');
  makeDirectory(missing);
  request.leaseReference = path.join(missing, leaseName);
} else if (scenario === 'lease-outside-root') {
  const outside = path.join(caseParent, 'outside-root');
  makeDirectory(outside);
  const outsideLease = path.join(outside, leaseName);
  copyFileSync(leasePath, outsideLease);
  request.leaseReference = outsideLease;
} else if (scenario === 'wrong-lease-protocol') {
  lease.protocol = 'wrong-worker-lease-protocol'; rewriteLease();
} else if (scenario === 'wrong-coordinator-pid') {
  lease.coordinatorPid = process.pid + 1; rewriteLease();
} else if (scenario === 'wrong-root-identity') {
  lease.privateRootIdentity = bumpIdentity(lease.privateRootIdentity); rewriteLease();
} else if (scenario === 'wrong-root-parent-identity') {
  lease.privateRootParentIdentity = bumpIdentity(lease.privateRootParentIdentity); rewriteLease();
} else if (scenario === 'wrong-assigned-identity') {
  lease.assignments[0].directoryIdentity = bumpIdentity(lease.assignments[0].directoryIdentity);
  rewriteLease();
} else if (scenario === 'wrong-assignment-id') {
  lease.assignments[0].assignmentId = 'worker-z'; rewriteLease();
} else if (scenario === 'wrong-assignment-nonce') {
  request.assignmentNonce = 'f'.repeat(64);
} else if (scenario === 'wrong-context-digest') {
  lease.lockedContextDigest = '0'.repeat(64); rewriteLease();
} else if (scenario === 'extra-request-field') {
  request.extra = true;
} else if (scenario === 'missing-request-field') {
  delete request.toolingRepositoryPath;
} else if (scenario === 'request-output-directory') {
  request.outputDirectory = path.join(caseParent, 'caller-output');
} else if (scenario === 'request-archive-path') {
  request.archivePath = path.join(caseParent, 'caller-artifact.tar');
} else if (
  scenario === 'invalid-first-only'
  || scenario === 'invalid-then-second-request'
  || scenario === 'invalid-first-ordering'
) {
  request.outputDirectory = path.join(caseParent, 'caller-output');
} else if (scenario === 'request-output-path') {
  request.outputPath = path.join(caseParent, 'caller-output.tar');
} else if (scenario === 'request-target-path') {
  request.targetPath = path.join(caseParent, 'caller-target.tar');
} else if (scenario === 'request-working-directory') {
  request.workingDirectory = caseParent;
} else if (scenario === 'reordered-request') {
  request = {
    assignmentId: request.assignmentId, protocol: request.protocol,
    leaseReference: request.leaseReference, assignmentNonce: request.assignmentNonce,
    sourceRepositoryPath: request.sourceRepositoryPath,
    toolingRepositoryPath: request.toolingRepositoryPath,
    lockedContext: request.lockedContext,
  };
} else if (scenario === 'malformed-request') {
  rawRequest = '{"protocol":\n';
} else if (scenario === 'duplicate-request-field') {
  rawRequest = JSON.stringify(request).replace(
    '{"protocol":"' + protocol + '"',
    '{"protocol":"' + protocol + '","protocol":"' + protocol + '"',
  ) + '\n';
} else if (scenario === 'worker-a-nonce-for-worker-b') {
  request.assignmentId = 'worker-b';
  request.assignmentNonce = nonceA;
} else if (scenario === 'assignment-swap') {
  const temporary = workerA + '.swap';
  renameSync(workerA, temporary); renameSync(workerB, workerA); renameSync(temporary, workerB);
} else if (scenario === 'claim-precreated') {
  writeFileSync(path.join(workerA, claimName), 'unrelated claim\n');
} else if (scenario === 'archive-precreated') {
  writeFileSync(path.join(workerA, archiveName), 'unrelated archive\n');
} else if (scenario === 'additional-file') {
  writeFileSync(path.join(workerA, 'unrelated.bin'), 'unrelated\n');
} else if (scenario === 'path-normalization-alias') {
  request.leaseReference = root + path.sep + '.' + path.sep + leaseName;
} else if (scenario.startsWith('context-')) {
  request.lockedContext = JSON.parse(JSON.stringify(context));
  const key = scenario.slice('context-'.length);
  if (key === 'sourceCommit' || key === 'toolingCommit') request.lockedContext[key] = 'e'.repeat(40);
  else if (key === 'matrixCellId') request.lockedContext[key] = 'changed-matrix-cell';
  else if (key === 'artifactRole') request.lockedContext[key] = 'changed-artifact-role';
  else if (key === 'formatProfile') request.lockedContext[key] = 'changed-format-profile';
  else request.lockedContext[key] = 'e'.repeat(64);
}

const requestText = () => rawRequest ?? privateBytes(request).toString('utf8');
const validRequestText = () => privateBytes(pristineRequest()).toString('utf8');
const hostileSecondOutput = path.join(caseParent, 'hostile-second-output');
const hostileSecondRequestText = () => privateBytes({
  ...pristineRequest(), outputDirectory: hostileSecondOutput,
}).toString('utf8');
const promptFatalScenarios = new Set([
  'no-lease', 'wrong-assignment-id', 'wrong-assignment-nonce',
  'wrong-context-digest', 'missing-request-field', 'request-output-directory',
  'request-archive-path', 'invalid-first-only', 'invalid-then-second-request',
  'invalid-first-ordering', 'context-sourceCommit',
]);
const workerExitTimeoutMs = promptFatalScenarios.has(scenario) ? 5000 : 60000;
const launch = (text, cwd, afterFork = null) => new Promise((resolve, reject) => {
  const env = {...process.env};
  env.IELTMPS_REPRODUCIBILITY_WORKER_TOKEN = 'a'.repeat(64);
  const child = fork(process.env.IELTMPS_CORE, [], {
    cwd, env, execArgv: [], serialization: 'json', windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  let stderr = '';
  const messages = [];
  let exitObserved = false;
  let exitCode = null;
  let exitSignal = null;
  let timedOut = false;
  let forcedTermination = false;
  let secondMessageAttempted = false;
  let secondMessageCallbackError = null;
  let claimObservedBeforeSecondSend = false;
  let claimWatcher = null;
  const parentDisconnected = false;
  const claimPath = path.join(workerA, claimName);
  const attemptSecondMessage = (payload) => {
    secondMessageAttempted = true;
    try {
      child.send(payload, (error) => {
        secondMessageCallbackError = error?.code ?? null;
      });
    } catch (error) {
      secondMessageCallbackError = error?.code ?? 'send-threw';
    }
  };
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('message', (message) => { messages.push(message); });
  const timeout = setTimeout(() => {
    timedOut = true;
    forcedTermination = true;
    child.kill();
  }, workerExitTimeoutMs);
  child.on('error', (error) => {
    claimWatcher?.close();
    clearTimeout(timeout);
    reject(error);
  });
  child.on('exit', (code, signal) => {
    exitObserved = true;
    exitCode = code;
    exitSignal = signal;
    clearTimeout(timeout);
  });
  child.on('close', (code, signal) => {
    claimWatcher?.close();
    resolve({
      code: exitCode ?? code,
      signal: exitSignal ?? signal,
      stderr,
      messages,
      exitObserved,
      timedOut,
      forcedTermination,
      secondMessageAttempted,
      secondMessageCallbackError,
      claimObservedBeforeSecondSend,
      parentDisconnected,
    });
  });
  if (scenario === 'post-claim-two-ipc-requests') {
    claimWatcher = watch(workerA, (_event, filename) => {
      if (secondMessageAttempted) return;
      if (filename !== claimName && !existsSync(claimPath)) return;
      if (!existsSync(claimPath)) return;
      claimObservedBeforeSecondSend = true;
      attemptSecondMessage(hostileSecondRequestText());
      claimWatcher?.close();
      claimWatcher = null;
    });
  }
  if (afterFork) afterFork();
  child.send(text, () => {});
  if (scenario === 'two-ipc-requests' || scenario === 'valid-then-hostile-request') {
    attemptSecondMessage(hostileSecondRequestText());
  } else if (
    scenario === 'invalid-then-second-request'
    || scenario === 'invalid-first-ordering'
  ) {
    attemptSecondMessage(validRequestText());
  }
});

let first = null;
let second = null;
let replacementMade = false;
if (scenario === 'valid-two-assignments') {
  const requestB = privateBytes({
    ...request,
    assignmentId: 'worker-b',
    assignmentNonce: nonceB,
  }).toString('utf8');
  [first, second] = await Promise.all([
    launch(requestText(), workerA),
    launch(requestB, workerB),
  ]);
} else if (
  scenario === 'replay'
  || scenario === 'same-assignment-twice'
  || scenario === 'lease-reused-after-completion'
) {
  first = await launch(requestText(), workerA);
  if (scenario === 'lease-reused-after-completion') {
    const savedLease = readFileSync(leasePath);
    rmSync(path.join(workerA, archiveName), {force: true});
    rmSync(path.join(workerA, claimName), {force: true});
    rmdirSync(workerA); rmdirSync(workerB);
    unlinkSync(leasePath); rmdirSync(root);
    makeDirectory(root); makeDirectory(workerA); makeDirectory(workerB);
    writeFileSync(leasePath, savedLease, {mode: 0o600});
  }
  second = await launch(requestText(), workerA);
} else {
  let cwd = request.assignmentId === 'worker-b' ? workerB : workerA;
  let afterFork = null;
  if (scenario === 'root-replaced-after-fork') {
    cwd = caseParent;
    afterFork = () => {
      const old = root + '.original'; renameSync(root, old);
      makeDirectory(root); makeDirectory(workerA); makeDirectory(workerB);
      copyFileSync(path.join(old, leaseName), leasePath);
    };
  } else if (scenario === 'assignment-replaced-after-fork') {
    cwd = caseParent;
    afterFork = () => { renameSync(workerA, workerA + '.original'); makeDirectory(workerA); };
  } else if (scenario === 'assignment-reparse-alias') {
    cwd = caseParent;
    afterFork = () => {
      const original = workerA + '.original'; renameSync(workerA, original);
      symlinkSync(original, workerA, process.platform === 'win32' ? 'junction' : 'dir');
    };
  } else if (scenario === 'parent-replaced-after-fork') {
    cwd = path.dirname(caseParent);
    afterFork = () => {
      const oldParent = caseParent + '.original'; renameSync(caseParent, oldParent);
      makeDirectory(caseParent); makeDirectory(root); makeDirectory(workerA); makeDirectory(workerB);
      copyFileSync(path.join(oldParent, 'same-host-workers', leaseName), leasePath);
    };
  } else if (scenario === 'archive-replaced-during-generation') {
    const watcher = watch(workerA, (_event, filename) => {
      if (!replacementMade && filename === archiveName && existsSync(path.join(workerA, archiveName))) {
        try {
          renameSync(path.join(workerA, archiveName), path.join(workerA, 'artifact.original'));
          writeFileSync(path.join(workerA, archiveName), 'replacement\n');
          replacementMade = true;
        } catch { /* the next watch event retries */ }
      }
    });
    first = await launch(requestText(), cwd);
    watcher.close();
  }
  if (first === null) first = await launch(requestText(), cwd, afterFork);
}

const safeEntries = (value) => existsSync(value) ? readdirSync(value).sort() : [];
const archiveAPath = path.join(workerA, archiveName);
const archiveBPath = path.join(workerB, archiveName);
const archiveABytes = existsSync(archiveAPath) ? readFileSync(archiveAPath) : null;
const archiveBBytes = existsSync(archiveBPath) ? readFileSync(archiveBPath) : null;
process.stdout.write(JSON.stringify({
  first, second, replacementMade,
  assignmentEntries: safeEntries(workerA),
  secondAssignmentEntries: safeEntries(workerB),
  archivePresent: archiveABytes !== null,
  archiveSha256: archiveABytes === null ? null : sha256(archiveABytes),
  archiveByteLength: archiveABytes?.length ?? null,
  claimPresent: existsSync(path.join(workerA, claimName)),
  secondArchivePresent: archiveBBytes !== null,
  secondArchiveSha256: archiveBBytes === null ? null : sha256(archiveBBytes),
  secondArchiveByteLength: archiveBBytes?.length ?? null,
  secondClaimPresent: existsSync(path.join(workerB, claimName)),
  completionPresent: existsSync(path.join(caseParent, '.complete')),
  callerOutputPresent: existsSync(path.join(caseParent, 'caller-output')),
  callerOutputArchivePresent: existsSync(path.join(caseParent, 'caller-output', archiveName)),
  callerOutputCompletionPresent: existsSync(path.join(caseParent, 'caller-output', '.complete')),
  callerArchivePresent: existsSync(path.join(caseParent, 'caller-artifact.tar')),
  hostileSecondOutputPresent: existsSync(hostileSecondOutput),
  hostileSecondArchivePresent: existsSync(path.join(hostileSecondOutput, archiveName)),
  hostileSecondCompletionPresent: existsSync(path.join(hostileSecondOutput, '.complete')),
  privateState: {
    leasePath,
    privateRoot: root,
    assignmentDirectory: workerA,
    assignmentNonce: nonceA,
    runId: lease.runId,
    contextDigestInput: context.sourceRepository.pathSha256,
    contextDigest: digest,
    claimMarkerPath: path.join(workerA, claimName),
    coordinatorPid: process.pid,
  },
}));
"""

        base_environment = {
            "IELTMPS_CORE": str(self.core),
            "IELTMPS_COORDINATOR": str(self.coordinator),
            "IELTMPS_SOURCE_REPO": str(self.source_repo),
            "IELTMPS_TOOLING_REPO": str(self.tooling_repo),
            "IELTMPS_SOURCE_COMMIT": self.source_commit,
            "IELTMPS_TOOLING_COMMIT": self.tooling_commit,
            "IELTMPS_POLICY_SHA256": _sha256(self.policy_bytes),
            "IELTMPS_CRITICAL_SHA256": _sha256(self.critical_bytes),
            "IELTMPS_RUNTIME_SHA256": _sha256(self.runtime_bytes),
            "IELTMPS_GIT_IDENTITY_SHA256": _sha256(self.git_bytes),
            "IELTMPS_PROBE_SHA256": _sha256(self.probe_bytes),
            "IELTMPS_VECTOR_SHA256": _sha256(self.vector_path.read_bytes()),
            "IELTMPS_MEMBERSHIP_SHA256": _sha256(self.report_bytes),
            "IELTMPS_INPUT_SHA256": _sha256(self.input_bytes),
            "IELTMPS_GIT_EXECUTABLE_SHA256": self.git_value["executableSha256"],
            "IELTMPS_GIT_EXECUTABLE_LENGTH": str(self.git_value["executableByteLength"]),
        }

        def assert_unassisted_worker_exit(
            result: dict[str, object], scenario: str, expected_code: int
        ) -> None:
            self.assertTrue(result["exitObserved"], scenario)
            self.assertFalse(result["timedOut"], scenario)
            self.assertFalse(result["forcedTermination"], scenario)
            self.assertEqual(result["code"], expected_code, scenario)
            self.assertIsNone(result["signal"], scenario)

        context_fields = (
            "sourceCommit",
            "toolingCommit",
            "policySha256",
            "matrixCellId",
            "criticalToolSetSha256",
            "runtimeIdentitySha256",
            "gitIdentitySha256",
            "platformProbeSha256",
            "testVectorSetSha256",
            "membershipReportSha256",
            "inputSetSha256",
            "artifactRole",
            "formatProfile",
        )
        legitimate_root = self.base / "worker-protocol-000-valid-two-assignments"
        legitimate = self._run(
            [str(self.node), "--input-type=module", "--eval", lease_harness],
            timeout=240,
            environment=self._environment(
                {
                    **base_environment,
                    "IELTMPS_SCENARIO": "valid-two-assignments",
                    "IELTMPS_CASE_ROOT": str(legitimate_root),
                }
            ),
        )
        self.assertEqual(legitimate.returncode, 0, legitimate.stderr)
        legitimate_value = json.loads(legitimate.stdout)
        assert_unassisted_worker_exit(legitimate_value["first"], "worker-a", 0)
        assert_unassisted_worker_exit(legitimate_value["second"], "worker-b", 0)
        self.assertEqual(legitimate_value["first"]["stderr"], "")
        self.assertEqual(legitimate_value["second"]["stderr"], "")
        self.assertEqual(len(legitimate_value["first"]["messages"]), 1)
        self.assertEqual(len(legitimate_value["second"]["messages"]), 1)
        response_a = json.loads(legitimate_value["first"]["messages"][0])
        response_b = json.loads(legitimate_value["second"]["messages"][0])
        response_keys = [
            "protocol",
            "runId",
            "assignmentId",
            "contextDigest",
            "status",
            "archiveSha256",
            "archiveByteLength",
            "transcriptBase64",
            "transcriptSha256",
            "transcriptByteLength",
            "workerPid",
            "assignedDirectoryIdentity",
            "archiveFileIdentity",
        ]
        self.assertEqual(list(response_a), response_keys)
        self.assertEqual(list(response_b), response_keys)
        self.assertEqual(response_a["assignmentId"], "worker-a")
        self.assertEqual(response_b["assignmentId"], "worker-b")
        self.assertEqual(response_a["status"], "ok")
        self.assertEqual(response_b["status"], "ok")
        self.assertNotEqual(response_a["workerPid"], response_b["workerPid"])
        self.assertNotEqual(
            response_a["assignedDirectoryIdentity"],
            response_b["assignedDirectoryIdentity"],
        )
        self.assertNotEqual(response_a["archiveFileIdentity"], response_b["archiveFileIdentity"])
        self.assertEqual(response_a["runId"], response_b["runId"])
        self.assertEqual(response_a["contextDigest"], response_b["contextDigest"])
        self.assertEqual(response_a["archiveSha256"], response_b["archiveSha256"])
        self.assertEqual(response_a["archiveByteLength"], response_b["archiveByteLength"])
        self.assertEqual(response_a["transcriptBase64"], response_b["transcriptBase64"])
        self.assertTrue(legitimate_value["archivePresent"])
        self.assertTrue(legitimate_value["claimPresent"])
        self.assertTrue(legitimate_value["secondArchivePresent"])
        self.assertTrue(legitimate_value["secondClaimPresent"])
        self.assertEqual(
            legitimate_value["assignmentEntries"], [".worker-claim.json", "artifact.tar"]
        )
        self.assertEqual(
            legitimate_value["secondAssignmentEntries"],
            [".worker-claim.json", "artifact.tar"],
        )
        self.assertEqual(legitimate_value["archiveSha256"], response_a["archiveSha256"])
        self.assertEqual(
            legitimate_value["archiveByteLength"], response_a["archiveByteLength"]
        )
        self.assertEqual(
            legitimate_value["secondArchiveSha256"], response_b["archiveSha256"]
        )
        self.assertEqual(
            legitimate_value["secondArchiveByteLength"], response_b["archiveByteLength"]
        )
        self.assertFalse(legitimate_value["completionPresent"])
        self.assertFalse(legitimate_value["hostileSecondOutputPresent"])
        self.assertFalse(legitimate_value["first"]["parentDisconnected"])
        self.assertFalse(legitimate_value["second"]["parentDisconnected"])
        private_state = legitimate_value["privateState"]
        type(self)._worker_private_values = (
            private_state["leasePath"],
            private_state["privateRoot"],
            private_state["assignmentDirectory"],
            private_state["assignmentNonce"],
            private_state["runId"],
            private_state["contextDigestInput"],
            private_state["contextDigest"],
            private_state["claimMarkerPath"],
            f'"coordinatorPid":{private_state["coordinatorPid"]}',
            f'"workerPid":{response_a["workerPid"]}',
            f'"workerPid":{response_b["workerPid"]}',
        )
        completed_protocol_cases += 2
        shutil.rmtree(legitimate_root, ignore_errors=True)

        def assert_successful_single_worker(
            value: dict[str, object],
            scenario: str,
            *,
            second_attempted: bool,
            claim_observed_before_second: bool = False,
        ) -> None:
            result = value["first"]
            assert_unassisted_worker_exit(result, scenario, 0)
            self.assertEqual(result["stderr"], "", scenario)
            self.assertEqual(len(result["messages"]), 1, scenario)
            response = json.loads(result["messages"][0])
            self.assertEqual(list(response), response_keys, scenario)
            self.assertEqual(response["assignmentId"], "worker-a", scenario)
            self.assertEqual(response["status"], "ok", scenario)
            self.assertTrue(value["archivePresent"], scenario)
            self.assertTrue(value["claimPresent"], scenario)
            self.assertEqual(
                value["assignmentEntries"], [".worker-claim.json", "artifact.tar"], scenario
            )
            self.assertEqual(value["archiveSha256"], response["archiveSha256"], scenario)
            self.assertEqual(
                value["archiveByteLength"], response["archiveByteLength"], scenario
            )
            self.assertFalse(value["completionPresent"], scenario)
            self.assertFalse(value["callerOutputPresent"], scenario)
            self.assertFalse(value["callerOutputArchivePresent"], scenario)
            self.assertFalse(value["callerOutputCompletionPresent"], scenario)
            self.assertFalse(value["callerArchivePresent"], scenario)
            self.assertFalse(value["hostileSecondOutputPresent"], scenario)
            self.assertFalse(value["hostileSecondArchivePresent"], scenario)
            self.assertFalse(value["hostileSecondCompletionPresent"], scenario)
            self.assertEqual(result["secondMessageAttempted"], second_attempted, scenario)
            self.assertEqual(
                result["claimObservedBeforeSecondSend"],
                claim_observed_before_second,
                scenario,
            )
            self.assertFalse(result["parentDisconnected"], scenario)

        positive_single_worker_cases = (
            ("valid-first-only", False, False),
            ("two-ipc-requests", True, False),
            ("post-claim-two-ipc-requests", True, True),
            ("valid-then-hostile-request", True, False),
            ("parent-keeps-ipc-open", False, False),
        )
        for offset, (scenario, second_attempted, claim_observed) in enumerate(
            positive_single_worker_cases, start=400
        ):
            case_root = self.base / f"worker-protocol-{offset}-{scenario}"
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", lease_harness],
                timeout=240,
                environment=self._environment(
                    {
                        **base_environment,
                        "IELTMPS_SCENARIO": scenario,
                        "IELTMPS_CASE_ROOT": str(case_root),
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, f"{scenario}: {process.stderr}")
            value = json.loads(process.stdout)
            assert_successful_single_worker(
                value,
                scenario,
                second_attempted=second_attempted,
                claim_observed_before_second=claim_observed,
            )
            completed_protocol_cases += 1
            shutil.rmtree(case_root, ignore_errors=True)

        fail_before_claim = (
            "no-lease",
            "lease-outside-root",
            "wrong-lease-protocol",
            "wrong-coordinator-pid",
            "wrong-root-identity",
            "wrong-root-parent-identity",
            "wrong-assigned-identity",
            "wrong-assignment-id",
            "wrong-assignment-nonce",
            "wrong-context-digest",
            "extra-request-field",
            "missing-request-field",
            "request-output-directory",
            "request-archive-path",
            "invalid-first-only",
            "invalid-then-second-request",
            "invalid-first-ordering",
            "request-output-path",
            "request-target-path",
            "request-working-directory",
            "reordered-request",
            "malformed-request",
            "duplicate-request-field",
            "worker-a-nonce-for-worker-b",
            "assignment-swap",
            "path-normalization-alias",
            "root-replaced-after-fork",
            "assignment-replaced-after-fork",
            "assignment-reparse-alias",
            "parent-replaced-after-fork",
            *(f"context-{field}" for field in context_fields),
        )
        fatal_malformed_matrix = {
            "no-lease",
            "wrong-assignment-id",
            "wrong-assignment-nonce",
            "wrong-context-digest",
            "missing-request-field",
            "request-output-directory",
            "request-archive-path",
            "invalid-first-only",
            "invalid-then-second-request",
            "invalid-first-ordering",
            "context-sourceCommit",
        }
        self.assertTrue(fatal_malformed_matrix.issubset(fail_before_claim))
        for number, scenario in enumerate(fail_before_claim, start=1):
            case_root = self.base / f"worker-protocol-{number:02d}-{scenario}"
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", lease_harness],
                timeout=180,
                environment=self._environment(
                    {
                        **base_environment,
                        "IELTMPS_SCENARIO": scenario,
                        "IELTMPS_CASE_ROOT": str(case_root),
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, f"{scenario}: {process.stderr}")
            value = json.loads(process.stdout)
            assert_unassisted_worker_exit(value["first"], scenario, 1)
            self.assertFalse(value["first"]["messages"], scenario)
            self.assertEqual(value["first"]["stderr"].count("\n"), 1, scenario)
            self.assertTrue(value["first"]["stderr"].endswith("\n"), scenario)
            self.assertTrue(
                value["first"]["stderr"].startswith("ERROR SAME_HOST: private-worker-"),
                scenario,
            )
            self.assertNotIn(str(self.base), value["first"]["stderr"], scenario)
            self.assertFalse(value["completionPresent"], scenario)
            self.assertFalse(value["claimPresent"], scenario)
            self.assertFalse(value["archivePresent"], scenario)
            self.assertFalse(value["callerOutputPresent"], scenario)
            self.assertFalse(value["callerOutputArchivePresent"], scenario)
            self.assertFalse(value["callerOutputCompletionPresent"], scenario)
            self.assertFalse(value["callerArchivePresent"], scenario)
            self.assertFalse(value["hostileSecondOutputPresent"], scenario)
            self.assertFalse(value["hostileSecondArchivePresent"], scenario)
            self.assertFalse(value["hostileSecondCompletionPresent"], scenario)
            self.assertFalse(value["first"]["parentDisconnected"], scenario)
            if scenario in {"invalid-then-second-request", "invalid-first-ordering"}:
                self.assertTrue(value["first"]["secondMessageAttempted"], scenario)
            completed_protocol_cases += 1
            shutil.rmtree(case_root.parent / f"{case_root.name}.original", ignore_errors=True)
            shutil.rmtree(case_root, ignore_errors=True)

        preserved_cases = (
            ("claim-precreated", ".worker-claim.json"),
            ("archive-precreated", "artifact.tar"),
            ("additional-file", "unrelated.bin"),
        )
        for offset, (scenario, preserved_name) in enumerate(preserved_cases, start=100):
            case_root = self.base / f"worker-protocol-{offset}-{scenario}"
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", lease_harness],
                timeout=180,
                environment=self._environment(
                    {
                        **base_environment,
                        "IELTMPS_SCENARIO": scenario,
                        "IELTMPS_CASE_ROOT": str(case_root),
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, f"{scenario}: {process.stderr}")
            value = json.loads(process.stdout)
            assert_unassisted_worker_exit(value["first"], scenario, 1)
            self.assertIn(preserved_name, value["assignmentEntries"], scenario)
            self.assertFalse(value["completionPresent"], scenario)
            completed_protocol_cases += 1
            shutil.rmtree(case_root, ignore_errors=True)

        for offset, scenario in enumerate(
            ("same-assignment-twice", "replay", "lease-reused-after-completion"),
            start=200,
        ):
            case_root = self.base / f"worker-protocol-{offset}-{scenario}"
            process = self._run(
                [str(self.node), "--input-type=module", "--eval", lease_harness],
                timeout=240,
                environment=self._environment(
                    {
                        **base_environment,
                        "IELTMPS_SCENARIO": scenario,
                        "IELTMPS_CASE_ROOT": str(case_root),
                    }
                ),
            )
            self.assertEqual(process.returncode, 0, f"{scenario}: {process.stderr}")
            value = json.loads(process.stdout)
            assert_unassisted_worker_exit(value["first"], scenario + "-first", 0)
            self.assertEqual(len(value["first"]["messages"]), 1, scenario)
            assert_unassisted_worker_exit(value["second"], scenario + "-second", 1)
            self.assertFalse(value["second"]["messages"], scenario)
            self.assertFalse(value["completionPresent"], scenario)
            completed_protocol_cases += 2
            shutil.rmtree(case_root, ignore_errors=True)

        replacement_root = self.base / "worker-protocol-300-archive-replacement"
        replacement = self._run(
            [str(self.node), "--input-type=module", "--eval", lease_harness],
            timeout=240,
            environment=self._environment(
                {
                    **base_environment,
                    "IELTMPS_SCENARIO": "archive-replaced-during-generation",
                    "IELTMPS_CASE_ROOT": str(replacement_root),
                }
            ),
        )
        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        replacement_value = json.loads(replacement.stdout)
        self.assertTrue(replacement_value["replacementMade"])
        assert_unassisted_worker_exit(
            replacement_value["first"], "archive-replaced-during-generation", 1
        )
        self.assertIn("artifact.original", replacement_value["assignmentEntries"])
        self.assertFalse(replacement_value["completionPresent"])
        completed_protocol_cases += 1
        shutil.rmtree(replacement_root, ignore_errors=True)

        core_text = self.core.read_text(encoding="utf-8")
        self.assertIn("value.assignmentId !== expected.assignmentId", core_text)
        self.assertIn("value.workerPid !== expected.workerPid", core_text)
        self.assertNotIn("request.outputDirectory", core_text)
        self.assertNotIn("request.archivePath", core_text)
        self.assertIn('process.once("message", onFirstMessage)', core_text)
        self.assertIn('process.removeListener("message", onFirstMessage)', core_text)
        self.assertNotIn("requestCount", core_text)
        self.assertGreater(completed_protocol_cases, 10)
        type(self).worker_protocol_cases += completed_protocol_cases
        type(self).cleanup_cases += len(fail_before_claim) + len(preserved_cases) + 5

    def test_07_privacy_canaries_are_absent_from_public_and_canonical_outputs(self) -> None:
        run = self._ensure_success()
        output: Path = run["output"]
        checked = (
            run["process"].stdout
            + (output / "semantic-report.json").read_text("ascii")
            + (output / "evidence.json").read_text("ascii")
            + (output / "verification-result.json").read_text("ascii")
        )
        for canary in CANARIES.values():
            self.assertNotIn(canary, checked)
        self.assertNotIn(str(self.base), checked)
        self.assertNotIn(platform.node(), checked)

        private_canaries = tuple(
            CANARIES[name]
            for name in (
                "lease_path",
                "private_root",
                "assignment_directory",
                "assignment_nonce",
                "run_id",
                "context_digest_input",
                "claim_marker",
                "coordinator_pid",
                "worker_pid",
            )
        )
        failure_output: Path = type(self)._failure_output
        failure_text = "".join(
            item.read_text("ascii")
            for item in failure_output.iterdir()
            if item.is_file()
        )
        direct = self._run(
            [str(self.node), str(self.core)],
            environment=self._environment(
                {"IELTMPS_REPRODUCIBILITY_WORKER_TOKEN": "f" * 64}
            ),
            timeout=10,
        )
        self.assertEqual(direct.returncode, 1)
        self.assertEqual(direct.stderr, "ERROR CLI: private-worker-unavailable\n")
        vector_script = r"""
import {pathToFileURL} from 'node:url';
const module = await import(pathToFileURL(process.env.IELTMPS_RUNNER).href);
const result = await module.runPublicSourceArchiveBoundaryVectors({
  testVectorSet: process.env.IELTMPS_VECTOR,
  temporaryParent: process.env.IELTMPS_VECTOR_PARENT,
  expectedSha256: process.env.IELTMPS_VECTOR_SHA256,
});
process.stdout.write(JSON.stringify(result));
"""
        vector = self._run(
            [str(self.node), "--input-type=module", "--eval", vector_script],
            timeout=240,
            environment=self._environment(
                {
                    "IELTMPS_RUNNER": str(self.runner),
                    "IELTMPS_VECTOR": str(self.vector_path),
                    "IELTMPS_VECTOR_PARENT": str(self.base),
                    "IELTMPS_VECTOR_SHA256": _sha256(self.vector_path.read_bytes()),
                }
            ),
        )
        self.assertEqual(vector.returncode, 0, vector.stderr)
        vector_value = json.loads(vector.stdout)
        self.assertEqual(vector_value["passedCount"], 52)
        private_surfaces = checked + failure_text + direct.stderr + vector.stdout
        for canary in private_canaries:
            self.assertNotIn(canary, private_surfaces)
        for private_value in type(self)._worker_private_values:
            self.assertNotIn(private_value, private_surfaces)
        type(self).positive_adapter_cases += len(CANARIES)

    def test_08_schema_identity_and_override_adversarial_matrix(self) -> None:
        case_number = 0

        def run_policy_case(
            label: str,
            policy_value: dict[str, object],
            *,
            critical: Path | None = None,
            runtime: Path | None = None,
            git_identity: Path | None = None,
            probe: Path | None = None,
            vectors: Path | None = None,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal case_number
            case_number += 1
            policy_path = self.docs / f"adversarial-policy-{case_number}-{label}.json"
            policy_path.write_bytes(_canonical(policy_value))
            output = self.base / f"adversarial-output-{case_number}-{label}"
            arguments = self._adapter_arguments(
                output,
                policy=policy_path,
                critical=critical,
                probe=probe,
            )
            if runtime is not None:
                position = arguments.index("--runtime-identity") + 1
                arguments[position] = str(runtime)
            if git_identity is not None:
                position = arguments.index("--git-identity") + 1
                arguments[position] = str(git_identity)
            if vectors is not None:
                position = arguments.index("--test-vector-set") + 1
                arguments[position] = str(vectors)
            process = self._run(arguments, timeout=180)
            self.assertEqual(process.returncode, 1, f"{label}: {process.stdout} {process.stderr}")
            self.assertFalse(output.exists(), label)
            self.assertEqual(process.stdout, "", label)
            self.assertEqual(process.stderr.count("\n"), 1, label)
            self.assertNotIn(str(self.base), process.stderr, label)
            return process

        for label, source_value in (
            ("source-branch", CANARIES["branch"]),
            ("source-abbreviated", self.source_commit[:12]),
            ("source-missing", "f" * 40),
        ):
            policy = copy.deepcopy(self.policy)
            policy["sourceCommit"] = source_value
            run_policy_case(label, policy)

        policy = copy.deepcopy(self.policy)
        policy["toolingCommit"] = "e" * 40
        run_policy_case("tooling-missing", policy)

        blob_id = self._git(
            self.source_repo, "rev-parse", f"{self.source_commit}:css/app.css"
        ).decode("ascii").strip()
        policy = copy.deepcopy(self.policy)
        policy["sourceCommit"] = blob_id
        run_policy_case("source-blob-object", policy)

        critical_base = json.loads(self.critical_bytes)
        critical_mutations: list[tuple[str, dict[str, object]]] = []
        missing = copy.deepcopy(critical_base)
        missing["entries"].pop()
        critical_mutations.append(("critical-missing", missing))
        extra = copy.deepcopy(critical_base)
        extra["entries"].append(copy.deepcopy(extra["entries"][-1]))
        extra["entries"][-1]["path"] = "developer/extra-production-tool.mjs"
        critical_mutations.append(("critical-extra", extra))
        reordered = copy.deepcopy(critical_base)
        reordered["entries"][0], reordered["entries"][1] = (
            reordered["entries"][1],
            reordered["entries"][0],
        )
        critical_mutations.append(("critical-reordered", reordered))
        wrong_blob = copy.deepcopy(critical_base)
        wrong_blob["entries"][0]["gitBlobObjectId"] = "a" * 40
        critical_mutations.append(("critical-wrong-blob", wrong_blob))
        for label, value in critical_mutations:
            document_path = self.docs / f"{label}.json"
            document_bytes = _canonical(value)
            document_path.write_bytes(document_bytes)
            policy = copy.deepcopy(self.policy)
            policy["criticalToolSetSha256"] = _sha256(document_bytes)
            run_policy_case(label, policy, critical=document_path)

        for label, field, replacement in (
            ("runtime-version", "nodeVersion", "0.0.0-synthetic"),
            ("runtime-executable", "executableSha256", "1" * 64),
        ):
            value = copy.deepcopy(self.runtime_value)
            value[field] = replacement
            document_path = self.docs / f"{label}.json"
            document_bytes = _canonical(value)
            document_path.write_bytes(document_bytes)
            policy = copy.deepcopy(self.policy)
            policy["requiredCells"][0]["runtimeIdentitySha256"] = _sha256(document_bytes)
            run_policy_case(label, policy, runtime=document_path)

        for label, field, replacement in (
            ("git-version", "reportedVersion", "0.0.0-synthetic"),
            ("git-executable", "executableSha256", "2" * 64),
        ):
            value = copy.deepcopy(self.git_value)
            value[field] = replacement
            document_path = self.docs / f"{label}.json"
            document_bytes = _canonical(value)
            document_path.write_bytes(document_bytes)
            policy = copy.deepcopy(self.policy)
            policy["requiredCells"][0]["gitIdentitySha256"] = _sha256(document_bytes)
            run_policy_case(label, policy, git_identity=document_path)

        probe = copy.deepcopy(self.probe_value)
        probe["operatingSystem"] = (
            "linux" if probe["operatingSystem"] != "linux" else "windows"
        )
        probe_path = self.docs / "platform-static-mismatch.json"
        probe_bytes = _canonical(probe)
        probe_path.write_bytes(probe_bytes)
        policy = copy.deepcopy(self.policy)
        policy["requiredCells"][0]["operatingSystem"] = probe["operatingSystem"]
        policy["requiredCells"][0]["platformProbeSha256"] = _sha256(probe_bytes)
        run_policy_case("platform-static-mismatch", policy, probe=probe_path)

        vector_value = json.loads(self.vector_path.read_bytes())
        vector_mutations: list[tuple[str, dict[str, object]]] = []
        missing_vector = copy.deepcopy(vector_value)
        missing_vector["vectors"].pop()
        vector_mutations.append(("vector-missing", missing_vector))
        extra_vector = copy.deepcopy(vector_value)
        extra_vector["vectors"].append(copy.deepcopy(extra_vector["vectors"][-1]))
        extra_vector["vectors"][-1]["vectorId"] = "M23"
        vector_mutations.append(("vector-extra", extra_vector))
        reordered_vector = copy.deepcopy(vector_value)
        reordered_vector["vectors"][0], reordered_vector["vectors"][1] = (
            reordered_vector["vectors"][1],
            reordered_vector["vectors"][0],
        )
        vector_mutations.append(("vector-reordered", reordered_vector))
        changed_vector = copy.deepcopy(vector_value)
        changed_vector["vectors"][0]["caseId"] = "payload-2"
        vector_mutations.append(("vector-content", changed_vector))
        for label, value in vector_mutations:
            document_path = self.docs / f"{label}.json"
            document_bytes = _canonical(value)
            document_path.write_bytes(document_bytes)
            policy = copy.deepcopy(self.policy)
            policy["testVectorSetSha256"] = _sha256(document_bytes)
            run_policy_case(label, policy, vectors=document_path)

        replacement_commit = self._git(
            self.source_repo,
            "commit-tree",
            f"{self.source_commit}^{{tree}}",
            "-p",
            self.source_commit,
            input_bytes=b"replacement commit\n",
        ).decode("ascii").strip()
        self._git(self.source_repo, "replace", self.source_commit, replacement_commit)
        try:
            run_policy_case("replacement-object-ref", copy.deepcopy(self.policy))
        finally:
            self._git(self.source_repo, "replace", "-d", self.source_commit)

        hostile_output = self.base / "hostile-git-existing-output"
        hostile_output.mkdir()
        hostile_environment = self._environment(
            {name: str(self.base / f"hostile-{name.lower()}") for name in GIT_REDIRECTIONS}
        )
        hostile = self._run(
            self._adapter_arguments(hostile_output),
            timeout=180,
            environment=hostile_environment,
        )
        self.assertEqual(hostile.returncode, 1, hostile.stderr)
        self.assertIn("output-directory-exists", hostile.stderr)
        self.assertEqual(list(hostile_output.iterdir()), [])

        for label, output in (
            ("output-inside-source", self.source_repo / "forbidden-output"),
            ("output-inside-tooling", self.tooling_repo / "forbidden-output"),
        ):
            process = self._run(self._adapter_arguments(output), timeout=180)
            self.assertEqual(process.returncode, 1, label)
            self.assertFalse(output.exists(), label)
            self.assertIn("output-directory-contained", process.stderr, label)

        override_flags = (
            "--source-commit",
            "--tooling-commit",
            "--archive-sha256",
            "--member",
            "--canonical-verifier-passed",
            "--same-process-repeatable",
            "--same-host-repeatable",
            "--boundary-vector-set-passed",
            "--claim-level",
            "--repeat-count",
            "--worker-command",
            "--worker-output-path",
            "--worker-environment",
            "--platform-attestation-verified",
            "--sign",
            "--publish",
            "--overwrite",
            "--test-hook",
        )
        for flag in override_flags:
            process = self._run([str(self.node), str(self.coordinator), flag, "x"])
            self.assertEqual(process.returncode, 1, flag)
            self.assertEqual(process.stdout, "", flag)
            self.assertEqual(process.stderr.count("\n"), 1, flag)
            self.assertNotIn(str(self.base), process.stderr, flag)

        type(self).adversarial_subcases += case_number + len(override_flags) + 3
        type(self).cleanup_cases += case_number + 3

    def test_09_tamper_detection_and_identity_safe_cleanup_refusal(self) -> None:
        run = self._ensure_success()
        output: Path = run["output"]
        artifact = (output / "artifact.tar").read_bytes()
        mutated_path = self.base / "mutated-final-archive.tar"
        truncated_path = self.base / "truncated-final-archive.tar"
        mutated = bytearray(artifact)
        mutated[BLOCK_SIZE] ^= 1
        mutated_path.write_bytes(mutated)
        truncated_path.write_bytes(artifact[:-1])
        verifier_args = [
            str(self.node),
            str(self.b3_verifier),
            "--repo",
            str(self.source_repo),
            "--commit",
            self.source_commit,
            "--archive",
        ]
        for candidate in (mutated_path, truncated_path):
            rejected = self._run([*verifier_args, str(candidate)])
            self.assertNotEqual(rejected.returncode, 0)
        mutated_path.unlink()
        truncated_path.unlink()

        semantic = json.loads((output / "semantic-report.json").read_bytes())
        semantic["sameProcessRepeatable"] = False
        semantic_path = self.base / "mutated-semantic-report.json"
        semantic_path.write_bytes(_canonical(semantic))
        r1_verifier = self.tooling_repo / PRODUCTION_PATHS[5]
        r1_arguments = [
            str(self.node),
            str(r1_verifier),
            "--evidence",
            str(output / "evidence.json"),
            "--policy",
            str(self.policy_path),
            "--source-repo",
            str(self.source_repo),
            "--tooling-repo",
            str(self.tooling_repo),
            "--critical-tool-set",
            str(self.critical_path),
            "--manifest",
            str(output / "b1-membership-report.json"),
            "--input-set",
            str(output / "input-set.json"),
            "--runtime-identity",
            str(self.runtime_path),
            "--git-identity",
            str(self.git_path),
            "--test-vector-set",
            str(self.vector_path),
            "--platform-probe",
            str(self.probe_path),
            "--artifact",
            str(output / "artifact.tar"),
            "--semantic-report",
            str(semantic_path),
        ]
        semantic_rejected = self._run(r1_arguments)
        self.assertNotEqual(semantic_rejected.returncode, 0)
        semantic_path.unlink()

        overwrite = self._run(self._adapter_arguments(output), timeout=180)
        self.assertEqual(overwrite.returncode, 1)
        self.assertIn("output-directory-exists", overwrite.stderr)
        self.assertEqual(
            (output / ".complete").read_bytes(),
            b"ieltmps-public-source-archive-reproducibility-complete-v1\n",
        )

        cleanup_root = self.base / "cleanup-identity-substitution-output"
        cleanup_harness = r"""
import {existsSync, renameSync, writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
const core = await import(pathToFileURL(process.env.IELTMPS_CORE).href);
const output = await core.createExclusiveOutputDirectory({
  outputDirectory: process.env.IELTMPS_CLEANUP_OUTPUT,
  sourceRepo: process.env.IELTMPS_SOURCE_REPO,
  toolingRepo: process.env.IELTMPS_TOOLING_REPO,
});
const ledger = [];
const privateRoot = await core.createOwnedDirectory(output, 'cleanup-private', ledger);
await core.writeOwnedFile(privateRoot, 'owned.bin', Buffer.from('owned\n'), ledger);
const owned = path.join(privateRoot.path, 'owned.bin');
renameSync(owned, owned + '.identity-changed');
writeFileSync(owned, 'replacement\n');
let reason = null;
try { await core.cleanupOwnedLedger(ledger); } catch (error) { reason = error?.reason ?? null; }
process.stdout.write(JSON.stringify({
  reason,
  replacementPreserved: existsSync(owned),
  originalPreserved: existsSync(owned + '.identity-changed'),
  markerAbsent: !existsSync(path.join(output.path, '.complete')),
}));
"""
        cleanup = self._run(
            [str(self.node), "--input-type=module", "--eval", cleanup_harness],
            environment=self._environment(
                {
                    "IELTMPS_CORE": str(self.core),
                    "IELTMPS_CLEANUP_OUTPUT": str(cleanup_root),
                    "IELTMPS_SOURCE_REPO": str(self.source_repo),
                    "IELTMPS_TOOLING_REPO": str(self.tooling_repo),
                }
            ),
        )
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr)
        cleanup_result = json.loads(cleanup.stdout)
        self.assertEqual(cleanup_result["reason"], "cleanup-incomplete")
        self.assertTrue(cleanup_result["replacementPreserved"])
        self.assertTrue(cleanup_result["originalPreserved"])
        self.assertTrue(cleanup_result["markerAbsent"])
        shutil.rmtree(cleanup_root)
        type(self).adversarial_subcases += 8
        type(self).cleanup_cases += 6


if __name__ == "__main__":
    unittest.main(verbosity=2)
