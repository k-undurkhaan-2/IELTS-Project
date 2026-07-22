#!/usr/bin/env python3
"""Synthetic canonicality, identity, and claim-binding tests for R1-10A."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
CORE = REPO_ROOT / "developer/reproducibility-evidence-core.mjs"
VERIFIER = REPO_ROOT / "developer/verify-reproducibility-evidence.mjs"
COMPARATOR = REPO_ROOT / "developer/compare-reproducibility-evidence.mjs"

POLICY_KIND = "ieltmps-reproducibility-matrix-policy"
EVIDENCE_KIND = "ieltmps-reproducibility-evidence"
SEMANTIC_KIND = "ieltmps-reproducibility-semantic-report"
VERIFICATION_KIND = "ieltmps-reproducibility-evidence-verification"
COMPARISON_KIND = "ieltmps-reproducibility-comparison-report"

POLICY_KEYS = (
    "policyKind",
    "schemaVersion",
    "policyId",
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "criticalToolSetSha256",
    "manifestSha256",
    "inputSetSha256",
    "testVectorSetSha256",
    "requiredClaimLevels",
    "requiredCells",
    "optionalCells",
)
CELL_KEYS = (
    "matrixCellId",
    "runtimeProfileId",
    "runtimeIdentitySha256",
    "gitProfileId",
    "gitIdentitySha256",
    "operatingSystem",
    "operatingSystemBuild",
    "architecture",
    "filesystemProfile",
    "localeProfile",
    "timezoneProfile",
    "platformProbeSha256",
)
EVIDENCE_KEYS = (
    "evidenceKind",
    "schemaVersion",
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "criticalToolSetSha256",
    "manifestSha256",
    "inputSetSha256",
    "runtimeProfileId",
    "runtimeIdentitySha256",
    "gitProfileId",
    "gitIdentitySha256",
    "runnerPolicySha256",
    "testVectorSetSha256",
    "matrixCellId",
    "operatingSystem",
    "operatingSystemBuild",
    "architecture",
    "filesystemProfile",
    "localeProfile",
    "timezoneProfile",
    "platformProbeSha256",
    "artifactSha256",
    "artifactByteLength",
    "semanticReportSha256",
    "semanticReportByteLength",
    "result",
    "failureClass",
    "failureCode",
)
SEMANTIC_KEYS = (
    "semanticReportKind",
    "schemaVersion",
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "inputSetSha256",
    "artifactSha256",
    "artifactByteLength",
    "canonicalVerifierPassed",
    "sameProcessRepeatable",
    "sameHostRepeatable",
    "boundaryVectorSetPassed",
    "result",
    "failureCode",
)
VERIFICATION_KEYS = (
    "verificationKind",
    "schemaVersion",
    "status",
    "mode",
    "policyId",
    "artifactRole",
    "formatProfile",
    "matrixCellId",
    "evidenceSha256",
    "evidenceByteLength",
    "policySha256",
    "comparisonIdentitySha256",
    "sourceCommitObjectVerified",
    "toolingCommitObjectVerified",
    "criticalToolSetVerified",
    "manifestVerified",
    "inputSetVerified",
    "runtimeIdentityVerified",
    "gitIdentityVerified",
    "testVectorSetVerified",
    "platformProbeVerified",
    "artifactVerified",
    "semanticReportVerified",
    "policyCellVerified",
    "semanticClaimsBound",
    "canonicalVerifierPassed",
    "sameProcessRepeatable",
    "sameHostRepeatable",
    "boundaryVectorSetPassed",
    "semanticClaimsIndependentlyReplayed",
    "evidenceResult",
    "comparisonEligible",
    "platformAttestationVerified",
    "evidenceSigningRequired",
    "projectPublicationAuthorized",
)

CANARIES = {
    "source_repo": "canary-source-repo-91a3",
    "tooling_repo": "canary-tooling-repo-82b4",
    "policy": "canary-policy-73c5",
    "evidence": "canary-evidence-64d6",
    "artifact": "canary-artifact-55e7",
    "semantic_report": "canary-semantic-report-46f8",
    "verification_result": "canary-verification-result-3709",
    "runtime_identity": "canary-runtime-identity-281a",
    "git_identity": "canary-git-identity-192b",
    "platform_probe": "canary-platform-probe-083c",
    "manifest": "canary-manifest-f94d",
    "input_set": "canary-input-set-e85e",
    "test_vector_set": "canary-test-vector-set-d76f",
    "username": "canary-username-c680",
    "drive": "canary-drive-b791",
    "hostname": "canary-hostname-a8a2",
    "branch": "canary-branch-99b3",
    "remote": "canary-remote-8ac4",
    "environment": "canary-environment-7bd5",
}

PARSER_HARNESS = r"""
import { pathToFileURL } from "node:url";
let source = "";
for await (const chunk of process.stdin) source += chunk;
const request = JSON.parse(source);
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const methods = {
  evidence: core.parseCanonicalReproducibilityEvidence,
  policy: core.parseCanonicalMatrixPolicy,
  semantic: core.parseCanonicalSemanticReport,
  verification: core.parseCanonicalVerificationResult,
};
const results = request.cases.map((entry) => {
  try {
    methods[request.kind](Buffer.from(entry, "base64"));
    return {ok: true};
  } catch (error) {
    return {
      ok: false,
      phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
      reason: typeof error?.reason === "string" ? error.reason : "parser-harness",
    };
  }
});
process.stdout.write(JSON.stringify(results) + "\n");
"""

FILE_RACE_HARNESS = r"""
import { appendFileSync, renameSync, truncateSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const request = JSON.parse(process.env.IELTMPS_TEST_REQUEST);
let acted = false;
try {
  const result = await core.readStableFile(request.path, {
    kind: request.kind,
    hooks: {checkpoint({checkpoint}) {
      if (acted || checkpoint !== request.checkpoint) return;
      acted = true;
      if (request.action === "mutate") writeFileSync(request.path, request.payload);
      else if (request.action === "truncate") truncateSync(request.path, 1);
      else if (request.action === "grow") appendFileSync(request.path, request.payload);
      else if (request.action === "replace") {
        renameSync(request.path, request.path + ".old");
        writeFileSync(request.path, request.payload);
      }
    }},
  });
  process.stdout.write(JSON.stringify({ok: true, sha256: result.sha256}) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
    reason: typeof error?.reason === "string" ? error.reason : "file-race-harness",
  }) + "\n");
}
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def _ordered_copy(value: dict, keys: tuple[str, ...]) -> dict:
    return {key: copy.deepcopy(value[key]) for key in keys}


def _replace_number(raw: bytes, field: str, replacement: bytes) -> bytes:
    marker = f'"{field}":'.encode("ascii")
    start = raw.index(marker) + len(marker)
    end = start
    while raw[end] in b"0123456789":
        end += 1
    return raw[:start] + replacement + raw[end:]


class ReproducibilityEvidenceTests(unittest.TestCase):
    malformed_evidence_cases = 0
    malformed_policy_cases = 0
    malformed_semantic_cases = 0
    malformed_verification_cases = 0
    semantic_copy_mismatch_cases = 0
    comparator_anti_inference_cases = 0
    comparator_adversarial_cases = 0
    privacy_canary_count = len(CANARIES)

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = Path(os.environ.get("IELTMPS_NODE") or shutil.which("node") or "")
        if not cls.node.is_file():
            raise RuntimeError("IELTMPS_NODE or node on PATH is required")
        cls.git = shutil.which("git")
        if not cls.git:
            raise RuntimeError("git on PATH is required")

    @classmethod
    def tearDownClass(cls) -> None:
        duration = time.monotonic() - cls.started
        methods = unittest.defaultTestLoader.loadTestsFromTestCase(cls).countTestCases()
        print(
            "R1-10A-SUMMARY "
            f"test_methods={methods} "
            f"malformed_evidence_cases={cls.malformed_evidence_cases} "
            f"malformed_policy_cases={cls.malformed_policy_cases} "
            f"malformed_semantic_report_cases={cls.malformed_semantic_cases} "
            f"malformed_verification_result_cases={cls.malformed_verification_cases} "
            f"semantic_copy_mismatch_cases={cls.semantic_copy_mismatch_cases} "
            f"comparator_anti_inference_cases={cls.comparator_anti_inference_cases} "
            f"comparator_adversarial_cases={cls.comparator_adversarial_cases} "
            f"privacy_canaries={cls.privacy_canary_count} "
            f"duration_seconds={duration:.3f}"
        )

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="r1-10a-")
        self.base = Path(self._temporary.name).resolve()
        self.source_repo = self.base / CANARIES["source_repo"]
        self.tooling_repo = self.base / CANARIES["tooling_repo"]
        self.source_commit = self._create_repo(self.source_repo, "source")
        self.tooling_commit = self._create_repo(self.tooling_repo, "tooling")

        self.critical_tool_set = self.base / "critical-tool-set-document.bin"
        self.manifest = self.base / f"{CANARIES['manifest']}.bin"
        self.input_set = self.base / f"{CANARIES['input_set']}.bin"
        self.git_identity = self.base / f"{CANARIES['git_identity']}.bin"
        self.test_vector_set = self.base / f"{CANARIES['test_vector_set']}.bin"
        self._write(self.critical_tool_set, b"synthetic-critical-tools-v1\n")
        self._write(self.manifest, b"synthetic-manifest-v1\n")
        self._write(self.input_set, b"synthetic-input-set-v1\n")
        self._write(self.git_identity, b"synthetic-git-identity-v1\n")
        self._write(self.test_vector_set, b"synthetic-test-vectors-v1\n")

        runtime_20 = self.base / f"{CANARIES['runtime_identity']}-20.bin"
        runtime_22 = self.base / f"{CANARIES['runtime_identity']}-22.bin"
        linux_probe = self.base / f"{CANARIES['platform_probe']}-linux.bin"
        windows_probe = self.base / f"{CANARIES['platform_probe']}-windows.bin"
        self._write(runtime_20, b"synthetic-runtime-node-20\n")
        self._write(runtime_22, b"synthetic-runtime-node-22\n")
        self._write(linux_probe, b"synthetic-linux-platform-profile\n")
        self._write(windows_probe, b"synthetic-windows-platform-profile\n")
        git_hash = _sha256(self.git_identity.read_bytes())
        self.cells = {
            "linux-node20": {
                "matrixCellId": "linux-node20",
                "runtimeProfileId": "node20",
                "runtimeIdentitySha256": _sha256(runtime_20.read_bytes()),
                "gitProfileId": "git-sha1",
                "gitIdentitySha256": git_hash,
                "operatingSystem": "linux",
                "operatingSystemBuild": "ubuntu-24.04",
                "architecture": "x64",
                "filesystemProfile": "case-sensitive",
                "localeProfile": "en-us",
                "timezoneProfile": "utc",
                "platformProbeSha256": _sha256(linux_probe.read_bytes()),
                "runtime_path": runtime_20,
                "probe_path": linux_probe,
            },
            "linux-node22": {
                "matrixCellId": "linux-node22",
                "runtimeProfileId": "node22",
                "runtimeIdentitySha256": _sha256(runtime_22.read_bytes()),
                "gitProfileId": "git-sha1",
                "gitIdentitySha256": git_hash,
                "operatingSystem": "linux",
                "operatingSystemBuild": "ubuntu-24.04",
                "architecture": "x64",
                "filesystemProfile": "case-sensitive",
                "localeProfile": "en-us",
                "timezoneProfile": "utc",
                "platformProbeSha256": _sha256(linux_probe.read_bytes()),
                "runtime_path": runtime_22,
                "probe_path": linux_probe,
            },
            "windows-node20": {
                "matrixCellId": "windows-node20",
                "runtimeProfileId": "node20",
                "runtimeIdentitySha256": _sha256(runtime_20.read_bytes()),
                "gitProfileId": "git-sha1",
                "gitIdentitySha256": git_hash,
                "operatingSystem": "windows",
                "operatingSystemBuild": "windows-11-23h2",
                "architecture": "x64",
                "filesystemProfile": "case-preserving",
                "localeProfile": "en-us",
                "timezoneProfile": "utc",
                "platformProbeSha256": _sha256(windows_probe.read_bytes()),
                "runtime_path": runtime_20,
                "probe_path": windows_probe,
            },
        }
        self.policy_path = self.base / f"{CANARIES['policy']}.json"
        self._set_policy(
            ("linux-node20", "linux-node22", "windows-node20"),
            (),
            ("L0", "L1", "L2", "L3", "L4", "L5"),
        )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        environment["IELTMPS_TEST_USERNAME"] = CANARIES["username"]
        environment["IELTMPS_TEST_DRIVE"] = CANARIES["drive"]
        environment["IELTMPS_TEST_HOSTNAME"] = CANARIES["hostname"]
        environment["IELTMPS_TEST_ENVIRONMENT"] = CANARIES["environment"]
        if additions:
            environment.update(additions)
        return environment

    def _git(self, repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.git), "-C", str(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
            timeout=30,
        )

    def _create_repo(self, repo: Path, label: str) -> str:
        repo.mkdir(parents=True)
        subprocess.run(
            [str(self.git), "init", str(repo)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
        self._git(repo, "config", "user.name", CANARIES["username"])
        self._git(repo, "config", "user.email", f"{label}@example.invalid")
        self._git(repo, "config", "commit.gpgsign", "false")
        self._git(repo, "checkout", "-b", CANARIES["branch"])
        self._git(repo, "remote", "add", "origin", f"https://example.invalid/{CANARIES['remote']}.git")
        (repo / "synthetic-source.txt").write_text(
            f"synthetic {label} input\n", encoding="utf-8", newline="\n"
        )
        self._git(repo, "add", "synthetic-source.txt")
        self._git(repo, "commit", "-m", f"synthetic {label} commit")
        return self._git(repo, "rev-parse", "HEAD").stdout.strip()

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _set_policy(
        self,
        required_ids: tuple[str, ...],
        optional_ids: tuple[str, ...],
        levels: tuple[str, ...],
    ) -> None:
        def public_cell(cell_id: str) -> dict:
            return {key: self.cells[cell_id][key] for key in CELL_KEYS}

        self.policy = {
            "policyKind": POLICY_KIND,
            "schemaVersion": 1,
            "policyId": "r1-10a-synthetic",
            "artifactRole": "standalone-package",
            "formatProfile": "canonical-v1",
            "sourceCommit": self.source_commit,
            "toolingCommit": self.tooling_commit,
            "criticalToolSetSha256": _sha256(self.critical_tool_set.read_bytes()),
            "manifestSha256": _sha256(self.manifest.read_bytes()),
            "inputSetSha256": _sha256(self.input_set.read_bytes()),
            "testVectorSetSha256": _sha256(self.test_vector_set.read_bytes()),
            "requiredClaimLevels": list(levels),
            "requiredCells": [public_cell(value) for value in required_ids],
            "optionalCells": [public_cell(value) for value in optional_ids],
        }
        self.policy_bytes = _canonical(self.policy)
        self._write(self.policy_path, self.policy_bytes)
        self.policy_sha256 = _sha256(self.policy_bytes)

    def _semantic(
        self,
        artifact_bytes: bytes,
        claims: tuple[bool, bool, bool, bool],
        changes: dict | None = None,
    ) -> dict:
        value = {
            "semanticReportKind": SEMANTIC_KIND,
            "schemaVersion": 1,
            "artifactRole": self.policy["artifactRole"],
            "formatProfile": self.policy["formatProfile"],
            "sourceCommit": self.source_commit,
            "toolingCommit": self.tooling_commit,
            "inputSetSha256": self.policy["inputSetSha256"],
            "artifactSha256": _sha256(artifact_bytes),
            "artifactByteLength": len(artifact_bytes),
            "canonicalVerifierPassed": claims[0],
            "sameProcessRepeatable": claims[1],
            "sameHostRepeatable": claims[2],
            "boundaryVectorSetPassed": claims[3],
            "result": "pass",
            "failureCode": None,
        }
        if changes:
            value.update(changes)
        return value

    def _evidence(
        self,
        cell_id: str,
        artifact_bytes: bytes,
        semantic_bytes: bytes,
        result: str = "pass",
    ) -> dict:
        cell = self.cells[cell_id]
        value = {
            "evidenceKind": EVIDENCE_KIND,
            "schemaVersion": 1,
            "artifactRole": self.policy["artifactRole"],
            "formatProfile": self.policy["formatProfile"],
            "sourceCommit": self.source_commit,
            "toolingCommit": self.tooling_commit,
            "criticalToolSetSha256": self.policy["criticalToolSetSha256"],
            "manifestSha256": self.policy["manifestSha256"],
            "inputSetSha256": self.policy["inputSetSha256"],
            "runtimeProfileId": cell["runtimeProfileId"],
            "runtimeIdentitySha256": cell["runtimeIdentitySha256"],
            "gitProfileId": cell["gitProfileId"],
            "gitIdentitySha256": cell["gitIdentitySha256"],
            "runnerPolicySha256": self.policy_sha256,
            "testVectorSetSha256": self.policy["testVectorSetSha256"],
            "matrixCellId": cell["matrixCellId"],
            "operatingSystem": cell["operatingSystem"],
            "operatingSystemBuild": cell["operatingSystemBuild"],
            "architecture": cell["architecture"],
            "filesystemProfile": cell["filesystemProfile"],
            "localeProfile": cell["localeProfile"],
            "timezoneProfile": cell["timezoneProfile"],
            "platformProbeSha256": cell["platformProbeSha256"],
            "artifactSha256": _sha256(artifact_bytes) if result == "pass" else None,
            "artifactByteLength": len(artifact_bytes) if result == "pass" else None,
            "semanticReportSha256": _sha256(semantic_bytes) if result == "pass" else None,
            "semanticReportByteLength": len(semantic_bytes) if result == "pass" else None,
            "result": result,
            "failureClass": None if result == "pass" else "implementation-defect",
            "failureCode": None if result == "pass" else "synthetic-failure",
        }
        return value

    def _verifier_arguments(
        self,
        evidence_path: Path,
        cell_id: str,
        artifact_path: Path | None,
        semantic_path: Path | None,
    ) -> list[str]:
        cell = self.cells[cell_id]
        arguments = [
            "--evidence",
            str(evidence_path),
            "--policy",
            str(self.policy_path),
            "--source-repo",
            str(self.source_repo),
            "--tooling-repo",
            str(self.tooling_repo),
            "--critical-tool-set",
            str(self.critical_tool_set),
            "--manifest",
            str(self.manifest),
            "--input-set",
            str(self.input_set),
            "--runtime-identity",
            str(cell["runtime_path"]),
            "--git-identity",
            str(self.git_identity),
            "--test-vector-set",
            str(self.test_vector_set),
            "--platform-probe",
            str(cell["probe_path"]),
        ]
        if artifact_path is not None:
            arguments.extend(("--artifact", str(artifact_path)))
        if semantic_path is not None:
            arguments.extend(("--semantic-report", str(semantic_path)))
        return arguments

    def _run_script(
        self,
        script: Path | str,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.node), str(script), *arguments],
            cwd=cwd or self.base,
            env=environment or self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def _verify(
        self,
        cell_id: str,
        *,
        label: str | None = None,
        claims: tuple[bool, bool, bool, bool] = (True, True, True, True),
        artifact_bytes: bytes = b"synthetic-identical-artifact\n",
        semantic_changes: dict | None = None,
        result: str = "pass",
        expect_success: bool = True,
        environment: dict[str, str] | None = None,
    ) -> dict:
        suffix = label or cell_id
        artifact_path = self.base / f"{CANARIES['artifact']}-{suffix}.bin"
        semantic_path = self.base / f"{CANARIES['semantic_report']}-{suffix}.json"
        if result == "pass":
            self._write(artifact_path, artifact_bytes)
            semantic = self._semantic(artifact_bytes, claims, semantic_changes)
            semantic_bytes = _canonical(semantic)
            self._write(semantic_path, semantic_bytes)
        else:
            semantic = None
            semantic_bytes = b""
            artifact_path = None
            semantic_path = None
        evidence = self._evidence(cell_id, artifact_bytes, semantic_bytes, result)
        evidence_bytes = _canonical(evidence)
        evidence_path = self.base / f"{CANARIES['evidence']}-{suffix}.json"
        self._write(evidence_path, evidence_bytes)
        process = self._run_script(
            VERIFIER,
            self._verifier_arguments(evidence_path, cell_id, artifact_path, semantic_path),
            environment=environment,
        )
        if not expect_success:
            return {
                "process": process,
                "evidence": evidence,
                "evidence_path": evidence_path,
                "semantic_path": semantic_path,
                "artifact_path": artifact_path,
            }
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        self.assertEqual(process.stdout.count("\n"), 1)
        verification = json.loads(process.stdout)
        verification_path = self.base / f"{CANARIES['verification_result']}-{suffix}.json"
        self._write(verification_path, process.stdout.encode("ascii"))
        return {
            "process": process,
            "evidence": evidence,
            "evidence_path": evidence_path,
            "artifact_path": artifact_path,
            "semantic": semantic,
            "semantic_path": semantic_path,
            "verification": verification,
            "verification_path": verification_path,
        }

    def _compare(self, runs: list[dict]) -> tuple[subprocess.CompletedProcess, dict]:
        arguments = ["--policy", str(self.policy_path)]
        for run in runs:
            arguments.extend(
                (
                    "--verified-run",
                    str(run["evidence_path"]),
                    str(run["verification_path"]),
                )
            )
        process = self._run_script(COMPARATOR, arguments)
        report = json.loads(process.stdout) if process.stdout else {}
        return process, report

    def _assert_cli_error(
        self,
        process: subprocess.CompletedProcess,
        phase: str,
        reason: str | None = None,
    ) -> None:
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, "")
        self.assertEqual(process.stderr.count("\n"), 1)
        self.assertTrue(process.stderr.startswith(f"ERROR {phase}: "), process.stderr)
        if reason is not None:
            self.assertEqual(process.stderr, f"ERROR {phase}: {reason}\n")
        self.assertNotIn("Traceback", process.stderr)
        self.assertNotIn(" at ", process.stderr)

    def _assert_parser_cases(
        self,
        kind: str,
        cases: list[tuple[str, bytes, str, str]],
    ) -> None:
        self.assertEqual(len({case[1] for case in cases}), len(cases))
        request = {"kind": kind, "cases": [base64.b64encode(case[1]).decode() for case in cases]}
        process = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", PARSER_HARNESS],
            cwd=self.base,
            env=self._environment(),
            input=json.dumps(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        results = json.loads(process.stdout)
        self.assertEqual(len(results), len(cases))
        for case, result in zip(cases, results):
            with self.subTest(case=case[0]):
                self.assertFalse(result["ok"])
                self.assertEqual(result["phase"], case[2])
                self.assertEqual(result["reason"], case[3])

    @staticmethod
    def _generic_malformed_cases(
        baseline: bytes,
        value: dict,
        phase: str,
        label: str,
    ) -> list[tuple[str, bytes, str, str]]:
        unknown = copy.deepcopy(value)
        unknown["unknownField"] = True
        missing = copy.deepcopy(value)
        missing.pop(next(iter(missing)))
        keys = list(value)
        reordered = {key: copy.deepcopy(value[key]) for key in (keys[1], keys[0], *keys[2:])}
        first_key = keys[0]
        duplicate = baseline[:-2] + f',"{first_key}":"duplicate"'.encode() + b"}\n"
        trailing = baseline[:-1] + b"x\n"
        return [
            ("missing-final-lf", baseline[:-1], phase, "missing-final-lf"),
            ("extra-final-lf", baseline + b"\n", phase, "extra-final-lf"),
            ("crlf", baseline[:-1] + b"\r\n", phase, "crlf-or-cr"),
            ("bom", b"\xef\xbb\xbf" + baseline, phase, "utf8-bom"),
            ("internal-lf", baseline[:1] + b"\n" + baseline[1:], phase, "internal-lf"),
            ("whitespace", baseline.replace(b":", b": ", 1), phase, "noncanonical-whitespace"),
            ("escaped-ascii", baseline.replace(b"a", b"\\u0061", 1), phase, "string-escape"),
            ("non-ascii", baseline.replace(b"a", "é".encode(), 1), phase, "non-ascii-string"),
            ("trailing-byte", trailing, phase, "trailing-bytes"),
            ("duplicate-key", duplicate, phase, "duplicate-key"),
            ("unknown-field", _canonical(unknown), phase, f"{label}-unknown-field"),
            ("missing-field", _canonical(missing), phase, f"{label}-missing-field"),
            ("reordered-field", _canonical(reordered), phase, f"{label}-key-order"),
        ]

    def _verification_fixture(self, result: str = "pass") -> dict:
        passing = result == "pass"
        return {
            "verificationKind": VERIFICATION_KIND,
            "schemaVersion": 1,
            "status": "ok",
            "mode": "reproducibility-evidence-verification",
            "policyId": "r1-10a-synthetic",
            "artifactRole": "standalone-package",
            "formatProfile": "canonical-v1",
            "matrixCellId": "linux-node20",
            "evidenceSha256": "1" * 64,
            "evidenceByteLength": 100,
            "policySha256": "2" * 64,
            "comparisonIdentitySha256": "3" * 64,
            "sourceCommitObjectVerified": True,
            "toolingCommitObjectVerified": True,
            "criticalToolSetVerified": True,
            "manifestVerified": True,
            "inputSetVerified": True,
            "runtimeIdentityVerified": True,
            "gitIdentityVerified": True,
            "testVectorSetVerified": True,
            "platformProbeVerified": True,
            "artifactVerified": passing,
            "semanticReportVerified": passing,
            "policyCellVerified": True,
            "semanticClaimsBound": passing,
            "canonicalVerifierPassed": True if passing else None,
            "sameProcessRepeatable": True if passing else None,
            "sameHostRepeatable": True if passing else None,
            "boundaryVectorSetPassed": True if passing else None,
            "semanticClaimsIndependentlyReplayed": False,
            "evidenceResult": result,
            "comparisonEligible": passing,
            "platformAttestationVerified": False,
            "evidenceSigningRequired": True,
            "projectPublicationAuthorized": False,
        }

    def test_01_verifier_copies_bound_semantic_claims_and_is_deterministic(self) -> None:
        combinations = (
            (True, True, True, True),
            (True, False, True, True),
            (True, True, False, True),
            (True, True, True, False),
        )
        for index, claims in enumerate(combinations):
            with self.subTest(claims=claims):
                run = self._verify("linux-node20", label=f"semantic-copy-{index}", claims=claims)
                result = run["verification"]
                self.assertEqual(
                    (
                        result["canonicalVerifierPassed"],
                        result["sameProcessRepeatable"],
                        result["sameHostRepeatable"],
                        result["boundaryVectorSetPassed"],
                    ),
                    claims,
                )
                self.assertTrue(result["semanticReportVerified"])
                self.assertTrue(result["semanticClaimsBound"])
                self.assertFalse(result["semanticClaimsIndependentlyReplayed"])
                self.assertFalse(result["platformAttestationVerified"])
                self.assertTrue(result["evidenceSigningRequired"])
                self.assertFalse(result["projectPublicationAuthorized"])
        first = self._verify("linux-node20", label="deterministic-a")
        second_process = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                first["evidence_path"],
                "linux-node20",
                first["artifact_path"],
                first["semantic_path"],
            ),
        )
        self.assertEqual(second_process.returncode, 0, second_process.stderr)
        self.assertEqual(second_process.stdout, first["process"].stdout)
        type(self).semantic_copy_mismatch_cases += 5

    def test_02_failure_evidence_has_explicit_null_semantics(self) -> None:
        run = self._verify("linux-node20", label="failure", result="fail")
        result = run["verification"]
        for key in (
            "canonicalVerifierPassed",
            "sameProcessRepeatable",
            "sameHostRepeatable",
            "boundaryVectorSetPassed",
        ):
            self.assertIsNone(result[key])
        self.assertFalse(result["artifactVerified"])
        self.assertFalse(result["semanticReportVerified"])
        self.assertFalse(result["semanticClaimsBound"])
        self.assertFalse(result["comparisonEligible"])
        forbidden = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                run["evidence_path"],
                "linux-node20",
                self.base / "synthetic-forbidden-artifact.bin",
                None,
            ),
        )
        self._assert_cli_error(
            forbidden, "CLI", "failure-artifact-or-semantic-report-forbidden"
        )
        type(self).semantic_copy_mismatch_cases += 2

    def test_03_semantic_report_identity_and_field_mismatches_are_rejected(self) -> None:
        artifact = b"semantic-mismatch-artifact\n"
        cases = [
            ("artifact-role", {"artifactRole": "different-role"}, "artifact-role-mismatch"),
            ("format-profile", {"formatProfile": "different-profile"}, "format-profile-mismatch"),
            ("source-commit", {"sourceCommit": "a" * 40}, "source-commit-mismatch"),
            ("tooling-commit", {"toolingCommit": "b" * 40}, "tooling-commit-mismatch"),
            ("input-set", {"inputSetSha256": "c" * 64}, "input-set-sha256-mismatch"),
            ("artifact-hash", {"artifactSha256": "d" * 64}, "artifact-sha256-mismatch"),
            ("artifact-length", {"artifactByteLength": len(artifact) + 1}, "artifact-byte-length-mismatch"),
            (
                "failure-result",
                {"result": "fail", "failureCode": "adapter-failure", "canonicalVerifierPassed": False},
                "pass-evidence-report-result",
            ),
        ]
        for index, (label, changes, reason) in enumerate(cases):
            with self.subTest(case=label):
                semantic = self._semantic(artifact, (True, True, True, True), changes)
                semantic_bytes = _canonical(semantic)
                artifact_path = self.base / f"semantic-mismatch-artifact-{index}.bin"
                semantic_path = self.base / f"semantic-mismatch-report-{index}.json"
                evidence_path = self.base / f"semantic-mismatch-evidence-{index}.json"
                self._write(artifact_path, artifact)
                self._write(semantic_path, semantic_bytes)
                evidence = self._evidence("linux-node20", artifact, semantic_bytes)
                self._write(evidence_path, _canonical(evidence))
                process = self._run_script(
                    VERIFIER,
                    self._verifier_arguments(
                        evidence_path, "linux-node20", artifact_path, semantic_path
                    ),
                )
                self._assert_cli_error(process, "SEMANTIC_REPORT_SCHEMA", reason)

        canonical_false = self._verify(
            "linux-node20",
            label="canonical-false",
            claims=(False, True, True, True),
            expect_success=False,
        )
        self._assert_cli_error(
            canonical_false["process"], "SEMANTIC_REPORT_SCHEMA", "pass-canonical-verifier"
        )

        hash_run = self._verify("linux-node20", label="semantic-hash-base")
        hash_run["semantic_path"].write_bytes(hash_run["semantic_path"].read_bytes() + b"x")
        hash_process = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                hash_run["evidence_path"],
                "linux-node20",
                hash_run["artifact_path"],
                hash_run["semantic_path"],
            ),
        )
        self._assert_cli_error(
            hash_process,
            "SEMANTIC_REPORT_SCHEMA",
            "semantic-report-identity-mismatch",
        )

        length_run = self._verify("linux-node20", label="semantic-length-base")
        length_evidence = copy.deepcopy(length_run["evidence"])
        length_evidence["semanticReportByteLength"] += 1
        length_run["evidence_path"].write_bytes(_canonical(length_evidence))
        length_process = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                length_run["evidence_path"],
                "linux-node20",
                length_run["artifact_path"],
                length_run["semantic_path"],
            ),
        )
        self._assert_cli_error(
            length_process,
            "SEMANTIC_REPORT_SCHEMA",
            "semantic-report-identity-mismatch",
        )
        type(self).semantic_copy_mismatch_cases += 11

    def test_04_malformed_evidence_cases_have_exact_typed_reasons(self) -> None:
        artifact = b"fixture\n"
        semantic = _canonical(self._semantic(artifact, (True, True, True, True)))
        baseline_value = self._evidence("linux-node20", artifact, semantic)
        baseline = _canonical(baseline_value)
        phase = "EVIDENCE_SCHEMA"
        cases = self._generic_malformed_cases(baseline, baseline_value, phase, "evidence")

        def changed(key: str, value, reason: str, label: str | None = None) -> None:
            fixture = copy.deepcopy(baseline_value)
            fixture[key] = value
            cases.append((label or key, _canonical(fixture), phase, reason))

        changed("evidenceKind", "wrong-kind", "evidence-kind")
        changed("schemaVersion", 2, "schema-version")
        for index, (key, reason) in enumerate(
            (
                ("artifactRole", "artifact-role"),
                ("formatProfile", "format-profile"),
                ("runtimeProfileId", "runtime-profile-id"),
                ("gitProfileId", "git-profile-id"),
                ("matrixCellId", "matrix-cell-id"),
                ("operatingSystemBuild", "operating-system-build"),
                ("filesystemProfile", "filesystem-profile"),
                ("localeProfile", "locale-profile"),
                ("timezoneProfile", "timezone-profile"),
            )
        ):
            changed(key, f"Bad/Path/{index}", reason, f"invalid-{key}")
        for key, reason in (
            ("sourceCommit", "source-commit"),
            ("toolingCommit", "tooling-commit"),
            ("criticalToolSetSha256", "critical-tool-set-sha256"),
            ("manifestSha256", "manifest-sha256"),
            ("inputSetSha256", "input-set-sha256"),
            ("runtimeIdentitySha256", "runtime-identity-sha256"),
            ("gitIdentitySha256", "git-identity-sha256"),
            ("runnerPolicySha256", "runner-policy-sha256"),
            ("testVectorSetSha256", "test-vector-set-sha256"),
            ("platformProbeSha256", "platform-probe-sha256"),
            ("artifactSha256", "artifact-sha256"),
            ("semanticReportSha256", "semantic-report-sha256"),
        ):
            changed(key, "A" * (40 if "Commit" in key else 64), reason, f"uppercase-{key}")
        changed("operatingSystem", "freebsd", "operating-system")
        changed("architecture", "x86", "architecture")
        changed("result", "unknown", "result")
        changed("artifactByteLength", None, "artifact-byte-length")
        changed("semanticReportByteLength", None, "semantic-report-byte-length")
        changed("failureClass", "implementation-defect", "pass-failure-fields")
        changed("failureCode", "unexpected", "pass-failure-fields")

        failure = self._evidence("linux-node20", artifact, b"", result="fail")
        for label, key, value, reason in (
            ("failure-artifact-hash", "artifactSha256", "a" * 64, "failure-artifact-fields"),
            ("failure-artifact-length", "artifactByteLength", 1, "failure-artifact-fields"),
            ("failure-semantic-hash", "semanticReportSha256", "b" * 64, "failure-artifact-fields"),
            ("failure-semantic-length", "semanticReportByteLength", 1, "failure-artifact-fields"),
            ("failure-class", "failureClass", "unknown", "failure-class"),
            ("failure-code", "failureCode", "Bad/Code", "failure-code"),
        ):
            fixture = copy.deepcopy(failure)
            fixture[key] = value
            cases.append((label, _canonical(fixture), phase, reason))
        for label, replacement, reason in (
            ("negative-integer", b"-1", "integer-negative"),
            ("fraction-integer", b"1.0", "integer-fraction"),
            ("exponent-integer", b"1e0", "integer-exponent"),
            ("leading-zero-integer", b"01", "integer-leading-zero"),
            ("unsafe-integer", b"9007199254740992", "integer-range"),
        ):
            cases.append(
                (label, _replace_number(baseline, "artifactByteLength", replacement), phase, reason)
            )
        self.assertGreaterEqual(len(cases), 52)
        self._assert_parser_cases("evidence", cases)
        type(self).malformed_evidence_cases += len(cases)

    def test_05_malformed_policy_cases_have_exact_typed_reasons(self) -> None:
        baseline_value = copy.deepcopy(self.policy)
        baseline = _canonical(baseline_value)
        phase = "POLICY_SCHEMA"
        cases = self._generic_malformed_cases(baseline, baseline_value, phase, "policy")

        def changed(key: str, value, reason: str, label: str | None = None) -> None:
            fixture = copy.deepcopy(baseline_value)
            fixture[key] = value
            cases.append((label or key, _canonical(fixture), phase, reason))

        changed("policyKind", "wrong-kind", "policy-kind")
        changed("schemaVersion", 2, "schema-version")
        changed("policyId", "Bad/Policy", "policy-id")
        changed("artifactRole", "Bad/Role", "artifact-role")
        changed("formatProfile", "Bad/Profile", "format-profile")
        for key, reason in (
            ("sourceCommit", "source-commit"),
            ("toolingCommit", "tooling-commit"),
            ("criticalToolSetSha256", "critical-tool-set-sha256"),
            ("manifestSha256", "manifest-sha256"),
            ("inputSetSha256", "input-set-sha256"),
            ("testVectorSetSha256", "test-vector-set-sha256"),
        ):
            changed(key, "F" * (40 if "Commit" in key else 64), reason, f"invalid-{key}")
        changed("requiredClaimLevels", [], "required-claim-levels-count", "claims-empty")
        changed("requiredClaimLevels", ["L0", "L0"], "required-claim-levels-duplicate", "claims-duplicate")
        changed("requiredClaimLevels", ["L1", "L0"], "required-claim-levels-order", "claims-order")
        changed("requiredClaimLevels", ["L1"], "required-claim-levels-l0", "claims-no-l0")
        changed("requiredClaimLevels", ["L0", "L7"], "required-claim-levels-value", "claims-unknown")
        changed("requiredCells", [], "required-cells-count")
        reordered_cells = copy.deepcopy(baseline_value)
        reordered_cells["requiredCells"] = list(reversed(reordered_cells["requiredCells"]))
        cases.append(("cell-order", _canonical(reordered_cells), phase, "required-cells-order"))
        duplicate_cells = copy.deepcopy(baseline_value)
        duplicate_cells["requiredCells"][1] = copy.deepcopy(duplicate_cells["requiredCells"][0])
        cases.append(("cell-duplicate", _canonical(duplicate_cells), phase, "required-cells-duplicate"))
        overlap = copy.deepcopy(baseline_value)
        overlap["optionalCells"] = [copy.deepcopy(overlap["requiredCells"][0])]
        cases.append(("cell-overlap", _canonical(overlap), phase, "required-optional-overlap"))

        cell_mutations = (
            ("matrixCellId", "Bad/Cell", "cell-id"),
            ("runtimeProfileId", "Bad/Runtime", "runtime-profile-id"),
            ("runtimeIdentitySha256", "A" * 64, "runtime-identity-sha256"),
            ("gitProfileId", "Bad/Git", "git-profile-id"),
            ("gitIdentitySha256", "B" * 64, "git-identity-sha256"),
            ("operatingSystem", "freebsd", "operating-system"),
            ("operatingSystemBuild", "Bad/Build", "operating-system-build"),
            ("architecture", "x86", "architecture"),
            ("filesystemProfile", "Bad/Fs", "filesystem-profile"),
            ("localeProfile", "Bad/Locale", "locale-profile"),
            ("timezoneProfile", "Bad/Timezone", "timezone-profile"),
            ("platformProbeSha256", "C" * 64, "platform-probe-sha256"),
        )
        for index, (key, value, reason) in enumerate(cell_mutations):
            fixture = copy.deepcopy(baseline_value)
            fixture["requiredCells"][0][key] = value
            cases.append((f"cell-field-{index}", _canonical(fixture), phase, reason))
        cell_unknown = copy.deepcopy(baseline_value)
        cell_unknown["requiredCells"][0]["unknown"] = True
        cases.append(("cell-unknown", _canonical(cell_unknown), phase, "cell-unknown-field"))
        cell_missing = copy.deepcopy(baseline_value)
        cell_missing["requiredCells"][0].pop("platformProbeSha256")
        cases.append(("cell-missing", _canonical(cell_missing), phase, "cell-missing-field"))
        cell_reorder = copy.deepcopy(baseline_value)
        cell = cell_reorder["requiredCells"][0]
        cell_reorder["requiredCells"][0] = {
            key: cell[key] for key in (CELL_KEYS[1], CELL_KEYS[0], *CELL_KEYS[2:])
        }
        cases.append(("cell-key-order", _canonical(cell_reorder), phase, "cell-key-order"))
        self.assertGreaterEqual(len(cases), 36)
        self._assert_parser_cases("policy", cases)
        type(self).malformed_policy_cases += len(cases)

    def test_06_malformed_semantic_report_cases_have_exact_typed_reasons(self) -> None:
        artifact = b"semantic-fixture\n"
        baseline_value = self._semantic(artifact, (True, True, True, True))
        baseline = _canonical(baseline_value)
        phase = "SEMANTIC_REPORT_SCHEMA"
        cases = self._generic_malformed_cases(
            baseline, baseline_value, phase, "semantic-report"
        )

        def changed(key: str, value, reason: str, label: str | None = None) -> None:
            fixture = copy.deepcopy(baseline_value)
            fixture[key] = value
            cases.append((label or key, _canonical(fixture), phase, reason))

        changed("semanticReportKind", "wrong-kind", "semantic-report-kind")
        changed("schemaVersion", 2, "schema-version")
        changed("artifactRole", "Bad/Role", "artifact-role")
        changed("formatProfile", "Bad/Profile", "format-profile")
        changed("sourceCommit", "A" * 40, "source-commit")
        changed("toolingCommit", "B" * 40, "tooling-commit")
        changed("inputSetSha256", "C" * 64, "input-set-sha256")
        changed("artifactSha256", "D" * 64, "artifact-sha256")
        changed("artifactByteLength", None, "artifact-byte-length")
        changed("canonicalVerifierPassed", "true", "canonical-verifier-passed")
        changed("sameProcessRepeatable", None, "same-process-repeatable")
        changed("sameHostRepeatable", 1, "same-host-repeatable")
        changed("boundaryVectorSetPassed", "false", "boundary-vector-set-passed")
        changed("result", "unknown", "result")
        changed("failureCode", "unexpected", "pass-failure-code")
        changed("canonicalVerifierPassed", False, "pass-canonical-verifier", "pass-canonical-false")
        failure = copy.deepcopy(baseline_value)
        failure["result"] = "fail"
        failure["failureCode"] = "adapter-failure"
        failure["canonicalVerifierPassed"] = False
        invalid_failure = copy.deepcopy(failure)
        invalid_failure["failureCode"] = "Bad/Failure"
        cases.append(("failure-code-invalid", _canonical(invalid_failure), phase, "failure-code"))
        for label, replacement, reason in (
            ("negative-integer", b"-1", "integer-negative"),
            ("fraction-integer", b"1.0", "integer-fraction"),
            ("exponent-integer", b"1e0", "integer-exponent"),
            ("leading-zero-integer", b"01", "integer-leading-zero"),
            ("unsafe-integer", b"9007199254740992", "integer-range"),
        ):
            cases.append(
                (label, _replace_number(baseline, "artifactByteLength", replacement), phase, reason)
            )
        self.assertGreaterEqual(len(cases), 28)
        self._assert_parser_cases("semantic", cases)
        type(self).malformed_semantic_cases += len(cases)

    def test_07_malformed_verification_results_cover_corrected_semantics(self) -> None:
        baseline_value = self._verification_fixture("pass")
        baseline = _canonical(baseline_value)
        phase = "VERIFICATION_RESULT_SCHEMA"
        cases = self._generic_malformed_cases(
            baseline, baseline_value, phase, "verification-result"
        )

        def changed(key: str, value, reason: str, label: str | None = None) -> None:
            fixture = copy.deepcopy(baseline_value)
            fixture[key] = value
            cases.append((label or key, _canonical(fixture), phase, reason))

        changed("verificationKind", "wrong-kind", "verification-kind")
        changed("schemaVersion", 2, "schema-version")
        changed("status", "blocked", "verification-mode")
        changed("mode", "wrong-mode", "verification-mode")
        changed("policyId", "Bad/Policy", "policy-id")
        changed("artifactRole", "Bad/Role", "artifact-role")
        changed("formatProfile", "Bad/Profile", "format-profile")
        changed("matrixCellId", "Bad/Cell", "matrix-cell-id")
        changed("evidenceSha256", "A" * 64, "verification-hash")
        changed("policySha256", "B" * 64, "verification-hash")
        changed("comparisonIdentitySha256", "C" * 64, "verification-hash")
        changed("evidenceByteLength", None, "evidence-byte-length")

        for key in (
            "canonicalVerifierPassed",
            "sameProcessRepeatable",
            "sameHostRepeatable",
            "boundaryVectorSetPassed",
        ):
            missing = copy.deepcopy(baseline_value)
            missing.pop(key)
            cases.append(
                (f"missing-{key}", _canonical(missing), phase, "verification-result-missing-field")
            )
            changed(key, None, "pass-semantic-claim", f"null-{key}")

        keys = list(VERIFICATION_KEYS)
        reordered = copy.deepcopy(baseline_value)
        left = keys.index("canonicalVerifierPassed")
        keys[left], keys[left + 1] = keys[left + 1], keys[left]
        reordered = {key: reordered[key] for key in keys}
        cases.append(
            ("reordered-new-fields", _canonical(reordered), phase, "verification-result-key-order")
        )
        duplicate = baseline[:-2] + b',"canonicalVerifierPassed":true}\n'
        cases.append(("duplicate-new-field", duplicate, phase, "duplicate-key"))
        unknown = copy.deepcopy(baseline_value)
        items = list(unknown.items())
        position = keys.index("canonicalVerifierPassed")
        items.insert(position, ("semanticClaimSource", True))
        cases.append(
            (
                "unknown-near-claims",
                _canonical(dict(items)),
                phase,
                "verification-result-unknown-field",
            )
        )

        failure = self._verification_fixture("fail")
        for key in (
            "canonicalVerifierPassed",
            "sameProcessRepeatable",
            "sameHostRepeatable",
            "boundaryVectorSetPassed",
        ):
            fixture = copy.deepcopy(failure)
            fixture[key] = True
            cases.append(
                (
                    f"failure-boolean-{key}",
                    _canonical(fixture),
                    phase,
                    "failure-semantic-claim-not-null",
                )
            )
        changed(
            "semanticReportVerified",
            False,
            "pass-verification-semantics",
            "unverified-bound-claim",
        )
        changed(
            "semanticClaimsBound",
            False,
            "pass-verification-semantics",
            "unbound-non-null-claim",
        )
        changed(
            "semanticClaimsIndependentlyReplayed",
            True,
            "semantic-claims-independently-replayed",
        )
        failure_eligible = copy.deepcopy(failure)
        failure_eligible["comparisonEligible"] = True
        cases.append(
            (
                "failure-comparison-eligible",
                _canonical(failure_eligible),
                phase,
                "failure-verification-semantics",
            )
        )
        changed("platformAttestationVerified", True, "platform-attestation-verified")
        changed("evidenceSigningRequired", False, "evidence-signing-not-required")
        changed("projectPublicationAuthorized", True, "project-publication-authorized")
        for key in (
            "sourceCommitObjectVerified",
            "toolingCommitObjectVerified",
            "criticalToolSetVerified",
            "manifestVerified",
            "inputSetVerified",
            "runtimeIdentityVerified",
            "gitIdentityVerified",
            "testVectorSetVerified",
            "platformProbeVerified",
            "policyCellVerified",
        ):
            changed(key, False, "required-identity-not-verified", f"false-{key}")
        changed("artifactVerified", False, "pass-verification-semantics")
        changed("comparisonEligible", False, "pass-verification-semantics")
        self.assertGreaterEqual(len(cases), 36)
        self._assert_parser_cases("verification", cases)
        type(self).malformed_verification_cases += len(cases)

    def test_08_three_cell_end_to_end_derives_l0_through_l5_but_never_l6(self) -> None:
        runs = [self._verify(cell_id) for cell_id in self.cells]
        process, report = self._compare(runs)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        self.assertEqual(report["comparisonKind"], COMPARISON_KIND)
        self.assertEqual(report["claimLevelsSatisfied"], ["L0", "L1", "L2", "L3", "L4", "L5"])
        self.assertEqual(report["highestClaimLevel"], "L5")
        self.assertTrue(report["claimAllowed"])
        self.assertTrue(report["matrixComplete"])
        self.assertTrue(report["sameArtifactBytes"])
        self.assertTrue(report["sameSemanticReport"])
        self.assertEqual(report["claimScope"], "controlled-runner-matrix-evidence")
        self.assertFalse(report["platformAttestationVerified"])
        self.assertTrue(report["evidenceSigningRequired"])
        self.assertFalse(report["projectPublicationAuthorized"])
        self.assertEqual(
            report["evidenceRecordSha256s"],
            [_sha256(run["evidence_path"].read_bytes()) for run in runs],
        )
        self.assertEqual(
            report["verificationResultSha256s"],
            [_sha256(run["verification_path"].read_bytes()) for run in runs],
        )
        identity = {
            "artifactRole": self.policy["artifactRole"],
            "formatProfile": self.policy["formatProfile"],
            "sourceCommit": self.policy["sourceCommit"],
            "toolingCommit": self.policy["toolingCommit"],
            "criticalToolSetSha256": self.policy["criticalToolSetSha256"],
            "manifestSha256": self.policy["manifestSha256"],
            "inputSetSha256": self.policy["inputSetSha256"],
            "runnerPolicySha256": self.policy_sha256,
            "testVectorSetSha256": self.policy["testVectorSetSha256"],
        }
        expected_identity = _sha256(
            b"ieltmps-reproducibility-comparison-identity-v1\n"
            + json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            + b"\n"
        )
        self.assertEqual(report["comparisonIdentitySha256"], expected_identity)
        for run in runs:
            self.assertEqual(run["verification"]["comparisonIdentitySha256"], expected_identity)

        self._set_policy(
            ("linux-node20", "linux-node22", "windows-node20"),
            (),
            ("L0", "L1", "L2", "L3", "L4", "L5", "L6"),
        )
        l6_runs = [self._verify(cell_id, label=f"l6-{cell_id}") for cell_id in self.cells]
        l6_process, l6_report = self._compare(l6_runs)
        self.assertEqual(l6_process.returncode, 2, l6_process.stderr)
        self.assertFalse(l6_report["claimAllowed"])
        self.assertNotIn("L6", l6_report["claimLevelsSatisfied"])
        self.assertIn("interoperability-evidence-required", l6_report["reasons"])

    def test_09_corrected_l1_l2_and_l5_derivation_is_fail_closed(self) -> None:
        scenarios = (
            ("same-process", (True, False, True, True), ("L0", "L1"), "L1"),
            ("same-host", (True, True, False, True), ("L0", "L2"), "L2"),
            ("boundary", (True, True, True, False), ("L0", "L5"), "L5"),
        )
        for label, claims, levels, absent in scenarios:
            with self.subTest(scenario=label):
                self._set_policy(("linux-node20",), (), levels)
                run = self._verify("linux-node20", label=f"claim-{label}", claims=claims)
                process, report = self._compare([run])
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertFalse(report["claimAllowed"])
                self.assertNotIn(absent, report["claimLevelsSatisfied"])
        type(self).comparator_anti_inference_cases += 6

    def test_10_comparator_rejects_null_unbound_or_fabricated_semantic_claims(self) -> None:
        self._set_policy(("linux-node20",), (), ("L0",))
        run = self._verify("linux-node20", label="anti-inference-base")
        malformed_values = []
        null_claim = copy.deepcopy(run["verification"])
        null_claim["sameProcessRepeatable"] = None
        malformed_values.append(("null-pass-claim", null_claim, "pass-semantic-claim"))
        unbound = copy.deepcopy(run["verification"])
        unbound["semanticClaimsBound"] = False
        malformed_values.append(("fabricated-unbound-claims", unbound, "pass-verification-semantics"))
        failure_nonnull = self._verification_fixture("fail")
        failure_nonnull["sameHostRepeatable"] = False
        malformed_values.append(
            ("failure-non-null", failure_nonnull, "failure-semantic-claim-not-null")
        )
        for label, fixture, reason in malformed_values:
            with self.subTest(case=label):
                result_path = self.base / f"malformed-comparator-{label}.json"
                result_path.write_bytes(_canonical(fixture))
                process = self._run_script(
                    COMPARATOR,
                    [
                        "--policy",
                        str(self.policy_path),
                        "--verified-run",
                        str(run["evidence_path"]),
                        str(result_path),
                    ],
                )
                self._assert_cli_error(process, "VERIFICATION_RESULT_SCHEMA", reason)
        semantic_argument = self._run_script(
            COMPARATOR,
            [
                "--policy",
                str(self.policy_path),
                "--verified-run",
                str(run["evidence_path"]),
                str(run["verification_path"]),
                "--semantic-report",
                str(run["semantic_path"]),
            ],
        )
        self._assert_cli_error(
            semantic_argument, "CLI", "unknown-or-positional-option"
        )
        comparator_source = COMPARATOR.read_text(encoding="utf-8")
        self.assertNotIn('"--semantic-report"', comparator_source)
        self.assertNotIn("parseCanonicalSemanticReport", comparator_source)
        type(self).comparator_anti_inference_cases += 4

    def test_11_optional_cells_missing_cells_and_failure_records_block_correctly(self) -> None:
        self._set_policy(
            ("linux-node20", "windows-node20"),
            ("linux-node22",),
            ("L0", "L1", "L2", "L4", "L5"),
        )
        required_runs = [
            self._verify("linux-node20", label="optional-linux"),
            self._verify("windows-node20", label="optional-windows"),
        ]
        absent_process, absent_report = self._compare(required_runs)
        self.assertEqual(absent_process.returncode, 0, absent_process.stderr)
        self.assertEqual(absent_report["presentOptionalCellCount"], 0)
        optional_run = self._verify("linux-node22", label="optional-present")
        present_process, present_report = self._compare([*required_runs, optional_run])
        self.assertEqual(present_process.returncode, 0, present_process.stderr)
        self.assertEqual(present_report["presentOptionalCellCount"], 1)
        missing_process, missing_report = self._compare(required_runs[:1])
        self.assertEqual(missing_process.returncode, 2, missing_process.stderr)
        self.assertFalse(missing_report["matrixComplete"])
        self.assertIn("missing-required-cell", missing_report["reasons"])
        failure = self._verify("linux-node22", label="optional-failure", result="fail")
        failed_process, failed_report = self._compare([*required_runs, failure])
        self.assertEqual(failed_process.returncode, 2, failed_process.stderr)
        self.assertIn("evidence-failure", failed_report["reasons"])

        self._set_policy(
            ("linux-node20", "linux-node22", "windows-node20"),
            (),
            ("L0", "L4"),
        )
        partial_cross_os = [
            self._verify("linux-node20", label="partial-l4-linux"),
            self._verify("windows-node20", label="partial-l4-windows"),
        ]
        partial_process, partial_report = self._compare(partial_cross_os)
        self.assertEqual(partial_process.returncode, 2, partial_process.stderr)
        self.assertIn("L4", partial_report["claimLevelsSatisfied"])
        self.assertIn("missing-required-cell", partial_report["reasons"])
        type(self).comparator_adversarial_cases += 5

    def test_12_artifact_and_semantic_identity_mismatches_block_comparison(self) -> None:
        self._set_policy(("linux-node20", "windows-node20"), (), ("L0", "L4", "L5"))
        first = self._verify("linux-node20", label="identity-first")
        artifact_changed = self._verify(
            "windows-node20",
            label="identity-artifact-changed",
            artifact_bytes=b"different-synthetic-artifact\n",
        )
        artifact_process, artifact_report = self._compare([first, artifact_changed])
        self.assertEqual(artifact_process.returncode, 2, artifact_process.stderr)
        self.assertFalse(artifact_report["sameArtifactBytes"])
        self.assertIn("artifact-identity-mismatch", artifact_report["reasons"])

        semantic_changed = self._verify(
            "windows-node20",
            label="identity-semantic-changed",
            claims=(True, True, False, True),
        )
        semantic_process, semantic_report = self._compare([first, semantic_changed])
        self.assertEqual(semantic_process.returncode, 2, semantic_process.stderr)
        self.assertTrue(semantic_report["sameArtifactBytes"])
        self.assertFalse(semantic_report["sameSemanticReport"])
        self.assertNotIn("L2", semantic_report["claimLevelsSatisfied"])
        self.assertIn("semantic-report-identity-mismatch", semantic_report["reasons"])
        type(self).comparator_adversarial_cases += 2

    def test_13_policy_and_matrix_binding_adversarial_cases_are_typed(self) -> None:
        baseline = self._verify("linux-node20", label="binding-baseline")
        mutations = (
            ("runner-policy", "runnerPolicySha256", "9" * 64, "POLICY_BINDING", "runner-policy-sha256"),
            ("artifact-role", "artifactRole", "other-role", "POLICY_BINDING", "artifact-role"),
            ("format-profile", "formatProfile", "other-profile", "POLICY_BINDING", "format-profile"),
            ("source-commit", "sourceCommit", "a" * 40, "POLICY_BINDING", "source-commit"),
            ("tooling-commit", "toolingCommit", "b" * 40, "POLICY_BINDING", "tooling-commit"),
            (
                "critical-tool-set",
                "criticalToolSetSha256",
                "c" * 64,
                "POLICY_BINDING",
                "critical-tool-set-sha256",
            ),
            ("manifest", "manifestSha256", "d" * 64, "POLICY_BINDING", "manifest-sha256"),
            ("input-set", "inputSetSha256", "e" * 64, "POLICY_BINDING", "input-set-sha256"),
            (
                "test-vector-set",
                "testVectorSetSha256",
                "f" * 64,
                "POLICY_BINDING",
                "test-vector-set-sha256",
            ),
            ("unknown-cell", "matrixCellId", "unknown-cell", "MATRIX_CELL", "unknown-matrix-cell"),
            (
                "runtime-profile",
                "runtimeProfileId",
                "other-runtime",
                "MATRIX_CELL",
                "runtime-profile-id-mismatch",
            ),
            (
                "runtime-hash",
                "runtimeIdentitySha256",
                "1" * 64,
                "MATRIX_CELL",
                "runtime-identity-sha256-mismatch",
            ),
            ("git-profile", "gitProfileId", "other-git", "MATRIX_CELL", "git-profile-id-mismatch"),
            (
                "git-hash",
                "gitIdentitySha256",
                "2" * 64,
                "MATRIX_CELL",
                "git-identity-sha256-mismatch",
            ),
            ("os", "operatingSystem", "macos", "MATRIX_CELL", "operating-system-mismatch"),
            (
                "os-build",
                "operatingSystemBuild",
                "other-build",
                "MATRIX_CELL",
                "operating-system-build-mismatch",
            ),
            ("architecture", "architecture", "arm64", "MATRIX_CELL", "architecture-mismatch"),
            (
                "filesystem",
                "filesystemProfile",
                "other-filesystem",
                "MATRIX_CELL",
                "filesystem-profile-mismatch",
            ),
            ("locale", "localeProfile", "zh-cn", "MATRIX_CELL", "locale-profile-mismatch"),
            ("timezone", "timezoneProfile", "utc+8", "MATRIX_CELL", "timezone-profile-mismatch"),
            (
                "platform-probe",
                "platformProbeSha256",
                "3" * 64,
                "MATRIX_CELL",
                "platform-probe-sha256-mismatch",
            ),
        )
        for index, (label, key, value, phase, reason) in enumerate(mutations):
            with self.subTest(case=label):
                evidence = copy.deepcopy(baseline["evidence"])
                evidence[key] = value
                evidence_path = self.base / f"binding-adversarial-{index}.json"
                evidence_path.write_bytes(_canonical(evidence))
                process = self._run_script(
                    VERIFIER,
                    self._verifier_arguments(
                        evidence_path,
                        "linux-node20",
                        baseline["artifact_path"],
                        baseline["semantic_path"],
                    ),
                )
                self._assert_cli_error(process, phase, reason)

    def test_14_comparator_pair_binding_and_adversarial_fields_are_typed(self) -> None:
        self._set_policy(("linux-node20", "windows-node20"), (), ("L0",))
        first = self._verify("linux-node20", label="pair-first")
        second = self._verify("windows-node20", label="pair-second")
        mutations = (
            ("evidenceSha256", "9" * 64, "evidence-sha256-mismatch"),
            ("evidenceByteLength", first["verification"]["evidenceByteLength"] + 1, "evidence-byte-length-mismatch"),
            ("policySha256", "8" * 64, "policy-sha256-mismatch"),
            ("comparisonIdentitySha256", "7" * 64, "comparison-identity-sha256-mismatch"),
            ("policyId", "other-policy", "policy-id-mismatch"),
            ("artifactRole", "other-role", "artifact-role-mismatch"),
            ("formatProfile", "other-profile", "format-profile-mismatch"),
            ("matrixCellId", "windows-node20", "matrix-cell-id-mismatch"),
        )
        for index, (key, value, reason) in enumerate(mutations):
            with self.subTest(field=key):
                result = copy.deepcopy(first["verification"])
                result[key] = value
                result_path = self.base / f"pair-binding-result-{index}.json"
                result_path.write_bytes(_canonical(result))
                process = self._run_script(
                    COMPARATOR,
                    [
                        "--policy",
                        str(self.policy_path),
                        "--verified-run",
                        str(first["evidence_path"]),
                        str(result_path),
                    ],
                )
                self._assert_cli_error(process, "COMPARISON", reason)
        duplicate = self._run_script(
            COMPARATOR,
            [
                "--policy",
                str(self.policy_path),
                "--verified-run",
                str(first["evidence_path"]),
                str(first["verification_path"]),
                "--verified-run",
                str(first["evidence_path"]),
                str(first["verification_path"]),
            ],
        )
        self._assert_cli_error(duplicate, "COMPARISON", "duplicate-matrix-cell")
        duplicate_result = self._run_script(
            COMPARATOR,
            [
                "--policy",
                str(self.policy_path),
                "--verified-run",
                str(first["evidence_path"]),
                str(first["verification_path"]),
                "--verified-run",
                str(second["evidence_path"]),
                str(first["verification_path"]),
            ],
        )
        self._assert_cli_error(
            duplicate_result, "COMPARISON", "duplicate-verification-result"
        )
        type(self).comparator_adversarial_cases += len(mutations) + 2

    def test_15_git_commit_authority_and_hostile_environment_are_fail_closed(self) -> None:
        self.assertNotEqual(self.source_commit, self.tooling_commit)
        hostile_names = (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_REPLACE_REF_BASE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_ASKPASS",
        )
        for index, name in enumerate(hostile_names):
            with self.subTest(variable=name):
                hostile = self._environment({name: str(self.base / f"hostile-{index}")})
                run = self._verify(
                    "linux-node20",
                    label=f"hostile-git-{index}",
                    environment=hostile,
                )
                self.assertTrue(run["verification"]["sourceCommitObjectVerified"])

        blob = self._git(
            self.source_repo, "hash-object", "-w", "synthetic-source.txt"
        ).stdout.strip()
        self._set_policy(("linux-node20",), (), ("L0",))
        self.policy["sourceCommit"] = blob
        self.policy_bytes = _canonical(self.policy)
        self.policy_path.write_bytes(self.policy_bytes)
        self.policy_sha256 = _sha256(self.policy_bytes)
        artifact = b"noncommit-artifact\n"
        semantic = self._semantic(artifact, (True, True, True, True))
        semantic["sourceCommit"] = blob
        semantic_bytes = _canonical(semantic)
        artifact_path = self.base / "noncommit-artifact.bin"
        semantic_path = self.base / "noncommit-semantic.json"
        evidence_path = self.base / "noncommit-evidence.json"
        artifact_path.write_bytes(artifact)
        semantic_path.write_bytes(semantic_bytes)
        evidence = self._evidence("linux-node20", artifact, semantic_bytes)
        evidence["sourceCommit"] = blob
        evidence_path.write_bytes(_canonical(evidence))
        noncommit = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                evidence_path, "linux-node20", artifact_path, semantic_path
            ),
        )
        self._assert_cli_error(noncommit, "GIT", "commit-object-type")

        missing = "f" * 40
        self.policy["sourceCommit"] = missing
        self.policy_bytes = _canonical(self.policy)
        self.policy_path.write_bytes(self.policy_bytes)
        self.policy_sha256 = _sha256(self.policy_bytes)
        evidence["sourceCommit"] = missing
        evidence["runnerPolicySha256"] = self.policy_sha256
        evidence_path.write_bytes(_canonical(evidence))
        missing_commit = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                evidence_path, "linux-node20", artifact_path, semantic_path
            ),
        )
        self._assert_cli_error(missing_commit, "GIT", "commit-object")

        abbreviated = copy.deepcopy(evidence)
        abbreviated["sourceCommit"] = self.source_commit[:12]
        evidence_path.write_bytes(_canonical(abbreviated))
        abbreviated_result = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                evidence_path, "linux-node20", artifact_path, semantic_path
            ),
        )
        self._assert_cli_error(abbreviated_result, "EVIDENCE_SCHEMA", "source-commit")

    def test_16_replacement_refs_are_rejected_and_committed_code_is_not_executed(self) -> None:
        marker = self.base / "committed-code-marker"
        executable = self.source_repo / "synthetic-executable.js"
        executable.write_text(
            f"require('node:fs').writeFileSync({json.dumps(str(marker))}, 'bad');\n",
            encoding="utf-8",
            newline="\n",
        )
        self._git(self.source_repo, "add", "synthetic-executable.js")
        self._git(self.source_repo, "commit", "-m", "synthetic inert committed code")
        replacement = self._git(self.source_repo, "rev-parse", "HEAD").stdout.strip()
        self._git(self.source_repo, "replace", self.source_commit, replacement)
        run = self._verify(
            "linux-node20", label="replacement-ref", expect_success=False
        )
        self._assert_cli_error(run["process"], "GIT", "replacement-object-ref")
        self.assertFalse(marker.exists())

    def test_17_bound_documents_and_artifact_hashes_are_exact(self) -> None:
        baseline = self._verify("linux-node20", label="identity-positive")
        bindings = (
            ("critical-tool-set", self.critical_tool_set),
            ("manifest", self.manifest),
            ("input-set", self.input_set),
            ("runtime-identity", self.cells["linux-node20"]["runtime_path"]),
            ("git-identity", self.git_identity),
            ("test-vector-set", self.test_vector_set),
            ("platform-probe", self.cells["linux-node20"]["probe_path"]),
        )
        for index, (label, target) in enumerate(bindings):
            with self.subTest(binding=label):
                original = target.read_bytes()
                target.write_bytes(original + f"mutation-{index}".encode())
                process = self._run_script(
                    VERIFIER,
                    self._verifier_arguments(
                        baseline["evidence_path"],
                        "linux-node20",
                        baseline["artifact_path"],
                        baseline["semantic_path"],
                    ),
                )
                self._assert_cli_error(
                    process, "FILE_IDENTITY", "bound-document-hash"
                )
                target.write_bytes(original)
        baseline["artifact_path"].write_bytes(b"artifact-mutation\n")
        artifact_process = self._run_script(
            VERIFIER,
            self._verifier_arguments(
                baseline["evidence_path"],
                "linux-node20",
                baseline["artifact_path"],
                baseline["semantic_path"],
            ),
        )
        self._assert_cli_error(
            artifact_process, "ARTIFACT_IDENTITY", "artifact-mismatch"
        )

    def test_18_stable_file_reader_rejects_races_links_and_replacements(self) -> None:
        actions = (
            ("same-size-mutation", "mutate", "after-file-hash", "z" * 32),
            ("truncation", "truncate", "after-file-open", "x"),
            ("growth", "grow", "after-file-open", "growth"),
            ("replacement", "replace", "after-file-hash", "replacement-bytes"),
        )
        for index, (label, action, checkpoint, payload) in enumerate(actions):
            with self.subTest(action=label):
                target = self.base / f"file-race-{index}.bin"
                target.write_bytes(b"x" * 32)
                request = {
                    "path": str(target),
                    "kind": ("policy", "evidence", "artifact", "semantic-report")[index],
                    "action": action,
                    "checkpoint": checkpoint,
                    "payload": payload,
                }
                process = subprocess.run(
                    [str(self.node), "--input-type=module", "--eval", FILE_RACE_HARNESS],
                    cwd=self.base,
                    env=self._environment(
                        {"IELTMPS_TEST_REQUEST": json.dumps(request, separators=(",", ":"))}
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(process.stdout)
                if action == "replace" and result["phase"] == "HARNESS":
                    source = CORE.read_text(encoding="utf-8")
                    self.assertIn("finalResolved", source)
                    self.assertIn("inspectParentChain(targetPath, phase, parentChain)", source)
                else:
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["phase"], "FILE_IDENTITY")

        hardlink_source = self.base / "hardlink-source.bin"
        hardlink_target = self.base / "hardlink-target.bin"
        hardlink_source.write_bytes(b"hard-link-fixture\n")
        os.link(hardlink_source, hardlink_target)
        request = {
            "path": str(hardlink_source),
            "kind": "verification-result",
            "action": "none",
            "checkpoint": "never",
            "payload": "none",
        }
        hardlink_process = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", FILE_RACE_HARNESS],
            cwd=self.base,
            env=self._environment(
                {"IELTMPS_TEST_REQUEST": json.dumps(request, separators=(",", ":"))}
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        hardlink_result = json.loads(hardlink_process.stdout)
        self.assertFalse(hardlink_result["ok"])
        self.assertEqual(hardlink_result["phase"], "FILE_IDENTITY")
        self.assertEqual(hardlink_result["reason"], "file-identity-state")

        symlink_target = self.base / "symlink-target.bin"
        symlink_path = self.base / "symlink-alias.bin"
        symlink_target.write_bytes(b"symlink-fixture\n")
        try:
            symlink_path.symlink_to(symlink_target)
        except OSError:
            source = CORE.read_text(encoding="utf-8")
            self.assertIn("initial.isSymbolicLink()", source)
            self.assertIn("realpath(targetPath)", source)
        else:
            request["path"] = str(symlink_path)
            symlink_process = subprocess.run(
                [str(self.node), "--input-type=module", "--eval", FILE_RACE_HARNESS],
                cwd=self.base,
                env=self._environment(
                    {"IELTMPS_TEST_REQUEST": json.dumps(request, separators=(",", ":"))}
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            symlink_result = json.loads(symlink_process.stdout)
            self.assertFalse(symlink_result["ok"])
            self.assertEqual(symlink_result["phase"], "FILE_IDENTITY")

    def test_19_privacy_canaries_never_appear_in_public_output(self) -> None:
        self.assertEqual(len(CANARIES), 19)
        self.assertEqual(len(set(CANARIES.values())), 19)
        self._set_policy(("linux-node20", "windows-node20"), (), ("L0", "L4"))
        run = self._verify("linux-node20", label="privacy-success")
        blocked_process, _ = self._compare([run])
        self.assertEqual(blocked_process.returncode, 2, blocked_process.stderr)
        failure_process = self._run_script(
            VERIFIER,
            ["--evidence", CANARIES["environment"], "--unknown-option", CANARIES["username"]],
        )
        self._assert_cli_error(failure_process, "CLI")
        comparison_failure = self._run_script(
            COMPARATOR,
            ["--policy", CANARIES["policy"], "--raw-artifact", CANARIES["artifact"]],
        )
        self._assert_cli_error(comparison_failure, "CLI")
        outputs = (
            run["process"].stdout,
            blocked_process.stdout,
            failure_process.stderr,
            comparison_failure.stderr,
        )
        for output in outputs:
            for label, canary in CANARIES.items():
                with self.subTest(output=output[:24], canary=label):
                    self.assertNotIn(canary, output)

    def test_20_imports_are_silent_and_direct_execution_handles_aliases(self) -> None:
        trace = self.base / "import-git-trace.json"
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
                str(CORE),
                str(VERIFIER),
                str(COMPARATOR),
            ],
            cwd=self.base,
            env=self._environment({"GIT_TRACE2_EVENT": str(trace)}),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(imported.stdout, "")
        self.assertEqual(imported.stderr, "")
        self.assertFalse(trace.exists())

        file_url_import = subprocess.run(
            [
                str(self.node),
                "--input-type=module",
                "--eval",
                "await import(process.argv[1]);",
                VERIFIER.as_uri(),
            ],
            cwd=self.base,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(file_url_import.returncode, 0, file_url_import.stderr)
        self.assertEqual(file_url_import.stdout, "")
        self.assertEqual(file_url_import.stderr, "")

        self._set_policy(("linux-node20",), (), ("L0",))
        direct_run = self._verify("linux-node20", label="direct-execution")
        verifier_arguments = self._verifier_arguments(
            direct_run["evidence_path"],
            "linux-node20",
            direct_run["artifact_path"],
            direct_run["semantic_path"],
        )
        comparator_arguments = [
            "--policy",
            str(self.policy_path),
            "--verified-run",
            str(direct_run["evidence_path"]),
            str(direct_run["verification_path"]),
        ]
        for script, valid_arguments in (
            (VERIFIER, verifier_arguments),
            (COMPARATOR, comparator_arguments),
        ):
            spellings = (
                str(script),
                os.path.relpath(script, self.base),
                str(script.parent) + os.sep + "." + os.sep + script.name,
            )
            for spelling in spellings:
                with self.subTest(script=script.name, spelling=spelling):
                    invalid = self._run_script(spelling, [], cwd=self.base)
                    self._assert_cli_error(invalid, "CLI")
                    valid = self._run_script(
                        spelling, valid_arguments, cwd=self.base
                    )
                    self.assertEqual(valid.returncode, 0, valid.stderr)
                    self.assertEqual(valid.stderr, "")
                    self.assertEqual(valid.stdout.count("\n"), 1)

        verifier_alias = self.base / "verifier-alias.mjs"
        comparator_alias = self.base / "comparator-alias.mjs"
        try:
            verifier_alias.symlink_to(VERIFIER)
            comparator_alias.symlink_to(COMPARATOR)
        except OSError:
            for source in (
                VERIFIER.read_text(encoding="utf-8"),
                COMPARATOR.read_text(encoding="utf-8"),
            ):
                self.assertIn("realpathSync.native", source)
                self.assertIn("fileURLToPath(import.meta.url)", source)
        else:
            for alias, valid_arguments in (
                (verifier_alias, verifier_arguments),
                (comparator_alias, comparator_arguments),
            ):
                invalid = self._run_script(alias, [])
                self._assert_cli_error(invalid, "CLI")
                valid = self._run_script(alias, valid_arguments)
                self.assertEqual(valid.returncode, 0, valid.stderr)
                self.assertEqual(valid.stderr, "")
                self.assertEqual(valid.stdout.count("\n"), 1)
            alias_import = subprocess.run(
                [
                    str(self.node),
                    "--input-type=module",
                    "--eval",
                    import_script,
                    "alias-import-sentinel",
                    str(verifier_alias),
                    str(comparator_alias),
                ],
                cwd=self.base,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            self.assertEqual(alias_import.returncode, 0, alias_import.stderr)
            self.assertEqual(alias_import.stdout, "")
            self.assertEqual(alias_import.stderr, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
