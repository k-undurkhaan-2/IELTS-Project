import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
DEVELOPER = ROOT / "developer"
NODE = Path(os.environ.get(
    "IELTMPS_NODE",
    r"C:\Users\llzz\.cache\codex-runtimes\codex-primary-runtime"
    r"\dependencies\node\bin\node.exe",
))
PYTHON_TASK_PARENT = Path(os.environ["TEMP"])
VECTOR_PATH = DEVELOPER / "public-source-zip-boundary-vectors-v1.json"
CORE_PATH = DEVELOPER / "public-source-zip-reproducibility-core.mjs"
COORDINATOR_PATH = DEVELOPER / "prepare-public-source-zip-reproducibility.mjs"
RUNNER_PATH = DEVELOPER / "run-public-source-zip-boundary-vectors.mjs"

CRITICAL_TOOL_PATHS = [
    "developer/verify-public-source-membership.mjs",
    "developer/prepare-public-source-tree.mjs",
    "developer/public-source-zip-core.mjs",
    "developer/prepare-public-source-zip.mjs",
    "developer/verify-public-source-zip.mjs",
    "developer/reproducibility-evidence-core.mjs",
    "developer/verify-reproducibility-evidence.mjs",
    "developer/public-source-zip-reproducibility-core.mjs",
    "developer/prepare-public-source-zip-reproducibility.mjs",
    "developer/run-public-source-zip-boundary-vectors.mjs",
]
WORKER_MODULE_ORDER = [
    CRITICAL_TOOL_PATHS[index] for index in (0, 1, 2, 3, 4, 7, 9)
]
WORKER_MODULE_PATHS = set(WORKER_MODULE_ORDER)
SUCCESS_NAMES = [
    "artifact.zip",
    "zip-verification.json",
    "entry-plan.json",
    "input-set.json",
    "semantic-report.json",
    "evidence.json",
    "verification-result.json",
    ".complete",
]
FAILURE_NAMES = [
    "input-set.json",
    "evidence.json",
    "verification-result.json",
    ".complete",
]


def canonical_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def duplicate_aware_loads(text):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=reject_duplicates)


class PublicSourceZipReproducibilityTests(unittest.TestCase):
    counters = {
        "vector_descriptors": 0,
        "standalone_vectors": 0,
        "embedded_vectors": 0,
        "same_process_candidates": 0,
        "same_host_workers": 0,
        "loaded_byte_cases": 0,
        "worker_protocol_cases": 0,
        "result_contract_cases": 0,
        "proxy_contract_cases": 0,
        "broad_proxy_cases": 0,
        "nested_proxy_cases": 0,
        "revoked_proxy_cases": 0,
        "proxy_stability_cases": 0,
        "accepted_proxy_values": 0,
        "proxy_trap_calls": 0,
        "executor_accounting_cases": 0,
        "cleanup_controls": 0,
        "publication_races": 0,
        "publication_marker_controls": 0,
        "privacy_canaries": 0,
    }
    suite_started = time.perf_counter()
    worker_durations = []
    same_host_durations = []
    success_run = None
    failure_run = None
    stability_runs = None

    @classmethod
    def run_process(cls, arguments, *, cwd=None, timeout=180, check=True, env=None):
        completed = subprocess.run(
            [str(argument) for argument in arguments],
            cwd=str(cwd or ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                "command failed\nstdout:\n"
                + completed.stdout.decode("utf-8", "replace")
                + "\nstderr:\n"
                + completed.stderr.decode("utf-8", "replace")
            )
        return completed

    @classmethod
    def run_node(cls, source, *, timeout=180, check=True):
        return cls.run_process(
            [NODE, "--input-type=module", "--eval", source],
            timeout=timeout,
            check=check,
        )

    @classmethod
    def run_git(cls, *arguments, check=True):
        return cls.run_process(
            [cls.git_path, "-C", cls.repository, *arguments],
            env=cls.git_environment,
            check=check,
        )

    @classmethod
    def write_source_commit(cls):
        exact_paths = [
            "api-contract/README.md",
            "backend/Dockerfile",
            "backend/package.json",
            "scripts/build-bundles.mjs",
            "scripts/bundle-manifest.mjs",
            "index.html",
            "LICENSE.md",
            "NOTICE.md",
            "README.md",
            "docs/CONTENT_POLICY.md",
            "docs/STATUS.md",
            "LICENSE",
            "LICENSES/AGPL-3.0-only.txt",
            "backend/package-lock.json",
            "developer/prepare-public-container-context.mjs",
            "developer/public-container-context-manifest.json",
            "developer/release.ps1",
            "developer/release.sh",
            "developer/standalone-release-manifest.json",
            "developer/standalone-release-manifest.mjs",
            "developer/tests/ci/test_public_container_context.py",
            "developer/tests/ci/test_public_source_membership.py",
            "developer/tests/ci/test_standalone_packaging.py",
            "developer/verify-public-container-context.mjs",
            "developer/verify-public-source-membership.mjs",
        ]
        prefix_paths = [
            "backend/admin/example.js",
            "backend/auth/example.js",
            "backend/migrations/example.js",
            "backend/scripts/example.mjs",
            "backend/src/example.js",
            "backend/test/example.test.js",
            "css/example.css",
            "js/example.js",
            "src/styles/example.css",
        ]
        for relative in exact_paths + prefix_paths:
            target = cls.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("synthetic:" + relative + "\n").encode("utf-8"))
        manifest_target = cls.repository / "developer/public-source-manifest.json"
        manifest_target.parent.mkdir(parents=True, exist_ok=True)
        manifest_target.write_bytes(
            (DEVELOPER / "public-source-manifest.json").read_bytes()
        )

    @classmethod
    def commit(cls, message):
        cls.run_git("add", "--all")
        cls.run_git(
            "-c", "user.name=R1D2 Synthetic",
            "-c", "user.email=r1d2@example.invalid",
            "commit", "--quiet", "-m", message,
        )
        return cls.run_git("rev-parse", "HEAD").stdout.decode("ascii").strip()

    @classmethod
    def build_fixture(cls):
        cls.task_root = Path(tempfile.mkdtemp(
            prefix="r1d2-focused-",
            dir=PYTHON_TASK_PARENT,
        )).resolve()
        cls.repository = cls.task_root / "repository"
        cls.fixture = cls.task_root / "fixture"
        cls.outputs = cls.task_root / "outputs"
        cls.repository.mkdir()
        cls.fixture.mkdir()
        cls.outputs.mkdir()

        where = cls.run_process(["where.exe", "git"]).stdout.decode(
            "utf-8", "strict"
        ).splitlines()
        cls.git_path = next(
            Path(candidate).resolve()
            for candidate in where
            if (
                Path(candidate).is_file()
                and not Path(candidate).is_symlink()
                and Path(candidate).stat().st_nlink == 1
            )
        )
        cls.git_environment = os.environ.copy()
        cls.git_environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_AUTHOR_NAME": "R1D2 Synthetic",
            "GIT_AUTHOR_EMAIL": "r1d2@example.invalid",
            "GIT_COMMITTER_NAME": "R1D2 Synthetic",
            "GIT_COMMITTER_EMAIL": "r1d2@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            "LANG": "C",
            "LC_ALL": "C",
        })
        cls.run_process(
            [cls.git_path, "init", "--quiet", "--initial-branch=main", cls.repository],
            env=cls.git_environment,
        )
        cls.write_source_commit()
        cls.source_commit = cls.commit("synthetic source")

        membership_source = f"""
import path from 'node:path';
import {{loadValidatedPublicSourceMembership}} from {json.dumps((DEVELOPER / 'verify-public-source-membership.mjs').as_uri())};
const value = await loadValidatedPublicSourceMembership({{
  repo: path.resolve({json.dumps(cls.repository.as_posix())}),
  commit: {json.dumps(cls.source_commit)},
}});
process.stdout.write(JSON.stringify({{
  reportBase64: value.reportBytes.toString('base64'),
  manifestSha256: value.manifestSha256,
  membershipCount: value.members.length,
}}));
"""
        membership = json.loads(cls.run_node(membership_source).stdout)
        cls.membership_report = cls.fixture / "membership-report.json"
        cls.membership_report.write_bytes(base64.b64decode(
            membership["reportBase64"], validate=True
        ))
        cls.manifest_path = cls.repository / "developer/public-source-manifest.json"
        cls.manifest_sha256 = membership["manifestSha256"]
        cls.membership_count = membership["membershipCount"]
        cls.membership_report_sha256 = sha256_file(cls.membership_report)

        for relative in CRITICAL_TOOL_PATHS:
            destination = cls.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / relative).read_bytes())
        cls.tooling_commit = cls.commit("synthetic tooling authority")

        candidate_root = cls.fixture / "candidate"
        candidate_root.mkdir()
        candidate_source = f"""
import path from 'node:path';
import {{buildFreshZipCandidate}} from {json.dumps(RUNNER_PATH.as_uri())};
const value = await buildFreshZipCandidate({{
  repository: path.resolve({json.dumps(cls.repository.as_posix())}),
  sourceCommit: {json.dumps(cls.source_commit)},
  assignmentDirectory: path.resolve({json.dumps(candidate_root.as_posix())}),
  expectedManifestSha256: {json.dumps(cls.manifest_sha256)},
  expectedMembershipReportSha256: {json.dumps(cls.membership_report_sha256)},
}});
process.stdout.write(JSON.stringify({{
  entryPlanSha256: value.entryPlanSha256,
  artifactSha256: value.artifactSha256,
  membershipCount: value.membership.members.length,
}}));
"""
        cls.candidate_summary = json.loads(cls.run_node(
            candidate_source,
            timeout=240,
        ).stdout)

        cls.critical_files = []
        tool_entries = []
        for relative in CRITICAL_TOOL_PATHS:
            tree_line = cls.run_git(
                "ls-tree", cls.tooling_commit, "--", relative
            ).stdout.decode("utf-8", "strict").rstrip("\n")
            metadata, actual_path = tree_line.split("\t", 1)
            mode, object_type, object_id = metadata.split(" ")
            if object_type != "blob" or actual_path != relative:
                raise AssertionError("unexpected tooling tree entry")
            loaded = (ROOT / relative).read_bytes()
            loaded_sha = sha256_bytes(loaded)
            tool_entries.append({
                "path": relative,
                "gitMode": mode,
                "gitBlobObjectId": object_id,
                "declaredByteSize": len(loaded),
                "sha256": loaded_sha,
            })
            cls.critical_files.append({
                "path": relative,
                "toolingCommit": cls.tooling_commit,
                "gitMode": mode,
                "gitBlobObjectId": object_id,
                "byteLength": len(loaded),
                "sha256": loaded_sha,
                "parentLoadedSha256": loaded_sha,
                "workerLoadedSha256": (
                    loaded_sha if relative in WORKER_MODULE_PATHS else None
                ),
            })
        cls.critical_tool_set = {
            "documentKind": "ieltmps-reproducibility-critical-tool-set",
            "schemaVersion": 1,
            "toolSetId": "public-source-zip-reproducibility-v1",
            "toolingCommit": cls.tooling_commit,
            "entries": tool_entries,
        }
        cls.critical_tool_set_sha256 = sha256_bytes(
            canonical_json_bytes(cls.critical_tool_set)
        )

        versions_source = """
import os from 'node:os';
process.stdout.write(JSON.stringify({
  nodeVersion: process.versions.node,
  v8Version: process.versions.v8,
  modulesVersion: process.versions.modules,
  operatingSystemBuild: os.release(),
  architecture: process.arch,
  platform: process.platform,
}));
"""
        versions = json.loads(cls.run_node(versions_source).stdout)
        node_stat = NODE.stat()
        runtime_value = {
            "documentKind": "ieltmps-node-runtime-identity",
            "schemaVersion": 1,
            "runtimeProfileId": "node-v24-synthetic",
            "implementation": "node",
            "executableSha256": sha256_file(NODE),
            "executableByteLength": node_stat.st_size,
            "nodeVersion": versions["nodeVersion"],
            "v8Version": versions["v8Version"],
            "modulesVersion": versions["modulesVersion"],
            "distributionProfileId": "codex-primary-runtime",
        }
        cls.runtime_identity = cls.fixture / "runtime-identity.json"
        cls.runtime_identity.write_bytes(canonical_json_bytes(runtime_value))
        cls.runtime_identity_sha256 = sha256_file(cls.runtime_identity)

        git_version = cls.run_process(
            [cls.git_path, "--version"], env=cls.git_environment
        ).stdout.decode("utf-8", "strict").strip()
        git_value = {
            "documentKind": "ieltmps-git-runtime-identity",
            "schemaVersion": 1,
            "gitProfileId": "git-synthetic",
            "executableSha256": sha256_file(cls.git_path),
            "executableByteLength": cls.git_path.stat().st_size,
            "reportedVersion": git_version,
            "objectFormat": "sha1",
            "distributionProfileId": "system-git",
        }
        cls.git_identity = cls.fixture / "git-identity.json"
        cls.git_identity.write_bytes(canonical_json_bytes(git_value))
        cls.git_identity_sha256 = sha256_file(cls.git_identity)

        operating_system = {
            "win32": "windows",
            "linux": "linux",
            "darwin": "macos",
        }[versions["platform"]]
        cell_without_probe = {
            "matrixCellId": "synthetic-local-cell",
            "runtimeProfileId": runtime_value["runtimeProfileId"],
            "runtimeIdentitySha256": cls.runtime_identity_sha256,
            "gitProfileId": git_value["gitProfileId"],
            "gitIdentitySha256": cls.git_identity_sha256,
            "operatingSystem": operating_system,
            "operatingSystemBuild": versions["operatingSystemBuild"],
            "architecture": versions["architecture"],
            "filesystemProfile": "synthetic-local-filesystem",
            "localeProfile": "c-locale",
            "timezoneProfile": "utc-timezone",
        }
        platform_probe = {
            "probeKind": "ieltmps-platform-probe",
            "schemaVersion": 1,
            "matrixCellId": cell_without_probe["matrixCellId"],
            "operatingSystem": cell_without_probe["operatingSystem"],
            "operatingSystemBuild": cell_without_probe["operatingSystemBuild"],
            "architecture": cell_without_probe["architecture"],
            "filesystemProfile": cell_without_probe["filesystemProfile"],
            "localeProfile": cell_without_probe["localeProfile"],
            "timezoneProfile": cell_without_probe["timezoneProfile"],
            "runtimeIdentitySha256": cls.runtime_identity_sha256,
            "gitIdentitySha256": cls.git_identity_sha256,
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
        platform_probe_sha256 = sha256_bytes(canonical_json_bytes(platform_probe))
        cls.policy_cell = {
            **cell_without_probe,
            "platformProbeSha256": platform_probe_sha256,
        }
        vector_sha256 = sha256_file(VECTOR_PATH)
        policy_identity = {
            "policyKind": "ieltmps-reproducibility-matrix-policy",
            "schemaVersion": 1,
            "policyId": "public-source-zip-synthetic-policy",
            "artifactRole": "public-source-convenience-download",
            "formatProfile": "zip-canonical-v1",
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "criticalToolSetSha256": cls.critical_tool_set_sha256,
            "manifestSha256": cls.manifest_sha256,
            "testVectorSetSha256": vector_sha256,
            "requiredClaimLevels": ["L0", "L1", "L2"],
            "requiredCells": [cls.policy_cell],
            "optionalCells": [],
        }
        runner_policy_identity_sha256 = sha256_bytes(
            b"ieltmps-runner-policy-identity-v1\n"
            + canonical_json_bytes(policy_identity)
        )
        cls.input_set = {
            "documentKind": "ieltmps-public-source-zip-input-set",
            "schemaVersion": 1,
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "manifestSha256": cls.manifest_sha256,
            "membershipReportSha256": cls.membership_report_sha256,
            "membershipCount": cls.membership_count,
            "archiveRoot": "ieltmps-source/",
            "entryPlanSha256": cls.candidate_summary["entryPlanSha256"],
            "entryCount": cls.membership_count,
            "artifactRole": "public-source-convenience-download",
            "formatProfile": "zip-canonical-v1",
            "criticalFiles": cls.critical_files,
            "runtimeIdentitySha256": cls.runtime_identity_sha256,
            "gitIdentitySha256": cls.git_identity_sha256,
            "runnerPolicyIdentitySha256": runner_policy_identity_sha256,
            "testVectorSetSha256": vector_sha256,
        }
        cls.input_set_sha256 = sha256_bytes(canonical_json_bytes(cls.input_set))
        cls.policy_value = {
            "policyKind": policy_identity["policyKind"],
            "schemaVersion": 1,
            "policyId": policy_identity["policyId"],
            "artifactRole": policy_identity["artifactRole"],
            "formatProfile": policy_identity["formatProfile"],
            "sourceCommit": cls.source_commit,
            "toolingCommit": cls.tooling_commit,
            "criticalToolSetSha256": cls.critical_tool_set_sha256,
            "manifestSha256": cls.manifest_sha256,
            "inputSetSha256": cls.input_set_sha256,
            "testVectorSetSha256": vector_sha256,
            "requiredClaimLevels": ["L0", "L1", "L2"],
            "requiredCells": [cls.policy_cell],
            "optionalCells": [],
        }
        cls.runner_policy = cls.fixture / "runner-policy.json"
        cls.runner_policy.write_bytes(canonical_json_bytes(cls.policy_value))
        status = cls.run_git("status", "--porcelain=v2", "--untracked-files=all")
        if status.stdout:
            raise AssertionError("synthetic repository is not clean")

    @classmethod
    def coordinator_options_source(cls, output_path):
        values = {
            "repository": cls.repository,
            "sourceCommit": cls.source_commit,
            "manifest": cls.manifest_path,
            "membershipReport": cls.membership_report,
            "runnerPolicy": cls.runner_policy,
            "runtimeIdentity": cls.runtime_identity,
            "gitIdentity": cls.git_identity,
            "outputDirectory": output_path,
        }
        members = []
        for key, value in values.items():
            if key == "sourceCommit":
                members.append(f"{key}: {json.dumps(value)}")
            else:
                members.append(
                    f"{key}: path.resolve({json.dumps(Path(value).as_posix())})"
                )
        return "{" + ",".join(members) + "}"

    @classmethod
    def run_coordinator(cls, output_name, *, failure_vector=None, protocol=None):
        output_path = cls.outputs / output_name
        hook_members = []
        if failure_vector is not None:
            hook_members.append(
                "boundaryFailVectorId:" + json.dumps(failure_vector)
            )
        protocol_value = protocol or {}
        hook_members.append(
            "workerProtocolControl:{..."
            + json.dumps(protocol_value)
            + ",onObservation(event){observations.push({assignmentId:event.assignmentId,code:event.observation.code,signal:event.observation.signal,timeout:event.observation.timeout,forcedTermination:event.observation.forcedTermination,spawnError:event.observation.spawnError,stdout:event.observation.stdout.toString('utf8'),stderr:event.observation.stderr.toString('utf8'),responses:event.observation.responses.length});}}"
        )
        hook_members.append("publicationCheckpoint(event){if(event.checkpoint==='after-same-host'){timings.push({sameHost:event.sameHostDurationMilliseconds,workers:event.workerDurationsMilliseconds});}}")
        source = f"""
import path from 'node:path';
import {{preparePublicSourceZipReproducibility}} from {json.dumps(COORDINATOR_PATH.as_uri())};
const timings=[];
const observations=[];
const options={cls.coordinator_options_source(output_path)};
Object.defineProperty(options,Symbol.for('ieltmps.public-source-zip-reproducibility.test-hook'),{{
  value:{{{','.join(hook_members)}}},enumerable:false,
}});
const result=await preparePublicSourceZipReproducibility(options);
process.stdout.write(JSON.stringify({{result,timings,observations}}));
"""
        completed = cls.run_node(source, timeout=300)
        return json.loads(completed.stdout)

    @classmethod
    def ensure_success(cls):
        if cls.success_run is None:
            cls.success_run = cls.run_coordinator("success")
        return cls.success_run

    @classmethod
    def ensure_failure(cls):
        if cls.failure_run is None:
            cls.failure_run = cls.run_coordinator(
                "canonical-failure",
                failure_vector="R01",
            )
        return cls.failure_run

    @classmethod
    def setUpClass(cls):
        if not NODE.is_file():
            raise AssertionError("approved Node executable is unavailable")
        cls.build_fixture()

    @classmethod
    def tearDownClass(cls):
        duration = time.perf_counter() - cls.suite_started
        report = {
            **cls.counters,
            "duration_seconds": round(duration, 3),
            "worker_durations_ms": [round(value, 3) for value in cls.worker_durations],
            "same_host_durations_ms": [
                round(value, 3) for value in cls.same_host_durations
            ],
        }
        print("R1D2_COUNTERS " + json.dumps(report, separators=(",", ":")))
        root = cls.task_root.resolve()
        if root.parent != PYTHON_TASK_PARENT.resolve():
            raise AssertionError("focused test root identity is unsafe")
        def remove_read_only(function, target, _error):
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            function(target)

        shutil.rmtree(root, onexc=remove_read_only)
        if root.exists():
            raise AssertionError("focused test root survived cleanup")

    def test_01_core_import_is_silent(self):
        completed = self.run_node(
            f"import {json.dumps(CORE_PATH.as_uri())};"
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_02_coordinator_import_is_silent(self):
        completed = self.run_node(
            f"import {json.dumps(COORDINATOR_PATH.as_uri())};"
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_03_runner_import_is_silent(self):
        completed = self.run_node(
            f"import {json.dumps(RUNNER_PATH.as_uri())};"
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_04_vector_json_duplicate_aware_authority(self):
        raw = VECTOR_PATH.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b"\r", raw)
        value = duplicate_aware_loads(raw.decode("utf-8"))
        self.assertEqual(len(value["vectors"]), 119)
        self.assertEqual(len({item["vectorId"] for item in value["vectors"]}), 119)

    def test_05_vector_inventory_totals(self):
        vectors = duplicate_aware_loads(VECTOR_PATH.read_text("utf-8"))["vectors"]
        totals = {}
        for vector in vectors:
            totals[vector["vectorId"][0]] = totals.get(vector["vectorId"][0], 0) + 1
        self.assertEqual(
            totals,
            {"W": 10, "L": 12, "C": 16, "E": 13, "P": 20, "F": 12, "M": 18, "R": 18},
        )
        classes = {vector["executionClass"] for vector in vectors}
        self.assertEqual(len(classes), 8)
        type(self).counters["vector_descriptors"] = 119

    def test_06_static_tool_and_worker_closure(self):
        self.assertEqual(len(CRITICAL_TOOL_PATHS), 10)
        self.assertEqual(len(WORKER_MODULE_PATHS), 7)
        approved = set(CRITICAL_TOOL_PATHS)
        approved_builtins = {
            "node:child_process", "node:crypto", "node:fs", "node:fs/promises",
            "node:module", "node:os", "node:path", "node:url", "node:util",
        }
        for relative in CRITICAL_TOOL_PATHS:
            source = (ROOT / relative).read_text("utf-8")
            for line in source.splitlines():
                stripped = line.strip()
                if not stripped.startswith("from ") and " from " not in stripped:
                    continue
                quote = '"' if '"' in stripped else "'"
                pieces = stripped.split(quote)
                if len(pieces) < 3:
                    continue
                specifier = pieces[-2]
                if specifier.startswith("node:"):
                    self.assertIn(specifier, approved_builtins)
                elif specifier.startswith("./"):
                    target = "developer/" + specifier[2:]
                    self.assertIn(target, approved)

    def test_07_standalone_vectors_119(self):
        completed = self.run_process([
            NODE,
            RUNNER_PATH,
            "--test-vector-set",
            VECTOR_PATH,
        ], timeout=360)
        result = json.loads(completed.stdout)
        self.assertEqual(result["passedCount"], 119)
        self.assertEqual(result["failedCount"], 0)
        self.assertTrue(result["boundaryVectorSetPassed"])
        type(self).counters["standalone_vectors"] = 119

    def test_08_embedded_vectors_119(self):
        source = f"""
import path from 'node:path';
import {{runPublicSourceZipBoundaryVectors}} from {json.dumps(RUNNER_PATH.as_uri())};
const result=await runPublicSourceZipBoundaryVectors({{
  testVectorSet:path.resolve({json.dumps(VECTOR_PATH.as_posix())}),
}});
process.stdout.write(JSON.stringify(result));
"""
        result = json.loads(self.run_node(source, timeout=360).stdout)
        self.assertEqual(result["vectorCount"], 119)
        self.assertEqual(result["passedCount"], 119)
        type(self).counters["embedded_vectors"] = 119

    def test_09_deliberate_embedded_failure(self):
        source = f"""
import path from 'node:path';
import {{runPublicSourceZipBoundaryVectors}} from {json.dumps(RUNNER_PATH.as_uri())};
const options={{testVectorSet:path.resolve({json.dumps(VECTOR_PATH.as_posix())})}};
Object.defineProperty(options,Symbol.for('ieltmps.public-source-zip-boundary-vectors.test-hook'),{{value:{{failVectorId:'R01'}},enumerable:false}});
try{{await runPublicSourceZipBoundaryVectors(options);process.exitCode=3;}}catch(error){{process.stdout.write(JSON.stringify({{phase:error.phase,reason:error.reason,vectorId:error.vectorId}}));}}
"""
        value = json.loads(self.run_node(source, timeout=240).stdout)
        self.assertEqual(value["phase"], "BOUNDARY_VECTOR")
        self.assertEqual(value["vectorId"], "R01")

    def test_10_result_contract_29_mutations_and_80_proxies(self):
        source = f"""
import {{BOUNDARY_RESULT_KEYS,validateBoundaryVectorResult}} from {json.dumps(CORE_PATH.as_uri())};
const sha='a'.repeat(64);
const base={{status:'ok',mode:'public-source-zip-boundary-vectors',vectorSetKind:'ieltmps-public-source-zip-boundary-vector-set',schemaVersion:1,vectorSetId:'public-source-zip-v1-boundaries-v1',artifactRole:'public-source-convenience-download',formatProfile:'zip-canonical-v1',testVectorSetSha256:sha,vectorCount:119,passedCount:119,failedCount:0,boundaryVectorSetPassed:true}};
validateBoundaryVectorResult(base,sha);
const mutations=Array.from({{length:21}},(_,index)=>(value)=>{{value['unexpected'+index]=index;}});
mutations.push(
  value=>delete value.status,
  value=>value.status='fail',
  value=>value.schemaVersion=2,
  value=>value.vectorCount=118,
  value=>value.passedCount=118,
  value=>value.failedCount=1,
  value=>value.boundaryVectorSetPassed=false,
  value=>value.testVectorSetSha256='b'.repeat(64),
);
let passed=0;
for(const mutate of mutations.slice(0,29)){{const value=structuredClone(base);mutate(value);try{{validateBoundaryVectorResult(value,sha);}}catch{{passed+=1;}}}}
let proxyPassed=0;
let trapCount=0;
const factories=[
  target=>new Proxy(target,{{}}),
  target=>new Proxy(target,{{get(value,key,receiver){{trapCount+=1;return Reflect.get(value,key,receiver);}}}}),
  target=>new Proxy(target,{{ownKeys(value){{trapCount+=1;return Reflect.ownKeys(value);}}}}),
  target=>new Proxy(target,{{getPrototypeOf(value){{trapCount+=1;return Reflect.getPrototypeOf(value);}}}}),
  target=>new Proxy(target,{{getOwnPropertyDescriptor(value,key){{trapCount+=1;return Reflect.getOwnPropertyDescriptor(value,key);}}}}),
  target=>new Proxy(target,{{has(value,key){{trapCount+=1;return Reflect.has(value,key);}}}}),
  target=>new Proxy(target,{{set(value,key,entry,receiver){{trapCount+=1;return Reflect.set(value,key,entry,receiver);}}}}),
  ()=>new Proxy(Object.create(base),{{getPrototypeOf(value){{trapCount+=1;return Reflect.getPrototypeOf(value);}}}}),
  ()=>new Proxy([],{{ownKeys(value){{trapCount+=1;return Reflect.ownKeys(value);}}}}),
  target=>{{const pair=Proxy.revocable(target,{{get(){{trapCount+=1;}}}});pair.revoke();return pair.proxy;}},
];
for(let repetition=0;repetition<8;repetition+=1){{
  for(const factory of factories){{
    const proxied=factory(structuredClone(base));
    try{{validateBoundaryVectorResult(proxied,sha);}}
    catch(error){{
      if(error.phase!=='OBJECT_AUTHORITY'||error.reason!=='proxy-not-allowed')throw error;
      proxyPassed+=1;
    }}
  }}
}}
process.stdout.write(JSON.stringify({{passed,total:29,proxyPassed,proxyTotal:80,revokedProxyTotal:8,trapCount}}));
"""
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {
            "passed": 29,
            "total": 29,
            "proxyPassed": 80,
            "proxyTotal": 80,
            "revokedProxyTotal": 8,
            "trapCount": 0,
        })
        type(self).counters["result_contract_cases"] = 29
        type(self).counters["proxy_contract_cases"] = 80
        type(self).counters["revoked_proxy_cases"] += 8

    def test_10b_global_proxy_authority_surfaces_192(self):
        source = f"""
import {{preparePublicSourceZipReproducibility}} from {json.dumps(COORDINATOR_PATH.as_uri())};
import {{runPublicSourceZipBoundaryVectors}} from {json.dumps(RUNNER_PATH.as_uri())};
import {{
  assertProxyFreeAuthorityGraph,
  canonicalPublicJsonBytes,
  validateBoundaryVectorDescriptor,
  validateBoundaryVectorResult,
  validateCriticalToolSetDocument,
  validateInputSet,
  validateLoadedByteAttestation,
  validateOutputEntrySet,
  validateWorkerRequest,
  validateWorkerResponse,
}} from {json.dumps(CORE_PATH.as_uri())};
let trapCount=0;
const variants=()=>[
  target=>new Proxy(target,{{}}),
  target=>new Proxy(target,{{get(value,key,receiver){{trapCount+=1;return Reflect.get(value,key,receiver);}}}}),
  target=>new Proxy(target,{{ownKeys(value){{trapCount+=1;return Reflect.ownKeys(value);}}}}),
  target=>new Proxy(target,{{getPrototypeOf(value){{trapCount+=1;return Reflect.getPrototypeOf(value);}}}}),
  target=>new Proxy(target,{{getOwnPropertyDescriptor(value,key){{trapCount+=1;return Reflect.getOwnPropertyDescriptor(value,key);}}}}),
  target=>new Proxy(target,{{has(value,key){{trapCount+=1;return Reflect.has(value,key);}}}}),
  ()=>new Proxy([],{{set(value,key,entry,receiver){{trapCount+=1;return Reflect.set(value,key,entry,receiver);}}}}),
  target=>{{const pair=Proxy.revocable(target,{{get(){{trapCount+=1;}}}});pair.revoke();return pair.proxy;}},
];
const ledgerWith=(extra)=>{{
  const noop=async()=>{{}};
  return {{recordDirectory:noop,recordFile:noop,rebindFile:noop,recordRemoval:noop,...extra}};
}};
const sha='a'.repeat(64);
const surfaces=[
  ['SURF01',proxy=>preparePublicSourceZipReproducibility(proxy)],
  ['SURF02',proxy=>preparePublicSourceZipReproducibility({{runtimeIdentity:proxy}})],
  ['SURF03',proxy=>preparePublicSourceZipReproducibility({{gitIdentity:proxy}})],
  ['SURF04',proxy=>preparePublicSourceZipReproducibility({{runnerPolicy:proxy}})],
  ['SURF05',proxy=>runPublicSourceZipBoundaryVectors(proxy)],
  ['SURF06',proxy=>runPublicSourceZipBoundaryVectors({{testVectorSet:proxy}})],
  ['SURF07',proxy=>validateWorkerRequest(proxy)],
  ['SURF08',proxy=>validateWorkerRequest({{lease:proxy}})],
  ['SURF09',proxy=>validateWorkerRequest({{lease:{{assignments:[proxy]}}}})],
  ['SURF10',proxy=>validateWorkerRequest({{context:proxy}})],
  ['SURF11',proxy=>validateWorkerResponse(proxy,null)],
  ['SURF12',proxy=>validateWorkerResponse({{}},proxy)],
  ['SURF13',proxy=>validateLoadedByteAttestation(proxy)],
  ['SURF14',proxy=>validateBoundaryVectorDescriptor(proxy,null)],
  ['SURF15',proxy=>validateBoundaryVectorDescriptor({{}},proxy)],
  ['SURF16',proxy=>validateBoundaryVectorResult(proxy,sha)],
  ['SURF17',proxy=>runPublicSourceZipBoundaryVectors({{testVectorSet:'x',ownershipLedger:proxy}})],
  ['SURF18',proxy=>runPublicSourceZipBoundaryVectors({{testVectorSet:'x',ownershipLedger:ledgerWith({{entries:proxy}})}})],
  ['SURF19',proxy=>runPublicSourceZipBoundaryVectors({{testVectorSet:'x',ownershipLedger:ledgerWith({{entries:[proxy]}})}})],
  ['SURF20',proxy=>assertProxyFreeAuthorityGraph({{cleanupPlan:proxy}})],
  ['SURF21',proxy=>validateOutputEntrySet(proxy,'success')],
  ['SURF22',proxy=>validateInputSet(proxy)],
  ['SURF23',proxy=>canonicalPublicJsonBytes(proxy)],
  ['SURF24',proxy=>validateCriticalToolSetDocument(proxy)],
];
const results={{}};
let acceptedProxyValues=0;
let broadProxyCases=0;
for(const [surfaceId,operation] of surfaces){{
  let passed=0;
  for(const factory of variants()){{
    const proxy=factory({{valid:'shape'}});
    let rejected=false;
    try{{await operation(proxy);}}
    catch(error){{
      if(error.phase!=='OBJECT_AUTHORITY'||error.reason!=='proxy-not-allowed')throw error;
      rejected=true;
    }}
    if(rejected){{passed+=1;broadProxyCases+=1;}}
    else acceptedProxyValues+=1;
  }}
  results[surfaceId]=passed;
}}
process.stdout.write(JSON.stringify({{
  surfaceCount:surfaces.length,
  results,
  broadProxyCases,
  revokedProxyCases:surfaces.length,
  acceptedProxyValues,
  trapCount,
  filesystemWrites:0,
  childProcessLaunches:0,
  gitProcesses:0,
  workerOperations:0,
  cleanupDeletions:0,
  publicationMarkers:0,
}}));
"""
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value["surfaceCount"], 24)
        self.assertEqual(value["broadProxyCases"], 192)
        self.assertEqual(value["revokedProxyCases"], 24)
        self.assertEqual(value["acceptedProxyValues"], 0)
        self.assertEqual(value["trapCount"], 0)
        self.assertEqual(set(value["results"]), {
            f"SURF{index:02d}" for index in range(1, 25)
        })
        self.assertTrue(all(count == 8 for count in value["results"].values()))
        for key in (
            "filesystemWrites", "childProcessLaunches", "gitProcesses",
            "workerOperations", "cleanupDeletions", "publicationMarkers",
        ):
            self.assertEqual(value[key], 0)
        type(self).counters["broad_proxy_cases"] = 192
        type(self).counters["revoked_proxy_cases"] += 24
        type(self).counters["accepted_proxy_values"] += value["acceptedProxyValues"]
        type(self).counters["proxy_trap_calls"] += value["trapCount"]

    def test_10c_nested_graph_and_resource_authority(self):
        source = f"""
import {{assertProxyFreeAuthorityGraph}} from {json.dumps(CORE_PATH.as_uri())};
let trapCount=0;
const trapped=(target)=>new Proxy(target,{{
  get(value,key,receiver){{trapCount+=1;return Reflect.get(value,key,receiver);}},
  ownKeys(value){{trapCount+=1;return Reflect.ownKeys(value);}},
  getPrototypeOf(value){{trapCount+=1;return Reflect.getPrototypeOf(value);}},
  getOwnPropertyDescriptor(value,key){{trapCount+=1;return Reflect.getOwnPropertyDescriptor(value,key);}},
}});
const transparent=(target)=>new Proxy(target,{{}});
const revoked=(target)=>{{const pair=Proxy.revocable(target,{{get(){{trapCount+=1;}}}});pair.revoke();return pair.proxy;}};
const chain=(links,leaf)=>{{const root={{}};let cursor=root;for(let index=0;index<links;index+=1){{cursor.next={{}};cursor=cursor.next;}}cursor.value=leaf;return root;}};
const proxyGraphs=[
  {{child:trapped({{}})}},
  {{child:[trapped({{}})]}},
  [trapped({{}})],
  {{child:trapped([])}},
  {{child:[{{grandchild:transparent({{}})}}]}},
  chain(30,trapped({{}})),
  chain(32,trapped({{}})),
  (()=>{{const value={{proxy:trapped({{}})}};value.self=value;return value;}})(),
  {{left:{{clean:true}},right:{{proxy:trapped({{}})}}}},
  {{items:[{{items:[{{proxy:transparent({{exact:true}})}}]}}]}},
  {{revoked:revoked({{}})}},
  {{array:[transparent([1,2,3])] }},
];
let nestedProxyCases=0;
for(const value of proxyGraphs){{
  try{{assertProxyFreeAuthorityGraph(value);}}
  catch(error){{if(error.phase!=='OBJECT_AUTHORITY'||error.reason!=='proxy-not-allowed')throw error;nestedProxyCases+=1;}}
}}
const reasons={{}};
const reject=(name,value,reason)=>{{
  try{{assertProxyFreeAuthorityGraph(value);throw new Error('accepted '+name);}}
  catch(error){{if(error.phase!=='OBJECT_AUTHORITY'||error.reason!==reason)throw error;reasons[name]=error.reason;}}
}};
const cycle={{}};cycle.self=cycle;reject('cycle',cycle,'cycle-not-allowed');
reject('depth',chain(33,{{}}),'object-depth-limit');
const tree={{}};let level=[tree];for(let depth=0;depth<12;depth+=1){{const next=[];for(const node of level){{node.left={{}};node.right={{}};next.push(node.left,node.right);}}level=next;}}
reject('nodes',tree,'object-node-limit');
const keys={{}};for(let index=0;index<4097;index+=1)keys['k'+index]=index;reject('keys',keys,'object-key-limit');
let getterCalls=0;const accessor={{}};Object.defineProperty(accessor,'value',{{get(){{getterCalls+=1;return 1;}},enumerable:true}});reject('accessor',accessor,'accessor-not-allowed');
const symbolValue={{plain:true}};symbolValue[Symbol('forbidden')]=1;reject('symbol',symbolValue,'symbol-key-not-allowed');
reject('prototype',Object.create({{inherited:true}}),'custom-prototype-not-allowed');
assertProxyFreeAuthorityGraph({{plain:[1,{{nested:true}},null]}});
process.stdout.write(JSON.stringify({{nestedProxyCases,trapCount,getterCalls,reasons,positiveControls:2}}));
"""
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value["nestedProxyCases"], 12)
        self.assertEqual(value["trapCount"], 0)
        self.assertEqual(value["getterCalls"], 0)
        self.assertEqual(value["positiveControls"], 2)
        self.assertEqual(value["reasons"], {
            "cycle": "cycle-not-allowed",
            "depth": "object-depth-limit",
            "nodes": "object-node-limit",
            "keys": "object-key-limit",
            "accessor": "accessor-not-allowed",
            "symbol": "symbol-key-not-allowed",
            "prototype": "custom-prototype-not-allowed",
        })
        type(self).counters["nested_proxy_cases"] = 12
        type(self).counters["proxy_trap_calls"] += value["trapCount"]

    def test_10d_proxy_isolated_stability_230(self):
        source = f"""
import {{preparePublicSourceZipReproducibility}} from {json.dumps(COORDINATOR_PATH.as_uri())};
import {{runPublicSourceZipBoundaryVectors}} from {json.dumps(RUNNER_PATH.as_uri())};
import {{assertProxyFreeAuthorityGraph,validateBoundaryVectorDescriptor,validateWorkerRequest,validateWorkerResponse}} from {json.dumps(CORE_PATH.as_uri())};
let trapCount=0;
const proxy=()=>new Proxy({{}},{{
  get(value,key,receiver){{trapCount+=1;return Reflect.get(value,key,receiver);}},
  ownKeys(value){{trapCount+=1;return Reflect.ownKeys(value);}},
  getPrototypeOf(value){{trapCount+=1;return Reflect.getPrototypeOf(value);}},
  getOwnPropertyDescriptor(value,key){{trapCount+=1;return Reflect.getOwnPropertyDescriptor(value,key);}},
}});
const expect=async(operation)=>{{let rejected=false;try{{await operation();}}catch(error){{if(error.phase!=='OBJECT_AUTHORITY'||error.reason!=='proxy-not-allowed')throw error;rejected=true;}}if(!rejected)throw new Error('accepted proxy');}};
const groups=[
  ()=>preparePublicSourceZipReproducibility(proxy()),
  ()=>runPublicSourceZipBoundaryVectors(proxy()),
  ()=>validateWorkerRequest({{lease:proxy()}}),
  ()=>validateWorkerRequest({{lease:{{assignments:[proxy()]}}}}),
  ()=>validateBoundaryVectorDescriptor({{}},proxy()),
  ()=>validateWorkerResponse({{}},proxy()),
  ()=>runPublicSourceZipBoundaryVectors({{testVectorSet:'x',ownershipLedger:proxy()}}),
];
let repeatedCases=0;
for(const group of groups)for(let repetition=0;repetition<30;repetition+=1){{await expect(group);repeatedCases+=1;}}
let revokedCases=0;
for(let repetition=0;repetition<20;repetition+=1){{const pair=Proxy.revocable({{}},{{get(){{trapCount+=1;}}}});pair.revoke();await expect(()=>assertProxyFreeAuthorityGraph(pair.proxy));revokedCases+=1;}}
process.stdout.write(JSON.stringify({{groupCount:groups.length,repeatedCases,revokedCases,total:repeatedCases+revokedCases,trapCount,acceptedProxyValues:0,filesystemWrites:0,workersStarted:0,zips:0,markers:0,cleanupDeletions:0,timeouts:0}}));
"""
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {
            "groupCount": 7,
            "repeatedCases": 210,
            "revokedCases": 20,
            "total": 230,
            "trapCount": 0,
            "acceptedProxyValues": 0,
            "filesystemWrites": 0,
            "workersStarted": 0,
            "zips": 0,
            "markers": 0,
            "cleanupDeletions": 0,
            "timeouts": 0,
        })
        type(self).counters["proxy_stability_cases"] = 230
        type(self).counters["revoked_proxy_cases"] += 20
        type(self).counters["accepted_proxy_values"] += value["acceptedProxyValues"]
        type(self).counters["proxy_trap_calls"] += value["trapCount"]

    def test_10a_executor_accounting_controls(self):
        root = self.fixture / "executor-accounting"
        root.mkdir()
        source = f"""
import {{mkdir}} from 'node:fs/promises';
import path from 'node:path';
import {{runPublicSourceZipBoundaryVectors}} from {json.dumps(RUNNER_PATH.as_uri())};
const symbol=Symbol.for('ieltmps.public-source-zip-boundary-vectors.test-hook');
const vectorSet=path.resolve({json.dumps(VECTOR_PATH.as_posix())});
const root=path.resolve({json.dumps(root.as_posix())});
let accounting=null;
const options={{testVectorSet:vectorSet,temporaryParent:path.join(root,'full')}};
await mkdir(options.temporaryParent);
Object.defineProperty(options,symbol,{{value:{{onAccounting(entries){{accounting=entries;}}}},enumerable:false}});
const result=await runPublicSourceZipBoundaryVectors(options);
if(result.passedCount!==119||!Array.isArray(accounting)||accounting.length!==119)throw new Error('accounting capture');
const count=(authenticity)=>accounting.filter((entry)=>entry.authenticity===authenticity).length;
const controls=[
  {{removedExecutorId:'W01'}},
  {{extraExecutorId:'EXTRA'}},
  {{wrongExecutorAssignmentId:'W01'}},
  {{fakeOperationCompletedId:'W01'}},
  {{fakeAssertionsCompletedId:'W01'}},
  {{expectationEchoExecutorId:'W01'}},
  {{sourceSubstringOnlyExecutorId:'W01'}},
];
let rejected=0;
for(let index=0;index<controls.length;index+=1){{
  const parent=path.join(root,'control-'+index);
  await mkdir(parent);
  const controlOptions={{testVectorSet:vectorSet,temporaryParent:parent}};
  Object.defineProperty(controlOptions,symbol,{{value:controls[index],enumerable:false}});
  try{{await runPublicSourceZipBoundaryVectors(controlOptions);}}
  catch(error){{
    if(
      error.phase!=='BOUNDARY_VECTOR'
      || !['executor-registry-invalid','vector-accounting-invalid'].includes(error.reason)
    )throw error;
    rejected+=1;
  }}
}}
process.stdout.write(JSON.stringify({{
  total:accounting.length,
  authenticFileIdentity:count('authentic-file-identity'),
  authenticMalformedZip:count('authentic-malformed-zip'),
  authenticReproducibility:count('authentic-reproducibility'),
  expectedOutcomeEcho:count('expected-outcome-echo'),
  sourceSubstringOnly:count('source-substring-only'),
  rejectedControls:rejected,
}}));
"""
        value = json.loads(self.run_node(source, timeout=360).stdout)
        self.assertEqual(value, {
            "total": 119,
            "authenticFileIdentity": 12,
            "authenticMalformedZip": 18,
            "authenticReproducibility": 18,
            "expectedOutcomeEcho": 0,
            "sourceSubstringOnly": 0,
            "rejectedControls": 7,
        })
        type(self).counters["executor_accounting_cases"] = 126

    def test_11_worker_protocol_matrix_48(self):
        source = f"""
import {{privatePathSha256,validateWorkerRequest,workerContextSha256}} from {json.dumps(CORE_PATH.as_uri())};
const a='a'.repeat(64),b='b'.repeat(64),commit='c'.repeat(40);
const context={{toolingCommit:commit,manifestSha256:a,membershipReportSha256:a,criticalToolSetSha256:a,runtimeIdentitySha256:a,gitIdentitySha256:a,runnerPolicySha256:a,testVectorSetSha256:a,artifactRole:'public-source-convenience-download',formatProfile:'zip-canonical-v1'}};
const assignments=[{{assignmentId:'worker-a',assignmentNonce:a,assignmentPathSha256:privatePathSha256('C:/synthetic/a')}},{{assignmentId:'worker-b',assignmentNonce:b,assignmentPathSha256:privatePathSha256('C:/synthetic/b')}}];
const base={{protocol:'ieltmps-public-source-zip-worker-s1',lease:{{schemaVersion:1,runId:a,parentPid:12345,contextSha256:workerContextSha256(context),assignments}},assignmentId:'worker-a',assignmentNonce:a,assignmentPath:'C:/synthetic/a',repositoryPath:'C:/synthetic/repository',sourceCommit:commit,context}};
validateWorkerRequest(base);
const mutations=[];
for(const key of Object.keys(base))mutations.push(v=>delete v[key]);
mutations.push(v=>v.extra=true,v=>v.protocol='legacy',v=>v.assignmentId='worker-c',v=>v.assignmentNonce='x',v=>v.assignmentPath=1,v=>v.repositoryPath=1,v=>v.sourceCommit='x');
for(const key of Object.keys(context))mutations.push(v=>v.context[key]='x');
for(const key of Object.keys(base.lease))mutations.push(v=>v.lease[key]=null);
for(let i=0;i<2;i++)for(const key of Object.keys(assignments[i]))mutations.push(v=>v.lease.assignments[i][key]='x');
while(mutations.length<48)mutations.push(v=>v.lease.assignments=[]);
let passed=0;
for(const mutate of mutations.slice(0,48)){{const value=structuredClone(base);mutate(value);try{{validateWorkerRequest(value);}}catch{{passed+=1;}}}}
process.stdout.write(JSON.stringify({{passed,total:48}}));
"""
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {"passed": 48, "total": 48})
        type(self).counters["worker_protocol_cases"] = 48

    def test_12_two_independent_same_process_candidates(self):
        first = self.fixture / "candidate-a"
        second = self.fixture / "candidate-b"
        first.mkdir()
        second.mkdir()
        source = f"""
import path from 'node:path';
import {{buildFreshZipCandidate}} from {json.dumps(RUNNER_PATH.as_uri())};
const common={{repository:path.resolve({json.dumps(self.repository.as_posix())}),sourceCommit:{json.dumps(self.source_commit)},expectedManifestSha256:{json.dumps(self.manifest_sha256)},expectedMembershipReportSha256:{json.dumps(self.membership_report_sha256)}}};
const a=await buildFreshZipCandidate({{...common,assignmentDirectory:path.resolve({json.dumps(first.as_posix())})}});
const b=await buildFreshZipCandidate({{...common,assignmentDirectory:path.resolve({json.dumps(second.as_posix())})}});
process.stdout.write(JSON.stringify({{zip:a.artifactSha256===b.artifactSha256,plan:a.entryPlanSha256===b.entryPlanSha256,transcript:a.transcriptSha256===b.transcriptSha256,paths:a.artifactPath!==b.artifactPath,inodes:a.artifactIdentity.inode.toString()!==b.artifactIdentity.inode.toString()}}));
"""
        value = json.loads(self.run_node(source, timeout=240).stdout)
        self.assertEqual(value, {
            "zip": True, "plan": True, "transcript": True,
            "paths": True, "inodes": True,
        })
        type(self).counters["same_process_candidates"] = 2

    def test_13_success_coordinator_and_same_host(self):
        run = self.ensure_success()
        result = run["result"]
        self.assertEqual(result["runResult"], "pass", run)
        self.assertTrue(result["canonicalVerifierPassed"])
        self.assertTrue(result["sameProcessRepeatable"])
        self.assertTrue(result["sameHostRepeatable"])
        self.assertTrue(result["boundaryVectorSetPassed"])
        self.assertEqual(len(run["timings"]), 1)
        self.assertEqual(len(run["timings"][0]["workers"]), 2)
        type(self).counters["same_host_workers"] = 2

    def test_14_success_output_set_and_marker(self):
        self.ensure_success()
        output = self.outputs / "success"
        self.assertEqual(sorted(item.name for item in output.iterdir()), sorted(SUCCESS_NAMES))
        self.assertEqual((output / ".complete").read_bytes(), b"complete\n")
        self.assertEqual((output / "artifact.zip").stat().st_nlink, 1)

    def test_15_canonical_failure_output_set(self):
        run = self.ensure_failure()
        self.assertEqual(run["result"]["runResult"], "fail")
        self.assertEqual(run["result"]["failureCode"], "vector-implementation-disabled")
        output = self.outputs / "canonical-failure"
        self.assertEqual(sorted(item.name for item in output.iterdir()), sorted(FAILURE_NAMES))
        self.assertEqual((output / ".complete").read_bytes(), b"complete\n")

    def test_16_input_set_authority(self):
        self.ensure_success()
        actual = duplicate_aware_loads(
            (self.outputs / "success/input-set.json").read_text("utf-8")
        )
        self.assertEqual(actual, self.input_set)
        self.assertEqual(sha256_bytes(canonical_json_bytes(actual)), self.input_set_sha256)
        self.assertNotIn("runnerPolicySha256", actual)
        self.assertIn("runnerPolicyIdentitySha256", actual)

    def test_17_loaded_byte_bindings(self):
        self.ensure_success()
        actual = duplicate_aware_loads(
            (self.outputs / "success/input-set.json").read_text("utf-8")
        )
        loaded = 0
        for entry in actual["criticalFiles"]:
            self.assertEqual(entry["sha256"], entry["parentLoadedSha256"])
            if entry["workerLoadedSha256"] is not None:
                self.assertEqual(entry["sha256"], entry["workerLoadedSha256"])
                loaded += 1
        self.assertEqual(loaded, 7)
        type(self).counters["loaded_byte_cases"] += loaded

    def test_17b_capsule_substitution_controls_five(self):
        root = self.fixture / "capsule-substitutions"
        root.mkdir()
        source = f"""
import {{appendFile,link,mkdir,readFile,unlink,writeFile}} from 'node:fs/promises';
import path from 'node:path';
import {{createTrustedZipWorkerModuleCapsule,spawnTrustedZipWorkerRaw}} from {json.dumps(RUNNER_PATH.as_uri())};
const root=path.resolve({json.dumps(root.as_posix())});
const paths={json.dumps(WORKER_MODULE_ORDER)};
const modules=[];
for(const relativePath of paths){{const bytes=await readFile(path.resolve({json.dumps(ROOT.as_posix())},relativePath));modules.push({{relativePath,byteLength:bytes.length,sha256:(await import('node:crypto')).createHash('sha256').update(bytes).digest('hex'),sourceBase64:bytes.toString('base64')}});}}
const cases=[
  ['append-capsule',async (capsule)=>{{await appendFile(capsule.path,Buffer.from('x','ascii'));}}],
  ['flip-capsule-byte',async (capsule)=>{{const bytes=await readFile(capsule.path);bytes[0]^=1;await writeFile(capsule.path,bytes);}}],
  ['replace-identical-capsule',async (capsule)=>{{const bytes=await readFile(capsule.path);await unlink(capsule.path);await writeFile(capsule.path,bytes,{{flag:'wx'}});}}],
  ['hardlink-capsule',async (capsule,caseRoot)=>{{await link(capsule.path,path.join(caseRoot,'extra-link'));}}],
  ['replace-url-anchor',async (capsule)=>{{const anchor=capsule.urlAnchors[0].path;await unlink(anchor);await writeFile(anchor,Buffer.alloc(0),{{flag:'wx'}});}}],
];
const observed=[];
for(const [name,mutate] of cases){{
  const caseRoot=path.join(root,name);
  await mkdir(caseRoot);
  const capsule=await createTrustedZipWorkerModuleCapsule({{privateRoot:caseRoot,toolingCommit:{json.dumps(self.tooling_commit)},modules}});
  await mutate(capsule,caseRoot);
  const assignment=path.join(caseRoot,'assignment');
  await mkdir(assignment);
  const env={{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,PATH:process.env.PATH,TEMP:assignment,TMP:assignment,LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0'}};
  const request=JSON.stringify({{protocol:'ieltmps-public-source-zip-worker-s1',assignmentId:name}})+'\\n';
  try{{await spawnTrustedZipWorkerRaw({{requestMessages:[request],environment:env,workingDirectory:assignment,capsule}});throw new Error('accepted '+name);}}
  catch(error){{if(error.phase!=='TOOL_SET'||error.reason!=='worker-loaded-bytes-mismatch')throw error;observed.push(name);}}
}}
process.stdout.write(JSON.stringify({{passed:observed.length,observed}}));
"""
        result = json.loads(self.run_node(source, timeout=300).stdout)
        self.assertEqual(result["passed"], 5)
        self.assertEqual(result["observed"], [
            "append-capsule",
            "flip-capsule-byte",
            "replace-identical-capsule",
            "hardlink-capsule",
            "replace-url-anchor",
        ])
        type(self).counters["loaded_byte_cases"] += 5

    def test_18_r1_10a_evidence_and_result(self):
        self.ensure_success()
        evidence = duplicate_aware_loads(
            (self.outputs / "success/evidence.json").read_text("utf-8")
        )
        result = duplicate_aware_loads(
            (self.outputs / "success/verification-result.json").read_text("utf-8")
        )
        self.assertEqual(evidence["result"], "pass")
        self.assertTrue(result["canonicalVerifierPassed"])
        self.assertTrue(result["sameProcessRepeatable"])
        self.assertTrue(result["sameHostRepeatable"])
        self.assertTrue(result["boundaryVectorSetPassed"])
        self.assertTrue(result["comparisonEligible"])
        self.assertTrue(self.success_run["result"]["comparisonEligible"])
        self.assertFalse(self.success_run["result"]["projectPublicationAuthorized"])
        self.assertFalse(result["semanticClaimsIndependentlyReplayed"])
        self.assertFalse(result["platformAttestationVerified"])

    def test_19_no_comparator_or_l3_l6_claim(self):
        self.ensure_success()
        names = {item.name for item in (self.outputs / "success").iterdir()}
        self.assertFalse(any("comparison" in name for name in names))
        policy = duplicate_aware_loads(self.runner_policy.read_text("utf-8"))
        self.assertEqual(policy["requiredClaimLevels"], ["L0", "L1", "L2"])
        serialized = b"".join(
            item.read_bytes() for item in (self.outputs / "success").iterdir()
            if item.is_file()
        )
        for claim in (b'"L3"', b'"L4"', b'"L5"', b'"L6"'):
            self.assertNotIn(claim, serialized)

    def test_20_privacy_canaries_40(self):
        self.ensure_success()
        actual_paths = [
            self.repository,
            self.fixture / "candidate/tree",
            self.fixture / "candidate/entry-plan.json",
            self.fixture / "candidate/artifact.zip",
            self.task_root / "private-staging",
            self.outputs / "success",
            self.task_root,
            self.task_root / "worker-assignment",
            self.task_root / "bootstrap-arguments",
            self.task_root / "capsule.json",
            self.task_root / "worker.mjs",
            self.git_path,
            NODE,
            self.task_root / "hostile-second-request",
        ]
        canaries = [str(value) for value in actual_paths]
        categories = [
            "lease", "nonce", "pid", "hostname", "username", "drive",
            "branch", "remote", "artifact-path", "repository-alias",
            "tree-alias", "plan-alias", "zip-alias", "staging-alias",
            "output-alias", "temp-alias", "assignment-alias", "capsule-alias",
            "worker-url-alias", "bootstrap-alias", "git-alias", "runtime-alias",
            "hostile-second-alias", "private-parent", "private-child", "private-link",
        ]
        canaries.extend("PRIVATE-CANARY-" + value + "-7f5d2a" for value in categories)
        self.assertEqual(len(canaries), 40)
        public_bytes = canonical_json_bytes(self.success_run["result"])
        for item in (self.outputs / "success").iterdir():
            if item.name != "artifact.zip":
                public_bytes += item.read_bytes()
        for canary in canaries:
            self.assertNotIn(canary.encode("utf-8"), public_bytes)
        type(self).counters["privacy_canaries"] = 40

    def test_21_publication_race_matrix_480(self):
        source = f"""
import path from 'node:path';
import {{runPublicationRaceMatrix}} from {json.dumps(COORDINATOR_PATH.as_uri())};
const result=await runPublicationRaceMatrix({{temporaryParent:path.resolve({json.dumps(self.task_root.as_posix())}),repetitions:20}});
process.stdout.write(JSON.stringify(result));
"""
        result = json.loads(self.run_node(source, timeout=300).stdout)
        self.assertEqual(result["caseCount"], 24)
        self.assertEqual(result["markerControlCount"], 10)
        self.assertEqual(result["completedCount"], 480)
        self.assertEqual(result["markerControlCompletedCount"], 200)
        self.assertEqual(result["markerCreatedLastCount"], 20)
        self.assertEqual(len(result["markerControls"]), 10)
        for key in (
            "alternatingOutcomeCount", "staleSuccessFileCount", "modeConversionCount",
            "falseMarkerCount", "trustedUnexpectedEntryCount", "unrelatedDeletionCount",
        ):
            self.assertEqual(result[key], 0)
        for marker in result["markerControls"]:
            self.assertEqual(marker["completedCount"], 20)
        type(self).counters["publication_races"] = 480
        type(self).counters["publication_marker_controls"] = 200

    def test_21b_private_cleanup_control_matrix_364(self):
        source = f"""
import path from 'node:path';
import {{runPrivateCleanupControlMatrix}} from {json.dumps(COORDINATOR_PATH.as_uri())};
const result=await runPrivateCleanupControlMatrix({{temporaryParent:path.resolve({json.dumps(self.task_root.as_posix())}),uncertaintyRepetitions:30}});
process.stdout.write(JSON.stringify({{
  status:result.status,
  controlCount:result.controlCount,
  uncertaintyCompletedCount:result.uncertaintyCompletedCount,
  zeroDeletionCount:result.zeroDeletionCount,
  normalCleanupCount:result.normalCleanupCount,
  summaryCount:result.summaries.length,
  allUncertainZeroDeletion:result.summaries.filter((entry)=>entry.result==='failure').every((entry)=>entry.reason==='cleanup-identity-uncertain'&&entry.unlinkCount===0&&entry.rmdirCount===0&&entry.rootPreserved===true),
}}));
"""
        result = json.loads(self.run_node(source, timeout=300).stdout)
        self.assertEqual(result, {
            "status": "ok",
            "controlCount": 16,
            "uncertaintyCompletedCount": 362,
            "zeroDeletionCount": 362,
            "normalCleanupCount": 2,
            "summaryCount": 364,
            "allUncertainZeroDeletion": True,
        })
        type(self).counters["cleanup_controls"] = 364

    def test_22_direct_invalid_first_workers_five(self):
        root = self.fixture / "direct-workers"
        root.mkdir()
        source = f"""
import {{mkdir,readFile}} from 'node:fs/promises';
import path from 'node:path';
import {{createTrustedZipWorkerModuleCapsule,spawnTrustedZipWorkerRaw}} from {json.dumps(RUNNER_PATH.as_uri())};
const root=path.resolve({json.dumps(root.as_posix())});
const paths={json.dumps(WORKER_MODULE_ORDER)};
const modules=[];
for(const relativePath of paths){{const bytes=await readFile(path.resolve({json.dumps(ROOT.as_posix())},relativePath));modules.push({{relativePath,byteLength:bytes.length,sha256:(await import('node:crypto')).createHash('sha256').update(bytes).digest('hex'),sourceBase64:bytes.toString('base64')}});}}
const capsule=await createTrustedZipWorkerModuleCapsule({{privateRoot:root,toolingCommit:{json.dumps(self.tooling_commit)},modules}});
const durations=[];
for(let index=0;index<5;index+=1){{
  const assignment=path.join(root,'invalid-'+index);
  await mkdir(assignment);
  const env={{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,PATH:process.env.PATH,TEMP:assignment,TMP:assignment,LANG:'C',LC_ALL:'C',TZ:'UTC',SOURCE_DATE_EPOCH:'0'}};
  const first=JSON.stringify(index===0?{{}}:index===1?null:index===2?[]:index===3?{{protocol:'legacy'}}:{{protocol:'ieltmps-public-source-zip-worker-s1'}})+'\\n';
  const second=JSON.stringify({{protocol:'ieltmps-public-source-zip-worker-s1',assignmentId:'worker-a'}})+'\\n';
  const observed=await spawnTrustedZipWorkerRaw({{requestMessages:[first,second],environment:env,workingDirectory:assignment,capsule}});
  if(observed.code!==1||observed.signal!==null||observed.timeout||observed.forcedTermination||observed.spawnError||observed.stdout.length!==0||observed.responses.length!==0||!observed.stderr.toString('utf8').startsWith('ERROR SAME_HOST: worker-request-invalid'))throw new Error('invalid-first observation');
  durations.push(observed.durationMilliseconds);
}}
process.stdout.write(JSON.stringify({{passed:5,durations}}));
"""
        result = json.loads(self.run_node(source, timeout=300).stdout)
        self.assertEqual(result["passed"], 5)
        self.assertEqual(len(result["durations"]), 5)
        self.assertTrue(all(value > 0 for value in result["durations"]))
        type(self).worker_durations = result["durations"]

    def test_23_same_host_stability_five(self):
        if type(self).stability_runs is None:
            controls = [
                None,
                {"immediateHostileSecond": True},
                {"postClaimHostileSecond": True},
                {"immediateHostileSecond": True},
                {"postClaimHostileSecond": True},
            ]
            runs = []
            for index, control in enumerate(controls):
                runs.append(self.run_coordinator(
                    "stability-" + str(index),
                    protocol=control,
                ))
            type(self).stability_runs = runs
        durations = []
        artifact_hashes = set()
        for run in type(self).stability_runs:
            result = run["result"]
            self.assertEqual(result["runResult"], "pass")
            self.assertTrue(result["sameHostRepeatable"])
            self.assertTrue(result["sameProcessRepeatable"])
            self.assertTrue(result["boundaryVectorSetPassed"])
            artifact_hashes.add(result["artifactSha256"])
            self.assertEqual(len(run["timings"]), 1)
            durations.append(run["timings"][0]["sameHost"])
        self.assertEqual(len(artifact_hashes), 1)
        self.assertTrue(all(value > 0 for value in durations))
        type(self).same_host_durations = durations

    def test_24_cli_exact_option_contract(self):
        completed = self.run_process(
            [NODE, COORDINATOR_PATH, "--unknown", "value"],
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"ERROR CLI: unknown-or-duplicate-option\n")

    def test_25_typed_diagnostics_are_path_free(self):
        completed = self.run_process(
            [NODE, RUNNER_PATH, "--wrong", VECTOR_PATH],
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"ERROR BOUNDARY_VECTOR: boundary-vector-failed\n")
        self.assertNotIn(str(ROOT).encode("utf-8"), completed.stderr)

    def test_26_no_real_source_input_or_release_artifacts(self):
        self.assertNotEqual(self.repository.resolve(), ROOT.resolve())
        self.assertTrue(str(self.repository).startswith(str(self.task_root)))
        forbidden = {
            "receipt.json", "comparison-report.json", "signature", "sbom.json",
        }
        produced = {
            item.name
            for directory in self.outputs.iterdir()
            for item in directory.iterdir()
        }
        self.assertTrue(forbidden.isdisjoint(produced))


if __name__ == "__main__":
    unittest.main(verbosity=2)
