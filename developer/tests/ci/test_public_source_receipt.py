#!/usr/bin/env python3
"""Synthetic security, canonicality, and publication tests for R1.1C receipts."""

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
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
RECEIPT_CORE = REPO_ROOT / "developer/public-source-receipt-core.mjs"
RECEIPT_GENERATOR = REPO_ROOT / "developer/prepare-public-source-receipt.mjs"
RECEIPT_VERIFIER = REPO_ROOT / "developer/verify-public-source-receipt.mjs"
ARCHIVE_CORE = REPO_ROOT / "developer/public-source-archive-core.mjs"
ARCHIVE_WRITER = REPO_ROOT / "developer/prepare-public-source-archive.mjs"
ARCHIVE_VERIFIER = REPO_ROOT / "developer/verify-public-source-archive.mjs"
B1_VERIFIER = REPO_ROOT / "developer/verify-public-source-membership.mjs"
B2_MATERIALIZER = REPO_ROOT / "developer/prepare-public-source-tree.mjs"
MANIFEST = REPO_ROOT / "developer/public-source-manifest.json"

RECEIPT_KIND = "ieltmps-public-source-receipt"
SCHEMA_VERSION = 1
ARCHIVE_FORMAT = "tar-ustar-v1"
RECEIPT_SUFFIX = ".source-receipt.json"
MAX_ARTIFACTS = 32

CRITICAL_TOOL_PATHS = (
    "developer/prepare-public-source-archive.mjs",
    "developer/prepare-public-source-receipt.mjs",
    "developer/prepare-public-source-tree.mjs",
    "developer/public-source-archive-core.mjs",
    "developer/public-source-manifest.json",
    "developer/public-source-receipt-core.mjs",
    "developer/verify-public-source-archive.mjs",
    "developer/verify-public-source-membership.mjs",
    "developer/verify-public-source-receipt.mjs",
)

ARTIFACT_REGISTRY = (
    ("public-container-context-receipt", "json"),
    ("standalone-release-archive", "zip"),
    ("standalone-release-receipt", "json"),
)

CANARIES = {
    "repository_path": "CANARY_REPOSITORY_PATH_7d6e",
    "archive_path": "CANARY_ARCHIVE_PATH_19a4",
    "artifact_path": "CANARY_ARTIFACT_PATH_80b2",
    "receipt_path": "CANARY_RECEIPT_PATH_5f31",
    "temporary_path": "CANARY_TEMPORARY_PATH_a90c",
    "username": "CANARY_USERNAME_e40d",
    "drive": "CANARY_DRIVE_f7b8",
    "hostname": "CANARY_HOSTNAME_21ce",
    "environment_value": "CANARY_ENVIRONMENT_VALUE_982a",
    "git_remote": "CANARY_GIT_REMOTE_6c53",
    "branch": "CANARY_BRANCH_341f",
    "private_filename": "CANARY_PRIVATE_FILENAME_abc7.private",
    "onion_hostname": "canary-onion-host-53bd.onion",
    "signer_email": "CANARY_SIGNER_EMAIL_72af@example.invalid",
    "signer_fingerprint": "CANARY_SIGNER_FINGERPRINT_5E0A",
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

SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._-]+$")
LOWER_COMMIT = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")


API_HARNESS = r"""
import {
  appendFileSync,
  linkSync,
  lstatSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

let inputText = "";
for await (const chunk of process.stdin) inputText += chunk;
const request = JSON.parse(inputText);
const observations = {
  signatureCalls: 0,
  checkpointCalls: 0,
  linkCalls: 0,
  contextsFrozen: true,
  materializedFiles: [],
  resultFrozen: false,
};

function mutatePath(targetPath, bytes) {
  const oldPath = targetPath + ".open-handle-original";
  renameSync(targetPath, oldPath);
  writeFileSync(targetPath, Buffer.from(bytes, "utf8"));
}

function observeMaterializedTools() {
  const temporaryRoot = process.env.TEMP;
  const roots = readdirSync(temporaryRoot)
    .filter((name) => name.startsWith("ieltmps-source-receipt-tools-"));
  for (const rootName of roots) {
    const root = path.join(temporaryRoot, rootName);
    const pending = [root];
    while (pending.length > 0) {
      const current = pending.pop();
      for (const name of readdirSync(current)) {
        const child = path.join(current, name);
        const state = lstatSync(child);
        if (state.isDirectory()) {
          pending.push(child);
        } else {
          observations.materializedFiles.push(
            path.relative(root, child).split(path.sep).join("/"),
          );
        }
      }
    }
  }
  observations.materializedFiles.sort();
}

const hooks = {
  verifyToolingCommitSignature(context) {
    observations.signatureCalls += 1;
    observations.contextsFrozen = observations.contextsFrozen && Object.isFrozen(context);
    if (
      process.env.IELTMPS_TEST_SIGNER_FINGERPRINT
      !== request.expectedSignerFingerprint
    ) {
      throw new Error("synthetic signer boundary mismatch");
    }
    if (request.signatureMode === "failure") {
      throw new Error("synthetic signature failure");
    }
    if (request.signatureMode === "return-value") {
      return true;
    }
    return undefined;
  },
  checkpoint(context) {
    observations.checkpointCalls += 1;
    observations.contextsFrozen = observations.contextsFrozen && Object.isFrozen(context);
    const action = request.checkpointAction;
    if (action === "late-destination" && context.checkpoint === "after-final-absence-check") {
      writeFileSync(context.outputPath, Buffer.from("late destination sentinel\n", "utf8"), { flag: "wx" });
    } else if (action === "all-temporary-collisions" && context.checkpoint === "before-temp-create-attempt") {
      writeFileSync(context.temporaryPath, Buffer.from("collision sentinel\n", "utf8"), { flag: "wx" });
    } else if (
      action === "one-temporary-collision"
      && context.checkpoint === "before-temp-create-attempt"
      && context.attempt === 0
    ) {
      writeFileSync(context.temporaryPath, Buffer.from("single collision\n", "utf8"), { flag: "wx" });
    } else if (action === "throw-after-link" && context.checkpoint === "after-link") {
      throw new Error("synthetic post-link failure");
    } else if (action === "throw-after-temp-create" && context.checkpoint === "after-temp-create") {
      throw new Error("synthetic post-temp-create failure");
    } else if (action === "throw-before-temp-verify" && context.checkpoint === "before-temp-verify") {
      throw new Error("synthetic pre-temp-verification failure");
    } else if (action === "throw-before-publish" && context.checkpoint === "before-publish") {
      throw new Error("synthetic pre-publication failure");
    } else if (action === "throw-after-final-verify" && context.checkpoint === "after-final-verify") {
      throw new Error("synthetic post-verification failure");
    } else if (action === "temporary-substitution" && context.checkpoint === "after-temp-create") {
      unlinkSync(context.temporaryPath);
      writeFileSync(context.temporaryPath, Buffer.from("suspect temporary replacement\n", "utf8"));
    } else if (action === "final-substitution" && context.checkpoint === "after-link") {
      unlinkSync(context.outputPath);
      writeFileSync(context.outputPath, Buffer.from("suspect final replacement\n", "utf8"));
    } else if (action === "post-publication-mutation" && context.checkpoint === "after-temp-unlink") {
      appendFileSync(context.outputPath, Buffer.from("post-publication mutation\n", "utf8"));
    } else if (action === "artifact-replacement" && context.checkpoint === "after-file-open" && context.kind === "artifact") {
      mutatePath(request.mutationPath, "replacement bytes of a different identity\n");
    } else if (
      action === "archive-replacement-before-worker"
      && (context.checkpoint === "before-source-worker" || context.checkpoint === "before-verified-worker")
    ) {
      mutatePath(request.mutationPath, "replacement archive bytes\n");
    } else if (
      action === "receipt-replacement-before-worker"
      && context.checkpoint === "before-verified-worker"
    ) {
      mutatePath(request.mutationPath, "replacement receipt bytes\n");
    } else if (
      action === "observe-tool-directory"
      && (context.checkpoint === "before-source-worker" || context.checkpoint === "before-verified-worker")
    ) {
      observeMaterializedTools();
    }
    return undefined;
  },
};

if (request.linkAction === "unsupported") {
  hooks.link = () => {
    observations.linkCalls += 1;
    const error = new Error("synthetic unsupported hard link");
    error.code = "ENOTSUP";
    throw error;
  };
} else if (request.linkAction === "link-then-throw") {
  hooks.link = (source, destination) => {
    observations.linkCalls += 1;
    linkSync(source, destination);
    throw new Error("synthetic post-link primitive failure");
  };
}

try {
  let result;
  if (request.module === "generator") {
    const imported = await import(pathToFileURL(process.env.IELTMPS_TEST_GENERATOR).href);
    result = await imported.preparePublicSourceReceipt({ ...request.options, testHooks: hooks });
  } else if (request.module === "verifier") {
    const imported = await import(pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href);
    const verifierHooks = {
      verifyToolingCommitSignature: hooks.verifyToolingCommitSignature,
      checkpoint: hooks.checkpoint,
    };
    result = await imported.verifyPublicSourceReceipt({
      ...request.options,
      testHooks: verifierHooks,
    });
  } else if (request.module === "derive") {
    const imported = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
    result = imported.deriveCriticalToolIdentities(
      request.options.repo,
      request.options.toolingCommit,
    );
    result = { criticalFiles: result.criticalFiles };
  } else {
    throw new Error("unknown synthetic harness module");
  }
  observations.resultFrozen = Object.isFrozen(result);
  process.stdout.write(JSON.stringify({ ok: true, result, observations }) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
    reason: typeof error?.reason === "string" ? error.reason : "synthetic-harness",
    message: typeof error?.message === "string" ? error.message : "synthetic harness failure",
    observations,
  }) + "\n");
}
"""


PARSER_HARNESS = r"""
import { pathToFileURL } from "node:url";
let inputText = "";
for await (const chunk of process.stdin) inputText += chunk;
const request = JSON.parse(inputText);
try {
  const imported = await import(pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href);
  const receipt = imported.parsePublicSourceReceiptBytes(
    Buffer.from(request.receiptBase64, "base64"),
  );
  process.stdout.write(JSON.stringify({
    ok: true,
    artifactCount: receipt.artifacts.length,
    sourceCommit: receipt.source.commit,
    toolingCommit: receipt.tooling.commit,
  }) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: typeof error?.phase === "string" ? error.phase : "HARNESS",
    reason: typeof error?.reason === "string" ? error.reason : "synthetic-parser",
  }) + "\n");
}
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


def _write_at(root: Path, relative: str, value: str | bytes) -> None:
    target = root / PurePosixPath(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        target.write_bytes(value)
    else:
        target.write_text(value, encoding="utf-8", newline="\n")


def _artifact_identities(artifacts: list[dict[str, object]]) -> list[dict[str, object]]:
    identities: list[dict[str, object]] = []
    roles: set[str] = set()
    tuples: set[tuple[str, str]] = set()
    hashes: set[str] = set()
    for artifact in artifacts:
        role = artifact["role"]
        artifact_format = artifact["format"]
        value = artifact["bytes"]
        if not isinstance(role, str) or not isinstance(artifact_format, str):
            raise ValueError("artifact role and format must be strings")
        if (role, artifact_format) not in ARTIFACT_REGISTRY:
            raise ValueError("unknown artifact role/format")
        if not isinstance(value, bytes):
            raise ValueError("artifact bytes must be bytes")
        digest = _sha256(value)
        if role in roles or (role, artifact_format) in tuples or digest in hashes:
            raise ValueError("duplicate independent artifact identity")
        roles.add(role)
        tuples.add((role, artifact_format))
        hashes.add(digest)
        identities.append(
            {
                "role": role,
                "format": artifact_format,
                "sha256": digest,
                "byteLength": len(value),
            }
        )
    if not 1 <= len(identities) <= MAX_ARTIFACTS:
        raise ValueError("artifact count outside v1 range")
    return sorted(
        identities,
        key=lambda item: (item["role"], item["format"], item["sha256"]),
    )


def _independent_receipt_value(
    *,
    source: dict[str, object],
    tooling_commit: str,
    critical_files: list[dict[str, object]],
    artifacts: list[dict[str, object]],
) -> dict[str, object]:
    """Build v1 in exact insertion order without invoking any receipt JavaScript."""
    if not LOWER_COMMIT.fullmatch(tooling_commit):
        raise ValueError("tooling commit is not canonical")
    if len(critical_files) != len(CRITICAL_TOOL_PATHS):
        raise ValueError("critical file count mismatch")
    canonical_critical: list[dict[str, object]] = []
    for expected_path, item in zip(CRITICAL_TOOL_PATHS, critical_files, strict=True):
        if item["path"] != expected_path:
            raise ValueError("critical file order mismatch")
        if not LOWER_COMMIT.fullmatch(str(item["gitBlobId"])):
            raise ValueError("critical blob ID is not canonical")
        if not LOWER_SHA256.fullmatch(str(item["sha256"])):
            raise ValueError("critical SHA-256 is not canonical")
        if not isinstance(item["byteLength"], int) or isinstance(item["byteLength"], bool):
            raise ValueError("critical byte length is not an integer")
        canonical_critical.append(
            {
                "path": expected_path,
                "gitBlobId": item["gitBlobId"],
                "sha256": item["sha256"],
                "byteLength": item["byteLength"],
            }
        )
    canonical_artifacts = sorted(
        copy.deepcopy(artifacts),
        key=lambda item: (item["role"], item["format"], item["sha256"]),
    )
    return {
        "receiptKind": RECEIPT_KIND,
        "schemaVersion": SCHEMA_VERSION,
        "source": {
            "commit": source["sourceCommit"],
            "manifestSha256": source["manifestSha256"],
            "membershipReportSha256": source["membershipReportSha256"],
            "membershipCount": source["membershipCount"],
            "archive": {
                "format": source["archiveFormat"],
                "sha256": source["archiveSha256"],
                "byteLength": source["archiveByteLength"],
                "memberCount": source["archiveMemberCount"],
            },
        },
        "tooling": {
            "commit": tooling_commit,
            "criticalFiles": canonical_critical,
        },
        "artifacts": canonical_artifacts,
        "correspondingSourceComplete": False,
        "publicationBlocked": True,
    }


def _independent_receipt_bytes(value: dict[str, object]) -> bytes:
    """Encode compact ASCII JSON plus exactly one LF, independently of JS."""
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    if encoded.startswith(b"\xef\xbb\xbf") or b"\r" in encoded:
        raise ValueError("independent encoder produced forbidden framing")
    if encoded.count(b"\n") != 1 or not encoded.endswith(b"\n"):
        raise ValueError("independent encoder produced noncanonical LF framing")
    return encoded


def _replace_once(value: bytes, old: bytes, new: bytes) -> bytes:
    if value.count(old) != 1:
        raise AssertionError(f"mutation token count was {value.count(old)}, expected one")
    mutated = value.replace(old, new, 1)
    if mutated == value:
        raise AssertionError("mutation did not change receipt bytes")
    return mutated


class PublicSourceReceiptTest(unittest.TestCase):
    """Every mutable repository, archive, artifact, link, and receipt is temporary."""

    maxDiff = None
    malformed_receipt_subcases = 0
    privacy_canary_count = len(CANARIES)
    deterministic_receipt_sha256 = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        cls.git = _find_git()
        required = (
            RECEIPT_CORE,
            RECEIPT_GENERATOR,
            RECEIPT_VERIFIER,
            ARCHIVE_CORE,
            ARCHIVE_WRITER,
            ARCHIVE_VERIFIER,
            B1_VERIFIER,
            B2_MATERIALIZER,
            MANIFEST,
        )
        if not all(path.is_file() for path in required):
            raise unittest.SkipTest("required R1.1C or frozen B1/B2/B3 source is unavailable")

        cls.manifest_bytes = MANIFEST.read_bytes()
        cls.manifest_value = json.loads(cls.manifest_bytes.decode("utf-8"))
        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-receipt-template-"
        )
        cls.template_base = Path(cls.template_temp.name).resolve()
        cls.template_root = cls.template_base / CANARIES["repository_path"]
        cls.template_root.mkdir()

        exact_paths: set[str] = set()
        for component in cls.manifest_value["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            content = (
                cls.manifest_bytes
                if relative == "developer/public-source-manifest.json"
                else f"synthetic historical source member: {relative}\n".encode("utf-8")
            )
            _write_at(cls.template_root, relative, content)

        prefix_members = {
            "backend/admin/example.js": b"export const adminFixture = true;\n",
            "backend/auth/example.js": b"export const authFixture = true;\n",
            "backend/migrations/001_fixture.sql": b"SELECT 1;\n",
            "backend/scripts/example.sh": b"#!/bin/sh\nexit 0\n",
            "backend/src/example.js": b"export const backendFixture = true;\n",
            "backend/test/example.test.js": b"export const testFixture = true;\n",
            "css/example.css": b":root { --synthetic: 1; }\n",
            "js/example.js": b"export const frontendFixture = true;\n",
            "src/styles/example.css": b"body { color: black; }\n",
        }
        for relative, content in prefix_members.items():
            _write_at(cls.template_root, relative, content)
        _write_at(
            cls.template_root,
            f"synthetic-not-selected/{CANARIES['private_filename']}",
            b"private-looking synthetic filename canary only\n",
        )

        cls._git_at(cls.template_root, "init")
        for key, value in (
            ("user.name", CANARIES["username"]),
            ("user.email", CANARIES["signer_email"]),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git_at(cls.template_root, "config", key, value)
        cls._git_at(cls.template_root, "checkout", "-b", CANARIES["branch"])
        cls._git_at(cls.template_root, "add", "-A")
        cls._git_at(
            cls.template_root,
            "commit",
            "-m",
            "synthetic historical source commit",
            commit_date="2001-02-03T04:05:06Z",
        )
        cls.source_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()

        source_by_relative = {
            "developer/prepare-public-source-archive.mjs": ARCHIVE_WRITER,
            "developer/prepare-public-source-receipt.mjs": RECEIPT_GENERATOR,
            "developer/prepare-public-source-tree.mjs": B2_MATERIALIZER,
            "developer/public-source-archive-core.mjs": ARCHIVE_CORE,
            "developer/public-source-manifest.json": MANIFEST,
            "developer/public-source-receipt-core.mjs": RECEIPT_CORE,
            "developer/verify-public-source-archive.mjs": ARCHIVE_VERIFIER,
            "developer/verify-public-source-membership.mjs": B1_VERIFIER,
            "developer/verify-public-source-receipt.mjs": RECEIPT_VERIFIER,
        }
        for relative, source_path in source_by_relative.items():
            _write_at(cls.template_root, relative, source_path.read_bytes())
        cls._git_at(cls.template_root, "add", "--", *CRITICAL_TOOL_PATHS)
        cls._git_at(
            cls.template_root,
            "commit",
            "-m",
            "synthetic current tooling commit",
            commit_date="2002-03-04T05:06:07Z",
        )
        cls.tooling_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()
        if cls.source_commit == cls.tooling_commit:
            raise AssertionError("synthetic historical source and tooling commits must differ")
        cls._git_at(
            cls.template_root,
            "remote",
            "add",
            "origin",
            (
                "https://"
                + CANARIES["onion_hostname"]
                + "/"
                + CANARIES["git_remote"]
                + ".git"
            ),
        )

        cls.template_archive = (
            cls.template_base / f"{CANARIES['archive_path']}.tar"
        )
        archive_run = subprocess.run(
            [
                str(cls.node),
                str(ARCHIVE_WRITER),
                "--repo",
                str(cls.template_root),
                "--commit",
                cls.source_commit,
                "--output",
                str(cls.template_archive),
            ],
            cwd=cls.template_base,
            env=cls._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        if archive_run.returncode != 0:
            raise AssertionError(
                "synthetic B3 archive setup failed: "
                + archive_run.stdout
                + archive_run.stderr
            )
        archive_verify = subprocess.run(
            [
                str(cls.node),
                str(ARCHIVE_VERIFIER),
                "--repo",
                str(cls.template_root),
                "--commit",
                cls.source_commit,
                "--archive",
                str(cls.template_archive),
            ],
            cwd=cls.template_base,
            env=cls._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        if archive_verify.returncode != 0:
            raise AssertionError(
                "synthetic B3 archive verification setup failed: "
                + archive_verify.stdout
                + archive_verify.stderr
            )
        cls.source_verification = json.loads(archive_verify.stdout)
        cls.critical_files = cls._derive_critical_files(
            cls.template_root, cls.tooling_commit
        )
        if cls._git_at(cls.template_root, "status", "--porcelain").stdout:
            raise AssertionError("synthetic tooling template is not clean")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()
        duration = time.monotonic() - cls.started
        methods = len(unittest.defaultTestLoader.getTestCaseNames(cls))
        print(
            "RECEIPT_COVERAGE "
            f"test_methods={methods} "
            f"malformed_receipt_subcases={cls.malformed_receipt_subcases} "
            f"privacy_canaries={cls.privacy_canary_count} "
            f"deterministic_receipt_sha256={cls.deterministic_receipt_sha256} "
            f"duration_seconds={duration:.3f}"
        )

    @classmethod
    def _environment(cls) -> dict[str, str]:
        environment = os.environ.copy()
        for name in GIT_REDIRECTION_NAMES:
            environment.pop(name, None)
        environment.pop("NODE_OPTIONS", None)
        environment.pop("NODE_PATH", None)
        path_parts = [str(cls.git.parent), str(cls.node.parent)]
        if environment.get("PATH"):
            path_parts.append(environment["PATH"])
        environment["PATH"] = os.pathsep.join(path_parts)
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["IELTMPS_TEST_USERNAME"] = CANARIES["username"]
        environment["IELTMPS_TEST_DRIVE"] = CANARIES["drive"]
        environment["IELTMPS_TEST_HOSTNAME"] = CANARIES["hostname"]
        environment["IELTMPS_TEST_ENVIRONMENT_VALUE"] = CANARIES[
            "environment_value"
        ]
        environment["IELTMPS_TEST_SIGNER_FINGERPRINT"] = CANARIES[
            "signer_fingerprint"
        ]
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
    def _derive_critical_files(
        cls, root: Path, tooling_commit: str
    ) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for relative in CRITICAL_TOOL_PATHS:
            record = cls._git_at(
                root, "ls-tree", tooling_commit, "--", relative
            ).stdout.decode("utf-8").strip()
            match = re.fullmatch(
                r"(100644|100755) blob ([0-9a-f]{40})\t(.+)", record
            )
            if not match or match.group(3) != relative:
                raise AssertionError(f"invalid synthetic critical tree record: {record}")
            blob_id = match.group(2)
            blob = cls._git_at(root, "cat-file", "blob", blob_id).stdout
            result.append(
                {
                    "path": relative,
                    "gitBlobId": blob_id,
                    "sha256": _sha256(blob),
                    "byteLength": len(blob),
                }
            )
        return result

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-receipt-case-"
        )
        self.case_base = Path(self.case_temp.name).resolve()
        self.fixture_root = self.case_base / CANARIES["repository_path"]
        shutil.copytree(self.template_root, self.fixture_root)
        self.source_archive = self.case_base / f"{CANARIES['archive_path']}.tar"
        shutil.copyfile(self.template_archive, self.source_archive)
        self.tool_temp = self.case_base / CANARIES["temporary_path"]
        self.tool_temp.mkdir()
        self.output_path = (
            self.case_base / f"{CANARIES['receipt_path']}{RECEIPT_SUFFIX}"
        )
        self.second_output = self.case_base / f"second{RECEIPT_SUFFIX}"
        self.artifact_paths: list[Path] = []
        self.assertEqual(self._head(), self.tooling_commit)
        self.assertEqual(self._git("status", "--porcelain").stdout, b"")

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    def _git(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self._git_at(
            self.fixture_root,
            *args,
            input_bytes=input_bytes,
            allow_failure=allow_failure,
        )

    def _head(self) -> str:
        return self._git("rev-parse", "HEAD").stdout.decode("ascii").strip()

    def _case_environment(
        self, updates: dict[str, str] | None = None
    ) -> dict[str, str]:
        environment = self._environment()
        environment["TEMP"] = str(self.tool_temp)
        environment["TMP"] = str(self.tool_temp)
        environment["TMPDIR"] = str(self.tool_temp)
        environment["IELTMPS_TEST_GENERATOR"] = str(
            self.fixture_root / "developer/prepare-public-source-receipt.mjs"
        )
        environment["IELTMPS_TEST_VERIFIER"] = str(
            self.fixture_root / "developer/verify-public-source-receipt.mjs"
        )
        environment["IELTMPS_TEST_CORE"] = str(
            self.fixture_root / "developer/public-source-receipt-core.mjs"
        )
        if updates:
            environment.update(updates)
        return environment

    def _artifacts(
        self, pairs: tuple[tuple[str, str], ...] = ARTIFACT_REGISTRY
    ) -> list[dict[str, object]]:
        artifacts: list[dict[str, object]] = []
        for index, (role, artifact_format) in enumerate(pairs):
            target = self.case_base / (
                f"{CANARIES['artifact_path']}-{index}-{role}.{artifact_format}"
            )
            value = f"synthetic artifact {index} for {role}/{artifact_format}\n".encode(
                "utf-8"
            )
            target.write_bytes(value)
            self.artifact_paths.append(target)
            artifacts.append(
                {
                    "role": role,
                    "format": artifact_format,
                    "path": str(target),
                    "bytes": value,
                }
            )
        return artifacts

    @staticmethod
    def _api_artifacts(
        artifacts: list[dict[str, object]]
    ) -> list[dict[str, str]]:
        return [
            {
                "role": str(item["role"]),
                "format": str(item["format"]),
                "path": str(item["path"]),
            }
            for item in artifacts
        ]

    def _generator_options(
        self,
        artifacts: list[dict[str, object]],
        output: Path | str | None = None,
        **overrides: object,
    ) -> dict[str, object]:
        options: dict[str, object] = {
            "repo": str(self.fixture_root),
            "sourceCommit": self.source_commit,
            "toolingCommit": self.tooling_commit,
            "sourceArchive": str(self.source_archive),
            "artifacts": self._api_artifacts(artifacts),
            "output": str(output or self.output_path),
        }
        options.update(overrides)
        return options

    def _verifier_options(
        self,
        mode: str,
        artifacts: list[dict[str, object]],
        receipt: Path | str | None = None,
        **overrides: object,
    ) -> dict[str, object]:
        options: dict[str, object] = {
            "mode": mode,
            "repo": str(self.fixture_root),
            "receipt": str(receipt or self.output_path),
            "sourceArchive": str(self.source_archive),
            "artifacts": self._api_artifacts(artifacts) if mode == "full" else [],
        }
        options.update(overrides)
        return options

    def _run_api(
        self,
        module: str,
        options: dict[str, object],
        *,
        signature_mode: str = "success",
        checkpoint_action: str | None = None,
        link_action: str | None = None,
        mutation_path: Path | str | None = None,
        environment_updates: dict[str, str] | None = None,
        node_prefix: list[str] | None = None,
        timeout: int = 240,
    ) -> dict[str, object]:
        request = {
            "module": module,
            "options": options,
            "signatureMode": signature_mode,
            "checkpointAction": checkpoint_action,
            "linkAction": link_action,
            "mutationPath": None if mutation_path is None else str(mutation_path),
            "expectedSignerFingerprint": CANARIES["signer_fingerprint"],
        }
        argv = [str(self.node)]
        if node_prefix:
            argv.extend(node_prefix)
        argv.extend(
            [
                "--input-type=module",
                "--eval",
                API_HARNESS,
                "receipt-api-harness-sentinel",
            ]
        )
        completed = subprocess.run(
            argv,
            cwd=self.case_base,
            env=self._case_environment(environment_updates),
            input=json.dumps(request, separators=(",", ":")),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertTrue(completed.stdout.endswith("\n"), completed.stdout)
        self.assertEqual(completed.stdout.count("\n"), 1, completed.stdout)
        return json.loads(completed.stdout)

    def _parse_receipt(self, value: bytes) -> dict[str, object]:
        request = {
            "receiptBase64": base64.b64encode(value).decode("ascii"),
        }
        completed = subprocess.run(
            [
                str(self.node),
                "--input-type=module",
                "--eval",
                PARSER_HARNESS,
                "receipt-parser-harness-sentinel",
            ],
            cwd=self.case_base,
            env=self._case_environment(),
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

    def _build_receipt_for_artifacts(
        self, artifacts: list[dict[str, object]]
    ) -> tuple[dict[str, object], bytes]:
        identities = _artifact_identities(artifacts)
        value = _independent_receipt_value(
            source=self.source_verification,
            tooling_commit=self.tooling_commit,
            critical_files=copy.deepcopy(self.critical_files),
            artifacts=identities,
        )
        return value, _independent_receipt_bytes(value)

    def _write_receipt(self, value: bytes, path: Path | None = None) -> Path:
        target = path or self.output_path
        target.write_bytes(value)
        return target

    def _assert_api_error(
        self,
        response: dict[str, object],
        phase: str,
        reason: str | None = None,
    ) -> None:
        self.assertFalse(response["ok"], response)
        self.assertEqual(response["phase"], phase, response)
        if reason is not None:
            self.assertEqual(response["reason"], reason, response)

    def _assert_no_canary(self, value: bytes | str) -> None:
        haystack = value if isinstance(value, bytes) else value.encode("utf-8")
        for label, canary in CANARIES.items():
            with self.subTest(canary=label):
                self.assertNotIn(canary.encode("utf-8"), haystack)

    def _run_cli(
        self,
        script: Path | str,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        environment_updates: dict[str, str] | None = None,
        node_prefix: list[str] | None = None,
        timeout: int = 240,
    ) -> subprocess.CompletedProcess[str]:
        argv = [str(self.node)]
        if node_prefix:
            argv.extend(node_prefix)
        argv.append(str(script))
        argv.extend(arguments)
        return subprocess.run(
            argv,
            cwd=cwd or self.case_base,
            env=self._case_environment(environment_updates),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def _environment_for_root(self, base: Path, root: Path) -> dict[str, str]:
        temporary = base / CANARIES["temporary_path"]
        temporary.mkdir(exist_ok=True)
        return {
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
            "IELTMPS_TEST_GENERATOR": str(
                root / "developer/prepare-public-source-receipt.mjs"
            ),
            "IELTMPS_TEST_VERIFIER": str(
                root / "developer/verify-public-source-receipt.mjs"
            ),
            "IELTMPS_TEST_CORE": str(root / "developer/public-source-receipt-core.mjs"),
        }

    def _generator_options_for_root(
        self,
        root: Path,
        artifacts: list[dict[str, object]],
        output: Path,
    ) -> dict[str, object]:
        return {
            "repo": str(root),
            "sourceCommit": self.source_commit,
            "toolingCommit": self.tooling_commit,
            "sourceArchive": str(self.source_archive),
            "artifacts": self._api_artifacts(artifacts),
            "output": str(output),
        }

    def _commit_with_critical_entry(
        self,
        *,
        relative: str,
        mode: str | None,
        object_type: str | None,
        object_id: str | None,
    ) -> str:
        self.assertTrue(relative.startswith("developer/"))
        name = relative.removeprefix("developer/")
        developer_records = self._git(
            "ls-tree", f"{self.tooling_commit}:developer"
        ).stdout.decode("utf-8").splitlines()
        replacement = (
            None
            if mode is None
            else f"{mode} {object_type} {object_id}\t{name}"
        )
        updated: list[str] = []
        replaced = False
        for record in developer_records:
            record_name = record.split("\t", 1)[1]
            if record_name == name:
                replaced = True
                if replacement is not None:
                    updated.append(replacement)
            else:
                updated.append(record)
        self.assertTrue(replaced)
        updated.sort(key=lambda record: record.split("\t", 1)[1].encode("utf-8"))
        developer_tree = self._git(
            "mktree", input_bytes=("\n".join(updated) + "\n").encode("utf-8")
        ).stdout.decode("ascii").strip()

        root_records = self._git("ls-tree", self.tooling_commit).stdout.decode(
            "utf-8"
        ).splitlines()
        new_root_records: list[str] = []
        for record in root_records:
            record_name = record.split("\t", 1)[1]
            if record_name == "developer":
                new_root_records.append(
                    f"040000 tree {developer_tree}\tdeveloper"
                )
            else:
                new_root_records.append(record)
        new_root_records.sort(
            key=lambda record: record.split("\t", 1)[1].encode("utf-8")
        )
        root_tree = self._git(
            "mktree",
            input_bytes=("\n".join(new_root_records) + "\n").encode("utf-8"),
        ).stdout.decode("ascii").strip()
        return self._git_at(
            self.fixture_root,
            "commit-tree",
            root_tree,
            "-p",
            self.tooling_commit,
            input_bytes=b"synthetic critical object variant\n",
            commit_date="2003-04-05T06:07:08Z",
        ).stdout.decode("ascii").strip()

    @contextmanager
    def _fresh_case_copy(self, label: str):
        with tempfile.TemporaryDirectory(
            prefix=f"ieltmps-receipt-{label}-"
        ) as temporary:
            base = Path(temporary).resolve()
            root = base / CANARIES["repository_path"]
            shutil.copytree(self.template_root, root)
            yield base, root

    def test_01_one_artifact_generation_full_and_partial_verification(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        generated = self._run_api(
            "generator",
            self._generator_options(artifacts),
            checkpoint_action="observe-tool-directory",
        )
        self.assertTrue(generated["ok"], generated)
        self.assertEqual(generated["observations"]["signatureCalls"], 1)
        self.assertTrue(generated["observations"]["contextsFrozen"])
        self.assertEqual(
            generated["observations"]["materializedFiles"],
            list(CRITICAL_TOOL_PATHS),
        )
        self.assertTrue(self.output_path.is_file())
        receipt_bytes = self.output_path.read_bytes()
        receipt = json.loads(receipt_bytes.decode("ascii"))
        independent_value, independent_bytes = self._build_receipt_for_artifacts(artifacts)
        self.assertEqual(receipt, independent_value)
        self.assertEqual(receipt_bytes, independent_bytes)
        self.assertEqual(receipt_bytes[-1:], b"\n")
        self.assertNotEqual(receipt_bytes[-2:-1], b"\n")
        self.assertNotIn(b"\r", receipt_bytes)
        self.assertFalse(receipt_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(receipt["receiptKind"], RECEIPT_KIND)
        self.assertEqual(receipt["schemaVersion"], SCHEMA_VERSION)
        self.assertEqual(receipt["source"]["commit"], self.source_commit)
        self.assertEqual(receipt["tooling"]["commit"], self.tooling_commit)
        self.assertNotEqual(self.source_commit, self.tooling_commit)
        self.assertEqual(
            [entry["path"] for entry in receipt["tooling"]["criticalFiles"]],
            list(CRITICAL_TOOL_PATHS),
        )
        self.assertEqual(len(receipt["tooling"]["criticalFiles"]), 9)
        self.assertFalse(receipt["correspondingSourceComplete"])
        self.assertTrue(receipt["publicationBlocked"])
        self.assertNotIn("timestamp", receipt)
        self.assertNotIn("receiptSha256", receipt)
        self.assertNotIn("signature", receipt)
        self.assertNotIn("signer", receipt)
        self._assert_no_canary(receipt_bytes)

        success = generated["result"]
        self.assertEqual(success["status"], "ok")
        self.assertEqual(success["mode"], "receipt-creation")
        self.assertTrue(success["receiptCreated"])
        self.assertTrue(success["receiptVerified"])
        self.assertEqual(success["receiptSha256"], _sha256(receipt_bytes))
        self.assertEqual(success["receiptByteLength"], len(receipt_bytes))
        self.assertTrue(success["sourceArchiveVerified"])
        self.assertTrue(success["toolingCommitSignatureValid"])
        self.assertTrue(success["artifactsVerified"])
        self._assert_no_canary(json.dumps(success, separators=(",", ":")))

        full = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self.assertTrue(full["ok"], full)
        self.assertEqual(full["observations"]["signatureCalls"], 1)
        self.assertEqual(full["result"]["status"], "ok")
        self.assertEqual(full["result"]["mode"], "full")
        self.assertTrue(full["result"]["verificationComplete"])
        self.assertTrue(full["result"]["artifactsVerified"])
        self.assertEqual(full["result"]["receiptSha256"], _sha256(receipt_bytes))

        partial = self._run_api(
            "verifier", self._verifier_options("source-only", artifacts)
        )
        self.assertTrue(partial["ok"], partial)
        self.assertEqual(partial["observations"]["signatureCalls"], 1)
        self.assertEqual(partial["result"]["status"], "partial")
        self.assertEqual(partial["result"]["mode"], "source-only")
        self.assertFalse(partial["result"]["verificationComplete"])
        self.assertFalse(partial["result"]["artifactsVerified"])
        self.assertTrue(partial["result"]["sourceArchiveVerified"])
        self.assertTrue(partial["result"]["toolingCommitSignatureValid"])
        self.assertEqual(list(self.tool_temp.iterdir()), [])

    def test_02_multi_artifact_permutation_determinism_and_replay(self) -> None:
        artifacts = self._artifacts()
        first = self._run_api(
            "generator",
            self._generator_options(list(reversed(artifacts)), self.output_path),
        )
        self.assertTrue(first["ok"], first)
        first_bytes = self.output_path.read_bytes()
        second = self._run_api(
            "generator",
            self._generator_options(artifacts, self.second_output),
        )
        self.assertTrue(second["ok"], second)
        second_bytes = self.second_output.read_bytes()
        third_output = self.case_base / f"third{RECEIPT_SUFFIX}"
        third = self._run_api(
            "generator",
            self._generator_options(copy.deepcopy(artifacts), third_output),
        )
        self.assertTrue(third["ok"], third)
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, third_output.read_bytes())
        type(self).deterministic_receipt_sha256 = _sha256(first_bytes)
        self.assertEqual(first["result"]["receiptSha256"], _sha256(first_bytes))
        self.assertEqual(second["result"]["receiptSha256"], _sha256(first_bytes))
        self.assertEqual(third["result"]["receiptSha256"], _sha256(first_bytes))
        receipt = json.loads(first_bytes.decode("ascii"))
        expected_order = sorted(role for role, _ in ARTIFACT_REGISTRY)
        self.assertEqual(
            [entry["role"] for entry in receipt["artifacts"]], expected_order
        )

        full = self._run_api(
            "verifier", self._verifier_options("full", artifacts, self.output_path)
        )
        partial = self._run_api(
            "verifier",
            self._verifier_options("source-only", artifacts, self.output_path),
        )
        self.assertTrue(full["ok"], full)
        self.assertTrue(partial["ok"], partial)
        Path(str(artifacts[0]["path"])).write_bytes(b"mutated replay artifact\n")
        mutated_full = self._run_api(
            "verifier", self._verifier_options("full", artifacts, self.output_path)
        )
        self._assert_api_error(mutated_full, "ARTIFACT", "artifact-set-binding")
        still_partial = self._run_api(
            "verifier",
            self._verifier_options("source-only", artifacts, self.output_path),
        )
        self.assertTrue(still_partial["ok"], still_partial)
        self.assertEqual(still_partial["result"]["status"], "partial")
        self.assertFalse(still_partial["result"]["verificationComplete"])
        self.assertFalse(still_partial["result"]["artifactsVerified"])

    def test_03_independent_python_built_receipt_is_accepted(self) -> None:
        artifacts = self._artifacts()
        value, receipt_bytes = self._build_receipt_for_artifacts(artifacts)
        self.assertEqual(
            list(value),
            [
                "receiptKind",
                "schemaVersion",
                "source",
                "tooling",
                "artifacts",
                "correspondingSourceComplete",
                "publicationBlocked",
            ],
        )
        self._write_receipt(receipt_bytes)
        parsed = self._parse_receipt(receipt_bytes)
        self.assertTrue(parsed["ok"], parsed)
        self.assertEqual(parsed["artifactCount"], 3)
        full = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        partial = self._run_api(
            "verifier", self._verifier_options("source-only", artifacts)
        )
        self.assertTrue(full["ok"], full)
        self.assertTrue(partial["ok"], partial)
        self.assertEqual(full["result"]["receiptSha256"], _sha256(receipt_bytes))
        self.assertEqual(full["result"]["receiptByteLength"], len(receipt_bytes))

    def test_04_independently_malformed_receipts_have_exact_typed_reasons(self) -> None:
        artifacts = self._artifacts()
        value, baseline = self._build_receipt_for_artifacts(artifacts)
        source_commit = self.source_commit.encode("ascii")
        manifest_hash = str(self.source_verification["manifestSha256"]).encode("ascii")
        membership_count = str(self.source_verification["membershipCount"]).encode(
            "ascii"
        )

        reordered_critical = copy.deepcopy(value)
        reordered_critical["tooling"]["criticalFiles"][0:2] = reversed(
            reordered_critical["tooling"]["criticalFiles"][0:2]
        )
        reordered_artifacts = copy.deepcopy(value)
        reordered_artifacts["artifacts"][0:2] = reversed(
            reordered_artifacts["artifacts"][0:2]
        )

        def replace_first(old: bytes, new: bytes) -> bytes:
            self.assertIn(old, baseline)
            mutated = baseline.replace(old, new, 1)
            self.assertNotEqual(mutated, baseline)
            return mutated

        cases: list[tuple[str, bytes, str]] = [
            (
                "wrong-kind",
                replace_first(RECEIPT_KIND.encode("ascii"), b"wrong-receipt-kind"),
                "receipt-kind",
            ),
            (
                "wrong-version",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":2'),
                "schema-version",
            ),
            (
                "unknown-field",
                replace_first(
                    b',"publicationBlocked":true}',
                    b',"unknownField":0,"publicationBlocked":true}',
                ),
                "top-level-unknown-field",
            ),
            (
                "missing-field",
                replace_first(b',"publicationBlocked":true', b""),
                "top-level-missing-field",
            ),
            (
                "reordered-top-level",
                replace_first(
                    (
                        b'{"receiptKind":"'
                        + RECEIPT_KIND.encode("ascii")
                        + b'","schemaVersion":1'
                    ),
                    (
                        b'{"schemaVersion":1,"receiptKind":"'
                        + RECEIPT_KIND.encode("ascii")
                        + b'"'
                    ),
                ),
                "top-level-key-order",
            ),
            (
                "reordered-nested",
                replace_first(
                    b'"source":{"commit":"'
                    + source_commit
                    + b'","manifestSha256":"'
                    + manifest_hash
                    + b'"',
                    b'"source":{"manifestSha256":"'
                    + manifest_hash
                    + b'","commit":"'
                    + source_commit
                    + b'"',
                ),
                "source-key-order",
            ),
            (
                "duplicate-key",
                replace_first(
                    b'"schemaVersion":1',
                    b'"receiptKind":"'
                    + RECEIPT_KIND.encode("ascii")
                    + b'","schemaVersion":1',
                ),
                "top-level-duplicate-key",
            ),
            (
                "extra-whitespace",
                replace_first(b'"schemaVersion":1', b'"schemaVersion": 1'),
                "noncanonical-whitespace",
            ),
            ("leading-whitespace", b" " + baseline, "noncanonical-whitespace"),
            ("trailing-whitespace", baseline[:-1] + b" \n", "trailing-bytes"),
            ("crlf", baseline[:-1] + b"\r\n", "crlf-or-cr"),
            ("missing-final-lf", baseline[:-1], "missing-final-lf"),
            ("extra-final-lf", baseline + b"\n", "extra-final-lf"),
            ("utf8-bom", b"\xef\xbb\xbf" + baseline, "utf8-bom"),
            (
                "non-ascii-string",
                replace_first(b"ieltmps", "ieltémps".encode("utf-8")),
                "non-ascii-string",
            ),
            (
                "escaped-safe-ascii",
                replace_first(b"ieltmps", b"ielt\\u006dps"),
                "string-escape",
            ),
            (
                "uppercase-commit",
                replace_first(source_commit, source_commit.upper()),
                "source-commit",
            ),
            (
                "short-commit",
                replace_first(source_commit, source_commit[:-1]),
                "source-commit",
            ),
            (
                "uppercase-hash",
                replace_first(manifest_hash, manifest_hash.upper()),
                "manifest-sha256",
            ),
            (
                "short-hash",
                replace_first(manifest_hash, manifest_hash[:-1]),
                "manifest-sha256",
            ),
            (
                "leading-zero-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":01'),
                "schema-version-leading-zero",
            ),
            (
                "negative-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":-1'),
                "schema-version-negative",
            ),
            (
                "float-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":1.0'),
                "schema-version-fraction",
            ),
            (
                "exponent-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":1e0'),
                "schema-version-exponent",
            ),
            (
                "unsafe-integer",
                replace_first(
                    b'"membershipCount":' + membership_count,
                    b'"membershipCount":9007199254740992',
                ),
                "membership-count-range",
            ),
            (
                "nan-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":NaN'),
                "schema-version-encoding",
            ),
            (
                "infinity-integer",
                replace_first(b'"schemaVersion":1', b'"schemaVersion":Infinity'),
                "schema-version-encoding",
            ),
            (
                "null-integer",
                replace_first(
                    b'"membershipCount":' + membership_count,
                    b'"membershipCount":null',
                ),
                "membership-count-encoding",
            ),
            (
                "null-boolean",
                replace_first(
                    b'"correspondingSourceComplete":false',
                    b'"correspondingSourceComplete":null',
                ),
                "corresponding-source-complete-null",
            ),
            (
                "wrong-boolean",
                replace_first(
                    b'"correspondingSourceComplete":false',
                    b'"correspondingSourceComplete":true',
                ),
                "corresponding-source-complete",
            ),
            (
                "unknown-archive-format",
                replace_first(ARCHIVE_FORMAT.encode("ascii"), b"tar-pax-v1"),
                "archive-format",
            ),
            (
                "reordered-critical-files",
                _independent_receipt_bytes(reordered_critical),
                "critical-file-path-order",
            ),
            (
                "reordered-artifacts",
                _independent_receipt_bytes(reordered_artifacts),
                "artifact-order",
            ),
        ]

        for label, malformed, expected_reason in cases:
            with self.subTest(case=label):
                self.assertNotEqual(malformed, baseline)
                result = self._parse_receipt(malformed)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["phase"], "RECEIPT_SCHEMA", result)
                self.assertEqual(result["reason"], expected_reason, result)
        type(self).malformed_receipt_subcases += len(cases)

    def test_05_receipt_tooling_array_binding_fails_closed(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        baseline_value, _ = self._build_receipt_for_artifacts(artifacts)
        variants: list[tuple[str, dict[str, object], str, str]] = []

        missing = copy.deepcopy(baseline_value)
        missing["tooling"]["criticalFiles"].pop()
        variants.append(
            ("missing", missing, "RECEIPT_SCHEMA", "critical-files-count")
        )
        extra = copy.deepcopy(baseline_value)
        extra["tooling"]["criticalFiles"].append(
            copy.deepcopy(extra["tooling"]["criticalFiles"][-1])
        )
        variants.append(
            (
                "extra",
                extra,
                "RECEIPT_SCHEMA",
                "critical-file-path-order",
            )
        )
        reordered = copy.deepcopy(baseline_value)
        reordered["tooling"]["criticalFiles"][0:2] = reversed(
            reordered["tooling"]["criticalFiles"][0:2]
        )
        variants.append(
            (
                "reordered",
                reordered,
                "RECEIPT_SCHEMA",
                "critical-file-path-order",
            )
        )
        wrong_path = copy.deepcopy(baseline_value)
        wrong_path["tooling"]["criticalFiles"][0]["path"] = (
            "developer/not-a-critical-tool.mjs"
        )
        variants.append(
            (
                "wrong-path",
                wrong_path,
                "RECEIPT_SCHEMA",
                "critical-file-path-order",
            )
        )
        wrong_blob = copy.deepcopy(baseline_value)
        wrong_blob["tooling"]["criticalFiles"][0]["gitBlobId"] = "0" * 40
        variants.append(
            ("wrong-blob", wrong_blob, "TOOLING", "critical-file-mismatch")
        )
        wrong_hash = copy.deepcopy(baseline_value)
        wrong_hash["tooling"]["criticalFiles"][0]["sha256"] = "0" * 64
        variants.append(
            ("wrong-hash", wrong_hash, "TOOLING", "critical-file-mismatch")
        )
        wrong_length = copy.deepcopy(baseline_value)
        wrong_length["tooling"]["criticalFiles"][0]["byteLength"] += 1
        variants.append(
            ("wrong-length", wrong_length, "TOOLING", "critical-file-mismatch")
        )
        wrong_commit = copy.deepcopy(baseline_value)
        wrong_commit["tooling"]["commit"] = self.source_commit
        variants.append(
            (
                "wrong-tooling-commit",
                wrong_commit,
                "TOOLING",
                "head-tooling-commit",
            )
        )

        for index, (label, value, phase, reason) in enumerate(variants):
            with self.subTest(case=label):
                target = self.case_base / f"tooling-{index}{RECEIPT_SUFFIX}"
                target.write_bytes(_independent_receipt_bytes(value))
                response = self._run_api(
                    "verifier",
                    self._verifier_options("full", artifacts, target),
                )
                self._assert_api_error(response, phase, reason)

    def test_06_tooling_commit_type_and_signature_boundaries(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        blob_id = self._git(
            "rev-parse", f"{self.tooling_commit}:developer/public-source-receipt-core.mjs"
        ).stdout.decode("ascii").strip()
        non_commit = self._run_api(
            "generator",
            self._generator_options(artifacts, toolingCommit=blob_id),
        )
        self._assert_api_error(non_commit, "TOOLING", "commit-object-type")

        missing_tools = self._run_api(
            "generator",
            self._generator_options(artifacts, toolingCommit=self.source_commit),
        )
        self._assert_api_error(missing_tools, "TOOLING", "head-tooling-commit")

        signature_failure = self._run_api(
            "generator",
            self._generator_options(artifacts),
            signature_mode="failure",
        )
        self._assert_api_error(
            signature_failure, "TOOLING", "tooling-commit-signature"
        )
        self.assertEqual(
            signature_failure["observations"]["signatureCalls"], 1
        )
        self.assertFalse(self.output_path.exists())

        returned_value = self._run_api(
            "generator",
            self._generator_options(artifacts),
            signature_mode="return-value",
        )
        self._assert_api_error(
            returned_value, "TOOLING", "signature-adapter-return-value"
        )

        cli_arguments = [
            "--repo",
            str(self.fixture_root),
            "--source-commit",
            self.source_commit,
            "--tooling-commit",
            self.tooling_commit,
            "--source-archive",
            str(self.source_archive),
            "--artifact",
            str(artifacts[0]["role"]),
            str(artifacts[0]["format"]),
            str(artifacts[0]["path"]),
            "--output",
            str(self.output_path),
        ]
        production = self._run_cli(
            self.fixture_root / "developer/prepare-public-source-receipt.mjs",
            cli_arguments,
        )
        self.assertNotEqual(production.returncode, 0)
        self.assertEqual(production.stdout, "")
        self.assertEqual(
            production.stderr,
            "ERROR TOOLING: tooling commit or critical-tool verification failed\n",
        )
        self.assertFalse(self.output_path.exists())
        self._assert_no_canary(production.stderr)

    def test_07_critical_paths_reject_symlink_submodule_tree_and_missing(self) -> None:
        target = CRITICAL_TOOL_PATHS[0]
        symlink_blob = self._git(
            "hash-object", "-w", "--stdin", input_bytes=b"synthetic-target\n"
        ).stdout.decode("ascii").strip()
        empty_tree = self._git("mktree", input_bytes=b"").stdout.decode(
            "ascii"
        ).strip()
        variants = (
            ("symlink", "120000", "blob", symlink_blob),
            ("submodule", "160000", "commit", self.source_commit),
            ("tree", "040000", "tree", empty_tree),
            ("missing", None, None, None),
        )
        for label, mode, object_type, object_id in variants:
            with self.subTest(case=label):
                commit = self._commit_with_critical_entry(
                    relative=target,
                    mode=mode,
                    object_type=object_type,
                    object_id=object_id,
                )
                response = self._run_api(
                    "derive",
                    {"repo": str(self.fixture_root), "toolingCommit": commit},
                )
                expected = (
                    "critical-tool-set" if label == "missing" else "critical-tree-entry"
                )
                self._assert_api_error(response, "TOOLING", expected)

    def test_08_dirty_head_index_untracked_replace_and_active_ops_fail(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))

        def run_for(base: Path, root: Path, output_name: str) -> dict[str, object]:
            output = base / f"{output_name}{RECEIPT_SUFFIX}"
            return self._run_api(
                "generator",
                self._generator_options_for_root(root, artifacts, output),
                environment_updates=self._environment_for_root(base, root),
            )

        dirty_paths = (
            "developer/prepare-public-source-receipt.mjs",
            "developer/public-source-receipt-core.mjs",
            "developer/verify-public-source-receipt.mjs",
            "developer/verify-public-source-archive.mjs",
            "developer/public-source-archive-core.mjs",
        )
        for index, relative in enumerate(dirty_paths):
            with self.subTest(dirty=relative), self._fresh_case_copy(
                f"dirty-{index}"
            ) as (base, root):
                with (root / PurePosixPath(relative)).open("ab") as stream:
                    stream.write(b"// synthetic dirty byte\n")
                response = run_for(base, root, f"dirty-{index}")
                self._assert_api_error(response, "TOOLING", "dirty-worktree")

        with self._fresh_case_copy("staged") as (base, root):
            target = root / "developer/public-source-receipt-core.mjs"
            with target.open("ab") as stream:
                stream.write(b"// staged synthetic change\n")
            self._git_at(root, "add", "--", "developer/public-source-receipt-core.mjs")
            response = run_for(base, root, "staged")
            self._assert_api_error(response, "TOOLING", "dirty-worktree")

        with self._fresh_case_copy("untracked") as (base, root):
            _write_at(root, "developer/untracked-shadow-module.mjs", b"export {};\n")
            response = run_for(base, root, "untracked")
            self._assert_api_error(response, "TOOLING", "dirty-worktree")

        with self._fresh_case_copy("head-mismatch") as (base, root):
            _write_at(root, "synthetic-not-selected/head-mismatch.txt", b"new head\n")
            self._git_at(root, "add", "--", "synthetic-not-selected/head-mismatch.txt")
            self._git_at(
                root,
                "commit",
                "-m",
                "synthetic head mismatch",
                commit_date="2004-05-06T07:08:09Z",
            )
            response = run_for(base, root, "head-mismatch")
            self._assert_api_error(response, "TOOLING", "head-tooling-commit")

        with self._fresh_case_copy("replacement") as (base, root):
            self._git_at(root, "replace", self.source_commit, self.tooling_commit)
            response = run_for(base, root, "replacement")
            self._assert_api_error(response, "TOOLING", "replacement-object-ref")

        with self._fresh_case_copy("active-operation") as (base, root):
            git_dir_text = self._git_at(root, "rev-parse", "--git-dir").stdout.decode(
                "utf-8"
            ).strip()
            git_dir = Path(git_dir_text)
            if not git_dir.is_absolute():
                git_dir = root / git_dir
            (git_dir / "MERGE_HEAD").write_text(
                self.source_commit + "\n", encoding="ascii", newline="\n"
            )
            response = run_for(base, root, "active-operation")
            self._assert_api_error(response, "TOOLING", "active-git-operation")

    def test_09_hostile_git_node_and_module_redirection_state(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        hostile_output = self.case_base / f"hostile-git{RECEIPT_SUFFIX}"
        hostile_git = {
            "GIT_DIR": str(self.case_base / "hostile-git-dir"),
            "GIT_WORK_TREE": str(self.case_base / "hostile-work-tree"),
            "GIT_INDEX_FILE": str(self.case_base / "hostile-index"),
            "GIT_OBJECT_DIRECTORY": str(self.case_base / "hostile-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(
                self.case_base / "hostile-alternates"
            ),
            "GIT_REPLACE_REF_BASE": "refs/hostile-replacements/",
            "GIT_CONFIG_GLOBAL": str(self.case_base / "hostile-global-config"),
            "GIT_CONFIG_SYSTEM": str(self.case_base / "hostile-system-config"),
            "GIT_SSH_COMMAND": CANARIES["environment_value"],
        }
        hostile = self._run_api(
            "generator",
            self._generator_options(artifacts, hostile_output),
            environment_updates=hostile_git,
        )
        self.assertTrue(hostile["ok"], hostile)
        self.assertTrue(hostile_output.is_file())

        redirections: list[tuple[str, dict[str, str] | None, list[str] | None]] = [
            ("node-options", {"NODE_OPTIONS": "--no-warnings"}, None),
            ("node-path", {"NODE_PATH": str(self.case_base)}, None),
            ("preload-long", None, ["--require", "node:path"]),
            ("import", None, ["--import=data:text/javascript,0"]),
        ]
        loader = self.case_base / "synthetic-loader.mjs"
        loader.write_text(
            "export async function resolve(s,c,n){return n(s,c);}\n"
            "export async function load(u,c,n){return n(u,c);}\n",
            encoding="utf-8",
            newline="\n",
        )
        redirections.append(
            ("loader", None, ["--no-warnings", f"--loader={loader.as_uri()}"])
        )
        for index, (label, env_updates, node_prefix) in enumerate(redirections):
            with self.subTest(case=label):
                output = self.case_base / f"redirect-{index}{RECEIPT_SUFFIX}"
                response = self._run_api(
                    "generator",
                    self._generator_options(artifacts, output),
                    environment_updates=env_updates,
                    node_prefix=node_prefix,
                )
                expected_reason = (
                    "node-environment-redirection"
                    if label in {"node-options", "node-path"}
                    else "node-process-redirection"
                )
                self._assert_api_error(response, "TOOLING", expected_reason)
                self.assertFalse(output.exists())

        short_preload = subprocess.run(
            [str(self.node), "-rnode:path", "--version"],
            cwd=self.case_base,
            env=self._case_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertNotEqual(short_preload.returncode, 0)
        self.assertEqual(short_preload.stdout, "")
        self.assertIn("bad option", short_preload.stderr)
        self.assertIn('argument.startsWith("-r")', RECEIPT_CORE.read_text(encoding="utf-8"))

        shadow = self.case_base / "synthetic-shadow"
        shadow.mkdir()
        shutil.copyfile(RECEIPT_GENERATOR, shadow / RECEIPT_GENERATOR.name)
        shutil.copyfile(RECEIPT_CORE, shadow / RECEIPT_CORE.name)
        shadow_output = self.case_base / f"shadow{RECEIPT_SUFFIX}"
        shadowed = self._run_api(
            "generator",
            self._generator_options(artifacts, shadow_output),
            environment_updates={
                "IELTMPS_TEST_GENERATOR": str(shadow / RECEIPT_GENERATOR.name),
                "IELTMPS_TEST_CORE": str(shadow / RECEIPT_CORE.name),
            },
        )
        self._assert_api_error(shadowed, "TOOLING", "canonical-module-location")
        self.assertFalse(shadow_output.exists())

    def test_10_source_archive_and_receipt_source_identities_are_b3_owned(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        baseline_value, baseline_bytes = self._build_receipt_for_artifacts(artifacts)
        self._write_receipt(baseline_bytes)
        valid = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self.assertTrue(valid["ok"], valid)
        self.assertNotEqual(self.source_commit, self.tooling_commit)

        original_archive = self.source_archive.read_bytes()
        mutations: list[tuple[str, bytes]] = []
        flipped = bytearray(original_archive)
        flipped[len(flipped) // 2] ^= 0x01
        mutations.append(("mutation", bytes(flipped)))
        mutations.append(("truncation", original_archive[:-512]))
        for label, archive_bytes in mutations:
            with self.subTest(archive=label):
                self.source_archive.write_bytes(archive_bytes)
                response = self._run_api(
                    "verifier", self._verifier_options("full", artifacts)
                )
                self._assert_api_error(response, "SOURCE_ARCHIVE", "b3-verifier")
                self.source_archive.write_bytes(original_archive)

        replacement = self._run_api(
            "verifier",
            self._verifier_options("full", artifacts),
            checkpoint_action="archive-replacement-before-worker",
            mutation_path=self.source_archive,
        )
        self._assert_api_error(replacement, "SOURCE_ARCHIVE", "b3-verifier")
        self.source_archive.write_bytes(original_archive)

        variants: list[tuple[str, dict[str, object], str, str]] = []
        wrong_commit = copy.deepcopy(baseline_value)
        wrong_commit["source"]["commit"] = self.tooling_commit
        variants.append(
            ("wrong-source-commit", wrong_commit, "SOURCE_ARCHIVE", "b3-verifier")
        )
        wrong_archive_hash = copy.deepcopy(baseline_value)
        wrong_archive_hash["source"]["archive"]["sha256"] = "0" * 64
        variants.append(
            (
                "wrong-archive-hash",
                wrong_archive_hash,
                "SOURCE_ARCHIVE",
                "receipt-source-binding",
            )
        )
        wrong_archive_length = copy.deepcopy(baseline_value)
        wrong_archive_length["source"]["archive"]["byteLength"] += 1
        variants.append(
            (
                "wrong-archive-length",
                wrong_archive_length,
                "SOURCE_ARCHIVE",
                "receipt-source-binding",
            )
        )
        wrong_manifest = copy.deepcopy(baseline_value)
        wrong_manifest["source"]["manifestSha256"] = "0" * 64
        variants.append(
            (
                "wrong-manifest",
                wrong_manifest,
                "SOURCE_ARCHIVE",
                "receipt-source-binding",
            )
        )
        wrong_report = copy.deepcopy(baseline_value)
        wrong_report["source"]["membershipReportSha256"] = "0" * 64
        variants.append(
            (
                "wrong-membership-report",
                wrong_report,
                "SOURCE_ARCHIVE",
                "receipt-source-binding",
            )
        )
        wrong_counts = copy.deepcopy(baseline_value)
        wrong_counts["source"]["membershipCount"] += 1
        wrong_counts["source"]["archive"]["memberCount"] += 1
        variants.append(
            (
                "wrong-membership-and-member-count",
                wrong_counts,
                "SOURCE_ARCHIVE",
                "receipt-source-binding",
            )
        )
        wrong_member_only = copy.deepcopy(baseline_value)
        wrong_member_only["source"]["archive"]["memberCount"] += 1
        variants.append(
            (
                "wrong-member-count-only",
                wrong_member_only,
                "RECEIPT_SCHEMA",
                "archive-member-count",
            )
        )
        wrong_format = copy.deepcopy(baseline_value)
        wrong_format["source"]["archive"]["format"] = "tar-pax-v1"
        variants.append(
            (
                "wrong-format",
                wrong_format,
                "RECEIPT_SCHEMA",
                "archive-format",
            )
        )
        for index, (label, value, phase, reason) in enumerate(variants):
            with self.subTest(identity=label):
                target = self.case_base / f"source-identity-{index}{RECEIPT_SUFFIX}"
                target.write_bytes(_independent_receipt_bytes(value))
                response = self._run_api(
                    "verifier",
                    self._verifier_options("full", artifacts, target),
                )
                self._assert_api_error(response, phase, reason)

        archive_link = self.case_base / "source-archive-hard-link.tar"
        os.link(self.source_archive, archive_link)
        hard_linked = self._run_api(
            "verifier",
            self._verifier_options(
                "full", artifacts, sourceArchive=str(self.source_archive)
            ),
        )
        self._assert_api_error(hard_linked, "SOURCE_ARCHIVE", "b3-verifier")

        cli = self._run_cli(
            self.fixture_root / "developer/verify-public-source-receipt.mjs",
            [
                "--full",
                "--repo",
                str(self.fixture_root),
                "--receipt",
                str(self.output_path),
                "--source-archive",
                str(self.source_archive),
                "--artifact",
                str(artifacts[0]["role"]),
                str(artifacts[0]["format"]),
                str(artifacts[0]["path"]),
                "--source-commit",
                self.source_commit,
            ],
        )
        self.assertNotEqual(cli.returncode, 0)
        self.assertEqual(
            cli.stderr,
            "ERROR CLI: invalid command line or imported API options\n",
        )

    def test_11_artifact_set_identity_count_duplicates_and_replacement(self) -> None:
        artifacts = self._artifacts()
        _, receipt_bytes = self._build_receipt_for_artifacts(artifacts)
        self._write_receipt(receipt_bytes)

        first_path = Path(str(artifacts[0]["path"]))
        original_first = first_path.read_bytes()
        first_path.write_bytes(b"same-size-artifact-mutation".ljust(len(original_first), b"!"))
        mutated = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self._assert_api_error(mutated, "ARTIFACT", "artifact-set-binding")
        first_path.write_bytes(original_first)
        first_path.write_bytes(original_first[:-1])
        truncated = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self._assert_api_error(truncated, "ARTIFACT", "artifact-set-binding")
        first_path.write_bytes(original_first)

        replacement_output = self.case_base / f"artifact-race{RECEIPT_SUFFIX}"
        replacement = self._run_api(
            "generator",
            self._generator_options(artifacts, replacement_output),
            checkpoint_action="artifact-replacement",
            mutation_path=first_path,
        )
        self._assert_api_error(replacement, "ARTIFACT", "artifact-identity")
        self.assertFalse(replacement_output.exists())
        if first_path.with_name(first_path.name + ".open-handle-original").exists():
            first_path.with_name(first_path.name + ".open-handle-original").unlink()
        first_path.write_bytes(original_first)

        linked = self.case_base / "artifact-hard-link.bin"
        os.link(first_path, linked)
        hard_linked = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self._assert_api_error(hard_linked, "ARTIFACT", "artifact-input-state")
        linked.unlink()

        symlink = self.case_base / "artifact-symbolic-link.bin"
        symlink_supported = True
        try:
            os.symlink(first_path, symlink)
        except (OSError, NotImplementedError):
            symlink_supported = False
        if symlink_supported:
            symlink_artifacts = copy.deepcopy(artifacts)
            symlink_artifacts[0]["path"] = str(symlink)
            response = self._run_api(
                "verifier", self._verifier_options("full", symlink_artifacts)
            )
            self._assert_api_error(response, "ARTIFACT", "artifact-input-state")
        else:
            core_source = RECEIPT_CORE.read_text(encoding="utf-8")
            self.assertIn("state.isSymbolicLink()", core_source)
            self.assertIn("realpath(syntax.targetPath)", core_source)

        missing = self._run_api(
            "verifier", self._verifier_options("full", artifacts[:-1])
        )
        self._assert_api_error(missing, "ARTIFACT", "artifact-set-count")

        one_value, one_bytes = self._build_receipt_for_artifacts([artifacts[0]])
        self.assertEqual(len(one_value["artifacts"]), 1)
        one_receipt = self.case_base / f"one-for-extra{RECEIPT_SUFFIX}"
        one_receipt.write_bytes(one_bytes)
        extra = self._run_api(
            "verifier",
            self._verifier_options("full", artifacts[:2], one_receipt),
        )
        self._assert_api_error(extra, "ARTIFACT", "artifact-set-count")

        duplicate_role = copy.deepcopy(artifacts[:2])
        duplicate_role[1]["role"] = duplicate_role[0]["role"]
        duplicate_role[1]["format"] = duplicate_role[0]["format"]
        duplicate_response = self._run_api(
            "generator",
            self._generator_options(
                duplicate_role, self.case_base / f"duplicate-role{RECEIPT_SUFFIX}"
            ),
        )
        self._assert_api_error(
            duplicate_response, "ARTIFACT", "duplicate-artifact-role"
        )

        identical = copy.deepcopy(artifacts[:2])
        Path(str(identical[1]["path"])).write_bytes(
            Path(str(identical[0]["path"])).read_bytes()
        )
        identical_response = self._run_api(
            "generator",
            self._generator_options(
                identical, self.case_base / f"duplicate-hash{RECEIPT_SUFFIX}"
            ),
        )
        self._assert_api_error(
            identical_response, "ARTIFACT", "duplicate-artifact-bytes"
        )

        unknown = copy.deepcopy(artifacts[:1])
        unknown[0]["role"] = "caller-defined-role"
        unknown_response = self._run_api(
            "generator",
            self._generator_options(
                unknown, self.case_base / f"unknown-role{RECEIPT_SUFFIX}"
            ),
        )
        self._assert_api_error(unknown_response, "ARTIFACT", "unknown-role-format")

        zero = self._run_api(
            "generator",
            self._generator_options(
                [], self.case_base / f"zero-artifacts{RECEIPT_SUFFIX}"
            ),
        )
        self._assert_api_error(zero, "CLI", "api-required-option")
        too_many = [copy.deepcopy(artifacts[0]) for _ in range(MAX_ARTIFACTS + 1)]
        over_limit = self._run_api(
            "generator",
            self._generator_options(
                too_many, self.case_base / f"too-many-artifacts{RECEIPT_SUFFIX}"
            ),
        )
        self._assert_api_error(over_limit, "CLI", "api-required-option")

        source_only_null_options = self._verifier_options(
            "source-only", artifacts
        )
        source_only_null_options["artifacts"] = None
        source_only_null = self._run_api(
            "verifier", source_only_null_options
        )
        self._assert_api_error(source_only_null, "CLI", "api-artifacts-array")

        caller_identity = self._api_artifacts(artifacts[:1])
        caller_identity[0]["sha256"] = "0" * 64
        caller_hash_options = self._generator_options(
            artifacts[:1], self.case_base / f"caller-hash{RECEIPT_SUFFIX}"
        )
        caller_hash_options["artifacts"] = caller_identity
        caller_hash = self._run_api("generator", caller_hash_options)
        self._assert_api_error(caller_hash, "ARTIFACT", "artifact-input-shape")

    def test_12_receipt_input_output_parent_suffix_and_existing_boundaries(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        relative = self._run_api(
            "generator",
            self._generator_options(artifacts, "relative.source-receipt.json"),
        )
        self._assert_api_error(relative, "OUTPUT_PARENT", "absolute-path")

        inside = self.fixture_root / f"inside{RECEIPT_SUFFIX}"
        inside_response = self._run_api(
            "generator", self._generator_options(artifacts, inside)
        )
        self._assert_api_error(
            inside_response,
            "OUTPUT_PARENT",
            "receipt-output-repository-containment",
        )
        self.assertFalse(inside.exists())

        equal_repo = self._run_api(
            "generator", self._generator_options(artifacts, self.fixture_root)
        )
        self._assert_api_error(
            equal_repo, "OUTPUT_PARENT", "receipt-output-suffix"
        )

        missing_parent_output = (
            self.case_base / "missing-parent" / f"missing{RECEIPT_SUFFIX}"
        )
        missing_parent = self._run_api(
            "generator", self._generator_options(artifacts, missing_parent_output)
        )
        self._assert_api_error(missing_parent, "OUTPUT_PARENT", "parent-directory")
        self.assertFalse(missing_parent_output.parent.exists())

        wrong_suffix_output = self.case_base / "wrong-suffix.json"
        wrong_suffix = self._run_api(
            "generator", self._generator_options(artifacts, wrong_suffix_output)
        )
        self._assert_api_error(
            wrong_suffix, "OUTPUT_PARENT", "receipt-output-suffix"
        )

        sentinel = b"preexisting output sentinel\n"
        self.output_path.write_bytes(sentinel)
        existing = self._run_api(
            "generator", self._generator_options(artifacts)
        )
        self._assert_api_error(
            existing, "OUTPUT_PARENT", "receipt-output-exists"
        )
        self.assertEqual(self.output_path.read_bytes(), sentinel)

        symlink_parent = self.case_base / "output-parent-alias"
        real_parent = self.case_base / "real-output-parent"
        real_parent.mkdir()
        symlink_supported = True
        try:
            os.symlink(real_parent, symlink_parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            symlink_supported = False
        if symlink_supported:
            alias_output = symlink_parent / f"alias{RECEIPT_SUFFIX}"
            alias_result = self._run_api(
                "generator", self._generator_options(artifacts, alias_output)
            )
            self._assert_api_error(alias_result, "OUTPUT_PARENT", "parent-directory")
            self.assertFalse((real_parent / alias_output.name).exists())
        else:
            core_source = RECEIPT_CORE.read_text(encoding="utf-8")
            self.assertIn("inspectRealDirectory", core_source)
            self.assertIn('reason + "-reparse"', core_source)

        _, receipt_bytes = self._build_receipt_for_artifacts(artifacts)
        external_receipt = self.case_base / f"external-input{RECEIPT_SUFFIX}"
        external_receipt.write_bytes(receipt_bytes)
        relative_input = self._run_api(
            "verifier",
            self._verifier_options("full", artifacts, "relative.source-receipt.json"),
        )
        self._assert_api_error(relative_input, "RECEIPT_VERIFY", "absolute-path")
        inside_input = self.fixture_root / f"inside-input{RECEIPT_SUFFIX}"
        inside_input.write_bytes(receipt_bytes)
        inside_verify = self._run_api(
            "verifier", self._verifier_options("full", artifacts, inside_input)
        )
        self._assert_api_error(
            inside_verify,
            "RECEIPT_VERIFY",
            "receipt-input-repository-containment",
        )

    def test_13_no_replace_collisions_hardlink_and_late_destination(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        late = self._run_api(
            "generator",
            self._generator_options(artifacts),
            checkpoint_action="late-destination",
        )
        self._assert_api_error(late, "PUBLISH", "destination-appeared")
        self.assertEqual(self.output_path.read_bytes(), b"late destination sentinel\n")
        self.output_path.unlink()

        collision_output = self.case_base / f"one-collision{RECEIPT_SUFFIX}"
        one_collision = self._run_api(
            "generator",
            self._generator_options(artifacts, collision_output),
            checkpoint_action="one-temporary-collision",
        )
        self.assertTrue(one_collision["ok"], one_collision)
        self.assertTrue(collision_output.is_file())

        exhausted_output = self.case_base / f"collision-exhausted{RECEIPT_SUFFIX}"
        exhausted = self._run_api(
            "generator",
            self._generator_options(artifacts, exhausted_output),
            checkpoint_action="all-temporary-collisions",
        )
        self._assert_api_error(
            exhausted, "RECEIPT_WRITE", "temporary-collision-exhaustion"
        )
        self.assertFalse(exhausted_output.exists())

        unsupported_output = self.case_base / f"unsupported-link{RECEIPT_SUFFIX}"
        unsupported = self._run_api(
            "generator",
            self._generator_options(artifacts, unsupported_output),
            link_action="unsupported",
        )
        self._assert_api_error(unsupported, "RECEIPT_WRITE", "receipt-publication")
        self.assertEqual(unsupported["observations"]["linkCalls"], 1)
        self.assertFalse(unsupported_output.exists())
        unsupported_temps = [
            path
            for path in self.case_base.iterdir()
            if path.name.startswith(f".{unsupported_output.name}.ieltmps-source-receipt-tmp-")
        ]
        self.assertEqual(unsupported_temps, [])

        existing_bytes = collision_output.read_bytes()
        repeat = self._run_api(
            "generator",
            self._generator_options(artifacts, collision_output),
        )
        self._assert_api_error(repeat, "OUTPUT_PARENT", "receipt-output-exists")
        self.assertEqual(collision_output.read_bytes(), existing_bytes)

        core_source = RECEIPT_CORE.read_text(encoding="utf-8")
        self.assertIn("await publicationLink(temporary.path, outputBoundary.targetPath)", core_source)
        self.assertNotIn("rename(", core_source)
        self.assertNotIn("copyFile", core_source)

    def test_14_post_link_rollback_and_identity_uncertain_cleanup(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))

        after_link_output = self.case_base / f"after-link{RECEIPT_SUFFIX}"
        after_link = self._run_api(
            "generator",
            self._generator_options(artifacts, after_link_output),
            checkpoint_action="throw-after-link",
        )
        self._assert_api_error(after_link, "RECEIPT_WRITE", "receipt-publication")
        self.assertFalse(after_link_output.exists())
        self.assertEqual(
            [
                path
                for path in self.case_base.iterdir()
                if path.name.startswith(
                    f".{after_link_output.name}.ieltmps-source-receipt-tmp-"
                )
            ],
            [],
        )

        link_throw_output = self.case_base / f"link-then-throw{RECEIPT_SUFFIX}"
        link_throw = self._run_api(
            "generator",
            self._generator_options(artifacts, link_throw_output),
            link_action="link-then-throw",
        )
        self._assert_api_error(link_throw, "RECEIPT_WRITE", "receipt-publication")
        self.assertFalse(link_throw_output.exists())

        final_verify_output = self.case_base / f"final-verify{RECEIPT_SUFFIX}"
        final_verify = self._run_api(
            "generator",
            self._generator_options(artifacts, final_verify_output),
            checkpoint_action="throw-after-final-verify",
        )
        self._assert_api_error(
            final_verify, "RECEIPT_WRITE", "receipt-publication"
        )
        self.assertFalse(final_verify_output.exists())

        temporary_output = self.case_base / f"temporary-substitution{RECEIPT_SUFFIX}"
        temporary_substitution = self._run_api(
            "generator",
            self._generator_options(artifacts, temporary_output),
            checkpoint_action="temporary-substitution",
        )
        self._assert_api_error(
            temporary_substitution, "CLEANUP", "receipt-publication-cleanup"
        )
        self.assertFalse(temporary_output.exists())
        suspect_temps = [
            path
            for path in self.case_base.iterdir()
            if path.name.startswith(
                f".{temporary_output.name}.ieltmps-source-receipt-tmp-"
            )
        ]
        self.assertEqual(len(suspect_temps), 1)
        self.assertEqual(
            suspect_temps[0].read_bytes(), b"suspect temporary replacement\n"
        )

        final_output = self.case_base / f"final-substitution{RECEIPT_SUFFIX}"
        final_substitution = self._run_api(
            "generator",
            self._generator_options(artifacts, final_output),
            checkpoint_action="final-substitution",
        )
        self._assert_api_error(
            final_substitution, "CLEANUP", "receipt-publication-cleanup"
        )
        self.assertEqual(final_output.read_bytes(), b"suspect final replacement\n")

        mutation_output = self.case_base / f"post-publication{RECEIPT_SUFFIX}"
        post_mutation = self._run_api(
            "generator",
            self._generator_options(artifacts, mutation_output),
            checkpoint_action="post-publication-mutation",
        )
        self._assert_api_error(
            post_mutation, "CLEANUP", "receipt-publication-cleanup"
        )
        self.assertIn(b"post-publication mutation\n", mutation_output.read_bytes())

    def test_15_privacy_canaries_absent_from_bytes_success_and_failures(self) -> None:
        self.assertEqual(len(CANARIES), 15)
        self.assertEqual(len(set(CANARIES.values())), 15)
        artifacts = self._artifacts()
        generated = self._run_api(
            "generator", self._generator_options(artifacts)
        )
        self.assertTrue(generated["ok"], generated)
        full = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        partial = self._run_api(
            "verifier", self._verifier_options("source-only", artifacts)
        )
        self.assertTrue(full["ok"], full)
        self.assertTrue(partial["ok"], partial)
        self._assert_no_canary(self.output_path.read_bytes())
        self._assert_no_canary(
            json.dumps(generated["result"], separators=(",", ":"))
        )
        self._assert_no_canary(json.dumps(full["result"], separators=(",", ":")))
        self._assert_no_canary(
            json.dumps(partial["result"], separators=(",", ":"))
        )

        unknown = copy.deepcopy(artifacts[:1])
        unknown[0]["role"] = "privacy-failure-unknown-role"
        generator_failure = self._run_api(
            "generator",
            self._generator_options(
                unknown, self.case_base / f"privacy-failure{RECEIPT_SUFFIX}"
            ),
        )
        self.assertFalse(generator_failure["ok"])
        self._assert_no_canary(
            json.dumps(generator_failure, separators=(",", ":"))
        )
        Path(str(artifacts[0]["path"])).write_bytes(b"privacy verifier mutation\n")
        verifier_failure = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        self.assertFalse(verifier_failure["ok"])
        self._assert_no_canary(
            json.dumps(verifier_failure, separators=(",", ":"))
        )

        production_failure = self._run_cli(
            self.fixture_root / "developer/prepare-public-source-receipt.mjs",
            ["--repo", str(self.fixture_root), "--signature-bypass"],
        )
        self.assertNotEqual(production_failure.returncode, 0)
        self._assert_no_canary(production_failure.stderr)

    def test_16_imports_direct_execution_and_production_cli_are_exact(self) -> None:
        modules = (
            self.fixture_root / "developer/public-source-receipt-core.mjs",
            self.fixture_root / "developer/prepare-public-source-receipt.mjs",
            self.fixture_root / "developer/verify-public-source-receipt.mjs",
        )
        import_temp = self.case_base / "import-only-temp"
        import_temp.mkdir()
        import_script = (
            "import { pathToFileURL } from 'node:url';"
            "const before=process.exitCode;"
            "await import(pathToFileURL(process.argv[2]).href);"
            "if(process.exitCode!==before)throw new Error('exitCode mutation');"
        )
        for module in modules:
            with self.subTest(module=module.name):
                trace = import_temp / f"{module.name}.git-trace"
                environment = self._case_environment(
                    {
                        "TEMP": str(import_temp),
                        "TMP": str(import_temp),
                        "TMPDIR": str(import_temp),
                        "GIT_TRACE2_EVENT": str(trace),
                    }
                )
                before_status = self._git("status", "--porcelain").stdout
                completed = subprocess.run(
                    [
                        str(self.node),
                        "--input-type=module",
                        "--eval",
                        import_script,
                        "import-harness-sentinel",
                        str(module),
                    ],
                    cwd=self.case_base,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=60,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr, b"")
                self.assertFalse(trace.exists())
                self.assertEqual(self._git("status", "--porcelain").stdout, before_status)

        generator = self.fixture_root / "developer/prepare-public-source-receipt.mjs"
        verifier = self.fixture_root / "developer/verify-public-source-receipt.mjs"
        invocations = (
            (generator, str(generator)),
            (generator, os.path.relpath(generator, self.case_base)),
            (generator, str(generator.parent / "." / generator.name)),
            (verifier, str(verifier)),
            (verifier, os.path.relpath(verifier, self.case_base)),
            (verifier, str(verifier.parent / "." / verifier.name)),
        )
        for script, spelling in invocations:
            with self.subTest(script=script.name, spelling=spelling):
                completed = self._run_cli(spelling, [], cwd=self.case_base)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(
                    completed.stderr,
                    "ERROR CLI: invalid command line or imported API options\n",
                )

        for forbidden in (
            "--signature-bypass",
            "--test-hook",
            "--overwrite",
            "--schema-version",
            "--archive-sha256",
            "--artifact-sha256",
            "--timestamp",
            "--sbom",
        ):
            with self.subTest(forbidden=forbidden):
                completed = self._run_cli(generator, [forbidden, "x"])
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(
                    completed.stderr,
                    "ERROR CLI: invalid command line or imported API options\n",
                )

        core_source = RECEIPT_CORE.read_text(encoding="utf-8")
        generator_source = RECEIPT_GENERATOR.read_text(encoding="utf-8")
        verifier_source = RECEIPT_VERIFIER.read_text(encoding="utf-8")
        self.assertIn('["verify-commit", "--raw", toolingCommit]', core_source)
        self.assertNotIn("signature-bypass", core_source + generator_source + verifier_source)
        self.assertNotIn("unsigned-success", core_source + generator_source + verifier_source)
        self.assertNotIn("process.env.IELTMPS", generator_source + verifier_source)
        self.assertNotIn("./prepare-public-source-archive.mjs", generator_source)
        self.assertIn(
            'from "./verify-public-source-archive.mjs"', verifier_source
        )
        self.assertIn("verifyPublicSourceArchive({", verifier_source)
        self.assertNotIn("preparePublicSourceArchive", verifier_source)

    def test_17_early_publication_checkpoint_failures_remove_known_temporaries(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        actions = (
            "throw-after-temp-create",
            "throw-before-temp-verify",
            "throw-before-publish",
        )
        for index, action in enumerate(actions):
            with self.subTest(action=action):
                output = self.case_base / f"checkpoint-{index}{RECEIPT_SUFFIX}"
                response = self._run_api(
                    "generator",
                    self._generator_options(artifacts, output),
                    checkpoint_action=action,
                )
                self._assert_api_error(
                    response, "RECEIPT_WRITE", "receipt-publication"
                )
                self.assertFalse(output.exists())
                temporary_paths = [
                    path
                    for path in self.case_base.iterdir()
                    if path.name.startswith(
                        f".{output.name}.ieltmps-source-receipt-tmp-"
                    )
                ]
                self.assertEqual(temporary_paths, [])

    def test_18_receipt_input_identity_suffix_hardlink_symlink_and_replacement(self) -> None:
        artifacts = self._artifacts((ARTIFACT_REGISTRY[1],))
        _, receipt_bytes = self._build_receipt_for_artifacts(artifacts)
        self._write_receipt(receipt_bytes)

        wrong_suffix = self.case_base / "receipt-input.json"
        wrong_suffix.write_bytes(receipt_bytes)
        wrong = self._run_api(
            "verifier", self._verifier_options("full", artifacts, wrong_suffix)
        )
        self._assert_api_error(
            wrong, "RECEIPT_VERIFY", "receipt-input-suffix"
        )

        receipt_link = self.case_base / f"receipt-hard-link{RECEIPT_SUFFIX}"
        os.link(self.output_path, receipt_link)
        hard_linked = self._run_api(
            "verifier", self._verifier_options("full", artifacts, self.output_path)
        )
        self._assert_api_error(
            hard_linked, "RECEIPT_VERIFY", "receipt-input-state"
        )
        receipt_link.unlink()

        receipt_symlink = self.case_base / f"receipt-symlink{RECEIPT_SUFFIX}"
        symlink_supported = True
        try:
            os.symlink(self.output_path, receipt_symlink)
        except (OSError, NotImplementedError):
            symlink_supported = False
        if symlink_supported:
            symlinked = self._run_api(
                "verifier",
                self._verifier_options("full", artifacts, receipt_symlink),
            )
            self._assert_api_error(
                symlinked, "RECEIPT_VERIFY", "receipt-input-state"
            )
        else:
            core_source = RECEIPT_CORE.read_text(encoding="utf-8")
            self.assertIn("state.isSymbolicLink()", core_source)

        replaced = self._run_api(
            "verifier",
            self._verifier_options("full", artifacts, self.output_path),
            checkpoint_action="receipt-replacement-before-worker",
            mutation_path=self.output_path,
        )
        self.assertFalse(replaced["ok"], replaced)
        self.assertIn(
            replaced["phase"], {"RECEIPT_SCHEMA", "RECEIPT_VERIFY"}, replaced
        )
        self.assertTrue(
            self.output_path.with_name(
                self.output_path.name + ".open-handle-original"
            ).exists()
        )

    def test_19_registry_schema_success_shapes_and_worker_isolation_are_fixed(self) -> None:
        artifacts = self._artifacts()
        generated = self._run_api(
            "generator", self._generator_options(artifacts)
        )
        self.assertTrue(generated["ok"], generated)
        self.assertTrue(generated["observations"]["resultFrozen"])
        full = self._run_api(
            "verifier", self._verifier_options("full", artifacts)
        )
        partial = self._run_api(
            "verifier", self._verifier_options("source-only", artifacts)
        )
        self.assertTrue(full["ok"], full)
        self.assertTrue(partial["ok"], partial)
        self.assertTrue(full["observations"]["resultFrozen"])
        self.assertTrue(partial["observations"]["resultFrozen"])
        self.assertEqual(
            list(generated["result"]),
            [
                "status",
                "mode",
                "receiptKind",
                "schemaVersion",
                "sourceCommit",
                "toolingCommit",
                "artifactCount",
                "receiptCreated",
                "receiptVerified",
                "receiptSha256",
                "receiptByteLength",
                "sourceArchiveVerified",
                "toolingCommitSignatureValid",
                "artifactsVerified",
                "correspondingSourceComplete",
                "publicationBlocked",
            ],
        )
        verifier_keys = [
            "status",
            "mode",
            "verificationComplete",
            "receiptKind",
            "schemaVersion",
            "sourceCommit",
            "toolingCommit",
            "artifactCount",
            "receiptSha256",
            "receiptByteLength",
            "sourceArchiveVerified",
            "toolingCommitSignatureValid",
            "artifactsVerified",
            "correspondingSourceComplete",
            "publicationBlocked",
        ]
        self.assertEqual(list(full["result"]), verifier_keys)
        self.assertEqual(list(partial["result"]), verifier_keys)

        core_source = RECEIPT_CORE.read_text(encoding="utf-8")
        self.assertIn(
            'role: "public-container-context-receipt"', core_source
        )
        self.assertIn('role: "standalone-release-archive"', core_source)
        self.assertIn('role: "standalone-release-receipt"', core_source)
        self.assertIn('format: "zip"', core_source)
        self.assertGreaterEqual(core_source.count('format: "json"'), 2)
        self.assertIn('mediaType: "application/zip"', core_source)
        self.assertGreaterEqual(
            core_source.count('mediaType: "application/json"'), 2
        )
        self.assertIn("prepare/verify-public-container-context.mjs", core_source)
        self.assertIn("release.ps1, release.sh", core_source)
        self.assertIn("standalone-release-manifest.mjs", core_source)
        self.assertIn('environment.GIT_NO_REPLACE_OBJECTS = "1"', core_source)
        self.assertIn("delete environment.NODE_OPTIONS", core_source)
        self.assertIn("delete environment.NODE_PATH", core_source)
        self.assertIn("cwd: toolDirectory.rootPath", core_source)
        self.assertIn("shell: false", core_source)
        self.assertIn("...CRITICAL_TOOL_PATHS", core_source)
        self.assertEqual(list(self.tool_temp.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
