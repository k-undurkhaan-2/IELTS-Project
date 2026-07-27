#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  constants as FS_CONSTANTS,
  realpathSync,
  writeSync,
} from "node:fs";
import {
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rmdir,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import { materializePublicSourceTree } from "./prepare-public-source-tree.mjs";
import {
  ZIP_ARCHIVE_ROOT,
  ZIP_FIELD_VALUES,
  ZIP_LIMITS,
  PublicSourceZipError,
  computeCanonicalZipLayout,
  crc32Bytes,
  createCanonicalZipEntryPlan,
  encodeCanonicalZipEntryPlan,
  encodeCentralDirectoryRecord,
  encodeEndOfCentralDirectory,
  encodeLocalFileHeader,
  parseCanonicalZipEntryPlanBytes,
  requireZip32Number,
  validateZipSourcePath,
} from "./public-source-zip-core.mjs";
import { preparePublicSourceZip } from "./prepare-public-source-zip.mjs";
import {
  encodeCanonicalZipVerificationResult,
  verifyPublicSourceZip,
} from "./verify-public-source-zip.mjs";
import {
  ARCHIVE_ROOT,
  ARTIFACT_ROLE,
  BOUNDARY_RESULT_KEYS,
  CANONICAL_FAILURE_OUTPUT_NAMES,
  CRITICAL_TOOL_PATHS,
  FORMAT_PROFILE,
  SUCCESS_OUTPUT_NAMES,
  VECTOR_EXECUTION_CLASSES,
  VECTOR_SET_ID,
  VECTOR_SET_KIND,
  WORKER_BOOTSTRAP_SOURCE,
  WORKER_CAPSULE_KIND,
  WORKER_CAPSULE_KEYS,
  WORKER_CAPSULE_MODULE_KEYS,
  WORKER_ENTRY_MODULE,
  WORKER_MODULE_PATHS,
  WORKER_PROTOCOL,
  PublicSourceZipReproducibilityError,
  assertProxyFreeAuthorityGraph,
  asZipReproducibilityError,
  canonicalPrivateJsonBytes,
  deepFreezeZipReproducibility,
  encodeCanonicalCriticalToolSet,
  failZipReproducibility,
  parseCanonicalPrivateJsonText,
  parseCanonicalPublicJsonBytes,
  privatePathSha256,
  sha256Bytes,
  validateBoundaryVectorResult,
  validateBoundaryVectorSet,
  validateLoadedByteAttestation,
  validateWorkerRequest,
  validateWorkerResponse,
  workerContextSha256,
} from "./public-source-zip-reproducibility-core.mjs";

const VECTOR_TEST_HOOK = Symbol.for(
  "ieltmps.public-source-zip-boundary-vectors.test-hook",
);
const VECTOR_AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([VECTOR_TEST_HOOK]),
  allowFunctions: true,
});
const CALLABLE_AUTHORITY_OPTIONS = Object.freeze({ allowFunctions: true });
const ASYNC_RESULT_AUTHORITY_OPTIONS = Object.freeze({ allowPromise: true });
const WORKER_CLAIM_BASENAME = ".claim";
const WORKER_CAPSULE_DIRECTORY = "worker-module-capsule";
const WORKER_CAPSULE_BASENAME = "worker-modules.capsule.json";
const WORKER_ARTIFACT_BASENAME = "artifact.zip";
const WORKER_PLAN_BASENAME = "entry-plan.json";
const WORKER_TREE_BASENAME = "source-tree";
const MAX_VECTOR_SET_BYTES = 1024 * 1024;
const MAX_WORKER_CAPSULE_BYTES = 16 * 1024 * 1024;
const MAX_WORKER_STDIO_BYTES = 64 * 1024;
const MAX_WORKER_RESPONSE_BYTES = 4 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SYNTHETIC_SOURCE_EXACT_PATHS = Object.freeze([
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
  "developer/public-source-manifest.json",
  "developer/release.ps1",
  "developer/release.sh",
  "developer/standalone-release-manifest.json",
  "developer/standalone-release-manifest.mjs",
  "developer/tests/ci/test_public_container_context.py",
  "developer/tests/ci/test_public_source_membership.py",
  "developer/tests/ci/test_standalone_packaging.py",
  "developer/verify-public-container-context.mjs",
  "developer/verify-public-source-membership.mjs",
]);
const SYNTHETIC_SOURCE_PREFIX_PATHS = Object.freeze([
  "backend/admin/example.js",
  "backend/auth/example.js",
  "backend/migrations/example.js",
  "backend/scripts/example.mjs",
  "backend/src/example.js",
  "backend/test/example.test.js",
  "css/example.css",
  "js/example.js",
  "src/styles/example.css",
]);

function descriptor(
  vectorId,
  executionClass,
  caseId,
  expectedOutcome,
  expectedPhase = null,
  expectedReason = null,
) {
  return Object.freeze({
    vectorId,
    executionClass,
    caseId,
    expectedOutcome,
    expectedPhase,
    expectedReason,
  });
}

const W_CASES = Object.freeze([
  "one-empty-file",
  "one-one-byte-file",
  "multiple-files",
  "utf8-filename",
  "maximum-approved-1024-byte-archive-filename",
  "unsigned-utf8-ordering",
  "crc-known-answer-vectors",
  "mode-100644",
  "mode-100755",
  "independently-built-full-round-trip",
]);

const L_CASES = Object.freeze([
  ["wrong-local-signature", "ZIP_PARSE", "local-signature"],
  ["wrong-version-needed", "ZIP_PROFILE", "version-needed"],
  ["unsupported-compression", "ZIP_PROFILE", "compression-method"],
  ["data-descriptor-flag", "ZIP_PROFILE", "general-purpose-flag"],
  ["encryption-flag", "ZIP_PROFILE", "general-purpose-flag"],
  ["missing-utf8-flag", "ZIP_PROFILE", "general-purpose-flag"],
  ["unsupported-flag", "ZIP_PROFILE", "general-purpose-flag"],
  ["local-extra", "ZIP_PROFILE", "local-metadata"],
  ["noncanonical-timestamp", "ZIP_PROFILE", "dos-time"],
  ["crc-mismatch", "ZIP_BINDING", "stored-payload-mismatch"],
  ["stored-size-mismatch", "ZIP_PROFILE", "local-metadata"],
  ["uncompressed-size-mismatch", "ZIP_PROFILE", "local-metadata"],
]);

const C_CASES = Object.freeze([
  ["wrong-central-signature", "ZIP_PARSE", "central-signature"],
  ["wrong-version-made-by", "ZIP_PROFILE", "version-made-by"],
  ["wrong-central-version-needed", "ZIP_PROFILE", "version-needed"],
  ["flags-method-mismatch", "ZIP_PROFILE", "general-purpose-flag"],
  ["timestamp-mismatch", "ZIP_PROFILE", "dos-time"],
  ["central-extra", "ZIP_PROFILE", "central-metadata"],
  ["file-comment", "ZIP_PROFILE", "central-metadata"],
  ["disk-start-value", "ZIP_PROFILE", "central-metadata"],
  ["internal-attributes", "ZIP_PROFILE", "central-metadata"],
  ["symlink-attributes", "ZIP_PROFILE", "central-metadata"],
  ["directory-entry-attributes", "ZIP_PROFILE", "central-metadata"],
  ["host-mode-leakage", "ZIP_PROFILE", "central-metadata"],
  ["local-central-filename-mismatch", "ZIP_BINDING", "local-central-filename"],
  ["local-central-crc-or-size-mismatch", "ZIP_BINDING", "central-entry-plan-mismatch"],
  ["wrong-local-offset", "ZIP_BINDING", "central-entry-plan-mismatch"],
  ["entry-reorder", "ZIP_BINDING", "central-filename"],
]);

const E_CASES = Object.freeze([
  ["wrong-eocd-signature", "ZIP_PARSE", "eocd-signature"],
  ["archive-comment", "ZIP_PROFILE", "archive-comment"],
  ["current-disk-value", "ZIP_PROFILE", "eocd-disk-number"],
  ["central-directory-disk-value", "ZIP_PROFILE", "eocd-central-disk"],
  ["count-mismatch", "ZIP_PROFILE", "eocd-entry-count"],
  ["central-length-mismatch", "ZIP_PARSE", "central-directory-range"],
  ["central-offset-mismatch", "ZIP_PARSE", "central-directory-range"],
  ["gap-before-central-directory", "ZIP_PARSE", "central-directory-range"],
  ["trailing-bytes", "ZIP_PARSE", "eocd-signature"],
  ["prepended-bytes", "ZIP_PARSE", "central-directory-range"],
  ["multiple-eocd-candidates", "ZIP_PARSE", "central-directory-range"],
  ["concatenated-zip", "ZIP_PARSE", "central-directory-range"],
  ["empty-archive", "ZIP_PROFILE", "eocd-entry-count"],
]);

const P_CASES = Object.freeze([
  ["leading-slash", "PATH_AUTHORITY", "source-path-not-portable-relative"],
  ["trailing-slash", "PATH_AUTHORITY", "source-path-not-portable-relative"],
  ["backslash", "PATH_AUTHORITY", "source-path-backslash"],
  ["drive-prefix", "PATH_AUTHORITY", "source-path-colon"],
  ["colon", "PATH_AUTHORITY", "source-path-colon"],
  ["nul", "PATH_AUTHORITY", "source-path-control-character"],
  ["empty-path-or-segment", "PATH_AUTHORITY", "source-path-not-portable-relative"],
  ["dot-segment", "PATH_AUTHORITY", "source-path-component"],
  ["dot-dot-segment", "PATH_AUTHORITY", "source-path-component"],
  ["repeated-separator", "PATH_AUTHORITY", "source-path-not-portable-relative"],
  ["duplicate-path", "PATH_AUTHORITY", "archive-path-collision"],
  ["case-collision", "PATH_AUTHORITY", "archive-path-collision"],
  ["normalization-collision", "PATH_AUTHORITY", "source-path-not-nfc"],
  ["invalid-utf8", "ENTRY_PLAN", "utf8-encoding"],
  ["overlong-filename", "PATH_AUTHORITY", "archive-path-too-long"],
  ["non-nfc-path", "PATH_AUTHORITY", "source-path-not-nfc"],
  ["overlong-component", "PATH_AUTHORITY", "source-path-component-too-long"],
  ["windows-reserved-component", "PATH_AUTHORITY", "source-path-reserved-name"],
  ["trailing-dot-or-space", "PATH_AUTHORITY", "source-path-trailing-dot-or-space"],
  ["uri-unc-or-device-prefix", "PATH_AUTHORITY", "source-path-colon"],
]);

const F_CASES = Object.freeze([
  ["mutation-during-source-read", "SOURCE_FILE", "source-file-identity"],
  ["same-size-source-replacement", "SOURCE_FILE", "source-file-identity"],
  ["source-truncation", "SOURCE_FILE", "source-file-truncated"],
  ["source-growth", "SOURCE_FILE", "source-file-growth"],
  ["parent-replacement", "SOURCE_FILE", "source-parent-identity"],
  ["archive-symlink-or-reparse", "PATH_AUTHORITY", "archive-file-state"],
  ["hard-link-anomaly", "PATH_AUTHORITY", "archive-file-state"],
  ["output-replacement", "OUTPUT_PUBLICATION", "final-target-exists"],
  ["mutation-during-archive-read", "ZIP_PARSE", "archive-identity"],
  ["same-size-archive-replacement", "ZIP_PARSE", "archive-identity"],
  ["archive-growth", "ZIP_PARSE", "archive-growth"],
  ["source-change-between-passes", "SOURCE_FILE", "source-file-identity"],
]);

const M_CASES = Object.freeze([
  ["independently-encoded-valid-zip", "accept", null, null],
  ["eocd-signature-inside-payload", "accept", null, null],
  ["zip64-extra", "reject", "ZIP_PROFILE", "central-metadata"],
  ["zip64-eocd", "reject", "ZIP_PARSE", "central-directory-range"],
  ["zip64-locator", "reject", "ZIP_PARSE", "central-directory-range"],
  ["65534-entry-virtual-acceptance", "accept", null, null],
  ["65535-entry-rejection", "reject", "ZIP_LAYOUT", "entry-count"],
  ["0xfffffffe-scalar-acceptance", "accept", null, null],
  ["0xffffffff-rejection", "reject", "ZIP_LAYOUT", "zip32-value"],
  ["offset-addition-overflow", "reject", "ZIP_LAYOUT", "stored-payload-end"],
  ["central-arithmetic-overflow", "reject", "ZIP_LAYOUT", "central-directory-end"],
  ["overlapping-data", "reject", "ZIP_PARSE", "stored-payload-range"],
  ["central-data-overlap", "reject", "ZIP_BINDING", "eocd-entry-plan-mismatch"],
  ["truncated-data", "reject", "ZIP_PARSE", "stored-payload-truncated"],
  ["unreferenced-local-header", "reject", "ZIP_BINDING", "eocd-entry-plan-mismatch"],
  ["digital-signature-record", "reject", "ZIP_PARSE", "central-signature"],
  ["archive-encryption-decryption-record", "reject", "ZIP_PARSE", "central-signature"],
  ["unexpected-structural-record", "reject", "ZIP_PARSE", "central-signature"],
]);

const R_CASES = Object.freeze([
  ["same-process-zip-equality", "accept", null, null],
  ["same-process-verifier-transcript-equality", "accept", null, null],
  ["distinct-same-process-paths", "accept", null, null],
  ["distinct-same-process-file-identities-and-reads", "accept", null, null],
  ["no-reuse-copy-or-hard-link", "accept", null, null],
  ["same-host-zip-equality", "accept", null, null],
  ["same-host-verifier-transcript-equality", "accept", null, null],
  ["four-output-equality-with-distinct-identities", "accept", null, null],
  ["locale-invariance", "accept", null, null],
  ["timezone-and-source-date-epoch-invariance", "accept", null, null],
  ["source-timestamp-invariance", "accept", null, null],
  ["source-permission-invariance", "accept", null, null],
  ["invalid-first-s1-message", "reject", "SAME_HOST", "worker-request-invalid"],
  ["hostile-second-s1-message", "accept", null, null],
  ["assignment-replay", "reject", "SAME_HOST", "worker-replay"],
  ["capsule-substitution", "reject", "TOOL_SET", "worker-loaded-bytes-mismatch"],
  ["natural-exit-stdio-and-ipc-binding", "accept", null, null],
  ["output-privacy-fixed-set-and-comparator-absence", "accept", null, null],
]);

function numbered(prefix, values, executionClass, shape = "reject") {
  return values.map((entry, index) => {
    const vectorId = prefix + String(index + 1).padStart(2, "0");
    if (typeof entry === "string") {
      return descriptor(vectorId, executionClass, entry, "accept");
    }
    if (shape === "reject") {
      return descriptor(vectorId, executionClass, entry[0], "reject", entry[1], entry[2]);
    }
    return descriptor(vectorId, executionClass, entry[0], entry[1], entry[2], entry[3]);
  });
}

export const BOUNDARY_VECTOR_DESCRIPTORS = Object.freeze([
  ...numbered("W", W_CASES, VECTOR_EXECUTION_CLASSES[0]),
  ...numbered("L", L_CASES, VECTOR_EXECUTION_CLASSES[1]),
  ...numbered("C", C_CASES, VECTOR_EXECUTION_CLASSES[2]),
  ...numbered("E", E_CASES, VECTOR_EXECUTION_CLASSES[3]),
  ...numbered("P", P_CASES, VECTOR_EXECUTION_CLASSES[4]),
  ...numbered("F", F_CASES, VECTOR_EXECUTION_CLASSES[5]),
  ...numbered("M", M_CASES, VECTOR_EXECUTION_CLASSES[6], "mixed"),
  ...numbered("R", R_CASES, VECTOR_EXECUTION_CLASSES[7], "mixed"),
]);

const EXECUTOR_ID_GROUPS = Object.freeze([
  Object.freeze(["W01", "W02", "W03", "W04", "W05", "W06", "W07", "W08", "W09", "W10"]),
  Object.freeze(["L01", "L02", "L03", "L04", "L05", "L06", "L07", "L08", "L09", "L10", "L11", "L12"]),
  Object.freeze(["C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11", "C12", "C13", "C14", "C15", "C16"]),
  Object.freeze(["E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08", "E09", "E10", "E11", "E12", "E13"]),
  Object.freeze(["P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10", "P11", "P12", "P13", "P14", "P15", "P16", "P17", "P18", "P19", "P20"]),
  Object.freeze(["F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08", "F09", "F10", "F11", "F12"]),
  Object.freeze(["M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M09", "M10", "M11", "M12", "M13", "M14", "M15", "M16", "M17", "M18"]),
  Object.freeze(["R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08", "R09", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18"]),
]);

export const BOUNDARY_VECTOR_EXECUTOR_IDS = Object.freeze(
  EXECUTOR_ID_GROUPS.flat(),
);

function executorDefinition(vectorId, executionClass, authenticity, execute) {
  return Object.freeze({
    vectorId,
    executionClass,
    authenticity,
    execute,
  });
}

function executorForGroup(vectorId, groupIndex) {
  const executionClass = VECTOR_EXECUTION_CLASSES[groupIndex];
  if (groupIndex === 0) {
    return executorDefinition(
      vectorId,
      executionClass,
      "production-operation",
      async ({ vector, root }) => {
        await executeWriterVector(vector, root);
        return Object.freeze({ outcome: "accept", phase: null, reason: null });
      },
    );
  }
  if (groupIndex >= 1 && groupIndex <= 3) {
    return executorDefinition(
      vectorId,
      executionClass,
      "production-operation",
      ({ vector, root, state }) => executeStructuralVector(
        vector,
        root,
        state.structuralFixture,
      ),
    );
  }
  if (groupIndex === 4) {
    return executorDefinition(
      vectorId,
      executionClass,
      "production-operation",
      ({ vector }) => executePathVector(vector),
    );
  }
  if (groupIndex === 5) {
    return executorDefinition(
      vectorId,
      executionClass,
      "authentic-file-identity",
      ({ vector, root }) => executeFileIdentityVector(vector, root),
    );
  }
  if (groupIndex === 6) {
    return executorDefinition(
      vectorId,
      executionClass,
      "authentic-malformed-zip",
      ({ vector, root, state }) => executeMalformedVector(
        vector,
        root,
        state.structuralFixture,
      ),
    );
  }
  if (groupIndex === 7) {
    return executorDefinition(
      vectorId,
      executionClass,
      "authentic-reproducibility",
      ({ vector, root, state }) => executeReproducibilityVector(
        vector,
        root,
        state,
      ),
    );
  }
  failVector(vectorId, "executor-registry-invalid");
}

const BOUNDARY_VECTOR_EXECUTOR_REGISTRY = new Map();
for (let groupIndex = 0; groupIndex < EXECUTOR_ID_GROUPS.length; groupIndex += 1) {
  for (const vectorId of EXECUTOR_ID_GROUPS[groupIndex]) {
    BOUNDARY_VECTOR_EXECUTOR_REGISTRY.set(
      vectorId,
      executorForGroup(vectorId, groupIndex),
    );
  }
}

export class PublicSourceZipBoundaryVectorError
  extends PublicSourceZipReproducibilityError {
  constructor(vectorId = null, reason = "boundary-vector-failed") {
    super("BOUNDARY_VECTOR", reason);
    this.name = "PublicSourceZipBoundaryVectorError";
    this.vectorId = typeof vectorId === "string" ? vectorId : null;
  }
}

function failVector(vectorId = null, reason = "boundary-vector-failed") {
  throw new PublicSourceZipBoundaryVectorError(vectorId, reason);
}

function canonicalNativePath(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function pathsEqual(left, right) {
  return canonicalNativePath(left) === canonicalNativePath(right);
}

function identityFromState(state) {
  return Object.freeze({
    device: state.dev,
    inode: state.ino,
    size: state.size,
    links: state.nlink,
    mode: state.mode,
    mtimeNs: state.mtimeNs,
    ctimeNs: state.ctimeNs,
    birthtimeNs: state.birthtimeNs,
    meaningful: state.dev !== 0n || state.ino !== 0n,
  });
}

function sameObject(left, right) {
  return Boolean(left && right && left.meaningful && right.meaningful)
    && left.device === right.device
    && left.inode === right.inode;
}

function cleanupIdentityKey(identity) {
  return identity.device.toString(10) + ":" + identity.inode.toString(10);
}

function identitiesEqual(left, right) {
  return Boolean(left && right)
    && left.device === right.device
    && left.inode === right.inode
    && left.size === right.size
    && left.links === right.links
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs;
}

function privateIdentity(identity) {
  return Object.freeze({
    device: identity.device.toString(10),
    inode: identity.inode.toString(10),
  });
}

function noFollowFlag() {
  return process.platform !== "win32"
    && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

async function stableRead(filePath, maximum = 1024 * 1024 * 1024) {
  const resolved = path.resolve(filePath);
  const initial = await lstat(resolved, { bigint: true });
  if (
    initial.isSymbolicLink()
    || !initial.isFile()
    || initial.nlink !== 1n
    || initial.size < 0n
    || initial.size > BigInt(maximum)
    || !pathsEqual(await realpath(resolved), resolved)
  ) failZipReproducibility("SOURCE_BINDING", "stable-file-state");
  const identity = identityFromState(initial);
  if (!identity.meaningful) {
    failZipReproducibility("SOURCE_BINDING", "stable-file-identity");
  }
  let handle = null;
  try {
    handle = await open(resolved, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (!identitiesEqual(identity, identityFromState(before))) {
      failZipReproducibility("SOURCE_BINDING", "stable-file-identity");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const final = await lstat(resolved, { bigint: true });
    if (
      !identitiesEqual(identity, identityFromState(after))
      || !identitiesEqual(identity, identityFromState(final))
      || bytes.length !== Number(identity.size)
    ) failZipReproducibility("SOURCE_BINDING", "stable-file-identity");
    return Object.freeze({
      path: resolved,
      bytes,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      identity,
    });
  } finally {
    if (handle) await handle.close();
  }
}

async function requireRealDirectory(directoryPath) {
  const resolved = path.resolve(directoryPath);
  const state = await lstat(resolved, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !pathsEqual(await realpath(resolved), resolved)
  ) failZipReproducibility("SOURCE_BINDING", "directory-state");
  const identity = identityFromState(state);
  if (!identity.meaningful) {
    failZipReproducibility("SOURCE_BINDING", "directory-identity");
  }
  return Object.freeze({ path: resolved, identity });
}

async function writeExclusive(filePath, bytes, mode = 0o600) {
  await writeFile(filePath, bytes, { flag: "wx", mode });
  return stableRead(filePath, Math.max(bytes.length, 1));
}

function validateOwnershipLedger(value) {
  assertProxyFreeAuthorityGraph(value, CALLABLE_AUTHORITY_OPTIONS);
  if (value === null || value === undefined) return null;
  const keys = [
    "recordDirectory",
    "recordFile",
    "rebindFile",
    "recordRemoval",
  ];
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) failZipReproducibility("CLEANUP", "cleanup-identity-uncertain");
  const actual = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
    || keys.some((key) => (
      !descriptors[key]
      || !Object.hasOwn(descriptors[key], "value")
      || descriptors[key].enumerable !== true
      || typeof descriptors[key].value !== "function"
    ))
  ) failZipReproducibility("CLEANUP", "cleanup-identity-uncertain");
  return value;
}

async function invokeOwnershipLedger(value, method, argumentsList) {
  const ledger = validateOwnershipLedger(value);
  const descriptor = Object.getOwnPropertyDescriptor(ledger, method);
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    failZipReproducibility("CLEANUP", "cleanup-identity-uncertain");
  }
  const pending = Reflect.apply(descriptor.value, ledger, argumentsList);
  assertProxyFreeAuthorityGraph(pending, ASYNC_RESULT_AUTHORITY_OPTIONS);
  const result = await pending;
  assertProxyFreeAuthorityGraph(result);
  return result;
}

async function recordMaterializedTreeOwnership(
  ownershipLedger,
  sourceTree,
  membership,
  phase,
) {
  assertProxyFreeAuthorityGraph(
    ownershipLedger,
    CALLABLE_AUTHORITY_OPTIONS,
  );
  if (!ownershipLedger) return;
  await invokeOwnershipLedger(
    ownershipLedger,
    "recordDirectory",
    [sourceTree, phase + "-root"],
  );
  const directories = new Set();
  for (const member of membership.members) {
    const components = member.path.split("/");
    for (let length = 1; length < components.length; length += 1) {
      directories.add(components.slice(0, length).join("/"));
    }
  }
  for (const relative of [...directories].sort((left, right) => (
    left.split("/").length - right.split("/").length
    || (left < right ? -1 : left > right ? 1 : 0)
  ))) {
    await invokeOwnershipLedger(ownershipLedger, "recordDirectory", [
      path.join(sourceTree, ...relative.split("/")),
      phase + "-directory",
    ]);
  }
  for (const member of membership.members) {
    await invokeOwnershipLedger(ownershipLedger, "recordFile", [
      path.join(sourceTree, ...member.path.split("/")),
      {
        byteLength: member.declaredByteSize,
        sha256: member.sha256,
      },
      phase + "-file",
    ]);
  }
}

function crc32Hex(bytes) {
  return crc32Bytes(bytes).toString(16).padStart(8, "0");
}

export async function validatePublicSourceZipBoundaryVectorSet(options = {}) {
  assertProxyFreeAuthorityGraph(options);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "testVectorSet",
      "expectedSha256",
    ].includes(key))
  ) failVector();
  const { testVectorSet, expectedSha256 = null } = options;
  if (
    typeof testVectorSet !== "string"
    || !path.isAbsolute(testVectorSet)
    || path.resolve(testVectorSet) !== testVectorSet
    || (expectedSha256 !== null && !SHA256_PATTERN.test(expectedSha256))
  ) failVector();
  let stable;
  let value;
  try {
    stable = await stableRead(testVectorSet, MAX_VECTOR_SET_BYTES);
    value = parseCanonicalPublicJsonBytes(stable.bytes, "BOUNDARY_VECTOR");
    validateBoundaryVectorSet(value, BOUNDARY_VECTOR_DESCRIPTORS);
  } catch (error) {
    if (error instanceof PublicSourceZipBoundaryVectorError) throw error;
    failVector();
  }
  if (expectedSha256 !== null && stable.sha256 !== expectedSha256) {
    failVector(null, "vector-set-identity-mismatch");
  }
  return Object.freeze({
    bytes: stable.bytes,
    sha256: stable.sha256,
    byteLength: stable.byteLength,
    value,
  });
}

export async function buildFreshZipCandidate(options = {}) {
  assertProxyFreeAuthorityGraph(options, CALLABLE_AUTHORITY_OPTIONS);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "repository",
      "sourceCommit",
      "assignmentDirectory",
      "expectedManifestSha256",
      "expectedMembershipReportSha256",
      "ownershipLedger",
    ].includes(key))
  ) failZipReproducibility("SOURCE_BINDING", "candidate-options");
  let {
    repository,
    sourceCommit,
    assignmentDirectory,
    expectedManifestSha256 = null,
    expectedMembershipReportSha256 = null,
    ownershipLedger = null,
  } = options;
  ownershipLedger = validateOwnershipLedger(ownershipLedger);
  if (
    typeof repository !== "string"
    || typeof assignmentDirectory !== "string"
    || !path.isAbsolute(repository)
    || !path.isAbsolute(assignmentDirectory)
    || path.resolve(repository) !== repository
    || path.resolve(assignmentDirectory) !== assignmentDirectory
    || typeof sourceCommit !== "string"
    || !/^[0-9a-f]{40}$/u.test(sourceCommit)
  ) failZipReproducibility("SOURCE_BINDING", "candidate-options");
  const assignment = await requireRealDirectory(assignmentDirectory);
  const initialEntries = await readdir(assignment.path);
  const allowedInitial = new Set([WORKER_CLAIM_BASENAME]);
  if (initialEntries.some((entry) => !allowedInitial.has(entry))) {
    failZipReproducibility("SOURCE_BINDING", "assignment-not-empty");
  }
  const membership = await loadValidatedPublicSourceMembership({
    repo: repository,
    commit: sourceCommit,
  });
  const membershipReportSha256 = sha256Bytes(membership.reportBytes);
  if (
    (expectedManifestSha256 !== null
      && membership.manifestSha256 !== expectedManifestSha256)
    || (expectedMembershipReportSha256 !== null
      && membershipReportSha256 !== expectedMembershipReportSha256)
  ) failZipReproducibility("SOURCE_BINDING", "membership-authority-mismatch");

  const sourceTree = path.join(assignment.path, WORKER_TREE_BASENAME);
  const entryPlanPath = path.join(assignment.path, WORKER_PLAN_BASENAME);
  const artifactPath = path.join(assignment.path, WORKER_ARTIFACT_BASENAME);
  const materialized = await materializePublicSourceTree({
    repo: repository,
    commit: sourceCommit,
    output: sourceTree,
  });
  if (
    materialized.status !== "ok"
    || materialized.treeMaterialized !== true
    || materialized.sourceCommit !== sourceCommit
    || materialized.manifestSha256 !== membership.manifestSha256
    || materialized.membershipReportSha256 !== membershipReportSha256
    || materialized.membershipCount !== membership.members.length
  ) failZipReproducibility("SOURCE_BINDING", "b2-result-mismatch");
  await recordMaterializedTreeOwnership(
    ownershipLedger,
    sourceTree,
    membership,
    "candidate-source-tree",
  );

  const plan = createCanonicalZipEntryPlan({
    sourceCommit,
    manifestSha256: membership.manifestSha256,
    membershipReportSha256,
    membershipCount: membership.members.length,
    entries: membership.members.map((member) => ({
      sourcePath: member.path,
      gitMode: member.gitMode,
      sha256: member.sha256,
      crc32: crc32Hex(member.blobBytes),
      byteLength: member.declaredByteSize,
    })),
  });
  const entryPlanBytes = encodeCanonicalZipEntryPlan(plan);
  const planFile = await writeExclusive(entryPlanPath, entryPlanBytes);
  if (ownershipLedger) {
    await invokeOwnershipLedger(ownershipLedger, "recordFile", [
      entryPlanPath,
      { byteLength: entryPlanBytes.length, sha256: sha256Bytes(entryPlanBytes) },
      "candidate-entry-plan",
    ]);
  }
  const writer = await preparePublicSourceZip({
    sourceTree,
    entryPlan: entryPlanPath,
    output: artifactPath,
  });
  const verification = await verifyPublicSourceZip({
    archive: artifactPath,
    entryPlan: entryPlanPath,
  });
  const transcript = encodeCanonicalZipVerificationResult(verification);
  const artifact = await stableRead(artifactPath);
  if (ownershipLedger) {
    await invokeOwnershipLedger(ownershipLedger, "recordFile", [
      artifactPath,
      { byteLength: artifact.byteLength, sha256: artifact.sha256 },
      "candidate-artifact",
    ]);
  }
  const tree = await requireRealDirectory(sourceTree);
  if (
    writer.status !== "ok"
    || verification.status !== "ok"
    || verification.mode !== "full"
    || verification.canonicalProfileVerified !== true
    || verification.entryPlanVerified !== true
    || verification.storedPayloadsVerified !== true
    || verification.crc32Verified !== true
    || verification.verificationComplete !== true
    || verification.archiveSha256 !== artifact.sha256
    || verification.archiveByteLength !== artifact.byteLength
    || verification.entryPlanSha256 !== planFile.sha256
    || planFile.sha256 !== sha256Bytes(entryPlanBytes)
    || artifact.identity.links !== 1n
    || !artifact.identity.meaningful
    || !planFile.identity.meaningful
    || sameObject(artifact.identity, planFile.identity)
    || pathsEqual(sourceTree, entryPlanPath)
    || pathsEqual(sourceTree, artifactPath)
    || pathsEqual(entryPlanPath, artifactPath)
  ) failZipReproducibility("ZIP_VERIFICATION", "candidate-verification-mismatch");
  return Object.freeze({
    assignment,
    sourceTree: tree,
    entryPlanPath,
    artifactPath,
    plan,
    entryPlanBytes,
    entryPlanSha256: planFile.sha256,
    entryPlanIdentity: planFile.identity,
    artifactBytes: artifact.bytes,
    artifactSha256: artifact.sha256,
    artifactByteLength: artifact.byteLength,
    artifactIdentity: artifact.identity,
    verification,
    transcript,
    transcriptSha256: sha256Bytes(transcript),
    membership,
    membershipReportSha256,
  });
}

function moduleSetSha256(modules) {
  const digest = createHash("sha256");
  for (const module of modules) {
    const bytes = Buffer.from(module.sourceBase64, "base64");
    digest.update(Buffer.from(module.relativePath, "utf8"));
    digest.update(Buffer.from([0]));
    digest.update(Buffer.from(String(bytes.length), "ascii"));
    digest.update(Buffer.from([0]));
    digest.update(bytes);
  }
  return digest.digest("hex");
}

function exactKeys(value, keys) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && Object.keys(value).every((key, index) => key === keys[index]);
}

export async function createTrustedZipWorkerModuleCapsule(options = {}) {
  assertProxyFreeAuthorityGraph(options, CALLABLE_AUTHORITY_OPTIONS);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "privateRoot",
      "toolingCommit",
      "modules",
      "ownershipLedger",
    ].includes(key))
  ) failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  let {
    privateRoot,
    toolingCommit,
    modules,
    ownershipLedger = null,
  } = options;
  ownershipLedger = validateOwnershipLedger(ownershipLedger);
  if (
    typeof privateRoot !== "string"
    || !path.isAbsolute(privateRoot)
    || path.resolve(privateRoot) !== privateRoot
    || !/^[0-9a-f]{40}$/u.test(toolingCommit ?? "")
    || !Array.isArray(modules)
    || modules.length !== WORKER_MODULE_PATHS.length
  ) failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  const normalized = modules.map((entry, index) => {
    if (
      !exactKeys(entry, WORKER_CAPSULE_MODULE_KEYS)
      || entry.relativePath !== WORKER_MODULE_PATHS[index]
      || !Number.isSafeInteger(entry.byteLength)
      || entry.byteLength < 0
      || !SHA256_PATTERN.test(entry.sha256)
      || typeof entry.sourceBase64 !== "string"
    ) failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
    const bytes = Buffer.from(entry.sourceBase64, "base64");
    if (
      bytes.toString("base64") !== entry.sourceBase64
      || bytes.length !== entry.byteLength
      || sha256Bytes(bytes) !== entry.sha256
      || !Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes)
    ) failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
    return Object.freeze({ ...entry });
  });
  const entry = normalized.find(
    (module) => module.relativePath === WORKER_ENTRY_MODULE,
  );
  if (!entry) {
    failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  }
  const root = await requireRealDirectory(privateRoot);
  const directoryPath = path.join(root.path, WORKER_CAPSULE_DIRECTORY);
  await mkdir(directoryPath, { recursive: false, mode: 0o700 });
  const directory = await requireRealDirectory(directoryPath);
  if (ownershipLedger) {
    await invokeOwnershipLedger(ownershipLedger, "recordDirectory", [
      directoryPath,
      "worker-capsule-directory",
    ]);
  }
  const value = {
    capsuleKind: WORKER_CAPSULE_KIND,
    schemaVersion: 1,
    toolingCommit,
    entryModule: WORKER_ENTRY_MODULE,
    moduleOrder: WORKER_MODULE_PATHS,
    modules: normalized,
    moduleSetSha256: moduleSetSha256(normalized),
  };
  if (!exactKeys(value, WORKER_CAPSULE_KEYS)) {
    failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  }
  const bytes = canonicalPrivateJsonBytes(value, "TOOL_SET");
  if (bytes.length > MAX_WORKER_CAPSULE_BYTES) {
    failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  }
  const capsulePath = path.join(directory.path, WORKER_CAPSULE_BASENAME);
  const file = await writeExclusive(capsulePath, bytes);
  if (ownershipLedger) {
    await invokeOwnershipLedger(ownershipLedger, "recordFile", [
      capsulePath,
      { byteLength: bytes.length, sha256: sha256Bytes(bytes) },
      "worker-capsule-file",
    ]);
  }
  if (!file.identity.meaningful || file.identity.links !== 1n) {
    failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
  }
  const anchorRootPath = path.join(directory.path, "virtual-root");
  await mkdir(anchorRootPath, { recursive: false, mode: 0o700 });
  const anchorRoot = await requireRealDirectory(anchorRootPath);
  if (ownershipLedger) {
    await invokeOwnershipLedger(ownershipLedger, "recordDirectory", [
      anchorRootPath,
      "worker-anchor-root",
    ]);
  }
  const urlAnchors = [];
  const recordedAnchorDirectories = new Set([anchorRootPath]);
  for (const module of normalized) {
    const anchorPath = path.join(anchorRoot.path, module.relativePath);
    const relativeDirectory = path.dirname(module.relativePath);
    let currentDirectory = anchorRoot.path;
    if (relativeDirectory !== ".") {
      for (const component of relativeDirectory.split("/")) {
        currentDirectory = path.join(currentDirectory, component);
        if (!recordedAnchorDirectories.has(currentDirectory)) {
          await mkdir(currentDirectory, { recursive: false, mode: 0o700 });
          if (ownershipLedger) {
            await invokeOwnershipLedger(ownershipLedger, "recordDirectory", [
              currentDirectory,
              "worker-anchor-directory",
            ]);
          }
          recordedAnchorDirectories.add(currentDirectory);
        }
      }
    }
    const anchor = await writeExclusive(anchorPath, Buffer.alloc(0));
    if (ownershipLedger) {
      await invokeOwnershipLedger(ownershipLedger, "recordFile", [
        anchorPath,
        { byteLength: 0, sha256: sha256Bytes(Buffer.alloc(0)) },
        "worker-anchor-file",
      ]);
    }
    if (!anchor.identity.meaningful || anchor.identity.links !== 1n) {
      failZipReproducibility("TOOL_SET", "worker-module-capsule-invalid");
    }
    urlAnchors.push(Object.freeze({
      path: anchorPath,
      identity: anchor.identity,
    }));
  }
  return Object.freeze({
    path: capsulePath,
    pathSha256: privatePathSha256(capsulePath),
    sha256: file.sha256,
    byteLength: file.byteLength,
    moduleSetSha256: value.moduleSetSha256,
    entryModuleSha256: entry.sha256,
    fileIdentity: file.identity,
    parentIdentity: directory.identity,
    anchorRoot: Object.freeze({
      path: anchorRoot.path,
      identity: anchorRoot.identity,
    }),
    urlAnchors: Object.freeze(urlAnchors),
    value: deepFreezeZipReproducibility(value),
  });
}

async function requireCapsuleState(capsule) {
  try {
    const file = await stableRead(capsule.path, MAX_WORKER_CAPSULE_BYTES);
    const parent = await requireRealDirectory(path.dirname(capsule.path));
    const anchorRoot = await requireRealDirectory(capsule.anchorRoot.path);
    if (
      file.sha256 !== capsule.sha256
      || !identitiesEqual(file.identity, capsule.fileIdentity)
      || !sameObject(parent.identity, capsule.parentIdentity)
      || !sameObject(anchorRoot.identity, capsule.anchorRoot.identity)
      || privatePathSha256(capsule.path) !== capsule.pathSha256
    ) throw new Error();
    for (const anchor of capsule.urlAnchors) {
      const state = await stableRead(anchor.path, 0);
      if (
        state.byteLength !== 0
        || !identitiesEqual(state.identity, anchor.identity)
      ) throw new Error();
    }
  } catch {
    failZipReproducibility("TOOL_SET", "worker-loaded-bytes-mismatch");
  }
}

function sanitizedWorkerEnvironment(base, temporaryDirectory, profile) {
  const environment = {};
  for (const [key, value] of Object.entries(base)) {
    const upper = key.toUpperCase();
    if (
      upper.startsWith("GIT_")
      || upper === "NODE_OPTIONS"
      || upper === "NODE_PATH"
      || upper.includes("LOADER")
      || upper.includes("PRELOAD")
      || [
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ",
        "SOURCE_DATE_EPOCH",
      ].includes(upper)
    ) continue;
    environment[key] = value;
  }
  environment.TEMP = temporaryDirectory;
  environment.TMP = temporaryDirectory;
  environment.TMPDIR = temporaryDirectory;
  environment.LANG = profile.lang;
  environment.LC_ALL = profile.lcAll;
  environment.TZ = profile.timezone;
  environment.SOURCE_DATE_EPOCH = profile.sourceDateEpoch;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  return environment;
}

export async function spawnTrustedZipWorkerRaw(options = {}) {
  assertProxyFreeAuthorityGraph(options, CALLABLE_AUTHORITY_OPTIONS);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "requestMessages",
      "environment",
      "workingDirectory",
      "capsule",
      "timeoutMilliseconds",
      "afterSpawn",
    ].includes(key))
  ) failZipReproducibility("SAME_HOST", "worker-request-invalid");
  const {
    requestMessages,
    environment,
    workingDirectory,
    capsule,
    timeoutMilliseconds = 120000,
    afterSpawn = null,
  } = options;
  if (
    !Array.isArray(requestMessages)
    || requestMessages.length < 1
    || requestMessages.some((entry) => typeof entry !== "string")
    || !Number.isSafeInteger(timeoutMilliseconds)
    || timeoutMilliseconds < 1
    || (afterSpawn !== null && typeof afterSpawn !== "function")
  ) failZipReproducibility("SAME_HOST", "worker-request-invalid");
  await requireCapsuleState(capsule);
  return new Promise((resolve) => {
    const startedAt = process.hrtime.bigint();
    const child = spawn(process.execPath, [
      "--input-type=module",
      "--eval",
      WORKER_BOOTSTRAP_SOURCE,
      "--",
      capsule.path,
      capsule.sha256,
      capsule.fileIdentity.device.toString(10),
      capsule.fileIdentity.inode.toString(10),
      capsule.parentIdentity.device.toString(10),
      capsule.parentIdentity.inode.toString(10),
      capsule.pathSha256,
    ], {
      cwd: workingDirectory,
      env: environment,
      serialization: "json",
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    const responses = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let timeout = false;
    let forcedTermination = false;
    let spawnError = false;
    let settled = false;
    const terminate = () => {
      if (forcedTermination) return;
      forcedTermination = true;
      try { child.kill(); } catch { /* close is authoritative */ }
    };
    const capture = (target, chunk, stdoutStream) => {
      const bytes = Buffer.from(chunk);
      if (stdoutStream) stdoutLength += bytes.length;
      else stderrLength += bytes.length;
      if (
        stdoutLength > MAX_WORKER_STDIO_BYTES
        || stderrLength > MAX_WORKER_STDIO_BYTES
      ) {
        terminate();
        return;
      }
      target.push(bytes);
    };
    child.stdout.on("data", (chunk) => capture(stdout, chunk, true));
    child.stderr.on("data", (chunk) => capture(stderr, chunk, false));
    child.on("message", (message) => {
      try {
        assertProxyFreeAuthorityGraph(message);
        responses.push(message);
      } catch {
        spawnError = true;
        terminate();
      }
    });
    child.on("error", () => { spawnError = true; });
    const timer = setTimeout(() => {
      timeout = true;
      terminate();
    }, timeoutMilliseconds);
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(Object.freeze({
        pid: child.pid,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        responses: Object.freeze([...responses]),
        code,
        signal,
        timeout,
        forcedTermination,
        spawnError,
        durationMilliseconds: Number(
          process.hrtime.bigint() - startedAt,
        ) / 1_000_000,
      }));
    });
    if (!Number.isSafeInteger(child.pid) || child.pid <= 0 || !child.connected) {
      spawnError = true;
      terminate();
      return;
    }
    for (const message of requestMessages) {
      try { child.send(message); } catch { terminate(); }
    }
    if (afterSpawn) {
      try {
        const pending = afterSpawn(Object.freeze({
          pid: child.pid,
          send(message) {
            if (typeof message !== "string" || settled) return false;
            try { return child.send(message); } catch { return false; }
          },
        }));
        assertProxyFreeAuthorityGraph(
          pending,
          ASYNC_RESULT_AUTHORITY_OPTIONS,
        );
        Promise.resolve(pending).then((result) => {
          assertProxyFreeAuthorityGraph(result);
        }).catch(terminate);
      } catch {
        terminate();
      }
    }
  });
}

function workerFailure(error) {
  const safe = asZipReproducibilityError(
    error,
    "SAME_HOST",
    "worker-operation-failed",
  );
  try { process.removeAllListeners("message"); } catch { /* continue */ }
  try {
    writeSync(2, Buffer.from(
      "ERROR " + safe.phase + ": " + safe.reason + "\n",
      "utf8",
    ));
  } catch { /* continue */ }
  try { if (process.connected) process.disconnect(); } catch { /* continue */ }
  process.exitCode = 1;
}

export async function runPrivateZipWorker() {
  try {
    if (typeof process.send !== "function" || !process.connected) {
      failZipReproducibility("SAME_HOST", "worker-request-invalid");
    }
    const firstMessage = await new Promise((resolve, reject) => {
      let claimed = false;
      const onFirstMessage = (message) => {
        claimed = true;
        process.removeListener("message", onFirstMessage);
        clearTimeout(timer);
        resolve(message);
      };
      const timer = setTimeout(() => {
        if (claimed) return;
        process.removeListener("message", onFirstMessage);
        reject(new PublicSourceZipReproducibilityError(
          "SAME_HOST",
          "worker-request-invalid",
        ));
      }, 30000);
      process.once("message", onFirstMessage);
    });
    if (typeof firstMessage !== "string") {
      failZipReproducibility("SAME_HOST", "worker-request-invalid");
    }
    const request = validateWorkerRequest(
      parseCanonicalPrivateJsonText(firstMessage, "SAME_HOST"),
    );
    if (
      request.lease.parentPid !== process.ppid
      || path.resolve(process.cwd()) !== request.assignmentPath
    ) failZipReproducibility("SAME_HOST", "worker-request-invalid");
    const loadedCandidate = globalThis.__IELTMPS_ZIP_WORKER_LOADED_BYTES__;
    assertProxyFreeAuthorityGraph(loadedCandidate);
    if (
      !loadedCandidate
      || !SHA256_PATTERN.test(loadedCandidate.workerCapsuleSha256)
      || !SHA256_PATTERN.test(loadedCandidate.workerModuleSetSha256)
      || !SHA256_PATTERN.test(loadedCandidate.workerEntryModuleSha256)
    ) failZipReproducibility("TOOL_SET", "worker-loaded-bytes-mismatch");
    const loaded = validateLoadedByteAttestation(loadedCandidate);
    const claimPath = path.join(request.assignmentPath, WORKER_CLAIM_BASENAME);
    try {
      await writeFile(
        claimPath,
        Buffer.from(request.assignmentNonce + "\n", "ascii"),
        { flag: "wx", mode: 0o600 },
      );
    } catch (error) {
      if (error && error.code === "EEXIST") {
        failZipReproducibility("SAME_HOST", "worker-replay");
      }
      throw error;
    }
    const candidate = await buildFreshZipCandidate({
      repository: request.repositoryPath,
      sourceCommit: request.sourceCommit,
      assignmentDirectory: request.assignmentPath,
      expectedManifestSha256: request.context.manifestSha256,
      expectedMembershipReportSha256: request.context.membershipReportSha256,
    });
    const auditAuthority = globalThis.__IELTMPS_ZIP_WORKER_AUDIT__;
    assertProxyFreeAuthorityGraph(
      auditAuthority,
      CALLABLE_AUTHORITY_OPTIONS,
    );
    const audit = auditAuthority?.snapshot?.();
    assertProxyFreeAuthorityGraph(audit);
    if (
      !audit
      || !Number.isSafeInteger(audit.workerProcessInvocationCount)
      || audit.workerProcessInvocationCount < 1
      || audit.comparatorProcessInvocationCount !== 0
      || !Number.isSafeInteger(audit.workerLoadedModuleCount)
      || audit.workerLoadedModuleCount < WORKER_MODULE_PATHS.length
      || audit.workerUnapprovedModuleLoadCount !== 0
    ) failZipReproducibility("SAME_HOST", "worker-response-invalid");
    const response = {
      protocol: WORKER_PROTOCOL,
      runId: request.lease.runId,
      assignmentId: request.assignmentId,
      contextSha256: request.lease.contextSha256,
      status: "ok",
      artifactSha256: candidate.artifactSha256,
      artifactByteLength: candidate.artifactByteLength,
      entryPlanSha256: candidate.entryPlanSha256,
      entryPlanByteLength: candidate.entryPlanBytes.length,
      transcriptSha256: candidate.transcriptSha256,
      transcriptByteLength: candidate.transcript.length,
      entryPlanBase64: candidate.entryPlanBytes.toString("base64"),
      transcriptBase64: candidate.transcript.toString("base64"),
      workerCapsuleSha256: loaded.workerCapsuleSha256,
      workerModuleSetSha256: loaded.workerModuleSetSha256,
      workerEntryModuleSha256: loaded.workerEntryModuleSha256,
      workerRequestListenerCount: process.listenerCount("message"),
      claimCount: 1,
      workerProcessInvocationCount: audit.workerProcessInvocationCount,
      comparatorProcessInvocationCount: audit.comparatorProcessInvocationCount,
      workerLoadedModuleCount: audit.workerLoadedModuleCount,
      workerUnapprovedModuleLoadCount: audit.workerUnapprovedModuleLoadCount,
      assignmentDirectoryIdentity: privateIdentity(candidate.assignment.identity),
      artifactFileIdentity: privateIdentity(candidate.artifactIdentity),
    };
    const responseText = canonicalPrivateJsonBytes(response).toString("utf8");
    if (Buffer.byteLength(responseText, "utf8") > MAX_WORKER_RESPONSE_BYTES) {
      failZipReproducibility("SAME_HOST", "worker-response-invalid");
    }
    await new Promise((resolve, reject) => {
      process.send(responseText, (error) => error ? reject(error) : resolve());
    });
    process.disconnect();
    process.exitCode = 0;
  } catch (error) {
    workerFailure(error);
  }
}

export async function runSameHostZipCandidates(options = {}) {
  assertProxyFreeAuthorityGraph(options, CALLABLE_AUTHORITY_OPTIONS);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "repository",
      "sourceCommit",
      "privateRoot",
      "context",
      "capsule",
      "protocolControl",
      "ownershipLedger",
    ].includes(key))
  ) failZipReproducibility("SAME_HOST", "worker-request-invalid");
  let {
    repository,
    sourceCommit,
    privateRoot,
    context,
    capsule,
    protocolControl = null,
    ownershipLedger = null,
  } = options;
  ownershipLedger = validateOwnershipLedger(ownershipLedger);
  const root = await requireRealDirectory(privateRoot);
  const ownershipMembership = ownershipLedger
    ? await loadValidatedPublicSourceMembership({
      repo: repository,
      commit: sourceCommit,
    })
    : null;
  const contextSha256 = workerContextSha256(context);
  const assignments = [];
  for (const assignmentId of ["worker-a", "worker-b"]) {
    const assignmentPath = path.join(root.path, assignmentId);
    await mkdir(assignmentPath, { recursive: false, mode: 0o700 });
    const assignment = await requireRealDirectory(assignmentPath);
    if (ownershipLedger) {
      await invokeOwnershipLedger(ownershipLedger, "recordDirectory", [
        assignmentPath,
        "worker-assignment-directory",
      ]);
    }
    assignments.push(Object.freeze({
      assignmentId,
      assignmentNonce: randomBytes(32).toString("hex"),
      assignmentPathSha256: privatePathSha256(assignment.path),
      path: assignment.path,
      identity: assignment.identity,
    }));
  }
  const lease = {
    schemaVersion: 1,
    runId: randomBytes(32).toString("hex"),
    parentPid: process.pid,
    contextSha256,
    assignments: assignments.map((entry) => ({
      assignmentId: entry.assignmentId,
      assignmentNonce: entry.assignmentNonce,
      assignmentPathSha256: entry.assignmentPathSha256,
    })),
  };
  const profiles = [
    { lang: "C", lcAll: "C", timezone: "UTC", sourceDateEpoch: "0" },
    {
      lang: "tr_TR.UTF-8",
      lcAll: "tr_TR.UTF-8",
      timezone: "Pacific/Kiritimati",
      sourceDateEpoch: "4102444800",
    },
  ];
  const outputs = [];
  for (let index = 0; index < assignments.length; index += 1) {
    const assignment = assignments[index];
    const request = {
      protocol: WORKER_PROTOCOL,
      lease,
      assignmentId: assignment.assignmentId,
      assignmentNonce: assignment.assignmentNonce,
      assignmentPath: assignment.path,
      repositoryPath: repository,
      sourceCommit,
      context,
    };
    validateWorkerRequest(request);
    const messages = [canonicalPrivateJsonBytes(request).toString("utf8")];
    if (protocolControl?.immediateHostileSecond === true) {
      messages.push(canonicalPrivateJsonBytes({ hostile: assignment.path }).toString("utf8"));
    }
    const observation = await spawnTrustedZipWorkerRaw({
      requestMessages: messages,
      environment: sanitizedWorkerEnvironment(
        process.env,
        assignment.path,
        profiles[index],
      ),
      workingDirectory: assignment.path,
      capsule,
      afterSpawn: protocolControl?.postClaimHostileSecond === true
        ? async (child) => {
          await new Promise((resolve) => setTimeout(resolve, 50));
          child.send(canonicalPrivateJsonBytes({ hostile: assignment.path }).toString("utf8"));
        }
        : null,
    });
    if (protocolControl?.onObservation) {
      const pending = protocolControl.onObservation(Object.freeze({
        assignmentId: assignment.assignmentId,
        observation,
      }));
      assertProxyFreeAuthorityGraph(pending, ASYNC_RESULT_AUTHORITY_OPTIONS);
      const returned = await pending;
      assertProxyFreeAuthorityGraph(returned);
      if (returned !== undefined) {
        failZipReproducibility("SAME_HOST", "worker-observation-hook-invalid");
      }
    }
    if (
      observation.code !== 0
      || observation.signal !== null
      || observation.timeout
      || observation.forcedTermination
      || observation.spawnError
      || !Number.isFinite(observation.durationMilliseconds)
      || observation.durationMilliseconds <= 0
      || observation.stdout.length !== 0
      || observation.stderr.length !== 0
      || observation.responses.length !== 1
      || typeof observation.responses[0] !== "string"
    ) failZipReproducibility("SAME_HOST", "worker-observation-invalid");
    const response = validateWorkerResponse(
      parseCanonicalPrivateJsonText(observation.responses[0], "SAME_HOST"),
      {
        runId: lease.runId,
        assignmentId: assignment.assignmentId,
        contextSha256,
        workerCapsuleSha256: capsule.sha256,
        workerModuleSetSha256: capsule.moduleSetSha256,
        workerEntryModuleSha256: capsule.entryModuleSha256,
      },
    );
    if (ownershipLedger) {
      const claimPath = path.join(assignment.path, WORKER_CLAIM_BASENAME);
      const claimBytes = Buffer.from(assignment.assignmentNonce + "\n", "ascii");
      await invokeOwnershipLedger(ownershipLedger, "recordFile", [
        claimPath,
        { byteLength: claimBytes.length, sha256: sha256Bytes(claimBytes) },
        "worker-claim-file",
      ]);
      await recordMaterializedTreeOwnership(
        ownershipLedger,
        path.join(assignment.path, WORKER_TREE_BASENAME),
        ownershipMembership,
        "worker-source-tree",
      );
      await invokeOwnershipLedger(ownershipLedger, "recordFile", [
        path.join(assignment.path, WORKER_PLAN_BASENAME),
        {
          byteLength: response.entryPlanByteLength,
          sha256: response.entryPlanSha256,
        },
        "worker-entry-plan",
      ]);
      await invokeOwnershipLedger(ownershipLedger, "recordFile", [
        path.join(assignment.path, WORKER_ARTIFACT_BASENAME),
        {
          byteLength: response.artifactByteLength,
          sha256: response.artifactSha256,
        },
        "worker-artifact",
      ]);
    }
    const artifact = await stableRead(
      path.join(assignment.path, WORKER_ARTIFACT_BASENAME),
    );
    if (
      artifact.sha256 !== response.artifactSha256
      || artifact.byteLength !== response.artifactByteLength
      || artifact.identity.links !== 1n
      || !artifact.identity.meaningful
    ) failZipReproducibility("SAME_HOST", "worker-output-invalid");
    outputs.push(Object.freeze({
      assignment,
      observation,
      response,
      artifact,
    }));
  }
  const [left, right] = outputs;
  if (
    left.response.artifactSha256 !== right.response.artifactSha256
    || left.response.artifactByteLength !== right.response.artifactByteLength
    || left.response.entryPlanSha256 !== right.response.entryPlanSha256
    || left.response.transcriptSha256 !== right.response.transcriptSha256
    || !left.artifact.bytes.equals(right.artifact.bytes)
    || !left.response.entryPlan.equals(right.response.entryPlan)
    || !left.response.transcript.equals(right.response.transcript)
    || pathsEqual(left.assignment.path, right.assignment.path)
    || sameObject(left.assignment.identity, right.assignment.identity)
    || sameObject(left.artifact.identity, right.artifact.identity)
  ) failZipReproducibility("SAME_HOST", "same-host-mismatch");
  return Object.freeze({
    outputs: Object.freeze(outputs),
    profiles: Object.freeze(profiles.map((entry) => Object.freeze({ ...entry }))),
    sameHostRepeatable: true,
    canonicalVerifierPassed: true,
  });
}

function independentZip(plan, payloads) {
  const chunks = [];
  for (const entry of plan.entries) {
    const name = Buffer.from(entry.archivePath, "utf8");
    const payload = payloads.get(entry.sourcePath);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(0x0014, 4);
    header.writeUInt16LE(0x0800, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(0, 10);
    header.writeUInt16LE(0x0021, 12);
    header.writeUInt32LE(crc32Bytes(payload), 14);
    header.writeUInt32LE(payload.length, 18);
    header.writeUInt32LE(payload.length, 22);
    header.writeUInt16LE(name.length, 26);
    header.writeUInt16LE(0, 28);
    chunks.push(header, name, payload);
  }
  for (const entry of plan.entries) {
    const name = Buffer.from(entry.archivePath, "utf8");
    const payload = payloads.get(entry.sourcePath);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(0x0314, 4);
    record.writeUInt16LE(0x0014, 6);
    record.writeUInt16LE(0x0800, 8);
    record.writeUInt16LE(0, 10);
    record.writeUInt16LE(0, 12);
    record.writeUInt16LE(0x0021, 14);
    record.writeUInt32LE(crc32Bytes(payload), 16);
    record.writeUInt32LE(payload.length, 20);
    record.writeUInt32LE(payload.length, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt16LE(0, 30);
    record.writeUInt16LE(0, 32);
    record.writeUInt16LE(0, 34);
    record.writeUInt16LE(0, 36);
    record.writeUInt32LE(
      entry.gitMode === "100755" ? 0x81ed0000 : 0x81a40000,
      38,
    );
    record.writeUInt32LE(entry.localHeaderOffset, 42);
    chunks.push(record, name);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(plan.entryCount, 8);
  eocd.writeUInt16LE(plan.entryCount, 10);
  eocd.writeUInt32LE(plan.centralDirectoryByteLength, 12);
  eocd.writeUInt32LE(plan.centralDirectoryOffset, 16);
  eocd.writeUInt16LE(0, 20);
  chunks.push(eocd);
  const result = Buffer.concat(chunks);
  if (result.length !== plan.archiveByteLength) failVector();
  return result;
}

function planForFiles(files) {
  const payloads = new Map();
  const entries = files.map(({ sourcePath, gitMode = "100644", payload }) => {
    const bytes = Buffer.from(payload);
    payloads.set(sourcePath, bytes);
    return {
      sourcePath,
      gitMode,
      sha256: sha256Bytes(bytes),
      crc32: crc32Hex(bytes),
      byteLength: bytes.length,
    };
  });
  const plan = createCanonicalZipEntryPlan({
    sourceCommit: "a".repeat(40),
    manifestSha256: "b".repeat(64),
    membershipReportSha256: "c".repeat(64),
    membershipCount: entries.length,
    entries,
  });
  return Object.freeze({
    plan,
    planBytes: encodeCanonicalZipEntryPlan(plan),
    payloads,
    zipBytes: independentZip(plan, payloads),
  });
}

async function writeSyntheticSourceTree(root, files) {
  await mkdir(root, { recursive: false, mode: 0o700 });
  for (const file of files) {
    const target = path.join(root, ...file.sourcePath.split("/"));
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, file.payload, { flag: "wx", mode: 0o600 });
    if (process.platform !== "win32") {
      await chmod(target, file.gitMode === "100755" ? 0o755 : 0o644);
    }
  }
}

async function createSimpleCandidate(directory, files, independent = false) {
  await mkdir(directory, { recursive: false, mode: 0o700 });
  const sourceTree = path.join(directory, "tree");
  const planPath = path.join(directory, "plan.json");
  const archivePath = path.join(directory, "artifact.zip");
  await writeSyntheticSourceTree(sourceTree, files);
  const fixture = planForFiles(files);
  await writeFile(planPath, fixture.planBytes, { flag: "wx", mode: 0o600 });
  if (independent) {
    await writeFile(archivePath, fixture.zipBytes, { flag: "wx", mode: 0o600 });
  } else {
    await preparePublicSourceZip({
      sourceTree,
      entryPlan: planPath,
      output: archivePath,
    });
  }
  const verification = await verifyPublicSourceZip({
    archive: archivePath,
    entryPlan: planPath,
  });
  const artifact = await stableRead(archivePath);
  const planFile = await stableRead(planPath, fixture.planBytes.length);
  const transcript = encodeCanonicalZipVerificationResult(verification);
  if (
    artifact.sha256 !== verification.archiveSha256
    || artifact.byteLength !== verification.archiveByteLength
    || planFile.sha256 !== verification.entryPlanSha256
  ) failVector();
  return Object.freeze({
    directory,
    sourceTree,
    planPath,
    archivePath,
    fixture,
    verification,
    artifact,
    planFile,
    transcript,
  });
}

function maximumArchivePath() {
  let remaining = ZIP_LIMITS.maximumArchiveFilenameBytes
    - Buffer.byteLength(ZIP_ARCHIVE_ROOT, "utf8");
  const components = [];
  while (remaining > ZIP_LIMITS.maximumPathComponentBytes) {
    components.push("a".repeat(250));
    remaining -= 251;
  }
  components.push("z".repeat(remaining));
  const result = components.join("/");
  if (
    Buffer.byteLength(ZIP_ARCHIVE_ROOT + result, "utf8")
      !== ZIP_LIMITS.maximumArchiveFilenameBytes
  ) failVector();
  return result;
}

function writerFiles(vectorId) {
  switch (vectorId) {
    case "W01":
      return [{ sourcePath: "empty.txt", gitMode: "100644", payload: Buffer.alloc(0) }];
    case "W02":
      return [{ sourcePath: "one.txt", gitMode: "100644", payload: Buffer.from([0x61]) }];
    case "W03":
      return [
        { sourcePath: "a.txt", gitMode: "100644", payload: Buffer.from("a") },
        { sourcePath: "nested/b.txt", gitMode: "100644", payload: Buffer.from("bb") },
        { sourcePath: "run.sh", gitMode: "100755", payload: Buffer.from("#!/bin/sh\n") },
      ];
    case "W04":
      return [{ sourcePath: "css/caf\u00e9.css", gitMode: "100644", payload: Buffer.from("utf8\n") }];
    case "W05":
      return [{ sourcePath: maximumArchivePath(), gitMode: "100644", payload: Buffer.from("max\n") }];
    case "W06":
      return [
        { sourcePath: "css/\u00e9.css", gitMode: "100644", payload: Buffer.from("e\n") },
        { sourcePath: "css/z.css", gitMode: "100644", payload: Buffer.from("z\n") },
      ];
    case "W07":
      return [
        { sourcePath: "empty.bin", gitMode: "100644", payload: Buffer.alloc(0) },
        { sourcePath: "kat.bin", gitMode: "100644", payload: Buffer.from("123456789", "ascii") },
      ];
    case "W08":
      return [{ sourcePath: "plain.txt", gitMode: "100644", payload: Buffer.from("plain\n") }];
    case "W09":
      return [{ sourcePath: "run.sh", gitMode: "100755", payload: Buffer.from("#!/bin/sh\n") }];
    case "W10":
      return [
        { sourcePath: "a.txt", gitMode: "100644", payload: Buffer.from("independent\n") },
        { sourcePath: "b.sh", gitMode: "100755", payload: Buffer.from("#!/bin/sh\n") },
      ];
    default: failVector(vectorId);
  }
}

async function executeWriterVector(vector, root) {
  const directory = path.join(root, vector.vectorId);
  const candidate = await createSimpleCandidate(
    directory,
    writerFiles(vector.vectorId),
    vector.vectorId === "W10",
  );
  if (
    candidate.verification.status !== "ok"
    || candidate.verification.verificationComplete !== true
    || candidate.verification.authoritativeCorrespondingSource !== false
  ) failVector(vector.vectorId);
  if (
    vector.vectorId === "W07"
    && (
      crc32Bytes(Buffer.alloc(0)) !== 0
      || crc32Bytes(Buffer.from("123456789", "ascii")) !== 0xcbf43926
    )
  ) failVector(vector.vectorId);
  if (
    vector.vectorId === "W05"
    && Buffer.byteLength(
      candidate.fixture.plan.entries[0].archivePath,
      "utf8",
    ) !== 1024
  ) failVector(vector.vectorId);
}

function mutateStructural(vectorId, fixture) {
  const bytes = Buffer.from(fixture.zipBytes);
  const local = fixture.plan.entries[0].localHeaderOffset;
  const central = fixture.plan.entries[0].centralDirectoryRecordOffset;
  const eocd = bytes.length - 22;
  switch (vectorId) {
    case "L01": bytes.writeUInt32LE(0, local); break;
    case "L02": bytes.writeUInt16LE(19, local + 4); break;
    case "L03": bytes.writeUInt16LE(8, local + 8); break;
    case "L04": bytes.writeUInt16LE(0x0808, local + 6); break;
    case "L05": bytes.writeUInt16LE(0x0801, local + 6); break;
    case "L06": bytes.writeUInt16LE(0, local + 6); break;
    case "L07": bytes.writeUInt16LE(0x1800, local + 6); break;
    case "L08": bytes.writeUInt16LE(1, local + 28); break;
    case "L09": bytes.writeUInt16LE(1, local + 10); break;
    case "L10": bytes.writeUInt32LE((bytes.readUInt32LE(local + 14) + 1) >>> 0, local + 14); break;
    case "L11": bytes.writeUInt32LE(bytes.readUInt32LE(local + 18) + 1, local + 18); break;
    case "L12": bytes.writeUInt32LE(bytes.readUInt32LE(local + 22) + 1, local + 22); break;
    case "C01": bytes.writeUInt32LE(0, central); break;
    case "C02": bytes.writeUInt16LE(0x0014, central + 4); break;
    case "C03": bytes.writeUInt16LE(19, central + 6); break;
    case "C04": bytes.writeUInt16LE(0, central + 8); break;
    case "C05": bytes.writeUInt16LE(1, central + 12); break;
    case "C06": bytes.writeUInt16LE(1, central + 30); break;
    case "C07": bytes.writeUInt16LE(1, central + 32); break;
    case "C08": bytes.writeUInt16LE(1, central + 34); break;
    case "C09": bytes.writeUInt16LE(1, central + 36); break;
    case "C10": bytes.writeUInt32LE(0xa1ff0000, central + 38); break;
    case "C11": bytes.writeUInt32LE(0x41ed0010, central + 38); break;
    case "C12": bytes.writeUInt32LE(0x81a40020, central + 38); break;
    case "C13": bytes[local + 30] ^= 1; break;
    case "C14": bytes.writeUInt32LE((bytes.readUInt32LE(central + 16) + 1) >>> 0, central + 16); break;
    case "C15": bytes.writeUInt32LE(bytes.readUInt32LE(central + 42) + 1, central + 42); break;
    case "C16": {
      const left = fixture.plan.entries[0];
      const right = fixture.plan.entries[1];
      const leftLength = right.centralDirectoryRecordOffset - left.centralDirectoryRecordOffset;
      const rightLength = fixture.plan.centralDirectoryOffset
        + fixture.plan.centralDirectoryByteLength
        - right.centralDirectoryRecordOffset;
      if (leftLength !== rightLength) failVector(vectorId);
      const a = Buffer.from(bytes.subarray(left.centralDirectoryRecordOffset, right.centralDirectoryRecordOffset));
      const b = Buffer.from(bytes.subarray(right.centralDirectoryRecordOffset, right.centralDirectoryRecordOffset + rightLength));
      b.copy(bytes, left.centralDirectoryRecordOffset);
      a.copy(bytes, right.centralDirectoryRecordOffset);
      break;
    }
    case "E01": bytes.writeUInt32LE(0, eocd); break;
    case "E02": bytes.writeUInt16LE(1, eocd + 20); break;
    case "E03": bytes.writeUInt16LE(1, eocd + 4); break;
    case "E04": bytes.writeUInt16LE(1, eocd + 6); break;
    case "E05": bytes.writeUInt16LE(0, eocd + 8); break;
    case "E06": bytes.writeUInt32LE(bytes.readUInt32LE(eocd + 12) + 1, eocd + 12); break;
    case "E07": bytes.writeUInt32LE(bytes.readUInt32LE(eocd + 16) + 1, eocd + 16); break;
    case "E08": return Buffer.concat([
      bytes.subarray(0, fixture.plan.centralDirectoryOffset),
      Buffer.from([0]),
      bytes.subarray(fixture.plan.centralDirectoryOffset),
    ]);
    case "E09": return Buffer.concat([bytes, Buffer.from([0])]);
    case "E10": return Buffer.concat([Buffer.from([0]), bytes]);
    case "E11": return Buffer.concat([bytes, bytes.subarray(eocd)]);
    case "E12": return Buffer.concat([bytes, bytes]);
    case "E13": {
      const empty = Buffer.alloc(22);
      empty.writeUInt32LE(0x06054b50, 0);
      return empty;
    }
    case "M03": bytes.writeUInt16LE(1, central + 30); break;
    case "M04": return Buffer.concat([
      bytes.subarray(0, eocd),
      Buffer.from([0x50, 0x4b, 0x06, 0x06]),
      Buffer.alloc(52),
      bytes.subarray(eocd),
    ]);
    case "M05": return Buffer.concat([
      bytes.subarray(0, eocd),
      Buffer.from([0x50, 0x4b, 0x06, 0x07]),
      Buffer.alloc(16),
      bytes.subarray(eocd),
    ]);
    case "M12": {
      const length = fixture.plan.centralDirectoryOffset + 1;
      bytes.writeUInt32LE(length, local + 18);
      bytes.writeUInt32LE(length, local + 22);
      break;
    }
    case "M13":
      bytes.writeUInt32LE(
        fixture.plan.centralDirectoryByteLength + 1,
        eocd + 12,
      );
      bytes.writeUInt32LE(
        fixture.plan.centralDirectoryOffset - 1,
        eocd + 16,
      );
      break;
    case "M15": {
      const unreferenced = Buffer.alloc(30);
      unreferenced.writeUInt32LE(0x04034b50, 0);
      const changed = Buffer.concat([
        bytes.subarray(0, fixture.plan.centralDirectoryOffset),
        unreferenced,
        bytes.subarray(fixture.plan.centralDirectoryOffset),
      ]);
      const changedEocd = changed.length - 22;
      changed.writeUInt32LE(
        fixture.plan.centralDirectoryOffset + unreferenced.length,
        changedEocd + 16,
      );
      return changed;
    }
    case "M16": bytes.writeUInt32LE(0x05054b50, central); break;
    case "M17": bytes.writeUInt32LE(0x08064b50, central); break;
    case "M18": bytes.writeUInt32LE(0x08074b50, central); break;
    default: failVector(vectorId);
  }
  return bytes;
}

async function observeVerifierOutcome(
  vector,
  root,
  fixture,
  bytes,
  testHooks = undefined,
) {
  const directory = path.join(root, vector.vectorId);
  await mkdir(directory, { recursive: false, mode: 0o700 });
  const planPath = path.join(directory, "plan.json");
  const archivePath = path.join(directory, "artifact.zip");
  await writeFile(planPath, fixture.planBytes, { flag: "wx", mode: 0o600 });
  await writeFile(archivePath, bytes, { flag: "wx", mode: 0o600 });
  try {
    await verifyPublicSourceZip({
      archive: archivePath,
      entryPlan: planPath,
      testHooks,
    });
    return Object.freeze({ outcome: "accept", phase: null, reason: null });
  } catch (error) {
    if (!(error instanceof PublicSourceZipError)) throw error;
    return Object.freeze({
      outcome: "reject",
      phase: error.phase,
      reason: error.reason,
    });
  }
}

async function executeStructuralVector(vector, root, structuralFixture) {
  const bytes = mutateStructural(vector.vectorId, structuralFixture);
  return observeVerifierOutcome(vector, root, structuralFixture, bytes);
}

function expectZipError(operation) {
  try {
    operation();
  } catch (error) {
    if (error instanceof PublicSourceZipError) {
      return Object.freeze({
        outcome: "reject",
        phase: error.phase,
        reason: error.reason,
      });
    }
    throw error;
  }
  return Object.freeze({ outcome: "accept", phase: null, reason: null });
}

function collisionPlan(paths) {
  return createCanonicalZipEntryPlan({
    sourceCommit: "a".repeat(40),
    manifestSha256: "b".repeat(64),
    membershipReportSha256: "c".repeat(64),
    membershipCount: paths.length,
    entries: paths.map((sourcePath) => ({
      sourcePath,
      gitMode: "100644",
      sha256: sha256Bytes(Buffer.from(sourcePath, "utf8")),
      crc32: crc32Hex(Buffer.from(sourcePath, "utf8")),
      byteLength: Buffer.byteLength(sourcePath, "utf8"),
    })),
  });
}

function executePathVector(vector) {
  switch (vector.vectorId) {
    case "P01": return expectZipError(() => validateZipSourcePath("/a"));
    case "P02": return expectZipError(() => validateZipSourcePath("a/"));
    case "P03": return expectZipError(() => validateZipSourcePath("a\\b"));
    case "P04": return expectZipError(() => validateZipSourcePath("C:/a"));
    case "P05": return expectZipError(() => validateZipSourcePath("a:b"));
    case "P06": return expectZipError(() => validateZipSourcePath("a\0b"));
    case "P07": return expectZipError(() => validateZipSourcePath("a//b"));
    case "P08": return expectZipError(() => validateZipSourcePath("a/./b"));
    case "P09": return expectZipError(() => validateZipSourcePath("a/../b"));
    case "P10": return expectZipError(() => validateZipSourcePath("a//b"));
    case "P11": return expectZipError(() => collisionPlan(["a.txt", "a.txt"]));
    case "P12": return expectZipError(() => collisionPlan(["A.txt", "a.txt"]));
    case "P13": return expectZipError(() => collisionPlan(["caf\u00e9.txt", "cafe\u0301.txt"]));
    case "P14": {
      const valid = planForFiles([{
        sourcePath: "a.txt",
        gitMode: "100644",
        payload: Buffer.from("a"),
      }]).planBytes;
      const changed = Buffer.from(valid);
      const position = changed.indexOf(Buffer.from("a.txt", "ascii"));
      if (position < 0) failVector(vector.vectorId);
      changed[position] = 0xff;
      return expectZipError(() => parseCanonicalZipEntryPlanBytes(changed));
    }
    case "P15": return expectZipError(() => validateZipSourcePath(maximumArchivePath() + "x"));
    case "P16": return expectZipError(() => validateZipSourcePath("cafe\u0301.txt"));
    case "P17": return expectZipError(() => validateZipSourcePath("a".repeat(256)));
    case "P18": return expectZipError(() => validateZipSourcePath("CON.txt"));
    case "P19": return expectZipError(() => validateZipSourcePath("a./b"));
    case "P20": return expectZipError(() => validateZipSourcePath("file://device"));
    default: failVector(vector.vectorId);
  }
}

async function observeZipAuthorityOperation(operation) {
  try {
    await operation();
    return Object.freeze({ outcome: "accept", phase: null, reason: null });
  } catch (error) {
    if (!(error instanceof PublicSourceZipError)) throw error;
    return Object.freeze({
      outcome: "reject",
      phase: error.phase,
      reason: error.reason,
    });
  }
}

async function createWriterOperationFixture(root, vectorId) {
  const directory = path.join(root, vectorId);
  await mkdir(directory, { recursive: false, mode: 0o700 });
  const files = [{
    sourcePath: "nested/subject.bin",
    gitMode: "100644",
    payload: Buffer.from("authentic-file-identity-vector\n", "ascii"),
  }];
  const sourceTree = path.join(directory, "tree");
  const planPath = path.join(directory, "plan.json");
  const outputPath = path.join(directory, "artifact.zip");
  await writeSyntheticSourceTree(sourceTree, files);
  const fixture = planForFiles(files);
  await writeFile(planPath, fixture.planBytes, { flag: "wx", mode: 0o600 });
  return Object.freeze({
    directory,
    files,
    sourceTree,
    sourcePath: path.join(sourceTree, "nested", "subject.bin"),
    planPath,
    outputPath,
    fixture,
  });
}

async function executeFileIdentityVector(vector, root) {
  if (["F06", "F07", "F09", "F10", "F11"].includes(vector.vectorId)) {
    const candidate = await createSimpleCandidate(
      path.join(root, vector.vectorId),
      [{
        sourcePath: "subject.bin",
        gitMode: "100644",
        payload: Buffer.from("authentic-archive-identity-vector\n", "ascii"),
      }],
    );
    if (vector.vectorId === "F06") {
      await unlink(candidate.archivePath);
      await mkdir(candidate.archivePath, { recursive: false, mode: 0o700 });
      return observeZipAuthorityOperation(() => verifyPublicSourceZip({
        archive: candidate.archivePath,
        entryPlan: candidate.planPath,
      }));
    }
    if (vector.vectorId === "F07") {
      await link(
        candidate.archivePath,
        path.join(candidate.directory, "archive-extra-link.zip"),
      );
      return observeZipAuthorityOperation(() => verifyPublicSourceZip({
        archive: candidate.archivePath,
        entryPlan: candidate.planPath,
      }));
    }
    let mutationPerformed = false;
    const replacementPath = path.join(candidate.directory, "replacement.zip");
    if (vector.vectorId === "F10") {
      await writeFile(replacementPath, candidate.artifact.bytes, {
        flag: "wx",
        mode: 0o600,
      });
    }
    const observed = await observeZipAuthorityOperation(() => verifyPublicSourceZip({
      archive: candidate.archivePath,
      entryPlan: candidate.planPath,
      testHooks: {
        async checkpoint(details) {
          const mutationCheckpoint = vector.vectorId === "F11"
            ? "after-archive-open"
            : "after-archive-hash";
          if (details.checkpoint !== mutationCheckpoint || mutationPerformed) return;
          mutationPerformed = true;
          if (vector.vectorId === "F09") {
            const changed = Buffer.from(candidate.artifact.bytes);
            changed[0] ^= 1;
            await writeFile(candidate.archivePath, changed);
          } else if (vector.vectorId === "F10") {
            await rename(
              candidate.archivePath,
              path.join(candidate.directory, "original-opened.zip"),
            );
            await rename(replacementPath, candidate.archivePath);
          } else if (vector.vectorId === "F11") {
            await appendFile(candidate.archivePath, Buffer.from([0x78]));
          }
        },
      },
    }));
    if (!mutationPerformed) failVector(vector.vectorId);
    return observed;
  }

  const fixture = await createWriterOperationFixture(root, vector.vectorId);
  if (vector.vectorId === "F08") {
    await writeFile(
      fixture.outputPath,
      Buffer.from("occupied\n", "ascii"),
      { flag: "wx", mode: 0o600 },
    );
    return observeZipAuthorityOperation(() => preparePublicSourceZip({
      sourceTree: fixture.sourceTree,
      entryPlan: fixture.planPath,
      output: fixture.outputPath,
    }));
  }
  let mutationPerformed = false;
  let replacementPath = null;
  if (["F02", "F12"].includes(vector.vectorId)) {
    replacementPath = path.join(fixture.directory, "replacement-source.bin");
    await writeFile(replacementPath, fixture.files[0].payload, {
      flag: "wx",
      mode: 0o600,
    });
  }
  const observed = await observeZipAuthorityOperation(() => preparePublicSourceZip({
    sourceTree: fixture.sourceTree,
    entryPlan: fixture.planPath,
    output: fixture.outputPath,
    testHooks: {
      async checkpoint(details) {
        const sourceOpen = details.checkpoint === "after-pass-a-source-open";
        const betweenPasses = details.checkpoint === "before-pass-b";
        if (mutationPerformed) return;
        if (vector.vectorId === "F01" && sourceOpen) {
          const changed = Buffer.from(fixture.files[0].payload);
          changed[0] ^= 1;
          await writeFile(fixture.sourcePath, changed);
          mutationPerformed = true;
        } else if (vector.vectorId === "F02" && sourceOpen) {
          await rename(
            fixture.sourcePath,
            path.join(fixture.directory, "opened-source.bin"),
          );
          await rename(replacementPath, fixture.sourcePath);
          mutationPerformed = true;
        } else if (vector.vectorId === "F03" && sourceOpen) {
          await writeFile(
            fixture.sourcePath,
            fixture.files[0].payload.subarray(0, 5),
          );
          mutationPerformed = true;
        } else if (vector.vectorId === "F04" && sourceOpen) {
          await appendFile(fixture.sourcePath, Buffer.from("growth", "ascii"));
          mutationPerformed = true;
        } else if (vector.vectorId === "F05" && betweenPasses) {
          const sourceParent = path.dirname(fixture.sourcePath);
          await rename(sourceParent, sourceParent + "-replaced");
          await mkdir(sourceParent, { recursive: false, mode: 0o700 });
          await writeFile(fixture.sourcePath, fixture.files[0].payload, {
            flag: "wx",
            mode: 0o600,
          });
          mutationPerformed = true;
        } else if (vector.vectorId === "F12" && betweenPasses) {
          await rename(
            fixture.sourcePath,
            path.join(fixture.directory, "pass-a-source.bin"),
          );
          await rename(replacementPath, fixture.sourcePath);
          mutationPerformed = true;
        }
      },
    },
  }));
  if (!mutationPerformed) failVector(vector.vectorId);
  return observed;
}

async function pathExists(target) {
  try {
    await lstat(target);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
}

async function executeMalformedVector(vector, root, fixture) {
  switch (vector.vectorId) {
    case "M01":
      return observeVerifierOutcome(vector, root, fixture, fixture.zipBytes);
    case "M02": {
      const payloadFixture = planForFiles([{
        sourcePath: "payload.bin",
        gitMode: "100644",
        payload: Buffer.concat([
          Buffer.from([0x50, 0x4b, 0x05, 0x06]),
          Buffer.from("ordinary-payload", "ascii"),
        ]),
      }]);
      return observeVerifierOutcome(vector, root, payloadFixture, payloadFixture.zipBytes);
    }
    case "M03":
    case "M04":
    case "M05":
    case "M12":
      return observeVerifierOutcome(
        vector,
        root,
        fixture,
        mutateStructural(vector.vectorId, fixture),
      );
    case "M06": {
      const layout = computeCanonicalZipLayout(
        Array.from({ length: ZIP_LIMITS.maximumEntryCount }, (_, index) => ({
          sourcePath: "x/" + String(index).padStart(5, "0"),
          gitMode: "100644",
          byteLength: 0,
        })),
      );
      if (
        ZIP_LIMITS.maximumEntryCount !== 65534
        || layout.entries.length !== ZIP_LIMITS.maximumEntryCount
        || layout.entries[0].sourcePath !== "x/00000"
        || layout.entries.at(-1).sourcePath !== "x/65533"
        || layout.entryCount !== undefined
      ) failVector(vector.vectorId);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    }
    case "M07": {
      const observed = expectZipError(() => computeCanonicalZipLayout(
        Array.from({ length: 65535 }, (_, index) => ({
          sourcePath: "x/" + String(index).padStart(5, "0"),
          gitMode: "100644",
          byteLength: 0,
        })),
      ));
      return observed;
    }
    case "M08":
      if (requireZip32Number(0xfffffffe) !== 0xfffffffe) failVector(vector.vectorId);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "M09":
      return expectZipError(() => requireZip32Number(0xffffffff));
    case "M10":
      return expectZipError(() => computeCanonicalZipLayout([{
        sourcePath: "x",
        gitMode: "100644",
        byteLength: 0xfffffffe,
      }]));
    case "M11": {
      const centralDirectoryOffset = 0xfffffffe;
      const centralDirectoryLength = 1;
      return expectZipError(() => requireZip32Number(
        centralDirectoryOffset + centralDirectoryLength,
        "ZIP_LAYOUT",
        "central-directory-end",
      ));
    }
    case "M13":
    case "M15":
    case "M16":
    case "M17":
    case "M18":
      return observeVerifierOutcome(
        vector,
        root,
        fixture,
        mutateStructural(vector.vectorId, fixture),
      );
    case "M14": {
      let truncated = false;
      const observed = await observeVerifierOutcome(
        vector,
        root,
        fixture,
        fixture.zipBytes,
        {
          async checkpoint(details) {
            if (details.checkpoint !== "after-central-directory" || truncated) return;
            truncated = true;
            const [first] = fixture.plan.entries;
            const truncatedLength = first.dataOffset + first.byteLength - 1;
            await writeFile(
              path.join(root, vector.vectorId, "artifact.zip"),
              fixture.zipBytes.subarray(0, truncatedLength),
            );
          },
        },
      );
      if (!truncated) failVector(vector.vectorId);
      return observed;
    }
    default: failVector(vector.vectorId);
  }
}

function moduleRepositoryRoot() {
  return path.dirname(path.dirname(fileURLToPath(import.meta.url)));
}

function syntheticGitEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) {
      environment[key] = value;
    }
  }
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.GIT_AUTHOR_NAME = "R Vector Synthetic";
  environment.GIT_AUTHOR_EMAIL = "r-vector@example.invalid";
  environment.GIT_COMMITTER_NAME = "R Vector Synthetic";
  environment.GIT_COMMITTER_EMAIL = "r-vector@example.invalid";
  environment.GIT_AUTHOR_DATE = "2000-01-01T00:00:00Z";
  environment.GIT_COMMITTER_DATE = "2000-01-01T00:00:00Z";
  environment.LANG = "C";
  environment.LC_ALL = "C";
  environment.TZ = "UTC";
  return environment;
}

function runSyntheticGit(args, { cwd = undefined } = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: null,
    env: syntheticGitEnvironment(),
    maxBuffer: 512 * 1024 * 1024,
    shell: false,
    windowsHide: true,
  });
  if (result.error || result.status !== 0 || result.signal !== null) {
    failVector(null, "synthetic-git-authority-failed");
  }
  return result.stdout;
}

async function writeSyntheticRepositoryFile(
  repository,
  relativePath,
  bytes,
  { exclusive = true, mode = 0o644 } = {},
) {
  const target = path.join(repository, ...relativePath.split("/"));
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await writeFile(target, bytes, { flag: exclusive ? "wx" : "w", mode });
}

async function populateSyntheticSourceCommit(repository) {
  const root = moduleRepositoryRoot();
  const manifestPath = "developer/public-source-manifest.json";
  const manifestBytes = await readFile(path.join(root, ...manifestPath.split("/")));
  for (const relativePath of [
    ...SYNTHETIC_SOURCE_EXACT_PATHS,
    ...SYNTHETIC_SOURCE_PREFIX_PATHS,
  ]) {
    const bytes = relativePath === manifestPath
      ? manifestBytes
      : Buffer.from("synthetic:" + relativePath + "\n", "utf8");
    await writeSyntheticRepositoryFile(repository, relativePath, bytes);
  }
}

function commitSyntheticRepository(repository, message) {
  runSyntheticGit(["add", "--all"], { cwd: repository });
  runSyntheticGit([
    "-c",
    "user.name=R Vector Synthetic",
    "-c",
    "user.email=r-vector@example.invalid",
    "commit",
    "--quiet",
    "-m",
    message,
  ], { cwd: repository });
  const commit = runSyntheticGit(["rev-parse", "HEAD"], { cwd: repository })
    .toString("ascii")
    .trim();
  if (!/^[0-9a-f]{40}$/u.test(commit)) failVector(null, "synthetic-git-authority-failed");
  return commit;
}

function parseSyntheticTreeEntry(bytes, expectedPath) {
  const text = bytes.toString("utf8").trim();
  if (text.length === 0 || text.includes("\n")) {
    failVector(null, "synthetic-git-authority-failed");
  }
  const tab = text.indexOf("\t");
  if (tab < 0) failVector(null, "synthetic-git-authority-failed");
  const metadata = text.slice(0, tab).split(" ");
  const actualPath = text.slice(tab + 1);
  if (metadata.length !== 3 || actualPath !== expectedPath) {
    failVector(null, "synthetic-git-authority-failed");
  }
  const [gitMode, objectType, gitBlobObjectId] = metadata;
  if (
    objectType !== "blob"
    || !["100644", "100755"].includes(gitMode)
    || !/^[0-9a-f]{40}$/u.test(gitBlobObjectId)
  ) failVector(null, "synthetic-git-authority-failed");
  return Object.freeze({ gitMode, gitBlobObjectId });
}

async function loadSyntheticCriticalToolAuthority(repository, toolingCommit) {
  const root = moduleRepositoryRoot();
  const entries = [];
  const modules = [];
  for (const relativePath of CRITICAL_TOOL_PATHS) {
    const tree = parseSyntheticTreeEntry(
      runSyntheticGit(["ls-tree", toolingCommit, "--", relativePath], {
        cwd: repository,
      }),
      relativePath,
    );
    const bytes = await readFile(path.join(root, ...relativePath.split("/")));
    const sha256 = sha256Bytes(bytes);
    entries.push(Object.freeze({
      path: relativePath,
      gitMode: tree.gitMode,
      gitBlobObjectId: tree.gitBlobObjectId,
      declaredByteSize: bytes.length,
      sha256,
    }));
    if (WORKER_MODULE_PATHS.includes(relativePath)) {
      modules.push(Object.freeze({
        relativePath,
        byteLength: bytes.length,
        sha256,
        sourceBase64: bytes.toString("base64"),
      }));
    }
  }
  const criticalToolSet = {
    documentKind: "ieltmps-reproducibility-critical-tool-set",
    schemaVersion: 1,
    toolSetId: "public-source-zip-reproducibility-v1",
    toolingCommit,
    entries,
  };
  return Object.freeze({
    criticalToolSet: deepFreezeZipReproducibility(criticalToolSet),
    criticalToolSetSha256: sha256Bytes(
      encodeCanonicalCriticalToolSet(criticalToolSet),
    ),
    modules: Object.freeze(modules),
  });
}

async function createSyntheticGitAuthority(root) {
  const repository = path.join(root, "repository");
  await mkdir(repository, { recursive: false, mode: 0o700 });
  runSyntheticGit(["init", "--quiet", "--initial-branch=main"], {
    cwd: repository,
  });
  await populateSyntheticSourceCommit(repository);
  const sourceCommit = commitSyntheticRepository(repository, "synthetic source");
  const realRoot = moduleRepositoryRoot();
  for (const relativePath of CRITICAL_TOOL_PATHS) {
    const bytes = await readFile(path.join(realRoot, ...relativePath.split("/")));
    await writeSyntheticRepositoryFile(
      repository,
      relativePath,
      bytes,
      { exclusive: false },
    );
  }
  const toolingCommit = commitSyntheticRepository(repository, "synthetic tooling");
  return Object.freeze({ repository, sourceCommit, toolingCommit });
}

function syntheticContextSha256(label) {
  return sha256Bytes(Buffer.from("ieltmps-r-vector-context:" + label + "\n", "ascii"));
}

async function buildReproducibilityCandidate(cell, label) {
  const assignmentDirectory = path.join(cell.root, label);
  await mkdir(assignmentDirectory, { recursive: false, mode: 0o700 });
  return buildFreshZipCandidate({
    repository: cell.repository,
    sourceCommit: cell.sourceCommit,
    assignmentDirectory,
    expectedManifestSha256: cell.context.manifestSha256,
    expectedMembershipReportSha256: cell.context.membershipReportSha256,
  });
}

function comparableLocalCandidate(candidate) {
  return Object.freeze({
    artifactPath: candidate.artifactPath,
    artifactIdentity: candidate.artifactIdentity,
    artifactSha256: candidate.artifactSha256,
    artifactByteLength: candidate.artifactByteLength,
    artifactBytes: candidate.artifactBytes,
    entryPlanPath: candidate.entryPlanPath,
    entryPlanIdentity: candidate.entryPlanIdentity,
    entryPlanSha256: candidate.entryPlanSha256,
    entryPlanBytes: candidate.entryPlanBytes,
    transcriptSha256: candidate.transcriptSha256,
    transcript: candidate.transcript,
  });
}

function comparableWorkerOutput(output) {
  return Object.freeze({
    artifactPath: output.artifact.path,
    artifactIdentity: output.artifact.identity,
    artifactSha256: output.response.artifactSha256,
    artifactByteLength: output.response.artifactByteLength,
    artifactBytes: output.artifact.bytes,
    entryPlanPath: null,
    entryPlanIdentity: null,
    entryPlanSha256: output.response.entryPlanSha256,
    entryPlanBytes: output.response.entryPlan,
    transcriptSha256: output.response.transcriptSha256,
    transcript: output.response.transcript,
  });
}

function requireSameReproducibleBytes(vectorId, outputs) {
  const [first] = outputs;
  if (!first) failVector(vectorId);
  for (const output of outputs) {
    if (
      output.artifactSha256 !== first.artifactSha256
      || output.artifactByteLength !== first.artifactByteLength
      || output.entryPlanSha256 !== first.entryPlanSha256
      || output.transcriptSha256 !== first.transcriptSha256
      || !output.artifactBytes.equals(first.artifactBytes)
      || !output.entryPlanBytes.equals(first.entryPlanBytes)
      || !output.transcript.equals(first.transcript)
    ) failVector(vectorId);
  }
}

function requireDistinctArtifactIdentities(vectorId, outputs) {
  const seenPaths = new Set();
  const seenIdentities = new Set();
  for (const output of outputs) {
    if (
      typeof output.artifactPath !== "string"
      || output.artifactIdentity.links !== 1n
      || !output.artifactIdentity.meaningful
    ) failVector(vectorId);
    const pathKey = canonicalNativePath(output.artifactPath);
    const identityKey = cleanupIdentityKey(output.artifactIdentity);
    if (seenPaths.has(pathKey) || seenIdentities.has(identityKey)) {
      failVector(vectorId);
    }
    seenPaths.add(pathKey);
    seenIdentities.add(identityKey);
  }
}

function requireSameProcessIndependence(vectorId, outputs) {
  for (let left = 0; left < outputs.length; left += 1) {
    const leftOutput = outputs[left];
    if (
      leftOutput.artifactIdentity.links !== 1n
      || leftOutput.entryPlanIdentity.links !== 1n
      || !leftOutput.artifactIdentity.meaningful
      || !leftOutput.entryPlanIdentity.meaningful
      || sha256Bytes(leftOutput.entryPlanBytes) !== leftOutput.entryPlanSha256
      || sha256Bytes(leftOutput.artifactBytes) !== leftOutput.artifactSha256
    ) failVector(vectorId);
    for (let right = left + 1; right < outputs.length; right += 1) {
      const rightOutput = outputs[right];
      if (
        pathsEqual(leftOutput.artifactPath, rightOutput.artifactPath)
        || pathsEqual(leftOutput.entryPlanPath, rightOutput.entryPlanPath)
        || sameObject(leftOutput.artifactIdentity, rightOutput.artifactIdentity)
        || sameObject(leftOutput.entryPlanIdentity, rightOutput.entryPlanIdentity)
      ) failVector(vectorId);
    }
  }
}

async function createReproducibilityCell(root) {
  await mkdir(root, { recursive: false, mode: 0o700 });
  const authority = await createSyntheticGitAuthority(root);
  const membership = await loadValidatedPublicSourceMembership({
    repo: authority.repository,
    commit: authority.sourceCommit,
  });
  const critical = await loadSyntheticCriticalToolAuthority(
    authority.repository,
    authority.toolingCommit,
  );
  const vectorSetSha256 = sha256Bytes(
    await readFile(path.join(
      moduleRepositoryRoot(),
      "developer",
      "public-source-zip-boundary-vectors-v1.json",
    )),
  );
  const context = Object.freeze({
    toolingCommit: authority.toolingCommit,
    manifestSha256: membership.manifestSha256,
    membershipReportSha256: sha256Bytes(membership.reportBytes),
    criticalToolSetSha256: critical.criticalToolSetSha256,
    runtimeIdentitySha256: syntheticContextSha256("runtime"),
    gitIdentitySha256: syntheticContextSha256("git"),
    runnerPolicySha256: syntheticContextSha256("policy"),
    testVectorSetSha256: vectorSetSha256,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
  });
  const cell = {
    root,
    repository: authority.repository,
    sourceCommit: authority.sourceCommit,
    toolingCommit: authority.toolingCommit,
    context,
    modules: critical.modules,
    capsule: null,
    sameProcess: null,
    sameHost: null,
    timestampCandidate: null,
    permissionCandidate: null,
    timestampMutationObserved: false,
    permissionMutationObserved: false,
  };
  const capsuleRoot = path.join(root, "capsule");
  await mkdir(capsuleRoot, { recursive: false, mode: 0o700 });
  cell.capsule = await createTrustedZipWorkerModuleCapsule({
    privateRoot: capsuleRoot,
    toolingCommit: authority.toolingCommit,
    modules: critical.modules,
  });
  cell.sameProcess = Object.freeze([
    comparableLocalCandidate(await buildReproducibilityCandidate(cell, "same-process-a")),
    comparableLocalCandidate(await buildReproducibilityCandidate(cell, "same-process-b")),
  ]);

  const timestampPath = path.join(
    authority.repository,
    "api-contract",
    "README.md",
  );
  const timestampBefore = await lstat(timestampPath, { bigint: true });
  await utimes(timestampPath, new Date(946684801000), new Date(946684801000));
  const timestampAfter = await lstat(timestampPath, { bigint: true });
  cell.timestampMutationObserved = timestampBefore.mtimeNs !== timestampAfter.mtimeNs;
  cell.timestampCandidate = comparableLocalCandidate(
    await buildReproducibilityCandidate(cell, "timestamp-mutation"),
  );

  const permissionPath = path.join(
    authority.repository,
    "backend",
    "scripts",
    "example.mjs",
  );
  const permissionBefore = await lstat(permissionPath, { bigint: true });
  await chmod(permissionPath, 0o444);
  const permissionAfter = await lstat(permissionPath, { bigint: true });
  cell.permissionMutationObserved = permissionBefore.mode !== permissionAfter.mode;
  try {
    cell.permissionCandidate = comparableLocalCandidate(
      await buildReproducibilityCandidate(cell, "permission-mutation"),
    );
  } finally {
    await chmod(permissionPath, 0o666).catch(() => {});
  }

  const sameHostRoot = path.join(root, "same-host");
  await mkdir(sameHostRoot, { recursive: false, mode: 0o700 });
  cell.sameHost = await runSameHostZipCandidates({
    repository: authority.repository,
    sourceCommit: authority.sourceCommit,
    privateRoot: sameHostRoot,
    context,
    capsule: cell.capsule,
  });
  return Object.freeze(cell);
}

function directWorkerProfile() {
  return Object.freeze({
    lang: "C",
    lcAll: "C",
    timezone: "UTC",
    sourceDateEpoch: "0",
  });
}

async function createDirectWorkerRequest(cell, root, assignmentId = "worker-a") {
  await mkdir(root, { recursive: false, mode: 0o700 });
  const assignments = [];
  for (const id of ["worker-a", "worker-b"]) {
    const assignmentPath = path.join(root, id);
    await mkdir(assignmentPath, { recursive: false, mode: 0o700 });
    assignments.push(Object.freeze({
      assignmentId: id,
      assignmentNonce: randomBytes(32).toString("hex"),
      assignmentPathSha256: privatePathSha256(assignmentPath),
      path: assignmentPath,
    }));
  }
  const selected = assignments.find((entry) => entry.assignmentId === assignmentId);
  if (!selected) failVector();
  const contextSha256 = workerContextSha256(cell.context);
  const lease = {
    schemaVersion: 1,
    runId: randomBytes(32).toString("hex"),
    parentPid: process.pid,
    contextSha256,
    assignments: assignments.map((entry) => ({
      assignmentId: entry.assignmentId,
      assignmentNonce: entry.assignmentNonce,
      assignmentPathSha256: entry.assignmentPathSha256,
    })),
  };
  const request = {
    protocol: WORKER_PROTOCOL,
    lease,
    assignmentId: selected.assignmentId,
    assignmentNonce: selected.assignmentNonce,
    assignmentPath: selected.path,
    repositoryPath: cell.repository,
    sourceCommit: cell.sourceCommit,
    context: cell.context,
  };
  validateWorkerRequest(request);
  return Object.freeze({
    request,
    assignmentPath: selected.path,
    message: canonicalPrivateJsonBytes(request).toString("utf8"),
    environment: sanitizedWorkerEnvironment(
      process.env,
      selected.path,
      directWorkerProfile(),
    ),
    expectedResponse: Object.freeze({
      runId: lease.runId,
      assignmentId: selected.assignmentId,
      contextSha256,
      workerCapsuleSha256: cell.capsule.sha256,
      workerModuleSetSha256: cell.capsule.moduleSetSha256,
      workerEntryModuleSha256: cell.capsule.entryModuleSha256,
    }),
  });
}

function outcomeFromWorkerObservation(vectorId, observation) {
  if (
    observation.code === 0
    && observation.signal === null
    && !observation.timeout
    && !observation.forcedTermination
    && !observation.spawnError
    && observation.stderr.length === 0
  ) return Object.freeze({ outcome: "accept", phase: null, reason: null });
  if (
    observation.code !== 1
    || observation.signal !== null
    || observation.timeout
    || observation.forcedTermination
    || observation.spawnError
    || observation.stdout.length !== 0
    || observation.responses.length !== 0
  ) failVector(vectorId);
  const match = /^ERROR ([A-Z_]+): ([a-z0-9]+(?:-[a-z0-9]+)*)\n$/u
    .exec(observation.stderr.toString("utf8"));
  if (!match) failVector(vectorId);
  return Object.freeze({ outcome: "reject", phase: match[1], reason: match[2] });
}

function validateSuccessfulDirectWorker(vectorId, observation, expectedResponse) {
  if (
    observation.code !== 0
    || observation.signal !== null
    || observation.timeout
    || observation.forcedTermination
    || observation.spawnError
    || observation.stdout.length !== 0
    || observation.stderr.length !== 0
    || observation.responses.length !== 1
    || typeof observation.responses[0] !== "string"
  ) failVector(vectorId);
  return validateWorkerResponse(
    parseCanonicalPrivateJsonText(observation.responses[0], "SAME_HOST"),
    expectedResponse,
  );
}

async function observeReproducibilityOperation(operation) {
  try {
    await operation();
    return Object.freeze({ outcome: "accept", phase: null, reason: null });
  } catch (error) {
    if (error instanceof PublicSourceZipBoundaryVectorError) throw error;
    if (!(error instanceof PublicSourceZipReproducibilityError)) throw error;
    return Object.freeze({
      outcome: "reject",
      phase: error.phase,
      reason: error.reason,
    });
  }
}

function mutateWorkerModules(modules, relativePath, transformSource) {
  return Object.freeze(modules.map((entry) => {
    if (entry.relativePath !== relativePath) return entry;
    const source = Buffer.from(entry.sourceBase64, "base64").toString("utf8");
    const changed = Buffer.from(transformSource(source), "utf8");
    return Object.freeze({
      relativePath: entry.relativePath,
      byteLength: changed.length,
      sha256: sha256Bytes(changed),
      sourceBase64: changed.toString("base64"),
    });
  }));
}

async function observeInvalidFirstWorker(cell, root) {
  const direct = await createDirectWorkerRequest(cell, root);
  const observation = await spawnTrustedZipWorkerRaw({
    requestMessages: [
      canonicalPrivateJsonBytes({ protocol: "legacy" }).toString("utf8"),
      direct.message,
    ],
    environment: direct.environment,
    workingDirectory: direct.assignmentPath,
    capsule: cell.capsule,
  });
  return outcomeFromWorkerObservation("R13", observation);
}

async function runHostileSecondWorkerSet(cell, root) {
  await mkdir(root, { recursive: false, mode: 0o700 });
  const result = await runSameHostZipCandidates({
    repository: cell.repository,
    sourceCommit: cell.sourceCommit,
    privateRoot: root,
    context: cell.context,
    capsule: cell.capsule,
    protocolControl: { immediateHostileSecond: true },
  });
  requireSameReproducibleBytes(
    "R14",
    result.outputs.map(comparableWorkerOutput),
  );
  return result;
}

async function observeReplayWorker(cell, root) {
  const direct = await createDirectWorkerRequest(cell, root);
  const first = await spawnTrustedZipWorkerRaw({
    requestMessages: [direct.message],
    environment: direct.environment,
    workingDirectory: direct.assignmentPath,
    capsule: cell.capsule,
  });
  validateSuccessfulDirectWorker("R15", first, direct.expectedResponse);
  const second = await spawnTrustedZipWorkerRaw({
    requestMessages: [direct.message],
    environment: direct.environment,
    workingDirectory: direct.assignmentPath,
    capsule: cell.capsule,
  });
  return outcomeFromWorkerObservation("R15", second);
}

async function observeCapsuleSubstitution(cell, root) {
  const capsuleRoot = path.join(root, "capsule");
  await mkdir(root, { recursive: false, mode: 0o700 });
  await mkdir(capsuleRoot, { recursive: false, mode: 0o700 });
  const substitutedModules = mutateWorkerModules(
    cell.modules,
    WORKER_ENTRY_MODULE,
    (source) => source + "\n// R16 capsule-substitution control\n",
  );
  const substitutedCapsule = await createTrustedZipWorkerModuleCapsule({
    privateRoot: capsuleRoot,
    toolingCommit: cell.toolingCommit,
    modules: substitutedModules,
  });
  const direct = await createDirectWorkerRequest(cell, path.join(root, "assignment"));
  const observation = await spawnTrustedZipWorkerRaw({
    requestMessages: [direct.message],
    environment: direct.environment,
    workingDirectory: direct.assignmentPath,
    capsule: substitutedCapsule,
  });
  return observeReproducibilityOperation(async () => {
    if (
      observation.code !== 0
      || observation.signal !== null
      || observation.timeout
      || observation.forcedTermination
      || observation.spawnError
      || observation.stdout.length !== 0
      || observation.stderr.length !== 0
      || observation.responses.length !== 1
      || typeof observation.responses[0] !== "string"
    ) failVector("R16");
    validateWorkerResponse(
      parseCanonicalPrivateJsonText(observation.responses[0], "SAME_HOST"),
      direct.expectedResponse,
    );
  });
}

async function observeUnapprovedWorkerImport(cell, root) {
  const capsuleRoot = path.join(root, "capsule");
  await mkdir(root, { recursive: false, mode: 0o700 });
  await mkdir(capsuleRoot, { recursive: false, mode: 0o700 });
  const substitutedModules = mutateWorkerModules(
    cell.modules,
    WORKER_ENTRY_MODULE,
    (source) => "import \"node:assert\";\n" + source,
  );
  const substitutedCapsule = await createTrustedZipWorkerModuleCapsule({
    privateRoot: capsuleRoot,
    toolingCommit: cell.toolingCommit,
    modules: substitutedModules,
  });
  const direct = await createDirectWorkerRequest(cell, path.join(root, "assignment"));
  const observation = await spawnTrustedZipWorkerRaw({
    requestMessages: [direct.message],
    environment: direct.environment,
    workingDirectory: direct.assignmentPath,
    capsule: substitutedCapsule,
  });
  return outcomeFromWorkerObservation("R18", observation);
}

function requireNaturalWorkerExit(vectorId, sameHost) {
  for (const output of sameHost.outputs) {
    if (
      output.observation.code !== 0
      || output.observation.signal !== null
      || output.observation.timeout
      || output.observation.forcedTermination
      || output.observation.spawnError
      || output.observation.stdout.length !== 0
      || output.observation.stderr.length !== 0
      || output.observation.responses.length !== 1
      || output.response.workerRequestListenerCount !== 0
      || output.response.claimCount !== 1
    ) failVector(vectorId);
  }
}

function requireWorkerAudit(vectorId, sameHost) {
  for (const output of sameHost.outputs) {
    if (
      output.response.workerProcessInvocationCount < 1
      || output.response.comparatorProcessInvocationCount !== 0
      || output.response.workerLoadedModuleCount !== WORKER_MODULE_PATHS.length
      || output.response.workerUnapprovedModuleLoadCount !== 0
    ) failVector(vectorId);
  }
}

async function executeReproducibilityVector(vector, root, state) {
  if (!state.reproducibility) {
    state.reproducibility = await createReproducibilityCell(
      path.join(root, "reproducibility-cell"),
    );
  }
  const cell = state.reproducibility;
  const sameProcess = cell.sameProcess;
  const sameHost = cell.sameHost.outputs.map(comparableWorkerOutput);
  switch (vector.vectorId) {
    case "R01":
      requireSameReproducibleBytes(vector.vectorId, sameProcess);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R02":
      if (!sameProcess[0].transcript.equals(sameProcess[1].transcript)) {
        failVector(vector.vectorId);
      }
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R03":
      if (
        pathsEqual(sameProcess[0].artifactPath, sameProcess[1].artifactPath)
        || pathsEqual(sameProcess[0].entryPlanPath, sameProcess[1].entryPlanPath)
      ) failVector(vector.vectorId);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R04":
      requireSameProcessIndependence(vector.vectorId, sameProcess);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R05":
      requireDistinctArtifactIdentities(vector.vectorId, sameProcess);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R06":
      requireSameReproducibleBytes(vector.vectorId, sameHost);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R07":
      if (!sameHost[0].transcript.equals(sameHost[1].transcript)) {
        failVector(vector.vectorId);
      }
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R08": {
      const four = Object.freeze([...sameProcess, ...sameHost]);
      requireSameReproducibleBytes(vector.vectorId, four);
      requireDistinctArtifactIdentities(vector.vectorId, four);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    }
    case "R09":
      if (
        cell.sameHost.profiles[0].lang === cell.sameHost.profiles[1].lang
        || cell.sameHost.profiles[0].lcAll === cell.sameHost.profiles[1].lcAll
      ) failVector(vector.vectorId);
      requireSameReproducibleBytes(vector.vectorId, sameHost);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R10":
      if (
        cell.sameHost.profiles[0].timezone === cell.sameHost.profiles[1].timezone
        || cell.sameHost.profiles[0].sourceDateEpoch
          === cell.sameHost.profiles[1].sourceDateEpoch
      ) failVector(vector.vectorId);
      requireSameReproducibleBytes(vector.vectorId, sameHost);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R11":
      if (!cell.timestampMutationObserved) failVector(vector.vectorId);
      requireSameReproducibleBytes(
        vector.vectorId,
        [sameProcess[0], cell.timestampCandidate],
      );
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R12":
      if (!cell.permissionMutationObserved) failVector(vector.vectorId);
      requireSameReproducibleBytes(
        vector.vectorId,
        [sameProcess[0], cell.permissionCandidate],
      );
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R13":
      return observeInvalidFirstWorker(cell, path.join(root, "r13-invalid-first"));
    case "R14":
      await runHostileSecondWorkerSet(cell, path.join(root, "r14-hostile-second"));
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R15":
      return observeReplayWorker(cell, path.join(root, "r15-replay"));
    case "R16":
      return observeCapsuleSubstitution(cell, path.join(root, "r16-capsule"));
    case "R17":
      requireNaturalWorkerExit(vector.vectorId, cell.sameHost);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    case "R18": {
      requireWorkerAudit(vector.vectorId, cell.sameHost);
      if (
        CRITICAL_TOOL_PATHS.some((entry) => entry.includes("compare-reproducibility"))
        || SUCCESS_OUTPUT_NAMES.length !== 8
        || CANONICAL_FAILURE_OUTPUT_NAMES.length !== 4
        || SUCCESS_OUTPUT_NAMES.at(-1) !== ".complete"
      ) failVector(vector.vectorId);
      const observed = await observeUnapprovedWorkerImport(
        cell,
        path.join(root, "r18-unapproved-import"),
      );
      if (
        observed.outcome !== "reject"
        || observed.phase !== "TOOL_SET"
        || observed.reason !== "worker-loaded-bytes-mismatch"
      ) failVector(vector.vectorId);
      return Object.freeze({ outcome: "accept", phase: null, reason: null });
    }
    default: failVector(vector.vectorId);
  }
}

function requireObservedOutcome(vector, observed) {
  if (
    !observed
    || observed.outcome !== vector.expectedOutcome
    || observed.phase !== vector.expectedPhase
    || observed.reason !== vector.expectedReason
  ) failVector(vector.vectorId, "vector-expected-outcome-mismatch");
}

async function executeVector(vector, root, state, registry, control) {
  const executor = registry.get(vector.vectorId);
  if (!executor) failVector(vector.vectorId, "executor-registry-invalid");
  const observed = await executor.execute(Object.freeze({
    vector,
    root,
    state,
  }));
  let operationCompleted = true;
  requireObservedOutcome(vector, observed);
  let assertionsCompleted = true;
  if (control?.fakeOperationCompletedId === vector.vectorId) {
    operationCompleted = false;
  }
  if (control?.fakeAssertionsCompletedId === vector.vectorId) {
    assertionsCompleted = false;
  }
  return Object.freeze({
    internalResultId: "completed-" + vector.vectorId,
    vectorId: vector.vectorId,
    executorId: executor.vectorId,
    executionClass: executor.executionClass,
    authenticity: executor.authenticity,
    operationCompleted,
    assertionsCompleted,
  });
}

async function validateTemporaryParent(value) {
  const selected = value ?? path.resolve(os.tmpdir());
  if (
    typeof selected !== "string"
    || !path.isAbsolute(selected)
    || path.resolve(selected) !== selected
  ) failVector();
  await requireRealDirectory(selected);
  return selected;
}

async function cleanupVectorRoot(root, identity) {
  const capture = async () => {
    const rootState = await lstat(root, { bigint: true });
    if (
      rootState.isSymbolicLink()
      || !rootState.isDirectory()
      || rootState.dev !== identity.device
      || rootState.ino !== identity.inode
      || !pathsEqual(await realpath(root), root)
    ) failVector();
    const records = [];
    const pending = [root];
    while (pending.length > 0) {
      const directoryPath = pending.shift();
      const directoryState = await lstat(directoryPath, { bigint: true });
      if (directoryState.isSymbolicLink() || !directoryState.isDirectory()) {
        failVector();
      }
      records.push(Object.freeze({
        path: directoryPath,
        kind: "directory",
        identity: identityFromState(directoryState),
      }));
      for (const name of (await readdir(directoryPath)).sort()) {
        const childPath = path.join(directoryPath, name);
        const childState = await lstat(childPath, { bigint: true });
        if (childState.isDirectory() && !childState.isSymbolicLink()) {
          pending.push(childPath);
          continue;
        }
        const bytes = childState.isFile() ? await readFile(childPath) : null;
        records.push(Object.freeze({
          path: childPath,
          kind: childState.isSymbolicLink() ? "reparse" : "file",
          identity: identityFromState(childState),
          byteLength: bytes?.length ?? null,
          sha256: bytes ? sha256Bytes(bytes) : null,
        }));
      }
    }
    return Object.freeze(records);
  };
  const validate = async (records) => {
    for (const record of records) {
      const state = await lstat(record.path, { bigint: true });
      const observed = identityFromState(state);
      if (!sameObject(observed, record.identity) || state.mode !== record.identity.mode) {
        failVector();
      }
      if (record.kind === "directory") {
        if (state.isSymbolicLink() || !state.isDirectory()) failVector();
      } else if (record.kind === "reparse") {
        if (!state.isSymbolicLink()) failVector();
      } else if (
        state.isSymbolicLink()
        || !state.isFile()
        || state.size !== BigInt(record.byteLength)
        || state.nlink !== record.identity.links
        || sha256Bytes(await readFile(record.path)) !== record.sha256
      ) failVector();
    }
  };
  const records = await capture();
  await validate(records);
  const second = await capture();
  if (
    second.length !== records.length
    || second.some((record, index) => (
      record.path !== records[index].path
      || record.kind !== records[index].kind
      || !identitiesEqual(record.identity, records[index].identity)
      || record.byteLength !== records[index].byteLength
      || record.sha256 !== records[index].sha256
    ))
  ) failVector();
  const leaves = records
    .filter((record) => record.kind !== "directory")
    .sort((left, right) => right.path.length - left.path.length);
  const priorUnlinks = new Map();
  for (const record of leaves) {
    const state = await lstat(record.path, { bigint: true });
    const key = cleanupIdentityKey(record.identity);
    const prior = priorUnlinks.get(key) ?? 0n;
    if (
      !sameObject(identityFromState(state), record.identity)
      || (
        record.kind === "file"
        && (
          state.nlink !== record.identity.links - prior
          || state.size !== BigInt(record.byteLength)
          || sha256Bytes(await readFile(record.path)) !== record.sha256
        )
      )
    ) failVector();
    await unlink(record.path);
    priorUnlinks.set(key, prior + 1n);
    if (await pathExists(record.path)) failVector();
  }
  const directories = records
    .filter((record) => record.kind === "directory")
    .sort((left, right) => right.path.length - left.path.length);
  for (const record of directories) {
    const state = await lstat(record.path, { bigint: true });
    if (
      state.isSymbolicLink()
      || !state.isDirectory()
      || !sameObject(identityFromState(state), record.identity)
      || (await readdir(record.path)).length !== 0
    ) failVector();
    await rmdir(record.path);
    if (await pathExists(record.path)) failVector();
  }
}

function buildEffectiveExecutorRegistry(control) {
  const registry = new Map(BOUNDARY_VECTOR_EXECUTOR_REGISTRY);
  if (control?.removedExecutorId !== undefined) {
    registry.delete(control.removedExecutorId);
  }
  if (control?.extraExecutorId !== undefined) {
    registry.set(control.extraExecutorId, executorDefinition(
      control.extraExecutorId,
      VECTOR_EXECUTION_CLASSES[0],
      "production-operation",
      async () => Object.freeze({ outcome: "accept", phase: null, reason: null }),
    ));
  }
  if (control?.wrongExecutorAssignmentId !== undefined) {
    const vectorId = control.wrongExecutorAssignmentId;
    const prior = registry.get(vectorId);
    if (prior) {
      const index = BOUNDARY_VECTOR_EXECUTOR_IDS.indexOf(vectorId);
      const wrongId = BOUNDARY_VECTOR_EXECUTOR_IDS[
        (index + 1) % BOUNDARY_VECTOR_EXECUTOR_IDS.length
      ];
      registry.set(vectorId, Object.freeze({ ...prior, vectorId: wrongId }));
    }
  }
  if (control?.expectationEchoExecutorId !== undefined) {
    const vectorId = control.expectationEchoExecutorId;
    const prior = registry.get(vectorId);
    if (prior) {
      registry.set(vectorId, Object.freeze({
        ...prior,
        authenticity: "expected-outcome-echo",
        execute: async ({ vector }) => Object.freeze({
          outcome: vector.expectedOutcome,
          phase: vector.expectedPhase,
          reason: vector.expectedReason,
        }),
      }));
    }
  }
  if (control?.sourceSubstringOnlyExecutorId !== undefined) {
    const vectorId = control.sourceSubstringOnlyExecutorId;
    const prior = registry.get(vectorId);
    if (prior) {
      registry.set(vectorId, Object.freeze({
        ...prior,
        authenticity: "source-substring-only",
        execute: async () => Object.freeze({
          outcome: "accept",
          phase: null,
          reason: null,
        }),
      }));
    }
  }
  return registry;
}

function validateExecutorRegistry(registry) {
  const descriptorById = new Map(BOUNDARY_VECTOR_DESCRIPTORS.map(
    (entry) => [entry.vectorId, entry],
  ));
  const allowedAuthenticity = new Set([
    "production-operation",
    "authentic-file-identity",
    "authentic-malformed-zip",
    "authentic-reproducibility",
  ]);
  if (
    registry.size !== 119
    || descriptorById.size !== 119
    || BOUNDARY_VECTOR_EXECUTOR_IDS.length !== 119
    || new Set(BOUNDARY_VECTOR_EXECUTOR_IDS).size !== 119
  ) failVector(null, "executor-registry-invalid");
  for (const vectorId of BOUNDARY_VECTOR_EXECUTOR_IDS) {
    const descriptorValue = descriptorById.get(vectorId);
    const executor = registry.get(vectorId);
    if (
      !descriptorValue
      || !executor
      || executor.vectorId !== vectorId
      || executor.executionClass !== descriptorValue.executionClass
      || !allowedAuthenticity.has(executor.authenticity)
      || typeof executor.execute !== "function"
    ) failVector(vectorId, "executor-registry-invalid");
  }
  for (const vectorId of registry.keys()) {
    if (!descriptorById.has(vectorId)) {
      failVector(vectorId, "executor-registry-invalid");
    }
  }
  return registry;
}

function normalizeVectorOptions(options) {
  assertProxyFreeAuthorityGraph(options, VECTOR_AUTHORITY_OPTIONS);
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failVector();
  }
  const keys = Object.keys(options);
  const symbols = Object.getOwnPropertySymbols(options);
  if (
    keys.some((key) => ![
      "testVectorSet",
      "temporaryParent",
      "expectedSha256",
      "ownershipLedger",
    ].includes(key))
    || symbols.some((symbol) => symbol !== VECTOR_TEST_HOOK)
    || typeof options.testVectorSet !== "string"
    || (
      options.temporaryParent !== undefined
      && typeof options.temporaryParent !== "string"
    )
    || (
      options.expectedSha256 !== undefined
      && !SHA256_PATTERN.test(options.expectedSha256)
    )
    || (
      options.ownershipLedger !== undefined
      && validateOwnershipLedger(options.ownershipLedger) === null
    )
  ) failVector();
  const control = options[VECTOR_TEST_HOOK] ?? null;
  if (
    control !== null
    && (
      !control
      || typeof control !== "object"
      || Array.isArray(control)
      || Object.keys(control).some((key) => ![
        "disabledVectorId",
        "failVectorId",
        "removedExecutorId",
        "extraExecutorId",
        "wrongExecutorAssignmentId",
        "fakeOperationCompletedId",
        "fakeAssertionsCompletedId",
        "expectationEchoExecutorId",
        "sourceSubstringOnlyExecutorId",
        "onAccounting",
      ].includes(key))
      || (
        control.disabledVectorId !== undefined
        && typeof control.disabledVectorId !== "string"
      )
      || (
        control.failVectorId !== undefined
        && typeof control.failVectorId !== "string"
      )
      || [
        "removedExecutorId",
        "extraExecutorId",
        "wrongExecutorAssignmentId",
        "fakeOperationCompletedId",
        "fakeAssertionsCompletedId",
        "expectationEchoExecutorId",
        "sourceSubstringOnlyExecutorId",
      ].some((key) => (
        control[key] !== undefined && typeof control[key] !== "string"
      ))
      || (
        control.onAccounting !== undefined
        && typeof control.onAccounting !== "function"
      )
    )
  ) failVector();
  return Object.freeze({
    testVectorSet: options.testVectorSet,
    temporaryParent: options.temporaryParent,
    expectedSha256: options.expectedSha256 ?? null,
    ownershipLedger: validateOwnershipLedger(options.ownershipLedger),
    control,
  });
}

export async function runPublicSourceZipBoundaryVectors(options = {}) {
  assertProxyFreeAuthorityGraph(options, VECTOR_AUTHORITY_OPTIONS);
  const normalized = normalizeVectorOptions(options);
  const authority = await validatePublicSourceZipBoundaryVectorSet({
    testVectorSet: normalized.testVectorSet,
    expectedSha256: normalized.expectedSha256,
  });
  const executorRegistry = validateExecutorRegistry(
    buildEffectiveExecutorRegistry(normalized.control),
  );
  const parent = await validateTemporaryParent(normalized.temporaryParent);
  let root = null;
  let rootIdentity = null;
  const accounting = [];
  try {
    root = path.resolve(await mkdtemp(path.join(parent, "izv-")));
    const state = await requireRealDirectory(root);
    rootIdentity = state.identity;
    if (normalized.ownershipLedger) {
      await invokeOwnershipLedger(
        normalized.ownershipLedger,
        "recordDirectory",
        [
        root,
        "boundary-vector-root",
        ],
      );
    }
    const structuralFixture = planForFiles([
      { sourcePath: "a.txt", gitMode: "100644", payload: Buffer.from("alpha") },
      { sourcePath: "b.txt", gitMode: "100644", payload: Buffer.from("bravo") },
    ]);
    const executionState = { structuralFixture, reproducibility: null };
    for (const vector of BOUNDARY_VECTOR_DESCRIPTORS) {
      if (
        normalized.control?.disabledVectorId === vector.vectorId
        || normalized.control?.failVectorId === vector.vectorId
      ) failVector(vector.vectorId, "vector-implementation-disabled");
      try {
        const result = await executeVector(
          vector,
          root,
          executionState,
          executorRegistry,
          normalized.control,
        );
        if (
          result.operationCompleted !== true
          || result.assertionsCompleted !== true
          || result.vectorId !== vector.vectorId
          || result.executorId !== vector.vectorId
          || result.executionClass !== vector.executionClass
        ) failVector(vector.vectorId, "vector-accounting-invalid");
        accounting.push(result);
      } catch (error) {
        if (error instanceof PublicSourceZipBoundaryVectorError) throw error;
        failVector(vector.vectorId);
      }
    }
  } finally {
    if (root !== null && rootIdentity !== null) {
      await cleanupVectorRoot(root, rootIdentity);
      if (normalized.ownershipLedger) {
        await invokeOwnershipLedger(
          normalized.ownershipLedger,
          "recordRemoval",
          [
          root,
          "boundary-vector-root-cleanup",
          ],
        );
      }
    }
  }
  const vectorIds = new Set(accounting.map((entry) => entry.vectorId));
  const executorIds = new Set(accounting.map((entry) => entry.executorId));
  const resultIds = new Set(accounting.map((entry) => entry.internalResultId));
  const authenticFileIdentityVectors = accounting.filter(
    (entry) => entry.authenticity === "authentic-file-identity",
  ).length;
  const authenticMalformedZipVectors = accounting.filter(
    (entry) => entry.authenticity === "authentic-malformed-zip",
  ).length;
  const authenticReproducibilityVectors = accounting.filter(
    (entry) => entry.authenticity === "authentic-reproducibility",
  ).length;
  const expectedOutcomeEchoVectors = accounting.filter(
    (entry) => entry.authenticity === "expected-outcome-echo",
  ).length;
  const sourceSubstringOnlyVectors = accounting.filter(
    (entry) => entry.authenticity === "source-substring-only",
  ).length;
  if (
    accounting.length !== 119
    || vectorIds.size !== 119
    || executorIds.size !== 119
    || resultIds.size !== 119
    || BOUNDARY_VECTOR_EXECUTOR_IDS.some((vectorId) => (
      !vectorIds.has(vectorId)
      || !executorIds.has(vectorId)
      || !resultIds.has("completed-" + vectorId)
    ))
    || accounting.some((entry) => (
      entry.operationCompleted !== true
      || entry.assertionsCompleted !== true
    ))
    || authenticFileIdentityVectors !== 12
    || authenticMalformedZipVectors !== 18
    || authenticReproducibilityVectors !== 18
    || expectedOutcomeEchoVectors !== 0
    || sourceSubstringOnlyVectors !== 0
  ) failVector(null, "vector-accounting-invalid");
  if (normalized.control?.onAccounting) {
    const returned = normalized.control.onAccounting(Object.freeze([
      ...accounting,
    ]));
    assertProxyFreeAuthorityGraph(returned);
    if (returned !== undefined) failVector(null, "vector-accounting-invalid");
  }
  const result = {
    status: "ok",
    mode: "public-source-zip-boundary-vectors",
    vectorSetKind: VECTOR_SET_KIND,
    schemaVersion: 1,
    vectorSetId: VECTOR_SET_ID,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    testVectorSetSha256: authority.sha256,
    vectorCount: 119,
    passedCount: 119,
    failedCount: 0,
    boundaryVectorSetPassed: true,
  };
  if (Object.keys(result).some((key, index) => key !== BOUNDARY_RESULT_KEYS[index])) {
    failVector(null, "result-contract-invalid");
  }
  return validateBoundaryVectorResult(result, authority.sha256);
}

function parseOptions(argv) {
  if (
    argv.length !== 2
    || argv[0] !== "--test-vector-set"
    || argv[1].startsWith("--")
  ) failVector();
  return Object.freeze({ testVectorSet: path.resolve(argv[1]) });
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  if (import.meta.main === false) return false;
  const entry = process.argv[1];
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(entry));
  } catch {
    return false;
  }
}

async function main() {
  const result = await runPublicSourceZipBoundaryVectors(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceZipBoundaryVectorError
      ? error
      : new PublicSourceZipBoundaryVectorError();
    process.stderr.write(
      "ERROR BOUNDARY_VECTOR: " + safe.reason
      + (safe.vectorId ? " " + safe.vectorId : "")
      + "\n",
    );
    process.exitCode = 1;
  });
}
