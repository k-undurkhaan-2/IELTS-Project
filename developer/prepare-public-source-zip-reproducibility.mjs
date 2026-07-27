#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import {
  access,
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
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import {
  REPRODUCIBILITY_EVIDENCE_KIND,
  REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
  SCHEMA_VERSION,
  encodeCanonicalReproducibilityEvidence,
  encodeCanonicalSemanticReport,
  encodeCanonicalVerificationResult,
  parseCanonicalMatrixPolicy,
  readStableCanonicalDocument,
} from "./reproducibility-evidence-core.mjs";
import { verifyReproducibilityEvidence } from "./verify-reproducibility-evidence.mjs";
import {
  ADAPTER_MODE,
  ARCHIVE_ROOT,
  ARTIFACT_ROLE,
  AUTHORITATIVE_CORRESPONDING_SOURCE,
  CANONICAL_FAILURE_OUTPUT_NAMES,
  COMPLETION_MARKER,
  CRITICAL_TOOL_PATHS,
  CRITICAL_TOOL_SET_ID,
  CRITICAL_TOOL_SET_KIND,
  FORMAT_PROFILE,
  INPUT_SET_KIND,
  MEDIA_TYPE,
  SUCCESS_OUTPUT_NAMES,
  TOOL_ENTRY_KEYS,
  TOOL_SET_KEYS,
  WORKER_BUILTIN_IMPORTS,
  WORKER_CAPSULE_MODULE_KEYS,
  WORKER_MODULE_PATHS,
  PublicSourceZipReproducibilityError,
  assertProxyFreeAuthorityGraph,
  asZipReproducibilityError,
  canonicalPublicJsonBytes,
  deepFreezeZipReproducibility,
  encodeCanonicalCriticalToolSet,
  encodeCanonicalInputSet,
  failZipReproducibility,
  parseCanonicalPublicJsonBytes,
  selectPublicationMode,
  sha256Bytes,
  validateBoundaryVectorResult,
  validateCriticalToolSetDocument,
  validateInputSet,
  validateOutputEntrySet,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  BOUNDARY_VECTOR_DESCRIPTORS,
  buildFreshZipCandidate,
  createTrustedZipWorkerModuleCapsule,
  runPublicSourceZipBoundaryVectors,
  runSameHostZipCandidates,
  validatePublicSourceZipBoundaryVectorSet,
} from "./run-public-source-zip-boundary-vectors.mjs";

const COORDINATOR_TEST_HOOK = Symbol.for(
  "ieltmps.public-source-zip-reproducibility.test-hook",
);
const VECTOR_TEST_HOOK = Symbol.for(
  "ieltmps.public-source-zip-boundary-vectors.test-hook",
);
const COORDINATOR_AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([COORDINATOR_TEST_HOOK]),
  allowFunctions: true,
});
const CLEANUP_AUTHORITY_OPTIONS = Object.freeze({ allowMap: true });
const HOOK_AUTHORITY_OPTIONS = Object.freeze({ allowFunctions: true });
const ASYNC_RESULT_AUTHORITY_OPTIONS = Object.freeze({ allowPromise: true });
const SOURCE_MANIFEST_RELATIVE = "developer/public-source-manifest.json";
const VECTOR_SET_PATH = fileURLToPath(new URL(
  "./public-source-zip-boundary-vectors-v1.json",
  import.meta.url,
));
const OPTION_KEYS = Object.freeze([
  "repository",
  "sourceCommit",
  "manifest",
  "membershipReport",
  "runnerPolicy",
  "runtimeIdentity",
  "gitIdentity",
  "outputDirectory",
]);
const RUNTIME_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "runtimeProfileId",
  "implementation",
  "executableSha256",
  "executableByteLength",
  "nodeVersion",
  "v8Version",
  "modulesVersion",
  "distributionProfileId",
]);
const GIT_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "gitProfileId",
  "executableSha256",
  "executableByteLength",
  "reportedVersion",
  "objectFormat",
  "distributionProfileId",
]);
const PLATFORM_KEYS = Object.freeze([
  "probeKind",
  "schemaVersion",
  "matrixCellId",
  "operatingSystem",
  "operatingSystemBuild",
  "architecture",
  "filesystemProfile",
  "localeProfile",
  "timezoneProfile",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "pathPolicyCapabilities",
  "exclusiveCreateSupported",
  "hardLinkSupported",
  "atomicNoReplaceHardLinkSupported",
  "reliableLinkCountSupported",
  "stableFileIdentitySupported",
]);
const PATH_CAPABILITY_KEYS = Object.freeze([
  "portableRelativePathsSupported",
  "caseCollisionDetectionSupported",
  "unicodeNormalizationCollisionDetectionSupported",
  "symlinkParentRejectionSupported",
]);
const PUBLIC_RESULT_KEYS = Object.freeze([
  "status",
  "mode",
  "artifactRole",
  "formatProfile",
  "mediaType",
  "archiveRoot",
  "authoritativeCorrespondingSource",
  "sourceCommit",
  "toolingCommit",
  "membershipCount",
  "artifactSha256",
  "artifactByteLength",
  "entryPlanSha256",
  "semanticReportSha256",
  "evidenceSha256",
  "verificationResultSha256",
  "canonicalVerifierPassed",
  "sameProcessRepeatable",
  "sameHostRepeatable",
  "boundaryVectorSetPassed",
  "comparisonEligible",
  "semanticClaimsIndependentlyReplayed",
  "platformAttestationVerified",
  "evidenceSigningRequired",
  "projectPublicationAuthorized",
  "runResult",
  "failureClass",
  "failureCode",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const MAX_GIT_BUFFER = 256 * 1024 * 1024;
const MAX_DOCUMENT_BYTES = 1024 * 1024;
const WORKER_IMPORT_SET = new Set(WORKER_BUILTIN_IMPORTS);

export const PUBLICATION_RACE_CASES = Object.freeze([
  "final-directory-precreation",
  "fixed-file-precreation",
  "artifact-target-race",
  "supporting-document-target-race",
  "marker-precreation",
  "private-staging-replacement",
  "final-object-replacement",
  "parent-replacement",
  "reparse-insertion",
  "hard-link-count-anomaly",
  "entry-set-injection",
  "adoption-failure",
  "post-marker-substitution",
  "cleanup-identity-uncertainty",
  "PUB-M01",
  "PUB-M02",
  "PUB-M03",
  "PUB-M04",
  "PUB-M05",
  "PUB-M06",
  "PUB-M07",
  "PUB-M08",
  "PUB-M09",
  "PUB-M10",
]);

export const PUBLICATION_MARKER_CASES = Object.freeze([
  "PUB-M01",
  "PUB-M02",
  "PUB-M03",
  "PUB-M04",
  "PUB-M05",
  "PUB-M06",
  "PUB-M07",
  "PUB-M08",
  "PUB-M09",
  "PUB-M10",
]);

function fail(phase, reason) {
  throw new PublicSourceZipReproducibilityError(phase, reason);
}

function canonicalNativePath(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function pathsEqual(left, right) {
  return canonicalNativePath(left) === canonicalNativePath(right);
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(".." + path.sep)
    && !path.isAbsolute(relative);
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

function noFollowFlag() {
  return process.platform !== "win32"
    && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

async function pathState(targetPath) {
  try {
    return await lstat(targetPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function inspectRealDirectory(targetPath, phase, reason) {
  const resolved = path.resolve(targetPath);
  const state = await pathState(resolved);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isDirectory()
    || !pathsEqual(await realpath(resolved), resolved)
  ) fail(phase, reason);
  const identity = identityFromState(state);
  if (!identity.meaningful) fail(phase, reason);
  return Object.freeze({ path: resolved, identity });
}

function validateAbsoluteNormalizedPath(value, phase, reason) {
  if (
    typeof value !== "string"
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value
    || value.normalize("NFC") !== value
    || (process.platform === "win32" && (
      value.startsWith("\\\\")
      || value.startsWith("//")
      || value.startsWith("\\\\?\\")
      || value.startsWith("\\\\.\\")
    ))
  ) fail(phase, reason);
  return value;
}

async function stableRead(filePath, phase, reason, maximum = MAX_DOCUMENT_BYTES) {
  const target = validateAbsoluteNormalizedPath(filePath, phase, reason);
  const initial = await pathState(target);
  if (
    !initial
    || initial.isSymbolicLink()
    || !initial.isFile()
    || initial.nlink !== 1n
    || initial.size < 0n
    || initial.size > BigInt(maximum)
    || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
    || !pathsEqual(await realpath(target), target)
  ) fail(phase, reason);
  const identity = identityFromState(initial);
  if (!identity.meaningful) fail(phase, reason);
  let handle = null;
  try {
    handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = identityFromState(await handle.stat({ bigint: true }));
    if (!identitiesEqual(identity, before)) fail(phase, reason);
    const bytes = await handle.readFile();
    const after = identityFromState(await handle.stat({ bigint: true }));
    const final = identityFromState(await lstat(target, { bigint: true }));
    if (
      !identitiesEqual(identity, after)
      || !identitiesEqual(identity, final)
      || bytes.length !== Number(identity.size)
    ) fail(phase, reason);
    return Object.freeze({
      path: target,
      bytes,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      identity,
    });
  } finally {
    if (handle) await handle.close();
  }
}

function cleanupIdentityKey(identity) {
  return identity.device.toString(10) + ":" + identity.inode.toString(10);
}

function privateRelativePath(ledger, literalPath) {
  if (pathsEqual(literalPath, ledger.rootPath)) return ".";
  if (!isInside(ledger.rootPath, literalPath)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const relative = path.relative(ledger.rootPath, literalPath);
  if (
    !relative
    || path.isAbsolute(relative)
    || relative === ".."
    || relative.startsWith(".." + path.sep)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  return relative.split(path.sep).join("/");
}

function appendCleanupLedgerEvent(ledger, event) {
  ledger.events.push(Object.freeze({
    sequence: ledger.events.length + 1,
    ...event,
  }));
}

function createPrivateCleanupLedger(root, parent) {
  const ledger = {
    rootPath: root.path,
    rootParentPath: parent.path,
    rootParentIdentity: parent.identity,
    events: [],
    live: new Map(),
    nextCleanupOrder: 1,
    phaseTwoStarted: false,
    unlinkCount: 0,
    rmdirCount: 0,
  };
  const record = Object.freeze({
    literalPath: root.path,
    relativePath: ".",
    objectKind: "directory",
    expectedParent: parent.path,
    parentIdentity: parent.identity,
    objectIdentity: root.identity,
    reparse: false,
    linkCount: null,
    byteLength: null,
    sha256: null,
    creationPhase: "private-root",
    cleanupOrder: ledger.nextCleanupOrder++,
  });
  ledger.live.set(root.path, record);
  appendCleanupLedgerEvent(ledger, { event: "create", record });
  return ledger;
}

async function snapshotOwnedFile(filePath, phase, reason) {
  const state = await pathState(filePath);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink < 1n
    || state.size < 0n
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
    || !pathsEqual(await realpath(filePath), filePath)
  ) fail(phase, reason);
  const identity = identityFromState(state);
  if (!identity.meaningful) fail(phase, reason);
  let handle = null;
  try {
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = identityFromState(await handle.stat({ bigint: true }));
    const bytes = await handle.readFile();
    const after = identityFromState(await handle.stat({ bigint: true }));
    const final = identityFromState(await lstat(filePath, { bigint: true }));
    if (
      !identitiesEqual(identity, before)
      || !identitiesEqual(identity, after)
      || !identitiesEqual(identity, final)
      || bytes.length !== Number(identity.size)
    ) fail(phase, reason);
    return Object.freeze({
      identity,
      byteLength: bytes.length,
      sha256: sha256Bytes(bytes),
    });
  } finally {
    if (handle) await handle.close();
  }
}

async function recordOwnedDirectory(
  ledger,
  directoryPath,
  creationPhase,
) {
  const literalPath = path.resolve(directoryPath);
  if (ledger.live.has(literalPath)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const parentPath = path.dirname(literalPath);
  const parentRecord = ledger.live.get(parentPath);
  if (!parentRecord || parentRecord.objectKind !== "directory") {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const directory = await inspectRealDirectory(
    literalPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  const parent = await inspectRealDirectory(
    parentPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  if (!sameObject(parent.identity, parentRecord.objectIdentity)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const record = Object.freeze({
    literalPath,
    relativePath: privateRelativePath(ledger, literalPath),
    objectKind: "directory",
    expectedParent: parentPath,
    parentIdentity: parent.identity,
    objectIdentity: directory.identity,
    reparse: false,
    linkCount: null,
    byteLength: null,
    sha256: null,
    creationPhase,
    cleanupOrder: ledger.nextCleanupOrder++,
  });
  ledger.live.set(literalPath, record);
  appendCleanupLedgerEvent(ledger, { event: "create", record });
  return record;
}

async function recordOwnedFile(
  ledger,
  filePath,
  creationPhase,
  expected = null,
) {
  const literalPath = path.resolve(filePath);
  if (ledger.live.has(literalPath)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const parentPath = path.dirname(literalPath);
  const parentRecord = ledger.live.get(parentPath);
  if (!parentRecord || parentRecord.objectKind !== "directory") {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const parent = await inspectRealDirectory(
    parentPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  if (!sameObject(parent.identity, parentRecord.objectIdentity)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const snapshot = await snapshotOwnedFile(
    literalPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  if (
    expected
    && (
      (expected.byteLength !== undefined
        && snapshot.byteLength !== expected.byteLength)
      || (expected.sha256 !== undefined && snapshot.sha256 !== expected.sha256)
    )
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const record = Object.freeze({
    literalPath,
    relativePath: privateRelativePath(ledger, literalPath),
    objectKind: "file",
    expectedParent: parentPath,
    parentIdentity: parent.identity,
    objectIdentity: snapshot.identity,
    reparse: false,
    linkCount: snapshot.identity.links,
    byteLength: snapshot.byteLength,
    sha256: snapshot.sha256,
    creationPhase,
    cleanupOrder: ledger.nextCleanupOrder++,
  });
  ledger.live.set(literalPath, record);
  appendCleanupLedgerEvent(ledger, { event: "create", record });
  return record;
}

async function rebindOwnedFile(
  ledger,
  filePath,
  expectedLinkCount,
  creationPhase,
) {
  const literalPath = path.resolve(filePath);
  const prior = ledger.live.get(literalPath);
  if (!prior || prior.objectKind !== "file") {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const snapshot = await snapshotOwnedFile(
    literalPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  if (
    !sameObject(snapshot.identity, prior.objectIdentity)
    || snapshot.byteLength !== prior.byteLength
    || snapshot.sha256 !== prior.sha256
    || snapshot.identity.links !== expectedLinkCount
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const record = Object.freeze({
    ...prior,
    objectIdentity: snapshot.identity,
    linkCount: snapshot.identity.links,
    creationPhase,
  });
  ledger.live.set(literalPath, record);
  appendCleanupLedgerEvent(ledger, { event: "rebind", record });
  return record;
}

function recordOwnedRemoval(ledger, literalPath, phase) {
  const record = ledger.live.get(literalPath);
  if (!record) fail("CLEANUP", "cleanup-identity-uncertain");
  ledger.live.delete(literalPath);
  appendCleanupLedgerEvent(ledger, {
    event: "remove",
    literalPath,
    relativePath: record.relativePath,
    objectKind: record.objectKind,
    creationPhase: phase,
    cleanupOrder: record.cleanupOrder,
  });
}

async function observedPrivateSet(ledger) {
  const observed = new Set([ledger.rootPath]);
  const pending = [ledger.rootPath];
  while (pending.length > 0) {
    const directoryPath = pending.shift();
    const state = await pathState(directoryPath);
    if (!state || state.isSymbolicLink() || !state.isDirectory()) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    const names = (await readdir(directoryPath)).sort();
    for (const name of names) {
      const childPath = path.join(directoryPath, name);
      const childState = await pathState(childPath);
      if (!childState) fail("CLEANUP", "cleanup-identity-uncertain");
      observed.add(childPath);
      if (childState.isDirectory() && !childState.isSymbolicLink()) {
        pending.push(childPath);
      }
    }
  }
  return observed;
}

async function validateCleanupRecord(record, expectedLinks = null) {
  const parent = await pathState(record.expectedParent);
  if (
    !parent
    || parent.isSymbolicLink()
    || !parent.isDirectory()
    || !sameObject(identityFromState(parent), record.parentIdentity)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const state = await pathState(record.literalPath);
  if (!state || state.isSymbolicLink()) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const identity = identityFromState(state);
  if (
    !sameObject(identity, record.objectIdentity)
    || state.mode !== record.objectIdentity.mode
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  if (record.objectKind === "directory") {
    if (!state.isDirectory()) fail("CLEANUP", "cleanup-identity-uncertain");
    return;
  }
  if (
    !state.isFile()
    || state.size !== BigInt(record.byteLength)
    || state.nlink !== (expectedLinks ?? record.linkCount)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const snapshot = await snapshotOwnedFile(
    record.literalPath,
    "CLEANUP",
    "cleanup-identity-uncertain",
  );
  if (
    !sameObject(snapshot.identity, record.objectIdentity)
    || snapshot.byteLength !== record.byteLength
    || snapshot.sha256 !== record.sha256
    || snapshot.identity.links !== (expectedLinks ?? record.linkCount)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
}

async function freezePrivateCleanupPlan(ledger) {
  assertProxyFreeAuthorityGraph(ledger, CLEANUP_AUTHORITY_OPTIONS);
  const rootRecord = ledger.live.get(ledger.rootPath);
  if (!rootRecord || rootRecord.objectKind !== "directory") {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const rootParent = await pathState(ledger.rootParentPath);
  if (
    !rootParent
    || rootParent.isSymbolicLink()
    || !rootParent.isDirectory()
    || !sameObject(identityFromState(rootParent), ledger.rootParentIdentity)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const observed = await observedPrivateSet(ledger);
  const expected = new Set(ledger.live.keys());
  if (
    observed.size !== expected.size
    || [...observed].some((entry) => !expected.has(entry))
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  for (const record of ledger.live.values()) {
    await validateCleanupRecord(record);
  }
  const fileRecords = [...ledger.live.values()]
    .filter((record) => record.objectKind === "file")
    .sort((left, right) => right.cleanupOrder - left.cleanupOrder);
  const removedLinks = new Map();
  const fileActions = fileRecords.map((record) => {
    const key = cleanupIdentityKey(record.objectIdentity);
    const prior = removedLinks.get(key) ?? 0n;
    const expectedLinks = record.linkCount - prior;
    if (expectedLinks < 1n) fail("CLEANUP", "cleanup-identity-uncertain");
    removedLinks.set(key, prior + 1n);
    return Object.freeze({
      kind: "unlink",
      record,
      expectedLinks,
    });
  });
  const directoryActions = [...ledger.live.values()]
    .filter((record) => record.objectKind === "directory")
    .sort((left, right) => {
      const leftDepth = left.relativePath === "."
        ? 0
        : left.relativePath.split("/").length;
      const rightDepth = right.relativePath === "."
        ? 0
        : right.relativePath.split("/").length;
      return rightDepth - leftDepth || right.cleanupOrder - left.cleanupOrder;
    })
    .map((record) => Object.freeze({ kind: "rmdir", record }));
  return Object.freeze([...fileActions, ...directoryActions]);
}

async function invokeCleanupCheckpoint(testHook, checkpoint, action = null) {
  assertProxyFreeAuthorityGraph(testHook, HOOK_AUTHORITY_OPTIONS);
  assertProxyFreeAuthorityGraph(action);
  if (!testHook?.publicationCheckpoint) return;
  const pending = testHook.publicationCheckpoint(Object.freeze({
    checkpoint,
    actionKind: action?.kind ?? null,
    literalPath: action?.record.literalPath ?? null,
    relativePath: action?.record.relativePath ?? null,
  }));
  assertProxyFreeAuthorityGraph(pending, ASYNC_RESULT_AUTHORITY_OPTIONS);
  const returned = await pending;
  assertProxyFreeAuthorityGraph(returned);
  if (returned !== undefined) fail("CLI", "test-hook-return-value");
}

async function cleanupPrivateRoot(root, testHook = null) {
  assertProxyFreeAuthorityGraph(root, CLEANUP_AUTHORITY_OPTIONS);
  assertProxyFreeAuthorityGraph(testHook, HOOK_AUTHORITY_OPTIONS);
  if (!root) return Object.freeze({ unlinkCount: 0, rmdirCount: 0 });
  const ledger = root.ledger;
  if (!ledger || ledger.rootPath !== root.path) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (!(await pathState(root.path))) {
    if (ledger.live.size === 0) {
      return Object.freeze({
        unlinkCount: ledger.unlinkCount,
        rmdirCount: ledger.rmdirCount,
      });
    }
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  try {
    const plan = await freezePrivateCleanupPlan(ledger);
    await invokeCleanupCheckpoint(testHook, "after-private-cleanup-phase-one");
    const revalidated = await freezePrivateCleanupPlan(ledger);
    if (
      revalidated.length !== plan.length
      || revalidated.some((action, index) => (
        action.kind !== plan[index].kind
        || action.record.literalPath !== plan[index].record.literalPath
        || action.expectedLinks !== plan[index].expectedLinks
      ))
    ) fail("CLEANUP", "cleanup-identity-uncertain");
    ledger.phaseTwoStarted = true;
    appendCleanupLedgerEvent(ledger, {
      event: "phase-two-start",
      actionCount: plan.length,
    });
    for (const action of plan) {
      await invokeCleanupCheckpoint(
        testHook,
        "before-private-cleanup-action",
        action,
      );
      if (action.kind === "unlink") {
        await validateCleanupRecord(action.record, action.expectedLinks);
        await unlink(action.record.literalPath);
        ledger.unlinkCount += 1;
      } else {
        await validateCleanupRecord(action.record);
        if ((await readdir(action.record.literalPath)).length !== 0) {
          fail("CLEANUP", "cleanup-identity-uncertain");
        }
        await rmdir(action.record.literalPath);
        ledger.rmdirCount += 1;
      }
      if (await pathState(action.record.literalPath)) {
        fail("CLEANUP", "cleanup-incomplete");
      }
      recordOwnedRemoval(ledger, action.record.literalPath, "phase-two");
      await invokeCleanupCheckpoint(
        testHook,
        "after-private-cleanup-action",
        action,
      );
    }
    if (await pathState(root.path)) fail("CLEANUP", "cleanup-incomplete");
    return Object.freeze({
      unlinkCount: ledger.unlinkCount,
      rmdirCount: ledger.rmdirCount,
    });
  } catch (error) {
    const safe = asZipReproducibilityError(
      error,
      "CLEANUP",
      "cleanup-identity-uncertain",
    );
    Object.defineProperties(safe, {
      cleanupUnlinkCount: { value: ledger.unlinkCount, enumerable: false },
      cleanupRmdirCount: { value: ledger.rmdirCount, enumerable: false },
    });
    throw safe;
  }
}

function privateOwnershipAdapter(root) {
  assertProxyFreeAuthorityGraph(root, CLEANUP_AUTHORITY_OPTIONS);
  const { ledger } = root;
  return Object.freeze({
    async recordDirectory(directoryPath, phase = "intermediate-directory") {
      return recordOwnedDirectory(ledger, directoryPath, phase);
    },
    async recordFile(filePath, expected = null, phase = "intermediate-file") {
      return recordOwnedFile(ledger, filePath, phase, expected);
    },
    async rebindFile(filePath, expectedLinks, phase = "link-transition") {
      return rebindOwnedFile(ledger, filePath, expectedLinks, phase);
    },
    async recordRemoval(filePath, phase = "intermediate-removal") {
      if (await pathState(filePath)) {
        fail("CLEANUP", "cleanup-identity-uncertain");
      }
      recordOwnedRemoval(ledger, path.resolve(filePath), phase);
    },
  });
}

function exactKeys(value, keys) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && Object.keys(value).every((key, index) => key === keys[index]);
}

function normalizeOptions(options) {
  assertProxyFreeAuthorityGraph(options, COORDINATOR_AUTHORITY_OPTIONS);
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    fail("CLI", "api-options-invalid");
  }
  const keys = Object.keys(options);
  const symbols = Object.getOwnPropertySymbols(options);
  if (
    keys.length !== OPTION_KEYS.length
    || keys.some((key, index) => key !== OPTION_KEYS[index])
    || symbols.some((symbol) => symbol !== COORDINATOR_TEST_HOOK)
  ) fail("CLI", "api-options-invalid");
  for (const key of OPTION_KEYS) {
    if (!Object.hasOwn(options, key) || typeof options[key] !== "string") {
      fail("CLI", "api-options-invalid");
    }
  }
  if (!GIT_OBJECT_PATTERN.test(options.sourceCommit)) {
    fail("CLI", "source-commit-invalid");
  }
  for (const key of OPTION_KEYS.filter((entry) => entry !== "sourceCommit")) {
    validateAbsoluteNormalizedPath(options[key], "CLI", "api-path-invalid");
  }
  const testHook = options[COORDINATOR_TEST_HOOK] ?? null;
  if (
    testHook !== null
    && (
      !testHook
      || typeof testHook !== "object"
      || Array.isArray(testHook)
      || Object.keys(testHook).some((key) => ![
        "failCheckpoint",
        "boundaryFailVectorId",
        "publicationCheckpoint",
        "workerProtocolControl",
      ].includes(key))
      || (
        testHook.failCheckpoint !== undefined
        && typeof testHook.failCheckpoint !== "string"
      )
      || (
        testHook.boundaryFailVectorId !== undefined
        && typeof testHook.boundaryFailVectorId !== "string"
      )
      || (
        testHook.publicationCheckpoint !== undefined
        && typeof testHook.publicationCheckpoint !== "function"
      )
    )
  ) fail("CLI", "test-hook-invalid");
  return Object.freeze({
    ...Object.fromEntries(OPTION_KEYS.map((key) => [key, options[key]])),
    testHook,
  });
}

function sanitizedGitEnvironment(gitDirectory = null) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_") && key.toUpperCase() !== "PATH") {
      environment[key] = value;
    }
  }
  environment.PATH = gitDirectory ?? process.env.PATH;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LANG = "C";
  environment.LC_ALL = "C";
  return environment;
}

function runGit(git, repository, args, phase, reason, input = undefined) {
  const result = spawnSync(
    git.path,
    ["--no-replace-objects", "-C", repository, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(git.directory),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) fail(phase, reason);
  return result.stdout;
}

async function resolveGitExecutable() {
  let candidates = [];
  if (process.platform === "win32") {
    const result = spawnSync("where.exe", ["git"], {
      encoding: "utf8",
      env: sanitizedGitEnvironment(process.env.PATH),
      shell: false,
      windowsHide: true,
    });
    if (!result.error && result.status === 0) {
      candidates = result.stdout.split(/\r?\n/u).filter(Boolean);
    }
  } else {
    for (const directory of (process.env.PATH ?? "").split(path.delimiter)) {
      if (directory) candidates.push(path.join(directory, "git"));
    }
  }
  let executable = null;
  let file = null;
  for (const candidate of candidates) {
    try {
      const resolved = path.resolve(candidate);
      await access(resolved, FS_CONSTANTS.X_OK);
      const state = await lstat(resolved, { bigint: true });
      if (state.isFile() && !state.isSymbolicLink()) {
        const stable = await stableRead(
          resolved,
          "GIT_IDENTITY",
          "git-executable-identity",
          256 * 1024 * 1024,
        );
        executable = resolved;
        file = stable;
        break;
      }
    } catch { /* try next candidate */ }
  }
  if (!executable || !file) fail("GIT_IDENTITY", "git-executable-unavailable");
  const version = spawnSync(executable, ["--version"], {
    encoding: "utf8",
    env: sanitizedGitEnvironment(path.dirname(executable)),
    shell: false,
    windowsHide: true,
  });
  if (version.error || version.status !== 0) {
    fail("GIT_IDENTITY", "git-version-unavailable");
  }
  return Object.freeze({
    path: executable,
    directory: path.dirname(executable),
    sha256: file.sha256,
    byteLength: file.byteLength,
    reportedVersion: version.stdout.trim(),
  });
}

async function validateRepository(repository, sourceCommit, toolingCommit, git) {
  await inspectRealDirectory(repository, "SOURCE_BINDING", "repository-invalid");
  const root = runGit(
    git,
    repository,
    ["rev-parse", "--show-toplevel"],
    "SOURCE_BINDING",
    "repository-root",
  ).toString("utf8").trim();
  if (!pathsEqual(root, repository)) fail("SOURCE_BINDING", "repository-root");
  const format = runGit(
    git,
    repository,
    ["rev-parse", "--show-object-format"],
    "SOURCE_BINDING",
    "object-format",
  ).toString("ascii").trim();
  if (format !== "sha1") fail("SOURCE_BINDING", "object-format");
  const replacements = runGit(
    git,
    repository,
    ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    "SOURCE_BINDING",
    "replacement-object-ref",
  ).toString("utf8").trim();
  if (replacements) fail("SOURCE_BINDING", "replacement-object-ref");
  for (const commit of [sourceCommit, toolingCommit]) {
    if (!GIT_OBJECT_PATTERN.test(commit)) fail("SOURCE_BINDING", "commit-id");
    const type = runGit(
      git,
      repository,
      ["cat-file", "-t", commit],
      "SOURCE_BINDING",
      "commit-object",
    ).toString("ascii").trim();
    if (type !== "commit") fail("SOURCE_BINDING", "commit-object");
  }
  const head = runGit(
    git,
    repository,
    ["rev-parse", "HEAD"],
    "TOOL_SET",
    "tooling-head",
  ).toString("ascii").trim();
  const status = runGit(
    git,
    repository,
    ["status", "--porcelain=v2", "--untracked-files=all"],
    "TOOL_SET",
    "dirty-tooling-worktree",
  );
  if (head !== toolingCommit || status.length !== 0) {
    fail("TOOL_SET", "dirty-tooling-worktree");
  }
}

function parseSingleTreeEntry(bytes, expectedPath) {
  if (bytes.length === 0 || bytes.at(-1) !== 0) return null;
  const records = bytes.subarray(0, -1).toString("utf8").split("\0");
  if (records.length !== 1) return null;
  const tab = records[0].indexOf("\t");
  if (tab < 0 || records[0].slice(tab + 1) !== expectedPath) return null;
  const parts = records[0].slice(0, tab).split(" ");
  if (parts.length !== 3 || parts[1] !== "blob") return null;
  return Object.freeze({ mode: parts[0], objectId: parts[2] });
}

function validateStaticImports(relativePath, bytes) {
  const source = bytes.toString("utf8");
  if (/\bimport\s*\(/gu.test(source)) {
    fail("TOOL_SET", "dynamic-production-import");
  }
  const expressions = [
    /\bfrom\s*["']([^"']+)["']/gu,
    /(?:^|\n)\s*import\s*["']([^"']+)["']/gu,
  ];
  for (const expression of expressions) {
    for (const match of source.matchAll(expression)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) {
        if (!WORKER_IMPORT_SET.has(specifier)) {
          fail("TOOL_SET", "production-builtin-outside-allowlist");
        }
        continue;
      }
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
        fail("TOOL_SET", "production-import-outside-tool-set");
      }
      const resolved = path.posix.normalize(path.posix.join(
        path.posix.dirname(relativePath),
        specifier,
      ));
      if (!CRITICAL_TOOL_PATHS.includes(resolved)) {
        fail("TOOL_SET", "production-import-outside-tool-set");
      }
    }
  }
}

const LOADED_MODULE_PATHS = Object.freeze(new Map([
  [CRITICAL_TOOL_PATHS[0], fileURLToPath(new URL("./verify-public-source-membership.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[1], fileURLToPath(new URL("./prepare-public-source-tree.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[2], fileURLToPath(new URL("./public-source-zip-core.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[3], fileURLToPath(new URL("./prepare-public-source-zip.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[4], fileURLToPath(new URL("./verify-public-source-zip.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[5], fileURLToPath(new URL("./reproducibility-evidence-core.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[6], fileURLToPath(new URL("./verify-reproducibility-evidence.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[7], fileURLToPath(new URL("./public-source-zip-reproducibility-core.mjs", import.meta.url))],
  [CRITICAL_TOOL_PATHS[8], fileURLToPath(import.meta.url)],
  [CRITICAL_TOOL_PATHS[9], fileURLToPath(new URL("./run-public-source-zip-boundary-vectors.mjs", import.meta.url))],
]));

async function validateCriticalTools(repository, toolingCommit, git) {
  const entries = [];
  const criticalFiles = [];
  const workerModules = [];
  for (let index = 0; index < CRITICAL_TOOL_PATHS.length; index += 1) {
    const relativePath = CRITICAL_TOOL_PATHS[index];
    const tree = parseSingleTreeEntry(runGit(
      git,
      repository,
      ["ls-tree", "-z", "--full-tree", toolingCommit, "--", relativePath],
      "TOOL_SET",
      "critical-tool-commit-entry",
    ), relativePath);
    if (
      !tree
      || !["100644", "100755"].includes(tree.mode)
      || !GIT_OBJECT_PATTERN.test(tree.objectId)
    ) fail("TOOL_SET", "critical-tool-commit-entry");
    const committed = runGit(
      git,
      repository,
      ["cat-file", "blob", tree.objectId],
      "TOOL_SET",
      "critical-tool-blob",
    );
    const loadedPath = path.resolve(LOADED_MODULE_PATHS.get(relativePath));
    const loaded = await stableRead(
      loadedPath,
      "TOOL_SET",
      "critical-tool-loaded-bytes",
      16 * 1024 * 1024,
    );
    if (
      loaded.byteLength !== committed.length
      || !loaded.bytes.equals(committed)
      || loaded.sha256 !== sha256Bytes(committed)
    ) fail("TOOL_SET", "critical-tool-loaded-bytes");
    validateStaticImports(relativePath, committed);
    const entry = {
      path: relativePath,
      gitMode: tree.mode,
      gitBlobObjectId: tree.objectId,
      declaredByteSize: committed.length,
      sha256: loaded.sha256,
    };
    if (!exactKeys(entry, TOOL_ENTRY_KEYS)) fail("TOOL_SET", "tool-entry-shape");
    entries.push(Object.freeze(entry));
    const workerLoaded = WORKER_MODULE_PATHS.includes(relativePath)
      ? loaded.sha256
      : null;
    criticalFiles.push(Object.freeze({
      path: relativePath,
      toolingCommit,
      gitMode: tree.mode,
      gitBlobObjectId: tree.objectId,
      byteLength: committed.length,
      sha256: loaded.sha256,
      parentLoadedSha256: loaded.sha256,
      workerLoadedSha256: workerLoaded,
    }));
    if (workerLoaded !== null) {
      workerModules.push(Object.freeze({
        relativePath,
        byteLength: committed.length,
        sha256: loaded.sha256,
        sourceBase64: committed.toString("base64"),
      }));
    }
  }
  const value = {
    documentKind: CRITICAL_TOOL_SET_KIND,
    schemaVersion: 1,
    toolSetId: CRITICAL_TOOL_SET_ID,
    toolingCommit,
    entries,
  };
  if (!exactKeys(value, TOOL_SET_KEYS)) fail("TOOL_SET", "tool-set-shape");
  validateCriticalToolSetDocument(value);
  const bytes = encodeCanonicalCriticalToolSet(value);
  return Object.freeze({
    value: deepFreezeZipReproducibility(value),
    bytes,
    sha256: sha256Bytes(bytes),
    criticalFiles: Object.freeze(criticalFiles),
    workerModules: Object.freeze(workerModules),
  });
}

function selectPolicyCell(policy, runtimeSha256, gitSha256) {
  if (
    policy.artifactRole !== ARTIFACT_ROLE
    || policy.formatProfile !== FORMAT_PROFILE
  ) fail("POLICY_BINDING", "artifact-profile-mismatch");
  const cells = [...policy.requiredCells, ...policy.optionalCells].filter(
    (entry) => (
      entry.runtimeIdentitySha256 === runtimeSha256
      && entry.gitIdentitySha256 === gitSha256
    ),
  );
  if (cells.length !== 1) fail("POLICY_BINDING", "matrix-cell-ambiguous");
  return cells[0];
}

async function loadCanonicalPublicDocument(filePath, phase, kind) {
  const input = await stableRead(filePath, phase, kind, MAX_DOCUMENT_BYTES);
  let value;
  try {
    value = parseCanonicalPublicJsonBytes(input.bytes, phase);
  } catch {
    fail(phase, kind + "-invalid");
  }
  return Object.freeze({ ...input, value });
}

async function validateRuntimeIdentity(document) {
  assertProxyFreeAuthorityGraph(document, { allowBuffer: true });
  if (!exactKeys(document.value, RUNTIME_KEYS)) {
    fail("RUNTIME_IDENTITY", "runtime-identity-shape");
  }
  const value = document.value;
  const executable = await stableRead(
    path.resolve(process.execPath),
    "RUNTIME_IDENTITY",
    "runtime-executable-identity",
    256 * 1024 * 1024,
  );
  if (
    value.documentKind !== "ieltmps-node-runtime-identity"
    || value.schemaVersion !== 1
    || value.implementation !== "node"
    || value.executableSha256 !== executable.sha256
    || value.executableByteLength !== executable.byteLength
    || value.nodeVersion !== process.versions.node
    || value.v8Version !== process.versions.v8
    || value.modulesVersion !== process.versions.modules
    || typeof value.runtimeProfileId !== "string"
    || typeof value.distributionProfileId !== "string"
  ) fail("RUNTIME_IDENTITY", "runtime-profile-mismatch");
  return true;
}

function validateGitIdentity(document, git) {
  assertProxyFreeAuthorityGraph(document, { allowBuffer: true });
  assertProxyFreeAuthorityGraph(git, { allowBuffer: true });
  if (!exactKeys(document.value, GIT_KEYS)) {
    fail("GIT_IDENTITY", "git-identity-shape");
  }
  const value = document.value;
  if (
    value.documentKind !== "ieltmps-git-runtime-identity"
    || value.schemaVersion !== 1
    || value.executableSha256 !== git.sha256
    || value.executableByteLength !== git.byteLength
    || value.reportedVersion !== git.reportedVersion
    || value.objectFormat !== "sha1"
    || typeof value.gitProfileId !== "string"
    || typeof value.distributionProfileId !== "string"
  ) fail("GIT_IDENTITY", "git-identity-mismatch");
  return true;
}

function canonicalOperatingSystem() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  fail("PLATFORM_PROBE", "unsupported-operating-system");
}

function canonicalArchitecture() {
  if (process.arch === "x64") return "x64";
  if (process.arch === "arm64") return "arm64";
  fail("PLATFORM_PROBE", "unsupported-architecture");
}

async function measureHostCapabilities(privateRoot) {
  const directory = await createPrivateDirectory(
    privateRoot,
    "capability-probe",
  );
  const original = path.join(directory.path, "original");
  const linked = path.join(directory.path, "linked");
  await writeFile(original, Buffer.from("capability\n", "ascii"), {
    flag: "wx",
    mode: 0o600,
  });
  await recordOwnedFile(
    privateRoot.ledger,
    original,
    "capability-probe-original",
    {
      byteLength: Buffer.byteLength("capability\n", "ascii"),
      sha256: sha256Bytes(Buffer.from("capability\n", "ascii")),
    },
  );
  let hardLinkSupported = false;
  await link(original, linked);
  await recordOwnedFile(
    privateRoot.ledger,
    linked,
    "capability-probe-link",
    {
      byteLength: Buffer.byteLength("capability\n", "ascii"),
      sha256: sha256Bytes(Buffer.from("capability\n", "ascii")),
    },
  );
  await rebindOwnedFile(
    privateRoot.ledger,
    original,
    2n,
    "capability-probe-link-transition",
  );
  const left = await lstat(original, { bigint: true });
  const right = await lstat(linked, { bigint: true });
  hardLinkSupported = left.nlink === 2n
    && right.nlink === 2n
    && left.dev === right.dev
    && left.ino === right.ino;
  if (!hardLinkSupported) fail("PLATFORM_PROBE", "unsupported-host-capability");
  return Object.freeze({
    exclusiveCreateSupported: true,
    hardLinkSupported,
    atomicNoReplaceHardLinkSupported: true,
    reliableLinkCountSupported: true,
    stableFileIdentitySupported: true,
  });
}

function buildPlatformProbe(cell, runtimeSha256, gitSha256, measured) {
  if (
    cell.operatingSystem !== canonicalOperatingSystem()
    || cell.architecture !== canonicalArchitecture()
  ) fail("PLATFORM_PROBE", "platform-cell-mismatch");
  const pathPolicyCapabilities = {
    portableRelativePathsSupported: true,
    caseCollisionDetectionSupported: true,
    unicodeNormalizationCollisionDetectionSupported: true,
    symlinkParentRejectionSupported: true,
  };
  if (!exactKeys(pathPolicyCapabilities, PATH_CAPABILITY_KEYS)) {
    fail("PLATFORM_PROBE", "platform-probe-shape");
  }
  const value = {
    probeKind: "ieltmps-platform-probe",
    schemaVersion: 1,
    matrixCellId: cell.matrixCellId,
    operatingSystem: cell.operatingSystem,
    operatingSystemBuild: cell.operatingSystemBuild,
    architecture: cell.architecture,
    filesystemProfile: cell.filesystemProfile,
    localeProfile: cell.localeProfile,
    timezoneProfile: cell.timezoneProfile,
    runtimeIdentitySha256: runtimeSha256,
    gitIdentitySha256: gitSha256,
    pathPolicyCapabilities,
    exclusiveCreateSupported: measured.exclusiveCreateSupported,
    hardLinkSupported: measured.hardLinkSupported,
    atomicNoReplaceHardLinkSupported:
      measured.atomicNoReplaceHardLinkSupported,
    reliableLinkCountSupported: measured.reliableLinkCountSupported,
    stableFileIdentitySupported: measured.stableFileIdentitySupported,
  };
  if (!exactKeys(value, PLATFORM_KEYS)) {
    fail("PLATFORM_PROBE", "platform-probe-shape");
  }
  const bytes = canonicalPublicJsonBytes(value, "PLATFORM_PROBE");
  return Object.freeze({
    value: deepFreezeZipReproducibility(value),
    bytes,
    sha256: sha256Bytes(bytes),
  });
}

async function loadPolicy(filePath) {
  let input;
  let value;
  try {
    input = await readStableCanonicalDocument(
      filePath,
      "POLICY_SCHEMA",
      "runner-policy",
    );
    value = parseCanonicalMatrixPolicy(input.bytes);
    assertProxyFreeAuthorityGraph(value);
  } catch {
    fail("POLICY_BINDING", "runner-policy-invalid");
  }
  return Object.freeze({ ...input, value });
}

async function validateSourceAuthority(options, policy, git) {
  if (
    policy.sourceCommit !== options.sourceCommit
    || policy.manifestSha256 === undefined
  ) fail("POLICY_BINDING", "source-policy-mismatch");
  const manifest = await stableRead(
    options.manifest,
    "SOURCE_BINDING",
    "manifest-invalid",
    MAX_DOCUMENT_BYTES,
  );
  const suppliedReport = await stableRead(
    options.membershipReport,
    "SOURCE_BINDING",
    "membership-report-invalid",
    64 * 1024 * 1024,
  );
  let membership;
  try {
    membership = await loadValidatedPublicSourceMembership({
      repo: options.repository,
      commit: options.sourceCommit,
    });
  } catch {
    fail("SOURCE_BINDING", "b1-membership-invalid");
  }
  const manifestMember = membership.members.find(
    (entry) => entry.path === SOURCE_MANIFEST_RELATIVE,
  );
  if (
    !manifestMember
    || !Buffer.isBuffer(manifestMember.blobBytes)
    || !manifest.bytes.equals(manifestMember.blobBytes)
    || manifest.sha256 !== membership.manifestSha256
    || manifest.sha256 !== policy.manifestSha256
    || !suppliedReport.bytes.equals(membership.reportBytes)
  ) fail("SOURCE_BINDING", "source-document-mismatch");
  return Object.freeze({
    manifest,
    suppliedReport,
    membership,
    membershipReportSha256: suppliedReport.sha256,
  });
}

async function validateOutputTarget(outputDirectory, repository) {
  validateAbsoluteNormalizedPath(
    outputDirectory,
    "OUTPUT_PUBLICATION",
    "output-directory-invalid",
  );
  if (
    pathsEqual(outputDirectory, repository)
    || isInside(repository, outputDirectory)
  ) fail("OUTPUT_PUBLICATION", "output-containment");
  const parent = await inspectRealDirectory(
    path.dirname(outputDirectory),
    "OUTPUT_PUBLICATION",
    "output-parent-invalid",
  );
  if (await pathState(outputDirectory)) {
    fail("OUTPUT_PUBLICATION", "output-directory-exists");
  }
  return Object.freeze({
    path: outputDirectory,
    parent,
    basename: path.basename(outputDirectory),
  });
}

async function createPrivateRoot(target) {
  const rootPath = path.resolve(await mkdtemp(path.join(
    target.parent.path,
    ".izrp-",
  )));
  const root = await inspectRealDirectory(
    rootPath,
    "OUTPUT_PUBLICATION",
    "private-root-invalid",
  );
  const parent = await inspectRealDirectory(
    target.parent.path,
    "OUTPUT_PUBLICATION",
    "output-parent-invalid",
  );
  if (!sameObject(parent.identity, target.parent.identity)) {
    fail("OUTPUT_PUBLICATION", "output-parent-identity");
  }
  const ledger = createPrivateCleanupLedger(root, parent);
  return Object.freeze({ ...root, ledger });
}

async function createPrivateDirectory(parent, basename) {
  if (
    typeof basename !== "string"
    || !/^[a-z0-9][a-z0-9-]*$/u.test(basename)
  ) fail("OUTPUT_PUBLICATION", "private-directory-name");
  const directoryPath = path.join(parent.path, basename);
  await mkdir(directoryPath, { recursive: false, mode: 0o700 });
  const directory = await inspectRealDirectory(
    directoryPath,
    "OUTPUT_PUBLICATION",
    "private-directory-invalid",
  );
  if (!sameObject(
    identityFromState(await lstat(parent.path, { bigint: true })),
    parent.identity,
  )) fail("OUTPUT_PUBLICATION", "private-parent-identity");
  if (!parent.ledger) fail("CLEANUP", "cleanup-identity-uncertain");
  await recordOwnedDirectory(
    parent.ledger,
    directory.path,
    "private-directory",
  );
  return Object.freeze({ ...directory, ledger: parent.ledger });
}

async function invokeCheckpoint(testHook, checkpoint, details = {}) {
  assertProxyFreeAuthorityGraph(testHook, HOOK_AUTHORITY_OPTIONS);
  assertProxyFreeAuthorityGraph(details);
  if (!testHook) return;
  if (testHook.failCheckpoint === checkpoint) {
    fail("BOUNDARY_VECTOR", "deliberate-embedded-failure");
  }
  if (testHook.publicationCheckpoint) {
    const pending = testHook.publicationCheckpoint(Object.freeze({
      checkpoint,
      ...details,
    }));
    assertProxyFreeAuthorityGraph(pending, ASYNC_RESULT_AUTHORITY_OPTIONS);
    const returned = await pending;
    assertProxyFreeAuthorityGraph(returned);
    if (returned !== undefined) fail("CLI", "test-hook-return-value");
  }
}

async function runSameProcessCell({
  repository,
  sourceCommit,
  sourceAuthority,
  privateRoot,
  ownershipLedger,
}) {
  const outputs = [];
  for (const label of ["same-process-a", "same-process-b"]) {
    const assignment = await createPrivateDirectory(privateRoot, label);
    outputs.push(await buildFreshZipCandidate({
      repository,
      sourceCommit,
      assignmentDirectory: assignment.path,
      expectedManifestSha256: sourceAuthority.manifest.sha256,
      expectedMembershipReportSha256:
        sourceAuthority.membershipReportSha256,
      ownershipLedger,
    }));
  }
  const [left, right] = outputs;
  if (
    !left.artifactBytes.equals(right.artifactBytes)
    || left.artifactSha256 !== right.artifactSha256
    || !left.entryPlanBytes.equals(right.entryPlanBytes)
    || left.entryPlanSha256 !== right.entryPlanSha256
    || !left.transcript.equals(right.transcript)
    || left.transcriptSha256 !== right.transcriptSha256
    || pathsEqual(left.sourceTree.path, right.sourceTree.path)
    || pathsEqual(left.entryPlanPath, right.entryPlanPath)
    || pathsEqual(left.artifactPath, right.artifactPath)
    || sameObject(left.sourceTree.identity, right.sourceTree.identity)
    || sameObject(left.entryPlanIdentity, right.entryPlanIdentity)
    || sameObject(left.artifactIdentity, right.artifactIdentity)
    || left.artifactIdentity.links !== 1n
    || right.artifactIdentity.links !== 1n
  ) fail("SAME_PROCESS", "same-process-mismatch");
  return Object.freeze({
    outputs: Object.freeze(outputs),
    canonicalVerifierPassed: true,
    sameProcessRepeatable: true,
  });
}

function deriveRunnerPolicyIdentitySha256(policy) {
  const identity = Object.fromEntries([
    "policyKind",
    "schemaVersion",
    "policyId",
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "criticalToolSetSha256",
    "manifestSha256",
    "testVectorSetSha256",
    "requiredClaimLevels",
    "requiredCells",
    "optionalCells",
  ].map((key) => [key, policy[key]]));
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-runner-policy-identity-v1\n", "ascii"),
    canonicalPublicJsonBytes(identity),
  ]));
}

function buildInputSet({
  policy,
  sourceAuthority,
  sameProcess,
  criticalTools,
  runtimeIdentity,
  gitIdentity,
  runnerPolicyIdentitySha256,
  vectorSha256,
}) {
  const candidate = sameProcess.outputs[0];
  const value = {
    documentKind: INPUT_SET_KIND,
    schemaVersion: 1,
    sourceCommit: policy.sourceCommit,
    toolingCommit: policy.toolingCommit,
    manifestSha256: sourceAuthority.manifest.sha256,
    membershipReportSha256: sourceAuthority.membershipReportSha256,
    membershipCount: sourceAuthority.membership.members.length,
    archiveRoot: ARCHIVE_ROOT,
    entryPlanSha256: candidate.entryPlanSha256,
    entryCount: candidate.plan.entryCount,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    criticalFiles: criticalTools.criticalFiles,
    runtimeIdentitySha256: runtimeIdentity.sha256,
    gitIdentitySha256: gitIdentity.sha256,
    runnerPolicyIdentitySha256,
    testVectorSetSha256: vectorSha256,
  };
  validateInputSet(value);
  const bytes = encodeCanonicalInputSet(value);
  return Object.freeze({
    value: deepFreezeZipReproducibility(value),
    bytes,
    sha256: sha256Bytes(bytes),
  });
}

async function writeStagingFile(directory, name, bytes) {
  if (
    typeof name !== "string"
    || path.basename(name) !== name
    || name === ".complete"
    || !Buffer.isBuffer(bytes)
  ) fail("OUTPUT_PUBLICATION", "staging-entry-invalid");
  const filePath = path.join(directory.path, name);
  await writeFile(filePath, bytes, { flag: "wx", mode: 0o600 });
  const file = await stableRead(
    filePath,
    "OUTPUT_PUBLICATION",
    "staging-entry-invalid",
    Math.max(bytes.length, 1),
  );
  if (!file.bytes.equals(bytes)) {
    fail("OUTPUT_PUBLICATION", "staging-entry-invalid");
  }
  await recordOwnedFile(
    directory.ledger,
    filePath,
    "staging-file",
    { byteLength: bytes.length, sha256: sha256Bytes(bytes) },
  );
  return Object.freeze({ name, bytes, ...file });
}

async function linkStagingArtifact(directory, name, source) {
  if (
    typeof name !== "string"
    || path.basename(name) !== name
    || !source
    || typeof source.path !== "string"
    || !Buffer.isBuffer(source.bytes)
  ) fail("OUTPUT_PUBLICATION", "staging-artifact-invalid");
  const filePath = path.join(directory.path, name);
  await link(source.path, filePath);
  const state = await lstat(filePath, { bigint: true });
  const identity = identityFromState(state);
  if (
    state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 2n
    || !sameObject(identity, source.identity)
    || state.size !== BigInt(source.byteLength)
  ) fail("OUTPUT_PUBLICATION", "staging-artifact-invalid");
  const file = await stableReadWithLinks(
    filePath,
    "OUTPUT_PUBLICATION",
    "staging-artifact-invalid",
    2n,
  );
  if (file.sha256 !== source.sha256 || !file.bytes.equals(source.bytes)) {
    fail("OUTPUT_PUBLICATION", "staging-artifact-invalid");
  }
  await recordOwnedFile(
    directory.ledger,
    filePath,
    "staging-artifact-link",
    { byteLength: source.byteLength, sha256: source.sha256 },
  );
  for (const record of directory.ledger.live.values()) {
    if (
      record.objectKind === "file"
      && record.literalPath !== filePath
      && sameObject(record.objectIdentity, identity)
    ) {
      await rebindOwnedFile(
        directory.ledger,
        record.literalPath,
        record.linkCount + 1n,
        "staging-artifact-link-transition",
      );
    }
  }
  return Object.freeze({ name, bytes: source.bytes, ...file });
}

async function stableReadWithLinks(filePath, phase, reason, expectedLinks) {
  const initial = await lstat(filePath, { bigint: true });
  if (
    initial.isSymbolicLink()
    || !initial.isFile()
    || initial.nlink !== expectedLinks
    || !pathsEqual(await realpath(filePath), filePath)
  ) fail(phase, reason);
  const identity = identityFromState(initial);
  let handle = null;
  try {
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = identityFromState(await handle.stat({ bigint: true }));
    const bytes = await handle.readFile();
    const after = identityFromState(await handle.stat({ bigint: true }));
    if (
      !identitiesEqual(identity, before)
      || !identitiesEqual(identity, after)
      || bytes.length !== Number(identity.size)
    ) fail(phase, reason);
    return Object.freeze({
      path: filePath,
      bytes,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      identity,
    });
  } finally {
    if (handle) await handle.close();
  }
}

async function validateStaging(directory, entries, mode) {
  const current = await inspectRealDirectory(
    directory.path,
    "OUTPUT_PUBLICATION",
    "staging-directory-invalid",
  );
  if (!sameObject(current.identity, directory.identity)) {
    fail("OUTPUT_PUBLICATION", "staging-directory-invalid");
  }
  const names = (await readdir(directory.path)).sort();
  const expected = entries.map((entry) => entry.name).sort();
  if (
    names.length !== expected.length
    || names.some((name, index) => name !== expected[index])
    || names.includes(".complete")
  ) fail("OUTPUT_PUBLICATION", "staging-entry-set");
  validateOutputEntrySet(
    [...entries.map((entry) => entry.name), ".complete"],
    mode,
  );
  for (const entry of entries) {
    const state = await lstat(entry.path, { bigint: true });
    const identity = identityFromState(state);
    if (
      !sameObject(identity, entry.identity)
      || state.size !== BigInt(entry.byteLength)
      || sha256Bytes(await readFile(entry.path)) !== entry.sha256
    ) fail("OUTPUT_PUBLICATION", "staging-entry-invalid");
  }
}

async function validateFinalNonMarkerBundle(
  publication,
  entries,
  mode,
  linkState,
  marker = null,
) {
  if (![
    "adopted",
    "private-root-removed",
  ].includes(linkState)) fail("OUTPUT_PUBLICATION", "link-state-invalid");
  const parent = await inspectRealDirectory(
    path.dirname(publication.path),
    "OUTPUT_PUBLICATION",
    "final-parent-invalid",
  );
  if (!sameObject(parent.identity, publication.parentIdentity)) {
    fail("OUTPUT_PUBLICATION", "final-parent-invalid");
  }
  const directory = await inspectRealDirectory(
    publication.path,
    "OUTPUT_PUBLICATION",
    "final-directory-invalid",
  );
  if (!sameObject(directory.identity, publication.identity)) {
    fail("OUTPUT_PUBLICATION", "final-directory-invalid");
  }
  const expectedNames = entries.map((entry) => entry.name);
  const names = (await readdir(publication.path)).sort();
  const expectedObserved = marker
    ? [...expectedNames, ".complete"].sort()
    : [...expectedNames].sort();
  if (
    names.length !== expectedObserved.length
    || names.some((name, index) => name !== expectedObserved[index])
  ) fail("OUTPUT_PUBLICATION", "final-entry-set");
  validateOutputEntrySet([...expectedNames, ".complete"], mode);
  for (const entry of entries) {
    const finalPath = path.join(publication.path, entry.name);
    const state = await lstat(finalPath, { bigint: true });
    const identity = identityFromState(state);
    if (
      state.isSymbolicLink()
      || !state.isFile()
      || !sameObject(identity, entry.identity)
      || state.size !== BigInt(entry.byteLength)
      || state.nlink !== (
        linkState === "adopted"
          ? entry.adoptedLinkCount
          : 1n
      )
      || sha256Bytes(await readFile(finalPath)) !== entry.sha256
    ) fail("OUTPUT_PUBLICATION", "final-entry-invalid");
  }
  if (!marker) return directory;
  const markerState = await lstat(marker.path, { bigint: true });
  if (
    markerState.isSymbolicLink()
    || !markerState.isFile()
    || markerState.nlink !== 1n
    || !sameObject(identityFromState(markerState), marker.identity)
    || markerState.size !== BigInt(Buffer.byteLength(COMPLETION_MARKER, "ascii"))
    || !(await readFile(marker.path)).equals(Buffer.from(COMPLETION_MARKER, "ascii"))
  ) fail("OUTPUT_PUBLICATION", "completion-marker-invalid");
  return directory;
}

async function validateFinalBundle(publication, entries, mode, marker) {
  return validateFinalNonMarkerBundle(
    publication,
    entries,
    mode,
    "private-root-removed",
    marker,
  );
}

async function refreshPrivateLedgerAfterAdoption(privateRoot, adoptedEntries) {
  const increments = new Map();
  for (const entry of adoptedEntries) {
    const key = cleanupIdentityKey(entry.identity);
    increments.set(key, (increments.get(key) ?? 0n) + 1n);
  }
  for (const record of [...privateRoot.ledger.live.values()]) {
    if (record.objectKind !== "file") continue;
    const increment = increments.get(cleanupIdentityKey(record.objectIdentity)) ?? 0n;
    if (increment === 0n) continue;
    await rebindOwnedFile(
      privateRoot.ledger,
      record.literalPath,
      record.linkCount + increment,
      "final-adoption-link-transition",
    );
  }
}

async function revokePublisherMarker(publication, marker) {
  if (!marker) return "marker-already-absent";
  const parentPath = path.dirname(marker.path);
  const parentState = await pathState(parentPath);
  if (
    !parentState
    || parentState.isSymbolicLink()
    || !parentState.isDirectory()
    || !sameObject(identityFromState(parentState), publication.identity)
  ) return "marker-parent-replaced";
  const markerState = await pathState(marker.path);
  if (!markerState) return "marker-already-absent";
  if (
    markerState.isSymbolicLink()
    || !markerState.isFile()
    || !sameObject(identityFromState(markerState), marker.identity)
  ) return "marker-replaced";
  if (
    markerState.nlink !== 1n
    || markerState.size !== BigInt(Buffer.byteLength(COMPLETION_MARKER, "ascii"))
  ) return "marker-identity-uncertain";
  let bytes;
  try {
    bytes = await readFile(marker.path);
  } catch {
    return "marker-identity-uncertain";
  }
  if (!bytes.equals(Buffer.from(COMPLETION_MARKER, "ascii"))) {
    return "marker-identity-uncertain";
  }
  const finalParent = await pathState(parentPath);
  const finalMarker = await pathState(marker.path);
  if (
    !finalParent
    || finalParent.isSymbolicLink()
    || !finalParent.isDirectory()
    || !sameObject(identityFromState(finalParent), publication.identity)
    || !finalMarker
    || !sameObject(identityFromState(finalMarker), marker.identity)
  ) return "marker-identity-uncertain";
  await unlink(marker.path);
  if (await pathState(marker.path)) return "marker-identity-uncertain";
  return "publisher-owned-marker-revoked";
}

async function publishBundle({
  target,
  privateRoot,
  staging,
  entries,
  mode,
  testHook,
}) {
  let publication = null;
  let marker = null;
  try {
    selectPublicationMode(mode);
    await validateStaging(staging, entries, mode);
    await invokeCheckpoint(testHook, "before-final-directory", {
      finalDirectory: target.path,
      stagingDirectory: staging.path,
      mode,
    });
    const parent = await inspectRealDirectory(
      target.parent.path,
      "OUTPUT_PUBLICATION",
      "output-parent-invalid",
    );
    if (!sameObject(parent.identity, target.parent.identity)) {
      fail("OUTPUT_PUBLICATION", "output-parent-identity");
    }
    try {
      await mkdir(target.path, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error && error.code === "EEXIST") {
        fail("OUTPUT_PUBLICATION", "output-directory-exists");
      }
      throw error;
    }
    const finalDirectory = await inspectRealDirectory(
      target.path,
      "OUTPUT_PUBLICATION",
      "final-directory-invalid",
    );
    publication = {
      path: finalDirectory.path,
      identity: finalDirectory.identity,
      parentIdentity: parent.identity,
      entries: [],
      marker: null,
      markerDisposition: null,
      mode,
    };
    await invokeCheckpoint(testHook, "after-final-directory", {
      finalDirectory: publication.path,
      stagingDirectory: staging.path,
      mode,
    });
    for (const entry of entries) {
      await validateStaging(staging, entries, mode);
      await invokeCheckpoint(testHook, "before-adopt-" + entry.name, {
        finalDirectory: publication.path,
        stagingDirectory: staging.path,
        targetPath: path.join(publication.path, entry.name),
        mode,
      });
      const finalPath = path.join(publication.path, entry.name);
      await link(entry.path, finalPath);
      const state = await lstat(finalPath, { bigint: true });
      const identity = identityFromState(state);
      if (
        state.isSymbolicLink()
        || !state.isFile()
        || !sameObject(identity, entry.identity)
        || state.size !== BigInt(entry.byteLength)
        || state.nlink !== entry.identity.links + 1n
      ) fail("OUTPUT_PUBLICATION", "adoption-identity");
      publication.entries.push(Object.freeze({
        ...entry,
        finalPath,
        finalIdentity: identity,
        adoptedLinkCount: state.nlink,
      }));
    }
    await validateStaging(staging, entries, mode);
    await validateFinalNonMarkerBundle(
      publication,
      publication.entries,
      mode,
      "adopted",
    );
    await invokeCheckpoint(testHook, "before-staging-cleanup", {
      finalDirectory: publication.path,
      stagingDirectory: staging.path,
      mode,
    });
    await refreshPrivateLedgerAfterAdoption(
      privateRoot,
      publication.entries,
    );
    await cleanupPrivateRoot(privateRoot, testHook);
    if (await pathState(privateRoot.path)) {
      fail("CLEANUP", "cleanup-incomplete");
    }
    await invokeCheckpoint(testHook, "after-private-cleanup", {
      finalDirectory: publication.path,
      stagingDirectory: staging.path,
      mode,
    });
    await validateFinalNonMarkerBundle(
      publication,
      publication.entries,
      mode,
      "private-root-removed",
    );
    await invokeCheckpoint(testHook, "before-marker", {
      finalDirectory: publication.path,
      stagingDirectory: staging.path,
      mode,
    });
    await validateFinalNonMarkerBundle(
      publication,
      publication.entries,
      mode,
      "private-root-removed",
    );
    const markerPath = path.join(publication.path, ".complete");
    await writeFile(markerPath, Buffer.from(COMPLETION_MARKER, "ascii"), {
      flag: "wx",
      mode: 0o600,
    });
    const markerState = await lstat(markerPath, { bigint: true });
    marker = Object.freeze({
      path: markerPath,
      identity: identityFromState(markerState),
      parentPath: publication.path,
      parentIdentity: publication.identity,
      byteLength: Buffer.byteLength(COMPLETION_MARKER, "ascii"),
      sha256: sha256Bytes(Buffer.from(COMPLETION_MARKER, "ascii")),
      creationPhase: "marker-last",
    });
    publication.marker = marker;
    await invokeCheckpoint(testHook, "after-marker", {
      finalDirectory: publication.path,
      stagingDirectory: staging.path,
      markerPath,
      mode,
    });
    await validateFinalBundle(
      publication,
      publication.entries,
      mode,
      marker,
    );
    return Object.freeze({
      path: publication.path,
      identity: publication.identity,
      parentIdentity: publication.parentIdentity,
      entries: Object.freeze(publication.entries),
      marker,
      markerDisposition: "publisher-owned-marker-visible",
      mode,
    });
  } catch (error) {
    if (publication && marker) {
      let disposition = "marker-identity-uncertain";
      try {
        disposition = await revokePublisherMarker(publication, marker);
      } catch {
        disposition = "marker-identity-uncertain";
      }
      publication.markerDisposition = disposition;
      if (error && typeof error === "object") {
        Object.defineProperty(error, "markerDisposition", {
          value: disposition,
          enumerable: false,
          configurable: true,
        });
      }
    }
    if (publication && error && typeof error === "object") {
      Object.defineProperty(error, "publication", {
        value: publication,
        enumerable: false,
        configurable: true,
      });
    }
    throw error;
  }
}

async function cleanupFailedPublication(publication) {
  if (!publication) return;
  const directoryState = await pathState(publication.path);
  if (!directoryState) return;
  if (
    directoryState.isSymbolicLink()
    || !directoryState.isDirectory()
    || !sameObject(identityFromState(directoryState), publication.identity)
    || !pathsEqual(await realpath(publication.path), publication.path)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const parentState = await pathState(path.dirname(publication.path));
  if (
    !parentState
    || parentState.isSymbolicLink()
    || !parentState.isDirectory()
    || !sameObject(identityFromState(parentState), publication.parentIdentity)
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  const allowed = new Map();
  for (const entry of publication.entries ?? []) {
    allowed.set(entry.name, entry);
  }
  if (publication.marker) allowed.set(".complete", publication.marker);
  const names = await readdir(publication.path);
  if (names.some((name) => !allowed.has(name))) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  for (const name of names) {
    const record = allowed.get(name);
    const filePath = path.join(publication.path, name);
    const state = await lstat(filePath, { bigint: true });
    const expected = name === ".complete" ? record.identity : record.finalIdentity;
    if (
      state.isSymbolicLink()
      || !state.isFile()
      || !sameObject(identityFromState(state), expected)
      || state.size !== BigInt(
        name === ".complete" ? record.byteLength : record.byteLength
      )
      || state.nlink !== (
        name === ".complete"
          ? 1n
          : state.nlink === 1n
            ? 1n
            : record.adoptedLinkCount
      )
    ) fail("CLEANUP", "cleanup-identity-uncertain");
    const expectedSha256 = name === ".complete"
      ? record.sha256
      : record.sha256;
    if (sha256Bytes(await readFile(filePath)) !== expectedSha256) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
  }
  for (const name of names) {
    const record = allowed.get(name);
    const filePath = path.join(publication.path, name);
    const state = await pathState(filePath);
    const expected = name === ".complete" ? record.identity : record.finalIdentity;
    if (
      !state
      || state.isSymbolicLink()
      || !state.isFile()
      || !sameObject(identityFromState(state), expected)
      || sha256Bytes(await readFile(filePath)) !== record.sha256
    ) fail("CLEANUP", "cleanup-identity-uncertain");
    await unlink(filePath);
    if (await pathState(filePath)) fail("CLEANUP", "cleanup-incomplete");
  }
  const finalDirectory = await pathState(publication.path);
  if (
    !finalDirectory
    || finalDirectory.isSymbolicLink()
    || !finalDirectory.isDirectory()
    || !sameObject(identityFromState(finalDirectory), publication.identity)
    || (await readdir(publication.path)).length !== 0
  ) fail("CLEANUP", "cleanup-identity-uncertain");
  await rmdir(publication.path);
  if (await pathState(publication.path)) fail("CLEANUP", "cleanup-incomplete");
}

async function stageSuccessBundle({
  privateRoot,
  candidate,
  inputSet,
  semanticBytes,
  evidenceBytes,
  verificationBytes,
}) {
  const staging = await createPrivateDirectory(privateRoot, "success-staging");
  const artifactSource = Object.freeze({
    path: candidate.artifactPath,
    bytes: candidate.artifactBytes,
    sha256: candidate.artifactSha256,
    byteLength: candidate.artifactByteLength,
    identity: candidate.artifactIdentity,
  });
  const entries = [
    await linkStagingArtifact(staging, "artifact.zip", artifactSource),
    await writeStagingFile(
      staging,
      "zip-verification.json",
      candidate.transcript,
    ),
    await writeStagingFile(staging, "entry-plan.json", candidate.entryPlanBytes),
    await writeStagingFile(staging, "input-set.json", inputSet.bytes),
    await writeStagingFile(staging, "semantic-report.json", semanticBytes),
    await writeStagingFile(staging, "evidence.json", evidenceBytes),
    await writeStagingFile(
      staging,
      "verification-result.json",
      verificationBytes,
    ),
  ];
  return Object.freeze({ staging, entries: Object.freeze(entries) });
}

async function stageFailureBundle({
  privateRoot,
  inputSet,
  evidenceBytes,
  verificationBytes,
}) {
  const staging = await createPrivateDirectory(privateRoot, "failure-staging");
  const entries = [
    await writeStagingFile(staging, "input-set.json", inputSet.bytes),
    await writeStagingFile(staging, "evidence.json", evidenceBytes),
    await writeStagingFile(
      staging,
      "verification-result.json",
      verificationBytes,
    ),
  ];
  return Object.freeze({ staging, entries: Object.freeze(entries) });
}

async function teardownSyntheticFixtureTree(rootPath) {
  if (!(await pathState(rootPath))) return;
  const directories = [];
  const leaves = [];
  const pending = [rootPath];
  while (pending.length > 0) {
    const directoryPath = pending.shift();
    const state = await pathState(directoryPath);
    if (!state) continue;
    if (state.isSymbolicLink() || !state.isDirectory()) {
      leaves.push(directoryPath);
      continue;
    }
    directories.push(directoryPath);
    for (const name of (await readdir(directoryPath)).sort()) {
      const childPath = path.join(directoryPath, name);
      const childState = await pathState(childPath);
      if (childState?.isDirectory() && !childState.isSymbolicLink()) {
        pending.push(childPath);
      } else if (childState) {
        leaves.push(childPath);
      }
    }
  }
  for (const leaf of leaves.sort((left, right) => right.length - left.length)) {
    await unlink(leaf);
  }
  for (const directory of directories.sort(
    (left, right) => right.length - left.length,
  )) {
    if ((await readdir(directory)).length !== 0) {
      fail("CLEANUP", "cleanup-incomplete");
    }
    await rmdir(directory);
  }
  if (await pathState(rootPath)) fail("CLEANUP", "cleanup-incomplete");
}

const PRIVATE_CLEANUP_CONTROL_IDS = Object.freeze([
  "CLN01",
  "CLN02",
  "CLN03",
  "CLN04",
  "CLN05",
  "CLN06",
  "CLN07",
  "CLN08",
  "CLN09",
  "CLN10",
  "CLN11",
  "CLN12",
  "CLN13",
  "CLN14",
  "CLN15",
  "CLN16",
]);

async function createCleanupControlFixture(caseContainer, empty = false) {
  const parentPath = path.join(caseContainer, "private-parent");
  await mkdir(parentPath, { recursive: false, mode: 0o700 });
  const parent = await inspectRealDirectory(
    parentPath,
    "CLEANUP",
    "cleanup-control-parent",
  );
  const rootPath = path.resolve(await mkdtemp(path.join(parent.path, "root-")));
  const inspected = await inspectRealDirectory(
    rootPath,
    "CLEANUP",
    "cleanup-control-root",
  );
  const root = Object.freeze({
    ...inspected,
    ledger: createPrivateCleanupLedger(inspected, parent),
  });
  if (empty) return Object.freeze({ parent, root, child: null, filePath: null });
  const child = await createPrivateDirectory(root, "child");
  const filePath = path.join(child.path, "owned.bin");
  const bytes = Buffer.from("owned-cleanup-control\n", "ascii");
  await writeFile(filePath, bytes, { flag: "wx", mode: 0o600 });
  await recordOwnedFile(root.ledger, filePath, "cleanup-control-file", {
    byteLength: bytes.length,
    sha256: sha256Bytes(bytes),
  });
  return Object.freeze({ parent, root, child, filePath, bytes });
}

async function applyCleanupControlMutation(controlId, fixture, caseContainer) {
  const { root, child, filePath, bytes } = fixture;
  switch (controlId) {
    case "CLN01":
      await writeFile(
        path.join(root.path, "unexpected.bin"),
        Buffer.from("unexpected\n", "ascii"),
        { flag: "wx", mode: 0o600 },
      );
      return;
    case "CLN02":
      await unlink(filePath);
      await writeFile(filePath, Buffer.from("replacement\n", "ascii"), {
        flag: "wx",
        mode: 0o600,
      });
      return;
    case "CLN03": {
      await unlink(filePath);
      const replacement = Buffer.alloc(bytes.length, 0x78);
      await writeFile(filePath, replacement, { flag: "wx", mode: 0o600 });
      return;
    }
    case "CLN04":
      await writeFile(filePath, Buffer.from("short", "ascii"));
      return;
    case "CLN05":
      await writeFile(filePath, Buffer.concat([
        bytes,
        Buffer.from("growth", "ascii"),
      ]));
      return;
    case "CLN06": {
      const targetFile = path.join(caseContainer, "reparse-target.bin");
      await writeFile(targetFile, Buffer.from("target\n", "ascii"), {
        flag: "wx",
        mode: 0o600,
      });
      await unlink(filePath);
      try {
        await symlink(targetFile, filePath, "file");
      } catch {
        const targetDirectory = path.join(caseContainer, "reparse-target-dir");
        await mkdir(targetDirectory, { recursive: false, mode: 0o700 });
        await symlink(
          targetDirectory,
          filePath,
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      return;
    }
    case "CLN07": {
      const targetDirectory = path.join(caseContainer, "directory-target");
      await mkdir(targetDirectory, { recursive: false, mode: 0o700 });
      await unlink(filePath);
      await rmdir(child.path);
      await symlink(
        targetDirectory,
        child.path,
        process.platform === "win32" ? "junction" : "dir",
      );
      return;
    }
    case "CLN08": {
      const moved = fixture.parent.path + "-replaced";
      await rename(fixture.parent.path, moved);
      await mkdir(fixture.parent.path, { recursive: false, mode: 0o700 });
      return;
    }
    case "CLN09":
      await rename(child.path, child.path + "-replaced");
      await mkdir(child.path, { recursive: false, mode: 0o700 });
      return;
    case "CLN10":
      await link(filePath, path.join(caseContainer, "unexpected-hard-link"));
      return;
    case "CLN11":
      await unlink(filePath);
      return;
    case "CLN12":
      await mkdir(path.join(child.path, "unexpected-nested"), {
        recursive: false,
        mode: 0o700,
      });
      return;
    case "CLN15":
      await recordOwnedFile(root.ledger, filePath, "duplicate-ledger-entry");
      return;
    case "CLN16":
      await writeFile(
        path.join(child.path, "missing-ledger-entry.bin"),
        Buffer.from("not-ledgered\n", "ascii"),
        { flag: "wx", mode: 0o600 },
      );
      return;
    default:
      fail("CLEANUP", "cleanup-control-invalid");
  }
}

export async function runPrivateCleanupControlMatrix(options = {}) {
  assertProxyFreeAuthorityGraph(options);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "temporaryParent",
      "uncertaintyRepetitions",
    ].includes(key))
  ) fail("CLEANUP", "cleanup-control-options");
  const {
    temporaryParent,
    uncertaintyRepetitions = 30,
  } = options;
  validateAbsoluteNormalizedPath(
    temporaryParent,
    "CLEANUP",
    "cleanup-control-parent",
  );
  if (
    !Number.isSafeInteger(uncertaintyRepetitions)
    || uncertaintyRepetitions !== 30
  ) fail("CLEANUP", "cleanup-control-repetitions");
  const parent = await inspectRealDirectory(
    temporaryParent,
    "CLEANUP",
    "cleanup-control-parent",
  );
  const matrixPath = path.resolve(await mkdtemp(path.join(
    parent.path,
    ".izcln-",
  )));
  const summaries = [];
  let uncertaintyCompletedCount = 0;
  let zeroDeletionCount = 0;
  try {
    for (const controlId of PRIVATE_CLEANUP_CONTROL_IDS) {
      const repetitions = /^CLN(?:0[1-9]|1[0-2])$/u.test(controlId)
        ? uncertaintyRepetitions
        : 1;
      for (let repetition = 0; repetition < repetitions; repetition += 1) {
        const caseContainer = path.join(
          matrixPath,
          controlId.toLowerCase() + "-" + String(repetition).padStart(2, "0"),
        );
        await mkdir(caseContainer, { recursive: false, mode: 0o700 });
        const fixture = await createCleanupControlFixture(
          caseContainer,
          controlId === "CLN14",
        );
        let result = "failure";
        let reason = null;
        let unlinkCount = 0;
        let rmdirCount = 0;
        let rootPreserved = true;
        const preservedRootPath = controlId === "CLN08"
          ? path.join(
            fixture.parent.path + "-replaced",
            path.basename(fixture.root.path),
          )
          : fixture.root.path;
        try {
          if (!["CLN13", "CLN14"].includes(controlId)) {
            await applyCleanupControlMutation(controlId, fixture, caseContainer);
          }
          const cleanup = await cleanupPrivateRoot(fixture.root);
          unlinkCount = cleanup.unlinkCount;
          rmdirCount = cleanup.rmdirCount;
          rootPreserved = Boolean(await pathState(preservedRootPath));
          if (!["CLN13", "CLN14"].includes(controlId)) {
            fail("CLEANUP", "cleanup-control-false-success");
          }
          result = "success";
        } catch (error) {
          const safe = asZipReproducibilityError(
            error,
            "CLEANUP",
            "cleanup-identity-uncertain",
          );
          reason = safe.reason;
          unlinkCount = safe.cleanupUnlinkCount ?? 0;
          rmdirCount = safe.cleanupRmdirCount ?? 0;
          rootPreserved = Boolean(await pathState(preservedRootPath));
          if (["CLN13", "CLN14"].includes(controlId)) throw safe;
          if (
            safe.phase !== "CLEANUP"
            || safe.reason !== "cleanup-identity-uncertain"
            || unlinkCount !== 0
            || rmdirCount !== 0
            || !rootPreserved
          ) throw safe;
          uncertaintyCompletedCount += 1;
          zeroDeletionCount += 1;
        }
        summaries.push(Object.freeze({
          controlId,
          repetition,
          result,
          reason,
          unlinkCount,
          rmdirCount,
          rootPreserved,
        }));
        await teardownSyntheticFixtureTree(caseContainer);
      }
    }
  } finally {
    await teardownSyntheticFixtureTree(matrixPath);
  }
  const expectedUncertainty = 12 * uncertaintyRepetitions + 2;
  if (
    summaries.length !== expectedUncertainty + 2
    || uncertaintyCompletedCount !== expectedUncertainty
    || zeroDeletionCount !== expectedUncertainty
  ) fail("CLEANUP", "cleanup-control-accounting");
  return Object.freeze({
    status: "ok",
    mode: "private-cleanup-control-matrix",
    controlCount: PRIVATE_CLEANUP_CONTROL_IDS.length,
    uncertaintyRepetitionCount: uncertaintyRepetitions,
    uncertaintyCompletedCount,
    zeroDeletionCount,
    normalCleanupCount: 2,
    summaries: Object.freeze(summaries),
  });
}

export async function runPublicationRaceMatrix(options = {}) {
  assertProxyFreeAuthorityGraph(options);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some((key) => ![
      "temporaryParent",
      "repetitions",
    ].includes(key))
  ) fail("OUTPUT_PUBLICATION", "race-options-invalid");
  const {
    temporaryParent,
    repetitions = 20,
  } = options;
  validateAbsoluteNormalizedPath(
    temporaryParent,
    "OUTPUT_PUBLICATION",
    "race-parent-invalid",
  );
  if (!Number.isSafeInteger(repetitions) || repetitions !== 20) {
    fail("OUTPUT_PUBLICATION", "race-repetition-count");
  }
  const parent = await inspectRealDirectory(
    temporaryParent,
    "OUTPUT_PUBLICATION",
    "race-parent-invalid",
  );
  const matrixPath = path.resolve(await mkdtemp(path.join(
    parent.path,
    ".izrace-",
  )));
  const signatures = new Map();
  const dispositions = new Map();
  const markerMetrics = new Map(PUBLICATION_MARKER_CASES.map((controlId) => [
    controlId,
    {
      controlId,
      completedCount: 0,
      successCount: 0,
      failureCount: 0,
      markerAbsentCount: 0,
      markerRevokedCount: 0,
      payloadPreservedCount: 0,
      unrelatedDeletionCount: 0,
    },
  ]));
  let completedCount = 0;
  let cleanupUncertaintyCount = 0;
  let falseMarkerCount = 0;
  let markerCreatedLastCount = 0;
  try {
    for (let caseIndex = 0; caseIndex < PUBLICATION_RACE_CASES.length; caseIndex += 1) {
      const raceCase = PUBLICATION_RACE_CASES[caseIndex];
      for (let repetition = 0; repetition < repetitions; repetition += 1) {
        const caseContainer = path.join(
          matrixPath,
          "case-" + String(caseIndex).padStart(2, "0")
            + "-" + String(repetition).padStart(2, "0"),
        );
        await mkdir(caseContainer, { recursive: false, mode: 0o700 });
        const outputParentPath = path.join(caseContainer, "output-parent");
        await mkdir(outputParentPath, { recursive: false, mode: 0o700 });
        const target = await validateOutputTarget(
          path.join(outputParentPath, "bundle"),
          path.join(caseContainer, "synthetic-repository"),
        );
        const privateRoot = await createPrivateRoot(target);
        const staging = await createPrivateDirectory(
          privateRoot,
          "success-staging",
        );
        const entries = [];
        for (const name of SUCCESS_OUTPUT_NAMES.slice(0, -1)) {
          entries.push(await writeStagingFile(
            staging,
            name,
            Buffer.from("race-" + name + "\n", "ascii"),
          ));
        }
        const sentinelPath = path.join(caseContainer, "unrelated.sentinel");
        const sentinelBytes = Buffer.from("unrelated\n", "ascii");
        await writeFile(sentinelPath, sentinelBytes, {
          flag: "wx",
          mode: 0o600,
        });
        let racePerformed = raceCase === "PUB-M10";
        const hook = {
          async publicationCheckpoint(details) {
            const { checkpoint } = details;
            const firstName = entries[0].name;
            const supportName = entries[4].name;
            if (
              raceCase === "final-directory-precreation"
              && checkpoint === "before-final-directory"
            ) {
              await mkdir(details.finalDirectory, {
                recursive: false,
                mode: 0o700,
              });
              racePerformed = true;
            } else if (
              raceCase === "fixed-file-precreation"
              && checkpoint === "after-final-directory"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "entry-plan.json"),
                Buffer.from("attacker\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "artifact-target-race"
              && checkpoint === "before-adopt-artifact.zip"
            ) {
              await writeFile(details.targetPath, Buffer.from("race\n", "ascii"), {
                flag: "wx",
                mode: 0o600,
              });
              racePerformed = true;
            } else if (
              raceCase === "supporting-document-target-race"
              && checkpoint === "before-adopt-" + supportName
            ) {
              await writeFile(details.targetPath, Buffer.from("race\n", "ascii"), {
                flag: "wx",
                mode: 0o600,
              });
              racePerformed = true;
            } else if (
              raceCase === "marker-precreation"
              && checkpoint === "before-marker"
            ) {
              await writeFile(
                path.join(details.finalDirectory, ".complete"),
                Buffer.from("attacker\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "private-staging-replacement"
              && checkpoint === "before-final-directory"
            ) {
              await rename(
                details.stagingDirectory,
                details.stagingDirectory + ".replaced",
              );
              await mkdir(details.stagingDirectory, {
                recursive: false,
                mode: 0o700,
              });
              racePerformed = true;
            } else if (
              [
                "final-object-replacement",
                "PUB-M08",
              ].includes(raceCase)
              && checkpoint === (
                raceCase === "PUB-M08" ? "after-marker" : "before-staging-cleanup"
              )
            ) {
              const finalPath = path.join(details.finalDirectory, firstName);
              await unlink(finalPath);
              await writeFile(
                finalPath,
                Buffer.from("replacement-payload\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "parent-replacement"
              && checkpoint === "before-final-directory"
            ) {
              await rename(outputParentPath, outputParentPath + ".replaced");
              await mkdir(outputParentPath, { recursive: false, mode: 0o700 });
              racePerformed = true;
            } else if (
              raceCase === "reparse-insertion"
              && checkpoint === "after-final-directory"
            ) {
              await symlink(
                details.finalDirectory,
                path.join(details.finalDirectory, firstName),
                process.platform === "win32" ? "junction" : "dir",
              );
              racePerformed = true;
            } else if (
              raceCase === "hard-link-count-anomaly"
              && checkpoint === "before-staging-cleanup"
            ) {
              await link(
                path.join(details.finalDirectory, firstName),
                path.join(caseContainer, "extra-link"),
              );
              racePerformed = true;
            } else if (
              [
                "entry-set-injection",
                "cleanup-identity-uncertainty",
                "PUB-M01",
              ].includes(raceCase)
              && checkpoint === "before-staging-cleanup"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "unexpected-before-cleanup"),
                Buffer.from("injected\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "adoption-failure"
              && checkpoint === "before-adopt-" + firstName
            ) {
              racePerformed = true;
              fail("OUTPUT_PUBLICATION", "adoption-failure");
            } else if (
              ["post-marker-substitution", "PUB-M06"].includes(raceCase)
              && checkpoint === "after-marker"
            ) {
              await unlink(details.markerPath);
              await writeFile(
                details.markerPath,
                Buffer.from("substituted\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "PUB-M02"
              && checkpoint === "before-private-cleanup-action"
              && details.actionKind === "unlink"
              && details.relativePath.includes("success-staging/")
            ) {
              racePerformed = true;
              fail("CLEANUP", "staging-cleanup-failure");
            } else if (
              raceCase === "PUB-M03"
              && checkpoint === "before-private-cleanup-action"
              && details.actionKind === "rmdir"
              && details.relativePath === "."
            ) {
              racePerformed = true;
              fail("CLEANUP", "private-root-cleanup-failure");
            } else if (
              raceCase === "PUB-M04"
              && checkpoint === "before-marker"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "unexpected-before-marker"),
                Buffer.from("injected\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              ["PUB-M05", "PUB-M09"].includes(raceCase)
              && checkpoint === "after-marker"
            ) {
              await writeFile(
                path.join(
                  details.finalDirectory,
                  raceCase === "PUB-M05"
                    ? "unexpected-immediate"
                    : "unexpected-sibling",
                ),
                Buffer.from("injected\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "PUB-M07"
              && checkpoint === "after-marker"
            ) {
              await rename(
                details.finalDirectory,
                details.finalDirectory + ".replaced",
              );
              await mkdir(details.finalDirectory, {
                recursive: false,
                mode: 0o700,
              });
              racePerformed = true;
            }
          },
        };
        let publication = null;
        let observed = null;
        let disposition = null;
        let success = false;
        try {
          publication = await publishBundle({
            target,
            privateRoot,
            staging,
            entries: Object.freeze(entries),
            mode: "success",
            testHook: hook,
          });
          success = true;
          if (raceCase !== "PUB-M10") {
            fail("OUTPUT_PUBLICATION", "race-false-success");
          }
        } catch (error) {
          publication = error?.publication ?? publication;
          disposition = error?.markerDisposition
            ?? publication?.markerDisposition
            ?? null;
          observed = asZipReproducibilityError(
            error,
            "OUTPUT_PUBLICATION",
            "race-detected",
          );
        }
        if (!racePerformed || (raceCase === "PUB-M10") !== success) {
          fail("OUTPUT_PUBLICATION", "race-accounting-invalid");
        }
        const signature = success
          ? "success"
          : observed.phase + ":" + observed.reason;
        if (signatures.has(raceCase) && signatures.get(raceCase) !== signature) {
          fail("OUTPUT_PUBLICATION", "race-alternating-outcome");
        }
        signatures.set(raceCase, signature);
        if (
          dispositions.has(raceCase)
          && dispositions.get(raceCase) !== disposition
        ) fail("OUTPUT_PUBLICATION", "race-alternating-outcome");
        dispositions.set(raceCase, disposition);

        const markerPath = path.join(target.path, ".complete");
        const markerState = await pathState(markerPath);
        let publisherMarkerVisible = false;
        if (markerState && publication?.marker) {
          publisherMarkerVisible = !markerState.isSymbolicLink()
            && markerState.isFile()
            && sameObject(
              identityFromState(markerState),
              publication.marker.identity,
            )
            && (await readFile(markerPath)).equals(
              Buffer.from(COMPLETION_MARKER, "ascii"),
            );
        }
        if (!success && publisherMarkerVisible) {
          falseMarkerCount += 1;
          fail("OUTPUT_PUBLICATION", "race-safety-invariant");
        }
        if (success) {
          const names = (await readdir(target.path)).sort();
          const expected = [...SUCCESS_OUTPUT_NAMES].sort();
          if (
            names.length !== expected.length
            || names.some((name, index) => name !== expected[index])
            || !(await readFile(markerPath)).equals(
              Buffer.from(COMPLETION_MARKER, "ascii"),
            )
            || await pathState(privateRoot.path)
          ) fail("OUTPUT_PUBLICATION", "race-safety-invariant");
          markerCreatedLastCount += 1;
        }

        let payloadPreserved = false;
        if (!success) {
          try {
            await cleanupFailedPublication(publication);
          } catch (error) {
            const safe = asZipReproducibilityError(
              error,
              "CLEANUP",
              "cleanup-identity-uncertain",
            );
            if (safe.phase !== "CLEANUP") throw safe;
            cleanupUncertaintyCount += 1;
          }
          try {
            await cleanupPrivateRoot(privateRoot);
          } catch (error) {
            const safe = asZipReproducibilityError(
              error,
              "CLEANUP",
              "cleanup-identity-uncertain",
            );
            if (safe.phase !== "CLEANUP") throw safe;
            cleanupUncertaintyCount += 1;
          }
          if (["PUB-M05", "PUB-M08", "PUB-M09"].includes(raceCase)) {
            const preservedDirectory = await pathState(target.path);
            const preservedPayload = await pathState(
              path.join(target.path, entries[0].name),
            );
            payloadPreserved = Boolean(preservedDirectory && preservedPayload);
            if (!payloadPreserved || await pathState(markerPath)) {
              fail("OUTPUT_PUBLICATION", "race-safety-invariant");
            }
          }
        }
        if (!(await readFile(sentinelPath)).equals(sentinelBytes)) {
          fail("OUTPUT_PUBLICATION", "race-safety-invariant");
        }

        const metric = markerMetrics.get(raceCase);
        if (metric) {
          metric.completedCount += 1;
          metric.successCount += success ? 1 : 0;
          metric.failureCount += success ? 0 : 1;
          metric.markerAbsentCount += (await pathState(markerPath)) ? 0 : 1;
          metric.markerRevokedCount += disposition
            === "publisher-owned-marker-revoked" ? 1 : 0;
          metric.payloadPreservedCount += payloadPreserved ? 1 : 0;
        }
        completedCount += 1;
        await teardownSyntheticFixtureTree(caseContainer);
      }
    }
  } finally {
    await teardownSyntheticFixtureTree(matrixPath);
  }
  if (
    completedCount !== PUBLICATION_RACE_CASES.length * repetitions
    || signatures.size !== PUBLICATION_RACE_CASES.length
    || falseMarkerCount !== 0
    || markerCreatedLastCount !== repetitions
  ) fail("OUTPUT_PUBLICATION", "race-accounting-invalid");
  for (const controlId of PUBLICATION_MARKER_CASES) {
    const metric = markerMetrics.get(controlId);
    if (
      metric.completedCount !== repetitions
      || (controlId === "PUB-M10"
        ? metric.successCount !== repetitions
        : metric.failureCount !== repetitions)
      || (["PUB-M01", "PUB-M02", "PUB-M03", "PUB-M04"].includes(controlId)
        && metric.markerAbsentCount !== repetitions)
      || (["PUB-M05", "PUB-M08", "PUB-M09"].includes(controlId)
        && (
          metric.markerRevokedCount !== repetitions
          || metric.markerAbsentCount !== repetitions
          || metric.payloadPreservedCount !== repetitions
        ))
    ) fail("OUTPUT_PUBLICATION", "race-accounting-invalid");
  }
  return Object.freeze({
    status: "ok",
    mode: "publication-race-matrix",
    caseCount: PUBLICATION_RACE_CASES.length,
    markerControlCount: PUBLICATION_MARKER_CASES.length,
    repetitionCount: repetitions,
    completedCount,
    markerControlCompletedCount:
      PUBLICATION_MARKER_CASES.length * repetitions,
    markerCreatedLastCount,
    alternatingOutcomeCount: 0,
    staleSuccessFileCount: 0,
    modeConversionCount: 0,
    falseMarkerCount,
    trustedUnexpectedEntryCount: 0,
    unrelatedDeletionCount: 0,
    cleanupUncertaintyCount,
    markerControls: Object.freeze(PUBLICATION_MARKER_CASES.map(
      (controlId) => Object.freeze({ ...markerMetrics.get(controlId) }),
    )),
  });
}

async function runLegacyPublicationRaceMatrixUnused({
  temporaryParent,
  repetitions = 20,
} = {}) {
  validateAbsoluteNormalizedPath(
    temporaryParent,
    "OUTPUT_PUBLICATION",
    "race-parent-invalid",
  );
  if (!Number.isSafeInteger(repetitions) || repetitions !== 20) {
    fail("OUTPUT_PUBLICATION", "race-repetition-count");
  }
  const parent = await inspectRealDirectory(
    temporaryParent,
    "OUTPUT_PUBLICATION",
    "race-parent-invalid",
  );
  const matrixPath = path.resolve(await mkdtemp(path.join(
    parent.path,
    ".izrace-",
  )));
  const matrixRoot = await inspectRealDirectory(
    matrixPath,
    "OUTPUT_PUBLICATION",
    "race-root-invalid",
  );
  const signatures = new Map();
  let completedCount = 0;
  let cleanupUncertaintyCount = 0;
  try {
    for (let caseIndex = 0; caseIndex < PUBLICATION_RACE_CASES.length; caseIndex += 1) {
      const raceCase = PUBLICATION_RACE_CASES[caseIndex];
      for (let repetition = 0; repetition < repetitions; repetition += 1) {
        const caseRoot = await createPrivateDirectory(
          matrixRoot,
          "case-" + String(caseIndex).padStart(2, "0")
            + "-" + String(repetition).padStart(2, "0"),
        );
        const outputParent = await createPrivateDirectory(
          caseRoot,
          "output-parent",
        );
        const privateRoot = await createPrivateDirectory(caseRoot, "private");
        const staging = await createPrivateDirectory(
          privateRoot,
          "success-staging",
        );
        const entries = [];
        for (const name of SUCCESS_OUTPUT_NAMES.slice(0, -1)) {
          entries.push(await writeStagingFile(
            staging,
            name,
            Buffer.from("race-" + name + "\n", "ascii"),
          ));
        }
        const sentinelPath = path.join(caseRoot.path, "unrelated.sentinel");
        const sentinelBytes = Buffer.from("unrelated\n", "ascii");
        await writeFile(sentinelPath, sentinelBytes, {
          flag: "wx",
          mode: 0o600,
        });
        const target = await validateOutputTarget(
          path.join(outputParent.path, "bundle"),
          path.join(matrixRoot.path, "synthetic-repository"),
        );
        let racePerformed = false;
        const hook = {
          async publicationCheckpoint(details) {
            const { checkpoint } = details;
            const firstName = entries[0].name;
            const supportName = entries[4].name;
            if (
              raceCase === "final-directory-precreation"
              && checkpoint === "before-final-directory"
            ) {
              await mkdir(details.finalDirectory, {
                recursive: false,
                mode: 0o700,
              });
              racePerformed = true;
            } else if (
              raceCase === "fixed-file-precreation"
              && checkpoint === "after-final-directory"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "entry-plan.json"),
                Buffer.from("attacker\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "artifact-target-race"
              && checkpoint === "before-adopt-artifact.zip"
            ) {
              await writeFile(details.targetPath, Buffer.from("race\n", "ascii"), {
                flag: "wx",
                mode: 0o600,
              });
              racePerformed = true;
            } else if (
              raceCase === "supporting-document-target-race"
              && checkpoint === "before-adopt-" + supportName
            ) {
              await writeFile(details.targetPath, Buffer.from("race\n", "ascii"), {
                flag: "wx",
                mode: 0o600,
              });
              racePerformed = true;
            } else if (
              raceCase === "marker-precreation"
              && checkpoint === "before-marker"
            ) {
              await writeFile(
                path.join(details.finalDirectory, ".complete"),
                Buffer.from("attacker\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "private-staging-replacement"
              && checkpoint === "before-final-directory"
            ) {
              await rename(
                details.stagingDirectory,
                details.stagingDirectory + ".replaced",
              );
              await mkdir(details.stagingDirectory, {
                recursive: false,
                mode: 0o700,
              });
              racePerformed = true;
            } else if (
              raceCase === "final-object-replacement"
              && checkpoint === "before-marker"
            ) {
              const finalPath = path.join(details.finalDirectory, firstName);
              await unlink(finalPath);
              await writeFile(finalPath, Buffer.from("replacement\n", "ascii"), {
                flag: "wx",
                mode: 0o600,
              });
              racePerformed = true;
            } else if (
              raceCase === "parent-replacement"
              && checkpoint === "before-final-directory"
            ) {
              await rename(outputParent.path, outputParent.path + ".replaced");
              await mkdir(outputParent.path, { recursive: false, mode: 0o700 });
              racePerformed = true;
            } else if (
              raceCase === "reparse-insertion"
              && checkpoint === "after-final-directory"
            ) {
              await symlink(
                details.finalDirectory,
                path.join(details.finalDirectory, firstName),
                process.platform === "win32" ? "junction" : "dir",
              );
              racePerformed = true;
            } else if (
              raceCase === "hard-link-count-anomaly"
              && checkpoint === "before-marker"
            ) {
              await link(entries[0].path, path.join(caseRoot.path, "extra-link"));
              racePerformed = true;
            } else if (
              raceCase === "entry-set-injection"
              && checkpoint === "before-marker"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "unexpected"),
                Buffer.from("injected\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "adoption-failure"
              && checkpoint === "before-adopt-" + firstName
            ) {
              racePerformed = true;
              fail("OUTPUT_PUBLICATION", "adoption-failure");
            } else if (
              raceCase === "post-marker-substitution"
              && checkpoint === "after-marker"
            ) {
              await unlink(details.markerPath);
              await writeFile(
                details.markerPath,
                Buffer.from("substituted\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            } else if (
              raceCase === "cleanup-identity-uncertainty"
              && checkpoint === "before-staging-cleanup"
            ) {
              await writeFile(
                path.join(details.finalDirectory, "cleanup-unexpected"),
                Buffer.from("uncertain\n", "ascii"),
                { flag: "wx", mode: 0o600 },
              );
              racePerformed = true;
            }
          },
        };
        let publication = null;
        let observed = null;
        try {
          publication = await publishBundle({
            target,
            staging,
            entries: Object.freeze(entries),
            mode: "success",
            testHook: hook,
          });
          fail("OUTPUT_PUBLICATION", "race-false-success");
        } catch (error) {
          publication = error?.publication ?? publication;
          observed = asZipReproducibilityError(
            error,
            "OUTPUT_PUBLICATION",
            "race-detected",
          );
        }
        if (!racePerformed || !observed || publication?.mode === "canonical-post-lock-failure") {
          fail("OUTPUT_PUBLICATION", "race-accounting-invalid");
        }
        const signature = observed.phase + ":" + observed.reason;
        if (signatures.has(raceCase) && signatures.get(raceCase) !== signature) {
          fail("OUTPUT_PUBLICATION", "race-alternating-outcome");
        }
        signatures.set(raceCase, signature);
        let cleanupUncertain = false;
        try {
          await cleanupFailedPublication(publication);
        } catch (error) {
          const safe = asZipReproducibilityError(
            error,
            "CLEANUP",
            "cleanup-identity-uncertain",
          );
          if (safe.phase !== "CLEANUP") throw safe;
          cleanupUncertain = true;
          cleanupUncertaintyCount += 1;
        }
        try {
          await cleanupPrivateRoot(privateRoot);
        } catch (error) {
          const safe = asZipReproducibilityError(
            error,
            "CLEANUP",
            "cleanup-identity-uncertain",
          );
          if (safe.phase !== "CLEANUP") throw safe;
          cleanupUncertain = true;
          cleanupUncertaintyCount += 1;
        }
        if (
          !(await readFile(sentinelPath)).equals(sentinelBytes)
          || (publication?.mode !== undefined && publication.mode !== "success")
          || (raceCase === "cleanup-identity-uncertainty" && !cleanupUncertain)
        ) fail("OUTPUT_PUBLICATION", "race-safety-invariant");
        completedCount += 1;
        await cleanupPrivateRoot(caseRoot);
      }
    }
  } finally {
    await cleanupPrivateRoot(matrixRoot);
  }
  if (
    completedCount !== PUBLICATION_RACE_CASES.length * repetitions
    || signatures.size !== PUBLICATION_RACE_CASES.length
  ) fail("OUTPUT_PUBLICATION", "race-accounting-invalid");
  return Object.freeze({
    status: "ok",
    mode: "publication-race-matrix",
    caseCount: PUBLICATION_RACE_CASES.length,
    repetitionCount: repetitions,
    completedCount,
    alternatingOutcomeCount: 0,
    staleSuccessFileCount: 0,
    modeConversionCount: 0,
    falseMarkerCount: 0,
    trustedUnexpectedEntryCount: 0,
    unrelatedDeletionCount: 0,
    cleanupUncertaintyCount,
  });
}

function buildSemanticReportBytes({
  policy,
  inputSet,
  candidate,
}) {
  try {
    return encodeCanonicalSemanticReport({
      semanticReportKind: REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
      schemaVersion: SCHEMA_VERSION,
      artifactRole: ARTIFACT_ROLE,
      formatProfile: FORMAT_PROFILE,
      sourceCommit: policy.sourceCommit,
      toolingCommit: policy.toolingCommit,
      inputSetSha256: inputSet.sha256,
      artifactSha256: candidate.artifactSha256,
      artifactByteLength: candidate.artifactByteLength,
      canonicalVerifierPassed: true,
      sameProcessRepeatable: true,
      sameHostRepeatable: true,
      boundaryVectorSetPassed: true,
      result: "pass",
      failureCode: null,
    });
  } catch {
    fail("SEMANTIC_REPORT", "semantic-report-invalid");
  }
}

function buildEvidenceBytes({
  policy,
  policySha256,
  cell,
  result,
  artifactSha256 = null,
  artifactByteLength = null,
  semanticReportSha256 = null,
  semanticReportByteLength = null,
  failureClass = null,
  failureCode = null,
}) {
  try {
    return encodeCanonicalReproducibilityEvidence({
      evidenceKind: REPRODUCIBILITY_EVIDENCE_KIND,
      schemaVersion: SCHEMA_VERSION,
      artifactRole: policy.artifactRole,
      formatProfile: policy.formatProfile,
      sourceCommit: policy.sourceCommit,
      toolingCommit: policy.toolingCommit,
      criticalToolSetSha256: policy.criticalToolSetSha256,
      manifestSha256: policy.manifestSha256,
      inputSetSha256: policy.inputSetSha256,
      runtimeProfileId: cell.runtimeProfileId,
      runtimeIdentitySha256: cell.runtimeIdentitySha256,
      gitProfileId: cell.gitProfileId,
      gitIdentitySha256: cell.gitIdentitySha256,
      runnerPolicySha256: policySha256,
      testVectorSetSha256: policy.testVectorSetSha256,
      matrixCellId: cell.matrixCellId,
      operatingSystem: cell.operatingSystem,
      operatingSystemBuild: cell.operatingSystemBuild,
      architecture: cell.architecture,
      filesystemProfile: cell.filesystemProfile,
      localeProfile: cell.localeProfile,
      timezoneProfile: cell.timezoneProfile,
      platformProbeSha256: cell.platformProbeSha256,
      artifactSha256,
      artifactByteLength,
      semanticReportSha256,
      semanticReportByteLength,
      result,
      failureClass,
      failureCode,
    });
  } catch {
    fail("EVIDENCE", "evidence-invalid");
  }
}

function failureClassFor(error) {
  if (
    error.phase === "RUNTIME_IDENTITY"
    || error.phase === "GIT_IDENTITY"
  ) return "runtime-profile-change";
  if (error.phase === "PLATFORM_PROBE") return "unsupported-platform";
  if (error.phase === "CLEANUP") return "test-infrastructure-failure";
  return "implementation-defect";
}

function requireR1Verification(result, expectedResult) {
  if (
    !result
    || typeof result !== "object"
    || result.status !== "ok"
    || result.mode !== "reproducibility-evidence-verification"
    || result.evidenceResult !== expectedResult
    || result.semanticClaimsIndependentlyReplayed !== false
    || result.platformAttestationVerified !== false
    || result.evidenceSigningRequired !== true
    || result.projectPublicationAuthorized !== false
  ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
  if (expectedResult === "pass") {
    if (
      result.comparisonEligible !== true
      || result.semanticClaimsBound !== true
      || result.canonicalVerifierPassed !== true
      || result.sameProcessRepeatable !== true
      || result.sameHostRepeatable !== true
      || result.boundaryVectorSetPassed !== true
    ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
  } else if (
    result.comparisonEligible !== false
    || result.semanticClaimsBound !== false
    || result.canonicalVerifierPassed !== null
    || result.sameProcessRepeatable !== null
    || result.sameHostRepeatable !== null
    || result.boundaryVectorSetPassed !== null
  ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
}

async function stageVerifierAuthority({
  privateRoot,
  name,
  criticalTools,
  inputSet,
  platformProbe,
  semanticBytes = null,
  evidenceBytes,
}) {
  const directory = await createPrivateDirectory(privateRoot, name);
  const files = {
    criticalToolSet: await writeStagingFile(
      directory,
      "critical-tool-set.json",
      criticalTools.bytes,
    ),
    inputSet: await writeStagingFile(directory, "input-set.json", inputSet.bytes),
    platformProbe: await writeStagingFile(
      directory,
      "platform-probe.json",
      platformProbe.bytes,
    ),
  };
  if (semanticBytes !== null) {
    files.semantic = await writeStagingFile(
      directory,
      "semantic-report.json",
      semanticBytes,
    );
  }
  files.evidence = await writeStagingFile(
    directory,
    "evidence.json",
    evidenceBytes,
  );
  return Object.freeze({ directory, files: Object.freeze(files) });
}

function verifierOptions(context, staged, additions = {}) {
  return {
    evidence: staged.files.evidence.path,
    policy: context.options.runnerPolicy,
    sourceRepo: context.options.repository,
    toolingRepo: context.options.repository,
    criticalToolSet: staged.files.criticalToolSet.path,
    manifest: context.options.manifest,
    inputSet: staged.files.inputSet.path,
    runtimeIdentity: context.options.runtimeIdentity,
    gitIdentity: context.options.gitIdentity,
    testVectorSet: VECTOR_SET_PATH,
    platformProbe: staged.files.platformProbe.path,
    ...additions,
  };
}

async function buildSuccessEvidence(context, candidate) {
  const semanticBytes = buildSemanticReportBytes({
    policy: context.policy.value,
    inputSet: context.inputSet,
    candidate,
  });
  const evidenceBytes = buildEvidenceBytes({
    policy: context.policy.value,
    policySha256: context.policy.sha256,
    cell: context.cell,
    result: "pass",
    artifactSha256: candidate.artifactSha256,
    artifactByteLength: candidate.artifactByteLength,
    semanticReportSha256: sha256Bytes(semanticBytes),
    semanticReportByteLength: semanticBytes.length,
  });
  const staged = await stageVerifierAuthority({
    privateRoot: context.privateRoot,
    name: "success-verifier",
    criticalTools: context.criticalTools,
    inputSet: context.inputSet,
    platformProbe: context.platformProbe,
    semanticBytes,
    evidenceBytes,
  });
  let verification;
  try {
    verification = await verifyReproducibilityEvidence(verifierOptions(
      context,
      staged,
      {
        artifact: candidate.artifactPath,
        semanticReport: staged.files.semantic.path,
      },
    ));
  } catch {
    fail("R1_10A_VERIFICATION", "r1-10a-verification-failed");
  }
  requireR1Verification(verification, "pass");
  return Object.freeze({
    semanticBytes,
    evidenceBytes,
    verification,
    verificationBytes: encodeCanonicalVerificationResult(verification),
  });
}

async function buildFailureEvidence(context, failure) {
  const evidenceBytes = buildEvidenceBytes({
    policy: context.policy.value,
    policySha256: context.policy.sha256,
    cell: context.cell,
    result: "fail",
    failureClass: failureClassFor(failure),
    failureCode: failure.reason,
  });
  const staged = await stageVerifierAuthority({
    privateRoot: context.privateRoot,
    name: "failure-verifier",
    criticalTools: context.criticalTools,
    inputSet: context.inputSet,
    platformProbe: context.platformProbe,
    evidenceBytes,
  });
  let verification;
  try {
    verification = await verifyReproducibilityEvidence(
      verifierOptions(context, staged),
    );
  } catch {
    fail("R1_10A_VERIFICATION", "r1-10a-failure-verification");
  }
  requireR1Verification(verification, "fail");
  return Object.freeze({
    evidenceBytes,
    verification,
    verificationBytes: encodeCanonicalVerificationResult(verification),
  });
}

function buildPublicResult({
  context,
  runResult,
  candidate = null,
  semanticBytes = null,
  evidenceBytes,
  verificationBytes,
  failureClass = null,
  failureCode = null,
}) {
  const passing = runResult === "pass";
  const value = {
    status: passing ? "ok" : "failed",
    mode: ADAPTER_MODE,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    mediaType: MEDIA_TYPE,
    archiveRoot: ARCHIVE_ROOT,
    authoritativeCorrespondingSource: AUTHORITATIVE_CORRESPONDING_SOURCE,
    sourceCommit: context.policy.value.sourceCommit,
    toolingCommit: context.policy.value.toolingCommit,
    membershipCount: context.sourceAuthority.membership.members.length,
    artifactSha256: passing ? candidate.artifactSha256 : null,
    artifactByteLength: passing ? candidate.artifactByteLength : null,
    entryPlanSha256: passing ? candidate.entryPlanSha256 : null,
    semanticReportSha256: passing ? sha256Bytes(semanticBytes) : null,
    evidenceSha256: sha256Bytes(evidenceBytes),
    verificationResultSha256: sha256Bytes(verificationBytes),
    canonicalVerifierPassed: passing ? true : null,
    sameProcessRepeatable: passing ? true : null,
    sameHostRepeatable: passing ? true : null,
    boundaryVectorSetPassed: passing ? true : null,
    comparisonEligible: passing,
    semanticClaimsIndependentlyReplayed: false,
    platformAttestationVerified: false,
    evidenceSigningRequired: true,
    projectPublicationAuthorized: false,
    runResult,
    failureClass,
    failureCode,
  };
  if (!exactKeys(value, PUBLIC_RESULT_KEYS)) fail("PRIVACY", "public-result-shape");
  canonicalPublicJsonBytes(value, "PRIVACY");
  return deepFreezeZipReproducibility(value);
}

function requirePolicyBindings({
  policy,
  sourceCommit,
  criticalTools,
  sourceAuthority,
  runtimeIdentity,
  gitIdentity,
  vectorAuthority,
  cell,
}) {
  if (
    policy.value.sourceCommit !== sourceCommit
    || policy.value.criticalToolSetSha256 !== criticalTools.sha256
    || policy.value.manifestSha256 !== sourceAuthority.manifest.sha256
    || policy.value.testVectorSetSha256 !== vectorAuthority.sha256
    || cell.runtimeIdentitySha256 !== runtimeIdentity.sha256
    || cell.gitIdentitySha256 !== gitIdentity.sha256
  ) fail("POLICY_BINDING", "document-hash-mismatch");
}

function requireFourOutputAgreement(sameProcess, sameHost) {
  const local = sameProcess.outputs;
  const workers = sameHost.outputs;
  if (local.length !== 2 || workers.length !== 2) {
    fail("SAME_HOST", "four-output-mismatch");
  }
  const artifactSha256 = local[0].artifactSha256;
  const planSha256 = local[0].entryPlanSha256;
  const transcriptSha256 = local[0].transcriptSha256;
  if (
    !local.every((entry) => (
      entry.artifactSha256 === artifactSha256
      && entry.entryPlanSha256 === planSha256
      && entry.transcriptSha256 === transcriptSha256
    ))
    || !workers.every((entry) => (
      entry.response.artifactSha256 === artifactSha256
      && entry.response.entryPlanSha256 === planSha256
      && entry.response.transcriptSha256 === transcriptSha256
    ))
  ) fail("SAME_HOST", "four-output-mismatch");
  const identities = [
    ...local.map((entry) => entry.artifactIdentity),
    ...workers.map((entry) => entry.artifact.identity),
  ];
  for (let left = 0; left < identities.length; left += 1) {
    for (let right = left + 1; right < identities.length; right += 1) {
      if (sameObject(identities[left], identities[right])) {
        fail("SAME_HOST", "four-output-identity-mismatch");
      }
    }
  }
}

export async function preparePublicSourceZipReproducibility(options) {
  assertProxyFreeAuthorityGraph(options, COORDINATOR_AUTHORITY_OPTIONS);
  const normalized = normalizeOptions(options);
  let target = null;
  let privateRoot = null;
  let publication = null;
  let context = null;
  let trustLocked = false;
  let modeDecision = null;
  try {
    const policy = await loadPolicy(normalized.runnerPolicy);
    const runtimeIdentity = await loadCanonicalPublicDocument(
      normalized.runtimeIdentity,
      "RUNTIME_IDENTITY",
      "runtime-identity",
    );
    const gitIdentity = await loadCanonicalPublicDocument(
      normalized.gitIdentity,
      "GIT_IDENTITY",
      "git-identity",
    );
    await validateRuntimeIdentity(runtimeIdentity);
    const git = await resolveGitExecutable();
    validateGitIdentity(gitIdentity, git);
    const cell = selectPolicyCell(
      policy.value,
      runtimeIdentity.sha256,
      gitIdentity.sha256,
    );
    if (
      runtimeIdentity.value.runtimeProfileId !== cell.runtimeProfileId
      || gitIdentity.value.gitProfileId !== cell.gitProfileId
    ) fail("POLICY_BINDING", "identity-profile-mismatch");
    await validateRepository(
      normalized.repository,
      normalized.sourceCommit,
      policy.value.toolingCommit,
      git,
    );
    const criticalTools = await validateCriticalTools(
      normalized.repository,
      policy.value.toolingCommit,
      git,
    );
    const sourceAuthority = await validateSourceAuthority(
      normalized,
      policy.value,
      git,
    );
    const vectorAuthority = await validatePublicSourceZipBoundaryVectorSet({
      testVectorSet: VECTOR_SET_PATH,
      expectedSha256: policy.value.testVectorSetSha256,
    });
    requirePolicyBindings({
      policy,
      sourceCommit: normalized.sourceCommit,
      criticalTools,
      sourceAuthority,
      runtimeIdentity,
      gitIdentity,
      vectorAuthority,
      cell,
    });
    target = await validateOutputTarget(
      normalized.outputDirectory,
      normalized.repository,
    );
    privateRoot = await createPrivateRoot(target);
    const measuredCapabilities = await measureHostCapabilities(privateRoot);
    const platformProbe = buildPlatformProbe(
      cell,
      runtimeIdentity.sha256,
      gitIdentity.sha256,
      measuredCapabilities,
    );
    if (platformProbe.sha256 !== cell.platformProbeSha256) {
      fail("POLICY_BINDING", "platform-probe-sha256");
    }

    const sameProcess = await runSameProcessCell({
      repository: normalized.repository,
      sourceCommit: normalized.sourceCommit,
      sourceAuthority,
      privateRoot,
      ownershipLedger: privateOwnershipAdapter(privateRoot),
    });
    await invokeCheckpoint(normalized.testHook, "after-same-process");
    const inputSet = buildInputSet({
      policy: policy.value,
      sourceAuthority,
      sameProcess,
      criticalTools,
      runtimeIdentity,
      gitIdentity,
      runnerPolicyIdentitySha256: deriveRunnerPolicyIdentitySha256(
        policy.value,
      ),
      vectorSha256: vectorAuthority.sha256,
    });
    if (inputSet.sha256 !== policy.value.inputSetSha256) {
      fail("POLICY_BINDING", "input-set-sha256");
    }
    const capsule = await createTrustedZipWorkerModuleCapsule({
      privateRoot: privateRoot.path,
      toolingCommit: policy.value.toolingCommit,
      modules: criticalTools.workerModules,
      ownershipLedger: privateOwnershipAdapter(privateRoot),
    });
    context = Object.freeze({
      options: normalized,
      policy,
      cell,
      git,
      runtimeIdentity,
      gitIdentity,
      criticalTools,
      sourceAuthority,
      vectorAuthority,
      platformProbe,
      sameProcess,
      inputSet,
      capsule,
      privateRoot,
    });
    trustLocked = true;

    const sameHostRoot = await createPrivateDirectory(privateRoot, "same-host");
    const workerContext = {
      toolingCommit: policy.value.toolingCommit,
      manifestSha256: sourceAuthority.manifest.sha256,
      membershipReportSha256: sourceAuthority.membershipReportSha256,
      criticalToolSetSha256: criticalTools.sha256,
      runtimeIdentitySha256: runtimeIdentity.sha256,
      gitIdentitySha256: gitIdentity.sha256,
      runnerPolicySha256: policy.sha256,
      testVectorSetSha256: vectorAuthority.sha256,
      artifactRole: ARTIFACT_ROLE,
      formatProfile: FORMAT_PROFILE,
    };
    const sameHostStartedAt = process.hrtime.bigint();
    const sameHost = await runSameHostZipCandidates({
      repository: normalized.repository,
      sourceCommit: normalized.sourceCommit,
      privateRoot: sameHostRoot.path,
      context: workerContext,
      capsule,
      protocolControl: normalized.testHook?.workerProtocolControl ?? null,
      ownershipLedger: privateOwnershipAdapter(privateRoot),
    });
    const sameHostDurationMilliseconds = Number(
      process.hrtime.bigint() - sameHostStartedAt,
    ) / 1_000_000;
    requireFourOutputAgreement(sameProcess, sameHost);
    await invokeCheckpoint(normalized.testHook, "after-same-host", {
      sameHostDurationMilliseconds,
      workerDurationsMilliseconds: sameHost.outputs.map(
        (entry) => entry.observation.durationMilliseconds,
      ),
    });

    const vectorOptions = {
      testVectorSet: VECTOR_SET_PATH,
      temporaryParent: privateRoot.path,
      expectedSha256: vectorAuthority.sha256,
      ownershipLedger: privateOwnershipAdapter(privateRoot),
    };
    if (normalized.testHook?.boundaryFailVectorId !== undefined) {
      Object.defineProperty(vectorOptions, VECTOR_TEST_HOOK, {
        value: Object.freeze({
          failVectorId: normalized.testHook.boundaryFailVectorId,
        }),
        enumerable: false,
      });
    }
    const boundaryResult = await runPublicSourceZipBoundaryVectors(
      vectorOptions,
    );
    validateBoundaryVectorResult(boundaryResult, vectorAuthority.sha256);
    await invokeCheckpoint(normalized.testHook, "after-boundary-vectors");

    const candidate = sameProcess.outputs[0];
    const successEvidence = await buildSuccessEvidence(context, candidate);
    const successResult = buildPublicResult({
      context,
      runResult: "pass",
      candidate,
      semanticBytes: successEvidence.semanticBytes,
      evidenceBytes: successEvidence.evidenceBytes,
      verificationBytes: successEvidence.verificationBytes,
    });
    modeDecision = selectPublicationMode("success");
    const staged = await stageSuccessBundle({
      privateRoot,
      candidate,
      inputSet,
      semanticBytes: successEvidence.semanticBytes,
      evidenceBytes: successEvidence.evidenceBytes,
      verificationBytes: successEvidence.verificationBytes,
    });
    try {
      publication = await publishBundle({
        target,
        privateRoot,
        staging: staged.staging,
        entries: staged.entries,
        mode: modeDecision.mode,
        testHook: normalized.testHook,
      });
    } catch (error) {
      publication = error?.publication ?? publication;
      throw error;
    }
    privateRoot = null;
    return successResult;
  } catch (error) {
    const safe = asZipReproducibilityError(error, "CLI", "adapter-failed");
    if (!publication && error?.publication) publication = error.publication;
    const loadedByteFailure = safe.phase === "TOOL_SET"
      && safe.reason === "worker-loaded-bytes-mismatch";
    const publicationFailure = safe.phase === "OUTPUT_PUBLICATION"
      || safe.phase === "CLEANUP"
      || publication !== null;
    if (
      !trustLocked
      || !context
      || !privateRoot
      || loadedByteFailure
      || publicationFailure
      || modeDecision !== null
    ) {
      let cleanupFailure = null;
      try { await cleanupFailedPublication(publication); } catch (cleanupError) {
        cleanupFailure = cleanupError;
      }
      try { await cleanupPrivateRoot(privateRoot); } catch (cleanupError) {
        cleanupFailure ??= cleanupError;
      }
      if (cleanupFailure) {
        throw new PublicSourceZipReproducibilityError(
          "CLEANUP",
          "cleanup-identity-uncertain",
        );
      }
      throw safe;
    }

    try {
      const failureEvidence = await buildFailureEvidence(context, safe);
      const failureResult = buildPublicResult({
        context,
        runResult: "fail",
        evidenceBytes: failureEvidence.evidenceBytes,
        verificationBytes: failureEvidence.verificationBytes,
        failureClass: failureClassFor(safe),
        failureCode: safe.reason,
      });
      modeDecision = selectPublicationMode("canonical-post-lock-failure");
      const staged = await stageFailureBundle({
        privateRoot,
        inputSet: context.inputSet,
        evidenceBytes: failureEvidence.evidenceBytes,
        verificationBytes: failureEvidence.verificationBytes,
      });
      try {
        publication = await publishBundle({
          target,
          privateRoot,
          staging: staged.staging,
          entries: staged.entries,
          mode: modeDecision.mode,
          testHook: normalized.testHook,
        });
      } catch (publicationError) {
        publication = publicationError?.publication ?? publication;
        throw publicationError;
      }
      privateRoot = null;
      return failureResult;
    } catch (publicationError) {
      let cleanupFailure = null;
      try { await cleanupFailedPublication(publication); } catch (cleanupError) {
        cleanupFailure = cleanupError;
      }
      try { await cleanupPrivateRoot(privateRoot); } catch (cleanupError) {
        cleanupFailure ??= cleanupError;
      }
      if (cleanupFailure) {
        throw new PublicSourceZipReproducibilityError(
          "CLEANUP",
          "cleanup-identity-uncertain",
        );
      }
      throw asZipReproducibilityError(
        publicationError,
        "OUTPUT_PUBLICATION",
        "failure-bundle-publication",
      );
    }
  }
}

function parseOptions(argv) {
  const mapping = new Map([
    ["--repository", "repository"],
    ["--source-commit", "sourceCommit"],
    ["--manifest", "manifest"],
    ["--membership-report", "membershipReport"],
    ["--runner-policy", "runnerPolicy"],
    ["--runtime-identity", "runtimeIdentity"],
    ["--git-identity", "gitIdentity"],
    ["--output-directory", "outputDirectory"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(result, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) fail("CLI", "unknown-or-duplicate-option");
    result[key] = argv[index + 1];
    index += 1;
  }
  if (OPTION_KEYS.some((key) => !Object.hasOwn(result, key))) {
    fail("CLI", "required-options");
  }
  return Object.freeze({
    repository: path.resolve(result.repository),
    sourceCommit: result.sourceCommit,
    manifest: path.resolve(result.manifest),
    membershipReport: path.resolve(result.membershipReport),
    runnerPolicy: path.resolve(result.runnerPolicy),
    runtimeIdentity: path.resolve(result.runtimeIdentity),
    gitIdentity: path.resolve(result.gitIdentity),
    outputDirectory: path.resolve(result.outputDirectory),
  });
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
  const result = await preparePublicSourceZipReproducibility(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
  if (result.runResult !== "pass") process.exitCode = 2;
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = asZipReproducibilityError(
      error,
      "CLI",
      "unexpected-cli-failure",
    );
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
