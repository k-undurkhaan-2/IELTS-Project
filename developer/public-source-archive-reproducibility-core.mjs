import { createHash, randomBytes } from "node:crypto";
import { fork, spawnSync } from "node:child_process";
import { constants as FS_CONSTANTS, realpathSync, writeSync } from "node:fs";
import {
  access,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  identityFromState,
  identitiesEqual,
  isInside,
  noFollowFlag,
  pathState,
  pathsEqual,
  validateParentChain,
} from "./public-source-archive-core.mjs";
import { preparePublicSourceArchive } from "./prepare-public-source-archive.mjs";
import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  REPRODUCIBILITY_EVIDENCE_KIND,
  REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
  SCHEMA_VERSION,
  encodeCanonicalReproducibilityEvidence,
  encodeCanonicalSemanticReport,
  parseCanonicalMatrixPolicy,
  parseCanonicalOpaqueJsonBytes,
  readStableCanonicalDocument,
  readStableFile,
  sha256Bytes,
} from "./reproducibility-evidence-core.mjs";

export const ADAPTER_MODE = "public-source-archive-reproducibility";
export const ARTIFACT_ROLE = "public-source-archive";
export const FORMAT_PROFILE = "tar-ustar-v1";
export const INPUT_SET_KIND = "ieltmps-public-source-archive-input-set";
export const INPUT_SET_PROFILE = "git-sha1-b1-membership-v1";
export const CRITICAL_TOOL_SET_KIND =
  "ieltmps-reproducibility-critical-tool-set";
export const CRITICAL_TOOL_SET_ID =
  "public-source-archive-reproducibility-v1";
export const RUNTIME_IDENTITY_KIND = "ieltmps-node-runtime-identity";
export const GIT_IDENTITY_KIND = "ieltmps-git-runtime-identity";
export const PLATFORM_PROBE_KIND = "ieltmps-platform-probe";
export const COMPLETION_MARKER =
  "ieltmps-public-source-archive-reproducibility-complete-v1\n";

export const CRITICAL_TOOL_PATHS = Object.freeze([
  "developer/verify-public-source-membership.mjs",
  "developer/public-source-archive-core.mjs",
  "developer/prepare-public-source-archive.mjs",
  "developer/verify-public-source-archive.mjs",
  "developer/reproducibility-evidence-core.mjs",
  "developer/verify-reproducibility-evidence.mjs",
  "developer/public-source-archive-reproducibility-core.mjs",
  "developer/prepare-public-source-archive-reproducibility.mjs",
  "developer/run-public-source-archive-boundary-vectors.mjs",
]);

export const ADAPTER_PHASES = Object.freeze([
  "CLI",
  "POLICY_BINDING",
  "SOURCE_BINDING",
  "TOOLING_BINDING",
  "RUNTIME_BINDING",
  "GIT_BINDING",
  "PLATFORM_PROBE",
  "BOUNDARY_VECTOR",
  "SAME_PROCESS",
  "SAME_HOST",
  "ARCHIVE_VERIFICATION",
  "SEMANTIC_REPORT",
  "EVIDENCE",
  "R1_10A_VERIFICATION",
  "OUTPUT_PUBLICATION",
  "CLEANUP",
]);

const ADAPTER_PHASE_SET = new Set(ADAPTER_PHASES);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const IDENTIFIER_PATTERN =
  /^[a-z0-9](?:[a-z0-9._+-]{0,126}[a-z0-9])?$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const WORKER_PROTOCOL = "ieltmps-public-source-archive-worker-v2";
const WORKER_LEASE_PROTOCOL =
  "ieltmps-public-source-archive-worker-lease-v1";
const WORKER_CLAIM_PROTOCOL =
  "ieltmps-public-source-archive-worker-claim-v1";
const LEGACY_WORKER_TOKEN_ENV = "IELTMPS_REPRODUCIBILITY_WORKER_TOKEN";
const WORKER_LEASE_BASENAME = ".worker-lease.json";
const WORKER_CLAIM_BASENAME = ".worker-claim.json";
const WORKER_ARCHIVE_BASENAME = "artifact.tar";
const MAX_WORKER_REQUEST_BYTES = 16 * 1024;
const MAX_WORKER_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_WORKER_LEASE_BYTES = 64 * 1024;
const FILE_CHUNK_SIZE = 64 * 1024;
const MAX_GIT_BUFFER = 128 * 1024 * 1024;

const INPUT_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "sourceRepositoryProfileId",
  "sourceCommit",
  "sourceManifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "members",
]);
const INPUT_MEMBER_KEYS = Object.freeze([
  "pathUtf8Hex",
  "gitMode",
  "gitBlobObjectId",
  "declaredByteSize",
  "contentSha256",
  "role",
  "licenseScope",
]);
const TOOL_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "toolSetId",
  "toolingCommit",
  "entries",
]);
const TOOL_ENTRY_KEYS = Object.freeze([
  "path",
  "gitMode",
  "gitBlobObjectId",
  "declaredByteSize",
  "sha256",
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
const B3_TRANSCRIPT_KEYS = Object.freeze([
  "sourceCommit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archiveSha256",
  "archiveByteLength",
  "archiveMemberCount",
  "archiveFormat",
  "membershipValid",
  "archiveVerified",
  "correspondingSourceComplete",
  "publicationBlocked",
]);
const PRIVATE_IDENTITY_KEYS = Object.freeze([
  "device",
  "inode",
  "meaningful",
]);
const WORKER_REPOSITORY_BINDING_KEYS = Object.freeze([
  "pathSha256",
  "identity",
]);
const WORKER_CONTEXT_KEYS = Object.freeze([
  "sourceRepository",
  "toolingRepository",
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
  "gitExecutableSha256",
  "gitExecutableByteLength",
]);
const WORKER_ASSIGNMENT_KEYS = Object.freeze([
  "assignmentId",
  "assignmentNonce",
  "directoryPathSha256",
  "directoryParentIdentity",
  "directoryIdentity",
  "archiveFilename",
  "lockedContextDigest",
  "state",
]);
const WORKER_LEASE_KEYS = Object.freeze([
  "protocol",
  "schemaVersion",
  "runId",
  "coordinatorPid",
  "coordinatorModuleRealpathSha256",
  "privateRootPathSha256",
  "privateRootIdentity",
  "privateRootParentIdentity",
  "lockedContext",
  "lockedContextDigest",
  "assignments",
]);
const WORKER_REQUEST_KEYS = Object.freeze([
  "protocol",
  "leaseReference",
  "assignmentId",
  "assignmentNonce",
  "sourceRepositoryPath",
  "toolingRepositoryPath",
  "lockedContext",
]);
const WORKER_RESPONSE_KEYS = Object.freeze([
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
]);

const MODULE_PATHS = Object.freeze(new Map([
  [CRITICAL_TOOL_PATHS[0], fileURLToPath(new URL(
    "./verify-public-source-membership.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[1], fileURLToPath(new URL(
    "./public-source-archive-core.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[2], fileURLToPath(new URL(
    "./prepare-public-source-archive.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[3], fileURLToPath(new URL(
    "./verify-public-source-archive.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[4], fileURLToPath(new URL(
    "./reproducibility-evidence-core.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[5], fileURLToPath(new URL(
    "./verify-reproducibility-evidence.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[6], fileURLToPath(import.meta.url)],
  [CRITICAL_TOOL_PATHS[7], fileURLToPath(new URL(
    "./prepare-public-source-archive-reproducibility.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[8], fileURLToPath(new URL(
    "./run-public-source-archive-boundary-vectors.mjs", import.meta.url,
  ))],
]));

export class PublicSourceArchiveReproducibilityError extends Error {
  constructor(phase, reason) {
    const safePhase = ADAPTER_PHASE_SET.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string"
      && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(reason)
      ? reason
      : "invalid-operation";
    super("public source archive reproducibility operation failed");
    this.name = "PublicSourceArchiveReproducibilityError";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failAdapter(phase, reason) {
  throw new PublicSourceArchiveReproducibilityError(phase, reason);
}

export function asAdapterError(error, phase, reason) {
  return error instanceof PublicSourceArchiveReproducibilityError
    ? error
    : new PublicSourceArchiveReproducibilityError(phase, reason);
}

export function deepFreezeAdapter(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreezeAdapter(entry);
    Object.freeze(value);
  }
  return value;
}

function exactKeys(value, keys, phase, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failAdapter(phase, reason);
  }
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) {
    failAdapter(phase, reason);
  }
}

function requireIdentifier(value, phase, reason) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireSha256(value, phase, reason) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireGitObject(value, phase, reason) {
  if (typeof value !== "string" || !GIT_OBJECT_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireLength(value, phase, reason) {
  if (!Number.isSafeInteger(value) || value < 0) failAdapter(phase, reason);
  return value;
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") failAdapter(phase, reason);
  return value;
}

export function canonicalAdapterJsonBytes(value, phase = "POLICY_BINDING") {
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failAdapter(phase, "canonical-document-encoding");
  }
  if (
    bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
  ) {
    failAdapter(phase, "canonical-document-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failAdapter(phase, "canonical-document-encoding");
    }
  }
  return bytes;
}

export async function readAdapterCanonicalDocument(
  filePath,
  phase,
  kind,
) {
  try {
    const input = await readStableCanonicalDocument(
      filePath,
      "FILE_IDENTITY",
      kind,
    );
    const value = parseCanonicalOpaqueJsonBytes(input.bytes, "FILE_IDENTITY");
    return Object.freeze({ ...input, value });
  } catch {
    failAdapter(phase, kind + "-invalid");
  }
}

export async function readAndParseMatrixPolicy(filePath) {
  try {
    const input = await readStableCanonicalDocument(
      filePath,
      "POLICY_SCHEMA",
      "policy",
    );
    return Object.freeze({
      ...input,
      value: parseCanonicalMatrixPolicy(input.bytes),
    });
  } catch {
    failAdapter("POLICY_BINDING", "policy-invalid");
  }
}

export function selectPolicyCell(policy, matrixCellId) {
  requireIdentifier(matrixCellId, "POLICY_BINDING", "matrix-cell-id");
  if (policy.artifactRole !== ARTIFACT_ROLE || policy.formatProfile !== FORMAT_PROFILE) {
    failAdapter("POLICY_BINDING", "artifact-profile-mismatch");
  }
  const required = policy.requiredCells.find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  const optional = policy.optionalCells.find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  if (!required && !optional) failAdapter("POLICY_BINDING", "matrix-cell-unknown");
  return required ?? optional;
}

export function buildCanonicalInputSet(membership) {
  try {
    if (
      !membership
      || typeof membership !== "object"
      || !Array.isArray(membership.members)
      || !membership.report
      || !Array.isArray(membership.report.members)
      || !Buffer.isBuffer(membership.reportBytes)
      || membership.report.members.length !== membership.members.length
      || membership.report.membershipCount !== membership.members.length
      || membership.report.sourceCommit !== membership.sourceCommit
    ) {
      failAdapter("SOURCE_BINDING", "membership-result-invalid");
    }
    const membershipReportSha256 = sha256Bytes(membership.reportBytes);
    const members = membership.members.map((member, index) => {
      const projected = membership.report.members[index];
      if (
        !member
        || !projected
        || projected.path !== member.path
        || projected.gitMode !== member.gitMode
        || projected.sha256 !== member.sha256
        || projected.role !== member.role
        || projected.licenseScope !== member.licenseScope
        || !Buffer.isBuffer(member.blobBytes)
        || member.blobBytes.length !== member.declaredByteSize
        || sha256Bytes(member.blobBytes) !== member.sha256
      ) {
        failAdapter("SOURCE_BINDING", "membership-result-invalid");
      }
      const value = {
        pathUtf8Hex: Buffer.from(member.path, "utf8").toString("hex"),
        gitMode: member.gitMode,
        gitBlobObjectId: member.objectId,
        declaredByteSize: member.declaredByteSize,
        contentSha256: member.sha256,
        role: member.role,
        licenseScope: member.licenseScope,
      };
      exactKeys(value, INPUT_MEMBER_KEYS, "SOURCE_BINDING", "input-member-shape");
      requireGitObject(value.gitBlobObjectId, "SOURCE_BINDING", "input-member-object");
      requireSha256(value.contentSha256, "SOURCE_BINDING", "input-member-hash");
      requireLength(value.declaredByteSize, "SOURCE_BINDING", "input-member-length");
      requireIdentifier(value.role, "SOURCE_BINDING", "input-member-role");
      requireIdentifier(value.licenseScope, "SOURCE_BINDING", "input-member-license");
      return Object.freeze(value);
    });
    const value = deepFreezeAdapter({
      documentKind: INPUT_SET_KIND,
      schemaVersion: 1,
      sourceRepositoryProfileId: INPUT_SET_PROFILE,
      sourceCommit: membership.sourceCommit,
      sourceManifestSha256: membership.manifestSha256,
      membershipReportSha256,
      membershipCount: members.length,
      members,
    });
    exactKeys(value, INPUT_SET_KEYS, "SOURCE_BINDING", "input-set-shape");
    requireGitObject(value.sourceCommit, "SOURCE_BINDING", "source-commit");
    requireSha256(value.sourceManifestSha256, "SOURCE_BINDING", "source-manifest-hash");
    requireSha256(value.membershipReportSha256, "SOURCE_BINDING", "membership-report-hash");
    const bytes = canonicalAdapterJsonBytes(value, "SOURCE_BINDING");
    return Object.freeze({
      value,
      bytes,
      sha256: sha256Bytes(bytes),
      membershipReportSha256,
    });
  } catch (error) {
    throw asAdapterError(error, "SOURCE_BINDING", "input-set-invalid");
  }
}

function canonicalOsName() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  failAdapter("PLATFORM_PROBE", "unsupported-operating-system");
}

function identityStrings(identity) {
  return Object.freeze({
    device: identity.device.toString(10),
    inode: identity.inode.toString(10),
    meaningful: identity.meaningful,
  });
}

function identityMatchesStrings(identity, strings) {
  return strings
    && identity.meaningful === strings.meaningful
    && identity.device.toString(10) === strings.device
    && identity.inode.toString(10) === strings.inode;
}

function requirePrivateIdentityStrings(value, reason) {
  exactKeys(value, PRIVATE_IDENTITY_KEYS, "SAME_HOST", reason);
  if (
    !DECIMAL_PATTERN.test(value.device)
    || !DECIMAL_PATTERN.test(value.inode)
    || value.meaningful !== true
  ) failAdapter("SAME_HOST", reason);
  return value;
}

function privateJsonBytes(value, reason) {
  try {
    return Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failAdapter("SAME_HOST", reason);
  }
}

function parseExactPrivateJsonText(text, maximumBytes, reason) {
  if (typeof text !== "string") failAdapter("SAME_HOST", reason);
  const bytes = Buffer.from(text, "utf8");
  if (
    bytes.length === 0
    || bytes.length > maximumBytes
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
  ) failAdapter("SAME_HOST", reason);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    failAdapter("SAME_HOST", reason);
  }
  if (!privateJsonBytes(value, reason).equals(bytes)) {
    failAdapter("SAME_HOST", reason);
  }
  return value;
}

function requireExactPrivatePath(value, reason) {
  if (
    typeof value !== "string"
    || value.length === 0
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || path.resolve(value) !== value
    || value.normalize("NFC") !== value
  ) failAdapter("SAME_HOST", reason);
  return value;
}

function privatePathSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-private-path-v1\0", "ascii"),
    Buffer.from(value, "utf8"),
  ]));
}

function lockedContextSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-worker-locked-context-v1\0", "ascii"),
    privateJsonBytes(value, "private-worker-context-invalid"),
  ]));
}

function assignmentNonceSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-worker-assignment-nonce-v1\0", "ascii"),
    Buffer.from(value, "ascii"),
  ]));
}

async function readStablePrivateFile(filePath, maximumBytes, reason) {
  requireExactPrivatePath(filePath, reason);
  let handle = null;
  try {
    const initial = await lstat(filePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.nlink !== 1n
      || initial.size <= 0n
      || initial.size > BigInt(maximumBytes)
      || !identityFromState(initial).meaningful
      || path.resolve(await realpath(filePath)) !== filePath
    ) failAdapter("SAME_HOST", reason);
    const identity = identityFromState(initial);
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || before.size !== initial.size
      || !identitiesEqual(identity, identityFromState(before))
    ) failAdapter("SAME_HOST", reason);
    const bytes = Buffer.alloc(Number(initial.size));
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!result || result.bytesRead <= 0) failAdapter("SAME_HOST", reason);
      offset += result.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    const after = await handle.stat({ bigint: true });
    const final = await lstat(filePath, { bigint: true });
    if (
      trailing.bytesRead !== 0
      || after.size !== before.size
      || final.size !== initial.size
      || final.nlink !== 1n
      || !identitiesEqual(identity, identityFromState(after))
      || !identitiesEqual(identity, identityFromState(final))
      || path.resolve(await realpath(filePath)) !== filePath
    ) failAdapter("SAME_HOST", reason);
    return Object.freeze({ bytes, identity });
  } catch (error) {
    throw asAdapterError(error, "SAME_HOST", reason);
  } finally {
    if (handle) await handle.close();
  }
}

async function inspectExactPrivateDirectory(directoryPath, reason) {
  requireExactPrivatePath(directoryPath, reason);
  const parentPath = path.dirname(directoryPath);
  let parentChain;
  try {
    parentChain = await validateParentChain(parentPath);
  } catch {
    failAdapter("SAME_HOST", reason);
  }
  const state = await lstat(directoryPath, { bigint: true });
  const identity = identityFromState(state);
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !identity.meaningful
    || path.resolve(await realpath(directoryPath)) !== directoryPath
  ) failAdapter("SAME_HOST", reason);
  await validateParentChain(parentPath, parentChain);
  return Object.freeze({
    path: directoryPath,
    pathSha256: privatePathSha256(directoryPath),
    identity,
    parentIdentity: parentChain.at(-1).identity,
    parentChain,
  });
}

function repositoryBinding(directory) {
  return Object.freeze({
    pathSha256: directory.pathSha256,
    identity: identityStrings(directory.identity),
  });
}

function validateRepositoryBinding(value, reason) {
  exactKeys(value, WORKER_REPOSITORY_BINDING_KEYS, "SAME_HOST", reason);
  requireSha256(value.pathSha256, "SAME_HOST", reason);
  requirePrivateIdentityStrings(value.identity, reason);
}

function validateLockedWorkerContext(value, reason = "private-worker-context-invalid") {
  exactKeys(value, WORKER_CONTEXT_KEYS, "SAME_HOST", reason);
  validateRepositoryBinding(value.sourceRepository, reason);
  validateRepositoryBinding(value.toolingRepository, reason);
  requireGitObject(value.sourceCommit, "SAME_HOST", reason);
  requireGitObject(value.toolingCommit, "SAME_HOST", reason);
  for (const key of [
    "policySha256",
    "criticalToolSetSha256",
    "runtimeIdentitySha256",
    "gitIdentitySha256",
    "platformProbeSha256",
    "testVectorSetSha256",
    "membershipReportSha256",
    "inputSetSha256",
    "gitExecutableSha256",
  ]) requireSha256(value[key], "SAME_HOST", reason);
  requireIdentifier(value.matrixCellId, "SAME_HOST", reason);
  if (
    value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Number.isSafeInteger(value.gitExecutableByteLength)
    || value.gitExecutableByteLength <= 0
  ) failAdapter("SAME_HOST", reason);
  return value;
}

function contextsEqual(left, right) {
  return privateJsonBytes(left, "private-worker-context-invalid").equals(
    privateJsonBytes(right, "private-worker-context-invalid"),
  );
}

async function inspectExecutable(candidate) {
  let state;
  try {
    state = await lstat(candidate, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
  if (state.isSymbolicLink() || !state.isFile()) {
    failAdapter("GIT_BINDING", "git-executable-reparse");
  }
  const resolved = await realpath(candidate);
  if (!pathsEqual(resolved, candidate)) {
    failAdapter("GIT_BINDING", "git-executable-reparse");
  }
  if (process.platform !== "win32") {
    try {
      await access(candidate, FS_CONSTANTS.X_OK);
    } catch {
      failAdapter("GIT_BINDING", "git-executable-permission");
    }
  }
  return path.resolve(candidate);
}

async function hashStableRegularFile(filePath, phase, reason) {
  let handle = null;
  try {
    const initial = await lstat(filePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.size < 0n
      || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !pathsEqual(await realpath(filePath), filePath)
    ) failAdapter(phase, reason);
    const identity = identityFromState(initial);
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.size !== initial.size
      || !identitiesEqual(identity, identityFromState(before))
    ) failAdapter(phase, reason);
    const hash = createHash("sha256");
    let offset = 0;
    const byteLength = Number(initial.size);
    while (offset < byteLength) {
      const chunk = Buffer.alloc(Math.min(FILE_CHUNK_SIZE, byteLength - offset));
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        failAdapter(phase, reason);
      }
      hash.update(chunk.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    if (trailing.bytesRead !== 0) failAdapter(phase, reason);
    const after = await handle.stat({ bigint: true });
    const finalState = await lstat(filePath, { bigint: true });
    if (
      after.size !== initial.size
      || finalState.size !== initial.size
      || !identitiesEqual(identity, identityFromState(after))
      || !identitiesEqual(identity, identityFromState(finalState))
      || !pathsEqual(await realpath(filePath), filePath)
    ) failAdapter(phase, reason);
    return Object.freeze({ sha256: hash.digest("hex"), byteLength });
  } catch (error) {
    throw asAdapterError(error, phase, reason);
  } finally {
    if (handle) await handle.close();
  }
}

export async function resolveControlledGitExecutable() {
  const pathValue = Object.entries(process.env).find(
    ([key]) => key.toUpperCase() === "PATH",
  )?.[1];
  if (typeof pathValue !== "string" || pathValue.length === 0) {
    failAdapter("GIT_BINDING", "git-path-unavailable");
  }
  const names = process.platform === "win32" ? ["git.exe", "git.com"] : ["git"];
  for (const rawEntry of pathValue.split(path.delimiter)) {
    const unquoted = rawEntry.length >= 2
      && rawEntry.startsWith('"')
      && rawEntry.endsWith('"')
      ? rawEntry.slice(1, -1)
      : rawEntry;
    if (!unquoted) continue;
    const directory = path.isAbsolute(unquoted)
      ? path.normalize(unquoted)
      : path.resolve(unquoted);
    for (const name of names) {
      const candidate = path.join(directory, name);
      const executable = await inspectExecutable(candidate);
      if (!executable) continue;
      const identity = await hashStableRegularFile(
        executable,
        "GIT_BINDING",
        "git-executable-identity",
      );
      const version = spawnSync(executable, ["--version"], {
        encoding: "utf8",
        env: sanitizedGitEnvironment(process.env, executable),
        shell: false,
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      });
      const match = !version.error && version.status === 0
        ? /^git version ([0-9][0-9A-Za-z.+-]*)\r?\n?$/u.exec(version.stdout)
        : null;
      if (!match) failAdapter("GIT_BINDING", "git-version-invalid");
      return Object.freeze({
        path: executable,
        directory: path.dirname(executable),
        sha256: identity.sha256,
        byteLength: identity.byteLength,
        reportedVersion: match[1],
      });
    }
  }
  failAdapter("GIT_BINDING", "git-executable-unavailable");
}

function sanitizedGitEnvironment(source, executable) {
  const environment = {};
  for (const [key, value] of Object.entries(source)) {
    if (!key.toUpperCase().startsWith("GIT_") && key.toUpperCase() !== "PATH") {
      environment[key] = value;
    }
  }
  environment.PATH = path.dirname(executable);
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LC_ALL = "C";
  environment.LANG = "C";
  return environment;
}

export function installControlledGitPath(git) {
  const prior = Object.entries(process.env).filter(
    ([key]) => key.toUpperCase() === "PATH",
  );
  for (const [key] of prior) delete process.env[key];
  process.env.PATH = git.directory;
  return () => {
    for (const [key] of Object.entries(process.env)) {
      if (key.toUpperCase() === "PATH") delete process.env[key];
    }
    for (const [key, value] of prior) process.env[key] = value;
  };
}

function runControlledGit(git, repoRoot, args, phase, reason, input = undefined) {
  const result = spawnSync(
    git.path,
    ["--no-replace-objects", "-C", repoRoot, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(process.env, git.path),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) failAdapter(phase, reason);
  return result.stdout;
}

export async function validateRepositoryCommit(repoArgument, commit, git, phase) {
  if (
    typeof repoArgument !== "string"
    || !path.isAbsolute(repoArgument)
    || path.resolve(repoArgument) !== repoArgument
  ) {
    failAdapter(phase, "repository-path-invalid");
  }
  const state = await pathState(repoArgument);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    failAdapter(phase, "repository-path-invalid");
  }
  const resolved = await realpath(repoArgument);
  if (!pathsEqual(resolved, repoArgument)) failAdapter(phase, "repository-reparse");
  const root = runControlledGit(
    git, repoArgument, ["rev-parse", "--show-toplevel"], phase, "repository-root",
  ).toString("utf8").trim();
  if (!pathsEqual(root, repoArgument)) failAdapter(phase, "repository-root");
  const objectFormat = runControlledGit(
    git, repoArgument, ["rev-parse", "--show-object-format"], phase, "object-format",
  ).toString("ascii").trim();
  if (objectFormat !== "sha1") failAdapter(phase, "object-format");
  const replacements = runControlledGit(
    git,
    repoArgument,
    ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    phase,
    "replacement-object-ref",
  ).toString("utf8").trim();
  if (replacements) failAdapter(phase, "replacement-object-ref");
  requireGitObject(commit, phase, "commit-id");
  const type = runControlledGit(
    git, repoArgument, ["cat-file", "-t", commit], phase, "commit-object",
  ).toString("ascii").trim();
  if (type !== "commit") failAdapter(phase, "commit-object-type");
  return repoArgument;
}

function parseSingleTreeEntry(bytes, expectedPath) {
  const records = bytes.length === 0
    ? []
    : bytes.subarray(0, -1).toString("utf8").split("\0");
  if (bytes.at(-1) !== 0 || records.length !== 1) return null;
  const tab = records[0].indexOf("\t");
  if (tab < 0 || records[0].slice(tab + 1) !== expectedPath) return null;
  const parts = records[0].slice(0, tab).split(" ");
  if (parts.length !== 3 || parts[1] !== "blob") return null;
  return Object.freeze({ mode: parts[0], objectId: parts[2] });
}

function validateStaticImports(relativePath, bytes) {
  const source = bytes.toString("utf8");
  if (/\bimport\s*\(/u.test(source)) {
    failAdapter("TOOLING_BINDING", "dynamic-production-import");
  }
  const expressions = [
    /\bfrom\s*["']([^"']+)["']/gu,
    /(?:^|\n)\s*import\s*["']([^"']+)["']/gu,
  ];
  for (const expression of expressions) {
    for (const match of source.matchAll(expression)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
        failAdapter("TOOLING_BINDING", "production-import-outside-tool-set");
      }
      const resolved = path.posix.normalize(
        path.posix.join(path.posix.dirname(relativePath), specifier),
      );
      if (!CRITICAL_TOOL_PATHS.includes(resolved)) {
        failAdapter("TOOLING_BINDING", "production-import-outside-tool-set");
      }
    }
  }
}

export async function validateCriticalToolSet({
  document,
  toolingRepo,
  toolingCommit,
  git,
}) {
  const phase = "TOOLING_BINDING";
  const value = document.value;
  exactKeys(value, TOOL_SET_KEYS, phase, "critical-tool-set-shape");
  if (
    value.documentKind !== CRITICAL_TOOL_SET_KIND
    || value.schemaVersion !== 1
    || value.toolSetId !== CRITICAL_TOOL_SET_ID
    || value.toolingCommit !== toolingCommit
    || !Array.isArray(value.entries)
    || value.entries.length !== CRITICAL_TOOL_PATHS.length
  ) {
    failAdapter(phase, "critical-tool-set-invalid");
  }
  for (let index = 0; index < value.entries.length; index += 1) {
    const entry = value.entries[index];
    exactKeys(entry, TOOL_ENTRY_KEYS, phase, "critical-tool-entry-shape");
    const expectedPath = CRITICAL_TOOL_PATHS[index];
    if (
      entry.path !== expectedPath
      || (entry.gitMode !== "100644" && entry.gitMode !== "100755")
      || !GIT_OBJECT_PATTERN.test(entry.gitBlobObjectId)
      || !Number.isSafeInteger(entry.declaredByteSize)
      || entry.declaredByteSize < 0
      || !SHA256_PATTERN.test(entry.sha256)
    ) {
      failAdapter(phase, "critical-tool-entry-invalid");
    }
    const tree = parseSingleTreeEntry(
      runControlledGit(
        git,
        toolingRepo,
        ["ls-tree", "-z", "--full-tree", toolingCommit, "--", expectedPath],
        phase,
        "critical-tool-commit-entry",
      ),
      expectedPath,
    );
    if (
      !tree
      || tree.mode !== entry.gitMode
      || tree.objectId !== entry.gitBlobObjectId
    ) {
      failAdapter(phase, "critical-tool-commit-entry");
    }
    const committed = runControlledGit(
      git,
      toolingRepo,
      ["cat-file", "blob", entry.gitBlobObjectId],
      phase,
      "critical-tool-blob",
    );
    if (
      committed.length !== entry.declaredByteSize
      || sha256Bytes(committed) !== entry.sha256
    ) {
      failAdapter(phase, "critical-tool-blob");
    }
    const expectedLoadedPath = path.join(toolingRepo, ...expectedPath.split("/"));
    const modulePath = MODULE_PATHS.get(expectedPath);
    let loadedMatches = false;
    try {
      loadedMatches = Boolean(modulePath)
        && pathsEqual(
          realpathSync.native(modulePath),
          realpathSync.native(expectedLoadedPath),
        );
    } catch {
      loadedMatches = false;
    }
    if (!loadedMatches) {
      failAdapter(phase, "critical-tool-loaded-path");
    }
    let actual;
    try {
      actual = await readStableFile(expectedLoadedPath, {
        phase: "FILE_IDENTITY",
        reason: "critical-tool",
        kind: "critical-tool",
        captureBytes: true,
      });
    } catch {
      failAdapter(phase, "critical-tool-loaded-bytes");
    }
    if (
      actual.byteLength !== entry.declaredByteSize
      || actual.sha256 !== entry.sha256
      || !actual.bytes.equals(committed)
    ) {
      failAdapter(phase, "critical-tool-loaded-bytes");
    }
    validateStaticImports(expectedPath, committed);
  }
  return true;
}

export async function validateRuntimeIdentity(document, cell) {
  const phase = "RUNTIME_BINDING";
  const value = document.value;
  exactKeys(value, RUNTIME_KEYS, phase, "runtime-identity-shape");
  const measured = await hashStableRegularFile(
    path.resolve(process.execPath),
    phase,
    "runtime-executable-identity",
  );
  if (
    value.documentKind !== RUNTIME_IDENTITY_KIND
    || value.schemaVersion !== 1
    || value.runtimeProfileId !== cell.runtimeProfileId
    || document.sha256 !== cell.runtimeIdentitySha256
    || value.implementation !== "node"
    || value.executableSha256 !== measured.sha256
    || value.executableByteLength !== measured.byteLength
    || value.nodeVersion !== process.versions.node
    || value.v8Version !== process.versions.v8
    || value.modulesVersion !== process.versions.modules
  ) {
    failAdapter(phase, "runtime-profile-mismatch");
  }
  requireIdentifier(value.runtimeProfileId, phase, "runtime-profile-id");
  requireIdentifier(value.distributionProfileId, phase, "runtime-distribution-profile");
  return true;
}

export function validateGitIdentity(document, cell, git) {
  const phase = "GIT_BINDING";
  const value = document.value;
  exactKeys(value, GIT_KEYS, phase, "git-identity-shape");
  if (
    value.documentKind !== GIT_IDENTITY_KIND
    || value.schemaVersion !== 1
    || value.gitProfileId !== cell.gitProfileId
    || document.sha256 !== cell.gitIdentitySha256
    || value.executableSha256 !== git.sha256
    || value.executableByteLength !== git.byteLength
    || value.reportedVersion !== git.reportedVersion
    || value.objectFormat !== "sha1"
  ) {
    failAdapter(phase, "git-identity-mismatch");
  }
  requireIdentifier(value.gitProfileId, phase, "git-profile-id");
  requireIdentifier(value.distributionProfileId, phase, "git-distribution-profile");
  return true;
}

export function validatePlatformProbeShape(
  document,
  cell,
  runtimeIdentitySha256,
  gitIdentitySha256,
) {
  const phase = "PLATFORM_PROBE";
  const value = document.value;
  exactKeys(value, PLATFORM_KEYS, phase, "platform-probe-shape");
  exactKeys(
    value.pathPolicyCapabilities,
    PATH_CAPABILITY_KEYS,
    phase,
    "path-capability-shape",
  );
  for (const key of PATH_CAPABILITY_KEYS) {
    requireBoolean(value.pathPolicyCapabilities[key], phase, "path-capability-value");
  }
  for (const key of [
    "exclusiveCreateSupported",
    "hardLinkSupported",
    "atomicNoReplaceHardLinkSupported",
    "reliableLinkCountSupported",
    "stableFileIdentitySupported",
  ]) requireBoolean(value[key], phase, "host-capability-value");
  const expectedStatic = {
    matrixCellId: cell.matrixCellId,
    operatingSystem: canonicalOsName(),
    operatingSystemBuild: os.release().toLowerCase(),
    architecture: process.arch,
    filesystemProfile: cell.filesystemProfile,
    localeProfile: cell.localeProfile,
    timezoneProfile: cell.timezoneProfile,
    runtimeIdentitySha256,
    gitIdentitySha256,
  };
  if (
    document.sha256 !== cell.platformProbeSha256
    || !["x64", "arm64"].includes(process.arch)
    || Object.entries(expectedStatic).some(([key, expected]) => value[key] !== expected)
  ) {
    failAdapter(phase, "platform-probe-mismatch");
  }
  return value;
}

export function validateMeasuredCapabilities(probe, measured) {
  const pathCapabilities = probe.pathPolicyCapabilities;
  if (PATH_CAPABILITY_KEYS.some((key) => pathCapabilities[key] !== true)) {
    failAdapter("PLATFORM_PROBE", "unsupported-host-capability");
  }
  const keys = [
    "exclusiveCreateSupported",
    "hardLinkSupported",
    "atomicNoReplaceHardLinkSupported",
    "reliableLinkCountSupported",
    "stableFileIdentitySupported",
  ];
  if (keys.some((key) => measured[key] !== true)) {
    failAdapter("PLATFORM_PROBE", "unsupported-host-capability");
  }
  if (keys.some((key) => probe[key] !== measured[key])) {
    failAdapter("PLATFORM_PROBE", "platform-probe-mismatch");
  }
  return true;
}

export async function createExclusiveOutputDirectory({
  outputDirectory,
  sourceRepo,
  toolingRepo,
}) {
  if (
    typeof outputDirectory !== "string"
    || !path.isAbsolute(outputDirectory)
    || path.normalize(outputDirectory) !== outputDirectory
    || path.resolve(outputDirectory) !== outputDirectory
  ) {
    failAdapter("CLI", "output-directory-invalid");
  }
  if (
    pathsEqual(outputDirectory, sourceRepo)
    || isInside(sourceRepo, outputDirectory)
    || pathsEqual(outputDirectory, toolingRepo)
    || isInside(toolingRepo, outputDirectory)
  ) {
    failAdapter("CLI", "output-directory-contained");
  }
  const parent = path.dirname(outputDirectory);
  let parentChain;
  try {
    parentChain = await validateParentChain(parent);
  } catch {
    failAdapter("CLI", "output-parent-invalid");
  }
  if (await pathState(outputDirectory)) failAdapter("CLI", "output-directory-exists");
  try {
    await mkdir(outputDirectory, { mode: 0o700 });
    await validateParentChain(parent, parentChain);
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "output-directory-create");
  }
  const state = await lstat(outputDirectory, { bigint: true });
  const resolved = await realpath(outputDirectory);
  if (state.isSymbolicLink() || !state.isDirectory() || !pathsEqual(resolved, outputDirectory)) {
    failAdapter("OUTPUT_PUBLICATION", "output-directory-identity");
  }
  return Object.freeze({
    path: outputDirectory,
    parent,
    parentChain,
    identity: identityFromState(state),
  });
}

async function requireDirectoryIdentity(record) {
  const state = await pathState(record.path);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isDirectory()
    || !identitiesEqual(record.identity, identityFromState(state))
    || !pathsEqual(await realpath(record.path), record.path)
  ) {
    failAdapter("CLEANUP", "cleanup-incomplete");
  }
  return state;
}

export async function removeEmptyOutputDirectory(record) {
  try {
    await requireDirectoryIdentity(record);
    await rmdir(record.path);
  } catch {
    failAdapter("CLEANUP", "cleanup-incomplete");
  }
}

export async function createOwnedDirectory(parentRecord, basename, ledger) {
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(basename)) {
    failAdapter("OUTPUT_PUBLICATION", "private-directory-name");
  }
  await requireDirectoryIdentity(parentRecord);
  const target = path.join(parentRecord.path, basename);
  if (await pathState(target)) failAdapter("OUTPUT_PUBLICATION", "private-directory-exists");
  await mkdir(target, { mode: 0o700 });
  const state = await lstat(target, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !pathsEqual(await realpath(target), target)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "private-directory-identity");
  }
  const record = Object.freeze({
    kind: "directory",
    path: target,
    identity: identityFromState(state),
  });
  ledger.push(record);
  return record;
}

export async function recordOwnedFile(filePath, ledger) {
  const state = await lstat(filePath, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isFile()
    || state.size < 0n
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
    || !pathsEqual(await realpath(filePath), filePath)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "owned-file-identity");
  }
  const record = Object.freeze({
    kind: "file",
    path: filePath,
    identity: identityFromState(state),
    byteLength: Number(state.size),
  });
  ledger.push(record);
  return record;
}

export async function writeOwnedFile(parentRecord, basename, bytes, ledger) {
  if (
    typeof basename !== "string"
    || basename.length === 0
    || basename.includes("/")
    || basename.includes("\\")
    || !Buffer.isBuffer(bytes)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "output-file-invalid");
  }
  await requireDirectoryIdentity(parentRecord);
  const target = path.join(parentRecord.path, basename);
  let handle = null;
  let record = null;
  try {
    handle = await open(
      target,
      FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | FS_CONSTANTS.O_WRONLY
        | noFollowFlag(),
      0o600,
    );
    const initial = await handle.stat({ bigint: true });
    record = Object.freeze({
      kind: "file",
      path: target,
      identity: identityFromState(initial),
      byteLength: bytes.length,
    });
    ledger.push(record);
    let offset = 0;
    while (offset < bytes.length) {
      const written = await handle.write(bytes, offset, bytes.length - offset, null);
      if (!written || written.bytesWritten <= 0) {
        failAdapter("OUTPUT_PUBLICATION", "output-file-write");
      }
      offset += written.bytesWritten;
    }
    await handle.sync();
    await handle.close();
    handle = null;
    const actual = await readStableFile(target, {
      phase: "FILE_IDENTITY",
      reason: "output-file",
      kind: "output-file",
      captureBytes: true,
    });
    const state = await lstat(target, { bigint: true });
    if (
      !actual.bytes.equals(bytes)
      || actual.sha256 !== sha256Bytes(bytes)
      || actual.byteLength !== bytes.length
      || !identitiesEqual(record.identity, identityFromState(state))
      || state.nlink !== 1n
      || state.size !== BigInt(bytes.length)
    ) {
      failAdapter("OUTPUT_PUBLICATION", "output-file-verify");
    }
    return record;
  } catch (error) {
    if (handle) {
      try { await handle.close(); } catch { /* cleanup reports the identity failure */ }
    }
    throw asAdapterError(error, "OUTPUT_PUBLICATION", "output-file-write");
  }
}

export async function cleanupOwnedLedger(ledger) {
  let complete = true;
  for (let index = ledger.length - 1; index >= 0; index -= 1) {
    const record = ledger[index];
    try {
      const state = await pathState(record.path);
      if (!state) continue;
      if (
        state.isSymbolicLink()
        || !identitiesEqual(record.identity, identityFromState(state))
        || !pathsEqual(await realpath(record.path), record.path)
      ) {
        complete = false;
        continue;
      }
      if (record.kind === "file") {
        if (!state.isFile() || state.size !== BigInt(record.byteLength)) {
          complete = false;
          continue;
        }
        await unlink(record.path);
      } else {
        if (!state.isDirectory()) {
          complete = false;
          continue;
        }
        await rmdir(record.path);
      }
      if (await pathState(record.path)) complete = false;
    } catch {
      complete = false;
    }
  }
  if (!complete) failAdapter("CLEANUP", "cleanup-incomplete");
}

export async function runHostCapabilityProbe(privateRoot, ledger) {
  const directory = await createOwnedDirectory(privateRoot, "capability-probe", ledger);
  const sourcePath = path.join(directory.path, "source.bin");
  const linkedPath = path.join(directory.path, "linked.bin");
  const occupiedPath = path.join(directory.path, "occupied.bin");
  let sourceHandle = null;
  let exclusiveCreateSupported = false;
  let hardLinkSupported = false;
  let atomicNoReplaceHardLinkSupported = false;
  let reliableLinkCountSupported = false;
  let stableFileIdentitySupported = false;
  try {
    sourceHandle = await open(sourcePath, "wx", 0o600);
    await sourceHandle.writeFile(Buffer.from("capability-probe\n", "ascii"));
    await sourceHandle.sync();
    await sourceHandle.close();
    sourceHandle = null;
    const sourceRecord = await recordOwnedFile(sourcePath, ledger);
    try {
      const duplicate = await open(sourcePath, "wx", 0o600);
      await duplicate.close();
    } catch (error) {
      exclusiveCreateSupported = Boolean(error && error.code === "EEXIST");
    }
    const before = await lstat(sourcePath, { bigint: true });
    await link(sourcePath, linkedPath);
    const linkedRecord = await recordOwnedFile(linkedPath, ledger);
    hardLinkSupported = true;
    const after = await lstat(sourcePath, { bigint: true });
    reliableLinkCountSupported = before.nlink === 1n && after.nlink === 2n;
    stableFileIdentitySupported = sourceRecord.identity.meaningful
      && identitiesEqual(sourceRecord.identity, identityFromState(after))
      && identitiesEqual(sourceRecord.identity, linkedRecord.identity);
    const occupiedHandle = await open(occupiedPath, "wx", 0o600);
    await occupiedHandle.close();
    await recordOwnedFile(occupiedPath, ledger);
    try {
      await link(sourcePath, occupiedPath);
    } catch (error) {
      atomicNoReplaceHardLinkSupported = Boolean(error && error.code === "EEXIST");
    }
  } catch {
    // False capability values are reported to the platform binding layer.
  } finally {
    if (sourceHandle) {
      try { await sourceHandle.close(); } catch { /* ledger cleanup is authoritative */ }
    }
  }
  return Object.freeze({
    exclusiveCreateSupported,
    hardLinkSupported,
    atomicNoReplaceHardLinkSupported,
    reliableLinkCountSupported,
    stableFileIdentitySupported,
  });
}

export function encodeB3VerificationTranscript(result, sourceCommit) {
  if (!result || typeof result !== "object") {
    failAdapter("ARCHIVE_VERIFICATION", "b3-verification-result");
  }
  const actualKeys = Object.keys(result);
  if (
    actualKeys.length !== B3_TRANSCRIPT_KEYS.length
    || actualKeys.some((key, index) => key !== B3_TRANSCRIPT_KEYS[index])
  ) {
    failAdapter("ARCHIVE_VERIFICATION", "b3-verification-result");
  }
  if (
    result.sourceCommit !== sourceCommit
    || result.archiveFormat !== FORMAT_PROFILE
    || result.membershipValid !== true
    || result.archiveVerified !== true
    || result.correspondingSourceComplete !== false
    || result.publicationBlocked !== true
    || !SHA256_PATTERN.test(result.manifestSha256)
    || !SHA256_PATTERN.test(result.membershipReportSha256)
    || !SHA256_PATTERN.test(result.archiveSha256)
    || !Number.isSafeInteger(result.membershipCount)
    || !Number.isSafeInteger(result.archiveByteLength)
    || !Number.isSafeInteger(result.archiveMemberCount)
  ) {
    failAdapter("ARCHIVE_VERIFICATION", "b3-verification-result");
  }
  const ordered = Object.fromEntries(B3_TRANSCRIPT_KEYS.map((key) => [key, result[key]]));
  return canonicalAdapterJsonBytes(ordered, "ARCHIVE_VERIFICATION");
}

async function compareFileStreams(leftPath, rightPath, expectedLength) {
  let left = null;
  let right = null;
  try {
    left = await open(leftPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    right = await open(rightPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    let offset = 0;
    while (offset < expectedLength) {
      const length = Math.min(FILE_CHUNK_SIZE, expectedLength - offset);
      const leftBytes = Buffer.alloc(length);
      const rightBytes = Buffer.alloc(length);
      const [leftRead, rightRead] = await Promise.all([
        left.read(leftBytes, 0, length, null),
        right.read(rightBytes, 0, length, null),
      ]);
      if (
        leftRead.bytesRead !== length
        || rightRead.bytesRead !== length
        || !leftBytes.equals(rightBytes)
      ) return false;
      offset += length;
    }
    const trailingLeft = await left.read(Buffer.alloc(1), 0, 1, null);
    const trailingRight = await right.read(Buffer.alloc(1), 0, 1, null);
    return trailingLeft.bytesRead === 0 && trailingRight.bytesRead === 0;
  } finally {
    if (left) await left.close();
    if (right) await right.close();
  }
}

function requireIndependentArchives(left, right, phase) {
  if (
    identitiesEqual(left.file.identity, right.file.identity)
    || left.file.path === right.file.path
    || left.directory.path === right.directory.path
    || left.verification.archiveSha256 !== right.verification.archiveSha256
    || left.verification.archiveByteLength !== right.verification.archiveByteLength
    || !left.transcript.equals(right.transcript)
  ) {
    failAdapter(phase, phase === "SAME_PROCESS"
      ? "same-process-mismatch"
      : "same-host-mismatch");
  }
}

export async function runSameProcessRepetitions({
  sourceRepo,
  sourceCommit,
  privateRoot,
  ledger,
}) {
  const outputs = [];
  for (const label of ["same-process-a", "same-process-b"]) {
    const directory = await createOwnedDirectory(privateRoot, label, ledger);
    const archivePath = path.join(directory.path, "artifact.tar");
    try {
      await preparePublicSourceArchive({
        repo: sourceRepo,
        commit: sourceCommit,
        output: archivePath,
      });
      const file = await recordOwnedFile(archivePath, ledger);
      const state = await lstat(archivePath, { bigint: true });
      if (state.nlink !== 1n || !file.identity.meaningful) {
        failAdapter("SAME_PROCESS", "same-process-mismatch");
      }
      const verification = await verifyPublicSourceArchive({
        repo: sourceRepo,
        commit: sourceCommit,
        archive: archivePath,
      });
      const transcript = encodeB3VerificationTranscript(verification, sourceCommit);
      outputs.push(Object.freeze({ directory, file, verification, transcript }));
    } catch (error) {
      throw asAdapterError(error, "SAME_PROCESS", "same-process-mismatch");
    }
  }
  requireIndependentArchives(outputs[0], outputs[1], "SAME_PROCESS");
  if (!await compareFileStreams(
    outputs[0].file.path,
    outputs[1].file.path,
    outputs[0].verification.archiveByteLength,
  )) failAdapter("SAME_PROCESS", "same-process-mismatch");
  return Object.freeze({
    outputs: Object.freeze(outputs),
    sameProcessRepeatable: true,
    canonicalVerifierPassed: true,
  });
}

function sanitizedWorkerEnvironment(base, temporaryDirectory, locale) {
  const environment = {};
  for (const [key, value] of Object.entries(base)) {
    const upper = key.toUpperCase();
    if (
      upper.startsWith("GIT_")
      || upper === "NODE_OPTIONS"
      || upper === "NODE_PATH"
      || upper.includes("LOADER")
      || upper.includes("PRELOAD")
      || upper === "TEMP"
      || upper === "TMP"
      || upper === "TMPDIR"
      || upper === "LANG"
      || upper === "LC_ALL"
      || upper === "TZ"
      || upper === "SOURCE_DATE_EPOCH"
      || upper === LEGACY_WORKER_TOKEN_ENV
    ) continue;
    environment[key] = value;
  }
  environment.PATH = base.PATH;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.TEMP = temporaryDirectory;
  environment.TMP = temporaryDirectory;
  environment.TMPDIR = temporaryDirectory;
  environment.LANG = locale.lang;
  environment.LC_ALL = locale.lcAll;
  environment.TZ = locale.timezone;
  environment.SOURCE_DATE_EPOCH = locale.sourceDateEpoch;
  delete environment[LEGACY_WORKER_TOKEN_ENV];
  return environment;
}

function validateWorkerResponseText(text, expected) {
  const value = parseExactPrivateJsonText(
    text,
    MAX_WORKER_RESPONSE_BYTES,
    "private-worker-response-invalid",
  );
  exactKeys(
    value,
    WORKER_RESPONSE_KEYS,
    "SAME_HOST",
    "private-worker-response-invalid",
  );
  if (
    value.protocol !== WORKER_PROTOCOL
    || value.runId !== expected.runId
    || value.assignmentId !== expected.assignmentId
    || value.contextDigest !== expected.contextDigest
    || value.status !== "ok"
    || !SHA256_PATTERN.test(value.archiveSha256)
    || !Number.isSafeInteger(value.archiveByteLength)
    || value.archiveByteLength < 0
    || typeof value.transcriptBase64 !== "string"
    || !SHA256_PATTERN.test(value.transcriptSha256)
    || !Number.isSafeInteger(value.transcriptByteLength)
    || value.transcriptByteLength < 0
    || value.workerPid !== expected.workerPid
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  requirePrivateIdentityStrings(
    value.assignedDirectoryIdentity,
    "private-worker-response-invalid",
  );
  requirePrivateIdentityStrings(
    value.archiveFileIdentity,
    "private-worker-response-invalid",
  );
  if (!identityMatchesStrings(
    expected.directoryIdentity,
    value.assignedDirectoryIdentity,
  )) failAdapter("SAME_HOST", "private-worker-response-invalid");
  let transcript;
  try {
    transcript = Buffer.from(value.transcriptBase64, "base64");
    if (transcript.toString("base64") !== value.transcriptBase64) throw new Error();
  } catch {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  if (
    transcript.length !== value.transcriptByteLength
    || sha256Bytes(transcript) !== value.transcriptSha256
  ) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  return Object.freeze({ ...value, transcript });
}

async function forkOneWorker({
  requestText,
  environment,
  workingDirectory,
  expected,
}) {
  const modulePath = fileURLToPath(import.meta.url);
  return new Promise((resolve, reject) => {
    const child = fork(modulePath, [], {
      cwd: workingDirectory,
      env: environment,
      execArgv: [],
      serialization: "json",
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      windowsHide: true,
    });
    let response = null;
    let responseCount = 0;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new PublicSourceArchiveReproducibilityError(
        "SAME_HOST",
        "private-worker-unavailable",
      ));
    }, 120000);
    child.on("message", (message) => {
      responseCount += 1;
      if (responseCount !== 1) return;
      try {
        response = validateWorkerResponseText(message, {
          ...expected,
          workerPid: child.pid,
        });
      } catch {
        response = false;
      }
    });
    child.on("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new PublicSourceArchiveReproducibilityError(
        "SAME_HOST",
        "private-worker-unavailable",
      ));
    });
    child.on("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (
        code !== 0
        || signal !== null
        || responseCount !== 1
        || !response
      ) {
        reject(new PublicSourceArchiveReproducibilityError(
          "SAME_HOST",
          response === false
            ? "private-worker-response-invalid"
            : "private-worker-unavailable",
        ));
      } else {
        resolve(response);
      }
    });
    if (
      !Number.isSafeInteger(child.pid)
      || child.pid <= 0
      || !child.connected
    ) {
      settled = true;
      clearTimeout(timer);
      child.kill();
      reject(new PublicSourceArchiveReproducibilityError(
        "SAME_HOST",
        "private-worker-unavailable",
      ));
      return;
    }
    child.send(requestText, (error) => {
      if (error && !settled) {
        settled = true;
        clearTimeout(timer);
        child.kill();
        reject(new PublicSourceArchiveReproducibilityError(
          "SAME_HOST",
          "private-worker-unavailable",
        ));
      }
    });
  });
}

async function coordinatorModuleRealpathSha256() {
  const modulePath = MODULE_PATHS.get(CRITICAL_TOOL_PATHS[7]);
  const resolved = path.resolve(await realpath(modulePath));
  return privatePathSha256(resolved);
}

async function buildLockedWorkerContext({
  sourceRepo,
  toolingRepo,
  sourceCommit,
  toolingCommit,
  policySha256,
  matrixCellId,
  criticalToolSetSha256,
  runtimeIdentitySha256,
  gitIdentitySha256,
  platformProbeSha256,
  testVectorSetSha256,
  membershipReportSha256,
  inputSetSha256,
  git,
}) {
  const [sourceDirectory, toolingDirectory] = await Promise.all([
    inspectExactPrivateDirectory(sourceRepo, "private-worker-context-invalid"),
    inspectExactPrivateDirectory(toolingRepo, "private-worker-context-invalid"),
  ]);
  const value = {
    sourceRepository: repositoryBinding(sourceDirectory),
    toolingRepository: repositoryBinding(toolingDirectory),
    sourceCommit,
    toolingCommit,
    policySha256,
    matrixCellId,
    criticalToolSetSha256,
    runtimeIdentitySha256,
    gitIdentitySha256,
    platformProbeSha256,
    testVectorSetSha256,
    membershipReportSha256,
    inputSetSha256,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    gitExecutableSha256: git.sha256,
    gitExecutableByteLength: git.byteLength,
  };
  validateLockedWorkerContext(value);
  return Object.freeze({
    value: deepFreezeAdapter(value),
    digest: lockedContextSha256(value),
    sourceDirectory,
    toolingDirectory,
  });
}

function assignmentLeaseValue(directory, assignmentId, nonce, contextDigest) {
  return deepFreezeAdapter({
    assignmentId,
    assignmentNonce: nonce,
    directoryPathSha256: privatePathSha256(directory.path),
    directoryParentIdentity: identityStrings(directory.parentIdentity),
    directoryIdentity: identityStrings(directory.identity),
    archiveFilename: WORKER_ARCHIVE_BASENAME,
    lockedContextDigest: contextDigest,
    state: "unused",
  });
}

async function createCoordinatorWorkerLease({
  privateRoot,
  ledger,
  context,
}) {
  // The worker accepts only a one-time coordinator lease for an already
  // created, identity-bound private root and assignment. It cannot select or
  // write an archive outside that assignment. This is a local capability and
  // does not claim cryptographic authentication of every process on the host.
  const workerRoot = await createOwnedDirectory(
    privateRoot,
    "same-host-workers",
    ledger,
  );
  const root = await inspectExactPrivateDirectory(
    workerRoot.path,
    "private-worker-root-mismatch",
  );
  if (!identitiesEqual(root.identity, workerRoot.identity)) {
    failAdapter("SAME_HOST", "private-worker-root-mismatch");
  }
  if (
    pathsEqual(root.path, context.sourceDirectory.path)
    || isInside(context.sourceDirectory.path, root.path)
    || pathsEqual(root.path, context.toolingDirectory.path)
    || isInside(context.toolingDirectory.path, root.path)
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const directories = [];
  for (const assignmentId of ["worker-a", "worker-b"]) {
    const record = await createOwnedDirectory(workerRoot, assignmentId, ledger);
    const inspected = await inspectExactPrivateDirectory(
      record.path,
      "private-worker-assignment-mismatch",
    );
    if (
      !identitiesEqual(record.identity, inspected.identity)
      || !identitiesEqual(root.identity, inspected.parentIdentity)
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    directories.push(Object.freeze({ record, inspected }));
  }
  const runId = randomBytes(32).toString("hex");
  const assignments = directories.map((directory, index) => {
    const assignmentId = index === 0 ? "worker-a" : "worker-b";
    const nonce = randomBytes(32).toString("hex");
    return Object.freeze({
      record: directory.record,
      inspected: directory.inspected,
      value: assignmentLeaseValue(
        directory.inspected,
        assignmentId,
        nonce,
        context.digest,
      ),
    });
  });
  const lease = deepFreezeAdapter({
    protocol: WORKER_LEASE_PROTOCOL,
    schemaVersion: 1,
    runId,
    coordinatorPid: process.pid,
    coordinatorModuleRealpathSha256: await coordinatorModuleRealpathSha256(),
    privateRootPathSha256: root.pathSha256,
    privateRootIdentity: identityStrings(root.identity),
    privateRootParentIdentity: identityStrings(root.parentIdentity),
    lockedContext: context.value,
    lockedContextDigest: context.digest,
    assignments: assignments.map((entry) => entry.value),
  });
  const leaseBytes = privateJsonBytes(lease, "private-worker-lease-invalid");
  if (leaseBytes.length > MAX_WORKER_LEASE_BYTES) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const leaseRecord = await writeOwnedFile(
    workerRoot,
    WORKER_LEASE_BASENAME,
    leaseBytes,
    ledger,
  );
  const leasePath = path.join(workerRoot.path, WORKER_LEASE_BASENAME);
  const stableLease = await readStablePrivateFile(
    leasePath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  if (
    !stableLease.bytes.equals(leaseBytes)
    || !identitiesEqual(stableLease.identity, leaseRecord.identity)
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  return Object.freeze({
    workerRoot,
    root,
    lease,
    leaseBytes,
    leasePath,
    leaseRecord,
    assignments: Object.freeze(assignments),
  });
}

function claimBytesFor(lease, assignment) {
  return privateJsonBytes({
    protocol: WORKER_CLAIM_PROTOCOL,
    runId: lease.runId,
    assignmentId: assignment.assignmentId,
    assignmentNonceSha256: assignmentNonceSha256(assignment.assignmentNonce),
    contextDigest: lease.lockedContextDigest,
    state: "claimed",
  }, "private-worker-assignment-mismatch");
}

async function requireCoordinatorLeaseState(leaseState) {
  const root = await inspectExactPrivateDirectory(
    leaseState.workerRoot.path,
    "private-worker-root-mismatch",
  );
  if (
    !identitiesEqual(root.identity, leaseState.root.identity)
    || !identitiesEqual(root.parentIdentity, leaseState.root.parentIdentity)
    || root.pathSha256 !== leaseState.lease.privateRootPathSha256
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const stableLease = await readStablePrivateFile(
    leaseState.leasePath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  if (
    !stableLease.bytes.equals(leaseState.leaseBytes)
    || !identitiesEqual(stableLease.identity, leaseState.leaseRecord.identity)
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  const rootEntries = await readdir(root.path);
  const expectedRootEntries = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== expectedRootEntries.size
    || rootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  for (const assignment of leaseState.assignments) {
    const directory = await inspectExactPrivateDirectory(
      assignment.record.path,
      "private-worker-assignment-mismatch",
    );
    if (
      !identityMatchesStrings(directory.identity, assignment.value.directoryIdentity)
      || !identityMatchesStrings(
        directory.parentIdentity,
        assignment.value.directoryParentIdentity,
      )
      || directory.pathSha256 !== assignment.value.directoryPathSha256
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
}

async function adoptWorkerOutput(leaseState, assignment, response, ledger) {
  await requireCoordinatorLeaseState(leaseState);
  const directory = await inspectExactPrivateDirectory(
    assignment.record.path,
    "private-worker-assignment-mismatch",
  );
  if (
    !identityMatchesStrings(directory.identity, response.assignedDirectoryIdentity)
    || !identityMatchesStrings(directory.identity, assignment.value.directoryIdentity)
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  const entries = await readdir(directory.path);
  const expectedEntries = new Set([
    WORKER_CLAIM_BASENAME,
    WORKER_ARCHIVE_BASENAME,
  ]);
  if (
    entries.length !== expectedEntries.size
    || entries.some((entry) => !expectedEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-output-escape");
  const claimPath = path.join(directory.path, WORKER_CLAIM_BASENAME);
  const claim = await readStablePrivateFile(
    claimPath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-assignment-mismatch",
  );
  const expectedClaim = claimBytesFor(leaseState.lease, assignment.value);
  if (!claim.bytes.equals(expectedClaim)) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  const claimRecord = await recordOwnedFile(claimPath, []);
  if (!identitiesEqual(claim.identity, claimRecord.identity)) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  ledger.push(claimRecord);
  const file = await recordOwnedFile(
    path.join(directory.path, WORKER_ARCHIVE_BASENAME),
    [],
  );
  if (!identityMatchesStrings(file.identity, response.archiveFileIdentity)) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  const state = await lstat(file.path, { bigint: true });
  if (state.nlink !== 1n || file.byteLength !== response.archiveByteLength) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  const hashed = await hashStableRegularFile(
    file.path,
    "SAME_HOST",
    "private-worker-response-invalid",
  );
  if (
    hashed.sha256 !== response.archiveSha256
    || hashed.byteLength !== response.archiveByteLength
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  ledger.push(file);
  return Object.freeze({ directory: assignment.record, file });
}

export async function runSameHostRepetitions({
  sourceRepo,
  toolingRepo,
  sourceCommit,
  toolingCommit,
  policySha256,
  matrixCellId,
  criticalToolSetSha256,
  runtimeIdentitySha256,
  gitIdentitySha256,
  platformProbeSha256,
  testVectorSetSha256,
  membershipReportSha256,
  inputSetSha256,
  privateRoot,
  ledger,
  git,
  sameProcess,
}) {
  const context = await buildLockedWorkerContext({
    sourceRepo,
    toolingRepo,
    sourceCommit,
    toolingCommit,
    policySha256,
    matrixCellId,
    criticalToolSetSha256,
    runtimeIdentitySha256,
    gitIdentitySha256,
    platformProbeSha256,
    testVectorSetSha256,
    membershipReportSha256,
    inputSetSha256,
    git,
  });
  const leaseState = await createCoordinatorWorkerLease({
    privateRoot,
    ledger,
    context,
  });
  const requestFor = (assignment) => privateJsonBytes({
    protocol: WORKER_PROTOCOL,
    leaseReference: leaseState.leasePath,
    assignmentId: assignment.value.assignmentId,
    assignmentNonce: assignment.value.assignmentNonce,
    sourceRepositoryPath: sourceRepo,
    toolingRepositoryPath: toolingRepo,
    lockedContext: context.value,
  }, "private-worker-request-invalid").toString("utf8");
  const localeA = {
    lang: "C",
    lcAll: "C",
    timezone: "UTC",
    sourceDateEpoch: "0",
  };
  const localeB = {
    lang: "tr_TR.UTF-8",
    lcAll: "tr_TR.UTF-8",
    timezone: "Pacific/Kiritimati",
    sourceDateEpoch: "4102444800",
  };
  let responses;
  try {
    await requireCoordinatorLeaseState(leaseState);
    const settled = await Promise.allSettled([
      forkOneWorker({
        requestText: requestFor(leaseState.assignments[0]),
        environment: sanitizedWorkerEnvironment(
          process.env,
          leaseState.assignments[0].record.path,
          localeA,
        ),
        workingDirectory: leaseState.assignments[0].record.path,
        expected: {
          runId: leaseState.lease.runId,
          assignmentId: "worker-a",
          contextDigest: context.digest,
          directoryIdentity: leaseState.assignments[0].record.identity,
        },
      }),
      forkOneWorker({
        requestText: requestFor(leaseState.assignments[1]),
        environment: sanitizedWorkerEnvironment(
          process.env,
          leaseState.assignments[1].record.path,
          localeB,
        ),
        workingDirectory: leaseState.assignments[1].record.path,
        expected: {
          runId: leaseState.lease.runId,
          assignmentId: "worker-b",
          contextDigest: context.digest,
          directoryIdentity: leaseState.assignments[1].record.identity,
        },
      }),
    ]);
    for (let index = 0; index < settled.length; index += 1) {
      if (settled[index].status === "fulfilled") {
        await adoptWorkerOutput(
          leaseState,
          leaseState.assignments[index],
          settled[index].value,
          ledger,
        );
      }
    }
    if (settled.some((entry) => entry.status !== "fulfilled")) {
      const rejected = settled.find((entry) => entry.status === "rejected");
      throw asAdapterError(
        rejected?.reason,
        "SAME_HOST",
        "private-worker-unavailable",
      );
    }
    responses = settled.map((entry) => entry.value);
  } catch (error) {
    throw asAdapterError(error, "SAME_HOST", "private-worker-unavailable");
  }
  const outputs = responses.map((response, index) => Object.freeze({
    directory: leaseState.assignments[index].record,
    file: Object.freeze({
      kind: "file",
      path: path.join(
        leaseState.assignments[index].record.path,
        WORKER_ARCHIVE_BASENAME,
      ),
      identity: Object.freeze({
        device: BigInt(response.archiveFileIdentity.device),
        inode: BigInt(response.archiveFileIdentity.inode),
        meaningful: true,
      }),
      byteLength: response.archiveByteLength,
    }),
    verification: Object.freeze({
      archiveSha256: response.archiveSha256,
      archiveByteLength: response.archiveByteLength,
    }),
    transcript: response.transcript,
    pid: response.workerPid,
  }));
  requireIndependentArchives(outputs[0], outputs[1], "SAME_HOST");
  if (
    outputs[0].pid === outputs[1].pid
    || outputs[0].pid === process.pid
    || outputs[1].pid === process.pid
    || identitiesEqual(outputs[0].directory.identity, outputs[1].directory.identity)
    || !await compareFileStreams(
      outputs[0].file.path,
      outputs[1].file.path,
      outputs[0].verification.archiveByteLength,
    )
  ) failAdapter("SAME_HOST", "same-host-mismatch");
  for (const output of outputs) {
    for (const processOutput of sameProcess.outputs) {
      if (
        identitiesEqual(output.file.identity, processOutput.file.identity)
        || output.verification.archiveSha256 !== processOutput.verification.archiveSha256
        || output.verification.archiveByteLength
          !== processOutput.verification.archiveByteLength
        || !output.transcript.equals(processOutput.transcript)
        || !await compareFileStreams(
          output.file.path,
          processOutput.file.path,
          output.verification.archiveByteLength,
        )
      ) failAdapter("SAME_HOST", "same-host-mismatch");
    }
  }
  return Object.freeze({
    outputs: Object.freeze(outputs),
    sameHostRepeatable: true,
  });
}

export async function publishArchiveNoReplace(
  outputDirectory,
  candidate,
  outputLedger,
) {
  const target = path.join(outputDirectory.path, "artifact.tar");
  await requireDirectoryIdentity(outputDirectory);
  if (await pathState(target)) failAdapter("OUTPUT_PUBLICATION", "archive-exists");
  const sourceState = await lstat(candidate.file.path, { bigint: true });
  if (
    sourceState.nlink !== 1n
    || !identitiesEqual(candidate.file.identity, identityFromState(sourceState))
  ) failAdapter("OUTPUT_PUBLICATION", "archive-source-identity");
  try {
    await link(candidate.file.path, target);
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "archive-link-failed");
  }
  const targetState = await lstat(target, { bigint: true });
  if (
    !targetState.isFile()
    || targetState.isSymbolicLink()
    || targetState.nlink !== 2n
    || targetState.size !== BigInt(candidate.file.byteLength)
    || !identitiesEqual(candidate.file.identity, identityFromState(targetState))
  ) failAdapter("OUTPUT_PUBLICATION", "archive-link-identity");
  const record = Object.freeze({
    kind: "file",
    path: target,
    identity: candidate.file.identity,
    byteLength: candidate.file.byteLength,
  });
  outputLedger.push(record);
  return record;
}

export async function verifyPublishedArchive(record, expectedSha256) {
  let actual;
  try {
    actual = await readStableFile(record.path, {
      phase: "FILE_IDENTITY",
      reason: "published-archive",
      kind: "published-archive",
      captureBytes: false,
    });
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "published-archive-identity");
  }
  if (actual.sha256 !== expectedSha256 || actual.byteLength !== record.byteLength) {
    failAdapter("OUTPUT_PUBLICATION", "published-archive-identity");
  }
}

export function buildSemanticReportBytes({
  sourceCommit,
  toolingCommit,
  inputSetSha256,
  artifactSha256,
  artifactByteLength,
}) {
  try {
    return encodeCanonicalSemanticReport({
      semanticReportKind: REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
      schemaVersion: SCHEMA_VERSION,
      artifactRole: ARTIFACT_ROLE,
      formatProfile: FORMAT_PROFILE,
      sourceCommit,
      toolingCommit,
      inputSetSha256,
      artifactSha256,
      artifactByteLength,
      canonicalVerifierPassed: true,
      sameProcessRepeatable: true,
      sameHostRepeatable: true,
      boundaryVectorSetPassed: true,
      result: "pass",
      failureCode: null,
    });
  } catch {
    failAdapter("SEMANTIC_REPORT", "semantic-report-invalid");
  }
}

export function buildEvidenceBytes({
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
    failAdapter("EVIDENCE", "evidence-invalid");
  }
}

export function failureClassFor(error) {
  if (error.reason === "runtime-profile-mismatch") return "runtime-profile-change";
  if (error.reason === "git-identity-mismatch") return "runtime-profile-change";
  if (error.reason === "unsupported-host-capability") {
    return error.phase === "PLATFORM_PROBE"
      ? "unsupported-platform"
      : "filesystem-incompatibility";
  }
  if (
    error.reason === "cleanup-incomplete"
    || error.reason.startsWith("private-worker-")
  ) {
    return "test-infrastructure-failure";
  }
  return "implementation-defect";
}

function parseWorkerRequestText(text) {
  const request = parseExactPrivateJsonText(
    text,
    MAX_WORKER_REQUEST_BYTES,
    "private-worker-request-invalid",
  );
  exactKeys(
    request,
    WORKER_REQUEST_KEYS,
    "SAME_HOST",
    "private-worker-request-invalid",
  );
  if (
    request.protocol !== WORKER_PROTOCOL
    || !["worker-a", "worker-b"].includes(request.assignmentId)
    || !SHA256_PATTERN.test(request.assignmentNonce)
  ) failAdapter("SAME_HOST", "private-worker-request-invalid");
  requireExactPrivatePath(
    request.leaseReference,
    "private-worker-request-invalid",
  );
  requireExactPrivatePath(
    request.sourceRepositoryPath,
    "private-worker-request-invalid",
  );
  requireExactPrivatePath(
    request.toolingRepositoryPath,
    "private-worker-request-invalid",
  );
  validateLockedWorkerContext(request.lockedContext);
  return request;
}

function validateLeaseAssignment(value, expectedId, contextDigest) {
  exactKeys(
    value,
    WORKER_ASSIGNMENT_KEYS,
    "SAME_HOST",
    "private-worker-lease-invalid",
  );
  if (
    value.assignmentId !== expectedId
    || !SHA256_PATTERN.test(value.assignmentNonce)
    || !SHA256_PATTERN.test(value.directoryPathSha256)
    || value.archiveFilename !== WORKER_ARCHIVE_BASENAME
    || value.lockedContextDigest !== contextDigest
    || value.state !== "unused"
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  requirePrivateIdentityStrings(
    value.directoryParentIdentity,
    "private-worker-lease-invalid",
  );
  requirePrivateIdentityStrings(
    value.directoryIdentity,
    "private-worker-lease-invalid",
  );
}

async function readAndValidateWorkerLease(request) {
  if (path.basename(request.leaseReference) !== WORKER_LEASE_BASENAME) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const rootPath = path.dirname(request.leaseReference);
  const [root, sourceDirectory, toolingDirectory, stableLease] = await Promise.all([
    inspectExactPrivateDirectory(rootPath, "private-worker-root-mismatch"),
    inspectExactPrivateDirectory(
      request.sourceRepositoryPath,
      "private-worker-context-invalid",
    ),
    inspectExactPrivateDirectory(
      request.toolingRepositoryPath,
      "private-worker-context-invalid",
    ),
    readStablePrivateFile(
      request.leaseReference,
      MAX_WORKER_LEASE_BYTES,
      "private-worker-lease-invalid",
    ),
  ]);
  const leaseText = stableLease.bytes.toString("utf8");
  if (!Buffer.from(leaseText, "utf8").equals(stableLease.bytes)) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const lease = parseExactPrivateJsonText(
    leaseText,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  exactKeys(
    lease,
    WORKER_LEASE_KEYS,
    "SAME_HOST",
    "private-worker-lease-invalid",
  );
  if (
    lease.protocol !== WORKER_LEASE_PROTOCOL
    || lease.schemaVersion !== 1
    || !SHA256_PATTERN.test(lease.runId)
    || !Number.isSafeInteger(lease.coordinatorPid)
    || lease.coordinatorPid <= 0
    || !SHA256_PATTERN.test(lease.coordinatorModuleRealpathSha256)
    || !SHA256_PATTERN.test(lease.privateRootPathSha256)
    || !SHA256_PATTERN.test(lease.lockedContextDigest)
    || !Array.isArray(lease.assignments)
    || lease.assignments.length !== 2
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  requirePrivateIdentityStrings(
    lease.privateRootIdentity,
    "private-worker-lease-invalid",
  );
  requirePrivateIdentityStrings(
    lease.privateRootParentIdentity,
    "private-worker-lease-invalid",
  );
  validateLockedWorkerContext(lease.lockedContext);
  if (
    !contextsEqual(lease.lockedContext, request.lockedContext)
    || lockedContextSha256(request.lockedContext) !== lease.lockedContextDigest
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  if (
    lease.coordinatorPid !== process.ppid
    || lease.coordinatorModuleRealpathSha256
      !== await coordinatorModuleRealpathSha256()
  ) failAdapter("SAME_HOST", "private-worker-parent-mismatch");
  if (
    root.pathSha256 !== lease.privateRootPathSha256
    || !identityMatchesStrings(root.identity, lease.privateRootIdentity)
    || !identityMatchesStrings(
      root.parentIdentity,
      lease.privateRootParentIdentity,
    )
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  if (
    pathsEqual(root.path, sourceDirectory.path)
    || isInside(sourceDirectory.path, root.path)
    || pathsEqual(root.path, toolingDirectory.path)
    || isInside(toolingDirectory.path, root.path)
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  if (
    sourceDirectory.pathSha256 !== request.lockedContext.sourceRepository.pathSha256
    || !identityMatchesStrings(
      sourceDirectory.identity,
      request.lockedContext.sourceRepository.identity,
    )
    || toolingDirectory.pathSha256
      !== request.lockedContext.toolingRepository.pathSha256
    || !identityMatchesStrings(
      toolingDirectory.identity,
      request.lockedContext.toolingRepository.identity,
    )
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  validateLeaseAssignment(
    lease.assignments[0],
    "worker-a",
    lease.lockedContextDigest,
  );
  validateLeaseAssignment(
    lease.assignments[1],
    "worker-b",
    lease.lockedContextDigest,
  );
  const assignment = lease.assignments.find(
    (entry) => entry.assignmentId === request.assignmentId,
  );
  if (
    !assignment
    || assignment.assignmentNonce !== request.assignmentNonce
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const assignmentPath = path.join(root.path, request.assignmentId);
  requireExactPrivatePath(
    assignmentPath,
    "private-worker-assignment-mismatch",
  );
  const directory = await inspectExactPrivateDirectory(
    assignmentPath,
    "private-worker-assignment-mismatch",
  );
  if (
    directory.pathSha256 !== assignment.directoryPathSha256
    || !identityMatchesStrings(directory.identity, assignment.directoryIdentity)
    || !identityMatchesStrings(
      directory.parentIdentity,
      assignment.directoryParentIdentity,
    )
    || !identitiesEqual(directory.parentIdentity, root.identity)
    || path.resolve(process.cwd()) !== assignmentPath
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const git = await resolveControlledGitExecutable();
  if (
    git.sha256 !== request.lockedContext.gitExecutableSha256
    || git.byteLength !== request.lockedContext.gitExecutableByteLength
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  const rootEntries = await readdir(root.path);
  const expectedRootEntries = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== expectedRootEntries.size
    || rootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const entries = await readdir(directory.path);
  if (entries.includes(WORKER_CLAIM_BASENAME)) {
    failAdapter("SAME_HOST", "private-worker-replay");
  }
  if (entries.length !== 0) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  return Object.freeze({
    request,
    lease,
    leaseBytes: stableLease.bytes,
    leaseIdentity: stableLease.identity,
    root,
    sourceDirectory,
    toolingDirectory,
    assignment,
    directory,
  });
}

async function requireWorkerLeaseState(binding, expectedEntries) {
  const [root, sourceDirectory, toolingDirectory, directory, leaseFile] =
    await Promise.all([
      inspectExactPrivateDirectory(
        binding.root.path,
        "private-worker-root-mismatch",
      ),
      inspectExactPrivateDirectory(
        binding.sourceDirectory.path,
        "private-worker-context-invalid",
      ),
      inspectExactPrivateDirectory(
        binding.toolingDirectory.path,
        "private-worker-context-invalid",
      ),
      inspectExactPrivateDirectory(
        binding.directory.path,
        "private-worker-assignment-mismatch",
      ),
      readStablePrivateFile(
        binding.request.leaseReference,
        MAX_WORKER_LEASE_BYTES,
        "private-worker-lease-invalid",
      ),
    ]);
  if (
    !identitiesEqual(root.identity, binding.root.identity)
    || !identitiesEqual(root.parentIdentity, binding.root.parentIdentity)
    || !identitiesEqual(sourceDirectory.identity, binding.sourceDirectory.identity)
    || !identitiesEqual(toolingDirectory.identity, binding.toolingDirectory.identity)
    || !identitiesEqual(directory.identity, binding.directory.identity)
    || !identitiesEqual(directory.parentIdentity, root.identity)
    || !identitiesEqual(leaseFile.identity, binding.leaseIdentity)
    || !leaseFile.bytes.equals(binding.leaseBytes)
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const rootEntries = await readdir(root.path);
  const allowedRoot = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== allowedRoot.size
    || rootEntries.some((entry) => !allowedRoot.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const entries = await readdir(directory.path);
  const allowed = new Set(expectedEntries);
  if (
    entries.length !== allowed.size
    || entries.some((entry) => !allowed.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-output-escape");
}

async function claimWorkerAssignment(binding, ledger) {
  await requireWorkerLeaseState(binding, []);
  const claimPath = path.join(binding.directory.path, WORKER_CLAIM_BASENAME);
  const claimBytes = claimBytesFor(binding.lease, binding.assignment);
  let handle = null;
  try {
    handle = await open(
      claimPath,
      FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | FS_CONSTANTS.O_WRONLY
        | noFollowFlag(),
      0o600,
    );
    const initial = await handle.stat({ bigint: true });
    const record = Object.freeze({
      kind: "file",
      path: claimPath,
      identity: identityFromState(initial),
      byteLength: claimBytes.length,
    });
    if (!record.identity.meaningful || initial.nlink !== 1n) {
      failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    }
    ledger.push(record);
    await handle.writeFile(claimBytes);
    await handle.sync();
    await handle.close();
    handle = null;
    const stable = await readStablePrivateFile(
      claimPath,
      MAX_WORKER_LEASE_BYTES,
      "private-worker-assignment-mismatch",
    );
    if (
      !stable.bytes.equals(claimBytes)
      || !identitiesEqual(stable.identity, record.identity)
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    await requireWorkerLeaseState(binding, [WORKER_CLAIM_BASENAME]);
    return record;
  } catch (error) {
    if (error && error.code === "EEXIST") {
      failAdapter("SAME_HOST", "private-worker-replay");
    }
    throw asAdapterError(
      error,
      "SAME_HOST",
      "private-worker-assignment-mismatch",
    );
  } finally {
    if (handle) await handle.close();
  }
}

async function workerOperation(requestText) {
  const request = parseWorkerRequestText(requestText);
  const binding = await readAndValidateWorkerLease(request);
  const workerLedger = [];
  let claimed = false;
  try {
    claimed = true;
    await claimWorkerAssignment(binding, workerLedger);
    const archivePath = path.join(
      binding.directory.path,
      binding.assignment.archiveFilename,
    );
    if (await pathState(archivePath)) {
      failAdapter("SAME_HOST", "private-worker-replay");
    }
    await preparePublicSourceArchive({
      repo: request.sourceRepositoryPath,
      commit: request.lockedContext.sourceCommit,
      output: archivePath,
    });
    // The archive creator validates its own identity-safe publication, but it
    // does not return that file identity. Keep the post-return observation out
    // of the worker cleanup ledger so a race cannot trick cleanup into deleting
    // a substituted object. The coordinator adopts it only after the response
    // binds the observed identity; otherwise assignment cleanup fails closed.
    const file = await recordOwnedFile(archivePath, []);
    const fileState = await lstat(archivePath, { bigint: true });
    if (
      fileState.isSymbolicLink()
      || !fileState.isFile()
      || fileState.nlink !== 1n
      || !identitiesEqual(file.identity, identityFromState(fileState))
      || !file.identity.meaningful
    ) failAdapter("SAME_HOST", "private-worker-output-escape");
    await requireWorkerLeaseState(binding, [
      WORKER_CLAIM_BASENAME,
      WORKER_ARCHIVE_BASENAME,
    ]);
    const verification = await verifyPublicSourceArchive({
      repo: request.sourceRepositoryPath,
      commit: request.lockedContext.sourceCommit,
      archive: archivePath,
    });
    const transcript = encodeB3VerificationTranscript(
      verification,
      request.lockedContext.sourceCommit,
    );
    const stableArchive = await hashStableRegularFile(
      archivePath,
      "SAME_HOST",
      "private-worker-output-escape",
    );
    if (
      stableArchive.sha256 !== verification.archiveSha256
      || stableArchive.byteLength !== verification.archiveByteLength
    ) failAdapter("SAME_HOST", "private-worker-output-escape");
    await requireWorkerLeaseState(binding, [
      WORKER_CLAIM_BASENAME,
      WORKER_ARCHIVE_BASENAME,
    ]);
    const response = {
      protocol: WORKER_PROTOCOL,
      runId: binding.lease.runId,
      assignmentId: request.assignmentId,
      contextDigest: binding.lease.lockedContextDigest,
      status: "ok",
      archiveSha256: verification.archiveSha256,
      archiveByteLength: verification.archiveByteLength,
      transcriptBase64: transcript.toString("base64"),
      transcriptSha256: sha256Bytes(transcript),
      transcriptByteLength: transcript.length,
      workerPid: process.pid,
      assignedDirectoryIdentity: identityStrings(binding.directory.identity),
      archiveFileIdentity: identityStrings(file.identity),
    };
    let cleanupAvailable = true;
    return Object.freeze({
      response,
      cleanup: async () => {
        if (!cleanupAvailable) return;
        cleanupAvailable = false;
        await cleanupOwnedLedger(workerLedger);
      },
    });
  } catch (error) {
    if (claimed) {
      try {
        await cleanupOwnedLedger(workerLedger);
      } catch {
        throw new PublicSourceArchiveReproducibilityError(
          "CLEANUP",
          "cleanup-incomplete",
        );
      }
    }
    throw asAdapterError(error, "SAME_HOST", "private-worker-output-escape");
  }
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const entry = process.argv[1];
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(entry));
  } catch {
    return false;
  }
}

let privateWorkerFatalTerminationStarted = false;

function terminatePrivateWorkerFatal(error) {
  if (privateWorkerFatalTerminationStarted) process.exit(1);
  privateWorkerFatalTerminationStarted = true;

  const safe = asAdapterError(error, "CLI", "private-worker-unavailable");
  const line = "ERROR " + safe.phase + ": " + safe.reason + "\n";
  try {
    process.removeAllListeners("message");
  } catch {
    // Forced termination must continue even if listener shutdown fails.
  }
  try {
    writeSync(2, Buffer.from(line, "utf8"));
  } catch {
    // Forced termination must continue even if stderr is unavailable.
  }
  try {
    if (process.connected) process.disconnect();
  } catch {
    // Forced termination must continue even if IPC disconnect fails.
  }
  process.exitCode = 1;
  process.exit(1);
}

async function privateWorkerMain() {
  if (
    typeof process.send !== "function"
    || !process.connected
  ) failAdapter("CLI", "private-worker-unavailable");
  const requestText = await new Promise((resolve, reject) => {
    let requestSlotConsumed = false;
    let timeout;
    const onFirstMessage = (message) => {
      requestSlotConsumed = true;
      process.removeListener("message", onFirstMessage);
      clearTimeout(timeout);
      resolve(message);
    };
    timeout = setTimeout(
      () => {
        if (requestSlotConsumed) return;
        process.removeListener("message", onFirstMessage);
        reject(new PublicSourceArchiveReproducibilityError(
          "SAME_HOST", "private-worker-request-invalid",
        ));
      },
      30000,
    );
    process.once("message", onFirstMessage);
  });
  const operation = await workerOperation(requestText);
  const responseText = privateJsonBytes(
    operation.response,
    "private-worker-response-invalid",
  ).toString("utf8");
  if (Buffer.byteLength(responseText, "utf8") > MAX_WORKER_RESPONSE_BYTES) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  try {
    await new Promise((resolve, reject) => {
      process.send(responseText, (error) => error ? reject(error) : resolve());
    });
  } catch {
    await operation.cleanup();
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  process.disconnect();
  process.exitCode = 0;
}

if (isMainModule()) {
  privateWorkerMain().catch(terminatePrivateWorkerFatal);
}
