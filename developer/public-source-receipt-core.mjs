import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as FS_CONSTANTS } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const RECEIPT_KIND = "ieltmps-public-source-receipt";
export const SCHEMA_VERSION = 1;
export const RECEIPT_OUTPUT_SUFFIX = ".source-receipt.json";
export const MAX_ARTIFACTS = 32;

export const CRITICAL_TOOL_PATHS = Object.freeze([
  "developer/prepare-public-source-archive.mjs",
  "developer/prepare-public-source-receipt.mjs",
  "developer/prepare-public-source-tree.mjs",
  "developer/public-source-archive-core.mjs",
  "developer/public-source-manifest.json",
  "developer/public-source-receipt-core.mjs",
  "developer/verify-public-source-archive.mjs",
  "developer/verify-public-source-membership.mjs",
  "developer/verify-public-source-receipt.mjs",
]);

/*
 * Evidence for this deliberately small registry is limited to the authorized
 * production references:
 *
 * - prepare/verify-public-container-context.mjs create and verify the JSON
 *   public-container context receipt;
 * - release.ps1, release.sh, and standalone-release-manifest.mjs explicitly
 *   produce a standalone ZIP and a JSON release receipt.
 *
 * No container-image serialization is registered: those references establish
 * an image workflow, but not one stable file encoding whose bytes can be bound.
 */
export const ARTIFACT_ROLE_FORMAT_REGISTRY = Object.freeze([
  Object.freeze({
    role: "public-container-context-receipt",
    format: "json",
    mediaType: "application/json",
  }),
  Object.freeze({
    role: "standalone-release-archive",
    format: "zip",
    mediaType: "application/zip",
  }),
  Object.freeze({
    role: "standalone-release-receipt",
    format: "json",
    mediaType: "application/json",
  }),
]);

const ARCHIVE_FORMAT = "tar-ustar-v1";
const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9._-]+$/u;
const TEMPORARY_RANDOM_PATTERN = /^[0-9a-f]{32}$/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/u;
const MAX_GIT_BUFFER = 256 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 1024 * 1024;
const FILE_CHUNK_SIZE = 64 * 1024;
const TEMPORARY_CREATE_RETRIES = 8;

const TOP_LEVEL_KEYS = Object.freeze([
  "receiptKind",
  "schemaVersion",
  "source",
  "tooling",
  "artifacts",
  "correspondingSourceComplete",
  "publicationBlocked",
]);
const SOURCE_KEYS = Object.freeze([
  "commit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archive",
]);
const ARCHIVE_KEYS = Object.freeze([
  "format",
  "sha256",
  "byteLength",
  "memberCount",
]);
const TOOLING_KEYS = Object.freeze(["commit", "criticalFiles"]);
const CRITICAL_FILE_KEYS = Object.freeze([
  "path",
  "gitBlobId",
  "sha256",
  "byteLength",
]);
const ARTIFACT_KEYS = Object.freeze([
  "role",
  "format",
  "sha256",
  "byteLength",
]);

const ERROR_MESSAGES = Object.freeze({
  CLI: "invalid command line or imported API options",
  TOOLING: "tooling commit or critical-tool verification failed",
  SOURCE_ARCHIVE: "source archive verification failed",
  ARTIFACT: "artifact-set verification failed",
  RECEIPT_SCHEMA: "restricted receipt schema verification failed",
  OUTPUT_PARENT: "receipt input or output boundary validation failed",
  RECEIPT_WRITE: "temporary receipt creation or write failed",
  RECEIPT_VERIFY: "independent receipt verification failed",
  PUBLISH: "atomic no-replace receipt publication failed",
  CLEANUP: "receipt cleanup identity validation failed",
});

const PUBLICATION_CHECKPOINTS = new Set([
  "before-temp-create-attempt",
  "after-temp-create",
  "before-temp-verify",
  "after-temp-verify",
  "before-publish",
  "after-final-absence-check",
  "after-link",
  "after-temp-unlink",
  "before-final-verify",
  "after-final-verify",
]);

const REGISTRY_KEYS = new Set(
  ARTIFACT_ROLE_FORMAT_REGISTRY.map(({ role, format }) => role + "\0" + format),
);

export class PublicSourceReceiptError extends Error {
  constructor(phase, reason) {
    super(ERROR_MESSAGES[phase] ?? "public source receipt operation failed");
    this.name = "PublicSourceReceiptError";
    this.phase = phase;
    this.reason = reason;
  }
}

export function failReceipt(phase, reason) {
  throw new PublicSourceReceiptError(phase, reason);
}

export function asReceiptError(error, phase, reason) {
  return error instanceof PublicSourceReceiptError
    ? error
    : new PublicSourceReceiptError(phase, reason);
}

export async function inReceiptPhase(phase, reason, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asReceiptError(error, phase, reason);
  }
}

export function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha1GitBlob(value) {
  return createHash("sha1")
    .update(Buffer.from("blob " + value.length + "\0", "ascii"))
    .update(value)
    .digest("hex");
}

export function canonicalNativePath(value) {
  const normalized = path.resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

export function pathsEqual(left, right) {
  return canonicalNativePath(left) === canonicalNativePath(right);
}

export function isInside(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(".." + path.sep)
    && !path.isAbsolute(relative);
}

function safeInteger(value, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function exactKeys(value, expected, phase, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failReceipt(phase, reason + "-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failReceipt(phase, reason + "-keys");
  }
}

function requireLowerHex(value, pattern, reason) {
  if (typeof value !== "string" || !pattern.test(value)) {
    failReceipt("RECEIPT_SCHEMA", reason);
  }
  return value;
}

function requireRegistryToken(value, reason) {
  if (
    typeof value !== "string"
    || !SAFE_TOKEN_PATTERN.test(value)
    || CONTROL_CHARACTER_PATTERN.test(value)
  ) {
    failReceipt("RECEIPT_SCHEMA", reason);
  }
  return value;
}

export function validateArtifactRoleFormat(role, format, phase = "ARTIFACT") {
  if (
    typeof role !== "string"
    || typeof format !== "string"
    || !SAFE_TOKEN_PATTERN.test(role)
    || !SAFE_TOKEN_PATTERN.test(format)
    || !REGISTRY_KEYS.has(role + "\0" + format)
  ) {
    failReceipt(phase, "unknown-role-format");
  }
  return Object.freeze({ role, format });
}

function validateCriticalFiles(entries) {
  if (!Array.isArray(entries) || entries.length !== CRITICAL_TOOL_PATHS.length) {
    failReceipt("RECEIPT_SCHEMA", "critical-file-count");
  }
  return Object.freeze(entries.map((entry, index) => {
    exactKeys(entry, CRITICAL_FILE_KEYS, "RECEIPT_SCHEMA", "critical-file");
    if (entry.path !== CRITICAL_TOOL_PATHS[index]) {
      failReceipt("RECEIPT_SCHEMA", "critical-file-path-order");
    }
    requireLowerHex(entry.gitBlobId, FULL_OBJECT_ID_PATTERN, "critical-git-blob-id");
    requireLowerHex(entry.sha256, SHA256_PATTERN, "critical-sha256");
    if (!safeInteger(entry.byteLength)) {
      failReceipt("RECEIPT_SCHEMA", "critical-byte-length");
    }
    return Object.freeze({
      path: entry.path,
      gitBlobId: entry.gitBlobId,
      sha256: entry.sha256,
      byteLength: entry.byteLength,
    });
  }));
}

export function canonicalizeArtifactIdentities(entries, phase = "ARTIFACT") {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_ARTIFACTS) {
    failReceipt(phase, "artifact-count");
  }
  const roles = new Set();
  const tuples = new Set();
  const hashes = new Set();
  const validated = entries.map((entry) => {
    exactKeys(entry, ARTIFACT_KEYS, phase, "artifact");
    validateArtifactRoleFormat(entry.role, entry.format, phase);
    if (typeof entry.sha256 !== "string" || !SHA256_PATTERN.test(entry.sha256)) {
      failReceipt(phase, "artifact-sha256");
    }
    if (!safeInteger(entry.byteLength)) {
      failReceipt(phase, "artifact-byte-length");
    }
    const tuple = entry.role + "\0" + entry.format;
    if (roles.has(entry.role)) {
      failReceipt(phase, "duplicate-artifact-role");
    }
    if (tuples.has(tuple)) {
      failReceipt(phase, "duplicate-artifact-tuple");
    }
    if (hashes.has(entry.sha256)) {
      failReceipt(phase, "duplicate-artifact-bytes");
    }
    roles.add(entry.role);
    tuples.add(tuple);
    hashes.add(entry.sha256);
    return {
      role: entry.role,
      format: entry.format,
      sha256: entry.sha256,
      byteLength: entry.byteLength,
    };
  });
  validated.sort((left, right) => (
    compareOrdinal(left.role, right.role)
    || compareOrdinal(left.format, right.format)
    || compareOrdinal(left.sha256, right.sha256)
  ));
  return Object.freeze(validated.map((entry) => Object.freeze(entry)));
}

export function validatePublicSourceReceipt(receipt) {
  exactKeys(receipt, TOP_LEVEL_KEYS, "RECEIPT_SCHEMA", "top-level");
  if (receipt.receiptKind !== RECEIPT_KIND) {
    failReceipt("RECEIPT_SCHEMA", "receipt-kind");
  }
  if (receipt.schemaVersion !== SCHEMA_VERSION) {
    failReceipt("RECEIPT_SCHEMA", "schema-version");
  }

  exactKeys(receipt.source, SOURCE_KEYS, "RECEIPT_SCHEMA", "source");
  requireLowerHex(receipt.source.commit, FULL_OBJECT_ID_PATTERN, "source-commit");
  requireLowerHex(receipt.source.manifestSha256, SHA256_PATTERN, "manifest-sha256");
  requireLowerHex(
    receipt.source.membershipReportSha256,
    SHA256_PATTERN,
    "membership-report-sha256",
  );
  if (!safeInteger(receipt.source.membershipCount, { minimum: 1 })) {
    failReceipt("RECEIPT_SCHEMA", "membership-count");
  }
  exactKeys(receipt.source.archive, ARCHIVE_KEYS, "RECEIPT_SCHEMA", "archive");
  if (receipt.source.archive.format !== ARCHIVE_FORMAT) {
    failReceipt("RECEIPT_SCHEMA", "archive-format");
  }
  requireLowerHex(receipt.source.archive.sha256, SHA256_PATTERN, "archive-sha256");
  if (!safeInteger(receipt.source.archive.byteLength)) {
    failReceipt("RECEIPT_SCHEMA", "archive-byte-length");
  }
  if (
    !safeInteger(receipt.source.archive.memberCount, { minimum: 1 })
    || receipt.source.archive.memberCount !== receipt.source.membershipCount
  ) {
    failReceipt("RECEIPT_SCHEMA", "archive-member-count");
  }

  exactKeys(receipt.tooling, TOOLING_KEYS, "RECEIPT_SCHEMA", "tooling");
  requireLowerHex(receipt.tooling.commit, FULL_OBJECT_ID_PATTERN, "tooling-commit");
  const criticalFiles = validateCriticalFiles(receipt.tooling.criticalFiles);
  const artifacts = canonicalizeArtifactIdentities(receipt.artifacts, "RECEIPT_SCHEMA");
  for (let index = 0; index < artifacts.length; index += 1) {
    const observed = receipt.artifacts[index];
    const expected = artifacts[index];
    if (
      observed.role !== expected.role
      || observed.format !== expected.format
      || observed.sha256 !== expected.sha256
      || observed.byteLength !== expected.byteLength
    ) {
      failReceipt("RECEIPT_SCHEMA", "artifact-order");
    }
  }
  if (receipt.correspondingSourceComplete !== false) {
    failReceipt("RECEIPT_SCHEMA", "corresponding-source-complete");
  }
  if (receipt.publicationBlocked !== true) {
    failReceipt("RECEIPT_SCHEMA", "publication-blocked");
  }

  return Object.freeze({
    receiptKind: RECEIPT_KIND,
    schemaVersion: SCHEMA_VERSION,
    source: Object.freeze({
      commit: receipt.source.commit,
      manifestSha256: receipt.source.manifestSha256,
      membershipReportSha256: receipt.source.membershipReportSha256,
      membershipCount: receipt.source.membershipCount,
      archive: Object.freeze({
        format: ARCHIVE_FORMAT,
        sha256: receipt.source.archive.sha256,
        byteLength: receipt.source.archive.byteLength,
        memberCount: receipt.source.archive.memberCount,
      }),
    }),
    tooling: Object.freeze({
      commit: receipt.tooling.commit,
      criticalFiles,
    }),
    artifacts,
    correspondingSourceComplete: false,
    publicationBlocked: true,
  });
}

export function encodeCanonicalReceipt(receipt) {
  const validated = validatePublicSourceReceipt(receipt);
  const bytes = Buffer.from(JSON.stringify(validated) + "\n", "utf8");
  if (
    bytes.length > MAX_RECEIPT_BYTES
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
  ) {
    failReceipt("RECEIPT_SCHEMA", "canonical-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failReceipt("RECEIPT_SCHEMA", "canonical-ascii");
    }
  }
  return bytes;
}

export function buildPublicSourceReceipt({
  sourceVerification,
  toolingCommit,
  criticalFiles,
  artifacts,
} = {}) {
  if (
    !sourceVerification
    || typeof sourceVerification !== "object"
    || sourceVerification.archiveVerified !== true
    || sourceVerification.membershipValid !== true
    || sourceVerification.correspondingSourceComplete !== false
    || sourceVerification.publicationBlocked !== true
    || sourceVerification.archiveFormat !== ARCHIVE_FORMAT
    || sourceVerification.archiveMemberCount !== sourceVerification.membershipCount
  ) {
    failReceipt("SOURCE_ARCHIVE", "b3-result-shape");
  }
  const receipt = {
    receiptKind: RECEIPT_KIND,
    schemaVersion: SCHEMA_VERSION,
    source: {
      commit: sourceVerification.sourceCommit,
      manifestSha256: sourceVerification.manifestSha256,
      membershipReportSha256: sourceVerification.membershipReportSha256,
      membershipCount: sourceVerification.membershipCount,
      archive: {
        format: sourceVerification.archiveFormat,
        sha256: sourceVerification.archiveSha256,
        byteLength: sourceVerification.archiveByteLength,
        memberCount: sourceVerification.archiveMemberCount,
      },
    },
    tooling: {
      commit: toolingCommit,
      criticalFiles,
    },
    artifacts,
    correspondingSourceComplete: false,
    publicationBlocked: true,
  };
  return validatePublicSourceReceipt(receipt);
}

function sanitizedGitEnvironment() {
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
  environment.LC_ALL = "C";
  environment.LANG = "C";
  return environment;
}

export function sanitizedNodeEnvironment() {
  const environment = sanitizedGitEnvironment();
  delete environment.NODE_OPTIONS;
  delete environment.NODE_PATH;
  return environment;
}

function runGit(repoRoot, args, { input = undefined, allowFailure = false } = {}) {
  const result = spawnSync(
    "git",
    ["--no-replace-objects", "-C", repoRoot, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || (!allowFailure && result.status !== 0)) {
    failReceipt("TOOLING", "git-" + args[0]);
  }
  return result;
}

export async function pathState(targetPath) {
  try {
    return await lstat(targetPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export function identityFromState(state) {
  if (!state || typeof state !== "object") {
    failReceipt("CLEANUP", "identity-state");
  }
  return Object.freeze({
    device: state.dev,
    inode: state.ino,
    meaningful: state.dev !== 0n || state.ino !== 0n,
  });
}

export function identitiesEqual(left, right) {
  if (!left || !right) {
    return false;
  }
  if (!left.meaningful || !right.meaningful) {
    return false;
  }
  return left.device === right.device && left.inode === right.inode;
}

function identityMatches(identity, state) {
  return identitiesEqual(identity, identityFromState(state));
}

async function inspectRealDirectory(targetPath, phase, reason) {
  const expectedPath = path.resolve(targetPath);
  const state = await pathState(expectedPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    failReceipt(phase, reason + "-directory");
  }
  const resolved = await realpath(expectedPath);
  if (!pathsEqual(resolved, expectedPath)) {
    failReceipt(phase, reason + "-reparse");
  }
  return Object.freeze({
    expectedPath,
    canonicalPath: path.resolve(resolved),
    identity: identityFromState(state),
  });
}

function parentChainPaths(parentPath) {
  const normalizedParent = path.resolve(parentPath);
  const root = path.parse(normalizedParent).root;
  if (!root) {
    failReceipt("OUTPUT_PARENT", "parent-root");
  }
  const values = [path.resolve(root)];
  const relative = path.relative(root, normalizedParent);
  if (!relative) {
    return values;
  }
  let current = root;
  for (const component of relative.split(path.sep)) {
    if (!component || component === "." || component === "..") {
      failReceipt("OUTPUT_PARENT", "parent-component");
    }
    current = path.join(current, component);
    values.push(path.resolve(current));
  }
  return values;
}

export async function validateParentChain(
  parentPath,
  recorded = null,
  phase = "OUTPUT_PARENT",
) {
  const chainPaths = parentChainPaths(parentPath);
  const inspected = [];
  for (let index = 0; index < chainPaths.length; index += 1) {
    const record = await inspectRealDirectory(chainPaths[index], phase, "parent");
    if (
      recorded
      && (
        recorded.length !== chainPaths.length
        || !pathsEqual(recorded[index].expectedPath, record.expectedPath)
        || !pathsEqual(recorded[index].canonicalPath, record.canonicalPath)
        || !identitiesEqual(recorded[index].identity, record.identity)
      )
    ) {
      failReceipt(phase, "parent-identity");
    }
    inspected.push(record);
  }
  return Object.freeze(inspected);
}

function validateFinalComponent(targetPath, phase) {
  const name = path.basename(targetPath);
  if (
    !name
    || name === "."
    || name === ".."
    || CONTROL_CHARACTER_PATTERN.test(name)
    || name.includes(":")
    || name.includes("/")
    || name.includes("\\")
    || name.endsWith(".")
    || name.endsWith(" ")
    || WINDOWS_RESERVED_NAME_PATTERN.test(name)
  ) {
    failReceipt(phase, "final-component");
  }
  return name;
}

function validateAbsoluteNormalizedPath(value, phase) {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    failReceipt(phase, "absolute-path");
  }
  if (
    process.platform === "win32"
    && (
      value.startsWith("\\\\")
      || value.startsWith("//")
      || value.startsWith("\\\\?\\")
      || value.startsWith("\\\\.\\")
    )
  ) {
    failReceipt(phase, "path-namespace");
  }
  const normalized = path.normalize(value);
  const resolved = path.resolve(value);
  if (normalized !== value || !pathsEqual(resolved, value)) {
    failReceipt(phase, "normalized-path");
  }
  const parentPath = path.dirname(resolved);
  if (pathsEqual(parentPath, resolved)) {
    failReceipt(phase, "filesystem-root");
  }
  return Object.freeze({
    targetPath: resolved,
    parentPath,
    finalBasename: validateFinalComponent(resolved, phase),
  });
}

export async function validateRepositoryRoot(repoArgument) {
  const syntax = validateAbsoluteNormalizedPath(repoArgument, "TOOLING");
  const root = syntax.targetPath;
  await inspectRealDirectory(root, "TOOLING", "repository-root");
  const reported = runGit(root, ["rev-parse", "--show-toplevel"])
    .stdout.toString("utf8").trim();
  if (!pathsEqual(reported, root)) {
    failReceipt("TOOLING", "repository-root-exact");
  }
  return root;
}

export function validateFullCommit(repoRoot, value, phase = "TOOLING") {
  if (typeof value !== "string" || !FULL_OBJECT_ID_PATTERN.test(value)) {
    failReceipt(phase, "full-lowercase-commit");
  }
  const type = runGit(repoRoot, ["cat-file", "-t", value])
    .stdout.toString("ascii").trim();
  if (type !== "commit") {
    failReceipt(phase, "commit-object-type");
  }
  return value;
}

function parseLsTreeRecord(record) {
  const tab = record.indexOf(0x09);
  if (tab < 0) {
    failReceipt("TOOLING", "ls-tree-record");
  }
  const header = record.subarray(0, tab).toString("ascii").split(" ");
  if (header.length !== 3) {
    failReceipt("TOOLING", "ls-tree-header");
  }
  const [mode, type, objectId] = header;
  const relativePath = record.subarray(tab + 1).toString("utf8");
  if (
    (mode !== "100644" && mode !== "100755")
    || type !== "blob"
    || !FULL_OBJECT_ID_PATTERN.test(objectId)
    || !CRITICAL_TOOL_PATHS.includes(relativePath)
  ) {
    failReceipt("TOOLING", "critical-tree-entry");
  }
  return Object.freeze({ mode, type, objectId, path: relativePath });
}

function splitNullRecords(buffer) {
  const records = [];
  let offset = 0;
  while (offset < buffer.length) {
    const end = buffer.indexOf(0, offset);
    if (end < 0) {
      failReceipt("TOOLING", "git-nul-record");
    }
    if (end > offset) {
      records.push(buffer.subarray(offset, end));
    }
    offset = end + 1;
  }
  return records;
}

function readBlobBatch(repoRoot, objectIds) {
  const result = runGit(
    repoRoot,
    ["cat-file", "--batch"],
    { input: Buffer.from(objectIds.join("\n") + "\n", "ascii") },
  );
  const blobs = new Map();
  let offset = 0;
  for (const requestedId of objectIds) {
    const headerEnd = result.stdout.indexOf(0x0a, offset);
    if (headerEnd < 0) {
      failReceipt("TOOLING", "cat-file-header");
    }
    const parts = result.stdout.subarray(offset, headerEnd).toString("ascii").split(" ");
    const size = Number(parts[2]);
    if (
      parts.length !== 3
      || parts[0] !== requestedId
      || parts[1] !== "blob"
      || !safeInteger(size)
    ) {
      failReceipt("TOOLING", "cat-file-object");
    }
    const contentStart = headerEnd + 1;
    const contentEnd = contentStart + size;
    if (contentEnd >= result.stdout.length || result.stdout[contentEnd] !== 0x0a) {
      failReceipt("TOOLING", "cat-file-truncated");
    }
    const bytes = Buffer.from(result.stdout.subarray(contentStart, contentEnd));
    if (bytes.length !== size || sha1GitBlob(bytes) !== requestedId) {
      failReceipt("TOOLING", "git-blob-identity");
    }
    blobs.set(requestedId, bytes);
    offset = contentEnd + 1;
  }
  if (offset !== result.stdout.length) {
    failReceipt("TOOLING", "cat-file-trailing");
  }
  return blobs;
}

export function deriveCriticalToolIdentities(repoRoot, toolingCommit) {
  validateFullCommit(repoRoot, toolingCommit, "TOOLING");
  const result = runGit(repoRoot, [
    "ls-tree",
    "-z",
    "--full-tree",
    toolingCommit,
    "--",
    ...CRITICAL_TOOL_PATHS,
  ]);
  const entries = splitNullRecords(result.stdout).map(parseLsTreeRecord);
  entries.sort((left, right) => compareOrdinal(left.path, right.path));
  if (
    entries.length !== CRITICAL_TOOL_PATHS.length
    || entries.some((entry, index) => entry.path !== CRITICAL_TOOL_PATHS[index])
  ) {
    failReceipt("TOOLING", "critical-tool-set");
  }
  const objectIds = entries.map((entry) => entry.objectId);
  const blobMap = readBlobBatch(repoRoot, objectIds);
  const records = entries.map((entry) => {
    const bytes = blobMap.get(entry.objectId);
    if (!bytes) {
      failReceipt("TOOLING", "critical-blob-missing");
    }
    return Object.freeze({
      path: entry.path,
      gitMode: entry.mode,
      gitBlobId: entry.objectId,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      blobBytes: bytes,
    });
  });
  const criticalFiles = Object.freeze(records.map((record) => Object.freeze({
    path: record.path,
    gitBlobId: record.gitBlobId,
    sha256: record.sha256,
    byteLength: record.byteLength,
  })));
  return Object.freeze({ records: Object.freeze(records), criticalFiles });
}

function exactHookObject(value, allowedKeys) {
  if (value === undefined) {
    return Object.freeze({});
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failReceipt("CLI", "test-hooks-object");
  }
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!allowedKeys.has(key) || typeof value[key] !== "function") {
      failReceipt("CLI", "test-hook-key");
    }
  }
  return Object.freeze({ ...value });
}

export function normalizeVerifierTestHooks(value) {
  return exactHookObject(value, new Set([
    "verifyToolingCommitSignature",
    "checkpoint",
  ]));
}

export function normalizeGeneratorTestHooks(value) {
  return exactHookObject(value, new Set([
    "verifyToolingCommitSignature",
    "checkpoint",
    "link",
  ]));
}

export async function invokeTestCheckpoint(hooks, checkpoint, context, phase) {
  if (!hooks?.checkpoint) {
    return;
  }
  const returned = await hooks.checkpoint(Object.freeze({ checkpoint, ...context }));
  if (returned !== undefined) {
    failReceipt(phase, "checkpoint-return-value");
  }
}

export async function verifyToolingCommitSignature(
  repoRoot,
  toolingCommit,
  hooks = Object.freeze({}),
) {
  validateFullCommit(repoRoot, toolingCommit, "TOOLING");
  if (hooks.verifyToolingCommitSignature) {
    let returned;
    try {
      returned = await hooks.verifyToolingCommitSignature(Object.freeze({
        repo: repoRoot,
        toolingCommit,
      }));
    } catch (error) {
      throw asReceiptError(error, "TOOLING", "tooling-commit-signature");
    }
    if (returned !== undefined) {
      failReceipt("TOOLING", "signature-adapter-return-value");
    }
    return true;
  }
  const result = runGit(
    repoRoot,
    ["verify-commit", "--raw", toolingCommit],
    { allowFailure: true },
  );
  if (result.error || result.status !== 0) {
    failReceipt("TOOLING", "tooling-commit-signature");
  }
  return true;
}

export function assertNoModuleRedirection() {
  if (
    (typeof process.env.NODE_OPTIONS === "string" && process.env.NODE_OPTIONS.length > 0)
    || (typeof process.env.NODE_PATH === "string" && process.env.NODE_PATH.length > 0)
  ) {
    failReceipt("TOOLING", "node-environment-redirection");
  }
  const forbiddenExact = new Set([
    "-r",
    "--require",
    "--loader",
    "--experimental-loader",
    "--import",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
  ]);
  for (const argument of process.execArgv) {
    if (
      forbiddenExact.has(argument)
      || argument.startsWith("-r")
      || argument.startsWith("--require=")
      || argument.startsWith("--loader=")
      || argument.startsWith("--experimental-loader=")
      || argument.startsWith("--import=")
    ) {
      failReceipt("TOOLING", "node-process-redirection");
    }
  }
}

function gitPath(repoRoot, name) {
  const reported = runGit(repoRoot, ["rev-parse", "--git-path", name])
    .stdout.toString("utf8").trim();
  return path.isAbsolute(reported) ? path.resolve(reported) : path.resolve(repoRoot, reported);
}

async function assertCleanToolingWorktree(repoRoot, toolingCommit) {
  const head = runGit(repoRoot, ["rev-parse", "HEAD"])
    .stdout.toString("ascii").trim();
  if (head !== toolingCommit) {
    failReceipt("TOOLING", "head-tooling-commit");
  }
  const status = runGit(repoRoot, [
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
  ]).stdout;
  if (status.length !== 0) {
    failReceipt("TOOLING", "dirty-worktree");
  }
  if (runGit(repoRoot, ["ls-files", "-u", "-z"]).stdout.length !== 0) {
    failReceipt("TOOLING", "unmerged-index");
  }
  if (
    runGit(repoRoot, ["for-each-ref", "--format=%(refname)", "refs/replace/"])
      .stdout.toString("utf8").trim().length > 0
  ) {
    failReceipt("TOOLING", "replacement-object-ref");
  }
  const operations = [
    "MERGE_HEAD",
    "rebase-merge",
    "rebase-apply",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_LOG",
    "sequencer",
  ];
  for (const operation of operations) {
    if (await pathState(gitPath(repoRoot, operation))) {
      failReceipt("TOOLING", "active-git-operation");
    }
  }
}

function noFollowFlag() {
  return process.platform !== "win32" && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

function requireRegularState(
  state,
  identity,
  expectedLength,
  phase,
  reason,
  expectedLinks = 1,
) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || !identityMatches(identity, state)
    || state.size !== BigInt(expectedLength)
    || state.nlink !== BigInt(expectedLinks)
  ) {
    failReceipt(phase, reason);
  }
}

async function hashOpenRegularFile(
  targetPath,
  boundary,
  phase,
  reason,
  hooks = null,
) {
  let handle = null;
  try {
    const expectedLinks = boundary.expectedLinks ?? 1;
    if (!safeInteger(expectedLinks, { minimum: 1 })) {
      failReceipt(phase, reason + "-links");
    }
    handle = await open(targetPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    requireRegularState(
      before,
      boundary.identity,
      boundary.byteLength,
      phase,
      reason,
      expectedLinks,
    );
    await invokeTestCheckpoint(
      hooks,
      "after-file-open",
      Object.freeze({ kind: boundary.kind ?? "file" }),
      phase,
    );
    const digest = createHash("sha256");
    let offset = 0;
    while (offset < boundary.byteLength) {
      const chunk = Buffer.alloc(Math.min(FILE_CHUNK_SIZE, boundary.byteLength - offset));
      const result = await handle.read(chunk, 0, chunk.length, null);
      if (!result || result.bytesRead <= 0 || result.bytesRead > chunk.length) {
        failReceipt(phase, reason + "-read");
      }
      digest.update(chunk.subarray(0, result.bytesRead));
      offset += result.bytesRead;
    }
    const trailing = Buffer.alloc(1);
    const trailingResult = await handle.read(trailing, 0, 1, null);
    if (!trailingResult || trailingResult.bytesRead !== 0) {
      failReceipt(phase, reason + "-trailing");
    }
    const after = await handle.stat({ bigint: true });
    requireRegularState(
      after,
      boundary.identity,
      boundary.byteLength,
      phase,
      reason,
      expectedLinks,
    );
    await validateParentChain(boundary.parentPath, boundary.parentChain, phase);
    const finalState = await pathState(targetPath);
    requireRegularState(
      finalState,
      boundary.identity,
      boundary.byteLength,
      phase,
      reason,
      expectedLinks,
    );
    const resolved = await realpath(targetPath);
    if (!pathsEqual(resolved, targetPath)) {
      failReceipt(phase, reason + "-reparse");
    }
    await invokeTestCheckpoint(
      hooks,
      "after-file-hash",
      Object.freeze({ kind: boundary.kind ?? "file" }),
      phase,
    );
    return Object.freeze({
      sha256: digest.digest("hex"),
      byteLength: offset,
    });
  } finally {
    if (handle) {
      await handle.close();
    }
  }
}

async function inspectCanonicalToolFile(repoRoot, record) {
  const targetPath = path.join(repoRoot, ...record.path.split("/"));
  if (!isInside(repoRoot, targetPath)) {
    failReceipt("TOOLING", "critical-worktree-containment");
  }
  const state = await pathState(targetPath);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size !== BigInt(record.byteLength)
  ) {
    failReceipt("TOOLING", "critical-worktree-state");
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failReceipt("TOOLING", "critical-worktree-reparse");
  }
  const boundary = Object.freeze({
    targetPath,
    parentPath: path.dirname(targetPath),
    parentChain: await validateParentChain(path.dirname(targetPath), null, "TOOLING"),
    identity: identityFromState(state),
    byteLength: record.byteLength,
    kind: "tool",
  });
  const identity = await hashOpenRegularFile(
    targetPath,
    boundary,
    "TOOLING",
    "critical-worktree-identity",
  );
  if (identity.sha256 !== record.sha256) {
    failReceipt("TOOLING", "critical-worktree-bytes");
  }
  return targetPath;
}

export async function verifyToolingBootstrap({
  repo,
  toolingCommit,
  entryRelativePath,
  entryModulePath,
  invocationPath,
} = {}) {
  assertNoModuleRedirection();
  const repoRoot = await validateRepositoryRoot(repo);
  validateFullCommit(repoRoot, toolingCommit, "TOOLING");
  await assertCleanToolingWorktree(repoRoot, toolingCommit);
  const derived = deriveCriticalToolIdentities(repoRoot, toolingCommit);
  for (const record of derived.records) {
    await inspectCanonicalToolFile(repoRoot, record);
  }

  if (!CRITICAL_TOOL_PATHS.includes(entryRelativePath)) {
    failReceipt("TOOLING", "entrypoint-role");
  }
  const expectedEntry = path.join(repoRoot, ...entryRelativePath.split("/"));
  const expectedCore = path.join(
    repoRoot,
    "developer",
    "public-source-receipt-core.mjs",
  );
  if (
    !pathsEqual(entryModulePath, expectedEntry)
    || !pathsEqual(fileURLToPath(import.meta.url), expectedCore)
  ) {
    failReceipt("TOOLING", "canonical-module-location");
  }
  if (
    invocationPath !== undefined
    && (
      typeof invocationPath !== "string"
      || !pathsEqual(path.resolve(invocationPath), expectedEntry)
      || path.resolve(invocationPath) !== expectedEntry
    )
  ) {
    failReceipt("TOOLING", "entrypoint-alias");
  }
  return Object.freeze({ repoRoot, toolingCommit, ...derived });
}

export function requireCriticalFilesEqual(actual, expected, phase = "TOOLING") {
  const left = validateCriticalFiles(actual);
  const right = validateCriticalFiles(expected);
  for (let index = 0; index < left.length; index += 1) {
    for (const key of CRITICAL_FILE_KEYS) {
      if (left[index][key] !== right[index][key]) {
        failReceipt(phase, "critical-file-mismatch");
      }
    }
  }
}

async function verifyDirectoryIdentity(targetPath, identity, phase, reason) {
  const state = await pathState(targetPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory() || !identityMatches(identity, state)) {
    failReceipt(phase, reason);
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failReceipt(phase, reason + "-reparse");
  }
}

async function writeAll(handle, bytes, phase, reason) {
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.write(bytes, offset, bytes.length - offset, null);
    if (!result || result.bytesWritten <= 0 || result.bytesWritten > bytes.length - offset) {
      failReceipt(phase, reason);
    }
    offset += result.bytesWritten;
  }
}

export async function materializeVerifiedToolDirectory(records) {
  if (
    !Array.isArray(records)
    || records.length !== CRITICAL_TOOL_PATHS.length
    || records.some((record, index) => record.path !== CRITICAL_TOOL_PATHS[index])
  ) {
    failReceipt("TOOLING", "materialization-records");
  }
  const temporaryParent = path.resolve(os.tmpdir());
  await validateParentChain(temporaryParent, null, "TOOLING");
  const rootPath = await mkdtemp(path.join(temporaryParent, "ieltmps-source-receipt-tools-"));
  const rootState = await pathState(rootPath);
  if (!rootState || rootState.isSymbolicLink() || !rootState.isDirectory()) {
    failReceipt("TOOLING", "tool-root-create");
  }
  const rootIdentity = identityFromState(rootState);
  const developerPath = path.join(rootPath, "developer");
  const fileRecords = [];
  let developerIdentity = null;
  let primaryError = null;
  try {
    await mkdir(developerPath, { mode: 0o700 });
    const developerState = await pathState(developerPath);
    if (!developerState || developerState.isSymbolicLink() || !developerState.isDirectory()) {
      failReceipt("TOOLING", "tool-directory-create");
    }
    developerIdentity = identityFromState(developerState);
    for (const record of records) {
      const targetPath = path.join(rootPath, ...record.path.split("/"));
      if (!pathsEqual(path.dirname(targetPath), developerPath)) {
        failReceipt("TOOLING", "tool-materialization-path");
      }
      let handle = null;
      try {
        handle = await open(
          targetPath,
          FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY | noFollowFlag(),
          0o600,
        );
        await writeAll(handle, record.blobBytes, "TOOLING", "tool-materialization-write");
        await handle.datasync();
        await handle.sync();
        await handle.close();
        handle = null;
      } finally {
        if (handle) {
          await handle.close();
        }
      }
      const state = await pathState(targetPath);
      if (
        !state
        || state.isSymbolicLink()
        || !state.isFile()
        || state.nlink !== 1n
        || state.size !== BigInt(record.byteLength)
      ) {
        failReceipt("TOOLING", "tool-materialization-state");
      }
      const fileRecord = Object.freeze({
        path: targetPath,
        relativePath: record.path,
        identity: identityFromState(state),
        sha256: record.sha256,
        byteLength: record.byteLength,
      });
      const hashed = await hashOpenRegularFile(
        targetPath,
        Object.freeze({
          targetPath,
          parentPath: developerPath,
          parentChain: await validateParentChain(developerPath, null, "TOOLING"),
          identity: fileRecord.identity,
          byteLength: fileRecord.byteLength,
          kind: "materialized-tool",
        }),
        "TOOLING",
        "tool-materialization-readback",
      );
      if (hashed.sha256 !== record.sha256) {
        failReceipt("TOOLING", "tool-materialization-hash");
      }
      fileRecords.push(fileRecord);
    }
    return Object.freeze({
      rootPath,
      developerPath,
      rootIdentity,
      developerIdentity,
      fileRecords: Object.freeze(fileRecords),
    });
  } catch (error) {
    primaryError = asReceiptError(error, "TOOLING", "tool-materialization");
  }
  const partial = Object.freeze({
    rootPath,
    developerPath,
    rootIdentity,
    developerIdentity,
    fileRecords: Object.freeze(fileRecords),
  });
  try {
    await cleanupVerifiedToolDirectory(partial);
  } catch {
    throw new PublicSourceReceiptError("CLEANUP", "tool-materialization-cleanup");
  }
  throw primaryError;
}

export async function verifyMaterializedToolDirectory(rootPath, criticalFiles) {
  const syntax = validateAbsoluteNormalizedPath(rootPath, "TOOLING");
  const rootRecord = await inspectRealDirectory(syntax.targetPath, "TOOLING", "verified-tool-root");
  const developerPath = path.join(rootRecord.expectedPath, "developer");
  await inspectRealDirectory(developerPath, "TOOLING", "verified-tool-directory");
  const validated = validateCriticalFiles(criticalFiles);
  for (const entry of validated) {
    const targetPath = path.join(rootRecord.expectedPath, ...entry.path.split("/"));
    const state = await pathState(targetPath);
    if (
      !state
      || state.isSymbolicLink()
      || !state.isFile()
      || state.nlink !== 1n
      || state.size !== BigInt(entry.byteLength)
    ) {
      failReceipt("TOOLING", "verified-tool-state");
    }
    const resolved = await realpath(targetPath);
    if (!pathsEqual(resolved, targetPath)) {
      failReceipt("TOOLING", "verified-tool-reparse");
    }
    const hashed = await hashOpenRegularFile(
      targetPath,
      Object.freeze({
        targetPath,
        parentPath: developerPath,
        parentChain: await validateParentChain(developerPath, null, "TOOLING"),
        identity: identityFromState(state),
        byteLength: entry.byteLength,
        kind: "verified-tool",
      }),
      "TOOLING",
      "verified-tool-identity",
    );
    if (hashed.sha256 !== entry.sha256) {
      failReceipt("TOOLING", "verified-tool-hash");
    }
  }
  return true;
}

export async function cleanupVerifiedToolDirectory(directory) {
  if (!directory || typeof directory !== "object") {
    failReceipt("CLEANUP", "tool-cleanup-record");
  }
  for (const record of [...directory.fileRecords].reverse()) {
    const state = await pathState(record.path);
    if (!state) {
      continue;
    }
    if (
      state.isSymbolicLink()
      || !state.isFile()
      || state.nlink !== 1n
      || state.size !== BigInt(record.byteLength)
      || !identityMatches(record.identity, state)
    ) {
      failReceipt("CLEANUP", "tool-file-identity");
    }
    const resolved = await realpath(record.path);
    if (!pathsEqual(resolved, record.path)) {
      failReceipt("CLEANUP", "tool-file-reparse");
    }
    const hashed = await hashOpenRegularFile(
      record.path,
      Object.freeze({
        targetPath: record.path,
        parentPath: directory.developerPath,
        parentChain: await validateParentChain(directory.developerPath, null, "CLEANUP"),
        identity: record.identity,
        byteLength: record.byteLength,
        kind: "tool-cleanup",
      }),
      "CLEANUP",
      "tool-file-hash",
    );
    if (hashed.sha256 !== record.sha256) {
      failReceipt("CLEANUP", "tool-file-bytes");
    }
    await unlink(record.path);
    if (await pathState(record.path)) {
      failReceipt("CLEANUP", "tool-file-unlink");
    }
  }
  if (directory.developerIdentity) {
    await verifyDirectoryIdentity(
      directory.developerPath,
      directory.developerIdentity,
      "CLEANUP",
      "tool-directory-identity",
    );
    await rmdir(directory.developerPath);
  }
  await verifyDirectoryIdentity(
    directory.rootPath,
    directory.rootIdentity,
    "CLEANUP",
    "tool-root-identity",
  );
  await rmdir(directory.rootPath);
  if (await pathState(directory.rootPath)) {
    failReceipt("CLEANUP", "tool-root-remove");
  }
}

export async function validateExternalFile(
  repoRoot,
  targetArgument,
  {
    phase,
    reason,
    suffix = null,
    maximumLength = Number.MAX_SAFE_INTEGER,
    kind = "file",
  },
) {
  const syntax = validateAbsoluteNormalizedPath(targetArgument, phase);
  if (suffix !== null && !syntax.finalBasename.endsWith(suffix)) {
    failReceipt(phase, reason + "-suffix");
  }
  if (pathsEqual(repoRoot, syntax.targetPath) || isInside(repoRoot, syntax.targetPath)) {
    failReceipt(phase, reason + "-repository-containment");
  }
  const parentChain = await validateParentChain(syntax.parentPath, null, phase);
  const canonicalTarget = path.join(parentChain.at(-1).canonicalPath, syntax.finalBasename);
  if (pathsEqual(repoRoot, canonicalTarget) || isInside(repoRoot, canonicalTarget)) {
    failReceipt(phase, reason + "-canonical-containment");
  }
  const state = await pathState(syntax.targetPath);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size < 0n
    || state.size > BigInt(maximumLength)
  ) {
    failReceipt(phase, reason + "-state");
  }
  const resolved = await realpath(syntax.targetPath);
  if (!pathsEqual(resolved, syntax.targetPath)) {
    failReceipt(phase, reason + "-reparse");
  }
  return Object.freeze({
    ...syntax,
    parentChain,
    identity: identityFromState(state),
    byteLength: Number(state.size),
    kind,
  });
}

export async function hashArtifactInputs(repoRoot, artifacts, hooks = null) {
  if (!Array.isArray(artifacts) || artifacts.length < 1 || artifacts.length > MAX_ARTIFACTS) {
    failReceipt("ARTIFACT", "artifact-count");
  }
  const roles = new Set();
  const tuples = new Set();
  const hashed = [];
  for (const artifact of artifacts) {
    if (
      !artifact
      || typeof artifact !== "object"
      || Array.isArray(artifact)
      || Object.keys(artifact).length !== 3
      || !Object.hasOwn(artifact, "role")
      || !Object.hasOwn(artifact, "format")
      || !Object.hasOwn(artifact, "path")
    ) {
      failReceipt("ARTIFACT", "artifact-input-shape");
    }
    validateArtifactRoleFormat(artifact.role, artifact.format, "ARTIFACT");
    const tuple = artifact.role + "\0" + artifact.format;
    if (roles.has(artifact.role)) {
      failReceipt("ARTIFACT", "duplicate-artifact-role");
    }
    if (tuples.has(tuple)) {
      failReceipt("ARTIFACT", "duplicate-artifact-tuple");
    }
    roles.add(artifact.role);
    tuples.add(tuple);
    const boundary = await validateExternalFile(repoRoot, artifact.path, {
      phase: "ARTIFACT",
      reason: "artifact-input",
      kind: "artifact",
    });
    const identity = await hashOpenRegularFile(
      boundary.targetPath,
      boundary,
      "ARTIFACT",
      "artifact-identity",
      hooks,
    );
    hashed.push({
      role: artifact.role,
      format: artifact.format,
      sha256: identity.sha256,
      byteLength: identity.byteLength,
    });
  }
  return canonicalizeArtifactIdentities(hashed, "ARTIFACT");
}

export async function readReceiptInput(repoRoot, receiptPath) {
  const boundary = await validateExternalFile(repoRoot, receiptPath, {
    phase: "RECEIPT_VERIFY",
    reason: "receipt-input",
    suffix: RECEIPT_OUTPUT_SUFFIX,
    maximumLength: MAX_RECEIPT_BYTES,
    kind: "receipt",
  });
  let handle = null;
  try {
    handle = await open(boundary.targetPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    requireRegularState(
      before,
      boundary.identity,
      boundary.byteLength,
      "RECEIPT_VERIFY",
      "receipt-input-identity",
    );
    const bytes = Buffer.alloc(boundary.byteLength);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!result || result.bytesRead <= 0 || result.bytesRead > bytes.length - offset) {
        failReceipt("RECEIPT_VERIFY", "receipt-input-read");
      }
      offset += result.bytesRead;
    }
    const trailing = Buffer.alloc(1);
    const trailingResult = await handle.read(trailing, 0, 1, null);
    if (!trailingResult || trailingResult.bytesRead !== 0) {
      failReceipt("RECEIPT_VERIFY", "receipt-input-trailing");
    }
    const after = await handle.stat({ bigint: true });
    requireRegularState(
      after,
      boundary.identity,
      boundary.byteLength,
      "RECEIPT_VERIFY",
      "receipt-input-identity",
    );
    await validateParentChain(boundary.parentPath, boundary.parentChain, "RECEIPT_VERIFY");
    const pathAfter = await pathState(boundary.targetPath);
    requireRegularState(
      pathAfter,
      boundary.identity,
      boundary.byteLength,
      "RECEIPT_VERIFY",
      "receipt-input-identity",
    );
    return Object.freeze({
      bytes,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      boundary,
    });
  } finally {
    if (handle) {
      await handle.close();
    }
  }
}

function validateOutputBoundarySyntax(repoRoot, outputArgument) {
  const syntax = validateAbsoluteNormalizedPath(outputArgument, "OUTPUT_PARENT");
  if (!syntax.finalBasename.endsWith(RECEIPT_OUTPUT_SUFFIX)) {
    failReceipt("OUTPUT_PARENT", "receipt-output-suffix");
  }
  if (pathsEqual(repoRoot, syntax.targetPath) || isInside(repoRoot, syntax.targetPath)) {
    failReceipt("OUTPUT_PARENT", "receipt-output-repository-containment");
  }
  return syntax;
}

async function validateOutputBoundary(repoRoot, outputArgument) {
  const syntax = validateOutputBoundarySyntax(repoRoot, outputArgument);
  const parentChain = await validateParentChain(syntax.parentPath, null, "OUTPUT_PARENT");
  const canonicalTarget = path.join(parentChain.at(-1).canonicalPath, syntax.finalBasename);
  if (pathsEqual(repoRoot, canonicalTarget) || isInside(repoRoot, canonicalTarget)) {
    failReceipt("OUTPUT_PARENT", "receipt-output-canonical-containment");
  }
  if (await pathState(syntax.targetPath)) {
    failReceipt("OUTPUT_PARENT", "receipt-output-exists");
  }
  return Object.freeze({
    ...syntax,
    canonicalTarget,
    canonicalParent: parentChain.at(-1).canonicalPath,
    parentChain,
  });
}

function temporaryBasename(finalBasename, randomPart) {
  return "." + finalBasename + ".ieltmps-source-receipt-tmp-"
    + randomPart + RECEIPT_OUTPUT_SUFFIX;
}

function validTemporaryBasename(finalBasename, value) {
  const prefix = "." + finalBasename + ".ieltmps-source-receipt-tmp-";
  return value.startsWith(prefix)
    && value.endsWith(RECEIPT_OUTPUT_SUFFIX)
    && value.length === prefix.length + 32 + RECEIPT_OUTPUT_SUFFIX.length
    && TEMPORARY_RANDOM_PATTERN.test(
      value.slice(prefix.length, -RECEIPT_OUTPUT_SUFFIX.length),
    );
}

async function createTemporaryReceipt(output, hooks) {
  for (let attempt = 0; attempt < TEMPORARY_CREATE_RETRIES; attempt += 1) {
    const randomPart = randomBytes(16).toString("hex");
    const basename = temporaryBasename(output.finalBasename, randomPart);
    if (!validTemporaryBasename(output.finalBasename, basename)) {
      failReceipt("RECEIPT_WRITE", "temporary-name");
    }
    const temporaryPath = path.join(output.parentPath, basename);
    await invokeTestCheckpoint(
      hooks,
      "before-temp-create-attempt",
      Object.freeze({ attempt, temporaryPath, temporaryBasename: basename }),
      "RECEIPT_WRITE",
    );
    if (await pathState(output.targetPath)) {
      failReceipt("RECEIPT_WRITE", "destination-appeared");
    }
    let handle = null;
    try {
      handle = await open(
        temporaryPath,
        FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY | noFollowFlag(),
        0o600,
      );
    } catch (error) {
      if (error && error.code === "EEXIST") {
        continue;
      }
      throw error;
    }
    const state = await handle.stat({ bigint: true });
    if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1n || state.size !== 0n) {
      await handle.close();
      failReceipt("RECEIPT_WRITE", "temporary-state");
    }
    const temporary = Object.freeze({
      path: temporaryPath,
      basename,
      identity: identityFromState(state),
    });
    return Object.freeze({ handle, temporary });
  }
  failReceipt("RECEIPT_WRITE", "temporary-collision-exhaustion");
}

async function inspectReceiptLink(output, targetPath, temporary, expected, links, phase) {
  await validateParentChain(output.parentPath, output.parentChain, phase);
  const state = await pathState(targetPath);
  requireRegularState(
    state,
    temporary.identity,
    expected.byteLength,
    phase,
    "receipt-link-state",
    links,
  );
  const resolved = await realpath(targetPath);
  if (
    !pathsEqual(resolved, targetPath)
    || !pathsEqual(path.dirname(resolved), output.canonicalParent)
  ) {
    failReceipt(phase, "receipt-link-reparse");
  }
  const boundary = Object.freeze({
    targetPath,
    parentPath: output.parentPath,
    parentChain: output.parentChain,
    identity: temporary.identity,
    byteLength: expected.byteLength,
    expectedLinks: links,
    kind: "receipt-publication",
  });
  const hashed = await hashOpenRegularFile(
    targetPath,
    boundary,
    phase,
    "receipt-link-identity",
  );
  if (hashed.sha256 !== expected.sha256) {
    failReceipt(phase, "receipt-link-hash");
  }
}

async function removeKnownReceiptPath(
  output,
  temporary,
  targetPath,
  expected,
  isFinal,
  allowIncomplete = false,
) {
  const authorized = isFinal
    ? pathsEqual(targetPath, output.targetPath)
    : validTemporaryBasename(output.finalBasename, temporary.basename)
      && pathsEqual(targetPath, temporary.path)
      && isInside(output.parentPath, targetPath);
  if (!authorized) {
    return false;
  }
  const state = await pathState(targetPath);
  if (!state) {
    return true;
  }
  if (
    state.isSymbolicLink()
    || !state.isFile()
    || !identityMatches(temporary.identity, state)
    || state.nlink < 1n
  ) {
    return false;
  }
  if (
    (!allowIncomplete && state.size !== BigInt(expected.byteLength))
    || (allowIncomplete && state.size > BigInt(MAX_RECEIPT_BYTES))
    || state.nlink > 2n
  ) {
    return false;
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    return false;
  }
  const boundary = Object.freeze({
    targetPath,
    parentPath: output.parentPath,
    parentChain: output.parentChain,
    identity: temporary.identity,
    byteLength: allowIncomplete ? Number(state.size) : expected.byteLength,
    expectedLinks: Number(state.nlink),
    kind: "receipt-cleanup",
  });
  try {
    const hashed = await hashOpenRegularFile(
      targetPath,
      boundary,
      "CLEANUP",
      "receipt-cleanup-identity",
    );
    if (!allowIncomplete && hashed.sha256 !== expected.sha256) {
      return false;
    }
    await unlink(targetPath);
    return !(await pathState(targetPath));
  } catch {
    return false;
  }
}

async function cleanupReceiptRun(output, temporary, expected, finalLinked) {
  let complete = true;
  if (finalLinked) {
    complete = await removeKnownReceiptPath(
      output,
      temporary,
      output.targetPath,
      expected,
      true,
    );
  }
  const temporaryRemoved = await removeKnownReceiptPath(
    output,
    temporary,
    temporary.path,
    expected,
    false,
    !finalLinked,
  );
  if (!complete || !temporaryRemoved) {
    failReceipt("CLEANUP", "receipt-cleanup-identity");
  }
}

/*
 * Crash and durability contract:
 *
 * Caught failures attempt identity-safe cleanup. A crash before publication may
 * leave a verified random temporary receipt. A crash after hard-link creation
 * and before temporary unlink may leave two names for the same complete,
 * independently verified receipt. After unlink, only the complete final name
 * remains. File datasync/sync is performed; directory-sync and power-loss
 * durability are not guaranteed. There is no wildcard stale cleanup.
 */
export async function publishCanonicalReceipt({
  repoRoot,
  output,
  receiptBytes,
  verifyTemporary,
  verifyFinal,
  hooks,
} = {}) {
  if (
    !Buffer.isBuffer(receiptBytes)
    || typeof verifyTemporary !== "function"
    || typeof verifyFinal !== "function"
  ) {
    failReceipt("CLI", "receipt-publication-options");
  }
  const outputBoundary = await validateOutputBoundary(repoRoot, output);
  const expected = Object.freeze({
    sha256: sha256Bytes(receiptBytes),
    byteLength: receiptBytes.length,
  });
  let temporary = null;
  let handle = null;
  let finalLinked = false;
  try {
    const created = await createTemporaryReceipt(outputBoundary, hooks);
    temporary = created.temporary;
    handle = created.handle;
    await invokeTestCheckpoint(
      hooks,
      "after-temp-create",
      Object.freeze({
        temporaryPath: temporary.path,
        temporaryBasename: temporary.basename,
      }),
      "RECEIPT_WRITE",
    );
    await writeAll(handle, receiptBytes, "RECEIPT_WRITE", "receipt-write");
    await handle.datasync();
    await handle.sync();
    await handle.close();
    handle = null;
    await inspectReceiptLink(
      outputBoundary,
      temporary.path,
      temporary,
      expected,
      1,
      "RECEIPT_WRITE",
    );

    await invokeTestCheckpoint(
      hooks,
      "before-temp-verify",
      Object.freeze({ temporaryPath: temporary.path }),
      "RECEIPT_VERIFY",
    );
    const temporaryResult = await verifyTemporary(temporary.path);
    await invokeTestCheckpoint(
      hooks,
      "after-temp-verify",
      Object.freeze({ temporaryPath: temporary.path }),
      "RECEIPT_VERIFY",
    );
    await inspectReceiptLink(
      outputBoundary,
      temporary.path,
      temporary,
      expected,
      1,
      "RECEIPT_VERIFY",
    );

    await invokeTestCheckpoint(
      hooks,
      "before-publish",
      Object.freeze({ temporaryPath: temporary.path, outputPath: outputBoundary.targetPath }),
      "PUBLISH",
    );
    await validateParentChain(outputBoundary.parentPath, outputBoundary.parentChain, "PUBLISH");
    if (await pathState(outputBoundary.targetPath)) {
      failReceipt("PUBLISH", "destination-appeared");
    }
    await invokeTestCheckpoint(
      hooks,
      "after-final-absence-check",
      Object.freeze({ temporaryPath: temporary.path, outputPath: outputBoundary.targetPath }),
      "PUBLISH",
    );
    if (await pathState(outputBoundary.targetPath)) {
      failReceipt("PUBLISH", "destination-appeared");
    }
    const publicationLink = hooks?.link ?? link;
    await publicationLink(temporary.path, outputBoundary.targetPath);
    finalLinked = true;
    await inspectReceiptLink(
      outputBoundary,
      temporary.path,
      temporary,
      expected,
      2,
      "PUBLISH",
    );
    await inspectReceiptLink(
      outputBoundary,
      outputBoundary.targetPath,
      temporary,
      expected,
      2,
      "PUBLISH",
    );
    await invokeTestCheckpoint(
      hooks,
      "after-link",
      Object.freeze({ temporaryPath: temporary.path, outputPath: outputBoundary.targetPath }),
      "PUBLISH",
    );
    await inspectReceiptLink(
      outputBoundary,
      temporary.path,
      temporary,
      expected,
      2,
      "PUBLISH",
    );
    await inspectReceiptLink(
      outputBoundary,
      outputBoundary.targetPath,
      temporary,
      expected,
      2,
      "PUBLISH",
    );
    await unlink(temporary.path);
    if (await pathState(temporary.path)) {
      failReceipt("PUBLISH", "temporary-unlink");
    }
    await invokeTestCheckpoint(
      hooks,
      "after-temp-unlink",
      Object.freeze({ outputPath: outputBoundary.targetPath }),
      "PUBLISH",
    );
    await inspectReceiptLink(
      outputBoundary,
      outputBoundary.targetPath,
      temporary,
      expected,
      1,
      "PUBLISH",
    );

    await invokeTestCheckpoint(
      hooks,
      "before-final-verify",
      Object.freeze({ outputPath: outputBoundary.targetPath }),
      "RECEIPT_VERIFY",
    );
    const finalResult = await verifyFinal(outputBoundary.targetPath);
    await invokeTestCheckpoint(
      hooks,
      "after-final-verify",
      Object.freeze({ outputPath: outputBoundary.targetPath }),
      "RECEIPT_VERIFY",
    );
    await inspectReceiptLink(
      outputBoundary,
      outputBoundary.targetPath,
      temporary,
      expected,
      1,
      "RECEIPT_VERIFY",
    );
    return Object.freeze({
      output: outputBoundary,
      temporary,
      expected,
      temporaryResult,
      finalResult,
    });
  } catch (error) {
    const primary = asReceiptError(error, "RECEIPT_WRITE", "receipt-publication");
    if (handle) {
      try {
        await handle.close();
      } catch {
        throw new PublicSourceReceiptError("CLEANUP", "receipt-handle-close");
      }
    }
    if (temporary) {
      try {
        if (!finalLinked) {
          const temporaryState = await pathState(temporary.path);
          const finalState = await pathState(outputBoundary.targetPath);
          if (
            temporaryState
            && finalState
            && identityMatches(temporary.identity, temporaryState)
            && identityMatches(temporary.identity, finalState)
            && temporaryState.size === BigInt(expected.byteLength)
            && finalState.size === BigInt(expected.byteLength)
            && temporaryState.nlink === 2n
            && finalState.nlink === 2n
          ) {
            finalLinked = true;
          }
        }
        await cleanupReceiptRun(outputBoundary, temporary, expected, finalLinked);
      } catch {
        throw new PublicSourceReceiptError("CLEANUP", "receipt-publication-cleanup");
      }
    }
    throw primary;
  }
}

export async function rollbackPublishedReceipt(publication) {
  if (!publication || typeof publication !== "object") {
    failReceipt("CLEANUP", "publication-record");
  }
  const removed = await removeKnownReceiptPath(
    publication.output,
    publication.temporary,
    publication.output.targetPath,
    publication.expected,
    true,
  );
  if (!removed) {
    failReceipt("CLEANUP", "published-receipt-rollback");
  }
}

const WORKER_BOOTSTRAP = String.raw`
import path from "node:path";
import { pathToFileURL } from "node:url";
let input = "";
for await (const chunk of process.stdin) input += chunk;
try {
  const request = JSON.parse(input);
  const modulePath = path.resolve("developer/verify-public-source-receipt.mjs");
  const receiptModule = await import(pathToFileURL(modulePath).href);
  const result = await receiptModule.runVerifiedReceiptWorker(request);
  process.stdout.write(JSON.stringify({ ok: true, result }) + "\n");
} catch (error) {
  const phase = typeof error?.phase === "string" ? error.phase : "RECEIPT_VERIFY";
  const reason = typeof error?.reason === "string" ? error.reason : "verified-worker";
  process.stdout.write(JSON.stringify({ ok: false, phase, reason }) + "\n");
  process.exitCode = 1;
}
`;

export function runVerifiedToolWorker(toolDirectory, request) {
  if (!toolDirectory || typeof toolDirectory.rootPath !== "string") {
    failReceipt("TOOLING", "worker-tool-directory");
  }
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", WORKER_BOOTSTRAP],
    {
      cwd: toolDirectory.rootPath,
      env: sanitizedNodeEnvironment(),
      input: JSON.stringify(request),
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || typeof result.stdout !== "string") {
    failReceipt("RECEIPT_VERIFY", "verified-worker-spawn");
  }
  let response;
  try {
    if (!result.stdout.endsWith("\n") || result.stdout.split("\n").length !== 2) {
      throw new Error("worker framing");
    }
    response = JSON.parse(result.stdout.slice(0, -1));
  } catch {
    failReceipt("RECEIPT_VERIFY", "verified-worker-output");
  }
  if (result.status !== 0 || response.ok !== true) {
    const phase = typeof response.phase === "string" ? response.phase : "RECEIPT_VERIFY";
    const reason = typeof response.reason === "string" ? response.reason : "verified-worker";
    failReceipt(phase, reason);
  }
  return Object.freeze(response.result);
}

export function modulePathFromUrl(value) {
  return fileURLToPath(value);
}
