#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  CRITICAL_TOOL_PATHS,
  MAX_ARTIFACTS,
  RECEIPT_KIND,
  RECEIPT_OUTPUT_SUFFIX,
  SCHEMA_VERSION,
  PublicSourceReceiptError,
  canonicalizeArtifactIdentities,
  cleanupVerifiedToolDirectory,
  compareOrdinal,
  encodeCanonicalReceipt,
  failReceipt,
  hashArtifactInputs,
  inReceiptPhase,
  materializeVerifiedToolDirectory,
  modulePathFromUrl,
  normalizeVerifierTestHooks,
  readReceiptInput,
  requireCriticalFilesEqual,
  runVerifiedToolWorker,
  validateArtifactRoleFormat,
  validateFullCommit,
  validateRepositoryRoot,
  verifyMaterializedToolDirectory,
  verifyToolingBootstrap,
  verifyToolingCommitSignature,
  invokeTestCheckpoint,
} from "./public-source-receipt-core.mjs";

const ENTRY_RELATIVE_PATH = "developer/verify-public-source-receipt.mjs";
const ARCHIVE_FORMAT = "tar-ustar-v1";
const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9._-]+$/u;

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

function parserFailure(reason) {
  failReceipt("RECEIPT_SCHEMA", reason);
}

class RestrictedReceiptParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  peek() {
    return this.text[this.index];
  }

  expect(value, reason) {
    if (!this.text.startsWith(value, this.index)) {
      const observed = this.peek();
      if (observed === " " || observed === "\t" || observed === "\r" || observed === "\n") {
        parserFailure("noncanonical-whitespace");
      }
      parserFailure(reason);
    }
    this.index += value.length;
  }

  parseString(reason) {
    this.expect('"', reason);
    const start = this.index;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      const code = this.text.charCodeAt(this.index);
      if (character === '"') {
        const value = this.text.slice(start, this.index);
        this.index += 1;
        return value;
      }
      if (character === "\\") {
        parserFailure("string-escape");
      }
      if (code < 0x20 || code > 0x7e) {
        parserFailure("non-ascii-string");
      }
      this.index += 1;
    }
    parserFailure(reason);
  }

  parseInteger(label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
    const start = this.index;
    while (this.index < this.text.length && !",}]".includes(this.text[this.index])) {
      this.index += 1;
    }
    const token = this.text.slice(start, this.index);
    if (/\s/u.test(token)) {
      parserFailure("noncanonical-whitespace");
    }
    if (token.startsWith("-")) {
      parserFailure(label + "-negative");
    }
    if (token.includes(".")) {
      parserFailure(label + "-fraction");
    }
    if (/[eE]/u.test(token)) {
      parserFailure(label + "-exponent");
    }
    if (/^0[0-9]+$/u.test(token)) {
      parserFailure(label + "-leading-zero");
    }
    if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) {
      parserFailure(label + "-encoding");
    }
    const value = Number(token);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      parserFailure(label + "-range");
    }
    return value;
  }

  parseBoolean(expected, label) {
    const literal = expected ? "true" : "false";
    if (!this.text.startsWith(literal, this.index)) {
      if (this.text.startsWith("null", this.index)) {
        parserFailure(label + "-null");
      }
      parserFailure(label);
    }
    this.index += literal.length;
    return expected;
  }

  parseObject(expectedKeys, parsers, label) {
    this.expect("{", label + "-object");
    const result = {};
    const seen = new Set();
    for (let expectedIndex = 0; expectedIndex < expectedKeys.length; expectedIndex += 1) {
      if (this.peek() === "}") {
        parserFailure(label + "-missing-field");
      }
      const key = this.parseString(label + "-key");
      if (seen.has(key)) {
        parserFailure(label + "-duplicate-key");
      }
      seen.add(key);
      const expectedKey = expectedKeys[expectedIndex];
      if (key !== expectedKey) {
        if (expectedKeys.includes(key)) {
          parserFailure(label + "-key-order");
        }
        parserFailure(label + "-unknown-field");
      }
      this.expect(":", label + "-colon");
      result[key] = parsers[key]();
      if (expectedIndex < expectedKeys.length - 1) {
        if (this.peek() === "}") {
          parserFailure(label + "-missing-field");
        }
        this.expect(",", label + "-comma");
      }
    }
    if (this.peek() === ",") {
      this.index += 1;
      const extra = this.parseString(label + "-extra-key");
      if (seen.has(extra)) {
        parserFailure(label + "-duplicate-key");
      }
      parserFailure(label + "-unknown-field");
    }
    this.expect("}", label + "-close");
    return result;
  }

  parseArray(itemParser, label, { minimum, maximum, exact = null }) {
    this.expect("[", label + "-array");
    const values = [];
    if (this.peek() !== "]") {
      while (true) {
        values.push(itemParser(values.length));
        if (values.length > maximum) {
          parserFailure(label + "-count");
        }
        if (this.peek() === "]") {
          break;
        }
        this.expect(",", label + "-comma");
      }
    }
    this.expect("]", label + "-close");
    if (values.length < minimum || values.length > maximum) {
      parserFailure(label + "-count");
    }
    if (exact !== null && values.length !== exact) {
      parserFailure(label + "-count");
    }
    return values;
  }

  parseHex(pattern, label) {
    const value = this.parseString(label);
    if (!pattern.test(value)) {
      parserFailure(label);
    }
    return value;
  }

  parseCriticalFile(index) {
    const entry = this.parseObject(
      CRITICAL_FILE_KEYS,
      {
        path: () => this.parseString("critical-path"),
        gitBlobId: () => this.parseHex(FULL_OBJECT_ID_PATTERN, "critical-git-blob-id"),
        sha256: () => this.parseHex(SHA256_PATTERN, "critical-sha256"),
        byteLength: () => this.parseInteger("critical-byte-length"),
      },
      "critical-file",
    );
    if (entry.path !== CRITICAL_TOOL_PATHS[index]) {
      parserFailure("critical-file-path-order");
    }
    return entry;
  }

  parseArtifact() {
    const entry = this.parseObject(
      ARTIFACT_KEYS,
      {
        role: () => this.parseString("artifact-role"),
        format: () => this.parseString("artifact-format"),
        sha256: () => this.parseHex(SHA256_PATTERN, "artifact-sha256"),
        byteLength: () => this.parseInteger("artifact-byte-length"),
      },
      "artifact",
    );
    if (!SAFE_TOKEN_PATTERN.test(entry.role) || !SAFE_TOKEN_PATTERN.test(entry.format)) {
      parserFailure("artifact-role-format-ascii");
    }
    validateArtifactRoleFormat(entry.role, entry.format, "RECEIPT_SCHEMA");
    return entry;
  }

  parseArchive() {
    const archive = this.parseObject(
      ARCHIVE_KEYS,
      {
        format: () => this.parseString("archive-format"),
        sha256: () => this.parseHex(SHA256_PATTERN, "archive-sha256"),
        byteLength: () => this.parseInteger("archive-byte-length"),
        memberCount: () => this.parseInteger("archive-member-count", { minimum: 1 }),
      },
      "archive",
    );
    if (archive.format !== ARCHIVE_FORMAT) {
      parserFailure("archive-format");
    }
    return archive;
  }

  parseSource() {
    const source = this.parseObject(
      SOURCE_KEYS,
      {
        commit: () => this.parseHex(FULL_OBJECT_ID_PATTERN, "source-commit"),
        manifestSha256: () => this.parseHex(SHA256_PATTERN, "manifest-sha256"),
        membershipReportSha256: () => (
          this.parseHex(SHA256_PATTERN, "membership-report-sha256")
        ),
        membershipCount: () => this.parseInteger("membership-count", { minimum: 1 }),
        archive: () => this.parseArchive(),
      },
      "source",
    );
    if (source.archive.memberCount !== source.membershipCount) {
      parserFailure("archive-member-count");
    }
    return source;
  }

  parseTooling() {
    return this.parseObject(
      TOOLING_KEYS,
      {
        commit: () => this.parseHex(FULL_OBJECT_ID_PATTERN, "tooling-commit"),
        criticalFiles: () => this.parseArray(
          (index) => this.parseCriticalFile(index),
          "critical-files",
          {
            minimum: CRITICAL_TOOL_PATHS.length,
            maximum: CRITICAL_TOOL_PATHS.length,
            exact: CRITICAL_TOOL_PATHS.length,
          },
        ),
      },
      "tooling",
    );
  }

  parseReceipt() {
    const receipt = this.parseObject(
      TOP_LEVEL_KEYS,
      {
        receiptKind: () => this.parseString("receipt-kind"),
        schemaVersion: () => this.parseInteger("schema-version", { minimum: 1 }),
        source: () => this.parseSource(),
        tooling: () => this.parseTooling(),
        artifacts: () => this.parseArray(
          () => this.parseArtifact(),
          "artifacts",
          { minimum: 1, maximum: MAX_ARTIFACTS },
        ),
        correspondingSourceComplete: () => (
          this.parseBoolean(false, "corresponding-source-complete")
        ),
        publicationBlocked: () => this.parseBoolean(true, "publication-blocked"),
      },
      "top-level",
    );
    if (receipt.receiptKind !== RECEIPT_KIND) {
      parserFailure("receipt-kind");
    }
    if (receipt.schemaVersion !== SCHEMA_VERSION) {
      parserFailure("schema-version");
    }
    const canonical = canonicalizeArtifactIdentities(
      receipt.artifacts,
      "RECEIPT_SCHEMA",
    );
    for (let index = 0; index < canonical.length; index += 1) {
      const actual = receipt.artifacts[index];
      const expected = canonical[index];
      if (
        actual.role !== expected.role
        || actual.format !== expected.format
        || actual.sha256 !== expected.sha256
        || actual.byteLength !== expected.byteLength
      ) {
        parserFailure("artifact-order");
      }
    }
    if (this.index !== this.text.length) {
      parserFailure("trailing-bytes");
    }
    return receipt;
  }
}

export function parsePublicSourceReceiptBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    parserFailure("receipt-bytes");
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    parserFailure("utf8-bom");
  }
  if (bytes.length === 0 || bytes.at(-1) !== 0x0a) {
    parserFailure("missing-final-lf");
  }
  if (bytes.length >= 2 && bytes.at(-2) === 0x0a) {
    parserFailure("extra-final-lf");
  }
  const body = bytes.subarray(0, -1);
  for (const byte of body) {
    if (byte === 0x0d) {
      parserFailure("crlf-or-cr");
    }
    if (byte === 0x5c) {
      parserFailure("string-escape");
    }
    if (byte < 0x20 || byte > 0x7e) {
      parserFailure("non-ascii-string");
    }
  }
  const parser = new RestrictedReceiptParser(body.toString("ascii"));
  const receipt = parser.parseReceipt();
  const canonicalBytes = encodeCanonicalReceipt(receipt);
  if (!canonicalBytes.equals(bytes)) {
    parserFailure("noncanonical-bytes");
  }
  return receipt;
}

function validateB3Result(result) {
  if (
    !result
    || typeof result !== "object"
    || !FULL_OBJECT_ID_PATTERN.test(result.sourceCommit)
    || !SHA256_PATTERN.test(result.manifestSha256)
    || !SHA256_PATTERN.test(result.membershipReportSha256)
    || !Number.isSafeInteger(result.membershipCount)
    || result.membershipCount < 1
    || !SHA256_PATTERN.test(result.archiveSha256)
    || !Number.isSafeInteger(result.archiveByteLength)
    || result.archiveByteLength < 0
    || result.archiveMemberCount !== result.membershipCount
    || result.archiveFormat !== ARCHIVE_FORMAT
    || result.membershipValid !== true
    || result.archiveVerified !== true
    || result.correspondingSourceComplete !== false
    || result.publicationBlocked !== true
  ) {
    failReceipt("SOURCE_ARCHIVE", "b3-result");
  }
  return Object.freeze({
    sourceCommit: result.sourceCommit,
    manifestSha256: result.manifestSha256,
    membershipReportSha256: result.membershipReportSha256,
    membershipCount: result.membershipCount,
    archiveSha256: result.archiveSha256,
    archiveByteLength: result.archiveByteLength,
    archiveMemberCount: result.archiveMemberCount,
    archiveFormat: result.archiveFormat,
    membershipValid: true,
    archiveVerified: true,
    correspondingSourceComplete: false,
    publicationBlocked: true,
  });
}

function requireSourceMatchesReceipt(source, receipt) {
  if (
    source.sourceCommit !== receipt.source.commit
    || source.manifestSha256 !== receipt.source.manifestSha256
    || source.membershipReportSha256 !== receipt.source.membershipReportSha256
    || source.membershipCount !== receipt.source.membershipCount
    || source.archiveFormat !== receipt.source.archive.format
    || source.archiveSha256 !== receipt.source.archive.sha256
    || source.archiveByteLength !== receipt.source.archive.byteLength
    || source.archiveMemberCount !== receipt.source.archive.memberCount
    || source.correspondingSourceComplete !== receipt.correspondingSourceComplete
    || source.publicationBlocked !== receipt.publicationBlocked
  ) {
    failReceipt("SOURCE_ARCHIVE", "receipt-source-binding");
  }
}

function requireArtifactSetMatches(actual, expected) {
  if (actual.length !== expected.length) {
    failReceipt("ARTIFACT", "artifact-set-count");
  }
  for (let index = 0; index < actual.length; index += 1) {
    for (const key of ARTIFACT_KEYS) {
      if (actual[index][key] !== expected[index][key]) {
        failReceipt("ARTIFACT", "artifact-set-binding");
      }
    }
  }
}

function exactWorkerRequest(request, expectedKeys) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    failReceipt("RECEIPT_VERIFY", "worker-request-object");
  }
  const actual = Object.keys(request);
  if (
    actual.length !== expectedKeys.length
    || actual.some((key, index) => key !== expectedKeys[index])
  ) {
    failReceipt("RECEIPT_VERIFY", "worker-request-keys");
  }
}

export async function runVerifiedReceiptWorker(request) {
  if (request?.operation === "source") {
    exactWorkerRequest(request, [
      "operation",
      "toolRoot",
      "criticalFiles",
      "repo",
      "sourceCommit",
      "sourceArchive",
    ]);
    await verifyMaterializedToolDirectory(request.toolRoot, request.criticalFiles);
    if (
      typeof request.repo !== "string"
      || typeof request.sourceArchive !== "string"
      || typeof request.sourceCommit !== "string"
      || !FULL_OBJECT_ID_PATTERN.test(request.sourceCommit)
    ) {
      failReceipt("SOURCE_ARCHIVE", "worker-source-options");
    }
    return validateB3Result(await inReceiptPhase(
      "SOURCE_ARCHIVE",
      "b3-verifier",
      async () => verifyPublicSourceArchive({
        repo: request.repo,
        commit: request.sourceCommit,
        archive: request.sourceArchive,
      }),
    ));
  }

  if (request?.operation !== "verify") {
    failReceipt("RECEIPT_VERIFY", "worker-operation");
  }
  exactWorkerRequest(request, [
    "operation",
    "toolRoot",
    "criticalFiles",
    "mode",
    "repo",
    "receipt",
    "sourceArchive",
    "artifacts",
  ]);
  if (request.mode !== "full" && request.mode !== "source-only") {
    failReceipt("CLI", "verification-mode");
  }
  const repoRoot = await validateRepositoryRoot(request.repo);
  await verifyMaterializedToolDirectory(request.toolRoot, request.criticalFiles);
  const receiptInput = await readReceiptInput(repoRoot, request.receipt);
  const receipt = parsePublicSourceReceiptBytes(receiptInput.bytes);
  requireCriticalFilesEqual(
    receipt.tooling.criticalFiles,
    request.criticalFiles,
    "TOOLING",
  );
  const source = validateB3Result(await inReceiptPhase(
    "SOURCE_ARCHIVE",
    "b3-verifier",
    async () => verifyPublicSourceArchive({
      repo: repoRoot,
      commit: receipt.source.commit,
      archive: request.sourceArchive,
    }),
  ));
  requireSourceMatchesReceipt(source, receipt);

  let artifactsVerified = false;
  if (request.mode === "full") {
    if (!Array.isArray(request.artifacts) || request.artifacts.length < 1) {
      failReceipt("ARTIFACT", "full-artifact-count");
    }
    const artifacts = await hashArtifactInputs(repoRoot, request.artifacts);
    requireArtifactSetMatches(artifacts, receipt.artifacts);
    artifactsVerified = true;
  } else if (!Array.isArray(request.artifacts) || request.artifacts.length !== 0) {
    failReceipt("CLI", "source-only-artifacts");
  }

  return Object.freeze({
    status: request.mode === "full" ? "ok" : "partial",
    mode: request.mode,
    verificationComplete: request.mode === "full",
    receiptKind: RECEIPT_KIND,
    schemaVersion: SCHEMA_VERSION,
    sourceCommit: receipt.source.commit,
    toolingCommit: receipt.tooling.commit,
    artifactCount: receipt.artifacts.length,
    receiptSha256: receiptInput.sha256,
    receiptByteLength: receiptInput.byteLength,
    sourceArchiveVerified: true,
    toolingCommitSignatureValid: true,
    artifactsVerified,
    correspondingSourceComplete: false,
    publicationBlocked: true,
  });
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failReceipt("CLI", "api-options-object");
  }
  const allowed = new Set([
    "mode",
    "repo",
    "receipt",
    "sourceArchive",
    "artifacts",
    "testHooks",
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failReceipt("CLI", "api-option-key");
    }
  }
  if (
    (options.mode !== "full" && options.mode !== "source-only")
    || typeof options.repo !== "string"
    || typeof options.receipt !== "string"
    || typeof options.sourceArchive !== "string"
  ) {
    failReceipt("CLI", "api-required-option");
  }
  const artifacts = options.artifacts === undefined ? [] : options.artifacts;
  if (!Array.isArray(artifacts)) {
    failReceipt("CLI", "api-artifacts-array");
  }
  if (options.mode === "full" && (artifacts.length < 1 || artifacts.length > MAX_ARTIFACTS)) {
    failReceipt("CLI", "full-artifact-count");
  }
  if (options.mode === "source-only" && artifacts.length !== 0) {
    failReceipt("CLI", "source-only-artifacts");
  }
  return Object.freeze({
    mode: options.mode,
    repo: options.repo,
    receipt: options.receipt,
    sourceArchive: options.sourceArchive,
    artifacts: Object.freeze([...artifacts]),
    hooks: normalizeVerifierTestHooks(options.testHooks),
  });
}

async function verifyPublicSourceReceiptInternal(options, invocationPath) {
  const validated = validateApiOptions(options);
  const repoRoot = await validateRepositoryRoot(validated.repo);
  const receiptInput = await readReceiptInput(repoRoot, validated.receipt);
  const receipt = parsePublicSourceReceiptBytes(receiptInput.bytes);
  validateFullCommit(repoRoot, receipt.tooling.commit, "TOOLING");

  const bootstrap = await verifyToolingBootstrap({
    repo: repoRoot,
    toolingCommit: receipt.tooling.commit,
    entryRelativePath: ENTRY_RELATIVE_PATH,
    entryModulePath: modulePathFromUrl(import.meta.url),
    invocationPath,
  });
  requireCriticalFilesEqual(
    receipt.tooling.criticalFiles,
    bootstrap.criticalFiles,
    "TOOLING",
  );
  await verifyToolingCommitSignature(
    repoRoot,
    receipt.tooling.commit,
    validated.hooks,
  );

  let toolDirectory = null;
  let primaryError = null;
  try {
    toolDirectory = await materializeVerifiedToolDirectory(bootstrap.records);
    await invokeTestCheckpoint(
      validated.hooks,
      "before-verified-worker",
      Object.freeze({ mode: validated.mode }),
      "RECEIPT_VERIFY",
    );
    const result = runVerifiedToolWorker(toolDirectory, {
      operation: "verify",
      toolRoot: toolDirectory.rootPath,
      criticalFiles: bootstrap.criticalFiles,
      mode: validated.mode,
      repo: repoRoot,
      receipt: validated.receipt,
      sourceArchive: validated.sourceArchive,
      artifacts: validated.artifacts,
    });
    await invokeTestCheckpoint(
      validated.hooks,
      "after-verified-worker",
      Object.freeze({ mode: validated.mode }),
      "RECEIPT_VERIFY",
    );
    if (
      result.toolingCommit !== receipt.tooling.commit
      || result.receiptSha256 !== receiptInput.sha256
      || result.receiptByteLength !== receiptInput.byteLength
      || result.artifactCount !== receipt.artifacts.length
      || result.toolingCommitSignatureValid !== true
    ) {
      failReceipt("RECEIPT_VERIFY", "worker-result-binding");
    }
    return result;
  } catch (error) {
    primaryError = error;
  } finally {
    if (toolDirectory) {
      try {
        await cleanupVerifiedToolDirectory(toolDirectory);
      } catch {
        throw new PublicSourceReceiptError("CLEANUP", "verified-tool-cleanup");
      }
    }
  }
  throw primaryError;
}

export async function verifyPublicSourceReceipt(options = {}) {
  return verifyPublicSourceReceiptInternal(options, undefined);
}

function parseOptions(argv) {
  let mode = null;
  const singleton = new Map();
  const artifacts = [];
  const singletonFlags = new Set(["--repo", "--receipt", "--source-archive"]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--full" || argument === "--source-only") {
      if (mode !== null) {
        failReceipt("CLI", "duplicate-mode");
      }
      mode = argument === "--full" ? "full" : "source-only";
      continue;
    }
    if (argument === "--artifact") {
      if (index + 3 >= argv.length) {
        failReceipt("CLI", "artifact-arity");
      }
      artifacts.push(Object.freeze({
        role: argv[index + 1],
        format: argv[index + 2],
        path: argv[index + 3],
      }));
      index += 3;
      continue;
    }
    if (
      !singletonFlags.has(argument)
      || singleton.has(argument)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      failReceipt("CLI", "unknown-or-duplicate-option");
    }
    singleton.set(argument, argv[index + 1]);
    index += 1;
  }
  if (
    mode === null
    || singleton.size !== singletonFlags.size
    || (mode === "full" && artifacts.length < 1)
    || (mode === "source-only" && artifacts.length !== 0)
    || artifacts.length > MAX_ARTIFACTS
  ) {
    failReceipt("CLI", "required-options");
  }
  return Object.freeze({
    mode,
    repo: singleton.get("--repo"),
    receipt: singleton.get("--receipt"),
    sourceArchive: singleton.get("--source-archive"),
    artifacts: Object.freeze(artifacts),
  });
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const result = await verifyPublicSourceReceiptInternal(options, process.argv[1]);
  process.stdout.write(JSON.stringify(result) + "\n");
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const argvEntry = process.argv[1];
  if (typeof argvEntry !== "string" || argvEntry.length === 0) {
    return false;
  }
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(argvEntry));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceReceiptError
      ? error
      : new PublicSourceReceiptError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.message + "\n");
    process.exitCode = 1;
  });
}
