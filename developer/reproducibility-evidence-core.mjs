import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

export const REPRODUCIBILITY_EVIDENCE_KIND =
  "ieltmps-reproducibility-evidence";
export const REPRODUCIBILITY_POLICY_KIND =
  "ieltmps-reproducibility-matrix-policy";
export const REPRODUCIBILITY_SEMANTIC_REPORT_KIND =
  "ieltmps-reproducibility-semantic-report";
export const REPRODUCIBILITY_VERIFICATION_KIND =
  "ieltmps-reproducibility-evidence-verification";
export const REPRODUCIBILITY_COMPARISON_KIND =
  "ieltmps-reproducibility-comparison-report";
export const SCHEMA_VERSION = 1;

export const MAX_CANONICAL_JSON_BYTES = 1024 * 1024;
export const MAX_REQUIRED_CELLS = 4096;
export const MAX_OPTIONAL_CELLS = 4096;
export const MAX_COMPARISON_PAIRS = 4096;
export const MAX_COMPARISON_HASHES = 4096;

export const ERROR_PHASES = Object.freeze([
  "CLI",
  "EVIDENCE_SCHEMA",
  "POLICY_SCHEMA",
  "SEMANTIC_REPORT_SCHEMA",
  "VERIFICATION_RESULT_SCHEMA",
  "COMPARISON",
  "CLAIM_LEVEL",
  "GIT",
  "FILE_IDENTITY",
  "ARTIFACT_IDENTITY",
  "POLICY_BINDING",
  "MATRIX_CELL",
  "PRIVACY",
]);

export const POLICY_KEYS = Object.freeze([
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
]);

export const POLICY_CELL_KEYS = Object.freeze([
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
]);

export const EVIDENCE_KEYS = Object.freeze([
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
]);

export const SEMANTIC_REPORT_KEYS = Object.freeze([
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
]);

export const VERIFICATION_RESULT_KEYS = Object.freeze([
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
]);

export const COMPARISON_IDENTITY_KEYS = Object.freeze([
  "artifactRole",
  "formatProfile",
  "sourceCommit",
  "toolingCommit",
  "criticalToolSetSha256",
  "manifestSha256",
  "inputSetSha256",
  "runnerPolicySha256",
  "testVectorSetSha256",
]);

export const COMPARISON_REPORT_KEYS = Object.freeze([
  "comparisonKind",
  "schemaVersion",
  "status",
  "mode",
  "claimScope",
  "policyId",
  "artifactRole",
  "formatProfile",
  "policySha256",
  "comparisonIdentitySha256",
  "evidenceRecordSha256s",
  "verificationResultSha256s",
  "requiredCellCount",
  "presentRequiredCellCount",
  "optionalCellCount",
  "presentOptionalCellCount",
  "artifactSha256",
  "artifactByteLength",
  "semanticReportSha256",
  "semanticReportByteLength",
  "sameArtifactBytes",
  "sameSemanticReport",
  "matrixComplete",
  "claimLevelsSatisfied",
  "requiredClaimLevels",
  "highestClaimLevel",
  "claimAllowed",
  "platformAttestationVerified",
  "evidenceSigningRequired",
  "projectPublicationAuthorized",
  "reasons",
]);

export const CLAIM_LEVELS = Object.freeze([
  "L0", "L1", "L2", "L3", "L4", "L5", "L6",
]);
export const OPERATING_SYSTEMS = Object.freeze(["windows", "linux", "macos"]);
export const ARCHITECTURES = Object.freeze(["x64", "arm64"]);
export const FAILURE_CLASSES = Object.freeze([
  "format-defect",
  "implementation-defect",
  "unsupported-platform",
  "runtime-profile-change",
  "filesystem-incompatibility",
  "interoperability-limitation",
  "test-infrastructure-failure",
  "evidence-incompleteness",
]);
export const COMPARISON_REASONS = Object.freeze([
  "evidence-failure",
  "missing-required-cell",
  "artifact-identity-mismatch",
  "semantic-report-identity-mismatch",
  "comparison-identity-mismatch",
  "same-process-repeatability-required",
  "same-host-repeatability-required",
  "cross-runtime-evidence-required",
  "cross-operating-system-evidence-required",
  "boundary-vector-evidence-required",
  "interoperability-evidence-required",
]);

const ERROR_PHASE_SET = new Set(ERROR_PHASES);
const FULL_GIT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const PUBLIC_IDENTIFIER_PATTERN =
  /^[a-z0-9](?:[a-z0-9._+-]{0,126}[a-z0-9])?$/u;
const TIMESTAMP_PATTERN =
  /(?:^|[._+-])[0-9]{4}-[0-9]{2}-[0-9]{2}(?:$|[t._+-])/u;
const MAX_BOUND_FILE_BYTES = 1024 * 1024 * 1024;
const MAX_GIT_BUFFER = 16 * 1024 * 1024;
const FILE_CHUNK_SIZE = 64 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const ERROR_MESSAGES = Object.freeze({
  CLI: "reproducibility command options are invalid",
  EVIDENCE_SCHEMA: "canonical evidence validation failed",
  POLICY_SCHEMA: "canonical matrix policy validation failed",
  SEMANTIC_REPORT_SCHEMA: "canonical semantic report validation failed",
  VERIFICATION_RESULT_SCHEMA: "canonical verification result validation failed",
  COMPARISON: "reproducibility comparison failed",
  CLAIM_LEVEL: "claim-level derivation failed",
  GIT: "immutable Git commit verification failed",
  FILE_IDENTITY: "stable file identity verification failed",
  ARTIFACT_IDENTITY: "artifact identity verification failed",
  POLICY_BINDING: "evidence policy binding failed",
  MATRIX_CELL: "matrix cell binding failed",
  PRIVACY: "privacy boundary validation failed",
});

export class ReproducibilityEvidenceError extends Error {
  constructor(phase, reason) {
    const safePhase = ERROR_PHASE_SET.has(phase) ? phase : "CLI";
    super(ERROR_MESSAGES[safePhase]);
    this.name = "ReproducibilityEvidenceError";
    this.phase = safePhase;
    this.reason = typeof reason === "string" && /^[a-z0-9-]+$/u.test(reason)
      ? reason
      : "invalid-operation";
  }
}

export function failReproducibility(phase, reason) {
  throw new ReproducibilityEvidenceError(phase, reason);
}

export function asReproducibilityError(error, phase, reason) {
  return error instanceof ReproducibilityEvidenceError
    ? error
    : new ReproducibilityEvidenceError(phase, reason);
}

export async function inReproducibilityPhase(phase, reason, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asReproducibilityError(error, phase, reason);
  }
}

export function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function compareUnsignedUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function exactKeys(value, expected, phase, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failReproducibility(phase, label + "-object");
  }
  const actual = Object.keys(value);
  const unknown = actual.find((key) => !expected.includes(key));
  if (unknown !== undefined) {
    failReproducibility(phase, label + "-unknown-field");
  }
  const missing = expected.find((key) => !Object.hasOwn(value, key));
  if (missing !== undefined) {
    failReproducibility(phase, label + "-missing-field");
  }
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failReproducibility(phase, label + "-key-order");
  }
}

function safeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function requireSafeInteger(value, phase, reason) {
  if (!safeInteger(value)) {
    failReproducibility(phase, reason);
  }
  return value;
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") {
    failReproducibility(phase, reason);
  }
  return value;
}

function requireLowerHex(value, pattern, phase, reason) {
  if (typeof value !== "string" || !pattern.test(value)) {
    failReproducibility(phase, reason);
  }
  return value;
}

export function requirePublicIdentifier(value, phase, reason) {
  if (
    typeof value !== "string"
    || Buffer.byteLength(value, "utf8") > 128
    || !PUBLIC_IDENTIFIER_PATTERN.test(value)
    || value.includes("..")
    || TIMESTAMP_PATTERN.test(value)
  ) {
    failReproducibility(phase, reason);
  }
  return value;
}

function requireEnum(value, allowed, phase, reason) {
  if (!allowed.includes(value)) {
    failReproducibility(phase, reason);
  }
  return value;
}

function validateOrderedEnumArray(value, allowed, phase, reason, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    failReproducibility(phase, reason + "-count");
  }
  const seen = new Set();
  let previous = -1;
  const result = value.map((entry) => {
    const position = allowed.indexOf(entry);
    if (position < 0) {
      failReproducibility(phase, reason + "-value");
    }
    if (seen.has(entry)) {
      failReproducibility(phase, reason + "-duplicate");
    }
    if (position <= previous) {
      failReproducibility(phase, reason + "-order");
    }
    previous = position;
    seen.add(entry);
    return entry;
  });
  return Object.freeze(result);
}

class RestrictedJsonParser {
  constructor(text, phase) {
    this.text = text;
    this.phase = phase;
    this.index = 0;
  }

  fail(reason) {
    failReproducibility(this.phase, reason);
  }

  peek() {
    return this.text[this.index];
  }

  consume(literal, reason) {
    if (!this.text.startsWith(literal, this.index)) {
      if (/\s/u.test(this.peek() ?? "")) {
        this.fail("noncanonical-whitespace");
      }
      this.fail(reason);
    }
    this.index += literal.length;
  }

  parseString() {
    this.consume('"', "string-open");
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
        this.fail("string-escape");
      }
      if (code < 0x20 || code > 0x7e) {
        this.fail("non-ascii-string");
      }
      this.index += 1;
    }
    this.fail("unterminated-string");
  }

  parseInteger() {
    const start = this.index;
    while (this.index < this.text.length && !",}]".includes(this.peek())) {
      if (/\s/u.test(this.peek())) {
        this.fail("noncanonical-whitespace");
      }
      this.index += 1;
    }
    const token = this.text.slice(start, this.index);
    if (token.startsWith("-")) this.fail("integer-negative");
    if (token.includes(".")) this.fail("integer-fraction");
    if (/[eE]/u.test(token)) this.fail("integer-exponent");
    if (/^0[0-9]+$/u.test(token)) this.fail("integer-leading-zero");
    if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) this.fail("integer-encoding");
    const value = Number(token);
    if (!Number.isSafeInteger(value)) this.fail("integer-range");
    return value;
  }

  parseArray() {
    this.consume("[", "array-open");
    const result = [];
    if (this.peek() === "]") {
      this.index += 1;
      return result;
    }
    while (true) {
      result.push(this.parseValue());
      if (this.peek() === "]") {
        this.index += 1;
        return result;
      }
      this.consume(",", "array-comma");
    }
  }

  parseObject() {
    this.consume("{", "object-open");
    const result = Object.create(null);
    const seen = new Set();
    if (this.peek() === "}") {
      this.index += 1;
      return result;
    }
    while (true) {
      const key = this.parseString();
      if (seen.has(key)) this.fail("duplicate-key");
      seen.add(key);
      this.consume(":", "object-colon");
      Object.defineProperty(result, key, {
        value: this.parseValue(),
        writable: true,
        enumerable: true,
        configurable: true,
      });
      if (this.peek() === "}") {
        this.index += 1;
        return result;
      }
      this.consume(",", "object-comma");
    }
  }

  parseValue() {
    const character = this.peek();
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (character === "t") {
      this.consume("true", "boolean-encoding");
      return true;
    }
    if (character === "f") {
      this.consume("false", "boolean-encoding");
      return false;
    }
    if (character === "n") {
      this.consume("null", "null-encoding");
      return null;
    }
    if (character === "-" || /[0-9]/u.test(character ?? "")) {
      return this.parseInteger();
    }
    if (/\s/u.test(character ?? "")) this.fail("noncanonical-whitespace");
    this.fail("value-encoding");
  }

  parse() {
    const result = this.parseValue();
    if (this.index !== this.text.length) {
      if (/\s/u.test(this.peek() ?? "")) this.fail("noncanonical-whitespace");
      this.fail("trailing-bytes");
    }
    return result;
  }
}

function parseRestrictedJsonBytes(bytes, phase) {
  if (!Buffer.isBuffer(bytes)) {
    failReproducibility(phase, "document-bytes");
  }
  if (bytes.length > MAX_CANONICAL_JSON_BYTES) {
    failReproducibility(phase, "document-size");
  }
  if (bytes.length >= 3 && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) {
    failReproducibility(phase, "utf8-bom");
  }
  if (bytes.length === 0 || bytes.at(-1) !== 0x0a) {
    failReproducibility(phase, "missing-final-lf");
  }
  if (bytes.length >= 2 && bytes.at(-2) === 0x0a) {
    failReproducibility(phase, "extra-final-lf");
  }
  const body = bytes.subarray(0, -1);
  for (const byte of body) {
    if (byte === 0x0a) failReproducibility(phase, "internal-lf");
    if (byte === 0x0d) failReproducibility(phase, "crlf-or-cr");
    if (byte < 0x20 || byte > 0x7e) {
      failReproducibility(phase, "non-ascii-string");
    }
  }
  let text;
  try {
    text = UTF8_DECODER.decode(body);
  } catch {
    failReproducibility(phase, "utf8-encoding");
  }
  return new RestrictedJsonParser(text, phase).parse();
}

function assertCanonicalEncodedBytes(bytes, phase) {
  if (
    bytes.length > MAX_CANONICAL_JSON_BYTES
    || bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
  ) {
    failReproducibility(phase, "canonical-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failReproducibility(phase, "canonical-ascii");
    }
  }
  return bytes;
}

function encodeValidatedDocument(value, phase) {
  return assertCanonicalEncodedBytes(
    Buffer.from(JSON.stringify(value) + "\n", "utf8"),
    phase,
  );
}

function parseAndRequireCanonical(bytes, phase, validator, encoder) {
  const parsed = parseRestrictedJsonBytes(bytes, phase);
  const validated = validator(parsed);
  const canonical = encoder(validated);
  if (!canonical.equals(bytes)) {
    failReproducibility(phase, "noncanonical-bytes");
  }
  return validated;
}

function validatePolicyCell(value) {
  const phase = "POLICY_SCHEMA";
  exactKeys(value, POLICY_CELL_KEYS, phase, "cell");
  return deepFreeze({
    matrixCellId: requirePublicIdentifier(value.matrixCellId, phase, "cell-id"),
    runtimeProfileId: requirePublicIdentifier(
      value.runtimeProfileId, phase, "runtime-profile-id",
    ),
    runtimeIdentitySha256: requireLowerHex(
      value.runtimeIdentitySha256, SHA256_PATTERN, phase, "runtime-identity-sha256",
    ),
    gitProfileId: requirePublicIdentifier(value.gitProfileId, phase, "git-profile-id"),
    gitIdentitySha256: requireLowerHex(
      value.gitIdentitySha256, SHA256_PATTERN, phase, "git-identity-sha256",
    ),
    operatingSystem: requireEnum(
      value.operatingSystem, OPERATING_SYSTEMS, phase, "operating-system",
    ),
    operatingSystemBuild: requirePublicIdentifier(
      value.operatingSystemBuild, phase, "operating-system-build",
    ),
    architecture: requireEnum(value.architecture, ARCHITECTURES, phase, "architecture"),
    filesystemProfile: requirePublicIdentifier(
      value.filesystemProfile, phase, "filesystem-profile",
    ),
    localeProfile: requirePublicIdentifier(
      value.localeProfile, phase, "locale-profile",
    ),
    timezoneProfile: requirePublicIdentifier(
      value.timezoneProfile, phase, "timezone-profile",
    ),
    platformProbeSha256: requireLowerHex(
      value.platformProbeSha256, SHA256_PATTERN, phase, "platform-probe-sha256",
    ),
  });
}

function validateCellArray(value, maximum, label) {
  if (!Array.isArray(value) || value.length > maximum) {
    failReproducibility("POLICY_SCHEMA", label + "-count");
  }
  const seen = new Set();
  let previous = null;
  const result = value.map((entry) => {
    const cell = validatePolicyCell(entry);
    if (seen.has(cell.matrixCellId)) {
      failReproducibility("POLICY_SCHEMA", label + "-duplicate");
    }
    if (previous !== null && compareUnsignedUtf8(previous, cell.matrixCellId) >= 0) {
      failReproducibility("POLICY_SCHEMA", label + "-order");
    }
    previous = cell.matrixCellId;
    seen.add(cell.matrixCellId);
    return cell;
  });
  return Object.freeze(result);
}

export function validateMatrixPolicy(value) {
  const phase = "POLICY_SCHEMA";
  exactKeys(value, POLICY_KEYS, phase, "policy");
  if (value.policyKind !== REPRODUCIBILITY_POLICY_KIND) {
    failReproducibility(phase, "policy-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failReproducibility(phase, "schema-version");
  }
  const requiredClaimLevels = validateOrderedEnumArray(
    value.requiredClaimLevels,
    CLAIM_LEVELS,
    phase,
    "required-claim-levels",
    { nonempty: true },
  );
  if (!requiredClaimLevels.includes("L0")) {
    failReproducibility(phase, "required-claim-levels-l0");
  }
  const requiredCells = validateCellArray(
    value.requiredCells, MAX_REQUIRED_CELLS, "required-cells",
  );
  if (requiredCells.length === 0) {
    failReproducibility(phase, "required-cells-count");
  }
  const optionalCells = validateCellArray(
    value.optionalCells, MAX_OPTIONAL_CELLS, "optional-cells",
  );
  const requiredIds = new Set(requiredCells.map((entry) => entry.matrixCellId));
  if (optionalCells.some((entry) => requiredIds.has(entry.matrixCellId))) {
    failReproducibility(phase, "required-optional-overlap");
  }
  return deepFreeze({
    policyKind: REPRODUCIBILITY_POLICY_KIND,
    schemaVersion: SCHEMA_VERSION,
    policyId: requirePublicIdentifier(value.policyId, phase, "policy-id"),
    artifactRole: requirePublicIdentifier(value.artifactRole, phase, "artifact-role"),
    formatProfile: requirePublicIdentifier(value.formatProfile, phase, "format-profile"),
    sourceCommit: requireLowerHex(
      value.sourceCommit, FULL_GIT_ID_PATTERN, phase, "source-commit",
    ),
    toolingCommit: requireLowerHex(
      value.toolingCommit, FULL_GIT_ID_PATTERN, phase, "tooling-commit",
    ),
    criticalToolSetSha256: requireLowerHex(
      value.criticalToolSetSha256, SHA256_PATTERN, phase, "critical-tool-set-sha256",
    ),
    manifestSha256: requireLowerHex(
      value.manifestSha256, SHA256_PATTERN, phase, "manifest-sha256",
    ),
    inputSetSha256: requireLowerHex(
      value.inputSetSha256, SHA256_PATTERN, phase, "input-set-sha256",
    ),
    testVectorSetSha256: requireLowerHex(
      value.testVectorSetSha256, SHA256_PATTERN, phase, "test-vector-set-sha256",
    ),
    requiredClaimLevels,
    requiredCells,
    optionalCells,
  });
}

export function validateReproducibilityEvidence(value) {
  const phase = "EVIDENCE_SCHEMA";
  exactKeys(value, EVIDENCE_KEYS, phase, "evidence");
  if (value.evidenceKind !== REPRODUCIBILITY_EVIDENCE_KIND) {
    failReproducibility(phase, "evidence-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failReproducibility(phase, "schema-version");
  }
  const result = requireEnum(value.result, ["pass", "fail"], phase, "result");
  let artifactSha256;
  let artifactByteLength;
  let semanticReportSha256;
  let semanticReportByteLength;
  let failureClass;
  let failureCode;
  if (result === "pass") {
    artifactSha256 = requireLowerHex(
      value.artifactSha256, SHA256_PATTERN, phase, "artifact-sha256",
    );
    artifactByteLength = requireSafeInteger(
      value.artifactByteLength, phase, "artifact-byte-length",
    );
    semanticReportSha256 = requireLowerHex(
      value.semanticReportSha256, SHA256_PATTERN, phase, "semantic-report-sha256",
    );
    semanticReportByteLength = requireSafeInteger(
      value.semanticReportByteLength, phase, "semantic-report-byte-length",
    );
    if (value.failureClass !== null || value.failureCode !== null) {
      failReproducibility(phase, "pass-failure-fields");
    }
    failureClass = null;
    failureCode = null;
  } else {
    if (
      value.artifactSha256 !== null
      || value.artifactByteLength !== null
      || value.semanticReportSha256 !== null
      || value.semanticReportByteLength !== null
    ) {
      failReproducibility(phase, "failure-artifact-fields");
    }
    artifactSha256 = null;
    artifactByteLength = null;
    semanticReportSha256 = null;
    semanticReportByteLength = null;
    failureClass = requireEnum(
      value.failureClass, FAILURE_CLASSES, phase, "failure-class",
    );
    failureCode = requirePublicIdentifier(value.failureCode, phase, "failure-code");
  }
  return deepFreeze({
    evidenceKind: REPRODUCIBILITY_EVIDENCE_KIND,
    schemaVersion: SCHEMA_VERSION,
    artifactRole: requirePublicIdentifier(value.artifactRole, phase, "artifact-role"),
    formatProfile: requirePublicIdentifier(value.formatProfile, phase, "format-profile"),
    sourceCommit: requireLowerHex(
      value.sourceCommit, FULL_GIT_ID_PATTERN, phase, "source-commit",
    ),
    toolingCommit: requireLowerHex(
      value.toolingCommit, FULL_GIT_ID_PATTERN, phase, "tooling-commit",
    ),
    criticalToolSetSha256: requireLowerHex(
      value.criticalToolSetSha256, SHA256_PATTERN, phase, "critical-tool-set-sha256",
    ),
    manifestSha256: requireLowerHex(
      value.manifestSha256, SHA256_PATTERN, phase, "manifest-sha256",
    ),
    inputSetSha256: requireLowerHex(
      value.inputSetSha256, SHA256_PATTERN, phase, "input-set-sha256",
    ),
    runtimeProfileId: requirePublicIdentifier(
      value.runtimeProfileId, phase, "runtime-profile-id",
    ),
    runtimeIdentitySha256: requireLowerHex(
      value.runtimeIdentitySha256, SHA256_PATTERN, phase, "runtime-identity-sha256",
    ),
    gitProfileId: requirePublicIdentifier(value.gitProfileId, phase, "git-profile-id"),
    gitIdentitySha256: requireLowerHex(
      value.gitIdentitySha256, SHA256_PATTERN, phase, "git-identity-sha256",
    ),
    runnerPolicySha256: requireLowerHex(
      value.runnerPolicySha256, SHA256_PATTERN, phase, "runner-policy-sha256",
    ),
    testVectorSetSha256: requireLowerHex(
      value.testVectorSetSha256, SHA256_PATTERN, phase, "test-vector-set-sha256",
    ),
    matrixCellId: requirePublicIdentifier(value.matrixCellId, phase, "matrix-cell-id"),
    operatingSystem: requireEnum(
      value.operatingSystem, OPERATING_SYSTEMS, phase, "operating-system",
    ),
    operatingSystemBuild: requirePublicIdentifier(
      value.operatingSystemBuild, phase, "operating-system-build",
    ),
    architecture: requireEnum(value.architecture, ARCHITECTURES, phase, "architecture"),
    filesystemProfile: requirePublicIdentifier(
      value.filesystemProfile, phase, "filesystem-profile",
    ),
    localeProfile: requirePublicIdentifier(
      value.localeProfile, phase, "locale-profile",
    ),
    timezoneProfile: requirePublicIdentifier(
      value.timezoneProfile, phase, "timezone-profile",
    ),
    platformProbeSha256: requireLowerHex(
      value.platformProbeSha256, SHA256_PATTERN, phase, "platform-probe-sha256",
    ),
    artifactSha256,
    artifactByteLength,
    semanticReportSha256,
    semanticReportByteLength,
    result,
    failureClass,
    failureCode,
  });
}

export function validateSemanticReport(value) {
  const phase = "SEMANTIC_REPORT_SCHEMA";
  exactKeys(value, SEMANTIC_REPORT_KEYS, phase, "semantic-report");
  if (value.semanticReportKind !== REPRODUCIBILITY_SEMANTIC_REPORT_KIND) {
    failReproducibility(phase, "semantic-report-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failReproducibility(phase, "schema-version");
  }
  const result = requireEnum(value.result, ["pass", "fail"], phase, "result");
  const canonicalVerifierPassed = requireBoolean(
    value.canonicalVerifierPassed, phase, "canonical-verifier-passed",
  );
  const failureCode = result === "pass"
    ? (() => {
      if (value.failureCode !== null) {
        failReproducibility(phase, "pass-failure-code");
      }
      if (!canonicalVerifierPassed) {
        failReproducibility(phase, "pass-canonical-verifier");
      }
      return null;
    })()
    : requirePublicIdentifier(value.failureCode, phase, "failure-code");
  return deepFreeze({
    semanticReportKind: REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
    schemaVersion: SCHEMA_VERSION,
    artifactRole: requirePublicIdentifier(value.artifactRole, phase, "artifact-role"),
    formatProfile: requirePublicIdentifier(value.formatProfile, phase, "format-profile"),
    sourceCommit: requireLowerHex(
      value.sourceCommit, FULL_GIT_ID_PATTERN, phase, "source-commit",
    ),
    toolingCommit: requireLowerHex(
      value.toolingCommit, FULL_GIT_ID_PATTERN, phase, "tooling-commit",
    ),
    inputSetSha256: requireLowerHex(
      value.inputSetSha256, SHA256_PATTERN, phase, "input-set-sha256",
    ),
    artifactSha256: requireLowerHex(
      value.artifactSha256, SHA256_PATTERN, phase, "artifact-sha256",
    ),
    artifactByteLength: requireSafeInteger(
      value.artifactByteLength, phase, "artifact-byte-length",
    ),
    canonicalVerifierPassed,
    sameProcessRepeatable: requireBoolean(
      value.sameProcessRepeatable, phase, "same-process-repeatable",
    ),
    sameHostRepeatable: requireBoolean(
      value.sameHostRepeatable, phase, "same-host-repeatable",
    ),
    boundaryVectorSetPassed: requireBoolean(
      value.boundaryVectorSetPassed, phase, "boundary-vector-set-passed",
    ),
    result,
    failureCode,
  });
}

const REQUIRED_IDENTITY_BOOLEAN_KEYS = Object.freeze([
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
]);

export function validateVerificationResult(value) {
  const phase = "VERIFICATION_RESULT_SCHEMA";
  exactKeys(value, VERIFICATION_RESULT_KEYS, phase, "verification-result");
  if (value.verificationKind !== REPRODUCIBILITY_VERIFICATION_KIND) {
    failReproducibility(phase, "verification-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failReproducibility(phase, "schema-version");
  }
  if (value.status !== "ok" || value.mode !== "reproducibility-evidence-verification") {
    failReproducibility(phase, "verification-mode");
  }
  for (const key of REQUIRED_IDENTITY_BOOLEAN_KEYS) {
    requireBoolean(value[key], phase, "verification-boolean");
    if (!value[key]) {
      failReproducibility(phase, "required-identity-not-verified");
    }
  }
  for (const key of [
    "artifactVerified",
    "semanticReportVerified",
    "semanticClaimsBound",
    "semanticClaimsIndependentlyReplayed",
    "comparisonEligible",
    "platformAttestationVerified",
    "evidenceSigningRequired",
    "projectPublicationAuthorized",
  ]) {
    requireBoolean(value[key], phase, "verification-boolean");
  }
  if (value.semanticClaimsIndependentlyReplayed) {
    failReproducibility(phase, "semantic-claims-independently-replayed");
  }
  if (value.platformAttestationVerified) {
    failReproducibility(phase, "platform-attestation-verified");
  }
  if (!value.evidenceSigningRequired) {
    failReproducibility(phase, "evidence-signing-not-required");
  }
  if (value.projectPublicationAuthorized) {
    failReproducibility(phase, "project-publication-authorized");
  }
  const evidenceResult = requireEnum(
    value.evidenceResult, ["pass", "fail"], phase, "evidence-result",
  );
  const claimKeys = [
    "canonicalVerifierPassed",
    "sameProcessRepeatable",
    "sameHostRepeatable",
    "boundaryVectorSetPassed",
  ];
  if (evidenceResult === "pass") {
    if (
      !value.artifactVerified
      || !value.semanticReportVerified
      || !value.semanticClaimsBound
      || !value.comparisonEligible
    ) {
      failReproducibility(phase, "pass-verification-semantics");
    }
    for (const key of claimKeys) {
      requireBoolean(value[key], phase, "pass-semantic-claim");
    }
    if (!value.canonicalVerifierPassed) {
      failReproducibility(phase, "pass-canonical-verifier");
    }
  } else {
    if (
      value.artifactVerified
      || value.semanticReportVerified
      || value.semanticClaimsBound
      || value.comparisonEligible
    ) {
      failReproducibility(phase, "failure-verification-semantics");
    }
    if (claimKeys.some((key) => value[key] !== null)) {
      failReproducibility(phase, "failure-semantic-claim-not-null");
    }
  }
  if (!value.semanticReportVerified && value.semanticClaimsBound) {
    failReproducibility(phase, "unverified-semantic-claims-bound");
  }
  if (
    (!value.semanticReportVerified || !value.semanticClaimsBound)
    && claimKeys.some((key) => value[key] !== null)
  ) {
    failReproducibility(phase, "unbound-semantic-claim");
  }
  return deepFreeze(Object.fromEntries(VERIFICATION_RESULT_KEYS.map((key) => {
    let entry = value[key];
    if (["policyId", "artifactRole", "formatProfile", "matrixCellId"].includes(key)) {
      entry = requirePublicIdentifier(entry, phase, key.replace(/[A-Z]/gu, (c) => "-" + c.toLowerCase()));
    } else if ([
      "evidenceSha256", "policySha256", "comparisonIdentitySha256",
    ].includes(key)) {
      entry = requireLowerHex(entry, SHA256_PATTERN, phase, "verification-hash");
    } else if (key === "evidenceByteLength") {
      entry = requireSafeInteger(entry, phase, "evidence-byte-length");
    }
    return [key, entry];
  })));
}

function validateHashArray(value, phase, reason) {
  if (!Array.isArray(value) || value.length > MAX_COMPARISON_HASHES) {
    failReproducibility(phase, reason + "-count");
  }
  return Object.freeze(value.map((entry) => (
    requireLowerHex(entry, SHA256_PATTERN, phase, reason)
  )));
}

export function validateComparisonReport(value) {
  const phase = "COMPARISON";
  exactKeys(value, COMPARISON_REPORT_KEYS, phase, "comparison-report");
  if (value.comparisonKind !== REPRODUCIBILITY_COMPARISON_KIND) {
    failReproducibility(phase, "comparison-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failReproducibility(phase, "schema-version");
  }
  if (value.mode !== "reproducibility-evidence-comparison") {
    failReproducibility(phase, "comparison-mode");
  }
  if (value.claimScope !== "controlled-runner-matrix-evidence") {
    failReproducibility(phase, "claim-scope");
  }
  const claimLevelsSatisfied = validateOrderedEnumArray(
    value.claimLevelsSatisfied, CLAIM_LEVELS, phase, "claim-levels-satisfied",
  );
  const requiredClaimLevels = validateOrderedEnumArray(
    value.requiredClaimLevels, CLAIM_LEVELS, phase, "required-claim-levels", { nonempty: true },
  );
  const reasons = validateOrderedEnumArray(
    value.reasons, COMPARISON_REASONS, phase, "reasons",
  );
  const claimAllowed = requireBoolean(value.claimAllowed, phase, "claim-allowed");
  if (value.status !== (claimAllowed ? "ok" : "blocked")) {
    failReproducibility(phase, "status-claim-consistency");
  }
  if (
    value.platformAttestationVerified !== false
    || value.evidenceSigningRequired !== true
    || value.projectPublicationAuthorized !== false
  ) {
    failReproducibility(phase, "authority-overstatement");
  }
  const artifactNull = value.artifactSha256 === null && value.artifactByteLength === null;
  const semanticNull = value.semanticReportSha256 === null
    && value.semanticReportByteLength === null;
  if (!artifactNull) {
    requireLowerHex(value.artifactSha256, SHA256_PATTERN, phase, "artifact-sha256");
    requireSafeInteger(value.artifactByteLength, phase, "artifact-byte-length");
  }
  if (!semanticNull) {
    requireLowerHex(
      value.semanticReportSha256, SHA256_PATTERN, phase, "semantic-report-sha256",
    );
    requireSafeInteger(
      value.semanticReportByteLength, phase, "semantic-report-byte-length",
    );
  }
  if ((value.artifactSha256 === null) !== (value.artifactByteLength === null)) {
    failReproducibility(phase, "artifact-null-pair");
  }
  if ((value.semanticReportSha256 === null) !== (value.semanticReportByteLength === null)) {
    failReproducibility(phase, "semantic-report-null-pair");
  }
  const highest = claimLevelsSatisfied.length === 0
    ? null
    : claimLevelsSatisfied.at(-1);
  if (value.highestClaimLevel !== highest) {
    failReproducibility(phase, "highest-claim-level");
  }
  return deepFreeze({
    comparisonKind: REPRODUCIBILITY_COMPARISON_KIND,
    schemaVersion: SCHEMA_VERSION,
    status: value.status,
    mode: "reproducibility-evidence-comparison",
    claimScope: "controlled-runner-matrix-evidence",
    policyId: requirePublicIdentifier(value.policyId, phase, "policy-id"),
    artifactRole: requirePublicIdentifier(value.artifactRole, phase, "artifact-role"),
    formatProfile: requirePublicIdentifier(value.formatProfile, phase, "format-profile"),
    policySha256: requireLowerHex(
      value.policySha256, SHA256_PATTERN, phase, "policy-sha256",
    ),
    comparisonIdentitySha256: requireLowerHex(
      value.comparisonIdentitySha256, SHA256_PATTERN, phase, "comparison-identity-sha256",
    ),
    evidenceRecordSha256s: validateHashArray(
      value.evidenceRecordSha256s, phase, "evidence-record-sha256",
    ),
    verificationResultSha256s: validateHashArray(
      value.verificationResultSha256s, phase, "verification-result-sha256",
    ),
    requiredCellCount: requireSafeInteger(
      value.requiredCellCount, phase, "required-cell-count",
    ),
    presentRequiredCellCount: requireSafeInteger(
      value.presentRequiredCellCount, phase, "present-required-cell-count",
    ),
    optionalCellCount: requireSafeInteger(
      value.optionalCellCount, phase, "optional-cell-count",
    ),
    presentOptionalCellCount: requireSafeInteger(
      value.presentOptionalCellCount, phase, "present-optional-cell-count",
    ),
    artifactSha256: value.artifactSha256,
    artifactByteLength: value.artifactByteLength,
    semanticReportSha256: value.semanticReportSha256,
    semanticReportByteLength: value.semanticReportByteLength,
    sameArtifactBytes: requireBoolean(
      value.sameArtifactBytes, phase, "same-artifact-bytes",
    ),
    sameSemanticReport: requireBoolean(
      value.sameSemanticReport, phase, "same-semantic-report",
    ),
    matrixComplete: requireBoolean(value.matrixComplete, phase, "matrix-complete"),
    claimLevelsSatisfied,
    requiredClaimLevels,
    highestClaimLevel: highest,
    claimAllowed,
    platformAttestationVerified: false,
    evidenceSigningRequired: true,
    projectPublicationAuthorized: false,
    reasons,
  });
}

export function encodeCanonicalMatrixPolicy(value) {
  return encodeValidatedDocument(validateMatrixPolicy(value), "POLICY_SCHEMA");
}

export function encodeCanonicalReproducibilityEvidence(value) {
  return encodeValidatedDocument(
    validateReproducibilityEvidence(value), "EVIDENCE_SCHEMA",
  );
}

export function encodeCanonicalSemanticReport(value) {
  return encodeValidatedDocument(validateSemanticReport(value), "SEMANTIC_REPORT_SCHEMA");
}

export function encodeCanonicalVerificationResult(value) {
  return encodeValidatedDocument(
    validateVerificationResult(value), "VERIFICATION_RESULT_SCHEMA",
  );
}

export function encodeCanonicalComparisonReport(value) {
  return encodeValidatedDocument(validateComparisonReport(value), "COMPARISON");
}

export function parseCanonicalMatrixPolicy(bytes) {
  return parseAndRequireCanonical(
    bytes, "POLICY_SCHEMA", validateMatrixPolicy, encodeCanonicalMatrixPolicy,
  );
}

export function parseCanonicalReproducibilityEvidence(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "EVIDENCE_SCHEMA",
    validateReproducibilityEvidence,
    encodeCanonicalReproducibilityEvidence,
  );
}

export function parseCanonicalSemanticReport(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "SEMANTIC_REPORT_SCHEMA",
    validateSemanticReport,
    encodeCanonicalSemanticReport,
  );
}

export function parseCanonicalVerificationResult(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "VERIFICATION_RESULT_SCHEMA",
    validateVerificationResult,
    encodeCanonicalVerificationResult,
  );
}

export function parseCanonicalComparisonReport(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "COMPARISON",
    validateComparisonReport,
    encodeCanonicalComparisonReport,
  );
}

export function parseCanonicalOpaqueJsonBytes(bytes, phase = "FILE_IDENTITY") {
  const parsed = parseRestrictedJsonBytes(bytes, phase);
  const canonical = encodeValidatedDocument(parsed, phase);
  if (!canonical.equals(bytes)) {
    failReproducibility(phase, "noncanonical-opaque-document");
  }
  return deepFreeze(parsed);
}

function validateComparisonIdentityObject(value) {
  const phase = "COMPARISON";
  exactKeys(value, COMPARISON_IDENTITY_KEYS, phase, "comparison-identity");
  return deepFreeze({
    artifactRole: requirePublicIdentifier(value.artifactRole, phase, "artifact-role"),
    formatProfile: requirePublicIdentifier(value.formatProfile, phase, "format-profile"),
    sourceCommit: requireLowerHex(
      value.sourceCommit, FULL_GIT_ID_PATTERN, phase, "source-commit",
    ),
    toolingCommit: requireLowerHex(
      value.toolingCommit, FULL_GIT_ID_PATTERN, phase, "tooling-commit",
    ),
    criticalToolSetSha256: requireLowerHex(
      value.criticalToolSetSha256, SHA256_PATTERN, phase, "critical-tool-set-sha256",
    ),
    manifestSha256: requireLowerHex(
      value.manifestSha256, SHA256_PATTERN, phase, "manifest-sha256",
    ),
    inputSetSha256: requireLowerHex(
      value.inputSetSha256, SHA256_PATTERN, phase, "input-set-sha256",
    ),
    runnerPolicySha256: requireLowerHex(
      value.runnerPolicySha256, SHA256_PATTERN, phase, "runner-policy-sha256",
    ),
    testVectorSetSha256: requireLowerHex(
      value.testVectorSetSha256, SHA256_PATTERN, phase, "test-vector-set-sha256",
    ),
  });
}

export function deriveComparisonIdentity(value) {
  const identity = validateComparisonIdentityObject(value);
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-reproducibility-comparison-identity-v1\n", "utf8"),
    Buffer.from(JSON.stringify(identity), "utf8"),
    Buffer.from("\n", "ascii"),
  ]));
}

export function comparisonIdentityFromEvidence(evidence) {
  const record = validateReproducibilityEvidence(evidence);
  return deriveComparisonIdentity(Object.fromEntries(
    COMPARISON_IDENTITY_KEYS.map((key) => [key, record[key]]),
  ));
}

export function bindEvidenceToPolicy(evidenceValue, policyValue, policySha256) {
  const evidence = validateReproducibilityEvidence(evidenceValue);
  const policy = validateMatrixPolicy(policyValue);
  requireLowerHex(policySha256, SHA256_PATTERN, "POLICY_BINDING", "policy-sha256");
  if (evidence.runnerPolicySha256 !== policySha256) {
    failReproducibility("POLICY_BINDING", "runner-policy-sha256");
  }
  for (const key of [
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "criticalToolSetSha256",
    "manifestSha256",
    "inputSetSha256",
    "testVectorSetSha256",
  ]) {
    if (evidence[key] !== policy[key]) {
      failReproducibility("POLICY_BINDING", key.replace(/[A-Z]/gu, (c) => "-" + c.toLowerCase()));
    }
  }
  const required = policy.requiredCells.find(
    (entry) => entry.matrixCellId === evidence.matrixCellId,
  );
  const optional = policy.optionalCells.find(
    (entry) => entry.matrixCellId === evidence.matrixCellId,
  );
  const cell = required ?? optional;
  if (!cell) {
    failReproducibility("MATRIX_CELL", "unknown-matrix-cell");
  }
  for (const key of POLICY_CELL_KEYS) {
    if (evidence[key] !== cell[key]) {
      failReproducibility(
        "MATRIX_CELL",
        key.replace(/[A-Z]/gu, (c) => "-" + c.toLowerCase()) + "-mismatch",
      );
    }
  }
  return Object.freeze({ policy, evidence, cell, required: Boolean(required) });
}

function sameArtifactIdentity(left, right) {
  return left.artifactSha256 === right.artifactSha256
    && left.artifactByteLength === right.artifactByteLength;
}

function sameSemanticIdentity(left, right) {
  return left.semanticReportSha256 === right.semanticReportSha256
    && left.semanticReportByteLength === right.semanticReportByteLength;
}

function samePlatformProfile(left, right) {
  return [
    "operatingSystem",
    "operatingSystemBuild",
    "architecture",
    "filesystemProfile",
    "localeProfile",
    "timezoneProfile",
    "platformProbeSha256",
  ].every((key) => left[key] === right[key]);
}

export function deriveClaimLevels(policyValue, pairs) {
  const policy = validateMatrixPolicy(policyValue);
  if (!Array.isArray(pairs) || pairs.length > MAX_COMPARISON_PAIRS) {
    failReproducibility("CLAIM_LEVEL", "comparison-pair-count");
  }
  const normalized = pairs.map((pair) => {
    if (!pair || typeof pair !== "object" || Array.isArray(pair)) {
      failReproducibility("CLAIM_LEVEL", "comparison-pair-object");
    }
    return Object.freeze({
      evidence: validateReproducibilityEvidence(pair.evidence),
      verification: validateVerificationResult(pair.verification),
      comparisonIdentitySha256: requireLowerHex(
        pair.comparisonIdentitySha256,
        SHA256_PATTERN,
        "CLAIM_LEVEL",
        "comparison-identity-sha256",
      ),
    });
  });
  const byCell = new Map(normalized.map((pair) => [pair.evidence.matrixCellId, pair]));
  const requiredPairs = policy.requiredCells
    .map((cell) => byCell.get(cell.matrixCellId))
    .filter(Boolean);
  const requiredComplete = requiredPairs.length === policy.requiredCells.length;
  const allRequiredPass = requiredComplete
    && requiredPairs.every((pair) => pair.evidence.result === "pass");
  const passPairs = normalized.filter((pair) => pair.evidence.result === "pass");
  const sameArtifacts = passPairs.length > 0
    && passPairs.every((pair) => sameArtifactIdentity(pair.evidence, passPairs[0].evidence));
  const sameSemantics = passPairs.length > 0
    && passPairs.every((pair) => sameSemanticIdentity(pair.evidence, passPairs[0].evidence));
  const sameComparisons = passPairs.length > 0
    && passPairs.every((pair) => (
      pair.comparisonIdentitySha256 === passPairs[0].comparisonIdentitySha256
    ));
  const levels = ["L0"];
  if (
    allRequiredPass
    && requiredPairs.every((pair) => (
      pair.verification.canonicalVerifierPassed
      && pair.verification.sameProcessRepeatable
    ))
  ) {
    levels.push("L1");
  }
  if (
    allRequiredPass
    && requiredPairs.every((pair) => (
      pair.verification.canonicalVerifierPassed
      && pair.verification.sameHostRepeatable
    ))
  ) {
    levels.push("L2");
  }
  let l3 = false;
  for (let left = 0; left < passPairs.length && !l3; left += 1) {
    for (let right = left + 1; right < passPairs.length; right += 1) {
      const a = passPairs[left];
      const b = passPairs[right];
      if (
        a.verification.canonicalVerifierPassed
        && b.verification.canonicalVerifierPassed
        && samePlatformProfile(a.evidence, b.evidence)
        && (
          a.evidence.runtimeProfileId !== b.evidence.runtimeProfileId
          || a.evidence.runtimeIdentitySha256 !== b.evidence.runtimeIdentitySha256
        )
        && sameArtifactIdentity(a.evidence, b.evidence)
        && sameSemanticIdentity(a.evidence, b.evidence)
        && a.comparisonIdentitySha256 === b.comparisonIdentitySha256
      ) {
        l3 = true;
        break;
      }
    }
  }
  if (l3) levels.push("L3");
  const distinctOperatingSystems = new Set(requiredPairs.map(
    (pair) => pair.evidence.operatingSystem,
  ));
  if (
    requiredPairs.every((pair) => pair.evidence.result === "pass")
    && distinctOperatingSystems.size >= 2
    && requiredPairs.every((pair) => pair.verification.canonicalVerifierPassed)
    && sameArtifacts
    && sameSemantics
    && sameComparisons
  ) {
    levels.push("L4");
  }
  if (
    allRequiredPass
    && normalized.every((pair) => pair.evidence.result === "pass")
    && requiredPairs.every((pair) => (
      pair.verification.canonicalVerifierPassed
      && pair.verification.boundaryVectorSetPassed
    ))
    && sameArtifacts
    && sameSemantics
    && sameComparisons
  ) {
    levels.push("L5");
  }
  return Object.freeze({
    claimLevelsSatisfied: Object.freeze(levels),
    requiredComplete,
    allRequiredPass,
    sameArtifactBytes: sameArtifacts,
    sameSemanticReport: sameSemantics,
    sameComparisonIdentity: sameComparisons,
  });
}

export function canonicalNativePath(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function pathsEqual(left, right) {
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
  });
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

function directoryIdentitiesEqual(left, right) {
  return Boolean(left && right)
    && left.device === right.device
    && left.inode === right.inode
    && left.mode === right.mode
    && left.birthtimeNs === right.birthtimeNs;
}

async function pathState(targetPath) {
  try {
    return await lstat(targetPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function validateAbsoluteNormalizedPath(value, phase, reason) {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    failReproducibility(phase, reason + "-absolute");
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
    failReproducibility(phase, reason + "-namespace");
  }
  if (path.normalize(value) !== value || !pathsEqual(path.resolve(value), value)) {
    failReproducibility(phase, reason + "-normalized");
  }
  return path.resolve(value);
}

async function inspectRealDirectory(targetPath, phase, reason) {
  const state = await pathState(targetPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    failReproducibility(phase, reason + "-directory");
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failReproducibility(phase, reason + "-reparse");
  }
  return Object.freeze({
    path: path.resolve(targetPath),
    canonicalPath: path.resolve(resolved),
    identity: identityFromState(state),
  });
}

function parentChainPaths(targetPath) {
  const parent = path.dirname(targetPath);
  const root = path.parse(parent).root;
  const result = [path.resolve(root)];
  const relative = path.relative(root, parent);
  let current = root;
  if (relative) {
    for (const component of relative.split(path.sep)) {
      current = path.join(current, component);
      result.push(path.resolve(current));
    }
  }
  return result;
}

async function inspectParentChain(targetPath, phase, recorded = null) {
  const paths = parentChainPaths(targetPath);
  const result = [];
  for (let index = 0; index < paths.length; index += 1) {
    const current = await inspectRealDirectory(paths[index], phase, "file-parent");
    if (
      recorded
      && (
        recorded.length !== paths.length
        || !pathsEqual(recorded[index].path, current.path)
        || !pathsEqual(recorded[index].canonicalPath, current.canonicalPath)
        || !directoryIdentitiesEqual(recorded[index].identity, current.identity)
      )
    ) {
      failReproducibility(phase, "file-parent-identity");
    }
    result.push(current);
  }
  return Object.freeze(result);
}

function noFollowFlag() {
  return process.platform !== "win32" && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

function requireStableRegularState(state, identity, phase, reason) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size < 0n
    || state.size > BigInt(MAX_BOUND_FILE_BYTES)
    || !identitiesEqual(identity, identityFromState(state))
  ) {
    failReproducibility(phase, reason);
  }
}

export function normalizeIdentityTestHooks(value) {
  if (value === undefined) return Object.freeze({});
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).some((key) => key !== "checkpoint")
    || (Object.hasOwn(value, "checkpoint") && typeof value.checkpoint !== "function")
  ) {
    failReproducibility("CLI", "test-hooks");
  }
  return Object.freeze({ checkpoint: value.checkpoint });
}

async function invokeIdentityCheckpoint(hooks, checkpoint, kind, phase) {
  if (!hooks?.checkpoint) return;
  const returned = await hooks.checkpoint(Object.freeze({ checkpoint, kind }));
  if (returned !== undefined) {
    failReproducibility(phase, "checkpoint-return-value");
  }
}

export async function readStableFile(
  fileArgument,
  {
    phase = "FILE_IDENTITY",
    reason = "file-identity",
    maximumLength = MAX_BOUND_FILE_BYTES,
    kind = "file",
    hooks = Object.freeze({}),
    captureBytes = true,
  } = {},
) {
  const targetPath = validateAbsoluteNormalizedPath(fileArgument, phase, reason);
  const parentChain = await inspectParentChain(targetPath, phase);
  const initial = await pathState(targetPath);
  if (
    !initial
    || initial.isSymbolicLink()
    || !initial.isFile()
    || initial.nlink !== 1n
    || initial.size < 0n
    || initial.size > BigInt(maximumLength)
    || initial.size > BigInt(MAX_BOUND_FILE_BYTES)
    || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    failReproducibility(phase, reason + "-state");
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failReproducibility(phase, reason + "-reparse");
  }
  const identity = identityFromState(initial);
  let handle = null;
  try {
    handle = await open(targetPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    requireStableRegularState(before, identity, phase, reason + "-identity");
    await invokeIdentityCheckpoint(hooks, "after-file-open", kind, phase);
    const sha256 = createHash("sha256");
    const chunks = [];
    let offset = 0;
    const expectedLength = Number(identity.size);
    while (offset < expectedLength) {
      const chunk = Buffer.alloc(Math.min(FILE_CHUNK_SIZE, expectedLength - offset));
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        failReproducibility(phase, reason + "-read");
      }
      const bytes = chunk.subarray(0, read.bytesRead);
      if (captureBytes) chunks.push(Buffer.from(bytes));
      sha256.update(bytes);
      offset += read.bytesRead;
    }
    const trailing = Buffer.alloc(1);
    const trailingRead = await handle.read(trailing, 0, 1, null);
    if (!trailingRead || trailingRead.bytesRead !== 0) {
      failReproducibility(phase, reason + "-trailing");
    }
    await invokeIdentityCheckpoint(hooks, "after-file-hash", kind, phase);
    const after = await handle.stat({ bigint: true });
    requireStableRegularState(after, identity, phase, reason + "-identity");
    await inspectParentChain(targetPath, phase, parentChain);
    const finalState = await pathState(targetPath);
    requireStableRegularState(finalState, identity, phase, reason + "-identity");
    const finalResolved = await realpath(targetPath);
    if (!pathsEqual(finalResolved, targetPath)) {
      failReproducibility(phase, reason + "-reparse");
    }
    return Object.freeze({
      bytes: captureBytes ? Buffer.concat(chunks, offset) : null,
      sha256: sha256.digest("hex"),
      byteLength: offset,
    });
  } finally {
    if (handle) await handle.close();
  }
}

export async function readStableCanonicalDocument(
  fileArgument,
  phase,
  kind,
  hooks = Object.freeze({}),
) {
  return readStableFile(fileArgument, {
    phase,
    reason: "canonical-document",
    maximumLength: MAX_CANONICAL_JSON_BYTES,
    kind,
    hooks,
    captureBytes: true,
  });
}

function sanitizedGitEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) environment[key] = value;
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

function runGit(repoRoot, args, phase, reason) {
  const result = spawnSync(
    "git",
    ["--no-replace-objects", "-C", repoRoot, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(),
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) {
    failReproducibility(phase, reason);
  }
  return result.stdout;
}

export async function validateGitRepository(repoArgument, phase = "GIT") {
  const repoRoot = validateAbsoluteNormalizedPath(repoArgument, phase, "repository");
  await inspectRealDirectory(repoRoot, phase, "repository");
  const reported = runGit(
    repoRoot, ["rev-parse", "--show-toplevel"], phase, "repository-root",
  ).toString("utf8").trim();
  if (!pathsEqual(reported, repoRoot)) {
    failReproducibility(phase, "repository-root");
  }
  const objectFormat = runGit(
    repoRoot, ["rev-parse", "--show-object-format"], phase, "git-object-format",
  ).toString("ascii").trim();
  if (objectFormat !== "sha1") {
    failReproducibility(phase, "git-object-format");
  }
  const replacements = runGit(
    repoRoot,
    ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    phase,
    "replacement-object-check",
  ).toString("utf8").trim();
  if (replacements.length !== 0) {
    failReproducibility(phase, "replacement-object-ref");
  }
  return repoRoot;
}

export function verifyGitCommitObject(repoRoot, commit, phase = "GIT") {
  requireLowerHex(commit, FULL_GIT_ID_PATTERN, phase, "commit-id");
  const type = runGit(
    repoRoot, ["cat-file", "-t", commit], phase, "commit-object",
  ).toString("ascii").trim();
  if (type !== "commit") {
    failReproducibility(phase, "commit-object-type");
  }
  return true;
}

export function requireFileIdentityMatches(actual, expectedSha256, expectedLength, phase, reason) {
  if (
    !actual
    || actual.sha256 !== expectedSha256
    || actual.byteLength !== expectedLength
  ) {
    failReproducibility(phase, reason);
  }
  return true;
}
