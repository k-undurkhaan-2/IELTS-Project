import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

export const PROVENANCE_RECORD_KIND = "ieltmps-generated-data-provenance";
export const PROVENANCE_REGISTRY_KIND =
  "ieltmps-generated-data-provenance-registry";
export const RELEASE_REFERENCE_KIND =
  "ieltmps-generated-data-release-reference";
export const SCHEMA_VERSION = 1;

export const MAX_CANONICAL_JSON_BYTES = 1024 * 1024;
export const MAX_INPUTS = 4096;
export const MAX_GENERATOR_FILES = 1024;
export const MAX_DEPENDENCIES = 1024;
export const MAX_OUTPUTS = 4096;
export const MAX_REGISTRY_RECORDS = 4096;
export const MAX_RELEASE_REFERENCES = 4096;

export const ERROR_PHASES = Object.freeze([
  "CLI",
  "RECORD_SCHEMA",
  "REGISTRY_SCHEMA",
  "RELEASE_REFERENCE_SCHEMA",
  "PREFERRED_SOURCE",
  "INPUT",
  "GENERATOR",
  "DEPENDENCY",
  "OUTPUT",
  "DETERMINISTIC_POLICY",
  "RIGHTS",
  "REPLAY",
  "RELEASE_GATE",
  "FILE_IDENTITY",
  "GIT",
]);

const ERROR_PHASE_SET = new Set(ERROR_PHASES);
const FULL_GIT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$/u;
const SAFE_PATH_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$/u;
const LICENSE_EXPRESSION_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9.+-]*(?: (?:AND|OR|WITH) [A-Za-z0-9][A-Za-z0-9.+-]*)*$/u;
const MUTABLE_IDENTITY_PATTERN =
  /(?:^|[._-])(?:branch|current|head|latest|main|master|stable|tag|tip|trunk)(?:$|[._-])/iu;
const PRIVATE_IDENTIFIER_PATTERN =
  /(?:^|[._-])(?:confidential|internal|private|protected|secret)(?:$|[._-])/iu;
const TIMESTAMP_PATTERN = /(?:^|[._-])[0-9]{4}-[0-9]{2}-[0-9]{2}(?:$|[T._-])/u;
const URI_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const DRIVE_PATTERN = /^[A-Za-z]:/u;
const PATH_WILDCARD_PATTERN = /[?*[\]]/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const MAX_GIT_BUFFER = 512 * 1024 * 1024;
const MAX_BOUND_FILE_BYTES = 1024 * 1024 * 1024;
const FILE_CHUNK_SIZE = 64 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const RECORD_KEYS = Object.freeze([
  "recordKind",
  "schemaVersion",
  "component",
  "preferredSource",
  "inputs",
  "generator",
  "deterministicPolicy",
  "outputs",
  "rights",
  "releaseEligible",
  "publicationBlocked",
]);
const COMPONENT_KEYS = Object.freeze([
  "componentId",
  "generationSetId",
  "recordId",
  "requiredDistributionScopes",
]);
const GIT_SOURCE_KEYS = Object.freeze([
  "kind",
  "projectId",
  "objectFormat",
  "commit",
  "tree",
]);
const COMMIT_BLOB_SOURCE_KEYS = Object.freeze([
  ...GIT_SOURCE_KEYS,
  "inputSetSha256",
]);
const ARCHIVE_SOURCE_KEYS = Object.freeze([
  "kind",
  "projectId",
  "revision",
  "format",
  "sha256",
  "byteLength",
  "memberManifestSha256",
]);
const INPUT_KEYS = Object.freeze([
  "role",
  "identifier",
  "sha256",
  "byteLength",
  "gitBlobId",
  "normalization",
]);
const GENERATOR_KEYS = Object.freeze([
  "projectId",
  "toolingCommit",
  "toolingTree",
  "entryPoint",
  "files",
  "runtime",
  "dependencies",
]);
const GENERATOR_FILE_KEYS = Object.freeze([
  "path",
  "gitBlobId",
  "sha256",
  "byteLength",
]);
const RUNTIME_KEYS = Object.freeze([
  "implementation",
  "version",
  "distributionSha256",
  "distributionByteLength",
]);
const DEPENDENCY_KEYS = Object.freeze([
  "role",
  "identifier",
  "version",
  "sha256",
  "byteLength",
  "gitBlobId",
]);
const POLICY_KEYS = Object.freeze([
  "policyId",
  "encoding",
  "bom",
  "lineEndings",
  "locale",
  "timezone",
  "unicodeNormalization",
  "caseFolding",
  "ordering",
  "sqlOrdering",
  "randomness",
  "timestamp",
  "filesystemEnumeration",
]);
const RANDOMNESS_KEYS = Object.freeze(["mode", "algorithm", "seedSha256"]);
const TIMESTAMP_KEYS = Object.freeze(["mode", "sourceIdentifier"]);
const OUTPUT_KEYS = Object.freeze([
  "role",
  "identifier",
  "format",
  "sha256",
  "byteLength",
  "gitBlobId",
]);
const RIGHTS_KEYS = Object.freeze([
  "reviewStatus",
  "reviewedScope",
  "evidenceReferences",
  "licenseStatus",
  "licenseExpression",
  "sourceDistribution",
  "artifactDistribution",
  "reviewDecisionCommit",
]);
const EVIDENCE_KEYS = Object.freeze(["evidenceId", "sha256", "byteLength"]);
const REGISTRY_KEYS = Object.freeze(["registryKind", "schemaVersion", "records"]);
const REGISTRY_RECORD_KEYS = Object.freeze([
  "componentId",
  "recordId",
  "recordSha256",
  "relationship",
]);
const RELEASE_REFERENCE_KEYS = Object.freeze([
  "releaseReferenceKind",
  "schemaVersion",
  "components",
]);
const RELEASE_COMPONENT_KEYS = Object.freeze([
  "componentId",
  "recordSha256",
  "outputSetSha256",
  "requiredEligibility",
]);
const ELIGIBILITY_FACT_KEYS = Object.freeze([
  "recordValid",
  "preferredSourceVerified",
  "inputsVerified",
  "generatorVerified",
  "deterministicPolicyValid",
  "outputsVerified",
  "replayVerified",
  "rightsVerified",
]);

const DISTRIBUTION_SCOPE_ORDER = Object.freeze(["source", "artifact"]);
const REVIEWED_SCOPE_ORDER = Object.freeze([
  "preferred-source",
  "inputs",
  "generator",
  "outputs",
  "source-distribution",
  "artifact-distribution",
]);

const ERROR_MESSAGES = Object.freeze({
  CLI: "generated-data command options are invalid",
  RECORD_SCHEMA: "canonical provenance record validation failed",
  REGISTRY_SCHEMA: "canonical provenance registry validation failed",
  RELEASE_REFERENCE_SCHEMA: "canonical release reference validation failed",
  PREFERRED_SOURCE: "preferred source verification failed",
  INPUT: "input identity verification failed",
  GENERATOR: "generator identity verification failed",
  DEPENDENCY: "dependency identity verification failed",
  OUTPUT: "output identity verification failed",
  DETERMINISTIC_POLICY: "deterministic policy validation failed",
  RIGHTS: "rights evidence validation failed",
  REPLAY: "deterministic replay verification is unavailable",
  RELEASE_GATE: "generated-data release gate failed",
  FILE_IDENTITY: "stable file identity verification failed",
  GIT: "immutable Git object verification failed",
});

export class GeneratedDataProvenanceError extends Error {
  constructor(phase, reason) {
    const safePhase = ERROR_PHASE_SET.has(phase) ? phase : "CLI";
    super(ERROR_MESSAGES[safePhase]);
    this.name = "GeneratedDataProvenanceError";
    this.phase = safePhase;
    this.reason = typeof reason === "string" && /^[a-z0-9-]+$/u.test(reason)
      ? reason
      : "invalid-operation";
  }
}

export function failProvenance(phase, reason) {
  throw new GeneratedDataProvenanceError(phase, reason);
}

export function asProvenanceError(error, phase, reason) {
  return error instanceof GeneratedDataProvenanceError
    ? error
    : new GeneratedDataProvenanceError(phase, reason);
}

export async function inProvenancePhase(phase, reason, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asProvenanceError(error, phase, reason);
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

export function compareUnsignedUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function gitBlobIdBytes(value) {
  return createHash("sha1")
    .update(Buffer.from("blob " + value.length + "\0", "ascii"))
    .update(value)
    .digest("hex");
}

function safeInteger(value, minimum = 0) {
  return Number.isSafeInteger(value) && value >= minimum;
}

function exactKeys(value, expected, phase, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failProvenance(phase, label + "-object");
  }
  const actual = Object.keys(value);
  const unknown = actual.find((key) => !expected.includes(key));
  if (unknown !== undefined) {
    failProvenance(phase, label + "-unknown-field");
  }
  const missing = expected.find((key) => !Object.hasOwn(value, key));
  if (missing !== undefined) {
    failProvenance(phase, label + "-missing-field");
  }
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failProvenance(phase, label + "-key-order");
  }
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") {
    failProvenance(phase, reason);
  }
  return value;
}

function requireSafeInteger(value, phase, reason) {
  if (!safeInteger(value)) {
    failProvenance(phase, reason);
  }
  return value;
}

function requireLowerHex(value, pattern, phase, reason) {
  if (typeof value !== "string" || !pattern.test(value)) {
    failProvenance(phase, reason);
  }
  return value;
}

function rejectPrivateOrMutable(value, phase, reason, { mutable = false } = {}) {
  if (
    PRIVATE_IDENTIFIER_PATTERN.test(value)
    || TIMESTAMP_PATTERN.test(value)
    || (mutable && MUTABLE_IDENTITY_PATTERN.test(value))
  ) {
    failProvenance(phase, reason);
  }
  return value;
}

function requirePublicToken(value, phase, reason, options = {}) {
  if (typeof value !== "string" || !SAFE_TOKEN_PATTERN.test(value)) {
    failProvenance(phase, reason);
  }
  return rejectPrivateOrMutable(value, phase, reason, options);
}

function validatePathSegment(segment, phase, reason) {
  if (
    !SAFE_PATH_SEGMENT_PATTERN.test(segment)
    || segment === "."
    || segment === ".."
    || segment.endsWith(".")
    || segment.endsWith(" ")
    || WINDOWS_RESERVED_NAME_PATTERN.test(segment)
    || PRIVATE_IDENTIFIER_PATTERN.test(segment)
  ) {
    failProvenance(phase, reason);
  }
}

export function validatePublicRelativePath(value, phase, reason) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.startsWith("/")
    || value.endsWith("/")
    || value.includes("\\")
    || value.includes(":")
    || DRIVE_PATTERN.test(value)
    || URI_PATTERN.test(value)
    || PATH_WILDCARD_PATTERN.test(value)
    || path.posix.isAbsolute(value)
    || path.posix.normalize(value) !== value
  ) {
    failProvenance(phase, reason);
  }
  const segments = value.split("/");
  if (segments.length === 0) {
    failProvenance(phase, reason);
  }
  for (const segment of segments) {
    validatePathSegment(segment, phase, reason);
  }
  return value;
}

function validatePublicIdentifierOrPath(value, phase, reason) {
  return typeof value === "string" && value.includes("/")
    ? validatePublicRelativePath(value, phase, reason)
    : requirePublicToken(value, phase, reason);
}

function requireNullOrGitId(value, phase, reason) {
  if (value === null) {
    return null;
  }
  return requireLowerHex(value, FULL_GIT_ID_PATTERN, phase, reason);
}

function requireCanonicalOrder(entries, fields, phase, reason) {
  for (let index = 1; index < entries.length; index += 1) {
    let comparison = 0;
    for (const field of fields) {
      comparison = compareUnsignedUtf8(entries[index - 1][field], entries[index][field]);
      if (comparison !== 0) {
        break;
      }
    }
    if (comparison >= 0) {
      failProvenance(phase, reason);
    }
  }
}

function validateOrderedEnumArray(value, allowed, phase, reason, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) {
    failProvenance(phase, reason + "-count");
  }
  const seen = new Set();
  let previous = -1;
  const result = value.map((entry) => {
    const position = allowed.indexOf(entry);
    if (position < 0) {
      failProvenance(phase, reason + "-value");
    }
    if (seen.has(entry)) {
      failProvenance(phase, reason + "-duplicate");
    }
    if (position <= previous) {
      failProvenance(phase, reason + "-order");
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
    failProvenance(this.phase, reason);
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
    if (token.startsWith("-")) {
      this.fail("integer-negative");
    }
    if (token.includes(".")) {
      this.fail("integer-fraction");
    }
    if (/[eE]/u.test(token)) {
      this.fail("integer-exponent");
    }
    if (/^0[0-9]+$/u.test(token)) {
      this.fail("integer-leading-zero");
    }
    if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) {
      this.fail("integer-encoding");
    }
    const value = Number(token);
    if (!Number.isSafeInteger(value)) {
      this.fail("integer-range");
    }
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
      if (seen.has(key)) {
        this.fail("duplicate-key");
      }
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
    if (character === "{") {
      return this.parseObject();
    }
    if (character === "[") {
      return this.parseArray();
    }
    if (character === '"') {
      return this.parseString();
    }
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
    if (/\s/u.test(character ?? "")) {
      this.fail("noncanonical-whitespace");
    }
    this.fail("value-encoding");
  }

  parse() {
    const result = this.parseValue();
    if (this.index !== this.text.length) {
      if (/\s/u.test(this.peek() ?? "")) {
        this.fail("noncanonical-whitespace");
      }
      this.fail("trailing-bytes");
    }
    return result;
  }
}

function parseRestrictedJsonBytes(bytes, phase) {
  if (!Buffer.isBuffer(bytes)) {
    failProvenance(phase, "document-bytes");
  }
  if (bytes.length > MAX_CANONICAL_JSON_BYTES) {
    failProvenance(phase, "document-size");
  }
  if (bytes.length >= 3 && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) {
    failProvenance(phase, "utf8-bom");
  }
  if (bytes.length === 0 || bytes.at(-1) !== 0x0a) {
    failProvenance(phase, "missing-final-lf");
  }
  if (bytes.length >= 2 && bytes.at(-2) === 0x0a) {
    failProvenance(phase, "extra-final-lf");
  }
  const body = bytes.subarray(0, -1);
  for (const byte of body) {
    if (byte === 0x0a) {
      failProvenance(phase, "internal-lf");
    }
    if (byte === 0x0d) {
      failProvenance(phase, "crlf-or-cr");
    }
    if (byte < 0x20 || byte > 0x7e) {
      failProvenance(phase, "non-ascii-string");
    }
  }
  return new RestrictedJsonParser(body.toString("ascii"), phase).parse();
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
    failProvenance(phase, "canonical-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failProvenance(phase, "canonical-ascii");
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

function validateComponent(value) {
  exactKeys(value, COMPONENT_KEYS, "RECORD_SCHEMA", "component");
  const componentId = requirePublicToken(
    value.componentId,
    "RECORD_SCHEMA",
    "component-id",
  );
  const generationSetId = requirePublicToken(
    value.generationSetId,
    "RECORD_SCHEMA",
    "generation-set-id",
    { mutable: true },
  );
  const recordId = requirePublicToken(
    value.recordId,
    "RECORD_SCHEMA",
    "record-id",
    { mutable: true },
  );
  const requiredDistributionScopes = validateOrderedEnumArray(
    value.requiredDistributionScopes,
    DISTRIBUTION_SCOPE_ORDER,
    "RECORD_SCHEMA",
    "required-distribution-scopes",
    { nonempty: true },
  );
  return Object.freeze({
    componentId,
    generationSetId,
    recordId,
    requiredDistributionScopes,
  });
}

function validatePreferredSource(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failProvenance("PREFERRED_SOURCE", "preferred-source-object");
  }
  if (value.kind === "git-commit") {
    exactKeys(value, GIT_SOURCE_KEYS, "PREFERRED_SOURCE", "git-source");
    if (value.objectFormat !== "sha1") {
      failProvenance("PREFERRED_SOURCE", "git-object-format");
    }
    return Object.freeze({
      kind: "git-commit",
      projectId: requirePublicToken(
        value.projectId,
        "PREFERRED_SOURCE",
        "source-project-id",
      ),
      objectFormat: "sha1",
      commit: requireLowerHex(
        value.commit,
        FULL_GIT_ID_PATTERN,
        "PREFERRED_SOURCE",
        "source-commit",
      ),
      tree: requireLowerHex(
        value.tree,
        FULL_GIT_ID_PATTERN,
        "PREFERRED_SOURCE",
        "source-tree",
      ),
    });
  }
  if (value.kind === "commit-owned-git-blob-set") {
    exactKeys(
      value,
      COMMIT_BLOB_SOURCE_KEYS,
      "PREFERRED_SOURCE",
      "commit-blob-source",
    );
    if (value.objectFormat !== "sha1") {
      failProvenance("PREFERRED_SOURCE", "git-object-format");
    }
    return Object.freeze({
      kind: "commit-owned-git-blob-set",
      projectId: requirePublicToken(
        value.projectId,
        "PREFERRED_SOURCE",
        "source-project-id",
      ),
      objectFormat: "sha1",
      commit: requireLowerHex(
        value.commit,
        FULL_GIT_ID_PATTERN,
        "PREFERRED_SOURCE",
        "source-commit",
      ),
      tree: requireLowerHex(
        value.tree,
        FULL_GIT_ID_PATTERN,
        "PREFERRED_SOURCE",
        "source-tree",
      ),
      inputSetSha256: requireLowerHex(
        value.inputSetSha256,
        SHA256_PATTERN,
        "PREFERRED_SOURCE",
        "input-set-sha256",
      ),
    });
  }
  if (value.kind === "immutable-upstream-archive") {
    exactKeys(value, ARCHIVE_SOURCE_KEYS, "PREFERRED_SOURCE", "archive-source");
    return Object.freeze({
      kind: "immutable-upstream-archive",
      projectId: requirePublicToken(
        value.projectId,
        "PREFERRED_SOURCE",
        "source-project-id",
      ),
      revision: requirePublicToken(
        value.revision,
        "PREFERRED_SOURCE",
        "archive-revision",
        { mutable: true },
      ),
      format: requirePublicToken(
        value.format,
        "PREFERRED_SOURCE",
        "archive-format",
      ),
      sha256: requireLowerHex(
        value.sha256,
        SHA256_PATTERN,
        "PREFERRED_SOURCE",
        "archive-sha256",
      ),
      byteLength: requireSafeInteger(
        value.byteLength,
        "PREFERRED_SOURCE",
        "archive-byte-length",
      ),
      memberManifestSha256: requireLowerHex(
        value.memberManifestSha256,
        SHA256_PATTERN,
        "PREFERRED_SOURCE",
        "member-manifest-sha256",
      ),
    });
  }
  failProvenance("PREFERRED_SOURCE", "unknown-source-kind");
}

function validateInputs(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_INPUTS) {
    failProvenance("INPUT", "input-count");
  }
  const roles = new Set();
  const identifiers = new Set();
  const tuples = new Set();
  const hashes = new Set();
  const inputs = value.map((entry) => {
    exactKeys(entry, INPUT_KEYS, "INPUT", "input");
    const input = {
      role: requirePublicToken(entry.role, "INPUT", "input-role"),
      identifier: validatePublicIdentifierOrPath(
        entry.identifier,
        "INPUT",
        "input-identifier",
      ),
      sha256: requireLowerHex(entry.sha256, SHA256_PATTERN, "INPUT", "input-sha256"),
      byteLength: requireSafeInteger(entry.byteLength, "INPUT", "input-byte-length"),
      gitBlobId: requireNullOrGitId(entry.gitBlobId, "INPUT", "input-git-blob-id"),
      normalization: entry.normalization,
    };
    if (!new Set(["raw-bytes-v1", "utf8-nfc-lf-v1"]).has(input.normalization)) {
      failProvenance("INPUT", "input-normalization");
    }
    const tuple = input.role + "\0" + input.identifier;
    if (roles.has(input.role)) {
      failProvenance("INPUT", "duplicate-input-role");
    }
    if (identifiers.has(input.identifier)) {
      failProvenance("INPUT", "duplicate-input-identifier");
    }
    if (tuples.has(tuple)) {
      failProvenance("INPUT", "duplicate-input-tuple");
    }
    if (hashes.has(input.sha256)) {
      failProvenance("INPUT", "duplicate-input-hash");
    }
    roles.add(input.role);
    identifiers.add(input.identifier);
    tuples.add(tuple);
    hashes.add(input.sha256);
    return Object.freeze(input);
  });
  requireCanonicalOrder(inputs, ["role", "identifier"], "INPUT", "input-order");
  return Object.freeze(inputs);
}

function validateGeneratorFiles(value) {
  if (
    !Array.isArray(value)
    || value.length < 1
    || value.length > MAX_GENERATOR_FILES
  ) {
    failProvenance("GENERATOR", "generator-file-count");
  }
  const paths = new Set();
  const entries = value.map((entry) => {
    exactKeys(entry, GENERATOR_FILE_KEYS, "GENERATOR", "generator-file");
    const record = {
      path: validatePublicRelativePath(
        entry.path,
        "GENERATOR",
        "generator-file-path",
      ),
      gitBlobId: requireLowerHex(
        entry.gitBlobId,
        FULL_GIT_ID_PATTERN,
        "GENERATOR",
        "generator-file-git-blob-id",
      ),
      sha256: requireLowerHex(
        entry.sha256,
        SHA256_PATTERN,
        "GENERATOR",
        "generator-file-sha256",
      ),
      byteLength: requireSafeInteger(
        entry.byteLength,
        "GENERATOR",
        "generator-file-byte-length",
      ),
    };
    if (paths.has(record.path)) {
      failProvenance("GENERATOR", "duplicate-generator-file");
    }
    paths.add(record.path);
    return Object.freeze(record);
  });
  requireCanonicalOrder(entries, ["path"], "GENERATOR", "generator-file-order");
  return Object.freeze(entries);
}

function validateRuntime(value) {
  exactKeys(value, RUNTIME_KEYS, "GENERATOR", "runtime");
  return Object.freeze({
    implementation: requirePublicToken(
      value.implementation,
      "GENERATOR",
      "runtime-implementation",
    ),
    version: requirePublicToken(
      value.version,
      "GENERATOR",
      "runtime-version",
      { mutable: true },
    ),
    distributionSha256: requireLowerHex(
      value.distributionSha256,
      SHA256_PATTERN,
      "GENERATOR",
      "runtime-distribution-sha256",
    ),
    distributionByteLength: requireSafeInteger(
      value.distributionByteLength,
      "GENERATOR",
      "runtime-distribution-byte-length",
    ),
  });
}

function validateDependencies(value) {
  if (!Array.isArray(value) || value.length > MAX_DEPENDENCIES) {
    failProvenance("DEPENDENCY", "dependency-count");
  }
  const pairs = new Set();
  const tuples = new Set();
  const entries = value.map((entry) => {
    exactKeys(entry, DEPENDENCY_KEYS, "DEPENDENCY", "dependency");
    const dependency = {
      role: requirePublicToken(entry.role, "DEPENDENCY", "dependency-role"),
      identifier: validatePublicIdentifierOrPath(
        entry.identifier,
        "DEPENDENCY",
        "dependency-identifier",
      ),
      version: requirePublicToken(
        entry.version,
        "DEPENDENCY",
        "dependency-version",
        { mutable: true },
      ),
      sha256: requireLowerHex(
        entry.sha256,
        SHA256_PATTERN,
        "DEPENDENCY",
        "dependency-sha256",
      ),
      byteLength: requireSafeInteger(
        entry.byteLength,
        "DEPENDENCY",
        "dependency-byte-length",
      ),
      gitBlobId: requireNullOrGitId(
        entry.gitBlobId,
        "DEPENDENCY",
        "dependency-git-blob-id",
      ),
    };
    const pair = dependency.role + "\0" + dependency.identifier;
    const tuple = pair + "\0" + dependency.version;
    if (pairs.has(pair) || tuples.has(tuple)) {
      failProvenance("DEPENDENCY", "duplicate-dependency");
    }
    pairs.add(pair);
    tuples.add(tuple);
    return Object.freeze(dependency);
  });
  requireCanonicalOrder(
    entries,
    ["role", "identifier", "version"],
    "DEPENDENCY",
    "dependency-order",
  );
  return Object.freeze(entries);
}

function validateGenerator(value) {
  exactKeys(value, GENERATOR_KEYS, "GENERATOR", "generator");
  const files = validateGeneratorFiles(value.files);
  const entryPoint = validatePublicRelativePath(
    value.entryPoint,
    "GENERATOR",
    "generator-entry-point",
  );
  if (!files.some((entry) => entry.path === entryPoint)) {
    failProvenance("GENERATOR", "generator-entry-point-unbound");
  }
  return Object.freeze({
    projectId: requirePublicToken(
      value.projectId,
      "GENERATOR",
      "generator-project-id",
    ),
    toolingCommit: requireLowerHex(
      value.toolingCommit,
      FULL_GIT_ID_PATTERN,
      "GENERATOR",
      "tooling-commit",
    ),
    toolingTree: requireLowerHex(
      value.toolingTree,
      FULL_GIT_ID_PATTERN,
      "GENERATOR",
      "tooling-tree",
    ),
    entryPoint,
    files,
    runtime: validateRuntime(value.runtime),
    dependencies: validateDependencies(value.dependencies),
  });
}

function validateDeterministicPolicy(value) {
  exactKeys(value, POLICY_KEYS, "DETERMINISTIC_POLICY", "deterministic-policy");
  const fixed = {
    policyId: "ieltmps-generated-data-determinism-v1",
    encoding: "utf-8",
    bom: "forbidden",
    lineEndings: "lf",
    locale: "C",
    timezone: "UTC",
    ordering: "unsigned-utf8-byte-order",
    filesystemEnumeration: "forbidden",
  };
  for (const [key, expected] of Object.entries(fixed)) {
    if (value[key] !== expected) {
      failProvenance("DETERMINISTIC_POLICY", "policy-" + key.replace(/[A-Z]/gu, (x) => "-" + x.toLowerCase()));
    }
  }
  if (!new Set(["none", "nfc"]).has(value.unicodeNormalization)) {
    failProvenance("DETERMINISTIC_POLICY", "policy-unicode-normalization");
  }
  if (!new Set(["none", "unicode-casefold-v1"]).has(value.caseFolding)) {
    failProvenance("DETERMINISTIC_POLICY", "policy-case-folding");
  }
  if (!new Set(["explicit-complete-order-by", "not-applicable"]).has(value.sqlOrdering)) {
    failProvenance("DETERMINISTIC_POLICY", "policy-sql-ordering");
  }

  exactKeys(value.randomness, RANDOMNESS_KEYS, "DETERMINISTIC_POLICY", "randomness");
  let randomness;
  if (value.randomness.mode === "forbidden") {
    if (value.randomness.algorithm !== null || value.randomness.seedSha256 !== null) {
      failProvenance("DETERMINISTIC_POLICY", "randomness-forbidden-binding");
    }
    randomness = Object.freeze({ mode: "forbidden", algorithm: null, seedSha256: null });
  } else if (value.randomness.mode === "fixed-seed") {
    randomness = Object.freeze({
      mode: "fixed-seed",
      algorithm: requirePublicToken(
        value.randomness.algorithm,
        "DETERMINISTIC_POLICY",
        "randomness-algorithm",
      ),
      seedSha256: requireLowerHex(
        value.randomness.seedSha256,
        SHA256_PATTERN,
        "DETERMINISTIC_POLICY",
        "randomness-seed-sha256",
      ),
    });
  } else {
    failProvenance("DETERMINISTIC_POLICY", "randomness-mode");
  }

  exactKeys(value.timestamp, TIMESTAMP_KEYS, "DETERMINISTIC_POLICY", "timestamp");
  let timestamp;
  if (value.timestamp.mode === "forbidden") {
    if (value.timestamp.sourceIdentifier !== null) {
      failProvenance("DETERMINISTIC_POLICY", "timestamp-forbidden-binding");
    }
    timestamp = Object.freeze({ mode: "forbidden", sourceIdentifier: null });
  } else if (value.timestamp.mode === "source-defined") {
    timestamp = Object.freeze({
      mode: "source-defined",
      sourceIdentifier: requirePublicToken(
        value.timestamp.sourceIdentifier,
        "DETERMINISTIC_POLICY",
        "timestamp-source-identifier",
      ),
    });
  } else {
    failProvenance("DETERMINISTIC_POLICY", "timestamp-mode");
  }

  return Object.freeze({
    policyId: fixed.policyId,
    encoding: fixed.encoding,
    bom: fixed.bom,
    lineEndings: fixed.lineEndings,
    locale: fixed.locale,
    timezone: fixed.timezone,
    unicodeNormalization: value.unicodeNormalization,
    caseFolding: value.caseFolding,
    ordering: fixed.ordering,
    sqlOrdering: value.sqlOrdering,
    randomness,
    timestamp,
    filesystemEnumeration: fixed.filesystemEnumeration,
  });
}

function validateOutputs(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_OUTPUTS) {
    failProvenance("OUTPUT", "output-count");
  }
  const roles = new Set();
  const identifiers = new Set();
  const tuples = new Set();
  const hashes = new Set();
  const outputs = value.map((entry) => {
    exactKeys(entry, OUTPUT_KEYS, "OUTPUT", "output");
    const output = {
      role: requirePublicToken(entry.role, "OUTPUT", "output-role"),
      identifier: validatePublicIdentifierOrPath(
        entry.identifier,
        "OUTPUT",
        "output-identifier",
      ),
      format: requirePublicToken(entry.format, "OUTPUT", "output-format"),
      sha256: requireLowerHex(entry.sha256, SHA256_PATTERN, "OUTPUT", "output-sha256"),
      byteLength: requireSafeInteger(entry.byteLength, "OUTPUT", "output-byte-length"),
      gitBlobId: requireNullOrGitId(entry.gitBlobId, "OUTPUT", "output-git-blob-id"),
    };
    const tuple = output.role + "\0" + output.identifier + "\0" + output.format;
    if (roles.has(output.role)) {
      failProvenance("OUTPUT", "duplicate-output-role");
    }
    if (identifiers.has(output.identifier)) {
      failProvenance("OUTPUT", "duplicate-output-identifier");
    }
    if (tuples.has(tuple)) {
      failProvenance("OUTPUT", "duplicate-output-tuple");
    }
    if (hashes.has(output.sha256)) {
      failProvenance("OUTPUT", "duplicate-output-hash");
    }
    roles.add(output.role);
    identifiers.add(output.identifier);
    tuples.add(tuple);
    hashes.add(output.sha256);
    return Object.freeze(output);
  });
  requireCanonicalOrder(
    outputs,
    ["role", "identifier", "format"],
    "OUTPUT",
    "output-order",
  );
  return Object.freeze(outputs);
}

function validateEvidenceReferences(value) {
  if (!Array.isArray(value) || value.length > MAX_DEPENDENCIES) {
    failProvenance("RIGHTS", "evidence-count");
  }
  const ids = new Set();
  const hashes = new Set();
  const evidence = value.map((entry) => {
    exactKeys(entry, EVIDENCE_KEYS, "RIGHTS", "evidence");
    const record = {
      evidenceId: requirePublicToken(entry.evidenceId, "RIGHTS", "evidence-id"),
      sha256: requireLowerHex(entry.sha256, SHA256_PATTERN, "RIGHTS", "evidence-sha256"),
      byteLength: requireSafeInteger(entry.byteLength, "RIGHTS", "evidence-byte-length"),
    };
    if (ids.has(record.evidenceId) || hashes.has(record.sha256)) {
      failProvenance("RIGHTS", "duplicate-evidence");
    }
    ids.add(record.evidenceId);
    hashes.add(record.sha256);
    return Object.freeze(record);
  });
  requireCanonicalOrder(evidence, ["evidenceId"], "RIGHTS", "evidence-order");
  return Object.freeze(evidence);
}

function validateRights(value) {
  exactKeys(value, RIGHTS_KEYS, "RIGHTS", "rights");
  if (!new Set(["unresolved", "blocked", "reviewed"]).has(value.reviewStatus)) {
    failProvenance("RIGHTS", "review-status");
  }
  const reviewedScope = validateOrderedEnumArray(
    value.reviewedScope,
    REVIEWED_SCOPE_ORDER,
    "RIGHTS",
    "reviewed-scope",
  );
  const evidenceReferences = validateEvidenceReferences(value.evidenceReferences);
  if (!new Set(["unresolved", "identified"]).has(value.licenseStatus)) {
    failProvenance("RIGHTS", "license-status");
  }
  let licenseExpression = value.licenseExpression;
  if (value.licenseStatus === "unresolved") {
    if (licenseExpression !== null) {
      failProvenance("RIGHTS", "unresolved-license-expression");
    }
  } else if (
    typeof licenseExpression !== "string"
    || !LICENSE_EXPRESSION_PATTERN.test(licenseExpression)
    || PRIVATE_IDENTIFIER_PATTERN.test(licenseExpression)
  ) {
    failProvenance("RIGHTS", "license-expression");
  }
  const distributionValues = new Set(["unresolved", "denied", "approved"]);
  if (!distributionValues.has(value.sourceDistribution)) {
    failProvenance("RIGHTS", "source-distribution");
  }
  if (!distributionValues.has(value.artifactDistribution)) {
    failProvenance("RIGHTS", "artifact-distribution");
  }
  let reviewDecisionCommit = value.reviewDecisionCommit;
  if (value.reviewStatus === "reviewed") {
    if (reviewedScope.length === 0) {
      failProvenance("RIGHTS", "reviewed-scope-empty");
    }
    if (evidenceReferences.length === 0) {
      failProvenance("RIGHTS", "reviewed-evidence-empty");
    }
    reviewDecisionCommit = requireLowerHex(
      reviewDecisionCommit,
      FULL_GIT_ID_PATTERN,
      "RIGHTS",
      "review-decision-commit",
    );
    if (value.licenseStatus !== "identified" || licenseExpression === null) {
      failProvenance("RIGHTS", "reviewed-license-unidentified");
    }
  } else {
    if (reviewDecisionCommit !== null) {
      failProvenance("RIGHTS", "unreviewed-decision-commit");
    }
    if (reviewedScope.length !== 0) {
      failProvenance("RIGHTS", "unreviewed-scope");
    }
    if (value.reviewStatus === "unresolved" && evidenceReferences.length !== 0) {
      failProvenance("RIGHTS", "unresolved-evidence");
    }
    if (value.sourceDistribution === "approved" || value.artifactDistribution === "approved") {
      failProvenance("RIGHTS", "unreviewed-approval");
    }
  }
  return Object.freeze({
    reviewStatus: value.reviewStatus,
    reviewedScope,
    evidenceReferences,
    licenseStatus: value.licenseStatus,
    licenseExpression,
    sourceDistribution: value.sourceDistribution,
    artifactDistribution: value.artifactDistribution,
    reviewDecisionCommit,
  });
}

export function deriveRightsVerified(component, rights) {
  const required = component.requiredDistributionScopes;
  if (
    rights.reviewStatus !== "reviewed"
    || !FULL_GIT_ID_PATTERN.test(rights.reviewDecisionCommit ?? "")
    || rights.evidenceReferences.length === 0
    || rights.licenseStatus !== "identified"
    || rights.licenseExpression === null
  ) {
    return false;
  }
  for (const scope of required) {
    const distributionKey = scope === "source"
      ? "sourceDistribution"
      : "artifactDistribution";
    const reviewedScope = scope === "source"
      ? "source-distribution"
      : "artifact-distribution";
    if (
      rights[distributionKey] !== "approved"
      || !rights.reviewedScope.includes(reviewedScope)
    ) {
      return false;
    }
  }
  return true;
}

export function deriveEligibility(facts) {
  exactKeys(facts, ELIGIBILITY_FACT_KEYS, "REPLAY", "eligibility-facts");
  for (const key of ELIGIBILITY_FACT_KEYS) {
    requireBoolean(facts[key], "REPLAY", "eligibility-fact-" + key.replace(/[A-Z]/gu, (x) => "-" + x.toLowerCase()));
  }
  const releaseEligible = ELIGIBILITY_FACT_KEYS.every((key) => facts[key] === true);
  return Object.freeze({
    releaseEligible,
    publicationBlocked: !releaseEligible,
  });
}

export function validateProvenanceRecord(value) {
  exactKeys(value, RECORD_KEYS, "RECORD_SCHEMA", "top-level");
  if (value.recordKind !== PROVENANCE_RECORD_KIND) {
    failProvenance("RECORD_SCHEMA", "record-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failProvenance("RECORD_SCHEMA", "schema-version");
  }
  const component = validateComponent(value.component);
  const preferredSource = validatePreferredSource(value.preferredSource);
  const inputs = validateInputs(value.inputs);
  if (
    preferredSource.kind === "immutable-upstream-archive"
    && inputs.some((entry) => entry.gitBlobId !== null)
  ) {
    failProvenance("INPUT", "archive-source-git-input");
  }
  const generator = validateGenerator(value.generator);
  const deterministicPolicy = validateDeterministicPolicy(value.deterministicPolicy);
  const outputs = validateOutputs(value.outputs);
  const rights = validateRights(value.rights);
  requireBoolean(value.releaseEligible, "RECORD_SCHEMA", "release-eligible-boolean");
  requireBoolean(
    value.publicationBlocked,
    "RECORD_SCHEMA",
    "publication-blocked-boolean",
  );
  const structural = deriveEligibility({
    recordValid: true,
    preferredSourceVerified: true,
    inputsVerified: true,
    generatorVerified: true,
    deterministicPolicyValid: true,
    outputsVerified: true,
    replayVerified: false,
    rightsVerified: deriveRightsVerified(component, rights),
  });
  if (value.releaseEligible !== structural.releaseEligible) {
    failProvenance("RECORD_SCHEMA", "stored-release-eligible-mismatch");
  }
  if (value.publicationBlocked !== structural.publicationBlocked) {
    failProvenance("RECORD_SCHEMA", "stored-publication-blocked-mismatch");
  }
  return deepFreeze({
    recordKind: PROVENANCE_RECORD_KIND,
    schemaVersion: SCHEMA_VERSION,
    component,
    preferredSource,
    inputs,
    generator,
    deterministicPolicy,
    outputs,
    rights,
    releaseEligible: structural.releaseEligible,
    publicationBlocked: structural.publicationBlocked,
  });
}

export function validateProvenanceRegistry(value) {
  exactKeys(value, REGISTRY_KEYS, "REGISTRY_SCHEMA", "registry");
  if (value.registryKind !== PROVENANCE_REGISTRY_KIND) {
    failProvenance("REGISTRY_SCHEMA", "registry-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failProvenance("REGISTRY_SCHEMA", "schema-version");
  }
  if (!Array.isArray(value.records) || value.records.length > MAX_REGISTRY_RECORDS) {
    failProvenance("REGISTRY_SCHEMA", "registry-record-count");
  }
  const componentIds = new Set();
  const recordIds = new Set();
  const hashes = new Set();
  const records = value.records.map((entry) => {
    exactKeys(entry, REGISTRY_RECORD_KEYS, "REGISTRY_SCHEMA", "registry-record");
    const record = {
      componentId: requirePublicToken(
        entry.componentId,
        "REGISTRY_SCHEMA",
        "registry-component-id",
      ),
      recordId: requirePublicToken(
        entry.recordId,
        "REGISTRY_SCHEMA",
        "registry-record-id",
        { mutable: true },
      ),
      recordSha256: requireLowerHex(
        entry.recordSha256,
        SHA256_PATTERN,
        "REGISTRY_SCHEMA",
        "registry-record-sha256",
      ),
      relationship: entry.relationship,
    };
    if (!new Set(["required", "optional"]).has(record.relationship)) {
      failProvenance("REGISTRY_SCHEMA", "registry-relationship");
    }
    if (
      componentIds.has(record.componentId)
      || recordIds.has(record.recordId)
      || hashes.has(record.recordSha256)
    ) {
      failProvenance("REGISTRY_SCHEMA", "duplicate-registry-record");
    }
    componentIds.add(record.componentId);
    recordIds.add(record.recordId);
    hashes.add(record.recordSha256);
    return Object.freeze(record);
  });
  requireCanonicalOrder(
    records,
    ["componentId"],
    "REGISTRY_SCHEMA",
    "registry-record-order",
  );
  return deepFreeze({
    registryKind: PROVENANCE_REGISTRY_KIND,
    schemaVersion: SCHEMA_VERSION,
    records,
  });
}

export function validateReleaseReference(value) {
  exactKeys(
    value,
    RELEASE_REFERENCE_KEYS,
    "RELEASE_REFERENCE_SCHEMA",
    "release-reference",
  );
  if (value.releaseReferenceKind !== RELEASE_REFERENCE_KIND) {
    failProvenance("RELEASE_REFERENCE_SCHEMA", "release-reference-kind");
  }
  if (value.schemaVersion !== SCHEMA_VERSION) {
    failProvenance("RELEASE_REFERENCE_SCHEMA", "schema-version");
  }
  if (
    !Array.isArray(value.components)
    || value.components.length > MAX_RELEASE_REFERENCES
  ) {
    failProvenance("RELEASE_REFERENCE_SCHEMA", "release-component-count");
  }
  const ids = new Set();
  const components = value.components.map((entry) => {
    exactKeys(
      entry,
      RELEASE_COMPONENT_KEYS,
      "RELEASE_REFERENCE_SCHEMA",
      "release-component",
    );
    const component = {
      componentId: requirePublicToken(
        entry.componentId,
        "RELEASE_REFERENCE_SCHEMA",
        "release-component-id",
      ),
      recordSha256: requireLowerHex(
        entry.recordSha256,
        SHA256_PATTERN,
        "RELEASE_REFERENCE_SCHEMA",
        "release-record-sha256",
      ),
      outputSetSha256: requireLowerHex(
        entry.outputSetSha256,
        SHA256_PATTERN,
        "RELEASE_REFERENCE_SCHEMA",
        "release-output-set-sha256",
      ),
      requiredEligibility: entry.requiredEligibility,
    };
    if (component.requiredEligibility !== true) {
      failProvenance("RELEASE_REFERENCE_SCHEMA", "required-eligibility");
    }
    if (ids.has(component.componentId)) {
      failProvenance("RELEASE_REFERENCE_SCHEMA", "duplicate-release-component");
    }
    ids.add(component.componentId);
    return Object.freeze(component);
  });
  requireCanonicalOrder(
    components,
    ["componentId"],
    "RELEASE_REFERENCE_SCHEMA",
    "release-component-order",
  );
  return deepFreeze({
    releaseReferenceKind: RELEASE_REFERENCE_KIND,
    schemaVersion: SCHEMA_VERSION,
    components,
  });
}

export function encodeCanonicalProvenanceRecord(value) {
  return encodeValidatedDocument(validateProvenanceRecord(value), "RECORD_SCHEMA");
}

export function encodeCanonicalProvenanceRegistry(value) {
  return encodeValidatedDocument(validateProvenanceRegistry(value), "REGISTRY_SCHEMA");
}

export function encodeCanonicalReleaseReference(value) {
  return encodeValidatedDocument(
    validateReleaseReference(value),
    "RELEASE_REFERENCE_SCHEMA",
  );
}

function parseAndRequireCanonical(bytes, phase, validator, encoder) {
  const parsed = parseRestrictedJsonBytes(bytes, phase);
  const validated = validator(parsed);
  const canonical = encoder(validated);
  if (!canonical.equals(bytes)) {
    failProvenance(phase, "noncanonical-bytes");
  }
  return validated;
}

export function parseCanonicalProvenanceRecord(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "RECORD_SCHEMA",
    validateProvenanceRecord,
    encodeCanonicalProvenanceRecord,
  );
}

export function parseCanonicalProvenanceRegistry(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "REGISTRY_SCHEMA",
    validateProvenanceRegistry,
    encodeCanonicalProvenanceRegistry,
  );
}

export function parseCanonicalReleaseReference(bytes) {
  return parseAndRequireCanonical(
    bytes,
    "RELEASE_REFERENCE_SCHEMA",
    validateReleaseReference,
    encodeCanonicalReleaseReference,
  );
}

export function parseCanonicalOpaqueJsonBytes(bytes, phase = "PREFERRED_SOURCE") {
  const parsed = parseRestrictedJsonBytes(bytes, phase);
  const canonical = encodeValidatedDocument(parsed, phase);
  if (!canonical.equals(bytes)) {
    failProvenance(phase, "noncanonical-member-manifest");
  }
  return deepFreeze(parsed);
}

export function deriveInputSetSha256(inputs) {
  const validated = validateInputs(inputs);
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-generated-input-set-v1\n", "utf8"),
    Buffer.from(JSON.stringify(validated), "utf8"),
    Buffer.from("\n", "ascii"),
  ]));
}

export function deriveOutputSetSha256(outputs) {
  const validated = validateOutputs(outputs);
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-generated-output-set-v1\n", "utf8"),
    Buffer.from(JSON.stringify(validated), "utf8"),
    Buffer.from("\n", "ascii"),
  ]));
}

export function deriveStructuralRecordFacts(record) {
  const validated = validateProvenanceRecord(record);
  const rightsVerified = deriveRightsVerified(validated.component, validated.rights);
  const eligibility = deriveEligibility({
    recordValid: true,
    preferredSourceVerified: true,
    inputsVerified: true,
    generatorVerified: true,
    deterministicPolicyValid: true,
    outputsVerified: true,
    replayVerified: false,
    rightsVerified,
  });
  return Object.freeze({ rightsVerified, ...eligibility });
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
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function validateAbsoluteNormalizedPath(value, phase, reason) {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    failProvenance(phase, reason + "-absolute");
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
    failProvenance(phase, reason + "-namespace");
  }
  if (path.normalize(value) !== value || !pathsEqual(path.resolve(value), value)) {
    failProvenance(phase, reason + "-normalized");
  }
  return path.resolve(value);
}

async function inspectRealDirectory(targetPath, phase, reason) {
  const state = await pathState(targetPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    failProvenance(phase, reason + "-directory");
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failProvenance(phase, reason + "-reparse");
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
      failProvenance(phase, "file-parent-identity");
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
    failProvenance(phase, reason);
  }
}

export function normalizeIdentityTestHooks(value) {
  if (value === undefined) {
    return Object.freeze({});
  }
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).some((key) => key !== "checkpoint")
    || (Object.hasOwn(value, "checkpoint") && typeof value.checkpoint !== "function")
  ) {
    failProvenance("CLI", "test-hooks");
  }
  return Object.freeze({ checkpoint: value.checkpoint });
}

async function invokeIdentityCheckpoint(hooks, checkpoint, kind, phase) {
  if (!hooks?.checkpoint) {
    return;
  }
  const returned = await hooks.checkpoint(Object.freeze({ checkpoint, kind }));
  if (returned !== undefined) {
    failProvenance(phase, "checkpoint-return-value");
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
  ) {
    failProvenance(phase, reason + "-state");
  }
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    failProvenance(phase, reason + "-reparse");
  }
  const identity = identityFromState(initial);
  let handle = null;
  try {
    handle = await open(targetPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    requireStableRegularState(before, identity, phase, reason + "-identity");
    await invokeIdentityCheckpoint(hooks, "after-file-open", kind, phase);
    const sha256 = createHash("sha256");
    const gitBlob = createHash("sha1").update(
      Buffer.from("blob " + Number(identity.size) + "\0", "ascii"),
    );
    const chunks = [];
    let offset = 0;
    while (offset < Number(identity.size)) {
      const chunk = Buffer.alloc(
        Math.min(FILE_CHUNK_SIZE, Number(identity.size) - offset),
      );
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        failProvenance(phase, reason + "-read");
      }
      const bytes = Buffer.from(chunk.subarray(0, read.bytesRead));
      chunks.push(bytes);
      sha256.update(bytes);
      gitBlob.update(bytes);
      offset += read.bytesRead;
    }
    const trailing = Buffer.alloc(1);
    const trailingRead = await handle.read(trailing, 0, 1, null);
    if (!trailingRead || trailingRead.bytesRead !== 0) {
      failProvenance(phase, reason + "-trailing");
    }
    await invokeIdentityCheckpoint(hooks, "after-file-hash", kind, phase);
    const after = await handle.stat({ bigint: true });
    requireStableRegularState(after, identity, phase, reason + "-identity");
    await inspectParentChain(targetPath, phase, parentChain);
    const finalState = await pathState(targetPath);
    requireStableRegularState(finalState, identity, phase, reason + "-identity");
    const finalResolved = await realpath(targetPath);
    if (!pathsEqual(finalResolved, targetPath)) {
      failProvenance(phase, reason + "-reparse");
    }
    const bytes = Buffer.concat(chunks, offset);
    return Object.freeze({
      bytes,
      sha256: sha256.digest("hex"),
      byteLength: offset,
      gitBlobId: gitBlob.digest("hex"),
    });
  } finally {
    if (handle) {
      await handle.close();
    }
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
  });
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

function runGit(repoRoot, args, phase, reason, { input = undefined } = {}) {
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
  if (result.error || result.status !== 0) {
    failProvenance(phase, reason);
  }
  return result.stdout;
}

export async function validateGitRepository(repoArgument, phase = "GIT") {
  const repoRoot = validateAbsoluteNormalizedPath(repoArgument, phase, "repository");
  await inspectRealDirectory(repoRoot, phase, "repository");
  const reported = runGit(
    repoRoot,
    ["rev-parse", "--show-toplevel"],
    phase,
    "repository-root",
  ).toString("utf8").trim();
  if (!pathsEqual(reported, repoRoot)) {
    failProvenance(phase, "repository-root");
  }
  const objectFormat = runGit(
    repoRoot,
    ["rev-parse", "--show-object-format"],
    phase,
    "git-object-format",
  ).toString("ascii").trim();
  if (objectFormat !== "sha1") {
    failProvenance(phase, "git-object-format");
  }
  const replacements = runGit(
    repoRoot,
    ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    phase,
    "replacement-object-check",
  ).toString("utf8").trim();
  if (replacements.length !== 0) {
    failProvenance(phase, "replacement-object-ref");
  }
  return repoRoot;
}

export function verifyGitCommitTree(repoRoot, commit, expectedTree, phase = "GIT") {
  requireLowerHex(commit, FULL_GIT_ID_PATTERN, phase, "commit-id");
  requireLowerHex(expectedTree, FULL_GIT_ID_PATTERN, phase, "tree-id");
  const type = runGit(
    repoRoot,
    ["cat-file", "-t", commit],
    phase,
    "commit-object",
  ).toString("ascii").trim();
  if (type !== "commit") {
    failProvenance(phase, "commit-object-type");
  }
  const commitBytes = runGit(
    repoRoot,
    ["cat-file", "commit", commit],
    phase,
    "commit-read",
  );
  const firstLf = commitBytes.indexOf(0x0a);
  const firstLine = commitBytes.subarray(0, firstLf).toString("ascii");
  if (firstLf < 0 || firstLine !== "tree " + expectedTree) {
    failProvenance(phase, "tree-mismatch");
  }
  const treeType = runGit(
    repoRoot,
    ["cat-file", "-t", expectedTree],
    phase,
    "tree-object",
  ).toString("ascii").trim();
  if (treeType !== "tree") {
    failProvenance(phase, "tree-object-type");
  }
  return true;
}

function splitNullRecords(buffer, phase) {
  const result = [];
  let offset = 0;
  while (offset < buffer.length) {
    const end = buffer.indexOf(0, offset);
    if (end < 0) {
      failProvenance(phase, "git-record-framing");
    }
    if (end > offset) {
      result.push(buffer.subarray(offset, end));
    }
    offset = end + 1;
  }
  return result;
}

function readGitBlobBatch(repoRoot, objectIds, phase) {
  const unique = [...new Set(objectIds)];
  if (unique.length === 0) {
    return new Map();
  }
  const output = runGit(
    repoRoot,
    ["cat-file", "--batch"],
    phase,
    "git-blob-batch",
    { input: Buffer.from(unique.join("\n") + "\n", "ascii") },
  );
  const result = new Map();
  let offset = 0;
  for (const requested of unique) {
    const headerEnd = output.indexOf(0x0a, offset);
    if (headerEnd < 0) {
      failProvenance(phase, "git-blob-header");
    }
    const parts = output.subarray(offset, headerEnd).toString("ascii").split(" ");
    const size = Number(parts[2]);
    if (
      parts.length !== 3
      || parts[0] !== requested
      || parts[1] !== "blob"
      || !safeInteger(size)
    ) {
      failProvenance(phase, "git-blob-object");
    }
    const start = headerEnd + 1;
    const end = start + size;
    if (end >= output.length || output[end] !== 0x0a) {
      failProvenance(phase, "git-blob-truncated");
    }
    const bytes = Buffer.from(output.subarray(start, end));
    if (gitBlobIdBytes(bytes) !== requested) {
      failProvenance(phase, "git-blob-identity");
    }
    result.set(requested, bytes);
    offset = end + 1;
  }
  if (offset !== output.length) {
    failProvenance(phase, "git-blob-trailing");
  }
  return result;
}

export function readGitPathIdentities(repoRoot, commit, entries, phase) {
  if (!Array.isArray(entries)) {
    failProvenance(phase, "git-entry-array");
  }
  if (entries.length === 0) {
    return new Map();
  }
  const requestedPaths = entries.map((entry) => entry.path);
  const output = runGit(
    repoRoot,
    ["ls-tree", "-z", "--full-tree", commit, "--", ...requestedPaths],
    phase,
    "git-tree-read",
  );
  const observed = new Map();
  for (const record of splitNullRecords(output, phase)) {
    const tab = record.indexOf(0x09);
    if (tab < 0) {
      failProvenance(phase, "git-tree-record");
    }
    const [mode, type, objectId] = record
      .subarray(0, tab).toString("ascii").split(" ");
    const relativePath = record.subarray(tab + 1).toString("utf8");
    if (
      (mode !== "100644" && mode !== "100755")
      || type !== "blob"
      || !FULL_GIT_ID_PATTERN.test(objectId)
      || !requestedPaths.includes(relativePath)
      || observed.has(relativePath)
    ) {
      failProvenance(phase, "git-tree-entry");
    }
    observed.set(relativePath, Object.freeze({ mode, objectId }));
  }
  if (observed.size !== requestedPaths.length) {
    failProvenance(phase, "git-path-set");
  }
  const blobs = readGitBlobBatch(
    repoRoot,
    [...observed.values()].map((entry) => entry.objectId),
    phase,
  );
  const result = new Map();
  for (const expected of entries) {
    const treeEntry = observed.get(expected.path);
    const bytes = treeEntry ? blobs.get(treeEntry.objectId) : null;
    if (!treeEntry || !bytes) {
      failProvenance(phase, "git-path-set");
    }
    const identity = Object.freeze({
      bytes,
      gitBlobId: treeEntry.objectId,
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
    });
    if (
      expected.gitBlobId !== identity.gitBlobId
      || expected.sha256 !== identity.sha256
      || expected.byteLength !== identity.byteLength
    ) {
      failProvenance(phase, "git-identity-mismatch");
    }
    result.set(expected.path, identity);
  }
  return result;
}

export function validateNormalizedInputBytes(bytes, normalization) {
  if (normalization === "raw-bytes-v1") {
    return true;
  }
  if (normalization !== "utf8-nfc-lf-v1") {
    failProvenance("INPUT", "input-normalization");
  }
  if (
    bytes.length >= 3
    && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
  ) {
    failProvenance("INPUT", "input-normalization-bom");
  }
  let text;
  try {
    text = UTF8_DECODER.decode(bytes);
  } catch {
    failProvenance("INPUT", "input-normalization-utf8");
  }
  if (text.includes("\r") || text.normalize("NFC") !== text) {
    failProvenance("INPUT", "input-normalization-bytes");
  }
  return true;
}

export function validateDeterministicOutputBytes(bytes, policy) {
  if (
    bytes.length >= 3
    && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
  ) {
    failProvenance("OUTPUT", "output-bom");
  }
  let text;
  try {
    text = UTF8_DECODER.decode(bytes);
  } catch {
    failProvenance("OUTPUT", "output-utf8");
  }
  if (text.includes("\r")) {
    failProvenance("OUTPUT", "output-line-endings");
  }
  if (policy.unicodeNormalization === "nfc" && text.normalize("NFC") !== text) {
    failProvenance("OUTPUT", "output-unicode-normalization");
  }
  if (bytes.length > 0 && bytes.at(-1) !== 0x0a) {
    failProvenance("OUTPUT", "output-final-lf");
  }
  return true;
}

export function requireFileIdentityMatches(actual, expected, phase, reason) {
  if (
    actual.sha256 !== expected.sha256
    || actual.byteLength !== expected.byteLength
    || (
      expected.gitBlobId !== null
      && expected.gitBlobId !== undefined
      && actual.gitBlobId !== expected.gitBlobId
    )
  ) {
    failProvenance(phase, reason);
  }
  return true;
}
