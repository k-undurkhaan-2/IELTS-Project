import { createHash } from "node:crypto";
import { TextDecoder, types as utilTypes } from "node:util";

export const ADAPTER_MODE = "public-source-zip-reproducibility";
export const ARTIFACT_ROLE = "public-source-convenience-download";
export const FORMAT_PROFILE = "zip-canonical-v1";
export const MEDIA_TYPE = "application/zip";
export const ARCHIVE_ROOT = "ieltmps-source/";
export const AUTHORITATIVE_CORRESPONDING_SOURCE = false;
export const INPUT_SET_KIND = "ieltmps-public-source-zip-input-set";
export const CRITICAL_TOOL_SET_KIND =
  "ieltmps-reproducibility-critical-tool-set";
export const CRITICAL_TOOL_SET_ID =
  "public-source-zip-reproducibility-v1";
export const VECTOR_SET_KIND =
  "ieltmps-public-source-zip-boundary-vector-set";
export const VECTOR_SET_ID = "public-source-zip-v1-boundaries-v1";
export const WORKER_PROTOCOL = "ieltmps-public-source-zip-worker-s1";
export const WORKER_CAPSULE_KIND =
  "ieltmps-public-source-zip-worker-capsule-s1";
export const WORKER_ENTRY_MODULE =
  "developer/run-public-source-zip-boundary-vectors.mjs";
export const COMPLETION_MARKER = "complete\n";

export const CRITICAL_TOOL_PATHS = Object.freeze([
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
]);

export const WORKER_MODULE_PATHS = Object.freeze([
  CRITICAL_TOOL_PATHS[0],
  CRITICAL_TOOL_PATHS[1],
  CRITICAL_TOOL_PATHS[2],
  CRITICAL_TOOL_PATHS[3],
  CRITICAL_TOOL_PATHS[4],
  CRITICAL_TOOL_PATHS[7],
  CRITICAL_TOOL_PATHS[9],
]);

export const WORKER_BUILTIN_IMPORTS = Object.freeze([
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:module",
  "node:os",
  "node:path",
  "node:url",
  "node:util",
]);

export const ADAPTER_PHASES = Object.freeze([
  "CLI",
  "POLICY_BINDING",
  "SOURCE_BINDING",
  "TOOL_SET",
  "RUNTIME_IDENTITY",
  "GIT_IDENTITY",
  "PLATFORM_PROBE",
  "ENTRY_PLAN",
  "ZIP_CONSTRUCTION",
  "ZIP_VERIFICATION",
  "BOUNDARY_VECTOR",
  "VECTOR_RESULT",
  "SAME_PROCESS",
  "SAME_HOST",
  "SEMANTIC_REPORT",
  "EVIDENCE",
  "R1_10A_VERIFICATION",
  "OUTPUT_PUBLICATION",
  "CLEANUP",
  "PRIVACY",
]);

export const SUCCESS_OUTPUT_NAMES = Object.freeze([
  "artifact.zip",
  "zip-verification.json",
  "entry-plan.json",
  "input-set.json",
  "semantic-report.json",
  "evidence.json",
  "verification-result.json",
  ".complete",
]);

export const CANONICAL_FAILURE_OUTPUT_NAMES = Object.freeze([
  "input-set.json",
  "evidence.json",
  "verification-result.json",
  ".complete",
]);

export const PUBLICATION_MODES = Object.freeze([
  "success",
  "canonical-post-lock-failure",
  "local-only-failure",
]);

export const VECTOR_EXECUTION_CLASSES = Object.freeze([
  "canonical-writer-verifier",
  "local-header-boundary",
  "central-directory-boundary",
  "eocd-boundary",
  "path-authority",
  "file-identity",
  "independent-malformed-zip",
  "reproducibility-and-privacy",
]);

export const VECTOR_EXPECTED_PHASES = Object.freeze([
  ...ADAPTER_PHASES,
  "ENTRY_PLAN",
  "PATH_AUTHORITY",
  "SOURCE_FILE",
  "ZIP_LAYOUT",
  "ZIP_WRITE",
  "ZIP_PARSE",
  "ZIP_PROFILE",
  "ZIP_BINDING",
]);

export const BOUNDARY_RESULT_KEYS = Object.freeze([
  "status",
  "mode",
  "vectorSetKind",
  "schemaVersion",
  "vectorSetId",
  "artifactRole",
  "formatProfile",
  "testVectorSetSha256",
  "vectorCount",
  "passedCount",
  "failedCount",
  "boundaryVectorSetPassed",
]);

export const VECTOR_SET_KEYS = Object.freeze([
  "vectorSetKind",
  "schemaVersion",
  "vectorSetId",
  "artifactRole",
  "formatProfile",
  "vectors",
]);

export const VECTOR_DESCRIPTOR_KEYS = Object.freeze([
  "vectorId",
  "executionClass",
  "caseId",
  "expectedOutcome",
  "expectedPhase",
  "expectedReason",
]);

export const INPUT_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "sourceCommit",
  "toolingCommit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archiveRoot",
  "entryPlanSha256",
  "entryCount",
  "artifactRole",
  "formatProfile",
  "criticalFiles",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "runnerPolicyIdentitySha256",
  "testVectorSetSha256",
]);

export const INPUT_CRITICAL_FILE_KEYS = Object.freeze([
  "path",
  "toolingCommit",
  "gitMode",
  "gitBlobObjectId",
  "byteLength",
  "sha256",
  "parentLoadedSha256",
  "workerLoadedSha256",
]);

export const TOOL_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "toolSetId",
  "toolingCommit",
  "entries",
]);

export const TOOL_ENTRY_KEYS = Object.freeze([
  "path",
  "gitMode",
  "gitBlobObjectId",
  "declaredByteSize",
  "sha256",
]);

export const WORKER_REQUEST_KEYS = Object.freeze([
  "protocol",
  "lease",
  "assignmentId",
  "assignmentNonce",
  "assignmentPath",
  "repositoryPath",
  "sourceCommit",
  "context",
]);

export const WORKER_LEASE_KEYS = Object.freeze([
  "schemaVersion",
  "runId",
  "parentPid",
  "contextSha256",
  "assignments",
]);

export const WORKER_ASSIGNMENT_KEYS = Object.freeze([
  "assignmentId",
  "assignmentNonce",
  "assignmentPathSha256",
]);

export const WORKER_CONTEXT_KEYS = Object.freeze([
  "toolingCommit",
  "manifestSha256",
  "membershipReportSha256",
  "criticalToolSetSha256",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "runnerPolicySha256",
  "testVectorSetSha256",
  "artifactRole",
  "formatProfile",
]);

export const WORKER_RESPONSE_KEYS = Object.freeze([
  "protocol",
  "runId",
  "assignmentId",
  "contextSha256",
  "status",
  "artifactSha256",
  "artifactByteLength",
  "entryPlanSha256",
  "entryPlanByteLength",
  "transcriptSha256",
  "transcriptByteLength",
  "entryPlanBase64",
  "transcriptBase64",
  "workerCapsuleSha256",
  "workerModuleSetSha256",
  "workerEntryModuleSha256",
  "workerRequestListenerCount",
  "claimCount",
  "workerProcessInvocationCount",
  "comparatorProcessInvocationCount",
  "workerLoadedModuleCount",
  "workerUnapprovedModuleLoadCount",
  "assignmentDirectoryIdentity",
  "artifactFileIdentity",
]);

export const WORKER_CAPSULE_KEYS = Object.freeze([
  "capsuleKind",
  "schemaVersion",
  "toolingCommit",
  "entryModule",
  "moduleOrder",
  "modules",
  "moduleSetSha256",
]);

export const WORKER_CAPSULE_MODULE_KEYS = Object.freeze([
  "relativePath",
  "byteLength",
  "sha256",
  "sourceBase64",
]);

export const LOADED_BYTE_ATTESTATION_KEYS = Object.freeze([
  "workerCapsuleSha256",
  "workerModuleSetSha256",
  "workerEntryModuleSha256",
]);

export const OBJECT_AUTHORITY_LIMITS = Object.freeze({
  maximumDepth: 32,
  maximumNodes: 4096,
  maximumOwnKeys: 4096,
});

const PHASE_SET = new Set([...ADAPTER_PHASES, "OBJECT_AUTHORITY"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const GIT_MODE_SET = new Set(["100644", "100755"]);
const IDENTIFIER_PATTERN = /^[a-z0-9](?:[a-z0-9._+-]{0,126}[a-z0-9])?$/u;
const REASON_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const VECTOR_ID_PATTERN = /^(?:W(?:0[1-9]|10)|L(?:0[1-9]|1[0-2])|C(?:0[1-9]|1[0-6])|E(?:0[1-9]|1[0-3])|P(?:0[1-9]|1[0-9]|20)|F(?:0[1-9]|1[0-2])|M(?:0[1-9]|1[0-8])|R(?:0[1-9]|1[0-8]))$/u;
const ABSOLUTE_WINDOWS_PATH = /^[A-Za-z]:[\\/]/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

export class PublicSourceZipReproducibilityError extends Error {
  constructor(phase, reason) {
    const safePhase = PHASE_SET.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string" && REASON_PATTERN.test(reason)
      ? reason
      : "invalid-operation";
    super("public source ZIP reproducibility operation failed");
    this.name = "PublicSourceZipReproducibilityError";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failZipReproducibility(phase, reason) {
  throw new PublicSourceZipReproducibilityError(phase, reason);
}

export function asZipReproducibilityError(error, phase, reason) {
  assertProxyFreeAuthorityGraph(error, { allowError: true });
  return error instanceof PublicSourceZipReproducibilityError
    ? error
    : new PublicSourceZipReproducibilityError(phase, reason);
}

function deepFreezeTrustedAuthorityGraph(value, visited) {
  if (
    value === null
    || (typeof value !== "object" && typeof value !== "function")
    || visited.has(value)
  ) return value;
  visited.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (Array.isArray(value) && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, "value")) {
      deepFreezeTrustedAuthorityGraph(descriptor.value, visited);
    }
  }
  if (!Object.isFrozen(value)) Object.freeze(value);
  return value;
}

function objectLike(value) {
  return value !== null
    && (typeof value === "object" || typeof value === "function");
}

function failObjectAuthority(reason) {
  throw new PublicSourceZipReproducibilityError("OBJECT_AUTHORITY", reason);
}

function authorityOptionDescriptors(options) {
  if (options === undefined) return Object.create(null);
  if (objectLike(options) && utilTypes.isProxy(options)) {
    failObjectAuthority("proxy-not-allowed");
  }
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype
  ) failObjectAuthority("authority-options-invalid");
  let keys;
  try {
    keys = Reflect.ownKeys(options);
  } catch {
    failObjectAuthority("authority-options-invalid");
  }
  const allowed = new Set([
    "maximumDepth",
    "maximumNodes",
    "maximumOwnKeys",
    "allowedSymbols",
    "allowFunctions",
    "allowBuffer",
    "allowMap",
    "allowSet",
    "allowError",
    "allowPromise",
    "allowNullPrototype",
  ]);
  const descriptors = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string" || !allowed.has(key)) {
      failObjectAuthority("authority-options-invalid");
    }
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failObjectAuthority("authority-options-invalid");
    }
    descriptors[key] = descriptor.value;
  }
  return descriptors;
}

function normalizeAllowedSymbols(value) {
  if (value === undefined) return new Set();
  if (objectLike(value) && utilTypes.isProxy(value)) {
    failObjectAuthority("proxy-not-allowed");
  }
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    failObjectAuthority("authority-options-invalid");
  }
  const keys = Reflect.ownKeys(value);
  const symbols = new Set();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failObjectAuthority("authority-options-invalid");
    }
    if (key === "length") continue;
    if (!/^(?:0|[1-9][0-9]*)$/u.test(key) || typeof descriptor.value !== "symbol") {
      failObjectAuthority("authority-options-invalid");
    }
    symbols.add(descriptor.value);
  }
  return symbols;
}

function authorityConfiguration(options) {
  const descriptors = authorityOptionDescriptors(options);
  const boundedInteger = (name, minimum, maximum) => {
    const selected = descriptors[name] ?? maximum;
    if (
      !Number.isSafeInteger(selected)
      || selected < minimum
      || selected > maximum
    ) failObjectAuthority("authority-options-invalid");
    return selected;
  };
  const flag = (name) => {
    const selected = descriptors[name] ?? false;
    if (typeof selected !== "boolean") {
      failObjectAuthority("authority-options-invalid");
    }
    return selected;
  };
  return Object.freeze({
    maximumDepth: boundedInteger(
      "maximumDepth",
      0,
      OBJECT_AUTHORITY_LIMITS.maximumDepth,
    ),
    maximumNodes: boundedInteger(
      "maximumNodes",
      1,
      OBJECT_AUTHORITY_LIMITS.maximumNodes,
    ),
    maximumOwnKeys: boundedInteger(
      "maximumOwnKeys",
      1,
      OBJECT_AUTHORITY_LIMITS.maximumOwnKeys,
    ),
    allowedSymbols: normalizeAllowedSymbols(descriptors.allowedSymbols),
    allowFunctions: flag("allowFunctions"),
    allowBuffer: flag("allowBuffer"),
    allowMap: flag("allowMap"),
    allowSet: flag("allowSet"),
    allowError: flag("allowError"),
    allowPromise: flag("allowPromise"),
    allowNullPrototype: flag("allowNullPrototype"),
  });
}

function inspectAuthorityOwnData(value, depth, state, visit, arrayValue) {
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    failObjectAuthority("reflection-failed");
  }
  if (keys.length > state.configuration.maximumOwnKeys) {
    failObjectAuthority("object-key-limit");
  }
  for (const key of keys) {
    if (arrayValue && key === "length") continue;
    if (
      typeof key === "symbol"
      && !(depth === 0 && state.configuration.allowedSymbols.has(key))
    ) failObjectAuthority("symbol-key-not-allowed");
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      failObjectAuthority("reflection-failed");
    }
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failObjectAuthority("accessor-not-allowed");
    }
    visit(descriptor.value, depth + 1);
  }
}

export function assertProxyFreeAuthorityGraph(value, options = undefined) {
  if (objectLike(value) && utilTypes.isProxy(value)) {
    failObjectAuthority("proxy-not-allowed");
  }
  const configuration = authorityConfiguration(options);
  const state = {
    configuration,
    nodes: 0,
    active: new WeakSet(),
    visited: new WeakSet(),
  };
  const visit = (current, depth) => {
    if (!objectLike(current)) return;
    if (utilTypes.isProxy(current)) failObjectAuthority("proxy-not-allowed");
    if (depth > configuration.maximumDepth) {
      failObjectAuthority("object-depth-limit");
    }
    if (state.active.has(current)) failObjectAuthority("cycle-not-allowed");
    if (state.visited.has(current)) return;
    state.nodes += 1;
    if (state.nodes > configuration.maximumNodes) {
      failObjectAuthority("object-node-limit");
    }
    if (typeof current === "function") {
      if (!configuration.allowFunctions) {
        failObjectAuthority("custom-prototype-not-allowed");
      }
      state.visited.add(current);
      return;
    }
    if (configuration.allowBuffer && Buffer.isBuffer(current)) {
      if (Object.getPrototypeOf(current) !== Buffer.prototype) {
        failObjectAuthority("custom-prototype-not-allowed");
      }
      state.visited.add(current);
      return;
    }
    if (configuration.allowError && utilTypes.isNativeError(current)) {
      state.visited.add(current);
      return;
    }
    if (configuration.allowPromise && utilTypes.isPromise(current)) {
      state.visited.add(current);
      return;
    }
    let prototype;
    try {
      prototype = Object.getPrototypeOf(current);
    } catch {
      failObjectAuthority("reflection-failed");
    }
    const arrayValue = Array.isArray(current);
    const mapValue = prototype === Map.prototype;
    const setValue = prototype === Set.prototype;
    if (
      (arrayValue && prototype !== Array.prototype)
      || (
        !arrayValue
        && !mapValue
        && !setValue
        && prototype !== Object.prototype
        && !(configuration.allowNullPrototype && prototype === null)
      )
      || (mapValue && !configuration.allowMap)
      || (setValue && !configuration.allowSet)
    ) failObjectAuthority("custom-prototype-not-allowed");
    state.active.add(current);
    inspectAuthorityOwnData(current, depth, state, visit, arrayValue);
    if (mapValue) {
      for (const pair of Map.prototype.entries.call(current)) {
        visit(pair[0], depth + 1);
        visit(pair[1], depth + 1);
      }
    } else if (setValue) {
      for (const entry of Set.prototype.values.call(current)) {
        visit(entry, depth + 1);
      }
    }
    state.active.delete(current);
    state.visited.add(current);
  };
  visit(value, 0);
  return value;
}

export function deepFreezeZipReproducibility(value) {
  assertProxyFreeAuthorityGraph(value);
  return deepFreezeTrustedAuthorityGraph(value, new WeakSet());
}

export function sha256Bytes(value) {
  assertProxyFreeAuthorityGraph(value, { allowBuffer: true });
  return createHash("sha256").update(value).digest("hex");
}

function rejectProxyBeforeReflection(value) {
  return assertProxyFreeAuthorityGraph(value);
}

function rejectPrivateMaterialTrusted(value, phase, label) {
  if (typeof value === "string") {
    if (
      value.includes("\0")
      || ABSOLUTE_WINDOWS_PATH.test(value)
      || value.startsWith("/")
      || value.startsWith("\\\\")
      || /^file:/iu.test(value)
    ) failZipReproducibility(phase, "private-material");
    return value;
  }
  if (!value || typeof value !== "object") return value;
  const arrayValue = Array.isArray(value);
  for (const key of Reflect.ownKeys(value)) {
    if (arrayValue && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    const entry = descriptor.value;
    if (!arrayValue && /path$/iu.test(key) && key !== "path") {
      failZipReproducibility(phase, "private-material");
    }
    rejectPrivateMaterialTrusted(
      entry,
      phase,
      arrayValue ? label + "[" + key + "]" : label + "." + key,
    );
  }
  return value;
}

function exactOrderedDataObject(
  value,
  keys,
  phase,
  reason,
  proxyPhase = phase,
) {
  rejectProxyBeforeReflection(value, proxyPhase);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    failZipReproducibility(phase, reason + "-object");
  }
  let actual;
  let descriptors;
  try {
    actual = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    failZipReproducibility(phase, reason + "-object");
  }
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) {
    failZipReproducibility(phase, reason + "-keys");
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true
      || descriptor.get !== undefined
      || descriptor.set !== undefined
    ) {
      failZipReproducibility(phase, reason + "-descriptor");
    }
  }
  return value;
}

function exactParsedObject(value, keys, phase, reason) {
  rejectProxyBeforeReflection(value, phase);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    failZipReproducibility(phase, reason + "-object");
  }
  let actual;
  let descriptors;
  try {
    actual = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    failZipReproducibility(phase, reason + "-object");
  }
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) {
    failZipReproducibility(phase, reason + "-keys");
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true
      || descriptor.get !== undefined
      || descriptor.set !== undefined
    ) {
      failZipReproducibility(phase, reason + "-descriptor");
    }
  }
  return value;
}

function requireSha256(value, phase, reason) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    failZipReproducibility(phase, reason);
  }
  return value;
}

function requireGitObject(value, phase, reason) {
  if (typeof value !== "string" || !GIT_OBJECT_PATTERN.test(value)) {
    failZipReproducibility(phase, reason);
  }
  return value;
}

function requireIdentifier(value, phase, reason) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    failZipReproducibility(phase, reason);
  }
  return value;
}

function requireCount(value, phase, reason, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    failZipReproducibility(phase, reason);
  }
  return value;
}

function plainClone(value) {
  if (Array.isArray(value)) return value.map(plainClone);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(
      ([key, entry]) => [key, plainClone(entry)],
    ));
  }
  return value;
}

class DuplicateAwareCanonicalJsonParser {
  constructor(text, phase) {
    this.text = text;
    this.phase = phase;
    this.index = 0;
  }

  fail(reason) {
    failZipReproducibility(this.phase, reason);
  }

  peek() {
    return this.text[this.index];
  }

  consume(value, reason) {
    if (!this.text.startsWith(value, this.index)) this.fail(reason);
    this.index += value.length;
  }

  parseString() {
    this.consume('"', "json-string-open");
    const start = this.index;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      const character = this.text[this.index];
      if (character === '"') {
        const value = this.text.slice(start, this.index);
        this.index += 1;
        return value;
      }
      if (character === "\\" || code < 0x20 || code > 0x7e) {
        this.fail("json-string-encoding");
      }
      this.index += 1;
    }
    this.fail("json-string-unterminated");
  }

  parseInteger() {
    const remaining = this.text.slice(this.index);
    const match = /^(?:0|[1-9][0-9]*)/u.exec(remaining);
    if (!match) this.fail("json-integer-encoding");
    this.index += match[0].length;
    const result = Number(match[0]);
    if (!Number.isSafeInteger(result)) this.fail("json-integer-range");
    return result;
  }

  parseArray() {
    this.consume("[", "json-array-open");
    const values = [];
    if (this.peek() === "]") {
      this.index += 1;
      return values;
    }
    while (true) {
      values.push(this.parseValue());
      if (this.peek() === "]") {
        this.index += 1;
        return values;
      }
      this.consume(",", "json-array-comma");
    }
  }

  parseObject() {
    this.consume("{", "json-object-open");
    const value = Object.create(null);
    const seen = new Set();
    if (this.peek() === "}") {
      this.index += 1;
      return value;
    }
    while (true) {
      const key = this.parseString();
      if (seen.has(key)) this.fail("duplicate-json-key");
      seen.add(key);
      this.consume(":", "json-object-colon");
      Object.defineProperty(value, key, {
        value: this.parseValue(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      if (this.peek() === "}") {
        this.index += 1;
        return value;
      }
      this.consume(",", "json-object-comma");
    }
  }

  parseValue() {
    const character = this.peek();
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (character === "t") {
      this.consume("true", "json-boolean");
      return true;
    }
    if (character === "f") {
      this.consume("false", "json-boolean");
      return false;
    }
    if (character === "n") {
      this.consume("null", "json-null");
      return null;
    }
    if (/[0-9]/u.test(character ?? "")) return this.parseInteger();
    this.fail("json-value");
  }

  parse() {
    const value = this.parseValue();
    if (this.index !== this.text.length) this.fail("json-trailing-data");
    return value;
  }
}

export function canonicalPublicJsonBytes(value, phase = "POLICY_BINDING") {
  rejectPrivateMaterial(value, phase);
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failZipReproducibility(phase, "canonical-json-encoding");
  }
  if (
    bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
  ) {
    failZipReproducibility(phase, "canonical-json-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failZipReproducibility(phase, "canonical-json-encoding");
    }
  }
  return bytes;
}

export function parseCanonicalPublicJsonBytes(bytes, phase = "POLICY_BINDING") {
  assertProxyFreeAuthorityGraph(bytes, { allowBuffer: true });
  if (
    !Buffer.isBuffer(bytes)
    || bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
    || (
      bytes.length >= 3
      && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
    )
  ) {
    failZipReproducibility(phase, "canonical-json-framing");
  }
  let text;
  try {
    text = UTF8_DECODER.decode(bytes.subarray(0, -1));
  } catch {
    failZipReproducibility(phase, "canonical-json-utf8");
  }
  const parsed = new DuplicateAwareCanonicalJsonParser(text, phase).parse();
  const value = plainClone(parsed);
  if (!canonicalPublicJsonBytes(value, phase).equals(bytes)) {
    failZipReproducibility(phase, "canonical-json-bytes");
  }
  return deepFreezeZipReproducibility(value);
}

export function rejectPrivateMaterial(value, phase = "PRIVACY", label = "public") {
  assertProxyFreeAuthorityGraph(value);
  return rejectPrivateMaterialTrusted(value, phase, label);
}

export function validateBoundaryVectorDescriptor(value, expected = null) {
  assertProxyFreeAuthorityGraph(value);
  assertProxyFreeAuthorityGraph(expected);
  exactParsedObject(value, VECTOR_DESCRIPTOR_KEYS, "BOUNDARY_VECTOR", "descriptor");
  if (
    typeof value.vectorId !== "string"
    || !VECTOR_ID_PATTERN.test(value.vectorId)
    || !VECTOR_EXECUTION_CLASSES.includes(value.executionClass)
    || !IDENTIFIER_PATTERN.test(value.caseId)
    || !["accept", "reject"].includes(value.expectedOutcome)
    || (
      value.expectedOutcome === "accept"
      && (value.expectedPhase !== null || value.expectedReason !== null)
    )
    || (
      value.expectedOutcome === "reject"
      && (
        typeof value.expectedPhase !== "string"
        || !VECTOR_EXPECTED_PHASES.includes(value.expectedPhase)
        || typeof value.expectedReason !== "string"
        || !REASON_PATTERN.test(value.expectedReason)
      )
    )
  ) {
    failZipReproducibility("BOUNDARY_VECTOR", "descriptor-value");
  }
  if (
    expected
    && VECTOR_DESCRIPTOR_KEYS.some((key) => value[key] !== expected[key])
  ) {
    failZipReproducibility("BOUNDARY_VECTOR", "descriptor-authority");
  }
  return deepFreezeZipReproducibility({ ...value });
}

export function validateBoundaryVectorSet(value, expectedDescriptors) {
  assertProxyFreeAuthorityGraph(value);
  assertProxyFreeAuthorityGraph(expectedDescriptors);
  exactParsedObject(value, VECTOR_SET_KEYS, "BOUNDARY_VECTOR", "vector-set");
  if (
    value.vectorSetKind !== VECTOR_SET_KIND
    || value.schemaVersion !== 1
    || value.vectorSetId !== VECTOR_SET_ID
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Array.isArray(value.vectors)
    || value.vectors.length !== 119
    || !Array.isArray(expectedDescriptors)
    || expectedDescriptors.length !== 119
  ) {
    failZipReproducibility("BOUNDARY_VECTOR", "vector-set-value");
  }
  const seen = new Set();
  const vectors = value.vectors.map((entry, index) => {
    const validated = validateBoundaryVectorDescriptor(
      entry,
      expectedDescriptors[index],
    );
    if (seen.has(validated.vectorId)) {
      failZipReproducibility("BOUNDARY_VECTOR", "descriptor-duplicate");
    }
    seen.add(validated.vectorId);
    return validated;
  });
  if (
    new Set(vectors.map((entry) => entry.executionClass)).size
      !== VECTOR_EXECUTION_CLASSES.length
  ) {
    failZipReproducibility("BOUNDARY_VECTOR", "execution-class-set");
  }
  return deepFreezeZipReproducibility({ ...value, vectors });
}

export function validateBoundaryVectorResult(value, expectedSha256) {
  assertProxyFreeAuthorityGraph(value);
  exactOrderedDataObject(
    value,
    BOUNDARY_RESULT_KEYS,
    "BOUNDARY_VECTOR",
    "result",
    "VECTOR_RESULT",
  );
  if (
    value.status !== "ok"
    || value.mode !== "public-source-zip-boundary-vectors"
    || value.vectorSetKind !== VECTOR_SET_KIND
    || value.schemaVersion !== 1
    || value.vectorSetId !== VECTOR_SET_ID
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || value.testVectorSetSha256 !== expectedSha256
    || !SHA256_PATTERN.test(value.testVectorSetSha256)
    || value.vectorCount !== 119
    || value.passedCount !== 119
    || value.failedCount !== 0
    || value.boundaryVectorSetPassed !== true
  ) {
    failZipReproducibility("BOUNDARY_VECTOR", "result-value");
  }
  return deepFreezeZipReproducibility({ ...value });
}

function validateCriticalFile(value, index) {
  exactParsedObject(
    value,
    INPUT_CRITICAL_FILE_KEYS,
    "TOOL_SET",
    "input-critical-file",
  );
  if (
    value.path !== CRITICAL_TOOL_PATHS[index]
    || value.toolingCommit === undefined
    || !GIT_MODE_SET.has(value.gitMode)
    || !GIT_OBJECT_PATTERN.test(value.gitBlobObjectId)
    || !Number.isSafeInteger(value.byteLength)
    || value.byteLength < 0
    || !SHA256_PATTERN.test(value.sha256)
    || value.parentLoadedSha256 !== value.sha256
    || (
      value.workerLoadedSha256 !== null
      && value.workerLoadedSha256 !== value.sha256
    )
    || (
      WORKER_MODULE_PATHS.includes(value.path)
        !== (value.workerLoadedSha256 === value.sha256)
    )
  ) {
    failZipReproducibility("TOOL_SET", "input-critical-file-value");
  }
  requireGitObject(value.toolingCommit, "TOOL_SET", "tooling-commit");
  return Object.freeze({ ...value });
}

export function validateInputSet(value) {
  assertProxyFreeAuthorityGraph(value);
  exactParsedObject(value, INPUT_SET_KEYS, "SOURCE_BINDING", "input-set");
  if (
    value.documentKind !== INPUT_SET_KIND
    || value.schemaVersion !== 1
    || value.archiveRoot !== ARCHIVE_ROOT
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Array.isArray(value.criticalFiles)
    || value.criticalFiles.length !== CRITICAL_TOOL_PATHS.length
    || value.membershipCount !== value.entryCount
    || !Number.isSafeInteger(value.membershipCount)
    || value.membershipCount < 1
  ) {
    failZipReproducibility("SOURCE_BINDING", "input-set-value");
  }
  requireGitObject(value.sourceCommit, "SOURCE_BINDING", "source-commit");
  requireGitObject(value.toolingCommit, "SOURCE_BINDING", "tooling-commit");
  for (const key of [
    "manifestSha256",
    "membershipReportSha256",
    "entryPlanSha256",
    "runtimeIdentitySha256",
    "gitIdentitySha256",
    "runnerPolicyIdentitySha256",
    "testVectorSetSha256",
  ]) requireSha256(value[key], "SOURCE_BINDING", key.replace(/[A-Z]/gu, "-sha"));
  const criticalFiles = value.criticalFiles.map(validateCriticalFile);
  if (criticalFiles.some((entry) => entry.toolingCommit !== value.toolingCommit)) {
    failZipReproducibility("TOOL_SET", "tooling-commit-mismatch");
  }
  return deepFreezeZipReproducibility({ ...value, criticalFiles });
}

export function encodeCanonicalInputSet(value) {
  return canonicalPublicJsonBytes(validateInputSet(value), "SOURCE_BINDING");
}

export function parseCanonicalInputSet(bytes) {
  assertProxyFreeAuthorityGraph(bytes, { allowBuffer: true });
  const value = validateInputSet(
    parseCanonicalPublicJsonBytes(bytes, "SOURCE_BINDING"),
  );
  if (!encodeCanonicalInputSet(value).equals(bytes)) {
    failZipReproducibility("SOURCE_BINDING", "input-set-bytes");
  }
  return value;
}

export function validateCriticalToolSetDocument(value) {
  assertProxyFreeAuthorityGraph(value);
  exactParsedObject(value, TOOL_SET_KEYS, "TOOL_SET", "tool-set");
  if (
    value.documentKind !== CRITICAL_TOOL_SET_KIND
    || value.schemaVersion !== 1
    || value.toolSetId !== CRITICAL_TOOL_SET_ID
    || !Array.isArray(value.entries)
    || value.entries.length !== CRITICAL_TOOL_PATHS.length
  ) failZipReproducibility("TOOL_SET", "tool-set-value");
  requireGitObject(value.toolingCommit, "TOOL_SET", "tooling-commit");
  const entries = value.entries.map((entry, index) => {
    exactParsedObject(entry, TOOL_ENTRY_KEYS, "TOOL_SET", "tool-entry");
    if (
      entry.path !== CRITICAL_TOOL_PATHS[index]
      || !GIT_MODE_SET.has(entry.gitMode)
      || !GIT_OBJECT_PATTERN.test(entry.gitBlobObjectId)
      || !Number.isSafeInteger(entry.declaredByteSize)
      || entry.declaredByteSize < 0
      || !SHA256_PATTERN.test(entry.sha256)
    ) failZipReproducibility("TOOL_SET", "tool-entry-value");
    return Object.freeze({ ...entry });
  });
  return deepFreezeZipReproducibility({ ...value, entries });
}

export function encodeCanonicalCriticalToolSet(value) {
  return canonicalPublicJsonBytes(
    validateCriticalToolSetDocument(value),
    "TOOL_SET",
  );
}

export function validateLoadedByteAttestation(value) {
  assertProxyFreeAuthorityGraph(value);
  exactOrderedDataObject(
    value,
    LOADED_BYTE_ATTESTATION_KEYS,
    "TOOL_SET",
    "loaded-byte-attestation",
  );
  for (const key of LOADED_BYTE_ATTESTATION_KEYS) {
    requireSha256(value[key], "TOOL_SET", "worker-loaded-bytes-mismatch");
  }
  return Object.freeze({ ...value });
}

function validatePrivateIdentity(value, phase, reason) {
  assertProxyFreeAuthorityGraph(value);
  const keys = ["device", "inode"];
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).length !== keys.length
    || Object.keys(value).some((key, index) => key !== keys[index])
    || !/^(?:0|[1-9][0-9]*)$/u.test(value.device)
    || !/^(?:0|[1-9][0-9]*)$/u.test(value.inode)
  ) failZipReproducibility(phase, reason);
  return Object.freeze({ ...value });
}

export function privatePathSha256(value) {
  if (typeof value !== "string" || value.length === 0) {
    failZipReproducibility("SAME_HOST", "private-path-invalid");
  }
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-private-path-v1\0", "ascii"),
    Buffer.from(value, "utf8"),
  ]));
}

export function canonicalPrivateJsonBytes(value, phase = "SAME_HOST") {
  assertProxyFreeAuthorityGraph(value);
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failZipReproducibility(phase, "private-json-invalid");
  }
  if (
    bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
  ) failZipReproducibility(phase, "private-json-invalid");
  return bytes;
}

export function parseCanonicalPrivateJsonText(text, phase = "SAME_HOST") {
  if (typeof text !== "string") {
    failZipReproducibility(phase, "private-json-invalid");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    failZipReproducibility(phase, "private-json-invalid");
  }
  assertProxyFreeAuthorityGraph(value);
  if (!canonicalPrivateJsonBytes(value, phase).equals(Buffer.from(text, "utf8"))) {
    failZipReproducibility(phase, "private-json-invalid");
  }
  return value;
}

function validateWorkerContext(value) {
  assertProxyFreeAuthorityGraph(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failZipReproducibility("SAME_HOST", "worker-context-invalid");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== WORKER_CONTEXT_KEYS.length
    || actual.some((key, index) => key !== WORKER_CONTEXT_KEYS[index])
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
  ) failZipReproducibility("SAME_HOST", "worker-context-invalid");
  requireGitObject(value.toolingCommit, "SAME_HOST", "worker-context-invalid");
  for (const key of WORKER_CONTEXT_KEYS.slice(1, -2)) {
    requireSha256(value[key], "SAME_HOST", "worker-context-invalid");
  }
  return Object.freeze({ ...value });
}

export function workerContextSha256(value) {
  const context = validateWorkerContext(value);
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-public-source-zip-worker-context-s1\0", "ascii"),
    canonicalPrivateJsonBytes(context),
  ]));
}

export function validateWorkerRequest(value) {
  assertProxyFreeAuthorityGraph(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failZipReproducibility("SAME_HOST", "worker-request-invalid");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== WORKER_REQUEST_KEYS.length
    || actual.some((key, index) => key !== WORKER_REQUEST_KEYS[index])
    || value.protocol !== WORKER_PROTOCOL
    || !["worker-a", "worker-b"].includes(value.assignmentId)
    || !SHA256_PATTERN.test(value.assignmentNonce)
    || typeof value.assignmentPath !== "string"
    || typeof value.repositoryPath !== "string"
    || !GIT_OBJECT_PATTERN.test(value.sourceCommit)
  ) failZipReproducibility("SAME_HOST", "worker-request-invalid");
  const context = validateWorkerContext(value.context);
  const lease = value.lease;
  if (!lease || typeof lease !== "object" || Array.isArray(lease)) {
    failZipReproducibility("SAME_HOST", "worker-lease-invalid");
  }
  const leaseKeys = Object.keys(lease);
  if (
    leaseKeys.length !== WORKER_LEASE_KEYS.length
    || leaseKeys.some((key, index) => key !== WORKER_LEASE_KEYS[index])
    || lease.schemaVersion !== 1
    || !SHA256_PATTERN.test(lease.runId)
    || !Number.isSafeInteger(lease.parentPid)
    || lease.parentPid <= 0
    || lease.contextSha256 !== workerContextSha256(context)
    || !Array.isArray(lease.assignments)
    || lease.assignments.length !== 2
  ) failZipReproducibility("SAME_HOST", "worker-lease-invalid");
  const assignments = lease.assignments.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      failZipReproducibility("SAME_HOST", "worker-assignment-invalid");
    }
    const keys = Object.keys(entry);
    if (
      keys.length !== WORKER_ASSIGNMENT_KEYS.length
      || keys.some((key, position) => key !== WORKER_ASSIGNMENT_KEYS[position])
      || entry.assignmentId !== ["worker-a", "worker-b"][index]
      || !SHA256_PATTERN.test(entry.assignmentNonce)
      || !SHA256_PATTERN.test(entry.assignmentPathSha256)
    ) failZipReproducibility("SAME_HOST", "worker-assignment-invalid");
    return Object.freeze({ ...entry });
  });
  const assignment = assignments.find(
    (entry) => entry.assignmentId === value.assignmentId,
  );
  if (
    !assignment
    || assignment.assignmentNonce !== value.assignmentNonce
    || assignment.assignmentPathSha256 !== privatePathSha256(value.assignmentPath)
  ) failZipReproducibility("SAME_HOST", "worker-assignment-invalid");
  return deepFreezeZipReproducibility({
    ...value,
    lease: { ...lease, assignments },
    context,
  });
}

export function validateWorkerResponse(value, expected) {
  assertProxyFreeAuthorityGraph(value);
  assertProxyFreeAuthorityGraph(expected);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failZipReproducibility("SAME_HOST", "worker-response-invalid");
  }
  const keys = Object.keys(value);
  if (
    keys.length !== WORKER_RESPONSE_KEYS.length
    || keys.some((key, index) => key !== WORKER_RESPONSE_KEYS[index])
    || value.protocol !== WORKER_PROTOCOL
    || value.status !== "ok"
    || value.workerRequestListenerCount !== 0
    || value.claimCount !== 1
    || value.comparatorProcessInvocationCount !== 0
    || value.workerUnapprovedModuleLoadCount !== 0
  ) failZipReproducibility("SAME_HOST", "worker-response-invalid");
  for (const key of [
    "artifactSha256",
    "entryPlanSha256",
    "transcriptSha256",
    ...LOADED_BYTE_ATTESTATION_KEYS,
  ]) requireSha256(value[key], "SAME_HOST", "worker-response-invalid");
  for (const key of [
    "artifactByteLength",
    "entryPlanByteLength",
    "transcriptByteLength",
    "workerProcessInvocationCount",
    "workerLoadedModuleCount",
  ]) requireCount(value[key], "SAME_HOST", "worker-response-invalid", 1);
  for (const key of [
    "comparatorProcessInvocationCount",
    "workerUnapprovedModuleLoadCount",
  ]) requireCount(value[key], "SAME_HOST", "worker-response-invalid", 0);
  if (
    expected
    && (
      value.runId !== expected.runId
      || value.assignmentId !== expected.assignmentId
      || value.contextSha256 !== expected.contextSha256
      || value.workerCapsuleSha256 !== expected.workerCapsuleSha256
      || value.workerModuleSetSha256 !== expected.workerModuleSetSha256
      || value.workerEntryModuleSha256 !== expected.workerEntryModuleSha256
    )
  ) failZipReproducibility("TOOL_SET", "worker-loaded-bytes-mismatch");
  let entryPlan;
  let transcript;
  try {
    entryPlan = Buffer.from(value.entryPlanBase64, "base64");
    transcript = Buffer.from(value.transcriptBase64, "base64");
  } catch {
    failZipReproducibility("SAME_HOST", "worker-response-invalid");
  }
  if (
    entryPlan.toString("base64") !== value.entryPlanBase64
    || transcript.toString("base64") !== value.transcriptBase64
    || entryPlan.length !== value.entryPlanByteLength
    || transcript.length !== value.transcriptByteLength
    || sha256Bytes(entryPlan) !== value.entryPlanSha256
    || sha256Bytes(transcript) !== value.transcriptSha256
  ) failZipReproducibility("SAME_HOST", "worker-response-invalid");
  validatePrivateIdentity(
    value.assignmentDirectoryIdentity,
    "SAME_HOST",
    "worker-response-invalid",
  );
  validatePrivateIdentity(
    value.artifactFileIdentity,
    "SAME_HOST",
    "worker-response-invalid",
  );
  return Object.freeze({ ...value, entryPlan, transcript });
}

export function validateOutputEntrySet(names, mode) {
  assertProxyFreeAuthorityGraph(names);
  if (!Array.isArray(names) || !PUBLICATION_MODES.includes(mode)) {
    failZipReproducibility("OUTPUT_PUBLICATION", "output-entry-set");
  }
  const expected = mode === "success"
    ? SUCCESS_OUTPUT_NAMES
    : mode === "canonical-post-lock-failure"
      ? CANONICAL_FAILURE_OUTPUT_NAMES
      : [];
  if (
    names.length !== expected.length
    || names.some((name, index) => name !== expected[index])
  ) failZipReproducibility("OUTPUT_PUBLICATION", "output-entry-set");
  return Object.freeze([...names]);
}

export function selectPublicationMode(mode) {
  if (!PUBLICATION_MODES.includes(mode)) {
    failZipReproducibility("OUTPUT_PUBLICATION", "publication-mode");
  }
  return Object.freeze({ mode });
}

export const WORKER_BOOTSTRAP_SOURCE = String.raw`
import childProcess from "node:child_process";
import {createHash} from "node:crypto";
import {constants as C,writeSync} from "node:fs";
import {lstat,open,realpath} from "node:fs/promises";
import {registerHooks,syncBuiltinESMExports} from "node:module";
import path from "node:path";
import {pathToFileURL} from "node:url";
const FAIL=Buffer.from("ERROR TOOL_SET: worker-loaded-bytes-mismatch\n","ascii");
const fatal=()=>{try{writeSync(2,FAIL);}catch{}try{if(process.connected)process.disconnect();}catch{}process.exit(1);};
const hex=(bytes)=>createHash("sha256").update(bytes).digest("hex");
const same=(state,device,inode)=>String(state.dev)===device&&String(state.ino)===inode;
const samePath=(a,b)=>process.platform==="win32"?a.toLowerCase()===b.toLowerCase():a===b;
const exact=(value,keys)=>value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&Object.keys(value).every((key,index)=>key===keys[index]);
const capsuleKeys=${JSON.stringify(WORKER_CAPSULE_KEYS)};
const moduleKeys=${JSON.stringify(WORKER_CAPSULE_MODULE_KEYS)};
const builtins=new Set(${JSON.stringify(WORKER_BUILTIN_IMPORTS)});
const audit={workerProcessInvocationCount:0,comparatorProcessInvocationCount:0,loadedUrls:new Set(),workerUnapprovedModuleLoadCount:0};
const auditProcess=(command,args)=>{audit.workerProcessInvocationCount+=1;const list=[String(command??""),...(Array.isArray(args)?args.map((entry)=>String(entry)):[])].join("\0");if(/compare-reproducibility/iu.test(list))audit.comparatorProcessInvocationCount+=1;};
const originalSpawn=childProcess.spawn.bind(childProcess);
const originalSpawnSync=childProcess.spawnSync.bind(childProcess);
childProcess.spawn=function(command,args,...rest){auditProcess(command,args);return originalSpawn(command,args,...rest);};
childProcess.spawnSync=function(command,args,...rest){auditProcess(command,args);return originalSpawnSync(command,args,...rest);};
syncBuiltinESMExports();
let capsule,moduleMap,capsulePath;
try{
  if(process.argv.length!==8)throw new Error();
  capsulePath=path.resolve(process.argv[1]);
  if(capsulePath!==process.argv[1])throw new Error();
  const [expectedSha,device,inode,parentDevice,parentInode,pathSha]=process.argv.slice(2);
  if(!/^[0-9a-f]{64}$/u.test(expectedSha)||!/^[0-9]+$/u.test(device)||!/^[0-9]+$/u.test(inode)||!/^[0-9]+$/u.test(parentDevice)||!/^[0-9]+$/u.test(parentInode)||!/^[0-9a-f]{64}$/u.test(pathSha))throw new Error();
  const parent=path.dirname(capsulePath);
  const parentBefore=await lstat(parent,{bigint:true});
  const before=await lstat(capsulePath,{bigint:true});
  if(parentBefore.isSymbolicLink()||!parentBefore.isDirectory()||before.isSymbolicLink()||!before.isFile()||before.nlink!==1n||!same(parentBefore,parentDevice,parentInode)||!same(before,device,inode)||!samePath(path.resolve(await realpath(parent)),parent)||!samePath(path.resolve(await realpath(capsulePath)),capsulePath)||hex(Buffer.concat([Buffer.from("ieltmps-private-path-v1\0","ascii"),Buffer.from(capsulePath,"utf8")]))!==pathSha)throw new Error();
  const handle=await open(capsulePath,C.O_RDONLY|(C.O_NOFOLLOW??0));
  let bytes;
  try{const opened=await handle.stat({bigint:true});if(!same(opened,device,inode)||opened.nlink!==1n||opened.size<1n||opened.size>16777216n)throw new Error();bytes=await handle.readFile();const after=await handle.stat({bigint:true});if(!same(after,device,inode)||BigInt(bytes.length)!==after.size)throw new Error();}finally{await handle.close();}
  const final=await lstat(capsulePath,{bigint:true});
  if(!same(final,device,inode)||final.nlink!==1n||hex(bytes)!==expectedSha)throw new Error();
  capsule=JSON.parse(bytes.toString("utf8"));
  if(!Buffer.from(JSON.stringify(capsule)+"\n","utf8").equals(bytes)||!exact(capsule,capsuleKeys)||capsule.capsuleKind!==${JSON.stringify(WORKER_CAPSULE_KIND)}||capsule.schemaVersion!==1||!/^[0-9a-f]{40}$/u.test(capsule.toolingCommit)||capsule.entryModule!==${JSON.stringify(WORKER_ENTRY_MODULE)}||!Array.isArray(capsule.moduleOrder)||!Array.isArray(capsule.modules)||capsule.moduleOrder.length!==capsule.modules.length||capsule.moduleOrder.length<1||!/^[0-9a-f]{64}$/u.test(capsule.moduleSetSha256))throw new Error();
  moduleMap=new Map();const digest=createHash("sha256");
  for(let index=0;index<capsule.modules.length;index+=1){const entry=capsule.modules[index];if(!exact(entry,moduleKeys)||entry.relativePath!==capsule.moduleOrder[index]||entry.relativePath.includes("..")||!/^[a-z0-9][a-z0-9./_-]*\.mjs$/u.test(entry.relativePath)||!Number.isSafeInteger(entry.byteLength)||entry.byteLength<0||!/^[0-9a-f]{64}$/u.test(entry.sha256)||typeof entry.sourceBase64!=="string"||moduleMap.has(entry.relativePath))throw new Error();const source=Buffer.from(entry.sourceBase64,"base64");if(source.toString("base64")!==entry.sourceBase64||source.length!==entry.byteLength||hex(source)!==entry.sha256||!Buffer.from(source.toString("utf8"),"utf8").equals(source))throw new Error();digest.update(Buffer.from(entry.relativePath,"utf8"));digest.update(Buffer.from([0]));digest.update(Buffer.from(String(source.length),"ascii"));digest.update(Buffer.from([0]));digest.update(source);moduleMap.set(entry.relativePath,Object.freeze({source:source.toString("utf8"),sha256:entry.sha256}));}
  if(digest.digest("hex")!==capsule.moduleSetSha256||!moduleMap.has(capsule.entryModule))throw new Error();
  const anchorRoot=path.join(path.dirname(capsulePath),"virtual-root");
  const anchorRootState=await lstat(anchorRoot,{bigint:true});
  if(anchorRootState.isSymbolicLink()||!anchorRootState.isDirectory()||!samePath(path.resolve(await realpath(anchorRoot)),anchorRoot))throw new Error();
  for(const relativePath of capsule.moduleOrder){const anchorPath=path.join(anchorRoot,relativePath);const anchor=await lstat(anchorPath,{bigint:true});if(anchor.isSymbolicLink()||!anchor.isFile()||anchor.nlink!==1n||anchor.size!==0n||!samePath(path.resolve(await realpath(anchorPath)),anchorPath))throw new Error();}
}catch{fatal();}
const base=pathToFileURL(path.join(path.dirname(capsulePath),"virtual-root")+path.sep).href;
const urls=new Map([...moduleMap].map(([relativePath,value])=>[new URL(relativePath,base).href,value]));
const requireUrl=(url)=>{if(typeof url!=="string"||!urls.has(url)){audit.workerUnapprovedModuleLoadCount+=1;throw new Error();}audit.loadedUrls.add(url);return urls.get(url);};
const entryUrl=new URL(capsule.entryModule,base).href;
registerHooks({resolve(specifier,context,next){if(builtins.has(specifier))return next(specifier,context);if(specifier===entryUrl)return{url:entryUrl,shortCircuit:true};if(typeof specifier!=="string"||(!specifier.startsWith("./")&&!specifier.startsWith("../"))||typeof context.parentURL!=="string"||!urls.has(context.parentURL)){audit.workerUnapprovedModuleLoadCount+=1;throw new Error();}const resolved=new URL(specifier,context.parentURL).href;requireUrl(resolved);return{url:resolved,shortCircuit:true};},load(url,context,next){if(builtins.has(url))return next(url,context);return{format:"module",source:requireUrl(url).source,shortCircuit:true};}});
const entry=moduleMap.get(capsule.entryModule);
Object.defineProperty(globalThis,"__IELTMPS_ZIP_WORKER_LOADED_BYTES__",{value:Object.freeze({workerCapsuleSha256:process.argv[2],workerModuleSetSha256:capsule.moduleSetSha256,workerEntryModuleSha256:entry.sha256}),writable:false,configurable:false,enumerable:false});
Object.defineProperty(globalThis,"__IELTMPS_ZIP_WORKER_AUDIT__",{value:Object.freeze({snapshot:()=>Object.freeze({workerProcessInvocationCount:audit.workerProcessInvocationCount,comparatorProcessInvocationCount:audit.comparatorProcessInvocationCount,workerLoadedModuleCount:audit.loadedUrls.size,workerUnapprovedModuleLoadCount:audit.workerUnapprovedModuleLoadCount})}),writable:false,configurable:false,enumerable:false});
let worker;
try{worker=await im${""}port(entryUrl);if(typeof worker.runPrivateZipWorker!=="function")throw new Error();}catch{fatal();}
await worker.runPrivateZipWorker();
`;
