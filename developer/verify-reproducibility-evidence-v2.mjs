#!/usr/bin/env node

import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
  parseCanonicalInputSet,
  parseCanonicalPublicJsonBytes,
  validateCriticalToolSetDocument,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  ReproducibilityEvidenceV2Error,
  buildExecutionIdentityV2,
  buildPlatformClassV2,
  buildReproducibilityEvidenceV2,
  buildRuntimeClassV2,
  buildSemanticInputSetV2,
  buildVerificationResultV2,
  encodeCanonicalExecutionIdentityV2,
  encodeCanonicalPlatformClassV2,
  encodeCanonicalReproducibilityEvidenceV2,
  encodeCanonicalRuntimeClassV2,
  encodeCanonicalSemanticInputSetV2,
  encodeCanonicalVerificationResultV2,
  failReproducibilityEvidenceV2,
  parseCanonicalExecutionIdentityV2Bytes,
  parseCanonicalPlatformClassV2Bytes,
  parseCanonicalReproducibilityEvidenceV2Bytes,
  parseCanonicalRuntimeClassV2Bytes,
  parseCanonicalSemanticInputSetV2Bytes,
  parseCanonicalVerificationResultV2Bytes,
} from "./reproducibility-evidence-v2-core.mjs";
import {
  parseCanonicalCampaignPolicyBytes,
  parseCanonicalEnvironmentLockBytes,
  findCellProducerGpgAuthorities,
  parseCanonicalGitIdentityBindingBytes,
  parseCanonicalPlatformProbeBytes,
  parseCanonicalRuntimeIdentityBindingBytes,
} from "./public-source-zip-campaign-core.mjs";

const VERIFIER_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.verify-v2.test-adapter",
);
const AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([VERIFIER_TEST_ADAPTER]),
  allowFunctions: true,
});
const REQUIRED_OPTIONS = Object.freeze([
  "campaignPolicy",
  "criticalToolSet",
  "runtimeIdentity",
  "gitIdentity",
  "platformProbe",
  "environmentLock",
  "semanticInputSet",
  "executionIdentity",
  "platformClass",
  "runtimeClass",
  "evidence",
  "d2InputSet",
  "d2SemanticReport",
  "d2Evidence",
  "d2VerificationResult",
  "artifact",
  "entryPlan",
  "zipVerification",
]);
const OPTIONAL_OPTIONS = Object.freeze(["verificationResult"]);
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;

function authority(value, options = undefined) {
  try {
    assertProxyFreeAuthorityGraph(value, options);
  } catch {
    failReproducibilityEvidenceV2(
      "OBJECT_AUTHORITY",
      "authority-graph-rejected",
    );
  }
  return value;
}

function normalizeOptions(options) {
  authority(options, AUTHORITY_OPTIONS);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype
  ) failReproducibilityEvidenceV2("CLI", "api-options-object");
  const keys = Reflect.ownKeys(options);
  const allowed = new Set([...REQUIRED_OPTIONS, ...OPTIONAL_OPTIONS]);
  for (const key of keys) {
    if (key === VERIFIER_TEST_ADAPTER) continue;
    if (typeof key !== "string" || !allowed.has(key)) {
      failReproducibilityEvidenceV2("CLI", "api-option-key");
    }
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failReproducibilityEvidenceV2("CLI", "api-option-descriptor");
    }
  }
  for (const key of REQUIRED_OPTIONS) {
    if (!Object.hasOwn(options, key) || typeof options[key] !== "string" || options[key].length === 0) {
      failReproducibilityEvidenceV2("CLI", "api-required-option");
    }
  }
  if (
    Object.hasOwn(options, "verificationResult")
    && (typeof options.verificationResult !== "string" || options.verificationResult.length === 0)
  ) failReproducibilityEvidenceV2("CLI", "api-optional-option");
  const hookDescriptor = Object.getOwnPropertyDescriptor(options, VERIFIER_TEST_ADAPTER);
  return Object.freeze({
    ...Object.fromEntries(REQUIRED_OPTIONS.map((key) => [key, options[key]])),
    verificationResult: options.verificationResult,
    testAdapter: hookDescriptor?.value ?? null,
  });
}

function nativeComparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

async function stableRead(filePath, label, maximumBytes, testAdapter) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    failReproducibilityEvidenceV2("CLI", "file-option");
  }
  let initial;
  let handle = null;
  try {
    initial = await lstat(filePath, { bigint: true });
    if (
      !initial.isFile()
      || initial.isSymbolicLink()
      || initial.nlink !== 1n
      || initial.size < 0n
      || initial.size > BigInt(maximumBytes)
      || nativeComparable(await realpath(filePath)) !== nativeComparable(filePath)
    ) failReproducibilityEvidenceV2("D2_BINDING", "stable-file-identity");
    handle = await open(
      filePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = await handle.stat({ bigint: true });
    if (testAdapter?.afterOpen !== undefined) {
      const pending = testAdapter.afterOpen(Object.freeze({ label }));
      authority(pending, { allowPromise: true });
      const returned = await pending;
      authority(returned);
      if (returned !== undefined) {
        failReproducibilityEvidenceV2("CLI", "test-adapter-return-value");
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const same = ["dev", "ino", "size", "nlink", "mode"].every(
      (key) => initial[key] === before[key] && before[key] === after[key],
    );
    if (!same || bytes.length !== Number(initial.size)) {
      failReproducibilityEvidenceV2("D2_BINDING", "mutable-input");
    }
    return bytes;
  } catch (error) {
    if (error instanceof ReproducibilityEvidenceV2Error) throw error;
    failReproducibilityEvidenceV2("D2_BINDING", "stable-file-read");
  } finally {
    if (handle) await handle.close();
  }
}

function requireExactBytes(actual, expected, phase, reason) {
  if (!actual.equals(expected)) {
    failReproducibilityEvidenceV2(phase, reason);
  }
}

async function verifyInternal(options) {
  const normalized = normalizeOptions(options);
  const documents = Object.create(null);
  for (const key of REQUIRED_OPTIONS) {
    const maximum = key === "artifact" ? MAX_ARTIFACT_BYTES : MAX_DOCUMENT_BYTES;
    documents[key] = await stableRead(
      normalized[key],
      key,
      maximum,
      normalized.testAdapter,
    );
  }

  let campaignPolicy;
  let criticalToolSet;
  let runtimeIdentity;
  let gitIdentity;
  let platformProbe;
  let environmentLock;
  let semanticInputSet;
  let executionIdentity;
  let platformClass;
  let runtimeClass;
  let evidence;
  try {
    campaignPolicy = parseCanonicalCampaignPolicyBytes(documents.campaignPolicy);
    criticalToolSet = validateCriticalToolSetDocument(
      parseCanonicalPublicJsonBytes(documents.criticalToolSet, "TOOL_SET"),
    );
    runtimeIdentity = parseCanonicalRuntimeIdentityBindingBytes(documents.runtimeIdentity);
    gitIdentity = parseCanonicalGitIdentityBindingBytes(documents.gitIdentity);
    platformProbe = parseCanonicalPlatformProbeBytes(documents.platformProbe);
    environmentLock = parseCanonicalEnvironmentLockBytes(documents.environmentLock);
    semanticInputSet = parseCanonicalSemanticInputSetV2Bytes(documents.semanticInputSet);
    executionIdentity = parseCanonicalExecutionIdentityV2Bytes(documents.executionIdentity);
    platformClass = parseCanonicalPlatformClassV2Bytes(documents.platformClass);
    runtimeClass = parseCanonicalRuntimeClassV2Bytes(documents.runtimeClass);
    evidence = parseCanonicalReproducibilityEvidenceV2Bytes(documents.evidence);
  } catch (error) {
    if (error instanceof ReproducibilityEvidenceV2Error) throw error;
    failReproducibilityEvidenceV2("D2_BINDING", "supporting-document-invalid");
  }

  const gpgAuthority = findCellProducerGpgAuthorities(
    campaignPolicy,
    evidence.matrixCellId,
  ).signing;
  if (
    executionIdentity.producerGpgProfileSha256 !== gpgAuthority.profileSha256
    || evidence.producerGpgProfileSha256 !== gpgAuthority.profileSha256
  ) failReproducibilityEvidenceV2(
    "EXECUTION_IDENTITY",
    "gpg-verifier-profile-binding",
  );

  const rebuiltSemantic = buildSemanticInputSetV2({
    campaignPolicy,
    d2InputSet: (() => {
      try {
        return parseCanonicalInputSet(documents.d2InputSet);
      } catch {
        failReproducibilityEvidenceV2("D2_BINDING", "d2-input-set-invalid");
      }
    })(),
    criticalToolSet,
  });
  requireExactBytes(
    documents.semanticInputSet,
    encodeCanonicalSemanticInputSetV2(rebuiltSemantic),
    "SEMANTIC_IDENTITY",
    "semantic-input-set-mismatch",
  );

  const rebuiltPlatformClass = buildPlatformClassV2({
    campaignPolicy,
    platformProbe,
  });
  requireExactBytes(
    documents.platformClass,
    encodeCanonicalPlatformClassV2(rebuiltPlatformClass),
    "PLATFORM_CLASS",
    "platform-class-mismatch",
  );

  const rebuiltRuntimeClass = buildRuntimeClassV2({
    runtimeIdentity,
    platformProbe,
  });
  requireExactBytes(
    documents.runtimeClass,
    encodeCanonicalRuntimeClassV2(rebuiltRuntimeClass),
    "RUNTIME_CLASS",
    "runtime-class-mismatch",
  );

  const rebuiltExecution = buildExecutionIdentityV2({
    campaignPolicy,
    matrixCellId: evidence.matrixCellId,
    runtimeIdentity,
    runtimeClass: rebuiltRuntimeClass,
    gitIdentity,
    platformProbe,
    platformClass: rebuiltPlatformClass,
    environmentLock,
    runNonce: executionIdentity.runNonce,
  });
  requireExactBytes(
    documents.executionIdentity,
    encodeCanonicalExecutionIdentityV2(rebuiltExecution),
    "EXECUTION_IDENTITY",
    "execution-identity-mismatch",
  );

  const rebuiltEvidence = buildReproducibilityEvidenceV2({
    campaignPolicy,
    matrixCellId: evidence.matrixCellId,
    semanticInputSet: rebuiltSemantic,
    executionIdentity: rebuiltExecution,
    platformClass: rebuiltPlatformClass,
    runtimeClass: rebuiltRuntimeClass,
    d2Bundle: {
      inputSetBytes: documents.d2InputSet,
      semanticReportBytes: documents.d2SemanticReport,
      evidenceBytes: documents.d2Evidence,
      verificationResultBytes: documents.d2VerificationResult,
      artifactBytes: documents.artifact,
      entryPlanBytes: documents.entryPlan,
      zipVerificationBytes: documents.zipVerification,
    },
  });
  requireExactBytes(
    documents.evidence,
    encodeCanonicalReproducibilityEvidenceV2(rebuiltEvidence),
    "EVIDENCE_SCHEMA",
    "evidence-mismatch",
  );

  const result = buildVerificationResultV2({ evidence: rebuiltEvidence });
  if (normalized.verificationResult !== undefined) {
    const expectedBytes = await stableRead(
      normalized.verificationResult,
      "verificationResult",
      MAX_DOCUMENT_BYTES,
      normalized.testAdapter,
    );
    parseCanonicalVerificationResultV2Bytes(expectedBytes);
    requireExactBytes(
      expectedBytes,
      encodeCanonicalVerificationResultV2(result),
      "VERIFICATION_RESULT_SCHEMA",
      "verification-result-mismatch",
    );
  }
  return result;
}

export async function verifyReproducibilityEvidenceV2(options = {}) {
  return verifyInternal(options);
}

function parseOptions(argv) {
  authority(argv);
  const flagMap = new Map([
    ["--campaign-policy", "campaignPolicy"],
    ["--critical-tool-set", "criticalToolSet"],
    ["--runtime-identity", "runtimeIdentity"],
    ["--git-identity", "gitIdentity"],
    ["--platform-probe", "platformProbe"],
    ["--environment-lock", "environmentLock"],
    ["--semantic-input-set", "semanticInputSet"],
    ["--execution-identity", "executionIdentity"],
    ["--platform-class", "platformClass"],
    ["--runtime-class", "runtimeClass"],
    ["--evidence", "evidence"],
    ["--verification-result", "verificationResult"],
    ["--d2-input-set", "d2InputSet"],
    ["--d2-semantic-report", "d2SemanticReport"],
    ["--d2-evidence", "d2Evidence"],
    ["--d2-verification-result", "d2VerificationResult"],
    ["--artifact", "artifact"],
    ["--entry-plan", "entryPlan"],
    ["--zip-verification", "zipVerification"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = flagMap.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(result, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) failReproducibilityEvidenceV2("CLI", "unknown-or-duplicate-option");
    result[key] = argv[index + 1];
    index += 1;
  }
  if (REQUIRED_OPTIONS.some((key) => !Object.hasOwn(result, key))) {
    failReproducibilityEvidenceV2("CLI", "required-options");
  }
  return Object.fromEntries([
    ...REQUIRED_OPTIONS.map((key) => [key, result[key]]),
    ...(Object.hasOwn(result, "verificationResult")
      ? [["verificationResult", result.verificationResult]]
      : []),
  ]);
}

function isMainModule() {
  if (typeof process.argv[1] !== "string" || process.argv[1].length === 0) return false;
  try {
    const modulePath = realpathSync.native(fileURLToPath(import.meta.url));
    const entryPath = realpathSync.native(path.resolve(process.argv[1]));
    return nativeComparable(modulePath) === nativeComparable(entryPath);
  } catch {
    return false;
  }
}

async function main() {
  const result = await verifyInternal(parseOptions(process.argv.slice(2)));
  process.stdout.write(encodeCanonicalVerificationResultV2(result));
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof ReproducibilityEvidenceV2Error
      ? error
      : new ReproducibilityEvidenceV2Error("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
