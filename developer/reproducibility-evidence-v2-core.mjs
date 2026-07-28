import { createHash } from "node:crypto";

import {
  assertProxyFreeAuthorityGraph,
  canonicalPublicJsonBytes,
  deepFreezeZipReproducibility,
  encodeCanonicalCriticalToolSet,
  encodeCanonicalInputSet,
  parseCanonicalInputSet,
  parseCanonicalPublicJsonBytes,
  validateCriticalToolSetDocument,
  validateInputSet,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  parseCanonicalReproducibilityEvidence,
  parseCanonicalSemanticReport,
  parseCanonicalVerificationResult,
} from "./reproducibility-evidence-core.mjs";

export const REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION = 2;
export const SEMANTIC_INPUT_SET_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-semantic-input-set-v2";
export const EXECUTION_IDENTITY_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-execution-identity-v2";
export const PLATFORM_CLASS_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-platform-class-v2";
export const RUNTIME_CLASS_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-runtime-class-v2";
export const REPRODUCIBILITY_EVIDENCE_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-evidence-v2";
export const REPRODUCIBILITY_VERIFICATION_V2_DOCUMENT_KIND =
  "ieltmps-reproducibility-evidence-v2-verification";

export const CLAIM_LEVELS_V2 = Object.freeze([
  "L0", "L1", "L2", "L3", "L4", "L5",
]);

export const SEMANTIC_INPUT_SET_V2_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "campaignSchemaId",
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
  "criticalToolSemanticSetSha256",
  "vectorSetSha256",
]);

export const EXECUTION_IDENTITY_V2_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "campaignId",
  "matrixCellId",
  "sourceCommit",
  "toolingCommit",
  "runtimeIdentitySha256",
  "nodeRuntimeProfileSha256",
  "nodeImmutableInstallationProfileSha256",
  "runtimeClassSha256",
  "gitIdentitySha256",
  "producerGpgProfileSha256",
  "producerGpgImmutableInstallationProfileSha256",
  "platformProbeSha256",
  "platformClassSha256",
  "environmentLockSha256",
  "runNonce",
]);

export const PLATFORM_CLASS_V2_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "platformProfileVersion",
  "osFamily",
  "osBuildPolicy",
  "architecture",
  "filesystemClass",
]);

export const RUNTIME_CLASS_V2_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "runtimeFamily",
  "runtimeVersion",
  "v8Version",
  "modulesAbi",
  "distributionProfile",
  "architecture",
]);

export const REPRODUCIBILITY_EVIDENCE_V2_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "campaignId",
  "matrixCellId",
  "sourceCommit",
  "toolingCommit",
  "semanticInputSetSha256",
  "executionIdentitySha256",
  "producerGpgProfileSha256",
  "platformClassSha256",
  "runtimeClassSha256",
  "d2InputSetSha256",
  "d2SemanticReportSha256",
  "d2EvidenceSha256",
  "d2VerificationResultSha256",
  "artifactSha256",
  "entryPlanSha256",
  "zipVerificationSha256",
  "vectorSetSha256",
  "canonicalVerifierPassed",
  "sameProcessRepeatable",
  "sameHostRepeatable",
  "boundaryVectorSetPassed",
]);

export const VERIFICATION_RESULT_V2_KEYS = Object.freeze([
  "status",
  "mode",
  "schemaVersion",
  "campaignId",
  "matrixCellId",
  "semanticInputSetSha256",
  "executionIdentitySha256",
  "producerGpgProfileSha256",
  "platformClassSha256",
  "runtimeClassSha256",
  "artifactSha256",
  "comparisonEligible",
  "semanticClaimsBound",
  "semanticClaimsIndependentlyReplayed",
  "evidenceSigningRequired",
  "platformAttestationVerified",
  "projectPublicationAuthorized",
]);

const SEMANTIC_BUILD_KEYS = Object.freeze([
  "campaignPolicy", "d2InputSet", "criticalToolSet",
]);
const PLATFORM_BUILD_KEYS = Object.freeze([
  "campaignPolicy", "platformProbe",
]);
const RUNTIME_BUILD_KEYS = Object.freeze([
  "runtimeIdentity", "platformProbe",
]);
const EXECUTION_BUILD_KEYS = Object.freeze([
  "campaignPolicy",
  "matrixCellId",
  "runtimeIdentity",
  "runtimeClass",
  "gitIdentity",
  "platformProbe",
  "platformClass",
  "environmentLock",
  "runNonce",
]);
const EVIDENCE_BUILD_KEYS = Object.freeze([
  "campaignPolicy",
  "matrixCellId",
  "semanticInputSet",
  "executionIdentity",
  "platformClass",
  "runtimeClass",
  "d2Bundle",
]);
const D2_BUNDLE_KEYS = Object.freeze([
  "inputSetBytes",
  "semanticReportBytes",
  "evidenceBytes",
  "verificationResultBytes",
  "artifactBytes",
  "entryPlanBytes",
  "zipVerificationBytes",
]);
const VERIFICATION_BUILD_KEYS = Object.freeze(["evidence"]);

const ERROR_PHASES = new Set([
  "CLI",
  "OBJECT_AUTHORITY",
  "SEMANTIC_IDENTITY",
  "EXECUTION_IDENTITY",
  "PLATFORM_CLASS",
  "RUNTIME_CLASS",
  "EVIDENCE_SCHEMA",
  "VERIFICATION_RESULT_SCHEMA",
  "D2_BINDING",
  "PRIVACY",
]);
const REASON_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const IDENTIFIER_PATTERN =
  /^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,126}[A-Za-z0-9])?$/u;
const RUN_NONCE_PATTERN = /^[0-9a-f]{32}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,126}[A-Za-z0-9])?$/u;
const PLATFORM_SPECIFIC_DISTRIBUTION_PATTERN =
  /(?:^|[._+-])(?:win(?:32|64|dows)?|linux|darwin|macos|ubuntu|debian|alpine|fedora|rhel|centos|msys2?|mingw|cygwin|glibc|musl|msi|exe|zip|tar|tgz|deb|rpm)(?:$|[._+-])/iu;
const OS_FAMILIES = new Set(["windows", "linux"]);
const FILESYSTEM_CLASSES = new Set(["ntfs", "ext4-class"]);
const PROHIBITED_PRIVACY_KEYS = new Set([
  "absolutepath",
  "relativehostpath",
  "hostname",
  "username",
  "homedirectory",
  "deviceid",
  "mountid",
  "ipaddress",
  "pid",
  "processid",
  "temporaryroot",
  "temproot",
  "transportlocation",
  "transportpath",
  "signaturepath",
  "runtimepath",
  "gitpath",
  "gpghome",
  "keygrip",
  "agentsocket",
  "privatekey",
  "commandline",
]);

export class ReproducibilityEvidenceV2Error extends Error {
  constructor(phase, reason) {
    const safePhase = ERROR_PHASES.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string" && REASON_PATTERN.test(reason)
      ? reason
      : "invalid-operation";
    super("reproducibility evidence v2 operation failed");
    this.name = "ReproducibilityEvidenceV2Error";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failReproducibilityEvidenceV2(phase, reason) {
  throw new ReproducibilityEvidenceV2Error(phase, reason);
}

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

function exactDataObject(value, keys, phase, reason, options = undefined) {
  authority(value, options);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) failReproducibilityEvidenceV2(phase, reason + "-object");
  let actual;
  let descriptors;
  try {
    actual = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    failReproducibilityEvidenceV2(phase, reason + "-object");
  }
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) failReproducibilityEvidenceV2(phase, reason + "-keys");
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true
      || descriptor.get !== undefined
      || descriptor.set !== undefined
    ) failReproducibilityEvidenceV2(phase, reason + "-descriptor");
  }
  return value;
}

function requiredPlainObject(value, phase, reason) {
  authority(value);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) failReproducibilityEvidenceV2(phase, reason);
  return value;
}

function requireOwn(value, key, phase, reason) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return descriptor.value;
}

function requireString(value, phase, reason) {
  if (typeof value !== "string") {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function requireIdentifier(value, phase, reason) {
  if (
    typeof value !== "string"
    || !IDENTIFIER_PATTERN.test(value)
    || value.includes("..")
  ) failReproducibilityEvidenceV2(phase, reason);
  return value;
}

function requireVersion(value, phase, reason) {
  if (typeof value !== "string" || !VERSION_PATTERN.test(value)) {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function requireLogicalDistributionProfile(value, phase, reason) {
  requireVersion(value, phase, reason);
  if (
    PLATFORM_SPECIFIC_DISTRIBUTION_PATTERN.test(value)
    || /(?:x86|x64|amd64|arm64|aarch64)/iu.test(value)
    || SHA256_PATTERN.test(value)
    || GIT_OBJECT_PATTERN.test(value)
  ) failReproducibilityEvidenceV2(phase, reason);
  return value;
}

function requireSha256(value, phase, reason) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function requireGitObject(value, phase, reason) {
  if (typeof value !== "string" || !GIT_OBJECT_PATTERN.test(value)) {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function requireCount(value, phase, reason) {
  if (!Number.isSafeInteger(value) || value < 0) {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") {
    failReproducibilityEvidenceV2(phase, reason);
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalAuthorityBytes(value, phase, reason) {
  authority(value);
  try {
    return canonicalPublicJsonBytes(value, "PRIVACY");
  } catch {
    failReproducibilityEvidenceV2(phase, reason);
  }
}

function parsedAuthority(bytes, validator, phase, reason) {
  authority(bytes, { allowBuffer: true });
  if (!Buffer.isBuffer(bytes)) {
    failReproducibilityEvidenceV2(phase, reason + "-bytes");
  }
  let value;
  try {
    value = parseCanonicalPublicJsonBytes(bytes, "PRIVACY");
  } catch {
    failReproducibilityEvidenceV2(phase, reason + "-canonical");
  }
  return validator(value);
}

function rejectPrivacyTrusted(value, keyName = "") {
  if (typeof value === "string") {
    if (
      value.includes("\0")
      || /^[A-Za-z]:[\\/]/u.test(value)
      || value.startsWith("/")
      || value.startsWith("\\\\")
      || /^file:/iu.test(value)
      || /(?:^|[\\/])\.\.(?:[\\/]|$)/u.test(value)
      || (
        !keyName.toLowerCase().includes("v8version")
        && /(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])/u.test(value)
      )
      || value.includes("\\")
      || (value.includes("/") && keyName !== "archiveRoot")
    ) failReproducibilityEvidenceV2("PRIVACY", "private-material");
    return;
  }
  if (!value || typeof value !== "object") return;
  const arrayValue = Array.isArray(value);
  for (const key of Reflect.ownKeys(value)) {
    if (arrayValue && key === "length") continue;
    if (typeof key !== "string") {
      failReproducibilityEvidenceV2("PRIVACY", "symbol-key");
    }
    if (!arrayValue && PROHIBITED_PRIVACY_KEYS.has(key.toLowerCase())) {
      failReproducibilityEvidenceV2("PRIVACY", "private-field");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    rejectPrivacyTrusted(descriptor.value, arrayValue ? keyName : key);
  }
}

export function rejectReproducibilityEvidenceV2Privacy(value) {
  authority(value);
  rejectPrivacyTrusted(value);
  return value;
}

function frozen(value) {
  rejectReproducibilityEvidenceV2Privacy(value);
  return deepFreezeZipReproducibility(value);
}

function policyValue(policy, key, phase) {
  requiredPlainObject(policy, phase, "campaign-policy-object");
  return requireOwn(policy, key, phase, "campaign-policy-field");
}

function requireSchemaHeader(value, kind, phase) {
  if (
    value.documentKind !== kind
    || value.schemaVersion !== REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION
  ) failReproducibilityEvidenceV2(phase, "document-header");
}

export function validateSemanticInputSetV2(value) {
  const phase = "SEMANTIC_IDENTITY";
  exactDataObject(value, SEMANTIC_INPUT_SET_V2_KEYS, phase, "semantic-input-set");
  requireSchemaHeader(value, SEMANTIC_INPUT_SET_V2_DOCUMENT_KIND, phase);
  requireIdentifier(value.campaignSchemaId, phase, "campaign-schema-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  for (const key of [
    "manifestSha256",
    "membershipReportSha256",
    "entryPlanSha256",
    "criticalToolSemanticSetSha256",
    "vectorSetSha256",
  ]) requireSha256(value[key], phase, "semantic-digest");
  requireCount(value.membershipCount, phase, "membership-count");
  requireCount(value.entryCount, phase, "entry-count");
  if (value.membershipCount !== value.entryCount) {
    failReproducibilityEvidenceV2(phase, "entry-count-mismatch");
  }
  if (value.archiveRoot !== "ieltmps-source/") {
    failReproducibilityEvidenceV2(phase, "archive-root");
  }
  requireIdentifier(value.artifactRole, phase, "artifact-role");
  requireIdentifier(value.formatProfile, phase, "format-profile");
  return frozen(value);
}

export function buildSemanticInputSetV2(options) {
  const phase = "SEMANTIC_IDENTITY";
  exactDataObject(options, SEMANTIC_BUILD_KEYS, phase, "build-options");
  let d2InputSet;
  let criticalToolSet;
  try {
    d2InputSet = validateInputSet(options.d2InputSet);
    criticalToolSet = validateCriticalToolSetDocument(options.criticalToolSet);
  } catch {
    failReproducibilityEvidenceV2(phase, "frozen-d2-authority");
  }
  const policy = requiredPlainObject(
    options.campaignPolicy,
    phase,
    "campaign-policy-object",
  );
  const sourceCommit = requireGitObject(
    policyValue(policy, "sourceCommit", phase),
    phase,
    "source-commit",
  );
  const toolingCommit = requireGitObject(
    policyValue(policy, "toolingCommit", phase),
    phase,
    "tooling-commit",
  );
  const vectorSetSha256 = requireSha256(
    policyValue(policy, "vectorSetSha256", phase),
    phase,
    "vector-set-sha256",
  );
  if (
    d2InputSet.sourceCommit !== sourceCommit
    || d2InputSet.toolingCommit !== toolingCommit
    || d2InputSet.testVectorSetSha256 !== vectorSetSha256
    || criticalToolSet.toolingCommit !== toolingCommit
  ) failReproducibilityEvidenceV2(phase, "authority-binding-mismatch");
  let criticalToolSemanticSetSha256;
  try {
    criticalToolSemanticSetSha256 = sha256(
      encodeCanonicalCriticalToolSet(criticalToolSet),
    );
  } catch {
    failReproducibilityEvidenceV2(phase, "critical-tool-set");
  }
  return validateSemanticInputSetV2({
    documentKind: SEMANTIC_INPUT_SET_V2_DOCUMENT_KIND,
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    campaignSchemaId: requireIdentifier(
      policyValue(policy, "campaignSchemaId", phase),
      phase,
      "campaign-schema-id",
    ),
    sourceCommit,
    toolingCommit,
    manifestSha256: d2InputSet.manifestSha256,
    membershipReportSha256: d2InputSet.membershipReportSha256,
    membershipCount: d2InputSet.membershipCount,
    archiveRoot: d2InputSet.archiveRoot,
    entryPlanSha256: d2InputSet.entryPlanSha256,
    entryCount: d2InputSet.entryCount,
    artifactRole: d2InputSet.artifactRole,
    formatProfile: d2InputSet.formatProfile,
    criticalToolSemanticSetSha256,
    vectorSetSha256,
  });
}

export function encodeCanonicalSemanticInputSetV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validateSemanticInputSetV2(value),
    "SEMANTIC_IDENTITY",
    "canonical-encoding",
  );
}

export function parseCanonicalSemanticInputSetV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validateSemanticInputSetV2,
    "SEMANTIC_IDENTITY",
    "semantic-input-set",
  );
}

export function semanticInputSetSha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalSemanticInputSetV2(value));
}

export function validatePlatformClassV2(value) {
  const phase = "PLATFORM_CLASS";
  exactDataObject(value, PLATFORM_CLASS_V2_KEYS, phase, "platform-class");
  requireSchemaHeader(value, PLATFORM_CLASS_V2_DOCUMENT_KIND, phase);
  requireIdentifier(value.platformProfileVersion, phase, "platform-profile-version");
  if (!OS_FAMILIES.has(value.osFamily)) {
    failReproducibilityEvidenceV2(phase, "os-family");
  }
  requireIdentifier(value.osBuildPolicy, phase, "os-build-policy");
  if (value.architecture !== "x64") {
    failReproducibilityEvidenceV2(phase, "architecture");
  }
  if (!FILESYSTEM_CLASSES.has(value.filesystemClass)) {
    failReproducibilityEvidenceV2(phase, "filesystem-class");
  }
  return frozen(value);
}

export function buildPlatformClassV2(options) {
  const phase = "PLATFORM_CLASS";
  exactDataObject(options, PLATFORM_BUILD_KEYS, phase, "build-options");
  const policy = requiredPlainObject(
    options.campaignPolicy,
    phase,
    "campaign-policy-object",
  );
  const probe = requiredPlainObject(
    options.platformProbe,
    phase,
    "platform-probe-object",
  );
  for (const key of [
    "osFamilyMatchesPolicy",
    "architectureMatchesPolicy",
    "filesystemClassMatchesPolicy",
  ]) {
    if (requireOwn(probe, key, phase, "platform-probe-field") !== true) {
      failReproducibilityEvidenceV2(phase, "platform-policy-mismatch");
    }
  }
  const environment = requiredPlainObject(
    policyValue(policy, "environmentProfile", phase),
    phase,
    "environment-profile-object",
  );
  const osFamily = requireOwn(probe, "osFamily", phase, "os-family");
  const buildPolicyKey = osFamily === "windows"
    ? "windowsBuildPolicy"
    : "linuxBuildPolicy";
  return validatePlatformClassV2({
    documentKind: PLATFORM_CLASS_V2_DOCUMENT_KIND,
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    platformProfileVersion: requireIdentifier(
      requireOwn(environment, "platformProfileVersion", phase, "platform-profile-version"),
      phase,
      "platform-profile-version",
    ),
    osFamily,
    osBuildPolicy: requireIdentifier(
      requireOwn(environment, buildPolicyKey, phase, "os-build-policy"),
      phase,
      "os-build-policy",
    ),
    architecture: requireOwn(probe, "architecture", phase, "architecture"),
    filesystemClass: requireOwn(
      probe,
      "filesystemClass",
      phase,
      "filesystem-class",
    ),
  });
}

export function encodeCanonicalPlatformClassV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validatePlatformClassV2(value),
    "PLATFORM_CLASS",
    "canonical-encoding",
  );
}

export function parseCanonicalPlatformClassV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validatePlatformClassV2,
    "PLATFORM_CLASS",
    "platform-class",
  );
}

export function platformClassSha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalPlatformClassV2(value));
}

export function validateRuntimeClassV2(value) {
  const phase = "RUNTIME_CLASS";
  exactDataObject(value, RUNTIME_CLASS_V2_KEYS, phase, "runtime-class");
  requireSchemaHeader(value, RUNTIME_CLASS_V2_DOCUMENT_KIND, phase);
  if (value.runtimeFamily !== "node") {
    failReproducibilityEvidenceV2(phase, "runtime-family");
  }
  for (const key of ["runtimeVersion", "v8Version", "modulesAbi"]) {
    requireVersion(value[key], phase, "runtime-field");
  }
  requireLogicalDistributionProfile(
    value.distributionProfile,
    phase,
    "distribution-profile",
  );
  if (value.architecture !== "x64") {
    failReproducibilityEvidenceV2(phase, "architecture");
  }
  return frozen(value);
}

export function buildRuntimeClassV2(options) {
  const phase = "RUNTIME_CLASS";
  exactDataObject(options, RUNTIME_BUILD_KEYS, phase, "build-options");
  const runtime = requiredPlainObject(
    options.runtimeIdentity,
    phase,
    "runtime-identity-object",
  );
  const probe = requiredPlainObject(
    options.platformProbe,
    phase,
    "platform-probe-object",
  );
  return validateRuntimeClassV2({
    documentKind: RUNTIME_CLASS_V2_DOCUMENT_KIND,
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    runtimeFamily: requireOwn(runtime, "implementation", phase, "runtime-family"),
    runtimeVersion: requireOwn(runtime, "nodeVersion", phase, "runtime-version"),
    v8Version: requireOwn(runtime, "v8Version", phase, "v8-version"),
    modulesAbi: requireOwn(runtime, "modulesVersion", phase, "modules-abi"),
    distributionProfile: requireOwn(
      runtime,
      "distributionProfileId",
      phase,
      "distribution-profile",
    ),
    architecture: requireOwn(probe, "architecture", phase, "architecture"),
  });
}

export function encodeCanonicalRuntimeClassV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validateRuntimeClassV2(value),
    "RUNTIME_CLASS",
    "canonical-encoding",
  );
}

export function parseCanonicalRuntimeClassV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validateRuntimeClassV2,
    "RUNTIME_CLASS",
    "runtime-class",
  );
}

export function runtimeClassSha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalRuntimeClassV2(value));
}

function policyCellExecutionProfileAuthority(policy, matrixCellId) {
  const phase = "EXECUTION_IDENTITY";
  const assignments = requireOwn(
    policy,
    "gpgVerifierAssignments",
    phase,
    "gpg-verifier-assignments",
  );
  const profiles = requireOwn(
    policy,
    "gpgVerifierProfiles",
    phase,
    "gpg-verifier-profiles",
  );
  authority(assignments);
  authority(profiles);
  if (
    !Array.isArray(assignments)
    || Object.getPrototypeOf(assignments) !== Array.prototype
    || !Array.isArray(profiles)
    || Object.getPrototypeOf(profiles) !== Array.prototype
  ) failReproducibilityEvidenceV2(phase, "gpg-policy-authority");
  const selected = assignments.filter((entry) => {
    requiredPlainObject(entry, phase, "gpg-assignment-object");
    return requireOwn(entry, "matrixCellId", phase, "gpg-assignment-field")
        === matrixCellId
      && requireOwn(entry, "comparisonRole", phase, "gpg-assignment-field")
        === null
      && requireOwn(entry, "gpgRole", phase, "gpg-assignment-field")
        === "cell-producer-sign"
      && requireOwn(entry, "operation", phase, "gpg-assignment-field")
        === "detached-sign";
  });
  if (selected.length !== 1) {
    failReproducibilityEvidenceV2(phase, "gpg-assignment-binding");
  }
  const matchingProfiles = profiles.filter((profile) => {
    requiredPlainObject(profile, phase, "gpg-profile-object");
    return requireOwn(profile, "profileId", phase, "gpg-profile-field")
      === selected[0].profileId;
  });
  if (matchingProfiles.length !== 1) {
    failReproducibilityEvidenceV2(phase, "gpg-profile-binding");
  }
  const producerProfile = matchingProfiles[0];
  const producerGpgImmutableInstallationProfileSha256 = requireSha256(
    requireOwn(
      producerProfile,
      "immutableInstallationProfileSha256",
      phase,
      "gpg-immutable-profile-field",
    ),
    phase,
    "gpg-immutable-profile-sha256",
  );
  const nodeAssignments = requireOwn(
    policy,
    "nodeRuntimeAssignments",
    phase,
    "node-runtime-assignments",
  );
  const nodeProfiles = requireOwn(
    policy,
    "nodeRuntimeProfiles",
    phase,
    "node-runtime-profiles",
  );
  authority(nodeAssignments);
  authority(nodeProfiles);
  if (
    !Array.isArray(nodeAssignments)
    || Object.getPrototypeOf(nodeAssignments) !== Array.prototype
    || !Array.isArray(nodeProfiles)
    || Object.getPrototypeOf(nodeProfiles) !== Array.prototype
  ) failReproducibilityEvidenceV2(phase, "node-policy-authority");
  const selectedNodeAssignments = nodeAssignments.filter((entry) => {
    requiredPlainObject(entry, phase, "node-assignment-object");
    return requireOwn(entry, "campaignRole", phase, "node-assignment-field")
        === "cell-producer"
      && requireOwn(entry, "matrixCellId", phase, "node-assignment-field")
        === matrixCellId;
  });
  if (selectedNodeAssignments.length !== 1) {
    failReproducibilityEvidenceV2(phase, "node-assignment-binding");
  }
  const matchingNodeProfiles = nodeProfiles.filter((profile) => {
    requiredPlainObject(profile, phase, "node-profile-object");
    return requireOwn(profile, "profileId", phase, "node-profile-field")
      === selectedNodeAssignments[0].profileId;
  });
  if (matchingNodeProfiles.length !== 1) {
    failReproducibilityEvidenceV2(phase, "node-profile-binding");
  }
  const nodeProfile = matchingNodeProfiles[0];
  return Object.freeze({
    nodeRuntimeProfileSha256: sha256(canonicalAuthorityBytes(
      nodeProfile,
      phase,
      "node-profile-canonical",
    )),
    nodeImmutableInstallationProfileSha256: requireSha256(
      requireOwn(
        nodeProfile,
        "immutableInstallationProfileSha256",
        phase,
        "node-immutable-profile-field",
      ),
      phase,
      "node-immutable-profile-sha256",
    ),
    producerGpgProfileSha256: sha256(canonicalAuthorityBytes(
      producerProfile,
      phase,
      "gpg-profile-canonical",
    )),
    producerGpgImmutableInstallationProfileSha256,
  });
}

export function validateExecutionIdentityV2(value) {
  const phase = "EXECUTION_IDENTITY";
  exactDataObject(value, EXECUTION_IDENTITY_V2_KEYS, phase, "execution-identity");
  requireSchemaHeader(value, EXECUTION_IDENTITY_V2_DOCUMENT_KIND, phase);
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  const hashes = [
    "runtimeIdentitySha256",
    "nodeRuntimeProfileSha256",
    "nodeImmutableInstallationProfileSha256",
    "runtimeClassSha256",
    "gitIdentitySha256",
    "producerGpgProfileSha256",
    "producerGpgImmutableInstallationProfileSha256",
    "platformProbeSha256",
    "platformClassSha256",
    "environmentLockSha256",
  ].map((key) => requireSha256(value[key], phase, "execution-digest"));
  if (new Set(hashes).size !== hashes.length) {
    failReproducibilityEvidenceV2(phase, "digest-semantic-reuse");
  }
  if (typeof value.runNonce !== "string" || !RUN_NONCE_PATTERN.test(value.runNonce)) {
    failReproducibilityEvidenceV2(phase, "run-nonce");
  }
  return frozen(value);
}

export function buildExecutionIdentityV2(options) {
  const phase = "EXECUTION_IDENTITY";
  exactDataObject(options, EXECUTION_BUILD_KEYS, phase, "build-options");
  const policy = requiredPlainObject(
    options.campaignPolicy,
    phase,
    "campaign-policy-object",
  );
  const runtimeClass = validateRuntimeClassV2(options.runtimeClass);
  const platformClass = validatePlatformClassV2(options.platformClass);
  const probe = requiredPlainObject(
    options.platformProbe,
    phase,
    "platform-probe-object",
  );
  const runtimeIdentityBytes = canonicalAuthorityBytes(
    options.runtimeIdentity,
    phase,
    "runtime-identity-canonical",
  );
  const gitIdentityBytes = canonicalAuthorityBytes(
    options.gitIdentity,
    phase,
    "git-identity-canonical",
  );
  const platformProbeBytes = canonicalAuthorityBytes(
    probe,
    phase,
    "platform-probe-canonical",
  );
  const environmentLockBytes = canonicalAuthorityBytes(
    options.environmentLock,
    phase,
    "environment-lock-canonical",
  );
  const runtimeIdentitySha256 = sha256(runtimeIdentityBytes);
  const gitIdentitySha256 = sha256(gitIdentityBytes);
  const executionProfiles = policyCellExecutionProfileAuthority(
    policy,
    options.matrixCellId,
  );
  if (
    requireOwn(probe, "runtimeIdentitySha256", phase, "runtime-identity-binding")
      !== runtimeIdentitySha256
    || requireOwn(probe, "gitIdentitySha256", phase, "git-identity-binding")
      !== gitIdentitySha256
    || runtimeClass.architecture !== platformClass.architecture
  ) failReproducibilityEvidenceV2(phase, "authority-binding-mismatch");
  return validateExecutionIdentityV2({
    documentKind: EXECUTION_IDENTITY_V2_DOCUMENT_KIND,
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    campaignId: requireIdentifier(
      policyValue(policy, "campaignId", phase),
      phase,
      "campaign-id",
    ),
    matrixCellId: requireIdentifier(options.matrixCellId, phase, "matrix-cell-id"),
    sourceCommit: requireGitObject(
      policyValue(policy, "sourceCommit", phase),
      phase,
      "source-commit",
    ),
    toolingCommit: requireGitObject(
      policyValue(policy, "toolingCommit", phase),
      phase,
      "tooling-commit",
    ),
    runtimeIdentitySha256,
    nodeRuntimeProfileSha256: executionProfiles.nodeRuntimeProfileSha256,
    nodeImmutableInstallationProfileSha256:
      executionProfiles.nodeImmutableInstallationProfileSha256,
    runtimeClassSha256: runtimeClassSha256V2(runtimeClass),
    gitIdentitySha256,
    producerGpgProfileSha256: executionProfiles.producerGpgProfileSha256,
    producerGpgImmutableInstallationProfileSha256:
      executionProfiles.producerGpgImmutableInstallationProfileSha256,
    platformProbeSha256: sha256(platformProbeBytes),
    platformClassSha256: platformClassSha256V2(platformClass),
    environmentLockSha256: sha256(environmentLockBytes),
    runNonce: options.runNonce,
  });
}

export function encodeCanonicalExecutionIdentityV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validateExecutionIdentityV2(value),
    "EXECUTION_IDENTITY",
    "canonical-encoding",
  );
}

export function parseCanonicalExecutionIdentityV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validateExecutionIdentityV2,
    "EXECUTION_IDENTITY",
    "execution-identity",
  );
}

export function executionIdentitySha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalExecutionIdentityV2(value));
}

export function validateReproducibilityEvidenceV2(value) {
  const phase = "EVIDENCE_SCHEMA";
  exactDataObject(
    value,
    REPRODUCIBILITY_EVIDENCE_V2_KEYS,
    phase,
    "evidence",
  );
  requireSchemaHeader(value, REPRODUCIBILITY_EVIDENCE_V2_DOCUMENT_KIND, phase);
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  for (const key of REPRODUCIBILITY_EVIDENCE_V2_KEYS.filter(
    (key) => key.endsWith("Sha256"),
  )) requireSha256(value[key], phase, "evidence-digest");
  for (const key of [
    "canonicalVerifierPassed",
    "sameProcessRepeatable",
    "sameHostRepeatable",
    "boundaryVectorSetPassed",
  ]) {
    if (requireBoolean(value[key], phase, "semantic-claim") !== true) {
      failReproducibilityEvidenceV2(phase, "semantic-claim-not-passed");
    }
  }
  return frozen(value);
}

function parseFrozenD2Bundle(bundle) {
  exactDataObject(bundle, D2_BUNDLE_KEYS, "D2_BINDING", "d2-bundle", {
    allowBuffer: true,
  });
  for (const key of D2_BUNDLE_KEYS) {
    if (!Buffer.isBuffer(bundle[key])) {
      failReproducibilityEvidenceV2("D2_BINDING", "d2-bundle-bytes");
    }
  }
  let inputSet;
  let semanticReport;
  let evidence;
  let verificationResult;
  try {
    inputSet = parseCanonicalInputSet(bundle.inputSetBytes);
    semanticReport = parseCanonicalSemanticReport(bundle.semanticReportBytes);
    evidence = parseCanonicalReproducibilityEvidence(bundle.evidenceBytes);
    verificationResult = parseCanonicalVerificationResult(
      bundle.verificationResultBytes,
    );
    parseCanonicalPublicJsonBytes(bundle.entryPlanBytes, "ENTRY_PLAN");
    parseCanonicalPublicJsonBytes(bundle.zipVerificationBytes, "ZIP_VERIFICATION");
  } catch {
    failReproducibilityEvidenceV2("D2_BINDING", "d2-canonical-authority");
  }
  return Object.freeze({
    inputSet,
    semanticReport,
    evidence,
    verificationResult,
  });
}

function requireD2PassBindings(bundle, parsed, policy, matrixCellId) {
  const inputSetSha256 = sha256(bundle.inputSetBytes);
  const semanticReportSha256 = sha256(bundle.semanticReportBytes);
  const evidenceSha256 = sha256(bundle.evidenceBytes);
  const artifactSha256 = sha256(bundle.artifactBytes);
  const entryPlanSha256 = sha256(bundle.entryPlanBytes);
  const vectorSetSha256 = policyValue(policy, "vectorSetSha256", "D2_BINDING");
  const frozenV1MatrixCellId = matrixCellId.toLowerCase();
  const { inputSet, semanticReport, evidence, verificationResult } = parsed;
  if (
    evidence.result !== "pass"
    || evidence.sourceCommit !== policy.sourceCommit
    || evidence.toolingCommit !== policy.toolingCommit
    || evidence.matrixCellId !== frozenV1MatrixCellId
    || evidence.inputSetSha256 !== inputSetSha256
    || evidence.semanticReportSha256 !== semanticReportSha256
    || evidence.semanticReportByteLength !== bundle.semanticReportBytes.length
    || evidence.artifactSha256 !== artifactSha256
    || evidence.artifactByteLength !== bundle.artifactBytes.length
    || evidence.testVectorSetSha256 !== vectorSetSha256
    || inputSet.sourceCommit !== evidence.sourceCommit
    || inputSet.toolingCommit !== evidence.toolingCommit
    || inputSet.testVectorSetSha256 !== vectorSetSha256
    || inputSet.entryPlanSha256 !== entryPlanSha256
    || semanticReport.inputSetSha256 !== inputSetSha256
    || semanticReport.artifactSha256 !== artifactSha256
    || semanticReport.artifactByteLength !== bundle.artifactBytes.length
    || semanticReport.sourceCommit !== evidence.sourceCommit
    || semanticReport.toolingCommit !== evidence.toolingCommit
    || semanticReport.result !== "pass"
    || verificationResult.status !== "ok"
    || verificationResult.mode !== "reproducibility-evidence-verification"
    || verificationResult.evidenceSha256 !== evidenceSha256
    || verificationResult.evidenceByteLength !== bundle.evidenceBytes.length
    || verificationResult.matrixCellId !== frozenV1MatrixCellId
    || verificationResult.evidenceResult !== "pass"
    || verificationResult.comparisonEligible !== true
    || verificationResult.semanticClaimsBound !== true
    || verificationResult.semanticClaimsIndependentlyReplayed !== false
    || verificationResult.evidenceSigningRequired !== true
    || verificationResult.platformAttestationVerified !== false
    || verificationResult.projectPublicationAuthorized !== false
  ) failReproducibilityEvidenceV2("D2_BINDING", "d2-binding-mismatch");
  for (const key of [
    "canonicalVerifierPassed",
    "sameProcessRepeatable",
    "sameHostRepeatable",
    "boundaryVectorSetPassed",
  ]) {
    if (semanticReport[key] !== true || verificationResult[key] !== true) {
      failReproducibilityEvidenceV2("D2_BINDING", "d2-semantic-claim");
    }
  }
}

export function buildReproducibilityEvidenceV2(options) {
  const phase = "EVIDENCE_SCHEMA";
  exactDataObject(options, EVIDENCE_BUILD_KEYS, phase, "build-options", {
    allowBuffer: true,
  });
  const policy = requiredPlainObject(
    options.campaignPolicy,
    phase,
    "campaign-policy-object",
  );
  const semanticInputSet = validateSemanticInputSetV2(options.semanticInputSet);
  const executionIdentity = validateExecutionIdentityV2(options.executionIdentity);
  const platformClass = validatePlatformClassV2(options.platformClass);
  const runtimeClass = validateRuntimeClassV2(options.runtimeClass);
  const matrixCellId = requireIdentifier(
    options.matrixCellId,
    phase,
    "matrix-cell-id",
  );
  const parsed = parseFrozenD2Bundle(options.d2Bundle);
  requireD2PassBindings(options.d2Bundle, parsed, policy, matrixCellId);
  const campaignId = policyValue(policy, "campaignId", phase);
  const sourceCommit = policyValue(policy, "sourceCommit", phase);
  const toolingCommit = policyValue(policy, "toolingCommit", phase);
  if (
    semanticInputSet.sourceCommit !== sourceCommit
    || semanticInputSet.toolingCommit !== toolingCommit
    || parsed.inputSet.manifestSha256 !== semanticInputSet.manifestSha256
    || parsed.inputSet.membershipReportSha256
      !== semanticInputSet.membershipReportSha256
    || parsed.inputSet.membershipCount !== semanticInputSet.membershipCount
    || parsed.inputSet.entryPlanSha256 !== semanticInputSet.entryPlanSha256
    || parsed.evidence.manifestSha256 !== semanticInputSet.manifestSha256
    || parsed.evidence.criticalToolSetSha256
      !== semanticInputSet.criticalToolSemanticSetSha256
    || parsed.evidence.runtimeIdentitySha256
      !== executionIdentity.runtimeIdentitySha256
    || parsed.evidence.gitIdentitySha256 !== executionIdentity.gitIdentitySha256
    || parsed.inputSet.runtimeIdentitySha256
      !== executionIdentity.runtimeIdentitySha256
    || parsed.inputSet.gitIdentitySha256 !== executionIdentity.gitIdentitySha256
    || executionIdentity.campaignId !== campaignId
    || executionIdentity.matrixCellId !== matrixCellId
    || executionIdentity.sourceCommit !== sourceCommit
    || executionIdentity.toolingCommit !== toolingCommit
    || executionIdentity.platformClassSha256 !== platformClassSha256V2(platformClass)
    || executionIdentity.runtimeClassSha256 !== runtimeClassSha256V2(runtimeClass)
    || executionIdentity.producerGpgProfileSha256
      !== policyCellExecutionProfileAuthority(policy, matrixCellId)
        .producerGpgProfileSha256
  ) failReproducibilityEvidenceV2(phase, "identity-binding-mismatch");
  return validateReproducibilityEvidenceV2({
    documentKind: REPRODUCIBILITY_EVIDENCE_V2_DOCUMENT_KIND,
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    campaignId,
    matrixCellId,
    sourceCommit,
    toolingCommit,
    semanticInputSetSha256: semanticInputSetSha256V2(semanticInputSet),
    executionIdentitySha256: executionIdentitySha256V2(executionIdentity),
    producerGpgProfileSha256: executionIdentity.producerGpgProfileSha256,
    platformClassSha256: platformClassSha256V2(platformClass),
    runtimeClassSha256: runtimeClassSha256V2(runtimeClass),
    d2InputSetSha256: sha256(options.d2Bundle.inputSetBytes),
    d2SemanticReportSha256: sha256(options.d2Bundle.semanticReportBytes),
    d2EvidenceSha256: sha256(options.d2Bundle.evidenceBytes),
    d2VerificationResultSha256: sha256(
      options.d2Bundle.verificationResultBytes,
    ),
    artifactSha256: sha256(options.d2Bundle.artifactBytes),
    entryPlanSha256: sha256(options.d2Bundle.entryPlanBytes),
    zipVerificationSha256: sha256(options.d2Bundle.zipVerificationBytes),
    vectorSetSha256: requireSha256(
      policyValue(policy, "vectorSetSha256", phase),
      phase,
      "vector-set-sha256",
    ),
    canonicalVerifierPassed: parsed.semanticReport.canonicalVerifierPassed,
    sameProcessRepeatable: parsed.semanticReport.sameProcessRepeatable,
    sameHostRepeatable: parsed.semanticReport.sameHostRepeatable,
    boundaryVectorSetPassed: parsed.semanticReport.boundaryVectorSetPassed,
  });
}

export function encodeCanonicalReproducibilityEvidenceV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validateReproducibilityEvidenceV2(value),
    "EVIDENCE_SCHEMA",
    "canonical-encoding",
  );
}

export function parseCanonicalReproducibilityEvidenceV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validateReproducibilityEvidenceV2,
    "EVIDENCE_SCHEMA",
    "evidence",
  );
}

export function reproducibilityEvidenceSha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalReproducibilityEvidenceV2(value));
}

export function validateVerificationResultV2(value) {
  const phase = "VERIFICATION_RESULT_SCHEMA";
  exactDataObject(value, VERIFICATION_RESULT_V2_KEYS, phase, "verification-result");
  if (
    value.status !== "ok"
    || value.mode !== "reproducibility-evidence-v2-verification"
    || value.schemaVersion !== REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION
  ) failReproducibilityEvidenceV2(phase, "verification-mode");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  for (const key of [
    "semanticInputSetSha256",
    "executionIdentitySha256",
    "producerGpgProfileSha256",
    "platformClassSha256",
    "runtimeClassSha256",
    "artifactSha256",
  ]) requireSha256(value[key], phase, "verification-digest");
  const fixed = {
    comparisonEligible: true,
    semanticClaimsBound: true,
    semanticClaimsIndependentlyReplayed: false,
    evidenceSigningRequired: true,
    platformAttestationVerified: false,
    projectPublicationAuthorized: false,
  };
  for (const [key, expected] of Object.entries(fixed)) {
    if (requireBoolean(value[key], phase, "verification-boolean") !== expected) {
      failReproducibilityEvidenceV2(phase, "verification-semantics");
    }
  }
  return frozen(value);
}

export function buildVerificationResultV2(options) {
  const phase = "VERIFICATION_RESULT_SCHEMA";
  exactDataObject(options, VERIFICATION_BUILD_KEYS, phase, "build-options");
  const evidence = validateReproducibilityEvidenceV2(options.evidence);
  return validateVerificationResultV2({
    status: "ok",
    mode: "reproducibility-evidence-v2-verification",
    schemaVersion: REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
    campaignId: evidence.campaignId,
    matrixCellId: evidence.matrixCellId,
    semanticInputSetSha256: evidence.semanticInputSetSha256,
    executionIdentitySha256: evidence.executionIdentitySha256,
    producerGpgProfileSha256: evidence.producerGpgProfileSha256,
    platformClassSha256: evidence.platformClassSha256,
    runtimeClassSha256: evidence.runtimeClassSha256,
    artifactSha256: evidence.artifactSha256,
    comparisonEligible: true,
    semanticClaimsBound: true,
    semanticClaimsIndependentlyReplayed: false,
    evidenceSigningRequired: true,
    platformAttestationVerified: false,
    projectPublicationAuthorized: false,
  });
}

export function encodeCanonicalVerificationResultV2(value) {
  authority(value);
  return canonicalAuthorityBytes(
    validateVerificationResultV2(value),
    "VERIFICATION_RESULT_SCHEMA",
    "canonical-encoding",
  );
}

export function parseCanonicalVerificationResultV2Bytes(bytes) {
  return parsedAuthority(
    bytes,
    validateVerificationResultV2,
    "VERIFICATION_RESULT_SCHEMA",
    "verification-result",
  );
}

export function verificationResultSha256V2(value) {
  authority(value);
  return sha256(encodeCanonicalVerificationResultV2(value));
}
