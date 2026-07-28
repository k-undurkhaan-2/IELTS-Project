import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants as FS_CONSTANTS,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  statfsSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
  canonicalPublicJsonBytes,
  deepFreezeZipReproducibility,
  parseCanonicalPublicJsonBytes,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  CLAIM_LEVELS_V2,
  REPRODUCIBILITY_EVIDENCE_V2_SCHEMA_VERSION,
  encodeCanonicalExecutionIdentityV2,
  encodeCanonicalReproducibilityEvidenceV2,
  encodeCanonicalVerificationResultV2,
  executionIdentitySha256V2,
  platformClassSha256V2,
  runtimeClassSha256V2,
  semanticInputSetSha256V2,
  validateExecutionIdentityV2,
  validateReproducibilityEvidenceV2,
  validateVerificationResultV2,
} from "./reproducibility-evidence-v2-core.mjs";

export const CAMPAIGN_SCHEMA_VERSION = 1;
export const CAMPAIGN_SCHEMA_ID =
  "ieltmps-r1-10e-additive-v2-campaign-v1";
export const CAMPAIGN_POLICY_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-policy";
export const ENVIRONMENT_LOCK_DOCUMENT_KIND =
  "ieltmps-public-source-zip-environment-lock";
export const PLATFORM_PROBE_DOCUMENT_KIND =
  "ieltmps-public-source-zip-platform-probe";
export const CELL_RESULT_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-cell-result";
export const CELL_MANIFEST_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-cell-manifest";
export const SIGNATURE_VERIFICATION_DOCUMENT_KIND =
  "ieltmps-public-source-zip-signature-verification";
export const CELL_VERIFICATION_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-cell-verification";
export const CAMPAIGN_COMPARISON_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-comparison";
export const CAMPAIGN_FAILURE_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-failure";
export const CAMPAIGN_COMPARISON_MANIFEST_DOCUMENT_KIND =
  "ieltmps-public-source-zip-campaign-comparison-manifest";
export const GPG_VERIFIER_PROFILE_DOCUMENT_KIND =
  "ieltmps-gpg-verifier-execution-profile-v1";
export const GPG_INVOCATION_PROFILE_DOCUMENT_KIND =
  "ieltmps-gpg-invocation-profile-v1";
export const IMMUTABLE_INSTALLATION_PROFILE_DOCUMENT_KIND =
  "ieltmps-immutable-installation-profile-v1";
export const MEASURED_QUALIFICATION_RESULT_DOCUMENT_KIND =
  "ieltmps-immutable-installation-qualification-result-v1";
export const NODE_RUNTIME_PROFILE_DOCUMENT_KIND =
  "ieltmps-node-execution-profile-v1";

export const GPG_VERIFIER_PROFILE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "profileId",
  "verifierFamily",
  "distributionProfile",
  "osFamily",
  "architecture",
  "executableSha256",
  "executableByteLength",
  "version",
  "statusProtocol",
  "fileIdentityPolicy",
  "linkPolicy",
  "networkPolicy",
  "invocationProfileSha256",
  "immutableInstallationProfileSha256",
]);
export const GPG_INVOCATION_PROFILE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "allowedOperations",
  "requiredGlobalArguments",
  "operationProfiles",
  "statusFdUsage",
  "batchMode",
  "noTty",
  "noOptions",
  "noAutoKeyRetrieve",
  "networkProhibition",
  "shell",
  "argumentArrayExecution",
  "timeoutPolicy",
  "stdoutBoundBytes",
  "stderrBoundBytes",
  "gpgHomeRequirement",
]);
export const GPG_INVOCATION_OPERATION_KEYS = Object.freeze([
  "operation", "statusFd", "arguments",
]);
export const GPG_VERIFIER_ASSIGNMENT_KEYS = Object.freeze([
  "assignmentId",
  "gpgRole",
  "profileId",
  "operation",
  "matrixCellId",
  "comparisonRole",
  "hostRole",
  "osFamily",
  "architecture",
  "signerRole",
  "signatureNamespace",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
]);
export const IMMUTABLE_INSTALLATION_PROFILE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "profileId",
  "qualificationMode",
  "osFamily",
  "architecture",
  "distributionProfile",
  "executableSha256",
  "executableByteLength",
  "fileIdentityPolicy",
  "ownerPolicy",
  "principalPolicy",
  "parentChainPolicy",
  "accessControlPolicy",
  "linkPolicy",
  "filesystemPolicy",
  "qualificationProbeMode",
  "qualificationProbeProfileSha256",
]);
export const MEASURED_QUALIFICATION_RESULT_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "profileId",
  "profileSha256",
  "status",
  "phase",
  "reason",
  "osFamily",
  "architecture",
  "executableSha256",
  "executableByteLength",
  "fileIdentitySha256",
  "parentChainEvidenceSha256",
  "accessControlEvidenceSha256",
  "filesystemEvidenceSha256",
  "linkCount",
  "reparseOrSymlink",
  "campaignPrincipalWritable",
  "campaignPrincipalDeleteOrRenameCapable",
  "campaignPrincipalAclChangeCapable",
  "campaignPrincipalOwnershipTakeoverCapable",
]);
export const NODE_RUNTIME_PROFILE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "profileId",
  "runtimeFamily",
  "distributionProfile",
  "osFamily",
  "architecture",
  "runtimeVersion",
  "v8Version",
  "modulesAbi",
  "executableSha256",
  "executableByteLength",
  "immutableInstallationProfileSha256",
  "sourceCommit",
  "toolingCommit",
]);
export const NODE_RUNTIME_ASSIGNMENT_KEYS = Object.freeze([
  "assignmentId",
  "profileId",
  "campaignRole",
  "matrixCellId",
  "hostRole",
  "osFamily",
  "architecture",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
]);

export const GPG_OPERATION_ROLES = Object.freeze([
  "cell-producer-sign",
  "cell-producer-local-verify",
  "cell-import-consumer-verify",
  "comparison-result-sign",
  "comparison-result-local-verify",
  "independent-result-review-verify",
]);
export const NODE_CAMPAIGN_ROLES = Object.freeze([
  "cell-producer",
  "cell-import-consumer",
  "comparison-host",
  "independent-review-host",
]);

export const CELL_COMPLETION_MARKER = Buffer.from("complete\n", "ascii");
export const COMPARISON_COMPLETION_MARKER = Buffer.from("complete\n", "ascii");

export const SIGNATURE_NAMESPACES = Object.freeze([
  "ieltmps-r1-10e-cell-v1",
  "ieltmps-r1-10e-comparison-v1",
  "ieltmps-r1-10e-review-v1",
  "ieltmps-r1-10e-closure-v1",
]);
export const CELL_SIGNATURE_NAMESPACE = SIGNATURE_NAMESPACES[0];
export const COMPARISON_SIGNATURE_NAMESPACE = SIGNATURE_NAMESPACES[1];

export const REQUIRED_MATRIX_CELL_IDS = Object.freeze([
  "WIN-A", "LINUX-A", "LINUX-B",
]);
export const OPTIONAL_MATRIX_CELL_IDS = Object.freeze(["WIN-B"]);

export const CAMPAIGN_LOADED_TOOL_PATHS = Object.freeze([
  "developer/reproducibility-evidence-v2-core.mjs",
  "developer/verify-reproducibility-evidence-v2.mjs",
  "developer/compare-reproducibility-evidence-v2.mjs",
  "developer/public-source-zip-campaign-core.mjs",
  "developer/prepare-public-source-zip-campaign.mjs",
  "developer/verify-public-source-zip-campaign-cell.mjs",
  "developer/compare-public-source-zip-campaign.mjs",
  "developer/verify-public-source-membership.mjs",
  "developer/prepare-public-source-tree.mjs",
  "developer/public-source-zip-core.mjs",
  "developer/prepare-public-source-zip.mjs",
  "developer/verify-public-source-zip.mjs",
  "developer/reproducibility-evidence-core.mjs",
  "developer/verify-reproducibility-evidence.mjs",
  "developer/compare-reproducibility-evidence.mjs",
  "developer/public-source-zip-reproducibility-core.mjs",
  "developer/prepare-public-source-zip-reproducibility.mjs",
  "developer/run-public-source-zip-boundary-vectors.mjs",
]);

export const MATRIX_CELL_ROLE_AUTHORITY = Object.freeze({
  "WIN-A": Object.freeze({
    osFamily: "windows",
    runtimeRole: "A",
    filesystemClass: "ntfs",
  }),
  "LINUX-A": Object.freeze({
    osFamily: "linux",
    runtimeRole: "A",
    filesystemClass: "ext4-class",
  }),
  "LINUX-B": Object.freeze({
    osFamily: "linux",
    runtimeRole: "B",
    filesystemClass: "ext4-class",
  }),
  "WIN-B": Object.freeze({
    osFamily: "windows",
    runtimeRole: "B",
    filesystemClass: "ntfs",
  }),
});

export const CELL_PAYLOAD_NAMES = Object.freeze([
  "d2/artifact.zip",
  "d2/zip-verification.json",
  "d2/entry-plan.json",
  "d2/input-set.json",
  "d2/semantic-report.json",
  "d2/evidence.json",
  "d2/verification-result.json",
  "d2/.complete",
  "authority/campaign-policy.json",
  "authority/runtime-identity.json",
  "authority/node-qualification.json",
  "authority/producer-gpg-qualification.json",
  "authority/producer-local-gpg-qualification.json",
  "authority/git-identity.json",
  "authority/platform-probe.json",
  "authority/platform-class.json",
  "authority/runtime-class.json",
  "authority/environment-lock.json",
  "authority/critical-tool-set.json",
  "authority/public-source-manifest.json",
  "authority/membership-report.json",
  "authority/test-vector-set.json",
  "v2/semantic-input-set.json",
  "v2/execution-identity.json",
  "v2/evidence.json",
  "v2/verification-result.json",
  "cell-result.json",
]);

export const SEALED_CELL_OUTPUT_NAMES = Object.freeze([
  ...CELL_PAYLOAD_NAMES,
  "cell-manifest.json",
  "cell-manifest.sig",
  "cell.complete",
]);

export const COMPARISON_PAYLOAD_NAMES = Object.freeze([
  "campaign-result.json",
]);
export const SEALED_COMPARISON_OUTPUT_NAMES = Object.freeze([
  ...COMPARISON_PAYLOAD_NAMES,
  "comparison-manifest.json",
  "comparison-manifest.sig",
  "comparison.complete",
]);

export const CAMPAIGN_POLICY_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "campaignSchemaId",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
  "vectorSetSha256",
  "requiredCells",
  "optionalCells",
  "claimRules",
  "environmentProfile",
  "allowedSignerRoles",
  "allowedSignerFingerprints",
  "immutableInstallationProfiles",
  "nodeRuntimeProfiles",
  "nodeRuntimeAssignments",
  "gpgVerifierProfiles",
  "gpgVerifierAssignments",
  "transportPolicy",
  "retentionPolicy",
]);
export const POLICY_CELL_KEYS = Object.freeze([
  "matrixCellId",
  "osFamily",
  "runtimeRole",
  "filesystemClass",
  "signerRole",
]);
export const CLAIM_RULE_KEYS = Object.freeze([
  "crossRuntimePair",
  "crossOsPair",
  "requiredClaimLevels",
  "requireL5",
  "allowL6",
]);
export const ENVIRONMENT_PROFILE_KEYS = Object.freeze([
  "platformProfileVersion",
  "architecture",
  "runtimeFamily",
  "lang",
  "lcAll",
  "timezone",
  "sourceDateEpoch",
  "networkPolicy",
  "lineEndingPolicy",
  "filesystemExecutionPolicy",
  "hostIdentifierPolicy",
  "windowsBuildPolicy",
  "linuxBuildPolicy",
]);
export const SIGNER_FINGERPRINT_KEYS = Object.freeze([
  "fingerprint", "role", "matrixCellId",
]);
export const TRANSPORT_POLICY_KEYS = Object.freeze([
  "signatureRequired",
  "ledgerRequired",
  "immutableVerificationRequired",
  "noAutoKeyRetrieval",
  "uniqueSignerPerCell",
  "maxManifestBytes",
  "maxSignatureBytes",
]);
export const RETENTION_POLICY_KEYS = Object.freeze([
  "rawCellEvidencePrivate",
  "commitRawCells",
  "closureReviewRequired",
  "retentionProfile",
]);
export const ENVIRONMENT_LOCK_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "lang",
  "lcAll",
  "timezone",
  "sourceDateEpoch",
  "networkPolicy",
  "lineEndingPolicy",
  "filesystemExecutionPolicy",
  "hostIdentifierPolicy",
]);
export const PLATFORM_CAPABILITY_KEYS = Object.freeze([
  "nativeFilesystemStatSupported",
  "exclusiveCreateSupported",
  "hardLinkSupported",
  "stableFileIdentitySupported",
]);
export const PLATFORM_MEASUREMENT_KEYS = Object.freeze([
  "osFamily",
  "osRelease",
  "osVersion",
  "architecture",
  "filesystemTypeCode",
  "filesystemClass",
  "capabilities",
]);
export const PLATFORM_PROBE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "matrixCellId",
  "osFamily",
  "osRelease",
  "osVersion",
  "architecture",
  "filesystemTypeCode",
  "filesystemClass",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "nativeFilesystemStatSupported",
  "exclusiveCreateSupported",
  "hardLinkSupported",
  "stableFileIdentitySupported",
  "policyExpectedOsFamily",
  "policyExpectedArchitecture",
  "policyExpectedFilesystemClass",
  "osFamilyMatchesPolicy",
  "architectureMatchesPolicy",
  "filesystemClassMatchesPolicy",
  "platformAttestationVerified",
]);
export const RUNTIME_IDENTITY_KEYS = Object.freeze([
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
export const GIT_IDENTITY_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "gitProfileId",
  "executableSha256",
  "executableByteLength",
  "reportedVersion",
  "objectFormat",
  "distributionProfileId",
]);
export const FILE_LEDGER_ENTRY_KEYS = Object.freeze([
  "name", "role", "sha256", "byteLength", "comparisonClass",
]);
export const CELL_RESULT_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "status",
  "mode",
  "campaignId",
  "matrixCellId",
  "sourceCommit",
  "toolingCommit",
  "runNonce",
  "nodeRuntimeProfileId",
  "nodeRuntimeProfileSha256",
  "nodeImmutableInstallationProfileSha256",
  "nodeQualificationResultSha256",
  "producerGpgProfileId",
  "producerGpgProfileSha256",
  "producerGpgImmutableInstallationProfileSha256",
  "producerSignAssignmentSha256",
  "producerSignQualificationResultSha256",
  "producerLocalVerifierProfileId",
  "producerLocalVerifierProfileSha256",
  "producerLocalGpgImmutableInstallationProfileSha256",
  "producerLocalVerifyAssignmentSha256",
  "producerLocalVerifyQualificationResultSha256",
  "semanticInputSetSha256",
  "executionIdentitySha256",
  "platformClassSha256",
  "runtimeClassSha256",
  "artifactSha256",
  "entryPlanSha256",
  "zipVerificationSha256",
  "d1CanonicalVerificationPassed",
  "d2SameProcessPassed",
  "d2SameHostPassed",
  "boundaryVectorSetPassed",
  "localArtifactCreated",
  "localFileIdentityVerified",
  "foreignCellInputUsed",
  "privacyGatePassed",
  "temporaryRootCleanupVerified",
  "environmentBlockerAbsent",
  "comparisonEligible",
  "platformAttestationVerified",
  "projectPublicationAuthorized",
]);
export const CELL_MANIFEST_KEYS = Object.freeze([
  "documentKind",
  "namespace",
  "schemaVersion",
  "campaignId",
  "matrixCellId",
  "sourceCommit",
  "toolingCommit",
  "campaignPolicySha256",
  "runNonce",
  "nodeRuntimeProfileId",
  "nodeRuntimeProfileSha256",
  "nodeImmutableInstallationProfileSha256",
  "nodeQualificationResultSha256",
  "producerGpgProfileId",
  "producerGpgProfileSha256",
  "producerGpgImmutableInstallationProfileSha256",
  "producerSignAssignmentSha256",
  "producerSignQualificationResultSha256",
  "producerLocalVerifierProfileId",
  "producerLocalVerifierProfileSha256",
  "producerLocalGpgImmutableInstallationProfileSha256",
  "producerLocalVerifyAssignmentSha256",
  "producerLocalVerifyQualificationResultSha256",
  "semanticInputSetSha256",
  "executionIdentitySha256",
  "platformClassSha256",
  "runtimeClassSha256",
  "resultStatus",
  "fileLedgerSha256",
  "fileLedger",
]);
export const SIGNATURE_VERIFICATION_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "status",
  "mode",
  "namespace",
  "campaignId",
  "matrixCellId",
  "signerFingerprint",
  "signerRole",
  "gpgRole",
  "hostRole",
  "gpgVerifierProfileId",
  "gpgVerifierProfileSha256",
  "gpgAssignmentSha256",
  "gpgImmutableInstallationProfileSha256",
  "gpgQualificationResultSha256",
  "signatureVerified",
  "primaryFingerprintVerified",
  "policyBindingVerified",
  "platformAttestationVerified",
]);
export const CELL_VERIFICATION_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "status",
  "mode",
  "campaignId",
  "matrixCellId",
  "sourceCommit",
  "toolingCommit",
  "campaignPolicySha256",
  "runNonce",
  "nodeRuntimeProfileId",
  "nodeRuntimeProfileSha256",
  "nodeImmutableInstallationProfileSha256",
  "nodeQualificationResultSha256",
  "producerGpgProfileId",
  "producerGpgProfileSha256",
  "producerGpgImmutableInstallationProfileSha256",
  "producerSignAssignmentSha256",
  "producerSignQualificationResultSha256",
  "producerLocalVerifierProfileId",
  "producerLocalVerifierProfileSha256",
  "producerLocalGpgImmutableInstallationProfileSha256",
  "producerLocalVerifyAssignmentSha256",
  "producerLocalVerifyQualificationResultSha256",
  "verificationRole",
  "verificationHostRole",
  "consumerNodeRuntimeProfileId",
  "consumerNodeRuntimeProfileSha256",
  "consumerNodeImmutableInstallationProfileSha256",
  "consumerNodeQualificationResultSha256",
  "consumerRuntimeIdentitySha256",
  "consumerVerifierProfileId",
  "consumerVerifierProfileSha256",
  "consumerVerifyAssignmentSha256",
  "consumerImmutableInstallationProfileSha256",
  "consumerQualificationResultSha256",
  "semanticInputSetSha256",
  "executionIdentitySha256",
  "platformClassSha256",
  "runtimeClassSha256",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "artifactSha256",
  "entryPlanSha256",
  "zipVerificationSha256",
  "evidenceSha256",
  "verificationResultSha256",
  "signerFingerprint",
  "signerRole",
  "signatureNamespace",
  "signatureVerified",
  "fileLedgerVerified",
  "exactOutputSetVerified",
  "d1CanonicalVerificationPassed",
  "d2SameProcessPassed",
  "d2SameHostPassed",
  "boundaryVectorSetPassed",
  "privacyGatePassed",
  "temporaryRootCleanupVerified",
  "environmentBlockerAbsent",
  "comparisonEligible",
  "platformAttestationVerified",
  "projectPublicationAuthorized",
]);
export const CAMPAIGN_COMPARISON_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "status",
  "mode",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
  "matrixComplete",
  "claimAllowed",
  "claimLevelsSatisfied",
  "crossRuntimePair",
  "crossOsPair",
  "artifactSha256",
  "entryPlanSha256",
  "zipVerificationSha256",
  "semanticInputSetSha256",
  "cellAuthorities",
  "comparisonNodeRuntimeProfileId",
  "comparisonNodeRuntimeProfileSha256",
  "comparisonNodeImmutableInstallationProfileSha256",
  "comparisonNodeQualificationResultSha256",
  "comparisonSignerProfileId",
  "comparisonSignerProfileSha256",
  "comparisonSignAssignmentSha256",
  "comparisonSignerImmutableInstallationProfileSha256",
  "comparisonSignQualificationResultSha256",
  "comparisonLocalVerifierProfileId",
  "comparisonLocalVerifierProfileSha256",
  "comparisonLocalVerifyAssignmentSha256",
  "comparisonLocalVerifierImmutableInstallationProfileSha256",
  "comparisonLocalVerifyQualificationResultSha256",
  "independentReviewVerifierProfileId",
  "independentReviewVerifierProfileSha256",
  "independentReviewVerifyAssignmentSha256",
  "independentReviewVerifierImmutableInstallationProfileSha256",
  "independentReviewCompleted",
  "allExecutionProfilesQualified",
  "requiredCellCount",
  "acceptedCellCount",
  "evidenceSigningRequired",
  "platformAttestationVerified",
  "projectPublicationAuthorized",
]);
export const COMPARISON_CELL_AUTHORITY_KEYS = Object.freeze([
  "matrixCellId",
  "runtimeIdentitySha256",
  "nodeRuntimeProfileSha256",
  "nodeImmutableInstallationProfileSha256",
  "nodeQualificationResultSha256",
  "producerGpgProfileId",
  "producerGpgProfileSha256",
  "producerSignAssignmentSha256",
  "producerLocalVerifierProfileId",
  "producerLocalVerifierProfileSha256",
  "producerLocalVerifyAssignmentSha256",
  "consumerVerifierProfileId",
  "consumerVerifierProfileSha256",
  "consumerVerifyAssignmentSha256",
  "consumerHostRole",
  "consumerNodeRuntimeProfileSha256",
  "consumerNodeImmutableInstallationProfileSha256",
  "consumerNodeQualificationResultSha256",
  "consumerRuntimeIdentitySha256",
  "signatureVerified",
]);
export const CAMPAIGN_FAILURE_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "status",
  "mode",
  "phase",
  "reason",
  "matrixComplete",
  "claimAllowed",
  "platformAttestationVerified",
  "projectPublicationAuthorized",
]);
export const COMPARISON_MANIFEST_KEYS = Object.freeze([
  "documentKind",
  "namespace",
  "schemaVersion",
  "campaignId",
  "role",
  "sourceCommit",
  "toolingCommit",
  "campaignPolicySha256",
  "cellAuthoritiesSha256",
  "comparisonNodeRuntimeProfileId",
  "comparisonNodeRuntimeProfileSha256",
  "comparisonNodeImmutableInstallationProfileSha256",
  "comparisonNodeQualificationResultSha256",
  "comparisonSignerProfileId",
  "comparisonSignerProfileSha256",
  "comparisonSignAssignmentSha256",
  "comparisonSignerImmutableInstallationProfileSha256",
  "comparisonSignQualificationResultSha256",
  "comparisonLocalVerifierProfileId",
  "comparisonLocalVerifierProfileSha256",
  "comparisonLocalVerifyAssignmentSha256",
  "comparisonLocalVerifierImmutableInstallationProfileSha256",
  "comparisonLocalVerifyQualificationResultSha256",
  "independentReviewVerifierProfileId",
  "independentReviewVerifierProfileSha256",
  "independentReviewVerifyAssignmentSha256",
  "independentReviewVerifierImmutableInstallationProfileSha256",
  "fileLedgerSha256",
  "runNonce",
  "resultStatus",
  "fileLedger",
]);

const ERROR_PHASES = new Set([
  "CLI",
  "OBJECT_AUTHORITY",
  "POLICY",
  "ENVIRONMENT_LOCK",
  "PLATFORM_PROBE",
  "D2_BINDING",
  "RUNTIME_IDENTITY",
  "GIT_IDENTITY",
  "FILE_LEDGER",
  "CELL_RESULT",
  "CELL_MANIFEST",
  "SIGNATURE",
  "GPG_PROFILE",
  "GPG_EXECUTION",
  "ENVIRONMENT",
  "CELL_VERIFICATION",
  "COMPARISON",
  "OUTPUT_PUBLICATION",
  "CLEANUP",
  "PRIVACY",
]);
const REASON_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/u;
const IDENTIFIER_PATTERN =
  /^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,126}[A-Za-z0-9])?$/u;
const RUN_NONCE_PATTERN = /^[0-9a-f]{32}$/u;
const PUBLIC_TEXT_PATTERN = /^[\x20-\x7e]{1,256}$/u;
const GPG_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9]+)*$/u;
const GPG_DISTRIBUTION_PROFILE_PATTERN =
  /^(?:test-only-)?gnupg-[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const GPG_ALLOWED_OPERATIONS = Object.freeze([
  "detached-sign", "detached-verify", "version-query",
]);
const GPG_SIGNATURE_OPERATIONS = Object.freeze([
  "detached-sign", "detached-verify",
]);
const GPG_COMPARISON_ROLE = "campaign-comparison";
const GPG_TIMEOUT_MILLISECONDS = 30_000;
const GPG_STDOUT_BOUND_BYTES = 1024 * 1024;
const GPG_STDERR_BOUND_BYTES = 1024 * 1024;
const GPG_EXECUTABLE_MAXIMUM_BYTES = 256 * 1024 * 1024;
const NODE_EXECUTABLE_MAXIMUM_BYTES = 256 * 1024 * 1024;
const GPG_PROCESS_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.gpg-process.test-adapter",
);
const EXECUTION_QUALIFICATION_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.execution-qualification.test-adapter",
);
const IMMUTABLE_QUALIFICATION_MODES = Object.freeze([
  "windows-acl-immutable-installation-v1",
  "linux-owner-mode-mount-immutable-installation-v1",
  "synthetic-test-only-v1",
]);
const NODE_ASSIGNMENT_ROLE_SET = new Set(NODE_CAMPAIGN_ROLES);
const GPG_ROLE_SET = new Set(GPG_OPERATION_ROLES);
const COMPARISON_CLASS_SET = new Set([
  "byte-identical", "semantic", "cell-specific", "private-verification",
]);
const PROHIBITED_PUBLIC_KEYS = new Set([
  "path",
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
  "gpghome",
  "keygrip",
  "agentsocket",
  "privatekey",
  "commandline",
]);

export class PublicSourceZipCampaignError extends Error {
  constructor(phase, reason) {
    const safePhase = ERROR_PHASES.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string" && REASON_PATTERN.test(reason)
      ? reason
      : "invalid-operation";
    super("public source ZIP campaign operation failed");
    this.name = "PublicSourceZipCampaignError";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failPublicSourceZipCampaign(phase, reason) {
  throw new PublicSourceZipCampaignError(phase, reason);
}

export function asPublicSourceZipCampaignError(error, phase, reason) {
  try {
    assertProxyFreeAuthorityGraph(error, { allowError: true });
  } catch {
    return new PublicSourceZipCampaignError("OBJECT_AUTHORITY", "authority-graph-rejected");
  }
  return error instanceof PublicSourceZipCampaignError
    ? error
    : new PublicSourceZipCampaignError(phase, reason);
}

function authority(value, options = undefined) {
  try {
    assertProxyFreeAuthorityGraph(value, options);
  } catch {
    failPublicSourceZipCampaign("OBJECT_AUTHORITY", "authority-graph-rejected");
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
  ) failPublicSourceZipCampaign(phase, reason + "-object");
  let actual;
  let descriptors;
  try {
    actual = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    failPublicSourceZipCampaign(phase, reason + "-object");
  }
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) failPublicSourceZipCampaign(phase, reason + "-keys");
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true
      || descriptor.get !== undefined
      || descriptor.set !== undefined
    ) failPublicSourceZipCampaign(phase, reason + "-descriptor");
  }
  return value;
}

function requireArray(value, phase, reason, options = undefined) {
  authority(value, options);
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireIdentifier(value, phase, reason) {
  if (
    typeof value !== "string"
    || !IDENTIFIER_PATTERN.test(value)
    || value.includes("..")
  ) failPublicSourceZipCampaign(phase, reason);
  return value;
}

function requirePublicText(value, phase, reason) {
  if (
    typeof value !== "string"
    || !PUBLIC_TEXT_PATTERN.test(value)
    || value.includes("\\")
    || /^[A-Za-z]:[\\/]/u.test(value)
    || value.startsWith("/")
    || /^file:/iu.test(value)
  ) failPublicSourceZipCampaign(phase, reason);
  return value;
}

function requireSha256(value, phase, reason) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireGitObject(value, phase, reason) {
  if (typeof value !== "string" || !GIT_OBJECT_PATTERN.test(value)) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireFingerprint(value, phase, reason) {
  if (typeof value !== "string" || !FINGERPRINT_PATTERN.test(value)) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireCount(value, phase, reason, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function requireFixedBoolean(value, expected, phase, reason) {
  if (requireBoolean(value, phase, reason) !== expected) {
    failPublicSourceZipCampaign(phase, reason);
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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
      || (value.includes("/") && !["name"].includes(keyName))
    ) failPublicSourceZipCampaign("PRIVACY", "private-material");
    return;
  }
  if (!value || typeof value !== "object") return;
  const arrayValue = Array.isArray(value);
  for (const key of Reflect.ownKeys(value)) {
    if (arrayValue && key === "length") continue;
    if (typeof key !== "string") {
      failPublicSourceZipCampaign("PRIVACY", "symbol-key");
    }
    if (!arrayValue && PROHIBITED_PUBLIC_KEYS.has(key.toLowerCase())) {
      failPublicSourceZipCampaign("PRIVACY", "private-field");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    rejectPrivacyTrusted(descriptor.value, arrayValue ? keyName : key);
  }
}

export function rejectCampaignPrivateMaterial(value) {
  authority(value);
  rejectPrivacyTrusted(value);
  return value;
}

function frozen(value) {
  rejectCampaignPrivateMaterial(value);
  return deepFreezeZipReproducibility(value);
}

function canonicalBytes(value, phase, reason) {
  authority(value);
  rejectCampaignPrivateMaterial(value);
  try {
    return canonicalPublicJsonBytes(value, "PRIVACY");
  } catch {
    failPublicSourceZipCampaign(phase, reason);
  }
}

function parseCanonical(bytes, validator, phase, reason) {
  authority(bytes, { allowBuffer: true });
  if (!Buffer.isBuffer(bytes)) failPublicSourceZipCampaign(phase, reason + "-bytes");
  let parsed;
  try {
    parsed = parseCanonicalPublicJsonBytes(bytes, "PRIVACY");
  } catch {
    failPublicSourceZipCampaign(phase, reason + "-canonical");
  }
  return validator(parsed);
}

function validateGpgInvocationOperation(value, expected) {
  const phase = "GPG_PROFILE";
  exactDataObject(
    value,
    GPG_INVOCATION_OPERATION_KEYS,
    phase,
    "invocation-operation",
  );
  if (
    value.operation !== expected.operation
    || value.statusFd !== expected.statusFd
  ) failPublicSourceZipCampaign(phase, "invocation-operation-authority");
  requireArray(value.arguments, phase, "invocation-arguments");
  if (
    value.arguments.length !== expected.arguments.length
    || value.arguments.some((entry, index) => entry !== expected.arguments[index])
  ) failPublicSourceZipCampaign(phase, "invocation-arguments-authority");
  return frozen(value);
}

const IMPLEMENTATION_GPG_INVOCATION_OPERATIONS = Object.freeze([
  Object.freeze({
    operation: "detached-sign",
    statusFd: "stdout-fd-1",
    arguments: Object.freeze([
      "--pinentry-mode", "loopback",
      "--status-fd", "1",
      "--local-user", "<SIGNING_FINGERPRINT>",
      "--detach-sign",
      "--output", "<SIGNATURE_FILE>",
      "<SIGNED_FILE>",
    ]),
  }),
  Object.freeze({
    operation: "detached-verify",
    statusFd: "stdout-fd-1",
    arguments: Object.freeze([
      "--status-fd", "1",
      "--verify", "<SIGNATURE_FILE>", "<SIGNED_FILE>",
    ]),
  }),
  Object.freeze({
    operation: "version-query",
    statusFd: "unused",
    arguments: Object.freeze(["--version"]),
  }),
]);

export function validateGpgInvocationProfile(value) {
  const phase = "GPG_PROFILE";
  exactDataObject(
    value,
    GPG_INVOCATION_PROFILE_KEYS,
    phase,
    "invocation-profile",
  );
  if (
    value.documentKind !== GPG_INVOCATION_PROFILE_DOCUMENT_KIND
    || value.schemaVersion !== 1
  ) failPublicSourceZipCampaign(phase, "invocation-profile-header");
  requireArray(value.allowedOperations, phase, "allowed-operations");
  if (
    value.allowedOperations.length !== GPG_ALLOWED_OPERATIONS.length
    || value.allowedOperations.some(
      (entry, index) => entry !== GPG_ALLOWED_OPERATIONS[index],
    )
  ) failPublicSourceZipCampaign(phase, "allowed-operations-authority");
  const expectedGlobalArguments = [
    "--no-options",
    "--homedir", "<GNUPGHOME>",
    "--batch",
    "--no-tty",
    "--no-auto-key-retrieve",
    "--auto-key-locate", "clear",
  ];
  requireArray(value.requiredGlobalArguments, phase, "global-arguments");
  if (
    value.requiredGlobalArguments.length !== expectedGlobalArguments.length
    || value.requiredGlobalArguments.some(
      (entry, index) => entry !== expectedGlobalArguments[index],
    )
  ) failPublicSourceZipCampaign(phase, "global-arguments-authority");
  requireArray(value.operationProfiles, phase, "operation-profiles");
  if (value.operationProfiles.length !== IMPLEMENTATION_GPG_INVOCATION_OPERATIONS.length) {
    failPublicSourceZipCampaign(phase, "operation-profile-count");
  }
  value.operationProfiles.forEach((entry, index) => {
    validateGpgInvocationOperation(
      entry,
      IMPLEMENTATION_GPG_INVOCATION_OPERATIONS[index],
    );
  });
  if (
    value.statusFdUsage !== "cryptographic-operations-only-stdout-fd-1"
    || value.batchMode !== true
    || value.noTty !== true
    || value.noOptions !== true
    || value.noAutoKeyRetrieve !== true
    || value.networkProhibition !== "no-network-no-auto-key-retrieve"
    || value.shell !== false
    || value.argumentArrayExecution !== true
    || value.timeoutPolicy !== "terminate-after-30000ms"
    || value.stdoutBoundBytes !== GPG_STDOUT_BOUND_BYTES
    || value.stderrBoundBytes !== GPG_STDERR_BOUND_BYTES
    || value.gpgHomeRequirement !== "explicit-absolute-non-reparse-directory"
  ) failPublicSourceZipCampaign(phase, "invocation-profile-authority");
  return frozen(value);
}

const IMPLEMENTATION_GPG_INVOCATION_PROFILE = validateGpgInvocationProfile({
  documentKind: GPG_INVOCATION_PROFILE_DOCUMENT_KIND,
  schemaVersion: 1,
  allowedOperations: [...GPG_ALLOWED_OPERATIONS],
  requiredGlobalArguments: [
    "--no-options",
    "--homedir", "<GNUPGHOME>",
    "--batch",
    "--no-tty",
    "--no-auto-key-retrieve",
    "--auto-key-locate", "clear",
  ],
  operationProfiles: IMPLEMENTATION_GPG_INVOCATION_OPERATIONS.map((entry) => ({
    operation: entry.operation,
    statusFd: entry.statusFd,
    arguments: [...entry.arguments],
  })),
  statusFdUsage: "cryptographic-operations-only-stdout-fd-1",
  batchMode: true,
  noTty: true,
  noOptions: true,
  noAutoKeyRetrieve: true,
  networkProhibition: "no-network-no-auto-key-retrieve",
  shell: false,
  argumentArrayExecution: true,
  timeoutPolicy: "terminate-after-30000ms",
  stdoutBoundBytes: GPG_STDOUT_BOUND_BYTES,
  stderrBoundBytes: GPG_STDERR_BOUND_BYTES,
  gpgHomeRequirement: "explicit-absolute-non-reparse-directory",
});

export function encodeCanonicalGpgInvocationProfile() {
  return canonicalBytes(
    IMPLEMENTATION_GPG_INVOCATION_PROFILE,
    "GPG_PROFILE",
    "canonical-invocation-profile",
  );
}

export function gpgInvocationProfileSha256() {
  return sha256(encodeCanonicalGpgInvocationProfile());
}

function requireNullableSha256(value, phase, reason) {
  if (value === null) return null;
  return requireSha256(value, phase, reason);
}

export function validateImmutableInstallationProfile(value) {
  const phase = "ENVIRONMENT";
  exactDataObject(
    value,
    IMMUTABLE_INSTALLATION_PROFILE_KEYS,
    phase,
    "immutable-installation-profile",
  );
  if (
    value.documentKind !== IMMUTABLE_INSTALLATION_PROFILE_DOCUMENT_KIND
    || value.schemaVersion !== 1
    || !IMMUTABLE_QUALIFICATION_MODES.includes(value.qualificationMode)
  ) failPublicSourceZipCampaign(phase, "immutable-installation-profile-header");
  requireIdentifier(value.profileId, phase, "immutable-installation-profile-id");
  if (!["windows", "linux"].includes(value.osFamily)) {
    failPublicSourceZipCampaign(phase, "immutable-installation-os-family");
  }
  if (!["x64", "arm64"].includes(value.architecture)) {
    failPublicSourceZipCampaign(phase, "immutable-installation-architecture");
  }
  requireIdentifier(value.distributionProfile, phase, "immutable-installation-distribution");
  requireSha256(value.executableSha256, phase, "immutable-installation-executable-sha256");
  requireCount(
    value.executableByteLength,
    phase,
    "immutable-installation-executable-length",
    NODE_EXECUTABLE_MAXIMUM_BYTES,
  );
  if (value.executableByteLength === 0) {
    failPublicSourceZipCampaign(phase, "immutable-installation-executable-length");
  }
  for (const key of [
    "fileIdentityPolicy",
    "ownerPolicy",
    "principalPolicy",
    "parentChainPolicy",
    "accessControlPolicy",
    "linkPolicy",
    "filesystemPolicy",
    "qualificationProbeMode",
  ]) requireIdentifier(value[key], phase, "immutable-installation-policy-field");
  requireNullableSha256(
    value.qualificationProbeProfileSha256,
    phase,
    "qualification-probe-profile-sha256",
  );
  if (
    value.fileIdentityPolicy !== "stable-device-inode-or-volume-file-id"
    || value.parentChainPolicy !== "all-replacement-relevant-parents-immutable"
    || value.linkPolicy !== "non-reparse-single-link"
    || value.filesystemPolicy !== "qualified-local-filesystem"
  ) failPublicSourceZipCampaign(phase, "immutable-installation-common-policy");
  if (value.qualificationMode === "windows-acl-immutable-installation-v1") {
    if (
      value.osFamily !== "windows"
      || value.ownerPolicy !== "administrator-controlled-owner-no-campaign-takeover"
      || value.principalPolicy !== "campaign-principal-and-enabled-groups-denied-mutation"
      || value.accessControlPolicy !== "effective-dacl-file-and-parent-chain-v1"
      || value.qualificationProbeMode !== "required-qualified-probe"
      || value.qualificationProbeProfileSha256 === null
    ) failPublicSourceZipCampaign(phase, "windows-immutable-installation-policy");
  } else if (value.qualificationMode === "linux-owner-mode-mount-immutable-installation-v1") {
    if (
      value.osFamily !== "linux"
      || value.ownerPolicy !== "root-controlled-owner-no-campaign-takeover"
      || value.principalPolicy !== "campaign-uid-and-effective-groups-denied-mutation"
      || value.accessControlPolicy !== "owner-mode-parent-chain-v1"
      || value.qualificationProbeMode !== "node-built-in-no-probe"
      || value.qualificationProbeProfileSha256 !== null
    ) failPublicSourceZipCampaign(phase, "linux-immutable-installation-policy");
  } else if (
    value.ownerPolicy !== "synthetic-test-only"
    || value.principalPolicy !== "synthetic-test-only"
    || value.accessControlPolicy !== "synthetic-test-only"
    || value.qualificationProbeMode !== "synthetic-test-only"
    || value.qualificationProbeProfileSha256 !== null
  ) failPublicSourceZipCampaign(phase, "synthetic-immutable-installation-policy");
  return frozen(value);
}

export function encodeCanonicalImmutableInstallationProfile(value) {
  authority(value);
  return canonicalBytes(
    validateImmutableInstallationProfile(value),
    "ENVIRONMENT",
    "canonical-immutable-installation-profile",
  );
}

export function parseCanonicalImmutableInstallationProfileBytes(bytes) {
  return parseCanonical(
    bytes,
    validateImmutableInstallationProfile,
    "ENVIRONMENT",
    "immutable-installation-profile",
  );
}

export function immutableInstallationProfileSha256(value) {
  authority(value);
  return sha256(encodeCanonicalImmutableInstallationProfile(value));
}

export function validateMeasuredQualificationResult(value) {
  const phase = "ENVIRONMENT";
  exactDataObject(
    value,
    MEASURED_QUALIFICATION_RESULT_KEYS,
    phase,
    "qualification-result",
  );
  if (
    value.documentKind !== MEASURED_QUALIFICATION_RESULT_DOCUMENT_KIND
    || value.schemaVersion !== 1
    || !["qualified", "blocked"].includes(value.status)
  ) failPublicSourceZipCampaign(phase, "qualification-result-header");
  requireIdentifier(value.profileId, phase, "qualification-profile-id");
  requireSha256(value.profileSha256, phase, "qualification-profile-sha256");
  requireIdentifier(value.phase, phase, "qualification-phase");
  requireIdentifier(value.reason, phase, "qualification-reason");
  if (!["windows", "linux"].includes(value.osFamily)) {
    failPublicSourceZipCampaign(phase, "qualification-os-family");
  }
  if (!["x64", "arm64"].includes(value.architecture)) {
    failPublicSourceZipCampaign(phase, "qualification-architecture");
  }
  requireSha256(value.executableSha256, phase, "qualification-executable-sha256");
  requireCount(
    value.executableByteLength,
    phase,
    "qualification-executable-length",
    NODE_EXECUTABLE_MAXIMUM_BYTES,
  );
  for (const key of [
    "fileIdentitySha256",
    "parentChainEvidenceSha256",
    "accessControlEvidenceSha256",
    "filesystemEvidenceSha256",
  ]) requireSha256(value[key], phase, "qualification-evidence-sha256");
  requireCount(value.linkCount, phase, "qualification-link-count", 1024);
  for (const key of [
    "reparseOrSymlink",
    "campaignPrincipalWritable",
    "campaignPrincipalDeleteOrRenameCapable",
    "campaignPrincipalAclChangeCapable",
    "campaignPrincipalOwnershipTakeoverCapable",
  ]) requireBoolean(value[key], phase, "qualification-boolean");
  const mechanicallyQualified = value.linkCount === 1
    && value.reparseOrSymlink === false
    && value.campaignPrincipalWritable === false
    && value.campaignPrincipalDeleteOrRenameCapable === false
    && value.campaignPrincipalAclChangeCapable === false
    && value.campaignPrincipalOwnershipTakeoverCapable === false;
  if (
    (value.status === "qualified") !== mechanicallyQualified
    || (value.status === "qualified"
      && value.reason !== "immutable-installation-qualified")
    || (value.status === "blocked"
      && value.reason !== "immutable-installation-not-proven")
  ) failPublicSourceZipCampaign(phase, "qualification-result-semantics");
  return frozen(value);
}

export function encodeCanonicalMeasuredQualificationResult(value) {
  authority(value);
  return canonicalBytes(
    validateMeasuredQualificationResult(value),
    "ENVIRONMENT",
    "canonical-qualification-result",
  );
}

export function parseCanonicalMeasuredQualificationResultBytes(bytes) {
  return parseCanonical(
    bytes,
    validateMeasuredQualificationResult,
    "ENVIRONMENT",
    "qualification-result",
  );
}

export function measuredQualificationResultSha256(value) {
  authority(value);
  return sha256(encodeCanonicalMeasuredQualificationResult(value));
}

export function validateNodeRuntimeProfile(value) {
  const phase = "RUNTIME_IDENTITY";
  exactDataObject(value, NODE_RUNTIME_PROFILE_KEYS, phase, "node-runtime-profile");
  if (
    value.documentKind !== NODE_RUNTIME_PROFILE_DOCUMENT_KIND
    || value.schemaVersion !== 1
    || value.runtimeFamily !== "nodejs"
  ) failPublicSourceZipCampaign(phase, "node-runtime-profile-header");
  requireIdentifier(value.profileId, phase, "node-runtime-profile-id");
  requireIdentifier(value.distributionProfile, phase, "node-runtime-distribution");
  if (!["windows", "linux"].includes(value.osFamily)) {
    failPublicSourceZipCampaign(phase, "node-runtime-os-family");
  }
  if (!["x64", "arm64"].includes(value.architecture)) {
    failPublicSourceZipCampaign(phase, "node-runtime-architecture");
  }
  for (const key of ["runtimeVersion", "v8Version", "modulesAbi"]) {
    requireIdentifier(value[key], phase, "node-runtime-version-field");
  }
  requireSha256(value.executableSha256, phase, "node-runtime-executable-sha256");
  requireCount(
    value.executableByteLength,
    phase,
    "node-runtime-executable-length",
    NODE_EXECUTABLE_MAXIMUM_BYTES,
  );
  if (value.executableByteLength === 0) {
    failPublicSourceZipCampaign(phase, "node-runtime-executable-length");
  }
  requireSha256(
    value.immutableInstallationProfileSha256,
    phase,
    "node-runtime-immutable-profile-sha256",
  );
  requireGitObject(value.sourceCommit, phase, "node-runtime-source-commit");
  requireGitObject(value.toolingCommit, phase, "node-runtime-tooling-commit");
  return frozen(value);
}

export function encodeCanonicalNodeRuntimeProfile(value) {
  authority(value);
  return canonicalBytes(
    validateNodeRuntimeProfile(value),
    "RUNTIME_IDENTITY",
    "canonical-node-runtime-profile",
  );
}

export function parseCanonicalNodeRuntimeProfileBytes(bytes) {
  return parseCanonical(
    bytes,
    validateNodeRuntimeProfile,
    "RUNTIME_IDENTITY",
    "node-runtime-profile",
  );
}

export function nodeRuntimeProfileSha256(value) {
  authority(value);
  return sha256(encodeCanonicalNodeRuntimeProfile(value));
}

export function gpgVerifierAssignmentSha256(value) {
  authority(value);
  exactDataObject(
    value,
    GPG_VERIFIER_ASSIGNMENT_KEYS,
    "POLICY",
    "gpg-verifier-assignment",
  );
  return sha256(canonicalBytes(value, "POLICY", "canonical-gpg-assignment"));
}

export function nodeRuntimeAssignmentSha256(value) {
  authority(value);
  exactDataObject(
    value,
    NODE_RUNTIME_ASSIGNMENT_KEYS,
    "POLICY",
    "node-runtime-assignment",
  );
  return sha256(canonicalBytes(value, "POLICY", "canonical-node-assignment"));
}

export function validateGpgVerifierExecutionProfile(value) {
  const phase = "GPG_PROFILE";
  exactDataObject(
    value,
    GPG_VERIFIER_PROFILE_KEYS,
    phase,
    "gpg-verifier-profile",
  );
  if (
    value.documentKind !== GPG_VERIFIER_PROFILE_DOCUMENT_KIND
    || value.schemaVersion !== 1
    || value.verifierFamily !== "gnupg"
    || value.statusProtocol !== "gnupg-status-fd-v1"
    || value.fileIdentityPolicy
      !== "stable-file-identity-pre-spawn-post-spawn"
    || value.linkPolicy !== "non-reparse-single-link"
    || value.networkPolicy !== "no-network-no-auto-key-retrieve"
  ) failPublicSourceZipCampaign(phase, "gpg-verifier-profile-authority");
  requireIdentifier(value.profileId, phase, "profile-id");
  if (
    typeof value.distributionProfile !== "string"
    || !GPG_DISTRIBUTION_PROFILE_PATTERN.test(value.distributionProfile)
  ) failPublicSourceZipCampaign(phase, "distribution-profile");
  if (!new Set(["windows", "linux"]).has(value.osFamily)) {
    failPublicSourceZipCampaign(phase, "os-family");
  }
  if (!new Set(["x64", "arm64"]).has(value.architecture)) {
    failPublicSourceZipCampaign(phase, "architecture");
  }
  requireSha256(value.executableSha256, phase, "executable-sha256");
  requireCount(
    value.executableByteLength,
    phase,
    "executable-byte-length",
    GPG_EXECUTABLE_MAXIMUM_BYTES,
  );
  if (value.executableByteLength === 0) {
    failPublicSourceZipCampaign(phase, "executable-byte-length");
  }
  if (typeof value.version !== "string" || !GPG_VERSION_PATTERN.test(value.version)) {
    failPublicSourceZipCampaign(phase, "version");
  }
  if (value.invocationProfileSha256 !== gpgInvocationProfileSha256()) {
    failPublicSourceZipCampaign(phase, "invocation-profile-binding");
  }
  requireSha256(
    value.immutableInstallationProfileSha256,
    phase,
    "immutable-installation-profile-binding",
  );
  return frozen(value);
}

export function encodeCanonicalGpgVerifierExecutionProfile(value) {
  authority(value);
  return canonicalBytes(
    validateGpgVerifierExecutionProfile(value),
    "GPG_PROFILE",
    "canonical-gpg-verifier-profile",
  );
}

export function parseCanonicalGpgVerifierExecutionProfileBytes(bytes) {
  return parseCanonical(
    bytes,
    validateGpgVerifierExecutionProfile,
    "GPG_PROFILE",
    "gpg-verifier-profile",
  );
}

export function gpgVerifierExecutionProfileSha256(value) {
  authority(value);
  return sha256(encodeCanonicalGpgVerifierExecutionProfile(value));
}

function validateImmutablePolicyAuthority(policy) {
  const phase = "POLICY";
  requireArray(
    policy.immutableInstallationProfiles,
    phase,
    "immutable-installation-profiles",
  );
  if (policy.immutableInstallationProfiles.length === 0) {
    failPublicSourceZipCampaign(phase, "immutable-installation-profile-count");
  }
  const profiles = policy.immutableInstallationProfiles.map((entry) => (
    validateImmutableInstallationProfile(entry)
  ));
  const ids = profiles.map((entry) => entry.profileId);
  const hashes = profiles.map((entry) => immutableInstallationProfileSha256(entry));
  if (new Set(ids).size !== ids.length || new Set(hashes).size !== hashes.length) {
    failPublicSourceZipCampaign(phase, "duplicate-immutable-installation-profile");
  }
  return Object.freeze({
    profiles: Object.freeze(profiles),
    hashes: Object.freeze(hashes),
  });
}

function validateNodePolicyAuthority(policy, cells, immutableAuthority) {
  const phase = "POLICY";
  requireArray(policy.nodeRuntimeProfiles, phase, "node-runtime-profiles");
  requireArray(policy.nodeRuntimeAssignments, phase, "node-runtime-assignments");
  if (policy.nodeRuntimeProfiles.length === 0) {
    failPublicSourceZipCampaign(phase, "node-runtime-profile-count");
  }
  const profiles = policy.nodeRuntimeProfiles.map((entry) => validateNodeRuntimeProfile(entry));
  const profileIds = profiles.map((entry) => entry.profileId);
  if (new Set(profileIds).size !== profileIds.length) {
    failPublicSourceZipCampaign(phase, "duplicate-node-runtime-profile");
  }
  for (const profile of profiles) {
    const immutableIndex = immutableAuthority.hashes.indexOf(
      profile.immutableInstallationProfileSha256,
    );
    const immutable = immutableAuthority.profiles[immutableIndex];
    if (
      immutableIndex < 0
      || immutable.osFamily !== profile.osFamily
      || immutable.architecture !== profile.architecture
      || immutable.distributionProfile !== profile.distributionProfile
      || immutable.executableSha256 !== profile.executableSha256
      || immutable.executableByteLength !== profile.executableByteLength
      || profile.sourceCommit !== policy.sourceCommit
      || profile.toolingCommit !== policy.toolingCommit
    ) failPublicSourceZipCampaign(phase, "node-runtime-immutable-profile-binding");
  }
  if (policy.nodeRuntimeAssignments.length !== cells.length + 3) {
    failPublicSourceZipCampaign(phase, "node-runtime-assignment-count");
  }
  const assignmentIds = new Set();
  const usedProfiles = new Set();
  const tailRoles = [
    "cell-import-consumer",
    "comparison-host",
    "independent-review-host",
  ];
  for (let index = 0; index < policy.nodeRuntimeAssignments.length; index += 1) {
    const assignment = policy.nodeRuntimeAssignments[index];
    exactDataObject(
      assignment,
      NODE_RUNTIME_ASSIGNMENT_KEYS,
      phase,
      "node-runtime-assignment",
    );
    requireIdentifier(assignment.assignmentId, phase, "node-assignment-id");
    requireIdentifier(assignment.profileId, phase, "node-assignment-profile-id");
    requireIdentifier(assignment.hostRole, phase, "node-assignment-host-role");
    if (
      assignmentIds.has(assignment.assignmentId)
      || !NODE_ASSIGNMENT_ROLE_SET.has(assignment.campaignRole)
    ) failPublicSourceZipCampaign(phase, "duplicate-or-unknown-node-assignment");
    assignmentIds.add(assignment.assignmentId);
    const cell = index < cells.length ? cells[index] : null;
    const expectedRole = cell === null ? tailRoles[index - cells.length] : "cell-producer";
    const expectedMatrixCellId = cell?.matrixCellId ?? null;
    if (
      assignment.campaignRole !== expectedRole
      || assignment.matrixCellId !== expectedMatrixCellId
      || (cell !== null && assignment.hostRole !== cell.matrixCellId)
      || assignment.campaignId !== policy.campaignId
      || assignment.sourceCommit !== policy.sourceCommit
      || assignment.toolingCommit !== policy.toolingCommit
    ) failPublicSourceZipCampaign(phase, "node-runtime-assignment-binding");
    const profile = profiles.find((entry) => entry.profileId === assignment.profileId);
    if (
      !profile
      || assignment.osFamily !== profile.osFamily
      || assignment.architecture !== profile.architecture
    ) failPublicSourceZipCampaign(phase, "node-runtime-assignment-profile");
    usedProfiles.add(profile.profileId);
  }
  if (profiles.some((entry) => !usedProfiles.has(entry.profileId))) {
    failPublicSourceZipCampaign(phase, "unassigned-node-runtime-profile");
  }
  return Object.freeze({
    profiles: Object.freeze(profiles),
    assignments: Object.freeze([...policy.nodeRuntimeAssignments]),
  });
}

function validateGpgPolicyAuthority(policy, cells, immutableAuthority, nodeAuthority) {
  const phase = "POLICY";
  requireArray(policy.gpgVerifierProfiles, phase, "gpg-verifier-profiles");
  requireArray(policy.gpgVerifierAssignments, phase, "gpg-verifier-assignments");
  if (policy.gpgVerifierProfiles.length === 0) {
    failPublicSourceZipCampaign(phase, "gpg-verifier-profile-count");
  }
  const profiles = policy.gpgVerifierProfiles.map((entry) => (
    validateGpgVerifierExecutionProfile(entry)
  ));
  const profileIds = profiles.map((entry) => entry.profileId);
  if (new Set(profileIds).size !== profileIds.length) {
    failPublicSourceZipCampaign(phase, "duplicate-gpg-verifier-profile");
  }
  for (const profile of profiles) {
    const immutableIndex = immutableAuthority.hashes.indexOf(
      profile.immutableInstallationProfileSha256,
    );
    const immutable = immutableAuthority.profiles[immutableIndex];
    if (
      immutableIndex < 0
      || immutable.osFamily !== profile.osFamily
      || immutable.architecture !== profile.architecture
      || immutable.distributionProfile !== profile.distributionProfile
      || immutable.executableSha256 !== profile.executableSha256
      || immutable.executableByteLength !== profile.executableByteLength
    ) failPublicSourceZipCampaign(phase, "gpg-immutable-profile-binding");
  }
  const expectedAssignmentCount = (cells.length * 3) + 3;
  if (policy.gpgVerifierAssignments.length !== expectedAssignmentCount) {
    failPublicSourceZipCampaign(phase, "gpg-verifier-assignment-count");
  }
  const consumerNode = nodeAuthority.assignments.find(
    (entry) => entry.campaignRole === "cell-import-consumer",
  );
  const comparisonNode = nodeAuthority.assignments.find(
    (entry) => entry.campaignRole === "comparison-host",
  );
  const reviewNode = nodeAuthority.assignments.find(
    (entry) => entry.campaignRole === "independent-review-host",
  );
  const assignmentIds = new Set();
  const usedProfiles = new Set();
  let comparisonSignerRole = null;
  for (let index = 0; index < policy.gpgVerifierAssignments.length; index += 1) {
    const assignment = policy.gpgVerifierAssignments[index];
    exactDataObject(
      assignment,
      GPG_VERIFIER_ASSIGNMENT_KEYS,
      phase,
      "gpg-verifier-assignment",
    );
    requireIdentifier(assignment.assignmentId, phase, "gpg-assignment-id");
    requireIdentifier(assignment.gpgRole, phase, "gpg-assignment-role");
    requireIdentifier(assignment.hostRole, phase, "gpg-assignment-host-role");
    if (
      assignmentIds.has(assignment.assignmentId)
      || !GPG_ROLE_SET.has(assignment.gpgRole)
    ) failPublicSourceZipCampaign(phase, "duplicate-or-unknown-gpg-assignment");
    assignmentIds.add(assignment.assignmentId);
    let cell = null;
    let expectedRole;
    let expectedOperation;
    let expectedComparisonRole;
    let expectedHostRole;
    let expectedNamespace;
    let expectedNodeCampaignRole;
    if (index < cells.length * 3) {
      cell = cells[Math.floor(index / 3)];
      expectedRole = [
        "cell-producer-sign",
        "cell-producer-local-verify",
        "cell-import-consumer-verify",
      ][index % 3];
      expectedOperation = index % 3 === 0 ? "detached-sign" : "detached-verify";
      expectedComparisonRole = null;
      expectedHostRole = index % 3 === 2 ? consumerNode.hostRole : cell.matrixCellId;
      expectedNamespace = CELL_SIGNATURE_NAMESPACE;
      expectedNodeCampaignRole = index % 3 === 2
        ? "cell-import-consumer"
        : "cell-producer";
    } else {
      expectedRole = [
        "comparison-result-sign",
        "comparison-result-local-verify",
        "independent-result-review-verify",
      ][index - (cells.length * 3)];
      expectedOperation = expectedRole === "comparison-result-sign"
        ? "detached-sign"
        : "detached-verify";
      expectedComparisonRole = expectedRole === "independent-result-review-verify"
        ? "independent-review"
        : GPG_COMPARISON_ROLE;
      expectedHostRole = expectedRole === "independent-result-review-verify"
        ? reviewNode.hostRole
        : comparisonNode.hostRole;
      expectedNamespace = COMPARISON_SIGNATURE_NAMESPACE;
      expectedNodeCampaignRole = expectedRole === "independent-result-review-verify"
        ? "independent-review-host"
        : "comparison-host";
      if (comparisonSignerRole === null) comparisonSignerRole = assignment.signerRole;
    }
    if (
      assignment.gpgRole !== expectedRole
      || assignment.operation !== expectedOperation
      || assignment.matrixCellId !== (cell?.matrixCellId ?? null)
      || assignment.comparisonRole !== expectedComparisonRole
      || assignment.hostRole !== expectedHostRole
      || assignment.signerRole !== (cell?.signerRole ?? comparisonSignerRole)
      || assignment.signatureNamespace !== expectedNamespace
      || assignment.campaignId !== policy.campaignId
      || assignment.sourceCommit !== policy.sourceCommit
      || assignment.toolingCommit !== policy.toolingCommit
      || !policy.allowedSignerRoles.includes(assignment.signerRole)
    ) failPublicSourceZipCampaign(phase, "gpg-verifier-assignment-binding");
    const profile = profiles.find((entry) => entry.profileId === assignment.profileId);
    const hostNodeAssignment = nodeAuthority.assignments.find(
      (entry) => entry.hostRole === expectedHostRole
        && entry.campaignRole === expectedNodeCampaignRole
        && entry.matrixCellId === (expectedNodeCampaignRole === "cell-producer"
          ? cell.matrixCellId
          : null),
    );
    const hostNodeProfile = nodeAuthority.profiles.find(
      (entry) => entry.profileId === hostNodeAssignment?.profileId,
    );
    if (
      !profile
      || !hostNodeAssignment
      || !hostNodeProfile
      || assignment.osFamily !== profile.osFamily
      || assignment.architecture !== profile.architecture
      || profile.osFamily !== hostNodeProfile.osFamily
      || profile.architecture !== hostNodeProfile.architecture
    ) failPublicSourceZipCampaign(phase, "gpg-verifier-assignment-profile");
    usedProfiles.add(profile.profileId);
  }
  if (
    comparisonSignerRole === null
    || profiles.some((entry) => !usedProfiles.has(entry.profileId))
  ) failPublicSourceZipCampaign(phase, "gpg-verifier-profile-target-binding");
  return Object.freeze({
    profiles: Object.freeze(profiles),
    assignments: Object.freeze([...policy.gpgVerifierAssignments]),
  });
}

function requireCellDefinition(value, expectedCellId) {
  const phase = "POLICY";
  exactDataObject(value, POLICY_CELL_KEYS, phase, "cell-definition");
  const matrixCellId = requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  if (matrixCellId !== expectedCellId || !Object.hasOwn(MATRIX_CELL_ROLE_AUTHORITY, matrixCellId)) {
    failPublicSourceZipCampaign(phase, "matrix-cell-authority");
  }
  const expected = MATRIX_CELL_ROLE_AUTHORITY[matrixCellId];
  if (
    value.osFamily !== expected.osFamily
    || value.runtimeRole !== expected.runtimeRole
    || value.filesystemClass !== expected.filesystemClass
  ) failPublicSourceZipCampaign(phase, "matrix-cell-role");
  requireIdentifier(value.signerRole, phase, "signer-role");
  return frozen(value);
}

function validateClaimRules(value) {
  const phase = "POLICY";
  exactDataObject(value, CLAIM_RULE_KEYS, phase, "claim-rules");
  const crossRuntimePair = requireArray(value.crossRuntimePair, phase, "cross-runtime-pair");
  const crossOsPair = requireArray(value.crossOsPair, phase, "cross-os-pair");
  const levels = requireArray(value.requiredClaimLevels, phase, "required-claim-levels");
  if (
    crossRuntimePair.length !== 2
    || crossRuntimePair[0] !== "LINUX-A"
    || crossRuntimePair[1] !== "LINUX-B"
    || crossOsPair.length !== 2
    || crossOsPair[0] !== "WIN-A"
    || crossOsPair[1] !== "LINUX-A"
    || levels.length !== CLAIM_LEVELS_V2.length
    || levels.some((entry, index) => entry !== CLAIM_LEVELS_V2[index])
    || value.requireL5 !== true
    || value.allowL6 !== false
  ) failPublicSourceZipCampaign(phase, "claim-rules-authority");
  return frozen(value);
}

function validateEnvironmentProfile(value) {
  const phase = "POLICY";
  exactDataObject(value, ENVIRONMENT_PROFILE_KEYS, phase, "environment-profile");
  for (const key of [
    "platformProfileVersion",
    "runtimeFamily",
    "networkPolicy",
    "lineEndingPolicy",
    "filesystemExecutionPolicy",
    "hostIdentifierPolicy",
    "windowsBuildPolicy",
    "linuxBuildPolicy",
  ]) requireIdentifier(value[key], phase, "environment-profile-field");
  if (
    value.architecture !== "x64"
    || value.runtimeFamily !== "node"
    || value.lang !== "C"
    || value.lcAll !== "C"
    || value.timezone !== "UTC"
    || value.sourceDateEpoch !== 0
    || value.networkPolicy !== "disabled-during-generation"
    || value.lineEndingPolicy !== "git-object-b2-bytes"
    || value.filesystemExecutionPolicy !== "native-local"
    || value.hostIdentifierPolicy !== "opaque-cell-id-only"
  ) failPublicSourceZipCampaign(phase, "environment-profile-authority");
  return frozen(value);
}

function validateSignerFingerprints(value, cells) {
  const phase = "POLICY";
  requireArray(value, phase, "signer-fingerprints");
  if (value.length !== cells.length) {
    failPublicSourceZipCampaign(phase, "signer-fingerprint-count");
  }
  const fingerprints = new Set();
  return Object.freeze(value.map((entry, index) => {
    exactDataObject(entry, SIGNER_FINGERPRINT_KEYS, phase, "signer-fingerprint");
    const cell = cells[index];
    if (entry.matrixCellId !== cell.matrixCellId || entry.role !== cell.signerRole) {
      failPublicSourceZipCampaign(phase, "signer-cell-binding");
    }
    requireFingerprint(entry.fingerprint, phase, "signer-fingerprint");
    if (fingerprints.has(entry.fingerprint)) {
      failPublicSourceZipCampaign(phase, "duplicate-signer");
    }
    fingerprints.add(entry.fingerprint);
    return frozen(entry);
  }));
}

export function validateCampaignPolicy(value) {
  const phase = "POLICY";
  exactDataObject(value, CAMPAIGN_POLICY_KEYS, phase, "campaign-policy");
  if (
    value.documentKind !== CAMPAIGN_POLICY_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.campaignSchemaId !== CAMPAIGN_SCHEMA_ID
  ) failPublicSourceZipCampaign(phase, "campaign-policy-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  requireSha256(value.vectorSetSha256, phase, "vector-set-sha256");
  requireArray(value.requiredCells, phase, "required-cells");
  requireArray(value.optionalCells, phase, "optional-cells");
  if (value.requiredCells.length !== REQUIRED_MATRIX_CELL_IDS.length) {
    failPublicSourceZipCampaign(phase, "required-cell-count");
  }
  const requiredCells = value.requiredCells.map((entry, index) => (
    requireCellDefinition(entry, REQUIRED_MATRIX_CELL_IDS[index])
  ));
  if (value.optionalCells.length > 1) {
    failPublicSourceZipCampaign(phase, "optional-cell-count");
  }
  const optionalCells = value.optionalCells.map((entry, index) => (
    requireCellDefinition(entry, OPTIONAL_MATRIX_CELL_IDS[index])
  ));
  validateClaimRules(value.claimRules);
  validateEnvironmentProfile(value.environmentProfile);
  requireArray(value.allowedSignerRoles, phase, "allowed-signer-roles");
  const allCells = [...requiredCells, ...optionalCells];
  const roles = allCells.map((entry) => entry.signerRole);
  if (
    value.allowedSignerRoles.length !== roles.length
    || value.allowedSignerRoles.some((entry, index) => entry !== roles[index])
    || new Set(roles).size !== roles.length
  ) failPublicSourceZipCampaign(phase, "allowed-signer-roles");
  for (const role of roles) requireIdentifier(role, phase, "signer-role");
  validateSignerFingerprints(value.allowedSignerFingerprints, allCells);
  const immutableAuthority = validateImmutablePolicyAuthority(value);
  const nodeAuthority = validateNodePolicyAuthority(
    value,
    allCells,
    immutableAuthority,
  );
  validateGpgPolicyAuthority(
    value,
    allCells,
    immutableAuthority,
    nodeAuthority,
  );
  exactDataObject(
    value.transportPolicy,
    TRANSPORT_POLICY_KEYS,
    phase,
    "transport-policy",
  );
  if (
    value.transportPolicy.signatureRequired !== true
    || value.transportPolicy.ledgerRequired !== true
    || value.transportPolicy.immutableVerificationRequired !== true
    || value.transportPolicy.noAutoKeyRetrieval !== true
    || value.transportPolicy.uniqueSignerPerCell !== true
  ) failPublicSourceZipCampaign(phase, "transport-policy-authority");
  requireCount(value.transportPolicy.maxManifestBytes, phase, "max-manifest-bytes", 4 * 1024 * 1024);
  requireCount(value.transportPolicy.maxSignatureBytes, phase, "max-signature-bytes", 1024 * 1024);
  if (
    value.transportPolicy.maxManifestBytes < 1024
    || value.transportPolicy.maxSignatureBytes < 256
  ) failPublicSourceZipCampaign(phase, "transport-policy-limits");
  exactDataObject(
    value.retentionPolicy,
    RETENTION_POLICY_KEYS,
    phase,
    "retention-policy",
  );
  if (
    value.retentionPolicy.rawCellEvidencePrivate !== true
    || value.retentionPolicy.commitRawCells !== false
    || value.retentionPolicy.closureReviewRequired !== true
  ) failPublicSourceZipCampaign(phase, "retention-policy-authority");
  requireIdentifier(value.retentionPolicy.retentionProfile, phase, "retention-profile");
  return frozen(value);
}

export function encodeCanonicalCampaignPolicy(value) {
  authority(value);
  return canonicalBytes(validateCampaignPolicy(value), "POLICY", "canonical-policy");
}

export function parseCanonicalCampaignPolicyBytes(bytes) {
  return parseCanonical(bytes, validateCampaignPolicy, "POLICY", "campaign-policy");
}

export function campaignPolicySha256(value) {
  authority(value);
  return sha256(encodeCanonicalCampaignPolicy(value));
}

export function validateExternalCampaignPolicyAuthority(options) {
  authority(options, { allowBuffer: true });
  const keys = Object.freeze([
    "expectedCanonicalPolicyBytes",
    "expectedPolicySha256",
    "campaignId",
    "sourceCommit",
    "toolingCommit",
  ]);
  exactDataObject(
    options,
    keys,
    "POLICY",
    "external-policy-authority",
    { allowBuffer: true },
  );
  if (!Buffer.isBuffer(options.expectedCanonicalPolicyBytes)) {
    failPublicSourceZipCampaign("POLICY", "expected-policy-bytes");
  }
  requireSha256(options.expectedPolicySha256, "POLICY", "expected-policy-sha256");
  requireIdentifier(options.campaignId, "POLICY", "expected-campaign-id");
  requireGitObject(options.sourceCommit, "POLICY", "expected-source-commit");
  requireGitObject(options.toolingCommit, "POLICY", "expected-tooling-commit");
  const policy = parseCanonicalCampaignPolicyBytes(
    options.expectedCanonicalPolicyBytes,
  );
  const canonical = encodeCanonicalCampaignPolicy(policy);
  const digest = sha256(canonical);
  if (
    !canonical.equals(options.expectedCanonicalPolicyBytes)
    || digest !== options.expectedPolicySha256
    || policy.campaignId !== options.campaignId
    || policy.sourceCommit !== options.sourceCommit
    || policy.toolingCommit !== options.toolingCommit
  ) failPublicSourceZipCampaign("POLICY", "external-policy-authority-mismatch");
  return Object.freeze({ policy, policySha256: digest });
}

export function findCampaignCell(policyValue, matrixCellId) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireIdentifier(matrixCellId, "POLICY", "matrix-cell-id");
  const cell = [...policy.requiredCells, ...policy.optionalCells].find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  if (!cell) failPublicSourceZipCampaign("POLICY", "unknown-matrix-cell");
  return cell;
}

export function findAllowedSigner(policyValue, matrixCellId) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  const cell = findCampaignCell(policy, matrixCellId);
  const signer = policy.allowedSignerFingerprints.find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  if (!signer || signer.role !== cell.signerRole) {
    failPublicSourceZipCampaign("POLICY", "signer-policy-binding");
  }
  return signer;
}

export function findGpgVerifierExecutionProfile(policyValue, profileId) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireIdentifier(profileId, "POLICY", "profile-id");
  const profile = policy.gpgVerifierProfiles.find(
    (entry) => entry.profileId === profileId,
  );
  if (!profile) failPublicSourceZipCampaign("POLICY", "unknown-gpg-verifier-profile");
  return profile;
}

export function findImmutableInstallationProfile(
  policyValue,
  profileSha256,
) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireSha256(profileSha256, "POLICY", "immutable-profile-sha256");
  const matches = policy.immutableInstallationProfiles.filter(
    (entry) => immutableInstallationProfileSha256(entry) === profileSha256,
  );
  if (matches.length !== 1) {
    failPublicSourceZipCampaign("POLICY", "unknown-or-ambiguous-immutable-profile");
  }
  return matches[0];
}

export function findNodeRuntimeProfile(policyValue, profileId) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireIdentifier(profileId, "POLICY", "node-runtime-profile-id");
  const matches = policy.nodeRuntimeProfiles.filter(
    (entry) => entry.profileId === profileId,
  );
  if (matches.length !== 1) {
    failPublicSourceZipCampaign("POLICY", "unknown-or-ambiguous-node-runtime-profile");
  }
  return matches[0];
}

export function findNodeRuntimeAssignment(policyValue, options) {
  authority(policyValue);
  authority(options);
  const keys = Object.freeze(["campaignRole", "matrixCellId", "hostRole"]);
  exactDataObject(options, keys, "POLICY", "node-assignment-options");
  const policy = validateCampaignPolicy(policyValue);
  if (!NODE_ASSIGNMENT_ROLE_SET.has(options.campaignRole)) {
    failPublicSourceZipCampaign("POLICY", "node-campaign-role");
  }
  if (options.matrixCellId !== null) {
    requireIdentifier(options.matrixCellId, "POLICY", "matrix-cell-id");
  }
  requireIdentifier(options.hostRole, "POLICY", "node-host-role");
  const matches = policy.nodeRuntimeAssignments.filter((entry) => (
    entry.campaignRole === options.campaignRole
    && entry.matrixCellId === options.matrixCellId
    && entry.hostRole === options.hostRole
  ));
  if (matches.length !== 1) {
    failPublicSourceZipCampaign("POLICY", "missing-or-ambiguous-node-assignment");
  }
  const assignment = matches[0];
  const profile = findNodeRuntimeProfile(policy, assignment.profileId);
  const immutableProfile = findImmutableInstallationProfile(
    policy,
    profile.immutableInstallationProfileSha256,
  );
  return Object.freeze({
    assignment,
    assignmentSha256: nodeRuntimeAssignmentSha256(assignment),
    profile,
    profileSha256: nodeRuntimeProfileSha256(profile),
    immutableProfile,
    immutableProfileSha256: immutableInstallationProfileSha256(immutableProfile),
  });
}

export function findGpgVerifierAssignment(policyValue, options) {
  authority(policyValue);
  authority(options);
  const keys = Object.freeze([
    "gpgRole", "operation", "matrixCellId", "comparisonRole", "hostRole",
    "signerRole", "signatureNamespace",
  ]);
  exactDataObject(options, keys, "POLICY", "gpg-assignment-options");
  const policy = validateCampaignPolicy(policyValue);
  if (!GPG_SIGNATURE_OPERATIONS.includes(options.operation)) {
    failPublicSourceZipCampaign("POLICY", "gpg-operation");
  }
  if (!GPG_ROLE_SET.has(options.gpgRole)) {
    failPublicSourceZipCampaign("POLICY", "gpg-role");
  }
  if (
    (options.matrixCellId === null) === (options.comparisonRole === null)
    || (options.matrixCellId !== null
      && typeof options.matrixCellId !== "string")
    || (options.comparisonRole !== null
      && typeof options.comparisonRole !== "string")
  ) failPublicSourceZipCampaign("POLICY", "gpg-assignment-target");
  requireIdentifier(options.hostRole, "POLICY", "gpg-host-role");
  requireIdentifier(options.signerRole, "POLICY", "signer-role");
  validateSignatureNamespace(options.signatureNamespace);
  const matches = policy.gpgVerifierAssignments.filter((entry) => (
    entry.gpgRole === options.gpgRole
    && entry.operation === options.operation
    && entry.matrixCellId === options.matrixCellId
    && entry.comparisonRole === options.comparisonRole
    && entry.hostRole === options.hostRole
    && entry.signerRole === options.signerRole
    && entry.signatureNamespace === options.signatureNamespace
  ));
  if (matches.length !== 1) {
    failPublicSourceZipCampaign("POLICY", "missing-or-ambiguous-gpg-assignment");
  }
  const assignment = matches[0];
  const profile = findGpgVerifierExecutionProfile(policy, assignment.profileId);
  const immutableProfile = findImmutableInstallationProfile(
    policy,
    profile.immutableInstallationProfileSha256,
  );
  return Object.freeze({
    assignment,
    assignmentSha256: gpgVerifierAssignmentSha256(assignment),
    profile,
    profileSha256: gpgVerifierExecutionProfileSha256(profile),
    immutableProfile,
    immutableProfileSha256: immutableInstallationProfileSha256(immutableProfile),
  });
}

export function findCellProducerGpgAuthorities(policyValue, matrixCellId) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  const cell = findCampaignCell(policy, matrixCellId);
  const signer = findAllowedSigner(policy, matrixCellId);
  const signing = findGpgVerifierAssignment(policy, {
    gpgRole: "cell-producer-sign",
    operation: "detached-sign",
    matrixCellId,
    comparisonRole: null,
    hostRole: matrixCellId,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
  const verification = findGpgVerifierAssignment(policy, {
    gpgRole: "cell-producer-local-verify",
    operation: "detached-verify",
    matrixCellId,
    comparisonRole: null,
    hostRole: matrixCellId,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
  if (cell.signerRole !== signer.role) {
    failPublicSourceZipCampaign("POLICY", "cell-gpg-role-binding");
  }
  return Object.freeze({ signing, localVerification: verification });
}

export function findCellImportConsumerGpgAuthority(
  policyValue,
  matrixCellId,
  consumerHostRole,
) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  const signer = findAllowedSigner(policy, matrixCellId);
  return findGpgVerifierAssignment(policy, {
    gpgRole: "cell-import-consumer-verify",
    operation: "detached-verify",
    matrixCellId,
    comparisonRole: null,
    hostRole: consumerHostRole,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
}

export function findComparisonGpgAuthorities(
  policyValue,
  comparisonHostRole,
  signerRole,
) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireIdentifier(signerRole, "POLICY", "comparison-signer-role");
  const signing = findGpgVerifierAssignment(policy, {
    gpgRole: "comparison-result-sign",
    operation: "detached-sign",
    matrixCellId: null,
    comparisonRole: GPG_COMPARISON_ROLE,
    hostRole: comparisonHostRole,
    signerRole,
    signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
  });
  const verification = findGpgVerifierAssignment(policy, {
    gpgRole: "comparison-result-local-verify",
    operation: "detached-verify",
    matrixCellId: null,
    comparisonRole: GPG_COMPARISON_ROLE,
    hostRole: comparisonHostRole,
    signerRole,
    signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
  });
  return Object.freeze({ signing, localVerification: verification });
}

export function findIndependentReviewGpgAuthority(
  policyValue,
  reviewHostRole,
  signerRole,
) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  requireIdentifier(signerRole, "POLICY", "comparison-signer-role");
  return findGpgVerifierAssignment(policy, {
    gpgRole: "independent-result-review-verify",
    operation: "detached-verify",
    matrixCellId: null,
    comparisonRole: "independent-review",
    hostRole: reviewHostRole,
    signerRole,
    signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
  });
}

export function findCellGpgVerifierAuthority(policyValue, matrixCellId) {
  return findCellProducerGpgAuthorities(policyValue, matrixCellId).signing;
}

export function findComparisonGpgVerifierAuthority(policyValue, signerRole) {
  authority(policyValue);
  const policy = validateCampaignPolicy(policyValue);
  const assignment = policy.gpgVerifierAssignments.find(
    (entry) => entry.gpgRole === "comparison-result-sign"
      && entry.signerRole === signerRole,
  );
  if (!assignment) {
    failPublicSourceZipCampaign("POLICY", "missing-comparison-signing-assignment");
  }
  return findComparisonGpgAuthorities(
    policy,
    assignment.hostRole,
    signerRole,
  ).signing;
}

let activeExecutionQualificationTestAdapter = null;

function privateEvidenceSha256(value) {
  return sha256(Buffer.from(JSON.stringify(value), "utf8"));
}

function normalizedIdentityEvidence(state) {
  return Object.freeze({
    device: state.dev.toString(10),
    inode: state.ino.toString(10),
    size: state.size.toString(10),
    links: state.nlink.toString(10),
    mode: state.mode.toString(10),
    modifiedNanoseconds: state.mtimeNs.toString(10),
    changedNanoseconds: state.ctimeNs.toString(10),
  });
}

function replacementRelevantParentPaths(executablePath) {
  const resolved = path.resolve(executablePath);
  const root = path.parse(resolved).root;
  const result = [];
  let current = path.dirname(resolved);
  for (;;) {
    result.push(current);
    if (gpgComparable(current) === gpgComparable(root)) break;
    const parent = path.dirname(current);
    if (gpgComparable(parent) === gpgComparable(current)) {
      failPublicSourceZipCampaign("ENVIRONMENT", "parent-chain-unbounded");
    }
    current = parent;
  }
  return Object.freeze(result);
}

function inspectExecutableInstallation(executablePath, maximumBytes) {
  if (
    typeof executablePath !== "string"
    || !path.isAbsolute(executablePath)
    || !Number.isSafeInteger(maximumBytes)
    || maximumBytes < 1
  ) failPublicSourceZipCampaign("ENVIRONMENT", "executable-measurement-options");
  let descriptor = null;
  try {
    const resolved = path.resolve(executablePath);
    const initial = lstatSync(resolved, { bigint: true });
    const executableReparseOrSymlink = initial.isSymbolicLink();
    if (
      !initial.isFile()
      || executableReparseOrSymlink
      || initial.size < 1n
      || initial.size > BigInt(maximumBytes)
      || gpgComparable(realpathSync.native(resolved)) !== gpgComparable(resolved)
    ) failPublicSourceZipCampaign("ENVIRONMENT", "executable-measurement-identity");
    descriptor = openSync(
      resolved,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const pathAfter = lstatSync(resolved, { bigint: true });
    const beforeIdentity = normalizedIdentityEvidence(before);
    if (
      JSON.stringify(normalizedIdentityEvidence(initial))
        !== JSON.stringify(beforeIdentity)
      || JSON.stringify(beforeIdentity)
        !== JSON.stringify(normalizedIdentityEvidence(after))
      || JSON.stringify(beforeIdentity)
        !== JSON.stringify(normalizedIdentityEvidence(pathAfter))
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign("ENVIRONMENT", "executable-measurement-mutable");
    const parentEvidence = [];
    let parentReparseOrSymlink = false;
    for (const [depth, parentPath] of replacementRelevantParentPaths(resolved).entries()) {
      const state = lstatSync(parentPath, { bigint: true });
      const isLink = state.isSymbolicLink();
      let canonicalPathMatches = false;
      try {
        canonicalPathMatches = gpgComparable(realpathSync.native(parentPath))
          === gpgComparable(parentPath);
      } catch {
        canonicalPathMatches = false;
      }
      parentReparseOrSymlink ||= isLink || !canonicalPathMatches;
      if (!state.isDirectory()) {
        failPublicSourceZipCampaign("ENVIRONMENT", "parent-chain-identity");
      }
      parentEvidence.push(Object.freeze({
        depth,
        ...normalizedIdentityEvidence(state),
        ownerNumber: state.uid.toString(10),
        groupNumber: state.gid.toString(10),
      }));
    }
    return Object.freeze({
      executablePath: resolved,
      executableSha256: sha256(bytes),
      executableByteLength: bytes.length,
      fileState: initial,
      fileIdentitySha256: privateEvidenceSha256(beforeIdentity),
      parentEvidence: Object.freeze(parentEvidence),
      parentChainEvidenceSha256: privateEvidenceSha256(parentEvidence),
      reparseOrSymlink: executableReparseOrSymlink || parentReparseOrSymlink,
    });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("ENVIRONMENT", "executable-measurement-failed");
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch {
        failPublicSourceZipCampaign("ENVIRONMENT", "executable-measurement-close");
      }
    }
  }
}

function testQualificationFacts(context) {
  const adapter = activeExecutionQualificationTestAdapter;
  if (adapter === null) return null;
  const descriptor = Object.getOwnPropertyDescriptor(
    adapter,
    EXECUTION_QUALIFICATION_TEST_ADAPTER,
  );
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    failPublicSourceZipCampaign("ENVIRONMENT", "qualification-adapter-authority");
  }
  const implementation = descriptor.value;
  authority(implementation, { allowFunctions: true });
  if (
    !implementation
    || typeof implementation !== "object"
    || Array.isArray(implementation)
    || Object.getPrototypeOf(implementation) !== Object.prototype
    || Reflect.ownKeys(implementation).length !== 2
    || Reflect.ownKeys(implementation)[0] !== "qualificationFacts"
    || Reflect.ownKeys(implementation)[1] !== "nodeProcessFacts"
    || typeof implementation.qualificationFacts !== "function"
    || typeof implementation.nodeProcessFacts !== "function"
  ) failPublicSourceZipCampaign("ENVIRONMENT", "qualification-adapter-shape");
  const facts = implementation.qualificationFacts(frozen(context));
  authority(facts);
  return facts;
}

function productionQualificationFacts(profile, snapshot) {
  const common = {
    linkCount: Number(snapshot.fileState.nlink),
    reparseOrSymlink: snapshot.reparseOrSymlink,
  };
  if (
    profile.qualificationMode === "synthetic-test-only-v1"
    || profile.osFamily === "windows"
  ) {
    const blocked = {
      ...common,
      campaignPrincipalWritable: true,
      campaignPrincipalDeleteOrRenameCapable: true,
      campaignPrincipalAclChangeCapable: true,
      campaignPrincipalOwnershipTakeoverCapable: true,
    };
    return Object.freeze({
      ...blocked,
      accessControlEvidenceSha256: privateEvidenceSha256({
        qualifiedAclProbeAvailable: false,
        ...blocked,
      }),
      filesystemEvidenceSha256: privateEvidenceSha256({
        filesystemQualified: false,
        qualificationMode: profile.qualificationMode,
      }),
    });
  }
  if (profile.osFamily !== "linux" || process.platform !== "linux") {
    return Object.freeze({
      ...common,
      campaignPrincipalWritable: true,
      campaignPrincipalDeleteOrRenameCapable: true,
      campaignPrincipalAclChangeCapable: true,
      campaignPrincipalOwnershipTakeoverCapable: true,
      accessControlEvidenceSha256: privateEvidenceSha256({ hostMismatch: true }),
      filesystemEvidenceSha256: privateEvidenceSha256({ hostMismatch: true }),
    });
  }
  const effectiveUser = process.geteuid?.();
  const effectiveGroup = process.getegid?.();
  const effectiveGroups = new Set(process.getgroups?.() ?? []);
  if (!Number.isInteger(effectiveUser) || !Number.isInteger(effectiveGroup)) {
    failPublicSourceZipCampaign("ENVIRONMENT", "linux-principal-unavailable");
  }
  effectiveGroups.add(effectiveGroup);
  const modeAllowsWrite = (state) => effectiveUser === 0
    || (effectiveUser === Number(state.uid) && (Number(state.mode) & 0o200) !== 0)
    || (effectiveGroups.has(Number(state.gid)) && (Number(state.mode) & 0o020) !== 0)
    || (Number(state.mode) & 0o002) !== 0;
  const directoryAllowsReplacement = (entry) => {
    const mode = Number(entry.mode);
    const owner = Number(entry.ownerNumber);
    const group = Number(entry.groupNumber);
    return effectiveUser === 0
      || (effectiveUser === owner && (mode & 0o300) === 0o300)
      || (effectiveGroups.has(group) && (mode & 0o030) === 0o030)
      || (mode & 0o003) === 0o003;
  };
  const ownerControlled = snapshot.fileState.uid === 0n
    && snapshot.parentEvidence.every((entry) => entry.ownerNumber === "0");
  const campaignPrincipalWritable = modeAllowsWrite(snapshot.fileState);
  const campaignPrincipalDeleteOrRenameCapable = snapshot.parentEvidence.some(
    directoryAllowsReplacement,
  );
  const campaignPrincipalAclChangeCapable = effectiveUser === 0
    || effectiveUser === Number(snapshot.fileState.uid)
    || snapshot.parentEvidence.some(
      (entry) => effectiveUser === Number(entry.ownerNumber),
    );
  const campaignPrincipalOwnershipTakeoverCapable = effectiveUser === 0;
  let filesystemType = null;
  let filesystemQualified = false;
  try {
    const filesystem = statfsSync(snapshot.executablePath, { bigint: true });
    filesystemType = filesystem.type.toString(16);
    filesystemQualified = new Set([
      "ef53", "58465342", "73717368", "9123683e",
    ]).has(filesystemType.toLowerCase());
  } catch {
    filesystemType = "unavailable";
  }
  const accessEvidence = {
    ownerControlled,
    campaignPrincipalWritable,
    campaignPrincipalDeleteOrRenameCapable,
    campaignPrincipalAclChangeCapable,
    campaignPrincipalOwnershipTakeoverCapable,
    effectiveGroupCount: effectiveGroups.size,
  };
  return Object.freeze({
    ...common,
    campaignPrincipalWritable:
      campaignPrincipalWritable || !ownerControlled || !filesystemQualified,
    campaignPrincipalDeleteOrRenameCapable:
      campaignPrincipalDeleteOrRenameCapable || !ownerControlled || !filesystemQualified,
    campaignPrincipalAclChangeCapable:
      campaignPrincipalAclChangeCapable || !ownerControlled || !filesystemQualified,
    campaignPrincipalOwnershipTakeoverCapable:
      campaignPrincipalOwnershipTakeoverCapable || !ownerControlled || !filesystemQualified,
    accessControlEvidenceSha256: privateEvidenceSha256(accessEvidence),
    filesystemEvidenceSha256: privateEvidenceSha256({
      filesystemType,
      filesystemQualified,
      stableDeviceIdentity: snapshot.fileState.dev >= 0n,
    }),
  });
}

function exactQualificationFacts(value) {
  const keys = Object.freeze([
    "linkCount",
    "reparseOrSymlink",
    "campaignPrincipalWritable",
    "campaignPrincipalDeleteOrRenameCapable",
    "campaignPrincipalAclChangeCapable",
    "campaignPrincipalOwnershipTakeoverCapable",
    "accessControlEvidenceSha256",
    "filesystemEvidenceSha256",
  ]);
  exactDataObject(value, keys, "ENVIRONMENT", "qualification-facts");
  requireCount(value.linkCount, "ENVIRONMENT", "qualification-link-count", 1024);
  for (const key of keys.slice(1, 6)) {
    requireBoolean(value[key], "ENVIRONMENT", "qualification-fact-boolean");
  }
  requireSha256(
    value.accessControlEvidenceSha256,
    "ENVIRONMENT",
    "qualification-access-evidence",
  );
  requireSha256(
    value.filesystemEvidenceSha256,
    "ENVIRONMENT",
    "qualification-filesystem-evidence",
  );
  return frozen(value);
}

export function measureExecutableInstallationQualification(options) {
  authority(options);
  const keys = Object.freeze([
    "executablePath", "immutableInstallationProfile", "phase", "purpose",
  ]);
  exactDataObject(options, keys, "ENVIRONMENT", "qualification-options");
  requireIdentifier(options.phase, "ENVIRONMENT", "qualification-phase");
  requireIdentifier(options.purpose, "ENVIRONMENT", "qualification-purpose");
  const profile = validateImmutableInstallationProfile(
    options.immutableInstallationProfile,
  );
  const snapshot = inspectExecutableInstallation(
    options.executablePath,
    profile.executableByteLength,
  );
  const adapterFacts = testQualificationFacts({
    purpose: options.purpose,
    phase: options.phase,
    profileId: profile.profileId,
    profileSha256: immutableInstallationProfileSha256(profile),
    osFamily: profile.osFamily,
    architecture: profile.architecture,
    executableSha256: snapshot.executableSha256,
    executableByteLength: snapshot.executableByteLength,
    fileIdentitySha256: snapshot.fileIdentitySha256,
    parentChainEvidenceSha256: snapshot.parentChainEvidenceSha256,
    linkCount: Number(snapshot.fileState.nlink),
    reparseOrSymlink: snapshot.reparseOrSymlink,
  });
  const facts = exactQualificationFacts(
    adapterFacts ?? productionQualificationFacts(profile, snapshot),
  );
  const mechanicallyQualified = facts.linkCount === 1
    && facts.reparseOrSymlink === false
    && facts.campaignPrincipalWritable === false
    && facts.campaignPrincipalDeleteOrRenameCapable === false
    && facts.campaignPrincipalAclChangeCapable === false
    && facts.campaignPrincipalOwnershipTakeoverCapable === false;
  const result = validateMeasuredQualificationResult({
    documentKind: MEASURED_QUALIFICATION_RESULT_DOCUMENT_KIND,
    schemaVersion: 1,
    profileId: profile.profileId,
    profileSha256: immutableInstallationProfileSha256(profile),
    status: mechanicallyQualified ? "qualified" : "blocked",
    phase: options.phase,
    reason: mechanicallyQualified
      ? "immutable-installation-qualified"
      : "immutable-installation-not-proven",
    osFamily: profile.osFamily,
    architecture: profile.architecture,
    executableSha256: snapshot.executableSha256,
    executableByteLength: snapshot.executableByteLength,
    fileIdentitySha256: snapshot.fileIdentitySha256,
    parentChainEvidenceSha256: snapshot.parentChainEvidenceSha256,
    accessControlEvidenceSha256: facts.accessControlEvidenceSha256,
    filesystemEvidenceSha256: facts.filesystemEvidenceSha256,
    linkCount: facts.linkCount,
    reparseOrSymlink: facts.reparseOrSymlink,
    campaignPrincipalWritable: facts.campaignPrincipalWritable,
    campaignPrincipalDeleteOrRenameCapable:
      facts.campaignPrincipalDeleteOrRenameCapable,
    campaignPrincipalAclChangeCapable: facts.campaignPrincipalAclChangeCapable,
    campaignPrincipalOwnershipTakeoverCapable:
      facts.campaignPrincipalOwnershipTakeoverCapable,
  });
  return Object.freeze({
    result,
    resultSha256: measuredQualificationResultSha256(result),
  });
}

function requireQualifiedExecutableInstallation(options) {
  const measured = measureExecutableInstallationQualification(options);
  const profile = validateImmutableInstallationProfile(
    options.immutableInstallationProfile,
  );
  if (
    measured.result.status !== "qualified"
    || measured.result.profileSha256 !== immutableInstallationProfileSha256(profile)
    || measured.result.executableSha256 !== profile.executableSha256
    || measured.result.executableByteLength !== profile.executableByteLength
    || measured.result.osFamily !== profile.osFamily
    || measured.result.architecture !== profile.architecture
  ) failPublicSourceZipCampaign("ENVIRONMENT", "immutable-installation-not-proven");
  return measured;
}

function actualNodeProcessFacts(profile) {
  const adapter = activeExecutionQualificationTestAdapter;
  if (adapter !== null) {
    const implementation = Object.getOwnPropertyDescriptor(
      adapter,
      EXECUTION_QUALIFICATION_TEST_ADAPTER,
    )?.value;
    const facts = implementation.nodeProcessFacts(frozen({
      profileId: profile.profileId,
      expectedOsFamily: profile.osFamily,
      expectedArchitecture: profile.architecture,
      expectedRuntimeVersion: profile.runtimeVersion,
      expectedV8Version: profile.v8Version,
      expectedModulesAbi: profile.modulesAbi,
      actualOsFamily: actualGpgOsFamily(),
      actualArchitecture: process.arch,
      actualRuntimeVersion: process.version,
      actualV8Version: process.versions.v8,
      actualModulesAbi: process.versions.modules,
    }));
    authority(facts);
    const keys = Object.freeze([
      "osFamily", "architecture", "runtimeVersion", "v8Version", "modulesAbi",
    ]);
    exactDataObject(facts, keys, "RUNTIME_IDENTITY", "node-process-facts");
    return frozen(facts);
  }
  return frozen({
    osFamily: actualGpgOsFamily(),
    architecture: process.arch,
    runtimeVersion: process.version,
    v8Version: process.versions.v8,
    modulesAbi: process.versions.modules,
  });
}

export function measureCurrentNodeProcessAuthority(options) {
  authority(options);
  const keys = Object.freeze([
    "campaignPolicy", "campaignRole", "matrixCellId", "hostRole",
  ]);
  exactDataObject(options, keys, "RUNTIME_IDENTITY", "node-measurement-options");
  const policy = validateCampaignPolicy(options.campaignPolicy);
  const selected = findNodeRuntimeAssignment(policy, {
    campaignRole: options.campaignRole,
    matrixCellId: options.matrixCellId,
    hostRole: options.hostRole,
  });
  const qualification = requireQualifiedExecutableInstallation({
    executablePath: process.execPath,
    immutableInstallationProfile: selected.immutableProfile,
    phase: "node-campaign-execution",
    purpose: options.campaignRole,
  });
  const actual = actualNodeProcessFacts(selected.profile);
  const profile = selected.profile;
  if (
    qualification.result.executableSha256 !== profile.executableSha256
    || qualification.result.executableByteLength !== profile.executableByteLength
    || actual.osFamily !== profile.osFamily
    || actual.architecture !== profile.architecture
    || actual.runtimeVersion !== profile.runtimeVersion
    || actual.v8Version !== profile.v8Version
    || actual.modulesAbi !== profile.modulesAbi
  ) failPublicSourceZipCampaign("RUNTIME_IDENTITY", "node-process-profile-mismatch");
  const runtimeIdentity = validateRuntimeIdentityBinding({
    documentKind: "ieltmps-node-runtime-identity",
    schemaVersion: 1,
    runtimeProfileId: profile.profileId,
    implementation: "node",
    executableSha256: qualification.result.executableSha256,
    executableByteLength: qualification.result.executableByteLength,
    nodeVersion: actual.runtimeVersion,
    v8Version: actual.v8Version,
    modulesVersion: actual.modulesAbi,
    distributionProfileId: profile.distributionProfile,
  });
  return Object.freeze({
    campaignRole: options.campaignRole,
    matrixCellId: options.matrixCellId,
    hostRole: options.hostRole,
    assignmentId: selected.assignment.assignmentId,
    assignmentSha256: selected.assignmentSha256,
    profileId: profile.profileId,
    profileSha256: selected.profileSha256,
    immutableInstallationProfileSha256: selected.immutableProfileSha256,
    qualificationResult: qualification.result,
    qualificationResultSha256: qualification.resultSha256,
    runtimeIdentity,
    runtimeIdentitySha256: sha256(encodeCanonicalRuntimeIdentityBinding(runtimeIdentity)),
  });
}

export function recheckCurrentNodeProcessAuthority(options) {
  authority(options);
  const keys = Object.freeze([
    "campaignPolicy", "campaignRole", "matrixCellId", "hostRole",
    "expectedRuntimeIdentitySha256", "expectedQualificationResultSha256",
  ]);
  exactDataObject(options, keys, "RUNTIME_IDENTITY", "node-recheck-options");
  requireSha256(
    options.expectedRuntimeIdentitySha256,
    "RUNTIME_IDENTITY",
    "expected-runtime-identity-sha256",
  );
  requireSha256(
    options.expectedQualificationResultSha256,
    "RUNTIME_IDENTITY",
    "expected-qualification-result-sha256",
  );
  const current = measureCurrentNodeProcessAuthority({
    campaignPolicy: options.campaignPolicy,
    campaignRole: options.campaignRole,
    matrixCellId: options.matrixCellId,
    hostRole: options.hostRole,
  });
  if (
    current.runtimeIdentitySha256 !== options.expectedRuntimeIdentitySha256
    || current.qualificationResultSha256
      !== options.expectedQualificationResultSha256
  ) failPublicSourceZipCampaign("ENVIRONMENT", "node-authority-changed");
  return current;
}

const GPG_FATAL_SIGNATURE_STATUS = new Set([
  "BADSIG",
  "ERRSIG",
  "NO_PUBKEY",
  "EXPSIG",
  "EXPKEYSIG",
  "REVKEYSIG",
  "KEYEXPIRED",
  "SIGEXPIRED",
  "BADARMOR",
  "NODATA",
  "FAILURE",
  "ERROR",
]);
const GPG_ALLOWED_SIGNATURE_STATUS = new Set([
  "NEWSIG",
  "KEY_CONSIDERED",
  "SIG_ID",
  "GOODSIG",
  "VALIDSIG",
  "TRUST_UNDEFINED",
  "TRUST_NEVER",
  "TRUST_MARGINAL",
  "TRUST_FULLY",
  "TRUST_ULTIMATE",
]);
const GPG_ALLOWED_SIGNING_STATUS = new Set([
  "KEY_CONSIDERED", "BEGIN_SIGNING", "SIG_CREATED",
]);

function decodeBoundedGpgOutput(bytes, reason) {
  if (!Buffer.isBuffer(bytes) || bytes.includes(0)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", reason);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    failPublicSourceZipCampaign("GPG_EXECUTION", reason);
  }
}

export function parseOpenPgpStatusOutput(stdout) {
  authority(stdout);
  if (
    typeof stdout !== "string"
    || Buffer.byteLength(stdout, "utf8") > GPG_STDOUT_BOUND_BYTES
    || stdout.includes("\0")
  ) failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
  let newsigCount = 0;
  let goodKeyId = null;
  let valid = null;
  for (const line of stdout.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    if (!line.startsWith("[GNUPG:] ")) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-status-noise");
    }
    const body = line.slice(9);
    if (body.length === 0 || body.includes("  ")) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
    }
    const tokens = body.split(" ");
    const keyword = tokens[0];
    if (GPG_FATAL_SIGNATURE_STATUS.has(keyword)) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
    }
    if (!GPG_ALLOWED_SIGNATURE_STATUS.has(keyword)) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-status-unexpected");
    }
    if (keyword === "NEWSIG") {
      newsigCount += 1;
      if (newsigCount > 1) {
        failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
      }
      continue;
    }
    if (keyword === "GOODSIG") {
      if (goodKeyId !== null || !/^[0-9A-F]{16}$/u.test(tokens[1] ?? "")) {
        failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
      }
      goodKeyId = tokens[1];
      continue;
    }
    if (keyword === "VALIDSIG") {
      if (valid !== null || ![10, 11].includes(tokens.length)) {
        failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
      }
      const signingFingerprint = tokens[1];
      const primaryFingerprint = tokens.length === 11
        ? tokens[10]
        : signingFingerprint;
      if (
        !FINGERPRINT_PATTERN.test(signingFingerprint ?? "")
        || !FINGERPRINT_PATTERN.test(primaryFingerprint ?? "")
        || !/^[0-9A-Fa-f]{2}$/u.test(tokens[9] ?? "")
      ) failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
      valid = Object.freeze({ signingFingerprint, primaryFingerprint });
    }
  }
  if (
    goodKeyId === null
    || valid === null
    || !valid.signingFingerprint.endsWith(goodKeyId)
  ) failPublicSourceZipCampaign("SIGNATURE", "gpg-status-invalid");
  return valid;
}

function parseOpenPgpSigningStatusOutput(stdout) {
  if (
    typeof stdout !== "string"
    || Buffer.byteLength(stdout, "utf8") > GPG_STDOUT_BOUND_BYTES
    || stdout.includes("\0")
  ) failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-invalid");
  let createdFingerprint = null;
  for (const line of stdout.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    if (!line.startsWith("[GNUPG:] ")) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-noise");
    }
    const body = line.slice(9);
    if (body.length === 0 || body.includes("  ")) {
      failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-invalid");
    }
    const tokens = body.split(" ");
    const keyword = tokens[0];
    if (
      GPG_FATAL_SIGNATURE_STATUS.has(keyword)
      || !GPG_ALLOWED_SIGNING_STATUS.has(keyword)
    ) failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-invalid");
    if (keyword === "SIG_CREATED") {
      const fingerprint = tokens.at(-1);
      if (
        createdFingerprint !== null
        || tokens.length < 7
        || !FINGERPRINT_PATTERN.test(fingerprint ?? "")
      ) failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-invalid");
      createdFingerprint = fingerprint;
    }
  }
  if (createdFingerprint === null) {
    failPublicSourceZipCampaign("SIGNATURE", "gpg-signing-status-invalid");
  }
  return createdFingerprint;
}

function gpgComparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function gpgFileIdentity(state) {
  return Object.freeze({
    dev: state.dev,
    ino: state.ino,
    size: state.size,
    nlink: state.nlink,
    mode: state.mode,
    mtimeNs: state.mtimeNs,
    ctimeNs: state.ctimeNs,
  });
}

function gpgDirectoryIdentity(state, bindDirectoryMutation) {
  const identity = {
    dev: state.dev,
    ino: state.ino,
    mode: state.mode,
  };
  if (bindDirectoryMutation) {
    identity.nlink = state.nlink;
    identity.mtimeNs = state.mtimeNs;
    identity.ctimeNs = state.ctimeNs;
  }
  return Object.freeze(identity);
}

function sameGpgIdentity(left, right) {
  const leftKeys = Reflect.ownKeys(left);
  const rightKeys = Reflect.ownKeys(right);
  return leftKeys.length === rightKeys.length
    && leftKeys.every((key) => left[key] === right[key]);
}

function inspectGpgDirectory(
  directoryPath,
  reason,
  bindDirectoryMutation = false,
) {
  if (typeof directoryPath !== "string" || !path.isAbsolute(directoryPath)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", reason);
  }
  try {
    const state = lstatSync(directoryPath, { bigint: true });
    if (
      !state.isDirectory()
      || state.isSymbolicLink()
      || gpgComparable(realpathSync.native(directoryPath))
        !== gpgComparable(directoryPath)
    ) failPublicSourceZipCampaign("GPG_EXECUTION", reason);
    return gpgDirectoryIdentity(state, bindDirectoryMutation);
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("GPG_EXECUTION", reason);
  }
}

function inspectGpgExecutable(executablePath, profile) {
  if (typeof executablePath !== "string" || !path.isAbsolute(executablePath)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-absolute");
  }
  let descriptor = null;
  try {
    const parentPath = path.dirname(executablePath);
    const parentIdentity = inspectGpgDirectory(
      parentPath,
      "gpg-executable-parent-identity",
      true,
    );
    const initial = lstatSync(executablePath, { bigint: true });
    if (
      !initial.isFile()
      || initial.isSymbolicLink()
      || initial.nlink !== 1n
      || initial.size < 1n
      || initial.size > BigInt(GPG_EXECUTABLE_MAXIMUM_BYTES)
      || gpgComparable(realpathSync.native(executablePath))
        !== gpgComparable(executablePath)
    ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-identity");
    descriptor = openSync(
      executablePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = gpgFileIdentity(fstatSync(descriptor, { bigint: true }));
    const bytes = readFileSync(descriptor);
    const after = gpgFileIdentity(fstatSync(descriptor, { bigint: true }));
    const pathAfter = gpgFileIdentity(lstatSync(executablePath, { bigint: true }));
    if (
      !sameGpgIdentity(gpgFileIdentity(initial), before)
      || !sameGpgIdentity(before, after)
      || !sameGpgIdentity(after, pathAfter)
      || !sameGpgIdentity(
        parentIdentity,
        inspectGpgDirectory(
          parentPath,
          "gpg-executable-parent-identity",
          true,
        ),
      )
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-mutable");
    const executableSha256 = sha256(bytes);
    if (
      executableSha256 !== profile.executableSha256
      || bytes.length !== profile.executableByteLength
    ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-profile-mismatch");
    return Object.freeze({
      identity: before,
      parentIdentity,
      executableSha256,
      executableByteLength: bytes.length,
    });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-identity");
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch {
        failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-close");
      }
    }
  }
}

function sameGpgExecutableSnapshot(left, right) {
  return left.executableSha256 === right.executableSha256
    && left.executableByteLength === right.executableByteLength
    && sameGpgIdentity(left.identity, right.identity)
    && sameGpgIdentity(left.parentIdentity, right.parentIdentity);
}

function inspectGpgInputFile(filePath, maximumBytes, reason) {
  let descriptor = null;
  try {
    if (typeof filePath !== "string" || !path.isAbsolute(filePath)) {
      failPublicSourceZipCampaign("SIGNATURE", reason);
    }
    const initial = lstatSync(filePath, { bigint: true });
    if (
      !initial.isFile()
      || initial.isSymbolicLink()
      || initial.nlink !== 1n
      || initial.size < 1n
      || initial.size > BigInt(maximumBytes)
      || gpgComparable(realpathSync.native(filePath)) !== gpgComparable(filePath)
    ) failPublicSourceZipCampaign("SIGNATURE", reason);
    descriptor = openSync(
      filePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = gpgFileIdentity(fstatSync(descriptor, { bigint: true }));
    const bytes = readFileSync(descriptor);
    const after = gpgFileIdentity(fstatSync(descriptor, { bigint: true }));
    if (
      !sameGpgIdentity(gpgFileIdentity(initial), before)
      || !sameGpgIdentity(before, after)
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign("SIGNATURE", reason);
    return Object.freeze({ identity: before, bytes });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("SIGNATURE", reason);
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch {
        failPublicSourceZipCampaign("SIGNATURE", reason);
      }
    }
  }
}

function requireUnchangedGpgInput(filePath, expected, maximumBytes, reason) {
  const current = inspectGpgInputFile(filePath, maximumBytes, reason);
  if (
    !sameGpgIdentity(expected.identity, current.identity)
    || !expected.bytes.equals(current.bytes)
  ) failPublicSourceZipCampaign("SIGNATURE", "gpg-input-mutable");
}

function actualGpgOsFamily() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return "linux";
  failPublicSourceZipCampaign("GPG_EXECUTION", "unsupported-os-family");
}

function requireGpgProfileHost(profile) {
  const syntheticHost = activeExecutionQualificationTestAdapter !== null;
  if (
    (!syntheticHost && profile.osFamily !== actualGpgOsFamily())
    || (!syntheticHost && profile.architecture !== process.arch)
  ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-profile-host-mismatch");
  if (profile.invocationProfileSha256 !== gpgInvocationProfileSha256()) {
    failPublicSourceZipCampaign("GPG_PROFILE", "invocation-profile-binding");
  }
}

function sanitizedGpgEnvironment(gpgHome) {
  const environment = {};
  const removed = new Set([
    "GNUPGHOME", "GPG_AGENT_INFO", "GPG_TTY",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  ]);
  for (const [key, value] of Object.entries(process.env)) {
    if (!removed.has(key.toUpperCase())) environment[key] = value;
  }
  environment.GNUPGHOME = gpgHome;
  environment.LANG = "C";
  environment.LC_ALL = "C";
  environment.TZ = "UTC";
  return environment;
}

async function invokeGpgTestAdapter(testAdapter, checkpoint) {
  if (testAdapter === null || testAdapter.checkpoint === undefined) return;
  const pending = testAdapter.checkpoint(Object.freeze({ checkpoint }));
  authority(pending, { allowPromise: true });
  const returned = await pending;
  authority(returned);
  if (returned !== undefined) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "test-adapter-return-value");
  }
}

async function waitForGpgChild(child, state) {
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (value) => {
      if (resolved) return;
      resolved = true;
      resolve(value);
    };
    child.once("error", (error) => finish(Object.freeze({ error })));
    child.once("close", (code, signal) => finish(Object.freeze({ code, signal })));
    const timeout = setTimeout(() => {
      state.timedOut = true;
      child.kill();
    }, GPG_TIMEOUT_MILLISECONDS);
    timeout.unref?.();
    child.once("close", () => clearTimeout(timeout));
    child.once("error", () => clearTimeout(timeout));
  });
}

async function runSealedGpgProcess({
  executablePath,
  argumentsList,
  gpgHome,
  profile,
  expectedExecutable,
  testAdapter,
  checkpointPrefix,
}) {
  await invokeGpgTestAdapter(testAdapter, checkpointPrefix + "-before-spawn");
  const beforeSpawn = inspectGpgExecutable(executablePath, profile);
  if (!sameGpgExecutableSnapshot(expectedExecutable, beforeSpawn)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-replaced");
  }
  const child = spawn(executablePath, argumentsList, {
    env: sanitizedGpgEnvironment(gpgHome),
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdoutChunks = [];
  const stderrChunks = [];
  const state = { timedOut: false, outputExceeded: false };
  let stdoutLength = 0;
  let stderrLength = 0;
  child.stdout.on("data", (chunk) => {
    stdoutLength += chunk.length;
    if (stdoutLength > GPG_STDOUT_BOUND_BYTES) {
      state.outputExceeded = true;
      child.kill();
      return;
    }
    stdoutChunks.push(chunk);
  });
  child.stderr.on("data", (chunk) => {
    stderrLength += chunk.length;
    if (stderrLength > GPG_STDERR_BOUND_BYTES) {
      state.outputExceeded = true;
      child.kill();
      return;
    }
    stderrChunks.push(chunk);
  });
  const outcomePromise = waitForGpgChild(child, state);
  try {
    if (
      typeof child.pid !== "number"
      || child.pid <= 0
      || gpgComparable(child.spawnfile) !== gpgComparable(executablePath)
      || argumentsList.some(
        (entry, index) => child.spawnargs[index + 1] !== entry,
      )
    ) failPublicSourceZipCampaign("GPG_EXECUTION", "spawned-process-authority");
    await invokeGpgTestAdapter(testAdapter, checkpointPrefix + "-after-spawn");
    const immediatelyAfterSpawn = inspectGpgExecutable(executablePath, profile);
    if (!sameGpgExecutableSnapshot(expectedExecutable, immediatelyAfterSpawn)) {
      failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-replaced");
    }
  } catch (error) {
    child.kill();
    await outcomePromise;
    throw error;
  }
  const outcome = await outcomePromise;
  await invokeGpgTestAdapter(
    testAdapter,
    checkpointPrefix + "-after-exit-before-recheck",
  );
  const afterExit = inspectGpgExecutable(executablePath, profile);
  if (!sameGpgExecutableSnapshot(expectedExecutable, afterExit)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-replaced");
  }
  if (
    Object.hasOwn(outcome, "error")
    || state.timedOut
    || state.outputExceeded
    || outcome.signal !== null
    || outcome.code !== 0
  ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-process-failure");
  return Object.freeze({
    stdout: Buffer.concat(stdoutChunks, stdoutLength),
    stderr: Buffer.concat(stderrChunks, stderrLength),
  });
}

function normalizedGpgVersion(stdoutBytes) {
  const stdout = decodeBoundedGpgOutput(stdoutBytes, "gpg-version-output");
  const lines = stdout.split(/\r?\n/u);
  const match = /^gpg \(GnuPG\) ([0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9]+)*)$/u
    .exec(lines[0] ?? "");
  if (!match || lines.length < 2) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-version-output");
  }
  return match[1];
}

function gpgAuthorityForOperation(policy, options) {
  return findGpgVerifierAssignment(policy, {
    gpgRole: options.gpgRole,
    operation: options.operation,
    matrixCellId: options.matrixCellId,
    comparisonRole: options.comparisonRole,
    hostRole: options.hostRole,
    signerRole: options.signerRole,
    signatureNamespace: options.signatureNamespace,
  });
}

export function validateProfiledGpgExecutionContext(options) {
  authority(options);
  const keys = Object.freeze([
    "gpgRole", "operation", "executablePath", "gpgHome", "campaignPolicy",
    "expectedPolicySha256", "matrixCellId", "comparisonRole", "hostRole",
    "signerRole", "signatureNamespace",
  ]);
  exactDataObject(options, keys, "GPG_EXECUTION", "gpg-context-options");
  const policy = validateCampaignPolicy(options.campaignPolicy);
  if (campaignPolicySha256(policy) !== options.expectedPolicySha256) {
    failPublicSourceZipCampaign("POLICY", "gpg-external-policy-binding");
  }
  const selected = gpgAuthorityForOperation(policy, options);
  requireGpgProfileHost(selected.profile);
  inspectGpgDirectory(options.gpgHome, "gpg-home-identity");
  inspectGpgExecutable(options.executablePath, selected.profile);
  const qualification = requireQualifiedExecutableInstallation({
    executablePath: options.executablePath,
    immutableInstallationProfile: selected.immutableProfile,
    phase: "gpg-campaign-execution",
    purpose: options.gpgRole,
  });
  return frozen({
    gpgRole: options.gpgRole,
    hostRole: options.hostRole,
    signerRole: options.signerRole,
    signatureNamespace: options.signatureNamespace,
    assignmentSha256: selected.assignmentSha256,
    profileId: selected.profile.profileId,
    profileSha256: selected.profileSha256,
    immutableInstallationProfileSha256: selected.immutableProfileSha256,
    qualificationResult: qualification.result,
    qualificationResultSha256: qualification.resultSha256,
  });
}

export async function runProfiledGpgOperation(options) {
  const authorityOptions = Object.freeze({
    allowedSymbols: Object.freeze([GPG_PROCESS_TEST_ADAPTER]),
    allowFunctions: true,
  });
  authority(options, authorityOptions);
  const keys = Object.freeze([
    "gpgRole",
    "operation",
    "executablePath",
    "gpgHome",
    "campaignPolicy",
    "expectedPolicySha256",
    "matrixCellId",
    "comparisonRole",
    "hostRole",
    "signerRole",
    "signatureNamespace",
    "signingFingerprint",
    "signatureFile",
    "signedFile",
    "allowedPrimaryFingerprints",
  ]);
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype
  ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-operation-options-object");
  const actualKeys = Reflect.ownKeys(options).filter(
    (key) => key !== GPG_PROCESS_TEST_ADAPTER,
  );
  if (
    actualKeys.length !== keys.length
    || actualKeys.some((key, index) => key !== keys[index])
  ) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-operation-options-keys");
  const policy = validateCampaignPolicy(options.campaignPolicy);
  if (campaignPolicySha256(policy) !== options.expectedPolicySha256) {
    failPublicSourceZipCampaign("POLICY", "gpg-external-policy-binding");
  }
  if (!GPG_SIGNATURE_OPERATIONS.includes(options.operation)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-operation");
  }
  const selected = gpgAuthorityForOperation(policy, options);
  const profile = selected.profile;
  requireGpgProfileHost(profile);
  const gpgHomeIdentity = inspectGpgDirectory(
    options.gpgHome,
    "gpg-home-identity",
  );
  const initialExecutable = inspectGpgExecutable(options.executablePath, profile);
  const initialQualification = requireQualifiedExecutableInstallation({
    executablePath: options.executablePath,
    immutableInstallationProfile: selected.immutableProfile,
    phase: "gpg-campaign-execution",
    purpose: options.gpgRole,
  });
  const expectedSigner = options.matrixCellId === null
    ? policy.allowedSignerFingerprints.find(
      (entry) => entry.role === options.signerRole,
    )
    : findAllowedSigner(policy, options.matrixCellId);
  if (!expectedSigner) {
    failPublicSourceZipCampaign("POLICY", "gpg-signer-assignment");
  }
  if (
    typeof options.signatureFile !== "string"
    || !path.isAbsolute(options.signatureFile)
    || typeof options.signedFile !== "string"
    || !path.isAbsolute(options.signedFile)
  ) failPublicSourceZipCampaign("SIGNATURE", "gpg-data-path");
  let signingFingerprint = null;
  let allowedPrimaryFingerprints = null;
  if (options.operation === "detached-sign") {
    if (
      options.signingFingerprint !== expectedSigner.fingerprint
      || options.allowedPrimaryFingerprints !== null
    ) failPublicSourceZipCampaign("POLICY", "gpg-signing-authority");
    signingFingerprint = options.signingFingerprint;
  } else {
    if (
      options.signingFingerprint !== null
      || !Array.isArray(options.allowedPrimaryFingerprints)
      || Object.getPrototypeOf(options.allowedPrimaryFingerprints) !== Array.prototype
      || options.allowedPrimaryFingerprints.length !== 1
      || options.allowedPrimaryFingerprints[0] !== expectedSigner.fingerprint
    ) failPublicSourceZipCampaign("POLICY", "gpg-verification-authority");
    allowedPrimaryFingerprints = options.allowedPrimaryFingerprints;
  }
  const testAdapter = Object.getOwnPropertyDescriptor(
    options,
    GPG_PROCESS_TEST_ADAPTER,
  )?.value ?? null;
  const signedSnapshot = inspectGpgInputFile(
    options.signedFile,
    4 * 1024 * 1024,
    "signed-file-identity",
  );
  const signatureSnapshot = options.operation === "detached-verify"
    ? inspectGpgInputFile(
      options.signatureFile,
      GPG_STDOUT_BOUND_BYTES,
      "signature-file-identity",
    )
    : null;
  const globalArguments = [
    "--no-options",
    "--homedir", options.gpgHome,
    "--batch",
    "--no-tty",
    "--no-auto-key-retrieve",
    "--auto-key-locate", "clear",
  ];
  const versionResult = await runSealedGpgProcess({
    executablePath: options.executablePath,
    argumentsList: [...globalArguments, "--version"],
    gpgHome: options.gpgHome,
    profile,
    expectedExecutable: initialExecutable,
    testAdapter,
    checkpointPrefix: "version-query",
  });
  const version = normalizedGpgVersion(versionResult.stdout);
  if (version !== profile.version) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-version-profile-mismatch");
  }
  await invokeGpgTestAdapter(testAdapter, "after-version-query");
  const operationArguments = options.operation === "detached-sign"
    ? [
      "--pinentry-mode", "loopback",
      "--status-fd", "1",
      "--local-user", signingFingerprint,
      "--detach-sign",
      "--output", options.signatureFile,
      options.signedFile,
    ]
    : [
      "--status-fd", "1",
      "--verify", options.signatureFile, options.signedFile,
    ];
  const operationResult = await runSealedGpgProcess({
    executablePath: options.executablePath,
    argumentsList: [...globalArguments, ...operationArguments],
    gpgHome: options.gpgHome,
    profile,
    expectedExecutable: initialExecutable,
    testAdapter,
    checkpointPrefix: options.operation,
  });
  requireUnchangedGpgInput(
    options.signedFile,
    signedSnapshot,
    4 * 1024 * 1024,
    "signed-file-identity",
  );
  if (signatureSnapshot !== null) {
    requireUnchangedGpgInput(
      options.signatureFile,
      signatureSnapshot,
      GPG_STDOUT_BOUND_BYTES,
      "signature-file-identity",
    );
  } else {
    inspectGpgInputFile(
      options.signatureFile,
      GPG_STDOUT_BOUND_BYTES,
      "signature-file-identity",
    );
  }
  if (!sameGpgIdentity(
    gpgHomeIdentity,
    inspectGpgDirectory(options.gpgHome, "gpg-home-identity"),
  )) failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-home-replaced");
  const finalExecutable = inspectGpgExecutable(options.executablePath, profile);
  if (!sameGpgExecutableSnapshot(initialExecutable, finalExecutable)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-replaced");
  }
  const stdout = decodeBoundedGpgOutput(
    operationResult.stdout,
    "gpg-status-output",
  );
  let signingStatusFingerprint = null;
  let verifiedFingerprints = null;
  if (options.operation === "detached-sign") {
    signingStatusFingerprint = parseOpenPgpSigningStatusOutput(stdout);
  } else {
    verifiedFingerprints = parseOpenPgpStatusOutput(stdout);
    if (!allowedPrimaryFingerprints.includes(verifiedFingerprints.primaryFingerprint)) {
      failPublicSourceZipCampaign("SIGNATURE", "signer-not-allowed");
    }
  }
  await invokeGpgTestAdapter(testAdapter, "before-final-return");
  const returnExecutable = inspectGpgExecutable(options.executablePath, profile);
  if (!sameGpgExecutableSnapshot(initialExecutable, returnExecutable)) {
    failPublicSourceZipCampaign("GPG_EXECUTION", "gpg-executable-replaced");
  }
  const finalQualification = requireQualifiedExecutableInstallation({
    executablePath: options.executablePath,
    immutableInstallationProfile: selected.immutableProfile,
    phase: "gpg-campaign-execution",
    purpose: options.gpgRole,
  });
  if (
    finalQualification.resultSha256 !== initialQualification.resultSha256
  ) failPublicSourceZipCampaign("ENVIRONMENT", "gpg-qualification-changed");
  return frozen({
    authority: "non-authoritative-low-level-result",
    gpgRole: options.gpgRole,
    hostRole: options.hostRole,
    signerRole: options.signerRole,
    signatureNamespace: options.signatureNamespace,
    operation: options.operation,
    assignmentSha256: selected.assignmentSha256,
    profileId: profile.profileId,
    profileSha256: selected.profileSha256,
    immutableInstallationProfileSha256: selected.immutableProfileSha256,
    qualificationResult: initialQualification.result,
    qualificationResultSha256: initialQualification.resultSha256,
    version,
    signingStatusFingerprint,
    signingFingerprint: verifiedFingerprints?.signingFingerprint ?? null,
    primaryFingerprint: verifiedFingerprints?.primaryFingerprint ?? null,
  });
}

export function buildEnvironmentLock() {
  return validateEnvironmentLock({
    documentKind: ENVIRONMENT_LOCK_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    lang: "C",
    lcAll: "C",
    timezone: "UTC",
    sourceDateEpoch: 0,
    networkPolicy: "disabled-during-generation",
    lineEndingPolicy: "git-object-b2-bytes",
    filesystemExecutionPolicy: "native-local",
    hostIdentifierPolicy: "opaque-cell-id-only",
  });
}

export function validateEnvironmentLock(value) {
  const phase = "ENVIRONMENT_LOCK";
  exactDataObject(value, ENVIRONMENT_LOCK_KEYS, phase, "environment-lock");
  if (
    value.documentKind !== ENVIRONMENT_LOCK_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.lang !== "C"
    || value.lcAll !== "C"
    || value.timezone !== "UTC"
    || value.sourceDateEpoch !== 0
    || value.networkPolicy !== "disabled-during-generation"
    || value.lineEndingPolicy !== "git-object-b2-bytes"
    || value.filesystemExecutionPolicy !== "native-local"
    || value.hostIdentifierPolicy !== "opaque-cell-id-only"
  ) failPublicSourceZipCampaign(phase, "environment-lock-authority");
  return frozen(value);
}

export function encodeCanonicalEnvironmentLock(value) {
  authority(value);
  return canonicalBytes(
    validateEnvironmentLock(value),
    "ENVIRONMENT_LOCK",
    "canonical-environment-lock",
  );
}

export function parseCanonicalEnvironmentLockBytes(bytes) {
  return parseCanonical(
    bytes,
    validateEnvironmentLock,
    "ENVIRONMENT_LOCK",
    "environment-lock",
  );
}

export function validateRuntimeIdentityBinding(value) {
  const phase = "RUNTIME_IDENTITY";
  exactDataObject(value, RUNTIME_IDENTITY_KEYS, phase, "runtime-identity");
  if (
    value.documentKind !== "ieltmps-node-runtime-identity"
    || value.schemaVersion !== 1
    || value.implementation !== "node"
  ) failPublicSourceZipCampaign(phase, "runtime-identity-header");
  requireIdentifier(value.runtimeProfileId, phase, "runtime-profile-id");
  requireSha256(value.executableSha256, phase, "executable-sha256");
  requireCount(value.executableByteLength, phase, "executable-byte-length");
  for (const key of [
    "nodeVersion", "v8Version", "modulesVersion", "distributionProfileId",
  ]) requireIdentifier(value[key], phase, "runtime-identity-field");
  return frozen(value);
}

export function encodeCanonicalRuntimeIdentityBinding(value) {
  authority(value);
  return canonicalBytes(
    validateRuntimeIdentityBinding(value),
    "RUNTIME_IDENTITY",
    "canonical-runtime-identity",
  );
}

export function parseCanonicalRuntimeIdentityBindingBytes(bytes) {
  return parseCanonical(
    bytes,
    validateRuntimeIdentityBinding,
    "RUNTIME_IDENTITY",
    "runtime-identity",
  );
}

export function validateGitIdentityBinding(value) {
  const phase = "GIT_IDENTITY";
  exactDataObject(value, GIT_IDENTITY_KEYS, phase, "git-identity");
  if (
    value.documentKind !== "ieltmps-git-runtime-identity"
    || value.schemaVersion !== 1
    || value.objectFormat !== "sha1"
  ) failPublicSourceZipCampaign(phase, "git-identity-header");
  requireIdentifier(value.gitProfileId, phase, "git-profile-id");
  requireSha256(value.executableSha256, phase, "executable-sha256");
  requireCount(value.executableByteLength, phase, "executable-byte-length");
  requirePublicText(value.reportedVersion, phase, "reported-version");
  requireIdentifier(value.distributionProfileId, phase, "distribution-profile");
  return frozen(value);
}

export function encodeCanonicalGitIdentityBinding(value) {
  authority(value);
  return canonicalBytes(
    validateGitIdentityBinding(value),
    "GIT_IDENTITY",
    "canonical-git-identity",
  );
}

export function parseCanonicalGitIdentityBindingBytes(bytes) {
  return parseCanonical(
    bytes,
    validateGitIdentityBinding,
    "GIT_IDENTITY",
    "git-identity",
  );
}

function toolPathComparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function toolFileIdentity(state) {
  return Object.freeze({
    dev: state.dev,
    ino: state.ino,
    size: state.size,
    nlink: state.nlink,
    mode: state.mode,
    mtimeNs: state.mtimeNs,
    ctimeNs: state.ctimeNs,
  });
}

function sameToolFileIdentity(left, right) {
  return Reflect.ownKeys(left).every((key) => left[key] === right[key]);
}

function stableToolReadSync(filePath, maximumBytes, phase, reason) {
  let descriptor = null;
  try {
    const initialState = lstatSync(filePath, { bigint: true });
    if (
      !initialState.isFile()
      || initialState.isSymbolicLink()
      || initialState.nlink !== 1n
      || initialState.size < 0n
      || initialState.size > BigInt(maximumBytes)
      || toolPathComparable(realpathSync.native(filePath))
        !== toolPathComparable(filePath)
    ) failPublicSourceZipCampaign(phase, reason);
    descriptor = openSync(
      filePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = toolFileIdentity(fstatSync(descriptor, { bigint: true }));
    const bytes = readFileSync(descriptor);
    const after = toolFileIdentity(fstatSync(descriptor, { bigint: true }));
    if (
      !sameToolFileIdentity(toolFileIdentity(initialState), before)
      || !sameToolFileIdentity(before, after)
      || bytes.length !== Number(initialState.size)
    ) failPublicSourceZipCampaign(phase, "loaded-tool-mutable");
    return Object.freeze({ bytes, identity: before });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign(phase, reason);
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch {
        failPublicSourceZipCampaign(phase, "loaded-tool-close");
      }
    }
  }
}

function sanitizedToolGitEnvironment(gitDirectory) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_") && key.toUpperCase() !== "PATH") {
      environment[key] = value;
    }
  }
  environment.PATH = gitDirectory;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LANG = "C";
  environment.LC_ALL = "C";
  return environment;
}

function runToolGit(gitExecutable, repository, argumentsList, reason) {
  const result = spawnSync(
    gitExecutable,
    ["--no-replace-objects", "-C", repository, ...argumentsList],
    {
      encoding: null,
      env: sanitizedToolGitEnvironment(path.dirname(gitExecutable)),
      maxBuffer: 64 * 1024 * 1024,
      timeout: 30_000,
      shell: false,
      windowsHide: true,
    },
  );
  if (
    result.error
    || result.signal
    || result.status !== 0
    || (result.stdout?.length ?? 0) + (result.stderr?.length ?? 0)
      > 64 * 1024 * 1024
  ) failPublicSourceZipCampaign("D2_BINDING", reason);
  return result.stdout;
}

function singleToolTreeEntry(bytes, expectedPath) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.at(-1) !== 0) {
    return null;
  }
  const records = bytes.subarray(0, -1).toString("utf8").split("\0");
  if (records.length !== 1) return null;
  const separator = records[0].indexOf("\t");
  if (separator < 0 || records[0].slice(separator + 1) !== expectedPath) return null;
  const fields = records[0].slice(0, separator).split(" ");
  if (fields.length !== 3 || fields[1] !== "blob") return null;
  return Object.freeze({ mode: fields[0], objectId: fields[2] });
}

export function verifyCampaignLoadedToolBytes(options) {
  const phase = "D2_BINDING";
  const keys = Object.freeze([
    "repository", "toolingCommit", "gitExecutable", "gitIdentity",
  ]);
  exactDataObject(options, keys, phase, "loaded-tool-options");
  if (
    typeof options.repository !== "string"
    || !path.isAbsolute(options.repository)
    || typeof options.gitExecutable !== "string"
    || !path.isAbsolute(options.gitExecutable)
  ) failPublicSourceZipCampaign(phase, "loaded-tool-path");
  requireGitObject(options.toolingCommit, phase, "tooling-commit");
  const gitIdentity = validateGitIdentityBinding(options.gitIdentity);
  let repositoryState;
  try {
    repositoryState = lstatSync(options.repository, { bigint: true });
    if (
      !repositoryState.isDirectory()
      || repositoryState.isSymbolicLink()
      || toolPathComparable(realpathSync.native(options.repository))
        !== toolPathComparable(options.repository)
    ) failPublicSourceZipCampaign(phase, "loaded-tool-repository");
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign(phase, "loaded-tool-repository");
  }
  const gitFile = stableToolReadSync(
    options.gitExecutable,
    256 * 1024 * 1024,
    "GIT_IDENTITY",
    "git-executable-identity",
  );
  const gitVersion = runToolGit(
    options.gitExecutable,
    options.repository,
    ["--version"],
    "git-version",
  ).toString("utf8").trim();
  if (
    sha256(gitFile.bytes) !== gitIdentity.executableSha256
    || gitFile.bytes.length !== gitIdentity.executableByteLength
    || gitVersion !== gitIdentity.reportedVersion
  ) failPublicSourceZipCampaign("GIT_IDENTITY", "git-executable-binding");
  if (runToolGit(
    options.gitExecutable,
    options.repository,
    ["cat-file", "-t", options.toolingCommit],
    "tooling-commit-object",
  ).toString("ascii").trim() !== "commit") {
    failPublicSourceZipCampaign(phase, "tooling-commit-object");
  }
  const loadedRoot = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
  const framed = createHash("sha256");
  for (const relativePath of CAMPAIGN_LOADED_TOOL_PATHS) {
    const tree = singleToolTreeEntry(runToolGit(
      options.gitExecutable,
      options.repository,
      ["ls-tree", "-z", "--full-tree", options.toolingCommit, "--", relativePath],
      "loaded-tool-tree-entry",
    ), relativePath);
    if (
      !tree
      || !["100644", "100755"].includes(tree.mode)
      || !GIT_OBJECT_PATTERN.test(tree.objectId)
    ) failPublicSourceZipCampaign(phase, "loaded-tool-tree-entry");
    const committed = runToolGit(
      options.gitExecutable,
      options.repository,
      ["cat-file", "blob", tree.objectId],
      "loaded-tool-blob",
    );
    const loadedPath = path.resolve(loadedRoot, ...relativePath.split("/"));
    const relative = path.relative(loadedRoot, loadedPath);
    if (
      relative === ".."
      || relative.startsWith(".." + path.sep)
      || path.isAbsolute(relative)
    ) failPublicSourceZipCampaign(phase, "loaded-tool-containment");
    const loaded = stableToolReadSync(
      loadedPath,
      16 * 1024 * 1024,
      phase,
      "loaded-tool-file",
    );
    if (!loaded.bytes.equals(committed)) {
      failPublicSourceZipCampaign(phase, "loaded-tool-byte-mismatch");
    }
    framed.update(Buffer.from(relativePath, "utf8"));
    framed.update(Buffer.from([0]));
    framed.update(Buffer.from(String(committed.length), "ascii"));
    framed.update(Buffer.from([0]));
    framed.update(committed);
  }
  return Object.freeze({
    toolingCommit: options.toolingCommit,
    toolCount: CAMPAIGN_LOADED_TOOL_PATHS.length,
    framedSha256: framed.digest("hex"),
    gitExecutableSha256: gitIdentity.executableSha256,
  });
}

export function buildPlatformProbe(options) {
  const phase = "PLATFORM_PROBE";
  const keys = Object.freeze([
    "campaignPolicy", "matrixCellId", "runtimeIdentity", "gitIdentity", "measurement",
  ]);
  exactDataObject(options, keys, phase, "build-options");
  const policy = validateCampaignPolicy(options.campaignPolicy);
  const cell = findCampaignCell(policy, options.matrixCellId);
  const runtime = validateRuntimeIdentityBinding(options.runtimeIdentity);
  const git = validateGitIdentityBinding(options.gitIdentity);
  const measurement = exactDataObject(
    options.measurement,
    PLATFORM_MEASUREMENT_KEYS,
    phase,
    "measurement",
  );
  const capabilities = exactDataObject(
    measurement.capabilities,
    PLATFORM_CAPABILITY_KEYS,
    phase,
    "capabilities",
  );
  for (const key of PLATFORM_CAPABILITY_KEYS) {
    requireBoolean(capabilities[key], phase, "capability-boolean");
  }
  return validatePlatformProbe({
    documentKind: PLATFORM_PROBE_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    matrixCellId: cell.matrixCellId,
    osFamily: measurement.osFamily,
    osRelease: measurement.osRelease,
    osVersion: measurement.osVersion,
    architecture: measurement.architecture,
    filesystemTypeCode: measurement.filesystemTypeCode,
    filesystemClass: measurement.filesystemClass,
    runtimeIdentitySha256: sha256(encodeCanonicalRuntimeIdentityBinding(runtime)),
    gitIdentitySha256: sha256(encodeCanonicalGitIdentityBinding(git)),
    nativeFilesystemStatSupported: capabilities.nativeFilesystemStatSupported,
    exclusiveCreateSupported: capabilities.exclusiveCreateSupported,
    hardLinkSupported: capabilities.hardLinkSupported,
    stableFileIdentitySupported: capabilities.stableFileIdentitySupported,
    policyExpectedOsFamily: cell.osFamily,
    policyExpectedArchitecture: policy.environmentProfile.architecture,
    policyExpectedFilesystemClass: cell.filesystemClass,
    osFamilyMatchesPolicy: measurement.osFamily === cell.osFamily,
    architectureMatchesPolicy:
      measurement.architecture === policy.environmentProfile.architecture,
    filesystemClassMatchesPolicy:
      measurement.filesystemClass === cell.filesystemClass,
    platformAttestationVerified: false,
  });
}

export function validatePlatformProbe(value) {
  const phase = "PLATFORM_PROBE";
  exactDataObject(value, PLATFORM_PROBE_KEYS, phase, "platform-probe");
  if (
    value.documentKind !== PLATFORM_PROBE_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
  ) failPublicSourceZipCampaign(phase, "platform-probe-header");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  if (!["windows", "linux"].includes(value.osFamily)) {
    failPublicSourceZipCampaign(phase, "os-family");
  }
  requirePublicText(value.osRelease, phase, "os-release");
  requirePublicText(value.osVersion, phase, "os-version");
  if (value.architecture !== "x64") failPublicSourceZipCampaign(phase, "architecture");
  requireIdentifier(value.filesystemTypeCode, phase, "filesystem-type-code");
  if (!["ntfs", "ext4-class"].includes(value.filesystemClass)) {
    failPublicSourceZipCampaign(phase, "filesystem-class");
  }
  requireSha256(value.runtimeIdentitySha256, phase, "runtime-identity-sha256");
  requireSha256(value.gitIdentitySha256, phase, "git-identity-sha256");
  for (const key of [
    "nativeFilesystemStatSupported",
    "exclusiveCreateSupported",
    "hardLinkSupported",
    "stableFileIdentitySupported",
    "osFamilyMatchesPolicy",
    "architectureMatchesPolicy",
    "filesystemClassMatchesPolicy",
  ]) requireBoolean(value[key], phase, "platform-boolean");
  if (
    value.nativeFilesystemStatSupported !== true
    || value.exclusiveCreateSupported !== true
    || value.hardLinkSupported !== true
    || value.stableFileIdentitySupported !== true
    || value.osFamilyMatchesPolicy !== true
    || value.architectureMatchesPolicy !== true
    || value.filesystemClassMatchesPolicy !== true
    || value.platformAttestationVerified !== false
  ) failPublicSourceZipCampaign(phase, "platform-probe-not-eligible");
  if (
    value.policyExpectedOsFamily !== value.osFamily
    || value.policyExpectedArchitecture !== value.architecture
    || value.policyExpectedFilesystemClass !== value.filesystemClass
  ) failPublicSourceZipCampaign(phase, "platform-expected-mismatch");
  return frozen(value);
}

export function encodeCanonicalPlatformProbe(value) {
  authority(value);
  return canonicalBytes(
    validatePlatformProbe(value),
    "PLATFORM_PROBE",
    "canonical-platform-probe",
  );
}

export function parseCanonicalPlatformProbeBytes(bytes) {
  return parseCanonical(
    bytes,
    validatePlatformProbe,
    "PLATFORM_PROBE",
    "platform-probe",
  );
}

function portableLedgerName(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 240
    || value.includes("\\")
    || value.startsWith("/")
    || value.endsWith("/")
    || /^[A-Za-z]:/u.test(value)
    || value.normalize("NFC") !== value
    || value.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) failPublicSourceZipCampaign("FILE_LEDGER", "ledger-name");
  return value;
}

function ledgerRoleForName(name) {
  if (name === "d2/artifact.zip") return "artifact";
  if (name.startsWith("d2/")) return "frozen-d2-authority";
  if (name.startsWith("authority/")) return "campaign-authority";
  if (name.startsWith("v2/")) return "additive-v2-authority";
  if (name === "cell-result.json") return "cell-result";
  failPublicSourceZipCampaign("FILE_LEDGER", "ledger-name-not-authorized");
}

function comparisonClassForName(name) {
  if ([
    "d2/artifact.zip",
    "d2/zip-verification.json",
    "d2/entry-plan.json",
    "authority/public-source-manifest.json",
    "authority/membership-report.json",
    "authority/test-vector-set.json",
    "v2/semantic-input-set.json",
  ].includes(name)) return "byte-identical";
  if ([
    "d2/input-set.json",
    "d2/semantic-report.json",
    "authority/campaign-policy.json",
    "authority/critical-tool-set.json",
    "authority/environment-lock.json",
  ].includes(name)) return "semantic";
  if ([
    "d2/evidence.json",
    "d2/verification-result.json",
    "d2/.complete",
  ].includes(name)) return "private-verification";
  return "cell-specific";
}

export function validateFileLedgerEntry(value) {
  const phase = "FILE_LEDGER";
  exactDataObject(value, FILE_LEDGER_ENTRY_KEYS, phase, "ledger-entry");
  portableLedgerName(value.name);
  if (value.role !== ledgerRoleForName(value.name)) {
    failPublicSourceZipCampaign(phase, "ledger-role");
  }
  requireSha256(value.sha256, phase, "ledger-sha256");
  requireCount(value.byteLength, phase, "ledger-byte-length", 1024 * 1024 * 1024);
  if (
    !COMPARISON_CLASS_SET.has(value.comparisonClass)
    || value.comparisonClass !== comparisonClassForName(value.name)
  ) failPublicSourceZipCampaign(phase, "comparison-class");
  return frozen(value);
}

export function validateCellFileLedger(value) {
  const phase = "FILE_LEDGER";
  requireArray(value, phase, "file-ledger");
  if (value.length !== CELL_PAYLOAD_NAMES.length) {
    failPublicSourceZipCampaign(phase, "ledger-count");
  }
  const lowerNames = new Set();
  const normalizedNames = new Set();
  const result = value.map((entry, index) => {
    const validated = validateFileLedgerEntry(entry);
    if (validated.name !== CELL_PAYLOAD_NAMES[index]) {
      failPublicSourceZipCampaign(phase, "ledger-order");
    }
    const lower = validated.name.toLowerCase();
    const normalized = validated.name.normalize("NFC");
    if (lowerNames.has(lower) || normalizedNames.has(normalized)) {
      failPublicSourceZipCampaign(phase, "ledger-name-collision");
    }
    lowerNames.add(lower);
    normalizedNames.add(normalized);
    return validated;
  });
  return Object.freeze(result);
}

export function buildCellFileLedger(options) {
  const phase = "FILE_LEDGER";
  exactDataObject(options, Object.freeze(["files"]), phase, "build-options", {
    allowBuffer: true,
  });
  const files = requireArray(options.files, phase, "files", {
    allowBuffer: true,
  });
  if (files.length !== CELL_PAYLOAD_NAMES.length) {
    failPublicSourceZipCampaign(phase, "file-count");
  }
  const result = files.map((entry, index) => {
    exactDataObject(
      entry,
      Object.freeze(["name", "bytes"]),
      phase,
      "file-entry",
      { allowBuffer: true },
    );
    if (entry.name !== CELL_PAYLOAD_NAMES[index] || !Buffer.isBuffer(entry.bytes)) {
      failPublicSourceZipCampaign(phase, "file-entry-binding");
    }
    return validateFileLedgerEntry({
      name: entry.name,
      role: ledgerRoleForName(entry.name),
      sha256: sha256(entry.bytes),
      byteLength: entry.bytes.length,
      comparisonClass: comparisonClassForName(entry.name),
    });
  });
  return Object.freeze(result);
}

export function cellFileLedgerSha256(value) {
  authority(value);
  return sha256(canonicalBytes(validateCellFileLedger(value), "FILE_LEDGER", "ledger-canonical"));
}

export function validateCellResult(value) {
  const phase = "CELL_RESULT";
  exactDataObject(value, CELL_RESULT_KEYS, phase, "cell-result");
  if (
    value.documentKind !== CELL_RESULT_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.status !== "ok"
    || value.mode !== "public-source-zip-campaign-cell"
  ) failPublicSourceZipCampaign(phase, "cell-result-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  for (const key of [
    "nodeRuntimeProfileId",
    "producerGpgProfileId",
    "producerLocalVerifierProfileId",
  ]) requireIdentifier(value[key], phase, "execution-profile-id");
  if (typeof value.runNonce !== "string" || !RUN_NONCE_PATTERN.test(value.runNonce)) {
    failPublicSourceZipCampaign(phase, "run-nonce");
  }
  for (const key of CELL_RESULT_KEYS.filter((key) => key.endsWith("Sha256"))) {
    requireSha256(value[key], phase, "cell-result-digest");
  }
  const trueKeys = [
    "d1CanonicalVerificationPassed",
    "d2SameProcessPassed",
    "d2SameHostPassed",
    "boundaryVectorSetPassed",
    "localArtifactCreated",
    "localFileIdentityVerified",
    "privacyGatePassed",
    "temporaryRootCleanupVerified",
    "environmentBlockerAbsent",
    "comparisonEligible",
  ];
  for (const key of trueKeys) requireFixedBoolean(value[key], true, phase, "cell-result-semantics");
  for (const key of [
    "foreignCellInputUsed",
    "platformAttestationVerified",
    "projectPublicationAuthorized",
  ]) requireFixedBoolean(value[key], false, phase, "cell-result-semantics");
  return frozen(value);
}

export function buildCellResult(options) {
  const phase = "CELL_RESULT";
  exactDataObject(
    options,
    Object.freeze([
      "campaignPolicy",
      "evidence",
      "executionIdentity",
      "nodeAuthority",
      "producerSigningAuthority",
      "producerLocalVerificationAuthority",
    ]),
    phase,
    "build-options",
  );
  const policy = validateCampaignPolicy(options.campaignPolicy);
  const evidence = validateReproducibilityEvidenceV2(options.evidence);
  const execution = validateExecutionIdentityV2(options.executionIdentity);
  authority(options.nodeAuthority);
  authority(options.producerSigningAuthority);
  authority(options.producerLocalVerificationAuthority);
  const gpgAuthorities = findCellProducerGpgAuthorities(
    policy,
    execution.matrixCellId,
  );
  const nodeAuthority = findNodeRuntimeAssignment(policy, {
    campaignRole: "cell-producer",
    matrixCellId: execution.matrixCellId,
    hostRole: execution.matrixCellId,
  });
  const measuredNode = options.nodeAuthority;
  const signing = options.producerSigningAuthority;
  const localVerification = options.producerLocalVerificationAuthority;
  if (
    evidence.campaignId !== policy.campaignId
    || evidence.sourceCommit !== policy.sourceCommit
    || evidence.toolingCommit !== policy.toolingCommit
    || execution.campaignId !== evidence.campaignId
    || execution.matrixCellId !== evidence.matrixCellId
    || executionIdentitySha256V2(execution) !== evidence.executionIdentitySha256
    || execution.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || evidence.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || execution.nodeRuntimeProfileSha256 !== nodeAuthority.profileSha256
    || execution.nodeImmutableInstallationProfileSha256
      !== nodeAuthority.immutableProfileSha256
    || execution.producerGpgImmutableInstallationProfileSha256
      !== gpgAuthorities.signing.immutableProfileSha256
    || measuredNode.profileId !== nodeAuthority.profile.profileId
    || measuredNode.profileSha256 !== nodeAuthority.profileSha256
    || measuredNode.immutableInstallationProfileSha256
      !== nodeAuthority.immutableProfileSha256
    || measuredNode.runtimeIdentitySha256 !== execution.runtimeIdentitySha256
    || signing.gpgRole !== "cell-producer-sign"
    || signing.hostRole !== execution.matrixCellId
    || signing.profileId !== gpgAuthorities.signing.profile.profileId
    || signing.profileSha256 !== gpgAuthorities.signing.profileSha256
    || signing.assignmentSha256 !== gpgAuthorities.signing.assignmentSha256
    || signing.immutableInstallationProfileSha256
      !== gpgAuthorities.signing.immutableProfileSha256
    || localVerification.gpgRole !== "cell-producer-local-verify"
    || localVerification.hostRole !== execution.matrixCellId
    || localVerification.profileId
      !== gpgAuthorities.localVerification.profile.profileId
    || localVerification.profileSha256
      !== gpgAuthorities.localVerification.profileSha256
    || localVerification.assignmentSha256
      !== gpgAuthorities.localVerification.assignmentSha256
    || localVerification.immutableInstallationProfileSha256
      !== gpgAuthorities.localVerification.immutableProfileSha256
  ) failPublicSourceZipCampaign(phase, "cell-result-binding");
  return validateCellResult({
    documentKind: CELL_RESULT_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    status: "ok",
    mode: "public-source-zip-campaign-cell",
    campaignId: evidence.campaignId,
    matrixCellId: evidence.matrixCellId,
    sourceCommit: evidence.sourceCommit,
    toolingCommit: evidence.toolingCommit,
    runNonce: execution.runNonce,
    nodeRuntimeProfileId: measuredNode.profileId,
    nodeRuntimeProfileSha256: measuredNode.profileSha256,
    nodeImmutableInstallationProfileSha256:
      measuredNode.immutableInstallationProfileSha256,
    nodeQualificationResultSha256: measuredNode.qualificationResultSha256,
    producerGpgProfileId: signing.profileId,
    producerGpgProfileSha256: signing.profileSha256,
    producerGpgImmutableInstallationProfileSha256:
      signing.immutableInstallationProfileSha256,
    producerSignAssignmentSha256: signing.assignmentSha256,
    producerSignQualificationResultSha256: signing.qualificationResultSha256,
    producerLocalVerifierProfileId: localVerification.profileId,
    producerLocalVerifierProfileSha256: localVerification.profileSha256,
    producerLocalGpgImmutableInstallationProfileSha256:
      localVerification.immutableInstallationProfileSha256,
    producerLocalVerifyAssignmentSha256:
      localVerification.assignmentSha256,
    producerLocalVerifyQualificationResultSha256:
      localVerification.qualificationResultSha256,
    semanticInputSetSha256: evidence.semanticInputSetSha256,
    executionIdentitySha256: evidence.executionIdentitySha256,
    platformClassSha256: evidence.platformClassSha256,
    runtimeClassSha256: evidence.runtimeClassSha256,
    artifactSha256: evidence.artifactSha256,
    entryPlanSha256: evidence.entryPlanSha256,
    zipVerificationSha256: evidence.zipVerificationSha256,
    d1CanonicalVerificationPassed: evidence.canonicalVerifierPassed,
    d2SameProcessPassed: evidence.sameProcessRepeatable,
    d2SameHostPassed: evidence.sameHostRepeatable,
    boundaryVectorSetPassed: evidence.boundaryVectorSetPassed,
    localArtifactCreated: true,
    localFileIdentityVerified: true,
    foreignCellInputUsed: false,
    privacyGatePassed: true,
    temporaryRootCleanupVerified: true,
    environmentBlockerAbsent: true,
    comparisonEligible: true,
    platformAttestationVerified: false,
    projectPublicationAuthorized: false,
  });
}

export function encodeCanonicalCellResult(value) {
  authority(value);
  return canonicalBytes(validateCellResult(value), "CELL_RESULT", "canonical-cell-result");
}

export function parseCanonicalCellResultBytes(bytes) {
  return parseCanonical(bytes, validateCellResult, "CELL_RESULT", "cell-result");
}

export function validateCellManifest(value) {
  const phase = "CELL_MANIFEST";
  exactDataObject(value, CELL_MANIFEST_KEYS, phase, "cell-manifest");
  if (
    value.documentKind !== CELL_MANIFEST_DOCUMENT_KIND
    || value.namespace !== CELL_SIGNATURE_NAMESPACE
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.resultStatus !== "ok"
  ) failPublicSourceZipCampaign(phase, "cell-manifest-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  for (const key of [
    "nodeRuntimeProfileId",
    "producerGpgProfileId",
    "producerLocalVerifierProfileId",
  ]) requireIdentifier(value[key], phase, "execution-profile-id");
  for (const key of CELL_MANIFEST_KEYS.filter((key) => key.endsWith("Sha256"))) {
    requireSha256(value[key], phase, "manifest-digest");
  }
  if (typeof value.runNonce !== "string" || !RUN_NONCE_PATTERN.test(value.runNonce)) {
    failPublicSourceZipCampaign(phase, "run-nonce");
  }
  const ledger = validateCellFileLedger(value.fileLedger);
  if (cellFileLedgerSha256(ledger) !== value.fileLedgerSha256) {
    failPublicSourceZipCampaign(phase, "manifest-ledger-binding");
  }
  return frozen(value);
}

export function buildCellManifest(options) {
  const phase = "CELL_MANIFEST";
  exactDataObject(
    options,
    Object.freeze(["campaignPolicy", "cellResult", "fileLedger"]),
    phase,
    "build-options",
  );
  const policy = validateCampaignPolicy(options.campaignPolicy);
  const result = validateCellResult(options.cellResult);
  const ledger = validateCellFileLedger(options.fileLedger);
  const gpgAuthorities = findCellProducerGpgAuthorities(
    policy,
    result.matrixCellId,
  );
  if (
    result.campaignId !== policy.campaignId
    || result.sourceCommit !== policy.sourceCommit
    || result.toolingCommit !== policy.toolingCommit
    || result.producerGpgProfileId
      !== gpgAuthorities.signing.profile.profileId
    || result.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || result.producerSignAssignmentSha256
      !== gpgAuthorities.signing.assignmentSha256
    || result.producerLocalVerifierProfileId
      !== gpgAuthorities.localVerification.profile.profileId
    || result.producerLocalVerifierProfileSha256
      !== gpgAuthorities.localVerification.profileSha256
    || result.producerLocalVerifyAssignmentSha256
      !== gpgAuthorities.localVerification.assignmentSha256
  ) failPublicSourceZipCampaign(phase, "manifest-policy-binding");
  findCampaignCell(policy, result.matrixCellId);
  return validateCellManifest({
    documentKind: CELL_MANIFEST_DOCUMENT_KIND,
    namespace: CELL_SIGNATURE_NAMESPACE,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    campaignId: result.campaignId,
    matrixCellId: result.matrixCellId,
    sourceCommit: result.sourceCommit,
    toolingCommit: result.toolingCommit,
    campaignPolicySha256: campaignPolicySha256(policy),
    runNonce: result.runNonce,
    nodeRuntimeProfileId: result.nodeRuntimeProfileId,
    nodeRuntimeProfileSha256: result.nodeRuntimeProfileSha256,
    nodeImmutableInstallationProfileSha256:
      result.nodeImmutableInstallationProfileSha256,
    nodeQualificationResultSha256: result.nodeQualificationResultSha256,
    producerGpgProfileId: result.producerGpgProfileId,
    producerGpgProfileSha256: result.producerGpgProfileSha256,
    producerGpgImmutableInstallationProfileSha256:
      result.producerGpgImmutableInstallationProfileSha256,
    producerSignAssignmentSha256: result.producerSignAssignmentSha256,
    producerSignQualificationResultSha256:
      result.producerSignQualificationResultSha256,
    producerLocalVerifierProfileId: result.producerLocalVerifierProfileId,
    producerLocalVerifierProfileSha256:
      result.producerLocalVerifierProfileSha256,
    producerLocalGpgImmutableInstallationProfileSha256:
      result.producerLocalGpgImmutableInstallationProfileSha256,
    producerLocalVerifyAssignmentSha256:
      result.producerLocalVerifyAssignmentSha256,
    producerLocalVerifyQualificationResultSha256:
      result.producerLocalVerifyQualificationResultSha256,
    semanticInputSetSha256: result.semanticInputSetSha256,
    executionIdentitySha256: result.executionIdentitySha256,
    platformClassSha256: result.platformClassSha256,
    runtimeClassSha256: result.runtimeClassSha256,
    resultStatus: result.status,
    fileLedgerSha256: cellFileLedgerSha256(ledger),
    fileLedger: ledger,
  });
}

export function encodeCanonicalCellManifest(value) {
  authority(value);
  return canonicalBytes(
    validateCellManifest(value),
    "CELL_MANIFEST",
    "canonical-cell-manifest",
  );
}

export function parseCanonicalCellManifestBytes(bytes) {
  return parseCanonical(
    bytes,
    validateCellManifest,
    "CELL_MANIFEST",
    "cell-manifest",
  );
}

export function validateSignatureNamespace(value) {
  authority(value);
  if (typeof value !== "string" || !SIGNATURE_NAMESPACES.includes(value)) {
    failPublicSourceZipCampaign("SIGNATURE", "signature-namespace");
  }
  return value;
}

export function validateSignatureVerificationRecord(value) {
  const phase = "SIGNATURE";
  exactDataObject(value, SIGNATURE_VERIFICATION_KEYS, phase, "signature-record");
  if (
    value.documentKind !== SIGNATURE_VERIFICATION_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.status !== "ok"
    || value.mode !== "openpgp-detached-signature-verification"
  ) failPublicSourceZipCampaign(phase, "signature-record-header");
  validateSignatureNamespace(value.namespace);
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireFingerprint(value.signerFingerprint, phase, "signer-fingerprint");
  requireIdentifier(value.signerRole, phase, "signer-role");
  if (!GPG_ROLE_SET.has(value.gpgRole)) {
    failPublicSourceZipCampaign(phase, "signature-gpg-role");
  }
  requireIdentifier(value.hostRole, phase, "signature-host-role");
  requireIdentifier(value.gpgVerifierProfileId, phase, "gpg-verifier-profile-id");
  for (const key of [
    "gpgVerifierProfileSha256",
    "gpgAssignmentSha256",
    "gpgImmutableInstallationProfileSha256",
    "gpgQualificationResultSha256",
  ]) requireSha256(value[key], phase, "gpg-verification-digest");
  for (const key of [
    "signatureVerified", "primaryFingerprintVerified", "policyBindingVerified",
  ]) requireFixedBoolean(value[key], true, phase, "signature-verification");
  requireFixedBoolean(
    value.platformAttestationVerified,
    false,
    phase,
    "platform-attestation",
  );
  return frozen(value);
}

export function encodeCanonicalSignatureVerificationRecord(value) {
  authority(value);
  return canonicalBytes(
    validateSignatureVerificationRecord(value),
    "SIGNATURE",
    "canonical-signature-record",
  );
}

export function validateCellVerificationResult(value) {
  const phase = "CELL_VERIFICATION";
  exactDataObject(value, CELL_VERIFICATION_KEYS, phase, "cell-verification");
  if (
    value.documentKind !== CELL_VERIFICATION_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.status !== "ok"
    || value.mode !== "public-source-zip-campaign-cell-verification"
  ) failPublicSourceZipCampaign(phase, "cell-verification-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.matrixCellId, phase, "matrix-cell-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  for (const key of [
    "nodeRuntimeProfileId",
    "producerGpgProfileId",
    "producerLocalVerifierProfileId",
    "verificationRole",
    "verificationHostRole",
    "consumerNodeRuntimeProfileId",
    "consumerVerifierProfileId",
  ]) requireIdentifier(value[key], phase, "cell-verification-identity");
  if (value.verificationRole !== "cell-import-consumer-verify") {
    failPublicSourceZipCampaign(phase, "cell-verification-role");
  }
  if (typeof value.runNonce !== "string" || !RUN_NONCE_PATTERN.test(value.runNonce)) {
    failPublicSourceZipCampaign(phase, "run-nonce");
  }
  for (const key of CELL_VERIFICATION_KEYS.filter((key) => key.endsWith("Sha256"))) {
    requireSha256(value[key], phase, "cell-verification-digest");
  }
  requireFingerprint(value.signerFingerprint, phase, "signer-fingerprint");
  requireIdentifier(value.signerRole, phase, "signer-role");
  if (value.signatureNamespace !== CELL_SIGNATURE_NAMESPACE) {
    failPublicSourceZipCampaign(phase, "signature-namespace");
  }
  for (const key of [
    "signatureVerified",
    "fileLedgerVerified",
    "exactOutputSetVerified",
    "d1CanonicalVerificationPassed",
    "d2SameProcessPassed",
    "d2SameHostPassed",
    "boundaryVectorSetPassed",
    "privacyGatePassed",
    "temporaryRootCleanupVerified",
    "environmentBlockerAbsent",
    "comparisonEligible",
  ]) requireFixedBoolean(value[key], true, phase, "cell-verification-semantics");
  for (const key of ["platformAttestationVerified", "projectPublicationAuthorized"]) {
    requireFixedBoolean(value[key], false, phase, "cell-verification-semantics");
  }
  return frozen(value);
}

export function encodeCanonicalCellVerificationResult(value) {
  authority(value);
  return canonicalBytes(
    validateCellVerificationResult(value),
    "CELL_VERIFICATION",
    "canonical-cell-verification",
  );
}

export function validateCampaignComparisonResult(value) {
  const phase = "COMPARISON";
  exactDataObject(value, CAMPAIGN_COMPARISON_KEYS, phase, "campaign-comparison");
  if (
    value.documentKind !== CAMPAIGN_COMPARISON_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.status !== "ok"
    || value.mode !== "public-source-zip-campaign-comparison"
  ) failPublicSourceZipCampaign(phase, "comparison-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  requireFixedBoolean(value.matrixComplete, true, phase, "matrix-complete");
  requireFixedBoolean(value.claimAllowed, true, phase, "claim-allowed");
  requireArray(value.claimLevelsSatisfied, phase, "claim-levels");
  if (
    value.claimLevelsSatisfied.length !== CLAIM_LEVELS_V2.length
    || value.claimLevelsSatisfied.some((entry, index) => entry !== CLAIM_LEVELS_V2[index])
  ) failPublicSourceZipCampaign(phase, "claim-levels");
  for (const [key, expected] of [
    ["crossRuntimePair", ["LINUX-A", "LINUX-B"]],
    ["crossOsPair", ["WIN-A", "LINUX-A"]],
  ]) {
    requireArray(value[key], phase, key);
    if (value[key].length !== 2 || value[key].some((entry, index) => entry !== expected[index])) {
      failPublicSourceZipCampaign(phase, "comparison-pair");
    }
  }
  for (const key of [
    "artifactSha256", "entryPlanSha256", "zipVerificationSha256", "semanticInputSetSha256",
  ]) requireSha256(value[key], phase, "comparison-digest");
  requireArray(value.cellAuthorities, phase, "comparison-cell-authorities");
  const expectedCellOrder = [
    ...REQUIRED_MATRIX_CELL_IDS,
    ...(value.acceptedCellCount === 4 ? OPTIONAL_MATRIX_CELL_IDS : []),
  ].sort((left, right) => Buffer.compare(
    Buffer.from(left, "utf8"),
    Buffer.from(right, "utf8"),
  ));
  if (value.cellAuthorities.length !== value.acceptedCellCount) {
    failPublicSourceZipCampaign(phase, "comparison-cell-authority-count");
  }
  value.cellAuthorities.forEach((entry, index) => {
    exactDataObject(entry, COMPARISON_CELL_AUTHORITY_KEYS, phase, "cell-authority");
    if (entry.matrixCellId !== expectedCellOrder[index]) {
      failPublicSourceZipCampaign(phase, "comparison-cell-authority-order");
    }
    for (const key of [
      "producerGpgProfileId",
      "producerLocalVerifierProfileId",
      "consumerVerifierProfileId",
      "consumerHostRole",
    ]) requireIdentifier(entry[key], phase, "comparison-cell-authority-id");
    for (const key of COMPARISON_CELL_AUTHORITY_KEYS.filter(
      (key) => key.endsWith("Sha256"),
    )) requireSha256(entry[key], phase, "comparison-cell-authority-digest");
    requireFixedBoolean(
      entry.signatureVerified,
      true,
      phase,
      "comparison-cell-signature",
    );
  });
  for (const key of [
    "comparisonNodeRuntimeProfileId",
    "comparisonSignerProfileId",
    "comparisonLocalVerifierProfileId",
    "independentReviewVerifierProfileId",
  ]) requireIdentifier(value[key], phase, "comparison-profile-id");
  for (const key of CAMPAIGN_COMPARISON_KEYS.filter(
    (key) => key.endsWith("Sha256"),
  )) requireSha256(value[key], phase, "comparison-authority-digest");
  requireCount(value.requiredCellCount, phase, "required-cell-count", 4);
  requireCount(value.acceptedCellCount, phase, "accepted-cell-count", 4);
  if (
    value.requiredCellCount !== REQUIRED_MATRIX_CELL_IDS.length
    || value.acceptedCellCount < value.requiredCellCount
    || value.acceptedCellCount > 4
  ) failPublicSourceZipCampaign(phase, "comparison-count");
  requireFixedBoolean(value.evidenceSigningRequired, true, phase, "evidence-signing");
  requireFixedBoolean(
    value.independentReviewCompleted,
    false,
    phase,
    "independent-review-state",
  );
  requireFixedBoolean(
    value.allExecutionProfilesQualified,
    true,
    phase,
    "execution-profile-qualification",
  );
  requireFixedBoolean(value.platformAttestationVerified, false, phase, "platform-attestation");
  requireFixedBoolean(value.projectPublicationAuthorized, false, phase, "publication-authorization");
  return frozen(value);
}

export function encodeCanonicalCampaignComparisonResult(value) {
  authority(value);
  return canonicalBytes(
    validateCampaignComparisonResult(value),
    "COMPARISON",
    "canonical-comparison",
  );
}

export function validateComparisonFileLedger(value) {
  const phase = "FILE_LEDGER";
  requireArray(value, phase, "comparison-file-ledger");
  if (value.length !== 1) {
    failPublicSourceZipCampaign(phase, "comparison-ledger-count");
  }
  const entry = value[0];
  exactDataObject(entry, FILE_LEDGER_ENTRY_KEYS, phase, "comparison-ledger-entry");
  if (
    entry.name !== "campaign-result.json"
    || entry.role !== "campaign-result"
    || entry.comparisonClass !== "semantic"
  ) failPublicSourceZipCampaign(phase, "comparison-ledger-authority");
  requireSha256(entry.sha256, phase, "comparison-ledger-sha256");
  requireCount(entry.byteLength, phase, "comparison-ledger-byte-length", 4 * 1024 * 1024);
  return Object.freeze([frozen(entry)]);
}

export function validateComparisonManifest(value) {
  const phase = "COMPARISON";
  exactDataObject(
    value,
    COMPARISON_MANIFEST_KEYS,
    phase,
    "comparison-manifest",
  );
  if (
    value.documentKind !== CAMPAIGN_COMPARISON_MANIFEST_DOCUMENT_KIND
    || value.namespace !== COMPARISON_SIGNATURE_NAMESPACE
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.resultStatus !== "ok"
  ) failPublicSourceZipCampaign(phase, "comparison-manifest-header");
  requireIdentifier(value.campaignId, phase, "campaign-id");
  requireIdentifier(value.role, phase, "comparison-signer-role");
  requireGitObject(value.sourceCommit, phase, "source-commit");
  requireGitObject(value.toolingCommit, phase, "tooling-commit");
  requireSha256(value.campaignPolicySha256, phase, "campaign-policy-sha256");
  for (const key of [
    "comparisonNodeRuntimeProfileId",
    "comparisonSignerProfileId",
    "comparisonLocalVerifierProfileId",
    "independentReviewVerifierProfileId",
  ]) requireIdentifier(value[key], phase, "comparison-profile-id");
  for (const key of COMPARISON_MANIFEST_KEYS.filter(
    (key) => key.endsWith("Sha256"),
  )) requireSha256(value[key], phase, "comparison-manifest-digest");
  if (typeof value.runNonce !== "string" || !RUN_NONCE_PATTERN.test(value.runNonce)) {
    failPublicSourceZipCampaign(phase, "run-nonce");
  }
  const ledger = validateComparisonFileLedger(value.fileLedger);
  const ledgerBytes = canonicalBytes(ledger, phase, "comparison-ledger-canonical");
  if (sha256(ledgerBytes) !== value.fileLedgerSha256) {
    failPublicSourceZipCampaign(phase, "comparison-ledger-binding");
  }
  return frozen(value);
}

export function encodeCanonicalComparisonManifest(value) {
  authority(value);
  return canonicalBytes(
    validateComparisonManifest(value),
    "COMPARISON",
    "canonical-comparison-manifest",
  );
}

export function parseCanonicalComparisonManifestBytes(bytes) {
  return parseCanonical(
    bytes,
    validateComparisonManifest,
    "COMPARISON",
    "comparison-manifest",
  );
}

export function validateCampaignFailureResult(value) {
  const phase = "COMPARISON";
  exactDataObject(value, CAMPAIGN_FAILURE_KEYS, phase, "campaign-failure");
  if (
    value.documentKind !== CAMPAIGN_FAILURE_DOCUMENT_KIND
    || value.schemaVersion !== CAMPAIGN_SCHEMA_VERSION
    || value.status !== "failed"
    || value.mode !== "public-source-zip-campaign-failure"
    || typeof value.phase !== "string"
    || !ERROR_PHASES.has(value.phase)
    || typeof value.reason !== "string"
    || !REASON_PATTERN.test(value.reason)
  ) failPublicSourceZipCampaign(phase, "campaign-failure-header");
  for (const key of [
    "matrixComplete", "claimAllowed", "platformAttestationVerified", "projectPublicationAuthorized",
  ]) requireFixedBoolean(value[key], false, phase, "campaign-failure-semantics");
  return frozen(value);
}

export function validateExactCellOutputNames(value) {
  authority(value);
  requireArray(value, "FILE_LEDGER", "output-names");
  if (
    value.length !== SEALED_CELL_OUTPUT_NAMES.length
    || value.some((entry, index) => entry !== SEALED_CELL_OUTPUT_NAMES[index])
  ) failPublicSourceZipCampaign("FILE_LEDGER", "exact-output-set");
  return Object.freeze([...value]);
}

export function validateV2EvidenceAndResultBinding(evidenceValue, resultValue) {
  authority(evidenceValue);
  authority(resultValue);
  const evidence = validateReproducibilityEvidenceV2(evidenceValue);
  const result = validateVerificationResultV2(resultValue);
  for (const key of [
    "campaignId",
    "matrixCellId",
    "semanticInputSetSha256",
    "executionIdentitySha256",
    "producerGpgProfileSha256",
    "platformClassSha256",
    "runtimeClassSha256",
    "artifactSha256",
  ]) {
    if (evidence[key] !== result[key]) {
      failPublicSourceZipCampaign("CELL_VERIFICATION", "v2-result-binding");
    }
  }
  return true;
}
