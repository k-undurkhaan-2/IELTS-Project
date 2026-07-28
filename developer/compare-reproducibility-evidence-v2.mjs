#!/usr/bin/env node

import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
  parseCanonicalPublicJsonBytes,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  CLAIM_LEVELS_V2,
  encodeCanonicalReproducibilityEvidenceV2,
  encodeCanonicalVerificationResultV2,
  executionIdentitySha256V2,
  validateExecutionIdentityV2,
  validateReproducibilityEvidenceV2,
  validateVerificationResultV2,
} from "./reproducibility-evidence-v2-core.mjs";
import {
  CAMPAIGN_COMPARISON_DOCUMENT_KIND,
  CAMPAIGN_SCHEMA_VERSION,
  OPTIONAL_MATRIX_CELL_IDS,
  PublicSourceZipCampaignError,
  REQUIRED_MATRIX_CELL_IDS,
  campaignPolicySha256,
  failPublicSourceZipCampaign,
  findCellProducerGpgAuthorities,
  findCellImportConsumerGpgAuthority,
  findComparisonGpgAuthorities,
  findIndependentReviewGpgAuthority,
  findNodeRuntimeAssignment,
  parseCanonicalCampaignPolicyBytes,
  validateCampaignComparisonResult,
  validateCampaignPolicy,
  validateCellVerificationResult,
  validateV2EvidenceAndResultBinding,
} from "./public-source-zip-campaign-core.mjs";

export const VERIFIED_EVIDENCE_CELL_KEYS = Object.freeze([
  "verifiedCell",
  "evidence",
  "verificationResult",
  "executionIdentity",
]);

const COMPARISON_OPTION_KEYS = Object.freeze([
  "campaignPolicy",
  "cells",
  "comparisonNodeAuthority",
  "comparisonSigningAuthority",
  "comparisonLocalVerificationAuthority",
  "independentReviewAuthority",
]);
const MAX_CLI_DOCUMENT_BYTES = 4 * 1024 * 1024;

function authority(value) {
  try {
    assertProxyFreeAuthorityGraph(value);
  } catch {
    failPublicSourceZipCampaign("OBJECT_AUTHORITY", "authority-graph-rejected");
  }
  return value;
}

function exactDataObject(value, keys, phase, reason) {
  authority(value);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) failPublicSourceZipCampaign(phase, reason + "-object");
  const actual = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
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
    ) {
      failPublicSourceZipCampaign(phase, reason + "-descriptor");
    }
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeCellRecord(value, policy, policySha256) {
  const phase = "COMPARISON";
  exactDataObject(value, VERIFIED_EVIDENCE_CELL_KEYS, phase, "cell-record");
  const verifiedCell = validateCellVerificationResult(value.verifiedCell);
  const evidence = validateReproducibilityEvidenceV2(value.evidence);
  const verificationResult = validateVerificationResultV2(value.verificationResult);
  const executionIdentity = validateExecutionIdentityV2(value.executionIdentity);
  const gpgAuthorities = findCellProducerGpgAuthorities(
    policy,
    verifiedCell.matrixCellId,
  );
  const consumerAuthority = findCellImportConsumerGpgAuthority(
    policy,
    verifiedCell.matrixCellId,
    verifiedCell.verificationHostRole,
  );
  validateV2EvidenceAndResultBinding(evidence, verificationResult);
  const evidenceSha256 = sha256(encodeCanonicalReproducibilityEvidenceV2(evidence));
  const verificationResultSha256 = sha256(
    encodeCanonicalVerificationResultV2(verificationResult),
  );
  if (
    verifiedCell.campaignId !== policy.campaignId
    || verifiedCell.sourceCommit !== policy.sourceCommit
    || verifiedCell.toolingCommit !== policy.toolingCommit
    || verifiedCell.campaignPolicySha256 !== policySha256
    || evidence.campaignId !== verifiedCell.campaignId
    || evidence.matrixCellId !== verifiedCell.matrixCellId
    || evidence.sourceCommit !== verifiedCell.sourceCommit
    || evidence.toolingCommit !== verifiedCell.toolingCommit
    || verificationResult.matrixCellId !== verifiedCell.matrixCellId
    || executionIdentity.campaignId !== verifiedCell.campaignId
    || executionIdentity.matrixCellId !== verifiedCell.matrixCellId
    || executionIdentity.sourceCommit !== verifiedCell.sourceCommit
    || executionIdentity.toolingCommit !== verifiedCell.toolingCommit
    || executionIdentity.runNonce !== verifiedCell.runNonce
    || executionIdentitySha256V2(executionIdentity)
      !== verifiedCell.executionIdentitySha256
    || evidenceSha256 !== verifiedCell.evidenceSha256
    || verificationResultSha256 !== verifiedCell.verificationResultSha256
    || executionIdentity.runtimeIdentitySha256 !== verifiedCell.runtimeIdentitySha256
    || executionIdentity.gitIdentitySha256 !== verifiedCell.gitIdentitySha256
    || verifiedCell.producerGpgProfileId
      !== gpgAuthorities.signing.profile.profileId
    || verifiedCell.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || verifiedCell.producerSignAssignmentSha256
      !== gpgAuthorities.signing.assignmentSha256
    || verifiedCell.producerLocalVerifierProfileId
      !== gpgAuthorities.localVerification.profile.profileId
    || verifiedCell.producerLocalVerifierProfileSha256
      !== gpgAuthorities.localVerification.profileSha256
    || verifiedCell.producerLocalVerifyAssignmentSha256
      !== gpgAuthorities.localVerification.assignmentSha256
    || executionIdentity.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || evidence.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || verificationResult.producerGpgProfileSha256
      !== gpgAuthorities.signing.profileSha256
    || verifiedCell.verificationRole !== "cell-import-consumer-verify"
    || verifiedCell.consumerVerifierProfileId
      !== consumerAuthority.profile.profileId
    || verifiedCell.consumerVerifierProfileSha256
      !== consumerAuthority.profileSha256
    || verifiedCell.consumerVerifyAssignmentSha256
      !== consumerAuthority.assignmentSha256
    || verifiedCell.consumerImmutableInstallationProfileSha256
      !== consumerAuthority.immutableProfileSha256
  ) failPublicSourceZipCampaign(phase, "swapped-cell-binding");
  for (const key of [
    "semanticInputSetSha256",
    "executionIdentitySha256",
    "platformClassSha256",
    "runtimeClassSha256",
    "artifactSha256",
    "entryPlanSha256",
    "zipVerificationSha256",
  ]) {
    if (verifiedCell[key] !== evidence[key]) {
      failPublicSourceZipCampaign(phase, "cell-evidence-binding");
    }
  }
  return Object.freeze({
    matrixCellId: verifiedCell.matrixCellId,
    verifiedCell,
    evidence,
    verificationResult,
    executionIdentity,
    evidenceSha256,
    verificationResultSha256,
  });
}

function requirePairCommon(left, right) {
  if (
    left.evidence.semanticInputSetSha256 !== right.evidence.semanticInputSetSha256
    || left.evidence.artifactSha256 !== right.evidence.artifactSha256
    || left.evidence.entryPlanSha256 !== right.evidence.entryPlanSha256
    || left.evidence.zipVerificationSha256 !== right.evidence.zipVerificationSha256
    || left.verificationResult.comparisonEligible !== true
    || right.verificationResult.comparisonEligible !== true
    || left.verifiedCell.signatureVerified !== true
    || right.verifiedCell.signatureVerified !== true
  ) failPublicSourceZipCampaign("COMPARISON", "pair-common-authority");
}

function deriveL3(recordsById) {
  const left = recordsById.get("LINUX-A");
  const right = recordsById.get("LINUX-B");
  requirePairCommon(left, right);
  if (
    left.evidence.platformClassSha256 !== right.evidence.platformClassSha256
    || left.evidence.runtimeClassSha256 === right.evidence.runtimeClassSha256
    || left.executionIdentity.runtimeIdentitySha256
      === right.executionIdentity.runtimeIdentitySha256
  ) failPublicSourceZipCampaign("COMPARISON", "l3-derivation");
  return true;
}

function deriveL4(recordsById) {
  const left = recordsById.get("WIN-A");
  const right = recordsById.get("LINUX-A");
  requirePairCommon(left, right);
  if (
    left.evidence.platformClassSha256 === right.evidence.platformClassSha256
    || left.evidence.runtimeClassSha256 !== right.evidence.runtimeClassSha256
    || left.evidence.executionIdentitySha256 === right.evidence.executionIdentitySha256
  ) failPublicSourceZipCampaign("COMPARISON", "l4-derivation");
  return true;
}

function deriveL5(records, requiredIds) {
  for (const matrixCellId of requiredIds) {
    const record = records.find((entry) => entry.matrixCellId === matrixCellId);
    const cell = record.verifiedCell;
    const evidence = record.evidence;
    if (
      cell.d1CanonicalVerificationPassed !== true
      || cell.d2SameProcessPassed !== true
      || cell.d2SameHostPassed !== true
      || cell.boundaryVectorSetPassed !== true
      || cell.privacyGatePassed !== true
      || cell.signatureVerified !== true
      || cell.fileLedgerVerified !== true
      || cell.temporaryRootCleanupVerified !== true
      || cell.environmentBlockerAbsent !== true
      || evidence.canonicalVerifierPassed !== true
      || evidence.sameProcessRepeatable !== true
      || evidence.sameHostRepeatable !== true
      || evidence.boundaryVectorSetPassed !== true
    ) failPublicSourceZipCampaign("COMPARISON", "l5-derivation");
  }
  return true;
}

function requireOptionalWinB(recordsById) {
  if (!recordsById.has("WIN-B")) return;
  const winB = recordsById.get("WIN-B");
  const winA = recordsById.get("WIN-A");
  const linuxB = recordsById.get("LINUX-B");
  requirePairCommon(winB, winA);
  requirePairCommon(winB, linuxB);
  if (
    winB.evidence.platformClassSha256 !== winA.evidence.platformClassSha256
    || winB.evidence.runtimeClassSha256 !== linuxB.evidence.runtimeClassSha256
    || winB.evidence.executionIdentitySha256 === winA.evidence.executionIdentitySha256
    || winB.evidence.executionIdentitySha256 === linuxB.evidence.executionIdentitySha256
  ) failPublicSourceZipCampaign("COMPARISON", "optional-win-b-derivation");
}

export function compareReproducibilityEvidenceV2(options) {
  authority(options);
  exactDataObject(options, COMPARISON_OPTION_KEYS, "COMPARISON", "options");
  const policy = validateCampaignPolicy(options.campaignPolicy);
  authority(options.comparisonNodeAuthority);
  authority(options.comparisonSigningAuthority);
  authority(options.comparisonLocalVerificationAuthority);
  authority(options.independentReviewAuthority);
  const comparisonNode = options.comparisonNodeAuthority;
  const comparisonSigning = options.comparisonSigningAuthority;
  const comparisonLocal = options.comparisonLocalVerificationAuthority;
  const review = options.independentReviewAuthority;
  const expectedComparisonNode = findNodeRuntimeAssignment(policy, {
    campaignRole: "comparison-host",
    matrixCellId: null,
    hostRole: comparisonNode.hostRole,
  });
  const expectedComparisonGpg = findComparisonGpgAuthorities(
    policy,
    comparisonNode.hostRole,
    comparisonSigning.signerRole,
  );
  const expectedReview = findIndependentReviewGpgAuthority(
    policy,
    review.assignment.hostRole,
    comparisonSigning.signerRole,
  );
  if (
    comparisonNode.campaignRole !== "comparison-host"
    || comparisonNode.matrixCellId !== null
    || comparisonNode.profileSha256 !== expectedComparisonNode.profileSha256
    || comparisonNode.assignmentSha256
      !== expectedComparisonNode.assignmentSha256
    || comparisonNode.immutableInstallationProfileSha256
      !== expectedComparisonNode.immutableProfileSha256
    || comparisonNode.qualificationResult?.status !== "qualified"
    || comparisonSigning.gpgRole !== "comparison-result-sign"
    || comparisonSigning.profileSha256
      !== expectedComparisonGpg.signing.profileSha256
    || comparisonSigning.assignmentSha256
      !== expectedComparisonGpg.signing.assignmentSha256
    || comparisonSigning.immutableInstallationProfileSha256
      !== expectedComparisonGpg.signing.immutableProfileSha256
    || comparisonSigning.qualificationResult?.status !== "qualified"
    || comparisonLocal.gpgRole !== "comparison-result-local-verify"
    || comparisonLocal.hostRole !== comparisonNode.hostRole
    || comparisonLocal.profileSha256
      !== expectedComparisonGpg.localVerification.profileSha256
    || comparisonLocal.assignmentSha256
      !== expectedComparisonGpg.localVerification.assignmentSha256
    || comparisonLocal.immutableInstallationProfileSha256
      !== expectedComparisonGpg.localVerification.immutableProfileSha256
    || comparisonLocal.qualificationResult?.status !== "qualified"
    || review.assignmentSha256 !== expectedReview.assignmentSha256
    || review.profileSha256 !== expectedReview.profileSha256
    || review.immutableProfileSha256 !== expectedReview.immutableProfileSha256
  ) failPublicSourceZipCampaign("COMPARISON", "comparison-execution-authority");
  authority(options.cells);
  if (!Array.isArray(options.cells) || ![3, 4].includes(options.cells.length)) {
    failPublicSourceZipCampaign("COMPARISON", "cell-count");
  }
  const policySha256 = campaignPolicySha256(policy);
  const records = options.cells.map((entry) => (
    normalizeCellRecord(entry, policy, policySha256)
  ));
  const ids = records.map((entry) => entry.matrixCellId);
  if (new Set(ids).size !== ids.length) {
    failPublicSourceZipCampaign("COMPARISON", "duplicate-matrix-cell");
  }
  const allowedIds = new Set([
    ...policy.requiredCells.map((entry) => entry.matrixCellId),
    ...policy.optionalCells.map((entry) => entry.matrixCellId),
  ]);
  if (ids.some((entry) => !allowedIds.has(entry))) {
    failPublicSourceZipCampaign("COMPARISON", "unexpected-matrix-cell");
  }
  for (const requiredId of REQUIRED_MATRIX_CELL_IDS) {
    if (!ids.includes(requiredId)) {
      failPublicSourceZipCampaign("COMPARISON", "missing-required-cell");
    }
  }
  if (ids.includes("WIN-B") && !policy.optionalCells.some(
    (entry) => entry.matrixCellId === "WIN-B",
  )) failPublicSourceZipCampaign("COMPARISON", "unauthorized-optional-cell");
  for (const hashes of [
    records.map((entry) => entry.evidenceSha256),
    records.map((entry) => entry.verificationResultSha256),
    records.map((entry) => entry.executionIdentity.runNonce),
    records.map((entry) => entry.verifiedCell.signerFingerprint),
  ]) {
    if (new Set(hashes).size !== hashes.length) {
      failPublicSourceZipCampaign("COMPARISON", "replayed-cell-authority");
    }
  }
  const sorted = [...records].sort((left, right) => (
    Buffer.compare(
      Buffer.from(left.matrixCellId, "utf8"),
      Buffer.from(right.matrixCellId, "utf8"),
    )
  ));
  const recordsById = new Map(sorted.map((entry) => [entry.matrixCellId, entry]));
  const first = sorted[0];
  for (const record of sorted.slice(1)) {
    if (
      record.evidence.semanticInputSetSha256 !== first.evidence.semanticInputSetSha256
      || record.evidence.artifactSha256 !== first.evidence.artifactSha256
      || record.evidence.entryPlanSha256 !== first.evidence.entryPlanSha256
      || record.evidence.zipVerificationSha256 !== first.evidence.zipVerificationSha256
    ) failPublicSourceZipCampaign("COMPARISON", "campaign-byte-identity");
  }
  deriveL3(recordsById);
  deriveL4(recordsById);
  deriveL5(sorted, REQUIRED_MATRIX_CELL_IDS);
  requireOptionalWinB(recordsById);
  const cellAuthorities = sorted.map((record) => Object.freeze({
    matrixCellId: record.matrixCellId,
    runtimeIdentitySha256: record.verifiedCell.runtimeIdentitySha256,
    nodeRuntimeProfileSha256: record.verifiedCell.nodeRuntimeProfileSha256,
    nodeImmutableInstallationProfileSha256:
      record.verifiedCell.nodeImmutableInstallationProfileSha256,
    nodeQualificationResultSha256:
      record.verifiedCell.nodeQualificationResultSha256,
    producerGpgProfileId: record.verifiedCell.producerGpgProfileId,
    producerGpgProfileSha256: record.verifiedCell.producerGpgProfileSha256,
    producerSignAssignmentSha256:
      record.verifiedCell.producerSignAssignmentSha256,
    producerLocalVerifierProfileId:
      record.verifiedCell.producerLocalVerifierProfileId,
    producerLocalVerifierProfileSha256:
      record.verifiedCell.producerLocalVerifierProfileSha256,
    producerLocalVerifyAssignmentSha256:
      record.verifiedCell.producerLocalVerifyAssignmentSha256,
    consumerVerifierProfileId: record.verifiedCell.consumerVerifierProfileId,
    consumerVerifierProfileSha256:
      record.verifiedCell.consumerVerifierProfileSha256,
    consumerVerifyAssignmentSha256:
      record.verifiedCell.consumerVerifyAssignmentSha256,
    consumerHostRole: record.verifiedCell.verificationHostRole,
    consumerNodeRuntimeProfileSha256:
      record.verifiedCell.consumerNodeRuntimeProfileSha256,
    consumerNodeImmutableInstallationProfileSha256:
      record.verifiedCell.consumerNodeImmutableInstallationProfileSha256,
    consumerNodeQualificationResultSha256:
      record.verifiedCell.consumerNodeQualificationResultSha256,
    consumerRuntimeIdentitySha256:
      record.verifiedCell.consumerRuntimeIdentitySha256,
    signatureVerified: record.verifiedCell.signatureVerified,
  }));
  return validateCampaignComparisonResult({
    documentKind: CAMPAIGN_COMPARISON_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    status: "ok",
    mode: "public-source-zip-campaign-comparison",
    campaignId: policy.campaignId,
    sourceCommit: policy.sourceCommit,
    toolingCommit: policy.toolingCommit,
    matrixComplete: true,
    claimAllowed: true,
    claimLevelsSatisfied: [...CLAIM_LEVELS_V2],
    crossRuntimePair: [...policy.claimRules.crossRuntimePair],
    crossOsPair: [...policy.claimRules.crossOsPair],
    artifactSha256: first.evidence.artifactSha256,
    entryPlanSha256: first.evidence.entryPlanSha256,
    zipVerificationSha256: first.evidence.zipVerificationSha256,
    semanticInputSetSha256: first.evidence.semanticInputSetSha256,
    cellAuthorities,
    comparisonNodeRuntimeProfileId: comparisonNode.profileId,
    comparisonNodeRuntimeProfileSha256: comparisonNode.profileSha256,
    comparisonNodeImmutableInstallationProfileSha256:
      comparisonNode.immutableInstallationProfileSha256,
    comparisonNodeQualificationResultSha256:
      comparisonNode.qualificationResultSha256,
    comparisonSignerProfileId: comparisonSigning.profileId,
    comparisonSignerProfileSha256: comparisonSigning.profileSha256,
    comparisonSignAssignmentSha256: comparisonSigning.assignmentSha256,
    comparisonSignerImmutableInstallationProfileSha256:
      comparisonSigning.immutableInstallationProfileSha256,
    comparisonSignQualificationResultSha256:
      comparisonSigning.qualificationResultSha256,
    comparisonLocalVerifierProfileId: comparisonLocal.profileId,
    comparisonLocalVerifierProfileSha256: comparisonLocal.profileSha256,
    comparisonLocalVerifyAssignmentSha256: comparisonLocal.assignmentSha256,
    comparisonLocalVerifierImmutableInstallationProfileSha256:
      comparisonLocal.immutableInstallationProfileSha256,
    comparisonLocalVerifyQualificationResultSha256:
      comparisonLocal.qualificationResultSha256,
    independentReviewVerifierProfileId: review.profile.profileId,
    independentReviewVerifierProfileSha256: review.profileSha256,
    independentReviewVerifyAssignmentSha256: review.assignmentSha256,
    independentReviewVerifierImmutableInstallationProfileSha256:
      review.immutableProfileSha256,
    independentReviewCompleted: false,
    allExecutionProfilesQualified: true,
    requiredCellCount: REQUIRED_MATRIX_CELL_IDS.length,
    acceptedCellCount: sorted.length,
    evidenceSigningRequired: true,
    platformAttestationVerified: false,
    projectPublicationAuthorized: false,
  });
}

function nativeComparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function isMainModule() {
  if (typeof process.argv[1] !== "string" || process.argv[1].length === 0) return false;
  try {
    return nativeComparable(realpathSync.native(fileURLToPath(import.meta.url)))
      === nativeComparable(realpathSync.native(path.resolve(process.argv[1])));
  } catch {
    return false;
  }
}

function parseCli(argv) {
  authority(argv);
  let campaignPolicy = null;
  let comparisonAuthority = null;
  const cellRecords = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (
      !["--campaign-policy", "--cell-record", "--comparison-authority"].includes(argument)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) failPublicSourceZipCampaign("CLI", "unknown-or-incomplete-option");
    const value = argv[index + 1];
    index += 1;
    if (argument === "--campaign-policy") {
      if (campaignPolicy !== null) {
        failPublicSourceZipCampaign("CLI", "duplicate-option");
      }
      campaignPolicy = value;
    } else if (argument === "--comparison-authority") {
      if (comparisonAuthority !== null) {
        failPublicSourceZipCampaign("CLI", "duplicate-option");
      }
      comparisonAuthority = value;
    } else {
      cellRecords.push(value);
    }
  }
  if (
    campaignPolicy === null
    || comparisonAuthority === null
    || ![3, 4].includes(cellRecords.length)
  ) {
    failPublicSourceZipCampaign("CLI", "required-options");
  }
  return Object.freeze({
    campaignPolicy,
    comparisonAuthority,
    cellRecords: Object.freeze(cellRecords),
  });
}

async function readBounded(filePath) {
  const bytes = await readFile(filePath);
  if (bytes.length === 0 || bytes.length > MAX_CLI_DOCUMENT_BYTES) {
    failPublicSourceZipCampaign("CLI", "input-size");
  }
  return bytes;
}

async function main() {
  const cli = parseCli(process.argv.slice(2));
  const policy = parseCanonicalCampaignPolicyBytes(await readBounded(cli.campaignPolicy));
  const comparisonAuthority = parseCanonicalPublicJsonBytes(
    await readBounded(cli.comparisonAuthority),
    "COMPARISON",
  );
  const cells = [];
  for (const cellPath of cli.cellRecords) {
    let record;
    try {
      record = parseCanonicalPublicJsonBytes(await readBounded(cellPath), "COMPARISON");
    } catch {
      failPublicSourceZipCampaign("CLI", "cell-record-canonical");
    }
    cells.push(record);
  }
  const result = compareReproducibilityEvidenceV2({
    campaignPolicy: policy,
    cells,
    comparisonNodeAuthority: comparisonAuthority.comparisonNodeAuthority,
    comparisonSigningAuthority: comparisonAuthority.comparisonSigningAuthority,
    comparisonLocalVerificationAuthority:
      comparisonAuthority.comparisonLocalVerificationAuthority,
    independentReviewAuthority: comparisonAuthority.independentReviewAuthority,
  });
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceZipCampaignError
      ? error
      : new PublicSourceZipCampaignError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
