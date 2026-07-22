#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  REPRODUCIBILITY_COMPARISON_KIND,
  SCHEMA_VERSION,
  ReproducibilityEvidenceError,
  bindEvidenceToPolicy,
  compareUnsignedUtf8,
  comparisonIdentityFromEvidence,
  deriveClaimLevels,
  encodeCanonicalComparisonReport,
  failReproducibility,
  normalizeIdentityTestHooks,
  parseCanonicalMatrixPolicy,
  parseCanonicalReproducibilityEvidence,
  parseCanonicalVerificationResult,
  readStableCanonicalDocument,
  validateComparisonReport,
} from "./reproducibility-evidence-core.mjs";

const VERIFIED_RUN_KEYS = Object.freeze(["evidence", "verificationResult"]);

function exactRunKeys(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failReproducibility("CLI", "verified-run-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== VERIFIED_RUN_KEYS.length
    || actual.some((key, index) => key !== VERIFIED_RUN_KEYS[index])
  ) {
    failReproducibility("CLI", "verified-run-keys");
  }
  for (const key of VERIFIED_RUN_KEYS) {
    if (typeof value[key] !== "string" || value[key].length === 0) {
      failReproducibility("CLI", "verified-run-path");
    }
  }
  return Object.freeze({
    evidence: value.evidence,
    verificationResult: value.verificationResult,
  });
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failReproducibility("CLI", "api-options-object");
  }
  const allowed = new Set(["policy", "verifiedRuns", "testHooks"]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failReproducibility("CLI", "api-option-key");
    }
  }
  if (typeof options.policy !== "string" || options.policy.length === 0) {
    failReproducibility("CLI", "api-policy-option");
  }
  if (
    !Array.isArray(options.verifiedRuns)
    || options.verifiedRuns.length === 0
    || options.verifiedRuns.length > 4096
  ) {
    failReproducibility("CLI", "verified-run-count");
  }
  return Object.freeze({
    policy: options.policy,
    verifiedRuns: Object.freeze(options.verifiedRuns.map(exactRunKeys)),
    hooks: normalizeIdentityTestHooks(options.testHooks),
  });
}

function requirePairBinding(pair, policy, policyInput) {
  bindEvidenceToPolicy(pair.evidence, policy, policyInput.sha256);
  const result = pair.verification;
  const evidence = pair.evidence;
  const expectedComparisonIdentity = comparisonIdentityFromEvidence(evidence);
  const equalityChecks = [
    [result.policyId, policy.policyId, "policy-id"],
    [result.artifactRole, evidence.artifactRole, "artifact-role"],
    [result.formatProfile, evidence.formatProfile, "format-profile"],
    [result.matrixCellId, evidence.matrixCellId, "matrix-cell-id"],
    [result.evidenceSha256, pair.evidenceInput.sha256, "evidence-sha256"],
    [result.evidenceByteLength, pair.evidenceInput.byteLength, "evidence-byte-length"],
    [result.policySha256, policyInput.sha256, "policy-sha256"],
    [
      result.comparisonIdentitySha256,
      expectedComparisonIdentity,
      "comparison-identity-sha256",
    ],
    [result.evidenceResult, evidence.result, "evidence-result"],
  ];
  for (const [actual, expected, reason] of equalityChecks) {
    if (actual !== expected) {
      failReproducibility("COMPARISON", reason + "-mismatch");
    }
  }
  if (evidence.result === "pass") {
    if (
      !result.comparisonEligible
      || !result.semanticReportVerified
      || !result.semanticClaimsBound
      || result.semanticClaimsIndependentlyReplayed
      || typeof result.canonicalVerifierPassed !== "boolean"
      || typeof result.sameProcessRepeatable !== "boolean"
      || typeof result.sameHostRepeatable !== "boolean"
      || typeof result.boundaryVectorSetPassed !== "boolean"
    ) {
      failReproducibility("COMPARISON", "pass-verification-binding");
    }
  } else if (
    result.comparisonEligible
    || result.semanticReportVerified
    || result.semanticClaimsBound
    || result.canonicalVerifierPassed !== null
    || result.sameProcessRepeatable !== null
    || result.sameHostRepeatable !== null
    || result.boundaryVectorSetPassed !== null
  ) {
    failReproducibility("COMPARISON", "failure-verification-binding");
  }
  if (
    result.platformAttestationVerified
    || !result.evidenceSigningRequired
    || result.projectPublicationAuthorized
  ) {
    failReproducibility("COMPARISON", "authority-overstatement");
  }
  return expectedComparisonIdentity;
}

function reasonForMissingClaim(level) {
  return Object.freeze({
    L1: "same-process-repeatability-required",
    L2: "same-host-repeatability-required",
    L3: "cross-runtime-evidence-required",
    L4: "cross-operating-system-evidence-required",
    L5: "boundary-vector-evidence-required",
    L6: "interoperability-evidence-required",
  })[level];
}

async function compareReproducibilityEvidenceInternal(options) {
  const normalized = validateApiOptions(options);
  const policyInput = await readStableCanonicalDocument(
    normalized.policy,
    "POLICY_SCHEMA",
    "policy",
    normalized.hooks,
  );
  const policy = parseCanonicalMatrixPolicy(policyInput.bytes);

  const pairs = [];
  const seenCells = new Set();
  const seenEvidenceHashes = new Set();
  const seenVerificationHashes = new Set();
  for (const run of normalized.verifiedRuns) {
    const evidenceInput = await readStableCanonicalDocument(
      run.evidence,
      "EVIDENCE_SCHEMA",
      "evidence",
      normalized.hooks,
    );
    const verificationInput = await readStableCanonicalDocument(
      run.verificationResult,
      "VERIFICATION_RESULT_SCHEMA",
      "verification-result",
      normalized.hooks,
    );
    const evidence = parseCanonicalReproducibilityEvidence(evidenceInput.bytes);
    const verification = parseCanonicalVerificationResult(verificationInput.bytes);
    if (seenCells.has(evidence.matrixCellId)) {
      failReproducibility("COMPARISON", "duplicate-matrix-cell");
    }
    if (seenEvidenceHashes.has(evidenceInput.sha256)) {
      failReproducibility("COMPARISON", "duplicate-evidence-record");
    }
    if (seenVerificationHashes.has(verificationInput.sha256)) {
      failReproducibility("COMPARISON", "duplicate-verification-result");
    }
    const pair = Object.freeze({
      evidence,
      verification,
      evidenceInput,
      verificationInput,
    });
    const comparisonIdentitySha256 = requirePairBinding(
      pair, policy, policyInput,
    );
    seenCells.add(evidence.matrixCellId);
    seenEvidenceHashes.add(evidenceInput.sha256);
    seenVerificationHashes.add(verificationInput.sha256);
    pairs.push(Object.freeze({ ...pair, comparisonIdentitySha256 }));
  }

  pairs.sort((left, right) => compareUnsignedUtf8(
    left.evidence.matrixCellId, right.evidence.matrixCellId,
  ));
  const requiredIds = new Set(policy.requiredCells.map((cell) => cell.matrixCellId));
  const optionalIds = new Set(policy.optionalCells.map((cell) => cell.matrixCellId));
  const presentRequiredCellCount = pairs.filter(
    (pair) => requiredIds.has(pair.evidence.matrixCellId),
  ).length;
  const presentOptionalCellCount = pairs.filter(
    (pair) => optionalIds.has(pair.evidence.matrixCellId),
  ).length;
  const matrixComplete = presentRequiredCellCount === policy.requiredCells.length;
  const passPairs = pairs.filter((pair) => pair.evidence.result === "pass");
  const firstPass = passPairs[0] ?? null;
  const claims = deriveClaimLevels(policy, pairs);

  const reasons = new Set();
  if (pairs.some((pair) => pair.evidence.result === "fail")) {
    reasons.add("evidence-failure");
  }
  if (!matrixComplete) reasons.add("missing-required-cell");
  if (!claims.sameArtifactBytes) reasons.add("artifact-identity-mismatch");
  if (!claims.sameSemanticReport) reasons.add("semantic-report-identity-mismatch");
  if (!claims.sameComparisonIdentity) reasons.add("comparison-identity-mismatch");
  for (const level of policy.requiredClaimLevels) {
    if (!claims.claimLevelsSatisfied.includes(level)) {
      const reason = reasonForMissingClaim(level);
      if (reason) reasons.add(reason);
    }
  }
  const reasonOrder = [
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
  ];
  const orderedReasons = reasonOrder.filter((reason) => reasons.has(reason));
  const claimAllowed = orderedReasons.length === 0
    && policy.requiredClaimLevels.every(
      (level) => claims.claimLevelsSatisfied.includes(level),
    );

  return validateComparisonReport({
    comparisonKind: REPRODUCIBILITY_COMPARISON_KIND,
    schemaVersion: SCHEMA_VERSION,
    status: claimAllowed ? "ok" : "blocked",
    mode: "reproducibility-evidence-comparison",
    claimScope: "controlled-runner-matrix-evidence",
    policyId: policy.policyId,
    artifactRole: policy.artifactRole,
    formatProfile: policy.formatProfile,
    policySha256: policyInput.sha256,
    comparisonIdentitySha256: pairs[0].comparisonIdentitySha256,
    evidenceRecordSha256s: pairs.map((pair) => pair.evidenceInput.sha256),
    verificationResultSha256s: pairs.map(
      (pair) => pair.verificationInput.sha256,
    ),
    requiredCellCount: policy.requiredCells.length,
    presentRequiredCellCount,
    optionalCellCount: policy.optionalCells.length,
    presentOptionalCellCount,
    artifactSha256: firstPass ? firstPass.evidence.artifactSha256 : null,
    artifactByteLength: firstPass ? firstPass.evidence.artifactByteLength : null,
    semanticReportSha256: firstPass ? firstPass.evidence.semanticReportSha256 : null,
    semanticReportByteLength: firstPass
      ? firstPass.evidence.semanticReportByteLength
      : null,
    sameArtifactBytes: claims.sameArtifactBytes,
    sameSemanticReport: claims.sameSemanticReport,
    matrixComplete,
    claimLevelsSatisfied: claims.claimLevelsSatisfied,
    requiredClaimLevels: policy.requiredClaimLevels,
    highestClaimLevel: claims.claimLevelsSatisfied.at(-1) ?? null,
    claimAllowed,
    platformAttestationVerified: false,
    evidenceSigningRequired: true,
    projectPublicationAuthorized: false,
    reasons: orderedReasons,
  });
}

export async function compareReproducibilityEvidence(options = {}) {
  return compareReproducibilityEvidenceInternal(options);
}

function parseOptions(argv) {
  let policy;
  const verifiedRuns = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--policy") {
      if (
        policy !== undefined
        || index + 1 >= argv.length
        || argv[index + 1].startsWith("--")
      ) {
        failReproducibility("CLI", "policy-option");
      }
      policy = argv[index + 1];
      index += 1;
      continue;
    }
    if (argument === "--verified-run") {
      if (
        index + 2 >= argv.length
        || argv[index + 1].startsWith("--")
        || argv[index + 2].startsWith("--")
      ) {
        failReproducibility("CLI", "verified-run-arity");
      }
      verifiedRuns.push(Object.freeze({
        evidence: argv[index + 1],
        verificationResult: argv[index + 2],
      }));
      index += 2;
      continue;
    }
    failReproducibility("CLI", "unknown-or-positional-option");
  }
  if (policy === undefined || verifiedRuns.length === 0) {
    failReproducibility("CLI", "required-options");
  }
  return Object.freeze({ policy, verifiedRuns: Object.freeze(verifiedRuns) });
}

async function main() {
  const result = await compareReproducibilityEvidenceInternal(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(encodeCanonicalComparisonReport(result));
  if (!result.claimAllowed) process.exitCode = 2;
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const argvEntry = process.argv[1];
  if (typeof argvEntry !== "string" || argvEntry.length === 0) return false;
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(argvEntry));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof ReproducibilityEvidenceError
      ? error
      : new ReproducibilityEvidenceError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
