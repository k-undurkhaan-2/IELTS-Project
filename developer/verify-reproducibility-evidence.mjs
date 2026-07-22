#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  REPRODUCIBILITY_VERIFICATION_KIND,
  SCHEMA_VERSION,
  ReproducibilityEvidenceError,
  bindEvidenceToPolicy,
  deriveComparisonIdentity,
  encodeCanonicalVerificationResult,
  failReproducibility,
  normalizeIdentityTestHooks,
  parseCanonicalMatrixPolicy,
  parseCanonicalReproducibilityEvidence,
  parseCanonicalSemanticReport,
  readStableCanonicalDocument,
  readStableFile,
  requireFileIdentityMatches,
  validateGitRepository,
  validateVerificationResult,
  verifyGitCommitObject,
} from "./reproducibility-evidence-core.mjs";

const REQUIRED_STRING_OPTIONS = Object.freeze([
  "evidence",
  "policy",
  "sourceRepo",
  "toolingRepo",
  "criticalToolSet",
  "manifest",
  "inputSet",
  "runtimeIdentity",
  "gitIdentity",
  "testVectorSet",
  "platformProbe",
]);

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failReproducibility("CLI", "api-options-object");
  }
  const allowed = new Set([
    ...REQUIRED_STRING_OPTIONS,
    "artifact",
    "semanticReport",
    "testHooks",
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failReproducibility("CLI", "api-option-key");
    }
  }
  for (const key of REQUIRED_STRING_OPTIONS) {
    if (typeof options[key] !== "string" || options[key].length === 0) {
      failReproducibility("CLI", "api-required-option");
    }
  }
  for (const key of ["artifact", "semanticReport"]) {
    if (options[key] !== undefined && typeof options[key] !== "string") {
      failReproducibility("CLI", "api-optional-path");
    }
  }
  return Object.freeze({
    evidence: options.evidence,
    policy: options.policy,
    sourceRepo: options.sourceRepo,
    toolingRepo: options.toolingRepo,
    criticalToolSet: options.criticalToolSet,
    manifest: options.manifest,
    inputSet: options.inputSet,
    runtimeIdentity: options.runtimeIdentity,
    gitIdentity: options.gitIdentity,
    testVectorSet: options.testVectorSet,
    platformProbe: options.platformProbe,
    artifact: options.artifact,
    semanticReport: options.semanticReport,
    hooks: normalizeIdentityTestHooks(options.testHooks),
  });
}

async function requireDocumentHash(filePath, expectedSha256, kind, hooks) {
  const identity = await readStableFile(filePath, {
    phase: "FILE_IDENTITY",
    reason: "bound-document",
    kind,
    hooks,
    captureBytes: false,
  });
  if (identity.sha256 !== expectedSha256) {
    failReproducibility("FILE_IDENTITY", "bound-document-hash");
  }
  return true;
}

function requireSemanticAgreement(report, evidence) {
  for (const key of [
    "artifactRole",
    "formatProfile",
    "sourceCommit",
    "toolingCommit",
    "inputSetSha256",
    "artifactSha256",
    "artifactByteLength",
  ]) {
    if (report[key] !== evidence[key]) {
      failReproducibility(
        "SEMANTIC_REPORT_SCHEMA",
        key.replace(/[A-Z]/gu, (character) => "-" + character.toLowerCase()) + "-mismatch",
      );
    }
  }
  if (report.result !== "pass") {
    failReproducibility("SEMANTIC_REPORT_SCHEMA", "pass-evidence-report-result");
  }
  if (!report.canonicalVerifierPassed) {
    failReproducibility("SEMANTIC_REPORT_SCHEMA", "pass-canonical-verifier");
  }
}

async function verifyReproducibilityEvidenceInternal(options) {
  const normalized = validateApiOptions(options);

  const policyInput = await readStableCanonicalDocument(
    normalized.policy,
    "POLICY_SCHEMA",
    "policy",
    normalized.hooks,
  );
  const policy = parseCanonicalMatrixPolicy(policyInput.bytes);

  const evidenceInput = await readStableCanonicalDocument(
    normalized.evidence,
    "EVIDENCE_SCHEMA",
    "evidence",
    normalized.hooks,
  );
  const evidence = parseCanonicalReproducibilityEvidence(evidenceInput.bytes);
  bindEvidenceToPolicy(evidence, policy, policyInput.sha256);

  if (evidence.result === "pass") {
    if (
      typeof normalized.artifact !== "string"
      || typeof normalized.semanticReport !== "string"
    ) {
      failReproducibility("CLI", "pass-artifact-and-semantic-report-required");
    }
  } else if (normalized.artifact !== undefined || normalized.semanticReport !== undefined) {
    failReproducibility("CLI", "failure-artifact-or-semantic-report-forbidden");
  }

  const sourceRepo = await validateGitRepository(normalized.sourceRepo, "GIT");
  const toolingRepo = await validateGitRepository(normalized.toolingRepo, "GIT");
  verifyGitCommitObject(sourceRepo, evidence.sourceCommit, "GIT");
  verifyGitCommitObject(toolingRepo, evidence.toolingCommit, "GIT");

  await requireDocumentHash(
    normalized.criticalToolSet,
    evidence.criticalToolSetSha256,
    "critical-tool-set",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.manifest,
    evidence.manifestSha256,
    "manifest",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.inputSet,
    evidence.inputSetSha256,
    "input-set",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.runtimeIdentity,
    evidence.runtimeIdentitySha256,
    "runtime-identity",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.gitIdentity,
    evidence.gitIdentitySha256,
    "git-identity",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.testVectorSet,
    evidence.testVectorSetSha256,
    "test-vector-set",
    normalized.hooks,
  );
  await requireDocumentHash(
    normalized.platformProbe,
    evidence.platformProbeSha256,
    "platform-probe",
    normalized.hooks,
  );

  let artifactVerified = false;
  let semanticReportVerified = false;
  let semanticClaimsBound = false;
  let canonicalVerifierPassed = null;
  let sameProcessRepeatable = null;
  let sameHostRepeatable = null;
  let boundaryVectorSetPassed = null;

  if (evidence.result === "pass") {
    const artifactInput = await readStableFile(normalized.artifact, {
      phase: "ARTIFACT_IDENTITY",
      reason: "artifact",
      kind: "artifact",
      hooks: normalized.hooks,
      captureBytes: false,
    });
    requireFileIdentityMatches(
      artifactInput,
      evidence.artifactSha256,
      evidence.artifactByteLength,
      "ARTIFACT_IDENTITY",
      "artifact-mismatch",
    );
    artifactVerified = true;

    const semanticInput = await readStableCanonicalDocument(
      normalized.semanticReport,
      "SEMANTIC_REPORT_SCHEMA",
      "semantic-report",
      normalized.hooks,
    );
    requireFileIdentityMatches(
      semanticInput,
      evidence.semanticReportSha256,
      evidence.semanticReportByteLength,
      "SEMANTIC_REPORT_SCHEMA",
      "semantic-report-identity-mismatch",
    );
    const semanticReport = parseCanonicalSemanticReport(semanticInput.bytes);
    requireSemanticAgreement(semanticReport, evidence);
    semanticReportVerified = true;
    semanticClaimsBound = true;
    canonicalVerifierPassed = semanticReport.canonicalVerifierPassed;
    sameProcessRepeatable = semanticReport.sameProcessRepeatable;
    sameHostRepeatable = semanticReport.sameHostRepeatable;
    boundaryVectorSetPassed = semanticReport.boundaryVectorSetPassed;
  }

  const comparisonIdentitySha256 = deriveComparisonIdentity({
    artifactRole: evidence.artifactRole,
    formatProfile: evidence.formatProfile,
    sourceCommit: evidence.sourceCommit,
    toolingCommit: evidence.toolingCommit,
    criticalToolSetSha256: evidence.criticalToolSetSha256,
    manifestSha256: evidence.manifestSha256,
    inputSetSha256: evidence.inputSetSha256,
    runnerPolicySha256: evidence.runnerPolicySha256,
    testVectorSetSha256: evidence.testVectorSetSha256,
  });

  return validateVerificationResult({
    verificationKind: REPRODUCIBILITY_VERIFICATION_KIND,
    schemaVersion: SCHEMA_VERSION,
    status: "ok",
    mode: "reproducibility-evidence-verification",
    policyId: policy.policyId,
    artifactRole: evidence.artifactRole,
    formatProfile: evidence.formatProfile,
    matrixCellId: evidence.matrixCellId,
    evidenceSha256: evidenceInput.sha256,
    evidenceByteLength: evidenceInput.byteLength,
    policySha256: policyInput.sha256,
    comparisonIdentitySha256,
    sourceCommitObjectVerified: true,
    toolingCommitObjectVerified: true,
    criticalToolSetVerified: true,
    manifestVerified: true,
    inputSetVerified: true,
    runtimeIdentityVerified: true,
    gitIdentityVerified: true,
    testVectorSetVerified: true,
    platformProbeVerified: true,
    artifactVerified,
    semanticReportVerified,
    policyCellVerified: true,
    semanticClaimsBound,
    canonicalVerifierPassed,
    sameProcessRepeatable,
    sameHostRepeatable,
    boundaryVectorSetPassed,
    semanticClaimsIndependentlyReplayed: false,
    evidenceResult: evidence.result,
    comparisonEligible: evidence.result === "pass",
    platformAttestationVerified: false,
    evidenceSigningRequired: true,
    projectPublicationAuthorized: false,
  });
}

export async function verifyReproducibilityEvidence(options = {}) {
  return verifyReproducibilityEvidenceInternal(options);
}

function parseOptions(argv) {
  const flagToOption = new Map([
    ["--evidence", "evidence"],
    ["--policy", "policy"],
    ["--source-repo", "sourceRepo"],
    ["--tooling-repo", "toolingRepo"],
    ["--critical-tool-set", "criticalToolSet"],
    ["--manifest", "manifest"],
    ["--input-set", "inputSet"],
    ["--runtime-identity", "runtimeIdentity"],
    ["--git-identity", "gitIdentity"],
    ["--test-vector-set", "testVectorSet"],
    ["--platform-probe", "platformProbe"],
    ["--artifact", "artifact"],
    ["--semantic-report", "semanticReport"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const option = flagToOption.get(argument);
    if (
      option === undefined
      || Object.hasOwn(result, option)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      failReproducibility("CLI", "unknown-or-duplicate-option");
    }
    result[option] = argv[index + 1];
    index += 1;
  }
  if (REQUIRED_STRING_OPTIONS.some((key) => !Object.hasOwn(result, key))) {
    failReproducibility("CLI", "required-options");
  }
  return Object.freeze(result);
}

async function main() {
  const result = await verifyReproducibilityEvidenceInternal(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(encodeCanonicalVerificationResult(result));
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
