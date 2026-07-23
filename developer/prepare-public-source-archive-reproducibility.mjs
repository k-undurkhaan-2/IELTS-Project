#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import {
  ARTIFACT_ROLE,
  FORMAT_PROFILE,
  ADAPTER_MODE,
  COMPLETION_MARKER,
  PublicSourceArchiveReproducibilityError,
  asAdapterError,
  buildCanonicalInputSet,
  buildEvidenceBytes,
  buildSemanticReportBytes,
  cleanupOwnedLedger,
  createExclusiveOutputDirectory,
  createOwnedDirectory,
  deepFreezeAdapter,
  encodeB3VerificationTranscript,
  failureClassFor,
  installControlledGitPath,
  publishArchiveNoReplace,
  readAdapterCanonicalDocument,
  readAndParseMatrixPolicy,
  removeEmptyOutputDirectory,
  resolveControlledGitExecutable,
  runHostCapabilityProbe,
  runSameHostRepetitions,
  runSameProcessRepetitions,
  selectPolicyCell,
  validateCriticalToolSet,
  validateGitIdentity,
  validateMeasuredCapabilities,
  validatePlatformProbeShape,
  validateRepositoryCommit,
  validateRuntimeIdentity,
  verifyPublishedArchive,
  writeOwnedFile,
} from "./public-source-archive-reproducibility-core.mjs";
import {
  encodeCanonicalVerificationResult,
  sha256Bytes,
} from "./reproducibility-evidence-core.mjs";
import { verifyReproducibilityEvidence } from "./verify-reproducibility-evidence.mjs";
import {
  PublicSourceArchiveBoundaryVectorError,
  runPublicSourceArchiveBoundaryVectors,
  validatePublicSourceArchiveBoundaryVectorSet,
} from "./run-public-source-archive-boundary-vectors.mjs";

const OPTION_KEYS = Object.freeze([
  "sourceRepo",
  "toolingRepo",
  "policy",
  "matrixCellId",
  "criticalToolSet",
  "runtimeIdentity",
  "gitIdentity",
  "platformProbe",
  "testVectorSet",
  "outputDirectory",
]);

const OUTPUT_NAMES = Object.freeze({
  artifact: "artifact.tar",
  manifest: "b1-membership-report.json",
  inputSet: "input-set.json",
  transcript: "b3-verification.json",
  semantic: "semantic-report.json",
  evidence: "evidence.json",
  verification: "verification-result.json",
  marker: ".complete",
});

function fail(phase, reason) {
  throw new PublicSourceArchiveReproducibilityError(phase, reason);
}

function validateOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    fail("CLI", "api-options-invalid");
  }
  const actual = Object.keys(options);
  if (
    actual.length !== OPTION_KEYS.length
    || actual.some((key) => !OPTION_KEYS.includes(key))
    || OPTION_KEYS.some((key) => !Object.hasOwn(options, key))
  ) fail("CLI", "api-options-invalid");
  for (const key of OPTION_KEYS) {
    if (typeof options[key] !== "string" || options[key].length === 0) {
      fail("CLI", "api-options-invalid");
    }
  }
  for (const key of OPTION_KEYS.filter((entry) => entry !== "matrixCellId")) {
    if (!path.isAbsolute(options[key]) || path.resolve(options[key]) !== options[key]) {
      fail("CLI", "api-path-invalid");
    }
  }
  return Object.freeze(Object.fromEntries(OPTION_KEYS.map((key) => [key, options[key]])));
}

function requirePolicyBindings({
  policyDocument,
  criticalToolSet,
  runtimeIdentity,
  gitIdentity,
  platformProbe,
  vectorAuthority,
  cell,
}) {
  const policy = policyDocument.value;
  if (
    policy.sourceCommit === policy.toolingCommit
    || criticalToolSet.sha256 !== policy.criticalToolSetSha256
    || runtimeIdentity.sha256 !== cell.runtimeIdentitySha256
    || gitIdentity.sha256 !== cell.gitIdentitySha256
    || platformProbe.sha256 !== cell.platformProbeSha256
    || vectorAuthority.sha256 !== policy.testVectorSetSha256
  ) fail("POLICY_BINDING", "document-hash-mismatch");
}

function requireBoundaryResult(result, expectedSha256) {
  const keys = [
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
  ];
  const actual = Object.keys(result);
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
    || result.status !== "ok"
    || result.mode !== "public-source-archive-boundary-vectors"
    || result.artifactRole !== ARTIFACT_ROLE
    || result.formatProfile !== FORMAT_PROFILE
    || result.testVectorSetSha256 !== expectedSha256
    || result.vectorCount !== 52
    || result.passedCount !== 52
    || result.failedCount !== 0
    || result.boundaryVectorSetPassed !== true
  ) fail("BOUNDARY_VECTOR", "boundary-vector-failed");
}

function requireR1Verification(result, expectedResult) {
  if (
    !result
    || typeof result !== "object"
    || result.status !== "ok"
    || result.mode !== "reproducibility-evidence-verification"
    || result.evidenceResult !== expectedResult
    || result.semanticClaimsIndependentlyReplayed !== false
    || result.platformAttestationVerified !== false
    || result.evidenceSigningRequired !== true
    || result.projectPublicationAuthorized !== false
  ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
  if (expectedResult === "pass") {
    if (
      result.comparisonEligible !== true
      || result.semanticClaimsBound !== true
      || result.canonicalVerifierPassed !== true
      || result.sameProcessRepeatable !== true
      || result.sameHostRepeatable !== true
      || result.boundaryVectorSetPassed !== true
    ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
  } else if (
    result.comparisonEligible !== false
    || result.semanticClaimsBound !== false
    || result.canonicalVerifierPassed !== null
    || result.sameProcessRepeatable !== null
    || result.sameHostRepeatable !== null
    || result.boundaryVectorSetPassed !== null
  ) fail("R1_10A_VERIFICATION", "r1-10a-result-invalid");
}

async function stageCanonicalDocuments({
  staging,
  ledger,
  manifestBytes,
  inputSetBytes,
  semanticBytes = null,
  evidenceBytes,
}) {
  const records = {
    manifest: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.manifest,
      manifestBytes,
      ledger,
    ),
    inputSet: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.inputSet,
      inputSetBytes,
      ledger,
    ),
  };
  if (semanticBytes !== null) {
    records.semantic = await writeOwnedFile(
      staging,
      OUTPUT_NAMES.semantic,
      semanticBytes,
      ledger,
    );
  }
  records.evidence = await writeOwnedFile(
    staging,
    OUTPUT_NAMES.evidence,
    evidenceBytes,
    ledger,
  );
  return Object.freeze(records);
}

function verifierOptions(context, staged, evidencePath, additions = {}) {
  return {
    evidence: evidencePath,
    policy: context.options.policy,
    sourceRepo: context.options.sourceRepo,
    toolingRepo: context.options.toolingRepo,
    criticalToolSet: context.options.criticalToolSet,
    manifest: staged.manifest.path,
    inputSet: staged.inputSet.path,
    runtimeIdentity: context.options.runtimeIdentity,
    gitIdentity: context.options.gitIdentity,
    testVectorSet: context.options.testVectorSet,
    platformProbe: context.options.platformProbe,
    ...additions,
  };
}

async function writeSuccessBundle({
  context,
  outputDirectory,
  outputLedger,
  candidate,
  transcriptBytes,
  semanticBytes,
  evidenceBytes,
  verificationBytes,
}) {
  const artifact = await publishArchiveNoReplace(
    outputDirectory,
    candidate,
    outputLedger,
  );
  return Object.freeze({
    artifact,
    manifest: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.manifest,
      context.membership.reportBytes,
      outputLedger,
    ),
    inputSet: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.inputSet,
      context.inputSet.bytes,
      outputLedger,
    ),
    transcript: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.transcript,
      transcriptBytes,
      outputLedger,
    ),
    semantic: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.semantic,
      semanticBytes,
      outputLedger,
    ),
    evidence: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.evidence,
      evidenceBytes,
      outputLedger,
    ),
    verification: await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.verification,
      verificationBytes,
      outputLedger,
    ),
  });
}

async function writeFailureBundle({
  context,
  outputDirectory,
  failure,
}) {
  if (failure.phase === "CLEANUP") throw failure;
  const privateLedger = [];
  const outputLedger = [];
  try {
    const privateRoot = await createOwnedDirectory(
      outputDirectory,
      "failure-staging",
      privateLedger,
    );
    const evidenceBytes = buildEvidenceBytes({
      policy: context.policyDocument.value,
      policySha256: context.policyDocument.sha256,
      cell: context.cell,
      result: "fail",
      failureClass: failureClassFor(failure),
      failureCode: failure.reason,
    });
    const staged = await stageCanonicalDocuments({
      staging: privateRoot,
      ledger: privateLedger,
      manifestBytes: context.membership.reportBytes,
      inputSetBytes: context.inputSet.bytes,
      evidenceBytes,
    });
    let verification;
    try {
      verification = await verifyReproducibilityEvidence(
        verifierOptions(context, staged, staged.evidence.path),
      );
    } catch {
      fail("R1_10A_VERIFICATION", "r1-10a-failure-verification");
    }
    requireR1Verification(verification, "fail");
    const verificationBytes = encodeCanonicalVerificationResult(verification);
    await cleanupOwnedLedger(privateLedger);
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.manifest,
      context.membership.reportBytes,
      outputLedger,
    );
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.inputSet,
      context.inputSet.bytes,
      outputLedger,
    );
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.evidence,
      evidenceBytes,
      outputLedger,
    );
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.verification,
      verificationBytes,
      outputLedger,
    );
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.marker,
      Buffer.from(COMPLETION_MARKER, "ascii"),
      outputLedger,
    );
    return buildPublicResult({
      context,
      runResult: "fail",
      evidenceBytes,
      verificationBytes,
      failureClass: failureClassFor(failure),
      failureCode: failure.reason,
    });
  } catch (error) {
    try { await cleanupOwnedLedger(outputLedger); } catch { /* reported below */ }
    try { await cleanupOwnedLedger(privateLedger); } catch {
      throw new PublicSourceArchiveReproducibilityError(
        "CLEANUP",
        "cleanup-incomplete",
      );
    }
    throw asAdapterError(error, "OUTPUT_PUBLICATION", "failure-bundle-write");
  }
}

function buildPublicResult({
  context,
  runResult,
  artifactSha256 = null,
  artifactByteLength = null,
  semanticBytes = null,
  evidenceBytes,
  verificationBytes,
  failureClass = null,
  failureCode = null,
}) {
  const passing = runResult === "pass";
  return deepFreezeAdapter({
    status: passing ? "ok" : "failed",
    mode: ADAPTER_MODE,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    matrixCellId: context.cell.matrixCellId,
    sourceCommit: context.policyDocument.value.sourceCommit,
    toolingCommit: context.policyDocument.value.toolingCommit,
    membershipCount: context.membership.members.length,
    artifactSha256,
    artifactByteLength,
    semanticReportSha256: semanticBytes === null ? null : sha256Bytes(semanticBytes),
    evidenceSha256: sha256Bytes(evidenceBytes),
    verificationResultSha256: sha256Bytes(verificationBytes),
    canonicalVerifierPassed: passing ? true : null,
    sameProcessRepeatable: passing ? true : null,
    sameHostRepeatable: passing ? true : null,
    boundaryVectorSetPassed: passing ? true : null,
    comparisonEligible: passing,
    semanticClaimsIndependentlyReplayed: false,
    platformAttestationVerified: false,
    evidenceSigningRequired: true,
    projectPublicationAuthorized: false,
    runResult,
    failureClass,
    failureCode,
  });
}

export async function preparePublicSourceArchiveReproducibility(options) {
  const normalized = validateOptions(options);
  let restoreGitPath = null;
  let outputDirectory = null;
  let privateLedger = [];
  let outputLedger = [];
  let context = null;
  try {
    const policyDocument = await readAndParseMatrixPolicy(normalized.policy);
    const cell = selectPolicyCell(policyDocument.value, normalized.matrixCellId);
    const git = await resolveControlledGitExecutable();
    restoreGitPath = installControlledGitPath(git);

    await validateRepositoryCommit(
      normalized.sourceRepo,
      policyDocument.value.sourceCommit,
      git,
      "SOURCE_BINDING",
    );
    await validateRepositoryCommit(
      normalized.toolingRepo,
      policyDocument.value.toolingCommit,
      git,
      "TOOLING_BINDING",
    );

    const [criticalToolSet, runtimeIdentity, gitIdentity, platformProbe] =
      await Promise.all([
        readAdapterCanonicalDocument(
          normalized.criticalToolSet,
          "TOOLING_BINDING",
          "critical-tool-set",
        ),
        readAdapterCanonicalDocument(
          normalized.runtimeIdentity,
          "RUNTIME_BINDING",
          "runtime-identity",
        ),
        readAdapterCanonicalDocument(
          normalized.gitIdentity,
          "GIT_BINDING",
          "git-identity",
        ),
        readAdapterCanonicalDocument(
          normalized.platformProbe,
          "PLATFORM_PROBE",
          "platform-probe",
        ),
      ]);
    const vectorAuthority =
      await validatePublicSourceArchiveBoundaryVectorSet({
        testVectorSet: normalized.testVectorSet,
        expectedSha256: policyDocument.value.testVectorSetSha256,
      });
    requirePolicyBindings({
      policyDocument,
      criticalToolSet,
      runtimeIdentity,
      gitIdentity,
      platformProbe,
      vectorAuthority,
      cell,
    });
    await validateCriticalToolSet({
      document: criticalToolSet,
      toolingRepo: normalized.toolingRepo,
      toolingCommit: policyDocument.value.toolingCommit,
      git,
    });
    await validateRuntimeIdentity(runtimeIdentity, cell);
    validateGitIdentity(gitIdentity, cell, git);
    const platformProbeValue = validatePlatformProbeShape(
      platformProbe,
      cell,
      runtimeIdentity.sha256,
      gitIdentity.sha256,
    );

    outputDirectory = await createExclusiveOutputDirectory({
      outputDirectory: normalized.outputDirectory,
      sourceRepo: normalized.sourceRepo,
      toolingRepo: normalized.toolingRepo,
    });
    const privateRoot = await createOwnedDirectory(
      outputDirectory,
      "private-run",
      privateLedger,
    );

    let membership;
    try {
      membership = await loadValidatedPublicSourceMembership({
        repo: normalized.sourceRepo,
        commit: policyDocument.value.sourceCommit,
      });
    } catch {
      fail("SOURCE_BINDING", "b1-membership-invalid");
    }
    const inputSet = buildCanonicalInputSet(membership);
    if (
      inputSet.membershipReportSha256 !== policyDocument.value.manifestSha256
      || inputSet.sha256 !== policyDocument.value.inputSetSha256
    ) fail("POLICY_BINDING", "source-document-hash-mismatch");

    context = Object.freeze({
      options: normalized,
      policyDocument,
      cell,
      membership,
      inputSet,
      git,
    });

    const measuredCapabilities = await runHostCapabilityProbe(
      privateRoot,
      privateLedger,
    );
    validateMeasuredCapabilities(platformProbeValue, measuredCapabilities);

    const sameProcess = await runSameProcessRepetitions({
      sourceRepo: normalized.sourceRepo,
      sourceCommit: policyDocument.value.sourceCommit,
      privateRoot,
      ledger: privateLedger,
    });
    const sameHost = await runSameHostRepetitions({
      sourceRepo: normalized.sourceRepo,
      toolingRepo: normalized.toolingRepo,
      sourceCommit: policyDocument.value.sourceCommit,
      toolingCommit: policyDocument.value.toolingCommit,
      policySha256: policyDocument.sha256,
      matrixCellId: cell.matrixCellId,
      criticalToolSetSha256: criticalToolSet.sha256,
      runtimeIdentitySha256: runtimeIdentity.sha256,
      gitIdentitySha256: gitIdentity.sha256,
      platformProbeSha256: platformProbe.sha256,
      testVectorSetSha256: vectorAuthority.sha256,
      membershipReportSha256: inputSet.membershipReportSha256,
      inputSetSha256: inputSet.sha256,
      privateRoot,
      ledger: privateLedger,
      git,
      sameProcess,
    });
    if (!sameProcess.sameProcessRepeatable || !sameHost.sameHostRepeatable) {
      fail("SAME_HOST", "same-host-mismatch");
    }

    let boundaryResult;
    try {
      boundaryResult = await runPublicSourceArchiveBoundaryVectors({
        testVectorSet: normalized.testVectorSet,
        temporaryParent: privateRoot.path,
        expectedSha256: policyDocument.value.testVectorSetSha256,
      });
    } catch (error) {
      if (error instanceof PublicSourceArchiveBoundaryVectorError) {
        fail("BOUNDARY_VECTOR", "boundary-vector-failed");
      }
      throw error;
    }
    requireBoundaryResult(boundaryResult, policyDocument.value.testVectorSetSha256);

    const candidate = sameProcess.outputs[0];
    const transcriptBytes = encodeB3VerificationTranscript(
      candidate.verification,
      policyDocument.value.sourceCommit,
    );
    if (
      !sameProcess.outputs.every((entry) => entry.transcript.equals(transcriptBytes))
      || !sameHost.outputs.every((entry) => entry.transcript.equals(transcriptBytes))
    ) fail("ARCHIVE_VERIFICATION", "b3-transcript-mismatch");

    const semanticBytes = buildSemanticReportBytes({
      sourceCommit: policyDocument.value.sourceCommit,
      toolingCommit: policyDocument.value.toolingCommit,
      inputSetSha256: inputSet.sha256,
      artifactSha256: candidate.verification.archiveSha256,
      artifactByteLength: candidate.verification.archiveByteLength,
    });
    const evidenceBytes = buildEvidenceBytes({
      policy: policyDocument.value,
      policySha256: policyDocument.sha256,
      cell,
      result: "pass",
      artifactSha256: candidate.verification.archiveSha256,
      artifactByteLength: candidate.verification.archiveByteLength,
      semanticReportSha256: sha256Bytes(semanticBytes),
      semanticReportByteLength: semanticBytes.length,
    });

    const staging = await createOwnedDirectory(
      privateRoot,
      "canonical-staging",
      privateLedger,
    );
    const staged = await stageCanonicalDocuments({
      staging,
      ledger: privateLedger,
      manifestBytes: membership.reportBytes,
      inputSetBytes: inputSet.bytes,
      semanticBytes,
      evidenceBytes,
    });
    let verification;
    try {
      verification = await verifyReproducibilityEvidence(verifierOptions(
        context,
        staged,
        staged.evidence.path,
        {
          artifact: candidate.file.path,
          semanticReport: staged.semantic.path,
        },
      ));
    } catch {
      fail("R1_10A_VERIFICATION", "r1-10a-verification-failed");
    }
    requireR1Verification(verification, "pass");
    const verificationBytes = encodeCanonicalVerificationResult(verification);

    const bundle = await writeSuccessBundle({
      context,
      outputDirectory,
      outputLedger,
      candidate,
      transcriptBytes,
      semanticBytes,
      evidenceBytes,
      verificationBytes,
    });
    await cleanupOwnedLedger(privateLedger);
    privateLedger = [];
    await verifyPublishedArchive(
      bundle.artifact,
      candidate.verification.archiveSha256,
    );
    await writeOwnedFile(
      outputDirectory,
      OUTPUT_NAMES.marker,
      Buffer.from(COMPLETION_MARKER, "ascii"),
      outputLedger,
    );
    return buildPublicResult({
      context,
      runResult: "pass",
      artifactSha256: candidate.verification.archiveSha256,
      artifactByteLength: candidate.verification.archiveByteLength,
      semanticBytes,
      evidenceBytes,
      verificationBytes,
    });
  } catch (error) {
    let safe = asAdapterError(error, "CLI", "adapter-failed");
    if (error instanceof PublicSourceArchiveBoundaryVectorError) {
      safe = new PublicSourceArchiveReproducibilityError(
        "BOUNDARY_VECTOR",
        "boundary-vector-failed",
      );
    }
    try {
      if (outputLedger.length > 0) await cleanupOwnedLedger(outputLedger);
      outputLedger = [];
      if (privateLedger.length > 0) await cleanupOwnedLedger(privateLedger);
      privateLedger = [];
    } catch {
      throw new PublicSourceArchiveReproducibilityError(
        "CLEANUP",
        "cleanup-incomplete",
      );
    }
    if (
      outputDirectory
      && safe.phase === "SAME_HOST"
      && safe.reason.startsWith("private-worker-")
    ) {
      await removeEmptyOutputDirectory(outputDirectory);
      outputDirectory = null;
      throw safe;
    }
    if (context && outputDirectory && safe.phase !== "CLEANUP") {
      return writeFailureBundle({ context, outputDirectory, failure: safe });
    }
    if (outputDirectory) {
      await removeEmptyOutputDirectory(outputDirectory);
    }
    throw safe;
  } finally {
    if (restoreGitPath) restoreGitPath();
  }
}

function parseOptions(argv) {
  const mapping = new Map([
    ["--source-repo", "sourceRepo"],
    ["--tooling-repo", "toolingRepo"],
    ["--policy", "policy"],
    ["--matrix-cell-id", "matrixCellId"],
    ["--critical-tool-set", "criticalToolSet"],
    ["--runtime-identity", "runtimeIdentity"],
    ["--git-identity", "gitIdentity"],
    ["--platform-probe", "platformProbe"],
    ["--test-vector-set", "testVectorSet"],
    ["--output-directory", "outputDirectory"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(result, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) fail("CLI", "unknown-or-duplicate-option");
    result[key] = argv[index + 1];
    index += 1;
  }
  if (OPTION_KEYS.some((key) => !Object.hasOwn(result, key))) {
    fail("CLI", "required-options");
  }
  return Object.freeze(result);
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const entry = process.argv[1];
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(entry));
  } catch {
    return false;
  }
}

async function main() {
  const result = await preparePublicSourceArchiveReproducibility(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
  if (result.runResult !== "pass") process.exitCode = 2;
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = asAdapterError(error, "CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
