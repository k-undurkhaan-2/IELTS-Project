#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  deriveCriticalToolIdentities,
  hashArtifactInputs,
} from "./public-source-receipt-core.mjs";
import {
  ADAPTER_MODE,
  ARTIFACT_ROLE,
  COMPLETION_MARKER,
  FORMAT_PROFILE,
  PublicSourceReceiptReproducibilityError,
  asAdapterError,
  buildCanonicalInputSet,
  buildEvidenceBytes,
  buildSemanticReportBytes,
  cleanupOwnedLedger,
  createCoordinatorPrivateRoot,
  createExclusiveOutputDirectory,
  createOwnedDirectory,
  createTrustedWorkerModuleCapsule,
  deepFreezeAdapter,
  failureClassFor,
  finalizePublishedBundle,
  installControlledGitPath,
  publishReceiptNoReplace,
  publishPrivateBundleNoReplace,
  readAdapterCanonicalDocument,
  readAndParseMatrixPolicy,
  removeEmptyOutputDirectory,
  resolveControlledGitExecutable,
  runHostCapabilityProbe,
  runSameHostRepetitions,
  runSameProcessRepetitions,
  selectIrrevocableBundleMode,
  selectPolicyCell,
  validateCriticalToolSet,
  validateOutputTarget,
  validatePrivateBundleStaging,
  validateGitIdentity,
  validateMeasuredCapabilities,
  validatePlatformProbeShape,
  validateRepositoryCommit,
  validateRuntimeIdentity,
  verifyPublishedReceipt,
  writeOwnedFile,
} from "./public-source-receipt-reproducibility-core.mjs";
import {
  encodeCanonicalVerificationResult,
  sha256Bytes,
} from "./reproducibility-evidence-core.mjs";
import { verifyReproducibilityEvidence } from "./verify-reproducibility-evidence.mjs";
import {
  PublicSourceReceiptBoundaryVectorError,
  resolveSyntheticSigningHelperAuthority,
  runPublicSourceReceiptBoundaryVectors,
  validatePublicSourceReceiptBoundaryVectorSet,
} from "./run-public-source-receipt-boundary-vectors.mjs";

const OPTION_KEYS = Object.freeze([
  "repository",
  "policy",
  "matrixCellId",
  "criticalToolSet",
  "runtimeIdentity",
  "gitIdentity",
  "platformProbe",
  "testVectorSet",
  "sourceArchive",
  "artifacts",
  "outputDirectory",
]);
const ARTIFACT_INPUT_KEYS = Object.freeze(["role", "format", "path"]);
const OUTPUT_NAMES = Object.freeze({
  receipt: "receipt.source-receipt.json",
  transcript: "receipt-verification.json",
  inputSet: "input-set.json",
  semantic: "semantic-report.json",
  evidence: "evidence.json",
  verification: "verification-result.json",
  marker: ".complete",
});
const SOURCE_MANIFEST_PATH = "developer/public-source-manifest.json";
const BOUNDARY_RESULT_KEYS = Object.freeze([
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
const WORKER_TEST_HOOK = Symbol.for(
  "ieltmps.public-source-receipt-reproducibility.worker-test-hook",
);

function fail(phase, reason) {
  throw new PublicSourceReceiptReproducibilityError(phase, reason);
}

function requireAbsolutePath(value) {
  return typeof value === "string"
    && value.length > 0
    && path.isAbsolute(value)
    && path.resolve(value) === value;
}

function validateOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    fail("CLI", "api-options-invalid");
  }
  const actual = Object.keys(options);
  const symbols = Object.getOwnPropertySymbols(options);
  if (
    actual.length !== OPTION_KEYS.length
    || actual.some((key, index) => key !== OPTION_KEYS[index])
    || symbols.some((symbol) => symbol !== WORKER_TEST_HOOK)
  ) fail("CLI", "api-options-invalid");
  for (const key of OPTION_KEYS) {
    if (!Object.hasOwn(options, key)) fail("CLI", "api-options-invalid");
  }
  if (
    typeof options.matrixCellId !== "string"
    || options.matrixCellId.length === 0
    || !Array.isArray(options.artifacts)
    || options.artifacts.length < 1
    || options.artifacts.length > 32
  ) fail("CLI", "api-options-invalid");
  for (const key of OPTION_KEYS.filter(
    (entry) => entry !== "matrixCellId" && entry !== "artifacts",
  )) {
    if (!requireAbsolutePath(options[key])) fail("CLI", "api-path-invalid");
  }
  const artifacts = options.artifacts.map((artifact) => {
    if (
      !artifact
      || typeof artifact !== "object"
      || Array.isArray(artifact)
      || Object.keys(artifact).length !== ARTIFACT_INPUT_KEYS.length
      || Object.keys(artifact).some(
        (key, index) => key !== ARTIFACT_INPUT_KEYS[index],
      )
      || typeof artifact.role !== "string"
      || typeof artifact.format !== "string"
      || !requireAbsolutePath(artifact.path)
    ) fail("CLI", "artifact-option-invalid");
    return Object.freeze({
      role: artifact.role,
      format: artifact.format,
      path: artifact.path,
    });
  });
  return Object.freeze({
    repository: options.repository,
    policy: options.policy,
    matrixCellId: options.matrixCellId,
    criticalToolSet: options.criticalToolSet,
    runtimeIdentity: options.runtimeIdentity,
    gitIdentity: options.gitIdentity,
    platformProbe: options.platformProbe,
    testVectorSet: options.testVectorSet,
    sourceArchive: options.sourceArchive,
    artifacts: Object.freeze(artifacts),
    outputDirectory: options.outputDirectory,
    workerHooks: options[WORKER_TEST_HOOK] ?? null,
  });
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
  let actual;
  let descriptors;
  try {
    if (
      !result
      || typeof result !== "object"
      || Array.isArray(result)
      || Object.getPrototypeOf(result) !== Object.prototype
    ) fail("BOUNDARY_VECTOR", "boundary-vector-failed");
    actual = Reflect.ownKeys(result);
    descriptors = Object.getOwnPropertyDescriptors(result);
  } catch {
    fail("BOUNDARY_VECTOR", "boundary-vector-failed");
  }
  if (
    actual.length !== BOUNDARY_RESULT_KEYS.length
    || actual.some((key, index) => key !== BOUNDARY_RESULT_KEYS[index])
  ) fail("BOUNDARY_VECTOR", "boundary-vector-failed");
  const values = Object.create(null);
  for (const key of BOUNDARY_RESULT_KEYS) {
    const descriptor = descriptors[key];
    if (
      !descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true
      || descriptor.get !== undefined
      || descriptor.set !== undefined
    ) fail("BOUNDARY_VECTOR", "boundary-vector-failed");
    values[key] = descriptor.value;
  }
  try {
    structuredClone(result);
  } catch {
    fail("BOUNDARY_VECTOR", "boundary-vector-failed");
  }
  if (
    values.status !== "ok"
    || values.mode !== "public-source-receipt-boundary-vectors"
    || values.vectorSetKind
      !== "ieltmps-public-source-receipt-boundary-vector-set"
    || values.schemaVersion !== 1
    || values.vectorSetId !== "public-source-receipt-v1-boundaries-v1"
    || values.artifactRole !== ARTIFACT_ROLE
    || values.formatProfile !== FORMAT_PROFILE
    || values.testVectorSetSha256 !== expectedSha256
    || values.vectorCount !== 70
    || values.passedCount !== 70
    || values.failedCount !== 0
    || values.boundaryVectorSetPassed !== true
  ) fail("BOUNDARY_VECTOR", "boundary-vector-failed");
  return true;
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

function manifestBytesFromMembership(membership) {
  const member = membership.members.find(
    (entry) => entry.path === SOURCE_MANIFEST_PATH,
  );
  if (
    !member
    || !Buffer.isBuffer(member.blobBytes)
    || sha256Bytes(member.blobBytes) !== membership.manifestSha256
  ) fail("SOURCE_BINDING", "source-manifest-authority");
  return member.blobBytes;
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
      "public-source-manifest.json",
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
    sourceRepo: context.options.repository,
    toolingRepo: context.options.repository,
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

async function stageSuccessBundle({
  staging,
  stagingLedger,
  candidate,
  transcriptBytes,
  semanticBytes,
  evidenceBytes,
  verificationBytes,
  inputSetBytes,
}) {
  const receipt = await publishReceiptNoReplace(
    staging,
    candidate,
    stagingLedger,
  );
  const records = Object.freeze({
    receipt,
    transcript: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.transcript,
      transcriptBytes,
      stagingLedger,
    ),
    inputSet: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.inputSet,
      inputSetBytes,
      stagingLedger,
    ),
    semantic: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.semantic,
      semanticBytes,
      stagingLedger,
    ),
    evidence: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.evidence,
      evidenceBytes,
      stagingLedger,
    ),
    verification: await writeOwnedFile(
      staging,
      OUTPUT_NAMES.verification,
      verificationBytes,
      stagingLedger,
    ),
  });
  return Object.freeze([
    Object.freeze({ name: OUTPUT_NAMES.receipt, record: records.receipt, bytes: candidate.receiptBytes }),
    Object.freeze({ name: OUTPUT_NAMES.transcript, record: records.transcript, bytes: transcriptBytes }),
    Object.freeze({ name: OUTPUT_NAMES.inputSet, record: records.inputSet, bytes: inputSetBytes }),
    Object.freeze({ name: OUTPUT_NAMES.semantic, record: records.semantic, bytes: semanticBytes }),
    Object.freeze({ name: OUTPUT_NAMES.evidence, record: records.evidence, bytes: evidenceBytes }),
    Object.freeze({ name: OUTPUT_NAMES.verification, record: records.verification, bytes: verificationBytes }),
  ]);
}

async function buildCanonicalFailureDocuments({
  context,
  privateRoot,
  workLedger,
  failure,
}) {
  const verifierStaging = await createOwnedDirectory(
    privateRoot,
    "failure-verifier-inputs",
    workLedger,
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
    staging: verifierStaging,
    ledger: workLedger,
    manifestBytes: context.manifestBytes,
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
  return Object.freeze({
    evidenceBytes,
    verificationBytes: encodeCanonicalVerificationResult(verification),
  });
}

async function stageFailureBundle({
  staging,
  stagingLedger,
  inputSetBytes,
  evidenceBytes,
  verificationBytes,
}) {
  const inputSet = await writeOwnedFile(
    staging,
    OUTPUT_NAMES.inputSet,
    inputSetBytes,
    stagingLedger,
  );
  const evidence = await writeOwnedFile(
    staging,
    OUTPUT_NAMES.evidence,
    evidenceBytes,
    stagingLedger,
  );
  const verification = await writeOwnedFile(
    staging,
    OUTPUT_NAMES.verification,
    verificationBytes,
    stagingLedger,
  );
  return Object.freeze([
    Object.freeze({ name: OUTPUT_NAMES.inputSet, record: inputSet, bytes: inputSetBytes }),
    Object.freeze({ name: OUTPUT_NAMES.evidence, record: evidence, bytes: evidenceBytes }),
    Object.freeze({ name: OUTPUT_NAMES.verification, record: verification, bytes: verificationBytes }),
  ]);
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

export async function preparePublicSourceReceiptReproducibility(options) {
  const normalized = validateOptions(options);
  let target = null;
  let privateRoot = null;
  let workerCapsule = null;
  let publication = null;
  let rootLedger = [];
  let workLedger = [];
  let stagingLedger = [];
  let finalLedger = [];
  let context = null;
  let trustLocked = false;
  let bundleDecision = null;

  const cleanupPrivateState = async () => {
    let failure = null;
    for (const ledger of [stagingLedger, workLedger, rootLedger]) {
      if (ledger.length === 0) continue;
      try {
        await cleanupOwnedLedger(ledger);
        ledger.length = 0;
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure) {
      throw new PublicSourceReceiptReproducibilityError(
        "CLEANUP",
        "cleanup-incomplete",
      );
    }
  };

  const cleanupPublicState = async () => {
    let failure = null;
    if (finalLedger.length > 0) {
      try {
        await cleanupOwnedLedger(finalLedger);
        finalLedger = [];
      } catch (error) {
        failure = error;
      }
    }
    if (publication?.finalDirectory) {
      try {
        await removeEmptyOutputDirectory(publication.finalDirectory);
        publication = null;
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure) {
      throw new PublicSourceReceiptReproducibilityError(
        "CLEANUP",
        "cleanup-incomplete",
      );
    }
  };

  try {
    const policyDocument = await readAndParseMatrixPolicy(normalized.policy);
    const cell = selectPolicyCell(policyDocument.value, normalized.matrixCellId);
    const git = await resolveControlledGitExecutable();
    const [criticalToolSet, runtimeIdentity, gitIdentity, platformProbe] =
      await Promise.all([
        readAdapterCanonicalDocument(
          normalized.criticalToolSet,
          "TOOL_SET",
          "critical-tool-set",
        ),
        readAdapterCanonicalDocument(
          normalized.runtimeIdentity,
          "RUNTIME_IDENTITY",
          "runtime-identity",
        ),
        readAdapterCanonicalDocument(
          normalized.gitIdentity,
          "GIT_IDENTITY",
          "git-identity",
        ),
        readAdapterCanonicalDocument(
          normalized.platformProbe,
          "PLATFORM_PROBE",
          "platform-probe",
        ),
      ]);
    const vectorAuthority = await validatePublicSourceReceiptBoundaryVectorSet({
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
    validateGitIdentity(gitIdentity, cell, git);
    const syntheticSigningHelperAuthority = await resolveSyntheticSigningHelperAuthority({
      git,
    });
    installControlledGitPath(git);

    await validateRepositoryCommit(
      normalized.repository,
      policyDocument.value.sourceCommit,
      git,
      "SOURCE_BINDING",
    );
    await validateRepositoryCommit(
      normalized.repository,
      policyDocument.value.toolingCommit,
      git,
      "TOOL_SET",
    );
    const workerModuleAuthority = await validateCriticalToolSet({
      document: criticalToolSet,
      toolingRepo: normalized.repository,
      toolingCommit: policyDocument.value.toolingCommit,
      git,
    });
    await validateRuntimeIdentity(runtimeIdentity, cell);
    const platformProbeValue = validatePlatformProbeShape(
      platformProbe,
      cell,
      runtimeIdentity.sha256,
      gitIdentity.sha256,
    );

    let membership;
    let archiveVerification;
    let criticalFiles;
    let artifactIdentities;
    try {
      membership = await loadValidatedPublicSourceMembership({
        repo: normalized.repository,
        commit: policyDocument.value.sourceCommit,
      });
      archiveVerification = await verifyPublicSourceArchive({
        repo: normalized.repository,
        commit: policyDocument.value.sourceCommit,
        archive: normalized.sourceArchive,
      });
      criticalFiles = deriveCriticalToolIdentities(
        normalized.repository,
        policyDocument.value.toolingCommit,
      ).criticalFiles;
      artifactIdentities = await hashArtifactInputs(
        normalized.repository,
        normalized.artifacts,
      );
    } catch {
      fail("ARCHIVE_VERIFICATION", "direct-authority-invalid");
    }
    const manifestBytes = manifestBytesFromMembership(membership);
    const inputSet = buildCanonicalInputSet({
      membership,
      archiveVerification,
      toolingCommit: policyDocument.value.toolingCommit,
      criticalFiles,
      artifacts: artifactIdentities,
    });
    if (
      membership.manifestSha256 !== policyDocument.value.manifestSha256
      || inputSet.sha256 !== policyDocument.value.inputSetSha256
    ) fail("POLICY_BINDING", "source-document-hash-mismatch");

    target = await validateOutputTarget({
      outputDirectory: normalized.outputDirectory,
      sourceRepo: normalized.repository,
      toolingRepo: normalized.repository,
    });
    privateRoot = await createCoordinatorPrivateRoot({
      target,
      ledger: rootLedger,
    });
    workerCapsule = await createTrustedWorkerModuleCapsule({
      privateRoot,
      ledger: workLedger,
      toolingCommit: policyDocument.value.toolingCommit,
      workerModuleAuthority,
    });
    context = Object.freeze({
      options: normalized,
      policyDocument,
      cell,
      membership,
      manifestBytes,
      inputSet,
      git,
      workerCapsule,
    });
    trustLocked = true;
    const measuredCapabilities = await runHostCapabilityProbe(
      privateRoot,
      workLedger,
    );
    validateMeasuredCapabilities(platformProbeValue, measuredCapabilities);

    const sameProcess = await runSameProcessRepetitions({
      repository: normalized.repository,
      sourceCommit: policyDocument.value.sourceCommit,
      toolingCommit: policyDocument.value.toolingCommit,
      sourceArchive: normalized.sourceArchive,
      artifacts: normalized.artifacts,
      privateRoot,
      ledger: workLedger,
    });
    const sameHost = await runSameHostRepetitions({
      repository: normalized.repository,
      sourceCommit: policyDocument.value.sourceCommit,
      toolingCommit: policyDocument.value.toolingCommit,
      sourceArchive: normalized.sourceArchive,
      artifacts: normalized.artifacts,
      policySha256: policyDocument.sha256,
      matrixCellId: cell.matrixCellId,
      criticalToolSetSha256: criticalToolSet.sha256,
      runtimeIdentitySha256: runtimeIdentity.sha256,
      gitIdentitySha256: gitIdentity.sha256,
      platformProbeSha256: platformProbe.sha256,
      testVectorSetSha256: vectorAuthority.sha256,
      manifestSha256: inputSet.value.manifestSha256,
      membershipReportSha256: inputSet.membershipReportSha256,
      inputSetSha256: inputSet.sha256,
      sourceArchiveSha256: inputSet.value.archive.sha256,
      sourceArchiveByteLength: inputSet.value.archive.byteLength,
      artifactIdentities: inputSet.value.artifacts,
      privateRoot,
      ledger: workLedger,
      git,
      sameProcess,
      workerModuleAuthority,
      workerCapsule,
      workerHooks: normalized.workerHooks,
    });
    if (!sameProcess.sameProcessRepeatable || !sameHost.sameHostRepeatable) {
      fail("SAME_HOST", "same-host-mismatch");
    }

    let boundaryResult;
    try {
      const vectorParentAuthority = target.parentChain.at(-2);
      if (!vectorParentAuthority) {
        fail("BOUNDARY_VECTOR", "boundary-vector-failed");
      }
      boundaryResult = await runPublicSourceReceiptBoundaryVectors({
        testVectorSet: normalized.testVectorSet,
        temporaryParent: path.dirname(privateRoot.path),
        temporaryParentIdentity: Object.freeze({
          device: vectorParentAuthority.identity.device.toString(10),
          inode: vectorParentAuthority.identity.inode.toString(10),
        }),
        expectedSha256: policyDocument.value.testVectorSetSha256,
        syntheticSigningHelperAuthority,
      });
    } catch (error) {
      if (error instanceof PublicSourceReceiptBoundaryVectorError) {
        fail("BOUNDARY_VECTOR", "boundary-vector-failed");
      }
      throw error;
    }
    const boundaryVectorSetPassed = requireBoundaryResult(
      boundaryResult,
      policyDocument.value.testVectorSetSha256,
    );
    if (boundaryVectorSetPassed !== true) {
      fail("BOUNDARY_VECTOR", "boundary-vector-failed");
    }

    const candidate = sameProcess.outputs[0];
    const transcriptBytes = candidate.transcript;
    if (
      !sameProcess.outputs.every((entry) => entry.transcript.equals(transcriptBytes))
      || !sameHost.outputs.every((entry) => entry.transcript.equals(transcriptBytes))
    ) fail("RECEIPT_VERIFICATION", "receipt-transcript-mismatch");
    const semanticBytes = buildSemanticReportBytes({
      sourceCommit: policyDocument.value.sourceCommit,
      toolingCommit: policyDocument.value.toolingCommit,
      inputSetSha256: inputSet.sha256,
      artifactSha256: candidate.verification.receiptSha256,
      artifactByteLength: candidate.verification.receiptByteLength,
    });
    const evidenceBytes = buildEvidenceBytes({
      policy: policyDocument.value,
      policySha256: policyDocument.sha256,
      cell,
      result: "pass",
      artifactSha256: candidate.verification.receiptSha256,
      artifactByteLength: candidate.verification.receiptByteLength,
      semanticReportSha256: sha256Bytes(semanticBytes),
      semanticReportByteLength: semanticBytes.length,
    });
    const verifierStaging = await createOwnedDirectory(
      privateRoot,
      "success-verifier-inputs",
      workLedger,
    );
    const staged = await stageCanonicalDocuments({
      staging: verifierStaging,
      ledger: workLedger,
      manifestBytes,
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

    bundleDecision = selectIrrevocableBundleMode("success");
    const bundleStaging = await createOwnedDirectory(
      privateRoot,
      "success-bundle-staging",
      stagingLedger,
    );
    const entries = await stageSuccessBundle({
      staging: bundleStaging,
      stagingLedger,
      candidate,
      transcriptBytes,
      semanticBytes,
      evidenceBytes,
      verificationBytes,
      inputSetBytes: inputSet.bytes,
    });
    await cleanupOwnedLedger(workLedger);
    workLedger = [];
    await validatePrivateBundleStaging(bundleStaging, entries);
    publication = await publishPrivateBundleNoReplace({
      target,
      sourceRepo: normalized.repository,
      toolingRepo: normalized.repository,
      staging: bundleStaging,
      entries,
      finalLedger,
      modeDecision: bundleDecision,
    });
    await cleanupOwnedLedger(stagingLedger);
    stagingLedger = [];
    await cleanupOwnedLedger(rootLedger);
    rootLedger = [];
    await finalizePublishedBundle({
      publication,
      entries,
      finalLedger,
      markerBytes: Buffer.from(COMPLETION_MARKER, "ascii"),
    });
    return buildPublicResult({
      context,
      runResult: "pass",
      artifactSha256: candidate.verification.receiptSha256,
      artifactByteLength: candidate.verification.receiptByteLength,
      semanticBytes,
      evidenceBytes,
      verificationBytes,
    });
  } catch (error) {
    let safe = asAdapterError(error, "CLI", "adapter-failed");
    if (!publication && error?.finalDirectory) {
      publication = Object.freeze({
        finalDirectory: error.finalDirectory,
        mode: bundleDecision?.mode ?? "local-only-failure",
      });
    }
    if (error instanceof PublicSourceReceiptBoundaryVectorError) {
      safe = new PublicSourceReceiptReproducibilityError(
        "BOUNDARY_VECTOR",
        "boundary-vector-failed",
      );
    }
    if (publication || finalLedger.length > 0) {
      try {
        await cleanupPublicState();
        await cleanupPrivateState();
      } catch {
        throw new PublicSourceReceiptReproducibilityError(
          "CLEANUP",
          "cleanup-incomplete",
        );
      }
      throw safe;
    }
    const loadedByteFailure = safe.phase === "TOOL_SET"
      && safe.reason === "worker-loaded-bytes-mismatch";
    if (
      !trustLocked
      || !context
      || !privateRoot
      || safe.phase === "CLEANUP"
      || loadedByteFailure
      || bundleDecision !== null
    ) {
      if (bundleDecision === null) {
        bundleDecision = selectIrrevocableBundleMode("local-only-failure");
      }
      try {
        await cleanupPrivateState();
      } catch {
        throw new PublicSourceReceiptReproducibilityError(
          "CLEANUP",
          "cleanup-incomplete",
        );
      }
      throw safe;
    }

    try {
      const failureDocuments = await buildCanonicalFailureDocuments({
        context,
        privateRoot,
        workLedger,
        failure: safe,
      });
      bundleDecision = selectIrrevocableBundleMode(
        "canonical-post-lock-failure",
      );
      const failureStaging = await createOwnedDirectory(
        privateRoot,
        "failure-bundle-staging",
        stagingLedger,
      );
      const entries = await stageFailureBundle({
        staging: failureStaging,
        stagingLedger,
        inputSetBytes: context.inputSet.bytes,
        evidenceBytes: failureDocuments.evidenceBytes,
        verificationBytes: failureDocuments.verificationBytes,
      });
      await cleanupOwnedLedger(workLedger);
      workLedger = [];
      await validatePrivateBundleStaging(failureStaging, entries);
      publication = await publishPrivateBundleNoReplace({
        target,
        sourceRepo: normalized.repository,
        toolingRepo: normalized.repository,
        staging: failureStaging,
        entries,
        finalLedger,
        modeDecision: bundleDecision,
      });
      await cleanupOwnedLedger(stagingLedger);
      stagingLedger = [];
      await cleanupOwnedLedger(rootLedger);
      rootLedger = [];
      await finalizePublishedBundle({
        publication,
        entries,
        finalLedger,
        markerBytes: Buffer.from(COMPLETION_MARKER, "ascii"),
      });
      return buildPublicResult({
        context,
        runResult: "fail",
        evidenceBytes: failureDocuments.evidenceBytes,
        verificationBytes: failureDocuments.verificationBytes,
        failureClass: failureClassFor(safe),
        failureCode: safe.reason,
      });
    } catch (publicationError) {
      const publicationSafe = asAdapterError(
        publicationError,
        "OUTPUT_PUBLICATION",
        "failure-bundle-publication",
      );
      if (!publication && publicationError?.finalDirectory) {
        publication = Object.freeze({
          finalDirectory: publicationError.finalDirectory,
          mode: bundleDecision.mode,
        });
      }
      try {
        await cleanupPublicState();
        await cleanupPrivateState();
      } catch {
        throw new PublicSourceReceiptReproducibilityError(
          "CLEANUP",
          "cleanup-incomplete",
        );
      }
      throw publicationSafe;
    }
  }
}

function parseOptions(argv) {
  const mapping = new Map([
    ["--repository", "repository"],
    ["--policy", "policy"],
    ["--matrix-cell-id", "matrixCellId"],
    ["--critical-tool-set", "criticalToolSet"],
    ["--runtime-identity", "runtimeIdentity"],
    ["--git-identity", "gitIdentity"],
    ["--platform-probe", "platformProbe"],
    ["--test-vector-set", "testVectorSet"],
    ["--source-archive", "sourceArchive"],
    ["--output-directory", "outputDirectory"],
  ]);
  const result = Object.create(null);
  const artifacts = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--artifact") {
      if (
        index + 3 >= argv.length
        || argv[index + 1].startsWith("--")
        || argv[index + 2].startsWith("--")
        || argv[index + 3].startsWith("--")
      ) fail("CLI", "artifact-option-invalid");
      artifacts.push({
        role: argv[index + 1],
        format: argv[index + 2],
        path: argv[index + 3],
      });
      index += 3;
      continue;
    }
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
  const singletonKeys = OPTION_KEYS.filter((key) => key !== "artifacts");
  if (
    singletonKeys.some((key) => !Object.hasOwn(result, key))
    || artifacts.length < 1
  ) fail("CLI", "required-options");
  return Object.freeze({
    repository: result.repository,
    policy: result.policy,
    matrixCellId: result.matrixCellId,
    criticalToolSet: result.criticalToolSet,
    runtimeIdentity: result.runtimeIdentity,
    gitIdentity: result.gitIdentity,
    platformProbe: result.platformProbe,
    testVectorSet: result.testVectorSet,
    sourceArchive: result.sourceArchive,
    artifacts: Object.freeze(artifacts.map((entry) => Object.freeze(entry))),
    outputDirectory: result.outputDirectory,
  });
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
  const result = await preparePublicSourceReceiptReproducibility(
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
