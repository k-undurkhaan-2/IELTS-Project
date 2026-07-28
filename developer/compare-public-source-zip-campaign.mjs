#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
  canonicalPublicJsonBytes,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  parseCanonicalExecutionIdentityV2Bytes,
  parseCanonicalReproducibilityEvidenceV2Bytes,
  parseCanonicalVerificationResultV2Bytes,
} from "./reproducibility-evidence-v2-core.mjs";
import {
  CAMPAIGN_COMPARISON_MANIFEST_DOCUMENT_KIND,
  CAMPAIGN_SCHEMA_VERSION,
  COMPARISON_COMPLETION_MARKER,
  COMPARISON_SIGNATURE_NAMESPACE,
  PublicSourceZipCampaignError,
  SEALED_COMPARISON_OUTPUT_NAMES,
  campaignPolicySha256,
  encodeCanonicalCampaignComparisonResult,
  encodeCanonicalComparisonManifest,
  failPublicSourceZipCampaign,
  findComparisonGpgAuthorities,
  findIndependentReviewGpgAuthority,
  measureCurrentNodeProcessAuthority,
  recheckCurrentNodeProcessAuthority,
  parseCanonicalGitIdentityBindingBytes,
  validateExternalCampaignPolicyAuthority,
  validateComparisonManifest,
  validateGitIdentityBinding,
  validateProfiledGpgExecutionContext,
  verifyCampaignLoadedToolBytes,
  runProfiledGpgOperation,
} from "./public-source-zip-campaign-core.mjs";
import { compareReproducibilityEvidenceV2 } from "./compare-reproducibility-evidence-v2.mjs";
import {
  verifyDetachedOpenPgpSignature,
  verifyPublicSourceZipCampaignCell,
} from "./verify-public-source-zip-campaign-cell.mjs";

let campaignCellVerifier = verifyPublicSourceZipCampaignCell;

const COMPARATOR_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.comparator.test-adapter",
);
const AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([COMPARATOR_TEST_ADAPTER]),
  allowFunctions: true,
  allowBuffer: true,
});
const OPTION_KEYS = new Set([
  "expectedCanonicalPolicyBytes",
  "expectedPolicySha256",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
  "cells",
  "gpgExecutable",
  "gpgHome",
  "outputDirectory",
  "comparisonSigningFingerprint",
  "comparisonSignerRole",
  "comparisonHostRole",
  "reviewHostRole",
  "repository",
  "gitExecutable",
  "gitIdentity",
]);
const CELL_OPTION_KEYS = Object.freeze(["matrixCellId", "capsuleRoot"]);
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/u;

function authority(value, options = undefined) {
  try {
    assertProxyFreeAuthorityGraph(value, options);
  } catch {
    failPublicSourceZipCampaign("OBJECT_AUTHORITY", "authority-graph-rejected");
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
  ) failPublicSourceZipCampaign("CLI", "api-options-object");
  for (const key of Reflect.ownKeys(options)) {
    if (key === COMPARATOR_TEST_ADAPTER) continue;
    if (typeof key !== "string" || !OPTION_KEYS.has(key)) {
      failPublicSourceZipCampaign("CLI", "api-option-key");
    }
  }
  for (const key of [
    "expectedCanonicalPolicyBytes", "expectedPolicySha256", "campaignId",
    "sourceCommit", "toolingCommit", "cells", "gpgExecutable", "gpgHome",
    "outputDirectory", "comparisonSigningFingerprint", "comparisonSignerRole",
    "comparisonHostRole", "reviewHostRole",
    "repository", "gitExecutable", "gitIdentity",
  ]) {
    if (!Object.hasOwn(options, key)) {
      failPublicSourceZipCampaign("CLI", "api-required-option");
    }
  }
  const externalPolicyAuthority = validateExternalCampaignPolicyAuthority({
    expectedCanonicalPolicyBytes: options.expectedCanonicalPolicyBytes,
    expectedPolicySha256: options.expectedPolicySha256,
    campaignId: options.campaignId,
    sourceCommit: options.sourceCommit,
    toolingCommit: options.toolingCommit,
  });
  const policy = externalPolicyAuthority.policy;
  if (
    typeof options.gpgExecutable !== "string"
    || typeof options.gpgHome !== "string"
    || !path.isAbsolute(options.gpgExecutable)
    || !path.isAbsolute(options.gpgHome)
    || typeof options.repository !== "string"
    || !path.isAbsolute(options.repository)
    || typeof options.gitExecutable !== "string"
    || !path.isAbsolute(options.gitExecutable)
  ) failPublicSourceZipCampaign("CLI", "gpg-path-option");
  const gitIdentity = (() => {
    try {
      return validateGitIdentityBinding(options.gitIdentity);
    } catch {
      failPublicSourceZipCampaign("GIT_IDENTITY", "git-identity-invalid");
    }
  })();
  if (!Array.isArray(options.cells) || ![3, 4].includes(options.cells.length)) {
    failPublicSourceZipCampaign("CLI", "cell-count");
  }
  const cells = options.cells.map((entry) => {
    authority(entry);
    if (
      !entry
      || typeof entry !== "object"
      || Array.isArray(entry)
      || Reflect.ownKeys(entry).length !== CELL_OPTION_KEYS.length
      || Reflect.ownKeys(entry).some((key, index) => key !== CELL_OPTION_KEYS[index])
      || typeof entry.matrixCellId !== "string"
      || typeof entry.capsuleRoot !== "string"
      || !path.isAbsolute(entry.capsuleRoot)
    ) failPublicSourceZipCampaign("CLI", "cell-option");
    return Object.freeze({
      matrixCellId: entry.matrixCellId,
      capsuleRoot: entry.capsuleRoot,
    });
  });
  if (
    typeof options.outputDirectory !== "string"
    || !path.isAbsolute(options.outputDirectory)
    || typeof options.comparisonSigningFingerprint !== "string"
    || !FINGERPRINT_PATTERN.test(options.comparisonSigningFingerprint)
    || typeof options.comparisonSignerRole !== "string"
    || typeof options.comparisonHostRole !== "string"
    || typeof options.reviewHostRole !== "string"
  ) failPublicSourceZipCampaign("CLI", "comparison-signing-options");
  const comparisonNodeAuthority = measureCurrentNodeProcessAuthority({
    campaignPolicy: policy,
    campaignRole: "comparison-host",
    matrixCellId: null,
    hostRole: options.comparisonHostRole,
  });
    const allowed = policy.allowedSignerFingerprints.find((entry) => (
      entry.fingerprint === options.comparisonSigningFingerprint
      && entry.role === options.comparisonSignerRole
    ));
    if (!allowed) failPublicSourceZipCampaign("SIGNATURE", "comparison-signer-not-allowed");
    const gpgAuthorities = findComparisonGpgAuthorities(
      policy,
      options.comparisonHostRole,
      options.comparisonSignerRole,
    );
    const signingAuthority = validateProfiledGpgExecutionContext({
      gpgRole: "comparison-result-sign",
      operation: "detached-sign",
      executablePath: options.gpgExecutable,
      gpgHome: options.gpgHome,
      campaignPolicy: policy,
      expectedPolicySha256: externalPolicyAuthority.policySha256,
      matrixCellId: null,
      comparisonRole: "campaign-comparison",
      hostRole: options.comparisonHostRole,
      signerRole: options.comparisonSignerRole,
      signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
    });
    const localVerificationAuthority = validateProfiledGpgExecutionContext({
      gpgRole: "comparison-result-local-verify",
      operation: "detached-verify",
      executablePath: options.gpgExecutable,
      gpgHome: options.gpgHome,
      campaignPolicy: policy,
      expectedPolicySha256: externalPolicyAuthority.policySha256,
      matrixCellId: null,
      comparisonRole: "campaign-comparison",
      hostRole: options.comparisonHostRole,
      signerRole: options.comparisonSignerRole,
      signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
    });
    const independentReviewAuthority = findIndependentReviewGpgAuthority(
      policy,
      options.reviewHostRole,
      options.comparisonSignerRole,
    );
    const signing = Object.freeze({
      outputDirectory: options.outputDirectory,
      fingerprint: options.comparisonSigningFingerprint,
      role: options.comparisonSignerRole,
      gpgAuthorities,
      signingAuthority,
      localVerificationAuthority,
      independentReviewAuthority,
    });
  return Object.freeze({
    campaignPolicy: policy,
    expectedCanonicalPolicyBytes: options.expectedCanonicalPolicyBytes,
    expectedPolicySha256: externalPolicyAuthority.policySha256,
    cells: Object.freeze(cells),
    gpgExecutable: options.gpgExecutable,
    gpgHome: options.gpgHome,
    repository: options.repository,
    gitExecutable: options.gitExecutable,
    gitIdentity,
    signing,
    comparisonHostRole: options.comparisonHostRole,
    reviewHostRole: options.reviewHostRole,
    comparisonNodeAuthority,
    testAdapter:
      Object.getOwnPropertyDescriptor(options, COMPARATOR_TEST_ADAPTER)?.value ?? null,
  });
}

async function invokeTestAdapter(testAdapter, checkpoint, details = undefined) {
  if (!testAdapter || testAdapter.checkpoint === undefined) return;
  const pending = testAdapter.checkpoint(Object.freeze({
    checkpoint,
    ...(details === undefined ? {} : details),
  }));
  authority(pending, { allowPromise: true });
  const returned = await pending;
  authority(returned);
  if (returned !== undefined) {
    failPublicSourceZipCampaign("CLI", "test-adapter-return-value");
  }
}

function comparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

async function pathExists(value) {
  try {
    await access(value);
    return true;
  } catch {
    return false;
  }
}

function publicationIdentity(state, kind) {
  const value = { dev: state.dev, ino: state.ino, mode: state.mode };
  if (kind === "file") {
    value.size = state.size;
    value.nlink = state.nlink;
    value.mtimeNs = state.mtimeNs;
    value.ctimeNs = state.ctimeNs;
  }
  return Object.freeze(value);
}

function samePublicationIdentity(left, right) {
  const keys = Reflect.ownKeys(left);
  return keys.length === Reflect.ownKeys(right).length
    && keys.every((key) => left[key] === right[key]);
}

async function inspectPublicationPath(literalPath, kind) {
  try {
    const state = await lstat(literalPath, { bigint: true });
    if (
      state.isSymbolicLink()
      || (kind === "directory" && !state.isDirectory())
      || (kind === "file" && (!state.isFile() || state.nlink !== 1n))
      || comparable(await realpath(literalPath)) !== comparable(literalPath)
    ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    return publicationIdentity(state, kind);
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
}

async function stablePublicationRead(filePath, maximumBytes) {
  let handle = null;
  try {
    const initial = await lstat(filePath, { bigint: true });
    if (
      !initial.isFile()
      || initial.isSymbolicLink()
      || initial.nlink !== 1n
      || initial.size < 0n
      || initial.size > BigInt(maximumBytes)
      || comparable(await realpath(filePath)) !== comparable(filePath)
    ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-file-identity");
    handle = await open(
      filePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = publicationIdentity(await handle.stat({ bigint: true }), "file");
    const bytes = await handle.readFile();
    const after = publicationIdentity(await handle.stat({ bigint: true }), "file");
    if (
      !samePublicationIdentity(publicationIdentity(initial, "file"), before)
      || !samePublicationIdentity(before, after)
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-file-identity");
    return Object.freeze({ bytes, identity: before });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-file-identity");
  } finally {
    if (handle) await handle.close();
  }
}

async function createComparisonLedger(root, parent) {
  const ledger = {
    root: path.resolve(root),
    parent: path.resolve(parent),
    parentIdentity: await inspectPublicationPath(parent, "directory"),
    rootIdentity: await inspectPublicationPath(root, "directory"),
    files: new Map(),
    events: [],
    phaseTwoStarted: false,
  };
  ledger.events.push(Object.freeze({ event: "create-root" }));
  return ledger;
}

async function recordComparisonFile(ledger, filePath) {
  const target = path.resolve(filePath);
  if (
    path.dirname(target) !== ledger.root
    || ledger.files.has(target)
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  const record = Object.freeze({
    literalPath: target,
    identity: await inspectPublicationPath(target, "file"),
  });
  ledger.files.set(target, record);
  ledger.events.push(Object.freeze({ event: "create-file", record }));
  return record;
}

async function freezeComparisonCleanupPlan(ledger) {
  if (ledger.phaseTwoStarted) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    !samePublicationIdentity(
      await inspectPublicationPath(ledger.parent, "directory"),
      ledger.parentIdentity,
    )
    || !samePublicationIdentity(
      await inspectPublicationPath(ledger.root, "directory"),
      ledger.rootIdentity,
    )
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  const names = await readdir(ledger.root, { withFileTypes: true });
  if (
    names.length !== ledger.files.size
    || names.some((entry) => (
      !entry.isFile()
      || entry.isSymbolicLink()
      || !ledger.files.has(path.join(ledger.root, entry.name))
    ))
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  for (const record of ledger.files.values()) {
    if (!samePublicationIdentity(
      await inspectPublicationPath(record.literalPath, "file"),
      record.identity,
    )) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  return Object.freeze([...ledger.files.values()]);
}

async function cleanupComparisonLedger(ledger) {
  const first = await freezeComparisonCleanupPlan(ledger);
  const second = await freezeComparisonCleanupPlan(ledger);
  if (
    first.length !== second.length
    || first.some((record, index) => record !== second[index])
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  ledger.phaseTwoStarted = true;
  ledger.events.push(Object.freeze({ event: "phase-two-start" }));
  for (const record of second) {
    if (!samePublicationIdentity(
      await inspectPublicationPath(record.literalPath, "file"),
      record.identity,
    )) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    try {
      await unlink(record.literalPath);
    } catch {
      failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
    }
    ledger.events.push(Object.freeze({ event: "remove-file", record }));
  }
  try {
    await rmdir(ledger.root);
  } catch {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
  }
  if (await pathExists(ledger.root)) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
  }
}

async function writeComparisonFile(ledger, name, bytes) {
  const target = path.join(ledger.root, name);
  await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
  const snapshot = await stablePublicationRead(target, Math.max(bytes.length, 1));
  if (!snapshot.bytes.equals(bytes)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-file-bytes");
  }
  await recordComparisonFile(ledger, target);
  return snapshot;
}

async function revokeComparisonMarker(ledger) {
  const markerPath = path.join(ledger.root, "comparison.complete");
  const record = ledger.files.get(markerPath);
  if (!record) return;
  if (!samePublicationIdentity(
    await inspectPublicationPath(markerPath, "file"),
    record.identity,
  )) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  try {
    await unlink(markerPath);
  } catch {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
  }
  ledger.files.delete(markerPath);
  ledger.events.push(Object.freeze({ event: "revoke-marker", record }));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function cellFile(root, relative) {
  const result = path.join(root, ...relative.split("/"));
  const fromRoot = path.relative(root, result);
  if (
    fromRoot.length === 0
    || fromRoot === ".."
    || fromRoot.startsWith(".." + path.sep)
    || path.isAbsolute(fromRoot)
  ) failPublicSourceZipCampaign("COMPARISON", "cell-file-containment");
  return result;
}

async function readVerifiedCellRecord(normalized, cell) {
  const verifiedCell = await campaignCellVerifier({
    capsuleRoot: cell.capsuleRoot,
    expectedCanonicalPolicyBytes: normalized.expectedCanonicalPolicyBytes,
    expectedPolicySha256: normalized.expectedPolicySha256,
    campaignId: normalized.campaignPolicy.campaignId,
    sourceCommit: normalized.campaignPolicy.sourceCommit,
    toolingCommit: normalized.campaignPolicy.toolingCommit,
    matrixCellId: cell.matrixCellId,
    consumerHostRole: normalized.comparisonHostRole,
    gpgExecutable: normalized.gpgExecutable,
    gpgHome: normalized.gpgHome,
    repository: normalized.repository,
    gitExecutable: normalized.gitExecutable,
    gitIdentity: normalized.gitIdentity,
  });
  if (verifiedCell.matrixCellId !== cell.matrixCellId) {
    failPublicSourceZipCampaign("COMPARISON", "cell-id-swap");
  }
  let evidenceBytes;
  let resultBytes;
  let executionBytes;
  try {
    [evidenceBytes, resultBytes, executionBytes] = await Promise.all([
      readFile(cellFile(cell.capsuleRoot, "v2/evidence.json")),
      readFile(cellFile(cell.capsuleRoot, "v2/verification-result.json")),
      readFile(cellFile(cell.capsuleRoot, "v2/execution-identity.json")),
    ]);
  } catch {
    failPublicSourceZipCampaign("COMPARISON", "verified-cell-read");
  }
  if (
    sha256(evidenceBytes) !== verifiedCell.evidenceSha256
    || sha256(resultBytes) !== verifiedCell.verificationResultSha256
  ) failPublicSourceZipCampaign("COMPARISON", "post-verification-mutation");
  return {
    verifiedCell,
    evidence: parseCanonicalReproducibilityEvidenceV2Bytes(evidenceBytes),
    verificationResult: parseCanonicalVerificationResultV2Bytes(resultBytes),
    executionIdentity: parseCanonicalExecutionIdentityV2Bytes(executionBytes),
  };
}

async function signComparison(normalized, signing, manifestPath, signaturePath) {
  return runProfiledGpgOperation({
    gpgRole: "comparison-result-sign",
    operation: "detached-sign",
    executablePath: normalized.gpgExecutable,
    gpgHome: normalized.gpgHome,
    campaignPolicy: normalized.campaignPolicy,
    expectedPolicySha256: normalized.expectedPolicySha256,
    matrixCellId: null,
    comparisonRole: "campaign-comparison",
    hostRole: normalized.comparisonHostRole,
    signerRole: signing.role,
    signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
    signingFingerprint: signing.fingerprint,
    signatureFile: signaturePath,
    signedFile: manifestPath,
    allowedPrimaryFingerprints: null,
  });
}

async function publishComparison(normalized, comparison) {
  const signing = normalized.signing;
  await invokeTestAdapter(normalized.testAdapter, "before-output-directory", {
    outputDirectory: signing.outputDirectory,
  });
  if (await pathExists(signing.outputDirectory)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-output-exists");
  }
  const parent = path.dirname(signing.outputDirectory);
  try {
    const state = await lstat(parent, { bigint: true });
    if (
      !state.isDirectory()
      || state.isSymbolicLink()
      || comparable(await realpath(parent)) !== comparable(parent)
    ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-parent-identity");
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-parent-identity");
  }
  let ledger = null;
  try {
    await mkdir(signing.outputDirectory, { recursive: false, mode: 0o700 });
    ledger = await createComparisonLedger(signing.outputDirectory, parent);
    await invokeTestAdapter(normalized.testAdapter, "after-output-directory", {
      outputDirectory: signing.outputDirectory,
    });
    const resultBytes = encodeCanonicalCampaignComparisonResult(comparison);
    const resultPath = path.join(signing.outputDirectory, "campaign-result.json");
    const resultSnapshot = await writeComparisonFile(
      ledger,
      "campaign-result.json",
      resultBytes,
    );
    await invokeTestAdapter(normalized.testAdapter, "after-result", {
      outputDirectory: signing.outputDirectory,
      resultPath,
    });
    const payloadLedger = Object.freeze([Object.freeze({
      name: "campaign-result.json",
      role: "campaign-result",
      sha256: sha256(resultBytes),
      byteLength: resultBytes.length,
      comparisonClass: "semantic",
    })]);
    const ledgerSha256 = sha256(canonicalPublicJsonBytes(payloadLedger, "COMPARISON"));
    const manifest = validateComparisonManifest({
      documentKind: CAMPAIGN_COMPARISON_MANIFEST_DOCUMENT_KIND,
      namespace: COMPARISON_SIGNATURE_NAMESPACE,
      schemaVersion: CAMPAIGN_SCHEMA_VERSION,
      campaignId: normalized.campaignPolicy.campaignId,
      role: signing.role,
      sourceCommit: normalized.campaignPolicy.sourceCommit,
      toolingCommit: normalized.campaignPolicy.toolingCommit,
      campaignPolicySha256: campaignPolicySha256(normalized.campaignPolicy),
      cellAuthoritiesSha256: sha256(canonicalPublicJsonBytes(
        comparison.cellAuthorities,
        "COMPARISON",
      )),
      comparisonNodeRuntimeProfileId:
        comparison.comparisonNodeRuntimeProfileId,
      comparisonNodeRuntimeProfileSha256:
        comparison.comparisonNodeRuntimeProfileSha256,
      comparisonNodeImmutableInstallationProfileSha256:
        comparison.comparisonNodeImmutableInstallationProfileSha256,
      comparisonNodeQualificationResultSha256:
        comparison.comparisonNodeQualificationResultSha256,
      comparisonSignerProfileId: comparison.comparisonSignerProfileId,
      comparisonSignerProfileSha256: comparison.comparisonSignerProfileSha256,
      comparisonSignAssignmentSha256:
        comparison.comparisonSignAssignmentSha256,
      comparisonSignerImmutableInstallationProfileSha256:
        comparison.comparisonSignerImmutableInstallationProfileSha256,
      comparisonSignQualificationResultSha256:
        comparison.comparisonSignQualificationResultSha256,
      comparisonLocalVerifierProfileId:
        comparison.comparisonLocalVerifierProfileId,
      comparisonLocalVerifierProfileSha256:
        comparison.comparisonLocalVerifierProfileSha256,
      comparisonLocalVerifyAssignmentSha256:
        comparison.comparisonLocalVerifyAssignmentSha256,
      comparisonLocalVerifierImmutableInstallationProfileSha256:
        comparison.comparisonLocalVerifierImmutableInstallationProfileSha256,
      comparisonLocalVerifyQualificationResultSha256:
        comparison.comparisonLocalVerifyQualificationResultSha256,
      independentReviewVerifierProfileId:
        comparison.independentReviewVerifierProfileId,
      independentReviewVerifierProfileSha256:
        comparison.independentReviewVerifierProfileSha256,
      independentReviewVerifyAssignmentSha256:
        comparison.independentReviewVerifyAssignmentSha256,
      independentReviewVerifierImmutableInstallationProfileSha256:
        comparison.independentReviewVerifierImmutableInstallationProfileSha256,
      fileLedgerSha256: ledgerSha256,
      runNonce: randomBytes(16).toString("hex"),
      resultStatus: "ok",
      fileLedger: payloadLedger,
    });
    const manifestPath = path.join(signing.outputDirectory, "comparison-manifest.json");
    const signaturePath = path.join(signing.outputDirectory, "comparison-manifest.sig");
    const manifestBytes = encodeCanonicalComparisonManifest(manifest);
    const manifestSnapshot = await writeComparisonFile(
      ledger,
      "comparison-manifest.json",
      manifestBytes,
    );
    await invokeTestAdapter(normalized.testAdapter, "after-manifest", {
      outputDirectory: signing.outputDirectory,
      manifestPath,
    });
    await invokeTestAdapter(normalized.testAdapter, "before-signature", {
      outputDirectory: signing.outputDirectory,
      manifestPath,
      signaturePath,
    });
    const signingResult = await signComparison(
      normalized,
      signing,
      manifestPath,
      signaturePath,
    );
    if (
      signingResult.gpgRole !== "comparison-result-sign"
      || signingResult.profileId !== manifest.comparisonSignerProfileId
      || signingResult.profileSha256 !== manifest.comparisonSignerProfileSha256
      || signingResult.assignmentSha256
        !== manifest.comparisonSignAssignmentSha256
      || signingResult.qualificationResultSha256
        !== manifest.comparisonSignQualificationResultSha256
    ) failPublicSourceZipCampaign("SIGNATURE", "comparison-signing-profile");
    const signatureSnapshot = await stablePublicationRead(
      signaturePath,
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
    );
    if (signatureSnapshot.bytes.length === 0) {
      failPublicSourceZipCampaign("SIGNATURE", "comparison-signature-empty");
    }
    await recordComparisonFile(ledger, signaturePath);
    await invokeTestAdapter(normalized.testAdapter, "after-signature", {
      outputDirectory: signing.outputDirectory,
      manifestPath,
      signaturePath,
    });
    const manifestAfterSigning = await stablePublicationRead(
      manifestPath,
      normalized.campaignPolicy.transportPolicy.maxManifestBytes,
    );
    if (
      !manifestAfterSigning.bytes.equals(manifestSnapshot.bytes)
      || !samePublicationIdentity(
        manifestAfterSigning.identity,
        manifestSnapshot.identity,
      )
    ) failPublicSourceZipCampaign("SIGNATURE", "comparison-manifest-mutable");
    await invokeTestAdapter(normalized.testAdapter, "before-signature-verification", {
      outputDirectory: signing.outputDirectory,
      manifestPath,
      signaturePath,
    });
    const verified = await verifyDetachedOpenPgpSignature({
      campaignPolicy: normalized.campaignPolicy,
      expectedPolicySha256: normalized.expectedPolicySha256,
      gpgRole: "comparison-result-local-verify",
      hostRole: normalized.comparisonHostRole,
      matrixCellId: null,
      comparisonRole: "campaign-comparison",
      signerRole: signing.role,
      signatureNamespace: COMPARISON_SIGNATURE_NAMESPACE,
      gpgExecutable: normalized.gpgExecutable,
      gpgHome: normalized.gpgHome,
      signatureFile: signaturePath,
      signedFile: manifestPath,
      allowedPrimaryFingerprints: [signing.fingerprint],
    });
    if (verified.primaryFingerprint !== signing.fingerprint) {
      failPublicSourceZipCampaign("SIGNATURE", "comparison-signature-fingerprint");
    }
    if (
      verified.gpgRole !== "comparison-result-local-verify"
      || verified.profileId !== manifest.comparisonLocalVerifierProfileId
      || verified.profileSha256
        !== manifest.comparisonLocalVerifierProfileSha256
      || verified.assignmentSha256
        !== manifest.comparisonLocalVerifyAssignmentSha256
      || verified.qualificationResultSha256
        !== manifest.comparisonLocalVerifyQualificationResultSha256
    ) failPublicSourceZipCampaign("SIGNATURE", "comparison-verification-profile");
    await invokeTestAdapter(normalized.testAdapter, "after-signature-verification", {
      outputDirectory: signing.outputDirectory,
      manifestPath,
      signaturePath,
    });
    const signatureAfterVerification = await stablePublicationRead(
      signaturePath,
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
    );
    if (
      !signatureAfterVerification.bytes.equals(signatureSnapshot.bytes)
      || !samePublicationIdentity(
        signatureAfterVerification.identity,
        signatureSnapshot.identity,
      )
    ) failPublicSourceZipCampaign("SIGNATURE", "comparison-signature-mutable");
    await invokeTestAdapter(normalized.testAdapter, "before-marker", {
      outputDirectory: signing.outputDirectory,
    });
    const markerSnapshot = await writeComparisonFile(
      ledger,
      "comparison.complete",
      COMPARISON_COMPLETION_MARKER,
    );
    await invokeTestAdapter(normalized.testAdapter, "after-marker", {
      outputDirectory: signing.outputDirectory,
      markerPath: path.join(signing.outputDirectory, "comparison.complete"),
    });
    await invokeTestAdapter(normalized.testAdapter, "before-final-verification", {
      outputDirectory: signing.outputDirectory,
    });
    const names = (await readdir(signing.outputDirectory)).sort();
    const expected = [...SEALED_COMPARISON_OUTPUT_NAMES].sort();
    const finalResult = await stablePublicationRead(
      path.join(signing.outputDirectory, "campaign-result.json"),
      resultBytes.length,
    );
    const finalManifest = await stablePublicationRead(
      path.join(signing.outputDirectory, "comparison-manifest.json"),
      manifestBytes.length,
    );
    const finalSignature = await stablePublicationRead(
      path.join(signing.outputDirectory, "comparison-manifest.sig"),
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
    );
    const finalMarker = await stablePublicationRead(
      path.join(signing.outputDirectory, "comparison.complete"),
      COMPARISON_COMPLETION_MARKER.length,
    );
    if (
      names.length !== expected.length
      || names.some((entry, index) => entry !== expected[index])
      || !finalResult.bytes.equals(resultSnapshot.bytes)
      || !samePublicationIdentity(finalResult.identity, resultSnapshot.identity)
      || !finalManifest.bytes.equals(manifestSnapshot.bytes)
      || !samePublicationIdentity(finalManifest.identity, manifestSnapshot.identity)
      || !finalSignature.bytes.equals(signatureSnapshot.bytes)
      || !samePublicationIdentity(finalSignature.identity, signatureSnapshot.identity)
      || !finalMarker.bytes.equals(markerSnapshot.bytes)
      || !samePublicationIdentity(finalMarker.identity, markerSnapshot.identity)
      || !samePublicationIdentity(
        await inspectPublicationPath(ledger.parent, "directory"),
        ledger.parentIdentity,
      )
      || !samePublicationIdentity(
        await inspectPublicationPath(ledger.root, "directory"),
        ledger.rootIdentity,
      )
    ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "comparison-final-verification");
    await invokeTestAdapter(normalized.testAdapter, "after-final-verification", {
      outputDirectory: signing.outputDirectory,
    });
  } catch (error) {
    let safe = error instanceof PublicSourceZipCampaignError
      ? error
      : new PublicSourceZipCampaignError("OUTPUT_PUBLICATION", "comparison-publication-failure");
    if (ledger !== null && await pathExists(ledger.root)) {
      try {
        await revokeComparisonMarker(ledger);
        await cleanupComparisonLedger(ledger);
      } catch (cleanupError) {
        safe = cleanupError instanceof PublicSourceZipCampaignError
          ? cleanupError
          : new PublicSourceZipCampaignError("CLEANUP", "cleanup-identity-uncertain");
      }
    }
    throw safe;
  }
}

async function compareInternal(options) {
  const normalized = normalizeOptions(options);
  const verifyLoadedTools = () => {
    if (normalized.testAdapter?.loadedToolAuthorityBypass === true) {
      return Object.freeze({
        toolingCommit: normalized.campaignPolicy.toolingCommit,
        toolCount: 0,
        framedSha256: "0".repeat(64),
        gitExecutableSha256: normalized.gitIdentity.executableSha256,
      });
    }
    return verifyCampaignLoadedToolBytes({
      repository: normalized.repository,
      toolingCommit: normalized.campaignPolicy.toolingCommit,
      gitExecutable: normalized.gitExecutable,
      gitIdentity: normalized.gitIdentity,
    });
  };
  const initialLoadedTools = verifyLoadedTools();
  const requireUnchangedLoadedTools = () => {
    const current = verifyLoadedTools();
    if (
      current.toolingCommit !== initialLoadedTools.toolingCommit
      || current.toolCount !== initialLoadedTools.toolCount
      || current.framedSha256 !== initialLoadedTools.framedSha256
      || current.gitExecutableSha256 !== initialLoadedTools.gitExecutableSha256
    ) failPublicSourceZipCampaign("D2_BINDING", "loaded-tool-attestation-changed");
  };
  const records = [];
  for (const cell of normalized.cells) {
    records.push(await readVerifiedCellRecord(normalized, cell));
  }
  const recheckComparisonNode = () => recheckCurrentNodeProcessAuthority({
    campaignPolicy: normalized.campaignPolicy,
    campaignRole: "comparison-host",
    matrixCellId: null,
    hostRole: normalized.comparisonHostRole,
    expectedRuntimeIdentitySha256:
      normalized.comparisonNodeAuthority.runtimeIdentitySha256,
    expectedQualificationResultSha256:
      normalized.comparisonNodeAuthority.qualificationResultSha256,
  });
  recheckComparisonNode();
  const result = compareReproducibilityEvidenceV2({
    campaignPolicy: normalized.campaignPolicy,
    cells: records,
    comparisonNodeAuthority: normalized.comparisonNodeAuthority,
    comparisonSigningAuthority: normalized.signing.signingAuthority,
    comparisonLocalVerificationAuthority:
      normalized.signing.localVerificationAuthority,
    independentReviewAuthority:
      normalized.signing.independentReviewAuthority,
  });
  requireUnchangedLoadedTools();
  recheckComparisonNode();
  await publishComparison(normalized, result);
  recheckComparisonNode();
  requireUnchangedLoadedTools();
  return result;
}

export async function comparePublicSourceZipCampaign(options = {}) {
  return compareInternal(options);
}

function parseCli(argv) {
  authority(argv);
  const scalarMap = new Map([
    ["--expected-campaign-policy", "expectedPolicyPath"],
    ["--expected-policy-sha256", "expectedPolicySha256"],
    ["--campaign-id", "campaignId"],
    ["--source-commit", "sourceCommit"],
    ["--tooling-commit", "toolingCommit"],
    ["--gpg", "gpgExecutable"],
    ["--gpg-home", "gpgHome"],
    ["--output-directory", "outputDirectory"],
    ["--comparison-signing-fingerprint", "comparisonSigningFingerprint"],
    ["--comparison-signer-role", "comparisonSignerRole"],
    ["--comparison-host-role", "comparisonHostRole"],
    ["--review-host-role", "reviewHostRole"],
    ["--repository", "repository"],
    ["--git", "gitExecutable"],
    ["--git-identity", "gitIdentity"],
  ]);
  const values = Object.create(null);
  const cells = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
      failPublicSourceZipCampaign("CLI", "incomplete-option");
    }
    const value = argv[index + 1];
    index += 1;
    if (argument === "--cell") {
      const separator = value.indexOf("=");
      if (separator <= 0 || separator === value.length - 1) {
        failPublicSourceZipCampaign("CLI", "cell-option");
      }
      cells.push({
        matrixCellId: value.slice(0, separator),
        capsuleRoot: value.slice(separator + 1),
      });
      continue;
    }
    const key = scalarMap.get(argument);
    if (key === undefined || Object.hasOwn(values, key)) {
      failPublicSourceZipCampaign("CLI", "unknown-or-duplicate-option");
    }
    values[key] = value;
  }
  if ([
    "expectedPolicyPath", "expectedPolicySha256", "campaignId",
    "sourceCommit", "toolingCommit", "gpgExecutable", "gpgHome",
    "outputDirectory", "comparisonSigningFingerprint", "comparisonSignerRole",
    "comparisonHostRole", "reviewHostRole",
    "repository", "gitExecutable", "gitIdentity",
  ].some(
    (key) => !Object.hasOwn(values, key),
  ) || ![3, 4].includes(cells.length)) {
    failPublicSourceZipCampaign("CLI", "required-options");
  }
  return Object.freeze({ values, cells: Object.freeze(cells) });
}

function isMainModule() {
  if (typeof process.argv[1] !== "string" || process.argv[1].length === 0) return false;
  try {
    return comparable(realpathSync.native(fileURLToPath(import.meta.url)))
      === comparable(realpathSync.native(path.resolve(process.argv[1])));
  } catch {
    return false;
  }
}

async function main() {
  const cli = parseCli(process.argv.slice(2));
  let expectedCanonicalPolicyBytes;
  let gitIdentity;
  try {
    expectedCanonicalPolicyBytes = await readFile(
      cli.values.expectedPolicyPath,
    );
  } catch {
    failPublicSourceZipCampaign("POLICY", "campaign-policy-invalid");
  }
  try {
    gitIdentity = parseCanonicalGitIdentityBindingBytes(
      await readFile(cli.values.gitIdentity),
    );
  } catch {
    failPublicSourceZipCampaign("GIT_IDENTITY", "git-identity-invalid");
  }
  const options = {
    expectedCanonicalPolicyBytes,
    expectedPolicySha256: cli.values.expectedPolicySha256,
    campaignId: cli.values.campaignId,
    sourceCommit: cli.values.sourceCommit,
    toolingCommit: cli.values.toolingCommit,
    cells: cli.cells,
    gpgExecutable: cli.values.gpgExecutable,
    gpgHome: cli.values.gpgHome,
    repository: cli.values.repository,
    gitExecutable: cli.values.gitExecutable,
    gitIdentity,
    outputDirectory: cli.values.outputDirectory,
    comparisonSigningFingerprint: cli.values.comparisonSigningFingerprint,
    comparisonSignerRole: cli.values.comparisonSignerRole,
    comparisonHostRole: cli.values.comparisonHostRole,
    reviewHostRole: cli.values.reviewHostRole,
  };
  const result = await compareInternal(options);
  process.stdout.write(encodeCanonicalCampaignComparisonResult(result));
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
