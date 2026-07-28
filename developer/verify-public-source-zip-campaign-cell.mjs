#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  constants as FS_CONSTANTS,
  realpathSync,
} from "node:fs";
import { lstat, open, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
} from "./public-source-zip-reproducibility-core.mjs";
import {
  parseCanonicalExecutionIdentityV2Bytes,
  parseCanonicalReproducibilityEvidenceV2Bytes,
  parseCanonicalVerificationResultV2Bytes,
} from "./reproducibility-evidence-v2-core.mjs";
import {
  CAMPAIGN_SCHEMA_VERSION,
  CELL_COMPLETION_MARKER,
  CELL_SIGNATURE_NAMESPACE,
  CELL_VERIFICATION_DOCUMENT_KIND,
  PublicSourceZipCampaignError,
  SEALED_CELL_OUTPUT_NAMES,
  SIGNATURE_VERIFICATION_DOCUMENT_KIND,
  campaignPolicySha256,
  encodeCanonicalCellVerificationResult,
  failPublicSourceZipCampaign,
  findAllowedSigner,
  findCampaignCell,
  findCellImportConsumerGpgAuthority,
  findCellProducerGpgAuthorities,
  measureCurrentNodeProcessAuthority,
  measuredQualificationResultSha256,
  parseCanonicalMeasuredQualificationResultBytes,
  recheckCurrentNodeProcessAuthority,
  parseOpenPgpStatusOutput as parseAuthenticatedOpenPgpStatusOutput,
  parseCanonicalCellManifestBytes,
  parseCanonicalCellResultBytes,
  parseCanonicalGitIdentityBindingBytes,
  parseCanonicalRuntimeIdentityBindingBytes,
  validateGitIdentityBinding,
  validateExternalCampaignPolicyAuthority,
  validateCellVerificationResult,
  validateSignatureVerificationRecord,
  validateV2EvidenceAndResultBinding,
  validateProfiledGpgExecutionContext,
  verifyCampaignLoadedToolBytes,
  runProfiledGpgOperation,
} from "./public-source-zip-campaign-core.mjs";
import { verifyReproducibilityEvidenceV2 } from "./verify-reproducibility-evidence-v2.mjs";

const CELL_VERIFIER_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.cell-verifier.test-adapter",
);
const AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([CELL_VERIFIER_TEST_ADAPTER]),
  allowFunctions: true,
  allowBuffer: true,
});
const OPTION_KEYS = Object.freeze([
  "capsuleRoot",
  "expectedCanonicalPolicyBytes",
  "expectedPolicySha256",
  "campaignId",
  "sourceCommit",
  "toolingCommit",
  "matrixCellId",
  "consumerHostRole",
  "gpgExecutable",
  "gpgHome",
  "repository",
  "gitExecutable",
  "gitIdentity",
]);
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 1024 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024 * 1024;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}$/u;

function authority(value, options = undefined) {
  try {
    assertProxyFreeAuthorityGraph(value, options);
  } catch {
    failPublicSourceZipCampaign("OBJECT_AUTHORITY", "authority-graph-rejected");
  }
  return value;
}

function exactOptions(value) {
  authority(value, AUTHORITY_OPTIONS);
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) failPublicSourceZipCampaign("CLI", "api-options-object");
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (key === CELL_VERIFIER_TEST_ADAPTER) continue;
    if (typeof key !== "string" || !OPTION_KEYS.includes(key)) {
      failPublicSourceZipCampaign("CLI", "api-option-key");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failPublicSourceZipCampaign("CLI", "api-option-descriptor");
    }
  }
  const hook = Object.getOwnPropertyDescriptor(value, CELL_VERIFIER_TEST_ADAPTER)?.value ?? null;
  const loadedToolAuthorityBypass = hook?.loadedToolAuthorityBypass === true;
  const requiredKeys = loadedToolAuthorityBypass
    ? OPTION_KEYS.slice(0, 10)
    : OPTION_KEYS;
  for (const key of requiredKeys) {
    if (!Object.hasOwn(value, key)) {
      failPublicSourceZipCampaign("CLI", "api-required-option");
    }
  }
  if (
    typeof value.capsuleRoot !== "string"
    || typeof value.matrixCellId !== "string"
    || typeof value.consumerHostRole !== "string"
    || typeof value.gpgExecutable !== "string"
    || typeof value.gpgHome !== "string"
  ) failPublicSourceZipCampaign("CLI", "api-path-option");
  if (
    !loadedToolAuthorityBypass
    && (
      typeof value.repository !== "string"
      || !path.isAbsolute(value.repository)
      || typeof value.gitExecutable !== "string"
      || !path.isAbsolute(value.gitExecutable)
    )
  ) failPublicSourceZipCampaign("CLI", "api-tool-path-option");
  const externalPolicyAuthority = validateExternalCampaignPolicyAuthority({
    expectedCanonicalPolicyBytes: value.expectedCanonicalPolicyBytes,
    expectedPolicySha256: value.expectedPolicySha256,
    campaignId: value.campaignId,
    sourceCommit: value.sourceCommit,
    toolingCommit: value.toolingCommit,
  });
  const policy = externalPolicyAuthority.policy;
  const cell = findCampaignCell(policy, value.matrixCellId);
  const signer = findAllowedSigner(policy, value.matrixCellId);
  const producerGpgAuthorities = findCellProducerGpgAuthorities(
    policy,
    value.matrixCellId,
  );
  const nodeAuthority = measureCurrentNodeProcessAuthority({
    campaignPolicy: policy,
    campaignRole: "cell-import-consumer",
    matrixCellId: null,
    hostRole: value.consumerHostRole,
  });
  const gpgAuthority = findCellImportConsumerGpgAuthority(
    policy,
    value.matrixCellId,
    value.consumerHostRole,
  );
  const gpgExecutionAuthority = validateProfiledGpgExecutionContext({
    gpgRole: "cell-import-consumer-verify",
    operation: "detached-verify",
    executablePath: value.gpgExecutable,
    gpgHome: value.gpgHome,
    campaignPolicy: policy,
    expectedPolicySha256: externalPolicyAuthority.policySha256,
    matrixCellId: cell.matrixCellId,
    comparisonRole: null,
    hostRole: value.consumerHostRole,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
  const gitIdentity = loadedToolAuthorityBypass
    ? null
    : (() => {
      try {
        return validateGitIdentityBinding(value.gitIdentity);
      } catch {
        failPublicSourceZipCampaign("GIT_IDENTITY", "git-identity-invalid");
      }
    })();
  return Object.freeze({
    capsuleRoot: value.capsuleRoot,
    campaignPolicy: policy,
    expectedCanonicalPolicyBytes: value.expectedCanonicalPolicyBytes,
    expectedPolicySha256: externalPolicyAuthority.policySha256,
    matrixCellId: cell.matrixCellId,
    consumerHostRole: value.consumerHostRole,
    signer,
    producerGpgAuthorities,
    gpgAuthority,
    gpgExecutionAuthority,
    nodeAuthority,
    gpgExecutable: value.gpgExecutable,
    gpgHome: value.gpgHome,
    repository: loadedToolAuthorityBypass ? null : value.repository,
    gitExecutable: loadedToolAuthorityBypass ? null : value.gitExecutable,
    gitIdentity,
    testAdapter: hook,
    loadedToolAuthorityBypass,
  });
}

function comparable(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function stateIdentity(state) {
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

function identitiesEqual(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

async function inspectCapsuleRoot(rootPath) {
  if (typeof rootPath !== "string" || !path.isAbsolute(rootPath)) {
    failPublicSourceZipCampaign("CELL_VERIFICATION", "capsule-root-absolute");
  }
  try {
    const state = await lstat(rootPath, { bigint: true });
    if (
      !state.isDirectory()
      || state.isSymbolicLink()
      || comparable(await realpath(rootPath)) !== comparable(rootPath)
    ) failPublicSourceZipCampaign("CELL_VERIFICATION", "capsule-root-identity");
    return Object.freeze({ path: path.resolve(rootPath), identity: stateIdentity(state) });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("CELL_VERIFICATION", "capsule-root-identity");
  }
}

async function stableRead(filePath, maximumBytes, phase, reason) {
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
    ) failPublicSourceZipCampaign(phase, reason);
    handle = await open(
      filePath,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const before = stateIdentity(await handle.stat({ bigint: true }));
    const bytes = await handle.readFile();
    const after = stateIdentity(await handle.stat({ bigint: true }));
    if (
      !identitiesEqual(stateIdentity(initial), before)
      || !identitiesEqual(before, after)
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign(phase, "mutable-capsule");
    return Object.freeze({ bytes, identity: before });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign(phase, reason);
  } finally {
    if (handle) await handle.close();
  }
}

async function recheckStableRead(filePath, expected, maximumBytes, phase, reason) {
  const current = await stableRead(filePath, maximumBytes, phase, reason);
  if (
    !expected.bytes.equals(current.bytes)
    || !identitiesEqual(expected.identity, current.identity)
  ) failPublicSourceZipCampaign(phase, "mutable-capsule");
  return current;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parseOpenPgpStatusOutput(stdout) {
  return parseAuthenticatedOpenPgpStatusOutput(stdout);
}

export function validateOpenPgpExecutionContext(options) {
  return validateProfiledGpgExecutionContext(options);
}

export async function verifyDetachedOpenPgpSignature(options) {
  authority(options);
  const keys = [
    "campaignPolicy",
    "expectedPolicySha256",
    "gpgRole",
    "hostRole",
    "matrixCellId",
    "comparisonRole",
    "signerRole",
    "signatureNamespace",
    "gpgExecutable",
    "gpgHome",
    "signatureFile",
    "signedFile",
    "allowedPrimaryFingerprints",
  ];
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Reflect.ownKeys(options).length !== keys.length
    || Reflect.ownKeys(options).some((key, index) => key !== keys[index])
  ) failPublicSourceZipCampaign("SIGNATURE", "signature-options");
  for (const key of ["signatureFile", "signedFile"]) {
    if (typeof options[key] !== "string" || !path.isAbsolute(options[key])) {
      failPublicSourceZipCampaign("SIGNATURE", "signature-path-option");
    }
  }
  if (
    !Array.isArray(options.allowedPrimaryFingerprints)
    || options.allowedPrimaryFingerprints.length === 0
    || options.allowedPrimaryFingerprints.some((entry) => !FINGERPRINT_PATTERN.test(entry))
  ) failPublicSourceZipCampaign("SIGNATURE", "allowed-fingerprints");
  return runProfiledGpgOperation({
    gpgRole: options.gpgRole,
    operation: "detached-verify",
    executablePath: options.gpgExecutable,
    gpgHome: options.gpgHome,
    campaignPolicy: options.campaignPolicy,
    expectedPolicySha256: options.expectedPolicySha256,
    matrixCellId: options.matrixCellId,
    comparisonRole: options.comparisonRole,
    hostRole: options.hostRole,
    signerRole: options.signerRole,
    signatureNamespace: options.signatureNamespace,
    signingFingerprint: null,
    signatureFile: options.signatureFile,
    signedFile: options.signedFile,
    allowedPrimaryFingerprints: options.allowedPrimaryFingerprints,
  });
}

async function invokeTestAdapter(testAdapter, checkpoint) {
  if (!testAdapter || testAdapter.checkpoint === undefined) return;
  const pending = testAdapter.checkpoint(Object.freeze({ checkpoint }));
  authority(pending, { allowPromise: true });
  const returned = await pending;
  authority(returned);
  if (returned !== undefined) failPublicSourceZipCampaign("CLI", "test-adapter-return-value");
}

async function listCapsuleFiles(rootPath) {
  const result = [];
  async function walk(relativeDirectory) {
    const directoryPath = relativeDirectory.length === 0
      ? rootPath
      : path.join(rootPath, ...relativeDirectory.split("/"));
    const entries = await readdir(directoryPath, { withFileTypes: true });
    entries.sort((left, right) => Buffer.compare(
      Buffer.from(left.name, "utf8"),
      Buffer.from(right.name, "utf8"),
    ));
    for (const entry of entries) {
      const relative = relativeDirectory.length === 0
        ? entry.name
        : relativeDirectory + "/" + entry.name;
      if (entry.isSymbolicLink()) {
        failPublicSourceZipCampaign("FILE_LEDGER", "reparse-entry");
      }
      if (entry.isDirectory()) await walk(relative);
      else if (entry.isFile()) result.push(relative);
      else failPublicSourceZipCampaign("FILE_LEDGER", "unsupported-entry");
    }
  }
  await walk("");
  return result;
}

async function requireExactCapsuleOutputSet(rootPath) {
  const actualNames = await listCapsuleFiles(rootPath);
  const sortedExpected = [...SEALED_CELL_OUTPUT_NAMES].sort((left, right) => (
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
  ));
  const sortedActual = [...actualNames].sort((left, right) => (
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
  ));
  if (
    sortedActual.length !== sortedExpected.length
    || sortedActual.some((entry, index) => entry !== sortedExpected[index])
  ) failPublicSourceZipCampaign("FILE_LEDGER", "exact-output-set");
  return Object.freeze(sortedActual);
}

function pathFor(rootPath, relativeName) {
  const result = path.join(rootPath, ...relativeName.split("/"));
  const relative = path.relative(rootPath, result);
  if (
    relative.length === 0
    || relative === ".."
    || relative.startsWith(".." + path.sep)
    || path.isAbsolute(relative)
  ) failPublicSourceZipCampaign("FILE_LEDGER", "ledger-containment");
  return result;
}

async function verifyInternal(options) {
  const normalized = exactOptions(options);
  const verifyLoadedTools = () => {
    if (normalized.loadedToolAuthorityBypass) return null;
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
    if (current === null) return;
    if (
      current.toolingCommit !== initialLoadedTools.toolingCommit
      || current.toolCount !== initialLoadedTools.toolCount
      || current.framedSha256 !== initialLoadedTools.framedSha256
      || current.gitExecutableSha256 !== initialLoadedTools.gitExecutableSha256
    ) failPublicSourceZipCampaign("D2_BINDING", "loaded-tool-attestation-changed");
  };
  const root = await inspectCapsuleRoot(normalized.capsuleRoot);
  await requireExactCapsuleOutputSet(root.path);
  const manifestPath = pathFor(root.path, "cell-manifest.json");
  const signaturePath = pathFor(root.path, "cell-manifest.sig");
  const rawManifest = await stableRead(
    manifestPath,
    Math.min(
      normalized.campaignPolicy.transportPolicy.maxManifestBytes,
      MAX_MANIFEST_BYTES,
    ),
    "CELL_MANIFEST",
    "manifest-read",
  );
  const rawSignature = await stableRead(
    signaturePath,
    Math.min(
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
      MAX_SIGNATURE_BYTES,
    ),
    "SIGNATURE",
    "signature-read",
  );
  if (rawSignature.bytes.length === 0) {
    failPublicSourceZipCampaign("SIGNATURE", "signature-empty");
  }
  await invokeTestAdapter(normalized.testAdapter, "before-signature");
  const signatureFingerprints = await verifyDetachedOpenPgpSignature({
    campaignPolicy: normalized.campaignPolicy,
    expectedPolicySha256: normalized.expectedPolicySha256,
    gpgRole: "cell-import-consumer-verify",
    hostRole: normalized.consumerHostRole,
    matrixCellId: normalized.matrixCellId,
    comparisonRole: null,
    signerRole: normalized.signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
    gpgExecutable: normalized.gpgExecutable,
    gpgHome: normalized.gpgHome,
    signatureFile: signaturePath,
    signedFile: manifestPath,
    allowedPrimaryFingerprints: [normalized.signer.fingerprint],
  });
  await invokeTestAdapter(normalized.testAdapter, "after-signature");
  const manifestAfterSignature = await stableRead(
    manifestPath,
    MAX_MANIFEST_BYTES,
    "CELL_MANIFEST",
    "manifest-read",
  );
  if (
    !rawManifest.bytes.equals(manifestAfterSignature.bytes)
    || !identitiesEqual(rawManifest.identity, manifestAfterSignature.identity)
  ) failPublicSourceZipCampaign("SIGNATURE", "mutable-signed-manifest");
  await recheckStableRead(
    signaturePath,
    rawSignature,
    Math.min(
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
      MAX_SIGNATURE_BYTES,
    ),
    "SIGNATURE",
    "signature-read",
  );
  requireUnchangedLoadedTools();

  const manifest = parseCanonicalCellManifestBytes(rawManifest.bytes);
  const expectedSigner = findAllowedSigner(
    normalized.campaignPolicy,
    manifest.matrixCellId,
  );
  if (signatureFingerprints.primaryFingerprint !== expectedSigner.fingerprint) {
    failPublicSourceZipCampaign("SIGNATURE", "signer-cell-mismatch");
  }
  const signatureRecord = validateSignatureVerificationRecord({
    documentKind: SIGNATURE_VERIFICATION_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    status: "ok",
    mode: "openpgp-detached-signature-verification",
    namespace: manifest.namespace,
    campaignId: manifest.campaignId,
    matrixCellId: manifest.matrixCellId,
    signerFingerprint: signatureFingerprints.primaryFingerprint,
    signerRole: expectedSigner.role,
    gpgRole: signatureFingerprints.gpgRole,
    hostRole: signatureFingerprints.hostRole,
    gpgVerifierProfileId: signatureFingerprints.profileId,
    gpgVerifierProfileSha256: signatureFingerprints.profileSha256,
    gpgAssignmentSha256: signatureFingerprints.assignmentSha256,
    gpgImmutableInstallationProfileSha256:
      signatureFingerprints.immutableInstallationProfileSha256,
    gpgQualificationResultSha256:
      signatureFingerprints.qualificationResultSha256,
    signatureVerified: true,
    primaryFingerprintVerified: true,
    policyBindingVerified: true,
    platformAttestationVerified: false,
  });
  if (
    manifest.namespace !== CELL_SIGNATURE_NAMESPACE
    || manifest.matrixCellId !== normalized.matrixCellId
    || manifest.campaignId !== normalized.campaignPolicy.campaignId
    || manifest.sourceCommit !== normalized.campaignPolicy.sourceCommit
    || manifest.toolingCommit !== normalized.campaignPolicy.toolingCommit
    || manifest.campaignPolicySha256 !== campaignPolicySha256(normalized.campaignPolicy)
    || manifest.producerGpgProfileId
      !== normalized.producerGpgAuthorities.signing.profile.profileId
    || manifest.producerGpgProfileSha256
      !== normalized.producerGpgAuthorities.signing.profileSha256
    || manifest.producerSignAssignmentSha256
      !== normalized.producerGpgAuthorities.signing.assignmentSha256
    || manifest.producerGpgImmutableInstallationProfileSha256
      !== normalized.producerGpgAuthorities.signing.immutableProfileSha256
    || manifest.producerLocalVerifierProfileId
      !== normalized.producerGpgAuthorities.localVerification.profile.profileId
    || manifest.producerLocalVerifierProfileSha256
      !== normalized.producerGpgAuthorities.localVerification.profileSha256
    || manifest.producerLocalVerifyAssignmentSha256
      !== normalized.producerGpgAuthorities.localVerification.assignmentSha256
    || manifest.producerLocalGpgImmutableInstallationProfileSha256
      !== normalized.producerGpgAuthorities.localVerification.immutableProfileSha256
    || signatureFingerprints.gpgRole !== "cell-import-consumer-verify"
    || signatureFingerprints.hostRole !== normalized.consumerHostRole
    || signatureFingerprints.profileId
      !== normalized.gpgAuthority.profile.profileId
    || signatureFingerprints.profileSha256
      !== normalized.gpgAuthority.profileSha256
    || signatureFingerprints.assignmentSha256
      !== normalized.gpgAuthority.assignmentSha256
    || signatureFingerprints.immutableInstallationProfileSha256
      !== normalized.gpgAuthority.immutableProfileSha256
    || signatureFingerprints.qualificationResultSha256
      !== normalized.gpgExecutionAuthority.qualificationResultSha256
  ) failPublicSourceZipCampaign("CELL_MANIFEST", "manifest-policy-binding");

  const payloadBytes = new Map();
  const payloadSnapshots = new Map();
  for (const ledgerEntry of manifest.fileLedger) {
    const input = await stableRead(
      pathFor(root.path, ledgerEntry.name),
      MAX_PAYLOAD_BYTES,
      "FILE_LEDGER",
      "ledger-file-read",
    );
    if (
      input.bytes.length !== ledgerEntry.byteLength
      || sha256(input.bytes) !== ledgerEntry.sha256
    ) failPublicSourceZipCampaign("FILE_LEDGER", "ledger-file-mismatch");
    payloadBytes.set(ledgerEntry.name, input.bytes);
    payloadSnapshots.set(ledgerEntry.name, Object.freeze({
      input,
      maximumBytes: MAX_PAYLOAD_BYTES,
    }));
    await invokeTestAdapter(normalized.testAdapter, "during-ledger");
  }
  await requireExactCapsuleOutputSet(root.path);
  const marker = await stableRead(
    pathFor(root.path, "cell.complete"),
    CELL_COMPLETION_MARKER.length,
    "OUTPUT_PUBLICATION",
    "completion-marker",
  );
  if (!marker.bytes.equals(CELL_COMPLETION_MARKER)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "completion-marker");
  }
  const d2Marker = payloadBytes.get("d2/.complete");
  if (!d2Marker || !d2Marker.equals(CELL_COMPLETION_MARKER)) {
    failPublicSourceZipCampaign("FILE_LEDGER", "d2-completion-marker");
  }
  if (
    !payloadBytes.get("authority/campaign-policy.json")?.equals(
      normalized.expectedCanonicalPolicyBytes,
    )
    || sha256(payloadBytes.get("authority/campaign-policy.json"))
      !== normalized.expectedPolicySha256
  ) failPublicSourceZipCampaign("POLICY", "transport-policy-swap");

  const v2Options = {
    campaignPolicy: pathFor(root.path, "authority/campaign-policy.json"),
    criticalToolSet: pathFor(root.path, "authority/critical-tool-set.json"),
    runtimeIdentity: pathFor(root.path, "authority/runtime-identity.json"),
    gitIdentity: pathFor(root.path, "authority/git-identity.json"),
    platformProbe: pathFor(root.path, "authority/platform-probe.json"),
    environmentLock: pathFor(root.path, "authority/environment-lock.json"),
    semanticInputSet: pathFor(root.path, "v2/semantic-input-set.json"),
    executionIdentity: pathFor(root.path, "v2/execution-identity.json"),
    platformClass: pathFor(root.path, "authority/platform-class.json"),
    runtimeClass: pathFor(root.path, "authority/runtime-class.json"),
    evidence: pathFor(root.path, "v2/evidence.json"),
    d2InputSet: pathFor(root.path, "d2/input-set.json"),
    d2SemanticReport: pathFor(root.path, "d2/semantic-report.json"),
    d2Evidence: pathFor(root.path, "d2/evidence.json"),
    d2VerificationResult: pathFor(root.path, "d2/verification-result.json"),
    artifact: pathFor(root.path, "d2/artifact.zip"),
    entryPlan: pathFor(root.path, "d2/entry-plan.json"),
    zipVerification: pathFor(root.path, "d2/zip-verification.json"),
    verificationResult: pathFor(root.path, "v2/verification-result.json"),
  };
  const v2Result = await verifyReproducibilityEvidenceV2(v2Options);
  for (const [name, snapshot] of payloadSnapshots) {
    await recheckStableRead(
      pathFor(root.path, name),
      snapshot.input,
      snapshot.maximumBytes,
      "CELL_VERIFICATION",
      "payload-identity-recheck",
    );
  }
  const evidence = parseCanonicalReproducibilityEvidenceV2Bytes(
    payloadBytes.get("v2/evidence.json"),
  );
  const storedV2Result = parseCanonicalVerificationResultV2Bytes(
    payloadBytes.get("v2/verification-result.json"),
  );
  validateV2EvidenceAndResultBinding(evidence, storedV2Result);
  validateV2EvidenceAndResultBinding(evidence, v2Result);
  const execution = parseCanonicalExecutionIdentityV2Bytes(
    payloadBytes.get("v2/execution-identity.json"),
  );
  const runtimeIdentity = parseCanonicalRuntimeIdentityBindingBytes(
    payloadBytes.get("authority/runtime-identity.json"),
  );
  const gitIdentity = parseCanonicalGitIdentityBindingBytes(
    payloadBytes.get("authority/git-identity.json"),
  );
  const cellResult = parseCanonicalCellResultBytes(
    payloadBytes.get("cell-result.json"),
  );
  const nodeQualification = parseCanonicalMeasuredQualificationResultBytes(
    payloadBytes.get("authority/node-qualification.json"),
  );
  const producerGpgQualification = parseCanonicalMeasuredQualificationResultBytes(
    payloadBytes.get("authority/producer-gpg-qualification.json"),
  );
  const producerLocalGpgQualification =
    parseCanonicalMeasuredQualificationResultBytes(
      payloadBytes.get("authority/producer-local-gpg-qualification.json"),
    );
  for (const key of [
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
  ]) {
    if (manifest[key] !== cellResult[key]) {
      failPublicSourceZipCampaign("CELL_RESULT", "manifest-result-binding");
    }
  }
  for (const key of [
    "semanticInputSetSha256",
    "executionIdentitySha256",
    "producerGpgProfileSha256",
    "platformClassSha256",
    "runtimeClassSha256",
    "artifactSha256",
    "entryPlanSha256",
    "zipVerificationSha256",
  ]) {
    if (cellResult[key] !== evidence[key]) {
      failPublicSourceZipCampaign("CELL_RESULT", "result-evidence-binding");
    }
  }
  if (
    sha256(payloadBytes.get("authority/runtime-identity.json"))
      !== execution.runtimeIdentitySha256
    || sha256(payloadBytes.get("authority/git-identity.json"))
      !== execution.gitIdentitySha256
    || execution.producerGpgProfileSha256
      !== normalized.producerGpgAuthorities.signing.profileSha256
    || evidence.producerGpgProfileSha256
      !== normalized.producerGpgAuthorities.signing.profileSha256
    || execution.nodeRuntimeProfileSha256 !== cellResult.nodeRuntimeProfileSha256
    || execution.nodeImmutableInstallationProfileSha256
      !== cellResult.nodeImmutableInstallationProfileSha256
    || execution.producerGpgImmutableInstallationProfileSha256
      !== cellResult.producerGpgImmutableInstallationProfileSha256
    || measuredQualificationResultSha256(nodeQualification)
      !== cellResult.nodeQualificationResultSha256
    || measuredQualificationResultSha256(producerGpgQualification)
      !== cellResult.producerSignQualificationResultSha256
    || measuredQualificationResultSha256(producerLocalGpgQualification)
      !== cellResult.producerLocalVerifyQualificationResultSha256
    || nodeQualification.status !== "qualified"
    || producerGpgQualification.status !== "qualified"
    || producerLocalGpgQualification.status !== "qualified"
    || nodeQualification.profileSha256
      !== cellResult.nodeImmutableInstallationProfileSha256
    || producerGpgQualification.profileSha256
      !== cellResult.producerGpgImmutableInstallationProfileSha256
    || producerLocalGpgQualification.profileSha256
      !== cellResult.producerLocalGpgImmutableInstallationProfileSha256
    || runtimeIdentity.implementation !== "node"
    || gitIdentity.objectFormat !== "sha1"
  ) failPublicSourceZipCampaign("CELL_VERIFICATION", "execution-authority-binding");

  await invokeTestAdapter(normalized.testAdapter, "before-final-root-check");
  await invokeTestAdapter(normalized.testAdapter, "before-final-return");
  await recheckStableRead(
    manifestPath,
    rawManifest,
    Math.min(
      normalized.campaignPolicy.transportPolicy.maxManifestBytes,
      MAX_MANIFEST_BYTES,
    ),
    "CELL_MANIFEST",
    "manifest-final-recheck",
  );
  await recheckStableRead(
    signaturePath,
    rawSignature,
    Math.min(
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
      MAX_SIGNATURE_BYTES,
    ),
    "SIGNATURE",
    "signature-final-recheck",
  );
  await recheckStableRead(
    pathFor(root.path, "cell.complete"),
    marker,
    CELL_COMPLETION_MARKER.length,
    "OUTPUT_PUBLICATION",
    "marker-final-recheck",
  );
  for (const [name, snapshot] of payloadSnapshots) {
    await recheckStableRead(
      pathFor(root.path, name),
      snapshot.input,
      snapshot.maximumBytes,
      "CELL_VERIFICATION",
      "payload-final-recheck",
    );
  }
  await requireExactCapsuleOutputSet(root.path);
  const finalRoot = await inspectCapsuleRoot(root.path);
  if (!identitiesEqual(root.identity, finalRoot.identity)) {
    failPublicSourceZipCampaign("CELL_VERIFICATION", "mutable-capsule-root");
  }
  recheckCurrentNodeProcessAuthority({
    campaignPolicy: normalized.campaignPolicy,
    campaignRole: "cell-import-consumer",
    matrixCellId: null,
    hostRole: normalized.consumerHostRole,
    expectedRuntimeIdentitySha256:
      normalized.nodeAuthority.runtimeIdentitySha256,
    expectedQualificationResultSha256:
      normalized.nodeAuthority.qualificationResultSha256,
  });
  requireUnchangedLoadedTools();
  return validateCellVerificationResult({
    documentKind: CELL_VERIFICATION_DOCUMENT_KIND,
    schemaVersion: CAMPAIGN_SCHEMA_VERSION,
    status: "ok",
    mode: "public-source-zip-campaign-cell-verification",
    campaignId: evidence.campaignId,
    matrixCellId: evidence.matrixCellId,
    sourceCommit: evidence.sourceCommit,
    toolingCommit: evidence.toolingCommit,
    campaignPolicySha256: manifest.campaignPolicySha256,
    runNonce: execution.runNonce,
    nodeRuntimeProfileId: manifest.nodeRuntimeProfileId,
    nodeRuntimeProfileSha256: manifest.nodeRuntimeProfileSha256,
    nodeImmutableInstallationProfileSha256:
      manifest.nodeImmutableInstallationProfileSha256,
    nodeQualificationResultSha256: manifest.nodeQualificationResultSha256,
    producerGpgProfileId: manifest.producerGpgProfileId,
    producerGpgProfileSha256: manifest.producerGpgProfileSha256,
    producerGpgImmutableInstallationProfileSha256:
      manifest.producerGpgImmutableInstallationProfileSha256,
    producerSignAssignmentSha256: manifest.producerSignAssignmentSha256,
    producerSignQualificationResultSha256:
      manifest.producerSignQualificationResultSha256,
    producerLocalVerifierProfileId: manifest.producerLocalVerifierProfileId,
    producerLocalVerifierProfileSha256:
      manifest.producerLocalVerifierProfileSha256,
    producerLocalGpgImmutableInstallationProfileSha256:
      manifest.producerLocalGpgImmutableInstallationProfileSha256,
    producerLocalVerifyAssignmentSha256:
      manifest.producerLocalVerifyAssignmentSha256,
    producerLocalVerifyQualificationResultSha256:
      manifest.producerLocalVerifyQualificationResultSha256,
    verificationRole: "cell-import-consumer-verify",
    verificationHostRole: normalized.consumerHostRole,
    consumerNodeRuntimeProfileId: normalized.nodeAuthority.profileId,
    consumerNodeRuntimeProfileSha256: normalized.nodeAuthority.profileSha256,
    consumerNodeImmutableInstallationProfileSha256:
      normalized.nodeAuthority.immutableInstallationProfileSha256,
    consumerNodeQualificationResultSha256:
      normalized.nodeAuthority.qualificationResultSha256,
    consumerRuntimeIdentitySha256:
      normalized.nodeAuthority.runtimeIdentitySha256,
    consumerVerifierProfileId: signatureRecord.gpgVerifierProfileId,
    consumerVerifierProfileSha256: signatureRecord.gpgVerifierProfileSha256,
    consumerVerifyAssignmentSha256: signatureRecord.gpgAssignmentSha256,
    consumerImmutableInstallationProfileSha256:
      signatureRecord.gpgImmutableInstallationProfileSha256,
    consumerQualificationResultSha256:
      signatureRecord.gpgQualificationResultSha256,
    semanticInputSetSha256: evidence.semanticInputSetSha256,
    executionIdentitySha256: evidence.executionIdentitySha256,
    platformClassSha256: evidence.platformClassSha256,
    runtimeClassSha256: evidence.runtimeClassSha256,
    runtimeIdentitySha256: execution.runtimeIdentitySha256,
    gitIdentitySha256: execution.gitIdentitySha256,
    artifactSha256: evidence.artifactSha256,
    entryPlanSha256: evidence.entryPlanSha256,
    zipVerificationSha256: evidence.zipVerificationSha256,
    evidenceSha256: sha256(payloadBytes.get("v2/evidence.json")),
    verificationResultSha256: sha256(payloadBytes.get("v2/verification-result.json")),
    signerFingerprint: signatureRecord.signerFingerprint,
    signerRole: signatureRecord.signerRole,
    signatureNamespace: signatureRecord.namespace,
    signatureVerified: true,
    fileLedgerVerified: true,
    exactOutputSetVerified: true,
    d1CanonicalVerificationPassed: cellResult.d1CanonicalVerificationPassed,
    d2SameProcessPassed: cellResult.d2SameProcessPassed,
    d2SameHostPassed: cellResult.d2SameHostPassed,
    boundaryVectorSetPassed: cellResult.boundaryVectorSetPassed,
    privacyGatePassed: cellResult.privacyGatePassed,
    temporaryRootCleanupVerified: cellResult.temporaryRootCleanupVerified,
    environmentBlockerAbsent: cellResult.environmentBlockerAbsent,
    comparisonEligible: v2Result.comparisonEligible,
    platformAttestationVerified: false,
    projectPublicationAuthorized: false,
  });
}

export async function verifyPublicSourceZipCampaignCell(options = {}) {
  return verifyInternal(options);
}

function parseCli(argv) {
  authority(argv);
  const mapping = new Map([
    ["--capsule-root", "capsuleRoot"],
    ["--expected-campaign-policy", "expectedPolicyPath"],
    ["--expected-policy-sha256", "expectedPolicySha256"],
    ["--campaign-id", "campaignId"],
    ["--source-commit", "sourceCommit"],
    ["--tooling-commit", "toolingCommit"],
    ["--matrix-cell-id", "matrixCellId"],
    ["--consumer-host-role", "consumerHostRole"],
    ["--gpg", "gpgExecutable"],
    ["--gpg-home", "gpgHome"],
    ["--repository", "repository"],
    ["--git", "gitExecutable"],
    ["--git-identity", "gitIdentity"],
  ]);
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(values, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) failPublicSourceZipCampaign("CLI", "unknown-or-duplicate-option");
    values[key] = argv[index + 1];
    index += 1;
  }
  if ([
    "capsuleRoot", "expectedPolicyPath", "expectedPolicySha256", "campaignId",
    "sourceCommit", "toolingCommit", "matrixCellId", "consumerHostRole",
    "gpgExecutable", "gpgHome",
    "repository", "gitExecutable", "gitIdentity",
  ].some(
    (key) => !Object.hasOwn(values, key),
  )) failPublicSourceZipCampaign("CLI", "required-options");
  return values;
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
    expectedCanonicalPolicyBytes = await readFile(cli.expectedPolicyPath);
  } catch {
    failPublicSourceZipCampaign("POLICY", "campaign-policy-invalid");
  }
  try {
    gitIdentity = parseCanonicalGitIdentityBindingBytes(await readFile(cli.gitIdentity));
  } catch {
    failPublicSourceZipCampaign("GIT_IDENTITY", "git-identity-invalid");
  }
  const result = await verifyInternal({
    capsuleRoot: cli.capsuleRoot,
    expectedCanonicalPolicyBytes,
    expectedPolicySha256: cli.expectedPolicySha256,
    campaignId: cli.campaignId,
    sourceCommit: cli.sourceCommit,
    toolingCommit: cli.toolingCommit,
    matrixCellId: cli.matrixCellId,
    consumerHostRole: cli.consumerHostRole,
    gpgExecutable: cli.gpgExecutable,
    gpgHome: cli.gpgHome,
    repository: cli.repository,
    gitExecutable: cli.gitExecutable,
    gitIdentity,
  });
  process.stdout.write(encodeCanonicalCellVerificationResult(result));
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
