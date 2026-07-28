#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import {
  access,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rmdir,
  statfs,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertProxyFreeAuthorityGraph,
  encodeCanonicalCriticalToolSet,
  parseCanonicalInputSet,
  parseCanonicalPublicJsonBytes,
  validateCriticalToolSetDocument,
} from "./public-source-zip-reproducibility-core.mjs";
import { preparePublicSourceZipReproducibility } from "./prepare-public-source-zip-reproducibility.mjs";
import {
  buildExecutionIdentityV2,
  buildPlatformClassV2,
  buildReproducibilityEvidenceV2,
  buildRuntimeClassV2,
  buildSemanticInputSetV2,
  encodeCanonicalExecutionIdentityV2,
  encodeCanonicalPlatformClassV2,
  encodeCanonicalReproducibilityEvidenceV2,
  encodeCanonicalRuntimeClassV2,
  encodeCanonicalSemanticInputSetV2,
  encodeCanonicalVerificationResultV2,
} from "./reproducibility-evidence-v2-core.mjs";
import {
  CAMPAIGN_SCHEMA_VERSION,
  CELL_COMPLETION_MARKER,
  CELL_PAYLOAD_NAMES,
  CELL_SIGNATURE_NAMESPACE,
  PublicSourceZipCampaignError,
  buildCellFileLedger,
  buildCellManifest,
  buildCellResult,
  buildEnvironmentLock,
  buildPlatformProbe,
  encodeCanonicalCampaignPolicy,
  encodeCanonicalCellManifest,
  encodeCanonicalCellResult,
  encodeCanonicalEnvironmentLock,
  encodeCanonicalGitIdentityBinding,
  encodeCanonicalMeasuredQualificationResult,
  encodeCanonicalNodeRuntimeProfile,
  encodeCanonicalPlatformProbe,
  encodeCanonicalRuntimeIdentityBinding,
  failPublicSourceZipCampaign,
  findAllowedSigner,
  findCampaignCell,
  findCellProducerGpgAuthorities,
  findNodeRuntimeAssignment,
  measureCurrentNodeProcessAuthority,
  recheckCurrentNodeProcessAuthority,
  nodeRuntimeProfileSha256,
  parseCanonicalCampaignPolicyBytes,
  parseCanonicalGitIdentityBindingBytes,
  parseCanonicalNodeRuntimeProfileBytes,
  campaignPolicySha256,
  validateCampaignPolicy,
  validateProfiledGpgExecutionContext,
  verifyCampaignLoadedToolBytes,
  runProfiledGpgOperation,
} from "./public-source-zip-campaign-core.mjs";
import { verifyReproducibilityEvidenceV2 } from "./verify-reproducibility-evidence-v2.mjs";
import {
  verifyDetachedOpenPgpSignature,
} from "./verify-public-source-zip-campaign-cell.mjs";

const PREPARER_TEST_ADAPTER = Symbol(
  "ieltmps.r1-10e.campaign-preparer.test-adapter",
);
const AUTHORITY_OPTIONS = Object.freeze({
  allowedSymbols: Object.freeze([PREPARER_TEST_ADAPTER]),
  allowFunctions: true,
});
const OPTION_KEYS = Object.freeze([
  "campaignPolicy",
  "matrixCellId",
  "repository",
  "sourceCommit",
  "manifest",
  "membershipReport",
  "d2RunnerPolicy",
  "nodeRuntimeProfile",
  "gitIdentity",
  "gitExecutable",
  "criticalToolSet",
  "testVectorSet",
  "outputDirectory",
  "gpgExecutable",
  "gpgHome",
  "signingFingerprint",
]);
const D2_OUTPUT_NAMES = Object.freeze([
  "artifact.zip",
  "zip-verification.json",
  "entry-plan.json",
  "input-set.json",
  "semantic-report.json",
  "evidence.json",
  "verification-result.json",
  ".complete",
]);
const MAX_DOCUMENT_BYTES = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;
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
  const keys = Reflect.ownKeys(options);
  for (const key of keys) {
    if (key === PREPARER_TEST_ADAPTER) continue;
    if (typeof key !== "string" || !OPTION_KEYS.includes(key)) {
      failPublicSourceZipCampaign("CLI", "api-option-key");
    }
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      failPublicSourceZipCampaign("CLI", "api-option-descriptor");
    }
  }
  for (const key of OPTION_KEYS) {
    if (!Object.hasOwn(options, key)) {
      failPublicSourceZipCampaign("CLI", "api-required-option");
    }
  }
  const policy = validateCampaignPolicy(options.campaignPolicy);
  const cell = findCampaignCell(policy, options.matrixCellId);
  const signer = findAllowedSigner(policy, cell.matrixCellId);
  if (
    options.sourceCommit !== policy.sourceCommit
    || options.signingFingerprint !== signer.fingerprint
  ) failPublicSourceZipCampaign("POLICY", "preparation-policy-binding");
  for (const key of [
    "repository",
    "manifest",
    "membershipReport",
    "d2RunnerPolicy",
    "nodeRuntimeProfile",
    "gitIdentity",
    "gitExecutable",
    "criticalToolSet",
    "testVectorSet",
    "outputDirectory",
    "gpgExecutable",
    "gpgHome",
  ]) {
    if (typeof options[key] !== "string" || !path.isAbsolute(options[key])) {
      failPublicSourceZipCampaign("CLI", "absolute-path-option");
    }
  }
  if (!FINGERPRINT_PATTERN.test(options.signingFingerprint)) {
    failPublicSourceZipCampaign("SIGNATURE", "signing-fingerprint");
  }
  const gpgAuthorities = findCellProducerGpgAuthorities(
    policy,
    cell.matrixCellId,
  );
  const expectedPolicySha256 = campaignPolicySha256(policy);
  const producerSigningAuthority = validateProfiledGpgExecutionContext({
    gpgRole: "cell-producer-sign",
    operation: "detached-sign",
    executablePath: options.gpgExecutable,
    gpgHome: options.gpgHome,
    campaignPolicy: policy,
    expectedPolicySha256,
    matrixCellId: cell.matrixCellId,
    comparisonRole: null,
    hostRole: cell.matrixCellId,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
  const producerLocalVerificationAuthority = validateProfiledGpgExecutionContext({
    gpgRole: "cell-producer-local-verify",
    operation: "detached-verify",
    executablePath: options.gpgExecutable,
    gpgHome: options.gpgHome,
    campaignPolicy: policy,
    expectedPolicySha256,
    matrixCellId: cell.matrixCellId,
    comparisonRole: null,
    hostRole: cell.matrixCellId,
    signerRole: signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
  });
  return Object.freeze({
    ...Object.fromEntries(OPTION_KEYS.map((key) => [key, options[key]])),
    campaignPolicy: policy,
    cell,
    signer,
    expectedPolicySha256,
    gpgAuthorities,
    producerSigningAuthority,
    producerLocalVerificationAuthority,
    testAdapter:
      Object.getOwnPropertyDescriptor(options, PREPARER_TEST_ADAPTER)?.value ?? null,
  });
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

function ownedIdentity(state, kind) {
  const common = {
    dev: state.dev,
    ino: state.ino,
    mode: state.mode,
  };
  if (kind === "directory") return Object.freeze(common);
  return Object.freeze({
    ...common,
    size: state.size,
    nlink: state.nlink,
    mtimeNs: state.mtimeNs,
    ctimeNs: state.ctimeNs,
  });
}

function sameOwnedIdentity(left, right) {
  const keys = Reflect.ownKeys(left);
  return keys.length === Reflect.ownKeys(right).length
    && keys.every((key) => left[key] === right[key]);
}

async function inspectOwnedPath(literalPath, kind) {
  try {
    const state = await lstat(literalPath, { bigint: true });
    if (
      state.isSymbolicLink()
      || (kind === "directory" && !state.isDirectory())
      || (kind === "file" && (!state.isFile() || state.nlink !== 1n))
      || comparable(await realpath(literalPath)) !== comparable(literalPath)
    ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    return ownedIdentity(state, kind);
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
}

async function createOwnershipLedger(rootPath, parentPath) {
  const root = path.resolve(rootPath);
  const parent = path.resolve(parentPath);
  const ledger = {
    root,
    parent,
    parentIdentity: await inspectOwnedPath(parent, "directory"),
    records: new Map(),
    events: [],
    nextOrder: 1,
    phaseTwoStarted: false,
  };
  const rootRecord = Object.freeze({
    literalPath: root,
    kind: "directory",
    identity: await inspectOwnedPath(root, "directory"),
    order: ledger.nextOrder++,
  });
  ledger.records.set(root, rootRecord);
  ledger.events.push(Object.freeze({ event: "create", record: rootRecord }));
  return ledger;
}

async function recordOwnedPath(ledger, literalPath, kind) {
  const target = path.resolve(literalPath);
  const relative = path.relative(ledger.root, target);
  const parent = path.dirname(target);
  if (
    target === ledger.root
    || relative === ".."
    || relative.startsWith(".." + path.sep)
    || path.isAbsolute(relative)
    || ledger.records.has(target)
    || !ledger.records.has(parent)
    || ledger.records.get(parent).kind !== "directory"
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  const record = Object.freeze({
    literalPath: target,
    kind,
    identity: await inspectOwnedPath(target, kind),
    order: ledger.nextOrder++,
  });
  ledger.records.set(target, record);
  ledger.events.push(Object.freeze({ event: "create", record }));
  return record;
}

async function observedOwnedPaths(ledger) {
  const observed = new Map();
  const walk = async (directoryPath) => {
    const directoryIdentity = await inspectOwnedPath(directoryPath, "directory");
    observed.set(directoryPath, Object.freeze({
      kind: "directory",
      identity: directoryIdentity,
    }));
    let entries;
    try {
      entries = await readdir(directoryPath, { withFileTypes: true });
    } catch {
      failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    }
    for (const entry of entries) {
      const child = path.join(directoryPath, entry.name);
      if (entry.isSymbolicLink()) {
        failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
      }
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile()) {
        observed.set(child, Object.freeze({
          kind: "file",
          identity: await inspectOwnedPath(child, "file"),
        }));
      } else failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    }
  };
  await walk(ledger.root);
  return observed;
}

async function freezeCleanupPlan(ledger) {
  if (ledger.phaseTwoStarted) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  const parentIdentity = await inspectOwnedPath(ledger.parent, "directory");
  if (!sameOwnedIdentity(parentIdentity, ledger.parentIdentity)) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  const observed = await observedOwnedPaths(ledger);
  if (observed.size !== ledger.records.size) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  for (const [literalPath, record] of ledger.records) {
    const current = observed.get(literalPath);
    if (
      !current
      || current.kind !== record.kind
      || !sameOwnedIdentity(current.identity, record.identity)
    ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  const actions = [...ledger.records.values()].sort((left, right) => {
    if (left.kind !== right.kind) return left.kind === "file" ? -1 : 1;
    if (left.kind === "directory") {
      const leftDepth = left.literalPath.split(path.sep).length;
      const rightDepth = right.literalPath.split(path.sep).length;
      if (leftDepth !== rightDepth) return rightDepth - leftDepth;
    }
    return right.order - left.order;
  });
  return Object.freeze(actions);
}

async function cleanupOwnedTree(ledger, forceUncertainty = false) {
  const first = await freezeCleanupPlan(ledger);
  if (forceUncertainty) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  const second = await freezeCleanupPlan(ledger);
  if (
    first.length !== second.length
    || first.some((record, index) => record !== second[index])
  ) failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  ledger.phaseTwoStarted = true;
  ledger.events.push(Object.freeze({ event: "phase-two-start" }));
  let unlinkCount = 0;
  let rmdirCount = 0;
  for (const record of second) {
    const current = await inspectOwnedPath(record.literalPath, record.kind);
    if (!sameOwnedIdentity(current, record.identity)) {
      failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
    }
    try {
      if (record.kind === "file") {
        await unlink(record.literalPath);
        unlinkCount += 1;
      } else {
        await rmdir(record.literalPath);
        rmdirCount += 1;
      }
    } catch {
      failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
    }
    ledger.events.push(Object.freeze({ event: "remove", record }));
  }
  if (await pathExists(ledger.root)) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
  }
  return Object.freeze({ unlinkCount, rmdirCount });
}

async function revokeOwnedCompletionMarker(ledger) {
  const markerPath = path.join(ledger.root, "cell.complete");
  const record = ledger.records.get(markerPath);
  if (!record) return;
  const current = await inspectOwnedPath(markerPath, "file");
  if (!sameOwnedIdentity(current, record.identity)) {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-identity-uncertain");
  }
  try {
    await unlink(markerPath);
  } catch {
    failPublicSourceZipCampaign("CLEANUP", "cleanup-incomplete");
  }
  ledger.records.delete(markerPath);
  ledger.events.push(Object.freeze({ event: "revoke-marker", record }));
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
    const before = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== initial.dev
      || before.ino !== initial.ino
      || before.size !== initial.size
      || before.nlink !== initial.nlink
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.nlink !== before.nlink
      || bytes.length !== Number(initial.size)
    ) failPublicSourceZipCampaign(phase, "mutable-input");
    return Object.freeze({
      bytes,
      identity: Object.freeze({ dev: initial.dev, ino: initial.ino, nlink: initial.nlink }),
    });
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign(phase, reason);
  } finally {
    if (handle) await handle.close();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireEnvironmentLock() {
  if (
    process.env.LANG !== "C"
    || process.env.LC_ALL !== "C"
    || process.env.TZ !== "UTC"
    || process.env.SOURCE_DATE_EPOCH !== "0"
  ) failPublicSourceZipCampaign("ENVIRONMENT_LOCK", "process-environment-mismatch");
}

async function inspectOutputTarget(outputDirectory, repository) {
  if (
    comparable(outputDirectory) === comparable(repository)
    || comparable(outputDirectory).startsWith(comparable(repository) + path.sep)
  ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "repository-containment");
  if (await pathExists(outputDirectory)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-directory-exists");
  }
  const parentPath = path.dirname(outputDirectory);
  try {
    const parentState = await lstat(parentPath, { bigint: true });
    if (
      !parentState.isDirectory()
      || parentState.isSymbolicLink()
      || comparable(await realpath(parentPath)) !== comparable(parentPath)
    ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-parent-identity");
  } catch (error) {
    if (error instanceof PublicSourceZipCampaignError) throw error;
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-parent-identity");
  }
  return parentPath;
}

async function measureCapabilities(privateRoot) {
  const probeRoot = path.join(privateRoot, "capability");
  await mkdir(probeRoot, { recursive: false, mode: 0o700 });
  const original = path.join(probeRoot, "original");
  const linked = path.join(probeRoot, "linked");
  await writeFile(original, Buffer.from("capability\n", "ascii"), {
    flag: "wx",
    mode: 0o600,
  });
  await link(original, linked);
  const left = await lstat(original, { bigint: true });
  const right = await lstat(linked, { bigint: true });
  const hardLinkSupported = left.nlink === 2n
    && right.nlink === 2n
    && left.dev === right.dev
    && left.ino === right.ino;
  await unlink(linked);
  await unlink(original);
  await rmdir(probeRoot);
  if (!hardLinkSupported) {
    failPublicSourceZipCampaign("PLATFORM_PROBE", "hard-link-not-supported");
  }
  return Object.freeze({
    nativeFilesystemStatSupported: true,
    exclusiveCreateSupported: true,
    hardLinkSupported: true,
    stableFileIdentitySupported: true,
  });
}

function nativeOsFamily() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return "linux";
  failPublicSourceZipCampaign("PLATFORM_PROBE", "unsupported-os-family");
}

async function measuredPlatform(privateRoot) {
  if (process.arch !== "x64") {
    failPublicSourceZipCampaign("PLATFORM_PROBE", "unsupported-architecture");
  }
  const nativeStat = await statfs(privateRoot, { bigint: true });
  const typeCode = BigInt.asUintN(64, nativeStat.type).toString(16);
  const osFamily = nativeOsFamily();
  let filesystemClass;
  if (osFamily === "windows") filesystemClass = "ntfs";
  else if (typeCode.toLowerCase() === "ef53") filesystemClass = "ext4-class";
  else failPublicSourceZipCampaign("PLATFORM_PROBE", "unsupported-filesystem-class");
  return Object.freeze({
    osFamily,
    osRelease: os.release(),
    osVersion: os.version(),
    architecture: process.arch,
    filesystemTypeCode: "native-" + typeCode.toLowerCase(),
    filesystemClass,
    capabilities: await measureCapabilities(privateRoot),
  });
}

async function invokeTestCheckpoint(testAdapter, checkpoint) {
  if (!testAdapter || testAdapter.checkpoint === undefined) return;
  const pending = testAdapter.checkpoint(Object.freeze({ checkpoint }));
  authority(pending, { allowPromise: true });
  const returned = await pending;
  authority(returned);
  if (returned !== undefined) failPublicSourceZipCampaign("CLI", "test-adapter-return-value");
}

async function invokeD2(normalized, outputDirectory, runtimeIdentityPath) {
  if (normalized.testAdapter?.prepareD2Bundle !== undefined) {
    const pending = normalized.testAdapter.prepareD2Bundle(Object.freeze({
      outputDirectory,
      campaignId: normalized.campaignPolicy.campaignId,
      matrixCellId: normalized.matrixCellId,
      sourceCommit: normalized.sourceCommit,
      toolingCommit: normalized.campaignPolicy.toolingCommit,
      runtimeIdentityPath,
    }));
    authority(pending, { allowPromise: true });
    const returned = await pending;
    authority(returned);
    if (returned !== undefined) {
      failPublicSourceZipCampaign("CLI", "test-adapter-return-value");
    }
    return;
  }
  await preparePublicSourceZipReproducibility({
    repository: normalized.repository,
    sourceCommit: normalized.sourceCommit,
    manifest: normalized.manifest,
    membershipReport: normalized.membershipReport,
    runnerPolicy: normalized.d2RunnerPolicy,
    runtimeIdentity: runtimeIdentityPath,
    gitIdentity: normalized.gitIdentity,
    outputDirectory,
  });
}

async function readD2Bundle(directory) {
  let names;
  try {
    names = await readdir(directory);
  } catch {
    failPublicSourceZipCampaign("D2_BINDING", "d2-output-missing");
  }
  const sorted = [...names].sort();
  const expected = [...D2_OUTPUT_NAMES].sort();
  if (
    sorted.length !== expected.length
    || sorted.some((entry, index) => entry !== expected[index])
  ) failPublicSourceZipCampaign("D2_BINDING", "d2-output-set");
  const result = Object.create(null);
  for (const name of D2_OUTPUT_NAMES) {
    const maximum = name === "artifact.zip" ? MAX_ARTIFACT_BYTES : MAX_DOCUMENT_BYTES;
    result[name] = await stableRead(
      path.join(directory, name),
      maximum,
      "D2_BINDING",
      "d2-output-read",
    );
  }
  if (!result[".complete"].bytes.equals(CELL_COMPLETION_MARKER)) {
    failPublicSourceZipCampaign("D2_BINDING", "d2-completion-marker");
  }
  const artifactIdentity = result["artifact.zip"].identity;
  for (const name of D2_OUTPUT_NAMES.filter((entry) => entry !== "artifact.zip")) {
    const identity = result[name].identity;
    if (identity.dev === artifactIdentity.dev && identity.ino === artifactIdentity.ino) {
      failPublicSourceZipCampaign("D2_BINDING", "d2-hard-link-alias");
    }
  }
  return result;
}

function d2BundleForV2(bundle) {
  return {
    inputSetBytes: bundle["input-set.json"].bytes,
    semanticReportBytes: bundle["semantic-report.json"].bytes,
    evidenceBytes: bundle["evidence.json"].bytes,
    verificationResultBytes: bundle["verification-result.json"].bytes,
    artifactBytes: bundle["artifact.zip"].bytes,
    entryPlanBytes: bundle["entry-plan.json"].bytes,
    zipVerificationBytes: bundle["zip-verification.json"].bytes,
  };
}

async function writeOwnedFile(root, relativeName, bytes, ownershipLedger = null) {
  if (!Buffer.isBuffer(bytes)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-bytes");
  }
  const target = path.join(root, ...relativeName.split("/"));
  const relative = path.relative(root, target);
  if (
    relative.length === 0
    || relative === ".."
    || relative.startsWith(".." + path.sep)
    || path.isAbsolute(relative)
  ) failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-containment");
  await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
  const confirmed = await stableRead(
    target,
    Math.max(bytes.length, 1),
    "OUTPUT_PUBLICATION",
    "output-file-identity",
  );
  if (!confirmed.bytes.equals(bytes)) {
    failPublicSourceZipCampaign("OUTPUT_PUBLICATION", "output-file-bytes");
  }
  if (ownershipLedger !== null) {
    await recordOwnedPath(ownershipLedger, target, "file");
  }
}

async function signManifest(normalized, manifestPath, signaturePath) {
  return runProfiledGpgOperation({
    gpgRole: "cell-producer-sign",
    operation: "detached-sign",
    executablePath: normalized.gpgExecutable,
    gpgHome: normalized.gpgHome,
    campaignPolicy: normalized.campaignPolicy,
    expectedPolicySha256: normalized.expectedPolicySha256,
    matrixCellId: normalized.matrixCellId,
    comparisonRole: null,
    hostRole: normalized.matrixCellId,
    signerRole: normalized.signer.role,
    signatureNamespace: CELL_SIGNATURE_NAMESPACE,
    signingFingerprint: normalized.signingFingerprint,
    signatureFile: signaturePath,
    signedFile: manifestPath,
    allowedPrimaryFingerprints: null,
  });
}

async function prepareInternal(options) {
  const normalized = normalizeOptions(options);
  requireEnvironmentLock();
  const nodeAuthority = measureCurrentNodeProcessAuthority({
    campaignPolicy: normalized.campaignPolicy,
    campaignRole: "cell-producer",
    matrixCellId: normalized.matrixCellId,
    hostRole: normalized.matrixCellId,
  });
  const expectedNodeBytes = await stableRead(
    normalized.nodeRuntimeProfile,
    MAX_DOCUMENT_BYTES,
    "RUNTIME_IDENTITY",
    "node-runtime-profile-read",
  );
  let expectedNodeProfile;
  try {
    expectedNodeProfile = parseCanonicalNodeRuntimeProfileBytes(
      expectedNodeBytes.bytes,
    );
  } catch {
    failPublicSourceZipCampaign("RUNTIME_IDENTITY", "node-runtime-profile-invalid");
  }
  const selectedNodeAuthority = findNodeRuntimeAssignment(
    normalized.campaignPolicy,
    {
      campaignRole: "cell-producer",
      matrixCellId: normalized.matrixCellId,
      hostRole: normalized.matrixCellId,
    },
  );
  if (
    expectedNodeProfile.profileId !== selectedNodeAuthority.profile.profileId
    || nodeRuntimeProfileSha256(expectedNodeProfile)
      !== selectedNodeAuthority.profileSha256
    || !expectedNodeBytes.bytes.equals(
      encodeCanonicalNodeRuntimeProfile(expectedNodeProfile),
    )
  ) failPublicSourceZipCampaign("RUNTIME_IDENTITY", "expected-node-profile-mismatch");
  const runtimeIdentity = nodeAuthority.runtimeIdentity;
  const gitBytes = await stableRead(
    normalized.gitIdentity,
    MAX_DOCUMENT_BYTES,
    "GIT_IDENTITY",
    "git-identity-read",
  );
  let gitIdentity;
  try {
    gitIdentity = parseCanonicalGitIdentityBindingBytes(gitBytes.bytes);
  } catch {
    failPublicSourceZipCampaign("GIT_IDENTITY", "git-identity-invalid");
  }
  const verifyLoadedTools = () => {
    if (normalized.testAdapter?.loadedToolAuthorityBypass === true) {
      return Object.freeze({
        toolingCommit: normalized.campaignPolicy.toolingCommit,
        toolCount: 0,
        framedSha256: "0".repeat(64),
        gitExecutableSha256: gitIdentity.executableSha256,
      });
    }
    return verifyCampaignLoadedToolBytes({
      repository: normalized.repository,
      toolingCommit: normalized.campaignPolicy.toolingCommit,
      gitExecutable: normalized.gitExecutable,
      gitIdentity,
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
  const parent = await inspectOutputTarget(
    normalized.outputDirectory,
    normalized.repository,
  );
  const criticalBytes = await stableRead(
    normalized.criticalToolSet,
    MAX_DOCUMENT_BYTES,
    "D2_BINDING",
    "critical-tool-set-read",
  );
  const manifestBytes = await stableRead(
    normalized.manifest,
    MAX_DOCUMENT_BYTES,
    "D2_BINDING",
    "manifest-read",
  );
  const membershipBytes = await stableRead(
    normalized.membershipReport,
    MAX_DOCUMENT_BYTES,
    "D2_BINDING",
    "membership-report-read",
  );
  const vectorBytes = await stableRead(
    normalized.testVectorSet,
    MAX_DOCUMENT_BYTES,
    "D2_BINDING",
    "test-vector-set-read",
  );
  let criticalToolSet;
  try {
    criticalToolSet = validateCriticalToolSetDocument(
      parseCanonicalPublicJsonBytes(criticalBytes.bytes, "TOOL_SET"),
    );
    parseCanonicalPublicJsonBytes(vectorBytes.bytes, "BOUNDARY_VECTOR");
  } catch {
    failPublicSourceZipCampaign("D2_BINDING", "supporting-authority-invalid");
  }
  if (
    sha256(vectorBytes.bytes) !== normalized.campaignPolicy.vectorSetSha256
    || criticalToolSet.toolingCommit !== normalized.campaignPolicy.toolingCommit
  ) failPublicSourceZipCampaign("D2_BINDING", "supporting-authority-binding");

  let privateRoot = null;
  let privateLedger = null;
  let outputLedger = null;
  try {
    privateRoot = path.resolve(await mkdtemp(path.join(parent, ".r1e1-")));
    privateLedger = await createOwnershipLedger(privateRoot, parent);
    const measuredRuntimeIdentityPath = path.join(
      privateRoot,
      "measured-runtime-identity.json",
    );
    await writeOwnedFile(
      privateRoot,
      "measured-runtime-identity.json",
      encodeCanonicalRuntimeIdentityBinding(runtimeIdentity),
      privateLedger,
    );
    const d2Directory = path.join(privateRoot, "d2-output");
    await invokeD2(normalized, d2Directory, measuredRuntimeIdentityPath);
    const d2 = await readD2Bundle(d2Directory);
    recheckCurrentNodeProcessAuthority({
      campaignPolicy: normalized.campaignPolicy,
      campaignRole: "cell-producer",
      matrixCellId: normalized.matrixCellId,
      hostRole: normalized.matrixCellId,
      expectedRuntimeIdentitySha256: nodeAuthority.runtimeIdentitySha256,
      expectedQualificationResultSha256:
        nodeAuthority.qualificationResultSha256,
    });
    await recordOwnedPath(privateLedger, d2Directory, "directory");
    for (const name of D2_OUTPUT_NAMES) {
      await recordOwnedPath(privateLedger, path.join(d2Directory, name), "file");
    }
    const d2Input = (() => {
      try {
        return parseCanonicalInputSet(d2["input-set.json"].bytes);
      } catch {
        failPublicSourceZipCampaign("D2_BINDING", "d2-input-set-invalid");
      }
    })();
    if (
      d2Input.sourceCommit !== normalized.campaignPolicy.sourceCommit
      || d2Input.toolingCommit !== normalized.campaignPolicy.toolingCommit
      || d2Input.manifestSha256 !== sha256(manifestBytes.bytes)
      || d2Input.membershipReportSha256 !== sha256(membershipBytes.bytes)
      || d2Input.testVectorSetSha256 !== sha256(vectorBytes.bytes)
    ) failPublicSourceZipCampaign("D2_BINDING", "d2-source-authority-binding");
    const measurement = normalized.testAdapter?.measurement ?? await measuredPlatform(privateRoot);
    authority(measurement);
    const environmentLock = buildEnvironmentLock();
    const platformProbe = buildPlatformProbe({
      campaignPolicy: normalized.campaignPolicy,
      matrixCellId: normalized.matrixCellId,
      runtimeIdentity,
      gitIdentity,
      measurement,
    });
    const platformClass = buildPlatformClassV2({
      campaignPolicy: normalized.campaignPolicy,
      platformProbe,
    });
    const runtimeClass = buildRuntimeClassV2({ runtimeIdentity, platformProbe });
    const semanticInputSet = buildSemanticInputSetV2({
      campaignPolicy: normalized.campaignPolicy,
      d2InputSet: d2Input,
      criticalToolSet,
    });
    const executionIdentity = buildExecutionIdentityV2({
      campaignPolicy: normalized.campaignPolicy,
      matrixCellId: normalized.matrixCellId,
      runtimeIdentity,
      runtimeClass,
      gitIdentity,
      platformProbe,
      platformClass,
      environmentLock,
      runNonce: randomBytes(16).toString("hex"),
    });
    const evidence = buildReproducibilityEvidenceV2({
      campaignPolicy: normalized.campaignPolicy,
      matrixCellId: normalized.matrixCellId,
      semanticInputSet,
      executionIdentity,
      platformClass,
      runtimeClass,
      d2Bundle: d2BundleForV2(d2),
    });

    await cleanupOwnedTree(
      privateLedger,
      normalized.testAdapter?.forceCleanupUncertainty === true,
    );
    privateRoot = null;
    privateLedger = null;

    recheckCurrentNodeProcessAuthority({
      campaignPolicy: normalized.campaignPolicy,
      campaignRole: "cell-producer",
      matrixCellId: normalized.matrixCellId,
      hostRole: normalized.matrixCellId,
      expectedRuntimeIdentitySha256: nodeAuthority.runtimeIdentitySha256,
      expectedQualificationResultSha256:
        nodeAuthority.qualificationResultSha256,
    });

    await mkdir(normalized.outputDirectory, { recursive: false, mode: 0o700 });
    outputLedger = await createOwnershipLedger(normalized.outputDirectory, parent);
    for (const directory of ["d2", "authority", "v2"]) {
      const directoryPath = path.join(normalized.outputDirectory, directory);
      await mkdir(directoryPath, {
        recursive: false,
        mode: 0o700,
      });
      await recordOwnedPath(outputLedger, directoryPath, "directory");
    }
    const payload = new Map([
      ["d2/artifact.zip", d2["artifact.zip"].bytes],
      ["d2/zip-verification.json", d2["zip-verification.json"].bytes],
      ["d2/entry-plan.json", d2["entry-plan.json"].bytes],
      ["d2/input-set.json", d2["input-set.json"].bytes],
      ["d2/semantic-report.json", d2["semantic-report.json"].bytes],
      ["d2/evidence.json", d2["evidence.json"].bytes],
      ["d2/verification-result.json", d2["verification-result.json"].bytes],
      ["d2/.complete", d2[".complete"].bytes],
      ["authority/campaign-policy.json", encodeCanonicalCampaignPolicy(normalized.campaignPolicy)],
      ["authority/runtime-identity.json", encodeCanonicalRuntimeIdentityBinding(runtimeIdentity)],
      ["authority/node-qualification.json", encodeCanonicalMeasuredQualificationResult(
        nodeAuthority.qualificationResult,
      )],
      ["authority/producer-gpg-qualification.json", encodeCanonicalMeasuredQualificationResult(
        normalized.producerSigningAuthority.qualificationResult,
      )],
      ["authority/producer-local-gpg-qualification.json", encodeCanonicalMeasuredQualificationResult(
        normalized.producerLocalVerificationAuthority.qualificationResult,
      )],
      ["authority/git-identity.json", encodeCanonicalGitIdentityBinding(gitIdentity)],
      ["authority/platform-probe.json", encodeCanonicalPlatformProbe(platformProbe)],
      ["authority/platform-class.json", encodeCanonicalPlatformClassV2(platformClass)],
      ["authority/runtime-class.json", encodeCanonicalRuntimeClassV2(runtimeClass)],
      ["authority/environment-lock.json", encodeCanonicalEnvironmentLock(environmentLock)],
      ["authority/critical-tool-set.json", encodeCanonicalCriticalToolSet(criticalToolSet)],
      ["authority/public-source-manifest.json", manifestBytes.bytes],
      ["authority/membership-report.json", membershipBytes.bytes],
      ["authority/test-vector-set.json", vectorBytes.bytes],
      ["v2/semantic-input-set.json", encodeCanonicalSemanticInputSetV2(semanticInputSet)],
      ["v2/execution-identity.json", encodeCanonicalExecutionIdentityV2(executionIdentity)],
      ["v2/evidence.json", encodeCanonicalReproducibilityEvidenceV2(evidence)],
    ]);
    for (const [name, bytes] of payload) {
      await writeOwnedFile(normalized.outputDirectory, name, bytes, outputLedger);
    }
    const v2Result = await verifyReproducibilityEvidenceV2({
      campaignPolicy: path.join(normalized.outputDirectory, "authority", "campaign-policy.json"),
      criticalToolSet: path.join(normalized.outputDirectory, "authority", "critical-tool-set.json"),
      runtimeIdentity: path.join(normalized.outputDirectory, "authority", "runtime-identity.json"),
      gitIdentity: path.join(normalized.outputDirectory, "authority", "git-identity.json"),
      platformProbe: path.join(normalized.outputDirectory, "authority", "platform-probe.json"),
      environmentLock: path.join(normalized.outputDirectory, "authority", "environment-lock.json"),
      semanticInputSet: path.join(normalized.outputDirectory, "v2", "semantic-input-set.json"),
      executionIdentity: path.join(normalized.outputDirectory, "v2", "execution-identity.json"),
      platformClass: path.join(normalized.outputDirectory, "authority", "platform-class.json"),
      runtimeClass: path.join(normalized.outputDirectory, "authority", "runtime-class.json"),
      evidence: path.join(normalized.outputDirectory, "v2", "evidence.json"),
      d2InputSet: path.join(normalized.outputDirectory, "d2", "input-set.json"),
      d2SemanticReport: path.join(normalized.outputDirectory, "d2", "semantic-report.json"),
      d2Evidence: path.join(normalized.outputDirectory, "d2", "evidence.json"),
      d2VerificationResult: path.join(normalized.outputDirectory, "d2", "verification-result.json"),
      artifact: path.join(normalized.outputDirectory, "d2", "artifact.zip"),
      entryPlan: path.join(normalized.outputDirectory, "d2", "entry-plan.json"),
      zipVerification: path.join(normalized.outputDirectory, "d2", "zip-verification.json"),
    });
    const v2ResultBytes = encodeCanonicalVerificationResultV2(v2Result);
    payload.set("v2/verification-result.json", v2ResultBytes);
    await writeOwnedFile(
      normalized.outputDirectory,
      "v2/verification-result.json",
      v2ResultBytes,
      outputLedger,
    );
    const cellResult = buildCellResult({
      campaignPolicy: normalized.campaignPolicy,
      evidence,
      executionIdentity,
      nodeAuthority,
      producerSigningAuthority: normalized.producerSigningAuthority,
      producerLocalVerificationAuthority:
        normalized.producerLocalVerificationAuthority,
    });
    const cellResultBytes = encodeCanonicalCellResult(cellResult);
    payload.set("cell-result.json", cellResultBytes);
    await writeOwnedFile(
      normalized.outputDirectory,
      "cell-result.json",
      cellResultBytes,
      outputLedger,
    );
    const files = CELL_PAYLOAD_NAMES.map((name) => ({ name, bytes: payload.get(name) }));
    if (files.some((entry) => !Buffer.isBuffer(entry.bytes))) {
      failPublicSourceZipCampaign("FILE_LEDGER", "payload-incomplete");
    }
    const fileLedger = buildCellFileLedger({ files });
    requireUnchangedLoadedTools();
    const cellManifest = buildCellManifest({
      campaignPolicy: normalized.campaignPolicy,
      cellResult,
      fileLedger,
    });
    const cellManifestBytes = encodeCanonicalCellManifest(cellManifest);
    await writeOwnedFile(
      normalized.outputDirectory,
      "cell-manifest.json",
      cellManifestBytes,
      outputLedger,
    );
    const manifestPath = path.join(normalized.outputDirectory, "cell-manifest.json");
    const signaturePath = path.join(normalized.outputDirectory, "cell-manifest.sig");
    const signingResult = await signManifest(
      normalized,
      manifestPath,
      signaturePath,
    );
    if (
      signingResult.gpgRole !== "cell-producer-sign"
      || signingResult.profileId !== cellManifest.producerGpgProfileId
      || signingResult.profileSha256 !== cellManifest.producerGpgProfileSha256
      || signingResult.assignmentSha256
        !== cellManifest.producerSignAssignmentSha256
      || signingResult.qualificationResultSha256
        !== cellManifest.producerSignQualificationResultSha256
    ) failPublicSourceZipCampaign("SIGNATURE", "signing-profile-binding");
    const signature = await stableRead(
      signaturePath,
      normalized.campaignPolicy.transportPolicy.maxSignatureBytes,
      "SIGNATURE",
      "signature-output-read",
    );
    if (signature.bytes.length === 0) {
      failPublicSourceZipCampaign("SIGNATURE", "signature-output-empty");
    }
    await recordOwnedPath(outputLedger, signaturePath, "file");
    const verifiedSignature = await verifyDetachedOpenPgpSignature({
      campaignPolicy: normalized.campaignPolicy,
      expectedPolicySha256: normalized.expectedPolicySha256,
      gpgRole: "cell-producer-local-verify",
      hostRole: normalized.matrixCellId,
      matrixCellId: normalized.matrixCellId,
      comparisonRole: null,
      signerRole: normalized.signer.role,
      signatureNamespace: CELL_SIGNATURE_NAMESPACE,
      gpgExecutable: normalized.gpgExecutable,
      gpgHome: normalized.gpgHome,
      signatureFile: signaturePath,
      signedFile: manifestPath,
      allowedPrimaryFingerprints: [normalized.signingFingerprint],
    });
    if (verifiedSignature.primaryFingerprint !== normalized.signingFingerprint) {
      failPublicSourceZipCampaign("SIGNATURE", "signature-fingerprint-mismatch");
    }
    if (
      verifiedSignature.gpgRole !== "cell-producer-local-verify"
      || verifiedSignature.profileId
        !== cellManifest.producerLocalVerifierProfileId
      || verifiedSignature.profileSha256
        !== cellManifest.producerLocalVerifierProfileSha256
      || verifiedSignature.assignmentSha256
        !== cellManifest.producerLocalVerifyAssignmentSha256
      || verifiedSignature.qualificationResultSha256
        !== cellManifest.producerLocalVerifyQualificationResultSha256
    ) failPublicSourceZipCampaign("SIGNATURE", "verification-profile-binding");
    requireUnchangedLoadedTools();
    recheckCurrentNodeProcessAuthority({
      campaignPolicy: normalized.campaignPolicy,
      campaignRole: "cell-producer",
      matrixCellId: normalized.matrixCellId,
      hostRole: normalized.matrixCellId,
      expectedRuntimeIdentitySha256: nodeAuthority.runtimeIdentitySha256,
      expectedQualificationResultSha256:
        nodeAuthority.qualificationResultSha256,
    });
    await invokeTestCheckpoint(normalized.testAdapter, "before-completion-marker");
    await writeOwnedFile(
      normalized.outputDirectory,
      "cell.complete",
      CELL_COMPLETION_MARKER,
      outputLedger,
    );
    await invokeTestCheckpoint(normalized.testAdapter, "after-completion-marker");
    recheckCurrentNodeProcessAuthority({
      campaignPolicy: normalized.campaignPolicy,
      campaignRole: "cell-producer",
      matrixCellId: normalized.matrixCellId,
      hostRole: normalized.matrixCellId,
      expectedRuntimeIdentitySha256: nodeAuthority.runtimeIdentitySha256,
      expectedQualificationResultSha256:
        nodeAuthority.qualificationResultSha256,
    });
    requireUnchangedLoadedTools();
    return cellResult;
  } catch (error) {
    let safe = error instanceof PublicSourceZipCampaignError
      ? error
      : new PublicSourceZipCampaignError("CLI", "unexpected-preparation-failure");
    if (
      outputLedger !== null
      && await pathExists(outputLedger.root)
      && !(safe.phase === "CLEANUP" && safe.reason === "cleanup-identity-uncertain")
    ) {
      try {
        await revokeOwnedCompletionMarker(outputLedger);
        await cleanupOwnedTree(outputLedger);
      } catch (cleanupError) {
        safe = cleanupError instanceof PublicSourceZipCampaignError
          ? cleanupError
          : new PublicSourceZipCampaignError("CLEANUP", "cleanup-identity-uncertain");
      }
    }
    if (
      privateLedger !== null
      && privateRoot !== null
      && await pathExists(privateRoot)
      && !(safe.phase === "CLEANUP" && safe.reason === "cleanup-identity-uncertain")
    ) {
      try {
        await cleanupOwnedTree(privateLedger);
      } catch (cleanupError) {
        safe = cleanupError instanceof PublicSourceZipCampaignError
          ? cleanupError
          : new PublicSourceZipCampaignError("CLEANUP", "cleanup-identity-uncertain");
      }
    }
    throw safe;
  }
}

export async function preparePublicSourceZipCampaign(options = {}) {
  return prepareInternal(options);
}

function parseCli(argv) {
  authority(argv);
  const mapping = new Map([
    ["--campaign-policy", "campaignPolicy"],
    ["--matrix-cell-id", "matrixCellId"],
    ["--repository", "repository"],
    ["--source-commit", "sourceCommit"],
    ["--manifest", "manifest"],
    ["--membership-report", "membershipReport"],
    ["--d2-runner-policy", "d2RunnerPolicy"],
    ["--node-runtime-profile", "nodeRuntimeProfile"],
    ["--git-identity", "gitIdentity"],
    ["--git", "gitExecutable"],
    ["--critical-tool-set", "criticalToolSet"],
    ["--test-vector-set", "testVectorSet"],
    ["--output-directory", "outputDirectory"],
    ["--gpg", "gpgExecutable"],
    ["--gpg-home", "gpgHome"],
    ["--signing-fingerprint", "signingFingerprint"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(result, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) failPublicSourceZipCampaign("CLI", "unknown-or-duplicate-option");
    result[key] = argv[index + 1];
    index += 1;
  }
  const expected = OPTION_KEYS.filter((key) => key !== "campaignPolicy");
  if (!Object.hasOwn(result, "campaignPolicy") || expected.some((key) => !Object.hasOwn(result, key))) {
    failPublicSourceZipCampaign("CLI", "required-options");
  }
  return result;
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
  let policy;
  try {
    policy = parseCanonicalCampaignPolicyBytes(await readFile(cli.campaignPolicy));
  } catch {
    failPublicSourceZipCampaign("POLICY", "campaign-policy-invalid");
  }
  const result = await prepareInternal({
    campaignPolicy: policy,
    ...Object.fromEntries(OPTION_KEYS.filter((key) => key !== "campaignPolicy").map(
      (key) => [key, cli[key]],
    )),
  });
  process.stdout.write(encodeCanonicalCellResult(result));
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
