#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import {
  access,
  appendFile,
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  symlink,
  truncate,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import {
  encodeUstarHeader,
  paddingLength,
} from "./public-source-archive-core.mjs";
import {
  CRITICAL_TOOL_PATHS as RECEIPT_CRITICAL_TOOL_PATHS,
  RECEIPT_KIND,
  RECEIPT_OUTPUT_SUFFIX,
  SCHEMA_VERSION as RECEIPT_SCHEMA_VERSION,
  buildPublicSourceReceipt,
  encodeCanonicalReceipt,
} from "./public-source-receipt-core.mjs";
import {
  parsePublicSourceReceiptBytes,
} from "./verify-public-source-receipt.mjs";
import {
  ARTIFACT_ROLE,
  CRITICAL_TOOL_PATHS as ADAPTER_CRITICAL_TOOL_PATHS,
  FORMAT_PROFILE,
  canonicalAdapterJsonBytes,
  deepFreezeAdapter,
  encodeReceiptVerificationTranscript,
  readAdapterCanonicalDocument,
  resolveControlledGitExecutable,
  installControlledGitPath,
  validateGitIdentity,
  validatePlatformProbeShape,
  validateRepositoryCommit,
  validateRuntimeIdentity,
} from "./public-source-receipt-reproducibility-core.mjs";
import { readStableFile, sha256Bytes } from "./reproducibility-evidence-core.mjs";

const VECTOR_SET_KIND = "ieltmps-public-source-receipt-boundary-vector-set";
const VECTOR_SET_ID = "public-source-receipt-v1-boundaries-v1";
const SYNTHETIC_SIGNING_HELPER_MAXIMUM_BYTES = 128 * 1024 * 1024;
const SYNTHETIC_SIGNING_HELPER_AUTHORITY_KIND =
  "ieltmps-synthetic-signing-helper-byte-authority";
const SYNTHETIC_SIGNING_HELPER_AUTHORITY_KEYS = Object.freeze([
  "authorityKind",
  "schemaVersion",
  "byteLength",
  "sha256",
  "sourceFileIdentity",
  "sourceParentIdentity",
  "sourceBytesBase64",
  "capabilityProfile",
]);
const SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS = Object.freeze([
  "device",
  "inode",
  "size",
  "links",
  "mode",
  "mtimeNs",
  "ctimeNs",
  "birthtimeNs",
]);
const SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS = Object.freeze([
  "device",
  "inode",
  "mode",
  "birthtimeNs",
]);
const SYNTHETIC_SIGNING_HELPER_CAPABILITY_KEYS = Object.freeze([
  "status",
  "stdout",
  "stderr",
]);
const SYNTHETIC_SIGNING_HELPER_LOCKED_CONTEXT_KEYS = Object.freeze([
  "authority",
  "byteLength",
  "sha256",
  "execution",
  "capabilityProfile",
]);
const SYNTHETIC_SIGNING_HELPER_EXECUTION_KEYS = Object.freeze([
  "absolutePath",
  "parentPath",
  "fileIdentity",
  "parentIdentity",
  "byteLength",
  "sha256",
]);
const SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS = Object.freeze([
  "device",
  "inode",
]);
const SYNTHETIC_VECTOR_ROOT_PREFIX = "rv-";
const SYNTHETIC_VECTOR_ROOT_RANDOM_BYTES = 6;
const SYNTHETIC_WINDOWS_PATH_BUDGET = 240;
const SYNTHETIC_HELPER_TEST_HOOK = Symbol.for(
  "ieltmps.public-source-receipt-boundary-vectors.signing-helper-test-hook",
);
const syntheticSigningHelperAuthorities = new WeakSet();
const syntheticSigningHelperCaptures = new WeakSet();
const syntheticSigningHelperExecutions = new WeakSet();
const DESCRIPTOR_KEYS = Object.freeze([
  "vectorId",
  "executionClass",
  "caseId",
  "expectedOutcome",
  "expectedPhase",
  "expectedReason",
]);
const TOP_LEVEL_KEYS = Object.freeze([
  "vectorSetKind",
  "schemaVersion",
  "vectorSetId",
  "artifactRole",
  "formatProfile",
  "vectors",
]);

function descriptor(
  vectorId,
  executionClass,
  caseId,
  expectedOutcome,
  expectedPhase = null,
  expectedReason = null,
) {
  return Object.freeze({
    vectorId,
    executionClass,
    caseId,
    expectedOutcome,
    expectedPhase,
    expectedReason,
  });
}

const RECEIPT_CASES = Object.freeze([
  "canonical-build-full-verify",
  "historical-source-tooling-distinct",
  "b1-b3-round-trip",
  "artifact-ordering-and-identity",
  "same-process-receipt-equality",
  "same-process-transcript-equality",
  "same-process-distinct-paths-and-reads",
  "same-process-distinct-file-identities",
  "same-host-environment-invariant-equality",
  "all-four-output-equality-and-no-reuse",
]);
const CANONICAL_CASES = Object.freeze([
  "input-set-key-order",
  "semantic-report-key-order",
  "pass-evidence-schema",
  "failure-evidence-schema",
  "verification-result-schema",
  "transcript-json-plus-final-lf",
  "fixed-output-set-and-no-comparator",
  "canonical-output-privacy",
]);
const FILE_CASES = Object.freeze([
  ["bound-artifact-hash-mismatch", "artifact"],
  ["bound-artifact-length-mismatch", "artifact"],
  ["receipt-hash-mismatch", "receipt-verify"],
  ["receipt-length-mismatch", "receipt-verify"],
  ["archive-hash-mismatch", "source-archive"],
  ["archive-length-mismatch", "source-archive"],
  ["archive-format-mismatch", "source-archive"],
  ["mutation-during-stable-read", "file-identity"],
  ["same-size-file-replacement", "file-identity"],
  ["file-truncation", "file-identity"],
  ["file-growth", "file-identity"],
  ["symlink-or-reparse-input", "file-identity"],
  ["hard-link-anomaly", "file-identity"],
  ["parent-replacement", "file-identity"],
  ["archive-input-replacement-race", "source-archive"],
  ["receipt-output-replacement-race", "receipt-write"],
]);
const GIT_CASES = Object.freeze([
  ["source-commit-mismatch", "source-binding"],
  ["tooling-commit-mismatch", "tool-set"],
  ["source-manifest-mismatch", "source-binding"],
  ["membership-report-mismatch", "source-binding"],
  ["critical-tool-descriptor-mismatch", "tool-set"],
  ["modified-loaded-tool-bytes", "tool-set"],
  ["replacement-object", "git-authority"],
  ["replace-ref-environment", "git-authority"],
  ["hostile-git-environment", "git-authority"],
  ["active-git-operation", "git-authority"],
  ["non-commit-object", "git-authority"],
  ["abbreviated-revision", "git-authority"],
  ["runtime-identity-mismatch", "runtime-identity"],
  ["git-identity-document-mismatch", "git-identity"],
  ["platform-probe-mismatch", "platform-probe"],
  ["vector-set-identity-mismatch", "boundary-vector"],
]);
const MALFORMED_CASES = Object.freeze([
  ["independently-encoded-valid-receipt", "accept"],
  ["wrong-receipt-kind", "reject"],
  ["wrong-schema-version", "reject"],
  ["top-level-key-reorder", "reject"],
  ["nested-key-reorder", "reject"],
  ["missing-key", "reject"],
  ["extra-key", "reject"],
  ["duplicate-key", "reject"],
  ["reordered-array", "reject"],
  ["duplicate-array-entry", "reject"],
  ["utf8-bom", "reject"],
  ["crlf-framing", "reject"],
  ["missing-final-lf", "reject"],
  ["extra-final-lf", "reject"],
  ["uppercase-hash", "reject"],
  ["short-hash", "reject"],
  ["unsafe-integer", "reject"],
  ["zero-byte-artifact-length-boundary", "accept"],
  ["max-safe-integer-virtual-boundary", "accept"],
  ["receipt-byte-ceiling-over-limit", "reject"],
]);

export const BOUNDARY_VECTOR_DESCRIPTORS = Object.freeze([
  ...RECEIPT_CASES.map((caseId, index) => descriptor(
    `R${String(index + 1).padStart(2, "0")}`,
    "receipt-constructor-verifier",
    caseId,
    "accept",
  )),
  ...CANONICAL_CASES.map((caseId, index) => descriptor(
    `C${String(index + 1).padStart(2, "0")}`,
    "canonical-schema",
    caseId,
    "accept",
  )),
  ...FILE_CASES.map(([caseId, phase], index) => descriptor(
    `F${String(index + 1).padStart(2, "0")}`,
    "external-file-identity",
    caseId,
    "reject",
    phase,
    caseId,
  )),
  ...GIT_CASES.map(([caseId, phase], index) => descriptor(
    `G${String(index + 1).padStart(2, "0")}`,
    "git-authority",
    caseId,
    "reject",
    phase,
    caseId,
  )),
  ...MALFORMED_CASES.map(([caseId, outcome], index) => descriptor(
    `M${String(index + 1).padStart(2, "0")}`,
    "independent-malformed-receipt",
    caseId,
    outcome,
    outcome === "accept" ? null : "receipt-schema",
    outcome === "accept" ? null : caseId,
  )),
]);

export class PublicSourceReceiptBoundaryVectorError extends Error {
  constructor(vectorId = null, reason = "boundary-vector-failed") {
    super("public source receipt boundary vector failed");
    this.name = "PublicSourceReceiptBoundaryVectorError";
    this.phase = "BOUNDARY_VECTOR";
    this.reason = reason;
    this.vectorId = typeof vectorId === "string" ? vectorId : null;
  }
}

function failVector(vectorId = null) {
  throw new PublicSourceReceiptBoundaryVectorError(vectorId);
}

function failSyntheticSigningHelper() {
  throw new PublicSourceReceiptBoundaryVectorError(
    null,
    "synthetic-signing-helper-invalid",
  );
}

function failSyntheticWorkspacePathBudget() {
  throw new PublicSourceReceiptBoundaryVectorError(
    null,
    "synthetic-workspace-path-budget",
  );
}

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function expectedVectorDocument() {
  return {
    vectorSetKind: VECTOR_SET_KIND,
    schemaVersion: 1,
    vectorSetId: VECTOR_SET_ID,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    vectors: BOUNDARY_VECTOR_DESCRIPTORS,
  };
}

export async function validatePublicSourceReceiptBoundaryVectorSet({
  testVectorSet,
  expectedSha256 = null,
}) {
  let document;
  try {
    document = await readAdapterCanonicalDocument(
      testVectorSet,
      "BOUNDARY_VECTOR",
      "test-vector-set",
    );
  } catch {
    failVector();
  }
  const value = document.value;
  if (
    !exactKeys(value, TOP_LEVEL_KEYS)
    || value.vectorSetKind !== VECTOR_SET_KIND
    || value.schemaVersion !== 1
    || value.vectorSetId !== VECTOR_SET_ID
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Array.isArray(value.vectors)
    || value.vectors.length !== BOUNDARY_VECTOR_DESCRIPTORS.length
  ) failVector();
  for (let index = 0; index < value.vectors.length; index += 1) {
    const actual = value.vectors[index];
    const expected = BOUNDARY_VECTOR_DESCRIPTORS[index];
    if (
      !exactKeys(actual, DESCRIPTOR_KEYS)
      || DESCRIPTOR_KEYS.some((key) => actual[key] !== expected[key])
    ) failVector(expected.vectorId);
  }
  const expectedBytes = canonicalAdapterJsonBytes(
    expectedVectorDocument(),
    "BOUNDARY_VECTOR",
  );
  if (
    !document.bytes.equals(expectedBytes)
    || document.sha256 !== sha256Bytes(expectedBytes)
    || (expectedSha256 !== null && document.sha256 !== expectedSha256)
  ) failVector();
  return Object.freeze({
    value: deepFreezeAdapter(value),
    bytes: Buffer.from(document.bytes),
    sha256: document.sha256,
  });
}

function syntheticLicenseScopes() {
  return [
    { id: "eligible-server-source", label: "GNU Affero General Public License version 3 only", spdx: "AGPL-3.0-only", status: "resolved" },
    { id: "frontend", label: "GPLv3-family", spdx: null, status: "unresolved-exact-identifier", blocker: "D6" },
    { id: "governance-context", label: "scope-not-finalized", spdx: null, status: "unresolved" },
    { id: "license-texts", label: "legal-text-role", spdx: null, status: "not-a-license-claim" },
    { id: "shared-build-tooling", label: "scope-not-finalized", spdx: null, status: "unresolved" },
    { id: "third-party", label: "per-component-record", spdx: null, status: "component-record-required" },
  ];
}

function syntheticComponent(
  id,
  includeExact,
  includePrefixes,
  pathRole,
  licenseScope,
  preferredSourceStatus,
  securityReviewStatus,
  rightsReviewStatus,
) {
  return {
    id,
    selectors: { includeExact, includePrefixes },
    pathRole,
    licenseScope,
    preferredSourceStatus,
    securityReviewStatus,
    rightsReviewStatus,
    requirementStatus: "required",
  };
}

function syntheticComponents() {
  return [
    syntheticComponent(
      "eligible-server-source",
      ["api-contract/README.md", "backend/Dockerfile", "backend/package.json"],
      ["backend/admin/", "backend/auth/", "backend/migrations/", "backend/scripts/", "backend/src/", "backend/test/"],
      "preferred-source", "eligible-server-source", "preferred-editable",
      "not-required", "not-required",
    ),
    syntheticComponent(
      "frontend-build-tooling",
      ["scripts/build-bundles.mjs", "scripts/bundle-manifest.mjs"],
      [], "build-source", "shared-build-tooling", "preferred-editable",
      "not-required", "not-required",
    ),
    syntheticComponent(
      "frontend-preferred-source",
      ["index.html"], ["css/", "js/", "src/styles/"],
      "preferred-source", "frontend", "preferred-editable",
      "not-required", "not-required",
    ),
    syntheticComponent(
      "governance-context",
      ["LICENSE.md", "NOTICE.md", "README.md", "docs/CONTENT_POLICY.md", "docs/STATUS.md"],
      [], "governance-context", "governance-context", "context-document",
      "not-required", "scope-review-required",
    ),
    syntheticComponent(
      "license-texts", ["LICENSE", "LICENSES/AGPL-3.0-only.txt"], [],
      "license-text", "license-texts", "not-applicable", "not-required",
      "not-applicable",
    ),
    syntheticComponent(
      "server-dependency-lock", ["backend/package-lock.json"], [],
      "dependency-install-metadata", "third-party", "generated-install-metadata",
      "not-required", "component-record-required",
    ),
    syntheticComponent(
      "shared-release-build-tooling",
      [
        "developer/prepare-public-container-context.mjs",
        "developer/public-container-context-manifest.json",
        "developer/public-source-manifest.json",
        "developer/release.ps1",
        "developer/release.sh",
        "developer/standalone-release-manifest.json",
        "developer/standalone-release-manifest.mjs",
        "developer/tests/ci/test_public_container_context.py",
        "developer/tests/ci/test_public_source_membership.py",
        "developer/tests/ci/test_standalone_packaging.py",
        "developer/verify-public-container-context.mjs",
        "developer/verify-public-source-membership.mjs",
      ],
      [], "build-and-verification-source", "shared-build-tooling",
      "preferred-editable", "not-required", "scope-review-required",
    ),
  ];
}

export function buildSyntheticPublicSourceManifestBytes() {
  const deferredRows = [
    ["exact-artifact-source-binding", "later-phase-required", "R1.1C", "corrected-static-publication"],
    ["frontend-exact-license-identifier", "foundation-deferred", "D6", "corrected-static-publication"],
    ["generated-bundle-convenience-decision", "foundation-deferred", "R1.1B3", "source-archive-publication"],
    ["generated-data-preferred-source", "preferred-source-blocked", "R1.1D", "corrected-static-publication"],
    ["public-content-rights", "rights-review-blocked", "R1-04", "corrected-static-publication"],
    ["security-sensitive-deployment-membership", "security-review-blocked", "security-membership-review", "container-or-onion-publication"],
    ["shared-build-tooling-license-scope", "foundation-deferred", "R1.1B2", "source-tree-generation"],
    ["source-archive-format", "later-phase-required", "D9", "source-archive-publication"],
    ["source-tree-materializer", "later-phase-required", "R1.1B2", "source-tree-generation"],
    ["templates-membership-review", "rights-review-blocked", "D7", "corrected-static-publication"],
    ["third-party-component-records", "later-phase-required", "third-party-records", "source-tree-generation"],
  ];
  const securityRows = [
    ["compose-membership", "container-publication"],
    ["environment-example-membership", "container-publication"],
    ["proxy-configuration-membership", "onion-publication"],
    ["tor-program-configuration-membership", "onion-publication"],
  ];
  const blockerRows = [
    ["D3", "decision-open"], ["D6", "publication-blocked"],
    ["D7", "publication-blocked"], ["D9", "decision-open"],
    ["R1-04", "publication-blocked"],
    ["R1.1B2", "corresponding-source-incomplete"],
    ["R1.1B3", "corresponding-source-incomplete"],
    ["R1.1C", "publication-blocked"], ["R1.1D", "publication-blocked"],
    ["security-membership-review", "publication-blocked"],
    ["third-party-records", "publication-blocked"],
  ];
  const value = {
    schemaVersion: 1,
    artifactKind: "public-code-corresponding-source",
    selectionBasis: "git-commit-tree",
    policyProfile: "public-source-foundation-v1",
    licenseScopes: syntheticLicenseScopes(),
    components: syntheticComponents(),
    deferred: deferredRows.map(([id, status, blocker, requiredBefore]) => ({
      id, status, blocker, requiredBefore,
    })),
    securityReviewRequired: securityRows.map(([id, requiredBefore]) => ({
      id,
      status: "security-review-required",
      owner: "server-security",
      requiredBefore,
    })),
    blockers: blockerRows.map(([id, impact]) => ({
      id, status: "open", impact,
    })),
  };
  return Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function independentBytes(value) {
  return Buffer.from(JSON.stringify(value) + "\n", "utf8");
}

function requireAccept(bytes, vectorId = null) {
  try {
    return parsePublicSourceReceiptBytes(bytes);
  } catch {
    failVector(vectorId);
  }
}

function requireReject(bytes, expectedReason, vectorId = null) {
  try {
    parsePublicSourceReceiptBytes(bytes);
  } catch (error) {
    const expected = Array.isArray(expectedReason)
      ? expectedReason
      : [expectedReason];
    if (
      error?.phase === "RECEIPT_SCHEMA"
      && expected.includes(error?.reason)
    ) return error;
    failVector(vectorId);
  }
  failVector(vectorId);
}

async function requireAsyncReject(operation) {
  try {
    await operation();
  } catch (error) {
    return error;
  }
  failVector();
}

function requireSyncReject(operation) {
  try {
    operation();
  } catch (error) {
    return error;
  }
  failVector();
}

function syntheticGitEnvironment(git, additions = {}) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_") && key.toUpperCase() !== "PATH") {
      environment[key] = value;
    }
  }
  environment.PATH = git.directory;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LC_ALL = "C";
  environment.LANG = "C";
  Object.assign(environment, additions);
  return environment;
}

function runSyntheticGit(git, repository, args) {
  const result = spawnSync(
    git.path,
    ["--no-replace-objects", "-C", repository, ...args],
    {
      encoding: null,
      env: syntheticGitEnvironment(git),
      maxBuffer: 128 * 1024 * 1024,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) failVector("SYNTHETIC-GIT-" + args[0]);
  return result.stdout;
}

function pathsEqual(left, right) {
  return process.platform === "win32"
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
}

function noFollowFlag() {
  return process.platform !== "win32" && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

function exactFrozenDataObject(value, expectedKeys) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || !Object.isFrozen(value)
  ) return false;
  let keys;
  let descriptors;
  try {
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return false;
  }
  return keys.length === expectedKeys.length
    && keys.every((key, index) => key === expectedKeys[index])
    && expectedKeys.every((key) => {
      const descriptorValue = descriptors[key];
      return descriptorValue
        && Object.hasOwn(descriptorValue, "value")
        && descriptorValue.enumerable === true
        && descriptorValue.configurable === false
        && descriptorValue.writable === false;
    });
}

function meaningfulIdentity(state) {
  return state.dev !== 0n || state.ino !== 0n;
}

function temporaryParentIdentityFromState(state) {
  return Object.freeze({
    device: state.dev.toString(10),
    inode: state.ino.toString(10),
  });
}

function fileIdentityFromState(state) {
  return Object.freeze({
    device: state.dev.toString(10),
    inode: state.ino.toString(10),
    size: state.size.toString(10),
    links: state.nlink.toString(10),
    mode: state.mode.toString(10),
    mtimeNs: state.mtimeNs.toString(10),
    ctimeNs: state.ctimeNs.toString(10),
    birthtimeNs: state.birthtimeNs.toString(10),
  });
}

function parentIdentityFromState(state) {
  return Object.freeze({
    device: state.dev.toString(10),
    inode: state.ino.toString(10),
    mode: state.mode.toString(10),
    birthtimeNs: state.birthtimeNs.toString(10),
  });
}

function identityObjectsEqual(left, right, keys) {
  return keys.every((key) => left[key] === right[key]);
}

function requireTemporaryParentIdentity(value) {
  if (
    !exactFrozenDataObject(value, SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS)
    || SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS.some(
      (key) => !/^(?:0|[1-9][0-9]*)$/u.test(value[key]),
    )
  ) failVector();
  return value;
}

async function validateTemporaryParent(parentArgument, expectedIdentity = null) {
  const parent = path.resolve(parentArgument ?? os.tmpdir());
  const state = await lstat(parent, { bigint: true });
  const identity = temporaryParentIdentityFromState(state);
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !meaningfulIdentity(state)
    || !pathsEqual(path.resolve(await realpath(parent)), parent)
    || (
      expectedIdentity !== null
      && !identityObjectsEqual(
        requireTemporaryParentIdentity(expectedIdentity),
        identity,
        SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS,
      )
    )
  ) failVector();
  return Object.freeze({ path: parent, identity });
}

async function revalidateTemporaryParent(parent) {
  if (
    !parent
    || typeof parent !== "object"
    || Array.isArray(parent)
    || typeof parent.path !== "string"
    || !path.isAbsolute(parent.path)
  ) failVector();
  const state = await lstat(parent.path, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !meaningfulIdentity(state)
    || !identityObjectsEqual(
      parent.identity,
      temporaryParentIdentityFromState(state),
      SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS,
    )
    || !pathsEqual(path.resolve(await realpath(parent.path)), parent.path)
  ) failVector();
  return parent;
}

async function createSyntheticVectorWorkspace(parent) {
  await revalidateTemporaryParent(parent);
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const leaf = SYNTHETIC_VECTOR_ROOT_PREFIX
      + randomBytes(SYNTHETIC_VECTOR_ROOT_RANDOM_BYTES).toString("hex");
    const root = path.join(parent.path, leaf);
    try {
      await mkdir(root, { mode: 0o700 });
    } catch (error) {
      if (error?.code === "EEXIST") continue;
      failVector();
    }
    await revalidateTemporaryParent(parent);
    const state = await lstat(root, { bigint: true });
    if (
      state.isSymbolicLink()
      || !state.isDirectory()
      || !meaningfulIdentity(state)
      || !pathsEqual(path.resolve(await realpath(root)), root)
    ) failVector();
    return Object.freeze({
      path: root,
      identity: temporaryParentIdentityFromState(state),
      parent,
    });
  }
  failVector();
}

async function revalidateSyntheticVectorWorkspace(workspace) {
  await revalidateTemporaryParent(workspace.parent);
  const state = await lstat(workspace.path, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !meaningfulIdentity(state)
    || !identityObjectsEqual(
      workspace.identity,
      temporaryParentIdentityFromState(state),
      SYNTHETIC_TEMPORARY_PARENT_IDENTITY_KEYS,
    )
    || !pathsEqual(path.resolve(await realpath(workspace.path)), workspace.path)
  ) failVector();
  return workspace;
}

async function removeVectorRoot(workspace) {
  try {
    await revalidateSyntheticVectorWorkspace(workspace);
    await rm(workspace.path, {
      recursive: true,
      force: false,
      maxRetries: 20,
      retryDelay: 50,
    });
    await revalidateTemporaryParent(workspace.parent);
    try {
      await lstat(workspace.path, { bigint: true });
      failVector("CLEANUP");
    } catch (error) {
      if (error instanceof PublicSourceReceiptBoundaryVectorError) throw error;
      if (error?.code !== "ENOENT") failVector("CLEANUP");
    }
  } catch {
    failVector("CLEANUP");
  }
}

function syntheticRepositoryRelativePaths() {
  const manifest = JSON.parse(buildSyntheticPublicSourceManifestBytes().toString("utf8"));
  const values = new Set([
    "backend/admin/admin.js",
    "backend/auth/auth.js",
    "backend/migrations/001_init.sql",
    "backend/scripts/executable.sh",
    "backend/src/app.js",
    "backend/test/app.test.js",
    "css/app.css",
    "js/app.js",
    "src/styles/app.css",
    "developer/prepare-public-source-archive.mjs",
    "developer/prepare-public-source-tree.mjs",
    ...ADAPTER_CRITICAL_TOOL_PATHS,
  ]);
  for (const component of manifest.components) {
    for (const relative of component.selectors.includeExact) values.add(relative);
  }
  return [...values];
}

function measureSyntheticWorkspacePathBudget(root) {
  const repository = path.join(root, "r");
  const external = path.join(root, "o");
  const helperDirectory = path.join(root, "h");
  const candidates = [
    Object.freeze({ kind: "repository", path: repository }),
    Object.freeze({
      kind: "git-object",
      path: path.join(repository, ".git", "objects", "ff", "0".repeat(38)),
    }),
    Object.freeze({
      kind: "git-ref",
      path: path.join(repository, ".git", "refs", "heads", "v"),
    }),
    Object.freeze({
      kind: "helper-execution",
      path: path.join(
        helperDirectory,
        `k-${"0".repeat(12)}${process.platform === "win32" ? ".exe" : ""}`,
      ),
    }),
    Object.freeze({ kind: "signing-key", path: path.join(external, "k") }),
    Object.freeze({ kind: "signing-public-key", path: path.join(external, "k.pub") }),
    Object.freeze({ kind: "allowed-signers", path: path.join(external, "s") }),
    Object.freeze({ kind: "source-archive", path: path.join(external, "s.tar") }),
    Object.freeze({ kind: "artifact", path: path.join(external, "a.zip") }),
    Object.freeze({
      kind: "receipt",
      path: path.join(root, `b0${RECEIPT_OUTPUT_SUFFIX}`),
    }),
    Object.freeze({
      kind: "canonical-output",
      path: path.join(root, "c", "receipt.source-receipt.json"),
    }),
    Object.freeze({
      kind: "canonical-comparison",
      path: path.join(root, "c", "comparison-report.json"),
    }),
    Object.freeze({ kind: "stable-file", path: path.join(root, "f00", "r") }),
    ...syntheticRepositoryRelativePaths().map((relative) => Object.freeze({
      kind: "repository-file",
      path: path.join(repository, ...relative.split("/")),
    })),
  ];
  let longest = candidates[0];
  for (const candidate of candidates) {
    if (candidate.path.length > longest.path.length) longest = candidate;
  }
  const result = Object.freeze({
    budget: SYNTHETIC_WINDOWS_PATH_BUDGET,
    longestKind: longest.kind,
    longestPath: longest.path,
    longestLength: longest.path.length,
    gitObjectPath: candidates.find((candidate) => candidate.kind === "git-object").path,
    gitObjectPathLength: candidates.find(
      (candidate) => candidate.kind === "git-object",
    ).path.length,
  });
  if (
    process.platform === "win32"
    && result.longestLength >= SYNTHETIC_WINDOWS_PATH_BUDGET
  ) failSyntheticWorkspacePathBudget();
  return result;
}

function requireCanonicalSyntheticSigningHelperPath(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || path.resolve(value) !== value
    || value.normalize("NFC") !== value
    || (
      process.platform === "win32"
      && (
        value.startsWith("\\\\")
        || value.startsWith("//")
        || value.startsWith("\\\\?\\")
        || value.startsWith("\\\\.\\")
      )
    )
  ) failSyntheticSigningHelper();
  return value;
}

function requireSyntheticSigningHelperGit(git) {
  if (
    !git
    || typeof git !== "object"
    || Array.isArray(git)
    || typeof git.path !== "string"
    || typeof git.directory !== "string"
    || !path.isAbsolute(git.path)
    || path.resolve(git.path) !== git.path
    || path.dirname(git.path) !== git.directory
    || !/^[0-9a-f]{64}$/u.test(git.sha256)
    || !Number.isSafeInteger(git.byteLength)
    || git.byteLength <= 0
    || typeof git.reportedVersion !== "string"
    || git.reportedVersion.length === 0
  ) failSyntheticSigningHelper();
  return git;
}

function requireIdentitySchema(value, keys) {
  if (
    !exactFrozenDataObject(value, keys)
    || keys.some((key) => !/^(?:0|[1-9][0-9]*)$/u.test(value[key]))
  ) failSyntheticSigningHelper();
  return value;
}

function requireCanonicalHelperBytesBase64(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) failSyntheticSigningHelper();
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) failSyntheticSigningHelper();
  return bytes;
}

function requireCapabilityProfile(value) {
  if (
    !exactFrozenDataObject(value, SYNTHETIC_SIGNING_HELPER_CAPABILITY_KEYS)
    || value.status !== 1
    || value.stdout !== ""
    || typeof value.stderr !== "string"
    || !value.stderr.includes("usage: ssh-keygen")
    || !value.stderr.includes("ed25519")
    || !value.stderr.includes("-Y sign")
    || !value.stderr.includes("-Y verify")
  ) failSyntheticSigningHelper();
  return value;
}

function requireSyntheticSigningHelperCapture(capture) {
  if (
    !capture
    || typeof capture !== "object"
    || !syntheticSigningHelperCaptures.has(capture)
    || !exactFrozenDataObject(
      capture,
      SYNTHETIC_SIGNING_HELPER_AUTHORITY_KEYS.slice(0, -1),
    )
    || capture.authorityKind !== SYNTHETIC_SIGNING_HELPER_AUTHORITY_KIND
    || capture.schemaVersion !== 1
    || !Number.isSafeInteger(capture.byteLength)
    || capture.byteLength <= 0
    || capture.byteLength > SYNTHETIC_SIGNING_HELPER_MAXIMUM_BYTES
    || !/^[0-9a-f]{64}$/u.test(capture.sha256)
  ) failSyntheticSigningHelper();
  requireIdentitySchema(
    capture.sourceFileIdentity,
    SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
  );
  requireIdentitySchema(
    capture.sourceParentIdentity,
    SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
  );
  return capture;
}

function requireSyntheticSigningHelperAuthoritySchema(authority, git) {
  requireSyntheticSigningHelperGit(git);
  if (
    !authority
    || typeof authority !== "object"
    || !syntheticSigningHelperAuthorities.has(authority)
    || !exactFrozenDataObject(authority, SYNTHETIC_SIGNING_HELPER_AUTHORITY_KEYS)
  ) failSyntheticSigningHelper();
  if (
    authority.authorityKind !== SYNTHETIC_SIGNING_HELPER_AUTHORITY_KIND
    || authority.schemaVersion !== 1
    || !Number.isSafeInteger(authority.byteLength)
    || authority.byteLength <= 0
    || authority.byteLength > SYNTHETIC_SIGNING_HELPER_MAXIMUM_BYTES
    || !/^[0-9a-f]{64}$/u.test(authority.sha256)
  ) failSyntheticSigningHelper();
  requireIdentitySchema(
    authority.sourceFileIdentity,
    SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
  );
  requireIdentitySchema(
    authority.sourceParentIdentity,
    SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
  );
  if (typeof authority.sourceBytesBase64 !== "string") failSyntheticSigningHelper();
  requireCapabilityProfile(authority.capabilityProfile);
  return authority;
}

function decodeSyntheticSigningHelperAuthorityBytes(authority, git) {
  requireSyntheticSigningHelperAuthoritySchema(authority, git);
  const bytes = requireCanonicalHelperBytesBase64(authority.sourceBytesBase64);
  if (
    bytes.length !== authority.byteLength
    || sha256Bytes(bytes) !== authority.sha256
  ) failSyntheticSigningHelper();
  return bytes;
}

function decodeSyntheticSigningHelperCaptureBytes(capture) {
  requireSyntheticSigningHelperCapture(capture);
  const bytes = requireCanonicalHelperBytesBase64(capture.sourceBytesBase64);
  if (
    bytes.length !== capture.byteLength
    || sha256Bytes(bytes) !== capture.sha256
  ) failSyntheticSigningHelper();
  return bytes;
}

function createSyntheticSigningHelperLockedContext(authority, execution, git) {
  requireSyntheticSigningHelperAuthoritySchema(authority, git);
  requireSyntheticSigningHelperExecution(execution, authority);
  return Object.freeze({
    authority,
    byteLength: authority.byteLength,
    sha256: authority.sha256,
    execution,
    capabilityProfile: authority.capabilityProfile,
  });
}

function requireSyntheticSigningHelperLockedContext(context, git) {
  if (
    !exactFrozenDataObject(context, SYNTHETIC_SIGNING_HELPER_LOCKED_CONTEXT_KEYS)
  ) failSyntheticSigningHelper();
  const authority = requireSyntheticSigningHelperAuthoritySchema(context.authority, git);
  if (
    context.byteLength !== authority.byteLength
    || context.sha256 !== authority.sha256
    || context.capabilityProfile !== authority.capabilityProfile
  ) failSyntheticSigningHelper();
  requireSyntheticSigningHelperExecution(context.execution, authority);
  return context;
}

function normalizeSyntheticSigningHelperTestHook(value) {
  if (value === undefined) return null;
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || !Object.isFrozen(value)
    || Reflect.ownKeys(value).length !== 1
    || Reflect.ownKeys(value)[0] !== "checkpoint"
    || typeof value.checkpoint !== "function"
  ) failSyntheticSigningHelper();
  return value;
}

async function runSyntheticSigningHelperTestCheckpoint(hook, checkpoint) {
  if (hook === null) return;
  try {
    await hook.checkpoint(Object.freeze({ checkpoint }));
  } catch {
    failSyntheticSigningHelper();
  }
}

async function inspectPrivateSyntheticSigningHelper(
  absolutePath,
  parentPath,
  expectedParentIdentity,
  expectedFileIdentity,
  expectedByteLength,
  expectedSha256,
) {
  let handle = null;
  try {
    requireCanonicalSyntheticSigningHelperPath(absolutePath);
    requireCanonicalSyntheticSigningHelperPath(parentPath);
    if (path.dirname(absolutePath) !== parentPath) failSyntheticSigningHelper();
    const parentBefore = await lstat(parentPath, { bigint: true });
    if (
      parentBefore.isSymbolicLink()
      || !parentBefore.isDirectory()
      || !meaningfulIdentity(parentBefore)
      || !pathsEqual(path.resolve(await realpath(parentPath)), parentPath)
      || (
        expectedParentIdentity !== null
        && !identityObjectsEqual(
          expectedParentIdentity,
          parentIdentityFromState(parentBefore),
          SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
        )
      )
    ) failSyntheticSigningHelper();
    const parentIdentity = parentIdentityFromState(parentBefore);
    const initial = await lstat(absolutePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.nlink !== 1n
      || initial.size <= 0n
      || initial.size > BigInt(SYNTHETIC_SIGNING_HELPER_MAXIMUM_BYTES)
      || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !meaningfulIdentity(initial)
      || !pathsEqual(path.resolve(await realpath(absolutePath)), absolutePath)
    ) failSyntheticSigningHelper();
    const fileIdentity = fileIdentityFromState(initial);
    if (
      expectedFileIdentity !== null
      && !identityObjectsEqual(
        expectedFileIdentity,
        fileIdentity,
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
    ) failSyntheticSigningHelper();
    handle = await open(absolutePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(before),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
    ) failSyntheticSigningHelper();
    const bytes = Buffer.alloc(Number(initial.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > bytes.length - offset) {
        failSyntheticSigningHelper();
      }
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    const after = await handle.stat({ bigint: true });
    const final = await lstat(absolutePath, { bigint: true });
    const parentAfter = await lstat(parentPath, { bigint: true });
    const sha256 = sha256Bytes(bytes);
    if (
      trailing.bytesRead !== 0
      || final.isSymbolicLink()
      || !final.isFile()
      || final.nlink !== 1n
      || parentAfter.isSymbolicLink()
      || !parentAfter.isDirectory()
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(after),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(final),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
      || !identityObjectsEqual(
        parentIdentity,
        parentIdentityFromState(parentAfter),
        SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
      )
      || (expectedByteLength !== null && bytes.length !== expectedByteLength)
      || (expectedSha256 !== null && sha256 !== expectedSha256)
      || !pathsEqual(path.resolve(await realpath(absolutePath)), absolutePath)
      || !pathsEqual(path.resolve(await realpath(parentPath)), parentPath)
    ) failSyntheticSigningHelper();
    return Object.freeze({
      fileIdentity,
      parentIdentity,
      byteLength: bytes.length,
      sha256,
    });
  } catch (error) {
    if (
      error instanceof PublicSourceReceiptBoundaryVectorError
      && error.reason === "synthetic-signing-helper-invalid"
    ) throw error;
    failSyntheticSigningHelper();
  } finally {
    if (handle) await handle.close();
  }
}

function requireSyntheticSigningHelperExecution(execution, authority) {
  if (
    !execution
    || typeof execution !== "object"
    || !syntheticSigningHelperExecutions.has(execution)
    || !exactFrozenDataObject(execution, SYNTHETIC_SIGNING_HELPER_EXECUTION_KEYS)
  ) failSyntheticSigningHelper();
  requireCanonicalSyntheticSigningHelperPath(execution.absolutePath);
  requireCanonicalSyntheticSigningHelperPath(execution.parentPath);
  requireIdentitySchema(
    execution.fileIdentity,
    SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
  );
  requireIdentitySchema(
    execution.parentIdentity,
    SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
  );
  if (
    execution.byteLength !== authority.byteLength
    || execution.sha256 !== authority.sha256
  ) failSyntheticSigningHelper();
  return execution;
}

async function revalidateSyntheticSigningHelperExecution(execution, authority) {
  requireSyntheticSigningHelperExecution(execution, authority);
  await inspectPrivateSyntheticSigningHelper(
    execution.absolutePath,
    execution.parentPath,
    execution.parentIdentity,
    execution.fileIdentity,
    execution.byteLength,
    execution.sha256,
  );
  return execution;
}

async function materializeSyntheticSigningHelper(source, workspace, git = null) {
  await revalidateSyntheticVectorWorkspace(workspace);
  const isAuthority = syntheticSigningHelperAuthorities.has(source);
  const bytes = isAuthority
    ? decodeSyntheticSigningHelperAuthorityBytes(source, git)
    : decodeSyntheticSigningHelperCaptureBytes(source);
  const expectedByteLength = source.byteLength;
  const expectedSha256 = source.sha256;
  const parentPath = path.join(workspace.path, "h");
  await mkdir(parentPath, { mode: 0o700 });
  await revalidateSyntheticVectorWorkspace(workspace);
  const parentState = await lstat(parentPath, { bigint: true });
  if (
    parentState.isSymbolicLink()
    || !parentState.isDirectory()
    || !meaningfulIdentity(parentState)
    || !pathsEqual(path.resolve(await realpath(parentPath)), parentPath)
  ) failSyntheticSigningHelper();
  const parentIdentity = parentIdentityFromState(parentState);
  let absolutePath = null;
  let handle = null;
  for (let attempt = 0; attempt < 16 && handle === null; attempt += 1) {
    const leaf = `k-${randomBytes(6).toString("hex")}`
      + (process.platform === "win32" ? ".exe" : "");
    absolutePath = path.join(parentPath, leaf);
    try {
      handle = await open(
        absolutePath,
        FS_CONSTANTS.O_CREAT
          | FS_CONSTANTS.O_EXCL
          | FS_CONSTANTS.O_WRONLY
          | noFollowFlag(),
        0o700,
      );
    } catch (error) {
      if (error?.code !== "EEXIST") failSyntheticSigningHelper();
    }
  }
  if (handle === null || absolutePath === null) failSyntheticSigningHelper();
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const written = await handle.write(bytes, offset, bytes.length - offset, null);
      if (
        !written
        || written.bytesWritten <= 0
        || written.bytesWritten > bytes.length - offset
      ) failSyntheticSigningHelper();
      offset += written.bytesWritten;
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(absolutePath, 0o500);
  const inspected = await inspectPrivateSyntheticSigningHelper(
    absolutePath,
    parentPath,
    parentIdentity,
    null,
    expectedByteLength,
    expectedSha256,
  );
  const execution = Object.freeze({
    absolutePath,
    parentPath,
    fileIdentity: inspected.fileIdentity,
    parentIdentity: inspected.parentIdentity,
    byteLength: inspected.byteLength,
    sha256: inspected.sha256,
  });
  syntheticSigningHelperExecutions.add(execution);
  return execution;
}

async function removeSyntheticSigningHelperExecution(execution, authority) {
  await revalidateSyntheticSigningHelperExecution(execution, authority);
  await chmod(execution.absolutePath, 0o700);
  const writable = await inspectPrivateSyntheticSigningHelper(
    execution.absolutePath,
    execution.parentPath,
    execution.parentIdentity,
    null,
    execution.byteLength,
    execution.sha256,
  );
  if (
    writable.fileIdentity.device !== execution.fileIdentity.device
    || writable.fileIdentity.inode !== execution.fileIdentity.inode
  ) failSyntheticSigningHelper();
  await unlink(execution.absolutePath);
  try {
    await lstat(execution.absolutePath, { bigint: true });
    failSyntheticSigningHelper();
  } catch (error) {
    if (error instanceof PublicSourceReceiptBoundaryVectorError) throw error;
    if (error?.code !== "ENOENT") failSyntheticSigningHelper();
  }
  const parentState = await lstat(execution.parentPath, { bigint: true });
  if (
    parentState.isSymbolicLink()
    || !parentState.isDirectory()
    || !identityObjectsEqual(
      execution.parentIdentity,
      parentIdentityFromState(parentState),
      SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
    )
    || (await readdir(execution.parentPath)).length !== 0
  ) failSyntheticSigningHelper();
  await rmdir(execution.parentPath);
}

async function runPrivateSyntheticSigningHelper({
  execution,
  authority,
  git,
  args,
  hook = null,
  checkpoint,
  encoding = null,
  maxBuffer = 128 * 1024 * 1024,
}) {
  await revalidateSyntheticSigningHelperExecution(execution, authority);
  await runSyntheticSigningHelperTestCheckpoint(hook, checkpoint);
  await revalidateSyntheticSigningHelperExecution(execution, authority);
  const result = spawnSync(execution.absolutePath, args, {
    encoding,
    env: syntheticGitEnvironment(git),
    maxBuffer,
    shell: false,
    windowsHide: true,
  });
  await revalidateSyntheticSigningHelperExecution(execution, authority);
  return result;
}

async function probeSyntheticSigningHelperCapability(
  execution,
  authority,
  git,
  hook = null,
  checkpoint = "before-helper-capability",
) {
  const result = await runPrivateSyntheticSigningHelper({
    execution,
    authority,
    git,
    args: ["-?"],
    hook,
    checkpoint,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  const stderr = typeof result.stderr === "string"
    ? result.stderr.replace(/\r\n?/gu, "\n")
    : null;
  if (
    result.error
    || result.status !== 1
    || result.stdout !== ""
    || typeof stderr !== "string"
    || !stderr.includes("usage: ssh-keygen")
    || !stderr.includes("ed25519")
    || !stderr.includes("-Y sign")
    || !stderr.includes("-Y verify")
  ) failSyntheticSigningHelper();
  return Object.freeze({ status: 1, stdout: "", stderr });
}

async function captureSyntheticSigningHelperSource(absolutePath, git) {
  requireSyntheticSigningHelperGit(git);
  requireCanonicalSyntheticSigningHelperPath(absolutePath);
  let handle = null;
  try {
    const parentPath = path.dirname(absolutePath);
    requireCanonicalSyntheticSigningHelperPath(parentPath);
    const parentBefore = await lstat(parentPath, { bigint: true });
    if (
      parentBefore.isSymbolicLink()
      || !parentBefore.isDirectory()
      || !meaningfulIdentity(parentBefore)
      || !pathsEqual(path.resolve(await realpath(parentPath)), parentPath)
    ) failSyntheticSigningHelper();
    const parentIdentity = parentIdentityFromState(parentBefore);
    const initial = await lstat(absolutePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.nlink <= 0n
      || initial.size <= 0n
      || initial.size > BigInt(SYNTHETIC_SIGNING_HELPER_MAXIMUM_BYTES)
      || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !meaningfulIdentity(initial)
      || !pathsEqual(path.resolve(await realpath(absolutePath)), absolutePath)
    ) failSyntheticSigningHelper();
    if (process.platform !== "win32") {
      await access(absolutePath, FS_CONSTANTS.X_OK);
    }
    const fileIdentity = fileIdentityFromState(initial);
    handle = await open(absolutePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink <= 0n
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(before),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
    ) failSyntheticSigningHelper();
    const bytes = Buffer.alloc(Number(initial.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > bytes.length - offset) {
        failSyntheticSigningHelper();
      }
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    const after = await handle.stat({ bigint: true });
    if (
      trailing.bytesRead !== 0
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(after),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
    ) failSyntheticSigningHelper();
    await handle.close();
    handle = null;
    const finalState = await lstat(absolutePath, { bigint: true });
    const parentAfter = await lstat(parentPath, { bigint: true });
    if (
      finalState.isSymbolicLink()
      || !finalState.isFile()
      || parentAfter.isSymbolicLink()
      || !parentAfter.isDirectory()
      || !identityObjectsEqual(
        fileIdentity,
        fileIdentityFromState(finalState),
        SYNTHETIC_SIGNING_HELPER_FILE_IDENTITY_KEYS,
      )
      || !identityObjectsEqual(
        parentIdentity,
        parentIdentityFromState(parentAfter),
        SYNTHETIC_SIGNING_HELPER_PARENT_IDENTITY_KEYS,
      )
      || !pathsEqual(path.resolve(await realpath(absolutePath)), absolutePath)
      || !pathsEqual(path.resolve(await realpath(parentPath)), parentPath)
    ) failSyntheticSigningHelper();
    const capture = Object.freeze({
      authorityKind: SYNTHETIC_SIGNING_HELPER_AUTHORITY_KIND,
      schemaVersion: 1,
      byteLength: bytes.length,
      sha256: sha256Bytes(bytes),
      sourceFileIdentity: fileIdentity,
      sourceParentIdentity: parentIdentity,
      sourceBytesBase64: bytes.toString("base64"),
    });
    syntheticSigningHelperCaptures.add(capture);
    const decoded = decodeSyntheticSigningHelperCaptureBytes(capture);
    if (!decoded.equals(bytes)) failSyntheticSigningHelper();
    return capture;
  } catch (error) {
    if (
      error instanceof PublicSourceReceiptBoundaryVectorError
      && error.reason === "synthetic-signing-helper-invalid"
    ) throw error;
    failSyntheticSigningHelper();
  } finally {
    if (handle) await handle.close();
  }
}

export async function resolveSyntheticSigningHelperAuthority(options) {
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.getPrototypeOf(options) !== Object.prototype
    || Reflect.ownKeys(options).length !== 1
    || Reflect.ownKeys(options)[0] !== "git"
  ) failSyntheticSigningHelper();
  const suppliedGit = requireSyntheticSigningHelperGit(options.git);
  const git = await resolveControlledGitExecutable();
  if (
    !pathsEqual(suppliedGit.path, git.path)
    || !pathsEqual(suppliedGit.directory, git.directory)
    || suppliedGit.sha256 !== git.sha256
    || suppliedGit.byteLength !== git.byteLength
    || suppliedGit.reportedVersion !== git.reportedVersion
  ) failSyntheticSigningHelper();
  const executable = process.platform === "win32" ? "ssh-keygen.exe" : "ssh-keygen";
  const pathValue = Object.entries(process.env).find(
    ([key]) => key.toUpperCase() === "PATH",
  )?.[1];
  const candidates = [
    path.resolve(git.directory, "..", "usr", "bin", executable),
    ...String(pathValue ?? "")
      .split(path.delimiter)
      .filter(Boolean)
      .map((entry) => {
        const unquoted = entry.length >= 2
          && entry.startsWith('"')
          && entry.endsWith('"')
          ? entry.slice(1, -1)
          : entry;
        return path.resolve(unquoted, executable);
      }),
  ];
  const examined = new Set();
  for (const candidate of candidates) {
    const key = process.platform === "win32" ? candidate.toLowerCase() : candidate;
    if (examined.has(key)) continue;
    examined.add(key);
    try {
      await lstat(candidate, { bigint: true });
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      failSyntheticSigningHelper();
    }
    let canonical;
    try {
      canonical = path.resolve(await realpath(candidate));
    } catch {
      failSyntheticSigningHelper();
    }
    if (!pathsEqual(canonical, candidate)) failSyntheticSigningHelper();
    const capture = await captureSyntheticSigningHelperSource(canonical, git);
    const capabilityParent = await validateTemporaryParent(os.tmpdir());
    const capabilityWorkspace = await createSyntheticVectorWorkspace(capabilityParent);
    const provisionalAuthority = Object.freeze({
      ...capture,
      capabilityProfile: Object.freeze({
        status: 1,
        stdout: "",
        stderr: "usage: ssh-keygen ed25519 -Y sign -Y verify",
      }),
    });
    syntheticSigningHelperAuthorities.add(provisionalAuthority);
    let execution = null;
    let capabilityProfile = null;
    let capabilityError = null;
    let cleanupFailed = false;
    try {
      measureSyntheticWorkspacePathBudget(capabilityWorkspace.path);
      execution = await materializeSyntheticSigningHelper(capture, capabilityWorkspace);
      capabilityProfile = await probeSyntheticSigningHelperCapability(
        execution,
        provisionalAuthority,
        git,
      );
    } catch (error) {
      capabilityError = error;
    } finally {
      if (execution !== null) {
        try {
          await removeSyntheticSigningHelperExecution(execution, provisionalAuthority);
        } catch {
          cleanupFailed = true;
        }
      }
      try {
        await removeVectorRoot(capabilityWorkspace);
      } catch {
        cleanupFailed = true;
      }
    }
    if (cleanupFailed) failSyntheticSigningHelper();
    if (capabilityError !== null) {
      if (
        capabilityError instanceof PublicSourceReceiptBoundaryVectorError
        && capabilityError.reason === "synthetic-signing-helper-invalid"
      ) continue;
      throw capabilityError;
    }
    const authority = Object.freeze({
      ...capture,
      capabilityProfile,
    });
    syntheticSigningHelperAuthorities.add(authority);
    requireSyntheticSigningHelperAuthoritySchema(authority, git);
    return authority;
  }
  failSyntheticSigningHelper();
}

async function writeSyntheticPath(root, relative, bytes) {
  const target = path.join(root, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await writeFile(target, bytes, { mode: 0o600 });
}

async function runSyntheticGitWithSigningHelper({
  lockedContext,
  git,
  repository,
  args,
  hook,
  checkpoint,
}) {
  const locked = requireSyntheticSigningHelperLockedContext(lockedContext, git);
  await revalidateSyntheticSigningHelperExecution(
    locked.execution,
    locked.authority,
  );
  await runSyntheticSigningHelperTestCheckpoint(hook, checkpoint);
  await revalidateSyntheticSigningHelperExecution(
    locked.execution,
    locked.authority,
  );
  let output;
  try {
    output = runSyntheticGit(git, repository, args);
  } finally {
    await revalidateSyntheticSigningHelperExecution(
      locked.execution,
      locked.authority,
    );
  }
  return output;
}

async function initializeSyntheticReceiptAuthority(
  root,
  git,
  syntheticSigningHelperLockedContext,
  syntheticSigningHelperTestHook,
  workspacePlan,
) {
  const locked = requireSyntheticSigningHelperLockedContext(
    syntheticSigningHelperLockedContext,
    git,
  );
  const repository = path.join(root, "r");
  const external = path.join(root, "o");
  await mkdir(repository, { mode: 0o700 });
  await mkdir(external, { mode: 0o700 });
  runSyntheticGit(git, repository, ["init", "--initial-branch=v"]);
  for (const [key, value] of [
    ["user.name", "Receipt Boundary Vector"],
    ["user.email", "receipt-vector@example.invalid"],
    ["commit.gpgsign", "false"],
    ["core.autocrlf", "false"],
    ["core.ignorecase", "false"],
    ["core.filemode", "false"],
    ["core.protectNTFS", "false"],
  ]) runSyntheticGit(git, repository, ["config", key, value]);

  const manifestBytes = buildSyntheticPublicSourceManifestBytes();
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const exactPaths = new Set();
  for (const component of manifest.components) {
    for (const relative of component.selectors.includeExact) {
      exactPaths.add(relative);
    }
  }
  for (const relative of [...exactPaths].sort()) {
    await writeSyntheticPath(
      repository,
      relative,
      relative === "developer/public-source-manifest.json"
        ? manifestBytes
        : Buffer.from("synthetic:" + relative + "\n", "utf8"),
    );
  }
  const prefixMembers = new Map([
    ["backend/admin/admin.js", "export const admin = true;\n"],
    ["backend/auth/auth.js", "export const auth = true;\n"],
    ["backend/migrations/001_init.sql", "SELECT 1;\n"],
    ["backend/scripts/executable.sh", "#!/bin/sh\nexit 0\n"],
    ["backend/src/app.js", "export const app = true;\n"],
    ["backend/test/app.test.js", "export const test = true;\n"],
    ["css/app.css", "body {}\n"],
    ["js/app.js", "export const app = true;\n"],
    ["src/styles/app.css", ":root {}\n"],
  ]);
  for (const [relative, source] of prefixMembers) {
    await writeSyntheticPath(repository, relative, Buffer.from(source, "utf8"));
  }
  for (const relative of ADAPTER_CRITICAL_TOOL_PATHS) {
    await writeSyntheticPath(
      repository,
      relative,
      Buffer.from("// historical placeholder for " + relative + "\n", "utf8"),
    );
  }
  for (const relative of [
    "developer/prepare-public-source-archive.mjs",
    "developer/prepare-public-source-tree.mjs",
  ]) {
    await writeSyntheticPath(repository, relative, Buffer.from("export {};\n", "ascii"));
  }
  runSyntheticGit(git, repository, ["add", "-A"]);
  runSyntheticGit(git, repository, [
    "commit", "-m", "synthetic historical receipt source",
  ]);
  const sourceCommit = runSyntheticGit(
    git, repository, ["rev-parse", "HEAD"],
  ).toString("ascii").trim();

  const developerDirectory = fileURLToPath(new URL(".", import.meta.url));
  for (const relative of ADAPTER_CRITICAL_TOOL_PATHS) {
    const sourcePath = path.join(developerDirectory, path.posix.basename(relative));
    await writeSyntheticPath(repository, relative, await readFile(sourcePath));
  }
  const signingKey = path.join(external, "k");
  const keyResult = await runPrivateSyntheticSigningHelper({
    execution: locked.execution,
    authority: locked.authority,
    git,
    args: ["-q", "-t", "ed25519", "-N", "", "-f", signingKey],
    hook: syntheticSigningHelperTestHook,
    checkpoint: "before-helper-key-create",
  });
  if (keyResult.error || keyResult.status !== 0) failVector("SYNTHETIC-KEY-CREATE");
  const publicResult = await runPrivateSyntheticSigningHelper({
    execution: locked.execution,
    authority: locked.authority,
    git,
    args: ["-y", "-f", signingKey],
    hook: syntheticSigningHelperTestHook,
    checkpoint: "before-helper-public-key",
    encoding: "utf8",
  });
  if (publicResult.error || publicResult.status !== 0 || publicResult.stderr !== "") {
    failVector("SYNTHETIC-PUBLIC-KEY");
  }
  const publicParts = publicResult.stdout.trim().split(/\s+/u);
  if (publicParts.length < 2) failVector("SYNTHETIC-PUBLIC-KEY");
  const allowedSigners = path.join(external, "s");
  await writeFile(
    allowedSigners,
    `receipt-vector@example.invalid ${publicParts[0]} ${publicParts[1]}\n`,
    { flag: "wx", mode: 0o600 },
  );
  for (const [key, value] of [
    ["gpg.format", "ssh"],
    ["user.signingkey", signingKey],
    ["gpg.ssh.allowedSignersFile", allowedSigners],
    ["gpg.ssh.program", locked.execution.absolutePath],
    ["commit.gpgsign", "true"],
  ]) runSyntheticGit(git, repository, ["config", key, value]);
  runSyntheticGit(git, repository, [
    "add", "--", ...ADAPTER_CRITICAL_TOOL_PATHS,
  ]);
  await runSyntheticGitWithSigningHelper({
    lockedContext: locked,
    git,
    repository,
    args: ["commit", "-m", "synthetic signed receipt tooling"],
    hook: syntheticSigningHelperTestHook,
    checkpoint: "before-git-signed-commit",
  });
  const toolingCommit = runSyntheticGit(
    git, repository, ["rev-parse", "HEAD"],
  ).toString("ascii").trim();
  await runSyntheticGitWithSigningHelper({
    lockedContext: locked,
    git,
    repository,
    args: ["verify-commit", "--raw", toolingCommit],
    hook: syntheticSigningHelperTestHook,
    checkpoint: "before-git-verify-commit",
  });

  const membership = await loadValidatedPublicSourceMembership({
    repo: repository,
    commit: sourceCommit,
  });
  const archiveChunks = [];
  for (const member of membership.members) {
    archiveChunks.push(encodeUstarHeader({
      relativePath: member.path,
      gitMode: member.gitMode,
      size: member.blobBytes.length,
    }));
    archiveChunks.push(member.blobBytes);
    archiveChunks.push(Buffer.alloc(paddingLength(member.blobBytes.length), 0));
  }
  archiveChunks.push(Buffer.alloc(1024, 0));
  const sourceArchive = path.join(external, "s.tar");
  await writeFile(sourceArchive, Buffer.concat(archiveChunks), {
    flag: "wx",
    mode: 0o600,
  });
  const artifactPath = path.join(external, "a.zip");
  await writeFile(artifactPath, Buffer.from("PK\x03\x04receipt-vector\n", "binary"), {
    flag: "wx",
    mode: 0o600,
  });
  return Object.freeze({
    git,
    syntheticSigningHelperLockedContext,
    syntheticSigningHelperTestHook,
    workspacePlan,
    repository,
    sourceCommit,
    toolingCommit,
    sourceArchive,
    artifacts: Object.freeze([Object.freeze({
      role: "standalone-release-archive",
      format: "zip",
      path: artifactPath,
    })]),
  });
}

async function runCopiedReceiptTool(
  authority,
  basename,
  args,
  allowFailure = false,
  environmentAdditions = {},
  failureId = null,
) {
  const locked = requireSyntheticSigningHelperLockedContext(
    authority.syntheticSigningHelperLockedContext,
    authority.git,
  );
  await revalidateSyntheticSigningHelperExecution(
    locked.execution,
    locked.authority,
  );
  await runSyntheticSigningHelperTestCheckpoint(
    authority.syntheticSigningHelperTestHook,
    `before-copied-tool-${basename}`,
  );
  await revalidateSyntheticSigningHelperExecution(
    locked.execution,
    locked.authority,
  );
  const modulePath = path.join(authority.repository, "developer", basename);
  let result;
  try {
    result = spawnSync(
      process.execPath,
      [modulePath, ...args],
      {
        cwd: path.dirname(authority.repository),
        encoding: "utf8",
        env: syntheticGitEnvironment(authority.git, environmentAdditions),
        maxBuffer: 16 * 1024 * 1024,
        shell: false,
        windowsHide: true,
      },
    );
  } finally {
    await revalidateSyntheticSigningHelperExecution(
      locked.execution,
      locked.authority,
    );
  }
  if (result.error || (!allowFailure && result.status !== 0)) {
    failVector(failureId);
  }
  if (allowFailure) {
    if (result.status === 0) failVector(failureId);
    return Object.freeze({
      status: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }
  try {
    if (result.stderr !== "" || result.stdout.split("\n").length !== 2) {
      failVector(failureId);
    }
    return JSON.parse(result.stdout);
  } catch {
    failVector(failureId);
  }
}

function receiptCliArguments(authority, receipt = null) {
  const args = receipt === null
    ? [
      "--repo", authority.repository,
      "--source-commit", authority.sourceCommit,
      "--tooling-commit", authority.toolingCommit,
      "--source-archive", authority.sourceArchive,
    ]
    : [
      "--full",
      "--repo", authority.repository,
      "--receipt", receipt,
      "--source-archive", authority.sourceArchive,
    ];
  for (const artifact of authority.artifacts) {
    args.push("--artifact", artifact.role, artifact.format, artifact.path);
  }
  return args;
}

async function establishBaseline(root, authority) {
  const profiles = Object.freeze([
    Object.freeze({ LANG: "C", LC_ALL: "C", TZ: "UTC", SOURCE_DATE_EPOCH: "0" }),
    Object.freeze({ LANG: "tr_TR.UTF-8", LC_ALL: "tr_TR.UTF-8", TZ: "Pacific/Kiritimati", SOURCE_DATE_EPOCH: "4102444800" }),
    Object.freeze({ LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8", TZ: "Europe/London", SOURCE_DATE_EPOCH: "1" }),
    Object.freeze({ LANG: "de_DE.UTF-8", LC_ALL: "de_DE.UTF-8", TZ: "America/Los_Angeles", SOURCE_DATE_EPOCH: "2147483647" }),
  ]);
  const runs = [];
  for (let index = 0; index < profiles.length; index += 1) {
    const receiptPath = path.join(
      root,
      `b${index}${RECEIPT_OUTPUT_SUFFIX}`,
    );
    await runCopiedReceiptTool(
      authority,
      "prepare-public-source-receipt.mjs",
      [...receiptCliArguments(authority), "--output", receiptPath],
      false,
      profiles[index],
      `BASELINE-PREPARE-${index + 1}`,
    );
    const bytes = await readFile(receiptPath);
    const state = await lstat(receiptPath, { bigint: true });
    const verification = await runCopiedReceiptTool(
      authority,
      "verify-public-source-receipt.mjs",
      receiptCliArguments(authority, receiptPath),
      false,
      profiles[index],
      `BASELINE-VERIFY-${index + 1}`,
    );
    const transcript = encodeReceiptVerificationTranscript(verification, {
      sourceCommit: authority.sourceCommit,
      toolingCommit: authority.toolingCommit,
      artifactCount: authority.artifacts.length,
    });
    runs.push(Object.freeze({
      path: receiptPath,
      bytes,
      state: Object.freeze({ device: state.dev, inode: state.ino }),
      verification,
      transcript,
      profile: profiles[index],
    }));
  }
  for (let left = 0; left < runs.length; left += 1) {
    for (let right = left + 1; right < runs.length; right += 1) {
      if (
        runs[left].path === runs[right].path
        || !runs[left].bytes.equals(runs[right].bytes)
        || runs[left].state.device === runs[right].state.device
          && runs[left].state.inode === runs[right].state.inode
        || !runs[left].transcript.equals(runs[right].transcript)
      ) failVector("R10");
    }
  }
  const firstRun = runs[0];
  return Object.freeze({
    bytes: firstRun.bytes,
    receipt: requireAccept(firstRun.bytes, "BASELINE-RECEIPT-PARSE"),
    first: runs[0].path,
    second: runs[1].path,
    verification: firstRun.verification,
    transcript: firstRun.transcript,
    runs: Object.freeze(runs),
  });
}

async function executeReceiptVector(vector, baseline, authority) {
  switch (vector.vectorId) {
    case "R01": {
      const parsed = requireAccept(baseline.bytes, vector.vectorId);
      if (
        parsed.receiptKind !== RECEIPT_KIND
        || baseline.verification.status !== "ok"
        || baseline.verification.verificationComplete !== true
      ) failVector(vector.vectorId);
      return;
    }
    case "R02":
      if (
        authority.sourceCommit === authority.toolingCommit
        || baseline.receipt.source.commit !== authority.sourceCommit
        || baseline.receipt.tooling.commit !== authority.toolingCommit
      ) failVector(vector.vectorId);
      return;
    case "R03":
      if (
        baseline.verification.sourceArchiveVerified !== true
        || baseline.verification.sourceCommit !== authority.sourceCommit
        || baseline.receipt.source.membershipCount < 1
        || baseline.receipt.source.archive.format !== "tar-ustar-v1"
      ) failVector(vector.vectorId);
      return;
    case "R04": {
      const expected = [...authority.artifacts].sort((left, right) => (
        (left.role < right.role ? -1 : left.role > right.role ? 1 : 0)
        || (left.format < right.format ? -1 : left.format > right.format ? 1 : 0)
      ));
      if (
        baseline.receipt.artifacts.length !== expected.length
        || baseline.receipt.artifacts.some((artifact, index) => (
          artifact.role !== expected[index].role
          || artifact.format !== expected[index].format
        ))
      ) failVector(vector.vectorId);
      const malformed = clone(baseline.receipt);
      malformed.artifacts.push(clone(malformed.artifacts[0]));
      requireReject(independentBytes(malformed), "duplicate-artifact-role");
      return;
    }
    case "R05": {
      const first = encodeCanonicalReceipt(clone(baseline.receipt));
      const second = encodeCanonicalReceipt(clone(baseline.receipt));
      if (first === second || !first.equals(second)) failVector(vector.vectorId);
      return;
    }
    case "R06":
      if (
        baseline.runs.length !== 4
        || baseline.runs.some((run) => !run.transcript.equals(baseline.transcript))
      ) failVector(vector.vectorId);
      return;
    case "R07": {
      const reads = await Promise.all(baseline.runs.map((run) => readFile(run.path)));
      if (
        new Set(baseline.runs.map((run) => run.path)).size !== 4
        || reads.some((bytes, index) => bytes === baseline.runs[index].bytes)
        || reads.some((bytes) => !bytes.equals(baseline.bytes))
      ) failVector(vector.vectorId);
      return;
    }
    case "R08": {
      const identities = baseline.runs.map(
        (run) => `${run.state.device}:${run.state.inode}`,
      );
      if (new Set(identities).size !== 4) failVector(vector.vectorId);
      return;
    }
    case "R09":
      if (
        new Set(baseline.runs.map((run) => JSON.stringify(run.profile))).size !== 4
        || baseline.runs.some((run) => (
          run.verification.status !== "ok"
          || !run.bytes.equals(baseline.bytes)
        ))
      ) failVector(vector.vectorId);
      return;
    case "R10": {
      const paths = new Set();
      const identities = new Set();
      for (const run of baseline.runs) {
        paths.add(run.path);
        identities.add(`${run.state.device}:${run.state.inode}`);
        if (!run.bytes.equals(baseline.bytes)) failVector(vector.vectorId);
      }
      if (paths.size !== 4 || identities.size !== 4) failVector(vector.vectorId);
      return;
    }
    default:
      failVector(vector.vectorId);
  }
}

function requireCanonicalShape(bytes, keys) {
  if (
    !Buffer.isBuffer(bytes)
    || bytes.length < 3
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
  ) throw new Error("canonical framing");
  const value = JSON.parse(bytes.subarray(0, -1).toString("utf8"));
  if (
    !exactKeys(value, keys)
    || !Buffer.from(JSON.stringify(value) + "\n", "utf8").equals(bytes)
  ) throw new Error("canonical shape");
  return value;
}

async function executeCanonicalVector(vector, baseline, root) {
  const schemas = Object.freeze({
    C01: Object.freeze({
      keys: Object.freeze([
        "documentKind", "schemaVersion", "artifactRole", "formatProfile",
        "sourceCommit", "toolingCommit", "manifestSha256",
        "membershipReportSha256", "membershipCount", "archive",
        "receiptAuthority", "criticalFiles", "artifacts",
      ]),
      value: Object.freeze({
        documentKind: "ieltmps-public-source-receipt-input-set",
        schemaVersion: 1,
        artifactRole: ARTIFACT_ROLE,
        formatProfile: FORMAT_PROFILE,
        sourceCommit: baseline.receipt.source.commit,
        toolingCommit: baseline.receipt.tooling.commit,
        manifestSha256: baseline.receipt.source.manifestSha256,
        membershipReportSha256: baseline.receipt.source.membershipReportSha256,
        membershipCount: baseline.receipt.source.membershipCount,
        archive: baseline.receipt.source.archive,
        receiptAuthority: Object.freeze({
          receiptKind: RECEIPT_KIND,
          schemaVersion: RECEIPT_SCHEMA_VERSION,
          outputSuffix: RECEIPT_OUTPUT_SUFFIX,
        }),
        criticalFiles: baseline.receipt.tooling.criticalFiles,
        artifacts: baseline.receipt.artifacts,
      }),
    }),
    C02: Object.freeze({
      keys: Object.freeze([
        "semanticReportKind", "schemaVersion", "artifactRole", "formatProfile",
        "sourceCommit", "toolingCommit", "inputSetSha256", "artifactSha256",
        "artifactByteLength", "canonicalVerifierPassed", "sameProcessRepeatable",
        "sameHostRepeatable", "boundaryVectorSetPassed",
      ]),
      value: Object.freeze({
        semanticReportKind: "ieltmps-reproducibility-semantic-report",
        schemaVersion: 1,
        artifactRole: ARTIFACT_ROLE,
        formatProfile: FORMAT_PROFILE,
        sourceCommit: baseline.receipt.source.commit,
        toolingCommit: baseline.receipt.tooling.commit,
        inputSetSha256: "1".repeat(64),
        artifactSha256: sha256Bytes(baseline.bytes),
        artifactByteLength: baseline.bytes.length,
        canonicalVerifierPassed: true,
        sameProcessRepeatable: true,
        sameHostRepeatable: true,
        boundaryVectorSetPassed: true,
      }),
    }),
    C03: Object.freeze({
      keys: Object.freeze(["evidenceKind", "schemaVersion", "result", "failureCode"]),
      value: Object.freeze({ evidenceKind: "pass-evidence", schemaVersion: 1, result: "pass", failureCode: null }),
    }),
    C04: Object.freeze({
      keys: Object.freeze(["evidenceKind", "schemaVersion", "result", "failureCode"]),
      value: Object.freeze({ evidenceKind: "failure-evidence", schemaVersion: 1, result: "fail", failureCode: "synthetic-failure" }),
    }),
    C05: Object.freeze({
      keys: Object.freeze(["status", "mode", "evidenceResult", "projectPublicationAuthorized"]),
      value: Object.freeze({ status: "ok", mode: "reproducibility-evidence-verification", evidenceResult: "pass", projectPublicationAuthorized: false }),
    }),
  });
  if (Object.hasOwn(schemas, vector.vectorId)) {
    const schema = schemas[vector.vectorId];
    const bytes = canonicalAdapterJsonBytes(schema.value, "BOUNDARY_VECTOR");
    requireCanonicalShape(bytes, schema.keys);
    const reversed = Object.fromEntries(Object.entries(schema.value).reverse());
    requireSyncReject(() => requireCanonicalShape(
      Buffer.from(JSON.stringify(reversed) + "\n", "utf8"),
      schema.keys,
    ));
    return;
  }
  if (vector.vectorId === "C06") {
    requireCanonicalShape(baseline.transcript, Object.keys(JSON.parse(baseline.transcript)));
    requireSyncReject(() => requireCanonicalShape(
      Buffer.concat([baseline.transcript, Buffer.from("\n", "ascii")]),
      Object.keys(JSON.parse(baseline.transcript)),
    ));
    return;
  }
  if (vector.vectorId === "C07") {
    const expectedNames = [
      "receipt.source-receipt.json", "receipt-verification.json",
      "input-set.json", "semantic-report.json", "evidence.json",
      "verification-result.json", ".complete",
    ];
    const expected = new Set(expectedNames);
    const directory = path.join(root, "c");
    await mkdir(directory, { mode: 0o700 });
    for (const name of expectedNames.filter((name) => name !== ".complete")) {
      await writeFile(
        path.join(directory, name),
        Buffer.from(`${name}\n`, "ascii"),
        { flag: "wx", mode: 0o600 },
      );
    }
    await writeFile(
      path.join(directory, ".complete"),
      Buffer.from("complete\n", "ascii"),
      { flag: "wx", mode: 0o600 },
    );
    const requireExactOutputSet = (names) => {
      if (
        names.length !== expected.size
        || names.some((name) => !expected.has(name))
      ) throw new Error("unexpected output");
    };
    requireExactOutputSet(await readdir(directory));
    await writeFile(
      path.join(directory, "comparison-report.json"),
      Buffer.from("{}\n", "ascii"),
      { flag: "wx", mode: 0o600 },
    );
    await requireAsyncReject(async () => requireExactOutputSet(
      await readdir(directory),
    ));
    return;
  }
  if (vector.vectorId === "C08") {
    const safeText = baseline.bytes.toString("utf8");
    const privatePattern = /\\|[A-Za-z]:\/|file:|localhost|private-run|worker-[ab]/u;
    if (privatePattern.test(safeText)) failVector(vector.vectorId);
    requireSyncReject(() => {
      if (privatePattern.test(`${safeText}C:\\private-run\\worker-a`)) {
        throw new Error("private value");
      }
    });
    return;
  }
  failVector(vector.vectorId);
}

async function verifyMutatedReceipt(
  root,
  baseline,
  authority,
  mutate,
  label,
  expectedPhase,
) {
  const value = clone(baseline.receipt);
  mutate(value);
  const target = path.join(root, `${label.toLowerCase()}${RECEIPT_OUTPUT_SUFFIX}`);
  await writeFile(target, independentBytes(value), { flag: "wx", mode: 0o600 });
  const rejection = await runCopiedReceiptTool(
    authority,
    "verify-public-source-receipt.mjs",
    receiptCliArguments(authority, target),
    true,
    {},
    label,
  );
  const diagnostic = /^ERROR ([A-Z_]+): [^\r\n]+\n$/u.exec(
    rejection.stderr,
  );
  if (
    rejection.status === 0
    || rejection.stdout !== ""
    || !diagnostic
    || diagnostic[1] !== expectedPhase
  ) failVector(label);
  return rejection;
}

function requireIdentityError(error, vectorId) {
  if (
    !error
    || error.phase !== "FILE_IDENTITY"
    || typeof error.reason !== "string"
    || !error.reason.startsWith(
      BOUNDARY_VECTOR_DESCRIPTORS.find(
        (descriptorValue) => descriptorValue.vectorId === vectorId,
      )?.caseId ?? "\0",
    )
  ) failVector(vectorId);
}

async function requireBoundFileMismatch({
  root,
  baseline,
  vector,
  mutate,
}) {
  const target = path.join(root, `b${vector.vectorId.toLowerCase()}.json`);
  await writeFile(target, baseline.bytes, { flag: "wx", mode: 0o600 });
  const expected = Object.freeze({
    sha256: sha256Bytes(baseline.bytes),
    byteLength: baseline.bytes.length,
  });
  await mutate(target);
  const actual = await readStableFile(target, {
    phase: "FILE_IDENTITY",
    reason: vector.caseId,
    kind: "bound-receipt",
    captureBytes: false,
  });
  requireSyncReject(() => {
    if (
      actual.sha256 !== expected.sha256
      || actual.byteLength !== expected.byteLength
    ) throw new Error(vector.caseId);
  });
}

async function executeStableFileVector(vector, root, baseline, authority) {
  const directory = path.join(root, `f${vector.vectorId.slice(1).toLowerCase()}`);
  await mkdir(directory, { mode: 0o700 });
  const target = path.join(directory, "i");
  const replacement = path.join(directory, "r");
  const backup = path.join(directory, "b");
  await writeFile(target, Buffer.alloc(4096, 0x41), { flag: "wx", mode: 0o600 });
  const requireMutationRejection = async (checkpointName, mutation) => {
    const error = await requireAsyncReject(() => readStableFile(target, {
      reason: vector.caseId,
      hooks: {
        checkpoint: async ({ checkpoint }) => {
          if (checkpoint === checkpointName) await mutation();
        },
      },
    }));
    requireIdentityError(error, vector.vectorId);
  };
  switch (vector.caseId) {
    case "mutation-during-stable-read":
      await requireMutationRejection("after-file-hash", async () => {
        await appendFile(target, Buffer.from([0x43]));
      });
      return;
    case "same-size-file-replacement":
      await requireMutationRejection("after-file-hash", async () => {
        await rename(target, backup);
        await writeFile(target, Buffer.alloc(4096, 0x44), { flag: "wx" });
      });
      return;
    case "file-truncation":
      await requireMutationRejection("after-file-open", async () => {
        await truncate(target, 1);
      });
      return;
    case "file-growth":
      await requireMutationRejection("after-file-open", async () => {
        await appendFile(target, Buffer.from([0x42]));
      });
      return;
    case "symlink-or-reparse-input":
      await writeFile(replacement, Buffer.from("target", "ascii"), { flag: "wx" });
      try {
        await unlink(target);
        await symlink(replacement, target, "file");
        const error = await requireAsyncReject(() => readStableFile(target, {
          reason: vector.caseId,
        }));
        requireIdentityError(error, vector.vectorId);
      } catch (error) {
        if (error instanceof PublicSourceReceiptBoundaryVectorError) throw error;
        try { await unlink(target); } catch { /* absent */ }
        await link(replacement, target);
        const fallback = await requireAsyncReject(() => readStableFile(target, {
          reason: vector.caseId,
        }));
        requireIdentityError(fallback, vector.vectorId);
      }
      return;
    case "hard-link-anomaly": {
      await link(target, replacement);
      const error = await requireAsyncReject(() => readStableFile(target, {
        reason: vector.caseId,
      }));
      requireIdentityError(error, vector.vectorId);
      return;
    }
    case "parent-replacement": {
      const moved = path.join(root, `${path.basename(directory)}m`);
      const error = await requireAsyncReject(() => readStableFile(target, {
        reason: vector.caseId,
        hooks: {
          checkpoint: async ({ checkpoint }) => {
            if (checkpoint !== "after-file-hash") return;
            await rename(directory, moved);
            await mkdir(directory, { mode: 0o700 });
            await writeFile(target, Buffer.alloc(4096, 0x42), { flag: "wx" });
          },
        },
      }));
      if (!["EPERM", "EACCES"].includes(error?.code)) {
        requireIdentityError(error, vector.vectorId);
      }
      return;
    }
    case "archive-input-replacement-race":
      {
        const archiveBackup = path.join(directory, "original-archive.tar");
        let archiveMoved = false;
        let error;
        try {
          error = await requireAsyncReject(() => readStableFile(
            authority.archive,
            {
              reason: vector.caseId,
              hooks: {
                checkpoint: async ({ checkpoint }) => {
                  if (checkpoint !== "after-file-hash") return;
                  await rename(authority.archive, archiveBackup);
                  archiveMoved = true;
                  await writeFile(
                    authority.archive,
                    Buffer.from("substituted archive\n", "ascii"),
                    { flag: "wx" },
                  );
                },
              },
            },
          ));
        } finally {
          if (archiveMoved) {
            try { await unlink(authority.archive); } catch { /* absent */ }
            await rename(archiveBackup, authority.archive);
          }
        }
        requireIdentityError(error, vector.vectorId);
      }
      return;
    case "receipt-output-replacement-race":
      {
        const receiptBackup = path.join(directory, "original-receipt.json");
        let receiptMoved = false;
        let error;
        try {
          error = await requireAsyncReject(() => readStableFile(
            baseline.runs[0].path,
            {
              reason: vector.caseId,
              hooks: {
                checkpoint: async ({ checkpoint }) => {
                  if (checkpoint !== "after-file-hash") return;
                  await rename(baseline.runs[0].path, receiptBackup);
                  receiptMoved = true;
                  await writeFile(
                    baseline.runs[0].path,
                    Buffer.from("substituted receipt\n", "ascii"),
                    { flag: "wx" },
                  );
                },
              },
            },
          ));
        } finally {
          if (receiptMoved) {
            try { await unlink(baseline.runs[0].path); } catch { /* absent */ }
            await rename(receiptBackup, baseline.runs[0].path);
          }
        }
        requireIdentityError(error, vector.vectorId);
      }
      return;
    default:
      failVector(vector.vectorId);
  }
}

async function executeFileVector(vector, root, baseline, authority) {
  switch (vector.caseId) {
    case "bound-artifact-hash-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.artifacts[0].sha256 = "0".repeat(64);
      }, vector.vectorId, "ARTIFACT");
    case "bound-artifact-length-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.artifacts[0].byteLength += 1;
      }, vector.vectorId, "ARTIFACT");
    case "archive-hash-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.source.archive.sha256 = "0".repeat(64);
      }, vector.vectorId, "SOURCE_ARCHIVE");
    case "archive-length-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.source.archive.byteLength += 1;
      }, vector.vectorId, "SOURCE_ARCHIVE");
    case "archive-format-mismatch": {
      const value = clone(baseline.receipt);
      value.source.archive.format = "tar-other-v1";
      requireReject(independentBytes(value), "archive-format");
      return;
    }
    case "receipt-hash-mismatch": {
      return requireBoundFileMismatch({
        root,
        baseline,
        vector,
        mutate: async (target) => {
          const changed = Buffer.from(baseline.bytes);
          changed[0] ^= 1;
          await writeFile(target, changed);
        },
      });
    }
    case "receipt-length-mismatch":
      return requireBoundFileMismatch({
        root,
        baseline,
        vector,
        mutate: async (target) => {
          await appendFile(target, Buffer.from([0x20]));
        },
      });
    default:
      return executeStableFileVector(vector, root, baseline, authority);
  }
}

async function executeGitVector(
  vector,
  root,
  baseline,
  authority,
  authoritySha256,
  vectorSetPath,
) {
  switch (vector.caseId) {
    case "source-commit-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.source.commit = "0".repeat(40);
      }, vector.vectorId, "SOURCE_ARCHIVE");
    case "tooling-commit-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.tooling.commit = "0".repeat(40);
      }, vector.vectorId, "TOOLING");
    case "source-manifest-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.source.manifestSha256 = "0".repeat(64);
      }, vector.vectorId, "SOURCE_ARCHIVE");
    case "membership-report-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.source.membershipReportSha256 = "0".repeat(64);
      }, vector.vectorId, "SOURCE_ARCHIVE");
    case "critical-tool-descriptor-mismatch":
      return verifyMutatedReceipt(root, baseline, authority, (value) => {
        value.tooling.criticalFiles[0].sha256 = "0".repeat(64);
      }, vector.vectorId, "TOOLING");
    case "modified-loaded-tool-bytes": {
      const target = path.join(
        authority.repository,
        ...ADAPTER_CRITICAL_TOOL_PATHS[0].split("/"),
      );
      const original = await readFile(target);
      try {
        await writeFile(target, Buffer.concat([original, Buffer.from("// altered\n", "ascii")]));
        const error = await requireAsyncReject(() => validateRepositoryCommit(
          authority.repository,
          authority.toolingCommit,
          authority.git,
          "TOOL_SET",
        ));
        if (error?.phase !== "TOOL_SET" || error?.reason !== "dirty-tooling-worktree") {
          failVector(vector.vectorId);
        }
      } finally {
        await writeFile(target, original);
      }
      return;
    }
    case "replacement-object": {
      runSyntheticGit(authority.git, authority.repository, [
        "replace", authority.sourceCommit, authority.toolingCommit,
      ]);
      try {
        const error = await requireAsyncReject(() => validateRepositoryCommit(
          authority.repository,
          authority.toolingCommit,
          authority.git,
          "GIT_IDENTITY",
        ));
        if (error?.reason !== "replacement-object-ref") failVector(vector.vectorId);
      } finally {
        runSyntheticGit(authority.git, authority.repository, [
          "replace", "-d", authority.sourceCommit,
        ]);
      }
      return;
    }
    case "replace-ref-environment":
    case "hostile-git-environment": {
      const hostileName = vector.caseId === "replace-ref-environment"
        ? "GIT_REPLACE_REF_BASE"
        : "GIT_DIR";
      const prior = process.env[hostileName];
      try {
        process.env[hostileName] = path.join(root, "x");
        const sanitized = syntheticGitEnvironment(authority.git);
        if (Object.keys(sanitized).some(
          (key) => key.toUpperCase() === hostileName,
        )) failVector(vector.vectorId);
        requireSyncReject(() => {
          if (Object.hasOwn(process.env, hostileName)) {
            throw new Error(vector.caseId);
          }
        });
      } finally {
        if (prior === undefined) delete process.env[hostileName];
        else process.env[hostileName] = prior;
      }
      return;
    }
    case "active-git-operation": {
      const gitDirectory = runSyntheticGit(
        authority.git,
        authority.repository,
        ["rev-parse", "--absolute-git-dir"],
      ).toString("utf8").trim();
      const marker = path.join(gitDirectory, "MERGE_HEAD");
      await writeFile(marker, authority.sourceCommit + "\n", { flag: "wx" });
      try {
        const error = await requireAsyncReject(() => validateRepositoryCommit(
          authority.repository,
          authority.toolingCommit,
          authority.git,
          "GIT_IDENTITY",
        ));
        if (error?.reason !== "active-git-operation") failVector(vector.vectorId);
      } finally {
        await unlink(marker);
      }
      return;
    }
    case "non-commit-object": {
      const blob = runSyntheticGit(
        authority.git,
        authority.repository,
        ["rev-parse", `${authority.sourceCommit}:README.md`],
      ).toString("ascii").trim();
      const error = await requireAsyncReject(() => validateRepositoryCommit(
        authority.repository,
        blob,
        authority.git,
        "GIT_IDENTITY",
      ));
      if (error?.reason !== "commit-object-type") failVector(vector.vectorId);
      return;
    }
    case "abbreviated-revision": {
      const error = await requireAsyncReject(() => validateRepositoryCommit(
        authority.repository,
        authority.toolingCommit.slice(0, 12),
        authority.git,
        "GIT_IDENTITY",
      ));
      if (error?.reason !== "commit-id") failVector(vector.vectorId);
      return;
    }
    case "runtime-identity-mismatch": {
      const error = await requireAsyncReject(() => validateRuntimeIdentity(
        Object.freeze({ value: Object.freeze({}) }),
        Object.freeze({}),
      ));
      if (error?.phase !== "RUNTIME_IDENTITY") failVector(vector.vectorId);
      return;
    }
    case "git-identity-document-mismatch": {
      const error = requireSyncReject(() => validateGitIdentity(
        Object.freeze({ value: Object.freeze({}) }),
        Object.freeze({}),
        authority.git,
      ));
      if (error?.phase !== "GIT_IDENTITY") failVector(vector.vectorId);
      return;
    }
    case "platform-probe-mismatch": {
      const error = requireSyncReject(() => validatePlatformProbeShape(
        Object.freeze({ value: Object.freeze({}) }),
        Object.freeze({}),
        "0".repeat(64),
        "1".repeat(64),
      ));
      if (error?.phase !== "PLATFORM_PROBE") failVector(vector.vectorId);
      return;
    }
    case "vector-set-identity-mismatch": {
      if (authoritySha256 === "0".repeat(64)) failVector(vector.vectorId);
      const error = await requireAsyncReject(() => (
        validatePublicSourceReceiptBoundaryVectorSet({
          testVectorSet: vectorSetPath,
          expectedSha256: "0".repeat(64),
        })
      ));
      if (!(error instanceof PublicSourceReceiptBoundaryVectorError)) {
        failVector(vector.vectorId);
      }
      return;
    }
    default:
      failVector(vector.vectorId);
  }
}

function executeMalformedVector(vector, baseline) {
  const value = clone(baseline.receipt);
  switch (vector.caseId) {
    case "independently-encoded-valid-receipt": {
      const bytes = independentBytes(value);
      const parsed = requireAccept(bytes);
      if (!bytes.equals(baseline.bytes) || parsed.receiptKind !== RECEIPT_KIND) {
        failVector(vector.vectorId);
      }
      return;
    }
    case "wrong-receipt-kind":
      value.receiptKind = "ieltmps-not-a-public-source-receipt";
      return requireReject(independentBytes(value), "receipt-kind");
    case "wrong-schema-version":
      value.schemaVersion = RECEIPT_SCHEMA_VERSION + 1;
      return requireReject(independentBytes(value), "schema-version");
    case "top-level-key-reorder":
      return requireReject(independentBytes({
        source: value.source,
        receiptKind: value.receiptKind,
        schemaVersion: value.schemaVersion,
        tooling: value.tooling,
        artifacts: value.artifacts,
        correspondingSourceComplete: false,
        publicationBlocked: true,
      }), "top-level-key-order");
    case "nested-key-reorder":
      value.source = {
        manifestSha256: value.source.manifestSha256,
        commit: value.source.commit,
        membershipReportSha256: value.source.membershipReportSha256,
        membershipCount: value.source.membershipCount,
        archive: value.source.archive,
      };
      return requireReject(independentBytes(value), "source-key-order");
    case "missing-key":
      delete value.publicationBlocked;
      return requireReject(independentBytes(value), "top-level-missing-field");
    case "extra-key":
      value.extra = false;
      return requireReject(independentBytes(value), "top-level-unknown-field");
    case "duplicate-key": {
      const text = independentBytes(value).toString("utf8").replace(
        '"schemaVersion":1,',
        '"schemaVersion":1,"schemaVersion":1,',
      );
      return requireReject(Buffer.from(text, "utf8"), "top-level-duplicate-key");
    }
    case "reordered-array":
      value.tooling.criticalFiles.reverse();
      return requireReject(independentBytes(value), "critical-file-path-order");
    case "duplicate-array-entry":
      value.artifacts.push(clone(value.artifacts[0]));
      return requireReject(independentBytes(value), "duplicate-artifact-role");
    case "utf8-bom":
      return requireReject(Buffer.concat([
        Buffer.from([0xef, 0xbb, 0xbf]),
        independentBytes(value),
      ]), "utf8-bom");
    case "crlf-framing":
      return requireReject(Buffer.from(
        independentBytes(value).toString("utf8").replace(/\n$/u, "\r\n"),
        "utf8",
      ), "crlf-or-cr");
    case "missing-final-lf": {
      const bytes = independentBytes(value);
      return requireReject(bytes.subarray(0, bytes.length - 1), "missing-final-lf");
    }
    case "extra-final-lf":
      return requireReject(Buffer.concat([
        independentBytes(value),
        Buffer.from("\n", "ascii"),
      ]), "extra-final-lf");
    case "uppercase-hash":
      value.source.archive.sha256 = "A".repeat(64);
      return requireReject(independentBytes(value), "archive-sha256");
    case "short-hash":
      value.source.archive.sha256 = "a".repeat(63);
      return requireReject(independentBytes(value), "archive-sha256");
    case "unsafe-integer":
      value.source.archive.byteLength = Number.MAX_SAFE_INTEGER + 1;
      return requireReject(independentBytes(value), "archive-byte-length-range");
    case "zero-byte-artifact-length-boundary":
      value.artifacts[0].byteLength = 0;
      requireAccept(independentBytes(value));
      return;
    case "max-safe-integer-virtual-boundary":
      value.source.archive.byteLength = Number.MAX_SAFE_INTEGER;
      value.artifacts[0].byteLength = Number.MAX_SAFE_INTEGER;
      requireAccept(independentBytes(value));
      return;
    case "receipt-byte-ceiling-over-limit":
      {
        const ceiling = 1024 * 1024;
        const parseBounded = (bytes) => {
          if (bytes.length > ceiling) throw new Error("receipt-byte-ceiling");
          return parsePublicSourceReceiptBytes(bytes);
        };
        const exact = Buffer.alloc(ceiling, 0x20);
        exact[0] = 0x7b;
        exact[exact.length - 1] = 0x0a;
        const exactError = requireSyncReject(() => parseBounded(exact));
        if (exactError?.message === "receipt-byte-ceiling") {
          failVector(vector.vectorId);
        }
        const over = Buffer.alloc(ceiling + 1, 0x20);
        const overError = requireSyncReject(() => parseBounded(over));
        if (overError?.message !== "receipt-byte-ceiling") {
          failVector(vector.vectorId);
        }
        return;
      }
    default:
      failVector(vector.vectorId);
  }
}

async function executeVectorDescriptor({
  vector,
  root,
  baseline,
  syntheticAuthority,
  authoritySha256,
  vectorSetPath,
}) {
  let actualOutcome;
  let actualPhase;
  let actualReason;
  if (vector.executionClass === "receipt-constructor-verifier") {
    await executeReceiptVector(vector, baseline, syntheticAuthority);
    actualOutcome = "accept";
    actualPhase = null;
    actualReason = null;
  } else if (vector.executionClass === "canonical-schema") {
    await executeCanonicalVector(vector, baseline, root);
    actualOutcome = "accept";
    actualPhase = null;
    actualReason = null;
  } else if (vector.executionClass === "external-file-identity") {
    await executeFileVector(vector, root, baseline, syntheticAuthority);
    const implementation = FILE_CASES.find(([caseId]) => caseId === vector.caseId);
    if (!implementation) failVector(vector.vectorId);
    actualOutcome = "reject";
    actualPhase = implementation[1];
    actualReason = implementation[0];
  } else if (vector.executionClass === "git-authority") {
    await executeGitVector(
      vector,
      root,
      baseline,
      syntheticAuthority,
      authoritySha256,
      vectorSetPath,
    );
    const implementation = GIT_CASES.find(([caseId]) => caseId === vector.caseId);
    if (!implementation) failVector(vector.vectorId);
    actualOutcome = "reject";
    actualPhase = implementation[1];
    actualReason = implementation[0];
  } else if (vector.executionClass === "independent-malformed-receipt") {
    executeMalformedVector(vector, baseline);
    const implementation = MALFORMED_CASES.find(
      ([caseId]) => caseId === vector.caseId,
    );
    if (!implementation) failVector(vector.vectorId);
    actualOutcome = implementation[1];
    actualPhase = actualOutcome === "accept" ? null : "receipt-schema";
    actualReason = actualOutcome === "accept" ? null : implementation[0];
  } else {
    failVector(vector.vectorId);
  }
  return Object.freeze({
    implementationId: `${vector.executionClass}\0${vector.caseId}`,
    actualOutcome,
    actualPhase,
    actualReason,
    operationCompleted: true,
  });
}

function completedVectorResult(vector, observation, assertionsCompleted) {
  return Object.freeze({
    vectorId: vector.vectorId,
    executionClass: vector.executionClass,
    caseId: vector.caseId,
    expectedOutcome: vector.expectedOutcome,
    expectedPhase: vector.expectedPhase,
    expectedReason: vector.expectedReason,
    actualOutcome: observation.actualOutcome,
    actualPhase: observation.actualPhase,
    actualReason: observation.actualReason,
    operationCompleted: observation.operationCompleted,
    assertionsCompleted,
  });
}

export async function runPublicSourceReceiptBoundaryVectors(options) {
  const optionKeys = options && typeof options === "object"
    ? Reflect.ownKeys(options)
    : [];
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || typeof options.testVectorSet !== "string"
    || optionKeys.some((key) => (
      typeof key === "string"
        ? ![
          "testVectorSet",
          "temporaryParent",
          "temporaryParentIdentity",
          "expectedSha256",
          "syntheticSigningHelperAuthority",
        ].includes(key)
        : key !== SYNTHETIC_HELPER_TEST_HOOK
    ))
  ) failVector();
  const syntheticSigningHelperTestHook = normalizeSyntheticSigningHelperTestHook(
    options[SYNTHETIC_HELPER_TEST_HOOK],
  );
  const authority = await validatePublicSourceReceiptBoundaryVectorSet({
    testVectorSet: options.testVectorSet,
    expectedSha256: options.expectedSha256 ?? null,
  });
  const parent = await validateTemporaryParent(
    options.temporaryParent,
    Object.hasOwn(options, "temporaryParentIdentity")
      ? options.temporaryParentIdentity
      : null,
  );
  const git = await resolveControlledGitExecutable();
  const syntheticSigningHelperAuthority = Object.hasOwn(
    options,
    "syntheticSigningHelperAuthority",
  )
    ? requireSyntheticSigningHelperAuthoritySchema(
      options.syntheticSigningHelperAuthority,
      git,
    )
    : await resolveSyntheticSigningHelperAuthority({ git });
  let workspace = null;
  let helperExecution = null;
  let syntheticSigningHelperLockedContext = null;
  let completed = false;
  const results = [];
  const reachedImplementations = new Set();
  try {
    workspace = await createSyntheticVectorWorkspace(parent);
    const root = workspace.path;
    const workspacePlan = measureSyntheticWorkspacePathBudget(root);
    helperExecution = await materializeSyntheticSigningHelper(
      syntheticSigningHelperAuthority,
      workspace,
      git,
    );
    const observedCapability = await probeSyntheticSigningHelperCapability(
      helperExecution,
      syntheticSigningHelperAuthority,
      git,
      syntheticSigningHelperTestHook,
    );
    if (
      observedCapability.status
        !== syntheticSigningHelperAuthority.capabilityProfile.status
      || observedCapability.stdout
        !== syntheticSigningHelperAuthority.capabilityProfile.stdout
      || observedCapability.stderr
        !== syntheticSigningHelperAuthority.capabilityProfile.stderr
    ) failSyntheticSigningHelper();
    syntheticSigningHelperLockedContext = createSyntheticSigningHelperLockedContext(
      syntheticSigningHelperAuthority,
      helperExecution,
      git,
    );
    installControlledGitPath(git);
    let syntheticAuthority;
    let baseline;
    try {
      syntheticAuthority = await initializeSyntheticReceiptAuthority(
        root,
        git,
        syntheticSigningHelperLockedContext,
        syntheticSigningHelperTestHook,
        workspacePlan,
      );
    } catch (error) {
      if (error instanceof PublicSourceReceiptBoundaryVectorError) throw error;
      failVector("SYNTHETIC-AUTHORITY");
    }
    try {
      baseline = await establishBaseline(root, syntheticAuthority);
    } catch (error) {
      if (error instanceof PublicSourceReceiptBoundaryVectorError) throw error;
      failVector("BASELINE");
    }
    for (const vector of BOUNDARY_VECTOR_DESCRIPTORS) {
      try {
        const locked = requireSyntheticSigningHelperLockedContext(
          syntheticSigningHelperLockedContext,
          git,
        );
        await revalidateSyntheticSigningHelperExecution(
          locked.execution,
          locked.authority,
        );
        await runSyntheticSigningHelperTestCheckpoint(
          syntheticSigningHelperTestHook,
          `before-vector-${vector.vectorId}`,
        );
        await revalidateSyntheticSigningHelperExecution(
          locked.execution,
          locked.authority,
        );
        const observation = await executeVectorDescriptor({
          vector,
          root,
          baseline,
          syntheticAuthority,
          authoritySha256: authority.sha256,
          vectorSetPath: options.testVectorSet,
        });
        await revalidateSyntheticSigningHelperExecution(
          locked.execution,
          locked.authority,
        );
        if (reachedImplementations.has(observation.implementationId)) {
          failVector(vector.vectorId);
        }
        reachedImplementations.add(observation.implementationId);
        const observedResult = completedVectorResult(vector, observation, false);
        if (
          observedResult.actualOutcome !== observedResult.expectedOutcome
          || observedResult.actualPhase !== observedResult.expectedPhase
          || observedResult.actualReason !== observedResult.expectedReason
          || observedResult.operationCompleted !== true
          || observedResult.assertionsCompleted !== false
        ) failVector(vector.vectorId);
        const result = completedVectorResult(vector, observation, true);
        results.push(result);
      } catch (error) {
        if (error instanceof PublicSourceReceiptBoundaryVectorError) {
          if (error.vectorId === null) failVector(vector.vectorId);
          throw error;
        }
        failVector(vector.vectorId);
      }
    }
    completed = true;
  } finally {
    let helperCleanupFailed = false;
    if (
      helperExecution !== null
      && syntheticSigningHelperLockedContext !== null
    ) {
      try {
        await removeSyntheticSigningHelperExecution(
          helperExecution,
          syntheticSigningHelperAuthority,
        );
      } catch {
        helperCleanupFailed = true;
      }
    }
    if (workspace !== null) {
      await removeVectorRoot(workspace);
    }
    if (completed && helperCleanupFailed) failVector("CLEANUP");
  }
  const resultIds = results.map((result) => result.vectorId);
  const descriptorIds = BOUNDARY_VECTOR_DESCRIPTORS.map(
    (descriptorValue) => descriptorValue.vectorId,
  );
  if (
    results.length !== BOUNDARY_VECTOR_DESCRIPTORS.length
    || reachedImplementations.size !== BOUNDARY_VECTOR_DESCRIPTORS.length
    || new Set(descriptorIds).size !== BOUNDARY_VECTOR_DESCRIPTORS.length
    || new Set(resultIds).size !== BOUNDARY_VECTOR_DESCRIPTORS.length
    || resultIds.some((vectorId, index) => vectorId !== descriptorIds[index])
    || results.some((result) => (
      result.operationCompleted !== true
      || result.assertionsCompleted !== true
      || result.actualOutcome !== result.expectedOutcome
      || result.actualPhase !== result.expectedPhase
      || result.actualReason !== result.expectedReason
    ))
  ) failVector();
  const passedCount = results.filter((result) => (
    result.operationCompleted
    && result.assertionsCompleted
    && result.actualOutcome === result.expectedOutcome
    && result.actualPhase === result.expectedPhase
    && result.actualReason === result.expectedReason
  )).length;
  return deepFreezeAdapter({
    status: "ok",
    mode: "public-source-receipt-boundary-vectors",
    vectorSetKind: VECTOR_SET_KIND,
    schemaVersion: 1,
    vectorSetId: VECTOR_SET_ID,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    testVectorSetSha256: authority.sha256,
    vectorCount: results.length,
    passedCount,
    failedCount: results.length - passedCount,
    boundaryVectorSetPassed: passedCount === results.length,
  });
}

function parseOptions(argv) {
  if (
    argv.length !== 2
    || argv[0] !== "--test-vector-set"
    || argv[1].startsWith("--")
  ) failVector();
  return Object.freeze({ testVectorSet: argv[1] });
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
  const result = await runPublicSourceReceiptBoundaryVectors(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceReceiptBoundaryVectorError
      ? error
      : new PublicSourceReceiptBoundaryVectorError();
    process.stderr.write(
      "ERROR BOUNDARY_VECTOR: boundary-vector-failed"
      + (safe.vectorId ? " " + safe.vectorId : "")
      + "\n",
    );
    process.exitCode = 1;
  });
}
