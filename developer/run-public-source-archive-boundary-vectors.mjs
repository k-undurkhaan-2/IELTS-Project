#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import {
  BLOCK_SIZE,
  MAX_USTAR_SIZE,
  USTAR_LAYOUT,
  ArchiveCoreError,
  encodeUstarHeader,
  paddingLength,
  pathsEqual,
  safeAddLength,
} from "./public-source-archive-core.mjs";
import { preparePublicSourceArchive } from "./prepare-public-source-archive.mjs";
import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  ARTIFACT_ROLE,
  FORMAT_PROFILE,
  deepFreezeAdapter,
  readAdapterCanonicalDocument,
  resolveControlledGitExecutable,
} from "./public-source-archive-reproducibility-core.mjs";

const VECTOR_SET_KIND = "ieltmps-public-source-archive-boundary-vector-set";
const VECTOR_SET_ID = "public-source-archive-tar-ustar-v1-boundaries-v1";
const MAX_GIT_BUFFER = 128 * 1024 * 1024;

function descriptor(vectorId, executionClass, caseId, expectedOutcome) {
  return Object.freeze({ vectorId, executionClass, caseId, expectedOutcome });
}

export const BOUNDARY_VECTOR_DESCRIPTORS = Object.freeze([
  descriptor("W01", "writer-verifier", "payload-0", "accept"),
  descriptor("W02", "writer-verifier", "payload-1", "accept"),
  descriptor("W03", "writer-verifier", "payload-511", "accept"),
  descriptor("W04", "writer-verifier", "payload-512", "accept"),
  descriptor("W05", "writer-verifier", "payload-513", "accept"),
  descriptor("W06", "writer-verifier", "name-bytes-99", "accept"),
  descriptor("W07", "writer-verifier", "name-bytes-100", "accept"),
  descriptor("W08", "writer-verifier", "name-bytes-101", "reject"),
  descriptor("W09", "writer-verifier", "prefix-bytes-154", "accept"),
  descriptor("W10", "writer-verifier", "prefix-bytes-155", "accept"),
  descriptor("W11", "writer-verifier", "prefix-bytes-156", "reject"),
  descriptor("W12", "writer-verifier", "split-prefix-155-name-100", "accept"),
  descriptor("W13", "writer-verifier", "utf8-name-bytes-100", "accept"),
  descriptor("W14", "writer-verifier", "utf8-name-bytes-101", "reject"),
  descriptor("W15", "writer-verifier", "utf8-prefix-bytes-155", "accept"),
  descriptor("W16", "writer-verifier", "utf8-prefix-bytes-156", "reject"),
  descriptor("W17", "writer-verifier", "git-mode-100644", "accept"),
  descriptor("W18", "writer-verifier", "git-mode-100755", "accept"),
  descriptor("W19", "writer-verifier", "ordinal-member-order", "accept"),
  descriptor("A01", "core-arithmetic", "padding-size-0", "accept"),
  descriptor("A02", "core-arithmetic", "padding-size-1", "accept"),
  descriptor("A03", "core-arithmetic", "padding-size-511", "accept"),
  descriptor("A04", "core-arithmetic", "padding-size-512", "accept"),
  descriptor("A05", "core-arithmetic", "padding-size-513", "accept"),
  descriptor("A06", "core-arithmetic", "ustar-size-8589934591-header", "accept"),
  descriptor("A07", "core-arithmetic", "ustar-size-8589934592", "reject"),
  descriptor("A08", "core-arithmetic", "safe-add-max-safe-integer", "accept"),
  descriptor("A09", "core-arithmetic", "safe-add-max-safe-integer-overflow", "reject"),
  descriptor("A10", "core-arithmetic", "virtual-zero-payload-member-count-limit", "accept"),
  descriptor("A11", "core-arithmetic", "virtual-zero-payload-member-count-overflow", "reject"),
  descriptor("M01", "independent-malformed-verifier", "canonical-zero-metadata-control", "accept"),
  descriptor("M02", "independent-malformed-verifier", "checksum-mismatch", "reject"),
  descriptor("M03", "independent-malformed-verifier", "equivalent-noncanonical-checksum", "reject"),
  descriptor("M04", "independent-malformed-verifier", "mode-0600", "reject"),
  descriptor("M05", "independent-malformed-verifier", "uid-nonzero", "reject"),
  descriptor("M06", "independent-malformed-verifier", "gid-nonzero", "reject"),
  descriptor("M07", "independent-malformed-verifier", "mtime-nonzero", "reject"),
  descriptor("M08", "independent-malformed-verifier", "devmajor-nonzero", "reject"),
  descriptor("M09", "independent-malformed-verifier", "devminor-nonzero", "reject"),
  descriptor("M10", "independent-malformed-verifier", "payload-padding-nonzero", "reject"),
  descriptor("M11", "independent-malformed-verifier", "terminator-zero-blocks", "reject"),
  descriptor("M12", "independent-malformed-verifier", "terminator-one-block", "reject"),
  descriptor("M13", "independent-malformed-verifier", "terminator-three-blocks", "reject"),
  descriptor("M14", "independent-malformed-verifier", "trailing-zero-byte", "reject"),
  descriptor("M15", "independent-malformed-verifier", "trailing-nonzero-byte", "reject"),
  descriptor("M16", "independent-malformed-verifier", "duplicate-member", "reject"),
  descriptor("M17", "independent-malformed-verifier", "out-of-order-member", "reject"),
  descriptor("M18", "independent-malformed-verifier", "case-collision", "reject"),
  descriptor("M19", "independent-malformed-verifier", "unicode-normalization-collision", "reject"),
  descriptor("M20", "independent-malformed-verifier", "declared-size-plus-one", "reject"),
  descriptor("M21", "independent-malformed-verifier", "payload-truncation", "reject"),
  descriptor("M22", "independent-malformed-verifier", "same-length-payload-mutation", "reject"),
]);

const VECTOR_SET_KEYS = Object.freeze([
  "vectorSetKind",
  "schemaVersion",
  "vectorSetId",
  "artifactRole",
  "formatProfile",
  "vectors",
]);
const VECTOR_KEYS = Object.freeze([
  "vectorId",
  "executionClass",
  "caseId",
  "expectedOutcome",
]);

export class PublicSourceArchiveBoundaryVectorError extends Error {
  constructor(vectorId = null) {
    super("public source archive boundary vector execution failed");
    this.name = "PublicSourceArchiveBoundaryVectorError";
    this.phase = "BOUNDARY_VECTOR";
    this.reason = "boundary-vector-failed";
    this.vectorId = typeof vectorId === "string" && /^[WAM][0-9]{2}$/u.test(vectorId)
      ? vectorId
      : null;
  }
}

function failVector(vectorId = null) {
  throw new PublicSourceArchiveBoundaryVectorError(vectorId);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

export async function validatePublicSourceArchiveBoundaryVectorSet({
  testVectorSet,
  expectedSha256 = null,
} = {}) {
  if (
    typeof testVectorSet !== "string"
    || !path.isAbsolute(testVectorSet)
    || (expectedSha256 !== null && !/^[0-9a-f]{64}$/u.test(expectedSha256))
  ) failVector();
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
    !exactKeys(value, VECTOR_SET_KEYS)
    || value.vectorSetKind !== VECTOR_SET_KIND
    || value.schemaVersion !== 1
    || value.vectorSetId !== VECTOR_SET_ID
    || value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Array.isArray(value.vectors)
    || value.vectors.length !== BOUNDARY_VECTOR_DESCRIPTORS.length
    || (expectedSha256 !== null && document.sha256 !== expectedSha256)
  ) failVector();
  for (let index = 0; index < value.vectors.length; index += 1) {
    const actual = value.vectors[index];
    const expected = BOUNDARY_VECTOR_DESCRIPTORS[index];
    if (
      !exactKeys(actual, VECTOR_KEYS)
      || VECTOR_KEYS.some((key) => actual[key] !== expected[key])
    ) failVector(expected.vectorId);
  }
  return Object.freeze({
    bytes: document.bytes,
    sha256: document.sha256,
    value,
  });
}

function licenseScopes() {
  return [
    {
      id: "eligible-server-source",
      label: "GNU Affero General Public License version 3 only",
      spdx: "AGPL-3.0-only",
      status: "resolved",
    },
    {
      id: "frontend",
      label: "GPLv3-family",
      spdx: null,
      status: "unresolved-exact-identifier",
      blocker: "D6",
    },
    {
      id: "governance-context",
      label: "scope-not-finalized",
      spdx: null,
      status: "unresolved",
    },
    {
      id: "license-texts",
      label: "legal-text-role",
      spdx: null,
      status: "not-a-license-claim",
    },
    {
      id: "shared-build-tooling",
      label: "scope-not-finalized",
      spdx: null,
      status: "unresolved",
    },
    {
      id: "third-party",
      label: "per-component-record",
      spdx: null,
      status: "component-record-required",
    },
  ];
}

function component(
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

function components() {
  return [
    component(
      "eligible-server-source",
      ["api-contract/README.md", "backend/Dockerfile", "backend/package.json"],
      [
        "backend/admin/",
        "backend/auth/",
        "backend/migrations/",
        "backend/scripts/",
        "backend/src/",
        "backend/test/",
      ],
      "preferred-source",
      "eligible-server-source",
      "preferred-editable",
      "not-required",
      "not-required",
    ),
    component(
      "frontend-build-tooling",
      ["scripts/build-bundles.mjs", "scripts/bundle-manifest.mjs"],
      [],
      "build-source",
      "shared-build-tooling",
      "preferred-editable",
      "not-required",
      "not-required",
    ),
    component(
      "frontend-preferred-source",
      ["index.html"],
      ["css/", "js/", "src/styles/"],
      "preferred-source",
      "frontend",
      "preferred-editable",
      "not-required",
      "not-required",
    ),
    component(
      "governance-context",
      ["LICENSE.md", "NOTICE.md", "README.md", "docs/CONTENT_POLICY.md", "docs/STATUS.md"],
      [],
      "governance-context",
      "governance-context",
      "context-document",
      "not-required",
      "scope-review-required",
    ),
    component(
      "license-texts",
      ["LICENSE", "LICENSES/AGPL-3.0-only.txt"],
      [],
      "license-text",
      "license-texts",
      "not-applicable",
      "not-required",
      "not-applicable",
    ),
    component(
      "server-dependency-lock",
      ["backend/package-lock.json"],
      [],
      "dependency-install-metadata",
      "third-party",
      "generated-install-metadata",
      "not-required",
      "component-record-required",
    ),
    component(
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
      [],
      "build-and-verification-source",
      "shared-build-tooling",
      "preferred-editable",
      "not-required",
      "scope-review-required",
    ),
  ];
}

function deferred() {
  const values = [
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
  return values.map(([id, status, blocker, requiredBefore]) => ({
    id, status, blocker, requiredBefore,
  }));
}

function securityReviews() {
  const values = [
    ["compose-membership", "container-publication"],
    ["environment-example-membership", "container-publication"],
    ["proxy-configuration-membership", "onion-publication"],
    ["tor-program-configuration-membership", "onion-publication"],
  ];
  return values.map(([id, requiredBefore]) => ({
    id,
    status: "security-review-required",
    owner: "server-security",
    requiredBefore,
  }));
}

function blockers() {
  const values = [
    ["D3", "decision-open"],
    ["D6", "publication-blocked"],
    ["D7", "publication-blocked"],
    ["D9", "decision-open"],
    ["R1-04", "publication-blocked"],
    ["R1.1B2", "corresponding-source-incomplete"],
    ["R1.1B3", "corresponding-source-incomplete"],
    ["R1.1C", "publication-blocked"],
    ["R1.1D", "publication-blocked"],
    ["security-membership-review", "publication-blocked"],
    ["third-party-records", "publication-blocked"],
  ];
  return values.map(([id, impact]) => ({ id, status: "open", impact }));
}

export function buildSyntheticPublicSourceManifestBytes() {
  const value = {
    schemaVersion: 1,
    artifactKind: "public-code-corresponding-source",
    selectionBasis: "git-commit-tree",
    policyProfile: "public-source-foundation-v1",
    licenseScopes: licenseScopes(),
    components: components(),
    deferred: deferred(),
    securityReviewRequired: securityReviews(),
    blockers: blockers(),
  };
  return Buffer.from(JSON.stringify(value, null, 2) + "\n", "utf8");
}

function gitEnvironment(git) {
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
  return environment;
}

function runGit(git, repo, args, input = undefined) {
  const result = spawnSync(
    git.path,
    ["--no-replace-objects", "-C", repo, ...args],
    {
      encoding: null,
      env: gitEnvironment(git),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) failVector();
  return result.stdout;
}

async function writeSyntheticFile(repo, relative, bytes) {
  const target = path.join(repo, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
}

async function initializeSyntheticRepository(root, git) {
  const repo = path.join(root, "source-repository");
  await mkdir(repo, { mode: 0o700 });
  runGit(git, repo, ["init"]);
  for (const [key, value] of [
    ["user.name", "Boundary Vector"],
    ["user.email", "boundary-vector@example.invalid"],
    ["commit.gpgsign", "false"],
    ["core.autocrlf", "false"],
    ["core.ignorecase", "false"],
    ["core.filemode", "true"],
    ["core.protectNTFS", "false"],
  ]) runGit(git, repo, ["config", key, value]);
  const manifestBytes = buildSyntheticPublicSourceManifestBytes();
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const exact = new Set();
  for (const item of manifest.components) {
    for (const relative of item.selectors.includeExact) exact.add(relative);
  }
  for (const relative of [...exact].sort()) {
    const bytes = relative === "developer/public-source-manifest.json"
      ? manifestBytes
      : Buffer.from("synthetic:" + relative + "\n", "utf8");
    await writeSyntheticFile(repo, relative, bytes);
  }
  runGit(git, repo, ["add", "-A"]);
  runGit(git, repo, ["commit", "-m", "synthetic boundary baseline"]);
  const commit = runGit(git, repo, ["rev-parse", "HEAD"])
    .toString("ascii").trim();
  return Object.freeze({ repo, commit });
}

function commitWithEntries(repository, baseCommit, entries, git) {
  runGit(git, repository, ["read-tree", baseCommit]);
  for (const entry of entries) {
    const objectId = runGit(
      git,
      repository,
      ["hash-object", "-w", "--stdin"],
      entry.payload,
    ).toString("ascii").trim();
    runGit(git, repository, [
      "update-index",
      "--add",
      "--cacheinfo",
      entry.mode + "," + objectId + "," + entry.path,
    ]);
  }
  const tree = runGit(git, repository, ["write-tree"]).toString("ascii").trim();
  return runGit(
    git,
    repository,
    ["commit-tree", tree, "-p", baseCommit],
    Buffer.from("synthetic vector commit\n", "ascii"),
  ).toString("ascii").trim();
}

function utf8ExactLength(length) {
  return "é".repeat(Math.floor(length / 2)) + (length % 2 === 0 ? "" : "x");
}

function prefixPath(prefixBytes, nameBytes = 1, utf8Prefix = false) {
  const fixed = Buffer.byteLength("ieltmps-source/css/", "utf8");
  const fillerLength = prefixBytes - fixed;
  const filler = utf8Prefix ? utf8ExactLength(fillerLength) : "p".repeat(fillerLength);
  return "css/" + filler + "/" + "n".repeat(nameBytes);
}

function writerEntries(vector) {
  const payloadMatch = /^payload-(0|1|511|512|513)$/u.exec(vector.caseId);
  if (payloadMatch) {
    return [{
      mode: "100644",
      path: "css/vector-payload.css",
      payload: Buffer.alloc(Number(payloadMatch[1]), 0x61),
    }];
  }
  const nameMatch = /^name-bytes-(99|100|101)$/u.exec(vector.caseId);
  if (nameMatch) {
    return [{
      mode: "100644",
      path: "css/" + "n".repeat(Number(nameMatch[1])),
      payload: Buffer.from("name-boundary\n", "ascii"),
    }];
  }
  const prefixMatch = /^prefix-bytes-(154|155|156)$/u.exec(vector.caseId);
  if (prefixMatch) {
    return [{
      mode: "100644",
      path: prefixPath(Number(prefixMatch[1])),
      payload: Buffer.from("prefix-boundary\n", "ascii"),
    }];
  }
  if (vector.caseId === "split-prefix-155-name-100") {
    return [{
      mode: "100644",
      path: prefixPath(155, 100),
      payload: Buffer.from("split-boundary\n", "ascii"),
    }];
  }
  const utf8NameMatch = /^utf8-name-bytes-(100|101)$/u.exec(vector.caseId);
  if (utf8NameMatch) {
    return [{
      mode: "100644",
      path: "css/" + utf8ExactLength(Number(utf8NameMatch[1])),
      payload: Buffer.from("utf8-name-boundary\n", "ascii"),
    }];
  }
  const utf8PrefixMatch = /^utf8-prefix-bytes-(155|156)$/u.exec(vector.caseId);
  if (utf8PrefixMatch) {
    return [{
      mode: "100644",
      path: prefixPath(Number(utf8PrefixMatch[1]), 1, true),
      payload: Buffer.from("utf8-prefix-boundary\n", "ascii"),
    }];
  }
  if (vector.caseId === "git-mode-100644" || vector.caseId === "git-mode-100755") {
    const mode = vector.caseId.slice("git-mode-".length);
    return [{
      mode,
      path: "backend/scripts/vector-mode.sh",
      payload: Buffer.from("#!/bin/sh\nexit 0\n", "ascii"),
    }];
  }
  if (vector.caseId === "ordinal-member-order") {
    return [
      { mode: "100644", path: "css/z-vector.css", payload: Buffer.from("z\n") },
      { mode: "100644", path: "css/a-vector.css", payload: Buffer.from("a\n") },
    ];
  }
  failVector(vector.vectorId);
}

async function executeWriterVector(vector, fixture, archives, git) {
  const commit = commitWithEntries(
    fixture.repo,
    fixture.commit,
    writerEntries(vector),
    git,
  );
  await loadValidatedPublicSourceMembership({ repo: fixture.repo, commit });
  const archive = path.join(archives, vector.vectorId + ".tar");
  let accepted = false;
  try {
    await preparePublicSourceArchive({ repo: fixture.repo, commit, output: archive });
    const result = await verifyPublicSourceArchive({
      repo: fixture.repo,
      commit,
      archive,
    });
    accepted = result.archiveVerified === true;
  } catch {
    accepted = false;
  }
  if (accepted !== (vector.expectedOutcome === "accept")) failVector(vector.vectorId);
  try {
    await unlink(archive);
  } catch (error) {
    if (!error || error.code !== "ENOENT") failVector(vector.vectorId);
  }
  const leftovers = await readdir(archives);
  if (leftovers.length !== 0) failVector(vector.vectorId);
}

function expectArchiveCoreRejection(operation) {
  try {
    operation();
  } catch (error) {
    return error instanceof ArchiveCoreError;
  }
  return false;
}

function executeArithmeticVector(vector) {
  let accepted = false;
  switch (vector.caseId) {
    case "padding-size-0": accepted = paddingLength(0) === 0; break;
    case "padding-size-1": accepted = paddingLength(1) === 511; break;
    case "padding-size-511": accepted = paddingLength(511) === 1; break;
    case "padding-size-512": accepted = paddingLength(512) === 0; break;
    case "padding-size-513": accepted = paddingLength(513) === 511; break;
    case "ustar-size-8589934591-header":
      accepted = encodeUstarHeader({
        relativePath: "css/vector.css",
        gitMode: "100644",
        size: MAX_USTAR_SIZE,
      }).length === BLOCK_SIZE;
      break;
    case "ustar-size-8589934592":
      accepted = !expectArchiveCoreRejection(() => encodeUstarHeader({
        relativePath: "css/vector.css",
        gitMode: "100644",
        size: MAX_USTAR_SIZE + 1,
      }));
      break;
    case "safe-add-max-safe-integer":
      accepted = safeAddLength(Number.MAX_SAFE_INTEGER - 1, 1)
        === Number.MAX_SAFE_INTEGER;
      break;
    case "safe-add-max-safe-integer-overflow":
      accepted = !expectArchiveCoreRejection(
        () => safeAddLength(Number.MAX_SAFE_INTEGER, 1),
      );
      break;
    case "virtual-zero-payload-member-count-limit": {
      const maximum = Math.floor((Number.MAX_SAFE_INTEGER - 1024) / 512);
      accepted = safeAddLength(maximum * 512, 1024) <= Number.MAX_SAFE_INTEGER;
      break;
    }
    case "virtual-zero-payload-member-count-overflow": {
      const maximum = Math.floor((Number.MAX_SAFE_INTEGER - 1024) / 512);
      accepted = !expectArchiveCoreRejection(() => safeAddLength(
        safeAddLength(maximum * 512, 512),
        1024,
      ));
      break;
    }
    default: failVector(vector.vectorId);
  }
  if (accepted !== (vector.expectedOutcome === "accept")) failVector(vector.vectorId);
}

function encodeOctal(value, width) {
  const encoded = value.toString(8);
  if (!Number.isSafeInteger(value) || value < 0 || encoded.length > width - 1) {
    failVector();
  }
  return Buffer.from(encoded.padStart(width - 1, "0") + "\0", "ascii");
}

function independentChecksum(header) {
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  let result = 0;
  for (const byte of copy) result += byte;
  return result;
}

function checksumField(value) {
  const encoded = value.toString(8);
  if (encoded.length > 6) failVector();
  return Buffer.from(encoded.padStart(6, "0") + "\0 ", "ascii");
}

function independentSplit(archivePath) {
  const full = Buffer.from(archivePath, "utf8");
  if (full.length <= 100) return { name: archivePath, prefix: "" };
  let separator = archivePath.lastIndexOf("/");
  while (separator > 0) {
    const prefix = archivePath.slice(0, separator);
    const name = archivePath.slice(separator + 1);
    if (
      Buffer.byteLength(prefix, "utf8") <= 155
      && Buffer.byteLength(name, "utf8") <= 100
    ) return { name, prefix };
    separator = archivePath.lastIndexOf("/", separator - 1);
  }
  failVector();
}

function independentHeader(archivePath, mode, size) {
  const split = independentSplit(archivePath);
  const header = Buffer.alloc(BLOCK_SIZE);
  Buffer.from(split.name, "utf8").copy(header, 0);
  encodeOctal(mode, 8).copy(header, 100);
  encodeOctal(0, 8).copy(header, 108);
  encodeOctal(0, 8).copy(header, 116);
  encodeOctal(size, 12).copy(header, 124);
  encodeOctal(0, 12).copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  Buffer.from("ustar\0", "ascii").copy(header, 257);
  Buffer.from("00", "ascii").copy(header, 263);
  encodeOctal(0, 8).copy(header, 329);
  encodeOctal(0, 8).copy(header, 337);
  Buffer.from(split.prefix, "utf8").copy(header, 345);
  checksumField(independentChecksum(header)).copy(header, 148);
  return header;
}

function independentArchive(members) {
  const chunks = [];
  for (const member of members) {
    const archivePath = member.archivePath ?? "ieltmps-source/" + member.path;
    const mode = member.mode ?? (member.gitMode === "100755" ? 0o755 : 0o644);
    const payload = member.payload ?? member.blobBytes;
    chunks.push(independentHeader(archivePath, mode, payload.length));
    chunks.push(Buffer.from(payload));
    chunks.push(Buffer.alloc((BLOCK_SIZE - (payload.length % BLOCK_SIZE)) % BLOCK_SIZE));
  }
  chunks.push(Buffer.alloc(2 * BLOCK_SIZE));
  return Buffer.concat(chunks);
}

function recordStarts(members) {
  const starts = [];
  let offset = 0;
  for (const member of members) {
    starts.push(offset);
    offset += BLOCK_SIZE + member.declaredByteSize + paddingLength(member.declaredByteSize);
  }
  return Object.freeze({ starts, terminator: offset });
}

function replaceHeaderPath(bytes, offset, archivePath) {
  const header = Buffer.from(bytes.subarray(offset, offset + BLOCK_SIZE));
  const split = independentSplit(archivePath);
  header.fill(0, USTAR_LAYOUT.name.offset, USTAR_LAYOUT.name.offset + USTAR_LAYOUT.name.length);
  header.fill(0, USTAR_LAYOUT.prefix.offset, USTAR_LAYOUT.prefix.offset + USTAR_LAYOUT.prefix.length);
  Buffer.from(split.name, "utf8").copy(header, USTAR_LAYOUT.name.offset);
  Buffer.from(split.prefix, "utf8").copy(header, USTAR_LAYOUT.prefix.offset);
  checksumField(independentChecksum(header)).copy(header, USTAR_LAYOUT.checksum.offset);
  header.copy(bytes, offset);
}

function replaceOctal(bytes, offset, field, value) {
  const header = Buffer.from(bytes.subarray(offset, offset + BLOCK_SIZE));
  encodeOctal(value, field.length).copy(header, field.offset);
  checksumField(independentChecksum(header)).copy(header, USTAR_LAYOUT.checksum.offset);
  header.copy(bytes, offset);
}

function malformedBytes(caseId, membership, unicodeMembership) {
  const members = membership.members;
  const canonical = independentArchive(members);
  const layout = recordStarts(members);
  const bytes = Buffer.from(canonical);
  switch (caseId) {
    case "canonical-zero-metadata-control": return bytes;
    case "checksum-mismatch": bytes[0] ^= 1; return bytes;
    case "equivalent-noncanonical-checksum": {
      const field = bytes.subarray(148, 154);
      const index = field.indexOf(0x30);
      if (index < 0) failVector();
      bytes[148 + index] = 0x20;
      return bytes;
    }
    case "mode-0600": replaceOctal(bytes, 0, USTAR_LAYOUT.mode, 0o600); return bytes;
    case "uid-nonzero": replaceOctal(bytes, 0, USTAR_LAYOUT.uid, 1); return bytes;
    case "gid-nonzero": replaceOctal(bytes, 0, USTAR_LAYOUT.gid, 1); return bytes;
    case "mtime-nonzero": replaceOctal(bytes, 0, USTAR_LAYOUT.mtime, 1); return bytes;
    case "devmajor-nonzero": replaceOctal(bytes, 0, USTAR_LAYOUT.devmajor, 1); return bytes;
    case "devminor-nonzero": replaceOctal(bytes, 0, USTAR_LAYOUT.devminor, 1); return bytes;
    case "payload-padding-nonzero": {
      const index = members.findIndex((member) => paddingLength(member.declaredByteSize) > 0);
      if (index < 0) failVector();
      bytes[layout.starts[index] + BLOCK_SIZE + members[index].declaredByteSize] = 1;
      return bytes;
    }
    case "terminator-zero-blocks": return bytes.subarray(0, layout.terminator);
    case "terminator-one-block": return bytes.subarray(0, layout.terminator + BLOCK_SIZE);
    case "terminator-three-blocks": return Buffer.concat([bytes, Buffer.alloc(BLOCK_SIZE)]);
    case "trailing-zero-byte": return Buffer.concat([bytes, Buffer.from([0])]);
    case "trailing-nonzero-byte": return Buffer.concat([bytes, Buffer.from([1])]);
    case "duplicate-member":
      replaceHeaderPath(bytes, layout.starts[1], "ieltmps-source/" + members[0].path);
      return bytes;
    case "out-of-order-member":
      return independentArchive([members[1], members[0], ...members.slice(2)]);
    case "case-collision":
      replaceHeaderPath(
        bytes,
        layout.starts[1],
        ("ieltmps-source/" + members[0].path).toLowerCase(),
      );
      return bytes;
    case "unicode-normalization-collision": {
      const unicodeMembers = unicodeMembership.members;
      const unicodeIndex = unicodeMembers.findIndex((member) => member.path === "css/café.css");
      if (unicodeIndex < 0 || unicodeIndex + 1 >= unicodeMembers.length) failVector();
      const unicodeBytes = Buffer.from(independentArchive(unicodeMembers));
      const unicodeLayout = recordStarts(unicodeMembers);
      replaceHeaderPath(
        unicodeBytes,
        unicodeLayout.starts[unicodeIndex + 1],
        "ieltmps-source/css/café.css".normalize("NFD"),
      );
      return unicodeBytes;
    }
    case "declared-size-plus-one":
      replaceOctal(bytes, 0, USTAR_LAYOUT.size, members[0].declaredByteSize + 1);
      return bytes;
    case "payload-truncation":
      return Buffer.concat([bytes.subarray(0, BLOCK_SIZE), bytes.subarray(BLOCK_SIZE + 1)]);
    case "same-length-payload-mutation":
      if (members[0].declaredByteSize === 0) failVector();
      bytes[BLOCK_SIZE] ^= 1;
      return bytes;
    default: failVector();
  }
}

async function executeMalformedVector(
  vector,
  fixture,
  membership,
  unicodeMembership,
  archives,
) {
  const bytes = malformedBytes(vector.caseId, membership, unicodeMembership);
  const archive = path.join(archives, vector.vectorId + ".tar");
  await writeFile(archive, bytes, { flag: "wx", mode: 0o600 });
  let accepted = false;
  try {
    const selectedMembership = vector.caseId === "unicode-normalization-collision"
      ? unicodeMembership
      : membership;
    const result = await verifyPublicSourceArchive({
      repo: fixture.repo,
      commit: selectedMembership.sourceCommit,
      archive,
    });
    accepted = result.archiveVerified === true;
  } catch {
    accepted = false;
  }
  await unlink(archive);
  if (accepted !== (vector.expectedOutcome === "accept")) failVector(vector.vectorId);
}

async function validateTemporaryParent(value) {
  const selected = value ?? path.resolve(os.tmpdir());
  if (!path.isAbsolute(selected) || path.resolve(selected) !== selected) failVector();
  const state = await lstat(selected, { bigint: true });
  if (state.isSymbolicLink() || !state.isDirectory()) failVector();
  const resolved = await realpath(selected);
  if (!pathsEqual(resolved, selected)) failVector();
  return selected;
}

async function removeVectorRoot(root, identity) {
  try {
    const state = await lstat(root, { bigint: true });
    if (
      state.isSymbolicLink()
      || !state.isDirectory()
      || state.dev !== identity.dev
      || state.ino !== identity.ino
      || !pathsEqual(await realpath(root), root)
    ) failVector();
    await rm(root, { recursive: true, force: false, maxRetries: 2 });
  } catch {
    failVector();
  }
}

export async function runPublicSourceArchiveBoundaryVectors(options = {}) {
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || Object.keys(options).some(
      (key) => !["testVectorSet", "temporaryParent", "expectedSha256"].includes(key),
    )
    || typeof options.testVectorSet !== "string"
  ) failVector();
  const authority = await validatePublicSourceArchiveBoundaryVectorSet({
    testVectorSet: options.testVectorSet,
    expectedSha256: options.expectedSha256 ?? null,
  });
  const parent = await validateTemporaryParent(options.temporaryParent);
  const git = await resolveControlledGitExecutable();
  let root = null;
  let rootIdentity = null;
  let passedCount = 0;
  try {
    root = await mkdtemp(path.join(parent, "ieltmps-boundary-vectors-"));
    root = path.resolve(root);
    const rootState = await lstat(root, { bigint: true });
    rootIdentity = { dev: rootState.dev, ino: rootState.ino };
    if (
      rootState.isSymbolicLink()
      || !rootState.isDirectory()
      || !pathsEqual(await realpath(root), root)
    ) failVector();
    const fixture = await initializeSyntheticRepository(root, git);
    const archives = path.join(root, "archives");
    await mkdir(archives, { mode: 0o700 });
    const membership = await loadValidatedPublicSourceMembership({
      repo: fixture.repo,
      commit: fixture.commit,
    });
    const unicodeCommit = commitWithEntries(
      fixture.repo,
      fixture.commit,
      [{
        mode: "100644",
        path: "css/café.css",
        payload: Buffer.from("unicode vector\n", "utf8"),
      }],
      git,
    );
    const unicodeMembership = await loadValidatedPublicSourceMembership({
      repo: fixture.repo,
      commit: unicodeCommit,
    });
    for (const vector of BOUNDARY_VECTOR_DESCRIPTORS) {
      try {
        if (vector.executionClass === "writer-verifier") {
          await executeWriterVector(vector, fixture, archives, git);
        } else if (vector.executionClass === "core-arithmetic") {
          executeArithmeticVector(vector);
        } else {
          await executeMalformedVector(
            vector,
            fixture,
            membership,
            unicodeMembership,
            archives,
          );
        }
        passedCount += 1;
      } catch (error) {
        if (error instanceof PublicSourceArchiveBoundaryVectorError) throw error;
        failVector(vector.vectorId);
      }
    }
  } finally {
    if (root !== null && rootIdentity !== null) {
      await removeVectorRoot(root, rootIdentity);
    }
  }
  if (passedCount !== BOUNDARY_VECTOR_DESCRIPTORS.length) failVector();
  return deepFreezeAdapter({
    status: "ok",
    mode: "public-source-archive-boundary-vectors",
    vectorSetKind: VECTOR_SET_KIND,
    schemaVersion: 1,
    vectorSetId: VECTOR_SET_ID,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    testVectorSetSha256: authority.sha256,
    vectorCount: BOUNDARY_VECTOR_DESCRIPTORS.length,
    passedCount,
    failedCount: 0,
    boundaryVectorSetPassed: true,
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
  const result = await runPublicSourceArchiveBoundaryVectors(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceArchiveBoundaryVectorError
      ? error
      : new PublicSourceArchiveBoundaryVectorError();
    process.stderr.write(
      "ERROR BOUNDARY_VECTOR: boundary-vector-failed"
      + (safe.vectorId ? " " + safe.vectorId : "")
      + "\n",
    );
    process.exitCode = 1;
  });
}
