#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { lstat, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

const SCHEMA_VERSION = 1;
const MANIFEST_PATH = "developer/public-source-manifest.json";
const FULL_COMMIT_PATTERN = /^[0-9a-fA-F]{40}$/u;
const OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const SURROGATE_PATTERN = /[\uD800-\uDFFF]/u;
const DRIVE_LETTER_PATTERN = /^[A-Za-z]:/u;
const URI_PREFIX_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const WINDOWS_INVALID_CHARACTER_PATTERN = /[<>:"|?*]/u;
const GIT_PATHSPEC_WILDCARD_PATTERN = /[\[\]*?]/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const MIGRATION_FILENAME_PATTERN = /^[0-9]{3}_[a-z0-9_]+\.sql$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const MAX_GIT_BUFFER = 512 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const TOP_LEVEL_KEYS = Object.freeze([
  "schemaVersion",
  "artifactKind",
  "selectionBasis",
  "policyProfile",
  "licenseScopes",
  "components",
  "deferred",
  "securityReviewRequired",
  "blockers",
]);

const EXACT_SELECTOR_CEILING = Object.freeze([
  "LICENSE",
  "LICENSE.md",
  "LICENSES/AGPL-3.0-only.txt",
  "NOTICE.md",
  "README.md",
  "api-contract/README.md",
  "backend/Dockerfile",
  "backend/package-lock.json",
  "backend/package.json",
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
  "docs/CONTENT_POLICY.md",
  "docs/STATUS.md",
  "index.html",
  "scripts/build-bundles.mjs",
  "scripts/bundle-manifest.mjs",
]);

const PREFIX_SELECTOR_CEILING = Object.freeze([
  "backend/admin/",
  "backend/auth/",
  "backend/migrations/",
  "backend/scripts/",
  "backend/src/",
  "backend/test/",
  "css/",
  "js/",
  "src/styles/",
]);

const EXACT_SELECTOR_CEILING_SET = new Set(EXACT_SELECTOR_CEILING);
const PREFIX_SELECTOR_CEILING_SET = new Set(PREFIX_SELECTOR_CEILING);

const DENIED_EXACT_PATHS = Object.freeze([
  "backend/DEPLOYMENT-RUNBOOK.md",
  "backend/docker-compose.admin-onion.override.yml",
  "backend/docker-compose.auth-onion.override.yml",
  "backend/docker-compose.bridges-encrypted.yml",
  "backend/docker-compose.business-onion.override.yml",
  "backend/docker-compose.local-browser.yml",
  "backend/docker-compose.yml",
]);

const DENIED_ROOT_PREFIXES = Object.freeze([
  ".build/",
  ".codex/",
  ".git/",
  ".github/",
  "ListeningPractice/",
  "ReadingPractice/",
  "assets/",
  "backend/admin-proxy/",
  "backend/auth-proxy/",
  "backend/business-proxy/",
  "backend/tor/",
  "dist/",
  "js/bundles/",
  "node_modules/",
  "templates/",
]);

const DENIED_PATH_COMPONENTS = Object.freeze([
  ".build",
  ".codex",
  ".git",
  ".github",
  "authorized-clients",
  "authorized_clients",
  "client-auth",
  "dist",
  "hidden-service",
  "hidden_service",
  "node_modules",
  "onion-auth",
]);

const DENIED_FILE_SUFFIXES = Object.freeze([
  ".sql.gz",
  ".tar.gz",
  ".keystore",
  ".sqlite3",
  ".backup",
  ".sqlite",
  ".dump",
  ".p12",
  ".pfx",
  ".jks",
  ".bak",
  ".dmp",
  ".db",
  ".key",
  ".pem",
  ".log",
  ".sql",
  ".tar",
  ".tgz",
  ".zip",
  ".7z",
  ".rar",
]);

const DENIED_EXACT_SET = new Set(
  DENIED_EXACT_PATHS.map((entry) => entry.toLowerCase()),
);
const DENIED_COMPONENT_SET = new Set(DENIED_PATH_COMPONENTS);

const EXPECTED_LICENSE_SCOPES = Object.freeze({
  "eligible-server-source": Object.freeze({
    id: "eligible-server-source",
    label: "GNU Affero General Public License version 3 only",
    spdx: "AGPL-3.0-only",
    status: "resolved",
  }),
  frontend: Object.freeze({
    id: "frontend",
    label: "GPLv3-family",
    spdx: null,
    status: "unresolved-exact-identifier",
    blocker: "D6",
  }),
  "governance-context": Object.freeze({
    id: "governance-context",
    label: "scope-not-finalized",
    spdx: null,
    status: "unresolved",
  }),
  "license-texts": Object.freeze({
    id: "license-texts",
    label: "legal-text-role",
    spdx: null,
    status: "not-a-license-claim",
  }),
  "shared-build-tooling": Object.freeze({
    id: "shared-build-tooling",
    label: "scope-not-finalized",
    spdx: null,
    status: "unresolved",
  }),
  "third-party": Object.freeze({
    id: "third-party",
    label: "per-component-record",
    spdx: null,
    status: "component-record-required",
  }),
});

const EXPECTED_COMPONENTS = Object.freeze({
  "eligible-server-source": Object.freeze({
    includeExact: Object.freeze([
      "api-contract/README.md",
      "backend/Dockerfile",
      "backend/package.json",
    ]),
    includePrefixes: Object.freeze([
      "backend/admin/",
      "backend/auth/",
      "backend/migrations/",
      "backend/scripts/",
      "backend/src/",
      "backend/test/",
    ]),
    pathRole: "preferred-source",
    licenseScope: "eligible-server-source",
    preferredSourceStatus: "preferred-editable",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "not-required",
    requirementStatus: "required",
  }),
  "frontend-build-tooling": Object.freeze({
    includeExact: Object.freeze([
      "scripts/build-bundles.mjs",
      "scripts/bundle-manifest.mjs",
    ]),
    includePrefixes: Object.freeze([]),
    pathRole: "build-source",
    licenseScope: "shared-build-tooling",
    preferredSourceStatus: "preferred-editable",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "not-required",
    requirementStatus: "required",
  }),
  "frontend-preferred-source": Object.freeze({
    includeExact: Object.freeze(["index.html"]),
    includePrefixes: Object.freeze(["css/", "js/", "src/styles/"]),
    pathRole: "preferred-source",
    licenseScope: "frontend",
    preferredSourceStatus: "preferred-editable",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "not-required",
    requirementStatus: "required",
  }),
  "governance-context": Object.freeze({
    includeExact: Object.freeze([
      "LICENSE.md",
      "NOTICE.md",
      "README.md",
      "docs/CONTENT_POLICY.md",
      "docs/STATUS.md",
    ]),
    includePrefixes: Object.freeze([]),
    pathRole: "governance-context",
    licenseScope: "governance-context",
    preferredSourceStatus: "context-document",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "scope-review-required",
    requirementStatus: "required",
  }),
  "license-texts": Object.freeze({
    includeExact: Object.freeze([
      "LICENSE",
      "LICENSES/AGPL-3.0-only.txt",
    ]),
    includePrefixes: Object.freeze([]),
    pathRole: "license-text",
    licenseScope: "license-texts",
    preferredSourceStatus: "not-applicable",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "not-applicable",
    requirementStatus: "required",
  }),
  "server-dependency-lock": Object.freeze({
    includeExact: Object.freeze(["backend/package-lock.json"]),
    includePrefixes: Object.freeze([]),
    pathRole: "dependency-install-metadata",
    licenseScope: "third-party",
    preferredSourceStatus: "generated-install-metadata",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "component-record-required",
    requirementStatus: "required",
  }),
  "shared-release-build-tooling": Object.freeze({
    includeExact: Object.freeze([
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
    ]),
    includePrefixes: Object.freeze([]),
    pathRole: "build-and-verification-source",
    licenseScope: "shared-build-tooling",
    preferredSourceStatus: "preferred-editable",
    securityReviewStatus: "not-required",
    rightsReviewStatus: "scope-review-required",
    requirementStatus: "required",
  }),
});

const EXPECTED_DEFERRED = Object.freeze({
  "exact-artifact-source-binding": Object.freeze({
    status: "later-phase-required",
    blocker: "R1.1C",
    requiredBefore: "corrected-static-publication",
  }),
  "frontend-exact-license-identifier": Object.freeze({
    status: "foundation-deferred",
    blocker: "D6",
    requiredBefore: "corrected-static-publication",
  }),
  "generated-bundle-convenience-decision": Object.freeze({
    status: "foundation-deferred",
    blocker: "R1.1B3",
    requiredBefore: "source-archive-publication",
  }),
  "generated-data-preferred-source": Object.freeze({
    status: "preferred-source-blocked",
    blocker: "R1.1D",
    requiredBefore: "corrected-static-publication",
  }),
  "public-content-rights": Object.freeze({
    status: "rights-review-blocked",
    blocker: "R1-04",
    requiredBefore: "corrected-static-publication",
  }),
  "security-sensitive-deployment-membership": Object.freeze({
    status: "security-review-blocked",
    blocker: "security-membership-review",
    requiredBefore: "container-or-onion-publication",
  }),
  "shared-build-tooling-license-scope": Object.freeze({
    status: "foundation-deferred",
    blocker: "R1.1B2",
    requiredBefore: "source-tree-generation",
  }),
  "source-archive-format": Object.freeze({
    status: "later-phase-required",
    blocker: "D9",
    requiredBefore: "source-archive-publication",
  }),
  "source-tree-materializer": Object.freeze({
    status: "later-phase-required",
    blocker: "R1.1B2",
    requiredBefore: "source-tree-generation",
  }),
  "templates-membership-review": Object.freeze({
    status: "rights-review-blocked",
    blocker: "D7",
    requiredBefore: "corrected-static-publication",
  }),
  "third-party-component-records": Object.freeze({
    status: "later-phase-required",
    blocker: "third-party-records",
    requiredBefore: "source-tree-generation",
  }),
});

const EXPECTED_SECURITY_REVIEWS = Object.freeze({
  "compose-membership": Object.freeze({
    status: "security-review-required",
    owner: "server-security",
    requiredBefore: "container-publication",
  }),
  "environment-example-membership": Object.freeze({
    status: "security-review-required",
    owner: "server-security",
    requiredBefore: "container-publication",
  }),
  "proxy-configuration-membership": Object.freeze({
    status: "security-review-required",
    owner: "server-security",
    requiredBefore: "onion-publication",
  }),
  "tor-program-configuration-membership": Object.freeze({
    status: "security-review-required",
    owner: "server-security",
    requiredBefore: "onion-publication",
  }),
});

const EXPECTED_CORE_BLOCKERS = Object.freeze({
  D3: "decision-open",
  D6: "publication-blocked",
  D7: "publication-blocked",
  D9: "decision-open",
  "R1-04": "publication-blocked",
  "R1.1B2": "corresponding-source-incomplete",
  "R1.1B3": "corresponding-source-incomplete",
  "R1.1C": "publication-blocked",
  "R1.1D": "publication-blocked",
  "security-membership-review": "publication-blocked",
  "third-party-records": "publication-blocked",
});

const CORRESPONDING_SOURCE_BLOCKERS = new Set([
  "D6",
  "R1-04",
  "R1.1B2",
  "R1.1B3",
  "R1.1C",
  "R1.1D",
  "security-membership-review",
  "third-party-records",
]);

const PUBLICATION_BLOCKERS = new Set([
  "D6",
  "D7",
  "R1-04",
  "R1.1B2",
  "R1.1B3",
  "R1.1C",
  "R1.1D",
  "security-membership-review",
  "third-party-records",
]);

const DEFERRED_STATUSES = new Set([
  "foundation-deferred",
  "rights-review-blocked",
  "preferred-source-blocked",
  "security-review-blocked",
  "later-phase-required",
]);
const BLOCKER_STATUSES = new Set(["open", "resolved"]);
const BLOCKER_IMPACTS = new Set([
  "decision-open",
  "corresponding-source-incomplete",
  "publication-blocked",
]);
const COMPONENT_KEYS = Object.freeze([
  "id",
  "selectors",
  "pathRole",
  "licenseScope",
  "preferredSourceStatus",
  "securityReviewStatus",
  "rightsReviewStatus",
  "requirementStatus",
]);

function fail(message) {
  throw new Error(message);
}

function failPath(relativePath, message) {
  fail(relativePath + ": " + message);
}

function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function arraysEqual(left, right) {
  return left.length === right.length
    && left.every((entry, index) => entry === right[index]);
}

function canonicalNativePath(value) {
  const normalized = path.resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isInside(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(".." + path.sep)
    && !path.isAbsolute(relative);
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(label + " must be a JSON object");
  }
}

function assertExactKeys(value, expectedKeys, label) {
  const actual = Object.keys(value).sort(compareOrdinal);
  const expected = [...expectedKeys].sort(compareOrdinal);
  if (!arraysEqual(actual, expected)) {
    fail(label + " must contain exactly: " + expected.join(", "));
  }
}

function validateIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    fail(label + " must be a path-free identifier");
  }
  return value;
}

function rejectHostPathLeaks(value, label = "manifest") {
  if (typeof value === "string") {
    if (CONTROL_CHARACTER_PATTERN.test(value) || SURROGATE_PATTERN.test(value)) {
      fail(label + " contains a control character or unpaired surrogate");
    }
    if (
      /^[A-Za-z]:[\\/]/u.test(value)
      || value.startsWith("/")
      || value.startsWith("\\\\")
      || /^file:/iu.test(value)
    ) {
      fail(label + " contains an absolute host-path value");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectHostPathLeaks(entry, label + "[" + index + "]"));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      rejectHostPathLeaks(entry, label + "." + key);
    }
  }
}

function validateRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(label + " must be a non-empty relative path");
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    fail(label + " contains a control character");
  }
  if (SURROGATE_PATTERN.test(value)) {
    fail(label + " contains an unpaired Unicode surrogate");
  }
  if (value.includes("\\")) {
    fail(label + " must use '/' separators");
  }
  if (
    value.startsWith("/")
    || DRIVE_LETTER_PATTERN.test(value)
    || path.posix.isAbsolute(value)
    || URI_PREFIX_PATTERN.test(value)
  ) {
    fail(label + " must be relative and must not use a drive or URI prefix");
  }
  if (GIT_PATHSPEC_WILDCARD_PATTERN.test(value)) {
    fail(label + " must not contain a Git pathspec wildcard");
  }
  if (value.endsWith("/") || path.posix.normalize(value) !== value) {
    fail(label + " is not a normalized file path");
  }

  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    fail(label + " contains an empty, '.' or '..' segment");
  }
  for (const segment of segments) {
    if (WINDOWS_INVALID_CHARACTER_PATTERN.test(segment)) {
      fail(label + " contains a non-portable Windows or ADS character");
    }
    if (segment.endsWith(".") || segment.endsWith(" ")) {
      fail(label + " contains a trailing dot or space segment");
    }
    if (WINDOWS_RESERVED_NAME_PATTERN.test(segment)) {
      fail(label + " contains a reserved Windows device name");
    }
  }
  return value;
}

function validatePrefix(value, label) {
  if (typeof value !== "string" || !value.endsWith("/") || value === "/") {
    fail(label + " must be a non-root directory prefix ending in '/'");
  }
  validateRelativePath(value.slice(0, -1), label);
  return value;
}

function portableIdentity(value) {
  return value.normalize("NFC").toLowerCase();
}

function validateSortedPathArray(value, label, validator) {
  if (!Array.isArray(value)) {
    fail(label + " must be an array");
  }
  const exact = new Set();
  const portable = new Set();
  let previous = null;
  const checked = value.map((entry, index) => {
    const validated = validator(entry, label + "[" + index + "]");
    const folded = portableIdentity(validated);
    if (exact.has(validated) || portable.has(folded)) {
      fail(label + " contains a duplicate or portable-colliding value: " + validated);
    }
    if (previous !== null && compareOrdinal(previous, validated) >= 0) {
      fail(label + " must be in deterministic ordinal order");
    }
    exact.add(validated);
    portable.add(folded);
    previous = validated;
    return validated;
  });
  return Object.freeze(checked);
}

function isMigrationException(relativePath) {
  const prefix = "backend/migrations/";
  if (!relativePath.startsWith(prefix)) {
    return false;
  }
  const fileName = relativePath.slice(prefix.length);
  return !fileName.includes("/") && MIGRATION_FILENAME_PATTERN.test(fileName);
}

function mandatoryDenial(relativePath) {
  const folded = relativePath.toLowerCase();
  if (DENIED_EXACT_SET.has(folded)) {
    return { kind: "root-or-component", reason: "forbidden exact path" };
  }
  for (const deniedPrefix of DENIED_ROOT_PREFIXES) {
    const deniedFolded = deniedPrefix.toLowerCase();
    if (
      folded === deniedFolded.slice(0, -1)
      || folded.startsWith(deniedFolded)
    ) {
      return { kind: "root-or-component", reason: "forbidden root or prefix" };
    }
  }
  const components = folded.split("/");
  if (components.some((component) => DENIED_COMPONENT_SET.has(component))) {
    return { kind: "root-or-component", reason: "forbidden path component" };
  }
  const fileName = components.at(-1);
  if (fileName === ".env" || fileName.startsWith(".env.")) {
    return { kind: "suffix", reason: "environment-file family is forbidden" };
  }
  if (DENIED_FILE_SUFFIXES.some((suffix) => fileName.endsWith(suffix))) {
    return { kind: "suffix", reason: "forbidden file family" };
  }
  return null;
}

function validateSelectorCeilings(includeExact, includePrefixes, componentId) {
  for (const relativePath of includeExact) {
    const denial = mandatoryDenial(relativePath);
    if (denial && !(denial.kind === "suffix" && isMigrationException(relativePath))) {
      failPath(relativePath, "component " + componentId + " selector is mandatorily denied");
    }
    if (!EXACT_SELECTOR_CEILING_SET.has(relativePath)) {
      failPath(relativePath, "exact selector is outside the code-owned exact ceiling");
    }
  }
  for (const prefix of includePrefixes) {
    const denial = mandatoryDenial(prefix.slice(0, -1));
    if (denial) {
      failPath(prefix, "component " + componentId + " prefix is mandatorily denied");
    }
    if (!PREFIX_SELECTOR_CEILING_SET.has(prefix)) {
      failPath(prefix, "prefix selector is outside the code-owned prefix ceiling");
    }
  }
}

function validateRecordIds(records, label) {
  if (!Array.isArray(records)) {
    fail(label + " must be an array");
  }
  const ids = new Set();
  const portableIds = new Set();
  let previous = null;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    assertPlainObject(record, label + "[" + index + "]");
    const id = validateIdentifier(record.id, label + "[" + index + "].id");
    const folded = portableIdentity(id);
    if (ids.has(id) || portableIds.has(folded)) {
      fail(label + " contains a duplicate or portable-colliding id: " + id);
    }
    if (previous !== null && compareOrdinal(previous, id) >= 0) {
      fail(label + " must be in deterministic ordinal id order");
    }
    ids.add(id);
    portableIds.add(folded);
    previous = id;
  }
  return ids;
}

function validateLicenseScopes(records) {
  const ids = validateRecordIds(records, "licenseScopes");
  const expectedIds = Object.keys(EXPECTED_LICENSE_SCOPES).sort(compareOrdinal);
  if (!arraysEqual([...ids].sort(compareOrdinal), expectedIds)) {
    fail("licenseScopes must define exactly the approved B1 scope ids");
  }
  const scopes = new Map();
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const expected = EXPECTED_LICENSE_SCOPES[record.id];
    if (record.id === "frontend" && record.spdx !== null) {
      fail("frontend exact SPDX identifier must remain null while D6 is unresolved");
    }
    assertExactKeys(record, Object.keys(expected), "licenseScopes[" + index + "]");
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (record[key] !== expectedValue) {
        fail("license scope " + record.id + " has an invalid " + key + " value");
      }
    }
    scopes.set(record.id, Object.freeze({ ...record }));
  }
  return scopes;
}

function selectorsOverlap(components) {
  const exact = [];
  const prefixes = [];
  for (const component of components) {
    for (const relativePath of component.selectors.includeExact) {
      exact.push({ path: relativePath, component: component.id });
    }
    for (const prefix of component.selectors.includePrefixes) {
      prefixes.push({ path: prefix, component: component.id });
    }
  }
  for (let leftIndex = 0; leftIndex < exact.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < exact.length; rightIndex += 1) {
      if (portableIdentity(exact[leftIndex].path) === portableIdentity(exact[rightIndex].path)) {
        fail("component exact selectors overlap: " + exact[leftIndex].path);
      }
    }
  }
  for (let leftIndex = 0; leftIndex < prefixes.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < prefixes.length; rightIndex += 1) {
      const left = portableIdentity(prefixes[leftIndex].path);
      const right = portableIdentity(prefixes[rightIndex].path);
      if (left.startsWith(right) || right.startsWith(left)) {
        fail("component prefix selectors overlap: " + prefixes[leftIndex].path);
      }
    }
  }
  for (const exactEntry of exact) {
    for (const prefixEntry of prefixes) {
      if (portableIdentity(exactEntry.path).startsWith(portableIdentity(prefixEntry.path))) {
        fail("component exact and prefix selectors overlap: " + exactEntry.path);
      }
    }
  }
}

function validateComponents(records, licenseScopes) {
  const ids = validateRecordIds(records, "components");
  const expectedIds = Object.keys(EXPECTED_COMPONENTS).sort(compareOrdinal);
  if (!arraysEqual([...ids].sort(compareOrdinal), expectedIds)) {
    fail("components must define exactly the approved B1 component ids");
  }

  const components = [];
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.requirementStatus === "required" && !record.licenseScope) {
      fail("required component " + record.id + " has no license scope");
    }
    assertExactKeys(record, COMPONENT_KEYS, "components[" + index + "]");
    assertPlainObject(record.selectors, "components[" + index + "].selectors");
    assertExactKeys(
      record.selectors,
      ["includeExact", "includePrefixes"],
      "components[" + index + "].selectors",
    );
    const includeExact = validateSortedPathArray(
      record.selectors.includeExact,
      "components[" + index + "].selectors.includeExact",
      validateRelativePath,
    );
    const includePrefixes = validateSortedPathArray(
      record.selectors.includePrefixes,
      "components[" + index + "].selectors.includePrefixes",
      validatePrefix,
    );
    validateSelectorCeilings(includeExact, includePrefixes, record.id);
    if (!licenseScopes.has(record.licenseScope)) {
      fail("component " + record.id + " uses unknown license scope: " + record.licenseScope);
    }

    const expected = EXPECTED_COMPONENTS[record.id];
    if (
      !arraysEqual(includeExact, expected.includeExact)
      || !arraysEqual(includePrefixes, expected.includePrefixes)
    ) {
      fail("component " + record.id + " selectors do not match the approved B1 definition");
    }
    for (const key of [
      "pathRole",
      "licenseScope",
      "preferredSourceStatus",
      "securityReviewStatus",
      "rightsReviewStatus",
      "requirementStatus",
    ]) {
      if (record[key] !== expected[key]) {
        fail("component " + record.id + " has an invalid " + key + " value");
      }
    }
    components.push(Object.freeze({
      ...record,
      selectors: Object.freeze({ includeExact, includePrefixes }),
    }));
  }
  selectorsOverlap(components);
  return Object.freeze(components);
}

function validateDeferred(records) {
  const ids = validateRecordIds(records, "deferred");
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    assertExactKeys(record, ["id", "status", "blocker", "requiredBefore"], "deferred[" + index + "]");
    if (!DEFERRED_STATUSES.has(record.status)) {
      fail("deferred category " + record.id + " cannot be marked complete or use an unknown status");
    }
    validateIdentifier(record.blocker, "deferred[" + index + "].blocker");
    validateIdentifier(record.requiredBefore, "deferred[" + index + "].requiredBefore");
  }
  for (const [id, expected] of Object.entries(EXPECTED_DEFERRED)) {
    if (!ids.has(id)) {
      fail("missing required deferred category: " + id);
    }
    const record = records.find((entry) => entry.id === id);
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (record[key] !== expectedValue) {
        fail("deferred category " + id + " has an invalid " + key + " value");
      }
    }
  }
  return Object.freeze(records.map((record) => Object.freeze({ ...record })));
}

function validateSecurityReviews(records) {
  const selectionFields = new Set([
    "path",
    "paths",
    "selectors",
    "includeExact",
    "includePrefixes",
  ]);
  for (const record of records) {
    if (record && typeof record === "object" && !Array.isArray(record)) {
      if (Object.keys(record).some((key) => selectionFields.has(key))) {
        fail("security-review-required categories cannot select paths");
      }
    }
  }
  const ids = validateRecordIds(records, "securityReviewRequired");
  const expectedIds = Object.keys(EXPECTED_SECURITY_REVIEWS).sort(compareOrdinal);
  if (!arraysEqual([...ids].sort(compareOrdinal), expectedIds)) {
    fail("securityReviewRequired must define exactly the approved generic category ids");
  }
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    assertExactKeys(
      record,
      ["id", "status", "owner", "requiredBefore"],
      "securityReviewRequired[" + index + "]",
    );
    const expected = EXPECTED_SECURITY_REVIEWS[record.id];
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (record[key] !== expectedValue) {
        fail("security review category " + record.id + " has an invalid " + key + " value");
      }
    }
  }
  return Object.freeze(records.map((record) => Object.freeze({ ...record })));
}

function validateBlockers(records) {
  const ids = validateRecordIds(records, "blockers");
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    assertExactKeys(record, ["id", "status", "impact"], "blockers[" + index + "]");
    if (!BLOCKER_STATUSES.has(record.status)) {
      fail("blocker " + record.id + " has an invalid status");
    }
    if (!BLOCKER_IMPACTS.has(record.impact)) {
      fail("blocker " + record.id + " has an invalid impact");
    }
  }
  for (const [id, expectedImpact] of Object.entries(EXPECTED_CORE_BLOCKERS)) {
    if (!ids.has(id)) {
      fail("missing required B1 blocker: " + id);
    }
    const record = records.find((entry) => entry.id === id);
    if (record.status !== "open" || record.impact !== expectedImpact) {
      fail("required B1 blocker " + id + " must remain open with its approved impact");
    }
  }
  return Object.freeze(records.map((record) => Object.freeze({ ...record })));
}

function deriveCompleteness(blockers, deferred, securityReviews) {
  const activeIds = new Set(
    blockers.filter((record) => record.status === "open").map((record) => record.id),
  );
  const correspondingSourceComplete = ![...activeIds].some(
    (id) => CORRESPONDING_SOURCE_BLOCKERS.has(id),
  ) && deferred.length === 0;
  const publicationBlocked = [...activeIds].some(
    (id) => PUBLICATION_BLOCKERS.has(id),
  ) || securityReviews.length > 0;
  if (correspondingSourceComplete) {
    fail("B1 policy cannot claim correspondingSourceComplete: true");
  }
  if (!publicationBlocked) {
    fail("B1 policy cannot claim publicationBlocked: false while blockers remain");
  }
  return Object.freeze({ correspondingSourceComplete, publicationBlocked });
}

function validateManifest(value) {
  assertPlainObject(value, "public source manifest");
  rejectHostPathLeaks(value);
  for (const forbiddenKey of ["license", "spdx", "artifactLicense", "licenseExpression"]) {
    if (Object.hasOwn(value, forbiddenKey)) {
      fail("whole-artifact license or AGPL claims are forbidden in the B1 manifest");
    }
  }
  assertExactKeys(value, TOP_LEVEL_KEYS, "public source manifest");
  if (value.schemaVersion !== SCHEMA_VERSION) {
    fail("unsupported public source manifest schemaVersion");
  }
  if (value.artifactKind !== "public-code-corresponding-source") {
    fail("invalid artifactKind");
  }
  if (value.selectionBasis !== "git-commit-tree") {
    fail("invalid selectionBasis");
  }
  if (value.policyProfile !== "public-source-foundation-v1") {
    fail("invalid policyProfile");
  }

  const licenseScopes = validateLicenseScopes(value.licenseScopes);
  const components = validateComponents(value.components, licenseScopes);
  const deferred = validateDeferred(value.deferred);
  const securityReviewRequired = validateSecurityReviews(value.securityReviewRequired);
  const blockers = validateBlockers(value.blockers);
  const blockerIds = new Set(blockers.map((record) => record.id));
  for (const record of deferred) {
    if (!blockerIds.has(record.blocker)) {
      fail("deferred category " + record.id + " references an unknown blocker");
    }
  }
  const completeness = deriveCompleteness(blockers, deferred, securityReviewRequired);
  return Object.freeze({
    licenseScopes,
    components,
    deferred,
    securityReviewRequired,
    blockers,
    completeness,
  });
}

function parseOptions(argv) {
  const valueOptions = new Set(["--repo", "--commit", "--output"]);
  const values = new Map();
  let mode = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--policy-only" || argument === "--dry-run-report") {
      if (mode !== null) {
        fail("exactly one of --policy-only or --dry-run-report is required");
      }
      mode = argument;
      continue;
    }
    if (!valueOptions.has(argument) || index + 1 >= argv.length || values.has(argument)) {
      fail("invalid or duplicate argument: " + String(argument));
    }
    values.set(argument, argv[index + 1]);
    index += 1;
  }
  if (mode === null) {
    fail("exactly one of --policy-only or --dry-run-report is required");
  }
  for (const required of ["--repo", "--commit"]) {
    if (!values.has(required)) {
      fail("missing required argument: " + required);
    }
  }
  if (mode === "--dry-run-report" && !values.has("--output")) {
    fail("--dry-run-report requires --output");
  }
  if (mode === "--policy-only" && values.has("--output")) {
    fail("--output is only valid with --dry-run-report");
  }
  return Object.freeze({ mode, values });
}

function sanitizedGitEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) {
      environment[key] = value;
    }
  }
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LC_ALL = "C";
  environment.LANG = "C";
  return environment;
}

function runGit(repoRoot, args, { input = undefined } = {}) {
  const result = spawnSync(
    "git",
    ["--no-replace-objects", "-C", repoRoot, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error) {
    fail("git execution failed: " + result.error.message);
  }
  if (result.status !== 0) {
    const firstError = result.stderr
      ? result.stderr.toString("utf8").trim().split(/\r?\n/u)[0]
      : "";
    fail("git " + args[0] + " failed" + (firstError ? ": " + firstError : ""));
  }
  return result;
}

async function pathState(targetPath) {
  try {
    return await lstat(targetPath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function assertNoReparseDirectory(targetPath, label) {
  const state = await pathState(targetPath);
  if (!state) {
    fail(label + " is missing");
  }
  if (state.isSymbolicLink() || !state.isDirectory()) {
    fail(label + " must be a regular non-reparse directory");
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(label + " resolves through a symlink, junction, or reparse point");
  }
}

async function validateRepository(repoArgument) {
  if (!path.isAbsolute(repoArgument)) {
    fail("--repo must be an absolute path");
  }
  const repoRoot = path.resolve(repoArgument);
  await assertNoReparseDirectory(repoRoot, "repository root");
  const result = runGit(repoRoot, ["rev-parse", "--show-toplevel"]);
  const reportedRoot = result.stdout.toString("utf8").trim();
  if (canonicalNativePath(reportedRoot) !== canonicalNativePath(repoRoot)) {
    fail("--repo must name the exact Git worktree root");
  }
  return repoRoot;
}

function validateOriginalCommit(repoRoot, value) {
  if (typeof value !== "string" || !FULL_COMMIT_PATTERN.test(value)) {
    fail("--commit must be a full 40-hex commit id");
  }
  const sourceCommit = value.toLowerCase();
  const type = runGit(repoRoot, ["cat-file", "-t", sourceCommit])
    .stdout.toString("ascii").trim();
  if (type !== "commit") {
    fail("--commit must identify an original commit object");
  }
  return sourceCommit;
}

function splitNullRecords(buffer, label) {
  const records = [];
  let offset = 0;
  while (offset < buffer.length) {
    const end = buffer.indexOf(0, offset);
    if (end === -1) {
      fail(label + " returned a non-NUL-terminated record");
    }
    if (end > offset) {
      records.push(buffer.subarray(offset, end));
    }
    offset = end + 1;
  }
  return records;
}

function decodeGitPath(bytes) {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch (error) {
    fail("Git tree contains a path that is not valid UTF-8: " + error.message);
  }
}

function parseTreeEntries(buffer) {
  const entries = [];
  const seen = new Set();
  for (const record of splitNullRecords(buffer, "git ls-tree")) {
    const tab = record.indexOf(0x09);
    if (tab < 0) {
      fail("git ls-tree returned a malformed entry");
    }
    const header = record.subarray(0, tab).toString("ascii");
    const parts = header.split(" ");
    if (parts.length !== 3) {
      fail("git ls-tree returned a malformed header");
    }
    const [mode, type, objectId] = parts;
    if (!OBJECT_ID_PATTERN.test(objectId)) {
      fail("git ls-tree returned an invalid object id");
    }
    const relativePath = validateRelativePath(
      decodeGitPath(record.subarray(tab + 1)),
      "Git tree path",
    );
    if (seen.has(relativePath)) {
      failPath(relativePath, "duplicate normalized Git tree path");
    }
    seen.add(relativePath);
    entries.push(Object.freeze({ mode, type, objectId, path: relativePath }));
  }
  return entries;
}

function readTreeEntries(repoRoot, sourceCommit, pathspecs) {
  if (!Array.isArray(pathspecs) || pathspecs.length === 0) {
    fail("internal error: targeted Git tree enumeration requires pathspecs");
  }
  const result = runGit(repoRoot, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    sourceCommit,
    "--",
    ...pathspecs,
  ]);
  return parseTreeEntries(result.stdout);
}

function readGitBlobs(repoRoot, objectIds) {
  const requestedIds = [...new Set(objectIds)];
  if (requestedIds.length === 0) {
    return new Map();
  }
  for (const objectId of requestedIds) {
    if (!OBJECT_ID_PATTERN.test(objectId)) {
      fail("invalid Git blob id requested");
    }
  }
  const result = runGit(
    repoRoot,
    ["cat-file", "--batch"],
    { input: Buffer.from(requestedIds.join("\n") + "\n", "ascii") },
  );
  const blobs = new Map();
  let offset = 0;
  for (const requestedId of requestedIds) {
    const headerEnd = result.stdout.indexOf(0x0a, offset);
    if (headerEnd < 0) {
      fail("git cat-file returned a truncated header");
    }
    const parts = result.stdout.subarray(offset, headerEnd).toString("ascii").split(" ");
    if (parts.length !== 3) {
      fail("git cat-file returned a malformed header");
    }
    const [actualId, type, sizeText] = parts;
    const size = Number(sizeText);
    if (
      actualId !== requestedId
      || type !== "blob"
      || !Number.isSafeInteger(size)
      || size < 0
    ) {
      fail("git cat-file returned an unexpected object for " + requestedId);
    }
    const contentStart = headerEnd + 1;
    const contentEnd = contentStart + size;
    if (contentEnd >= result.stdout.length || result.stdout[contentEnd] !== 0x0a) {
      fail("git cat-file returned truncated blob bytes for " + requestedId);
    }
    const blobBytes = Buffer.from(
      result.stdout.subarray(contentStart, contentEnd),
    );
    if (blobBytes.length !== size) {
      fail("git cat-file returned an inconsistent declared blob size");
    }
    blobs.set(requestedId, Object.freeze({
      declaredByteSize: size,
      blobBytes,
    }));
    offset = contentEnd + 1;
  }
  if (offset !== result.stdout.length) {
    fail("git cat-file returned unexpected trailing output");
  }
  return blobs;
}

function loadCommitOwnedManifest(repoRoot, sourceCommit) {
  const entries = readTreeEntries(repoRoot, sourceCommit, [MANIFEST_PATH]);
  if (entries.length !== 1 || entries[0].path !== MANIFEST_PATH) {
    fail("selected commit does not contain the fixed manifest: " + MANIFEST_PATH);
  }
  const entry = entries[0];
  if (
    (entry.mode !== "100644" && entry.mode !== "100755")
    || entry.type !== "blob"
  ) {
    fail("selected commit manifest must be a regular Git blob");
  }
  const manifestBlob = readGitBlobs(repoRoot, [entry.objectId]).get(entry.objectId);
  if (!manifestBlob) {
    fail("selected commit manifest blob was not loaded");
  }
  const manifestBytes = manifestBlob.blobBytes;
  if (manifestBytes.length !== manifestBlob.declaredByteSize) {
    fail("selected commit manifest blob size validation failed");
  }
  let text;
  try {
    text = UTF8_DECODER.decode(manifestBytes);
  } catch (error) {
    fail("public source manifest is not valid UTF-8: " + error.message);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail("public source manifest is not valid JSON: " + error.message);
  }
  return Object.freeze({
    manifest: validateManifest(value),
    manifestSha256: sha256Bytes(manifestBytes),
  });
}

function isWithinCodeOwnedCeiling(relativePath) {
  return EXACT_SELECTOR_CEILING_SET.has(relativePath)
    || PREFIX_SELECTOR_CEILING.some((prefix) => relativePath.startsWith(prefix));
}

function matchingComponents(components, relativePath) {
  return components.filter((component) => (
    component.selectors.includeExact.includes(relativePath)
    || component.selectors.includePrefixes.some(
      (prefix) => relativePath.startsWith(prefix),
    )
  ));
}

function registerPortableMemberPath(relativePath, registry) {
  const segments = relativePath.split("/");
  let current = "";
  for (let index = 0; index < segments.length; index += 1) {
    current = current ? current + "/" + segments[index] : segments[index];
    const kind = index === segments.length - 1 ? "file" : "directory";
    const identities = [
      "case:" + current.toLowerCase(),
      "nfc:" + current.normalize("NFC"),
      "nfd:" + current.normalize("NFD"),
      "portable:" + portableIdentity(current),
    ];
    for (const identity of identities) {
      const existing = registry.get(identity);
      if (existing) {
        if (
          existing.path !== current
          || existing.kind !== kind
          || kind === "file"
        ) {
          failPath(relativePath, "duplicate, case-insensitive, or Unicode-normalization collision");
        }
      } else {
        registry.set(identity, { path: current, kind });
      }
    }
  }
}

function validateSelectedMode(entry) {
  if (entry.mode === "120000") {
    failPath(entry.path, "selected Git symlink is forbidden");
  }
  if (entry.mode === "160000" || entry.type === "commit") {
    failPath(entry.path, "selected Git gitlink is forbidden");
  }
  if (
    (entry.mode !== "100644" && entry.mode !== "100755")
    || entry.type !== "blob"
  ) {
    failPath(entry.path, "selected entry must be a regular 100644 or 100755 Git blob");
  }
}

function enumerateMembership(repoRoot, sourceCommit, manifest) {
  const selected = new Map();
  const portableRegistry = new Map();

  for (const component of manifest.components) {
    const pathspecs = [
      ...component.selectors.includeExact,
      ...component.selectors.includePrefixes,
    ];
    const entries = readTreeEntries(repoRoot, sourceCommit, pathspecs);
    const foundExact = new Set();

    for (const entry of entries) {
      const exactMatch = component.selectors.includeExact.includes(entry.path);
      const prefixMatch = component.selectors.includePrefixes.some(
        (prefix) => entry.path.startsWith(prefix),
      );
      if (!exactMatch && !prefixMatch) {
        failPath(entry.path, "targeted Git pathspec returned an unexpected path");
      }

      // Path safety is applied while parsing ls-tree. Mandatory roots and
      // components precede suffixes, the immutable migration exception,
      // the code-owned ceiling, and finally commit-owned selection.
      const denial = mandatoryDenial(entry.path);
      if (denial && denial.kind === "root-or-component") {
        if (exactMatch) {
          failPath(entry.path, denial.reason);
        }
        continue;
      }
      if (denial && !(denial.kind === "suffix" && isMigrationException(entry.path))) {
        failPath(entry.path, denial.reason);
      }
      if (!isWithinCodeOwnedCeiling(entry.path)) {
        failPath(entry.path, "selected path is outside the code-owned membership ceiling");
      }

      const owners = matchingComponents(manifest.components, entry.path);
      if (owners.length !== 1 || owners[0].id !== component.id) {
        failPath(entry.path, "selected member must resolve to exactly one component");
      }
      if (isMigrationException(entry.path) && component.id !== "eligible-server-source") {
        failPath(entry.path, "migration SQL exception is restricted to eligible server source");
      }

      validateSelectedMode(entry);
      registerPortableMemberPath(entry.path, portableRegistry);
      if (selected.has(entry.path)) {
        failPath(entry.path, "duplicate selected member");
      }
      if (exactMatch) {
        foundExact.add(entry.path);
      }
      selected.set(entry.path, Object.freeze({
        ...entry,
        role: component.pathRole,
        licenseScope: component.licenseScope,
      }));
    }

    const missing = component.selectors.includeExact.filter(
      (relativePath) => !foundExact.has(relativePath),
    );
    if (missing.length > 0) {
      fail(
        "required exact members are missing or denied for component "
        + component.id + ": " + missing.join(", "),
      );
    }
  }

  const ordered = [...selected.values()].sort(
    (left, right) => compareOrdinal(left.path, right.path),
  );
  const blobs = readGitBlobs(repoRoot, ordered.map((entry) => entry.objectId));
  return ordered.map((entry) => {
    const blob = blobs.get(entry.objectId);
    if (!blob) {
      failPath(entry.path, "selected Git blob was not loaded");
    }
    const blobBytes = Buffer.from(blob.blobBytes);
    if (blobBytes.length !== blob.declaredByteSize) {
      failPath(entry.path, "selected Git blob size validation failed");
    }
    return Object.freeze({
      path: entry.path,
      gitMode: entry.mode,
      objectId: entry.objectId,
      declaredByteSize: blob.declaredByteSize,
      sha256: sha256Bytes(blobBytes),
      role: entry.role,
      licenseScope: entry.licenseScope,
      blobBytes,
    });
  });
}

async function prepareOutputPath(repoRoot, outputArgument) {
  if (!path.isAbsolute(outputArgument)) {
    fail("--output must be an absolute path");
  }
  const outputPath = path.resolve(outputArgument);
  if (
    canonicalNativePath(outputPath) === canonicalNativePath(repoRoot)
    || isInside(repoRoot, outputPath)
  ) {
    fail("--output must be outside the repository");
  }
  const parentPath = path.dirname(outputPath);
  if (canonicalNativePath(parentPath) === canonicalNativePath(outputPath)) {
    fail("--output must not be a filesystem root");
  }
  await assertNoReparseDirectory(parentPath, "output parent directory");
  if (await pathState(outputPath)) {
    fail("output path already exists; reports are never overwritten");
  }
  return Object.freeze({ outputPath, parentPath });
}

function buildReport(sourceCommit, manifestSha256, manifest, members) {
  const rightsReviewRequired = new Set();
  for (const component of manifest.components) {
    if (!new Set(["not-required", "not-applicable"]).has(component.rightsReviewStatus)) {
      rightsReviewRequired.add(component.id);
    }
  }
  for (const record of manifest.deferred) {
    if (record.status === "rights-review-blocked") {
      rightsReviewRequired.add(record.id);
    }
  }
  const activeBlockers = manifest.blockers
    .filter((record) => record.status === "open")
    .map((record) => record.id)
    .sort(compareOrdinal);
  const publicMembers = members.map((member) => Object.freeze({
    path: member.path,
    gitMode: member.gitMode,
    sha256: member.sha256,
    role: member.role,
    licenseScope: member.licenseScope,
  }));

  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    sourceCommit,
    manifestPath: MANIFEST_PATH,
    manifestSha256,
    membershipValid: true,
    membershipCount: members.length,
    members: Object.freeze(publicMembers),
    deferredCategories: Object.freeze(
      manifest.deferred.map((record) => record.id).sort(compareOrdinal),
    ),
    securityReviewRequired: Object.freeze(
      manifest.securityReviewRequired
        .map((record) => record.id)
        .sort(compareOrdinal),
    ),
    rightsReviewRequired: Object.freeze(
      [...rightsReviewRequired].sort(compareOrdinal),
    ),
    correspondingSourceComplete: manifest.completeness.correspondingSourceComplete,
    publicationBlocked: manifest.completeness.publicationBlocked,
    blockers: Object.freeze(activeBlockers),
  });
}

function buildValidatedMembershipResult(repoRoot, sourceCommit, loaded) {
  const members = Object.freeze(
    enumerateMembership(repoRoot, sourceCommit, loaded.manifest),
  );
  const report = buildReport(
    sourceCommit,
    loaded.manifestSha256,
    loaded.manifest,
    members,
  );
  const reportBytes = Buffer.from(JSON.stringify(report, null, 2) + "\n", "utf8");
  const serialized = reportBytes.toString("utf8");
  if (serialized.includes(repoRoot) || /"[A-Za-z]:[\\/]/u.test(serialized)) {
    fail("internal report privacy validation detected an absolute host path");
  }
  return Object.freeze({
    repoRoot,
    sourceCommit,
    manifestSha256: loaded.manifestSha256,
    report,
    reportBytes,
    members,
  });
}

export async function loadValidatedPublicSourceMembership({ repo, commit } = {}) {
  const repoRoot = await validateRepository(repo);
  const sourceCommit = validateOriginalCommit(repoRoot, commit);
  const loaded = loadCommitOwnedManifest(repoRoot, sourceCommit);
  return buildValidatedMembershipResult(repoRoot, sourceCommit, loaded);
}

async function writeReportAtomically(output, reportBytes) {
  const temporaryPath = path.join(
    output.parentPath,
    "." + path.basename(output.outputPath)
      + ".tmp-" + process.pid + "-" + randomBytes(8).toString("hex"),
  );
  let temporaryExists = false;
  try {
    await writeFile(temporaryPath, reportBytes, { flag: "wx", mode: 0o600 });
    temporaryExists = true;
    if (await pathState(output.outputPath)) {
      fail("output path appeared during report generation; refusing to overwrite it");
    }
    await rename(temporaryPath, output.outputPath);
    temporaryExists = false;
  } finally {
    if (temporaryExists) {
      try {
        await unlink(temporaryPath);
      } catch (error) {
        if (!error || error.code !== "ENOENT") {
          throw error;
        }
      }
    }
  }
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const repoRoot = await validateRepository(options.values.get("--repo"));
  const sourceCommit = validateOriginalCommit(repoRoot, options.values.get("--commit"));
  const loaded = loadCommitOwnedManifest(repoRoot, sourceCommit);

  if (options.mode === "--policy-only") {
    process.stdout.write(JSON.stringify({
      status: "ok",
      mode: "policy-only",
      sourceCommit,
      manifestSha256: loaded.manifestSha256,
      policyValid: true,
      membershipValidated: false,
      correspondingSourceComplete: loaded.manifest.completeness.correspondingSourceComplete,
      publicationBlocked: loaded.manifest.completeness.publicationBlocked,
    }) + "\n");
    return;
  }

  const output = await prepareOutputPath(repoRoot, options.values.get("--output"));
  const validated = buildValidatedMembershipResult(repoRoot, sourceCommit, loaded);
  if (validated.reportBytes.toString("utf8").includes(output.outputPath)) {
    fail("internal report privacy validation detected an absolute host path");
  }
  await writeReportAtomically(output, validated.reportBytes);
  process.stdout.write(JSON.stringify({
    status: "ok",
    mode: "dry-run-report",
    sourceCommit,
    membershipCount: validated.members.length,
    reportSha256: sha256Bytes(validated.reportBytes),
  }) + "\n");
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32"
    ? canonical.toLowerCase()
    : canonical;
}

function isMainModule() {
  const argvEntry = process.argv[1];
  if (typeof argvEntry !== "string" || argvEntry.length === 0) {
    return false;
  }
  try {
    const modulePath = fileURLToPath(import.meta.url);
    const argvPath = path.resolve(argvEntry);
    return (
      comparableCanonicalPath(modulePath) ===
      comparableCanonicalPath(argvPath)
    );
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    process.stderr.write("ERROR: " + error.message + "\n");
    process.exitCode = 1;
  });
}
