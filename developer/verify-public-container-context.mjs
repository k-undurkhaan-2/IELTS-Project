#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

const RECEIPT_SCHEMA_VERSION = 2;
const RECEIPT_NAME = ".ieltmps-public-context.json";
const MANIFEST_PATH = "developer/public-container-context-manifest.json";
const VERIFIER_PATH = "developer/verify-public-container-context.mjs";
const MAX_RECEIPT_BYTES = 16 * 1024 * 1024;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const SURROGATE_PATTERN = /[\uD800-\uDFFF]/u;
const DRIVE_LETTER_PATTERN = /^[A-Za-z]:/u;
const WINDOWS_INVALID_CHARACTER_PATTERN = /[<>:"|?*]/u;
const PORTABLE_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const REVIEWED_MIGRATION_PATTERN = /^[0-9]{3}_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const ALLOWED_EXACT_PATHS = new Set([
  ".dockerignore",
  "backend/.env.example",
  "backend/Dockerfile",
  "backend/package-lock.json",
  "backend/package.json",
  "index.html",
  VERIFIER_PATH,
]);
const ALLOWED_PREFIXES = [
  "assets/",
  "backend/admin/",
  "backend/auth/",
  "backend/migrations/",
  "backend/scripts/",
  "backend/src/",
  "css/",
  "js/",
  "src/styles/",
  "templates/",
];
const FORBIDDEN_EXACT_PATHS = new Set(["backend/deployment-runbook.md"]);
const FORBIDDEN_COMPONENTS = new Set([
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
  "listeningpractice",
  "node_modules",
  "onion-auth",
  "readingpractice",
]);
const FORBIDDEN_SUFFIXES = [
  ".sql.gz",
  ".tar.gz",
  ".sqlite3",
  ".keystore",
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
];

function fail(message) {
  throw new Error(message);
}

function failPath(relativePath, message) {
  fail(`${relativePath}: ${message}`);
}

function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalNativePath(value) {
  const normalized = path.normalize(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isInside(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function resolveInside(rootPath, relativePath) {
  const resolved = path.resolve(rootPath, ...relativePath.split("/"));
  if (!isInside(rootPath, resolved)) {
    failPath(relativePath, "path escapes the context root");
  }
  return resolved;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label}: expected a JSON object`);
  }
}

function assertExactKeys(value, expectedKeys, label) {
  const actual = Object.keys(value).sort(compareOrdinal);
  const expected = [...expectedKeys].sort(compareOrdinal);
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) {
    fail(`${label}: unexpected metadata fields`);
  }
}

function validateRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label}: expected a non-empty relative path`);
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    fail(`${label}: control characters are forbidden`);
  }
  if (SURROGATE_PATTERN.test(value)) {
    fail(`${label}: unpaired Unicode surrogates are forbidden`);
  }
  if (value.includes("\\")) {
    fail(`${label}: only '/' separators are permitted`);
  }
  if (value.startsWith("/") || DRIVE_LETTER_PATTERN.test(value) || path.posix.isAbsolute(value)) {
    fail(`${label}: absolute paths are forbidden`);
  }
  if (value.endsWith("/") || path.posix.normalize(value) !== value) {
    fail(`${label}: path is not normalized`);
  }

  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    fail(`${label}: empty, '.' and '..' segments are forbidden`);
  }
  for (const segment of segments) {
    if (WINDOWS_INVALID_CHARACTER_PATTERN.test(segment)) {
      fail(`${label}: non-portable Windows or alternate data stream character`);
    }
    if (segment.endsWith(".") || segment.endsWith(" ") || PORTABLE_RESERVED_NAME_PATTERN.test(segment)) {
      fail(`${label}: non-portable Windows path segment`);
    }
  }
  return value;
}

function structuralException(relativePath, denialKind) {
  if (denialKind === "environment" && relativePath === "backend/.env.example") {
    return true;
  }
  if (denialKind !== "suffix" || !relativePath.startsWith("backend/migrations/")) {
    return false;
  }
  const remainder = relativePath.slice("backend/migrations/".length);
  return !remainder.includes("/") && REVIEWED_MIGRATION_PATTERN.test(remainder);
}

function mandatoryDenial(relativePath) {
  const folded = relativePath.toLowerCase();
  if (FORBIDDEN_EXACT_PATHS.has(folded)) {
    return { kind: "path", reason: "forbidden exact path" };
  }
  const components = folded.split("/");
  if (components.some((component) => FORBIDDEN_COMPONENTS.has(component))) {
    return { kind: "component", reason: "forbidden root or path component" };
  }
  const fileName = components.at(-1);
  if (fileName === ".env" || fileName.startsWith(".env.")) {
    return { kind: "environment", reason: "environment-file family is forbidden" };
  }
  if (FORBIDDEN_SUFFIXES.some((suffix) => fileName.endsWith(suffix))) {
    return { kind: "suffix", reason: "forbidden file family" };
  }
  return null;
}

function validatePayloadPolicy(relativePath, label) {
  validateRelativePath(relativePath, label);
  if (relativePath === RECEIPT_NAME) {
    failPath(relativePath, "receipt must not list itself as a payload member");
  }

  const denial = mandatoryDenial(relativePath);
  if (denial && !structuralException(relativePath, denial.kind)) {
    failPath(relativePath, denial.reason);
  }

  if (!ALLOWED_EXACT_PATHS.has(relativePath)
      && !ALLOWED_PREFIXES.some((prefix) => relativePath.startsWith(prefix))) {
    failPath(relativePath, "path is outside the code-owned public ceiling");
  }
  return relativePath;
}

function parseOptions(argv) {
  let mode = null;
  const values = new Map();
  const valueOptions = new Set([
    "--context",
    "--expected-commit",
    "--expected-manifest-sha256",
    "--expected-receipt-sha256",
  ]);

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--receipt-only" || argument === "--full") {
      if (mode !== null) {
        fail("exactly one of --receipt-only or --full is required");
      }
      mode = argument;
      continue;
    }
    if (!valueOptions.has(argument) || index + 1 >= argv.length || values.has(argument)) {
      fail(`invalid or duplicate argument: ${argument}`);
    }
    values.set(argument, argv[index + 1]);
    index += 1;
  }

  if (mode === null) {
    fail("exactly one of --receipt-only or --full is required");
  }
  for (const option of valueOptions) {
    if (!values.has(option)) {
      fail(`missing required argument: ${option}`);
    }
  }
  return { mode, values };
}

function validateHex(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value.toLowerCase())) {
    fail(`${label}: invalid hexadecimal identity`);
  }
  return value.toLowerCase();
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
    fail(`${label}: directory is missing`);
  }
  if (state.isSymbolicLink() || !state.isDirectory()) {
    fail(`${label}: expected a regular non-reparse directory`);
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(`${label}: directory resolves through a symlink, junction, or reparse point`);
  }
  return state;
}

async function assertNoReparseFile(targetPath, relativePath) {
  const state = await pathState(targetPath);
  if (!state) {
    failPath(relativePath, "file is missing");
  }
  if (state.isSymbolicLink() || !state.isFile()) {
    failPath(relativePath, "expected a regular non-reparse file");
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    failPath(relativePath, "file resolves through a symlink, junction, or reparse point");
  }
  return state;
}

function sameFileIdentity(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size;
}

async function readCheckedFile(targetPath, relativePath) {
  const before = await assertNoReparseFile(targetPath, relativePath);
  const bytes = await readFile(targetPath);
  const after = await assertNoReparseFile(targetPath, relativePath);
  if (!sameFileIdentity(before, after) || after.size !== bytes.length) {
    failPath(relativePath, "file changed while it was being verified");
  }
  return { bytes, state: after };
}

function parseReceipt(receiptBytes, expected) {
  let text;
  try {
    text = UTF8_DECODER.decode(receiptBytes);
  } catch {
    failPath(RECEIPT_NAME, "receipt is not valid UTF-8");
  }

  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    failPath(RECEIPT_NAME, "receipt is not valid JSON");
  }
  assertPlainObject(receipt, RECEIPT_NAME);
  assertExactKeys(
    receipt,
    ["fileCount", "files", "manifestPath", "manifestSha256", "schemaVersion", "sourceCommit"],
    RECEIPT_NAME,
  );
  if (receipt.schemaVersion !== RECEIPT_SCHEMA_VERSION) {
    failPath(RECEIPT_NAME, "unsupported schemaVersion");
  }
  if (receipt.sourceCommit !== expected.commit) {
    failPath(RECEIPT_NAME, "sourceCommit does not match the expected commit");
  }
  if (receipt.manifestPath !== MANIFEST_PATH) {
    failPath(RECEIPT_NAME, "manifestPath is not the fixed commit-owned manifest path");
  }
  if (receipt.manifestSha256 !== expected.manifestSha256) {
    failPath(RECEIPT_NAME, "manifestSha256 does not match the expected manifest");
  }
  if (!Number.isSafeInteger(receipt.fileCount) || receipt.fileCount < 1) {
    failPath(RECEIPT_NAME, "fileCount must be a positive safe integer");
  }
  if (!Array.isArray(receipt.files) || receipt.files.length !== receipt.fileCount) {
    failPath(RECEIPT_NAME, "files length does not match fileCount");
  }

  const exactPaths = new Set();
  const foldedPaths = new Set();
  let previousPath = null;
  for (let index = 0; index < receipt.files.length; index += 1) {
    const entry = receipt.files[index];
    const label = `${RECEIPT_NAME} files[${index}]`;
    assertPlainObject(entry, label);
    assertExactKeys(entry, ["executable", "path", "sha256"], label);
    const relativePath = validatePayloadPolicy(entry.path, `${label}.path`);
    const folded = relativePath.toLowerCase();
    if (exactPaths.has(relativePath) || foldedPaths.has(folded)) {
      failPath(relativePath, "duplicate or case-colliding receipt path");
    }
    if (previousPath !== null && compareOrdinal(previousPath, relativePath) >= 0) {
      failPath(relativePath, "receipt files are not in ordinal sorted order");
    }
    if (typeof entry.sha256 !== "string" || !SHA256_PATTERN.test(entry.sha256)) {
      failPath(relativePath, "invalid SHA-256 metadata");
    }
    if (typeof entry.executable !== "boolean") {
      failPath(relativePath, "executable metadata must be boolean");
    }
    exactPaths.add(relativePath);
    foldedPaths.add(folded);
    previousPath = relativePath;
  }
  if (!exactPaths.has(VERIFIER_PATH)) {
    failPath(VERIFIER_PATH, "required verifier payload is absent from the receipt");
  }
  return receipt;
}

function expectedDirectoryPaths(receipt) {
  const expected = new Set();
  for (const entry of receipt.files) {
    const segments = entry.path.split("/");
    for (let length = 1; length < segments.length; length += 1) {
      expected.add(segments.slice(0, length).join("/"));
    }
  }
  return expected;
}

async function verifyMember(contextPath, entry) {
  const targetPath = resolveInside(contextPath, entry.path);
  const { bytes, state } = await readCheckedFile(targetPath, entry.path);
  if (sha256Bytes(bytes) !== entry.sha256) {
    failPath(entry.path, "SHA-256 mismatch");
  }
  const executable = process.platform === "win32" ? false : Boolean(state.mode & 0o111);
  if (executable !== entry.executable) {
    failPath(entry.path, "executable metadata mismatch");
  }
}

async function scanFullContext(contextPath, receipt) {
  const expectedFiles = new Set([RECEIPT_NAME, ...receipt.files.map((entry) => entry.path)]);
  const expectedDirectories = expectedDirectoryPaths(receipt);
  const seenFiles = new Set();
  const seenFolded = new Set();

  async function walk(directoryPath, relativeDirectory) {
    const entries = await readdir(directoryPath, { withFileTypes: true });
    entries.sort((left, right) => compareOrdinal(left.name, right.name));
    for (const entry of entries) {
      const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      validateRelativePath(relativePath, relativePath);
      const folded = relativePath.toLowerCase();
      if (seenFolded.has(folded)) {
        failPath(relativePath, "case-colliding filesystem entry");
      }
      seenFolded.add(folded);

      const fullPath = resolveInside(contextPath, relativePath);
      const state = await pathState(fullPath);
      if (!state || state.isSymbolicLink()) {
        failPath(relativePath, "symlink, junction, or reparse point is forbidden");
      }
      const resolved = await realpath(fullPath);
      if (canonicalNativePath(resolved) !== canonicalNativePath(fullPath)) {
        failPath(relativePath, "entry resolves through a symlink, junction, or reparse point");
      }

      const denial = mandatoryDenial(relativePath);
      if (denial && !structuralException(relativePath, denial.kind)) {
        failPath(relativePath, denial.reason);
      }
      if (state.isDirectory()) {
        if (!expectedDirectories.has(relativePath)) {
          failPath(relativePath, "extra directory is not represented by receipt membership");
        }
        await walk(fullPath, relativePath);
      } else if (state.isFile()) {
        if (!expectedFiles.has(relativePath)) {
          failPath(relativePath, "extra file is not represented by the receipt");
        }
        seenFiles.add(relativePath);
      } else {
        failPath(relativePath, "non-regular filesystem entry is forbidden");
      }
    }
  }

  await walk(contextPath, "");
  for (const expectedPath of expectedFiles) {
    if (!seenFiles.has(expectedPath)) {
      failPath(expectedPath, "receipt member is missing from the context");
    }
  }
}

async function verifyContext(options) {
  const contextArgument = options.values.get("--context");
  if (!path.isAbsolute(contextArgument)) {
    fail("--context: absolute path required");
  }
  const contextPath = path.resolve(contextArgument);
  await assertNoReparseDirectory(contextPath, "--context");

  const expected = {
    commit: validateHex(options.values.get("--expected-commit"), COMMIT_PATTERN, "--expected-commit"),
    manifestSha256: validateHex(
      options.values.get("--expected-manifest-sha256"),
      SHA256_PATTERN,
      "--expected-manifest-sha256",
    ),
    receiptSha256: validateHex(
      options.values.get("--expected-receipt-sha256"),
      SHA256_PATTERN,
      "--expected-receipt-sha256",
    ),
  };

  const receiptPath = resolveInside(contextPath, RECEIPT_NAME);
  const receiptRead = await readCheckedFile(receiptPath, RECEIPT_NAME);
  if (receiptRead.bytes.length > MAX_RECEIPT_BYTES) {
    failPath(RECEIPT_NAME, "receipt exceeds the size limit");
  }
  if (sha256Bytes(receiptRead.bytes) !== expected.receiptSha256) {
    failPath(RECEIPT_NAME, "receipt SHA-256 does not match the expected identity");
  }
  const receipt = parseReceipt(receiptRead.bytes, expected);
  const verifierEntry = receipt.files.find((entry) => entry.path === VERIFIER_PATH);
  await verifyMember(contextPath, verifierEntry);

  if (options.mode === "--full") {
    await scanFullContext(contextPath, receipt);
    for (const entry of receipt.files) {
      await verifyMember(contextPath, entry);
    }
  }
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  await verifyContext(options);
}

main().catch((error) => {
  process.stderr.write(`ERROR: ${error.message}\n`);
  process.exitCode = 1;
});
