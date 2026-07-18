#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

const SCHEMA_VERSION = 2;
const MANIFEST_RELATIVE_PATH = "developer/public-container-context-manifest.json";
const VERIFIER_RELATIVE_PATH = "developer/verify-public-container-context.mjs";
const RECEIPT_NAME = ".ieltmps-public-context.json";
const FULL_COMMIT_PATTERN = /^(?:[0-9a-f]{40}|[0-9A-F]{40})$/u;
const OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const SURROGATE_PATTERN = /[\uD800-\uDFFF]/u;
const DRIVE_LETTER_PATTERN = /^[A-Za-z]:/u;
const WINDOWS_INVALID_CHARACTER_PATTERN = /[<>:"|?*]/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const MIGRATION_FILENAME_PATTERN = /^[0-9]{3}_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/u;
const MAX_GIT_BUFFER = 512 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const EXACT_ALLOW_CEILING = Object.freeze([
  ".dockerignore",
  "index.html",
  "backend/Dockerfile",
  "backend/package.json",
  "backend/package-lock.json",
  "backend/.env.example",
  VERIFIER_RELATIVE_PATH,
]);
const PREFIX_ALLOW_CEILING = Object.freeze([
  "assets/",
  "css/",
  "js/",
  "src/styles/",
  "templates/",
  "backend/src/",
  "backend/scripts/",
  "backend/migrations/",
  "backend/admin/",
  "backend/auth/",
]);
const DENIED_EXACT_PATHS = Object.freeze([
  "backend/DEPLOYMENT-RUNBOOK.md",
]);
const DENIED_PATH_COMPONENTS = Object.freeze([
  "listeningpractice",
  "readingpractice",
  ".git",
  ".github",
  ".codex",
  ".build",
  "dist",
  "node_modules",
  "authorized_clients",
  "authorized-clients",
  "client-auth",
  "onion-auth",
  "hidden_service",
  "hidden-service",
]);
const DENIED_FILE_SUFFIXES = Object.freeze([
  ".key",
  ".pem",
  ".p12",
  ".pfx",
  ".jks",
  ".keystore",
  ".bak",
  ".backup",
  ".dump",
  ".dmp",
  ".db",
  ".sqlite",
  ".sqlite3",
  ".log",
  ".sql",
  ".sql.gz",
  ".tar",
  ".tar.gz",
  ".tgz",
  ".zip",
  ".7z",
  ".rar",
]);
const EXACT_ALLOW_SET = new Set(EXACT_ALLOW_CEILING);
const DENIED_EXACT_SET = new Set(
  DENIED_EXACT_PATHS.map((entry) => entry.toLowerCase()),
);
const DENIED_COMPONENT_SET = new Set(DENIED_PATH_COMPONENTS);

function fail(message) {
  throw new Error(message);
}

function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
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

function resolveInside(rootPath, relativePath, label) {
  const resolved = path.resolve(rootPath, ...relativePath.split("/"));
  if (!isInside(rootPath, resolved)) {
    fail(label + " escapes its root: " + relativePath);
  }
  return resolved;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(label + " must be a JSON object");
  }
}

function assertExactKeys(value, expectedKeys, label) {
  const actual = Object.keys(value).sort(compareOrdinal);
  const expected = [...expectedKeys].sort(compareOrdinal);
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(label + " must contain exactly: " + expected.join(", "));
  }
}

function validateRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(label + " must be a non-empty string");
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    fail(label + " contains a control character: " + JSON.stringify(value));
  }
  if (SURROGATE_PATTERN.test(value)) {
    fail(label + " contains an unpaired Unicode surrogate");
  }
  if (value.includes("\\")) {
    fail(label + " must use '/' separators: " + value);
  }
  if (
    value.startsWith("/")
    || DRIVE_LETTER_PATTERN.test(value)
    || path.posix.isAbsolute(value)
  ) {
    fail(label + " must be relative: " + value);
  }
  if (value.endsWith("/") || path.posix.normalize(value) !== value) {
    fail(label + " is not a normalized file path: " + value);
  }

  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    fail(label + " contains an empty, '.' or '..' segment: " + value);
  }
  for (const segment of segments) {
    if (WINDOWS_INVALID_CHARACTER_PATTERN.test(segment)) {
      fail(label + " contains a non-portable Windows or ADS character: " + value);
    }
    if (segment.endsWith(".") || segment.endsWith(" ")) {
      fail(label + " contains a trailing dot or space segment: " + value);
    }
    if (WINDOWS_RESERVED_NAME_PATTERN.test(segment)) {
      fail(label + " contains a reserved Windows name: " + value);
    }
  }
  return value;
}

function validatePrefix(value, label) {
  if (typeof value !== "string" || !value.endsWith("/") || value === "/") {
    fail(
      label
      + " must be a non-root relative directory prefix ending in '/': "
      + String(value),
    );
  }
  validateRelativePath(value.slice(0, -1), label);
  return value;
}

function validateUniquePathArray(value, label, validator) {
  if (!Array.isArray(value)) {
    fail(label + " must be an array");
  }
  const exact = new Set();
  const portable = new Set();
  return value.map((entry, index) => {
    const checked = validator(entry, label + "[" + index + "]");
    const folded = checked.toLowerCase();
    if (exact.has(checked) || portable.has(folded)) {
      fail(label + " contains a duplicate or case-colliding value: " + checked);
    }
    exact.add(checked);
    portable.add(folded);
    return checked;
  });
}

function prefixIsWithinCeiling(prefix) {
  return PREFIX_ALLOW_CEILING.some((ceiling) => prefix.startsWith(ceiling));
}

function hasDeniedComponent(relativePath) {
  return relativePath
    .split("/")
    .some((segment) => DENIED_COMPONENT_SET.has(segment.toLowerCase()));
}

function hasDeniedFileFamily(relativePath) {
  const fileName = relativePath
    .slice(relativePath.lastIndexOf("/") + 1)
    .toLowerCase();
  if (fileName === ".env" || fileName.startsWith(".env.")) {
    return true;
  }
  return DENIED_FILE_SUFFIXES.some((suffix) => fileName.endsWith(suffix));
}

function isCodeOwnedStructuralException(relativePath) {
  if (relativePath === "backend/.env.example") {
    return true;
  }
  const migrationPrefix = "backend/migrations/";
  if (!relativePath.startsWith(migrationPrefix)) {
    return false;
  }
  const fileName = relativePath.slice(migrationPrefix.length);
  return !fileName.includes("/") && MIGRATION_FILENAME_PATTERN.test(fileName);
}

function isMandatorilyDeniedExact(relativePath) {
  if (
    DENIED_EXACT_SET.has(relativePath.toLowerCase())
    || hasDeniedComponent(relativePath)
  ) {
    return true;
  }
  return hasDeniedFileFamily(relativePath)
    && !isCodeOwnedStructuralException(relativePath);
}

function isMandatorilyDeniedPrefix(prefix) {
  const relativeDirectory = prefix.slice(0, -1);
  return DENIED_EXACT_SET.has(relativeDirectory.toLowerCase())
    || hasDeniedComponent(relativeDirectory);
}

function validateManifest(value) {
  assertPlainObject(value, "public container context manifest");
  assertExactKeys(
    value,
    ["schemaVersion", "includeExact", "includePrefixes"],
    "public container context manifest",
  );
  if (value.schemaVersion !== SCHEMA_VERSION) {
    fail(
      "unsupported public container context manifest schemaVersion: "
      + value.schemaVersion,
    );
  }

  const includeExact = validateUniquePathArray(
    value.includeExact,
    "manifest includeExact",
    validateRelativePath,
  );
  const includePrefixes = validateUniquePathArray(
    value.includePrefixes,
    "manifest includePrefixes",
    validatePrefix,
  );

  for (const relativePath of includeExact) {
    if (isMandatorilyDeniedExact(relativePath)) {
      fail(
        "manifest exact path is forbidden by code-owned mandatory policy: "
        + relativePath,
      );
    }
    if (!EXACT_ALLOW_SET.has(relativePath)) {
      fail(
        "manifest exact path is outside the code-owned exact ceiling: "
        + relativePath,
      );
    }
  }
  for (const prefix of includePrefixes) {
    if (isMandatorilyDeniedPrefix(prefix)) {
      fail(
        "manifest prefix is forbidden by code-owned mandatory policy: "
        + prefix,
      );
    }
    if (!prefixIsWithinCeiling(prefix)) {
      fail(
        "manifest prefix is outside the code-owned prefix ceiling: "
        + prefix,
      );
    }
  }
  if (!includeExact.includes(VERIFIER_RELATIVE_PATH)) {
    fail(
      "manifest includeExact must include the context verifier: "
      + VERIFIER_RELATIVE_PATH,
    );
  }

  return Object.freeze({
    includeExact: Object.freeze(includeExact),
    includePrefixes: Object.freeze(includePrefixes),
  });
}

function isWithinCodeOwnedCeiling(relativePath) {
  return EXACT_ALLOW_SET.has(relativePath)
    || PREFIX_ALLOW_CEILING.some((prefix) => relativePath.startsWith(prefix));
}

function parseOptions(argv) {
  const allowed = new Set(["--repo", "--commit", "--output"]);
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!allowed.has(key) || index + 1 >= argv.length) {
      fail("invalid argument: " + String(key));
    }
    if (options.has(key)) {
      fail("duplicate argument: " + key);
    }
    options.set(key, argv[index + 1]);
    index += 1;
  }
  for (const key of allowed) {
    if (!options.has(key)) {
      fail("missing required argument: " + key);
    }
  }
  return options;
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
  environment.GIT_CONFIG_GLOBAL =
    process.platform === "win32" ? "NUL" : "/dev/null";
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
    const stderr = result.stderr
      ? result.stderr.toString("utf8").trim().split(/\r?\n/u)[0]
      : "";
    fail(
      "git "
      + args[0]
      + " failed"
      + (stderr ? ": " + stderr : ""),
    );
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
    fail(label + " is missing: " + targetPath);
  }
  if (state.isSymbolicLink()) {
    fail(
      label
      + " must not be a symbolic link, junction, or reparse point: "
      + targetPath,
    );
  }
  if (!state.isDirectory()) {
    fail(label + " must be a directory: " + targetPath);
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(
      label
      + " resolves through a symbolic link, junction, or reparse point: "
      + targetPath,
    );
  }
}

async function validateRepository(repoRoot) {
  await assertNoReparseDirectory(repoRoot, "repository root");
  const result = runGit(repoRoot, ["rev-parse", "--show-toplevel"]);
  const topLevel = result.stdout.toString("utf8").trim();
  if (canonicalNativePath(topLevel) !== canonicalNativePath(repoRoot)) {
    fail(
      "--repo must name the exact Git worktree root; Git reported: "
      + topLevel,
    );
  }
}

function validateFullCommit(value) {
  if (typeof value !== "string" || !FULL_COMMIT_PATTERN.test(value)) {
    fail(
      "--commit must be a full all-lowercase or all-uppercase "
      + "40-character commit SHA",
    );
  }
  return value.toLowerCase();
}

function validateOriginalCommit(repoRoot, requestedCommit) {
  const sourceCommit = validateFullCommit(requestedCommit);
  const type = runGit(repoRoot, ["cat-file", "-t", sourceCommit])
    .stdout.toString("ascii").trim();
  if (type !== "commit") {
    fail(
      "--commit must identify an original commit object: "
      + sourceCommit,
    );
  }
  return sourceCommit;
}

function splitNullRecords(buffer) {
  const records = [];
  let offset = 0;
  while (offset < buffer.length) {
    const end = buffer.indexOf(0, offset);
    if (end === -1) {
      fail("git ls-tree returned a non-NUL-terminated record");
    }
    if (end > offset) {
      records.push(buffer.subarray(offset, end));
    }
    offset = end + 1;
  }
  return records;
}

function decodeGitPath(value) {
  try {
    return UTF8_DECODER.decode(value);
  } catch (error) {
    fail(
      "git tree contains a path that is not valid UTF-8: "
      + error.message,
    );
  }
}

function readCommitTree(repoRoot, sourceCommit) {
  const result = runGit(
    repoRoot,
    ["ls-tree", "-r", "-z", "--full-tree", sourceCommit],
  );
  const entries = [];
  for (const record of splitNullRecords(result.stdout)) {
    const tab = record.indexOf(0x09);
    if (tab < 0) {
      fail("git ls-tree returned a malformed entry without a path separator");
    }
    const header = record.subarray(0, tab).toString("ascii");
    const parts = header.split(" ");
    if (parts.length !== 3) {
      fail("git ls-tree returned a malformed entry header: " + header);
    }
    const [mode, type, objectId] = parts;
    if (!OBJECT_ID_PATTERN.test(objectId)) {
      fail("git ls-tree returned an invalid object id");
    }
    const relativePath = validateRelativePath(
      decodeGitPath(record.subarray(tab + 1)),
      "Git tree path",
    );
    entries.push({ mode, type, objectId, path: relativePath });
  }
  return entries;
}

function readGitBlobs(repoRoot, objectIds) {
  const requestedIds = [...new Set(objectIds)];
  if (requestedIds.length === 0) {
    return new Map();
  }
  for (const objectId of requestedIds) {
    if (!OBJECT_ID_PATTERN.test(objectId)) {
      fail("invalid Git blob id requested: " + objectId);
    }
  }
  const input = Buffer.from(requestedIds.join("\n") + "\n", "ascii");
  const result = runGit(repoRoot, ["cat-file", "--batch"], { input });
  const blobs = new Map();
  let offset = 0;
  for (const requestedId of requestedIds) {
    const headerEnd = result.stdout.indexOf(0x0a, offset);
    if (headerEnd === -1) {
      fail("git cat-file returned a truncated header for " + requestedId);
    }
    const header = result.stdout
      .subarray(offset, headerEnd)
      .toString("ascii");
    const parts = header.split(" ");
    if (parts.length !== 3) {
      fail("git cat-file returned a malformed header for " + requestedId);
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
    if (
      contentEnd >= result.stdout.length
      || result.stdout[contentEnd] !== 0x0a
    ) {
      fail("git cat-file returned truncated blob bytes for " + requestedId);
    }
    blobs.set(
      requestedId,
      result.stdout.subarray(contentStart, contentEnd),
    );
    offset = contentEnd + 1;
  }
  if (offset !== result.stdout.length) {
    fail("git cat-file returned unexpected trailing output");
  }
  return blobs;
}

function loadCommitOwnedManifest(repoRoot, treeEntries) {
  const manifestEntry = treeEntries.find(
    (entry) => entry.path === MANIFEST_RELATIVE_PATH,
  );
  if (!manifestEntry) {
    fail(
      "selected commit does not contain "
      + MANIFEST_RELATIVE_PATH,
    );
  }
  if (
    (manifestEntry.mode !== "100644" && manifestEntry.mode !== "100755")
    || manifestEntry.type !== "blob"
  ) {
    fail(
      "selected commit manifest must be a regular Git blob: "
      + MANIFEST_RELATIVE_PATH,
    );
  }
  const manifestBytes = readGitBlobs(
    repoRoot,
    [manifestEntry.objectId],
  ).get(manifestEntry.objectId);
  if (!manifestBytes) {
    fail("selected commit manifest blob was not loaded");
  }
  let manifestText;
  try {
    manifestText = UTF8_DECODER.decode(manifestBytes);
  } catch (error) {
    fail(
      "public container context manifest is not valid UTF-8: "
      + error.message,
    );
  }
  let manifestValue;
  try {
    manifestValue = JSON.parse(manifestText);
  } catch (error) {
    fail(
      "public container context manifest contains malformed JSON: "
      + error.message,
    );
  }
  return {
    manifest: validateManifest(manifestValue),
    manifestSha256: sha256Bytes(manifestBytes),
  };
}

function registerPortableOutputPath(relativePath, registry) {
  const segments = relativePath.split("/");
  let current = "";
  for (let index = 0; index < segments.length; index += 1) {
    current = current
      ? current + "/" + segments[index]
      : segments[index];
    const kind =
      index === segments.length - 1 ? "file" : "directory";
    const folded = current.toLowerCase();
    const existing = registry.get(folded);
    if (existing) {
      if (
        existing.path !== current
        || existing.kind !== kind
        || kind === "file"
      ) {
        fail(
          "selected Git tree contains a duplicate or "
          + "case-colliding output path: "
          + relativePath,
        );
      }
    } else {
      registry.set(folded, { path: current, kind });
    }
  }
}

function selectPayloadEntries(treeEntries, manifest) {
  const exactIncludes = new Set(manifest.includeExact);
  const foundExact = new Set();
  const foundPrefixes = new Set();
  const portableRegistry = new Map();
  const selected = [];

  for (const entry of treeEntries) {
    const relativePath = entry.path;

    // Path safety was applied while parsing the tree. Mandatory denials
    // precede structural exceptions, ceilings, and manifest selection.
    if (
      DENIED_EXACT_SET.has(relativePath.toLowerCase())
      || hasDeniedComponent(relativePath)
    ) {
      continue;
    }
    const deniedFileFamily = hasDeniedFileFamily(relativePath);
    if (
      deniedFileFamily
      && !isCodeOwnedStructuralException(relativePath)
    ) {
      continue;
    }
    if (!isWithinCodeOwnedCeiling(relativePath)) {
      continue;
    }

    const exactMatch = exactIncludes.has(relativePath);
    const matchingPrefixes = manifest.includePrefixes.filter(
      (prefix) => relativePath.startsWith(prefix),
    );
    if (!exactMatch && matchingPrefixes.length === 0) {
      continue;
    }

    if (entry.mode === "120000") {
      fail("selected Git symlink is forbidden: " + relativePath);
    }
    if (entry.mode === "160000" || entry.type === "commit") {
      fail("selected Git submodule is forbidden: " + relativePath);
    }
    if (
      (entry.mode !== "100644" && entry.mode !== "100755")
      || entry.type !== "blob"
    ) {
      fail(
        "selected Git entry must be a regular blob with mode "
        + "100644 or 100755: "
        + relativePath,
      );
    }
    if (process.platform === "win32" && entry.mode === "100755") {
      fail(
        "selected executable Git payload is unsupported on Windows: "
        + relativePath,
      );
    }

    registerPortableOutputPath(relativePath, portableRegistry);
    if (exactMatch) {
      foundExact.add(relativePath);
    }
    for (const prefix of matchingPrefixes) {
      foundPrefixes.add(prefix);
    }
    selected.push({
      executable: entry.mode === "100755",
      objectId: entry.objectId,
      path: relativePath,
    });
  }

  const missingExact = manifest.includeExact.filter(
    (entry) => !foundExact.has(entry),
  );
  if (missingExact.length > 0) {
    fail(
      "manifest exact paths are missing or denied in the selected commit: "
      + missingExact.join(", "),
    );
  }
  const missingPrefixes = manifest.includePrefixes.filter(
    (entry) => !foundPrefixes.has(entry),
  );
  if (missingPrefixes.length > 0) {
    fail(
      "manifest prefixes contain no permitted files in the selected commit: "
      + missingPrefixes.join(", "),
    );
  }

  selected.sort((left, right) => compareOrdinal(left.path, right.path));
  return selected;
}

async function prepareOutputPath(outputArgument) {
  if (!path.isAbsolute(outputArgument)) {
    fail("--output must be an absolute path");
  }
  const outputPath = path.resolve(outputArgument);
  const parentPath = path.dirname(outputPath);
  if (canonicalNativePath(parentPath) === canonicalNativePath(outputPath)) {
    fail(
      "--output must be a dedicated child directory, "
      + "not a filesystem root",
    );
  }
  await assertNoReparseDirectory(
    parentPath,
    "output parent directory",
  );
  if (await pathState(outputPath)) {
    fail(
      "output path already exists; one-use generation "
      + "will not replace or delete it",
    );
  }
  return { outputPath, parentPath };
}

async function materializeContext(
  stagingPath,
  selected,
  blobs,
  receiptBase,
) {
  const files = [];
  for (const entry of selected) {
    const destinationPath = resolveInside(
      stagingPath,
      entry.path,
      "generated output path",
    );
    await mkdir(path.dirname(destinationPath), { recursive: true });
    const content = blobs.get(entry.objectId);
    if (!content) {
      fail("selected Git blob was not loaded: " + entry.path);
    }
    await writeFile(destinationPath, content, {
      flag: "wx",
      mode: entry.executable ? 0o755 : 0o644,
    });
    if (process.platform !== "win32") {
      await chmod(
        destinationPath,
        entry.executable ? 0o755 : 0o644,
      );
    }
    files.push({
      path: entry.path,
      sha256: sha256Bytes(content),
      executable: entry.executable,
    });
  }

  const receipt = {
    schemaVersion: SCHEMA_VERSION,
    sourceCommit: receiptBase.sourceCommit,
    manifestPath: MANIFEST_RELATIVE_PATH,
    manifestSha256: receiptBase.manifestSha256,
    fileCount: files.length,
    files,
  };
  if (
    !SHA256_PATTERN.test(receipt.manifestSha256)
    || receipt.fileCount !== receipt.files.length
  ) {
    fail("internal receipt metadata validation failed");
  }
  const receiptBytes = Buffer.from(
    JSON.stringify(receipt, null, 2) + "\n",
    "utf8",
  );
  const receiptPath = resolveInside(
    stagingPath,
    RECEIPT_NAME,
    "generated receipt path",
  );

  // The receipt is deliberately the final file written into the context.
  await writeFile(
    receiptPath,
    receiptBytes,
    { flag: "wx", mode: 0o644 },
  );
  return { receipt, receiptBytes };
}

function simulatedFailureRequested() {
  return process.env.IELTMPS_PUBLIC_CONTEXT_TEST_MODE === "1"
    && process.env.IELTMPS_PUBLIC_CONTEXT_TEST_FAIL_BEFORE_PUBLISH === "1";
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const repoArgument = options.get("--repo");
  if (!path.isAbsolute(repoArgument)) {
    fail("--repo must be an absolute path");
  }
  const repoRoot = path.resolve(repoArgument);
  await validateRepository(repoRoot);

  const sourceCommit = validateOriginalCommit(
    repoRoot,
    options.get("--commit"),
  );
  const treeEntries = readCommitTree(repoRoot, sourceCommit);
  const { manifest, manifestSha256 } = loadCommitOwnedManifest(
    repoRoot,
    treeEntries,
  );
  const selected = selectPayloadEntries(treeEntries, manifest);
  const blobs = readGitBlobs(
    repoRoot,
    selected.map((entry) => entry.objectId),
  );
  const { outputPath, parentPath } = await prepareOutputPath(
    options.get("--output"),
  );

  const temporaryPrefix = path.join(
    parentPath,
    "." + path.basename(outputPath) + ".tmp-" + process.pid + "-",
  );
  let stagingPath = await mkdtemp(temporaryPrefix);
  try {
    await assertNoReparseDirectory(
      stagingPath,
      "temporary output directory",
    );
    const { receipt, receiptBytes } = await materializeContext(
      stagingPath,
      selected,
      blobs,
      { sourceCommit, manifestSha256 },
    );

    if (simulatedFailureRequested()) {
      fail("simulated interruption before atomic context publication");
    }
    if (await pathState(outputPath)) {
      fail(
        "output path appeared during generation; "
        + "refusing to replace it",
      );
    }
    await rename(stagingPath, outputPath);
    stagingPath = null;

    process.stdout.write(
      JSON.stringify({
        status: "ok",
        sourceCommit,
        manifestSha256,
        receiptSha256: sha256Bytes(receiptBytes),
        fileCount: receipt.fileCount,
        output: outputPath,
      }) + "\n",
    );
  } finally {
    if (stagingPath) {
      await rm(stagingPath, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  process.stderr.write("ERROR: " + error.message + "\n");
  process.exitCode = 1;
});
