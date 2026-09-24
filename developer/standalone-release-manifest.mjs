#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  constants as fsConstants,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const MANIFEST_RELATIVE_PATH = "developer/standalone-release-manifest.json";
const EXPECTED_MANAGED_ROOTS = ["assets", "css", "js/bundles", "src/styles"];
const READING_ROOT = "ReadingPractice";
const LEGACY_LISTENING_SWITCH = "INCLUDE_LOCAL_LISTENING";
const READING_MANIFEST_VARIABLE = "READING_PRACTICE_PUBLIC_MANIFEST";
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/u;
const DRIVE_LETTER_PATTERN = /^[A-Za-z]:/u;
const LOWERCASE_SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const PORTABLE_RESERVED_NAME_PATTERN = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/iu;
const DANGEROUS_FILE_PATTERN = /(^|\/)(?:\.env(?:\..*)?|credentials\.json|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:key|pem|p12|pfx|kdbx|log|tmp|temp|bak))$/iu;
const DANGEROUS_SEGMENT_PATTERN = /(^|\/)\.ssh(?:\/|$)/iu;
const FORBIDDEN_PREFIXES = [
  ".git/",
  "assets/generated/listening-exams/",
  "backend/",
  "developer/",
  "ListeningPractice/",
  "node_modules/",
  "templates/",
];

function fail(message) {
  throw new Error(message);
}

function parseOptions(argv) {
  if (argv.length === 0) {
    fail("a command is required");
  }

  const command = argv[0];
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith("--") || index + 1 >= argv.length) {
      fail(`invalid argument: ${key}`);
    }
    if (Object.hasOwn(options, key)) {
      fail(`duplicate argument: ${key}`);
    }
    options[key] = argv[index + 1];
    index += 1;
  }
  return { command, options };
}

function requiredOption(options, name) {
  const value = options[name];
  if (!value) {
    fail(`missing required argument: ${name}`);
  }
  return value;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be a JSON object`);
  }
}

function assertExactKeys(value, allowedKeys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...allowedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} must contain exactly: ${expected.join(", ")}`);
  }
}

function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalNativePath(value) {
  const normalized = path.normalize(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function validateRelativePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    fail(`${label} contains a NUL or control character: ${JSON.stringify(value)}`);
  }
  if (value.includes("\\")) {
    fail(`${label} must use '/' separators: ${value}`);
  }
  if (value.startsWith("/") || DRIVE_LETTER_PATTERN.test(value) || path.posix.isAbsolute(value)) {
    fail(`${label} must be relative: ${value}`);
  }
  if (value.endsWith("/") || path.posix.normalize(value) !== value) {
    fail(`${label} is not a normalized file path: ${value}`);
  }

  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    fail(`${label} contains an empty, '.' or '..' segment: ${value}`);
  }
  for (const segment of segments) {
    if (segment.includes(":")) {
      fail(`${label} contains a non-portable ':' segment: ${value}`);
    }
    if (segment.endsWith(".") || segment.endsWith(" ") || PORTABLE_RESERVED_NAME_PATTERN.test(segment)) {
      fail(`${label} contains a non-portable Windows segment: ${value}`);
    }
  }
  return value;
}

function assertDefenseInDepthPath(relativePath, label) {
  const normalized = `${relativePath}/`;
  if (FORBIDDEN_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    fail(`${label} uses a forbidden release scope: ${relativePath}`);
  }
  if (DANGEROUS_SEGMENT_PATTERN.test(relativePath) || DANGEROUS_FILE_PATTERN.test(relativePath)) {
    fail(`${label} matches a dangerous secret or temporary path pattern: ${relativePath}`);
  }
  if (relativePath.startsWith("assets/scripts/") && relativePath.endsWith(".py")) {
    fail(`${label} must not publish Python source from assets/scripts: ${relativePath}`);
  }
  if (/^js\/(?:app|components|core|data|presentation|runtime|services|utils|views)\//u.test(relativePath)) {
    fail(`${label} must not publish unbundled JavaScript source: ${relativePath}`);
  }
}

function validatePathArray(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    fail(`${label} must be a non-empty array`);
  }

  const exact = new Set();
  const portable = new Set();
  const paths = value.map((entry, index) => {
    const validated = validateRelativePath(entry, `${label}[${index}]`);
    const folded = validated.toLowerCase();
    if (exact.has(validated) || portable.has(folded)) {
      fail(`${label} contains a duplicate or case-colliding path: ${validated}`);
    }
    exact.add(validated);
    portable.add(folded);
    return validated;
  });

  const sorted = [...paths].sort(compareOrdinal);
  if (paths.some((entry, index) => entry !== sorted[index])) {
    fail(`${label} must be sorted with ordinal path ordering`);
  }
  return paths;
}

function isWithinManagedRoot(relativePath, managedRoot) {
  return relativePath.startsWith(`${managedRoot}/`);
}

async function readJson(jsonPath, label) {
  let source;
  try {
    source = await readFile(jsonPath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      fail(`${label} is missing: ${jsonPath}`);
    }
    throw error;
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${label} contains malformed JSON: ${error.message}`);
  }
}

async function sha256File(filePath) {
  const content = await readFile(filePath);
  return createHash("sha256").update(content).digest("hex");
}

async function sha256Text(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
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

async function assertNoReparsePoint(targetPath, displayPath) {
  const state = await lstat(targetPath);
  if (state.isSymbolicLink()) {
    fail(`release input must not contain a symbolic link or reparse point: ${displayPath}`);
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(`release input resolves through a symbolic link or reparse point: ${displayPath}`);
  }
  return state;
}

function resolveInside(rootPath, relativePath, label) {
  const resolved = path.resolve(rootPath, ...relativePath.split("/"));
  const relative = path.relative(rootPath, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`${label} escapes or aliases the release root: ${relativePath}`);
  }
  return resolved;
}

async function assertSafeRegularFile(rootPath, relativePath, label) {
  const fullPath = resolveInside(rootPath, relativePath, label);
  const segments = relativePath.split("/");
  let current = rootPath;
  await assertNoReparsePoint(rootPath, ".");
  for (let index = 0; index < segments.length; index += 1) {
    current = path.join(current, segments[index]);
    let state;
    try {
      state = await assertNoReparsePoint(current, segments.slice(0, index + 1).join("/"));
    } catch (error) {
      if (error && error.code === "ENOENT") {
        fail(`${label} is missing: ${relativePath}`);
      }
      throw error;
    }
    if (index < segments.length - 1 && !state.isDirectory()) {
      fail(`${label} has a non-directory parent: ${relativePath}`);
    }
    if (index === segments.length - 1 && !state.isFile()) {
      fail(`${label} must be a regular file: ${relativePath}`);
    }
  }
  return fullPath;
}

async function assertStandaloneRegularFile(filePath, label) {
  let state;
  try {
    state = await assertNoReparsePoint(filePath, filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      fail(`${label} is missing: ${filePath}`);
    }
    throw error;
  }
  if (!state.isFile()) {
    fail(`${label} must be a regular file: ${filePath}`);
  }
}

function validateMainManifest(manifest) {
  assertPlainObject(manifest, "standalone release manifest");
  assertExactKeys(
    manifest,
    ["files", "managedRoots", "nonReleaseFiles", "requiredFiles", "schemaVersion"],
    "standalone release manifest",
  );
  if (manifest.schemaVersion !== SCHEMA_VERSION) {
    fail(`unsupported standalone release manifest schemaVersion: ${manifest.schemaVersion}`);
  }

  const managedRoots = validatePathArray(manifest.managedRoots, "managedRoots");
  if (
    managedRoots.length !== EXPECTED_MANAGED_ROOTS.length
    || managedRoots.some((entry, index) => entry !== EXPECTED_MANAGED_ROOTS[index])
  ) {
    fail(`managedRoots must be exactly: ${EXPECTED_MANAGED_ROOTS.join(", ")}`);
  }

  const files = validatePathArray(manifest.files, "files");
  const fileSet = new Set(files);
  for (const relativePath of files) {
    assertDefenseInDepthPath(relativePath, "main manifest path");
    if (relativePath.startsWith(`${READING_ROOT}/`) || relativePath === READING_ROOT) {
      fail(`ReadingPractice must be authorized only by the external manifest: ${relativePath}`);
    }
    if (relativePath !== "index.html" && !managedRoots.some((root) => isWithinManagedRoot(relativePath, root))) {
      fail(`main manifest path is outside index.html and managedRoots: ${relativePath}`);
    }
  }

  const requiredFiles = validatePathArray(manifest.requiredFiles, "requiredFiles");
  for (const relativePath of requiredFiles) {
    if (!fileSet.has(relativePath)) {
      fail(`requiredFiles entry is not present in files: ${relativePath}`);
    }
  }
  for (const managedRoot of managedRoots) {
    if (!files.some((relativePath) => isWithinManagedRoot(relativePath, managedRoot))) {
      fail(`managed root has no authorized files: ${managedRoot}`);
    }
  }

  const nonReleaseFiles = validatePathArray(manifest.nonReleaseFiles, "nonReleaseFiles");
  for (const relativePath of nonReleaseFiles) {
    if (fileSet.has(relativePath)) {
      fail(`path cannot be both published and non-release: ${relativePath}`);
    }
    if (!managedRoots.some((root) => isWithinManagedRoot(relativePath, root))) {
      fail(`nonReleaseFiles entry is outside managedRoots: ${relativePath}`);
    }
  }

  return { files, managedRoots, nonReleaseFiles, requiredFiles };
}

function validateReadingManifest(manifest) {
  assertPlainObject(manifest, "ReadingPractice public manifest");
  assertExactKeys(manifest, ["files", "schemaVersion"], "ReadingPractice public manifest");
  if (manifest.schemaVersion !== SCHEMA_VERSION) {
    fail(`unsupported ReadingPractice manifest schemaVersion: ${manifest.schemaVersion}`);
  }
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    fail("ReadingPractice manifest files must be a non-empty array");
  }

  const exact = new Set();
  const portable = new Set();
  const files = manifest.files.map((entry, index) => {
    assertPlainObject(entry, `ReadingPractice files[${index}]`);
    assertExactKeys(entry, ["path", "sha256"], `ReadingPractice files[${index}]`);
    const relativePath = validateRelativePath(entry.path, `ReadingPractice files[${index}].path`);
    assertDefenseInDepthPath(relativePath, "ReadingPractice manifest path");
    const folded = relativePath.toLowerCase();
    if (exact.has(relativePath) || portable.has(folded)) {
      fail(`ReadingPractice manifest contains a duplicate or case-colliding path: ${relativePath}`);
    }
    if (typeof entry.sha256 !== "string" || !LOWERCASE_SHA256_PATTERN.test(entry.sha256)) {
      fail(`ReadingPractice files[${index}].sha256 must be a lowercase SHA-256: ${relativePath}`);
    }
    exact.add(relativePath);
    portable.add(folded);
    return { path: relativePath, sha256: entry.sha256 };
  });

  const sorted = [...files].sort((left, right) => compareOrdinal(left.path, right.path));
  if (files.some((entry, index) => entry.path !== sorted[index].path)) {
    fail("ReadingPractice manifest files must be sorted with ordinal path ordering");
  }
  return files;
}

async function scanRegularFiles(rootPath, relativeRoot) {
  const files = [];
  const rootState = await assertNoReparsePoint(rootPath, relativeRoot);
  if (!rootState.isDirectory()) {
    fail(`managed release root must be a directory: ${relativeRoot}`);
  }

  async function walk(directoryPath, directoryRelativePath) {
    const names = (await readdir(directoryPath)).sort(compareOrdinal);
    for (const name of names) {
      const childPath = path.join(directoryPath, name);
      const childRelativePath = `${directoryRelativePath}/${name}`;
      const state = await assertNoReparsePoint(childPath, childRelativePath);
      if (state.isDirectory()) {
        await walk(childPath, childRelativePath);
      } else if (state.isFile()) {
        validateRelativePath(childRelativePath, "filesystem release path");
        files.push(childRelativePath);
      } else {
        fail(`release input must contain only regular files and directories: ${childRelativePath}`);
      }
    }
  }

  await walk(rootPath, relativeRoot);
  return files;
}

async function assertManagedRootDrift(projectRoot, manifest) {
  const classified = new Set([...manifest.files, ...manifest.nonReleaseFiles]);
  for (const managedRoot of manifest.managedRoots) {
    const rootPath = resolveInside(projectRoot, `${managedRoot}/placeholder`, "managed root");
    const actualRootPath = path.dirname(rootPath);
    let actualFiles;
    try {
      actualFiles = await scanRegularFiles(actualRootPath, managedRoot);
    } catch (error) {
      if (error && error.code === "ENOENT") {
        fail(`managed release root is missing: ${managedRoot}`);
      }
      throw error;
    }
    const expectedFiles = manifest.files.filter((relativePath) => isWithinManagedRoot(relativePath, managedRoot));
    const expectedNonReleaseFiles = manifest.nonReleaseFiles.filter((relativePath) => isWithinManagedRoot(relativePath, managedRoot));
    const expectedClassifiedFiles = [...expectedFiles, ...expectedNonReleaseFiles];
    const unknown = actualFiles.filter((relativePath) => !classified.has(relativePath));
    const missing = expectedClassifiedFiles.filter((relativePath) => !actualFiles.includes(relativePath));
    if (unknown.length > 0) {
      fail(`managed release root contains unknown files under ${managedRoot}: ${unknown.join(", ")}`);
    }
    if (missing.length > 0) {
      fail(`managed release root is missing classified files under ${managedRoot}: ${missing.join(", ")}`);
    }
  }
}

function runGit(projectRoot, args, allowFailure = false) {
  const result = spawnSync("git", ["-C", projectRoot, ...args], {
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (result.error) {
    if (allowFailure && result.error.code === "ENOENT") {
      return result;
    }
    fail(`git execution failed: ${result.error.message}`);
  }
  if (!allowFailure && result.status !== 0) {
    const stderr = result.stderr ? result.stderr.toString("utf8").trim() : "";
    fail(`git ${args.join(" ")} failed${stderr ? `: ${stderr}` : ""}`);
  }
  return result;
}

async function detectGitRepository(projectRoot) {
  const markerExists = Boolean(await pathState(path.join(projectRoot, ".git")));
  const result = runGit(projectRoot, ["rev-parse", "--show-toplevel"], true);
  if (result.error && result.error.code === "ENOENT") {
    if (markerExists) {
      fail("Git metadata is present but git is unavailable for release provenance validation");
    }
    return null;
  }
  if (result.status !== 0) {
    if (markerExists) {
      fail("Git metadata is present but the release source is not a valid Git worktree");
    }
    return null;
  }

  const topLevel = result.stdout.toString("utf8").trim();
  if (canonicalNativePath(topLevel) !== canonicalNativePath(projectRoot)) {
    fail(`release source is nested inside a different Git worktree: ${topLevel}`);
  }
  return topLevel;
}

function decodeNullSeparated(buffer) {
  return buffer.toString("utf8").split("\0").filter(Boolean);
}

function assertGitTrackedAndClean(projectRoot, relativePaths) {
  const trackedResult = runGit(projectRoot, ["ls-files", "-z", "--", ...relativePaths]);
  const tracked = new Set(decodeNullSeparated(trackedResult.stdout));
  const missing = relativePaths.filter((relativePath) => !tracked.has(relativePath));
  if (missing.length > 0) {
    fail(`release manifest and payload must be tracked by Git: ${missing.join(", ")}`);
  }

  const unstagedResult = runGit(projectRoot, ["diff", "--name-only", "-z", "--", ...relativePaths]);
  const stagedResult = runGit(projectRoot, ["diff", "--cached", "--name-only", "-z", "--", ...relativePaths]);
  const dirty = [...new Set([
    ...decodeNullSeparated(unstagedResult.stdout),
    ...decodeNullSeparated(stagedResult.stdout),
  ])].sort(compareOrdinal);
  if (dirty.length > 0) {
    fail(`release manifest and payload must be clean in Git: ${dirty.join(" | ")}`);
  }
}

async function loadReadingAuthorization(projectRoot) {
  const readingRootPath = path.join(projectRoot, READING_ROOT);
  const readingRootState = await pathState(readingRootPath);
  const configuredManifest = process.env[READING_MANIFEST_VARIABLE] || "";

  if (!readingRootState) {
    if (configuredManifest) {
      fail(`${READING_MANIFEST_VARIABLE} was provided but ${READING_ROOT}/ is absent`);
    }
    return { files: [], manifestPath: null, manifestSha256: null };
  }
  if (!configuredManifest) {
    fail(`${READING_ROOT}/ is present but is not authorized; set ${READING_MANIFEST_VARIABLE} to an explicit public manifest`);
  }

  const externalManifestPath = path.resolve(projectRoot, configuredManifest);
  await assertStandaloneRegularFile(externalManifestPath, "ReadingPractice public manifest");
  const manifestSource = await readFile(externalManifestPath, "utf8");
  let manifest;
  try {
    manifest = JSON.parse(manifestSource);
  } catch (error) {
    fail(`ReadingPractice public manifest contains malformed JSON: ${error.message}`);
  }
  const authorizedFiles = validateReadingManifest(manifest);

  const actualArchiveRelativeFiles = await scanRegularFiles(readingRootPath, READING_ROOT);
  let manifestRelativeToReading = path.relative(readingRootPath, externalManifestPath);
  if (!manifestRelativeToReading.startsWith("..") && !path.isAbsolute(manifestRelativeToReading)) {
    manifestRelativeToReading = manifestRelativeToReading.split(path.sep).join("/");
    if (authorizedFiles.some((entry) => entry.path === manifestRelativeToReading)) {
      fail("ReadingPractice public manifest must not authorize itself for the archive");
    }
  } else {
    manifestRelativeToReading = null;
  }

  const actualFiles = actualArchiveRelativeFiles
    .map((relativePath) => relativePath.slice(`${READING_ROOT}/`.length))
    .filter((relativePath) => relativePath !== manifestRelativeToReading);
  const authorizedSet = new Set(authorizedFiles.map((entry) => entry.path));
  const unknown = actualFiles.filter((relativePath) => !authorizedSet.has(relativePath));
  const missing = authorizedFiles.filter((entry) => !actualFiles.includes(entry.path)).map((entry) => entry.path);
  if (unknown.length > 0) {
    fail(`ReadingPractice contains files not authorized by the external manifest: ${unknown.join(", ")}`);
  }
  if (missing.length > 0) {
    fail(`ReadingPractice external manifest lists missing files: ${missing.join(", ")}`);
  }

  for (const entry of authorizedFiles) {
    const sourcePath = await assertSafeRegularFile(readingRootPath, entry.path, "ReadingPractice manifest file");
    const actualHash = await sha256File(sourcePath);
    if (actualHash !== entry.sha256) {
      fail(`ReadingPractice SHA-256 mismatch for ${entry.path}: expected ${entry.sha256}, got ${actualHash}`);
    }
  }

  return {
    files: authorizedFiles,
    manifestPath: externalManifestPath,
    manifestSha256: await sha256Text(manifestSource),
  };
}

function archiveDirectories(filePaths, archiveRoots) {
  const directories = new Set();
  for (const filePath of filePaths) {
    const parts = filePath.split("/");
    for (let length = 1; length < parts.length; length += 1) {
      const directory = parts.slice(0, length).join("/");
      if (archiveRoots.some((root) => directory === root || directory.startsWith(`${root}/`))) {
        directories.add(`${directory}/`);
      }
    }
  }
  return [...directories].sort(compareOrdinal);
}

async function copyAuthorizedFile({
  sourceRoot,
  sourceRelativePath,
  stagingRoot,
  archivePath,
  expectedSha256 = null,
  kind,
}) {
  const sourcePath = await assertSafeRegularFile(sourceRoot, sourceRelativePath, `${kind} release file`);
  const beforeHash = await sha256File(sourcePath);
  if (expectedSha256 && beforeHash !== expectedSha256) {
    fail(`${kind} SHA-256 mismatch before staging: ${sourceRelativePath}`);
  }

  const destinationPath = resolveInside(stagingRoot, archivePath, "archive path");
  await mkdir(path.dirname(destinationPath), { recursive: true });
  await copyFile(sourcePath, destinationPath, fsConstants.COPYFILE_EXCL);
  const destinationState = await lstat(destinationPath);
  if (!destinationState.isFile() || destinationState.isSymbolicLink()) {
    fail(`staged release member is not a regular file: ${archivePath}`);
  }
  const destinationHash = await sha256File(destinationPath);
  const afterHash = await sha256File(sourcePath);
  if (beforeHash !== destinationHash || beforeHash !== afterHash) {
    fail(`release input changed while staging: ${sourceRelativePath}`);
  }
  return {
    archivePath,
    kind,
    sha256: beforeHash,
    sourcePath: sourceRelativePath,
  };
}

async function writeJsonAtomic(targetPath, value) {
  await mkdir(path.dirname(targetPath), { recursive: true });
  const temporaryPath = `${targetPath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  await rename(temporaryPath, targetPath);
}

async function stageRelease(projectRootArgument, receiptArgument) {
  if (process.env[LEGACY_LISTENING_SWITCH] && process.env[LEGACY_LISTENING_SWITCH] !== "0") {
    fail(`${LEGACY_LISTENING_SWITCH} is no longer supported; private Listening resources must use the separate runtime/deployment flow`);
  }

  const projectRoot = path.resolve(projectRootArgument);
  const receiptPath = path.resolve(receiptArgument);
  const projectRootState = await assertNoReparsePoint(projectRoot, ".");
  if (!projectRootState.isDirectory()) {
    fail(`project root must be a directory: ${projectRoot}`);
  }

  const manifestPath = path.join(projectRoot, ...MANIFEST_RELATIVE_PATH.split("/"));
  const manifestFilePath = await assertSafeRegularFile(projectRoot, MANIFEST_RELATIVE_PATH, "standalone release manifest");
  const manifestSource = await readFile(manifestFilePath, "utf8");
  let manifestJson;
  try {
    manifestJson = JSON.parse(manifestSource);
  } catch (error) {
    fail(`standalone release manifest contains malformed JSON: ${error.message}`);
  }
  const manifest = validateMainManifest(manifestJson);

  await assertManagedRootDrift(projectRoot, manifest);
  for (const relativePath of manifest.files) {
    await assertSafeRegularFile(projectRoot, relativePath, "main manifest file");
  }
  for (const relativePath of manifest.requiredFiles) {
    await assertSafeRegularFile(projectRoot, relativePath, "required release file");
  }

  const reading = await loadReadingAuthorization(projectRoot);
  const gitRoot = await detectGitRepository(projectRoot);
  const provenancePaths = [MANIFEST_RELATIVE_PATH, ...manifest.files];
  if (gitRoot) {
    assertGitTrackedAndClean(projectRoot, provenancePaths);
  }

  let temporaryRoot = null;
  try {
    temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "ielts-standalone-release-"));
    const stagingRoot = path.join(temporaryRoot, "payload");
    await mkdir(stagingRoot);
    const mappings = [];

    for (const relativePath of manifest.files) {
      mappings.push(await copyAuthorizedFile({
        sourceRoot: projectRoot,
        sourceRelativePath: relativePath,
        stagingRoot,
        archivePath: relativePath,
        kind: "default",
      }));
    }
    for (const entry of reading.files) {
      const archivePath = `${READING_ROOT}/${entry.path}`;
      validateRelativePath(archivePath, "ReadingPractice archive path");
      mappings.push(await copyAuthorizedFile({
        sourceRoot: path.join(projectRoot, READING_ROOT),
        sourceRelativePath: entry.path,
        stagingRoot,
        archivePath,
        expectedSha256: entry.sha256,
        kind: "reading",
      }));
    }

    if (gitRoot) {
      assertGitTrackedAndClean(projectRoot, provenancePaths);
    }

    mappings.sort((left, right) => compareOrdinal(left.archivePath, right.archivePath));
    const head = gitRoot
      ? runGit(projectRoot, ["rev-parse", "HEAD"]).stdout.toString("utf8").trim()
      : null;
    const receipt = {
      schemaVersion: SCHEMA_VERSION,
      createdAt: new Date().toISOString(),
      sourceRoot: projectRoot,
      git: { repository: Boolean(gitRoot), head },
      mainManifest: {
        path: MANIFEST_RELATIVE_PATH,
        sha256: await sha256Text(manifestSource),
        fileCount: manifest.files.length,
      },
      managedRoots: manifest.managedRoots,
      nonReleaseFiles: manifest.nonReleaseFiles,
      requiredFiles: manifest.requiredFiles,
      effectiveDefaultFiles: manifest.files,
      readingManifest: reading.manifestPath
        ? { path: reading.manifestPath, sha256: reading.manifestSha256 }
        : null,
      effectiveReadingFiles: reading.files.map((entry) => `${READING_ROOT}/${entry.path}`),
      archiveDirectories: archiveDirectories(
        mappings.map((entry) => entry.archivePath),
        [...manifest.managedRoots, ...(reading.files.length > 0 ? [READING_ROOT] : [])],
      ),
      files: mappings,
    };
    await writeJsonAtomic(receiptPath, receipt);
    process.stdout.write(`${stagingRoot.split(path.sep).join("/")}\n`);
  } catch (error) {
    if (temporaryRoot) {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
    throw error;
  }
}

async function printArchivePaths(receiptPath) {
  const receipt = await readJson(path.resolve(receiptPath), "release receipt");
  assertPlainObject(receipt, "release receipt");
  if (!Array.isArray(receipt.archiveDirectories) || !Array.isArray(receipt.files)) {
    fail("release receipt is missing archiveDirectories or files");
  }
  const paths = [
    ...receipt.archiveDirectories,
    ...receipt.files.map((entry) => entry.archivePath),
  ];
  process.stdout.write(`${paths.join("\n")}\n`);
}

function validateArchiveEntry(entry) {
  const isDirectory = entry.endsWith("/");
  const pathValue = isDirectory ? entry.slice(0, -1) : entry;
  validateRelativePath(pathValue, "archive entry");
  assertDefenseInDepthPath(pathValue, "archive entry");
  return { isDirectory, pathValue };
}

async function verifyArchiveList(receiptPath, archiveListPath) {
  const receipt = await readJson(path.resolve(receiptPath), "release receipt");
  assertPlainObject(receipt, "release receipt");
  const source = (await readFile(path.resolve(archiveListPath), "utf8")).replace(/^\uFEFF/u, "");
  const actual = source.split(/\r?\n/u).filter(Boolean);
  const exact = new Set();
  const portable = new Set();
  for (const entry of actual) {
    validateArchiveEntry(entry);
    const folded = entry.toLowerCase();
    if (exact.has(entry) || portable.has(folded)) {
      fail(`release archive contains a duplicate or case-colliding entry: ${entry}`);
    }
    exact.add(entry);
    portable.add(folded);
  }

  const expected = [
    ...receipt.archiveDirectories,
    ...receipt.files.map((entry) => entry.archivePath),
  ];
  const expectedSet = new Set(expected);
  const missing = expected.filter((entry) => !exact.has(entry));
  const unexpected = actual.filter((entry) => !expectedSet.has(entry));
  if (missing.length > 0 || unexpected.length > 0) {
    fail(`release archive membership differs from the receipt; missing=${missing.join(", ") || "none"}; unexpected=${unexpected.join(", ") || "none"}`);
  }
}

async function main() {
  const { command, options } = parseOptions(process.argv.slice(2));
  if (command === "stage") {
    await stageRelease(
      requiredOption(options, "--project-root"),
      requiredOption(options, "--receipt"),
    );
    return;
  }
  if (command === "archive-paths") {
    await printArchivePaths(requiredOption(options, "--receipt"));
    return;
  }
  if (command === "verify-archive-list") {
    await verifyArchiveList(
      requiredOption(options, "--receipt"),
      requiredOption(options, "--archive-list"),
    );
    return;
  }
  fail(`unknown command: ${command}`);
}

main().catch((error) => {
  process.stderr.write(`ERROR: ${error.message}\n`);
  process.exitCode = 1;
});
