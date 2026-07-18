#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  lstat,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const MANIFEST_PATH = "developer/public-container-context-manifest.json";
const GENERATOR_PATH = "developer/prepare-public-container-context.mjs";
const VERIFIER_PATH = "developer/verify-public-container-context.mjs";
const RECEIPT_NAME = ".ieltmps-public-context.json";
const CANONICAL_COMPOSE_PATH = "backend/docker-compose.yml";
const DOCKERFILE_PATH = "backend/Dockerfile";
const SERVICE_NAME = "app";
const TRANSACTION_ROOT_RELATIVE = ".build/public-container-transactions";
const CONTEXT_DIRECTORY_NAME = "context";
const OVERRIDE_FILE_NAME = "compose.override.yml";
const MAX_CHILD_BUFFER = 512 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 16 * 1024 * 1024;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(message);
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

function resolveInside(rootPath, ...segments) {
  const resolved = path.resolve(rootPath, ...segments);
  if (!isInside(rootPath, resolved)) {
    fail(`transaction path escapes its root: ${segments.join("/")}`);
  }
  return resolved;
}

function sanitizedGitEnvironment(extra = {}) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) {
      environment[key] = value;
    }
  }
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  return { ...environment, ...extra };
}

function stderrSummary(result) {
  if (!result.stderr) {
    return "";
  }
  const text = result.stderr.toString("utf8").trim();
  return text.length > 4096 ? `${text.slice(0, 4096)}...` : text;
}

function runGit(repoRoot, args, { allowFailure = false } = {}) {
  const result = spawnSync("git", ["--no-replace-objects", "-C", repoRoot, ...args], {
    encoding: null,
    env: sanitizedGitEnvironment(),
    maxBuffer: MAX_CHILD_BUFFER,
    shell: false,
    windowsHide: true,
  });
  if (result.error) {
    fail(`git execution failed: ${result.error.message}`);
  }
  if (!allowFailure && result.status !== 0) {
    const stderr = stderrSummary(result);
    fail(`git ${args[0]} failed${stderr ? `: ${stderr}` : ""}`);
  }
  return result;
}

function runNodeScript(scriptPath, args, { cwd, label }) {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd,
    encoding: null,
    env: sanitizedGitEnvironment(),
    maxBuffer: MAX_CHILD_BUFFER,
    shell: false,
    windowsHide: true,
  });
  if (result.error) {
    fail(`${label} failed to execute: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = stderrSummary(result);
    fail(`${label} failed${stderr ? `: ${stderr}` : ""}`);
  }
  return result;
}

function parseOptions(argv) {
  const valueOptions = new Set([
    "--commit",
    "--compose-file",
    "--docker-executable",
    "--repo",
    "--service",
    "--test-before-invoke-hook",
  ]);
  const values = new Map();
  let testMode = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--test-mode") {
      if (testMode) {
        fail("duplicate argument: --test-mode");
      }
      testMode = true;
      continue;
    }
    if (!valueOptions.has(argument) || index + 1 >= argv.length || values.has(argument)) {
      fail(`invalid or duplicate argument: ${argument}`);
    }
    values.set(argument, argv[index + 1]);
    index += 1;
  }

  for (const required of ["--repo", "--commit"]) {
    if (!values.has(required)) {
      fail(`missing required argument: ${required}`);
    }
  }
  if (!testMode && (values.has("--docker-executable") || values.has("--test-before-invoke-hook"))) {
    fail("test-only executable arguments require --test-mode");
  }
  if (testMode && !values.has("--docker-executable")) {
    fail("--test-mode requires --docker-executable");
  }
  return { testMode, values };
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
    fail(`${label} is missing: ${targetPath}`);
  }
  if (state.isSymbolicLink() || !state.isDirectory()) {
    fail(`${label} must be a regular non-reparse directory: ${targetPath}`);
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(`${label} resolves through a symlink, junction, or reparse point: ${targetPath}`);
  }
  return state;
}

async function assertNoReparseFile(targetPath, label) {
  const state = await pathState(targetPath);
  if (!state) {
    fail(`${label} is missing: ${targetPath}`);
  }
  if (state.isSymbolicLink() || !state.isFile()) {
    fail(`${label} must be a regular non-reparse file: ${targetPath}`);
  }
  const resolved = await realpath(targetPath);
  if (canonicalNativePath(resolved) !== canonicalNativePath(targetPath)) {
    fail(`${label} resolves through a symlink, junction, or reparse point: ${targetPath}`);
  }
  return state;
}

async function readCheckedFile(targetPath, label) {
  const before = await assertNoReparseFile(targetPath, label);
  const bytes = await readFile(targetPath);
  const after = await assertNoReparseFile(targetPath, label);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || after.size !== bytes.length) {
    fail(`${label} changed while it was being read`);
  }
  return bytes;
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
    fail(`--repo must name the exact Git worktree root; Git reported: ${reportedRoot}`);
  }
  return repoRoot;
}

function validateCommit(repoRoot, commitArgument) {
  const lowercase = typeof commitArgument === "string" ? commitArgument.toLowerCase() : "";
  const uppercase = typeof commitArgument === "string" ? commitArgument.toUpperCase() : "";
  if (!COMMIT_PATTERN.test(lowercase)
      || (commitArgument !== lowercase && commitArgument !== uppercase)) {
    fail("--commit must be a full all-lowercase or all-uppercase 40-character hexadecimal commit id");
  }
  const commit = lowercase;
  const type = runGit(repoRoot, ["cat-file", "-t", commit]).stdout.toString("ascii").trim();
  if (type !== "commit") {
    fail("--commit must identify an original commit object");
  }
  const resolved = runGit(repoRoot, ["rev-parse", "--verify", `${commit}^{commit}`])
    .stdout.toString("ascii").trim().toLowerCase();
  if (resolved !== commit) {
    fail("--commit did not resolve to the exact original commit object");
  }
  return commit;
}

function selectedBlobSha256(repoRoot, commit, relativePath) {
  const listing = runGit(repoRoot, ["ls-tree", "-z", commit, "--", relativePath]).stdout;
  if (listing.length === 0 || listing.at(-1) !== 0) {
    fail(`selected commit is missing ${relativePath}`);
  }
  const records = listing.subarray(0, listing.length - 1).toString("utf8").split("\0");
  if (records.length !== 1) {
    fail(`selected commit has an ambiguous ${relativePath}`);
  }
  const tab = records[0].indexOf("\t");
  if (tab < 0 || records[0].slice(tab + 1) !== relativePath) {
    fail(`selected commit has a malformed ${relativePath} entry`);
  }
  const [mode, type, objectId, ...extra] = records[0].slice(0, tab).split(" ");
  if (extra.length !== 0
      || (mode !== "100644" && mode !== "100755")
      || type !== "blob"
      || !COMMIT_PATTERN.test(objectId)) {
    fail(`selected commit ${relativePath} must be a regular blob`);
  }
  const manifestBytes = runGit(repoRoot, ["cat-file", "blob", objectId]).stdout;
  return sha256Bytes(manifestBytes);
}

async function validateCanonicalCompose(repoRoot, composeArgument) {
  const canonicalPath = path.join(repoRoot, ...CANONICAL_COMPOSE_PATH.split("/"));
  const requestedPath = composeArgument
    ? path.resolve(repoRoot, composeArgument)
    : canonicalPath;
  if (canonicalNativePath(requestedPath) !== canonicalNativePath(canonicalPath)) {
    fail(`--compose-file may only select ${CANONICAL_COMPOSE_PATH}`);
  }
  await assertNoReparseFile(canonicalPath, "canonical Compose file");
  const result = runGit(repoRoot, ["ls-files", "--error-unmatch", "--", CANONICAL_COMPOSE_PATH]);
  if (result.stdout.toString("utf8").trim() !== CANONICAL_COMPOSE_PATH) {
    fail("canonical Compose file is not tracked at its fixed path");
  }
  return canonicalPath;
}

async function ensureChildDirectory(parentPath, childName, label) {
  await assertNoReparseDirectory(parentPath, `${label} parent`);
  const childPath = resolveInside(parentPath, childName);
  const existing = await pathState(childPath);
  if (!existing) {
    try {
      await mkdir(childPath, { recursive: false });
    } catch (error) {
      if (!error || error.code !== "EEXIST") {
        throw error;
      }
    }
  }
  await assertNoReparseDirectory(childPath, label);
  return childPath;
}

async function createTransaction(repoRoot) {
  const buildRoot = await ensureChildDirectory(repoRoot, ".build", "repository .build directory");
  const transactionParent = await ensureChildDirectory(
    buildRoot,
    "public-container-transactions",
    "public container transaction parent",
  );
  const transactionPath = resolveInside(transactionParent, randomUUID());
  if (await pathState(transactionPath)) {
    fail("new public container transaction path unexpectedly already exists");
  }
  await mkdir(transactionPath, { recursive: false });
  const identity = await assertNoReparseDirectory(transactionPath, "public container transaction");
  if (!isInside(buildRoot, transactionPath) || !isInside(repoRoot, transactionPath)) {
    fail("public container transaction is outside the repository .build root");
  }
  return {
    dev: identity.dev,
    ino: identity.ino,
    parentPath: transactionParent,
    path: transactionPath,
    realPath: await realpath(transactionPath),
  };
}

async function cleanupTransaction(transaction) {
  if (!transaction) {
    return;
  }
  await assertNoReparseDirectory(transaction.parentPath, "public container transaction parent during cleanup");
  const current = await pathState(transaction.path);
  if (!current) {
    return;
  }
  if (current.isSymbolicLink() || !current.isDirectory()) {
    fail("refusing to recursively clean a replaced or reparse transaction path");
  }
  const currentRealPath = await realpath(transaction.path);
  if (canonicalNativePath(currentRealPath) !== canonicalNativePath(transaction.realPath)
      || current.dev !== transaction.dev
      || current.ino !== transaction.ino) {
    fail("refusing to clean a transaction directory whose identity changed");
  }
  await rm(transaction.path, { force: false, recursive: true });
  if (await pathState(transaction.path)) {
    fail("public container transaction cleanup did not remove the transaction");
  }
}

function validateGeneratorResult(result, expected) {
  let value;
  try {
    value = JSON.parse(result.stdout.toString("utf8").trim());
  } catch {
    fail("context generator returned malformed status JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)
      || value.status !== "ok"
      || value.sourceCommit !== expected.commit
      || value.manifestSha256 !== expected.manifestSha256
      || !Number.isSafeInteger(value.fileCount)
      || value.fileCount < 1
      || typeof value.receiptSha256 !== "string"
      || !SHA256_PATTERN.test(value.receiptSha256)
      || typeof value.output !== "string"
      || !path.isAbsolute(value.output)
      || canonicalNativePath(path.resolve(value.output)) !== canonicalNativePath(expected.contextPath)) {
    fail("context generator returned status for an unexpected output or identity");
  }
  return value.receiptSha256;
}

function verifierArguments(contextPath, identities, mode = "--full") {
  return [
    mode,
    "--context",
    contextPath,
    "--expected-commit",
    identities.commit,
    "--expected-manifest-sha256",
    identities.manifestSha256,
    "--expected-receipt-sha256",
    identities.receiptSha256,
  ];
}

function yamlSingleQuoted(value) {
  if (typeof value !== "string" || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail("unsafe value for generated Compose override");
  }
  return `'${value.replaceAll("'", "''")}'`;
}

function composeOverride(contextPath, identities) {
  return [
    "services:",
    `  ${SERVICE_NAME}:`,
    "    build:",
    `      context: ${yamlSingleQuoted(contextPath)}`,
    `      dockerfile: ${yamlSingleQuoted(DOCKERFILE_PATH)}`,
    "      args:",
    `        IELTMPS_SOURCE_COMMIT: ${yamlSingleQuoted(identities.commit)}`,
    `        IELTMPS_CONTEXT_MANIFEST_SHA256: ${yamlSingleQuoted(identities.manifestSha256)}`,
    `        IELTMPS_CONTEXT_RECEIPT_SHA256: ${yamlSingleQuoted(identities.receiptSha256)}`,
    "",
  ].join("\n");
}

async function validateTemporaryProgram(programArgument, label) {
  if (!path.isAbsolute(programArgument)) {
    fail(`${label} must be an absolute path inside the temporary directory`);
  }
  const programPath = path.resolve(programArgument);
  await assertNoReparseFile(programPath, label);
  const temporaryRoot = await realpath(os.tmpdir());
  const programRealPath = await realpath(programPath);
  if (!isInside(temporaryRoot, programRealPath)) {
    fail(`${label} must be located beneath the operating-system temporary directory`);
  }
  return programPath;
}

function testProgramCommand(programPath, args) {
  const extension = path.extname(programPath).toLowerCase();
  if (extension === ".js" || extension === ".mjs" || extension === ".cjs") {
    return { executable: process.execPath, args: [programPath, ...args] };
  }
  if (process.platform === "win32" && (extension === ".cmd" || extension === ".bat" || extension === ".ps1")) {
    fail("test programs must be native executables or Node scripts; shell scripts are forbidden");
  }
  return { executable: programPath, args };
}

function runTestHook(hookPath, contextPath, identities, repoRoot) {
  const command = testProgramCommand(hookPath, [contextPath]);
  const result = spawnSync(command.executable, command.args, {
    cwd: repoRoot,
    encoding: null,
    env: sanitizedGitEnvironment({
      IELTMPS_SOURCE_COMMIT: identities.commit,
      IELTMPS_CONTEXT_MANIFEST_SHA256: identities.manifestSha256,
      IELTMPS_CONTEXT_RECEIPT_SHA256: identities.receiptSha256,
      IELTMPS_TEST_CONTEXT: contextPath,
    }),
    maxBuffer: MAX_CHILD_BUFFER,
    shell: false,
    windowsHide: true,
  });
  if (result.error) {
    fail(`test-before-invoke hook failed to execute: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`test-before-invoke hook failed with status ${result.status}`);
  }
}

function runDocker(dockerProgram, dockerArgs, identities, repoRoot, testMode) {
  const command = testMode
    ? testProgramCommand(dockerProgram, dockerArgs)
    : { executable: dockerProgram, args: dockerArgs };
  const result = spawnSync(command.executable, command.args, {
    cwd: repoRoot,
    env: {
      ...process.env,
      IELTMPS_SOURCE_COMMIT: identities.commit,
      IELTMPS_CONTEXT_MANIFEST_SHA256: identities.manifestSha256,
      IELTMPS_CONTEXT_RECEIPT_SHA256: identities.receiptSha256,
    },
    shell: false,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error) {
    fail(`Docker Compose failed to execute: ${result.error.message}`);
  }
  if (!Number.isInteger(result.status)) {
    fail("Docker Compose exited without a numeric status");
  }
  return result.status;
}

async function executeBuild(options) {
  const repoRoot = await validateRepository(options.values.get("--repo"));
  const commit = validateCommit(repoRoot, options.values.get("--commit"));
  const manifestSha256 = selectedBlobSha256(repoRoot, commit, MANIFEST_PATH);
  const verifierSha256 = selectedBlobSha256(repoRoot, commit, VERIFIER_PATH);
  const composePath = await validateCanonicalCompose(repoRoot, options.values.get("--compose-file"));
  const service = options.values.get("--service") || SERVICE_NAME;
  if (service !== SERVICE_NAME) {
    fail(`--service must be exactly ${SERVICE_NAME}`);
  }

  const generatorPath = path.join(repoRoot, ...GENERATOR_PATH.split("/"));
  const trustedVerifierPath = path.join(repoRoot, ...VERIFIER_PATH.split("/"));
  await assertNoReparseFile(generatorPath, "context generator");
  await assertNoReparseFile(trustedVerifierPath, "trusted context verifier");

  let dockerProgram = "docker";
  let testHookPath = null;
  if (options.testMode) {
    dockerProgram = await validateTemporaryProgram(
      options.values.get("--docker-executable"),
      "--docker-executable",
    );
    if (options.values.has("--test-before-invoke-hook")) {
      testHookPath = await validateTemporaryProgram(
        options.values.get("--test-before-invoke-hook"),
        "--test-before-invoke-hook",
      );
    }
  }

  let transaction = null;
  let primaryError = null;
  let dockerStatus = null;
  try {
    transaction = await createTransaction(repoRoot);
    const contextPath = resolveInside(transaction.path, CONTEXT_DIRECTORY_NAME);
    const overridePath = resolveInside(transaction.path, OVERRIDE_FILE_NAME);
    if (await pathState(contextPath)) {
      fail("ephemeral context path unexpectedly already exists");
    }
    if (await pathState(overridePath)) {
      fail("ephemeral Compose override unexpectedly already exists");
    }

    const generatorResult = runNodeScript(
      generatorPath,
      ["--repo", repoRoot, "--commit", commit, "--output", contextPath],
      { cwd: repoRoot, label: "context generator" },
    );
    const generatedReceiptSha256 = validateGeneratorResult(
      generatorResult,
      { commit, contextPath, manifestSha256 },
    );
    await assertNoReparseDirectory(contextPath, "generated ephemeral context");
    const contextVerifierPath = resolveInside(contextPath, ...VERIFIER_PATH.split("/"));
    const assertCommitOwnedVerifier = async () => {
      const bytes = await readCheckedFile(contextVerifierPath, "commit-owned context verifier");
      if (sha256Bytes(bytes) !== verifierSha256) {
        fail("commit-owned context verifier SHA-256 mismatch");
      }
    };

    const receiptPath = resolveInside(contextPath, RECEIPT_NAME);
    const receiptBytes = await readCheckedFile(receiptPath, "generated context receipt");
    if (receiptBytes.length > MAX_RECEIPT_BYTES) {
      fail("generated context receipt exceeds the size limit");
    }
    const receiptSha256 = sha256Bytes(receiptBytes);
    if (!SHA256_PATTERN.test(receiptSha256)) {
      fail("generated context receipt identity is invalid");
    }
    if (receiptSha256 !== generatedReceiptSha256) {
      fail("generated context receipt changed after generator publication");
    }
    const identities = { commit, manifestSha256, receiptSha256 };

    await assertCommitOwnedVerifier();
    runNodeScript(trustedVerifierPath, verifierArguments(contextPath, identities), {
      cwd: repoRoot,
      label: "full context verification",
    });

    if (testHookPath) {
      runTestHook(testHookPath, contextPath, identities, repoRoot);
    }

    await assertCommitOwnedVerifier();
    runNodeScript(trustedVerifierPath, verifierArguments(contextPath, identities), {
      cwd: repoRoot,
      label: "immediate pre-invocation context re-verification",
    });

    await writeFile(overridePath, composeOverride(contextPath, identities), {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await assertNoReparseFile(overridePath, "ephemeral Compose override");

    const dockerArgs = [
      "compose",
      "-f",
      composePath,
      "-f",
      overridePath,
      "build",
      SERVICE_NAME,
    ];
    dockerStatus = runDocker(dockerProgram, dockerArgs, identities, repoRoot, options.testMode);
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await cleanupTransaction(transaction);
    } catch (cleanupError) {
      primaryError = primaryError
        ? new Error(`${primaryError.message}; transaction cleanup failed: ${cleanupError.message}`)
        : cleanupError;
    }
  }

  if (primaryError) {
    throw primaryError;
  }
  return dockerStatus;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const status = await executeBuild(options);
  process.exitCode = status;
}

main().catch((error) => {
  process.stderr.write(`ERROR: ${error.message}\n`);
  process.exitCode = 1;
});
