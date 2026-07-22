#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MAX_ARTIFACTS,
  RECEIPT_KIND,
  SCHEMA_VERSION,
  PublicSourceReceiptError,
  buildPublicSourceReceipt,
  cleanupVerifiedToolDirectory,
  encodeCanonicalReceipt,
  failReceipt,
  hashArtifactInputs,
  invokeTestCheckpoint,
  materializeVerifiedToolDirectory,
  modulePathFromUrl,
  normalizeGeneratorTestHooks,
  publishCanonicalReceipt,
  requireCriticalFilesEqual,
  rollbackPublishedReceipt,
  runVerifiedToolWorker,
  sha256Bytes,
  validateFullCommit,
  validateRepositoryRoot,
  verifyToolingBootstrap,
  verifyToolingCommitSignature,
} from "./public-source-receipt-core.mjs";

const ENTRY_RELATIVE_PATH = "developer/prepare-public-source-receipt.mjs";
const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failReceipt("CLI", "api-options-object");
  }
  const allowed = new Set([
    "repo",
    "sourceCommit",
    "toolingCommit",
    "sourceArchive",
    "artifacts",
    "output",
    "testHooks",
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failReceipt("CLI", "api-option-key");
    }
  }
  if (
    typeof options.repo !== "string"
    || typeof options.sourceCommit !== "string"
    || !FULL_OBJECT_ID_PATTERN.test(options.sourceCommit)
    || typeof options.toolingCommit !== "string"
    || !FULL_OBJECT_ID_PATTERN.test(options.toolingCommit)
    || typeof options.sourceArchive !== "string"
    || typeof options.output !== "string"
    || !Array.isArray(options.artifacts)
    || options.artifacts.length < 1
    || options.artifacts.length > MAX_ARTIFACTS
  ) {
    failReceipt("CLI", "api-required-option");
  }
  return Object.freeze({
    repo: options.repo,
    sourceCommit: options.sourceCommit,
    toolingCommit: options.toolingCommit,
    sourceArchive: options.sourceArchive,
    artifacts: Object.freeze([...options.artifacts]),
    output: options.output,
    hooks: normalizeGeneratorTestHooks(options.testHooks),
  });
}

function requireGeneratedVerification(
  result,
  {
    sourceCommit,
    toolingCommit,
    artifactCount,
    receiptSha256,
    receiptByteLength,
  },
) {
  if (
    !result
    || result.status !== "ok"
    || result.mode !== "full"
    || result.verificationComplete !== true
    || result.sourceCommit !== sourceCommit
    || result.toolingCommit !== toolingCommit
    || result.artifactCount !== artifactCount
    || result.receiptSha256 !== receiptSha256
    || result.receiptByteLength !== receiptByteLength
    || result.sourceArchiveVerified !== true
    || result.toolingCommitSignatureValid !== true
    || result.artifactsVerified !== true
    || result.correspondingSourceComplete !== false
    || result.publicationBlocked !== true
  ) {
    failReceipt("RECEIPT_VERIFY", "generated-receipt-binding");
  }
}

async function preparePublicSourceReceiptInternal(options, invocationPath) {
  const validated = validateApiOptions(options);
  const repoRoot = await validateRepositoryRoot(validated.repo);
  validateFullCommit(repoRoot, validated.toolingCommit, "TOOLING");

  const bootstrap = await verifyToolingBootstrap({
    repo: repoRoot,
    toolingCommit: validated.toolingCommit,
    entryRelativePath: ENTRY_RELATIVE_PATH,
    entryModulePath: modulePathFromUrl(import.meta.url),
    invocationPath,
  });
  await verifyToolingCommitSignature(
    repoRoot,
    validated.toolingCommit,
    validated.hooks,
  );

  let toolDirectory = null;
  let publication = null;
  let primaryError = null;
  let success = null;
  try {
    toolDirectory = await materializeVerifiedToolDirectory(bootstrap.records);
    await invokeTestCheckpoint(
      validated.hooks,
      "before-source-worker",
      Object.freeze({ sourceCommit: validated.sourceCommit }),
      "SOURCE_ARCHIVE",
    );
    const sourceVerification = runVerifiedToolWorker(toolDirectory, {
      operation: "source",
      toolRoot: toolDirectory.rootPath,
      criticalFiles: bootstrap.criticalFiles,
      repo: repoRoot,
      sourceCommit: validated.sourceCommit,
      sourceArchive: validated.sourceArchive,
    });
    await invokeTestCheckpoint(
      validated.hooks,
      "after-source-worker",
      Object.freeze({ sourceCommit: validated.sourceCommit }),
      "SOURCE_ARCHIVE",
    );
    if (sourceVerification.sourceCommit !== validated.sourceCommit) {
      failReceipt("SOURCE_ARCHIVE", "source-commit-binding");
    }

    const artifacts = await hashArtifactInputs(
      repoRoot,
      validated.artifacts,
      validated.hooks,
    );
    const receipt = buildPublicSourceReceipt({
      sourceVerification,
      toolingCommit: validated.toolingCommit,
      criticalFiles: bootstrap.criticalFiles,
      artifacts,
    });
    requireCriticalFilesEqual(
      receipt.tooling.criticalFiles,
      bootstrap.criticalFiles,
      "TOOLING",
    );
    const receiptBytes = encodeCanonicalReceipt(receipt);
    const receiptSha256 = sha256Bytes(receiptBytes);
    const receiptByteLength = receiptBytes.length;

    const verifyAt = async (receiptPath) => runVerifiedToolWorker(toolDirectory, {
      operation: "verify",
      toolRoot: toolDirectory.rootPath,
      criticalFiles: bootstrap.criticalFiles,
      mode: "full",
      repo: repoRoot,
      receipt: receiptPath,
      sourceArchive: validated.sourceArchive,
      artifacts: validated.artifacts,
    });

    publication = await publishCanonicalReceipt({
      repoRoot,
      output: validated.output,
      receiptBytes,
      verifyTemporary: verifyAt,
      verifyFinal: verifyAt,
      hooks: validated.hooks,
    });
    requireGeneratedVerification(publication.temporaryResult, {
      sourceCommit: validated.sourceCommit,
      toolingCommit: validated.toolingCommit,
      artifactCount: artifacts.length,
      receiptSha256,
      receiptByteLength,
    });
    requireGeneratedVerification(publication.finalResult, {
      sourceCommit: validated.sourceCommit,
      toolingCommit: validated.toolingCommit,
      artifactCount: artifacts.length,
      receiptSha256,
      receiptByteLength,
    });

    success = Object.freeze({
      status: "ok",
      mode: "receipt-creation",
      receiptKind: RECEIPT_KIND,
      schemaVersion: SCHEMA_VERSION,
      sourceCommit: validated.sourceCommit,
      toolingCommit: validated.toolingCommit,
      artifactCount: artifacts.length,
      receiptCreated: true,
      receiptVerified: true,
      receiptSha256,
      receiptByteLength,
      sourceArchiveVerified: true,
      toolingCommitSignatureValid: true,
      artifactsVerified: true,
      correspondingSourceComplete: false,
      publicationBlocked: true,
    });
  } catch (error) {
    primaryError = error;
  }

  if (toolDirectory) {
    try {
      await cleanupVerifiedToolDirectory(toolDirectory);
    } catch {
      if (publication) {
        try {
          await rollbackPublishedReceipt(publication);
        } catch {
          throw new PublicSourceReceiptError("CLEANUP", "tool-and-receipt-cleanup");
        }
      }
      throw new PublicSourceReceiptError("CLEANUP", "verified-tool-cleanup");
    }
  }
  if (primaryError) {
    if (publication) {
      try {
        await rollbackPublishedReceipt(publication);
      } catch {
        throw new PublicSourceReceiptError("CLEANUP", "receipt-rollback");
      }
    }
    throw primaryError;
  }
  return success;
}

export async function preparePublicSourceReceipt(options = {}) {
  return preparePublicSourceReceiptInternal(options, undefined);
}

function parseOptions(argv) {
  const singletonFlags = new Set([
    "--repo",
    "--source-commit",
    "--tooling-commit",
    "--source-archive",
    "--output",
  ]);
  const singleton = new Map();
  const artifacts = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--artifact") {
      if (index + 3 >= argv.length) {
        failReceipt("CLI", "artifact-arity");
      }
      artifacts.push(Object.freeze({
        role: argv[index + 1],
        format: argv[index + 2],
        path: argv[index + 3],
      }));
      index += 3;
      continue;
    }
    if (
      !singletonFlags.has(argument)
      || singleton.has(argument)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      failReceipt("CLI", "unknown-or-duplicate-option");
    }
    singleton.set(argument, argv[index + 1]);
    index += 1;
  }
  if (
    singleton.size !== singletonFlags.size
    || artifacts.length < 1
    || artifacts.length > MAX_ARTIFACTS
  ) {
    failReceipt("CLI", "required-options");
  }
  return Object.freeze({
    repo: singleton.get("--repo"),
    sourceCommit: singleton.get("--source-commit"),
    toolingCommit: singleton.get("--tooling-commit"),
    sourceArchive: singleton.get("--source-archive"),
    artifacts: Object.freeze(artifacts),
    output: singleton.get("--output"),
  });
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const result = await preparePublicSourceReceiptInternal(options, process.argv[1]);
  process.stdout.write(JSON.stringify(result) + "\n");
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const argvEntry = process.argv[1];
  if (typeof argvEntry !== "string" || argvEntry.length === 0) {
    return false;
  }
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(argvEntry));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceReceiptError
      ? error
      : new PublicSourceReceiptError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.message + "\n");
    process.exitCode = 1;
  });
}
