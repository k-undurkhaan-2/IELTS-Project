#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import {
  ARCHIVE_FORMAT,
  BLOCK_SIZE,
  END_BLOCK_COUNT,
  compareOrdinal,
  noFollowFlag,
  paddingLength,
  parseUstarHeader,
  readExactly,
  readForEof,
  registerArchiveMemberPath,
  requireHeaderMatchesMember,
  requireZeroBuffer,
  safeAddLength,
  validateExistingArchiveBoundary,
  validateParentChain,
  verifyArchivePathIdentity,
  verifyRegularArchiveState,
} from "./public-source-archive-core.mjs";

const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const PAYLOAD_CHUNK_SIZE = 64 * 1024;

const ERROR_MESSAGES = Object.freeze({
  CLI: "invalid command line or imported API options",
  MEMBERSHIP: "public source membership validation failed",
  OUTPUT_PARENT: "archive input boundary validation failed",
  TEMP_CREATE: "temporary archive creation failed",
  ARCHIVE_HEADER: "restricted USTAR header validation failed",
  MEMBER_WRITE: "archive member write failed",
  ARCHIVE_FINALIZE: "archive finalization failed",
  ARCHIVE_VERIFY: "independent archive verification failed",
  PUBLISH: "archive publication failed",
  POST_PUBLISH_VERIFY: "published archive verification failed",
  CLEANUP: "archive cleanup identity validation failed",
});

export class PublicSourceArchiveVerificationError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? "public source archive verification failed");
    this.name = "PublicSourceArchiveVerificationError";
    this.code = code;
  }
}

function fail(code) {
  throw new PublicSourceArchiveVerificationError(code);
}

function asPhaseError(code, error) {
  return error instanceof PublicSourceArchiveVerificationError
    ? error
    : new PublicSourceArchiveVerificationError(code);
}

async function inPhase(code, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asPhaseError(code, error);
  }
}

function inSynchronousPhase(code, operation) {
  try {
    return operation();
  } catch (error) {
    throw asPhaseError(code, error);
  }
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateMembershipResult(result) {
  if (
    !result
    || typeof result !== "object"
    || typeof result.repoRoot !== "string"
    || !path.isAbsolute(result.repoRoot)
    || !FULL_OBJECT_ID_PATTERN.test(result.sourceCommit)
    || !SHA256_PATTERN.test(result.manifestSha256)
    || !result.report
    || typeof result.report !== "object"
    || !Buffer.isBuffer(result.reportBytes)
    || !Array.isArray(result.members)
    || !Array.isArray(result.report.members)
    || result.report.members.length !== result.members.length
    || result.report.membershipCount !== result.members.length
    || result.report.sourceCommit !== result.sourceCommit
    || result.report.manifestSha256 !== result.manifestSha256
    || result.report.membershipValid !== true
    || result.report.correspondingSourceComplete !== false
    || result.report.publicationBlocked !== true
  ) {
    fail("MEMBERSHIP");
  }
  const reportBytes = Buffer.from(
    JSON.stringify(result.report, null, 2) + "\n",
    "utf8",
  );
  if (!reportBytes.equals(result.reportBytes)) {
    fail("MEMBERSHIP");
  }

  let previousPath = null;
  const seen = new Set();
  for (let index = 0; index < result.members.length; index += 1) {
    const member = result.members[index];
    const projected = result.report.members[index];
    if (
      !member
      || typeof member !== "object"
      || typeof member.path !== "string"
      || !member.path
      || (previousPath !== null && compareOrdinal(previousPath, member.path) >= 0)
      || seen.has(member.path)
      || (member.gitMode !== "100644" && member.gitMode !== "100755")
      || !FULL_OBJECT_ID_PATTERN.test(member.objectId)
      || !Number.isSafeInteger(member.declaredByteSize)
      || member.declaredByteSize < 0
      || !SHA256_PATTERN.test(member.sha256)
      || !Buffer.isBuffer(member.blobBytes)
      || member.blobBytes.length !== member.declaredByteSize
      || sha256Bytes(member.blobBytes) !== member.sha256
      || !projected
      || projected.path !== member.path
      || projected.gitMode !== member.gitMode
      || projected.sha256 !== member.sha256
    ) {
      fail("MEMBERSHIP");
    }
    previousPath = member.path;
    seen.add(member.path);
  }
  return Object.freeze({
    ...result,
    membershipReportSha256: sha256Bytes(result.reportBytes),
  });
}

async function readTracked(handle, length, archiveHash, counter, code) {
  const bytes = await inPhase(code, async () => readExactly(handle, length));
  archiveHash.update(bytes);
  counter.value = inSynchronousPhase(
    code,
    () => safeAddLength(counter.value, bytes.length),
  );
  return bytes;
}

async function parseAndVerifyArchive(handle, membership) {
  const archiveHash = createHash("sha256");
  const counter = { value: 0 };
  const observedNames = new Map();

  for (let index = 0; index < membership.members.length; index += 1) {
    const member = membership.members[index];
    const header = await readTracked(
      handle,
      BLOCK_SIZE,
      archiveHash,
      counter,
      "ARCHIVE_HEADER",
    );
    const parsed = inSynchronousPhase(
      "ARCHIVE_HEADER",
      () => parseUstarHeader(header),
    );
    inSynchronousPhase("ARCHIVE_HEADER", () => {
      registerArchiveMemberPath(parsed.archivePath, observedNames);
      requireHeaderMatchesMember(parsed, member);
    });

    const payloadHash = createHash("sha256");
    let payloadOffset = 0;
    while (payloadOffset < member.declaredByteSize) {
      const chunkLength = Math.min(
        PAYLOAD_CHUNK_SIZE,
        member.declaredByteSize - payloadOffset,
      );
      const chunk = await readTracked(
        handle,
        chunkLength,
        archiveHash,
        counter,
        "ARCHIVE_VERIFY",
      );
      const expected = member.blobBytes.subarray(
        payloadOffset,
        payloadOffset + chunkLength,
      );
      if (!chunk.equals(expected)) {
        fail("ARCHIVE_VERIFY");
      }
      payloadHash.update(chunk);
      payloadOffset += chunk.length;
    }
    if (
      payloadOffset !== member.declaredByteSize
      || payloadHash.digest("hex") !== member.sha256
    ) {
      fail("ARCHIVE_VERIFY");
    }

    const padding = inSynchronousPhase(
      "ARCHIVE_VERIFY",
      () => paddingLength(member.declaredByteSize),
    );
    if (padding > 0) {
      const paddingBytes = await readTracked(
        handle,
        padding,
        archiveHash,
        counter,
        "ARCHIVE_VERIFY",
      );
      inSynchronousPhase(
        "ARCHIVE_VERIFY",
        () => requireZeroBuffer(paddingBytes),
      );
    }
  }

  for (let index = 0; index < END_BLOCK_COUNT; index += 1) {
    const endBlock = await readTracked(
      handle,
      BLOCK_SIZE,
      archiveHash,
      counter,
      "ARCHIVE_VERIFY",
    );
    inSynchronousPhase(
      "ARCHIVE_VERIFY",
      () => requireZeroBuffer(endBlock),
    );
  }
  const trailing = await inPhase(
    "ARCHIVE_VERIFY",
    async () => readForEof(handle),
  );
  if (trailing.bytesRead !== 0) {
    archiveHash.update(trailing.byte.subarray(0, 1));
    counter.value = inSynchronousPhase(
      "ARCHIVE_VERIFY",
      () => safeAddLength(counter.value, 1),
    );
    fail("ARCHIVE_VERIFY");
  }

  return Object.freeze({
    archiveSha256: archiveHash.digest("hex"),
    archiveByteLength: counter.value,
    archiveMemberCount: membership.members.length,
  });
}

async function verifyArchiveHandle(boundary, membership) {
  let handle = null;
  let primaryError = null;
  let parsedResult = null;
  try {
    handle = await inPhase("ARCHIVE_VERIFY", async () => open(
      boundary.targetPath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    ));
    const before = await inPhase(
      "ARCHIVE_VERIFY",
      async () => handle.stat({ bigint: true }),
    );
    inSynchronousPhase("ARCHIVE_VERIFY", () => verifyRegularArchiveState(
      before,
      boundary.identity,
      {
        expectedLength: boundary.byteLength,
        parentIdentity: boundary.parentChain.at(-1).identity,
      },
    ));
    await inPhase("ARCHIVE_VERIFY", async () => verifyArchivePathIdentity(
      boundary.targetPath,
      boundary.identity,
      {
        expectedLength: boundary.byteLength,
        parentIdentity: boundary.parentChain.at(-1).identity,
      },
    ));

    parsedResult = await parseAndVerifyArchive(handle, membership);
    if (parsedResult.archiveByteLength !== boundary.byteLength) {
      fail("ARCHIVE_VERIFY");
    }

    const after = await inPhase(
      "ARCHIVE_VERIFY",
      async () => handle.stat({ bigint: true }),
    );
    inSynchronousPhase("ARCHIVE_VERIFY", () => verifyRegularArchiveState(
      after,
      boundary.identity,
      {
        expectedLength: boundary.byteLength,
        parentIdentity: boundary.parentChain.at(-1).identity,
      },
    ));
    await inPhase("ARCHIVE_VERIFY", async () => {
      await validateParentChain(boundary.parentPath, boundary.parentChain);
      await verifyArchivePathIdentity(
        boundary.targetPath,
        boundary.identity,
        {
          expectedLength: boundary.byteLength,
          parentIdentity: boundary.parentChain.at(-1).identity,
        },
      );
    });
  } catch (error) {
    primaryError = asPhaseError("ARCHIVE_VERIFY", error);
  }

  if (handle) {
    try {
      await handle.close();
    } catch (error) {
      if (!primaryError) {
        primaryError = asPhaseError("ARCHIVE_VERIFY", error);
      }
    }
  }
  if (!primaryError) {
    try {
      await validateParentChain(boundary.parentPath, boundary.parentChain);
      await verifyArchivePathIdentity(
        boundary.targetPath,
        boundary.identity,
        {
          expectedLength: boundary.byteLength,
          parentIdentity: boundary.parentChain.at(-1).identity,
        },
      );
    } catch (error) {
      primaryError = asPhaseError("ARCHIVE_VERIFY", error);
    }
  }
  if (primaryError) {
    throw primaryError;
  }
  return parsedResult;
}

export async function verifyPublicSourceArchive({ repo, commit, archive } = {}) {
  if (
    typeof repo !== "string"
    || !path.isAbsolute(repo)
    || typeof commit !== "string"
    || typeof archive !== "string"
  ) {
    fail("CLI");
  }
  const membership = await inPhase("MEMBERSHIP", async () => (
    validateMembershipResult(
      await loadValidatedPublicSourceMembership({ repo, commit }),
    )
  ));
  const boundary = await inPhase("OUTPUT_PARENT", async () => (
    validateExistingArchiveBoundary(membership.repoRoot, archive)
  ));
  const verified = await verifyArchiveHandle(boundary, membership);

  return Object.freeze({
    sourceCommit: membership.sourceCommit,
    manifestSha256: membership.manifestSha256,
    membershipReportSha256: membership.membershipReportSha256,
    membershipCount: membership.members.length,
    archiveSha256: verified.archiveSha256,
    archiveByteLength: verified.archiveByteLength,
    archiveMemberCount: verified.archiveMemberCount,
    archiveFormat: ARCHIVE_FORMAT,
    membershipValid: true,
    archiveVerified: true,
    correspondingSourceComplete: false,
    publicationBlocked: true,
  });
}

function parseOptions(argv) {
  const allowed = new Set(["--repo", "--commit", "--archive"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (
      !allowed.has(flag)
      || values.has(flag)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      fail("CLI");
    }
    values.set(flag, argv[index + 1]);
    index += 1;
  }
  if (values.size !== allowed.size) {
    fail("CLI");
  }
  return Object.freeze({
    repo: values.get("--repo"),
    commit: values.get("--commit"),
    archive: values.get("--archive"),
  });
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const result = await verifyPublicSourceArchive(options);
  process.stdout.write(JSON.stringify({
    status: "ok",
    mode: "archive-verification",
    sourceCommit: result.sourceCommit,
    manifestSha256: result.manifestSha256,
    membershipReportSha256: result.membershipReportSha256,
    membershipCount: result.membershipCount,
    archiveVerified: result.archiveVerified,
    archiveSha256: result.archiveSha256,
    archiveByteLength: result.archiveByteLength,
    archiveMemberCount: result.archiveMemberCount,
    archiveFormat: result.archiveFormat,
    correspondingSourceComplete: result.correspondingSourceComplete,
    publicationBlocked: result.publicationBlocked,
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
    return comparableCanonicalPath(modulePath) === comparableCanonicalPath(argvPath);
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    const safeError = error instanceof PublicSourceArchiveVerificationError
      ? error
      : new PublicSourceArchiveVerificationError("CLI");
    process.stderr.write(
      "ERROR " + safeError.code + ": " + safeError.message + "\n",
    );
    process.exitCode = 1;
  });
}
