#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import { link, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";
import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  ARCHIVE_FORMAT,
  BLOCK_SIZE,
  END_BLOCK_COUNT,
  archivePathForMember,
  compareOrdinal,
  encodeUstarHeader,
  identityFromState,
  identityMatches,
  isInside,
  noFollowFlag,
  paddingLength,
  pathState,
  pathsEqual,
  registerArchiveMemberPath,
  safeAddLength,
  validateOutputArchiveBoundary,
  validateParentChain,
  validateTemporaryBasename,
  verifyArchivePathIdentity,
  verifyRegularArchiveState,
} from "./public-source-archive-core.mjs";

const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const TEMPORARY_RANDOM_PATTERN = /^[0-9a-f]{32}$/u;
const TEMPORARY_CREATE_RETRIES = 8;

const CHECKPOINTS = Object.freeze(new Set([
  "before-temp-create-attempt",
  "after-temp-create",
  "after-member-header",
  "after-member-payload",
  "before-finalize",
  "before-file-datasync",
  "before-file-sync",
  "before-file-close",
  "after-finalize",
  "before-verify",
  "after-verify",
  "before-publish",
  "after-final-absence-check",
  "after-link",
  "after-publish",
]));

const ERROR_MESSAGES = Object.freeze({
  CLI: "invalid command line or imported API options",
  MEMBERSHIP: "public source membership validation failed",
  OUTPUT_PARENT: "stable ordinary local output parent validation failed",
  TEMP_CREATE: "exclusive temporary archive creation failed",
  ARCHIVE_HEADER: "restricted USTAR header construction failed",
  MEMBER_WRITE: "exact archive member write failed",
  ARCHIVE_FINALIZE: "archive finalization and file sync failed",
  ARCHIVE_VERIFY: "independent pre-publication archive verification failed",
  PUBLISH: "same-parent archive publication failed",
  POST_PUBLISH_VERIFY: "published archive verification failed",
  CLEANUP: "identity-verified archive cleanup could not be completed safely",
});

export class PublicSourceArchiveCreationError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? "public source archive creation failed");
    this.name = "PublicSourceArchiveCreationError";
    this.code = code;
  }
}

function fail(code) {
  throw new PublicSourceArchiveCreationError(code);
}

function asPhaseError(code, error) {
  return error instanceof PublicSourceArchiveCreationError
    ? error
    : new PublicSourceArchiveCreationError(code);
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
  const deterministicReportBytes = Buffer.from(
    JSON.stringify(result.report, null, 2) + "\n",
    "utf8",
  );
  if (!deterministicReportBytes.equals(result.reportBytes)) {
    fail("MEMBERSHIP");
  }

  let previousPath = null;
  const seenPaths = new Set();
  const archiveRegistry = new Map();
  let expectedArchiveLength = 0;
  for (let index = 0; index < result.members.length; index += 1) {
    const member = result.members[index];
    const projected = result.report.members[index];
    if (
      !member
      || typeof member !== "object"
      || typeof member.path !== "string"
      || !member.path
      || (previousPath !== null && compareOrdinal(previousPath, member.path) >= 0)
      || seenPaths.has(member.path)
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
    inSynchronousPhase("ARCHIVE_HEADER", () => {
      registerArchiveMemberPath(archivePathForMember(member.path), archiveRegistry);
      encodeUstarHeader({
        relativePath: member.path,
        gitMode: member.gitMode,
        size: member.declaredByteSize,
      });
    });
    expectedArchiveLength = inSynchronousPhase(
      "ARCHIVE_HEADER",
      () => safeAddLength(expectedArchiveLength, BLOCK_SIZE),
    );
    expectedArchiveLength = inSynchronousPhase(
      "ARCHIVE_HEADER",
      () => safeAddLength(expectedArchiveLength, member.declaredByteSize),
    );
    expectedArchiveLength = inSynchronousPhase(
      "ARCHIVE_HEADER",
      () => safeAddLength(
        expectedArchiveLength,
        paddingLength(member.declaredByteSize),
      ),
    );
    previousPath = member.path;
    seenPaths.add(member.path);
  }
  expectedArchiveLength = inSynchronousPhase(
    "ARCHIVE_HEADER",
    () => safeAddLength(
      expectedArchiveLength,
      BLOCK_SIZE * END_BLOCK_COUNT,
    ),
  );
  return Object.freeze({
    ...result,
    membershipReportSha256: sha256Bytes(result.reportBytes),
    expectedArchiveLength,
  });
}

async function invokeCheckpoint(testHooks, checkpoint, context, code) {
  if (!CHECKPOINTS.has(checkpoint)) {
    fail(code);
  }
  if (!testHooks) {
    return;
  }
  await inPhase(code, async () => {
    await testHooks(Object.freeze({ checkpoint, ...context }));
  });
}

async function verifyTemporaryIdentity(output, temporary, code, expectedLength = null) {
  await inPhase(code, async () => {
    await validateParentChain(output.parentPath, output.parentChain);
    await verifyArchivePathIdentity(
      temporary.path,
      temporary.identity,
      {
        expectedLength,
        parentIdentity: output.parentChain.at(-1).identity,
      },
    );
  });
}

async function createTemporaryArchive(output, testHooks) {
  for (let attempt = 0; attempt < TEMPORARY_CREATE_RETRIES; attempt += 1) {
    const randomPart = randomBytes(16).toString("hex");
    if (!TEMPORARY_RANDOM_PATTERN.test(randomPart)) {
      fail("TEMP_CREATE");
    }
    const basename = "." + output.finalBasename
      + ".ieltmps-source-archive-tmp-" + randomPart;
    if (!validateTemporaryBasename(output.finalBasename, basename)) {
      fail("TEMP_CREATE");
    }
    const temporaryPath = path.join(output.parentPath, basename);
    if (
      !isInside(output.parentPath, temporaryPath)
      || !pathsEqual(path.dirname(temporaryPath), output.parentPath)
    ) {
      fail("TEMP_CREATE");
    }
    await invokeCheckpoint(
      testHooks,
      "before-temp-create-attempt",
      Object.freeze({
        attempt,
        temporaryPath,
        temporaryBasename: basename,
      }),
      "TEMP_CREATE",
    );
    if (await pathState(output.targetPath)) {
      fail("TEMP_CREATE");
    }

    let handle = null;
    let temporary = null;
    try {
      handle = await open(
        temporaryPath,
        FS_CONSTANTS.O_CREAT
          | FS_CONSTANTS.O_EXCL
          | FS_CONSTANTS.O_WRONLY
          | noFollowFlag(),
        0o600,
      );
    } catch (error) {
      if (error && error.code === "EEXIST") {
        continue;
      }
      throw error;
    }

    try {
      const state = await handle.stat({ bigint: true });
      if (
        !state.isFile()
        || state.isSymbolicLink()
        || state.nlink !== 1n
        || state.size !== 0n
      ) {
        fail("TEMP_CREATE");
      }
      const identity = identityFromState(state);
      temporary = Object.freeze({
        path: temporaryPath,
        basename,
        identity,
      });
      verifyRegularArchiveState(
        state,
        identity,
        {
          expectedLength: 0,
          parentIdentity: output.parentChain.at(-1).identity,
        },
      );
      await verifyTemporaryIdentity(output, temporary, "TEMP_CREATE", 0);
      if (await pathState(output.targetPath)) {
        fail("TEMP_CREATE");
      }
      await invokeCheckpoint(
        testHooks,
        "after-temp-create",
        Object.freeze({ temporaryPath, temporaryBasename: basename }),
        "TEMP_CREATE",
      );
      await verifyTemporaryIdentity(output, temporary, "TEMP_CREATE", 0);
      return Object.freeze({ handle, temporary });
    } catch (error) {
      try {
        await handle.close();
      } catch {
        throw new PublicSourceArchiveCreationError("CLEANUP");
      }
      if (!temporary) {
        throw new PublicSourceArchiveCreationError("CLEANUP");
      }
      try {
        await cleanupArchive(output, temporary, {
          finalLinked: false,
          expectedLength: null,
        });
      } catch {
        throw new PublicSourceArchiveCreationError("CLEANUP");
      }
      throw error;
    }
  }
  fail("TEMP_CREATE");
}

async function writeAllTracked(handle, bytes, archiveHash, counter, code) {
  if (!Buffer.isBuffer(bytes)) {
    fail(code);
  }
  let offset = 0;
  while (offset < bytes.length) {
    const result = await inPhase(code, async () => handle.write(
      bytes,
      offset,
      bytes.length - offset,
      null,
    ));
    if (
      !result
      || !Number.isInteger(result.bytesWritten)
      || result.bytesWritten <= 0
      || result.bytesWritten > bytes.length - offset
    ) {
      fail(code);
    }
    const written = bytes.subarray(offset, offset + result.bytesWritten);
    archiveHash.update(written);
    counter.value = inSynchronousPhase(
      code,
      () => safeAddLength(counter.value, written.length),
    );
    offset += result.bytesWritten;
  }
}

async function writeArchive({
  handle,
  temporary,
  output,
  membership,
  testHooks,
}) {
  const archiveHash = createHash("sha256");
  const counter = { value: 0 };

  for (let index = 0; index < membership.members.length; index += 1) {
    const member = membership.members[index];
    if (
      member.blobBytes.length !== member.declaredByteSize
      || sha256Bytes(member.blobBytes) !== member.sha256
    ) {
      fail("MEMBER_WRITE");
    }
    const header = inSynchronousPhase("ARCHIVE_HEADER", () => encodeUstarHeader({
      relativePath: member.path,
      gitMode: member.gitMode,
      size: member.declaredByteSize,
    }));
    await writeAllTracked(handle, header, archiveHash, counter, "MEMBER_WRITE");
    await invokeCheckpoint(
      testHooks,
      "after-member-header",
      Object.freeze({
        memberIndex: index,
        temporaryPath: temporary.path,
        archiveByteLength: counter.value,
      }),
      "MEMBER_WRITE",
    );

    await writeAllTracked(
      handle,
      member.blobBytes,
      archiveHash,
      counter,
      "MEMBER_WRITE",
    );
    await invokeCheckpoint(
      testHooks,
      "after-member-payload",
      Object.freeze({
        memberIndex: index,
        temporaryPath: temporary.path,
        archiveByteLength: counter.value,
      }),
      "MEMBER_WRITE",
    );
    const padding = inSynchronousPhase(
      "MEMBER_WRITE",
      () => paddingLength(member.declaredByteSize),
    );
    if (padding > 0) {
      await writeAllTracked(
        handle,
        Buffer.alloc(padding),
        archiveHash,
        counter,
        "MEMBER_WRITE",
      );
    }
  }

  await invokeCheckpoint(
    testHooks,
    "before-finalize",
    Object.freeze({
      temporaryPath: temporary.path,
      archiveByteLength: counter.value,
    }),
    "ARCHIVE_FINALIZE",
  );
  await writeAllTracked(
    handle,
    Buffer.alloc(BLOCK_SIZE * END_BLOCK_COUNT),
    archiveHash,
    counter,
    "ARCHIVE_FINALIZE",
  );
  if (counter.value !== membership.expectedArchiveLength) {
    fail("ARCHIVE_FINALIZE");
  }

  await invokeCheckpoint(
    testHooks,
    "before-file-datasync",
    Object.freeze({ temporaryPath: temporary.path }),
    "ARCHIVE_FINALIZE",
  );
  await inPhase("ARCHIVE_FINALIZE", async () => handle.datasync());
  await invokeCheckpoint(
    testHooks,
    "before-file-sync",
    Object.freeze({ temporaryPath: temporary.path }),
    "ARCHIVE_FINALIZE",
  );
  await inPhase("ARCHIVE_FINALIZE", async () => handle.sync());
  await invokeCheckpoint(
    testHooks,
    "before-file-close",
    Object.freeze({ temporaryPath: temporary.path }),
    "ARCHIVE_FINALIZE",
  );
  await inPhase("ARCHIVE_FINALIZE", async () => handle.close());
  await verifyTemporaryIdentity(
    output,
    temporary,
    "ARCHIVE_FINALIZE",
    counter.value,
  );
  await invokeCheckpoint(
    testHooks,
    "after-finalize",
    Object.freeze({
      temporaryPath: temporary.path,
      archiveByteLength: counter.value,
    }),
    "ARCHIVE_FINALIZE",
  );
  await verifyTemporaryIdentity(
    output,
    temporary,
    "ARCHIVE_FINALIZE",
    counter.value,
  );

  return Object.freeze({
    archiveSha256: archiveHash.digest("hex"),
    archiveByteLength: counter.value,
  });
}

function requireVerificationMatches(verified, membership, written, code) {
  if (
    !verified
    || typeof verified !== "object"
    || verified.archiveVerified !== true
    || verified.membershipValid !== true
    || verified.sourceCommit !== membership.sourceCommit
    || verified.manifestSha256 !== membership.manifestSha256
    || verified.membershipReportSha256 !== membership.membershipReportSha256
    || verified.membershipCount !== membership.members.length
    || verified.archiveMemberCount !== membership.members.length
    || verified.archiveFormat !== ARCHIVE_FORMAT
    || verified.archiveSha256 !== written.archiveSha256
    || verified.archiveByteLength !== written.archiveByteLength
    || verified.correspondingSourceComplete !== false
    || verified.publicationBlocked !== true
  ) {
    fail(code);
  }
}

function requireArchiveLinkState(
  state,
  expectedIdentity,
  {
    expectedLength,
    expectedLinkCount,
    parentIdentity,
  },
  code,
) {
  const expectedLinks = expectedLinkCount === null
    ? null
    : BigInt(expectedLinkCount);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || !identityMatches(expectedIdentity, state)
    || typeof state.nlink !== "bigint"
    || state.nlink < 1n
    || (expectedLinks !== null && state.nlink !== expectedLinks)
    || state.size < 0n
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
    || (
      expectedLength !== null
      && (
        !Number.isSafeInteger(expectedLength)
        || expectedLength < 0
        || state.size !== BigInt(expectedLength)
      )
    )
    || (
      parentIdentity
      && parentIdentity.meaningful
      && state.dev !== parentIdentity.device
    )
  ) {
    fail(code);
  }
}

async function inspectArchiveLink(
  output,
  targetPath,
  expectedIdentity,
  written,
  expectedLinkCount,
  code,
) {
  await validateParentChain(output.parentPath, output.parentChain);
  const options = Object.freeze({
    expectedLength: written.archiveByteLength,
    expectedLinkCount,
    parentIdentity: output.parentChain.at(-1).identity,
  });
  const beforePathState = await pathState(targetPath);
  requireArchiveLinkState(beforePathState, expectedIdentity, options, code);
  const resolved = await realpath(targetPath);
  if (
    !pathsEqual(resolved, targetPath)
    || !pathsEqual(path.dirname(resolved), output.canonicalParent)
  ) {
    fail(code);
  }

  let handle = null;
  try {
    handle = await open(
      targetPath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const beforeHandleState = await handle.stat({ bigint: true });
    requireArchiveLinkState(beforeHandleState, expectedIdentity, options, code);

    const archiveHash = createHash("sha256");
    let archiveByteLength = 0;
    while (archiveByteLength < written.archiveByteLength) {
      const chunk = Buffer.alloc(
        Math.min(64 * 1024, written.archiveByteLength - archiveByteLength),
      );
      const result = await handle.read(chunk, 0, chunk.length, null);
      if (
        !result
        || !Number.isInteger(result.bytesRead)
        || result.bytesRead <= 0
        || result.bytesRead > chunk.length
      ) {
        fail(code);
      }
      archiveHash.update(chunk.subarray(0, result.bytesRead));
      archiveByteLength = safeAddLength(
        archiveByteLength,
        result.bytesRead,
      );
    }
    const trailing = Buffer.alloc(1);
    const trailingResult = await handle.read(trailing, 0, 1, null);
    if (!trailingResult || trailingResult.bytesRead !== 0) {
      fail(code);
    }

    const afterHandleState = await handle.stat({ bigint: true });
    requireArchiveLinkState(afterHandleState, expectedIdentity, options, code);
    const afterPathState = await pathState(targetPath);
    requireArchiveLinkState(afterPathState, expectedIdentity, options, code);
    if (
      archiveByteLength !== written.archiveByteLength
      || archiveHash.digest("hex") !== written.archiveSha256
    ) {
      fail(code);
    }
  } finally {
    if (handle) {
      await handle.close();
    }
  }
}

async function unlinkVerifiedArchiveLink(
  output,
  temporary,
  written,
  expectedLinkCount,
  code,
) {
  await inspectArchiveLink(
    output,
    temporary.path,
    temporary.identity,
    written,
    expectedLinkCount,
    code,
  );
  await unlink(temporary.path);
  if (await pathState(temporary.path)) {
    fail(code);
  }
}

function cleanupTargetIsAuthorized(output, temporary, targetPath, isFinal) {
  if (isFinal) {
    return pathsEqual(targetPath, output.targetPath)
      && path.basename(targetPath) === output.finalBasename;
  }
  return validateTemporaryBasename(output.finalBasename, temporary.basename)
    && pathsEqual(targetPath, temporary.path)
    && path.basename(targetPath) === temporary.basename
    && pathsEqual(path.dirname(targetPath), output.parentPath)
    && isInside(output.parentPath, targetPath);
}

async function removeKnownArchivePath(
  output,
  temporary,
  targetPath,
  isFinal,
  expectedLength,
) {
  if (!cleanupTargetIsAuthorized(output, temporary, targetPath, isFinal)) {
    return false;
  }
  try {
    await validateParentChain(output.parentPath, output.parentChain);
    const state = await pathState(targetPath);
    if (!state) {
      return true;
    }
    requireArchiveLinkState(
      state,
      temporary.identity,
      {
        expectedLength,
        expectedLinkCount: null,
        parentIdentity: output.parentChain.at(-1).identity,
      },
      "CLEANUP",
    );
    const resolved = await realpath(targetPath);
    if (
      !pathsEqual(resolved, targetPath)
      || !pathsEqual(path.dirname(resolved), output.canonicalParent)
    ) {
      return false;
    }
    await unlink(targetPath);
    return !(await pathState(targetPath));
  } catch {
    return false;
  }
}

async function cleanupArchive(
  output,
  temporary,
  { finalLinked, expectedLength },
) {
  let complete = true;
  if (finalLinked) {
    complete = await removeKnownArchivePath(
      output,
      temporary,
      output.targetPath,
      true,
      expectedLength,
    );
  }
  const temporaryRemoved = await removeKnownArchivePath(
    output,
    temporary,
    temporary.path,
    false,
    expectedLength,
  );
  complete = temporaryRemoved && complete;
  if (!complete) {
    fail("CLEANUP");
  }
}

/*
 * Trusted-parent and crash contract:
 *
 * Portable Node APIs do not lock every ancestor. The caller must provide a
 * stable ordinary local parent that is not concurrently controlled by an
 * adversary. Every ancestor and file identity is revalidated around the
 * same-parent atomic no-replace hard-link publication operation. This writer
 * requires reliable positive link counts from Node stat/lstat and fails closed
 * when the host cannot provide that contract.
 *
 * Caught failures remove only identities proven to be this run's temporary or
 * final archive link. A process crash before hard-link publication may leave a
 * verified random temporary file. A crash after hard-link creation but before
 * temporary unlink may leave both names referring to the same complete,
 * pre-verified archive. After temporary unlink, only the complete final archive
 * remains. No partial final archive is exposed by publication. File datasync
 * and sync improve file durability, but no cross-platform directory-sync or
 * power-loss durability guarantee is made. Stale names require exact manual
 * review; there is deliberately no wildcard cleanup operation.
 */
export async function preparePublicSourceArchive({
  repo,
  commit,
  output,
  testHooks,
  testLink,
} = {}) {
  if (
    typeof repo !== "string"
    || !path.isAbsolute(repo)
    || typeof commit !== "string"
    || typeof output !== "string"
    || (
      typeof testHooks !== "undefined"
      && typeof testHooks !== "function"
    )
    || (
      typeof testLink !== "undefined"
      && typeof testLink !== "function"
    )
  ) {
    fail("CLI");
  }

  const membership = await inPhase("MEMBERSHIP", async () => (
    validateMembershipResult(
      await loadValidatedPublicSourceMembership({ repo, commit }),
    )
  ));
  const outputBoundary = await inPhase("OUTPUT_PARENT", async () => (
    validateOutputArchiveBoundary(membership.repoRoot, output)
  ));

  const publicationLink = testLink ?? link;
  let temporary = null;
  let handle = null;
  let written = null;
  let finalLinked = false;
  try {
    await inPhase("TEMP_CREATE", async () => {
      await validateParentChain(
        outputBoundary.parentPath,
        outputBoundary.parentChain,
      );
      if (await pathState(outputBoundary.targetPath)) {
        fail("TEMP_CREATE");
      }
    });
    const created = await inPhase(
      "TEMP_CREATE",
      async () => createTemporaryArchive(outputBoundary, testHooks),
    );
    temporary = created.temporary;
    handle = created.handle;

    written = await writeArchive({
      handle,
      temporary,
      output: outputBoundary,
      membership,
      testHooks,
    });
    handle = null;

    await invokeCheckpoint(
      testHooks,
      "before-verify",
      Object.freeze({
        temporaryPath: temporary.path,
        archiveByteLength: written.archiveByteLength,
      }),
      "ARCHIVE_VERIFY",
    );
    const prePublishVerification = await inPhase(
      "ARCHIVE_VERIFY",
      async () => verifyPublicSourceArchive({
        repo: membership.repoRoot,
        commit: membership.sourceCommit,
        archive: temporary.path,
      }),
    );
    inSynchronousPhase(
      "ARCHIVE_VERIFY",
      () => requireVerificationMatches(
        prePublishVerification,
        membership,
        written,
        "ARCHIVE_VERIFY",
      ),
    );
    await invokeCheckpoint(
      testHooks,
      "after-verify",
      Object.freeze({
        temporaryPath: temporary.path,
        archiveByteLength: written.archiveByteLength,
      }),
      "ARCHIVE_VERIFY",
    );

    await invokeCheckpoint(
      testHooks,
      "before-publish",
      Object.freeze({
        temporaryPath: temporary.path,
        outputPath: outputBoundary.targetPath,
      }),
      "PUBLISH",
    );
    await inPhase("PUBLISH", async () => {
      await validateParentChain(
        outputBoundary.parentPath,
        outputBoundary.parentChain,
      );
      await verifyArchivePathIdentity(
        temporary.path,
        temporary.identity,
        {
          expectedLength: written.archiveByteLength,
          parentIdentity: outputBoundary.parentChain.at(-1).identity,
        },
      );
      if (await pathState(outputBoundary.targetPath)) {
        fail("PUBLISH");
      }
      await invokeCheckpoint(
        testHooks,
        "after-final-absence-check",
        Object.freeze({
          temporaryPath: temporary.path,
          outputPath: outputBoundary.targetPath,
        }),
        "PUBLISH",
      );
      await publicationLink(temporary.path, outputBoundary.targetPath);
      finalLinked = true;

      await inspectArchiveLink(
        outputBoundary,
        temporary.path,
        temporary.identity,
        written,
        2,
        "PUBLISH",
      );
      await inspectArchiveLink(
        outputBoundary,
        outputBoundary.targetPath,
        temporary.identity,
        written,
        2,
        "PUBLISH",
      );
      await invokeCheckpoint(
        testHooks,
        "after-link",
        Object.freeze({
          temporaryPath: temporary.path,
          outputPath: outputBoundary.targetPath,
          archiveByteLength: written.archiveByteLength,
        }),
        "PUBLISH",
      );
      await inspectArchiveLink(
        outputBoundary,
        temporary.path,
        temporary.identity,
        written,
        2,
        "PUBLISH",
      );
      await inspectArchiveLink(
        outputBoundary,
        outputBoundary.targetPath,
        temporary.identity,
        written,
        2,
        "PUBLISH",
      );
      await unlinkVerifiedArchiveLink(
        outputBoundary,
        temporary,
        written,
        2,
        "PUBLISH",
      );
      await inspectArchiveLink(
        outputBoundary,
        outputBoundary.targetPath,
        temporary.identity,
        written,
        1,
        "PUBLISH",
      );
    });

    await invokeCheckpoint(
      testHooks,
      "after-publish",
      Object.freeze({
        outputPath: outputBoundary.targetPath,
        archiveByteLength: written.archiveByteLength,
      }),
      "POST_PUBLISH_VERIFY",
    );
    const postPublishVerification = await inPhase(
      "POST_PUBLISH_VERIFY",
      async () => verifyPublicSourceArchive({
        repo: membership.repoRoot,
        commit: membership.sourceCommit,
        archive: outputBoundary.targetPath,
      }),
    );
    inSynchronousPhase(
      "POST_PUBLISH_VERIFY",
      () => requireVerificationMatches(
        postPublishVerification,
        membership,
        written,
        "POST_PUBLISH_VERIFY",
      ),
    );
    await inPhase("POST_PUBLISH_VERIFY", async () => {
      await inspectArchiveLink(
        outputBoundary,
        outputBoundary.targetPath,
        temporary.identity,
        written,
        1,
        "POST_PUBLISH_VERIFY",
      );
    });

    return Object.freeze({
      status: "ok",
      mode: "archive-creation",
      sourceCommit: membership.sourceCommit,
      manifestSha256: membership.manifestSha256,
      membershipReportSha256: membership.membershipReportSha256,
      membershipValid: true,
      treeMaterializerAvailable: true,
      archiveCreated: true,
      archiveVerified: true,
      archiveSha256: written.archiveSha256,
      archiveByteLength: written.archiveByteLength,
      archiveMemberCount: membership.members.length,
      archiveFormat: ARCHIVE_FORMAT,
      correspondingSourceComplete: false,
      publicationBlocked: true,
    });
  } catch (error) {
    const primary = error instanceof PublicSourceArchiveCreationError
      ? error
      : new PublicSourceArchiveCreationError("MEMBERSHIP");
    if (handle) {
      try {
        await handle.close();
        handle = null;
      } catch {
        throw new PublicSourceArchiveCreationError("CLEANUP");
      }
    }
    if (temporary) {
      try {
        await cleanupArchive(outputBoundary, temporary, {
          finalLinked,
          expectedLength: written?.archiveByteLength ?? null,
        });
      } catch {
        throw new PublicSourceArchiveCreationError("CLEANUP");
      }
    }
    throw primary;
  }
}

function parseOptions(argv) {
  const allowed = new Set(["--repo", "--commit", "--output"]);
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
    output: values.get("--output"),
  });
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const summary = await preparePublicSourceArchive(options);
  process.stdout.write(JSON.stringify(summary) + "\n");
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
    const safeError = error instanceof PublicSourceArchiveCreationError
      ? error
      : new PublicSourceArchiveCreationError("CLI");
    process.stderr.write(
      "ERROR " + safeError.code + ": " + safeError.message + "\n",
    );
    process.exitCode = 1;
  });
}
