#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ZIP_ARCHIVE_ROOT,
  ZIP_ARTIFACT_ROLE,
  ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE,
  ZIP_FIELD_VALUES,
  ZIP_FORMAT_PROFILE,
  ZIP_LIMITS,
  PublicSourceZipError,
  asPublicSourceZipError,
  canonicalizeHostFilesystemPath,
  crc32Finalize,
  crc32Init,
  crc32Update,
  deepFreezeZip,
  parseCanonicalZipEntryPlanBytes,
} from "./public-source-zip-core.mjs";

export const ZIP_VERIFICATION_KIND =
  "ieltmps-public-source-zip-verification";

const VERIFICATION_RESULT_KEYS = Object.freeze([
  "verificationKind",
  "schemaVersion",
  "status",
  "mode",
  "artifactRole",
  "formatProfile",
  "sourceCommit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archiveRoot",
  "entryPlanSha256",
  "archiveSha256",
  "archiveByteLength",
  "entryCount",
  "centralDirectoryOffset",
  "centralDirectoryByteLength",
  "canonicalProfileVerified",
  "entryPlanVerified",
  "storedPayloadsVerified",
  "crc32Verified",
  "authoritativeCorrespondingSource",
  "verificationComplete",
]);

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CRC32_PATTERN = /^[0-9a-f]{8}$/u;
const FILE_CHUNK_SIZE = ZIP_LIMITS.payloadChunkBytes;

function fail(phase, reason) {
  throw new PublicSourceZipError(phase, reason);
}

function canonicalNativePath(value) {
  const resolved = path.resolve(canonicalizeHostFilesystemPath(value));
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function pathsEqual(left, right) {
  return canonicalNativePath(left) === canonicalNativePath(right);
}

function validateAbsoluteNormalizedPath(value, phase, reason) {
  if (typeof value !== "string") {
    fail(phase, reason + "-absolute");
  }
  const canonicalPath = canonicalizeHostFilesystemPath(value);
  if (!path.isAbsolute(canonicalPath)) {
    fail(phase, reason + "-absolute");
  }
  if (
    value.normalize("NFC") !== value
    || path.normalize(canonicalPath) !== canonicalPath
    || !pathsEqual(path.resolve(canonicalPath), canonicalPath)
  ) {
    fail(phase, reason + "-normalized");
  }
  const resolved = canonicalizeHostFilesystemPath(path.resolve(canonicalPath));
  if (pathsEqual(path.dirname(resolved), resolved)) {
    fail(phase, reason + "-root");
  }
  return resolved;
}

async function pathState(targetPath) {
  const canonicalPath = canonicalizeHostFilesystemPath(targetPath);
  try {
    return await lstat(canonicalPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function resolveRealHostPath(targetPath) {
  const canonicalTarget = canonicalizeHostFilesystemPath(targetPath);
  const realPath = canonicalizeHostFilesystemPath(await realpath(canonicalTarget));
  return canonicalizeHostFilesystemPath(path.resolve(realPath));
}

function identityFromState(state) {
  return Object.freeze({
    device: state.dev,
    inode: state.ino,
    size: state.size,
    links: state.nlink,
    mode: state.mode,
    mtimeNs: state.mtimeNs,
    ctimeNs: state.ctimeNs,
    birthtimeNs: state.birthtimeNs,
    meaningful: state.dev !== 0n || state.ino !== 0n,
  });
}

function identitiesEqual(left, right) {
  return Boolean(left && right)
    && left.device === right.device
    && left.inode === right.inode
    && left.size === right.size
    && left.links === right.links
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs
    && left.meaningful === right.meaningful;
}

function directoryIdentitiesEqual(left, right) {
  return Boolean(left && right)
    && left.device === right.device
    && left.inode === right.inode
    && left.mode === right.mode
    && left.birthtimeNs === right.birthtimeNs
    && left.meaningful === right.meaningful;
}

function parentChainPaths(targetPath) {
  const parentPath = path.dirname(targetPath);
  const root = path.parse(parentPath).root;
  if (!root) fail("PATH_AUTHORITY", "parent-chain-root");
  const values = [path.resolve(root)];
  const relative = path.relative(root, parentPath);
  let current = root;
  if (relative) {
    for (const component of relative.split(path.sep)) {
      if (!component || component === "." || component === "..") {
        fail("PATH_AUTHORITY", "parent-chain-component");
      }
      current = path.join(current, component);
      values.push(path.resolve(current));
    }
  }
  return values;
}

async function inspectRealDirectory(targetPath, phase, reason) {
  const state = await pathState(targetPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    fail(phase, reason + "-directory");
  }
  const resolved = await resolveRealHostPath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    fail(phase, reason + "-reparse");
  }
  const identity = identityFromState(state);
  if (!identity.meaningful) fail(phase, reason + "-identity");
  return Object.freeze({
    path: canonicalizeHostFilesystemPath(path.resolve(targetPath)),
    canonicalPath: canonicalizeHostFilesystemPath(path.resolve(resolved)),
    identity,
  });
}

async function inspectParentChain(targetPath, phase, recorded = null) {
  const paths = parentChainPaths(targetPath);
  const result = [];
  for (let index = 0; index < paths.length; index += 1) {
    const current = await inspectRealDirectory(
      paths[index],
      phase,
      "input-parent",
    );
    if (
      recorded
      && (
        recorded.length !== paths.length
        || !pathsEqual(recorded[index].path, current.path)
        || !pathsEqual(recorded[index].canonicalPath, current.canonicalPath)
        || !directoryIdentitiesEqual(
          recorded[index].identity,
          current.identity,
        )
      )
    ) {
      fail(phase, "input-parent-identity");
    }
    result.push(current);
  }
  return Object.freeze(result);
}

function noFollowFlag() {
  return process.platform !== "win32"
    && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

function requireStableRegularState(state, boundary, phase, reason) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size !== BigInt(boundary.byteLength)
    || !identitiesEqual(boundary.identity, identityFromState(state))
  ) {
    fail(phase, reason);
  }
}

async function inspectStableFileBoundary(
  fileArgument,
  { phase, reason, maximumLength, minimumLength = 0 },
) {
  const targetPath = validateAbsoluteNormalizedPath(
    fileArgument,
    phase,
    reason,
  );
  const parentChain = await inspectParentChain(targetPath, phase);
  const state = await pathState(targetPath);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size < BigInt(minimumLength)
    || state.size > BigInt(maximumLength)
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail(phase, reason + "-state");
  }
  const identity = identityFromState(state);
  if (!identity.meaningful) fail(phase, reason + "-identity");
  const resolved = await resolveRealHostPath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    fail(phase, reason + "-reparse");
  }
  return Object.freeze({
    targetPath,
    parentPath: path.dirname(targetPath),
    parentChain,
    identity,
    byteLength: Number(state.size),
  });
}

async function verifyStableFileBoundary(boundary, phase, reason) {
  await inspectParentChain(boundary.targetPath, phase, boundary.parentChain);
  const state = await pathState(boundary.targetPath);
  requireStableRegularState(state, boundary, phase, reason + "-identity");
  const resolved = await resolveRealHostPath(boundary.targetPath);
  if (!pathsEqual(resolved, boundary.targetPath)) {
    fail(phase, reason + "-reparse");
  }
  return state;
}

function normalizeTestHooks(value) {
  if (value === undefined) return Object.freeze({});
  if (typeof value === "function") {
    return Object.freeze({ checkpoint: value });
  }
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).some((key) => key !== "checkpoint")
    || (
      Object.hasOwn(value, "checkpoint")
      && typeof value.checkpoint !== "function"
    )
  ) {
    fail("CLI", "test-hooks");
  }
  return Object.freeze(
    Object.hasOwn(value, "checkpoint")
      ? { checkpoint: value.checkpoint }
      : {},
  );
}

async function invokeCheckpoint(hooks, checkpoint, kind) {
  if (!hooks.checkpoint) return;
  const returned = await hooks.checkpoint(Object.freeze({ checkpoint, kind }));
  if (returned !== undefined) fail("CLI", "checkpoint-return-value");
}

async function readExactlyAt(handle, length, position, phase, reason) {
  if (
    !Number.isSafeInteger(length)
    || length < 0
    || !Number.isSafeInteger(position)
    || position < 0
  ) {
    fail(phase, reason + "-range");
  }
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const read = await handle.read(
      bytes,
      offset,
      length - offset,
      position + offset,
    );
    if (
      !read
      || !Number.isInteger(read.bytesRead)
      || read.bytesRead <= 0
      || read.bytesRead > length - offset
    ) {
      fail(phase, reason + "-truncated");
    }
    offset += read.bytesRead;
  }
  return bytes;
}

async function readStableCapturedFile(boundary, phase, reason, hooks, kind) {
  let handle = null;
  try {
    handle = await open(
      boundary.targetPath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const before = await handle.stat({ bigint: true });
    requireStableRegularState(before, boundary, phase, reason + "-identity");
    await invokeCheckpoint(hooks, "after-file-open", kind);
    const chunks = [];
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < boundary.byteLength) {
      const length = Math.min(FILE_CHUNK_SIZE, boundary.byteLength - offset);
      const chunk = await readExactlyAt(
        handle,
        length,
        offset,
        phase,
        reason,
      );
      chunks.push(chunk);
      hash.update(chunk);
      offset += chunk.length;
    }
    const eof = await handle.read(Buffer.alloc(1), 0, 1, boundary.byteLength);
    if (!eof || eof.bytesRead !== 0) fail(phase, reason + "-growth");
    const after = await handle.stat({ bigint: true });
    requireStableRegularState(after, boundary, phase, reason + "-identity");
    await invokeCheckpoint(hooks, "after-file-read", kind);
    await verifyStableFileBoundary(boundary, phase, reason);
    return Object.freeze({
      bytes: Buffer.concat(chunks, boundary.byteLength),
      sha256: hash.digest("hex"),
      byteLength: boundary.byteLength,
      boundary,
    });
  } catch (error) {
    throw asPublicSourceZipError(error, phase, reason);
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (error) {
        throw asPublicSourceZipError(error, phase, reason + "-close");
      }
    }
  }
}

export async function readCanonicalZipEntryPlanFile(
  entryPlan,
  testHooks = undefined,
) {
  const hooks = normalizeTestHooks(testHooks);
  const boundary = await inspectStableFileBoundary(entryPlan, {
    phase: "ENTRY_PLAN",
    reason: "entry-plan-file",
    maximumLength: ZIP_LIMITS.maximumCanonicalEntryPlanBytes,
    minimumLength: 1,
  });
  const input = await readStableCapturedFile(
    boundary,
    "ENTRY_PLAN",
    "entry-plan-file",
    hooks,
    "entry-plan",
  );
  let value;
  try {
    value = parseCanonicalZipEntryPlanBytes(input.bytes);
  } catch (error) {
    throw asPublicSourceZipError(error, "ENTRY_PLAN", "entry-plan-invalid");
  }
  return Object.freeze({ ...input, value });
}

function requireFixed16(record, offset, expected, reason) {
  if (record.readUInt16LE(offset) !== expected) {
    fail("ZIP_PROFILE", reason);
  }
}

function requireFixed32(record, offset, expected, reason) {
  if (record.readUInt32LE(offset) !== expected) {
    fail("ZIP_PROFILE", reason);
  }
}

function expectedExternalAttributes(gitMode) {
  return gitMode === "100755"
    ? ZIP_FIELD_VALUES.externalAttributes100755
    : ZIP_FIELD_VALUES.externalAttributes100644;
}

function crc32PlanNumber(value) {
  if (!CRC32_PATTERN.test(value)) fail("ZIP_BINDING", "entry-plan-crc32");
  return Number.parseInt(value, 16) >>> 0;
}

function parseEocd(record, archiveByteLength, plan) {
  if (record.length !== ZIP_LIMITS.endOfCentralDirectoryBytes) {
    fail("ZIP_PARSE", "eocd-length");
  }
  if (record.readUInt32LE(0) !== ZIP_FIELD_VALUES.endOfCentralDirectorySignature) {
    fail("ZIP_PARSE", "eocd-signature");
  }
  requireFixed16(record, 4, ZIP_FIELD_VALUES.diskNumber, "eocd-disk-number");
  requireFixed16(
    record,
    6,
    ZIP_FIELD_VALUES.centralDirectoryDisk,
    "eocd-central-disk",
  );
  const diskEntryCount = record.readUInt16LE(8);
  const entryCount = record.readUInt16LE(10);
  if (
    diskEntryCount !== entryCount
    || entryCount < ZIP_LIMITS.minimumEntryCount
    || entryCount > ZIP_LIMITS.maximumEntryCount
    || entryCount === ZIP_LIMITS.zip16Sentinel
  ) {
    fail("ZIP_PROFILE", "eocd-entry-count");
  }
  requireFixed16(
    record,
    20,
    ZIP_FIELD_VALUES.archiveCommentLength,
    "archive-comment",
  );
  const centralDirectoryByteLength = record.readUInt32LE(12);
  const centralDirectoryOffset = record.readUInt32LE(16);
  if (
    centralDirectoryByteLength > ZIP_LIMITS.maximumZip32Value
    || centralDirectoryOffset > ZIP_LIMITS.maximumZip32Value
    || centralDirectoryByteLength === ZIP_LIMITS.zip32Sentinel
    || centralDirectoryOffset === ZIP_LIMITS.zip32Sentinel
  ) {
    fail("ZIP_PROFILE", "zip64-sentinel");
  }
  const eocdOffset = archiveByteLength - ZIP_LIMITS.endOfCentralDirectoryBytes;
  if (
    BigInt(centralDirectoryOffset) + BigInt(centralDirectoryByteLength)
      !== BigInt(eocdOffset)
  ) {
    fail("ZIP_PARSE", "central-directory-range");
  }
  if (
    entryCount !== plan.entryCount
    || centralDirectoryOffset !== plan.centralDirectoryOffset
    || centralDirectoryByteLength !== plan.centralDirectoryByteLength
    || archiveByteLength !== plan.archiveByteLength
  ) {
    fail("ZIP_BINDING", "eocd-entry-plan-mismatch");
  }
  return Object.freeze({
    entryCount,
    centralDirectoryOffset,
    centralDirectoryByteLength,
    eocdOffset,
  });
}

async function parseCentralDirectory(handle, eocd, plan) {
  const records = [];
  let cursor = eocd.centralDirectoryOffset;
  const boundary = cursor + eocd.centralDirectoryByteLength;
  for (let index = 0; index < eocd.entryCount; index += 1) {
    const planned = plan.entries[index];
    if (cursor !== planned.centralDirectoryRecordOffset) {
      fail("ZIP_BINDING", "central-record-offset");
    }
    if (cursor + ZIP_LIMITS.centralDirectoryRecordFixedBytes > boundary) {
      fail("ZIP_PARSE", "central-record-truncated");
    }
    const fixed = await readExactlyAt(
      handle,
      ZIP_LIMITS.centralDirectoryRecordFixedBytes,
      cursor,
      "ZIP_PARSE",
      "central-record",
    );
    if (fixed.readUInt32LE(0) !== ZIP_FIELD_VALUES.centralDirectorySignature) {
      fail("ZIP_PARSE", "central-signature");
    }
    requireFixed16(fixed, 4, ZIP_FIELD_VALUES.versionMadeBy, "version-made-by");
    requireFixed16(fixed, 6, ZIP_FIELD_VALUES.versionNeeded, "version-needed");
    requireFixed16(
      fixed,
      8,
      ZIP_FIELD_VALUES.generalPurposeFlag,
      "general-purpose-flag",
    );
    requireFixed16(
      fixed,
      10,
      ZIP_FIELD_VALUES.compressionMethod,
      "compression-method",
    );
    requireFixed16(fixed, 12, ZIP_FIELD_VALUES.dosTime, "dos-time");
    requireFixed16(fixed, 14, ZIP_FIELD_VALUES.dosDate, "dos-date");
    const crc32 = fixed.readUInt32LE(16);
    const storedSize = fixed.readUInt32LE(20);
    const uncompressedSize = fixed.readUInt32LE(24);
    const filenameLength = fixed.readUInt16LE(28);
    const extraLength = fixed.readUInt16LE(30);
    const commentLength = fixed.readUInt16LE(32);
    const diskStart = fixed.readUInt16LE(34);
    const internalAttributes = fixed.readUInt16LE(36);
    const externalAttributes = fixed.readUInt32LE(38);
    const localHeaderOffset = fixed.readUInt32LE(42);
    if (
      storedSize > ZIP_LIMITS.maximumZip32Value
      || uncompressedSize > ZIP_LIMITS.maximumZip32Value
      || localHeaderOffset > ZIP_LIMITS.maximumZip32Value
    ) {
      fail("ZIP_PROFILE", "zip64-sentinel");
    }
    if (storedSize !== uncompressedSize) {
      fail("ZIP_PROFILE", "stored-size-mismatch");
    }
    if (
      filenameLength === 0
      || filenameLength > ZIP_LIMITS.maximumArchiveFilenameBytes
      || extraLength !== ZIP_FIELD_VALUES.centralExtraLength
      || commentLength !== ZIP_FIELD_VALUES.fileCommentLength
      || diskStart !== ZIP_FIELD_VALUES.diskStart
      || internalAttributes !== ZIP_FIELD_VALUES.internalAttributes
      || externalAttributes !== expectedExternalAttributes(planned.gitMode)
    ) {
      fail("ZIP_PROFILE", "central-metadata");
    }
    const recordLength = ZIP_LIMITS.centralDirectoryRecordFixedBytes
      + filenameLength + extraLength + commentLength;
    if (cursor + recordLength > boundary) {
      fail("ZIP_PARSE", "central-record-range");
    }
    const filename = await readExactlyAt(
      handle,
      filenameLength,
      cursor + ZIP_LIMITS.centralDirectoryRecordFixedBytes,
      "ZIP_PARSE",
      "central-filename",
    );
    const expectedFilename = Buffer.from(planned.archivePath, "utf8");
    if (!filename.equals(expectedFilename)) {
      fail("ZIP_BINDING", "central-filename");
    }
    if (
      crc32 !== crc32PlanNumber(planned.crc32)
      || storedSize !== planned.byteLength
      || localHeaderOffset !== planned.localHeaderOffset
    ) {
      fail("ZIP_BINDING", "central-entry-plan-mismatch");
    }
    records.push(Object.freeze({
      filename,
      crc32,
      storedSize,
      localHeaderOffset,
      recordOffset: cursor,
    }));
    cursor += recordLength;
  }
  if (cursor !== boundary) {
    fail("ZIP_PARSE", "central-directory-boundary");
  }
  return Object.freeze(records);
}

async function replayLocalRecords(handle, eocd, centralRecords, plan) {
  let cursor = 0;
  for (let index = 0; index < plan.entries.length; index += 1) {
    const planned = plan.entries[index];
    const central = centralRecords[index];
    if (
      cursor !== planned.localHeaderOffset
      || cursor !== central.localHeaderOffset
    ) {
      fail("ZIP_BINDING", "local-header-offset");
    }
    if (cursor + ZIP_LIMITS.localHeaderFixedBytes > eocd.centralDirectoryOffset) {
      fail("ZIP_PARSE", "local-header-range");
    }
    const fixed = await readExactlyAt(
      handle,
      ZIP_LIMITS.localHeaderFixedBytes,
      cursor,
      "ZIP_PARSE",
      "local-header",
    );
    if (fixed.readUInt32LE(0) !== ZIP_FIELD_VALUES.localFileHeaderSignature) {
      fail("ZIP_PARSE", "local-signature");
    }
    requireFixed16(fixed, 4, ZIP_FIELD_VALUES.versionNeeded, "version-needed");
    requireFixed16(
      fixed,
      6,
      ZIP_FIELD_VALUES.generalPurposeFlag,
      "general-purpose-flag",
    );
    requireFixed16(
      fixed,
      8,
      ZIP_FIELD_VALUES.compressionMethod,
      "compression-method",
    );
    requireFixed16(fixed, 10, ZIP_FIELD_VALUES.dosTime, "dos-time");
    requireFixed16(fixed, 12, ZIP_FIELD_VALUES.dosDate, "dos-date");
    const crc32 = fixed.readUInt32LE(14);
    const storedSize = fixed.readUInt32LE(18);
    const uncompressedSize = fixed.readUInt32LE(22);
    const filenameLength = fixed.readUInt16LE(26);
    const extraLength = fixed.readUInt16LE(28);
    if (
      storedSize > ZIP_LIMITS.maximumZip32Value
      || uncompressedSize > ZIP_LIMITS.maximumZip32Value
    ) {
      fail("ZIP_PROFILE", "zip64-sentinel");
    }
    if (
      storedSize !== uncompressedSize
      || extraLength !== ZIP_FIELD_VALUES.localExtraLength
      || filenameLength === 0
      || filenameLength > ZIP_LIMITS.maximumArchiveFilenameBytes
    ) {
      fail("ZIP_PROFILE", "local-metadata");
    }
    const filename = await readExactlyAt(
      handle,
      filenameLength,
      cursor + ZIP_LIMITS.localHeaderFixedBytes,
      "ZIP_PARSE",
      "local-filename",
    );
    if (!filename.equals(central.filename)) {
      fail("ZIP_BINDING", "local-central-filename");
    }
    const expectedFilename = Buffer.from(planned.archivePath, "utf8");
    if (!filename.equals(expectedFilename)) {
      fail("ZIP_BINDING", "local-filename");
    }
    const dataOffset = cursor + ZIP_LIMITS.localHeaderFixedBytes
      + filenameLength + extraLength;
    if (dataOffset !== planned.dataOffset) {
      fail("ZIP_BINDING", "local-data-offset");
    }
    const payloadEnd = dataOffset + storedSize;
    if (payloadEnd > eocd.centralDirectoryOffset) {
      fail("ZIP_PARSE", "stored-payload-range");
    }
    const payloadHash = createHash("sha256");
    let crcState = crc32Init();
    let payloadOffset = 0;
    while (payloadOffset < storedSize) {
      const length = Math.min(FILE_CHUNK_SIZE, storedSize - payloadOffset);
      const chunk = await readExactlyAt(
        handle,
        length,
        dataOffset + payloadOffset,
        "ZIP_PARSE",
        "stored-payload",
      );
      payloadHash.update(chunk);
      crcState = crc32Update(crcState, chunk);
      payloadOffset += chunk.length;
    }
    const observedCrc32 = crc32Finalize(crcState);
    if (
      crc32 !== central.crc32
      || crc32 !== crc32PlanNumber(planned.crc32)
      || storedSize !== central.storedSize
      || storedSize !== planned.byteLength
      || payloadOffset !== planned.byteLength
      || observedCrc32 !== crc32
      || payloadHash.digest("hex") !== planned.sha256
    ) {
      fail("ZIP_BINDING", "stored-payload-mismatch");
    }
    cursor = payloadEnd;
  }
  if (cursor !== eocd.centralDirectoryOffset) {
    fail("ZIP_PARSE", "local-central-boundary");
  }
}

async function hashCompleteArchive(handle, archiveByteLength) {
  const hash = createHash("sha256");
  let offset = 0;
  while (offset < archiveByteLength) {
    const length = Math.min(FILE_CHUNK_SIZE, archiveByteLength - offset);
    const bytes = await readExactlyAt(
      handle,
      length,
      offset,
      "ZIP_PARSE",
      "archive-hash",
    );
    hash.update(bytes);
    offset += bytes.length;
  }
  const eof = await handle.read(Buffer.alloc(1), 0, 1, archiveByteLength);
  if (!eof || eof.bytesRead !== 0) fail("ZIP_PARSE", "archive-growth");
  return hash.digest("hex");
}

async function verifyArchiveHandle(boundary, plan, hooks) {
  let handle = null;
  try {
    handle = await open(
      boundary.targetPath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const before = await handle.stat({ bigint: true });
    requireStableRegularState(
      before,
      boundary,
      "ZIP_PARSE",
      "archive-identity",
    );
    await invokeCheckpoint(hooks, "after-archive-open", "archive");
    if (boundary.byteLength < ZIP_LIMITS.endOfCentralDirectoryBytes) {
      fail("ZIP_PARSE", "archive-too-short");
    }
    const eocdOffset = boundary.byteLength
      - ZIP_LIMITS.endOfCentralDirectoryBytes;
    const eocdRecord = await readExactlyAt(
      handle,
      ZIP_LIMITS.endOfCentralDirectoryBytes,
      eocdOffset,
      "ZIP_PARSE",
      "eocd",
    );
    const eocd = parseEocd(eocdRecord, boundary.byteLength, plan);
    await invokeCheckpoint(hooks, "after-eocd", "archive");
    const centralRecords = await parseCentralDirectory(handle, eocd, plan);
    await invokeCheckpoint(hooks, "after-central-directory", "archive");
    await replayLocalRecords(handle, eocd, centralRecords, plan);
    await invokeCheckpoint(hooks, "after-local-records", "archive");
    await invokeCheckpoint(hooks, "before-archive-hash", "archive");
    const archiveSha256 = await hashCompleteArchive(
      handle,
      boundary.byteLength,
    );
    await invokeCheckpoint(hooks, "after-archive-hash", "archive");
    const after = await handle.stat({ bigint: true });
    requireStableRegularState(
      after,
      boundary,
      "ZIP_PARSE",
      "archive-identity",
    );
    await invokeCheckpoint(hooks, "before-final-identity", "archive");
    await verifyStableFileBoundary(
      boundary,
      "ZIP_PARSE",
      "archive",
    );
    return Object.freeze({ archiveSha256, eocd });
  } catch (error) {
    throw asPublicSourceZipError(error, "ZIP_PARSE", "archive-invalid");
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (error) {
        throw asPublicSourceZipError(error, "ZIP_PARSE", "archive-close");
      }
    }
  }
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    fail("CLI", "api-options");
  }
  const allowed = new Set(["archive", "entryPlan", "testHooks"]);
  if (
    Object.keys(options).some((key) => !allowed.has(key))
    || typeof options.archive !== "string"
    || typeof options.entryPlan !== "string"
  ) {
    fail("CLI", "api-options");
  }
  return Object.freeze({
    archive: canonicalizeHostFilesystemPath(options.archive),
    entryPlan: canonicalizeHostFilesystemPath(options.entryPlan),
    hooks: normalizeTestHooks(options.testHooks),
  });
}

export function encodeCanonicalZipVerificationResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("ZIP_BINDING", "verification-result-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== VERIFICATION_RESULT_KEYS.length
    || actual.some((key, index) => key !== VERIFICATION_RESULT_KEYS[index])
    || value.verificationKind !== ZIP_VERIFICATION_KIND
    || value.schemaVersion !== 1
    || value.status !== "ok"
    || value.mode !== "full"
    || value.artifactRole !== ZIP_ARTIFACT_ROLE
    || value.formatProfile !== ZIP_FORMAT_PROFILE
    || value.archiveRoot !== ZIP_ARCHIVE_ROOT
    || !SHA256_PATTERN.test(value.entryPlanSha256)
    || !SHA256_PATTERN.test(value.archiveSha256)
    || value.canonicalProfileVerified !== true
    || value.entryPlanVerified !== true
    || value.storedPayloadsVerified !== true
    || value.crc32Verified !== true
    || value.authoritativeCorrespondingSource
      !== ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE
    || value.verificationComplete !== true
  ) {
    fail("ZIP_BINDING", "verification-result-shape");
  }
  return Buffer.from(JSON.stringify(value) + "\n", "utf8");
}

export async function verifyPublicSourceZip(options = {}) {
  const normalized = validateApiOptions(options);
  const planInput = await readCanonicalZipEntryPlanFile(
    normalized.entryPlan,
    normalized.hooks,
  );
  const archiveBoundary = await inspectStableFileBoundary(
    normalized.archive,
    {
      phase: "PATH_AUTHORITY",
      reason: "archive-file",
      maximumLength: ZIP_LIMITS.maximumZip32Value,
      minimumLength: ZIP_LIMITS.endOfCentralDirectoryBytes,
    },
  );
  if (pathsEqual(archiveBoundary.targetPath, planInput.boundary.targetPath)) {
    fail("PATH_AUTHORITY", "archive-entry-plan-alias");
  }
  const verified = await verifyArchiveHandle(
    archiveBoundary,
    planInput.value,
    normalized.hooks,
  );
  await verifyStableFileBoundary(
    planInput.boundary,
    "ENTRY_PLAN",
    "entry-plan-file",
  );
  const plan = planInput.value;
  return deepFreezeZip({
    verificationKind: ZIP_VERIFICATION_KIND,
    schemaVersion: 1,
    status: "ok",
    mode: "full",
    artifactRole: ZIP_ARTIFACT_ROLE,
    formatProfile: ZIP_FORMAT_PROFILE,
    sourceCommit: plan.sourceCommit,
    manifestSha256: plan.manifestSha256,
    membershipReportSha256: plan.membershipReportSha256,
    membershipCount: plan.membershipCount,
    archiveRoot: ZIP_ARCHIVE_ROOT,
    entryPlanSha256: planInput.sha256,
    archiveSha256: verified.archiveSha256,
    archiveByteLength: archiveBoundary.byteLength,
    entryCount: plan.entryCount,
    centralDirectoryOffset: verified.eocd.centralDirectoryOffset,
    centralDirectoryByteLength: verified.eocd.centralDirectoryByteLength,
    canonicalProfileVerified: true,
    entryPlanVerified: true,
    storedPayloadsVerified: true,
    crc32Verified: true,
    authoritativeCorrespondingSource:
      ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE,
    verificationComplete: true,
  });
}

function parseOptions(argv) {
  const mapping = new Map([
    ["--archive", "archive"],
    ["--entry-plan", "entryPlan"],
  ]);
  const result = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    if (
      key === undefined
      || Object.hasOwn(result, key)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      fail("CLI", "unknown-or-duplicate-option");
    }
    result[key] = argv[index + 1];
    index += 1;
  }
  if (!Object.hasOwn(result, "archive") || !Object.hasOwn(result, "entryPlan")) {
    fail("CLI", "required-options");
  }
  return Object.freeze(result);
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  if (import.meta.main === false) return false;
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
  const result = await verifyPublicSourceZip(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(encodeCanonicalZipVerificationResult(result));
}

if (isMainModule()) {
  main().catch((error) => {
    const safe = error instanceof PublicSourceZipError
      ? error
      : new PublicSourceZipError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
