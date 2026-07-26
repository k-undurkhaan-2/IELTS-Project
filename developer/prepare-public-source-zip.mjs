#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as FS_CONSTANTS,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  unlinkSync,
} from "node:fs";
import { link, lstat, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ZIP_ARCHIVE_ROOT,
  ZIP_ARTIFACT_ROLE,
  ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE,
  ZIP_FORMAT_PROFILE,
  ZIP_LIMITS,
  PublicSourceZipError,
  asPublicSourceZipError,
  canonicalizeHostFilesystemPath,
  crc32Finalize,
  crc32Init,
  crc32Update,
  deepFreezeZip,
  encodeCentralDirectoryRecord,
  encodeEndOfCentralDirectory,
  encodeLocalFileHeader,
} from "./public-source-zip-core.mjs";
import {
  readCanonicalZipEntryPlanFile,
  verifyPublicSourceZip,
} from "./verify-public-source-zip.mjs";

const TEMPORARY_BASENAME_PATTERN = /^\.__iz-[0-9a-f]{24}\.tmp$/u;
const TEMPORARY_CREATE_RETRIES = 8;
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

function isInside(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(".." + path.sep)
    && !path.isAbsolute(relative);
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

function sameObjectIdentity(left, right) {
  return Boolean(left && right && left.meaningful && right.meaningful)
    && left.device === right.device
    && left.inode === right.inode;
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
      "output-parent",
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
      fail(phase, "output-parent-identity");
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

async function invokeCheckpoint(hooks, checkpoint, details = {}) {
  if (!hooks.checkpoint) return;
  const returned = await hooks.checkpoint(Object.freeze({
    checkpoint,
    ...details,
  }));
  if (returned !== undefined) fail("CLI", "checkpoint-return-value");
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    fail("CLI", "api-options");
  }
  const allowed = new Set(["sourceTree", "entryPlan", "output", "testHooks"]);
  if (
    Object.keys(options).some((key) => !allowed.has(key))
    || typeof options.sourceTree !== "string"
    || typeof options.entryPlan !== "string"
    || typeof options.output !== "string"
  ) {
    fail("CLI", "api-options");
  }
  return Object.freeze({
    sourceTree: canonicalizeHostFilesystemPath(options.sourceTree),
    entryPlan: canonicalizeHostFilesystemPath(options.entryPlan),
    output: canonicalizeHostFilesystemPath(options.output),
    hooks: normalizeTestHooks(options.testHooks),
  });
}

function moduleRepositoryRoot() {
  try {
    const modulePath = realpathSync.native(fileURLToPath(import.meta.url));
    return canonicalizeHostFilesystemPath(path.dirname(path.dirname(modulePath)));
  } catch {
    fail("PATH_AUTHORITY", "repository-boundary");
  }
}

async function validateSourceTree(sourceTreeArgument) {
  const sourceTree = validateAbsoluteNormalizedPath(
    sourceTreeArgument,
    "PATH_AUTHORITY",
    "source-tree",
  );
  const record = await inspectRealDirectory(
    sourceTree,
    "PATH_AUTHORITY",
    "source-tree",
  );
  const parentChain = await inspectParentChain(
    path.join(sourceTree, "source-tree-boundary"),
    "PATH_AUTHORITY",
  );
  return Object.freeze({ ...record, parentChain });
}

async function verifySourceTree(sourceTree, phase = "SOURCE_FILE") {
  const current = await inspectRealDirectory(
    sourceTree.path,
    phase,
    "source-tree",
  );
  if (
    !pathsEqual(current.canonicalPath, sourceTree.canonicalPath)
    || !directoryIdentitiesEqual(current.identity, sourceTree.identity)
  ) {
    fail(phase, "source-tree-identity");
  }
  await inspectParentChain(
    path.join(sourceTree.path, "source-tree-boundary"),
    phase,
    sourceTree.parentChain,
  );
}

async function validateOutputBoundary(outputArgument, sourceTree) {
  const outputPath = validateAbsoluteNormalizedPath(
    outputArgument,
    "PATH_AUTHORITY",
    "output",
  );
  if (!path.basename(outputPath).endsWith(".zip")) {
    fail("PATH_AUTHORITY", "output-extension");
  }
  const parentPath = path.dirname(outputPath);
  canonicalizeHostFilesystemPath(parentPath);
  const parentChain = await inspectParentChain(
    outputPath,
    "PATH_AUTHORITY",
  );
  const canonicalParent = canonicalizeHostFilesystemPath(
    parentChain.at(-1).canonicalPath,
  );
  const canonicalOutput = canonicalizeHostFilesystemPath(
    path.join(canonicalParent, path.basename(outputPath)),
  );
  const repositoryRoot = moduleRepositoryRoot();
  if (
    pathsEqual(outputPath, sourceTree.path)
    || pathsEqual(parentPath, sourceTree.path)
    || pathsEqual(canonicalParent, sourceTree.canonicalPath)
    || isInside(sourceTree.path, outputPath)
    || pathsEqual(repositoryRoot, canonicalOutput)
    || isInside(repositoryRoot, canonicalOutput)
  ) {
    fail("PATH_AUTHORITY", "output-containment");
  }
  if (await pathState(outputPath)) {
    fail("OUTPUT_PUBLICATION", "final-target-exists");
  }
  return Object.freeze({
    outputPath,
    parentPath,
    parentChain,
    canonicalParent,
  });
}

async function verifyOutputParent(output, phase) {
  await inspectParentChain(output.outputPath, phase, output.parentChain);
  const current = output.parentChain.at(-1);
  const inspected = await inspectRealDirectory(
    output.parentPath,
    phase,
    "output-parent",
  );
  if (
    !pathsEqual(inspected.canonicalPath, output.canonicalParent)
    || !directoryIdentitiesEqual(inspected.identity, current.identity)
  ) {
    fail(phase, "output-parent-identity");
  }
}

function expectedUnixMode(gitMode) {
  return gitMode === "100755" ? 0o755 : 0o644;
}

function requireSourceFileState(state, sourceTree, entry, identity = null) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size !== BigInt(entry.byteLength)
    || (sourceTree.identity.meaningful && state.dev !== sourceTree.identity.device)
    || (
      process.platform !== "win32"
      && Number(state.mode & 0o777n) !== expectedUnixMode(entry.gitMode)
    )
  ) {
    fail("SOURCE_FILE", "source-file-state");
  }
  const actual = identityFromState(state);
  if (!actual.meaningful || (identity && !identitiesEqual(identity, actual))) {
    fail("SOURCE_FILE", "source-file-identity");
  }
  return actual;
}

async function inspectSourceDirectoryChain(sourceTree, sourcePath, recorded = null) {
  await verifySourceTree(sourceTree);
  const components = sourcePath.split("/").slice(0, -1);
  const records = [];
  let currentPath = sourceTree.path;
  for (let index = 0; index < components.length; index += 1) {
    currentPath = path.join(currentPath, components[index]);
    if (!isInside(sourceTree.path, currentPath)) {
      fail("SOURCE_FILE", "source-parent-containment");
    }
    const inspected = await inspectRealDirectory(
      currentPath,
      "SOURCE_FILE",
      "source-parent",
    );
    if (
      sourceTree.identity.meaningful
      && inspected.identity.device !== sourceTree.identity.device
    ) {
      fail("SOURCE_FILE", "source-parent-device");
    }
    if (
      recorded
      && (
        recorded.length !== components.length
        || !pathsEqual(recorded[index].path, inspected.path)
        || !directoryIdentitiesEqual(
          recorded[index].identity,
          inspected.identity,
        )
      )
    ) {
      fail("SOURCE_FILE", "source-parent-identity");
    }
    records.push(inspected);
  }
  return Object.freeze(records);
}

function sourceFilePath(sourceTree, sourcePath) {
  const result = canonicalizeHostFilesystemPath(
    path.join(sourceTree.path, ...sourcePath.split("/")),
  );
  if (!isInside(sourceTree.path, result)) {
    fail("SOURCE_FILE", "source-file-containment");
  }
  return result;
}

async function verifySourcePathIdentity(binding, sourceTree, entry) {
  await inspectSourceDirectoryChain(
    sourceTree,
    entry.sourcePath,
    binding.directories,
  );
  const state = await pathState(binding.filePath);
  requireSourceFileState(state, sourceTree, entry, binding.identity);
  const resolved = await resolveRealHostPath(binding.filePath);
  if (!pathsEqual(resolved, binding.filePath)) {
    fail("SOURCE_FILE", "source-file-reparse");
  }
}

async function readAndBindSourceFile({
  sourceTree,
  entry,
  recordedBinding = null,
  hooks,
  pass,
  outputHandle = null,
}) {
  const directories = await inspectSourceDirectoryChain(
    sourceTree,
    entry.sourcePath,
    recordedBinding?.directories ?? null,
  );
  const filePath = sourceFilePath(sourceTree, entry.sourcePath);
  const initial = await pathState(filePath);
  const initialIdentity = requireSourceFileState(
    initial,
    sourceTree,
    entry,
    recordedBinding?.identity ?? null,
  );
  const resolved = await resolveRealHostPath(filePath);
  if (!pathsEqual(resolved, filePath)) {
    fail("SOURCE_FILE", "source-file-reparse");
  }
  const binding = Object.freeze({
    filePath,
    directories,
    identity: initialIdentity,
  });
  let handle = null;
  try {
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    requireSourceFileState(before, sourceTree, entry, initialIdentity);
    await invokeCheckpoint(hooks, `after-${pass}-source-open`, {
      sourcePath: filePath,
      sourceRelativePath: entry.sourcePath,
    });
    const sha256 = createHash("sha256");
    let crcState = crc32Init();
    let offset = 0;
    while (offset < entry.byteLength) {
      const chunk = Buffer.alloc(
        Math.min(FILE_CHUNK_SIZE, entry.byteLength - offset),
      );
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (
        !read
        || !Number.isInteger(read.bytesRead)
        || read.bytesRead <= 0
        || read.bytesRead > chunk.length
      ) {
        fail("SOURCE_FILE", "source-file-truncated");
      }
      const bytes = chunk.subarray(0, read.bytesRead);
      sha256.update(bytes);
      crcState = crc32Update(crcState, bytes);
      if (outputHandle) await writeAll(outputHandle, bytes);
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    if (!trailing || trailing.bytesRead !== 0) {
      fail("SOURCE_FILE", "source-file-growth");
    }
    await invokeCheckpoint(hooks, `after-${pass}-source-read`, {
      sourcePath: filePath,
      sourceRelativePath: entry.sourcePath,
    });
    const after = await handle.stat({ bigint: true });
    requireSourceFileState(after, sourceTree, entry, initialIdentity);
    await verifySourcePathIdentity(binding, sourceTree, entry);
    const sha256Hex = sha256.digest("hex");
    const crc32Hex = crc32Finalize(crcState).toString(16).padStart(8, "0");
    if (
      offset !== entry.byteLength
      || sha256Hex !== entry.sha256
      || crc32Hex !== entry.crc32
    ) {
      fail("ZIP_BINDING", "source-entry-plan-mismatch");
    }
    return binding;
  } catch (error) {
    throw asPublicSourceZipError(error, "SOURCE_FILE", "source-file-read");
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (error) {
        throw asPublicSourceZipError(error, "SOURCE_FILE", "source-file-close");
      }
    }
  }
}

async function runPassA(sourceTree, plan, hooks) {
  await invokeCheckpoint(hooks, "before-pass-a");
  const bindings = [];
  for (let index = 0; index < plan.entries.length; index += 1) {
    const entry = plan.entries[index];
    await invokeCheckpoint(hooks, "before-pass-a-entry", {
      entryIndex: index,
      sourceRelativePath: entry.sourcePath,
    });
    bindings.push(await readAndBindSourceFile({
      sourceTree,
      entry,
      hooks,
      pass: "pass-a",
    }));
    await invokeCheckpoint(hooks, "after-pass-a-entry", {
      entryIndex: index,
      sourceRelativePath: entry.sourcePath,
    });
  }
  await verifySourceTree(sourceTree);
  await invokeCheckpoint(hooks, "after-pass-a");
  return Object.freeze(bindings);
}

async function writeAll(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = await handle.write(
      bytes,
      offset,
      bytes.length - offset,
      null,
    );
    if (
      !written
      || !Number.isInteger(written.bytesWritten)
      || written.bytesWritten <= 0
      || written.bytesWritten > bytes.length - offset
    ) {
      fail("ZIP_WRITE", "archive-write-progress");
    }
    offset += written.bytesWritten;
  }
}

function temporaryBasenameIsValid(value) {
  return typeof value === "string" && TEMPORARY_BASENAME_PATTERN.test(value);
}

async function createPrivateTemporary(output, hooks) {
  for (let attempt = 0; attempt < TEMPORARY_CREATE_RETRIES; attempt += 1) {
    await verifyOutputParent(output, "ZIP_WRITE");
    if (await pathState(output.outputPath)) {
      fail("OUTPUT_PUBLICATION", "final-target-exists");
    }
    const basename = ".__iz-" + randomBytes(12).toString("hex") + ".tmp";
    if (!temporaryBasenameIsValid(basename)) {
      fail("ZIP_WRITE", "temporary-name");
    }
    const temporaryPath = canonicalizeHostFilesystemPath(
      path.join(output.parentPath, basename),
    );
    if (!pathsEqual(path.dirname(temporaryPath), output.parentPath)) {
      fail("ZIP_WRITE", "temporary-containment");
    }
    await invokeCheckpoint(hooks, "before-temporary-create", {
      temporaryArchive: temporaryPath,
      finalOutput: output.outputPath,
      attempt,
    });
    let handle;
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
      if (error && error.code === "EEXIST") continue;
      throw asPublicSourceZipError(error, "ZIP_WRITE", "temporary-create");
    }
    const state = await handle.stat({ bigint: true });
    const pathObserved = await pathState(temporaryPath);
    const identity = identityFromState(state);
    if (
      !state.isFile()
      || state.isSymbolicLink()
      || state.nlink !== 1n
      || state.size !== 0n
      || !identity.meaningful
      || !pathObserved
      || !sameObjectIdentity(identity, identityFromState(pathObserved))
    ) {
      try { await handle.close(); } catch { /* cleanup remains authoritative */ }
      fail("ZIP_WRITE", "temporary-identity");
    }
    const temporary = {
      path: temporaryPath,
      basename,
      objectIdentity: identity,
      expectedIdentity: identity,
      byteLength: 0,
      exists: true,
      handle,
    };
    await invokeCheckpoint(hooks, "after-temporary-create", {
      temporaryArchive: temporaryPath,
      finalOutput: output.outputPath,
    });
    return temporary;
  }
  fail("ZIP_WRITE", "temporary-collision-limit");
}

async function refreshTemporaryFromHandle(temporary) {
  if (!temporary.handle) return;
  const state = await temporary.handle.stat({ bigint: true });
  const identity = identityFromState(state);
  if (!sameObjectIdentity(identity, temporary.objectIdentity)) {
    fail("ZIP_WRITE", "temporary-handle-identity");
  }
  temporary.expectedIdentity = identity;
  temporary.byteLength = Number(state.size);
}

async function closeTemporaryHandle(temporary, phase = "ZIP_WRITE") {
  if (!temporary.handle) return;
  try {
    await refreshTemporaryFromHandle(temporary);
    await temporary.handle.close();
    temporary.handle = null;
  } catch (error) {
    temporary.handle = null;
    throw asPublicSourceZipError(error, phase, "temporary-close");
  }
}

async function writeCanonicalArchive({
  temporary,
  sourceTree,
  plan,
  passABindings,
  hooks,
}) {
  let archiveOffset = 0;
  for (let index = 0; index < plan.entries.length; index += 1) {
    const entry = plan.entries[index];
    if (archiveOffset !== entry.localHeaderOffset) {
      fail("ZIP_LAYOUT", "local-header-offset");
    }
    const header = encodeLocalFileHeader(entry);
    await writeAll(temporary.handle, header);
    archiveOffset += header.length;
    if (archiveOffset !== entry.dataOffset) {
      fail("ZIP_LAYOUT", "data-offset");
    }
    await invokeCheckpoint(hooks, "before-pass-b-entry", {
      entryIndex: index,
      sourceRelativePath: entry.sourcePath,
      temporaryArchive: temporary.path,
    });
    await readAndBindSourceFile({
      sourceTree,
      entry,
      recordedBinding: passABindings[index],
      hooks,
      pass: "pass-b",
      outputHandle: temporary.handle,
    });
    archiveOffset += entry.byteLength;
    await invokeCheckpoint(hooks, "after-pass-b-entry", {
      entryIndex: index,
      sourceRelativePath: entry.sourcePath,
      temporaryArchive: temporary.path,
    });
  }
  if (archiveOffset !== plan.centralDirectoryOffset) {
    fail("ZIP_LAYOUT", "central-directory-offset");
  }
  for (const entry of plan.entries) {
    if (archiveOffset !== entry.centralDirectoryRecordOffset) {
      fail("ZIP_LAYOUT", "central-record-offset");
    }
    const record = encodeCentralDirectoryRecord(entry);
    await writeAll(temporary.handle, record);
    archiveOffset += record.length;
  }
  if (
    archiveOffset
      !== plan.centralDirectoryOffset + plan.centralDirectoryByteLength
  ) {
    fail("ZIP_LAYOUT", "central-directory-length");
  }
  const eocd = encodeEndOfCentralDirectory(plan);
  await writeAll(temporary.handle, eocd);
  archiveOffset += eocd.length;
  if (archiveOffset !== plan.archiveByteLength) {
    fail("ZIP_LAYOUT", "archive-byte-length");
  }
  await temporary.handle.sync();
  const complete = await temporary.handle.stat({ bigint: true });
  const identity = identityFromState(complete);
  if (
    !complete.isFile()
    || complete.nlink !== 1n
    || complete.size !== BigInt(plan.archiveByteLength)
    || !sameObjectIdentity(identity, temporary.objectIdentity)
  ) {
    fail("ZIP_WRITE", "temporary-final-state");
  }
  temporary.expectedIdentity = identity;
  temporary.byteLength = plan.archiveByteLength;
  await invokeCheckpoint(hooks, "after-archive-write", {
    temporaryArchive: temporary.path,
  });
}

async function requireOwnedFilePath(
  filePath,
  expectedIdentity,
  objectIdentity,
  expectedLength,
  expectedLinks,
  phase,
  reason,
) {
  const state = await pathState(filePath);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== BigInt(expectedLinks)
    || state.size !== BigInt(expectedLength)
  ) {
    fail(phase, reason);
  }
  const identity = identityFromState(state);
  if (
    !sameObjectIdentity(identity, objectIdentity)
    || (expectedIdentity && !identitiesEqual(identity, expectedIdentity))
  ) {
    fail(phase, reason);
  }
  const resolved = await resolveRealHostPath(filePath);
  if (!pathsEqual(resolved, filePath)) fail(phase, reason);
  return identity;
}

async function hashStableOwnedFile(temporary, output) {
  await verifyOutputParent(output, "ZIP_BINDING");
  await requireOwnedFilePath(
    temporary.path,
    temporary.expectedIdentity,
    temporary.objectIdentity,
    temporary.byteLength,
    1,
    "ZIP_BINDING",
    "temporary-archive-identity",
  );
  let handle = null;
  try {
    handle = await open(
      temporary.path,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const before = await handle.stat({ bigint: true });
    if (!identitiesEqual(identityFromState(before), temporary.expectedIdentity)) {
      fail("ZIP_BINDING", "temporary-archive-identity");
    }
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < temporary.byteLength) {
      const chunk = Buffer.alloc(
        Math.min(FILE_CHUNK_SIZE, temporary.byteLength - offset),
      );
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        fail("ZIP_BINDING", "temporary-archive-read");
      }
      hash.update(chunk.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    if (!trailing || trailing.bytesRead !== 0) {
      fail("ZIP_BINDING", "temporary-archive-growth");
    }
    const after = await handle.stat({ bigint: true });
    if (!identitiesEqual(identityFromState(after), temporary.expectedIdentity)) {
      fail("ZIP_BINDING", "temporary-archive-identity");
    }
    await requireOwnedFilePath(
      temporary.path,
      temporary.expectedIdentity,
      temporary.objectIdentity,
      temporary.byteLength,
      1,
      "ZIP_BINDING",
      "temporary-archive-identity",
    );
    return Object.freeze({
      sha256: hash.digest("hex"),
      byteLength: offset,
    });
  } finally {
    if (handle) await handle.close();
  }
}

function createPublicationLedger(temporary, output) {
  return {
    path: output.outputPath,
    objectIdentity: temporary.objectIdentity,
    expectedIdentity: null,
    byteLength: temporary.byteLength,
    archiveSha256: temporary.archiveSha256 ?? null,
    exists: false,
    linkCreated: false,
  };
}

async function publishNoReplace(temporary, publication, output, hooks) {
  await verifyOutputParent(output, "OUTPUT_PUBLICATION");
  await requireOwnedFilePath(
    temporary.path,
    temporary.expectedIdentity,
    temporary.objectIdentity,
    temporary.byteLength,
    1,
    "OUTPUT_PUBLICATION",
    "temporary-source-identity",
  );
  await invokeCheckpoint(hooks, "before-publication", {
    temporaryArchive: temporary.path,
    finalOutput: output.outputPath,
  });
  await verifyOutputParent(output, "OUTPUT_PUBLICATION");
  if (await pathState(output.outputPath)) {
    fail("OUTPUT_PUBLICATION", "final-target-exists");
  }
  try {
    await link(temporary.path, output.outputPath);
    publication.linkCreated = true;
    publication.exists = true;
  } catch (error) {
    if (error && error.code === "EEXIST") {
      fail("OUTPUT_PUBLICATION", "final-target-exists");
    }
    throw asPublicSourceZipError(
      error,
      "OUTPUT_PUBLICATION",
      "hard-link-failed",
    );
  }
  const temporaryState = await pathState(temporary.path);
  const finalState = await pathState(output.outputPath);
  if (!temporaryState || !finalState) {
    fail("OUTPUT_PUBLICATION", "hard-link-identity");
  }
  const temporaryIdentity = identityFromState(temporaryState);
  const finalIdentity = identityFromState(finalState);
  if (
    temporaryState.isSymbolicLink()
    || finalState.isSymbolicLink()
    || !temporaryState.isFile()
    || !finalState.isFile()
    || temporaryState.nlink !== 2n
    || finalState.nlink !== 2n
    || temporaryState.size !== BigInt(temporary.byteLength)
    || finalState.size !== BigInt(temporary.byteLength)
    || !sameObjectIdentity(temporaryIdentity, temporary.objectIdentity)
    || !identitiesEqual(temporaryIdentity, finalIdentity)
  ) {
    fail("OUTPUT_PUBLICATION", "hard-link-identity");
  }
  temporary.expectedIdentity = temporaryIdentity;
  publication.expectedIdentity = finalIdentity;
  await invokeCheckpoint(hooks, "after-publication-link", {
    temporaryArchive: temporary.path,
    finalOutput: output.outputPath,
  });
}

async function removeTemporaryLink(temporary, publication, output, hooks) {
  await invokeCheckpoint(hooks, "before-temporary-cleanup", {
    temporaryArchive: temporary.path,
    finalOutput: publication.path,
  });
  await verifyOutputParent(output, "CLEANUP");
  await requireOwnedFilePath(
    temporary.path,
    temporary.expectedIdentity,
    temporary.objectIdentity,
    temporary.byteLength,
    2,
    "CLEANUP",
    "temporary-identity",
  );
  await requireOwnedFilePath(
    publication.path,
    publication.expectedIdentity,
    publication.objectIdentity,
    publication.byteLength,
    2,
    "CLEANUP",
    "final-identity",
  );
  await unlink(temporary.path);
  temporary.exists = false;
  if (await pathState(temporary.path)) fail("CLEANUP", "temporary-unlink");
  const finalState = await pathState(publication.path);
  if (
    !finalState
    || finalState.nlink !== 1n
    || finalState.size !== BigInt(publication.byteLength)
    || !sameObjectIdentity(
      identityFromState(finalState),
      publication.objectIdentity,
    )
  ) {
    fail("CLEANUP", "final-identity");
  }
  publication.expectedIdentity = identityFromState(finalState);
  await invokeCheckpoint(hooks, "after-temporary-cleanup", {
    finalOutput: publication.path,
  });
}

function pathStateSync(targetPath) {
  const canonicalPath = canonicalizeHostFilesystemPath(targetPath);
  try {
    return lstatSync(canonicalPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function resolveRealHostPathSync(targetPath) {
  const canonicalTarget = canonicalizeHostFilesystemPath(targetPath);
  return canonicalizeHostFilesystemPath(realpathSync.native(canonicalTarget));
}

function verifyOutputParentSync(output) {
  for (const recorded of output.parentChain) {
    const currentPath = canonicalizeHostFilesystemPath(recorded.path);
    const state = pathStateSync(currentPath);
    if (!state || state.isSymbolicLink() || !state.isDirectory()) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    const resolved = resolveRealHostPathSync(currentPath);
    const identity = identityFromState(state);
    if (
      !pathsEqual(resolved, currentPath)
      || !pathsEqual(recorded.canonicalPath, resolved)
      || !directoryIdentitiesEqual(recorded.identity, identity)
    ) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
  }
  const finalParent = output.parentChain.at(-1);
  if (
    !finalParent
    || !pathsEqual(finalParent.path, output.parentPath)
    || !pathsEqual(finalParent.canonicalPath, output.canonicalParent)
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
}

function requireCleanupPathAuthority(candidatePath, output) {
  const canonicalPath = canonicalizeHostFilesystemPath(candidatePath);
  if (
    canonicalPath !== candidatePath
    || !pathsEqual(path.dirname(canonicalPath), output.parentPath)
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  return canonicalPath;
}

function requireCleanupFileState(
  state,
  candidate,
  priorSameObjectDeletions = 0,
) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.size !== BigInt(candidate.byteLength)
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const identity = identityFromState(state);
  if (priorSameObjectDeletions === 0) {
    if (!identitiesEqual(identity, candidate.observedIdentity)) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
  } else if (
    !sameObjectIdentity(identity, candidate.observedIdentity)
    || identity.links
      !== candidate.observedIdentity.links - BigInt(priorSameObjectDeletions)
    || identity.mode !== candidate.observedIdentity.mode
    || identity.mtimeNs !== candidate.observedIdentity.mtimeNs
    || identity.birthtimeNs !== candidate.observedIdentity.birthtimeNs
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  return identity;
}

async function hashCleanupCandidate(candidatePath, expectedIdentity, byteLength) {
  let handle = null;
  try {
    handle = await open(
      candidatePath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const before = await handle.stat({ bigint: true });
    if (!identitiesEqual(identityFromState(before), expectedIdentity)) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < byteLength) {
      const chunk = Buffer.alloc(Math.min(FILE_CHUNK_SIZE, byteLength - offset));
      const read = await handle.read(chunk, 0, chunk.length, offset);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        fail("CLEANUP", "cleanup-identity-uncertain");
      }
      hash.update(chunk.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, byteLength);
    if (!trailing || trailing.bytesRead !== 0) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    const after = await handle.stat({ bigint: true });
    if (!identitiesEqual(identityFromState(after), expectedIdentity)) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    return hash.digest("hex");
  } finally {
    if (handle) await handle.close();
  }
}

function hashCleanupCandidateSync(candidate, priorSameObjectDeletions) {
  let descriptor = null;
  try {
    descriptor = openSync(
      candidate.path,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    requireCleanupFileState(
      fstatSync(descriptor, { bigint: true }),
      candidate,
      priorSameObjectDeletions,
    );
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < candidate.byteLength) {
      const chunk = Buffer.alloc(
        Math.min(FILE_CHUNK_SIZE, candidate.byteLength - offset),
      );
      const bytesRead = readSync(
        descriptor,
        chunk,
        0,
        chunk.length,
        offset,
      );
      if (bytesRead <= 0 || bytesRead > chunk.length) {
        fail("CLEANUP", "cleanup-identity-uncertain");
      }
      hash.update(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (readSync(descriptor, Buffer.alloc(1), 0, 1, candidate.byteLength) !== 0) {
      fail("CLEANUP", "cleanup-identity-uncertain");
    }
    requireCleanupFileState(
      fstatSync(descriptor, { bigint: true }),
      candidate,
      priorSameObjectDeletions,
    );
    return hash.digest("hex");
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

async function inspectCleanupCandidate(kind, ledger, output) {
  const candidatePath = requireCleanupPathAuthority(ledger.path, output);
  const state = await pathState(candidatePath);
  if (!ledger.exists) {
    if (state) fail("CLEANUP", "cleanup-identity-uncertain");
    return Object.freeze({
      kind,
      path: candidatePath,
      ledger,
      expectedPresent: false,
      observedIdentity: null,
      objectIdentity: ledger.objectIdentity,
      byteLength: ledger.byteLength,
      archiveSha256: ledger.archiveSha256 ?? null,
    });
  }
  if (!ledger.expectedIdentity || !ledger.objectIdentity) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.size !== BigInt(ledger.byteLength)
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  const observedIdentity = identityFromState(state);
  if (
    !sameObjectIdentity(observedIdentity, ledger.objectIdentity)
    || !identitiesEqual(observedIdentity, ledger.expectedIdentity)
    || !pathsEqual(await resolveRealHostPath(candidatePath), candidatePath)
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    ledger.archiveSha256
    && await hashCleanupCandidate(
      candidatePath,
      observedIdentity,
      ledger.byteLength,
    ) !== ledger.archiveSha256
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  return Object.freeze({
    kind,
    path: candidatePath,
    ledger,
    expectedPresent: true,
    observedIdentity,
    objectIdentity: ledger.objectIdentity,
    byteLength: ledger.byteLength,
    archiveSha256: ledger.archiveSha256 ?? null,
  });
}

async function inspectFailureCleanupPlan(temporary, publication, output) {
  await verifyOutputParent(output, "CLEANUP");
  const candidates = [];
  if (temporary) {
    candidates.push(await inspectCleanupCandidate("temporary", temporary, output));
  }
  if (publication?.linkCreated) {
    candidates.push(await inspectCleanupCandidate("final", publication, output));
  }
  const temporaryCandidate = candidates.find(
    (candidate) => candidate.kind === "temporary",
  );
  const finalCandidate = candidates.find((candidate) => candidate.kind === "final");
  if (
    temporaryCandidate?.expectedPresent
    && finalCandidate?.expectedPresent
    && (
      temporaryCandidate.observedIdentity.links !== 2n
      || finalCandidate.observedIdentity.links !== 2n
      || !identitiesEqual(
        temporaryCandidate.observedIdentity,
        finalCandidate.observedIdentity,
      )
      || !sameObjectIdentity(
        temporaryCandidate.objectIdentity,
        finalCandidate.objectIdentity,
      )
    )
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    temporaryCandidate?.expectedPresent
    && !finalCandidate
    && temporaryCandidate.observedIdentity.links !== 1n
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    finalCandidate?.expectedPresent
    && !temporaryCandidate?.expectedPresent
    && finalCandidate.observedIdentity.links !== 1n
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  return Object.freeze({
    output,
    candidates: Object.freeze(candidates),
    deletionOrder: Object.freeze(["temporary", "final"]),
  });
}

function revalidateCleanupCandidateSync(candidate, output, priorDeletions = []) {
  const canonicalPath = requireCleanupPathAuthority(candidate.path, output);
  const state = pathStateSync(canonicalPath);
  if (!candidate.expectedPresent) {
    if (state) fail("CLEANUP", "cleanup-identity-uncertain");
    return;
  }
  const priorSameObjectDeletions = priorDeletions.filter(
    (deleted) => sameObjectIdentity(
      deleted.objectIdentity,
      candidate.objectIdentity,
    ),
  ).length;
  requireCleanupFileState(state, candidate, priorSameObjectDeletions);
  if (!pathsEqual(resolveRealHostPathSync(canonicalPath), canonicalPath)) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
  if (
    candidate.archiveSha256
    && hashCleanupCandidateSync(candidate, priorSameObjectDeletions)
      !== candidate.archiveSha256
  ) {
    fail("CLEANUP", "cleanup-identity-uncertain");
  }
}

function executeFrozenCleanupPlan(plan) {
  let unlinkCount = 0;
  const deleted = [];
  try {
    verifyOutputParentSync(plan.output);
    for (const candidate of plan.candidates) {
      revalidateCleanupCandidateSync(candidate, plan.output);
    }

    const deletions = plan.deletionOrder.flatMap((kind) =>
      plan.candidates.filter(
        (candidate) => candidate.kind === kind && candidate.expectedPresent,
      )
    );
    for (const candidate of deletions) {
      verifyOutputParentSync(plan.output);
      revalidateCleanupCandidateSync(candidate, plan.output, deleted);
      unlinkSync(candidate.path);
      candidate.ledger.exists = false;
      unlinkCount += 1;
      deleted.push(candidate);
      if (pathStateSync(candidate.path)) {
        fail("CLEANUP", "cleanup-identity-uncertain");
      }
    }
    return Object.freeze({ complete: true, unlinkCount });
  } catch {
    return Object.freeze({ complete: false, unlinkCount });
  }
}

async function cleanupAfterFailure(temporary, publication, output) {
  let plan;
  try {
    plan = await inspectFailureCleanupPlan(temporary, publication, output);
  } catch {
    return Object.freeze({ complete: false, unlinkCount: 0 });
  }
  return executeFrozenCleanupPlan(plan);
}

function requireVerifierAgreement(result, plan, planSha256, archiveIdentity) {
  if (
    !result
    || typeof result !== "object"
    || result.status !== "ok"
    || result.mode !== "full"
    || result.artifactRole !== ZIP_ARTIFACT_ROLE
    || result.formatProfile !== ZIP_FORMAT_PROFILE
    || result.sourceCommit !== plan.sourceCommit
    || result.manifestSha256 !== plan.manifestSha256
    || result.membershipReportSha256 !== plan.membershipReportSha256
    || result.membershipCount !== plan.membershipCount
    || result.archiveRoot !== ZIP_ARCHIVE_ROOT
    || result.entryPlanSha256 !== planSha256
    || result.archiveSha256 !== archiveIdentity.sha256
    || result.archiveByteLength !== archiveIdentity.byteLength
    || result.entryCount !== plan.entryCount
    || result.centralDirectoryOffset !== plan.centralDirectoryOffset
    || result.centralDirectoryByteLength !== plan.centralDirectoryByteLength
    || result.canonicalProfileVerified !== true
    || result.entryPlanVerified !== true
    || result.storedPayloadsVerified !== true
    || result.crc32Verified !== true
    || result.authoritativeCorrespondingSource
      !== ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE
    || result.verificationComplete !== true
  ) {
    fail("ZIP_BINDING", "verifier-result-mismatch");
  }
}

export async function preparePublicSourceZip(options = {}) {
  const normalized = validateApiOptions(options);
  let temporary = null;
  let publication = null;
  let output = null;
  try {
    const sourceTree = await validateSourceTree(normalized.sourceTree);
    output = await validateOutputBoundary(normalized.output, sourceTree);
    const planInput = await readCanonicalZipEntryPlanFile(
      normalized.entryPlan,
    );
    const plan = planInput.value;
    if (
      pathsEqual(planInput.boundary.targetPath, output.outputPath)
      || pathsEqual(planInput.boundary.targetPath, sourceTree.path)
      || isInside(sourceTree.path, planInput.boundary.targetPath)
    ) {
      fail("PATH_AUTHORITY", "entry-plan-containment");
    }

    const passABindings = await runPassA(
      sourceTree,
      plan,
      normalized.hooks,
    );
    await verifyOutputParent(output, "ZIP_WRITE");
    if (await pathState(output.outputPath)) {
      fail("OUTPUT_PUBLICATION", "final-target-exists");
    }
    await invokeCheckpoint(normalized.hooks, "before-pass-b", {
      finalOutput: output.outputPath,
    });
    await verifySourceTree(sourceTree);
    temporary = await createPrivateTemporary(output, normalized.hooks);
    await writeCanonicalArchive({
      temporary,
      sourceTree,
      plan,
      passABindings,
      hooks: normalized.hooks,
    });
    await closeTemporaryHandle(temporary);
    temporary.expectedIdentity = await requireOwnedFilePath(
      temporary.path,
      null,
      temporary.objectIdentity,
      plan.archiveByteLength,
      1,
      "ZIP_WRITE",
      "temporary-final-identity",
    );

    await invokeCheckpoint(normalized.hooks, "before-temporary-verification", {
      temporaryArchive: temporary.path,
    });
    const temporaryVerification = await verifyPublicSourceZip({
      archive: temporary.path,
      entryPlan: normalized.entryPlan,
      testHooks: normalized.hooks,
    });
    await invokeCheckpoint(normalized.hooks, "after-temporary-verification", {
      temporaryArchive: temporary.path,
    });
    await invokeCheckpoint(normalized.hooks, "before-archive-stable-read", {
      temporaryArchive: temporary.path,
    });
    const archiveIdentity = await hashStableOwnedFile(temporary, output);
    temporary.archiveSha256 = archiveIdentity.sha256;
    await invokeCheckpoint(normalized.hooks, "after-archive-stable-read", {
      temporaryArchive: temporary.path,
    });
    requireVerifierAgreement(
      temporaryVerification,
      plan,
      planInput.sha256,
      archiveIdentity,
    );

    publication = createPublicationLedger(temporary, output);
    await publishNoReplace(
      temporary,
      publication,
      output,
      normalized.hooks,
    );
    await removeTemporaryLink(
      temporary,
      publication,
      output,
      normalized.hooks,
    );
    await invokeCheckpoint(normalized.hooks, "before-final-verification", {
      finalOutput: publication.path,
    });
    const finalVerification = await verifyPublicSourceZip({
      archive: publication.path,
      entryPlan: normalized.entryPlan,
    });
    requireVerifierAgreement(
      finalVerification,
      plan,
      planInput.sha256,
      archiveIdentity,
    );
    await invokeCheckpoint(normalized.hooks, "after-final-verification", {
      finalOutput: publication.path,
    });
    publication.expectedIdentity = await requireOwnedFilePath(
      publication.path,
      publication.expectedIdentity,
      publication.objectIdentity,
      publication.byteLength,
      1,
      "OUTPUT_PUBLICATION",
      "final-identity",
    );
    await verifyOutputParent(output, "OUTPUT_PUBLICATION");

    return deepFreezeZip({
      status: "ok",
      mode: "prepare-public-source-zip",
      artifactRole: ZIP_ARTIFACT_ROLE,
      formatProfile: ZIP_FORMAT_PROFILE,
      sourceCommit: plan.sourceCommit,
      manifestSha256: plan.manifestSha256,
      membershipReportSha256: plan.membershipReportSha256,
      membershipCount: plan.membershipCount,
      archiveRoot: ZIP_ARCHIVE_ROOT,
      entryPlanSha256: planInput.sha256,
      archiveSha256: archiveIdentity.sha256,
      archiveByteLength: archiveIdentity.byteLength,
      entryCount: plan.entryCount,
      centralDirectoryOffset: plan.centralDirectoryOffset,
      centralDirectoryByteLength: plan.centralDirectoryByteLength,
      canonicalProfileVerified: true,
      entryPlanVerified: true,
      storedPayloadsVerified: true,
      crc32Verified: true,
      authoritativeCorrespondingSource:
        ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE,
      verificationComplete: true,
    });
  } catch (error) {
    const primary = asPublicSourceZipError(
      error,
      "ZIP_WRITE",
      "writer-failure",
    );
    if (temporary?.handle) {
      try {
        await closeTemporaryHandle(temporary, "CLEANUP");
      } catch {
        throw new PublicSourceZipError("CLEANUP", "temporary-close");
      }
    }
    if (output) {
      const cleanup = await cleanupAfterFailure(temporary, publication, output);
      if (!cleanup.complete) {
        const cleanupError = new PublicSourceZipError(
          "CLEANUP",
          "cleanup-identity-uncertain",
        );
        cleanupError.cleanupUnlinkCount = cleanup.unlinkCount;
        throw cleanupError;
      }
      primary.cleanupUnlinkCount = cleanup.unlinkCount;
    }
    throw primary;
  }
}

function parseOptions(argv) {
  const mapping = new Map([
    ["--source-tree", "sourceTree"],
    ["--entry-plan", "entryPlan"],
    ["--output", "output"],
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
  if (["sourceTree", "entryPlan", "output"].some(
    (key) => !Object.hasOwn(result, key),
  )) {
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
  const result = await preparePublicSourceZip(
    parseOptions(process.argv.slice(2)),
  );
  process.stdout.write(JSON.stringify(result) + "\n");
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
