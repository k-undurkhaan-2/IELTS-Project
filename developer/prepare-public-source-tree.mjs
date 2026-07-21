#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, realpathSync } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadValidatedPublicSourceMembership } from "./verify-public-source-membership.mjs";

const FULL_OBJECT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const STAGING_RANDOM_PATTERN = /^[0-9a-f]{32}$/u;
const STAGING_RETRIES = 8;
const CHECKPOINTS = Object.freeze(new Set([
  "after-member-write",
  "before-read-back",
  "after-read-back",
  "before-full-walk",
  "before-publish",
]));
const ERROR_MESSAGES = Object.freeze({
  CLI: "invalid command line or imported API options",
  REPOSITORY: "repository validation failed",
  MEMBERSHIP: "public source membership validation failed",
  OUTPUT_PARENT: "stable ordinary local output parent validation failed",
  STAGING_CREATE: "exclusive staging directory creation failed",
  DIRECTORY_CREATE: "staging directory creation or identity validation failed",
  MEMBER_WRITE: "exclusive member write or source-byte validation failed",
  MEMBER_READBACK: "written member read-back validation failed",
  TREE_AUDIT: "complete staging-tree audit failed",
  PUBLISH: "final tree publication or post-publication validation failed",
  CLEANUP: "verified staging-tree cleanup could not be completed safely",
});

class PublicSourceTreeError extends Error {
  constructor(code) {
    super(ERROR_MESSAGES[code] ?? "public source tree materialization failed");
    this.name = "PublicSourceTreeError";
    this.code = code;
  }
}

function fail(code) {
  throw new PublicSourceTreeError(code);
}

function asPhaseError(code, error) {
  return error instanceof PublicSourceTreeError
    ? error
    : new PublicSourceTreeError(code);
}

async function inPhase(code, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asPhaseError(code, error);
  }
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalNativePath(value) {
  const normalized = path.resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
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

function resolveInside(rootPath, relativePath, code) {
  const resolved = path.join(rootPath, ...relativePath.split("/"));
  if (!isInside(rootPath, resolved)) {
    fail(code);
  }
  return resolved;
}

async function pathState(targetPath) {
  try {
    return await lstat(targetPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function identityFromState(state) {
  const meaningful = state.dev !== 0n || state.ino !== 0n;
  return Object.freeze({
    device: state.dev,
    inode: state.ino,
    meaningful,
  });
}

function identityMatches(recorded, state) {
  if (!recorded.meaningful) {
    return state.dev === 0n && state.ino === 0n;
  }
  return recorded.device === state.dev && recorded.inode === state.ino;
}

function requireSameDevice(rootIdentity, state, code) {
  if (rootIdentity.meaningful && rootIdentity.device !== state.dev) {
    fail(code);
  }
}

async function inspectRealDirectory(targetPath, code) {
  const expectedPath = path.resolve(targetPath);
  const state = await pathState(expectedPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    fail(code);
  }
  const resolved = await realpath(expectedPath);
  if (!pathsEqual(resolved, expectedPath)) {
    fail(code);
  }
  return Object.freeze({
    expectedPath,
    canonicalPath: path.resolve(resolved),
    identity: identityFromState(state),
  });
}

function parentChainPaths(parentPath) {
  const normalizedParent = path.resolve(parentPath);
  const root = path.parse(normalizedParent).root;
  if (!root) {
    fail("OUTPUT_PARENT");
  }
  const values = [path.resolve(root)];
  const relative = path.relative(root, normalizedParent);
  if (!relative) {
    return values;
  }
  let current = root;
  for (const component of relative.split(path.sep)) {
    if (!component || component === "." || component === "..") {
      fail("OUTPUT_PARENT");
    }
    current = path.join(current, component);
    values.push(path.resolve(current));
  }
  return values;
}

async function validateParentChain(parentPath, recorded = null) {
  const chainPaths = parentChainPaths(parentPath);
  const inspected = [];
  for (let index = 0; index < chainPaths.length; index += 1) {
    const record = await inspectRealDirectory(chainPaths[index], "OUTPUT_PARENT");
    if (
      recorded
      && (
        recorded.length !== chainPaths.length
        || !pathsEqual(recorded[index].expectedPath, record.expectedPath)
        || !pathsEqual(recorded[index].canonicalPath, record.canonicalPath)
        || !identitiesEqual(recorded[index].identity, record.identity)
      )
    ) {
      fail("OUTPUT_PARENT");
    }
    inspected.push(record);
  }
  return Object.freeze(inspected);
}

function validateFinalComponent(outputPath) {
  const name = path.basename(outputPath);
  if (
    !name
    || name === "."
    || name === ".."
    || CONTROL_CHARACTER_PATTERN.test(name)
    || name.includes(":")
    || name.includes("/")
    || name.includes('\\')
    || name.endsWith(".")
    || name.endsWith(" ")
    || WINDOWS_RESERVED_NAME_PATTERN.test(name)
  ) {
    fail("OUTPUT_PARENT");
  }
  return name;
}

function validateOutputSyntax(outputArgument) {
  if (typeof outputArgument !== "string" || !path.isAbsolute(outputArgument)) {
    fail("OUTPUT_PARENT");
  }
  if (
    process.platform === "win32"
    && (
      outputArgument.startsWith('\\\\')
      || outputArgument.startsWith('//')
    )
  ) {
    fail("OUTPUT_PARENT");
  }
  const normalized = path.normalize(outputArgument);
  const outputPath = path.resolve(outputArgument);
  if (normalized !== outputArgument || !pathsEqual(outputPath, outputArgument)) {
    fail("OUTPUT_PARENT");
  }
  const parentPath = path.dirname(outputPath);
  if (pathsEqual(parentPath, outputPath)) {
    fail("OUTPUT_PARENT");
  }
  const finalBasename = validateFinalComponent(outputPath);
  return Object.freeze({ outputPath, parentPath, finalBasename });
}

async function prepareOutputBoundary(repoRoot, outputArgument) {
  const syntax = validateOutputSyntax(outputArgument);
  if (pathsEqual(repoRoot, syntax.outputPath) || isInside(repoRoot, syntax.outputPath)) {
    fail("OUTPUT_PARENT");
  }
  const parentChain = await validateParentChain(syntax.parentPath);
  const canonicalParent = parentChain.at(-1).canonicalPath;
  const canonicalOutput = path.join(canonicalParent, syntax.finalBasename);
  if (pathsEqual(repoRoot, canonicalOutput) || isInside(repoRoot, canonicalOutput)) {
    fail("OUTPUT_PARENT");
  }
  if (await pathState(syntax.outputPath)) {
    fail("OUTPUT_PARENT");
  }
  return Object.freeze({
    ...syntax,
    parentChain,
    canonicalParent,
  });
}

function identitiesEqual(left, right) {
  if (!left.meaningful || !right.meaningful) {
    return !left.meaningful && !right.meaningful;
  }
  return left.device === right.device && left.inode === right.inode;
}

function requiredDirectorySet(members) {
  const directories = new Set();
  for (const member of members) {
    const components = member.path.split("/");
    let current = "";
    for (const component of components.slice(0, -1)) {
      current = current ? current + "/" + component : component;
      directories.add(current);
    }
  }
  return directories;
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

  const memberByPath = new Map();
  let previousPath = null;
  for (let index = 0; index < result.members.length; index += 1) {
    const member = result.members[index];
    const projected = result.report.members[index];
    if (
      !member
      || typeof member !== "object"
      || typeof member.path !== "string"
      || !member.path
      || (previousPath !== null && compareOrdinal(previousPath, member.path) >= 0)
      || memberByPath.has(member.path)
      || (member.gitMode !== "100644" && member.gitMode !== "100755")
      || !FULL_OBJECT_ID_PATTERN.test(member.objectId)
      || !Number.isSafeInteger(member.declaredByteSize)
      || member.declaredByteSize < 0
      || !SHA256_PATTERN.test(member.sha256)
      || typeof member.role !== "string"
      || typeof member.licenseScope !== "string"
      || !Buffer.isBuffer(member.blobBytes)
      || member.blobBytes.length !== member.declaredByteSize
      || sha256Bytes(member.blobBytes) !== member.sha256
      || !projected
      || projected.path !== member.path
      || projected.gitMode !== member.gitMode
      || projected.sha256 !== member.sha256
      || projected.role !== member.role
      || projected.licenseScope !== member.licenseScope
    ) {
      fail("MEMBERSHIP");
    }
    previousPath = member.path;
    memberByPath.set(member.path, member);
  }
  return Object.freeze({
    ...result,
    memberByPath,
    requiredDirectories: requiredDirectorySet(result.members),
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

async function createStagingDirectory(output) {
  for (let attempt = 0; attempt < STAGING_RETRIES; attempt += 1) {
    const randomPart = randomBytes(16).toString("hex");
    if (!STAGING_RANDOM_PATTERN.test(randomPart)) {
      fail("STAGING_CREATE");
    }
    const basename = "." + output.finalBasename
      + ".ieltmps-source-tmp-" + randomPart;
    const stagingPath = path.join(output.parentPath, basename);
    if (!isInside(output.parentPath, stagingPath)) {
      fail("STAGING_CREATE");
    }
    try {
      await mkdir(stagingPath, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error && error.code === "EEXIST") {
        continue;
      }
      throw error;
    }
    let provisional = null;
    try {
      const stagingState = await pathState(stagingPath);
      if (
        !stagingState
        || stagingState.isSymbolicLink()
        || !stagingState.isDirectory()
      ) {
        fail("CLEANUP");
      }
      const resolved = await realpath(stagingPath);
      provisional = Object.freeze({
        path: stagingPath,
        basename,
        canonicalPath: path.resolve(resolved),
        identity: identityFromState(stagingState),
      });
      if (
        !pathsEqual(resolved, stagingPath)
        || !pathsEqual(path.dirname(resolved), output.canonicalParent)
      ) {
        fail("CLEANUP");
      }
      requireSameDevice(
        output.parentChain.at(-1).identity,
        stagingState,
        "STAGING_CREATE",
      );
      return provisional;
    } catch (error) {
      if (!provisional) {
        throw new PublicSourceTreeError("CLEANUP");
      }
      try {
        await cleanupVerifiedStaging(output, provisional);
      } catch {
        throw new PublicSourceTreeError("CLEANUP");
      }
      throw error;
    }
  }
  fail("STAGING_CREATE");
}

async function verifyDirectoryIdentity(targetPath, recorded, rootIdentity, code) {
  const state = await pathState(targetPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    fail(code);
  }
  const resolved = await realpath(targetPath);
  if (
    !pathsEqual(resolved, targetPath)
    || !identityMatches(recorded.identity, state)
  ) {
    fail(code);
  }
  requireSameDevice(rootIdentity, state, code);
}

async function verifyStagingIdentity(staging, code) {
  await verifyDirectoryIdentity(
    staging.path,
    staging,
    staging.identity,
    code,
  );
}

async function ensureMemberDirectories(
  staging,
  relativePath,
  createdDirectories,
) {
  const components = relativePath.split("/").slice(0, -1);
  let relativeDirectory = "";
  let parentPath = staging.path;
  let parentRecord = staging;
  for (const component of components) {
    relativeDirectory = relativeDirectory
      ? relativeDirectory + "/" + component
      : component;
    const directoryPath = resolveInside(
      staging.path,
      relativeDirectory,
      "DIRECTORY_CREATE",
    );
    await verifyDirectoryIdentity(
      parentPath,
      parentRecord,
      staging.identity,
      "DIRECTORY_CREATE",
    );
    const recorded = createdDirectories.get(relativeDirectory);
    if (recorded) {
      await verifyDirectoryIdentity(
        directoryPath,
        recorded,
        staging.identity,
        "DIRECTORY_CREATE",
      );
    } else {
      if (await pathState(directoryPath)) {
        fail("DIRECTORY_CREATE");
      }
      await mkdir(directoryPath, { recursive: false, mode: 0o700 });
      const inspected = await inspectRealDirectory(
        directoryPath,
        "DIRECTORY_CREATE",
      );
      const directoryState = await lstat(directoryPath, { bigint: true });
      requireSameDevice(staging.identity, directoryState, "DIRECTORY_CREATE");
      createdDirectories.set(relativeDirectory, inspected);
      parentRecord = inspected;
    }
    parentPath = directoryPath;
    parentRecord = createdDirectories.get(relativeDirectory);
  }
}

async function verifyMemberDirectoryChain(
  staging,
  relativePath,
  createdDirectories,
  code,
) {
  await verifyStagingIdentity(staging, code);
  const components = relativePath.split("/").slice(0, -1);
  let relativeDirectory = "";
  for (const component of components) {
    relativeDirectory = relativeDirectory
      ? relativeDirectory + "/" + component
      : component;
    const record = createdDirectories.get(relativeDirectory);
    if (!record) {
      fail(code);
    }
    await verifyDirectoryIdentity(
      resolveInside(staging.path, relativeDirectory, code),
      record,
      staging.identity,
      code,
    );
  }
}

function noFollowFlag() {
  return process.platform !== "win32"
    && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

function expectedUnixMode(member) {
  return member.gitMode === "100755" ? 0o755 : 0o644;
}

function verifyRegularFileState(state, stagingIdentity, member, code) {
  if (
    !state.isFile()
    || state.isSymbolicLink()
    || state.nlink !== 1n
    || state.size !== BigInt(member.declaredByteSize)
  ) {
    fail(code);
  }
  requireSameDevice(stagingIdentity, state, code);
  if (
    process.platform !== "win32"
    && Number(state.mode & 0o777n) !== expectedUnixMode(member)
  ) {
    fail(code);
  }
}

async function verifyFilePathIdentity(
  filePath,
  expectedIdentity,
  stagingIdentity,
  member,
  code,
) {
  const state = await pathState(filePath);
  if (!state || state.isSymbolicLink()) {
    fail(code);
  }
  const resolved = await realpath(filePath);
  if (!pathsEqual(resolved, filePath) || !identityMatches(expectedIdentity, state)) {
    fail(code);
  }
  verifyRegularFileState(state, stagingIdentity, member, code);
}

async function writeAllBytes(handle, blobBytes) {
  let offset = 0;
  while (offset < blobBytes.length) {
    const result = await handle.write(
      blobBytes,
      offset,
      blobBytes.length - offset,
      offset,
    );
    if (!result || !Number.isInteger(result.bytesWritten) || result.bytesWritten <= 0) {
      fail("MEMBER_WRITE");
    }
    offset += result.bytesWritten;
  }
}

async function readCompleteHandle(handle, expectedLength, code) {
  const bytes = Buffer.alloc(expectedLength);
  let offset = 0;
  while (offset < expectedLength) {
    const result = await handle.read(
      bytes,
      offset,
      expectedLength - offset,
      offset,
    );
    if (!result || !Number.isInteger(result.bytesRead) || result.bytesRead <= 0) {
      fail(code);
    }
    offset += result.bytesRead;
  }
  const extra = Buffer.alloc(1);
  const trailing = await handle.read(extra, 0, 1, expectedLength);
  if (!trailing || trailing.bytesRead !== 0) {
    fail(code);
  }
  return bytes;
}

async function readBackAndVerify(
  staging,
  filePath,
  fileRecord,
  member,
  code,
) {
  let handle;
  try {
    handle = await open(
      filePath,
      FS_CONSTANTS.O_RDONLY | noFollowFlag(),
    );
    const before = await handle.stat({ bigint: true });
    verifyRegularFileState(before, staging.identity, member, code);
    if (!identityMatches(fileRecord.identity, before)) {
      fail(code);
    }
    await verifyFilePathIdentity(
      filePath,
      fileRecord.identity,
      staging.identity,
      member,
      code,
    );
    const bytes = await readCompleteHandle(handle, member.declaredByteSize, code);
    const after = await handle.stat({ bigint: true });
    verifyRegularFileState(after, staging.identity, member, code);
    if (!identityMatches(fileRecord.identity, after)) {
      fail(code);
    }
    if (
      !bytes.equals(member.blobBytes)
      || bytes.length !== member.declaredByteSize
      || sha256Bytes(bytes) !== member.sha256
    ) {
      fail(code);
    }
    return bytes;
  } catch (error) {
    throw asPhaseError(code, error);
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch (error) {
        throw asPhaseError(code, error);
      }
    }
  }
}

async function materializeMember({
  staging,
  member,
  memberIndex,
  createdDirectories,
  createdFiles,
  testHooks,
}) {
  await inPhase("MEMBER_WRITE", async () => {
    if (
      member.blobBytes.length !== member.declaredByteSize
      || sha256Bytes(member.blobBytes) !== member.sha256
    ) {
      fail("MEMBER_WRITE");
    }
    await ensureMemberDirectories(
      staging,
      member.path,
      createdDirectories,
    );
    await verifyMemberDirectoryChain(
      staging,
      member.path,
      createdDirectories,
      "MEMBER_WRITE",
    );
    const stagedFilePath = resolveInside(
      staging.path,
      member.path,
      "MEMBER_WRITE",
    );
    if (await pathState(stagedFilePath)) {
      fail("MEMBER_WRITE");
    }

    let handle;
    let fileRecord;
    try {
      handle = await open(
        stagedFilePath,
        FS_CONSTANTS.O_CREAT
          | FS_CONSTANTS.O_EXCL
          | FS_CONSTANTS.O_WRONLY
          | noFollowFlag(),
        0o600,
      );
      const initial = await handle.stat({ bigint: true });
      if (!initial.isFile() || initial.nlink !== 1n || initial.size !== 0n) {
        fail("MEMBER_WRITE");
      }
      requireSameDevice(staging.identity, initial, "MEMBER_WRITE");
      const initialIdentity = identityFromState(initial);
      const pathInitial = await pathState(stagedFilePath);
      if (
        !pathInitial
        || pathInitial.isSymbolicLink()
        || !identityMatches(initialIdentity, pathInitial)
      ) {
        fail("MEMBER_WRITE");
      }
      await writeAllBytes(handle, member.blobBytes);
      if (sha256Bytes(member.blobBytes) !== member.sha256) {
        fail("MEMBER_WRITE");
      }
      if (process.platform !== "win32") {
        await handle.chmod(expectedUnixMode(member));
      }
      const complete = await handle.stat({ bigint: true });
      verifyRegularFileState(
        complete,
        staging.identity,
        member,
        "MEMBER_WRITE",
      );
      if (!identityMatches(initialIdentity, complete)) {
        fail("MEMBER_WRITE");
      }
      fileRecord = Object.freeze({
        identity: identityFromState(complete),
      });
      await verifyFilePathIdentity(
        stagedFilePath,
        fileRecord.identity,
        staging.identity,
        member,
        "MEMBER_WRITE",
      );
    } finally {
      if (handle) {
        await handle.close();
      }
    }
    createdFiles.set(member.path, fileRecord);

    const memberContext = Object.freeze({
      memberIndex,
      relativePath: member.path,
      stagingRoot: staging.path,
      stagedFilePath,
    });
    await invokeCheckpoint(
      testHooks,
      "after-member-write",
      memberContext,
      "MEMBER_WRITE",
    );
    await invokeCheckpoint(
      testHooks,
      "before-read-back",
      memberContext,
      "MEMBER_READBACK",
    );
    await readBackAndVerify(
      staging,
      stagedFilePath,
      fileRecord,
      member,
      "MEMBER_READBACK",
    );
    await invokeCheckpoint(
      testHooks,
      "after-read-back",
      memberContext,
      "MEMBER_READBACK",
    );
  });
}

function registerAuditedPath(relativePath, kind, registry, code) {
  const identities = [
    "case:" + relativePath.toLowerCase(),
    "nfc:" + relativePath.normalize("NFC"),
    "nfd:" + relativePath.normalize("NFD"),
    "portable:" + relativePath.normalize("NFC").toLowerCase(),
  ];
  for (const identity of identities) {
    const existing = registry.get(identity);
    if (existing && (existing.path !== relativePath || existing.kind !== kind)) {
      fail(code);
    }
    registry.set(identity, Object.freeze({ path: relativePath, kind }));
  }
}

function setsEqual(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

async function auditTree({
  rootPath,
  rootIdentity,
  membership,
  createdDirectories,
  createdFiles,
  code,
}) {
  const rootRecord = Object.freeze({ identity: rootIdentity });
  await verifyDirectoryIdentity(
    rootPath,
    rootRecord,
    rootIdentity,
    code,
  );
  if (
    createdDirectories.size !== membership.requiredDirectories.size
    || createdFiles.size !== membership.members.length
  ) {
    fail(code);
  }

  const auditedFiles = new Set();
  const auditedDirectories = new Set();
  const portableRegistry = new Map();

  async function walk(directoryPath, relativeDirectory) {
    const entries = await readdir(directoryPath, { withFileTypes: true });
    entries.sort((left, right) => compareOrdinal(left.name, right.name));
    if (relativeDirectory && entries.length === 0) {
      fail(code);
    }
    for (const entry of entries) {
      const entryPath = path.join(directoryPath, entry.name);
      if (!isInside(rootPath, entryPath)) {
        fail(code);
      }
      const relativePath = path.relative(rootPath, entryPath)
        .split(path.sep)
        .join("/");
      if (
        !relativePath
        || relativePath.split("/").some(
          (component) => component.toLowerCase() === ".git",
        )
      ) {
        fail(code);
      }
      const state = await pathState(entryPath);
      if (!state || state.isSymbolicLink()) {
        fail(code);
      }
      const resolved = await realpath(entryPath);
      if (!pathsEqual(resolved, entryPath)) {
        fail(code);
      }

      if (state.isDirectory()) {
        registerAuditedPath(relativePath, "directory", portableRegistry, code);
        if (
          !membership.requiredDirectories.has(relativePath)
          || auditedDirectories.has(relativePath)
        ) {
          fail(code);
        }
        const record = createdDirectories.get(relativePath);
        if (!record || !identityMatches(record.identity, state)) {
          fail(code);
        }
        requireSameDevice(rootIdentity, state, code);
        auditedDirectories.add(relativePath);
        await walk(entryPath, relativePath);
        continue;
      }

      if (!state.isFile()) {
        fail(code);
      }
      registerAuditedPath(relativePath, "file", portableRegistry, code);
      const member = membership.memberByPath.get(relativePath);
      const fileRecord = createdFiles.get(relativePath);
      if (!member || !fileRecord || auditedFiles.has(relativePath)) {
        fail(code);
      }
      verifyRegularFileState(state, rootIdentity, member, code);
      if (!identityMatches(fileRecord.identity, state)) {
        fail(code);
      }
      const bytes = await readBackAndVerify(
        { identity: rootIdentity },
        entryPath,
        fileRecord,
        member,
        code,
      );
      if (
        bytes.length !== member.declaredByteSize
        || sha256Bytes(bytes) !== member.sha256
      ) {
        fail(code);
      }
      auditedFiles.add(relativePath);
    }
  }

  await walk(rootPath, "");
  if (
    !setsEqual(auditedFiles, new Set(membership.memberByPath.keys()))
    || !setsEqual(auditedDirectories, membership.requiredDirectories)
  ) {
    fail(code);
  }
}

function stagingBasenameIsExact(output, staging) {
  const prefix = "." + output.finalBasename + ".ieltmps-source-tmp-";
  return staging.basename.startsWith(prefix)
    && staging.basename.length === prefix.length + 32
    && STAGING_RANDOM_PATTERN.test(staging.basename.slice(prefix.length))
    && path.basename(staging.path) === staging.basename
    && pathsEqual(path.dirname(staging.path), output.parentPath);
}

async function cleanupVerifiedStaging(output, staging) {
  if (!stagingBasenameIsExact(output, staging)) {
    fail("CLEANUP");
  }
  await validateParentChain(output.parentPath, output.parentChain);
  const state = await pathState(staging.path);
  if (!state) {
    return;
  }
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !identityMatches(staging.identity, state)
  ) {
    fail("CLEANUP");
  }
  const resolved = await realpath(staging.path);
  if (
    !pathsEqual(resolved, staging.path)
    || !pathsEqual(path.dirname(resolved), output.canonicalParent)
    || !isInside(output.parentPath, staging.path)
  ) {
    fail("CLEANUP");
  }
  await rm(staging.path, { recursive: true, force: false });
  if (await pathState(staging.path)) {
    fail("CLEANUP");
  }
}

/*
 * Trusted-parent boundary and crash contract:
 *
 * Portable Node APIs cannot lock every ancestor against hostile concurrent
 * replacement and do not expose one cross-platform, no-replace directory
 * rename. The caller must therefore provide a stable local output parent that
 * is not concurrently controlled by an adversary. We still revalidate every
 * ancestor, publish only a random same-parent staging directory, recheck final
 * absence and identities immediately before rename, and verify again after it.
 *
 * Caught pre-publication failures remove only the identity-verified staging
 * tree. A process crash or power loss can leave its random sibling; a crash
 * after rename can leave a complete final tree. Stale siblings require exact
 * manual inspection and are never wildcard-cleaned. File bytes are verified as
 * process-visible data, but this batch intentionally performs no fsync and
 * makes no power-loss durability promise. Host times, owner/group, ACLs and
 * extended attributes are noncanonical and are neither set nor claimed.
 */
export async function materializePublicSourceTree({
  repo,
  commit,
  output,
  testHooks,
} = {}) {
  if (typeof testHooks !== "undefined" && typeof testHooks !== "function") {
    fail("CLI");
  }
  if (typeof repo !== "string" || !path.isAbsolute(repo)) {
    fail("REPOSITORY");
  }
  if (typeof commit !== "string") {
    fail("MEMBERSHIP");
  }

  const membership = await inPhase("MEMBERSHIP", async () => (
    validateMembershipResult(
      await loadValidatedPublicSourceMembership({ repo, commit }),
    )
  ));
  const outputBoundary = await inPhase("OUTPUT_PARENT", async () => (
    prepareOutputBoundary(membership.repoRoot, output)
  ));

  let staging = null;
  let stagingWasRenamed = false;
  try {
    await inPhase("STAGING_CREATE", async () => {
      await validateParentChain(
        outputBoundary.parentPath,
        outputBoundary.parentChain,
      );
      if (await pathState(outputBoundary.outputPath)) {
        fail("STAGING_CREATE");
      }
    });
    staging = await inPhase(
      "STAGING_CREATE",
      async () => createStagingDirectory(outputBoundary),
    );
    await inPhase("STAGING_CREATE", async () => {
      await validateParentChain(
        outputBoundary.parentPath,
        outputBoundary.parentChain,
      );
      await verifyStagingIdentity(staging, "STAGING_CREATE");
      if (await pathState(outputBoundary.outputPath)) {
        fail("STAGING_CREATE");
      }
    });

    const createdDirectories = new Map();
    const createdFiles = new Map();
    for (let index = 0; index < membership.members.length; index += 1) {
      await materializeMember({
        staging,
        member: membership.members[index],
        memberIndex: index,
        createdDirectories,
        createdFiles,
        testHooks,
      });
    }

    await invokeCheckpoint(
      testHooks,
      "before-full-walk",
      Object.freeze({ stagingRoot: staging.path }),
      "TREE_AUDIT",
    );
    await inPhase("TREE_AUDIT", async () => auditTree({
      rootPath: staging.path,
      rootIdentity: staging.identity,
      membership,
      createdDirectories,
      createdFiles,
      code: "TREE_AUDIT",
    }));

    await invokeCheckpoint(
      testHooks,
      "before-publish",
      Object.freeze({ stagingRoot: staging.path }),
      "PUBLISH",
    );
    await inPhase("PUBLISH", async () => {
      await validateParentChain(
        outputBoundary.parentPath,
        outputBoundary.parentChain,
      );
      await verifyStagingIdentity(staging, "PUBLISH");
      if (await pathState(outputBoundary.outputPath)) {
        fail("PUBLISH");
      }
      await auditTree({
        rootPath: staging.path,
        rootIdentity: staging.identity,
        membership,
        createdDirectories,
        createdFiles,
        code: "PUBLISH",
      });
      if (await pathState(outputBoundary.outputPath)) {
        fail("PUBLISH");
      }
      await rename(staging.path, outputBoundary.outputPath);
      stagingWasRenamed = true;

      const finalRecord = Object.freeze({ identity: staging.identity });
      await verifyDirectoryIdentity(
        outputBoundary.outputPath,
        finalRecord,
        staging.identity,
        "PUBLISH",
      );
      if (await pathState(staging.path)) {
        fail("PUBLISH");
      }
      await auditTree({
        rootPath: outputBoundary.outputPath,
        rootIdentity: staging.identity,
        membership,
        createdDirectories,
        createdFiles,
        code: "PUBLISH",
      });
    });

    return Object.freeze({
      status: "ok",
      mode: "tree-materialization",
      sourceCommit: membership.sourceCommit,
      manifestSha256: membership.manifestSha256,
      membershipReportSha256: sha256Bytes(membership.reportBytes),
      membershipCount: membership.members.length,
      membershipValid: true,
      treeMaterialized: true,
      correspondingSourceComplete: false,
      publicationBlocked: true,
    });
  } catch (error) {
    const primary = error instanceof PublicSourceTreeError
      ? error
      : new PublicSourceTreeError("MEMBERSHIP");
    if (staging && !stagingWasRenamed) {
      try {
        await cleanupVerifiedStaging(outputBoundary, staging);
      } catch {
        throw new PublicSourceTreeError("CLEANUP");
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
  const summary = await materializePublicSourceTree(options);
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
    const safeError = error instanceof PublicSourceTreeError
      ? error
      : new PublicSourceTreeError("CLI");
    process.stderr.write(
      "ERROR " + safeError.code + ": " + safeError.message + "\n",
    );
    process.exitCode = 1;
  });
}
