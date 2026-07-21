import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

export const ARCHIVE_FORMAT = "tar-ustar-v1";
export const ARCHIVE_ROOT = "ieltmps-source/";
export const BLOCK_SIZE = 512;
export const END_BLOCK_COUNT = 2;
export const MAX_USTAR_SIZE = 0o77777777777;

export const USTAR_LAYOUT = Object.freeze({
  name: Object.freeze({ offset: 0, length: 100 }),
  mode: Object.freeze({ offset: 100, length: 8 }),
  uid: Object.freeze({ offset: 108, length: 8 }),
  gid: Object.freeze({ offset: 116, length: 8 }),
  size: Object.freeze({ offset: 124, length: 12 }),
  mtime: Object.freeze({ offset: 136, length: 12 }),
  checksum: Object.freeze({ offset: 148, length: 8 }),
  typeflag: Object.freeze({ offset: 156, length: 1 }),
  linkname: Object.freeze({ offset: 157, length: 100 }),
  magic: Object.freeze({ offset: 257, length: 6 }),
  version: Object.freeze({ offset: 263, length: 2 }),
  uname: Object.freeze({ offset: 265, length: 32 }),
  gname: Object.freeze({ offset: 297, length: 32 }),
  devmajor: Object.freeze({ offset: 329, length: 8 }),
  devminor: Object.freeze({ offset: 337, length: 8 }),
  prefix: Object.freeze({ offset: 345, length: 155 }),
  reserved: Object.freeze({ offset: 500, length: 12 }),
});

const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u;
const SURROGATE_PATTERN = /[\uD800-\uDFFF]/u;
const DRIVE_LETTER_PATTERN = /^[A-Za-z]:/u;
const URI_PREFIX_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const WINDOWS_INVALID_CHARACTER_PATTERN = /[<>:"|?*]/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const TEMPORARY_RANDOM_PATTERN = /^[0-9a-f]{32}$/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

export class ArchiveCoreError extends Error {
  constructor(reason) {
    super("restricted USTAR invariant failed");
    this.name = "ArchiveCoreError";
    this.reason = reason;
  }
}

function fail(reason) {
  throw new ArchiveCoreError(reason);
}

export function compareOrdinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function canonicalNativePath(value) {
  const normalized = path.resolve(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

export function pathsEqual(left, right) {
  return canonicalNativePath(left) === canonicalNativePath(right);
}

export function isInside(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return Boolean(relative)
    && relative !== ".."
    && !relative.startsWith(".." + path.sep)
    && !path.isAbsolute(relative);
}

export function safeAddLength(current, increment) {
  if (
    !Number.isSafeInteger(current)
    || current < 0
    || !Number.isSafeInteger(increment)
    || increment < 0
    || current > Number.MAX_SAFE_INTEGER - increment
  ) {
    fail("archive-length");
  }
  return current + increment;
}

function fieldSlice(header, field) {
  return header.subarray(field.offset, field.offset + field.length);
}

function allZero(value) {
  for (const byte of value) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

export function isZeroBuffer(value) {
  return Buffer.isBuffer(value) && allZero(value);
}

export function requireZeroBuffer(value) {
  if (!Buffer.isBuffer(value) || !allZero(value)) {
    fail("nonzero-padding");
  }
}

function validatePathComponent(component) {
  if (
    !component
    || component === "."
    || component === ".."
    || WINDOWS_INVALID_CHARACTER_PATTERN.test(component)
    || component.endsWith(".")
    || component.endsWith(" ")
    || WINDOWS_RESERVED_NAME_PATTERN.test(component)
  ) {
    fail("unsafe-member-path");
  }
}

export function validateMemberRelativePath(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || CONTROL_CHARACTER_PATTERN.test(value)
    || SURROGATE_PATTERN.test(value)
    || value.includes("\\")
    || value.includes(":")
    || value.startsWith("/")
    || DRIVE_LETTER_PATTERN.test(value)
    || URI_PREFIX_PATTERN.test(value)
    || path.posix.isAbsolute(value)
    || value.endsWith("/")
    || path.posix.normalize(value) !== value
  ) {
    fail("unsafe-member-path");
  }
  const components = value.split("/");
  for (const component of components) {
    validatePathComponent(component);
  }
  return value;
}

export function archivePathForMember(relativePath) {
  return ARCHIVE_ROOT + validateMemberRelativePath(relativePath);
}

export function validateArchiveMemberPath(value) {
  if (
    typeof value !== "string"
    || !value.startsWith(ARCHIVE_ROOT)
    || value === ARCHIVE_ROOT
  ) {
    fail("archive-root");
  }
  const relativePath = value.slice(ARCHIVE_ROOT.length);
  validateMemberRelativePath(relativePath);
  if (ARCHIVE_ROOT + relativePath !== value) {
    fail("archive-root");
  }
  return value;
}

export function archiveIdentityKeys(value) {
  validateArchiveMemberPath(value);
  return Object.freeze([
    "case:" + value.toLowerCase(),
    "nfc:" + value.normalize("NFC"),
    "nfd:" + value.normalize("NFD"),
    "portable:" + value.normalize("NFC").toLowerCase(),
  ]);
}

export function registerArchiveMemberPath(value, registry) {
  if (!(registry instanceof Map)) {
    fail("archive-registry");
  }
  for (const identity of archiveIdentityKeys(value)) {
    const existing = registry.get(identity);
    if (existing !== undefined) {
      fail(existing === value ? "duplicate-member" : "portable-collision");
    }
    registry.set(identity, value);
  }
}

export function splitUstarPath(value) {
  validateArchiveMemberPath(value);
  const fullBytes = Buffer.from(value, "utf8");
  if (fullBytes.length <= USTAR_LAYOUT.name.length) {
    return Object.freeze({ name: value, prefix: "" });
  }

  let separator = value.lastIndexOf("/");
  while (separator > 0) {
    const prefix = value.slice(0, separator);
    const name = value.slice(separator + 1);
    if (
      prefix.length > 0
      && name.length > 0
      && Buffer.byteLength(prefix, "utf8") <= USTAR_LAYOUT.prefix.length
      && Buffer.byteLength(name, "utf8") <= USTAR_LAYOUT.name.length
    ) {
      return Object.freeze({ name, prefix });
    }
    separator = value.lastIndexOf("/", separator - 1);
  }
  fail("ustar-path-unrepresentable");
}

export function tarModeForGitMode(gitMode) {
  if (gitMode === "100644") {
    return 0o644;
  }
  if (gitMode === "100755") {
    return 0o755;
  }
  fail("git-mode");
}

export function paddingLength(size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_USTAR_SIZE) {
    fail("member-size");
  }
  return (BLOCK_SIZE - (size % BLOCK_SIZE)) % BLOCK_SIZE;
}

function encodeCanonicalOctal(value, width, reason) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(reason);
  }
  const digits = width - 1;
  const encoded = value.toString(8);
  if (encoded.length > digits) {
    fail(reason);
  }
  return Buffer.from(encoded.padStart(digits, "0") + "\0", "ascii");
}

function parseCanonicalOctal(value, width, reason) {
  if (
    !Buffer.isBuffer(value)
    || value.length !== width
    || value.at(-1) !== 0
  ) {
    fail(reason);
  }
  let result = 0;
  for (let index = 0; index < width - 1; index += 1) {
    const byte = value[index];
    if (byte < 0x30 || byte > 0x37) {
      fail(reason);
    }
    result = result * 8 + (byte - 0x30);
    if (!Number.isSafeInteger(result)) {
      fail(reason);
    }
  }
  return result;
}

function encodeChecksum(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail("checksum-field");
  }
  const encoded = value.toString(8);
  if (encoded.length > 6) {
    fail("checksum-field");
  }
  return Buffer.from(encoded.padStart(6, "0") + "\0 ", "ascii");
}

function copyStringField(header, field, value, reason) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > field.length) {
    fail(reason);
  }
  bytes.copy(header, field.offset);
}

function copyField(header, field, value) {
  if (!Buffer.isBuffer(value) || value.length !== field.length) {
    fail("header-field-width");
  }
  value.copy(header, field.offset);
}

export function calculateHeaderChecksum(header) {
  if (!Buffer.isBuffer(header) || header.length !== BLOCK_SIZE) {
    fail("header-size");
  }
  const copy = Buffer.from(header);
  copy.fill(
    0x20,
    USTAR_LAYOUT.checksum.offset,
    USTAR_LAYOUT.checksum.offset + USTAR_LAYOUT.checksum.length,
  );
  let checksum = 0;
  for (const byte of copy) {
    checksum += byte;
  }
  if (!Number.isSafeInteger(checksum)) {
    fail("checksum-field");
  }
  return checksum;
}

export function encodeUstarHeader({ relativePath, gitMode, size } = {}) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_USTAR_SIZE) {
    fail("member-size");
  }
  const archivePath = archivePathForMember(relativePath);
  const split = splitUstarPath(archivePath);
  const mode = tarModeForGitMode(gitMode);
  const header = Buffer.alloc(BLOCK_SIZE);

  copyStringField(header, USTAR_LAYOUT.name, split.name, "ustar-name");
  copyField(header, USTAR_LAYOUT.mode, encodeCanonicalOctal(mode, 8, "mode-field"));
  copyField(header, USTAR_LAYOUT.uid, encodeCanonicalOctal(0, 8, "uid-field"));
  copyField(header, USTAR_LAYOUT.gid, encodeCanonicalOctal(0, 8, "gid-field"));
  copyField(header, USTAR_LAYOUT.size, encodeCanonicalOctal(size, 12, "size-field"));
  copyField(header, USTAR_LAYOUT.mtime, encodeCanonicalOctal(0, 12, "mtime-field"));
  header.fill(
    0x20,
    USTAR_LAYOUT.checksum.offset,
    USTAR_LAYOUT.checksum.offset + USTAR_LAYOUT.checksum.length,
  );
  header[USTAR_LAYOUT.typeflag.offset] = 0x30;
  Buffer.from("ustar\0", "ascii").copy(header, USTAR_LAYOUT.magic.offset);
  Buffer.from("00", "ascii").copy(header, USTAR_LAYOUT.version.offset);
  copyField(
    header,
    USTAR_LAYOUT.devmajor,
    encodeCanonicalOctal(0, 8, "devmajor-field"),
  );
  copyField(
    header,
    USTAR_LAYOUT.devminor,
    encodeCanonicalOctal(0, 8, "devminor-field"),
  );
  copyStringField(header, USTAR_LAYOUT.prefix, split.prefix, "ustar-prefix");
  copyField(
    header,
    USTAR_LAYOUT.checksum,
    encodeChecksum(calculateHeaderChecksum(header)),
  );
  return header;
}

function requireExactAscii(header, field, expected, reason) {
  if (!fieldSlice(header, field).equals(Buffer.from(expected, "ascii"))) {
    fail(reason);
  }
}

function requireZeroField(header, field, reason) {
  if (!allZero(fieldSlice(header, field))) {
    fail(reason);
  }
}

function decodeStringField(header, field, { allowEmpty, reason }) {
  const bytes = fieldSlice(header, field);
  const zeroIndex = bytes.indexOf(0);
  const content = zeroIndex === -1 ? bytes : bytes.subarray(0, zeroIndex);
  if (zeroIndex !== -1 && !allZero(bytes.subarray(zeroIndex))) {
    fail(reason);
  }
  if (!allowEmpty && content.length === 0) {
    fail(reason);
  }
  try {
    return UTF8_DECODER.decode(content);
  } catch {
    fail(reason);
  }
}

function verifyCanonicalChecksum(header) {
  const calculated = calculateHeaderChecksum(header);
  const expected = encodeChecksum(calculated);
  if (!fieldSlice(header, USTAR_LAYOUT.checksum).equals(expected)) {
    fail("header-checksum");
  }
  return calculated;
}

export function parseUstarHeader(header) {
  if (!Buffer.isBuffer(header) || header.length !== BLOCK_SIZE) {
    fail("header-size");
  }
  if (allZero(header)) {
    fail("premature-zero-header");
  }
  const checksum = verifyCanonicalChecksum(header);
  requireExactAscii(header, USTAR_LAYOUT.magic, "ustar\0", "ustar-magic");
  requireExactAscii(header, USTAR_LAYOUT.version, "00", "ustar-version");
  if (header[USTAR_LAYOUT.typeflag.offset] !== 0x30) {
    fail("typeflag");
  }
  requireZeroField(header, USTAR_LAYOUT.linkname, "linkname");
  requireZeroField(header, USTAR_LAYOUT.uname, "uname");
  requireZeroField(header, USTAR_LAYOUT.gname, "gname");
  requireZeroField(header, USTAR_LAYOUT.reserved, "reserved");

  const mode = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.mode),
    USTAR_LAYOUT.mode.length,
    "mode-field",
  );
  const uid = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.uid),
    USTAR_LAYOUT.uid.length,
    "uid-field",
  );
  const gid = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.gid),
    USTAR_LAYOUT.gid.length,
    "gid-field",
  );
  const size = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.size),
    USTAR_LAYOUT.size.length,
    "size-field",
  );
  const mtime = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.mtime),
    USTAR_LAYOUT.mtime.length,
    "mtime-field",
  );
  const devmajor = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.devmajor),
    USTAR_LAYOUT.devmajor.length,
    "devmajor-field",
  );
  const devminor = parseCanonicalOctal(
    fieldSlice(header, USTAR_LAYOUT.devminor),
    USTAR_LAYOUT.devminor.length,
    "devminor-field",
  );
  if (mode !== 0o644 && mode !== 0o755) {
    fail("mode-value");
  }
  if (uid !== 0 || gid !== 0 || mtime !== 0 || devmajor !== 0 || devminor !== 0) {
    fail("canonical-metadata");
  }
  if (size > MAX_USTAR_SIZE) {
    fail("member-size");
  }

  const name = decodeStringField(header, USTAR_LAYOUT.name, {
    allowEmpty: false,
    reason: "ustar-name",
  });
  const prefix = decodeStringField(header, USTAR_LAYOUT.prefix, {
    allowEmpty: true,
    reason: "ustar-prefix",
  });
  const archivePath = prefix ? prefix + "/" + name : name;
  validateArchiveMemberPath(archivePath);

  return Object.freeze({
    name,
    prefix,
    archivePath,
    mode,
    uid,
    gid,
    size,
    mtime,
    devmajor,
    devminor,
    checksum,
    typeflag: "0",
  });
}

export function requireHeaderMatchesMember(parsed, member) {
  if (!parsed || typeof parsed !== "object" || !member || typeof member !== "object") {
    fail("header-member-shape");
  }
  const archivePath = archivePathForMember(member.path);
  const split = splitUstarPath(archivePath);
  const expectedMode = tarModeForGitMode(member.gitMode);
  if (
    parsed.archivePath !== archivePath
    || parsed.name !== split.name
    || parsed.prefix !== split.prefix
    || parsed.mode !== expectedMode
    || parsed.size !== member.declaredByteSize
    || parsed.typeflag !== "0"
  ) {
    fail("header-member-mismatch");
  }
}

export async function readExactly(handle, length) {
  if (
    !handle
    || typeof handle.read !== "function"
    || !Number.isSafeInteger(length)
    || length < 0
  ) {
    fail("exact-read");
  }
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const result = await handle.read(bytes, offset, length - offset, null);
    if (
      !result
      || !Number.isInteger(result.bytesRead)
      || result.bytesRead <= 0
      || result.bytesRead > length - offset
    ) {
      fail("exact-read");
    }
    offset += result.bytesRead;
  }
  return bytes;
}

export async function readForEof(handle) {
  if (!handle || typeof handle.read !== "function") {
    fail("exact-read");
  }
  const byte = Buffer.alloc(1);
  const result = await handle.read(byte, 0, 1, null);
  if (!result || !Number.isInteger(result.bytesRead)) {
    fail("exact-read");
  }
  if (result.bytesRead !== 0 && result.bytesRead !== 1) {
    fail("exact-read");
  }
  return Object.freeze({ bytesRead: result.bytesRead, byte });
}

export async function pathState(targetPath) {
  try {
    return await lstat(targetPath, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

export function identityFromState(state) {
  if (!state || typeof state !== "object") {
    fail("file-identity");
  }
  const meaningful = state.dev !== 0n || state.ino !== 0n;
  return Object.freeze({
    device: state.dev,
    inode: state.ino,
    meaningful,
  });
}

export function identitiesEqual(left, right) {
  if (!left || !right) {
    return false;
  }
  if (!left.meaningful || !right.meaningful) {
    return !left.meaningful && !right.meaningful;
  }
  return left.device === right.device && left.inode === right.inode;
}

export function identityMatches(recorded, state) {
  return identitiesEqual(recorded, identityFromState(state));
}

function requireSameDevice(parentIdentity, state) {
  if (
    parentIdentity
    && parentIdentity.meaningful
    && parentIdentity.device !== state.dev
  ) {
    fail("file-device");
  }
}

async function inspectRealDirectory(targetPath) {
  const expectedPath = path.resolve(targetPath);
  const state = await pathState(expectedPath);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    fail("parent-directory");
  }
  const resolved = await realpath(expectedPath);
  if (!pathsEqual(resolved, expectedPath)) {
    fail("parent-reparse");
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
    fail("parent-directory");
  }
  const values = [path.resolve(root)];
  const relative = path.relative(root, normalizedParent);
  if (!relative) {
    return values;
  }
  let current = root;
  for (const component of relative.split(path.sep)) {
    if (!component || component === "." || component === "..") {
      fail("parent-directory");
    }
    current = path.join(current, component);
    values.push(path.resolve(current));
  }
  return values;
}

export async function validateParentChain(parentPath, recorded = null) {
  const chainPaths = parentChainPaths(parentPath);
  const inspected = [];
  for (let index = 0; index < chainPaths.length; index += 1) {
    const record = await inspectRealDirectory(chainPaths[index]);
    if (
      recorded
      && (
        recorded.length !== chainPaths.length
        || !pathsEqual(recorded[index].expectedPath, record.expectedPath)
        || !pathsEqual(recorded[index].canonicalPath, record.canonicalPath)
        || !identitiesEqual(recorded[index].identity, record.identity)
      )
    ) {
      fail("parent-identity");
    }
    inspected.push(record);
  }
  return Object.freeze(inspected);
}

function validateFinalComponent(targetPath) {
  const name = path.basename(targetPath);
  if (
    !name
    || name === "."
    || name === ".."
    || CONTROL_CHARACTER_PATTERN.test(name)
    || SURROGATE_PATTERN.test(name)
    || name.includes(":")
    || name.includes("/")
    || name.includes("\\")
    || name.endsWith(".")
    || name.endsWith(" ")
    || WINDOWS_RESERVED_NAME_PATTERN.test(name)
  ) {
    fail("final-component");
  }
  return name;
}

function validateAbsoluteNormalizedPath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    fail("absolute-path");
  }
  if (
    process.platform === "win32"
    && (
      value.startsWith("\\\\")
      || value.startsWith("//")
      || value.startsWith("\\\\?\\")
      || value.startsWith("\\\\.\\")
    )
  ) {
    fail("path-namespace");
  }
  const normalized = path.normalize(value);
  const resolved = path.resolve(value);
  if (normalized !== value || !pathsEqual(resolved, value)) {
    fail("normalized-path");
  }
  const parentPath = path.dirname(resolved);
  if (pathsEqual(parentPath, resolved)) {
    fail("filesystem-root");
  }
  const finalBasename = validateFinalComponent(resolved);
  return Object.freeze({
    targetPath: resolved,
    parentPath,
    finalBasename,
  });
}

async function validateBoundary(repoRoot, targetArgument, { mustExist, requireTar }) {
  if (typeof repoRoot !== "string" || !path.isAbsolute(repoRoot)) {
    fail("repository-root");
  }
  const syntax = validateAbsoluteNormalizedPath(targetArgument);
  if (requireTar && !syntax.finalBasename.endsWith(".tar")) {
    fail("tar-extension");
  }
  if (
    pathsEqual(repoRoot, syntax.targetPath)
    || isInside(repoRoot, syntax.targetPath)
  ) {
    fail("repository-containment");
  }
  const parentChain = await validateParentChain(syntax.parentPath);
  const canonicalParent = parentChain.at(-1).canonicalPath;
  const canonicalTarget = path.join(canonicalParent, syntax.finalBasename);
  if (
    pathsEqual(repoRoot, canonicalTarget)
    || isInside(repoRoot, canonicalTarget)
  ) {
    fail("repository-containment");
  }

  const state = await pathState(syntax.targetPath);
  if (mustExist) {
    if (!state) {
      fail("archive-missing");
    }
  } else if (state) {
    fail("archive-exists");
  }
  return Object.freeze({
    ...syntax,
    canonicalTarget,
    canonicalParent,
    parentChain,
    initialState: state,
  });
}

export async function validateOutputArchiveBoundary(repoRoot, outputArgument) {
  return validateBoundary(repoRoot, outputArgument, {
    mustExist: false,
    requireTar: true,
  });
}

export async function validateExistingArchiveBoundary(repoRoot, archiveArgument) {
  const boundary = await validateBoundary(repoRoot, archiveArgument, {
    mustExist: true,
    requireTar: false,
  });
  const state = boundary.initialState;
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || state.size < 0n
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail("archive-file-state");
  }
  const resolved = await realpath(boundary.targetPath);
  if (
    !pathsEqual(resolved, boundary.targetPath)
    || !pathsEqual(path.dirname(resolved), boundary.canonicalParent)
  ) {
    fail("archive-reparse");
  }
  return Object.freeze({
    ...boundary,
    identity: identityFromState(state),
    byteLength: Number(state.size),
  });
}

export function noFollowFlag() {
  return process.platform !== "win32"
    && Number.isInteger(FS_CONSTANTS.O_NOFOLLOW)
    ? FS_CONSTANTS.O_NOFOLLOW
    : 0;
}

export function verifyRegularArchiveState(
  state,
  expectedIdentity,
  { expectedLength = null, parentIdentity = null } = {},
) {
  if (
    !state
    || state.isSymbolicLink()
    || !state.isFile()
    || state.nlink !== 1n
    || !identityMatches(expectedIdentity, state)
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
  ) {
    fail("archive-file-identity");
  }
  requireSameDevice(parentIdentity, state);
}

export async function verifyArchivePathIdentity(
  targetPath,
  expectedIdentity,
  options = {},
) {
  const state = await pathState(targetPath);
  verifyRegularArchiveState(state, expectedIdentity, options);
  const resolved = await realpath(targetPath);
  if (!pathsEqual(resolved, targetPath)) {
    fail("archive-reparse");
  }
  return state;
}

export function validateTemporaryBasename(finalBasename, temporaryBasename) {
  const prefix = "." + finalBasename + ".ieltmps-source-archive-tmp-";
  return (
    typeof temporaryBasename === "string"
    && temporaryBasename.startsWith(prefix)
    && temporaryBasename.length === prefix.length + 32
    && TEMPORARY_RANDOM_PATTERN.test(temporaryBasename.slice(prefix.length))
  );
}
