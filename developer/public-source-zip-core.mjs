import { TextDecoder } from "node:util";
import path from "node:path";

export const ZIP_ARTIFACT_ROLE = "public-source-convenience-download";
export const ZIP_FORMAT_PROFILE = "zip-canonical-v1";
export const ZIP_MEDIA_TYPE = "application/zip";
export const ZIP_ARCHIVE_ROOT = "ieltmps-source/";
export const ZIP_AUTHORITATIVE_CORRESPONDING_SOURCE = false;

export const ZIP_LIMITS = Object.freeze({
  minimumEntryCount: 1,
  maximumEntryCount: 0xfffe,
  zip16Sentinel: 0xffff,
  maximumZip32Value: 0xfffffffe,
  zip32Sentinel: 0xffffffff,
  maximumArchiveFilenameBytes: 1024,
  maximumPathComponentBytes: 255,
  maximumCanonicalEntryPlanBytes: 128 * 1024 * 1024,
  localHeaderFixedBytes: 30,
  centralDirectoryRecordFixedBytes: 46,
  endOfCentralDirectoryBytes: 22,
  payloadChunkBytes: 64 * 1024,
});

export const ZIP_FIELD_VALUES = Object.freeze({
  localFileHeaderSignature: 0x04034b50,
  centralDirectorySignature: 0x02014b50,
  endOfCentralDirectorySignature: 0x06054b50,
  versionNeeded: 0x0014,
  versionMadeBy: 0x0314,
  generalPurposeFlag: 0x0800,
  compressionMethod: 0,
  dosTime: 0x0000,
  dosDate: 0x0021,
  localExtraLength: 0,
  centralExtraLength: 0,
  fileCommentLength: 0,
  archiveCommentLength: 0,
  diskNumber: 0,
  centralDirectoryDisk: 0,
  diskStart: 0,
  internalAttributes: 0,
  externalAttributes100644: 0x81a40000,
  externalAttributes100755: 0x81ed0000,
});

export const ZIP_ENTRY_PLAN_KIND =
  "ieltmps-public-source-zip-entry-plan";
export const ZIP_ENTRY_PLAN_SCHEMA_VERSION = 1;

export const ZIP_ERROR_PHASES = Object.freeze([
  "CLI",
  "ENTRY_PLAN",
  "PATH_AUTHORITY",
  "SOURCE_FILE",
  "ZIP_LAYOUT",
  "ZIP_WRITE",
  "ZIP_PARSE",
  "ZIP_PROFILE",
  "ZIP_BINDING",
  "OUTPUT_PUBLICATION",
  "CLEANUP",
  "PRIVACY",
]);

const ERROR_PHASE_SET = new Set(ZIP_ERROR_PHASES);
const REASON_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const FULL_GIT_ID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CRC32_PATTERN = /^[0-9a-f]{8}$/u;
const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;
const UNPAIRED_SURROGATE_PATTERN =
  /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF])/u;
const DRIVE_PREFIX_PATTERN = /^[A-Za-z]:/u;
const URI_PREFIX_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const WINDOWS_INVALID_COMPONENT_PATTERN = /[<>"|?*]/u;
const WINDOWS_RESERVED_NAME_PATTERN =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\..*)?$/iu;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const UINT32_PROJECT_MAX = BigInt(ZIP_LIMITS.maximumZip32Value);

const TOP_LEVEL_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "artifactRole",
  "formatProfile",
  "sourceCommit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archiveRoot",
  "entryCount",
  "entries",
  "centralDirectoryOffset",
  "centralDirectoryByteLength",
  "archiveByteLength",
]);

const ENTRY_KEYS = Object.freeze([
  "sourcePath",
  "archivePath",
  "gitMode",
  "sha256",
  "crc32",
  "byteLength",
  "localHeaderOffset",
  "dataOffset",
  "centralDirectoryRecordOffset",
]);

export class PublicSourceZipError extends Error {
  constructor(phase, reason) {
    const safePhase = ERROR_PHASE_SET.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string" && REASON_PATTERN.test(reason)
      ? reason
      : "invalid-operation";
    super("public source ZIP operation failed");
    this.name = "PublicSourceZipError";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failPublicSourceZip(phase, reason) {
  throw new PublicSourceZipError(phase, reason);
}

export function validateWindowsHostPathAuthority(value) {
  if (typeof value !== "string") {
    failPublicSourceZip("PATH_AUTHORITY", "host-path-value");
  }
  const firstColon = value.indexOf(":");
  if (firstColon === -1) return value;
  const validDriveDesignator = firstColon === 1
    && /^[A-Za-z]$/u.test(value[0])
    && (value[2] === "\\" || value[2] === "/");
  if (
    !validDriveDesignator
    || value.indexOf(":", firstColon + 1) !== -1
  ) {
    failPublicSourceZip(
      "PATH_AUTHORITY",
      "windows-alternate-data-stream",
    );
  }
  return value;
}

export function canonicalizeHostFilesystemPath(value) {
  if (typeof value !== "string") {
    failPublicSourceZip("PATH_AUTHORITY", "host-path-value");
  }
  if (process.platform !== "win32") return value;

  validateWindowsHostPathAuthority(value);
  const canonicalPath = value.replaceAll("/", "\\");
  if (
    !/^[A-Za-z]:\\/u.test(canonicalPath)
    || canonicalPath.startsWith("\\\\")
    || !path.win32.isAbsolute(canonicalPath)
  ) {
    failPublicSourceZip("PATH_AUTHORITY", "windows-host-path-absolute");
  }
  if (path.win32.normalize(canonicalPath) !== canonicalPath) {
    failPublicSourceZip("PATH_AUTHORITY", "windows-host-path-normalized");
  }
  return canonicalPath;
}

export function validateHostFilesystemPath(value) {
  return canonicalizeHostFilesystemPath(value);
}

export function asPublicSourceZipError(error, phase, reason) {
  return error instanceof PublicSourceZipError
    ? error
    : new PublicSourceZipError(phase, reason);
}

export async function inPublicSourceZipPhase(phase, reason, operation) {
  try {
    return await operation();
  } catch (error) {
    throw asPublicSourceZipError(error, phase, reason);
  }
}

export function deepFreezeZip(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreezeZip(entry);
    Object.freeze(value);
  }
  return value;
}

function exactOrderedKeys(value, expected, phase, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failPublicSourceZip(phase, reason + "-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failPublicSourceZip(phase, reason + "-keys");
  }
}

function requireLowerHex(value, pattern, phase, reason) {
  if (typeof value !== "string" || !pattern.test(value)) {
    failPublicSourceZip(phase, reason);
  }
  return value;
}

function requireGitMode(value, phase = "ENTRY_PLAN", reason = "git-mode") {
  if (value !== "100644" && value !== "100755") {
    failPublicSourceZip(phase, reason);
  }
  return value;
}

function requireCount(value, phase, reason) {
  if (
    !Number.isSafeInteger(value)
    || value < ZIP_LIMITS.minimumEntryCount
    || value > ZIP_LIMITS.maximumEntryCount
    || value === ZIP_LIMITS.zip16Sentinel
  ) {
    failPublicSourceZip(phase, reason);
  }
  return value;
}

export function requireZip32Number(
  value,
  phase = "ZIP_LAYOUT",
  reason = "zip32-value",
) {
  if (
    !Number.isSafeInteger(value)
    || value < 0
    || value > ZIP_LIMITS.maximumZip32Value
    || value === ZIP_LIMITS.zip32Sentinel
  ) {
    failPublicSourceZip(phase, reason);
  }
  return value;
}

function numberFromLayout(value, reason, { allowZero = true } = {}) {
  if (
    typeof value !== "bigint"
    || value < 0n
    || (!allowZero && value === 0n)
    || value > UINT32_PROJECT_MAX
    || value === BigInt(ZIP_LIMITS.zip32Sentinel)
    || value > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    failPublicSourceZip("ZIP_LAYOUT", reason);
  }
  const converted = Number(value);
  if (!Number.isSafeInteger(converted) || BigInt(converted) !== value) {
    failPublicSourceZip("ZIP_LAYOUT", reason);
  }
  return converted;
}

function checkedLayoutAdd(left, right, reason) {
  if (
    typeof left !== "bigint"
    || typeof right !== "bigint"
    || left < 0n
    || right < 0n
    || left > UINT32_PROJECT_MAX
    || right > UINT32_PROJECT_MAX
  ) {
    failPublicSourceZip("ZIP_LAYOUT", reason);
  }
  const result = left + right;
  if (result > UINT32_PROJECT_MAX) {
    failPublicSourceZip("ZIP_LAYOUT", reason);
  }
  return result;
}

export function compareUnsignedUtf8(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    failPublicSourceZip("PATH_AUTHORITY", "utf8-comparison-value");
  }
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function crc32Init() {
  return 0xffffffff;
}

export function crc32Update(state, bytes) {
  if (!Number.isInteger(state) || state < 0 || state > 0xffffffff) {
    failPublicSourceZip("ZIP_BINDING", "crc32-state");
  }
  if (!(bytes instanceof Uint8Array)) {
    failPublicSourceZip("ZIP_BINDING", "crc32-bytes");
  }
  let current = state >>> 0;
  for (const byte of bytes) {
    current ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      current = (current >>> 1) ^ ((current & 1) ? 0xedb88320 : 0);
    }
  }
  return current >>> 0;
}

export function crc32Finalize(state) {
  if (!Number.isInteger(state) || state < 0 || state > 0xffffffff) {
    failPublicSourceZip("ZIP_BINDING", "crc32-state");
  }
  return (state ^ 0xffffffff) >>> 0;
}

export function crc32Bytes(bytes) {
  return crc32Finalize(crc32Update(crc32Init(), bytes));
}

function hasUnsafeNamespacePrefix(value) {
  const folded = value.toLowerCase();
  return folded.startsWith("//")
    || folded.startsWith("\\\\")
    || folded.startsWith("//?/")
    || folded.startsWith("//./")
    || folded.startsWith("\\\\?\\")
    || folded.startsWith("\\\\.\\");
}

export function validateZipSourcePath(value) {
  if (typeof value !== "string" || value.length === 0) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-empty");
  }
  if (value.normalize("NFC") !== value) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-not-nfc");
  }
  if (UNPAIRED_SURROGATE_PATTERN.test(value)) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-surrogate");
  }
  if (ASCII_CONTROL_PATTERN.test(value)) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-control-character");
  }
  if (value.includes("\0")) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-nul");
  }
  if (value.includes(":")) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-colon");
  }
  if (value.includes("\\")) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-backslash");
  }
  if (
    value.startsWith("/")
    || value.endsWith("/")
    || value.includes("//")
    || DRIVE_PREFIX_PATTERN.test(value)
    || URI_PREFIX_PATTERN.test(value)
    || hasUnsafeNamespacePrefix(value)
  ) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-not-portable-relative");
  }

  const components = value.split("/");
  if (components.some((component) => !component || component === "." || component === "..")) {
    failPublicSourceZip("PATH_AUTHORITY", "source-path-component");
  }
  for (const component of components) {
    if (WINDOWS_INVALID_COMPONENT_PATTERN.test(component)) {
      failPublicSourceZip("PATH_AUTHORITY", "source-path-invalid-character");
    }
    if (component.endsWith(".") || component.endsWith(" ")) {
      failPublicSourceZip("PATH_AUTHORITY", "source-path-trailing-dot-or-space");
    }
    if (WINDOWS_RESERVED_NAME_PATTERN.test(component)) {
      failPublicSourceZip("PATH_AUTHORITY", "source-path-reserved-name");
    }
    if (Buffer.byteLength(component, "utf8") > ZIP_LIMITS.maximumPathComponentBytes) {
      failPublicSourceZip("PATH_AUTHORITY", "source-path-component-too-long");
    }
  }

  const archivePath = ZIP_ARCHIVE_ROOT + value;
  if (Buffer.byteLength(archivePath, "utf8") > ZIP_LIMITS.maximumArchiveFilenameBytes) {
    failPublicSourceZip("PATH_AUTHORITY", "archive-path-too-long");
  }
  return value;
}

export function deriveZipArchivePath(sourcePath) {
  return ZIP_ARCHIVE_ROOT + validateZipSourcePath(sourcePath);
}

function collisionTransforms(value) {
  return Object.freeze([
    Buffer.from(value, "utf8").toString("hex"),
    value.toLowerCase(),
    value.normalize("NFC"),
    value.normalize("NFD"),
    value.toLowerCase().normalize("NFC"),
    value.toLowerCase().normalize("NFD"),
  ]);
}

function validatePathSet(entries) {
  const registries = Array.from({ length: 6 }, () => new Set());
  const transformedPaths = Array.from({ length: 6 }, () => []);
  for (const entry of entries) {
    const identities = collisionTransforms(entry.archivePath);
    identities.forEach((identity, index) => {
      if (registries[index].has(identity)) {
        failPublicSourceZip("PATH_AUTHORITY", "archive-path-collision");
      }
      registries[index].add(identity);
      transformedPaths[index].push(identity);
    });
  }

  for (let transform = 1; transform < transformedPaths.length; transform += 1) {
    const files = registries[transform];
    for (const value of transformedPaths[transform]) {
      let separator = value.indexOf("/");
      while (separator >= 0) {
        const prefix = value.slice(0, separator);
        if (files.has(prefix)) {
          failPublicSourceZip("PATH_AUTHORITY", "file-parent-collision");
        }
        separator = value.indexOf("/", separator + 1);
      }
    }
  }
}

function normalizeLayoutEntry(entry, index) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    failPublicSourceZip("ZIP_LAYOUT", "entry-object");
  }
  const sourcePath = validateZipSourcePath(entry.sourcePath);
  const archivePath = deriveZipArchivePath(sourcePath);
  if (
    Object.hasOwn(entry, "archivePath")
    && entry.archivePath !== archivePath
  ) {
    failPublicSourceZip("PATH_AUTHORITY", "archive-path-derivation");
  }
  const byteLength = requireZip32Number(
    entry.byteLength,
    "ZIP_LAYOUT",
    "entry-byte-length",
  );
  return Object.freeze({
    index,
    sourcePath,
    archivePath,
    gitMode: requireGitMode(entry.gitMode, "ZIP_LAYOUT", "entry-git-mode"),
    byteLength,
  });
}

export function computeCanonicalZipLayout(value) {
  const entries = Array.isArray(value) ? value : value?.entries;
  if (!Array.isArray(entries)) {
    failPublicSourceZip("ZIP_LAYOUT", "entries-array");
  }
  requireCount(entries.length, "ZIP_LAYOUT", "entry-count");
  const normalized = entries.map(normalizeLayoutEntry);
  validatePathSet(normalized);
  for (let index = 1; index < normalized.length; index += 1) {
    if (
      compareUnsignedUtf8(
        normalized[index - 1].archivePath,
        normalized[index].archivePath,
      ) >= 0
    ) {
      failPublicSourceZip("ZIP_LAYOUT", "entry-order");
    }
  }

  let localCursor = 0n;
  let totalStoredBytes = 0n;
  const localRecords = [];
  for (const entry of normalized) {
    const filenameByteLength = Buffer.byteLength(entry.archivePath, "utf8");
    const filenameLength = BigInt(filenameByteLength);
    const localHeaderByteLength = checkedLayoutAdd(
      BigInt(ZIP_LIMITS.localHeaderFixedBytes),
      filenameLength,
      "local-header-length",
    );
    const localHeaderOffset = localCursor;
    const dataOffset = checkedLayoutAdd(
      localHeaderOffset,
      localHeaderByteLength,
      "data-offset",
    );
    const storedPayloadEnd = checkedLayoutAdd(
      dataOffset,
      BigInt(entry.byteLength),
      "stored-payload-end",
    );
    totalStoredBytes = checkedLayoutAdd(
      totalStoredBytes,
      BigInt(entry.byteLength),
      "total-stored-bytes",
    );
    localRecords.push({
      ...entry,
      filenameByteLength,
      localHeaderByteLength: numberFromLayout(
        localHeaderByteLength,
        "local-header-length",
      ),
      localHeaderOffset: numberFromLayout(
        localHeaderOffset,
        "local-header-offset",
      ),
      dataOffset: numberFromLayout(dataOffset, "data-offset"),
      storedPayloadEnd: numberFromLayout(
        storedPayloadEnd,
        "stored-payload-end",
      ),
    });
    localCursor = storedPayloadEnd;
  }

  const centralDirectoryOffsetBig = localCursor;
  let centralCursor = centralDirectoryOffsetBig;
  const completeEntries = [];
  for (const entry of localRecords) {
    const recordLength = checkedLayoutAdd(
      BigInt(ZIP_LIMITS.centralDirectoryRecordFixedBytes),
      BigInt(entry.filenameByteLength),
      "central-record-length",
    );
    const centralDirectoryRecordOffset = centralCursor;
    centralCursor = checkedLayoutAdd(
      centralCursor,
      recordLength,
      "central-directory-end",
    );
    completeEntries.push(Object.freeze({
      ...entry,
      centralDirectoryRecordByteLength: numberFromLayout(
        recordLength,
        "central-record-length",
      ),
      centralDirectoryRecordOffset: numberFromLayout(
        centralDirectoryRecordOffset,
        "central-record-offset",
      ),
    }));
  }

  const centralDirectoryByteLengthBig =
    centralCursor - centralDirectoryOffsetBig;
  const eocdOffsetBig = centralCursor;
  const archiveByteLengthBig = checkedLayoutAdd(
    eocdOffsetBig,
    BigInt(ZIP_LIMITS.endOfCentralDirectoryBytes),
    "archive-byte-length",
  );

  return deepFreezeZip({
    entries: completeEntries,
    totalStoredBytes: numberFromLayout(
      totalStoredBytes,
      "total-stored-bytes",
    ),
    centralDirectoryOffset: numberFromLayout(
      centralDirectoryOffsetBig,
      "central-directory-offset",
    ),
    centralDirectoryByteLength: numberFromLayout(
      centralDirectoryByteLengthBig,
      "central-directory-byte-length",
    ),
    eocdOffset: numberFromLayout(eocdOffsetBig, "eocd-offset"),
    archiveByteLength: numberFromLayout(
      archiveByteLengthBig,
      "archive-byte-length",
      { allowZero: false },
    ),
  });
}

function validateEntryMetadata(entry, index) {
  exactOrderedKeys(entry, ENTRY_KEYS, "ENTRY_PLAN", "entry");
  const sourcePath = validateZipSourcePath(entry.sourcePath);
  const archivePath = deriveZipArchivePath(sourcePath);
  if (entry.archivePath !== archivePath) {
    failPublicSourceZip("ENTRY_PLAN", "archive-path-mismatch");
  }
  return Object.freeze({
    sourcePath,
    archivePath,
    gitMode: requireGitMode(entry.gitMode),
    sha256: requireLowerHex(
      entry.sha256,
      SHA256_PATTERN,
      "ENTRY_PLAN",
      "entry-sha256",
    ),
    crc32: requireLowerHex(
      entry.crc32,
      CRC32_PATTERN,
      "ENTRY_PLAN",
      "entry-crc32",
    ),
    byteLength: requireZip32Number(
      entry.byteLength,
      "ENTRY_PLAN",
      "entry-byte-length",
    ),
    localHeaderOffset: requireZip32Number(
      entry.localHeaderOffset,
      "ENTRY_PLAN",
      "local-header-offset",
    ),
    dataOffset: requireZip32Number(
      entry.dataOffset,
      "ENTRY_PLAN",
      "data-offset",
    ),
    centralDirectoryRecordOffset: requireZip32Number(
      entry.centralDirectoryRecordOffset,
      "ENTRY_PLAN",
      "central-record-offset",
    ),
    index,
  });
}

export function validateCanonicalZipEntryPlan(value) {
  exactOrderedKeys(value, TOP_LEVEL_KEYS, "ENTRY_PLAN", "entry-plan");
  if (value.documentKind !== ZIP_ENTRY_PLAN_KIND) {
    failPublicSourceZip("ENTRY_PLAN", "document-kind");
  }
  if (value.schemaVersion !== ZIP_ENTRY_PLAN_SCHEMA_VERSION) {
    failPublicSourceZip("ENTRY_PLAN", "schema-version");
  }
  if (value.artifactRole !== ZIP_ARTIFACT_ROLE) {
    failPublicSourceZip("ENTRY_PLAN", "artifact-role");
  }
  if (value.formatProfile !== ZIP_FORMAT_PROFILE) {
    failPublicSourceZip("ENTRY_PLAN", "format-profile");
  }
  const sourceCommit = requireLowerHex(
    value.sourceCommit,
    FULL_GIT_ID_PATTERN,
    "ENTRY_PLAN",
    "source-commit",
  );
  const manifestSha256 = requireLowerHex(
    value.manifestSha256,
    SHA256_PATTERN,
    "ENTRY_PLAN",
    "manifest-sha256",
  );
  const membershipReportSha256 = requireLowerHex(
    value.membershipReportSha256,
    SHA256_PATTERN,
    "ENTRY_PLAN",
    "membership-report-sha256",
  );
  if (value.archiveRoot !== ZIP_ARCHIVE_ROOT) {
    failPublicSourceZip("ENTRY_PLAN", "archive-root");
  }
  if (!Array.isArray(value.entries)) {
    failPublicSourceZip("ENTRY_PLAN", "entries-array");
  }
  const entryCount = requireCount(
    value.entryCount,
    "ENTRY_PLAN",
    "entry-count",
  );
  const membershipCount = requireCount(
    value.membershipCount,
    "ENTRY_PLAN",
    "membership-count",
  );
  if (
    entryCount !== value.entries.length
    || membershipCount !== entryCount
  ) {
    failPublicSourceZip("ENTRY_PLAN", "entry-count-mismatch");
  }

  const entriesWithIndex = value.entries.map(validateEntryMetadata);
  const layout = computeCanonicalZipLayout(entriesWithIndex);
  const entries = entriesWithIndex.map((entry, index) => {
    const expected = layout.entries[index];
    if (
      entry.localHeaderOffset !== expected.localHeaderOffset
      || entry.dataOffset !== expected.dataOffset
      || entry.centralDirectoryRecordOffset
        !== expected.centralDirectoryRecordOffset
    ) {
      failPublicSourceZip("ENTRY_PLAN", "entry-layout-mismatch");
    }
    return Object.freeze({
      sourcePath: entry.sourcePath,
      archivePath: entry.archivePath,
      gitMode: entry.gitMode,
      sha256: entry.sha256,
      crc32: entry.crc32,
      byteLength: entry.byteLength,
      localHeaderOffset: entry.localHeaderOffset,
      dataOffset: entry.dataOffset,
      centralDirectoryRecordOffset: entry.centralDirectoryRecordOffset,
    });
  });

  const centralDirectoryOffset = requireZip32Number(
    value.centralDirectoryOffset,
    "ENTRY_PLAN",
    "central-directory-offset",
  );
  const centralDirectoryByteLength = requireZip32Number(
    value.centralDirectoryByteLength,
    "ENTRY_PLAN",
    "central-directory-byte-length",
  );
  const archiveByteLength = requireZip32Number(
    value.archiveByteLength,
    "ENTRY_PLAN",
    "archive-byte-length",
  );
  if (
    archiveByteLength === 0
    || centralDirectoryOffset !== layout.centralDirectoryOffset
    || centralDirectoryByteLength !== layout.centralDirectoryByteLength
    || archiveByteLength !== layout.archiveByteLength
  ) {
    failPublicSourceZip("ENTRY_PLAN", "document-layout-mismatch");
  }

  return deepFreezeZip({
    documentKind: ZIP_ENTRY_PLAN_KIND,
    schemaVersion: ZIP_ENTRY_PLAN_SCHEMA_VERSION,
    artifactRole: ZIP_ARTIFACT_ROLE,
    formatProfile: ZIP_FORMAT_PROFILE,
    sourceCommit,
    manifestSha256,
    membershipReportSha256,
    membershipCount,
    archiveRoot: ZIP_ARCHIVE_ROOT,
    entryCount,
    entries,
    centralDirectoryOffset,
    centralDirectoryByteLength,
    archiveByteLength,
  });
}

export function createCanonicalZipEntryPlan({
  sourceCommit,
  manifestSha256,
  membershipReportSha256,
  membershipCount,
  entries,
} = {}) {
  requireLowerHex(
    sourceCommit,
    FULL_GIT_ID_PATTERN,
    "ENTRY_PLAN",
    "source-commit",
  );
  requireLowerHex(
    manifestSha256,
    SHA256_PATTERN,
    "ENTRY_PLAN",
    "manifest-sha256",
  );
  requireLowerHex(
    membershipReportSha256,
    SHA256_PATTERN,
    "ENTRY_PLAN",
    "membership-report-sha256",
  );
  if (!Array.isArray(entries)) {
    failPublicSourceZip("ENTRY_PLAN", "entries-array");
  }
  requireCount(entries.length, "ENTRY_PLAN", "entry-count");
  if (membershipCount !== undefined && membershipCount !== entries.length) {
    failPublicSourceZip("ENTRY_PLAN", "membership-count-mismatch");
  }
  const prepared = entries.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      failPublicSourceZip("ENTRY_PLAN", "entry-object");
    }
    const sourcePathValue = validateZipSourcePath(entry.sourcePath);
    return Object.freeze({
      sourcePath: sourcePathValue,
      archivePath: deriveZipArchivePath(sourcePathValue),
      gitMode: requireGitMode(entry.gitMode),
      sha256: requireLowerHex(
        entry.sha256,
        SHA256_PATTERN,
        "ENTRY_PLAN",
        "entry-sha256",
      ),
      crc32: requireLowerHex(
        entry.crc32,
        CRC32_PATTERN,
        "ENTRY_PLAN",
        "entry-crc32",
      ),
      byteLength: requireZip32Number(
        entry.byteLength,
        "ENTRY_PLAN",
        "entry-byte-length",
      ),
    });
  }).sort((left, right) => (
    compareUnsignedUtf8(left.archivePath, right.archivePath)
  ));
  const layout = computeCanonicalZipLayout(prepared);
  const canonicalEntries = prepared.map((entry, index) => Object.freeze({
    sourcePath: entry.sourcePath,
    archivePath: entry.archivePath,
    gitMode: entry.gitMode,
    sha256: entry.sha256,
    crc32: entry.crc32,
    byteLength: entry.byteLength,
    localHeaderOffset: layout.entries[index].localHeaderOffset,
    dataOffset: layout.entries[index].dataOffset,
    centralDirectoryRecordOffset:
      layout.entries[index].centralDirectoryRecordOffset,
  }));
  return validateCanonicalZipEntryPlan({
    documentKind: ZIP_ENTRY_PLAN_KIND,
    schemaVersion: ZIP_ENTRY_PLAN_SCHEMA_VERSION,
    artifactRole: ZIP_ARTIFACT_ROLE,
    formatProfile: ZIP_FORMAT_PROFILE,
    sourceCommit,
    manifestSha256,
    membershipReportSha256,
    membershipCount: entries.length,
    archiveRoot: ZIP_ARCHIVE_ROOT,
    entryCount: entries.length,
    entries: canonicalEntries,
    centralDirectoryOffset: layout.centralDirectoryOffset,
    centralDirectoryByteLength: layout.centralDirectoryByteLength,
    archiveByteLength: layout.archiveByteLength,
  });
}

class DuplicateAwareJsonParser {
  constructor(text) {
    this.text = text;
    this.index = 0;
  }

  fail(reason) {
    failPublicSourceZip("ENTRY_PLAN", reason);
  }

  peek() {
    return this.text[this.index];
  }

  consume(value, reason) {
    if (!this.text.startsWith(value, this.index)) this.fail(reason);
    this.index += value.length;
  }

  parseString() {
    if (this.peek() !== '"') this.fail("json-string-open");
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      const character = this.text[this.index];
      if (!escaped && character === '"') {
        this.index += 1;
        const token = this.text.slice(start, this.index);
        let value;
        try {
          value = JSON.parse(token);
        } catch {
          this.fail("json-string-encoding");
        }
        if (UNPAIRED_SURROGATE_PATTERN.test(value)) {
          this.fail("json-string-surrogate");
        }
        return value;
      }
      if (!escaped && code < 0x20) this.fail("json-string-control");
      if (!escaped && character === "\\") {
        escaped = true;
        this.index += 1;
        continue;
      }
      escaped = false;
      this.index += 1;
    }
    this.fail("json-string-unterminated");
  }

  parseNumber() {
    const remaining = this.text.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(remaining);
    if (!match) this.fail("json-number-encoding");
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.fail("json-number-range");
    return value;
  }

  parseArray() {
    this.consume("[", "json-array-open");
    const values = [];
    if (this.peek() === "]") {
      this.index += 1;
      return values;
    }
    while (true) {
      values.push(this.parseValue());
      if (this.peek() === "]") {
        this.index += 1;
        return values;
      }
      this.consume(",", "json-array-comma");
    }
  }

  parseObject() {
    this.consume("{", "json-object-open");
    const result = Object.create(null);
    const seen = new Set();
    if (this.peek() === "}") {
      this.index += 1;
      return result;
    }
    while (true) {
      const key = this.parseString();
      if (seen.has(key)) this.fail("duplicate-json-key");
      seen.add(key);
      this.consume(":", "json-object-colon");
      Object.defineProperty(result, key, {
        value: this.parseValue(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      if (this.peek() === "}") {
        this.index += 1;
        return result;
      }
      this.consume(",", "json-object-comma");
    }
  }

  parseValue() {
    const character = this.peek();
    if (/\s/u.test(character ?? "")) this.fail("json-whitespace");
    if (character === "{") return this.parseObject();
    if (character === "[") return this.parseArray();
    if (character === '"') return this.parseString();
    if (character === "t") {
      this.consume("true", "json-boolean");
      return true;
    }
    if (character === "f") {
      this.consume("false", "json-boolean");
      return false;
    }
    if (character === "n") {
      this.consume("null", "json-null");
      return null;
    }
    if (character === "-" || /[0-9]/u.test(character ?? "")) {
      return this.parseNumber();
    }
    this.fail("json-value");
  }

  parse() {
    const value = this.parseValue();
    if (this.index !== this.text.length) this.fail("json-trailing-data");
    return value;
  }
}

export function encodeCanonicalZipEntryPlan(value) {
  const validated = validateCanonicalZipEntryPlan(value);
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(validated) + "\n", "utf8");
  } catch {
    failPublicSourceZip("ENTRY_PLAN", "canonical-encoding");
  }
  if (
    bytes.length > ZIP_LIMITS.maximumCanonicalEntryPlanBytes
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
  ) {
    failPublicSourceZip("ENTRY_PLAN", "canonical-encoding");
  }
  return bytes;
}

export function parseCanonicalZipEntryPlanBytes(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    failPublicSourceZip("ENTRY_PLAN", "document-bytes");
  }
  if (
    bytes.length === 0
    || bytes.length > ZIP_LIMITS.maximumCanonicalEntryPlanBytes
  ) {
    failPublicSourceZip("ENTRY_PLAN", "document-size");
  }
  if (
    bytes.length >= 3
    && bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
  ) {
    failPublicSourceZip("ENTRY_PLAN", "utf8-bom");
  }
  if (
    bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
  ) {
    failPublicSourceZip("ENTRY_PLAN", "final-lf");
  }
  let text;
  try {
    text = UTF8_DECODER.decode(bytes.subarray(0, -1));
  } catch {
    failPublicSourceZip("ENTRY_PLAN", "utf8-encoding");
  }
  const parsed = new DuplicateAwareJsonParser(text).parse();
  const validated = validateCanonicalZipEntryPlan(parsed);
  const canonical = encodeCanonicalZipEntryPlan(validated);
  if (!canonical.equals(bytes)) {
    failPublicSourceZip("ENTRY_PLAN", "noncanonical-bytes");
  }
  return validated;
}

function crc32Number(value, phase = "ZIP_LAYOUT", reason = "crc32") {
  requireLowerHex(value, CRC32_PATTERN, phase, reason);
  return Number.parseInt(value, 16) >>> 0;
}

function filenameBytesForEntry(entry, phase = "ZIP_LAYOUT") {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    failPublicSourceZip(phase, "entry-object");
  }
  const sourcePath = validateZipSourcePath(entry.sourcePath);
  const archivePath = deriveZipArchivePath(sourcePath);
  if (entry.archivePath !== archivePath) {
    failPublicSourceZip(phase, "archive-path-mismatch");
  }
  const bytes = Buffer.from(archivePath, "utf8");
  if (
    bytes.length === 0
    || bytes.length > ZIP_LIMITS.maximumArchiveFilenameBytes
    || bytes.length >= ZIP_LIMITS.zip16Sentinel
  ) {
    failPublicSourceZip(phase, "filename-length");
  }
  return bytes;
}

function externalAttributes(gitMode, phase = "ZIP_LAYOUT") {
  requireGitMode(gitMode, phase, "git-mode");
  return gitMode === "100755"
    ? ZIP_FIELD_VALUES.externalAttributes100755
    : ZIP_FIELD_VALUES.externalAttributes100644;
}

export function encodeLocalFileHeader(entry) {
  const filename = filenameBytesForEntry(entry);
  const byteLength = requireZip32Number(
    entry.byteLength,
    "ZIP_LAYOUT",
    "entry-byte-length",
  );
  const header = Buffer.alloc(ZIP_LIMITS.localHeaderFixedBytes + filename.length);
  header.writeUInt32LE(ZIP_FIELD_VALUES.localFileHeaderSignature, 0);
  header.writeUInt16LE(ZIP_FIELD_VALUES.versionNeeded, 4);
  header.writeUInt16LE(ZIP_FIELD_VALUES.generalPurposeFlag, 6);
  header.writeUInt16LE(ZIP_FIELD_VALUES.compressionMethod, 8);
  header.writeUInt16LE(ZIP_FIELD_VALUES.dosTime, 10);
  header.writeUInt16LE(ZIP_FIELD_VALUES.dosDate, 12);
  header.writeUInt32LE(crc32Number(entry.crc32), 14);
  header.writeUInt32LE(byteLength, 18);
  header.writeUInt32LE(byteLength, 22);
  header.writeUInt16LE(filename.length, 26);
  header.writeUInt16LE(ZIP_FIELD_VALUES.localExtraLength, 28);
  filename.copy(header, ZIP_LIMITS.localHeaderFixedBytes);
  return header;
}

export function encodeCentralDirectoryRecord(entry) {
  const filename = filenameBytesForEntry(entry);
  const byteLength = requireZip32Number(
    entry.byteLength,
    "ZIP_LAYOUT",
    "entry-byte-length",
  );
  const localHeaderOffset = requireZip32Number(
    entry.localHeaderOffset,
    "ZIP_LAYOUT",
    "local-header-offset",
  );
  const record = Buffer.alloc(
    ZIP_LIMITS.centralDirectoryRecordFixedBytes + filename.length,
  );
  record.writeUInt32LE(ZIP_FIELD_VALUES.centralDirectorySignature, 0);
  record.writeUInt16LE(ZIP_FIELD_VALUES.versionMadeBy, 4);
  record.writeUInt16LE(ZIP_FIELD_VALUES.versionNeeded, 6);
  record.writeUInt16LE(ZIP_FIELD_VALUES.generalPurposeFlag, 8);
  record.writeUInt16LE(ZIP_FIELD_VALUES.compressionMethod, 10);
  record.writeUInt16LE(ZIP_FIELD_VALUES.dosTime, 12);
  record.writeUInt16LE(ZIP_FIELD_VALUES.dosDate, 14);
  record.writeUInt32LE(crc32Number(entry.crc32), 16);
  record.writeUInt32LE(byteLength, 20);
  record.writeUInt32LE(byteLength, 24);
  record.writeUInt16LE(filename.length, 28);
  record.writeUInt16LE(ZIP_FIELD_VALUES.centralExtraLength, 30);
  record.writeUInt16LE(ZIP_FIELD_VALUES.fileCommentLength, 32);
  record.writeUInt16LE(ZIP_FIELD_VALUES.diskStart, 34);
  record.writeUInt16LE(ZIP_FIELD_VALUES.internalAttributes, 36);
  record.writeUInt32LE(externalAttributes(entry.gitMode), 38);
  record.writeUInt32LE(localHeaderOffset, 42);
  filename.copy(record, ZIP_LIMITS.centralDirectoryRecordFixedBytes);
  return record;
}

export function encodeEndOfCentralDirectory(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failPublicSourceZip("ZIP_LAYOUT", "eocd-object");
  }
  const entryCount = requireCount(
    value.entryCount,
    "ZIP_LAYOUT",
    "entry-count",
  );
  const centralDirectoryByteLength = requireZip32Number(
    value.centralDirectoryByteLength,
    "ZIP_LAYOUT",
    "central-directory-byte-length",
  );
  const centralDirectoryOffset = requireZip32Number(
    value.centralDirectoryOffset,
    "ZIP_LAYOUT",
    "central-directory-offset",
  );
  const record = Buffer.alloc(ZIP_LIMITS.endOfCentralDirectoryBytes);
  record.writeUInt32LE(ZIP_FIELD_VALUES.endOfCentralDirectorySignature, 0);
  record.writeUInt16LE(ZIP_FIELD_VALUES.diskNumber, 4);
  record.writeUInt16LE(ZIP_FIELD_VALUES.centralDirectoryDisk, 6);
  record.writeUInt16LE(entryCount, 8);
  record.writeUInt16LE(entryCount, 10);
  record.writeUInt32LE(centralDirectoryByteLength, 12);
  record.writeUInt32LE(centralDirectoryOffset, 16);
  record.writeUInt16LE(ZIP_FIELD_VALUES.archiveCommentLength, 20);
  return record;
}
