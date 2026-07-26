import { createHash, randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { constants as FS_CONSTANTS, realpathSync, writeSync } from "node:fs";
import {
  access,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  identityFromState,
  identitiesEqual,
  isInside,
  noFollowFlag,
  pathState,
  pathsEqual,
  validateParentChain,
} from "./public-source-archive-core.mjs";
import { verifyPublicSourceArchive } from "./verify-public-source-archive.mjs";
import {
  buildPublicSourceReceipt,
  cleanupVerifiedToolDirectory,
  CRITICAL_TOOL_PATHS as RECEIPT_CRITICAL_TOOL_PATHS,
  deriveCriticalToolIdentities,
  encodeCanonicalReceipt,
  hashArtifactInputs,
  materializeVerifiedToolDirectory,
  RECEIPT_KIND,
  RECEIPT_OUTPUT_SUFFIX,
  requireCriticalFilesEqual,
  SCHEMA_VERSION as RECEIPT_SCHEMA_VERSION,
  verifyToolingCommitSignature,
} from "./public-source-receipt-core.mjs";
import { preparePublicSourceReceipt } from "./prepare-public-source-receipt.mjs";
import {
  runVerifiedReceiptWorker,
  verifyPublicSourceReceipt,
} from "./verify-public-source-receipt.mjs";
import {
  REPRODUCIBILITY_EVIDENCE_KIND,
  REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
  SCHEMA_VERSION,
  encodeCanonicalReproducibilityEvidence,
  encodeCanonicalSemanticReport,
  parseCanonicalMatrixPolicy,
  parseCanonicalOpaqueJsonBytes,
  readStableCanonicalDocument,
  readStableFile,
  sha256Bytes,
} from "./reproducibility-evidence-core.mjs";

export const ADAPTER_MODE = "public-source-receipt-reproducibility";
export const ARTIFACT_ROLE = "public-source-receipt";
export const FORMAT_PROFILE = "ieltmps-public-source-receipt-v1";
export const INPUT_SET_KIND = "ieltmps-public-source-receipt-input-set";
export const CRITICAL_TOOL_SET_KIND =
  "ieltmps-reproducibility-critical-tool-set";
export const CRITICAL_TOOL_SET_ID =
  "public-source-receipt-reproducibility-v1";
export const RUNTIME_IDENTITY_KIND = "ieltmps-node-runtime-identity";
export const GIT_IDENTITY_KIND = "ieltmps-git-runtime-identity";
export const PLATFORM_PROBE_KIND = "ieltmps-platform-probe";
export const COMPLETION_MARKER =
  "ieltmps-public-source-receipt-reproducibility-complete-v1\n";

export const CRITICAL_TOOL_PATHS = Object.freeze([
  "developer/verify-public-source-membership.mjs",
  "developer/public-source-archive-core.mjs",
  "developer/verify-public-source-archive.mjs",
  "developer/public-source-receipt-core.mjs",
  "developer/prepare-public-source-receipt.mjs",
  "developer/verify-public-source-receipt.mjs",
  "developer/reproducibility-evidence-core.mjs",
  "developer/verify-reproducibility-evidence.mjs",
  "developer/public-source-receipt-reproducibility-core.mjs",
  "developer/prepare-public-source-receipt-reproducibility.mjs",
  "developer/run-public-source-receipt-boundary-vectors.mjs",
]);

export const ADAPTER_PHASES = Object.freeze([
  "CLI",
  "POLICY_BINDING",
  "SOURCE_BINDING",
  "TOOL_SET",
  "RUNTIME_IDENTITY",
  "GIT_IDENTITY",
  "PLATFORM_PROBE",
  "ARCHIVE_VERIFICATION",
  "RECEIPT_CONSTRUCTION",
  "RECEIPT_VERIFICATION",
  "BOUNDARY_VECTOR",
  "SAME_PROCESS",
  "SAME_HOST",
  "SEMANTIC_REPORT",
  "EVIDENCE",
  "R1_10A_VERIFICATION",
  "OUTPUT_PUBLICATION",
  "CLEANUP",
  "PRIVACY",
]);

const ADAPTER_PHASE_SET = new Set(ADAPTER_PHASES);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const IDENTIFIER_PATTERN =
  /^[a-z0-9](?:[a-z0-9._+-]{0,126}[a-z0-9])?$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const WORKER_PROTOCOL = "ieltmps-public-source-receipt-worker-v1";
const WORKER_LEASE_PROTOCOL =
  "ieltmps-public-source-receipt-worker-lease-v1";
const WORKER_CLAIM_PROTOCOL =
  "ieltmps-public-source-receipt-worker-claim-v1";
const LEGACY_WORKER_TOKEN_ENV = "IELTMPS_REPRODUCIBILITY_WORKER_TOKEN";
const WORKER_LEASE_BASENAME = ".worker-lease.json";
const WORKER_CLAIM_BASENAME = ".worker-claim.json";
const WORKER_RECEIPT_BASENAME = `receipt${RECEIPT_OUTPUT_SUFFIX}`;
const WORKER_CAPSULE_KIND = "ieltmps-public-source-receipt-worker-capsule";
const WORKER_CAPSULE_BASENAME = "worker-modules.capsule.json";
const WORKER_CAPSULE_DIRECTORY = "worker-module-capsule";
const WORKER_ENTRY_MODULE =
  "developer/public-source-receipt-reproducibility-core.mjs";
const MAX_WORKER_REQUEST_BYTES = 1024 * 1024;
const MAX_WORKER_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_WORKER_LEASE_BYTES = 64 * 1024;
const MAX_WORKER_CAPSULE_BYTES = 16 * 1024 * 1024;
const MAX_WORKER_STDIO_BYTES = 64 * 1024;
const FILE_CHUNK_SIZE = 64 * 1024;
const MAX_GIT_BUFFER = 128 * 1024 * 1024;
const WORKER_BUILTIN_IMPORTS = Object.freeze([
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:module",
  "node:os",
  "node:path",
  "node:url",
  "node:util",
]);
const WORKER_BUILTIN_IMPORT_SET = new Set(WORKER_BUILTIN_IMPORTS);

// This source is passed to Node directly with --eval. The child never opens a
// repository entry point. It validates one coordinator-created capsule before
// registering synchronous in-memory module hooks. The split spelling below
// keeps the parent module's static-import validator from mistaking bootstrap
// source text for a production dynamic import.
const WORKER_BOOTSTRAP_SOURCE = String.raw`
import {createHash} from "node:crypto";
import {constants as C,writeSync} from "node:fs";
import {lstat,open,realpath} from "node:fs/promises";
import {registerHooks} from "node:module";
import path from "node:path";
import {pathToFileURL} from "node:url";
const FAIL_LINE=Buffer.from("ERROR TOOL_SET: worker-loaded-bytes-mismatch\n","ascii");
const fail=()=>{try{writeSync(2,FAIL_LINE);}catch{}try{if(process.connected)process.disconnect();}catch{}process.exit(1);};
const hex=(bytes)=>createHash("sha256").update(bytes).digest("hex");
const sameIdentity=(state,device,inode)=>String(state.dev)===device&&String(state.ino)===inode;
const samePath=(left,right)=>process.platform==="win32"?left.toLowerCase()===right.toLowerCase():left===right;
const exactKeys=(value,keys)=>value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&Object.keys(value).every((key,index)=>key===keys[index]);
const capsuleKeys=["capsuleKind","schemaVersion","toolingCommit","entryModule","moduleOrder","modules","moduleSetSha256"];
const moduleKeys=["relativePath","byteLength","sha256","sourceBase64"];
const builtins=new Set(${JSON.stringify(WORKER_BUILTIN_IMPORTS)});
let capsule;
let moduleMap;
let capsulePath;
try{
  if(process.argv.length!==8)throw new Error();
  capsulePath=path.resolve(process.argv[1]);
  if(capsulePath!==process.argv[1])throw new Error();
  const expectedSha=process.argv[2];
  const expectedDevice=process.argv[3];
  const expectedInode=process.argv[4];
  const expectedParentDevice=process.argv[5];
  const expectedParentInode=process.argv[6];
  const expectedPathSha=process.argv[7];
  if(!/^[0-9a-f]{64}$/u.test(expectedSha)||!/^\d+$/u.test(expectedDevice)||!/^\d+$/u.test(expectedInode)||!/^\d+$/u.test(expectedParentDevice)||!/^\d+$/u.test(expectedParentInode)||!/^[0-9a-f]{64}$/u.test(expectedPathSha))throw new Error();
  const parentPath=path.dirname(capsulePath);
  const parentBefore=await lstat(parentPath,{bigint:true});
  const pathBefore=await lstat(capsulePath,{bigint:true});
  const parentReal=path.resolve(await realpath(parentPath));
  const capsuleReal=path.resolve(await realpath(capsulePath));
  const actualPathSha=hex(Buffer.concat([Buffer.from("ieltmps-private-path-v1\0","ascii"),Buffer.from(capsulePath,"utf8")]));
  const initialChecks=[parentBefore.isSymbolicLink(),!parentBefore.isDirectory(),pathBefore.isSymbolicLink(),!pathBefore.isFile(),pathBefore.nlink!==1n,!sameIdentity(parentBefore,expectedParentDevice,expectedParentInode),!sameIdentity(pathBefore,expectedDevice,expectedInode),actualPathSha!==expectedPathSha,!samePath(parentReal,parentPath),!samePath(capsuleReal,capsulePath)];
  if(initialChecks.some(Boolean))throw new Error();
  const handle=await open(capsulePath,C.O_RDONLY|(C.O_NOFOLLOW??0));
  let bytes;
  try{
    const openedBefore=await handle.stat({bigint:true});
    if(!openedBefore.isFile()||openedBefore.nlink!==1n||!sameIdentity(openedBefore,expectedDevice,expectedInode)||openedBefore.size<1n||openedBefore.size>BigInt(${MAX_WORKER_CAPSULE_BYTES}))throw new Error();
    bytes=await handle.readFile();
    const openedAfter=await handle.stat({bigint:true});
    if(!sameIdentity(openedAfter,expectedDevice,expectedInode)||openedAfter.nlink!==1n||openedAfter.size!==openedBefore.size||BigInt(bytes.length)!==openedBefore.size)throw new Error();
  }finally{await handle.close();}
  const parentAfter=await lstat(parentPath,{bigint:true});
  const pathAfter=await lstat(capsulePath,{bigint:true});
  if(!sameIdentity(parentAfter,expectedParentDevice,expectedParentInode)||!sameIdentity(pathAfter,expectedDevice,expectedInode)||pathAfter.nlink!==1n||BigInt(bytes.length)!==pathAfter.size||hex(bytes)!==expectedSha)throw new Error();
  const text=bytes.toString("utf8");
  if(!Buffer.from(text,"utf8").equals(bytes))throw new Error();
  capsule=JSON.parse(text);
  if(!Buffer.from(JSON.stringify(capsule)+"\n","utf8").equals(bytes)||!exactKeys(capsule,capsuleKeys)||capsule.capsuleKind!=="${WORKER_CAPSULE_KIND}"||capsule.schemaVersion!==1||!/^[0-9a-f]{40}$/u.test(capsule.toolingCommit)||capsule.entryModule!=="${WORKER_ENTRY_MODULE}"||!Array.isArray(capsule.moduleOrder)||!Array.isArray(capsule.modules)||capsule.moduleOrder.length!==capsule.modules.length||capsule.moduleOrder.length<1||!/^[0-9a-f]{64}$/u.test(capsule.moduleSetSha256))throw new Error();
  moduleMap=new Map();
  const setHash=createHash("sha256");
  for(let index=0;index<capsule.modules.length;index+=1){
    const entry=capsule.modules[index];
    if(!exactKeys(entry,moduleKeys)||entry.relativePath!==capsule.moduleOrder[index]||!/^[a-z0-9][a-z0-9./_-]*\.mjs$/u.test(entry.relativePath)||entry.relativePath.includes("..")||!Number.isSafeInteger(entry.byteLength)||entry.byteLength<0||!/^[0-9a-f]{64}$/u.test(entry.sha256)||typeof entry.sourceBase64!=="string"||moduleMap.has(entry.relativePath))throw new Error();
    const source=Buffer.from(entry.sourceBase64,"base64");
    if(source.toString("base64")!==entry.sourceBase64||source.length!==entry.byteLength||hex(source)!==entry.sha256||!Buffer.from(source.toString("utf8"),"utf8").equals(source))throw new Error();
    setHash.update(Buffer.from(entry.relativePath,"utf8"));setHash.update(Buffer.from([0]));setHash.update(Buffer.from(String(source.length),"ascii"));setHash.update(Buffer.from([0]));setHash.update(source);
    moduleMap.set(entry.relativePath,Object.freeze({source:source.toString("utf8"),sha256:entry.sha256}));
  }
  if(setHash.digest("hex")!==capsule.moduleSetSha256||!moduleMap.has(capsule.entryModule))throw new Error();
}catch{fail();}
const moduleBaseUrl=pathToFileURL(path.join(path.dirname(capsulePath),"virtual-root")+path.sep).href;
const urlMap=new Map([...moduleMap].map(([relativePath,value])=>[new URL(relativePath,moduleBaseUrl).href,value]));
const requireModuleUrl=(url)=>{if(typeof url!=="string"||!urlMap.has(url))throw new Error();return urlMap.get(url);};
const entryUrl=new URL(capsule.entryModule,moduleBaseUrl).href;
registerHooks({
  resolve(specifier,context,nextResolve){
    if(builtins.has(specifier))return nextResolve(specifier,context);
    if(specifier===entryUrl)return{url:entryUrl,shortCircuit:true};
    if(typeof specifier!=="string"||(!specifier.startsWith("./")&&!specifier.startsWith("../"))||typeof context.parentURL!=="string"||!urlMap.has(context.parentURL))throw new Error();
    const resolved=new URL(specifier,context.parentURL).href;
    requireModuleUrl(resolved);
    return{url:resolved,shortCircuit:true};
  },
  load(url,context,nextLoad){
    if(builtins.has(url))return nextLoad(url,context);
    return{format:"module",source:requireModuleUrl(url).source,shortCircuit:true};
  },
});
const entry=moduleMap.get(capsule.entryModule);
Object.defineProperty(globalThis,"__IELTMPS_WORKER_LOADED_BYTES__",{value:Object.freeze({workerCapsuleSha256:process.argv[2],workerModuleSetSha256:capsule.moduleSetSha256,workerEntryModuleSha256:entry.sha256}),writable:false,configurable:false,enumerable:false});
let workerModule;
try{workerModule=await im${""}port(entryUrl);if(typeof workerModule.runPrivateReceiptWorker!=="function")throw new Error();}catch{fail();}
await workerModule.runPrivateReceiptWorker();
`;

const INPUT_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "artifactRole",
  "formatProfile",
  "sourceCommit",
  "toolingCommit",
  "manifestSha256",
  "membershipReportSha256",
  "membershipCount",
  "archive",
  "receiptAuthority",
  "criticalFiles",
  "artifacts",
]);
const INPUT_ARCHIVE_KEYS = Object.freeze([
  "format",
  "sha256",
  "byteLength",
  "memberCount",
]);
const INPUT_RECEIPT_AUTHORITY_KEYS = Object.freeze([
  "receiptKind",
  "schemaVersion",
  "outputSuffix",
]);
const INPUT_CRITICAL_FILE_KEYS = Object.freeze([
  "path",
  "gitBlobId",
  "sha256",
  "byteLength",
]);
const INPUT_ARTIFACT_KEYS = Object.freeze([
  "role",
  "format",
  "sha256",
  "byteLength",
]);
const TOOL_SET_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "toolSetId",
  "toolingCommit",
  "entries",
]);
const TOOL_ENTRY_KEYS = Object.freeze([
  "path",
  "gitMode",
  "gitBlobObjectId",
  "declaredByteSize",
  "sha256",
]);
const RUNTIME_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "runtimeProfileId",
  "implementation",
  "executableSha256",
  "executableByteLength",
  "nodeVersion",
  "v8Version",
  "modulesVersion",
  "distributionProfileId",
]);
const GIT_KEYS = Object.freeze([
  "documentKind",
  "schemaVersion",
  "gitProfileId",
  "executableSha256",
  "executableByteLength",
  "reportedVersion",
  "objectFormat",
  "distributionProfileId",
]);
const PLATFORM_KEYS = Object.freeze([
  "probeKind",
  "schemaVersion",
  "matrixCellId",
  "operatingSystem",
  "operatingSystemBuild",
  "architecture",
  "filesystemProfile",
  "localeProfile",
  "timezoneProfile",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "pathPolicyCapabilities",
  "exclusiveCreateSupported",
  "hardLinkSupported",
  "atomicNoReplaceHardLinkSupported",
  "reliableLinkCountSupported",
  "stableFileIdentitySupported",
]);
const PATH_CAPABILITY_KEYS = Object.freeze([
  "portableRelativePathsSupported",
  "caseCollisionDetectionSupported",
  "unicodeNormalizationCollisionDetectionSupported",
  "symlinkParentRejectionSupported",
]);
const RECEIPT_TRANSCRIPT_KEYS = Object.freeze([
  "status",
  "mode",
  "verificationComplete",
  "receiptKind",
  "schemaVersion",
  "sourceCommit",
  "toolingCommit",
  "artifactCount",
  "receiptSha256",
  "receiptByteLength",
  "sourceArchiveVerified",
  "toolingCommitSignatureValid",
  "artifactsVerified",
  "correspondingSourceComplete",
  "publicationBlocked",
]);
const PRIVATE_IDENTITY_KEYS = Object.freeze([
  "device",
  "inode",
  "meaningful",
]);
const WORKER_REPOSITORY_BINDING_KEYS = Object.freeze([
  "pathSha256",
  "identity",
]);
const WORKER_CONTEXT_KEYS = Object.freeze([
  "repository",
  "sourceCommit",
  "toolingCommit",
  "policySha256",
  "matrixCellId",
  "criticalToolSetSha256",
  "runtimeIdentitySha256",
  "gitIdentitySha256",
  "platformProbeSha256",
  "testVectorSetSha256",
  "manifestSha256",
  "membershipReportSha256",
  "inputSetSha256",
  "sourceArchiveSha256",
  "sourceArchiveByteLength",
  "artifacts",
  "artifactRole",
  "formatProfile",
  "gitExecutableSha256",
  "gitExecutableByteLength",
  "workerCapsuleSha256",
  "workerModuleSetSha256",
  "workerEntryModuleSha256",
]);
const WORKER_ASSIGNMENT_KEYS = Object.freeze([
  "assignmentId",
  "assignmentNonce",
  "directoryPathSha256",
  "directoryParentIdentity",
  "directoryIdentity",
  "receiptFilename",
  "lockedContextDigest",
  "state",
]);
const WORKER_LEASE_KEYS = Object.freeze([
  "protocol",
  "schemaVersion",
  "runId",
  "coordinatorPid",
  "coordinatorBootstrapSha256",
  "privateRootPathSha256",
  "privateRootIdentity",
  "privateRootParentIdentity",
  "lockedContext",
  "lockedContextDigest",
  "assignments",
]);
const WORKER_REQUEST_KEYS = Object.freeze([
  "protocol",
  "leaseReference",
  "assignmentId",
  "assignmentNonce",
  "repositoryPath",
  "sourceArchivePath",
  "artifacts",
  "lockedContext",
]);
const WORKER_RESPONSE_KEYS = Object.freeze([
  "protocol",
  "runId",
  "assignmentId",
  "contextDigest",
  "status",
  "receiptSha256",
  "receiptByteLength",
  "receiptVerificationTranscript",
  "workerPid",
  "assignedDirectoryIdentity",
  "receiptFileIdentity",
  "workerCapsuleSha256",
  "workerModuleSetSha256",
  "workerEntryModuleSha256",
  "workerRequestListenerCount",
]);

const MODULE_PATHS = Object.freeze(new Map([
  [CRITICAL_TOOL_PATHS[0], fileURLToPath(new URL(
    "./verify-public-source-membership.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[1], fileURLToPath(new URL(
    "./public-source-archive-core.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[2], fileURLToPath(new URL(
    "./verify-public-source-archive.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[3], fileURLToPath(new URL(
    "./public-source-receipt-core.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[4], fileURLToPath(new URL(
    "./prepare-public-source-receipt.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[5], fileURLToPath(new URL(
    "./verify-public-source-receipt.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[6], fileURLToPath(new URL(
    "./reproducibility-evidence-core.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[7], fileURLToPath(new URL(
    "./verify-reproducibility-evidence.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[8], fileURLToPath(import.meta.url)],
  [CRITICAL_TOOL_PATHS[9], fileURLToPath(new URL(
    "./prepare-public-source-receipt-reproducibility.mjs", import.meta.url,
  ))],
  [CRITICAL_TOOL_PATHS[10], fileURLToPath(new URL(
    "./run-public-source-receipt-boundary-vectors.mjs", import.meta.url,
  ))],
]));

export class PublicSourceReceiptReproducibilityError extends Error {
  constructor(phase, reason) {
    const safePhase = ADAPTER_PHASE_SET.has(phase) ? phase : "CLI";
    const safeReason = typeof reason === "string"
      && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(reason)
      ? reason
      : "invalid-operation";
    super("public source receipt reproducibility operation failed");
    this.name = "PublicSourceReceiptReproducibilityError";
    this.phase = safePhase;
    this.reason = safeReason;
  }
}

export function failAdapter(phase, reason) {
  throw new PublicSourceReceiptReproducibilityError(phase, reason);
}

export function asAdapterError(error, phase, reason) {
  return error instanceof PublicSourceReceiptReproducibilityError
    ? error
    : new PublicSourceReceiptReproducibilityError(phase, reason);
}

export function deepFreezeAdapter(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const entry of Object.values(value)) deepFreezeAdapter(entry);
    Object.freeze(value);
  }
  return value;
}

function exactKeys(value, keys, phase, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failAdapter(phase, reason);
  }
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length
    || actual.some((key, index) => key !== keys[index])
  ) {
    failAdapter(phase, reason);
  }
}

function requireIdentifier(value, phase, reason) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireSha256(value, phase, reason) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireGitObject(value, phase, reason) {
  if (typeof value !== "string" || !GIT_OBJECT_PATTERN.test(value)) {
    failAdapter(phase, reason);
  }
  return value;
}

function requireLength(value, phase, reason) {
  if (!Number.isSafeInteger(value) || value < 0) failAdapter(phase, reason);
  return value;
}

function requireBoolean(value, phase, reason) {
  if (typeof value !== "boolean") failAdapter(phase, reason);
  return value;
}

export function canonicalAdapterJsonBytes(value, phase = "POLICY_BINDING") {
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failAdapter(phase, "canonical-document-encoding");
  }
  if (
    bytes.length === 0
    || bytes.at(-1) !== 0x0a
    || bytes.subarray(0, -1).includes(0x0a)
    || bytes.includes(0x0d)
    || bytes.includes(0x5c)
  ) {
    failAdapter(phase, "canonical-document-encoding");
  }
  for (const byte of bytes.subarray(0, -1)) {
    if (byte < 0x20 || byte > 0x7e) {
      failAdapter(phase, "canonical-document-encoding");
    }
  }
  return bytes;
}

export async function readAdapterCanonicalDocument(
  filePath,
  phase,
  kind,
) {
  try {
    const input = await readStableCanonicalDocument(
      filePath,
      "FILE_IDENTITY",
      kind,
    );
    const value = parseCanonicalOpaqueJsonBytes(input.bytes, "FILE_IDENTITY");
    return Object.freeze({ ...input, value });
  } catch {
    failAdapter(phase, kind + "-invalid");
  }
}

export async function readAndParseMatrixPolicy(filePath) {
  try {
    const input = await readStableCanonicalDocument(
      filePath,
      "POLICY_SCHEMA",
      "policy",
    );
    return Object.freeze({
      ...input,
      value: parseCanonicalMatrixPolicy(input.bytes),
    });
  } catch {
    failAdapter("POLICY_BINDING", "policy-invalid");
  }
}

export function selectPolicyCell(policy, matrixCellId) {
  requireIdentifier(matrixCellId, "POLICY_BINDING", "matrix-cell-id");
  if (policy.artifactRole !== ARTIFACT_ROLE || policy.formatProfile !== FORMAT_PROFILE) {
    failAdapter("POLICY_BINDING", "artifact-profile-mismatch");
  }
  const required = policy.requiredCells.find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  const optional = policy.optionalCells.find(
    (entry) => entry.matrixCellId === matrixCellId,
  );
  if (!required && !optional) failAdapter("POLICY_BINDING", "matrix-cell-unknown");
  return required ?? optional;
}

export function buildCanonicalInputSet({
  membership,
  archiveVerification,
  toolingCommit,
  criticalFiles,
  artifacts,
}) {
  try {
    if (
      !membership
      || typeof membership !== "object"
      || !Array.isArray(membership.members)
      || !membership.report
      || !Array.isArray(membership.report.members)
      || !Buffer.isBuffer(membership.reportBytes)
      || membership.report.members.length !== membership.members.length
      || membership.report.membershipCount !== membership.members.length
      || membership.report.sourceCommit !== membership.sourceCommit
    ) {
      failAdapter("SOURCE_BINDING", "membership-result-invalid");
    }
    const membershipReportSha256 = sha256Bytes(membership.reportBytes);
    for (let index = 0; index < membership.members.length; index += 1) {
      const member = membership.members[index];
      const projected = membership.report.members[index];
      if (
        !member
        || !projected
        || projected.path !== member.path
        || projected.gitMode !== member.gitMode
        || projected.sha256 !== member.sha256
        || projected.role !== member.role
        || projected.licenseScope !== member.licenseScope
        || !Buffer.isBuffer(member.blobBytes)
        || member.blobBytes.length !== member.declaredByteSize
        || sha256Bytes(member.blobBytes) !== member.sha256
      ) failAdapter("SOURCE_BINDING", "membership-result-invalid");
    }
    if (
      !archiveVerification
      || archiveVerification.sourceCommit !== membership.sourceCommit
      || archiveVerification.manifestSha256 !== membership.manifestSha256
      || archiveVerification.membershipReportSha256 !== membershipReportSha256
      || archiveVerification.membershipCount !== membership.members.length
      || archiveVerification.archiveFormat !== "tar-ustar-v1"
      || archiveVerification.membershipValid !== true
      || archiveVerification.archiveVerified !== true
      || archiveVerification.correspondingSourceComplete !== false
      || archiveVerification.publicationBlocked !== true
    ) failAdapter("ARCHIVE_VERIFICATION", "b3-verification-result");
    requireGitObject(toolingCommit, "SOURCE_BINDING", "tooling-commit");
    requireSha256(archiveVerification.archiveSha256, "ARCHIVE_VERIFICATION", "archive-hash");
    requireLength(archiveVerification.archiveByteLength, "ARCHIVE_VERIFICATION", "archive-length");
    requireLength(archiveVerification.archiveMemberCount, "ARCHIVE_VERIFICATION", "archive-members");
    if (!Array.isArray(criticalFiles)
      || criticalFiles.length !== RECEIPT_CRITICAL_TOOL_PATHS.length
      || !Array.isArray(artifacts)
      || artifacts.length < 1) {
      failAdapter("SOURCE_BINDING", "input-set-authority");
    }
    const frozenCriticalFiles = criticalFiles.map((entry, index) => {
      exactKeys(entry, INPUT_CRITICAL_FILE_KEYS, "SOURCE_BINDING", "critical-file-shape");
      if (entry.path !== RECEIPT_CRITICAL_TOOL_PATHS[index]) {
        failAdapter("SOURCE_BINDING", "critical-file-order");
      }
      requireGitObject(entry.gitBlobId, "SOURCE_BINDING", "critical-file-object");
      requireSha256(entry.sha256, "SOURCE_BINDING", "critical-file-hash");
      requireLength(entry.byteLength, "SOURCE_BINDING", "critical-file-length");
      return Object.freeze({ ...entry });
    });
    const frozenArtifacts = artifacts.map((entry) => {
      exactKeys(entry, INPUT_ARTIFACT_KEYS, "SOURCE_BINDING", "artifact-shape");
      requireIdentifier(entry.role, "SOURCE_BINDING", "artifact-role");
      requireIdentifier(entry.format, "SOURCE_BINDING", "artifact-format");
      requireSha256(entry.sha256, "SOURCE_BINDING", "artifact-hash");
      requireLength(entry.byteLength, "SOURCE_BINDING", "artifact-length");
      return Object.freeze({ ...entry });
    });
    const value = deepFreezeAdapter({
      documentKind: INPUT_SET_KIND,
      schemaVersion: 1,
      artifactRole: ARTIFACT_ROLE,
      formatProfile: FORMAT_PROFILE,
      sourceCommit: membership.sourceCommit,
      toolingCommit,
      manifestSha256: membership.manifestSha256,
      membershipReportSha256,
      membershipCount: membership.members.length,
      archive: {
        format: "tar-ustar-v1",
        sha256: archiveVerification.archiveSha256,
        byteLength: archiveVerification.archiveByteLength,
        memberCount: archiveVerification.archiveMemberCount,
      },
      receiptAuthority: {
        receiptKind: RECEIPT_KIND,
        schemaVersion: RECEIPT_SCHEMA_VERSION,
        outputSuffix: RECEIPT_OUTPUT_SUFFIX,
      },
      criticalFiles: frozenCriticalFiles,
      artifacts: frozenArtifacts,
    });
    exactKeys(value, INPUT_SET_KEYS, "SOURCE_BINDING", "input-set-shape");
    exactKeys(value.archive, INPUT_ARCHIVE_KEYS, "SOURCE_BINDING", "archive-shape");
    exactKeys(value.receiptAuthority, INPUT_RECEIPT_AUTHORITY_KEYS, "SOURCE_BINDING", "receipt-authority-shape");
    requireGitObject(value.sourceCommit, "SOURCE_BINDING", "source-commit");
    requireGitObject(value.toolingCommit, "SOURCE_BINDING", "tooling-commit");
    requireSha256(value.manifestSha256, "SOURCE_BINDING", "source-manifest-hash");
    requireSha256(value.membershipReportSha256, "SOURCE_BINDING", "membership-report-hash");
    const bytes = canonicalAdapterJsonBytes(value, "SOURCE_BINDING");
    return Object.freeze({
      value,
      bytes,
      sha256: sha256Bytes(bytes),
      membershipReportSha256,
    });
  } catch (error) {
    throw asAdapterError(error, "SOURCE_BINDING", "input-set-invalid");
  }
}

function canonicalOsName() {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  failAdapter("PLATFORM_PROBE", "unsupported-operating-system");
}

function identityStrings(identity) {
  return Object.freeze({
    device: identity.device.toString(10),
    inode: identity.inode.toString(10),
    meaningful: identity.meaningful,
  });
}

function identityMatchesStrings(identity, strings) {
  return strings
    && identity.meaningful === strings.meaningful
    && identity.device.toString(10) === strings.device
    && identity.inode.toString(10) === strings.inode;
}

function requirePrivateIdentityStrings(value, reason) {
  exactKeys(value, PRIVATE_IDENTITY_KEYS, "SAME_HOST", reason);
  if (
    !DECIMAL_PATTERN.test(value.device)
    || !DECIMAL_PATTERN.test(value.inode)
    || value.meaningful !== true
  ) failAdapter("SAME_HOST", reason);
  return value;
}

function privateJsonBytes(value, reason) {
  try {
    return Buffer.from(JSON.stringify(value) + "\n", "utf8");
  } catch {
    failAdapter("SAME_HOST", reason);
  }
}

function parseExactPrivateJsonText(text, maximumBytes, reason) {
  if (typeof text !== "string") failAdapter("SAME_HOST", reason);
  const bytes = Buffer.from(text, "utf8");
  if (
    bytes.length === 0
    || bytes.length > maximumBytes
    || bytes.at(-1) !== 0x0a
    || bytes.includes(0x00)
    || bytes.includes(0x0d)
  ) failAdapter("SAME_HOST", reason);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    failAdapter("SAME_HOST", reason);
  }
  if (!privateJsonBytes(value, reason).equals(bytes)) {
    failAdapter("SAME_HOST", reason);
  }
  return value;
}

function requireExactPrivatePath(value, reason) {
  if (
    typeof value !== "string"
    || value.length === 0
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || path.resolve(value) !== value
    || value.normalize("NFC") !== value
  ) failAdapter("SAME_HOST", reason);
  return value;
}

function privatePathSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-private-path-v1\0", "ascii"),
    Buffer.from(value, "utf8"),
  ]));
}

function lockedContextSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-worker-locked-context-v1\0", "ascii"),
    privateJsonBytes(value, "private-worker-context-invalid"),
  ]));
}

function assignmentNonceSha256(value) {
  return sha256Bytes(Buffer.concat([
    Buffer.from("ieltmps-worker-assignment-nonce-v1\0", "ascii"),
    Buffer.from(value, "ascii"),
  ]));
}

async function readStablePrivateFile(filePath, maximumBytes, reason) {
  requireExactPrivatePath(filePath, reason);
  let handle = null;
  try {
    const initial = await lstat(filePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.nlink !== 1n
      || initial.size <= 0n
      || initial.size > BigInt(maximumBytes)
      || !identityFromState(initial).meaningful
      || path.resolve(await realpath(filePath)) !== filePath
    ) failAdapter("SAME_HOST", reason);
    const identity = identityFromState(initial);
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || before.size !== initial.size
      || !identitiesEqual(identity, identityFromState(before))
    ) failAdapter("SAME_HOST", reason);
    const bytes = Buffer.alloc(Number(initial.size));
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, null);
      if (!result || result.bytesRead <= 0) failAdapter("SAME_HOST", reason);
      offset += result.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    const after = await handle.stat({ bigint: true });
    const final = await lstat(filePath, { bigint: true });
    if (
      trailing.bytesRead !== 0
      || after.size !== before.size
      || final.size !== initial.size
      || final.nlink !== 1n
      || !identitiesEqual(identity, identityFromState(after))
      || !identitiesEqual(identity, identityFromState(final))
      || path.resolve(await realpath(filePath)) !== filePath
    ) failAdapter("SAME_HOST", reason);
    return Object.freeze({
      bytes,
      identity,
      nlink: final.nlink,
      sha256: sha256Bytes(bytes),
    });
  } catch (error) {
    throw asAdapterError(error, "SAME_HOST", reason);
  } finally {
    if (handle) await handle.close();
  }
}

async function inspectExactPrivateDirectory(directoryPath, reason) {
  requireExactPrivatePath(directoryPath, reason);
  const parentPath = path.dirname(directoryPath);
  let parentChain;
  try {
    parentChain = await validateParentChain(parentPath);
  } catch {
    failAdapter("SAME_HOST", reason);
  }
  const state = await lstat(directoryPath, { bigint: true });
  const identity = identityFromState(state);
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !identity.meaningful
    || path.resolve(await realpath(directoryPath)) !== directoryPath
  ) failAdapter("SAME_HOST", reason);
  await validateParentChain(parentPath, parentChain);
  return Object.freeze({
    path: directoryPath,
    pathSha256: privatePathSha256(directoryPath),
    identity,
    parentIdentity: parentChain.at(-1).identity,
    parentChain,
  });
}

function repositoryBinding(directory) {
  return Object.freeze({
    pathSha256: directory.pathSha256,
    identity: identityStrings(directory.identity),
  });
}

function validateRepositoryBinding(value, reason) {
  exactKeys(value, WORKER_REPOSITORY_BINDING_KEYS, "SAME_HOST", reason);
  requireSha256(value.pathSha256, "SAME_HOST", reason);
  requirePrivateIdentityStrings(value.identity, reason);
}

function validateLockedWorkerContext(value, reason = "private-worker-context-invalid") {
  exactKeys(value, WORKER_CONTEXT_KEYS, "SAME_HOST", reason);
  validateRepositoryBinding(value.repository, reason);
  requireGitObject(value.sourceCommit, "SAME_HOST", reason);
  requireGitObject(value.toolingCommit, "SAME_HOST", reason);
  for (const key of [
    "policySha256",
    "criticalToolSetSha256",
    "runtimeIdentitySha256",
    "gitIdentitySha256",
    "platformProbeSha256",
    "testVectorSetSha256",
    "manifestSha256",
    "membershipReportSha256",
    "inputSetSha256",
    "sourceArchiveSha256",
    "gitExecutableSha256",
    "workerCapsuleSha256",
    "workerModuleSetSha256",
    "workerEntryModuleSha256",
  ]) requireSha256(value[key], "SAME_HOST", reason);
  requireIdentifier(value.matrixCellId, "SAME_HOST", reason);
  if (
    value.artifactRole !== ARTIFACT_ROLE
    || value.formatProfile !== FORMAT_PROFILE
    || !Number.isSafeInteger(value.sourceArchiveByteLength)
    || value.sourceArchiveByteLength < 0
    || !Array.isArray(value.artifacts)
    || value.artifacts.length < 1
    || !Number.isSafeInteger(value.gitExecutableByteLength)
    || value.gitExecutableByteLength <= 0
  ) failAdapter("SAME_HOST", reason);
  for (const artifact of value.artifacts) {
    exactKeys(artifact, INPUT_ARTIFACT_KEYS, "SAME_HOST", reason);
    requireIdentifier(artifact.role, "SAME_HOST", reason);
    requireIdentifier(artifact.format, "SAME_HOST", reason);
    requireSha256(artifact.sha256, "SAME_HOST", reason);
    requireLength(artifact.byteLength, "SAME_HOST", reason);
  }
  return value;
}

function contextsEqual(left, right) {
  return privateJsonBytes(left, "private-worker-context-invalid").equals(
    privateJsonBytes(right, "private-worker-context-invalid"),
  );
}

async function inspectExecutable(candidate) {
  let state;
  try {
    state = await lstat(candidate, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
  if (state.isSymbolicLink() || !state.isFile()) {
    failAdapter("GIT_IDENTITY", "git-executable-reparse");
  }
  const resolved = await realpath(candidate);
  if (!pathsEqual(resolved, candidate)) {
    failAdapter("GIT_IDENTITY", "git-executable-reparse");
  }
  if (process.platform !== "win32") {
    try {
      await access(candidate, FS_CONSTANTS.X_OK);
    } catch {
      failAdapter("GIT_IDENTITY", "git-executable-permission");
    }
  }
  return path.resolve(candidate);
}

async function hashStableRegularFile(filePath, phase, reason) {
  let handle = null;
  try {
    const initial = await lstat(filePath, { bigint: true });
    if (
      initial.isSymbolicLink()
      || !initial.isFile()
      || initial.size < 0n
      || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
      || !pathsEqual(await realpath(filePath), filePath)
    ) failAdapter(phase, reason);
    const identity = identityFromState(initial);
    handle = await open(filePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.size !== initial.size
      || !identitiesEqual(identity, identityFromState(before))
    ) failAdapter(phase, reason);
    const hash = createHash("sha256");
    let offset = 0;
    const byteLength = Number(initial.size);
    while (offset < byteLength) {
      const chunk = Buffer.alloc(Math.min(FILE_CHUNK_SIZE, byteLength - offset));
      const read = await handle.read(chunk, 0, chunk.length, null);
      if (!read || read.bytesRead <= 0 || read.bytesRead > chunk.length) {
        failAdapter(phase, reason);
      }
      hash.update(chunk.subarray(0, read.bytesRead));
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.alloc(1), 0, 1, null);
    if (trailing.bytesRead !== 0) failAdapter(phase, reason);
    const after = await handle.stat({ bigint: true });
    const finalState = await lstat(filePath, { bigint: true });
    if (
      after.size !== initial.size
      || finalState.size !== initial.size
      || !identitiesEqual(identity, identityFromState(after))
      || !identitiesEqual(identity, identityFromState(finalState))
      || !pathsEqual(await realpath(filePath), filePath)
    ) failAdapter(phase, reason);
    return Object.freeze({ sha256: hash.digest("hex"), byteLength });
  } catch (error) {
    throw asAdapterError(error, phase, reason);
  } finally {
    if (handle) await handle.close();
  }
}

export async function resolveControlledGitExecutable() {
  const pathValue = Object.entries(process.env).find(
    ([key]) => key.toUpperCase() === "PATH",
  )?.[1];
  if (typeof pathValue !== "string" || pathValue.length === 0) {
    failAdapter("GIT_IDENTITY", "git-path-unavailable");
  }
  const names = process.platform === "win32" ? ["git.exe", "git.com"] : ["git"];
  for (const rawEntry of pathValue.split(path.delimiter)) {
    const unquoted = rawEntry.length >= 2
      && rawEntry.startsWith('"')
      && rawEntry.endsWith('"')
      ? rawEntry.slice(1, -1)
      : rawEntry;
    if (!unquoted) continue;
    const directory = path.isAbsolute(unquoted)
      ? path.normalize(unquoted)
      : path.resolve(unquoted);
    for (const name of names) {
      const candidate = path.join(directory, name);
      const executable = await inspectExecutable(candidate);
      if (!executable) continue;
      const identity = await hashStableRegularFile(
        executable,
        "GIT_IDENTITY",
        "git-executable-identity",
      );
      const version = spawnSync(executable, ["--version"], {
        encoding: "utf8",
        env: sanitizedGitEnvironment(process.env, executable),
        shell: false,
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      });
      const match = !version.error && version.status === 0
        ? /^git version ([0-9][0-9A-Za-z.+-]*)\r?\n?$/u.exec(version.stdout)
        : null;
      if (!match) failAdapter("GIT_IDENTITY", "git-version-invalid");
      return Object.freeze({
        path: executable,
        directory: path.dirname(executable),
        sha256: identity.sha256,
        byteLength: identity.byteLength,
        reportedVersion: match[1],
      });
    }
  }
  failAdapter("GIT_IDENTITY", "git-executable-unavailable");
}

function sanitizedGitEnvironment(source, executable) {
  const environment = {};
  for (const [key, value] of Object.entries(source)) {
    if (!key.toUpperCase().startsWith("GIT_") && key.toUpperCase() !== "PATH") {
      environment[key] = value;
    }
  }
  environment.PATH = path.dirname(executable);
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.LC_ALL = "C";
  environment.LANG = "C";
  return environment;
}

export function installControlledGitPath(git) {
  const prior = Object.entries(process.env).filter(
    ([key]) => key.toUpperCase() === "PATH",
  );
  for (const [key] of prior) delete process.env[key];
  process.env.PATH = git.directory;
  return () => {
    for (const [key] of Object.entries(process.env)) {
      if (key.toUpperCase() === "PATH") delete process.env[key];
    }
    for (const [key, value] of prior) process.env[key] = value;
  };
}

function runControlledGit(git, repoRoot, args, phase, reason, input = undefined) {
  const result = spawnSync(
    git.path,
    ["--no-replace-objects", "-C", repoRoot, ...args],
    {
      encoding: null,
      env: sanitizedGitEnvironment(process.env, git.path),
      input,
      maxBuffer: MAX_GIT_BUFFER,
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0) failAdapter(phase, reason);
  return result.stdout;
}

export async function validateRepositoryCommit(repoArgument, commit, git, phase) {
  if (
    typeof repoArgument !== "string"
    || !path.isAbsolute(repoArgument)
    || path.resolve(repoArgument) !== repoArgument
  ) {
    failAdapter(phase, "repository-path-invalid");
  }
  const state = await pathState(repoArgument);
  if (!state || state.isSymbolicLink() || !state.isDirectory()) {
    failAdapter(phase, "repository-path-invalid");
  }
  const resolved = await realpath(repoArgument);
  if (!pathsEqual(resolved, repoArgument)) failAdapter(phase, "repository-reparse");
  const root = runControlledGit(
    git, repoArgument, ["rev-parse", "--show-toplevel"], phase, "repository-root",
  ).toString("utf8").trim();
  if (!pathsEqual(root, repoArgument)) failAdapter(phase, "repository-root");
  const objectFormat = runControlledGit(
    git, repoArgument, ["rev-parse", "--show-object-format"], phase, "object-format",
  ).toString("ascii").trim();
  if (objectFormat !== "sha1") failAdapter(phase, "object-format");
  const replacements = runControlledGit(
    git,
    repoArgument,
    ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    phase,
    "replacement-object-ref",
  ).toString("utf8").trim();
  if (replacements) failAdapter(phase, "replacement-object-ref");
  for (const marker of [
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_LOG",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
  ]) {
    const markerPath = runControlledGit(
      git,
      repoArgument,
      ["rev-parse", "--path-format=absolute", "--git-path", marker],
      phase,
      "active-git-operation",
    ).toString("utf8").trim();
    if (markerPath && await pathState(markerPath)) {
      failAdapter(phase, "active-git-operation");
    }
  }
  requireGitObject(commit, phase, "commit-id");
  const type = runControlledGit(
    git, repoArgument, ["cat-file", "-t", commit], phase, "commit-object",
  ).toString("ascii").trim();
  if (type !== "commit") failAdapter(phase, "commit-object-type");
  if (phase === "TOOL_SET") {
    const head = runControlledGit(
      git,
      repoArgument,
      ["rev-parse", "--verify", "HEAD"],
      phase,
      "tooling-head",
    ).toString("ascii").trim();
    const status = runControlledGit(
      git,
      repoArgument,
      ["status", "--porcelain=v2", "--untracked-files=all"],
      phase,
      "dirty-tooling-worktree",
    );
    if (head !== commit) failAdapter(phase, "tooling-head");
    if (status.length !== 0) failAdapter(phase, "dirty-tooling-worktree");
  }
  return repoArgument;
}

function parseSingleTreeEntry(bytes, expectedPath) {
  const records = bytes.length === 0
    ? []
    : bytes.subarray(0, -1).toString("utf8").split("\0");
  if (bytes.at(-1) !== 0 || records.length !== 1) return null;
  const tab = records[0].indexOf("\t");
  if (tab < 0 || records[0].slice(tab + 1) !== expectedPath) return null;
  const parts = records[0].slice(0, tab).split(" ");
  if (parts.length !== 3 || parts[1] !== "blob") return null;
  return Object.freeze({ mode: parts[0], objectId: parts[2] });
}

function validateStaticImports(relativePath, bytes) {
  const source = bytes.toString("utf8");
  const dynamicImports = [...source.matchAll(/\bimport\s*\(/gu)];
  if (dynamicImports.length > 0) {
    const frozenReceiptWorkerIsBound = relativePath
      === "developer/public-source-receipt-core.mjs"
      && dynamicImports.length === 1
      && source.includes(
        'path.resolve("developer/verify-public-source-receipt.mjs")',
      )
      && source.includes("im" + "port(pathToFileURL(modulePath).href)");
    if (!frozenReceiptWorkerIsBound) {
      failAdapter("TOOL_SET", "dynamic-production-import");
    }
  }
  const expressions = [
    /\bfrom\s*["']([^"']+)["']/gu,
    /(?:^|\n)\s*import\s*["']([^"']+)["']/gu,
  ];
  for (const expression of expressions) {
    for (const match of source.matchAll(expression)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) {
        if (!WORKER_BUILTIN_IMPORT_SET.has(specifier)) {
          failAdapter("TOOL_SET", "production-builtin-outside-allowlist");
        }
        continue;
      }
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
        failAdapter("TOOL_SET", "production-import-outside-tool-set");
      }
      const resolved = path.posix.normalize(
        path.posix.join(path.posix.dirname(relativePath), specifier),
      );
      if (!CRITICAL_TOOL_PATHS.includes(resolved)) {
        failAdapter("TOOL_SET", "production-import-outside-tool-set");
      }
    }
  }
}

function moduleSetSha256(modules) {
  const digest = createHash("sha256");
  for (const module of modules) {
    const source = Buffer.from(module.sourceBase64, "base64");
    digest.update(Buffer.from(module.relativePath, "utf8"));
    digest.update(Buffer.from([0]));
    digest.update(Buffer.from(String(source.length), "ascii"));
    digest.update(Buffer.from([0]));
    digest.update(source);
  }
  return digest.digest("hex");
}

export async function validateCriticalToolSet({
  document,
  toolingRepo,
  toolingCommit,
  git,
}) {
  const phase = "TOOL_SET";
  const value = document.value;
  exactKeys(value, TOOL_SET_KEYS, phase, "critical-tool-set-shape");
  if (
    value.documentKind !== CRITICAL_TOOL_SET_KIND
    || value.schemaVersion !== 1
    || value.toolSetId !== CRITICAL_TOOL_SET_ID
    || value.toolingCommit !== toolingCommit
    || !Array.isArray(value.entries)
    || value.entries.length !== CRITICAL_TOOL_PATHS.length
  ) {
    failAdapter(phase, "critical-tool-set-invalid");
  }
  const workerModules = [];
  for (let index = 0; index < value.entries.length; index += 1) {
    const entry = value.entries[index];
    exactKeys(entry, TOOL_ENTRY_KEYS, phase, "critical-tool-entry-shape");
    const expectedPath = CRITICAL_TOOL_PATHS[index];
    if (
      entry.path !== expectedPath
      || (entry.gitMode !== "100644" && entry.gitMode !== "100755")
      || !GIT_OBJECT_PATTERN.test(entry.gitBlobObjectId)
      || !Number.isSafeInteger(entry.declaredByteSize)
      || entry.declaredByteSize < 0
      || !SHA256_PATTERN.test(entry.sha256)
    ) {
      failAdapter(phase, "critical-tool-entry-invalid");
    }
    const tree = parseSingleTreeEntry(
      runControlledGit(
        git,
        toolingRepo,
        ["ls-tree", "-z", "--full-tree", toolingCommit, "--", expectedPath],
        phase,
        "critical-tool-commit-entry",
      ),
      expectedPath,
    );
    if (
      !tree
      || tree.mode !== entry.gitMode
      || tree.objectId !== entry.gitBlobObjectId
    ) {
      failAdapter(phase, "critical-tool-commit-entry");
    }
    const committed = runControlledGit(
      git,
      toolingRepo,
      ["cat-file", "blob", entry.gitBlobObjectId],
      phase,
      "critical-tool-blob",
    );
    if (
      committed.length !== entry.declaredByteSize
      || sha256Bytes(committed) !== entry.sha256
    ) {
      failAdapter(phase, "critical-tool-blob");
    }
    const expectedLoadedPath = path.join(toolingRepo, ...expectedPath.split("/"));
    const modulePath = MODULE_PATHS.get(expectedPath);
    let loadedMatches = false;
    try {
      loadedMatches = Boolean(modulePath)
        && pathsEqual(
          realpathSync.native(modulePath),
          realpathSync.native(expectedLoadedPath),
        );
    } catch {
      loadedMatches = false;
    }
    if (!loadedMatches) {
      failAdapter(phase, "critical-tool-loaded-path");
    }
    let actual;
    try {
      actual = await readStableFile(expectedLoadedPath, {
        phase: "FILE_IDENTITY",
        reason: "critical-tool",
        kind: "critical-tool",
        captureBytes: true,
      });
    } catch {
      failAdapter(phase, "critical-tool-loaded-bytes");
    }
    if (
      actual.byteLength !== entry.declaredByteSize
      || actual.sha256 !== entry.sha256
      || !actual.bytes.equals(committed)
    ) {
      failAdapter(phase, "critical-tool-loaded-bytes");
    }
    validateStaticImports(expectedPath, committed);
    workerModules.push(Object.freeze({
      relativePath: expectedPath,
      byteLength: committed.length,
      sha256: entry.sha256,
      sourceBase64: committed.toString("base64"),
    }));
  }
  const moduleSet = moduleSetSha256(workerModules);
  const entry = workerModules.find(
    (module) => module.relativePath === WORKER_ENTRY_MODULE,
  );
  if (!entry || !SHA256_PATTERN.test(moduleSet)) {
    failAdapter(phase, "critical-tool-set-invalid");
  }
  return Object.freeze({
    toolingCommit,
    moduleOrder: Object.freeze([...CRITICAL_TOOL_PATHS]),
    modules: Object.freeze(workerModules),
    moduleSetSha256: moduleSet,
    entryModule: WORKER_ENTRY_MODULE,
    entryModuleSha256: entry.sha256,
  });
}

export async function validateRuntimeIdentity(document, cell) {
  const phase = "RUNTIME_IDENTITY";
  const value = document.value;
  exactKeys(value, RUNTIME_KEYS, phase, "runtime-identity-shape");
  const measured = await hashStableRegularFile(
    path.resolve(process.execPath),
    phase,
    "runtime-executable-identity",
  );
  if (
    value.documentKind !== RUNTIME_IDENTITY_KIND
    || value.schemaVersion !== 1
    || value.runtimeProfileId !== cell.runtimeProfileId
    || document.sha256 !== cell.runtimeIdentitySha256
    || value.implementation !== "node"
    || value.executableSha256 !== measured.sha256
    || value.executableByteLength !== measured.byteLength
    || value.nodeVersion !== process.versions.node
    || value.v8Version !== process.versions.v8
    || value.modulesVersion !== process.versions.modules
  ) {
    failAdapter(phase, "runtime-profile-mismatch");
  }
  requireIdentifier(value.runtimeProfileId, phase, "runtime-profile-id");
  requireIdentifier(value.distributionProfileId, phase, "runtime-distribution-profile");
  return true;
}

export function validateGitIdentity(document, cell, git) {
  const phase = "GIT_IDENTITY";
  const value = document.value;
  exactKeys(value, GIT_KEYS, phase, "git-identity-shape");
  if (
    value.documentKind !== GIT_IDENTITY_KIND
    || value.schemaVersion !== 1
    || value.gitProfileId !== cell.gitProfileId
    || document.sha256 !== cell.gitIdentitySha256
    || value.executableSha256 !== git.sha256
    || value.executableByteLength !== git.byteLength
    || value.reportedVersion !== git.reportedVersion
    || value.objectFormat !== "sha1"
  ) {
    failAdapter(phase, "git-identity-mismatch");
  }
  requireIdentifier(value.gitProfileId, phase, "git-profile-id");
  requireIdentifier(value.distributionProfileId, phase, "git-distribution-profile");
  return true;
}

export function validatePlatformProbeShape(
  document,
  cell,
  runtimeIdentitySha256,
  gitIdentitySha256,
) {
  const phase = "PLATFORM_PROBE";
  const value = document.value;
  exactKeys(value, PLATFORM_KEYS, phase, "platform-probe-shape");
  exactKeys(
    value.pathPolicyCapabilities,
    PATH_CAPABILITY_KEYS,
    phase,
    "path-capability-shape",
  );
  for (const key of PATH_CAPABILITY_KEYS) {
    requireBoolean(value.pathPolicyCapabilities[key], phase, "path-capability-value");
  }
  for (const key of [
    "exclusiveCreateSupported",
    "hardLinkSupported",
    "atomicNoReplaceHardLinkSupported",
    "reliableLinkCountSupported",
    "stableFileIdentitySupported",
  ]) requireBoolean(value[key], phase, "host-capability-value");
  const expectedStatic = {
    matrixCellId: cell.matrixCellId,
    operatingSystem: canonicalOsName(),
    operatingSystemBuild: os.release().toLowerCase(),
    architecture: process.arch,
    filesystemProfile: cell.filesystemProfile,
    localeProfile: cell.localeProfile,
    timezoneProfile: cell.timezoneProfile,
    runtimeIdentitySha256,
    gitIdentitySha256,
  };
  if (
    document.sha256 !== cell.platformProbeSha256
    || !["x64", "arm64"].includes(process.arch)
    || Object.entries(expectedStatic).some(([key, expected]) => value[key] !== expected)
  ) {
    failAdapter(phase, "platform-probe-mismatch");
  }
  return value;
}

export function validateMeasuredCapabilities(probe, measured) {
  const pathCapabilities = probe.pathPolicyCapabilities;
  if (PATH_CAPABILITY_KEYS.some((key) => pathCapabilities[key] !== true)) {
    failAdapter("PLATFORM_PROBE", "unsupported-host-capability");
  }
  const keys = [
    "exclusiveCreateSupported",
    "hardLinkSupported",
    "atomicNoReplaceHardLinkSupported",
    "reliableLinkCountSupported",
    "stableFileIdentitySupported",
  ];
  if (keys.some((key) => measured[key] !== true)) {
    failAdapter("PLATFORM_PROBE", "unsupported-host-capability");
  }
  if (keys.some((key) => probe[key] !== measured[key])) {
    failAdapter("PLATFORM_PROBE", "platform-probe-mismatch");
  }
  return true;
}

export async function validateOutputTarget({
  outputDirectory,
  sourceRepo,
  toolingRepo,
}) {
  if (
    typeof outputDirectory !== "string"
    || !path.isAbsolute(outputDirectory)
    || path.normalize(outputDirectory) !== outputDirectory
    || path.resolve(outputDirectory) !== outputDirectory
  ) {
    failAdapter("CLI", "output-directory-invalid");
  }
  if (
    pathsEqual(outputDirectory, sourceRepo)
    || isInside(sourceRepo, outputDirectory)
    || pathsEqual(outputDirectory, toolingRepo)
    || isInside(toolingRepo, outputDirectory)
  ) {
    failAdapter("CLI", "output-directory-contained");
  }
  const parent = path.dirname(outputDirectory);
  let parentChain;
  try {
    parentChain = await validateParentChain(parent);
  } catch {
    failAdapter("CLI", "output-parent-invalid");
  }
  if (await pathState(outputDirectory)) failAdapter("CLI", "output-directory-exists");
  return Object.freeze({
    path: outputDirectory,
    parent,
    parentChain,
    parentIdentity: parentChain.at(-1).identity,
  });
}

export async function createCoordinatorPrivateRoot({ target, ledger }) {
  let privatePath = null;
  try {
    await validateParentChain(target.parent, target.parentChain);
    if (await pathState(target.path)) failAdapter("CLI", "output-directory-exists");
    const privateParent = path.dirname(target.parent);
    const privateParentChain = target.parentChain.slice(0, -1);
    if (privateParentChain.length === 0) {
      failAdapter("OUTPUT_PUBLICATION", "private-root-parent");
    }
    await validateParentChain(privateParent, privateParentChain);
    privatePath = path.join(
      privateParent,
      `.ieltmps-receipt-private-${randomBytes(24).toString("hex")}`,
    );
    await mkdir(privatePath, { mode: 0o700 });
    await validateParentChain(privateParent, privateParentChain);
    await validateParentChain(target.parent, target.parentChain);
    const state = await lstat(privatePath, { bigint: true });
    if (
      state.isSymbolicLink()
      || !state.isDirectory()
      || !identityFromState(state).meaningful
      || !pathsEqual(await realpath(privatePath), privatePath)
    ) failAdapter("OUTPUT_PUBLICATION", "private-root-identity");
    const record = Object.freeze({
      kind: "directory",
      path: privatePath,
      identity: identityFromState(state),
    });
    ledger.push(record);
    return record;
  } catch (error) {
    throw asAdapterError(error, "OUTPUT_PUBLICATION", "private-root-create");
  }
}

export async function createExclusiveOutputDirectory({
  outputDirectory,
  sourceRepo,
  toolingRepo,
  validatedTarget = null,
}) {
  const target = validatedTarget ?? await validateOutputTarget({
    outputDirectory,
    sourceRepo,
    toolingRepo,
  });
  if (
    target.path !== outputDirectory
    || target.parent !== path.dirname(outputDirectory)
  ) failAdapter("OUTPUT_PUBLICATION", "output-target-binding");
  await validateParentChain(target.parent, target.parentChain);
  if (await pathState(outputDirectory)) failAdapter("OUTPUT_PUBLICATION", "output-directory-exists");
  try {
    await mkdir(outputDirectory, { mode: 0o700 });
    await validateParentChain(target.parent, target.parentChain);
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "output-directory-create");
  }
  const state = await lstat(outputDirectory, { bigint: true });
  const resolved = await realpath(outputDirectory);
  if (state.isSymbolicLink() || !state.isDirectory() || !pathsEqual(resolved, outputDirectory)) {
    failAdapter("OUTPUT_PUBLICATION", "output-directory-identity");
  }
  return Object.freeze({
    path: outputDirectory,
    parent: target.parent,
    parentChain: target.parentChain,
    identity: identityFromState(state),
  });
}

async function requireDirectoryIdentity(record) {
  const state = await pathState(record.path);
  if (
    !state
    || state.isSymbolicLink()
    || !state.isDirectory()
    || !identitiesEqual(record.identity, identityFromState(state))
    || !pathsEqual(await realpath(record.path), record.path)
  ) {
    failAdapter("CLEANUP", "cleanup-incomplete");
  }
  return state;
}

export async function removeEmptyOutputDirectory(record) {
  try {
    await requireDirectoryIdentity(record);
    await rmdir(record.path);
  } catch {
    failAdapter("CLEANUP", "cleanup-incomplete");
  }
}

export async function createOwnedDirectory(parentRecord, basename, ledger) {
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(basename)) {
    failAdapter("OUTPUT_PUBLICATION", "private-directory-name");
  }
  await requireDirectoryIdentity(parentRecord);
  const target = path.join(parentRecord.path, basename);
  if (await pathState(target)) failAdapter("OUTPUT_PUBLICATION", "private-directory-exists");
  await mkdir(target, { mode: 0o700 });
  const state = await lstat(target, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isDirectory()
    || !pathsEqual(await realpath(target), target)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "private-directory-identity");
  }
  const record = Object.freeze({
    kind: "directory",
    path: target,
    identity: identityFromState(state),
  });
  ledger.push(record);
  return record;
}

export async function recordOwnedFile(filePath, ledger) {
  const state = await lstat(filePath, { bigint: true });
  if (
    state.isSymbolicLink()
    || !state.isFile()
    || state.size < 0n
    || state.size > BigInt(Number.MAX_SAFE_INTEGER)
    || !pathsEqual(await realpath(filePath), filePath)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "owned-file-identity");
  }
  const stable = await hashStableRegularFile(
    filePath,
    "FILE_IDENTITY",
    "owned-file",
  );
  const checkedState = await lstat(filePath, { bigint: true });
  if (!identitiesEqual(identityFromState(state), identityFromState(checkedState))) {
    failAdapter("OUTPUT_PUBLICATION", "owned-file-identity");
  }
  const record = Object.freeze({
    kind: "file",
    path: filePath,
    identity: identityFromState(state),
    byteLength: Number(state.size),
    sha256: stable.sha256,
  });
  ledger.push(record);
  return record;
}

export async function writeOwnedFile(parentRecord, basename, bytes, ledger) {
  if (
    typeof basename !== "string"
    || basename.length === 0
    || basename.includes("/")
    || basename.includes("\\")
    || !Buffer.isBuffer(bytes)
  ) {
    failAdapter("OUTPUT_PUBLICATION", "output-file-invalid");
  }
  await requireDirectoryIdentity(parentRecord);
  const target = path.join(parentRecord.path, basename);
  let handle = null;
  let record = null;
  try {
    handle = await open(
      target,
      FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | FS_CONSTANTS.O_WRONLY
        | noFollowFlag(),
      0o600,
    );
    const initial = await handle.stat({ bigint: true });
    record = Object.freeze({
      kind: "file",
      path: target,
      identity: identityFromState(initial),
      byteLength: bytes.length,
      sha256: sha256Bytes(bytes),
    });
    ledger.push(record);
    let offset = 0;
    while (offset < bytes.length) {
      const written = await handle.write(bytes, offset, bytes.length - offset, null);
      if (!written || written.bytesWritten <= 0) {
        failAdapter("OUTPUT_PUBLICATION", "output-file-write");
      }
      offset += written.bytesWritten;
    }
    await handle.sync();
    await handle.close();
    handle = null;
    const actual = await readStableFile(target, {
      phase: "FILE_IDENTITY",
      reason: "output-file",
      kind: "output-file",
      captureBytes: true,
    });
    const state = await lstat(target, { bigint: true });
    if (
      !actual.bytes.equals(bytes)
      || actual.sha256 !== sha256Bytes(bytes)
      || actual.byteLength !== bytes.length
      || !identitiesEqual(record.identity, identityFromState(state))
      || state.nlink !== 1n
      || state.size !== BigInt(bytes.length)
    ) {
      failAdapter("OUTPUT_PUBLICATION", "output-file-verify");
    }
    return record;
  } catch (error) {
    if (handle) {
      try { await handle.close(); } catch { /* cleanup reports the identity failure */ }
    }
    throw asAdapterError(error, "OUTPUT_PUBLICATION", "output-file-write");
  }
}

export async function cleanupOwnedLedger(ledger) {
  let complete = true;
  for (let index = ledger.length - 1; index >= 0; index -= 1) {
    const record = ledger[index];
    try {
      const state = await pathState(record.path);
      if (!state) continue;
      if (
        state.isSymbolicLink()
        || !identitiesEqual(record.identity, identityFromState(state))
        || !pathsEqual(await realpath(record.path), record.path)
      ) {
        complete = false;
        continue;
      }
      if (record.kind === "file") {
        if (!state.isFile() || state.size !== BigInt(record.byteLength)) {
          complete = false;
          continue;
        }
        if (typeof record.sha256 === "string") {
          const stable = await hashStableRegularFile(
            record.path,
            "CLEANUP",
            "cleanup-owned-file",
          );
          const checkedState = await lstat(record.path, { bigint: true });
          if (
            stable.sha256 !== record.sha256
            || stable.byteLength !== record.byteLength
            || !identitiesEqual(
              record.identity,
              identityFromState(checkedState),
            )
          ) {
            complete = false;
            continue;
          }
        }
        await unlink(record.path);
      } else {
        if (!state.isDirectory()) {
          complete = false;
          continue;
        }
        await rmdir(record.path);
      }
      if (await pathState(record.path)) complete = false;
    } catch {
      complete = false;
    }
  }
  if (!complete) failAdapter("CLEANUP", "cleanup-incomplete");
}

export async function runHostCapabilityProbe(privateRoot, ledger) {
  const directory = await createOwnedDirectory(privateRoot, "capability-probe", ledger);
  const sourcePath = path.join(directory.path, "source.bin");
  const linkedPath = path.join(directory.path, "linked.bin");
  const occupiedPath = path.join(directory.path, "occupied.bin");
  let sourceHandle = null;
  let exclusiveCreateSupported = false;
  let hardLinkSupported = false;
  let atomicNoReplaceHardLinkSupported = false;
  let reliableLinkCountSupported = false;
  let stableFileIdentitySupported = false;
  try {
    sourceHandle = await open(sourcePath, "wx", 0o600);
    await sourceHandle.writeFile(Buffer.from("capability-probe\n", "ascii"));
    await sourceHandle.sync();
    await sourceHandle.close();
    sourceHandle = null;
    const sourceRecord = await recordOwnedFile(sourcePath, ledger);
    try {
      const duplicate = await open(sourcePath, "wx", 0o600);
      await duplicate.close();
    } catch (error) {
      exclusiveCreateSupported = Boolean(error && error.code === "EEXIST");
    }
    const before = await lstat(sourcePath, { bigint: true });
    await link(sourcePath, linkedPath);
    const linkedRecord = await recordOwnedFile(linkedPath, ledger);
    hardLinkSupported = true;
    const after = await lstat(sourcePath, { bigint: true });
    reliableLinkCountSupported = before.nlink === 1n && after.nlink === 2n;
    stableFileIdentitySupported = sourceRecord.identity.meaningful
      && identitiesEqual(sourceRecord.identity, identityFromState(after))
      && identitiesEqual(sourceRecord.identity, linkedRecord.identity);
    const occupiedHandle = await open(occupiedPath, "wx", 0o600);
    await occupiedHandle.close();
    await recordOwnedFile(occupiedPath, ledger);
    try {
      await link(sourcePath, occupiedPath);
    } catch (error) {
      atomicNoReplaceHardLinkSupported = Boolean(error && error.code === "EEXIST");
    }
  } catch {
    // False capability values are reported to the platform binding layer.
  } finally {
    if (sourceHandle) {
      try { await sourceHandle.close(); } catch { /* ledger cleanup is authoritative */ }
    }
  }
  return Object.freeze({
    exclusiveCreateSupported,
    hardLinkSupported,
    atomicNoReplaceHardLinkSupported,
    reliableLinkCountSupported,
    stableFileIdentitySupported,
  });
}

export function encodeReceiptVerificationTranscript(
  result,
  { sourceCommit, toolingCommit, artifactCount },
) {
  if (!result || typeof result !== "object") {
    failAdapter("RECEIPT_VERIFICATION", "receipt-verification-result");
  }
  const actualKeys = Object.keys(result);
  if (
    actualKeys.length !== RECEIPT_TRANSCRIPT_KEYS.length
    || actualKeys.some((key, index) => key !== RECEIPT_TRANSCRIPT_KEYS[index])
  ) {
    failAdapter("RECEIPT_VERIFICATION", "receipt-verification-result");
  }
  if (
    result.status !== "ok"
    || result.mode !== "full"
    || result.verificationComplete !== true
    || result.receiptKind !== RECEIPT_KIND
    || result.schemaVersion !== RECEIPT_SCHEMA_VERSION
    || result.sourceCommit !== sourceCommit
    || result.toolingCommit !== toolingCommit
    || result.artifactCount !== artifactCount
    || result.sourceArchiveVerified !== true
    || result.toolingCommitSignatureValid !== true
    || result.artifactsVerified !== true
    || result.correspondingSourceComplete !== false
    || result.publicationBlocked !== true
    || !SHA256_PATTERN.test(result.receiptSha256)
    || !Number.isSafeInteger(result.receiptByteLength)
    || result.receiptByteLength < 0
  ) {
    failAdapter("RECEIPT_VERIFICATION", "receipt-verification-result");
  }
  const ordered = Object.fromEntries(
    RECEIPT_TRANSCRIPT_KEYS.map((key) => [key, result[key]]),
  );
  return canonicalAdapterJsonBytes(ordered, "RECEIPT_VERIFICATION");
}

async function compareFileStreams(leftPath, rightPath, expectedLength) {
  let left = null;
  let right = null;
  try {
    left = await open(leftPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    right = await open(rightPath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
    let offset = 0;
    while (offset < expectedLength) {
      const length = Math.min(FILE_CHUNK_SIZE, expectedLength - offset);
      const leftBytes = Buffer.alloc(length);
      const rightBytes = Buffer.alloc(length);
      const [leftRead, rightRead] = await Promise.all([
        left.read(leftBytes, 0, length, null),
        right.read(rightBytes, 0, length, null),
      ]);
      if (
        leftRead.bytesRead !== length
        || rightRead.bytesRead !== length
        || !leftBytes.equals(rightBytes)
      ) return false;
      offset += length;
    }
    const trailingLeft = await left.read(Buffer.alloc(1), 0, 1, null);
    const trailingRight = await right.read(Buffer.alloc(1), 0, 1, null);
    return trailingLeft.bytesRead === 0 && trailingRight.bytesRead === 0;
  } finally {
    if (left) await left.close();
    if (right) await right.close();
  }
}

function requireIndependentReceipts(left, right, phase) {
  if (
    identitiesEqual(left.file.identity, right.file.identity)
    || left.file.path === right.file.path
    || left.directory.path === right.directory.path
    || left.verification.receiptSha256 !== right.verification.receiptSha256
    || left.verification.receiptByteLength !== right.verification.receiptByteLength
    || !left.transcript.equals(right.transcript)
  ) {
    failAdapter(phase, phase === "SAME_PROCESS"
      ? "same-process-mismatch"
      : "same-host-mismatch");
  }
}

export async function runSameProcessRepetitions({
  repository,
  sourceCommit,
  toolingCommit,
  sourceArchive,
  artifacts,
  privateRoot,
  ledger,
}) {
  const outputs = [];
  for (const label of ["same-process-a", "same-process-b"]) {
    const directory = await createOwnedDirectory(privateRoot, label, ledger);
    const receiptPath = path.join(directory.path, WORKER_RECEIPT_BASENAME);
    try {
      await preparePublicSourceReceipt({
        repo: repository,
        sourceCommit,
        toolingCommit,
        sourceArchive,
        artifacts,
        output: receiptPath,
      });
      const file = await recordOwnedFile(receiptPath, ledger);
      const state = await lstat(receiptPath, { bigint: true });
      if (state.nlink !== 1n || !file.identity.meaningful) {
        failAdapter("SAME_PROCESS", "same-process-mismatch");
      }
      const stableReceipt = await readStableFile(receiptPath, {
        phase: "FILE_IDENTITY",
        reason: "same-process-receipt",
        kind: "same-process-receipt",
        captureBytes: true,
      });
      const verification = await verifyPublicSourceReceipt({
        mode: "full",
        repo: repository,
        receipt: receiptPath,
        sourceArchive,
        artifacts,
      });
      const transcript = encodeReceiptVerificationTranscript(verification, {
        sourceCommit,
        toolingCommit,
        artifactCount: artifacts.length,
      });
      if (
        stableReceipt.sha256 !== verification.receiptSha256
        || stableReceipt.byteLength !== verification.receiptByteLength
      ) failAdapter("SAME_PROCESS", "same-process-mismatch");
      outputs.push(Object.freeze({
        directory,
        file,
        verification,
        transcript,
        receiptBytes: stableReceipt.bytes,
      }));
    } catch (error) {
      throw asAdapterError(error, "SAME_PROCESS", "same-process-mismatch");
    }
  }
  requireIndependentReceipts(outputs[0], outputs[1], "SAME_PROCESS");
  if (!await compareFileStreams(
    outputs[0].file.path,
    outputs[1].file.path,
    outputs[0].verification.receiptByteLength,
  )) failAdapter("SAME_PROCESS", "same-process-mismatch");
  return Object.freeze({
    outputs: Object.freeze(outputs),
    sameProcessRepeatable: true,
    canonicalVerifierPassed: true,
  });
}

function sanitizedWorkerEnvironment(base, temporaryDirectory, locale) {
  const environment = {};
  for (const [key, value] of Object.entries(base)) {
    const upper = key.toUpperCase();
    if (
      upper.startsWith("GIT_")
      || upper === "NODE_OPTIONS"
      || upper === "NODE_PATH"
      || upper.includes("LOADER")
      || upper.includes("PRELOAD")
      || upper === "TEMP"
      || upper === "TMP"
      || upper === "TMPDIR"
      || upper === "LANG"
      || upper === "LC_ALL"
      || upper === "TZ"
      || upper === "SOURCE_DATE_EPOCH"
      || upper === LEGACY_WORKER_TOKEN_ENV
    ) continue;
    environment[key] = value;
  }
  environment.PATH = base.PATH;
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = process.platform === "win32" ? "NUL" : "/dev/null";
  environment.TEMP = temporaryDirectory;
  environment.TMP = temporaryDirectory;
  environment.TMPDIR = temporaryDirectory;
  environment.LANG = locale.lang;
  environment.LC_ALL = locale.lcAll;
  environment.TZ = locale.timezone;
  environment.SOURCE_DATE_EPOCH = locale.sourceDateEpoch;
  delete environment[LEGACY_WORKER_TOKEN_ENV];
  return environment;
}

export async function createTrustedWorkerModuleCapsule({
  privateRoot,
  ledger,
  toolingCommit,
  workerModuleAuthority,
}) {
  if (
    !workerModuleAuthority
    || workerModuleAuthority.toolingCommit !== toolingCommit
    || workerModuleAuthority.entryModule !== WORKER_ENTRY_MODULE
    || !Array.isArray(workerModuleAuthority.moduleOrder)
    || !Array.isArray(workerModuleAuthority.modules)
    || workerModuleAuthority.moduleOrder.length !== CRITICAL_TOOL_PATHS.length
    || workerModuleAuthority.modules.length !== CRITICAL_TOOL_PATHS.length
    || workerModuleAuthority.moduleSetSha256
      !== moduleSetSha256(workerModuleAuthority.modules)
  ) failAdapter("TOOL_SET", "worker-module-capsule-invalid");
  const capsuleDirectory = await createOwnedDirectory(
    privateRoot,
    WORKER_CAPSULE_DIRECTORY,
    ledger,
  );
  const capsule = {
    capsuleKind: WORKER_CAPSULE_KIND,
    schemaVersion: 1,
    toolingCommit,
    entryModule: workerModuleAuthority.entryModule,
    moduleOrder: workerModuleAuthority.moduleOrder,
    modules: workerModuleAuthority.modules,
    moduleSetSha256: workerModuleAuthority.moduleSetSha256,
  };
  const capsuleBytes = privateJsonBytes(capsule, "worker-module-capsule-invalid");
  if (capsuleBytes.length > MAX_WORKER_CAPSULE_BYTES) {
    failAdapter("TOOL_SET", "worker-module-capsule-invalid");
  }
  const capsuleRecord = await writeOwnedFile(
    capsuleDirectory,
    WORKER_CAPSULE_BASENAME,
    capsuleBytes,
    ledger,
  );
  const capsulePath = path.join(
    capsuleDirectory.path,
    WORKER_CAPSULE_BASENAME,
  );
  const stable = await readStablePrivateFile(
    capsulePath,
    MAX_WORKER_CAPSULE_BYTES,
    "worker-module-capsule-invalid",
  );
  const directory = await inspectExactPrivateDirectory(
    capsuleDirectory.path,
    "worker-module-capsule-invalid",
  );
  const capsuleSha256 = sha256Bytes(capsuleBytes);
  if (
    !stable.bytes.equals(capsuleBytes)
    || !identitiesEqual(stable.identity, capsuleRecord.identity)
    || !identitiesEqual(directory.identity, capsuleDirectory.identity)
    || stable.nlink !== 1n
    || !stable.identity.meaningful
    || !directory.identity.meaningful
  ) failAdapter("TOOL_SET", "worker-module-capsule-invalid");
  return Object.freeze({
    path: capsulePath,
    pathSha256: privatePathSha256(capsulePath),
    sha256: capsuleSha256,
    moduleSetSha256: workerModuleAuthority.moduleSetSha256,
    entryModuleSha256: workerModuleAuthority.entryModuleSha256,
    fileIdentity: capsuleRecord.identity,
    parentIdentity: directory.identity,
    record: capsuleRecord,
    directory: capsuleDirectory,
  });
}

async function requireCoordinatorCapsuleState(capsule) {
  try {
    const [stable, directory] = await Promise.all([
      readStablePrivateFile(
        capsule.path,
        MAX_WORKER_CAPSULE_BYTES,
        "worker-module-capsule-invalid",
      ),
      inspectExactPrivateDirectory(
        capsule.directory.path,
        "worker-module-capsule-invalid",
      ),
    ]);
    if (
      stable.sha256 !== capsule.sha256
      || stable.nlink !== 1n
      || !identitiesEqual(stable.identity, capsule.fileIdentity)
      || !identitiesEqual(directory.identity, capsule.parentIdentity)
      || capsule.pathSha256 !== privatePathSha256(capsule.path)
    ) throw new Error();
  } catch {
    failAdapter("TOOL_SET", "worker-loaded-bytes-mismatch");
  }
}

function validateWorkerResponseText(text, expected) {
  const value = parseExactPrivateJsonText(
    text,
    MAX_WORKER_RESPONSE_BYTES,
    "private-worker-response-invalid",
  );
  exactKeys(
    value,
    WORKER_RESPONSE_KEYS,
    "SAME_HOST",
    "private-worker-response-invalid",
  );
  if (
    value.protocol !== WORKER_PROTOCOL
    || value.runId !== expected.runId
    || value.assignmentId !== expected.assignmentId
    || value.contextDigest !== expected.contextDigest
    || value.status !== "ok"
    || !SHA256_PATTERN.test(value.receiptSha256)
    || !Number.isSafeInteger(value.receiptByteLength)
    || value.receiptByteLength < 0
    || typeof value.receiptVerificationTranscript !== "string"
    || value.workerPid !== expected.workerPid
    || value.workerRequestListenerCount !== 0
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  if (
    value.workerCapsuleSha256 !== expected.workerCapsuleSha256
    || value.workerModuleSetSha256 !== expected.workerModuleSetSha256
    || value.workerEntryModuleSha256 !== expected.workerEntryModuleSha256
  ) failAdapter("TOOL_SET", "worker-loaded-bytes-mismatch");
  requirePrivateIdentityStrings(
    value.assignedDirectoryIdentity,
    "private-worker-response-invalid",
  );
  requirePrivateIdentityStrings(
    value.receiptFileIdentity,
    "private-worker-response-invalid",
  );
  if (!identityMatchesStrings(
    expected.directoryIdentity,
    value.assignedDirectoryIdentity,
  )) failAdapter("SAME_HOST", "private-worker-response-invalid");
  let transcript;
  try {
    transcript = Buffer.from(value.receiptVerificationTranscript, "base64");
    if (
      transcript.toString("base64") !== value.receiptVerificationTranscript
      || transcript.length <= 1
      || transcript.length > MAX_WORKER_RESPONSE_BYTES
      || transcript.at(-1) !== 0x0a
      || transcript.subarray(0, -1).includes(0x0a)
      || transcript.includes(0x0d)
    ) throw new Error();
  } catch {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  return Object.freeze({ ...value, transcript });
}

export async function spawnTrustedWorkerRaw({
  requestMessages,
  environment,
  workingDirectory,
  capsule,
  timeoutMilliseconds = 120000,
  beforeSpawn = null,
  afterSpawn = null,
}) {
  if (
    !Array.isArray(requestMessages)
    || requestMessages.length < 1
    || requestMessages.some((message) => typeof message !== "string")
    || !Number.isSafeInteger(timeoutMilliseconds)
    || timeoutMilliseconds < 1
    || (beforeSpawn !== null && typeof beforeSpawn !== "function")
    || (afterSpawn !== null && typeof afterSpawn !== "function")
  ) failAdapter("SAME_HOST", "private-worker-request-invalid");
  await requireCoordinatorCapsuleState(capsule);
  if (beforeSpawn !== null) {
    const returned = await beforeSpawn();
    if (returned !== undefined) {
      failAdapter("SAME_HOST", "private-worker-request-invalid");
    }
  }
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      "--input-type=module",
      "--eval",
      WORKER_BOOTSTRAP_SOURCE,
      "--",
      capsule.path,
      capsule.sha256,
      String(capsule.fileIdentity.device),
      String(capsule.fileIdentity.inode),
      String(capsule.parentIdentity.device),
      String(capsule.parentIdentity.inode),
      capsule.pathSha256,
    ], {
      cwd: workingDirectory,
      env: environment,
      serialization: "json",
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    const responses = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stdioOverflow = false;
    let timeout = false;
    let forcedTermination = false;
    let spawnError = false;
    let settled = false;
    const terminate = () => {
      if (forcedTermination) return;
      forcedTermination = true;
      try { child.kill(); } catch { /* close observation remains authoritative */ }
    };
    const capture = (collection, chunk, isStdout) => {
      const bytes = Buffer.from(chunk);
      if (isStdout) stdoutBytes += bytes.length;
      else stderrBytes += bytes.length;
      if (stdoutBytes > MAX_WORKER_STDIO_BYTES
        || stderrBytes > MAX_WORKER_STDIO_BYTES) {
        stdioOverflow = true;
        terminate();
        return;
      }
      collection.push(bytes);
    };
    child.stdout.on("data", (chunk) => capture(stdout, chunk, true));
    child.stderr.on("data", (chunk) => capture(stderr, chunk, false));
    child.on("message", (message) => responses.push(message));
    child.on("error", () => {
      spawnError = true;
    });
    const timer = setTimeout(() => {
      timeout = true;
      terminate();
    }, timeoutMilliseconds);
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(Object.freeze({
        pid: child.pid,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        responses: Object.freeze([...responses]),
        code,
        signal,
        timeout,
        forcedTermination,
        stdioOverflow,
        spawnError,
      }));
    });
    if (
      !Number.isSafeInteger(child.pid)
      || child.pid <= 0
      || !child.connected
    ) {
      spawnError = true;
      terminate();
      return;
    }
    let sendFailed = false;
    for (const message of requestMessages) {
      child.send(message, (error) => {
        if (error && !settled) {
          sendFailed = true;
          terminate();
        }
      });
    }
    if (afterSpawn !== null) {
      Promise.resolve(afterSpawn(Object.freeze({
        pid: child.pid,
        send(message) {
          if (typeof message !== "string" || settled || sendFailed) return false;
          try { return child.send(message); } catch { return false; }
        },
      }))).catch(() => terminate());
    }
  });
}

async function forkOneWorker({
  requestText,
  environment,
  workingDirectory,
  expected,
  capsule,
  additionalMessages = [],
  afterSpawn = null,
}) {
  const observation = await spawnTrustedWorkerRaw({
    requestMessages: [requestText, ...additionalMessages],
    environment,
    workingDirectory,
    capsule,
    afterSpawn,
  });
  if (
    observation.code === 1
    && observation.signal === null
    && observation.timeout === false
    && observation.forcedTermination === false
    && observation.stdout.length === 0
    && observation.stderr.equals(Buffer.from(
      "ERROR TOOL_SET: worker-loaded-bytes-mismatch\n",
      "ascii",
    ))
    && observation.responses.length === 0
  ) failAdapter("TOOL_SET", "worker-loaded-bytes-mismatch");
  if (
    observation.spawnError
    || observation.timeout
    || observation.forcedTermination
    || observation.stdioOverflow
    || observation.stdout.length !== 0
    || observation.stderr.length !== 0
    || observation.code !== 0
    || observation.signal !== null
    || observation.responses.length !== 1
  ) failAdapter("SAME_HOST", "private-worker-unavailable");
  return validateWorkerResponseText(observation.responses[0], {
    ...expected,
    workerPid: observation.pid,
    workerCapsuleSha256: capsule.sha256,
    workerModuleSetSha256: capsule.moduleSetSha256,
    workerEntryModuleSha256: capsule.entryModuleSha256,
  });
}

function coordinatorBootstrapSha256() {
  return sha256Bytes(Buffer.from(WORKER_BOOTSTRAP_SOURCE, "utf8"));
}

async function buildLockedWorkerContext({
  repository,
  sourceCommit,
  toolingCommit,
  policySha256,
  matrixCellId,
  criticalToolSetSha256,
  runtimeIdentitySha256,
  gitIdentitySha256,
  platformProbeSha256,
  testVectorSetSha256,
  manifestSha256,
  membershipReportSha256,
  inputSetSha256,
  sourceArchiveSha256,
  sourceArchiveByteLength,
  artifactIdentities,
  git,
  capsule,
}) {
  const repositoryDirectory = await inspectExactPrivateDirectory(
    repository,
    "private-worker-context-invalid",
  );
  const value = {
    repository: repositoryBinding(repositoryDirectory),
    sourceCommit,
    toolingCommit,
    policySha256,
    matrixCellId,
    criticalToolSetSha256,
    runtimeIdentitySha256,
    gitIdentitySha256,
    platformProbeSha256,
    testVectorSetSha256,
    manifestSha256,
    membershipReportSha256,
    inputSetSha256,
    sourceArchiveSha256,
    sourceArchiveByteLength,
    artifacts: artifactIdentities,
    artifactRole: ARTIFACT_ROLE,
    formatProfile: FORMAT_PROFILE,
    gitExecutableSha256: git.sha256,
    gitExecutableByteLength: git.byteLength,
    workerCapsuleSha256: capsule.sha256,
    workerModuleSetSha256: capsule.moduleSetSha256,
    workerEntryModuleSha256: capsule.entryModuleSha256,
  };
  validateLockedWorkerContext(value);
  return Object.freeze({
    value: deepFreezeAdapter(value),
    digest: lockedContextSha256(value),
    repositoryDirectory,
  });
}

function assignmentLeaseValue(directory, assignmentId, nonce, contextDigest) {
  return deepFreezeAdapter({
    assignmentId,
    assignmentNonce: nonce,
    directoryPathSha256: privatePathSha256(directory.path),
    directoryParentIdentity: identityStrings(directory.parentIdentity),
    directoryIdentity: identityStrings(directory.identity),
    receiptFilename: WORKER_RECEIPT_BASENAME,
    lockedContextDigest: contextDigest,
    state: "unused",
  });
}

async function createCoordinatorWorkerLease({
  privateRoot,
  ledger,
  context,
}) {
  // The worker accepts only a one-time coordinator lease for an already
  // created, identity-bound private root and assignment. It cannot select or
  // write a receipt outside that assignment. This is a local capability and
  // does not claim cryptographic authentication of every process on the host.
  const workerRoot = await createOwnedDirectory(
    privateRoot,
    "same-host-workers",
    ledger,
  );
  const root = await inspectExactPrivateDirectory(
    workerRoot.path,
    "private-worker-root-mismatch",
  );
  if (!identitiesEqual(root.identity, workerRoot.identity)) {
    failAdapter("SAME_HOST", "private-worker-root-mismatch");
  }
  if (
    pathsEqual(root.path, context.repositoryDirectory.path)
    || isInside(context.repositoryDirectory.path, root.path)
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const directories = [];
  for (const assignmentId of ["worker-a", "worker-b"]) {
    const record = await createOwnedDirectory(workerRoot, assignmentId, ledger);
    const inspected = await inspectExactPrivateDirectory(
      record.path,
      "private-worker-assignment-mismatch",
    );
    if (
      !identitiesEqual(record.identity, inspected.identity)
      || !identitiesEqual(root.identity, inspected.parentIdentity)
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    directories.push(Object.freeze({ record, inspected }));
  }
  const runId = randomBytes(32).toString("hex");
  const assignments = directories.map((directory, index) => {
    const assignmentId = index === 0 ? "worker-a" : "worker-b";
    const nonce = randomBytes(32).toString("hex");
    return Object.freeze({
      record: directory.record,
      inspected: directory.inspected,
      value: assignmentLeaseValue(
        directory.inspected,
        assignmentId,
        nonce,
        context.digest,
      ),
    });
  });
  const lease = deepFreezeAdapter({
    protocol: WORKER_LEASE_PROTOCOL,
    schemaVersion: 1,
    runId,
    coordinatorPid: process.pid,
    coordinatorBootstrapSha256: coordinatorBootstrapSha256(),
    privateRootPathSha256: root.pathSha256,
    privateRootIdentity: identityStrings(root.identity),
    privateRootParentIdentity: identityStrings(root.parentIdentity),
    lockedContext: context.value,
    lockedContextDigest: context.digest,
    assignments: assignments.map((entry) => entry.value),
  });
  const leaseBytes = privateJsonBytes(lease, "private-worker-lease-invalid");
  if (leaseBytes.length > MAX_WORKER_LEASE_BYTES) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const leaseRecord = await writeOwnedFile(
    workerRoot,
    WORKER_LEASE_BASENAME,
    leaseBytes,
    ledger,
  );
  const leasePath = path.join(workerRoot.path, WORKER_LEASE_BASENAME);
  const stableLease = await readStablePrivateFile(
    leasePath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  if (
    !stableLease.bytes.equals(leaseBytes)
    || !identitiesEqual(stableLease.identity, leaseRecord.identity)
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  return Object.freeze({
    workerRoot,
    root,
    lease,
    leaseBytes,
    leasePath,
    leaseRecord,
    assignments: Object.freeze(assignments),
  });
}

function claimBytesFor(lease, assignment) {
  return privateJsonBytes({
    protocol: WORKER_CLAIM_PROTOCOL,
    runId: lease.runId,
    assignmentId: assignment.assignmentId,
    assignmentNonceSha256: assignmentNonceSha256(assignment.assignmentNonce),
    contextDigest: lease.lockedContextDigest,
    state: "claimed",
  }, "private-worker-assignment-mismatch");
}

async function requireCoordinatorLeaseState(leaseState) {
  const root = await inspectExactPrivateDirectory(
    leaseState.workerRoot.path,
    "private-worker-root-mismatch",
  );
  if (
    !identitiesEqual(root.identity, leaseState.root.identity)
    || !identitiesEqual(root.parentIdentity, leaseState.root.parentIdentity)
    || root.pathSha256 !== leaseState.lease.privateRootPathSha256
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const stableLease = await readStablePrivateFile(
    leaseState.leasePath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  if (
    !stableLease.bytes.equals(leaseState.leaseBytes)
    || !identitiesEqual(stableLease.identity, leaseState.leaseRecord.identity)
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  const rootEntries = await readdir(root.path);
  const expectedRootEntries = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== expectedRootEntries.size
    || rootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  for (const assignment of leaseState.assignments) {
    const directory = await inspectExactPrivateDirectory(
      assignment.record.path,
      "private-worker-assignment-mismatch",
    );
    if (
      !identityMatchesStrings(directory.identity, assignment.value.directoryIdentity)
      || !identityMatchesStrings(
        directory.parentIdentity,
        assignment.value.directoryParentIdentity,
      )
      || directory.pathSha256 !== assignment.value.directoryPathSha256
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
}

async function adoptWorkerOutput(leaseState, assignment, response, ledger) {
  await requireCoordinatorLeaseState(leaseState);
  const directory = await inspectExactPrivateDirectory(
    assignment.record.path,
    "private-worker-assignment-mismatch",
  );
  if (
    !identityMatchesStrings(directory.identity, response.assignedDirectoryIdentity)
    || !identityMatchesStrings(directory.identity, assignment.value.directoryIdentity)
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  const entries = await readdir(directory.path);
  const expectedEntries = new Set([
    WORKER_CLAIM_BASENAME,
    WORKER_RECEIPT_BASENAME,
  ]);
  if (
    entries.length !== expectedEntries.size
    || entries.some((entry) => !expectedEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-output-escape");
  const claimPath = path.join(directory.path, WORKER_CLAIM_BASENAME);
  const claim = await readStablePrivateFile(
    claimPath,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-assignment-mismatch",
  );
  const expectedClaim = claimBytesFor(leaseState.lease, assignment.value);
  if (!claim.bytes.equals(expectedClaim)) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  const claimRecord = await recordOwnedFile(claimPath, []);
  if (!identitiesEqual(claim.identity, claimRecord.identity)) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  ledger.push(claimRecord);
  const file = await recordOwnedFile(
    path.join(directory.path, WORKER_RECEIPT_BASENAME),
    [],
  );
  if (!identityMatchesStrings(file.identity, response.receiptFileIdentity)) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  const state = await lstat(file.path, { bigint: true });
  if (state.nlink !== 1n || file.byteLength !== response.receiptByteLength) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  const hashed = await hashStableRegularFile(
    file.path,
    "SAME_HOST",
    "private-worker-response-invalid",
  );
  if (
    hashed.sha256 !== response.receiptSha256
    || hashed.byteLength !== response.receiptByteLength
  ) failAdapter("SAME_HOST", "private-worker-response-invalid");
  ledger.push(file);
  return Object.freeze({ directory: assignment.record, file });
}

function requireInvalidWorkerObservation(observation) {
  if (
    observation.spawnError
    || observation.timeout
    || observation.forcedTermination
    || observation.stdioOverflow
    || observation.stdout.length !== 0
    || observation.code !== 1
    || observation.signal !== null
    || observation.responses.length !== 0
    || !/^ERROR [A-Z_]+: [a-z0-9]+(?:-[a-z0-9]+)*\n$/u.test(
      observation.stderr.toString("utf8"),
    )
  ) failAdapter("SAME_HOST", "private-worker-protocol-audit");
}

async function runInvalidFirstProtocolAudit({
  leaseState,
  requestFor,
  capsule,
  environment,
}) {
  const validA = JSON.parse(requestFor(leaseState.assignments[0]));
  const validB = JSON.parse(requestFor(leaseState.assignments[1]));
  const hostile = privateJsonBytes({
    protocol: WORKER_PROTOCOL,
    outputDirectory: path.join(leaseState.assignments[0].record.path, "hostile"),
  }, "private-worker-request-invalid").toString("utf8");
  const encoded = (mutate) => {
    const value = JSON.parse(JSON.stringify(validA));
    mutate(value);
    return JSON.stringify(value) + "\n";
  };
  const cases = [
    ["legacy-arbitrary-parent", [JSON.stringify({ parent: process.pid }) + "\n"]],
    ["invalid-first-only", ["{}\n"]],
    ["invalid-first-valid-second", ["{}\n", requestFor(leaseState.assignments[0])]],
    ["invalid-first-hostile-second", ["{}\n", hostile]],
    ["missing-required-field", [encoded((value) => { delete value.lockedContext; })]],
    ["extra-output-directory", [encoded((value) => { value.outputDirectory = path.join(leaseState.root.path, "hostile-output"); })]],
    ["extra-receipt-path", [encoded((value) => { value.receiptPath = path.join(leaseState.root.path, "hostile-receipt"); })]],
    ["invalid-lease", [encoded((value) => { value.leaseReference = path.join(leaseState.root.path, "missing-lease.json"); })]],
    ["invalid-assignment", [encoded((value) => { value.assignmentId = "worker-z"; })]],
    ["invalid-nonce", [encoded((value) => { value.assignmentNonce = "0".repeat(64); })]],
    ["invalid-context", [encoded((value) => { value.lockedContext.policySha256 = "0".repeat(64); })]],
    ["assignment-swap", [encoded((value) => {
      value.assignmentId = validB.assignmentId;
      value.assignmentNonce = validB.assignmentNonce;
    })]],
    ["nonce-swap", [encoded((value) => { value.assignmentNonce = validB.assignmentNonce; })]],
    ["context-swap", [encoded((value) => { value.lockedContext.inputSetSha256 = "f".repeat(64); })]],
  ];
  for (const [, messages] of cases) {
    const entriesBefore = await readdir(leaseState.assignments[0].record.path);
    if (entriesBefore.length !== 0) {
      failAdapter("SAME_HOST", "private-worker-protocol-audit");
    }
    const observation = await spawnTrustedWorkerRaw({
      requestMessages: messages,
      environment,
      workingDirectory: leaseState.assignments[0].record.path,
      capsule,
      timeoutMilliseconds: 30000,
    });
    requireInvalidWorkerObservation(observation);
    const entriesAfter = await readdir(leaseState.assignments[0].record.path);
    if (entriesAfter.length !== 0) {
      failAdapter("SAME_HOST", "private-worker-protocol-audit");
    }
  }
  return Object.freeze({
    count: cases.length,
    names: Object.freeze(cases.map(([name]) => name)),
  });
}

async function sendHostileAfterClaim(claimPath, control, hostileMessage) {
  for (let attempt = 0; attempt < 1200; attempt += 1) {
    if (await pathState(claimPath)) {
      if (!control.send(hostileMessage)) {
        failAdapter("SAME_HOST", "private-worker-protocol-audit");
      }
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  failAdapter("SAME_HOST", "private-worker-protocol-audit");
}

export async function runSameHostRepetitions({
  repository,
  sourceCommit,
  toolingCommit,
  sourceArchive,
  artifacts,
  policySha256,
  matrixCellId,
  criticalToolSetSha256,
  runtimeIdentitySha256,
  gitIdentitySha256,
  platformProbeSha256,
  testVectorSetSha256,
  manifestSha256,
  membershipReportSha256,
  inputSetSha256,
  sourceArchiveSha256,
  sourceArchiveByteLength,
  artifactIdentities,
  privateRoot,
  ledger,
  git,
  sameProcess,
  workerModuleAuthority,
  workerCapsule = null,
  workerHooks = null,
}) {
  if (
    workerHooks !== null
    && (
      typeof workerHooks !== "object"
      || Array.isArray(workerHooks)
      || Object.keys(workerHooks).some((key) => ![
        "afterCapsuleLocked",
        "afterWorkersCompleted",
        "protocolAudit",
        "onProtocolAudit",
      ].includes(key))
      || (Object.hasOwn(workerHooks, "afterCapsuleLocked")
        && typeof workerHooks.afterCapsuleLocked !== "function")
      || (Object.hasOwn(workerHooks, "afterWorkersCompleted")
        && typeof workerHooks.afterWorkersCompleted !== "function")
      || (Object.hasOwn(workerHooks, "protocolAudit")
        && typeof workerHooks.protocolAudit !== "boolean")
      || (Object.hasOwn(workerHooks, "onProtocolAudit")
        && typeof workerHooks.onProtocolAudit !== "function")
    )
  ) failAdapter("CLI", "worker-test-hooks-invalid");
  const capsule = workerCapsule ?? await createTrustedWorkerModuleCapsule({
    privateRoot,
    ledger,
    toolingCommit,
    workerModuleAuthority,
  });
  if (
    capsule.moduleSetSha256 !== workerModuleAuthority.moduleSetSha256
    || capsule.entryModuleSha256 !== workerModuleAuthority.entryModuleSha256
  ) failAdapter("TOOL_SET", "worker-loaded-bytes-mismatch");
  if (workerHooks?.afterCapsuleLocked) {
    const returned = await workerHooks.afterCapsuleLocked(Object.freeze({
      capsuleSha256: capsule.sha256,
      moduleSetSha256: capsule.moduleSetSha256,
      entryModuleSha256: capsule.entryModuleSha256,
    }));
    if (returned !== undefined) failAdapter("CLI", "worker-test-hooks-invalid");
  }
  await requireCoordinatorCapsuleState(capsule);
  const context = await buildLockedWorkerContext({
    repository,
    sourceCommit,
    toolingCommit,
    policySha256,
    matrixCellId,
    criticalToolSetSha256,
    runtimeIdentitySha256,
    gitIdentitySha256,
    platformProbeSha256,
    testVectorSetSha256,
    manifestSha256,
    membershipReportSha256,
    inputSetSha256,
    sourceArchiveSha256,
    sourceArchiveByteLength,
    artifactIdentities,
    git,
    capsule,
  });
  const leaseState = await createCoordinatorWorkerLease({
    privateRoot,
    ledger,
    context,
  });
  const requestForLease = (state, assignment) => privateJsonBytes({
    protocol: WORKER_PROTOCOL,
    leaseReference: state.leasePath,
    assignmentId: assignment.value.assignmentId,
    assignmentNonce: assignment.value.assignmentNonce,
    repositoryPath: repository,
    sourceArchivePath: sourceArchive,
    artifacts,
    lockedContext: context.value,
  }, "private-worker-request-invalid").toString("utf8");
  const requestFor = (assignment) => requestForLease(leaseState, assignment);
  const localeA = {
    lang: "C",
    lcAll: "C",
    timezone: "UTC",
    sourceDateEpoch: "0",
  };
  const localeB = {
    lang: "tr_TR.UTF-8",
    lcAll: "tr_TR.UTF-8",
    timezone: "Pacific/Kiritimati",
    sourceDateEpoch: "4102444800",
  };
  const environmentA = sanitizedWorkerEnvironment(
    process.env,
    leaseState.assignments[0].record.path,
    localeA,
  );
  const environmentB = sanitizedWorkerEnvironment(
    process.env,
    leaseState.assignments[1].record.path,
    localeB,
  );
  let invalidProtocolAudit = Object.freeze({ count: 0, names: Object.freeze([]) });
  let validOnlyProtocolAudit = null;
  const hostileSecondMessage = privateJsonBytes({
    protocol: WORKER_PROTOCOL,
    outputDirectory: path.join(leaseState.root.path, "hostile-second-output"),
  }, "private-worker-request-invalid").toString("utf8");
  let responses;
  try {
    await requireCoordinatorLeaseState(leaseState);
    if (workerHooks?.protocolAudit) {
      invalidProtocolAudit = await runInvalidFirstProtocolAudit({
        leaseState,
        requestFor,
        capsule,
        environment: environmentA,
      });
      await requireCoordinatorLeaseState(leaseState);
      const auditParent = await createOwnedDirectory(
        privateRoot,
        "direct-protocol-audit",
        ledger,
      );
      const auditLease = await createCoordinatorWorkerLease({
        privateRoot: auditParent,
        ledger,
        context,
      });
      const auditAssignment = auditLease.assignments[0];
      const auditEnvironment = sanitizedWorkerEnvironment(
        process.env,
        auditAssignment.record.path,
        localeA,
      );
      const auditResponse = await forkOneWorker({
        requestText: requestForLease(auditLease, auditAssignment),
        environment: auditEnvironment,
        workingDirectory: auditAssignment.record.path,
        expected: {
          runId: auditLease.lease.runId,
          assignmentId: "worker-a",
          contextDigest: context.digest,
          directoryIdentity: auditAssignment.record.identity,
        },
        capsule,
      });
      await adoptWorkerOutput(
        auditLease,
        auditAssignment,
        auditResponse,
        ledger,
      );
      const entriesBeforeReplay = (await readdir(
        auditAssignment.record.path,
      )).sort();
      const beforeReplayHashes = await Promise.all(
        entriesBeforeReplay.map((name) => hashStableRegularFile(
          path.join(auditAssignment.record.path, name),
          "SAME_HOST",
          "private-worker-protocol-audit",
        )),
      );
      const replayObservation = await spawnTrustedWorkerRaw({
        requestMessages: [requestForLease(auditLease, auditAssignment)],
        environment: auditEnvironment,
        workingDirectory: auditAssignment.record.path,
        capsule,
        timeoutMilliseconds: 30000,
      });
      requireInvalidWorkerObservation(replayObservation);
      const entriesAfterReplay = (await readdir(
        auditAssignment.record.path,
      )).sort();
      const afterReplayHashes = await Promise.all(
        entriesAfterReplay.map((name) => hashStableRegularFile(
          path.join(auditAssignment.record.path, name),
          "SAME_HOST",
          "private-worker-protocol-audit",
        )),
      );
      if (
        entriesBeforeReplay.length !== 2
        || entriesBeforeReplay.some(
          (name, index) => name !== entriesAfterReplay[index],
        )
        || beforeReplayHashes.some((identity, index) => (
          identity.sha256 !== afterReplayHashes[index]?.sha256
          || identity.byteLength !== afterReplayHashes[index]?.byteLength
        ))
        || auditResponse.workerRequestListenerCount !== 0
      ) failAdapter("SAME_HOST", "private-worker-protocol-audit");
      validOnlyProtocolAudit = Object.freeze({
        validFirstOnlyPassed: true,
        assignmentReplayPassed: true,
        parentIpcOpenExitPassed: true,
        loadedByteAuthorityPassed: true,
        legitimateStdioPassed: true,
        naturalExitPassed: true,
      });
    }
    const settled = await Promise.allSettled([
      forkOneWorker({
        requestText: requestFor(leaseState.assignments[0]),
        environment: environmentA,
        workingDirectory: leaseState.assignments[0].record.path,
        expected: {
          runId: leaseState.lease.runId,
          assignmentId: "worker-a",
          contextDigest: context.digest,
          directoryIdentity: leaseState.assignments[0].record.identity,
        },
        capsule,
        additionalMessages: workerHooks?.protocolAudit
          ? [hostileSecondMessage]
          : [],
      }),
      forkOneWorker({
        requestText: requestFor(leaseState.assignments[1]),
        environment: environmentB,
        workingDirectory: leaseState.assignments[1].record.path,
        expected: {
          runId: leaseState.lease.runId,
          assignmentId: "worker-b",
          contextDigest: context.digest,
          directoryIdentity: leaseState.assignments[1].record.identity,
        },
        capsule,
        afterSpawn: workerHooks?.protocolAudit
          ? (control) => sendHostileAfterClaim(
            path.join(
              leaseState.assignments[1].record.path,
              WORKER_CLAIM_BASENAME,
            ),
            control,
            hostileSecondMessage,
          )
          : null,
      }),
    ]);
    if (workerHooks?.afterWorkersCompleted) {
      const returned = await workerHooks.afterWorkersCompleted(Object.freeze({
        fulfilledCount: settled.filter(
          (entry) => entry.status === "fulfilled",
        ).length,
      }));
      if (returned !== undefined) failAdapter("CLI", "worker-test-hooks-invalid");
    }
    for (let index = 0; index < settled.length; index += 1) {
      if (settled[index].status === "fulfilled") {
        await adoptWorkerOutput(
          leaseState,
          leaseState.assignments[index],
          settled[index].value,
          ledger,
        );
      }
    }
    if (settled.some((entry) => entry.status !== "fulfilled")) {
      const rejected = settled.find((entry) => entry.status === "rejected");
      throw asAdapterError(
        rejected?.reason,
        "SAME_HOST",
        "private-worker-unavailable",
      );
    }
    responses = settled.map((entry) => entry.value);
    if (workerHooks?.protocolAudit) {
      if (
        responses.some((response) => response.workerRequestListenerCount !== 0)
        || responses.length !== 2
      ) failAdapter("SAME_HOST", "private-worker-protocol-audit");
      if (workerHooks.onProtocolAudit) {
        const returned = await workerHooks.onProtocolAudit(Object.freeze({
          invalidFirstCases: invalidProtocolAudit.count,
          invalidFirstCaseNames: invalidProtocolAudit.names,
          validFirstOnlyPassed: validOnlyProtocolAudit?.validFirstOnlyPassed === true,
          assignmentReplayPassed: validOnlyProtocolAudit?.assignmentReplayPassed === true,
          parentIpcOpenExitPassed: validOnlyProtocolAudit?.parentIpcOpenExitPassed === true,
          loadedByteAuthorityPassed: validOnlyProtocolAudit?.loadedByteAuthorityPassed === true,
          legitimateStdioPassed: validOnlyProtocolAudit?.legitimateStdioPassed === true,
          naturalExitPassed: validOnlyProtocolAudit?.naturalExitPassed === true,
          immediateHostileSecondPassed: true,
          postClaimHostileSecondPassed: true,
          legitimateWorkers: responses.length,
          requestListenerCount: 0,
        }));
        if (returned !== undefined) {
          failAdapter("CLI", "worker-test-hooks-invalid");
        }
      }
    }
  } catch (error) {
    throw asAdapterError(error, "SAME_HOST", "private-worker-unavailable");
  }
  const outputs = responses.map((response, index) => Object.freeze({
    directory: leaseState.assignments[index].record,
    file: Object.freeze({
      kind: "file",
      path: path.join(
        leaseState.assignments[index].record.path,
        WORKER_RECEIPT_BASENAME,
      ),
      identity: Object.freeze({
        device: BigInt(response.receiptFileIdentity.device),
        inode: BigInt(response.receiptFileIdentity.inode),
        meaningful: true,
      }),
      byteLength: response.receiptByteLength,
    }),
    verification: Object.freeze({
      receiptSha256: response.receiptSha256,
      receiptByteLength: response.receiptByteLength,
    }),
    transcript: response.transcript,
    pid: response.workerPid,
  }));
  requireIndependentReceipts(outputs[0], outputs[1], "SAME_HOST");
  if (
    outputs[0].pid === outputs[1].pid
    || outputs[0].pid === process.pid
    || outputs[1].pid === process.pid
    || identitiesEqual(outputs[0].directory.identity, outputs[1].directory.identity)
    || !await compareFileStreams(
      outputs[0].file.path,
      outputs[1].file.path,
      outputs[0].verification.receiptByteLength,
    )
  ) failAdapter("SAME_HOST", "same-host-mismatch");
  for (const output of outputs) {
    for (const processOutput of sameProcess.outputs) {
      if (
        identitiesEqual(output.file.identity, processOutput.file.identity)
        || output.verification.receiptSha256 !== processOutput.verification.receiptSha256
        || output.verification.receiptByteLength
          !== processOutput.verification.receiptByteLength
        || !output.transcript.equals(processOutput.transcript)
        || !await compareFileStreams(
          output.file.path,
          processOutput.file.path,
          output.verification.receiptByteLength,
        )
      ) failAdapter("SAME_HOST", "same-host-mismatch");
    }
  }
  return Object.freeze({
    outputs: Object.freeze(outputs),
    sameHostRepeatable: true,
  });
}

export async function publishReceiptNoReplace(
  outputDirectory,
  candidate,
  outputLedger,
) {
  const target = path.join(outputDirectory.path, WORKER_RECEIPT_BASENAME);
  await requireDirectoryIdentity(outputDirectory);
  if (await pathState(target)) failAdapter("OUTPUT_PUBLICATION", "receipt-exists");
  const sourceState = await lstat(candidate.file.path, { bigint: true });
  if (
    sourceState.nlink !== 1n
    || !identitiesEqual(candidate.file.identity, identityFromState(sourceState))
  ) failAdapter("OUTPUT_PUBLICATION", "receipt-source-identity");
  try {
    await link(candidate.file.path, target);
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "receipt-link-failed");
  }
  const targetState = await lstat(target, { bigint: true });
  if (
    !targetState.isFile()
    || targetState.isSymbolicLink()
    || targetState.nlink !== 2n
    || targetState.size !== BigInt(candidate.file.byteLength)
    || !identitiesEqual(candidate.file.identity, identityFromState(targetState))
  ) failAdapter("OUTPUT_PUBLICATION", "receipt-link-identity");
  const record = Object.freeze({
    kind: "file",
    path: target,
    identity: candidate.file.identity,
    byteLength: candidate.file.byteLength,
  });
  outputLedger.push(record);
  return record;
}

export async function verifyPublishedReceipt(record, expectedSha256) {
  let actual;
  try {
    actual = await readStableFile(record.path, {
      phase: "FILE_IDENTITY",
      reason: "published-receipt",
      kind: "published-receipt",
      captureBytes: false,
    });
  } catch {
    failAdapter("OUTPUT_PUBLICATION", "published-receipt-identity");
  }
  if (actual.sha256 !== expectedSha256 || actual.byteLength !== record.byteLength) {
    failAdapter("OUTPUT_PUBLICATION", "published-receipt-identity");
  }
}

async function invokePublicationCheckpoint(hooks, checkpoint, details) {
  if (!hooks?.checkpoint) return;
  const returned = await hooks.checkpoint(Object.freeze({
    checkpoint,
    ...details,
  }));
  if (returned !== undefined) {
    failAdapter("OUTPUT_PUBLICATION", "publication-checkpoint-invalid");
  }
}

function validateBundleEntries(entries) {
  if (!Array.isArray(entries) || entries.length < 1) {
    failAdapter("OUTPUT_PUBLICATION", "bundle-entry-set-invalid");
  }
  const names = new Set();
  for (const entry of entries) {
    if (
      !entry
      || typeof entry !== "object"
      || typeof entry.name !== "string"
      || entry.name.length === 0
      || entry.name.includes("/")
      || entry.name.includes("\\")
      || entry.name === ".complete"
      || names.has(entry.name)
      || !entry.record
      || entry.record.kind !== "file"
      || !Buffer.isBuffer(entry.bytes)
    ) failAdapter("OUTPUT_PUBLICATION", "bundle-entry-set-invalid");
    names.add(entry.name);
  }
  return names;
}

export function selectIrrevocableBundleMode(mode) {
  if (![
    "success",
    "canonical-post-lock-failure",
    "local-only-failure",
  ].includes(mode)) failAdapter("OUTPUT_PUBLICATION", "bundle-mode-invalid");
  let publicationStarted = false;
  return Object.freeze({
    mode,
    get publicationStarted() {
      return publicationStarted;
    },
    beginPublication(candidateMode) {
      if (publicationStarted || candidateMode !== mode || mode === "local-only-failure") {
        failAdapter("OUTPUT_PUBLICATION", "bundle-mode-immutable");
      }
      publicationStarted = true;
    },
  });
}

export async function validatePrivateBundleStaging(staging, entries) {
  const names = validateBundleEntries(entries);
  await requireDirectoryIdentity(staging);
  const actualNames = await readdir(staging.path);
  if (
    actualNames.length !== names.size
    || actualNames.some((name) => !names.has(name))
  ) failAdapter("OUTPUT_PUBLICATION", "bundle-staging-entry-set");
  for (const entry of entries) {
    const expectedPath = path.join(staging.path, entry.name);
    const state = await lstat(expectedPath, { bigint: true });
    const actual = await readStableFile(expectedPath, {
      phase: "FILE_IDENTITY",
      reason: "bundle-staging-file",
      kind: "bundle-staging-file",
      captureBytes: true,
    });
    if (
      entry.record.path !== expectedPath
      || state.isSymbolicLink()
      || !state.isFile()
      || state.nlink !== 1n
      || !identitiesEqual(entry.record.identity, identityFromState(state))
      || actual.byteLength !== entry.bytes.length
      || actual.sha256 !== sha256Bytes(entry.bytes)
      || !actual.bytes.equals(entry.bytes)
    ) failAdapter("OUTPUT_PUBLICATION", "bundle-staging-file");
  }
  return true;
}

export async function publishPrivateBundleNoReplace({
  target,
  sourceRepo,
  toolingRepo,
  staging,
  entries,
  finalLedger,
  modeDecision,
  hooks = null,
}) {
  if (
    !modeDecision
    || typeof modeDecision.beginPublication !== "function"
  ) failAdapter("OUTPUT_PUBLICATION", "bundle-mode-invalid");
  const mode = modeDecision.mode;
  modeDecision.beginPublication(mode);
  await validatePrivateBundleStaging(staging, entries);
  await invokePublicationCheckpoint(hooks, "before-final-directory", { mode });
  const finalDirectory = await createExclusiveOutputDirectory({
    outputDirectory: target.path,
    sourceRepo,
    toolingRepo,
    validatedTarget: target,
  });
  try {
    await invokePublicationCheckpoint(hooks, "after-final-directory", { mode });
    for (const entry of entries) {
      await requireDirectoryIdentity(finalDirectory);
      const sourceState = await lstat(entry.record.path, { bigint: true });
      if (
        sourceState.isSymbolicLink()
        || !sourceState.isFile()
        || sourceState.nlink !== 1n
        || sourceState.size !== BigInt(entry.bytes.length)
        || !identitiesEqual(entry.record.identity, identityFromState(sourceState))
      ) failAdapter("OUTPUT_PUBLICATION", "bundle-source-identity");
      const targetPath = path.join(finalDirectory.path, entry.name);
      if (await pathState(targetPath)) {
        failAdapter("OUTPUT_PUBLICATION", "bundle-target-exists");
      }
      try {
        await link(entry.record.path, targetPath);
      } catch {
        failAdapter("OUTPUT_PUBLICATION", "bundle-link-failed");
      }
      const targetState = await lstat(targetPath, { bigint: true });
      const record = Object.freeze({
        kind: "file",
        path: targetPath,
        identity: identityFromState(targetState),
        byteLength: entry.bytes.length,
        sha256: sha256Bytes(entry.bytes),
      });
      finalLedger.push(record);
      if (
        targetState.isSymbolicLink()
        || !targetState.isFile()
        || targetState.nlink !== 2n
        || targetState.size !== BigInt(entry.bytes.length)
        || !identitiesEqual(entry.record.identity, record.identity)
      ) failAdapter("OUTPUT_PUBLICATION", "bundle-link-identity");
      await invokePublicationCheckpoint(
        hooks,
        `after-publish-${entry.name}`,
        { mode, publishedCount: finalLedger.length },
      );
      const stable = await hashStableRegularFile(
        targetPath,
        "OUTPUT_PUBLICATION",
        "published-bundle-file",
      );
      const checkedState = await lstat(targetPath, { bigint: true });
      if (
        checkedState.nlink !== 2n
        || !identitiesEqual(record.identity, identityFromState(checkedState))
        || stable.sha256 !== sha256Bytes(entry.bytes)
        || stable.byteLength !== entry.bytes.length
      ) failAdapter("OUTPUT_PUBLICATION", "published-bundle-file");
    }
    const expectedNames = new Set(entries.map((entry) => entry.name));
    const finalNames = await readdir(finalDirectory.path);
    if (
      finalNames.length !== expectedNames.size
      || finalNames.some((name) => !expectedNames.has(name))
    ) failAdapter("OUTPUT_PUBLICATION", "published-bundle-entry-set");
    return Object.freeze({ finalDirectory, mode });
  } catch (error) {
    if (!error.finalDirectory) {
      try {
        Object.defineProperty(error, "finalDirectory", {
          value: finalDirectory,
          enumerable: false,
        });
      } catch { /* the caller still owns finalDirectory */ }
    }
    throw error;
  }
}

async function requirePublishedBundleEntries(publication, entries, finalLedger) {
  await requireDirectoryIdentity(publication.finalDirectory);
  for (const entry of entries) {
    const targetPath = path.join(publication.finalDirectory.path, entry.name);
    const record = finalLedger.find((candidate) => candidate.path === targetPath);
    const state = await lstat(targetPath, { bigint: true });
    const stable = await readStableFile(targetPath, {
      phase: "FILE_IDENTITY",
      reason: "published-bundle-file",
      kind: "published-bundle-file",
      captureBytes: true,
    });
    if (
      !record
      || state.nlink !== 1n
      || !identitiesEqual(record.identity, identityFromState(state))
      || record.sha256 !== sha256Bytes(entry.bytes)
      || stable.sha256 !== record.sha256
      || stable.byteLength !== entry.bytes.length
      || !stable.bytes.equals(entry.bytes)
    ) failAdapter("OUTPUT_PUBLICATION", "published-bundle-file");
  }
}

export async function finalizePublishedBundle({
  publication,
  entries,
  finalLedger,
  markerBytes,
  hooks = null,
}) {
  const names = validateBundleEntries(entries);
  await requirePublishedBundleEntries(publication, entries, finalLedger);
  const beforeMarker = await readdir(publication.finalDirectory.path);
  if (
    beforeMarker.length !== names.size
    || beforeMarker.some((name) => !names.has(name))
  ) failAdapter("OUTPUT_PUBLICATION", "published-bundle-entry-set");
  await invokePublicationCheckpoint(
    hooks,
    "before-completion-marker",
    { mode: publication.mode },
  );
  const marker = await writeOwnedFile(
    publication.finalDirectory,
    ".complete",
    markerBytes,
    finalLedger,
  );
  await invokePublicationCheckpoint(
    hooks,
    "after-completion-marker",
    { mode: publication.mode },
  );
  await requirePublishedBundleEntries(publication, entries, finalLedger);
  const markerState = await lstat(marker.path, { bigint: true });
  const markerStable = await readStableFile(marker.path, {
    phase: "FILE_IDENTITY",
    reason: "completion-marker",
    kind: "completion-marker",
    captureBytes: true,
  });
  const expectedFinal = new Set([...names, ".complete"]);
  const finalNames = await readdir(publication.finalDirectory.path);
  if (
    markerState.nlink !== 1n
    || !identitiesEqual(marker.identity, identityFromState(markerState))
    || !markerStable.bytes.equals(markerBytes)
    || finalNames.length !== expectedFinal.size
    || finalNames.some((name) => !expectedFinal.has(name))
  ) failAdapter("OUTPUT_PUBLICATION", "completion-marker-identity");
  return marker;
}

export function buildSemanticReportBytes({
  sourceCommit,
  toolingCommit,
  inputSetSha256,
  artifactSha256,
  artifactByteLength,
}) {
  try {
    return encodeCanonicalSemanticReport({
      semanticReportKind: REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
      schemaVersion: SCHEMA_VERSION,
      artifactRole: ARTIFACT_ROLE,
      formatProfile: FORMAT_PROFILE,
      sourceCommit,
      toolingCommit,
      inputSetSha256,
      artifactSha256,
      artifactByteLength,
      canonicalVerifierPassed: true,
      sameProcessRepeatable: true,
      sameHostRepeatable: true,
      boundaryVectorSetPassed: true,
      result: "pass",
      failureCode: null,
    });
  } catch {
    failAdapter("SEMANTIC_REPORT", "semantic-report-invalid");
  }
}

export function buildEvidenceBytes({
  policy,
  policySha256,
  cell,
  result,
  artifactSha256 = null,
  artifactByteLength = null,
  semanticReportSha256 = null,
  semanticReportByteLength = null,
  failureClass = null,
  failureCode = null,
}) {
  try {
    return encodeCanonicalReproducibilityEvidence({
      evidenceKind: REPRODUCIBILITY_EVIDENCE_KIND,
      schemaVersion: SCHEMA_VERSION,
      artifactRole: policy.artifactRole,
      formatProfile: policy.formatProfile,
      sourceCommit: policy.sourceCommit,
      toolingCommit: policy.toolingCommit,
      criticalToolSetSha256: policy.criticalToolSetSha256,
      manifestSha256: policy.manifestSha256,
      inputSetSha256: policy.inputSetSha256,
      runtimeProfileId: cell.runtimeProfileId,
      runtimeIdentitySha256: cell.runtimeIdentitySha256,
      gitProfileId: cell.gitProfileId,
      gitIdentitySha256: cell.gitIdentitySha256,
      runnerPolicySha256: policySha256,
      testVectorSetSha256: policy.testVectorSetSha256,
      matrixCellId: cell.matrixCellId,
      operatingSystem: cell.operatingSystem,
      operatingSystemBuild: cell.operatingSystemBuild,
      architecture: cell.architecture,
      filesystemProfile: cell.filesystemProfile,
      localeProfile: cell.localeProfile,
      timezoneProfile: cell.timezoneProfile,
      platformProbeSha256: cell.platformProbeSha256,
      artifactSha256,
      artifactByteLength,
      semanticReportSha256,
      semanticReportByteLength,
      result,
      failureClass,
      failureCode,
    });
  } catch {
    failAdapter("EVIDENCE", "evidence-invalid");
  }
}

export function failureClassFor(error) {
  if (error.reason === "runtime-profile-mismatch") return "runtime-profile-change";
  if (error.reason === "git-identity-mismatch") return "runtime-profile-change";
  if (error.reason === "unsupported-host-capability") {
    return error.phase === "PLATFORM_PROBE"
      ? "unsupported-platform"
      : "filesystem-incompatibility";
  }
  if (
    error.reason === "cleanup-incomplete"
    || error.reason.startsWith("private-worker-")
  ) {
    return "test-infrastructure-failure";
  }
  return "implementation-defect";
}

function parseWorkerRequestText(text) {
  const request = parseExactPrivateJsonText(
    text,
    MAX_WORKER_REQUEST_BYTES,
    "private-worker-request-invalid",
  );
  exactKeys(
    request,
    WORKER_REQUEST_KEYS,
    "SAME_HOST",
    "private-worker-request-invalid",
  );
  if (
    request.protocol !== WORKER_PROTOCOL
    || !["worker-a", "worker-b"].includes(request.assignmentId)
    || !SHA256_PATTERN.test(request.assignmentNonce)
  ) failAdapter("SAME_HOST", "private-worker-request-invalid");
  requireExactPrivatePath(
    request.leaseReference,
    "private-worker-request-invalid",
  );
  requireExactPrivatePath(
    request.repositoryPath,
    "private-worker-request-invalid",
  );
  requireExactPrivatePath(
    request.sourceArchivePath,
    "private-worker-request-invalid",
  );
  if (!Array.isArray(request.artifacts) || request.artifacts.length < 1) {
    failAdapter("SAME_HOST", "private-worker-request-invalid");
  }
  for (const artifact of request.artifacts) {
    exactKeys(
      artifact,
      ["role", "format", "path"],
      "SAME_HOST",
      "private-worker-request-invalid",
    );
    requireIdentifier(artifact.role, "SAME_HOST", "private-worker-request-invalid");
    requireIdentifier(artifact.format, "SAME_HOST", "private-worker-request-invalid");
    requireExactPrivatePath(artifact.path, "private-worker-request-invalid");
  }
  validateLockedWorkerContext(request.lockedContext);
  return request;
}

function validateLeaseAssignment(value, expectedId, contextDigest) {
  exactKeys(
    value,
    WORKER_ASSIGNMENT_KEYS,
    "SAME_HOST",
    "private-worker-lease-invalid",
  );
  if (
    value.assignmentId !== expectedId
    || !SHA256_PATTERN.test(value.assignmentNonce)
    || !SHA256_PATTERN.test(value.directoryPathSha256)
    || value.receiptFilename !== WORKER_RECEIPT_BASENAME
    || value.lockedContextDigest !== contextDigest
    || value.state !== "unused"
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  requirePrivateIdentityStrings(
    value.directoryParentIdentity,
    "private-worker-lease-invalid",
  );
  requirePrivateIdentityStrings(
    value.directoryIdentity,
    "private-worker-lease-invalid",
  );
}

async function readAndValidateWorkerLease(request) {
  if (path.basename(request.leaseReference) !== WORKER_LEASE_BASENAME) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const rootPath = path.dirname(request.leaseReference);
  const [root, repositoryDirectory, stableLease] = await Promise.all([
    inspectExactPrivateDirectory(rootPath, "private-worker-root-mismatch"),
    inspectExactPrivateDirectory(
      request.repositoryPath,
      "private-worker-context-invalid",
    ),
    readStablePrivateFile(
      request.leaseReference,
      MAX_WORKER_LEASE_BYTES,
      "private-worker-lease-invalid",
    ),
  ]);
  const leaseText = stableLease.bytes.toString("utf8");
  if (!Buffer.from(leaseText, "utf8").equals(stableLease.bytes)) {
    failAdapter("SAME_HOST", "private-worker-lease-invalid");
  }
  const lease = parseExactPrivateJsonText(
    leaseText,
    MAX_WORKER_LEASE_BYTES,
    "private-worker-lease-invalid",
  );
  exactKeys(
    lease,
    WORKER_LEASE_KEYS,
    "SAME_HOST",
    "private-worker-lease-invalid",
  );
  if (
    lease.protocol !== WORKER_LEASE_PROTOCOL
    || lease.schemaVersion !== 1
    || !SHA256_PATTERN.test(lease.runId)
    || !Number.isSafeInteger(lease.coordinatorPid)
    || lease.coordinatorPid <= 0
    || !SHA256_PATTERN.test(lease.coordinatorBootstrapSha256)
    || !SHA256_PATTERN.test(lease.privateRootPathSha256)
    || !SHA256_PATTERN.test(lease.lockedContextDigest)
    || !Array.isArray(lease.assignments)
    || lease.assignments.length !== 2
  ) failAdapter("SAME_HOST", "private-worker-lease-invalid");
  requirePrivateIdentityStrings(
    lease.privateRootIdentity,
    "private-worker-lease-invalid",
  );
  requirePrivateIdentityStrings(
    lease.privateRootParentIdentity,
    "private-worker-lease-invalid",
  );
  validateLockedWorkerContext(lease.lockedContext);
  if (
    !contextsEqual(lease.lockedContext, request.lockedContext)
    || lockedContextSha256(request.lockedContext) !== lease.lockedContextDigest
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  if (
    lease.coordinatorPid !== process.ppid
    || lease.coordinatorBootstrapSha256 !== coordinatorBootstrapSha256()
  ) failAdapter("SAME_HOST", "private-worker-parent-mismatch");
  if (
    root.pathSha256 !== lease.privateRootPathSha256
    || !identityMatchesStrings(root.identity, lease.privateRootIdentity)
    || !identityMatchesStrings(
      root.parentIdentity,
      lease.privateRootParentIdentity,
    )
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  if (
    pathsEqual(root.path, repositoryDirectory.path)
    || isInside(repositoryDirectory.path, root.path)
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  if (
    repositoryDirectory.pathSha256 !== request.lockedContext.repository.pathSha256
    || !identityMatchesStrings(
      repositoryDirectory.identity,
      request.lockedContext.repository.identity,
    )
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  validateLeaseAssignment(
    lease.assignments[0],
    "worker-a",
    lease.lockedContextDigest,
  );
  validateLeaseAssignment(
    lease.assignments[1],
    "worker-b",
    lease.lockedContextDigest,
  );
  const assignment = lease.assignments.find(
    (entry) => entry.assignmentId === request.assignmentId,
  );
  if (
    !assignment
    || assignment.assignmentNonce !== request.assignmentNonce
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const assignmentPath = path.join(root.path, request.assignmentId);
  requireExactPrivatePath(
    assignmentPath,
    "private-worker-assignment-mismatch",
  );
  const directory = await inspectExactPrivateDirectory(
    assignmentPath,
    "private-worker-assignment-mismatch",
  );
  if (
    directory.pathSha256 !== assignment.directoryPathSha256
    || !identityMatchesStrings(directory.identity, assignment.directoryIdentity)
    || !identityMatchesStrings(
      directory.parentIdentity,
      assignment.directoryParentIdentity,
    )
    || !identitiesEqual(directory.parentIdentity, root.identity)
    || path.resolve(process.cwd()) !== assignmentPath
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const git = await resolveControlledGitExecutable();
  if (
    git.sha256 !== request.lockedContext.gitExecutableSha256
    || git.byteLength !== request.lockedContext.gitExecutableByteLength
  ) failAdapter("SAME_HOST", "private-worker-context-invalid");
  const rootEntries = await readdir(root.path);
  const expectedRootEntries = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== expectedRootEntries.size
    || rootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const entries = await readdir(directory.path);
  if (entries.includes(WORKER_CLAIM_BASENAME)) {
    failAdapter("SAME_HOST", "private-worker-replay");
  }
  if (entries.length !== 0) {
    failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  }
  return Object.freeze({
    request,
    lease,
    leaseBytes: stableLease.bytes,
    leaseIdentity: stableLease.identity,
    root,
    repositoryDirectory,
    assignment,
    directory,
  });
}

async function requireWorkerLeaseState(binding, expectedEntries) {
  const [root, repositoryDirectory, directory, leaseFile] =
    await Promise.all([
      inspectExactPrivateDirectory(
        binding.root.path,
        "private-worker-root-mismatch",
      ),
      inspectExactPrivateDirectory(
        binding.repositoryDirectory.path,
        "private-worker-context-invalid",
      ),
      inspectExactPrivateDirectory(
        binding.directory.path,
        "private-worker-assignment-mismatch",
      ),
      readStablePrivateFile(
        binding.request.leaseReference,
        MAX_WORKER_LEASE_BYTES,
        "private-worker-lease-invalid",
      ),
    ]);
  if (
    !identitiesEqual(root.identity, binding.root.identity)
    || !identitiesEqual(root.parentIdentity, binding.root.parentIdentity)
    || !identitiesEqual(
      repositoryDirectory.identity,
      binding.repositoryDirectory.identity,
    )
    || !identitiesEqual(directory.identity, binding.directory.identity)
    || !identitiesEqual(directory.parentIdentity, root.identity)
    || !identitiesEqual(leaseFile.identity, binding.leaseIdentity)
    || !leaseFile.bytes.equals(binding.leaseBytes)
  ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
  const rootEntries = await readdir(root.path);
  const allowedRoot = new Set([
    WORKER_LEASE_BASENAME,
    "worker-a",
    "worker-b",
  ]);
  if (
    rootEntries.length !== allowedRoot.size
    || rootEntries.some((entry) => !allowedRoot.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-root-mismatch");
  const entries = await readdir(directory.path);
  const allowed = new Set(expectedEntries);
  if (
    entries.length !== allowed.size
    || entries.some((entry) => !allowed.has(entry))
  ) failAdapter("SAME_HOST", "private-worker-output-escape");
}

async function claimWorkerAssignment(binding, ledger) {
  await requireWorkerLeaseState(binding, []);
  const claimPath = path.join(binding.directory.path, WORKER_CLAIM_BASENAME);
  const claimBytes = claimBytesFor(binding.lease, binding.assignment);
  let handle = null;
  try {
    handle = await open(
      claimPath,
      FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | FS_CONSTANTS.O_WRONLY
        | noFollowFlag(),
      0o600,
    );
    const initial = await handle.stat({ bigint: true });
    const record = Object.freeze({
      kind: "file",
      path: claimPath,
      identity: identityFromState(initial),
      byteLength: claimBytes.length,
    });
    if (!record.identity.meaningful || initial.nlink !== 1n) {
      failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    }
    ledger.push(record);
    await handle.writeFile(claimBytes);
    await handle.sync();
    await handle.close();
    handle = null;
    const stable = await readStablePrivateFile(
      claimPath,
      MAX_WORKER_LEASE_BYTES,
      "private-worker-assignment-mismatch",
    );
    if (
      !stable.bytes.equals(claimBytes)
      || !identitiesEqual(stable.identity, record.identity)
    ) failAdapter("SAME_HOST", "private-worker-assignment-mismatch");
    await requireWorkerLeaseState(binding, [WORKER_CLAIM_BASENAME]);
    return record;
  } catch (error) {
    if (error && error.code === "EEXIST") {
      failAdapter("SAME_HOST", "private-worker-replay");
    }
    throw asAdapterError(
      error,
      "SAME_HOST",
      "private-worker-assignment-mismatch",
    );
  } finally {
    if (handle) await handle.close();
  }
}

async function createCapsuleAuthorizedWorkerReceipt({
  request,
  binding,
  receiptPath,
  ledger,
}) {
  const emptyHooks = Object.freeze({});
  let toolDirectory = null;
  let primaryError = null;
  let result = null;
  try {
    await verifyToolingCommitSignature(
      request.repositoryPath,
      request.lockedContext.toolingCommit,
      emptyHooks,
    );
    const bootstrap = deriveCriticalToolIdentities(
      request.repositoryPath,
      request.lockedContext.toolingCommit,
    );
    toolDirectory = await materializeVerifiedToolDirectory(bootstrap.records);
    const sourceVerification = await runVerifiedReceiptWorker({
      operation: "source",
      toolRoot: toolDirectory.rootPath,
      criticalFiles: bootstrap.criticalFiles,
      repo: request.repositoryPath,
      sourceCommit: request.lockedContext.sourceCommit,
      sourceArchive: request.sourceArchivePath,
    });
    if (sourceVerification.sourceCommit !== request.lockedContext.sourceCommit) {
      failAdapter("SAME_HOST", "private-worker-context-invalid");
    }
    const artifacts = await hashArtifactInputs(
      request.repositoryPath,
      request.artifacts,
      emptyHooks,
    );
    const receipt = buildPublicSourceReceipt({
      sourceVerification,
      toolingCommit: request.lockedContext.toolingCommit,
      criticalFiles: bootstrap.criticalFiles,
      artifacts,
    });
    requireCriticalFilesEqual(
      receipt.tooling.criticalFiles,
      bootstrap.criticalFiles,
      "TOOLING",
    );
    const receiptBytes = encodeCanonicalReceipt(receipt);
    const file = await writeOwnedFile(
      binding.directory,
      binding.assignment.receiptFilename,
      receiptBytes,
      ledger,
    );
    const verification = await runVerifiedReceiptWorker({
      operation: "verify",
      toolRoot: toolDirectory.rootPath,
      criticalFiles: bootstrap.criticalFiles,
      mode: "full",
      repo: request.repositoryPath,
      receipt: receiptPath,
      sourceArchive: request.sourceArchivePath,
      artifacts: request.artifacts,
    });
    if (
      verification.status !== "ok"
      || verification.mode !== "full"
      || verification.verificationComplete !== true
      || verification.sourceCommit !== request.lockedContext.sourceCommit
      || verification.toolingCommit !== request.lockedContext.toolingCommit
      || verification.artifactCount !== artifacts.length
      || verification.receiptSha256 !== sha256Bytes(receiptBytes)
      || verification.receiptByteLength !== receiptBytes.length
      || verification.sourceArchiveVerified !== true
      || verification.toolingCommitSignatureValid !== true
      || verification.artifactsVerified !== true
    ) failAdapter("SAME_HOST", "private-worker-response-invalid");
    result = Object.freeze({ file, verification });
  } catch (error) {
    primaryError = asAdapterError(
      error,
      "SAME_HOST",
      "private-worker-output-escape",
    );
  }
  if (toolDirectory) {
    try {
      await cleanupVerifiedToolDirectory(toolDirectory);
    } catch {
      throw new PublicSourceReceiptReproducibilityError(
        "CLEANUP",
        "cleanup-incomplete",
      );
    }
  }
  if (primaryError) throw primaryError;
  return result;
}

function loadedWorkerAttestation() {
  const value = globalThis.__IELTMPS_WORKER_LOADED_BYTES__;
  if (
    !value
    || typeof value !== "object"
    || Object.keys(value).length !== 3
    || Object.keys(value).some((key, index) => key !== [
      "workerCapsuleSha256",
      "workerModuleSetSha256",
      "workerEntryModuleSha256",
    ][index])
  ) failAdapter("TOOL_SET", "worker-loaded-bytes-mismatch");
  for (const key of Object.keys(value)) {
    requireSha256(value[key], "TOOL_SET", "worker-loaded-bytes-mismatch");
  }
  return value;
}

async function workerOperation(requestText, workerRequestListenerCount) {
  const request = parseWorkerRequestText(requestText);
  if (workerRequestListenerCount !== 0) {
    failAdapter("SAME_HOST", "private-worker-request-invalid");
  }
  const loadedBytes = loadedWorkerAttestation();
  const binding = await readAndValidateWorkerLease(request);
  const workerLedger = [];
  let claimed = false;
  try {
    claimed = true;
    await claimWorkerAssignment(binding, workerLedger);
    const archiveIdentity = await hashStableRegularFile(
      request.sourceArchivePath,
      "SAME_HOST",
      "private-worker-context-invalid",
    );
    if (
      archiveIdentity.sha256 !== request.lockedContext.sourceArchiveSha256
      || archiveIdentity.byteLength
        !== request.lockedContext.sourceArchiveByteLength
    ) failAdapter("SAME_HOST", "private-worker-context-invalid");
    const artifactIdentities = [];
    for (const artifact of request.artifacts) {
      const identity = await hashStableRegularFile(
        artifact.path,
        "SAME_HOST",
        "private-worker-context-invalid",
      );
      artifactIdentities.push({
        role: artifact.role,
        format: artifact.format,
        sha256: identity.sha256,
        byteLength: identity.byteLength,
      });
    }
    artifactIdentities.sort((left, right) => (
      (left.role < right.role ? -1 : left.role > right.role ? 1 : 0)
      || (left.format < right.format ? -1 : left.format > right.format ? 1 : 0)
      || (left.sha256 < right.sha256 ? -1 : left.sha256 > right.sha256 ? 1 : 0)
    ));
    const observedArtifacts = canonicalAdapterJsonBytes(
      artifactIdentities,
      "SAME_HOST",
    );
    const boundArtifacts = canonicalAdapterJsonBytes(
      request.lockedContext.artifacts,
      "SAME_HOST",
    );
    if (!observedArtifacts.equals(boundArtifacts)) {
      failAdapter("SAME_HOST", "private-worker-context-invalid");
    }
    const receiptPath = path.join(
      binding.directory.path,
      binding.assignment.receiptFilename,
    );
    if (await pathState(receiptPath)) {
      failAdapter("SAME_HOST", "private-worker-replay");
    }
    const created = await createCapsuleAuthorizedWorkerReceipt({
      request,
      binding,
      receiptPath,
      ledger: workerLedger,
    });
    const file = created.file;
    const fileState = await lstat(receiptPath, { bigint: true });
    if (
      fileState.isSymbolicLink()
      || !fileState.isFile()
      || fileState.nlink !== 1n
      || !identitiesEqual(file.identity, identityFromState(fileState))
      || !file.identity.meaningful
    ) failAdapter("SAME_HOST", "private-worker-output-escape");
    await requireWorkerLeaseState(binding, [
      WORKER_CLAIM_BASENAME,
      WORKER_RECEIPT_BASENAME,
    ]);
    const verification = created.verification;
    const transcript = encodeReceiptVerificationTranscript(verification, {
      sourceCommit: request.lockedContext.sourceCommit,
      toolingCommit: request.lockedContext.toolingCommit,
      artifactCount: request.artifacts.length,
    });
    const stableReceipt = await hashStableRegularFile(
      receiptPath,
      "SAME_HOST",
      "private-worker-output-escape",
    );
    if (
      stableReceipt.sha256 !== verification.receiptSha256
      || stableReceipt.byteLength !== verification.receiptByteLength
    ) failAdapter("SAME_HOST", "private-worker-output-escape");
    await requireWorkerLeaseState(binding, [
      WORKER_CLAIM_BASENAME,
      WORKER_RECEIPT_BASENAME,
    ]);
    const response = {
      protocol: WORKER_PROTOCOL,
      runId: binding.lease.runId,
      assignmentId: request.assignmentId,
      contextDigest: binding.lease.lockedContextDigest,
      status: "ok",
      receiptSha256: verification.receiptSha256,
      receiptByteLength: verification.receiptByteLength,
      receiptVerificationTranscript: transcript.toString("base64"),
      workerPid: process.pid,
      assignedDirectoryIdentity: identityStrings(binding.directory.identity),
      receiptFileIdentity: identityStrings(file.identity),
      workerCapsuleSha256: loadedBytes.workerCapsuleSha256,
      workerModuleSetSha256: loadedBytes.workerModuleSetSha256,
      workerEntryModuleSha256: loadedBytes.workerEntryModuleSha256,
      workerRequestListenerCount,
    };
    let cleanupAvailable = true;
    return Object.freeze({
      response,
      cleanup: async () => {
        if (!cleanupAvailable) return;
        cleanupAvailable = false;
        await cleanupOwnedLedger(workerLedger);
      },
    });
  } catch (error) {
    if (claimed) {
      try {
        await cleanupOwnedLedger(workerLedger);
      } catch {
        throw new PublicSourceReceiptReproducibilityError(
          "CLEANUP",
          "cleanup-incomplete",
        );
      }
    }
    throw asAdapterError(error, "SAME_HOST", "private-worker-output-escape");
  }
}

function comparableCanonicalPath(value) {
  const canonical = realpathSync.native(value);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

function isMainModule() {
  const entry = process.argv[1];
  if (typeof entry !== "string" || entry.length === 0) return false;
  try {
    return comparableCanonicalPath(fileURLToPath(import.meta.url))
      === comparableCanonicalPath(path.resolve(entry));
  } catch {
    return false;
  }
}

let privateWorkerFatalTerminationStarted = false;

function terminatePrivateWorkerFatal(error) {
  if (privateWorkerFatalTerminationStarted) process.exit(1);
  privateWorkerFatalTerminationStarted = true;

  const safe = asAdapterError(error, "CLI", "private-worker-unavailable");
  const line = "ERROR " + safe.phase + ": " + safe.reason + "\n";
  try {
    process.removeAllListeners("message");
  } catch {
    // Forced termination must continue even if listener shutdown fails.
  }
  try {
    writeSync(2, Buffer.from(line, "utf8"));
  } catch {
    // Forced termination must continue even if stderr is unavailable.
  }
  try {
    if (process.connected) process.disconnect();
  } catch {
    // Forced termination must continue even if IPC disconnect fails.
  }
  process.exitCode = 1;
  process.exit(1);
}

async function privateWorkerMain() {
  if (
    typeof process.send !== "function"
    || !process.connected
  ) failAdapter("CLI", "private-worker-unavailable");
  const firstRequest = await new Promise((resolve, reject) => {
    let requestSlotConsumed = false;
    let timeout;
    const onFirstMessage = (message) => {
      requestSlotConsumed = true;
      process.removeListener("message", onFirstMessage);
      clearTimeout(timeout);
      const requestListenerCount = process.listenerCount("message");
      resolve(Object.freeze({ message, requestListenerCount }));
    };
    timeout = setTimeout(
      () => {
        if (requestSlotConsumed) return;
        process.removeListener("message", onFirstMessage);
        reject(new PublicSourceReceiptReproducibilityError(
          "SAME_HOST", "private-worker-request-invalid",
        ));
      },
      30000,
    );
    process.once("message", onFirstMessage);
  });
  const operation = await workerOperation(
    firstRequest.message,
    firstRequest.requestListenerCount,
  );
  const responseText = privateJsonBytes(
    operation.response,
    "private-worker-response-invalid",
  ).toString("utf8");
  if (Buffer.byteLength(responseText, "utf8") > MAX_WORKER_RESPONSE_BYTES) {
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  try {
    await new Promise((resolve, reject) => {
      process.send(responseText, (error) => error ? reject(error) : resolve());
    });
  } catch {
    await operation.cleanup();
    failAdapter("SAME_HOST", "private-worker-response-invalid");
  }
  process.disconnect();
  process.exitCode = 0;
}

export async function runPrivateReceiptWorker() {
  try {
    await privateWorkerMain();
  } catch (error) {
    terminatePrivateWorkerFatal(error);
  }
}

if (isMainModule()) {
  runPrivateReceiptWorker();
}
