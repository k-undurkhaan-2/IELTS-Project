#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PROVENANCE_RECORD_KIND,
  SCHEMA_VERSION,
  GeneratedDataProvenanceError,
  deriveEligibility,
  deriveInputSetSha256,
  deriveOutputSetSha256,
  deriveRightsVerified,
  failProvenance,
  normalizeIdentityTestHooks,
  parseCanonicalOpaqueJsonBytes,
  parseCanonicalProvenanceRecord,
  readGitPathIdentities,
  readStableCanonicalDocument,
  readStableFile,
  requireFileIdentityMatches,
  sha256Bytes,
  validateDeterministicOutputBytes,
  validateGitRepository,
  validateNormalizedInputBytes,
  verifyGitCommitTree,
} from "./generated-data-provenance-core.mjs";

const INPUT_BINDING_KEYS = Object.freeze(["role", "identifier", "path"]);
const DEPENDENCY_BINDING_KEYS = Object.freeze(["role", "identifier", "path"]);
const OUTPUT_BINDING_KEYS = Object.freeze([
  "role",
  "identifier",
  "format",
  "path",
]);

function exactObjectKeys(value, expected, phase, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failProvenance(phase, reason + "-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failProvenance(phase, reason + "-keys");
  }
}

function normalizeBindings(value, keys, phase, reason, identityFields) {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(value)) {
    failProvenance("CLI", reason + "-array");
  }
  const identities = new Set();
  return Object.freeze(value.map((entry) => {
    exactObjectKeys(entry, keys, "CLI", reason);
    for (const key of keys) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) {
        failProvenance("CLI", reason + "-value");
      }
    }
    const identity = identityFields.map((field) => entry[field]).join("\0");
    if (identities.has(identity)) {
      failProvenance(phase, "duplicate-" + reason);
    }
    identities.add(identity);
    return Object.freeze(Object.fromEntries(keys.map((key) => [key, entry[key]])));
  }));
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failProvenance("CLI", "api-options-object");
  }
  const allowed = new Set([
    "record",
    "toolingRepo",
    "runtimeExecutable",
    "sourceRepo",
    "sourceArchive",
    "sourceMemberManifest",
    "inputs",
    "dependencies",
    "outputs",
    "testHooks",
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failProvenance("CLI", "api-option-key");
    }
  }
  if (
    typeof options.record !== "string"
    || typeof options.toolingRepo !== "string"
    || typeof options.runtimeExecutable !== "string"
  ) {
    failProvenance("CLI", "api-required-option");
  }
  for (const key of ["sourceRepo", "sourceArchive", "sourceMemberManifest"]) {
    if (options[key] !== undefined && typeof options[key] !== "string") {
      failProvenance("CLI", "api-source-option");
    }
  }
  return Object.freeze({
    record: options.record,
    toolingRepo: options.toolingRepo,
    runtimeExecutable: options.runtimeExecutable,
    sourceRepo: options.sourceRepo,
    sourceArchive: options.sourceArchive,
    sourceMemberManifest: options.sourceMemberManifest,
    inputs: normalizeBindings(
      options.inputs,
      INPUT_BINDING_KEYS,
      "INPUT",
      "input-binding",
      ["role", "identifier"],
    ),
    dependencies: normalizeBindings(
      options.dependencies,
      DEPENDENCY_BINDING_KEYS,
      "DEPENDENCY",
      "dependency-binding",
      ["role", "identifier"],
    ),
    outputs: normalizeBindings(
      options.outputs,
      OUTPUT_BINDING_KEYS,
      "OUTPUT",
      "output-binding",
      ["role", "identifier", "format"],
    ),
    hooks: normalizeIdentityTestHooks(options.testHooks),
  });
}

function bindingMap(bindings, fields) {
  return new Map(bindings.map((entry) => [
    fields.map((field) => entry[field]).join("\0"),
    entry,
  ]));
}

function requireExactBindingSet(expected, supplied, fields, phase, label) {
  const expectedKeys = new Set(expected.map((entry) => (
    fields.map((field) => entry[field]).join("\0")
  )));
  const suppliedKeys = new Set(supplied.map((entry) => (
    fields.map((field) => entry[field]).join("\0")
  )));
  if (
    expectedKeys.size !== suppliedKeys.size
    || [...expectedKeys].some((key) => !suppliedKeys.has(key))
  ) {
    failProvenance(phase, label + "-set");
  }
}

async function verifyPreferredSource(record, options) {
  const source = record.preferredSource;
  if (source.kind === "immutable-upstream-archive") {
    if (
      typeof options.sourceArchive !== "string"
      || typeof options.sourceMemberManifest !== "string"
      || options.sourceRepo !== undefined
    ) {
      failProvenance("CLI", "archive-source-options");
    }
    const archive = await readStableFile(options.sourceArchive, {
      phase: "PREFERRED_SOURCE",
      reason: "source-archive",
      kind: "source-archive",
      hooks: options.hooks,
    });
    requireFileIdentityMatches(
      archive,
      { sha256: source.sha256, byteLength: source.byteLength, gitBlobId: null },
      "PREFERRED_SOURCE",
      "source-archive-identity",
    );
    const memberManifest = await readStableCanonicalDocument(
      options.sourceMemberManifest,
      "PREFERRED_SOURCE",
      "source-member-manifest",
      options.hooks,
    );
    parseCanonicalOpaqueJsonBytes(memberManifest.bytes, "PREFERRED_SOURCE");
    if (memberManifest.sha256 !== source.memberManifestSha256) {
      failProvenance("PREFERRED_SOURCE", "member-manifest-identity");
    }
    return Object.freeze({ sourceRepo: null, gitInputs: new Map() });
  }

  if (
    typeof options.sourceRepo !== "string"
    || options.sourceArchive !== undefined
    || options.sourceMemberManifest !== undefined
  ) {
    failProvenance("CLI", "git-source-options");
  }
  const sourceRepo = await validateGitRepository(
    options.sourceRepo,
    "PREFERRED_SOURCE",
  );
  verifyGitCommitTree(
    sourceRepo,
    source.commit,
    source.tree,
    "PREFERRED_SOURCE",
  );
  const expected = record.inputs
    .filter((entry) => entry.gitBlobId !== null)
    .map((entry) => Object.freeze({
      path: entry.identifier,
      gitBlobId: entry.gitBlobId,
      sha256: entry.sha256,
      byteLength: entry.byteLength,
    }));
  const gitInputs = readGitPathIdentities(
    sourceRepo,
    source.commit,
    expected,
    "INPUT",
  );
  return Object.freeze({ sourceRepo, gitInputs });
}

async function verifyInputs(record, options, preferred) {
  const external = record.inputs.filter((entry) => entry.gitBlobId === null);
  requireExactBindingSet(
    external,
    options.inputs,
    ["role", "identifier"],
    "INPUT",
    "input-binding",
  );
  const bindings = bindingMap(options.inputs, ["role", "identifier"]);
  for (const input of record.inputs) {
    let bytes;
    if (input.gitBlobId !== null) {
      const identity = preferred.gitInputs.get(input.identifier);
      if (!identity) {
        failProvenance("INPUT", "git-input-missing");
      }
      bytes = identity.bytes;
    } else {
      const binding = bindings.get(input.role + "\0" + input.identifier);
      const identity = await readStableFile(binding.path, {
        phase: "INPUT",
        reason: "external-input",
        kind: "input",
        hooks: options.hooks,
      });
      requireFileIdentityMatches(
        identity,
        input,
        "INPUT",
        "external-input-identity",
      );
      bytes = identity.bytes;
    }
    validateNormalizedInputBytes(bytes, input.normalization);
  }
  if (
    record.preferredSource.kind === "commit-owned-git-blob-set"
    && deriveInputSetSha256(record.inputs) !== record.preferredSource.inputSetSha256
  ) {
    failProvenance("PREFERRED_SOURCE", "input-set-sha256-mismatch");
  }
  return true;
}

async function verifyGenerator(record, options) {
  const generator = record.generator;
  const toolingRepo = await validateGitRepository(options.toolingRepo, "GENERATOR");
  verifyGitCommitTree(
    toolingRepo,
    generator.toolingCommit,
    generator.toolingTree,
    "GENERATOR",
  );
  readGitPathIdentities(
    toolingRepo,
    generator.toolingCommit,
    generator.files,
    "GENERATOR",
  );

  const gitDependencies = generator.dependencies
    .filter((entry) => entry.gitBlobId !== null)
    .map((entry) => Object.freeze({
      path: entry.identifier,
      gitBlobId: entry.gitBlobId,
      sha256: entry.sha256,
      byteLength: entry.byteLength,
    }));
  readGitPathIdentities(
    toolingRepo,
    generator.toolingCommit,
    gitDependencies,
    "DEPENDENCY",
  );

  const external = generator.dependencies.filter((entry) => entry.gitBlobId === null);
  requireExactBindingSet(
    external,
    options.dependencies,
    ["role", "identifier"],
    "DEPENDENCY",
    "dependency-binding",
  );
  const bindings = bindingMap(options.dependencies, ["role", "identifier"]);
  for (const dependency of external) {
    const binding = bindings.get(dependency.role + "\0" + dependency.identifier);
    const identity = await readStableFile(binding.path, {
      phase: "DEPENDENCY",
      reason: "external-dependency",
      kind: "dependency",
      hooks: options.hooks,
    });
    requireFileIdentityMatches(
      identity,
      dependency,
      "DEPENDENCY",
      "external-dependency-identity",
    );
  }

  const runtime = await readStableFile(options.runtimeExecutable, {
    phase: "GENERATOR",
    reason: "runtime-distribution",
    kind: "runtime",
    hooks: options.hooks,
  });
  requireFileIdentityMatches(
    runtime,
    {
      sha256: generator.runtime.distributionSha256,
      byteLength: generator.runtime.distributionByteLength,
      gitBlobId: null,
    },
    "GENERATOR",
    "runtime-distribution-identity",
  );
  return true;
}

async function verifyOutputs(record, options) {
  requireExactBindingSet(
    record.outputs,
    options.outputs,
    ["role", "identifier", "format"],
    "OUTPUT",
    "output-binding",
  );
  const bindings = bindingMap(options.outputs, ["role", "identifier", "format"]);
  for (const output of record.outputs) {
    const key = output.role + "\0" + output.identifier + "\0" + output.format;
    const binding = bindings.get(key);
    const identity = await readStableFile(binding.path, {
      phase: "OUTPUT",
      reason: "output-file",
      kind: "output",
      hooks: options.hooks,
    });
    requireFileIdentityMatches(identity, output, "OUTPUT", "output-identity");
    validateDeterministicOutputBytes(identity.bytes, record.deterministicPolicy);
  }
  return true;
}

async function verifyGeneratedDataProvenanceInternal(options) {
  const validatedOptions = validateApiOptions(options);
  const recordInput = await readStableCanonicalDocument(
    validatedOptions.record,
    "RECORD_SCHEMA",
    "record",
    validatedOptions.hooks,
  );
  const record = parseCanonicalProvenanceRecord(recordInput.bytes);
  const preferred = await verifyPreferredSource(record, validatedOptions);
  await verifyInputs(record, validatedOptions, preferred);
  await verifyGenerator(record, validatedOptions);
  await verifyOutputs(record, validatedOptions);

  const rightsVerified = deriveRightsVerified(record.component, record.rights);
  const replayVerified = false;
  const eligibility = deriveEligibility({
    recordValid: true,
    preferredSourceVerified: true,
    inputsVerified: true,
    generatorVerified: true,
    deterministicPolicyValid: true,
    outputsVerified: true,
    replayVerified,
    rightsVerified,
  });
  if (
    record.releaseEligible !== eligibility.releaseEligible
    || record.publicationBlocked !== eligibility.publicationBlocked
  ) {
    failProvenance("RECORD_SCHEMA", "stored-eligibility-mismatch");
  }

  return Object.freeze({
    status: "ok",
    mode: "provenance-verification",
    recordKind: PROVENANCE_RECORD_KIND,
    schemaVersion: SCHEMA_VERSION,
    componentId: record.component.componentId,
    generationSetId: record.component.generationSetId,
    recordId: record.component.recordId,
    recordSha256: sha256Bytes(recordInput.bytes),
    recordByteLength: recordInput.byteLength,
    outputSetSha256: deriveOutputSetSha256(record.outputs),
    recordValid: true,
    preferredSourceVerified: true,
    inputsVerified: true,
    generatorVerified: true,
    deterministicPolicyValid: true,
    outputsVerified: true,
    replayVerified,
    rightsVerified,
    releaseEligible: eligibility.releaseEligible,
    publicationBlocked: eligibility.publicationBlocked,
  });
}

export async function verifyGeneratedDataProvenance(options = {}) {
  return verifyGeneratedDataProvenanceInternal(options);
}

function parseOptions(argv) {
  const singletonFlags = new Set([
    "--record",
    "--tooling-repo",
    "--runtime-executable",
    "--source-repo",
    "--source-archive",
    "--source-member-manifest",
  ]);
  const singletons = new Map();
  const inputs = [];
  const dependencies = [];
  const outputs = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--input") {
      if (index + 3 >= argv.length) {
        failProvenance("CLI", "input-arity");
      }
      inputs.push(Object.freeze({
        role: argv[index + 1],
        identifier: argv[index + 2],
        path: argv[index + 3],
      }));
      index += 3;
      continue;
    }
    if (argument === "--dependency") {
      if (index + 3 >= argv.length) {
        failProvenance("CLI", "dependency-arity");
      }
      dependencies.push(Object.freeze({
        role: argv[index + 1],
        identifier: argv[index + 2],
        path: argv[index + 3],
      }));
      index += 3;
      continue;
    }
    if (argument === "--output") {
      if (index + 4 >= argv.length) {
        failProvenance("CLI", "output-arity");
      }
      outputs.push(Object.freeze({
        role: argv[index + 1],
        identifier: argv[index + 2],
        format: argv[index + 3],
        path: argv[index + 4],
      }));
      index += 4;
      continue;
    }
    if (
      !singletonFlags.has(argument)
      || singletons.has(argument)
      || index + 1 >= argv.length
      || argv[index + 1].startsWith("--")
    ) {
      failProvenance("CLI", "unknown-or-duplicate-option");
    }
    singletons.set(argument, argv[index + 1]);
    index += 1;
  }
  for (const required of ["--record", "--tooling-repo", "--runtime-executable"]) {
    if (!singletons.has(required)) {
      failProvenance("CLI", "required-options");
    }
  }
  return Object.freeze({
    record: singletons.get("--record"),
    toolingRepo: singletons.get("--tooling-repo"),
    runtimeExecutable: singletons.get("--runtime-executable"),
    sourceRepo: singletons.get("--source-repo"),
    sourceArchive: singletons.get("--source-archive"),
    sourceMemberManifest: singletons.get("--source-member-manifest"),
    inputs: Object.freeze(inputs),
    dependencies: Object.freeze(dependencies),
    outputs: Object.freeze(outputs),
  });
}

async function main() {
  const result = await verifyGeneratedDataProvenanceInternal(
    parseOptions(process.argv.slice(2)),
  );
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
    const safe = error instanceof GeneratedDataProvenanceError
      ? error
      : new GeneratedDataProvenanceError("CLI", "unexpected-cli-failure");
    process.stderr.write("ERROR " + safe.phase + ": " + safe.reason + "\n");
    process.exitCode = 1;
  });
}
