#!/usr/bin/env node

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  GeneratedDataProvenanceError,
  deriveOutputSetSha256,
  deriveStructuralRecordFacts,
  failProvenance,
  normalizeIdentityTestHooks,
  parseCanonicalProvenanceRecord,
  parseCanonicalProvenanceRegistry,
  parseCanonicalReleaseReference,
  readStableCanonicalDocument,
  sha256Bytes,
} from "./generated-data-provenance-core.mjs";

const RECORD_BINDING_KEYS = Object.freeze(["componentId", "path"]);

function exactKeys(value, expected, reason) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failProvenance("CLI", reason + "-object");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    failProvenance("CLI", reason + "-keys");
  }
}

function normalizeRecordBindings(value) {
  if (value === undefined) {
    return Object.freeze([]);
  }
  if (!Array.isArray(value)) {
    failProvenance("CLI", "record-bindings-array");
  }
  const components = new Set();
  return Object.freeze(value.map((entry) => {
    exactKeys(entry, RECORD_BINDING_KEYS, "record-binding");
    if (
      typeof entry.componentId !== "string"
      || entry.componentId.length === 0
      || typeof entry.path !== "string"
      || entry.path.length === 0
    ) {
      failProvenance("CLI", "record-binding-value");
    }
    if (components.has(entry.componentId)) {
      failProvenance("RELEASE_GATE", "duplicate-record-binding");
    }
    components.add(entry.componentId);
    return Object.freeze({ componentId: entry.componentId, path: entry.path });
  }));
}

function validateApiOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    failProvenance("CLI", "api-options-object");
  }
  const allowed = new Set([
    "registry",
    "releaseReference",
    "records",
    "testHooks",
  ]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      failProvenance("CLI", "api-option-key");
    }
  }
  if (
    typeof options.registry !== "string"
    || typeof options.releaseReference !== "string"
  ) {
    failProvenance("CLI", "api-required-option");
  }
  return Object.freeze({
    registry: options.registry,
    releaseReference: options.releaseReference,
    records: normalizeRecordBindings(options.records),
    hooks: normalizeIdentityTestHooks(options.testHooks),
  });
}

function requireExactRecordBindings(references, bindings) {
  const expected = new Set(references.map((entry) => entry.componentId));
  const supplied = new Set(bindings.map((entry) => entry.componentId));
  if (
    expected.size !== supplied.size
    || [...expected].some((componentId) => !supplied.has(componentId))
  ) {
    failProvenance("RELEASE_GATE", "record-binding-set");
  }
}

async function verifyGeneratedDataReleaseGateInternal(options) {
  const validatedOptions = validateApiOptions(options);
  const registryInput = await readStableCanonicalDocument(
    validatedOptions.registry,
    "REGISTRY_SCHEMA",
    "registry",
    validatedOptions.hooks,
  );
  const registry = parseCanonicalProvenanceRegistry(registryInput.bytes);
  const releaseInput = await readStableCanonicalDocument(
    validatedOptions.releaseReference,
    "RELEASE_REFERENCE_SCHEMA",
    "release-reference",
    validatedOptions.hooks,
  );
  const releaseReference = parseCanonicalReleaseReference(releaseInput.bytes);

  const registryByComponent = new Map(
    registry.records.map((entry) => [entry.componentId, entry]),
  );
  const releaseByComponent = new Map(
    releaseReference.components.map((entry) => [entry.componentId, entry]),
  );
  for (const entry of registry.records) {
    if (entry.relationship === "required" && !releaseByComponent.has(entry.componentId)) {
      failProvenance("RELEASE_GATE", "required-record-omitted");
    }
  }
  for (const entry of releaseReference.components) {
    const registered = registryByComponent.get(entry.componentId);
    if (!registered) {
      failProvenance("RELEASE_GATE", "unknown-release-component");
    }
    if (entry.recordSha256 !== registered.recordSha256) {
      failProvenance("RELEASE_GATE", "release-registry-hash-mismatch");
    }
  }

  requireExactRecordBindings(releaseReference.components, validatedOptions.records);
  const bindings = new Map(
    validatedOptions.records.map((entry) => [entry.componentId, entry]),
  );
  for (const reference of releaseReference.components) {
    const registered = registryByComponent.get(reference.componentId);
    const binding = bindings.get(reference.componentId);
    const recordInput = await readStableCanonicalDocument(
      binding.path,
      "RECORD_SCHEMA",
      "record",
      validatedOptions.hooks,
    );
    const recordSha256 = sha256Bytes(recordInput.bytes);
    if (
      recordSha256 !== reference.recordSha256
      || recordSha256 !== registered.recordSha256
    ) {
      failProvenance("RELEASE_GATE", "record-hash-mismatch");
    }
    const record = parseCanonicalProvenanceRecord(recordInput.bytes);
    if (record.component.componentId !== reference.componentId) {
      failProvenance("RELEASE_GATE", "record-component-id-mismatch");
    }
    if (record.component.recordId !== registered.recordId) {
      failProvenance("RELEASE_GATE", "record-id-mismatch");
    }
    if (deriveOutputSetSha256(record.outputs) !== reference.outputSetSha256) {
      failProvenance("RELEASE_GATE", "output-set-hash-mismatch");
    }
    const structural = deriveStructuralRecordFacts(record);
    if (
      structural.releaseEligible !== record.releaseEligible
      || structural.publicationBlocked !== record.publicationBlocked
    ) {
      failProvenance("RELEASE_GATE", "stored-eligibility-mismatch");
    }
    if (record.releaseEligible !== true || record.publicationBlocked !== false) {
      failProvenance("RELEASE_GATE", "referenced-ineligible-record");
    }
  }

  return Object.freeze({
    status: "ok",
    mode: "generated-data-release-gate",
    registryVerified: true,
    releaseReferenceVerified: true,
    generatedComponentCount: 0,
    gateSatisfied: true,
    releaseEligible: true,
    publicationBlocked: false,
    projectPublicationAuthorized: false,
  });
}

export async function verifyGeneratedDataReleaseGate(options = {}) {
  return verifyGeneratedDataReleaseGateInternal(options);
}

function parseOptions(argv) {
  const singletonFlags = new Set(["--registry", "--release-reference"]);
  const singletons = new Map();
  const records = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--record") {
      if (index + 2 >= argv.length) {
        failProvenance("CLI", "record-arity");
      }
      records.push(Object.freeze({
        componentId: argv[index + 1],
        path: argv[index + 2],
      }));
      index += 2;
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
  if (!singletons.has("--registry") || !singletons.has("--release-reference")) {
    failProvenance("CLI", "required-options");
  }
  return Object.freeze({
    registry: singletons.get("--registry"),
    releaseReference: singletons.get("--release-reference"),
    records: Object.freeze(records),
  });
}

async function main() {
  const result = await verifyGeneratedDataReleaseGateInternal(
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
