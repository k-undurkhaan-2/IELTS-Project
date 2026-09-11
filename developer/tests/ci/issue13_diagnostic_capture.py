"""NON-AUTHORITATIVE / DIAGNOSTIC-ONLY paired preimages for Issue 13.

Only the terminal CLI hook calls this writer. CI never reads these files. Nothing
here changes command evidence, derives an authorization envelope, or grants a gate.
The separate `compare` entry point reads only this diagnostic schema.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import issue13_diagnostic_reporters as reporters

MARKER = "NON-AUTHORITATIVE / DIAGNOSTIC-ONLY"
VERSION = 1
MAX_COMMANDS = 8
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_PUBLIC_BYTES = 256 * 1024
MAX_TOTAL_BYTES = MAX_COMMANDS * (2 * reporters.MAX_STREAM_BYTES + MAX_RECORD_BYTES) + MAX_PUBLIC_BYTES
MAX_COMMAND_INVENTORY = 4096
FAMILIES = ("frontend-security", "backend-canonical", "standalone-packaging")
FRONTEND_IDS = frozenset({
    "d2dfc48e671db284a5aa30caa653d3b6c1e4fbb24aedf560c23488077666cf64",
    "bc0f8fad69fa4449a9b1496fef3b8234ec2e47364bd3d0e88dd435ef41dd7078",
    "410b1a676541c6a2bbe516852c6186e2825df76d2ce643d57c0aa911012af089",
})
IDENTITY_FIELDS = (
    "scope", "resultStatus", "testIds", "fileLocations", "assertionNames",
    "expectedValues", "observedValues", "errorClasses", "errorMessages", "pathAuthority",
)
STATE_FIELDS = (
    "executed", "started", "setupFailure", "exitCode", "timeoutStatus", "outputLimitStatus",
    "containment", "processTreeStatus", "containmentDisposition", "descendantsObserved",
    "descendantsReaped", "descendantsTerminated", "descendantsSurviving", "error",
    "processTreeError", "limitReason", "closureMutationState", "runtimeClosureGuard",
)
CONTEXT_FIELDS = (
    "commandPlanDigest", "producerObservationSetDigest", "producerObservationUniverseDigest",
    "producerTranscriptDigest", "authorizationContextBindingDigest",
    "executionInputBundleDigest", "dependencyClosureDigest", "runtimeClosureDigest",
)
STREAM_FIELDS = ("stdoutSha256", "stderrSha256", "stdoutBytesObserved", "stderrBytesObserved")
TOOL_FIELDS = ("role", "canonicalPath", "size", "sha256", "stableIdentity", "leaseHeld",
               "trustedRootClassification", "versionOutput", "version", "implementation", "available")
AUTHORITY_FIELDS = (
    "commandId", "ordinal", "commandClass", "commandRole", "profile", "platform",
    "argv", "logicalArgv", "executionArgv", "executionInputMode", "executionInputSha256",
    "executionInputSize", "cwd", "toolRole", "resolvedExecutablePath", "resolvedExecutableSize",
    "resolvedExecutableSha256", "resolvedExecutableFileIdentity", "targets", "resultSemantics",
    "allowedExecutionExits", "executionLease", "required",
)


class DiagnosticError(ValueError):
    """Messages are fixed categories; never interpolate input bytes or paths."""


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json(data):
    return (json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")


def _bounded_json(value, limit):
    nodes = 0

    def walk(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 60_000 or depth > 16:
            raise DiagnosticError("schema-bound")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not -(2 ** 31) <= item <= 2 ** 40:
                raise DiagnosticError("schema-bound")
        elif type(item) is str:
            if len(item.encode("utf-8")) > reporters.MAX_STREAM_BYTES:
                raise DiagnosticError("schema-bound")
        elif type(item) is list:
            if len(item) > reporters.MAX_LINES:
                raise DiagnosticError("schema-bound")
            for child in item:
                walk(child, depth + 1)
        elif type(item) is dict:
            if len(item) > 128 or any(type(k) is not str or len(k) > 128 for k in item):
                raise DiagnosticError("schema-bound")
            for child in item.values():
                walk(child, depth + 1)
        else:
            raise DiagnosticError("schema-type")
    walk(value, 0)
    data = _json(value)
    if len(data) > limit:
        raise DiagnosticError("schema-bound")
    return data


# An exact-key public schema: no free text, arbitrary property names, raw identities,
# paths, reporter output, environment values, or authorization documents are allowed.
def _digest(v):
    return type(v) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", v) is not None


def _count(v):
    return type(v) is int and 0 <= v <= 2 ** 40


def _nullable(check):
    return lambda v: v is None or check(v)


def _enum(*values):
    return lambda v: type(v) is str and v in values


def _list(schema, count):
    return (schema, count)


def _check(value, schema):
    if isinstance(schema, dict):
        if type(value) is not dict or set(value) != set(schema):
            raise DiagnosticError("schema-keys")
        for key, child in schema.items():
            _check(value[key], child)
    elif isinstance(schema, tuple):
        if type(value) is not list or len(value) > schema[1]:
            raise DiagnosticError("schema-bound")
        for child in value:
            _check(child, schema[0])
    elif not schema(value):
        raise DiagnosticError("schema-value")


BOOL = lambda v: type(v) is bool
EXIT = _nullable(lambda v: type(v) is int and -(2 ** 31) <= v <= 2 ** 32)
DIGEST_MAP = lambda keys: {k: _digest for k in keys}
STREAM_SCHEMA = {"sha256": _digest, "bytesObserved": _count, "retainedBytes": _count,
                 "retainedSha256": _nullable(_digest), "exact": BOOL}
REPORT_SCHEMA = {
    "kind": _enum("frontend-spec", "npm-spec", "python-unittest"), "complete": BOOL,
    "reasons": _list(_enum(*reporters.REASONS), len(reporters.REASONS)),
    "members": _list({"nameDigest": _digest, "status": _enum(*reporters.STATUSES)}, reporters.MAX_TESTS),
    "counts": {k: _nullable(_count) for k in sorted(set(reporters.NODE_COUNTS + reporters.PYTHON_COUNTS))},
    "semanticDigest": _digest, "membershipDigest": _digest, "unrecognizedCount": _count,
    "unrecognizedDigest": _digest, "presentationDigest": _digest, "bannerDigest": _digest,
}
FAILURE_SCHEMA = {
    "signatureDigest": _digest, "signatureCategory": _enum("pass", "known-node-failure", "identity-digest", "other"),
    "identityDigest": _digest,
    "fields": {k: {"present": BOOL, "digest": _digest, "cardinality": _nullable(_count)} for k in IDENTITY_FIELDS},
    "membersDigest": _digest, "sourceOutputDigest": _digest, "observationRecordDigest": _digest,
    "pathAuthorityDigest": _digest,
    "pathAuthority": {"present": BOOL, "kind": _enum("source-snapshot-bound", "none", "OTHER"),
                      "targets": _count, "tools": _count, "unmapped": _count, "literalPlaceholders": _count},
    "rawValidationErrors": _count, "sourceBinding": BOOL, "recordBinding": BOOL,
    "setBinding": BOOL, "captureObservationBinding": BOOL,
    "processSemanticDigest": _digest,
}
ROW_SCHEMA = {
    "ordinal": _count, "commandIdDigest": _digest, "family": _enum(*FAMILIES),
    "exitCode": EXIT, "captureExitCode": EXIT, "captureExecuted": BOOL,
    "commandRecordDigest": _digest, "expectedAuthorityDigest": _digest,
    "authorityFieldDigests": DIGEST_MAP(AUTHORITY_FIELDS),
    "stateFieldDigests": DIGEST_MAP(STATE_FIELDS + ("cleanupState", "mutationDetected")),
    "contextFieldDigests": DIGEST_MAP(CONTEXT_FIELDS),
    "toolAuthorityFieldDigests": {role: {kind: DIGEST_MAP(TOOL_FIELDS) for kind in ("lease", "runtimeClosure")}
                                 for role in ("npm", "node", "python")},
    "commandValidationErrors": _count, "commandHardFailure": BOOL, "commandAuthorityMatches": BOOL,
    "streams": {"stdout": STREAM_SCHEMA, "stderr": STREAM_SCHEMA},
    "sourceOutputDigest": _digest, "sourceOutputSemanticDigest": _digest,
    "reporter": REPORT_SCHEMA, "observations": _list(FAILURE_SCHEMA, 1),
    "adapterAuthority": {
        "sourceBound": BOOL, "invocationMatches": BOOL, "packageDigest": _digest,
        "scriptDigest": _digest, "lifecycleDigest": _digest, "inventoryDigest": _digest,
        "npmToolDigest": _digest, "nodeToolDigest": _digest, "pythonToolDigest": _digest,
        "executionArgvDigest": _digest,
        "packageNameDigest": _digest, "packageVersionDigest": _digest,
        "testScriptDigest": _digest, "pretestScriptDigest": _digest, "posttestScriptDigest": _digest,
    },
    "containment": {
        "backend": _enum("windows-job-object", "linux-subreaper-pidfd-proc-supervisor", "not-started", "OTHER"),
        "status": _enum("contained-clean", "cleanup-failed", "setup-failed", "not-started", "OTHER"),
        "disposition": _enum("natural-exit-reaped", "no-descendants", "forced-termination", "survivors", "unknown-ancestry", "not-applicable", "OTHER"),
        "observed": _count, "reaped": _count, "terminated": _count, "surviving": _count,
        "cleanup": _enum("closed", "open", "failed", "not-started", "OTHER"), "mutation": _nullable(BOOL),
        "timeout": _enum("within-limit", "TIMED-OUT", "OTHER"),
        "outputLimit": _enum("within-limit", "OUTPUT-LIMIT-EXCEEDED", "OTHER"),
        "errorPresent": BOOL, "processTreeErrorPresent": BOOL,
    },
    "privateRecordSha256": _digest, "privateRecordBytes": _count,
}
PUBLIC_SCHEMA = {
    "schema": _enum("Issue13DiagnosticCapture"), "version": lambda v: type(v) is int and v == VERSION,
    "authority": _enum(MARKER), "transaction": lambda v: type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) is not None,
    "phase": _enum("producer", "fresh-replay"), "platform": _enum("ubuntu", "windows"),
    "profile": _enum("all", "frontend", "backend", "standalone", "policy", "static"),
    "selectedCount": _count, "overflowCount": _count,
    "records": _list(ROW_SCHEMA, MAX_COMMANDS),
    "errors": _list({"ordinal": _count, "reason": _enum("capture-unavailable")}, MAX_COMMANDS),
}


def validate_public(value):
    _check(value, PUBLIC_SCHEMA)
    if len(value["records"]) + len(value["errors"]) + value["overflowCount"] != value["selectedCount"]:
        raise DiagnosticError("schema-count")
    ordinals = [r["ordinal"] for r in value["records"]] + [r["ordinal"] for r in value["errors"]]
    if len(set(ordinals)) != len(ordinals):
        raise DiagnosticError("schema-duplicate")
    return _bounded_json(value, MAX_PUBLIC_BYTES)


def _is_reparse(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _check_parent(root, repo_root):
    if not root.is_absolute() or len(str(root)) > 1024 or any(x in str(root) for x in ("\0", "\r", "\n")):
        raise DiagnosticError("destination")
    if root == repo_root or root.is_relative_to(repo_root) or repo_root.is_relative_to(root):
        raise DiagnosticError("checkout-destination")
    for parent in (root.parent, *root.parent.parents):
        metadata = parent.lstat()
        if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise DiagnosticError("reparse-destination")
        # Also exclude other worktrees/checkouts, regardless of this runner's root.
        if os.path.lexists(parent / ".git") or parent.name == ".ci-results":
            raise DiagnosticError("checkout-destination")
    if root.parent.resolve(strict=True) != root.parent:
        raise DiagnosticError("destination")


def _restrict_windows_directory(path):
    """Protected DACL: current token user and SYSTEM only, inheritable to files."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    advapi.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    advapi.SetFileSecurityW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    token, sid_text, descriptor = wintypes.HANDLE(), wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise DiagnosticError("private-permissions")
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65_536:
            raise DiagnosticError("private-permissions")
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise DiagnosticError("private-permissions")
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
            raise DiagnosticError("private-permissions")
        sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise DiagnosticError("private-permissions")
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise DiagnosticError("private-permissions")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(sid_text)
        if token:
            kernel.CloseHandle(token)


class PrivateDestination:
    def __init__(self, root, repo_root):
        self.root = Path(root)
        _check_parent(self.root, Path(repo_root).resolve(strict=True))
        # Existing directories, links, files and previous evidence are never reused.
        os.mkdir(self.root, 0o700)
        _restrict_windows_directory(self.root)
        self.identity = self.root.stat()
        self.total = 0

    def write(self, name, data, limit):
        if not re.fullmatch(r"(?:public\.json|[0-7]\.(?:json|stdout\.bin|stderr\.bin))", name):
            raise DiagnosticError("destination-name")
        if len(data) > limit or self.total + len(data) > MAX_TOTAL_BYTES:
            raise DiagnosticError("file-bound")
        current = self.root.lstat()
        if _is_reparse(current) or (current.st_dev, current.st_ino) != (self.identity.st_dev, self.identity.st_ino):
            raise DiagnosticError("destination-changed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.root / name, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise DiagnosticError("destination-file")
            with os.fdopen(fd, "wb", closefd=False) as out:
                out.write(data)
                out.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        self.total += len(data)


def _source(repo_root, expected, relative):
    if relative not in ("backend/package.json", "developer/tests/ci/test_standalone_packaging.py"):
        raise DiagnosticError("source-allowlist")
    matches = [t for t in expected.get("targets", []) if t.get("path") == relative]
    if len(matches) != 1:
        raise DiagnosticError("source-authority")
    path = Path(repo_root) / relative
    for part in (path, *path.parents):
        metadata = part.lstat()
        if _is_reparse(metadata):
            raise DiagnosticError("source-reparse")
        if part == Path(repo_root):
            break
    if path.stat().st_size > 512 * 1024 or not path.is_file():
        raise DiagnosticError("source-bound")
    with path.open("rb") as source:
        data = source.read(512 * 1024 + 1)
    if len(data) > 512 * 1024:
        raise DiagnosticError("source-bound")
    target = matches[0]
    if len(data) != target.get("size") or hashlib.sha256(data).hexdigest() != target.get("sha256"):
        raise DiagnosticError("source-changed")
    return data


def _source_authority(ci, runner, expected, record, repo_root):
    result = {k: reporters.digest(None) for k in ROW_SCHEMA["adapterAuthority"] if k not in ("sourceBound", "invocationMatches")}
    result.update(sourceBound=False, invocationMatches=False)
    tools = getattr(runner, "tool_authority_evidence", {})
    for tool in ("npm", "node", "python"):
        result[tool + "ToolDigest"] = ci.canonical_failure_digest(tools.get(tool))
    result["executionArgvDigest"] = ci.canonical_failure_digest(expected.get("executionArgv"))
    banner, inventory = None, None
    if record["commandClass"] == "backend-canonical":
        try:
            data = _source(repo_root, expected, "backend/package.json")
            package = ci.strict_json_loads(data.decode("utf-8"), label="diagnostic package")
            scripts = package.get("scripts", {})
            selected = [package.get("name"), package.get("version"), scripts.get("test")]
            if any(type(s) is not str or not 0 < len(s) <= 1024 for s in selected):
                raise DiagnosticError("source-schema")
            result["packageDigest"] = sha(data)
            result["scriptDigest"] = reporters.digest({k: scripts.get(k) for k in ("pretest", "test", "posttest")})
            result["packageNameDigest"] = reporters.digest(selected[0])
            result["packageVersionDigest"] = reporters.digest(selected[1])
            for script in ("test", "pretest", "posttest"):
                result[script + "ScriptDigest"] = reporters.digest(scripts.get(script))
            banner = [f"{selected[0]}@{selected[1]} test", selected[2]]
            result["lifecycleDigest"] = reporters.digest(banner)
            result["sourceBound"] = True
            argv = expected.get("executionArgv", [])
            logical = expected.get("logicalArgv", [])
            result["invocationMatches"] = (
                expected.get("toolRole") == "npm-backend-test"
                and len(argv) == 5 and argv[2:] == ["--prefix", "backend", "test"]
                and len(logical) == 4 and logical[1:] == argv[2:] and logical[0] == argv[1]
                and len(record.get("actualExecutionArgv", [])) == 5 and record["actualExecutionArgv"][2:] == argv[2:]
                and selected[2] == "node --test" and not scripts.get("pretest") and not scripts.get("posttest")
            )
        except (OSError, ValueError, TypeError, KeyError):
            pass
    elif record["commandClass"] == "standalone-packaging":
        try:
            data = _source(repo_root, expected, "developer/tests/ci/test_standalone_packaging.py")
            tree = ast.parse(data)
            classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "StandalonePackagingTest"]
            if len(classes) != 1:
                raise DiagnosticError("source-schema")
            names = [n.name for n in classes[0].body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")]
            if not 0 < len(names) <= reporters.MAX_TESTS or len(set(names)) != len(names):
                raise DiagnosticError("source-schema")
            inventory = ["__main__.StandalonePackagingTest." + n for n in sorted(names)]
            result.update(sourceBound=True, packageDigest=sha(data), inventoryDigest=reporters.digest(inventory))
            argv = expected.get("executionArgv", [])
            result["invocationMatches"] = (expected.get("toolRole") == "python-standalone-test"
                and len(argv) == 3 and argv[1:] == ["-B", "developer/tests/ci/test_standalone_packaging.py"]
                and len(record.get("actualExecutionArgv", [])) == 3 and record["actualExecutionArgv"][1:] == argv[1:])
        except (OSError, ValueError, TypeError, SyntaxError):
            pass
    else:
        result["sourceBound"] = bool(expected.get("targets"))
        result["invocationMatches"] = (len(record.get("actualExecutionArgv", [])) == len(expected.get("executionArgv", []))
            and record.get("actualExecutionArgv", [])[1:] == expected.get("executionArgv", [])[1:])
    return result, banner, inventory


def _category(value, options):
    return value if value in options else "OTHER"


def _stream(record, capture, name):
    raw = getattr(capture, name + "_raw", None)
    retained = raw if type(raw) is bytes and len(raw) <= reporters.MAX_STREAM_BYTES else None
    declared = "sha256:" + str(record.get(name + "Sha256", ""))
    observed = record.get(name + "BytesObserved", 0)
    info = {"sha256": declared, "bytesObserved": observed, "retainedBytes": len(retained) if retained is not None else 0,
            "retainedSha256": sha(retained) if retained is not None else None,
            "exact": retained is not None and sha(retained) == declared and len(retained) == observed}
    return retained, info


def _observations(ci, record, capture):
    raw_set = record.get("producerObservations", [])
    if type(raw_set) is not list or len(raw_set) > 1:
        raise DiagnosticError("observation-bound")
    _bounded_json(raw_set, MAX_RECORD_BYTES)
    public, derived = [], []
    for raw in raw_set:
        errors = ci._validate_raw_observation(raw, label="diagnostic", source=record)
        if errors:
            # Do not call a classifier on malformed observations or publish them as facts.
            raise DiagnosticError("observation-schema")
        facts = ci._raw_failure_outputs(copy.deepcopy(raw), copy.deepcopy(record))
        identity = facts["failureIdentity"]
        if set(identity) - set(IDENTITY_FIELDS):
            raise DiagnosticError("identity-schema")
        path = raw.get("failurePathAuthority")
        fields = {"executed": capture.executed, "exitCode": capture.exit_code,
                  "stdout": capture.identity_stdout if capture.identity_stdout is not None else capture.stdout,
                  "stderr": capture.identity_stderr if capture.identity_stderr is not None else capture.stderr,
                  "error": capture.identity_error if capture.identity_error is not None else capture.error}
        binding = None
        if raw["sourceResultId"] in ci.R03_FAILURE_TARGETS or raw["sourceResultId"] in ci.R11_KNOWN_DEBT_FAILURE_TARGETS:
            if isinstance(capture.failure_path_authority, ci.FailurePathAuthority):
                fields, binding = ci.canonicalize_failure_identity_value(fields, capture.failure_path_authority)
        reconstructed = ci.make_raw_observation(capture.command_id, record["ordinal"], raw["observationOrdinal"],
            "process-output-v1", raw["sourceResultId"], raw["sourcePath"], fields, ci.command_output_digest(record),
            failure_path_authority=binding)
        signature = facts["signature"]
        signature_category = ("pass" if signature == "pass" else "identity-digest" if _digest(signature)
                              else "known-node-failure" if signature in {v["signature"] for v in ci.KNOWN_NODE_FAILURES.values()} else "other")
        public.append({
            "signatureDigest": ci.canonical_failure_digest(signature), "signatureCategory": signature_category,
            "identityDigest": facts["failureIdentityHash"],
            "fields": {k: {"present": k in identity, "digest": ci.canonical_failure_digest(identity.get(k)),
                           "cardinality": len(identity[k]) if isinstance(identity.get(k), (list, dict)) else None} for k in IDENTITY_FIELDS},
            "membersDigest": ci.canonical_failure_digest(facts["derivedFailureMembers"]),
            "sourceOutputDigest": raw["sourceOutputDigest"], "observationRecordDigest": raw["producerRecordDigest"],
            "pathAuthorityDigest": ci.canonical_failure_digest(path),
            "pathAuthority": {"present": path is not None,
                "kind": "none" if path is None else "source-snapshot-bound" if path.get("canonicalizationKind") == "SOURCE-SNAPSHOT-BOUND-FAILURE-PATHS-V1" else "OTHER",
                "targets": len((path or {}).get("authorizedTargetPaths", [])), "tools": len((path or {}).get("authorizedToolRoles", [])),
                "unmapped": len((path or {}).get("unmappedAbsolutePathDigests", [])), "literalPlaceholders": len((path or {}).get("literalPlaceholderDigests", []))},
            "rawValidationErrors": len(errors), "sourceBinding": raw["sourceOutputDigest"] == ci.command_output_digest(record),
            "recordBinding": raw["producerRecordDigest"] == ci._producer_record_digest({k: v for k, v in raw.items() if k != "producerRecordDigest"}),
            "setBinding": record["producerObservationSetDigest"] == ci.producer_observation_set_digest(raw_set),
            "captureObservationBinding": reconstructed == raw, "processSemanticDigest": ci.canonical_failure_digest(facts),
        })
        derived.append(facts)
    return public, derived, copy.deepcopy(raw_set)


def build_record(ci, runner, record, expected, capture, repo_root):
    # All CI functions receive detached dictionaries. No function called here runs
    # commands, changes classifications, finalizes transcripts, or creates envelopes.
    record, expected = copy.deepcopy(record), copy.deepcopy(expected)
    errors = []
    hard = ci._validate_command_record(record, record["ordinal"], errors, expected_record=expected)
    authority_matches = ci._portable_command_plan_value([
        {k: record.get(k) for k in expected}
    ]) == ci._portable_command_plan_value([expected])
    stdout, out_info = _stream(record, capture, "stdout")
    stderr, err_info = _stream(record, capture, "stderr")
    authority, banner, inventory = _source_authority(ci, runner, expected, record, repo_root)
    observations, facts, raw_set = _observations(ci, record, capture)
    family = record["commandClass"]
    if family == "standalone-packaging":
        report = reporters.unittest_report(stdout, stderr, record.get("exitCode"), inventory=inventory)
    else:
        report = reporters.node_report(stdout, stderr, record.get("exitCode"), npm_banner=banner,
                                       frontend=family == "frontend-security")
    if not authority["sourceBound"] or not authority["invocationMatches"] or not authority_matches or errors:
        report["reasons"] = sorted(set(report["reasons"] + ["authority"]))
    if (hard or not out_info["exact"] or not err_info["exact"] or not record.get("executed")
        or record.get("timeoutStatus") != "within-limit" or record.get("outputLimitStatus") != "within-limit"
        or record.get("processTreeStatus") != "contained-clean" or record.get("error") or record.get("processTreeError")):
        report["reasons"] = sorted(set(report["reasons"] + ["execution-state"]))
    if family != "standalone-packaging" and (len(observations) != 1 or not all(
        all(o[k] for k in ("sourceBinding", "recordBinding", "setBinding", "captureObservationBinding")) for o in observations
    )):
        report["reasons"] = sorted(set(report["reasons"] + ["authority"]))
    report["complete"] = not report["reasons"]
    private = {
        "schema": "Issue13PrivatePreimages", "version": VERSION, "authority": MARKER,
        "reporter": report, "failureOutputs": facts, "observationSetInputs": raw_set,
        "sourceOutputInputs": {k: record.get(k) for k in STREAM_FIELDS},
    }
    private_bytes = validate_private(ci, private)
    public_report = {k: v for k, v in report.items() if k not in ("members", "counts")}
    public_report["members"] = [{"nameDigest": reporters.digest(x["name"]), "status": x["status"]} for x in report["members"]]
    public_report["counts"] = {k: report["counts"].get(k) for k in REPORT_SCHEMA["counts"]}
    bundle = record.get("protectedTargetBundle") or {}
    state = {**record, "cleanupState": bundle.get("cleanupState"), "mutationDetected": bundle.get("mutationDetected")}
    closure = getattr(runner, "runtime_closure_document", {}) or {}
    leases = getattr(runner, "tool_authority_evidence", {}) or {}
    tool_fields = {role: {
        "lease": {k: ci.canonical_failure_digest((leases.get(role) or {}).get(k)) for k in TOOL_FIELDS},
        "runtimeClosure": {k: ci.canonical_failure_digest((closure.get(key) or {}).get(k)) for k in TOOL_FIELDS},
    } for role, key in (("npm", "npmEntrypoint"), ("node", "nodeExecutable"), ("python", "pythonExecutable"))}
    row = {
        "ordinal": record["ordinal"], "commandIdDigest": sha(record["commandId"].encode("utf-8")), "family": family,
        "exitCode": record.get("exitCode"), "captureExitCode": capture.exit_code, "captureExecuted": capture.executed,
        "commandRecordDigest": ci.canonical_failure_digest(record), "expectedAuthorityDigest": ci.canonical_failure_digest(expected),
        "authorityFieldDigests": {k: ci.canonical_failure_digest(expected.get(k)) for k in AUTHORITY_FIELDS},
        "stateFieldDigests": {k: ci.canonical_failure_digest(state.get(k)) for k in ROW_SCHEMA["stateFieldDigests"]},
        "contextFieldDigests": {k: ci.canonical_failure_digest(record.get(k)) for k in CONTEXT_FIELDS},
        "toolAuthorityFieldDigests": tool_fields,
        "commandValidationErrors": len(errors), "commandHardFailure": hard, "commandAuthorityMatches": authority_matches,
        "streams": {"stdout": out_info, "stderr": err_info}, "sourceOutputDigest": ci.command_output_digest(record),
        "sourceOutputSemanticDigest": reporters.digest({"reporter": report["semanticDigest"], "failureOutputs": facts}),
        "reporter": public_report, "observations": observations, "adapterAuthority": authority,
        "containment": {
            "backend": _category(record.get("containment"), ("windows-job-object", "linux-subreaper-pidfd-proc-supervisor", "not-started")),
            "status": _category(record.get("processTreeStatus"), ("contained-clean", "cleanup-failed", "setup-failed", "not-started")),
            "disposition": _category(record.get("containmentDisposition"), ("natural-exit-reaped", "no-descendants", "forced-termination", "survivors", "unknown-ancestry", "not-applicable")),
            **{k: record.get("descendants" + v, 0) for k, v in (("observed", "Observed"), ("reaped", "Reaped"), ("terminated", "Terminated"), ("surviving", "Surviving"))},
            "cleanup": _category(bundle.get("cleanupState"), ("closed", "open", "failed", "not-started")),
            "mutation": bundle.get("mutationDetected") if type(bundle.get("mutationDetected")) is bool else None,
            "timeout": _category(record.get("timeoutStatus"), ("within-limit", "TIMED-OUT")),
            "outputLimit": _category(record.get("outputLimitStatus"), ("within-limit", "OUTPUT-LIMIT-EXCEEDED")),
            "errorPresent": bool(record.get("error")), "processTreeErrorPresent": bool(record.get("processTreeError")),
        },
        "privateRecordSha256": sha(private_bytes), "privateRecordBytes": len(private_bytes),
    }
    _check(row, ROW_SCHEMA)
    return row, private_bytes, stdout, stderr


def validate_private(ci, value):
    """Exact outer/private schemas plus the unchanged bounded observation schema."""
    text = lambda v: type(v) is str and len(v.encode("utf-8")) <= reporters.MAX_NAME_BYTES
    private_report_schema = {**REPORT_SCHEMA,
        "members": _list({"name": text, "status": _enum(*reporters.STATUSES)}, reporters.MAX_TESTS)}
    kind = value.get("reporter", {}).get("kind") if type(value) is dict else None
    count_keys = reporters.PYTHON_COUNTS if kind == "python-unittest" else reporters.NODE_COUNTS
    private_report_schema["counts"] = {k: _nullable(_count) for k in count_keys}
    if type(value) is not dict or set(value) != {"schema", "version", "authority", "reporter", "failureOutputs", "observationSetInputs", "sourceOutputInputs"}:
        raise DiagnosticError("private-schema")
    if value["schema"] != "Issue13PrivatePreimages" or type(value["version"]) is not int or value["version"] != VERSION or value["authority"] != MARKER:
        raise DiagnosticError("private-schema")
    _check(value["reporter"], private_report_schema)
    _check(value["sourceOutputInputs"], {k: (lambda v: type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) is not None) if k.endswith("Sha256") else _count for k in STREAM_FIELDS})
    raw_set, facts = value["observationSetInputs"], value["failureOutputs"]
    if type(raw_set) is not list or type(facts) is not list or len(raw_set) > 1 or len(facts) != len(raw_set):
        raise DiagnosticError("private-observation-count")
    for raw, derived in zip(raw_set, facts):
        if ci._validate_raw_observation(raw, label="diagnostic", source=None) or raw.get("observationKind") != "process-output-v1":
            raise DiagnosticError("private-observation-schema")
        _check(derived, {
            "commandClass": _enum("frontend-security", "backend-canonical"),
            "testOrPathScope": text, "outcome": _enum("pass", "fail", "unavailable"), "signature": text,
            "failureIdentity": lambda v: type(v) is dict and not (set(v) - set(IDENTITY_FIELDS)),
            "failureIdentityHash": _digest, "parserSemantics": _enum("frontend-security-process-result-v1", "backend-canonical-process-result-v1"),
            "derivedFailureMembers": lambda v: type(v) is list and len(v) <= 4096,
        })
        source = {"commandClass": derived["commandClass"]}
        if ci._raw_failure_outputs(raw, source) != derived:
            raise DiagnosticError("private-derivation")
    return _bounded_json(value, MAX_RECORD_BYTES)


def relevant(record, platform_name):
    family = record.get("commandClass")
    if family == "frontend-security":
        return (hashlib.sha256(str(record.get("commandId")).encode("utf-8")).hexdigest() in FRONTEND_IDS
                or record.get("exitCode") != 0)
    return family == "backend-canonical" or (family == "standalone-packaging" and platform_name == "ubuntu")


def capture_completed_runner(ci, runner, *, root, transaction, phase, repo_root):
    """Post-decision writer. Caller must isolate failures from authoritative results."""
    if (type(transaction) is not str or not re.fullmatch(r"[0-9a-f]{32}", transaction)
        or phase not in ("producer", "fresh-replay") or runner.platform not in ("ubuntu", "windows")):
        raise DiagnosticError("configuration")
    if len(runner.command_results) > MAX_COMMAND_INVENTORY or len(runner.command_plan) > MAX_COMMAND_INVENTORY or len(runner.captures) > MAX_COMMAND_INVENTORY:
        raise DiagnosticError("command-bound")
    selected = [r for r in runner.command_results if relevant(r, runner.platform)]
    selected.sort(key=lambda r: r["ordinal"])
    destination = PrivateDestination(root, repo_root)
    summary = {"schema": "Issue13DiagnosticCapture", "version": VERSION, "authority": MARKER,
               "transaction": transaction, "phase": phase, "platform": runner.platform, "profile": runner.profile,
               "selectedCount": len(selected), "overflowCount": max(0, len(selected) - MAX_COMMANDS), "records": [], "errors": []}
    for index, record in enumerate(selected[:MAX_COMMANDS]):
        try:
            expected = [r for r in runner.command_plan if r.get("commandId") == record.get("commandId") and r.get("ordinal") == record.get("ordinal")]
            captures = [c for c in runner.captures if c.command_id == record.get("commandId")]
            if len(expected) != 1 or len(captures) != 1:
                raise DiagnosticError("capture-membership")
            row, private, stdout, stderr = build_record(ci, runner, record, expected[0], captures[0], repo_root)
            if stdout is not None:
                destination.write(f"{index}.stdout.bin", stdout, reporters.MAX_STREAM_BYTES)
            if stderr is not None:
                destination.write(f"{index}.stderr.bin", stderr, reporters.MAX_STREAM_BYTES)
            destination.write(f"{index}.json", private, MAX_RECORD_BYTES)
            summary["records"].append(row)
        except Exception:
            # Only a fixed category; exception messages can contain paths or output.
            summary["errors"].append({"ordinal": record["ordinal"], "reason": "capture-unavailable"})
    destination.write("public.json", validate_public(summary), MAX_PUBLIC_BYTES)
    return summary


def capture_from_cli(ci, args, runner, phase):
    """No diagnostic exception, return value, or file feeds an authoritative branch."""
    root = getattr(args, "issue13_diagnostic_root", None)
    transaction = getattr(args, "issue13_diagnostic_transaction", None)
    if root is None and transaction is None:
        return
    try:
        if not root or not transaction:
            raise DiagnosticError("configuration")
        capture_completed_runner(ci, runner, root=Path(root), transaction=transaction, phase=phase, repo_root=ci.REPO_ROOT)
    except Exception:
        print(MARKER + ": capture unavailable", file=sys.stderr)
    else:
        print(MARKER + ": bounded capture written", file=sys.stderr)


def _read_file(path, limit):
    before = path.lstat()
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise DiagnosticError("input-file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_nlink != 1:
            raise DiagnosticError("input-file")
        data = source.read(limit + 1)
    if len(data) > limit or len(data) != before.st_size:
        raise DiagnosticError("input-bound")
    return data


def read_capture(ci, root, repo_root):
    """Read only bounded diagnostic files, never return an executable CI document."""
    root = Path(root)
    _check_parent(root, Path(repo_root).resolve(strict=True))
    if _is_reparse(root.lstat()):
        raise DiagnosticError("input-directory")
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            if index >= MAX_COMMANDS * 3 + 1 or not re.fullmatch(r"(?:public\.json|[0-7]\.(?:json|stdout\.bin|stderr\.bin))", entry.name):
                raise DiagnosticError("input-inventory")
    value = ci.strict_json_loads(_read_file(root / "public.json", MAX_PUBLIC_BYTES).decode("utf-8"), label="diagnostic")
    validate_public(value)
    indices = sorted([r["ordinal"] for r in value["records"]] + [r["ordinal"] for r in value["errors"]])
    for row in value["records"]:
        index = indices.index(row["ordinal"])
        data = _read_file(root / f"{index}.json", MAX_RECORD_BYTES)
        if sha(data) != row["privateRecordSha256"] or len(data) != row["privateRecordBytes"]:
            raise DiagnosticError("input-binding")
        private = ci.strict_json_loads(data.decode("utf-8"), label="diagnostic")
        validate_private(ci, private)
        report = private["reporter"]
        expected_report = {k: v for k, v in report.items() if k not in ("members", "counts")}
        expected_report["members"] = [{"nameDigest": reporters.digest(m["name"]), "status": m["status"]} for m in report["members"]]
        expected_report["counts"] = {k: report["counts"].get(k) for k in REPORT_SCHEMA["counts"]}
        if row["reporter"] != expected_report or row["sourceOutputDigest"] != ci.command_output_digest(private["sourceOutputInputs"]):
            raise DiagnosticError("input-binding")
        for stream in ("stdout", "stderr"):
            info = row["streams"][stream]
            if info["retainedSha256"] is not None:
                raw = _read_file(root / f"{index}.{stream}.bin", reporters.MAX_STREAM_BYTES)
                if sha(raw) != info["retainedSha256"] or len(raw) != info["retainedBytes"]:
                    raise DiagnosticError("input-binding")
                if info["exact"] and (sha(raw) != info["sha256"] or len(raw) != info["bytesObserved"]):
                    raise DiagnosticError("input-binding")
    return value


def compare_public(producer, replay):
    """Describe exact diagnostic field differences; never declare CI equivalence."""
    validate_public(producer)
    validate_public(replay)
    if (producer["phase"] != "producer" or replay["phase"] != "fresh-replay"
        or any(producer[k] != replay[k] for k in ("transaction", "platform", "profile"))):
        raise DiagnosticError("pair-context")
    def keyed(summary):
        return {(r["ordinal"], r["commandIdDigest"], r["family"]): r for r in summary["records"]}
    left, right = keyed(producer), keyed(replay)
    rows = []
    compare_keys = ("exitCode", "captureExitCode", "captureExecuted", "authorityFieldDigests", "toolAuthorityFieldDigests", "stateFieldDigests",
                    "contextFieldDigests", "streams", "sourceOutputDigest", "sourceOutputSemanticDigest",
                    "reporter", "observations", "adapterAuthority", "containment",
                    "commandValidationErrors", "commandHardFailure", "commandAuthorityMatches")
    def changes(a, b, prefix):
        if a == b:
            return []
        if type(a) is dict and type(b) is dict:
            return [p for k in sorted(a.keys() | b.keys()) for p in changes(a.get(k), b.get(k), prefix + "." + k)]
        if prefix == "observations" and len(a) == len(b) == 1:
            return changes(a[0], b[0], prefix + ".0")
        return [prefix]
    for key in sorted(left.keys() | right.keys())[:MAX_COMMANDS]:
        if key not in left or key not in right:
            rows.append({"ordinal": key[0], "commandIdDigest": key[1], "family": key[2], "pair": "missing",
                         "changedFields": [], "changedFieldOverflow": 0})
            continue
        changed = [p for k in compare_keys for p in changes(left[key][k], right[key][k], k)]
        rows.append({"ordinal": key[0], "commandIdDigest": key[1], "family": key[2], "pair": "present",
                     "changedFields": changed[:256], "changedFieldOverflow": max(0, len(changed) - 256)})
    return {"schema": "Issue13DiagnosticComparison", "version": VERSION, "authority": MARKER,
            "transaction": producer["transaction"], "platform": producer["platform"], "profile": producer["profile"],
            "producerCaptureErrors": len(producer["errors"]), "replayCaptureErrors": len(replay["errors"]),
            "producerOverflow": producer["overflowCount"], "replayOverflow": replay["overflowCount"],
            "pairOverflow": max(0, len(left.keys() | right.keys()) - MAX_COMMANDS), "records": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=MARKER + ": compare two private capture directories", allow_abbrev=False)
    parser.add_argument("producer")
    parser.add_argument("replay")
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args(argv)
    import run_ci_foundation as ci
    try:
        result = compare_public(read_capture(ci, Path(args.producer), ci.REPO_ROOT), read_capture(ci, Path(args.replay), ci.REPO_ROOT))
        target = PrivateDestination(Path(args.output_root), ci.REPO_ROOT)
        target.write("public.json", _bounded_json(result, MAX_PUBLIC_BYTES), MAX_PUBLIC_BYTES)
    except Exception:
        print(MARKER + ": comparison unavailable", file=sys.stderr)
        return 1
    print(MARKER + ": comparison written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
