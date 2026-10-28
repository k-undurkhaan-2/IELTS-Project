"""Backend-only cross-job result comparison; never local execution authority.

The outer verifier binds ordinary validated producer evidence to a fresh replay.
Exact streams come from validated process observations, never diagnostic previews.
The diagnostic reporter is deliberately not imported as an acceptance parser.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path


SCHEMA = "BackendCanonicalPortableResult"
VERSION = 2
TEST_COUNT = 141
MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_STREAM_LINES = 2048
COUNTS = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
EXPECTED_COUNTS = dict(zip(COUNTS, (TEST_COUNT, 0, TEST_COUNT, 0, 0, 0, 0)))
AUTHORITY_KEYS = frozenset({
    "commandId", "ordinal", "commandClass", "commandRole", "required", "profile",
    "platform", "argv", "logicalArgv", "executionArgv", "executionInputMode",
    "executionInputSize", "executionInputSha256", "cwd", "toolRole",
    "resolvedExecutablePath", "resolvedExecutableSize", "resolvedExecutableSha256",
    "resolvedExecutableFileIdentity", "executionLease", "targets", "resultSemantics",
    "allowedExecutionExits",
})
# Full-line grammar recognizers only. No search/substitution/number normalization.
_DECIMAL = rb"[0-9]{1,16}(?:\.[0-9]{1,16})?"
_MEMBER = re.compile("✔ ".encode() + rb"(.{1,1024}) \((" + _DECIMAL + rb")ms\)")
_DURATION = re.compile("ℹ duration_ms ".encode() + rb"(" + _DECIMAL + rb")")
_STABLE_KEYS = frozenset({
    "deviceOrVolume", "inodeOrFileIndex", "creationOrChangeTimeNs", "writeTimeNs",
    "reparsePoint",
})


@dataclass(frozen=True)
class _ProtocolDescriptor:
    """An immutable authority-selected reporter contract."""

    version: int
    digest_domain: str
    path_count: int
    path_bytes: int
    path_sha256: str
    top_level_members: int
    nested_members: int
    total_executed_members: int
    hierarchy_inventory_digest: str
    parent_top_level_ordinal: int | None
    duration_spans: int
    retained_segments: int
    expected_counts: tuple[int, ...]


@dataclass(frozen=True)
class _ProtocolSelection:
    descriptor: _ProtocolDescriptor
    source_variant: str | None
    source_tuple: tuple[tuple[str, int, str], ...]


_V2_PROTOCOL = _ProtocolDescriptor(
    version=2,
    digest_domain="ieltmps-backend-canonical-portable-result-v2",
    path_count=914,
    path_bytes=40446,
    path_sha256="ea143c283e5b8b28098505a303530d0fc9c0c2731273f5bde84d00d5022c52aa",
    top_level_members=141,
    nested_members=0,
    total_executed_members=141,
    hierarchy_inventory_digest="c19b500fff55e20740791a59de895da19ccb51e8998f212413cec3c83cd8238a",
    parent_top_level_ordinal=None,
    duration_spans=142,
    retained_segments=143,
    expected_counts=(141, 0, 141, 0, 0, 0, 0),
)
_V3_PROTOCOL = _ProtocolDescriptor(
    version=3,
    digest_domain="ieltmps-backend-canonical-portable-result-v3",
    path_count=916,
    path_bytes=40530,
    path_sha256="5b9401b4afa1b964ebd2887ec023c247a605d4faad6532de6cc168720f70c786",
    top_level_members=148,
    nested_members=6,
    total_executed_members=154,
    hierarchy_inventory_digest="3217938708947463015beba935fad163b387a6ba2969625679f326c7770e843a",
    parent_top_level_ordinal=144,
    duration_spans=155,
    retained_segments=156,
    expected_counts=(154, 0, 154, 0, 0, 0, 0),
)

_V3_SOURCE_PROFILES = (
    (
        "LF",
        564843,
        (
            ("backend/Dockerfile", 1222,
             "be87830d91db221b19de4a67c67b953ba6ee111c29372e87c7e6397415d1c825"),
            ("backend/package.json", 736,
             "64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c"),
            ("backend/src/app.js", 81856,
             "69a8947b2785ca73b2d31852da35e0e247af6197764426a408a805581b0e036f"),
            ("backend/src/publicListeningFrontend.js", 35922,
             "7f9e8b30341108af540d0694908411e12bdeaea0135af468856a2b3ee0f459e4"),
            ("backend/test/backend.test.js", 410758,
             "787d7c6763736960f7013b17161f2fc4445b2005a1d6c8b3ca04eb4cf13558ca"),
            ("backend/test/publicListeningFrontend.test.js", 34349,
             "6aab71707f520837fbfce399414fe3f08be0e130988aa2bf52bd6033e6676bab"),
        ),
    ),
    (
        "CRLF",
        577131,
        (
            ("backend/Dockerfile", 1258,
             "6a65d29fe167a6d9ef2364e1e3297257953ae31cbc82512ea4c103c6b145aebd"),
            ("backend/package.json", 763,
             "2a4f5fc9c2587ff92598f83e9516212ced6304d5c4bceecf0797084423c7bdf7"),
            ("backend/src/app.js", 83914,
             "da97a8be86a308a13710b7224d88ff39d120d239b33b049e09cd4f05ff5f69aa"),
            ("backend/src/publicListeningFrontend.js", 36794,
             "15772d7017cfc72fe63a409190fea626526d91522136f66d763285cb25b191bf"),
            ("backend/test/backend.test.js", 419284,
             "b638658447d0760d7ff6ce29bc3dd73dd02415cbe9e5e72f65d32d70b73988a3"),
            ("backend/test/publicListeningFrontend.test.js", 35118,
             "11bb1b9cb081fe93bf7e1b9d9af87d46778c23095e35fa89dfd7f5e38f5d201e"),
        ),
    ),
)

_V3_TOP_LEVEL_NAMES = (
    "Docker COPY and ADD parser rejects private roots across equivalent forms",
    "docker image hardening excludes secrets and runs app as non-root",
    "production app rejects missing or placeholder session secrets",
    "production app rejects weak TOTP encryption keys",
    "production app rejects missing auth handoff public URLs at construction",
    "production app validates public URL modes, handoff secrets, and trusted proxy config at construction",
    "real production process dominates caller nodeEnv in integrated createApp security controls",
    "auth registration rejects weak and duplicate credentials",
    "auth write endpoints require a valid CSRF token",
    "auth CSRF endpoint is rate limited to prevent session store flooding",
    "rate limiter bounds tracked keys",
    "rate limiter hashes oversized keys before tracking attempts",
    "login, logout, and authenticated practice API access",
    "authenticated APIs require the session verifier companion cookie",
    "authenticated APIs require an active server-side auth session registry entry",
    "business account session API lists safe metadata and revokes other sessions",
    "admin session API lists target sessions and revokes copied user sessions",
    "security epoch invalidates copied full cookie jars after account security changes",
    "auth session registry rejects copied sessions on the wrong onion audience",
    "TOTP verification rotates the session verifier for copied cookie jars",
    "sensitive API responses are not cacheable",
    "malformed JSON bodies return a stable validation error",
    "oversized JSON bodies return a stable payload error",
    "logout clears secure session cookies with matching attributes",
    "production public URL policy controls session and handoff cookie Secure attributes",
    "direct app always hides retired legacy account APIs",
    "login performs a dummy password check for unknown users",
    "password comparisons reject input beyond bcrypt byte limit",
    "legacy direct account mutations stay retired",
    "retired legacy account mutation routes do not revoke active sessions",
    "retired legacy account routes are hidden before sensitive checks run",
    "authenticated APIs refresh stale session users before trusting them",
    "pending TOTP sessions refresh stale users before trusting them",
    "legacy self-delete route is retired and preserves account data",
    "legacy admin self-delete route is retired before last-admin checks",
    "Auth stores refuse direct last-admin deletion",
    "auth login rate limit returns 429 after repeated attempts",
    "auth login rate limit applies across usernames from one IP",
    "auth registration rate limit applies across usernames from one IP",
    "auth and CSRF rate limits ignore X-Forwarded-For from untrusted clients",
    "TOTP rate limits ignore X-Forwarded-For from untrusted clients",
    "TOTP setup requires auth, CSRF, and returns recovery codes once",
    "TOTP setup rejects legacy plaintext pending secrets in sessions",
    "enabling TOTP revokes other active sessions for the same user",
    "TOTP login requires a second factor before full session access",
    "TOTP login treats corrupted stored secrets as invalid codes",
    "invalid TOTP codes do not trigger recovery code bcrypt checks",
    "TOTP setup code cannot be reused as a login code",
    "TOTP login rejects replayed current time-step tokens",
    "TOTP pending setup and login expire before verification",
    "TOTP recovery codes are one-time and can be regenerated",
    "Postgres TOTP recovery code consumption requires an unused row update",
    "Postgres TOTP time-step consumption rejects stale updates",
    "ordinary users can disable TOTP through scoped auth action state",
    "admin users cannot disable TOTP through business scoped auth action state",
    "managed TOTP disable revokes other active sessions for the same user",
    "removed passkey API returns 404",
    "practice API requires authentication",
    "ordinary practice sync preserves unseen history without exporting it",
    "copied authenticated session cannot export through sync or destructive routes",
    "practice sync merges concurrent mutations and rejects identity collisions atomically",
    "Postgres practice sync locks before reading and only writes merged changes",
    "Postgres practice import supports valid session moves without intermediate uniqueness conflicts",
    "Postgres partial merge preserves persisted ordering after deleting the first slot (P2 reproducer)",
    "Postgres partial merge preserves an updated slot after a middle deletion",
    "Postgres partial merge keeps session replacements in their persisted logical slot",
    "Postgres partial import appends several new records after the persisted maximum",
    "Postgres partial merge rejects identity conflicts without changing records or order",
    "Postgres partial merge guards integer exhaustion before any record mutation",
    "Postgres partial import preserves logical slots when an old ID is reused after session moves",
    "Postgres partial merge serializes same-user appends without duplicate order keys",
    "practice destructive data management requires data step-up bound to the business browser",
    "practice import deduplicates by id and non-empty sessionId",
    "PUT practice records replaces the list returned by GET",
    "PUT practice records deduplicates duplicate session ids before storing",
    "admin API rejects anonymous and non-admin users",
    "site content API requires admin TOTP for writes and publishes sanitized public content",
    "site content UI renders with text nodes and admin edit controls",
    "admin dashboard redirects anonymous users through auth handoff",
    "retired legacy admin login html is hidden from authenticated admin static access",
    "admin shell and business account menu do not link back through the business home",
    "business settings password and TOTP actions require scoped auth state",
    "auth handoff creates a one-time business session ticket",
    "auth logout handoff clears the shared auth session before returning to the target entry",
    "auth handoff ignores poisoned forwarded hosts and validates canonical start hosts",
    "auth handoff allows local-development relative redirects without public URLs",
    "auth login binds signed handoff state to an audience-specific entry",
    "auth audience login pages require a handoff state before showing credential forms",
    "auth generic login page requires a handoff state before showing credential forms",
    "auth audience login pages hide credentials for mismatched handoff state",
    "auth login page lets admin flow switch away from an existing learner auth session",
    "auth login page does not redeem admin handoff after learner credentials",
    "auth login page lets business flow switch away from an existing admin auth session",
    "auth login session conflict restart logs out and returns to the same flow",
    "auth API enforces account type for signed business and admin flows",
    "auth proxy rejects no-state login and registration mutations",
    "auth complete JSON mode returns redirect payloads and structured errors",
    "auth handoff rejects unsafe return paths and audience mismatches",
    "auth callback uses proxy audience headers to rescue misdirected tickets",
    "auth handoff rejects expired tickets",
    "admin auth handoff requires admin role and TOTP verification",
    "admin auth handoff preserves existing TOTP freshness without extending it",
    "practice API rejects unsafe record identifiers and oversized batches",
    "practice record import cannot grow beyond the batch record cap",
    "practice record normalization rejects circular payloads without overflowing the stack",
    "practice record normalization and memory store do not expose mutable payload aliases",
    "practice record normalization rejects non-JSON payload values before serialization",
    "practice record normalization clamps numeric statistics",
    "practice record metadata truncation preserves valid Unicode",
    "admin record serialization redacts sensitive payload fields",
    "admin record serialization preserves shared references while still detecting cycles",
    "admin record serialization caps display payload text and normalizes scalar fields",
    "admin can list users, inspect records, and delete one record",
    "admin sensitive mutations are rate limited",
    "admin mutation rate limits ignore X-Forwarded-For from untrusted clients",
    "admin API does not expose internal error messages",
    "admin routes require TOTP verification in the current session",
    "admin TOTP verification expires and can be renewed in-session",
    "admin sensitive mutations require recent password step-up",
    "admin account center and user-list sensitive reads require recent password step-up",
    "admin exports require one-time password step-up tokens",
    "admin mutations rotate the session verifier for copied cookie jars",
    "admin can manage users and inspect learning and traffic stats",
    "PostgresAdminStore refuses last-admin demotion inside a locked transaction",
    "MemoryAdminStore refuses direct last-admin demotion and deletion",
    "PostgresAdminStore deletes sessions and users inside a locked transaction",
    "admin user deletion clears target TOTP state in memory store",
    "memory admin session deletion skips oversized serialized sessions",
    "memory auth session deletion skips oversized serialized sessions",
    "admin search query normalization preserves valid Unicode",
    "traffic middleware minimizes untrusted request metadata",
    "traffic visitor hashing ignores raw user-agent entropy",
    "traffic middleware rejects weak hashing secrets in production",
    "Postgres traffic recent events respect the selected day window",
    "memory traffic store caps retained events",
    "admin user changes invalidate target sessions and stale admin roles",
    "admin web routes reject self password changes",
    "retired legacy admin account mutations preserve current TOTP verification",
    "migration runner serializes migrations with a PostgreSQL advisory lock",
    "migration runner releases the advisory lock after migration failure",
    "bootstrap admin creates and updates an admin user",
    "static hosting serves index and denies dotfiles with security headers",
    "static boundary rechecks optional roots created after an initial miss",
    "public Listening loader verifies its exact synthetic inventory and serves only retained bytes",
    "public Listening loader rejects Locator, Manifest, Payload and inventory corruption",
    "public Listening loader rejects symlinked Payload entries and path escape",
    "authenticated A2 public routes enforce allowlists, CSP separation and private containment",
    "production readiness fails closed and production rejects fixture or root overrides",
)
_V3_NESTED_NAMES = (
    "strict active locator schema",
    "Manifest bytes and digest",
    "same-length Manifest corruption is rejected by SHA-256",
    "per-file Payload checksum",
    "unexpected Payload file",
    "image-root-only dependency checksum",
)


@dataclass(frozen=True)
class _ReplayEvidence:
    """Full local replay facts, constructed only from the completed fresh runner."""

    command_record: Mapping
    expected_authority: Mapping
    stdout: bytes
    stderr: bytes
    package_json: bytes
    runtime: Mapping
    runtime_closure: Mapping
    runtime_guard: Mapping


@dataclass(frozen=True)
class _OrdinaryValidatedProducer:
    """An ordinary wire record after exact snapshot and context validation.

    This is deliberately not a full raw replay record. Compact duplicate arrays
    and phase digest references stay intact; no omitted held identity is invented.
    The expected authority belongs to the independently prepared verifier plan.
    """

    command_record: Mapping
    expected_authority: Mapping
    stdout: bytes
    stderr: bytes
    package_json: bytes
    runtime: Mapping
    runtime_closure: Mapping
    runtime_guard: Mapping


def _require(condition):
    if not condition:
        raise ValueError("backend portable result unavailable")


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _reject(reason):
    """Give direct tests a stable, non-sensitive rejection classification."""
    raise ValueError(f"backend portable result unavailable: {reason}")


def _trusted_path_profile(targets):
    """Canonicalize the complete protected target path authority."""
    if type(targets) is not list:
        _reject("invalid-target-authority")
    paths = []
    for target in targets:
        if not isinstance(target, Mapping):
            _reject("invalid-target-authority")
        path = target.get("path")
        if (type(path) is not str or not 0 < len(path) <= 4096
                or any(character in path for character in ("\x00", "\r", "\n"))):
            _reject("invalid-target-authority")
        paths.append(path)
    if len(set(paths)) != len(paths):
        _reject("invalid-target-authority")
    try:
        serialized = ("\n".join(sorted(paths)) + "\n").encode(
            "utf-8", errors="strict")
    except UnicodeEncodeError:
        _reject("invalid-target-authority")
    return {
        "trackedPaths": len(paths),
        "serializedUtf8Bytes": len(serialized),
        "sortedPathSha256": hashlib.sha256(serialized).hexdigest(),
    }


def _select_protocol(targets):
    """Select solely from protected paths and source identities, never stdout."""
    profile = _trusted_path_profile(targets)
    descriptors = [
        descriptor for descriptor in (_V2_PROTOCOL, _V3_PROTOCOL)
        if profile == {
            "trackedPaths": descriptor.path_count,
            "serializedUtf8Bytes": descriptor.path_bytes,
            "sortedPathSha256": descriptor.path_sha256,
        }
    ]
    if len(descriptors) != 1:
        _reject("unknown-path-profile")
    descriptor = descriptors[0]
    if descriptor is _V2_PROTOCOL:
        return _ProtocolSelection(descriptor, None, ())

    by_path = {target["path"]: target for target in targets}
    paths = tuple(item[0] for item in _V3_SOURCE_PROFILES[0][2])
    actual = []
    for path in paths:
        target = by_path.get(path)
        if not isinstance(target, Mapping):
            _reject("invalid-source-tuple")
        size, sha256 = target.get("size"), target.get("sha256")
        if (type(size) is not int or size <= 0 or type(sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", sha256) is None):
            _reject("invalid-source-tuple")
        actual.append((path, size, sha256))
    actual = tuple(actual)
    for variant, total_bytes, source_tuple in _V3_SOURCE_PROFILES:
        if actual == source_tuple:
            if sum(item[1] for item in actual) != total_bytes:
                _reject("invalid-source-tuple")
            return _ProtocolSelection(descriptor, variant, source_tuple)

    individually_approved = []
    for index, item in enumerate(actual):
        variants = [
            variant for variant, _total_bytes, source_tuple in _V3_SOURCE_PROFILES
            if item == source_tuple[index]
        ]
        if len(variants) != 1:
            _reject("invalid-source-tuple")
        individually_approved.append(variants[0])
    if len(set(individually_approved)) > 1:
        _reject("mixed-source-tuple")
    _reject("invalid-source-tuple")


_KNOWN_PROTOCOL_SELECTIONS = (
    _ProtocolSelection(_V2_PROTOCOL, None, ()),
    *(
        _ProtocolSelection(_V3_PROTOCOL, variant, source_tuple)
        for variant, _total_bytes, source_tuple in _V3_SOURCE_PROFILES
    ),
)


def _protocol_binding(selection):
    """Project only a known immutable selection into the side binding."""
    if type(selection) is not _ProtocolSelection or selection not in _KNOWN_PROTOCOL_SELECTIONS:
        _reject("protocol-binding")
    descriptor = selection.descriptor
    source_tuple = None
    if selection.source_variant is not None:
        totals = {variant: total for variant, total, _sources in _V3_SOURCE_PROFILES}
        source_tuple = {
            "variant": selection.source_variant,
            "totalBytes": totals[selection.source_variant],
            "sources": [
                {"path": path, "size": size, "sha256": sha256}
                for path, size, sha256 in selection.source_tuple
            ],
        }
    return {
        "schema": SCHEMA,
        "version": descriptor.version,
        "digestDomain": descriptor.digest_domain,
        "pathProfile": {
            "trackedPaths": descriptor.path_count,
            "serializedUtf8Bytes": descriptor.path_bytes,
            "sortedPathSha256": descriptor.path_sha256,
        },
        "hierarchyInventoryDigest": descriptor.hierarchy_inventory_digest,
        "topLevelMembers": descriptor.top_level_members,
        "nestedMembers": descriptor.nested_members,
        "totalExecutedMembers": descriptor.total_executed_members,
        "parentTopLevelOrdinal": descriptor.parent_top_level_ordinal,
        "durationSpans": descriptor.duration_spans,
        "retainedSegments": descriptor.retained_segments,
        "reporterCounts": dict(zip(COUNTS, descriptor.expected_counts)),
        "sourceTuple": source_tuple,
    }


def _selection_from_protocol_binding(value):
    for selection in _KNOWN_PROTOCOL_SELECTIONS:
        if value == _protocol_binding(selection):
            return selection
    _reject("protocol-binding")


def _identity(ci, value):
    # A bytes frame prevents the general canonical codec from folding Unicode.
    return ci.canonical_failure_digest({
        "digestDomain": "ieltmps-backend-canonical-portable-result-v2",
        "resultUtf8": _json_bytes(value),
    })


def _identity_v3(ci, value):
    # A distinct domain prevents either protocol from claiming the other's value.
    return ci.canonical_failure_digest({
        "digestDomain": "ieltmps-backend-canonical-portable-result-v3",
        "resultUtf8": _json_bytes(value),
    })


def _identity_for_protocol(ci, value, protocol_binding):
    selection = _selection_from_protocol_binding(protocol_binding)
    if selection.descriptor is _V2_PROTOCOL:
        return _identity(ci, value)
    if selection.descriptor is _V3_PROTOCOL:
        return _identity_v3(ci, value)
    _reject("protocol-binding")


def _parse_stdout(stdout, package):
    """Consume every byte, returning ordered members and the 143 exact gaps.

    Only the numeric spans in 141 terminal '(Dms)' fields and the one terminal
    'duration_ms D' footer are omitted. Units, punctuation, whitespace, names,
    line endings, and even the optional initial npm newline stay in the gaps.
    """
    _require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STREAM_BYTES)
    stdout.decode("utf-8", errors="strict")
    _require(not any(b < 32 and b not in (10, 13) or b == 127 for b in stdout))
    raw_lines = stdout.splitlines(keepends=True)
    _require(len(raw_lines) in (TEST_COUNT + 11, TEST_COUNT + 12))
    lines, offsets, offset = [], [], 0
    for line in raw_lines:
        _require(line.endswith(b"\n") and len(line) <= 2048)
        body = line[:-2] if line.endswith(b"\r\n") else line[:-1]
        _require(b"\r" not in body)
        offsets.append(offset)
        lines.append(body)
        offset += len(line)
    start = 1 if lines[0] == b"" else 0
    banner = f"> {package['name']}@{package['version']} test".encode("utf-8")
    _require(lines[start:start + 3] == [banner, b"> node --test", b""])
    _require(len(lines) == start + 3 + TEST_COUNT + 8)
    members, spans = [], []
    for index in range(start + 3, start + 3 + TEST_COUNT):
        match = _MEMBER.fullmatch(lines[index])
        _require(match is not None)
        name = match[1].decode("utf-8", errors="strict")
        _require(name == name.strip())
        members.append({"name": name, "status": "pass"})
        spans.append(tuple(offsets[index] + n for n in match.span(2)))
    _require(len({member["name"] for member in members}) == TEST_COUNT)
    footer = start + 3 + TEST_COUNT
    for index, key in enumerate(COUNTS):
        _require(lines[footer + index] == f"ℹ {key} {EXPECTED_COUNTS[key]}".encode())
    match = _DURATION.fullmatch(lines[-1])
    _require(match is not None)
    spans.append(tuple(offsets[-1] + n for n in match.span(1)))
    gaps, offset = [], 0
    for begin, end in spans:
        gaps.append(stdout[offset:begin].hex())
        offset = end
    gaps.append(stdout[offset:].hex())
    _require(len(spans) == TEST_COUNT + 1 and len(gaps) == TEST_COUNT + 2)
    return members, gaps


def _parse_stdout_v3(stdout, package):
    """Consume the exact hierarchy-aware v3 reporter and its 156 byte gaps."""
    if type(stdout) is not bytes or not 0 < len(stdout) <= MAX_STREAM_BYTES:
        _reject("stream-boundary")
    try:
        stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        _reject("stream-encoding")
    if any((byte < 32 and byte not in (10, 13)) or byte == 127 for byte in stdout):
        _reject("stream-encoding")
    raw_lines = stdout.splitlines(keepends=True)
    if not raw_lines or len(raw_lines) > MAX_STREAM_LINES:
        _reject("line-boundary")
    lines, offsets, offset = [], [], 0
    for line in raw_lines:
        if not line.endswith(b"\n") or len(line) > 2048:
            _reject("line-boundary")
        body = line[:-2] if line.endswith(b"\r\n") else line[:-1]
        if b"\r" in body:
            _reject("line-boundary")
        offsets.append(offset)
        lines.append(body)
        offset += len(line)

    start = 1 if lines[0] == b"" else 0
    try:
        banner = f"> {package['name']}@{package['version']} test".encode("utf-8")
    except (KeyError, TypeError, UnicodeError):
        _reject("banner-mismatch")
    if lines[start:start + 3] != [banner, b"> node --test", b""]:
        _reject("banner-mismatch")

    cursor = start + 3
    spans = []
    members = []
    parent_name = _V3_TOP_LEVEL_NAMES[_V3_PROTOCOL.parent_top_level_ordinal]
    parent_completion_prefix = "✔ ".encode() + parent_name.encode("utf-8") + b" ("

    def completion(prefix, name, mismatch_reason):
        nonlocal cursor
        if cursor >= len(lines):
            _reject(mismatch_reason)
        line = lines[cursor]
        name_bytes = name.encode("utf-8")
        stem = prefix + "✔ ".encode() + name_bytes
        framed = stem + b" ("
        if not line.startswith(framed) or not line.endswith(b"ms)"):
            stripped = line.lstrip(b" ")
            if prefix == b"  " and stripped.startswith("✔ ".encode() + name_bytes + b" ("):
                _reject("hierarchy-indentation-mismatch")
            _reject(mismatch_reason)
        number = line[len(framed):-3]
        if re.fullmatch(_DECIMAL, number) is None:
            _reject("duration-grammar")
        spans.append((offsets[cursor] + len(framed), offsets[cursor] + len(line) - 3))
        cursor += 1

    for ordinal, name in enumerate(_V3_TOP_LEVEL_NAMES):
        if ordinal != _V3_PROTOCOL.parent_top_level_ordinal:
            completion(b"", name, "hierarchy-member-mismatch")
            members.append({"name": name, "status": "pass"})
            continue

        heading = "▶ ".encode() + parent_name.encode("utf-8")
        if cursor >= len(lines):
            _reject("hierarchy-heading-mismatch")
        if lines[cursor] != heading:
            if lines[cursor].startswith(parent_completion_prefix):
                _reject("parent-completion-placement")
            _reject("hierarchy-heading-mismatch")
        cursor += 1
        children = []
        for child in _V3_NESTED_NAMES:
            if cursor < len(lines) and lines[cursor].startswith(parent_completion_prefix):
                _reject("parent-completion-placement")
            completion(b"  ", child, "hierarchy-member-mismatch")
            children.append({"name": child, "status": "pass"})
        if cursor >= len(lines) or not lines[cursor].startswith(parent_completion_prefix):
            _reject("parent-completion-placement")
        completion(b"", parent_name, "parent-completion-placement")
        members.append({"name": parent_name, "status": "pass", "children": children})

    if cursor < len(lines) and lines[cursor].lstrip(b" ").startswith(
            ("✔ ".encode(), "▶ ".encode())):
        _reject("hierarchy-member-mismatch")
    expected_counts = dict(zip(COUNTS, _V3_PROTOCOL.expected_counts))
    for key in COUNTS:
        if cursor >= len(lines) or lines[cursor] != f"ℹ {key} {expected_counts[key]}".encode():
            _reject("footer-mismatch")
        cursor += 1
    duration_prefix = "ℹ duration_ms ".encode()
    if cursor >= len(lines):
        _reject("footer-mismatch")
    duration_line = lines[cursor]
    if not duration_line.startswith(duration_prefix):
        _reject("footer-mismatch")
    duration = duration_line[len(duration_prefix):]
    if re.fullmatch(_DECIMAL, duration) is None:
        _reject("duration-grammar")
    spans.append((offsets[cursor] + len(duration_prefix), offsets[cursor] + len(duration_line)))
    cursor += 1
    if cursor != len(lines):
        _reject("footer-mismatch")

    gaps, offset = [], 0
    for begin, end in spans:
        gaps.append(stdout[offset:begin].hex())
        offset = end
    gaps.append(stdout[offset:].hex())
    if (len(members) != _V3_PROTOCOL.top_level_members
            or len(spans) != _V3_PROTOCOL.duration_spans
            or len(gaps) != _V3_PROTOCOL.retained_segments):
        _reject("hierarchy-member-mismatch")
    return members, gaps


def _parse_selected_stdout(stdout, package, protocol_binding):
    selection = _selection_from_protocol_binding(protocol_binding)
    if selection.descriptor is _V2_PROTOCOL:
        return _parse_stdout(stdout, package)
    if selection.descriptor is _V3_PROTOCOL:
        return _parse_stdout_v3(stdout, package)
    _reject("protocol-binding")


def _stable_identity(value):
    _require(isinstance(value, dict) and value.get("reparsePoint") is False)
    if set(value) == _STABLE_KEYS:
        keys = _STABLE_KEYS - {"reparsePoint"}
    else:
        # ExecutableIdentityLease._windows_identity (not the target-lease shape).
        _require(set(value) == {"volumeSerial", "fileIndex", "size", "writeTime", "links", "reparsePoint"})
        _require(type(value["size"]) is int and value["size"] > 0)
        _require(type(value["links"]) is int and value["links"] >= 1)
        keys = ("volumeSerial", "fileIndex", "writeTime")
    _require(all(type(value[k]) is str and re.fullmatch(r"-?[0-9]{1,24}", value[k])
                 for k in keys))


@dataclass(frozen=True)
class _BoundSide:
    # Immutable bytes only: no caller-owned mappings survive the binding boundary.
    stdout: bytes
    bindings: bytes


@dataclass(frozen=True)
class _ProducerContext:
    commands: dict
    plan: list
    producer: _OrdinaryValidatedProducer
    repo_root: Path
    side: _BoundSide


@dataclass(frozen=True)
class _BoundPair:
    producer: _BoundSide
    replay: _BoundSide
    producer_records: list
    replay_records: list
    plan_digest: str
    classes: list


def _bind_side(ci, evidence):
    """Bind wire producer semantics or full replay facts, without reporter parsing."""
    try:
        _require(type(evidence) in (_ReplayEvidence, _OrdinaryValidatedProducer))
        evidence = copy.deepcopy(evidence)
        record, expected = evidence.command_record, evidence.expected_authority
        _require(isinstance(record, dict) and isinstance(expected, dict))
        _require(set(expected) == AUTHORITY_KEYS)
        if type(evidence) is _OrdinaryValidatedProducer:
            _require(ci._portable_command_plan_value([{k: record[k] for k in AUTHORITY_KEYS}])
                     == ci._portable_command_plan_value([expected]))
        else:
            _require({key: record.get(key) for key in AUTHORITY_KEYS} == expected)
        _require(record["commandId"] == record["commandClass"] == "backend-canonical")
        _require(record["profile"] in ("backend", "all"))
        _require(record["toolRole"] == "npm-backend-test" and record["required"] is True)
        _require(record["resultSemantics"] == "baseline-classified-test-result")
        _require((record["commandRole"], tuple(record["allowedExecutionExits"])) in (
            ("required-execution", (0,)), ("observation-producing", (0, 1))))
        _require(record["executionInputMode"] == "PROTECTED-TARGET-BUNDLE")
        _require(record["executionInputSize"] is record["executionInputSha256"] is None)
        _require(type(record["exitCode"]) is int and record["exitCode"] == 0)
        _require(ci._command_execution_completed(record))
        _require(record["processTreeStatus"] == "contained-clean")
        _require(record["containmentDisposition"] in ("no-descendants", "natural-exit-reaped"))
        _require(record["descendantsTerminated"] == record["descendantsSurviving"] == 0)
        _require(record["descendantsObserved"] == record["descendantsReaped"])
        _require((record["containmentDisposition"] == "no-descendants")
                 == (record["descendantsObserved"] == 0))
        _require((record["platform"], record["containment"]) in (
            ("ubuntu", "linux-subreaper-pidfd-proc-supervisor"),
            ("windows", "windows-job-object")))
        _require(all(record.get(key) is None for key in ("error", "processTreeError", "limitReason")))
        errors = []
        _require(not ci._validate_command_record(record, record["ordinal"], errors,
                                                 expected_record=expected) and not errors)
        _require(0 < len(record["targets"]) <= 2048)
        record_selection = _select_protocol(record["targets"])
        expected_selection = _select_protocol(expected["targets"])
        if record_selection != expected_selection:
            _reject("protocol-selection-disagreement")
        protocol = _protocol_binding(record_selection)
        inputs = record["executionInputs"]
        if type(evidence) is _OrdinaryValidatedProducer:
            inputs = ci._reconstructed_protected_execution_inputs(record)
            _require(record["executionInputs"] == [] or record["executionInputs"] == inputs)
        _require(len(inputs) == len(record["targets"]))
        _require(record["executionInputBundleDigest"]
                 == ci.execution_input_bundle_digest(inputs))
        bundle_digest = ci._validated_portable_protected_input_bundle_digest(record)
        _require(bundle_digest is not None)
        authority = ci._portable_command_plan_value([expected])
        _require(isinstance(authority, list) and len(authority) == 1 and bool(authority[0]))
        for stream, raw in (("stdout", evidence.stdout), ("stderr", evidence.stderr)):
            _require(type(raw) is bytes and len(raw) <= MAX_STREAM_BYTES)
            _require(len(raw) == record[stream + "BytesObserved"])
            _require(hashlib.sha256(raw).hexdigest() == record[stream + "Sha256"])
            _require(ci._backend_exact_stream_text_is_safe(raw.decode("utf-8", errors="strict")))
        _require(evidence.stderr == b"")
        _require(len(record["producerObservations"]) == 1)
        raw = record["producerObservations"][0]
        _require(not ci._validate_raw_observation(raw, label="backend-portable", source=record))
        _require(raw["observationKind"] == "process-output-v1")
        _require(raw["observationOrdinal"] == 0 and raw["occurrences"] == 1)
        _require(raw["sourceResultId"] == "command:npm --prefix backend test")
        _require(raw["sourcePath"] == "backend/package.json" and raw["failurePathAuthority"] is None)
        _require(raw["rawStructuredFields"] == {
            "executed": True, "exitCode": 0, "stdout": evidence.stdout.decode("utf-8"),
            "stderr": "", "error": None,
        })
        package_targets = [t for t in expected["targets"] if t["path"] == "backend/package.json"]
        _require(len(package_targets) == 1 and type(evidence.package_json) is bytes)
        _require(0 < len(evidence.package_json) <= 512 * 1024)
        _require(len(evidence.package_json) == package_targets[0]["size"])
        _require(hashlib.sha256(evidence.package_json).hexdigest() == package_targets[0]["sha256"])
        package = ci.strict_json_loads(evidence.package_json.decode("utf-8"), label="backend package")
        _require(all(type(package.get(k)) is str and 0 < len(package[k]) <= 1024
                     and not any(ord(c) < 32 or ord(c) == 127 for c in package[k])
                     for k in ("name", "version")))
        scripts = package["scripts"]
        _require(scripts["test"] == "node --test")
        _require("pretest" not in scripts and "posttest" not in scripts)
        closure, guard, runtime = evidence.runtime_closure, evidence.runtime_guard, evidence.runtime
        ci._validate_runtime_dependency_closure(closure, guard, runtime,
            profile=record["profile"], status="PASS", errors=errors)
        _require(not errors and closure["measurementStatus"] == "measured-complete")
        _require(closure["runnerOS"] == {"ubuntu": "Linux", "windows": "Windows"}[record["platform"]])
        _require(record["dependencyBacked"] is True)
        _require(record["runtimeClosureDigest"] == closure["closureDigest"])
        _require(record["dependencyClosureDigest"] == closure["dependencyClosureDigest"])
        _require(record["runtimeClosureGuard"] == guard and guard["active"] is False)
        _require(guard["watcherBackend"] == {"ubuntu": "_InotifyMutationWatcher",
                 "windows": "_WindowsDirectoryMutationWatcher"}[record["platform"]])
        tools = {}
        for name, key, role in (("node", "nodeExecutable", "node-runtime"),
                                ("npm", "npmEntrypoint", "npm-entrypoint")):
            tool = closure[key]
            keys = {"role", "canonicalPath", "size", "sha256", "stableIdentity", "leaseHeld", "version"}
            _require(set(tool) == keys | ({"available"} if name == "npm" else set()))
            _require(tool["role"] == role and tool["leaseHeld"] is True)
            _require(type(tool["size"]) is int and tool["size"] > 0)
            _stable_identity(tool["stableIdentity"])
            _require(tool["version"] == runtime[name])
            _require(re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", tool["version"]) is not None)
            tools[name] = {k: tool[k] for k in ("role", "size", "sha256", "version")}
        node, npm = closure["nodeExecutable"], closure["npmEntrypoint"]
        _require(npm["available"] is True)
        _require(record["logicalArgv"] == [npm["canonicalPath"], "--prefix", "backend", "test"])
        _require(record["executionArgv"] == [node["canonicalPath"], *record["logicalArgv"]])
        _require(record["cwd"] == "." and record["resolvedExecutablePath"] == node["canonicalPath"])
        _require(record["resolvedExecutableSha256"] == node["sha256"])
        _require(record["resolvedExecutableSize"] == node["size"])
        _stable_identity(record["resolvedExecutableFileIdentity"])
        _require(record["resolvedTestRunnerEntrypoint"] == node["canonicalPath"])
        _require(record["resolvedTestRunnerSha256"] == node["sha256"])
        bindings = {
            "command": {k: record[k] for k in ("commandId", "commandClass", "ordinal")},
            "package": package, "packageJsonSha256": package_targets[0]["sha256"],
            "tools": tools, "authority": authority, "inputBundleDigest": bundle_digest,
            "dependencyClosureDigest": closure["dependencyClosureDigest"],
            "protocol": protocol,
        }
        return _BoundSide(evidence.stdout, _json_bytes(bindings))
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None


def _bind_producer(ci, commands, plan, repo_root):
    """Called only by the outer verifier after validating its exact raw snapshots."""
    try:
        commands, plan = copy.deepcopy((commands, plan))
        records = commands["records"]
        backend = [r for r in records if r["commandId"] == "backend-canonical"]
        expected = [p for p in plan if p["commandId"] == "backend-canonical"]
        _require(len(backend) == len(expected) == 1)
        record = backend[0]
        errors = []
        _require(not ci._validate_command_record(record, record["ordinal"], errors,
                     expected_record=expected[0]) and not errors)
        _require(ci._portable_command_plan_value([{k: record[k] for k in AUTHORITY_KEYS}])
                 == ci._portable_command_plan_value(expected))
        _require(commands["commandAuthority"] == ci._portable_command_plan_value(plan))
        _require(commands["commandPlanDigest"] == ci.command_plan_digest(plan))
        _require(commands["producerObservationUniverseDigest"]
                 == ci.producer_observation_universe_digest(records))
        _require(commands["producerTranscriptDigest"] == ci.producer_transcript_digest(
            commands["commandPlanDigest"], records, commands["actualCompletedCommandClasses"]))
        # Existing full-context observation claims never gain a rewrite path.
        _require(commands["observations"] == [])
        _require(len(record["producerObservations"]) == 1)
        observation = record["producerObservations"][0]
        _require(not ci._validate_raw_observation(observation, label="backend-portable", source=record))
        _require(observation["observationKind"] == "process-output-v1")
        streams = []
        for stream in ("stdout", "stderr"):
            value = observation["rawStructuredFields"][stream]
            _require(type(value) is str)
            # Reserve the writer's sentinel even when its hash/length match.
            # Literal captured marker bytes are intentionally nonportable too.
            _require(value != ci._BACKEND_STREAM_REDACTION_MARKER)
            data = value.encode("utf-8", errors="strict")
            _require(len(data) == record[stream + "BytesObserved"])
            _require(hashlib.sha256(data).hexdigest() == record[stream + "Sha256"])
            streams.append(data)
        # Read only the exact candidate's independently planned package target.
        # This fresh local lease never replaces an omitted producer lease preimage.
        package_targets = [t for t in expected[0]["targets"] if t["path"] == "backend/package.json"]
        _require(len(package_targets) == 1 and 0 < package_targets[0]["size"] <= 512 * 1024)
        lease = ci.TargetExecutionLease(package_targets[0], repo_root=repo_root,
                                        execution_adapter="PROTECTED-TARGET-BUNDLE")
        try:
            package_json = lease.materialize()
            _require(lease.verify()[0])
        finally:
            lease.close()
        producer = _OrdinaryValidatedProducer(record, expected[0], *streams, package_json,
            commands["runtime"], commands["runtimeDependencyClosure"], commands["runtimeDependencyGuard"])
        side = _bind_side(ci, producer)
        _require(side is not None)
        return _ProducerContext(commands, plan, producer, repo_root, side)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError, OSError):
        return None


def _bind_replay(ci, context, commands, runner):
    """Recheck producer bindings and bind only the completed fresh runner capture."""
    try:
        _require(type(context) is _ProducerContext)
        _require(commands == context.commands and runner.command_plan == context.plan)
        _require(ci.command_plan_digest(runner.command_plan) == runner.command_plan_digest
                 == commands["commandPlanDigest"])
        # Deferring unrelated result equality must not defer raw replay authority
        # or execution eligibility for those commands. Use the existing local
        # validators, including each command's protected inputs and observations.
        _require(not ci._command_authority_violations(
            runner.profile, runner.command_results, runner.observations,
            expected_plan=runner.command_plan))
        _require(len(runner.command_results) == len(runner.command_plan))
        for index, (record, expected) in enumerate(zip(runner.command_results, runner.command_plan)):
            errors = []
            _require(not ci._validate_command_record(record, index, errors,
                         expected_record=expected) and not errors)
        rebound = _bind_producer(ci, commands, runner.command_plan, context.repo_root)
        _require(rebound is not None and rebound.side == context.side)
        records = [r for r in runner.command_results if r["commandId"] == "backend-canonical"]
        plans = [p for p in runner.command_plan if p["commandId"] == "backend-canonical"]
        captures = [c for c in runner.captures if c.command_id == "backend-canonical"]
        _require(len(records) == len(plans) == len(captures) == 1)
        capture = captures[0]
        _require(type(capture) is ci.CommandCapture)
        # Backend uses the protected target bundle, never a captured stdin lease.
        # Capture.evidence() derives stdin inputs from this field; it must not be
        # hidden by the exclusions for bundle data later added by the runner.
        _require(capture.target_execution_lease is None)
        fresh = _ReplayEvidence(
            records[0], plans[0], capture.stdout_raw, capture.stderr_raw,
            context.producer.package_json, runner.runtime, runner.runtime_closure_document,
            runner.runtime_closure_guard_evidence,
        )
        side = _bind_side(ci, fresh)
        _require(side is not None)
        # Self-consistent producer tool/runtime claims are not fresh authority.
        # Bind all non-reporter inputs to the independently measured replay
        # before either reporter can be parsed (including npm hash/size/version).
        _require(side.bindings == context.side.bindings)
        _require(fresh.runtime_closure["closureDigest"] == runner.runtime_closure_digest)
        _require(fresh.runtime_closure["dependencyClosureDigest"] == runner.dependency_closure_digest)
        # These fields are added by FoundationRunner after capture; all measured
        # execution fields, including both streams, must equal the fresh record.
        runner_added = {"executionInputs", "executionInputBundleDigest", "protectedTargetBundle",
                        "producerObservations",
                        "producerObservationSetDigest", "completedCommandClass"}
        for key, value in capture.evidence().items():
            if key not in runner_added:
                _require(records[0].get(key) == value)
        _require(not runner.violations and all(r.get("status") == "pass"
                                              for r in runner.hard_gate_results))
        return _BoundPair(context.side, side, copy.deepcopy(commands["records"]),
                          copy.deepcopy(runner.command_results), runner.command_plan_digest,
                          list(runner.actual_completed_command_classes))
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None


def _project_record(ci, record, result):
    """Detached comparison values; never input to a raw/local authority function."""
    projected = ci._canonical_transcript_record(record)
    encoded = _json_bytes(result["result"])
    projected["stdoutSha256"] = hashlib.sha256(encoded).hexdigest()
    projected["stdoutBytesObserved"] = len(encoded)
    raw = copy.deepcopy(record["producerObservations"][0])
    raw["rawStructuredFields"]["stdout"] = copy.deepcopy(result)
    raw["sourceOutputDigest"] = result["identityDigest"]
    raw["producerRecordDigest"] = ci._producer_record_digest({
        key: value for key, value in raw.items() if key != "producerRecordDigest"})
    projected["producerObservations"] = [raw]
    projected["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
    return projected


def _comparison_view(ci, records, plan_digest, classes, result):
    projected = [_project_record(ci, r, result) if r["commandId"] == "backend-canonical"
                 else ci._canonical_transcript_record(r) for r in records]
    universe = ci.producer_observation_universe(records)
    for item, record in zip(universe, projected):
        if record["commandId"] == "backend-canonical":
            for key in ("producerObservations", "producerObservationSetDigest"):
                item[key] = record[key]
    universe_digest = ci.canonical_failure_digest(universe)
    transcript_digest = ci.canonical_failure_digest({
        "commandPlanDigest": plan_digest, "orderedCommandTranscript": projected,
        "orderedProducerObservationUniverse": universe,
        "producerObservationUniverseDigest": universe_digest,
        "completedCommandClasses": sorted(set(classes)),
        "completedCommandClassSetDigest": ci.completed_command_class_set_digest(classes),
    })
    return {"records": projected, "producerObservationUniverseDigest": universe_digest,
            "producerTranscriptDigest": transcript_digest}


def _comparison_views(ci, pair, result):
    _require(type(pair) is _BoundPair and result is not None)
    return {side: _comparison_view(ci, records, pair.plan_digest, pair.classes, result)
            for side, records in (("producer", pair.producer_records), ("replay", pair.replay_records))}


def _derive_equal_result(ci, pair):
    """Accept only two already bound immutable sides, after outer eligibility.

    Both complete reporters must parse before either result identity is computed.
    A failed binding never calls this function; a parse failure computes no identity.
    """
    try:
        _require(type(pair) is _BoundPair)
        decoded = []
        for side in (pair.producer, pair.replay):
            _require(type(side) is _BoundSide)
            bound = json.loads(side.bindings)
            selection = _selection_from_protocol_binding(bound.get("protocol"))
            decoded.append((side, bound, selection))
        if decoded[0][1]["protocol"] != decoded[1][1]["protocol"]:
            _reject("protocol-selection-disagreement")
        values = []
        for side, bound, selection in decoded:
            descriptor = selection.descriptor
            members, gaps = _parse_selected_stdout(side.stdout, bound["package"], bound["protocol"])
            value = {
                "schema": SCHEMA, "version": descriptor.version, "command": bound["command"],
                "orderedTests": members,
                "reporterCounts": dict(zip(COUNTS, descriptor.expected_counts)),
                "package": {"name": bound["package"]["name"], "version": bound["package"]["version"],
                            "packageJsonSha256": bound["packageJsonSha256"]},
                "lifecycle": {"event": "test", "pretest": None, "test": "node --test", "posttest": None},
                "tools": bound["tools"], "exitCode": 0,
                "stdoutNonDurationSegmentsHex": gaps,
                "stderr": {"byteLength": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                "portableAuthorityDigest": ci.canonical_failure_digest(bound["authority"]),
                "portableInputBundleDigest": bound["inputBundleDigest"],
                "dependencyClosureDigest": bound["dependencyClosureDigest"],
            }
            if descriptor is _V3_PROTOCOL:
                value["protocol"] = copy.deepcopy(bound["protocol"])
            values.append(value)
        results = [
            {"identityDigest": _identity_for_protocol(ci, value, bound["protocol"]), "result": value}
            for value, (_side, bound, _selection) in zip(values, decoded)
        ]
        _require(results[0] == results[1])
        return results[1]
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        return None
