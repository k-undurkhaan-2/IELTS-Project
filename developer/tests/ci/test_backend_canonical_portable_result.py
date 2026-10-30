"""Bounded Issue 13 fixtures: no hosted job or repository profile execution."""
from __future__ import annotations

import ast
import copy
import contextlib
from dataclasses import replace
import hashlib
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import run_ci_foundation as ci
import test_ci_foundation as fixtures
import backend_canonical_portable_result as portable


def portable_spy(name, **kwargs):
    return fixtures.frozen_backend_spy(name, direct_module=portable, **kwargs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


NAMES = [f"backend case {i:03d} preserves value {1000 + i}" for i in range(141)]
PACKAGE = json_bytes({"name": "fixture-backend", "version": "1.0.0",
                      "scripts": {"test": "node --test"}})

# Independent Issue 107 authorities.  These are deliberately not borrowed from
# the implementation module: a wrong production constant must fail the tests.
V2_PATH_PROFILE = (914, 40446, "ea143c283e5b8b28098505a303530d0fc9c0c2731273f5bde84d00d5022c52aa")
V3_PATH_PROFILE = (916, 40530, "5b9401b4afa1b964ebd2887ec023c247a605d4faad6532de6cc168720f70c786")
V3_ADDED_PATHS = (
    "backend/src/publicListeningFrontend.js",
    "backend/test/publicListeningFrontend.test.js",
)
V3_HIERARCHY_DIGEST = "3217938708947463015beba935fad163b387a6ba2969625679f326c7770e843a"
V3_SOURCE_PROFILES = {
    "LF": (
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
    "CRLF": (
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
}
V3_PACKAGE_LF = ("\n".join((
    "{",
    '  "name": "ielts-practice-backend",',
    '  "version": "0.1.0",',
    '  "private": true,',
    '  "license": "AGPL-3.0-only",',
    '  "main": "src/server.js",',
    '  "scripts": {',
    '    "start": "node src/server.js",',
    '    "test": "node --test",',
    '    "test:compose-profiles": "node scripts/check-compose-profiles.mjs",',
    '    "migrate": "node scripts/migrate.mjs",',
    '    "bootstrap:admin": "node scripts/bootstrap-admin.mjs",',
    '    "smoke:postgres": "node scripts/smoke-postgres.mjs"',
    "  },",
    '  "dependencies": {',
    '    "bcryptjs": "^2.4.3",',
    '    "connect-pg-simple": "^10.0.0",',
    '    "dotenv": "^16.4.7",',
    '    "express": "^4.19.2",',
    '    "express-session": "^1.18.1",',
    '    "helmet": "^7.1.0",',
    '    "otplib": "^13.4.1",',
    '    "pg": "^8.13.1",',
    '    "qrcode": "^1.5.4",',
    '    "zod": "^3.24.1"',
    "  }",
    "}",
)) + "\n").encode("ascii")
V3_PACKAGE_CRLF = V3_PACKAGE_LF.replace(b"\n", b"\r\n")

V3_TOP_LEVEL_NAMES = (
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
V3_NESTED_NAMES = (
    "strict active locator schema",
    "Manifest bytes and digest",
    "same-length Manifest corruption is rejected by SHA-256",
    "per-file Payload checksum",
    "unexpected Payload file",
    "image-root-only dependency checksum",
)
V3_PARENT_ORDINAL = 144
REAL_REPO_ROOT = ci.REPO_ROOT

def independent_path_profile(paths):
    serialized = ("\n".join(sorted(paths)) + "\n").encode("utf-8")
    return len(paths), len(serialized), digest(serialized)


def protocol_paths(version):
    if version not in (2, 3):
        raise AssertionError(("unknown-protocol-version", version))
    # Authenticate every live inventory, including after earlier fixture calls.
    paths, errors = ci.deterministic_candidate_paths(REAL_REPO_ROOT)
    if errors:
        raise AssertionError(errors)
    source_profile = independent_path_profile(paths)
    if len(paths) != len(set(paths)) or source_profile not in (V2_PATH_PROFILE, V3_PATH_PROFILE):
        raise AssertionError(("unexpected-live-path-profile", source_profile))
    if version == 2 and source_profile == V3_PATH_PROFILE:
        paths = [path for path in paths if path not in V3_ADDED_PATHS]
    elif version == 3 and source_profile == V2_PATH_PROFILE:
        paths = [*paths, *V3_ADDED_PATHS]
    expected = V2_PATH_PROFILE if version == 2 else V3_PATH_PROFILE
    target_profile = independent_path_profile(paths)
    if len(paths) != len(set(paths)) or target_profile != expected:
        raise AssertionError(("unexpected-target-path-profile", version, target_profile))
    return tuple(sorted(paths))


def protocol_targets(version, *, source_variant="LF", source_mask=None,
                     complete=False, physical="1"):
    """Build lightweight selector inputs or complete synthetic target authority."""
    paths = protocol_paths(version)
    stable = {"deviceOrVolume": physical, "inodeOrFileIndex": physical,
              "creationOrChangeTimeNs": physical, "writeTimeNs": physical,
              "reparsePoint": False}
    targets = []
    for path in paths:
        if complete:
            targets.append({
                "path": path, "canonicalSourcePath": str(REAL_REPO_ROOT / path),
                "size": max(1, len(path.encode("utf-8"))),
                "sha256": digest(b"issue107-selector\0" + path.encode("utf-8")),
                "fileIdentity": stable.copy(), "modeType": "regular-file",
                "reparsePoint": False,
            })
        else:
            targets.append({"path": path})
    if version == 3:
        by_path = {target["path"]: target for target in targets}
        lf_sources = V3_SOURCE_PROFILES["LF"][1]
        crlf_sources = V3_SOURCE_PROFILES["CRLF"][1]
        if source_mask is None:
            selected = V3_SOURCE_PROFILES[source_variant][1]
        else:
            selected = tuple(crlf_sources[index] if source_mask & (1 << index)
                             else lf_sources[index] for index in range(6))
        for path, size, sha256 in selected:
            by_path[path].update(size=size, sha256=sha256)
    return targets


def forced_selector_targets(version=2, source_variant="LF"):
    # Fresh targets also prevent shared mutable fixture authority from leaking.
    return protocol_targets(version, source_variant=source_variant)


def v3_package_bytes(source_variant="LF"):
    return V3_PACKAGE_LF if source_variant == "LF" else V3_PACKAGE_CRLF


def v3_reporter_lines(duration="1.25", total="99.5", *, initial=True):
    package = json.loads(V3_PACKAGE_LF)
    lines = ([""] if initial else []) + [
        f"> {package['name']}@{package['version']} test", "> node --test", "",
    ]
    for ordinal, name in enumerate(V3_TOP_LEVEL_NAMES):
        if ordinal == V3_PARENT_ORDINAL:
            lines.append(f"▶ {name}")
            lines.extend(f"  ✔ {child} ({duration}ms)" for child in V3_NESTED_NAMES)
        lines.append(f"✔ {name} ({duration}ms)")
    counts = (154, 0, 154, 0, 0, 0, 0)
    lines.extend(f"ℹ {key} {value}" for key, value in zip(portable.COUNTS, counts))
    lines.append(f"ℹ duration_ms {total}")
    return lines


def encode_reporter_lines(lines, *, newline="\n", terminal=True):
    text = newline.join(lines) + (newline if terminal else "")
    return text.encode("utf-8")


def npm_stdout_v3(duration="1.25", total="99.5", *, newline="\n", initial=True):
    return encode_reporter_lines(v3_reporter_lines(duration, total, initial=initial),
                                 newline=newline)


def v3_layout(*, initial=True):
    member_start = 4 if initial else 3
    heading = member_start + V3_PARENT_ORDINAL
    return SimpleNamespace(member_start=member_start, heading=heading,
        child_start=heading + 1, parent_completion=heading + 7,
        footer_start=member_start + 155)


def v3_duration_spans(stdout):
    """Locate duration spans independently from the production parser."""
    spans, offset = [], 0
    duration_prefix = "ℹ duration_ms ".encode()
    for raw_line in stdout.splitlines(keepends=True):
        body = raw_line[:-2] if raw_line.endswith(b"\r\n") else raw_line[:-1]
        if body.startswith(("✔ ".encode(), "  ✔ ".encode())):
            begin = body.rfind(b" (") + 2
            spans.append((offset + begin, offset + len(body) - 3))
        elif body.startswith(duration_prefix):
            spans.append((offset + len(duration_prefix), offset + len(body)))
        offset += len(raw_line)
    return spans


def retained_segments(stdout, spans):
    segments, offset = [], 0
    for begin, end in spans:
        segments.append(stdout[offset:begin].hex())
        offset = end
    segments.append(stdout[offset:].hex())
    return segments


def replace_spans(stdout, spans, replacements):
    changed = stdout
    for (begin, end), replacement in reversed(list(zip(spans, replacements))):
        changed = changed[:begin] + replacement + changed[end:]
    return changed


def selected_bound_side(stdout, protocol_binding):
    if protocol_binding["version"] == 2:
        package_bytes = PACKAGE
    else:
        package_bytes = v3_package_bytes(protocol_binding["sourceTuple"]["variant"])
    binding = {
        "command": {"commandId": "backend-canonical", "commandClass": "backend-canonical",
                    "ordinal": 0},
        "package": json.loads(package_bytes),
        "packageJsonSha256": digest(package_bytes),
        "tools": {}, "authority": [], "inputBundleDigest": "fixture-input",
        "dependencyClosureDigest": "fixture-dependency",
        "protocol": copy.deepcopy(protocol_binding),
    }
    return portable._BoundSide(stdout, json_bytes(binding))


def selected_bound_pair(producer_stdout, replay_stdout, producer_binding, replay_binding=None):
    replay_binding = producer_binding if replay_binding is None else replay_binding
    return portable._BoundPair(
        selected_bound_side(producer_stdout, producer_binding),
        selected_bound_side(replay_stdout, replay_binding), [], [], "fixture-plan", [])


@contextlib.contextmanager
def force_protocol_selection(version=2, source_variant="LF"):
    """Force only synthetic outer fixtures while preserving fresh-module types."""
    targets = forced_selector_targets(version, source_variant)
    loader = ci._frozen_backend_portable_verifier
    audit = []

    @contextlib.contextmanager
    def instrument(module):
        original = module._select_protocol

        def selected(_synthetic_targets):
            selection = original(targets)
            audit.append(copy.deepcopy(module._protocol_binding(selection)))
            return selection

        with mock.patch.object(module, "_select_protocol", side_effect=selected):
            yield

    @contextlib.contextmanager
    def observed(*args, **kwargs):
        with loader(*args, **kwargs) as module, instrument(module):
            yield module

    with instrument(portable), \
         mock.patch.object(ci, "_frozen_backend_portable_verifier", side_effect=observed):
        yield audit


def npm_stdout(duration="1.25", total="99.5", *, names=None, newline="\n", initial=True):
    names = NAMES if names is None else names
    lines = ([""] if initial else []) + ["> fixture-backend@1.0.0 test", "> node --test", ""]
    lines += [f"✔ {name} ({duration}ms)" for name in names]
    lines += [f"ℹ {key} {value}" for key, value in zip(portable.COUNTS,
               (len(names), 0, len(names), 0, 0, 0, 0))]
    return (newline.join(lines) + newline + f"ℹ duration_ms {total}" + newline).encode()


def fixture(platform="ubuntu", *, stdout=None, stderr=b"", physical="1", ordinal=0,
            retained_streams=("stdout", "stderr"), ordinary_streams=None):
    """Observed npm grammar/inventory size with public, synthetic preimages.

    Both platform labels exercise production record/bundle/closure validators.
    No real executable, package install, or private evidence is involved.
    """
    stable = {"deviceOrVolume": physical, "inodeOrFileIndex": physical,
              "creationOrChangeTimeNs": physical, "writeTimeNs": physical, "reparsePoint": False}
    targets = []
    for relative, data in (("backend/package.json", PACKAGE),
                           ("backend/test/backend.test.js", "\n".join(NAMES).encode())):
        targets.append({"path": relative, "canonicalSourcePath": str(ci.REPO_ROOT / relative),
                        "size": len(data), "sha256": digest(data), "fileIdentity": stable.copy(),
                        "modeType": "regular-file", "reparsePoint": False})
    node_path = str(Path(sys.executable).parent / "fixture-node.exe")
    npm_path = str(Path(sys.executable).parent / "fixture-npm-cli.js")
    spec = fixtures.synthetic_command_spec("backend-canonical", "backend-canonical", ordinal,
        command_role="observation-producing", allowed_exits=[0, 1], targets=targets,
        execution_input_mode="PROTECTED-TARGET-BUNDLE")
    spec.update(profile="all", platform=platform, toolRole="npm-backend-test",
                resultSemantics="baseline-classified-test-result",
                argv=[npm_path, "--prefix", "backend", "test"],
                logicalArgv=[npm_path, "--prefix", "backend", "test"],
                executionArgv=[node_path, npm_path, "--prefix", "backend", "test"],
                resolvedExecutablePath=node_path, resolvedExecutableSize=64,
                resolvedExecutableSha256=digest(b"fixture-node"),
                resolvedExecutableFileIdentity=stable.copy())
    stdout = npm_stdout() if stdout is None else stdout
    capture = ci.CommandCapture(command_id=spec["commandId"], command_class=spec["commandClass"],
        argv=spec["executionArgv"], executed=True, exit_code=0, duration_seconds=0.125,
        stdout=stdout.decode("utf-8", errors="replace"), stderr=stderr.decode("utf-8", errors="replace"),
        stdout_raw=stdout, stderr_raw=stderr,
        stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        include_preview=False, containment="windows-job-object" if platform == "windows"
        else "linux-subreaper-pidfd-proc-supervisor", process_tree_status="contained-clean",
        containment_disposition="natural-exit-reaped", descendants_observed=1, descendants_reaped=1,
        execution_input_mode="PROTECTED-TARGET-BUNDLE")
    record = fixtures.synthetic_record_from_spec(spec)
    record.update({k: v for k, v in capture.evidence().items() if k not in (
        "executionInputs", "executionInputBundleDigest", "protectedTargetBundle", "targetExecutionLease")})
    record.pop("parsedFailureSummary", None)
    # Establish the original measured authority before independently dropping
    # retained capture or replacing ordinary text. Neither supplies missing bytes.
    for stream in ("stdout", "stderr"):
        if stream not in retained_streams:
            setattr(capture, stream + "_raw", None)
        if ordinary_streams is not None and stream in ordinary_streams:
            setattr(capture, stream, ordinary_streams[stream])
    guard = {"guardSchemaVersion": ci.RUNTIME_DEPENDENCY_GUARD_SCHEMA_VERSION,
             "watcherBackend": "_WindowsDirectoryMutationWatcher" if platform == "windows"
             else "_InotifyMutationWatcher", "active": False, "activeDuringReplay": True,
             "mutationState": "clean", "queueOverflow": False, "mutationEventCount": 0}
    def tool(role, path, sha, **extra):
        tool_stable = stable.copy() if platform == "ubuntu" else {
            "volumeSerial": physical, "fileIndex": physical, "writeTime": physical,
            "size": 64, "links": 1, "reparsePoint": False}
        return {"role": role, "canonicalPath": path, "size": 64, "sha256": sha,
                "stableIdentity": tool_stable, "leaseHeld": True, **extra}
    roots = []
    for root in ("developer/node_modules", "backend/node_modules"):
        members = [{"relativePath": "fixture/index.js", "fileType": "regular-file", "mode": "100644",
                    "size": 1, "sha256": digest(root.encode()), "symlinkTarget": None}]
        roots.append({"logicalRoot": root, "memberCount": len(members), "members": members,
                      "memberManifestDigest": digest(ci._canonical_frame(members))})
    semantic = {"lockfiles": [{"relativePath": path, "mode": "100644", "size": 1,
                 "sha256": digest(path.encode())} for path in
                 ("developer/package-lock.json", "backend/package-lock.json")],
                "dependencyRoots": roots, "vitest": None, "nodePath": []}
    closure = {"closureSchemaVersion": ci.RUNTIME_DEPENDENCY_CLOSURE_SCHEMA_VERSION,
               "measurementStatus": "measured-complete", "profile": "all",
               "runnerOS": "Windows" if platform == "windows" else "Linux",
               "pythonExecutable": tool("python-verifier", sys.executable, digest(b"python")),
               "nodeExecutable": tool("node-runtime", node_path, digest(b"fixture-node"), version="v24.20.0"),
               "npmEntrypoint": tool("npm-entrypoint", npm_path, digest(b"fixture-npm"),
                                     version="11.0.0", available=True), "gitExecutable": None,
               **semantic, "dependencyClosureDigest": digest(ci._canonical_frame(semantic)),
               "dependencyMemberCount": 2}
    closure["closureDigest"] = digest(ci._canonical_frame(closure))
    runtime = {"node": "v24.20.0", "npm": "11.0.0", "runtimeClosureDigest": closure["closureDigest"],
               "dependencyClosureDigest": closure["dependencyClosureDigest"], "dependencyMemberCount": "2",
               "platform": platform, "os": "test", "python": "3.12.0", "pythonImplementation": "CPython"}
    record.update(dependencyBacked=True, runtimeClosureDigest=closure["closureDigest"],
        dependencyClosureDigest=closure["dependencyClosureDigest"], nodePath=[],
        resolvedTestRunnerEntrypoint=node_path, resolvedTestRunnerSha256=digest(b"fixture-node"),
        closureWatcherActive=True, closureMutationState="clean", runtimeClosureGuard=guard,
        completedCommandClass="backend-canonical")
    binder = object.__new__(ci.FoundationRunner)
    binder.command_results, binder.observations = [record], []
    ci.FoundationRunner.add_process_observation(binder, record, capture,
        source_result_id="command:npm --prefix backend test", source_path="backend/package.json")
    return portable._ReplayEvidence(record, spec, stdout, stderr, PACKAGE, runtime, closure, guard)


def v3_fixture(platform="ubuntu", *, duration="1.25", total="99.5", physical="1",
               ordinal=0, source_variant="LF"):
    package = v3_package_bytes(source_variant)
    expected_size, expected_sha256 = {
        "LF": (736, V3_SOURCE_PROFILES["LF"][1][1][2]),
        "CRLF": (763, V3_SOURCE_PROFILES["CRLF"][1][1][2]),
    }[source_variant]
    if (len(package), digest(package)) != (expected_size, expected_sha256):
        raise AssertionError(("v3-package-preimage", source_variant, len(package), digest(package)))
    evidence = fixture(platform, stdout=npm_stdout_v3(duration, total),
                       physical=physical, ordinal=ordinal)
    spec = copy.deepcopy(evidence.expected_authority)
    spec["targets"] = protocol_targets(3, source_variant=source_variant,
                                       complete=True, physical=physical)
    rebuilt = fixtures.synthetic_record_from_spec(spec)
    record = copy.deepcopy(evidence.command_record)
    for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest",
                "protectedTargetBundle"):
        record[key] = copy.deepcopy(rebuilt[key])
    return replace(evidence, command_record=record, expected_authority=spec,
                   package_json=package)


def unrelated_specs(family, ordinal):
    ids = (["frontend-security:adminFrontendGuard.test.js", "frontend-security:remotePracticeDataSource.test.js"]
           if family == "frontend-security" else [family])
    return [fixtures.synthetic_command_spec(command_id, family, ordinal + i) for i, command_id in enumerate(ids)]


def unrelated_record(spec):
    record = fixtures.synthetic_record_from_spec(spec)
    if spec["commandClass"] == "frontend-security":
        path = "developer/tests/js/" + spec["commandId"].split(":")[1]
        record["producerObservations"] = [ci.make_raw_observation(spec["commandId"], spec["ordinal"], 0,
            "process-output-v1", "file:" + path, path,
            {"executed": True, "exitCode": 0, "stdout": "", "stderr": "", "error": None},
            ci.command_output_digest(record))]
    return record


def replay_fixture(producer, replay, *, compact=False, extra=False, prefix_count=0, frontend_ordinals=()):
    prefix = [fixtures.synthetic_command_spec(f"fixture-{i}", "baseline-policy", i)
              for i in range(prefix_count)]
    for ordinal in frontend_ordinals:
        name = Path(ci.SECURITY_GUARD_FILES[ordinal - 687]).name
        prefix[ordinal] = fixtures.synthetic_command_spec(
            "frontend-security:" + name, "frontend-security", ordinal)
    specs = prefix + [copy.deepcopy(replay.expected_authority)]
    records = [unrelated_record(spec) for spec in prefix] + [copy.deepcopy(replay.command_record)]
    producer_records = copy.deepcopy(records[:-1]) + [copy.deepcopy(producer.command_record)]
    if extra:
        for family in extra if isinstance(extra, tuple) else ("fixture",):
            for spec in unrelated_specs(family, len(specs)):
                specs.append(spec)
                records.append(unrelated_record(spec))
                records[-1]["completedCommandClass"] = spec["commandClass"]
                producer_records.append(copy.deepcopy(records[-1]))
    runner = SimpleNamespace(profile="all", platform=replay.command_record["platform"], release_gate_required=False,
        command_plan=specs, command_results=records, observations=[], completed_classes=set(),
        hard_gate_results=[], violations=[], runtime_closure_digest=replay.runtime_closure["closureDigest"],
        runtime_closure_document=copy.deepcopy(replay.runtime_closure), runtime=copy.deepcopy(replay.runtime),
        runtime_closure_guard_evidence=copy.deepcopy(replay.runtime_guard),
        dependency_closure_digest=replay.runtime_closure["dependencyClosureDigest"], dependency_member_count=2)
    runner.execution_binding = fixtures.synthetic_execution_binding("all", ci.command_plan_digest(specs),
                                                                    platform_name=runner.platform)
    runner.captures = [ci.CommandCapture(
        command_id="backend-canonical", command_class="backend-canonical",
        argv=replay.expected_authority["executionArgv"], executed=True, exit_code=0,
        duration_seconds=0.125, stdout=replay.stdout.decode("utf-8", errors="replace"),
        stderr=replay.stderr.decode("utf-8", errors="replace"), stdout_raw=replay.stdout,
        stderr_raw=replay.stderr, stdout_bytes=len(replay.stdout), stderr_bytes=len(replay.stderr),
        include_preview=False, containment=replay.command_record["containment"],
        process_tree_status="contained-clean", containment_disposition="natural-exit-reaped",
        descendants_observed=1, descendants_reaped=1, execution_input_mode="PROTECTED-TARGET-BUNDLE")]
    ci.finalize_evidence_transcript(runner)
    transcript = ci.verification_replay_transcript(runner)
    commands = copy.deepcopy(transcript)
    commands.update(records=[ci._compact_command_record_for_evidence(r) if compact else r for r in producer_records],
        commandAuthority=ci._portable_command_plan_value(specs), observations=[], runtime=copy.deepcopy(producer.runtime),
        runtimeDependencyClosure=copy.deepcopy(producer.runtime_closure),
        runtimeDependencyGuard=copy.deepcopy(producer.runtime_guard),
        completedCommandClasses=transcript["actualCompletedCommandClasses"],
        producerObservationUniverseDigest=ci.producer_observation_universe_digest(producer_records),
        producerTranscriptDigest=ci.producer_transcript_digest(ci.command_plan_digest(specs),
            producer_records, transcript["actualCompletedCommandClasses"]))
    summary = {key: copy.deepcopy(transcript[key]) for key in ("profile", "executionBinding",
               "executionBindingDigest", "authorizationContextBinding", "authorizationContextBindingDigest")}
    comparison = fixtures.empty_comparison()
    summary.update(knownDebtsObserved=[], resolvedCandidates=[], expectedOmissions=[], releaseOnlySkips=[])
    return runner, {"summary.json": summary, "command-results.json": commands}, comparison


@contextlib.contextmanager
def outer_fixture(producer=None, replay=None, *, compact=True, extra=False, prefix_count=0,
                  hosted=False, frontend_ordinals=(), forced_protocol=(2, "LF")):
    with fixtures.backend_verifier_source_fixture() as source:
        producer = fixture() if producer is None else copy.deepcopy(producer)
        replay = fixture(stdout=npm_stdout("90", "912"), physical="9") if replay is None else copy.deepcopy(replay)
        # Both sides include the unchanged verifier source, with actual local authority.
        # Source authority is independently remeasured by the production loader.
        for evidence in (producer, replay):
            matches = [index for index, target in enumerate(evidence.expected_authority["targets"])
                       if target["path"] == source.target["path"]]
            if len(matches) > 1:
                raise AssertionError("duplicate backend verifier target in fixture")
            if matches:
                evidence.expected_authority["targets"][matches[0]] = copy.deepcopy(source.target)
            else:
                evidence.expected_authority["targets"].append(copy.deepcopy(source.target))
            rebuilt = fixtures.synthetic_record_from_spec(evidence.expected_authority)
            for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
                evidence.command_record[key] = copy.deepcopy(rebuilt[key])
        runner, _documents, _comparison = replay_fixture(producer, replay, extra=extra,
            prefix_count=prefix_count, frontend_ordinals=frontend_ordinals)
        runner.tools, runner.child_environment = source.tools, source.environment
        runner.execution_binding["trustFileDigest"] = source.trust_digest
        if hosted:
            runner.execution_binding.update(bindingMode="github-actions", producerJobId=(
                "windows-compatibility-producer" if runner.platform == "windows" else "ubuntu-canonical-producer"),
                runId="123456", runAttempt="1", eventName="workflow_dispatch", repository="fixture/backend-cli")
            runner.execution_binding["producerInvocationId"] = ci._github_binding_invocation_id({
                k: v for k, v in runner.execution_binding.items() if k != "producerInvocationId"})
        context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                          fresh_runtime_closure_digest=runner.runtime_closure_digest)
        runner.verifier_execution_binding = context.verifier_binding()
        runner.authorization_context_binding = context.authorization_context_binding()
        runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(
            runner.authorization_context_binding)
        runner.baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
        producer_runner = copy.deepcopy(runner)
        producer_runner.command_results[prefix_count] = copy.deepcopy(producer.command_record)
        producer_runner.command_plan[prefix_count] = copy.deepcopy(producer.expected_authority)
        producer_runner.runtime = copy.deepcopy(producer.runtime)
        producer_runner.runtime_closure_document = copy.deepcopy(producer.runtime_closure)
        producer_runner.runtime_closure_guard_evidence = copy.deepcopy(producer.runtime_guard)
        for target in (runner, producer_runner):
            target.observations = [{"rawObservation": raw} for record in target.command_results
                                   for raw in record["producerObservations"]]
            ci.finalize_evidence_transcript(target)
        root = source.root
        (root / "backend").mkdir(exist_ok=True)
        (root / "backend/package.json").write_bytes(producer.package_json)
        package_target = ci._target_authority(root, "backend/package.json")
        # The independent verifier plan uses the actual candidate's local identity.
        # Producer physical identities continue to differ and remain compact on wire.
        for target in runner.command_plan[prefix_count]["targets"]:
            if target["path"] == "backend/package.json":
                target.update(canonicalSourcePath=package_target["canonicalSourcePath"],
                              fileIdentity=package_target["fileIdentity"])
        rebuilt = fixtures.synthetic_record_from_spec(runner.command_plan[prefix_count])
        for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
            runner.command_results[prefix_count][key] = copy.deepcopy(rebuilt[key])
        ci.finalize_evidence_transcript(runner)
        output = root / ".ci-results"
        ci.create_fresh_evidence_root(output, repo_root=root)
        ci.write_evidence(producer_runner, fixtures.empty_comparison(), output_dir=output,
                          evidence_authority_root=root)
        documents, _snapshots, errors = ci._read_evidence_documents_for_replay(output)
        if errors:
            raise AssertionError(errors)
        if not compact:
            documents["command-results.json"]["records"] = producer_runner.command_results
            write_documents(output, documents)
        summary = documents["summary.json"]
        comparison = {key: summary[field] for key, field in (
            ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
            ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()
        runner.cleanup_task_resources = mock.Mock()
        selection_context = (contextlib.nullcontext([]) if forced_protocol is None
                             else force_protocol_selection(*forced_protocol))
        with selection_context as selected_protocols, \
             mock.patch.object(ci, "rebuild_external_verification_context", return_value=context), \
             mock.patch.object(ci, "REPO_ROOT", root):
            yield SimpleNamespace(producer=producer, replay=replay, runner=runner, context=context,
                root=root, output=output, documents=documents, comparison=comparison,
                pair={"producer": producer, "replay": replay}, source=source,
                selected_protocols=selected_protocols)


def write_documents(output, documents, *, ascii_json=False):
    summary = documents["summary.json"]
    payloads = {name: (json.dumps(value, ensure_ascii=True).encode() if ascii_json else ci._json_bytes(value))
                for name, value in documents.items() if name != "summary.json"}
    payloads["summary.md"] = ci.render_summary_markdown(summary).encode()
    for entry in summary["evidenceManifest"]:
        data = payloads[entry["relativeFilename"]]
        entry.update(byteLength=len(data), sha256=digest(data))
    payloads["summary.json"] = ci._json_bytes(summary)
    for name, data in payloads.items():
        (output / name).write_bytes(data)


def verify(case):
    return ci.verify_evidence_with_replay(case.output, expected_context=case.context,
        verification_runner=case.runner, evidence_authority_root=case.root,
        repo_root=case.root)


def reseal_producer(case):
    """Recompute ordinary aggregates so negatives test authority, not stale hashes."""
    commands = case.documents["command-results.json"]
    records = commands["records"]
    for record in records:
        for raw in record["producerObservations"]:
            raw["sourceOutputDigest"] = ci.command_output_digest(record)
            raw["producerRecordDigest"] = ci._producer_record_digest({
                key: value for key, value in raw.items() if key != "producerRecordDigest"})
        record["producerObservationSetDigest"] = ci.producer_observation_set_digest(record["producerObservations"])
    commands["producerObservationCount"] = sum(len(r["producerObservations"]) for r in records)
    commands["producerObservationUniverseDigest"] = ci.producer_observation_universe_digest(records)
    commands["producerTranscriptDigest"] = ci.producer_transcript_digest(
        commands["commandPlanDigest"], records, commands["actualCompletedCommandClasses"])
    write_documents(case.output, case.documents)


def invoke_main(case):
    """Keep the real CLI, five-file verifier, binding, comparison and envelope path."""
    context = case.context
    arguments = ["--verify-evidence", "--expected-profile", context.expected_profile,
                 "--untrusted-evidence-root", str(case.output), "--require-fresh-runtime-closure"]
    if context.binding_mode == "github-actions":
        arguments.extend(["--expected-producer-job", context.producer_job_id,
                          "--expected-verifier-job", context.verifier_job_id,
                          "--expected-runner-os", context.runner_os])
    else:
        arguments.extend(["--expected-invocation-id", context.producer_invocation_id])
    if context.runner_os == "Linux":
        arguments.append("--require-linux-containment-self-test")
    original = ci.verify_evidence_with_replay
    results = []
    def verified(*args, **kwargs):
        results.append(original(*args, **kwargs))
        return results[-1]
    output = io.StringIO()
    with mock.patch.object(ci, "prepare_verification_authority", return_value=(context, case.runner)), \
         mock.patch.object(ci, "capture_live_external_authority", return_value=fixtures._explicit_live_local_external_authority()), \
         mock.patch.object(ci, "verify_evidence_with_replay", side_effect=verified) as verifier, \
         contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        exit_code = ci.main(arguments)
    if len(results) != 1:
        raise AssertionError(output.getvalue())
    return exit_code, results[0], output.getvalue(), verifier.call_args


def unequal_ordinals(errors):
    prefix = "verification replay first command differences: "
    return sorted({item["ordinal"] for error in errors if error.startswith(prefix)
                   for item in json.loads(error[len(prefix):])})


def drift_unrelated_record(record):
    data = b"fresh unrelated result differs"
    record.update(stdoutSha256=digest(data), stdoutBytesObserved=len(data))
    for raw in record["producerObservations"]:
        raw["rawStructuredFields"]["stdout"] = data.decode()
        raw["sourceOutputDigest"] = ci.command_output_digest(record)
        raw["producerRecordDigest"] = ci._producer_record_digest({
            key: value for key, value in raw.items() if key != "producerRecordDigest"})
    record["producerObservationSetDigest"] = ci.producer_observation_set_digest(record["producerObservations"])


def unsafe_stream_cases():
    # Public synthetic material is assembled so repository secret scanning does
    # not mistake the regression source itself for retained operational output.
    return {
        "credential token": "github_" + "pat_" + "a" * 24,
        "credential assignment": "password" + "=synthetic-value",
        "CRLF password assignment": "password" + "\r\n=synthetic-value",
        "CRLF token assignment": "token" + "\r\n:synthetic-value",
        "CRLF session assignment": "sessionid" + "\r\n=synthetic-value",
        "Authorization header": "Authorization" + ": synthetic-auth-value",
        "Bearer text": "Bearer" + " synthetic-bearer-value",
        "cookie material": "Cookie" + ": session=synthetic-cookie-value",
        "Set-Cookie material": "Set-Cookie" + ": session=synthetic-cookie-value",
        "private-key marker": "-----BEGIN " + "PRIVATE KEY-----",
        "credential URL": "https://" + "fixture:synthetic-password@example.invalid/test",
        "credential URL separator alias": "https:" + "\\" * 2 + "fixture:synthetic-password@example.invalid/test",
        "database URL separator alias": "postgres:" + "\\" * 2 + "fixture:synthetic-password@example.invalid/db",
        "Windows drive path": r"C:\private-fixture\runner-output.txt",
        "Windows UNC path": r"\\private-fixture\share\runner-output.txt",
        "Windows device path": r"\\?\C:\private-fixture\runner-output.txt",
        "Windows file URI": "file:///C:/private-fixture/runner-output.txt",
        "POSIX home path": "/home/private-fixture/runner-output.txt",
        "POSIX task path": "/tmp/private-fixture/runner-output.txt",
        "POSIX home separator alias": r"\home\private-fixture\runner-output.txt",
        "POSIX opt separator alias": r"\opt\private-fixture\runner-output.txt",
        "POSIX mixed separators": r"/home\private-fixture\runner-output.txt",
        "reviewer literal t prefix": r"\tmp/private-fixture/runner-output.txt",
        "literal t mixed root": r"\tmp\private-fixture/runner-output.txt",
        "literal n prefix": r"\n \tmp/private-fixture/runner-output.txt",
        "literal r prefix": r"\r \tmp/private-fixture/runner-output.txt",
        "changed unsafe literal n suffix": r"\tmp/private-fixture/\notes.txt",
        "changed unsafe literal r suffix": r"\tmp/private-fixture/\runner-output.txt",
        "Windows mixed t prefix": r"C:\tmp/private-fixture\runner-output.txt",
        "Windows mixed n prefix": r"C:\new/private-fixture\runner-output.txt",
        "Windows mixed r prefix": r"C:\runner/private-fixture\runner-output.txt",
        "UNC mixed t prefix": r"\\tmp/private-fixture\runner-output.txt",
        "UNC mixed n prefix": r"\\new/private-fixture\runner-output.txt",
        "UNC mixed r prefix": r"\\runner/private-fixture\runner-output.txt",
        "file URI mixed t prefix": r"file:\\tmp/private-fixture\runner-output.txt",
        "file URI mixed n prefix": r"file:\\new/private-fixture\runner-output.txt",
        "file URI mixed r prefix": r"file:\\runner/private-fixture\runner-output.txt",
        "terminal escape": "\x1b[31mprivate-fixture\x1b[0m",
        "ASCII control": "private\x00fixture",
        "bidi control": "private\u202efixture",
        "Unicode format control": "private\u2066fixture\u2069",
    }


class BackendCanonicalPortableResultTest(unittest.TestCase):
    def test_policy_frontend_and_packaging_main_never_reach_backend_parser(self):
        for profile, family in (("policy", "baseline-policy"), ("all", "frontend-security"),
                                ("all", "standalone-packaging")):
            with self.subTest(profile=profile, family=family), tempfile.TemporaryDirectory(prefix="no-backend-") as temp:
                root = Path(temp)
                baseline = ci.strict_json_load_file(ci.BASELINE_PATH)
                if profile == "policy":
                    with mock.patch.object(ci, "expected_command_authority", return_value=[]):
                        runner = fixtures.fake_runner(baseline)
                else:
                    source = fixture()
                    runner, _, _ = replay_fixture(source, source)
                    runner.baseline = baseline
                runner.command_plan = unrelated_specs(family, 0)
                for spec in runner.command_plan:
                    spec.update(profile=profile, platform=runner.platform)
                runner.command_results = [unrelated_record(spec) for spec in runner.command_plan]
                runner.observations = [{"rawObservation": raw} for record in runner.command_results
                                       for raw in record["producerObservations"]]
                runner.command_plan_digest = ci.command_plan_digest(runner.command_plan)
                runner.runtime_closure_digest = runner.runtime_closure_document["closureDigest"]
                runner.dependency_closure_digest = runner.runtime_closure_document["dependencyClosureDigest"]
                runner.dependency_member_count = runner.runtime_closure_document["dependencyMemberCount"]
                runner.execution_binding = fixtures.synthetic_execution_binding(profile, runner.command_plan_digest,
                    platform_name=runner.platform)
                context = replace(fixtures.synthetic_external_context(runner.execution_binding),
                    fresh_runtime_closure_digest=runner.runtime_closure_digest)
                runner.verifier_execution_binding = context.verifier_binding()
                runner.authorization_context_binding = context.authorization_context_binding()
                runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(runner.authorization_context_binding)
                output = root / ".ci-results"
                ci.create_fresh_evidence_root(output, repo_root=root)
                summary = ci.write_evidence(runner, fixtures.empty_comparison(), output_dir=output, evidence_authority_root=root)
                comparison = {key: summary[field] for key, field in (
                    ("observedDebts", "knownDebtsObserved"), ("resolvedCandidates", "resolvedCandidates"),
                    ("expectedOmissions", "expectedOmissions"), ("releaseOnlySkips", "releaseOnlySkips"))}
                runner.run = mock.Mock(return_value=comparison)
                runner.close_execution_leases = mock.Mock()
                runner.cleanup_task_resources = mock.Mock()
                case = SimpleNamespace(context=context, runner=runner, output=output)
                with mock.patch.object(ci, "REPO_ROOT", root), \
                     mock.patch.object(ci, "rebuild_external_verification_context", return_value=context), \
                     portable_spy("_parse_stdout") as parser, \
                     portable_spy("_identity") as identity, \
                     portable_spy("_bind_producer") as binder:
                    exit_code, (errors, transcript), text, _ = invoke_main(case)
                self.assertEqual((exit_code, errors), (ci.EXIT_SUCCESS, []), text)
                self.assertEqual(transcript["finalAcceptance"], "PASS")
                self.assertNotIn("backendCanonicalPortableResult", transcript)
                runner.run.assert_called_once()
                parser.assert_not_called()
                identity.assert_not_called()
                binder.assert_not_called()
                print("BACKEND_NO_PATH " + json.dumps({"profile": profile, "family": family,
                    "parser": 0, "identity": 0, "acceptance": "PASS"}))

    def test_hosted_shaped_main_duration_drift_and_exact_unrelated_commands(self):
        for mismatch in (None, "frontend-security", "standalone-packaging"):
            with self.subTest(mismatch=mismatch), outer_fixture(
                fixture(ordinal=701), fixture(ordinal=701, stdout=npm_stdout("90", "912"), physical="9"),
                prefix_count=701, extra=("frontend-security", "standalone-packaging"), hosted=True) as case:
                record = case.documents["command-results.json"]["records"][701]
                self.assertEqual(record["executionInputs"], [])
                self.assertTrue(all(record["protectedTargetBundle"][k] == []
                    for k in ci._PROTECTED_BUNDLE_DUPLICATE_ARRAY_FIELDS))
                self.assertEqual(record["producerObservations"][0]["rawStructuredFields"]["stdout"].encode(),
                                 case.producer.stdout)
                before, raw_errors = ci.compare_verification_replay_claims(case.documents, case.runner, case.comparison)
                self.assertTrue(any('"ordinal":701' in e for e in raw_errors), raw_errors)
                if mismatch:
                    def drift():
                        other = next(r for r in case.runner.command_results if r["commandClass"] == mismatch)
                        drift_unrelated_record(other)
                        return case.comparison
                    case.runner.run.side_effect = drift
                with portable_spy("_parse_stdout") as parser, \
                     portable_spy("_identity") as identity:
                    exit_code, (errors, transcript), output, call = invoke_main(case)
                self.assertNotIn("backend_result_evidence", call.kwargs)
                case.runner.run.assert_called_once()
                case.runner.close_execution_leases.assert_called_once()
                case.runner.cleanup_task_resources.assert_called_once()
                self.assertFalse(any('"ordinal":701' in e for e in errors), errors)
                if mismatch:
                    self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
                    self.assertTrue(any(mismatch in e and "stdout-identity" in e for e in errors), errors)
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT")
                    self.assertEqual((parser.call_count, identity.call_count), (2, 2))
                else:
                    self.assertEqual((exit_code, errors), (ci.EXIT_SUCCESS, []), output)
                    self.assertEqual(transcript["finalAcceptance"], "PASS")
                    self.assertEqual(transcript["backendCanonicalPortableResult"]["result"]["command"]["ordinal"], 701)
                    self.assertEqual((parser.call_count, identity.call_count), (2, 2))
                print("BACKEND_CLI " + json.dumps({"mismatch": mismatch, "exit": exit_code,
                    "parser": parser.call_count, "identity": identity.call_count,
                    "ordinal701Unequal": False, "acceptance": transcript["finalAcceptance"]}))

    def assert_hosted_mismatches(self, platform, *, backend_change=None):
        frontend = (687, 692, 695) if platform == "windows" else (687, 695)
        stdout = npm_stdout("90", "912")
        if backend_change == "semantic mutation":
            stdout = stdout.replace(b"value 1000", b"value 9999", 1)
        elif backend_change == "parser failure":
            stdout += b"unknown numeric output 123\n"
        with outer_fixture(fixture(platform, ordinal=701, stderr=b""),
            fixture(platform, ordinal=701, stdout=stdout, stderr=b"", physical="9"), prefix_count=701,
            extra=("standalone-packaging",), hosted=True, frontend_ordinals=frontend) as case:
            self.assertIs(type(case.runner.captures[0].stderr_raw), bytes)
            self.assertEqual(case.runner.captures[0].stderr_raw, b"")
            for record in (case.producer.command_record, case.replay.command_record):
                self.assertEqual(record["producerObservations"][0]["rawStructuredFields"]["stderr"], "")
            def drift():
                for ordinal in (*frontend, 702):
                    drift_unrelated_record(case.runner.command_results[ordinal])
                if backend_change == "unavailable":
                    case.runner.captures.clear()
                return case.comparison
            case.runner.run.side_effect = drift
            with portable_spy("_parse_stdout") as parser, \
                 portable_spy("_identity") as identity:
                exit_code, (errors, transcript), output, call = invoke_main(case)
            self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
            self.assertEqual(transcript["finalAcceptance"], "REJECT")
            expected = sorted([*frontend, 702] + ([701] if backend_change else []))
            self.assertEqual(unequal_ordinals(errors), expected, errors)
            expected_calls = ((0, 0) if backend_change == "unavailable" else
                              (2, 0) if backend_change == "parser failure" else (2, 2))
            self.assertEqual((parser.call_count, identity.call_count), expected_calls)
            if backend_change:
                self.assertTrue(any("backend-canonical portable result unavailable" in e for e in errors))
            self.assertNotIn("backendCanonicalPortableResult", transcript)
            self.assertNotIn("backend_result_evidence", call.kwargs)
            case.runner.run.assert_called_once()
            case.runner.close_execution_leases.assert_called_once()
            case.runner.cleanup_task_resources.assert_called_once()
            self.assertEqual(set(p.name for p in case.output.iterdir()), set(ci.EVIDENCE_FILE_NAMES))
            print("BACKEND_HOSTED_SHAPED " + json.dumps({"platform": platform,
                "backendChange": backend_change, "unequalOrdinals": unequal_ordinals(errors),
                "parser": parser.call_count, "identity": identity.call_count,
                "finalAcceptance": transcript["finalAcceptance"]}, sort_keys=True))

    def test_hosted_shaped_ubuntu_main_unresolved_frontend_and_packaging(self):
        self.assert_hosted_mismatches("ubuntu")

    def test_hosted_shaped_windows_main_unresolved_frontend_and_packaging(self):
        self.assert_hosted_mismatches("windows")

    def test_hosted_shaped_backend_semantic_mutation_under_frontend_failure(self):
        self.assert_hosted_mismatches("ubuntu", backend_change="semantic mutation")

    def test_hosted_shaped_backend_unavailable_or_parser_failure_retains_701(self):
        for change in ("unavailable", "parser failure"):
            with self.subTest(change=change):
                self.assert_hosted_mismatches("ubuntu", backend_change=change)

    def assert_rejected(self, case, label, *, parser_calls=0, identity_calls=0):
        with portable_spy("_parse_stdout") as parser, \
             portable_spy("_identity") as identity:
            errors, transcript = verify(case)
        self.assertTrue(errors, label)
        self.assertNotIn("backendCanonicalPortableResult", transcript or {}, label)
        self.assertNotEqual((transcript or {}).get("finalAcceptance"), "PASS", label)
        self.assertEqual(parser.call_count, parser_calls, label)
        self.assertEqual(identity.call_count, identity_calls, label)
        print("BACKEND_NEGATIVE " + json.dumps({"case": label, "parser": parser.call_count,
            "identity": identity.call_count, "attached": False, "pass": False}, sort_keys=True))

    def assert_private_rejection(self, reason, function, *args):
        with self.assertRaisesRegex(
                ValueError, rf"^backend portable result unavailable: {reason}$"):
            function(*args)

    def test_valid_outer_path(self):
        for platform in ("ubuntu", "windows"):
            for compact in (False, True):
                with self.subTest(platform=platform, compact=compact), outer_fixture(
                    fixture(platform), fixture(platform, stdout=npm_stdout("90", "912"), physical="9"),
                    compact=compact) as case:
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    errors, transcript = verify(case)
                    self.assertEqual(errors, [])
                    self.assertEqual(transcript["finalAcceptance"], "PASS")
                    self.assertIn("backendCanonicalPortableResult", transcript)
                    case.runner.run.assert_called_once()
                    case.runner.close_execution_leases.assert_called_once()

    def test_call_order_and_detached_authorization_bound_attachment(self):
        with outer_fixture() as case:
            events = []
            names = ("_bind_producer", "_bind_replay", "_parse_stdout", "_identity")
            raw_verify = ci.verify_evidence_file_set
            semantics = ci._validate_evidence_semantics
            compare = ci._compare_verification_replay_claims
            eligibility = ci._verification_replay_eligibility
            finish = ci._finish_verification_replay
            read_snapshot = ci._read_evidence_file_snapshot
            def raw(*args, **kwargs):
                errors = raw_verify(*args, **kwargs)
                self.assertEqual(errors, [])
                events.append("raw-valid")
                return errors
            def semantic(*args, **kwargs):
                errors = semantics(*args, **kwargs)
                self.assertEqual(errors, [])
                events.append("semantics-valid")
                return errors
            def compared(*args, **kwargs):
                events.append("comparisons")
                return compare(*args, **kwargs)
            def eligible(*args, **kwargs):
                events.append("eligibility")
                return eligibility(*args, **kwargs)
            def finished(transcript, *args, **kwargs):
                events.append("attached-envelope" if "backendCanonicalPortableResult" in transcript
                              else "eligibility-envelope")
                return finish(transcript, *args, **kwargs)
            def stable(path, *args, **kwargs):
                if "fresh-run" in events:
                    events.append("stability:" + path.name)
                return read_snapshot(path, *args, **kwargs)
            case.runner.run.side_effect = lambda: (events.append("fresh-run") or case.comparison)
            case.runner.close_execution_leases.side_effect = lambda: events.append("closed")
            before_files = {p.name: p.read_bytes() for p in case.output.iterdir()}
            before_record = json_bytes(case.runner.command_results)
            with contextlib.ExitStack() as stack:
                for name in names:
                    stack.enter_context(portable_spy(name, before=lambda name=name: events.append(name)))
                stack.enter_context(mock.patch.object(ci, "verify_evidence_file_set", side_effect=raw))
                stack.enter_context(mock.patch.object(ci, "_validate_evidence_semantics", side_effect=semantic))
                stack.enter_context(mock.patch.object(ci, "_compare_verification_replay_claims", side_effect=compared))
                stack.enter_context(mock.patch.object(ci, "_verification_replay_eligibility", side_effect=eligible))
                stack.enter_context(mock.patch.object(ci, "_finish_verification_replay", side_effect=finished))
                stack.enter_context(mock.patch.object(ci, "_read_evidence_file_snapshot", side_effect=stable))
                stack.enter_context(mock.patch.object(ci, "rebuild_external_verification_context",
                    side_effect=lambda *a, **k: (events.append("external-context") or case.context)))
                errors, transcript = verify(case)
            self.assertEqual(errors, [])
            self.assertLess(events.index("raw-valid"), events.index("_bind_producer"))
            self.assertEqual(events[:events.index("_bind_producer")].count("semantics-valid"), 2)
            self.assertLess(events.index("_bind_producer"), events.index("fresh-run"))
            self.assertLess(events.index("closed"), events.index("_bind_replay"))
            self.assertEqual(events.count("_bind_replay"), 2)
            first_parse = events.index("_parse_stdout")
            self.assertEqual(events[:first_parse].count("_bind_replay"), 2)
            self.assertLess(events.index("eligibility"), events.index("eligibility-envelope"))
            self.assertLess(events.index("eligibility-envelope"), events.index("external-context"))
            self.assertNotIn("comparisons", events[:first_parse])
            self.assertLess(events.index("external-context"), first_parse)
            self.assertEqual(sum(e.startswith("stability:") for e in events[:first_parse]), 5)
            self.assertEqual(events[first_parse:], ["_parse_stdout", "_parse_stdout", "_identity", "_identity",
                                                   "comparisons", "eligibility", "attached-envelope"])
            self.assertEqual({p.name: p.read_bytes() for p in case.output.iterdir()}, before_files)
            self.assertEqual(json_bytes(case.runner.command_results), before_record)
            raw_transcript = {k: v for k, v in transcript.items() if k not in (
                "currentFullContextDigestSetDigest", "verifierReplayContextBinding",
                "verifierReplayContextDigest", "replayAuthorizationEnvelopeDigest", "finalAcceptance")}
            self.assertEqual(transcript["verifierReplayContextBinding"]["replayTranscriptDigest"],
                             ci.canonical_failure_digest(raw_transcript))
            transcript["backendCanonicalPortableResult"]["result"]["orderedTests"][0]["name"] = "detached"
            self.assertEqual(json_bytes(case.runner.command_results), before_record)
            print("BACKEND_ORDER " + json.dumps(events))

    def test_invalid_raw_documents_and_file_structure_never_reach_binding(self):
        changes = {
            "invalid schemaVersion": lambda d: d["summary.json"].update(schemaVersion=999),
            "invalid documentKind": lambda d: d["command-results.json"].update(documentKind="claimed"),
            "invalid authorization claim": lambda d: d["summary.json"]["authorizationContextBinding"].update(
                expectedVerifierJobId="another-verifier"),
            "invalid producer raw hash": lambda d: d["command-results.json"]["records"][0].update(
                stdoutSha256="0" * 64),
            "invalid producer raw record": lambda d: d["command-results.json"]["records"][0].update(
                unknownAuthority=True),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                change(case.documents)
                write_documents(case.output, case.documents)
                with portable_spy("_bind_producer", side_effect=AssertionError("must not bind")):
                    self.assert_rejected(case, label)
                case.runner.run.assert_not_called()
        for label in ("missing evidence file", "extra evidence file", "invalid JSON"):
            with self.subTest(case=label), outer_fixture() as case:
                if label == "missing evidence file":
                    (case.output / "summary.md").unlink()
                elif label == "extra evidence file":
                    (case.output / "extra.json").write_bytes(b"{}\n")
                else:
                    (case.output / "summary.json").write_bytes(b"{broken}\n")
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_second_snapshot_is_validated_before_binding(self):
        for field, value in (("schemaVersion", 999), ("documentKind", "forged"),
                             ("authorizationContextBindingDigest", "0" * 64)):
            with self.subTest(field=field), outer_fixture() as case:
                real_verify = ci.verify_evidence_file_set
                def replace_after_validation(*args, **kwargs):
                    errors = real_verify(*args, **kwargs)
                    self.assertEqual(errors, [])
                    case.documents["summary.json"][field] = value
                    write_documents(case.output, case.documents)
                    return errors
                with mock.patch.object(ci, "verify_evidence_file_set", side_effect=replace_after_validation):
                    self.assert_rejected(case, "second snapshot " + field)
                case.runner.run.assert_not_called()

    def test_compact_producer_authority_matrix(self):
        changes = {
            "raw reconstructed input digest": lambda r: r.update(executionInputBundleDigest="sha256:" + "0" * 64),
            "target path": lambda r: r["targets"][0].update(path="backend/other.json"),
            "target order": lambda r: r["targets"].reverse(),
            "target content": lambda r: r["targets"][0].update(sha256="0" * 64),
            "target size": lambda r: r["targets"][0].update(size=123),
            "target mode": lambda r: r["targets"][0].update(modeType="other"),
            "target reparse": lambda r: r["targets"][0].update(reparsePoint=True),
            "command association": lambda r: r.update(ordinal=1),
            "compact pre reference": lambda r: r["protectedTargetBundle"]["preExecutionIdentities"].__setitem__(0, "0" * 64),
            "compact post reference": lambda r: r["protectedTargetBundle"]["postExecutionIdentities"].__setitem__(0, "0" * 64),
            "NODE_PATH authority": lambda r: r.update(nodePath=["untrusted"]),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                record = case.documents["command-results.json"]["records"][0]
                self.assertEqual(record["executionInputs"], [])
                change(record)
                reseal_producer(case)
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_self_consistent_compact_rewrites_still_need_independent_authority(self):
        for kind in ("path", "order", "content", "mode", "reparse", "association"):
            with self.subTest(kind=kind), outer_fixture() as case:
                record = case.documents["command-results.json"]["records"][0]
                if kind == "order":
                    record["targets"].reverse()
                elif kind == "association":
                    record["ordinal"] = 1
                else:
                    field, value = {"path": ("path", "backend/other.json"),
                        "content": ("sha256", "0" * 64), "mode": ("modeType", "other"),
                        "reparse": ("reparsePoint", True)}[kind]
                    record["targets"][0][field] = value
                record["executionInputBundleDigest"] = ci.execution_input_bundle_digest(
                    ci._reconstructed_protected_execution_inputs(record))
                bundle = record["protectedTargetBundle"]
                bundle["executionInputBundleDigest"] = record["executionInputBundleDigest"]
                for phase, key in (("pre", "preExecutionIdentities"), ("post", "postExecutionIdentities")):
                    bundle[key] = ci._protected_bundle_compact_identity_digests(record, phase=phase)
                reseal_producer(case)
                errors = []
                ci._validate_command_record(record, 0, errors, expected_record=case.runner.command_plan[0])
                self.assertTrue(any("independently reconstructed" in e for e in errors), errors)
                self.assert_rejected(case, "self-consistent compact " + kind)
                case.runner.run.assert_not_called()

    def test_producer_runtime_closure_guard_matrix(self):
        changes = {
            "runtime mutation": lambda c: c["runtime"].update(node="v24.99.0"),
            "dependency mutation": lambda c: c["runtimeDependencyClosure"]["dependencyRoots"][0]["members"][0].update(sha256="0" * 64),
            "tool mutation": lambda c: c["runtimeDependencyClosure"]["npmEntrypoint"].update(sha256="0" * 64),
            "guard mutation": lambda c: c["runtimeDependencyGuard"].update(mutationState="dirty"),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                change(case.documents["command-results.json"])
                write_documents(case.output, case.documents)
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()

    def test_exact_observation_stream_reconstruction_matrix(self):
        for stream in ("stdout", "stderr"):
            for kind in ("bytes", "hash", "length", "missing", "type", "normalized"):
                with self.subTest(stream=stream, kind=kind), outer_fixture() as case:
                    record = case.documents["command-results.json"]["records"][0]
                    fields = record["producerObservations"][0]["rawStructuredFields"]
                    if kind == "bytes":
                        fields[stream] += "x"
                    elif kind == "normalized":
                        if stream == "stderr":
                            continue
                        fields[stream] = ci.raw_observation_json_value(fields[stream])
                    elif kind == "missing":
                        fields.pop(stream)
                    elif kind == "type":
                        fields[stream] = [fields[stream]]
                    elif kind == "hash":
                        record[stream + "Sha256"] = "0" * 64
                    else:
                        record[stream + "BytesObserved"] += 1
                    reseal_producer(case)
                    # All ordinary hashes are coherent; only exact stream recovery rejects.
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    self.assert_rejected(case, f"producer {stream} {kind}")
                    case.runner.run.assert_not_called()

    def test_fresh_runner_binding_and_execution_failures(self):
        changes = {
            "missing replay capture": lambda r: r.captures.clear(),
            "duplicate replay capture": lambda r: r.captures.append(copy.deepcopy(r.captures[0])),
            "fresh capture stdout mutation": lambda r: setattr(r.captures[0], "stdout_raw", b"wrong"),
            "fresh capture stderr mutation": lambda r: setattr(r.captures[0], "stderr_raw", b"wrong"),
            "fresh capture exit mutation": lambda r: setattr(r.captures[0], "exit_code", 1),
            "fresh capture argv mutation": lambda r: r.captures[0].argv.append("--help"),
            "fresh capture foreign stdin lease": lambda r: setattr(r.captures[0], "target_execution_lease", {
                "logicalTargetPath": "foreign.js", "executionAdapter": "TARGET-BYTES-STDIN",
                "plannedByteLength": 1, "plannedSha256": "0" * 64,
                "executedInputByteLength": 1, "executedInputSha256": "0" * 64}),
            "fresh runtime mutation": lambda r: r.runtime.update(node="v24.99.0"),
            "fresh dependency mutation": lambda r: r.runtime_closure_document["dependencyRoots"][0]["members"][0].update(sha256="0" * 64),
            "fresh tool mutation": lambda r: r.runtime_closure_document["nodeExecutable"].update(sha256="0" * 64),
            "fresh guard mutation": lambda r: r.runtime_closure_guard_evidence.update(queueOverflow=True),
            "fresh target mutation": lambda r: r.command_results[0]["targets"][0].update(sha256="0" * 64),
            "fresh input mutation": lambda r: r.command_results[0]["executionInputs"][0].update(actualSha256="0" * 64),
            "fresh mode mutation": lambda r: r.command_results[0]["executionInputs"][0].update(inputMode="NONE"),
            "fresh reparse mutation": lambda r: r.command_results[0]["targets"][0].update(reparsePoint=True),
            "fresh association mutation": lambda r: r.command_results[0]["executionInputs"].reverse(),
            "fresh plan mutation": lambda r: r.command_plan[0]["targets"][0].update(sha256="0" * 64),
            "hard-gate failure": lambda r: r.hard_gate_results.append({"id": ci.HARD_GATE_AUTHORITY[0], "status": "fail"}),
            "execution violation": lambda r: r.violations.append({"id": "CI-RUNNER-ERROR"}),
            "execution timeout": lambda r: r.command_results[0].update(timeoutStatus="TIMED-OUT"),
            "unclean cleanup": lambda r: setattr(r, "private_temp_handle", object()),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture() as case:
                def run():
                    change(case.runner)
                    return case.comparison
                case.runner.run.side_effect = run
                self.assert_rejected(case, label)
                case.runner.run.assert_called_once()
                case.runner.close_execution_leases.assert_called_once()
        for label, result in (("runner unavailable", OSError("unavailable")), ("comparison unavailable", None)):
            with self.subTest(case=label), outer_fixture() as case:
                if isinstance(result, Exception):
                    case.runner.run.side_effect = result
                else:
                    case.runner.run.return_value = result
                self.assert_rejected(case, label)

    def test_malformed_records_and_observations_do_not_execute(self):
        for kind in ("malformed record", "duplicate backend record", "missing observation",
                     "duplicate observation", "unknown observation kind", "foreign observation kind"):
            with self.subTest(kind=kind), outer_fixture() as case:
                records = case.documents["command-results.json"]["records"]
                record = records[0]
                if kind == "malformed record":
                    record.pop("protectedTargetBundle")
                elif kind == "duplicate backend record":
                    records.append(copy.deepcopy(record))
                elif kind == "missing observation":
                    record["producerObservations"].clear()
                elif kind == "duplicate observation":
                    record["producerObservations"].append(copy.deepcopy(record["producerObservations"][0]))
                    record["producerObservations"][-1]["observationOrdinal"] = 1
                else:
                    record["producerObservations"][0]["observationKind"] = (
                        "unknown" if kind == "unknown observation kind" else "normalized-fields-v1")
                reseal_producer(case)
                self.assert_rejected(case, kind)
                case.runner.run.assert_not_called()

    def test_package_and_source_stability_matrix(self):
        for kind in ("changed bytes", "missing file", "changed after raw validation",
                     "changed during replay", "changed after context recheck"):
            with self.subTest(kind=kind), outer_fixture() as case:
                source = case.root / "backend/package.json"
                def change():
                    source.write_bytes(PACKAGE + b" ")
                if kind == "changed bytes":
                    change()
                elif kind == "missing file":
                    source.unlink()
                elif kind == "changed after raw validation":
                    original = ci.verify_evidence_file_set
                    def validate(*args, **kwargs):
                        errors = original(*args, **kwargs)
                        self.assertEqual(errors, [])
                        change()
                        return errors
                    with mock.patch.object(ci, "verify_evidence_file_set", side_effect=validate):
                        self.assert_rejected(case, kind)
                    continue
                elif kind == "changed during replay":
                    case.runner.run.side_effect = lambda: (change() or case.comparison)
                else:
                    def recheck(*args, **kwargs):
                        change()
                        return case.context
                    with mock.patch.object(ci, "rebuild_external_verification_context", side_effect=recheck):
                        self.assert_rejected(case, kind)
                    continue
                self.assert_rejected(case, kind)
        missing = fixture()
        missing.expected_authority["targets"].pop(0)
        rebuilt = fixtures.synthetic_record_from_spec(missing.expected_authority)
        for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
            missing.command_record[key] = copy.deepcopy(rebuilt[key])
        with outer_fixture(missing, missing) as case:
            self.assert_rejected(case, "missing protected package target")
            case.runner.run.assert_not_called()

    def test_invalid_utf8_reconstruction_and_producer_stderr(self):
        for label, producer in (("invalid UTF-8 replacement", fixture(stdout=npm_stdout() + b"\xff")),
                                ("nonempty producer stderr", fixture(stderr=b"warning 123\n"))):
            with self.subTest(label=label), outer_fixture(producer=producer) as case:
                self.assert_rejected(case, label)
                case.runner.run.assert_not_called()
        with outer_fixture() as case:
            fields = case.documents["command-results.json"]["records"][0]["producerObservations"][0]["rawStructuredFields"]
            fields["stdout"] = "\ud800"
            write_documents(case.output, case.documents, ascii_json=True)
            self.assert_rejected(case, "unencodable UTF-8 surrogate")
            case.runner.run.assert_not_called()

    def test_public_outer_api_has_no_injection_argument(self):
        self.assertEqual(list(inspect.signature(ci.verify_evidence_with_replay).parameters),
            ["output_dir", "expected_context", "verification_runner", "repo_root", "evidence_authority_root"])
        with outer_fixture() as case:
            with self.assertRaises(TypeError):
                ci.verify_evidence_with_replay(case.output, expected_context=case.context,
                    verification_runner=case.runner, backend_result_evidence=case.pair)
            case.runner.run.assert_not_called()

    def test_outer_safety_precedes_parser_and_unrelated_semantics_follow(self):
        with outer_fixture() as case:
            with mock.patch.object(ci, "rebuild_external_verification_context",
                return_value=replace(case.context, verifier_invocation_id="8" * 64)):
                self.assert_rejected(case, "external context changed")
        with outer_fixture() as case:
            def changed_file():
                (case.output / "summary.md").write_bytes(b"changed during replay\n")
                return case.comparison
            case.runner.run.side_effect = changed_file
            self.assert_rejected(case, "evidence changed during replay")
        with outer_fixture() as case:
            def extra_file():
                (case.output / "extra.json").write_bytes(b"{}\n")
                return case.comparison
            case.runner.run.side_effect = extra_file
            self.assert_rejected(case, "evidence membership changed during replay")
        with outer_fixture() as case:
            case.runner.run.return_value = {**case.comparison, "resolvedCandidates": [{"unrelated": True}]}
            self.assert_rejected(case, "unrelated summary comparison", parser_calls=2, identity_calls=2)
        with outer_fixture(extra=True) as case:
            def other_command():
                case.runner.command_results[-1]["stdoutSha256"] = "0" * 64
                return case.comparison
            case.runner.run.side_effect = other_command
            self.assert_rejected(case, "unrelated command comparison", parser_calls=2, identity_calls=2)

    def test_unrelated_execution_state_and_authority_fail_before_parser(self):
        def coherent_binding(runner, key):
            runner.execution_binding[key] = "9" * 64
            runner.authorization_context_binding = ci.authorization_context_binding_from_execution_binding(
                runner.execution_binding)
            runner.authorization_context_binding_digest = ci.authorization_context_binding_digest(
                runner.authorization_context_binding)
        changes = {
            "profile selector": lambda r: setattr(r, "profile", "backend"),
            "execution binding": lambda r: coherent_binding(r, "producerInvocationId"),
            "authorization binding": lambda r: coherent_binding(r, "trustFileDigest"),
            "command membership": lambda r: r.command_results.pop(),
            "duplicate command": lambda r: r.command_results.append(copy.deepcopy(r.command_results[-1])),
            "incomplete unrelated command": lambda r: r.command_results[-1].update(exitCode=1),
            "unrelated command authority": lambda r: r.command_results[-1].update(commandRole="observation-producing"),
            "unrelated raw execution": lambda r: r.command_results[-1].update(actualExecutionArgv=["unbound"]),
            "unrelated raw stream schema": lambda r: r.command_results[-1].update(stdoutBytesObserved=-1),
        }
        for label, change in changes.items():
            with self.subTest(case=label), outer_fixture(extra=True) as case:
                case.runner.run.side_effect = lambda: (change(case.runner) or case.comparison)
                self.assert_rejected(case, label)

    def assert_private_stream_evidence(self, label, payload, placement, *, platform="ubuntu", ordinal=0,
                                       retained_streams=("stdout", "stderr"), invalid_stream=None):
        stream = "stderr" if placement == "stderr" else "stdout"
        streams = {"stdout": npm_stdout(), "stderr": b""}
        streams[stream] = (npm_stdout(names=[payload, *NAMES[1:]])
                           if placement == "reporter-name" else payload.encode())
        if invalid_stream is not None:
            streams[invalid_stream] += b"\xff"
        producer = fixture(platform, ordinal=ordinal, retained_streams=retained_streams, **streams)
        fields = producer.command_record["producerObservations"][0]["rawStructuredFields"]
        original = streams[stream].decode("utf-8", errors="replace")
        self.assertFalse(ci._backend_exact_stream_text_is_safe(original))
        ordinary = ci.raw_observation_json_value(original)
        expected = ordinary if ci._backend_exact_stream_text_is_safe(ordinary) else "[BACKEND STREAM REDACTED]"
        self.assertEqual(fields[stream], expected)
        self.assertTrue(all(ci._backend_exact_stream_text_is_safe(fields[s]) for s in streams))
        self.assertNotEqual(fields[stream].encode(), streams[stream])
        with outer_fixture(producer, fixture(platform, ordinal=ordinal, stdout=npm_stdout("90", "912")),
                           prefix_count=ordinal, hosted=ordinal == 701) as case:
            self.assertEqual(set(p.name for p in case.output.iterdir()), set(ci.EVIDENCE_FILE_NAMES))
            self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
            serialized = (case.output / "command-results.json").read_bytes()
            on_disk = json.loads(serialized)["records"][ordinal]
            self.assertEqual(on_disk["producerObservations"][0]["rawStructuredFields"], fields)
            self.assertNotIn(payload.encode(), serialized)
            self.assertNotIn(json.dumps(payload, ensure_ascii=False)[1:-1].encode(), serialized)
            for path in case.output.iterdir():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn(payload, text)
                self.assertNotIn(json.dumps(payload, ensure_ascii=False)[1:-1], text)
            for name, data in streams.items():
                for record in (producer.command_record, on_disk):
                    self.assertEqual(record[name + "Sha256"], digest(data))
                    self.assertEqual(record[name + "BytesObserved"], len(data))
            encoded = fields[stream].encode()
            self.assertFalse(len(encoded) == on_disk[stream + "BytesObserved"]
                             and digest(encoded) == on_disk[stream + "Sha256"])
            with portable_spy("_parse_stdout") as parser, \
                 portable_spy("_identity") as identity:
                self.assertIsNone(portable._bind_producer(ci, case.documents["command-results.json"],
                                  case.runner.command_plan, case.root))
                exit_code, (errors, transcript), output, _ = invoke_main(case)
                self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
                self.assertTrue(any("backend-canonical portable result unavailable" in e for e in errors), errors)
                self.assertNotIn("backendCanonicalPortableResult", transcript or {})
                self.assertNotEqual((transcript or {}).get("finalAcceptance"), "PASS")
                case.runner.run.assert_not_called()
                # The unchanged lower API compares the independently captured raw
                # pair. Sanitized observation equality cannot remove its ordinal.
                raw_transcript, raw_errors = ci.run_verification_replay(case.documents,
                    expected_context=case.context, verification_runner=case.runner, repo_root=case.root)
                self.assertEqual(unequal_ordinals(raw_errors), [ordinal], raw_errors)
                self.assertEqual(raw_transcript["finalAcceptance"], "REJECT")
                self.assertNotIn("backendCanonicalPortableResult", raw_transcript)
                parser.assert_not_called()
                identity.assert_not_called()
            print("BACKEND_PRIVACY " + json.dumps({"case": label, "placement": placement,
                "platform": platform, "ordinal": ordinal, "fallback": "ordinary" if expected == ordinary else "marker",
                "serializedOriginalAbsent": True, "serializedEscapedOriginalAbsent": True,
                "fiveFileEvidenceValid": True, "originalHashAndLengthPreserved": True,
                "producerExactStream": "unavailable", "parser": 0, "identity": 0,
                "rawUnequalOrdinals": unequal_ordinals(raw_errors), "finalAcceptance": "REJECT"}, sort_keys=True))

    def test_exact_stream_privacy_matrix_never_writes_unsafe_retained_bytes(self):
        for label, payload in unsafe_stream_cases().items():
            for placement in ("stdout", "stderr", "reporter-name"):
                with self.subTest(case=label, placement=placement):
                    self.assert_private_stream_evidence(label, payload, placement)

    def test_reviewer_counterexample_retains_raw_701_and_rejects_without_parsing(self):
        payload = r"\tmp/private-fixture/runner-output.txt"
        reporter = npm_stdout(names=[payload, *NAMES[1:]])
        members, _segments = portable._parse_stdout(reporter, json.loads(PACKAGE))
        self.assertEqual(len(members), 141)
        self.assertEqual(members[0]["name"], payload)
        for platform in ("ubuntu", "windows"):
            for placement in ("stdout", "stderr", "reporter-name"):
                with self.subTest(platform=platform, placement=placement):
                    self.assert_private_stream_evidence("reviewer counterexample", payload, placement,
                                                       platform=platform, ordinal=701)

    def test_missing_and_undecodable_raw_streams_still_check_ordinary_evidence(self):
        payload = r"\tmp/private-fixture/runner-output.txt"
        for stream in ("stdout", "stderr"):
            for missing in ("stdout", "stderr"):
                with self.subTest(stream=stream, missing=missing):
                    self.assert_private_stream_evidence("missing " + missing, payload, stream,
                        retained_streams=tuple(s for s in ("stdout", "stderr") if s != missing))
            for invalid in ("stdout", "stderr"):
                with self.subTest(stream=stream, invalid=invalid):
                    self.assert_private_stream_evidence("invalid UTF-8 " + invalid, payload, stream,
                                                       invalid_stream=invalid)

    def test_missing_raw_capture_selection_never_uses_ordinary_fallback(self):
        marker = "[BACKEND STREAM REDACTED]"
        for ordinary in ("", marker, "safe ordinary output", npm_stdout().decode(),
                         r"\tmp/private-fixture/runner-output.txt"):
            with self.subTest(ordinary=ordinary):
                self.assertEqual(ci._backend_successful_stream_observation_text(None, ordinary), marker)
        self.assertEqual(ci._backend_successful_stream_observation_text(b"", "safe ordinary output"), "")
        with mock.patch.object(ci, "_backend_exact_stream_text_is_safe", return_value=False) as guard:
            with self.assertRaisesRegex(ValueError, "^backend stream observation failed its privacy check$"):
                ci._backend_successful_stream_observation_text(None, "")
            self.assertTrue(guard.call_args_list)
            self.assertTrue(all(call.args == (marker,) for call in guard.call_args_list))

    def test_missing_raw_capture_matrix_rejects_before_parsing(self):
        marker = "[BACKEND STREAM REDACTED]"
        rewritten = "ordinary fallback output."
        self.assertEqual(len(rewritten.encode()), len(marker.encode()))
        cases = (
            ("missing stderr with empty fallback", ("stderr",), npm_stdout(), {"stderr": ""}),
            ("missing stdout", ("stdout",), npm_stdout(), {}),
            ("both captures missing", ("stdout", "stderr"), npm_stdout(), {}),
            ("missing stdout with coherently rewritten authority", ("stdout",), rewritten.encode(),
             {"stdout": rewritten}),
            ("missing stdout with coincident empty authority", ("stdout",), b"", {"stdout": ""}),
        )
        for platform in ("ubuntu", "windows"):
            for label, missing, stdout, ordinary_streams in cases:
                with self.subTest(platform=platform, case=label):
                    streams = {"stdout": stdout, "stderr": b""}
                    retained = tuple(stream for stream in streams if stream not in missing)
                    with mock.patch.object(ci, "_backend_successful_stream_observation_text",
                        wraps=ci._backend_successful_stream_observation_text) as select:
                        producer = fixture(platform, ordinal=701, retained_streams=retained,
                                           ordinary_streams=ordinary_streams, **streams)
                    self.assertEqual(select.call_count, 2)
                    fields = producer.command_record["producerObservations"][0]["rawStructuredFields"]
                    authority = {stream: {"bytes": len(data), "sha256": digest(data)}
                                 for stream, data in streams.items()}
                    fallback_matches = {}
                    for (stream, data), call in zip(streams.items(), select.call_args_list):
                        self.assertEqual(call.args[0], None if stream in missing else data)
                        ordinary = ci.raw_observation_json_value(ordinary_streams.get(stream, data.decode()))
                        self.assertEqual(call.args[1], ordinary)
                        fallback_matches[stream] = (len(ordinary.encode()) == len(data)
                                                    and digest(ordinary.encode()) == digest(data))
                        self.assertEqual(fields[stream], marker if stream in missing else data.decode())
                        self.assertTrue(ci._backend_exact_stream_text_is_safe(fields[stream]))
                    if "empty" in label or "rewritten" in label:
                        self.assertTrue(fallback_matches[missing[0]])
                    replay = fixture(platform, ordinal=701, stdout=npm_stdout("90", "912"), stderr=b"")
                    with outer_fixture(producer, replay, prefix_count=701, hosted=True) as case:
                        self.assertEqual(set(p.name for p in case.output.iterdir()), set(ci.EVIDENCE_FILE_NAMES))
                        self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                            expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                        serialized = (case.output / "command-results.json").read_bytes()
                        record = json.loads(serialized)["records"][701]
                        self.assertEqual(record["producerObservations"][0]["rawStructuredFields"], fields)
                        for stream, original in authority.items():
                            for observed in (producer.command_record, record):
                                self.assertEqual(observed[stream + "Sha256"], original["sha256"])
                                self.assertEqual(observed[stream + "BytesObserved"], original["bytes"])
                            if stream in missing:
                                emitted = fields[stream].encode()
                                self.assertFalse(len(emitted) == original["bytes"]
                                                 and digest(emitted) == original["sha256"])
                        if "rewritten" in label:
                            self.assertNotIn(rewritten.encode(), serialized)
                            self.assertEqual(len(fields["stdout"].encode()), record["stdoutBytesObserved"])
                            self.assertNotEqual(digest(fields["stdout"].encode()), record["stdoutSha256"])
                        before_files = {p.name: p.read_bytes() for p in case.output.iterdir()}
                        with portable_spy("_parse_stdout") as parser, \
                             portable_spy("_identity") as identity, \
                             portable_spy("_bind_side") as bind_side:
                            self.assertIsNone(portable._bind_producer(ci, case.documents["command-results.json"],
                                              case.runner.command_plan, case.root))
                            bind_side.assert_not_called()
                            exit_code, (errors, transcript), output, _ = invoke_main(case)
                            self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
                            self.assertTrue(any("backend-canonical portable result unavailable" in e
                                                for e in errors), errors)
                            self.assertNotIn("backendCanonicalPortableResult", transcript or {})
                            self.assertNotEqual((transcript or {}).get("finalAcceptance"), "PASS")
                            case.runner.run.assert_not_called()
                            raw_transcript, raw_errors = ci.run_verification_replay(case.documents,
                                expected_context=case.context, verification_runner=case.runner, repo_root=case.root)
                            self.assertEqual(unequal_ordinals(raw_errors), [701], raw_errors)
                            self.assertEqual(raw_transcript["finalAcceptance"], "REJECT")
                            self.assertNotIn("backendCanonicalPortableResult", raw_transcript)
                            parser.assert_not_called()
                            identity.assert_not_called()
                            bind_side.assert_not_called()
                        self.assertEqual({p.name: p.read_bytes() for p in case.output.iterdir()}, before_files)
                        print("BACKEND_CAPTURE_MISSING " + json.dumps({"platform": platform, "case": label,
                            "missing": missing, "ordinaryFallbackMatchesAuthority": fallback_matches,
                            "serializedStreams": {stream: fields[stream] for stream in streams},
                            "rawAuthority": authority, "originalHashAndLengthPreserved": True,
                            "fiveFileEvidenceValid": True, "serializedStreamsPrivacySafe": True,
                            "producerBinding": "unavailable before side binding", "parser": 0, "identity": 0,
                            "portablePresent": False, "rawUnequalOrdinals": unequal_ordinals(raw_errors),
                            "finalAcceptance": "REJECT"}, sort_keys=True))

    def assert_reserved_marker_nonportable(self, label, *, missing, ordinary):
        marker = "[BACKEND STREAM REDACTED]"
        marker_bytes = marker.encode("ascii")
        marker_sha256 = "819fd70120e7e0f1296db421669cc9291df70b0dd5e3baad731ddf844bd8f616"
        self.assertEqual(len(marker_bytes), 25)
        self.assertEqual(digest(marker_bytes), marker_sha256)
        for platform in ("ubuntu", "windows"):
            with self.subTest(platform=platform, case=label):
                with mock.patch.object(ci, "_backend_successful_stream_observation_text",
                    wraps=ci._backend_successful_stream_observation_text) as select:
                    producer = fixture(platform, ordinal=701, stdout=marker_bytes, stderr=b"",
                        retained_streams=("stderr",) if missing else ("stdout", "stderr"),
                        ordinary_streams={"stdout": ordinary})
                self.assertEqual(select.call_args_list,
                    [mock.call(None if missing else marker_bytes, ordinary), mock.call(b"", "")])
                original_authority = {stream + suffix: producer.command_record[stream + suffix]
                    for stream in ("stdout", "stderr") for suffix in ("BytesObserved", "Sha256")}
                self.assertEqual(original_authority, {
                    "stdoutBytesObserved": 25, "stdoutSha256": marker_sha256,
                    "stderrBytesObserved": 0, "stderrSha256": digest(b"")})
                replay = fixture(platform, ordinal=701, stdout=npm_stdout("90", "912"), stderr=b"")
                with outer_fixture(producer, replay, prefix_count=701, hosted=True) as case:
                    self.assertEqual(set(p.name for p in case.output.iterdir()), set(ci.EVIDENCE_FILE_NAMES))
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    record = json.loads((case.output / "command-results.json").read_bytes())["records"][701]
                    fields = record["producerObservations"][0]["rawStructuredFields"]
                    self.assertEqual((fields["stdout"], fields["stderr"]), (marker, ""))
                    # Exact marker authority must not upgrade this reserved value
                    # into portable evidence, even when the raw capture existed.
                    self.assertEqual(len(fields["stdout"].encode()), record["stdoutBytesObserved"])
                    self.assertEqual(digest(fields["stdout"].encode()), record["stdoutSha256"])
                    for observed in (producer.command_record, record):
                        self.assertEqual({key: observed[key] for key in original_authority}, original_authority)
                    before_files = {p.name: p.read_bytes() for p in case.output.iterdir()}
                    with portable_spy("_parse_stdout") as parser, \
                         portable_spy("_identity") as identity, \
                         portable_spy("_bind_side") as bind_side:
                        bound = portable._bind_producer(ci, case.documents["command-results.json"],
                                                       case.runner.command_plan, case.root)
                        self.assertTrue(bound is None, "reserved marker must fail before side binding")
                        bind_side.assert_not_called()
                        exit_code, (errors, transcript), output, _ = invoke_main(case)
                        self.assertEqual(exit_code, ci.EXIT_POLICY_VIOLATION, output)
                        self.assertTrue(any("backend-canonical portable result unavailable" in e
                                            for e in errors), errors)
                        self.assertNotIn("backendCanonicalPortableResult", transcript or {})
                        self.assertNotEqual((transcript or {}).get("finalAcceptance"), "PASS")
                        case.runner.run.assert_not_called()
                        raw_transcript, raw_errors = ci.run_verification_replay(case.documents,
                            expected_context=case.context, verification_runner=case.runner, repo_root=case.root)
                        self.assertEqual(unequal_ordinals(raw_errors), [701], raw_errors)
                        self.assertEqual(raw_transcript["finalAcceptance"], "REJECT")
                        self.assertNotIn("backendCanonicalPortableResult", raw_transcript)
                        parser.assert_not_called()
                        identity.assert_not_called()
                        bind_side.assert_not_called()
                    self.assertEqual({p.name: p.read_bytes() for p in case.output.iterdir()}, before_files)
                    print("BACKEND_RESERVED_MARKER " + json.dumps({"platform": platform, "case": label,
                        "rawCaptureMissing": missing, "ordinaryStdout": ordinary,
                        "serializedStdout": fields["stdout"], "serializedStderr": fields["stderr"],
                        "rawAuthority": original_authority, "originalHashAndLengthPreserved": True,
                        "fiveFileEvidenceValid": True, "markerAuthorityMatches": True,
                        "producerBinding": "unavailable before side binding", "parser": parser.call_count,
                        "identity": identity.call_count, "portablePresent": False,
                        "backendUnavailable": True, "rawUnequalOrdinals": unequal_ordinals(raw_errors),
                        "finalAcceptance": raw_transcript["finalAcceptance"]}, sort_keys=True))

    def test_missing_stdout_with_marker_authority_rejects_before_parsing(self):
        self.assert_reserved_marker_nonportable("missing stdout with empty fallback and marker authority",
                                               missing=True, ordinary="")

    def test_missing_stdout_with_marker_fallback_and_authority_rejects_before_parsing(self):
        self.assert_reserved_marker_nonportable("missing stdout with marker fallback and authority",
                                               missing=True, ordinary="[BACKEND STREAM REDACTED]")

    def test_captured_literal_marker_is_intentionally_nonportable(self):
        self.assert_reserved_marker_nonportable("retained literal marker capture with matching authority",
                                               missing=False, ordinary="[BACKEND STREAM REDACTED]")

    def test_captured_empty_stderr_preserves_exact_portability(self):
        for platform in ("ubuntu", "windows"):
            with self.subTest(platform=platform):
                with mock.patch.object(ci, "_backend_successful_stream_observation_text",
                    wraps=ci._backend_successful_stream_observation_text) as select:
                    producer = fixture(platform, ordinal=701, stderr=b"")
                self.assertIs(type(select.call_args_list[1].args[0]), bytes)
                self.assertEqual(select.call_args_list[1].args[0], b"")
                replay = fixture(platform, ordinal=701, stdout=npm_stdout("90", "912"), stderr=b"")
                with outer_fixture(producer, replay, prefix_count=701, hosted=True) as case:
                    record = json.loads((case.output / "command-results.json").read_bytes())["records"][701]
                    self.assertEqual(record["producerObservations"][0]["rawStructuredFields"]["stderr"], "")
                    self.assertEqual(record["stderrBytesObserved"], 0)
                    self.assertEqual(record["stderrSha256"], digest(b""))
                    self.assertEqual(case.runner.captures[0].stderr_raw, b"")
                    for path in case.output.iterdir():
                        self.assertNotIn("[BACKEND STREAM REDACTED]", path.read_text(encoding="utf-8"))
                    with portable_spy("_parse_stdout") as parser, \
                         portable_spy("_identity") as identity:
                        self.assertIsNotNone(portable._bind_producer(ci, case.documents["command-results.json"],
                                             case.runner.command_plan, case.root))
                        exit_code, (errors, transcript), output, _ = invoke_main(case)
                    self.assertEqual((exit_code, errors), (ci.EXIT_SUCCESS, []), output)
                    self.assertEqual(transcript["finalAcceptance"], "PASS")
                    self.assertEqual(transcript["backendCanonicalPortableResult"]["result"]["stderr"],
                                     {"byteLength": 0, "sha256": digest(b"")})
                    self.assertEqual(unequal_ordinals(errors), [])
                    self.assertEqual((parser.call_count, identity.call_count), (2, 2))
                    case.runner.run.assert_called_once()
                    print("BACKEND_CAPTURE_EMPTY " + json.dumps({"platform": platform, "stderrRaw": "b''",
                        "serializedStderr": "", "stderrBytesObserved": 0, "stderrSha256": digest(b""),
                        "markerEmitted": False, "producerBinding": "available", "parser": parser.call_count,
                        "identity": identity.call_count, "portablePresent": True, "unequalOrdinals": [],
                        "ordinal701Unequal": False, "finalAcceptance": transcript["finalAcceptance"]}, sort_keys=True))

    def test_backend_redaction_marker_is_fixed_and_final_value_must_pass_guard(self):
        marker = ci._BACKEND_STREAM_REDACTION_MARKER
        self.assertEqual(marker, "[BACKEND STREAM REDACTED]")
        self.assertEqual(len(marker.encode("ascii")), 25)
        self.assertTrue(all(0x20 <= ord(character) <= 0x7e for character in marker))
        self.assertEqual(ci.sanitize_text(marker), marker)
        self.assertEqual(ci.raw_observation_json_value(marker), marker)
        self.assertTrue(ci._backend_exact_stream_text_is_safe(marker))
        payload = r"\tmp/private-fixture/runner-output.txt"
        with mock.patch.object(ci, "_BACKEND_STREAM_REDACTION_MARKER", payload):
            with self.assertRaisesRegex(ValueError, "^backend stream observation failed its privacy check$"):
                fixture(stdout=payload.encode())

    def test_coherent_unsafe_exact_producer_and_replay_streams_fail_binding(self):
        for label, payload in unsafe_stream_cases().items():
            data = npm_stdout(names=[payload, *NAMES[1:]])
            for side in ("producer", "replay"):
                with self.subTest(case=label, side=side), outer_fixture() as case:
                    record = (case.documents["command-results.json"]["records"][0] if side == "producer"
                              else case.runner.command_results[0])
                    record.update(stdoutSha256=digest(data), stdoutBytesObserved=len(data))
                    raw = record["producerObservations"][0]
                    raw["rawStructuredFields"]["stdout"] = data.decode()
                    if side == "producer":
                        reseal_producer(case)
                    else:
                        raw["sourceOutputDigest"] = ci.command_output_digest(record)
                        raw["producerRecordDigest"] = ci._producer_record_digest({
                            k: v for k, v in raw.items() if k != "producerRecordDigest"})
                        record["producerObservationSetDigest"] = ci.producer_observation_set_digest([raw])
                        case.runner.captures[0].stdout = data.decode()
                        case.runner.captures[0].stdout_raw = data
                        case.runner.captures[0].stdout_bytes = len(data)
                    self.assert_rejected(case, "coherent unsafe " + side + " " + label)
                    if side == "producer":
                        case.runner.run.assert_not_called()
                    else:
                        case.runner.run.assert_called_once()
                    print("BACKEND_PRIVACY_BINDING " + json.dumps({"case": label, "side": side,
                        "parser": 0, "identity": 0, "portability": "unavailable"}, sort_keys=True))

    def test_safe_exact_streams_preserve_unicode_newlines_and_literal_escapes(self):
        names = ["caf\u00e9", "cafe\u0301", r'literal \n \u1234 {"value":123}', "timing text (42ms)",
                 "[BACKEND STREAM REDACTED]", *NAMES[5:]]
        for platform in ("ubuntu", "windows"):
            for newline in ("\n", "\r\n"):
                with self.subTest(platform=platform, newline=repr(newline)):
                    producer = fixture(platform, stdout=npm_stdout(names=names, newline=newline))
                    replay = fixture(platform, stdout=npm_stdout("90", "912", names=names, newline=newline))
                    for side in (producer, replay):
                        self.assertTrue(ci._backend_exact_stream_text_is_safe(side.stdout.decode()))
                        self.assertEqual(side.command_record["producerObservations"][0]
                                         ["rawStructuredFields"]["stdout"].encode(), side.stdout)
                    with outer_fixture(producer, replay) as case:
                        errors, transcript = verify(case)
                        self.assertEqual(errors, [])
                        self.assertEqual(transcript["finalAcceptance"], "PASS")
                    print("BACKEND_PRIVACY_SAFE " + json.dumps({"platform": platform,
                        "newline": repr(newline), "exactRetained": True, "finalAcceptance": "PASS"}))

    def test_reporter_failure_has_zero_identity_calls(self):
        for side in ("producer", "replay"):
            producer, replay = fixture(), fixture(stdout=npm_stdout("90", "912"))
            bad = fixture(stdout=npm_stdout() + b"unknown numeric output 123\n")
            if side == "producer":
                producer = bad
            else:
                replay = bad
            with self.subTest(side=side), outer_fixture(producer, replay) as case:
                self.assert_rejected(case, side + " reporter parse failure",
                                     parser_calls=1 if side == "producer" else 2)

    def test_identity_mismatch_never_attaches(self):
        variants = {
            "test name": npm_stdout().replace(b"case 000", b"case 999", 1),
            "numeric text in name": npm_stdout().replace(b"value 1000", b"value 1001", 1),
            "order": npm_stdout(names=[NAMES[1], NAMES[0], *NAMES[2:]]),
            "whitespace": npm_stdout().replace(b"case 000", b"case  000", 1),
            "LF/CRLF": npm_stdout(newline="\r\n"),
            "leading newline": npm_stdout(initial=False),
            "duration-looking name": npm_stdout(names=[NAMES[0] + " (42ms)", *NAMES[1:]]),
        }
        for label, stdout in variants.items():
            with self.subTest(case=label), outer_fixture(replay=fixture(stdout=stdout)) as case:
                self.assert_rejected(case, "identity mismatch " + label, parser_calls=2, identity_calls=2)

    def test_lower_public_apis_have_no_portable_argument_or_path(self):
        self.assertEqual(list(inspect.signature(ci.compare_verification_replay_claims).parameters),
                         ["documents", "runner", "comparison"])
        self.assertEqual(list(inspect.signature(ci.run_verification_replay).parameters),
                         ["documents", "expected_context", "verification_runner", "repo_root"])
        with outer_fixture() as case:
            bad = copy.deepcopy(case.documents)
            bad["summary.json"].update(schemaVersion=999, documentKind="forged", replayStatus="PASS",
                backend_result_evidence=case.pair, backendCanonicalPortableResult={"identityDigest": "claimed"})
            bad["command-results.json"]["records"][0]["stdoutSha256"] = "0" * 64
            case.runner.backend_result_evidence = case.pair
            with portable_spy("_parse_stdout", side_effect=AssertionError("lower parser")) as parser, \
                 portable_spy("_identity", side_effect=AssertionError("lower identity")) as identity, \
                 portable_spy("_derive_equal_result", side_effect=AssertionError("lower derivation")) as derive:
                for documents in (bad, {}):
                    transcript, errors = ci.compare_verification_replay_claims(documents, case.runner, case.comparison)
                    self.assertTrue(errors)
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                    transcript, errors = ci.run_verification_replay(documents, expected_context=case.context,
                        verification_runner=case.runner, repo_root=case.root)
                    self.assertTrue(errors)
                    self.assertEqual(transcript["finalAcceptance"], "REJECT")
                    self.assertNotIn("backendCanonicalPortableResult", transcript)
                with self.assertRaises(TypeError):
                    ci.compare_verification_replay_claims(bad, case.runner, case.comparison,
                                                         backend_result_evidence=case.pair)
                with self.assertRaises(TypeError):
                    ci.run_verification_replay(bad, expected_context=case.context,
                        verification_runner=case.runner, backend_result_evidence=case.pair)
                parser.assert_not_called()
                identity.assert_not_called()
                derive.assert_not_called()
        with portable_spy("_parse_stdout") as parser, portable_spy("_identity") as identity:
            self.assertIsNone(portable._derive_equal_result(ci, {"producer": fixture(), "replay": fixture()}))
            parser.assert_not_called()
            identity.assert_not_called()

    def test_raw_local_frontend_and_packaging_paths_are_unchanged(self):
        with outer_fixture() as case:
            before = json_bytes(ci.finalize_evidence_transcript(case.runner))
            with portable_spy("_parse_stdout", side_effect=AssertionError("local parser")), \
                 portable_spy("_identity", side_effect=AssertionError("local identity")):
                errors = []
                self.assertFalse(ci._validate_command_record(case.producer.command_record, 0, errors,
                    expected_record=case.producer.expected_authority))
                self.assertEqual(errors, [])
                self.assertEqual(json_bytes(ci.finalize_evidence_transcript(case.runner)), before)
                self.assertEqual(ci._command_authority_violations("all", case.runner.command_results,
                    case.runner.observations, expected_plan=case.runner.command_plan), [])
            forged = copy.deepcopy(case.producer.command_record)
            forged["backendCanonicalPortableResult"] = {"identityDigest": "claimed"}
            errors = []
            ci._validate_command_record(forged, 0, errors)
            self.assertTrue(any("keys are not valid" in e for e in errors))

    def test_issue110_a3_both_live_profiles_construct_exact_protocols(self):
        live_paths, errors = ci.deterministic_candidate_paths(REAL_REPO_ROOT)
        self.assertEqual(errors, [])
        ordinary, security = fixtures._r2_counterpart_inventories(live_paths)
        ordinary, security = tuple(ordinary), tuple(security)
        inventories = {2: ordinary, 3: security}
        for live_version in (2, 3, 2):
            with mock.patch.object(ci, "deterministic_candidate_paths",
                                   return_value=(list(inventories[live_version]), [])):
                for requested in (2, 3):
                    for variant in ("LF", "CRLF"):
                        with self.subTest(live=live_version, requested=requested, variant=variant):
                            self.assertEqual(protocol_paths(requested), inventories[requested])
                            targets = forced_selector_targets(requested, variant)
                            self.assertEqual(tuple(target["path"] for target in targets),
                                             inventories[requested])
                            binding = portable._protocol_binding(portable._select_protocol(targets))
                            self.assertEqual(binding["version"], requested)
                            if requested == 3:
                                self.assertEqual(binding["sourceTuple"]["variant"], variant)
        self.assertEqual(set(security) - set(ordinary), set(V3_ADDED_PATHS))
        self.assertFalse(set(ordinary) - set(security))

    def test_issue110_a3_rejects_live_drift_after_fixture_reuse(self):
        live_paths, errors = ci.deterministic_candidate_paths(REAL_REPO_ROOT)
        self.assertEqual(errors, [])
        ordinary, security = fixtures._r2_counterpart_inventories(live_paths)
        ordinary, security = tuple(ordinary), tuple(security)
        # Warm every former cache key before presenting an unauthorized live source.
        for version in (2, 3):
            for variant in ("LF", "CRLF"):
                forced_selector_targets(version, variant)
        corrupted = {
            "unknown": [],
            "duplicate": [*ordinary, ordinary[0]],
            "omitted": list(ordinary[:-1]),
            "extra": [*security, "backend/unapproved-extension.js"],
            "same-count-and-length": [ordinary[0][:-1] + "!", *ordinary[1:]],
            "partial-addition": [*ordinary, V3_ADDED_PATHS[0]],
            "partial-removal": [path for path in security if path != V3_ADDED_PATHS[0]],
            "duplicate-substitution": [ordinary[1], *ordinary[1:]],
        }
        original_selector = portable._select_protocol
        original_loader = ci._frozen_backend_portable_verifier
        for label, paths in corrupted.items():
            with mock.patch.object(ci, "deterministic_candidate_paths", return_value=(paths, [])):
                for version in (2, 3):
                    for build in (protocol_paths, protocol_targets, forced_selector_targets):
                        with self.subTest(source=label, version=version, builder=build.__name__), \
                             self.assertRaisesRegex(AssertionError, "unexpected-live-path-profile"):
                            build(version)
                    with self.assertRaisesRegex(AssertionError, "unexpected-live-path-profile"):
                        with force_protocol_selection(version):
                            self.fail("unauthenticated override entered")
            self.assertIs(portable._select_protocol, original_selector)
            self.assertIs(ci._frozen_backend_portable_verifier, original_loader)
        with mock.patch.object(ci, "deterministic_candidate_paths",
                               return_value=(list(ordinary), ["inventory read failed"])), \
             self.assertRaisesRegex(AssertionError, "inventory read failed"):
            forced_selector_targets()
        targets = forced_selector_targets(3)
        targets[0]["path"] = "backend/unauthorized.js"
        fresh = forced_selector_targets(3)
        self.assertEqual(tuple(target["path"] for target in fresh), security)
        self.assertEqual(portable._protocol_binding(portable._select_protocol(fresh))["version"], 3)

    def test_issue110_a3_target_authentication_and_override_restoration(self):
        live_paths, errors = ci.deterministic_candidate_paths(REAL_REPO_ROOT)
        self.assertEqual(errors, [])
        ordinary, security = fixtures._r2_counterpart_inventories(live_paths)
        ordinary, security = tuple(ordinary), tuple(security)
        for source, requested in ((ordinary, 3), (security, 2)):
            with mock.patch.object(ci, "deterministic_candidate_paths", return_value=(list(source), [])), \
                 mock.patch(__name__ + ".V3_ADDED_PATHS", (V3_ADDED_PATHS[0], "backend/wrong.js")), \
                 self.assertRaisesRegex(AssertionError, "unexpected-target-path-profile"):
                forced_selector_targets(requested)
        for version in (0, 1, 4, "3"):
            with self.assertRaisesRegex(AssertionError, "unknown-protocol-version"):
                forced_selector_targets(version)
        original_selector = portable._select_protocol
        original_loader = ci._frozen_backend_portable_verifier
        for version in (2, 3):
            with force_protocol_selection(version) as audit:
                self.assertEqual(portable._protocol_binding(portable._select_protocol([]))["version"], version)
            self.assertEqual([binding["version"] for binding in audit], [version])
            self.assertIs(portable._select_protocol, original_selector)
            self.assertIs(ci._frozen_backend_portable_verifier, original_loader)
            with self.assertRaisesRegex(RuntimeError, "fixture exit"):
                with force_protocol_selection(version):
                    raise RuntimeError("fixture exit")
            self.assertIs(portable._select_protocol, original_selector)
            self.assertIs(ci._frozen_backend_portable_verifier, original_loader)
            self.assert_private_rejection("unknown-path-profile", portable._select_protocol, [])

    def test_issue107_real_protocol_selection_and_exact_source_profiles(self):
        self.assertEqual((len(V3_PACKAGE_LF), digest(V3_PACKAGE_LF)),
            (736, "64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c"))
        self.assertEqual((len(V3_PACKAGE_CRLF), digest(V3_PACKAGE_CRLF)),
            (763, "2a4f5fc9c2587ff92598f83e9516212ced6304d5c4bceecf0797084423c7bdf7"))
        self.assertEqual(len(V3_TOP_LEVEL_NAMES), 148)
        self.assertEqual(V3_TOP_LEVEL_NAMES[V3_PARENT_ORDINAL],
            "public Listening loader rejects Locator, Manifest, Payload and inventory corruption")
        self.assertEqual(tuple(portable._V3_TOP_LEVEL_NAMES), V3_TOP_LEVEL_NAMES)
        self.assertEqual(tuple(portable._V3_NESTED_NAMES), V3_NESTED_NAMES)
        self.assertEqual(list(inspect.signature(portable._select_protocol).parameters), ["targets"])

        v2_targets = protocol_targets(2)
        self.assertEqual(independent_path_profile([target["path"] for target in v2_targets]),
                         V2_PATH_PROFILE)
        self.assertEqual(portable._trusted_path_profile(v2_targets), {
            "trackedPaths": V2_PATH_PROFILE[0], "serializedUtf8Bytes": V2_PATH_PROFILE[1],
            "sortedPathSha256": V2_PATH_PROFILE[2],
        })
        v2_selection = portable._select_protocol(v2_targets)
        v2_binding = portable._protocol_binding(v2_selection)
        self.assertEqual((v2_binding["version"], v2_binding["sourceTuple"]), (2, None))
        self.assertEqual(v2_binding["hierarchyInventoryDigest"],
                         "c19b500fff55e20740791a59de895da19ccb51e8998f212413cec3c83cd8238a")
        self.assertEqual(portable._parse_selected_stdout(npm_stdout(), json.loads(PACKAGE), v2_binding),
                         portable._parse_stdout(npm_stdout(), json.loads(PACKAGE)))

        for variant in ("LF", "CRLF"):
            targets = protocol_targets(3, source_variant=variant)
            self.assertEqual(independent_path_profile([target["path"] for target in targets]),
                             V3_PATH_PROFILE)
            selection = portable._select_protocol(targets)
            binding = portable._protocol_binding(selection)
            total_bytes, sources = V3_SOURCE_PROFILES[variant]
            self.assertEqual(binding["version"], 3)
            self.assertEqual(binding["digestDomain"],
                             "ieltmps-backend-canonical-portable-result-v3")
            self.assertEqual(binding["pathProfile"], {
                "trackedPaths": V3_PATH_PROFILE[0], "serializedUtf8Bytes": V3_PATH_PROFILE[1],
                "sortedPathSha256": V3_PATH_PROFILE[2],
            })
            self.assertEqual(binding["hierarchyInventoryDigest"], V3_HIERARCHY_DIGEST)
            self.assertEqual(binding["sourceTuple"], {
                "variant": variant, "totalBytes": total_bytes,
                "sources": [{"path": path, "size": size, "sha256": sha256}
                            for path, size, sha256 in sources],
            })

        path_cases = []
        missing = copy.deepcopy(v2_targets)
        missing.pop()
        path_cases.append(("missing", missing, "unknown-path-profile"))
        partial = copy.deepcopy(v2_targets) + [{"path": V3_ADDED_PATHS[0]}]
        path_cases.append(("partial", partial, "unknown-path-profile"))
        extended = protocol_targets(3)
        extended.append({"path": "backend/unapproved-extension.js"})
        path_cases.append(("extended", extended, "unknown-path-profile"))
        renamed = protocol_targets(3)
        renamed[0]["path"] += ".renamed"
        path_cases.append(("renamed", renamed, "unknown-path-profile"))
        duplicated = copy.deepcopy(v2_targets)
        duplicated.append(copy.deepcopy(duplicated[0]))
        path_cases.append(("duplicated", duplicated, "invalid-target-authority"))
        surrogate = copy.deepcopy(v2_targets)
        surrogate[0]["path"] = "backend/\ud800.js"
        path_cases.append(("surrogate", surrogate, "invalid-target-authority"))
        for label, targets, reason in path_cases:
            with self.subTest(path_profile=label):
                self.assert_private_rejection(reason, portable._select_protocol, targets)

        for field, value in (("sha256", "0" * 64), ("size", 1)):
            targets = protocol_targets(3)
            source = next(target for target in targets if target["path"] == "backend/src/app.js")
            source[field] = value
            with self.subTest(source_field=field):
                self.assertEqual(independent_path_profile([target["path"] for target in targets]),
                                 V3_PATH_PROFILE)
                self.assert_private_rejection("invalid-source-tuple", portable._select_protocol,
                                              targets)

    def test_issue107_rejects_all_62_mixed_source_tuples(self):
        accepted = {}
        for mask in range(64):
            targets = protocol_targets(3, source_mask=mask)
            self.assertEqual(independent_path_profile([target["path"] for target in targets]),
                             V3_PATH_PROFILE, mask)
            if mask in (0, 63):
                binding = portable._protocol_binding(portable._select_protocol(targets))
                accepted[mask] = binding["sourceTuple"]["variant"]
            else:
                with self.subTest(mask=f"{mask:06b}"):
                    self.assert_private_rejection("mixed-source-tuple", portable._select_protocol,
                                                  targets)
        self.assertEqual(accepted, {0: "LF", 63: "CRLF"})

    def test_issue107_v3_exact_hierarchy_footer_and_duration_only_normalization(self):
        stdout = npm_stdout_v3(initial=True)
        lines = stdout.splitlines(keepends=True)
        self.assertEqual(len(lines), 167)
        layout = v3_layout()
        self.assertEqual(lines[layout.heading].rstrip(b"\r\n").decode(),
                         "▶ " + V3_TOP_LEVEL_NAMES[V3_PARENT_ORDINAL])
        self.assertEqual([line.rstrip(b"\r\n").decode() for line in
                          lines[layout.child_start:layout.child_start + 6]],
                         [f"  ✔ {name} (1.25ms)" for name in V3_NESTED_NAMES])
        self.assertEqual([line.rstrip(b"\r\n").decode() for line in lines[-8:]], [
            "ℹ tests 154", "ℹ suites 0", "ℹ pass 154", "ℹ fail 0",
            "ℹ cancelled 0", "ℹ skipped 0", "ℹ todo 0", "ℹ duration_ms 99.5",
        ])

        package = json.loads(V3_PACKAGE_LF)
        members, gaps = portable._parse_stdout_v3(stdout, package)
        expected = [{"name": name, "status": "pass"} for name in V3_TOP_LEVEL_NAMES]
        expected[V3_PARENT_ORDINAL]["children"] = [
            {"name": name, "status": "pass"} for name in V3_NESTED_NAMES]
        self.assertEqual(members, expected)
        spans = v3_duration_spans(stdout)
        self.assertEqual((len(spans), len(gaps)), (155, 156))
        self.assertEqual(gaps, retained_segments(stdout, spans))
        self.assertEqual(b"".join(bytes.fromhex(gap) for gap in gaps),
                         b"".join(stdout[offset:begin] for offset, (begin, _end) in
                                  zip([0, *[end for _begin, end in spans]],
                                      [*spans, (len(stdout), len(stdout))])))

        decimals = (b"0", b"1.0", b"1234567890123456", b"0." + b"9" * 16)
        normalized = replace_spans(stdout, spans,
            [decimals[index % len(decimals)] for index in range(len(spans))])
        self.assertEqual(portable._parse_stdout_v3(normalized, package), (members, gaps))

        crlf_members, crlf_gaps = portable._parse_stdout_v3(
            npm_stdout_v3(newline="\r\n"), package)
        no_initial_members, no_initial_gaps = portable._parse_stdout_v3(
            npm_stdout_v3(initial=False), package)
        self.assertEqual(crlf_members, members)
        self.assertEqual(no_initial_members, members)
        self.assertNotEqual(crlf_gaps, gaps)
        self.assertNotEqual(no_initial_gaps, gaps)
        baseline_value = {"orderedTests": members, "stdoutNonDurationSegmentsHex": gaps}
        self.assertNotEqual(portable._identity_v3(ci, baseline_value), portable._identity_v3(ci, {
            "orderedTests": crlf_members, "stdoutNonDurationSegmentsHex": crlf_gaps,
        }))
        self.assertNotEqual(portable._identity_v3(ci, baseline_value), portable._identity_v3(ci, {
            "orderedTests": no_initial_members, "stdoutNonDurationSegmentsHex": no_initial_gaps,
        }))

    def test_issue107_v3_hierarchy_member_and_parent_negative_matrix(self):
        baseline = v3_reporter_lines()
        layout = v3_layout()
        variants = []

        def changed(label, reason, mutate):
            lines = baseline.copy()
            mutate(lines)
            variants.append((label, reason, lines))

        changed("missing top-level", "hierarchy-member-mismatch",
                lambda lines: lines.pop(layout.member_start))
        changed("duplicated top-level", "hierarchy-member-mismatch",
                lambda lines: lines.__setitem__(layout.member_start + 1,
                                                lines[layout.member_start]))
        changed("renamed top-level", "hierarchy-member-mismatch",
                lambda lines: lines.__setitem__(layout.member_start,
                    lines[layout.member_start].replace(V3_TOP_LEVEL_NAMES[0], "renamed member")))
        def reorder_top(lines):
            lines[layout.member_start], lines[layout.member_start + 1] = (
                lines[layout.member_start + 1], lines[layout.member_start])
        changed("reordered top-level", "hierarchy-member-mismatch", reorder_top)
        changed("additional top-level", "hierarchy-member-mismatch",
                lambda lines: lines.insert(layout.footer_start, "✔ additional member (1.25ms)"))
        changed("missing nested", "hierarchy-member-mismatch",
                lambda lines: lines.pop(layout.child_start))
        changed("duplicated nested", "hierarchy-member-mismatch",
                lambda lines: lines.__setitem__(layout.child_start + 1,
                                                lines[layout.child_start]))
        changed("renamed nested", "hierarchy-member-mismatch",
                lambda lines: lines.__setitem__(layout.child_start,
                    lines[layout.child_start].replace(V3_NESTED_NAMES[0], "renamed child")))
        def reorder_nested(lines):
            lines[layout.child_start], lines[layout.child_start + 1] = (
                lines[layout.child_start + 1], lines[layout.child_start])
        changed("reordered nested", "hierarchy-member-mismatch", reorder_nested)
        changed("additional nested", "parent-completion-placement",
                lambda lines: lines.insert(layout.parent_completion,
                                           "  ✔ additional child (1.25ms)"))
        changed("wrong suite heading", "hierarchy-heading-mismatch",
                lambda lines: lines.__setitem__(layout.heading, "▶ wrong suite"))
        changed("indented suite heading", "hierarchy-heading-mismatch",
                lambda lines: lines.__setitem__(layout.heading, "  " + lines[layout.heading]))
        changed("reparented child", "hierarchy-indentation-mismatch",
                lambda lines: lines.__setitem__(layout.child_start,
                                                lines[layout.child_start][2:]))
        changed("wrong child indentation", "hierarchy-indentation-mismatch",
                lambda lines: lines.__setitem__(layout.child_start,
                                                " " + lines[layout.child_start]))
        changed("indented parent completion", "parent-completion-placement",
                lambda lines: lines.__setitem__(layout.parent_completion,
                                                "  " + lines[layout.parent_completion]))
        def early_parent(lines):
            parent = lines.pop(layout.parent_completion)
            lines.insert(layout.child_start + 5, parent)
        changed("parent completion before children", "parent-completion-placement", early_parent)
        def late_parent(lines):
            parent = lines.pop(layout.parent_completion)
            lines.insert(layout.parent_completion + 1, parent)
        changed("parent completion after next top-level", "parent-completion-placement", late_parent)

        footer = baseline[-8:]
        for label, reason, lines in variants:
            with self.subTest(case=label):
                self.assertNotEqual(lines, baseline)
                self.assertEqual(lines[-8:], footer)
                self.assert_private_rejection(reason, portable._parse_stdout_v3,
                    encode_reporter_lines(lines), json.loads(V3_PACKAGE_LF))

    def test_issue107_v3_footer_stream_and_decimal_negative_matrix(self):
        baseline = v3_reporter_lines()
        layout = v3_layout()
        variants = []

        def changed(label, reason, mutate):
            lines = baseline.copy()
            mutate(lines)
            variants.append((label, reason, encode_reporter_lines(lines)))

        changed("footer count", "footer-mismatch",
                lambda lines: lines.__setitem__(layout.footer_start, "ℹ tests 153"))
        changed("footer field", "footer-mismatch",
                lambda lines: lines.__setitem__(layout.footer_start + 1, "ℹ suite 0"))
        def reorder_footer(lines):
            lines[layout.footer_start], lines[layout.footer_start + 1] = (
                lines[layout.footer_start + 1], lines[layout.footer_start])
        changed("footer order", "footer-mismatch", reorder_footer)
        changed("footer punctuation", "footer-mismatch",
                lambda lines: lines.__setitem__(layout.footer_start, "ℹ tests: 154"))
        changed("missing footer", "footer-mismatch",
                lambda lines: lines.pop(layout.footer_start))
        changed("additional footer", "footer-mismatch",
                lambda lines: lines.append("ℹ memory_bytes 1"))
        changed("wrong banner", "banner-mismatch",
                lambda lines: lines.__setitem__(1, "> ielts-practice-backend@0.2.0 test"))

        stdout = npm_stdout_v3()
        variants.extend((
            ("integral width", "duration-grammar",
             stdout.replace(b"(1.25ms)", b"(12345678901234567ms)", 1)),
            ("fractional width", "duration-grammar",
             stdout.replace(b"(1.25ms)", b"(1.12345678901234567ms)", 1)),
            ("exponent", "duration-grammar",
             stdout.replace(b"(1.25ms)", b"(1e3ms)", 1)),
            ("NaN", "duration-grammar", stdout.replace(b"(1.25ms)", b"(NaNms)", 1)),
            ("empty decimal", "duration-grammar",
             stdout.replace(b"(1.25ms)", b"(ms)", 1)),
            ("footer decimal width", "duration-grammar",
             stdout.replace(b"duration_ms 99.5", b"duration_ms " + b"9" * 17, 1)),
            ("invalid UTF-8", "stream-encoding", stdout.replace(b"Docker", b"Dock\xffr", 1)),
            ("control byte", "stream-encoding", stdout.replace(b"Docker", b"Dock\x00r", 1)),
            ("missing terminal newline", "line-boundary", stdout[:-1]),
            ("overlong line", "line-boundary", b"x" * 2048 + b"\n"),
            ("excessive lines", "line-boundary", b"\n" * (portable.MAX_STREAM_LINES + 1)),
            ("oversized stream", "stream-boundary", b"x" * (portable.MAX_STREAM_BYTES + 1)),
        ))
        for label, reason, data in variants:
            with self.subTest(case=label):
                self.assert_private_rejection(reason, portable._parse_stdout_v3,
                                              data, json.loads(V3_PACKAGE_LF))

    def test_issue107_protocol_binding_domains_disagreement_and_no_fallback(self):
        v2_binding = portable._protocol_binding(portable._select_protocol(protocol_targets(2)))
        v3_bindings = {variant: portable._protocol_binding(portable._select_protocol(
            protocol_targets(3, source_variant=variant))) for variant in ("LF", "CRLF")}

        probe = {"version": "domain-probe"}
        self.assertEqual(portable._identity_for_protocol(ci, probe, v2_binding),
                         portable._identity(ci, probe))
        self.assertEqual(portable._identity_for_protocol(ci, probe, v3_bindings["LF"]),
                         portable._identity_v3(ci, probe))
        self.assertNotEqual(portable._identity(ci, probe), portable._identity_v3(ci, probe))
        self.assertEqual(portable._identity_v3(ci, probe), ci.canonical_failure_digest({
            "digestDomain": "ieltmps-backend-canonical-portable-result-v3",
            "resultUtf8": json_bytes(probe),
        }))

        for variant, binding in v3_bindings.items():
            result = portable._derive_equal_result(ci, selected_bound_pair(
                npm_stdout_v3(), npm_stdout_v3("90", "912"), binding))
            self.assertIsNotNone(result, variant)
            self.assertEqual(result["result"]["version"], 3)
            self.assertEqual(result["result"]["protocol"], binding)
            self.assertEqual(len(result["result"]["orderedTests"]), 148)
            self.assertEqual(len(result["result"]["stdoutNonDurationSegmentsHex"]), 156)

        tamper_cases = {
            "version": lambda value: value.update(version=2),
            "digest domain": lambda value: value.update(
                digestDomain="ieltmps-backend-canonical-portable-result-v2"),
            "hierarchy": lambda value: value.update(hierarchyInventoryDigest="0" * 64),
            "path profile": lambda value: value["pathProfile"].update(sortedPathSha256="0" * 64),
            "source tuple": lambda value: value["sourceTuple"]["sources"][0].update(sha256="0" * 64),
        }
        for label, tamper in tamper_cases.items():
            binding = copy.deepcopy(v3_bindings["LF"])
            tamper(binding)
            with self.subTest(binding=label), mock.patch.object(
                    portable, "_parse_stdout_v3", wraps=portable._parse_stdout_v3) as parser:
                self.assert_private_rejection("protocol-binding", portable._parse_selected_stdout,
                    npm_stdout_v3(), json.loads(V3_PACKAGE_LF), binding)
                parser.assert_not_called()
                self.assert_private_rejection("protocol-binding", portable._identity_for_protocol,
                                              ci, probe, binding)

        with mock.patch.object(portable, "_parse_stdout",
                               side_effect=AssertionError("v2 fallback")) as v2_parser:
            self.assertIsNone(portable._derive_equal_result(ci, selected_bound_pair(
                npm_stdout(), npm_stdout(), v3_bindings["LF"])))
            v2_parser.assert_not_called()
        with mock.patch.object(portable, "_parse_stdout_v3",
                               side_effect=AssertionError("v3 probe")) as v3_parser:
            self.assertIsNone(portable._derive_equal_result(ci, selected_bound_pair(
                npm_stdout_v3(), npm_stdout_v3(), v2_binding)))
            v3_parser.assert_not_called()

        for label, producer_binding, replay_binding, producer_stdout, replay_stdout in (
            ("version", v2_binding, v3_bindings["LF"], npm_stdout(), npm_stdout_v3()),
            ("source profile", v3_bindings["LF"], v3_bindings["CRLF"],
             npm_stdout_v3(), npm_stdout_v3()),
        ):
            with self.subTest(disagreement=label), \
                 mock.patch.object(portable, "_parse_stdout", wraps=portable._parse_stdout) as v2_parser, \
                 mock.patch.object(portable, "_parse_stdout_v3", wraps=portable._parse_stdout_v3) as v3_parser:
                self.assertIsNone(portable._derive_equal_result(ci, selected_bound_pair(
                    producer_stdout, replay_stdout, producer_binding, replay_binding)))
                v2_parser.assert_not_called()
                v3_parser.assert_not_called()

    def test_issue107_v3_real_selector_outer_binding_and_candidate_selector_rejection(self):
        producer = v3_fixture(duration="1.25", total="99.5", physical="1")
        replay = v3_fixture(duration="90", total="912", physical="9")
        with outer_fixture(producer, replay, forced_protocol=None) as case:
            with portable_spy("_select_protocol") as selector, \
                 portable_spy("_parse_stdout_v3") as parser, \
                 portable_spy("_identity_v3") as identity:
                errors, transcript = verify(case)
            self.assertEqual(errors, [])
            self.assertEqual(transcript["finalAcceptance"], "PASS")
            result = transcript["backendCanonicalPortableResult"]["result"]
            self.assertEqual(result["version"], 3)
            self.assertEqual(result["reporterCounts"], {
                "tests": 154, "suites": 0, "pass": 154, "fail": 0,
                "cancelled": 0, "skipped": 0, "todo": 0,
            })
            self.assertEqual(result["protocol"]["sourceTuple"]["variant"], "LF")
            self.assertGreaterEqual(selector.call_count, 6)
            self.assertEqual((parser.call_count, identity.call_count), (2, 2))
            for call in selector.call_args_list:
                binding = portable._protocol_binding(portable._select_protocol(call.args[0]))
                self.assertEqual((binding["version"], binding["sourceTuple"]["variant"]),
                                 (3, "LF"))

            record = case.documents["command-results.json"]["records"][0]
            record["protocolVersion"] = 3
            reseal_producer(case)
            with portable_spy("_parse_stdout_v3") as rejected_parser, \
                 portable_spy("_identity_v3") as rejected_identity:
                self.assert_rejected(case, "candidate-supplied protocol selector")
            rejected_parser.assert_not_called()
            rejected_identity.assert_not_called()

    def test_v2_retained_bytes_and_142_duration_span_controls(self):
        stdout = npm_stdout(initial=False)
        package = json.loads(PACKAGE)
        members, gaps = portable._parse_stdout(stdout, package)
        baseline = {"orderedTests": members, "stdoutNonDurationSegmentsHex": gaps}
        baseline_digest = portable._identity(ci, baseline)
        spans, offset = [], 0
        # Locate the known fixture's numeric intervals independently of the parser.
        for line in stdout.splitlines(keepends=True):
            if line.endswith(b" (1.25ms)\n"):
                begin = offset + len(line) - len(b"1.25ms)\n")
                spans.append((begin, begin + 4))
            elif line.startswith("ℹ duration_ms ".encode()):
                spans.append((offset + len(line) - 5, offset + len(line) - 1))
            offset += len(line)
        excluded = {i for begin, end in spans for i in range(begin, end)}
        retained = [i for i in range(len(stdout)) if i not in excluded]
        self.assertEqual((len(spans), len(gaps), len(excluded), len(retained)), (142, 143, 568, 6780))
        self.assertEqual(b"".join(bytes.fromhex(gap) for gap in gaps), bytes(stdout[i] for i in retained))
        for position in retained:
            changed = stdout[:position] + bytes([stdout[position] ^ 1]) + stdout[position + 1:]
            try:
                changed_members, changed_gaps = portable._parse_stdout(changed, package)
            except (ValueError, UnicodeError):
                continue
            self.assertNotEqual(portable._identity(ci, {"orderedTests": changed_members,
                "stdoutNonDurationSegmentsHex": changed_gaps}), baseline_digest, position)
        for index, (begin, end) in enumerate(spans):
            changed = stdout[:begin] + b"98765.4321" + stdout[end:]
            self.assertEqual(portable._parse_stdout(changed, package), (members, gaps), index)
        print("BACKEND_BYTES retained=6780 excluded_spans=142 excluded_bytes=568 segments=143 duration_controls=142")

    def test_v2_exact_count_order_and_domain_are_bound(self):
        self.assertEqual((portable.VERSION, portable.TEST_COUNT), (2, 141))
        members, gaps = portable._parse_stdout(npm_stdout(), json.loads(PACKAGE))
        self.assertEqual(members, [{"name": name, "status": "pass"} for name in NAMES])
        self.assertEqual(len(gaps), 143)
        value = {"version": 2, "orderedTests": members, "stdoutNonDurationSegmentsHex": gaps}
        expected = ci.canonical_failure_digest({
            "digestDomain": "ieltmps-backend-canonical-portable-result-v2",
            "resultUtf8": json_bytes(value),
        })
        self.assertEqual(portable._identity(ci, value), expected)
        self.assertNotEqual(expected, ci.canonical_failure_digest({
            "digestDomain": "ieltmps-backend-canonical-portable-result-v1",
            "resultUtf8": json_bytes(value),
        }))
        # Order remains a retained semantic input, not a permitted normalization.
        reordered = npm_stdout(names=[NAMES[1], NAMES[0], *NAMES[2:]])
        reordered_members, reordered_gaps = portable._parse_stdout(reordered, json.loads(PACKAGE))
        self.assertEqual([member["name"] for member in reordered_members],
                         [NAMES[1], NAMES[0], *NAMES[2:]])
        self.assertNotEqual(portable._identity(ci, {
            "version": 2, "orderedTests": reordered_members,
            "stdoutNonDurationSegmentsHex": reordered_gaps}), expected)
        with outer_fixture(replay=fixture(stdout=reordered)) as case:
            self.assert_rejected(case, "reordered v2 inventory", parser_calls=2, identity_calls=2)

    def test_strict_reporter_grammar_matrix(self):
        source = npm_stdout()
        variants = {
            "old 128 tests": npm_stdout(names=NAMES[:128]),
            "140 tests": npm_stdout(names=NAMES[:-1]),
            "142 tests": npm_stdout(names=[*NAMES, "extra case"]),
            "missing member with 141 footer": source.replace(
                f"\u2714 {NAMES[70]} (1.25ms)\n".encode(), b"", 1),
            "duplicate member": npm_stdout(names=[NAMES[0], *NAMES[:-1]]),
            "missing footer": source.rsplit("ℹ duration_ms".encode(), 1)[0],
            "missing final newline": source[:-1],
            "added line": source + b"unexpected output\n",
            "added blank": source + b"\n",
            "removed blank": source.replace(b"node --test\n\n", b"node --test\n", 1),
            "unknown numeric": source.replace("ℹ duration_ms".encode(), "ℹ memory_bytes 123\nℹ duration_ms".encode()),
            "extra duration": source + "ℹ duration_ms 42\n".encode(),
            "misplaced duration": "ℹ duration_ms 42\n".encode() + source,
            "wrong banner": source.replace(b"fixture-backend@1.0.0", b"fixture-backend@1.0.1"),
            "invalid utf8": source.replace(b"backend case", b"backend\xffcase", 1),
            "ANSI": b"\x1b[32m" + source,
            "NUL": source.replace(b"case 000", b"case\x00000", 1),
            "exponent": source.replace(b"1.25ms", b"1e3ms", 1),
            "NaN": source.replace(b"1.25ms", b"NaNms", 1),
            "long decimal": source.replace(b"1.25ms", b"1" * 17 + b"ms", 1),
            "long fraction": source.replace(b"1.25ms", b"1." + b"1" * 17 + b"ms", 1),
            "missing units": source.replace(b"1.25ms", b"1.25", 1),
            "wrong units": source.replace(b"1.25ms", b"1.25us", 1),
            "punctuation": source.replace(b"(1.25ms)", b"[1.25ms]", 1),
            "status": source.replace("✔".encode(), "✖".encode(), 1),
            "TAP": b"TAP version 13\n1..128\n",
        }
        for key, expected in portable.EXPECTED_COUNTS.items():
            variants["count " + key] = source.replace(f"ℹ {key} {expected}".encode(),
                                                     f"ℹ {key} {expected + 1}".encode())
        for label, data in variants.items():
            with self.subTest(case=label), self.assertRaises((ValueError, UnicodeError)):
                portable._parse_stdout(data, json.loads(PACKAGE))
        tree = ast.parse(Path(portable.__file__).read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("sub", "subn") for n in ast.walk(tree)))

    def test_unicode_stderr_lifecycle_and_tool_authority_sensitivity(self):
        composed = fixture(stdout=npm_stdout(names=["caf\u00e9 test", *NAMES[1:]]))
        decomposed = fixture(stdout=npm_stdout(names=["cafe\u0301 test", *NAMES[1:]]))
        with outer_fixture(composed, decomposed) as case:
            self.assert_rejected(case, "Unicode spelling", parser_calls=2, identity_calls=2)
        with outer_fixture(replay=fixture(stderr=b"warning 123\n")) as case:
            self.assert_rejected(case, "nonempty stderr")
        for extra in ({"pretest": "echo extra"}, {"posttest": "echo extra"}, {"test": "node --test --test-reporter=tap"}):
            source = fixture()
            package = json.loads(PACKAGE)
            package["scripts"].update(extra)
            data = json_bytes(package)
            spec = copy.deepcopy(source.expected_authority)
            spec["targets"][0].update(size=len(data), sha256=digest(data))
            record = copy.deepcopy(source.command_record)
            rebuilt = fixtures.synthetic_record_from_spec(spec)
            for key in (*portable.AUTHORITY_KEYS, "executionInputs", "executionInputBundleDigest", "protectedTargetBundle"):
                record[key] = copy.deepcopy(rebuilt[key])
            modified = replace(source, command_record=record, expected_authority=spec, package_json=data)
            with outer_fixture(modified, modified) as case:
                self.assert_rejected(case, "package lifecycle " + next(iter(extra)))
        for kind in ("npm hash", "npm size", "npm version", "dependency membership"):
            replay = fixture(stdout=npm_stdout("90", "912"))
            closure = replay.runtime_closure
            if kind == "npm hash":
                closure["npmEntrypoint"]["sha256"] = digest(b"changed npm")
            elif kind == "npm size":
                closure["npmEntrypoint"]["size"] += 1
            elif kind == "npm version":
                closure["npmEntrypoint"]["version"] = replay.runtime["npm"] = "11.0.1"
            else:
                root = closure["dependencyRoots"][0]
                root["members"][0]["sha256"] = digest(b"changed dependency")
                root["memberManifestDigest"] = digest(ci._canonical_frame(root["members"]))
                semantic = {key: closure[key] for key in ("lockfiles", "dependencyRoots", "vitest", "nodePath")}
                closure["dependencyClosureDigest"] = digest(ci._canonical_frame(semantic))
                replay.runtime["dependencyClosureDigest"] = closure["dependencyClosureDigest"]
                replay.command_record["dependencyClosureDigest"] = closure["dependencyClosureDigest"]
            closure["closureDigest"] = digest(ci._canonical_frame({
                key: value for key, value in closure.items() if key != "closureDigest"}))
            replay.runtime["runtimeClosureDigest"] = closure["closureDigest"]
            replay.command_record["runtimeClosureDigest"] = closure["closureDigest"]
            for side in ("producer", "replay"):
                arguments = {"producer": replay, "replay": fixture()} if side == "producer" else {"replay": replay}
                with self.subTest(kind=kind, side=side), outer_fixture(**arguments) as case:
                    self.assertEqual(ci.verify_evidence_file_set(case.output, repo_root=case.root,
                        expected_command_plan=case.runner.command_plan, expected_context=case.context), [])
                    # Self-consistency cannot substitute for independent fresh authority.
                    self.assert_rejected(case, "coherent " + side + " " + kind)


if __name__ == "__main__":
    unittest.main(verbosity=2, testRunner=fixtures.InventoryTextTestRunner)
