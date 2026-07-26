#!/usr/bin/env python3
"""Independent authority tests for the canonical public-source ZIP profile."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Callable


sys.dont_write_bytecode = True

SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
CORE = REPO_ROOT / "developer/public-source-zip-core.mjs"
WRITER = REPO_ROOT / "developer/prepare-public-source-zip.mjs"
VERIFIER = REPO_ROOT / "developer/verify-public-source-zip.mjs"
ARCHIVE_ROOT = "ieltmps-source/"
APPROVED_NODE = Path(
    r"C:\Users\llzz\.cache\codex-runtimes\codex-primary-runtime"
    r"\dependencies\node\bin\node.exe"
)

LOCAL_SIGNATURE = 0x04034B50
CENTRAL_SIGNATURE = 0x02014B50
EOCD_SIGNATURE = 0x06054B50
VERSION_NEEDED = 0x0014
VERSION_MADE = 0x0314
UTF8_FLAG = 0x0800
DOS_DATE = 0x0021
MAX_ZIP32 = 0xFFFFFFFE

EXPECTED_COUNTS = {
    "W": 10,
    "L": 12,
    "C": 16,
    "E": 13,
    "P": 20,
    "F": 12,
    "M": 18,
}
EXPECTED_ADS_CASES = 12
EXPECTED_SLASH_CASES = 12
EXPECTED_TWO_PHASE_CLEANUP_CASES = 15
EXPECTED_SUBSTITUTION_REPETITIONS = 30
TEMPORARY_ZIP_PATTERN = re.compile(r"\A\.__iz-[0-9a-f]{24}\.tmp\Z")

ERROR_PATTERN = re.compile(
    r"\AERROR (CLI|ENTRY_PLAN|PATH_AUTHORITY|SOURCE_FILE|ZIP_LAYOUT|ZIP_WRITE|"
    r"ZIP_PARSE|ZIP_PROFILE|ZIP_BINDING|OUTPUT_PUBLICATION|CLEANUP|PRIVACY): "
    r"([a-z0-9]+(?:-[a-z0-9]+)*)\n\Z"
)


def _find_node() -> Path:
    configured = os.environ.get("IELTMPS_NODE")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file():
            return candidate
        raise unittest.SkipTest("IELTMPS_NODE does not name a file")
    if APPROVED_NODE.is_file():
        return APPROVED_NODE.resolve()
    discovered = shutil.which("node")
    if discovered:
        return Path(discovered).resolve()
    raise unittest.SkipTest("node is unavailable")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _crc32_hex(value: bytes) -> str:
    return f"{binascii.crc32(value) & 0xFFFFFFFF:08x}"


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _external_attributes(git_mode: str) -> int:
    if git_mode == "100644":
        return 0x81A40000
    if git_mode == "100755":
        return 0x81ED0000
    raise ValueError("unsupported Git mode")


def _make_plan(
    files: list[tuple[str, str, bytes]],
    *,
    source_commit: str = "a" * 40,
    manifest_sha256: str = "b" * 64,
    membership_report_sha256: str = "c" * 64,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    ordered = sorted(files, key=lambda item: (ARCHIVE_ROOT + item[0]).encode("utf-8"))
    entries: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    local_offset = 0
    for source_path, git_mode, payload in ordered:
        archive_path = ARCHIVE_ROOT + source_path
        name = archive_path.encode("utf-8")
        data_offset = local_offset + 30 + len(name)
        entries.append(
            {
                "sourcePath": source_path,
                "archivePath": archive_path,
                "gitMode": git_mode,
                "sha256": _sha256(payload),
                "crc32": _crc32_hex(payload),
                "byteLength": len(payload),
                "localHeaderOffset": local_offset,
                "dataOffset": data_offset,
                "centralDirectoryRecordOffset": 0,
            }
        )
        payloads[source_path] = payload
        local_offset = data_offset + len(payload)

    central_offset = local_offset
    central_cursor = central_offset
    for entry in entries:
        entry["centralDirectoryRecordOffset"] = central_cursor
        central_cursor += 46 + len(entry["archivePath"].encode("utf-8"))
    central_length = central_cursor - central_offset
    archive_length = central_cursor + 22
    plan = {
        "documentKind": "ieltmps-public-source-zip-entry-plan",
        "schemaVersion": 1,
        "artifactRole": "public-source-convenience-download",
        "formatProfile": "zip-canonical-v1",
        "sourceCommit": source_commit,
        "manifestSha256": manifest_sha256,
        "membershipReportSha256": membership_report_sha256,
        "membershipCount": len(entries),
        "archiveRoot": ARCHIVE_ROOT,
        "entryCount": len(entries),
        "entries": entries,
        "centralDirectoryOffset": central_offset,
        "centralDirectoryByteLength": central_length,
        "archiveByteLength": archive_length,
    }
    return plan, payloads


def _assemble_zip(plan: dict[str, Any], payloads: dict[str, bytes]) -> bytes:
    records: list[bytes] = []
    for entry in plan["entries"]:
        name = entry["archivePath"].encode("utf-8")
        payload = payloads[entry["sourcePath"]]
        crc = binascii.crc32(payload) & 0xFFFFFFFF
        records.append(
            struct.pack(
                "<IHHHHHIIIHH",
                LOCAL_SIGNATURE,
                VERSION_NEEDED,
                UTF8_FLAG,
                0,
                0,
                DOS_DATE,
                crc,
                len(payload),
                len(payload),
                len(name),
                0,
            )
            + name
            + payload
        )
    for entry in plan["entries"]:
        name = entry["archivePath"].encode("utf-8")
        payload = payloads[entry["sourcePath"]]
        crc = binascii.crc32(payload) & 0xFFFFFFFF
        records.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                CENTRAL_SIGNATURE,
                VERSION_MADE,
                VERSION_NEEDED,
                UTF8_FLAG,
                0,
                0,
                DOS_DATE,
                crc,
                len(payload),
                len(payload),
                len(name),
                0,
                0,
                0,
                0,
                _external_attributes(entry["gitMode"]),
                entry["localHeaderOffset"],
            )
            + name
        )
    records.append(
        struct.pack(
            "<IHHHHIIH",
            EOCD_SIGNATURE,
            0,
            0,
            plan["entryCount"],
            plan["entryCount"],
            plan["centralDirectoryByteLength"],
            plan["centralDirectoryOffset"],
            0,
        )
    )
    result = b"".join(records)
    if len(result) != plan["archiveByteLength"]:
        raise AssertionError("independent ZIP layout mismatch")
    return result


def _independent_parse_zip(value: bytes) -> list[dict[str, Any]]:
    if len(value) < 22:
        raise AssertionError("ZIP is shorter than EOCD")
    eocd_offset = len(value) - 22
    (
        signature,
        disk,
        central_disk,
        disk_count,
        entry_count,
        central_length,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<IHHHHIIH", value, eocd_offset)
    if (
        signature != EOCD_SIGNATURE
        or disk != 0
        or central_disk != 0
        or disk_count != entry_count
        or not 1 <= entry_count <= 65534
        or comment_length != 0
        or central_offset + central_length != eocd_offset
    ):
        raise AssertionError("noncanonical EOCD")

    central: list[dict[str, Any]] = []
    cursor = central_offset
    for _ in range(entry_count):
        fixed = struct.unpack_from("<IHHHHHHIIIHHHHHII", value, cursor)
        (
            signature,
            made,
            needed,
            flag,
            method,
            dos_time,
            dos_date,
            crc,
            stored,
            uncompressed,
            name_length,
            extra_length,
            comment_length,
            disk_start,
            internal,
            external,
            local_offset,
        ) = fixed
        if (
            signature != CENTRAL_SIGNATURE
            or made != VERSION_MADE
            or needed != VERSION_NEEDED
            or flag != UTF8_FLAG
            or method != 0
            or dos_time != 0
            or dos_date != DOS_DATE
            or stored != uncompressed
            or extra_length != 0
            or comment_length != 0
            or disk_start != 0
            or internal != 0
        ):
            raise AssertionError("noncanonical central record")
        name_start = cursor + 46
        name = value[name_start : name_start + name_length]
        central.append(
            {
                "name": name,
                "crc": crc,
                "size": stored,
                "external": external,
                "local_offset": local_offset,
                "central_offset": cursor,
            }
        )
        cursor = name_start + name_length
    if cursor != eocd_offset:
        raise AssertionError("central directory does not end at EOCD")

    local_cursor = 0
    parsed: list[dict[str, Any]] = []
    for central_entry in central:
        fixed = struct.unpack_from("<IHHHHHIIIHH", value, local_cursor)
        (
            signature,
            needed,
            flag,
            method,
            dos_time,
            dos_date,
            crc,
            stored,
            uncompressed,
            name_length,
            extra_length,
        ) = fixed
        if (
            signature != LOCAL_SIGNATURE
            or needed != VERSION_NEEDED
            or flag != UTF8_FLAG
            or method != 0
            or dos_time != 0
            or dos_date != DOS_DATE
            or stored != uncompressed
            or extra_length != 0
            or local_cursor != central_entry["local_offset"]
        ):
            raise AssertionError("noncanonical local record")
        name_start = local_cursor + 30
        name = value[name_start : name_start + name_length]
        data_start = name_start + name_length
        data_end = data_start + stored
        payload = value[data_start:data_end]
        if (
            name != central_entry["name"]
            or crc != central_entry["crc"]
            or crc != (binascii.crc32(payload) & 0xFFFFFFFF)
        ):
            raise AssertionError("local/central/payload mismatch")
        parsed.append(
            {
                "name": name.decode("utf-8"),
                "payload": payload,
                "external": central_entry["external"],
                "local_offset": local_cursor,
                "data_offset": data_start,
            }
        )
        local_cursor = data_end
    if local_cursor != central_offset:
        raise AssertionError("local records do not meet central directory")
    return parsed


class PublicSourceZipTest(unittest.TestCase):
    """All source trees, plans, ZIPs, aliases, and races are synthetic."""

    maxDiff = None
    authority_counts = {key: 0 for key in EXPECTED_COUNTS}
    ads_cases = 0
    ads_fixture_mode = "not-run"
    slash_cases = 0
    two_phase_cleanup_cases = 0
    substitution_repetitions = 0
    cleanup_assertions = 0
    started = 0.0
    method_count = 0

    privacy_canaries = [
        f"zip-privacy-canary-{index:02d}-q7v9"
        for index in range(1, 30)
    ]

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        if not all(item.is_file() for item in (CORE, WRITER, VERIFIER)):
            raise unittest.SkipTest("ZIP implementation files are unavailable")
        cls.method_count = len(
            [name for name in dir(cls) if name.startswith("test_")]
        )
        if cls.method_count < 25:
            raise AssertionError("focused suite has fewer than 25 methods")

    @classmethod
    def tearDownClass(cls) -> None:
        duration = time.monotonic() - cls.started
        isolated = os.environ.get("IELTMPS_ZIP_ISOLATED") == "1"
        require_ads = (
            not isolated
            or os.environ.get("IELTMPS_ZIP_EXPECT_ADS") == "1"
        )
        require_slash = (
            not isolated
            or os.environ.get("IELTMPS_ZIP_EXPECT_SLASH") == "1"
        )
        require_cleanup = (
            not isolated
            or os.environ.get("IELTMPS_ZIP_EXPECT_CLEANUP") == "1"
        )
        require_substitution = (
            not isolated
            or os.environ.get("IELTMPS_ZIP_EXPECT_SUBSTITUTION") == "1"
        )
        if require_ads and cls.ads_cases != EXPECTED_ADS_CASES:
            raise AssertionError(
                f"ADS path counters {cls.ads_cases} != {EXPECTED_ADS_CASES}"
            )
        if require_slash and cls.slash_cases != EXPECTED_SLASH_CASES:
            raise AssertionError(
                f"slash counters {cls.slash_cases} != {EXPECTED_SLASH_CASES}"
            )
        if (
            require_cleanup
            and cls.two_phase_cleanup_cases != EXPECTED_TWO_PHASE_CLEANUP_CASES
        ):
            raise AssertionError(
                "two-phase cleanup counters "
                f"{cls.two_phase_cleanup_cases} "
                f"!= {EXPECTED_TWO_PHASE_CLEANUP_CASES}"
            )
        if (
            require_substitution
            and cls.substitution_repetitions != EXPECTED_SUBSTITUTION_REPETITIONS
        ):
            raise AssertionError(
                "substitution repetitions "
                f"{cls.substitution_repetitions} "
                f"!= {EXPECTED_SUBSTITUTION_REPETITIONS}"
            )
        if not isolated:
            if cls.authority_counts != EXPECTED_COUNTS:
                raise AssertionError(
                    f"authority counters {cls.authority_counts!r} != {EXPECTED_COUNTS!r}"
                )
            if cls.cleanup_assertions <= 97:
                raise AssertionError("not more than 97 cleanup/publication assertions")
        total = sum(cls.authority_counts.values())
        print(
            "ZIP_AUTHORITY_SUMMARY "
            + " ".join(
                f"{key}={cls.authority_counts[key]}/{EXPECTED_COUNTS[key]}"
                for key in EXPECTED_COUNTS
            )
            + f" total={total}/101"
            + f" ads={cls.ads_cases}/{EXPECTED_ADS_CASES}"
            + f" slash={cls.slash_cases}/{EXPECTED_SLASH_CASES}"
            + " twoPhaseCleanup="
            + f"{cls.two_phase_cleanup_cases}/{EXPECTED_TWO_PHASE_CLEANUP_CASES}"
            + " substitution="
            + f"{cls.substitution_repetitions}/{EXPECTED_SUBSTITUTION_REPETITIONS}"
            + f" adsFixtures={cls.ads_fixture_mode}"
            + f" privacy={len(cls.privacy_canaries)}"
            + f" cleanup={cls.cleanup_assertions}"
            + f" methods={cls.method_count}"
            + f" duration={duration:.6f}s",
            flush=True,
        )

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(prefix="izd1-case-")
        self.temp_root = Path(self.case_temp.name).resolve()
        configured_temp = Path(tempfile.gettempdir()).resolve()
        self.assertTrue(
            self.temp_root.is_relative_to(configured_temp),
            "fixture escaped the configured temporary root",
        )
        self.source_tree = self.temp_root / "source-tree"
        self.entry_plan = self.temp_root / "entry-plan.json"
        self.output = self.temp_root / "public-source.zip"
        self.archive = self.temp_root / "independent.zip"
        self.sentinel = self.temp_root / "unrelated-sentinel.bin"
        self.sentinel.write_bytes(b"unrelated-object\n")
        self.plan: dict[str, Any] = {}
        self.payloads: dict[str, bytes] = {}

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    @classmethod
    def _mark(cls, category: str, count: int = 1) -> None:
        cls.authority_counts[category] += count

    @classmethod
    def _mark_ads(cls) -> None:
        cls.ads_cases += 1

    @classmethod
    def _mark_slash(cls, count: int = 1) -> None:
        cls.slash_cases += count

    @classmethod
    def _mark_two_phase_cleanup(cls, count: int = 1) -> None:
        cls.two_phase_cleanup_cases += count

    @classmethod
    def _mark_substitution(cls, count: int = 1) -> None:
        cls.substitution_repetitions += count

    @classmethod
    def _cleanup_assert(cls, condition: bool, message: str = "") -> None:
        if not condition:
            raise AssertionError(message or "cleanup/publication assertion failed")
        cls.cleanup_assertions += 1

    @classmethod
    def _environment(cls) -> dict[str, str]:
        environment = os.environ.copy()
        environment["IELTMPS_NODE"] = str(cls.node)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return environment

    def _install_fixture(self, files: list[tuple[str, str, bytes]]) -> None:
        if self.source_tree.exists():
            shutil.rmtree(self.source_tree)
        self.source_tree.mkdir()
        self.plan, self.payloads = _make_plan(files)
        for source_path, git_mode, payload in files:
            target = self.source_tree / PurePosixPath(source_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            if os.name != "nt":
                target.chmod(0o755 if git_mode == "100755" else 0o644)
        self.entry_plan.write_bytes(_canonical_json(self.plan))

    def _run_writer(
        self,
        *,
        source_tree: Path | str | None = None,
        entry_plan: Path | str | None = None,
        output: Path | str | None = None,
        extra_args: list[str] | None = None,
        script: Path | str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(script or WRITER),
            "--source-tree",
            str(source_tree or self.source_tree),
            "--entry-plan",
            str(entry_plan or self.entry_plan),
            "--output",
            str(output or self.output),
        ]
        if extra_args:
            argv.extend(extra_args)
        return subprocess.run(
            argv,
            cwd=cwd or self.temp_root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )

    def _run_verifier(
        self,
        archive: Path | str | None = None,
        *,
        entry_plan: Path | str | None = None,
        extra_args: list[str] | None = None,
        script: Path | str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(script or VERIFIER),
            "--archive",
            str(archive or self.archive),
            "--entry-plan",
            str(entry_plan or self.entry_plan),
        ]
        if extra_args:
            argv.extend(extra_args)
        return subprocess.run(
            argv,
            cwd=cwd or self.temp_root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )

    def _assert_privacy(self, text: str) -> None:
        for canary in self.privacy_canaries:
            self.assertNotIn(canary, text)
        for absolute in (
            str(self.temp_root),
            str(self.source_tree),
            str(self.entry_plan),
            str(self.output),
        ):
            self.assertNotIn(absolute, text)

    def _assert_success(
        self, completed: subprocess.CompletedProcess[str]
    ) -> dict[str, Any]:
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertTrue(completed.stdout.endswith("\n"))
        self.assertEqual(completed.stdout.count("\n"), 1)
        self._assert_privacy(completed.stdout)
        return json.loads(completed.stdout)

    def _assert_failure(
        self,
        completed: subprocess.CompletedProcess[str],
        phase: str | None = None,
        reason: str | None = None,
    ) -> tuple[str, str]:
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        match = ERROR_PATTERN.fullmatch(completed.stderr)
        self.assertIsNotNone(match, completed.stderr)
        assert match is not None
        observed = (match.group(1), match.group(2))
        if phase is not None:
            self.assertEqual(observed[0], phase)
        if reason is not None:
            self.assertEqual(observed[1], reason)
        self._assert_privacy(completed.stderr)
        return observed

    def _assert_ads_failure(
        self,
        completed: subprocess.CompletedProcess[str],
        *stream_names: str,
    ) -> None:
        self._assert_failure(
            completed,
            "PATH_AUTHORITY",
            "windows-alternate-data-stream",
        )
        self.assertEqual(
            completed.stderr,
            "ERROR PATH_AUTHORITY: windows-alternate-data-stream\n",
        )
        for stream_name in stream_names:
            self.assertNotIn(stream_name, completed.stderr)
        for secret in (
            self.temp_root.drive,
            os.environ.get("USERNAME", ""),
            os.environ.get("COMPUTERNAME", ""),
        ):
            if secret:
                self.assertNotIn(secret, completed.stderr)

    def _assert_no_owned_temporary_zip(self) -> None:
        self._cleanup_assert(
            not any(
                TEMPORARY_ZIP_PATTERN.fullmatch(item.name)
                for item in self.temp_root.iterdir()
            ),
            "owned temporary ZIP survived ADS rejection",
        )

    def _assert_ads_objects_preserved(
        self,
        host: Path,
        host_bytes: bytes,
        streams: dict[str, bytes],
    ) -> None:
        self._cleanup_assert(host.is_file(), "ADS host file was removed")
        self._cleanup_assert(
            host.read_bytes() == host_bytes,
            "ADS host file was modified",
        )
        for stream_path, expected in streams.items():
            self._cleanup_assert(
                Path(stream_path).read_bytes() == expected,
                "ADS stream was removed or modified",
            )
        self._cleanup_assert(
            self.sentinel.read_bytes() == b"unrelated-object\n",
            "unrelated sibling was modified",
        )
        self._assert_no_owned_temporary_zip()

    def _write_independent_archive(self) -> None:
        self.archive.write_bytes(_assemble_zip(self.plan, self.payloads))

    def _mutated_archive(self, value: bytes, name: str) -> Path:
        target = self.temp_root / f"malformed-{name}.zip"
        target.write_bytes(value)
        return target

    def _run_core_cases(self, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
        environment = self._environment()
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        environment["IELTMPS_TEST_CASES"] = base64.b64encode(
            json.dumps(cases, ensure_ascii=True).encode("utf-8")
        ).decode("ascii")
        script = r"""
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const cases = JSON.parse(Buffer.from(process.env.IELTMPS_TEST_CASES, "base64").toString("utf8"));
const results = [];
for (const value of cases) {
  try {
    let returned;
    if (value.kind === "path") returned = core.validateZipSourcePath(value.value);
    else if (value.kind === "windows-host-path") returned = core.validateWindowsHostPathAuthority(value.value);
    else if (value.kind === "host-path") returned = core.validateHostFilesystemPath(value.value);
    else if (value.kind === "canonical-host-path") returned = core.canonicalizeHostFilesystemPath(value.value);
    else if (value.kind === "layout") returned = core.computeCanonicalZipLayout(value.entries);
    else if (value.kind === "parse-plan") returned = core.parseCanonicalZipEntryPlanBytes(Buffer.from(value.bytes, "base64"));
    else if (value.kind === "local-header") returned = core.encodeLocalFileHeader(value.entry);
    else throw new Error("unknown test operation");
    results.push(
      value.kind === "canonical-host-path"
        ? { ok: true, value: returned ?? null }
        : { ok: true },
    );
  } catch (error) {
    results.push({ ok: false, phase: error.phase ?? null, reason: error.reason ?? null });
  }
}
process.stdout.write(JSON.stringify(results));
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        return json.loads(completed.stdout)

    def _run_imported_writer(self, action: str) -> dict[str, Any]:
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_WRITER": str(WRITER),
                "IELTMPS_TEST_ACTION": action,
                "IELTMPS_TEST_SOURCE_TREE": str(self.source_tree),
                "IELTMPS_TEST_ENTRY_PLAN": str(self.entry_plan),
                "IELTMPS_TEST_OUTPUT": str(self.output),
            }
        )
        script = r"""
import { pathToFileURL } from "node:url";
import * as fs from "node:fs/promises";
import path from "node:path";
const { preparePublicSourceZip } = await import(pathToFileURL(process.env.IELTMPS_TEST_WRITER).href);
const action = process.env.IELTMPS_TEST_ACTION;
let fired = false;
let hookPath = null;
let temporaryPath = null;
let renamedTemporary = null;
let renamedFinal = null;
let extraLink = null;
let renamedParent = null;
let replacementBytes = null;
let stagedReplacement = null;
const sourceFile = path.join(process.env.IELTMPS_TEST_SOURCE_TREE, "dir", "file.txt");
if (action === "temporary-replace-early") {
  stagedReplacement = path.join(path.dirname(process.env.IELTMPS_TEST_OUTPUT), "staged-replacement.bin");
  replacementBytes = Buffer.from("replacement-temp-early\n", "utf8");
  await fs.writeFile(stagedReplacement, replacementBytes, { flag: "wx" });
}
const hooks = { checkpoint: async (context) => {
  if (context.temporaryArchive) temporaryPath = context.temporaryArchive;
  if (action === "pass-a-mutate" && context.checkpoint === "after-pass-a-source-open") {
    await fs.appendFile(context.sourcePath, "growth");
  } else if (action === "pass-a-replace" && context.checkpoint === "after-pass-a-source-open") {
    const bytes = await fs.readFile(context.sourcePath);
    await fs.rename(context.sourcePath, context.sourcePath + ".old");
    await fs.writeFile(context.sourcePath, bytes, { mode: 0o644 });
  } else if (action === "pass-a-truncate" && context.checkpoint === "after-pass-a-source-open") {
    await fs.truncate(context.sourcePath, 0);
  } else if (action === "pass-a-grow" && context.checkpoint === "after-pass-a-source-open") {
    await fs.appendFile(context.sourcePath, "x");
  } else if (action === "parent-between" && context.checkpoint === "before-pass-b") {
    const parent = path.dirname(sourceFile);
    await fs.rename(parent, parent + ".old");
    await fs.mkdir(parent);
    await fs.writeFile(sourceFile, "stable-source\n", { mode: 0o644 });
  } else if (action === "content-between" && context.checkpoint === "before-pass-b") {
    await fs.writeFile(sourceFile, "changed-source\n", { mode: 0o644 });
  } else if (action === "final-precreate" && context.checkpoint === "before-publication") {
    await fs.writeFile(context.finalOutput, "racing-final\n", { flag: "wx" });
  } else if (
    ["final-replace", "final-reparse"].includes(action)
    && context.checkpoint === "after-publication-link"
  ) {
    hookPath = context.finalOutput;
    renamedFinal = context.finalOutput + ".original";
    await fs.rename(context.finalOutput, renamedFinal);
    if (action === "final-reparse") {
      await fs.symlink(renamedFinal, context.finalOutput, "file");
    } else {
      replacementBytes = Buffer.from("replacement-final\n", "utf8");
      await fs.writeFile(context.finalOutput, replacementBytes, { flag: "wx" });
    }
  } else if (
    [
      "temporary-replace",
      "temporary-replace-early",
      "temporary-replace-later",
      "temporary-replace-same-size",
      "temporary-replace-truncate",
      "temporary-replace-growth",
      "temporary-reparse",
    ].includes(action)
    && context.checkpoint === "after-publication-link"
  ) {
    hookPath = context.temporaryArchive;
    renamedTemporary = context.temporaryArchive + ".original";
    const original = await fs.readFile(context.temporaryArchive);
    await fs.rename(context.temporaryArchive, renamedTemporary);
    if (action === "temporary-replace-early") {
      await fs.rename(stagedReplacement, context.temporaryArchive);
    } else if (action === "temporary-replace-later") {
      await new Promise((resolve) => setTimeout(resolve, 5));
      replacementBytes = Buffer.from("replacement-temp-later\n", "utf8");
      await fs.writeFile(context.temporaryArchive, replacementBytes, { flag: "wx" });
    } else if (action === "temporary-replace-same-size") {
      replacementBytes = Buffer.alloc(original.length, 0x72);
      await fs.writeFile(context.temporaryArchive, replacementBytes, { flag: "wx" });
    } else if (action === "temporary-replace-truncate") {
      replacementBytes = Buffer.alloc(Math.max(0, original.length - 1), 0x74);
      await fs.writeFile(context.temporaryArchive, replacementBytes, { flag: "wx" });
    } else if (action === "temporary-replace-growth") {
      replacementBytes = Buffer.alloc(original.length + 1, 0x67);
      await fs.writeFile(context.temporaryArchive, replacementBytes, { flag: "wx" });
    } else if (action === "temporary-reparse") {
      await fs.symlink(renamedTemporary, context.temporaryArchive, "file");
    } else {
      replacementBytes = Buffer.from("replacement-temp\n", "utf8");
      await fs.writeFile(context.temporaryArchive, replacementBytes, { flag: "wx" });
    }
  } else if (action === "hard-link-count" && context.checkpoint === "after-publication-link") {
    hookPath = context.temporaryArchive;
    extraLink = context.temporaryArchive + ".extra-link";
    await fs.link(context.temporaryArchive, extraLink);
  } else if (
    ["parent-replace-before", "parent-replace-after"].includes(action)
    && context.checkpoint === (
      action === "parent-replace-before" ? "before-publication" : "after-publication-link"
    )
  ) {
    hookPath = context.temporaryArchive;
    const parent = path.dirname(context.finalOutput);
    renamedParent = parent + ".original";
    await fs.rename(parent, renamedParent);
    await fs.mkdir(parent);
  } else if (action === "safe-prepublication-cleanup" && context.checkpoint === "after-archive-write") {
    hookPath = context.temporaryArchive;
    throw new Error("forced prepublication failure");
  } else if (action === "safe-postpublication-cleanup" && context.checkpoint === "after-publication-link") {
    hookPath = context.temporaryArchive;
    throw new Error("forced postpublication failure");
  } else if (action === "unexpected-sibling" && context.checkpoint === "after-publication-link") {
    hookPath = context.temporaryArchive;
    await fs.writeFile(path.join(path.dirname(context.finalOutput), "unexpected-sibling.bin"), "unexpected\n", { flag: "wx" });
    throw new Error("forced sibling rollback");
  } else if (action === "verifier-failure-before-adoption" && context.checkpoint === "before-temporary-verification") {
    hookPath = context.temporaryArchive;
    throw new Error("forced verifier failure before adoption");
  } else if (action === "verifier-failure-after-adoption" && context.checkpoint === "before-final-verification") {
    hookPath = context.finalOutput;
    throw new Error("forced verifier failure after adoption");
  } else if (action === "temporary-precreate" && context.checkpoint === "before-temporary-create" && !fired) {
    fired = true;
    hookPath = context.temporaryArchive;
    await fs.writeFile(hookPath, "occupied-temp\n", { flag: "wx" });
  }
}};
const details = () => ({
  hookPath,
  temporaryPath,
  renamedTemporary,
  renamedFinal,
  extraLink,
  renamedParent,
  replacementBytes: replacementBytes === null ? null : replacementBytes.toString("base64"),
});
try {
  const result = await preparePublicSourceZip({
    sourceTree: process.env.IELTMPS_TEST_SOURCE_TREE,
    entryPlan: process.env.IELTMPS_TEST_ENTRY_PLAN,
    output: process.env.IELTMPS_TEST_OUTPUT,
    testHooks: hooks,
  });
  process.stdout.write(JSON.stringify({ ok: true, result, ...details() }));
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    phase: error.phase,
    reason: error.reason,
    cleanupUnlinkCount: error.cleanupUnlinkCount ?? null,
    ...details(),
  }));
}
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        return json.loads(completed.stdout)

    def _run_imported_verifier(self, action: str) -> dict[str, Any]:
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_VERIFIER": str(VERIFIER),
                "IELTMPS_TEST_ACTION": action,
                "IELTMPS_TEST_ARCHIVE": str(self.archive),
                "IELTMPS_TEST_ENTRY_PLAN": str(self.entry_plan),
            }
        )
        script = r"""
import { pathToFileURL } from "node:url";
import * as fs from "node:fs/promises";
const { verifyPublicSourceZip } = await import(pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href);
const action = process.env.IELTMPS_TEST_ACTION;
const hooks = { checkpoint: async (context) => {
  if (action === "payload-mutate" && context.checkpoint === "after-central-directory") {
    const handle = await fs.open(process.env.IELTMPS_TEST_ARCHIVE, "r+");
    const byte = Buffer.alloc(1);
    await handle.read(byte, 0, 1, 46);
    byte[0] ^= 1;
    await handle.write(byte, 0, 1, 46);
    await handle.close();
  } else if (action === "same-size-replace" && context.checkpoint === "after-archive-open") {
    const bytes = await fs.readFile(process.env.IELTMPS_TEST_ARCHIVE);
    await fs.rename(process.env.IELTMPS_TEST_ARCHIVE, process.env.IELTMPS_TEST_ARCHIVE + ".old");
    await fs.writeFile(process.env.IELTMPS_TEST_ARCHIVE, bytes);
  } else if (action === "archive-growth" && context.checkpoint === "after-archive-open") {
    await fs.appendFile(process.env.IELTMPS_TEST_ARCHIVE, "x");
  }
}};
try {
  const result = await verifyPublicSourceZip({
    archive: process.env.IELTMPS_TEST_ARCHIVE,
    entryPlan: process.env.IELTMPS_TEST_ENTRY_PLAN,
    testHooks: hooks,
  });
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, phase: error.phase, reason: error.reason }));
}
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        return json.loads(completed.stdout)

    def test_01_crc_known_answers_empty_and_one_byte(self) -> None:
        environment = self._environment()
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        script = r"""
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
process.stdout.write(JSON.stringify([
  core.crc32Bytes(Buffer.alloc(0)).toString(16).padStart(8, "0"),
  core.crc32Bytes(Buffer.from("123456789", "ascii")).toString(16).padStart(8, "0"),
]));
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), ["00000000", "cbf43926"])
        self.assertEqual(binascii.crc32(b"") & 0xFFFFFFFF, 0)
        self.assertEqual(binascii.crc32(b"123456789") & 0xFFFFFFFF, 0xCBF43926)
        self._mark("W")

        self._install_fixture([("empty.bin", "100644", b"")])
        summary = self._assert_success(self._run_writer())
        self.assertEqual(summary["entryCount"], 1)
        parsed = _independent_parse_zip(self.output.read_bytes())
        self.assertEqual(parsed[0]["payload"], b"")
        self._mark("W")

        self.output.unlink()
        self._install_fixture([("one.bin", "100644", b"x")])
        self._assert_success(self._run_writer())
        parsed = _independent_parse_zip(self.output.read_bytes())
        self.assertEqual(parsed[0]["payload"], b"x")
        self._mark("W")

    def test_02_multiple_utf8_unsigned_order_and_modes(self) -> None:
        files = [
            ("z-last.txt", "100644", b"z\n"),
            ("scripts/run.sh", "100755", b"#!/bin/sh\nexit 0\n"),
            ("caf\u00e9/\u8def\u5f84.txt", "100644", b"utf8\n"),
            ("A-first.txt", "100644", b"a\n"),
        ]
        self._install_fixture(files)
        first = self._assert_success(self._run_writer())
        second_output = self.temp_root / "second.zip"
        second = self._assert_success(self._run_writer(output=second_output))
        self.assertEqual(first, second)
        self.assertEqual(self.output.read_bytes(), second_output.read_bytes())
        parsed = _independent_parse_zip(self.output.read_bytes())
        names = [entry["name"] for entry in parsed]
        self.assertEqual(names, sorted(names, key=lambda value: value.encode("utf-8")))
        by_name = {entry["name"]: entry for entry in parsed}
        self.assertEqual(by_name[ARCHIVE_ROOT + "scripts/run.sh"]["external"], 0x81ED0000)
        self.assertEqual(by_name[ARCHIVE_ROOT + "A-first.txt"]["external"], 0x81A40000)
        self.assertIn(ARCHIVE_ROOT + "caf\u00e9/\u8def\u5f84.txt", by_name)
        self._mark("W", 5)

    def test_03_maximum_1024_byte_filename_is_virtual_and_valid(self) -> None:
        components = ["a" * 255, "b" * 255, "c" * 255, "d" * 241]
        source_path = "/".join(components)
        self.assertEqual(len((ARCHIVE_ROOT + source_path).encode("utf-8")), 1024)
        plan, _ = _make_plan([(source_path, "100644", b"")])
        result = self._run_core_cases(
            [
                {
                    "kind": "parse-plan",
                    "bytes": base64.b64encode(_canonical_json(plan)).decode("ascii"),
                }
            ]
        )[0]
        self.assertTrue(result["ok"], result)
        self._mark("W")

    def test_04_independent_python_full_round_trip(self) -> None:
        self._install_fixture(
            [
                ("alpha.txt", "100644", b"alpha\n"),
                ("bin/tool", "100755", b"\x00\xff\x10"),
            ]
        )
        self._write_independent_archive()
        parsed = _independent_parse_zip(self.archive.read_bytes())
        self.assertEqual(len(parsed), 2)
        result = self._assert_success(self._run_verifier())
        self.assertEqual(result["archiveSha256"], _sha256(self.archive.read_bytes()))
        self._mark("W")

    def test_05_local_header_authority_l01_l12(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = bytearray(_assemble_zip(self.plan, self.payloads))
        local = self.plan["entries"][0]["localHeaderOffset"]
        name_offset = local + 30
        mutations: list[tuple[str, Callable[[bytearray], None], str, str]] = [
            ("signature", lambda b: struct.pack_into("<I", b, local, 0), "ZIP_PARSE", "local-signature"),
            ("version", lambda b: struct.pack_into("<H", b, local + 4, 19), "ZIP_PROFILE", "version-needed"),
            ("flag", lambda b: struct.pack_into("<H", b, local + 6, 0), "ZIP_PROFILE", "general-purpose-flag"),
            ("method", lambda b: struct.pack_into("<H", b, local + 8, 8), "ZIP_PROFILE", "compression-method"),
            ("time", lambda b: struct.pack_into("<H", b, local + 10, 1), "ZIP_PROFILE", "dos-time"),
            ("date", lambda b: struct.pack_into("<H", b, local + 12, 0), "ZIP_PROFILE", "dos-date"),
            ("crc", lambda b: struct.pack_into("<I", b, local + 14, 0), "ZIP_BINDING", "stored-payload-mismatch"),
            ("stored", lambda b: struct.pack_into("<I", b, local + 18, 4), "ZIP_PROFILE", "local-metadata"),
            ("uncompressed", lambda b: struct.pack_into("<I", b, local + 22, 4), "ZIP_PROFILE", "local-metadata"),
            ("name-length", lambda b: struct.pack_into("<H", b, local + 26, 1), "ZIP_BINDING", "local-central-filename"),
            ("extra", lambda b: struct.pack_into("<H", b, local + 28, 1), "ZIP_PROFILE", "local-metadata"),
            ("name", lambda b: b.__setitem__(name_offset, b[name_offset] ^ 1), "ZIP_BINDING", "local-central-filename"),
        ]
        for name, mutate, phase, reason in mutations:
            with self.subTest(case=name):
                changed = bytearray(baseline)
                mutate(changed)
                target = self._mutated_archive(bytes(changed), "local-" + name)
                self._assert_failure(self._run_verifier(target), phase, reason)
        self._mark("L", 12)

    def test_06_central_directory_authority_c01_c08(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = bytearray(_assemble_zip(self.plan, self.payloads))
        central = self.plan["entries"][0]["centralDirectoryRecordOffset"]
        mutations: list[tuple[str, int, str, int, str, str]] = [
            ("signature", 0, "I", 0, "ZIP_PARSE", "central-signature"),
            ("made", 4, "H", 20, "ZIP_PROFILE", "version-made-by"),
            ("needed", 6, "H", 19, "ZIP_PROFILE", "version-needed"),
            ("flag", 8, "H", 0, "ZIP_PROFILE", "general-purpose-flag"),
            ("method", 10, "H", 8, "ZIP_PROFILE", "compression-method"),
            ("time", 12, "H", 1, "ZIP_PROFILE", "dos-time"),
            ("date", 14, "H", 0, "ZIP_PROFILE", "dos-date"),
            ("crc", 16, "I", 0, "ZIP_BINDING", "central-entry-plan-mismatch"),
        ]
        for name, relative, encoding, value, phase, reason in mutations:
            with self.subTest(case=name):
                changed = bytearray(baseline)
                struct.pack_into("<" + encoding, changed, central + relative, value)
                target = self._mutated_archive(bytes(changed), "central-a-" + name)
                self._assert_failure(self._run_verifier(target), phase, reason)
        self._mark("C", 8)

    def test_07_central_directory_authority_c09_c16(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = bytearray(_assemble_zip(self.plan, self.payloads))
        central = self.plan["entries"][0]["centralDirectoryRecordOffset"]
        mutations: list[tuple[str, int, str, int, str, str]] = [
            ("stored", 20, "I", 4, "ZIP_PROFILE", "stored-size-mismatch"),
            ("name-length", 28, "H", 1, "ZIP_BINDING", "central-filename"),
            ("extra", 30, "H", 1, "ZIP_PROFILE", "central-metadata"),
            ("comment", 32, "H", 1, "ZIP_PROFILE", "central-metadata"),
            ("disk", 34, "H", 1, "ZIP_PROFILE", "central-metadata"),
            ("internal", 36, "H", 1, "ZIP_PROFILE", "central-metadata"),
            ("external", 38, "I", 0, "ZIP_PROFILE", "central-metadata"),
            ("local-offset", 42, "I", 1, "ZIP_BINDING", "central-entry-plan-mismatch"),
        ]
        for name, relative, encoding, value, phase, reason in mutations:
            with self.subTest(case=name):
                changed = bytearray(baseline)
                struct.pack_into("<" + encoding, changed, central + relative, value)
                target = self._mutated_archive(bytes(changed), "central-b-" + name)
                self._assert_failure(self._run_verifier(target), phase, reason)
        self._mark("C", 8)

    def test_08_eocd_authority_e01_e07(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = bytearray(_assemble_zip(self.plan, self.payloads))
        eocd = len(baseline) - 22
        mutations: list[tuple[str, int, str, int, str, str]] = [
            ("signature", 0, "I", 0, "ZIP_PARSE", "eocd-signature"),
            ("disk", 4, "H", 1, "ZIP_PROFILE", "eocd-disk-number"),
            ("central-disk", 6, "H", 1, "ZIP_PROFILE", "eocd-central-disk"),
            ("disk-count", 8, "H", 2, "ZIP_PROFILE", "eocd-entry-count"),
            ("zero-count", 10, "H", 0, "ZIP_PROFILE", "eocd-entry-count"),
            ("plan-count", 10, "H", 2, "ZIP_PROFILE", "eocd-entry-count"),
            ("comment", 20, "H", 1, "ZIP_PROFILE", "archive-comment"),
        ]
        for name, relative, encoding, value, phase, reason in mutations:
            with self.subTest(case=name):
                changed = bytearray(baseline)
                struct.pack_into("<" + encoding, changed, eocd + relative, value)
                target = self._mutated_archive(bytes(changed), "eocd-a-" + name)
                self._assert_failure(self._run_verifier(target), phase, reason)
        self._mark("E", 7)

    def test_09_eocd_authority_e08_e13_and_payload_signature(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = bytearray(_assemble_zip(self.plan, self.payloads))
        eocd = len(baseline) - 22
        mutations: list[tuple[str, Callable[[bytearray], bytes], str, str]] = [
            ("size-sentinel", lambda b: (struct.pack_into("<I", b, eocd + 12, 0xFFFFFFFF) or bytes(b)), "ZIP_PROFILE", "zip64-sentinel"),
            ("offset-sentinel", lambda b: (struct.pack_into("<I", b, eocd + 16, 0xFFFFFFFF) or bytes(b)), "ZIP_PROFILE", "zip64-sentinel"),
            ("range", lambda b: (struct.pack_into("<I", b, eocd + 12, self.plan["centralDirectoryByteLength"] + 1) or bytes(b)), "ZIP_PARSE", "central-directory-range"),
            ("trailing", lambda b: bytes(b) + b"x", "ZIP_PARSE", "eocd-signature"),
            ("prepended", lambda b: b"x" + bytes(b), "ZIP_PARSE", "central-directory-range"),
        ]
        for name, mutate, phase, reason in mutations:
            with self.subTest(case=name):
                target = self._mutated_archive(mutate(bytearray(baseline)), "eocd-b-" + name)
                self._assert_failure(self._run_verifier(target), phase, reason)

        payload = struct.pack("<I", EOCD_SIGNATURE) + b"ordinary-payload"
        self._install_fixture([("signature.bin", "100644", payload)])
        self._write_independent_archive()
        self._assert_success(self._run_verifier())
        self._mark("E", 6)

    def test_10_path_authority_p01_p10(self) -> None:
        cases = [
            {"kind": "path", "value": ""},
            {"kind": "path", "value": "e\u0301.txt"},
            {"kind": "path", "value": "nul\u0000.txt"},
            {"kind": "path", "value": "ctl\u0001.txt"},
            {"kind": "path", "value": "C:drive.txt"},
            {"kind": "path", "value": "https:uri.txt"},
            {"kind": "path", "value": "//server/share.txt"},
            {"kind": "path", "value": "dir\\file.txt"},
            {"kind": "path", "value": "/absolute.txt"},
            {"kind": "path", "value": "trailing/"},
        ]
        results = self._run_core_cases(cases)
        for result in results:
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["phase"], "PATH_AUTHORITY")
        self._mark("P", 10)

    def test_11_path_collision_and_order_authority_p11_p20(self) -> None:
        layout_base = {
            "gitMode": "100644",
            "byteLength": 0,
        }
        cases = [
            {"kind": "path", "value": "repeat//separator.txt"},
            {"kind": "path", "value": "./dot.txt"},
            {"kind": "path", "value": "parent/../escape.txt"},
            {"kind": "path", "value": "bad?.txt"},
            {"kind": "path", "value": "CON.txt"},
            {"kind": "path", "value": "trailing-dot."},
            {"kind": "path", "value": "x" * 256},
            {
                "kind": "layout",
                "entries": [
                    {**layout_base, "sourcePath": "A.txt", "archivePath": ARCHIVE_ROOT + "A.txt"},
                    {**layout_base, "sourcePath": "a.txt", "archivePath": ARCHIVE_ROOT + "a.txt"},
                ],
            },
            {
                "kind": "layout",
                "entries": [
                    {**layout_base, "sourcePath": "a", "archivePath": ARCHIVE_ROOT + "a"},
                    {**layout_base, "sourcePath": "a/b", "archivePath": ARCHIVE_ROOT + "a/b"},
                ],
            },
            {
                "kind": "layout",
                "entries": [
                    {**layout_base, "sourcePath": "b", "archivePath": ARCHIVE_ROOT + "b"},
                    {**layout_base, "sourcePath": "a", "archivePath": ARCHIVE_ROOT + "a"},
                ],
            },
        ]
        results = self._run_core_cases(cases)
        for result in results:
            self.assertFalse(result["ok"], result)
        self._mark("P", 10)

    def test_12_source_identity_and_two_pass_races_f01_f06(self) -> None:
        actions = [
            "pass-a-mutate",
            "pass-a-replace",
            "pass-a-truncate",
            "pass-a-grow",
            "parent-between",
            "content-between",
        ]
        for action in actions:
            with self.subTest(action=action):
                self._install_fixture([("dir/file.txt", "100644", b"stable-source\n")])
                if self.output.exists():
                    self.output.unlink()
                result = self._run_imported_writer(action)
                self.assertFalse(result["ok"], result)
                self.assertIn(result["phase"], {"SOURCE_FILE", "ZIP_BINDING"})
                self.assertFalse(self.output.exists())
        self._mark("F", 6)

    def test_13_archive_identity_races_f07_f09(self) -> None:
        for action in ["payload-mutate", "same-size-replace", "archive-growth"]:
            with self.subTest(action=action):
                self._install_fixture([("file.txt", "100644", b"archive-source\n")])
                self._write_independent_archive()
                result = self._run_imported_verifier(action)
                self.assertFalse(result["ok"], result)
                self.assertIn(result["phase"], {"ZIP_PARSE", "ZIP_BINDING"})
        self._mark("F", 3)

    def test_14_symlink_hardlink_and_final_replacement_f10_f12(self) -> None:
        self._install_fixture([("dir/file.txt", "100644", b"stable-source\n")])
        self._write_independent_archive()
        alias = self.temp_root / "archive-alias.zip"
        alias.symlink_to(self.archive)
        self._assert_failure(
            self._run_verifier(alias),
            "PATH_AUTHORITY",
            "archive-file-state",
        )
        self._mark("F")

        source_file = self.source_tree / "dir/file.txt"
        source_link = self.temp_root / "source-hardlink.txt"
        os.link(source_file, source_link)
        self._assert_failure(
            self._run_writer(),
            "SOURCE_FILE",
            "source-file-state",
        )
        source_link.unlink()
        self._mark("F")

        result = self._run_imported_writer("final-replace")
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["phase"], "CLEANUP")
        self.assertEqual(result["reason"], "cleanup-identity-uncertain")
        self._cleanup_assert(result["cleanupUnlinkCount"] == 0)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.output.read_bytes(), b"replacement-final\n")
        self._mark("F")

    def test_15_malformed_whole_archive_authority_m01_m05_m10_m13(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        baseline = _assemble_zip(self.plan, self.payloads)
        central = self.plan["centralDirectoryOffset"]
        eocd = len(baseline) - 22
        malformed: list[tuple[str, bytes]] = []
        malformed.append(("empty", b""))
        malformed.append(("concatenated", baseline + baseline))
        malformed.append(("descriptor", baseline[:central] + b"PK\x07\x08" + baseline[central:]))
        malformed.append(("digital-signature", baseline[:eocd] + b"PK\x05\x05\x00\x00" + baseline[eocd:]))
        malformed.append(("unknown-record", baseline[:central] + b"PK\x99\x99" + baseline[central:]))
        malformed.append(("zip64-eocd", baseline + b"PK\x06\x06" + bytes(52)))
        malformed.append(("zip64-locator", baseline + b"PK\x06\x07" + bytes(16)))
        directory_plan, directory_payloads = _make_plan([("dir", "100644", b"")])
        directory_zip = bytearray(_assemble_zip(directory_plan, directory_payloads))
        name_length = len((ARCHIVE_ROOT + "dir").encode("utf-8"))
        directory_zip[30 + name_length - 1] = ord("/")
        malformed.append(("explicit-directory", bytes(directory_zip)))
        malformed.append(("truncated", baseline[:-1]))
        for name, value in malformed:
            with self.subTest(case=name):
                target = self._mutated_archive(value, "whole-" + name)
                self._assert_failure(self._run_verifier(target))
        self._mark("M", 9)

    def test_16_numeric_and_virtual_boundaries_m06_m09_m14_m18(self) -> None:
        environment = self._environment()
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        script = r"""
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const entry = (index, size = 0) => {
  const sourcePath = "f/" + String(index).padStart(5, "0");
  return { sourcePath, archivePath: core.ZIP_ARCHIVE_ROOT + sourcePath, gitMode: "100644", byteLength: size };
};
const results = [];
try { const value = core.computeCanonicalZipLayout(Array.from({length: 65534}, (_, i) => entry(i))); results.push(value.entries.length === 65534); } catch { results.push(false); }
for (const operation of [
  () => core.computeCanonicalZipLayout(Array.from({length: 65535}, (_, i) => entry(i))),
  () => core.encodeLocalFileHeader({ sourcePath: "a", archivePath: core.ZIP_ARCHIVE_ROOT + "a", gitMode: "100644", crc32: "00000000", byteLength: 0xffffffff }),
  () => core.encodeLocalFileHeader({ sourcePath: "a", archivePath: core.ZIP_ARCHIVE_ROOT + "a", gitMode: "100644", crc32: "00000000", byteLength: 0x100000000 }),
  () => core.computeCanonicalZipLayout([entry(0, 0xfffffffe)]),
]) {
  try { operation(); results.push(false); } catch { results.push(true); }
}
try {
  const header = core.encodeLocalFileHeader({ sourcePath: "a", archivePath: core.ZIP_ARCHIVE_ROOT + "a", gitMode: "100644", crc32: "00000000", byteLength: 0xfffffffe });
  results.push(header.readUInt32LE(18) === 0xfffffffe);
} catch { results.push(false); }
for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER]) {
  try { core.requireZip32Number(value); results.push(false); } catch { results.push(true); }
}
process.stdout.write(JSON.stringify(results));
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(completed.stdout)
        self.assertEqual(results, [True] * 9)
        self._mark("M", 9)

    def test_17_canonical_entry_plan_duplicate_keys_and_encoding(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        canonical = self.entry_plan.read_bytes()
        duplicate = canonical.replace(
            b'{"documentKind":',
            b'{"documentKind":"duplicate","documentKind":',
            1,
        )
        variants = [
            canonical[:-1],
            canonical + b"\n",
            b"\xef\xbb\xbf" + canonical,
            canonical.replace(b"\n", b"\r\n"),
            canonical.replace(b'"schemaVersion":1', b'"schemaVersion":1.0'),
            canonical.replace(b'"schemaVersion":1', b' "schemaVersion":1'),
            duplicate,
        ]
        cases = [
            {"kind": "parse-plan", "bytes": base64.b64encode(value).decode("ascii")}
            for value in variants
        ]
        results = self._run_core_cases(cases)
        self.assertTrue(all(not result["ok"] for result in results), results)
        self.assertEqual(self.entry_plan.read_bytes(), _canonical_json(self.plan))

    def test_18_publication_adoption_race_repeated_ten_times(self) -> None:
        for iteration in range(10):
            with self.subTest(iteration=iteration):
                self._install_fixture([("dir/file.txt", "100644", b"stable-source\n")])
                if self.output.exists():
                    self.output.unlink()
                result = self._run_imported_writer("final-precreate")
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["phase"], "OUTPUT_PUBLICATION")
                self.assertEqual(result["reason"], "final-target-exists")
                self._cleanup_assert(
                    self.output.read_bytes() == b"racing-final\n",
                    "writer overwrote the racing final target",
                )
                self._cleanup_assert(
                    not any(
                        item.name.startswith(".__iz-")
                        for item in self.temp_root.iterdir()
                    ),
                    "owned temporary ZIP survived adoption race",
                )
                self._cleanup_assert(
                    self.sentinel.read_bytes() == b"unrelated-object\n",
                    "unrelated object changed during adoption race",
                )
                self.output.unlink()

    def test_19_temporary_collision_and_substitution_cleanup(self) -> None:
        self._install_fixture([("dir/file.txt", "100644", b"stable-source\n")])
        collision = self._run_imported_writer("temporary-precreate")
        self.assertTrue(collision["ok"], collision)
        occupied = Path(collision["hookPath"])
        self.assertTrue(occupied.is_file())
        self.assertEqual(occupied.read_bytes(), b"occupied-temp\n")
        self.assertTrue(self.output.is_file())
        self._assert_success(self._run_verifier(self.output))
        occupied.unlink()
        self.output.unlink()

        result = self._run_imported_writer("temporary-replace")
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["phase"], "CLEANUP")
        self.assertEqual(result["reason"], "cleanup-identity-uncertain")
        self._cleanup_assert(result["cleanupUnlinkCount"] == 0)
        expected_archive = _assemble_zip(self.plan, self.payloads)
        temporary_path = Path(result["hookPath"])
        renamed_original = Path(result["renamedTemporary"])
        replacement = base64.b64decode(result["replacementBytes"])
        self._cleanup_assert(self.output.read_bytes() == expected_archive)
        self._cleanup_assert(temporary_path.read_bytes() == replacement)
        self._cleanup_assert(renamed_original.read_bytes() == expected_archive)
        self._cleanup_assert(
            self.sentinel.read_bytes() == b"unrelated-object\n"
        )
        _independent_parse_zip(self.output.read_bytes())

    def test_20_privacy_import_silence_and_cli_exactness(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        summary = self._assert_success(self._run_writer())
        verifier = self._assert_success(self._run_verifier(self.output))
        for value in (summary, verifier):
            serialized = json.dumps(value, separators=(",", ":"))
            self._assert_privacy(serialized)
            self.assertNotIn("output", value)
            self.assertNotIn("archive", value)
        plan_text = self.entry_plan.read_text(encoding="utf-8")
        for canary in self.privacy_canaries:
            self.assertNotIn(canary, plan_text)

        environment = self._environment()
        environment["IELTMPS_TEST_MODULES"] = os.pathsep.join(
            [str(CORE), str(WRITER), str(VERIFIER)]
        )
        script = r"""
import { pathToFileURL } from "node:url";
const before = process.exitCode;
for (const value of process.env.IELTMPS_TEST_MODULES.split(process.platform === "win32" ? ";" : ":")) {
  await import(pathToFileURL(value).href);
}
if (process.exitCode !== before) process.exit(91);
"""
        imported = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr.decode(errors="replace"))
        self.assertEqual(imported.stdout, b"")
        self.assertEqual(imported.stderr, b"")

        for flag in [
            "--overwrite",
            "--compression",
            "--timestamp",
            "--permission",
            "--root",
            "--format",
            "--hash",
            "--path",
            "--entry-count",
            "--zip64",
            "--test-hook",
        ]:
            with self.subTest(writer_flag=flag):
                self._assert_failure(
                    self._run_writer(extra_args=[flag, self.privacy_canaries[0]]),
                    "CLI",
                    "unknown-or-duplicate-option",
                )
        for flag in ["--output", "--format", "--zip64", "--test-hook"]:
            with self.subTest(verifier_flag=flag):
                self._assert_failure(
                    self._run_verifier(self.output, extra_args=[flag, self.privacy_canaries[1]]),
                    "CLI",
                    "unknown-or-duplicate-option",
                )

    def test_21_direct_execution_aliases_and_alias_import(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        relative_writer = os.path.relpath(WRITER, REPO_ROOT)
        relative_output = self.temp_root / "relative.zip"
        self._assert_success(
            self._run_writer(
                output=relative_output,
                script=relative_writer,
                cwd=REPO_ROOT,
            )
        )
        dot_writer = str(WRITER.parent) + os.sep + "." + os.sep + WRITER.name
        dot_output = self.temp_root / "dot.zip"
        self._assert_success(self._run_writer(output=dot_output, script=dot_writer))

        relative_verifier = os.path.relpath(VERIFIER, REPO_ROOT)
        self._assert_success(
            self._run_verifier(
                relative_output,
                script=relative_verifier,
                cwd=REPO_ROOT,
            )
        )
        dot_verifier = str(VERIFIER.parent) + os.sep + "." + os.sep + VERIFIER.name
        self._assert_success(
            self._run_verifier(relative_output, script=dot_verifier)
        )

        writer_alias = self.temp_root / "writer-alias.mjs"
        verifier_alias = self.temp_root / "verifier-alias.mjs"
        writer_alias.symlink_to(WRITER)
        verifier_alias.symlink_to(VERIFIER)
        alias_output = self.temp_root / "alias.zip"
        self._assert_success(self._run_writer(output=alias_output, script=writer_alias))
        self._assert_success(self._run_verifier(alias_output, script=verifier_alias))

        environment = self._environment()
        environment["IELTMPS_TEST_ALIAS"] = str(writer_alias)
        import_script = r"""
import { pathToFileURL } from "node:url";
const before = process.exitCode;
await import(pathToFileURL(process.env.IELTMPS_TEST_ALIAS).href);
if (process.exitCode !== before) process.exit(91);
"""
        imported = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", import_script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr.decode(errors="replace"))
        self.assertEqual(imported.stdout, b"")
        self.assertEqual(imported.stderr, b"")

        directory_alias = self.temp_root / "tool-directory-alias"
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(directory_alias), str(REPO_ROOT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
        else:
            directory_alias.symlink_to(REPO_ROOT, target_is_directory=True)
        try:
            directory_output = self.temp_root / "directory-alias.zip"
            self._assert_success(
                self._run_writer(
                    output=directory_output,
                    script=directory_alias / "developer" / WRITER.name,
                )
            )
            self._assert_success(
                self._run_verifier(
                    directory_output,
                    script=directory_alias / "developer" / VERIFIER.name,
                )
            )
        finally:
            if os.name == "nt":
                os.rmdir(directory_alias)
            else:
                directory_alias.unlink()

    def test_22_results_are_exact_frozen_and_path_free(self) -> None:
        self._install_fixture([("file.txt", "100644", b"abc")])
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_WRITER": str(WRITER),
                "IELTMPS_TEST_VERIFIER": str(VERIFIER),
                "IELTMPS_TEST_SOURCE_TREE": str(self.source_tree),
                "IELTMPS_TEST_ENTRY_PLAN": str(self.entry_plan),
                "IELTMPS_TEST_OUTPUT": str(self.output),
            }
        )
        script = r"""
import { pathToFileURL } from "node:url";
const { preparePublicSourceZip } = await import(pathToFileURL(process.env.IELTMPS_TEST_WRITER).href);
const { verifyPublicSourceZip } = await import(pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href);
const written = await preparePublicSourceZip({ sourceTree: process.env.IELTMPS_TEST_SOURCE_TREE, entryPlan: process.env.IELTMPS_TEST_ENTRY_PLAN, output: process.env.IELTMPS_TEST_OUTPUT });
const verified = await verifyPublicSourceZip({ archive: process.env.IELTMPS_TEST_OUTPUT, entryPlan: process.env.IELTMPS_TEST_ENTRY_PLAN });
process.stdout.write(JSON.stringify({
  writerFrozen: Object.isFrozen(written),
  verifierFrozen: Object.isFrozen(verified),
  writerKeys: Object.keys(written),
  verifierKeys: Object.keys(verified),
  hasBuffer: [...Object.values(written), ...Object.values(verified)].some((value) => Buffer.isBuffer(value)),
}));
"""
        completed = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["writerFrozen"])
        self.assertTrue(payload["verifierFrozen"])
        self.assertFalse(payload["hasBuffer"])
        self.assertEqual(payload["writerKeys"][0:4], ["status", "mode", "artifactRole", "formatProfile"])
        self.assertEqual(payload["verifierKeys"][0:4], ["verificationKind", "schemaVersion", "status", "mode"])

    def test_23_windows_ads_host_path_authority_ads01_ads12(self) -> None:
        self._install_fixture([("file.txt", "100644", b"stable-source\n")])
        self._write_independent_archive()
        archive_bytes = self.archive.read_bytes()
        plan_bytes = self.entry_plan.read_bytes()

        invalid_windows_paths = [
            r"C:\owned\host.txt:archive.zip",
            r"C:\owned\host.txt:plan.json",
            r"C:\owned\host.txt:stream:$DATA",
            r"C:\owned\host.txt::$DATA",
            r"C:\owned\dir:name\file.zip",
            r"C:\owned\file.zip:",
            r"C:\owned\:stream",
            r"C::\owned\file.zip",
            r"C:relative",
            r"C::",
            r"C::\path",
            r"1:\path",
            r":\path",
        ]
        valid_windows_paths = [
            r"C:\owned\plan.json",
            r"C:\owned\archive.zip",
            r"C:\owned\source-tree",
            r"C:\owned\output\artifact.zip",
        ]
        lexical = self._run_core_cases(
            [
                {"kind": "windows-host-path", "value": value}
                for value in invalid_windows_paths + valid_windows_paths
            ]
        )
        for result in lexical[: len(invalid_windows_paths)]:
            self.assertEqual(
                result,
                {
                    "ok": False,
                    "phase": "PATH_AUTHORITY",
                    "reason": "windows-alternate-data-stream",
                },
            )
        for result in lexical[len(invalid_windows_paths) :]:
            self.assertEqual(result, {"ok": True})

        if os.name != "nt":
            posix = self._run_core_cases(
                [{"kind": "host-path", "value": "/owned/host.txt:stream"}]
            )
            self.assertEqual(posix, [{"ok": True}])
            for _ in range(EXPECTED_ADS_CASES):
                self._mark_ads()
            self._cleanup_assert(self.sentinel.is_file())
            self._cleanup_assert(
                self.sentinel.read_bytes() == b"unrelated-object\n"
            )
            self._assert_no_owned_temporary_zip()
            self._cleanup_assert(not self.output.exists())
            self.__class__.ads_fixture_mode = "lexical-posix"
            return

        self.assertRegex(str(self.temp_root), r"\A[A-Za-z]:\\")
        probe_host = self.temp_root / "ads-probe-host.bin"
        probe_host.write_bytes(b"probe-host\n")
        probe_stream = Path(str(probe_host) + ":probe-stream")
        ads_supported = False
        try:
            probe_stream.write_bytes(b"probe-stream\n")
            ads_supported = probe_stream.read_bytes() == b"probe-stream\n"
        except OSError:
            ads_supported = False
        finally:
            if ads_supported:
                probe_stream.unlink()
        self.assertEqual(probe_host.read_bytes(), b"probe-host\n")
        self.__class__.ads_fixture_mode = (
            "real-ntfs" if ads_supported else "lexical-windows"
        )

        unrelated_tail = ":" + self.privacy_canaries[-1] + ".keep"

        def create_host(
            name: str,
            host_bytes: bytes,
            desired_streams: dict[str, bytes],
        ) -> tuple[Path, dict[str, bytes]]:
            host = self.temp_root / name
            host.write_bytes(host_bytes)
            snapshots: dict[str, bytes] = {}
            if ads_supported:
                for tail, value in desired_streams.items():
                    stream_path = str(host) + tail
                    Path(stream_path).write_bytes(value)
                    self.assertEqual(Path(stream_path).read_bytes(), value)
                    snapshots[stream_path] = value
            return host, snapshots

        # ADS01: verifier ADS archive with a normal entry plan.
        ads01_tail = ":" + self.privacy_canaries[0] + ".zip"
        ads01_host, ads01_streams = create_host(
            "ads01-host.bin",
            b"ads01-host\n",
            {
                ads01_tail: archive_bytes,
                unrelated_tail: b"ads01-unrelated-stream\n",
            },
        )
        ads01_archive = str(ads01_host) + ads01_tail
        self._assert_ads_failure(
            self._run_verifier(ads01_archive),
            ads01_tail[1:],
        )
        self._assert_ads_objects_preserved(
            ads01_host,
            b"ads01-host\n",
            ads01_streams,
        )
        self._mark_ads()

        # ADS02: verifier normal archive with an ADS entry plan.
        ads02_tail = ":" + self.privacy_canaries[1] + ".json"
        ads02_host, ads02_streams = create_host(
            "ads02-host.bin",
            b"ads02-host\n",
            {
                ads02_tail: plan_bytes,
                unrelated_tail: b"ads02-unrelated-stream\n",
            },
        )
        ads02_plan = str(ads02_host) + ads02_tail
        self._assert_ads_failure(
            self._run_verifier(self.archive, entry_plan=ads02_plan),
            ads02_tail[1:],
        )
        self._assert_ads_objects_preserved(
            ads02_host,
            b"ads02-host\n",
            ads02_streams,
        )
        self._mark_ads()

        # ADS03: verifier ADS archive and ADS entry plan; plan is preflighted first.
        ads03_archive_tail = ":" + self.privacy_canaries[2] + ".zip"
        ads03_plan_tail = ":" + self.privacy_canaries[3] + ".json"
        ads03_archive_host, ads03_archive_streams = create_host(
            "ads03-archive-host.bin",
            b"ads03-archive-host\n",
            {
                ads03_archive_tail: archive_bytes,
                unrelated_tail: b"ads03-archive-unrelated\n",
            },
        )
        ads03_plan_host, ads03_plan_streams = create_host(
            "ads03-plan-host.bin",
            b"ads03-plan-host\n",
            {
                ads03_plan_tail: plan_bytes,
                unrelated_tail: b"ads03-plan-unrelated\n",
            },
        )
        self._assert_ads_failure(
            self._run_verifier(
                str(ads03_archive_host) + ads03_archive_tail,
                entry_plan=str(ads03_plan_host) + ads03_plan_tail,
            ),
            ads03_archive_tail[1:],
            ads03_plan_tail[1:],
        )
        self._assert_ads_objects_preserved(
            ads03_archive_host,
            b"ads03-archive-host\n",
            ads03_archive_streams,
        )
        self._assert_ads_objects_preserved(
            ads03_plan_host,
            b"ads03-plan-host\n",
            ads03_plan_streams,
        )
        self._mark_ads()

        # ADS04: writer ADS entry plan.
        ads04_tail = ":" + self.privacy_canaries[4] + ".json"
        ads04_host, ads04_streams = create_host(
            "ads04-host.bin",
            b"ads04-host\n",
            {
                ads04_tail: plan_bytes,
                unrelated_tail: b"ads04-unrelated-stream\n",
            },
        )
        self._assert_ads_failure(
            self._run_writer(entry_plan=str(ads04_host) + ads04_tail),
            ads04_tail[1:],
        )
        self.assertFalse(self.output.exists())
        self._assert_ads_objects_preserved(
            ads04_host,
            b"ads04-host\n",
            ads04_streams,
        )
        self._mark_ads()

        # ADS05: writer ADS final output.
        ads05_host, ads05_streams = create_host(
            "ads05-host.bin",
            b"ads05-host\n",
            {unrelated_tail: b"ads05-unrelated-stream\n"},
        )
        ads05_tail = ":" + self.privacy_canaries[5] + ".zip"
        ads05_output = str(ads05_host) + ads05_tail
        self.assertFalse(Path(ads05_output).exists())
        self._assert_ads_failure(
            self._run_writer(output=ads05_output),
            ads05_tail[1:],
        )
        self.assertFalse(Path(ads05_output).exists())
        self._assert_ads_objects_preserved(
            ads05_host,
            b"ads05-host\n",
            ads05_streams,
        )
        self._mark_ads()

        # ADS06: writer source-tree path with a post-drive colon.
        ads06_host, ads06_streams = create_host(
            "ads06-host.bin",
            b"ads06-host\n",
            {unrelated_tail: b"ads06-unrelated-stream\n"},
        )
        ads06_tail = ":" + self.privacy_canaries[6] + "-source-tree"
        self._assert_ads_failure(
            self._run_writer(source_tree=str(ads06_host) + ads06_tail),
            ads06_tail[1:],
        )
        self.assertFalse(self.output.exists())
        self._assert_ads_objects_preserved(
            ads06_host,
            b"ads06-host\n",
            ads06_streams,
        )
        self._mark_ads()

        # ADS07: writer output parent with a post-drive colon.
        ads07_host, ads07_streams = create_host(
            "ads07-host.bin",
            b"ads07-host\n",
            {unrelated_tail: b"ads07-unrelated-stream\n"},
        )
        ads07_stream_name = self.privacy_canaries[7]
        ads07_output = (
            str(ads07_host)
            + ":"
            + ads07_stream_name
            + r"\artifact.zip"
        )
        self._assert_ads_failure(
            self._run_writer(output=ads07_output),
            ads07_stream_name,
        )
        self.assertFalse(Path(ads07_output).exists())
        self._assert_ads_objects_preserved(
            ads07_host,
            b"ads07-host\n",
            ads07_streams,
        )
        self._mark_ads()

        # ADS08: verifier archive using :$DATA.
        ads08_host = self.temp_root / "ads08-host.bin"
        ads08_host.write_bytes(b"ads08-host\n")
        ads08_archive = str(ads08_host) + ":$DATA"
        ads08_streams: dict[str, bytes] = {}
        if ads_supported:
            try:
                Path(ads08_archive).write_bytes(archive_bytes)
                ads08_streams[ads08_archive] = Path(ads08_archive).read_bytes()
            except OSError:
                pass
        ads08_host_bytes = ads08_host.read_bytes()
        self._assert_ads_failure(
            self._run_verifier(ads08_archive),
            "$DATA",
        )
        self._assert_ads_objects_preserved(
            ads08_host,
            ads08_host_bytes,
            ads08_streams,
        )
        self._mark_ads()

        # ADS09: verifier entry plan using the default stream spelling ::$DATA.
        ads09_host, ads09_streams = create_host(
            "ads09-host.bin",
            plan_bytes,
            {unrelated_tail: b"ads09-unrelated-stream\n"},
        )
        ads09_plan = str(ads09_host) + "::$DATA"
        if ads_supported:
            self.assertEqual(Path(ads09_plan).read_bytes(), plan_bytes)
            ads09_streams[ads09_plan] = plan_bytes
        self._assert_ads_failure(
            self._run_verifier(self.archive, entry_plan=ads09_plan),
            "$DATA",
        )
        self._assert_ads_objects_preserved(
            ads09_host,
            plan_bytes,
            ads09_streams,
        )
        self._mark_ads()

        # ADS10: verifier archive and plan streams on the same host file.
        ads10_archive_tail = ":" + self.privacy_canaries[9] + ".zip"
        ads10_plan_tail = ":" + self.privacy_canaries[10] + ".json"
        ads10_host, ads10_streams = create_host(
            "ads10-host.bin",
            b"ads10-host\n",
            {
                ads10_archive_tail: archive_bytes,
                ads10_plan_tail: plan_bytes,
                unrelated_tail: b"ads10-unrelated-stream\n",
            },
        )
        self._assert_ads_failure(
            self._run_verifier(
                str(ads10_host) + ads10_archive_tail,
                entry_plan=str(ads10_host) + ads10_plan_tail,
            ),
            ads10_archive_tail[1:],
            ads10_plan_tail[1:],
        )
        self._assert_ads_objects_preserved(
            ads10_host,
            b"ads10-host\n",
            ads10_streams,
        )
        self._mark_ads()

        # ADS11: a normal absolute drive path remains valid for the verifier.
        self.assertRegex(str(self.archive), r"\A[A-Za-z]:\\")
        verified = self._assert_success(self._run_verifier(self.archive))
        self.assertEqual(verified["status"], "ok")
        self._cleanup_assert(
            self.sentinel.read_bytes() == b"unrelated-object\n"
        )
        self._mark_ads()

        # ADS12: normal absolute drive paths remain valid for the writer.
        self.assertRegex(str(self.output), r"\A[A-Za-z]:\\")
        written = self._assert_success(self._run_writer())
        self.assertEqual(written["status"], "ok")
        self._cleanup_assert(self.output.is_file())
        self._assert_no_owned_temporary_zip()
        self._cleanup_assert(
            self.sentinel.read_bytes() == b"unrelated-object\n"
        )
        self._mark_ads()

    def test_24_windows_forward_slash_host_paths_slash01_slash12(self) -> None:
        self._install_fixture([("file.txt", "100644", b"slash-source\n")])
        self._write_independent_archive()

        if os.name != "nt":
            lexical = self._run_core_cases(
                [
                    {"kind": "canonical-host-path", "value": "/owned/archive.zip"},
                    {"kind": "canonical-host-path", "value": "/owned/file:stream"},
                ]
            )
            self.assertEqual(
                lexical,
                [
                    {"ok": True, "value": "/owned/archive.zip"},
                    {"ok": True, "value": "/owned/file:stream"},
                ],
            )
            self._mark_slash(EXPECTED_SLASH_CASES)
            return

        def slash(value: Path) -> str:
            return str(value).replace("\\", "/")

        def lowercase_drive(value: Path) -> str:
            text = slash(value)
            return text[0].lower() + text[1:]

        def mixed(value: Path) -> str:
            text = slash(value)
            return text[:3] + text[3:].replace("/", "\\")

        canonical_cases = self._run_core_cases(
            [
                {"kind": "canonical-host-path", "value": slash(self.archive)},
                {"kind": "canonical-host-path", "value": lowercase_drive(self.archive)},
                {"kind": "canonical-host-path", "value": mixed(self.archive)},
                {
                    "kind": "canonical-host-path",
                    "value": slash(self.archive) + ":stream",
                },
                {
                    "kind": "canonical-host-path",
                    "value": slash(self.archive.parent) + "/./" + self.archive.name,
                },
                {
                    "kind": "canonical-host-path",
                    "value": slash(self.archive.parent) + "//" + self.archive.name,
                },
            ]
        )
        self.assertEqual(canonical_cases[0]["value"], str(self.archive))
        self.assertEqual(canonical_cases[1]["value"], str(self.archive).lower()[0] + str(self.archive)[1:])
        self.assertEqual(canonical_cases[2]["value"], str(self.archive))
        for rejected in canonical_cases[3:]:
            self.assertFalse(rejected["ok"], rejected)
            self.assertEqual(rejected["phase"], "PATH_AUTHORITY")

        # SLASH01: verifier forward-slash archive and ordinary plan.
        self._assert_success(self._run_verifier(slash(self.archive)))
        self._mark_slash()

        # SLASH02: verifier ordinary archive and forward-slash plan.
        self._assert_success(
            self._run_verifier(self.archive, entry_plan=slash(self.entry_plan))
        )
        self._mark_slash()

        # SLASH03: verifier both paths with forward slashes.
        self._assert_success(
            self._run_verifier(
                slash(self.archive),
                entry_plan=slash(self.entry_plan),
            )
        )
        self._mark_slash()

        # SLASH04: writer forward-slash source tree.
        slash04 = self.temp_root / "slash04.zip"
        self._assert_success(
            self._run_writer(source_tree=slash(self.source_tree), output=slash04)
        )
        self._assert_success(self._run_verifier(slash04))
        self._mark_slash()

        # SLASH05: writer forward-slash entry plan.
        slash05 = self.temp_root / "slash05.zip"
        self._assert_success(
            self._run_writer(entry_plan=slash(self.entry_plan), output=slash05)
        )
        self._assert_success(self._run_verifier(slash05))
        self._mark_slash()

        # SLASH06: writer forward-slash output.
        slash06 = self.temp_root / "slash06.zip"
        self._assert_success(self._run_writer(output=slash(slash06)))
        self._assert_success(self._run_verifier(slash06))
        self._mark_slash()

        # SLASH07: lowercase drive with all writer paths using forward slashes.
        slash07 = self.temp_root / "slash07.zip"
        self._assert_success(
            self._run_writer(
                source_tree=lowercase_drive(self.source_tree),
                entry_plan=lowercase_drive(self.entry_plan),
                output=lowercase_drive(slash07),
            )
        )
        self._assert_success(
            self._run_verifier(
                lowercase_drive(slash07),
                entry_plan=lowercase_drive(self.entry_plan),
            )
        )
        self._mark_slash()

        # SLASH08: mixed separators that canonicalize without structural change.
        self._assert_success(
            self._run_verifier(
                mixed(self.archive),
                entry_plan=mixed(self.entry_plan),
            )
        )
        self._mark_slash()

        # SLASH09: forward-slash ADS archive remains rejected.
        self._assert_ads_failure(
            self._run_verifier(slash(self.archive) + ":slash09-stream"),
            "slash09-stream",
        )
        self._mark_slash()

        # SLASH10: forward-slash ADS plan remains rejected.
        self._assert_ads_failure(
            self._run_verifier(
                self.archive,
                entry_plan=slash(self.entry_plan) + ":slash10-stream",
            ),
            "slash10-stream",
        )
        self._mark_slash()

        # SLASH11: a forward-slash dot segment is not silently collapsed.
        dot_archive = slash(self.archive.parent) + "/./" + self.archive.name
        self._assert_failure(
            self._run_verifier(dot_archive),
            "PATH_AUTHORITY",
            "windows-host-path-normalized",
        )
        self._mark_slash()

        # SLASH12: repeated forward separators are not silently collapsed.
        repeated_archive = slash(self.archive.parent) + "//" + self.archive.name
        self._assert_failure(
            self._run_verifier(repeated_archive),
            "PATH_AUTHORITY",
            "windows-host-path-normalized",
        )
        self._mark_slash()
        self._cleanup_assert(
            self.sentinel.read_bytes() == b"unrelated-object\n"
        )

    def test_25_two_phase_failure_cleanup_complete_set(self) -> None:
        uncertain_actions = [
            "temporary-replace",
            "temporary-replace-same-size",
            "temporary-replace-truncate",
            "temporary-replace-growth",
            "final-replace",
            "temporary-reparse",
            "final-reparse",
            "hard-link-count",
            "parent-replace-before",
            "parent-replace-after",
        ]
        safe_actions = {
            "safe-prepublication-cleanup": 1,
            "safe-postpublication-cleanup": 2,
            "unexpected-sibling": 2,
            "verifier-failure-before-adoption": 1,
            "verifier-failure-after-adoption": 1,
        }
        actions = uncertain_actions + list(safe_actions)
        self.assertEqual(len(actions), EXPECTED_TWO_PHASE_CLEANUP_CASES)

        for index, action in enumerate(actions, start=1):
            with self.subTest(action=action):
                self._install_fixture(
                    [("dir/file.txt", "100644", b"stable-source\n")]
                )
                output_parent = self.temp_root / f"cleanup-control-{index:02d}"
                output_parent.mkdir()
                self.output = output_parent / "public-source.zip"
                expected_archive = _assemble_zip(self.plan, self.payloads)
                result = self._run_imported_writer(action)
                self.assertFalse(result["ok"], result)

                if action in uncertain_actions:
                    self.assertEqual(result["phase"], "CLEANUP")
                    self.assertEqual(
                        result["reason"],
                        "cleanup-identity-uncertain",
                    )
                    self._cleanup_assert(result["cleanupUnlinkCount"] == 0)

                    if action.startswith("temporary-replace"):
                        temporary_path = Path(result["hookPath"])
                        renamed = Path(result["renamedTemporary"])
                        replacement = base64.b64decode(result["replacementBytes"])
                        self._cleanup_assert(
                            self.output.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            temporary_path.read_bytes() == replacement
                        )
                        self._cleanup_assert(
                            renamed.read_bytes() == expected_archive
                        )
                    elif action == "temporary-reparse":
                        temporary_path = Path(result["hookPath"])
                        renamed = Path(result["renamedTemporary"])
                        self._cleanup_assert(temporary_path.is_symlink())
                        self._cleanup_assert(
                            renamed.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            self.output.read_bytes() == expected_archive
                        )
                    elif action == "final-replace":
                        renamed = Path(result["renamedFinal"])
                        replacement = base64.b64decode(result["replacementBytes"])
                        self._cleanup_assert(self.output.read_bytes() == replacement)
                        self._cleanup_assert(
                            renamed.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            Path(result["temporaryPath"]).read_bytes()
                            == expected_archive
                        )
                    elif action == "final-reparse":
                        renamed = Path(result["renamedFinal"])
                        self._cleanup_assert(self.output.is_symlink())
                        self._cleanup_assert(
                            renamed.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            Path(result["temporaryPath"]).read_bytes()
                            == expected_archive
                        )
                    elif action == "hard-link-count":
                        temporary_path = Path(result["hookPath"])
                        extra_link = Path(result["extraLink"])
                        self._cleanup_assert(
                            temporary_path.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            extra_link.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(
                            self.output.read_bytes() == expected_archive
                        )
                    else:
                        renamed_parent = Path(result["renamedParent"])
                        relocated_temporary = renamed_parent / Path(
                            result["hookPath"]
                        ).name
                        self._cleanup_assert(renamed_parent.is_dir())
                        self._cleanup_assert(
                            relocated_temporary.read_bytes() == expected_archive
                        )
                        self._cleanup_assert(not self.output.exists())
                        if action == "parent-replace-after":
                            relocated_final = renamed_parent / self.output.name
                            self._cleanup_assert(
                                relocated_final.read_bytes() == expected_archive
                            )
                else:
                    self.assertNotEqual(result["phase"], "CLEANUP")
                    self._cleanup_assert(
                        result["cleanupUnlinkCount"] == safe_actions[action]
                    )
                    self._cleanup_assert(not self.output.exists())
                    if result["hookPath"]:
                        self._cleanup_assert(not Path(result["hookPath"]).exists())
                    if action == "unexpected-sibling":
                        unexpected = output_parent / "unexpected-sibling.bin"
                        self._cleanup_assert(
                            unexpected.read_bytes() == b"unexpected\n"
                        )

                self._cleanup_assert(
                    self.sentinel.read_bytes() == b"unrelated-object\n"
                )
                self._mark_two_phase_cleanup()

    def test_26_temporary_substitution_stability_thirty_times(self) -> None:
        actions = [
            "temporary-replace",
            "temporary-replace-early",
            "temporary-replace-later",
            "temporary-replace-same-size",
            "temporary-replace-truncate",
            "temporary-replace-growth",
        ]
        durations: list[float] = []
        outcomes: list[tuple[str, str, int]] = []
        for iteration in range(EXPECTED_SUBSTITUTION_REPETITIONS):
            with self.subTest(iteration=iteration):
                self._install_fixture(
                    [("dir/file.txt", "100644", b"stable-source\n")]
                )
                output_parent = self.temp_root / f"substitution-{iteration:02d}"
                output_parent.mkdir()
                self.output = output_parent / "public-source.zip"
                expected_archive = _assemble_zip(self.plan, self.payloads)
                started = time.monotonic()
                result = self._run_imported_writer(
                    actions[iteration % len(actions)]
                )
                durations.append(time.monotonic() - started)
                outcome = (
                    result["phase"],
                    result["reason"],
                    result["cleanupUnlinkCount"],
                )
                outcomes.append(outcome)
                self.assertFalse(result["ok"], result)
                self.assertEqual(
                    outcome,
                    ("CLEANUP", "cleanup-identity-uncertain", 0),
                )
                temporary_path = Path(result["hookPath"])
                renamed_original = Path(result["renamedTemporary"])
                replacement = base64.b64decode(result["replacementBytes"])
                self._cleanup_assert(
                    self.output.read_bytes() == expected_archive
                )
                self._cleanup_assert(
                    temporary_path.read_bytes() == replacement
                )
                self._cleanup_assert(
                    renamed_original.read_bytes() == expected_archive
                )
                self._cleanup_assert(
                    self.sentinel.read_bytes() == b"unrelated-object\n"
                )
                self._mark_substitution()
        self.assertEqual(
            outcomes,
            [("CLEANUP", "cleanup-identity-uncertain", 0)]
            * EXPECTED_SUBSTITUTION_REPETITIONS,
        )
        print(
            "ZIP_SUBSTITUTION_STABILITY "
            f"count={len(durations)} "
            f"min={min(durations):.6f}s "
            f"max={max(durations):.6f}s "
            f"total={sum(durations):.6f}s",
            flush=True,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
