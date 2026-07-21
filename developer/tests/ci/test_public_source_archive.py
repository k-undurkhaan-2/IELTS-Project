#!/usr/bin/env python3
"""Synthetic security and format tests for the restricted public-source USTAR."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unicodedata
from collections.abc import Callable
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
CORE = REPO_ROOT / "developer/public-source-archive-core.mjs"
WRITER = REPO_ROOT / "developer/prepare-public-source-archive.mjs"
ARCHIVE_VERIFIER = REPO_ROOT / "developer/verify-public-source-archive.mjs"
B1_VERIFIER = REPO_ROOT / "developer/verify-public-source-membership.mjs"
B2_MATERIALIZER = REPO_ROOT / "developer/prepare-public-source-tree.mjs"
MANIFEST = REPO_ROOT / "developer/public-source-manifest.json"
MANIFEST_RELATIVE = "developer/public-source-manifest.json"
ARCHIVE_ROOT = "ieltmps-source/"
BLOCK_SIZE = 512
NAME_ONLY_BOUNDARY = "css/" + "n" * 77 + ".css"
SPLIT_BOUNDARY = "css/s/" + "p" * 96 + ".css"
UTF8_MEMBER = "css/路径/café.css"
GIT_REDIRECTION_NAMES = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_REPLACE_REF_BASE",
}


def _find_node() -> Path:
    configured = os.environ.get("IELTMPS_NODE")
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file():
            return candidate
        raise unittest.SkipTest("IELTMPS_NODE does not name a file")
    discovered = shutil.which("node")
    if discovered:
        return Path(discovered).resolve()
    raise unittest.SkipTest("node is unavailable")


def _find_git() -> Path:
    discovered = shutil.which("git")
    if discovered:
        return Path(discovered).resolve()
    raise unittest.SkipTest("git is unavailable")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _encode_octal_field(value: int, width: int) -> bytes:
    """Encode the canonical zero-padded ASCII-octal field used by USTAR."""
    if value < 0:
        raise ValueError("octal value must be nonnegative")
    encoded = format(value, "o")
    if len(encoded) > width - 1:
        raise ValueError("octal value does not fit")
    return encoded.rjust(width - 1, "0").encode("ascii") + b"\0"


def _calculate_header_checksum(header: bytes | bytearray) -> int:
    """Calculate the USTAR checksum with the checksum field treated as spaces."""
    if len(header) != BLOCK_SIZE:
        raise ValueError("USTAR headers are exactly one block")
    copy = bytearray(header)
    copy[148:156] = b" " * 8
    return sum(copy)


def _encode_checksum_field(value: int) -> bytes:
    encoded = format(value, "o")
    if len(encoded) > 6:
        raise ValueError("checksum does not fit")
    return encoded.rjust(6, "0").encode("ascii") + b"\0 "


def _rechecksum(header: bytearray) -> None:
    header[148:156] = _encode_checksum_field(
        _calculate_header_checksum(header)
    )


def _create_ustar_path_fields(archive_name: str) -> tuple[bytes, bytes]:
    """Independently split one UTF-8 archive path into USTAR name/prefix fields."""
    if not archive_name or "\0" in archive_name:
        raise ValueError("archive path is empty or contains NUL")
    full = archive_name.encode("utf-8")
    if len(full) <= 100:
        return full, b""

    separator = archive_name.rfind("/")
    while separator > 0:
        prefix = archive_name[:separator].encode("utf-8")
        name = archive_name[separator + 1 :].encode("utf-8")
        if prefix and name and len(prefix) <= 155 and len(name) <= 100:
            return name, prefix
        separator = archive_name.rfind("/", 0, separator)
    raise ValueError("archive path cannot be represented in USTAR")


def _create_ustar_header(archive_name: str, mode: int, size: int) -> bytes:
    """Create one canonical standard-library-only USTAR header."""
    if mode not in {0o644, 0o755} or size < 0:
        raise ValueError("unsupported canonical fixture metadata")
    name, prefix = _create_ustar_path_fields(archive_name)
    header = bytearray(BLOCK_SIZE)
    header[0 : len(name)] = name
    header[100:108] = _encode_octal_field(mode, 8)
    header[108:116] = _encode_octal_field(0, 8)
    header[116:124] = _encode_octal_field(0, 8)
    header[124:136] = _encode_octal_field(size, 12)
    header[136:148] = _encode_octal_field(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _encode_octal_field(0, 8)
    header[337:345] = _encode_octal_field(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    header[148:156] = _encode_checksum_field(
        _calculate_header_checksum(header)
    )
    return bytes(header)


def _assemble_ustar_archive(members: list[tuple[str, int, bytes]]) -> bytes:
    """Assemble canonical records followed by exactly two zero blocks."""
    records: list[bytes] = []
    for archive_name, mode, payload in members:
        if not isinstance(payload, bytes):
            raise TypeError("fixture payloads must be bytes")
        records.append(_create_ustar_header(archive_name, mode, len(payload)))
        records.append(payload)
        records.append(bytes((-len(payload)) % BLOCK_SIZE))
    records.append(bytes(2 * BLOCK_SIZE))
    return b"".join(records)


def _changed_byte_indexes(baseline: bytes, mutated: bytes) -> set[int]:
    if len(baseline) != len(mutated):
        raise ValueError("byte-difference isolation requires equal lengths")
    return {
        index
        for index, (left, right) in enumerate(zip(baseline, mutated, strict=True))
        if left != right
    }


def _portable_archive_key(value: str) -> str:
    """Independently model the documented portable archive identity key."""
    return unicodedata.normalize("NFC", value).casefold()


def _c_string(field: bytes) -> bytes:
    return field.split(b"\0", 1)[0]


def _parse_archive(value: bytes) -> tuple[list[dict[str, object]], int]:
    entries: list[dict[str, object]] = []
    offset = 0
    while True:
        if offset + BLOCK_SIZE > len(value):
            raise AssertionError("truncated header or terminator")
        header = value[offset : offset + BLOCK_SIZE]
        if header == bytes(BLOCK_SIZE):
            if value[offset : offset + 2 * BLOCK_SIZE] != bytes(2 * BLOCK_SIZE):
                raise AssertionError("missing canonical two-block terminator")
            if offset + 2 * BLOCK_SIZE != len(value):
                raise AssertionError("trailing archive bytes")
            return entries, offset
        if header[148:156] != f"{_calculate_header_checksum(header):06o}\0 ".encode("ascii"):
            raise AssertionError("noncanonical checksum")
        name = _c_string(header[0:100]).decode("utf-8")
        prefix = _c_string(header[345:500]).decode("utf-8")
        archive_name = f"{prefix}/{name}" if prefix else name
        size = int(header[124:135].decode("ascii"), 8)
        payload_offset = offset + BLOCK_SIZE
        payload_end = payload_offset + size
        padding = (-size) % BLOCK_SIZE
        record_end = payload_end + padding
        if record_end > len(value):
            raise AssertionError("truncated payload")
        entries.append(
            {
                "archive_name": archive_name,
                "name": name,
                "prefix": prefix,
                "mode": int(header[100:107].decode("ascii"), 8),
                "uid": int(header[108:115].decode("ascii"), 8),
                "gid": int(header[116:123].decode("ascii"), 8),
                "size": size,
                "mtime": int(header[136:147].decode("ascii"), 8),
                "typeflag": chr(header[156]),
                "uname": _c_string(header[265:297]),
                "gname": _c_string(header[297:329]),
                "devmajor": int(header[329:336].decode("ascii"), 8),
                "devminor": int(header[337:344].decode("ascii"), 8),
                "header_offset": offset,
                "payload_offset": payload_offset,
                "payload_end": payload_end,
                "padding": padding,
                "record_end": record_end,
                "header": header,
                "payload": value[payload_offset:payload_end],
                "padding_bytes": value[payload_end:record_end],
            }
        )
        offset = record_end


def _replace_header(
    archive: bytes,
    entry: dict[str, object],
    mutate: Callable[[bytearray], None],
    *,
    recalculate: bool = True,
) -> bytes:
    changed = bytearray(archive)
    header_offset = int(entry["header_offset"])
    header = bytearray(changed[header_offset : header_offset + BLOCK_SIZE])
    mutate(header)
    if recalculate:
        _rechecksum(header)
    changed[header_offset : header_offset + BLOCK_SIZE] = header
    return bytes(changed)


def _set_archive_name(header: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    if len(encoded) > 100:
        raise ValueError("test archive name is too long for the name field")
    header[0:100] = bytes(100)
    header[345:500] = bytes(155)
    header[0 : len(encoded)] = encoded


class PublicSourceArchiveTest(unittest.TestCase):
    """Every mutable repository, archive, alias and output lives under TEMP."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        cls.node = _find_node()
        cls.git = _find_git()
        required = [
            CORE,
            WRITER,
            ARCHIVE_VERIFIER,
            B1_VERIFIER,
            B2_MATERIALIZER,
            MANIFEST,
        ]
        if not all(item.is_file() for item in required):
            raise unittest.SkipTest("required archive, B1 or B2 source is unavailable")

        cls.manifest_bytes = MANIFEST.read_bytes()
        cls.manifest_value = json.loads(cls.manifest_bytes.decode("utf-8"))
        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-archive-template-"
        )
        cls.template_root = Path(cls.template_temp.name).resolve() / "fixture"
        cls.template_root.mkdir()

        cls.expected_bytes: dict[str, bytes] = {}
        exact_paths: set[str] = set()
        for component in cls.manifest_value["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            cls.expected_bytes[relative] = (
                cls.manifest_bytes
                if relative == MANIFEST_RELATIVE
                else f"placeholder:{relative}\n".encode("utf-8")
            )

        cls.expected_bytes.update(
            {
                "backend/admin/binary-nul.bin": b"prefix\x00middle\x00suffix\n",
                "backend/auth/empty.bin": b"",
                "backend/migrations/001_init.sql": b"SELECT 1;\n",
                "backend/scripts/executable.sh": b"#!/bin/sh\nprintf synthetic\n",
                "backend/src/non-utf8.bin": b"\x80\x81\xfe\xff\x00\n",
                "backend/test/trailing-newline.js": b"export const trailing = true;\n",
                "css/lf.css": b"body { color: black; }\n",
                "js/bom.js": b"\xef\xbb\xbfconst bom = true;\n",
                "js/crlf.js": b"const first = 1;\r\nconst second = 2;\r\n",
                "js/selected-code.mjs": (
                    b"import { writeFileSync } from 'node:fs';\n"
                    b"writeFileSync(process.env.IELTMPS_SELECTED_CODE_MARKER, 'executed');\n"
                ),
                "src/styles/app.css": b":root { --fixture: 1; }\n",
                NAME_ONLY_BOUNDARY: b"name-only boundary\n",
                SPLIT_BOUNDARY: b"split boundary\n",
                UTF8_MEMBER: b"utf8 path\n",
            }
        )
        for relative, value in cls.expected_bytes.items():
            cls._write_at(cls.template_root, relative, value)

        cls._git_at(cls.template_root, "init")
        for key, value in (
            ("user.name", "Public Source Archive Test"),
            ("user.email", "public-source-archive-test@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git_at(cls.template_root, "config", key, value)
        cls._git_at(cls.template_root, "add", "-A")
        cls._git_at(
            cls.template_root,
            "update-index",
            "--chmod=+x",
            "--",
            "backend/scripts/executable.sh",
        )
        cls._git_at(cls.template_root, "commit", "-m", "synthetic archive baseline")
        cls.template_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()
        cls.expected_modes = {
            relative: (
                0o755 if relative == "backend/scripts/executable.sh" else 0o644
            )
            for relative in cls.expected_bytes
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-archive-case-"
        )
        self.temp_root = Path(self.case_temp.name).resolve()
        self.fixture_root = self.temp_root / "fixture"
        shutil.copytree(self.template_root, self.fixture_root)
        self.base_commit = self._head()
        self.output_path = self.temp_root / "public-source.tar"
        self.second_output = self.temp_root / "public-source-second.tar"
        self.selected_code_marker = self.temp_root / "selected-code-executed"
        self.unrelated_sentinel = self.temp_root / "unrelated-sentinel.txt"
        self.unrelated_sentinel.write_bytes(b"unrelated sentinel\n")
        self.assertEqual(self.base_commit, self.template_commit)

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    @classmethod
    def _environment(cls) -> dict[str, str]:
        environment = os.environ.copy()
        for name in GIT_REDIRECTION_NAMES:
            environment.pop(name, None)
        path_parts = [str(cls.git.parent), str(cls.node.parent)]
        if environment.get("PATH"):
            path_parts.append(environment["PATH"])
        environment["PATH"] = os.pathsep.join(path_parts)
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        return environment

    @classmethod
    def _git_at(
        cls,
        root: Path,
        *args: str,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            [str(cls.git), "-C", str(root), *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=cls._environment(),
            timeout=30,
        )
        if completed.returncode != 0 and not allow_failure:
            raise AssertionError(completed.stdout.decode("utf-8", errors="replace"))
        return completed

    def _git(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self._git_at(
            self.fixture_root,
            *args,
            input_bytes=input_bytes,
            allow_failure=allow_failure,
        )

    @staticmethod
    def _write_at(root: Path, relative: str, value: str | bytes) -> None:
        target = root / PurePosixPath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            target.write_bytes(value)
        else:
            target.write_text(value, encoding="utf-8", newline="\n")

    def _write(self, relative: str, value: str | bytes) -> None:
        self._write_at(self.fixture_root, relative, value)

    def _head(self) -> str:
        return self._git("rev-parse", "HEAD").stdout.decode("ascii").strip()

    def _commit_paths(self, message: str, *paths: str) -> str:
        self._git("add", "--", *paths)
        self._git("commit", "-m", message)
        return self._head()

    def _run_writer(
        self,
        *,
        commit: str | None = None,
        output: Path | str | None = None,
        repo: Path | str | None = None,
        extra_args: list[str] | None = None,
        environment_updates: dict[str, str] | None = None,
        script: Path | str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(script or WRITER),
            "--repo",
            str(repo or self.fixture_root),
            "--commit",
            commit or self.base_commit,
            "--output",
            str(output or self.output_path),
        ]
        if extra_args:
            argv.extend(extra_args)
        environment = self._environment()
        environment["IELTMPS_SELECTED_CODE_MARKER"] = str(self.selected_code_marker)
        if environment_updates:
            environment.update(environment_updates)
        return subprocess.run(
            argv,
            cwd=cwd or self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    def _run_verifier(
        self,
        archive: Path | str | None = None,
        *,
        commit: str | None = None,
        repo: Path | str | None = None,
        extra_args: list[str] | None = None,
        script: Path | str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(script or ARCHIVE_VERIFIER),
            "--repo",
            str(repo or self.fixture_root),
            "--commit",
            commit or self.base_commit,
            "--archive",
            str(archive or self.output_path),
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
            timeout=120,
        )

    def _run_imported_writer(
        self,
        action: str,
        *,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_output = output or self.output_path
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_WRITER": str(WRITER),
                "IELTMPS_TEST_REPO": str(self.fixture_root),
                "IELTMPS_TEST_COMMIT": self.base_commit,
                "IELTMPS_TEST_OUTPUT": str(selected_output),
                "IELTMPS_TEST_ACTION": action,
                "IELTMPS_TEST_PROBE": str(self.temp_root / "file-handle-probe"),
            }
        )
        script = r"""
import { createHash } from "node:crypto";
import {
  linkSync,
  lstatSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const { preparePublicSourceArchive } = await import(
  pathToFileURL(process.env.IELTMPS_TEST_WRITER).href
);
const action = process.env.IELTMPS_TEST_ACTION;
const output = process.env.IELTMPS_TEST_OUTPUT;
const externalLink = output + "-external-hardlink";
const seen = [];
const collisions = [];
const temporaryPaths = [];
let acted = false;
let contextsFrozen = true;
let sentinelBefore = null;
let linkObservation = null;
let publishedObservation = null;
let linkCalls = 0;

function observePath(value) {
  try {
    const state = lstatSync(value, { bigint: true });
    const bytes = state.isFile() ? readFileSync(value) : Buffer.alloc(0);
    return {
      exists: true,
      device: state.dev.toString(),
      inode: state.ino.toString(),
      identityMeaningful: state.dev !== 0n || state.ino !== 0n,
      linkCount: Number(state.nlink),
      byteLength: Number(state.size),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return { exists: false };
    }
    throw error;
  }
}

const probe = await open(process.env.IELTMPS_TEST_PROBE, "w");
const fileHandlePrototype = Object.getPrototypeOf(probe);
await probe.close();
unlinkSync(process.env.IELTMPS_TEST_PROBE);
const original = {
  write: fileHandlePrototype.write,
  datasync: fileHandlePrototype.datasync,
  sync: fileHandlePrototype.sync,
  close: fileHandlePrototype.close,
};
let zeroWritten = false;
let closeFailed = false;
if (action === "partial-write") {
  fileHandlePrototype.write = function(buffer, offset, length, position) {
    return original.write.call(this, buffer, offset, Math.min(length, 7), position);
  };
} else if (action === "zero-write") {
  fileHandlePrototype.write = function(buffer, offset, length, position) {
    if (!zeroWritten) {
      zeroWritten = true;
      return Promise.resolve({ bytesWritten: 0, buffer });
    }
    return original.write.call(this, buffer, offset, length, position);
  };
} else if (action === "datasync-failure") {
  fileHandlePrototype.datasync = async function() {
    throw new Error("synthetic datasync failure");
  };
} else if (action === "sync-failure") {
  fileHandlePrototype.sync = async function() {
    throw new Error("synthetic sync failure");
  };
} else if (action === "close-failure") {
  fileHandlePrototype.close = function() {
    if (!closeFailed) {
      closeFailed = true;
      throw new Error("synthetic close failure");
    }
    return original.close.call(this);
  };
}

let testLink;
if (action === "link-unsupported") {
  testLink = async () => {
    linkCalls += 1;
    const error = new Error("synthetic unsupported hard-link canary");
    error.code = "EOPNOTSUPP";
    throw error;
  };
}

const hook = async (context) => {
  contextsFrozen = contextsFrozen && Object.isFrozen(context);
  seen.push(context.checkpoint);
  if (
    typeof context.temporaryPath === "string"
    && !temporaryPaths.includes(context.temporaryPath)
  ) {
    temporaryPaths.push(context.temporaryPath);
  }
  if (action === `throw:${context.checkpoint}`) {
    throw new Error("synthetic checkpoint failure with private canary");
  }
  if (
    action === "collision-once"
    && context.checkpoint === "before-temp-create-attempt"
    && context.attempt === 0
  ) {
    writeFileSync(context.temporaryPath, "collision sentinel\n");
    collisions.push(context.temporaryPath);
  } else if (
    action === "collision-exhaustion"
    && context.checkpoint === "before-temp-create-attempt"
  ) {
    writeFileSync(context.temporaryPath, `collision ${context.attempt}\n`);
    collisions.push(context.temporaryPath);
  } else if (
    action === "late-final-appears"
    && context.checkpoint === "after-final-absence-check"
  ) {
    writeFileSync(output, "late destination sentinel\n", { flag: "wx" });
    sentinelBefore = observePath(output);
    return Object.freeze({ ignoredDestinationOverride: context.temporaryPath });
  } else if (
    action === "observe-link-publication"
    && context.checkpoint === "after-link"
  ) {
    const temporaryBytes = readFileSync(context.temporaryPath);
    const finalBytes = readFileSync(context.outputPath);
    linkObservation = {
      temporary: observePath(context.temporaryPath),
      final: observePath(context.outputPath),
      bytesEqual: temporaryBytes.equals(finalBytes),
    };
  } else if (
    action === "observe-link-publication"
    && context.checkpoint === "after-publish"
  ) {
    publishedObservation = {
      temporary: observePath(temporaryPaths.at(-1)),
      final: observePath(context.outputPath),
    };
  } else if (
    action === "external-hardlink"
    && context.checkpoint === "after-link"
    && !acted
  ) {
    linkSync(context.outputPath, externalLink);
    acted = true;
  } else if (
    action === "corrupt-before-verify"
    && context.checkpoint === "before-verify"
    && !acted
  ) {
    const bytes = readFileSync(context.temporaryPath);
    bytes[512] ^= 0xff;
    writeFileSync(context.temporaryPath, bytes);
    acted = true;
  } else if (
    action === "temporary-identity"
    && context.checkpoint === "after-temp-create"
    && !acted
  ) {
    renameSync(context.temporaryPath, context.temporaryPath + "-original");
    writeFileSync(context.temporaryPath, "");
    acted = true;
  } else if (
    action === "post-publish-corruption"
    && context.checkpoint === "after-publish"
    && !acted
  ) {
    const bytes = readFileSync(context.outputPath);
    bytes[512] ^= 0xff;
    writeFileSync(context.outputPath, bytes);
    acted = true;
  } else if (
    action === "final-identity"
    && context.checkpoint === "after-publish"
    && !acted
  ) {
    const bytes = readFileSync(context.outputPath);
    renameSync(context.outputPath, context.outputPath + "-original");
    writeFileSync(context.outputPath, bytes);
    acted = true;
  }
};

let payload;
let returnCode = 0;
try {
  const summary = await preparePublicSourceArchive({
    repo: process.env.IELTMPS_TEST_REPO,
    commit: process.env.IELTMPS_TEST_COMMIT,
    output,
    testHooks: hook,
    testLink,
  });
  payload = { ok: true, summary, seen, collisions };
} catch (error) {
  payload = {
    ok: false,
    code: error.code,
    name: error.name,
    message: error.message,
    seen,
    collisions,
  };
  returnCode = 1;
} finally {
  fileHandlePrototype.write = original.write;
  fileHandlePrototype.datasync = original.datasync;
  fileHandlePrototype.sync = original.sync;
  fileHandlePrototype.close = original.close;
}
payload = {
  ...payload,
  contextsFrozen,
  temporaryPaths,
  temporaryObservationsAfter: temporaryPaths.map(observePath),
  sentinelBefore,
  sentinelAfter: sentinelBefore ? observePath(output) : null,
  linkObservation,
  publishedObservation,
  finalObservation: observePath(output),
  externalObservation: observePath(externalLink),
  linkCalls,
};
process.stdout.write(JSON.stringify(payload) + "\n");
process.exitCode = returnCode;
"""
        return subprocess.run(
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

    def _assert_success(
        self, result: subprocess.CompletedProcess[str]
    ) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.endswith("\n"), result.stdout)
        self.assertEqual(result.stdout.count("\n"), 1)
        return json.loads(result.stdout)

    def _assert_failure(
        self,
        result: subprocess.CompletedProcess[str],
        code: str | None = None,
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("ERROR "), result.stderr)
        self.assertEqual(result.stderr.count("\n"), 1, result.stderr)
        if code:
            self.assertTrue(result.stderr.startswith(f"ERROR {code}:"), result.stderr)
        self.assertNotIn("\n    at ", result.stderr)

    def _assert_archive_verification_failure(
        self,
        result: subprocess.CompletedProcess[str],
        archive_path: Path,
        expected_phase: str,
    ) -> None:
        messages = {
            "ARCHIVE_HEADER": "restricted USTAR header validation failed",
            "ARCHIVE_VERIFY": "independent archive verification failed",
        }
        self.assertIn(expected_phase, messages)
        self._assert_failure(result, expected_phase)
        self.assertEqual(
            result.stderr,
            f"ERROR {expected_phase}: {messages[expected_phase]}\n",
        )
        for forbidden_phase in ["CLI", "MEMBERSHIP", "OUTPUT_PARENT"]:
            self.assertNotIn(f"ERROR {forbidden_phase}:", result.stderr)
        for forbidden_path in [
            str(REPO_ROOT),
            str(self.fixture_root),
            str(self.temp_root),
            str(archive_path),
        ]:
            self.assertNotIn(forbidden_path, result.stderr)
        self.assertNotIn("placeholder:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("private canary", result.stderr)

    def _temp_siblings(self, output: Path | None = None) -> list[Path]:
        selected = output or self.output_path
        prefix = f".{selected.name}.ieltmps-source-archive-tmp-"
        return [
            item for item in selected.parent.iterdir() if item.name.startswith(prefix)
        ]

    def _valid_archive(self) -> tuple[bytes, list[dict[str, object]]]:
        self._assert_success(self._run_writer())
        value = self.output_path.read_bytes()
        entries, _ = _parse_archive(value)
        return value, entries

    def _independent_archive(self) -> tuple[bytes, list[dict[str, object]]]:
        members = [
            (
                ARCHIVE_ROOT + relative,
                self.expected_modes[relative],
                self.expected_bytes[relative],
            )
            for relative in sorted(self.expected_bytes)
        ]
        value = _assemble_ustar_archive(members)
        entries, _ = _parse_archive(value)
        return value, entries

    def test_01_valid_writer_verifier_and_exact_restricted_profile(self) -> None:
        writer = self._assert_success(self._run_writer())
        self.assertEqual(writer["status"], "ok")
        self.assertEqual(writer["mode"], "archive-creation")
        self.assertEqual(writer["sourceCommit"], self.base_commit)
        self.assertEqual(writer["manifestSha256"], _sha256(self.manifest_bytes))
        self.assertTrue(writer["membershipValid"])
        self.assertTrue(writer["treeMaterializerAvailable"])
        self.assertTrue(writer["archiveCreated"])
        self.assertTrue(writer["archiveVerified"])
        self.assertEqual(writer["archiveFormat"], "tar-ustar-v1")
        self.assertFalse(writer["correspondingSourceComplete"])
        self.assertTrue(writer["publicationBlocked"])
        self.assertEqual(self._temp_siblings(), [])

        verifier = self._assert_success(self._run_verifier())
        self.assertEqual(verifier["status"], "ok")
        self.assertEqual(verifier["mode"], "archive-verification")
        self.assertTrue(verifier["archiveVerified"])
        self.assertEqual(verifier["archiveSha256"], writer["archiveSha256"])
        self.assertEqual(verifier["archiveByteLength"], writer["archiveByteLength"])
        self.assertEqual(verifier["archiveMemberCount"], writer["archiveMemberCount"])

        archive = self.output_path.read_bytes()
        entries, end_offset = _parse_archive(archive)
        expected_paths = sorted(self.expected_bytes)
        self.assertEqual(
            [entry["archive_name"] for entry in entries],
            [ARCHIVE_ROOT + relative for relative in expected_paths],
        )
        self.assertEqual(writer["archiveMemberCount"], len(expected_paths))
        self.assertEqual(writer["archiveByteLength"], len(archive))
        self.assertEqual(writer["archiveSha256"], _sha256(archive))
        self.assertEqual(archive[end_offset:], bytes(2 * BLOCK_SIZE))
        for relative, entry in zip(expected_paths, entries, strict=True):
            with self.subTest(relative=relative):
                self.assertEqual(entry["typeflag"], "0")
                self.assertFalse(str(entry["archive_name"]).endswith("/"))
                self.assertEqual(entry["payload"], self.expected_bytes[relative])
                self.assertEqual(entry["mode"], self.expected_modes[relative])
                self.assertEqual(entry["uid"], 0)
                self.assertEqual(entry["gid"], 0)
                self.assertEqual(entry["mtime"], 0)
                self.assertEqual(entry["devmajor"], 0)
                self.assertEqual(entry["devminor"], 0)
                self.assertEqual(entry["uname"], b"")
                self.assertEqual(entry["gname"], b"")
                self.assertEqual(entry["padding_bytes"], bytes(int(entry["padding"])))

    def test_02_exact_payload_variants_and_git_modes_are_preserved(self) -> None:
        archive, entries = self._valid_archive()
        members = {
            str(entry["archive_name"])[len(ARCHIVE_ROOT) :]: entry
            for entry in entries
        }
        checks = {
            "backend/admin/binary-nul.bin": b"prefix\x00middle\x00suffix\n",
            "backend/auth/empty.bin": b"",
            "backend/src/non-utf8.bin": b"\x80\x81\xfe\xff\x00\n",
            "css/lf.css": b"body { color: black; }\n",
            "js/crlf.js": b"const first = 1;\r\nconst second = 2;\r\n",
            "js/bom.js": b"\xef\xbb\xbfconst bom = true;\n",
            "backend/test/trailing-newline.js": b"export const trailing = true;\n",
        }
        for relative, expected in checks.items():
            with self.subTest(relative=relative):
                self.assertEqual(members[relative]["payload"], expected)
        self.assertEqual(members["backend/scripts/executable.sh"]["mode"], 0o755)
        self.assertEqual(members["index.html"]["mode"], 0o644)
        self.assertNotIn(b"PaxHeaders", archive)

    def test_03_utf8_ustar_boundaries_and_same_host_determinism(self) -> None:
        first = self._assert_success(self._run_writer())
        second = self._assert_success(self._run_writer(output=self.second_output))
        self.assertEqual(first, second)
        self.assertEqual(self.output_path.read_bytes(), self.second_output.read_bytes())
        entries, _ = _parse_archive(self.output_path.read_bytes())
        members = {
            str(entry["archive_name"])[len(ARCHIVE_ROOT) :]: entry
            for entry in entries
        }
        name_only = members[NAME_ONLY_BOUNDARY]
        self.assertEqual(len((ARCHIVE_ROOT + NAME_ONLY_BOUNDARY).encode()), 100)
        self.assertEqual(name_only["prefix"], "")
        self.assertEqual(name_only["name"], ARCHIVE_ROOT + NAME_ONLY_BOUNDARY)
        split = members[SPLIT_BOUNDARY]
        self.assertTrue(split["prefix"])
        self.assertEqual(len(str(split["name"]).encode()), 100)
        self.assertEqual(
            f"{split['prefix']}/{split['name']}", ARCHIVE_ROOT + SPLIT_BOUNDARY
        )
        self.assertEqual(members[UTF8_MEMBER]["payload"], b"utf8 path\n")

    def test_04_b1_blobs_ignore_dirty_worktree_and_selected_code(self) -> None:
        first = self._assert_success(self._run_writer())
        first_bytes = self.output_path.read_bytes()
        self._write("index.html", b"dirty selected bytes\x00\xff\r\n")
        (self.fixture_root / MANIFEST_RELATIVE).write_text(
            '{"dirty":"manifest"}\n', encoding="utf-8", newline="\n"
        )
        second = self._assert_success(self._run_writer(output=self.second_output))
        self.assertEqual(first, second)
        self.assertEqual(first_bytes, self.second_output.read_bytes())
        self.assertFalse(self.selected_code_marker.exists())

    def test_05_untracked_manifest_cannot_replace_missing_commit_manifest(self) -> None:
        self._git("rm", "--cached", "--", MANIFEST_RELATIVE)
        self._git("commit", "-m", "manifest absent")
        result = self._run_writer(commit=self._head())
        self._assert_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_06_replacements_and_hostile_git_environment_are_ignored(self) -> None:
        baseline = self._assert_success(self._run_writer())
        baseline_bytes = self.output_path.read_bytes()
        self._write("index.html", b"replacement bytes\n")
        replacement = self._commit_paths("replacement", "index.html")
        self._git("replace", self.base_commit, replacement)
        replaced = self._assert_success(
            self._run_writer(commit=self.base_commit, output=self.second_output)
        )
        self.assertEqual(baseline, replaced)
        self.assertEqual(baseline_bytes, self.second_output.read_bytes())
        hostile_root = self.temp_root / "hostile-git"
        hostile_output = self.temp_root / "hostile.tar"
        hostile = {
            "GIT_DIR": str(hostile_root / "dir"),
            "GIT_WORK_TREE": str(hostile_root / "worktree"),
            "GIT_INDEX_FILE": str(hostile_root / "index"),
            "GIT_OBJECT_DIRECTORY": str(hostile_root / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(hostile_root / "alternate"),
            "GIT_REPLACE_REF_BASE": "refs/replace-hostile/",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(hostile_root / "hooks"),
        }
        hostile_summary = self._assert_success(
            self._run_writer(
                commit=self.base_commit,
                output=hostile_output,
                environment_updates=hostile,
            )
        )
        self.assertEqual(baseline, hostile_summary)
        self.assertEqual(baseline_bytes, hostile_output.read_bytes())
        self.assertFalse(hostile_root.exists())

    def test_07_production_path_uses_b1_not_b2_or_child_process(self) -> None:
        core_source = CORE.read_text(encoding="utf-8")
        writer_source = WRITER.read_text(encoding="utf-8")
        verifier_source = ARCHIVE_VERIFIER.read_text(encoding="utf-8")
        self.assertNotIn("node:child_process", core_source)
        self.assertNotIn("public-source-manifest.json", core_source)
        self.assertNotIn("node:child_process", writer_source)
        self.assertNotIn("node:child_process", verifier_source)
        self.assertNotIn("prepare-public-source-tree", writer_source)
        self.assertNotIn("prepare-public-source-tree", verifier_source)
        self.assertIn("loadValidatedPublicSourceMembership", writer_source)
        self.assertIn("loadValidatedPublicSourceMembership", verifier_source)
        self.assertIn("verifyPublicSourceArchive", writer_source)

    def test_08_output_boundaries_existing_and_privacy(self) -> None:
        sibling_parent = self.temp_root / "fixture-other"
        sibling_parent.mkdir()
        cases: list[Path | str] = [
            "relative-private-canary.tar",
            self.fixture_root,
            self.fixture_root / "inside.tar",
            self.temp_root / "archive.TAR",
            self.temp_root / "missing" / "archive.tar",
            self.temp_root / "CON.tar",
        ]
        for output in cases:
            with self.subTest(output=str(output)):
                result = self._run_writer(output=output)
                self._assert_failure(result, "OUTPUT_PARENT")
                for canary in [str(self.fixture_root), str(output), str(self.temp_root)]:
                    self.assertNotIn(canary, result.stderr)
        accepted = sibling_parent / "accepted.tar"
        self._assert_success(self._run_writer(output=accepted))
        self.assertTrue(accepted.is_file())
        existing = self.temp_root / "existing.tar"
        existing.write_bytes(b"do not overwrite\n")
        self._assert_failure(self._run_writer(output=existing), "OUTPUT_PARENT")
        self.assertEqual(existing.read_bytes(), b"do not overwrite\n")

    def test_09_reparse_output_parent_and_repository_alias_are_rejected(self) -> None:
        def make_alias(alias: Path, target: Path) -> None:
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError:
                if os.name != "nt":
                    raise
                completed = subprocess.run(
                    ["cmd", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout)

        real_parent = self.temp_root / "real-parent"
        real_parent.mkdir()
        linked_parent = self.temp_root / "linked-parent"
        make_alias(linked_parent, real_parent)
        try:
            self._assert_failure(
                self._run_writer(output=linked_parent / "archive.tar"),
                "OUTPUT_PARENT",
            )
            self.assertEqual(list(real_parent.iterdir()), [])
        finally:
            os.rmdir(linked_parent) if os.name == "nt" else linked_parent.unlink()

        repository_alias = self.temp_root / "repository-alias"
        make_alias(repository_alias, self.fixture_root)
        try:
            self._assert_failure(
                self._run_writer(output=repository_alias / "archive.tar"),
                "OUTPUT_PARENT",
            )
            self.assertFalse((self.fixture_root / "archive.tar").exists())
        finally:
            os.rmdir(repository_alias) if os.name == "nt" else repository_alias.unlink()

    def test_10_final_appearance_and_temporary_collision_behavior(self) -> None:
        unrelated_before = self.unrelated_sentinel.stat()
        appeared = self._run_imported_writer("late-final-appears")
        self.assertEqual(appeared.stderr, "")
        appeared_payload = json.loads(appeared.stdout)
        self.assertNotEqual(appeared.returncode, 0)
        self.assertFalse(appeared_payload["ok"])
        self.assertNotIn("summary", appeared_payload)
        self.assertEqual(appeared_payload["code"], "PUBLISH")
        self.assertEqual(
            appeared_payload["message"],
            "same-parent archive publication failed",
        )
        self.assertIn("after-final-absence-check", appeared_payload["seen"])
        self.assertTrue(appeared_payload["contextsFrozen"])
        self.assertEqual(
            self.output_path.read_bytes(), b"late destination sentinel\n"
        )
        self.assertEqual(
            appeared_payload["sentinelBefore"],
            appeared_payload["sentinelAfter"],
        )
        self.assertTrue(appeared_payload["sentinelAfter"]["exists"])
        self.assertEqual(appeared_payload["sentinelAfter"]["linkCount"], 1)
        self.assertTrue(
            all(
                not observation["exists"]
                for observation in appeared_payload["temporaryObservationsAfter"]
            )
        )
        self.assertEqual(self._temp_siblings(), [])
        unrelated_after = self.unrelated_sentinel.stat()
        self.assertEqual(
            (unrelated_after.st_dev, unrelated_after.st_ino),
            (unrelated_before.st_dev, unrelated_before.st_ino),
        )
        self.assertEqual(
            self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n"
        )
        self.assertNotIn(str(self.fixture_root), appeared_payload["message"])
        self.assertNotIn(str(self.temp_root), appeared_payload["message"])

        retry_output = self.temp_root / "collision-retry.tar"
        retry = self._run_imported_writer("collision-once", output=retry_output)
        retry_payload = json.loads(retry.stdout)
        self.assertEqual(retry.returncode, 0, retry_payload)
        self.assertEqual(len(retry_payload["collisions"]), 1)
        self.assertEqual(
            Path(retry_payload["collisions"][0]).read_bytes(),
            b"collision sentinel\n",
        )

        exhausted_output = self.temp_root / "collision-exhausted.tar"
        exhausted = self._run_imported_writer(
            "collision-exhaustion", output=exhausted_output
        )
        exhausted_payload = json.loads(exhausted.stdout)
        self.assertNotEqual(exhausted.returncode, 0)
        self.assertEqual(exhausted_payload["code"], "TEMP_CREATE")
        self.assertEqual(len(exhausted_payload["collisions"]), 8)
        self.assertFalse(exhausted_output.exists())
        for collision in exhausted_payload["collisions"]:
            self.assertTrue(Path(collision).is_file())

    def test_11_hard_link_publication_is_complete_and_no_replace(self) -> None:
        result = self._run_imported_writer("observe-link-publication")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["contextsFrozen"])
        summary = payload["summary"]
        self.assertTrue(summary["archiveCreated"])
        self.assertTrue(summary["archiveVerified"])
        self.assertFalse(summary["correspondingSourceComplete"])
        self.assertTrue(summary["publicationBlocked"])

        linked = payload["linkObservation"]
        self.assertIsNotNone(linked)
        self.assertTrue(linked["bytesEqual"])
        self.assertTrue(linked["temporary"]["exists"])
        self.assertTrue(linked["final"]["exists"])
        self.assertEqual(linked["temporary"]["linkCount"], 2)
        self.assertEqual(linked["final"]["linkCount"], 2)
        self.assertEqual(
            (linked["temporary"]["device"], linked["temporary"]["inode"]),
            (linked["final"]["device"], linked["final"]["inode"]),
        )
        self.assertEqual(
            linked["temporary"]["sha256"], summary["archiveSha256"]
        )
        self.assertEqual(linked["final"]["sha256"], summary["archiveSha256"])
        self.assertEqual(
            linked["final"]["byteLength"], summary["archiveByteLength"]
        )

        published = payload["publishedObservation"]
        self.assertIsNotNone(published)
        self.assertFalse(published["temporary"]["exists"])
        self.assertTrue(published["final"]["exists"])
        self.assertEqual(published["final"]["linkCount"], 1)
        self.assertEqual(published["final"]["sha256"], summary["archiveSha256"])
        self.assertTrue(
            all(
                not observation["exists"]
                for observation in payload["temporaryObservationsAfter"]
            )
        )
        self.assertEqual(self.output_path.stat().st_nlink, 1)
        self.assertEqual(self._temp_siblings(), [])

        verified = self._assert_success(self._run_verifier())
        self.assertEqual(verified["archiveSha256"], summary["archiveSha256"])
        self.assertEqual(
            verified["archiveByteLength"], summary["archiveByteLength"]
        )
        writer_source = WRITER.read_text(encoding="utf-8")
        self.assertIn(
            "await publicationLink(temporary.path, outputBoundary.targetPath);",
            writer_source,
        )
        self.assertNotIn("rename", writer_source.lower())
        self.assertNotIn("copyfile", writer_source.lower())
        self.assertNotIn("createreadstream", writer_source.lower())
        self.assertNotIn("createwritestream", writer_source.lower())
        serialized = json.dumps(summary, separators=(",", ":"))
        self.assertNotIn("hard-link", serialized)
        self.assertNotIn(str(self.output_path), serialized)
        for temporary_path in payload["temporaryPaths"]:
            self.assertNotIn(temporary_path, serialized)

    def test_12_unsupported_and_external_hard_links_fail_closed(self) -> None:
        unsupported_output = self.temp_root / "unsupported-link.tar"
        unsupported = self._run_imported_writer(
            "link-unsupported", output=unsupported_output
        )
        self.assertEqual(unsupported.stderr, "")
        unsupported_payload = json.loads(unsupported.stdout)
        self.assertNotEqual(unsupported.returncode, 0)
        self.assertFalse(unsupported_payload["ok"])
        self.assertNotIn("summary", unsupported_payload)
        self.assertEqual(unsupported_payload["code"], "PUBLISH")
        self.assertEqual(unsupported_payload["linkCalls"], 1)
        self.assertFalse(unsupported_payload["finalObservation"]["exists"])
        self.assertTrue(
            all(
                not observation["exists"]
                for observation in unsupported_payload[
                    "temporaryObservationsAfter"
                ]
            )
        )
        self.assertEqual(self._temp_siblings(unsupported_output), [])
        self.assertEqual(
            unsupported_payload["message"],
            "same-parent archive publication failed",
        )
        self.assertNotIn("unsupported hard-link canary", unsupported_payload["message"])

        external_output = self.temp_root / "external-link.tar"
        external = self._run_imported_writer(
            "external-hardlink", output=external_output
        )
        self.assertEqual(external.stderr, "")
        external_payload = json.loads(external.stdout)
        self.assertNotEqual(external.returncode, 0)
        self.assertFalse(external_payload["ok"])
        self.assertEqual(external_payload["code"], "PUBLISH")
        self.assertFalse(external_payload["finalObservation"]["exists"])
        self.assertTrue(
            all(
                not observation["exists"]
                for observation in external_payload["temporaryObservationsAfter"]
            )
        )
        external_path = Path(str(external_output) + "-external-hardlink")
        self.assertTrue(external_path.is_file())
        self.assertTrue(external_payload["externalObservation"]["exists"])
        self.assertEqual(external_payload["externalObservation"]["linkCount"], 1)
        try:
            self._assert_success(self._run_verifier(external_path))
        finally:
            external_path.unlink()
        self.assertFalse(external_path.exists())
        self.assertEqual(self._temp_siblings(external_output), [])

    def test_13_independent_python_canonical_archive_is_accepted(self) -> None:
        self.assertFalse(self.output_path.exists())
        valid, entries = self._independent_archive()
        expected_paths = sorted(self.expected_bytes)
        self.assertEqual(
            [entry["archive_name"] for entry in entries],
            [ARCHIVE_ROOT + relative for relative in expected_paths],
        )
        self.assertEqual(
            [entry["payload"] for entry in entries],
            [self.expected_bytes[relative] for relative in expected_paths],
        )
        self.assertEqual(
            [entry["mode"] for entry in entries],
            [self.expected_modes[relative] for relative in expected_paths],
        )
        for relative, entry in zip(expected_paths, entries, strict=True):
            with self.subTest(canonical_header=relative):
                header = bytes(entry["header"])
                name, prefix = _create_ustar_path_fields(ARCHIVE_ROOT + relative)
                self.assertEqual(_c_string(header[0:100]), name)
                self.assertEqual(_c_string(header[345:500]), prefix)
                self.assertEqual(
                    header[100:108],
                    _encode_octal_field(self.expected_modes[relative], 8),
                )
                self.assertEqual(
                    header[124:136],
                    _encode_octal_field(len(self.expected_bytes[relative]), 12),
                )
                self.assertEqual(header[257:263], b"ustar\0")
                self.assertEqual(header[263:265], b"00")
                self.assertEqual(header[156:157], b"0")
                self.assertEqual(
                    header[148:156],
                    _encode_checksum_field(_calculate_header_checksum(header)),
                )
        _, end_offset = _parse_archive(valid)
        self.assertEqual(valid[end_offset:], bytes(2 * BLOCK_SIZE))
        self.assertEqual(len(valid) - end_offset, 2 * BLOCK_SIZE)

        archive_path = self.temp_root / "independent-canonical.tar"
        archive_path.write_bytes(valid)
        try:
            verified = self._assert_success(self._run_verifier(archive_path))
            self.assertTrue(verified["archiveVerified"])
            self.assertFalse(verified["correspondingSourceComplete"])
            self.assertTrue(verified["publicationBlocked"])
            self.assertEqual(verified["archiveSha256"], _sha256(valid))
            self.assertEqual(verified["archiveByteLength"], len(valid))
            self.assertEqual(verified["archiveMemberCount"], len(expected_paths))
        finally:
            archive_path.unlink()
        self.assertFalse(archive_path.exists())
        self.assertFalse(self.output_path.exists())

    def test_14_independently_malformed_archives_are_all_rejected(self) -> None:
        valid, entries = self._independent_archive()
        records = [
            valid[int(entry["header_offset"]) : int(entry["record_end"])]
            for entry in entries
        ]
        body = b"".join(records)
        terminators = bytes(2 * BLOCK_SIZE)
        self.assertEqual(valid, body + terminators)
        first = entries[0]
        first_header = bytes(first["header"])
        cases: dict[str, tuple[bytes, str]] = {}

        def add_case(label: str, malformed: bytes, expected_phase: str) -> None:
            self.assertNotIn(label, cases)
            self.assertIn(expected_phase, {"ARCHIVE_HEADER", "ARCHIVE_VERIFY"})
            cases[label] = (malformed, expected_phase)

        def replace_first_field(
            start: int,
            end: int,
            raw: bytes,
            *,
            recalculate: bool = True,
        ) -> bytes:
            self.assertEqual(len(raw), end - start)
            return _replace_header(
                valid,
                first,
                lambda header: header.__setitem__(slice(start, end), raw),
                recalculate=recalculate,
            )

        def assert_header_isolation(
            malformed: bytes,
            entry: dict[str, object],
            *allowed_ranges: tuple[int, int],
        ) -> bytes:
            self.assertEqual(len(malformed), len(valid))
            header_offset = int(entry["header_offset"])
            normalized = bytearray(malformed)
            normalized[header_offset + 148 : header_offset + 156] = valid[
                header_offset + 148 : header_offset + 156
            ]
            changes = _changed_byte_indexes(valid, bytes(normalized))
            allowed = {
                header_offset + index
                for start, end in allowed_ranges
                for index in range(start, end)
            }
            self.assertTrue(changes)
            self.assertLessEqual(changes, allowed)
            header = malformed[header_offset : header_offset + BLOCK_SIZE]
            self.assertEqual(
                header[148:156],
                _encode_checksum_field(_calculate_header_checksum(header)),
            )
            return header

        def assert_checksum_only(malformed: bytes) -> bytes:
            self.assertEqual(len(malformed), len(valid))
            changes = _changed_byte_indexes(valid, malformed)
            header_offset = int(first["header_offset"])
            self.assertTrue(changes)
            self.assertLessEqual(
                changes,
                set(range(header_offset + 148, header_offset + 156)),
            )
            return malformed[header_offset : header_offset + BLOCK_SIZE]

        canonical_checksum = first_header[148:156]
        wrong_checksum = bytearray(canonical_checksum)
        wrong_checksum[0] = ord("1") if wrong_checksum[0] != ord("1") else ord("2")
        malformed = replace_first_field(
            148, 156, bytes(wrong_checksum), recalculate=False
        )
        header = assert_checksum_only(malformed)
        self.assertNotEqual(
            int(header[148:156].rstrip(b"\0 "), 8),
            _calculate_header_checksum(header),
        )
        add_case("bad-checksum", malformed, "ARCHIVE_HEADER")

        calculated_checksum = _calculate_header_checksum(first_header)
        equivalent_checksum = (
            b" " + f"{calculated_checksum:06o}".encode("ascii") + b"\0"
        )
        self.assertEqual(len(equivalent_checksum), 8)
        malformed = replace_first_field(
            148, 156, equivalent_checksum, recalculate=False
        )
        header = assert_checksum_only(malformed)
        self.assertEqual(
            int(header[148:156].strip(b"\0 "), 8), calculated_checksum
        )
        self.assertEqual(_calculate_header_checksum(header), calculated_checksum)
        self.assertNotEqual(header[148:156], canonical_checksum)
        self.assertNotEqual(
            header[148:156],
            _encode_checksum_field(_calculate_header_checksum(header)),
        )
        add_case(
            "equivalent-noncanonical-checksum", malformed, "ARCHIVE_HEADER"
        )

        base256_size = bytearray(first_header[124:136])
        base256_size[0] |= 0x80
        malformed = replace_first_field(124, 136, bytes(base256_size))
        header = assert_header_isolation(malformed, first, (124, 136))
        self.assertNotEqual(header[124] & 0x80, 0)
        self.assertFalse(
            all(byte in b"01234567" for byte in header[124:135])
            and header[135] == 0
        )
        add_case("base256-size", malformed, "ARCHIVE_HEADER")

        noncanonical_size = b" " + first_header[125:136]
        malformed = replace_first_field(124, 136, noncanonical_size)
        header = assert_header_isolation(malformed, first, (124, 136))
        self.assertEqual(
            int(header[124:136].strip(b"\0 "), 8), int(first["size"])
        )
        self.assertNotEqual(
            header[124:136], _encode_octal_field(int(first["size"]), 12)
        )
        add_case("noncanonical-octal", malformed, "ARCHIVE_HEADER")

        header_field_cases = [
            ("wrong-magic", 257, 263, b"broken"),
            ("wrong-version", 263, 265, b"01"),
            ("nonzero-reserved", 500, 512, b"\x01" + bytes(11)),
            ("nonzero-uname", 265, 297, b"u" + bytes(31)),
            ("nonzero-gname", 297, 329, b"g" + bytes(31)),
            ("nonzero-uid", 108, 116, _encode_octal_field(1, 8)),
            ("nonzero-gid", 116, 124, _encode_octal_field(1, 8)),
            ("nonzero-mtime", 136, 148, _encode_octal_field(1, 12)),
            ("nonzero-devmajor", 329, 337, _encode_octal_field(1, 8)),
            ("nonzero-devminor", 337, 345, _encode_octal_field(1, 8)),
        ]
        for label, start, end, raw in header_field_cases:
            malformed = replace_first_field(start, end, raw)
            header = assert_header_isolation(malformed, first, (start, end))
            self.assertEqual(header[start:end], raw)
            if label == "wrong-magic":
                self.assertNotEqual(header[257:263], b"ustar\0")
            elif label == "wrong-version":
                self.assertNotEqual(header[263:265], b"00")
            else:
                self.assertTrue(any(header[start:end]))
            add_case(label, malformed, "ARCHIVE_HEADER")

        expected_mode = int(first["mode"])
        wrong_mode = 0o755 if expected_mode != 0o755 else 0o644
        malformed = replace_first_field(
            100, 108, _encode_octal_field(wrong_mode, 8)
        )
        header = assert_header_isolation(malformed, first, (100, 108))
        self.assertEqual(int(header[100:107], 8), wrong_mode)
        self.assertNotEqual(wrong_mode, expected_mode)
        add_case("wrong-mode", malformed, "ARCHIVE_HEADER")

        for label, typeflag in {
            "wrong-typeflag": b"9",
            "symlink": b"2",
            "hardlink": b"1",
            "directory": b"5",
            "fifo": b"6",
            "char-device": b"3",
            "block-device": b"4",
            "pax": b"x",
            "gnu-long-name": b"L",
        }.items():
            malformed = replace_first_field(156, 157, typeflag)
            header = assert_header_isolation(malformed, first, (156, 157))
            self.assertEqual(header[156:157], typeflag)
            self.assertNotEqual(header[156:157], b"0")
            add_case(label, malformed, "ARCHIVE_HEADER")

        duplicate = records[0] + records[0] + b"".join(records[2:]) + terminators
        duplicate_entries, _ = _parse_archive(duplicate)
        self.assertEqual(
            duplicate_entries[0]["archive_name"],
            duplicate_entries[1]["archive_name"],
        )
        self.assertEqual(duplicate, records[0] + records[0] + b"".join(records[2:]) + terminators)
        add_case("duplicate-member", duplicate, "ARCHIVE_HEADER")

        out_of_order = records[1] + records[0] + b"".join(records[2:]) + terminators
        out_entries, _ = _parse_archive(out_of_order)
        out_names = [str(entry["archive_name"]) for entry in out_entries]
        self.assertNotEqual(out_names, sorted(out_names))
        self.assertEqual(out_names[:2], [str(entries[1]["archive_name"]), str(entries[0]["archive_name"])])
        add_case("out-of-order-member", out_of_order, "ARCHIVE_HEADER")

        missing = b"".join(records[:-1]) + terminators
        missing_entries, _ = _parse_archive(missing)
        self.assertEqual(len(missing_entries), len(entries) - 1)
        self.assertEqual(missing, b"".join(records[:-1]) + terminators)
        add_case("missing-member", missing, "ARCHIVE_HEADER")

        extra = body + records[0] + terminators
        extra_entries, _ = _parse_archive(extra)
        self.assertEqual(len(extra_entries), len(entries) + 1)
        self.assertEqual(extra_entries[-1]["archive_name"], entries[0]["archive_name"])
        add_case("extra-member", extra, "ARCHIVE_VERIFY")

        def path_case(
            label: str,
            archive_name: str,
            predicate: Callable[[str], bool],
        ) -> None:
            malformed_path = _replace_header(
                valid,
                first,
                lambda header: _set_archive_name(header, archive_name),
            )
            header = assert_header_isolation(
                malformed_path, first, (0, 100), (345, 500)
            )
            observed_name = _c_string(header[0:100]).decode("utf-8")
            observed_prefix = _c_string(header[345:500]).decode("utf-8")
            observed = (
                f"{observed_prefix}/{observed_name}"
                if observed_prefix
                else observed_name
            )
            self.assertEqual(observed, archive_name)
            self.assertTrue(predicate(observed))
            add_case(label, malformed_path, "ARCHIVE_HEADER")

        path_case(
            "wrong-fixed-root",
            "other-root/member",
            lambda value: not value.startswith(ARCHIVE_ROOT),
        )
        path_case(
            "traversal",
            "ieltmps-source/../escape",
            lambda value: "/../" in value,
        )
        path_case("absolute-path", "/absolute", lambda value: value.startswith("/"))
        path_case(
            "backslash-path",
            "ieltmps-source/bad\\name",
            lambda value: "\\" in value,
        )
        path_case(
            "ads-colon-path",
            "ieltmps-source/name:stream",
            lambda value: ":" in value,
        )

        first_name = str(first["archive_name"])
        first_suffix = first_name[len(ARCHIVE_ROOT) :]
        case_character_index = next(
            index
            for index, character in enumerate(first_suffix)
            if character.isascii() and character.isalpha()
        )
        toggled_character = (
            first_suffix[case_character_index].upper()
            if first_suffix[case_character_index].islower()
            else first_suffix[case_character_index].lower()
        )
        case_suffix = (
            first_suffix[:case_character_index]
            + toggled_character
            + first_suffix[case_character_index + 1 :]
        )
        case_variant = ARCHIVE_ROOT + case_suffix
        self.assertNotEqual(case_variant, first_name)
        self.assertTrue(first_name.startswith(ARCHIVE_ROOT))
        self.assertTrue(case_variant.startswith(ARCHIVE_ROOT))
        self.assertEqual(
            first_name[: len(ARCHIVE_ROOT)],
            case_variant[: len(ARCHIVE_ROOT)],
        )
        self.assertNotEqual(case_suffix, first_suffix)
        self.assertEqual(
            _changed_byte_indexes(
                first_suffix.encode("utf-8"),
                case_suffix.encode("utf-8"),
            ),
            {case_character_index},
        )
        self.assertEqual(
            len(first_name.encode("utf-8")),
            len(case_variant.encode("utf-8")),
        )
        self.assertEqual(
            _portable_archive_key(first_name),
            _portable_archive_key(case_variant),
        )

        def assert_valid_portable_member_path(value: str) -> None:
            encoded = value.encode("utf-8")
            self.assertEqual(encoded.decode("utf-8"), value)
            self.assertTrue(value.startswith(ARCHIVE_ROOT))
            suffix = value[len(ARCHIVE_ROOT) :]
            self.assertTrue(suffix)
            self.assertFalse(PurePosixPath(value).is_absolute())
            self.assertNotIn("\\", value)
            self.assertNotIn(":", value)
            parts = PurePosixPath(value).parts
            self.assertEqual("/".join(parts), value)
            self.assertEqual(parts[0], ARCHIVE_ROOT.rstrip("/"))
            reserved = {
                "con",
                "prn",
                "aux",
                "nul",
                "clock$",
                "conin$",
                "conout$",
                *(f"com{number}" for number in range(1, 10)),
                *(f"lpt{number}" for number in range(1, 10)),
            }
            for part in parts[1:]:
                self.assertNotIn(part, {"", ".", ".."})
                self.assertFalse(part.endswith((" ", ".")))
                self.assertNotIn(part.split(".", 1)[0].casefold(), reserved)
            name_field, prefix_field = _create_ustar_path_fields(value)
            self.assertEqual(
                _c_string(name_field.ljust(100, b"\0")),
                _c_string(value.encode("utf-8")[-len(name_field) :].ljust(100, b"\0")),
            )
            observed = (
                f"{prefix_field.decode('utf-8')}/{name_field.decode('utf-8')}"
                if prefix_field
                else name_field.decode("utf-8")
            )
            self.assertEqual(observed, value)

        assert_valid_portable_member_path(first_name)
        assert_valid_portable_member_path(case_variant)

        case_record = bytearray(records[1])
        case_header = bytearray(case_record[:BLOCK_SIZE])
        original_header = bytes(case_header)
        case_name_field, case_prefix_field = _create_ustar_path_fields(case_variant)
        case_header[0:100] = case_name_field.ljust(100, b"\0")
        case_header[345:500] = case_prefix_field.ljust(155, b"\0")
        _rechecksum(case_header)
        mutated_header = bytes(case_header)
        archive_root_bytes = ARCHIVE_ROOT.encode("utf-8")
        self.assertEqual(original_header[: len(archive_root_bytes)], archive_root_bytes)
        self.assertEqual(mutated_header[: len(archive_root_bytes)], archive_root_bytes)
        self.assertEqual(original_header[100:148], mutated_header[100:148])
        self.assertEqual(original_header[156:345], mutated_header[156:345])
        self.assertEqual(original_header[500:BLOCK_SIZE], mutated_header[500:BLOCK_SIZE])

        canonical_header = bytearray(original_header)
        canonical_header[0:100] = case_name_field.ljust(100, b"\0")
        canonical_header[345:500] = case_prefix_field.ljust(155, b"\0")
        _rechecksum(canonical_header)
        self.assertEqual(mutated_header, bytes(canonical_header))

        case_record[:BLOCK_SIZE] = case_header
        second_offset = int(entries[1]["header_offset"])
        case_collision = records[0] + bytes(case_record) + b"".join(records[2:]) + terminators
        self.assertEqual(case_collision[:second_offset], valid[:second_offset])
        self.assertEqual(
            case_collision[second_offset + len(case_record) :],
            valid[second_offset + len(case_record) :],
        )
        case_header_observed = assert_header_isolation(
            case_collision, entries[1], (0, 100), (345, 500)
        )
        self.assertEqual(case_header_observed, mutated_header)
        case_entries, case_terminator_offset = _parse_archive(case_collision)
        self.assertEqual(case_terminator_offset, len(body))
        self.assertEqual(len(case_entries), len(entries))
        self.assertEqual(case_entries[1]["archive_name"], case_variant)
        self.assertEqual(case_entries[0]["archive_name"], entries[0]["archive_name"])
        self.assertEqual(
            [entry["archive_name"] for entry in case_entries[2:]],
            [entry["archive_name"] for entry in entries[2:]],
        )
        for key in (
            "header_offset",
            "payload_offset",
            "payload_end",
            "record_end",
            "size",
            "typeflag",
        ):
            self.assertEqual(case_entries[1][key], entries[1][key])
        self.assertEqual(case_entries[1]["payload"], entries[1]["payload"])
        self.assertEqual(case_entries[1]["padding_bytes"], entries[1]["padding_bytes"])

        node_script = r"""
import { Buffer } from "node:buffer";
import { pathToFileURL } from "node:url";
const {
  ArchiveCoreError,
  parseUstarHeader,
  registerArchiveMemberPath,
} = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
const firstHeader = Buffer.from(process.env.IELTMPS_FIRST_HEADER_B64, "base64");
const secondHeader = Buffer.from(process.env.IELTMPS_SECOND_HEADER_B64, "base64");
const seen = new Map();
const names = [];
let errorName = null;
let reason = null;
try {
  for (const header of [firstHeader, secondHeader]) {
    const entry = parseUstarHeader(header);
    names.push(entry.name);
    registerArchiveMemberPath(entry.name, seen);
  }
} catch (error) {
  errorName = error instanceof ArchiveCoreError ? "ArchiveCoreError" : error.name;
  reason = error && typeof error === "object" ? error.reason : null;
}
console.log(JSON.stringify({ names, errorName, reason }));
"""
        node_env = os.environ.copy()
        node_env.update(
            {
                "IELTMPS_TEST_CORE": str(CORE),
                "IELTMPS_FIRST_HEADER_B64": base64.b64encode(first_header).decode("ascii"),
                "IELTMPS_SECOND_HEADER_B64": base64.b64encode(mutated_header).decode("ascii"),
            }
        )
        node_result = subprocess.run(
            [str(self.node), "--input-type=module", "-e", node_script],
            check=True,
            cwd=REPO_ROOT,
            env=node_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        collision_result = json.loads(node_result.stdout)
        self.assertEqual(collision_result["names"], [first_name, case_variant])
        self.assertEqual(collision_result["errorName"], "ArchiveCoreError")
        self.assertEqual(collision_result["reason"], "portable-collision")
        add_case("case-collision", case_collision, "ARCHIVE_HEADER")

        utf_index = next(
            index
            for index, entry in enumerate(entries)
            if entry["archive_name"] == ARCHIVE_ROOT + UTF8_MEMBER
        )
        unicode_name = str(entries[utf_index]["archive_name"])
        unicode_variant = unicodedata.normalize("NFD", unicode_name)
        self.assertNotEqual(unicode_variant, unicode_name)
        self.assertEqual(
            unicodedata.normalize("NFC", unicode_variant),
            unicodedata.normalize("NFC", unicode_name),
        )
        unicode_record = bytearray(records[utf_index + 1])
        unicode_header = bytearray(unicode_record[:BLOCK_SIZE])
        _set_archive_name(unicode_header, unicode_variant)
        _rechecksum(unicode_header)
        unicode_record[:BLOCK_SIZE] = unicode_header
        unicode_collision = (
            b"".join(records[: utf_index + 1])
            + bytes(unicode_record)
            + b"".join(records[utf_index + 2 :])
            + terminators
        )
        unicode_header_observed = assert_header_isolation(
            unicode_collision,
            entries[utf_index + 1],
            (0, 100),
            (345, 500),
        )
        observed_unicode = _c_string(unicode_header_observed[0:100]).decode("utf-8")
        self.assertEqual(observed_unicode, unicode_variant)
        self.assertEqual(
            unicodedata.normalize("NFC", observed_unicode),
            unicodedata.normalize("NFC", unicode_name),
        )
        add_case("unicode-normalization-collision", unicode_collision, "ARCHIVE_HEADER")

        mismatched_size = int(first["size"]) + 1
        size_mismatch = replace_first_field(
            124, 136, _encode_octal_field(mismatched_size, 12)
        )
        size_header = assert_header_isolation(size_mismatch, first, (124, 136))
        self.assertEqual(int(size_header[124:135], 8), mismatched_size)
        self.assertNotEqual(mismatched_size, int(first["size"]))
        add_case("size-mismatch", size_mismatch, "ARCHIVE_HEADER")

        payload_offset = int(first["payload_offset"])
        payload_end = int(first["payload_end"])
        truncated_payload = valid[: payload_end - 1]
        self.assertEqual(truncated_payload, valid[: payload_end - 1])
        self.assertEqual(
            len(truncated_payload) - payload_offset,
            int(first["size"]) - 1,
        )
        add_case("truncated-payload", truncated_payload, "ARCHIVE_VERIFY")

        payload_mutation = bytearray(valid)
        payload_mutation[payload_offset] ^= 0xFF
        payload_mutation_bytes = bytes(payload_mutation)
        payload_changes = _changed_byte_indexes(valid, payload_mutation_bytes)
        self.assertEqual(payload_changes, {payload_offset})
        self.assertEqual(
            len(payload_mutation_bytes[payload_offset:payload_end]),
            int(first["size"]),
        )
        self.assertNotEqual(
            payload_mutation_bytes[payload_offset:payload_end],
            valid[payload_offset:payload_end],
        )
        self.assertEqual(
            payload_mutation_bytes[int(first["header_offset"]) : payload_offset],
            valid[int(first["header_offset"]) : payload_offset],
        )
        add_case("same-size-payload-mutation", payload_mutation_bytes, "ARCHIVE_VERIFY")

        padded = next(entry for entry in entries if int(entry["padding"]) > 0)
        padding_offset = int(padded["payload_end"])
        nonzero_padding = bytearray(valid)
        nonzero_padding[padding_offset] = 1
        nonzero_padding_bytes = bytes(nonzero_padding)
        self.assertEqual(
            _changed_byte_indexes(valid, nonzero_padding_bytes),
            {padding_offset},
        )
        self.assertNotEqual(nonzero_padding_bytes[padding_offset], 0)
        add_case("nonzero-padding", nonzero_padding_bytes, "ARCHIVE_VERIFY")

        missing_first_terminator = body
        self.assertEqual(len(missing_first_terminator) - len(body), 0)
        add_case("missing-first-terminator", missing_first_terminator, "ARCHIVE_VERIFY")

        missing_second_terminator = body + bytes(BLOCK_SIZE)
        self.assertEqual(missing_second_terminator[len(body):], bytes(BLOCK_SIZE))
        add_case("missing-second-terminator", missing_second_terminator, "ARCHIVE_VERIFY")

        extra_third_terminator = body + bytes(3 * BLOCK_SIZE)
        self.assertEqual(
            extra_third_terminator[len(body):], bytes(3 * BLOCK_SIZE)
        )
        add_case("extra-third-zero-block", extra_third_terminator, "ARCHIVE_VERIFY")

        trailing_zero = valid + b"\0"
        self.assertEqual(trailing_zero[:-1], valid)
        self.assertEqual(trailing_zero[-1:], b"\0")
        add_case("trailing-zero-data", trailing_zero, "ARCHIVE_VERIFY")

        trailing_nonzero = valid + b"x"
        self.assertEqual(trailing_nonzero[:-1], valid)
        self.assertNotEqual(trailing_nonzero[-1:], b"\0")
        add_case("trailing-nonzero-data", trailing_nonzero, "ARCHIVE_VERIFY")

        arbitrary_suffix = b"arbitrary trailing bytes"
        trailing_arbitrary = valid + arbitrary_suffix
        self.assertEqual(trailing_arbitrary[:-len(arbitrary_suffix)], valid)
        self.assertEqual(trailing_arbitrary[-len(arbitrary_suffix):], arbitrary_suffix)
        add_case("arbitrary-trailing-data", trailing_arbitrary, "ARCHIVE_VERIFY")

        self.assertEqual(len(cases), 45)
        selected = os.environ.get("IELTMPS_MALFORMED_CASE")
        if selected:
            self.assertIn(selected, cases)
            selected_cases = [(selected, cases[selected])]
        else:
            selected_cases = list(cases.items())

        for index, (label, (malformed, expected_phase)) in enumerate(selected_cases):
            with self.subTest(label=label, expected_phase=expected_phase):
                archive_path = self.temp_root / f"malformed-{index:02d}-{label}.tar"
                archive_path.write_bytes(malformed)
                try:
                    result = self._run_verifier(archive_path)
                    self._assert_archive_verification_failure(
                        result, archive_path, expected_phase
                    )
                finally:
                    archive_path.unlink()
                self.assertFalse(archive_path.exists())
    def test_15_every_writer_checkpoint_fails_closed_and_cleans(self) -> None:
        checkpoints = [
            "before-temp-create-attempt",
            "after-temp-create",
            "after-member-header",
            "after-member-payload",
            "before-finalize",
            "before-file-datasync",
            "before-file-sync",
            "before-file-close",
            "after-finalize",
            "before-verify",
            "after-verify",
            "before-publish",
            "after-final-absence-check",
            "after-link",
            "after-publish",
        ]
        for index, checkpoint in enumerate(checkpoints):
            with self.subTest(checkpoint=checkpoint):
                output = self.temp_root / f"checkpoint-{index}.tar"
                result = self._run_imported_writer(f"throw:{checkpoint}", output=output)
                payload = json.loads(result.stdout)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(payload["ok"])
                self.assertIn(checkpoint, payload["seen"])
                self.assertFalse(output.exists())
                self.assertEqual(self._temp_siblings(output), [])
                self.assertEqual(
                    self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n"
                )
                self.assertNotIn(str(self.fixture_root), payload["message"])
                self.assertNotIn(str(self.temp_root), payload["message"])

    def test_16_partial_zero_progress_sync_and_close_failures(self) -> None:
        partial_output = self.temp_root / "partial-write.tar"
        partial = self._run_imported_writer("partial-write", output=partial_output)
        partial_payload = json.loads(partial.stdout)
        self.assertEqual(partial.returncode, 0, partial_payload)
        self.assertTrue(partial_output.is_file())
        self._assert_success(self._run_verifier(partial_output))

        expected_codes = {
            "zero-write": "MEMBER_WRITE",
            "datasync-failure": "ARCHIVE_FINALIZE",
            "sync-failure": "ARCHIVE_FINALIZE",
            "throw:before-file-close": "ARCHIVE_FINALIZE",
        }
        for index, (action, code) in enumerate(expected_codes.items()):
            with self.subTest(action=action):
                output = self.temp_root / f"io-failure-{index}.tar"
                result = self._run_imported_writer(action, output=output)
                payload = json.loads(result.stdout)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(payload["code"], code)
                self.assertFalse(output.exists())
                self.assertEqual(self._temp_siblings(output), [])

    def test_17_verifier_rejection_and_identity_safe_cleanup(self) -> None:
        corrupted = self._run_imported_writer("corrupt-before-verify")
        corrupted_payload = json.loads(corrupted.stdout)
        self.assertNotEqual(corrupted.returncode, 0)
        self.assertEqual(corrupted_payload["code"], "ARCHIVE_VERIFY")
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self._temp_siblings(), [])

        post_output = self.temp_root / "post-corruption.tar"
        post = self._run_imported_writer(
            "post-publish-corruption", output=post_output
        )
        post_payload = json.loads(post.stdout)
        self.assertNotEqual(post.returncode, 0)
        self.assertEqual(post_payload["code"], "POST_PUBLISH_VERIFY")
        self.assertFalse(post_output.exists())

        temp_identity_output = self.temp_root / "temp-identity.tar"
        temp_identity = self._run_imported_writer(
            "temporary-identity", output=temp_identity_output
        )
        temp_payload = json.loads(temp_identity.stdout)
        self.assertNotEqual(temp_identity.returncode, 0)
        self.assertEqual(temp_payload["code"], "CLEANUP")
        self.assertFalse(temp_identity_output.exists())
        self.assertGreaterEqual(len(self._temp_siblings(temp_identity_output)), 1)

        final_identity_output = self.temp_root / "final-identity.tar"
        final_identity = self._run_imported_writer(
            "final-identity", output=final_identity_output
        )
        final_payload = json.loads(final_identity.stdout)
        self.assertNotEqual(final_identity.returncode, 0)
        self.assertEqual(final_payload["code"], "CLEANUP")
        self.assertTrue(final_identity_output.is_file())
        self.assertTrue(Path(str(final_identity_output) + "-original").is_file())
        self.assertEqual(self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n")

    def test_18_imports_are_silent_git_free_and_cli_flags_are_exact(self) -> None:
        shim_root = self.temp_root / "git-shim"
        shim_root.mkdir()
        marker = self.temp_root / "git-invoked"
        if os.name == "nt":
            shim = shim_root / "git.cmd"
            shim.write_text(
                '@echo off\r\n> "%IELTMPS_TEST_GIT_MARKER%" echo invoked\r\nexit /b 99\r\n',
                encoding="ascii",
                newline="",
            )
        else:
            shim = shim_root / "git"
            shim.write_text(
                '#!/bin/sh\nprintf invoked > "$IELTMPS_TEST_GIT_MARKER"\nexit 99\n',
                encoding="ascii",
                newline="\n",
            )
            shim.chmod(0o755)
        environment = self._environment()
        environment["IELTMPS_TEST_GIT_MARKER"] = str(marker)
        environment["IELTMPS_TEST_MODULES"] = os.pathsep.join(
            [str(CORE), str(WRITER), str(ARCHIVE_VERIFIER)]
        )
        environment["PATH"] = os.pathsep.join(
            [str(shim_root), str(self.node.parent), environment.get("PATH", "")]
        )
        import_script = r"""
import { pathToFileURL } from "node:url";
const before = process.exitCode;
for (const value of process.env.IELTMPS_TEST_MODULES.split(process.platform === "win32" ? ";" : ":")) {
  await import(pathToFileURL(value).href);
}
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
        self.assertFalse(marker.exists())
        self.assertFalse(self.output_path.exists())

        writer_flags = ["--manifest", "--compression", "--overwrite", "--test-hooks"]
        for flag in writer_flags:
            with self.subTest(writer_flag=flag):
                self._assert_failure(self._run_writer(extra_args=[flag, "canary"]), "CLI")
        self._assert_failure(
            subprocess.run(
                [str(self.node), str(WRITER), "positional"],
                cwd=self.temp_root,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            ),
            "CLI",
        )

        self._assert_success(self._run_writer())
        for flag in ["--extract", "--output", "--format", "--compression"]:
            with self.subTest(verifier_flag=flag):
                self._assert_failure(
                    self._run_verifier(extra_args=[flag, "canary"]), "CLI"
                )

    def test_19_canonical_relative_dot_symlink_and_junction_execution(self) -> None:
        canonical_output = self.temp_root / "canonical.tar"
        relative_output = self.temp_root / "relative.tar"
        dot_output = self.temp_root / "dot.tar"
        self._assert_success(self._run_writer(output=canonical_output))
        relative_writer = os.path.relpath(WRITER, self.temp_root)
        self._assert_success(
            self._run_writer(
                output=relative_output,
                script=relative_writer,
                cwd=self.temp_root,
            )
        )
        dot_writer = str(WRITER.parent) + os.sep + "." + os.sep + WRITER.name
        self._assert_success(self._run_writer(output=dot_output, script=dot_writer))

        relative_verifier = os.path.relpath(ARCHIVE_VERIFIER, self.temp_root)
        self._assert_success(
            self._run_verifier(canonical_output, script=relative_verifier, cwd=self.temp_root)
        )
        dot_verifier = (
            str(ARCHIVE_VERIFIER.parent)
            + os.sep
            + "."
            + os.sep
            + ARCHIVE_VERIFIER.name
        )
        self._assert_success(self._run_verifier(canonical_output, script=dot_verifier))

        writer_alias = self.temp_root / "writer-alias.mjs"
        verifier_alias = self.temp_root / "verifier-alias.mjs"
        file_alias_available = True
        try:
            writer_alias.symlink_to(WRITER)
            verifier_alias.symlink_to(ARCHIVE_VERIFIER)
        except OSError:
            file_alias_available = False
        self.assertTrue(
            file_alias_available,
            "host cannot create required writer/verifier file symlink aliases",
        )
        if file_alias_available:
            alias_output = self.temp_root / "file-alias.tar"
            self._assert_success(self._run_writer(output=alias_output, script=writer_alias))
            self._assert_success(self._run_verifier(alias_output, script=verifier_alias))
            invalid = subprocess.run(
                [str(self.node), str(writer_alias), "--repo"],
                cwd=self.temp_root,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            self._assert_failure(invalid, "CLI")

        directory_alias = self.temp_root / "repository-tool-alias"
        alias_kind = ""
        try:
            directory_alias.symlink_to(REPO_ROOT, target_is_directory=True)
            alias_kind = "symlink"
        except OSError:
            if os.name == "nt":
                completed = subprocess.run(
                    [
                        "cmd",
                        "/d",
                        "/c",
                        "mklink",
                        "/J",
                        str(directory_alias),
                        str(REPO_ROOT),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout)
                alias_kind = "junction"
        self.assertTrue(alias_kind, "host provides no directory alias mechanism")
        try:
            directory_output = self.temp_root / "directory-alias.tar"
            alias_writer = directory_alias / "developer" / WRITER.name
            alias_verifier = directory_alias / "developer" / ARCHIVE_VERIFIER.name
            self._assert_success(
                self._run_writer(output=directory_output, script=alias_writer)
            )
            self._assert_success(
                self._run_verifier(directory_output, script=alias_verifier)
            )
        finally:
            if directory_alias.exists() or directory_alias.is_symlink():
                if os.name == "nt":
                    os.rmdir(directory_alias)
                else:
                    directory_alias.unlink()

    def test_20_alias_imports_remain_import_only(self) -> None:
        alias = self.temp_root / "writer-import-alias.mjs"
        try:
            alias.symlink_to(WRITER)
        except OSError:
            alias = WRITER
        environment = self._environment()
        environment["IELTMPS_TEST_ALIAS"] = str(alias)
        script = r"""
import { pathToFileURL } from "node:url";
const before = process.exitCode;
await import(pathToFileURL(process.env.IELTMPS_TEST_ALIAS).href);
if (process.exitCode !== before) process.exit(91);
"""
        result = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertFalse(self.output_path.exists())

    def test_21_unrepresentable_path_and_numeric_extension_are_rejected(self) -> None:
        unrepresentable = "css/" + "u" * 97 + ".css"
        self.assertEqual(len(PurePosixPath(unrepresentable).name.encode("utf-8")), 101)
        self._write(unrepresentable, b"unrepresentable USTAR path\n")
        commit = self._commit_paths("unrepresentable path", unrepresentable)
        result = self._run_writer(commit=commit)
        self._assert_failure(result, "ARCHIVE_HEADER")
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self._temp_siblings(), [])

        environment = self._environment()
        environment["IELTMPS_TEST_CORE"] = str(CORE)
        core_script = r"""
import { pathToFileURL } from "node:url";
const core = await import(pathToFileURL(process.env.IELTMPS_TEST_CORE).href);
let failures = 0;
for (const value of [-1, Number.MAX_SAFE_INTEGER, core.MAX_USTAR_SIZE + 1]) {
  try {
    core.encodeUstarHeader({ relativePath: "css/value.css", gitMode: "100644", size: value });
  } catch {
    failures += 1;
  }
}
try {
  core.encodeUstarHeader({ relativePath: "css/value.css", gitMode: "100600", size: 1 });
} catch {
  failures += 1;
}
process.stdout.write(String(failures));
"""
        core_result = subprocess.run(
            [str(self.node), "--input-type=module", "--eval", core_script],
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(core_result.returncode, 0, core_result.stderr)
        self.assertEqual(core_result.stdout, "4")

    def test_22_verifier_archive_input_symlink_hardlink_and_inside_repo(self) -> None:
        self._assert_success(self._run_writer())
        inside = self.fixture_root / "inside-archive.tar"
        inside.write_bytes(self.output_path.read_bytes())
        self._assert_failure(self._run_verifier(inside), "OUTPUT_PARENT")

        alias = self.temp_root / "archive-alias.tar"
        try:
            alias.symlink_to(self.output_path)
        except OSError:
            alias = None
        if alias is not None:
            self._assert_failure(self._run_verifier(alias), "OUTPUT_PARENT")

        hardlink = self.temp_root / "archive-hardlink.tar"
        try:
            os.link(self.output_path, hardlink)
        except OSError:
            hardlink = None
        if hardlink is not None:
            self._assert_failure(self._run_verifier(hardlink), "OUTPUT_PARENT")
            hardlink.unlink()
            self._assert_success(self._run_verifier())

    def test_23_success_json_is_deterministic_path_free_and_no_sidecars_exist(self) -> None:
        first = self._assert_success(self._run_writer())
        second = self._assert_success(self._run_writer(output=self.second_output))
        self.assertEqual(first, second)
        for summary in [first, self._assert_success(self._run_verifier())]:
            serialized = json.dumps(summary, separators=(",", ":"))
            for canary in [
                str(self.fixture_root),
                str(self.temp_root),
                str(self.output_path),
                self.temp_root.drive,
            ]:
                if canary:
                    self.assertNotIn(canary, serialized)
        siblings = {item.name for item in self.temp_root.iterdir()}
        forbidden_fragments = {
            "receipt",
            "sbom",
            "signature",
            "attestation",
            "membership-report",
            "source-tree",
        }
        self.assertFalse(
            any(fragment in name.lower() for name in siblings for fragment in forbidden_fragments)
        )
        self.assertFalse((self.temp_root / ".git").exists())

    def test_24_synthetic_b2_tree_matches_archive_files_and_bytes(self) -> None:
        self._assert_success(self._run_writer())
        archive_entries, _ = _parse_archive(self.output_path.read_bytes())
        archive_files = {
            str(entry["archive_name"])[len(ARCHIVE_ROOT) :]: entry["payload"]
            for entry in archive_entries
        }
        tree = self.temp_root / "b2-source-tree"
        result = subprocess.run(
            [
                str(self.node),
                str(B2_MATERIALIZER),
                "--repo",
                str(self.fixture_root),
                "--commit",
                self.base_commit,
                "--output",
                str(tree),
            ],
            cwd=self.temp_root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        tree_files: dict[str, bytes] = {}
        for current_text, directory_names, file_names in os.walk(
            tree, topdown=True, followlinks=False
        ):
            current = Path(current_text)
            for directory_name in directory_names:
                self.assertFalse((current / directory_name).is_symlink())
            for file_name in file_names:
                target = current / file_name
                self.assertTrue(target.is_file())
                self.assertFalse(target.is_symlink())
                tree_files[target.relative_to(tree).as_posix()] = target.read_bytes()
        self.assertEqual(tree_files, archive_files)
        shutil.rmtree(tree)
        self.assertFalse(tree.exists())

    def test_25_imported_verifier_result_is_frozen_and_contains_no_member_bytes(self) -> None:
        self._assert_success(self._run_writer())
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_VERIFIER": str(ARCHIVE_VERIFIER),
                "IELTMPS_TEST_REPO": str(self.fixture_root),
                "IELTMPS_TEST_COMMIT": self.base_commit,
                "IELTMPS_TEST_ARCHIVE": str(self.output_path),
            }
        )
        script = r"""
import { pathToFileURL } from "node:url";
const { verifyPublicSourceArchive } = await import(
  pathToFileURL(process.env.IELTMPS_TEST_VERIFIER).href
);
const result = await verifyPublicSourceArchive({
  repo: process.env.IELTMPS_TEST_REPO,
  commit: process.env.IELTMPS_TEST_COMMIT,
  archive: process.env.IELTMPS_TEST_ARCHIVE,
});
process.stdout.write(JSON.stringify({
  frozen: Object.isFrozen(result),
  keys: Object.keys(result),
  hasBytes: Object.values(result).some((value) => Buffer.isBuffer(value)),
}));
"""
        result = subprocess.run(
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
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["frozen"])
        self.assertFalse(payload["hasBytes"])
        self.assertNotIn("repo", payload["keys"])
        self.assertNotIn("archive", payload["keys"])


    @unittest.skipUnless(os.name == "nt", "junctions are a Windows host capability")
    def test_26_windows_junction_parent_and_tool_aliases(self) -> None:
        def make_junction(alias: Path, target: Path) -> None:
            completed = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)

        real_parent = self.temp_root / "junction-real-parent"
        junction_parent = self.temp_root / "junction-output-parent"
        real_parent.mkdir()
        make_junction(junction_parent, real_parent)
        try:
            self._assert_failure(
                self._run_writer(output=junction_parent / "archive.tar"),
                "OUTPUT_PARENT",
            )
            self.assertEqual(list(real_parent.iterdir()), [])
        finally:
            os.rmdir(junction_parent)

        tool_junction = self.temp_root / "junction-tool-root"
        make_junction(tool_junction, REPO_ROOT)
        try:
            alias_writer = tool_junction / "developer" / WRITER.name
            alias_verifier = tool_junction / "developer" / ARCHIVE_VERIFIER.name
            alias_core = tool_junction / "developer" / CORE.name
            output = self.temp_root / "junction-alias.tar"
            self._assert_success(self._run_writer(output=output, script=alias_writer))
            self._assert_success(self._run_verifier(output, script=alias_verifier))

            for alias_script in [alias_writer, alias_verifier]:
                invalid = subprocess.run(
                    [str(self.node), str(alias_script), "--repo"],
                    cwd=self.temp_root,
                    env=self._environment(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                self._assert_failure(invalid, "CLI")

            environment = self._environment()
            environment["IELTMPS_ALIAS_MODULES"] = os.pathsep.join(
                [str(alias_core), str(alias_writer), str(alias_verifier)]
            )
            import_script = r"""
import { pathToFileURL } from "node:url";
const separator = process.platform === "win32" ? ";" : ":";
const before = process.exitCode;
for (const value of process.env.IELTMPS_ALIAS_MODULES.split(separator)) {
  await import(pathToFileURL(value).href);
}
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
            self.assertEqual(
                imported.returncode,
                0,
                imported.stderr.decode("utf-8", errors="replace"),
            )
            self.assertEqual(imported.stdout, b"")
            self.assertEqual(imported.stderr, b"")
        finally:
            os.rmdir(tool_junction)


if __name__ == "__main__":
    unittest.main(verbosity=2)
