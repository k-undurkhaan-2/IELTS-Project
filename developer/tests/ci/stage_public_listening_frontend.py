#!/usr/bin/env python3
"""Build the frozen Issue #79 public Listening artifact from Git objects only.

The source bytes are acquired into a newly created bare object store at one
exact commit. No source file is read from a developer working tree and no
Listening generator is executed. The staged directory is built off to the
side, verified, and then moved into place only after every frozen identity,
path, mode, length, and digest has passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ARTIFACT_VERSION = "lpf-v1-1a576be93d7d-a2-fad166773fa6259a"
EXPECTED_MANIFEST_BYTES = 12_153
EXPECTED_MANIFEST_SHA256 = (
    "fad166773fa6259a18c752c240030aa228390f8380b7be5dacac3b8ba8d4b75d"
)
EXPECTED_SOURCE_REPOSITORY = "k-undurkhaan-2/IELTS-Project"
EXPECTED_SOURCE_URL = "https://github.com/k-undurkhaan-2/IELTS-Project.git"
EXPECTED_SOURCE_COMMIT = "1a576be93d7d18b8955adf5216efb311032bf62a"
EXPECTED_SOURCE_COMMIT_TREE = "4fcd96bc3f8564311bdf31853f4ba2e320b3343d"
EXPECTED_SOURCE_TREE = "2b9c9ef46ae748e6cb187114c5887d8a2f509fd5"
SOURCE_PREFIX = "ListeningPractice/vip special/"
SOURCE_SUBTREE_PATH = SOURCE_PREFIX.rstrip("/")

EXPECTED_APPROVED_ENTRIES = 31
EXPECTED_RUNTIME_SOURCE_ENTRIES = 24
EXPECTED_BUILD_ONLY_ENTRIES = 4
EXPECTED_OPTIONAL_ENTRIES = 3
EXPECTED_GENERATED_DEPENDENCY_RECORDS = 4
EXPECTED_GENERATED_PAYLOAD_ENTRIES = 2
EXPECTED_SERVED_PAYLOAD_ENTRIES = 26
EXPECTED_SERVED_PAYLOAD_BYTES = 14_533_213

MANIFEST_SCHEMA = "ieltmps.public-listening-frontend-manifest.v1"
MANIFEST_MODEL = "A2_ARTIFACT_RELATIVE_GENERATED_ASSETS"
ACTIVE_SCHEMA = "ieltmps.public-listening-frontend-active.v1"
INTEGRITY_ALGORITHM = "SHA-256"

CI_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = CI_DIRECTORY.parents[2]
MANIFEST_PATH = (
    CI_DIRECTORY
    / "public-listening-frontend"
    / f"{ARTIFACT_VERSION}.manifest.json"
)
DEFAULT_OUTPUT_ROOT = (
    REPOSITORY_ROOT / ".ieltmps-build" / "public-listening-frontend"
)

SHA1_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
WINDOWS_DEVICE_PATTERN = re.compile(
    r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?\Z", re.IGNORECASE
)
WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"\\|?*')
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
GIT_ENVIRONMENT_DIRECTORY = ".ieltmps-git-environment"
GIT_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "ComSpec",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
        "windir",
    }
)

TOP_LEVEL_FIELDS = (
    "schema",
    "model",
    "source_repository",
    "source_commit",
    "source_commit_tree",
    "source_tree",
    "integrity_algorithm",
    "approved_entries",
    "generated_dependencies",
)
APPROVED_ENTRY_FIELDS = (
    "source_path",
    "payload_path",
    "role",
    "included_in_runtime",
    "mode",
    "git_blob",
    "length",
    "sha256",
)
GENERATED_ENTRY_FIELDS = (
    "source_path",
    "artifact_path",
    "required_image_path",
    "mode",
    "git_blob",
    "length",
    "sha256",
)
ACTIVE_FIELDS = (
    "schema",
    "artifact_version",
    "manifest_path",
    "manifest_sha256",
    "manifest_bytes",
    "payload_path",
    "payload_files",
    "payload_bytes",
    "source_commit",
    "source_tree",
    "source_subtree",
)


class StagingError(RuntimeError):
    """Base class for fail-closed staging errors."""


class ManifestError(StagingError):
    """The frozen control manifest is absent, altered, or invalid."""


class SourceIntegrityError(StagingError):
    """The acquired Git object graph does not match the manifest."""


class UnsafePathError(StagingError):
    """A path is ambiguous or unsafe on supported staging platforms."""


class OutputIntegrityError(StagingError):
    """The materialized artifact does not match the frozen contract."""


class ResidualStateError(StagingError):
    """A failed staging transaction could not safely remove its owned output."""


@dataclass(frozen=True)
class ContractExpectations:
    manifest_bytes: int
    manifest_sha256: str
    source_repository: str
    source_commit: str
    source_commit_tree: str
    source_tree: str
    artifact_version: str
    approved_entries: int
    runtime_source_entries: int
    build_only_entries: int
    optional_entries: int
    generated_dependency_records: int
    generated_payload_entries: int
    served_payload_entries: int
    served_payload_bytes: int


FROZEN_EXPECTATIONS = ContractExpectations(
    manifest_bytes=EXPECTED_MANIFEST_BYTES,
    manifest_sha256=EXPECTED_MANIFEST_SHA256,
    source_repository=EXPECTED_SOURCE_REPOSITORY,
    source_commit=EXPECTED_SOURCE_COMMIT,
    source_commit_tree=EXPECTED_SOURCE_COMMIT_TREE,
    source_tree=EXPECTED_SOURCE_TREE,
    artifact_version=ARTIFACT_VERSION,
    approved_entries=EXPECTED_APPROVED_ENTRIES,
    runtime_source_entries=EXPECTED_RUNTIME_SOURCE_ENTRIES,
    build_only_entries=EXPECTED_BUILD_ONLY_ENTRIES,
    optional_entries=EXPECTED_OPTIONAL_ENTRIES,
    generated_dependency_records=EXPECTED_GENERATED_DEPENDENCY_RECORDS,
    generated_payload_entries=EXPECTED_GENERATED_PAYLOAD_ENTRIES,
    served_payload_entries=EXPECTED_SERVED_PAYLOAD_ENTRIES,
    served_payload_bytes=EXPECTED_SERVED_PAYLOAD_BYTES,
)


@dataclass(frozen=True)
class ManifestRecord:
    source_path: str
    payload_path: str | None
    role: str
    included_in_runtime: bool
    mode: str
    git_blob: str
    length: int
    sha256: str


@dataclass(frozen=True)
class GeneratedRecord:
    source_path: str
    artifact_path: str | None
    required_image_path: str
    mode: str
    git_blob: str
    length: int
    sha256: str


@dataclass(frozen=True)
class ManifestContract:
    raw_bytes: bytes
    expectations: ContractExpectations
    approved_entries: tuple[ManifestRecord, ...]
    generated_dependencies: tuple[GeneratedRecord, ...]

    @property
    def runtime_entries(self) -> tuple[ManifestRecord, ...]:
        return tuple(item for item in self.approved_entries if item.included_in_runtime)

    @property
    def generated_payload_entries(self) -> tuple[GeneratedRecord, ...]:
        return tuple(
            item for item in self.generated_dependencies if item.artifact_path is not None
        )

    @property
    def payload_records(self) -> tuple[ManifestRecord | GeneratedRecord, ...]:
        return self.runtime_entries + self.generated_payload_entries


@dataclass(frozen=True)
class GitTreeEntry:
    path: str
    mode: str
    object_type: str
    object_id: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_id(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _git_commit_id(data: bytes) -> str:
    header = f"commit {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ManifestError(f"non-finite JSON value is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON member is forbidden: {key}")
        result[key] = value
    return result


def _exact_fields(value: Mapping[str, Any], expected: Sequence[str], label: str) -> None:
    actual = tuple(value.keys())
    if actual != tuple(expected):
        raise ManifestError(
            f"{label} fields/order mismatch: expected {tuple(expected)!r}, got {actual!r}"
        )


def _require_string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ManifestError(f"{label} must be a nonempty string")
    return value


def _require_digest(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _require_string(value, label)
    if pattern.fullmatch(text) is None:
        raise ManifestError(f"{label} is not a lowercase hexadecimal digest")
    return text


def _require_length(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ManifestError(f"{label} must be a nonnegative integer")
    return value


def validate_relative_path(value: Any, label: str) -> str:
    """Return one canonical, portable repository-relative POSIX path."""

    path = _require_string(value, label)
    if path != unicodedata.normalize("NFC", path):
        raise UnsafePathError(f"{label} must use NFC Unicode normalization")
    if path.startswith("/") or path.endswith("/"):
        raise UnsafePathError(f"{label} must be a relative file path")
    if "\0" in path or "\\" in path:
        raise UnsafePathError(f"{label} contains a forbidden separator or NUL")
    parts = path.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise UnsafePathError(f"{label} contains an empty or traversal segment")
    for part in parts:
        if part.endswith((" ", ".")):
            raise UnsafePathError(f"{label} contains a trailing space or dot")
        if WINDOWS_DEVICE_PATTERN.fullmatch(part):
            raise UnsafePathError(f"{label} contains a reserved device name")
        if any(character in WINDOWS_FORBIDDEN_CHARACTERS for character in part):
            raise UnsafePathError(f"{label} contains a platform-forbidden character")
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise UnsafePathError(f"{label} contains a control character")
    return path


def _path_collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def reject_path_collisions(paths: Iterable[str], label: str) -> None:
    exact: set[str] = set()
    portable: dict[str, str] = {}
    for index, raw_path in enumerate(paths):
        path = validate_relative_path(raw_path, f"{label}[{index}]")
        if path in exact:
            raise UnsafePathError(f"duplicate {label} path: {path}")
        exact.add(path)
        collision_key = _path_collision_key(path)
        prior = portable.get(collision_key)
        if prior is not None:
            raise UnsafePathError(
                f"portable {label} collision between {prior!r} and {path!r}"
            )
        portable[collision_key] = path


def _validate_required_image_path(value: Any, label: str) -> str:
    path = _require_string(value, label)
    if not path.startswith("/app/"):
        raise ManifestError(f"{label} must be rooted beneath /app")
    validate_relative_path(path.removeprefix("/"), label)
    return path


def _record_from_json(value: Any, index: int) -> ManifestRecord:
    if type(value) is not dict:
        raise ManifestError(f"approved_entries[{index}] must be an object")
    _exact_fields(value, APPROVED_ENTRY_FIELDS, f"approved_entries[{index}]")
    source_path = validate_relative_path(
        value["source_path"], f"approved_entries[{index}].source_path"
    )
    if not source_path.startswith(SOURCE_PREFIX):
        raise ManifestError(f"approved_entries[{index}] is outside the frozen subtree")
    role = _require_string(value["role"], f"approved_entries[{index}].role")
    if role not in {"runtime_required", "build_only", "optional"}:
        raise ManifestError(f"approved_entries[{index}] has an unknown role")
    included = value["included_in_runtime"]
    if type(included) is not bool:
        raise ManifestError(
            f"approved_entries[{index}].included_in_runtime must be boolean"
        )
    payload_value = value["payload_path"]
    if role == "runtime_required":
        if included is not True:
            raise ManifestError(f"runtime entry {source_path!r} must be included")
        payload_path = validate_relative_path(
            payload_value, f"approved_entries[{index}].payload_path"
        )
        expected_payload_path = source_path.removeprefix(SOURCE_PREFIX)
        if payload_path != expected_payload_path:
            raise ManifestError(
                f"runtime entry {source_path!r} has a noncanonical payload path"
            )
    else:
        if included is not False or payload_value is not None:
            raise ManifestError(f"non-runtime entry {source_path!r} cannot be served")
        payload_path = None
    mode = _require_string(value["mode"], f"approved_entries[{index}].mode")
    if mode != "100644":
        raise ManifestError(f"approved entry {source_path!r} has a forbidden mode")
    return ManifestRecord(
        source_path=source_path,
        payload_path=payload_path,
        role=role,
        included_in_runtime=included,
        mode=mode,
        git_blob=_require_digest(
            value["git_blob"], SHA1_PATTERN, f"approved_entries[{index}].git_blob"
        ),
        length=_require_length(value["length"], f"approved_entries[{index}].length"),
        sha256=_require_digest(
            value["sha256"], SHA256_PATTERN, f"approved_entries[{index}].sha256"
        ),
    )


def _generated_record_from_json(value: Any, index: int) -> GeneratedRecord:
    if type(value) is not dict:
        raise ManifestError(f"generated_dependencies[{index}] must be an object")
    _exact_fields(value, GENERATED_ENTRY_FIELDS, f"generated_dependencies[{index}]")
    source_path = validate_relative_path(
        value["source_path"], f"generated_dependencies[{index}].source_path"
    )
    artifact_value = value["artifact_path"]
    artifact_path = (
        None
        if artifact_value is None
        else validate_relative_path(
            artifact_value, f"generated_dependencies[{index}].artifact_path"
        )
    )
    if artifact_path is not None and artifact_path != source_path:
        raise ManifestError(
            f"generated dependency {source_path!r} must preserve its artifact path"
        )
    mode = _require_string(value["mode"], f"generated_dependencies[{index}].mode")
    if mode != "100644":
        raise ManifestError(f"generated dependency {source_path!r} has a forbidden mode")
    return GeneratedRecord(
        source_path=source_path,
        artifact_path=artifact_path,
        required_image_path=_validate_required_image_path(
            value["required_image_path"],
            f"generated_dependencies[{index}].required_image_path",
        ),
        mode=mode,
        git_blob=_require_digest(
            value["git_blob"],
            SHA1_PATTERN,
            f"generated_dependencies[{index}].git_blob",
        ),
        length=_require_length(
            value["length"], f"generated_dependencies[{index}].length"
        ),
        sha256=_require_digest(
            value["sha256"],
            SHA256_PATTERN,
            f"generated_dependencies[{index}].sha256",
        ),
    )


def load_manifest(
    path: Path = MANIFEST_PATH,
    expectations: ContractExpectations = FROZEN_EXPECTATIONS,
) -> ManifestContract:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read canonical manifest: {exc}") from exc
    if len(raw_bytes) != expectations.manifest_bytes:
        raise ManifestError(
            f"canonical manifest length mismatch: expected {expectations.manifest_bytes}, "
            f"got {len(raw_bytes)}"
        )
    digest = _sha256(raw_bytes)
    if digest != expectations.manifest_sha256:
        raise ManifestError(
            f"canonical manifest SHA-256 mismatch: expected "
            f"{expectations.manifest_sha256}, got {digest}"
        )
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ManifestError("canonical manifest must not contain a UTF-8 BOM")
    try:
        document = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"canonical manifest is not strict UTF-8 JSON: {exc}") from exc
    if type(document) is not dict:
        raise ManifestError("canonical manifest top level must be an object")
    _exact_fields(document, TOP_LEVEL_FIELDS, "manifest")
    exact_values = {
        "schema": MANIFEST_SCHEMA,
        "model": MANIFEST_MODEL,
        "source_repository": expectations.source_repository,
        "source_commit": expectations.source_commit,
        "source_commit_tree": expectations.source_commit_tree,
        "source_tree": expectations.source_tree,
        "integrity_algorithm": INTEGRITY_ALGORITHM,
    }
    for field, expected in exact_values.items():
        if document[field] != expected:
            raise ManifestError(
                f"manifest {field} mismatch: expected {expected!r}, got {document[field]!r}"
            )
    approved_values = document["approved_entries"]
    generated_values = document["generated_dependencies"]
    if type(approved_values) is not list or type(generated_values) is not list:
        raise ManifestError("manifest entry collections must be arrays")
    approved = tuple(
        _record_from_json(value, index) for index, value in enumerate(approved_values)
    )
    generated = tuple(
        _generated_record_from_json(value, index)
        for index, value in enumerate(generated_values)
    )
    if tuple(item.source_path for item in approved) != tuple(
        sorted(item.source_path for item in approved)
    ):
        raise ManifestError("approved entries are not in lexicographic source-path order")
    reject_path_collisions(
        (item.source_path for item in approved), "approved source"
    )
    reject_path_collisions(
        (item.source_path for item in generated), "generated source"
    )
    payload_paths = [
        item.payload_path for item in approved if item.payload_path is not None
    ] + [
        item.artifact_path for item in generated if item.artifact_path is not None
    ]
    reject_path_collisions((path for path in payload_paths if path is not None), "payload")

    role_counts = {
        role: sum(1 for item in approved if item.role == role)
        for role in ("runtime_required", "build_only", "optional")
    }
    actual_counts = {
        "approved_entries": len(approved),
        "runtime_source_entries": role_counts["runtime_required"],
        "build_only_entries": role_counts["build_only"],
        "optional_entries": role_counts["optional"],
        "generated_dependency_records": len(generated),
        "generated_payload_entries": sum(
            item.artifact_path is not None for item in generated
        ),
    }
    expected_counts = {
        "approved_entries": expectations.approved_entries,
        "runtime_source_entries": expectations.runtime_source_entries,
        "build_only_entries": expectations.build_only_entries,
        "optional_entries": expectations.optional_entries,
        "generated_dependency_records": expectations.generated_dependency_records,
        "generated_payload_entries": expectations.generated_payload_entries,
    }
    if actual_counts != expected_counts:
        raise ManifestError(
            f"manifest inventory mismatch: expected {expected_counts!r}, "
            f"got {actual_counts!r}"
        )
    served_entries = (
        actual_counts["runtime_source_entries"]
        + actual_counts["generated_payload_entries"]
    )
    served_bytes = sum(item.length for item in approved if item.included_in_runtime)
    served_bytes += sum(
        item.length for item in generated if item.artifact_path is not None
    )
    if served_entries != expectations.served_payload_entries:
        raise ManifestError("served payload entry count does not match the frozen contract")
    if served_bytes != expectations.served_payload_bytes:
        raise ManifestError("served payload byte count does not match the frozen contract")
    return ManifestContract(
        raw_bytes=raw_bytes,
        expectations=expectations,
        approved_entries=approved,
        generated_dependencies=generated,
    )


def active_locator_bytes(contract: ManifestContract) -> bytes:
    version = contract.expectations.artifact_version
    locator = {
        "schema": ACTIVE_SCHEMA,
        "artifact_version": version,
        "manifest_path": f"{version}/manifest.json",
        "manifest_sha256": contract.expectations.manifest_sha256,
        "manifest_bytes": contract.expectations.manifest_bytes,
        "payload_path": f"{version}/payload",
        "payload_files": contract.expectations.served_payload_entries,
        "payload_bytes": contract.expectations.served_payload_bytes,
        "source_commit": contract.expectations.source_commit,
        "source_tree": contract.expectations.source_commit_tree,
        "source_subtree": contract.expectations.source_tree,
    }
    if tuple(locator) != ACTIVE_FIELDS:
        raise AssertionError("active locator field order changed")
    serialized = json.dumps(
        locator,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
    )
    return (serialized + "\n").encode("utf-8")


def _repository_protocol(repository: str) -> str:
    if type(repository) is not str or not repository:
        raise SourceIntegrityError("Git repository must be a nonempty location")
    if repository.startswith("https://"):
        return "https"
    if Path(repository).is_absolute():
        return "file"
    raise SourceIntegrityError(
        "Git repository must use HTTPS or an absolute local fixture path"
    )


def _clean_git_environment(
    control_root: Path,
    *,
    allowed_protocol: str,
    ceiling_directory: Path,
) -> dict[str, str]:
    """Build one credential-free Git environment from an explicit allowlist."""

    home = control_root / "home"
    xdg = control_root / "xdg"
    templates = control_root / "templates"
    global_config = control_root / "global.gitconfig"
    if not all(path.is_dir() for path in (home, xdg, templates)):
        raise SourceIntegrityError("controlled Git environment directories are absent")
    if not global_config.is_file() or global_config.read_bytes() != b"":
        raise SourceIntegrityError("controlled Git global configuration is not empty")

    environment = {
        name: os.environ[name]
        for name in GIT_ENVIRONMENT_ALLOWLIST
        if name in os.environ
    }
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(xdg),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_TEMPLATE_DIR": str(templates),
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(ceiling_directory),
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ALLOW_PROTOCOL": allowed_protocol,
            "GIT_PROTOCOL_FROM_USER": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


def _prepare_git_environment(
    object_store: Path, repository: str
) -> dict[str, str]:
    """Create private empty config, home, XDG, and template inputs for Git."""

    control_root = object_store / GIT_ENVIRONMENT_DIRECTORY
    try:
        object_store.mkdir(mode=0o700)
        control_root.mkdir(mode=0o700)
        for name in ("home", "xdg", "templates"):
            (control_root / name).mkdir(mode=0o700)
        (control_root / "global.gitconfig").write_bytes(b"")
    except OSError as exc:
        raise SourceIntegrityError(
            f"cannot create controlled Git environment: {exc}"
        ) from exc
    return _clean_git_environment(
        control_root,
        allowed_protocol=_repository_protocol(repository),
        ceiling_directory=object_store.parent,
    )


def resolve_git_executable(value: str) -> str:
    if type(value) is not str or not value:
        raise SourceIntegrityError("Git executable must be a nonempty path or command")
    candidate = Path(value)
    if not candidate.is_absolute():
        resolved_from_path = shutil.which(value)
        if resolved_from_path is None:
            raise SourceIntegrityError("cannot resolve Git executable on PATH")
        candidate = Path(resolved_from_path)
    try:
        candidate = candidate.resolve(strict=True)
        metadata = candidate.stat()
    except OSError as exc:
        raise SourceIntegrityError(f"cannot resolve Git executable: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SourceIntegrityError("resolved Git executable is not a regular file")
    return str(candidate)


def _run_command(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    input_bytes: bytes | None = None,
    accepted_returncodes: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            list(command),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=dict(environment),
        )
    except OSError as exc:
        raise SourceIntegrityError(f"cannot execute Git: {exc}") from exc
    if completed.returncode not in accepted_returncodes:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        if len(diagnostic) > 2_000:
            diagnostic = diagnostic[:2_000] + "..."
        raise SourceIntegrityError(
            f"Git command failed with exit {completed.returncode}: {diagnostic}"
        )
    return completed


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise OutputIntegrityError(f"cannot inspect path metadata: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_linked_existing_ancestors(path: Path) -> None:
    current = path.absolute()
    existing: list[Path] = []
    while not os.path.lexists(current):
        parent = current.parent
        if parent == current:
            break
        current = parent
    while True:
        existing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for item in existing:
        if _is_link_or_reparse(item):
            raise OutputIntegrityError(f"linked/reparse ancestor is forbidden: {item}")


def _path_is_within(path: Path, parent: Path) -> bool:
    path_text = os.path.normcase(str(path.absolute()))
    parent_text = os.path.normcase(str(parent.absolute()))
    try:
        return os.path.commonpath((path_text, parent_text)) == parent_text
    except ValueError:
        return False


def acquire_exact_commit(
    repository: str,
    commit: str,
    object_store: Path,
    *,
    git_executable: str = "git",
) -> "BareGitObjectStore":
    """Fetch one full commit ID into a new, standalone bare object store."""

    if SHA1_PATTERN.fullmatch(commit) is None:
        raise SourceIntegrityError("source revision must be one full lowercase SHA-1")
    git_executable = resolve_git_executable(git_executable)
    object_store = object_store.absolute()
    if _path_is_within(object_store, REPOSITORY_ROOT):
        raise SourceIntegrityError("bare object store must be outside the subject checkout")
    _reject_linked_existing_ancestors(object_store)
    if os.path.lexists(object_store):
        raise SourceIntegrityError("bare object-store path must not already exist")
    try:
        object_store.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SourceIntegrityError(f"cannot create object-store parent: {exc}") from exc
    git_environment = _prepare_git_environment(object_store, repository)
    _run_command(
        (git_executable, "init", "--bare", str(object_store)),
        environment=git_environment,
    )
    store = BareGitObjectStore(
        object_store,
        git_executable=git_executable,
        git_environment=git_environment,
    )
    if store.git_text("rev-parse", "--is-bare-repository") != "true":
        raise SourceIntegrityError("isolated Git object store is not bare")
    if store.git_text("rev-parse", "--show-object-format") != "sha1":
        raise SourceIntegrityError("isolated Git object store must use SHA-1 object IDs")
    alternates = object_store / "objects" / "info" / "alternates"
    if alternates.exists():
        raise SourceIntegrityError("Git object alternates are forbidden")
    store.git(
        "-c",
        "fetch.writeCommitGraph=false",
        "fetch",
        "--no-tags",
        "--depth=1",
        repository,
        commit,
    )
    fetched_commit = store.git_text("rev-parse", "FETCH_HEAD^{commit}")
    if fetched_commit != commit:
        raise SourceIntegrityError(
            f"FETCH_HEAD identity mismatch: expected {commit}, got {fetched_commit}"
        )
    object_type = store.git_text("cat-file", "-t", commit)
    if object_type != "commit":
        raise SourceIntegrityError("fetched source object is not a commit")
    commit_bytes = store.git("cat-file", "commit", commit).stdout
    if _git_commit_id(commit_bytes) != commit:
        raise SourceIntegrityError("fetched commit object identity mismatch")
    show_ref = store.git("show-ref", accepted_returncodes=frozenset({0, 1}))
    if show_ref.stdout:
        raise SourceIntegrityError("bare acquisition unexpectedly created a mutable ref")
    return store


class BareGitObjectStore:
    def __init__(
        self,
        git_directory: Path,
        *,
        git_executable: str,
        git_environment: Mapping[str, str],
    ) -> None:
        self.git_directory = git_directory.absolute()
        self.git_executable = git_executable
        self._git_environment = dict(git_environment)

    def git(
        self,
        *arguments: str,
        accepted_returncodes: frozenset[int] = frozenset({0}),
    ) -> subprocess.CompletedProcess[bytes]:
        command = (
            self.git_executable,
            f"--git-dir={self.git_directory}",
            "--literal-pathspecs",
            *arguments,
        )
        return _run_command(
            command,
            environment=self._git_environment,
            accepted_returncodes=accepted_returncodes,
        )

    def git_text(self, *arguments: str) -> str:
        output = self.git(*arguments).stdout
        try:
            return output.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise SourceIntegrityError("Git identity output was not ASCII") from exc

    @staticmethod
    def _parse_ls_tree(output: bytes) -> tuple[GitTreeEntry, ...]:
        entries: list[GitTreeEntry] = []
        for raw_record in output.split(b"\0"):
            if not raw_record:
                continue
            try:
                raw_header, raw_path = raw_record.split(b"\t", 1)
                mode, object_type, object_id = raw_header.decode("ascii").split(" ")
                path = raw_path.decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError) as exc:
                raise SourceIntegrityError("malformed or non-UTF-8 Git tree entry") from exc
            if SHA1_PATTERN.fullmatch(object_id) is None:
                raise SourceIntegrityError("Git tree entry has an invalid object ID")
            entries.append(
                GitTreeEntry(
                    path=path,
                    mode=mode,
                    object_type=object_type,
                    object_id=object_id,
                )
            )
        return tuple(entries)

    def commit_tree(self, commit: str) -> str:
        commit_bytes = self.git("cat-file", "commit", commit).stdout
        first_line = commit_bytes.splitlines()[0] if commit_bytes else b""
        if not first_line.startswith(b"tree "):
            raise SourceIntegrityError("commit object has no canonical tree header")
        try:
            tree = first_line.removeprefix(b"tree ").decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise SourceIntegrityError("commit tree ID was not ASCII") from exc
        if SHA1_PATTERN.fullmatch(tree) is None:
            raise SourceIntegrityError("commit tree ID is invalid")
        return tree

    def entry(self, commit: str, path: str) -> GitTreeEntry:
        validate_relative_path(path, "Git source path")
        output = self.git("ls-tree", "-z", "--full-tree", commit, "--", path).stdout
        entries = self._parse_ls_tree(output)
        exact = tuple(item for item in entries if item.path == path)
        if len(exact) != 1:
            raise SourceIntegrityError(f"expected exactly one Git tree entry for {path!r}")
        return exact[0]

    def recursive_inventory(self, commit: str, path: str) -> tuple[GitTreeEntry, ...]:
        validate_relative_path(path, "Git inventory path")
        output = self.git(
            "ls-tree", "-r", "-z", "--full-tree", commit, "--", path
        ).stdout
        return self._parse_ls_tree(output)

    def blob_bytes(self, object_id: str) -> bytes:
        if SHA1_PATTERN.fullmatch(object_id) is None:
            raise SourceIntegrityError("blob object ID is invalid")
        if self.git_text("cat-file", "-t", object_id) != "blob":
            raise SourceIntegrityError(f"Git object {object_id} is not a blob")
        data = self.git("cat-file", "blob", object_id).stdout
        if _git_blob_id(data) != object_id:
            raise SourceIntegrityError(f"Git blob {object_id} failed identity verification")
        return data


def _verify_record(
    store: BareGitObjectStore,
    entry: GitTreeEntry,
    record: ManifestRecord | GeneratedRecord,
) -> bytes:
    if entry.path != record.source_path:
        raise SourceIntegrityError("Git source path does not match manifest record")
    if entry.object_type != "blob":
        raise SourceIntegrityError(f"source entry {entry.path!r} is not a blob")
    if entry.mode != "100644" or entry.mode != record.mode:
        raise SourceIntegrityError(f"source entry {entry.path!r} has a forbidden mode")
    if entry.object_id != record.git_blob:
        raise SourceIntegrityError(f"source entry {entry.path!r} has a blob mismatch")
    data = store.blob_bytes(entry.object_id)
    if len(data) != record.length:
        raise SourceIntegrityError(f"source entry {entry.path!r} has a length mismatch")
    if _sha256(data) != record.sha256:
        raise SourceIntegrityError(f"source entry {entry.path!r} has a SHA-256 mismatch")
    return data


def verified_payloads(
    store: BareGitObjectStore,
    contract: ManifestContract,
) -> dict[str, bytes]:
    """Verify the complete approved inventory and return only 26 served bytes."""

    expected = contract.expectations
    commit_tree = store.commit_tree(expected.source_commit)
    if commit_tree != expected.source_commit_tree:
        raise SourceIntegrityError(
            f"source commit tree mismatch: expected {expected.source_commit_tree}, "
            f"got {commit_tree}"
        )
    subtree = store.entry(expected.source_commit, SOURCE_SUBTREE_PATH)
    if (
        subtree.mode != "040000"
        or subtree.object_type != "tree"
        or subtree.object_id != expected.source_tree
    ):
        raise SourceIntegrityError("frozen Listening subtree identity mismatch")

    source_inventory = store.recursive_inventory(
        expected.source_commit, SOURCE_SUBTREE_PATH
    )
    source_by_path = {item.path: item for item in source_inventory}
    if len(source_by_path) != len(source_inventory):
        raise SourceIntegrityError("duplicate paths appeared in the Git source inventory")
    approved_by_path = {item.source_path: item for item in contract.approved_entries}
    if set(source_by_path) != set(approved_by_path):
        missing = sorted(set(approved_by_path) - set(source_by_path))
        unexpected = sorted(set(source_by_path) - set(approved_by_path))
        raise SourceIntegrityError(
            f"approved source inventory mismatch: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )

    payloads: dict[str, bytes] = {}
    for record in contract.approved_entries:
        data = _verify_record(store, source_by_path[record.source_path], record)
        if record.payload_path is not None:
            payloads[record.payload_path] = data

    for record in contract.generated_dependencies:
        entry = store.entry(expected.source_commit, record.source_path)
        data = _verify_record(store, entry, record)
        if record.artifact_path is not None:
            if record.artifact_path in payloads:
                raise SourceIntegrityError("generated payload path collides at materialization")
            payloads[record.artifact_path] = data

    expected_paths = {
        item.payload_path
        for item in contract.approved_entries
        if item.payload_path is not None
    } | {
        item.artifact_path
        for item in contract.generated_dependencies
        if item.artifact_path is not None
    }
    if set(payloads) != expected_paths:
        raise SourceIntegrityError("served payload inventory changed during verification")
    if len(payloads) != expected.served_payload_entries:
        raise SourceIntegrityError("served payload count changed during verification")
    if sum(len(data) for data in payloads.values()) != expected.served_payload_bytes:
        raise SourceIntegrityError("served payload bytes changed during verification")
    return payloads


def _safe_destination(root: Path, relative_path: str) -> Path:
    canonical = validate_relative_path(relative_path, "staged path")
    destination = root.joinpath(*canonical.split("/"))
    root_text = os.path.normcase(str(root.absolute()))
    destination_text = os.path.normcase(str(destination.absolute()))
    try:
        common = os.path.commonpath((root_text, destination_text))
    except ValueError as exc:
        raise UnsafePathError("staged path crosses filesystem roots") from exc
    if common != root_text:
        raise UnsafePathError("staged path escapes the artifact root")
    return destination


def _write_file(root: Path, relative_path: str, data: bytes) -> None:
    destination = _safe_destination(root, relative_path)
    try:
        current = root
        for segment in validate_relative_path(relative_path, "staged path").split("/")[:-1]:
            current = current / segment
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                pass
            if not current.is_dir() or _is_link_or_reparse(current):
                raise OutputIntegrityError(
                    f"staged parent is not a plain directory: {current}"
                )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o644)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                output.write(data)
                output.flush()
            os.chmod(destination, 0o644)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise OutputIntegrityError(f"cannot write staged file {relative_path!r}: {exc}") from exc


def _relative_output_inventory(
    root: Path,
) -> tuple[tuple[tuple[str, Path], ...], tuple[tuple[str, Path], ...]]:
    if not root.is_dir() or _is_link_or_reparse(root):
        raise OutputIntegrityError("staging root is absent, non-directory, or linked")
    files: list[tuple[str, Path]] = []
    directories: list[tuple[str, Path]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        if _is_link_or_reparse(directory_path):
            raise OutputIntegrityError("linked/reparse directory found in staged output")
        for name in directory_names:
            child = directory_path / name
            if _is_link_or_reparse(child):
                raise OutputIntegrityError("linked/reparse directory found in staged output")
            if not stat.S_ISDIR(child.stat().st_mode):
                raise OutputIntegrityError("non-directory found in staged directory inventory")
            relative = child.relative_to(root).as_posix()
            validate_relative_path(relative, "staged directory path")
            directories.append((relative, child))
        for name in file_names:
            child = directory_path / name
            if _is_link_or_reparse(child):
                raise OutputIntegrityError("linked/reparse file found in staged output")
            if not stat.S_ISREG(child.stat().st_mode):
                raise OutputIntegrityError("non-regular file found in staged output")
            relative = child.relative_to(root).as_posix()
            validate_relative_path(relative, "staged inventory path")
            files.append((relative, child))
    files.sort(key=lambda item: item[0])
    directories.sort(key=lambda item: item[0])
    reject_path_collisions((item[0] for item in files), "staged inventory")
    reject_path_collisions((item[0] for item in directories), "staged directory")
    return tuple(files), tuple(directories)


def verify_staged_output(root: Path, contract: ManifestContract) -> dict[str, Any]:
    root = root.absolute()
    version = contract.expectations.artifact_version
    payload_by_path: dict[str, ManifestRecord | GeneratedRecord] = {}
    for record in contract.approved_entries:
        if record.payload_path is not None:
            payload_by_path[record.payload_path] = record
    for record in contract.generated_dependencies:
        if record.artifact_path is not None:
            payload_by_path[record.artifact_path] = record

    expected_files = {
        "active.json",
        f"{version}/manifest.json",
        *(f"{version}/payload/{path}" for path in payload_by_path),
    }
    expected_directories: set[str] = set()
    for file_path in expected_files:
        segments = file_path.split("/")[:-1]
        for index in range(1, len(segments) + 1):
            expected_directories.add("/".join(segments[:index]))
    inventory, directory_inventory = _relative_output_inventory(root)
    actual_files = {relative for relative, _path in inventory}
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unexpected = sorted(actual_files - expected_files)
        raise OutputIntegrityError(
            f"staged file inventory mismatch: missing={missing!r}, unexpected={unexpected!r}"
        )
    actual_directories = {relative for relative, _path in directory_inventory}
    if actual_directories != expected_directories:
        missing = sorted(expected_directories - actual_directories)
        unexpected = sorted(actual_directories - expected_directories)
        raise OutputIntegrityError(
            f"staged directory inventory mismatch: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )
    if os.name == "posix":
        if stat.S_IMODE(root.stat().st_mode) != 0o755:
            raise OutputIntegrityError("staging root has a noncanonical filesystem mode")
        for _relative, path in inventory:
            if stat.S_IMODE(path.stat().st_mode) != 0o644:
                raise OutputIntegrityError("staged file has a noncanonical filesystem mode")
        for _relative, path in directory_inventory:
            if stat.S_IMODE(path.stat().st_mode) != 0o755:
                raise OutputIntegrityError(
                    "staged directory has a noncanonical filesystem mode"
                )

    active_path = root / "active.json"
    manifest_path = root / version / "manifest.json"
    if active_path.read_bytes() != active_locator_bytes(contract):
        raise OutputIntegrityError("active locator bytes do not match the frozen contract")
    if manifest_path.read_bytes() != contract.raw_bytes:
        raise OutputIntegrityError("staged manifest bytes do not match the canonical input")

    payload_bytes = 0
    for relative, record in sorted(payload_by_path.items()):
        path = root / version / "payload" / Path(*relative.split("/"))
        data = path.read_bytes()
        if len(data) != record.length or _sha256(data) != record.sha256:
            raise OutputIntegrityError(f"staged payload integrity mismatch: {relative!r}")
        if _git_blob_id(data) != record.git_blob:
            raise OutputIntegrityError(f"staged payload Git identity mismatch: {relative!r}")
        payload_bytes += len(data)
    if payload_bytes != contract.expectations.served_payload_bytes:
        raise OutputIntegrityError("staged payload byte total mismatch")

    file_records = []
    for relative, path in inventory:
        data = path.read_bytes()
        file_records.append(
            {
                "path": relative,
                "mode": "100644",
                "length": len(data),
                "sha256": _sha256(data),
            }
        )
    identity_bytes = json.dumps(
        file_records,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "artifact_version": version,
        "source_commit": contract.expectations.source_commit,
        "source_commit_tree": contract.expectations.source_commit_tree,
        "source_tree": contract.expectations.source_tree,
        "manifest_bytes": len(contract.raw_bytes),
        "manifest_sha256": _sha256(contract.raw_bytes),
        "active_bytes": len(active_locator_bytes(contract)),
        "active_sha256": _sha256(active_locator_bytes(contract)),
        "approved_source_entries": len(contract.approved_entries),
        "runtime_source_entries": len(contract.runtime_entries),
        "generated_payload_entries": len(contract.generated_payload_entries),
        "served_payload_entries": len(payload_by_path),
        "served_payload_bytes": payload_bytes,
        "staged_control_files": 2,
        "staged_total_files": len(inventory),
        "unexpected_payload_paths": 0,
        "source_identity_mismatches": 0,
        "manifest_mismatches": 0,
        "private_content_inputs": 0,
        "content_source": "ISOLATED_BARE_GIT_OBJECT_STORE",
        "output_identity_sha256": _sha256(identity_bytes),
        "files": file_records,
    }


def _owned_directory_identity(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ResidualStateError(f"cannot establish {label} ownership: {exc}") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ResidualStateError(f"{label} is not a transaction-owned plain directory")
    return metadata


def _require_owned_directory(
    path: Path, identity: os.stat_result, label: str
) -> bool:
    if not os.path.lexists(path):
        return False
    current = _owned_directory_identity(path, label)
    if not os.path.samestat(identity, current):
        raise ResidualStateError(
            f"{label} identity changed; refusing to remove another transaction's output"
        )
    return True


def _remove_owned_temporary_root(
    temporary_root: Path, identity: os.stat_result
) -> None:
    if not _require_owned_directory(
        temporary_root, identity, "temporary staging root"
    ):
        return
    try:
        shutil.rmtree(temporary_root)
    except OSError as exc:
        if not os.path.lexists(temporary_root):
            return
        raise ResidualStateError(
            f"staging failed and temporary residual state remains at {temporary_root}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if os.path.lexists(temporary_root):
        raise ResidualStateError(
            f"staging failed and temporary residual state remains at {temporary_root}"
        )


def _rollback_published_root(output_root: Path, identity: os.stat_result) -> None:
    if not _require_owned_directory(output_root, identity, "published staging root"):
        return
    quarantine_root = output_root.parent / (
        f".{output_root.name}.failed-{uuid.uuid4().hex}"
    )
    if os.path.lexists(quarantine_root):
        raise ResidualStateError(
            "post-publication verification failed and quarantine path already exists"
        )
    try:
        os.replace(output_root, quarantine_root)
    except OSError as exc:
        raise ResidualStateError(
            "post-publication verification failed and the transaction-owned final "
            f"output could not be quarantined at {output_root}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if os.path.lexists(output_root):
        raise ResidualStateError(
            "post-publication verification failed and the accepted output path was "
            f"repopulated during rollback: {output_root}"
        )
    try:
        if _require_owned_directory(
            quarantine_root, identity, "quarantined staging root"
        ):
            shutil.rmtree(quarantine_root)
    except OSError as exc:
        if not os.path.lexists(quarantine_root):
            return
        raise ResidualStateError(
            "post-publication verification failed; quarantined residual state remains "
            f"at {quarantine_root}: {type(exc).__name__}: {exc}"
        ) from exc
    if os.path.lexists(quarantine_root):
        raise ResidualStateError(
            "post-publication verification failed; quarantined residual state remains "
            f"at {quarantine_root}"
        )


def stage_from_store(
    store: BareGitObjectStore,
    contract: ManifestContract,
    output_root: Path,
) -> dict[str, Any]:
    """Create one verified staging root without consulting a working tree."""

    output_root = output_root.absolute()
    _reject_linked_existing_ancestors(output_root)
    if os.path.lexists(output_root):
        raise OutputIntegrityError("output root must not already exist")
    payloads = verified_payloads(store, contract)
    try:
        output_root.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputIntegrityError(f"cannot create output parent: {exc}") from exc
    temporary_root = output_root.parent / (
        f".{output_root.name}.tmp-{uuid.uuid4().hex}"
    )
    if os.path.lexists(temporary_root):
        raise OutputIntegrityError("temporary staging root unexpectedly exists")
    temporary_identity: os.stat_result | None = None
    published = False
    try:
        temporary_root.mkdir()
        temporary_identity = _owned_directory_identity(
            temporary_root, "temporary staging root"
        )
        version = contract.expectations.artifact_version
        _write_file(temporary_root, "active.json", active_locator_bytes(contract))
        _write_file(temporary_root, f"{version}/manifest.json", contract.raw_bytes)
        for relative_path, data in sorted(payloads.items()):
            _write_file(
                temporary_root,
                f"{version}/payload/{relative_path}",
                data,
            )
        for directory, directory_names, _file_names in os.walk(temporary_root):
            os.chmod(directory, 0o755)
            for name in directory_names:
                os.chmod(Path(directory) / name, 0o755)
        report = verify_staged_output(temporary_root, contract)
        try:
            os.replace(temporary_root, output_root)
        except BaseException as exc:
            try:
                publication_took_effect = _require_owned_directory(
                    output_root, temporary_identity, "published staging root"
                )
            except ResidualStateError as ownership_error:
                raise ResidualStateError(
                    f"publication outcome is ambiguous at {output_root}: "
                    f"{ownership_error}; original failure was "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            if publication_took_effect:
                published = True
                try:
                    _rollback_published_root(output_root, temporary_identity)
                except ResidualStateError as rollback_error:
                    raise ResidualStateError(
                        f"{rollback_error}; original failure was "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
            raise
        published = True
        try:
            final_report = verify_staged_output(output_root, contract)
            return final_report | {
                "pre_publish_output_identity_sha256": report["output_identity_sha256"]
            }
        except BaseException as exc:
            try:
                _rollback_published_root(output_root, temporary_identity)
            except ResidualStateError as rollback_error:
                raise ResidualStateError(
                    f"{rollback_error}; original failure was "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            raise
    except BaseException as exc:
        if not published and temporary_identity is not None:
            try:
                _remove_owned_temporary_root(temporary_root, temporary_identity)
            except ResidualStateError as cleanup_error:
                raise cleanup_error from exc
        raise


def compare_staged_outputs(
    left: Path,
    right: Path,
    contract: ManifestContract,
) -> dict[str, Any]:
    left_report = verify_staged_output(left, contract)
    right_report = verify_staged_output(right, contract)
    if left_report["files"] != right_report["files"]:
        raise OutputIntegrityError("independent staged outputs are not byte-identical")
    if left_report["output_identity_sha256"] != right_report["output_identity_sha256"]:
        raise OutputIntegrityError("independent staged output identities differ")
    return {
        "two_run_reproducibility": "PASS",
        "output_identity_sha256": left_report["output_identity_sha256"],
        "served_payload_entries": left_report["served_payload_entries"],
        "served_payload_bytes": left_report["served_payload_bytes"],
        "unexpected_payload_paths": 0,
        "manifest_mismatches": 0,
        "source_identity_mismatches": 0,
        "private_content_inputs": 0,
    }


def _print_report(report: Mapping[str, Any]) -> None:
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    )


def _stage_command(args: argparse.Namespace) -> dict[str, Any]:
    contract = load_manifest()
    if args.object_store is not None:
        store = acquire_exact_commit(
            EXPECTED_SOURCE_URL,
            EXPECTED_SOURCE_COMMIT,
            Path(args.object_store),
            git_executable=args.git,
        )
        return stage_from_store(store, contract, Path(args.output_root))
    with tempfile.TemporaryDirectory(prefix="ieltmps-public-listening-objects-") as raw:
        object_store = Path(raw) / "source.git"
        store = acquire_exact_commit(
            EXPECTED_SOURCE_URL,
            EXPECTED_SOURCE_COMMIT,
            object_store,
            git_executable=args.git,
        )
        return stage_from_store(store, contract, Path(args.output_root))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage and verify the frozen Issue #79 public Listening artifact.",
        allow_abbrev=False,
    )
    parser.add_argument("--git", default="git", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    stage_parser = commands.add_parser(
        "stage",
        help="acquire the exact source commit and create one new staging root",
        allow_abbrev=False,
    )
    stage_parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="new public-listening-frontend staging root",
    )
    stage_parser.add_argument(
        "--object-store",
        help="new external bare object-store path (temporary when omitted)",
    )

    verify_parser = commands.add_parser(
        "verify", help="verify one existing staging root", allow_abbrev=False
    )
    verify_parser.add_argument("--output-root", required=True)

    compare_parser = commands.add_parser(
        "compare", help="independently verify and compare two staging roots", allow_abbrev=False
    )
    compare_parser.add_argument("--left-output-root", required=True)
    compare_parser.add_argument("--right-output-root", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            report = _stage_command(args)
        elif args.command == "verify":
            report = verify_staged_output(Path(args.output_root), load_manifest())
        elif args.command == "compare":
            report = compare_staged_outputs(
                Path(args.left_output_root),
                Path(args.right_output_root),
                load_manifest(),
            )
        else:  # pragma: no cover - argparse enforces the registry.
            parser.error("unknown command")
        _print_report(report)
        return 0
    except StagingError as exc:
        print(f"public Listening staging failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
