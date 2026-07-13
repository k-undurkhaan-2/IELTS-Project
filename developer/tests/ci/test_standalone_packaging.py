#!/usr/bin/env python3
"""Security and compatibility coverage for the standalone release manifest."""

from __future__ import annotations

from contextlib import contextmanager
import functools
import hashlib
from html.parser import HTMLParser
import http.server
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import unquote, urlsplit
import urllib.request
import uuid
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = Path("developer/standalone-release-manifest.json")
HELPER_PATH = Path("developer/standalone-release-manifest.mjs")
SAFE_SENTINEL = "SAFE_SENTINEL_NOT_A_REAL_SECRET\n"
REQUIRED_STYLES = {
    "src/styles/tokens.css",
    "src/styles/components.css",
    "src/styles/layout.css",
}
MANAGED_ROOTS = ["assets", "css", "js/bundles", "src/styles"]
NON_RELEASE_FILES = {
    "assets/generated/listening-exams/listening-index.compat.js",
    "assets/generated/listening-exams/listening-practice-unified.html",
    "assets/generated/listening-exams/manifest.js",
    "assets/scripts/generate_reading_explanations.py",
    "assets/scripts/generate_reading_explanations_with_agent.py",
}
UNKNOWN_MANAGED_SENTINELS = [
    "assets/private.key",
    "assets/credentials.json",
    "assets/nested/allowed-name.txt",
    "assets/operator/.ssh/id_rsa",
    "js/bundles/runtime-entry.bundle.js.map",
    "css/nested/.npmrc",
    "src/styles/nested/local.css",
]
CANDIDATE_OVERLAY_PATHS = [
    "README.md",
    "developer/release.ps1",
    "developer/release.sh",
    "developer/standalone-release-manifest.json",
    "developer/standalone-release-manifest.mjs",
    "developer/tests/ci/run_static_suite.py",
    "developer/tests/ci/test_standalone_packaging.py",
]


class _IndexAssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.paths: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "link":
            return
        attributes = dict(attrs)
        relations = set((attributes.get("rel") or "").lower().split())
        href = attributes.get("href")
        if "stylesheet" in relations and href:
            self.paths.add(href)


def _command(name: str, env_name: str | None = None) -> str:
    configured = os.environ.get(env_name, "") if env_name else ""
    if configured:
        return configured
    if name == "bash":
        git_bash = Path(r"D:\Git\bin\bash.exe")
        if git_bash.is_file():
            return str(git_bash)
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"required command not found: {name}")
    if name == "bash" and Path(resolved).resolve() == Path(r"C:\Windows\System32\bash.exe"):
        raise RuntimeError("Git Bash is required; WSL launcher is not a usable Bash runtime")
    return resolved


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(file_path: Path) -> str:
    return _sha256_bytes(file_path.read_bytes())


def _content_manifest_sha256(file_hashes: dict[str, str]) -> str:
    source = "".join(f"{path}\t{file_hashes[path]}\n" for path in sorted(file_hashes))
    return _sha256_bytes(source.encode("utf-8"))


def _normalized_file_hashes(
    entries: list[tuple[str, str]],
    label: str,
) -> dict[str, str]:
    file_hashes: dict[str, str] = {}
    portable_paths: set[str] = set()
    for path, sha256 in entries:
        normalized_path = PurePosixPath(path).as_posix()
        if (
            normalized_path != path
            or "\\" in path
            or PurePosixPath(path).is_absolute()
            or re.match(r"^[A-Za-z]:", path)
            or ".." in PurePosixPath(path).parts
        ):
            raise AssertionError(f"{label} contains a non-normalized path: {path}")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise AssertionError(f"{label} contains a non-lowercase SHA-256: {path}")
        portable_path = path.lower()
        if path in file_hashes or portable_path in portable_paths:
            raise AssertionError(f"{label} contains a duplicate or case-colliding path: {path}")
        file_hashes[path] = sha256
        portable_paths.add(portable_path)
    return dict(sorted(file_hashes.items()))


def _source_file_hashes(source_root: Path, relative_paths: list[str]) -> dict[str, str]:
    return _normalized_file_hashes(
        [(relative_path, _sha256_file(source_root / relative_path)) for relative_path in relative_paths],
        "authorized source map",
    )


def _receipt_file_hashes(receipt: dict[str, object]) -> dict[str, str]:
    return _normalized_file_hashes(
        [
            (entry["archivePath"], entry["sha256"])
            for entry in receipt["files"]
        ],
        "staging receipt map",
    )


def _local_asset_path(value: str) -> str | None:
    value = value.strip().strip("\"'")
    if not value or value.startswith(("#", "data:", "blob:", "var(")):
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return None
    return unquote(parsed.path)


def _msys_path(file_path: Path | str) -> str:
    value = Path(file_path).resolve().as_posix()
    match = re.match(r"^([A-Za-z]):/(.*)$", value)
    if match:
        return f"/{match.group(1).lower()}/{match.group(2)}"
    return value


class StandalonePackagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="ielts-standalone-manifest-tests-")
        cls.temp_root = Path(cls.temp_dir.name)
        cls.source_root = cls.temp_root / "candidate-source"
        cls.receipt_root = cls.temp_root / "receipts"
        cls.receipt_root.mkdir()
        cls.node = Path(_command("node", "NODE_EXE"))
        cls.powershell = _command("powershell", "POWERSHELL_EXE")
        cls.bash = _command("bash", "BASH_EXE")
        cls.git = _command("git")
        cls._copy_candidate_tree(cls.source_root)
        cls._initialize_temporary_git_repo(cls.source_root)
        cls.zip_shim_dir = cls._create_zip_shim()
        cls.manifest = json.loads((cls.source_root / MANIFEST_PATH).read_text(encoding="utf-8"))

        cls.absent_windows = cls._build_release("windows", "focused-default-windows")
        cls.absent_unix = cls._build_release("unix", "focused-default-unix")
        cls.source_file_hashes = _source_file_hashes(cls.source_root, cls.manifest["files"])
        cls.extract_root = cls.temp_root / "extracted-default"
        with zipfile.ZipFile(io.BytesIO(cls.absent_windows["archive_bytes"])) as archive:
            archive.extractall(cls.extract_root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    @classmethod
    def _copy_candidate_tree(cls, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        base_archive = cls.temp_root / f"base-{uuid.uuid4().hex}.zip"
        subprocess.run(
            [cls.git, "-C", str(REPO_ROOT), "archive", "--format=zip", "-o", str(base_archive), "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with zipfile.ZipFile(base_archive) as archive:
            archive.extractall(destination)
        for relative_path in CANDIDATE_OVERLAY_PATHS:
            source = REPO_ROOT / relative_path
            if not source.is_file():
                raise AssertionError(f"candidate overlay is missing: {relative_path}")
            target = destination / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    @classmethod
    def _initialize_temporary_git_repo(cls, root: Path) -> None:
        commands = [
            [cls.git, "-C", str(root), "init", "-q"],
            [cls.git, "-C", str(root), "config", "user.name", "Codex TEMP Validation"],
            [cls.git, "-C", str(root), "config", "user.email", "codex-temp@example.invalid"],
            [cls.git, "-C", str(root), "config", "commit.gpgsign", "false"],
            [cls.git, "-C", str(root), "config", "core.autocrlf", "true"],
            [cls.git, "-C", str(root), "add", "-f", "--all"],
            [cls.git, "-C", str(root), "commit", "-q", "-m", "temporary standalone manifest candidate"],
        ]
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @classmethod
    def _create_zip_shim(cls) -> Path:
        shim_dir = cls.temp_root / "unix-zip-shim"
        shim_dir.mkdir()
        python_script = shim_dir / "zip-shim.py"
        python_script.write_text(
            """
import pathlib
import sys
import zipfile

args = sys.argv[1:]
if "-T" in args:
    archive = pathlib.Path(args[args.index("-T") + 1])
    with zipfile.ZipFile(archive, "r") as handle:
        bad = handle.testzip()
    raise SystemExit(1 if bad else 0)

archive_arg = next((arg for arg in args if not arg.startswith("-")), None)
if not archive_arg or "-@" not in args:
    print("unsupported TEMP zip shim invocation", file=sys.stderr)
    raise SystemExit(2)

paths = [line.rstrip("\\r\\n") for line in sys.stdin if line.rstrip("\\r\\n")]
with zipfile.ZipFile(pathlib.Path(archive_arg), "w", compression=zipfile.ZIP_DEFLATED) as handle:
    for name in paths:
        if name.endswith("/"):
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o40775 << 16) | 0x10
            handle.writestr(info, b"")
        else:
            handle.write(pathlib.Path(name), name)
""".lstrip(),
            encoding="utf-8",
        )
        wrapper = shim_dir / "zip"
        wrapper.write_text(
            f'#!/bin/bash\nexec "{_msys_path(Path(sys.executable))}" "{_msys_path(python_script)}" "$@"\n',
            encoding="utf-8",
            newline="\n",
        )
        wrapper.chmod(0o755)
        return shim_dir

    @classmethod
    def _release_env(cls, overrides: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("INCLUDE_LOCAL_LISTENING", None)
        env.pop("READING_PRACTICE_PUBLIC_MANIFEST", None)
        env["PATH"] = str(cls.node.parent) + os.pathsep + env.get("PATH", "")
        if overrides:
            env.update(overrides)
        return env

    @classmethod
    def _run_release(
        cls,
        platform: str,
        version: str,
        *,
        root: Path | None = None,
        overrides: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        source_root = root or cls.source_root
        env = cls._release_env(overrides)
        if platform == "windows":
            command = [
                cls.powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(source_root / "developer/release.ps1"),
                version,
            ]
        elif platform == "unix":
            path_prefix = ":".join([
                "/usr/bin",
                "/mingw64/bin",
                _msys_path(cls.zip_shim_dir),
                _msys_path(cls.node.parent),
            ])
            shell_command = (
                f"export PATH={shlex.quote(path_prefix)}:$PATH; "
                f"cd {shlex.quote(_msys_path(source_root))}; "
                f"bash developer/release.sh {shlex.quote(version)}"
            )
            command = [cls.bash, "-lc", shell_command]
        else:
            raise ValueError(f"unknown release platform: {platform}")

        result = subprocess.run(
            command,
            cwd=source_root,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=240,
        )
        archive_path = source_root / f"dist/ielts-practice-{version}.zip"
        receipt_path = source_root / f"dist/ielts-practice-{version}.release-receipt.json"
        return result, archive_path, receipt_path

    @classmethod
    def _build_release(
        cls,
        platform: str,
        version: str,
        *,
        root: Path | None = None,
        overrides: dict[str, str] | None = None,
    ) -> dict[str, object]:
        result, archive_path, receipt_path = cls._run_release(
            platform,
            version,
            root=root,
            overrides=overrides,
        )
        if result.returncode:
            raise AssertionError(
                f"{platform} release command failed ({result.returncode}):\n{result.stdout}"
            )
        archive_bytes = archive_path.read_bytes()
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt_copy = cls.receipt_root / f"{version}.json"
        shutil.copy2(receipt_path, receipt_copy)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            entries = archive.infolist()
            file_hashes = _normalized_file_hashes(
                [
                    (entry.filename, _sha256_bytes(archive.read(entry)))
                    for entry in entries
                    if not entry.is_dir()
                ],
                f"{platform} archive map",
            )
        return {
            "archive_bytes": archive_bytes,
            "entries": entries,
            "file_hashes": file_hashes,
            "receipt": receipt,
            "receipt_path": receipt_copy,
            "stdout": result.stdout,
        }

    @classmethod
    def _run_helper(
        cls,
        *,
        root: Path | None = None,
        overrides: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, dict[str, object] | None]:
        source_root = root or cls.source_root
        receipt_path = cls.receipt_root / f"helper-{uuid.uuid4().hex}.json"
        result = subprocess.run(
            [
                str(cls.node),
                str(source_root / HELPER_PATH),
                "stage",
                "--project-root",
                str(source_root),
                "--receipt",
                str(receipt_path),
            ],
            cwd=source_root,
            env=cls._release_env(overrides),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        receipt = None
        if result.returncode == 0:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            staging_root = Path(result.stdout.strip()).parent
            shutil.rmtree(staging_root)
        return result, receipt_path, receipt

    @classmethod
    def _write_reading_manifest(cls, entries: list[dict[str, str]]) -> Path:
        manifest_path = cls.temp_root / f"reading-public-{uuid.uuid4().hex}.json"
        manifest_path.write_text(
            json.dumps({"schemaVersion": 1, "files": entries}, indent=2) + "\n",
            encoding="utf-8",
        )
        return manifest_path

    @classmethod
    def _create_reading_files(cls, relative_paths: list[str]) -> list[dict[str, str]]:
        root = cls.source_root / "ReadingPractice"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        entries = []
        for relative_path in relative_paths:
            target = root / PurePosixPath(relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(SAFE_SENTINEL, encoding="utf-8", newline="\n")
            entries.append({"path": relative_path, "sha256": _sha256_file(target)})
        return sorted(entries, key=lambda entry: entry["path"])

    @classmethod
    def _clear_reading(cls) -> None:
        root = cls.source_root / "ReadingPractice"
        if root.exists():
            shutil.rmtree(root)

    @classmethod
    @contextmanager
    def _directory_link(cls, link: Path, target: Path):
        link.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if completed.returncode:
                raise AssertionError(f"failed to create TEMP junction: {completed.stdout}")
        else:
            link.symlink_to(target, target_is_directory=True)
        try:
            yield
        finally:
            if os.name == "nt":
                os.rmdir(link)
            else:
                link.unlink()

    @staticmethod
    def _entry_names(snapshot: dict[str, object]) -> list[str]:
        return [entry.filename for entry in snapshot["entries"]]

    def assertHelperFailure(
        self,
        result: subprocess.CompletedProcess[str],
        expected: str,
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected.lower(), result.stdout.lower())

    def assertFileHashMapsEqual(
        self,
        expected: dict[str, str],
        actual: dict[str, str],
        *,
        expected_label: str,
        actual_label: str,
    ) -> None:
        missing_paths = sorted(set(expected) - set(actual))
        extra_paths = sorted(set(actual) - set(expected))
        hash_mismatch_paths = sorted(
            path
            for path in set(expected) & set(actual)
            if expected[path] != actual[path]
        )
        if missing_paths or extra_paths or hash_mismatch_paths:
            self.fail(
                f"{actual_label} differs from {expected_label}; "
                f"missing paths={missing_paths}; extra paths={extra_paths}; "
                f"hash-mismatch paths={hash_mismatch_paths}"
            )

    def test_default_windows_and_unix_release_use_one_positive_manifest(self) -> None:
        manifest_files = set(self.manifest["files"])
        self.assertEqual(len(manifest_files), 430)
        self.assertEqual(self.manifest["managedRoots"], MANAGED_ROOTS)
        self.assertSetEqual(set(self.manifest["nonReleaseFiles"]), NON_RELEASE_FILES)
        self.assertSetEqual(set(self.source_file_hashes), manifest_files)
        source_content_manifest_sha256 = _content_manifest_sha256(self.source_file_hashes)

        for platform, snapshot in (
            ("Windows", self.absent_windows),
            ("Unix", self.absent_unix),
        ):
            file_names = {
                entry.filename for entry in snapshot["entries"]
                if not entry.is_dir()
            }
            receipt_file_hashes = _receipt_file_hashes(snapshot["receipt"])
            self.assertSetEqual(file_names, manifest_files)
            self.assertEqual(len(snapshot["entries"]), len({entry.filename for entry in snapshot["entries"]}))
            self.assertFileHashMapsEqual(
                self.source_file_hashes,
                receipt_file_hashes,
                expected_label="current authorized source map",
                actual_label=f"{platform} staging receipt map",
            )
            self.assertFileHashMapsEqual(
                self.source_file_hashes,
                snapshot["file_hashes"],
                expected_label="current authorized source map",
                actual_label=f"{platform} archive map",
            )
            self.assertEqual(
                _content_manifest_sha256(receipt_file_hashes),
                source_content_manifest_sha256,
            )
            self.assertEqual(
                _content_manifest_sha256(snapshot["file_hashes"]),
                source_content_manifest_sha256,
            )
            self.assertEqual(snapshot["receipt"]["mainManifest"]["fileCount"], 430)
            self.assertEqual(snapshot["receipt"]["managedRoots"], MANAGED_ROOTS)
            self.assertEqual(snapshot["receipt"]["effectiveReadingFiles"], [])
            self.assertFalse(any(name.startswith("ReadingPractice/") for name in file_names))
            self.assertFalse(any(name.startswith("ListeningPractice/") for name in file_names))
            self.assertFalse(any(name.startswith("assets/generated/listening-exams/") for name in file_names))
            self.assertIn("js/bundles/listening-wrapper.bundle.js", file_names)

        self.assertEqual(
            self.absent_windows["file_hashes"],
            self.absent_unix["file_hashes"],
        )
        self.assertSetEqual(
            set(self._entry_names(self.absent_windows)),
            set(self._entry_names(self.absent_unix)),
        )

    def test_main_manifest_missing_malformed_schema_and_paths_fail_closed(self) -> None:
        manifest_path = self.source_root / MANIFEST_PATH
        original = manifest_path.read_bytes()
        backup = self.temp_root / f"manifest-backup-{uuid.uuid4().hex}.json"
        manifest_path.rename(backup)
        try:
            result, _receipt_path, _receipt = self._run_helper()
            self.assertHelperFailure(result, "manifest is missing")
        finally:
            backup.rename(manifest_path)

        cases: list[tuple[str, bytes, str]] = []
        cases.append(("malformed", b"{", "malformed json"))
        for name, mutate, expected in [
            ("schema", lambda value: value.__setitem__("schemaVersion", 2), "schemaVersion"),
            ("duplicate", lambda value: value["files"].append(value["files"][0]), "duplicate"),
            ("absolute", lambda value: value["files"].__setitem__(0, "C:/absolute.txt"), "relative"),
            ("traversal", lambda value: value["files"].__setitem__(0, "../escape.txt"), "'..' segment"),
            ("backslash", lambda value: value["files"].__setitem__(0, r"assets\escape.txt"), "separators"),
            (
                "listening-generated",
                lambda value: value["files"].__setitem__(
                    slice(None),
                    sorted([
                        *value["files"][1:],
                        "assets/generated/listening-exams/manifest.js",
                    ]),
                ),
                "forbidden release scope",
            ),
        ]:
            candidate = json.loads(original.decode("utf-8"))
            mutate(candidate)
            cases.append((name, (json.dumps(candidate, indent=2) + "\n").encode(), expected))

        for name, content, expected in cases:
            with self.subTest(name=name):
                manifest_path.write_bytes(content)
                try:
                    result, _receipt_path, _receipt = self._run_helper()
                    self.assertHelperFailure(result, expected)
                finally:
                    manifest_path.write_bytes(original)

    def test_required_and_manifest_listed_files_fail_closed_when_missing(self) -> None:
        for relative_path in ["index.html", "assets/data/path-map.json"]:
            with self.subTest(relative_path=relative_path):
                source = self.source_root / relative_path
                backup = self.temp_root / f"missing-{uuid.uuid4().hex}"
                source.rename(backup)
                try:
                    result, _receipt_path, _receipt = self._run_helper()
                    self.assertHelperFailure(result, "missing")
                finally:
                    backup.rename(source)

    def test_required_root_fails_before_zip_on_windows_and_unix(self) -> None:
        source = self.source_root / "src/styles"
        backup = self.temp_root / f"styles-missing-{uuid.uuid4().hex}"
        source.rename(backup)
        try:
            for platform in ("windows", "unix"):
                with self.subTest(platform=platform):
                    result, archive_path, _receipt_path = self._run_release(
                        platform,
                        f"missing-root-{platform}",
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("src/styles", result.stdout)
                    self.assertFalse(archive_path.exists())
        finally:
            backup.rename(source)

    def test_manifest_listed_path_reparse_fails_closed(self) -> None:
        styles = self.source_root / "src/styles"
        target = self.temp_root / f"styles-target-{uuid.uuid4().hex}"
        styles.rename(target)
        try:
            with self._directory_link(styles, target):
                result, _receipt_path, _receipt = self._run_helper()
                self.assertHelperFailure(result, "reparse")
        finally:
            target.rename(styles)

    def test_git_manifest_and_payload_dirty_changes_fail_closed(self) -> None:
        manifest_path = self.source_root / MANIFEST_PATH
        original_manifest = manifest_path.read_bytes()
        manifest_path.write_bytes(original_manifest + b" \n")
        try:
            result, _receipt_path, _receipt = self._run_helper()
            self.assertHelperFailure(result, "clean in git")
        finally:
            manifest_path.write_bytes(original_manifest)

        payload_path = self.source_root / "index.html"
        original_payload = payload_path.read_bytes()
        payload_path.write_bytes(original_payload + b"\n<!-- SAFE_SENTINEL_NOT_A_REAL_SECRET -->\n")
        try:
            result, _receipt_path, _receipt = self._run_helper()
            self.assertHelperFailure(result, "clean in git")
        finally:
            payload_path.write_bytes(original_payload)

        payload_path.write_bytes(original_payload + b"\n<!-- SAFE_SENTINEL_NOT_A_REAL_SECRET -->\n")
        subprocess.run(
            [self.git, "-C", str(self.source_root), "add", "index.html"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            result, _receipt_path, _receipt = self._run_helper()
            self.assertHelperFailure(result, "clean in git")
        finally:
            payload_path.write_bytes(original_payload)
            subprocess.run(
                [self.git, "-C", str(self.source_root), "add", "index.html"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        cached = subprocess.run(
            [self.git, "-C", str(self.source_root), "diff", "--cached", "--quiet"],
        )
        self.assertEqual(cached.returncode, 0)

    def test_clean_no_git_source_archive_still_releases_safely(self) -> None:
        no_git_root = self.temp_root / "no-git-source"
        shutil.copytree(
            self.source_root,
            no_git_root,
            ignore=shutil.ignore_patterns("dist"),
        )
        for git_file in (no_git_root / ".git").rglob("*"):
            if git_file.is_file():
                git_file.chmod(stat.S_IWRITE)
        shutil.rmtree(no_git_root / ".git")
        self.assertFalse((no_git_root / ".git").exists())
        no_git_source_file_hashes = _source_file_hashes(no_git_root, self.manifest["files"])
        self.assertFileHashMapsEqual(
            self.source_file_hashes,
            no_git_source_file_hashes,
            expected_label="tracked current source map",
            actual_label="no-Git source map",
        )
        snapshot = self._build_release(
            "windows",
            "focused-no-git",
            root=no_git_root,
        )
        receipt_file_hashes = _receipt_file_hashes(snapshot["receipt"])
        self.assertFalse(snapshot["receipt"]["git"]["repository"])
        self.assertSetEqual(set(snapshot["file_hashes"]), set(self.manifest["files"]))
        self.assertFileHashMapsEqual(
            no_git_source_file_hashes,
            receipt_file_hashes,
            expected_label="no-Git source map",
            actual_label="no-Git staging receipt map",
        )
        self.assertFileHashMapsEqual(
            no_git_source_file_hashes,
            snapshot["file_hashes"],
            expected_label="no-Git source map",
            actual_label="no-Git archive map",
        )
        no_git_content_manifest_sha256 = _content_manifest_sha256(no_git_source_file_hashes)
        self.assertEqual(_content_manifest_sha256(receipt_file_hashes), no_git_content_manifest_sha256)
        self.assertEqual(_content_manifest_sha256(snapshot["file_hashes"]), no_git_content_manifest_sha256)

    def test_unknown_files_in_every_managed_root_fail_before_staging(self) -> None:
        for relative_path in UNKNOWN_MANAGED_SENTINELS:
            with self.subTest(relative_path=relative_path):
                sentinel = self.source_root / PurePosixPath(relative_path)
                sentinel.parent.mkdir(parents=True, exist_ok=True)
                sentinel.write_text(SAFE_SENTINEL, encoding="utf-8", newline="\n")
                try:
                    result, receipt_path, _receipt = self._run_helper()
                    self.assertHelperFailure(result, "unknown files")
                    self.assertFalse(receipt_path.exists())
                finally:
                    sentinel.unlink()
                    parent = sentinel.parent
                    while parent != self.source_root and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent

    def test_reading_root_requires_explicit_manifest(self) -> None:
        self._create_reading_files(["public-example.txt"])
        try:
            result, _receipt_path, _receipt = self._run_helper()
            self.assertHelperFailure(result, "is present but is not authorized")
        finally:
            self._clear_reading()

    def test_authorized_reading_has_real_windows_unix_parity_and_hashes(self) -> None:
        entries = self._create_reading_files([
            "nested/public-example.html",
            "public-example.txt",
        ])
        manifest_path = self._write_reading_manifest(entries)
        overrides = {"READING_PRACTICE_PUBLIC_MANIFEST": str(manifest_path)}
        try:
            windows = self._build_release(
                "windows",
                "focused-reading-windows",
                overrides=overrides,
            )
            unix = self._build_release(
                "unix",
                "focused-reading-unix",
                overrides=overrides,
            )
        finally:
            self._clear_reading()

        self.assertEqual(windows["file_hashes"], unix["file_hashes"])
        self.assertSetEqual(
            set(self._entry_names(windows)),
            set(self._entry_names(unix)),
        )
        reading_paths = {f"ReadingPractice/{entry['path']}" for entry in entries}
        self.assertSetEqual(
            {path for path in windows["file_hashes"] if path.startswith("ReadingPractice/")},
            reading_paths,
        )
        for entry in entries:
            self.assertEqual(
                windows["file_hashes"][f"ReadingPractice/{entry['path']}"],
                entry["sha256"],
            )
        self.assertNotIn(manifest_path.name, self._entry_names(windows))
        self.assertEqual(windows["receipt"]["effectiveReadingFiles"], sorted(reading_paths))

    def test_reading_hash_missing_duplicate_and_unsafe_paths_fail_closed(self) -> None:
        valid_entries = self._create_reading_files(["public-example.txt"])
        valid_hash = valid_entries[0]["sha256"]
        cases = [
            (
                "hash-mismatch",
                [{"path": "public-example.txt", "sha256": "0" * 64}],
                "sha-256 mismatch",
            ),
            (
                "duplicate",
                [valid_entries[0], valid_entries[0]],
                "duplicate",
            ),
            (
                "traversal",
                [{"path": "../escape.txt", "sha256": valid_hash}],
                "'..' segment",
            ),
            (
                "absolute",
                [{"path": "C:/absolute.txt", "sha256": valid_hash}],
                "relative",
            ),
            (
                "backslash",
                [{"path": r"nested\file.txt", "sha256": valid_hash}],
                "separators",
            ),
        ]
        try:
            for name, entries, expected in cases:
                with self.subTest(name=name):
                    manifest_path = self._write_reading_manifest(entries)
                    result, _receipt_path, _receipt = self._run_helper(
                        overrides={"READING_PRACTICE_PUBLIC_MANIFEST": str(manifest_path)}
                    )
                    self.assertHelperFailure(result, expected)
        finally:
            self._clear_reading()

        (self.source_root / "ReadingPractice").mkdir()
        missing_manifest = self._write_reading_manifest([
            {"path": "missing.txt", "sha256": _sha256_bytes(SAFE_SENTINEL.encode("utf-8"))}
        ])
        try:
            result, _receipt_path, _receipt = self._run_helper(
                overrides={"READING_PRACTICE_PUBLIC_MANIFEST": str(missing_manifest)}
            )
            self.assertHelperFailure(result, "lists missing files")
        finally:
            self._clear_reading()

    def test_reading_unknown_and_hidden_files_fail_closed(self) -> None:
        for extra_path in ["unlisted.txt", ".hidden"]:
            with self.subTest(extra_path=extra_path):
                entries = self._create_reading_files(["public-example.txt", extra_path])
                manifest_path = self._write_reading_manifest([
                    entry for entry in entries if entry["path"] == "public-example.txt"
                ])
                try:
                    result, _receipt_path, _receipt = self._run_helper(
                        overrides={"READING_PRACTICE_PUBLIC_MANIFEST": str(manifest_path)}
                    )
                    self.assertHelperFailure(result, "not authorized")
                finally:
                    self._clear_reading()

    def test_reading_file_and_external_manifest_reparse_fail_closed(self) -> None:
        reading_root = self.source_root / "ReadingPractice"
        reading_root.mkdir()
        target = self.temp_root / f"reading-target-{uuid.uuid4().hex}"
        target.mkdir()
        target_file = target / "public-example.txt"
        target_file.write_text(SAFE_SENTINEL, encoding="utf-8", newline="\n")
        manifest_path = self._write_reading_manifest([
            {"path": "nested/public-example.txt", "sha256": _sha256_file(target_file)}
        ])
        try:
            with self._directory_link(reading_root / "nested", target):
                result, _receipt_path, _receipt = self._run_helper(
                    overrides={"READING_PRACTICE_PUBLIC_MANIFEST": str(manifest_path)}
                )
                self.assertHelperFailure(result, "reparse")
        finally:
            self._clear_reading()

        entries = self._create_reading_files(["public-example.txt"])
        manifest_target_dir = self.temp_root / f"manifest-target-{uuid.uuid4().hex}"
        manifest_target_dir.mkdir()
        target_manifest = manifest_target_dir / "reading.json"
        target_manifest.write_text(
            json.dumps({"schemaVersion": 1, "files": entries}, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_link = self.temp_root / f"manifest-link-{uuid.uuid4().hex}"
        try:
            with self._directory_link(manifest_link, manifest_target_dir):
                result, _receipt_path, _receipt = self._run_helper(
                    overrides={"READING_PRACTICE_PUBLIC_MANIFEST": str(manifest_link / "reading.json")}
                )
                self.assertHelperFailure(result, "reparse")
        finally:
            self._clear_reading()

    def test_private_listening_switch_fails_and_root_is_not_scanned(self) -> None:
        private_root = self.source_root / "ListeningPractice/P1"
        private_root.mkdir(parents=True)
        (private_root / "SAFE_SENTINEL.txt").write_text(
            SAFE_SENTINEL,
            encoding="utf-8",
            newline="\n",
        )
        try:
            result, _receipt_path, receipt = self._run_helper()
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(any(
                entry["archivePath"].startswith("ListeningPractice/")
                for entry in receipt["files"]
            ))

            result, receipt_path, _receipt = self._run_helper(
                overrides={"INCLUDE_LOCAL_LISTENING": "1"}
            )
            self.assertHelperFailure(result, "no longer supported")
            self.assertFalse(receipt_path.exists())
        finally:
            shutil.rmtree(self.source_root / "ListeningPractice")

    def test_archive_list_verifier_rejects_duplicate_and_unsafe_entries(self) -> None:
        receipt_path = Path(self.absent_windows["receipt_path"])
        expected = self._entry_names(self.absent_windows)
        cases = {
            "duplicate": [*expected, expected[0]],
            "absolute": [*expected[:-1], "C:/absolute.txt"],
            "traversal": [*expected[:-1], "../escape.txt"],
            "backslash": [*expected[:-1], r"css\main.css"],
            "dangerous": [*expected[:-1], "assets/private.key"],
        }
        for name, entries in cases.items():
            with self.subTest(name=name):
                archive_list = self.temp_root / f"archive-list-{name}-{uuid.uuid4().hex}.txt"
                archive_list.write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")
                result = subprocess.run(
                    [
                        str(self.node),
                        str(self.source_root / HELPER_PATH),
                        "verify-archive-list",
                        "--receipt",
                        str(receipt_path),
                        "--archive-list",
                        str(archive_list),
                    ],
                    cwd=self.source_root,
                    env=self._release_env(),
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_archive_entries_are_unique_portable_relative_and_not_symlinks(self) -> None:
        for snapshot in (self.absent_windows, self.absent_unix):
            names = self._entry_names(snapshot)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(len(names), len({name.lower() for name in names}))
            for entry in snapshot["entries"]:
                name = entry.filename
                value = name[:-1] if name.endswith("/") else name
                path_value = PurePosixPath(value)
                self.assertNotIn("\\", name)
                self.assertFalse(path_value.is_absolute(), name)
                self.assertIsNone(re.match(r"^[A-Za-z]:", name), name)
                self.assertNotIn("..", path_value.parts, name)
                unix_mode = entry.external_attr >> 16
                self.assertFalse(stat.S_ISLNK(unix_mode), name)
                self.assertNotIn(str(self.source_root).replace("\\", "/"), name)

    def test_extracted_payload_is_self_contained_and_serves_required_styles(self) -> None:
        parser = _IndexAssetParser()
        parser.feed((self.extract_root / "index.html").read_text(encoding="utf-8"))
        missing: list[str] = []
        for value in parser.paths:
            local_path = _local_asset_path(value)
            if local_path and not (self.extract_root / local_path.lstrip("/")).is_file():
                missing.append(value)

        css_url_pattern = re.compile(r"url\(\s*([^)]*?)\s*\)", re.IGNORECASE)
        for css_path in self.extract_root.rglob("*.css"):
            css_source = css_path.read_text(encoding="utf-8")
            for match in css_url_pattern.finditer(css_source):
                local_path = _local_asset_path(match.group(1))
                if not local_path:
                    continue
                target = (css_path.parent / local_path).resolve()
                try:
                    target.relative_to(self.extract_root.resolve())
                except ValueError:
                    missing.append(f"unsafe CSS URL in {css_path}: {local_path}")
                    continue
                if not target.is_file():
                    missing.append(f"{css_path.relative_to(self.extract_root)} -> {local_path}")
        self.assertEqual(missing, [])

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                return

        handler = functools.partial(QuietHandler, directory=str(self.extract_root))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}/"
            for relative_path in ["index.html", *sorted(REQUIRED_STYLES)]:
                with urllib.request.urlopen(base_url + relative_path, timeout=5) as response:
                    self.assertEqual(response.status, 200, relative_path)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        tokens = (self.extract_root / "src/styles/tokens.css").read_text(encoding="utf-8")
        consumers = "\n".join(
            (self.extract_root / relative_path).read_text(encoding="utf-8")
            for relative_path in ("src/styles/components.css", "src/styles/layout.css")
        )
        for token in ("--background", "--accent", "--space-4"):
            self.assertRegex(tokens, rf"{re.escape(token)}\s*:\s*[^;]+;")
            self.assertIn(f"var({token})", consumers)

    def test_scripts_consume_only_the_shared_manifest_helper_staging_contract(self) -> None:
        powershell_source = (REPO_ROOT / "developer/release.ps1").read_text(encoding="utf-8")
        shell_source = (REPO_ROOT / "developer/release.sh").read_text(encoding="utf-8")
        helper_name = "developer/standalone-release-manifest.mjs"
        for source in (powershell_source, shell_source):
            self.assertIn("standalone-release-manifest.mjs", source)
            self.assertIn("stage", source)
            self.assertIn("verify-archive-list", source)
        self.assertNotIn("Get-ChildItem -LiteralPath $item.FullName -Recurse", powershell_source)
        self.assertNotIn("zip -r", shell_source)
        self.assertNotIn("READING_ZIP_INPUTS", shell_source)
        self.assertNotIn("LISTENING_ZIP_INPUTS", shell_source)
        self.assertTrue(helper_name.endswith(".mjs"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
