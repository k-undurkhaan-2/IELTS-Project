#!/usr/bin/env python3
"""Focused regression coverage for the standalone release archive."""

from __future__ import annotations

import collections
import functools
import hashlib
import http.server
from html.parser import HTMLParser
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import unquote, urlsplit
import urllib.request
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[3]
REQUIRED_STYLES = {
    "src/styles/tokens.css",
    "src/styles/components.css",
    "src/styles/layout.css",
}
FUTURE_STYLE = "src/styles/future-public-style.css"
READING_FIXTURE = "ReadingPractice/example-public-fixture.txt"


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
    resolved = configured or shutil.which(name)
    if not resolved:
        raise RuntimeError(f"required command not found: {name}")
    return resolved


def _git_paths(*args: str) -> list[str]:
    if not args:
        raise ValueError("git subcommand is required")
    result = subprocess.run(
        [_command("git"), "-C", str(REPO_ROOT), args[0], "-z", *args[1:]],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def _is_excluded(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    name = path.name
    lowered_suffix = path.suffix.lower()
    if name == ".DS_Store" or name.startswith("~$"):
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    if lowered_suffix in {".mov", ".mp4", ".md", ".py", ".log", ".tmp", ".temp", ".bak"}:
        return True
    if relative_path == ".gitignore" or relative_path == ".git" or relative_path.startswith(".git/"):
        return True
    if relative_path == ".claude" or relative_path.startswith(".claude/"):
        return True
    if relative_path == "node_modules" or relative_path.startswith("node_modules/"):
        return True
    if relative_path == "assets/developer" or relative_path.startswith("assets/developer/"):
        return True
    if relative_path == "assets/generated/listening-exams" or relative_path.startswith("assets/generated/listening-exams/"):
        return True
    if relative_path == "ListeningPractice" or relative_path.startswith("ListeningPractice/"):
        return True
    return False


def _local_asset_path(value: str) -> str | None:
    value = value.strip().strip("\"'")
    if not value or value.startswith(("#", "data:", "blob:", "var(")):
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return None
    return unquote(parsed.path)


class StandalonePackagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="ielts-standalone-packaging-")
        cls.source_root = Path(cls.temp_dir.name) / "source"
        cls.source_root.mkdir()

        tracked_paths = _git_paths("ls-files")
        for relative_path in tracked_paths:
            source = REPO_ROOT / relative_path
            if not source.is_file():
                continue
            destination = cls.source_root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        reading_root = cls.source_root / "ReadingPractice"
        if reading_root.exists():
            raise AssertionError("tracked-only snapshot unexpectedly contains ReadingPractice/")

        future_style = cls.source_root / FUTURE_STYLE
        future_style.write_text(":root { --future-public-style: 1; }\n", encoding="utf-8")
        (cls.source_root / "src/styles/.env").write_text("DO_NOT_PACKAGE=1\n", encoding="utf-8")
        (cls.source_root / "src/styles/local-output.tmp").write_text("temporary\n", encoding="utf-8")

        cls.absent_windows = cls._build_release("windows", "focused-absent-windows")
        cls.absent_unix = cls._build_release("unix", "focused-absent-unix")
        cls.absent_windows_repeat = cls._build_release("windows", "focused-absent-windows-repeat")
        cls.extract_root = Path(cls.temp_dir.name) / "extracted"
        with zipfile.ZipFile(io.BytesIO(cls.absent_windows["archive_bytes"])) as archive:
            archive.extractall(cls.extract_root)

        reading_fixture = cls.source_root / READING_FIXTURE
        reading_fixture.parent.mkdir(parents=True)
        reading_fixture.write_text("public reading fixture\n", encoding="utf-8")
        cls.present_windows = cls._build_release("windows", "focused-present-windows")
        cls.present_unix = cls._build_release("unix", "focused-present-unix")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    @classmethod
    def _run_release(cls, platform: str, version: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        node = Path(_command("node", "NODE_EXE"))
        env = os.environ.copy()
        env["PATH"] = str(node.parent) + os.pathsep + env.get("PATH", "")
        if platform == "windows":
            command = [
                _command("powershell"),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(cls.source_root / "developer/release.ps1"),
                version,
            ]
        elif platform == "unix":
            unix_release_image = env.get("UNIX_RELEASE_IMAGE", "")
            if unix_release_image:
                command = [
                    _command("docker"),
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--volume",
                    f"{cls.source_root}:/workspace",
                    "--workdir",
                    "/workspace",
                    "--entrypoint",
                    "bash",
                    unix_release_image,
                    "developer/release.sh",
                    version,
                ]
            else:
                command = [_command("bash", "BASH_EXE"), "developer/release.sh", version]
        else:
            raise ValueError(f"unknown release platform: {platform}")

        result = subprocess.run(
            command,
            cwd=cls.source_root,
            env=env,
            text=True,
            encoding="utf-8" if platform == "unix" else None,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
        archive_path = cls.source_root / f"dist/ielts-practice-{version}.zip"
        return result, archive_path

    @classmethod
    def _build_release(cls, platform: str, version: str) -> dict[str, object]:
        result, archive_path = cls._run_release(platform, version)
        if result.returncode:
            raise AssertionError(
                f"{platform} release command failed ({result.returncode}):\n{result.stdout}"
            )
        archive_bytes = archive_path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            entries = archive.infolist()
            file_hashes = {
                entry.filename: hashlib.sha256(archive.read(entry)).hexdigest()
                for entry in entries
                if not entry.is_dir()
            }
        return {
            "archive_bytes": archive_bytes,
            "entries": entries,
            "file_hashes": file_hashes,
            "stdout": result.stdout,
        }

    @staticmethod
    def _entry_names(snapshot: dict[str, object]) -> list[str]:
        return [entry.filename for entry in snapshot["entries"]]

    def test_all_public_styles_are_included_once_and_future_styles_follow_the_rule(self) -> None:
        names = [entry.filename for entry in self.present_windows["entries"] if not entry.is_dir()]
        counts = collections.Counter(names)
        tracked_styles = {
            path for path in _git_paths("ls-files", "--", "src/styles")
            if not _is_excluded(path)
        }
        self.assertTrue(REQUIRED_STYLES.issubset(tracked_styles))
        for style_path in tracked_styles | {FUTURE_STYLE}:
            self.assertEqual(counts[style_path], 1, style_path)

    def test_archive_scope_matches_the_public_runtime_allowlist(self) -> None:
        actual_files = {
            entry.filename for entry in self.present_windows["entries"]
            if not entry.is_dir()
        }
        expected_files: set[str] = set()
        for relative_root in ("index.html", "css", "js/bundles", "assets", "ReadingPractice", "src/styles"):
            root = self.source_root / relative_root
            candidates = [root] if root.is_file() else root.rglob("*")
            for candidate in candidates:
                if not candidate.is_file():
                    continue
                relative_path = candidate.relative_to(self.source_root).as_posix()
                if not _is_excluded(relative_path):
                    expected_files.add(relative_path)
        self.assertSetEqual(actual_files, expected_files)

        forbidden_prefixes = (
            ".git/",
            "node_modules/",
            "developer/tests/",
            "backend/",
            "templates/",
            "ListeningPractice/",
            "js/app/",
            "js/core/",
            "js/data/",
            "js/runtime/",
            "js/services/",
        )
        self.assertFalse(any(name.startswith(forbidden_prefixes) for name in actual_files))
        self.assertFalse(any(PurePosixPath(name).name == ".env" for name in actual_files))
        self.assertFalse(any(PurePosixPath(name).name.startswith(".env.") for name in actual_files))
        self.assertFalse(any(PurePosixPath(name).suffix.lower() in {".log", ".tmp", ".temp", ".bak"} for name in actual_files))
        self.assertFalse(any(PurePosixPath(name).name in {"WORKTREE_GUARD.md", "IELTS_WORKTREE_ROUTING.md"} for name in actual_files))

    def test_entries_are_unique_portable_relative_paths_without_symlinks(self) -> None:
        names = self._entry_names(self.present_windows)
        self.assertEqual(len(names), len(set(names)))
        for entry in self.present_windows["entries"]:
            name = entry.filename
            path = PurePosixPath(name)
            self.assertNotIn("\\", name)
            self.assertFalse(path.is_absolute(), name)
            self.assertIsNone(re.match(r"^[A-Za-z]:", name), name)
            self.assertNotIn("..", path.parts, name)
            unix_mode = entry.external_attr >> 16
            self.assertFalse(stat.S_ISLNK(unix_mode), name)

    def test_repeat_build_preserves_the_same_unique_entry_set(self) -> None:
        first = self._entry_names(self.absent_windows)
        second = self._entry_names(self.absent_windows_repeat)
        self.assertEqual(first, second)
        self.assertEqual(len(second), len(set(second)))

    def test_reading_practice_absent_has_real_cross_platform_archive_parity(self) -> None:
        windows_names = self._entry_names(self.absent_windows)
        unix_names = self._entry_names(self.absent_unix)
        for names in (windows_names, unix_names):
            self.assertFalse(any(name.startswith("ReadingPractice/") for name in names))
            counts = collections.Counter(names)
            for required_style in REQUIRED_STYLES:
                self.assertEqual(counts[required_style], 1, required_style)
        self.assertSetEqual(set(windows_names), set(unix_names))
        self.assertDictEqual(
            self.absent_windows["file_hashes"],
            self.absent_unix["file_hashes"],
        )
        self.assertIn(
            "Optional release input skipped: ReadingPractice/",
            self.absent_unix["stdout"],
        )

    def test_reading_practice_present_has_real_cross_platform_archive_parity(self) -> None:
        windows_names = self._entry_names(self.present_windows)
        unix_names = self._entry_names(self.present_unix)
        self.assertEqual(windows_names.count(READING_FIXTURE), 1)
        self.assertEqual(unix_names.count(READING_FIXTURE), 1)
        self.assertSetEqual(set(windows_names), set(unix_names))
        self.assertDictEqual(
            self.present_windows["file_hashes"],
            self.present_unix["file_hashes"],
        )

        absent_hashes = self.absent_windows["file_hashes"]
        present_hashes = self.present_windows["file_hashes"]
        self.assertSetEqual(set(present_hashes) - set(absent_hashes), {READING_FIXTURE})
        self.assertDictEqual(
            {name: present_hashes[name] for name in absent_hashes},
            absent_hashes,
        )

    def test_required_release_root_stays_fail_closed_on_windows_and_unix(self) -> None:
        required_root = self.source_root / "src/styles"
        temporary_backup = self.source_root / "src/styles-required-root-backup"
        required_root.rename(temporary_backup)
        try:
            for platform in ("windows", "unix"):
                with self.subTest(platform=platform):
                    result, _archive_path = self._run_release(
                        platform,
                        f"focused-missing-required-{platform}",
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("src/styles", result.stdout)
        finally:
            temporary_backup.rename(required_root)

    def test_extracted_html_and_css_references_are_self_contained(self) -> None:
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

    def test_extracted_static_server_serves_styles_and_core_tokens(self) -> None:
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

    def test_windows_and_unix_release_entries_stay_in_sync(self) -> None:
        powershell_source = (REPO_ROOT / "developer/release.ps1").read_text(encoding="utf-8")
        shell_source = (REPO_ROOT / "developer/release.sh").read_text(encoding="utf-8")
        for required in REQUIRED_STYLES:
            self.assertIn(required, powershell_source)
            self.assertIn(required, shell_source)
        self.assertIn("'src/styles'", powershell_source)
        self.assertIn("src/styles/", shell_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
