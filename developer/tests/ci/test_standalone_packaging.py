#!/usr/bin/env python3
"""Focused regression coverage for the standalone release archive."""

from __future__ import annotations

import collections
import functools
import http.server
from html.parser import HTMLParser
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

        future_style = cls.source_root / FUTURE_STYLE
        future_style.write_text(":root { --future-public-style: 1; }\n", encoding="utf-8")
        (cls.source_root / "src/styles/.env").write_text("DO_NOT_PACKAGE=1\n", encoding="utf-8")
        (cls.source_root / "src/styles/local-output.tmp").write_text("temporary\n", encoding="utf-8")

        cls.first_entries = cls._build_release()
        cls.second_entries = cls._build_release()
        cls.archive_path = cls.source_root / "dist/ielts-practice-focused-test.zip"
        cls.extract_root = Path(cls.temp_dir.name) / "extracted"
        with zipfile.ZipFile(cls.archive_path) as archive:
            archive.extractall(cls.extract_root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    @classmethod
    def _build_release(cls) -> list[zipfile.ZipInfo]:
        node = Path(_command("node", "NODE_EXE"))
        powershell = _command("powershell")
        env = os.environ.copy()
        env["PATH"] = str(node.parent) + os.pathsep + env.get("PATH", "")
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(cls.source_root / "developer/release.ps1"),
                "focused-test",
            ],
            cwd=cls.source_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        if result.returncode:
            raise AssertionError(f"release command failed ({result.returncode}):\n{result.stdout}")
        archive_path = cls.source_root / "dist/ielts-practice-focused-test.zip"
        with zipfile.ZipFile(archive_path) as archive:
            return archive.infolist()

    def test_all_public_styles_are_included_once_and_future_styles_follow_the_rule(self) -> None:
        names = [entry.filename for entry in self.second_entries if not entry.is_dir()]
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
            entry.filename for entry in self.second_entries
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
        names = [entry.filename for entry in self.second_entries]
        self.assertEqual(len(names), len(set(names)))
        for entry in self.second_entries:
            name = entry.filename
            path = PurePosixPath(name)
            self.assertNotIn("\\", name)
            self.assertFalse(path.is_absolute(), name)
            self.assertIsNone(re.match(r"^[A-Za-z]:", name), name)
            self.assertNotIn("..", path.parts, name)
            unix_mode = entry.external_attr >> 16
            self.assertFalse(stat.S_ISLNK(unix_mode), name)

    def test_repeat_build_preserves_the_same_unique_entry_set(self) -> None:
        first = [entry.filename for entry in self.first_entries]
        second = [entry.filename for entry in self.second_entries]
        self.assertEqual(first, second)
        self.assertEqual(len(second), len(set(second)))

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
