#!/usr/bin/env python3
"""Synthetic end-to-end tests for the public-source tree materializer."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
MATERIALIZER = REPO_ROOT / "developer/prepare-public-source-tree.mjs"
VERIFIER = REPO_ROOT / "developer/verify-public-source-membership.mjs"
MANIFEST = REPO_ROOT / "developer/public-source-manifest.json"
MANIFEST_RELATIVE = "developer/public-source-manifest.json"
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


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class PreparePublicSourceTreeTest(unittest.TestCase):
    """All repositories, output trees, aliases and canaries live in TEMP."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.node = _find_node()
        cls.git = _find_git()
        if not MATERIALIZER.is_file() or not VERIFIER.is_file() or not MANIFEST.is_file():
            raise unittest.SkipTest("working-tree materializer, verifier or manifest is unavailable")

        cls.manifest_bytes = MANIFEST.read_bytes()
        cls.manifest_value = json.loads(cls.manifest_bytes.decode("utf-8"))
        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-source-tree-template-"
        )
        cls.template_root = Path(cls.template_temp.name).resolve() / "fixture"
        cls.template_root.mkdir()

        cls.expected_bytes: dict[str, bytes] = {}
        exact_paths: set[str] = set()
        for component in cls.manifest_value["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            value = (
                cls.manifest_bytes
                if relative == MANIFEST_RELATIVE
                else f"placeholder:{relative}\n".encode("utf-8")
            )
            cls.expected_bytes[relative] = value

        cls.expected_bytes.update(
            {
                "backend/admin/binary-nul.bin": b"prefix\x00middle\x00suffix\n",
                "backend/auth/empty.bin": b"",
                "backend/migrations/001_init.sql": b"SELECT 1;\n",
                "backend/scripts/executable.sh": b"#!/bin/sh\nprintf synthetic\n",
                "backend/src/non-utf8.bin": b"\x80\x81\xfe\xff\x00\n",
                "backend/test/app.test.js": b"export const test = true;\n",
                "css/lf.css": b"body { color: black; }\n",
                "js/crlf.js": b"const first = 1;\r\nconst second = 2;\r\n",
                "src/styles/app.css": b":root { --fixture: 1; }\n",
            }
        )
        for relative, value in cls.expected_bytes.items():
            cls._write_at(cls.template_root, relative, value)

        cls._git_at(cls.template_root, "init")
        for key, value in (
            ("user.name", "Source Tree Test"),
            ("user.email", "source-tree-test@example.invalid"),
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
        cls._git_at(cls.template_root, "commit", "-m", "synthetic source tree baseline")
        cls.template_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()
        cls.expected_modes = {
            relative: (
                "100755" if relative == "backend/scripts/executable.sh" else "100644"
            )
            for relative in cls.expected_bytes
        }
        cls.expected_directories = cls._required_directories(cls.expected_bytes)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-source-tree-case-"
        )
        self.temp_root = Path(self.case_temp.name).resolve()
        self.fixture_root = self.temp_root / "fixture"
        shutil.copytree(self.template_root, self.fixture_root)
        self.base_commit = self._head()
        self.output_path = self.temp_root / "public-source"
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

    def _manifest(self) -> dict[str, object]:
        return json.loads(
            (self.fixture_root / MANIFEST_RELATIVE).read_text(encoding="utf-8")
        )

    def _commit_manifest(
        self, message: str, mutate: Callable[[dict[str, object]], None]
    ) -> str:
        value = self._manifest()
        mutate(value)
        (self.fixture_root / MANIFEST_RELATIVE).write_bytes(_json_bytes(value))
        return self._commit_paths(message, MANIFEST_RELATIVE)

    def _component(self, value: dict[str, object], component_id: str) -> dict[str, object]:
        return next(
            component
            for component in value["components"]
            if component["id"] == component_id
        )

    def _hash_blob(self, value: bytes = b"synthetic blob\n") -> str:
        return self._git(
            "hash-object", "-w", "--stdin", input_bytes=value
        ).stdout.decode("ascii").strip()

    def _plumbing_commit(
        self,
        entries: list[tuple[str, str, str]],
        message: str,
    ) -> str:
        self._git("read-tree", self.base_commit)
        for mode, object_id, relative in entries:
            record = (
                f"{mode} {object_id}\t".encode("ascii")
                + relative.encode("utf-8")
                + b"\0"
            )
            self._git(
                "-c",
                "core.protectNTFS=false",
                "update-index",
                "-z",
                "--index-info",
                input_bytes=record,
            )
        tree_id = self._git("write-tree").stdout.decode("ascii").strip()
        return self._git(
            "commit-tree",
            tree_id,
            "-p",
            self.base_commit,
            input_bytes=(message + "\n").encode("utf-8"),
        ).stdout.decode("ascii").strip()

    def _commit_raw_paths(self, *paths: str) -> str:
        return self._plumbing_commit(
            [
                ("100644", self._hash_blob((value + "\n").encode("utf-8")), value)
                for value in paths
            ],
            "synthetic raw paths",
        )

    @staticmethod
    def _required_directories(files: object) -> set[str]:
        directories: set[str] = set()
        for relative in files:
            parent = PurePosixPath(relative).parent
            while parent != PurePosixPath("."):
                directories.add(parent.as_posix())
                parent = parent.parent
        return directories

    def _run_cli(
        self,
        *,
        commit: str | None = None,
        output: Path | str | None = None,
        repo: Path | str | None = None,
        extra_args: list[str] | None = None,
        environment_updates: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(MATERIALIZER),
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
        if environment_updates:
            environment.update(environment_updates)
        return subprocess.run(
            argv,
            cwd=self.temp_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
        )

    def _run_imported(
        self,
        action: str,
        *,
        commit: str | None = None,
        output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = self._environment()
        environment.update(
            {
                "IELTMPS_TEST_MATERIALIZER": str(MATERIALIZER),
                "IELTMPS_TEST_REPO": str(self.fixture_root),
                "IELTMPS_TEST_COMMIT": commit or self.base_commit,
                "IELTMPS_TEST_OUTPUT": str(output or self.output_path),
                "IELTMPS_TEST_ACTION": action,
            }
        )
        script = r"""
import {
  chmodSync,
  cpSync,
  linkSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const materializerUrl = pathToFileURL(
  process.env.IELTMPS_TEST_MATERIALIZER,
).href;
const { materializePublicSourceTree } = await import(materializerUrl);
const action = process.env.IELTMPS_TEST_ACTION;
const finalOutput = process.env.IELTMPS_TEST_OUTPUT;
const seen = [];
let acted = false;

const testHooks = async (context) => {
  seen.push(context.checkpoint);
  if (action === `throw:${context.checkpoint}`) {
    throw new Error("synthetic checkpoint failure with private canary");
  }
  if (acted) {
    return "ignored callback return value";
  }
  if (action === "truncate" && context.checkpoint === "before-read-back") {
    const bytes = readFileSync(context.stagedFilePath);
    if (bytes.length > 0) {
      truncateSync(context.stagedFilePath, bytes.length - 1);
      acted = true;
    }
  } else if (action === "mutate" && context.checkpoint === "before-read-back") {
    const bytes = readFileSync(context.stagedFilePath);
    if (bytes.length > 0) {
      bytes[0] ^= 0xff;
      writeFileSync(context.stagedFilePath, bytes);
      acted = true;
    }
  } else if (
    action === "unexpected-preexisting"
    && context.checkpoint === "after-member-write"
    && context.memberIndex === 0
  ) {
    writeFileSync(path.join(context.stagingRoot, "LICENSE.md"), "unexpected");
    acted = true;
  } else if (action === "extra-file" && context.checkpoint === "before-full-walk") {
    writeFileSync(path.join(context.stagingRoot, "unexpected-extra.txt"), "extra");
    acted = true;
  } else if (action === "extra-directory" && context.checkpoint === "before-full-walk") {
    mkdirSync(path.join(context.stagingRoot, "unexpected-empty-directory"));
    acted = true;
  } else if (action === "hardlink" && context.checkpoint === "before-full-walk") {
    linkSync(
      path.join(context.stagingRoot, "LICENSE"),
      path.join(context.stagingRoot, "unexpected-hardlink"),
    );
    acted = true;
  } else if (action === "symlink-entry" && context.checkpoint === "before-full-walk") {
    symlinkSync(
      "LICENSE",
      path.join(context.stagingRoot, "unexpected-symlink"),
      "file",
    );
    acted = true;
  } else if (
    action === "file-identity"
    && context.checkpoint === "after-read-back"
    && context.memberIndex === 0
  ) {
    const bytes = readFileSync(context.stagedFilePath);
    unlinkSync(context.stagedFilePath);
    writeFileSync(context.stagedFilePath, bytes);
    if (process.platform !== "win32") {
      chmodSync(context.stagedFilePath, 0o644);
    }
    acted = true;
  } else if (
    action === "directory-identity"
    && context.checkpoint === "before-full-walk"
  ) {
    const original = path.join(context.stagingRoot, "css");
    const saved = context.stagingRoot + "-saved-directory";
    renameSync(original, saved);
    mkdirSync(original);
    for (const name of readdirSync(saved)) {
      cpSync(
        path.join(saved, name),
        path.join(original, name),
        { recursive: true },
      );
    }
    acted = true;
  } else if (action === "final-appears" && context.checkpoint === "before-publish") {
    mkdirSync(finalOutput);
    writeFileSync(path.join(finalOutput, "sentinel.txt"), "appeared before publish\n");
    acted = true;
  } else if (
    action === "cleanup-identity-mismatch"
    && context.checkpoint === "before-publish"
  ) {
    const saved = context.stagingRoot + "-original";
    renameSync(context.stagingRoot, saved);
    mkdirSync(context.stagingRoot);
    writeFileSync(path.join(context.stagingRoot, "sentinel.txt"), "suspect\n");
    acted = true;
    throw new Error("synthetic cleanup identity mismatch");
  }
  return "ignored callback return value";
};

try {
  const summary = await materializePublicSourceTree({
    repo: process.env.IELTMPS_TEST_REPO,
    commit: process.env.IELTMPS_TEST_COMMIT,
    output: finalOutput,
    testHooks,
  });
  process.stdout.write(JSON.stringify({ ok: true, summary, seen }) + "\n");
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    code: error.code,
    name: error.name,
    message: error.message,
    seen,
  }) + "\n");
  process.exitCode = 1;
}
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
            timeout=90,
        )

    def _assert_cli_success(
        self, result: subprocess.CompletedProcess[str]
    ) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.endswith("\n"))
        self.assertEqual(result.stdout.count("\n"), 1)
        return json.loads(result.stdout)

    def _assert_cli_failure(
        self,
        result: subprocess.CompletedProcess[str],
        code: str,
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith(f"ERROR {code}:"), result.stderr)
        self.assertNotIn("\n    at ", result.stderr)

    def _read_imported_result(
        self, result: subprocess.CompletedProcess[str]
    ) -> dict[str, object]:
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.endswith("\n"), result.stdout)
        return json.loads(result.stdout)

    @staticmethod
    def _tree_snapshot(root: Path) -> tuple[dict[str, bytes], set[str]]:
        files: dict[str, bytes] = {}
        directories: set[str] = set()
        for current_text, directory_names, file_names in os.walk(
            root, topdown=True, followlinks=False
        ):
            current = Path(current_text)
            for name in directory_names:
                target = current / name
                if target.is_symlink():
                    raise AssertionError(f"unexpected symlink: {target}")
                directories.add(target.relative_to(root).as_posix())
            for name in file_names:
                target = current / name
                if target.is_symlink() or not target.is_file():
                    raise AssertionError(f"unexpected nonregular file: {target}")
                files[target.relative_to(root).as_posix()] = target.read_bytes()
        return files, directories

    def _assert_exact_tree(self, output: Path | None = None) -> None:
        selected = output or self.output_path
        files, directories = self._tree_snapshot(selected)
        self.assertEqual(files, self.expected_bytes)
        self.assertEqual(directories, self.expected_directories)
        for relative in directories:
            self.assertTrue(any(path.startswith(relative + "/") for path in files))

    def _staging_siblings(self, output: Path | None = None) -> list[Path]:
        selected = output or self.output_path
        prefix = f".{selected.name}.ieltmps-source-tmp-"
        return [
            entry
            for entry in selected.parent.iterdir()
            if entry.name.startswith(prefix)
        ]

    def _assert_no_staging(self, output: Path | None = None) -> None:
        self.assertEqual(self._staging_siblings(output), [])

    def _assert_success_summary(self, summary: dict[str, object]) -> None:
        self.assertEqual(
            list(summary),
            [
                "status",
                "mode",
                "sourceCommit",
                "manifestSha256",
                "membershipReportSha256",
                "membershipCount",
                "membershipValid",
                "treeMaterialized",
                "correspondingSourceComplete",
                "publicationBlocked",
            ],
        )
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["mode"], "tree-materialization")
        self.assertEqual(summary["sourceCommit"], self.base_commit)
        self.assertEqual(summary["manifestSha256"], _sha256(self.manifest_bytes))
        self.assertRegex(summary["membershipReportSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["membershipCount"], len(self.expected_bytes))
        self.assertTrue(summary["membershipValid"])
        self.assertTrue(summary["treeMaterialized"])
        self.assertFalse(summary["correspondingSourceComplete"])
        self.assertTrue(summary["publicationBlocked"])

    def test_01_valid_tree_is_exact_private_and_tree_only(self) -> None:
        result = self._run_cli()
        summary = self._assert_cli_success(result)
        self._assert_success_summary(summary)
        self._assert_exact_tree()
        self._assert_no_staging()
        self.assertEqual(self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n")
        self.assertNotIn(str(self.fixture_root), result.stdout)
        self.assertNotIn(str(self.output_path), result.stdout)
        self.assertNotIn(str(self.temp_root), result.stdout)
        self.assertFalse((self.output_path / ".git").exists())
        self.assertFalse((self.output_path / "membership-report.json").exists())
        self.assertFalse((self.output_path / ".ieltmps-public-context.json").exists())
        files, _ = self._tree_snapshot(self.output_path)
        forbidden_suffixes = (".zip", ".tar", ".tar.gz", ".tgz")
        self.assertFalse(any(name.lower().endswith(forbidden_suffixes) for name in files))

    def test_02_binary_empty_lf_crlf_and_non_utf8_bytes_are_preserved(self) -> None:
        self._assert_cli_success(self._run_cli())
        checks = {
            "backend/admin/binary-nul.bin": b"prefix\x00middle\x00suffix\n",
            "backend/auth/empty.bin": b"",
            "css/lf.css": b"body { color: black; }\n",
            "js/crlf.js": b"const first = 1;\r\nconst second = 2;\r\n",
            "backend/src/non-utf8.bin": b"\x80\x81\xfe\xff\x00\n",
        }
        for relative, expected in checks.items():
            with self.subTest(relative=relative):
                actual = (self.output_path / PurePosixPath(relative)).read_bytes()
                self.assertEqual(actual, expected)
                self.assertEqual(_sha256(actual), _sha256(expected))

    def test_03_dirty_selected_source_and_dirty_manifest_are_ignored(self) -> None:
        self._write("index.html", b"dirty selected source\x00\xff\n")
        (self.fixture_root / MANIFEST_RELATIVE).write_text(
            '{"dirty":"manifest"}\n', encoding="utf-8", newline="\n"
        )
        self._assert_cli_success(self._run_cli())
        self._assert_exact_tree()

    def test_04_untracked_manifest_cannot_replace_missing_commit_manifest(self) -> None:
        self._git("rm", "--cached", "--", MANIFEST_RELATIVE)
        self._git("commit", "-m", "manifest absent from selected commit")
        commit = self._head()
        self.assertTrue((self.fixture_root / MANIFEST_RELATIVE).is_file())
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_05_replacement_commit_is_ignored(self) -> None:
        self._write("index.html", b"replacement bytes\n")
        replacement_commit = self._commit_paths("replacement", "index.html")
        self._git("replace", self.base_commit, replacement_commit)
        self._assert_cli_success(self._run_cli(commit=self.base_commit))
        self._assert_exact_tree()

    def test_06_hostile_inherited_git_environment_is_ignored(self) -> None:
        hostile = self.temp_root / "hostile-git-canary"
        updates = {
            "GIT_DIR": str(hostile / "dir"),
            "GIT_WORK_TREE": str(hostile / "worktree"),
            "GIT_INDEX_FILE": str(hostile / "index"),
            "GIT_OBJECT_DIRECTORY": str(hostile / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(hostile / "alternate"),
            "GIT_REPLACE_REF_BASE": "refs/replace-hostile/",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(hostile / "hooks"),
        }
        self._assert_cli_success(self._run_cli(environment_updates=updates))
        self._assert_exact_tree()
        self.assertFalse(hostile.exists())

    def test_07_repeated_materializations_have_identical_paths_and_bytes(self) -> None:
        second_output = self.temp_root / "public-source-second"
        first_summary = self._assert_cli_success(self._run_cli())
        second_summary = self._assert_cli_success(self._run_cli(output=second_output))
        self.assertEqual(self._tree_snapshot(self.output_path), self._tree_snapshot(second_output))
        self.assertEqual(first_summary, second_summary)
        self._assert_no_staging()
        self._assert_no_staging(second_output)

    def test_08_git_modes_follow_the_host_contract(self) -> None:
        result = self._run_cli()
        self._assert_cli_success(result)
        regular = self.output_path / "index.html"
        executable = self.output_path / "backend/scripts/executable.sh"
        self.assertTrue(regular.is_file())
        self.assertTrue(executable.is_file())
        git_entry = self._git(
            "ls-tree", self.base_commit, "--", "backend/scripts/executable.sh"
        ).stdout.decode("ascii")
        self.assertTrue(git_entry.startswith("100755 blob "), git_entry)
        if os.name == "nt":
            self.assertNotIn("executable", result.stdout.lower())
            self.assertNotIn("modepreserved", result.stdout.lower())
        else:
            self.assertEqual(stat.S_IMODE(regular.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)

    def test_09_relative_output_is_rejected(self) -> None:
        result = self._run_cli(output="relative-output-canary")
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertFalse((self.temp_root / "relative-output-canary").exists())

    def test_10_output_inside_repository_is_rejected(self) -> None:
        output = self.fixture_root / "generated-source"
        result = self._run_cli(output=output)
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertFalse(output.exists())

    def test_11_output_equal_to_repository_is_rejected(self) -> None:
        result = self._run_cli(output=self.fixture_root)
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertTrue((self.fixture_root / ".git").exists())

    def test_12_repository_prefix_sibling_is_not_confused_with_containment(self) -> None:
        sibling_parent = self.temp_root / "fixture-other"
        sibling_parent.mkdir()
        output = sibling_parent / "public-source"
        self._assert_cli_success(self._run_cli(output=output))
        self._assert_exact_tree(output)

    def test_13_existing_output_is_rejected_preserved_and_not_merged(self) -> None:
        self.output_path.mkdir()
        sentinel = self.output_path / "existing-sentinel.txt"
        sentinel.write_bytes(b"do not overwrite or merge\n")
        result = self._run_cli()
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertEqual(sentinel.read_bytes(), b"do not overwrite or merge\n")
        self.assertEqual(list(self.output_path.iterdir()), [sentinel])

    def test_14_unsafe_or_unnormalized_final_components_are_rejected(self) -> None:
        unsafe_values = [".", "..", "CON", "name.", "name ", "name:stream", "bad\tname"]
        for index, component in enumerate(unsafe_values):
            with self.subTest(component=repr(component)):
                if component in {".", ".."}:
                    output: str | Path = (
                        str(self.temp_root / "boundary") + os.sep + component
                    )
                else:
                    output = str(self.temp_root / component)
                result = self._run_cli(output=output)
                self._assert_cli_failure(result, "OUTPUT_PARENT")
                self.assertEqual(self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n")

        unnormalized = str(self.temp_root / "normal") + os.sep + ".." + os.sep + "normalized"
        self._assert_cli_failure(
            self._run_cli(output=unnormalized),
            "OUTPUT_PARENT",
        )

    @unittest.skipUnless(os.name == "nt", "Windows UNC/device syntax is host-specific")
    def test_15_windows_unc_and_device_paths_are_rejected(self) -> None:
        values = [
            r"\\server\share\public-source",
            r"\\?\C:\ieltmps\public-source",
            r"\\.\C:\ieltmps\public-source",
        ]
        for value in values:
            with self.subTest(value=value):
                self._assert_cli_failure(
                    self._run_cli(output=value),
                    "OUTPUT_PARENT",
                )

    def test_16_symlink_output_parent_is_rejected(self) -> None:
        real_parent = self.temp_root / "real-output-parent"
        linked_parent = self.temp_root / "linked-output-parent"
        real_parent.mkdir()
        try:
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"host cannot create a directory symlink: {error}")
        result = self._run_cli(output=linked_parent / "public-source")
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertEqual(list(real_parent.iterdir()), [])

    def test_17_parent_alias_to_repository_is_rejected(self) -> None:
        alias = self.temp_root / "repository-alias"
        try:
            alias.symlink_to(self.fixture_root, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"host cannot create a directory symlink: {error}")
        result = self._run_cli(output=alias / "aliased-output")
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertFalse((self.fixture_root / "aliased-output").exists())

    def test_18_missing_output_parent_is_rejected_without_recursive_creation(self) -> None:
        output = self.temp_root / "missing-parent" / "public-source"
        result = self._run_cli(output=output)
        self._assert_cli_failure(result, "OUTPUT_PARENT")
        self.assertFalse(output.parent.exists())

    def test_19_final_output_appearing_before_publish_is_preserved(self) -> None:
        result = self._run_imported("final-appears")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "PUBLISH")
        sentinel = self.output_path / "sentinel.txt"
        self.assertEqual(sentinel.read_bytes(), b"appeared before publish\n")
        self._assert_no_staging()

    def test_20_production_cli_rejects_test_and_failure_injection_flags(self) -> None:
        for flag in ["--test-hooks", "--fail-before-publish", "--materialize"]:
            with self.subTest(flag=flag):
                result = self._run_cli(extra_args=[flag, "1"])
                self._assert_cli_failure(result, "CLI")
                self.assertFalse(self.output_path.exists())

    def test_21_mandatory_denial_prevents_materialization(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selectors = self._component(value, "eligible-server-source")["selectors"]
            selectors["includeExact"].append("backend/docker-compose.yml")
            selectors["includeExact"].sort()

        commit = self._commit_manifest("select denied path", mutate)
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_22_selected_git_symlink_prevents_materialization(self) -> None:
        commit = self._plumbing_commit(
            [("120000", self._hash_blob(b"target\n"), "css/link.css")],
            "synthetic selected symlink",
        )
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_23_selected_gitlink_prevents_materialization(self) -> None:
        commit = self._plumbing_commit(
            [("160000", self.base_commit, "backend/src/vendor")],
            "synthetic selected gitlink",
        )
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_24_case_collision_prevents_materialization(self) -> None:
        commit = self._commit_raw_paths("css/Collision.css", "css/collision.css")
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_25_unicode_normalization_collision_prevents_materialization(self) -> None:
        commit = self._commit_raw_paths("css/caf\u00e9.css", "css/cafe\u0301.css")
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_26_relative_escape_selector_prevents_materialization(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selectors = self._component(value, "frontend-preferred-source")["selectors"]
            selectors["includeExact"].append("../escape-canary")
            selectors["includeExact"].sort()

        commit = self._commit_manifest("relative escape selector", mutate)
        result = self._run_cli(commit=commit)
        self._assert_cli_failure(result, "MEMBERSHIP")
        self.assertFalse(self.output_path.exists())

    def test_27_unexpected_preexisting_staging_member_fails_and_cleans(self) -> None:
        result = self._run_imported("unexpected-preexisting")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "MEMBER_WRITE")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()
        self.assertEqual(self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n")

    def test_28_extra_directory_injected_before_audit_fails_and_cleans(self) -> None:
        result = self._run_imported("extra-directory")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_29_extra_file_injected_before_audit_fails_and_cleans(self) -> None:
        result = self._run_imported("extra-file")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_30_hardlink_injection_fails_where_supported(self) -> None:
        source = self.temp_root / "hardlink-capability-source"
        target = self.temp_root / "hardlink-capability-target"
        source.write_bytes(b"hardlink capability\n")
        try:
            os.link(source, target)
        except OSError as error:
            self.skipTest(f"host cannot create a same-volume hardlink: {error}")
        target.unlink()
        source.unlink()
        result = self._run_imported("hardlink")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_31_symlink_injection_fails_where_supported(self) -> None:
        target = self.temp_root / "symlink-capability-target"
        link = self.temp_root / "symlink-capability-link"
        target.write_bytes(b"symlink capability\n")
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"host cannot create a file symlink: {error}")
        link.unlink()
        target.unlink()
        result = self._run_imported("symlink-entry")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_32_file_identity_replacement_fails(self) -> None:
        result = self._run_imported("file-identity")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_33_directory_identity_replacement_fails_when_observable(self) -> None:
        css_state = os.stat(self.fixture_root / "css")
        if css_state.st_ino == 0:
            self.skipTest("host reports no observable directory inode identity")
        result = self._run_imported("directory-identity")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "TREE_AUDIT")
        self.assertFalse(self.output_path.exists())
        saved = [entry for entry in self.temp_root.iterdir() if entry.name.endswith("-saved-directory")]
        self.assertEqual(len(saved), 1)
        active_staging = [
            entry
            for entry in self._staging_siblings()
            if not entry.name.endswith("-saved-directory")
        ]
        self.assertEqual(active_staging, [])

    def test_34_every_fixed_checkpoint_fails_closed_and_cleans(self) -> None:
        expected_codes = {
            "after-member-write": "MEMBER_WRITE",
            "before-read-back": "MEMBER_READBACK",
            "after-read-back": "MEMBER_READBACK",
            "before-full-walk": "TREE_AUDIT",
            "before-publish": "PUBLISH",
        }
        private_canaries = [
            str(self.fixture_root),
            str(self.temp_root),
            "synthetic checkpoint failure with private canary",
        ]
        for index, (checkpoint, expected_code) in enumerate(expected_codes.items()):
            with self.subTest(checkpoint=checkpoint):
                output = self.temp_root / f"checkpoint-output-{index}"
                result = self._run_imported(f"throw:{checkpoint}", output=output)
                payload = self._read_imported_result(result)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["code"], expected_code)
                self.assertIn(checkpoint, payload["seen"])
                self.assertFalse(output.exists())
                self._assert_no_staging(output)
                for canary in private_canaries:
                    self.assertNotIn(canary, result.stdout)
                    self.assertNotIn(canary, result.stderr)
                self.assertEqual(
                    self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n"
                )

    def test_35_truncated_write_is_detected_by_readback_and_cleaned(self) -> None:
        result = self._run_imported("truncate")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "MEMBER_READBACK")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_36_same_size_hash_mismatch_is_detected_and_cleaned(self) -> None:
        result = self._run_imported("mutate")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "MEMBER_READBACK")
        self.assertFalse(self.output_path.exists())
        self._assert_no_staging()

    def test_37_cleanup_identity_mismatch_leaves_suspect_entries_untouched(self) -> None:
        result = self._run_imported("cleanup-identity-mismatch")
        payload = self._read_imported_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload["code"], "CLEANUP")
        self.assertFalse(self.output_path.exists())
        staging_entries = self._staging_siblings()
        self.assertGreaterEqual(len(staging_entries), 2)
        suspect = next(
            entry for entry in staging_entries if (entry / "sentinel.txt").is_file()
        )
        self.assertEqual((suspect / "sentinel.txt").read_bytes(), b"suspect\n")
        self.assertEqual(self.unrelated_sentinel.read_bytes(), b"unrelated sentinel\n")

    def test_38_import_is_silent_git_free_and_does_not_execute_cli(self) -> None:
        shim_root = self.temp_root / "git-shim"
        shim_root.mkdir()
        marker = self.temp_root / "git-invoked-marker"
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
        environment["IELTMPS_TEST_MATERIALIZER"] = str(MATERIALIZER)
        environment["IELTMPS_TEST_GIT_MARKER"] = str(marker)
        environment["PATH"] = os.pathsep.join(
            [str(shim_root), str(self.node.parent), environment.get("PATH", "")]
        )
        script = r"""
import { pathToFileURL } from "node:url";
const before = process.exitCode;
await import(pathToFileURL(process.env.IELTMPS_TEST_MATERIALIZER).href);
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
        self.assertFalse(marker.exists())
        self.assertFalse(self.output_path.exists())

    def test_39_production_diagnostics_redact_all_path_and_member_canaries(self) -> None:
        rejected_member = "css/rejected-private-member-canary.pem"
        self._write(rejected_member, b"private canary\n")
        rejected_commit = self._commit_paths("rejected member", rejected_member)
        existing = self.temp_root / "private-output-canary"
        existing.mkdir()
        cases = [
            self._run_cli(commit=rejected_commit),
            self._run_cli(output=existing),
            self._run_cli(output="relative-private-output-canary"),
        ]
        canaries = [
            str(self.fixture_root),
            str(self.output_path),
            str(self.temp_root),
            rejected_member,
            "relative-private-output-canary",
        ]
        for result in cases:
            self.assertNotEqual(result.returncode, 0)
            combined = result.stdout + result.stderr
            for canary in canaries:
                self.assertNotIn(canary, combined)
            self.assertNotIn(" at ", combined)

    def test_40_environment_cannot_enable_test_hooks(self) -> None:
        summary = self._assert_cli_success(
            self._run_cli(
                environment_updates={
                    "IELTMPS_PUBLIC_SOURCE_TREE_TEST_HOOK": "before-publish",
                    "IELTMPS_PUBLIC_SOURCE_TREE_FAIL": "1",
                }
            )
        )
        self._assert_success_summary(summary)
        self._assert_exact_tree()

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows host capability")
    def test_41_junction_output_parent_is_rejected_where_supported(self) -> None:
        real_parent = self.temp_root / "junction-real-parent"
        junction_parent = self.temp_root / "junction-parent"
        real_parent.mkdir()
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction_parent), str(real_parent)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if completed.returncode != 0:
            self.skipTest(f"host cannot create a junction: {completed.stdout.strip()}")
        try:
            result = self._run_cli(output=junction_parent / "public-source")
            self._assert_cli_failure(result, "OUTPUT_PARENT")
            self.assertEqual(list(real_parent.iterdir()), [])
        finally:
            os.rmdir(junction_parent)

    def test_42_duplicate_missing_unknown_and_positional_cli_arguments_fail(self) -> None:
        duplicate = self._run_cli(extra_args=["--repo", str(self.fixture_root)])
        unknown = self._run_cli(extra_args=["--archive", "zip"])
        positional = self._run_cli(extra_args=["positional-canary"])
        missing = subprocess.run(
            [
                str(self.node),
                str(MATERIALIZER),
                "--repo",
                str(self.fixture_root),
                "--commit",
                self.base_commit,
            ],
            cwd=self.temp_root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        for result in [duplicate, unknown, positional, missing]:
            self._assert_cli_failure(result, "CLI")
        self.assertFalse(self.output_path.exists())

    def test_43_imported_hook_return_values_are_ignored_on_success(self) -> None:
        result = self._run_imported("none")
        payload = self._read_imported_result(result)
        self.assertEqual(result.returncode, 0, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(
            set(payload["seen"]),
            {
                "after-member-write",
                "before-read-back",
                "after-read-back",
                "before-full-walk",
                "before-publish",
            },
        )
        self._assert_success_summary(payload["summary"])
        self._assert_exact_tree()

    def test_44_materializer_has_no_git_or_child_process_implementation(self) -> None:
        source = MATERIALIZER.read_text(encoding="utf-8")
        self.assertNotIn("node:child_process", source)
        self.assertNotIn("spawnSync", source)
        self.assertNotIn("execFile", source)
        self.assertIn("loadValidatedPublicSourceMembership", source)

    def test_45_direct_alias_executes_cli_and_alias_import_is_side_effect_free(self) -> None:
        real_tool_root = self.temp_root / "alternate-real-tool"
        real_developer = real_tool_root / "developer"
        real_developer.mkdir(parents=True)
        real_materializer = real_developer / MATERIALIZER.name
        real_verifier = real_developer / VERIFIER.name
        shutil.copy2(MATERIALIZER, real_materializer)
        shutil.copy2(VERIFIER, real_verifier)
        self.assertNotEqual(real_materializer.resolve(), MATERIALIZER.resolve())
        self.assertNotEqual(real_verifier.resolve(), VERIFIER.resolve())

        file_alias = self.temp_root / "prepare-public-source-tree-alias.mjs"
        directory_alias = self.temp_root / "alternate-tool-alias"
        alias_script = file_alias
        alias_kind: str | None = None
        file_symlink_error: OSError | None = None
        directory_symlink_error: OSError | None = None

        try:
            try:
                file_alias.symlink_to(real_materializer)
                alias_kind = "file symlink"
            except OSError as error:
                file_symlink_error = error
                try:
                    directory_alias.symlink_to(real_tool_root, target_is_directory=True)
                    alias_kind = "directory symlink"
                    alias_script = directory_alias / "developer" / MATERIALIZER.name
                except OSError as directory_error:
                    directory_symlink_error = directory_error
                    if os.name != "nt":
                        self.fail(
                            "host cannot create a file or directory symlink: "
                            f"{file_symlink_error}; {directory_symlink_error}"
                        )
                    completed = subprocess.run(
                        [
                            "cmd",
                            "/d",
                            "/c",
                            "mklink",
                            "/J",
                            str(directory_alias),
                            str(real_tool_root),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30,
                    )
                    if completed.returncode != 0:
                        self.fail(
                            "host cannot create a file symlink, directory symlink, "
                            "or junction: "
                            f"{file_symlink_error}; {directory_symlink_error}; "
                            f"{completed.stdout.strip()}"
                        )
                    alias_kind = "junction"
                    alias_script = directory_alias / "developer" / MATERIALIZER.name

            self.assertIsNotNone(alias_kind)
            self.assertNotEqual(str(alias_script), str(real_materializer))
            self.assertEqual(
                alias_script.resolve(strict=True),
                real_materializer.resolve(strict=True),
            )

            def run_alias(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [str(self.node), str(alias_script), *args],
                    cwd=self.temp_root,
                    env=self._environment(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=90,
                )

            alias_output = self.temp_root / "alias-public-source"
            valid = run_alias(
                "--repo",
                str(self.fixture_root),
                "--commit",
                self.base_commit,
                "--output",
                str(alias_output),
            )
            summary = self._assert_cli_success(valid)
            self._assert_success_summary(summary)
            self._assert_exact_tree(alias_output)
            self._assert_no_staging(alias_output)
            self.assertFalse((alias_output / ".git").exists())
            self.assertFalse((alias_output / "membership-report.json").exists())
            self.assertFalse((alias_output / ".ieltmps-public-context.json").exists())
            files, _ = self._tree_snapshot(alias_output)
            forbidden_suffixes = (".zip", ".tar", ".tar.gz", ".tgz")
            self.assertFalse(any(name.lower().endswith(forbidden_suffixes) for name in files))

            invalid = run_alias(
                "--repo",
                str(self.fixture_root),
                "--commit",
                self.base_commit,
            )
            self._assert_cli_failure(invalid, "CLI")
            self._assert_no_staging(alias_output)

            import_probe = self.temp_root / "import-materializer-alias.mjs"
            import_probe.write_text(
                'import { pathToFileURL } from "node:url";\n'
                "const before = process.exitCode;\n"
                "await import(pathToFileURL("
                "process.env.IELTMPS_TEST_MATERIALIZER_ALIAS).href);\n"
                "if (process.exitCode !== before) process.exit(91);\n",
                encoding="utf-8",
                newline="\n",
            )
            environment = self._environment()
            environment["IELTMPS_TEST_MATERIALIZER_ALIAS"] = str(alias_script)
            imported = subprocess.run(
                [str(self.node), str(import_probe)],
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
            self.assertFalse((self.temp_root / "import-public-source").exists())
        finally:
            if alias_kind == "file symlink" and file_alias.is_symlink():
                file_alias.unlink()
            elif alias_kind in {"directory symlink", "junction"} and directory_alias.exists():
                if os.name == "nt":
                    os.rmdir(directory_alias)
                else:
                    directory_alias.unlink()



if __name__ == "__main__":
    unittest.main(verbosity=2)
