#!/usr/bin/env python3
"""Focused synthetic-Git tests for public source membership policy."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path, PurePosixPath


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = SOURCE_PATH.parents[3]
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


class PublicSourceMembershipTest(unittest.TestCase):
    """All repositories and mutable files created by this suite live in TEMP."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.node = _find_node()
        cls.git = _find_git()
        if not VERIFIER.is_file() or not MANIFEST.is_file():
            raise unittest.SkipTest("working-tree verifier or manifest is unavailable")

        cls.manifest_bytes = MANIFEST.read_bytes()
        cls.manifest_value = json.loads(cls.manifest_bytes.decode("utf-8"))
        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-template-"
        )
        cls.template_root = Path(cls.template_temp.name).resolve() / "fixture"
        cls.template_root.mkdir()

        exact_paths: set[str] = set()
        for component in cls.manifest_value["components"]:
            exact_paths.update(component["selectors"]["includeExact"])
        for relative in sorted(exact_paths):
            value = (
                cls.manifest_bytes
                if relative == MANIFEST_RELATIVE
                else f"placeholder:{relative}\n".encode("utf-8")
            )
            cls._write_at(cls.template_root, relative, value)

        prefix_placeholders = {
            "backend/admin/admin.js": "export const admin = true;\n",
            "backend/auth/auth.js": "export const auth = true;\n",
            "backend/migrations/001_init.sql": "SELECT 1;\n",
            "backend/scripts/task.mjs": "export const task = true;\n",
            "backend/src/app.js": "export const app = true;\n",
            "backend/test/app.test.js": "export const test = true;\n",
            "css/app.css": "body {}\n",
            "js/app.js": "globalThis.fixture = true;\n",
            "js/siteContent.js": "globalThis.siteContent = {};\n",
            "src/styles/app.css": ":root {}\n",
        }
        for relative, value in prefix_placeholders.items():
            cls._write_at(cls.template_root, relative, value)

        cls._git_at(cls.template_root, "init")
        for key, value in (
            ("user.name", "Public Source Test"),
            ("user.email", "public-source-test@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
            ("core.protectNTFS", "false"),
        ):
            cls._git_at(cls.template_root, "config", key, value)
        cls._git_at(cls.template_root, "add", "-A")
        cls._git_at(cls.template_root, "commit", "-m", "synthetic baseline")
        cls.template_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-source-case-"
        )
        self.temp_root = Path(self.case_temp.name).resolve()
        self.fixture_root = self.temp_root / "fixture"
        shutil.copytree(self.template_root, self.fixture_root)
        self.base_commit = self._head()
        self.output_path = self.temp_root / "membership-report.json"
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

    def _scope(self, value: dict[str, object], scope_id: str) -> dict[str, object]:
        return next(
            scope for scope in value["licenseScopes"] if scope["id"] == scope_id
        )

    def _run(
        self,
        *,
        commit: str | None = None,
        mode: str = "--dry-run-report",
        output: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_commit = commit or self.base_commit
        argv = [
            str(self.node),
            str(VERIFIER),
            "--repo",
            str(self.fixture_root),
            "--commit",
            selected_commit,
            mode,
        ]
        if mode == "--dry-run-report":
            argv.extend(["--output", str(output or self.output_path)])
        if extra_args:
            argv.extend(extra_args)
        return subprocess.run(
            argv,
            cwd=self.temp_root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def _assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout)

    def _assert_failure(
        self, result: subprocess.CompletedProcess[str], fragment: str | None = None
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if fragment is not None:
            self.assertIn(fragment.lower(), result.stdout.lower())

    def _read_report(self, output: Path | None = None) -> dict[str, object]:
        return json.loads((output or self.output_path).read_text(encoding="utf-8"))

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
            index_record = (
                f"{mode} {object_id}\t".encode("ascii")
                + relative.encode("utf-8")
                + b"\0"
            )
            self._git("-c", "core.protectNTFS=false", "update-index", "-z", "--index-info", input_bytes=index_record)
        tree_id = self._git("write-tree").stdout.decode("ascii").strip()
        return self._git(
            "commit-tree",
            tree_id,
            "-p",
            self.base_commit,
            input_bytes=(message + "\n").encode("utf-8"),
        ).stdout.decode("ascii").strip()

    def _commit_raw_paths(self, *paths: str) -> str:
        entries = [
            ("100644", self._hash_blob((path + "\n").encode("utf-8")), path)
            for path in paths
        ]
        return self._plumbing_commit(entries, "synthetic raw paths")

    def test_01_policy_only_validates_policy_without_writing_or_claiming_membership(self) -> None:
        result = self._run(mode="--policy-only")
        self._assert_success(result)
        summary = json.loads(result.stdout)
        self.assertTrue(summary["policyValid"])
        self.assertFalse(summary["membershipValidated"])
        self.assertNotIn("membershipValid", summary)
        self.assertFalse(self.output_path.exists())

    def test_02_committed_manifest_wins_over_dirty_worktree_manifest(self) -> None:
        (self.fixture_root / MANIFEST_RELATIVE).write_text(
            '{"license":"AGPL-3.0-only"}\n', encoding="utf-8", newline="\n"
        )
        result = self._run(mode="--policy-only")
        self._assert_success(result)

    def test_03_untracked_worktree_manifest_is_ignored(self) -> None:
        self._git("rm", "--cached", "--", MANIFEST_RELATIVE)
        self._git("commit", "-m", "manifest absent from commit")
        commit = self._head()
        self.assertTrue((self.fixture_root / MANIFEST_RELATIVE).is_file())
        result = self._run(commit=commit, mode="--policy-only")
        self._assert_failure(result, "does not contain")

    def test_04_missing_committed_manifest_fails(self) -> None:
        self._git("rm", "--", MANIFEST_RELATIVE)
        self._git("commit", "-m", "remove committed manifest")
        result = self._run(commit=self._head(), mode="--policy-only")
        self._assert_failure(result, "does not contain")

    def test_05_out_of_ceiling_exact_selector_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selectors = self._component(value, "frontend-preferred-source")["selectors"]
            selectors["includeExact"].append("outside.txt")
            selectors["includeExact"].sort()

        commit = self._commit_manifest("widen exact selector", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "exact ceiling")

    def test_06_out_of_ceiling_prefix_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selectors = self._component(value, "frontend-preferred-source")["selectors"]
            selectors["includePrefixes"].append("other/")
            selectors["includePrefixes"].sort()

        commit = self._commit_manifest("widen prefix selector", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "prefix ceiling")

    def test_07_mandatory_denial_overrides_exact_include(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selectors = self._component(value, "eligible-server-source")["selectors"]
            selectors["includeExact"].append("backend/docker-compose.yml")
            selectors["includeExact"].sort()

        commit = self._commit_manifest("select denied compose", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "mandatorily denied")

    def test_08_selected_symlink_fails_and_never_enters_report(self) -> None:
        commit = self._plumbing_commit(
            [("120000", self._hash_blob(b"target\n"), "css/link.css")],
            "synthetic symlink",
        )
        self._assert_failure(self._run(commit=commit), "symlink")
        self.assertFalse(self.output_path.exists())

    def test_09_selected_gitlink_fails_and_never_enters_report(self) -> None:
        commit = self._plumbing_commit(
            [("160000", self.base_commit, "backend/src/vendor")],
            "synthetic gitlink",
        )
        self._assert_failure(self._run(commit=commit), "gitlink")
        self.assertFalse(self.output_path.exists())

    def test_10_case_insensitive_collision_fails(self) -> None:
        commit = self._commit_raw_paths("css/Collision.css", "css/collision.css")
        self._assert_failure(self._run(commit=commit), "collision")

    def test_11_unicode_normalization_collision_fails(self) -> None:
        commit = self._commit_raw_paths("css/caf\u00e9.css", "css/cafe\u0301.css")
        self._assert_failure(self._run(commit=commit), "collision")

    def test_12_windows_reserved_name_fails(self) -> None:
        commit = self._commit_raw_paths("css/CON.txt")
        self._assert_failure(self._run(commit=commit), "reserved")

    def test_13_ads_colon_path_fails(self) -> None:
        commit = self._commit_raw_paths("css/name:stream")
        self._assert_failure(self._run(commit=commit), "ADS")

    def test_14_trailing_dot_path_fails(self) -> None:
        commit = self._commit_raw_paths("css/trailing.")
        self._assert_failure(self._run(commit=commit), "trailing dot")

    def test_15_trailing_space_path_fails(self) -> None:
        commit = self._commit_raw_paths("css/trailing ")
        self._assert_failure(self._run(commit=commit), "trailing dot or space")

    def test_16_replacement_commit_cannot_alter_membership(self) -> None:
        original_bytes = (self.fixture_root / "index.html").read_bytes()
        self._write("index.html", "replacement bytes\n")
        replacement_commit = self._commit_paths("replacement commit", "index.html")
        self._git("replace", self.base_commit, replacement_commit)
        result = self._run(commit=self.base_commit)
        self._assert_success(result)
        report = self._read_report()
        member = next(item for item in report["members"] if item["path"] == "index.html")
        self.assertEqual(member["sha256"], _sha256(original_bytes))

    def test_17_replacement_provided_manifest_is_ignored(self) -> None:
        self._git("rm", "--", MANIFEST_RELATIVE)
        self._git("commit", "-m", "original without manifest")
        missing_commit = self._head()
        self._git("replace", missing_commit, self.base_commit)
        result = self._run(commit=missing_commit, mode="--policy-only")
        self._assert_failure(result, "does not contain")

    def test_18_unknown_license_scope_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            self._component(value, "frontend-preferred-source")["licenseScope"] = "unknown"

        commit = self._commit_manifest("unknown scope", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "unknown license scope")

    def test_19_exact_frontend_spdx_value_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            self._scope(value, "frontend")["spdx"] = "GPL-3.0-only"

        commit = self._commit_manifest("claim exact frontend spdx", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "exact SPDX")

    def test_20_whole_artifact_agpl_claim_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["license"] = "AGPL-3.0-only"

        commit = self._commit_manifest("claim artifact license", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "whole-artifact")

    def test_21_required_member_without_license_scope_fails(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            del self._component(value, "frontend-preferred-source")["licenseScope"]

        commit = self._commit_manifest("remove required scope", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "has no license scope")

    def test_22_deferred_category_cannot_be_marked_complete(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["deferred"][0]["status"] = "complete"

        commit = self._commit_manifest("complete deferred category", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "cannot be marked complete")

    def test_23_security_review_category_cannot_select_a_path(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["securityReviewRequired"][0]["selectors"] = {
                "includeExact": ["backend/docker-compose.yml"],
                "includePrefixes": [],
            }

        commit = self._commit_manifest("select security category", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "cannot select paths")

    def test_24_missing_required_exact_member_fails(self) -> None:
        self._git("rm", "--", "LICENSES/AGPL-3.0-only.txt")
        self._git("commit", "-m", "remove required license text")
        self._assert_failure(self._run(commit=self._head()), "required exact members")

    def test_25_sql_outside_migrations_fails(self) -> None:
        self._write("backend/src/query.sql", "SELECT 1;\n")
        commit = self._commit_paths("sql outside migrations", "backend/src/query.sql")
        self._assert_failure(self._run(commit=commit), "forbidden file family")

    def test_26_nested_migration_sql_fails(self) -> None:
        self._write("backend/migrations/nested/002_more.sql", "SELECT 2;\n")
        commit = self._commit_paths(
            "nested migration", "backend/migrations/nested/002_more.sql"
        )
        self._assert_failure(self._run(commit=commit), "forbidden file family")

    def test_27_malformed_migration_filename_fails(self) -> None:
        self._write("backend/migrations/init.sql", "SELECT 2;\n")
        commit = self._commit_paths(
            "malformed migration", "backend/migrations/init.sql"
        )
        self._assert_failure(self._run(commit=commit), "forbidden file family")

    def test_28_valid_direct_migration_sql_succeeds(self) -> None:
        self._write("backend/migrations/002_more.sql", "SELECT 2;\n")
        commit = self._commit_paths(
            "valid migration", "backend/migrations/002_more.sql"
        )
        result = self._run(commit=commit)
        self._assert_success(result)
        paths = [member["path"] for member in self._read_report()["members"]]
        self.assertIn("backend/migrations/002_more.sql", paths)

    def test_29_report_contains_only_relative_paths_and_no_host_path(self) -> None:
        result = self._run()
        self._assert_success(result)
        raw = self.output_path.read_text(encoding="utf-8")
        report = json.loads(raw)
        self.assertNotIn(str(self.fixture_root), raw)
        self.assertNotIn(str(self.temp_root), raw)
        for member in report["members"]:
            relative = member["path"]
            self.assertFalse(PurePosixPath(relative).is_absolute())
            self.assertNotIn("\\", relative)
            self.assertNotRegex(relative, r"^[A-Za-z]:")

    def test_30_output_inside_repository_fails(self) -> None:
        output = self.fixture_root / "report.json"
        self._assert_failure(self._run(output=output), "outside the repository")
        self.assertFalse(output.exists())

    def test_31_existing_output_fails_without_overwrite(self) -> None:
        sentinel = b"do not overwrite\n"
        self.output_path.write_bytes(sentinel)
        self._assert_failure(self._run(), "already exists")
        self.assertEqual(self.output_path.read_bytes(), sentinel)

    def test_32_absolute_host_path_leak_in_manifest_metadata_fails(self) -> None:
        leaked = str(self.temp_root / "private-host-location")

        def mutate(value: dict[str, object]) -> None:
            value["repositoryPath"] = leaked

        commit = self._commit_manifest("host path leak", mutate)
        self._assert_failure(self._run(commit=commit, mode="--policy-only"), "host-path")

    def test_33_identical_commit_produces_byte_identical_reports(self) -> None:
        first = self.temp_root / "first.json"
        second = self.temp_root / "second.json"
        self._assert_success(self._run(output=first))
        self._assert_success(self._run(output=second))
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_34_dirty_selected_source_does_not_change_git_object_report(self) -> None:
        first = self.temp_root / "before.json"
        second = self.temp_root / "after.json"
        self._assert_success(self._run(output=first))
        self._write("index.html", "dirty working-tree bytes\n")
        self._assert_success(self._run(output=second))
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_35_report_states_foundation_membership_and_publication_status(self) -> None:
        self._assert_success(self._run())
        report = self._read_report()
        self.assertTrue(report["membershipValid"])
        self.assertFalse(report["correspondingSourceComplete"])
        self.assertTrue(report["publicationBlocked"])

    def test_36_archive_member_under_selected_prefix_fails(self) -> None:
        self._write("backend/src/source.zip", b"not an archive\n")
        commit = self._commit_paths("archive-shaped member", "backend/src/source.zip")
        self._assert_failure(self._run(commit=commit), "forbidden file family")

    def test_37_report_schema_and_member_schema_are_exact(self) -> None:
        self._assert_success(self._run())
        report = self._read_report()
        self.assertEqual(
            list(report),
            [
                "schemaVersion",
                "sourceCommit",
                "manifestPath",
                "manifestSha256",
                "membershipValid",
                "membershipCount",
                "members",
                "deferredCategories",
                "securityReviewRequired",
                "rightsReviewRequired",
                "correspondingSourceComplete",
                "publicationBlocked",
                "blockers",
            ],
        )
        self.assertEqual(report["membershipCount"], len(report["members"]))
        self.assertTrue(report["members"])
        for member in report["members"]:
            self.assertEqual(
                list(member), ["path", "gitMode", "sha256", "role", "licenseScope"]
            )
        self.assertTrue(self.output_path.read_bytes().endswith(b"\n"))

    def test_38_reparse_output_parent_fails_or_skips_with_platform_reason(self) -> None:
        real_parent = self.temp_root / "real-parent"
        linked_parent = self.temp_root / "linked-parent"
        real_parent.mkdir()
        try:
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"platform cannot create a directory symlink: {error}")
        output = linked_parent / "report.json"
        self._assert_failure(self._run(output=output), "reparse")
        self.assertFalse((real_parent / "report.json").exists())

    def test_39_arbitrary_policy_override_cli_is_rejected(self) -> None:
        result = self._run(
            mode="--policy-only",
            extra_args=["--manifest", str(self.temp_root / "override.json")],
        )
        self._assert_failure(result, "invalid")

    def test_40_frontend_editable_source_is_included_but_bundles_are_not(self) -> None:
        self._write("js/bundles/generated.js", "generated bytes\n")
        commit = self._commit_paths(
            "generated bundle remains denied", "js/bundles/generated.js"
        )
        self._assert_success(self._run(commit=commit))
        paths = [member["path"] for member in self._read_report()["members"]]
        self.assertIn("js/siteContent.js", paths)
        self.assertNotIn("js/bundles/generated.js", paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
