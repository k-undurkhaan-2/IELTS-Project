#!/usr/bin/env python3
"""Focused tests for Git-object-only public Listening frontend staging."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import stage_public_listening_frontend as staging


class SyntheticSource:
    """A small Git source with the same shape as the frozen A2 contract."""

    APPROVED = (
        (
            "ListeningPractice/vip special/assets/data/path-map.json",
            None,
            "optional",
            False,
            b'{"private":false}',
        ),
        (
            "ListeningPractice/vip special/assets/data/vocabulary.json",
            "assets/data/vocabulary.json",
            "runtime_required",
            True,
            b'{"word":"fixture"}',
        ),
        (
            "ListeningPractice/vip special/assets/images/favicon.svg",
            "assets/images/favicon.svg",
            "runtime_required",
            True,
            b"<svg>fixture</svg>",
        ),
        (
            "ListeningPractice/vip special/assets/scripts/generate.py",
            None,
            "build_only",
            False,
            b"raise SystemExit('must not run')\n",
        ),
    )
    GENERATED = (
        (
            "assets/generated/listening-exams/manifest.js",
            "assets/generated/listening-exams/manifest.js",
            "/app/assets/generated/listening-exams/manifest.js",
            b"globalThis.fixtureManifest = [];\n",
        ),
        (
            "assets/generated/listening-exams/listening-index.compat.js",
            "assets/generated/listening-exams/listening-index.compat.js",
            "/app/assets/generated/listening-exams/listening-index.compat.js",
            b"globalThis.fixtureIndex = [];\n",
        ),
        (
            "assets/generated/listening-exams/listening-practice-unified.html",
            None,
            "/app/assets/generated/listening-exams/listening-practice-unified.html",
            b"<!doctype html><title>fixture</title>",
        ),
        (
            "js/bundles/listening-wrapper.bundle.js",
            None,
            "/app/js/bundles/listening-wrapper.bundle.js",
            b"globalThis.fixtureWrapper = true;\n",
        ),
    )

    def __init__(
        self,
        root: Path,
        *,
        executable_source_path: str | None = None,
        corrupt_image_root_record: bool = False,
    ) -> None:
        self.root = root
        self.repository = root / "source"
        self.manifest_path = root / "fixture.manifest.json"
        self.repository.mkdir(parents=True)
        self._git("init")
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("config", "core.autocrlf", "false")
        self._git("config", "commit.gpgSign", "false")

        self.committed_bytes: dict[str, bytes] = {}
        for source_path, _payload, _role, _included, data in self.APPROVED:
            self._write(source_path, data)
        for source_path, _artifact, _image, data in self.GENERATED:
            self._write(source_path, data)
        self._git("add", "--all")
        if executable_source_path is not None:
            self._git("update-index", "--chmod=+x", "--", executable_source_path)
        commit_environment = {
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        }
        self._git("commit", "-m", "fixture", extra_environment=commit_environment)
        self.commit = self._git_text("rev-parse", "HEAD")
        self.commit_tree = self._git_text("rev-parse", "HEAD^{tree}")
        self.source_tree = self._git_text(
            "rev-parse", f"HEAD:{staging.SOURCE_SUBTREE_PATH}"
        )

        approved_entries = []
        for source_path, payload_path, role, included, data in self.APPROVED:
            _actual_mode, blob = self._entry_identity(source_path)
            approved_entries.append(
                {
                    "source_path": source_path,
                    "payload_path": payload_path,
                    "role": role,
                    "included_in_runtime": included,
                    "mode": "100644",
                    "git_blob": blob,
                    "length": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )

        generated_entries = []
        for index, (source_path, artifact_path, image_path, data) in enumerate(
            self.GENERATED
        ):
            _actual_mode, blob = self._entry_identity(source_path)
            digest = hashlib.sha256(data).hexdigest()
            if corrupt_image_root_record and index == len(self.GENERATED) - 1:
                digest = "0" * 64
            generated_entries.append(
                {
                    "source_path": source_path,
                    "artifact_path": artifact_path,
                    "required_image_path": image_path,
                    "mode": "100644",
                    "git_blob": blob,
                    "length": len(data),
                    "sha256": digest,
                }
            )

        document = {
            "schema": staging.MANIFEST_SCHEMA,
            "model": staging.MANIFEST_MODEL,
            "source_repository": "fixture/repository",
            "source_commit": self.commit,
            "source_commit_tree": self.commit_tree,
            "source_tree": self.source_tree,
            "integrity_algorithm": staging.INTEGRITY_ALGORITHM,
            "approved_entries": approved_entries,
            "generated_dependencies": generated_entries,
        }
        raw = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.manifest_path.write_bytes(raw)
        served_bytes = sum(
            len(data)
            for _source, payload, _role, _included, data in self.APPROVED
            if payload is not None
        ) + sum(
            len(data)
            for _source, artifact, _image, data in self.GENERATED
            if artifact is not None
        )
        self.expectations = staging.ContractExpectations(
            manifest_bytes=len(raw),
            manifest_sha256=hashlib.sha256(raw).hexdigest(),
            source_repository="fixture/repository",
            source_commit=self.commit,
            source_commit_tree=self.commit_tree,
            source_tree=self.source_tree,
            artifact_version="lpf-fixture-v1",
            approved_entries=4,
            runtime_source_entries=2,
            build_only_entries=1,
            optional_entries=1,
            generated_dependency_records=4,
            generated_payload_entries=2,
            served_payload_entries=4,
            served_payload_bytes=served_bytes,
        )
        self.contract = staging.load_manifest(self.manifest_path, self.expectations)

        # These are deliberately outside the commit. A working-tree copy would leak them.
        self.private_canaries = (
            b"PRIVATE-LISTENING-CANARY",
            b"PRIVATE-READING-CANARY",
        )
        self._write(
            "ListeningPractice/vip special/ListeningPractice/private-exam.html",
            self.private_canaries[0],
            committed=False,
        )
        self._write(
            "ReadingPractice/private-answer-key.txt",
            self.private_canaries[1],
            committed=False,
        )

    def _write(self, relative_path: str, data: bytes, *, committed: bool = True) -> None:
        destination = self.repository.joinpath(*relative_path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        if committed:
            self.committed_bytes[relative_path] = data

    def poison_tracked_worktree(self) -> None:
        runtime_path = self.APPROVED[1][0]
        self._write(runtime_path, b"WORKING-TREE-POISON", committed=False)

    def _git(
        self,
        *arguments: str,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment["GIT_TERMINAL_PROMPT"] = "0"
        if extra_environment:
            environment.update(extra_environment)
        completed = subprocess.run(
            ("git", "-C", str(self.repository), *arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            self.fail_git(arguments, completed)
        return completed

    @staticmethod
    def fail_git(
        arguments: tuple[str, ...], completed: subprocess.CompletedProcess[bytes]
    ) -> None:
        raise AssertionError(
            f"fixture Git command failed {arguments!r}: "
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )

    def _git_text(self, *arguments: str) -> str:
        return self._git(*arguments).stdout.decode("ascii").strip()

    def _entry_identity(self, path: str) -> tuple[str, str]:
        output = self._git("ls-tree", "HEAD", "--", path).stdout
        header, returned_path = output.rstrip(b"\n").split(b"\t", 1)
        if returned_path.decode("utf-8") != path:
            raise AssertionError("fixture path lookup changed")
        mode, object_type, object_id = header.decode("ascii").split(" ")
        if object_type != "blob":
            raise AssertionError("fixture entry is not a blob")
        return mode, object_id


class FrozenManifestContractTests(unittest.TestCase):
    def test_canonical_manifest_has_the_exact_frozen_identity_and_inventory(self) -> None:
        contract = staging.load_manifest()
        self.assertEqual(len(contract.raw_bytes), 12_153)
        self.assertEqual(
            hashlib.sha256(contract.raw_bytes).hexdigest(),
            "fad166773fa6259a18c752c240030aa228390f8380b7be5dacac3b8ba8d4b75d",
        )
        self.assertEqual(len(contract.approved_entries), 31)
        self.assertEqual(len(contract.runtime_entries), 24)
        self.assertEqual(
            sum(item.role == "build_only" for item in contract.approved_entries), 4
        )
        self.assertEqual(
            sum(item.role == "optional" for item in contract.approved_entries), 3
        )
        self.assertEqual(len(contract.generated_dependencies), 4)
        self.assertEqual(len(contract.generated_payload_entries), 2)
        self.assertEqual(len(contract.payload_records), 26)
        self.assertEqual(
            sum(item.length for item in contract.payload_records), 14_533_213
        )

    def test_active_locator_is_the_exact_immutable_version_binding(self) -> None:
        expected = (
            b'{\n'
            b'  "schema": "ieltmps.public-listening-frontend-active.v1",\n'
            b'  "artifact_version": "lpf-v1-1a576be93d7d-a2-fad166773fa6259a",\n'
            b'  "manifest_path": "lpf-v1-1a576be93d7d-a2-fad166773fa6259a/manifest.json",\n'
            b'  "manifest_sha256": "fad166773fa6259a18c752c240030aa228390f8380b7be5dacac3b8ba8d4b75d",\n'
            b'  "manifest_bytes": 12153,\n'
            b'  "payload_path": "lpf-v1-1a576be93d7d-a2-fad166773fa6259a/payload",\n'
            b'  "payload_files": 26,\n'
            b'  "payload_bytes": 14533213,\n'
            b'  "source_commit": "1a576be93d7d18b8955adf5216efb311032bf62a",\n'
            b'  "source_tree": "4fcd96bc3f8564311bdf31853f4ba2e320b3343d",\n'
            b'  "source_subtree": "2b9c9ef46ae748e6cb187114c5887d8a2f509fd5"\n'
            b'}\n'
        )
        actual = staging.active_locator_bytes(staging.load_manifest())
        self.assertEqual(actual, expected)
        self.assertFalse(actual.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(actual.endswith(b"\n"))
        self.assertFalse(actual.endswith(b"\n\n"))

    def test_generated_staging_root_is_ignored_exactly_once(self) -> None:
        lines = (staging.REPOSITORY_ROOT / ".gitignore").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertEqual(lines.count("/.ieltmps-build/"), 1)


class PortablePathTests(unittest.TestCase):
    def test_safe_path_validation_rejects_ambiguous_and_traversing_paths(self) -> None:
        invalid = (
            "/absolute/path",
            "C:/drive/path",
            "../escape",
            "parent/../escape",
            "double//separator",
            "backslash\\separator",
            "dot/./segment",
            "con/file.txt",
            "folder/trailing.",
            "folder/trailing ",
            "cafe\u0301/file.txt",
            "control/\x01.txt",
        )
        for path in invalid:
            with self.subTest(path=repr(path)):
                with self.assertRaises((staging.ManifestError, staging.UnsafePathError)):
                    staging.validate_relative_path(path, "test path")

    def test_safe_path_validation_accepts_the_contract_character_set(self) -> None:
        path = "ListeningPractice/vip special/资源/fixture-file_1.0.json"
        self.assertEqual(staging.validate_relative_path(path, "test path"), path)

    def test_exact_casefold_and_unicode_collisions_are_rejected(self) -> None:
        cases = (
            ("same/path", "same/path"),
            ("Asset/file.js", "asset/file.js"),
            ("É/file.js", "é/file.js"),
        )
        for paths in cases:
            with self.subTest(paths=paths):
                with self.assertRaises(staging.UnsafePathError):
                    staging.reject_path_collisions(paths, "test")


@unittest.skipUnless(shutil.which("git"), "Git is required for staging tests")
class GitObjectStagingTests(unittest.TestCase):
    def test_two_independent_runs_are_deterministic_and_ignore_worktree_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            fixture.poison_tracked_worktree()
            decoy = root / "decoy-working-tree"
            (decoy / "ListeningPractice").mkdir(parents=True)
            (decoy / "ListeningPractice" / "ignored-private.txt").write_bytes(
                b"CURRENT-DIRECTORY-PRIVATE-CANARY"
            )

            outputs = (root / "run-one", root / "run-two")
            reports = []
            stores = []
            original_directory = Path.cwd()
            try:
                os.chdir(decoy)
                for index, output in enumerate(outputs, start=1):
                    store = staging.acquire_exact_commit(
                        str(fixture.repository),
                        fixture.commit,
                        root / f"objects-{index}.git",
                    )
                    stores.append(store)
                    reports.append(
                        staging.stage_from_store(store, fixture.contract, output)
                    )
            finally:
                os.chdir(original_directory)

            comparison = staging.compare_staged_outputs(
                outputs[0], outputs[1], fixture.contract
            )
            self.assertEqual(comparison["two_run_reproducibility"], "PASS")
            self.assertEqual(
                reports[0]["output_identity_sha256"],
                reports[1]["output_identity_sha256"],
            )
            self.assertEqual(
                reports[0]["pre_publish_output_identity_sha256"],
                reports[0]["output_identity_sha256"],
            )
            self.assertEqual(reports[0]["private_content_inputs"], 0)
            self.assertEqual(reports[0]["served_payload_entries"], 4)
            self.assertEqual(reports[0]["unexpected_payload_paths"], 0)

            staged_version = outputs[0] / fixture.expectations.artifact_version
            staged_payload = staged_version / "payload"
            runtime_source, runtime_payload = (
                fixture.APPROVED[1][0],
                fixture.APPROVED[1][1],
            )
            self.assertEqual(
                staged_payload.joinpath(*runtime_payload.split("/")).read_bytes(),
                fixture.committed_bytes[runtime_source],
            )
            for source_path, artifact_path, _image_path, _data in fixture.GENERATED:
                if artifact_path is not None:
                    self.assertEqual(
                        staged_payload.joinpath(*artifact_path.split("/")).read_bytes(),
                        fixture.committed_bytes[source_path],
                    )
            staged_bytes = b"".join(
                path.read_bytes() for path in outputs[0].rglob("*") if path.is_file()
            )
            for canary in (
                *fixture.private_canaries,
                b"CURRENT-DIRECTORY-PRIVATE-CANARY",
                b"WORKING-TREE-POISON",
            ):
                self.assertNotIn(canary, staged_bytes)

            for store in stores:
                store_path = store.git_directory
                self.assertTrue((store_path / "FETCH_HEAD").is_file())
                self.assertFalse((store_path / "objects" / "info" / "alternates").exists())
                self.assertEqual(
                    store.git_text("rev-parse", "FETCH_HEAD^{commit}"), fixture.commit
                )
                self.assertTrue(Path(store.git_executable).is_absolute())
                config_keys = {
                    name
                    for name in store._git_environment
                    if name == "GIT_CONFIG" or name.startswith("GIT_CONFIG_")
                }
                self.assertEqual(
                    config_keys,
                    {
                        "GIT_CONFIG_GLOBAL",
                        "GIT_CONFIG_NOSYSTEM",
                        "GIT_CONFIG_SYSTEM",
                    },
                )
                self.assertEqual(store._git_environment["GIT_ALLOW_PROTOCOL"], "file")
                self.assertEqual(store._git_environment["GIT_PROTOCOL_FROM_USER"], "0")
                self.assertEqual(store._git_environment["GIT_NO_REPLACE_OBJECTS"], "1")
                global_config = Path(
                    store._git_environment["GIT_CONFIG_GLOBAL"]
                )
                self.assertEqual(global_config.read_bytes(), b"")
                self.assertTrue(
                    Path(store._git_environment["HOME"]).is_relative_to(store_path)
                )
                self.assertTrue(
                    Path(store._git_environment["XDG_CONFIG_HOME"]).is_relative_to(
                        store_path
                    )
                )

    def test_controlled_git_environment_blocks_ambient_url_rewrites(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            git_executable = staging.resolve_git_executable("git")
            hostile_bare = root / "hostile.git"
            clone = subprocess.run(
                (
                    git_executable,
                    "clone",
                    "--bare",
                    str(fixture.repository),
                    str(hostile_bare),
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                clone.returncode,
                0,
                clone.stderr.decode("utf-8", errors="replace"),
            )

            unavailable_https = "https://127.0.0.1:9/authorized.git"
            replacement = hostile_bare.as_uri()
            hostile_config_text = (
                f'[url "{replacement}"]\n'
                f"\tinsteadOf = {unavailable_https}\n"
                '[protocol "file"]\n'
                "\tallow = always\n"
            )
            global_config = root / "global.gitconfig"
            system_config = root / "system.gitconfig"
            home = root / "home"
            xdg = root / "xdg"
            empty_home = root / "empty-home"
            empty_xdg = root / "empty-xdg"
            for directory in (home, xdg / "git", empty_home, empty_xdg):
                directory.mkdir(parents=True)
            for path in (
                global_config,
                system_config,
                home / ".gitconfig",
                xdg / "git" / "config",
            ):
                path.write_text(
                    hostile_config_text,
                    encoding="utf-8",
                    newline="\n",
                )

            base_environment = os.environ.copy()
            for name in tuple(base_environment):
                if name == "GIT_CONFIG" or name.startswith("GIT_CONFIG_"):
                    base_environment.pop(name)
                elif name in {
                    "GIT_ALLOW_PROTOCOL",
                    "GIT_PROTOCOL_FROM_USER",
                    "HOME",
                    "USERPROFILE",
                    "XDG_CONFIG_HOME",
                }:
                    base_environment.pop(name)
            base_environment.update(
                {
                    "HOME": str(empty_home),
                    "USERPROFILE": str(empty_home),
                    "XDG_CONFIG_HOME": str(empty_xdg),
                    "GIT_TERMINAL_PROMPT": "0",
                }
            )
            hostile_surfaces = (
                (
                    "global",
                    {
                        "GIT_CONFIG_GLOBAL": str(global_config),
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                ),
                (
                    "system",
                    {
                        "GIT_CONFIG_SYSTEM": str(system_config),
                        "GIT_CONFIG_GLOBAL": os.devnull,
                    },
                ),
                (
                    "runtime-pairs",
                    {
                        "GIT_CONFIG_COUNT": "2",
                        "GIT_CONFIG_KEY_0": f"url.{replacement}.insteadOf",
                        "GIT_CONFIG_VALUE_0": unavailable_https,
                        "GIT_CONFIG_KEY_1": "protocol.file.allow",
                        "GIT_CONFIG_VALUE_1": "always",
                    },
                ),
                (
                    "home",
                    {
                        "HOME": str(home),
                        "USERPROFILE": str(home),
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                ),
                (
                    "xdg",
                    {
                        "XDG_CONFIG_HOME": str(xdg),
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                ),
                (
                    "parameters",
                    {
                        "GIT_CONFIG_PARAMETERS": (
                            f"'url.{replacement}.insteadOf'="
                            f"'{unavailable_https}' "
                            "'protocol.file.allow'='always'"
                        ),
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                ),
            )
            for name, additions in hostile_surfaces:
                with self.subTest(surface=name):
                    hostile_environment = base_environment | additions
                    control = subprocess.run(
                        (git_executable, "ls-remote", unavailable_https),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        env=hostile_environment,
                    )
                    self.assertEqual(
                        control.returncode,
                        0,
                        control.stderr.decode("utf-8", errors="replace"),
                    )
                    self.assertIn(fixture.commit.encode("ascii"), control.stdout)

                    object_store = root / f"blocked-{name}.git"
                    with mock.patch.dict(os.environ, hostile_environment, clear=True):
                        with self.assertRaises(staging.SourceIntegrityError):
                            staging.acquire_exact_commit(
                                unavailable_https,
                                fixture.commit,
                                object_store,
                                git_executable=git_executable,
                            )
                    fetch_head = object_store / "FETCH_HEAD"
                    if fetch_head.exists():
                        self.assertNotIn(
                            fixture.commit.encode("ascii"), fetch_head.read_bytes()
                        )

    def test_forbidden_source_mode_is_rejected_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable_path = SyntheticSource.APPROVED[1][0]
            fixture = SyntheticSource(
                root / "fixture", executable_source_path=executable_path
            )
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            with self.assertRaisesRegex(staging.SourceIntegrityError, "forbidden mode"):
                staging.stage_from_store(store, fixture.contract, output)
            self.assertFalse(output.exists())

    def test_image_root_only_generated_dependency_is_still_verified(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(
                root / "fixture", corrupt_image_root_record=True
            )
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            with self.assertRaisesRegex(staging.SourceIntegrityError, "SHA-256 mismatch"):
                staging.stage_from_store(store, fixture.contract, root / "output")

    def test_wrong_commit_tree_or_subtree_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            cases = (
                dataclasses.replace(
                    fixture.contract,
                    expectations=dataclasses.replace(
                        fixture.expectations, source_commit_tree="0" * 40
                    ),
                ),
                dataclasses.replace(
                    fixture.contract,
                    expectations=dataclasses.replace(
                        fixture.expectations, source_tree="0" * 40
                    ),
                ),
            )
            for index, contract in enumerate(cases):
                with self.subTest(index=index):
                    with self.assertRaises(staging.SourceIntegrityError):
                        staging.stage_from_store(store, contract, root / f"output-{index}")

    def test_branch_name_cannot_replace_the_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            object_store = root / "objects.git"
            with self.assertRaisesRegex(
                staging.SourceIntegrityError, "full lowercase SHA-1"
            ):
                staging.acquire_exact_commit(
                    str(fixture.repository), "main", object_store
                )
            self.assertFalse(object_store.exists())

    def test_object_store_and_output_paths_must_be_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            existing_store = root / "existing.git"
            existing_store.mkdir()
            with self.assertRaisesRegex(staging.SourceIntegrityError, "must not already"):
                staging.acquire_exact_commit(
                    str(fixture.repository), fixture.commit, existing_store
                )

            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            output.mkdir()
            with self.assertRaisesRegex(staging.OutputIntegrityError, "must not already"):
                staging.stage_from_store(store, fixture.contract, output)

    def test_object_store_must_be_outside_the_subject_checkout(self) -> None:
        forbidden_store = staging.REPOSITORY_ROOT / ".fixture-object-store.git"
        self.assertFalse(forbidden_store.exists())
        with self.assertRaisesRegex(staging.SourceIntegrityError, "outside"):
            staging.acquire_exact_commit(
                "https://example.invalid/repository.git",
                "0" * 40,
                forbidden_store,
        )
        self.assertFalse(forbidden_store.exists())

    def test_duplicate_manifest_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            original = fixture.manifest_path.read_bytes()
            duplicated = original.replace(
                b'{"schema":',
                b'{"schema":"duplicate","schema":',
                1,
            )
            self.assertNotEqual(original, duplicated)
            path = root / "duplicate.manifest.json"
            path.write_bytes(duplicated)
            expectations = dataclasses.replace(
                fixture.expectations,
                manifest_bytes=len(duplicated),
                manifest_sha256=hashlib.sha256(duplicated).hexdigest(),
            )
            with self.assertRaisesRegex(
                staging.ManifestError, "duplicate JSON member"
            ):
                staging.load_manifest(path, expectations)

    def test_wrong_full_commit_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            expected = SyntheticSource(root / "expected")
            wrong = SyntheticSource(
                root / "wrong",
                executable_source_path=SyntheticSource.APPROVED[1][0],
            )
            self.assertRegex(wrong.commit, r"[0-9a-f]{40}")
            self.assertNotEqual(wrong.commit, expected.commit)
            store = staging.acquire_exact_commit(
                str(wrong.repository), wrong.commit, root / "wrong-objects.git"
            )
            output = root / "output"
            with self.assertRaises(staging.SourceIntegrityError):
                staging.stage_from_store(store, expected.contract, output)
            self.assertFalse(output.exists())

    def test_symlink_or_reparse_output_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            real_parent = root / "real-parent"
            linked_parent = root / "linked-parent"
            real_parent.mkdir()
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            with self.assertRaisesRegex(
                staging.OutputIntegrityError, "linked/reparse ancestor"
            ):
                staging.stage_from_store(
                    store, fixture.contract, linked_parent / "output"
                )
            self.assertFalse((real_parent / "output").exists())

    def test_failure_before_publication_removes_temporary_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            with mock.patch.object(
                staging,
                "verify_staged_output",
                side_effect=staging.OutputIntegrityError(
                    "forced pre-publication verification failure"
                ),
            ):
                with self.assertRaisesRegex(
                    staging.OutputIntegrityError, "forced pre-publication"
                ):
                    staging.stage_from_store(store, fixture.contract, output)
            self.assertFalse(output.exists())
            self.assertEqual(tuple(root.glob(".output.tmp-*")), ())

    def test_post_publication_failure_rolls_back_final_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            original_verify = staging.verify_staged_output
            calls = 0

            def fail_second_verification(
                path: Path, contract: staging.ManifestContract
            ) -> dict[str, object]:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise staging.OutputIntegrityError(
                        "forced post-publication verification failure"
                    )
                return original_verify(path, contract)

            with mock.patch.object(
                staging,
                "verify_staged_output",
                side_effect=fail_second_verification,
            ):
                with self.assertRaisesRegex(
                    staging.OutputIntegrityError, "forced post-publication"
                ):
                    staging.stage_from_store(store, fixture.contract, output)
            self.assertEqual(calls, 2)
            self.assertFalse(output.exists())
            self.assertEqual(tuple(root.glob(".output.tmp-*")), ())
            self.assertEqual(tuple(root.glob(".output.failed-*")), ())

    def test_effective_rename_error_rolls_back_final_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            original_replace = staging.os.replace
            replace_calls = 0

            def replace_then_fail(source: Path, destination: Path) -> None:
                nonlocal replace_calls
                replace_calls += 1
                original_replace(source, destination)
                if replace_calls == 1:
                    raise OSError("forced error after effective publication")

            with mock.patch.object(
                staging.os,
                "replace",
                side_effect=replace_then_fail,
            ):
                with self.assertRaisesRegex(
                    OSError, "forced error after effective publication"
                ):
                    staging.stage_from_store(store, fixture.contract, output)
            self.assertEqual(replace_calls, 2)
            self.assertFalse(output.exists())
            self.assertEqual(tuple(root.glob(".output.tmp-*")), ())
            self.assertEqual(tuple(root.glob(".output.failed-*")), ())

    def test_interrupt_after_publication_rolls_back_final_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            original_verify = staging.verify_staged_output
            calls = 0

            def interrupt_second_verification(
                path: Path, contract: staging.ManifestContract
            ) -> dict[str, object]:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise KeyboardInterrupt("forced post-publication interrupt")
                return original_verify(path, contract)

            with mock.patch.object(
                staging,
                "verify_staged_output",
                side_effect=interrupt_second_verification,
            ):
                with self.assertRaisesRegex(
                    KeyboardInterrupt, "forced post-publication interrupt"
                ):
                    staging.stage_from_store(store, fixture.contract, output)
            self.assertEqual(calls, 2)
            self.assertFalse(output.exists())
            self.assertEqual(tuple(root.glob(".output.tmp-*")), ())
            self.assertEqual(tuple(root.glob(".output.failed-*")), ())

    def test_failed_post_publication_quarantine_is_a_residual_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            original_verify = staging.verify_staged_output
            original_replace = staging.os.replace
            verify_calls = 0
            replace_calls = 0

            def fail_second_verification(
                path: Path, contract: staging.ManifestContract
            ) -> dict[str, object]:
                nonlocal verify_calls
                verify_calls += 1
                if verify_calls == 2:
                    raise staging.OutputIntegrityError(
                        "forced post-publication verification failure"
                    )
                return original_verify(path, contract)

            def fail_quarantine(source: Path, destination: Path) -> None:
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 2:
                    raise OSError("forced quarantine failure")
                original_replace(source, destination)

            with mock.patch.object(
                staging,
                "verify_staged_output",
                side_effect=fail_second_verification,
            ), mock.patch.object(
                staging.os,
                "replace",
                side_effect=fail_quarantine,
            ):
                with self.assertRaisesRegex(
                    staging.ResidualStateError,
                    "could not be quarantined.*original failure",
                ):
                    staging.stage_from_store(store, fixture.contract, output)
            self.assertEqual(verify_calls, 2)
            self.assertEqual(replace_calls, 2)
            self.assertTrue(output.is_dir())

    def test_preexisting_valid_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            original_report = staging.stage_from_store(
                store, fixture.contract, output
            )
            original_files = original_report["files"]
            with self.assertRaisesRegex(
                staging.OutputIntegrityError, "must not already"
            ):
                staging.stage_from_store(store, fixture.contract, output)
            preserved_report = staging.verify_staged_output(
                output, fixture.contract
            )
            self.assertEqual(preserved_report["files"], original_files)
            self.assertEqual(
                preserved_report["output_identity_sha256"],
                original_report["output_identity_sha256"],
            )

    def test_output_verifier_rejects_tampering_and_unexpected_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            store = staging.acquire_exact_commit(
                str(fixture.repository), fixture.commit, root / "objects.git"
            )
            output = root / "output"
            staging.stage_from_store(store, fixture.contract, output)
            payload = (
                output
                / fixture.expectations.artifact_version
                / "payload"
                / "assets"
                / "data"
                / "vocabulary.json"
            )
            payload.write_bytes(b"tampered")
            with self.assertRaisesRegex(staging.OutputIntegrityError, "integrity mismatch"):
                staging.verify_staged_output(output, fixture.contract)

            payload.write_bytes(
                fixture.committed_bytes[fixture.APPROVED[1][0]]
            )
            (output / "unexpected.txt").write_bytes(b"unexpected")
            with self.assertRaisesRegex(staging.OutputIntegrityError, "inventory mismatch"):
                staging.verify_staged_output(output, fixture.contract)

    def test_manifest_payload_collision_is_rejected_before_git_access(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = SyntheticSource(root / "fixture")
            document = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
            document["generated_dependencies"][0]["artifact_path"] = (
                document["approved_entries"][1]["payload_path"]
            )
            document["generated_dependencies"][0]["source_path"] = (
                document["approved_entries"][1]["payload_path"]
            )
            raw_manifest = json.dumps(
                document, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            path = root / "collision.manifest.json"
            path.write_bytes(raw_manifest)
            expectations = dataclasses.replace(
                fixture.expectations,
                manifest_bytes=len(raw_manifest),
                manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
            )
            with self.assertRaises(staging.UnsafePathError):
                staging.load_manifest(path, expectations)


if __name__ == "__main__":
    unittest.main(verbosity=2)
