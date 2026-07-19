#!/usr/bin/env python3
"""Focused, Docker-free tests for the verified ephemeral build gateway."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from typing import Callable


SOURCE_PATH = Path(__file__).resolve()
REPO_ROOT = (
    SOURCE_PATH.parents[3]
    if len(SOURCE_PATH.parents) > 3
    else SOURCE_PATH.parent
)
# The draft is copied into the repository before execution.  Resolve that case,
# while retaining a useful source root when this temporary draft is run directly.
if not (REPO_ROOT / "developer").is_dir():
    configured_root = os.environ.get("IELTMPS_TEST_REPO_ROOT")
    REPO_ROOT = (
        Path(configured_root).resolve()
        if configured_root
        else Path.cwd().resolve()
    )

GENERATOR = "developer/prepare-public-container-context.mjs"
VERIFIER = "developer/verify-public-container-context.mjs"
GATEWAY = "developer/build-public-container.mjs"
MANIFEST = "developer/public-container-context-manifest.json"
COMPOSE = "backend/docker-compose.yml"
DOCKERFILE = "backend/Dockerfile"
RUNBOOK = "backend/DEPLOYMENT-RUNBOOK.md"
RECEIPT = ".ieltmps-public-context.json"
SENTINEL_CONTEXT = "../.build/BUILD_VIA_DEVELOPER_BUILD_PUBLIC_CONTAINER_MJS"
IDENTITY_NAMES = (
    "IELTMPS_SOURCE_COMMIT",
    "IELTMPS_CONTEXT_MANIFEST_SHA256",
    "IELTMPS_CONTEXT_RECEIPT_SHA256",
)
F6_TRACKED_TEXT_PATHS = frozenset(
    (MANIFEST, GENERATOR, VERIFIER, DOCKERFILE, COMPOSE, RUNBOOK)
)
F6_PROTECTED_ROOTS = frozenset(("listeningpractice", "readingpractice"))
GIT_REDIRECTION_NAMES = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_REPLACE_REF_BASE",
}


def _find_command(name: str, env_name: str) -> Path:
    configured = os.environ.get(env_name)
    if configured:
        candidate = Path(configured).resolve()
        if candidate.is_file():
            return candidate
    discovered = shutil.which(name)
    if discovered:
        return Path(discovered).resolve()

    dependencies = Path(sys.executable).resolve().parent.parent
    candidates = (
        [dependencies / "node/bin/node.exe", dependencies / "node/bin/node"]
        if name == "node"
        else [
            dependencies / "native/git/cmd/git.exe",
            dependencies / "native/git/bin/git",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise unittest.SkipTest(f"required local command is unavailable: {name}")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _read_f6_tracked_text(relative: str) -> str:
    if relative not in F6_TRACKED_TEXT_PATHS:
        raise ValueError(f"F6 tracked-text path is not approved: {relative}")
    normalized = PurePosixPath(relative)
    if (
        normalized.is_absolute()
        or normalized.as_posix() != relative
        or any(part in {"", ".", ".."} for part in normalized.parts)
    ):
        raise ValueError(f"F6 tracked-text path is not normalized: {relative}")
    repo_resolved = REPO_ROOT.resolve(strict=True)
    target = REPO_ROOT / normalized
    target_absolute = Path(os.path.abspath(target))
    try:
        target_resolved = target.resolve(strict=True)
    except OSError as error:
        raise AssertionError(
            f"approved F6 tracked-text path is not a regular file: {relative}"
        ) from error
    canonical = lambda path: os.path.normcase(os.path.normpath(str(path)))
    if canonical(target_resolved) != canonical(target_absolute):
        raise AssertionError(
            f"approved F6 tracked-text path resolves through a link or reparse point: {relative}"
        )
    try:
        target_resolved.relative_to(repo_resolved)
    except ValueError as error:
        raise AssertionError(
            f"approved F6 tracked-text path resolves outside the repository: {relative}"
        ) from error
    if not target_resolved.is_file():
        raise AssertionError(f"approved F6 tracked-text path is not a regular file: {relative}")
    return target_resolved.read_text(encoding="utf-8")


def _f6_javascript_string_collection(source: str, name: str) -> frozenset[str]:
    match = re.search(
        rf"const\s+{re.escape(name)}\s*=\s*(?:Object\.freeze|new Set)\(\[(.*?)\]\);",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"JavaScript string collection is missing: {name}")
    return frozenset(re.findall(r'"([^"]+)"', match.group(1)))


def _service_block(source: str, service_name: str) -> str | None:
    lines = source.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line == f"  {service_name}:"),
        None,
    )
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def _f6_logical_dockerfile_lines(source: str) -> list[tuple[str, str]]:
    logical: list[tuple[str, str]] = []
    pending: str | None = None
    escape_character = "\\"
    parser_directives_eligible = True
    for raw in source.splitlines():
        stripped = raw.strip()
        directive = (
            re.fullmatch(r"#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*", stripped)
            if parser_directives_eligible and pending is None
            else None
        )
        directive_name = directive.group(1).casefold() if directive else None
        if directive and directive_name in {"syntax", "escape", "check"}:
            if directive_name == "escape":
                if directive.group(2) not in {"\\", "`"}:
                    raise ValueError(
                        "F6 Dockerfile escape directive must contain one supported character"
                    )
                escape_character = directive.group(2)
            continue
        parser_directives_eligible = False
        if not stripped or stripped.startswith("#"):
            continue
        physical_line = raw.lstrip() if pending is None else raw
        combined = f"{pending or ''}{physical_line}"
        if physical_line.endswith(escape_character):
            pending = combined[: -len(escape_character)]
            continue
        logical.append((combined.strip(), escape_character))
        pending = None
    if pending is not None:
        raise ValueError("Dockerfile contains an unterminated continuation")
    return logical


def _logical_dockerfile_lines(source: str) -> list[str]:
    return [logical_line for logical_line, _ in _f6_logical_dockerfile_lines(source)]


def _f6_split_docker_shell_words(value: str, escape_character: str) -> list[str]:
    if escape_character not in {"\\", "`"}:
        raise ValueError("F6 Dockerfile escape character must be known")
    words: list[str] = []
    current = ""
    quote: str | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if character == escape_character:
            if index + 1 >= len(value):
                raise ValueError(
                    "F6 Dockerfile shell form must not end with an escape character"
                )
            current += value[index + 1]
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
            else:
                current += character
            index += 1
            continue
        if character in {"\"", "'"}:
            quote = character
        elif character.isspace():
            if current:
                words.append(current)
                current = ""
        else:
            current += character
        index += 1
    if quote is not None:
        raise ValueError("F6 Dockerfile shell form must not contain an unterminated quote")
    if current:
        words.append(current)
    return words


def _f6_dockerfile_copy_add_sources(source: str) -> list[dict[str, object]]:
    parsed: list[dict[str, object]] = []
    stage_index = -1
    stage_name: str | None = None
    for logical_line, escape_character in _f6_logical_dockerfile_lines(source):
        instruction_match = re.match(r"^([A-Za-z]+)\s+([\s\S]+)$", logical_line)
        if instruction_match is None:
            continue
        instruction = instruction_match.group(1).upper()
        if instruction == "FROM":
            from_match = re.fullmatch(
                r"FROM(?:\s+--[^\s]+)*\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?",
                logical_line,
                flags=re.IGNORECASE,
            )
            if from_match is None:
                raise ValueError(f"unsupported Dockerfile FROM instruction: {logical_line}")
            stage_index += 1
            stage_name = from_match.group(1)
            continue
        if instruction not in {"COPY", "ADD"}:
            continue

        arguments_text = instruction_match.group(2).lstrip()
        flags: dict[str, str] = {}
        while arguments_text.startswith("--"):
            flag_match = re.match(
                r"^--([A-Za-z][A-Za-z0-9_-]*)=([^\s]+)(?:\s+|$)",
                arguments_text,
            )
            if flag_match is None:
                raise ValueError(f"malformed Dockerfile {instruction} option: {logical_line}")
            flag_name = flag_match.group(1).lower()
            if flag_name in flags:
                raise ValueError(f"duplicate Dockerfile {instruction} option: {flag_name}")
            flags[flag_name] = flag_match.group(2)
            arguments_text = arguments_text[flag_match.end():].lstrip()

        if arguments_text.startswith("["):
            arguments = json.loads(arguments_text)
            if not isinstance(arguments, list) or not all(
                isinstance(argument, str) for argument in arguments
            ):
                raise ValueError(f"Dockerfile {instruction} JSON form must contain strings")
        else:
            arguments = _f6_split_docker_shell_words(arguments_text, escape_character)
        if len(arguments) < 2:
            raise ValueError(f"Dockerfile {instruction} must contain source and destination")
        for source_path in arguments[:-1]:
            parsed.append(
                {
                    "instruction": instruction,
                    "line": logical_line,
                    "source": source_path,
                    "stage_index": stage_index,
                    "stage_name": stage_name,
                    "from_stage": flags.get("from"),
                }
            )
    return parsed


def _f6_is_protected_docker_path(value: str) -> bool:
    components = {
        component.casefold()
        for component in value.replace("\\", "/").split("/")
        if component not in {"", ".", ".."}
    }
    return not components.isdisjoint(F6_PROTECTED_ROOTS)


def _f6_compose_volume_items(service: str) -> list[str]:
    lines = service.splitlines()
    volume_headers = [
        index for index, line in enumerate(lines) if line == "    volumes:"
    ]
    if len(volume_headers) != 1:
        raise AssertionError("app service must define exactly one volumes section")
    start = volume_headers[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        if re.fullmatch(r"    [A-Za-z0-9_-]+:", lines[index]):
            end = index
            break
    volume_lines = lines[start:end]
    item_starts = [
        index for index, line in enumerate(volume_lines) if line.startswith("      - ")
    ]
    return [
        "\n".join(volume_lines[item_start:item_end])
        for item_start, item_end in zip(item_starts, [*item_starts[1:], len(volume_lines)])
    ]


class PublicContainerContextTest(unittest.TestCase):
    """All mutable fixtures, fake executables, and hooks live under TEMP."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.node = _find_command("node", "NODE_EXE")
        cls.git = _find_command("git", "GIT_EXE")
        required = [GENERATOR, VERIFIER, GATEWAY, MANIFEST, COMPOSE, DOCKERFILE, RUNBOOK]
        missing = [name for name in required if not (REPO_ROOT / name).is_file()]
        if missing:
            raise unittest.SkipTest("repository source is unavailable: " + ", ".join(missing))

        cls.template_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-context-template-"
        )
        cls.template_root = Path(cls.template_temp.name).resolve() / "fixture"
        cls.template_root.mkdir()
        for relative in (GENERATOR, VERIFIER, GATEWAY, MANIFEST, COMPOSE, DOCKERFILE):
            destination = cls.template_root / PurePosixPath(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / relative, destination)

        base_files: dict[str, str | bytes] = {
            ".dockerignore": (REPO_ROOT / ".dockerignore").read_bytes(),
            ".gitignore": (
                "/.build/\n/ListeningPractice/\n/ReadingPractice/\n"
                "*.sql\n!backend/migrations/*.sql\n"
            ),
            "assets/allowed.bin": b"original-commit-bytes\x00\xff\n",
            "backend/.env.example": "SAFE_EXAMPLE=replace-me\n",
            "backend/DEPLOYMENT-RUNBOOK.md": "not public payload\n",
            "backend/admin/index.html": "admin fixture\n",
            "backend/auth/login.html": "auth fixture\n",
            "backend/migrations/001_init.sql": "SELECT 1;\n",
            "backend/package-lock.json": '{"lockfileVersion":3}\n',
            "backend/package.json": '{"name":"fixture"}\n',
            "backend/scripts/migrate.mjs": "export const migrate = true;\n",
            "backend/src/server.js": "export const server = true;\n",
            "css/main.css": "body{}\n",
            "index.html": "<!doctype html>\n",
            "js/app.js": "globalThis.fixture = true;\n",
            "src/styles/tokens.css": ":root{}\n",
            "templates/page.html": "<main></main>\n",
        }
        for relative, value in base_files.items():
            cls._write_at(cls.template_root, relative, value)

        cls._git_at(cls.template_root, "init")
        for key, value in (
            ("user.name", "Public Context Test"),
            ("user.email", "public-context-test@example.invalid"),
            ("commit.gpgsign", "false"),
            ("core.autocrlf", "false"),
            ("core.ignorecase", "false"),
            ("core.filemode", "true"),
        ):
            cls._git_at(cls.template_root, "config", key, value)
        cls._git_at(cls.template_root, "add", "-A")
        cls._git_at(cls.template_root, "commit", "-m", "fixture baseline")
        cls.template_commit = cls._git_at(
            cls.template_root, "rev-parse", "HEAD"
        ).stdout.decode("ascii").strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temp.cleanup()

    def setUp(self) -> None:
        self.case_temp = tempfile.TemporaryDirectory(
            prefix="ieltmps-public-context-case-"
        )
        self.temp_root = Path(self.case_temp.name).resolve()
        self.fixture_root = self.temp_root / "fixture"
        shutil.copytree(self.template_root, self.fixture_root)
        self.base_commit = self._head()
        self.output_path = self.temp_root / "generated-context"
        self.assertEqual(self.base_commit, self.template_commit)

    def tearDown(self) -> None:
        self.case_temp.cleanup()

    @classmethod
    def _environment_for(
        cls,
        *,
        restricted_path: bool = False,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        env = os.environ.copy()
        for name in GIT_REDIRECTION_NAMES:
            env.pop(name, None)
        path_parts = [str(cls.git.parent), str(cls.node.parent)]
        if not restricted_path and env.get("PATH"):
            path_parts.append(env["PATH"])
        env["PATH"] = os.pathsep.join(path_parts)
        env["GIT_OPTIONAL_LOCKS"] = "0"
        env["GIT_TERMINAL_PROMPT"] = "0"
        if extra:
            env.update(extra)
        return env

    @classmethod
    def _git_at(
        cls,
        root: Path,
        *args: str,
        input_bytes: bytes | None = None,
        original: bool = False,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        prefix = [str(cls.git)]
        if original:
            prefix.append("--no-replace-objects")
        completed = subprocess.run(
            [*prefix, "-C", str(root), *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=cls._environment_for(
                extra={"GIT_NO_REPLACE_OBJECTS": "1"} if original else None
            ),
            timeout=30,
        )
        if completed.returncode != 0 and not allow_failure:
            raise AssertionError(completed.stdout.decode("utf-8", errors="replace"))
        return completed

    def _git(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        original: bool = False,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self._git_at(
            self.fixture_root,
            *args,
            input_bytes=input_bytes,
            original=original,
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

    def _commit_paths(self, message: str, *paths: str, force: bool = False) -> str:
        add = ["add"]
        if force:
            add.append("-f")
        self._git(*add, "--", *paths)
        self._git("commit", "-m", message)
        return self._head()

    def _manifest_value(self) -> dict[str, object]:
        return json.loads((self.fixture_root / MANIFEST).read_text(encoding="utf-8"))

    def _commit_manifest(
        self, message: str, mutate: Callable[[dict[str, object]], None]
    ) -> str:
        value = self._manifest_value()
        mutate(value)
        (self.fixture_root / MANIFEST).write_bytes(_json_bytes(value))
        return self._commit_paths(message, MANIFEST)

    def _run(
        self,
        argv: list[str],
        *,
        extra_env: dict[str, str] | None = None,
        restricted_path: bool = False,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            cwd=self.fixture_root,
            env=self._environment_for(
                restricted_path=restricted_path,
                extra=extra_env,
            ),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )

    def _run_generator(
        self,
        *,
        commit: str | None = None,
        output: Path | None = None,
        extra_args: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = [
            str(self.node),
            str(self.fixture_root / GENERATOR),
            "--repo",
            str(self.fixture_root),
            "--commit",
            commit or self.base_commit,
            "--output",
            str(output or self.output_path),
        ]
        if extra_args:
            argv.extend(extra_args)
        return self._run(argv, extra_env=extra_env)

    def _assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout)

    def _assert_failure(
        self,
        result: subprocess.CompletedProcess[str],
        expected: str | None = None,
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        if expected:
            self.assertIn(expected.lower(), result.stdout.lower())

    def _generate(
        self, *, commit: str | None = None, output: Path | None = None
    ) -> Path:
        target = output or self.output_path
        result = self._run_generator(commit=commit, output=target)
        self._assert_success(result)
        status_value = json.loads(result.stdout)
        self.assertEqual(status_value["status"], "ok")
        self.assertEqual(Path(status_value["output"]).resolve(), target.resolve())
        self.assertRegex(status_value["receiptSha256"], r"^[0-9a-f]{64}$")
        return target

    @staticmethod
    def _receipt(context: Path) -> dict[str, object]:
        return json.loads((context / RECEIPT).read_text(encoding="utf-8"))

    @staticmethod
    def _receipt_sha(context: Path) -> str:
        return _sha256((context / RECEIPT).read_bytes())

    def _run_verifier(
        self,
        context: Path,
        *,
        mode: str = "--full",
        commit: str | None = None,
        manifest_sha: str | None = None,
        receipt_sha: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        receipt = self._receipt(context) if (context / RECEIPT).is_file() else {}
        argv = [
            str(self.node),
            str(self.fixture_root / VERIFIER),
            mode,
            "--context",
            str(context.resolve()),
            "--expected-commit",
            commit or str(receipt.get("sourceCommit", self.base_commit)),
            "--expected-manifest-sha256",
            manifest_sha or str(receipt.get("manifestSha256", "0" * 64)),
            "--expected-receipt-sha256",
            receipt_sha or (self._receipt_sha(context) if (context / RECEIPT).is_file() else "0" * 64),
        ]
        return self._run(argv)

    def _forge_receipt(
        self, context: Path, mutate: Callable[[dict[str, object]], None]
    ) -> str:
        value = self._receipt(context)
        mutate(value)
        receipt_bytes = _json_bytes(value)
        (context / RECEIPT).write_bytes(receipt_bytes)
        return _sha256(receipt_bytes)

    def _hash_blob(self, value: bytes) -> str:
        return self._git(
            "hash-object", "-w", "--stdin", input_bytes=value, original=True
        ).stdout.decode("ascii").strip()

    def _ls_tree_entries(
        self, treeish: str
    ) -> list[tuple[str, str, str, bytes]]:
        result = self._git("ls-tree", "-z", treeish, original=True).stdout
        entries: list[tuple[str, str, str, bytes]] = []
        for record in result.split(b"\0"):
            if not record:
                continue
            header, name = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            entries.append((mode, object_type, object_id, name))
        return entries

    def _hash_tree(self, entries: list[tuple[str, str, str, bytes]]) -> str:
        def tree_key(entry: tuple[str, str, str, bytes]) -> bytes:
            return entry[3] + (b"/" if entry[1] == "tree" else b"")

        raw = bytearray()
        for mode, _object_type, object_id, name in sorted(entries, key=tree_key):
            raw_mode = mode.lstrip("0") or "0"
            raw.extend(raw_mode.encode("ascii") + b" " + name + b"\0")
            raw.extend(bytes.fromhex(object_id))
        return self._git(
            "hash-object",
            "--literally",
            "-t",
            "tree",
            "-w",
            "--stdin",
            input_bytes=bytes(raw),
            original=True,
        ).stdout.decode("ascii").strip()

    def _commit_with_asset_entries(
        self,
        entries: list[tuple[str, str, str, bytes]],
        message: str,
    ) -> str:
        assets = self._ls_tree_entries(f"{self.base_commit}:assets")
        assets.extend(entries)
        assets_tree = self._hash_tree(assets)
        root = self._ls_tree_entries(self.base_commit)
        root = [
            (mode, kind, assets_tree if name == b"assets" else object_id, name)
            for mode, kind, object_id, name in root
        ]
        root_tree = self._hash_tree(root)
        return self._git(
            "commit-tree",
            root_tree,
            "-p",
            self.base_commit,
            input_bytes=(message + "\n").encode("utf-8"),
            original=True,
        ).stdout.decode("ascii").strip()

    def _commit_with_raw_asset_name(self, name: str, message: str) -> str:
        blob = self._hash_blob(b"unsafe portable path fixture\n")
        return self._commit_with_asset_entries(
            [("100644", "blob", blob, name.encode("utf-8"))], message
        )

    def _make_fake_docker(self, fake_id: str = "fake") -> Path:
        fake_path = self.temp_root / f"fake-docker-{fake_id}.mjs"
        fake_source = """import fs from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
const fIndexes = args.flatMap((value, index) => value === '-f' ? [index] : []);
const overridePath = fIndexes.length === 2 ? args[fIndexes[1] + 1] : null;
const overrideText = overridePath && fs.existsSync(overridePath)
  ? fs.readFileSync(overridePath, 'utf8') : '';
const match = /^\\s*context:\\s*'(.*)'\\s*$/m.exec(overrideText);
const contextPath = match ? match[1].replaceAll("''", "'") : null;
const countPath = process.env.IELTMPS_TEST_DOCKER_COUNT;
if (countPath) fs.appendFileSync(countPath, '1');
const record = {
  fakeId: __FAKE_ID__,
  argv: args,
  identities: {
    IELTMPS_SOURCE_COMMIT: process.env.IELTMPS_SOURCE_COMMIT,
    IELTMPS_CONTEXT_MANIFEST_SHA256: process.env.IELTMPS_CONTEXT_MANIFEST_SHA256,
    IELTMPS_CONTEXT_RECEIPT_SHA256: process.env.IELTMPS_CONTEXT_RECEIPT_SHA256,
  },
  overridePath,
  overrideExists: Boolean(overridePath && fs.existsSync(overridePath)),
  overrideText,
  contextPath,
  contextExists: Boolean(contextPath && fs.existsSync(contextPath)),
  transactionPath: overridePath ? path.dirname(overridePath) : null,
};
fs.writeFileSync(process.env.IELTMPS_TEST_DOCKER_RECORD, JSON.stringify(record));
process.exit(Number(process.env.IELTMPS_TEST_DOCKER_EXIT || '0'));
""".replace("__FAKE_ID__", json.dumps(fake_id))
        fake_path.write_text(fake_source, encoding="utf-8", newline="\n")
        return fake_path.resolve()

    def _make_tamper_hook(self) -> Path:
        hook_path = self.temp_root / "tamper-before-invoke.mjs"
        hook_path.write_text(
            """import fs from 'node:fs';
import path from 'node:path';
const context = process.argv[2];
fs.appendFileSync(path.join(context, 'assets', 'allowed.bin'), 'tampered');
if (process.env.IELTMPS_TEST_HOOK_RECORD) {
  fs.writeFileSync(process.env.IELTMPS_TEST_HOOK_RECORD, context);
}
""",
            encoding="utf-8",
            newline="\n",
        )
        return hook_path.resolve()

    def _run_gateway(
        self,
        *,
        fake: Path | None = None,
        hook: Path | None = None,
        extra_args: list[str] | None = None,
        docker_exit: int = 0,
        production: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        record = self.temp_root / "fake-docker-record.json"
        count = self.temp_root / "fake-docker-count.txt"
        argv = [
            str(self.node),
            str(self.fixture_root / GATEWAY),
            "--repo",
            str(self.fixture_root),
            "--commit",
            self.base_commit,
        ]
        if not production:
            self.assertIsNotNone(fake)
            argv.extend(["--test-mode", "--docker-executable", str(fake)])
            if hook:
                argv.extend(["--test-before-invoke-hook", str(hook)])
        if extra_args:
            argv.extend(extra_args)
        result = self._run(
            argv,
            restricted_path=production,
            extra_env={
                "IELTMPS_TEST_DOCKER_RECORD": str(record),
                "IELTMPS_TEST_DOCKER_COUNT": str(count),
                "IELTMPS_TEST_DOCKER_EXIT": str(docker_exit),
                "IELTMPS_TEST_HOOK_RECORD": str(self.temp_root / "hook-record.txt"),
            },
            timeout=90,
        )
        return result, record, count

    @staticmethod
    def _record(path: Path) -> dict[str, object]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _transaction_children(self) -> list[Path]:
        parent = self.fixture_root / ".build/public-container-transactions"
        return list(parent.iterdir()) if parent.is_dir() else []

    # Previous positive and negative generator behavior.

    def test_generator_materializes_only_selected_commit_payload(self) -> None:
        context = self._generate()
        actual = {
            path.relative_to(context).as_posix()
            for path in context.rglob("*")
            if path.is_file() and path.name != RECEIPT
        }
        expected = {
            ".dockerignore",
            "assets/allowed.bin",
            "backend/.env.example",
            "backend/Dockerfile",
            "backend/admin/index.html",
            "backend/auth/login.html",
            "backend/migrations/001_init.sql",
            "backend/package-lock.json",
            "backend/package.json",
            "backend/scripts/migrate.mjs",
            "backend/src/server.js",
            "css/main.css",
            "developer/verify-public-container-context.mjs",
            "index.html",
            "js/app.js",
            "src/styles/tokens.css",
            "templates/page.html",
        }
        self.assertSetEqual(actual, expected)

    def test_generator_uses_commit_bytes_and_excludes_worktree_additions(self) -> None:
        self._write("assets/allowed.bin", b"dirty bytes\n")
        for path in ("assets/untracked.txt", "js/untracked.js", "backend/src/new.js"):
            self._write(path, "untracked\n")
        context = self._generate()
        self.assertEqual(
            (context / "assets/allowed.bin").read_bytes(),
            b"original-commit-bytes\x00\xff\n",
        )
        for path in ("assets/untracked.txt", "js/untracked.js", "backend/src/new.js"):
            self.assertFalse((context / PurePosixPath(path)).exists())

    def test_generator_omits_private_and_forbidden_tracked_families(self) -> None:
        fixtures = {
            "ListeningPractice/private.mp3": b"private",
            "ReadingPractice/private.html": b"private",
            "assets/.env": b"SECRET=x",
            "assets/private.key": b"key",
            "js/cache.backup": b"backup",
            "backend/src/local.sqlite": b"db",
            "backend/admin/debug.log": b"log",
        }
        for path, value in fixtures.items():
            self._write(path, value)
        commit = self._commit_paths("forbidden fixtures", *fixtures, force=True)
        context = self._generate(commit=commit)
        paths = {entry["path"] for entry in self._receipt(context)["files"]}
        for path in fixtures:
            self.assertNotIn(path, paths)
            self.assertFalse((context / PurePosixPath(path)).exists())

    def test_selected_git_symlink_is_rejected(self) -> None:
        blob = self._hash_blob(b"target\n")
        commit = self._commit_with_asset_entries(
            [("120000", "blob", blob, b"linked")], "symlink fixture"
        )
        result = self._run_generator(commit=commit)
        self._assert_failure(result, "symlink")
        self.assertFalse(self.output_path.exists())

    def test_selected_gitlink_is_rejected(self) -> None:
        commit = self._commit_with_asset_entries(
            [("160000", "commit", self.base_commit, b"submodule")],
            "gitlink fixture",
        )
        result = self._run_generator(commit=commit)
        self._assert_failure(result, "submodule")

    def test_selected_case_collision_is_rejected(self) -> None:
        upper = self._hash_blob(b"upper\n")
        lower = self._hash_blob(b"lower\n")
        commit = self._commit_with_asset_entries(
            [
                ("100644", "blob", upper, b"Case.txt"),
                ("100644", "blob", lower, b"case.txt"),
            ],
            "case collision",
        )
        self._assert_failure(self._run_generator(commit=commit), "case-colliding")

    def test_existing_output_is_never_replaced_or_deleted(self) -> None:
        self.output_path.mkdir()
        sentinel = self.output_path / "keep-me.txt"
        sentinel.write_bytes(b"preserve\n")
        self._assert_failure(self._run_generator(), "already exists")
        self.assertEqual(sentinel.read_bytes(), b"preserve\n")

    def test_receipt_is_deterministic_exact_and_workstation_path_free(self) -> None:
        first = self._generate(output=self.temp_root / "first")
        second = self._generate(output=self.temp_root / "second")
        self.assertEqual((first / RECEIPT).read_bytes(), (second / RECEIPT).read_bytes())
        receipt = self._receipt(first)
        self.assertEqual(
            set(receipt),
            {"schemaVersion", "sourceCommit", "manifestPath", "manifestSha256", "fileCount", "files"},
        )
        self.assertEqual(receipt["schemaVersion"], 2)
        self.assertEqual(receipt["sourceCommit"], self.base_commit)
        self.assertEqual(receipt["manifestPath"], MANIFEST)
        self.assertEqual(receipt["fileCount"], len(receipt["files"]))
        serialized = json.dumps(receipt)
        self.assertNotIn(str(self.fixture_root), serialized)
        self.assertNotIn(str(self.temp_root), serialized)
        self.assertEqual([e["path"] for e in receipt["files"]], sorted(e["path"] for e in receipt["files"]))
        for entry in receipt["files"]:
            self.assertEqual(set(entry), {"path", "sha256", "executable"})
            self.assertEqual(
                entry["sha256"],
                _sha256((first / PurePosixPath(entry["path"])).read_bytes()),
            )
            self.assertIs(type(entry["executable"]), bool)

    def test_manifest_schema_v2_is_narrow_and_has_no_mutable_denials(self) -> None:
        manifest = json.loads((REPO_ROOT / MANIFEST).read_text(encoding="utf-8"))
        self.assertEqual(set(manifest), {"schemaVersion", "includeExact", "includePrefixes"})
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertIn(VERIFIER, manifest["includeExact"])
        self.assertNotIn("/", manifest["includePrefixes"])
        serialized = json.dumps(manifest).lower()
        for forbidden_key in ("exclude", "exception", "policyfile", "environmentfiles"):
            self.assertNotIn(forbidden_key, serialized)

    def test_deployment_runbook_is_absent_from_context(self) -> None:
        context = self._generate()
        self.assertFalse((context / "backend/DEPLOYMENT-RUNBOOK.md").exists())
        self.assertNotIn(
            "backend/DEPLOYMENT-RUNBOOK.md",
            {entry["path"] for entry in self._receipt(context)["files"]},
        )

    def test_commit_argument_accepts_uppercase_only_and_rejects_abbreviations(self) -> None:
        upper = self._run_generator(commit=self.base_commit.upper())
        self._assert_success(upper)
        for value in (self.base_commit[:12], "a" * 39, "g" * 40):
            output = self.temp_root / f"bad-{len(value)}-{value[0]}"
            with self.subTest(value=value):
                self._assert_failure(self._run_generator(commit=value, output=output))

    def test_selected_executable_mode_is_platform_aware(self) -> None:
        blob = self._hash_blob(b"#!/bin/sh\nexit 0\n")
        commit = self._commit_with_asset_entries(
            [("100755", "blob", blob, b"tool.sh")], "executable fixture"
        )
        result = self._run_generator(commit=commit)
        if os.name == "nt":
            self._assert_failure(result, "unsupported on Windows")
        else:
            self._assert_success(result)
            entry = next(
                item for item in self._receipt(self.output_path)["files"]
                if item["path"] == "assets/tool.sh"
            )
            self.assertIs(entry["executable"], True)

    # Part I 1-15: commit-owned policy and original-object semantics.

    def test_01_dirty_worktree_manifest_is_ignored(self) -> None:
        dirty = self._manifest_value()
        dirty["includeExact"].append("README.md")
        (self.fixture_root / MANIFEST).write_bytes(_json_bytes(dirty))
        context = self._generate()
        original = self._git("show", f"{self.base_commit}:{MANIFEST}", original=True).stdout
        self.assertEqual(self._receipt(context)["manifestSha256"], _sha256(original))

    def test_02_untracked_worktree_manifest_is_ignored(self) -> None:
        self._git("rm", "--", MANIFEST)
        self._git("commit", "-m", "commit without manifest")
        absent_commit = self._head()
        shutil.copy2(self.template_root / MANIFEST, self.fixture_root / MANIFEST)
        self._assert_failure(self._run_generator(commit=absent_commit), "does not contain")

    def test_03_manifest_absent_from_selected_commit_fails(self) -> None:
        self._git("rm", "--", MANIFEST)
        self._git("commit", "-m", "manifest absent")
        self._assert_failure(self._run_generator(commit=self._head()), "does not contain")

    def test_04_manifest_entry_outside_ceiling_fails(self) -> None:
        commit = self._commit_manifest(
            "outside ceiling",
            lambda value: value["includeExact"].append("README.md"),
        )
        self._assert_failure(self._run_generator(commit=commit), "ceiling")

    def test_05_manifest_cannot_add_exception_field(self) -> None:
        commit = self._commit_manifest(
            "mutable exception",
            lambda value: value.update({"exceptions": ["assets/private.sql"]}),
        )
        self._assert_failure(self._run_generator(commit=commit), "exactly")

    def test_06_exact_include_cannot_override_mandatory_denial(self) -> None:
        commit = self._commit_manifest(
            "exact denial",
            lambda value: value["includeExact"].append(".env"),
        )
        result = self._run_generator(commit=commit)
        self._assert_failure(result, "forbidden")
        self.assertNotIn("outside the code-owned", result.stdout.lower())

    def test_07_to_10_sql_and_archive_families_are_omitted(self) -> None:
        fixtures = {
            "assets/export.sql": "secret sql\n",
            "assets/export.sql.gz": b"compressed sql",
            "assets/source.tar": b"tar",
            "assets/source.tar.gz": b"tar gz",
        }
        for path, value in fixtures.items():
            self._write(path, value)
        commit = self._commit_paths("denied SQL archives", *fixtures, force=True)
        context = self._generate(commit=commit)
        paths = {entry["path"] for entry in self._receipt(context)["files"]}
        for path in fixtures:
            with self.subTest(path=path):
                self.assertNotIn(path, paths)

    def test_11_reviewed_direct_migration_sql_is_allowed(self) -> None:
        context = self._generate()
        self.assertEqual(
            (context / "backend/migrations/001_init.sql").read_text(encoding="utf-8"),
            "SELECT 1;\n",
        )
        entry = next(
            item for item in self._receipt(context)["files"]
            if item["path"] == "backend/migrations/001_init.sql"
        )
        self.assertEqual(entry["sha256"], _sha256(b"SELECT 1;\n"))

    def test_12_nested_and_malformed_migration_sql_are_denied(self) -> None:
        fixtures = {
            "backend/migrations/nested/002_hidden.sql": "hidden\n",
            "backend/migrations/bad.sql": "bad\n",
            "backend/migrations/002-BAD.sql": "bad\n",
        }
        for path, value in fixtures.items():
            self._write(path, value)
        commit = self._commit_paths("bad migrations", *fixtures, force=True)
        context = self._generate(commit=commit)
        paths = {entry["path"] for entry in self._receipt(context)["files"]}
        self.assertTrue(set(fixtures).isdisjoint(paths))

    def test_13_git_replace_does_not_change_selected_tree_bytes(self) -> None:
        self._write("assets/allowed.bin", b"replacement bytes\n")
        replacement = self._commit_paths("replacement content", "assets/allowed.bin")
        self._git("replace", self.base_commit, replacement)
        context = self._generate(commit=self.base_commit)
        self.assertEqual(
            (context / "assets/allowed.bin").read_bytes(),
            b"original-commit-bytes\x00\xff\n",
        )

    def test_14_replacement_provided_manifest_is_ignored(self) -> None:
        self._git("rm", "--", MANIFEST)
        self._git("commit", "-m", "original missing manifest")
        original = self._head()
        shutil.copy2(self.template_root / MANIFEST, self.fixture_root / MANIFEST)
        replacement = self._commit_paths("replacement adds manifest", MANIFEST)
        self._git("replace", original, replacement)
        self._assert_failure(self._run_generator(commit=original), "does not contain")

    def test_15_receipt_association_uses_original_commit_and_manifest(self) -> None:
        original_manifest = self._git(
            "show", f"{self.base_commit}:{MANIFEST}", original=True
        ).stdout
        self._write("assets/allowed.bin", b"replacement association\n")
        value = self._manifest_value()
        value["includeExact"].remove("index.html")
        (self.fixture_root / MANIFEST).write_bytes(_json_bytes(value))
        replacement = self._commit_paths(
            "replacement tree and manifest", "assets/allowed.bin", MANIFEST
        )
        self._git("replace", self.base_commit, replacement)
        receipt = self._receipt(self._generate(commit=self.base_commit))
        self.assertEqual(receipt["sourceCommit"], self.base_commit)
        self.assertEqual(receipt["manifestSha256"], _sha256(original_manifest))
        self.assertIn("index.html", {entry["path"] for entry in receipt["files"]})

    def test_generator_rejects_policy_override_cli_flags(self) -> None:
        for option in ("--manifest", "--policy-file", "--exceptions-file"):
            output = self.temp_root / f"override-{option[2:]}"
            result = self._run_generator(
                output=output, extra_args=[option, str(self.temp_root / "policy.json")]
            )
            with self.subTest(option=option):
                self._assert_failure(result, "invalid")
                self.assertFalse(output.exists())

    # Part I 16-24: independent verifier behavior and forged receipts.

    def test_verifier_full_mode_accepts_generated_context(self) -> None:
        result = self._run_verifier(self._generate(), mode="--full")
        self._assert_success(result)
        self.assertEqual(result.stdout, "")

    def test_verifier_receipt_only_accepts_preflight_subset(self) -> None:
        context = self._generate()
        preflight = self.temp_root / "preflight"
        (preflight / "developer").mkdir(parents=True)
        shutil.copy2(context / RECEIPT, preflight / RECEIPT)
        shutil.copy2(context / VERIFIER, preflight / VERIFIER)
        self._assert_success(self._run_verifier(preflight, mode="--receipt-only"))

    def test_16_missing_receipt_fails(self) -> None:
        context = self._generate()
        expected_sha = self._receipt_sha(context)
        (context / RECEIPT).unlink()
        self._assert_failure(
            self._run_verifier(context, receipt_sha=expected_sha), RECEIPT
        )

    def test_17_wrong_receipt_sha_fails(self) -> None:
        context = self._generate()
        self._assert_failure(
            self._run_verifier(context, receipt_sha="0" * 64), "receipt sha-256"
        )

    def test_18_wrong_expected_commit_fails(self) -> None:
        context = self._generate()
        wrong = "f" * 40 if self.base_commit != "f" * 40 else "e" * 40
        self._assert_failure(self._run_verifier(context, commit=wrong), "sourcecommit")

    def test_19_wrong_expected_manifest_hash_fails(self) -> None:
        context = self._generate()
        self._assert_failure(
            self._run_verifier(context, manifest_sha="0" * 64), "manifestsha256"
        )

    def test_20_extra_context_file_fails(self) -> None:
        context = self._generate()
        (context / "assets/extra.txt").write_text("extra\n", encoding="utf-8")
        self._assert_failure(self._run_verifier(context), "extra")

    def test_21_missing_context_file_fails(self) -> None:
        context = self._generate()
        (context / "assets/allowed.bin").unlink()
        self._assert_failure(self._run_verifier(context), "missing")

    def test_22_changed_context_bytes_fail(self) -> None:
        context = self._generate()
        (context / "assets/allowed.bin").write_bytes(b"changed\n")
        self._assert_failure(self._run_verifier(context), "sha-256")

    def test_23_wrong_executable_metadata_fails_on_all_platforms(self) -> None:
        context = self._generate()
        def toggle(value: dict[str, object]) -> None:
            entry = next(item for item in value["files"] if item["path"] == VERIFIER)
            entry["executable"] = not entry["executable"]
        receipt_sha = self._forge_receipt(context, toggle)
        self._assert_failure(
            self._run_verifier(context, receipt_sha=receipt_sha), "executable"
        )

    def test_24_forged_receipt_membership_fails(self) -> None:
        context = self._generate()
        def omit(value: dict[str, object]) -> None:
            value["files"] = [item for item in value["files"] if item["path"] != "assets/allowed.bin"]
            value["fileCount"] = len(value["files"])
        receipt_sha = self._forge_receipt(context, omit)
        self._assert_failure(
            self._run_verifier(context, receipt_sha=receipt_sha), "extra"
        )

    def test_verifier_rejects_unsafe_duplicate_forbidden_and_self_paths(self) -> None:
        base = self._generate()
        mutations: dict[str, Callable[[dict[str, object]], None]] = {}
        def unsafe(value: dict[str, object]) -> None:
            value["files"][0]["path"] = "C:/Users/example/private.txt"
        def duplicate(value: dict[str, object]) -> None:
            value["files"].append(dict(value["files"][0]))
            value["fileCount"] = len(value["files"])
        def forbidden(value: dict[str, object]) -> None:
            value["files"][0]["path"] = "ListeningPractice/private.txt"
        def self_member(value: dict[str, object]) -> None:
            verifier = next(item for item in value["files"] if item["path"] == VERIFIER)
            verifier["path"] = RECEIPT
        mutations.update(unsafe=unsafe, duplicate=duplicate, forbidden=forbidden, self_member=self_member)
        for name, mutate in mutations.items():
            variant = self.temp_root / f"verify-{name}"
            shutil.copytree(base, variant)
            receipt_sha = self._forge_receipt(variant, mutate)
            with self.subTest(name=name):
                self._assert_failure(self._run_verifier(variant, receipt_sha=receipt_sha))

    def test_verifier_rejects_nonportable_receipt_paths_in_both_modes(self) -> None:
        base = self._generate()
        unsafe_paths = (
            "assets/bad?.txt",
            "assets/CLOCK$.txt",
            "assets/c1\u0085control.txt",
            "assets/unpaired\ud800surrogate.txt",
        )
        for index, unsafe_path in enumerate(unsafe_paths):
            variant = self.temp_root / f"verify-portable-{index}"
            shutil.copytree(base, variant)

            def mutate(value: dict[str, object], path_value: str = unsafe_path) -> None:
                entry = next(
                    item for item in value["files"]
                    if item["path"] == "assets/allowed.bin"
                )
                entry["path"] = path_value
                value["files"].sort(key=lambda item: item["path"])

            receipt_sha = self._forge_receipt(variant, mutate)
            for mode in ("--receipt-only", "--full"):
                with self.subTest(path=ascii(unsafe_path), mode=mode):
                    self._assert_failure(
                        self._run_verifier(
                            variant,
                            mode=mode,
                            receipt_sha=receipt_sha,
                        )
                    )

    def test_verifier_rejects_symlink_or_reparse_member(self) -> None:
        context = self._generate()
        target = context / "assets/allowed.bin"
        target.unlink()
        try:
            target.symlink_to(context / "index.html")
        except OSError as error:
            self.skipTest(f"platform cannot create a symlink/reparse fixture: {error}")
        self._assert_failure(self._run_verifier(context), "reparse")

    # Part I 25-36: fake-Docker gateway replay, cleanup, and production rejection.

    def test_25_gateway_transactions_are_unique(self) -> None:
        fake = self._make_fake_docker("unique")
        records = []
        for index in range(2):
            result, record_path, _ = self._run_gateway(fake=fake)
            self._assert_success(result)
            record = self._record(record_path)
            records.append(record["transactionPath"])
            record_path.rename(self.temp_root / f"record-{index}.json")
        self.assertNotEqual(records[0], records[1])
        self.assertEqual(self._transaction_children(), [])

    def test_26_gateway_invokes_only_explicit_temp_fake_docker(self) -> None:
        fake = self._make_fake_docker("only-explicit-fake")
        self.assertTrue(fake.is_relative_to(self.temp_root))
        result, record_path, count_path = self._run_gateway(fake=fake)
        self._assert_success(result)
        self.assertEqual(self._record(record_path)["fakeId"], "only-explicit-fake")
        self.assertEqual(count_path.read_text(encoding="utf-8"), "1")

    def test_27_gateway_passes_canonical_compose_and_one_override(self) -> None:
        fake = self._make_fake_docker("compose")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        record = self._record(record_path)
        argv = record["argv"]
        self.assertEqual(argv[:2], ["compose", "-f"])
        self.assertEqual(Path(argv[2]).resolve(), (self.fixture_root / COMPOSE).resolve())
        self.assertEqual(argv.count("-f"), 2)
        self.assertEqual(Path(argv[4]).name, "compose.override.yml")
        self.assertTrue(record["overrideExists"])
        self.assertTrue(record["contextExists"])

    def test_28_gateway_builds_only_app_and_never_starts_services(self) -> None:
        fake = self._make_fake_docker("service")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        argv = self._record(record_path)["argv"]
        self.assertEqual(argv[-2:], ["build", "app"])
        self.assertNotIn("up", argv)
        self.assertNotIn("run", argv)

    def test_29_gateway_supplies_all_identity_values(self) -> None:
        fake = self._make_fake_docker("identity")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        record = self._record(record_path)
        identities = record["identities"]
        self.assertEqual(identities["IELTMPS_SOURCE_COMMIT"], self.base_commit)
        for name in IDENTITY_NAMES[1:]:
            self.assertRegex(identities[name], r"^[0-9a-f]{64}$")
            self.assertIn(name, record["overrideText"])
            self.assertIn(identities[name], record["overrideText"])

    def test_30_gateway_reverifies_after_tamper_hook_before_docker(self) -> None:
        fake = self._make_fake_docker("must-not-run")
        hook = self._make_tamper_hook()
        result, record_path, count_path = self._run_gateway(fake=fake, hook=hook)
        self._assert_failure(result, "re-verification")
        self.assertTrue((self.temp_root / "hook-record.txt").is_file())
        self.assertFalse(record_path.exists())
        self.assertFalse(count_path.exists())
        self.assertEqual(self._transaction_children(), [])

    def test_31_gateway_cleans_transaction_after_success(self) -> None:
        fake = self._make_fake_docker("success-cleanup")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        record = self._record(record_path)
        self.assertFalse(Path(record["transactionPath"]).exists())
        self.assertFalse(Path(record["overridePath"]).exists())
        self.assertFalse(Path(record["contextPath"]).exists())

    def test_32_gateway_returns_docker_status_and_cleans_after_failure(self) -> None:
        fake = self._make_fake_docker("failure-cleanup")
        result, record_path, count_path = self._run_gateway(fake=fake, docker_exit=17)
        self.assertEqual(result.returncode, 17, result.stdout)
        record = self._record(record_path)
        self.assertEqual(count_path.read_text(encoding="utf-8"), "1")
        self.assertFalse(Path(record["transactionPath"]).exists())

    def test_33_gateway_never_consumes_prior_persistent_context(self) -> None:
        persistent = self.fixture_root / ".build/ieltmps-public-container-context"
        persistent.mkdir(parents=True)
        sentinel = persistent / "do-not-consume.txt"
        sentinel.write_text("preserve\n", encoding="utf-8")
        fake = self._make_fake_docker("no-persistent")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        self.assertNotEqual(Path(self._record(record_path)["contextPath"]), persistent)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve\n")

    def test_34_gateway_preserves_arbitrary_build_content(self) -> None:
        unrelated = self.fixture_root / ".build/unrelated/keep.txt"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("keep\n", encoding="utf-8")
        fake = self._make_fake_docker("preserve-build")
        result, _, _ = self._run_gateway(fake=fake)
        self._assert_success(result)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep\n")

    def test_35_production_rejects_arbitrary_extra_compose_without_docker(self) -> None:
        extra = self.temp_root / "extra-compose.yml"
        extra.write_text("services: {}\n", encoding="utf-8")
        result, record, count = self._run_gateway(
            production=True, extra_args=["--compose-file", str(extra)]
        )
        self._assert_failure(result, "may only select")
        self.assertFalse(record.exists())
        self.assertFalse(count.exists())

    def test_36_production_rejects_context_manifest_receipt_and_dockerfile_flags(self) -> None:
        for option in ("--context", "--manifest", "--receipt", "--dockerfile", "--extra-compose-file"):
            with self.subTest(option=option):
                result, record, count = self._run_gateway(
                    production=True,
                    extra_args=[option, str(self.temp_root / "arbitrary")],
                )
                self._assert_failure(result, "invalid")
                self.assertFalse(record.exists())
                self.assertFalse(count.exists())

    def test_gateway_test_executable_requires_explicit_test_mode(self) -> None:
        fake = self._make_fake_docker("production-reject")
        result, record, count = self._run_gateway(
            production=True,
            extra_args=["--docker-executable", str(fake)],
        )
        self._assert_failure(result, "test-only")
        self.assertFalse(record.exists())
        self.assertFalse(count.exists())

    def test_gateway_fails_closed_on_dirty_trusted_worktree_verifier(self) -> None:
        (self.fixture_root / VERIFIER).write_text(
            "throw new Error('dirty trusted verifier executed');\n",
            encoding="utf-8",
            newline="\n",
        )
        fake = self._make_fake_docker("trusted-verifier-failure")
        result, record_path, _ = self._run_gateway(fake=fake)
        self._assert_failure(result, "full context verification")
        self.assertFalse(record_path.exists())
        self.assertEqual(self._transaction_children(), [])

    # Focused F6 runtime-only Listening overlay contract.

    def test_f6_reader_is_limited_to_approved_tracked_files(self) -> None:
        expected = frozenset(
            {MANIFEST, GENERATOR, VERIFIER, DOCKERFILE, COMPOSE, RUNBOOK}
        )
        self.assertSetEqual(F6_TRACKED_TEXT_PATHS, expected)
        for relative in sorted(F6_TRACKED_TEXT_PATHS):
            with self.subTest(relative=relative):
                tracked = self._git_at(
                    REPO_ROOT,
                    "ls-files",
                    "--error-unmatch",
                    "--",
                    relative,
                    original=True,
                )
                self.assertEqual(
                    tracked.stdout.decode("utf-8").splitlines(),
                    [relative],
                )
                self.assertIsInstance(_read_f6_tracked_text(relative), str)
        with self.assertRaisesRegex(ValueError, "not approved"):
            _read_f6_tracked_text("backend/package.json")

    def test_f6_manifest_and_code_policies_deny_both_protected_roots(self) -> None:
        manifest = json.loads(_read_f6_tracked_text(MANIFEST))
        selections = [*manifest["includeExact"], *manifest["includePrefixes"]]
        for selection in selections:
            components = {
                component.casefold()
                for component in PurePosixPath(selection.rstrip("/")).parts
            }
            with self.subTest(selection=selection):
                self.assertTrue(components.isdisjoint(F6_PROTECTED_ROOTS))

        generator = _read_f6_tracked_text(GENERATOR)
        verifier = _read_f6_tracked_text(VERIFIER)
        generator_denials = _f6_javascript_string_collection(
            generator, "DENIED_PATH_COMPONENTS"
        )
        verifier_denials = _f6_javascript_string_collection(
            verifier, "FORBIDDEN_COMPONENTS"
        )
        self.assertSetEqual(
            set(F6_PROTECTED_ROOTS),
            set(F6_PROTECTED_ROOTS & generator_denials),
        )
        self.assertSetEqual(
            set(F6_PROTECTED_ROOTS),
            set(F6_PROTECTED_ROOTS & verifier_denials),
        )
        self.assertIn("|| hasDeniedComponent(relativePath)", generator)
        self.assertIn(
            "components.some((component) => FORBIDDEN_COMPONENTS.has(component))",
            verifier,
        )

    def test_f6_dockerfile_parser_covers_common_protected_source_forms(self) -> None:
        synthetic = r"""
# COPY ListeningPractice ignored-comment
FROM scratch AS source
COPY ListeningPractice /one
COPY ./ReadingPractice /two
COPY ["ListeningPractice/example", "/three"]
ADD ReadingPractice/example /four
COPY \
  ./ListeningPractice/nested \
  /five
FROM scratch AS runtime
COPY --from=source /verified-context/ReadingPractice /six
"""
        parsed = _f6_dockerfile_copy_add_sources(synthetic)
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                f"FROM scratch\nCOPY Listening{chr(92)}Practice /seven\n"
            )
        )
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                "# escape=`\nFROM scratch\nCOPY Listening`Practice /eight\n"
            )
        )
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                f"FROM scratch\n# escape=`\nCOPY Listening{chr(92)}Practice /nine\n"
            )
        )
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                f"FROM scratch\nCOPY Listening{chr(92)}\nPractice /ten\n"
            )
        )
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                "# escape=`\nFROM scratch\nCOPY Reading`\nPractice /eleven\n"
            )
        )
        parsed.extend(
            _f6_dockerfile_copy_add_sources(
                f"# unknown=directive\n# escape=`\nFROM scratch\nCOPY Reading{chr(92)}Practice /twelve\n"
            )
        )
        protected = [
            entry for entry in parsed if _f6_is_protected_docker_path(str(entry["source"]))
        ]
        self.assertEqual(len(protected), 12)
        self.assertSetEqual(
            {str(entry["instruction"]) for entry in protected},
            {"COPY", "ADD"},
        )

    def test_f6_dockerfile_has_no_protected_sources_and_runtime_is_verified(self) -> None:
        dockerfile = _read_f6_tracked_text(DOCKERFILE)
        parsed = _f6_dockerfile_copy_add_sources(dockerfile)
        self.assertTrue(parsed)
        for entry in parsed:
            with self.subTest(line=entry["line"]):
                self.assertFalse(
                    _f6_is_protected_docker_path(str(entry["source"]))
                )

        logical_lines = _f6_logical_dockerfile_lines(dockerfile)
        from_entries = [
            (index, logical_line)
            for index, (logical_line, _) in enumerate(logical_lines)
            if re.match(r"(?i)^FROM(?:\s|$)", logical_line)
        ]
        self.assertTrue(from_entries)
        last_from_index, last_from = from_entries[-1]
        last_from_match = re.fullmatch(
            r"FROM(?:\s+--[^\s]+)*\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*",
            last_from,
            flags=re.IGNORECASE,
        )
        self.assertIsNotNone(last_from_match)
        last_stage_name = last_from_match.group(1) if last_from_match else None
        self.assertEqual((last_stage_name or "").casefold(), "runtime")
        runtime_index = len(from_entries) - 1
        runtime_entries = [
            entry for entry in parsed if entry["stage_index"] == runtime_index
        ]
        self.assertTrue(runtime_entries)
        for entry in runtime_entries:
            with self.subTest(line=entry["line"]):
                self.assertEqual(entry["instruction"], "COPY")
                self.assertEqual(entry["from_stage"], "verified-context")
        for logical_line, _ in logical_lines[last_from_index + 1:]:
            self.assertNotRegex(logical_line, r"(?i)^RUN\s+--mount=")

    def test_f6_compose_listening_mount_is_one_fail_closed_bind(self) -> None:
        app = _service_block(_read_f6_tracked_text(COMPOSE), "app")
        self.assertIsNotNone(app)
        items = _f6_compose_volume_items(app or "")
        listening = [
            item
            for item in items
            if "/app/ListeningPractice" in item
        ]
        self.assertEqual(len(listening), 1)
        mount = listening[0]
        self.assertEqual(
            mount,
            "\n".join(
                (
                    "      - type: bind",
                    "        source: ../ListeningPractice",
                    "        target: /app/ListeningPractice",
                    "        read_only: true",
                    "        bind:",
                    "          create_host_path: false",
                )
            ),
        )

    def test_f6_runbook_separates_image_and_runtime_readiness(self) -> None:
        runbook = _read_f6_tracked_text(RUNBOOK)
        self.assertNotIn("- `ListeningPractice/`", runbook)
        self.assertNotRegex(runbook, r"test\s+-d\s+/app/ListeningPractice")

        marker = "## Runtime-only Listening resource overlay"
        start = runbook.index(marker)
        following = re.search(r"(?m)^##\s+", runbook[start + len(marker):])
        end = (
            start + len(marker) + following.start()
            if following is not None
            else len(runbook)
        )
        section = runbook[start:end]
        stage_a_start = section.index("### Stage A - Public image verification")
        stage_b_start = section.index("### Stage B - Running-service overlay readiness")
        stage_a = section[stage_a_start:stage_b_start]
        stage_b = section[stage_b_start:]
        collapsed = re.sub(r"\s+", " ", section)

        self.assertNotIn("/app/ListeningPractice", stage_a)
        self.assertIn("/app/ListeningPractice", stage_b)
        for required in (
            "public application image intentionally excludes private Listening resources",
            "private resource root is absent from public image layers",
            "resources are provisioned separately from public image construction",
            "supplied only through the Compose runtime bind mount",
            "The overlay is runtime-only",
            "The bind mount must be read-only",
            "Compose-configured host source must already exist before Compose starts",
            "create_host_path` false",
            "Missing, unauthorized, unreadable, or incomplete overlay resources block readiness and launch",
            "Image verification and running-service overlay verification are separate gates",
            "passing either gate does not satisfy the other",
            "must not rebuild private Listening resources into public image layers",
            "authorization, manifesting, hashing, delivery, and rollback remain separately governed private-runtime procedures",
        ):
            with self.subTest(required=required):
                self.assertIn(required, collapsed)

    # Part I 37-45: Dockerfile, Compose, and ignore-file structural gates.

    def test_37_dockerfile_receipt_only_preflight_precedes_every_broad_copy(self) -> None:
        source = (REPO_ROOT / DOCKERFILE).read_text(encoding="utf-8")
        preflight = source.index("--receipt-only")
        self.assertLess(source.index(f"COPY {RECEIPT}"), preflight)
        self.assertLess(source.index(f"COPY {VERIFIER}"), preflight)
        for name in IDENTITY_NAMES:
            self.assertLess(source.index(f"ARG {name}"), preflight)
        broad = [
            match.start()
            for match in re.finditer(
                r"(?mi)^COPY\s+(?:assets|css|js|src/styles|templates|backend/src|backend/scripts|backend/migrations|backend/admin|backend/auth)\b",
                source,
            )
        ]
        self.assertTrue(broad)
        self.assertLess(preflight, min(broad))

    def test_38_final_stage_copies_only_from_verified_stage(self) -> None:
        source = (REPO_ROOT / DOCKERFILE).read_text(encoding="utf-8")
        runtime_match = re.search(r"(?mi)^FROM\s+\S+\s+AS\s+runtime\s*$", source)
        self.assertIsNotNone(runtime_match)
        runtime = source[runtime_match.end():]
        copies = [line for line in _logical_dockerfile_lines(runtime) if re.match(r"(?i)^COPY\b", line)]
        self.assertTrue(copies)
        for line in copies:
            self.assertRegex(line, r"(?i)^COPY\s+--from=verified-context\b")
        self.assertNotIn(RECEIPT, runtime)
        self.assertNotIn(VERIFIER, runtime)

    def test_39_dockerfile_has_no_private_copy_and_preserves_runtime_contract(self) -> None:
        source = (REPO_ROOT / DOCKERFILE).read_text(encoding="utf-8")
        for line in _logical_dockerfile_lines(source):
            if re.match(r"(?i)^(COPY|ADD)\b", line):
                self.assertNotIn("ListeningPractice", line)
                self.assertNotIn("ReadingPractice", line)
                self.assertNotIn("DEPLOYMENT-RUNBOOK.md", line)
        self.assertRegex(source, r"(?m)^USER node\s*$")
        self.assertIn(
            'CMD ["sh", "-c", "node scripts/migrate.mjs && node scripts/bootstrap-admin.mjs && node src/server.js"]',
            source,
        )

    def test_40_to_43_base_compose_is_fail_closed_without_context_fallback(self) -> None:
        source = (REPO_ROOT / COMPOSE).read_text(encoding="utf-8")
        app = _service_block(source, "app")
        self.assertIsNotNone(app)
        self.assertIn(f"context: {SENTINEL_CONTEXT}", app)
        contexts = re.findall(r"(?m)^\s+context:\s*(\S+)\s*$", app)
        self.assertEqual(contexts, [SENTINEL_CONTEXT])
        self.assertNotRegex(contexts[0], r"\$\{")
        self.assertNotIn("ieltmps-public-container-context", contexts[0].lower())
        for name in IDENTITY_NAMES:
            self.assertIn(f"{name}: ${{{name}:?Use developer/build-public-container.mjs}}", app)
        self.assertNotRegex(app, r"(?m)^\s+context:\s*\.\.?\s*$")

    def test_42_no_tracked_override_restores_repository_root_context(self) -> None:
        listed = subprocess.run(
            [str(self.git), "-C", str(REPO_ROOT), "ls-files", "--", "backend/docker-compose*.yml", "backend/docker-compose*.yaml"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=self._environment_for(restricted_path=True),
            timeout=30,
            check=True,
        ).stdout.splitlines()
        self.assertIn(COMPOSE, listed)
        for relative in listed:
            if relative == COMPOSE:
                continue
            app = _service_block((REPO_ROOT / relative).read_text(encoding="utf-8"), "app")
            if not app:
                continue
            context_lines = re.findall(r"(?m)^\s+context:\s*(\S+)\s*$", app)
            with self.subTest(path=relative):
                for context in context_lines:
                    self.assertNotIn(context, {".", "..", "../", "./"})
                    self.assertNotRegex(context, r"\$\{")

    def test_44_listening_mount_remains_read_only(self) -> None:
        app = _service_block((REPO_ROOT / COMPOSE).read_text(encoding="utf-8"), "app")
        self.assertRegex(
            app,
            r"source:\s*\.\./ListeningPractice[\s\S]*?target:\s*/app/ListeningPractice[\s\S]*?read_only:\s*true",
        )

    def test_45_listening_mount_disables_host_path_creation(self) -> None:
        app = _service_block((REPO_ROOT / COMPOSE).read_text(encoding="utf-8"), "app")
        listening = app[app.index("source: ../ListeningPractice"):]
        self.assertRegex(listening, r"bind:\s*\n\s+create_host_path:\s*false")

    def test_ignore_files_cover_transactions_private_data_sql_and_archives(self) -> None:
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/.build/public-container-transactions/", gitignore)
        self.assertIn("/.build/BUILD_VIA_DEVELOPER_BUILD_PUBLIC_CONTAINER_MJS", gitignore)
        dockerignore = {
            line.strip()
            for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        required = {
            ".git", ".build", "dist", "ListeningPractice", "ReadingPractice",
            "node_modules", "**/node_modules", "**/.env", "**/.env.*",
            "!backend/.env.example", "**/*.key", "**/*.pem", "**/*.dump",
            "**/*.sqlite", "**/*.log", "**/*.sql", "**/*.sql.gz",
            "**/*.tar", "**/*.tar.gz", "**/*.tgz", "**/*.zip", "**/*.7z",
            "**/*.rar", "!backend/migrations/*.sql", "**/authorized_clients",
            "**/authorized-clients", "**/hidden_service", "**/hidden-service",
            "**/onion-auth", "**/client-auth",
        }
        self.assertSetEqual(required - dockerignore, set())

    # Part I 46-52: portable output and interrupted publication.

    def test_46_to_50_nonportable_git_paths_fail(self) -> None:
        fixtures = {
            "reserved": "CON.txt",
            "trailing_dot": "bad.",
            "trailing_space": "bad ",
            "ads": "name:stream",
            "control": "bad\x01name.txt",
        }
        for label, name in fixtures.items():
            with self.subTest(label=label):
                commit = self._commit_with_raw_asset_name(name, label)
                output = self.temp_root / f"unsafe-{label}"
                result = self._run_generator(commit=commit, output=output)
                self._assert_failure(result)
                self.assertFalse(output.exists())

    def test_51_reparse_output_parent_fails_or_skips_with_platform_reason(self) -> None:
        real_parent = self.temp_root / "real-output-parent"
        real_parent.mkdir()
        linked_parent = self.temp_root / "linked-output-parent"
        try:
            linked_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"platform cannot create reparse/symlink fixture: {error}")
        output = linked_parent / "context"
        self._assert_failure(self._run_generator(output=output), "reparse")
        self.assertFalse((real_parent / "context").exists())

    def test_52_interrupted_generation_leaves_no_published_or_staged_context(self) -> None:
        result = self._run_generator(
            extra_env={
                "IELTMPS_PUBLIC_CONTEXT_TEST_MODE": "1",
                "IELTMPS_PUBLIC_CONTEXT_TEST_FAIL_BEFORE_PUBLISH": "1",
            }
        )
        self._assert_failure(result, "simulated")
        self.assertFalse(self.output_path.exists())
        self.assertEqual(list(self.temp_root.glob(".generated-context.tmp-*")), [])

    def test_interruption_hook_is_inert_without_explicit_test_mode(self) -> None:
        result = self._run_generator(
            extra_env={"IELTMPS_PUBLIC_CONTEXT_TEST_FAIL_BEFORE_PUBLISH": "1"}
        )
        self._assert_success(result)
        self.assertTrue((self.output_path / RECEIPT).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
