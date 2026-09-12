"""Focused transport tests only; no candidate recovery or hosted execution."""
from __future__ import annotations

import base64
import ast
import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import unittest
import types
from unittest import mock

import run_ci_foundation as ci
import issue13_diagnostic_capture as capture
import test_issue13_diagnostic_capture as fixtures
import issue13_acquisition_transport as transport


def local_gpg():
    # The local Windows workstation has a different installed GnuPG location.
    # This fixture does not add a hosted override or change production resolution.
    if os.name == "nt" and Path("D:/GnuPG/bin/gpg.exe").is_file():
        return Path("D:/GnuPG/bin/gpg.exe")
    return transport.find_gpg()


def certificate():
    return (ci.REPO_ROOT / transport.PUBLIC_KEY_PATH).read_bytes().replace(b"\r\n", b"\n")


def key_listing():
    lines = []
    for kind, fingerprint, algo, capability, curve in (
        ("pub", transport.PRIMARY, "22", "scESC", "ed25519"),
        ("sub", transport.SUBKEY, "18", "e", "cv25519")):
        row = [""] * 20
        row[0], row[1], row[2], row[3], row[4] = kind, "-", "255", algo, fingerprint[-16:]
        row[5], row[6], row[11], row[16] = "1000000000", "4000000000", capability, curve
        lines.append(":".join(row))
        fpr = [""] * 11
        fpr[0], fpr[9] = "fpr", fingerprint
        lines.append(":".join(fpr))
    return ("\n".join(lines) + "\n").encode()


def environment(root, phase="producer"):
    job = "windows-compatibility" if os.name == "nt" else "ubuntu-canonical"
    if phase == "producer":
        job += "-producer"
    return {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "13", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": transport.REPOSITORY,
            "GITHUB_REF": transport.BRANCH, "GITHUB_JOB": job, "RUNNER_TEMP": str(root),
            "UNRELATED_SECRET": fixtures.CANARY}


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="issue13-openpgp-tests-")
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)

    def ring(self, leaf="public-keyring"):
        return transport.PublicKeyring(local_gpg(), self.root / leaf, ci.REPO_ROOT, capture, certificate())

    def fixture_capture(self, phase="producer", family="frontend-security"):
        runner = fixtures.full_scope_fixture()
        env = environment(self.root, phase)
        env["GITHUB_SHA"] = runner.execution_binding["checkoutCommit"]
        transaction = transport.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], ci.platform_key())
        leaf = "issue13-producer" if phase == "producer" else "issue13-replay"
        summary = capture.capture_completed_runner(ci, runner, root=self.root / leaf,
            transaction=transaction, phase=phase, repo_root=ci.REPO_ROOT)
        return runner, env, summary, self.root / leaf

    def candidate(self, runner):
        return {"commit": runner.execution_binding["checkoutCommit"], "tree": runner.execution_binding["checkoutTree"],
                "captureCommit": transport.CAPTURE_COMMIT, "sources": []}

    def test_pinned_public_certificate_and_no_secret_packets(self):
        data = certificate()
        self.assertEqual(transport.digest(transport.public_armor(data)), transport.PUBLIC_KEY_SHA256)
        lines = data.decode().splitlines()
        tags = [tag for tag, _ in transport.packets(base64.b64decode("".join(lines[2:-2])), {2, 6, 13, 14})]
        self.assertEqual(tags.count(6), 1)
        self.assertEqual(tags.count(14), 2)
        for tag in (5, 7, 9, 18, 20):
            malicious = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + base64.b64encode(bytes([0xc0 | tag, 1, 0])) + b"\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
            with self.subTest(tag=tag), self.assertRaises(transport.TransportError):
                transport.public_armor(malicious)

    def test_fingerprint_and_capability_negative_matrix(self):
        valid = key_listing()
        self.assertEqual(transport.imported_identity(valid)["recipientSelector"], transport.SUBKEY + "!")
        cases = [valid.replace(transport.PRIMARY.encode(), b"0" * 40),
                 valid.replace(transport.SUBKEY.encode(), b"1" * 40),
                 valid.replace(b":e:", b":s:"), valid.replace(b"cv25519", b"nistp256"),
                 valid.replace(b":18:", b":22:"), valid.replace(b"sub:-:", b"sub:r:"),
                 valid.replace(b"pub:-:", b"pub:e:"), valid.replace(b":e:", b":eD:"),
                 valid.replace(b"4000000000", b"1000000001"), valid + valid,
                 valid.replace(b"sub:", b"ssb:"), valid.splitlines()[0] + b"\n"]
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(transport.TransportError):
                transport.imported_identity(value)

    def test_wrong_pin_rejected_before_keyring_or_import(self):
        armor = certificate().replace(b"\n", b"\r\n")
        with mock.patch.object(transport, "bounded_process") as process:
            with self.assertRaises(transport.TransportError):
                transport.PublicKeyring(local_gpg(), self.root / "wrong-pin", ci.REPO_ROOT, capture, armor)
        process.assert_not_called()
        self.assertFalse((self.root / "wrong-pin").exists())

    def test_real_public_only_import_and_exact_subkey_encryption(self):
        calls = []
        real = transport.bounded_process
        def observe(argv, home, **kwargs):
            calls.append(list(argv))
            return real(argv, home, **kwargs)
        with mock.patch.object(transport, "bounded_process", side_effect=observe):
            ring = self.ring()
            private = transport.private_tar({"0.stdout.bin": fixtures.CANARY.encode(), "public.json": b"{}\n"}, {"authority": transport.MARKER})
            encrypted = ring.encrypt(private)
        self.assertEqual(ring.identity["primaryFingerprint"], transport.PRIMARY)
        self.assertEqual(ring.identity["encryptionSubkeyFingerprint"], transport.SUBKEY)
        self.assertEqual(ring.identity["secretKeyCount"], 0)
        self.assertEqual(ring.run("--with-colons", "--list-secret-keys").strip(), b"")
        with self.assertRaises(transport.TransportError):
            ring.run("--decrypt", data=encrypted)  # Public-only keyring cannot decrypt.
        self.assertNotIn(fixtures.CANARY.encode(), encrypted)
        entries = transport.packets(encrypted, {1, 18, 20}, partial=True)
        self.assertEqual(entries[0][1][1:9].hex().upper(), transport.SUBKEY[-16:])
        self.assertIn(entries[1][0], (18, 20))
        encryption = [call for call in calls if "--encrypt" in call]
        self.assertEqual(len(encryption), 1)
        self.assertEqual(encryption[0][encryption[0].index("--recipient") + 1], transport.RECIPIENT)
        for call in calls:
            for flag in ("--no-options", "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve", "--no-auto-key-import"):
                self.assertIn(flag, call)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {"public-keyring"})
        transport.secret_free(ring.home)

    def test_secret_stub_and_unrecognized_keyring_file_rejected(self):
        home = self.root / "private-check"
        home.mkdir()
        secret_dir = home / "private-keys-v1.d"
        secret_dir.mkdir()
        transport.secret_free(home)
        (secret_dir / "fixture.key").write_bytes(b"NOT-A-KEY")
        with self.assertRaises(transport.TransportError):
            transport.secret_free(home)
        separate = self.root / "other-keyring"
        separate.mkdir()
        (separate / "secring.gpg").write_bytes(b"NOT-A-KEY")
        with self.assertRaises(transport.TransportError):
            transport.secret_free(separate)

    def test_ciphertext_wrong_recipient_or_unprotected_packets_rejected(self):
        ring = self.ring()
        body = bytes([3]) + bytes.fromhex("0000000000000000") + bytes([18])
        packet = bytes([0xc1, len(body)]) + body + bytes([0xd2, 2, 1, 0])
        for data in (packet, bytes([0xc9, 1, 0]), b"plaintext output"):
            with mock.patch.object(ring, "run", return_value=data), self.assertRaises(transport.TransportError):
                ring.encrypt(b"bounded synthetic input")

    def test_gpg_binary_change_and_failure_rejected(self):
        ring = self.ring()
        with mock.patch.object(transport, "bounded_file", return_value=b"changed"), self.assertRaises(transport.TransportError):
            ring.encrypt(b"synthetic")
        with mock.patch.object(transport, "bounded_process", side_effect=transport.TransportError("gpg-process")), self.assertRaises(transport.TransportError):
            ring.encrypt(b"synthetic")

    def test_subprocess_bounds_timeout_nonzero_and_environment_isolation(self):
        for code, limit, timeout in (("import sys;sys.stdout.buffer.write(b'x'*100000)", 100, 5),
                                    ("import time;time.sleep(2)", 100, 0.05),
                                    ("raise SystemExit(7)", 100, 5)):
            with self.subTest(code=code), self.assertRaises(transport.TransportError):
                transport.bounded_process([sys.executable, "-B", "-c", code], self.root, limit=limit, timeout=timeout)
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": fixtures.CANARY, "UNRELATED_SECRET": fixtures.CANARY}):
            data = transport.bounded_process([sys.executable, "-B", "-c", "import os;print('GITHUB_TOKEN' in os.environ or 'UNRELATED_SECRET' in os.environ)"], self.root)
        self.assertEqual(data.strip(), b"False")

    def test_private_archive_fixed_names_counts_metadata_and_bounds(self):
        files = {"0.stdout.bin": fixtures.CANARY.encode(), "public.json": b"{}\n"}
        encoded = transport.private_tar(files, {"authority": transport.MARKER})
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(encoded)), mode="r:") as archive:
            self.assertEqual(sorted(archive.getnames()), ["0.stdout.bin", "acquisition-manifest.json", "public.json"])
            self.assertEqual(archive.extractfile("0.stdout.bin").read(), files["0.stdout.bin"])
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode, member.uname, member.gname), (0, 0, 0, 0o600, "", ""))
        for bad in ({"../private": b"x"}, {"8.json": b"x"}, {"0.json": b"x" * (transport.MAX_PRIVATE_RECORD + 1)},
                    {str(n): b"x" for n in range(26)}):
            with self.assertRaises(transport.TransportError):
                transport.private_tar(bad, {})
        with self.assertRaises(transport.TransportError):
            transport.private_tar(files, {"large": "x" * transport.MAX_MANIFEST})

    def test_absent_private_destinations_fixed_names_no_overwrite(self):
        destination = transport.Destination(self.root / "output", ci.REPO_ROOT, capture)
        destination.write("public.json", b"{}", 10)
        with self.assertRaises(FileExistsError):
            destination.write("public.json", b"changed", 10)
        with self.assertRaises(FileExistsError):
            transport.Destination(destination.root, ci.REPO_ROOT, capture)
        for name in ("../other", "0.stdout.bin", "private.tar.gz", "secret.asc"):
            with self.assertRaises(transport.TransportError):
                destination.write(name, b"x", 10)
        with self.assertRaises(Exception):
            transport.Destination(ci.REPO_ROOT / "issue13-forbidden-output", ci.REPO_ROOT, capture)
        self.assertEqual((destination.root / "public.json").read_bytes(), b"{}")
        if os.name != "nt":
            self.assertEqual(destination.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination.root / "public.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX link creation and mode check")
    def test_symlink_hardlink_and_directory_rejected(self):
        source = self.root / "file"
        source.write_bytes(b"public")
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaises(transport.TransportError):
            transport.bounded_file(link, 100)
        hard = self.root / "hard"
        os.link(source, hard)
        with self.assertRaises(transport.TransportError):
            transport.bounded_file(hard, 100)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Exception):
            transport.Destination(alias / "out", ci.REPO_ROOT, capture)

    def test_paired_context_run_attempt_and_platform_fail_closed(self):
        env = environment(self.root)
        context = transport.live_context(env, "producer")
        self.assertEqual(len(context["transaction"]), 32)
        for key, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_REF", "refs/heads/codex/ci-recovery-node-replay"),
                           ("GITHUB_JOB", "repository-policy"), ("GITHUB_EVENT_NAME", "pull_request"),
                           ("GITHUB_SHA", "not-a-commit"), ("GITHUB_RUN_ID", "0")):
            with self.subTest(key=key), self.assertRaises(transport.TransportError):
                transport.live_context({**env, key: value}, "producer")
        with self.assertRaises(transport.TransportError):
            transport.live_context(env, "fresh-replay")

    def test_transaction_ids_are_exclusive_to_each_platform_pair(self):
        env = environment(self.root)
        ids = {platform_name: transport.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], platform_name)
               for platform_name in ("ubuntu", "windows")}
        self.assertNotEqual(ids["ubuntu"], ids["windows"])
        for job, (platform_name, phase) in transport.JOB_CONTEXT.items():
            with mock.patch.object(transport.os, "name", "nt" if platform_name == "windows" else "posix"):
                context = transport.live_context({**env, "GITHUB_JOB": job}, phase)
            self.assertEqual(context["transaction"], ids[platform_name])
        for invalid in (None, "", "Linux", "configuration", "ubuntu:windows"):
            with self.assertRaises(transport.TransportError):
                transport.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], invalid)
        for platform_name in ids:
            self.assertNotEqual(ids[platform_name], transport.transaction_id("b" * 40, "13", platform_name))
            self.assertNotEqual(ids[platform_name], transport.transaction_id("a" * 40, "14", platform_name))
        wrong = ids["ubuntu" if os.name == "nt" else "windows"]
        with mock.patch.object(transport, "source_identity") as authority:
            with self.assertRaises(transport.TransportError):
                transport.export_capture(ci.REPO_ROOT, env, "producer", wrong, "failure")
        authority.assert_not_called()

    def test_configuration_emits_exactly_two_platform_transaction_outputs(self):
        env = {**environment(self.root), "GITHUB_JOB": "acquisition-configuration",
               "GITHUB_OUTPUT": str(self.root / "configuration-output")}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(transport, "source_identity", return_value={}), \
             mock.patch.object(transport, "git_bytes", return_value=certificate()), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(transport.main(["configure"]), 0)
        outputs = dict(line.split("=", 1) for line in Path(env["GITHUB_OUTPUT"]).read_text().splitlines())
        self.assertEqual(outputs, {platform_name + "_transaction":
            transport.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], platform_name)
            for platform_name in ("ubuntu", "windows")})
        self.assertEqual(len(set(outputs.values())), 2)

    def test_snapshot_integrity_context_and_strict_inventory(self):
        _, env, summary, root = self.fixture_capture()
        context = transport.live_context(env, "producer")
        actual, files = transport.snapshot_capture(ci, capture, root, ci.REPO_ROOT, context)
        self.assertEqual(actual, summary)
        self.assertIn(fixtures.CANARY.encode(), files["0.stdout.bin"])
        with self.assertRaises(transport.TransportError):
            transport.snapshot_capture(ci, capture, root, ci.REPO_ROOT, {**context, "transaction": "0" * 32})
        original = (root / "0.stdout.bin").read_bytes()
        (root / "0.stdout.bin").write_bytes(original + b"tamper")
        with self.assertRaises(Exception):
            transport.snapshot_capture(ci, capture, root, ci.REPO_ROOT, context)

    def test_real_export_separates_ciphertext_public_json_and_preserves_authority(self):
        runner, env, summary, root = self.fixture_capture()
        before = ci._canonical_frame({"records": runner.command_results,
            "transcript": ci.verification_replay_transcript(runner), "violations": runner.violations,
            "hardGates": runner.hard_gate_results, "authorization": fixtures.claims_for(runner)})
        retained = {p.name: p.read_bytes() for p in root.iterdir()}
        fixture_identity = self.candidate(runner)
        with mock.patch.object(transport, "source_identity", return_value=fixture_identity), \
             mock.patch.object(transport, "git_bytes", return_value=certificate()), \
             mock.patch.object(transport, "find_gpg", return_value=local_gpg()):
            result = transport.export_capture(ci.REPO_ROOT, env, "producer", summary["transaction"], "failure")
        after = ci._canonical_frame({"records": runner.command_results,
            "transcript": ci.verification_replay_transcript(runner), "violations": runner.violations,
            "hardGates": runner.hard_gate_results, "authorization": fixtures.claims_for(runner)})
        self.assertEqual(before, after)
        self.assertEqual(retained, {p.name: p.read_bytes() for p in root.iterdir()})
        export = self.root / "issue13-producer-export"
        self.assertEqual(sorted(p.name for p in export.iterdir()), ["issue13-private.tar.gz.gpg", "public.json", "transport.json"])
        self.assertEqual((export / "public.json").read_bytes(), retained["public.json"])
        self.assertEqual(transport.digest((export / "issue13-private.tar.gz.gpg").read_bytes()), result["ciphertextSha256"])
        self.assertEqual(result["ordinaryStepOutcome"], "failure")
        for name in ("public.json", "transport.json"):
            self.assertNotIn(fixtures.CANARY.encode(), (export / name).read_bytes())
        self.assertFalse(any(p.suffix == ".gz" for p in self.root.rglob("*")))

    def test_transport_failure_never_changes_authoritative_state_or_exports_plaintext(self):
        runner, env, summary, root = self.fixture_capture()
        before = copy.deepcopy(runner.__dict__)
        original = {p.name: p.read_bytes() for p in root.iterdir()}
        for category in ("gpg-unavailable", "gpg-process", "recipient-rejected"):
            with mock.patch.object(transport, "source_identity", return_value=self.candidate(runner)), \
                 mock.patch.object(transport, "git_bytes", return_value=certificate()), \
                 mock.patch.object(transport, "find_gpg", side_effect=transport.TransportError(category)), \
                 self.assertRaises(transport.TransportError):
                transport.export_capture(ci.REPO_ROOT, env, "producer", summary["transaction"], "failure")
            self.assertEqual(runner.__dict__, before)
            self.assertEqual(original, {p.name: p.read_bytes() for p in root.iterdir()})
            self.assertFalse((self.root / "issue13-producer-export").exists())

    def test_paired_export_preserves_each_available_protocol_family(self):
        initial_root = self.root
        for family in ("all",):
            self.root = initial_root / family
            self.root.mkdir()
            summaries = []
            for phase in ("producer", "fresh-replay"):
                runner, env, summary, source = self.fixture_capture(phase=phase, family=family)
                self.assertEqual({row["family"] for row in summary["records"]}, set(capture.FAMILIES))
                self.assertIn(702, [row["ordinal"] for row in summary["records"]])
                before = ci._canonical_frame({"records": runner.command_results,
                    "canonicalReplayTranscript": ci.verification_replay_transcript(runner),
                    "violations": runner.violations, "hardGates": runner.hard_gate_results,
                    "authorizationClaims": fixtures.claims_for(runner)})
                retained = {path.name: path.read_bytes() for path in source.iterdir()}
                with mock.patch.object(transport, "source_identity", return_value=self.candidate(runner)), \
                     mock.patch.object(transport, "git_bytes", return_value=certificate()), \
                     mock.patch.object(transport, "find_gpg", return_value=local_gpg()):
                    result = transport.export_capture(ci.REPO_ROOT, env, phase, summary["transaction"], "failure")
                after = ci._canonical_frame({"records": runner.command_results,
                    "canonicalReplayTranscript": ci.verification_replay_transcript(runner),
                    "violations": runner.violations, "hardGates": runner.hard_gate_results,
                    "authorizationClaims": fixtures.claims_for(runner)})
                self.assertEqual(before, after)
                self.assertEqual(retained, {path.name: path.read_bytes() for path in source.iterdir()})
                self.assertEqual(result["ordinaryStepOutcome"], "failure")
                summaries.append(summary)
            comparison = capture.compare_public(*summaries)
            self.assertEqual(comparison["records"][0]["pair"], "present")
            self.assertEqual(comparison["records"][0]["changedFields"], [])
        self.root = initial_root

    def test_cli_exception_text_remains_private(self):
        output = io.StringIO()
        with mock.patch.object(transport, "export_capture", side_effect=ValueError(fixtures.CANARY)), \
             contextlib.redirect_stderr(output):
            status = transport.main(["export", "--phase", "producer", "--transaction", "0" * 32, "--ordinary-outcome", "failure"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), transport.MARKER + ": transport unavailable\n")

    def test_workflow_preserves_ordinary_commands_and_isolates_exports(self):
        base = ci.parse_canonical_workflow_yaml((ci.REPO_ROOT / ".github/workflows/ci.yml").read_text())
        acquisition = ci.parse_canonical_workflow_yaml((ci.REPO_ROOT / ".github/workflows/issue-13-acquisition.yml").read_text())
        self.assertEqual(ci.check_workflow_text((ci.REPO_ROOT / ".github/workflows/ci.yml").read_text()), [])
        self.assertEqual(acquisition["on"], {"push": {"branches": ["codex/issue-13-acquisition"]}})
        self.assertEqual(acquisition["permissions"], {"contents": "read"})
        self.assertEqual(acquisition["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(acquisition["jobs"]["acquisition-configuration"]["if"], "${{ github.event.created == true && github.run_attempt == 1 }}")
        self.assertEqual(set(acquisition["jobs"]), {"acquisition-configuration", *transport.JOB_CONTEXT})
        self.assertEqual(acquisition["jobs"]["acquisition-configuration"]["outputs"], {
            platform_name + "_transaction": "${{ steps.configuration.outputs." + platform_name + "_transaction }}"
            for platform_name in ("ubuntu", "windows")})
        for job in transport.JOB_CONTEXT:
            platform_name = transport.JOB_CONTEXT[job][0]
            self.assertEqual(acquisition["jobs"][job]["env"]["ISSUE13_TRANSACTION"],
                "${{ needs.acquisition-configuration.outputs." + platform_name + "_transaction }}")
            steps = acquisition["jobs"][job]["steps"]
            base_steps = base["jobs"][job]["steps"]
            self.assertEqual(len(steps), len(base_steps) + 3)
            for index, expected in enumerate(base_steps):
                actual = copy.deepcopy(steps[index])
                if actual.get("id") == "ordinary":
                    actual.pop("id")
                    self.assertNotIn("continue-on-error", actual)
                    prefix, flags = actual["run"].split(" --issue13-diagnostic-root ")
                    self.assertEqual(prefix, expected["run"])
                    self.assertIn("--issue13-diagnostic-transaction", flags)
                    self.assertIn("RUNNER_TEMP/issue13-", flags)
                    actual["run"] = prefix
                if "with" in actual and "fetch-depth" in actual["with"]:
                    self.assertEqual(actual["with"]["fetch-depth"], "2")
                    actual["with"]["fetch-depth"] = "1"
                self.assertEqual(actual, expected)
            export, private, public = steps[-3:]
            self.assertTrue(all(step["continue-on-error"] == "true" for step in steps[-3:]))
            self.assertIn("always()", export["if"])
            self.assertIn("steps.ordinary.outcome", export["if"])
            self.assertEqual(private["with"]["retention-days"], "1")
            self.assertTrue(private["with"]["path"].endswith("-export/issue13-private.tar.gz.gpg"))
            self.assertEqual(len(public["with"]["path"].splitlines()), 2)
            self.assertNotIn(".ci-results", private["with"]["path"] + public["with"]["path"])
            self.assertTrue(all("diagnostic-export.outcome == 'success'" in step["if"] for step in (private, public)))


def history_bytes(revision, name=None):
    args = ["cat-file", "blob", revision + ":" + name] if name else ["rev-parse", revision]
    return subprocess.check_output(["git", *args], cwd=ci.REPO_ROOT)


def checkpoint_module(name):
    module = types.ModuleType("reviewed_" + name)
    module.__file__ = str(ci.REPO_ROOT / "developer/tests/ci" / (name + ".py"))
    exec(compile(history_bytes(transport.V2_CAPTURE_COMMIT, "developer/tests/ci/" + name + ".py"),
                 module.__file__, "exec"), module.__dict__)
    return module


class SourceContractFixture:
    """Bounded in-memory Git responses; creates no A/B commits or workflow file."""
    def __init__(self, *, legacy_windows=False, legacy=False):
        import issue13_windows_transport_recovery as recovery
        self.repo = ci.REPO_ROOT
        self.legacy = legacy or legacy_windows
        self.commit = ("ddf1e597e18c6e73b0c191873cff3749fb349098" if legacy_windows else
                       recovery.PARENT if legacy else "b" * 40)
        self.parent = recovery.PARENT if legacy_windows else transport.CAPTURE_COMMIT if legacy else "a" * 40
        self.anchor = transport.CAPTURE_COMMIT if self.legacy else transport.V2_CAPTURE_COMMIT
        self.tree = "c" * 40
        self.refs = {"HEAD": self.commit, "HEAD^{tree}": self.tree, "HEAD^": self.parent,
                     "HEAD^^": self.anchor, "HEAD~2^{tree}": transport.V2_CAPTURE_TREE}
        self.paths = (tuple(sorted(set(transport.SOURCE_PATHS) | set(recovery.RECOVERY_PATHS)))
                      if legacy_windows else transport.SOURCE_PATHS if legacy else transport.V2_SOURCE_PATHS)
        self.files = {}
        if self.legacy:
            for revision in {self.commit, self.parent, self.anchor}:
                self.files[revision] = {p: history_bytes(self.parent if legacy_windows and revision == self.parent
                                                       and p in transport.SOURCE_PATHS else self.commit, p)
                                        for p in self.paths}
        else:
            self.files[self.anchor] = {p: history_bytes(self.anchor, p) for p in self.paths}
            self.files[self.parent] = dict(self.files[self.anchor])
            for p in transport.V2_AMENDMENT_PATHS:
                self.files[self.parent][p] = (self.repo / p).read_bytes()
            self.files[self.commit] = dict(self.files[self.parent])
            self.files[self.commit][transport.V2_WORKFLOW] = b"# synthetic workflow blob; never installed or executed\n"
        self.checkout = dict(self.files[self.commit])
        self.legacy_changes = list(recovery.RECOVERY_PATHS if legacy_windows else transport.TRANSPORT_PATHS)
        self.a_diff = b"".join(b"M\0" + p.encode() + b"\0" for p in transport.V2_AMENDMENT_PATHS)
        self.b_diff = b"A\0" + transport.V2_WORKFLOW.encode() + b"\0"
        self.replies = {}
        self.modes = {}

    def git(self, repo, *args, limit=2 * transport.MIB):
        if args in self.replies:
            data = self.replies[args]
        elif args[0] == "rev-parse":
            data = (self.refs[args[1]] + "\n").encode()
        elif args[0] == "rev-list":
            child = args[-1]
            parent = self.parent if child == self.commit else self.anchor
            data = (child + " " + parent + "\n").encode()
        elif args[0] == "diff-tree":
            data = (("\n".join(self.legacy_changes) + "\n").encode() if "--name-only" in args else
                    self.a_diff if args[-1] == self.parent else self.b_diff)
        elif args[0] == "ls-tree":
            revision, name = args[2], args[4]
            value = self.files[revision][name]
            oid = hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
            data = (self.modes.get((revision, name), "100644") + " blob " + oid + "\t" + name + "\0").encode()
        elif args[:2] == ("cat-file", "blob"):
            revision, name = args[2].split(":", 1)
            revision = self.refs.get(revision, revision)
            data = self.files[revision][name]
        else:
            raise AssertionError("unexpected Git read: " + repr(args))
        if len(data) > limit:
            raise transport.TransportError("output-bound")
        return data

    def file(self, path, limit):
        value = self.checkout[path.relative_to(self.repo).as_posix()]
        if len(value) > limit:
            raise transport.TransportError("file-bound")
        return value

    def installed(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(transport, "git_bytes", side_effect=self.git))
        stack.enter_context(mock.patch.object(transport, "bounded_file", side_effect=self.file))
        return stack


CONTRACT_RESULTS = {"legacyUbuntu": [], "v2Topology": [], "v2Context": []}


class SourceProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = checkpoint_module("issue13_acquisition_transport")

    def outcome(self, function, *args, **kwargs):
        try:
            return ("accept", transport.json_bytes(function(*args, **kwargs)))
        except Exception as error:
            return ("reject", type(error).__name__, str(error))

    def test_legacy_ubuntu_context_acceptance_rejection_is_identical(self):
        env = {**environment(Path("unused")), "GITHUB_JOB": "acquisition-configuration"}
        cases = [("historical-configuration", {}, None)]
        cases += [(key, {key: value}, None) for key, value in (
            ("GITHUB_REF", transport.V2_BRANCH), ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_JOB", "unknown"))]
        for label, changes, phase in cases:
            before = self.outcome(self.original.live_context, {**env, **changes}, phase)
            after = self.outcome(transport.profile_context, {**env, **changes}, phase, source_profile="legacy")
            self.assertEqual(before, after)
            self.assertEqual(after[0], "accept" if label == "historical-configuration" else "reject")
            CONTRACT_RESULTS["legacyUbuntu"].append({"case": label, "result": after[0], "byteEqual": True})
        for job, (platform_name, phase) in transport.JOB_CONTEXT.items():
            with mock.patch.object(transport.os, "name", "nt" if platform_name == "windows" else "posix"):
                for actual_phase in (phase, "wrong-phase"):
                    value = {**env, "GITHUB_JOB": job}
                    self.assertEqual(self.outcome(self.original.live_context, value, actual_phase),
                                     self.outcome(transport.profile_context, value, actual_phase))

    def test_legacy_ubuntu_source_acceptance_rejection_is_identical(self):
        fixture = SourceContractFixture(legacy=True)
        cases = ["historical", "parent", "tree", "scope", "pin", "checkout", "v2-tree"]
        for case in cases:
            control = copy.deepcopy(fixture)
            if case == "parent": control.refs["HEAD^"] = transport.V2_CAPTURE_COMMIT
            if case == "tree": control.refs["HEAD^{tree}"] = "invalid"
            if case == "scope": control.legacy_changes.append(transport.V2_WORKFLOW)
            if case == "pin": control.files[control.commit][next(iter(transport.CAPTURE_SOURCES))] += b"changed"
            if case == "checkout": control.checkout[transport.PUBLIC_KEY_PATH] += b"changed"
            if case == "v2-tree": control = SourceContractFixture()
            with control.installed(), mock.patch.object(self.original, "git_bytes", side_effect=control.git), \
                 mock.patch.object(self.original, "bounded_file", side_effect=control.file):
                before = self.outcome(self.original.source_identity, control.repo, control.commit)
                after = self.outcome(transport.profile_source_identity, control.repo, control.commit)
            self.assertEqual(before, after)
            self.assertEqual(after[0], "accept" if case == "historical" else "reject")
            CONTRACT_RESULTS["legacyUbuntu"].append({"case": "source-" + case, "result": after[0], "byteEqual": True})

    def test_synthetic_b_exact_two_edges_and_source_freeze_accepted(self):
        fixture = SourceContractFixture()
        with fixture.installed():
            result = transport.profile_source_identity(fixture.repo, fixture.commit, source_profile=transport.V2_PROFILE)
        self.assertEqual(result["parent"], fixture.parent)
        self.assertEqual(result["captureCommit"], transport.V2_CAPTURE_COMMIT)
        self.assertEqual(result["commit"], fixture.commit)
        self.assertEqual({r["source"] for r in result["sources"]}, {*transport.V2_SOURCE_PATHS, transport.V2_WORKFLOW})
        CONTRACT_RESULTS["v2Topology"].append({"case": "exact-two-edges", "result": "accept"})

    def test_v2_lineage_scope_and_metadata_negative_matrix(self):
        fixture = SourceContractFixture()
        cases = ["wrong-grandparent", "wrong-anchor-tree", "extra-commit", "merge-b", "merge-a", "wrong-expected-commit",
                 "b-extra-file", "b-second-workflow", "b-old-workflow", "b-missing-workflow", "b-workflow-modified",
                 "a-extra-file", "a-missing-amendment", "a-duplicate", "a-reordered", "a-renamed",
                 "malformed-oid", "multi-line-oid", "trailing-space-oid", "malformed-diff", "malformed-entry", "blob-oid-mismatch"]
        for case in cases:
            f = copy.deepcopy(fixture)
            expected = f.commit
            if case in ("wrong-grandparent", "extra-commit"): f.refs["HEAD^^"] = "d" * 40
            if case == "wrong-anchor-tree": f.refs["HEAD~2^{tree}"] = "d" * 40
            if case in ("merge-b", "merge-a"):
                child = f.commit if case == "merge-b" else f.parent
                ancestor = f.parent if case == "merge-b" else f.anchor
                f.replies[("rev-list", "--parents", "-n", "1", child)] = (child + " " + ancestor + " " + "d" * 40 + "\n").encode()
            if case == "wrong-expected-commit": expected = "d" * 40
            if case.startswith("b-extra"): f.b_diff += b"A\0extra.py\0"
            if case == "b-second-workflow": f.b_diff += b"A\0.github/workflows/second.yml\0"
            if case == "b-old-workflow": f.b_diff += b"M\0.github/workflows/ci.yml\0"
            if case == "b-missing-workflow": f.b_diff = b""
            if case == "b-workflow-modified": f.b_diff = b"M" + f.b_diff[1:]
            if case == "a-extra-file": f.a_diff += b"M\0developer/tests/ci/run_ci_foundation.py\0"
            if case == "a-missing-amendment": f.a_diff = b""
            if case == "a-duplicate": f.a_diff += f.a_diff
            if case == "a-reordered": f.a_diff = b"".join(b"M\0" + p.encode() + b"\0" for p in reversed(transport.V2_AMENDMENT_PATHS))
            if case == "a-renamed": f.a_diff = b"R100" + f.a_diff[1:]
            if case in ("malformed-oid", "multi-line-oid", "trailing-space-oid"):
                f.replies[("rev-parse", "HEAD^")] = {"malformed-oid": b"invalid\n", "multi-line-oid": b"a" * 40 + b"\nb\n",
                                                        "trailing-space-oid": b"a" * 40 + b" \n"}[case]
            if case == "malformed-diff": f.b_diff = f.b_diff.rstrip(b"\0")
            if case in ("malformed-entry", "blob-oid-mismatch"):
                name = transport.V2_SOURCE_PATHS[0]
                args = ("ls-tree", "-z", f.commit, "--", name)
                f.replies[args] = b"invalid" if case == "malformed-entry" else (
                    "100644 blob " + "0" * 40 + "\t" + name + "\0").encode()
            with self.subTest(case=case), f.installed(), self.assertRaises(transport.TransportError):
                transport.source_identity_v2(f.repo, expected)
            CONTRACT_RESULTS["v2Topology"].append({"case": case, "result": "reject"})

    def test_v2_frozen_sources_capture_pins_and_runtime_authority_negative_matrix(self):
        fixture = SourceContractFixture()
        for name in transport.V2_SOURCE_PATHS:
            f = copy.deepcopy(fixture)
            f.files[f.commit][name] += b"changed-in-b"
            f.checkout[name] = f.files[f.commit][name]
            with self.subTest(source=name), f.installed(), self.assertRaises(transport.TransportError):
                transport.source_identity_v2(f.repo, f.commit)
        for name in transport.V2_CAPTURE_PINS:
            f = copy.deepcopy(fixture)
            for revision in (f.parent, f.commit): f.files[revision][name] += b"changed-in-a"
            f.checkout[name] = f.files[f.commit][name]
            with self.subTest(inherited=name), f.installed(), self.assertRaises(transport.TransportError):
                transport.source_identity_v2(f.repo, f.commit)
            # Even falsely consistent anchor responses cannot replace pinned bytes.
            f.files[f.anchor][name] = f.files[f.commit][name]
            with self.subTest(pin=name), f.installed(), self.assertRaises(transport.TransportError):
                transport.source_identity_v2(f.repo, f.commit)
        for case in ("checkout", "workflow-symlink", "workflow-executable", "source-mode"):
            f = copy.deepcopy(fixture)
            name = transport.V2_WORKFLOW if case.startswith("workflow") else transport.V2_SOURCE_PATHS[0]
            if case == "checkout": f.checkout[name] += b"changed"
            else: f.modes[(f.commit, name)] = "120000" if case == "workflow-symlink" else "100755"
            with self.subTest(case=case), f.installed(), self.assertRaises(transport.TransportError):
                transport.source_identity_v2(f.repo, f.commit)
        CONTRACT_RESULTS["v2Topology"].append({"case": "source-freeze-and-pins", "result": "reject",
            "controls": len(transport.V2_SOURCE_PATHS) + 2 * len(transport.V2_CAPTURE_PINS) + 4})

    def test_v2_context_is_explicit_and_platform_transactions_are_paired(self):
        env = {**environment(Path("unused")), "GITHUB_REF": transport.V2_BRANCH}
        transactions = {}
        for platform_name, jobs in (("ubuntu", ("ubuntu-canonical-producer", "ubuntu-canonical")),
                                    ("windows", ("windows-compatibility-producer", "windows-compatibility"))):
            with mock.patch.object(transport.os, "name", "nt" if platform_name == "windows" else "posix"):
                pair = [transport.v2_context({**env, "GITHUB_JOB": job}, phase, platform_name=platform_name)
                        for job, phase in zip(jobs, ("producer", "fresh-replay"))]
            self.assertEqual(pair[0]["transaction"], pair[1]["transaction"])
            transactions[platform_name] = pair[0]["transaction"]
        self.assertNotEqual(transactions["ubuntu"], transactions["windows"])
        with mock.patch.object(transport.os, "name", "posix"):
            env["GITHUB_JOB"] = "acquisition-configuration"
            self.assertIsNone(transport.profile_context(env, source_profile=transport.V2_PROFILE)["transaction"])
            for key, value in (("GITHUB_REF", transport.BRANCH), ("GITHUB_REF", "refs/heads/other"),
                               ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_RUN_ATTEMPT", "2"),
                               ("GITHUB_SHA", "bad"), ("GITHUB_RUN_ID", "0"),
                               ("GITHUB_REPOSITORY", "other/repo"), ("GITHUB_JOB", "windows-gnupg-preflight")):
                with self.subTest(key=key, value=value), self.assertRaises(transport.TransportError):
                    transport.profile_context({**env, key: value}, source_profile=transport.V2_PROFILE)
            with self.assertRaises(transport.TransportError): transport.profile_context(env)
            with self.assertRaises(transport.TransportError): transport.profile_context(env, source_profile="unknown")
        CONTRACT_RESULTS["v2Context"].append({"platformPairsEqual": True, "platformsDistinct": True, "legacyRejectsV2": True})

    def test_context_source_dispatch_and_failure_precede_export(self):
        env = {**environment(Path("unused")), "GITHUB_REF": transport.V2_BRANCH,
               "GITHUB_JOB": "ubuntu-canonical-producer"}
        with mock.patch.object(transport.os, "name", "posix"), \
             mock.patch.object(transport, "source_identity_v2", side_effect=transport.TransportError("candidate-identity")) as source, \
             mock.patch.object(transport, "load_capture_modules") as capture_loader:
            tx = transport.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], "ubuntu")
            with self.assertRaises(transport.TransportError):
                transport.export_capture(ci.REPO_ROOT, env, "producer", tx, "failure", source_profile=transport.V2_PROFILE)
            source.assert_called_once_with(ci.REPO_ROOT, env["GITHUB_SHA"])
            capture_loader.assert_not_called()

    def test_v2_configuration_cli_selects_exact_contract_before_outputs(self):
        fixture = SourceContractFixture()
        with tempfile.TemporaryDirectory(prefix="issue13-v2-context-") as temporary:
            output = Path(temporary) / "outputs"
            env = {**environment(Path(temporary)), "GITHUB_REF": transport.V2_BRANCH,
                   "GITHUB_JOB": "acquisition-configuration", "GITHUB_SHA": fixture.commit,
                   "GITHUB_OUTPUT": str(output)}
            live = {"commit": fixture.commit, "runId": env["GITHUB_RUN_ID"], "attempt": 1,
                    "transaction": None, "platform": None, "phase": None}
            # The context's platform checks run independently above; this CLI
            # routing control can also run on the local Windows test host.
            with fixture.installed(), mock.patch.dict(os.environ, env), \
                 mock.patch.object(transport, "v2_context", return_value=live) as context, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(transport.main(["configure", "--source-profile", transport.V2_PROFILE]), 0)
                context.assert_called_once()
                self.assertEqual(output.read_text("ascii"), "".join(platform + "_transaction=" +
                    transport.transaction_id(fixture.commit, env["GITHUB_RUN_ID"], platform) + "\n"
                    for platform in ("ubuntu", "windows")))
                output.unlink()
                fixture.refs["HEAD^^"] = "d" * 40
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(transport.main(["configure", "--source-profile", transport.V2_PROFILE]), 1)
                self.assertFalse(output.exists())

    def test_legacy_functions_constants_and_all_nonidentity_logic_are_frozen(self):
        name = "developer/tests/ci/issue13_acquisition_transport.py"
        old = history_bytes(transport.V2_CAPTURE_COMMIT, name).decode().replace("\r\n", "\n")
        new = (ci.REPO_ROOT / name).read_text("utf-8")
        def nodes(source):
            return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body
                    if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        old_nodes, new_nodes = nodes(old), nodes(new)
        for function in old_nodes.keys() - {"export_capture", "main"}:
            self.assertEqual(old_nodes[function], new_nodes[function], function)
        export = new_nodes["export_capture"].replace(', *, source_profile="legacy"', '').replace(
            'profile_context(environment, phase, source_profile=source_profile)', 'live_context(environment, phase)').replace(
            'profile_source_identity(repo, context["commit"], source_profile=source_profile)', 'source_identity(repo, context["commit"])')
        self.assertEqual(old_nodes["export_capture"], export)
        for node in ast.parse(old).body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                key = node.targets[0].id
                self.assertEqual(getattr(self.original, key), getattr(transport, key), key)


if __name__ == "__main__":
    unittest.main()
