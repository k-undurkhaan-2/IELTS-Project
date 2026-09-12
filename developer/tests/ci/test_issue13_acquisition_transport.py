"""Focused transport tests only; no candidate recovery or hosted execution."""
from __future__ import annotations

import base64
import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
