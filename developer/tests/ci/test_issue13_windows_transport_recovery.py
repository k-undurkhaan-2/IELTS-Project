"""Focused Windows transport tests: no candidate, hosted job, or PATH GnuPG.

Real-process fixtures require an explicitly supplied reviewed package and a short
private test parent. No acquisition payload is decrypted by these tests.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import issue13_windows_transport_recovery as recovery
import issue13_acquisition_transport as base
import issue13_diagnostic_capture as capture
import run_ci_foundation as ci
import test_issue13_diagnostic_capture as fixtures

REPO = Path(__file__).resolve().parents[3]


def key_listing():
    lines = []
    for kind, fingerprint, algorithm, capability, curve in (
        ("pub", base.PRIMARY, "22", "scESC", "ed25519"),
        ("sub", base.SUBKEY, "18", "e", "cv25519")):
        fields = [""] * 20
        fields[0:7] = [kind, "-", "255", algorithm, fingerprint[-16:], "1000000000", "4000000000"]
        fields[11], fields[16] = capability, curve
        lines.append(":".join(fields))
        fields = [""] * 11
        fields[0], fields[9] = "fpr", fingerprint
        lines.append(":".join(fields))
    return ("\n".join(lines) + "\n").encode("ascii")


def environment(root, phase="producer"):
    job = "windows-compatibility-producer" if phase == "producer" else "windows-compatibility"
    return {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "99999913", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": base.REPOSITORY,
            "GITHUB_REF": recovery.BRANCH, "GITHUB_JOB": job, "RUNNER_TEMP": str(root),
            "GITHUB_OUTPUT": str(root / "output"), "UNRELATED_SECRET": fixtures.CANARY}


def safe_remove(root, parent):
    # Resolve and scope every recursive cleanup to a freshly created test root.
    resolved = root.resolve(strict=True)
    assert resolved == root and resolved.parent == parent and resolved.name.startswith("i")
    assert REPO not in resolved.parents and resolved not in REPO.parents
    shutil.rmtree(resolved)


def authority(runner):
    return ci._canonical_frame({"records": runner.command_results,
        "transcript": ci.verification_replay_transcript(runner),
        "violations": runner.violations, "hardGates": runner.hard_gate_results,
        "authorizationClaims": fixtures.claims_for(runner)})


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "nt":
            raise RuntimeError("Windows fixture host required")
        cls.parent = Path(os.environ["ISSUE13_TEST_TEMP_PARENT"]).resolve(strict=True)
        cls.shared = Path(tempfile.mkdtemp(prefix="i", dir=cls.parent)).resolve(strict=True)
        cls.config = recovery.configuration(REPO)
        cls.package = base.bounded_file(Path(os.environ["ISSUE13_REVIEWED_PACKAGE"]), recovery.PACKAGE_BYTES)
        cls.runtime = recovery.provision_runtime(cls.shared, REPO, cls.config, fetch=lambda *_: cls.package)
        cls.armor = base.git_bytes(REPO, "cat-file", "blob", "HEAD:" + base.PUBLIC_KEY_PATH)

    @classmethod
    def tearDownClass(cls):
        safe_remove(cls.shared, cls.parent)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="i", dir=self.parent)).resolve(strict=True)
        self.addCleanup(safe_remove, self.root, self.parent)

    def install(self):
        path = self.root / "issue13-gnupg"
        shutil.copytree(self.runtime, path)
        return path

    def reject(self, category, function, *args, **kwargs):
        with self.assertRaises(recovery.RecoveryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.category, category)

    def open_runtime(self, root):
        with recovery.RuntimeLease(root, self.config):
            pass

    def test_absent_approved_locations_never_search_path(self):
        with mock.patch.object(recovery, "APPROVED_LOCATIONS", (self.root / "absent",)), mock.patch.object(recovery, "child_process") as execute:
            self.assertEqual(recovery.inspect_approved_locations(), ("GPG_NOT_AVAILABLE", []))
            execute.assert_not_called()

    def test_approved_preinstalled_requires_entire_reviewed_closure(self):
        runtime = self.install()
        binary = runtime / "bin/gpg.exe"
        with mock.patch.object(recovery, "APPROVED_LOCATIONS", (binary,)):
            self.assertEqual(recovery.inspect_approved_locations(), ("GPG_APPROVED_RUNTIME_AVAILABLE", [0]))
            with recovery.RuntimeLease(runtime, self.config, preinstalled=True) as lease:
                self.assertEqual(base.digest(lease.files["bin/gpg.exe"].data(recovery.MAX_COMPONENT_BYTES)), recovery.BINARY_SHA256)
            (runtime / "bin/libgcrypt-20.dll").unlink()
            self.reject("gpg-runtime-closure", self.open_runtime, runtime)

    def test_unapproved_runtime_is_private_data_and_never_executed(self):
        unapproved = self.root / "unapproved.exe"
        unapproved.write_bytes(b"not executable")
        with mock.patch.object(recovery, "child_process") as execute:
            self.assertEqual(recovery.inspect_unapproved_hints([unapproved]), [{"path": str(unapproved), "bytes": 14}])
            self.reject("gpg-unapproved-location", recovery.RuntimeLease, self.root, self.config, binary=unapproved, preinstalled=True)
            self.reject("gpg-unapproved-location", recovery.inspect_unapproved_hints, [unapproved] * 9)
            execute.assert_not_called()

    def test_provisioned_official_package_full_closure_and_version(self):
        self.assertEqual((len(self.package), base.digest(self.package)), (recovery.PACKAGE_BYTES, recovery.PACKAGE_SHA256))
        self.assertEqual(len(recovery.cabinet_inventory(self.package, self.config)), 87)
        with recovery.RuntimeLease(self.runtime, self.config) as lease:
            ring = recovery.RecoveryKeyring(lease, self.root / "k", REPO, self.armor)
            self.assertEqual(ring.tool["version"], "gpg (GnuPG) 2.5.22")
            self.assertEqual(ring.tool["sha256"], recovery.BINARY_SHA256)
            self.assertEqual(ring.tool["runtimeClosureSha256"], recovery.CLOSURE_SHA256)
            self.assertEqual(ring.tool["runtimeFileCount"], 87)

    def test_download_hash_size_network_error_and_redirect_fail_closed(self):
        bad = bytes([self.package[0] ^ 1]) + self.package[1:]
        for payload in (bad, self.package[:-1], self.package + b"x"):
            with self.subTest(bytes=len(payload)), mock.patch.object(recovery, "child_process") as execute:
                self.reject("gpg-package-integrity", recovery.provision_runtime, self.root, REPO, self.config, fetch=lambda *_: payload)
                execute.assert_not_called()
                self.assertFalse((self.root / "issue13-gnupg").exists())
        with mock.patch.object(recovery.urllib.request, "urlopen", side_effect=OSError(fixtures.CANARY)):
            self.reject("gpg-package-integrity", recovery.package_bytes)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = "https://invalid.example/alternate"
        with mock.patch.object(recovery.urllib.request, "urlopen", return_value=response):
            self.reject("gpg-package-integrity", recovery.package_bytes)
            response.read.assert_not_called()

    def test_manifest_schema_version_count_and_closure_bounds(self):
        for mutation in (lambda d: d.update(version=2), lambda d: d.update(extra=True), lambda d: d["files"].pop(),
                         lambda d: d["files"][0].update(path="../escape"), lambda d: d["files"][0].update(sha256="0" * 64),
                         lambda d: d["files"][0].update(bytes=9 * base.MIB)):
            value = copy.deepcopy(self.config)
            mutation(value)
            with mock.patch.object(base, "bounded_file", return_value=base.json_bytes(value)):
                self.reject("gpg-runtime-closure", recovery.configuration, REPO)
        self.reject("gpg-runtime-closure", recovery.read_json, b'{"a":1,"a":2}')
        self.reject("output-bound", recovery.read_json, b" " * (base.MAX_MANIFEST + 1))

    def test_wrong_binary_and_adjacent_dll_hashes(self):
        runtime = self.install()
        for name, expected in (("bin/gpg.exe", "gpg-binary-integrity"), ("bin/libgcrypt-20.dll", "gpg-runtime-closure")):
            path = runtime / name
            original = path.read_bytes()
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            with mock.patch.object(recovery, "child_process") as execute:
                self.reject(expected, self.open_runtime, runtime)
                execute.assert_not_called()
            path.write_bytes(original)

    def test_required_runtime_missing_and_extra_components(self):
        runtime = self.install()
        path = runtime / "bin/gpgconf.exe"
        original = path.read_bytes()
        path.unlink()
        self.reject("gpg-runtime-closure", self.open_runtime, runtime)
        path.write_bytes(original)
        (runtime / "bin/unreviewed.dll").write_bytes(b"unexpected")
        self.reject("gpg-runtime-closure", self.open_runtime, runtime)

    def test_runtime_write_replace_and_directory_rename_blocked_while_leased(self):
        runtime = self.install()
        with recovery.RuntimeLease(runtime, self.config) as lease:
            with self.assertRaises(OSError):
                (runtime / "bin/gpg.exe").write_bytes(b"changed")
            with self.assertRaises(OSError):
                (runtime / "bin/libgcrypt-20.dll").unlink()
            with self.assertRaises(OSError):
                (runtime / "bin").rename(runtime / "changed-bin")
            lease.verify()
        (runtime / "bin/gpg.exe").write_bytes(b"changed after lease")
        self.reject("gpg-binary-integrity", self.open_runtime, runtime)

    def test_mutation_between_verification_and_execution_rejected(self):
        runtime = self.install()
        with recovery.RuntimeLease(runtime, self.config) as lease:
            (runtime / "unreviewed.dll").write_bytes(b"new entry")
            with mock.patch.object(recovery, "child_process") as execute:
                self.reject("gpg-runtime-closure", lease.run, ["--version"], self.root)
                execute.assert_not_called()

    def test_hardlinked_runtime_file_rejected(self):
        runtime = self.install()
        os.link(runtime / "bin/gpg.exe", self.root / "hardlink")
        with mock.patch.object(recovery, "child_process") as execute:
            self.reject("gpg-runtime-closure", self.open_runtime, runtime)
            execute.assert_not_called()

    def test_reparse_runtime_root_rejected(self):
        alias = self.root / "linked-runtime"
        import _winapi
        _winapi.CreateJunction(str(self.runtime), str(alias))
        self.addCleanup(os.rmdir, alias)
        self.assertTrue(base.is_link(alias.lstat()))
        with mock.patch.object(recovery, "child_process") as execute:
            self.reject("gpg-runtime-closure", self.open_runtime, alias)
            execute.assert_not_called()

    def test_wrong_absolute_runtime_binary_path_rejected(self):
        self.reject("gpg-unapproved-location", recovery.RuntimeLease, self.runtime, self.config, binary=self.runtime / "gpg.exe")
        self.reject("gpg-unapproved-location", recovery.RuntimeLease, Path("relative"), self.config)

    def test_version_mismatch_stops_before_import(self):
        runtime = mock.Mock()
        runtime.run.return_value = (0, b"gpg (GnuPG) 2.4.8\n", b"")
        self.reject("gpg-version", recovery.RecoveryKeyring, runtime, self.root / "k", REPO, self.armor)
        self.assertEqual(runtime.run.call_count, 1)

    def test_long_keyring_path_stops_before_any_gpg_process(self):
        runtime = mock.Mock()
        self.reject("gpg-process", recovery.RecoveryKeyring, runtime, self.root / ("k" * 50), REPO, self.armor)
        runtime.run.assert_not_called()

    def test_certificate_fingerprint_curve_capability_and_validity_matrix(self):
        good = key_listing()
        self.assertEqual(recovery.certificate_identity(good)["recipientSelector"], base.RECIPIENT)
        cases = [(good.replace(base.PRIMARY.encode(), b"0" * 40), "public-key-identity"),
                 (good.replace(base.SUBKEY.encode(), b"1" * 40), "public-key-identity"),
                 (good.replace(b"cv25519", b"nistp256"), "public-key-identity"),
                 (good.replace(b":e:", b":s:"), "public-key-identity"),
                 (good.replace(b"pub:-:", b"pub:r:"), "public-key-revoked"),
                 (good.replace(b"sub:-:", b"sub:r:"), "public-key-revoked"),
                 (good.replace(b"pub:-:", b"pub:e:"), "public-key-expired"),
                 (good.replace(b"sub:-:", b"sub:e:"), "public-key-expired"),
                 (good.replace(b"4000000000", b"1000000001", 1), "public-key-expired"),
                 (b"1000000001".join(good.rsplit(b"4000000000", 1)), "public-key-expired"),
                 (good.replace(b"sub:-:", b"sub:d:"), "public-key-identity"),
                 (good.replace(b"pub:-:", b"sec:-:"), "public-key-identity"),
                 (good.replace(b"sub:-:", b"ssb:-:"), "public-key-identity"),
                 (good + b"unexpected:data\n", "public-key-identity")]
        for index, (value, expected) in enumerate(cases):
            with self.subTest(case=index):
                self.reject(expected, recovery.certificate_identity, value)
        alternative = good + (b"sub:" + good.split(b"sub:", 1)[1]).replace(base.SUBKEY.encode(), b"2" * 40)
        self.reject("public-key-identity", recovery.certificate_identity, alternative)

    def test_public_certificate_pin_and_secret_packet_rejection_before_gpg(self):
        runtime = mock.Mock()
        self.reject("public-key-pin", recovery.RecoveryKeyring, runtime, self.root / "k", REPO, self.armor.replace(b"\n", b"\r\n"))
        for tag in (5, 7):
            payload = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + base64.b64encode(bytes([0xc0 | tag, 1, 0])) + b"\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
            self.reject("public-key-identity", recovery.RecoveryKeyring, runtime, self.root / "k", REPO, payload)
        runtime.run.assert_not_called()

    def test_real_synthetic_encrypt_exact_recipient_no_secret_no_plaintext(self):
        with recovery.RuntimeLease(self.runtime, self.config) as lease:
            ring = recovery.RecoveryKeyring(lease, self.root / "k", REPO, self.armor)
            result = recovery.synthetic_preflight(ring)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["recipientSelector"], base.SUBKEY + "!")
            self.assertTrue(result["publicOnlyDecryptionRejected"])
            self.assertEqual((result["secretKeyCount"], result["plaintextOutputBytes"]), (0, 0))
            self.assertLessEqual(result["ciphertextBytes"], 8192)
            recovery.public_home_inventory(ring.home)
            self.assertFalse(any(p.suffix in (".asc", ".gz", ".txt") or p.name == "common.conf" for p in ring.home.rglob("*")))

    def test_synthetic_encryption_failure_cannot_pass(self):
        ring = mock.Mock()
        ring.encrypt.side_effect = recovery.RecoveryError("encryption-process")
        self.reject("encryption-process", recovery.synthetic_preflight, ring)
        ring.result.assert_not_called()
        ring.encrypt.side_effect = None
        ring.encrypt.return_value = b"x" * 8193
        self.reject("encryption-preflight", recovery.synthetic_preflight, ring)

    def test_negative_decryption_requires_exact_no_secret_status_and_zero_output(self):
        ring = mock.Mock()
        ring.encrypt.return_value = b"synthetic ciphertext"
        good = b"[GNUPG:] NO_SECKEY " + base.SUBKEY[-16:].encode() + b"\n[GNUPG:] DECRYPTION_FAILED\n"
        for result in ((0, b"", good), (2, b"plaintext", good), (2, b"", b""), (2, b"", good.replace(base.SUBKEY[-16:].encode(), b"0" * 16))):
            ring.result.return_value = result
            self.reject("encryption-preflight", recovery.synthetic_preflight, ring)

    def test_ciphertext_empty_truncated_plaintext_fallback_wrong_or_extra_recipient(self):
        body = b"\x03" + bytes.fromhex(base.SUBKEY[-16:]) + b"\x12\x01\x07\x40" + b"x" * 32 + b"\x30" + b"k" * 48
        packet = b"\xc1" + bytes([len(body)]) + body + b"\xd4\x33\x01\x09\x02\x10" + b"e" * 47
        self.assertEqual(len(recovery.validate_ciphertext(packet)), 2)
        for value in (b"plaintext fallback", packet[:-1], packet.replace(bytes.fromhex(base.SUBKEY[-16:]), b"0" * 8), packet[:96] + packet, b"\xcb\x01x", b"",
                      packet.replace(b"\x01\x07\x40", b"\x01\x06\x40"),
                      b"\xc1\x0a" + body[:10] + b"\xd2\x02\x01\x00",
                      packet.replace(b"\xd4\x33", b"\xd2\x33"),
                      packet.replace(b"\x01\x09\x02\x10", b"\x01\x07\x02\x10"),
                      packet.replace(b"\x01\x09\x02\x10", b"\x01\x09\x02\x11")):
            with self.assertRaises(recovery.RecoveryError):
                recovery.validate_ciphertext(value)

    def test_nonzero_gpg_status_never_silently_accepted(self):
        ring = object.__new__(recovery.RecoveryKeyring)
        with mock.patch.object(ring, "result", return_value=(2, b"partial ciphertext", b"private error")):
            self.reject("encryption-process", ring.run, "--encrypt")
            self.reject("gpg-process", ring.run, "--import")

    def test_keyring_extra_secret_config_or_plaintext_file_rejected(self):
        with recovery.RuntimeLease(self.runtime, self.config) as lease:
            ring = recovery.RecoveryKeyring(lease, self.root / "k", REPO, self.armor)
            for name in ("plaintext.txt", "gpg.conf", "common.conf", "private-keys-v1.d/secret.key", "AppData/Roaming/gnupg/common.conf"):
                path = ring.home / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b"synthetic forbidden data")
                self.reject("public-key-identity", recovery.public_home_inventory, ring.home)
                path.unlink()
            recovery.public_home_inventory(ring.home)

    def test_child_process_output_timeout_and_environment_bounds(self):
        for program, limit, timeout, expected in (
            ("import sys;sys.stdout.buffer.write(b'x'*100000)", 100, 5, "output-bound"),
            ("import sys;sys.stderr.buffer.write(b'x'*100000)", 100, 5, "output-bound"),
            ("import time;time.sleep(2)", 100, 0.05, "gpg-process")):
            self.reject(expected, recovery.child_process, [sys.executable, "-B", "-c", program], self.root, limit=limit, timeout=timeout)
        code = "import os;print('GITHUB_TOKEN' in os.environ or 'UNRELATED_SECRET' in os.environ)"
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": fixtures.CANARY, "UNRELATED_SECRET": fixtures.CANARY}):
            result = recovery.child_process([sys.executable, "-B", "-c", code], self.root)
        self.assertEqual(result, (0, b"False\r\n", b""))

    def test_preflight_failure_has_no_scheduling_output_and_no_authoritative_execution(self):
        env = environment(self.root)
        (self.root / "output").write_bytes(b"")
        with mock.patch.object(recovery, "source_identity", return_value={}), \
             mock.patch.object(recovery, "provision_runtime", side_effect=recovery.RecoveryError("gpg-package-integrity")), \
             mock.patch.object(base, "load_capture_modules") as load, \
             mock.patch.object(ci.FoundationRunner, "run") as producer, \
             mock.patch.object(ci, "run_verification_replay") as replay, contextlib.redirect_stdout(io.StringIO()):
            self.reject("gpg-package-integrity", recovery.preflight, REPO, env)
            load.assert_not_called()
            producer.assert_not_called()
            replay.assert_not_called()
        self.assertEqual((self.root / "output").read_bytes(), b"")
        self.assertFalse((self.root / "issue13-gnupg-preflight").exists())

    def test_real_preflight_pass_emits_only_pair_id_and_scheduling_pass(self):
        env = environment(self.root)
        env["GITHUB_JOB"] = "windows-gnupg-preflight"
        (self.root / "output").write_bytes(b"")
        output = io.StringIO()
        with mock.patch.object(recovery, "source_identity", return_value={}), \
             mock.patch.object(base, "load_capture_modules") as load, \
             mock.patch.object(ci.FoundationRunner, "run") as producer, \
             mock.patch.object(ci, "run_verification_replay") as replay, contextlib.redirect_stdout(output):
            proof = recovery.preflight(REPO, env, fetch=lambda *_: self.package)
            load.assert_not_called()
            producer.assert_not_called()
            replay.assert_not_called()
        expected = "transaction=" + recovery.context(env)["transaction"] + "\npreflight=PASS\n"
        self.assertEqual((self.root / "output").read_bytes(), expected.encode("ascii"))
        self.assertIn(output.getvalue().strip(), {"GPG_NOT_AVAILABLE", "GPG_APPROVED_RUNTIME_AVAILABLE"})
        self.assertEqual(proof["synthetic"]["status"], "PASS")
        self.assertEqual(proof["authority"], base.MARKER)
        self.assertNotIn("ReplayAuthorizationEnvelope", base.json_bytes(proof).decode())
        live = recovery.context(env)
        self.assertEqual(recovery.validated_preflight(self.root, live, {}), proof)
        for change in (lambda value: value.update(extra=fixtures.CANARY),
                       lambda value: value.update(version=True),
                       lambda value: value["context"].update(attempt=True),
                       lambda value: value["recipient"].update(secretKeyCount=False),
                       lambda value: value["recipient"].update(encryptionCapable=1),
                       lambda value: value["tool"].update(bytes=float(recovery.BINARY_BYTES)),
                       lambda value: value["synthetic"].update(ciphertextSha256=fixtures.CANARY),
                       lambda value: value["synthetic"].update(ciphertextBytes=8193),
                       lambda value: value["synthetic"].update(publicOnlyDecryptionRejected=False),
                       lambda value: value["tool"].update(sha256="0" * 64),
                       lambda value: value["recipient"].update(recipientSelector=base.SUBKEY),
                       lambda value: value["context"].update(transaction=recovery.OLD_TRANSACTION),
                       lambda value: value.update(approvedLocationIndices=[0, 0]),
                       lambda value: value.update(candidate={"private": fixtures.CANARY})):
            changed = copy.deepcopy(proof)
            change(changed)
            with mock.patch.object(base, "bounded_file", return_value=base.json_bytes(changed)):
                self.reject("encryption-preflight", recovery.validated_preflight, self.root, live, {})

    def test_transaction_is_new_and_exclusive_to_windows_pair(self):
        env = environment(self.root)
        result = recovery.context(env)
        self.assertEqual(result["transaction"], recovery.context(environment(self.root, "fresh-replay"))["transaction"])
        self.assertNotEqual(result["transaction"], recovery.OLD_TRANSACTION)
        self.assertNotEqual(result["transaction"], recovery.context({**env, "GITHUB_SHA": "b" * 40})["transaction"])
        self.assertNotEqual(result["transaction"], recovery.context({**env, "GITHUB_RUN_ID": "99999914"})["transaction"])
        for key, value in (("GITHUB_SHA", recovery.PARENT), ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", base.BRANCH),
                           ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_JOB", "ubuntu-canonical"), ("GITHUB_REPOSITORY", "other/repo")):
            self.reject("unexpected-transport-category", recovery.context, {**env, key: value})

    def fixture_capture(self, phase, family):
        runner = fixtures.full_scope_fixture("windows")
        env = environment(self.root, phase)
        env["GITHUB_SHA"] = runner.execution_binding["checkoutCommit"]
        live = recovery.context(env, phase)
        leaf = "issue13-producer" if phase == "producer" else "issue13-replay"
        summary = capture.capture_completed_runner(ci, runner, root=self.root / leaf,
            transaction=live["transaction"], phase=phase, repo_root=REPO)
        return runner, env, summary, self.root / leaf

    def candidate(self, runner):
        return {"commit": runner.execution_binding["checkoutCommit"], "tree": runner.execution_binding["checkoutTree"]}

    def test_paired_real_exports_preserve_capture_and_authority_byte_for_byte(self):
        self.install()
        for phase, family in (("producer", "frontend-security"), ("fresh-replay", "backend-canonical")):
            runner, env, summary, source = self.fixture_capture(phase, family)
            before = authority(runner)
            retained = {p.name: p.read_bytes() for p in source.iterdir()}
            with mock.patch.object(recovery, "source_identity", return_value=self.candidate(runner)), \
                 mock.patch.object(recovery, "validated_preflight", return_value={"synthetic": {"ciphertextSha256": "d" * 64}}):
                result = recovery.export_capture(REPO, env, phase, summary["transaction"], "failure")
            self.assertEqual(before, authority(runner))
            self.assertEqual(retained, {p.name: p.read_bytes() for p in source.iterdir()})
            output = self.root / ("issue13-producer-export" if phase == "producer" else "issue13-replay-export")
            self.assertEqual(sorted(p.name for p in output.iterdir()), ["issue13-private.tar.gz.gpg", "public.json", "transport.json"])
            self.assertEqual((output / "public.json").read_bytes(), retained["public.json"])
            self.assertEqual(base.digest((output / "issue13-private.tar.gz.gpg").read_bytes()), result["ciphertextSha256"])
            self.assertEqual(result["ordinaryStepOutcome"], "failure")
            for name in ("public.json", "transport.json"):
                self.assertNotIn(fixtures.CANARY.encode(), (output / name).read_bytes())
        self.assertFalse(any(p.suffix == ".gz" or p.name.endswith(".tar") for p in self.root.rglob("*")))

    def test_export_failure_no_plaintext_fallback_no_capture_or_authority_change(self):
        runner, env, summary, source = self.fixture_capture("producer", "frontend-security")
        before = authority(runner)
        retained = {p.name: p.read_bytes() for p in source.iterdir()}
        for category in ("gpg-runtime-closure", "gpg-binary-integrity", "encryption-process"):
            with mock.patch.object(recovery, "source_identity", return_value=self.candidate(runner)), \
                 mock.patch.object(recovery, "validated_preflight", return_value={}), \
                 mock.patch.object(recovery, "RuntimeLease", side_effect=recovery.RecoveryError(category)):
                self.reject(category, recovery.export_capture, REPO, env, "producer", summary["transaction"], "failure")
            self.assertEqual(before, authority(runner))
            self.assertEqual(retained, {p.name: p.read_bytes() for p in source.iterdir()})
            self.assertFalse((self.root / "issue13-producer-export").exists())

    def test_replay_eligibility_byte_identical_with_real_transport_enabled_disabled_and_failure(self):
        # Existing compact fixture returns an already-completed comparison.
        # No repository command is executed or replayed.
        self.install()
        runner, claims, comparison = fixtures.fixtures.p52_compact_replay_fixture()
        runner.captures = []
        runner.run = mock.Mock(return_value=comparison)
        runner.close_execution_leases = mock.Mock()
        external = fixtures.fixtures.synthetic_external_context(runner.execution_binding)
        def eligibility():
            return ci.run_verification_replay(copy.deepcopy(claims), expected_context=external, verification_runner=runner)
        before_result = eligibility()
        before = ci._canonical_frame(before_result)
        self.assertEqual(before_result[0]["finalAcceptance"], "PASS")
        env = environment(self.root, "fresh-replay")
        live = recovery.context(env, "fresh-replay")
        capture.capture_completed_runner(ci, runner, root=self.root / "issue13-replay",
            transaction=live["transaction"], phase="fresh-replay", repo_root=REPO)
        summary = json.loads((self.root / "issue13-replay/public.json").read_bytes())
        self.assertEqual(summary["selectedCount"], 0)
        # This existing fixture is profile static; isolate that snapshot reader
        # boundary while retaining real packaging/encryption and eligibility.
        with mock.patch.object(recovery, "source_identity", return_value={}), \
             mock.patch.object(recovery, "validated_preflight", return_value={"synthetic": {"ciphertextSha256": "d" * 64}}), \
             mock.patch.object(base, "snapshot_capture", return_value=(summary, {"public.json": capture.validate_public(summary)})):
            recovery.export_capture(REPO, env, "fresh-replay", live["transaction"], "success")
        self.assertEqual(before, ci._canonical_frame(eligibility()))
        with mock.patch.object(recovery, "source_identity", side_effect=recovery.RecoveryError("gpg-runtime-closure")):
            self.reject("gpg-runtime-closure", recovery.export_capture, REPO, env, "fresh-replay", live["transaction"], "success")
        self.assertEqual(before, ci._canonical_frame(eligibility()))
        claims["command-results.json"]["records"][0]["exitCode"] = 93
        rejected_before = ci._canonical_frame(eligibility())
        self.assertNotEqual(before, rejected_before)
        with mock.patch.object(recovery, "source_identity", side_effect=recovery.RecoveryError("gpg-runtime-closure")):
            self.reject("gpg-runtime-closure", recovery.export_capture, REPO, env, "fresh-replay", live["transaction"], "failure")
        self.assertEqual(rejected_before, ci._canonical_frame(eligibility()))

    def test_diagnostic_documents_cannot_satisfy_authoritative_claims(self):
        runner, _, summary, _ = self.fixture_capture("producer", "frontend-security")
        _, violations = ci.compare_verification_replay_claims(
            {"summary.json": summary, "command-results.json": summary}, runner, fixtures.fixtures.empty_comparison())
        self.assertTrue(violations)
        for name in ("ReplayAuthorizationEnvelope", "knownDebtsObserved", "hardGates", "replayAuthorizationEnvelopeDigest"):
            self.assertNotIn(name, summary)

    def test_cli_failures_emit_only_allowlisted_categories_and_stop(self):
        for error in (ValueError(fixtures.CANARY), recovery.RecoveryError("gpg-binary-integrity")):
            output = io.StringIO()
            with mock.patch.object(recovery, "preflight", side_effect=error), contextlib.redirect_stderr(output):
                self.assertEqual(recovery.main(["preflight"]), 1)
            self.assertEqual(output.getvalue(), base.MARKER + ": " + recovery.category(error) + "\nSTOP WINDOWS ACQUISITION\n")
            self.assertNotIn(fixtures.CANARY, output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(recovery.main(["--unknown-private-path", fixtures.CANARY]), 1)
        self.assertNotIn(fixtures.CANARY, output.getvalue())

    def test_source_scope_and_static_no_preflight_runner_or_secret_operations(self):
        source = (REPO / recovery.RECOVERY_PATHS[1]).read_text("utf-8")
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        preflight = ast.get_source_segment(source, functions["preflight"])
        for forbidden in ("FoundationRunner", "verify_evidence", "run_verification_replay", "load_capture_modules", "unittest"):
            self.assertNotIn(forbidden, preflight)
        for forbidden in ("shutil.which", "find_gpg", "--recv-keys"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count('"--decrypt"'), 1)
        self.assertIn('ring.encrypt(SMOKE)', ast.get_source_segment(source, functions["synthetic_preflight"]))
        for name in base.SOURCE_PATHS:
            # These pins describe the historical recovery, not a later capture
            # candidate. v2 separately proves current ordinary/crypto isolation.
            self.assertEqual(base.git_bytes(REPO, "cat-file", "blob", "ddf1e597:" + name), base.git_bytes(REPO, "cat-file", "blob", recovery.PARENT + ":" + name))
        for name, digest in base.CAPTURE_SOURCES.items():
            self.assertEqual(base.digest(base.git_bytes(REPO, "cat-file", "blob", "ddf1e597:" + name)), digest)

    def test_workflow_pass_only_topology_no_ubuntu_or_rerun_ordinary_results_preserved(self):
        workflow = ci.parse_canonical_workflow_yaml((REPO / recovery.RECOVERY_PATHS[0]).read_text())
        old = ci.parse_canonical_workflow_yaml(base.git_bytes(REPO, "cat-file", "blob", recovery.PARENT + ":.github/workflows/issue-13-acquisition.yml").decode())
        self.assertEqual(workflow["on"], {"push": {"branches": ["codex/issue-13-windows-transport-recovery"]}})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        jobs = workflow["jobs"]
        self.assertEqual(set(jobs), {"windows-gnupg-preflight", *recovery.JOB_PHASES})
        self.assertEqual(jobs["windows-gnupg-preflight"]["if"], "${{ github.event.created == true && github.run_attempt == 1 }}")
        self.assertEqual(jobs["windows-compatibility-producer"]["if"], "${{ needs.windows-gnupg-preflight.outputs.preflight == 'PASS' }}")
        self.assertEqual(jobs["windows-compatibility"]["if"], "${{ always() && needs.windows-gnupg-preflight.outputs.preflight == 'PASS' && needs.windows-compatibility-producer.outputs.diagnostic_ready == 'true' }}")
        self.assertEqual(jobs["windows-compatibility"]["needs"], ["windows-gnupg-preflight", "windows-compatibility-producer"])
        for name, job in jobs.items():
            self.assertEqual(job["runs-on"], "windows-latest")
            steps = job["steps"]
            preflight = next(i for i, step in enumerate(steps) if step.get("id") in ("preflight", "local-preflight"))
            self.assertEqual(steps[preflight]["run"], "python -B developer/tests/ci/issue13_windows_transport_recovery.py preflight")
            self.assertNotIn("continue-on-error", steps[preflight])
            if name == "windows-gnupg-preflight":
                self.assertFalse(any("run_ci_foundation" in step.get("run", "") for step in steps))
                continue
            ordinary = next(i for i, step in enumerate(steps) if step.get("id") == "ordinary")
            self.assertLess(preflight, ordinary)
            self.assertEqual(steps[ordinary]["run"], next(step["run"] for step in old["jobs"][name]["steps"] if step.get("id") == "ordinary"))
            self.assertNotIn("continue-on-error", steps[ordinary])
            exports = [step for step in steps if step.get("id") in ("diagnostic-export", "private-upload", "public-upload")]
            self.assertEqual(len(exports), 3)
            self.assertTrue(all(step["continue-on-error"] == "true" for step in exports))
            self.assertTrue(all(steps.index(step) > ordinary for step in exports))
            self.assertIn("always()", exports[0]["if"])
            self.assertIn("steps.ordinary.outcome", exports[0]["if"])
            self.assertTrue(exports[1]["with"]["path"].endswith("/issue13-private.tar.gz.gpg"))
            self.assertEqual([Path(line).name for line in exports[2]["with"]["path"].splitlines()], ["public.json", "transport.json"])
            self.assertTrue(all("steps.diagnostic-export.outcome == 'success'" in step["if"] for step in exports[1:]))
        self.assertEqual(ci.check_workflow_text((REPO / ".github/workflows/ci.yml").read_text()), [])


WINDOWS_CONTRACT_RESULTS = {"legacyWindows": [], "v2Windows": []}


class WindowsSourceProfileTests(unittest.TestCase):
    """Source/context controls do not provision or execute a GnuPG runtime."""
    @classmethod
    def setUpClass(cls):
        import test_issue13_acquisition_transport as source_tests
        cls.source_tests = source_tests
        cls.original = source_tests.checkpoint_module("issue13_windows_transport_recovery")
        cls.original.base = source_tests.checkpoint_module("issue13_acquisition_transport")

    def outcome(self, function, *args, **kwargs):
        try:
            return ("accept", base.json_bytes(function(*args, **kwargs)))
        except Exception as error:
            return ("reject", type(error).__name__, str(error))

    def test_legacy_windows_context_acceptance_rejection_is_identical(self):
        env = environment(Path("unused"))
        for job, phase in (("windows-gnupg-preflight", None),
                           ("windows-compatibility-producer", "producer"),
                           ("windows-compatibility", "fresh-replay")):
            for label, changes in (("historical", {}), ("v2-branch", {"GITHUB_REF": base.V2_BRANCH}),
                ("ubuntu-branch", {"GITHUB_REF": base.BRANCH}), ("repository", {"GITHUB_REPOSITORY": "other/repo"}),
                ("attempt", {"GITHUB_RUN_ATTEMPT": "2"}), ("event", {"GITHUB_EVENT_NAME": "workflow_dispatch"}),
                ("commit", {"GITHUB_SHA": recovery.PARENT}), ("job", {"GITHUB_JOB": "unknown"})):
                value = {**env, "GITHUB_JOB": job, **changes}
                before = self.outcome(self.original.context, value, phase)
                after = self.outcome(recovery.profile_context, value, phase, source_profile="legacy")
                self.assertEqual(before, after)
                self.assertEqual(after[0], "accept" if label == "historical" else "reject")
                WINDOWS_CONTRACT_RESULTS["legacyWindows"].append({"case": job + ":" + label,
                    "result": after[0], "byteEqual": True})

    def test_legacy_windows_source_acceptance_rejection_is_identical(self):
        fixture = self.source_tests.SourceContractFixture(legacy_windows=True)
        for case in ("historical", "parent", "grandparent", "tree", "scope", "source", "checkout", "v2-tree"):
            f = copy.deepcopy(fixture)
            if case == "parent": f.refs["HEAD^"] = base.V2_CAPTURE_COMMIT
            if case == "grandparent": f.refs["HEAD^^"] = base.V2_CAPTURE_COMMIT
            if case == "tree": f.refs["HEAD^{tree}"] = "invalid"
            if case == "scope": f.legacy_changes.append(base.V2_WORKFLOW)
            if case == "source":
                name = base.PUBLIC_KEY_PATH
                f.files[f.commit][name] += b"changed"
                f.checkout[name] = f.files[f.commit][name]
            if case == "checkout": f.checkout[base.PUBLIC_KEY_PATH] += b"changed"
            if case == "v2-tree": f = self.source_tests.SourceContractFixture()
            with f.installed(), mock.patch.object(self.original.base, "git_bytes", side_effect=f.git), \
                 mock.patch.object(self.original.base, "bounded_file", side_effect=f.file):
                before = self.outcome(self.original.source_identity, f.repo, f.commit)
                after = self.outcome(recovery.profile_source_identity, f.repo, f.commit)
            self.assertEqual(before, after)
            self.assertEqual(after[0], "accept" if case == "historical" else "reject")
            WINDOWS_CONTRACT_RESULTS["legacyWindows"].append({"case": "source-" + case,
                "result": after[0], "byteEqual": True})

    def test_windows_v2_explicit_context_pair_and_source_contract(self):
        env = {**environment(Path("unused")), "GITHUB_REF": base.V2_BRANCH}
        rows = []
        with mock.patch.object(recovery.os, "name", "nt"):
            for job, phase in (("windows-gnupg-preflight", None),
                               ("windows-compatibility-producer", "producer"),
                               ("windows-compatibility", "fresh-replay")):
                value = {**env, "GITHUB_JOB": job}
                live = recovery.profile_context(value, phase, source_profile=base.V2_PROFILE)
                rows.append(live)
                self.assertEqual(live, recovery.profile_context(value, source_profile=base.V2_PROFILE))
                with self.assertRaises(recovery.RecoveryError): recovery.profile_context(value)
            self.assertEqual(len({row["transaction"] for row in rows}), 1)
            for key, value in (("GITHUB_REF", recovery.BRANCH), ("GITHUB_RUN_ATTEMPT", "2"),
                               ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_JOB", "ubuntu-canonical")):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.profile_context({**env, key: value}, source_profile=base.V2_PROFILE)
        fixture = self.source_tests.SourceContractFixture()
        with fixture.installed():
            identity = recovery.profile_source_identity(REPO, fixture.commit, source_profile=base.V2_PROFILE)
            self.assertEqual(identity, base.source_identity_v2(REPO, fixture.commit))
        with self.assertRaises(recovery.RecoveryError): recovery.profile_source_identity(REPO, fixture.commit, source_profile="unknown")
        WINDOWS_CONTRACT_RESULTS["v2Windows"].append({"case": "explicit-context-pair-and-source", "result": "accept"})

    def test_windows_v2_identity_failure_stops_preflight_and_export_before_runtime(self):
        env = {**environment(Path("unused")), "GITHUB_REF": base.V2_BRANCH,
               "GITHUB_JOB": "windows-compatibility-producer"}
        with mock.patch.object(recovery.os, "name", "nt"), \
             mock.patch.object(recovery, "inspect_approved_locations", return_value=("GPG_NOT_AVAILABLE", [])), \
             mock.patch.object(base, "source_identity_v2", side_effect=base.TransportError("candidate-identity")) as source, \
             mock.patch.object(recovery, "provision_runtime") as provision, \
             mock.patch.object(recovery, "validated_preflight") as proof, \
             mock.patch.object(base, "load_capture_modules") as capture_loader, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(recovery.RecoveryError):
                recovery.preflight(REPO, env, source_profile=base.V2_PROFILE)
            tx = base.transaction_id(env["GITHUB_SHA"], env["GITHUB_RUN_ID"], "windows")
            with self.assertRaises(recovery.RecoveryError):
                recovery.export_capture(REPO, env, "producer", tx, "failure", source_profile=base.V2_PROFILE)
            self.assertEqual(source.call_count, 2)
            provision.assert_not_called()
            proof.assert_not_called()
            capture_loader.assert_not_called()

    def test_windows_cli_explicit_profile_dispatch_and_original_default(self):
        for profile in ("legacy", base.V2_PROFILE):
            suffix = [] if profile == "legacy" else ["--source-profile", profile]
            with mock.patch.object(recovery, "preflight") as preflight, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(recovery.main(["preflight", *suffix]), 0)
                self.assertEqual(preflight.call_args.kwargs, {"source_profile": profile})
            with mock.patch.object(recovery, "export_capture") as export, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(recovery.main(["export", "--phase", "fresh-replay", "--transaction", "0" * 32,
                                               "--ordinary-outcome", "failure", *suffix]), 0)
                self.assertEqual(export.call_args.kwargs, {"source_profile": profile})

    def test_windows_v2_context_dispatch_does_not_change_preflight_body(self):
        env = {**environment(Path("unused")), "GITHUB_REF": base.V2_BRANCH}
        fixture = self.source_tests.SourceContractFixture()
        env["GITHUB_SHA"] = fixture.commit
        config = {"runtimeDirectory": "synthetic-runtime"}
        expected_identity = None
        with fixture.installed():
            expected_identity = base.source_identity_v2(REPO, fixture.commit)
        with mock.patch.object(recovery.os, "name", "nt"), \
             mock.patch.object(recovery, "inspect_approved_locations", return_value=("GPG_NOT_AVAILABLE", [])), \
             mock.patch.object(base, "source_identity_v2", return_value=expected_identity), \
             mock.patch.object(recovery, "configuration", return_value=config), \
             mock.patch.object(recovery, "provision_runtime", return_value=Path("synthetic-runtime")), \
             mock.patch.object(recovery, "RuntimeLease") as lease, \
             mock.patch.object(recovery, "RecoveryKeyring") as ring, \
             mock.patch.object(recovery, "recipient_certificate", return_value=b"public certificate"), \
             mock.patch.object(recovery, "synthetic_preflight", return_value={"status": "PASS"}), \
             mock.patch.object(recovery, "private_directory", return_value=Path("synthetic-proof")), \
             mock.patch.object(recovery, "exclusive") as write, \
             mock.patch.object(recovery, "write_github_preflight_output") as output, contextlib.redirect_stdout(io.StringIO()):
            ring.return_value.tool = {}
            ring.return_value.identity = {}
            proof = recovery.preflight(REPO, env, source_profile=base.V2_PROFILE)
            self.assertEqual(proof["candidate"], expected_identity)
            self.assertEqual(proof["context"]["transaction"], base.transaction_id(fixture.commit, env["GITHUB_RUN_ID"], "windows"))
            self.assertEqual(proof["synthetic"], {"status": "PASS"})
            write.assert_called_once()
            output.assert_called_once_with(env, proof["context"]["transaction"])
            lease.assert_called_once()

    def test_windows_legacy_functions_constants_and_nonidentity_logic_are_frozen(self):
        name = "developer/tests/ci/issue13_windows_transport_recovery.py"
        old = self.source_tests.history_bytes(base.V2_CAPTURE_COMMIT, name).decode().replace("\r\n", "\n")
        new = (REPO / name).read_text("utf-8")
        def nodes(source):
            return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body
                    if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        old_nodes, new_nodes = nodes(old), nodes(new)
        for name in old_nodes.keys() - {"preflight", "export_capture", "main"}:
            self.assertEqual(old_nodes[name], new_nodes[name], name)
        for name in ("preflight", "export_capture"):
            actual = new_nodes[name].replace(', *, source_profile="legacy"', '').replace(', source_profile="legacy"', '').replace(
                'profile_context(environment, source_profile=source_profile)', 'context(environment)').replace(
                'profile_context(environment, phase, source_profile=source_profile)', 'context(environment, phase)').replace(
                'profile_source_identity(repo, live["commit"], source_profile=source_profile)', 'source_identity(repo, live["commit"])')
            self.assertEqual(old_nodes[name], actual, name)
        for node in ast.parse(old).body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                key = node.targets[0].id
                self.assertEqual(getattr(self.original, key), getattr(recovery, key), key)


if __name__ == "__main__":
    unittest.main()
