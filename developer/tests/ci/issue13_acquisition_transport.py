"""NON-AUTHORITATIVE / DIAGNOSTIC-ONLY / ISSUE-13-ACQUISITION.

Temporary, encryption-only transport. Never imported by the CI verifier. Only
fixed diagnostic files are read; private bytes go to GnuPG on stdin, never logs.
No recipient private key, decryption, environment dump, or plaintext export.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time

MARKER = "NON-AUTHORITATIVE / DIAGNOSTIC-ONLY / ISSUE-13-ACQUISITION"
CAPTURE_COMMIT = "c696c5d7e8abbb195c0b42303be199049a63f6b9"
BRANCH = "refs/heads/codex/issue-13-acquisition"
REPOSITORY = "k-undurkhaan-2/IELTS-Project"
VERSION = 1
MIB = 1024 * 1024
MAX_BINARY = 16 * MIB
MAX_BUNDLE = 49 * MIB
MAX_CIPHERTEXT = 50 * MIB
MAX_MANIFEST = 64 * 1024
MAX_PRIVATE_RECORD = 8 * MIB
PRIMARY = "86D51BCDBC946CF1389969D530479D840D9D562B"
SUBKEY = "670239EA1230D51EE2220DBB96327B4091754647"
RECIPIENT = SUBKEY + "!"
PUBLIC_KEY_PATH = "developer/tests/ci/issue13-reviewer-public.asc"
PUBLIC_KEY_SHA256 = "52397bc3915c9738d73c2177c7af3eabd43d2372763fa9a6c57676b260cd3567"
CAPTURE_SOURCES = {
    "developer/tests/ci/run_ci_foundation.py": "3a836aaaf5db5c72a5b10a673721b4113a3702fdb9f619fc91548ceb26ba7ad3",
    "developer/tests/ci/issue13_diagnostic_capture.py": "d127ec9087172909b33c50ad1d698a47709c176a22cf4747f75e53885dbf5112",
    "developer/tests/ci/issue13_diagnostic_reporters.py": "c86dd42dfe59f2a32805cd9e847ecb6bbb70214d666ca587c8dde4fa3d7cf7e8",
    "developer/tests/ci/test_issue13_diagnostic_capture.py": "63bc91d1b809e58a9cdaeb4e25aee81bb385463dec791be858cbd96d44bc7fad",
}
TRANSPORT_PATHS = (
    ".github/workflows/issue-13-acquisition.yml",
    "developer/tests/ci/issue13_acquisition_transport.py",
    "developer/tests/ci/test_issue13_acquisition_transport.py",
    PUBLIC_KEY_PATH,
)
SOURCE_PATHS = (
    *CAPTURE_SOURCES,
    *TRANSPORT_PATHS,
    ".github/workflows/ci.yml",
    "developer/tests/ci/phase1-ci-baseline.json",
    "developer/tests/ci/test_ci_foundation.py",
    "developer/tests/ci/test_standalone_packaging.py",
    "backend/package.json",
)
JOB_CONTEXT = {
    "ubuntu-canonical-producer": ("ubuntu", "producer"),
    "ubuntu-canonical": ("ubuntu", "fresh-replay"),
    "windows-compatibility-producer": ("windows", "producer"),
    "windows-compatibility": ("windows", "fresh-replay"),
}


class TransportError(ValueError):
    """Only fixed categories may leave this module."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def transaction_id(commit, run_id, platform_name):
    if (not re.fullmatch(r"[0-9a-f]{40}", commit or "")
        or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id or "")
        or platform_name not in ("ubuntu", "windows")):
        raise TransportError("run-identity")
    return digest((MARKER + ":" + commit + ":" + run_id + ":" + platform_name).encode("ascii"))[:32]


def live_context(environment, phase=None):
    # Explicitly select seven non-secret context values; never serialize environ.
    values = {key: environment.get(key, "") for key in (
        "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_JOB")}
    if (values["GITHUB_REPOSITORY"] != REPOSITORY or values["GITHUB_REF"] != BRANCH
        or values["GITHUB_EVENT_NAME"] != "push" or values["GITHUB_RUN_ATTEMPT"] != "1"):
        raise TransportError("run-context")
    if phase is None:
        if values["GITHUB_JOB"] != "acquisition-configuration":
            raise TransportError("job-context")
        platform_name = None
    else:
        platform_name, expected_phase = JOB_CONTEXT.get(values["GITHUB_JOB"], (None, None))
        if phase != expected_phase or (os.name == "nt") != (platform_name == "windows"):
            raise TransportError("job-context")
    transaction = (None if platform_name is None else
                   transaction_id(values["GITHUB_SHA"], values["GITHUB_RUN_ID"], platform_name))
    return {"commit": values["GITHUB_SHA"], "runId": values["GITHUB_RUN_ID"],
            "attempt": 1, "transaction": transaction, "platform": platform_name, "phase": phase}


def git_bytes(repo, *args, limit=2 * MIB):
    # Fixed read-only git arguments only. Suppress stderr, which can contain paths.
    binary = shutil.which("git")
    if binary is None:
        raise TransportError("git-unavailable")
    return bounded_process([binary, *args], repo, limit=limit, timeout=20)


def source_identity(repo, expected_commit):
    commit = git_bytes(repo, "rev-parse", "HEAD").decode("ascii").strip()
    tree = git_bytes(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    parent = git_bytes(repo, "rev-parse", "HEAD^").decode("ascii").strip()
    if commit != expected_commit or parent != CAPTURE_COMMIT or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise TransportError("candidate-identity")
    changed = git_bytes(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").decode("ascii").splitlines()
    if sorted(changed) != sorted(TRANSPORT_PATHS):
        raise TransportError("candidate-scope")
    rows = []
    for name in SOURCE_PATHS:
        committed = git_bytes(repo, "cat-file", "blob", "HEAD:" + name)
        current = bounded_file(repo / name, 2 * MIB)
        if current not in (committed, committed.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")):
            raise TransportError("source-mutated")
        if name in CAPTURE_SOURCES and digest(committed) != CAPTURE_SOURCES[name]:
            raise TransportError("reviewed-source-identity")
        rows.append({"source": name, "gitBlobSha256": digest(committed),
                     "checkoutSha256": digest(current), "checkoutBytes": len(current)})
    return {"commit": commit, "tree": tree, "captureCommit": parent, "sources": rows}


def is_link(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def bounded_file(path, limit):
    before = path.lstat()
    if is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise TransportError("file-shape")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != (before.st_dev, before.st_ino, 1):
            raise TransportError("file-identity")
        data = stream.read(limit + 1)
    if len(data) > limit or len(data) != before.st_size:
        raise TransportError("file-bound")
    return data


def load_capture_modules(repo):
    # Source identity is checked by the caller before these imports. No verifier
    # execution or envelope-producing function is called by the transport.
    import run_ci_foundation as ci
    import issue13_diagnostic_capture as capture
    return ci, capture


def snapshot_capture(ci, capture, root, repo, context, *, candidate=None):
    summary = capture.read_capture(ci, root, repo)
    capture.validate_exportable(summary)
    if any(summary[key] != context[key] for key in ("transaction", "phase", "platform")) or summary["profile"] != "all":
        raise TransportError("capture-context")
    files = {}
    total = 0
    with os.scandir(root) as inventory:
        for index, item in enumerate(inventory):
            if index >= 25 or not re.fullmatch(r"public\.json|[0-7]\.(?:json|stdout\.bin|stderr\.bin)", item.name):
                raise TransportError("capture-inventory")
            limit = (capture.MAX_PUBLIC_BYTES if item.name == "public.json" else
                     MAX_PRIVATE_RECORD if item.name.endswith(".json") else 2 * MIB)
            data = bounded_file(root / item.name, limit)
            total += len(data)
            if total > capture.MAX_TOTAL_BYTES:
                raise TransportError("capture-bound")
            files[item.name] = data
    if files.get("public.json") != capture.validate_public(summary):
        raise TransportError("capture-changed")
    indices = sorted([r["ordinal"] for r in summary["records"]] + [r["ordinal"] for r in summary["errors"]])
    for row in summary["records"]:
        index = indices.index(row["ordinal"])
        private = files[f"{index}.json"]
        if capture.sha(private) != row["privateRecordSha256"] or len(private) != row["privateRecordBytes"]:
            raise TransportError("snapshot-binding")
        decoded = ci.strict_json_loads(private.decode("utf-8"), label="diagnostic")
        capture.validate_private(ci, decoded)
        capture.validate_authority_preimages(ci, decoded, row=row, summary=summary)
        if context.get("commit") is not None and decoded["captureBinding"]["candidateCommit"] != context["commit"]:
            raise TransportError("capture-context")
        if candidate is not None and any(decoded["captureBinding"]["candidate" + k.title()] != candidate.get(k) for k in ("commit", "tree")):
            raise TransportError("capture-context")
        for stream in ("stdout", "stderr"):
            info = row["streams"][stream]
            if info["retainedSha256"] is not None:
                raw = files[f"{index}.{stream}.bin"]
                if capture.sha(raw) != info["retainedSha256"] or len(raw) != info["retainedBytes"]:
                    raise TransportError("snapshot-binding")
    # Revalidate current directory after the bounded snapshot as well. The bytes
    # actually encrypted are bound independently to the snapshot's public rows.
    if capture.read_capture(ci, root, repo) != summary:
        raise TransportError("capture-changed")
    return summary, files


class Destination:
    def __init__(self, root, repo, capture):
        capture._check_parent(root, repo.resolve(strict=True))
        os.mkdir(root, 0o700)  # Never reuse or overwrite a destination.
        capture._restrict_windows_directory(root)
        self.root, self.identity, self.total = root, root.lstat(), 0

    def write(self, name, data, limit):
        if name not in ("issue13-private.tar.gz.gpg", "public.json", "transport.json"):
            raise TransportError("output-name")
        current = self.root.lstat()
        if (is_link(current) or (current.st_dev, current.st_ino) != (self.identity.st_dev, self.identity.st_ino)
            or len(data) > limit or self.total + len(data) > MAX_CIPHERTEXT + MIB):
            raise TransportError("output-bound")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.root / name, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise TransportError("output-file")
            stream.write(data)
        self.total += len(data)


def packets(data, allowed, *, partial=False):
    """Bounded OpenPGP framing, not cryptography; refuse secret packets pre-import."""
    if len(data) > MAX_CIPHERTEXT:
        raise TransportError("packet-bound")
    result, offset = [], 0
    while offset < len(data):
        header = data[offset]
        offset += 1
        if not header & 0x80 or len(result) >= 128:
            raise TransportError("packet-header")
        tag = header & 63 if header & 64 else (header >> 2) & 15
        if tag not in allowed:
            raise TransportError("packet-type")
        pieces, length_octets = [], 0
        while True:
            length_octets += 1
            if length_octets > 65536 or offset >= len(data):
                raise TransportError("packet-length")
            more = False
            if header & 64:
                first = data[offset]
                offset += 1
                if first < 192:
                    size = first
                elif first < 224:
                    if offset >= len(data):
                        raise TransportError("packet-length")
                    size = ((first - 192) << 8) + data[offset] + 192
                    offset += 1
                elif first == 255:
                    if offset + 4 > len(data):
                        raise TransportError("packet-length")
                    size = int.from_bytes(data[offset:offset + 4], "big")
                    offset += 4
                elif partial:
                    size, more = 1 << (first & 31), True
                else:
                    raise TransportError("packet-partial")
            else:
                width = (1, 2, 4, 0)[header & 3]
                if not width or offset + width > len(data):
                    raise TransportError("packet-length")
                size = int.from_bytes(data[offset:offset + width], "big")
                offset += width
            if offset + size > len(data):
                raise TransportError("packet-truncated")
            pieces.append(data[offset:offset + size])
            offset += size
            if not more:
                break
        result.append((tag, b"".join(pieces)))
    return result


def public_armor(data):
    if len(data) > MAX_MANIFEST:
        raise TransportError("public-key-bound")
    lines = data.decode("ascii").splitlines()
    if (len(lines) < 5 or lines[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        or lines[1] != "" or lines[-1] != "-----END PGP PUBLIC KEY BLOCK-----"
        or not re.fullmatch(r"=[A-Za-z0-9+/]{4}", lines[-2])):
        raise TransportError("public-key-armor")
    decoded = base64.b64decode("".join(lines[2:-2]), validate=True)
    tags = [tag for tag, _ in packets(decoded, {2, 6, 13, 14})]
    if not tags or tags[0] != 6 or tags.count(6) != 1 or not 1 <= tags.count(14) <= 8:
        raise TransportError("public-key-inventory")
    return data


def imported_identity(output, now=None):
    if len(output) > MAX_MANIFEST:
        raise TransportError("key-list-bound")
    now = int(time.time()) if now is None else now
    records, pending = [], None
    for line in output.decode("utf-8", "strict").splitlines():
        fields = line.split(":")
        if fields[0] in ("sec", "ssb"):
            raise TransportError("secret-material")
        if fields[0] in ("pub", "sub"):
            if len(fields) < 17 or pending is not None:
                raise TransportError("key-list-shape")
            pending = fields
        elif fields[0] == "fpr":
            if pending is None or len(fields) < 10:
                raise TransportError("key-list-shape")
            records.append((pending, fields[9]))
            pending = None
        elif fields[0] not in ("tru", "uid", "uat", "grp"):
            raise TransportError("key-list-shape")
    if pending is not None or not 2 <= len(records) <= 9:
        raise TransportError("key-list-shape")
    primary = records[0]
    selected = [record for record in records[1:] if record[1] == SUBKEY]
    if (primary[0][0] != "pub" or primary[1] != PRIMARY or len(selected) != 1
        or any(fields[0] != "sub" for fields, _ in records[1:])
        or len({fingerprint for _, fingerprint in records}) != len(records)
        or any("e" in fields[11] and fingerprint != SUBKEY for fields, fingerprint in records[1:])):
        raise TransportError("key-fingerprint")
    subkey = selected[0]
    for fields, _ in records:
        if fields[1] in ("r", "e", "d", "i") or "D" in fields[11] or (fields[6] and int(fields[6]) not in (0,) and int(fields[6]) <= now):
            raise TransportError("key-usability")
    if subkey[0][3] != "18" or "e" not in subkey[0][11] or subkey[0][16] != "cv25519":
        raise TransportError("subkey-encryption-capability")
    return {"primaryFingerprint": PRIMARY, "encryptionSubkeyFingerprint": SUBKEY,
            "recipientSelector": RECIPIENT, "curve": "cv25519", "encryptionCapable": True,
            "secretKeyCount": 0, "publicSubkeyCount": len(records) - 1}


def find_gpg():
    candidates = [Path("/usr/bin/gpg")] if os.name != "nt" else [
        Path("C:/Program Files (x86)/GnuPG/bin/gpg.exe"),
        Path("C:/Program Files/GnuPG/bin/gpg.exe"),
        Path("C:/Program Files/Git/usr/bin/gpg.exe")]
    for path in candidates:
        if path.is_file():
            for parent in (path, *path.parents):
                if is_link(parent.lstat()):
                    raise TransportError("gpg-location")
            bounded_file(path, MAX_BINARY)
            return path
    raise TransportError("gpg-unavailable")


def bounded_process(argv, home, *, data=b"", limit=MAX_MANIFEST, timeout=30):
    environment = {"PATH": str(Path(argv[0]).parent), "GNUPGHOME": str(home)}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")
    chunks, problems = [], []
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=environment, cwd=home) as process:
        def feed():
            try:
                process.stdin.write(data)
                process.stdin.close()
            except Exception:
                problems.append("stdin")
        def drain():
            count = 0
            try:
                while block := process.stdout.read(65536):
                    count += len(block)
                    if count > limit:
                        problems.append("output-bound")
                        process.kill()
                        break
                    chunks.append(block)
            except Exception:
                problems.append("stdout")
        workers = [threading.Thread(target=feed, daemon=True), threading.Thread(target=drain, daemon=True)]
        for worker in workers:
            worker.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            code = -1
        for worker in workers:
            worker.join(timeout=5)
        if code != 0 or problems or any(worker.is_alive() for worker in workers):
            raise TransportError("gpg-process")
    return b"".join(chunks)


def secret_free(home):
    metadata = home.lstat()
    if is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise TransportError("keyring-directory")
    with os.scandir(home) as inventory:
        for index, entry in enumerate(inventory):
            if index >= 16 or is_link(entry.stat(follow_symlinks=False)):
                raise TransportError("keyring-inventory")
            if entry.name == "private-keys-v1.d":
                with os.scandir(entry.path) as secrets:
                    if next(secrets, None) is not None:
                        raise TransportError("secret-material")
            elif entry.name not in ("pubring.kbx", "pubring.kbx~", "pubring.kb_", "pubring.kbx.lock",
                                    "trustdb.gpg", "trustdb.gpg.lock", "random_seed", ".gpg-v21-migrated"):
                raise TransportError("keyring-inventory")
            else:
                data = bounded_file(Path(entry.path), 2 * MIB)
                if entry.name.endswith(".lock") and data:
                    raise TransportError("keyring-lock")


class PublicKeyring:
    def __init__(self, binary, home, repo, capture, armor):
        public_armor(armor)  # Reject all secret packet types before import.
        if digest(armor) != PUBLIC_KEY_SHA256:
            raise TransportError("public-key-pin")
        destination = Destination(home, repo, capture)
        self.binary, self.home = binary, home
        self.home_identity = (destination.identity.st_dev, destination.identity.st_ino)
        self.binary_sha256 = digest(bounded_file(binary, MAX_BINARY))
        self.prefix = [str(binary), "--no-options", "--homedir", str(home), "--batch", "--no-tty",
                       "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve",
                       "--no-auto-key-import", "--auto-key-locate", "clear", "--pinentry-mode", "error"]
        self.run("--import", data=armor)
        output = self.run("--with-colons", "--fixed-list-mode", "--with-fingerprint",
                          "--with-subkey-fingerprint", "--list-keys")
        self.identity = imported_identity(output)
        # No secret key or card stub may be imported; no agent may autostart.
        if self.run("--with-colons", "--list-secret-keys").strip():
            raise TransportError("secret-material")
        secret_free(home)
        version = self.run("--version").splitlines()[0].decode("ascii")
        if not re.fullmatch(r"gpg \(GnuPG\) 2\.(?:2|4)\.[0-9]{1,3}", version):
            raise TransportError("gpg-version")
        self.tool = {"sha256": self.binary_sha256, "bytes": binary.stat().st_size, "version": version}

    def run(self, *args, data=b"", limit=MAX_MANIFEST, timeout=30):
        metadata = self.home.lstat()
        if is_link(metadata) or (metadata.st_dev, metadata.st_ino) != self.home_identity:
            raise TransportError("keyring-changed")
        if digest(bounded_file(self.binary, MAX_BINARY)) != self.binary_sha256:
            raise TransportError("gpg-mutated")
        return bounded_process([*self.prefix, *args], self.home, data=data, limit=limit, timeout=timeout)

    def encrypt(self, plaintext):
        if len(plaintext) > MAX_BUNDLE:
            raise TransportError("encryption-input")
        secret_free(self.home)
        encrypted = self.run("--trust-model", "always", "--recipient", RECIPIENT,
                             "--compress-algo", "none", "--set-filename", "",
                             "--output", "-", "--encrypt", data=plaintext, limit=MAX_CIPHERTEXT, timeout=90)
        entries = packets(encrypted, {1, 18, 20}, partial=True)
        if (len(entries) != 2 or entries[0][0] != 1 or entries[1][0] not in (18, 20) or len(entries[0][1]) < 10
            or entries[0][1][0] != 3 or entries[0][1][1:9].hex().upper() != SUBKEY[-16:]
            or entries[0][1][9] != 18 or not entries[1][1].startswith(b"\x01")):
            raise TransportError("ciphertext-recipient")
        secret_free(self.home)
        return encrypted


def private_tar(files, manifest):
    if len(files) > 25 or sum(map(len, files.values())) > 48 * MIB + 256 * 1024:
        raise TransportError("bundle-bound")
    payload = dict(files)
    payload["acquisition-manifest.json"] = json_bytes(manifest)
    if len(payload["acquisition-manifest.json"]) > MAX_MANIFEST:
        raise TransportError("manifest-bound")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(payload.items()):
            if not re.fullmatch(r"(?:public|acquisition-manifest)\.json|[0-7]\.(?:json|stdout\.bin|stderr\.bin)", name):
                raise TransportError("bundle-name")
            limit = (MAX_MANIFEST if name == "acquisition-manifest.json" else
                     256 * 1024 if name == "public.json" else
                     MAX_PRIVATE_RECORD if name.endswith(".json") else 2 * MIB)
            if len(data) > limit:
                raise TransportError("bundle-member-bound")
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            archive.addfile(info, io.BytesIO(data))
    data = output.getvalue()
    if len(data) > MAX_BUNDLE:
        raise TransportError("bundle-bound")
    compressed = gzip.compress(data, compresslevel=1, mtime=0)
    if len(compressed) > MAX_BUNDLE:
        raise TransportError("bundle-bound")
    return compressed


def export_capture(repo, environment, phase, transaction, outcome):
    context = live_context(environment, phase)
    if transaction != context["transaction"] or outcome not in ("success", "failure", "cancelled"):
        raise TransportError("export-context")
    identity = source_identity(repo, context["commit"])
    ci, capture = load_capture_modules(repo)
    temp = Path(environment.get("RUNNER_TEMP", ""))
    leaf = "issue13-producer" if phase == "producer" else "issue13-replay"
    summary, files = snapshot_capture(ci, capture, temp / leaf, repo, context, candidate=identity)
    private_manifest = {"schema": "Issue13EncryptedAcquisitionBundle", "version": VERSION,
                        "authority": MARKER, "context": context, "candidate": identity,
                        "primaryFingerprint": PRIMARY, "encryptionSubkeyFingerprint": SUBKEY,
                        "ordinaryStepOutcome": outcome,
                        "files": [{"name": name, "sha256": digest(data), "bytes": len(data)}
                                  for name, data in sorted(files.items())]}
    plaintext = private_tar(files, private_manifest)
    # Read the exact pinned public file from the candidate Git blob. This avoids
    # implicit Git checkout EOL conversion of the ASCII armor; working file bytes
    # are independently checked and reported by source_identity above.
    armor = git_bytes(repo, "cat-file", "blob", "HEAD:" + PUBLIC_KEY_PATH, limit=MAX_MANIFEST)
    keyring = PublicKeyring(find_gpg(), temp / (leaf + "-public-keyring"), repo, capture, armor)
    encrypted = keyring.encrypt(plaintext)
    public = {"schema": "Issue13AcquisitionTransport", "version": VERSION, "authority": MARKER,
              "context": context, "candidate": identity, "ordinaryStepOutcome": outcome,
              "recipient": keyring.identity, "publicKeySha256": PUBLIC_KEY_SHA256,
              "encryption": "OpenPGP-cv25519", "integrity": "MDC" if packets(encrypted, {1, 18, 20}, partial=True)[1][0] == 18 else "AEAD",
              "tool": keyring.tool, "ciphertextSha256": digest(encrypted),
              "ciphertextBytes": len(encrypted), "publicSha256": digest(files["public.json"]),
              "publicBytes": len(files["public.json"]), "privateFileCount": len(files),
              "privateBytes": sum(map(len, files.values())), "plaintextBundleSha256": digest(plaintext),
              "plaintextBundleBytes": len(plaintext), "retentionDays": 1}
    encoded = json_bytes(public)
    if len(encoded) > MAX_MANIFEST:
        raise TransportError("manifest-bound")
    destination = Destination(temp / (leaf + "-export"), repo, capture)
    destination.write("issue13-private.tar.gz.gpg", encrypted, MAX_CIPHERTEXT)
    destination.write("public.json", capture.validate_public(summary), capture.MAX_PUBLIC_BYTES)
    destination.write("transport.json", encoded, MAX_MANIFEST)
    return public


def main(argv=None):
    parser = argparse.ArgumentParser(description=MARKER, allow_abbrev=False)
    parser.add_argument("mode", choices=("configure", "export"))
    parser.add_argument("--phase", choices=("producer", "fresh-replay"))
    parser.add_argument("--transaction")
    parser.add_argument("--ordinary-outcome", choices=("success", "failure", "cancelled"))
    try:
        args = parser.parse_args(argv)
        repo = Path(__file__).resolve().parents[3]
        if args.mode == "configure":
            context = live_context(os.environ)
            source_identity(repo, context["commit"])
            armor = git_bytes(repo, "cat-file", "blob", "HEAD:" + PUBLIC_KEY_PATH, limit=MAX_MANIFEST)
            if digest(public_armor(armor)) != PUBLIC_KEY_SHA256:
                raise TransportError("public-key-pin")
            output = "".join(
                platform_name + "_transaction="
                + transaction_id(context["commit"], context["runId"], platform_name) + "\n"
                for platform_name in ("ubuntu", "windows"))
            # GitHub-owned output command file receives only two strictly
            # bounded public values, never capture paths, raw streams, or JSON.
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii", newline="\n") as stream:
                stream.write(output)
        else:
            export_capture(repo, os.environ, args.phase, args.transaction, args.ordinary_outcome)
    except Exception:
        print(MARKER + ": transport unavailable", file=sys.stderr)
        return 1
    print(MARKER + ": transport step completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
