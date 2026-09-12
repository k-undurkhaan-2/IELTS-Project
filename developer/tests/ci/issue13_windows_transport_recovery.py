"""Windows-only, NON-AUTHORITATIVE diagnostic transport recovery.

This module never runs a producer/verifier, changes a CI record, or creates an
authorization envelope. The workflow uses preflight only as a scheduling stop.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.request

import issue13_acquisition_transport as base
import issue13_diagnostic_capture as capture

MARKER = base.MARKER
PARENT = "bad2b46c8d22c587ac3b8604fb7a5dc12aa31cc0"
BRANCH = "refs/heads/codex/issue-13-windows-transport-recovery"
OLD_TRANSACTION = "127c77fd950b5dc7476b4aa2f0cadff1"
VERSION = "2.5.22"
PACKAGE_URL = "https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.22_20260831.wixlib"
PACKAGE_SHA256 = "d4e3d0fe66a09567d40cf64071ea935c13175b03b5bb83556130040a927cc9e1"
PACKAGE_BYTES = 7205212
BINARY_BYTES = 1376296
CABINET_BYTES = 7045608
BINARY_SHA256 = "576b217cc73f83058d7867d2dc4994fd8bc9328d5214c7917f2dc0a1e9e56fd3"
CLOSURE_SHA256 = "01be0bac21b43acd9ad6dc2cf5ed8e13a2847213909fae58cc42c3ce22810694"
MANIFEST_PATH = "developer/tests/ci/issue13_gnupg_windows_runtime.json"
RECOVERY_PATHS = (
    ".github/workflows/issue-13-windows-transport-recovery.yml",
    "developer/tests/ci/issue13_windows_transport_recovery.py",
    MANIFEST_PATH,
    "developer/tests/ci/test_issue13_windows_transport_recovery.py",
    "developer/tests/ci/ISSUE13_WINDOWS_TRANSPORT_RECOVERY.md",
)
APPROVED_LOCATIONS = (
    Path("C:/Program Files/GnuPG/bin/gpg.exe"),
    Path("C:/Program Files (x86)/GnuPG/bin/gpg.exe"),
    Path("C:/Program Files/Git/usr/bin/gpg.exe"),
)
CATEGORIES = frozenset({
    "gpg-unavailable", "gpg-unapproved-location", "gpg-package-integrity",
    "gpg-binary-integrity", "gpg-runtime-closure", "gpg-version", "gpg-process",
    "public-key-pin", "public-key-identity", "public-key-expired",
    "public-key-revoked", "encryption-preflight", "encryption-process",
    "output-bound", "unexpected-transport-category",
})
SMOKE = b"ISSUE-13 PUBLIC SYNTHETIC PREFLIGHT v1\n"
MAX_RUNTIME_FILES = 128
MAX_RUNTIME_NODES = 256
MAX_RUNTIME_BYTES = 32 * base.MIB
MAX_COMPONENT_BYTES = 8 * base.MIB
MAX_STDERR = 65536
JOB_PHASES = {"windows-compatibility-producer": "producer", "windows-compatibility": "fresh-replay"}


class RecoveryError(ValueError):
    def __init__(self, category):
        self.category = category if category in CATEGORIES else "unexpected-transport-category"
        super().__init__(self.category)


def category(error):
    return error.category if isinstance(error, RecoveryError) else "unexpected-transport-category"


def require(value, failure):
    if not value:
        raise RecoveryError(failure)


def read_json(data):
    require(len(data) <= base.MAX_MANIFEST, "output-bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "gpg-runtime-closure")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(RecoveryError("gpg-runtime-closure")))
    except (ValueError, UnicodeError) as error:
        raise RecoveryError("gpg-runtime-closure") from error


def configuration(repo):
    result = read_json(base.bounded_file(repo / MANIFEST_PATH, base.MAX_MANIFEST))
    expected = {"schema", "version", "authority", "distributionVersion", "source", "packageName",
                "packageSha256", "packageBytes", "cabinetBytes", "releaseSignerFingerprint",
                "runtimeDirectory", "binaryRelativePath", "binarySha256", "runtimeClosureSha256", "files"}
    require(type(result) is dict and result.keys() == expected, "gpg-runtime-closure")
    require(result["schema"] == "Issue13WindowsGnuPGRuntime" and type(result["version"]) is int and result["version"] == 1
            and result["authority"] == MARKER and result["distributionVersion"] == VERSION
            and result["source"] == PACKAGE_URL and result["packageSha256"] == PACKAGE_SHA256
            and result["packageBytes"] == PACKAGE_BYTES and result["cabinetBytes"] == CABINET_BYTES
            and result["packageName"] == "gnupg-w32-2.5.22_20260831.wixlib"
            and result["releaseSignerFingerprint"] == "6DAA6E64A76D2840571B4902528897B826403ADA"
            and result["runtimeDirectory"] == "issue13-gnupg" and result["binaryRelativePath"] == "bin/gpg.exe"
            and result["binarySha256"] == BINARY_SHA256 and result["runtimeClosureSha256"] == CLOSURE_SHA256,
            "gpg-runtime-closure")
    files = result["files"]
    require(type(files) is list and len(files) == 87, "gpg-runtime-closure")
    for row in files:
        require(type(row) is dict and row.keys() == {"path", "cabinetFileId", "sha256", "bytes"}, "gpg-runtime-closure")
        require(type(row["path"]) is str and re.fullmatch(r"[A-Za-z0-9_.+@/-]{1,180}", row["path"])
                and not PurePosixPath(row["path"]).is_absolute()
                and all(part not in (".", "..") for part in row["path"].split("/"))
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                and type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_COMPONENT_BYTES
                and re.fullmatch(r"[0-9]{1,2}", row["cabinetFileId"]), "gpg-runtime-closure")
    require(len({row["path"].casefold() for row in files}) == 87
            and {row["cabinetFileId"] for row in files} == {str(i) for i in range(87)}
            and sum(row["bytes"] for row in files) <= MAX_RUNTIME_BYTES
            and base.digest(base.json_bytes(files)) == CLOSURE_SHA256, "gpg-runtime-closure")
    return result


def private_directory(path, repo):
    try:
        capture._check_parent(path, repo.resolve(strict=True))
        path.mkdir(mode=0o700)
        capture._restrict_windows_directory(path)
    except Exception as error:
        raise RecoveryError("gpg-runtime-closure") from error
    return path


def exclusive(path, data, limit):
    require(len(data) <= limit, "output-bound")
    with path.open("xb") as output:
        output.write(data)


def inspect_approved_locations():
    """Metadata only, bounded fixed locations; location alone is not authority."""
    found = []
    for index, path in enumerate(APPROVED_LOCATIONS):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return "GPG_RUNTIME_INVALID", []
        if base.is_link(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_COMPONENT_BYTES:
            return "GPG_RUNTIME_INVALID", []
        found.append(index)
    return ("GPG_APPROVED_RUNTIME_AVAILABLE" if found else "GPG_NOT_AVAILABLE"), found


def inspect_unapproved_hints(hints):
    """Optional bounded private hints are data only; never execution candidates."""
    require(type(hints) is list and len(hints) <= 8, "gpg-unapproved-location")
    records = []
    for path in hints:
        require(isinstance(path, Path) and path.is_absolute() and len(str(path)) <= 1024,
                "gpg-unapproved-location")
        if path in APPROVED_LOCATIONS:
            continue
        try:
            metadata = path.lstat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and not base.is_link(metadata):
            records.append({"path": str(path), "bytes": metadata.st_size})
    return records  # Caller may write only to a private diagnostic location.


def child_process(argv, home, *, data=b"", limit=base.MAX_MANIFEST, timeout=30):
    """Bound both streams, retain in memory, return no raw bytes to public logs."""
    environment = {"PATH": str(Path(argv[0]).parent), "GNUPGHOME": str(home),
                   "USERPROFILE": str(home), "APPDATA": str(home), "TEMP": str(home), "TMP": str(home),
                   "SystemRoot": "C:\\Windows", "WINDIR": "C:\\Windows"}
    chunks = {"stdout": [], "stderr": []}
    problems = []
    try:
        with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=home, env=environment,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0) as process:
            def feed():
                try:
                    process.stdin.write(data)
                    process.stdin.close()
                except (OSError, ValueError):
                    problems.append("process")
            def drain(name, bound):
                count = 0
                try:
                    while block := getattr(process, name).read(65536):
                        count += len(block)
                        if count > bound:
                            problems.append("bound")
                            process.kill()
                            break
                        chunks[name].append(block)
                except (OSError, ValueError):
                    problems.append("process")
            workers = [threading.Thread(target=feed, daemon=True),
                       threading.Thread(target=drain, args=("stdout", limit), daemon=True),
                       threading.Thread(target=drain, args=("stderr", MAX_STDERR), daemon=True)]
            for worker in workers:
                worker.start()
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                problems.append("process")
                code = -1
            for worker in workers:
                worker.join(timeout=5)
            if "bound" in problems:
                raise RecoveryError("output-bound")
            require(not problems and not any(worker.is_alive() for worker in workers), "gpg-process")
    except (OSError, subprocess.SubprocessError) as error:
        raise RecoveryError("gpg-process") from error
    return code, b"".join(chunks["stdout"]), b"".join(chunks["stderr"])


class FileLease:
    """Windows share-read lease denies write/delete of a reviewed component."""
    def __init__(self, path, *, directory=False):
        require(os.name == "nt", "gpg-runtime-closure")
        import msvcrt
        self.path, self.fd, self.handle = path, None, None
        metadata = path.lstat()
        require(not base.is_link(metadata) and (stat.S_ISDIR(metadata.st_mode) if directory else
                stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1), "gpg-runtime-closure")
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                    ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        api.CreateFileW.restype = ctypes.c_void_p
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        self.api = api
        flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT; BACKUP_SEMANTICS
        handle = api.CreateFileW(str(path), 0x80000000, 1, None, 3, flags, None)
        require(handle not in (None, ctypes.c_void_p(-1).value), "gpg-runtime-closure")
        if directory:
            self.handle = handle
        else:
            try:
                self.fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                opened = os.fstat(self.fd)
                require((opened.st_dev, opened.st_ino, opened.st_nlink) == (metadata.st_dev, metadata.st_ino, 1), "gpg-runtime-closure")
            except Exception:
                if self.fd is not None:
                    os.close(self.fd)
                    self.fd = None
                else:
                    api.CloseHandle(handle)
                raise
        self.identity = (metadata.st_dev, metadata.st_ino)

    def data(self, limit):
        require(self.fd is not None, "gpg-runtime-closure")
        os.lseek(self.fd, 0, os.SEEK_SET)
        data = os.read(self.fd, limit + 1)
        require(len(data) <= limit, "gpg-runtime-closure")
        return data

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

class RuntimeLease:
    def __init__(self, root, config, *, binary=None, preinstalled=False):
        self.root, self.config = root, config
        self.binary = root / config["binaryRelativePath"] if binary is None else binary
        require(root.is_absolute() and self.binary == root / "bin/gpg.exe", "gpg-unapproved-location")
        if preinstalled:
            require(self.binary in APPROVED_LOCATIONS, "gpg-unapproved-location")
        self.files, self.directories, self.parents = {}, {}, {}
        self.active = False

    def inventory(self):
        files, directories, nodes = set(), set(), 0
        stack = [self.root]
        while stack:
            directory = stack.pop()
            metadata = directory.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and not base.is_link(metadata), "gpg-runtime-closure")
            directories.add(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    nodes += 1
                    require(nodes <= MAX_RUNTIME_NODES, "gpg-runtime-closure")
                    path = directory / entry.name
                    # DirEntry.stat on Windows omits link-count/file-ID data.
                    # Fetch full metadata independently instead of weakening it.
                    metadata = path.lstat()
                    require(not base.is_link(metadata), "gpg-runtime-closure")
                    if stat.S_ISDIR(metadata.st_mode):
                        stack.append(path)
                    else:
                        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                                "gpg-runtime-closure")
                        files.add(path.relative_to(self.root).as_posix())
        expected = {row["path"] for row in self.config["files"]}
        expected_dirs = {self.root}
        for name in expected:
            expected_dirs.update((self.root / name).parents)
        expected_dirs = {path for path in expected_dirs if path == self.root or self.root in path.parents}
        require(files == expected and directories == expected_dirs, "gpg-runtime-closure")
        return directories

    def __enter__(self):
        try:
            for path in self.root.parents:
                metadata = path.lstat()
                require(stat.S_ISDIR(metadata.st_mode) and not base.is_link(metadata), "gpg-runtime-closure")
                self.parents[path] = (metadata.st_dev, metadata.st_ino)
            directories = self.inventory()
            for path in sorted(directories, key=str):
                self.directories[path] = FileLease(path, directory=True)
            for row in self.config["files"]:
                lease = FileLease(self.root / row["path"])
                self.files[row["path"]] = lease
                data = lease.data(MAX_COMPONENT_BYTES)
                require(len(data) == row["bytes"] and base.digest(data) == row["sha256"],
                        "gpg-binary-integrity" if row["path"] == "bin/gpg.exe" else "gpg-runtime-closure")
            self.active = True
            self.verify()
            return self
        except Exception as error:
            self.close()
            if isinstance(error, RecoveryError):
                raise
            raise RecoveryError("gpg-runtime-closure") from error

    def verify(self):
        require(self.active, "gpg-runtime-closure")
        try:
            self.inventory()
            for path, identity in self.parents.items():
                metadata = path.lstat()
                require(not base.is_link(metadata) and (metadata.st_dev, metadata.st_ino) == identity,
                        "gpg-runtime-closure")
            for path, lease in self.directories.items():
                metadata = path.lstat()
                require(not base.is_link(metadata) and (metadata.st_dev, metadata.st_ino) == lease.identity,
                        "gpg-runtime-closure")
            for row in self.config["files"]:
                lease = self.files[row["path"]]
                metadata = lease.path.lstat()
                data = lease.data(MAX_COMPONENT_BYTES)
                require(not base.is_link(metadata) and metadata.st_nlink == 1
                        and (metadata.st_dev, metadata.st_ino) == lease.identity
                        and len(data) == row["bytes"] and base.digest(data) == row["sha256"],
                        "gpg-binary-integrity" if row["path"] == "bin/gpg.exe" else "gpg-runtime-closure")
        except OSError as error:
            raise RecoveryError("gpg-runtime-closure") from error

    def run(self, args, home, **kwargs):
        self.verify()  # All reviewed files remain share-read locked through wait.
        try:
            return child_process([str(self.binary), *args], home, **kwargs)
        finally:
            self.verify()  # Results cannot be used after a closure/inventory change.

    def close(self):
        self.active = False
        for lease in [*self.files.values(), *self.directories.values()]:
            lease.close()
        self.files.clear()
        self.directories.clear()

    def __exit__(self, *_):
        self.close()


def package_bytes(fetch=None):
    try:
        if fetch is None:
            with urllib.request.urlopen(PACKAGE_URL, timeout=30) as response:
                require(response.geturl() == PACKAGE_URL, "gpg-package-integrity")
                data = response.read(PACKAGE_BYTES + 1)
        else:
            data = fetch(PACKAGE_URL, PACKAGE_BYTES + 1)
        require(type(data) is bytes and len(data) == PACKAGE_BYTES and base.digest(data) == PACKAGE_SHA256,
                "gpg-package-integrity")
        return data
    except RecoveryError:
        raise
    except Exception as error:
        raise RecoveryError("gpg-package-integrity") from error


def cabinet_inventory(data, config):
    require(len(data) == PACKAGE_BYTES and base.digest(data) == PACKAGE_SHA256, "gpg-package-integrity")
    require(data[:8] == b"MSCF\0\0\0\0" and struct.unpack_from("<I", data, 8)[0] == CABINET_BYTES
            and struct.unpack_from("<HHH", data, 26) == (1, 87, 0), "gpg-package-integrity")
    offset = struct.unpack_from("<I", data, 16)[0]
    rows = {}
    try:
        for _ in range(87):
            require(offset + 16 < CABINET_BYTES, "gpg-package-integrity")
            size, _, folder, _, _, attributes = struct.unpack_from("<IIHHHH", data, offset)
            offset += 16
            end = data.index(0, offset, min(offset + 4, CABINET_BYTES))
            name = data[offset:end].decode("ascii")
            offset = end + 1
            require(name not in rows and re.fullmatch(r"[0-9]{1,2}", name) and folder == 0
                    and 0 < size <= MAX_COMPONENT_BYTES and not attributes & 0x10,
                    "gpg-package-integrity")
            rows[name] = size
    except (ValueError, UnicodeError, struct.error) as error:
        raise RecoveryError("gpg-package-integrity") from error
    require(rows == {row["cabinetFileId"]: row["bytes"] for row in config["files"]}, "gpg-package-integrity")
    return rows


def provision_runtime(temp, repo, config, *, fetch=None):
    require(os.name == "nt", "gpg-runtime-closure")
    data = package_bytes(fetch)
    cabinet_inventory(data, config)
    stage = private_directory(temp / "issue13-gnupg-package", repo)
    package = stage / "runtime.wixlib"
    exclusive(package, data, PACKAGE_BYTES)
    expanded = private_directory(stage / "expanded", repo)
    extractor = Path("C:/Windows/System32/expand.exe")
    try:
        # The extractor is an OS dependency; its protected absolute path is fixed.
        for path in (extractor, *extractor.parents):
            require(not base.is_link(path.lstat()), "gpg-runtime-closure")
        # Windows may hardlink its OS extractor into WinSxS. This exception
        # is confined to this fixed OS dependency, never GnuPG runtime files.
        metadata = extractor.lstat()
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= MAX_COMPONENT_BYTES,
                "gpg-runtime-closure")
        with FileLease(package) as source:
            require(base.digest(source.data(PACKAGE_BYTES)) == PACKAGE_SHA256, "gpg-package-integrity")
            code, _, _ = child_process([str(extractor), "-F:*", str(package), str(expanded)], stage, timeout=30)
            require(code == 0, "gpg-process")
            require(base.digest(source.data(PACKAGE_BYTES)) == PACKAGE_SHA256, "gpg-package-integrity")
        require({entry.name for entry in expanded.iterdir()} == {str(i) for i in range(87)}, "gpg-runtime-closure")
        runtime = private_directory(temp / config["runtimeDirectory"], repo)
        for row in config["files"]:
            contents = base.bounded_file(expanded / row["cabinetFileId"], MAX_COMPONENT_BYTES)
            require(len(contents) == row["bytes"] and base.digest(contents) == row["sha256"], "gpg-runtime-closure")
            destination = runtime / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            exclusive(destination, contents, MAX_COMPONENT_BYTES)
        with RuntimeLease(runtime, config):
            pass
        return runtime
    except RecoveryError:
        raise
    except Exception as error:
        raise RecoveryError("gpg-runtime-closure") from error


def certificate_identity(output, now=None):
    try:
        return base.imported_identity(output, now=now)
    except Exception as error:
        require(len(output) <= base.MAX_MANIFEST, "public-key-identity")
        rows = [line.split(":") for line in output.decode("utf-8", "replace").splitlines()
                if line.startswith(("pub:", "sub:"))]
        if any(len(row) >= 2 and row[1] == "r" for row in rows):
            raise RecoveryError("public-key-revoked") from error
        current = int(time.time()) if now is None else now
        if any(len(row) >= 7 and (row[1] == "e" or (row[6].isdigit() and 0 < int(row[6]) <= current)) for row in rows):
            raise RecoveryError("public-key-expired") from error
        raise RecoveryError("public-key-identity") from error


def profile_directories(home):
    # GnuPG 2.5.22 common/homedir.c: Windows socket namespace uses the first
    # 80 SHA-1 bits of the lowercase slash-form home, encoded as z-base-32.
    # This is a namespace calculation only, never an integrity digest.
    canonical = str(home).replace("\\", "/").lower().encode("ascii")
    suffix = base64.b32encode(hashlib.sha1(canonical).digest()[:10]).decode("ascii")
    suffix = suffix.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "ybndrfg8ejkmcpqxot1uwisza345h769"))
    return {"AppData", "AppData/Local", "AppData/Roaming", "AppData/Local/gnupg",
            "AppData/Roaming/gnupg", "AppData/Local/gnupg/d." + suffix}


def public_home_inventory(home):
    # Windows creates a profile socket namespace even with --no-autostart.
    # Precreated default directories prevent generation of common.conf. No
    # files, sockets, configs, or secret material are permitted in that tree.
    metadata = home.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not base.is_link(metadata), "public-key-identity")
    directories = profile_directories(home) | {"private-keys-v1.d"}
    files = {"pubring.kbx", "pubring.kbx~", "pubring.kb_", "pubring.kbx.lock",
             "trustdb.gpg", "trustdb.gpg.lock", "random_seed", ".gpg-v21-migrated"}
    pending, count = [home], 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as inventory:
            for entry in inventory:
                count += 1
                require(count <= 24, "public-key-identity")
                path = Path(entry.path)
                metadata = path.lstat()
                require(not base.is_link(metadata), "public-key-identity")
                relative = path.relative_to(home).as_posix()
                if stat.S_ISDIR(metadata.st_mode):
                    require(relative in directories, "public-key-identity")
                    pending.append(path)
                else:
                    require(relative in files and stat.S_ISREG(metadata.st_mode)
                            and metadata.st_nlink == 1, "public-key-identity")
                    data = base.bounded_file(path, 2 * base.MIB)
                    require(not relative.endswith(".lock") or data == b"", "public-key-identity")


class RecoveryKeyring:
    def __init__(self, runtime, home, repo, armor):
        try:
            base.public_armor(armor)
        except Exception as error:
            raise RecoveryError("public-key-identity") from error
        require(base.digest(armor) == base.PUBLIC_KEY_SHA256, "public-key-pin")
        # A bounded ASCII home leaves room for the Windows socket namespace;
        # long or redirected paths stop before invoking GnuPG.
        require(home.is_absolute() and str(home).isascii() and len(str(home)) <= 48,
                "gpg-process")
        self.runtime, self.home = runtime, private_directory(home, repo)
        for relative in sorted(profile_directories(home), key=lambda name: (name.count("/"), name)):
            (home / relative).mkdir()
        self.home_identity = (home.stat().st_dev, home.stat().st_ino)
        self.prefix = ["--no-options", "--homedir", str(home), "--batch", "--no-tty",
                       "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve",
                       "--no-auto-key-import", "--auto-key-locate", "clear", "--pinentry-mode", "error"]
        version = self.run("--version").splitlines()[0]
        require(version == ("gpg (GnuPG) " + VERSION).encode("ascii"), "gpg-version")
        self.run("--import-options", "only-pubkeys", "--import", data=armor)
        listing = self.run("--with-colons", "--fixed-list-mode", "--with-fingerprint",
                           "--with-subkey-fingerprint", "--list-keys")
        self.identity = certificate_identity(listing)
        self.assert_public_only()
        self.tool = {"version": version.decode("ascii"), "sha256": BINARY_SHA256,
                     "bytes": runtime.binary.stat().st_size, "runtimeClosureSha256": CLOSURE_SHA256,
                     "runtimeFileCount": 87, "packageSha256": PACKAGE_SHA256}

    def check_home(self):
        metadata = self.home.lstat()
        require(not base.is_link(metadata) and (metadata.st_dev, metadata.st_ino) == self.home_identity,
                "public-key-identity")
        public_home_inventory(self.home)

    def result(self, *args, data=b"", limit=base.MAX_MANIFEST, timeout=30):
        self.check_home()
        try:
            result = self.runtime.run([*self.prefix, *args], self.home, data=data, limit=limit, timeout=timeout)
            self.check_home()
            return result
        except RecoveryError:
            raise
        except Exception as error:
            raise RecoveryError("gpg-process") from error

    def run(self, *args, data=b"", limit=base.MAX_MANIFEST, timeout=30):
        code, stdout, _ = self.result(*args, data=data, limit=limit, timeout=timeout)
        require(code == 0, "encryption-process" if "--encrypt" in args else "gpg-process")
        return stdout

    def assert_public_only(self):
        require(not self.run("--with-colons", "--list-secret-keys").strip(), "public-key-identity")
        try:
            public_home_inventory(self.home)
        except Exception as error:
            raise RecoveryError("public-key-identity") from error

    def encrypt(self, plaintext):
        require(len(plaintext) <= base.MAX_BUNDLE, "output-bound")
        self.assert_public_only()
        output = self.run("--trust-model", "always", "--recipient", base.RECIPIENT,
                          "--compress-algo", "none", "--set-filename", "", "--output", "-", "--encrypt",
                          data=plaintext, limit=base.MAX_CIPHERTEXT, timeout=90)
        validate_ciphertext(output)
        self.assert_public_only()
        return output


def validate_ciphertext(data):
    require(0 < len(data) <= base.MAX_CIPHERTEXT, "output-bound")
    try:
        # Only the reviewed runtime's v3 ECDH PKESK + v1 AES-256/OCB form is
        # accepted. Validate the Curve25519 MPI and wrapped-key length too;
        # packet tags alone cannot establish a complete session-key packet.
        entries = base.packets(data, {1, 20}, partial=True)
        require(len(entries) == 2 and entries[0][0] == 1 and entries[1][0] == 20,
                "encryption-process")
        session, encrypted = entries[0][1], entries[1][1]
        require(len(session) == 94 and session[0] == 3
                and session[1:9].hex().upper() == base.SUBKEY[-16:] and session[9] == 18
                and session[10:13] == b"\x01\x07\x40"
                and session[45] == 48
                and len(encrypted) >= 51 and encrypted[:4] == b"\x01\x09\x02\x10", "encryption-process")
    except base.TransportError as error:
        raise RecoveryError("encryption-process") from error
    return entries


def synthetic_preflight(ring):
    encrypted = ring.encrypt(SMOKE)
    require(len(encrypted) <= 8192, "encryption-preflight")
    code, plaintext, stderr = ring.result("--status-fd", "2", "--output", "-", "--decrypt",
                                          data=encrypted, limit=8192)
    statuses = [line for line in stderr.splitlines() if line.startswith(b"[GNUPG:] ")]
    require(code == 2 and plaintext == b""
            and (b"[GNUPG:] NO_SECKEY " + base.SUBKEY[-16:].encode("ascii")) in statuses
            and b"[GNUPG:] DECRYPTION_FAILED" in statuses, "encryption-preflight")
    ring.assert_public_only()
    return {"status": "PASS", "syntheticPayloadSha256": base.digest(SMOKE),
            "ciphertextSha256": base.digest(encrypted), "ciphertextBytes": len(encrypted),
            "recipientSelector": base.RECIPIENT, "secretKeyCount": 0,
            "publicOnlyDecryptionRejected": True, "plaintextOutputBytes": 0}


def context(environment, phase=None):
    values = {key: environment.get(key, "") for key in (
        "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_JOB")}
    require(values["GITHUB_REPOSITORY"] == base.REPOSITORY and values["GITHUB_REF"] == BRANCH
            and values["GITHUB_EVENT_NAME"] == "push" and values["GITHUB_RUN_ATTEMPT"] == "1"
            and values["GITHUB_SHA"] != PARENT, "unexpected-transport-category")
    expected_phase = JOB_PHASES.get(values["GITHUB_JOB"])
    require(values["GITHUB_JOB"] in {*JOB_PHASES, "windows-gnupg-preflight"}
            and (phase is None or phase == expected_phase), "unexpected-transport-category")
    transaction = base.transaction_id(values["GITHUB_SHA"], values["GITHUB_RUN_ID"], "windows")
    require(transaction != OLD_TRANSACTION, "unexpected-transport-category")
    return {"commit": values["GITHUB_SHA"], "runId": values["GITHUB_RUN_ID"], "attempt": 1,
            "job": values["GITHUB_JOB"], "platform": "windows", "phase": expected_phase,
            "transaction": transaction}


def source_identity(repo, expected_commit):
    commit = base.git_bytes(repo, "rev-parse", "HEAD").decode("ascii").strip()
    tree = base.git_bytes(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    parent = base.git_bytes(repo, "rev-parse", "HEAD^").decode("ascii").strip()
    require(commit == expected_commit and parent == PARENT and re.fullmatch(r"[0-9a-f]{40}", tree),
            "unexpected-transport-category")
    changes = base.git_bytes(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").decode("ascii").splitlines()
    require(sorted(changes) == sorted(RECOVERY_PATHS), "unexpected-transport-category")
    require(base.git_bytes(repo, "rev-parse", "HEAD^^").decode("ascii").strip() == base.CAPTURE_COMMIT,
            "unexpected-transport-category")
    rows = []
    for name in (*base.SOURCE_PATHS, *RECOVERY_PATHS):
        committed = base.git_bytes(repo, "cat-file", "blob", "HEAD:" + name)
        current = base.bounded_file(repo / name, 2 * base.MIB)
        require(current in (committed, committed.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")),
                "unexpected-transport-category")
        if name in base.SOURCE_PATHS:
            require(committed == base.git_bytes(repo, "cat-file", "blob", PARENT + ":" + name),
                    "unexpected-transport-category")
        if name in base.CAPTURE_SOURCES:
            require(base.digest(committed) == base.CAPTURE_SOURCES[name], "unexpected-transport-category")
        rows.append({"source": name, "gitBlobSha256": base.digest(committed),
                     "checkoutSha256": base.digest(current), "checkoutBytes": len(current)})
    return {"commit": commit, "tree": tree, "parent": parent,
            "captureCommit": base.CAPTURE_COMMIT, "sources": rows}


def profile_context(environment, phase=None, *, source_profile="legacy"):
    if source_profile == "legacy":
        return context(environment, phase)
    require(source_profile == base.V2_PROFILE, "unexpected-transport-category")
    try:
        return base.v2_context(environment, phase, platform_name="windows")
    except base.TransportError:
        raise RecoveryError("unexpected-transport-category") from None


def profile_source_identity(repo, expected_commit, *, source_profile="legacy"):
    if source_profile == "legacy":
        return source_identity(repo, expected_commit)
    require(source_profile == base.V2_PROFILE, "unexpected-transport-category")
    try:
        return base.source_identity_v2(repo, expected_commit)
    except base.TransportError:
        raise RecoveryError("unexpected-transport-category") from None


def recipient_certificate(repo):
    armor = base.git_bytes(repo, "cat-file", "blob", "HEAD:" + base.PUBLIC_KEY_PATH, limit=base.MAX_MANIFEST)
    require(base.digest(armor) == base.PUBLIC_KEY_SHA256, "public-key-pin")
    return armor


def write_github_preflight_output(environment, transaction):
    require(re.fullmatch(r"[0-9a-f]{32}", transaction) is not None, "encryption-preflight")
    path = Path(environment.get("GITHUB_OUTPUT", ""))
    metadata = path.lstat()
    require(path.is_absolute() and not base.is_link(metadata) and stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1 and metadata.st_size <= base.MAX_MANIFEST, "encryption-preflight")
    with path.open("a", encoding="ascii", newline="\n") as output:
        output.write("transaction=" + transaction + "\npreflight=PASS\n")


def preflight(repo, environment, *, fetch=None, source_profile="legacy"):
    availability, approved_indices = inspect_approved_locations()
    print(availability)  # Fixed enum only, never the inspected paths or output.
    require(availability != "GPG_RUNTIME_INVALID", "gpg-binary-integrity")
    require(os.name == "nt", "gpg-runtime-closure")
    live = profile_context(environment, source_profile=source_profile)
    identity = profile_source_identity(repo, live["commit"], source_profile=source_profile)
    config = configuration(repo)
    temp = Path(environment.get("RUNNER_TEMP", ""))
    # The reviewed recovery configuration explicitly selects the full package.
    # Existing-location observations do not authorize those binaries or trigger
    # a PATH fallback. Each separate Windows job provisions and checks its host.
    runtime_root = provision_runtime(temp, repo, config, fetch=fetch)
    with RuntimeLease(runtime_root, config) as runtime:
        ring = RecoveryKeyring(runtime, temp / "i13-pf-keyring", repo, recipient_certificate(repo))
        smoke = synthetic_preflight(ring)
        proof = {"schema": "Issue13WindowsDiagnosticPreflight", "version": 1, "authority": MARKER,
                 "context": live, "candidate": identity, "availability": availability,
                 "approvedLocationIndices": approved_indices, "runtimeSource": "pinned-official-cab",
                 "tool": ring.tool, "recipient": ring.identity, "publicKeySha256": base.PUBLIC_KEY_SHA256,
                 "synthetic": smoke}
    directory = private_directory(temp / "issue13-gnupg-preflight", repo)
    exclusive(directory / "preflight.json", base.json_bytes(proof), base.MAX_MANIFEST)
    write_github_preflight_output(environment, live["transaction"])
    return proof


def same_json(left, right):
    # JSON scalar types are part of the diagnostic schema: True must not equal
    # integer 1, nor a floating-point count equal an integer count.
    try:
        return base.json_bytes(left) == base.json_bytes(right)
    except (TypeError, ValueError, OverflowError):
        return False


def validated_preflight(temp, live, identity):
    proof = read_json(base.bounded_file(temp / "issue13-gnupg-preflight/preflight.json", base.MAX_MANIFEST))
    expected_keys = {"schema", "version", "authority", "context", "candidate", "availability",
                     "approvedLocationIndices", "runtimeSource", "tool", "recipient", "publicKeySha256", "synthetic"}
    require(type(proof) is dict and proof.keys() == expected_keys, "encryption-preflight")
    require(proof["schema"] == "Issue13WindowsDiagnosticPreflight"
            and type(proof["version"]) is int and proof["version"] == 1 and proof["authority"] == MARKER
            and same_json(proof["context"], live) and same_json(proof["candidate"], identity)
            and proof["runtimeSource"] == "pinned-official-cab"
            and proof["publicKeySha256"] == base.PUBLIC_KEY_SHA256, "encryption-preflight")
    require(same_json(proof["tool"], {"version": "gpg (GnuPG) " + VERSION, "sha256": BINARY_SHA256,
            "bytes": BINARY_BYTES, "runtimeClosureSha256": CLOSURE_SHA256,
            "runtimeFileCount": 87, "packageSha256": PACKAGE_SHA256}), "encryption-preflight")
    require(same_json(proof["recipient"], {"primaryFingerprint": base.PRIMARY, "encryptionSubkeyFingerprint": base.SUBKEY,
            "recipientSelector": base.RECIPIENT, "curve": "cv25519", "encryptionCapable": True,
            "secretKeyCount": 0, "publicSubkeyCount": 2}), "encryption-preflight")
    indices = proof["approvedLocationIndices"]
    require(type(indices) is list and len(indices) <= 3 and all(type(i) is int and 0 <= i < 3 for i in indices)
            and indices == sorted(set(indices)) and proof["availability"] ==
            ("GPG_APPROVED_RUNTIME_AVAILABLE" if indices else "GPG_NOT_AVAILABLE"), "encryption-preflight")
    smoke = proof["synthetic"]
    require(type(smoke) is dict and smoke.keys() == {"status", "syntheticPayloadSha256", "ciphertextSha256",
            "ciphertextBytes", "recipientSelector", "secretKeyCount", "publicOnlyDecryptionRejected", "plaintextOutputBytes"},
            "encryption-preflight")
    require(smoke["status"] == "PASS" and smoke["syntheticPayloadSha256"] == base.digest(SMOKE)
            and type(smoke["ciphertextSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", smoke["ciphertextSha256"])
            and type(smoke["ciphertextBytes"]) is int and 0 < smoke["ciphertextBytes"] <= 8192
            and smoke["recipientSelector"] == base.RECIPIENT and type(smoke["secretKeyCount"]) is int
            and smoke["secretKeyCount"] == 0 and smoke["publicOnlyDecryptionRejected"] is True
            and type(smoke["plaintextOutputBytes"]) is int and smoke["plaintextOutputBytes"] == 0, "encryption-preflight")
    return proof  # Export-only scheduling evidence; never read by the verifier.


def export_capture(repo, environment, phase, transaction, outcome, *, source_profile="legacy"):
    live = profile_context(environment, phase, source_profile=source_profile)
    require(transaction == live["transaction"] and outcome in ("success", "failure", "cancelled"),
            "unexpected-transport-category")
    identity = profile_source_identity(repo, live["commit"], source_profile=source_profile)
    config = configuration(repo)
    temp = Path(environment.get("RUNNER_TEMP", ""))
    proof = validated_preflight(temp, live, identity)
    ci, _ = base.load_capture_modules(repo)
    leaf = "issue13-producer" if phase == "producer" else "issue13-replay"
    summary, files = base.snapshot_capture(ci, capture, temp / leaf, repo, live, candidate=identity)
    private_manifest = {"schema": "Issue13EncryptedAcquisitionBundle", "version": 1, "authority": MARKER,
                        "context": live, "candidate": identity, "ordinaryStepOutcome": outcome,
                        "primaryFingerprint": base.PRIMARY, "encryptionSubkeyFingerprint": base.SUBKEY,
                        "files": [{"name": name, "sha256": base.digest(data), "bytes": len(data)}
                                  for name, data in sorted(files.items())]}
    plaintext = base.private_tar(files, private_manifest)  # Bounded memory only.
    # Revalidate the entire installation after the ordinary command; preflight
    # PASS alone never authorizes an export or proves the current runtime bytes.
    with RuntimeLease(temp / config["runtimeDirectory"], config) as runtime:
        ring = RecoveryKeyring(runtime, temp / ("i13-producer-keyring" if phase == "producer" else "i13-replay-keyring"), repo, recipient_certificate(repo))
        encrypted = ring.encrypt(plaintext)
        public = {"schema": "Issue13WindowsRecoveryTransport", "version": 1, "authority": MARKER,
                  "context": live, "candidate": identity, "ordinaryStepOutcome": outcome,
                  "recipient": ring.identity, "publicKeySha256": base.PUBLIC_KEY_SHA256,
                  "tool": ring.tool, "encryption": "OpenPGP-cv25519",
                  "ciphertextSha256": base.digest(encrypted), "ciphertextBytes": len(encrypted),
                  "publicSha256": base.digest(files["public.json"]), "publicBytes": len(files["public.json"]),
                  "privateFileCount": len(files), "privateBytes": sum(map(len, files.values())),
                  "plaintextBundleSha256": base.digest(plaintext), "plaintextBundleBytes": len(plaintext),
                  "preflightSyntheticDigest": proof["synthetic"]["ciphertextSha256"], "retentionDays": 1}
    destination = base.Destination(temp / (leaf + "-export"), repo, capture)
    destination.write("issue13-private.tar.gz.gpg", encrypted, base.MAX_CIPHERTEXT)
    destination.write("public.json", capture.validate_public(summary), capture.MAX_PUBLIC_BYTES)
    destination.write("transport.json", base.json_bytes(public), base.MAX_MANIFEST)
    return public


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise RecoveryError("unexpected-transport-category")


def main(argv=None):
    parser = PrivateArgumentParser(prog="issue13-windows-transport", description=MARKER, allow_abbrev=False)
    parser.add_argument("mode", choices=("preflight", "export"))
    parser.add_argument("--source-profile", choices=("legacy", base.V2_PROFILE), default="legacy")
    parser.add_argument("--phase", choices=("producer", "fresh-replay"))
    parser.add_argument("--transaction")
    parser.add_argument("--ordinary-outcome", choices=("success", "failure", "cancelled"))
    mode = "preflight"
    try:
        args = parser.parse_args(argv)
        mode = args.mode
        repo = Path(__file__).resolve().parents[3]
        if mode == "preflight":
            preflight(repo, os.environ, source_profile=args.source_profile)
        else:
            export_capture(repo, os.environ, args.phase, args.transaction, args.ordinary_outcome,
                           source_profile=args.source_profile)
    except Exception as error:
        print(MARKER + ": " + category(error), file=sys.stderr)
        if mode == "preflight":
            print("STOP WINDOWS ACQUISITION", file=sys.stderr)
        return 1
    print(MARKER + (": preflight PASS" if mode == "preflight" else ": transport step completed"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
