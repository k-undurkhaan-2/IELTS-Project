#!/usr/bin/env python3
"""Issue 79 bounded runtime measurements; application code runs only in containers.

This control program never imports candidate modules. Both jobs independently
acquire Git objects and registry metadata. A successful producer report is not
an acceptance input: the verifier measures the transferred immutable image.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fnmatch
import gzip
import hashlib
import http.client
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
AUTH = json.loads((HERE / "authority.json").read_bytes())
REPO = "k-undurkhaan-2/IELTS-Project"
VERSION = AUTH["artifact"]
EXAM_ID = "listening-p1-very-007-notes-on-a-part-time-society-f0f5f9b6"
EXAM_ROUTE_ID = "p1-very-007"
EXAM_PATH = "P1/次高频/7. P1 Notes on A Part time Society/Notes on A Part time Society.html"
MANIFEST_PATH = f"developer/tests/ci/public-listening-frontend/{VERSION}.manifest.json"
STAGE_PATH = "developer/tests/ci/stage_public_listening_frontend.py"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(p: Path) -> str:
    with p.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encode(value) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def safe_name(name: str) -> str:
    value = name.removeprefix("./").rstrip("/")
    assert value and not value.startswith("/") and "\\" not in value
    assert all(p not in {"", ".", ".."} for p in value.split("/"))
    assert "\x00" not in value
    return value


def get_bytes(url: str, headers: dict | None = None) -> bytes:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def public_api(endpoint: str):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "issue79-runtime-verifier"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    return json.loads(get_bytes("https://api.github.com/" + endpoint, headers))


class Control:
    def __init__(self, role: str, producer: Path | None):
        assert role in {"producer", "verifier"}
        self.role = role
        self.producer = producer
        self.prefix = f"i79-runtime-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}-{role}"
        self.root = Path(os.environ["RUNNER_TEMP"]) / self.prefix
        self.root.mkdir(exist_ok=False)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.commands = []
        self.resources = {"containers": [], "networks": [], "volumes": [], "builders": [], "images": [], "processes": []}
        self.proxy = None
        self.proxy_logs = []
        self.results = {row: {"status": "NOT_RUN"} for row in AUTH["expected_rows"]}
        self.env = {k: v for k, v in os.environ.items() if k in {
            "PATH", "LANG", "LC_ALL", "TMPDIR", "LD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR"
        }}
        self.env.update({"CI": "1", "PLAYWRIGHT_BROWSERS_PATH": str(self.root / "browsers")})
        self.number = 0
        self.failed = None
        self.initial_images = set()
        self.sentinel = (self.prefix + "-SYNTHETIC-ONLY").encode()
        self.write("transaction.json", {"transaction": AUTH["transaction"], "role": role,
            "run": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "job": os.environ["GITHUB_JOB"], "control_commit": os.environ["I79_CONTROL_COMMIT"],
            "control_sources": {p.name: file_digest(p) for p in HERE.iterdir() if p.is_file()},
            "expected_rows": AUTH["expected_rows"], "started_at": time.time()})
        assert shutil.disk_usage(self.root).free >= 12 * 1024 ** 3, "Insufficient disposable disk budget"

    def write(self, name, value):
        (self.evidence / name).write_bytes(encode(value))

    def run(self, argv, *, cwd=None, env=None, stdin=None, timeout=180, allowed=(0,)):
        argv = [str(a) for a in argv]
        self.number += 1
        label = f"command-{self.number:04}"
        started = time.time()
        with (self.evidence / (label + ".stdout")).open("wb") as out, (self.evidence / (label + ".stderr")).open("wb") as err:
            try:
                p = subprocess.run(argv, cwd=cwd, env=env or self.env, stdin=stdin,
                    stdout=out, stderr=err, timeout=timeout, check=False)
                status = p.returncode
            except subprocess.TimeoutExpired:
                status = "TIMEOUT"
        record = {"id": label, "argv": argv, "cwd": str(cwd or Path.cwd()),
            "exit": status, "duration_seconds": time.time() - started,
            "stdout_sha256": file_digest(self.evidence / (label + ".stdout")),
            "stderr_sha256": file_digest(self.evidence / (label + ".stderr"))}
        self.commands.append(record)
        self.write("commands.json", self.commands)
        if status not in allowed:
            raise RuntimeError(f"{label}: exit {status}: {argv[:6]}")
        return (self.evidence / (label + ".stdout")).read_bytes()

    def docker(self, *args, **kwargs):
        return self.run([self.docker_path, "--context", "default", *args], **kwargs)

    def record(self, row, **facts):
        assert self.results[row]["status"] == "NOT_RUN"
        self.results[row] = {"status": "PASS", **facts}
        self.write("rows.json", self.results)

    def acquire_registry(self):
        self.registry = {}
        for name, identity in AUTH["images"].items():
            token = json.loads(get_bytes("https://auth.docker.io/token?" + urllib.parse.urlencode({
                "service": "registry.docker.io", "scope": f"repository:{identity['repo']}:pull"
            })))["token"]
            headers = {"Authorization": "Bearer " + token,
                "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
            base = f"https://registry-1.docker.io/v2/{identity['repo']}"
            raw = get_bytes(f"{base}/manifests/sha256:{identity['manifest']}", headers)
            assert digest(raw) == identity["manifest"]
            (self.evidence / f"registry-{name}-manifest.json").write_bytes(raw)
            manifest = json.loads(raw)
            assert manifest["config"]["digest"] == "sha256:" + identity["config"]
            raw = get_bytes(f"{base}/blobs/{manifest['config']['digest']}", headers)
            assert digest(raw) == identity["config"] and len(raw) == manifest["config"]["size"]
            config = json.loads(raw)
            assert (config["os"], config["architecture"]) == ("linux", "amd64")
            (self.evidence / f"registry-{name}-config.json").write_bytes(raw)
            self.registry[name] = {"manifest": manifest, "config": config}

    def admit(self):
        authority = public_api(f"repos/{REPO}/issues/comments/7167678279")
        assert digest(authority["body"].encode()) == "f6daf93e85cb8f357153f018c8fba729e36780e2b7e6782e1d4cbe26fc2a2b19"
        refs = {}
        for ref, expected in [("ci/master", AUTH["ci"]), ("security/server-security", AUTH["security"]), ("ui/master", AUTH["ui"])]:
            refs[ref] = public_api(f"repos/{REPO}/git/ref/heads/{ref}")
            assert refs[ref]["object"]["sha"] == expected
        self.write("immediate-authority-preflight.json", {"authority": authority, "refs": refs})
        assert sys.version_info[:3] == (3, 12, 10)
        assert platform.system() == "Linux" and platform.machine() == "x86_64"
        assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
        assert os.environ["ImageOS"] == "ubuntu22"
        self.node = str(Path(shutil.which("node")).resolve())
        self.git_path = str(Path(shutil.which("git")).resolve())
        self.docker_path = str(Path(shutil.which("docker")).resolve())
        self.openssl_path = str(Path(shutil.which("openssl")).resolve())
        assert self.run([self.node, "--version"]).strip() == b"v24.20.0"
        assert "/hostedtoolcache/" in self.node and "/hostedtoolcache/" in str(Path(sys.executable).resolve())
        image_version = os.environ["ImageVersion"]
        assert re.fullmatch(r"\d{8}\.\d+\.\d+", image_version)
        inventory_url = "https://raw.githubusercontent.com/actions/runner-images/" + \
            "ubuntu22/" + image_version.rsplit(".", 1)[0] + "/images/ubuntu/Ubuntu2204-Readme.md"
        inventory = get_bytes(inventory_url)
        (self.evidence / "official-runner-inventory.md").write_bytes(inventory)
        openssl_version = self.run([self.openssl_path, "version"]).decode().strip()
        openssl_match = re.search(r"OpenSSL (\d+\.\d+\.\d+)", openssl_version)
        assert openssl_match and openssl_match[1].encode() in inventory
        version = json.loads(self.docker("version", "--format", "{{json .}}"))
        assert version["Server"]["Os"] == "linux" and version["Server"]["Arch"] == "amd64"
        assert version["Client"]["Version"].encode() in inventory and version["Server"]["Version"].encode() in inventory
        buildx_version = self.docker("buildx", "version").decode().strip()
        match = re.search(r" v?(\d+\.\d+\.\d+)", buildx_version)
        assert match and match[1].encode() in inventory
        info = json.loads(self.docker("info", "--format", "{{json .}}"))
        buildx_path = next(x["Path"] for x in info["ClientInfo"]["Plugins"] if x["Name"] == "buildx")
        paths = [str(Path(sys.executable).resolve()), self.node, self.git_path, self.docker_path,
            buildx_path, shutil.which("dockerd"), shutil.which("ldd"), self.openssl_path]
        binaries = []
        for p in paths:
            assert p and Path(p).is_file()
            binaries.append({"path": p, "sha256": file_digest(Path(p)), "bytes": Path(p).stat().st_size})
        self.initial_images = set(self.docker("image", "ls", "--no-trunc", "--quiet").decode().splitlines())
        self.write("preexisting-resources.json", {
            "containers": self.docker("ps", "--all", "--no-trunc", "--format", "json").decode(),
            "networks": self.docker("network", "ls", "--no-trunc", "--format", "json").decode(),
            "volumes": self.docker("volume", "ls", "--format", "json").decode(),
            "images": sorted(self.initial_images)})
        self.write("host-admission.json", {"platform": platform.platform(), "runner_image": image_version,
            "provenance": inventory_url, "inventory_sha256": digest(inventory), "binaries": binaries,
            "docker_version": version, "docker_info": info, "buildx_version": buildx_version,
            "openssl_version": openssl_version,
            "context": json.loads(self.docker("context", "inspect", "default")),
            "control_runtime_setup": {"python": "3.12.10", "node": "24.20.0",
                "python_action": "5fda3b95a4ea91299a34e894583c3862153e4b97",
                "node_action": "820762786026740c76f36085b0efc47a31fe5020"}})
        self.acquire_registry()
        self.objects = self.root / "objects.git"
        self.run([self.git_path, "init", "--bare", self.objects])
        self.run([self.git_path, f"--git-dir={self.objects}", "fetch", "--no-tags", "--depth=1",
            f"https://github.com/{REPO}.git", AUTH["ci"], AUTH["security"], AUTH["ui"]])
        self.install_browser()
        self.builder = self.prefix + "-builder"
        self.resources["builders"].append(self.builder)
        self.write("resources.json", self.resources)
        buildkit = self.image_ref("buildkit")
        self.docker("buildx", "create", "--name", self.builder, "--driver", "docker-container",
            "--driver-opt", "image=" + buildkit, "--driver-opt", "memory=4g",
            "--driver-opt", "cpu-period=100000", "--driver-opt", "cpu-quota=200000", "--bootstrap", timeout=300)
        builder_info = self.docker("buildx", "inspect", "--builder", self.builder, "--bootstrap").decode()
        assert "v0.35.1" in builder_info
        builder_container = "buildx_buildkit_" + self.builder + "0"
        inspected = json.loads(self.docker("inspect", builder_container))[0]
        assert inspected["Image"] == "sha256:" + AUTH["images"]["buildkit"]["config"]
        actual = self.docker("exec", builder_container, "buildkitd", "--version").decode()
        assert "v0.35.1" in actual and "412cc86ad3c4252b82e929f9b1b1ad167376ded8" in actual
        binary = self.evidence / "buildkitd"
        self.docker("cp", builder_container + ":/usr/bin/buildkitd", binary)
        self.write("builder-admission.json", {"inspect": inspected, "version": actual,
            "binary_sha256": file_digest(binary), "builder": builder_info})
        binary.unlink()  # Retain the hash; the admitted image supplies the binary.
        self.run([sys.executable, "-I", HERE / "runtime.py", "admission-check", self.evidence])

    def git(self, *args):
        return self.run([self.git_path, f"--git-dir={self.objects}", *args])

    def blob(self, commit, relative):
        return self.git("show", f"{commit}:{relative}")

    def image_ref(self, name):
        item = AUTH["images"][name]
        return f"docker.io/{item['repo']}@sha256:{item['manifest']}"

    def install_browser(self):
        lock_raw = self.blob(AUTH["ci"], "developer/package-lock.json")
        assert digest(lock_raw) == AUTH["browser"]["lock_sha256"]
        lock = json.loads(lock_raw)
        self.tools = self.root / "browser-tools"
        installed = []
        for name in ["@playwright/test", "playwright", "playwright-core"]:
            metadata = lock["packages"]["node_modules/" + name]
            assert metadata["version"] == AUTH["browser"]["version"]
            assert metadata["resolved"].startswith("https://registry.npmjs.org/")
            archive = get_bytes(metadata["resolved"])
            algorithm, expected = metadata["integrity"].split("-", 1)
            assert algorithm == "sha512" and base64.b64encode(hashlib.sha512(archive).digest()).decode() == expected
            destination = self.tools / "node_modules" / name
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                for member in tar:
                    if member.isdir():
                        continue
                    assert member.isfile() and member.name.startswith("package/")
                    relative = safe_name(member.name.removeprefix("package/"))
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(member).read())
                    target.chmod(member.mode & 0o777)
            installed.append({"package": name, "version": metadata["version"], "url": metadata["resolved"],
                "integrity": metadata["integrity"], "archive_sha256": digest(archive),
                "files": self.inventory(destination)})
        browsers_json = self.tools / "node_modules/playwright-core/browsers.json"
        official = get_bytes("https://raw.githubusercontent.com/microsoft/playwright/" +
            AUTH["browser"]["source_commit"] + "/packages/playwright-core/browsers.json")
        assert browsers_json.read_bytes() == official
        for entry in json.loads(official)["browsers"]:
            if entry["name"] in {"chromium", "chromium-headless-shell"}:
                assert entry["revision"] == "1194" and entry["browserVersion"] == "141.0.7390.37"
        self.run([self.node, self.tools / "node_modules/playwright/cli.js", "install", "chromium"], timeout=600)
        executables = list((self.root / "browsers").glob("chromium*/chrome-linux*/chrome")) + \
            list((self.root / "browsers").glob("chromium_headless_shell*/chrome-linux*/headless_shell"))
        assert len(executables) == 2
        for p in executables:
            assert "141.0.7390.37" in self.run([p, "--version"]).decode()
            assert b"not found" not in self.run(["ldd", p])
        dependencies = {}
        for executable in [Path(sys.executable).resolve(), Path(self.node), Path(self.openssl_path), *executables]:
            listing = self.run(["ldd", executable]).decode()
            assert "not found" not in listing
            for candidate in re.findall(r"(?:=>\s+)?(/[^\s()]+)", listing):
                p = Path(candidate).resolve(strict=True)
                dependencies[str(p)] = {"bytes": p.stat().st_size, "sha256": file_digest(p)}
        self.write("browser-admission.json", {"vendor_source": AUTH["browser"]["source_commit"],
            "packages": installed, "browser_files": self.inventory(self.root / "browsers"),
            "dynamic_dependency_closure": dependencies,
            "system_dependency_provenance": "Official GitHub Ubuntu runner image recorded in host-admission.json",
            "executables": [{"path": str(p), "sha256": file_digest(p)} for p in executables],
            "non_applicable_optional_package": "fsevents is macOS-only; this host is Linux/amd64"})
        sandbox_probe = """
const {chromium} = require(process.argv[1]);
(async () => {
  const browser = await chromium.launch({headless: true, chromiumSandbox: true});
  try {
    const page = await browser.newPage();
    await page.goto('about:blank');
    console.log(JSON.stringify({version: browser.version(), chromium_sandbox: true, candidate_executed: false}));
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
"""
        probe = json.loads(self.run([self.node, "-e", sandbox_probe, self.tools / "node_modules/playwright"], timeout=60))
        assert probe == {"version": "141.0.7390.37", "chromium_sandbox": True, "candidate_executed": False}
        self.write("browser-sandbox-admission.json", probe)

    def inventory(self, root):
        result = []
        for p in sorted(root.rglob("*")):
            if p.is_dir() and not p.is_symlink():
                continue
            assert not p.is_symlink() and p.is_file(), str(p)
            result.append({"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size, "sha256": file_digest(p)})
        return result

    def acquire_candidate(self):
        signatures = {}
        for name in ["ci", "security", "ui"]:
            obj = public_api(f"repos/{REPO}/commits/{AUTH[name]}")
            assert obj["sha"] == AUTH[name] and obj["commit"]["verification"]["verified"]
            assert obj["commit"]["verification"]["reason"] == "valid"
            signatures[name] = obj
        self.write("source-signatures.json", signatures)
        raw = self.git("ls-tree", "-r", "-z", AUTH["security"])
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        source_inventory = []
        source_map = {x["path"]: x for x in AUTH["source_map"]["ui_delta"]}
        assert len(source_map) == 18
        seen = set()
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            descriptor, relative = entry.split(b"\t", 1)
            mode, kind, blob = descriptor.decode().split()
            name = safe_name(relative.decode())
            assert kind == "blob" and mode in {"100644", "100755"}
            if name in source_map:
                accepted = source_map[name]
                assert blob == accepted["security_blob"] and mode == accepted["mode"]
                assert self.git("rev-parse", AUTH["ui"] + ":" + name).decode().strip() == accepted["accepted_ui_blob"]
                blob = accepted["accepted_ui_blob"]
                seen.add(name)
            data = self.git("cat-file", "blob", blob)
            assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == blob
            out = self.candidate / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            out.chmod(0o755 if mode == "100755" else 0o644)
            source_inventory.append({"path": name, "mode": mode, "git_blob": blob,
                "bytes": len(data), "sha256": digest(data)})
        assert seen == set(source_map)
        self.write("candidate-inventory.json", source_inventory)
        self.ci = self.root / "accepted-ci"
        self.run([self.git_path, "init", self.ci])
        self.run([self.git_path, "-C", self.ci, "fetch", "--depth=1", "--no-tags",
            f"https://github.com/{REPO}.git", AUTH["ci"]])
        self.run([self.git_path, "-C", self.ci, "checkout", "--detach", AUTH["ci"]])
        assert file_digest(self.ci / STAGE_PATH) == AUTH["stage_helper_sha256"]
        manifest_raw = (self.ci / MANIFEST_PATH).read_bytes()
        assert len(manifest_raw) == 12153 and digest(manifest_raw) == AUTH["manifest_sha256"]
        self.manifest = json.loads(manifest_raw)
        for record in self.manifest["approved_entries"] + self.manifest["generated_dependencies"]:
            raw = self.blob(AUTH["ui"], record["source_path"])
            assert len(raw) == record["length"] and digest(raw) == record["sha256"]
            assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == record["git_blob"]
        stages = [self.root / "stage-1", self.root / "stage-2"]
        for stage in stages:
            self.run([sys.executable, "-I", self.ci / STAGE_PATH, "--git", self.git_path,
                "stage", "--output-root", stage], timeout=240)
            self.verify_stage(stage, manifest_raw)
        assert self.inventory(stages[0]) == self.inventory(stages[1])
        self.stage = stages[0]
        self.record("A", manifest_sha256=digest(manifest_raw), payload_files=26,
            payload_bytes=14533213, stage_files=28, logical_sha256=AUTH["stage_sha256"], independent_staging_runs=2)
        for record in self.manifest["generated_dependencies"]:
            p = self.candidate / record["source_path"]
            assert file_digest(p) == record["sha256"] and p.stat().st_size == record["length"]
        generated_text = (self.candidate / "assets/generated/listening-exams/manifest.js").read_text()
        encoded_manifest = generated_text.split("global.__LISTENING_EXAM_MANIFEST__ = ", 1)[1]
        exams, end = json.JSONDecoder().raw_decode(encoded_manifest)
        assert encoded_manifest[end:].strip() == ';\n})(typeof window !== "undefined" ? window : globalThis);'
        matching = []
        for key, entry in exams.items():
            canonical = str(entry.get("examId") or entry.get("dataKey") or key)
            match = re.match(r"^listening-(p[1-4])-(very|high|medium|low)-(\d{1,4})(?:-|$)", canonical, re.I)
            if match and f"{match[1].lower()}-{match[2].lower()}-{match[3].zfill(3)}" == EXAM_ROUTE_ID:
                matching.append(canonical)
        assert matching == [EXAM_ID]
        assert exams[EXAM_ID]["path"].rstrip("/") + "/" + exams[EXAM_ID]["filename"] == EXAM_PATH
        self.write("exam-route-authority.json", {"canonical_exam_id": EXAM_ID, "public_route_id": EXAM_ROUTE_ID,
            "unique_manifest_mapping": True, "manifest_sha256": digest(generated_text.encode())})
        self.source_inventory = source_inventory

    def verify_stage(self, stage, manifest_raw):
        expected = {f"{VERSION}/manifest.json": (len(manifest_raw), digest(manifest_raw)),
            "active.json": (628, AUTH["active_sha256"])}
        payload = []
        for r in self.manifest["approved_entries"]:
            if r["included_in_runtime"]:
                payload.append((r["payload_path"], r))
        for r in self.manifest["generated_dependencies"]:
            if r["artifact_path"] is not None:
                payload.append((r["artifact_path"], r))
        assert len(payload) == 26 and sum(r["length"] for _, r in payload) == 14533213
        for p, r in payload:
            expected[f"{VERSION}/payload/{p}"] = (r["length"], r["sha256"])
        actual = self.inventory(stage)
        assert {r["path"]: (r["bytes"], r["sha256"]) for r in actual} == expected
        logical_records = [{"path": r["path"], "mode": "100644", "length": r["bytes"],
            "sha256": r["sha256"]} for r in actual]
        logical = json.dumps(logical_records, ensure_ascii=False, separators=(",", ":")).encode()
        assert digest(logical) == AUTH["stage_sha256"]
        self.write(stage.name + "-inventory.json", actual)
        report = json.loads(self.run([sys.executable, "-I", self.ci / STAGE_PATH, "verify", "--output-root", stage]))
        self.write(stage.name + "-accepted-helper-verification.json", report)
        assert AUTH["stage_sha256"] in json.dumps(report)

    def prepare_context(self):
        self.context = self.root / "context"
        self.context.mkdir()
        rules = (self.candidate / ".dockerignore").read_text().splitlines()
        assert file_digest(self.candidate / ".dockerignore") == "48ccfae71420aed53ac179a546dbd42c458697c496423a2714b760be5f08d39a"
        assert file_digest(self.candidate / "backend/Dockerfile") == "be87830d91db221b19de4a67c67b953ba6ee111c29372e87c7e6397415d1c825"
        def ignored(name):
            excluded = False
            for rule in rules:
                rule = rule.strip()
                if not rule or rule.startswith("#"):
                    continue
                negated = rule.startswith("!")
                pattern = rule.removeprefix("!").rstrip("/")
                matches = fnmatch.fnmatchcase(name, pattern) or name.startswith(pattern + "/")
                if "/" not in pattern:
                    matches = matches or any(fnmatch.fnmatchcase(p, pattern) for p in name.split("/"))
                if matches:
                    excluded = not negated
            return excluded
        included = []
        for r in self.source_inventory:
            name = r["path"]
            if name not in {".dockerignore", "index.html"} and not name.startswith(("assets/", "css/", "js/", "src/styles/", "templates/", "backend/")):
                continue
            if ignored(name):
                continue
            p = self.context / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.candidate / name, p)
            p.chmod(0o755 if r["mode"] == "100755" else 0o644)
            included.append(name)
        target = self.context / ".ieltmps-build/public-listening-frontend"
        shutil.copytree(self.stage, target)
        self.context_inventory = self.inventory(self.context)
        self.write("context-inventory.json", self.context_inventory)
        self.context_tar = self.evidence / "context.tar"
        with tarfile.open(self.context_tar, "w", format=tarfile.PAX_FORMAT) as tar:
            for r in self.context_inventory:
                name = safe_name(r["path"])
                p = self.context / name
                member = tarfile.TarInfo(name)
                member.size = p.stat().st_size
                member.mode = p.stat().st_mode & 0o777
                member.mtime = 0
                with p.open("rb") as data:
                    tar.addfile(member, data)
        inventory = self.tar_inventory(self.context_tar)
        assert {r["path"]: (r["bytes"], r["sha256"]) for r in inventory} == {
            r["path"]: (r["bytes"], r["sha256"]) for r in self.context_inventory}
        self.context_sha = file_digest(self.context_tar)
        self.write("context-identity.json", {"sha256": self.context_sha, "files": len(inventory),
            "source": "Exact Git-derived COPY inputs plus independently verified stage; no working-tree input"})

    def tar_inventory(self, path, *, compressed=False):
        result = []
        seen = set()
        with tarfile.open(path, "r:*") as tar:
            for member in tar:
                if member.name in {".", "./", "/"}:
                    continue
                name = safe_name(member.name)
                assert name not in seen, name
                seen.add(name)
                row = {"path": name, "type": member.type.decode("ascii"), "bytes": member.size,
                    "mode": member.mode, "link": member.linkname}
                if member.isfile():
                    with tar.extractfile(member) as stream:
                        h = hashlib.sha256()
                        tail = b""
                        while chunk := stream.read(1024 * 1024):
                            assert self.sentinel not in tail + chunk
                            h.update(chunk)
                            tail = chunk[-len(self.sentinel):]
                        row["sha256"] = h.hexdigest()
                # Inventories include links and whiteouts; no tar is extracted.
                assert not name.startswith(("app/ListeningPractice/", "app/ReadingPractice/",
                    "ListeningPractice/", "ReadingPractice/"))
                assert name not in {"app/ListeningPractice", "app/ReadingPractice", "ListeningPractice", "ReadingPractice"}
                if name.startswith("app/") or path == getattr(self, "context_tar", None):
                    parts = name.split("/")
                    assert ".git" not in parts and not any(p == ".env" or (p.startswith(".env.") and p != ".env.example") for p in parts)
                result.append(row)
        return result

    def build(self):
        self.oci = self.evidence / "image.oci.tar"
        self.docker_tar = self.evidence / "image.docker.tar"
        self.tag = self.prefix + ":candidate"
        self.resources["images"].append(self.tag)
        self.write("resources.json", self.resources)
        env = {**self.env, "BUILDX_METADATA_PROVENANCE": "max", "BUILDX_METADATA_WARNINGS": "1"}
        with self.context_tar.open("rb") as stream:
            self.docker("buildx", "build", "--builder", self.builder,
                "--platform", "linux/amd64", "--build-context", "node:24-alpine=docker-image://" + self.image_ref("node"),
                "--file", "backend/Dockerfile", "--tag", self.tag, "--provenance=mode=max",
                "--metadata-file", self.evidence / "build-metadata.json", "--progress", "plain", "--no-cache",
                "--output", "type=oci,compression=gzip,dest=" + str(self.oci), "-",
                stdin=stream, timeout=1200, env=env)
        assert file_digest(self.context_tar) == self.context_sha
        assert self.inventory(self.context) == self.context_inventory
        self.image_id = self.inspect_image_archives(self.oci, self.docker_tar, "built", create_runtime_archive=True)
        self.docker("load", "--input", self.docker_tar, timeout=180)
        config = json.loads(self.docker("image", "inspect", self.image_id))[0]
        assert config["Id"] == self.image_id
        assert config["Config"]["User"] == "node"
        assert config["Config"]["Cmd"] == ["sh", "-c", "node scripts/migrate.mjs && node scripts/bootstrap-admin.mjs && node src/server.js"]
        assert "NODE_ENV=production" in config["Config"]["Env"]
        assert config["RootFS"]["Layers"][:4] == self.registry["node"]["config"]["rootfs"]["diff_ids"]
        self.write("built-image-inspect.json", config)
        self.inspect_filesystem(self.image_id, "built")
        self.record("C", context_sha256=self.context_sha, layer_inventories="built-layers.json",
            filesystem_inventory="built-filesystem.json", no_private_sources=True, no_local_credentials=True)
        self.record("D", image_id=self.image_id, oci_sha256=file_digest(self.oci),
            docker_archive_sha256=file_digest(self.docker_tar), named_base_override=True,
            base_rootfs_verified=True, materials_verified=True)

    def inspect_image_archives(self, oci, docker_tar, label, *, create_runtime_archive=False):
        # OCI retains attestations. Docker's legacy archive cannot represent an
        # attestation index, so package the very same verified config and layer
        # bytes in its documented single-image layout without a second build.
        with contextlib.ExitStack() as stack:
            tar = stack.enter_context(tarfile.open(oci, "r:"))
            runtime_archive = stack.enter_context(tarfile.open(docker_tar, "w")) if create_runtime_archive else None
            def append_runtime(name, data):
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.mtime = 0
                member.size = len(data)
                runtime_archive.addfile(member, io.BytesIO(data))
            members = {safe_name(m.name): m for m in tar if m.isfile()}
            def raw(name):
                return tar.extractfile(members[name]).read()
            index = json.loads(raw("index.json"))
            manifests = []
            manifest_digests = []
            attestations = []
            def follow(descriptor):
                expected = descriptor["digest"].removeprefix("sha256:")
                data = raw("blobs/sha256/" + expected)
                assert len(data) == descriptor["size"] and digest(data) == expected
                value = json.loads(data)
                if "manifests" in value:
                    for child in value["manifests"]:
                        follow(child)
                elif descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                    attestations.append(value)
                elif "config" in value:
                    manifests.append(value)
                    manifest_digests.append(expected)
            for descriptor in index["manifests"]:
                follow(descriptor)
            assert len(manifests) == 1
            manifest = manifests[0]
            def blob(descriptor):
                data = raw("blobs/sha256/" + descriptor["digest"].removeprefix("sha256:"))
                assert len(data) == descriptor["size"] and "sha256:" + digest(data) == descriptor["digest"]
                return data
            config_raw = blob(manifest["config"])
            config = json.loads(config_raw)
            assert config["rootfs"]["diff_ids"][:4] == self.registry["node"]["config"]["rootfs"]["diff_ids"]
            assert (config["os"], config["architecture"]) == ("linux", "amd64")
            layer_rows = []
            runtime_layers = []
            for i, (descriptor, diff_id) in enumerate(zip(manifest["layers"], config["rootfs"]["diff_ids"], strict=True)):
                compressed = blob(descriptor)
                data = gzip.decompress(compressed) if "gzip" in descriptor["mediaType"] else compressed
                assert "sha256:" + digest(data) == diff_id
                if runtime_archive:
                    runtime_layer = f"{i}/layer.tar"
                    append_runtime(runtime_layer, data)
                    runtime_layers.append(runtime_layer)
                layer_file = self.root / f"{label}-layer-{i}.tar"
                layer_file.write_bytes(data)
                inventory = self.tar_inventory(layer_file)
                layer_rows.append({"ordinal": i, "descriptor": descriptor, "diff_id": diff_id, "entries": inventory})
                layer_file.unlink()
            material_found = False
            provenance = []
            for attestation in attestations:
                blob(attestation["config"])
                for layer in attestation["layers"]:
                    statement = json.loads(blob(layer))
                    provenance.append(statement)
                    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
                    assert len(statement["subject"]) == 1 and statement["subject"][0]["digest"] == {"sha256": manifest_digests[0]}
                    definition = statement["predicate"]["buildDefinition"]
                    dependencies = definition["resolvedDependencies"]
                    assert len(dependencies) == 2
                    image_materials = [d for d in dependencies if d["uri"].startswith("pkg:docker/node?")]
                    context_materials = [d for d in dependencies if d["uri"].startswith("http://buildkit-session/")]
                    assert len(image_materials) == len(context_materials) == 1
                    assert image_materials[0]["digest"] == {"sha256": AUTH["images"]["node"]["manifest"]}
                    assert context_materials[0]["digest"] == {"sha256": self.context_sha}
                    external = definition["externalParameters"]
                    assert external["configSource"]["digest"] == {"sha256": self.context_sha}
                    assert external["configSource"]["path"] == "backend/Dockerfile"
                    assert external["request"]["args"]["context:node:24-alpine"] == "docker-image://" + self.image_ref("node")
                    assert definition["internalParameters"]["targetPlatform"] == "linux/amd64"
                    material_found = True
            self.write(label + "-provenance.json", provenance)
            assert material_found and len(provenance) == 1, "Exact approved build materials missing from OCI provenance"
            if runtime_archive:
                config_name = digest(config_raw) + ".json"
                append_runtime(config_name, config_raw)
                append_runtime("manifest.json", encode([{"Config": config_name, "RepoTags": [self.tag], "Layers": runtime_layers}]))
                self.write("runtime-archive-conversion.json", {"source": "The same OCI build result", "config_sha256": digest(config_raw),
                    "diff_ids": config["rootfs"]["diff_ids"], "conversion": "Verified config bytes and decompressed layer bytes in Docker archive format",
                    "attestations_retained_in": "image.oci.tar", "second_build_performed": False})
            self.write(label + "-layers.json", layer_rows)
            self.write(label + "-oci-config.json", config)
        with tarfile.open(docker_tar, "r:") as tar:
            manifest = json.load(tar.extractfile("manifest.json"))
            assert len(manifest) == 1
            docker_config = tar.extractfile(manifest[0]["Config"]).read()
            assert docker_config == config_raw
            for name, expected in zip(manifest[0]["Layers"], config["rootfs"]["diff_ids"], strict=True):
                with tar.extractfile(name) as stream:
                    assert "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() == expected
        return "sha256:" + digest(config_raw)

    def inspect_filesystem(self, image, label):
        name = self.prefix + "-" + label + "-inventory"
        self.resources["containers"].append(name)
        self.write("resources.json", self.resources)
        self.docker("create", "--name", name, image)
        output = self.evidence / (label + "-filesystem.tar")
        self.docker("export", "--output", output, name, timeout=180)
        inventory = self.tar_inventory(output)
        self.write(label + "-filesystem.json", inventory)
        by_path = {r["path"]: r for r in inventory}
        for r in self.inventory(self.stage):
            actual = by_path["app/public/listening-frontend/" + r["path"]]
            assert (actual["bytes"], actual["sha256"]) == (r["bytes"], r["sha256"])
        for r in self.manifest["generated_dependencies"]:
            actual = by_path[r["required_image_path"].removeprefix("/")]
            assert (actual["bytes"], actual["sha256"]) == (r["length"], r["sha256"])
        for r in self.source_inventory:
            actual_path = "app/" + r["path"]
            if (self.context / r["path"]).is_file() and r["path"] != ".dockerignore":
                actual = by_path[actual_path]
                assert (actual["bytes"], actual["sha256"]) == (r["bytes"], r["sha256"])
        self.write(label + "-placement.json", {"status": "PASS", "stage_files": 28,
            "payload_files": 26, "generated_dependencies": 4, "runtime_source_identity_preserved": True})

    def http(self, method, target, *, cookie="", body=None, host=None, label="http", headers=None):
        request_headers = {"Host": host or self.business_host, **(headers or {})}
        if cookie:
            request_headers["Cookie"] = cookie
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", self.tls_port, context=self.tls_context, timeout=20)
        try:
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            data = response.read()
            pairs = response.getheaders()
            status = response.status
        finally:
            connection.close()
        count = len(list(self.evidence.glob("http-*.json"))) + 1
        name = f"http-{count:04}-{label}"
        (self.evidence / (name + ".body")).write_bytes(data)
        self.write(name + ".json", {"method": method, "target": target, "status": status,
            "headers": pairs, "body_bytes": len(data), "body_sha256": digest(data)})
        return status, {k.lower(): v for k, v in pairs}, data

    def start_tls(self):
        certificate = self.evidence / "synthetic-tls-certificate.pem"
        key = self.root / "synthetic-tls-private-key.pem"
        hosts = [self.auth_host, self.business_host, self.admin_host]
        names = [h.split(":")[0] for h in hosts]
        self.run([self.openssl_path, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "1", "-subj", "/CN=" + names[0], "-addext",
            "subjectAltName=" + ",".join(["DNS:" + n for n in names] + ["IP:127.0.0.1"]),
            "-keyout", key, "-out", certificate])
        key.chmod(0o600)
        public_key = self.run([self.openssl_path, "pkey", "-in", key, "-pubout", "-outform", "DER"])
        self.tls_spki = base64.b64encode(hashlib.sha256(public_key).digest()).decode()
        self.tls_context = ssl.create_default_context(cafile=str(certificate))
        config = self.root / "tls-proxy-config.json"
        config.write_bytes(encode({"key": str(key), "certificate": str(certificate), "hosts": hosts,
            "port": self.tls_port, "upstream": self.port}))
        config.chmod(0o600)
        script = self.root / "tls-proxy.cjs"
        script.write_text(TLS_SOURCE)
        self.proxy_logs = [(self.evidence / ("tls-proxy." + suffix)).open("wb") for suffix in ["stdout", "stderr"]]
        self.proxy = subprocess.Popen([self.node, "--max-old-space-size=64", str(script), str(config)],
            env=self.env, stdin=subprocess.DEVNULL, stdout=self.proxy_logs[0], stderr=self.proxy_logs[1])
        self.resources["processes"].append({"pid": self.proxy.pid, "script": str(script), "purpose": "owned_loopback_tls"})
        self.write("resources.json", self.resources)
        self.write("tls-endpoint.json", {"listen": "127.0.0.1", "port": self.tls_port,
            "upstream_loopback_port": self.port, "hosts": hosts, "certificate_sha256": file_digest(certificate),
            "browser_certificate_spki_sha256_base64": self.tls_spki, "control_source_sha256": file_digest(script),
            "private_key_retained_in_artifact": False, "python_certificate_and_hostname_verification": True})

    def start(self, image, label):
        self.running_image = image
        self.fixtures = self.root / (label + "-fixtures")
        self.fixtures.mkdir()
        self.fixture_bytes = ("<!doctype html><html><head><meta charset='utf-8'><title>Synthetic exam</title></head>"
            "<body><h1 id='synthetic-marker'>" + self.sentinel.decode() + "</h1>"
            "<label for='q1'>Synthetic question 1</label><input id='q1' name='q1' data-question='1'>"
            "<button type='button'>Check answer</button></body></html>").encode()
        for relative in [EXAM_PATH, "vip special/ListeningPractice/" + EXAM_PATH]:
            p = self.fixtures / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(self.fixture_bytes)
        self.outside = self.root / (label + "-outside")
        (self.outside / "ListeningPractice").mkdir(parents=True)
        (self.outside / "sentinel.html").write_bytes(self.sentinel + b"-OUTSIDE-MOUNT")
        (self.outside / "ListeningPractice/sentinel.html").write_bytes(self.sentinel + b"-OUTSIDE-ANCESTOR")
        (self.fixtures / "escape.html").symlink_to("/i79-outside/sentinel.html")
        (self.fixtures / "escape-dir").symlink_to("/i79-outside", target_is_directory=True)
        (self.fixtures / "vip special/ListeningPractice/escape-dir").symlink_to("/i79-outside", target_is_directory=True)
        self.fixture_hashes = {p.relative_to(self.fixtures).as_posix(): file_digest(p)
            for p in self.fixtures.rglob("*") if p.is_file() and not p.is_symlink()}
        for p in [self.fixtures, self.outside, *self.fixtures.rglob("*"), *self.outside.rglob("*")]:
            if not p.is_symlink():
                p.chmod(0o755 if p.is_dir() else 0o644)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
            with socket.socket() as tls_socket:
                tls_socket.bind(("127.0.0.1", 0))
                self.tls_port = tls_socket.getsockname()[1]
        assert self.tls_port != self.port
        self.auth_host = "a" * 56 + ".onion:" + str(self.tls_port)
        self.business_host = "b" * 56 + ".onion:" + str(self.tls_port)
        self.admin_host = "c" * 56 + ".onion:" + str(self.tls_port)
        network = self.prefix + "-" + label + "-network"
        database = self.prefix + "-" + label + "-db"
        volume = self.prefix + "-" + label + "-data"
        self.app = self.prefix + "-" + label + "-app"
        self.database = database
        self.resources["networks"].append(network)
        self.resources["volumes"].append(volume)
        self.resources["containers"].extend([database, self.app])
        self.write("resources.json", self.resources)
        self.docker("network", "create", "--driver", "bridge",
            "--opt", "com.docker.network.bridge.host_binding_ipv4=127.0.0.1",
            "--opt", "com.docker.network.bridge.enable_ip_masquerade=false", network)
        network_info = json.loads(self.docker("network", "inspect", network))
        self.write(label + "-network.json", network_info)
        gateway = network_info[0]["IPAM"]["Config"][0]["Gateway"]
        assert ipaddress.ip_address(gateway).is_private and not ipaddress.ip_address(gateway).is_loopback
        self.docker("volume", "create", volume)
        database_password = secrets.token_urlsafe(36)
        self.admin_username = "i79admin" + secrets.token_hex(6)
        self.username = "i79user" + secrets.token_hex(6)
        self.password = "Aa1!" + secrets.token_urlsafe(28)
        db_env = self.root / (label + "-db.env")
        db_env.write_text(f"POSTGRES_PASSWORD={database_password}\nPOSTGRES_DB=i79\n")
        db_env.chmod(0o600)
        app_env = self.root / (label + "-app.env")
        values = {"DATABASE_URL": f"postgres://postgres:{database_password}@{database}:5432/i79",
            "SESSION_SECRET": secrets.token_urlsafe(48), "AUTH_HANDOFF_STATE_SECRET": secrets.token_urlsafe(48),
            "ADMIN_USERNAME": self.admin_username, "ADMIN_PASSWORD": "Aa1!" + secrets.token_urlsafe(32),
            "TOTP_ENCRYPTION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
            "AUTH_PUBLIC_URL": "https://" + self.auth_host, "BUSINESS_PUBLIC_URL": "https://" + self.business_host,
            "ADMIN_PUBLIC_URL": "https://" + self.admin_host, "TRUST_PROXY": "true", "TRUSTED_PROXY_IPS": gateway,
            "NODE_ENV": "production", "HOST": "0.0.0.0", "PORT": "3000"}
        app_env.write_text("".join(k + "=" + v + "\n" for k, v in values.items()))
        app_env.chmod(0o600)
        self.docker("pull", "--platform", "linux/amd64", self.image_ref("postgres"), timeout=300)
        db_image = json.loads(self.docker("image", "inspect", self.image_ref("postgres")))[0]
        assert db_image["Id"] == "sha256:" + AUTH["images"]["postgres"]["config"]
        self.docker("run", "--detach", "--name", database, "--network", network,
            "--memory", "1g", "--cpus", "1", "--pids-limit", "256", "--env-file", db_env,
            "--mount", f"type=volume,src={volume},dst=/var/lib/postgresql/data", self.image_ref("postgres"))
        for _ in range(30):
            self.docker("exec", database, "pg_isready", "-U", "postgres", "-d", "i79", allowed=(0, 1, 2))
            if self.commands[-1]["exit"] == 0:
                break
            time.sleep(1)
        assert self.commands[-1]["exit"] == 0
        assert b"16.16" in self.docker("exec", database, "postgres", "--version")
        self.docker("run", "--detach", "--name", self.app, "--network", network,
            "--memory", "768m", "--cpus", "1", "--pids-limit", "256", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--publish", f"127.0.0.1:{self.port}:3000",
            "--env-file", app_env, "--mount", f"type=bind,src={self.fixtures},dst=/app/ListeningPractice,readonly",
            "--mount", f"type=bind,src={self.outside},dst=/i79-outside,readonly", image)
        inspected = json.loads(self.docker("inspect", self.app))[0]
        assert inspected["Image"] == image and inspected["Config"]["User"] == "node"
        assert not inspected["HostConfig"]["Privileged"] and inspected["HostConfig"]["NetworkMode"] == network
        assert inspected["HostConfig"]["PortBindings"]["3000/tcp"] == [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]
        assert inspected["NetworkSettings"]["Ports"]["3000/tcp"] == [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]
        assert all(not m["RW"] for m in inspected["Mounts"])
        assert {m["Destination"] for m in inspected["Mounts"]} == {"/app/ListeningPractice", "/i79-outside"}
        inspected["Config"]["Env"] = [v if v.split("=", 1)[0] in {"NODE_ENV", "HOST", "PORT", "TRUST_PROXY", "TRUSTED_PROXY_IPS"} else v.split("=", 1)[0] + "=<synthetic-redacted>" for v in inspected["Config"]["Env"]]
        self.write(label + "-running-container.json", inspected)
        self.start_tls()
        self.wait_health(label)
        self.docker("exec", "--user", "0", self.app, "node", "-e",
            "const fs=require('node:fs');try{fs.writeFileSync('/app/ListeningPractice/i79-write-probe','forbidden');process.exit(9)}catch(e){if(e.code!=='EROFS')throw e;console.log('EROFS verified as container root')}" )
        assert not (self.fixtures / "i79-write-probe").exists()
        self.docker("restart", "--time", "10", self.app, timeout=40)
        self.wait_health(label + "-restart")
        self.docker("logs", self.app)
        self.docker("exec", database, "psql", "-U", "postgres", "-d", "i79", "-c",
            "SELECT username, role FROM users ORDER BY id;")
        self.record("E", executed_image=image, production_user="node", production_cmd_unchanged=True,
            migration_and_bootstrap_exit="Both exited 0, established by the unchanged shell && chain reaching server health before and after restart",
            fresh_database=True, healthy_start=True, healthy_restart=True)

    def wait_health(self, label):
        failures = []
        for _ in range(60):
            try:
                status, _, data = self.http("GET", "/api/health", label=label)
                if status == 200 and json.loads(data) == {"ok": True}:
                    return
                failures.append({"status": status, "body": data.decode(errors="replace")})
            except (OSError, http.client.HTTPException) as exc:
                failures.append(str(exc))
            time.sleep(1)
        self.docker("logs", self.app)
        self.write("startup-failures.json", failures)
        raise RuntimeError("Unchanged production CMD did not become healthy")

    def browser(self, login_only=False):
        config = {"auth": "https://" + self.auth_host, "business": "https://" + self.business_host,
            "admin": "https://" + self.admin_host, "username": self.username, "password": self.password,
            "tlsSpki": self.tls_spki,
            "exam": EXAM_ID, "routeId": EXAM_ROUTE_ID, "marker": self.sentinel.decode(), "evidence": str(self.evidence),
            "cookies": str(self.root / "browser-cookies.json"), "tools": str(self.tools), "loginOnly": login_only}
        config_file = self.root / "browser-config.json"
        config_file.write_bytes(encode(config))
        config_file.chmod(0o600)
        script = self.root / "browser-smoke.cjs"
        script.write_text(BROWSER_SOURCE)
        self.write("browser-control-identity.json", {"sha256": file_digest(script),
            "source": "Frozen BROWSER_SOURCE in runtime.py; no application module import"})
        self.run([self.node, script, config_file], timeout=240)
        result = json.loads((self.evidence / ("browser-login-report.json" if login_only else "browser-report.json")).read_bytes())
        expected = ["ordinary_registration", "ordinary_login", "public_entry", "initial_notice_acknowledged", "browse_search", "exam_wrapper", "private_marker", "question_input", "network_closure", "no_policy_violation"]
        assert result["cases"] == (["ordinary_login"] if login_only else expected) and result["status"] == "PASS"
        cookies = json.loads((self.root / "browser-cookies.json").read_bytes())
        assert all(c["secure"] for c in cookies if c["name"] in {"ielts.sid", "ielts.sv"})
        self.cookie = "; ".join(c["name"] + "=" + c["value"] for c in cookies
            if c["domain"].lstrip(".") == self.business_host.split(":")[0])
        assert "ielts.sid=" in self.cookie and "ielts.sv=" in self.cookie
        if not login_only:
            self.record("I", cases=expected, trace="browser-trace.zip", actual_image=self.running_image,
                entered_from_public_shell=True, synthetic_question_interacted=True)

    def route_tests(self):
        shell = "/ListeningPractice/vip%20special/"
        routes = []
        for r in self.manifest["approved_entries"]:
            if r["included_in_runtime"]:
                routes.append((shell + urllib.parse.quote(r["payload_path"], safe="/"), r, "shell"))
        for r in self.manifest["generated_dependencies"]:
            if r["artifact_path"] is not None:
                routes.append((shell + r["artifact_path"], r, "shell"))
            routes.append((r["required_image_path"].removeprefix("/app"), r, "root"))
        shell_record = next(r for r in self.manifest["approved_entries"] if r["payload_path"] == "index.html")
        routes.append((shell, shell_record, "shell"))
        csp_observed = []
        for target, record, kind in routes:
            for method in ["GET", "HEAD"]:
                status, headers, data = self.http(method, target, cookie=self.cookie, label="allowed")
                assert status == 200, (target, status)
                assert headers.get("content-length") == str(record["length"])
                suffix = PurePosixPath(target.rstrip("/") or "index.html").suffix or ".html"
                content_types = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
                    ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
                    ".woff2": "font/woff2", ".svg": "image/svg+xml"}
                retained_buffer = kind == "shell" or target in {
                    "/assets/generated/listening-exams/manifest.js", "/assets/generated/listening-exams/listening-index.compat.js"}
                expected_type = content_types[suffix]
                if not retained_buffer:
                    expected_type = expected_type.replace("charset=utf-8", "charset=UTF-8")
                assert headers["content-type"] == expected_type, (method, target, headers["content-type"], expected_type)
                expected_cache = "private, no-store" if retained_buffer else "public, max-age=0"
                assert headers["cache-control"] == expected_cache
                if method == "GET":
                    assert digest(data) == record["sha256"] and len(data) == record["length"]
                else:
                    assert not data
                if kind == "shell":
                    assert headers["content-security-policy"] == AUTH["csp"]["shell"]
                    assert headers["cache-control"] == "private, no-store"
                    csp_observed.append({"path": target, "policy": "shell"})
        private = "/ListeningPractice/" + urllib.parse.quote(EXAM_PATH, safe="/")
        nested = shell + "ListeningPractice/" + urllib.parse.quote(EXAM_PATH, safe="/")
        wrapper = "/practice/listening/" + EXAM_ID
        short_wrapper = "/practice/listening/" + EXAM_ROUTE_ID
        wrapper_bytes = (self.candidate / "assets/generated/listening-exams/listening-practice-unified.html").read_text()
        for attribute, value in {"data-exam-id": EXAM_ID, "data-source-url": private,
                "data-base-href": private.rsplit("/", 1)[0] + "/"}.items():
            wrapper_bytes, count = re.subn(attribute + r'="[^"]*"', attribute + '="' + value + '"', wrapper_bytes, count=1)
            assert count == 1
        wrapper_bytes = wrapper_bytes.encode()
        for target, policy, expected_data in [(private, "private", self.fixture_bytes),
                (nested, "private", self.fixture_bytes),
                (wrapper, "wrapper", wrapper_bytes), (short_wrapper, "wrapper", wrapper_bytes)]:
            for method in ["GET", "HEAD"]:
                status, headers, data = self.http(method, target, cookie=self.cookie, label=policy)
                assert status == 200
                assert headers["content-security-policy"] == AUTH["csp"][policy]
                expected_type = "text/html; charset=UTF-8" if policy == "private" else "text/html; charset=utf-8"
                assert headers["content-type"] == expected_type, (method, target, headers["content-type"], expected_type)
                assert headers["content-length"] == str(len(expected_data))
                if policy == "private":
                    assert headers["cache-control"] == "public, max-age=0"
                else:
                    assert "cache-control" not in headers
                if method == "GET":
                    assert data == expected_data
                else:
                    assert not data
                csp_observed.append({"path": target, "policy": policy})
        protected = [shell, *[r[0] for r in routes if r[2] == "shell"],
            "/assets/generated/listening-exams/manifest.js", "/assets/generated/listening-exams/listening-index.compat.js", wrapper, short_wrapper, private, nested]
        for target in sorted(set(protected)):
            for method in ["GET", "HEAD"]:
                status, headers, data = self.http(method, target, label="anonymous")
                assert status == 401 and self.sentinel not in data
                assert headers.get("cache-control") == "no-store"
        negative = [
            ("http://example.invalid/ListeningPractice/vip%20special/index.html", 400),
            (shell + "not-listed.js", 404), ("//ListeningPractice/vip%20special/index.html", 400),
            ("/ListeningPractice//vip%20special/index.html", 404),
            ("/listeningpractice/vip%20special/index.html", 404),
            ("/ListeningPractice/vip%2520special/index.html", 404),
            (shell + "%69ndex.html", 400), (shell + "%2e%2e/index.html", 400),
            (shell + "assets%2Fgenerated/listening-exams/manifest.js", 400),
            ("/assets/%67enerated/listening-exams/manifest.js", 404),
            ("//assets/generated/listening-exams/manifest.js", 400),
            ("/assets/generated/listening-exams/manifest.js.", 404),
            ("/assets/generated/listening-exams/manifest.js%2Fextra", 404),
            (shell + "ListeningPractice/%2e%2e/private.html", 400),
            (shell + "ListeningPractice/P2/./private/private.html", 400),
            (shell + "ListeningPractice/P2/private/../private/private.html", 400),
            (shell + "ListeningPractice/P2%2Fprivate/private.html", 400),
            (shell + "ListeningPractice/P2%5Cprivate/private.html", 400),
            (shell + "ListeningPractice/%252e%252e/private.html", 400),
            ("/ListeningPractice/missing.html", 404), ("/ListeningPractice/escape.html", 403),
            ("/ListeningPractice/escape-dir/sentinel.html", 403),
            (shell + "ListeningPractice/escape-dir/sentinel.html", 403),
        ]
        for target, expected in negative:
            for method in ["GET", "HEAD"]:
                status, _, data = self.http(method, target, cookie=self.cookie, label="negative")
                assert status == expected and self.sentinel not in data, (target, status, expected)
        aliases = []
        for file in ["manifest.js", "listening-index.compat.js"]:
            for root in ["/assets/generated/listening-exams/"]:
                target = root + file
                directory = root.rstrip("/")
                aliases.extend([
                    directory + "/./" + file, "/./" + target[1:], target.replace("/generated/", "/./generated/"),
                    directory + "/%2e/" + file, directory + "/%252e/" + file, directory + "/%25252e/" + file,
                    directory + "/temporary/../" + file, directory + "/temporary/%2e%2e/" + file,
                    directory + "//./" + file, directory + "\\.\\" + file,
                    directory + "/.%2F" + file, directory.upper() + "/./" + file,
                    directory + "/./%" + format(ord(file[0]), "x") + file[1:],
                    directory + "/./" + file + ".", directory + "/./" + file + "/extra",
                    directory + "/./" + file + "/.", directory + "/./" + file + "/%", target + "/../unrelated.js"])
        alias_results = []
        def test_aliases(cookie, audience):
            for target in aliases:
                for method in ["GET", "HEAD"]:
                    status, headers, data = self.http(method, target, cookie=cookie, label="alias")
                    assert status == 404 and headers.get("cache-control") == "no-store" and self.sentinel not in data, (target, status)
                    alias_results.append({"method": method, "target": target, "audience": audience, "status": status})
        test_aliases(self.cookie, "authenticated")
        test_aliases("", "anonymous")
        # Expiry/revocation alter only this transaction's disposable server-side state.
        for mode, sql in [("expired", "UPDATE session SET expire = NOW() - INTERVAL '1 day';"),
                ("revoked", "UPDATE auth_sessions SET revoked_at = NOW() WHERE revoked_at IS NULL;")]:
            if mode == "revoked":
                self.browser(login_only=True)
                assert self.http("GET", shell, cookie=self.cookie, label="fresh-before-revoke")[0] == 200
            self.docker("exec", self.database, "psql", "-U", "postgres", "-d", "i79", "-c", sql)
            for target in [shell, wrapper, short_wrapper, private, "/assets/generated/listening-exams/manifest.js"]:
                for method in ["GET", "HEAD"]:
                    status, headers, data = self.http(method, target, cookie=self.cookie, label=mode)
                    assert status == 401 and self.sentinel not in data
                    assert headers.get("cache-control") == "no-store"
            test_aliases(self.cookie, mode)
        assert len(alias_results) == 288
        self.write("alias-matrix.json", alias_results)
        self.write("live-csp-comparison.json", {"expected": AUTH["csp"], "observations": csp_observed, "status": "PASS"})
        self.record("F", allowed_get_head_routes=len(routes), alias_cases=288,
            anonymous=True, expired=True, revoked=True, negative_routes=len(negative))
        self.record("G", public_shell_exact=True, wrapper_exact=True, private_exam_exact=True)
        self.record("B", source_delta_paths=18, generated_dependencies=4,
            stage_and_image_placement=True, browser_network_verified=True)

    def private_boundaries(self):
        # Run the exact accepted A4 regressions in the same immutable image.
        # Its fail-closed cases require an absent production artifact; this
        # separate test container shadows that directory, never the live app.
        name = self.prefix + "-accepted-regressions"
        empty_artifact = self.root / "regression-empty-artifact"
        empty_artifact.mkdir()
        empty_artifact.chmod(0o755)
        self.resources["containers"].append(name)
        self.write("resources.json", self.resources)
        raw = self.docker("run", "--name", name, "--network", "none", "--memory", "768m", "--cpus", "1",
            "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,src={empty_artifact},dst=/app/public/listening-frontend,readonly",
            "--env", "NODE_ENV=test", "--entrypoint", "node", self.running_image,
            "--test", "--test-reporter=tap", "test/publicListeningFrontend.test.js", timeout=180)
        assert re.search(rb"^# fail 0$", raw, re.M) and re.search(rb"^# skipped 0$", raw, re.M)
        expected = [
            "nested private Listening routes reject roots and ancestors outside the top-level mount",
            "generated dependency dot aliases cannot serve unverified static bytes",
            "public Listening loader verifies its exact synthetic inventory and serves only retained bytes",
            "public Listening loader rejects Locator, Manifest, Payload and inventory corruption",
            "public Listening loader rejects symlinked Payload entries and path escape",
            "authenticated A2 public routes enforce allowlists, CSP separation and private containment",
            "production readiness fails closed and production rejects fixture or root overrides",
        ]
        observed = re.findall(r"^# Subtest: (.+)$", raw.decode(), re.M)
        assert observed == expected
        assert re.search(rb"^# tests 23$", raw, re.M) and re.search(rb"^# pass 23$", raw, re.M)
        self.write("accepted-regression-inventory.json", {"expected_top_level": expected,
            "observed_top_level": observed, "expected_total_including_nested": 23,
            "test_source_git_blob": "475f2785d853213b1e7eeb5c8f1f0955267dae98"})
        assert {p.relative_to(self.fixtures).as_posix(): file_digest(p)
            for p in self.fixtures.rglob("*") if p.is_file() and not p.is_symlink()} == self.fixture_hashes
        self.write("fixture-integrity.json", {"before_and_after": self.fixture_hashes, "status": "PASS"})
        self.record("H", synthetic_only=True, canonical_and_nested=True, missing_fixture_rejected=True,
            mount_rw=False, actual_root_write_rejected=True, fixture_hashes_unchanged=True,
            outside_mount_rejected=True, accepted_nested_and_intermediate_symlink_regressions=True)

    def cleanup(self):
        errors = []
        if self.proxy is not None:
            self.proxy.terminate()
            try:
                self.proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proxy.kill()
                self.proxy.wait(timeout=10)
            assert self.proxy.poll() is not None
            self.write("tls-proxy-cleanup.json", {"pid": self.proxy.pid, "terminated": True})
        for stream in self.proxy_logs:
            stream.close()
        def remove_if_present(inspect, remove):
            try:
                self.docker(*inspect, allowed=(0, 1))
                if self.commands[-1]["exit"] == 0:
                    self.docker(*remove)
            except Exception as exc:
                errors.append(str(exc))
        for name in reversed(self.resources["containers"]):
            remove_if_present(("container", "inspect", name), ("rm", "--force", name))
        for name in reversed(self.resources["builders"]):
            remove_if_present(("buildx", "inspect", "--builder", name), ("buildx", "rm", name))
        for kind, command in [("networks", "network"), ("volumes", "volume")]:
            for name in reversed(self.resources[kind]):
                remove_if_present((command, "inspect", name), (command, "rm", name))
        for name in reversed(self.resources["images"]):
            remove_if_present(("image", "inspect", name), ("image", "rm", name))
        for name in ["postgres", "buildkit", "node"]:
            reference = self.image_ref(name)
            raw = self.docker("image", "inspect", reference, allowed=(0, 1))
            if self.commands[-1]["exit"] == 0:
                identity = json.loads(raw)[0]["Id"]
                if identity not in self.initial_images:
                    remove_if_present(("image", "inspect", reference), ("image", "rm", reference))
        residual = {"containers": self.docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines(),
            "networks": self.docker("network", "ls", "--format", "{{.Name}}").decode().splitlines(),
            "volumes": self.docker("volume", "ls", "--format", "{{.Name}}").decode().splitlines()}
        residual = {k: [n for n in values if self.prefix in n] for k, values in residual.items()}
        residual["images"] = []
        for name in self.resources["images"]:
            self.docker("image", "inspect", name, allowed=(0, 1))
            if self.commands[-1]["exit"] == 0:
                residual["images"].append(name)
        if any(residual.values()):
            errors.append("Owned Docker resource remains")
        self.write("cleanup.json", {"errors": errors, "owned": self.resources, "residual": residual,
            "retained_local_evidence": "Uploaded before disposal of the dedicated GitHub-hosted runner"})
        return not errors


def admission_check(evidence):
    host = json.loads((evidence / "host-admission.json").read_bytes())
    for executable in host["binaries"]:
        p = Path(executable["path"])
        assert p.stat().st_size == executable["bytes"] and file_digest(p) == executable["sha256"]
    browser = json.loads((evidence / "browser-admission.json").read_bytes())
    for executable in browser["executables"]:
        assert file_digest(Path(executable["path"])) == executable["sha256"]
    for p, expected in browser["dynamic_dependency_closure"].items():
        assert file_digest(Path(p)) == expected["sha256"] and Path(p).stat().st_size == expected["bytes"]
    assert json.loads((evidence / "browser-sandbox-admission.json").read_bytes()) == {
        "version": "141.0.7390.37", "chromium_sandbox": True, "candidate_executed": False}
    builder = json.loads((evidence / "builder-admission.json").read_bytes())
    assert builder["inspect"]["Image"] == "sha256:" + AUTH["images"]["buildkit"]["config"]
    (evidence / "independent-admission-check.json").write_bytes(encode({
        "status": "PASS", "pid": os.getpid(), "candidate_executed": False,
        "records": {p.name: file_digest(p) for p in evidence.glob("*-admission.json")}}))


TLS_SOURCE = r"""
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const cfg = JSON.parse(fs.readFileSync(process.argv[2]));
const server = https.createServer({key: fs.readFileSync(cfg.key), cert: fs.readFileSync(cfg.certificate), minVersion: 'TLSv1.2'}, (req, res) => {
  if (!cfg.hosts.includes(req.headers.host)) {res.writeHead(400); return res.end();}
  const headers = {...req.headers, 'x-forwarded-proto': 'https', 'x-forwarded-host': req.headers.host, 'x-forwarded-for': '127.0.0.1'};
  const upstream = http.request({hostname: '127.0.0.1', port: cfg.upstream, method: req.method, path: req.url, headers}, response => {
    res.writeHead(response.statusCode, response.headers);
    response.pipe(res);
  });
  upstream.setTimeout(15000, () => upstream.destroy(new Error('upstream timeout')));
  upstream.on('error', error => {if (!res.headersSent) res.writeHead(502); res.end(); console.error(error.message);});
  req.pipe(upstream);
});
server.maxConnections = 32;
server.requestTimeout = 20000;
server.listen(cfg.port, '127.0.0.1', () => console.log(JSON.stringify({address: server.address(), upstream: cfg.upstream})));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
"""


BROWSER_SOURCE = r"""
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const cfg = JSON.parse(fs.readFileSync(process.argv[2]));
const {chromium} = require(path.join(cfg.tools, 'node_modules/playwright'));
const hosts = [cfg.auth, cfg.business, cfg.admin].map(x => new URL(x).hostname);
const report = {status: 'FAIL', cases: [], console: [], pageErrors: [], network: [], blockedExternal: [], policies: []};
const pending = [];
const shell = '/ListeningPractice/vip%20special/';
let browser, context;
const save = (name, data) => fs.writeFileSync(path.join(cfg.evidence, name), JSON.stringify(data, null, 2) + '\n');
async function freshContext() {
  const ctx = await browser.newContext({viewport: {width: 1440, height: 1000}});
  await ctx.tracing.start({screenshots: true, snapshots: true, sources: true});
  await ctx.route('**/*', route => {
    const u = new URL(route.request().url());
    if (!hosts.includes(u.hostname) || u.port !== new URL(cfg.business).port) {
      report.blockedExternal.push(route.request().url());
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  ctx.on('page', page => {
    page.on('console', msg => report.console.push({type: msg.type(), text: msg.text(), url: page.url()}));
    page.on('pageerror', error => report.pageErrors.push(String(error)));
    page.on('requestfailed', request => report.network.push({url: request.url(), failure: request.failure()}));
    page.on('response', response => pending.push((async () => {
      const record = {url: response.url(), status: response.status(), headers: await response.allHeaders()};
      try {const bytes = await response.body(); record.bytes = bytes.length; record.sha256 = crypto.createHash('sha256').update(bytes).digest('hex');}
      catch (error) {record.bodyUnavailable = String(error);}
      report.network.push(record);
    })()));
  });
  return ctx;
}
async function authenticate(ctx, register) {
  const page = await ctx.newPage();
  await page.goto(cfg.business + '/auth/business/start?return_to=' + encodeURIComponent(shell));
  await page.waitForURL(url => url.origin === cfg.auth && url.pathname === '/auth/business/login');
  if (register) await page.locator('#register-tab').click();
  await page.locator('#username').fill(cfg.username);
  await page.locator('#password').fill(cfg.password);
  await page.locator('#password-submit').click();
  await page.waitForURL(url => url.origin === cfg.business && decodeURIComponent(url.pathname).startsWith('/ListeningPractice/vip special'), {timeout: 45000});
  return page;
}
(async () => {
  browser = await chromium.launch({headless: true, chromiumSandbox: true,
    args: ['--host-resolver-rules=' + hosts.map(h => 'MAP ' + h + ' 127.0.0.1').join(', '),
      '--ignore-certificate-errors-spki-list=' + cfg.tlsSpki, '--proxy-bypass-list=*']});
  assert.equal(browser.version(), '141.0.7390.37');
  if (!cfg.loginOnly) {
    context = await freshContext();
    await authenticate(context, true);
    report.cases.push('ordinary_registration');
    await context.tracing.stop({path: path.join(cfg.evidence, 'browser-registration-trace.zip')});
    await context.close();
  }
  context = await freshContext();
  const page = await authenticate(context, false);
  report.cases.push('ordinary_login');
  if (!cfg.loginOnly) {
    assert.equal(new URL(page.url()).origin, cfg.business);
    assert.equal(await page.evaluate(() => window.isSecureContext), true, 'HTTPS secure context required');
    await page.locator('button[data-view="browse"]').waitFor({state: 'visible'});
    report.cases.push('public_entry');
    const notice = page.locator('#license-modal');
    await notice.locator('[data-index-action="accept-license"]').click();
    await page.locator('#license-modal.show').waitFor({state: 'hidden'});
    report.cases.push('initial_notice_acknowledged');
    const tour = page.locator('.onboarding-tooltip');
    try {
      await tour.waitFor({state: 'visible', timeout: 4000});
      // Escape is the accepted UI's ordinary onboarding skip operation.
      await page.keyboard.press('Escape');
      await tour.waitFor({state: 'hidden'});
      report.onboarding = 'skipped_through_supported_keyboard_action';
    } catch (error) {
      if (error.name !== 'TimeoutError' || await tour.isVisible()) throw error;
      report.onboarding = 'not_displayed';
    }
    await page.locator('button[data-view="browse"]').click();
    await page.locator('#exam-search-input').fill('Notes on A Part time Society');
    const start = page.locator('[data-exam-id="' + cfg.exam + '"][data-action="start"], [data-exam-id="' + cfg.exam + '"] [data-action="start"]').first();
    await start.waitFor({state: 'visible', timeout: 30000});
    await page.screenshot({path: path.join(cfg.evidence, 'browser-public-entry.png'), fullPage: true});
    report.cases.push('browse_search');
    await start.click();
    let wrapper, privateFrame;
    for (let i = 0; i < 100; i++) {
      for (const p of context.pages()) {
        for (const frame of p.frames()) {
          if (new URL(frame.url() || 'about:blank').pathname === '/practice/listening/' + cfg.routeId) wrapper = frame;
          if (await frame.locator('#synthetic-marker').count()) privateFrame = frame;
        }
      }
      if (wrapper && privateFrame) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    assert(wrapper, 'The real practice/listening route was not reached');
    assert.equal(await wrapper.locator('#listening-wrapper-root').getAttribute('data-exam-id'), cfg.exam);
    report.cases.push('exam_wrapper');
    assert(privateFrame, 'The private synthetic iframe was not loaded');
    assert.equal(await privateFrame.locator('#synthetic-marker').innerText(), cfg.marker);
    report.cases.push('private_marker');
    await privateFrame.locator('#q1').fill('synthetic answer');
    assert.equal(await privateFrame.locator('#q1').inputValue(), 'synthetic answer');
    report.cases.push('question_input');
    await privateFrame.page().screenshot({path: path.join(cfg.evidence, 'browser-synthetic-exam.png'), fullPage: true});
    await Promise.all(pending);
    for (const suffix of ['/assets/generated/listening-exams/manifest.js', '/assets/generated/listening-exams/listening-index.compat.js', '/js/bundles/listening-wrapper.bundle.js']) {
      assert(report.network.some(r => new URL(r.url).pathname.endsWith(suffix) && r.status === 200), 'Missing browser dependency: ' + suffix);
    }
    const failures = report.network.filter(r => /\.(?:js|css|woff2|svg|html)(?:\?|$)/.test(r.url) && (r.failure || r.status >= 400));
    assert.deepEqual(failures, [], 'A required static dependency failed in the real browser');
    assert.deepEqual(report.blockedExternal, [], 'Unexpected browser egress');
    report.cases.push('network_closure');
    assert.deepEqual(report.pageErrors, [], 'Browser application exception');
    assert.deepEqual(report.console.filter(r => /Content Security Policy|Refused to (?:load|execute|connect|frame)|violat.*directive|Cross-Origin-Opener-Policy.*ignored/i.test(r.text)), [], 'Browser security policy violation');
    report.cases.push('no_policy_violation');
  }
  fs.writeFileSync(cfg.cookies, JSON.stringify(await context.cookies()));
  report.status = 'PASS';
})().catch(error => {report.error = String(error.stack || error); process.exitCode = 1;}).finally(async () => {
  if (context) {
    report.finalPages = context.pages().map(p => ({url: p.url(), frames: p.frames().map(f => f.url())}));
    for (const [i, p] of context.pages().entries()) {
      try {const stem = (cfg.loginOnly ? 'browser-login-final-' : 'browser-final-') + i; await p.screenshot({path: path.join(cfg.evidence, stem + '.png')}); fs.writeFileSync(path.join(cfg.evidence, stem + '.html'), await p.content());} catch (_) {}
    }
    try {await context.tracing.stop({path: path.join(cfg.evidence, cfg.loginOnly ? 'browser-login-trace.zip' : 'browser-trace.zip')});} catch (_) {}
  }
  if (browser) await browser.close();
  await Promise.allSettled(pending);
  save(cfg.loginOnly ? 'browser-login-report.json' : 'browser-report.json', report);
});
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["producer", "verifier"])
    parser.add_argument("--producer", type=Path)
    args = parser.parse_args()
    control = Control(args.role, args.producer)
    try:
        control.admit()
        control.acquire_candidate()
        control.prepare_context()
        control.build()
        tested_image = control.image_id
        if args.role == "verifier":
            assert args.producer and args.producer.is_dir()
            artifacts = public_api(f"repos/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}/artifacts?per_page=100")
            selected = [a for a in artifacts["artifacts"] if str(a["id"]) == os.environ["I79_PRODUCER_ARTIFACT_ID"]]
            assert len(selected) == 1 and not selected[0]["expired"] and re.fullmatch(r"sha256:[0-9a-f]{64}", selected[0]["digest"])
            assert str(selected[0]["workflow_run"]["id"]) == os.environ["GITHUB_RUN_ID"]
            assert selected[0]["workflow_run"]["head_sha"] == os.environ["I79_CONTROL_COMMIT"]
            control.write("producer-artifact-api-readback.json", selected[0])
            inventory = json.loads((args.producer / "evidence-index.json").read_bytes())
            actual_names = {p.relative_to(args.producer).as_posix() for p in args.producer.rglob("*") if p.is_file()}
            assert actual_names == {r["path"] for r in inventory} | {"evidence-index.json"}
            for item in inventory:
                p = args.producer / safe_name(item["path"])
                assert not p.is_symlink() and p.stat().st_size == item["bytes"] and file_digest(p) == item["sha256"]
            producer_identity = json.loads((args.producer / "transaction.json").read_bytes())
            assert producer_identity["role"] == "producer" and producer_identity["run"] == os.environ["GITHUB_RUN_ID"]
            assert producer_identity["control_commit"] == os.environ["I79_CONTROL_COMMIT"]
            assert 1 <= int(producer_identity["attempt"]) <= int(os.environ["GITHUB_RUN_ATTEMPT"])
            assert selected[0]["name"] == "issue79-runtime-producer-" + producer_identity["attempt"]
            producer_context = json.loads((args.producer / "context-identity.json").read_bytes())
            assert producer_context["sha256"] == control.context_sha
            tested_image = control.inspect_image_archives(args.producer / "image.oci.tar", args.producer / "image.docker.tar", "producer")
            control.docker("load", "--input", args.producer / "image.docker.tar", timeout=180)
            with tarfile.open(args.producer / "image.docker.tar", "r:") as image_archive:
                transferred_tags = json.load(image_archive.extractfile("manifest.json"))[0]["RepoTags"]
            assert transferred_tags == [f"i79-runtime-{producer_identity['run']}-{producer_identity['attempt']}-producer:candidate"]
            control.resources["images"].extend(transferred_tags)
            control.write("resources.json", control.resources)
            control.inspect_filesystem(tested_image, "producer")
            assert json.loads((args.producer / "built-image-inspect.json").read_bytes())["Id"] == tested_image
            rebuilt_fs = json.loads((control.evidence / "built-filesystem.json").read_bytes())
            producer_fs = json.loads((control.evidence / "producer-filesystem.json").read_bytes())
            nondeterministic = ("root/.npm/_logs/", "root/.npm/_cacache/index-v5/")
            def stable_files(rows):
                return {r["path"]: r for r in rows if not r["path"].startswith(nondeterministic)}
            assert stable_files(rebuilt_fs) == stable_files(producer_fs), "Independently rebuilt and producer filesystems differ outside npm timestamp metadata"
            control.write("nondeterministic-build-metadata.json", {
                "recorded_nondeterministic_metadata": list(nondeterministic),
                "producer": [r for r in producer_fs if r["path"].startswith(nondeterministic)],
                "rebuild": [r for r in rebuilt_fs if r["path"].startswith(nondeterministic)]})
            control.write("independent-reconstruction.json", {"status": "PASS", "context_sha256": control.context_sha,
                "rebuilt_image": control.image_id, "producer_image_actually_tested": tested_image,
                "whole_image_byte_identity_required": False, "candidate_inventory": "candidate-inventory.json"})
        control.start(tested_image, "runtime")
        control.browser()
        control.route_tests()
        control.private_boundaries()
        if args.role == "verifier":
            assert all(value["status"] == "PASS" for key, value in control.results.items() if key != "J")
            producer_rows = json.loads((args.producer / "rows.json").read_bytes())
            assert set(producer_rows) == set(AUTH["expected_rows"])
            assert all(value["status"] == "PASS" for key, value in producer_rows.items() if key != "J")
            control.record("J", independent_git_and_registry=True, independent_context_reconstruction=True,
                independent_rebuild=True, producer_image_retested_by_config_digest=tested_image,
                separate_job_caches_credentials_and_database=True, complete_evidence_inventory_verified=True)
        else:
            control.results["J"] = {"status": "PENDING_INDEPENDENT_VERIFIER"}
    except BaseException as exc:
        control.failed = {"error": str(exc), "traceback": traceback.format_exc()}
        control.write("failure.json", control.failed)
        print(traceback.format_exc(), file=sys.stderr)
        browser_report = control.evidence / "browser-report.json"
        if browser_report.is_file():
            report = json.loads(browser_report.read_bytes())
            browser_error = report.get("error")
            if browser_error:
                print("Browser failure: " + browser_error[:16000], file=sys.stderr)
                print(json.dumps({"completed_browser_cases": report["cases"], "final_pages": report.get("finalPages")}), file=sys.stderr)
    finally:
        try:
            cleanup_ok = control.cleanup() if hasattr(control, "docker_path") else True
        except BaseException as exc:
            cleanup_ok = False
            control.write("cleanup-failure.json", {"error": str(exc), "traceback": traceback.format_exc()})
        control.write("rows.json", control.results)
        control.write("result.json", {"role": args.role, "failed": control.failed,
            "cleanup": "PASS" if cleanup_ok else "FAIL", "rows": control.results,
            "result": "MEASUREMENTS_COMPLETE" if not control.failed and cleanup_ok else "NOT_ACCEPTED"})
        index = control.inventory(control.evidence)
        control.write("evidence-index.json", index)
        print(json.dumps({"evidence": str(control.evidence), "rows": control.results, "failed": control.failed is not None}, indent=2))
    return 1 if control.failed or not cleanup_ok else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["admission-check"]:
        admission_check(Path(sys.argv[2]))
    else:
        raise SystemExit(main())
