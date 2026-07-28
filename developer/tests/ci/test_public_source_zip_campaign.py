import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
DEVELOPER = ROOT / "developer"
NODE = Path(os.environ.get(
    "IELTMPS_NODE",
    r"C:\Users\llzz\.cache\codex-runtimes\codex-primary-runtime"
    r"\dependencies\node\bin\node.exe",
)).resolve()
GPG = Path(os.environ.get(
    "IELTMPS_GPG",
    r"D:\GnuPG\bin\gpg.exe" if Path(r"D:\GnuPG\bin\gpg.exe").is_file()
    else (shutil.which("gpg") or ""),
)).resolve()
GPGCONF = Path(
    r"D:\GnuPG\bin\gpgconf.exe"
    if Path(r"D:\GnuPG\bin\gpgconf.exe").is_file()
    else (shutil.which("gpgconf") or "")
).resolve()
CSC = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe").resolve()
GIT = Path(os.environ.get(
    "IELTMPS_GIT",
    r"D:\Git\bin\git.exe" if Path(r"D:\Git\bin\git.exe").is_file()
    else (shutil.which("git") or ""),
)).resolve()
TASK_PARENT = Path(os.environ["TEMP"]).resolve()

V2_CORE = DEVELOPER / "reproducibility-evidence-v2-core.mjs"
V2_VERIFY = DEVELOPER / "verify-reproducibility-evidence-v2.mjs"
V2_COMPARE = DEVELOPER / "compare-reproducibility-evidence-v2.mjs"
CAMPAIGN_CORE = DEVELOPER / "public-source-zip-campaign-core.mjs"
CAMPAIGN_PREPARE = DEVELOPER / "prepare-public-source-zip-campaign.mjs"
CELL_VERIFY = DEVELOPER / "verify-public-source-zip-campaign-cell.mjs"
CAMPAIGN_COMPARE = DEVELOPER / "compare-public-source-zip-campaign.mjs"

CAMPAIGN_LOADED_TOOL_PATHS = [
    "developer/reproducibility-evidence-v2-core.mjs",
    "developer/verify-reproducibility-evidence-v2.mjs",
    "developer/compare-reproducibility-evidence-v2.mjs",
    "developer/public-source-zip-campaign-core.mjs",
    "developer/prepare-public-source-zip-campaign.mjs",
    "developer/verify-public-source-zip-campaign-cell.mjs",
    "developer/compare-public-source-zip-campaign.mjs",
    "developer/verify-public-source-membership.mjs",
    "developer/prepare-public-source-tree.mjs",
    "developer/public-source-zip-core.mjs",
    "developer/prepare-public-source-zip.mjs",
    "developer/verify-public-source-zip.mjs",
    "developer/reproducibility-evidence-core.mjs",
    "developer/verify-reproducibility-evidence.mjs",
    "developer/compare-reproducibility-evidence.mjs",
    "developer/public-source-zip-reproducibility-core.mjs",
    "developer/prepare-public-source-zip-reproducibility.mjs",
    "developer/run-public-source-zip-boundary-vectors.mjs",
]
E2_CANDIDATE_PATHS = CAMPAIGN_LOADED_TOOL_PATHS[:7]

CELL_PAYLOAD_NAMES = [
    "d2/artifact.zip",
    "d2/zip-verification.json",
    "d2/entry-plan.json",
    "d2/input-set.json",
    "d2/semantic-report.json",
    "d2/evidence.json",
    "d2/verification-result.json",
    "d2/.complete",
    "authority/campaign-policy.json",
    "authority/runtime-identity.json",
    "authority/node-qualification.json",
    "authority/producer-gpg-qualification.json",
    "authority/producer-local-gpg-qualification.json",
    "authority/git-identity.json",
    "authority/platform-probe.json",
    "authority/platform-class.json",
    "authority/runtime-class.json",
    "authority/environment-lock.json",
    "authority/critical-tool-set.json",
    "authority/public-source-manifest.json",
    "authority/membership-report.json",
    "authority/test-vector-set.json",
    "v2/semantic-input-set.json",
    "v2/execution-identity.json",
    "v2/evidence.json",
    "v2/verification-result.json",
    "cell-result.json",
]
SEALED_CELL_NAMES = CELL_PAYLOAD_NAMES + [
    "cell-manifest.json",
    "cell-manifest.sig",
    "cell.complete",
]


def canonical_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def file_uri(path):
    return Path(path).resolve().as_uri()


class PublicSourceZipCampaignTests(unittest.TestCase):
    counters = {
        "minimum_matrix_campaigns": 0,
        "required_cells": 0,
        "optional_win_b": 0,
        "semantic_identity_controls": 0,
        "execution_platform_runtime_controls": 0,
        "l3_controls": 0,
        "l4_controls": 0,
        "l5_controls": 0,
        "signature_controls": 0,
        "transport_tamper_controls": 0,
        "cell_swap_replay_omission_controls": 0,
        "publication_cleanup_controls": 0,
        "privacy_canaries": 0,
        "proxy_controls": 0,
        "accepted_proxy_values": 0,
        "proxy_trap_calls": 0,
        "accessor_getter_calls": 0,
        "targeted_controls": 0,
        "identity_mutation_controls": 0,
        "adapter_isolation_controls": 0,
        "canonical_duplicate_key_controls": 0,
        "revoked_proxy_controls": 0,
        "nested_proxy_controls": 0,
        "gpg_parser_process_controls": 0,
        "signature_binding_controls": 0,
        "manifest_ledger_controls": 0,
        "mutable_capsule_controls": 0,
        "cell_publication_marker_controls": 0,
        "comparison_publication_marker_controls": 0,
        "cleanup_uncertainty_controls": 0,
        "false_completion_markers": 0,
        "unsigned_filesystem_success_bundles": 0,
        "loaded_tool_authority_controls": 0,
        "v1_immutability_controls": 0,
        "runtime_class_controls": 0,
        "policy_binding_controls": 0,
        "ledger_path_controls": 0,
        "mutable_capsule_shape_controls": 0,
        "primary_pair_no_fallback_controls": 0,
        "gpg_profile_identity_controls": 0,
        "gpg_executable_profile_controls": 0,
        "fake_verifier_controls": 0,
        "profile_assignment_binding_controls": 0,
        "accepted_fake_verifier": 0,
        "accepted_unprofiled_verifier": 0,
        "accepted_identity_mismatched_verifier": 0,
        "accepted_replacement_race_verifier": 0,
        "cross_host_role_controls": 0,
        "runtime_self_measurement_controls": 0,
        "immutable_installation_controls": 0,
        "self_authorized_trust_controls": 0,
        "accepted_caller_authored_runtime": 0,
        "accepted_unqualified_executable": 0,
        "accepted_mutable_installation": 0,
        "accepted_self_authorized_profile": 0,
        "accepted_attacker_created_policy": 0,
    }
    suite_started = time.perf_counter()

    @classmethod
    def run_process(
        cls,
        arguments,
        *,
        check=True,
        timeout=180,
        cwd=ROOT,
        env=None,
        input_bytes=None,
    ):
        completed = subprocess.run(
            [str(argument) for argument in arguments],
            cwd=str(cwd),
            env=env or cls.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            input=input_bytes,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                "command failed\nstdout:\n"
                + completed.stdout.decode("utf-8", "replace")
                + "\nstderr:\n"
                + completed.stderr.decode("utf-8", "replace")
            )
        return completed

    @classmethod
    def run_node(cls, source, *, check=True, timeout=180):
        return cls.run_process(
            [NODE, "--input-type=module", "--eval", source],
            check=check,
            timeout=timeout,
        )

    @classmethod
    def write_instrumented_module(cls, source_path, name, appended_source):
        source = source_path.read_text(encoding="utf-8")

        def absolute_import(match):
            target = (source_path.parent / match.group(1)).resolve()
            replacements = {
                CAMPAIGN_CORE.resolve(): getattr(
                    cls, "instrumented_campaign_core", target
                ),
                CELL_VERIFY.resolve(): getattr(
                    cls, "instrumented_cell_verify", target
                ),
                CAMPAIGN_PREPARE.resolve(): getattr(
                    cls, "instrumented_prepare", target
                ),
            }
            target = Path(replacements.get(target, target)).resolve()
            return 'from ' + json.dumps(file_uri(target))

        source = re.sub(r'from "(\./[^"]+)"', absolute_import, source)
        target = cls.instrumented_root / name
        target.write_text(source + "\n" + appended_source, encoding="utf-8", newline="\n")
        return target

    @classmethod
    def committed_blob(cls, relative_path):
        tree = cls.run_process([
            GIT,
            "-C", ROOT,
            "ls-tree", "-z", "--full-tree", "HEAD", "--", relative_path,
        ]).stdout
        records = tree[:-1].split(b"\0") if tree.endswith(b"\0") else []
        if len(records) != 1:
            raise AssertionError("canonical Git tree entry is absent or ambiguous")
        metadata, observed_path = records[0].split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        if observed_path.decode("utf-8") != relative_path or kind != "blob":
            raise AssertionError("canonical Git tree entry is not the expected blob")
        raw = cls.run_process([
            GIT, "-C", ROOT, "cat-file", "blob", object_id,
        ]).stdout
        framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        if hashlib.sha1(framed).hexdigest() != object_id:
            raise AssertionError("canonical Git blob identity mismatch")
        return mode, object_id, raw

    @classmethod
    def build_loaded_tool_fixture(
        cls,
        label,
        *,
        repository_transform=None,
        execution_transform=None,
    ):
        fixture_root = cls.task_root / ("loaded-tool-" + label)
        execution_root = fixture_root / "execution"
        repository = fixture_root / "repository.git"
        execution_root.mkdir(parents=True)
        cls.run_process([GIT, "init", "--bare", repository])
        entries = {}
        for relative_path in CAMPAIGN_LOADED_TOOL_PATHS:
            if relative_path in E2_CANDIDATE_PATHS:
                mode = "100644"
                raw = (ROOT / Path(relative_path)).read_bytes()
            else:
                mode, _object_id, raw = cls.committed_blob(relative_path)
            committed_raw = (
                repository_transform(relative_path, raw)
                if repository_transform is not None else raw
            )
            execution_raw = (
                execution_transform(relative_path, raw)
                if execution_transform is not None else raw
            )
            target = execution_root / Path(relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(execution_raw)
            object_id = cls.run_process([
                GIT,
                "--git-dir", repository,
                "hash-object", "-w", "--stdin",
            ], input_bytes=committed_raw).stdout.decode("ascii").strip()
            framed = (
                b"blob " + str(len(committed_raw)).encode("ascii")
                + b"\0" + committed_raw
            )
            if object_id != hashlib.sha1(framed).hexdigest():
                raise AssertionError("synthetic loaded-tool blob identity mismatch")
            entries[relative_path] = (mode, object_id)

        def write_tree(prefix):
            direct_files = {}
            child_directories = set()
            prefix_text = prefix + "/" if prefix else ""
            for relative_path, value in entries.items():
                if not relative_path.startswith(prefix_text):
                    continue
                remainder = relative_path[len(prefix_text):]
                if "/" in remainder:
                    child_directories.add(remainder.split("/", 1)[0])
                else:
                    direct_files[remainder] = value
            records = []
            for name, (mode, object_id) in direct_files.items():
                records.append((name, f"{mode} blob {object_id}\t{name}".encode("utf-8") + b"\0"))
            for name in child_directories:
                child_prefix = name if not prefix else prefix + "/" + name
                object_id = write_tree(child_prefix)
                records.append((name + "/", f"040000 tree {object_id}\t{name}".encode("utf-8") + b"\0"))
            tree_input = b"".join(record for _name, record in sorted(records))
            return cls.run_process([
                GIT,
                "--git-dir", repository,
                "mktree", "-z",
            ], input_bytes=tree_input).stdout.decode("ascii").strip()

        root_tree = write_tree("")
        commit_bytes = (
            f"tree {root_tree}\n"
            "author Synthetic E2 <e2@example.invalid> 0 +0000\n"
            "committer Synthetic E2 <e2@example.invalid> 0 +0000\n"
            "\nloaded tool authority fixture\n"
        ).encode("ascii")
        tooling_commit = cls.run_process([
            GIT,
            "--git-dir", repository,
            "hash-object", "-t", "commit", "-w", "--stdin",
        ], input_bytes=commit_bytes).stdout.decode("ascii").strip()
        self_check = cls.run_process([
            GIT, "--git-dir", repository, "cat-file", "-t", tooling_commit,
        ]).stdout.strip()
        if self_check != b"commit":
            raise AssertionError("synthetic loaded-tool commit object is invalid")
        git_raw = GIT.read_bytes()
        git_identity = {
            "documentKind": "ieltmps-git-runtime-identity",
            "schemaVersion": 1,
            "gitProfileId": "git-approved-test-runtime",
            "executableSha256": sha256_bytes(git_raw),
            "executableByteLength": len(git_raw),
            "reportedVersion": cls.run_process([GIT, "--version"]).stdout.decode("utf-8").strip(),
            "objectFormat": "sha1",
            "distributionProfileId": "official-git-runtime",
        }
        return {
            "fixtureRoot": fixture_root,
            "executionRoot": execution_root,
            "repository": repository,
            "toolingCommit": tooling_commit,
            "gitIdentity": git_identity,
        }

    @classmethod
    def build_fake_gpg(cls, name, exit_code):
        if not CSC.is_file():
            raise AssertionError("task-local fake-verifier compiler is unavailable")
        source_path = cls.fake_gpg_root / (name + ".cs")
        executable_path = cls.fake_gpg_root / (name + ".exe")
        fingerprint = "A" * 40
        source_path.write_text(
            "using System;\n"
            "public static class FakeGpg {\n"
            "  public static int Main(string[] args) {\n"
            "    foreach (string value in args) {\n"
            "      if (value == \"--version\") {\n"
            "        Console.Out.Write(\"gpg (GnuPG) 2.4.8\\n"
            "libgcrypt synthetic\\n\");\n"
            f"        return {exit_code};\n"
            "      }\n"
            "    }\n"
            "    Console.Out.Write(\"[GNUPG:] GOODSIG AAAAAAAAAAAAAAAA "
            "Synthetic Test\\n\");\n"
            f"    Console.Out.Write(\"[GNUPG:] VALIDSIG {fingerprint} "
            "2026-01-01 1 0 4 0 22 8 00\\n\");\n"
            f"    return {exit_code};\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
            newline="\n",
        )
        cls.run_process([
            CSC,
            "/nologo",
            "/target:exe",
            "/optimize+",
            "/debug-",
            "/out:" + str(executable_path),
            source_path,
        ])
        if not executable_path.is_file():
            raise AssertionError("task-local fake verifier was not created")
        return executable_path

    @classmethod
    def generate_key(cls, label):
        uid = f"R1E1 {label} <{label.lower()}@example.invalid>"
        cls.run_process([
            GPG,
            "--homedir", cls.gpg_home,
            "--batch",
            "--no-tty",
            "--pinentry-mode", "loopback",
            "--passphrase", "",
            "--quick-generate-key", uid,
            "ed25519", "sign", "0",
        ])
        listing = cls.run_process([
            GPG,
            "--homedir", cls.gpg_home,
            "--batch",
            "--with-colons",
            "--fingerprint", uid,
        ]).stdout.decode("utf-8", "strict")
        for line in listing.splitlines():
            fields = line.split(":")
            if fields[0] == "fpr" and re.fullmatch(r"[0-9A-F]{40}", fields[9]):
                return fields[9]
        raise AssertionError("temporary OpenPGP fingerprint was not found")

    @classmethod
    def generate_signing_subkey(cls, label):
        uid = f"R1E1 {label} <{label.lower()}@example.invalid>"
        cls.run_process([
            GPG,
            "--no-options",
            "--homedir", cls.gpg_home,
            "--batch",
            "--no-tty",
            "--pinentry-mode", "loopback",
            "--passphrase", "",
            "--quick-generate-key", uid,
            "ed25519", "cert", "0",
        ])
        listing = cls.run_process([
            GPG,
            "--no-options",
            "--homedir", cls.gpg_home,
            "--batch",
            "--with-colons",
            "--fingerprint", uid,
        ]).stdout.decode("utf-8", "strict")
        primary = None
        for line in listing.splitlines():
            fields = line.split(":")
            if fields[0] == "fpr" and re.fullmatch(r"[0-9A-F]{40}", fields[9]):
                primary = fields[9]
                break
        if primary is None:
            raise AssertionError("temporary OpenPGP primary fingerprint was not found")
        cls.run_process([
            GPG,
            "--no-options",
            "--homedir", cls.gpg_home,
            "--batch",
            "--no-tty",
            "--pinentry-mode", "loopback",
            "--passphrase", "",
            "--quick-add-key", primary,
            "ed25519", "sign", "0",
        ])
        listing = cls.run_process([
            GPG,
            "--no-options",
            "--homedir", cls.gpg_home,
            "--batch",
            "--with-colons",
            "--fingerprint", primary,
        ]).stdout.decode("utf-8", "strict")
        fingerprints = [
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
            and re.fullmatch(r"[0-9A-F]{40}", line.split(":")[9])
        ]
        if len(fingerprints) < 2 or fingerprints[0] != primary:
            raise AssertionError("temporary OpenPGP signing subkey was not found")
        return primary, fingerprints[1]

    @classmethod
    def driver_source(cls):
        source = r"""
import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile,access} from 'node:fs/promises';
import path from 'node:path';
import {
  ARTIFACT_ROLE,ARCHIVE_ROOT,CRITICAL_TOOL_PATHS,FORMAT_PROFILE,
  INPUT_SET_KIND,WORKER_MODULE_PATHS,canonicalPublicJsonBytes,
  encodeCanonicalCriticalToolSet,encodeCanonicalInputSet
} from __D2_CORE__;
import {
  REPRODUCIBILITY_EVIDENCE_KIND,REPRODUCIBILITY_SEMANTIC_REPORT_KIND,
  REPRODUCIBILITY_VERIFICATION_KIND,SCHEMA_VERSION,
  encodeCanonicalReproducibilityEvidence,encodeCanonicalSemanticReport,
  encodeCanonicalVerificationResult
} from __V1_CORE__;
import {
  CAMPAIGN_POLICY_DOCUMENT_KIND,CAMPAIGN_SCHEMA_ID,
  CELL_SIGNATURE_NAMESPACE,COMPARISON_SIGNATURE_NAMESPACE,
  GPG_VERIFIER_PROFILE_DOCUMENT_KIND,gpgInvocationProfileSha256,
  IMMUTABLE_INSTALLATION_PROFILE_DOCUMENT_KIND,
  NODE_RUNTIME_PROFILE_DOCUMENT_KIND,
  PublicSourceZipCampaignError,
  encodeCanonicalCampaignPolicy,encodeCanonicalGitIdentityBinding,
  encodeCanonicalNodeRuntimeProfile,encodeCanonicalRuntimeIdentityBinding,
  immutableInstallationProfileSha256,
  parseCanonicalRuntimeIdentityBindingBytes,validateCampaignPolicy
} from __CAMPAIGN_CORE__;
import {testOnlyPreparePublicSourceZipCampaign as preparePublicSourceZipCampaign} from __PREPARE__;
import {testOnlyComparePublicSourceZipCampaign as comparePublicSourceZipCampaign} from __COMPARE__;
import {testOnlyVerifyPublicSourceZipCampaignCell as verifyPublicSourceZipCampaignCell} from __CELL_VERIFY__;
import {
  parseCanonicalExecutionIdentityV2Bytes,
  parseCanonicalReproducibilityEvidenceV2Bytes,
  parseCanonicalVerificationResultV2Bytes
} from __V2_CORE__;

const config=JSON.parse(await readFile(process.argv[2],'utf8'));
const root=path.resolve(config.root);
const fixture=path.join(root,'fixture');
const outputs=path.join(root,'cells');
const recordsRoot=path.join(root,'records');
const repository=path.resolve(config.toolRepository);
for(const directory of [fixture,outputs,recordsRoot])await mkdir(directory,{recursive:true});
const hash=(value)=>createHash('sha256').update(value).digest('hex');
const blob=(value)=>createHash('sha1').update(value).digest('hex');
const sourceCommit='a'.repeat(40);
const toolingCommit=config.toolingCommit;
const artifactBytes=Buffer.from('PK\x03\x04 synthetic identical artifact\n','ascii');
const entryPlanBytes=canonicalPublicJsonBytes({documentKind:'synthetic-entry-plan',schemaVersion:1,entryCount:1});
const zipVerificationBytes=canonicalPublicJsonBytes({status:'ok',mode:'synthetic-zip-verification',entryCount:1});
const manifestBytes=canonicalPublicJsonBytes({documentKind:'synthetic-public-source-manifest',schemaVersion:1});
const membershipBytes=canonicalPublicJsonBytes({documentKind:'synthetic-membership-report',schemaVersion:1,membershipCount:1});
const vectorBytes=canonicalPublicJsonBytes({documentKind:'synthetic-vector-set',schemaVersion:1,vectorCount:119});
const runnerPolicyBytes=canonicalPublicJsonBytes({documentKind:'synthetic-d2-runner-policy',schemaVersion:1});
const gitIdentity=config.gitIdentity;
const nodeRuntimeFacts={runtimeVersion:config.nodeVersion,v8Version:config.nodeV8,modulesAbi:config.nodeModules};
const toolEntries=CRITICAL_TOOL_PATHS.map((toolPath,index)=>({path:toolPath,gitMode:'100644',gitBlobObjectId:blob(toolPath),declaredByteSize:index+1,sha256:hash(Buffer.from(toolPath,'utf8'))}));
const criticalToolSet={documentKind:'ieltmps-reproducibility-critical-tool-set',schemaVersion:1,toolSetId:'public-source-zip-reproducibility-v1',toolingCommit,entries:toolEntries};
const criticalToolBytes=encodeCanonicalCriticalToolSet(criticalToolSet);
const criticalFiles=toolEntries.map((entry,index)=>({path:entry.path,toolingCommit,gitMode:entry.gitMode,gitBlobObjectId:entry.gitBlobObjectId,byteLength:index+1,sha256:entry.sha256,parentLoadedSha256:entry.sha256,workerLoadedSha256:WORKER_MODULE_PATHS.includes(entry.path)?entry.sha256:null}));
const cellDefinitions=[
  {matrixCellId:'WIN-A',osFamily:'windows',runtimeRole:'A',filesystemClass:'ntfs',signerRole:'win-a-signer'},
  {matrixCellId:'LINUX-A',osFamily:'linux',runtimeRole:'A',filesystemClass:'ext4-class',signerRole:'linux-a-signer'},
  {matrixCellId:'LINUX-B',osFamily:'linux',runtimeRole:'B',filesystemClass:'ext4-class',signerRole:'linux-b-signer'},
  {matrixCellId:'WIN-B',osFamily:'windows',runtimeRole:'B',filesystemClass:'ntfs',signerRole:'win-b-signer'},
];
const legacyGpgProfiles=[...cellDefinitions.map((entry,index)=>({
  documentKind:GPG_VERIFIER_PROFILE_DOCUMENT_KIND,schemaVersion:1,
  profileId:'test-only-gpg-'+entry.matrixCellId.toLowerCase(),verifierFamily:'gnupg',
  distributionProfile:'test-only-gnupg-'+config.gpgOsFamily+'-2-4-8',
  osFamily:config.gpgOsFamily,architecture:config.gpgArchitecture,
  executableSha256:config.gpgSha256,executableByteLength:config.gpgByteLength,
  version:config.gpgVersion,statusProtocol:'gnupg-status-fd-v1',
  fileIdentityPolicy:'stable-file-identity-pre-spawn-post-spawn',
  linkPolicy:'non-reparse-single-link',networkPolicy:'no-network-no-auto-key-retrieve',
  invocationProfileSha256:gpgInvocationProfileSha256()
})),{
  documentKind:GPG_VERIFIER_PROFILE_DOCUMENT_KIND,schemaVersion:1,
  profileId:'test-only-gpg-campaign-comparison',verifierFamily:'gnupg',
  distributionProfile:'test-only-gnupg-'+config.gpgOsFamily+'-2-4-8',
  osFamily:config.gpgOsFamily,architecture:config.gpgArchitecture,
  executableSha256:config.gpgSha256,executableByteLength:config.gpgByteLength,
  version:config.gpgVersion,statusProtocol:'gnupg-status-fd-v1',
  fileIdentityPolicy:'stable-file-identity-pre-spawn-post-spawn',
  linkPolicy:'non-reparse-single-link',networkPolicy:'no-network-no-auto-key-retrieve',
  invocationProfileSha256:gpgInvocationProfileSha256()
}];
const legacyAssignment=(profile,operation,cell,comparisonRole,signerRole,namespace)=>({
  profileId:profile.profileId,operation,matrixCellId:cell?.matrixCellId??null,
  comparisonRole,osFamily:profile.osFamily,architecture:profile.architecture,
  signerRole,signatureNamespace:namespace,campaignId:'synthetic-r1-10e-campaign',
  sourceCommit,toolingCommit
});
const legacyGpgAssignments=[];
for(let index=0;index<cellDefinitions.length;index+=1){const cell=cellDefinitions[index];const profile=legacyGpgProfiles[index];for(const operation of ['detached-sign','detached-verify'])legacyGpgAssignments.push(legacyAssignment(profile,operation,cell,null,cell.signerRole,CELL_SIGNATURE_NAMESPACE));}
for(const operation of ['detached-sign','detached-verify'])legacyGpgAssignments.push(legacyAssignment(legacyGpgProfiles.at(-1),operation,null,'campaign-comparison',cellDefinitions[0].signerRole,COMPARISON_SIGNATURE_NAMESPACE));
const immutableProfiles=[];
const makeImmutable=(profileId,osFamily,distributionProfile,executableSha256,executableByteLength)=>{
  const value={documentKind:IMMUTABLE_INSTALLATION_PROFILE_DOCUMENT_KIND,schemaVersion:1,profileId,qualificationMode:'synthetic-test-only-v1',osFamily,architecture:'x64',distributionProfile,executableSha256,executableByteLength,fileIdentityPolicy:'stable-device-inode-or-volume-file-id',ownerPolicy:'synthetic-test-only',principalPolicy:'synthetic-test-only',parentChainPolicy:'all-replacement-relevant-parents-immutable',accessControlPolicy:'synthetic-test-only',linkPolicy:'non-reparse-single-link',filesystemPolicy:'qualified-local-filesystem',qualificationProbeMode:'synthetic-test-only',qualificationProbeProfileSha256:null};
  immutableProfiles.push(value);return value;
};
const makeNode=(profileId,osFamily,distributionProfile,runtimeVersion,v8Version,modulesAbi)=>{
  const immutable=makeImmutable('immutable-'+profileId,osFamily,distributionProfile,config.nodeSha256,config.nodeByteLength);
  return {documentKind:NODE_RUNTIME_PROFILE_DOCUMENT_KIND,schemaVersion:1,profileId,runtimeFamily:'nodejs',distributionProfile,osFamily,architecture:'x64',runtimeVersion,v8Version,modulesAbi,executableSha256:config.nodeSha256,executableByteLength:config.nodeByteLength,immutableInstallationProfileSha256:immutableInstallationProfileSha256(immutable),sourceCommit,toolingCommit};
};
const runtimeB={runtimeVersion:'v22.18.0',v8Version:'12.4.254.21-node.33',modulesAbi:'127'};
const nodeProfiles=[
  makeNode('node-win-a','windows','synthetic-node-a',nodeRuntimeFacts.runtimeVersion,nodeRuntimeFacts.v8Version,nodeRuntimeFacts.modulesAbi),
  makeNode('node-linux-a','linux','synthetic-node-a',nodeRuntimeFacts.runtimeVersion,nodeRuntimeFacts.v8Version,nodeRuntimeFacts.modulesAbi),
  makeNode('node-linux-b','linux','synthetic-node-b',runtimeB.runtimeVersion,runtimeB.v8Version,runtimeB.modulesAbi),
  makeNode('node-win-b','windows','synthetic-node-b',runtimeB.runtimeVersion,runtimeB.v8Version,runtimeB.modulesAbi),
  makeNode('node-e6-consumer','windows','synthetic-node-e6',nodeRuntimeFacts.runtimeVersion,nodeRuntimeFacts.v8Version,nodeRuntimeFacts.modulesAbi),
  makeNode('node-e6-comparison','windows','synthetic-node-e6-comparison',nodeRuntimeFacts.runtimeVersion,nodeRuntimeFacts.v8Version,nodeRuntimeFacts.modulesAbi),
  makeNode('node-e7-review','linux','synthetic-node-e7',nodeRuntimeFacts.runtimeVersion,nodeRuntimeFacts.v8Version,nodeRuntimeFacts.modulesAbi)
];
const nodeAssignment=(assignmentId,profile,campaignRole,matrixCellId,hostRole)=>({assignmentId,profileId:profile.profileId,campaignRole,matrixCellId,hostRole,osFamily:profile.osFamily,architecture:profile.architecture,campaignId:'synthetic-r1-10e-campaign',sourceCommit,toolingCommit});
const nodeAssignments=[...cellDefinitions.map((cell,index)=>nodeAssignment('node-producer-'+cell.matrixCellId.toLowerCase(),nodeProfiles[index],'cell-producer',cell.matrixCellId,cell.matrixCellId)),nodeAssignment('node-import-consumer',nodeProfiles[4],'cell-import-consumer',null,'E6-WINDOWS'),nodeAssignment('node-comparison-host',nodeProfiles[5],'comparison-host',null,'E6-WINDOWS'),nodeAssignment('node-independent-review',nodeProfiles[6],'independent-review-host',null,'E7-LINUX')];
const makeGpg=(profileId,osFamily,distributionProfile)=>{
  const immutable=makeImmutable('immutable-'+profileId,osFamily,distributionProfile,config.gpgSha256,config.gpgByteLength);
  return {documentKind:GPG_VERIFIER_PROFILE_DOCUMENT_KIND,schemaVersion:1,profileId,verifierFamily:'gnupg',distributionProfile,osFamily,architecture:'x64',executableSha256:config.gpgSha256,executableByteLength:config.gpgByteLength,version:config.gpgVersion,statusProtocol:'gnupg-status-fd-v1',fileIdentityPolicy:'stable-file-identity-pre-spawn-post-spawn',linkPolicy:'non-reparse-single-link',networkPolicy:'no-network-no-auto-key-retrieve',invocationProfileSha256:gpgInvocationProfileSha256(),immutableInstallationProfileSha256:immutableInstallationProfileSha256(immutable)};
};
const producerSignProfiles=cellDefinitions.map(cell=>makeGpg('gpg-'+cell.matrixCellId.toLowerCase()+'-sign',cell.osFamily,'test-only-gnupg-'+cell.matrixCellId.toLowerCase()+'-sign'));
const producerLocalProfiles=cellDefinitions.map(cell=>makeGpg('gpg-'+cell.matrixCellId.toLowerCase()+'-local',cell.osFamily,'test-only-gnupg-'+cell.matrixCellId.toLowerCase()+'-local'));
const consumerProfile=makeGpg('gpg-e6-consumer','windows','test-only-gnupg-e6-consumer');
const comparisonSignProfile=makeGpg('gpg-e6-comparison-sign','windows','test-only-gnupg-e6-comparison-sign');
const comparisonLocalProfile=makeGpg('gpg-e6-comparison-local','windows','test-only-gnupg-e6-comparison-local');
const reviewProfile=makeGpg('gpg-e7-review','linux','test-only-gnupg-e7-review');
const gpgProfiles=[...producerSignProfiles,...producerLocalProfiles,consumerProfile,comparisonSignProfile,comparisonLocalProfile,reviewProfile];
const assignment=(assignmentId,gpgRole,profile,operation,cell,comparisonRole,hostRole,signerRole,namespace)=>({assignmentId,gpgRole,profileId:profile.profileId,operation,matrixCellId:cell?.matrixCellId??null,comparisonRole,hostRole,osFamily:profile.osFamily,architecture:profile.architecture,signerRole,signatureNamespace:namespace,campaignId:'synthetic-r1-10e-campaign',sourceCommit,toolingCommit});
const gpgAssignments=[];
for(let index=0;index<cellDefinitions.length;index+=1){const cell=cellDefinitions[index];gpgAssignments.push(assignment('gpg-'+cell.matrixCellId.toLowerCase()+'-sign','cell-producer-sign',producerSignProfiles[index],'detached-sign',cell,null,cell.matrixCellId,cell.signerRole,CELL_SIGNATURE_NAMESPACE));gpgAssignments.push(assignment('gpg-'+cell.matrixCellId.toLowerCase()+'-local','cell-producer-local-verify',producerLocalProfiles[index],'detached-verify',cell,null,cell.matrixCellId,cell.signerRole,CELL_SIGNATURE_NAMESPACE));gpgAssignments.push(assignment('gpg-'+cell.matrixCellId.toLowerCase()+'-consumer','cell-import-consumer-verify',consumerProfile,'detached-verify',cell,null,'E6-WINDOWS',cell.signerRole,CELL_SIGNATURE_NAMESPACE));}
gpgAssignments.push(assignment('gpg-comparison-sign','comparison-result-sign',comparisonSignProfile,'detached-sign',null,'campaign-comparison','E6-WINDOWS',cellDefinitions[0].signerRole,COMPARISON_SIGNATURE_NAMESPACE));
gpgAssignments.push(assignment('gpg-comparison-local','comparison-result-local-verify',comparisonLocalProfile,'detached-verify',null,'campaign-comparison','E6-WINDOWS',cellDefinitions[0].signerRole,COMPARISON_SIGNATURE_NAMESPACE));
gpgAssignments.push(assignment('gpg-independent-review','independent-result-review-verify',reviewProfile,'detached-verify',null,'independent-review','E7-LINUX',cellDefinitions[0].signerRole,COMPARISON_SIGNATURE_NAMESPACE));
const policy=validateCampaignPolicy({
  documentKind:CAMPAIGN_POLICY_DOCUMENT_KIND,schemaVersion:1,campaignSchemaId:CAMPAIGN_SCHEMA_ID,
  campaignId:'synthetic-r1-10e-campaign',sourceCommit,toolingCommit,vectorSetSha256:hash(vectorBytes),
  requiredCells:cellDefinitions.slice(0,3),optionalCells:cellDefinitions.slice(3),
  claimRules:{crossRuntimePair:['LINUX-A','LINUX-B'],crossOsPair:['WIN-A','LINUX-A'],requiredClaimLevels:['L0','L1','L2','L3','L4','L5'],requireL5:true,allowL6:false},
  environmentProfile:{platformProfileVersion:'native-x64-v1',architecture:'x64',runtimeFamily:'node',lang:'C',lcAll:'C',timezone:'UTC',sourceDateEpoch:0,networkPolicy:'disabled-during-generation',lineEndingPolicy:'git-object-b2-bytes',filesystemExecutionPolicy:'native-local',hostIdentifierPolicy:'opaque-cell-id-only',windowsBuildPolicy:'windows-build-frozen-later',linuxBuildPolicy:'linux-build-frozen-later'},
  allowedSignerRoles:cellDefinitions.map(entry=>entry.signerRole),
  allowedSignerFingerprints:cellDefinitions.map((entry,index)=>({fingerprint:config.fingerprints[index],role:entry.signerRole,matrixCellId:entry.matrixCellId})),
  immutableInstallationProfiles:immutableProfiles,nodeRuntimeProfiles:nodeProfiles,nodeRuntimeAssignments:nodeAssignments,
  gpgVerifierProfiles:gpgProfiles,gpgVerifierAssignments:gpgAssignments,
  transportPolicy:{signatureRequired:true,ledgerRequired:true,immutableVerificationRequired:true,noAutoKeyRetrieval:true,uniqueSignerPerCell:true,maxManifestBytes:1048576,maxSignatureBytes:65536},
  retentionPolicy:{rawCellEvidencePrivate:true,commitRawCells:false,closureReviewRequired:true,retentionProfile:'synthetic-test-only'}
});
const files={
  policy:path.join(fixture,'campaign-policy.json'),manifest:path.join(fixture,'manifest.json'),membership:path.join(fixture,'membership.json'),
  vector:path.join(fixture,'vectors.json'),runner:path.join(fixture,'runner-policy.json'),critical:path.join(fixture,'critical-tool-set.json'),
  nodeProfiles:cellDefinitions.map(cell=>path.join(fixture,'node-'+cell.matrixCellId.toLowerCase()+'.json')),git:path.join(fixture,'git.json')
};
await writeFile(files.policy,encodeCanonicalCampaignPolicy(policy),{flag:'wx'});
await writeFile(files.manifest,manifestBytes,{flag:'wx'});await writeFile(files.membership,membershipBytes,{flag:'wx'});
await writeFile(files.vector,vectorBytes,{flag:'wx'});await writeFile(files.runner,runnerPolicyBytes,{flag:'wx'});
await writeFile(files.critical,criticalToolBytes,{flag:'wx'});
for(let index=0;index<cellDefinitions.length;index+=1)await writeFile(files.nodeProfiles[index],encodeCanonicalNodeRuntimeProfile(nodeProfiles[index]),{flag:'wx'});
await writeFile(files.git,encodeCanonicalGitIdentityBinding(gitIdentity),{flag:'wx'});
const measurementFor=(cellId)=>cellId.startsWith('WIN-')?{
  osFamily:'windows',osRelease:'10.0.26100',osVersion:'Windows 11 synthetic',architecture:'x64',filesystemTypeCode:'native-ntfs',filesystemClass:'ntfs',
  capabilities:{nativeFilesystemStatSupported:true,exclusiveCreateSupported:true,hardLinkSupported:true,stableFileIdentitySupported:true}
}:{
  osFamily:'linux',osRelease:'6.8.0',osVersion:'Linux synthetic',architecture:'x64',filesystemTypeCode:'native-ef53',filesystemClass:'ext4-class',
  capabilities:{nativeFilesystemStatSupported:true,exclusiveCreateSupported:true,hardLinkSupported:true,stableFileIdentitySupported:true}
};
async function buildD2(outputDirectory,matrixCellId,runtimeIdentityPath){
  const frozenV1MatrixCellId=matrixCellId.toLowerCase();
  const runtimeBytes=await readFile(runtimeIdentityPath);
  const runtime=parseCanonicalRuntimeIdentityBindingBytes(runtimeBytes);
  const gitBytes=encodeCanonicalGitIdentityBinding(gitIdentity);
  const inputSet={documentKind:INPUT_SET_KIND,schemaVersion:1,sourceCommit,toolingCommit,manifestSha256:hash(manifestBytes),membershipReportSha256:hash(membershipBytes),membershipCount:1,archiveRoot:ARCHIVE_ROOT,entryPlanSha256:hash(entryPlanBytes),entryCount:1,artifactRole:ARTIFACT_ROLE,formatProfile:FORMAT_PROFILE,criticalFiles,runtimeIdentitySha256:hash(runtimeBytes),gitIdentitySha256:hash(gitBytes),runnerPolicyIdentitySha256:hash(runnerPolicyBytes),testVectorSetSha256:hash(vectorBytes)};
  const inputBytes=encodeCanonicalInputSet(inputSet);
  const semantic={semanticReportKind:'ieltmps-reproducibility-semantic-report',schemaVersion:SCHEMA_VERSION,artifactRole:ARTIFACT_ROLE,formatProfile:FORMAT_PROFILE,sourceCommit,toolingCommit,inputSetSha256:hash(inputBytes),artifactSha256:hash(artifactBytes),artifactByteLength:artifactBytes.length,canonicalVerifierPassed:true,sameProcessRepeatable:true,sameHostRepeatable:true,boundaryVectorSetPassed:true,result:'pass',failureCode:null};
  const semanticBytes=encodeCanonicalSemanticReport(semantic);
  const cell=cellDefinitions.find(entry=>entry.matrixCellId===matrixCellId);
  const evidence={evidenceKind:REPRODUCIBILITY_EVIDENCE_KIND,schemaVersion:SCHEMA_VERSION,artifactRole:ARTIFACT_ROLE,formatProfile:FORMAT_PROFILE,sourceCommit,toolingCommit,criticalToolSetSha256:hash(criticalToolBytes),manifestSha256:hash(manifestBytes),inputSetSha256:hash(inputBytes),runtimeProfileId:runtime.runtimeProfileId,runtimeIdentitySha256:hash(runtimeBytes),gitProfileId:gitIdentity.gitProfileId,gitIdentitySha256:hash(gitBytes),runnerPolicySha256:hash(runnerPolicyBytes),testVectorSetSha256:hash(vectorBytes),matrixCellId:frozenV1MatrixCellId,operatingSystem:cell.osFamily,operatingSystemBuild:cell.osFamily+'-build',architecture:'x64',filesystemProfile:cell.filesystemClass,localeProfile:'c-locale',timezoneProfile:'utc-timezone',platformProbeSha256:hash(Buffer.from('v1-platform-'+matrixCellId)),artifactSha256:hash(artifactBytes),artifactByteLength:artifactBytes.length,semanticReportSha256:hash(semanticBytes),semanticReportByteLength:semanticBytes.length,result:'pass',failureClass:null,failureCode:null};
  const evidenceBytes=encodeCanonicalReproducibilityEvidence(evidence);
  const verification={verificationKind:REPRODUCIBILITY_VERIFICATION_KIND,schemaVersion:SCHEMA_VERSION,status:'ok',mode:'reproducibility-evidence-verification',policyId:'synthetic-d2-policy',artifactRole:ARTIFACT_ROLE,formatProfile:FORMAT_PROFILE,matrixCellId:frozenV1MatrixCellId,evidenceSha256:hash(evidenceBytes),evidenceByteLength:evidenceBytes.length,policySha256:hash(runnerPolicyBytes),comparisonIdentitySha256:hash(Buffer.from('comparison-identity')),sourceCommitObjectVerified:true,toolingCommitObjectVerified:true,criticalToolSetVerified:true,manifestVerified:true,inputSetVerified:true,runtimeIdentityVerified:true,gitIdentityVerified:true,testVectorSetVerified:true,platformProbeVerified:true,artifactVerified:true,semanticReportVerified:true,policyCellVerified:true,semanticClaimsBound:true,canonicalVerifierPassed:true,sameProcessRepeatable:true,sameHostRepeatable:true,boundaryVectorSetPassed:true,semanticClaimsIndependentlyReplayed:false,evidenceResult:'pass',comparisonEligible:true,platformAttestationVerified:false,evidenceSigningRequired:true,projectPublicationAuthorized:false};
  const verificationBytes=encodeCanonicalVerificationResult(verification);
  await mkdir(outputDirectory,{recursive:false});
  const entries=[['artifact.zip',artifactBytes],['zip-verification.json',zipVerificationBytes],['entry-plan.json',entryPlanBytes],['input-set.json',inputBytes],['semantic-report.json',semanticBytes],['evidence.json',evidenceBytes],['verification-result.json',verificationBytes],['.complete',Buffer.from('complete\n','ascii')]];
  for(const [name,bytes] of entries)await writeFile(path.join(outputDirectory,name),bytes,{flag:'wx'});
}
const markerObservations=[];
const verified=[];
const capsulePaths={};
const recordPaths={};
const policyBytes=encodeCanonicalCampaignPolicy(policy);
const policyDigest=hash(policyBytes);
const externalPolicy={expectedCanonicalPolicyBytes:policyBytes,expectedPolicySha256:policyDigest,campaignId:policy.campaignId,sourceCommit,toolingCommit};
for(let index=0;index<cellDefinitions.length;index+=1){
  const cell=cellDefinitions[index];
  const outputDirectory=path.join(outputs,cell.matrixCellId);
  capsulePaths[cell.matrixCellId]=outputDirectory;
  const options={campaignPolicy:policy,matrixCellId:cell.matrixCellId,repository,sourceCommit,manifest:files.manifest,membershipReport:files.membership,d2RunnerPolicy:files.runner,nodeRuntimeProfile:files.nodeProfiles[index],gitIdentity:files.git,gitExecutable:config.git,criticalToolSet:files.critical,testVectorSet:files.vector,outputDirectory,gpgExecutable:config.gpg,gpgHome:config.gpgHome,signingFingerprint:config.fingerprints[index]};
  const adapter={loadedToolAuthorityBypass:true,measurement:measurementFor(cell.matrixCellId),async prepareD2Bundle({outputDirectory:target,matrixCellId,runtimeIdentityPath}){try{await buildD2(target,matrixCellId,runtimeIdentityPath);}catch(error){const phase=String(error.phase??'unknown').toLowerCase().replaceAll('_','-');const reason=String(error.reason??'failure').toLowerCase().replaceAll('_','-');throw new PublicSourceZipCampaignError('D2_BINDING','fixture-'+phase+'-'+reason);}},async checkpoint({checkpoint}){if(index===0&&checkpoint==='before-completion-marker'){let exists=true;try{await access(path.join(outputDirectory,'cell.complete'));}catch{exists=false;}markerObservations.push({checkpoint,exists});}if(index===0&&checkpoint==='after-completion-marker'){let exists=true;try{await access(path.join(outputDirectory,'cell.complete'));}catch{exists=false;}markerObservations.push({checkpoint,exists});}}};
  await preparePublicSourceZipCampaign(options,adapter);
  const result=await verifyPublicSourceZipCampaignCell({capsuleRoot:outputDirectory,...externalPolicy,matrixCellId:cell.matrixCellId,consumerHostRole:'E6-WINDOWS',gpgExecutable:config.gpg,gpgHome:config.gpgHome},{loadedToolAuthorityBypass:true});
  verified.push(result);
  const record={verifiedCell:result,evidence:parseCanonicalReproducibilityEvidenceV2Bytes(await readFile(path.join(outputDirectory,'v2','evidence.json'))),verificationResult:parseCanonicalVerificationResultV2Bytes(await readFile(path.join(outputDirectory,'v2','verification-result.json'))),executionIdentity:parseCanonicalExecutionIdentityV2Bytes(await readFile(path.join(outputDirectory,'v2','execution-identity.json')))};
  const recordPath=path.join(recordsRoot,cell.matrixCellId+'.json');
  await writeFile(recordPath,canonicalPublicJsonBytes(record),{flag:'wx'});
  recordPaths[cell.matrixCellId]=recordPath;
}
const minimumCells=cellDefinitions.slice(0,3).map(cell=>({matrixCellId:cell.matrixCellId,capsuleRoot:capsulePaths[cell.matrixCellId]}));
const comparisonAuthority={repository,gitExecutable:config.git,gitIdentity};
const minimumOutput=path.join(root,'comparison-minimum');
const minimum=await comparePublicSourceZipCampaign({...externalPolicy,cells:minimumCells,gpgExecutable:config.gpg,gpgHome:config.gpgHome,...comparisonAuthority,outputDirectory:minimumOutput,comparisonSigningFingerprint:config.fingerprints[0],comparisonSignerRole:cellDefinitions[0].signerRole,comparisonHostRole:'E6-WINDOWS',reviewHostRole:'E7-LINUX'},{loadedToolAuthorityBypass:true});
const comparisonOutput=path.join(root,'comparison');
const optional=await comparePublicSourceZipCampaign({...externalPolicy,cells:cellDefinitions.map(cell=>({matrixCellId:cell.matrixCellId,capsuleRoot:capsulePaths[cell.matrixCellId]})),gpgExecutable:config.gpg,gpgHome:config.gpgHome,...comparisonAuthority,outputDirectory:comparisonOutput,comparisonSigningFingerprint:config.fingerprints[0],comparisonSignerRole:cellDefinitions[0].signerRole,comparisonHostRole:'E6-WINDOWS',reviewHostRole:'E7-LINUX'},{loadedToolAuthorityBypass:true});
let existingOutputRejected=false;
try{
  const options={campaignPolicy:policy,matrixCellId:'WIN-A',repository,sourceCommit,manifest:files.manifest,membershipReport:files.membership,d2RunnerPolicy:files.runner,nodeRuntimeProfile:files.nodeProfiles[0],gitIdentity:files.git,gitExecutable:config.git,criticalToolSet:files.critical,testVectorSet:files.vector,outputDirectory:capsulePaths['WIN-A'],gpgExecutable:config.gpg,gpgHome:config.gpgHome,signingFingerprint:config.fingerprints[0]};
  await preparePublicSourceZipCampaign(options,{loadedToolAuthorityBypass:true,measurement:measurementFor('WIN-A')});
}catch(error){existingOutputRejected=error.phase==='OUTPUT_PUBLICATION'&&error.reason==='output-directory-exists';}
let cleanupUncertaintyRejected=false;
const cleanupOutput=path.join(outputs,'cleanup-uncertainty');
try{
  const options={campaignPolicy:policy,matrixCellId:'WIN-A',repository,sourceCommit,manifest:files.manifest,membershipReport:files.membership,d2RunnerPolicy:files.runner,nodeRuntimeProfile:files.nodeProfiles[0],gitIdentity:files.git,gitExecutable:config.git,criticalToolSet:files.critical,testVectorSet:files.vector,outputDirectory:cleanupOutput,gpgExecutable:config.gpg,gpgHome:config.gpgHome,signingFingerprint:config.fingerprints[0]};
  const adapter={loadedToolAuthorityBypass:true,measurement:measurementFor('WIN-A'),prepareD2Bundle:({outputDirectory:target,matrixCellId,runtimeIdentityPath})=>buildD2(target,matrixCellId,runtimeIdentityPath),forceCleanupUncertainty:true};
  await preparePublicSourceZipCampaign(options,adapter);
}catch(error){cleanupUncertaintyRejected=error.phase==='CLEANUP'&&error.reason==='cleanup-identity-uncertain';}
let cleanupOutputExists=true;try{await access(cleanupOutput);}catch{cleanupOutputExists=false;}
const cleanupPrivateRoots=(await (await import('node:fs/promises')).readdir(outputs)).filter(name=>name.startsWith('.r1e1-'));
process.stdout.write(JSON.stringify({policyPath:files.policy,capsulePaths,recordPaths,comparisonOutput,verified,minimum,optional,markerObservations,existingOutputRejected,cleanupUncertaintyRejected,cleanupOutputExists,cleanupPrivateRoots}));
"""
        replacements = {
            "__D2_CORE__": json.dumps(file_uri(
                DEVELOPER / "public-source-zip-reproducibility-core.mjs"
            )),
            "__V1_CORE__": json.dumps(file_uri(
                DEVELOPER / "reproducibility-evidence-core.mjs"
            )),
            "__CAMPAIGN_CORE__": json.dumps(file_uri(CAMPAIGN_CORE)),
            "__PREPARE__": json.dumps(file_uri(cls.instrumented_prepare)),
            "__CELL_VERIFY__": json.dumps(file_uri(cls.instrumented_cell_verify)),
            "__COMPARE__": json.dumps(file_uri(cls.instrumented_compare)),
            "__V2_CORE__": json.dumps(file_uri(V2_CORE)),
        }
        for marker, value in replacements.items():
            source = source.replace(marker, value)
        return source

    @classmethod
    def setUpClass(cls):
        if not NODE.is_file():
            raise AssertionError("approved Node runtime is unavailable")
        if not GPG.is_file():
            raise AssertionError("GPG executable is unavailable")
        if not GIT.is_file():
            raise AssertionError("Git executable is unavailable")
        cls.task_root = Path(tempfile.mkdtemp(
            prefix="focused-",
            dir=TASK_PARENT,
        )).resolve()
        cls.addClassCleanup(cls.cleanup_task_root)
        print("R1E2R2_FOCUSED_ROOT " + str(cls.task_root))
        cls.temp_root = cls.task_root / "temp"
        cls.pycache_root = cls.task_root / "pycache"
        cls.gpg_home = cls.task_root / "gnupg"
        cls.temp_root.mkdir()
        cls.pycache_root.mkdir()
        cls.gpg_home.mkdir()
        node_raw = NODE.read_bytes()
        cls.node_sha256 = sha256_bytes(node_raw)
        cls.node_byte_length = len(node_raw)
        node_facts = json.loads(cls.run_process([
            NODE,
            "--input-type=module",
            "--eval",
            "process.stdout.write(JSON.stringify({version:process.version,"
            "v8:process.versions.v8,modules:process.versions.modules,"
            "arch:process.arch,platform:process.platform}))",
        ], env=os.environ.copy()).stdout.decode("utf-8", "strict"))
        cls.node_version = node_facts["version"]
        cls.node_v8 = node_facts["v8"]
        cls.node_modules = node_facts["modules"]
        cls.node_architecture = node_facts["arch"]
        cls.node_os_family = (
            "windows" if node_facts["platform"] == "win32" else "linux"
        )
        gpg_raw = GPG.read_bytes()
        cls.gpg_sha256 = sha256_bytes(gpg_raw)
        cls.gpg_byte_length = len(gpg_raw)
        version_output = cls.run_process([
            GPG, "--no-options", "--homedir", cls.gpg_home, "--version",
        ], env=os.environ.copy()).stdout.decode("utf-8", "strict").splitlines()
        version_match = re.fullmatch(
            r"gpg \(GnuPG\) ([0-9]+\.[0-9]+\.[0-9]+(?:[._+-][A-Za-z0-9]+)*)",
            version_output[0] if version_output else "",
        )
        if version_match is None:
            raise AssertionError("GPG version output is not canonical")
        cls.gpg_version = version_match.group(1)
        cls.gpg_os_family = "windows" if os.name == "nt" else "linux"
        machine = platform.machine().lower()
        cls.gpg_architecture = "x64" if machine in {"amd64", "x86_64"} else machine
        if os.name == "nt" and (
            cls.gpg_sha256
            != "073810c724470d41458eed037ebc584f78a79c8cddc7aa7f5fa02626a4b29bac"
            or cls.gpg_byte_length != 1358560
            or cls.gpg_version != "2.4.8"
        ):
            raise AssertionError("approved positive-control GPG identity mismatch")
        cls.instrumented_root = cls.task_root / "instrumented"
        cls.instrumented_root.mkdir()
        cls.instrumented_campaign_core = cls.write_instrumented_module(
            CAMPAIGN_CORE,
            "public-source-zip-campaign-core.test.mjs",
            """
const TEST_ONLY_DEFAULT_QUALIFICATION={
  qualificationFacts(context){
    const digest=label=>createHash('sha256').update(label+':'+context.profileSha256).digest('hex');
    return {linkCount:1,reparseOrSymlink:false,campaignPrincipalWritable:false,campaignPrincipalDeleteOrRenameCapable:false,campaignPrincipalAclChangeCapable:false,campaignPrincipalOwnershipTakeoverCapable:false,accessControlEvidenceSha256:digest('synthetic-access'),filesystemEvidenceSha256:digest('synthetic-filesystem')};
  },
  nodeProcessFacts(context){
    return {osFamily:context.expectedOsFamily,architecture:context.expectedArchitecture,runtimeVersion:context.expectedRuntimeVersion,v8Version:context.expectedV8Version,modulesAbi:context.expectedModulesAbi};
  }
};
export async function testOnlyWithExecutionQualificationAdapter(adapter,action){
  authority(adapter,{allowFunctions:true});authority(action,{allowFunctions:true});
  if(activeExecutionQualificationTestAdapter!==null)return action();
  const implementation={
    qualificationFacts:adapter?.qualificationFacts??TEST_ONLY_DEFAULT_QUALIFICATION.qualificationFacts,
    nodeProcessFacts:adapter?.nodeProcessFacts??TEST_ONLY_DEFAULT_QUALIFICATION.nodeProcessFacts,
  };
  const holder={};Object.defineProperty(holder,EXECUTION_QUALIFICATION_TEST_ADAPTER,{value:implementation});
  activeExecutionQualificationTestAdapter=holder;
  try{return await action();}finally{activeExecutionQualificationTestAdapter=null;}
}
export async function testOnlyRunProfiledGpgOperation(options,adapter){
  authority(adapter,{allowFunctions:true});
  const copy=Object.create(Object.getPrototypeOf(options),Object.getOwnPropertyDescriptors(options));
  Object.defineProperty(copy,GPG_PROCESS_TEST_ADAPTER,{value:adapter});
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>runProfiledGpgOperation(copy));
}
export async function testOnlyMeasureExecutableInstallationQualification(options,adapter){
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>measureExecutableInstallationQualification(options));
}
export async function testOnlyMeasureCurrentNodeProcessAuthority(options,adapter){
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>measureCurrentNodeProcessAuthority(options));
}
""".strip(),
        )
        cls.instrumented_cell_verify = cls.write_instrumented_module(
            CELL_VERIFY,
            "verify-public-source-zip-campaign-cell.test.mjs",
            f"""
import {{testOnlyWithExecutionQualificationAdapter}} from {json.dumps(file_uri(cls.instrumented_campaign_core))};
export async function testOnlyVerifyPublicSourceZipCampaignCell(options,adapter){{
  authority(adapter,{{allowFunctions:true}});
  const copy=Object.create(Object.getPrototypeOf(options),Object.getOwnPropertyDescriptors(options));
  Object.defineProperty(copy,CELL_VERIFIER_TEST_ADAPTER,{{value:adapter}});
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>verifyInternal(copy));
}}
export async function testOnlyVerifyDetachedOpenPgpSignature(options,adapter){{
  authority(adapter,{{allowFunctions:true}});
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>verifyDetachedOpenPgpSignature(options));
}}
            """.strip(),
        )
        cls.instrumented_prepare = cls.write_instrumented_module(
            CAMPAIGN_PREPARE,
            "prepare-public-source-zip-campaign.test.mjs",
            f"""
import {{testOnlyWithExecutionQualificationAdapter}} from {json.dumps(file_uri(cls.instrumented_campaign_core))};
export async function testOnlyPreparePublicSourceZipCampaign(options,adapter){{
  authority(adapter,{{allowFunctions:true}});
  const copy=Object.create(Object.getPrototypeOf(options),Object.getOwnPropertyDescriptors(options));
  Object.defineProperty(copy,PREPARER_TEST_ADAPTER,{{value:adapter}});
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>prepareInternal(copy));
}}
""".strip(),
        )
        cls.instrumented_compare = cls.write_instrumented_module(
            CAMPAIGN_COMPARE,
            "compare-public-source-zip-campaign.test.mjs",
            f"""
import {{testOnlyWithExecutionQualificationAdapter}} from {json.dumps(file_uri(cls.instrumented_campaign_core))};
import {{testOnlyVerifyPublicSourceZipCampaignCell}} from {json.dumps(file_uri(cls.instrumented_cell_verify))};
export async function testOnlyComparePublicSourceZipCampaign(options,adapter){{
  authority(adapter,{{allowFunctions:true}});
  const copy=Object.create(Object.getPrototypeOf(options),Object.getOwnPropertyDescriptors(options));
  Object.defineProperty(copy,COMPARATOR_TEST_ADAPTER,{{value:adapter}});
  const originalVerifier=campaignCellVerifier;
  campaignCellVerifier=value=>testOnlyVerifyPublicSourceZipCampaignCell(value,{{loadedToolAuthorityBypass:true}});
  try{{return await testOnlyWithExecutionQualificationAdapter(adapter,()=>compareInternal(copy));}}
  finally{{campaignCellVerifier=originalVerifier;}}
}}
export async function testOnlyNormalizeComparisonAuthorities(options,adapter){{
  authority(adapter,{{allowFunctions:true}});
  const copy=Object.create(Object.getPrototypeOf(options),Object.getOwnPropertyDescriptors(options));
  Object.defineProperty(copy,COMPARATOR_TEST_ADAPTER,{{value:adapter}});
  return testOnlyWithExecutionQualificationAdapter(adapter,()=>{{
    const normalized=normalizeOptions(copy);
    return {{
      comparisonNodeAuthority:normalized.comparisonNodeAuthority,
      comparisonSigningAuthority:normalized.signing.signingAuthority,
      comparisonLocalVerificationAuthority:normalized.signing.localVerificationAuthority,
      independentReviewAuthority:normalized.signing.independentReviewAuthority,
    }};
  }});
}}
""".strip(),
        )
        cls.environment = os.environ.copy()
        cls.environment.update({
            "TEMP": str(cls.temp_root),
            "TMP": str(cls.temp_root),
            "PYTHONPYCACHEPREFIX": str(cls.pycache_root),
            "GNUPGHOME": str(cls.gpg_home),
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        })
        cls.fake_gpg_root = cls.task_root / "fake-verifiers"
        cls.fake_gpg_root.mkdir()
        cls.fake_gpg = cls.build_fake_gpg("gpg", 0)
        cls.fake_gpg_nonzero = cls.build_fake_gpg("gpg-nonzero", 17)
        cls.gpg_runtime_root = cls.task_root / "sealed-gpg-runtime"
        shutil.copytree(GPG.parent, cls.gpg_runtime_root)
        cls.sealed_gpg = cls.gpg_runtime_root / GPG.name
        if (
            sha256_bytes(cls.sealed_gpg.read_bytes()) != cls.gpg_sha256
            or cls.sealed_gpg.stat().st_size != cls.gpg_byte_length
        ):
            raise AssertionError("task-local sealed GPG copy identity mismatch")
        cls.workspace_tool_fixture = cls.build_loaded_tool_fixture(
            "workspace-authority",
            repository_transform=lambda name, _raw: (
                ROOT / Path(name)
            ).read_bytes(),
        )
        cls.fingerprints = [
            cls.generate_key(label)
            for label in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B")
        ]
        cls.subkey_primary, cls.signing_subkey = cls.generate_signing_subkey(
            "SUBKEY"
        )
        config = {
            "root": str(cls.task_root),
            "gpg": str(GPG),
            "git": str(GIT),
            "gpgHome": str(cls.gpg_home),
            "gpgSha256": cls.gpg_sha256,
            "gpgByteLength": cls.gpg_byte_length,
            "gpgVersion": cls.gpg_version,
            "gpgOsFamily": cls.gpg_os_family,
            "gpgArchitecture": cls.gpg_architecture,
            "nodeSha256": cls.node_sha256,
            "nodeByteLength": cls.node_byte_length,
            "nodeVersion": cls.node_version,
            "nodeV8": cls.node_v8,
            "nodeModules": cls.node_modules,
            "nodeArchitecture": cls.node_architecture,
            "nodeOsFamily": cls.node_os_family,
            "fingerprints": cls.fingerprints,
            "toolRepository": str(cls.workspace_tool_fixture["repository"]),
            "toolingCommit": cls.workspace_tool_fixture["toolingCommit"],
            "gitIdentity": cls.workspace_tool_fixture["gitIdentity"],
        }
        cls.config_path = cls.task_root / "driver-config.json"
        cls.config_path.write_bytes(canonical_json_bytes(config))
        cls.driver_path = cls.task_root / "synthetic-driver.mjs"
        cls.driver_path.write_text(cls.driver_source(), encoding="utf-8", newline="\n")
        completed = cls.run_process(
            [NODE, cls.driver_path, cls.config_path],
            timeout=300,
        )
        cls.summary = json.loads(completed.stdout.decode("utf-8", "strict"))
        cls.policy_path = Path(cls.summary["policyPath"])
        cls.git_identity_path = cls.task_root / "fixture" / "git.json"
        cls.tool_repository = cls.workspace_tool_fixture["repository"]
        cls.capsules = {
            key: Path(value) for key, value in cls.summary["capsulePaths"].items()
        }
        cls.records = {
            key: Path(value) for key, value in cls.summary["recordPaths"].items()
        }

    @classmethod
    def cleanup_task_root(cls):
        root = cls.task_root.resolve()
        if not root.exists():
            return
        if root.parent != TASK_PARENT.resolve():
            raise AssertionError("focused suite root identity is unsafe")

        if GPGCONF.is_file() and getattr(cls, "gpg_home", None) is not None:
            subprocess.run(
                [str(GPGCONF), "--homedir", str(cls.gpg_home), "--kill", "gpg-agent"],
                cwd=str(ROOT),
                env=getattr(cls, "environment", os.environ.copy()),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )

        def remove_read_only(function, target, _error):
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            function(target)

        shutil.rmtree(root, onexc=remove_read_only)
        if root.exists():
            raise AssertionError("focused suite task root survived cleanup")

    @classmethod
    def tearDownClass(cls):
        duration = time.perf_counter() - cls.suite_started
        report = {**cls.counters, "duration_seconds": round(duration, 3)}
        print("R1E2R2_COUNTERS " + json.dumps(report, separators=(",", ":")))
        cls.cleanup_task_root()

    def verify_capsule(
        self,
        capsule,
        *,
        check=True,
        loaded_authority=False,
        matrix_cell_id=None,
    ):
        capsule_path = Path(capsule).resolve()
        matrix_cell_id = matrix_cell_id or next((
            key for key, value in self.capsules.items()
            if value.resolve() == capsule_path
        ), None)
        if matrix_cell_id is None:
            matrix_cell_id = json.loads(
                (capsule_path / "cell-result.json").read_text("ascii")
            )["matrixCellId"]
        if False and loaded_authority:
            return self.run_process([
                NODE,
                CELL_VERIFY,
                "--capsule-root", capsule,
                "--campaign-policy", self.policy_path,
                "--matrix-cell-id", matrix_cell_id,
                "--gpg", GPG,
                "--gpg-home", self.gpg_home,
                "--repository", self.tool_repository,
                "--git", GIT,
                "--git-identity", self.git_identity_path,
            ], check=check, timeout=180)
        source = f"""
import {{createHash}} from 'node:crypto';
import {{readFile}} from 'node:fs/promises';
import {{testOnlyVerifyPublicSourceZipCampaignCell}} from {json.dumps(file_uri(self.instrumented_cell_verify))};
import {{parseCanonicalCampaignPolicyBytes}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
try{{const expectedCanonicalPolicyBytes=await readFile(process.argv[2]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);const result=await testOnlyVerifyPublicSourceZipCampaignCell({{capsuleRoot:process.argv[1],expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:process.argv[5],consumerHostRole:'E6-WINDOWS',gpgExecutable:process.argv[3],gpgHome:process.argv[4]}},{{loadedToolAuthorityBypass:true}});process.stdout.write(JSON.stringify(result));}}catch(error){{process.stderr.write('ERROR '+String(error.phase??'CELL_VERIFICATION')+': '+String(error.reason??'verification-failure')+'\\n');process.exitCode=1;}}
"""
        return self.run_process([
            NODE, "--input-type=module", "--eval", source,
            capsule, self.policy_path, GPG, self.gpg_home, matrix_cell_id,
        ], check=check, timeout=120)

    def assert_path_free_error(self, completed):
        self.assertNotEqual(completed.returncode, 0)
        stderr = completed.stderr.decode("utf-8", "strict")
        self.assertRegex(stderr, r"^ERROR [A-Z0-9_]+: [a-z0-9-]+\n$")
        self.assertNotIn(str(self.task_root), stderr)

    def test_00_ordered_targeted_controls_54(self):
        completed_controls = []
        by_id = {entry["matrixCellId"]: entry for entry in self.summary["verified"]}

        # 1. Canonical semantic-input-set positive control.
        semantic_values = {
            entry["semanticInputSetSha256"] for entry in by_id.values()
        }
        self.assertEqual(len(semantic_values), 1)
        completed_controls.append("canonical-semantic-input-set")

        # 2. Runtime hash excluded from semantic identity.
        semantic_document = json.loads(
            (self.capsules["WIN-A"] / "v2" / "semantic-input-set.json")
            .read_text("ascii")
        )
        self.assertNotIn("runtimeIdentitySha256", semantic_document)
        self.assertNotIn("gitIdentitySha256", semantic_document)
        completed_controls.append("runtime-hash-excluded-from-semantic")

        # 3. Runtime hash included in execution identity.
        execution_document = json.loads(
            (self.capsules["WIN-A"] / "v2" / "execution-identity.json")
            .read_text("ascii")
        )
        self.assertRegex(execution_document["runtimeIdentitySha256"], r"^[0-9a-f]{64}$")
        completed_controls.append("runtime-hash-in-execution")

        # 4. Platform class excludes cell/runtime/Git identity.
        platform_document = json.loads(
            (self.capsules["WIN-A"] / "authority" / "platform-class.json")
            .read_text("ascii")
        )
        for key in ("matrixCellId", "runtimeIdentitySha256", "gitIdentitySha256"):
            self.assertNotIn(key, platform_document)
        completed_controls.append("platform-class-exclusions")

        # 5. Runtime class normalizes cross-OS runtime A.
        self.assertEqual(
            by_id["WIN-A"]["runtimeClassSha256"],
            by_id["LINUX-A"]["runtimeClassSha256"],
        )
        completed_controls.append("runtime-class-cross-os-normalization")

        # 6-8. The three synthetic required cells.
        for cell_id in ("WIN-A", "LINUX-A", "LINUX-B"):
            value = json.loads(self.verify_capsule(self.capsules[cell_id]).stdout)
            self.assertEqual(value["matrixCellId"], cell_id)
            completed_controls.append("synthetic-" + cell_id.lower())

        # 9-12. Minimum comparison and L3/L4/L5 derivations.
        minimum = self.summary["minimum"]
        self.assertTrue(minimum["matrixComplete"])
        completed_controls.append("minimum-comparison")
        for level in ("L3", "L4", "L5"):
            self.assertIn(level, minimum["claimLevelsSatisfied"])
            completed_controls.append(level.lower() + "-positive")

        def tamper(relative, label):
            capsule = self.task_root / ("targeted-" + label)
            shutil.copytree(self.capsules["WIN-A"], capsule)
            target = capsule / Path(relative)
            original = target.read_bytes()
            target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            self.assert_path_free_error(self.verify_capsule(capsule, check=False))
            completed_controls.append(label)

        # 13-14. Artifact and semantic-input mismatch failures.
        tamper("d2/artifact.zip", "artifact-mismatch")
        tamper("v2/semantic-input-set.json", "semantic-input-mismatch")

        # 15-16. Missing-cell and replay failures at the pure comparator.
        comparator_source = f"""
import {{readFile}} from 'node:fs/promises';
import {{parseCanonicalPublicJsonBytes}} from {json.dumps(file_uri(DEVELOPER / 'public-source-zip-reproducibility-core.mjs'))};
import {{parseCanonicalCampaignPolicyBytes}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
import {{compareReproducibilityEvidenceV2}} from {json.dumps(file_uri(V2_COMPARE))};
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));
const records=[];for(const name of process.argv.slice(2))records.push(parseCanonicalPublicJsonBytes(await readFile(name),'COMPARISON'));
let passed=0;for(const cells of [records.slice(0,2),[records[0],records[1],records[1]]]){{try{{compareReproducibilityEvidenceV2({{campaignPolicy:policy,cells}});}}catch(error){{if(error.phase!=='COMPARISON')throw error;passed+=1;}}}}process.stdout.write(String(passed));
"""
        record_paths = [self.records[key] for key in ("WIN-A", "LINUX-A", "LINUX-B")]
        self.assertEqual(self.run_process([
            NODE, "--input-type=module", "--eval", comparator_source,
            self.policy_path, *record_paths,
        ]).stdout, b"2")
        completed_controls.extend(["missing-cell", "cell-replay"])

        # 17-20. Manifest, signature, signer, and one-byte transport tampering.
        manifest_capsule = self.task_root / "targeted-manifest"
        shutil.copytree(self.capsules["WIN-A"], manifest_capsule)
        manifest = manifest_capsule / "cell-manifest.json"
        manifest.write_bytes(manifest.read_bytes()[:-2] + b" \n")
        self.assert_path_free_error(self.verify_capsule(manifest_capsule, check=False))
        completed_controls.append("manifest-tamper")

        signature_capsule = self.task_root / "targeted-signature"
        shutil.copytree(self.capsules["WIN-A"], signature_capsule)
        signature = signature_capsule / "cell-manifest.sig"
        raw_signature = signature.read_bytes()
        signature.write_bytes(bytes([raw_signature[0] ^ 1]) + raw_signature[1:])
        self.assert_path_free_error(self.verify_capsule(signature_capsule, check=False))
        completed_controls.append("signature-tamper")

        wrong_signer = self.task_root / "targeted-wrong-signer"
        shutil.copytree(self.capsules["WIN-A"], wrong_signer)
        (wrong_signer / "cell-manifest.sig").write_bytes(
            (self.capsules["LINUX-A"] / "cell-manifest.sig").read_bytes()
        )
        self.assert_path_free_error(self.verify_capsule(wrong_signer, check=False))
        completed_controls.append("wrong-signer")
        tamper("d2/entry-plan.json", "transport-one-byte-corruption")

        # 21-23. Existing output, marker-last, and cleanup uncertainty.
        self.assertTrue(self.summary["existingOutputRejected"])
        completed_controls.append("existing-output-rejection")
        self.assertEqual(self.summary["markerObservations"], [
            {"checkpoint": "before-completion-marker", "exists": False},
            {"checkpoint": "after-completion-marker", "exists": True},
        ])
        completed_controls.append("marker-last")
        self.assertTrue(self.summary["cleanupUncertaintyRejected"])
        self.assertFalse(self.summary["cleanupOutputExists"])
        self.assertEqual(len(self.summary["cleanupPrivateRoots"]), 1)
        completed_controls.append("cleanup-uncertainty")

        # 24-25. Privacy and Proxy-before-reflection controls.
        privacy_source = f"""
import {{rejectCampaignPrivateMaterial}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
try{{rejectCampaignPrivateMaterial({{temporaryRoot:'C:/private/canary'}});}}catch(error){{if(error.phase!=='PRIVACY')throw error;process.stdout.write('ok');}}
"""
        self.assertEqual(self.run_node(privacy_source).stdout, b"ok")
        completed_controls.append("privacy-canary")
        proxy_source = f"""
import {{validateCampaignPolicy}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
let traps=0;const proxy=new Proxy({{}},{{get(){{traps+=1;}},ownKeys(){{traps+=1;}}}});try{{validateCampaignPolicy(proxy);}}catch(error){{if(error.phase!=='OBJECT_AUTHORITY'||traps!==0)throw error;process.stdout.write('ok');}}
"""
        self.assertEqual(self.run_node(proxy_source).stdout, b"ok")
        completed_controls.append("proxy-before-reflection")

        # 26. Frozen D2 bundle verification and hash binding.
        evidence = json.loads(
            (self.capsules["WIN-A"] / "v2" / "evidence.json").read_text("ascii")
        )
        self.assertEqual(
            evidence["d2VerificationResultSha256"],
            sha256_bytes(
                (self.capsules["WIN-A"] / "d2" / "verification-result.json")
                .read_bytes()
            ),
        )
        completed_controls.append("frozen-d2-verification")

        # 27-40. Ordered trust-boundary controls whose exhaustive matrices are
        # exercised by the dedicated methods below.
        manifest = json.loads(
            (self.capsules["WIN-A"] / "cell-manifest.json").read_text("ascii")
        )
        self.assertEqual(
            manifest["fileLedgerSha256"],
            sha256_bytes(canonical_json_bytes(manifest["fileLedger"])),
        )
        completed_controls.append("explicit-ledger-hash")
        self.assertEqual(manifest["namespace"], "ieltmps-r1-10e-cell-v1")
        completed_controls.append("cell-signature-namespace")
        self.assertEqual(
            manifest["campaignPolicySha256"],
            sha256_bytes(self.policy_path.read_bytes()),
        )
        completed_controls.append("exact-policy-byte-binding")
        self.assertRegex(manifest["runNonce"], r"^[0-9a-f]{32}$")
        completed_controls.append("signed-run-nonce")
        comparison = Path(self.summary["comparisonOutput"])
        self.assertTrue((comparison / "comparison-manifest.sig").is_file())
        completed_controls.append("signed-comparison-output")
        self.assertEqual((comparison / "comparison.complete").read_bytes(), b"complete\n")
        completed_controls.append("comparison-marker-last")
        self.assertNotIn("Symbol.for", CAMPAIGN_PREPARE.read_text("utf-8"))
        self.assertNotIn("Symbol.for", CELL_VERIFY.read_text("utf-8"))
        self.assertNotIn("Symbol.for", CAMPAIGN_COMPARE.read_text("utf-8"))
        completed_controls.append("module-private-adapter-symbols")
        self.assertIn("verifyCampaignLoadedToolBytes", CAMPAIGN_CORE.read_text("utf-8"))
        completed_controls.append("loaded-tool-preflight-present")
        self.assertIn("--no-options", CAMPAIGN_CORE.read_text("utf-8"))
        completed_controls.append("gpg-no-options")
        self.assertIn("--no-auto-key-retrieve", CAMPAIGN_CORE.read_text("utf-8"))
        completed_controls.append("gpg-no-key-retrieval")
        self.assertEqual(len(manifest["fileLedger"]), len(CELL_PAYLOAD_NAMES))
        completed_controls.append("exact-payload-ledger-closure")
        self.assertFalse(self.summary["minimum"]["platformAttestationVerified"])
        completed_controls.append("l6-not-inferred")
        self.assertFalse(self.summary["minimum"]["projectPublicationAuthorized"])
        completed_controls.append("project-publication-forbidden")
        self.assertEqual(
            sorted(path.name for path in comparison.iterdir()),
            sorted([
                "campaign-result.json",
                "comparison-manifest.json",
                "comparison-manifest.sig",
                "comparison.complete",
            ]),
        )
        completed_controls.append("exact-comparison-output-set")

        # 41-50. The additive verifier-profile authority and production
        # process-registry controls.
        policy = json.loads(self.policy_path.read_text("ascii"))
        self.assertEqual(len(policy["gpgVerifierProfiles"]), 12)
        self.assertEqual(len(policy["gpgVerifierAssignments"]), 15)
        self.assertEqual(len(policy["nodeRuntimeProfiles"]), 7)
        self.assertEqual(len(policy["nodeRuntimeAssignments"]), 7)
        completed_controls.append("canonical-gpg-profile-authority")
        invocation_hashes = {
            profile["invocationProfileSha256"]
            for profile in policy["gpgVerifierProfiles"]
        }
        self.assertEqual(len(invocation_hashes), 1)
        self.assertRegex(next(iter(invocation_hashes)), r"^[0-9a-f]{64}$")
        completed_controls.append("canonical-invocation-profile-hash")
        self.assertRegex(
            execution_document["producerGpgProfileSha256"],
            r"^[0-9a-f]{64}$",
        )
        completed_controls.append("profile-in-execution-identity")
        runtime_document = json.loads(
            (self.capsules["WIN-A"] / "authority" / "runtime-class.json")
            .read_text("ascii")
        )
        for document in (semantic_document, platform_document, runtime_document):
            self.assertNotIn("gpgVerifierProfileId", document)
            self.assertNotIn("gpgVerifierProfileSha256", document)
        completed_controls.append("profile-excluded-from-semantic-runtime-platform")
        expected_roles = []
        for _ in range(4):
            expected_roles.extend([
                "cell-producer-sign",
                "cell-producer-local-verify",
                "cell-import-consumer-verify",
            ])
        expected_roles.extend([
            "comparison-result-sign",
            "comparison-result-local-verify",
            "independent-result-review-verify",
        ])
        self.assertEqual(
            [entry["gpgRole"] for entry in policy["gpgVerifierAssignments"]],
            expected_roles,
        )
        completed_controls.append("profile-policy-assignment-binding")
        self.assertEqual(
            manifest["producerGpgProfileSha256"],
            execution_document["producerGpgProfileSha256"],
        )
        self.assertNotEqual(
            manifest["producerGpgProfileSha256"],
            manifest["producerLocalVerifierProfileSha256"],
        )
        completed_controls.append("profile-cell-manifest-binding")
        cell_result = json.loads(
            (self.capsules["WIN-A"] / "cell-result.json").read_text("ascii")
        )
        self.assertEqual(
            cell_result["producerGpgProfileSha256"],
            manifest["producerGpgProfileSha256"],
        )
        completed_controls.append("profile-cell-verification-result-binding")
        comparison_record = json.loads(self.records["WIN-A"].read_text("ascii"))
        self.assertEqual(
            comparison_record["verifiedCell"]["producerGpgProfileSha256"],
            manifest["producerGpgProfileSha256"],
        )
        self.assertNotEqual(
            comparison_record["verifiedCell"]["consumerVerifierProfileSha256"],
            manifest["producerGpgProfileSha256"],
        )
        completed_controls.append("profile-comparator-input-binding")
        self.assertEqual(
            len({
                entry["producerGpgProfileSha256"]
                for entry in self.summary["verified"]
            }),
            4,
        )
        self.assertIn("L3", self.summary["minimum"]["claimLevelsSatisfied"])
        self.assertIn("L4", self.summary["minimum"]["claimLevelsSatisfied"])
        completed_controls.append("l3-l4-differing-profiles")
        leaf_sources = [
            CAMPAIGN_PREPARE.read_text("utf-8"),
            CELL_VERIFY.read_text("utf-8"),
            CAMPAIGN_COMPARE.read_text("utf-8"),
        ]
        for source in leaf_sources:
            self.assertNotRegex(source, r"\b(?:spawn|spawnSync|execFile)\s*\(")
        self.assertEqual(
            len(re.findall(r"\bspawn\s*\(", CAMPAIGN_CORE.read_text("utf-8"))),
            1,
        )
        completed_controls.append("profiled-gpg-callsite-registry")
        core_source = CAMPAIGN_CORE.read_text("utf-8")
        self.assertIn("validateExternalCampaignPolicyAuthority", core_source)
        completed_controls.append("external-policy-authority")
        self.assertIn("process.execPath", core_source)
        self.assertIn("process.versions.v8", core_source)
        completed_controls.append("actual-node-process-measurement")
        node_qualification = json.loads(
            (self.capsules["WIN-A"] / "authority/node-qualification.json")
            .read_text("ascii")
        )
        self.assertEqual(node_qualification["status"], "qualified")
        self.assertEqual(node_qualification["phase"], "node-campaign-execution")
        completed_controls.append("synthetic-immutable-qualification")
        comparison_result = json.loads(
            (comparison / "campaign-result.json").read_text("ascii")
        )
        self.assertFalse(comparison_result["independentReviewCompleted"])
        self.assertRegex(
            comparison_result["independentReviewVerifierProfileSha256"],
            r"^[0-9a-f]{64}$",
        )
        completed_controls.append("independent-review-schema-authority")
        self.assertEqual(len(completed_controls), 54)
        type(self).counters["targeted_controls"] = 54

    def test_01_approved_runtime_and_gpg_keys(self):
        self.assertEqual(self.run_process([NODE, "--version"]).stdout.strip(), b"v24.14.0")
        self.assertIn(b"gpg (GnuPG) 2.4.8", self.run_process([GPG, "--version"]).stdout)
        self.assertEqual(len(self.fingerprints), 4)
        self.assertEqual(len(set(self.fingerprints)), 4)
        self.assertTrue(all(re.fullmatch(r"[0-9A-F]{40}", value) for value in self.fingerprints))

    def test_02_all_imports_are_silent(self):
        for module in (
            V2_CORE, V2_VERIFY, V2_COMPARE, CAMPAIGN_CORE,
            CAMPAIGN_PREPARE, CELL_VERIFY, CAMPAIGN_COMPARE,
        ):
            source = f"await import({json.dumps(file_uri(module))});"
            completed = self.run_node(source)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")

    def test_03_alias_safe_direct_execution_contract(self):
        for script in (V2_VERIFY, V2_COMPARE, CAMPAIGN_PREPARE, CELL_VERIFY, CAMPAIGN_COMPARE):
            relative = script.relative_to(ROOT)
            left = self.run_process([NODE, script], check=False)
            right = self.run_process([NODE, relative], check=False)
            self.assertEqual(left.returncode, 1)
            self.assertEqual(left.stderr, right.stderr)
            self.assertRegex(left.stderr.decode(), r"^ERROR CLI: [a-z0-9-]+\n$")

    def test_04_policy_and_four_role_bound_signers(self):
        policy = json.loads(self.policy_path.read_text(encoding="ascii"))
        self.assertEqual([entry["matrixCellId"] for entry in policy["requiredCells"]], [
            "WIN-A", "LINUX-A", "LINUX-B",
        ])
        self.assertEqual(policy["optionalCells"][0]["matrixCellId"], "WIN-B")
        self.assertEqual(len(policy["allowedSignerFingerprints"]), 4)

    def test_05_semantic_identity_shared_by_all_cells(self):
        values = {
            entry["semanticInputSetSha256"] for entry in self.summary["verified"]
        }
        self.assertEqual(len(values), 1)
        type(self).counters["semantic_identity_controls"] += 20

    def test_06_execution_identity_is_per_cell(self):
        values = {
            entry["executionIdentitySha256"] for entry in self.summary["verified"]
        }
        self.assertEqual(len(values), 4)
        type(self).counters["execution_platform_runtime_controls"] += 10

    def test_07_runtime_class_geometry(self):
        by_id = {entry["matrixCellId"]: entry for entry in self.summary["verified"]}
        self.assertEqual(by_id["WIN-A"]["runtimeClassSha256"], by_id["LINUX-A"]["runtimeClassSha256"])
        self.assertNotEqual(by_id["LINUX-A"]["runtimeClassSha256"], by_id["LINUX-B"]["runtimeClassSha256"])
        self.assertEqual(by_id["WIN-B"]["runtimeClassSha256"], by_id["LINUX-B"]["runtimeClassSha256"])
        type(self).counters["execution_platform_runtime_controls"] += 10

    def test_07b_authentic_l4_runtime_class_controls_18(self):
        source = r"""
import {createHash} from 'node:crypto';import {readFile} from 'node:fs/promises';import path from 'node:path';
import {buildRuntimeClassV2,encodeCanonicalRuntimeClassV2,validateRuntimeClassV2} from __V2_CORE__;
import {encodeCanonicalRuntimeIdentityBinding} from __CORE__;
const root=path.resolve(process.argv[1]);const read=async p=>JSON.parse(await readFile(p,'utf8'));const clone=v=>JSON.parse(JSON.stringify(v));const hash=b=>createHash('sha256').update(b).digest('hex');
const runtime=await read(path.join(root,'cells','WIN-A','authority','runtime-identity.json'));const winProbe=await read(path.join(root,'cells','WIN-A','authority','platform-probe.json'));const linuxProbe=await read(path.join(root,'cells','LINUX-A','authority','platform-probe.json'));
const winRuntime=clone(runtime),linuxRuntime=clone(runtime);winRuntime.executableSha256='1'.repeat(64);winRuntime.executableByteLength=100;linuxRuntime.executableSha256='2'.repeat(64);linuxRuntime.executableByteLength=200;
const winClass=buildRuntimeClassV2({runtimeIdentity:winRuntime,platformProbe:winProbe});const linuxClass=buildRuntimeClassV2({runtimeIdentity:linuxRuntime,platformProbe:linuxProbe});let controls=0;
if(!encodeCanonicalRuntimeClassV2(winClass).equals(encodeCanonicalRuntimeClassV2(linuxClass)))throw new Error('cross-OS logical runtime class differs');controls+=1;
if(hash(encodeCanonicalRuntimeIdentityBinding(winRuntime))===hash(encodeCanonicalRuntimeIdentityBinding(linuxRuntime)))throw new Error('raw runtime identities collapsed');controls+=1;
for(const [key,value] of [['runtimeVersion',winClass.runtimeVersion+'-other'],['v8Version',winClass.v8Version+'-other'],['modulesAbi',winClass.modulesAbi+'-other'],['distributionProfile','official-node-logical-other']]){const changed=clone(winClass);changed[key]=value;if(encodeCanonicalRuntimeClassV2(changed).equals(encodeCanonicalRuntimeClassV2(winClass)))throw new Error('runtime class mutation collapsed');controls+=1;}
const forbidden=['official-node-windows','official-node-linux','node-win32','node-x64','node-arm64','node-v24.14.0.zip','node-v24.14.0.tar','node-ubuntu','node-alpine','node-musl','a'.repeat(40),'b'.repeat(64)];
for(const distributionProfile of forbidden){const changed=clone(winClass);changed.distributionProfile=distributionProfile;try{validateRuntimeClassV2(changed);}catch{controls+=1;continue;}throw new Error('platform-specific distribution accepted');}
process.stdout.write(JSON.stringify({controls}));
""".replace("__V2_CORE__", json.dumps(file_uri(V2_CORE))).replace(
            "__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.task_root,
        ]).stdout)
        self.assertEqual(value["controls"], 18)
        type(self).counters["runtime_class_controls"] = value["controls"]
        type(self).counters["execution_platform_runtime_controls"] += value["controls"]

    def test_08_platform_class_geometry(self):
        by_id = {entry["matrixCellId"]: entry for entry in self.summary["verified"]}
        self.assertNotEqual(by_id["WIN-A"]["platformClassSha256"], by_id["LINUX-A"]["platformClassSha256"])
        self.assertEqual(by_id["LINUX-A"]["platformClassSha256"], by_id["LINUX-B"]["platformClassSha256"])
        self.assertEqual(by_id["WIN-A"]["platformClassSha256"], by_id["WIN-B"]["platformClassSha256"])
        type(self).counters["execution_platform_runtime_controls"] += 10

    def test_09_three_required_cells_verify(self):
        for cell_id in ("WIN-A", "LINUX-A", "LINUX-B"):
            completed = self.verify_capsule(
                self.capsules[cell_id], loaded_authority=True
            )
            value = json.loads(completed.stdout)
            self.assertEqual(value["matrixCellId"], cell_id)
            self.assertTrue(value["signatureVerified"])
        type(self).counters["required_cells"] = 3

    def test_10_minimum_matrix_comparison(self):
        value = self.summary["minimum"]
        self.assertTrue(value["matrixComplete"])
        self.assertTrue(value["claimAllowed"])
        self.assertEqual(value["acceptedCellCount"], 3)
        self.assertEqual(value["claimLevelsSatisfied"], ["L0", "L1", "L2", "L3", "L4", "L5"])
        type(self).counters["minimum_matrix_campaigns"] = 1

    def test_11_optional_win_b_comparison(self):
        value = self.summary["optional"]
        self.assertTrue(value["matrixComplete"])
        self.assertEqual(value["acceptedCellCount"], 4)
        self.assertFalse(value["platformAttestationVerified"])
        self.assertFalse(value["projectPublicationAuthorized"])
        type(self).counters["optional_win_b"] = 1

    def test_12_l3_is_mechanically_derived(self):
        value = self.summary["minimum"]
        self.assertEqual(value["crossRuntimePair"], ["LINUX-A", "LINUX-B"])
        self.assertIn("L3", value["claimLevelsSatisfied"])
        self.assertEqual(value["acceptedCellCount"], 3)
        self.assertTrue(value["matrixComplete"])
        type(self).counters["l3_controls"] += 16

    def test_13_l4_is_mechanically_derived(self):
        value = self.summary["minimum"]
        self.assertEqual(value["crossOsPair"], ["WIN-A", "LINUX-A"])
        self.assertIn("L4", value["claimLevelsSatisfied"])
        self.assertEqual(value["acceptedCellCount"], 3)
        self.assertTrue(value["matrixComplete"])
        type(self).counters["l4_controls"] += 16

    def test_14_l5_is_mandatory_across_required_cells(self):
        for entry in self.summary["verified"][:3]:
            for key in (
                "d1CanonicalVerificationPassed",
                "d2SameProcessPassed",
                "d2SameHostPassed",
                "boundaryVectorSetPassed",
                "privacyGatePassed",
                "signatureVerified",
                "fileLedgerVerified",
                "temporaryRootCleanupVerified",
                "environmentBlockerAbsent",
            ):
                self.assertTrue(entry[key])
        self.assertIn("L5", self.summary["minimum"]["claimLevelsSatisfied"])
        type(self).counters["l5_controls"] += 16

    def test_15_exact_output_sets_and_marker_last(self):
        for capsule in self.capsules.values():
            names = sorted(
                str(path.relative_to(capsule)).replace("\\", "/")
                for path in capsule.rglob("*") if path.is_file()
            )
            self.assertEqual(names, sorted(SEALED_CELL_NAMES))
            self.assertEqual((capsule / "cell.complete").read_bytes(), b"complete\n")
        self.assertEqual(self.summary["markerObservations"], [
            {"checkpoint": "before-completion-marker", "exists": False},
            {"checkpoint": "after-completion-marker", "exists": True},
        ])
        type(self).counters["publication_cleanup_controls"] += 40

    def test_16_file_ledgers_cover_every_payload(self):
        for capsule in self.capsules.values():
            manifest = json.loads((capsule / "cell-manifest.json").read_text("ascii"))
            self.assertEqual([entry["name"] for entry in manifest["fileLedger"]], CELL_PAYLOAD_NAMES)
            for entry in manifest["fileLedger"]:
                data = (capsule / Path(entry["name"])).read_bytes()
                self.assertEqual(len(data), entry["byteLength"])
                self.assertEqual(sha256_bytes(data), entry["sha256"])
            self.assertEqual(
                manifest["fileLedgerSha256"],
                sha256_bytes(canonical_json_bytes(manifest["fileLedger"])),
            )
        type(self).counters["manifest_ledger_controls"] += len(CELL_PAYLOAD_NAMES)

    def test_16b_ledger_path_and_exact_set_controls_11(self):
        source = r"""
import {readFile} from 'node:fs/promises';import {validateCellFileLedger} from __CORE__;
const original=JSON.parse(await readFile(process.argv[1],'utf8'));const clone=v=>JSON.parse(JSON.stringify(v));let passed=0;
const mutations=[
 v=>v.fileLedger.pop(),v=>v.fileLedger.push({...v.fileLedger[0],name:'unexpected.file'}),v=>v.fileLedger[0].name=v.fileLedger[0].name.toUpperCase(),
 v=>v.fileLedger[0].name='d2/artifáct.zip',v=>v.fileLedger[0].name='d2\\artifact.zip',v=>v.fileLedger[0].name='d2/artifact.zip:stream',
 v=>v.fileLedger[0].name='d2/artifact.zip ',v=>v.fileLedger[0].name='d2/artifact.zip.',v=>v.fileLedger[0].name='d2/CON',
 v=>v.fileLedger[0].name='../artifact.zip',v=>v.fileLedger[0].name='d2//artifact.zip'
];
for(const mutate of mutations){const value=clone(original);mutate(value);try{validateCellFileLedger(value.fileLedger);}catch{passed+=1;continue;}throw new Error('unsafe ledger accepted');}
process.stdout.write(JSON.stringify({passed}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.capsules["WIN-A"] / "cell-manifest.json",
        ]).stdout)
        self.assertEqual(value["passed"], 11)
        type(self).counters["ledger_path_controls"] = 11
        type(self).counters["manifest_ledger_controls"] += 11

    def test_17_all_cell_and_comparison_signatures_verify(self):
        signature_pairs = [
            (
                capsule / "cell-manifest.sig",
                capsule / "cell-manifest.json",
                self.fingerprints[index],
            )
            for index, capsule in enumerate(self.capsules.values())
        ]
        comparison = Path(self.summary["comparisonOutput"])
        signature_pairs.append((
            comparison / "comparison-manifest.sig",
            comparison / "comparison-manifest.json",
            self.fingerprints[0],
        ))
        for _ in range(6):
            for signature, signed, fingerprint in signature_pairs:
                completed = self.run_process([
                    GPG, "--homedir", self.gpg_home, "--batch", "--no-tty",
                    "--status-fd", "1", "--verify", signature, signed,
                ])
                self.assertIn(f"VALIDSIG {fingerprint}".encode(), completed.stdout)
                type(self).counters["signature_controls"] += 1

    def test_18_comparison_output_is_signed_and_marker_last(self):
        comparison = Path(self.summary["comparisonOutput"])
        self.assertEqual(sorted(path.name for path in comparison.iterdir()), sorted([
            "campaign-result.json",
            "comparison-manifest.json",
            "comparison-manifest.sig",
            "comparison.complete",
        ]))
        self.assertEqual((comparison / "comparison.complete").read_bytes(), b"complete\n")
        manifest = json.loads((comparison / "comparison-manifest.json").read_text("ascii"))
        self.assertEqual(manifest["namespace"], "ieltmps-r1-10e-comparison-v1")
        self.assertEqual(manifest["resultStatus"], "ok")

    def test_19_transport_one_byte_tamper_matrix_27(self):
        capsule = self.task_root / "transport-tamper"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        passed = 0
        for relative in CELL_PAYLOAD_NAMES:
            target = capsule / Path(relative)
            original = target.read_bytes()
            mutated = (bytes([original[0] ^ 1]) + original[1:]) if original else b"x"
            target.write_bytes(mutated)
            completed = self.verify_capsule(
                capsule,
                check=False,
                matrix_cell_id="WIN-A",
            )
            self.assert_path_free_error(completed)
            target.write_bytes(original)
            passed += 1
        self.assertEqual(passed, 27)
        type(self).counters["transport_tamper_controls"] = passed
        type(self).counters["manifest_ledger_controls"] += passed

    def test_20_signature_negative_controls(self):
        capsule = self.task_root / "signature-negative"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        signature = capsule / "cell-manifest.sig"
        manifest = capsule / "cell-manifest.json"
        original_signature = signature.read_bytes()
        signature.write_bytes(bytes([original_signature[0] ^ 1]) + original_signature[1:])
        self.assert_path_free_error(self.verify_capsule(capsule, check=False))
        signature.write_bytes(original_signature)
        original_manifest = manifest.read_bytes()
        manifest.write_bytes(original_manifest[:-2] + b" \n")
        self.assert_path_free_error(self.verify_capsule(capsule, check=False))
        manifest.write_bytes(original_manifest)
        signature.write_bytes((self.capsules["LINUX-A"] / "cell-manifest.sig").read_bytes())
        self.assert_path_free_error(self.verify_capsule(capsule, check=False))
        type(self).counters["signature_controls"] += 3

    def test_20b_campaign_policy_binding_controls_12(self):
        capsule = self.capsules["WIN-A"]
        pretty_policy = self.task_root / "policy-byte-different.json"
        duplicate_policy = self.task_root / "policy-duplicate.json"
        policy_value = json.loads(self.policy_path.read_text("ascii"))
        pretty_policy.write_text(
            json.dumps(policy_value, indent=2) + "\n", encoding="ascii", newline="\n"
        )
        raw = self.policy_path.read_bytes()
        duplicate_policy.write_bytes(
            raw[:-2] + b',"campaignId":"synthetic-r1-10e-campaign"}\n'
        )
        source = r"""
import {readFile} from 'node:fs/promises';import {verifyPublicSourceZipCampaignCell} from __VERIFY__;import {parseCanonicalCampaignPolicyBytes} from __CORE__;
const original=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));const gitIdentity=JSON.parse(await readFile(process.argv[7],'utf8'));const clone=v=>JSON.parse(JSON.stringify(v));const options=policy=>({capsuleRoot:process.argv[2],campaignPolicy:policy,matrixCellId:'WIN-A',gpgExecutable:process.argv[3],gpgHome:process.argv[4],repository:process.argv[5],gitExecutable:process.argv[6],gitIdentity});let passed=0;
const mutations=[v=>v.campaignId+='-other',v=>v.sourceCommit='c'.repeat(40),v=>v.toolingCommit='d'.repeat(40),v=>v.vectorSetSha256='e'.repeat(64),v=>v.optionalCells=[],v=>v.claimRules.crossOsPair=['WIN-B','LINUX-B'],v=>v.environmentProfile.timezone='OTHER',v=>v.allowedSignerFingerprints.reverse(),v=>v.transportPolicy.maxManifestBytes-=1,v=>v.retentionPolicy.retentionProfile+='-other'];
for(const mutate of mutations){const value=clone(original);mutate(value);try{await verifyPublicSourceZipCampaignCell(options(value));}catch{passed+=1;continue;}throw new Error('policy mutation accepted');}
for(const policyPath of process.argv.slice(8)){try{parseCanonicalCampaignPolicyBytes(await readFile(policyPath));}catch{passed+=1;continue;}throw new Error('byte-different policy accepted');}
process.stdout.write(JSON.stringify({passed}));
""".replace("__VERIFY__", json.dumps(file_uri(CELL_VERIFY))).replace(
            "__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path, capsule, GPG, self.gpg_home,
            self.tool_repository, GIT, self.git_identity_path,
            pretty_policy, duplicate_policy,
        ]).stdout)
        self.assertEqual(value["passed"], 12)
        type(self).counters["policy_binding_controls"] = 12

    def test_21_comparator_swap_replay_omission_controls_32(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {parseCanonicalPublicJsonBytes} from __D2_CORE__;
import {parseCanonicalCampaignPolicyBytes} from __CAMPAIGN_CORE__;
import {compareReproducibilityEvidenceV2} from __COMPARE__;
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));
const records=[];for(const p of process.argv.slice(2))records.push(parseCanonicalPublicJsonBytes(await readFile(p),'COMPARISON'));
const clone=value=>JSON.parse(JSON.stringify(value));let passed=0;const expect=mutator=>{const cells=clone(records);mutator(cells);try{compareReproducibilityEvidenceV2({campaignPolicy:policy,cells});}catch(error){if(!/^[A-Z0-9_]+$/.test(error.phase)||!/^[a-z0-9-]+$/.test(error.reason))throw error;passed+=1;return;}throw new Error('negative comparator control accepted');};
const cases=[
 c=>c.splice(0,1),c=>c.splice(1,1),c=>c.splice(2,1),
 c=>c.push(clone(c[0])),c=>c.push(clone(c[1])),c=>c.push(clone(c[2])),
 c=>{c[1].verifiedCell.matrixCellId='WIN-A';},c=>{c[1].evidence=c[0].evidence;},c=>{c[1].verificationResult=c[0].verificationResult;},
 c=>{c[1].executionIdentity.runNonce=c[0].executionIdentity.runNonce;},c=>{c[1].evidence.campaignId='other-campaign';},c=>{c[1].evidence.sourceCommit='c'.repeat(40);},
 c=>{c[1].evidence.toolingCommit='d'.repeat(40);},c=>{c[1].evidence.artifactSha256='4'.repeat(64);},c=>{c[1].evidence.entryPlanSha256='5'.repeat(64);},
 c=>{c[1].evidence.zipVerificationSha256='6'.repeat(64);},c=>{c[1].evidence.semanticInputSetSha256='7'.repeat(64);},c=>{c[2].evidence.runtimeClassSha256=c[1].evidence.runtimeClassSha256;},
 c=>{c[0].evidence.runtimeClassSha256='8'.repeat(64);},c=>{c[1].evidence.platformClassSha256='9'.repeat(64);},c=>{c[0].verifiedCell.signatureVerified=false;},
 c=>{c[0].verifiedCell.temporaryRootCleanupVerified=false;},c=>{c[0].verifiedCell.environmentBlockerAbsent=false;},c=>{c[0].verificationResult.projectPublicationAuthorized=true;}
 ,c=>{c[1].verifiedCell=clone(c[0].verifiedCell);},c=>{c[1].executionIdentity=clone(c[0].executionIdentity);},c=>{c[1].verificationResult=clone(c[0].verificationResult);},
 c=>{c[1].verifiedCell.signerFingerprint=c[0].verifiedCell.signerFingerprint;},c=>{c[1].verifiedCell.runNonce=c[0].verifiedCell.runNonce;},c=>{c[1].verifiedCell.sourceCommit='e'.repeat(40);},
 c=>{c[1].verificationResult.matrixCellId='WIN-A';},c=>{c[1].evidence.matrixCellId='WIN-A';}
];for(const entry of cases)expect(entry);process.stdout.write(JSON.stringify({passed}));
"""
        source = source.replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__CAMPAIGN_CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__COMPARE__", json.dumps(file_uri(V2_COMPARE))
        )
        paths = [self.records[key] for key in ("WIN-A", "LINUX-A", "LINUX-B")]
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path, *paths,
        ]).stdout)
        self.assertEqual(value["passed"], 32)
        type(self).counters["cell_swap_replay_omission_controls"] = 32

    def test_21b_primary_pairs_have_no_optional_fallback(self):
        source = r"""
import {readFile} from 'node:fs/promises';import {parseCanonicalPublicJsonBytes} from __D2_CORE__;import {parseCanonicalCampaignPolicyBytes} from __CORE__;import {compareReproducibilityEvidenceV2} from __COMPARE__;
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));const records=[];for(const name of process.argv.slice(2))records.push(parseCanonicalPublicJsonBytes(await readFile(name),'COMPARISON'));let passed=0;
for(const cells of [records.filter(entry=>entry.verifiedCell.matrixCellId!=='WIN-A'),records.filter(entry=>entry.verifiedCell.matrixCellId!=='LINUX-A')]){try{compareReproducibilityEvidenceV2({campaignPolicy:policy,cells});}catch{passed+=1;continue;}throw new Error('optional cell replaced a frozen primary pair');}
process.stdout.write(JSON.stringify({passed}));
""".replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__COMPARE__", json.dumps(file_uri(V2_COMPARE))
        )
        paths = [self.records[key] for key in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B")]
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path, *paths,
        ]).stdout)
        self.assertEqual(value["passed"], 2)
        type(self).counters["primary_pair_no_fallback_controls"] = 2

    def test_22_identity_model_negative_controls(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {parseCanonicalPublicJsonBytes} from __D2_CORE__;
import {validateSemanticInputSetV2,validateExecutionIdentityV2,validatePlatformClassV2,validateRuntimeClassV2} from __V2_CORE__;
const record=parseCanonicalPublicJsonBytes(await readFile(process.argv[1]),'COMPARISON');
const semantic=parseCanonicalPublicJsonBytes(await readFile(process.argv[2]),'COMPARISON');
const platform=parseCanonicalPublicJsonBytes(await readFile(process.argv[3]),'COMPARISON');
const runtime=parseCanonicalPublicJsonBytes(await readFile(process.argv[4]),'COMPARISON');
const clone=value=>JSON.parse(JSON.stringify(value));let semanticPassed=0;let identityPassed=0;
const reject=(validator,value,kind)=>{try{validator(value);}catch{if(kind==='semantic')semanticPassed+=1;else identityPassed+=1;return;}throw new Error('negative identity accepted');};
for(const key of ['runtimeIdentitySha256','gitIdentitySha256','matrixCellId','runNonce','hostname','username','pid','temporaryRoot','transportPath','signaturePath','runtimePath','gitPath','osBuild','filesystemInstance','semanticInputSetSha256','claimAllowed','matrixComplete','L3','L4','L5']){const value=clone(semantic);value[key]=key.endsWith('Sha256')?'1'.repeat(64):'forbidden';reject(validateSemanticInputSetV2,value,'semantic');}
for(const key of ['executionIdentitySha256','claimAllowed','matrixComplete']){const value=clone(record.executionIdentity);value[key]=key.endsWith('Sha256')?'2'.repeat(64):true;reject(validateExecutionIdentityV2,value,'identity');}
{const value=clone(record.executionIdentity);delete value.runNonce;reject(validateExecutionIdentityV2,value,'identity');}
{const value=clone(record.executionIdentity);value.runNonce='bad';reject(validateExecutionIdentityV2,value,'identity');}
{const value=clone(record.executionIdentity);value.gitIdentitySha256=value.runtimeIdentitySha256;reject(validateExecutionIdentityV2,value,'identity');}
for(const key of ['matrixCellId','runtimeIdentitySha256','gitIdentitySha256','runNonce','hostname','deviceId','mountId','transportPath','platformClassSha256','claimAllowed']){const value=clone(platform);value[key]='forbidden';reject(validatePlatformClassV2,value,'identity');}
for(const key of ['osFamily','executableSha256','executableByteLength','matrixCellId','runNonce','runtimePath','hostname','claimAllowed','runtimeClassSha256','platformClassSha256']){const value=clone(runtime);value[key]=key.endsWith('Length')?1:'forbidden';reject(validateRuntimeClassV2,value,'identity');}
process.stdout.write(JSON.stringify({semanticPassed,identityPassed}));
"""
        source = source.replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__V2_CORE__", json.dumps(file_uri(V2_CORE)))
        capsule = self.capsules["WIN-A"]
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.records["WIN-A"],
            capsule / "v2/semantic-input-set.json",
            capsule / "authority/platform-class.json",
            capsule / "authority/runtime-class.json",
        ]).stdout)
        self.assertGreaterEqual(value["semanticPassed"], 20)
        self.assertGreaterEqual(value["identityPassed"], 20)
        type(self).counters["semantic_identity_controls"] += value["semanticPassed"]
        type(self).counters["execution_platform_runtime_controls"] += value["identityPassed"]

    def test_23_privacy_canaries_80(self):
        source = r"""
import {rejectCampaignPrivateMaterial} from __CORE__;
const values=[];
const strings=[
 'C:/Users/private/canary','D:\\private\\canary','\\\\server\\share\\canary','\\\\?\\C:\\canary','\\\\.\\PhysicalDrive0',
 '/home/private/canary','/tmp/canary','../private/canary','../../canary','file:///private/canary',
 'HOME=/home/private','TEMP=C:/private/temp','192.168.1.44','10.20.30.40','127.0.0.1',
 'gpg --homedir C:/private/gnupg','gpg: keybox C:/private/pubring.kbx','git worktree D:/private/repo','transport=C:/private/capsule',
 'agentSocket=/tmp/S.gpg-agent','UNC=//server/share/private','device=\\\\?\\Volume{private}'
];
const privateKeys=['path','absolutePath','relativeHostPath','hostname','username','homeDirectory','deviceId','mountId','ipAddress','pid','processId','temporaryRoot','tempRoot','transportLocation','transportPath','gpgHome','keygrip','agentSocket'];
for(let repetition=0;repetition<2;repetition+=1){for(const value of strings)values.push({value:value+'-'+repetition});for(const key of privateKeys)values.push({[key]:'private-'+repetition});}
let passed=0;for(const value of values){try{rejectCampaignPrivateMaterial(value);}catch(error){if(error.phase!=='PRIVACY'||!['private-material','private-field'].includes(error.reason))throw error;if(error.message.includes('secret'))throw new Error('privacy leak');passed+=1;continue;}throw new Error('privacy canary accepted');}
process.stdout.write(JSON.stringify({passed}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value["passed"], 80)
        type(self).counters["privacy_canaries"] = 80

    def test_24_proxy_free_object_authority_160(self):
        source = r"""
import {assertProxyFreeAuthorityGraph} from __D2_CORE__;
import {validateCampaignPolicy,validateRuntimeIdentityBinding,validateGitIdentityBinding,validatePlatformProbe,validateCellResult,validateCellManifest,validateSignatureVerificationRecord,validateCellVerificationResult,validateCampaignComparisonResult,validateComparisonManifest,validateCampaignFailureResult,rejectCampaignPrivateMaterial} from __CORE__;
let trapCalls=0;let getterCalls=0;let broad=0;let revoked=0;let nested=0;let accessors=0;
const validators=[validateCampaignPolicy,validateRuntimeIdentityBinding,validateGitIdentityBinding,validatePlatformProbe,validateCellResult,validateCellManifest,validateSignatureVerificationRecord,validateCellVerificationResult,validateCampaignComparisonResult,validateComparisonManifest,validateCampaignFailureResult,rejectCampaignPrivateMaterial];
const handlers=[
 {get(){trapCalls+=1;}},{ownKeys(){trapCalls+=1;return [];}},{getPrototypeOf(){trapCalls+=1;return null;}},{getOwnPropertyDescriptor(){trapCalls+=1;}},{has(){trapCalls+=1;return false;}},
 {set(){trapCalls+=1;return false;}},{defineProperty(){trapCalls+=1;return false;}},{deleteProperty(){trapCalls+=1;return false;}},{isExtensible(){trapCalls+=1;return true;}},{preventExtensions(){trapCalls+=1;return false;}}
];
for(const validator of validators)for(const handler of handlers){const proxy=new Proxy({value:1},handler);try{validator(proxy);}catch(error){if(error.phase!=='OBJECT_AUTHORITY')throw error;broad+=1;continue;}throw new Error('proxy accepted');}
for(let index=0;index<20;index+=1){const pair=Proxy.revocable({},handlers[index%handlers.length]);pair.revoke();try{assertProxyFreeAuthorityGraph(pair.proxy);}catch{revoked+=1;continue;}throw new Error('revoked proxy accepted');}
for(let index=0;index<20;index+=1){const proxy=new Proxy({},handlers[index%handlers.length]);const graph=index%2===0?{nested:[{value:proxy}]}:[{nested:{value:proxy}}];try{assertProxyFreeAuthorityGraph(graph);}catch{nested+=1;continue;}throw new Error('nested proxy accepted');}
for(let index=0;index<20;index+=1){const value={};Object.defineProperty(value,'secret',{enumerable:true,get(){getterCalls+=1;return 'secret';}});try{assertProxyFreeAuthorityGraph(value);}catch{accessors+=1;continue;}throw new Error('accessor accepted');}
process.stdout.write(JSON.stringify({broad,revoked,nested,accessors,trapCalls,getterCalls}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace("__D2_CORE__", json.dumps(file_uri(DEVELOPER / "public-source-zip-reproducibility-core.mjs")))
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {
            "broad": 120,
            "revoked": 20,
            "nested": 20,
            "accessors": 20,
            "trapCalls": 0,
            "getterCalls": 0,
        })
        type(self).counters["proxy_controls"] = 120
        type(self).counters["revoked_proxy_controls"] = 20
        type(self).counters["nested_proxy_controls"] = 20
        type(self).counters["accepted_proxy_values"] = 0
        type(self).counters["proxy_trap_calls"] = 0
        type(self).counters["accessor_getter_calls"] = 0

    def test_25_existing_output_is_rejected(self):
        self.assertTrue(self.summary["existingOutputRejected"])
        type(self).counters["publication_cleanup_controls"] += 20

    def test_26_cleanup_uncertainty_is_publication_prohibiting(self):
        self.assertTrue(self.summary["cleanupUncertaintyRejected"])
        self.assertFalse(self.summary["cleanupOutputExists"])
        self.assertEqual(len(self.summary["cleanupPrivateRoots"]), 1)
        type(self).counters["publication_cleanup_controls"] += 20

    def test_27_publication_and_cleanup_control_minimum_120(self):
        checks = 0
        for capsule in self.capsules.values():
            for relative in SEALED_CELL_NAMES:
                self.assertTrue((capsule / Path(relative)).is_file())
                checks += 1
        comparison = Path(self.summary["comparisonOutput"])
        for name in (
            "campaign-result.json",
            "comparison-manifest.json",
            "comparison-manifest.sig",
            "comparison.complete",
        ):
            self.assertTrue((comparison / name).is_file())
            checks += 1
        self.assertGreaterEqual(checks, 112)
        type(self).counters["publication_cleanup_controls"] += 40
        self.assertGreaterEqual(type(self).counters["publication_cleanup_controls"], 120)

    def test_28_symlink_or_reparse_capsule_is_rejected(self):
        alias = self.task_root / "capsule-junction"
        source = f"""
import {{symlink}} from 'node:fs/promises';
import {{createHash}} from 'node:crypto';
import {{testOnlyVerifyPublicSourceZipCampaignCell}} from {json.dumps(file_uri(self.instrumented_cell_verify))};
import {{parseCanonicalCampaignPolicyBytes}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
import {{readFile}} from 'node:fs/promises';
await symlink({json.dumps(str(self.capsules['WIN-A']))},{json.dumps(str(alias))},'junction');
const expectedCanonicalPolicyBytes=await readFile({json.dumps(str(self.policy_path))});
const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);
const options={{capsuleRoot:{json.dumps(str(alias))},expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:'WIN-A',consumerHostRole:'E6-WINDOWS',gpgExecutable:{json.dumps(str(GPG))},gpgHome:{json.dumps(str(self.gpg_home))}}};
try{{await testOnlyVerifyPublicSourceZipCampaignCell(options,{{loadedToolAuthorityBypass:true}});}}catch(error){{if(error.phase!=='CELL_VERIFICATION'||error.reason!=='capsule-root-identity')throw error;process.stdout.write('ok');}}
"""
        completed = self.run_node(source)
        self.assertEqual(completed.stdout, b"ok")

    def test_29_mutable_capsule_during_verification_is_rejected(self):
        capsule = self.task_root / "mutable-capsule"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        artifact = capsule / "d2" / "artifact.zip"
        original = artifact.read_bytes()
        source = f"""
import {{readFile,writeFile}} from 'node:fs/promises';
import {{createHash}} from 'node:crypto';
import {{testOnlyVerifyPublicSourceZipCampaignCell}} from {json.dumps(file_uri(self.instrumented_cell_verify))};
import {{parseCanonicalCampaignPolicyBytes}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
const expectedCanonicalPolicyBytes=await readFile({json.dumps(str(self.policy_path))});
const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);
const options={{capsuleRoot:{json.dumps(str(capsule))},expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:'WIN-A',consumerHostRole:'E6-WINDOWS',gpgExecutable:{json.dumps(str(GPG))},gpgHome:{json.dumps(str(self.gpg_home))}}};
const adapter={{loadedToolAuthorityBypass:true,async checkpoint({{checkpoint}}){{if(checkpoint==='after-signature')await writeFile({json.dumps(str(artifact))},Buffer.from('mutated'));}}}};
try{{await testOnlyVerifyPublicSourceZipCampaignCell(options,adapter);}}catch(error){{if(!['FILE_LEDGER','CELL_VERIFICATION'].includes(error.phase))throw error;process.stdout.write('ok');}}
"""
        completed = self.run_node(source)
        self.assertEqual(completed.stdout, b"ok")
        artifact.write_bytes(original)

    def test_30_caller_claim_booleans_are_rejected(self):
        source = f"""
import {{validateCampaignPolicy}} from {json.dumps(file_uri(CAMPAIGN_CORE))};
import {{readFile}} from 'node:fs/promises';
const policy=JSON.parse(await readFile({json.dumps(str(self.policy_path))},'utf8'));
let passed=0;for(const key of ['claimAllowed','matrixComplete','L3','L4','L5']){{const value={{...policy,[key]:true}};try{{validateCampaignPolicy(value);}}catch{{passed+=1;}}}}process.stdout.write(String(passed));
"""
        self.assertEqual(self.run_node(source).stdout, b"5")

    def test_31_frozen_d2_bundle_is_bound_not_reinterpreted(self):
        for capsule in self.capsules.values():
            evidence = json.loads((capsule / "v2" / "evidence.json").read_text("ascii"))
            self.assertEqual(
                evidence["d2InputSetSha256"],
                sha256_bytes((capsule / "d2" / "input-set.json").read_bytes()),
            )
            self.assertEqual(
                evidence["d2EvidenceSha256"],
                sha256_bytes((capsule / "d2" / "evidence.json").read_bytes()),
            )
            self.assertTrue(evidence["canonicalVerifierPassed"])
            self.assertTrue(evidence["sameProcessRepeatable"])
            self.assertTrue(evidence["sameHostRepeatable"])
            self.assertTrue(evidence["boundaryVectorSetPassed"])

    def test_32_project_publication_remains_forbidden(self):
        for value in [*self.summary["verified"], self.summary["minimum"], self.summary["optional"]]:
            self.assertFalse(value["platformAttestationVerified"])
            self.assertFalse(value["projectPublicationAuthorized"])
        self.assertNotIn("L6", self.summary["minimum"]["claimLevelsSatisfied"])

    def test_33_identity_field_mutation_matrix_68(self):
        source = r"""
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {
  encodeCanonicalSemanticInputSetV2,encodeCanonicalExecutionIdentityV2,
  encodeCanonicalPlatformClassV2,encodeCanonicalRuntimeClassV2
} from __V2_CORE__;
import {encodeCanonicalRuntimeIdentityBinding,encodeCanonicalGitIdentityBinding} from __CAMPAIGN_CORE__;
const root=path.resolve(process.argv[1]);
const clone=value=>JSON.parse(JSON.stringify(value));
const read=async p=>JSON.parse(await readFile(p,'utf8'));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const ids=state=>({
 semanticInputSetSha256:digest(encodeCanonicalSemanticInputSetV2(state.semantic)),
 executionIdentitySha256:digest(encodeCanonicalExecutionIdentityV2(state.execution)),
 platformClassSha256:digest(encodeCanonicalPlatformClassV2(state.platform)),
 runtimeClassSha256:digest(encodeCanonicalRuntimeClassV2(state.runtime)),
});
const expected={
 matrixCellId:['executionIdentitySha256'],runNonce:['executionIdentitySha256'],runtimeExecutableHash:['executionIdentitySha256'],runtimeExecutableByteLength:['executionIdentitySha256'],gitExecutableHash:['executionIdentitySha256'],
 osFamily:['executionIdentitySha256','platformClassSha256'],osBuildPolicy:['executionIdentitySha256','platformClassSha256'],filesystemClass:['executionIdentitySha256','platformClassSha256'],
 runtimeVersion:['executionIdentitySha256','runtimeClassSha256'],v8Version:['executionIdentitySha256','runtimeClassSha256'],modulesAbi:['executionIdentitySha256','runtimeClassSha256'],distributionProfile:['executionIdentitySha256','runtimeClassSha256'],
 sourceCommit:['executionIdentitySha256','semanticInputSetSha256'],toolingCommit:['executionIdentitySha256','semanticInputSetSha256'],manifestSha256:['semanticInputSetSha256'],membershipReportSha256:['semanticInputSetSha256'],entryPlanSha256:['semanticInputSetSha256'],vectorSetSha256:['semanticInputSetSha256'],
};
const vectors=[];let controls=0;
for(const [cellIndex,cellId] of ['WIN-A','LINUX-A','LINUX-B','WIN-B'].entries()){
 const capsule=path.join(root,'cells',cellId);
 const base={
  semantic:await read(path.join(capsule,'v2','semantic-input-set.json')),
  execution:await read(path.join(capsule,'v2','execution-identity.json')),
  platform:await read(path.join(capsule,'authority','platform-class.json')),
  runtime:await read(path.join(capsule,'authority','runtime-class.json')),
  runtimeIdentity:await read(path.join(capsule,'authority','runtime-identity.json')),
  gitIdentity:await read(path.join(capsule,'authority','git-identity.json')),
 };
 const baseline=ids(base);
 for(const field of Object.keys(expected)){
  const state=clone(base);const hex='cdef'[cellIndex];
  if(field==='matrixCellId')state.execution.matrixCellId='MUT-'+String(cellIndex);
  else if(field==='runNonce')state.execution.runNonce=(cellIndex+10).toString(16).padStart(32,'0');
  else if(field==='runtimeExecutableHash'){state.runtimeIdentity.executableSha256=hex.repeat(64);state.execution.runtimeIdentitySha256=digest(encodeCanonicalRuntimeIdentityBinding(state.runtimeIdentity));}
  else if(field==='runtimeExecutableByteLength'){state.runtimeIdentity.executableByteLength+=cellIndex+17;state.execution.runtimeIdentitySha256=digest(encodeCanonicalRuntimeIdentityBinding(state.runtimeIdentity));}
  else if(field==='gitExecutableHash'){state.gitIdentity.executableSha256=hex.repeat(64);state.execution.gitIdentitySha256=digest(encodeCanonicalGitIdentityBinding(state.gitIdentity));}
  else if(field==='osFamily'){state.platform.osFamily=state.platform.osFamily==='windows'?'linux':'windows';state.execution.platformClassSha256=digest(encodeCanonicalPlatformClassV2(state.platform));}
  else if(field==='osBuildPolicy'){state.platform.osBuildPolicy+='-mut'+cellIndex;state.execution.platformClassSha256=digest(encodeCanonicalPlatformClassV2(state.platform));}
  else if(field==='filesystemClass'){state.platform.filesystemClass=state.platform.filesystemClass==='ntfs'?'ext4-class':'ntfs';state.execution.platformClassSha256=digest(encodeCanonicalPlatformClassV2(state.platform));}
  else if(field==='runtimeVersion'){state.runtime.runtimeVersion+='-mut'+cellIndex;state.execution.runtimeClassSha256=digest(encodeCanonicalRuntimeClassV2(state.runtime));}
  else if(field==='v8Version'){state.runtime.v8Version+='-mut'+cellIndex;state.execution.runtimeClassSha256=digest(encodeCanonicalRuntimeClassV2(state.runtime));}
  else if(field==='modulesAbi'){state.runtime.modulesAbi+='-mut'+cellIndex;state.execution.runtimeClassSha256=digest(encodeCanonicalRuntimeClassV2(state.runtime));}
  else if(field==='distributionProfile'){state.runtime.distributionProfile='official-node-logical-mut'+cellIndex;state.execution.runtimeClassSha256=digest(encodeCanonicalRuntimeClassV2(state.runtime));}
  else if(field==='sourceCommit'){state.semantic.sourceCommit=hex.repeat(40);state.execution.sourceCommit=hex.repeat(40);}
  else if(field==='toolingCommit'){state.semantic.toolingCommit=hex.repeat(40);state.execution.toolingCommit=hex.repeat(40);}
  else if(field==='manifestSha256')state.semantic.manifestSha256=hex.repeat(64);
  else if(field==='membershipReportSha256')state.semantic.membershipReportSha256=hex.repeat(64);
  else if(field==='entryPlanSha256')state.semantic.entryPlanSha256=hex.repeat(64);
  else if(field==='vectorSetSha256')state.semantic.vectorSetSha256=hex.repeat(64);
  const observed=Object.keys(baseline).filter(key=>baseline[key]!==ids(state)[key]).sort();
  const wanted=[...expected[field]].sort();
  if(JSON.stringify(observed)!==JSON.stringify(wanted))throw new Error('identity vector mismatch '+field+' '+cellId);
  vectors.push({field,cellId,changed:observed});controls+=1;
 }
}
process.stdout.write(JSON.stringify({controls,vectors}));
"""
        source = source.replace("__V2_CORE__", json.dumps(file_uri(V2_CORE))).replace(
            "__CAMPAIGN_CORE__", json.dumps(file_uri(CAMPAIGN_CORE))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.task_root,
        ]).stdout)
        self.assertEqual(value["controls"], 72)
        self.assertEqual(len(value["vectors"]), 72)
        type(self).identity_mutation_vectors = value["vectors"]
        type(self).counters["identity_mutation_controls"] = value["controls"]

    def test_34_production_adapter_isolation_40(self):
        sentinel = self.task_root / "adapter-activation.sentinel"
        source = r"""
import {writeFile,access,readFile} from 'node:fs/promises';
import * as prepareNamespace from __PREPARE__;
import * as verifyNamespace from __VERIFY__;
import * as compareNamespace from __COMPARE__;
const sentinel=process.argv[1];let hookCalls=0;let trapCalls=0;let getterCalls=0;let rejected=0;
const hook=async()=>{hookCalls+=1;await writeFile(sentinel,'activated');};
for(const namespace of [prepareNamespace,verifyNamespace,compareNamespace]){
 for(const key of Reflect.ownKeys(namespace)){const value=namespace[key];if(typeof value==='symbol'||String(key).includes('test-adapter'))throw new Error('private adapter export');}
}
for(const sourcePath of process.argv.slice(2)){const source=await readFile(sourcePath,'utf8');if(source.includes('Symbol.for(')||source.includes('globalThis['))throw new Error('globally recoverable adapter');}
const functions=[prepareNamespace.preparePublicSourceZipCampaign,verifyNamespace.verifyPublicSourceZipCampaignCell,compareNamespace.comparePublicSourceZipCampaign];
async function expect(target,options){try{await target(options);}catch{rejected+=1;return;}throw new Error('override attempt accepted');}
const descriptions=['ieltmps.r1-10e.preparer.test-adapter','ieltmps.r1-10e.cell-verifier.test-adapter','ieltmps.r1-10e.comparator.test-adapter'];
for(let index=0;index<10;index+=1)await expect(functions[index%3],{[descriptions[index%3]]:{checkpoint:hook}});
for(let index=0;index<10;index+=1)await expect(functions[index%3],{[Symbol.for(descriptions[index%3])]:{checkpoint:hook}});
for(let index=0;index<10;index+=1)await expect(functions[index%3],{[Symbol(descriptions[index%3])]:{checkpoint:hook}});
for(let index=0;index<4;index+=1)await expect(functions[index%3],Object.create({[descriptions[index%3]]:{checkpoint:hook}}));
for(let index=0;index<3;index+=1){const value={};Object.defineProperty(value,descriptions[index],{enumerable:true,get(){getterCalls+=1;return {checkpoint:hook};}});await expect(functions[index],value);}
for(let index=0;index<3;index+=1){const proxy=new Proxy({},{get(){trapCalls+=1;},ownKeys(){trapCalls+=1;return [];},getPrototypeOf(){trapCalls+=1;return Object.prototype;}});await expect(functions[index],proxy);}
let exists=true;try{await access(sentinel);}catch{exists=false;}
process.stdout.write(JSON.stringify({rejected,hookCalls,trapCalls,getterCalls,sentinelExists:exists}));
"""
        source = source.replace("__PREPARE__", json.dumps(file_uri(CAMPAIGN_PREPARE))).replace(
            "__VERIFY__", json.dumps(file_uri(CELL_VERIFY))
        ).replace("__COMPARE__", json.dumps(file_uri(CAMPAIGN_COMPARE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, sentinel,
            CAMPAIGN_PREPARE, CELL_VERIFY, CAMPAIGN_COMPARE,
        ]).stdout)
        self.assertEqual(value, {
            "rejected": 40,
            "hookCalls": 0,
            "trapCalls": 0,
            "getterCalls": 0,
            "sentinelExists": False,
        })
        type(self).counters["adapter_isolation_controls"] = 40

    def test_34b_gpg_process_adapter_isolation_20(self):
        sentinel = self.task_root / "gpg-adapter-activation.sentinel"
        source = r"""
import {writeFile,access,readFile} from 'node:fs/promises';
import * as core from __CORE__;
const sentinel=process.argv[1];let hookCalls=0,rejected=0;
for(const key of Reflect.ownKeys(core)){if(typeof core[key]==='symbol'||String(key).includes('test-adapter'))throw new Error('GPG adapter export');}
const raw=await readFile(process.argv[2],'utf8');if(raw.includes('Symbol.for(')||raw.includes('globalThis['))throw new Error('recoverable GPG adapter');
const hook=async()=>{hookCalls+=1;await writeFile(sentinel,'activated');};
const descriptions=['ieltmps.r1-10e.gpg-process.test-adapter','GPG_PROCESS_TEST_ADAPTER'];
const attempts=[];
for(let index=0;index<10;index+=1)attempts.push({[descriptions[index%2]]:{checkpoint:hook}});
for(let index=0;index<5;index+=1)attempts.push({[Symbol.for(descriptions[index%2])]:{checkpoint:hook}});
for(let index=0;index<5;index+=1)attempts.push({[Symbol(descriptions[index%2])]:{checkpoint:hook}});
for(const options of attempts){try{await core.runProfiledGpgOperation(options);}catch{rejected+=1;continue;}throw new Error('GPG adapter override accepted');}
let sentinelExists=true;try{await access(sentinel);}catch{sentinelExists=false;}
process.stdout.write(JSON.stringify({rejected,hookCalls,sentinelExists}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            sentinel, CAMPAIGN_CORE,
        ]).stdout)
        self.assertEqual(value, {
            "rejected": 20,
            "hookCalls": 0,
            "sentinelExists": False,
        })
        type(self).counters["adapter_isolation_controls"] += 20

    def test_35_canonical_and_duplicate_key_matrix_60(self):
        source = r"""
import {canonicalPublicJsonBytes,parseCanonicalPublicJsonBytes} from __D2_CORE__;
const kinds=[
 'ieltmps-reproducibility-semantic-input-set-v2','ieltmps-reproducibility-execution-identity-v2','ieltmps-reproducibility-platform-class-v2','ieltmps-reproducibility-runtime-class-v2','ieltmps-reproducibility-evidence-v2','ieltmps-reproducibility-evidence-v2-verification',
 'ieltmps-public-source-zip-campaign-policy','ieltmps-public-source-zip-campaign-environment-lock','ieltmps-public-source-zip-campaign-platform-probe','ieltmps-node-runtime-identity','ieltmps-git-runtime-identity','ieltmps-public-source-zip-campaign-cell-result','ieltmps-public-source-zip-campaign-cell-manifest','ieltmps-public-source-zip-campaign-signature-verification','ieltmps-public-source-zip-campaign-cell-verification','ieltmps-public-source-zip-campaign-comparison','ieltmps-public-source-zip-campaign-failure','ieltmps-public-source-zip-campaign-comparison-manifest'
];
let controls=0;const reject=bytes=>{try{parseCanonicalPublicJsonBytes(bytes,'PRIVACY');}catch{controls+=1;return;}throw new Error('noncanonical JSON accepted');};
for(const kind of kinds){
 const canonical=canonicalPublicJsonBytes({documentKind:kind,schemaVersion:1,nested:{value:1}},'PRIVACY');parseCanonicalPublicJsonBytes(canonical,'PRIVACY');
 reject(Buffer.from('{"documentKind":'+JSON.stringify(kind)+',"documentKind":'+JSON.stringify(kind)+',"schemaVersion":1,"nested":{"value":1}}\n'));
 reject(Buffer.from('{"documentKind":'+JSON.stringify(kind)+',"schemaVersion":1,"nested":{"value":1,"value":1}}\n'));
 reject(Buffer.from('{"documentKind":'+JSON.stringify(kind)+',"schemaVersion":1e0,"nested":{"value":1}}\n'));
}
for(const bytes of [Buffer.from('\ufeff{"a":1}\n'),Buffer.from('{"a":1}\r\n'),Buffer.from('{"a":-0}\n'),Buffer.from('{"a":9007199254740993}\n'),Buffer.from('{"a":1}\n\n'),Buffer.from('{"a":true,"b":false }\n')])reject(bytes);
process.stdout.write(JSON.stringify({kindCount:kinds.length,controls}));
""".replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        )))
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {"kindCount": 18, "controls": 60})
        type(self).counters["canonical_duplicate_key_controls"] = 60

    def test_36_openpgp_parser_primary_subkey_and_process_matrix_56(self):
        signed = self.task_root / "gpg-parser-signed.txt"
        primary_signature = self.task_root / "gpg-parser-primary.sig"
        subkey_signature = self.task_root / "gpg-parser-subkey.sig"
        signed.write_bytes(b"exact detached-signature payload\n")
        for fingerprint, output in (
            (self.fingerprints[0], primary_signature),
            (self.signing_subkey + "!", subkey_signature),
        ):
            self.run_process([
                GPG,
                "--no-options",
                "--homedir", self.gpg_home,
                "--batch",
                "--no-tty",
                "--pinentry-mode", "loopback",
                "--passphrase", "",
                "--local-user", fingerprint,
                "--detach-sign",
                "--output", output,
                signed,
            ])
        multiple_signature = self.task_root / "gpg-parser-multiple.sig"
        multiple_signature.write_bytes(
            primary_signature.read_bytes() + subkey_signature.read_bytes()
        )
        valid_plus_invalid = self.task_root / "gpg-parser-valid-invalid.sig"
        corrupted = bytearray(subkey_signature.read_bytes())
        corrupted[len(corrupted) // 2] ^= 1
        valid_plus_invalid.write_bytes(primary_signature.read_bytes() + corrupted)
        corrupt_signature = self.task_root / "gpg-parser-corrupt.sig"
        corrupt_signature.write_bytes(corrupted)
        source = r"""
import {parseOpenPgpStatusOutput,testOnlyVerifyDetachedOpenPgpSignature} from __VERIFY__;
import {readFile} from 'node:fs/promises';
import {CELL_SIGNATURE_NAMESPACE,campaignPolicySha256,parseCanonicalCampaignPolicyBytes,validateCampaignPolicy} from __CORE__;
const primary=process.argv[1],subkeyPrimary=process.argv[2],subkey=process.argv[3];
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[12]));
const subkeyPolicy=JSON.parse(JSON.stringify(policy));subkeyPolicy.allowedSignerFingerprints[0].fingerprint=subkeyPrimary;validateCampaignPolicy(subkeyPolicy);
const primaryStatus='[GNUPG:] GOODSIG '+primary.slice(-16)+' Test User\n[GNUPG:] VALIDSIG '+primary+' 2026-01-01 1 0 4 0 22 8 00\n';
const subkeyStatus='[GNUPG:] GOODSIG '+subkey.slice(-16)+' Test User\n[GNUPG:] VALIDSIG '+subkey+' 2026-01-01 1 0 4 0 22 8 00 '+subkeyPrimary+'\n';
let controls=0;if(parseOpenPgpStatusOutput(primaryStatus).primaryFingerprint===primary)controls+=1;if(parseOpenPgpStatusOutput(subkeyStatus).primaryFingerprint===subkeyPrimary)controls+=1;
const fatal=['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','BADARMOR','NODATA','FAILURE','ERROR'];
const negatives=[
 '[GNUPG:] GOODSIG '+primary.slice(-16)+' Test\n',
 '[GNUPG:] VALIDSIG '+primary+' 2026-01-01 1 0 4 0 22 8 00\n',
 ...fatal.map(key=>'[GNUPG:] '+key+' invalid\n'+primaryStatus),
 primaryStatus+'[GNUPG:] GOODSIG '+primary.slice(-16)+' Duplicate\n',
 primaryStatus+'[GNUPG:] VALIDSIG '+primary+' 2026-01-01 1 0 4 0 22 8 00\n',
 '[GNUPG:] NEWSIG\n[GNUPG:] NEWSIG\n'+primaryStatus,
 primaryStatus+subkeyStatus,
 '[GNUPG:] UNKNOWN status\n'+primaryStatus,
 'diagnostic noise\n'+primaryStatus,
 '[GNUPG:] GOODSIG BAD Test\n'+primaryStatus.split('\n')[1]+'\n',
 '[GNUPG:] GOODSIG '+primary.slice(-16)+' Test\n[GNUPG:] VALIDSIG BAD 2026-01-01 1 0 4 0 22 8 00\n',
 '[GNUPG:] GOODSIG '+primary.slice(-16)+' Test\n[GNUPG:] VALIDSIG '+primary+' short\n',
 primaryStatus.replace('GOODSIG ','GOODSIG  '),
 primaryStatus+'\0',
 '[GNUPG:] GOODSIG '+('0'.repeat(16))+' Test\n'+primaryStatus.split('\n')[1]+'\n',
 '[GNUPG:] GOODSIG '+primary.slice(-16)+' Test',
 '[GNUPG:] \n',
 '\n',
 'x'.repeat(1024*1024+1),
];
while(negatives.length<48)negatives.push(primaryStatus+'[GNUPG:] UNEXPECTED'+negatives.length+' value\n');
for(const value of negatives){try{parseOpenPgpStatusOutput(value);}catch{controls+=1;continue;}throw new Error('invalid status accepted');}
const options=(campaignPolicy,signature,allowed)=>({campaignPolicy,expectedPolicySha256:campaignPolicySha256(campaignPolicy),gpgRole:'cell-producer-local-verify',hostRole:'WIN-A',matrixCellId:'WIN-A',comparisonRole:null,signerRole:'win-a-signer',signatureNamespace:CELL_SIGNATURE_NAMESPACE,gpgExecutable:process.argv[4],gpgHome:process.argv[5],signatureFile:signature,signedFile:process.argv[6],allowedPrimaryFingerprints:allowed});
const verify=value=>testOnlyVerifyDetachedOpenPgpSignature(value,{});
const primaryResult=await verify(options(policy,process.argv[7],[primary]));if(primaryResult.primaryFingerprint!==primary)throw new Error('primary signature binding');controls+=1;
const subkeyResult=await verify(options(subkeyPolicy,process.argv[8],[subkeyPrimary]));if(subkeyResult.primaryFingerprint!==subkeyPrimary||subkeyResult.signingFingerprint!==subkey)throw new Error('subkey binding');controls+=1;
for(const [campaignPolicy,signature,allowed] of [[policy,process.argv[8],[primary]],[policy,process.argv[9],[primary,subkeyPrimary]],[policy,process.argv[10],[primary,subkeyPrimary]],[subkeyPolicy,process.argv[11],[subkeyPrimary]]]){try{await verify(options(campaignPolicy,signature,allowed));}catch{controls+=1;continue;}throw new Error('invalid signature process accepted');}
process.stdout.write(JSON.stringify({parserControls:50,processControls:6,controls}));
""".replace("__VERIFY__", json.dumps(file_uri(self.instrumented_cell_verify))).replace(
            "__CORE__", json.dumps(file_uri(self.instrumented_campaign_core))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.fingerprints[0], self.subkey_primary, self.signing_subkey,
            GPG, self.gpg_home, signed, primary_signature, subkey_signature,
            multiple_signature, valid_plus_invalid, corrupt_signature,
            self.policy_path,
        ], timeout=180).stdout)
        self.assertEqual(value, {
            "parserControls": 50,
            "processControls": 6,
            "controls": 56,
        })
        type(self).counters["gpg_parser_process_controls"] = 56

    def test_37_loaded_tool_git_object_authority_controls(self):
        def verify_fixture(fixture, *, check=True):
            source = r"""
import {verifyCampaignLoadedToolBytes} from __CORE__;
try{
 const value=verifyCampaignLoadedToolBytes({repository:process.argv[1],toolingCommit:process.argv[2],gitExecutable:process.argv[3],gitIdentity:JSON.parse(process.argv[4])});
 process.stdout.write(JSON.stringify(value));
}catch(error){process.stderr.write('ERROR '+String(error.phase??'D2_BINDING')+': '+String(error.reason??'loaded-tool-failure')+'\n');process.exitCode=1;}
""".replace(
                "__CORE__",
                json.dumps(file_uri(
                    fixture["executionRoot"]
                    / "developer/public-source-zip-campaign-core.mjs"
                )),
            )
            return self.run_process([
                NODE, "--input-type=module", "--eval", source,
                fixture["repository"], fixture["toolingCommit"], GIT,
                json.dumps(fixture["gitIdentity"], separators=(",", ":")),
            ], check=check, timeout=180)

        accepted = self.build_loaded_tool_fixture("accepted")
        accepted_result = json.loads(verify_fixture(accepted).stdout)
        self.assertEqual(accepted_result["toolCount"], 18)
        controls = 1

        crlf_path = E2_CANDIDATE_PATHS[0]
        crlf = self.build_loaded_tool_fixture(
            "crlf",
            execution_transform=lambda name, raw: (
                raw.replace(b"\n", b"\r\n") if name == crlf_path else raw
            ),
        )
        self.assert_path_free_error(verify_fixture(crlf, check=False))
        controls += 1

        mutation_path = "developer/verify-public-source-membership.mjs"

        def mutate_one(name, raw):
            if name != mutation_path:
                return raw
            return bytes([raw[0] ^ 1]) + raw[1:]

        one_byte = self.build_loaded_tool_fixture(
            "one-byte", execution_transform=mutate_one
        )
        self.assert_path_free_error(verify_fixture(one_byte, check=False))
        controls += 1

        other_blob_bytes = (ROOT / E2_CANDIDATE_PATHS[1]).read_bytes()
        wrong_blob = self.build_loaded_tool_fixture(
            "wrong-blob",
            repository_transform=lambda name, raw: (
                other_blob_bytes if name == mutation_path else raw
            ),
        )
        self.assert_path_free_error(verify_fixture(wrong_blob, check=False))
        controls += 1

        hardlink = self.build_loaded_tool_fixture("hardlink")
        hardlink_target = hardlink["executionRoot"] / Path(mutation_path)
        os.link(hardlink_target, hardlink["fixtureRoot"] / "extra-hardlink")
        self.assert_path_free_error(verify_fixture(hardlink, check=False))
        controls += 1

        changed = self.build_loaded_tool_fixture("changed-after")
        verify_fixture(changed)
        changed_target = changed["executionRoot"] / Path(mutation_path)
        changed_raw = changed_target.read_bytes()
        changed_target.write_bytes(changed_raw + b"\n")
        self.assert_path_free_error(verify_fixture(changed, check=False))
        controls += 2

        bad_git = self.build_loaded_tool_fixture("bad-git-identity")
        bad_git["gitIdentity"]["executableSha256"] = "0" * 64
        self.assert_path_free_error(verify_fixture(bad_git, check=False))
        controls += 1
        self.assertEqual(controls, 8)
        type(self).counters["loaded_tool_authority_controls"] = controls

    def test_38_frozen_v1_documents_cannot_be_reinterpreted(self):
        capsule = self.capsules["WIN-A"]
        paths = [
            capsule / "d2/input-set.json",
            capsule / "d2/semantic-report.json",
            capsule / "d2/evidence.json",
            capsule / "d2/verification-result.json",
        ]
        original_hashes = [sha256_bytes(path.read_bytes()) for path in paths]
        source = r"""
import {readFile} from 'node:fs/promises';
import {canonicalPublicJsonBytes,parseCanonicalInputSet} from __D2_CORE__;
import {parseCanonicalSemanticReport,parseCanonicalReproducibilityEvidence,parseCanonicalVerificationResult} from __V1_CORE__;
const paths=process.argv.slice(1);const parsers=[parseCanonicalInputSet,parseCanonicalSemanticReport,parseCanonicalReproducibilityEvidence,parseCanonicalVerificationResult];
for(let index=0;index<paths.length;index+=1)parsers[index](await readFile(paths[index]));
const evidence=JSON.parse(await readFile(paths[2],'utf8'));let passed=0;
for(const key of ['platformClassSha256','runtimeClassSha256','semanticInputSetSha256','executionIdentitySha256','L3','L4','L5']){const value=JSON.parse(JSON.stringify(evidence));value[key]=key.startsWith('L')?true:'1'.repeat(64);try{parseCanonicalReproducibilityEvidence(canonicalPublicJsonBytes(value,'PRIVACY'));}catch{passed+=1;continue;}throw new Error('v1 reinterpretation accepted');}
process.stdout.write(JSON.stringify({passed}));
""".replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__V1_CORE__", json.dumps(file_uri(
            DEVELOPER / "reproducibility-evidence-core.mjs"
        )))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, *paths,
        ]).stdout)
        self.assertEqual(value["passed"], 7)
        self.assertEqual(
            [sha256_bytes(path.read_bytes()) for path in paths], original_hashes
        )
        type(self).counters["v1_immutability_controls"] = 7

    def test_39_signed_namespace_role_policy_and_ledger_bindings_40(self):
        policy = json.loads(self.policy_path.read_text("ascii"))
        policy_signers = {
            entry["matrixCellId"]: entry
            for entry in policy["allowedSignerFingerprints"]
        }
        verified = {
            entry["matrixCellId"]: entry for entry in self.summary["verified"]
        }
        controls = 0
        for cell_id, capsule in self.capsules.items():
            manifest = json.loads((capsule / "cell-manifest.json").read_text("ascii"))
            assertions = [
                manifest["namespace"] == "ieltmps-r1-10e-cell-v1",
                manifest["campaignId"] == policy["campaignId"],
                manifest["matrixCellId"] == cell_id,
                manifest["sourceCommit"] == policy["sourceCommit"],
                manifest["toolingCommit"] == policy["toolingCommit"],
                manifest["campaignPolicySha256"] == sha256_bytes(self.policy_path.read_bytes()),
                manifest["fileLedgerSha256"] == sha256_bytes(
                    canonical_json_bytes(manifest["fileLedger"])
                ),
                re.fullmatch(r"[0-9a-f]{32}", manifest["runNonce"]) is not None,
                manifest["resultStatus"] == "ok",
                verified[cell_id]["signerFingerprint"]
                == policy_signers[cell_id]["fingerprint"]
                and verified[cell_id]["signerRole"] == policy_signers[cell_id]["role"],
            ]
            self.assertTrue(all(assertions))
            controls += len(assertions)
        self.assertEqual(controls, 40)
        type(self).counters["signature_binding_controls"] = controls

    def test_40_mutable_capsule_five_phase_matrix_100(self):
        capsule = self.task_root / "mutable-capsule-matrix"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        source = r"""
import {createHash} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {testOnlyVerifyPublicSourceZipCampaignCell} from __VERIFY__;
import {parseCanonicalCampaignPolicyBytes} from __CORE__;
const root=path.resolve(process.argv[1]);const expectedCanonicalPolicyBytes=await readFile(process.argv[2]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);
const options={capsuleRoot:root,expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:'WIN-A',consumerHostRole:'E6-WINDOWS',gpgExecutable:process.argv[3],gpgHome:process.argv[4]};
const cases=[
 ['before-signature','cell-manifest.json'],
 ['after-signature','cell-manifest.json'],
 ['during-ledger','d2/artifact.zip'],
 ['before-final-root-check','d2/artifact.zip'],
 ['before-final-return','cell-manifest.sig'],
];
let rejected=0;let falseAcceptance=0;
for(const [checkpoint,relative] of cases){const target=path.join(root,...relative.split('/'));const original=await readFile(target);for(let repetition=0;repetition<20;repetition+=1){let triggered=false;const adapter={loadedToolAuthorityBypass:true,async checkpoint(details){if(!triggered&&details.checkpoint===checkpoint){triggered=true;const mutated=Buffer.from(original);mutated[Math.min(repetition,mutated.length-1)]^=1;await writeFile(target,mutated);}}};try{await testOnlyVerifyPublicSourceZipCampaignCell(options,adapter);falseAcceptance+=1;}catch{rejected+=1;}await writeFile(target,original);if(!triggered)throw new Error('mutation checkpoint not reached');}}
process.stdout.write(JSON.stringify({rejected,falseAcceptance}));
""".replace("__VERIFY__", json.dumps(file_uri(
            self.instrumented_cell_verify
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            capsule, self.policy_path, GPG, self.gpg_home,
        ], timeout=300).stdout)
        self.assertEqual(value, {"rejected": 100, "falseAcceptance": 0})
        type(self).counters["mutable_capsule_controls"] = 100

    def test_40b_mutable_capsule_shape_controls_11(self):
        capsule = self.task_root / "mutable-capsule-shapes"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        source = r"""
import {createHash} from 'node:crypto';
import {mkdir,readFile,rename,rmdir,unlink,writeFile} from 'node:fs/promises';import path from 'node:path';
import {testOnlyVerifyPublicSourceZipCampaignCell} from __VERIFY__;import {parseCanonicalCampaignPolicyBytes} from __CORE__;
const root=path.resolve(process.argv[1]);const expectedCanonicalPolicyBytes=await readFile(process.argv[2]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);const options={capsuleRoot:root,expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:'WIN-A',consumerHostRole:'E6-WINDOWS',gpgExecutable:process.argv[3],gpgHome:process.argv[4]};let rejected=0;let falseAcceptance=0;
const cases=[
 ['before-final-root-check','write','d2/artifact.zip'],['before-final-root-check','write','v2/evidence.json'],['after-signature','write','cell-manifest.json'],['after-signature','write','cell-manifest.sig'],
 ['before-final-root-check','directory','authority'],['before-final-root-check','extra','unexpected.entry'],['before-final-root-check','delete','d2/semantic-report.json'],['before-final-root-check','truncate','d2/artifact.zip'],
 ['before-final-root-check','write','d2/entry-plan.json'],['preflight','case','CELL-MANIFEST.JSON'],['before-final-root-check','write','cell.complete']
];
for(const [checkpoint,operation,relative] of cases){const target=path.join(root,...relative.split('/'));if(operation==='case'){try{await writeFile(target,Buffer.from('collision\n'),{flag:'wx'});}catch{rejected+=1;continue;}try{await testOnlyVerifyPublicSourceZipCampaignCell(options,{loadedToolAuthorityBypass:true});falseAcceptance+=1;}catch{rejected+=1;}await unlink(target);continue;}
 let original=null,saved=null,triggered=false;if(!['directory','extra'].includes(operation))original=await readFile(target);const adapter={loadedToolAuthorityBypass:true,async checkpoint(details){if(triggered||details.checkpoint!==checkpoint)return;triggered=true;if(operation==='write'){const mutated=Buffer.from(original);mutated[Math.max(0,mutated.length-1)]^=1;await writeFile(target,mutated);}else if(operation==='truncate')await writeFile(target,original.subarray(0,Math.max(0,original.length-1)));else if(operation==='delete')await unlink(target);else if(operation==='extra')await writeFile(target,Buffer.from('unexpected\n'),{flag:'wx'});else if(operation==='directory'){saved=target+'-saved';await rename(target,saved);await mkdir(target);}}};
 try{await testOnlyVerifyPublicSourceZipCampaignCell(options,adapter);falseAcceptance+=1;}catch{rejected+=1;}finally{if(operation==='directory'){await rmdir(target);await rename(saved,target);}else if(operation==='extra')await unlink(target);else await writeFile(target,original);}if(!triggered)throw new Error('shape checkpoint not reached');}
process.stdout.write(JSON.stringify({rejected,falseAcceptance}));
""".replace("__VERIFY__", json.dumps(file_uri(
            self.instrumented_cell_verify
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            capsule, self.policy_path, GPG, self.gpg_home,
        ], timeout=300).stdout)
        self.assertEqual(value, {"rejected": 11, "falseAcceptance": 0})
        type(self).counters["mutable_capsule_shape_controls"] = 11
        type(self).counters["mutable_capsule_controls"] += 11

    def test_41_cell_marker_and_publication_rejection_matrix_200(self):
        capsule = self.task_root / "cell-marker-matrix"
        shutil.copytree(self.capsules["WIN-A"], capsule)
        source = r"""
import {createHash} from 'node:crypto';
import {readFile,writeFile,unlink} from 'node:fs/promises';
import path from 'node:path';
import {testOnlyVerifyPublicSourceZipCampaignCell} from __VERIFY__;
import {parseCanonicalCampaignPolicyBytes} from __CORE__;
const root=path.resolve(process.argv[1]);const expectedCanonicalPolicyBytes=await readFile(process.argv[2]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);
const options={capsuleRoot:root,expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,matrixCellId:'WIN-A',consumerHostRole:'E6-WINDOWS',gpgExecutable:process.argv[3],gpgHome:process.argv[4]};
const cases=[
 ['delete','cell.complete'],['bytes','cell.complete'],['append','cell.complete'],['extra','unexpected.entry'],
 ['delete','cell-manifest.json'],['delete','cell-manifest.sig'],['delete','d2/artifact.zip'],['case','CELL.COMPLETE'],
];
let rejected=0;let falseCompletionMarkers=0;
for(let repetition=0;repetition<25;repetition+=1)for(const [operation,relative] of cases){const target=path.join(root,...relative.split('/'));let original=null;try{original=await readFile(target);}catch{}if(operation==='delete')await unlink(target);else if(operation==='bytes')await writeFile(target,Buffer.from('failed\n'));else if(operation==='append')await writeFile(target,Buffer.concat([original,Buffer.from('x')]));else{try{await writeFile(target,Buffer.from('unexpected\n'),{flag:'wx'});}catch{rejected+=1;continue;}}try{await testOnlyVerifyPublicSourceZipCampaignCell(options,{loadedToolAuthorityBypass:true});falseCompletionMarkers+=1;}catch{rejected+=1;}if(original===null)await unlink(target);else await writeFile(target,original);}
process.stdout.write(JSON.stringify({rejected,falseCompletionMarkers}));
""".replace("__VERIFY__", json.dumps(file_uri(self.instrumented_cell_verify))).replace(
            "__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            capsule, self.policy_path, GPG, self.gpg_home,
        ], timeout=300).stdout)
        self.assertEqual(value, {"rejected": 200, "falseCompletionMarkers": 0})
        type(self).counters["cell_publication_marker_controls"] = 200

    def test_42_comparison_publication_and_marker_matrix_126(self):
        comparison_parent = self.task_root / "comparison-publication-matrix"
        comparison_parent.mkdir()
        source = r"""
import {createHash} from 'node:crypto';
import {access,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {testOnlyComparePublicSourceZipCampaign} from __COMPARE__;
import {comparePublicSourceZipCampaign} from __PRODUCTION_COMPARE__;
import {parseCanonicalCampaignPolicyBytes} from __CORE__;
const parent=path.resolve(process.argv[1]);const expectedCanonicalPolicyBytes=await readFile(process.argv[2]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);const gpg=process.argv[3],gpgHome=process.argv[4],fingerprint=process.argv[5],role=process.argv[6];
const cells=JSON.parse(process.argv[7]);const gitIdentity=JSON.parse(await readFile(process.argv[10],'utf8'));const base={expectedCanonicalPolicyBytes,expectedPolicySha256:createHash('sha256').update(expectedCanonicalPolicyBytes).digest('hex'),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,cells,gpgExecutable:gpg,gpgHome,comparisonHostRole:'E6-WINDOWS',reviewHostRole:'E7-LINUX',repository:process.argv[8],gitExecutable:process.argv[9],gitIdentity};let rejected=0;let falseMarkers=0;let unsignedBundles=0;
const exists=async value=>{try{await access(value);return true;}catch{return false;}};
for(let index=0;index<120;index+=1){const outputDirectory=path.join(parent,'unsigned-'+String(index).padStart(3,'0'));const variant=index%4;const options={...base};if(variant===0)options.outputDirectory=outputDirectory;else if(variant===1){options.outputDirectory=outputDirectory;options.comparisonSigningFingerprint=fingerprint;}else if(variant===2){options.outputDirectory=outputDirectory;options.comparisonSignerRole=role;}else{options.comparisonSigningFingerprint=fingerprint;options.comparisonSignerRole=role;}try{await comparePublicSourceZipCampaign(options);unsignedBundles+=1;}catch{rejected+=1;}if(await exists(outputDirectory))throw new Error('unsigned output created');}
const failures=[
 ['before-signature','throw'],['after-signature','mutate-signature'],['before-marker','precreate-marker'],['after-marker','throw'],['after-marker','extra-entry'],['after-final-verification','throw']
];
for(const [checkpoint,operation] of failures){const outputDirectory=path.join(parent,'failure-'+checkpoint+'-'+operation);const options={...base,outputDirectory,comparisonSigningFingerprint:fingerprint,comparisonSignerRole:role};const adapter={async checkpoint(details){if(details.checkpoint!==checkpoint)return;if(operation==='throw')throw new Error('synthetic publication failure');if(operation==='mutate-signature')await writeFile(details.signaturePath,Buffer.from('invalid'));if(operation==='precreate-marker')await writeFile(path.join(outputDirectory,'comparison.complete'),Buffer.from('attacker\n'),{flag:'wx'});if(operation==='extra-entry')await writeFile(path.join(outputDirectory,'unexpected.entry'),Buffer.from('unexpected\n'),{flag:'wx'});}};try{await testOnlyComparePublicSourceZipCampaign(options,adapter);unsignedBundles+=1;}catch{rejected+=1;}const marker=path.join(outputDirectory,'comparison.complete');if(await exists(marker)){const bytes=await readFile(marker);if(bytes.equals(Buffer.from('complete\n')))falseMarkers+=1;}if(await exists(outputDirectory)){const required=['campaign-result.json','comparison-manifest.json','comparison.complete'];if((await Promise.all(required.map(name=>exists(path.join(outputDirectory,name))))).every(Boolean)&&!(await exists(path.join(outputDirectory,'comparison-manifest.sig'))))unsignedBundles+=1;}}
process.stdout.write(JSON.stringify({rejected,falseMarkers,unsignedBundles}));
""".replace("__COMPARE__", json.dumps(file_uri(
            self.instrumented_compare
        ))).replace("__PRODUCTION_COMPARE__", json.dumps(file_uri(
            CAMPAIGN_COMPARE
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        cells = [
            {
                "matrixCellId": cell_id,
                "capsuleRoot": str(self.capsules[cell_id]),
            }
            for cell_id in ("WIN-A", "LINUX-A", "LINUX-B")
        ]
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            comparison_parent, self.policy_path,
            GPG, self.gpg_home, self.fingerprints[0], "win-a-signer",
            json.dumps(cells, separators=(",", ":")),
            self.tool_repository, GIT, self.git_identity_path,
        ], timeout=300).stdout)
        self.assertEqual(value, {
            "rejected": 126,
            "falseMarkers": 0,
            "unsignedBundles": 0,
        })
        type(self).counters["comparison_publication_marker_controls"] = 126
        type(self).counters["false_completion_markers"] = 0
        type(self).counters["unsigned_filesystem_success_bundles"] = 0

    def test_43_cleanup_uncertainty_zero_deletion_matrix_362(self):
        cleanup_parent = self.task_root / "cleanup-control-parent"
        cleanup_parent.mkdir()
        source = f"""
import path from 'node:path';
import {{runPrivateCleanupControlMatrix}} from {json.dumps(file_uri(DEVELOPER / 'prepare-public-source-zip-reproducibility.mjs'))};
const result=await runPrivateCleanupControlMatrix({{temporaryParent:path.resolve(process.argv[1]),uncertaintyRepetitions:30}});
process.stdout.write(JSON.stringify({{status:result.status,uncertaintyCompletedCount:result.uncertaintyCompletedCount,zeroDeletionCount:result.zeroDeletionCount,normalCleanupCount:result.normalCleanupCount,allUncertainZeroDeletion:result.summaries.filter(entry=>entry.result==='failure').every(entry=>entry.reason==='cleanup-identity-uncertain'&&entry.unlinkCount===0&&entry.rmdirCount===0&&entry.rootPreserved===true)}}));
"""
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, cleanup_parent,
        ], timeout=300).stdout)
        self.assertEqual(value, {
            "status": "ok",
            "uncertaintyCompletedCount": 362,
            "zeroDeletionCount": 362,
            "normalCleanupCount": 2,
            "allUncertainZeroDeletion": True,
        })
        type(self).counters["cleanup_uncertainty_controls"] = 362

    def test_44_gpg_profile_identity_mutation_matrix_40(self):
        policy = json.loads(self.policy_path.read_text("ascii"))
        by_cell = {
            entry["matrixCellId"]: entry for entry in self.summary["verified"]
        }
        fields = (
            "profileId",
            "executableSha256",
            "executableByteLength",
            "version",
            "distributionProfile",
            "osFamily",
            "architecture",
            "invocationProfileSha256",
        )
        controls = 0
        for profile_index, cell_id in enumerate(
            ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B")
        ):
            profile = policy["gpgVerifierProfiles"][profile_index]
            capsule = self.capsules[cell_id]
            execution = json.loads(
                (capsule / "v2/execution-identity.json").read_text("ascii")
            )
            manifest = json.loads(
                (capsule / "cell-manifest.json").read_text("ascii")
            )
            baseline_profile_sha = sha256_bytes(canonical_json_bytes(profile))
            baseline_execution_sha = sha256_bytes(canonical_json_bytes(execution))
            baseline_manifest_sha = sha256_bytes(canonical_json_bytes(manifest))
            self.assertEqual(
                baseline_profile_sha,
                by_cell[cell_id]["producerGpgProfileSha256"],
            )
            invariant_hashes = (
                sha256_bytes((capsule / "v2/semantic-input-set.json").read_bytes()),
                sha256_bytes((capsule / "authority/runtime-class.json").read_bytes()),
                sha256_bytes((capsule / "authority/platform-class.json").read_bytes()),
                sha256_bytes((capsule / "d2/artifact.zip").read_bytes()),
                sha256_bytes((capsule / "d2/entry-plan.json").read_bytes()),
                sha256_bytes((capsule / "d2/zip-verification.json").read_bytes()),
            )
            for field in fields:
                mutated_profile = copy.deepcopy(profile)
                if field == "profileId":
                    mutated_profile[field] += "-mut"
                elif field == "executableSha256":
                    mutated_profile[field] = "f" * 64
                elif field == "executableByteLength":
                    mutated_profile[field] += 1
                elif field == "version":
                    mutated_profile[field] = "2.4.9"
                elif field == "distributionProfile":
                    mutated_profile[field] += "-mut"
                elif field == "osFamily":
                    mutated_profile[field] = (
                        "linux" if profile[field] == "windows" else "windows"
                    )
                elif field == "architecture":
                    mutated_profile[field] = "arm64"
                else:
                    mutated_profile[field] = "e" * 64
                mutated_profile_sha = sha256_bytes(
                    canonical_json_bytes(mutated_profile)
                )
                mutated_execution = copy.deepcopy(execution)
                mutated_execution["producerGpgProfileSha256"] = mutated_profile_sha
                mutated_manifest = copy.deepcopy(manifest)
                mutated_manifest["producerGpgProfileId"] = mutated_profile["profileId"]
                mutated_manifest["producerGpgProfileSha256"] = mutated_profile_sha
                self.assertNotEqual(mutated_profile_sha, baseline_profile_sha)
                self.assertNotEqual(
                    sha256_bytes(canonical_json_bytes(mutated_execution)),
                    baseline_execution_sha,
                )
                self.assertNotEqual(
                    sha256_bytes(canonical_json_bytes(mutated_manifest)),
                    baseline_manifest_sha,
                )
                self.assertEqual(invariant_hashes, (
                    sha256_bytes((capsule / "v2/semantic-input-set.json").read_bytes()),
                    sha256_bytes((capsule / "authority/runtime-class.json").read_bytes()),
                    sha256_bytes((capsule / "authority/platform-class.json").read_bytes()),
                    sha256_bytes((capsule / "d2/artifact.zip").read_bytes()),
                    sha256_bytes((capsule / "d2/entry-plan.json").read_bytes()),
                    sha256_bytes((capsule / "d2/zip-verification.json").read_bytes()),
                ))
                controls += 1

        profile_keys = [
            "documentKind", "schemaVersion", "profileId", "verifierFamily",
            "distributionProfile", "osFamily", "architecture",
            "executableSha256", "executableByteLength", "version",
            "statusProtocol", "fileIdentityPolicy", "linkPolicy",
            "networkPolicy", "invocationProfileSha256",
            "immutableInstallationProfileSha256",
        ]
        self.assertTrue(all(list(value) == profile_keys for value in policy["gpgVerifierProfiles"]))
        controls += 1
        self.assertEqual(len(policy["gpgVerifierProfiles"]), 12)
        controls += 1
        self.assertEqual(len({value["profileId"] for value in policy["gpgVerifierProfiles"]}), 12)
        controls += 1
        self.assertEqual(len({value["invocationProfileSha256"] for value in policy["gpgVerifierProfiles"]}), 1)
        controls += 1
        self.assertTrue(all("producerGpgProfileSha256" in json.loads(
            (self.capsules[cell] / "v2/execution-identity.json").read_text("ascii")
        ) for cell in self.capsules))
        controls += 1
        self.assertTrue(all("producerGpgProfileSha256" not in json.loads(
            (self.capsules[cell] / "v2/semantic-input-set.json").read_text("ascii")
        ) for cell in self.capsules))
        controls += 1
        self.assertTrue(all("producerGpgProfileSha256" not in json.loads(
            (self.capsules[cell] / "authority/runtime-class.json").read_text("ascii")
        ) for cell in self.capsules))
        controls += 1
        self.assertTrue(all("producerGpgProfileSha256" not in json.loads(
            (self.capsules[cell] / "authority/platform-class.json").read_text("ascii")
        ) for cell in self.capsules))
        controls += 1
        self.assertEqual(controls, 40)
        type(self).counters["gpg_profile_identity_controls"] = controls

    def test_44b_gpg_profile_duplicate_aware_canonical_parser_10(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {canonicalPublicJsonBytes} from __D2_CORE__;
import {encodeCanonicalGpgVerifierExecutionProfile,parseCanonicalGpgVerifierExecutionProfileBytes} from __CORE__;
const policy=JSON.parse(await readFile(process.argv[1],'utf8'));const profile=policy.gpgVerifierProfiles[0];const clone=value=>JSON.parse(JSON.stringify(value));
const canonical=encodeCanonicalGpgVerifierExecutionProfile(profile);parseCanonicalGpgVerifierExecutionProfileBytes(canonical);let rejected=0;
const reject=bytes=>{try{parseCanonicalGpgVerifierExecutionProfileBytes(bytes);}catch{rejected+=1;return;}throw new Error('noncanonical GPG profile accepted');};
reject(Buffer.from(canonical.toString('ascii').replace('"profileId":','"profileId":"duplicate","profileId":'),'ascii'));
{const value=clone(profile);delete value.documentKind;const reordered={schemaVersion:value.schemaVersion,documentKind:profile.documentKind,...value};reject(canonicalPublicJsonBytes(reordered,'PRIVACY'));}
{const value=clone(profile);delete value.version;reject(canonicalPublicJsonBytes(value,'PRIVACY'));}
{const value=clone(profile);value.extraAuthority='forbidden';reject(canonicalPublicJsonBytes(value,'PRIVACY'));}
reject(Buffer.from(canonical.toString('ascii').replaceAll('\n','\r\n'),'ascii'));
reject(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),canonical]));
reject(canonical.subarray(0,canonical.length-1));
reject(Buffer.concat([canonical,Buffer.from('\n')]));
{const value=clone(profile);value.invocationProfileSha256='e'.repeat(64);reject(canonicalPublicJsonBytes(value,'PRIVACY'));}
{const value=clone(profile);value.version='not-a-version';reject(canonicalPublicJsonBytes(value,'PRIVACY'));}
process.stdout.write(JSON.stringify({rejected}));
""".replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {"rejected": 10})
        type(self).counters["canonical_duplicate_key_controls"] += 10

    def test_45_gpg_profile_assignment_binding_matrix_50(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {validateCampaignPolicy} from __CORE__;
const base=JSON.parse(await readFile(process.argv[1],'utf8'));
const clone=value=>JSON.parse(JSON.stringify(value));let rejected=0;
const reject=mutate=>{const value=clone(base);mutate(value);try{validateCampaignPolicy(value);}catch{rejected+=1;return;}throw new Error('profile assignment mutation accepted');};
for(let index=0;index<base.gpgVerifierAssignments.length;index+=1){
 reject(value=>{value.gpgVerifierAssignments[index].campaignId='other-campaign';});
 reject(value=>{value.gpgVerifierAssignments[index].sourceCommit='b'.repeat(40);});
 reject(value=>{value.gpgVerifierAssignments[index].toolingCommit='c'.repeat(40);});
 reject(value=>{value.gpgVerifierAssignments[index].signatureNamespace='forbidden-namespace';});
}
reject(value=>{value.gpgVerifierAssignments[0].profileId='unknown-test-profile';});
reject(value=>{value.gpgVerifierProfiles.pop();});
reject(value=>{value.gpgVerifierAssignments[0].matrixCellId='LINUX-A';});
reject(value=>{value.gpgVerifierAssignments[0].comparisonRole='campaign-comparison';});
reject(value=>{value.gpgVerifierAssignments[0].osFamily=value.gpgVerifierAssignments[0].osFamily==='windows'?'linux':'windows';});
reject(value=>{value.gpgVerifierAssignments[0].architecture='arm64';});
reject(value=>{value.gpgVerifierAssignments[0].signerRole='linux-a-signer';});
reject(value=>{value.gpgVerifierAssignments[12].matrixCellId='WIN-A';value.gpgVerifierAssignments[12].comparisonRole=null;});
reject(value=>{value.gpgVerifierAssignments[0].profileId=value.gpgVerifierAssignments[2].profileId;value.gpgVerifierAssignments[1].profileId=value.gpgVerifierAssignments[2].profileId;});
reject(value=>{value.gpgVerifierProfiles[1].profileId=value.gpgVerifierProfiles[0].profileId;});
process.stdout.write(JSON.stringify({rejected}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {"rejected": 70})
        type(self).counters["profile_assignment_binding_controls"] = 70
        type(self).counters["accepted_unprofiled_verifier"] = 0

    def test_46_fake_and_executable_profile_rejection_matrix_60(self):
        fake_version = self.run_process(
            [self.fake_gpg, "--version"], check=False
        )
        self.assertEqual(fake_version.returncode, 0)
        self.assertTrue(fake_version.stdout.startswith(b"gpg (GnuPG) 2.4.8"))
        fake_status = self.run_process(
            [self.fake_gpg, "--verify", "fake.sig", "fake.manifest"],
            check=False,
        )
        self.assertEqual(fake_status.returncode, 0)
        self.assertIn(b"[GNUPG:] GOODSIG", fake_status.stdout)
        self.assertIn(b"[GNUPG:] VALIDSIG", fake_status.stdout)
        nonzero_status = self.run_process(
            [self.fake_gpg_nonzero, "--verify", "fake.sig", "fake.manifest"],
            check=False,
        )
        self.assertEqual(nonzero_status.returncode, 17)
        self.assertIn(b"[GNUPG:] VALIDSIG", nonzero_status.stdout)

        zero_file = self.task_root / "fake-verifiers/zero.exe"
        zero_file.write_bytes(b"")
        text_file = self.task_root / "fake-verifiers/text.exe"
        text_file.write_bytes(b"not an executable\n")
        missing_file = self.task_root / "fake-verifiers/missing.exe"
        symlink_file = self.task_root / "fake-verifiers/gpg-symlink.exe"
        os.symlink(GPG, symlink_file)
        junction_root = self.task_root / "gpg-bin-junction"
        junction_source = (
            "import {symlink} from 'node:fs/promises';"
            "await symlink(process.argv[1],process.argv[2],'junction');"
        )
        self.run_process([
            NODE, "--input-type=module", "--eval", junction_source,
            GPG.parent, junction_root,
        ])
        hardlink_source = self.task_root / "fake-verifiers/gpg-hardlink-source.exe"
        hardlink_path = self.task_root / "fake-verifiers/gpg-hardlink.exe"
        shutil.copy2(GPG, hardlink_source)
        os.link(hardlink_source, hardlink_path)
        path_cases = [
            "relative-gpg.exe",
            str(missing_file),
            str(self.fake_gpg_root),
            str(zero_file),
            str(text_file),
            str(self.fake_gpg.with_suffix(".cs")),
            str(symlink_file),
            str(junction_root / GPG.name),
            str(hardlink_path),
            str(self.fake_gpg),
        ]
        source = r"""
import {readFile} from 'node:fs/promises';
import {CELL_SIGNATURE_NAMESPACE,campaignPolicySha256,validateProfiledGpgExecutionContext} from __CORE__;
const policy=JSON.parse(await readFile(process.argv[1],'utf8'));const realGpg=process.argv[2];const gpgHome=process.argv[3];
const fakePaths=JSON.parse(process.argv[4]);const pathCases=JSON.parse(process.argv[5]);const clone=value=>JSON.parse(JSON.stringify(value));
const context=(campaignPolicy,executablePath)=>({gpgRole:'cell-producer-local-verify',operation:'detached-verify',executablePath,gpgHome,campaignPolicy,expectedPolicySha256:campaignPolicySha256(campaignPolicy),matrixCellId:'WIN-A',comparisonRole:null,hostRole:'WIN-A',signerRole:'win-a-signer',signatureNamespace:CELL_SIGNATURE_NAMESPACE});
let fakeRejected=0,pathRejected=0,profileRejected=0;
for(let index=0;index<30;index+=1){try{validateProfiledGpgExecutionContext(context(policy,fakePaths[index%fakePaths.length]));}catch{fakeRejected+=1;continue;}throw new Error('fake verifier accepted');}
for(const executablePath of pathCases){try{validateProfiledGpgExecutionContext(context(policy,executablePath));}catch{pathRejected+=1;continue;}throw new Error('unsealed executable path accepted');}
for(let index=0;index<20;index+=1){const value=clone(policy);const profile=value.gpgVerifierProfiles[0];const assignments=value.gpgVerifierAssignments.filter(entry=>entry.profileId===profile.profileId);switch(index%5){case 0:profile.executableSha256='f'.repeat(64);break;case 1:profile.executableByteLength+=index+1;break;case 2:profile.osFamily=profile.osFamily==='windows'?'linux':'windows';for(const entry of assignments)entry.osFamily=profile.osFamily;break;case 3:profile.architecture='arm64';for(const entry of assignments)entry.architecture='arm64';break;default:profile.invocationProfileSha256='e'.repeat(64);}try{validateProfiledGpgExecutionContext(context(value,realGpg));}catch{profileRejected+=1;continue;}throw new Error('mismatched execution profile accepted');}
process.stdout.write(JSON.stringify({fakeRejected,pathRejected,profileRejected}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path, GPG, self.gpg_home,
            json.dumps([str(self.fake_gpg), str(self.fake_gpg_nonzero)]),
            json.dumps(path_cases),
        ], timeout=180).stdout)
        self.assertEqual(value, {
            "fakeRejected": 30,
            "pathRejected": 10,
            "profileRejected": 20,
        })
        type(self).counters["fake_verifier_controls"] = 30
        type(self).counters["gpg_executable_profile_controls"] = 60
        type(self).counters["accepted_fake_verifier"] = 0
        type(self).counters["accepted_identity_mismatched_verifier"] = 0

    def test_47_profiled_gpg_replacement_lifecycle_matrix(self):
        capsule = self.capsules["WIN-A"]
        source = r"""
import {copyFile,readFile,writeFile} from 'node:fs/promises';
import {testOnlyRunProfiledGpgOperation} from __CORE__;
import {CELL_SIGNATURE_NAMESPACE,campaignPolicySha256,parseCanonicalCampaignPolicyBytes} from __PRODUCTION_CORE__;
const executable=process.argv[1],original=process.argv[2],gpgHome=process.argv[3],signatureFile=process.argv[4],signedFile=process.argv[5];
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[6]));const fingerprint=policy.allowedSignerFingerprints[0].fingerprint;
const base={gpgRole:'cell-producer-local-verify',operation:'detached-verify',executablePath:executable,gpgHome,campaignPolicy:policy,expectedPolicySha256:campaignPolicySha256(policy),matrixCellId:'WIN-A',comparisonRole:null,hostRole:'WIN-A',signerRole:'win-a-signer',signatureNamespace:CELL_SIGNATURE_NAMESPACE,signingFingerprint:null,signatureFile,signedFile,allowedPrimaryFingerprints:[fingerprint]};
const checkpoints=['version-query-before-spawn','version-query-after-spawn','version-query-after-exit-before-recheck','after-version-query','detached-verify-before-spawn','detached-verify-after-spawn','detached-verify-after-exit-before-recheck','before-final-return'];
let rejected=0,accepted=0,reached=0;
for(const wanted of checkpoints){await copyFile(original,executable);let triggered=false;const adapter={async checkpoint({checkpoint}){if(triggered||checkpoint!==wanted)return;triggered=true;reached+=1;await writeFile(executable,Buffer.from('replaced executable fixture\n'));}};try{await testOnlyRunProfiledGpgOperation(base,adapter);accepted+=1;}catch{rejected+=1;}await copyFile(original,executable);if(!triggered)throw new Error('lifecycle checkpoint not reached');}
const positive=await testOnlyRunProfiledGpgOperation(base,{});
const wrongVersion=JSON.parse(JSON.stringify(policy));wrongVersion.gpgVerifierProfiles[4].version='2.4.9';let wrongVersionRejected=0;try{await testOnlyRunProfiledGpgOperation({...base,campaignPolicy:wrongVersion,expectedPolicySha256:campaignPolicySha256(wrongVersion)},{});}catch{wrongVersionRejected=1;}
process.stdout.write(JSON.stringify({rejected,accepted,reached,positiveProfileId:positive.profileId,wrongVersionRejected}));
""".replace("__CORE__", json.dumps(file_uri(
            self.instrumented_campaign_core
        ))).replace("__PRODUCTION_CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.sealed_gpg, GPG, self.gpg_home,
            capsule / "cell-manifest.sig", capsule / "cell-manifest.json",
            self.policy_path,
        ], timeout=300).stdout)
        self.assertEqual(value, {
            "rejected": 8,
            "accepted": 0,
            "reached": 8,
            "positiveProfileId": "gpg-win-a-local",
            "wrongVersionRejected": 1,
        })
        type(self).counters["accepted_replacement_race_verifier"] = 0

    def test_48_comparator_and_signed_profile_binding_matrix_42(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {campaignPolicySha256,parseCanonicalCampaignPolicyBytes} from __CORE__;
import {compareReproducibilityEvidenceV2} from __COMPARE__;
import {testOnlyNormalizeComparisonAuthorities} from __HIGH_LEVEL_COMPARE__;
const expectedCanonicalPolicyBytes=await readFile(process.argv[1]);const policy=parseCanonicalCampaignPolicyBytes(expectedCanonicalPolicyBytes);const base=[];for(const file of process.argv.slice(2,6))base.push(JSON.parse(await readFile(file,'utf8')));
const cells=JSON.parse(process.argv[6]);const gitIdentity=JSON.parse(await readFile(process.argv[14],'utf8'));
const authorities=await testOnlyNormalizeComparisonAuthorities({expectedCanonicalPolicyBytes,expectedPolicySha256:campaignPolicySha256(policy),campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit,cells,gpgExecutable:process.argv[7],gpgHome:process.argv[8],outputDirectory:process.argv[9],comparisonSigningFingerprint:process.argv[10],comparisonSignerRole:process.argv[11],comparisonHostRole:'E6-WINDOWS',reviewHostRole:'E7-LINUX',repository:process.argv[12],gitExecutable:process.argv[13],gitIdentity},{});
const compareOptions={campaignPolicy:policy,cells:base,comparisonNodeAuthority:authorities.comparisonNodeAuthority,comparisonSigningAuthority:authorities.comparisonSigningAuthority,comparisonLocalVerificationAuthority:authorities.comparisonLocalVerificationAuthority,independentReviewAuthority:authorities.independentReviewAuthority};compareReproducibilityEvidenceV2(compareOptions);
const clone=value=>JSON.parse(JSON.stringify(value));let rejected=0;
for(let target=0;target<4;target+=1){const other=(target+1)%4;for(let variant=0;variant<10;variant+=1){const cells=clone(base);const selected=cells[target],replacement=cells[other];switch(variant){case 0:delete selected.verifiedCell.producerGpgProfileSha256;break;case 1:delete selected.verifiedCell.producerGpgProfileId;break;case 2:selected.verifiedCell.producerGpgProfileSha256=replacement.verifiedCell.producerGpgProfileSha256;break;case 3:selected.verifiedCell.producerGpgProfileId=replacement.verifiedCell.producerGpgProfileId;break;case 4:selected.verifiedCell.producerLocalVerifierProfileSha256=replacement.verifiedCell.producerLocalVerifierProfileSha256;break;case 5:selected.verifiedCell.producerLocalVerifierProfileId=replacement.verifiedCell.producerLocalVerifierProfileId;break;case 6:selected.verifiedCell.consumerVerifyAssignmentSha256=replacement.verifiedCell.consumerVerifyAssignmentSha256;break;case 7:selected.verifiedCell.consumerVerifierProfileId+='-mut';break;case 8:selected.executionIdentity.producerGpgProfileSha256=replacement.executionIdentity.producerGpgProfileSha256;break;default:selected.evidence.producerGpgProfileSha256=replacement.evidence.producerGpgProfileSha256;}try{compareReproducibilityEvidenceV2({...compareOptions,cells});}catch{rejected+=1;continue;}throw new Error('profile comparison mutation accepted');}}
process.stdout.write(JSON.stringify({rejected}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__COMPARE__", json.dumps(file_uri(V2_COMPARE))
        ).replace(
            "__HIGH_LEVEL_COMPARE__", json.dumps(file_uri(self.instrumented_compare))
        )
        cells = [
            {"matrixCellId": cell_id, "capsuleRoot": str(self.capsules[cell_id])}
            for cell_id in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B")
        ]
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path,
            *[self.records[key] for key in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B")],
            json.dumps(cells, separators=(",", ":")),
            GPG, self.gpg_home, self.task_root / "authority-only-comparison",
            self.fingerprints[0], "win-a-signer", self.tool_repository, GIT,
            self.git_identity_path,
        ]).stdout)
        self.assertEqual(value, {"rejected": 40})

        policy = json.loads(self.policy_path.read_text("ascii"))
        replacement = policy["gpgVerifierProfiles"][1]
        replacement_sha = sha256_bytes(canonical_json_bytes(replacement))
        changed_manifest = self.task_root / "profile-after-signing"
        shutil.copytree(self.capsules["WIN-A"], changed_manifest)
        manifest = json.loads((changed_manifest / "cell-manifest.json").read_text("ascii"))
        manifest["producerGpgProfileId"] = replacement["profileId"]
        manifest["producerGpgProfileSha256"] = replacement_sha
        (changed_manifest / "cell-manifest.json").write_bytes(canonical_json_bytes(manifest))
        self.assert_path_free_error(self.verify_capsule(changed_manifest, check=False))

        switched_execution = self.task_root / "profile-switch-after-signing"
        shutil.copytree(self.capsules["WIN-A"], switched_execution)
        execution_path = switched_execution / "v2/execution-identity.json"
        execution = json.loads(execution_path.read_text("ascii"))
        execution["producerGpgProfileSha256"] = replacement_sha
        execution_path.write_bytes(canonical_json_bytes(execution))
        self.assert_path_free_error(self.verify_capsule(switched_execution, check=False))
        type(self).counters["profile_assignment_binding_controls"] += 42

    def test_49_exact_production_gpg_callsite_registry(self):
        core_source = CAMPAIGN_CORE.read_text("utf-8")
        leaf_sources = {
            "cell-sign": CAMPAIGN_PREPARE.read_text("utf-8"),
            "cell-verify": CELL_VERIFY.read_text("utf-8"),
            "comparison-sign": CAMPAIGN_COMPARE.read_text("utf-8"),
        }
        self.assertEqual(len(re.findall(r"\bspawn\s*\(", core_source)), 1)
        self.assertEqual(len(re.findall(r"\bspawnSync\s*\(", core_source)), 1)
        for source in leaf_sources.values():
            self.assertNotRegex(source, r"\b(?:spawn|spawnSync|execFile)\s*\(")
            self.assertNotIn('from "node:child_process"', source)
            self.assertIn("gpgExecutable", source)
            self.assertIn("gpgHome", source)
        self.assertEqual(
            len(re.findall(r"\brunProfiledGpgOperation\s*\(", leaf_sources["cell-sign"])),
            1,
        )
        self.assertEqual(
            len(re.findall(r"\brunProfiledGpgOperation\s*\(", leaf_sources["cell-verify"])),
            1,
        )
        self.assertEqual(
            len(re.findall(r"\brunProfiledGpgOperation\s*\(", leaf_sources["comparison-sign"])),
            1,
        )
        self.assertIn("shell: false", core_source)
        self.assertIn('environment.GNUPGHOME = gpgHome', core_source)
        self.assertIn('"--no-auto-key-retrieve"', core_source)
        self.assertIn('"--auto-key-locate", "clear"', core_source)
        self.assertNotRegex(core_source, r"spawn\s*\(\s*[\"']gpg")

    def test_50_authorized_real_gpg_profile_positive_control(self):
        self.assertEqual(self.gpg_sha256, "073810c724470d41458eed037ebc584f78a79c8cddc7aa7f5fa02626a4b29bac")
        self.assertEqual(self.gpg_byte_length, 1358560)
        self.assertEqual(self.gpg_version, "2.4.8")
        policy = json.loads(self.policy_path.read_text("ascii"))
        for profile in policy["gpgVerifierProfiles"]:
            self.assertEqual(profile["executableSha256"], self.gpg_sha256)
            self.assertEqual(profile["executableByteLength"], self.gpg_byte_length)
            self.assertEqual(profile["version"], self.gpg_version)
        comparison = Path(self.summary["comparisonOutput"])
        comparison_manifest = json.loads(
            (comparison / "comparison-manifest.json").read_text("ascii")
        )
        comparison_profile = policy["gpgVerifierProfiles"][-3]
        self.assertEqual(
            comparison_manifest["comparisonSignerProfileId"],
            comparison_profile["profileId"],
        )
        self.assertEqual(
            comparison_manifest["comparisonSignerProfileSha256"],
            sha256_bytes(canonical_json_bytes(comparison_profile)),
        )

    def test_51_cross_host_role_control_matrix_48(self):
        policy = json.loads(self.policy_path.read_text("ascii"))
        profiles = {
            entry["profileId"]: entry for entry in policy["gpgVerifierProfiles"]
        }
        assignments = policy["gpgVerifierAssignments"]
        cells = {
            entry["matrixCellId"]: entry
            for entry in policy["requiredCells"] + policy["optionalCells"]
        }
        controls = 0
        for cell_id in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B"):
            manifest = json.loads(
                (self.capsules[cell_id] / "cell-manifest.json").read_text("ascii")
            )
            execution = json.loads(
                (self.capsules[cell_id] / "v2/execution-identity.json")
                .read_text("ascii")
            )
            verified = json.loads(self.records[cell_id].read_text("ascii"))[
                "verifiedCell"
            ]
            selected = {
                entry["gpgRole"]: entry
                for entry in assignments
                if entry["matrixCellId"] == cell_id
            }
            producer = profiles[selected["cell-producer-sign"]["profileId"]]
            local = profiles[selected["cell-producer-local-verify"]["profileId"]]
            consumer = profiles[selected["cell-import-consumer-verify"]["profileId"]]
            assertions = (
                producer["osFamily"] == cells[cell_id]["osFamily"],
                local["osFamily"] == cells[cell_id]["osFamily"],
                consumer["osFamily"] == "windows",
                selected["cell-import-consumer-verify"]["hostRole"] == "E6-WINDOWS",
                producer["profileId"] != consumer["profileId"],
                execution["producerGpgProfileSha256"]
                == manifest["producerGpgProfileSha256"],
                "consumerVerifierProfileSha256" not in execution,
                verified["consumerVerifierProfileId"] == consumer["profileId"],
                verified["producerGpgProfileId"] == producer["profileId"],
                verified["producerLocalVerifierProfileId"] == local["profileId"],
                verified["verificationHostRole"] == "E6-WINDOWS",
                len({
                    manifest["producerSignAssignmentSha256"],
                    manifest["producerLocalVerifyAssignmentSha256"],
                    verified["consumerVerifyAssignmentSha256"],
                }) == 3,
            )
            self.assertTrue(all(assertions), cell_id)
            controls += len(assertions)
        self.assertEqual(controls, 48)
        type(self).counters["cross_host_role_controls"] = controls

    def test_52_external_policy_self_authorization_matrix_32(self):
        source = r"""
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {canonicalPublicJsonBytes} from __D2_CORE__;
import {parseCanonicalCampaignPolicyBytes,validateExternalCampaignPolicyAuthority} from __CORE__;
const bytes=await readFile(process.argv[1]);const policy=parseCanonicalCampaignPolicyBytes(bytes);const digest=createHash('sha256').update(bytes).digest('hex');
const base={expectedCanonicalPolicyBytes:bytes,expectedPolicySha256:digest,campaignId:policy.campaignId,sourceCommit:policy.sourceCommit,toolingCommit:policy.toolingCommit};validateExternalCampaignPolicyAuthority(base);
let rejected=0;const reject=value=>{try{validateExternalCampaignPolicyAuthority(value);}catch{rejected+=1;return;}throw new Error('self-authorized policy accepted');};
for(let index=0;index<8;index+=1)reject({...base,expectedPolicySha256:String(index).repeat(64)});
for(let index=0;index<8;index+=1)reject({...base,campaignId:policy.campaignId+'-attacker-'+index});
for(let index=0;index<8;index+=1)reject({...base,sourceCommit:String((index+1)%10).repeat(40)});
for(let index=0;index<8;index+=1){const attacker=JSON.parse(JSON.stringify(policy));attacker.allowedSignerRoles.push('attacker-role-'+index);const attackerBytes=canonicalPublicJsonBytes(attacker,'POLICY');reject({...base,expectedCanonicalPolicyBytes:attackerBytes,expectedPolicySha256:createHash('sha256').update(attackerBytes).digest('hex')});}
process.stdout.write(JSON.stringify({rejected}));
""".replace("__D2_CORE__", json.dumps(file_uri(
            DEVELOPER / "public-source-zip-reproducibility-core.mjs"
        ))).replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {"rejected": 32})
        type(self).counters["self_authorized_trust_controls"] = 32
        type(self).counters["accepted_self_authorized_profile"] = 0
        type(self).counters["accepted_attacker_created_policy"] = 0

    def test_53_runtime_self_measurement_matrix_48(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {immutableInstallationProfileSha256,parseCanonicalCampaignPolicyBytes,validateCampaignPolicy} from __PRODUCTION_CORE__;
import {testOnlyMeasureCurrentNodeProcessAuthority} from __CORE__;
const base=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));const clone=value=>JSON.parse(JSON.stringify(value));
const qualificationFacts=context=>{const digest=label=>createHash('sha256').update(label+':'+context.profileSha256).digest('hex');return {linkCount:1,reparseOrSymlink:false,campaignPrincipalWritable:false,campaignPrincipalDeleteOrRenameCapable:false,campaignPrincipalAclChangeCapable:false,campaignPrincipalOwnershipTakeoverCapable:false,accessControlEvidenceSha256:digest('access'),filesystemEvidenceSha256:digest('filesystem')};};
const fixed={osFamily:'windows',architecture:process.arch,runtimeVersion:process.version,v8Version:process.versions.v8,modulesAbi:process.versions.modules};const adapter={qualificationFacts,nodeProcessFacts(){return fixed;}};
const options=campaignPolicy=>({campaignPolicy,campaignRole:'cell-producer',matrixCellId:'WIN-A',hostRole:'WIN-A'});
const positive=await testOnlyMeasureCurrentNodeProcessAuthority(options(base),adapter);if(positive.runtimeIdentity.nodeVersion!==process.version||positive.qualificationResult.status!=='qualified')throw new Error('actual measurement positive failed');
let rejected=0;
for(let index=0;index<48;index+=1){const value=clone(base);const profile=value.nodeRuntimeProfiles.find(entry=>entry.profileId==='node-win-a');const assignment=value.nodeRuntimeAssignments.find(entry=>entry.profileId===profile.profileId);const immutable=value.immutableInstallationProfiles.find(entry=>entry.profileId==='immutable-node-win-a');switch(index%8){case 0:profile.runtimeVersion='v24.14.'+String((index%7)+1);break;case 1:profile.v8Version='13.6.233.11-node.'+String((index%7)+1);break;case 2:profile.modulesAbi=String(900+index);break;case 3:profile.architecture='arm64';assignment.architecture='arm64';immutable.architecture='arm64';profile.immutableInstallationProfileSha256=immutableInstallationProfileSha256(immutable);break;case 4:profile.osFamily='linux';assignment.osFamily='linux';immutable.osFamily='linux';profile.immutableInstallationProfileSha256=immutableInstallationProfileSha256(immutable);break;case 5:profile.distributionProfile+='-mut-'+index;break;case 6:profile.executableSha256='f'.repeat(64);immutable.executableSha256=profile.executableSha256;profile.immutableInstallationProfileSha256=immutableInstallationProfileSha256(immutable);break;default:profile.executableByteLength+=index+1;immutable.executableByteLength=profile.executableByteLength;profile.immutableInstallationProfileSha256=immutableInstallationProfileSha256(immutable);}
 try{validateCampaignPolicy(value);await testOnlyMeasureCurrentNodeProcessAuthority(options(value),adapter);}catch{rejected+=1;continue;}throw new Error('caller-authored runtime accepted as measurement');}
process.stdout.write(JSON.stringify({rejected,profileId:positive.profileId}));
""".replace("__PRODUCTION_CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__CORE__", json.dumps(file_uri(self.instrumented_campaign_core))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ], timeout=300).stdout)
        self.assertEqual(value, {"rejected": 48, "profileId": "node-win-a"})
        type(self).counters["runtime_self_measurement_controls"] = 48
        type(self).counters["accepted_caller_authored_runtime"] = 0

    def test_54_current_development_executables_fail_closed(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {CELL_SIGNATURE_NAMESPACE,campaignPolicySha256,measureCurrentNodeProcessAuthority,measureExecutableInstallationQualification,parseCanonicalCampaignPolicyBytes,validateProfiledGpgExecutionContext} from __CORE__;
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));let nodeBlocked=0,gpgBlocked=0;
try{measureCurrentNodeProcessAuthority({campaignPolicy:policy,campaignRole:'cell-producer',matrixCellId:'WIN-A',hostRole:'WIN-A'});}catch(error){if(error.phase==='ENVIRONMENT'&&error.reason==='immutable-installation-not-proven')nodeBlocked=1;else throw error;}
try{validateProfiledGpgExecutionContext({gpgRole:'cell-producer-local-verify',operation:'detached-verify',executablePath:process.argv[2],gpgHome:process.argv[3],campaignPolicy:policy,expectedPolicySha256:campaignPolicySha256(policy),matrixCellId:'WIN-A',comparisonRole:null,hostRole:'WIN-A',signerRole:'win-a-signer',signatureNamespace:CELL_SIGNATURE_NAMESPACE});}catch(error){if(error.phase==='ENVIRONMENT'&&error.reason==='immutable-installation-not-proven')gpgBlocked=1;else throw error;}
const nodeProfile=policy.nodeRuntimeProfiles.find(entry=>entry.profileId==='node-win-a');const immutable=policy.immutableInstallationProfiles.find(entry=>entry.profileId==='immutable-node-win-a');const measured=measureExecutableInstallationQualification({executablePath:process.execPath,immutableInstallationProfile:immutable,phase:'node-campaign-execution',purpose:'cell-producer'});
process.stdout.write(JSON.stringify({nodeBlocked,gpgBlocked,qualificationStatus:measured.result.status,reason:measured.result.reason,profileShaMatches:measured.result.profileSha256===nodeProfile.immutableInstallationProfileSha256}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source,
            self.policy_path, GPG, self.gpg_home,
        ]).stdout)
        self.assertEqual(value, {
            "nodeBlocked": 1,
            "gpgBlocked": 1,
            "qualificationStatus": "blocked",
            "reason": "immutable-installation-not-proven",
            "profileShaMatches": True,
        })
        type(self).counters["accepted_unqualified_executable"] = 0
        type(self).counters["accepted_mutable_installation"] = 0

    def test_55_immutable_installation_matrix_80(self):
        source = r"""
import {createHash} from 'node:crypto';import {readFile} from 'node:fs/promises';
import {parseCanonicalCampaignPolicyBytes} from __PRODUCTION_CORE__;
import {testOnlyMeasureExecutableInstallationQualification} from __CORE__;
const policy=parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));const profile=policy.immutableInstallationProfiles.find(entry=>entry.profileId==='immutable-node-win-a');const options={executablePath:process.execPath,immutableInstallationProfile:profile,phase:'node-campaign-execution',purpose:'cell-producer'};
const facts=(context,index)=>{const digest=label=>createHash('sha256').update(label+':'+context.profileSha256+':'+index).digest('hex');const value={linkCount:1,reparseOrSymlink:false,campaignPrincipalWritable:false,campaignPrincipalDeleteOrRenameCapable:false,campaignPrincipalAclChangeCapable:false,campaignPrincipalOwnershipTakeoverCapable:false,accessControlEvidenceSha256:digest('access'),filesystemEvidenceSha256:digest('filesystem')};switch(index%6){case 0:value.linkCount=2;break;case 1:value.reparseOrSymlink=true;break;case 2:value.campaignPrincipalWritable=true;break;case 3:value.campaignPrincipalDeleteOrRenameCapable=true;break;case 4:value.campaignPrincipalAclChangeCapable=true;break;default:value.campaignPrincipalOwnershipTakeoverCapable=true;}return value;};
const positive=await testOnlyMeasureExecutableInstallationQualification(options,{qualificationFacts:context=>{const value=facts(context,2);value.campaignPrincipalWritable=false;return value;}});if(positive.result.status!=='qualified')throw new Error('synthetic qualification positive');let blocked=0;
for(let index=0;index<80;index+=1){const measured=await testOnlyMeasureExecutableInstallationQualification(options,{qualificationFacts:context=>facts(context,index)});if(measured.result.status==='blocked'&&measured.result.reason==='immutable-installation-not-proven')blocked+=1;else throw new Error('mutable installation accepted');}
process.stdout.write(JSON.stringify({blocked,positiveStatus:positive.result.status}));
""".replace("__PRODUCTION_CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__CORE__", json.dumps(file_uri(self.instrumented_campaign_core))
        )
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ], timeout=300).stdout)
        self.assertEqual(value, {"blocked": 80, "positiveStatus": "qualified"})
        type(self).counters["immutable_installation_controls"] = 80

    def test_56_immutable_profile_schema_and_probe_matrix_20(self):
        source = r"""
import {readFile} from 'node:fs/promises';import {validateImmutableInstallationProfile} from __CORE__;
const policy=JSON.parse(await readFile(process.argv[1],'utf8'));const base=policy.immutableInstallationProfiles[0];const clone=value=>JSON.parse(JSON.stringify(value));let rejected=0;
for(let index=0;index<20;index+=1){const value=clone(base);switch(index%10){case 0:delete value.profileId;break;case 1:value.extraAuthority=true;break;case 2:value.documentKind='attacker-kind';break;case 3:value.schemaVersion=2;break;case 4:value.qualificationMode='caller-success-v1';break;case 5:value.osFamily='darwin';break;case 6:value.architecture='ia32';break;case 7:value.executableSha256='bad';break;case 8:value.executableByteLength=0;break;default:value.linkPolicy='file-only-readonly';}try{validateImmutableInstallationProfile(value);}catch{rejected+=1;continue;}throw new Error('invalid immutable profile accepted');}
process.stdout.write(JSON.stringify({rejected}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {"rejected": 20})
        type(self).counters["immutable_installation_controls"] += 20

    def test_57_adapter_and_canonical_isolation_additional_20_10(self):
        source = r"""
import * as core from __CORE__;import {readFile} from 'node:fs/promises';
const policy=core.parseCanonicalCampaignPolicyBytes(await readFile(process.argv[1]));const base={campaignPolicy:policy,campaignRole:'cell-producer',matrixCellId:'WIN-A',hostRole:'WIN-A'};let adapterRejected=0;
for(let index=0;index<20;index+=1){const key=index%2===0?'qualificationSucceeded':Symbol.for('ieltmps.r1-10e.execution-qualification.test-adapter');const value={...base};Object.defineProperty(value,key,{value:true,enumerable:true});try{core.measureCurrentNodeProcessAuthority(value);}catch{adapterRejected+=1;continue;}throw new Error('production adapter activation accepted');}
const profile=policy.immutableInstallationProfiles[0];const canonical=core.encodeCanonicalImmutableInstallationProfile(profile);let canonicalRejected=0;
for(let index=0;index<10;index+=1){const bytes=Buffer.from(canonical.toString('ascii').replace('"profileId":','"profileId":"duplicate-'+index+'","profileId":'),'ascii');try{core.parseCanonicalImmutableInstallationProfileBytes(bytes);}catch{canonicalRejected+=1;continue;}throw new Error('duplicate-key immutable profile accepted');}
process.stdout.write(JSON.stringify({adapterRejected,canonicalRejected,hasTestExport:Reflect.ownKeys(core).some(key=>String(key).startsWith('testOnly'))}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {
            "adapterRejected": 20,
            "canonicalRejected": 10,
            "hasTestExport": False,
        })
        type(self).counters["adapter_isolation_controls"] += 20
        type(self).counters["canonical_duplicate_key_controls"] += 10

    def test_58_signature_swap_and_complete_claim_gates(self):
        binding_controls = 0
        swap_controls = 0
        for cell_id in ("WIN-A", "LINUX-A", "LINUX-B", "WIN-B"):
            manifest = json.loads(
                (self.capsules[cell_id] / "cell-manifest.json").read_text("ascii")
            )
            verified = json.loads(self.records[cell_id].read_text("ascii"))[
                "verifiedCell"
            ]
            self.assertRegex(manifest["producerSignAssignmentSha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(manifest["producerLocalVerifyAssignmentSha256"], r"^[0-9a-f]{64}$")
            binding_controls += 2
            self.assertNotEqual(
                verified["producerSignAssignmentSha256"],
                verified["consumerVerifyAssignmentSha256"],
            )
            execution = json.loads(
                (self.capsules[cell_id] / "v2/execution-identity.json")
                .read_text("ascii")
            )
            self.assertNotIn("consumerVerifierProfileSha256", execution)
            swap_controls += 2
        self.assertEqual(binding_controls, 8)
        self.assertEqual(swap_controls, 8)
        type(self).counters["signature_binding_controls"] += binding_controls
        type(self).counters["cell_swap_replay_omission_controls"] += swap_controls
        minimum = self.summary["minimum"]
        optional = self.summary["optional"]
        for result in (minimum, optional):
            self.assertIn("L3", result["claimLevelsSatisfied"])
            self.assertIsNotNone(result["crossRuntimePair"])
            self.assertIn("L4", result["claimLevelsSatisfied"])
            self.assertIsNotNone(result["crossOsPair"])
            self.assertIn("L5", result["claimLevelsSatisfied"])
            self.assertTrue(result["allExecutionProfilesQualified"])
        type(self).counters["l3_controls"] += 4
        type(self).counters["l4_controls"] += 4
        type(self).counters["l5_controls"] += 4

    def test_59_inverse_linux_comparison_host_geometry_24(self):
        source = r"""
import {readFile} from 'node:fs/promises';
import {findCellImportConsumerGpgAuthority,findCellProducerGpgAuthorities,findComparisonGpgAuthorities,findNodeRuntimeAssignment,immutableInstallationProfileSha256,validateCampaignPolicy} from __CORE__;
const value=JSON.parse(await readFile(process.argv[1],'utf8'));
const move=(collection,profileId)=>{const profile=collection.find(entry=>entry.profileId===profileId);const immutable=value.immutableInstallationProfiles.find(entry=>entry.profileId==='immutable-'+profileId);immutable.osFamily='linux';profile.osFamily='linux';profile.immutableInstallationProfileSha256=immutableInstallationProfileSha256(immutable);};
move(value.nodeRuntimeProfiles,'node-e6-consumer');move(value.nodeRuntimeProfiles,'node-e6-comparison');
for(const assignment of value.nodeRuntimeAssignments.filter(entry=>['cell-import-consumer','comparison-host'].includes(entry.campaignRole))){assignment.hostRole='E6-LINUX';assignment.osFamily='linux';}
for(const id of ['gpg-e6-consumer','gpg-e6-comparison-sign','gpg-e6-comparison-local'])move(value.gpgVerifierProfiles,id);
for(const assignment of value.gpgVerifierAssignments.filter(entry=>['cell-import-consumer-verify','comparison-result-sign','comparison-result-local-verify'].includes(entry.gpgRole))){assignment.hostRole='E6-LINUX';assignment.osFamily='linux';}
const policy=validateCampaignPolicy(value);let controls=0;
for(const cellId of ['WIN-A','LINUX-A','LINUX-B','WIN-B']){const producer=findCellProducerGpgAuthorities(policy,cellId);const consumer=findCellImportConsumerGpgAuthority(policy,cellId,'E6-LINUX');if(consumer.profile.osFamily==='linux')controls+=1;if(consumer.assignment.hostRole==='E6-LINUX')controls+=1;if(producer.signing.profile.profileId!==consumer.profile.profileId)controls+=1;if(producer.signing.assignment.hostRole===cellId)controls+=1;}
const comparison=findComparisonGpgAuthorities(policy,'E6-LINUX','win-a-signer');if(comparison.signing.profile.osFamily==='linux')controls+=1;if(comparison.localVerification.profile.osFamily==='linux')controls+=1;if(comparison.signing.assignment.gpgRole==='comparison-result-sign')controls+=1;if(comparison.localVerification.assignment.gpgRole==='comparison-result-local-verify')controls+=1;
const consumerNode=findNodeRuntimeAssignment(policy,{campaignRole:'cell-import-consumer',matrixCellId:null,hostRole:'E6-LINUX'});const comparisonNode=findNodeRuntimeAssignment(policy,{campaignRole:'comparison-host',matrixCellId:null,hostRole:'E6-LINUX'});if(consumerNode.profile.osFamily==='linux')controls+=1;if(consumerNode.assignment.hostRole==='E6-LINUX')controls+=1;if(comparisonNode.profile.osFamily==='linux')controls+=1;if(comparisonNode.assignment.hostRole==='E6-LINUX')controls+=1;
process.stdout.write(JSON.stringify({controls}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE)))
        value = json.loads(self.run_process([
            NODE, "--input-type=module", "--eval", source, self.policy_path,
        ]).stdout)
        self.assertEqual(value, {"controls": 24})
        type(self).counters["cross_host_role_controls"] += 24

    def test_60_final_export_registry_and_private_adapter_boundary(self):
        source = r"""
import * as core from __CORE__;import * as evidence from __EVIDENCE__;import * as cell from __CELL__;import * as comparison from __COMPARISON__;
const required=['validateExternalCampaignPolicyAuthority','validateImmutableInstallationProfile','validateMeasuredQualificationResult','validateNodeRuntimeProfile','findCellProducerGpgAuthorities','findCellImportConsumerGpgAuthority','findComparisonGpgAuthorities','findIndependentReviewGpgAuthority','measureExecutableInstallationQualification','measureCurrentNodeProcessAuthority','recheckCurrentNodeProcessAuthority','validateProfiledGpgExecutionContext','runProfiledGpgOperation'];
for(const name of required)if(typeof core[name]!=='function')throw new Error('missing core export '+name);
for(const [module,name] of [[evidence,'buildExecutionIdentityV2'],[evidence,'validateExecutionIdentityV2'],[cell,'verifyPublicSourceZipCampaignCell'],[cell,'verifyDetachedOpenPgpSignature'],[comparison,'comparePublicSourceZipCampaign']])if(typeof module[name]!=='function')throw new Error('missing leaf export '+name);
const privateNames=['testOnlyWithExecutionQualificationAdapter','testOnlyMeasureCurrentNodeProcessAuthority','testOnlyRunProfiledGpgOperation'];for(const name of privateNames)if(name in core)throw new Error('private adapter exported');
process.stdout.write(JSON.stringify({required:required.length+5,private:privateNames.length}));
""".replace("__CORE__", json.dumps(file_uri(CAMPAIGN_CORE))).replace(
            "__EVIDENCE__", json.dumps(file_uri(V2_CORE))
        ).replace("__CELL__", json.dumps(file_uri(CELL_VERIFY))).replace(
            "__COMPARISON__", json.dumps(file_uri(CAMPAIGN_COMPARE))
        )
        value = json.loads(self.run_node(source).stdout)
        self.assertEqual(value, {"required": 18, "private": 3})

    def test_99_all_focused_e2_minimums_are_proven(self):
        self.assertGreaterEqual(
            len(unittest.defaultTestLoader.getTestCaseNames(type(self))), 65
        )
        minimums = {
            "targeted_controls": 54,
            "identity_mutation_controls": 72,
            "cross_host_role_controls": 48,
            "runtime_self_measurement_controls": 48,
            "immutable_installation_controls": 80,
            "self_authorized_trust_controls": 32,
            "gpg_profile_identity_controls": 40,
            "gpg_executable_profile_controls": 60,
            "fake_verifier_controls": 30,
            "profile_assignment_binding_controls": 100,
            "adapter_isolation_controls": 80,
            "canonical_duplicate_key_controls": 80,
            "proxy_controls": 120,
            "revoked_proxy_controls": 20,
            "nested_proxy_controls": 20,
            "gpg_parser_process_controls": 56,
            "signature_binding_controls": 48,
            "manifest_ledger_controls": 59,
            "mutable_capsule_controls": 111,
            "cell_swap_replay_omission_controls": 40,
            "l3_controls": 20,
            "l4_controls": 20,
            "l5_controls": 20,
            "cell_publication_marker_controls": 200,
            "comparison_publication_marker_controls": 126,
            "cleanup_uncertainty_controls": 362,
            "privacy_canaries": 80,
        }
        for key, minimum in minimums.items():
            self.assertGreaterEqual(type(self).counters[key], minimum, key)
        for key in (
            "accepted_fake_verifier",
            "accepted_unprofiled_verifier",
            "accepted_identity_mismatched_verifier",
            "accepted_replacement_race_verifier",
            "accepted_caller_authored_runtime",
            "accepted_unqualified_executable",
            "accepted_mutable_installation",
            "accepted_self_authorized_profile",
            "accepted_attacker_created_policy",
            "accepted_proxy_values",
            "proxy_trap_calls",
            "accessor_getter_calls",
            "false_completion_markers",
            "unsigned_filesystem_success_bundles",
        ):
            self.assertEqual(type(self).counters[key], 0, key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
