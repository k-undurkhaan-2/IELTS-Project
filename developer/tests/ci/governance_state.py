#!/usr/bin/env python3
"""Local delivery decisions only; records are inputs, never grants by this tool.

Runtime records belong outside the candidate checkout. The caller authenticates
current authority and evidence provenance and still enforces transition gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import run_ci_foundation as ci
from run_ci_foundation import _json_bytes as canonical, strict_json_load_file as read_document

OID = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
SHA = r"[0-9a-f]{64}"
STOPS = {"candidate_changed", "destination_changed", "authority_changed"}
MATERIAL = ("candidate_tree", "assurance_profile", "validation_definition_digest",
            "environment_contract_digest", "fixtures_digest")
ROOT = Path(__file__).resolve().parents[3]


def require(condition):
    if not condition:
        raise ValueError("invalid state")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def text(value):
    return isinstance(value, str) and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def unique(value, allowed=None):
    require(type(value) is list and all(text(v) for v in value) and len(value) == len(set(value)))
    require(allowed is None or set(value) <= allowed)


def timestamp(value):
    require(matches(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value))
    require(datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() is not None)


def ref_name(value):
    require(text(value) and value.startswith("refs/") and len(value.split("/")) >= 3)
    require(not re.search(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//", value))
    require(all(p and not p.startswith(".") and not p.endswith((".", ".lock")) for p in value.split("/")))


def destination(value):
    exact(value, ("role", "ref"))
    require(text(value["role"]))
    ref_name(value["ref"])


def validate_authority(value):
    exact(value, ("schema_version", "authority_id", "candidate_tree", "allowed_actions", "destination",
                  "required_evidence", "recovery", "stop_conditions", "issued_at", "issued_by"))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(text(value["authority_id"]) and text(value["issued_by"]) and matches(OID, value["candidate_tree"]))
    unique(value["allowed_actions"], {"stage", "sign", "verify"})
    require(bool(value["allowed_actions"]))
    unique(value["required_evidence"])
    require(not any(item.startswith("LC-") for item in value["required_evidence"]))
    destination(value["destination"])
    exact(value["recovery"], ("allowed_classes", "max_retries"))
    unique(value["recovery"]["allowed_classes"], {"parser", "environment"})
    require(type(value["recovery"]["max_retries"]) is int and value["recovery"]["max_retries"] == 1)
    unique(value["stop_conditions"], STOPS)
    require(set(value["stop_conditions"]) == STOPS)
    timestamp(value["issued_at"])


def validate_material(value):
    exact(value, MATERIAL)
    require(matches(OID, value["candidate_tree"]) and text(value["assurance_profile"]))
    for key in MATERIAL[2:]:
        require((key == "fixtures_digest" and value[key] is None) or matches(SHA, value[key]))


def decision(kind, reason, record=None, **extra):
    record = record if type(record) is dict else {}
    result = {"decision": kind, "reason": reason, "candidate_tree": record.get("candidate_tree")}
    result.update({key: record[key] for key in ("authority_id", "receipt_id", "validation_fingerprint") if key in record})
    return dict(result, **extra)


def check_authority(authority, candidate_tree, action, destination_role, destination_ref):
    try:
        validate_authority(authority)
    except (ValueError, TypeError, KeyError, OverflowError):
        return decision("DENY", "AUTHORITY_INVALID", authority)
    for valid, reason in ((candidate_tree == authority["candidate_tree"], "CANDIDATE_CHANGED"),
                          (action in authority["allowed_actions"], "ACTION_NOT_AUTHORIZED"),
                          ({"role": destination_role, "ref": destination_ref} == authority["destination"], "DESTINATION_CHANGED")):
        if not valid:
            return decision("DENY", reason, authority)
    return decision("ALLOW", "AUTHORITY_MATCH", authority, required_evidence=authority["required_evidence"])


def make_receipt(material):
    validate_material(material)
    return dict(schema_version=1, receipt_id="LC-" + uuid.uuid4().hex,
                trust_scope="local-validation-cache-only",
                candidate_tree=material["candidate_tree"], assurance_profile=material["assurance_profile"],
                validation_fingerprint=digest(material),
                fingerprint_inputs={key: material[key] for key in MATERIAL if key != "assurance_profile"},
                result="PASS", created_at=datetime.now(timezone.utc).isoformat())


def check_evidence(receipt, material):
    try:
        validate_material(material)
        exact(receipt, ("schema_version", "receipt_id", "trust_scope", "candidate_tree", "assurance_profile",
                        "validation_fingerprint", "fingerprint_inputs", "result", "created_at"))
        require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1)
        require(text(receipt["receipt_id"]) and receipt["receipt_id"].startswith("LC-"))
        require(receipt["trust_scope"] == "local-validation-cache-only")
        require(receipt["result"] in ("PASS", "FAIL"))
        timestamp(receipt["created_at"])
        exact(receipt["fingerprint_inputs"], set(MATERIAL) - {"assurance_profile"})
        recorded = dict(receipt["fingerprint_inputs"], assurance_profile=receipt["assurance_profile"])
        validate_material(recorded)
        require(receipt["candidate_tree"] == recorded["candidate_tree"])
        require(receipt["validation_fingerprint"] == digest(recorded))
    except (ValueError, TypeError, KeyError, OverflowError):
        return decision("REVALIDATE", "RECEIPT_INVALID", receipt)
    extra = {"fingerprint_components": material, "calculated_fingerprint": digest(material)}
    if receipt["result"] != "PASS":
        return decision("REVALIDATE", "RESULT_NOT_PASS", receipt, **extra)
    for key, reason in zip(MATERIAL, ("CANDIDATE_CHANGED", "ASSURANCE_PROFILE_CHANGED", "VALIDATOR_CHANGED", "ENVIRONMENT_CHANGED", "FIXTURES_CHANGED")):
        if material[key] != recorded[key]:
            return decision("REVALIDATE", reason, receipt, **extra)
    return decision("REUSE_ALLOWED", "FINGERPRINT_MATCH", receipt, **extra)


def external_path(path, repo):
    resolved = Path(path).resolve()
    require(not resolved.is_relative_to(Path(repo).resolve()))
    return resolved


def live_environment(repo):
    roles = ci.required_tool_names("static")
    tools, errors = ci.resolve_trusted_tools(roles, repo_root=repo)
    require(not errors and roles <= tools.keys())
    environment = ci._EnvironmentKeyAuthority(os.environ, windows=os.name == "nt").canonical_subset(
        ci.CHILD_ENVIRONMENT_ALLOWLIST | {"PATH", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "CI_SECURITY_TASK_TEMP"})
    return dict(tools={role: [path, hashlib.sha256(Path(path).read_bytes()).hexdigest()] for role, path in tools.items()},
                environment=environment)


def git(repo, *args):
    tools, errors = ci.resolve_trusted_tools({"git"}, repo_root=Path(repo))
    require(not errors and "git" in tools)
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run([tools["git"], "-c", f"safe.directory={Path(repo).resolve()}",
                           "-c", "core.fsmonitor=false", "-C", str(repo), *args],
                          env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def capture(repo, authority, selected_refs):
    validate_authority(authority)
    require(git(repo, "cat-file", "-t", authority["candidate_tree"]).strip() == b"tree")
    head = git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    require(all(entry.startswith(b"H ") for entry in git(repo, "ls-files", "-v", "-z").split(b"\0") if entry))
    entries = git(repo, "ls-files", "--stage", "-z")
    for entry in entries.split(b"\0"):
        if entry:
            mode, oid, stage = entry.split(b"\t", 1)[0].split()
            require(stage == b"0" and mode != b"160000")  # Unmerged/submodule state is unknown in v1.
    refs = {}
    for ref in sorted(set(selected_refs) | {authority["destination"]["ref"]}):
        ref_name(ref)
        refs[ref] = git(repo, "show-ref", "--verify", "--hash", ref).decode().strip()
        require(matches(OID, refs[ref]))  # Missing refs are unknown, never silently absent.
    untracked = []
    for name in git(repo, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if name:
            path = Path(repo) / os.fsdecode(name)
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400)
            untracked.append([name.hex(), stat.S_IMODE(metadata.st_mode), hashlib.sha256(path.read_bytes()).hexdigest()])
    diffs = [git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", *args).hex()
             for args in ((), ("--cached",))]
    return dict(schema_version=1, decision="SNAPSHOT", reason="CAPTURED", head_oid=head,
                candidate_tree=authority["candidate_tree"], index_identity=hashlib.sha256(entries).hexdigest(),
                worktree_diff_identity=digest([diffs, sorted(untracked)]), selected_refs=refs,
                destination=authority["destination"], authority_digest=digest(authority), authority_id=authority["authority_id"])


def snapshot(repo, authority, selected_refs):
    before = capture(repo, authority, selected_refs)
    require(before == capture(repo, authority, selected_refs))
    return before


def validate_snapshot(value):
    exact(value, ("schema_version", "decision", "reason", "head_oid", "candidate_tree", "index_identity",
                  "worktree_diff_identity", "selected_refs", "destination", "authority_digest", "authority_id"))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(value["decision"] == "SNAPSHOT" and value["reason"] == "CAPTURED" and text(value["authority_id"]))
    for key in ("head_oid", "candidate_tree"):
        require(matches(OID, value[key]))
    for key in ("index_identity", "worktree_diff_identity", "authority_digest"):
        require(matches(SHA, value[key]))
    destination(value["destination"])
    require(type(value["selected_refs"]) is dict and value["destination"]["ref"] in value["selected_refs"])
    for ref, oid in value["selected_refs"].items():
        ref_name(ref)
        require(matches(OID, oid))


def check_recovery(before, after, authority, failure_class, attempt):
    try:
        validate_authority(authority)
        validate_snapshot(before)
        validate_snapshot(after)
    except (ValueError, TypeError, KeyError, OverflowError):
        return decision("ESCALATE", "STATE_UNKNOWN", authority)
    for key, reason in (("candidate_tree", "CANDIDATE_CHANGED"), ("head_oid", "HEAD_CHANGED"),
                        ("index_identity", "INDEX_CHANGED"), ("worktree_diff_identity", "WORKTREE_CHANGED"),
                        ("selected_refs", "REF_CHANGED"), ("destination", "DESTINATION_CHANGED"),
                        ("authority_digest", "AUTHORITY_CHANGED"), ("authority_id", "AUTHORITY_CHANGED")):
        if before[key] != after[key]:
            return decision("ESCALATE", reason, authority)
    for key, expected, reason in (("candidate_tree", authority["candidate_tree"], "CANDIDATE_CHANGED"),
                                  ("destination", authority["destination"], "DESTINATION_CHANGED"),
                                  ("authority_digest", digest(authority), "AUTHORITY_CHANGED"),
                                  ("authority_id", authority["authority_id"], "AUTHORITY_CHANGED")):
        if before[key] != expected:
            return decision("ESCALATE", reason, authority)
    if failure_class not in authority["recovery"]["allowed_classes"]:
        return decision("ESCALATE", "FAILURE_CLASS_NOT_ALLOWED", authority)
    if type(attempt) is not int or not 1 <= attempt <= authority["recovery"]["max_retries"]:
        return decision("ESCALATE", "RETRY_LIMIT", authority)
    return decision("RETRY_ALLOWED", "NO_SEMANTIC_DELIVERY_STATE_MUTATION_DETECTED", authority)


def frozen_context(repo, environment_contract_path, fixtures_digest):
    """Local caller attests the external tool/dependency/fixture contract.

    This binds actual clean checkout and Python/platform identity as well. No
    authority, task ID or historical report contributes to technical identity.
    """
    repo = Path(repo).resolve()
    runtime = live_environment(repo)
    require(all(entry.startswith(b"H ") for entry in git(repo, "ls-files", "-v", "-z").split(b"\0") if entry))
    require(not git(repo, "status", "--porcelain=v1", "--untracked-files=all").strip())
    require(b"160000 " not in git(repo, "ls-files", "--stage", "-z"))
    contract = read_document(external_path(environment_contract_path, repo))
    require(type(contract) is dict and bool(contract))
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    ci_dir = repo / "developer/tests/ci"
    definitions = {name: hashlib.sha256((ci_dir / name).read_bytes()).hexdigest() for name in
                   ("run_ci_foundation.py", "test_ci_foundation.py", "governance_state.py",
                    "current-authority.v1.schema.json", "evidence-receipt.v1.schema.json")}
    material = dict(candidate_tree=tree, assurance_profile="r12-full-validation-v1",
                    validation_definition_digest=digest(definitions),
                    environment_contract_digest=digest(dict(contract=contract, runtime=runtime, python=sys.version,
                        platform=platform.platform(), executable_digest=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())),
                    fixtures_digest=fixtures_digest)
    validate_material(material)
    return material


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    auth = commands.add_parser("authority-check")
    for name in ("authority", "candidate-tree", "action", "destination-role", "destination-ref"):
        auth.add_argument("--" + name, required=True)
    evidence = commands.add_parser("evidence-check")
    evidence.add_argument("--receipt", required=True)
    for name in MATERIAL:
        evidence.add_argument("--" + name.replace("_", "-"), required=True)
    state = commands.add_parser("state-snapshot")
    state.add_argument("--authority", required=True)
    state.add_argument("--repo", type=Path, default=ROOT)
    state.add_argument("--selected-ref", action="append", default=[])
    recovery = commands.add_parser("recovery-check")
    for name in ("before", "after", "authority", "failure-class"):
        recovery.add_argument("--" + name, required=True)
    recovery.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args(argv)
    fallback = {"authority-check": ("DENY", "AUTHORITY_INVALID"), "evidence-check": ("REVALIDATE", "RECEIPT_INVALID"),
                "state-snapshot": ("ESCALATE", "STATE_UNKNOWN"), "recovery-check": ("ESCALATE", "STATE_UNKNOWN")}
    try:
        authority = read_document(external_path(args.authority, getattr(args, "repo", ROOT))) if hasattr(args, "authority") else None
        if args.command == "authority-check":
            result = check_authority(authority, args.candidate_tree, args.action, args.destination_role, args.destination_ref)
        elif args.command == "evidence-check":
            material = {name: getattr(args, name) for name in MATERIAL}
            if material["fixtures_digest"] == "null":
                material["fixtures_digest"] = None
            result = check_evidence(read_document(Path(args.receipt)), material)
        elif args.command == "state-snapshot":
            result = snapshot(args.repo, authority, args.selected_ref)
            require(authority == read_document(external_path(args.authority, args.repo)))
        else:
            result = check_recovery(read_document(Path(args.before)), read_document(Path(args.after)), authority, args.failure_class, args.attempt)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError):
        result = decision(*fallback[args.command], {"candidate_tree": getattr(args, "candidate_tree", None)})
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    return 0 if result["decision"] in ("ALLOW", "REUSE_ALLOWED", "SNAPSHOT", "RETRY_ALLOWED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
