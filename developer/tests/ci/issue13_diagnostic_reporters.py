"""Bounded reporter readers for Issue 13. NEVER an acceptance protocol.

These readers preserve reported membership and outcome counts for investigation.
A complete parse is a syntax fact, not proof of execution, coverage, or authority.
Unrecognized bytes remain in the private streams; they are never discarded from CI.
"""
from __future__ import annotations

import hashlib
import json
import re

MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_LINES = 16_384
MAX_LINE_BYTES = 16_384
MAX_TESTS = 512
MAX_NAME_BYTES = 1024
NODE_COUNTS = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
PYTHON_COUNTS = (
    "tests", "pass", "fail", "error", "skip", "expected-failure", "unexpected-success",
)
STATUSES = ("pass", "fail", "error", "skip", "todo", "cancelled",
            "expected-failure", "unexpected-success")
REASONS = (
    "raw-unavailable", "stream-bound", "encoding", "line-bound", "control-byte",
    "empty", "summary", "membership", "counts", "unexpected-output", "banner",
    "stderr", "exit", "source-inventory", "authority", "execution-state",
)


def digest(value):
    """Diagnostic JSON identity, deliberately separate from CI canonical framing."""
    return "sha256:" + hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")).hexdigest()


def _lines(raw):
    if raw is None:
        return [], ["raw-unavailable"]
    if type(raw) is not bytes or len(raw) > MAX_STREAM_BYTES:
        return [], ["stream-bound"]
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return [], ["encoding"]
    # No ANSI/control normalization. Only recognize LF and CRLF as line delimiters.
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text) or "\r" in text.replace("\r\n", ""):
        return [], ["control-byte"]
    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) > MAX_LINES or any(len(x.encode("utf-8")) > MAX_LINE_BYTES for x in lines):
        return [], ["line-bound"]
    return lines, []


def _member(name, status):
    if not name or name != name.strip() or len(name.encode("utf-8")) > MAX_NAME_BYTES:
        return None
    return {"name": name, "status": status}


def _finish(kind, members, counts, reasons, unrecognized, presentation, banner=None):
    if len(members) > MAX_TESTS:
        members = members[:MAX_TESTS]
        reasons.append("membership")
    if len({x["name"] for x in members}) != len(members):
        reasons.append("membership")
    semantic = {"kind": kind, "members": members, "counts": counts, "banner": banner}
    return {
        "kind": kind,
        "complete": not reasons,
        "reasons": sorted(set(reasons)),
        "members": members,
        "counts": counts,
        "semanticDigest": digest(semantic),
        "membershipDigest": digest(members),
        "unrecognizedCount": len(unrecognized),
        "unrecognizedDigest": digest(unrecognized),
        "presentationDigest": digest(presentation),
        "bannerDigest": digest(banner),
    }


_NODE_MEMBER = re.compile(r"([✔✖]) (.+) \((\d+(?:\.\d+)?)(ms)?\)")
_NODE_COUNT = re.compile(r"ℹ (tests|suites|pass|fail|cancelled|skipped|todo) (0|[1-9]\d{0,5})")
_NODE_DURATION = re.compile(r"ℹ duration_ms (\d+(?:\.\d+)?)")


def node_report(stdout, stderr, exit_code, *, npm_banner=None, frontend=False):
    """Recognize the observed flat Node spec grammar; other grammars stay unknown.

    Frontend failure payload is counted/digested separately, never called mere
    presentation. The unchanged CI classifier independently derives its identity.
    npm requires the complete lifecycle banner + all flat passing records + footer.
    """
    lines, reasons = _lines(stdout)
    _stderr_lines, stderr_reasons = _lines(stderr)
    reasons += stderr_reasons
    if not any(lines):
        reasons.append("empty")
    members, presentation, unrecognized, count_entries = [], [], [], []
    counts = {k: None for k in NODE_COUNTS}
    summaries = [(i, _NODE_COUNT.fullmatch(s)) for i, s in enumerate(lines)]
    first_summary = next((i for i, m in summaries if m), len(lines))
    banner_lines = []
    for i, line in enumerate(lines):
        if not line:
            continue
        m = _NODE_COUNT.fullmatch(line)
        if m:
            count_entries.append((i, m[1], int(m[2])))
            continue
        m = _NODE_DURATION.fullmatch(line)
        if m:
            presentation.append({"line": i, "duration": m[1]})
            continue
        m = _NODE_MEMBER.fullmatch(line)
        if m and i < first_summary:
            item = _member(m[2], "pass" if m[1] == "✔" else "fail")
            if item is None:
                reasons.append("membership")
            else:
                members.append(item)
            presentation.append({"line": i, "duration": m[3], "unit": m[4]})
        elif not frontend and line.startswith("> ") and not members and i < first_summary:
            banner_lines.append(line[2:])
        else:
            unrecognized.append(line)
    if [k for _, k, _ in count_entries] != list(NODE_COUNTS):
        reasons.append("summary")
    else:
        counts = {k: v for _, k, v in count_entries}
        positions = [i for i, _, _ in count_entries]
        if positions != list(range(first_summary, first_summary + len(NODE_COUNTS))):
            reasons.append("summary")
        footer_pos = first_summary + len(NODE_COUNTS)
        if footer_pos >= len(lines) or not _NODE_DURATION.fullmatch(lines[footer_pos]):
            reasons.append("summary")
        if sum(bool(_NODE_DURATION.fullmatch(s)) for s in lines) != 1:
            reasons.append("summary")
        if (counts["tests"] != len(members) or not members or counts["suites"] != 0
            or counts["pass"] != sum(x["status"] == "pass" for x in members)
            or counts["fail"] != sum(x["status"] == "fail" for x in members)
            or any(counts[k] for k in ("cancelled", "skipped", "todo"))):
            reasons.append("counts")
    if frontend:
        # Failure details are deliberately not a success grammar. Their full
        # identity is captured through the existing independently invoked parser.
        if exit_code != 1 or counts["fail"] != 1:
            reasons.append("exit")
    else:
        if npm_banner is None or banner_lines != npm_banner or len(banner_lines) != 2:
            reasons.append("banner")
        if unrecognized:
            reasons.append("unexpected-output")
        if stderr != b"":
            reasons.append("stderr")
        if exit_code != 0 or counts["fail"] != 0:
            reasons.append("exit")
    return _finish("frontend-spec" if frontend else "npm-spec", members, counts,
                   reasons, unrecognized, presentation, banner_lines if not frontend else None)


_UNIT_MEMBER = re.compile(
    r"(test_[A-Za-z0-9_]+) \((__main__\.StandalonePackagingTest\.test_[A-Za-z0-9_]+)\) \.\.\. "
    r"(ok|FAIL|ERROR|expected failure|unexpected success|skipped '[^\r\n]*')"
)
_RAN = re.compile(r"Ran (0|[1-9]\d{0,5}) tests? in (\d+(?:\.\d+)?)s")
_FOOTER = re.compile(r"(OK|FAILED)(?: \(([^\r\n]*)\))?")
_UNIT_STATUS = {"ok": "pass", "FAIL": "fail", "ERROR": "error",
                "expected failure": "expected-failure", "unexpected success": "unexpected-success"}
_FOOTER_STATUS = {"failures": "fail", "errors": "error", "skipped": "skip",
                  "expected failures": "expected-failure", "unexpected successes": "unexpected-success"}


def unittest_report(stdout, stderr, exit_code, *, inventory=None):
    lines, reasons = _lines(stderr)
    _, stdout_reasons = _lines(stdout)
    reasons += stdout_reasons
    if stdout != b"":
        reasons.append("unexpected-output")
    if not any(lines):
        reasons.append("empty")
    members, unrecognized, presentation, ran, footers, separators = [], [], [], [], [], []
    for i, line in enumerate(lines):
        if not line:
            continue
        m = _UNIT_MEMBER.fullmatch(line)
        if m:
            if ran or m[1] != m[2].rsplit(".", 1)[-1]:
                reasons.append("membership")
            status = "skip" if m[3].startswith("skipped ") else _UNIT_STATUS[m[3]]
            item = _member(m[2], status)
            if item is None:
                reasons.append("membership")
            else:
                members.append(item)
            # Skip reason is semantic, not duration presentation; retain its digest.
            if status == "skip":
                unrecognized.append(line)
        elif line == "-" * 70:
            separators.append(i)
        elif (m := _RAN.fullmatch(line)):
            ran.append((i, int(m[1])))
            presentation.append({"line": i, "duration": m[2]})
        elif (m := _FOOTER.fullmatch(line)):
            footers.append((i, m[1], m[2]))
        else:
            unrecognized.append(line)
    counts = {k: sum(x["status"] == k for x in members) for k in PYTHON_COUNTS if k != "tests"}
    counts["tests"] = len(members)
    if len(ran) != 1 or len(footers) != 1 or len(separators) != 1 or not members:
        reasons.append("summary")
    else:
        ri, total = ran[0]
        fi, result, detail = footers[0]
        if (total != len(members) or separators[0] != ri - 1 or fi != ri + 2
            or any(lines[fi + 1:]) or any(_UNIT_MEMBER.fullmatch(x) for x in lines[separators[0]:])):
            reasons.append("counts")
        reported = {k: 0 for k in _FOOTER_STATUS.values()}
        seen = set()
        for part in detail.split(", ") if detail else []:
            m = re.fullmatch(r"(failures|errors|skipped|expected failures|unexpected successes)=(0|[1-9]\d{0,5})", part)
            if not m or m[1] in seen:
                reasons.append("summary")
            else:
                seen.add(m[1])
                reported[_FOOTER_STATUS[m[1]]] = int(m[2])
        if any(counts[k] != v for k, v in reported.items()):
            reasons.append("counts")
        failed = bool(counts["fail"] or counts["error"] or counts["unexpected-success"])
        if result != ("FAILED" if failed else "OK") or exit_code != (1 if failed else 0):
            reasons.append("exit")
    if inventory is None or [x["name"] for x in members] != inventory:
        reasons.append("source-inventory")
    if unrecognized:
        reasons.append("unexpected-output")
    return _finish("python-unittest", members, counts, reasons, unrecognized, presentation)
