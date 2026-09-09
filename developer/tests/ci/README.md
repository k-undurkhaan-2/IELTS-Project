# Static CI entrypoint

This directory contains tooling that emulates the minimum CI checks for the
IELTS practice application.  The current focus is validating the static test
harness before running heavier manual validation.

## Usage

```bash
python developer/tests/ci/run_static_suite.py
```

The script generates `developer/tests/e2e/reports/static-ci-report.json` with a
machine-readable summary that can be uploaded by future CI/CD jobs.

## Local frozen-candidate cache reuse (v0.1)

`governance_state.py` evaluates four commands only: `authority-check`,
`evidence-check`, `state-snapshot`, and `recovery-check`. Run a command with
`--help` for its required inputs. Decisions are single JSON objects; exit 0
means the requested check passed, exit 1 means denied/stale/unknown. The tool
never stages, signs, changes refs, retries commands, or publishes anything.

The two adjacent v1 schemas describe prospective authority and local cache
receipts. Keep runtime authority, snapshots, environment contracts, and receipts
outside the candidate checkout. Use an owner-controlled record store: a JSON
record or matching hash does not authenticate its issuer. Historical prose is
never an execution contract. `authority-check` matches the candidate tree,
action, destination role, and full ref exactly. V1 supports `stage`, `sign`, and
`verify` only. Its ALLOW means scope matches; callers must independently check
its `required_evidence` IDs and every existing transition-specific gate.
Publication and merge authorization remain separate.

LC receipts are local optimization cache records.

They prove only that this adapter previously observed a complete successful
local harness run for matching technical fingerprint inputs.

They are not authenticated issuer evidence and cannot satisfy
Current Authority required_evidence or any publication/security/release gate.

Existing trusted evidence, verifier replay, security review, and release
evidence remain separate.

Every local receipt uses an `LC-` ID and the exact classification
`"trust_scope": "local-validation-cache-only"`. Current Authority rejects any
`required_evidence` entry beginning with `LC-`. A local cache receipt cannot
satisfy evidence requirements for `stage`, `sign`, `verify`, `merge`,
`publication`, `release`, or `deployment`. The same validated candidate may
later receive a separately authenticated authoritative evidence record.
Future authoritative evidence provenance is out of scope for v0.1.

The fingerprint is SHA-256 of `run_ci_foundation._json_bytes(material)`: UTF-8,
sorted keys, two-space indentation, no nonfinite numbers, and one final newline.
Material contains exactly `candidate_tree`, `assurance_profile`,
`validation_definition_digest`, `environment_contract_digest`, and
`fixtures_digest` (a SHA-256 or explicit JSON null). Authority IDs, receipt IDs,
timestamps, destinations, `trust_scope`, and prompt/report prose are excluded.
A receipt's nested candidate must also equal its top-level candidate. Decisions expose the
current components and calculated fingerprint to explain invalidation.

The existing full self-test entry has one opt-in local reuse point:

```text
python -B developer/tests/ci/test_ci_foundation.py --reuse-receipt-dir <external-directory> --environment-contract <external-json-file> --fixtures-digest null
```

Use a frozen, clean checkout. The environment contract must be a nonempty JSON
object describing the actual tool/runtime dependency and external fixture
closure; maintain it when those inputs change. It is a technical contract,
not a task record. The precheck additionally measures Python/platform identity,
resolves the existing static-profile trusted tools afresh, hashes their resolved
executables, and binds the existing relevant environment-key authority plus
PATH and runtime options. Ignored dependency/fixture contents are represented
by the caller-maintained contract/fixture digest, not inferred from Git.
The environment digest also binds the raw SHA-256 content, path, Git mode,
and filesystem permission mode of every tracked regular file. Git clean filters,
line-ending conversion, and `core.filemode=false` cannot hide a changed checkout
from the cache. Linked/reparse paths and unstable reads fail closed. Timestamps
and file IDs are used only to detect changes during capture, not as semantic
fingerprint inputs.
Python startup identity includes named `sys.flags`, `-X` options, warning options,
the effective `--check-hash-based-pycs` policy, and `PYTHON*` environment settings.
Optimized Python (`-O`, `-OO`, or an effective
`PYTHONOPTIMIZE`) cannot reuse or mint a receipt; the existing harness still runs.
The validation definition includes the existing runner, complete harness, new
module, and both schemas. The candidate tree binds all tracked source/tests.

Missing, stale, or malformed cache receipts run the existing complete harness. A
new immutable receipt is written exclusively only after all 476 tests execute
successfully without skips and the frozen context still matches. Dirty,
untracked, hidden-index, or unknown input state cannot reuse or mint cache
receipts.
The second identical decision returns `REUSE_ALLOWED` for the existing LC
receipt and invokes the full harness zero times. Test selectors
and hosted reuse are rejected; the default harness command, workflow, trusted
verifier replay, and security/release checks remain unchanged.

Snapshots use read-oriented Git identities and include raw tracked file contents
and modes as well as untracked file contents. Stable tracked deletions remain
representable; linked/reparse tracked paths are unknown state.
They always select the authority's destination ref in addition to explicitly
selected refs. V1 fails closed on missing refs, submodules, unmerged/hidden index
entries, unreadable state, or changes detected during capture. Recovery requires
valid equal snapshots, the same current authority/destination/candidate, an
explicitly allowed parser/environment class, and retry attempt 1. The caller
tracks attempts and executes any authorized retry; this CLI never does so.
Equality means **no semantic delivery-state mutation detected**, not proof of
zero filesystem writes. Capture and check promptly within the existing action
boundary; snapshots are not filesystem locks.

Focused tests: `python -B developer/tests/ci/test_governance_state.py`.
