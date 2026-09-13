# Issue 13: verified backend portable result

This local raw-capture availability remediation is based exactly
on `52677251a28f77116c2011be1ebf5a31310d102c`. The parent's proven ordinary-evidence
privacy, raw authority preservation, exact backend portability, protocol
isolation, and non-backend behavior are retained. The remaining blocker was
that an absent capture could use ordinary text as exact evidence, including
missing stderr with an empty fallback and recorded empty-stream authority.
The unresolved hosted state is represented by local synthetic
integration fixtures; this transaction does not run hosted CI, rerun
34710916747, modify either PR, or push a branch.

`BackendCanonicalPortableResult` is an optional comparison of the successful
128-test backend npm reporter. It becomes available only inside
`verify_evidence_with_replay`, after raw evidence, producer and fresh replay
bindings, and replay eligibility have succeeded. It never authorizes execution.

## Public boundary

The outer API has no `backend_result_evidence` injection argument:

```python
verify_evidence_with_replay(
    output_dir=OUTPUT_DIR, *, expected_context, verification_runner,
    repo_root=REPO_ROOT, evidence_authority_root=None,
)
```

The production path is `main()` -> `--verify-evidence` ->
`prepare_verification_authority()` -> `verify_evidence_with_replay()`.
After validating the ordinary five-file snapshots, a PASS summary with an
exit-zero backend-canonical result in the backend/all plan selects portability
automatically. The binder requires exactly one backend record. Policy and
plans without an eligible backend result retain the ordinary replay path.
There is no new CLI flag, workflow input, document, or document field.

The private `_OrdinaryValidatedProducer` explicitly holds the ordinary wire
representation, including compact empty arrays and digest references. It is
separate from `_ReplayEvidence`, which holds the fresh runner's full local facts.
Neither is an argument of any public verifier API.

The producer's generic
`raw_observation_json_value()` normalizes process text and strips leading/final
newlines. Successful backend observations now retain strict UTF-8 stdout/stderr
in their existing `rawStructuredFields` entries before their producer digest is
computed. This backend-only retention change preserves exact Unicode spelling,
line endings, and all other bytes. The generic observation encoder and other
command families retain their existing behavior. An older artifact with lossy
stream text is unavailable for portability and rejects; omitted bytes are never
guessed or restored from diagnostic previews.

Exact retention first checks the existing privacy rules for both streams:
terminal/Unicode format controls, authorized-root and absolute-path handling,
credential redaction, and high-confidence secrets. Privacy inspection also
covers the CRLF/separator-normalized representation used by the ordinary sanitizer.
This inspection never changes retained bytes. Safe LF/CRLF presentation,
Unicode spelling, whitespace, and literal escapes remain exact.

The backend-specific `_backend_successful_stream_observation_text` selects each
successful stdout/stderr observation independently, before its producer digest
or derived copies are created:

1. If the retained raw capture is `None`, select the existing fixed marker
   `[BACKEND STREAM REDACTED]` directly. Ordinary fallback text cannot replace
   missing bytes, even if its byte length and SHA-256 match recorded authority.
   Independently check the marker with the existing backend privacy guard before
   attaching it. No empty capture is synthesized or inferred from a record.
2. If the retained raw capture is a real bytes object, including `b""`, attempt
   strict UTF-8 decoding of the original captured bytes. Exact text is
   eligible only when the unchanged backend privacy guard accepts it and the
   existing ordinary privacy redaction patterns leave that text unchanged.
   This privacy transformation excludes ordinary timing, whitespace, and
   line-ending normalization, preserving safe reporter bytes as required.
3. Otherwise select the existing ordinary sanitized observation text. Independently
   run the backend privacy guard on this candidate; a sanitizer call or a change
   in text is not proof of safety.
4. If the selected candidate is unsafe, replace it with the single fixed marker
   `[BACKEND STREAM REDACTED]`. It is 25 printable ASCII bytes, deterministic,
   contains no source-derived text, and remains unchanged under both generic
   `sanitize_text` and `raw_observation_json_value`.
5. Check the final selected value again with the unchanged backend guard before
   admitting it to the observation. A failed final check raises a fixed error
   containing no source text, including if the marker itself becomes unsafe.

Missing raw bytes always take the marker path; strict decoding failure of an
available bytes object retains the existing independently checked ordinary
fallback path. An available `b""` decodes to exact `""` and remains portable
when the recorded empty-stream authority matches. The reviewer payload
`r"\tmp/private-fixture/runner-output.txt"` remains unsafe. Generic escape
protection/restoration preserves its literal `\t`, so this candidate requires
the fixed marker. Other mixed-separator candidates can change during generic
normalization yet remain unsafe; they receive the same marker.

Raw stream authority, ordinary display text, and portable exact availability
remain separate. The command keeps both original stream SHA-256 values and
observed byte lengths. Only observation text and its derived digests change.
The unchanged producer binder strictly encodes observation text and requires
both its byte length and SHA-256 to match the original stream. A sanitized or
marker fallback therefore makes that producer stream unavailable; it cannot
become a second authority path. The same unchanged privacy predicate in
producer/replay binding rejects coherently forged unsafe exact observations.
The generic sanitizer and secret/path policy are unchanged.

For missing stderr recorded as zero bytes with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
the emitted observation is the 25-byte marker. The unchanged producer binder
therefore fails byte-length reconstruction before reporter parsing or identity
derivation. The outer verifier reports backend unavailability; the ordinary raw
replay retains ordinal 701 and rejects. With retained `stderr_raw=b""` and the
same authority, the observation remains `""`, producer binding succeeds, and a
safe duration-only pair parses twice and derives identity twice without an
ordinal-701 mismatch. Capture availability does not expand generic assignment
key policy, including the inherited handling of `credential=...`.

The lower public signatures remain frozen:

```python
def compare_verification_replay_claims(
    documents: Mapping[str, dict[str, Any]],
    runner: FoundationRunner,
    comparison: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:

def run_verification_replay(
    documents: Mapping[str, dict[str, Any]],
    *,
    expected_context: ExternallyExpectedVerificationContext,
    verification_runner: FoundationRunner,
    repo_root: Path = REPO_ROOT,
) -> tuple[dict[str, Any] | None, list[str]]:
```

These APIs cannot select backend portability. They reject the additional keyword
with `TypeError` and never obtain a capability from document fields, runner
attributes, or mutable global state. They retain the original raw comparison,
execution, cleanup, diagnostics, and authorization-envelope behavior. The outer
path without an eligible backend result still calls public `run_verification_replay`.

## Binding before derivation

The automatically selected outer path executes these steps in order:

1. Validate the exact five-file set, safe bounded reads, document schemas,
   raw records, semantic claims, and external context using the existing validator.
2. Read replay snapshots and validate those exact documents and snapshots again.
   This closes the interval between the original validation and replay read.
   Recheck directory membership and require a PASS summary before binding.
3. Create a private producer context from the validated wire record. Bind
   command, ordinal, class, role, required/profile/platform, argv, independent
   command plan, runtime/dependency/tool/guard, protected targets and inputs,
   stdout/stderr hash/length/bytes, and raw observation/set/universe/transcript
   aggregates. Independently compare the portable authority projection.
   Reconstruct execution inputs only with
   `_reconstructed_protected_execution_inputs()`: each ordered retained target
   supplies logical path, canonical source path, planned byte length/hash/stable
   identity, actual byte length/hash equal to the plan, and the recorded input
   mode. Require exact reproduction of `executionInputBundleDigest`. The raw
   validator checks empty protected-bundle duplicate arrays and both compact
   phase digest arrays against independently reconstructed command authority.
   These checks are unchanged.
   Encode each exact process observation stream with strict UTF-8 and require
   its retained SHA-256 and byte count. Require one process-output observation
   and empty stderr. Read `backend/package.json` with the existing
   `TargetExecutionLease` using the independently prepared candidate target;
   compare its bytes with the retained producer target's exact hash and size.
   The fresh lease is closed locally. It is not a producer lease reconstruction.
   Bind runtime, closure, and guard directly from command-results.json.
   The wire record stays compact: duplicate bundle arrays are not expanded,
   and pre/post held-handle identities, file indexes, timestamps, and other
   omitted physical lease preimages remain intentionally unreconstructed.
4. Execute the externally selected runner once, retaining its existing
   `finally` cleanup behavior.
5. Validate every fresh command record against the existing raw validators and
   independent local command authority, including unrelated commands' execution
   state and protected inputs. Recheck the producer context and bind the replay to exactly one fresh command
   result, independent plan member, and actual `CommandCapture`, including exact
   raw capture bytes. Require no stdin lease for this protected-bundle command.
   Bind the capture's measured execution fields to the command record;
   validate fresh runtime/dependency/tool/guard, protected inputs, execution
   state, and hard gates. Compare both sides' bound non-reporter inputs,
   including npm hash, size, and version, before parsing. Self-consistent
   producer authority cannot substitute for independently measured fresh
   authority. Recompute the plan digest from the actual plan.
6. Check claimed replay fields, hard gates, profile,
   execution/authorization bindings, plan, command membership, and completed
   class eligibility. No command semantic equality is collected at this step,
   and no incomplete backend comparison view exists.
7. Validate the existing replay authorization/cleanup requirements. Rebuild the
   outer external context and recheck evidence identities, bytes, and membership.
   Rebind both sides again, reread the package through the candidate target lease,
   and require equality with the earlier bound pair.
8. Derive results from the two immutable bound sides. Parse both complete
   reporters before computing either backend result identity. Require equality
   of both complete result objects and identities.
9. Collect the complete comparisons once. Use portable backend views only when
   both complete results and identities were actually derived and equal;
   otherwise retain the raw backend record and emit the explicit unavailable
   backend error. Every unrelated command keeps its existing comparison.
   Aggregate command, observation, transcript, and summary differences. Attach
   `backendCanonicalPortableResult` only when there are no errors, then derive
   the final replay envelope over the transcript including that result.

Every binding failure has zero backend parser and identity calls. A producer
reporter parse failure has one parser call and zero identity calls; a replay
reporter parse failure has two parser calls and zero identity calls. An identity
mismatch has two parser calls and two identity calls. All of these failures
return no portable field and cannot yield a final PASS. Cleanup, raw authority,
execution eligibility, and outer evidence/context failures precede parsing.
Unrelated semantic mismatches do not block derivation, but still reject final
acceptance. An unavailable derivation never silently removes raw ordinal 701.
A failure
while finishing the final envelope removes the result and returns REJECT.

## Strict reporter and identity

The reviewed `_parse_stdout` implementation and full-line grammar are retained.
It accepts exactly 128 unique ordered passing members and exactly these counts:
tests 128, suites 0, pass 128, fail 0, cancelled 0, skipped 0, todo 0.
The npm banner must match the protected package name/version. The package's
test script must be exactly `node --test`, without pretest or posttest scripts.
Nonempty stderr and incomplete or nonpassing execution are ineligible.

The only excluded bytes are the decimal numeric span inside each terminal
`(Dms)` field and the final `ℹ duration_ms D` numeric span. A decimal has 1–16
ASCII integer digits and optionally a decimal point followed by 1–16 digits.
Exponent notation, NaN, alternate units, unknown lines, and other reporters are
rejected. There are exactly **129 excluded spans and 130 retained segments**.

Names, numeric text or duration-looking text inside names, statuses, ordering,
counts, banners, whitespace, punctuation, units, line endings, and the final
newline remain exact. A single optional leading npm newline is recognized but
retained. The stream limit is 2 MiB, each line is at most 2,048 bytes, and a name
is at most 1,024 UTF-8 bytes. No generic numeric or Unicode normalization occurs.

The detached result has these fields:

```text
identityDigest
result:
  schema: BackendCanonicalPortableResult
  version: 1
  command: commandId, commandClass, ordinal
  orderedTests: 128 exact name/status objects
  reporterCounts: tests, suites, pass, fail, cancelled, skipped, todo
  package: name, version, packageJsonSha256
  lifecycle: event=test, pretest=null, test="node --test", posttest=null
  tools: node and npm role, size, sha256, version
  exitCode: 0
  stdoutNonDurationSegmentsHex: 130 exact byte segments
  stderr: byteLength=0, sha256=SHA256(empty bytes)
  portableAuthorityDigest
  portableInputBundleDigest
  dependencyClosureDigest
```

`identityDigest` uses the existing canonical digest framing with domain
`ieltmps-backend-canonical-portable-result-v1` and `resultUtf8` containing exact
UTF-8 JSON bytes. JSON has sorted keys, compact separators, `ensure_ascii=False`,
and `allow_nan=False`. Byte framing preserves Unicode spelling. Protected-input,
tool, dependency, and authority differences do not become equivalent by
excluding durations.

## NODE_PATH and non-interference

The portable result validates consistency with the existing recorded/runtime
authority contract. Under existing behavior, the inherited launcher may provide
confined dependency roots through NODE_PATH. This change does not alter that
production behavior and does not assert that the effective backend environment
has an empty NODE_PATH.

The local canonical record/transcript functions, five-file writer, compaction,
local authority validators, authorization-envelope constructors, workflows, and
frontend-security/standalone-packaging result semantics retain their existing
implementations. Acquisition, capture, and GPG code are not
part of this patch. The raw replay transcript and evidence retain their original
stream hashes and aggregates; comparison views are detached private values.

## Validation

`test_backend_canonical_portable_result.py` exercises the actual `main()` and
outer verifier with five files written by the unchanged evidence writer and
validated by the real raw/semantic validators. Its hosted-shaped plan places
the compact backend record at ordinal 701. The two separately named hosted
controls have these unresolved differences after backend duration derivation:

| Fixture | Unequal ordinals | Backend parser calls | Backend identity calls | Final acceptance |
| --- | --- | --- | --- | --- |
| Ubuntu | 687, 695, 702 | 2 | 2 | REJECT |
| Windows | 687, 692, 695, 702 | 2 | 2 | REJECT |
| Ubuntu with backend semantic mutation | 687, 695, 701, 702 | 2 | 2 | REJECT |
| Ubuntu with backend reporter failure | 687, 695, 701, 702 | 2 | 0 | REJECT |
| Ubuntu with unavailable backend capture | 687, 695, 701, 702 | 0 | 0 | REJECT |

An equal backend result removes 701 only after actual derivation. Policy
and plans containing only frontend/packaging commands cannot select the backend
binder. The synthetic runner provides bounded fresh execution fixtures;
authority preparation and external-context rebuilding are controlled by the
fixture. This does not claim a hosted replay or a live backend npm execution.

The exact-stream privacy matrix retains all 26 previous synthetic payloads and
adds 15 escape-prefix and mixed-separator variants, for 41 payloads. Each is
tested as entire stdout, entire stderr, and a backend reporter test name:
token and credential assignments, including CRLF splits; Authorization/Bearer; Cookie and
Set-Cookie; private-key markers; credential HTTP and database URL separator
aliases; Windows drive, UNC, device, and file-URI paths; POSIX home/task paths
and mixed/backslash aliases; ANSI, ASCII, bidi, and other Unicode format
controls. The additions include literal `\t`, `\n`, and `\r` prefixes,
Windows/UNC/file-URI variants, and two transformed-but-still-unsafe candidates.
All 123 producer cases inspect actual serialized `command-results.json` bytes
and each of the five ordinary artifacts. Both the original substring and its
JSON-escaped representation must be absent. They validate the ordinary five-file
set and check unchanged SHA-256/length for both original streams on disk and in
memory, unavailable producer binding, zero parsing/identity calls, and raw
replay rejection with the backend ordinal retained.

The exact reviewer counterexample has six additional cases: all three placements
on Ubuntu and Windows fixtures with backend ordinal 701. The embedded case is
independently parsed once as a syntactically complete 128-test reporter before
the zero-call verifier instrumentation begins. Eight further serialized-artifact
cases cover absent or invalid UTF-8 raw captures on either stream, including an
unsafe companion stream. The fixed-marker test checks its printable ASCII
length, sanitizer stability, guard acceptance, and refusal to admit an unsafe
replacement marker.

For unsafe producers, the outer CLI rejects before running the replay fixture.
The unchanged lower replay API is then separately exercised with the captured
raw pair: it retains ordinal 701 (or ordinal 0 in the small matrix), returns
`finalAcceptance=REJECT`, and never calls backend parsing or identity. This
diagnostic check introduces no production authority or execution path.
Another 82 binding controls deliberately inject coherent unsafe producer/replay
records and prove binding rejects them. Safe Unicode, LF/CRLF, and literal-escape
controls prove exact retention remains available.

The availability matrix adds ten independent five-file cases: Ubuntu and
Windows versions of missing stdout, missing empty stderr with ordinary `""`,
both missing captures, missing stdout with coherently rewritten fallback
authority, and missing stdout whose empty fallback coincides with recorded
empty authority. All use backend ordinal 701. The rewritten 25-byte stdout
fallback also proves equal length cannot bypass the SHA-256 check. Each case
records the actual serialized stream values, preserves original hash/length,
requires zero parser/identity calls, reports explicit backend unavailability,
and separately retains raw ordinal 701 with `finalAcceptance=REJECT`.

Two additional hosted-shaped positive controls explicitly retain
`stderr_raw=b""`. They require exact empty serialized stderr, no marker in any
ordinary artifact, successful producer binding, two parser and two identity
calls, an attached portable result, and no ordinal-701 mismatch. The existing
Ubuntu and Windows unrelated-mismatch controls also explicitly retain empty
stderr bytes. A focused selector control rejects an independently unsafe marker
even with ordinary `""` and proves `None` never selects ordinary fallback text.

The dedicated entry point uses the unchanged foundation inventory runner. Its
37-method inventory retains all 34 parent methods and adds these three:

- `test_missing_raw_capture_selection_never_uses_ordinary_fallback`
- `test_missing_raw_capture_matrix_rejects_before_parsing`
- `test_captured_empty_stderr_preserves_exact_portability`

It names every executed method,
including both hosted OS controls, and reports discovered/executed/passed/failed/
error/skip and setup-blocked accounting in the same fresh log.

The tests instrument backend parsing and identity calls, emit the negative
matrix and successful call order, verify lower-API confinement, and check that
the final authorization binding covers the attached result. The no-leading-LF
reference fixture has 6,685 stdout bytes: 516 numeric bytes in 129 spans and
**6,169 retained bytes**. Every retained byte is individually mutated; each
mutation must reject or change identity. Each of the 129 duration spans is
independently changed and must preserve the parsed result. Leading-newline
sensitivity is tested separately.

Run the dedicated backend tests, focused replay/governance/security tests,
`git diff --check`, and the unchanged complete foundation entry point:

```text
python -B developer/tests/ci/test_backend_canonical_portable_result.py
python -B developer/tests/ci/test_ci_foundation.py CI6ReplayVerificationTest P52CompactIdentitySecurityTest CI7ExternalAuthorityBindingTest CI8FreshVerifierTrustDomainTest
python -B developer/tests/ci/test_governance_state.py
git diff --check
python -B developer/tests/ci/test_ci_foundation.py
```

The final foundation acceptance requires all 476 discovered tests to execute
and pass with zero failures, errors, skips, or blocked tests. It uses no cached
PASS receipt. The full-scale foundation fixture retains 705 commands and 16
classes, with 911 targets and 19,876 references. Its inventory expectations,
plan builder, and fixed size limits remain unchanged.
This transaction ends with one signed, verified local commit and
stops before push, hosted CI, or any PR modification.
