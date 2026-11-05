# Issue 13: verified backend portable result

This local reserved-marker nonportability remediation is based exactly
on `0c987ae704b18b31657c99db1ff935bf54f28d3a`. The parent's proven ordinary-evidence
privacy, raw authority preservation, exact backend portability, protocol
isolation, and non-backend behavior are retained. All prior review conclusions
remain closed except the marker-authority blocker: missing capture already
serialized as the fixed marker, but matching recorded marker length and SHA-256
could let that reserved value pass producer binding and reach reporter parsing.
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
The producer binder first rejects an observation whose entire text equals
`ci._BACKEND_STREAM_REDACTION_MARKER`, before strict UTF-8 encoding or accepting
its byte length and SHA-256 as an exact stream. The source of truth is the
existing private constant in `run_ci_foundation.py`; both the writer's selector
and `backend_canonical_portable_result._bind_producer` use it directly. It is
fixed trusted code, with no caller-controlled marker argument or artifact field.
Hash/length equality cannot upgrade the marker into exact evidence, regardless
of ordinary fallback contents. Other observation text still requires both its
byte length and SHA-256 to match the original stream. The same unchanged privacy
predicate in
producer/replay binding rejects coherently forged unsafe exact observations.
The generic sanitizer and secret/path policy are unchanged.

This is intentional fail-closed sentinel reservation: a retained raw stdout
whose complete value is literally `b"[BACKEND STREAM REDACTED]"` is also
nonportable, even with matching raw authority. Rejection makes no generic claim
that the underlying raw stream did not exist. A legitimate successful backend
reporter is structurally much larger and must contain the complete 128-test
grammar. Exact whole-stream sentinel equality does not reserve marker text
embedded in a valid reporter. An available `b""` remains distinct from the marker.

For missing stderr recorded as zero bytes with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
the emitted observation is the 25-byte marker. The producer binder
rejects the reserved value before reporter parsing or identity
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
   Reject each whole-stream reserved marker before accepting exact producer
   evidence, independently of recorded length and SHA-256. Encode every other
   process observation stream with strict UTF-8 and require
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
controls prove exact retention remains available. These controls also include
the marker as a complete test name inside a valid 128-test reporter, proving
that only whole-stream marker equality is reserved.

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

The reserved-marker regressions add six independently serialized five-file
cases: all three rows below on both Ubuntu- and Windows-shaped evidence, with
backend ordinal 701 and retained `stderr_raw=b""`:

| Retained stdout | Ordinary stdout | Serialized stdout | Producer binding | Parser / identity calls |
| --- | --- | --- | --- | --- |
| `None` | `""` | `[BACKEND STREAM REDACTED]` | unavailable before side binding | 0 / 0 |
| `None` | `[BACKEND STREAM REDACTED]` | `[BACKEND STREAM REDACTED]` | unavailable before side binding | 0 / 0 |
| `b"[BACKEND STREAM REDACTED]"` | `[BACKEND STREAM REDACTED]` | `[BACKEND STREAM REDACTED]` | unavailable before side binding | 0 / 0 |

Every row records and preserves `stdoutBytesObserved=25` and
`stdoutSha256=819fd70120e7e0f1296db421669cc9291df70b0dd5e3baad731ddf844bd8f616`.
The serialized marker exactly matches that authority, yet cannot bind. The
selector spy checks the actual raw capture and ordinary fallback inputs; the
real five-file validator accepts the evidence. Serialized stderr remains `""`
with the original empty-stream authority. The outer CLI explicitly reports
backend unavailability without running replay, parsing, or identity derivation,
and returns no portable result or PASS. The separately exercised unchanged raw
replay retains ordinal 701 and reports `finalAcceptance=REJECT`. All five files
remain byte-for-byte unchanged after verification. The retained-marker case
proves intentional sentinel reservation even when raw bytes were available.

The dedicated entry point uses the unchanged foundation inventory runner. Its
40-method inventory retains all 37 parent methods and adds these three:

- `test_missing_stdout_with_marker_authority_rejects_before_parsing`
- `test_missing_stdout_with_marker_fallback_and_authority_rejects_before_parsing`
- `test_captured_literal_marker_is_intentionally_nonportable`

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


## P1A current-contract v2 addendum

The preceding v1 descriptions, measurements and receipts are historical evidence.
They describe the 128-member backend contract and the earlier 18-method standalone
reporter. Those receipts have not been rewritten or promoted to v2 acceptance.

P1A reconciles the accepted CI foundation with the accepted P0 development changes.
The backend suite retains its former tests and adds 13 accepted tests, for 141.
The standalone suite replaces
`test_default_windows_and_unix_release_use_one_positive_manifest` with
`test_available_releases_use_one_positive_manifest`,
`test_default_windows_unix_release_parity`, and
`test_authorized_reading_releases_preserve_hashes`; the other 17 names remain.
The independently observed ordered inventory is authoritative, including the
fully qualified `__main__.StandalonePackagingTest` reporter identities.

The current backend contract is `BackendCanonicalPortableResult`, version **2**,
using digest domain `ieltmps-backend-canonical-portable-result-v2`. It requires
exactly 141 unique ordered passing members, tests/pass 141, suites 0, and zero
failures, cancellations, skips or todo. There are 142 excluded numeric duration
spans (141 member durations plus the terminal duration), leaving 143 exact byte
segments. Every name, ordering, framing byte and non-duration value remains bound.
An old 128-member report is unavailable under v2; wrong counts, duplicate or
missing members and malformed framing reject. Reordering changes identity and
cannot compare equal to the accepted ordered report.

The current standalone protocols are:

- `windows-standalone-packaging-verbose-unittest-duration-v2`: exactly 20 ordered
  methods, all `ok`, CRLF framing, `Ran 20 tests in <duration>s`, and `OK`.
- `ubuntu-standalone-packaging-verbose-unittest-duration-v2`: exactly 20 ordered
  methods, 18 `ok` and the two exact foreign-shell parity skips below, LF framing,
  `Ran 20 tests in <duration>s`, and `OK (skipped=2)`.

The Ubuntu skipped methods are
`test_authorized_reading_has_real_windows_unix_parity_and_hashes` and
`test_default_windows_unix_release_parity`. Each verbose line ends exactly with
`... skipped 'Windows/Unix parity requires unavailable shell(s): windows'`.
This is the measured Python unittest reporter form, including the single quotes.
Only the footer's numeric duration is excluded. The protocol, ordered names,
per-method statuses, skip identities/reason, line endings and all other framing
remain in the semantic identity. Windows allows no skips; Ubuntu requires both
named skips and rejects an all-ok report under this native-only contract.

Unexpected/missing/extra skips, another reason, native-shell failures, wrong
counts, warnings, extra output, duplicate/reordered/missing methods and malformed
footers remain rejecting. Nonzero execution cannot acquire portability. These
reporter forms grant no execution or replay authority: ordinary raw/local
validation, source/trust binding, runtime/dependency closure, containment, privacy
and fresh replay authorization still precede semantic comparison.

The immutable Phase-1 baseline and known-debt authority are unchanged. These two
Ubuntu parity skips are current platform/capability protocol semantics, not
historical baseline debt or release-only skips. The accepted 12-file reconciliation
candidate remains unchanged; this addendum versions only the current portable
contracts. Local v2 validation is separate from any future exact-head hosted
acceptance.

## Issue #107 R3 additive backend portable-result v3 addendum

This R3 section is additive. It does not rewrite the historical v1 material or
the P1A v2 addendum above, and it does not redefine a v2 report as v3. Under the
approved v2 source profile, `BackendCanonicalPortableResult` version **2** still
means exactly 141 ordered flat members, no nested members, 142 duration spans,
143 retained non-duration segments, inventory digest
`c19b500fff55e20740791a59de895da19ccb51e8998f212413cec3c83cd8238a`,
and digest domain `ieltmps-backend-canonical-portable-result-v2`. Historical
public constants such as `VERSION = 2` and `TEST_COUNT = 141` retain that
meaning. A v2-selected side neither accepts the v3 hierarchy nor silently
changes to the v3 digest domain.

R3 adds a separately selected `BackendCanonicalPortableResult` version **3**.
Its hierarchy inventory digest is
`3217938708947463015beba935fad163b387a6ba2969625679f326c7770e843a`
and its identity domain is
`ieltmps-backend-canonical-portable-result-v3`. Thus equal-looking retained
bytes cannot make a v2 result and a v3 result share an identity.

### Protected path-profile selection

Protocol selection happens before stdout parsing and is derived from the
independently rebuilt, complete trusted path authority. Paths are sorted by
Python Unicode code point, encoded as UTF-8, joined with LF, and serialized with
exactly one terminal LF. The only recognized profiles are:

| Protocol | Tracked paths | Serialized UTF-8 bytes | Sorted-path SHA-256 |
| --- | ---: | ---: | --- |
| historical v2 | 914 | 40,446 | `ea143c283e5b8b28098505a303530d0fc9c0c2731273f5bde84d00d5022c52aa` |
| additive v3 | 916 | 40,530 | `5b9401b4afa1b964ebd2887ec023c247a605d4faad6532de6cc168720f70c786` |

Cardinality alone never selects a protocol. Partial, mixed, unknown, or
extended path profiles reject. Stdout, reporter footer counts, branch names,
environment variables, candidate-provided version fields, permissive parser
probes, and parsing fallback are not selector inputs. Once protected authority
selects v3, any v3 parsing or binding failure is final for that side; the parser
must not retry the bytes as v2.

Producer and replay perform this selection independently. Each immutable side
binding includes its selected protocol, exact path-profile identity, protected
source identity, hierarchy inventory identity, and independently rebuilt
trusted command authority. Both sides must select and bind the same values
before semantic comparison. The existing package, runtime, dependency, tool,
protected-input, containment, stderr, exit-status, producer, and fresh-replay
checks remain effective and are not replaced by reporter parsing.

### Coherent v3 protected-source tuples

The v3 profile accepts exactly one of two complete six-file source tuples. The
per-file raw SHA-256 values are:

| Protected source | LF SHA-256 | CRLF SHA-256 |
| --- | --- | --- |
| `backend/Dockerfile` | `be87830d91db221b19de4a67c67b953ba6ee111c29372e87c7e6397415d1c825` | `6a65d29fe167a6d9ef2364e1e3297257953ae31cbc82512ea4c103c6b145aebd` |
| `backend/package.json` | `64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c` | `2a4f5fc9c2587ff92598f83e9516212ced6304d5c4bceecf0797084423c7bdf7` |
| `backend/src/app.js` | `69a8947b2785ca73b2d31852da35e0e247af6197764426a408a805581b0e036f` | `da97a8be86a308a13710b7224d88ff39d120d239b33b049e09cd4f05ff5f69aa` |
| `backend/src/publicListeningFrontend.js` | `7f9e8b30341108af540d0694908411e12bdeaea0135af468856a2b3ee0f459e4` | `15772d7017cfc72fe63a409190fea626526d91522136f66d763285cb25b191bf` |
| `backend/test/backend.test.js` | `787d7c6763736960f7013b17161f2fc4445b2005a1d6c8b3ca04eb4cf13558ca` | `b638658447d0760d7ff6ce29bc3dd73dd02415cbe9e5e72f65d32d70b73988a3` |
| `backend/test/publicListeningFrontend.test.js` | `6aab71707f520837fbfce399414fe3f08be0e130988aa2bf52bd6033e6676bab` | `11bb1b9cb081fe93bf7e1b9d9af87d46778c23095e35fa89dfd7f5e38f5d201e` |

The complete all-LF tuple contains exactly 564,843 bytes. The complete all-CRLF
tuple contains exactly 577,131 bytes. Those are the two accepted tuple-wide
states; all other 62 assignments across the six LF/CRLF alternatives reject.
A substituted, omitted, duplicated, unexpectedly extended, or otherwise
invalid protected source also rejects. Recognizing both coherent line-ending
representations does not normalize source bytes or permit per-file mixing.

### Exact v3 hierarchy and reporter cardinalities

The v3 reporter has 148 top-level members and six nested members, for 154 total
executed members. The first 143 top-level members are from
`backend.test.js`; the remaining five are from
`publicListeningFrontend.test.js`. The hierarchy parent is the second
top-level member of the latter file, so its global zero-based top-level ordinal
is exactly `143 + 1 = 144`.

The required suite heading is exactly:

```text
public Listening loader rejects Locator, Manifest, Payload and inventory corruption
```

It owns exactly these six children, in this order:

1. `strict active locator schema`
2. `Manifest bytes and digest`
3. `same-length Manifest corruption is rejected by SHA-256`
4. `per-file Payload checksum`
5. `unexpected Payload file`
6. `image-root-only dependency checksum`

All six children must have the exact required indentation and parent
association, and the parent's completion must follow all six nested
completions. The children are included in the 154 executed-member total; they
are not six additional top-level entries. Missing, duplicate, reordered,
renamed, additional, or reparented members, a changed suite heading, changed
indentation, or misplaced parent completion reject.

The footer requires the exact reporter framing, punctuation, and field order,
with `tests 154`, `suites 0`, `pass 154`, `fail 0`, `cancelled 0`,
`skipped 0`, and `todo 0`, followed by the terminal duration field. Wrong
counts, fields, ordering, punctuation, additional output, nonempty stderr, or a
nonzero/incomplete execution cannot acquire v3 portability.

### Duration-only normalization and identity

For v3, normalization excludes only the approved decimal numeric text in the
154 member-completion durations and the one terminal reporter duration: exactly
155 spans, leaving exactly 156 retained byte segments. Each decimal has 1-16
ASCII integral digits and, when a fractional part is present, 1-16 ASCII
fractional digits. Exponents, signs, alternate units, `NaN`, over-width
numbers, and duration-like text outside those spans reject or remain identity
bytes as required by their grammar position.

Every other byte remains exact: the npm banner, names, suite heading, reporter
glyphs, statuses, indentation, hierarchy, ordering, whitespace, punctuation,
units, footer labels and values, line endings, and stream boundaries. The
existing maximum stdout size of 2,097,152 bytes and maximum line count of 2,048
remain unchanged. The historical v2 normalization remains separately fixed at
142 duration spans and 143 retained segments.

Positive compatibility therefore means that exact historical v2 evidence still
accepts when protected authority selects v2, while either coherent v3 source
tuple accepts only the exact v3 hierarchy and footer. Producer and replay may
differ only in the approved duration numerics and still derive equal results.
Negative compatibility requires rejection of non-duration reporter changes,
any of the 62 mixed source tuples, source/path/hierarchy substitution,
candidate-directed version selection, v2/v3 or producer/replay disagreement,
and any attempted v3-to-v2 fallback.

### R3 validation and stop boundary

This addendum describes an Issue #107 R3 **local candidate**. Focused local
tests may establish historical v2 preservation, exact v3 positives, all 62
mixed-tuple negatives, hierarchy/footer negatives, duration-only behavior,
independent selection, producer/replay agreement, and no fallback. They do not
constitute Hosted CI evidence, integration acceptance, merge approval, or
acceptance of the Security PR whose frozen source identities were used as
authority inputs.

R4, R5, R6, and R7 remain outstanding and have not started. Cross-node
integration and the separately governed Issue #109 integration decision have
not started. Hosted CI has not been dispatched or rerun for this candidate.
The candidate remains unstaged, uncommitted, and unpublished until a later
maintainer disposition explicitly authorizes the next transaction.


## Version 4 — Issue #104 A8 Backend canonical portable result

This additive contract implements the [published A8 specification](https://github.com/k-undurkhaan-2/IELTS-Project/issues/104#issuecomment-6560907296). The v2 and v3 sections above remain authoritative and unchanged. The source tuples, member inventory and framing below are normative; retained producer observations are corroborating evidence only.

## Exact source authority


The protected path profile remains 916 paths, 40,530 serialized UTF-8 bytes and SHA-256 `5b9401b4afa1b964ebd2887ec023c247a605d4faad6532de6cc168720f70c786`. Serialize the complete sorted paths as LF-separated UTF-8 with one terminal LF, as the existing selector does. The unchanged count does not identify a protocol by itself.

The following six rows, in this order, define the complete source tuple. Git object identity is separate from checkout-byte identity. Every row is a regular mode-100644 blob in the accepted Head and the independently refreshed Git tree.

| Source path | Mode and type | Accepted Git blob | Git bytes | Git content SHA-256 |
| --- | --- | --- | ---: | --- |
| backend/Dockerfile | 100644 blob | 3cda28fa6fe82476f6b4750b282075b36f1d771c | 1222 | be87830d91db221b19de4a67c67b953ba6ee111c29372e87c7e6397415d1c825 |
| backend/package.json | 100644 blob | 98de1aeca0ada9aa3dff4127bb2baf5bb84ae1b5 | 736 | 64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c |
| backend/src/app.js | 100644 blob | c18e0b98772b80a218dc34d79b8bfc2508cffcbc | 82196 | 7e2a3c01fef143e952d2e5eada139ed79461a959721004d2bb6ac9cfca417513 |
| backend/src/publicListeningFrontend.js | 100644 blob | e4b5d6a67eff5e8de5718fa4ef744405c7829eb9 | 36102 | 92ded411a1cc6de6d4bbfabe6294652ba5ed8d361c2b9c52edd8a71a22e4ce60 |
| backend/test/backend.test.js | 100644 blob | 1692e8f51d2d537d8776931003cd3e46b1bfcdc3 | 410758 | 787d7c6763736960f7013b17161f2fc4445b2005a1d6c8b3ca04eb4cf13558ca |
| backend/test/publicListeningFrontend.test.js | 100644 blob | 475f2785d853213b1e7eeb5c8f1f0955267dae98 | 43973 | 9b8917b372ee78fdab1f59659762d06d0fd5d6af9cd9f2bfc9021f8b83b0e695 |

The exact accepted LF representation is the Git-object content. The exact CRLF representation is independently derived by replacing every LF in those verified LF-only blobs with CRLF. The measured retained Linux producer tuple equals the complete LF tuple; the Windows producer tuple equals the complete CRLF tuple.

| Source path | LF bytes | LF SHA-256 | CRLF bytes | CRLF SHA-256 |
| --- | ---: | --- | ---: | --- |
| backend/Dockerfile | 1222 | be87830d91db221b19de4a67c67b953ba6ee111c29372e87c7e6397415d1c825 | 1258 | 6a65d29fe167a6d9ef2364e1e3297257953ae31cbc82512ea4c103c6b145aebd |
| backend/package.json | 736 | 64b7da71131e3012c15ca83dc9e434286763e5caa4deed5a1df27d59ff34ad4c | 763 | 2a4f5fc9c2587ff92598f83e9516212ced6304d5c4bceecf0797084423c7bdf7 |
| backend/src/app.js | 82196 | 7e2a3c01fef143e952d2e5eada139ed79461a959721004d2bb6ac9cfca417513 | 84259 | 889321f101eea48610cb82adadd3f9b80b6c9b648ff5689facb5445a9006033b |
| backend/src/publicListeningFrontend.js | 36102 | 92ded411a1cc6de6d4bbfabe6294652ba5ed8d361c2b9c52edd8a71a22e4ce60 | 36976 | e609251b1665512646ac805987cbc1442de455e6b688c2414a68268db8fe9a04 |
| backend/test/backend.test.js | 410758 | 787d7c6763736960f7013b17161f2fc4445b2005a1d6c8b3ca04eb4cf13558ca | 419284 | b638658447d0760d7ff6ce29bc3dd73dd02415cbe9e5e72f65d32d70b73988a3 |
| backend/test/publicListeningFrontend.test.js | 43973 | 9b8917b372ee78fdab1f59659762d06d0fd5d6af9cd9f2bfc9021f8b83b0e695 | 44909 | 9c3bc27da8d0391d6e5e4b8cbcd942a95ca2850591f9e1db2029fba93feb4096 |

The complete LF tuple totals **574,987 bytes**; the complete CRLF tuple totals **587,449 bytes**. These are two whole-tuple alternatives, not six independently selectable per-file alternatives. Arbitrary text conversion, mixed LF/CRLF within a file, cross-file mixing, partial A4 substitutions, or bytes accepted solely because a producer reports them remain ineligible for v4.

The three changed identities relative to both frozen v3 alternatives are backend/src/app.js, backend/src/publicListeningFrontend.js and backend/test/publicListeningFrontend.test.js. Dockerfile, package.json and backend.test.js retain their v3 identities. The Git sources are already accepted Security A4 inputs under [Issue #104 A7](https://github.com/k-undurkhaan-2/IELTS-Project/issues/104#issuecomment-6529041606) and [Issue #79 A7](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-6539468720); A8 proposes their new portable-result applicability without changing them.

A platform label does not select a source variant. Only an exact, independently authenticated protected path/source tuple may select it. Linux LF and Windows CRLF are the observed hosted representations, not permission to infer arbitrary bytes from an operating-system label.


## Separate v4 selection and binding

Preserve public historical constants `VERSION = 2` and `TEST_COUNT = 141`, the v2 914-path contract, v2 digest/result representation, every v3 LF/CRLF profile, v3 148+6 grammar, v3 digest/result representation and their protected negatives.

The existing selector first demands a single descriptor for a path profile. Simply appending a second 916-path descriptor would reject both v3 and v4 as ambiguous. Replace only that decision with a bounded two-stage lookup: select the protected path family, then match the whole protected source tuple against the disjoint frozen v3 and v4 alternatives. The unchanged 914-path v2 path keeps its existing behavior. The 916-path family must yield exactly one immutable (protocol, variant, source tuple) selection; zero or multiple matches reject.

No reporter bytes, counts, environment/branch labels, claimed version, parser probing or fallback may select a protocol. Producer and independently prepared expected targets must select the same value. A selected parser's failure is final. Preserve existing v3 negative classifications where currently tested, including its 62 mixed LF/CRLF tuples; only the two explicitly new complete source tuples gain v4 applicability.

The v4 protocol binding uses these exact fields, without adding keys to v2/v3 serialized bindings:

~~~yaml
schema: BackendCanonicalPortableResult
version: 4
digestDomain: ieltmps-backend-canonical-portable-result-v4
pathProfile:
  trackedPaths: 916
  serializedUtf8Bytes: 40530
  sortedPathSha256: 5b9401b4afa1b964ebd2887ec023c247a605d4faad6532de6cc168720f70c786
hierarchyInventoryDigest: 55d5faeaf78bdd5ef3968cae114ea479a088eef64550f2db716b6b23840ded9d
topLevelMembers: 150
nestedMembers: 16
totalExecutedMembers: 166
parentTopLevelOrdinals: [143, 144, 146, 149]
nestedMembersByParent: [2, 2, 6, 6]
diagnosticLineCount: 2
durationSpans: 167
retainedSegments: 168
reporterCounts:
  tests: 166
  suites: 0
  pass: 166
  fail: 0
  cancelled: 0
  skipped: 0
  todo: 0
sourceTuple:
  variant: EXACT_LF_OR_CRLF_SELECTION
  totalBytes: EXACT_574987_OR_587449_FOR_SELECTED_VARIANT
  sources: EXACT_ORDERED_SIX_PATH_SIZE_SHA256_ROWS_ABOVE
~~~

The uppercase sourceTuple values describe substitution from the selected frozen rows; they are not literal wire strings. Bind totalBytes by protocol **and** variant, avoiding the current v3-only LF/CRLF lookup. Register only known immutable selections. A caller-created descriptor or a partially modified protocol binding rejects.

Retain the existing result fields for command, orderedTests, reporterCounts, package and its byte digest, lifecycle, tools, exitCode, stdoutNonDurationSegmentsHex, empty-stderr identity, portableAuthorityDigest, portableInputBundleDigest and dependencyClosureDigest. For v4 include its complete protocol binding, as v3 already does for v3. Compute v4 identity through the existing canonical codec with a frame whose digestDomain is `ieltmps-backend-canonical-portable-result-v4` and resultUtf8 is the strict UTF-8 canonical JSON bytes of the complete value. Preserve byte framing so Unicode cannot be folded by a general codec. Never send v4 through a v2/v3 identity function.

Keep the four existing module entry points and runner interface unchanged. The runner already cross-binds and leases the module, validates ordinary producer snapshots, executes a fresh verifier, rechecks source/context/evidence/cleanup, and only then permits parsing and detached comparison. Preserve _bind_producer, _bind_replay, _derive_equal_result and _comparison_views authority boundaries. Retained producer claims alone never grant execution or result acceptance.

## Exact current reporter contract


Both retained producers report the same 150 ordered top-level members and 16 ordered nested members, all successful, with 166 tests and passes. There are **four** parent groups:

| Zero-based parent ordinal | One-based position | Exact parent name | Children |
| ---: | ---: | --- | ---: |
| 143 | 144 | nested private Listening routes reject roots and ancestors outside the top-level mount | 2 |
| 144 | 145 | generated dependency dot aliases cannot serve unverified static bytes | 2 |
| 146 | 147 | public Listening loader rejects Locator, Manifest, Payload and inventory corruption | 6 |
| 149 | 150 | production readiness fails closed and production rejects fixture or root overrides | 6 |

The historical v3 corruption parent was ordinal 144; in the current contract it is ordinal 146. The final existing top-level production-readiness test now has six children. The two new top-level members occupy ordinals 143 and 144. All old top-level names retain their relative order.

The complete ordered inventory is frozen below. Ordinals are zero-based. Every listed top-level member and child has status `pass`; every other member, status, child association or ordering rejects. The first 143 top-level names exactly match declarations in [backend.test.js](https://github.com/k-undurkhaan-2/IELTS-Project/blob/751ab5aceeba90f8eca0058d5f6a289d3a2971e1/backend/test/backend.test.js); the last seven match [publicListeningFrontend.test.js](https://github.com/k-undurkhaan-2/IELTS-Project/blob/751ab5aceeba90f8eca0058d5f6a289d3a2971e1/backend/test/publicListeningFrontend.test.js#L432). Its explicit scenario order, two dependency constants, six named corruption tests and three ordered readiness calls establish every child name and parent relationship independently of reporter selection.

| Zero-based top-level ordinal | Exact name | Child count |
| ---: | --- | ---: |
| 0 | Docker COPY and ADD parser rejects private roots across equivalent forms | 0 |
| 1 | docker image hardening excludes secrets and runs app as non-root | 0 |
| 2 | production app rejects missing or placeholder session secrets | 0 |
| 3 | production app rejects weak TOTP encryption keys | 0 |
| 4 | production app rejects missing auth handoff public URLs at construction | 0 |
| 5 | production app validates public URL modes, handoff secrets, and trusted proxy config at construction | 0 |
| 6 | real production process dominates caller nodeEnv in integrated createApp security controls | 0 |
| 7 | auth registration rejects weak and duplicate credentials | 0 |
| 8 | auth write endpoints require a valid CSRF token | 0 |
| 9 | auth CSRF endpoint is rate limited to prevent session store flooding | 0 |
| 10 | rate limiter bounds tracked keys | 0 |
| 11 | rate limiter hashes oversized keys before tracking attempts | 0 |
| 12 | login, logout, and authenticated practice API access | 0 |
| 13 | authenticated APIs require the session verifier companion cookie | 0 |
| 14 | authenticated APIs require an active server-side auth session registry entry | 0 |
| 15 | business account session API lists safe metadata and revokes other sessions | 0 |
| 16 | admin session API lists target sessions and revokes copied user sessions | 0 |
| 17 | security epoch invalidates copied full cookie jars after account security changes | 0 |
| 18 | auth session registry rejects copied sessions on the wrong onion audience | 0 |
| 19 | TOTP verification rotates the session verifier for copied cookie jars | 0 |
| 20 | sensitive API responses are not cacheable | 0 |
| 21 | malformed JSON bodies return a stable validation error | 0 |
| 22 | oversized JSON bodies return a stable payload error | 0 |
| 23 | logout clears secure session cookies with matching attributes | 0 |
| 24 | production public URL policy controls session and handoff cookie Secure attributes | 0 |
| 25 | direct app always hides retired legacy account APIs | 0 |
| 26 | login performs a dummy password check for unknown users | 0 |
| 27 | password comparisons reject input beyond bcrypt byte limit | 0 |
| 28 | legacy direct account mutations stay retired | 0 |
| 29 | retired legacy account mutation routes do not revoke active sessions | 0 |
| 30 | retired legacy account routes are hidden before sensitive checks run | 0 |
| 31 | authenticated APIs refresh stale session users before trusting them | 0 |
| 32 | pending TOTP sessions refresh stale users before trusting them | 0 |
| 33 | legacy self-delete route is retired and preserves account data | 0 |
| 34 | legacy admin self-delete route is retired before last-admin checks | 0 |
| 35 | Auth stores refuse direct last-admin deletion | 0 |
| 36 | auth login rate limit returns 429 after repeated attempts | 0 |
| 37 | auth login rate limit applies across usernames from one IP | 0 |
| 38 | auth registration rate limit applies across usernames from one IP | 0 |
| 39 | auth and CSRF rate limits ignore X-Forwarded-For from untrusted clients | 0 |
| 40 | TOTP rate limits ignore X-Forwarded-For from untrusted clients | 0 |
| 41 | TOTP setup requires auth, CSRF, and returns recovery codes once | 0 |
| 42 | TOTP setup rejects legacy plaintext pending secrets in sessions | 0 |
| 43 | enabling TOTP revokes other active sessions for the same user | 0 |
| 44 | TOTP login requires a second factor before full session access | 0 |
| 45 | TOTP login treats corrupted stored secrets as invalid codes | 0 |
| 46 | invalid TOTP codes do not trigger recovery code bcrypt checks | 0 |
| 47 | TOTP setup code cannot be reused as a login code | 0 |
| 48 | TOTP login rejects replayed current time-step tokens | 0 |
| 49 | TOTP pending setup and login expire before verification | 0 |
| 50 | TOTP recovery codes are one-time and can be regenerated | 0 |
| 51 | Postgres TOTP recovery code consumption requires an unused row update | 0 |
| 52 | Postgres TOTP time-step consumption rejects stale updates | 0 |
| 53 | ordinary users can disable TOTP through scoped auth action state | 0 |
| 54 | admin users cannot disable TOTP through business scoped auth action state | 0 |
| 55 | managed TOTP disable revokes other active sessions for the same user | 0 |
| 56 | removed passkey API returns 404 | 0 |
| 57 | practice API requires authentication | 0 |
| 58 | ordinary practice sync preserves unseen history without exporting it | 0 |
| 59 | copied authenticated session cannot export through sync or destructive routes | 0 |
| 60 | practice sync merges concurrent mutations and rejects identity collisions atomically | 0 |
| 61 | Postgres practice sync locks before reading and only writes merged changes | 0 |
| 62 | Postgres practice import supports valid session moves without intermediate uniqueness conflicts | 0 |
| 63 | Postgres partial merge preserves persisted ordering after deleting the first slot (P2 reproducer) | 0 |
| 64 | Postgres partial merge preserves an updated slot after a middle deletion | 0 |
| 65 | Postgres partial merge keeps session replacements in their persisted logical slot | 0 |
| 66 | Postgres partial import appends several new records after the persisted maximum | 0 |
| 67 | Postgres partial merge rejects identity conflicts without changing records or order | 0 |
| 68 | Postgres partial merge guards integer exhaustion before any record mutation | 0 |
| 69 | Postgres partial import preserves logical slots when an old ID is reused after session moves | 0 |
| 70 | Postgres partial merge serializes same-user appends without duplicate order keys | 0 |
| 71 | practice destructive data management requires data step-up bound to the business browser | 0 |
| 72 | practice import deduplicates by id and non-empty sessionId | 0 |
| 73 | PUT practice records replaces the list returned by GET | 0 |
| 74 | PUT practice records deduplicates duplicate session ids before storing | 0 |
| 75 | admin API rejects anonymous and non-admin users | 0 |
| 76 | site content API requires admin TOTP for writes and publishes sanitized public content | 0 |
| 77 | site content UI renders with text nodes and admin edit controls | 0 |
| 78 | admin dashboard redirects anonymous users through auth handoff | 0 |
| 79 | retired legacy admin login html is hidden from authenticated admin static access | 0 |
| 80 | admin shell and business account menu do not link back through the business home | 0 |
| 81 | business settings password and TOTP actions require scoped auth state | 0 |
| 82 | auth handoff creates a one-time business session ticket | 0 |
| 83 | auth logout handoff clears the shared auth session before returning to the target entry | 0 |
| 84 | auth handoff ignores poisoned forwarded hosts and validates canonical start hosts | 0 |
| 85 | auth handoff allows local-development relative redirects without public URLs | 0 |
| 86 | auth login binds signed handoff state to an audience-specific entry | 0 |
| 87 | auth audience login pages require a handoff state before showing credential forms | 0 |
| 88 | auth generic login page requires a handoff state before showing credential forms | 0 |
| 89 | auth audience login pages hide credentials for mismatched handoff state | 0 |
| 90 | auth login page lets admin flow switch away from an existing learner auth session | 0 |
| 91 | auth login page does not redeem admin handoff after learner credentials | 0 |
| 92 | auth login page lets business flow switch away from an existing admin auth session | 0 |
| 93 | auth login session conflict restart logs out and returns to the same flow | 0 |
| 94 | auth API enforces account type for signed business and admin flows | 0 |
| 95 | auth proxy rejects no-state login and registration mutations | 0 |
| 96 | auth complete JSON mode returns redirect payloads and structured errors | 0 |
| 97 | auth handoff rejects unsafe return paths and audience mismatches | 0 |
| 98 | auth callback uses proxy audience headers to rescue misdirected tickets | 0 |
| 99 | auth handoff rejects expired tickets | 0 |
| 100 | admin auth handoff requires admin role and TOTP verification | 0 |
| 101 | admin auth handoff preserves existing TOTP freshness without extending it | 0 |
| 102 | practice API rejects unsafe record identifiers and oversized batches | 0 |
| 103 | practice record import cannot grow beyond the batch record cap | 0 |
| 104 | practice record normalization rejects circular payloads without overflowing the stack | 0 |
| 105 | practice record normalization and memory store do not expose mutable payload aliases | 0 |
| 106 | practice record normalization rejects non-JSON payload values before serialization | 0 |
| 107 | practice record normalization clamps numeric statistics | 0 |
| 108 | practice record metadata truncation preserves valid Unicode | 0 |
| 109 | admin record serialization redacts sensitive payload fields | 0 |
| 110 | admin record serialization preserves shared references while still detecting cycles | 0 |
| 111 | admin record serialization caps display payload text and normalizes scalar fields | 0 |
| 112 | admin can list users, inspect records, and delete one record | 0 |
| 113 | admin sensitive mutations are rate limited | 0 |
| 114 | admin mutation rate limits ignore X-Forwarded-For from untrusted clients | 0 |
| 115 | admin API does not expose internal error messages | 0 |
| 116 | admin routes require TOTP verification in the current session | 0 |
| 117 | admin TOTP verification expires and can be renewed in-session | 0 |
| 118 | admin sensitive mutations require recent password step-up | 0 |
| 119 | admin account center and user-list sensitive reads require recent password step-up | 0 |
| 120 | admin exports require one-time password step-up tokens | 0 |
| 121 | admin mutations rotate the session verifier for copied cookie jars | 0 |
| 122 | admin can manage users and inspect learning and traffic stats | 0 |
| 123 | PostgresAdminStore refuses last-admin demotion inside a locked transaction | 0 |
| 124 | MemoryAdminStore refuses direct last-admin demotion and deletion | 0 |
| 125 | PostgresAdminStore deletes sessions and users inside a locked transaction | 0 |
| 126 | admin user deletion clears target TOTP state in memory store | 0 |
| 127 | memory admin session deletion skips oversized serialized sessions | 0 |
| 128 | memory auth session deletion skips oversized serialized sessions | 0 |
| 129 | admin search query normalization preserves valid Unicode | 0 |
| 130 | traffic middleware minimizes untrusted request metadata | 0 |
| 131 | traffic visitor hashing ignores raw user-agent entropy | 0 |
| 132 | traffic middleware rejects weak hashing secrets in production | 0 |
| 133 | Postgres traffic recent events respect the selected day window | 0 |
| 134 | memory traffic store caps retained events | 0 |
| 135 | admin user changes invalidate target sessions and stale admin roles | 0 |
| 136 | admin web routes reject self password changes | 0 |
| 137 | retired legacy admin account mutations preserve current TOTP verification | 0 |
| 138 | migration runner serializes migrations with a PostgreSQL advisory lock | 0 |
| 139 | migration runner releases the advisory lock after migration failure | 0 |
| 140 | bootstrap admin creates and updates an admin user | 0 |
| 141 | static hosting serves index and denies dotfiles with security headers | 0 |
| 142 | static boundary rechecks optional roots created after an initial miss | 0 |
| 143 | nested private Listening routes reject roots and ancestors outside the top-level mount | 2 |
| 144 | generated dependency dot aliases cannot serve unverified static bytes | 2 |
| 145 | public Listening loader verifies its exact synthetic inventory and serves only retained bytes | 0 |
| 146 | public Listening loader rejects Locator, Manifest, Payload and inventory corruption | 6 |
| 147 | public Listening loader rejects symlinked Payload entries and path escape | 0 |
| 148 | authenticated A2 public routes enforce allowlists, CSP separation and private containment | 0 |
| 149 | production readiness fails closed and production rejects fixture or root overrides | 6 |

| Parent ordinal | Child ordinal | Exact child name |
| ---: | ---: | --- |
| 143 | 0 | nested-root |
| 143 | 1 | intermediate-ancestor |
| 144 | 0 | assets/generated/listening-exams/manifest.js |
| 144 | 1 | assets/generated/listening-exams/listening-index.compat.js |
| 146 | 0 | strict active locator schema |
| 146 | 1 | Manifest bytes and digest |
| 146 | 2 | same-length Manifest corruption is rejected by SHA-256 |
| 146 | 3 | per-file Payload checksum |
| 146 | 4 | unexpected Payload file |
| 146 | 5 | image-root-only dependency checksum |
| 149 | 0 | node-env-backstop: assets/generated/listening-exams/manifest.js |
| 149 | 1 | node-env-backstop: assets/generated/listening-exams/listening-index.compat.js |
| 149 | 2 | missing: assets/generated/listening-exams/manifest.js |
| 149 | 3 | missing: assets/generated/listening-exams/listening-index.compat.js |
| 149 | 4 | corrupted: assets/generated/listening-exams/manifest.js |
| 149 | 5 | corrupted: assets/generated/listening-exams/listening-index.compat.js |

Exactly these two diagnostic lines occur, respectively after child 0 and child 1 of parent 143, before the next completion or the parent completion:

~~~text
  ℹ {"scenario":"nested-root","authenticatedStatus":403,"outsideMarkerReturned":false}
  ℹ {"scenario":"intermediate-ancestor","authenticatedStatus":403,"outsideMarkerReturned":false}
~~~

These are exact UTF-8 lines with two leading spaces. Key order, punctuation, values, indentation and placement are fixed by the successful source assertions at [publicListeningFrontend.test.js lines 469 onward](https://github.com/k-undurkhaan-2/IELTS-Project/blob/751ab5aceeba90f8eca0058d5f6a289d3a2971e1/backend/test/publicListeningFrontend.test.js#L469). They are retained byte evidence; do not parse and reserialize their JSON, strip them, normalize the 403, or admit arbitrary diagnostic output.

The stdout grammar is:

1. Zero or one initial empty line, followed by `> ielts-practice-backend@0.1.0 test`, `> node --test` and one empty line. Bind package name, version and test lifecycle to the independently authenticated package bytes.
2. For each flat member, exactly `✔ NAME (Dms)`. For each parent, exactly `▶ NAME`, its ordered child completions `  ✔ CHILD (Dms)` with the two prescribed diagnostics where applicable, then exactly `✔ NAME (Dms)`. A heading is not an execution.
3. Exactly the ordered footer `ℹ tests 166`, `ℹ suites 0`, `ℹ pass 166`, `ℹ fail 0`, `ℹ cancelled 0`, `ℹ skipped 0`, `ℹ todo 0`, then `ℹ duration_ms D`. There is one terminal newline and no extra output.
4. Every line must terminate with LF or CRLF; reject embedded/bare CR, invalid UTF-8, forbidden controls, incomplete lines and oversized streams. Retain the existing 2-MiB stream, 2,048-line and 2,048-byte per-line bounds. Exact line endings, optional initial blank presence and all Unicode bytes remain identity-significant.
5. Only the numeric D spans may be omitted: exactly 166 terminal completion durations plus one final duration, **167 spans and 168 retained segments**. D must fully match `[0-9]{1,16}(?:\.[0-9]{1,16})?`. No signs, exponents, NaN, whitespace or unbounded numbers. Keep units, parentheses, names, all other numbers, diagnostics and every gap byte.
6. There are 183 lines without the optional initial blank and 184 with it. Both captured reports have 184 LF-terminated lines. This follows from 166 completions + four headings + two diagnostics + three banner lines + eight footer lines + one initial blank.
7. Stderr is exactly empty, the command exits 0, and existing completed-execution, containment, protected-input and fresh-replay checks must already have passed. Reported success alone never establishes verifier acceptance.

The normative inventory object uses schema `BackendCanonicalPortableHierarchyInventory`, version 4, ordinalBase 0, topLevelMembers 150, nestedMembers 16, totalExecutedMembers 166, orderedTests and diagnosticLines. orderedTests contains the rows above as ordered objects with name and status; only the four parents also have ordered children objects with name and status. diagnosticLines is the ordered two-object list with keys topLevelOrdinal=143, childOrdinal=0 or 1, position=`after-child-completion`, and utf8 equal to the exact corresponding line.

Its SHA-256 is **`55d5faeaf78bdd5ef3968cae114ea479a088eef64550f2db716b6b23840ded9d`**, computed over UTF-8 `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)` with no terminal newline. This newly defined v4 inventory identity does not reinterpret either historical inventory digest.

Ubuntu stdout is 14,588 bytes, SHA-256 `b522cbb8d361a4e981b1e260e0e3b2b03ab5a6680dd4fa10090d946059fb65a7`. Windows stdout is 14,273 bytes, SHA-256 `7083d4cb8c424b6eebab0178796c9dedccc0ec545b2e8d55d4a333781125bc01`. Their ordered inventories and 168 retained non-duration segments are equal. Their complete protocol bindings need not be equal across operating systems: each producer must match its own independently executed verifier, including its source variant and tool/runtime authority.



### Source admission and local candidate identity

The four-file Security adaptation freezes the final portable module, its independent tests and this document in `_R2_A8_SECURITY_CONTENT_DELTA`, together with one exact sorted path/mode/type/object manifest. The only object sentinel remains `developer/tests/ci/test_ci_foundation.py`; it does not exempt that file's execution bytes from command authority. Historical A1/A3/A4.1/A5/A6/A7 manifests and the A7.1 distinction between authenticated Git objects and measured checkout bytes remain intact. Historical fixture reconstruction restores the old module/test/document and Runtime objects before applying each historical overlay.

An uncommitted candidate is measured separately from accepted HEAD. Precommit source-admission validation must use an independently fixed prospective inventory and measured byte fixtures, without staging or presenting the worktree as accepted Git history. A standalone filtered hash cannot establish a future Index blob. Any later staging transaction must independently read its actual Index blobs and tree.

### Required rejection and compatibility controls

The union of the six per-file v3/v4 LF/CRLF alternatives has 512 assignments. Exactly four complete tuples are valid. Reject every partial old/current replacement, all 62 mixed LF/CRLF tuples for either protocol, within-file mixed newlines, substituted length or hash, missing/duplicated/extra path and same-count path replacement. Source metadata, stdout and OS labels cannot select a version. Unknown, ambiguous, forged or disagreeing bindings reject without parser probing or fallback.

Require the exact 150+16 hierarchy and diagnostic placements. Reject missing, duplicate, renamed, reordered or reparented members, changed statuses, misplaced headings or completions, diagnostic JSON/value/spacing changes, missing or extra banner/footer/stream material, malformed duration numbers, nonempty stderr, unsafe streams and partial consumption. Only the 167 bounded numeric duration spans may vary; every one of the other 168 segments remains identity-significant.

Both complete streams must parse before either identity is computed. Preserve the held-module outer path, independent source/package/tool/runtime/input authority, exact observations, repeated snapshots, context checks, containment and cleanup. Rejection retains raw differences and produces no detached portable acceptance. Attach a result only after all outer checks and complete producer/replay value equality. Preserve ordinary static/all counts 677/705, Security 679/707, and the fixed 33,554,432-byte command-results ceiling.
