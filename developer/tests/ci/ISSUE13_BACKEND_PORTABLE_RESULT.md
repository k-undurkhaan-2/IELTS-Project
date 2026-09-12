# Issue 13: verified backend portable result

This local remediation is based on frozen commit
`75a4c7532b036202ab7a283242beb7079da62b00`. The blocked candidate
`b241be9ab0474160893060dc1de5b42e59498fd9` supplies the reviewed reporter grammar
as a semantic reference; it is not the branch base.

`BackendCanonicalPortableResult` is an optional comparison of the successful
128-test backend npm reporter. It becomes available only inside
`verify_evidence_with_replay`, after raw evidence, producer and fresh replay
bindings, and replay eligibility have succeeded. It never authorizes execution.

## Public boundary

Only the outer API accepts an external `backend_result_evidence` argument:

```python
verify_evidence_with_replay(
    output_dir=OUTPUT_DIR, *, expected_context, verification_runner,
    repo_root=REPO_ROOT, evidence_authority_root=None,
    backend_result_evidence=None,
)
```

Its optional argument is a dictionary containing `producer` and optionally
`replay`. Each value is `BackendCanonicalReplayEvidence`, with a full command
record, full expected authority, original stdout/stderr bytes, package.json
bytes, runtime, runtime closure, and runtime guard. A compact wire record is
not a replacement for the retained full preimage. Missing streams are never
reconstructed from previews or normalized observations.

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
path without the optional argument still calls public `run_verification_replay`.

## Binding before derivation

The optional outer path executes these steps in order:

1. Validate the exact five-file set, safe bounded reads, document schemas,
   raw records, semantic claims, and external context using the existing validator.
2. Read replay snapshots and validate those exact documents and snapshots again.
   This closes the interval between the original validation and replay read.
   Recheck directory membership and require a PASS summary before binding.
3. Create a private producer context. Match its full preimage exactly to the
   actual wire record or the existing validated compact representation. Bind
   command, ordinal, class, role, required/profile/platform, argv, independent
   command plan, runtime/dependency/tool/guard, protected targets and inputs,
   stdout/stderr hash/length/bytes, and raw observation/set/universe/transcript
   aggregates. Independently compare the portable authority projection.
4. Execute the externally selected runner once, retaining its existing
   `finally` cleanup behavior.
5. Recheck the producer context and bind the replay to exactly one fresh command
   result, independent plan member, and actual `CommandCapture`. An explicitly
   supplied replay must equal these fresh facts, including exact raw capture
   bytes. Require no stdin lease for this protected-bundle backend command.
   Bind the capture's measured execution fields to the command record;
   validate fresh runtime/dependency/tool/guard, protected inputs, execution
   state, and hard gates. Compare both sides' bound non-reporter inputs,
   including npm hash, size, and version, before parsing. Self-consistent
   producer authority cannot substitute for independently measured fresh
   authority. Recompute the plan digest from the actual plan.
6. Check all unrelated replay comparisons using private eligibility views.
   Those views defer only backend stdout hash/length and its two derived raw
   observation fields. Every other field and every other command remains exact.
   Recompute aggregate comparison views from already validated raw records.
   No backend result, reporter parse, or result identity exists at this step.
7. Validate the existing replay authorization/cleanup requirements. Rebuild the
   outer external context and recheck evidence identities, bytes, and membership.
   Rebind both sides again and require equality with the earlier bound pair.
8. Derive results from the two immutable bound sides. Parse both complete
   reporters before computing either backend result identity. Require equality
   of both complete result objects and identities.
9. Repeat the complete comparisons with actual portable result views. Attach
   `backendCanonicalPortableResult` only when there are no errors, then derive
   the final replay envelope over the transcript including that result.

Every binding failure has zero backend parser and identity calls. A producer
reporter parse failure has one parser call and zero identity calls; a replay
reporter parse failure has two parser calls and zero identity calls. An identity
mismatch has two parser calls and two identity calls. All of these failures
return no portable field and cannot yield a final PASS. Cleanup, unrelated
comparison, and outer evidence/context failures also precede parsing. A failure
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

The complete `FoundationRunner`, local canonical records/transcripts, producer
writer, compaction, local authority validation, authorization-envelope
constructors, workflows, and frontend-security/standalone-packaging behavior
retain their frozen implementations. Acquisition, capture, and GPG code are not
part of this patch. The raw replay transcript and evidence retain their original
stream hashes and aggregates; comparison views are detached private values.

## Validation

`test_backend_canonical_portable_result.py` exercises the actual outer path with
five files written by the unchanged evidence writer and validated by the real
raw/semantic validators. The synthetic runner provides bounded fresh execution
fixtures; external-context rebuilding is controlled by the test fixture. This
does not claim a hosted replay or a live backend npm execution.

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
python -B developer/tests/ci/test_governance_state.py
python -B developer/tests/ci/test_ci_foundation.py
```

The final foundation acceptance requires all 476 discovered tests to execute
and pass with zero failures, errors, skips, or blocked tests. It uses no cached
PASS receipt. The full-scale fixture retains 705 commands and 16 classes; its
protected source inventory includes the three new files, increasing its exact
target count from 908 to 911 and its reference count from 19,811 to 19,876.
Only those fixture expectations change; the plan builder and fixed size limits
remain unchanged. This transaction ends with one signed, verified local commit and
stops before push, hosted CI, or any PR modification.
