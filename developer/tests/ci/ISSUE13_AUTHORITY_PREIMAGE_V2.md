# Issue #13 authority-preimage capture v2 — local candidate

This candidate extends the terminal diagnostic observer on parent `ddf1e597`
only to retain the authority preimages missing from the accepted offline
authority-resolution transaction and to include Windows standalone-packaging
ordinal 702. It makes no portability contract, adapter, reporter normalization,
ordinary verification, workflow, or PR #12 change. Historical evidence is not
reconstructed again. No acquisition or hosted execution is part of validation.

The existing terminal CLI flags enable capture after ordinary processing and
cleanup. The observer uses detached values from the completed runner; it does not
measure replacement target identities or reconstruct compact execution inputs.
The helper's LF and CRLF SHA-256 pins are the only change to the ordinary runner.

## Private values and production digest binding

`Issue13PrivatePreimages` version **2** retains its previous fields and adds:

- `expectedAuthority`: the complete original command-plan record, including the
  complete ordered `targets` array and all nested filesystem identity fields;
- `commandRecord`: the complete original command record, including ordered
  `executionInputs`, raw `executionInputBundleDigest`, `protectedTargetBundle`,
  held pre/post identities, containment/cleanup facts and ordinary observations;
- `captureBinding`: transaction, producer/fresh-replay phase, platform, profile,
  candidate commit/tree from the completed runner's execution binding, command
  ordinal/ID, command-record and expected-authority digests, targets digest, raw
  input-bundle digest, and input-context digest.

The selected command record and expected authority must agree exactly, including
physical fields. Each target has the production seven-key target schema, with
the five-key stable identity. Each input has the production eight-key input
schema, with the five-key planned stable identity. All values remain available
for independent enumeration and evaluation using the unchanged PR #12 code.
Capture itself never calls the portable projection or treats a projection as
authority. Its old portable plan comparison is replaced with exact raw equality.

The accepted transaction established that the recorded input-context field is a
**hash of a digest string**. With `D(v) = canonical_failure_digest(v)`, the exact
production chains are:

```text
D(private.expectedAuthority.targets)
    == public.authorityFieldDigests.targets

execution_input_bundle_digest(private.commandRecord.executionInputs)
    == D(private.commandRecord.executionInputs)
    == private.commandRecord.executionInputBundleDigest

D(private.commandRecord.executionInputBundleDigest)
    == public.contextFieldDigests.executionInputBundleDigest

D(private.commandRecord) == public.commandRecordDigest
D(private.expectedAuthority) == public.expectedAuthorityDigest
```

`D` uses the existing production `_canonical_frame` type/length framing, text
handling and array order. It is not a newly invented canonical-JSON hash.
Hashing the input array directly cannot equal the existing outer context field;
both levels are preserved and checked without redefining that field. Additional
SHA-256 hashes of the exact private JSON serialization bind original string
spellings as well, without changing the production digest codec.

All chains, schema shapes, exact target/input correspondence, duplicate logical
identities (including collisions under the existing production text codec), and
ordering are checked before record files are written. Missing, compact, partial,
malformed, oversized or inconsistent structures fail closed. The unchanged raw
command validator checks the retained full bundle and local identity evidence.
Its failure does not change any ordinary command or decision.

The private reader verifies the chains again against public rows and pairing
context. The encrypted transport independently checks its frozen byte snapshot,
including candidate commit/tree against transport source identity, before making
the existing in-memory tar/gzip bundle. Capture errors or incomplete required
membership prevent export. The original OpenPGP recipient, public-only keyring,
runtime validation, encryption, ciphertext-only export and privacy boundaries
remain unchanged.

## Selection and public additions

The original frontend selector remains in place. Windows packaging is now
selected as well. An `all` capture requires these identified records:

| Platform | Required ordinals |
| --- | --- |
| Ubuntu | frontend-security 687 and 695; backend-canonical 701; standalone-packaging 702 |
| Windows | frontend-security 687, 692 and 695; backend-canonical 701; standalone-packaging 702 |

Membership binds ordinal, fixed family and exact command-ID SHA-256 together.
The selection must be unique and in original ordinal order. More than eight
selected records fails capture instead of truncating the selection. A missing
required record, missing exact raw stream, or failed preimage prevents a complete
export. Ubuntu packaging is retained without additional normalization analysis.

`Issue13DiagnosticCapture` version **2** adds one `authorityPreimages` object per
row. Its exact-key schema permits only a fixed schema label, binding SHA-256,
presence booleans, command-record byte count, and target/input metadata. Each
target/input metadata object contains presence, entry count, recursive property
count, JSON byte count, JSON SHA-256, and production digest. Property counts include
the composite identity property and its five children (12 per target and 13 per
input). Existing authority/context digest meanings remain unchanged.

No target path, file identity, raw target/input array, raw stream, private command
value, or new free-text field is permitted in these public additions. The exact
private record's SHA-256 and byte count remain in the public row. Full stdout and
stderr remain separate private `.bin` files.

## Limits and maximum size impact

| Resource | v2 ceiling |
| --- | --- |
| Targets / execution inputs per selected command | 2,048 each, nonempty and equal counts |
| Structured target array | 1 MiB |
| Structured execution-input array | 2 MiB |
| Complete expected authority | 2 MiB |
| Complete command record | 6 MiB |
| Whole private record JSON | 8 MiB (v1: 2 MiB; maximum per-file increase: 6 MiB) |
| Each exact stdout / stderr | 2 MiB, unchanged |
| Public capture JSON | 256 KiB, unchanged |
| Selected records / capture files | 8 / 25, unchanged |
| Total capture files | 48.25 MiB = 50,593,792 bytes, unchanged |
| Plaintext tar/gzip bound | 49 MiB, unchanged |
| Ciphertext bound | 50 MiB, unchanged |

The per-value budgets share the whole-record and aggregate limits; their maxima
cannot all be consumed simultaneously. The writer reserves the public-file
budget before writing each row. The reader and frozen transport snapshot also
enforce the aggregate cap. Capture JSON has a 400,000-node and depth-16 bound;
full-record floating-point values must be finite and bounded. Authority schemas
reject floats or booleans where integer byte counts are required.

## Focused local verification

The capture tests use completed in-memory command fixtures on this Windows host,
including explicitly labelled Ubuntu/Windows contexts and a 920-entry full
bundle. They execute no repository profile, packaging command, hosted job, or
full 476-test suite. Separate reviewer-side tests apply existing projections to
synthetic retained values; capture and reader tests install failure sentinels on
every relevant projection/reconstruction entry point.

The focused matrix includes production digest rebinding in both phases/platforms,
target/input order and mode/reparse/content mutations, physical-field retention,
malformed/partial/duplicate structures, public/private separation, record and
aggregate limits, full Windows selection with ordinal 702, exact private streams
and cleanup, frozen transport rebinding, archive round trips, and static source
isolation. Exact non-interference compares eight separately serialized components
across 48 family/phase/PASS-or-REJECT/capture-mode cases. A further 20 actual CLI
control cases compare ordinary exit codes and stdout/stderr, excluding only the
fixed diagnostic status line. Ordinary execution and evidence writes in those
CLI tests are already-completed mocks; the real terminal observer is exercised.

Run the focused capture/transport tests and `git diff --check` only. The final
local report records the executed tests, skips, component equality checks, signed
commit, tree, parent and file list.

This is a reviewable local candidate. Existing acquisition workflows and their
historical source/branch pins remain unchanged and do not authorize this new
candidate for acquisition. Publishing, adapting acquisition pins, dispatching,
and gathering new execution evidence require a subsequent explicit request.

## Source/context contract amendment checkpoint A

Checkpoint A adds the explicit `--source-profile issue13-authority-preimage-v2`
option to the existing transport entry points. Omitting the option selects
`legacy`. Both historical context/source validator bodies, constants, path sets,
and source pins remain unchanged. The new profile does not select itself based
on an environment variable or a branch name. Historical workflows cannot accept
v2 by falling through to this profile.

The v2 profile accepts only a future checkpoint B with exactly these two edges:

```text
06b66c51e509c9567b881d671210074e7d78c156 -> A -> B
```

The fixed anchor tree is `c037d1d5009f662b24330564c3c2736348479ea9`.
Both A and B must have exactly one parent. A's own SHA is deliberately absent
from this contract: A must be separately reviewed and signed before B is allowed.
Checking ancestry alone, extra descendants, merges, and workflow-supplied parent
or source manifests cannot satisfy the contract.

The exact A diff is six modified existing files, with no added, removed, renamed,
duplicated, or extra paths:

- `developer/tests/ci/ISSUE13_AUTHORITY_PREIMAGE_V2.md`
- `developer/tests/ci/issue13_acquisition_transport.py`
- `developer/tests/ci/issue13_windows_transport_recovery.py`
- `developer/tests/ci/test_issue13_acquisition_transport.py`
- `developer/tests/ci/test_issue13_diagnostic_capture.py`
- `developer/tests/ci/test_issue13_windows_transport_recovery.py`

The capture-test amendment only permits the preflight's explicit context/source
dispatch in its static source comparison; the remainder of that comparison and
the capture behavior tests are unchanged. Runtime provisioning, encryption,
capture, replay, authorization, and ordinary result handling do not change.

B must add exactly `.github/workflows/issue-13-authority-preimage-v2.yml`, as a
regular non-executable file. No other B tree change is accepted. Consequently
every other committed source and input, including paths outside the explicit
checkout inventory, remains identical to A. The bounded source inventory also
checks the B and A Git blob bytes/modes, original anchor bytes for unamended
sources, five explicit SHA-256 pins for capture/runner/reporter/certificate/runtime
inputs, and current checkout bytes using the unchanged historical checkout-byte
allowance. Git object IDs are rebound to blob bytes. Malformed metadata, missing
objects, inconsistent order, mode changes, or a moved HEAD fail closed.

The exact v2 branch is `refs/heads/codex/issue-13-authority-preimage-v2`. Contexts
require the existing repository, a push, run attempt 1, a valid candidate SHA/run
ID, and the correct platform/job/phase. Ubuntu configure/export use the base
transport. Windows preflight/export use the reviewed pinned-runtime transport;
the Ubuntu v2 entry point rejects Windows jobs. Producer and replay derive the
same transaction from B's SHA, run ID, and their platform. The two platform
transactions differ. Each Windows job still performs its own preflight and
revalidates the runtime before export.

Checkpoint A contains no acquisition workflow or execution authorization. The
future B workflow must independently enforce branch creation, diagnostic-ready
dependencies, and artifact privacy when it is separately requested and reviewed.
Synthetic B tests supply in-memory Git metadata and source blobs; they create
neither B commits nor workflow files and execute no hosted or ordinary workload.
