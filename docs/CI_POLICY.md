# Baseline-aware CI policy

## Bootstrap trust boundary — candidate-controlled

Disposition:
`ACCEPTED-INHERENT-LIMITATION-WITH-EXPLICIT-EXTERNAL-REVIEW-BOUNDARY`.

SELF-VALIDATOR TRUST: candidate-controlled

MERGE AUTHORIZATION: not provided by this workflow

INDEPENDENT REVIEW: required for CI trust-file changes

A pull request can modify the workflow, validator, baseline, and validator tests together.
A successful run proves only the behavior of the exact candidate bytes that ran.
Changes to any CI trust file require independent review outside the candidate implementation worktree.
Until CODEOWNERS, required reviewer rules, and branch protection are separately configured and verified, CI success is not sufficient merge authorization.
Even after repository governance is configured, those controls—not this self-validator—provide the external bootstrap boundary.

The CI trust files are:

- `.github/workflows/ci.yml`
- `developer/tests/ci/phase1-ci-baseline.json`
- `developer/tests/ci/run_ci_foundation.py`
- `developer/tests/ci/run_static_suite.py`
- `developer/tests/ci/test_ci_foundation.py`
- `developer/tests/ci/test_standalone_packaging.py`
- `docs/CI_POLICY.md`
- `.gitignore`

.gitignore changes affecting CI evidence must also receive review.

This workflow is a candidate-local policy consistency check and source of
regression evidence. It is not self-authenticating, cannot approve coordinated
changes to its own trust files, and is not a substitute for human or security
review. This document does not assert that CODEOWNERS, required-reviewer rules,
or branch protection currently exist.

## Status and authority

This policy establishes the first GitHub Actions CI foundation after the frozen
Phase 1 engineering checkpoint. It compares current observations with commit
`db743cc625daded38442834731cbf35db024e10f`, tree
`c3f3825ecc4523a6e39da1164df41d6d59e3527a`, and tag
`checkpoint-phase1-20260730`.

Phase 1 is closed. The candidate-local checks identify new regressions and report exact frozen debt;
it does not make the checkpoint green by modifying product code, historical
tests, generated assets, or packaging manifests. CI is not release,
publication, deployment, or production-runtime authority.

The machine-readable record is
`developer/tests/ci/phase1-ci-baseline.json`, document kind
`ieltmps-phase1-ci-baseline-v1`, schema version 1, policy version `1.0.0`.
An internally read-only map in the checked-out candidate runner binds every one of the 26 approved
IDs to its exact collection, category, gate, command class, scope, outcome,
signature set, occurrence ceiling, platforms, checkpoint disposition, target
stage, and security impact. The top-level keys, approved action pins, hard-gate
set, policy version, and ratified counts `4/14/3/2/3` are also exact. Unknown,
missing, duplicate, moved, or changed entries fail schema validation. Baseline
data cannot authorize a hard-gate failure.

That internal map is immutable only during execution of those candidate bytes.
It is not externally immutable against a pull request that changes the runner,
baseline, workflow, tests, and policy together.

## Result classification

Hard gates cover:

- baseline semantic authority and known-debt enforcement;
- repository, Git, tracked-file, and symlink boundaries;
- tracked private-resource exclusion;
- complete high-confidence secret and operational-artifact scanning;
- licence and governance consistency;
- strict workflow self-policy;
- required JavaScript and Python syntax examination;
- bundle manifest and generated-byte parity;
- focused learner runtime execution;
- frontend export, privacy, protected-resource, and server-authority guards;
- the canonical backend authorization, session, TOTP, step-up, and protected-resource suite;
- standalone package integrity and index-to-manifest membership;
- lockfile and trusted-file byte integrity; and
- unknown non-pass fail-closed behavior.

Frozen debt is allowed only when command class, exact test or path scope,
outcome, platform, normalized complete failure identity, and aggregate
occurrence count match one ratified record. Observations are aggregated by
baseline ID, command class, scope, platform, identity, outcome, and signature
before the ceiling is enforced. Two matching observations against a ceiling of
one fail.

Failure identity retains all available test IDs, source paths and line/column
locations, assertion names, expected and observed values, error classes, and
messages. Exact known Node, static-session, and syntax identities are defined
outside the baseline document. A known substring cannot suppress a second
assertion, second failing test, changed location, wrong file, or otherwise
expanded failure set. Unknown or expanded identities fail. A known scope that
executes and passes is reported as `RESOLVED-CANDIDATE`; it is not silently
removed from policy.

No producer-supplied derived field can authorize that classification. Each
observation starts as a baseline-blind raw producer record bound to the exact
command ID and ordinal, observation ordinal and kind, source result/path,
source-output digest, occurrence count, and raw structured fields. Derived or
baseline-authority names such as `signature`, `failureIdentity`,
`structuredFailureSet`, `legacyBaselineComparisonDigest`,
`derivedFailureDigest`, and `currentFullContextDigest` are forbidden recursively
in those raw fields. The parent validates the complete producer set and record
digests, parses the raw facts under fixed semantics, and derives two distinct
values.

`legacyBaselineComparisonDigest` is the frozen-v1 comparison value. For the
three release-only observations it is produced only by
`derive_frozen_v1_release_skip_signature` from the validated raw observation.
That canonicalizer has an immutable schema version and fixed PDF, checklist,
and release-ZIP detail field sets. It normalizes strings to NFC, applies the
fixed repository/path and line-ending normalization, preserves type and array
order, represents every required field as present or absent, rejects duplicate
normalized keys and duplicate array members, and rejects non-finite or
non-JSON types. The final exact-match preimage retains the Phase 1 normalized
JSON-v1 wire representation because its SHA-256 values are already frozen.
Command authority, producer/transcript digests, completed-class sets, verifier
identity, runtime closure, absolute snapshot/task-root paths, timestamps,
durations, and run IDs are not members of that historical preimage. Missing,
expanded, misplaced, or otherwise non-exact material receives a non-baseline
digest and cannot be authorized.

Recognized path roots are normalized before any decoded backslash sequence is
protected as JSON-looking text. `normalize_authorized_path_text` first matches
the longest exact repository or task root at path-component boundaries,
applies conservative Windows security-authorization equivalence or exact POSIX
comparison, replaces the root with `<repo>` or `<task-root>`, normalizes
separators in the relative suffix, and only then applies the closed
`<abs-path>` redaction to other absolute paths. Windows comparison maps only
ASCII `A` through `Z` to their ASCII lowercase counterparts, treats `/` and
`\` as separators, and otherwise requires exact Unicode scalar equality in
every exact component. It never applies Unicode case folding, Unicode-aware
lowercasing, locale comparison, NFC/NFD/NFKC/NFKD, or `ntpath.normcase` before
authority is decided. The local-mode repository identity uses the versioned
`ieltmps-local-repository-identity-v1` projection: Windows resolves the root,
normalizes separators, folds ASCII characters only, preserves every non-ASCII
Unicode scalar exactly, encodes with strict UTF-8, and hashes the
domain-separated projection as `local-root-sha256:<64-hex>`. POSIX preserves
case and Unicode scalars exactly.

This deliberately permits false negatives for some filesystem-equivalent
non-ASCII names so that a distinct path cannot receive repository authority.
A single closed Windows classifier identifies drive, ordinary UNC, extended
UNC, extended drive, Win32 device, GLOBALROOT, Volume GUID, NT device,
NT DOS-device, NT UNC, file-drive URI, file-UNC URI, unsupported absolute
namespace, relative path, and ordinary prose forms before matching. Only
explicitly configured drive, UNC, extended drive/UNC, or file-URI roots may
receive `<repo>` or `<task-root>`. Every other recognized or suspicious
absolute namespace is reduced in full to `<abs-path>` without exposing a
server, share, volume GUID, device name, namespace prefix, or directory.
Ordinary prose containing `repo`, `file:`, or `server/share` is not a path
match, and a near-prefix such as `C:\repo2` cannot match `C:\repo`. File URI
handling uses a strict parser: `file` scheme comparison is ASCII
case-insensitive, percent escapes must be syntactically valid, decoded NUL or
control characters are rejected, userinfo/query/fragment are rejected, and
encoded separators or namespace ambiguity fail closed unless the entire URI
span is a unique authorized path. The matcher does not percent-decode or
reinterpret arbitrary producer text. Segments beginning `repo`, `temp-case`, `new-root`, `back-root`,
`form-root`, `u1234`, `r`, `t`, `n`, `b`, or `f` remain path components.
Decoded text is never passed through `unicode_escape`, `raw_unicode_escape`, or
an equivalent second decoding step. Actual carriage returns, tabs, newlines,
backspaces, form feeds, ANSI/OSC escapes, and bidi controls continue through
the existing terminal-safety policy after root tokenization.

`currentFullContextDigest` is the version-4, type-aware length-framed digest. It
binds command/profile/platform identity, logical and execution argv, cwd and
tool, raw exit/result semantics, execution-input and target identities, the
complete raw observation, parser semantics, derived outcome, the independently
derived legacy comparison digest, the complete ordered failure-member set with
explicit absences, command-local producer-set digest, producer-universe digest,
producer-transcript digest, completed command-class authority, and the
externally derived `authorizationContextBindingDigest`. The legacy
`signature` and `derivedFailureDigest` fields remain exact aliases for evidence
schema compatibility; they never provide separate authority.

Evidence verification independently rebuilds both values from the
producer-bound raw facts and rejects a claimed, copied, omitted, reordered,
expanded, or coherently rewritten derived identity. A frozen release-only skip
is authorized only when command ID, ordinal, class, profile, platform, source
ID/path/scope, complete raw schema, occurrence ceiling, frozen-v1 digest,
current full-context digest, fresh-replay producer membership, hard-gate
priority, and current gate disposition all agree. Neither digest alone,
producer-claimed structured identity, substring/display-name matching, nor a
command-class-wide nonzero waiver authorizes a skip.

Expected private-resource omissions remain separately labelled intentional
public-clone omissions and never weaken the tracked-resource hard gate.
Release-only ZIP, PDF, and checklist checks remain explicit skips because this
CI has no release input or publication authority. They are visible and
nonblocking in `static`; the same observation is blocking when `standalone` or
`all` makes a release gate required. If an observation could match both frozen
debt and hard-gate authority, the hard-gate result wins. No gate is
observational.

The static profile exposes two distinct hard gates. `STATIC-SUITE-EXECUTION`
requires a started child, zero exit, no timeout or output overflow, clean
process containment, one valid version-2 machine document, an exact invocation
ID, and complete execution of the producer's precomputed command plan.
`executionStatus: COMPLETE` says only that the runner and protocol completed;
it does not claim that every observed assertion passed. `STATIC-SUITE-RESULT`
is derived by the parent from the raw observations, frozen semantic authority,
the independently reconstructed plan, and hard gates. Exact ratified debt,
expected omissions, and permitted non-release skips remain visible and
nonblocking; unknown, expanded, over-ceiling, unexecuted, or hard-gate results
block.

## Frozen known-debt IDs

Product or packaging obligations:

- `B-STATIC-NAVIGATION-VIEW-COVERAGE`
- `G-STANDALONE-SITE-CONTENT-MEMBERSHIP`
- `B-SYNTAX-READING-EXPLANATION-P1-HIGH-194`
- `B-SYNTAX-READING-EXPLANATION-P3-LOW-151`

Validation-infrastructure obligations:

- `B-STATIC-E2E-SNAPSHOT-SCRIPT-DRIFT`
- `B-STATIC-SETTINGS-BUTTON-COVERAGE`
- `B-STATIC-PRACTICE-RECORDER-SYNTHETIC-GUARD`
- `B-STATIC-SUITE-SESSION-ROUTING`
- `B-STATIC-PY-PLAYWRIGHT-NB-DRAG`
- `B-STATIC-PY-PLAYWRIGHT-ROUNDTRIP`
- `B-STATIC-PY-PLAYWRIGHT-UNIFIED-SUBMIT`
- `B-STATIC-PY-PLAYWRIGHT-READING-QUICK-AUDIT`
- `B-STATIC-PRACTICE-CUSTOM-CARD-LAYOUT`
- `B-STATIC-ON-DEMAND-HARNESS-DOM-STUB`
- `B-SYNTAX-PERFORMANCE-BASELINE`
- `B-SYNTAX-STATE-SERIALIZER-TEST`
- `E-ADMIN-FRONTEND-DOM-STUB`
- `E-REMOTE-PRACTICE-DISABLE-TOTP-TEST-DRIFT`

Accepted checkpoint-nonblocking debt:

- `E-WINDOWS-LOCAL-DATA-CRLF-ASSERTION`
- `F-WINDOWS-BACKEND-COMPATIBILITY-RUNNER`
- `D-WSL-PLAYWRIGHT-BROWSER-UNAVAILABLE`

The Windows backend entry records historical V1 unavailability only. Current
CI requires the command to execute; unavailability fails, while a pass is a
resolved candidate.

Expected public-clone omissions:

- `B-STATIC-PRIVATE-LISTENING-INDEX-OMISSION`
- `B-STATIC-PRIVATE-LISTENING-BRIDGE-OMISSION`

Release-only skips:

- `B-SKIP-RELEASE-ZIP`
- `B-SKIP-PDF-RECONCILIATION`
- `B-SKIP-CHECKLIST-CONSISTENCY`

## Runner contract

The runner uses only Python standard-library code before installation:

```text
python -B developer/tests/ci/run_ci_foundation.py --profile PROFILE
python -B developer/tests/ci/run_ci_foundation.py --profile policy --verify-only
python -B developer/tests/ci/run_ci_foundation.py --profile policy --verify-only --require-install-tools
python -B developer/tests/ci/run_ci_foundation.py --prepare-developer-esbuild
python -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile PROFILE --expected-invocation-id LOCAL_INVOCATION_ID
<ABSOLUTE_PYTHON> -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile PROFILE --expected-producer-job PRODUCER --expected-verifier-job VERIFIER --expected-runner-os OS --untrusted-evidence-root ROOT
python -B developer/tests/ci/run_ci_foundation.py --list-profiles
```

`PROFILE` is exactly one of `policy`, `static`, `frontend`, `backend`,
`standalone`, or `all`.

`--verify-evidence` without `--expected-profile` is a configuration error and
exits before a replay runner is constructed or any evidence byte is read. The
expected profile is a single-use, case-sensitive fixed-enum CLI value; it is
never inferred from `summary.profile`, another evidence field, an evidence
filename, or an artifact name. Local verification also requires the exact
64-hex invocation identity printed by the immediately preceding local
generation command. GitHub Actions verification instead obtains run identity
from GitHub-controlled context, rejects a local invocation argument, requires
literal producer and verifier job identities, and reads evidence only from the
explicit untrusted artifact root. Linux verifier jobs additionally require
`--require-linux-containment-self-test`; dependency-using verifier jobs require
`--require-fresh-runtime-closure`.

- `policy` checks baseline authority, the Git/tracked boundary, private and secret exclusion, licence/governance consistency, and workflow policy.
- `static` runs the existing static suite through its opt-in machine stdout protocol, parses every JSON result, checks every tracked JavaScript/MJS source with `node --check`, and compiles every tracked Python source in memory.
- `frontend` runs bundle normalization and byte parity, focused learner tests, and the authoritative frontend security/export guards.
- `backend` runs `npm --prefix backend test` as the full canonical suite.
- `standalone` runs the canonical packaging security suite and exact index-to-positive-manifest membership audit.
- `all` executes every profile responsibility in one evidence set.

Exit codes are `0` for success, `2` for a test or policy violation, `3` for a
CLI or baseline configuration error, and `4` when safe evidence cannot be
produced. Before repository-controlled execution starts, the runner freezes an
ordered profile command plan from its fixed registry, platform/profile rules,
direct Git-index enumeration contract, trusted tool identities, target bytes,
and the frozen baseline. It never derives authority from observations,
evidence, summary counts, or a producer-supplied authority list. Every required
execution command must start, exit exactly zero, remain within time/output
bounds, complete clean containment, and avoid setup failure. An
observation-producing command may use only its individually planned nonzero
exit, with exact argv/cwd/executable/target identity and a corresponding
complete observation for parent classification. Evidence verification rejects
missing, extra, duplicate, reordered, renumbered, reclassified, retargeted, or
otherwise identity-changed commands.

Direct Node syntax checks distinguish the reviewed logical argv from the
immutable execution argv. The logical command names the repository target, but
Node receives the exact planned target bytes on standard input using the fixed
CommonJS or module input adapter. A versioned target-execution lease rejects
unsafe or case/normalization-aliased paths, linked or reparse parents, and
non-regular targets. POSIX opens with `O_NOFOLLOW`; Windows uses `CreateFileW`
with read access, read sharing only, `OPEN_EXISTING`, and
`FILE_FLAG_OPEN_REPARSE_POINT`. The held descriptor/handle is measured against
the planned canonical path, byte length, SHA-256, stable file identity, mode,
and reparse state before materialization and around process execution. Mutation
is sticky, and the lease is rechecked after launch, during execution, after
exit, before evidence, and during runner cleanup. Evidence records the logical
and actual execution argv, input mode/length/digest, pre/post source identities,
mutation state, and closed cleanup state. Verification independently rebuilds
the plan and requires the executed input identity to equal the planned bytes.

All target-bearing in-process checks use one `ProtectedTargetBundle` contract.
The command plan fixes an ordered list of logical paths, canonical source
paths, byte lengths, SHA-256 values, stable identities, mode, and reparse
state. The bundle opens every target through a `TargetExecutionLease`,
materializes the held bytes exactly once, and supplies only bytes, validated
UTF-8 text, or immutable parsed values to the policy evaluator. Evaluators do
not reopen repository paths. Bundle evidence records the ordered planned and
actual input identities, `executionInputBundleDigest`, pre- and post-execution
identities, sticky mutation state, and closed cleanup state. A missing,
reordered, additional, changed, linked, reparse-substituted, deleted, or
recreated member fails the command or the profile.

`workflow-self-policy` is a three-input protected command over
`.github/workflows/ci.yml`, `docs/CI_POLICY.md`, and the Phase 1 baseline JSON.
Its policy API accepts those three byte strings plus independently planned
target authority; it has no repository-root or path argument. Baseline schema,
private-boundary, secret, licence, Python syntax, standalone membership, and
lockfile checks use the same byte-only rule.

Every target-bearing external repository check executes from a task-owned
temporary workspace populated only from a protected bundle of the complete
candidate inventory. This includes the static producer, standalone packaging,
bundle/source parity, focused learner checks, frontend security guards, and the
canonical backend suite. Source handles remain leased through child exit and
final verification. The child receives a single non-secret snapshot marker in
the otherwise minimal environment. When already-installed Node dependency
roots are needed at runtime, only explicitly resolved, repository-contained,
non-reparse dependency roots are added to the derived child environment; the
candidate source under test still comes exclusively from the protected
snapshot. The temporary workspace is removed before the closed bundle evidence
is returned. This prevents those children from treating later live-worktree
bytes as their planned inputs.
Before authoritative parsing and stream hashing, the adapter translates only
the exact task-owned physical snapshot-root prefix in captured stdout and
stderr to the logical repository-root prefix. JSON-escaped, URI, slash, and
native path forms are covered. This preserves repository-relative file and
line identities and makes replay independent of randomized temporary-directory
names; unrelated absolute paths are not translated.
After the static machine document passes strict UTF-8, duplicate-key, schema,
invocation, and producer-plan validation, its evidence stream is serialized
canonically. Volatile duration fields and the narrow Python-unittest
`Ran N tests in Ns` timing form are normalized; all command results,
observations, statuses, diagnostics, and nonvolatile fields remain bound. The
canonical bytes, rather than wall-clock timing text, supply the recorded stream
digest and every producer record's source-output digest.

### Trusted tools and environment

Required executables pass five ordered boundaries: discovery, role-specific
validation, identity capture, absolute-path execution, and post-execution
revalidation. The runner resolves and verifies the complete tool set for the
selected profile before it constructs the immutable command plan or any
authorization binding. A missing or partial map fails with the stable,
path-free typed diagnostic
`CI_TOOL_AUTHORITY_UNAVAILABLE tool=<role> phase=<phase>`, a nonzero result, no
Python traceback, no `KeyError`, no partial binding, and no pass-shaped
evidence. Policy requires Python, Node, and Git; static and standalone also
require Bash and PowerShell/pwsh because the unchanged standalone packaging
producer invokes both shells; dependency-using profiles explicitly require the
npm entrypoint.

Authority is role-specific rather than a general PATH allowlist. Python is the
canonical `sys.executable` file identity or that same verified setup-python
toolcache identity. `python`, `python3`, `python3.12`, and `python.exe` are
aliases only when `samefile`/stable identity proves that they resolve to that
approved file; basename equality grants nothing. Node comes only from a
verified setup-node toolcache or the approved local runtime. Git comes from an
explicit POSIX system installation, Program Files Git, or the approved local
Git installation; a setup toolcache, workspace, runner temporary directory, or
user-writable shim cannot authorize Git. POSIX Bash comes from an explicit
system installation. PowerShell/pwsh comes only from the inspected Windows
system/Program Files installation or the explicit POSIX system/Microsoft
installation root. On Windows, an already approved Git for Windows executable
derives exactly one installation root by complete path components. The
supported executable suffixes are `bin\git.exe` and `cmd\git.exe`; both remove
their complete suffix and therefore identify the same installation root.
Relative, UNC, device, extended-device, reparse-escaped, unknown, and internal
`mingw*\bin\git.exe` spellings fail closed. Internal layouts are not added on
the strength of a filename or a hosted-image patch version; each needs separate
layout evidence and regression authority.

Windows Bash is never selected by `PATH`, `PATHEXT`, `shutil.which`, WSL,
System32, Sysnative, WindowsApps, the workspace, runner temporary storage,
`node_modules`, or another Git installation. It is enumerated only from the
derived Git root, in the fixed priority
`<TrustedGitRoot>\bin\bash.exe` then
`<TrustedGitRoot>\usr\bin\bash.exe`. The chosen path must be the exact fixed
candidate under the same component-equal root, not a near-prefix root or an
arbitrary descendant. A missing or invalid candidate retains the stable typed
tool-authority failure and cannot yield a partial authorization binding or a
pass-shaped artifact.

PATH order and executable shadowing are distinct facts. The resolver inspects
each absolute, non-link directory and enumerates the platform aliases for the
role being resolved. An earlier workspace, runner-temp, `node_modules/.bin`, or
other untrusted directory is harmless when it contains no relevant alias. If
it contains a different executable, script, shim, or alias that could shadow
an ordinarily PATH-resolved role, resolution fails closed. An uninspectable
directory, invalid entry type, or ambiguous identity also fails closed. Empty,
current-directory, relative, and duplicate entries are removed and never
inherited. An alias in an earlier directory may match only when file identity
proves it is the same approved executable; capture still records and executes
the canonical approved path, never the alias. Windows Git Bash is the narrow
exception to shadow authority because it is not PATH-resolved: a parent-PATH
Bash alias is detected for audit, but it cannot replace or veto the fixed
same-installation absolute candidate and is absent from the rebuilt child
PATH. The alias itself receives no authority and is never executed.

Each captured tool record contains its canonical absolute path, stable file
identity, byte length, SHA-256, version output, and trusted-root
classification. A held descriptor or handle revalidates the identity before
command construction, immediately before launch, after execution, and at final
cleanup. Replacement, rename/delete/recreate, mutation-and-restore, parent
redirection, or reparse substitution becomes a sticky hard failure and never
causes PATH re-resolution. npm is an entrypoint, not a PATH executable: it is
invoked only as `<CAPTURED_NODE> <CAPTURED_NPM_ENTRY> ...`. On Windows, the
selected Bash additionally uses a `CreateFileW` read-only, read-sharing-only,
no-delete-sharing identity lease rooted in the same trusted Git installation.
The Bash candidate must be a non-reparse, single-name regular `.exe` with a
non-reparse parent chain. Its stable file identity, complete byte length, and
SHA-256 are captured; version inspection invokes that captured absolute path;
and the held identity is checked before and after every authorized execution.
Identity, same-size, hardlink, or change-and-restore drift fails closed before
an unverified replacement can run.

A new real hosted Windows producer and independent verifier run remains
required before merge eligibility. Local synthetic layout evidence validates
the authority algorithm but does not make a hosted image name, image patch
number, or local installation a substitute for that remote gate.

Children receive an allowlisted environment containing only required runtime,
platform, locale, temporary-directory, and CI values. `PATH` is rebuilt solely
from directories containing captured approved executables plus the minimum
inspected system directories. It never contains the checkout, workspace,
runner temp, task fixture root, current directory, empty or relative entries,
`node_modules/.bin`, or an unapproved user-local directory, even when such a
parent PATH entry was empty during discovery. Consequently, a shadow created
after capture cannot redirect execution. Trusted shell bindings and one computed
Git `safe.directory` entry for the exact repository are added; inherited
versions of those controls are discarded. Credential-shaped variables,
GitHub tokens, authorization values, proxy variables, Node injection options,
and executable overrides are not inherited. Repository-controlled children do
not inherit `GITHUB_PATH`, `GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_STATE`,
`ACTIONS_RUNTIME_TOKEN`, either OIDC request variable, `RUNNER_TEMP`, or
`RUNNER_TOOL_CACHE`. `TEMP`, `TMP`, and `TMPDIR` are all rebound to the
verifier's task-owned private temporary root. Security fixtures that need an
NTFS task root do not infer authority from Python's temporary-directory
selection order: the explicit task parent must exist, be outside registered
worktrees, be non-reparse, use a bounded short child prefix, and be passed to
`TemporaryDirectory(dir=...)` or an equivalent explicit API. Distinct
`TEMP`/`TMP`/`TMPDIR` environments and coalesced environments are both valid
only when the fixture remains below the explicit task parent and leaves no
residual child.

Commands execute without a shell unless a reviewed repository command itself
requires a resolved shell. Direct Git operations use an absolute Git path and
an exact repository-scoped safety option, independent of mutable user config.
Standalone packaging fixtures centralize Git calls through one trusted helper;
on Windows each fixture Git invocation includes command-scoped
`-c core.longpaths=true`. Tests may write local config only inside a
task-owned disposable repository when Git itself requires identity metadata;
they never write global, system, or user Git configuration.
The runner never contacts the network or invokes Docker, SSH, GPG, WSL,
publication, deployment, or production operations.

Every child command runs inside an independently terminable process-tree
boundary. Its security invariant is: after command completion and bounded
cleanup, no tracked or attributable descendant remains alive. A forced-kill
counter is diagnostic only; `descendantsTerminated == 0` can be safe when a
child exited naturally, closed with the session, or was already reaped. Each
command therefore records descendants observed, explicitly reaped, forced
termination count, descendants surviving, and a disposition of
`no-descendants`, `natural-exit-reaped`, `forced-terminated`, `survivor`, or
`unknown-ancestry`. `contained-clean` requires zero survivors, complete
cleanup, and neither survivor nor unknown-ancestry disposition.

Linux no longer treats a process group or session as descendant
authority. The main verifier and a dedicated per-command supervisor both set
`PR_SET_CHILD_SUBREAPER`; a start gate holds the repository command before
`execve`. The supervisor continuously rebuilds `/proc` ancestry, records PID,
starttime, parent, process group, session, discovery generation, and an open
pidfd, and keeps reparented or session-changing descendants in one sticky
registry until explicit `waitpid` reaping. Cleanup repeatedly stops the known
domain, scans for newly reparented descendants, sends bounded TERM/CONT and
pidfd-validated KILL signals, reaps, and requires a fixed number of stable
empty scans. `/proc` errors, pidfd errors, PID reuse, ancestry ambiguity,
registry overflow, unexpected children, survivor state, and settle timeout all
fail closed. Windows creates the direct child suspended,
assigns it to a Job Object configured with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resumes it. Closing the Job Object
kills parent, child, and grandchild members; the runner waits for the observed
members to exit. Cleanup also runs after a direct parent exits successfully, so
a daemonized descendant cannot continue into evidence generation or upload.
Containment setup or cleanup failure is a hard execution failure.
The Linux evidence containment label is
`linux-subreaper-pidfd-proc-supervisor`.

Every Linux fresh verifier runs an in-process trusted pre-replay live matrix
covering setsid escape, double fork, sleeping grandchildren, sentinel writers,
parent-first exit, ignored SIGTERM, rapid fork/exit, ordinary daemons, timeout,
and stdout/stderr limits. It requires no survivors or sentinels and an active
containment count of zero before any artifact can be accepted. Windows unit
tests exercise the pure state machine and distinguish natural exit/reap,
forced termination, survivor, and unknown ancestry without requiring a
positive termination counter. A daemon fixture publishes its PID and ready
marker, schedules a delayed sentinel, and passes only when cleanup is complete,
the attributable PID is no longer alive, and the sentinel remains absent after
a bounded settle period. These model and Windows results do not claim
Linux-kernel execution. Local Windows status is
`REMOTE-LIVE-VALIDATION-PENDING`.

For required commands, output is eligible for semantic parsing only after the
process starts, exits exactly zero, stays within time and output bounds, and
its complete process tree is reaped. The static suite receives a deterministic
UUID derived independently from the planned static-producer path, length, and
SHA-256 using the fixed `--ci-machine-json-stdout --ci-invocation-id <UUID>` argv.
The producer pipe bytes are the sole static-report authority: no workspace or
temporary report path is opened after child exit. Machine stdout must be
exactly one BOM-free UTF-8 JSON document followed by one LF, with no prefix,
suffix, second document, or trailing whitespace. Its document kind, schema,
invocation ID, fields, counts, and internal status must be exact. The legacy
no-flag static-suite invocation retains its human output, report file, and exit
semantics, but that file is not CI authority. Pass-shaped output from a
nonzero, timed-out, output-limited, or incompletely reaped child has no
semantic authority.

Machine mode uses document kind `ieltmps-static-suite-machine-report-v2` and
schema version `2`. It carries the invocation ID, `executionStatus`, canonical
`commandPlanDigest`, complete command results, stable observations,
`nativeNonPassCount`, and `internalRunnerFailures`. Machine exit zero means the
plan and protocol completed even when recorded assertions are non-pass;
nonzero means runner, protocol, containment, output, timeout, or incomplete-plan
failure. The parent independently reconstructs both the producer plan and the
full profile plan, including each ordinal, full argv, repository-relative cwd,
tool role, absolute executable path/size/SHA-256/stable identity, target
path/size/SHA-256/stable identity, result semantics, and allowed exit set. The
report's digest and embedded authority are evidence to compare, never authority
to trust.

Observation authority is likewise producer-bound. Every command record carries
the complete ordered raw producer-observation set and its canonical set digest;
the top-level observation collection must be an exact one-for-one projection of
those records. The verifier rejects an omitted producer record, an additional or
duplicate observation, a wrong producer command/path/ordinal, a mismatched raw
output digest, or any derived-authority field embedded in raw structured data.

### Trusted-file integrity

The fixed trusted manifest is:

- `.github/workflows/ci.yml`
- `developer/tests/ci/phase1-ci-baseline.json`
- `developer/tests/ci/run_ci_foundation.py`
- `developer/tests/ci/run_static_suite.py`
- `developer/tests/ci/test_ci_foundation.py`
- `developer/tests/ci/test_standalone_packaging.py`
- `developer/package.json`
- `developer/package-lock.json`
- `backend/package.json`
- `backend/package-lock.json`

The four package/lock files also have exact candidate-local byte digests in the runner.
Snapshots are taken before untrusted installation or test execution and after
each lifecycle/test phase. A missing, replaced, linked, or changed trusted file
is a hard failure. The two lockfiles must also have no Git byte difference.

## Strict workflow parser and schema

The candidate-local verifier contains a deterministic parser for only the workflow's canonical
YAML subset. It constructs mapping, sequence, and scalar nodes from indentation
and accepts the exact literal `run` block form used here. It is intentionally
not a general YAML parser. Duplicate keys, tab indentation, quoted keys,
anchors, aliases, merge keys, tags, inline collections, folded scalars, and all
unsupported constructs fail before semantic validation. There is no textual or
regex acceptance fallback.

The AST validator requires exactly the top-level keys `name`, `on`,
`permissions`, `concurrency`, and `jobs`; the exact pull-request, push, and
manual triggers; and only `contents: read`. It requires the exact seven-job
graph, runner labels, timeouts, step order, action pins, action inputs, command
lines, artifact paths, and final-result script. Unknown top-level, trigger,
permission, job, or step keys fail. Job permissions, environments, inherited
secrets, reusable calls, containers, services, and self-hosted runners fail.

Every AST scalar is traversed. Secret and token expressions—including indexed
or quoted equivalents—and attacker-controlled GitHub contexts in shell source
fail. Parsed commands reject direct or indirect ref mutation, Docker, SSH, GPG,
arbitrary downloaders, write-capable GitHub CLI use, deployment, publication,
and environment-variable command indirection.

Only the five official GitHub-maintained actions below are allowed, at their
exact 40-character lowercase commits. Checkout must use
`persist-credentials: false` and `fetch-depth: 1`.

| Repository | Stable tag | Pinned commit |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | `v7.0.0` | `820762786026740c76f36085b0efc47a31fe5020` |
| `actions/setup-python` | `v7.0.0` | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | `v4.3.0` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |

The immutable Phase 1 baseline predates the new download boundary and still
ratifies its original four pins exactly. The additional candidate-local
download pin is enforced by the exact CI8 workflow grammar and remains subject
to independent review; it does not rewrite the frozen baseline.

The final job must use `always()`, depend on `repository-policy`,
`ubuntu-canonical`, and `windows-compatibility`, inspect every corresponding
`needs.*.result`, accept only `success`, and exit nonzero for every other
result. Removing a dependency, neutralizing a branch, replacing failure with a
no-op, or forcing a zero exit fails policy.

The final job always prints the three bootstrap warning lines above. A success
there means only that the candidate-local consistency jobs succeeded; it does
not authenticate those jobs or authorize a merge.

## Workflow architecture and lifecycle order

The workflow covers pull requests to `main`, pushes to `main` and
`ci/phase2-foundation`, and manual dispatch. It has read-only contents
permission, concurrency cancellation, explicit job timeouts, no
`continue-on-error`, and this graph:

```text
repository-policy-producer     -> repository-policy --------+
ubuntu-canonical-producer      -> ubuntu-canonical ---------+--> final-result
windows-compatibility-producer -> windows-compatibility ----+
```

The three producer jobs execute candidate profiles and upload exactly five
evidence files under distinct `untrusted-*-${{ runner.os }}-${{
github.run_attempt }}` names. They perform no evidence verification and grant
no merge or check authority. Each authoritative verifier retains its original
job ID, depends on exactly its one producer, checks out exact `github.sha` on a
new GitHub-hosted runner, and downloads only that producer's artifact into a
fixed `.ci-untrusted/<verifier>` root.

Before the terminal verifier, a fresh verifier permits only pinned checkout,
setup-python, setup-node, trusted absolute runtime capture, dependency-root
absence checks, fresh lockfile installation with lifecycle scripts disabled,
and the pinned artifact download. It does not run a repository Python/Node
script, test, sourced shell, Vitest, backend command, or bundle command. The
Ubuntu and Windows all-profile verifiers install independently with:

```text
<ABSOLUTE_NODE> <ABSOLUTE_NPM_ENTRY> --prefix developer ci --ignore-scripts --no-audit --no-fund
<ABSOLUTE_NODE> <ABSOLUTE_NPM_ENTRY> --prefix backend ci --ignore-scripts --no-audit --no-fund
```

Producer `node_modules`, runtime directories, PATH, TEMP, command files,
generated output, checkout mutations, and caches are never uploaded or restored
into a verifier. The terminal step invokes the validator only through the
captured absolute Python executable and passes literal profile, producer job,
verifier job, OS, and untrusted evidence root.
There is no workflow step after it. Official action post hooks are not evidence authority and cannot replace
the verifier result; task-owned cleanup occurs inside the verifier process.

Residual supply-chain boundary: GitHub-hosted runners still download the exact
pinned official action commits, and npm still retrieves lockfile-authorized
package bytes from its configured registry and applies lockfile integrity
checks. CI does not independently attest registry availability, the registry
operator, or every platform package beyond those locked identities and checks.
This residual does not authorize moving pins, unlocked installs, arbitrary
scripts, global installs, `npx`, publishing, or dependency updates. No
dependency cache is enabled.

### Runtime and dependency closure

Every GitHub verifier independently constructs `RuntimeDependencyClosure`
before replay. Its versioned document binds profile and runner OS; canonical
Python, Node, and npm paths; product versions; byte sizes and SHA-256 values;
stable executable identities; the two lockfiles; the ordered complete manifests
of required dependency roots; member type, mode, size, hash, and authorized
relative symlink target; resolved Vitest entrypoint and package version; exact
empty `NODE_PATH`; member count; dependency digest; and closure digest.
Inherited `NODE_PATH` or `NODE_OPTIONS` is rejected before tool access, so a
workspace loader, preload, or unplanned dependency root cannot extend the
closure.
The full producer closure claim is stored in `command-results.json`, but it is untrusted
and never becomes verifier runtime authority. The in-memory verifier transcript
records its independently measured fresh closure.

`RuntimeDependencyClosureGuard` takes a full manifest before replay and after
every phase and verifier completion. Windows uses recursive
`ReadDirectoryChangesW`; Linux uses recursive inotify. Queue overflow or watcher
failure is hard. Write, truncate, rename, delete, create, hardlink or symlink
substitution, mode/attribute change, `.bin` shadowing, and change-and-restore set
a sticky mutation state that restoration cannot clear. Dependency-backed
command records bind both closure digests, exact `NODE_PATH`, resolved runner
entrypoint and hash, executable identity, active watcher state, and mutation
state. Python, Node, npm, Vitest, and authority-relevant Git executables retain
non-Bash identity leases or held descriptors/handles through replay; drift is a
hard failure and never triggers automatic path re-resolution.

Local policy/static generation and replay may record
`local-nondependency-npm-unavailable` when no local npm exists. That mode has no
dependency roots and makes no fresh-install claim. It cannot be used by a
GitHub verifier or a dependency-using profile. Remote fresh npm installation
and Linux-kernel containment therefore remain accurately labelled
`REMOTE-LIVE-VALIDATION-PENDING` until the approved GitHub run occurs.

### Job-local skips and run-wide OS coverage

Test reporting distinguishes four facts: job-local discovered tests,
job-local passes, job-local skips caused by platform applicability, and the
required live run-wide coverage for each security family. A Windows Job Object
or Git Bash implementation test may truthfully be discovered and skipped on an
Ubuntu job when the required Windows job discovers and passes that family.
Likewise, a Windows execution of a pure POSIX model is supporting evidence, not
a substitute for the required live Ubuntu containment gate. The policy does
not claim that every individual job has zero skips.

The run-wide model fails closed when a Windows-only family is skipped on every
job, when any required cross-platform family has no live pass on one required
OS, when a required live family has only model execution, or when job-local
discovered/pass/fail/skipped totals are inconsistent. Platform skips are thus
neither mislabeled as implementation failures nor allowed to erase mandatory
coverage. This accounting changes no workflow job, verifier, artifact, or
final-result authority.

## Evidence filesystem and artifact boundary

An evidence-producing invocation requires `.ci-results` to be absent. The
runner validates every existing ancestor beneath the repository root, rejects
links, junctions, reparse points, non-directories, and resolution outside the
workspace, then creates a fresh directory. Each evidence file is created
exclusively as a regular file with no-follow behavior where supported.

The only allowed files are:

- `.ci-results/summary.json`
- `.ci-results/summary.md`
- `.ci-results/observed-debt.json`
- `.ci-results/resolved-candidates.json`
- `.ci-results/command-results.json`

After writing, the runner requires exactly those five entries, regular-file
type, no link/reparse status, acceptable link count, and the intended resolved
parent. Every JSON document has an exact versioned kind, top-level schema,
bounded collections, shared invocation identity, and shared runtime identity.
Counts, status, command execution failures, known debt, omissions, release
skips, and resolved candidates must agree across files. `summary.md` must equal
the canonical rendering of `summary.json` byte for byte.

### External replay and execution-binding authority

Evidence may describe its profile and execution context. Evidence never
selects the expected profile, workflow job, runner operating system, run
identity, checkout identity, or command plan that verification replays.

After CLI parsing and before opening `.ci-results`, verification constructs one
`ExternallyExpectedVerificationContext`. It loads the frozen baseline,
constructs `FoundationRunner` from the externally supplied expected profile,
independently freezes that profile's command plan, measures the current
checkout and CI trust files, and binds the current execution context. Only
then may evidence parsing begin. A profile or binding mismatch fails before
`runner.run()`; replay always uses
`ExternallyExpectedVerificationContext.expected_profile`.

Every structured evidence document contains the same strict
`ProducerExecutionBinding` and `executionBindingDigest`. Evidence is allowed to
claim only producer facts: binding kind/mode, `producerJobId`,
`producerRunnerOS`, `producerProfile`, run/attempt/event/repository,
checkout/baseline commit and tree, `trustFileDigest`, `commandPlanDigest`, and
`producerInvocationId`.

Generation also records one strict, versioned `AuthorizationContextBinding` and
its domain-separated, type-aware, length-framed, NFC-normalized
`authorizationContextBindingDigest`. Its exact stable projection is: binding
schema and kind, binding mode, expected profile, producer job ID, expected
verifier job ID, runner OS, run ID and attempt, event, repository, checkout
commit and tree, baseline commit and tree, CI trust-file digest, independently
rebuilt command-plan digest, and producer invocation ID. Local mode fixes the
roles to `local-producer` and `local-verifier`. The authoritative projection is
constructed from the fixed workflow mapping, GitHub-controlled or explicit
local verifier context, current checkout/baseline/trust bytes, the independently
rebuilt plan, and the caller-owned generation receipt. Artifact fields are
comparison claims only.

The authorization projection cannot contain `currentFullContextDigest`,
`derivedFailureDigest`, any evidence or summary/manifest digest, or its own
digest. Its digest is a direct member of every current full-context preimage.
Changing any stable authorization field therefore changes
`currentFullContextDigest`; copying a valid PDF or checklist digest across a
run, job, OS, checkout, trust-file set, plan, or invocation cannot authorize it.

### Normative Canonical Framing Grammar

This section is normative. It freezes the byte grammar already used by the
candidate. An implementation with only this policy, UTF-8, and SHA-256 can
reconstruct the three vectors below without consulting Python source.

<!-- CI_CANONICAL_FRAMING_CONSTANTS_V1 -->
```json
{
  "specificationVersion": 1,
  "textEncoding": "utf-8",
  "unicodeNormalization": "NFC",
  "lengthWidthBytes": 8,
  "countWidthBytes": 8,
  "byteOrder": "big",
  "mapKeyOrdering": "nfc-utf8-byte-lexicographic",
  "arrayOrdering": "input-order",
  "typeTags": {
    "null": "6e",
    "boolean": "62",
    "integer": "69",
    "float": "66",
    "text": "73",
    "bytes": "79",
    "list": "6c",
    "map": "6d",
    "map-key": "6b"
  },
  "domains": {
    "AuthorizationContextBindingDigest": "ieltmps-authorization-context-binding-v1",
    "VerifierReplayContextDigest": "ieltmps-verifier-replay-context-binding-v1",
    "ReplayAuthorizationEnvelopeDigest": "ieltmps-replay-authorization-envelope-v1"
  },
  "schemaVersions": {
    "AuthorizationContextBinding": 1,
    "VerifierReplayContextBinding": 1,
    "ReplayAuthorizationEnvelope": 1
  }
}
```

All lengths and collection counts are unsigned 64-bit big-endian integers.
`U64BE(x)` is exactly eight octets and permits `0 <= x <= 2^64-1`. For every
value, `FRAME(tag, payload) = tag || U64BE(byte_length(payload)) || payload`.
Each tag is the single octet listed above; there is no BOM, terminator, padding,
alignment, host-endian value, `repr`, or implicit outer wrapper.

Primitive and collection payloads are exactly:

- null: tag `6e`, empty payload;
- false/true: tag `62`, one ASCII octet `30`/`31` respectively;
- integer: tag `69`, the shortest base-10 ASCII spelling (`0`, positive digits
  without a leading zero, or `-` followed by nonzero-leading digits). Signed
  values are allowed and there is no fixed binary integer width; the variable
  ASCII payload has the mandatory eight-octet frame length;
- finite IEEE-754 binary64 float: tag `66`, the lowercase ASCII hexadecimal
  spelling produced by Python `float.hex()`. Positive and negative zero are
  exactly `0x0.0p+0` and `-0x0.0p+0`. Every other finite value is an optional
  `-`, `0x`, a leading `1` for a normal or `0` for a subnormal, `.`, exactly
  thirteen lowercase hexadecimal fraction digits, `p`, an explicit `+` or `-`,
  and the shortest decimal exponent digits; subnormals use exponent `-1022`.
  NaN and infinities are rejected. None of the three schemas below admits a
  float;
- byte string: tag `79`, unchanged octets;
- text string: tag `73`; first normalize the Unicode scalar sequence to NFC,
  then encode it as strict UTF-8. No BOM or terminator is present;
- list/array: tag `6c`; payload is `U64BE(element_count)` followed by each
  recursively framed element in input order. Tuple and list have this same wire
  type. Array order is significant;
- map/object: tag `6d`; payload is `U64BE(member_count)` followed by every
  key/value pair. A key must be text. Normalize each key to NFC, encode it as
  UTF-8, reject two keys whose normalized UTF-8 bytes are equal, sort pairs by
  unsigned lexicographic comparison of those key bytes, then emit the key as
  `FRAME(6b, key_bytes)` followed immediately by the recursively framed value.
  Source declaration/insertion order and locale are irrelevant.

The exact empty encodings are: null `6e0000000000000000`, empty text
`730000000000000000`, empty bytes `790000000000000000`, empty list
`6c00000000000000080000000000000000`, and empty map
`6d00000000000000080000000000000000`. An absent field contributes no bytes;
it is not null. Every field in the three schemas below is required, null is
invalid for every text field, and unknown fields are rejected. Map-key sorting
makes the declaration order below non-normative; array order remains normative.

The domain literal is not a raw prefix. Each digest hashes one complete framed
outer map containing a normal framed text member named `digestDomain` and one
normal framed schema member. SHA-256 consumes the complete outer-map frame.
These three digest functions return exactly 64 lowercase hexadecimal characters
with no `sha256:` prefix.

#### AuthorizationContextBindingDigest schema

The exact domain text is `ieltmps-authorization-context-binding-v1`; its UTF-8
hex is
`69656c746d70732d617574686f72697a6174696f6e2d636f6e746578742d62696e64696e672d7631`.
The complete preimage projection is the map
`{"digestDomain": domain_text, "binding": AuthorizationContextBinding}`.

| Field | Canonical type and constraint | Required |
| --- | --- | --- |
| `bindingSchemaVersion` | integer, exactly `1` | yes |
| `bindingKind` | text, exactly `AuthorizationContextBinding` | yes |
| `bindingMode` | text, `github-actions` or `local` | yes |
| `expectedProfile` | text, one of `policy`, `static`, `frontend`, `backend`, `standalone`, `all` | yes |
| `producerJobId`, `expectedVerifierJobId` | nonempty trimmed text, at most 512 UTF-8 octets | yes |
| `runnerOS` | text, `Linux` or `Windows` | yes |
| `runId`, `runAttempt`, `eventName`, `repository` | nonempty trimmed text, at most 512 UTF-8 octets | yes |
| `checkoutCommit`, `checkoutTree`, `baselineCommit`, `baselineTree` | exactly 40 lowercase hexadecimal text characters | yes |
| `trustFileDigest`, `commandPlanDigest`, `producerInvocationId` | exactly 64 lowercase hexadecimal text characters, without a prefix | yes |

The field set is exact: no optional or unknown member exists.

#### VerifierReplayContextDigest schema

The exact domain text is `ieltmps-verifier-replay-context-binding-v1`; its
UTF-8 hex is
`69656c746d70732d76657269666965722d7265706c61792d636f6e746578742d62696e64696e672d7631`.
The complete preimage projection is the map
`{"digestDomain": domain_text, "binding": VerifierReplayContextBinding}`.

| Field | Canonical type and constraint | Required |
| --- | --- | --- |
| `bindingSchemaVersion` | integer, exactly `1` | yes |
| `bindingKind` | text, exactly `VerifierReplayContextBinding` | yes |
| `actualVerifierJobId` | nonempty trimmed text | yes |
| `actualVerifierRunnerOS` | text, `Linux` or `Windows` | yes |
| `verifierInvocationId`, `freshRuntimeClosureDigest`, `freshDependencyClosureDigest` | exactly 64 lowercase hexadecimal text characters, without a prefix | yes |
| `linuxContainmentLiveTestResultDigest`, `replayTranscriptDigest` | text `sha256:` followed by exactly 64 lowercase hexadecimal characters | yes |
| `cleanupResult` | text, `closed-clean` or `cleanup-incomplete` | yes |

The field set is exact: no optional or unknown member exists.

#### ReplayAuthorizationEnvelopeDigest schema

The exact domain text is `ieltmps-replay-authorization-envelope-v1`; its UTF-8
hex is
`69656c746d70732d7265706c61792d617574686f72697a6174696f6e2d656e76656c6f70652d7631`.
The complete preimage projection is the map
`{"digestDomain": domain_text, "envelope": ReplayAuthorizationEnvelope}`.

| Field | Canonical type and constraint | Required |
| --- | --- | --- |
| `schemaVersion` | integer, exactly `1` | yes |
| `bindingKind` | text, exactly `ReplayAuthorizationEnvelope` | yes |
| `currentFullContextDigestSetDigest` | text `sha256:` followed by exactly 64 lowercase hexadecimal characters | yes |
| `authorizationContextBindingDigest`, `verifierReplayContextDigest` | exactly 64 lowercase hexadecimal text characters, without a prefix | yes |

The field set is exact: no optional or unknown member exists. The synthetic
values in Vector C are fixed inputs, not claims copied from a runtime receipt.

#### Normative test vectors

For every vector, `structuredInput` is the human-readable function input,
`canonicalNormalizedProjection` is the complete outer map after schema
projection, `canonicalPreimageByteLength` counts the complete framed outer map,
`canonicalPreimageHex` contains every preimage octet, and `sha256` plus
`expectedTextualDigest` contain the complete output.

##### Vector A: AuthorizationContextBinding

<!-- CI_CANONICAL_VECTOR_A_V1 -->
```json
{
  "vector": "A",
  "name": "AuthorizationContextBinding",
  "structuredInput": {
    "bindingSchemaVersion": 1,
    "bindingKind": "AuthorizationContextBinding",
    "bindingMode": "local",
    "expectedProfile": "policy",
    "producerJobId": "local-producer",
    "expectedVerifierJobId": "local-verifier",
    "runnerOS": "Windows",
    "runId": "vector-run",
    "runAttempt": "1",
    "eventName": "workflow_dispatch",
    "repository": "example/ieltmps",
    "checkoutCommit": "0101010101010101010101010101010101010101",
    "checkoutTree": "2323232323232323232323232323232323232323",
    "baselineCommit": "4545454545454545454545454545454545454545",
    "baselineTree": "6767676767676767676767676767676767676767",
    "trustFileDigest": "8989898989898989898989898989898989898989898989898989898989898989",
    "commandPlanDigest": "abababababababababababababababababababababababababababababababab",
    "producerInvocationId": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  },
  "canonicalNormalizedProjection": {
    "digestDomain": "ieltmps-authorization-context-binding-v1",
    "binding": {
      "bindingSchemaVersion": 1,
      "bindingKind": "AuthorizationContextBinding",
      "bindingMode": "local",
      "expectedProfile": "policy",
      "producerJobId": "local-producer",
      "expectedVerifierJobId": "local-verifier",
      "runnerOS": "Windows",
      "runId": "vector-run",
      "runAttempt": "1",
      "eventName": "workflow_dispatch",
      "repository": "example/ieltmps",
      "checkoutCommit": "0101010101010101010101010101010101010101",
      "checkoutTree": "2323232323232323232323232323232323232323",
      "baselineCommit": "4545454545454545454545454545454545454545",
      "baselineTree": "6767676767676767676767676767676767676767",
      "trustFileDigest": "8989898989898989898989898989898989898989898989898989898989898989",
      "commandPlanDigest": "abababababababababababababababababababababababababababababababab",
      "producerInvocationId": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    }
  },
  "canonicalPreimageByteLength": 1150,
  "canonicalPreimageHex": "6d000000000000047500000000000000026b000000000000000762696e64696e676d000000000000040e00000000000000126b000000000000000e626173656c696e65436f6d6d6974730000000000000028343534353435343534353435343534353435343534353435343534353435343534353435343534356b000000000000000c626173656c696e6554726565730000000000000028363736373637363736373637363736373637363736373637363736373637363736373637363736376b000000000000000b62696e64696e674b696e6473000000000000001b417574686f72697a6174696f6e436f6e7465787442696e64696e676b000000000000000b62696e64696e674d6f64657300000000000000056c6f63616c6b000000000000001462696e64696e67536368656d6156657273696f6e690000000000000001316b000000000000000e636865636b6f7574436f6d6d6974730000000000000028303130313031303130313031303130313031303130313031303130313031303130313031303130316b000000000000000c636865636b6f757454726565730000000000000028323332333233323332333233323332333233323332333233323332333233323332333233323332336b0000000000000011636f6d6d616e64506c616e446967657374730000000000000040616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626b00000000000000096576656e744e616d65730000000000000011776f726b666c6f775f64697370617463686b000000000000000f657870656374656450726f66696c65730000000000000006706f6c6963796b0000000000000015657870656374656456657269666965724a6f62496473000000000000000e6c6f63616c2d76657269666965726b000000000000001470726f6475636572496e766f636174696f6e4964730000000000000040636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646b000000000000000d70726f64756365724a6f62496473000000000000000e6c6f63616c2d70726f64756365726b000000000000000a7265706f7369746f727973000000000000000f6578616d706c652f69656c746d70736b000000000000000a72756e417474656d7074730000000000000001316b000000000000000572756e496473000000000000000a766563746f722d72756e6b000000000000000872756e6e65724f5373000000000000000757696e646f77736b000000000000000f747275737446696c65446967657374730000000000000040383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938396b000000000000000c646967657374446f6d61696e73000000000000002869656c746d70732d617574686f72697a6174696f6e2d636f6e746578742d62696e64696e672d7631",
  "sha256": "ddf4607eecbd29b2d42225427a7e1f7c18b7747db51d8a685156479e6b75f88f",
  "expectedTextualDigest": "ddf4607eecbd29b2d42225427a7e1f7c18b7747db51d8a685156479e6b75f88f"
}
```

##### Vector B: VerifierReplayContextBinding

<!-- CI_CANONICAL_VECTOR_B_V1 -->
```json
{
  "vector": "B",
  "name": "VerifierReplayContextBinding",
  "structuredInput": {
    "bindingSchemaVersion": 1,
    "bindingKind": "VerifierReplayContextBinding",
    "actualVerifierJobId": "local-verifier",
    "actualVerifierRunnerOS": "Windows",
    "verifierInvocationId": "1010101010101010101010101010101010101010101010101010101010101010",
    "freshRuntimeClosureDigest": "3232323232323232323232323232323232323232323232323232323232323232",
    "freshDependencyClosureDigest": "5454545454545454545454545454545454545454545454545454545454545454",
    "linuxContainmentLiveTestResultDigest": "sha256:7676767676767676767676767676767676767676767676767676767676767676",
    "replayTranscriptDigest": "sha256:9898989898989898989898989898989898989898989898989898989898989898",
    "cleanupResult": "closed-clean"
  },
  "canonicalNormalizedProjection": {
    "digestDomain": "ieltmps-verifier-replay-context-binding-v1",
    "binding": {
      "bindingSchemaVersion": 1,
      "bindingKind": "VerifierReplayContextBinding",
      "actualVerifierJobId": "local-verifier",
      "actualVerifierRunnerOS": "Windows",
      "verifierInvocationId": "1010101010101010101010101010101010101010101010101010101010101010",
      "freshRuntimeClosureDigest": "3232323232323232323232323232323232323232323232323232323232323232",
      "freshDependencyClosureDigest": "5454545454545454545454545454545454545454545454545454545454545454",
      "linuxContainmentLiveTestResultDigest": "sha256:7676767676767676767676767676767676767676767676767676767676767676",
      "replayTranscriptDigest": "sha256:9898989898989898989898989898989898989898989898989898989898989898",
      "cleanupResult": "closed-clean"
    }
  },
  "canonicalPreimageByteLength": 914,
  "canonicalPreimageHex": "6d000000000000038900000000000000026b000000000000000762696e64696e676d0000000000000320000000000000000a6b000000000000001361637475616c56657269666965724a6f62496473000000000000000e6c6f63616c2d76657269666965726b000000000000001661637475616c566572696669657252756e6e65724f5373000000000000000757696e646f77736b000000000000000b62696e64696e674b696e6473000000000000001c56657269666965725265706c6179436f6e7465787442696e64696e676b000000000000001462696e64696e67536368656d6156657273696f6e690000000000000001316b000000000000000d636c65616e7570526573756c7473000000000000000c636c6f7365642d636c65616e6b000000000000001c6672657368446570656e64656e6379436c6f73757265446967657374730000000000000040353435343534353435343534353435343534353435343534353435343534353435343534353435343534353435343534353435343534353435343534353435346b0000000000000019667265736852756e74696d65436c6f73757265446967657374730000000000000040333233323332333233323332333233323332333233323332333233323332333233323332333233323332333233323332333233323332333233323332333233326b00000000000000246c696e7578436f6e7461696e6d656e744c69766554657374526573756c744469676573747300000000000000477368613235363a373637363736373637363736373637363736373637363736373637363736373637363736373637363736373637363736373637363736373637363736373637366b00000000000000167265706c61795472616e7363726970744469676573747300000000000000477368613235363a393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839383938393839386b00000000000000147665726966696572496e766f636174696f6e4964730000000000000040313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031306b000000000000000c646967657374446f6d61696e73000000000000002a69656c746d70732d76657269666965722d7265706c61792d636f6e746578742d62696e64696e672d7631",
  "sha256": "0eb75602b7ad3b3eb6c8d3ced8256fcb3181e4b585167e88bb7db7f10d130fde",
  "expectedTextualDigest": "0eb75602b7ad3b3eb6c8d3ced8256fcb3181e4b585167e88bb7db7f10d130fde"
}
```

##### Vector C: ReplayAuthorizationEnvelope

<!-- CI_CANONICAL_VECTOR_C_V1 -->
```json
{
  "vector": "C",
  "name": "ReplayAuthorizationEnvelope",
  "structuredInput": {
    "schemaVersion": 1,
    "bindingKind": "ReplayAuthorizationEnvelope",
    "currentFullContextDigestSetDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "authorizationContextBindingDigest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "verifierReplayContextDigest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "canonicalNormalizedProjection": {
    "digestDomain": "ieltmps-replay-authorization-envelope-v1",
    "envelope": {
      "schemaVersion": 1,
      "bindingKind": "ReplayAuthorizationEnvelope",
      "currentFullContextDigestSetDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "authorizationContextBindingDigest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "verifierReplayContextDigest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
  },
  "canonicalPreimageByteLength": 555,
  "canonicalPreimageHex": "6d000000000000022200000000000000026b000000000000000c646967657374446f6d61696e73000000000000002869656c746d70732d7265706c61792d617574686f72697a6174696f6e2d656e76656c6f70652d76316b0000000000000008656e76656c6f70656d00000000000001ba00000000000000056b0000000000000021617574686f72697a6174696f6e436f6e7465787442696e64696e67446967657374730000000000000040626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626b000000000000000b62696e64696e674b696e6473000000000000001b5265706c6179417574686f72697a6174696f6e456e76656c6f70656b000000000000002163757272656e7446756c6c436f6e746578744469676573745365744469676573747300000000000000477368613235363a616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616b000000000000000d736368656d6156657273696f6e690000000000000001316b000000000000001b76657269666965725265706c6179436f6e7465787444696765737473000000000000004063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363",
  "sha256": "61979180b2cc001434451d1485e530a6b965aaa34d3a4a5f3346ef3a1d55071d",
  "expectedTextualDigest": "61979180b2cc001434451d1485e530a6b965aaa34d3a4a5f3346ef3a1d55071d"
}
```

The current verifier separately constructs `VerifierExecutionBinding` from
external GitHub context and current bytes. It binds `verifierJobId`,
`verifierRunnerOS`, `expectedProfile`, `expectedProducerJobId`, the same
run/attempt/event/repository and commit/tree identities, current
`trustFileDigest`, `independentlyRebuiltCommandPlanDigest`,
`freshRuntimeClosureDigest`, and `verifierInvocationId`. It is held in the
in-memory replay transcript and is never selected by artifact content.

`summary.md` canonically renders the same binding and digest. The verifier
requires exact binding equality across `summary.json`, `observed-debt.json`,
`resolved-candidates.json`, and `command-results.json`, regenerates Markdown,
then compares the claim with the independently built external context. A
coherent rewrite of every JSON file, Markdown, manifest, binding, digest,
command-plan claim, and replay-shaped field cannot replace that external
authority.

When `GITHUB_ACTIONS == true`, the binding mode is `github-actions`. The
verifier fails closed unless all of `GITHUB_JOB`, `RUNNER_OS`, `GITHUB_RUN_ID`,
`GITHUB_RUN_ATTEMPT`, `GITHUB_EVENT_NAME`, `GITHUB_REPOSITORY`, and `GITHUB_SHA`
are present and valid. The literal CLI producer job, verifier job, and OS must
equal those values and the fixed `WORKFLOW_JOB_PROFILE_AUTHORITY` mapping;
`GITHUB_SHA` must equal the current
checkout commit. The current checkout tree is independently resolved. The
producer and verifier invocation identities are independently derived from
their complete bindings without consulting evidence.

The canonical producer/verifier authority is:

| Producer | Verifier | OS | Profile | Untrusted artifact identity |
| --- | --- | --- | --- | --- |
| `repository-policy-producer` | `repository-policy` | `Linux` | `policy` | `untrusted-repository-policy-${{ runner.os }}-${{ github.run_attempt }}` |
| `ubuntu-canonical-producer` | `ubuntu-canonical` | `Linux` | `all` | `untrusted-ubuntu-canonical-${{ runner.os }}-${{ github.run_attempt }}` |
| `windows-compatibility-producer` | `windows-compatibility` | `Windows` | `all` | `untrusted-windows-compatibility-${{ runner.os }}-${{ github.run_attempt }}` |

Local mode never claims a GitHub job. It uses `local-producer` and
`local-verifier` sentinels, fixes run/attempt/event fields, binds the current
platform, uses a SHA-256 identity of the canonical repository root,
independently resolves current commit/tree and baseline commit/tree, and
requires a fresh 64-hex producer invocation identity supplied back through
`--expected-invocation-id`. Local and GitHub Actions bindings are mutually
exclusive.

The CI trust-file set used by replay binding is exactly, in order:

- `.github/workflows/ci.yml`
- `developer/tests/ci/phase1-ci-baseline.json`
- `developer/tests/ci/run_ci_foundation.py`
- `developer/tests/ci/run_static_suite.py`
- `developer/tests/ci/test_ci_foundation.py`
- `developer/tests/ci/test_standalone_packaging.py`
- `docs/CI_POLICY.md`
- `.gitignore`

`trustFileDigest` uses the `CITrustFileSetDigest` construction: it length-frames
the ordered relative path, Git mode, byte
length, and SHA-256 of every member. It measures current worktree bytes, not
only `HEAD`; therefore another commit, earlier candidate bytes, or changed
uncommitted CI bytes cannot reuse evidence. Generation and verification each
compute it independently.

These files do not establish authority by agreeing with one another. Structural
verification first reloads the frozen baseline, rebuilds the exact profile
command authority, validates raw observation records, and independently
derives observed known debt, expected omissions, release-only skips, resolved
candidates, unknown/expanded failures, hard failures, policy violations,
counts, and final status. Every derived record binds the baseline ID and
collection plus its category, gate, command class, scope, expected outcome,
signature set, occurrence ceiling, platforms, checkpoint disposition, target
stage, security impact, and source command. Unknown IDs,
collection/category movement, duplicate or split observations, source
movement, and unresolved or unexecuted "resolved" candidates are rejected.

Structural agreement is still only an evidence claim. Whenever `summary.json`
claims `PASS`, `--verify-evidence` executes the runner already constructed from
the external expected profile and frozen baseline, independently rebuilds its command plan,
and re-executes every required, observation-producing, and hard-gate command.
Historical command records, exits, producer sets, summary counts, manifest
hashes, and replay-shaped fields are never execution inputs. Missing tools or
dependencies make replay unavailable and the PASS claim is rejected.

A well-formed `FAIL` evidence set may pass structural and consistency
verification with `replay=NOT-REQUIRED`. That result validates only the five-file
schema, identities, derivations, manifest, and cross-file consistency. It does
not convert `FAIL` to `PASS`, authorize the artifact as a successful gate, or
waive any failure. Every `PASS` evidence claim still requires a fresh replay;
the FAIL/PASS boundary is not relaxed by structural verification.

The verifier keeps a `VerificationReplayTranscript` only in memory. For each
planned command it records profile and plan digest, ID, ordinal, class, role,
required state, completed class, logical and execution argv, relative cwd,
tool role, target and execution-input identities, start/execution/setup state,
exit, timeout and output state, containment and cleanup, stdout/stderr digests,
ordered producer observations and set digest, producer count, and bounded
duration class. Profile fields include the independently expected and actual
completed-command classes, their set digests, complete producer count,
producer-observation-universe digest, complete producer-transcript digest, and
missing, extra, or duplicate command IDs. Each planned command must appear
exactly once. Policy and static completed-class sets must be nonempty and must
equal the classes independently derived from the plan and clean replay facts.
The transcript also carries both the exact producer binding being compared and
the externally constructed verifier binding, plus the fresh runtime/dependency
closure and guard state. This binds expected profile, producer/verifier jobs,
OS, run/attempt/event/repository, checkout commit/tree, baseline commit/tree,
current trust-file digest, independently rebuilt command plan, fresh closure,
and both invocation identities to the replay.

The replay transcript is compared field by field with the evidence command
plan, command records, execution inputs, observations, producer sets, derived
debt/omission/resolution collections, and transcript digests. Only raw bounded
duration measurements and task-owned temporary-root spellings receive explicit
canonical normalization. The verifier neither overwrites the evidence nor
writes a second uploadable evidence set, and it rereads the original evidence
identities and bytes after replay.

After comparison, the fresh verifier constructs a separate strict, versioned
`VerifierReplayContextBinding`. Its exact projection contains actual verifier
job and runner OS, verifier invocation ID, fresh runtime and dependency closure
digests, the Linux containment live-test result digest, replay-transcript
digest, and cleanup result. These verifier-only facts are never required to
equal producer-time values and are never accepted from evidence. A
domain-separated `verifierReplayContextDigest` binds that projection.

Final PASS acceptance derives a `ReplayAuthorizationEnvelopeDigest` from the
ordered set of replayed `currentFullContextDigest` values, the independently
reconstructed `authorizationContextBindingDigest`, and the fresh
`verifierReplayContextDigest`. Replay-shaped fields in an artifact are rejected
rather than treated as inputs. The dependency graph is intentionally acyclic:

```text
raw observation + command authority + producer transcript facts
  + external stable AuthorizationContextBinding
    -> currentFullContextDigest

fresh verifier-only context + replay transcript
  + runtime/dependency closure and live-gate results
    -> verifierReplayContextDigest

ordered currentFullContextDigest set
  + authorizationContextBindingDigest
  + verifierReplayContextDigest
    -> ReplayAuthorizationEnvelopeDigest
    -> final PASS acceptance
```

No binding digest contains a full-context digest that also contains that
binding digest; the replay envelope cannot contain itself; and an evidence
claim supplies no authoritative node in this graph. The producer does not
predict a future verifier invocation, absolute runtime path, inode/file-index,
Linux PID, closure measurement, or live-test result.

An observation-producing command may legitimately replay with zero producer
observations only when its planned command appears exactly once, exits zero,
has clean execution and containment flags, and the replay scope is PASS or an
exact replay-derived resolved candidate. Rewriting an evidence exit to zero and
deleting its observations cannot create that fact.

`producerTranscriptDigest` binds the ordered complete command transcript, the
ordered complete producer-observation universe, completed-command classes,
command-plan digest, and execution-input identities. Full-context failure
material separately binds the single raw observation, its command-local
`producerObservationSetDigest`, the profile-wide
`producerObservationUniverseDigest`, `producerTranscriptDigest`, the command's
completed class, and the profile completed-class-set digest. These claimed
digests are comparison values only; replayed producer facts are the authority.
Consequently a coordinated rewrite of every evidence document, manifest
digest, and Markdown byte still fails when replay does not reproduce it.

One strict loader handles the baseline, static machine stdout, every evidence
JSON document, manifest-bearing evidence, and verification fixtures. It uses
decoded object-pair order to reject duplicate keys at every depth, including
identical values and Unicode-escaped equivalents. No security-critical JSON
path calls permissive `json.load` or `json.loads` outside that wrapper. All JSON
input also rejects `NaN`, positive or negative infinity, including values
created through overflow such as `1e309`. Float fields must be finite.
Durations are bounded by the configured job ceiling; byte counts and command
counts are non-negative bounded integers; timestamps must be finite and valid.
Fractional integer fields, negative values, and excessive finite values fail.
Dynamic Markdown text is passed through one deterministic HTML-and-Markdown
renderer that strips formatting controls and escapes HTML, links, images,
headings, block quotes, lists, tables, backticks, fences, and structural
newlines. Verification regenerates the canonical Markdown exactly.

`summary.json` contains a deterministic manifest for the other four files with
relative filename, byte length, SHA-256, and document kind. Verification reads
each file through a regular-file descriptor, compares pre-open, open, and
post-read identities, validates every schema and cross-file invariant, checks
the manifest, regenerates Markdown, and rechecks membership and identities.
Any missing, extra, contradictory, replaced, or mutated file is a hard failure.

Each artifact is uploaded by an explicitly non-authoritative producer. On a
fresh runner, the authoritative verifier's terminal step runs:

```text
repository-policy:
<ABSOLUTE_PYTHON> -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile policy --expected-producer-job repository-policy-producer --expected-verifier-job repository-policy --expected-runner-os Linux --untrusted-evidence-root .ci-untrusted/repository-policy --require-linux-containment-self-test

ubuntu-canonical:
<ABSOLUTE_PYTHON> -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile all --expected-producer-job ubuntu-canonical-producer --expected-verifier-job ubuntu-canonical --expected-runner-os Linux --untrusted-evidence-root .ci-untrusted/ubuntu-canonical --require-linux-containment-self-test --require-fresh-runtime-closure

windows-compatibility:
<ABSOLUTE_PYTHON> -B developer/tests/ci/run_ci_foundation.py --verify-evidence --expected-profile all --expected-producer-job windows-compatibility-producer --expected-verifier-job windows-compatibility --expected-runner-os Windows --untrusted-evidence-root .ci-untrusted/windows-compatibility --require-fresh-runtime-closure
```

This mode re-executes only the externally selected profile through protected
command authority and modifies no artifact byte. All-profile dependencies were
already installed freshly on this verifier runner with scripts disabled. The
verifier is the last declared workflow step; there is no later upload, shell,
cleanup, summary, or repository action for command-file poisoning to replace.
Producer workflow uploads list the
same five paths explicitly—no directory or glob—with `if-no-files-found:
error` and seven-day retention. Source archives, caches, environments,
credentials, Git objects, home directories, private resources, dependency
roots, runtimes, and release archives are never in artifact scope.

## Bounded diagnostics and redaction

Child output is streamed into bounded sinks, never accumulated without limit.
The fixed limits per command are:

- stdout: 1,048,576 bytes;
- stderr: 1,048,576 bytes;
- static machine stdout: 8,388,608 bytes;
- one line or NUL-delimited record: 16,384 bytes;
- sanitized evidence preview: 4,096 bytes; and
- complete command-results JSON: 33,554,432 bytes.

Crossing a stream or line limit terminates the child, records
`OUTPUT-LIMIT-EXCEEDED`, and fails a required command. Evidence records the
preauthorized command ID and ordinal, class/role, required flag, full argv,
repository-relative cwd, tool role, absolute executable identity, target
identities, allowed exits, actual exit, start/execution flags, containment,
timeout/output state, byte counts, a bounded sanitized preview when needed,
and parsed failure summaries. Full stdout/stderr, the environment, and secret
length or prefix are not retained.

Before evidence is written, redaction removes credential-bearing URLs,
authorization schemes and headers, cookies, session identifiers, GitHub token
forms, generic credential assignments, private-key blocks and isolated
markers. It handles multiline assignments and uses a generic `[REDACTED]`
replacement. ANSI CSI and OSC sequences, prohibited C0 controls, DEL, Unicode
bidi overrides/isolates, and other formatting controls are stripped to prevent
log spoofing.

## Complete streamed secret scanning

Every tracked and permitted implementation file is inspected as a regular
file. Every regular file—including recognized PNG, ZIP, PDF, font, audio, and
other binary content—is raw-byte scanned to EOF in bounded chunks with overlap.
Classification changes reporting only; it never skips credential patterns.
Applied families include GitHub and other token forms, generic credential
assignments, Authorization/Bearer/Basic values, credential-bearing URLs,
Cookie/Set-Cookie fields, private-key markers, session identifiers,
operational onion/bridge values, and database credential URLs.

In addition to raw-byte credential patterns and UTF-8/text patterns, every
regular file always receives four streamed ASCII credential views:
UTF-16LE alignment 0, UTF-16LE alignment 1, UTF-16BE alignment 0, and UTF-16BE
alignment 1. The first 8 KiB sample and NUL ratio affect reporting
classification only; they never gate a security view. Each view scans the full
file, including BOM-bearing and BOM-less content, carries incomplete code
units and pattern overlap across chunks, covers odd raw-byte offsets and the
final chunk, and remains bounded in memory. Files classified as binary are not
exempt. This supports raw-byte credential patterns, UTF-8/text patterns, and
UTF-16LE/BE ASCII credential forms across the full file; it is not a claim to
recognize arbitrary encodings. Read errors, short reads, mid-scan changes,
special files, links, and reparse points fail closed.

Each file record contains file size, scan classification, `rawBytesScanned`,
`encodingViewsApplied`, UTF-16LE/BE decoded-unit counts, the exact
`patternFamiliesApplied` set, and `hitCount`. For every successfully read
regular file, `rawBytesScanned` must equal its full byte length. File size never
creates an exemption and large binary files are never decoded into one
unbounded in-memory value.

## Runtime scope and remaining P3 limitation

All jobs use Python family `3.12` and Node family `24.x`. These are initial CI
runtime families only. They are not Alpha, signed runtime, release-toolchain,
production-runtime, or browser-support authority, and no exact patch is
ratified. This remains documented as CISEC-008, an accepted P3 limitation.

CISEC-009 is closed in this foundation: subprocess stdout, stderr, line length,
preview, and command-results size are all explicitly bounded, and over-limit
children fail closed.

## Historical traceability and future review receipts

HISTORICAL-TRACEABILITY:
UNRESOLVED — EXACT OLD EXECUTION ARTIFACTS NOT AVAILABLE

CURRENT ROOT CAUSE:
independently reproduced path-normalization nondeterminism

This bounded disposition does not claim that a prior review was wrong, that old
evidence never existed, or that an old signature was fabricated. Current sealed
candidate bytes have instead been reproduced in safe and JSON-escape-looking
disposable root shapes, and the path-normalization mechanism is now covered by
deterministic regression tests.

Before deleting a task-owned review root, a future independent review should
record a non-secret receipt containing the sealed candidate aggregate,
generation stdout receipt, raw `command-results.json` hash,
`observed-debt.json` hash, `summary.json` hash, canonical `summary.md` hash,
invocation identity, and the exact disposable-root shape or normalized root
category. After remote execution, the same receipt should also record the
workflow URL, run ID, job ID/name, and artifact receipt identifiers needed to
locate the sealed evidence. This is traceability guidance only: it adds no
artifact upload, workflow permission, private-content retention, or
secret-retention authority.
