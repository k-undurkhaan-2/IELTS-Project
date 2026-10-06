# Branch governance

This is the canonical subject document for branch roles, integration topology,
and baseline refresh. It records the established persistent-domain architecture
and defines policy for a future preview channel and local workspaces. Policy
definition does not activate a remote ref, configure protection, implement
automation, create a workspace, or authorize deployment.
[CONTRIBUTING.md](../CONTRIBUTING.md) remains the public contribution entry
point. Use this document together with the relevant issue and maintainer
authority when choosing a contribution target.

## Persistent authority branches

There are exactly six active **persistent authority branches**:

| Branch | Role |
| --- | --- |
| `main` | Canonical integrated repository baseline. |
| `dev/current-mainline` | Central continuous cross-domain integration authority. |
| `ci/master` | CI, CI trust contract, and workflow/validator authority. |
| `docs/master` | General documentation and governance authority. |
| `ui/master` | Production Web UI and browser interaction authority. |
| `security/server-security` | Server-security and protected-resource-boundary authority. |

There are exactly four peer subject domains: `docs/master`, `ui/master`, `ci/master`, and
`security/server-security`. Neither a branch prefix nor the existence of a
remote branch establishes active authority.

### Long-lived non-authoritative channels

`LONG_LIVED_NON_AUTHORITATIVE_CHANNEL` is a separate ref class. The planned
`deploy/preview` belongs to this class; it is not a fifth peer subject domain,
a development authority, a canonical branch, or a production branch. A
long-lived channel does not increase the six-branch authority count.
Historical retained refs are a separate classification again.

## Authority follows subject matter

Domain authority is determined by subject matter, not merely by filesystem
path. For example, `docs/CI_POLICY.md` remains CI-subject material even though
it is under `docs/`. Security-sensitive policy and server-authentication
semantics are not automatically Documentation-domain work merely because the
changed file is Markdown.

Cross-domain changes require explicit coordination among the affected domain
owners. Do not use a documentation path or file extension to bypass the
authority responsible for the subject.

## Integration and contribution targets

The canonical maintainer integration topology is:

```text
codex/{task}
    -> appropriate persistent domain head
    -> dev/current-mainline
    -> main
```

`codex/*` denotes temporary maintainer implementation branches, not persistent
authority. External contributors are not required to use the `codex/*`
namespace; their PR base must still follow the contribution rules.

Ordinary work starts from and targets the current head of the appropriate
persistent domain. Direct PRs to `dev/current-mainline` are reserved for
explicitly authorized integration or explicitly coordinated work whose
authority cannot correctly reside in a single existing domain. Routine PRs
must not target `main`. Merge and subsequent promotion require their own
maintainer authority; a successful check or domain merge does not authorize
the next step.

### Peer domains do not integrate laterally

Routine lateral merges between peer domains are prohibited. Flows such as
`docs/master -> ui/master`, `ui/master -> security/server-security`, and
`ci/master -> docs/master` are not the integration model. Cross-domain
integration belongs to `dev/current-mainline`.

## Continuous dev integration and blocking obligations

The role of `dev/current-mainline` is
`CENTRAL_CONTINUOUS_CROSS_DOMAIN_INTEGRATION_AUTHORITY`. Its current head is not
automatically deployment-ready, preview-ready, main-ready, or release-ready.

A dev state may be classified as `PARTIAL_INTEGRATION` when all of these hold:

```yaml
domain_change_integrated: true
related_cross_domain_followup_pending: true
blocking_obligation_explicitly_tracked: true
required_dev_checks_pass: true
```

This is a valid integration state provided required integration validation
passes and the sequential state is technically valid and safe under the atomic
threshold below. It is not automatically an eligible deployment or promotion
state.

A `BLOCKING_INTEGRATION_OBLIGATION` is an explicitly tracked cross-domain
follow-up that must be satisfied before the affected dev state can become
eligible for preview, main promotion, or deployment. Record the affected change
and dev state, the responsible subject authority, the required follow-up, and
the evidence needed to close the obligation. Domain acceptance alone does not
close a pending dev convergence obligation. Close it only after the required
follow-up has integrated and its acceptance evidence is recorded.

While the blocking-obligation count is greater than zero:

```yaml
preview_eligible: false
main_promotion_eligible: false
deployment_eligible: false
dev_integration_valid: true # Only if required integration validation passes.
```

Zero obligations is necessary, but does not replace validation or separately
granted promotion, release, or deployment authority.

### Sequential follow-up is the normal option

Cross-domain follow-up does not automatically require atomic integration.
Examples include a UI change plus a README update, security behavior plus a
runbook update, or backend behavior plus general documentation. Subject
authority and required validation still apply to each change.

The normal sequence may be:

```text
Domain A -> dev/current-mainline, with a blocking obligation recorded
Domain B -> dev/current-mainline, then close the satisfied obligation
```

The obligation must be explicit when the partial integration is accepted;
there must be no untracked interval of apparent promotion eligibility.

### Exceptional coordinated atomic integration

Coordinated atomic integration should be required only where sequential
integration would make dev technically invalid or materially unsafe. Technical
triggers include:

- Required CI fails.
- The repository cannot build or the runtime becomes unusable.
- A schema or migration and its consumer must switch together.
- API compatibility is broken.
- Security protection actually regresses.
- A repository contract explicitly requires an atomic transition.

Documentation lag by itself is not automatically a technical atomicity
condition. A blocking obligation cannot waive a required check or make an
unsafe intermediate state acceptable. Necessary atomic work still requires
explicit coordination and integration authority.

### U03 and Issue #64 policy transition

The earlier general `COORDINATED_ATOMIC_DEV_INTEGRATION` recommendation for
Security U03 plus Docs [Issue #64](https://github.com/k-undurkhaan-2/IELTS-Project/issues/64)
is superseded **as the default policy direction before execution**. The
proposed atomic integration branch was never created and remains unexecuted.
The preflight itself is not invalidated: its Git and topology findings, and
all historical evidence, remain evidence. The changed conclusion is governance
interpretation: partial dev integration may be valid when explicitly blocked
from preview, main promotion, and deployment.

Issue #64 remains open with cross-domain convergence pending. This amendment
does not modify or reclassify the issue, integrate Security or Docs into dev,
create an integration candidate, or close the obligation. Convergence will be
replanned after governance amendment acceptance, using the validation and
technical atomicity threshold above.

## Future experimental preview channel

The planned channel has this policy definition:

```yaml
branch: deploy/preview
ref_class: LONG_LIVED_NON_AUTHORITATIVE_CHANNEL
role: LONG_LIVED_NON_AUTHORITATIVE_EXPERIMENTAL_DEPLOYMENT_CHANNEL
development_authority: none
subject_authority: none
production_authority: false
activation: NOT_YET_PERFORMED
```

The remote ref has not been created. Its future protection and activation are
separately governed. The only normal source is an eligible exact
`dev/current-mainline` SHA:

```text
eligible dev/current-mainline SHA -> deploy/preview
```

Normal flows from `codex/{task}` or a domain directly to `deploy/preview` are
prohibited. Reverse flows from `deploy/preview` to a domain,
`dev/current-mainline`, or `main` are prohibited. Preview is a side deployment
channel; it is not an intermediate step in canonical source promotion.

Minimum preview eligibility is:

```yaml
source:
  branch: dev/current-mainline
blocking_integration_obligations:
  count: 0
required_integration_validation: PASS
preview_promotion_authority: separately_granted
```

Eligibility and validation must refer to the exact source SHA selected for
promotion. The exact workflow checks remain future CI/deployment implementation
under `CI_DOMAIN_FOLLOWUP`; passing these policy conditions does not itself
authorize deployment.

### Persistent local preview workspace

After remote activation, `deploy/preview` will have a persistent local
workspace with role `PERSISTENT_DEPLOYMENT_WORKSPACE`. It serves deployment,
not development. The workspace tracks only `origin/deploy/preview`. Its normal
synchronization is:

```sh
git fetch origin
git switch deploy/preview
git merge --ff-only origin/deploy/preview
```

An equivalent `pull --ff-only` is allowed. Before deployment require
`HEAD == origin/deploy/preview` after fetching, and a clean tracked worktree.
If synchronization cannot fast-forward, stop and require explicit workspace
reconciliation; do not automatically merge divergent history, rebase, run
`reset --hard`, or discard commits.

Within this workspace, prohibit tracked-source feature edits and bug fixes,
normal development commits, task branches originating from preview,
development merges, rebases for feature work, preview-only source patches, and
reverse promotion into dev or a domain. A defect detected in preview follows:

```text
detect in preview
    -> return to the correct subject domain
    -> domain implementation
    -> dev integration
    -> new eligible preview promotion
```

The filesystem is not completely read-only. Tracked repository content must
not receive development mutations or development commits. Deployment tooling
may write runtime state such as build outputs, CLI caches, temporary deployment
packages, local logs, deployment receipts, and Docker exports. Such state must
be ignored, external, temporary, or otherwise excluded from tracked source;
it must not leave tracked repository content modified. Deployment secrets
must not become Git-tracked repository content. Full secret-delivery
architecture is outside this amendment.

## Canonical domain baseline refresh

The default persistent-domain refresh source is `main`:

```text
main -> docs/master
main -> ui/master
main -> ci/master
main -> security/server-security
```

Refresh imports an accepted canonical baseline under separately granted
authority. It is distinct from development integration and preview promotion.
Routine `dev/current-mainline -> domain` refresh is prohibited and not required;
a domain being behind dev is not itself a defect. An exceptional baseline
dependency on dev requires separate explicit authorization because dev may
legally contain partial integration state.

### Future conditional automation

Automatic `main -> domain` refresh is future policy, not an implemented
workflow. Minimum eligibility requires all of these conditions:

```yaml
source: main
target_domain_head_is_ancestor_of_main: true
open_conflicting_PR_targeting_domain: false
concurrent_refresh: false
source_main_state:
  accepted: true
```

At minimum, any open PR targeting the domain prevents or defers automated
refresh, conservatively satisfying the conflicting-PR condition. Open-PR
detection does not prove the absence of unpublished local work; future
implementation may introduce stronger activity signals. Eligibility must be
rechecked against the actual source and target heads before applying a
fast-forward refresh; a concurrent change requires a new preflight.

If the domain head is not an ancestor of the selected accepted `main` head,
automatic refresh is prohibited. Return the manual classification
`DOMAIN_HAS_UNPROMOTED_OR_DIVERGED_HISTORY`. Divergence requires manual preflight;
automation must never resolve it by force push, reset, automatic rebase,
automatic conflict resolution, automatic merging of domain-only history, or
dropping domain commits.

A schedule means a **periodic eligibility check**, not periodic unconditional
synchronization. A future implementation may check daily and/or allow manual
dispatch. No refresh is required when eligibility is false or no new canonical
baseline exists. This document does not create a schedule or workflow.

No ruleset bypass is authorized by this policy. Any future automation identity
privileges require separate authorization, least privilege, an auditable
record, and a scope bounded to baseline refresh. Future CI implementation
belongs to `ci/master`; repository configuration remains separately governed.

## Local persistent workspace policy

The intended logical topology is:

| Workspace | Role |
| --- | --- |
| `control` | `GOVERNANCE_ORCHESTRATION` |
| `main` | `CANONICAL_BASELINE_WORKSPACE` |
| `dev` | `PERSISTENT_INTEGRATION_WORKSPACE` |
| `docs` | `PERSISTENT_DOMAIN_WORKSPACE` |
| `ui` | `PERSISTENT_DOMAIN_WORKSPACE` |
| `ci` | `PERSISTENT_DOMAIN_WORKSPACE` |
| `security` | `PERSISTENT_DOMAIN_WORKSPACE` |
| `preview` | `PERSISTENT_DEPLOYMENT_WORKSPACE` |

This is a conceptual topology, not a claim that local normalization or the
preview workspace has been created. Local workspace normalization is
separately governed.

Before new domain work, synchronize the persistent domain workspace:

```text
git fetch origin
git switch <persistent-domain>
git merge --ff-only origin/<persistent-domain>
```

Require `HEAD == origin/<persistent-domain>` and a clean working tree before
creating a new task branch or worktree. If synchronization cannot fast-forward,
**STOP** and require explicit workspace reconciliation. Do not automatically
merge divergent history, rebase, run `reset --hard`, or discard commits. A
dirty working tree or local-ahead head also fails the pre-task conditions;
preserve the work for reconciliation even if Git reports nothing to merge.

## Three distinct flows

| Operation | Direction |
| --- | --- |
| Development and canonical source promotion | `task -> subject domain -> dev/current-mainline -> main` |
| Canonical baseline refresh | `main -> subject domain` |
| Experimental deployment promotion | `eligible dev SHA -> deploy/preview` |

These operations must not be conflated. In particular,
`dev -> preview -> main` is not the source-control promotion chain.

## Historical and retained branches

Other existing refs may be temporary, historical, retained, salvage sources,
manual-review holds, or deletion candidates. These are distinct from the
planned long-lived non-authoritative channel class. Their existence does not
establish present contribution authority.
A prefix alone establishes no active authority; use this document and the
relevant issue or maintainer authority instead of inferring a target from a
historical name.

### Documentation governance audit anchor

The historical ref `docs/documentation-governance` has the frozen identity
`372589135a74c23067334876e2736c9d32eef657`. Its status is:

```text
HISTORICAL_AUDIT_ANCHOR
NOT_AN_ACTIVE_CONTRIBUTION_TARGET
```

The intended archive semantic, `ARCHIVED / RETAINED / READ_ONLY`, means:

- Preserve the historical ref and its frozen identity.
- Reject ordinary new development.
- Do not use it as a routine promotion source.
- Protect it against deletion and force-push.
- Retain it as evidence and audit history.

Actual archive-protection mutation: **NOT YET PERFORMED**. These semantics
describe the intended archive state, not a claim that protection has already
been applied. The later archive transaction remains separately governed.

## CI relationship

Push CI currently covers the six existing persistent authority branches. PR
validation and exact CI trust semantics remain governed by the
[CI Policy](CI_POLICY.md). Trigger eligibility does not establish contribution
authority for historical or other noncanonical branches. See
[Development Status](STATUS.md#persistent-domain-branch-architecture) for the
accepted domain-activation evidence.

Future preview/refresh CI requirements are `CI_DOMAIN_FOLLOWUP`. This amendment
does not change `docs/CI_POLICY.md`, Actions, CI triggers, or rulesets. The
existing CI allowlist is a current implementation fact, not evidence that a
future preview or refresh workflow already exists.

## Release and deployment boundary

Branch role does not grant release or deployment authority. Neither `main`,
`dev/current-mainline`, nor any domain head by itself authorizes production
deployment, release publication, or Hosted Service operation. Those actions
require separate authority and acceptance. The future experimental preview
channel grants no production authority; its remote activation and every
deployment require separately governed work.

## Separately governed follow-up sequence

After this amendment receives Documentation-domain acceptance, later work is
ordered as follows, each under its own authority:

1. `REMOTE_PERSISTENT_TOPOLOGY_COMPLETION`: create `deploy/preview`, establish
   protection, and validate its non-authority role.
2. `LOCAL_PERSISTENT_WORKSPACE_NORMALIZATION`: establish the intended control,
   main, dev, docs, UI, CI, Security, and preview workspace topology.
3. `ISSUE_64_SEQUENTIAL_DEV_CONVERGENCE_REPLAN`: replan convergence under the
   partial-integration and blocking-obligation model.
4. `AUTOMATION_IMPLEMENTATION`: implement conditional main-to-domain refresh
   and eligible-dev-to-preview promotion/deployment under the relevant CI and
   deployment authority.
5. `HISTORICAL_ARCHIVE_AND_LEGACY_CLEANUP`: act only when existing salvage and
   archive prerequisites permit.

No later phase starts automatically through this policy amendment.
