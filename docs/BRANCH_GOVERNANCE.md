# Branch governance

This is the canonical subject document for branch roles and integration
topology. It records the already-established persistent-domain architecture;
publication of this document does not create that architecture.
[CONTRIBUTING.md](../CONTRIBUTING.md) remains the public contribution entry
point. Use this document together with the relevant issue and maintainer
authority when choosing a contribution target.

## Active persistent branches

There are exactly six active persistent branches:

| Branch | Role |
| --- | --- |
| `main` | Canonical integrated repository baseline. |
| `dev/current-mainline` | Central cross-domain integration authority. |
| `ci/master` | CI, CI trust contract, and workflow/validator authority. |
| `docs/master` | General documentation and governance authority. |
| `ui/master` | Production Web UI and browser interaction authority. |
| `security/server-security` | Server-security and protected-resource-boundary authority. |

The four domain heads are peers: `docs/master`, `ui/master`, `ci/master`, and
`security/server-security`. Neither a branch prefix nor the existence of a
remote branch establishes active authority.

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

### Baseline refreshes require separate authority

Routine `dev/current-mainline -> domain` back-merges are not required. A domain
branch being behind `dev/current-mainline` is not itself a defect. A genuinely
necessary dev-to-domain baseline refresh requires separate explicit
authorization. This keeps persistent domains from continuously absorbing
unrelated peer-domain history.

## Historical and retained branches

Branches outside the six active persistent branches may be temporary,
historical, retained, salvage sources, manual-review holds, or deletion
candidates. Their existence does not establish present contribution authority.
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

Push CI currently covers exactly the six active persistent branches. PR
validation and exact CI trust semantics remain governed by the
[CI Policy](CI_POLICY.md). Trigger eligibility does not establish contribution
authority for historical or other noncanonical branches. See
[Development Status](STATUS.md#persistent-domain-branch-architecture) for the
accepted domain-activation evidence.

## Release and deployment boundary

Branch role does not grant release or deployment authority. Neither `main`,
`dev/current-mainline`, nor any domain head by itself authorizes production
deployment, release publication, or Hosted Service operation. Those actions
require separate authority and acceptance. This architecture introduces no
staging or production environment branches.
