# Contributing to the IELTMPS Project

Use this guide to plan a focused contribution and choose its pull request (PR)
target. The [Development Guide](docs/DEVELOPMENT.md) covers setup, test entry
points, generated files, and resource boundaries. The [CI Policy](docs/CI_POLICY.md)
defines validation authority. [LICENSE.md](LICENSE.md) and [NOTICE.md](NOTICE.md)
define the accepted licensing scope and provenance boundaries.

## Before starting

`IELTS-Project` maintains the integrated IELTMPS server-backed Web Service.
Internal contribution areas include the Server, production Web UI,
Server/client integration contracts, data/multi-device services, and
container/release integration. Service-required upstream-derived frontend
integration, adaptations, fixes, and compatibility work remain internal.

Generic upstream-only client/UI development, standalone/local applications,
and provider-specific AI applications are externalized from long-term internal
ownership under [ROADMAP.md](ROADMAP.md). This does not remove existing
frontend or transitional runtime code, and it does not imply that external
repositories already exist. Coordinate migration or scope-separation work
through its own issue and acceptance criteria.

Check existing issues and relevant branches for overlapping work. A focused PR
is sufficient for a small, obvious fix; a typo or trivial correction does not
need a separate issue.

Coordinate through the relevant issue before substantial changes, new features,
architecture changes, security-sensitive behavior changes, licensing or
provenance changes, public/private resource changes, or work affecting a
persistent domain. Describe the purpose and proposed scope, and confirm the target
branch with maintainers when it is unclear.

**Do not open public issues for undisclosed vulnerabilities.** Follow the
[Security Policy](.github/SECURITY.md) and use GitHub Private Vulnerability
Reporting, the repository's private reporting route. Keep exploit details and
sensitive information out of public issues, PRs, and discussions. Normal bugs
without security impact may use public issues. Changes to security-sensitive
boundaries may require additional security review.

## Choose the PR base

Choose the appropriate persistent domain for the subject being contributed.
[Branch Governance](docs/BRANCH_GOVERNANCE.md) defines the six active
persistent authority branches and the canonical integration topology.

| Branch role | Contribution target guidance |
| --- | --- |
| `main` | Canonical integrated repository baseline. Routine PRs must not target it; promotion requires separate maintainer authority. |
| `dev/current-mainline` | Central cross-domain integration authority. Direct PRs are reserved for explicitly authorized integration or explicitly coordinated work whose authority cannot correctly reside in a single existing domain. |
| `ci/master` | Target for CI, the CI trust contract, and workflow/validator work. |
| `docs/master` | Target for general documentation and governance work. |
| `ui/master` | Target for production Web UI and browser interaction work. |
| `security/server-security` | Target for server-security and protected-resource-boundary work. |
| `codex/*` | Temporary maintainer implementation branches, not persistent authorities or ordinary contribution targets. |

Start from the appropriate domain branch's current head so the PR contains the
intended work. Domain authority follows subject matter, not merely filesystem
path: `docs/CI_POLICY.md` belongs to CI, and security-sensitive Markdown does
not automatically belong to Documentation. Cross-domain changes require
explicit coordination.

A prefix alone establishes no active authority. Historical, retained,
deferred, salvage-source, and temporary branches may still exist remotely;
their existence does not make them contribution targets. Use Branch Governance
and the relevant issue or maintainer authority. In particular,
`docs/documentation-governance` is a historical audit anchor, not an active
contribution target.

The maintainer integration topology is:

```text
codex/{task}
    -> appropriate persistent domain head
    -> dev/current-mainline
    -> main
```

This describes maintainer integration. **External contributors are not required
to name branches `codex/*`.** Use a fork branch, a locally named topic branch, or
another maintainer-approved temporary branch. What matters is the PR's base.
When using a fork, select the intended branch in the upstream repository as the
PR base.

`docs/master`, `ui/master`, `ci/master`, and `security/server-security` are peer
domain authorities. Routine lateral merges are prohibited; cross-domain
integration belongs to `dev/current-mainline`. Routine dev-to-domain back-merges
are not required, and a domain being behind dev is not itself a defect. A
necessary baseline refresh requires separate explicit authorization.

Branch role does not grant release or deployment authority. `main`,
`dev/current-mainline`, and domain heads do not by themselves authorize release
publication, production deployment, or Hosted Service operation.

## Keep the scope focused

- Limit each PR to one coherent purpose; avoid unrelated cleanup or refactoring.
- Preserve existing user and maintainer work, and do not rewrite shared branch
  history.
- Explain material scope expansions and coordinate them through the relevant
  issue before including them.
- Keep generated output associated with its source change. Do not change
  generated files without the corresponding source change.
- Keep private resources and credentials out of commits and review material.

Maintainers retain merge, promotion, release, and deployment authority.

## Develop and validate

Follow the [Development Guide](docs/DEVELOPMENT.md) for the tooling and checks
appropriate to the affected area. Run the narrowest relevant validation, inspect
the complete diff (including new files), and run `git diff --check`. Check staged
changes as described in the guide, and include source/generated parity where
applicable. For documentation changes, check Markdown structure and relative
links. Report relevant validation results and any checks that could not run,
with a non-sensitive explanation.

Ensure CI passes where the target branch invokes it. The current PR workflow
filters the **base** branch: PRs into bases matching `codex/**` are excluded;
PRs into other bases are covered. Push CI covers exactly the six existing
persistent authority branches; historical retained branches may lack current CI authority.
See the [CI Policy](docs/CI_POLICY.md) for exact triggers,
profiles, evidence, and known-debt handling.

Passing CI is evidence, not merge authorization. CI trust-file changes require
independent review outside the candidate implementation worktree. Do not weaken
baselines, known-debt authority, hard gates, evidence limits, or replay semantics
merely to obtain a green run.

## Generated files

Edit canonical frontend source, run the canonical builder, and include the
required generated outputs with the source change:

```text
node scripts/build-bundles.mjs
```

Do not manually patch generated bundles. Review both source and output using
the [Development Guide](docs/DEVELOPMENT.md). Resource-dependent build profiles
are not general public workflows without confirmation of their resource boundary.

Generated educational content and data still require provenance and permission
for their source material. Generation does not erase source rights or authorize
using or publishing private content. Preserve applicable source licenses,
copyright notices, and attribution in generated outputs.

## Licensing and provenance

This is a mixed-license repository. Do not assume that one license covers every
contribution or that a file's location establishes its rights status. Follow
[LICENSE.md](LICENSE.md) and preserve the notices in [NOTICE.md](NOTICE.md):

- Applicable confirmed upstream-derived frontend source uses `GPL-3.0-or-later`,
  subject to actual provenance and the upstream authority documented in
  `LICENSE.md`. This is not a blanket license for every frontend file or asset.
- The identified eligible original IELTMPS Server scope uses `AGPL-3.0-only`.
- Third-party assets, dependencies, fonts, datasets, media, educational content,
  generated content/data, separately authored tooling, and other contributors'
  work may have separate licenses or rights status. Documentation and separately
  governed content do not receive an undocumented license merely by appearing
  in this repository.

By submitting a contribution, you must have the right to provide it for inclusion
under the licensing and rights model applicable to the target material.
Maintainers may request provenance or licensing clarification before accepting
it. For software paths whose accepted license is established, accepted
contributions must be compatible with that applicable license. Do not submit
material you lack authority to contribute. This policy creates no CLA, DCO,
copyright assignment, or blanket contributor-license agreement.

For uncertain provenance or licensing, disclose the available facts:

- Source or origin.
- Author or rightsholder, when known.
- License or permission, including any supporting reference.
- Whether the material has been modified.
- Attribution and redistribution requirements.

Identify unknowns rather than making unsupported legal conclusions. Maintainers
may reject or defer material whose provenance cannot be established.

## Keep public and private resources separate

Contributions must not include `.env` files or actual environment values,
credentials, tokens, passwords, private keys, hidden-service private material,
client-auth credentials, database dumps or backups, user data, private Listening
or other content resources, or operator-specific secrets. Private infrastructure
addresses must remain private unless explicitly intended and authorized for
publication. Use synthetic examples and redact sensitive details in PR text,
logs, screenshots, and test evidence as well as source files.

If a local test fails because private resources are absent, do not copy those
resources into the public repository to make it pass. Confirm the resource and
deployment contract with maintainers. The
[Development Guide](docs/DEVELOPMENT.md) defines the detailed boundary.

## Prepare the PR and respond to review

Make the PR easy to assess:

- Explain its purpose, scope, and meaningful behavior or documentation changes.
- Identify the related issue or workstream when applicable and the intended base
  branch.
- Disclose generated files and licensing or provenance implications.
- List relevant validation and keep secrets and private material out of evidence.
- Respond to review findings and revise the contribution when needed.

Ordinary contributors do not need an elaborate transaction receipt. Detailed
integration receipts belong to maintainer governance workflows.

Maintainers may request revisions, and security, licensing, or CI-trust changes
may require specialized review. CI success does not guarantee acceptance.
Maintainers decide the merge method and subsequent promotion. Merging into a
persistent branch is not promotion to `dev/current-mainline` or `main`; a merged
contribution may remain on its domain branch until broader integration is accepted.
