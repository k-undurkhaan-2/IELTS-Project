# IELTMPS Project Roadmap

## Purpose and repository scope

`IELTS-Project` maintains the integrated IELTMPS server-backed Web Service.
IELTMPS means Interactive English Language Test Mock Practice System. The
repository's long-term responsibilities include the Server platform, production
Web UI, Server/client integration contracts, server-backed data and multi-device
services, container deployment and release integration, and related governance.
A maintainer-operated IELTMPS Hosted Service remains conditional.

Generic upstream-client development, standalone/local applications, and
private/provider-specific AI applications are externalized. Integrating and
adapting upstream-derived code for the production Web Service remains internal.
These boundaries describe intended ownership; they do not assert that separate
repositories or a dedicated IELTMPS organization already exist.

This roadmap records durable direction, major outcomes, dependencies, and
migration boundaries. Inclusion is not implementation authority or a delivery
date. It does not authorize branch reactivation, code removal, support
withdrawal, merge, promotion, release, deployment, or service launch. Public
terminology does not authorize mechanical renaming of historical runtime,
package, storage, database, container, release, or test identifiers.

Current capabilities, maturity, and limitations belong in
[Project Status](docs/STATUS.md). Exact scoped work, decisions, and acceptance
belong in GitHub Issues; Projects track live execution state; Milestones group
bounded checkpoints. Specialized policy and technical documents retain detailed
subject authority. Where a summary is stale, accepted subject-specific policies
and decisions govern; documentation reconciliation remains separate work.

| State | Meaning |
| --- | --- |
| **Established / Current** | Accepted facts or evidenced capabilities, without implying completion of related work or promotion to another baseline. |
| **Active** | Current explicit execution authority exists in an issue or maintainer direction. Live activity is tracked externally, not assigned by roadmap inclusion. |
| **Planned** | An internal strategic outcome, without an implied owner, delivery date, active implementation, or execution authorization. |
| **Conditional** | A direction requiring stated prerequisites and a separate decision before execution or operation. |
| **Externalized** | Implementation is outside long-term internal repository scope; no external repository or delivery commitment is implied. |
| **Planned deprecation / decoupling** | Intended future support or ownership change, subject to separately authorized migration and acceptance. Current removal is not implied. |
| **Exploratory** | A genuinely optional internal question, such as sustainability mechanisms, requiring a later decision. |

## Established baseline

The established foundation includes provenance-qualified upstream
`GPL-3.0-or-later` for the confirmed self-authored frontend scope, eligible
original Server `AGPL-3.0-only`, and initial mixed-license scope and attribution
in [LICENSE.md](LICENSE.md) and [NOTICE.md](NOTICE.md). It also includes the
[Security Policy](.github/SECURITY.md), GitHub Private Vulnerability Reporting,
the [Contribution Policy](CONTRIBUTING.md), and the accepted CI foundation and
rollout at their defined scope under the [CI Policy](docs/CI_POLICY.md).

These foundations do not establish complete compliance or production readiness.
Unfinished work includes the complete file/contributor provenance manifest,
third-party and content rights, shared tooling and mixed/generated-input
classification, documentation rights, release notices, corresponding source,
release-delivery evidence, wider support/governance, and documentation
reconciliation. Accepted CI rollout does not mean every retained branch adopted
CI or that every release obligation is complete.

## Development tracks

### Governance & Compliance

Planned outcomes build on the established policies:

- Complete provenance and rights inventories for retained code, dependencies,
  fonts, images, dictionaries, wordlists, generated exams and explanations,
  Listening materials, and other separately governed resources. Classify
  shared/independent tooling, mixed generated outputs and their source inputs,
  and documentation rights without assuming a blanket license.
- Complete release notices and corresponding-source obligations with the
  deployment/release track, including artifacts still distributed during
  transition. Detailed licensing and attribution remain in
  [LICENSE.md](LICENSE.md) and [NOTICE.md](NOTICE.md).
- Maintain source/rights records and review distributed educational material
  for accuracy, rights, and machine-assisted labeling under the
  [Content Policy](docs/CONTENT_POLICY.md). Externalizing AI development does
  not remove these content obligations.
- Complete documentation governance and keep the canonical English README,
  Chinese localization, status, architecture, and policy descriptions
  consistent through separately scoped reconciliation.
- Strengthen review, release, decision-making, and responsibility boundaries;
  broaden maintainer/reviewer capacity and resilience; and maintain contribution
  policy. Define release and security-support policy before representing a
  release or service as formally supported. Support durations, service-level
  agreements, owners, and review cadence require separate decisions.
- Periodically review licenses, notices, dependencies, content rights, privacy,
  security, and service sustainability. Voluntary contributions, sponsorship,
  and infrastructure assistance remain optional, exploratory mechanisms.

Public source, authorized private runtime content, learner data, and deployment
secrets must remain separate across Server, production UI/bundles, and releases.
The [Contribution Policy](CONTRIBUTING.md),
[Development Guide](docs/DEVELOPMENT.md), and content policy define the detailed
resource boundaries.

### Server Platform & Integration Contracts

This is a core Planned internal responsibility:

- Consolidate authentication and session authority, with explicit TOTP,
  step-up, account, administration, authorization/role, and protected-resource
  boundaries. Validate these boundaries with the production UI integrations.
- Establish stable, versioned Server interfaces covering schemas, errors,
  synchronization semantics, compatibility, migration/version negotiation, and
  deprecation contracts for the production Web UI and external consumers.
- Move browser-authoritative validation, grading, and durable results toward
  explicit Server authority through separately scoped migration, coordinating
  data ownership and production UI changes.
- Publish appropriate public integration artifacts with explicit version and
  artifact-level license metadata. The [API Contract Directory](api-contract/README.md)
  describes the current artifact boundary; the final format, detailed versioning
  scheme, and licenses for future artifacts require separate decisions.
- Preserve generic integration security, authentication/authorization,
  learner-data privacy and release boundaries, and contract-required rate/quota
  capability where applicable. External clients and applications may depend on
  these contracts without becoming internal implementation responsibilities.

The [Architecture](docs/ARCHITECTURE.md) and security policies hold detailed
authority and technical requirements; existing components do not by themselves
prove that authority migration or deployment assurance is complete.

### Data & Multi-device Services

Planned outcomes concern Server-owned data semantics:

- Strengthen server-backed practice records, synchronization, conflict handling,
  consistency across devices, durable state, retention, and data ownership.
- Define trusted import/export, portable data, and migration contracts that
  preserve existing records and coordinate with database backup/restore.
- Establish explicit offline/server reconciliation and fallback contracts,
  including conflict and recovery behavior during separately authorized
  transitions.

Production UI presents these states through the following track. This data
responsibility does not create a generic standalone-client development program.

### Web Service UI & Client Integration

Production Web UI remains an internal Planned responsibility of the integrated
Web Service:

- Maintain Business, Auth, and Admin surfaces, including login/registration,
  account/security, TOTP/step-up, protected-resource interactions, and
  server-backed reading/listening/practice flows.
- Integrate history/statistics, settings, data/export, and multi-device state
  presentation with Server contracts, including conflict, fallback, and
  recovery states.
- Provide responsive behavior, accessibility, navigation, and clear
  error/recovery UX across the supported service experience.
- Keep production frontend bundles and service-required upstream revisions,
  fixes, adaptations, and compatibility aligned with Server integration and
  release requirements.

These responsibilities cover the service's production frontend. Generic
upstream UI development, standalone/static client development, and unrelated
local applications are externalized. Substantial UI changes still require
their own scope and acceptance criteria.

### Containerized Deployment & Release

This is a core Planned internal track. Docker/container deployment is the
intended long-term supported application deployment model for production and
self-hosting:

- Develop reproducible Docker images and Compose delivery, with explicit
  networking, configuration, PostgreSQL integration, persistent volumes,
  migrations, and proxies where applicable.
- Make development, builds, and release delivery reproducible, with license
  and notice delivery, corresponding source, release provenance, and source
  association. Exact release receipts and migration inventories belong to
  scoped execution records.
- Document and test PostgreSQL and service backup/restore, upgrade/rollback,
  and recovery with the data track. Browser-local backups alone do not
  establish database or service recovery.

License, notice, corresponding-source, and provenance obligations also remain
for any static archives or other transitional artifacts still distributed.
Planned decoupling does not discharge those obligations.

Outside-container Node, Python, PostgreSQL, build, analysis, and test tooling
remains legitimate where appropriate. Direct bare-host application deployment
is a planned deprecation; it is not declared already unsupported. Existing
commands and Compose configuration are starting points, not proof of completed
production support. See the [Development Guide](docs/DEVELOPMENT.md).

### Conditional Hosted-Service Operations

The maintainer-operated Hosted Service is **Conditional** on the integrated
Web Service and supported container deployment. Intended maintainer-operated
business access remains Tor-only; independent self-hosters have separate
operator responsibilities under the [Service Model](docs/SERVICE_MODEL.md).

Readiness requires:

- Rights/provenance evidence, content-source records, and operational
  correction/takedown procedures.
- Security review, including security-owner review of
  [Tor deployment guidance](docs/TOR_ACCESS.md), and trusted identity/address
  verification and rotation procedures if public operation is authorized.
- Reviewed terms, privacy information, and acceptable-use rules; service limits
  and support expectations; and a defined security-support policy when support
  claims are made.
- Monitoring, incident response, abuse handling, operational transparency and
  service-status reporting, and sufficient operator capacity.
- Tested backup/recovery and upgrade/rollback, followed by evidence-based
  readiness review and separate launch authority.

Repository status, tracked configuration, and private vulnerability reporting
do not establish a launched or operationally ready service. This roadmap
promises no launch date or availability, authorizes no public onion-address
publication, and creates no public clearnet maintainer-operated service
commitment.

## Externalized and adjacent workstreams

### Generic upstream-client maintenance

**Externalized.** General upstream-client features, UI development, and
unrelated maintenance campaigns are outside long-term internal ownership.
Integration, adaptation, fixes, and compatibility needed by the IELTMPS Web
Service remain internal, including upstream-derived production frontend code.

### Standalone/local applications

**Externalized.** Standalone, desktop/local, offline-first, and pure-local
applications belong to separate workstreams. Their future repository topology
and replacement-client availability are not established by this roadmap.

### Private/provider-specific AI applications

**Externalized / out of internal repository scope.** Model-provider abstraction,
provider credentials and user-provided/managed model API applications, local AI
applications, AI UI/features, and AI application releases/deployments belong
outside this repository. AI-specific cost/quota/failure behavior and
prompt/response/provider privacy and retention move with those applications.

Only generic Server interoperability, security, authorization, privacy/data
release, versioning, and contract-required rate/quota boundaries remain internal.
Optional third-party extension applications likewise have no internal delivery
commitment. The content policy still governs material served or distributed by
the Web Service. Licensing and service policy preserve the distinction between
source-code freedoms and resource-backed service costs without selecting
providers, pricing, or AI delivery commitments.

### Potential future project organization

A dedicated IELTMPS organization is **not established**. Future coordination
or consolidation may be considered if additional repositories or an
organization actually exist. Repository creation, transfers, canonical names,
and cross-repository governance require separate decisions.

## Deprecation and migration boundaries

| Area | Current evidence and intended transition |
| --- | --- |
| `file://`, static-only, and standalone use | Current compatibility, local records/data sources, and fallback remain implemented; long-term supported scope is transitional pending planned decoupling. |
| Non-Docker production/self-host application deployment | Direct-operation paths exist as current/transitional capability; bare-host production deployment is a planned deprecation as the supported model moves to containers. |

Current capability does not by itself certify production support. **Planned
deprecation, migration in progress, and removed/unsupported are distinct
states.** Actual removal or support withdrawal requires separately authorized
migration work and accepted evidence.

That work must account for affected users and deployments, local records and
ownership, data portability, backup/restore and loss prevention, durable-state
migration, offline/server reconciliation, synchronization conflicts and
fallback, replacement-client availability where needed, and stable Server/client
contracts. Deployment changes also need an accepted container path and tested
configuration, persistence, recovery, upgrade, and rollback. Documentation
migration, release communication, support/deprecation notices, and explicit
acceptance criteria must precede changing supported operation or removing code.
No replacement client is assumed to exist.

These transitions concern application deployment and supported client scope;
they do not prohibit normal development/test tooling outside containers.

## Non-goals and current non-commitments

- **Durable boundaries:** no blanket relicensing or automatic publication of
  private content; no generic upstream-client or provider-specific AI
  application ownership; and no implementation, branch reactivation, removal,
  merge, promotion, release, deployment, or launch authority from ROADMAP alone.
- **Planned deprecations / decoupling:** standalone/static supported scope and
  non-container application deployment move through the migration gates above.
  These are future changes, not completed removals.
- **Current non-commitments:** no launch date or currently launched Hosted
  Service claim, guaranteed public onion identity, public clearnet
  maintainer-operated service commitment, provider/vendor/pricing commitment,
  AI delivery/launch commitment, established funding mechanism, legal-entity
  claim, or established IELTMPS organization. Later separately authorized
  decisions may revisit these non-commitments.

## Dependencies and execution tracking

Priorities follow dependencies without calendar promises:

1. Complete Documentation Governance Baseline v1.
2. Formalize repository/client scope separation through separately scoped work.
3. Strengthen stable Server and integration contracts.
4. Scope and close remaining provenance and release-delivery gaps.
5. Advance the supported container deployment path.
6. Perform separately authorized Server/data-authority migration, coordinated
   with production UI integration.
7. Perform standalone/non-Docker decoupling or deprecation through explicit
   migration work and acceptance.
8. Consider Hosted Service only after readiness prerequisites are satisfied.

This direction is not a waterfall and authorizes no implementation by itself.
Contract, rights, UI, and deployment work may overlap when separately
authorized; distribution always requires applicable rights evidence, and
migration gates cannot be bypassed.

Use [GitHub Issues](https://github.com/k-undurkhaan-2/IELTS-Project/issues) for
exact scope, decisions, acceptance, and evidence;
[GitHub Projects](https://github.com/k-undurkhaan-2/IELTS-Project/projects) for
live execution state; and
[GitHub Milestones](https://github.com/k-undurkhaan-2/IELTS-Project/milestones)
for bounded checkpoints. Follow the linked specialized policies and technical
documents for detailed requirements. Branch existence does not prove activity:
this roadmap does not reactivate historical, retained, paused, or deferred
branches. Any continuation needs current authority and the applicable branch
role and CI-adoption preflight.
