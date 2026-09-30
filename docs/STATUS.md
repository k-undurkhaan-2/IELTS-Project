# Development Status

This document records what can be supported by tracked repository evidence. It does not certify a live deployment, a particular content set, or an operating environment.

## Status legend

- **Available:** implementation and supporting repository evidence are present. Deployment, content, and security conditions may still apply.
- **Active development:** a maturity label for substantial implementation or configuration with remaining consistency, review, or operational work. It does not mean an active implementation campaign; GitHub issues and Projects establish execution state, and the Roadmap's **Active** state requires explicit current authority.
- **Planned:** an approved direction exists, but the capability must not be described as complete.
- **Not currently evidenced:** the tracked repository does not support a claim that the capability or service exists now.

## Current repository state

The repository contains the IELTMPS Web Client, IELTMPS Server, PostgreSQL migrations, authentication and administration functions, protected-resource handling, generated frontend bundles, tests, and Docker Compose configurations.

The Web Client is derived from IELTS Atlas and still contains historical IELTS Atlas and IELTS Practice interface or compatibility identifiers. Runtime, package, container, database, storage, release-artifact, and test identifiers have not been mechanically renamed.

The current product combines browser-side practice logic and local fallback with server-backed accounts and practice records. The public-source tree intentionally excludes deployment secrets and some separately supplied runtime content.

The repository maintains the integrated server-backed Web Service. Long-term internal ownership includes the Server, production Web UI, Server/client integration contracts, data/multi-device services, and containerized deployment/release. Generic upstream-client development, standalone/local applications, and provider/private/local AI applications are externalized; this does not remove current code or imply that replacement repositories exist. [ROADMAP.md](../ROADMAP.md) governs direction.

## Available capabilities

| Capability | Status | Qualification |
|---|---|---|
| Browser IELTMPS Web Client | Available | Tracked interface, source, generated bundles, and tests are present |
| Registration and login | Available | Authentication routes, client integration, and tests are tracked |
| PostgreSQL practice records | Available | Database migrations and record APIs are tracked |
| Multi-device record access | Available | Authenticated remote records exist alongside local fallback |
| Administration UI and API | Available | Administration functions and access controls are tracked |
| TOTP | Available | Implementation, migrations, and tests are tracked |
| Session management | Available | Account and administrative session functions are tracked |
| Protected-resource middleware | Available | Protected-resource routing and tests are tracked |
| Reading practice | Available | Reading data, interface, and test evidence are tracked |
| Listening integration | Available | Requires separately supplied content with verified authorization |
| Suite/mock-practice mode | Available | Practice-session and suite implementation is tracked |
| Statistics | Available | Learner and administration statistics functions are tracked |
| Import/export | Available | Browser and server-backed data-management paths are tracked |
| Browser-data backup and restore | Available | Browser backup implementation and tests are tracked |
| Docker Compose development/self-hosting | Available | Tracked Compose and container configuration exists |
| Business/admin/auth separation | Available | Separation is tracked in code and configuration; live production operation is not verified |
| File/static operation | Available | Transitional compatibility remains implemented |

## Active development

| Area | Status | Current limitation |
|---|---|---|
| Tor deployment | Active development | Tracked configuration and an internal runbook exist, but public guidance and operational consistency need security-owner review |
| Public-service readiness | Active development | Policies, recovery, monitoring, content review, and operational evidence remain incomplete |
| Server-authoritative behavior | Active development | Substantial grading and practice logic remains browser-side |
| Release compliance | Active development | License notices, corresponding source, and stronger release evidence remain to be completed |
| License and provenance governance | Active development | Qualified upstream GPL and eligible Server AGPL identifiers are settled; the complete file/contributor manifest, shared tooling, mixed/generated inputs, content rights, and release delivery remain unresolved |

## Planned direction

The accepted [Roadmap](../ROADMAP.md) uses development tracks for Governance & Compliance, Server Platform & Integration Contracts, Data & Multi-device Services, Web Service UI & Client Integration, Containerized Deployment & Release, and Conditional Hosted-Service Operations. It owns the detailed objectives and dependencies.

Server authority migration, stable versioned integration artifacts, stronger synchronization/fallback contracts, reproducible delivery, and tested database recovery remain objectives, not completed capabilities. Docker/containerized deployment is the intended long-term supported application deployment model. Hosted Service is **Conditional**, with intended Tor-only business access and separate readiness/launch authority. Provider-specific AI applications are outside this repository's long-term implementation scope; generic Server interoperability/security/privacy boundaries remain internal where applicable.

## Not currently evidenced

| Claim or capability | Status |
|---|---|
| Public IELTMPS Hosted Service launch | Not currently evidenced |
| Published public business onion address | Not currently evidenced |
| Public clearnet Hosted Service endpoint | Not currently evidenced |
| Product AI/model API integration | Not currently evidenced |
| Payment workflow | Not currently evidenced |
| Donation workflow | Not currently evidenced |
| Subscription or billing workflow | Not currently evidenced |
| Turnkey PostgreSQL disaster recovery | Not currently evidenced |
| Production-readiness certification | Not currently evidenced |
| Complete rights clearance for all bundled content categories | Not currently evidenced |

## Legacy and transitional compatibility

Direct file and static operation remain available in the current codebase. Local storage, local data sources, and remote-to-local fallback are also present. These paths support existing users and environments, but they are transitional compatibility rather than the long-term primary product direction.

Direct non-Docker runtime paths also exist, including the local backend workflow in the [Development Guide](DEVELOPMENT.md). Docker Compose development/self-hosting remains available. Containerized application deployment is the intended long-term supported model; non-Docker production/self-host application deployment is a **planned deprecation**, and file/static/standalone scope is pending **planned decoupling**. No removal or support withdrawal has occurred through this reconciliation. Actual changes require separately authorized migration, compatibility and data-preservation analysis, release communication, and acceptance. Development/test tooling outside containers remains legitimate.

Historical IELTS Atlas and IELTS Practice names also remain in the shipped interface and technical identifiers. Their migration is separate from adopting IELTMPS Project as the canonical public documentation identity.

## Licensing and governance

The repository is a mixed-license structure.

The IELTMPS Web Client is derived from IELTS Atlas. [Upstream issue #96](https://github.com/sallowayma-git/IELTS-practice/issues/96), its [maintainer confirmation](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5141381894), and [downstream closeout clarification](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5143866503) establish `GPL-3.0-or-later` for the confirmed upstream maintainer's self-authored frontend scope within their authority. The settled option does not complete the downstream file/contributor manifest or license excluded third-party assets, fonts, datasets, media, educational/generated content outside that authority, private resources, other contributors' work, or independently governed material. [LICENSE.md](../LICENSE.md) and [NOTICE.md](../NOTICE.md) retain the exact boundaries.

Eligible original IELTMPS Server files are now licensed under `AGPL-3.0-only`. The exact boundary is documented in [LICENSE.md](../LICENSE.md), with attribution and exclusions in [NOTICE.md](../NOTICE.md) and the canonical text in [LICENSES/AGPL-3.0-only.txt](../LICENSES/AGPL-3.0-only.txt).

### Established in the governance baseline

- Server AGPL authorization recorded.
- Canonical AGPL Version 3 license text added.
- Server package license metadata added.
- Selected eligible Server files given SPDX headers.
- Initial mixed-license scope documented.
- The proprietary API placeholder replaced.
- Provenance-qualified upstream `GPL-3.0-or-later` confirmed, with exclusions preserved.
- [Security reporting policy](../.github/SECURITY.md) and GitHub Private Vulnerability Reporting established.
- [Contribution policy](../CONTRIBUTING.md) accepted.
- CI foundation and rollout accepted at their defined scope under [CI Policy](CI_POLICY.md); this does not imply adoption by every retained branch.
- G4 Roadmap development-track and repository-scope model accepted.

Documentation Governance Baseline v1 is not yet complete: G5 canonical/localized documentation acceptance and cross-document closeout remain required. Acceptance on the governance branch does not imply promotion to other branches.

### Still unresolved

- Complete frontend file/contributor provenance manifest.
- Shared-tooling classification.
- Mixed/generated-input classification and notice delivery.
- Third-party and content rights.
- Corresponding-source release delivery.
- Documentation licensing.
- Runtime source-offer UI.

The `api-contract/` placeholder now records the current factual interface-documentation state, but no separately versioned OpenAPI, Swagger, or JSON Schema contract artifact is published. The existing root `LICENSE` remains preserved and is not reinterpreted as a repository-wide declaration.

Copyright ownership remains with the respective copyright holders. Open-source permissions are granted under applicable licenses without transferring ownership. Upstream and third-party attribution must be preserved.

Software licensing does not automatically license examination questions, articles, audio, PDFs, images, explanations, fonts, dictionaries, logos, trade marks, or other separately copyrighted material.

## Hosted-service readiness

The maintainer-operated Hosted Service remains **Conditional**, with intended Tor-only business access. No launch date, availability, public onion identity, or public clearnet service is promised.

**Business onion address: Not yet published**

Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. No public clearnet Hosted Service endpoint is currently published. Tracked configuration is not proof of a live or security-reviewed public service.

Before any public launch claim, the project needs rights/provenance evidence, security-owner review, address-verification procedures, content correction/takedown processes, terms/privacy/acceptable-use policies, backup/recovery and upgrade/rollback testing, monitoring, incident response, abuse controls, support/security-support limits, operator capacity, and a separate evidence-based readiness and launch decision.

## Known documentation limitations

- Public deployment and detailed security guidance remain pending security-owner review.
- Generated DeepWiki documents under `developer/doc/Wiki/` are historical snapshots, not the current documentation authority.
- Older authentication and TOTP plans contain transitional assumptions.
- The historical release note does not represent current readiness.
- A complete license, notice, and content-rights inventory has not yet been published.
- The [Chinese README](../README.zh-CN.md) is a localization; [README.md](../README.md) remains the canonical English project-documentation authority.
