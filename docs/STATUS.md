# Development Status

This document records what can be supported by tracked repository evidence. It does not certify a live deployment, a particular content set, or an operating environment.

## Status legend

- **Available:** implementation and supporting repository evidence are present. Deployment, content, and security conditions may still apply.
- **Active development:** substantial implementation or configuration exists, but consistency, review, or operational work remains.
- **Planned:** an approved direction exists, but the capability must not be described as complete.
- **Not currently evidenced:** the tracked repository does not support a claim that the capability or service exists now.

## Current repository state

The repository contains the IELTMPS Web Client, IELTMPS Server, PostgreSQL migrations, authentication and administration functions, protected-resource handling, generated frontend bundles, tests, and Docker Compose configurations.

The Web Client is derived from IELTS Atlas and still contains historical IELTS Atlas and IELTS Practice interface or compatibility identifiers. Runtime, package, container, database, storage, release-artifact, and test identifiers have not been mechanically renamed.

The current product combines browser-side practice logic and local fallback with server-backed accounts and practice records. The public-source tree intentionally excludes deployment secrets and some separately supplied runtime content.

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
| License and provenance governance | Active development | Initial Server AGPL and mixed-license metadata are applied; frontend scope, shared tooling, content rights, and release delivery remain unresolved |

## Planned direction

- Move trust-sensitive validation, authoritative grading, and durable result state toward the IELTMPS Server.
- Complete a reproducible public-code and authorized-private-resource delivery model.
- Establish a security-reviewed Tor-only maintainer-operated service.
- Add documented PostgreSQL backup, restore, upgrade, and rollback procedures.
- Define versioned third-party API extension points.
- Explore model-provider abstractions and managed model access only after privacy, cost, and governance boundaries are defined.
- Publish contribution, security, service, and release governance after the underlying decisions are approved.

Planned direction is not current functionality.

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

This documentation batch does not remove, disable, or deprecate those behaviors. Any change requires a separate runtime migration, compatibility analysis, and release plan.

Historical IELTS Atlas and IELTS Practice names also remain in the shipped interface and technical identifiers. Their migration is separate from adopting IELTMPS Project as the canonical public documentation identity.

## Licensing and governance

The repository is a mixed-license structure.

The IELTMPS Web Client is derived from IELTS Atlas. Locally available provenance evidence establishes GNU GPL version 3 licensing history, but the exact `only` versus `or-later` identifier and the precise frontend file scope remain unresolved. This documentation does not assign a final frontend SPDX identifier.

Eligible original IELTMPS Server files are now licensed under `AGPL-3.0-only`. The exact boundary is documented in [LICENSE.md](../LICENSE.md), with attribution and exclusions in [NOTICE.md](../NOTICE.md) and the canonical text in [LICENSES/AGPL-3.0-only.txt](../LICENSES/AGPL-3.0-only.txt).

### Completed

- Server AGPL authorization recorded.
- Canonical AGPL Version 3 license text added.
- Server package license metadata added.
- Selected eligible Server files given SPDX headers.
- Initial mixed-license scope documented.
- The proprietary API placeholder replaced.

### Still unresolved

- Frontend exact `only` versus `or-later` identifier.
- Frontend final file manifest.
- Shared-tooling classification.
- Third-party and content rights.
- Corresponding-source release delivery.
- Documentation licensing.
- Runtime source-offer UI.

The `api-contract/` placeholder now records the current factual interface-documentation state, but no separately versioned OpenAPI, Swagger, or JSON Schema contract artifact is published. The existing root `LICENSE` remains preserved and is not reinterpreted as a repository-wide declaration.

Copyright ownership remains with the respective copyright holders. Open-source permissions are granted under applicable licenses without transferring ownership. Upstream and third-party attribution must be preserved.

Software licensing does not automatically license examination questions, articles, audio, PDFs, images, explanations, fonts, dictionaries, logos, trade marks, or other separately copyrighted material.

## Hosted-service readiness

The maintainer-operated deployment is designed for Tor-only access.

**Business onion address: Not yet published**

Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. No public clearnet Hosted Service endpoint is currently published. Tracked configuration is not proof of a live or security-reviewed public service.

Before any public launch claim, the project needs security-owner review, address-verification procedures, content review and takedown processes, privacy and acceptable-use policies, recovery testing, monitoring, incident response, and abuse controls.

## Known documentation limitations

- Public deployment and detailed security guidance remain pending security-owner review.
- Generated DeepWiki documents under `developer/doc/Wiki/` are historical snapshots, not the current documentation authority.
- Older authentication and TOTP plans contain transitional assumptions.
- The historical release note does not represent current readiness.
- A complete license, notice, and content-rights inventory has not yet been published.
- The Simplified Chinese README is currently a placeholder, not a complete synchronized translation.
