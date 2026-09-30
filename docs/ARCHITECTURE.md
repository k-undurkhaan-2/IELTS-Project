# Architecture

This document describes the current high-level architecture and the approved direction of the IELTMPS Project. It intentionally omits production topology, private addresses, credentials, hidden-service material, and untracked deployment overlays.

## Current architecture

IELTMPS currently combines a substantial browser application with an independently developed server and PostgreSQL database.

`IELTS-Project` maintains this integrated server-backed Web Service, including its production Web UI. [ROADMAP.md](../ROADMAP.md) governs long-term repository scope; current browser-side implementation is not erased by that direction.

The IELTMPS Web Client owns much of the present practice experience: resource loading, question interaction, session state, scoring-related presentation, statistics, import/export, browser backup, local storage, and local fallback. The tracked browser application is delivered partly through generated bundles built from canonical source.

The IELTMPS Server provides authentication, sessions, TOTP, administration functions, protected-resource handling, and practice-record APIs. Authenticated users can store records in PostgreSQL and access them across devices connected to the same deployment.

The current architecture is therefore server-assisted rather than fully server-authoritative. Browser-side state and grading-related behavior remain significant.

## Components

### IELTMPS Web Client

The Web Client is derived from IELTS Atlas and provides the browser interface for Reading, Listening integration, suite/mock practice, records, statistics, settings, and data management.

The production Business, Auth, and Admin UI remains internal, including account/security UX, responsive/accessibility work, multi-device state presentation, Server integration, and production bundles. Generic upstream-client/UI development, standalone/static-only clients, and unrelated local applications are externalized. Upstream revisions, fixes, adaptations, and compatibility needed by the integrated service remain internal work.

It currently uses:

- Canonical JavaScript and style sources.
- Generated JavaScript bundles.
- Browser storage.
- Local data sources.
- Remote data sources for supported server APIs.
- Local fallback when some remote operations are unavailable.
- Public runtime assets and separately classified third-party assets.

Historical IELTS Atlas and IELTS Practice names remain in parts of the interface and compatibility identifiers. Their migration is separate from the public documentation identity.

### Authentication and application APIs

Tracked server routes support registration, login, logout, session management, TOTP, account actions, practice records, administrative operations, protected resources, and selected site content.

The presence of these routes does not mean every trust-sensitive decision has moved to the Server. Frontend behavior remains transitional in areas such as grading and completion state.

### IELTMPS Server

The Server is independently developed and currently runs the application APIs and serves the browser application in the server-assisted model. It applies authentication, authorization, step-up, administration, and protected-resource controls at tracked boundaries.

The approved direction is for the Server to become the authority for durable and trust-sensitive behavior. That direction requires explicit contracts, migrations, compatibility handling, and tests before the browser can stop acting as an authority.

### PostgreSQL

PostgreSQL stores tracked server-side account, session, authentication, administration, and practice-record state through repository migrations.

Server-backed practice records support authenticated multi-device access. The repository does not currently evidence a complete turnkey disaster-recovery procedure. Deployment operators must define and test backup, restore, upgrade, rollback, and retention practices.

### Protected runtime resources

Some learning resources are supplied separately from the public source tree. Public code, authorized private runtime resources, and deployment secrets are distinct delivery categories.

The application may contain integration code or a limited tracked shell without containing the complete Listening or other private content set. A public release must not include private resources or content without verified distribution permission.

### Integration contracts and external applications

Stable Server/client integration contracts are a core internal architectural objective: schemas, errors, synchronization semantics, compatibility, version negotiation, migration/deprecation contracts, and validation/grading/result authority. Server-owned data direction includes durable records, conflict handling, retention, ownership, trusted import/export, and offline/server reconciliation. Existing remote records do not establish that all these contracts are complete.

No separately versioned public contract artifact is currently published in [api-contract/](../api-contract/README.md). Future artifacts require explicit version and license metadata; their format and publication timing remain undecided.

Provider/private/local AI applications, including model-provider abstractions and AI-specific UI, credentials, costs, and retention behavior, are externalized. No product AI/model API integration is currently evidenced. Only generic Server interoperability, authentication/authorization, security, privacy/data-release, and contract-required rate/quota boundaries remain internal where applicable. Externalization does not establish an external repository or implemented replacement application.

### Tor-based service exposure

Tracked configuration separates business, administration, and authentication service roles and includes Tor-based exposure. The public business layer of the intended maintainer-operated service is designed for Tor-only access.

Tracked configuration and an internal runbook do not verify a live public service. Public Tor and deployment guidance remains subject to security-owner review. This document intentionally excludes internal routes, ports, addresses, keys, client-auth details, and private overlays.

## Approved direction

The approved integrated Web Service direction is to:

- Maintain the production Web UI and bundles for service-specific interaction, accessibility, and Server-contract integration.
- Make the IELTMPS Server authoritative for authentication, durable records, protected-resource decisions, and eventually grading and trusted results.
- Keep public source code separate from private runtime resources and injected deployment secrets.
- Preserve a clear business, administration, and authentication service boundary.
- Use Docker/container deployment as the intended long-term supported application deployment model.
- Keep a maintainer-operated Hosted Service Conditional, with intended Tor-only public business access and separate readiness/launch authority.
- Make release artifacts reproducible and accompanied by applicable licenses, notices, and corresponding source.
- Establish stable Server integration and data/multi-device contracts with explicit security, authorization, and privacy boundaries.

“Approved direction” is not a claim that each item is implemented.

## Planned migration

Migration from the current architecture requires staged work:

1. Document browser/server state ownership and conflict behavior.
2. Define server contracts for authoritative validation, grading, completion, and trusted exports.
3. Migrate durable state without silently losing local records.
4. Define intentional offline and fallback behavior.
5. Update the Web Client, Server, migrations, and tests together.
6. Preserve compatibility long enough for existing users and deployments to transition.
7. Update release, backup, restore, and operational procedures.
8. Carry out planned file/static/standalone decoupling and non-Docker application deployment deprecation only through separately authorized migration and acceptance, including replacement-client availability where needed, support notices, and release communication.

This documentation batch does not modify application behavior.

## Deployment boundaries

Docker/container deployment is the intended long-term supported application deployment model. Docker Compose is the current tracked development/self-hosting starting point, not proof of production readiness. Current file/static operation, local storage/fallback, and direct runtime paths remain transitional capability. Non-Docker application deployment is a planned deprecation; file/static/standalone use is pending planned decoupling. Actual removal or support withdrawal requires the migration and acceptance described above. Normal development and test tooling may continue outside containers. A secure public deployment requires additional reviewed configuration and operating procedures.

Public documentation must not expose:

- Production secrets or environment values.
- Private network addresses.
- Administration, authentication, or internal onion addresses.
- Hidden-service keys or client-auth credentials.
- Untracked production overlays.
- Private runtime content.

The absence of those details from public documentation is intentional.

## Historical architecture documents

Generated DeepWiki material under `developer/doc/Wiki/` records earlier architecture and implementation snapshots. Its source references are historical, and some refer to unavailable revisions or removed files.

Those documents can help with repository archaeology, but they are not the current authority. This document, the public status document, current tracked source, and reviewed governance decisions take precedence for present architecture claims.
