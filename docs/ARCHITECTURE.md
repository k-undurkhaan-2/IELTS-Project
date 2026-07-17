# Architecture

This document describes the current high-level architecture and the approved direction of the IELTMPS Project. It intentionally omits production topology, private addresses, credentials, hidden-service material, and untracked deployment overlays.

## Current architecture

IELTMPS currently combines a substantial browser application with an independently developed server and PostgreSQL database.

The IELTMPS Web Client owns much of the present practice experience: resource loading, question interaction, session state, scoring-related presentation, statistics, import/export, browser backup, local storage, and local fallback. The tracked browser application is delivered partly through generated bundles built from canonical source.

The IELTMPS Server provides authentication, sessions, TOTP, administration functions, protected-resource handling, and practice-record APIs. Authenticated users can store records in PostgreSQL and access them across devices connected to the same deployment.

The current architecture is therefore server-assisted rather than fully server-authoritative. Browser-side state and grading-related behavior remain significant.

## Components

### IELTMPS Web Client

The Web Client is derived from IELTS Atlas and provides the browser interface for Reading, Listening integration, suite/mock practice, records, statistics, settings, and data management.

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

### Optional third-party APIs

Third-party APIs, including model providers, are future extension points rather than current product capabilities. No product AI/model API integration is currently evidenced.

A future design should isolate providers behind versioned interfaces, define user-provided versus managed credentials, apply quotas and cost controls, and establish privacy boundaries before sending learner data or content to another service.

### Tor-based service exposure

Tracked configuration separates business, administration, and authentication service roles and includes Tor-based exposure. The public business layer of the intended maintainer-operated service is designed for Tor-only access.

Tracked configuration and an internal runbook do not verify a live public service. Public Tor and deployment guidance remains subject to security-owner review. This document intentionally excludes internal routes, ports, addresses, keys, client-auth details, and private overlays.

## Approved direction

The approved server-first direction is to:

- Keep the IELTMPS Web Client focused on interaction and accessible practice UX.
- Make the IELTMPS Server authoritative for authentication, durable records, protected-resource decisions, and eventually grading and trusted results.
- Keep public source code separate from private runtime resources and injected deployment secrets.
- Preserve a clear business, administration, and authentication service boundary.
- Use Tor-only access for the maintainer-operated public business layer.
- Make release artifacts reproducible and accompanied by applicable licenses, notices, and corresponding source.
- Introduce third-party extension interfaces only with explicit privacy, security, and cost controls.

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
8. Deprecate legacy file/static behavior only through a separate reviewed change.

This documentation batch does not modify application behavior.

## Deployment boundaries

The repository supports a Docker Compose development and self-hosted path. A secure public deployment requires additional reviewed configuration and operating procedures.

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
