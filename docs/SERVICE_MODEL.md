# Service Model

## Purpose

This document describes the intended operating and sustainability model of the IELTMPS Project. It separates project direction from capabilities that are evidenced in the current repository.

`IELTS-Project` maintains the integrated IELTMPS server-backed Web Service for computer-based English-language test mock practice. Components are governed by their currently applicable licenses: provenance-qualified upstream frontend scope uses `GPL-3.0-or-later`, and eligible original Server scope uses `AGPL-3.0-only`, as defined in [LICENSE.md](../LICENSE.md) and [NOTICE.md](../NOTICE.md). This does not complete the provenance inventory or grant rights in excluded content and third-party material.

## Public-interest orientation

The project is public-interest and non-profit-oriented. Its mission is to make serious practice tooling more accessible while respecting open-source obligations, educational content rights, privacy, and service-security boundaries.

Basic public access is an intended goal of the maintainer-operated service. That goal does not establish that a public service is currently launched, that every feature will be free of operating cost, or that every learning resource can legally be published.

The public-interest orientation should be evaluated through actual access, transparency, content practices, and use of resources rather than promotional claims.

## Maintainer-operated service

The **IELTMPS Hosted Service** is a **Conditional** maintainer-operated service direction. No launch, availability, public onion identity, or public clearnet service is promised or scheduled.

Its public business layer is designed for Tor-only access. Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. The business onion address has not yet been published, and no public clearnet Hosted Service endpoint is currently published.

The maintainer-operated service is expected to define and maintain:

- Account, privacy, and acceptable-use information.
- Content sourcing, review, correction, and takedown processes.
- Security, monitoring, incident-response, backup, and recovery procedures.
- Clear service limits and support expectations.
- Address-verification channels.
- Separation of public source, authorized runtime content, and deployment secrets.
- Transparent descriptions of free, resource-backed, and managed capabilities.

These are readiness requirements and intended practices, not evidence that the service is live. Rights/provenance, security review, terms/privacy/acceptable-use policies, monitoring and incident/abuse handling, tested backup/recovery and upgrade/rollback, service/security-support limits, and operator capacity must support an evidence-based readiness review and separate launch decision under [ROADMAP.md](../ROADMAP.md).

## Third-party self-hosting

Users may self-host software available to them under the applicable open-source licenses. A third-party self-hosted deployment is independent of the IELTMPS Hosted Service unless a separate agreement says otherwise.

Docker/containerized deployment is the intended long-term supported application deployment model; Docker Compose is the current tracked starting point. Direct non-Docker application deployment remains present with planned deprecation, and current file/static/standalone use is transitional pending planned decoupling. Neither removal nor support withdrawal is complete; either requires separately authorized migration and acceptance. Development/test tooling outside containers remains legitimate. See [Development](DEVELOPMENT.md) and [Usage](USAGE.md).

Third-party operators are responsible for:

- Infrastructure, secrets, updates, backups, and incident response.
- Content permissions and attribution.
- User privacy and local legal obligations.
- Service terms, abuse controls, support, and operating costs.
- Compliance with applicable software and third-party licenses.

A third-party deployment may choose a different access model, subject to its licenses and obligations. It must not imply that it is the maintainer-operated service or endorsed by the project.

## Funding and sustainability

Operating a reliable service can require hosting, storage, bandwidth, backups, monitoring, support, content review, third-party APIs, and specialist work. Possible sources of support include:

- Voluntary contributions.
- Sponsorship.
- Donated or discounted infrastructure.
- Grants or in-kind assistance.
- Managed-service fees.
- Cost recovery for resource-intensive or third-party-backed capabilities.
- Paid support or deployment assistance.

These are possible sustainability mechanisms. The repository does not currently evidence an implemented contribution, donation, subscription, payment, or billing workflow.

Financial support should not be represented as purchasing exclusive rights to source code covered by an applicable open-source license.

## Paid capabilities

A maintainer-operated service may in the future charge for capabilities that create identifiable operating or third-party costs. Examples include:

- Managed hosting or deployment support.
- Higher resource limits.
- Resource-intensive processing.
- Specialist support.
- Third-party provider usage.

These are optional service-cost possibilities, not a selected business model or delivery commitment. Provider/private/local AI applications and managed model API applications are externalized from this repository's long-term implementation scope; they are not a promised paid IELTMPS Hosted Service capability. Generic Server interoperability, security, and privacy boundaries remain internal where applicable. The [Content Policy](CONTENT_POLICY.md) still applies to generated material served or distributed by the Web Service.

Fees would apply to operated services, external costs, resources, or support. They would not convert applicable open-source software into exclusive source code or remove recipients’ license rights.

## Open-source rights

The intended service model does not add noncommercial restrictions to software governed by GNU GPL or AGPL terms.

Recipients retain the rights granted by the applicable software license. Charging for distribution, hosting, support, or managed functionality does not itself transfer copyright ownership and does not eliminate source-code obligations.

Content and service conditions are separate. An operator may limit access to content when required by actual content rights, privacy, safety, abuse prevention, or resource constraints. Those limits must not be misrepresented as restrictions on software governed by an applicable open-source license.

## Current implementation status

Tracked repository evidence supports:

- A browser Web Client.
- Accounts, sessions, TOTP, administration, and protected-resource middleware.
- PostgreSQL-backed practice records.
- Reading and separately supplied Listening integration.
- Docker Compose development/self-hosting.
- Business, administration, and authentication service separation.
- Tor-related deployment configuration.

Tracked evidence does not currently establish:

- A launched public IELTMPS Hosted Service.
- A published business onion address.
- A public clearnet application endpoint.
- Product AI/model API integration.
- A payment, donation, subscription, or billing workflow.
- Turnkey PostgreSQL disaster recovery.
- Production-readiness certification.

See [Development Status](STATUS.md) for the complete capability classification and [Tor Access](TOR_ACCESS.md) for the public-safe access policy.

## Legal-entity disclaimer

The terms “public-interest” and “non-profit-oriented” describe project purpose and intended service priorities. They do not claim that IELTMPS has a particular incorporated, nonprofit, charitable, tax, or regulatory status.

Any future legal entity, fiscal sponsor, grant program, or fundraising arrangement must be described only after it exists and its terms are verified.
