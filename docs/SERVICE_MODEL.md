# Service Model

## Purpose

This document describes the intended operating and sustainability model of the IELTMPS Project. It separates project direction from capabilities that are evidenced in the current repository.

IELTMPS develops software for computer-based English-language test mock practice. Under the approved future licensing model, components will be made available under their applicable licenses for use in a maintainer-operated service and independently operated third-party self-hosted deployments.

## Public-interest orientation

The project is public-interest and non-profit-oriented. Its mission is to make serious practice tooling more accessible while respecting open-source obligations, educational content rights, privacy, and service-security boundaries.

Basic public access is an intended goal of the maintainer-operated service. That goal does not establish that a public service is currently launched, that every feature will be free of operating cost, or that every learning resource can legally be published.

The public-interest orientation should be evaluated through actual access, transparency, content practices, and use of resources rather than promotional claims.

## Maintainer-operated service

The **IELTMPS Hosted Service** is the intended service operated by project maintainers.

Its public business layer is designed for Tor-only access. Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. The business onion address has not yet been published, and no public clearnet Hosted Service endpoint is currently published.

The maintainer-operated service is expected to define and maintain:

- Account, privacy, and acceptable-use information.
- Content sourcing, review, correction, and takedown processes.
- Security, monitoring, incident-response, backup, and recovery procedures.
- Clear service limits and support expectations.
- Address-verification channels.
- Separation of public source, authorized runtime content, and deployment secrets.
- Transparent descriptions of free, resource-backed, and managed capabilities.

These are readiness requirements and intended practices, not evidence that the service is live.

## Third-party self-hosting

Users may self-host software available to them under the applicable open-source licenses. A third-party self-hosted deployment is independent of the IELTMPS Hosted Service unless a separate agreement says otherwise.

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
- Managed model API access.

AI model API access is an example of a possible future paid capability, not a current product feature. A future implementation would require provider abstraction, user-provided versus managed credential boundaries, quotas, cost controls, privacy information, retention rules, failure handling, and review of generated educational output.

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
