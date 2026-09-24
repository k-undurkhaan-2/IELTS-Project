# IELTMPS Project

**Interactive English Language Test Mock Practice System**

English | [简体中文（机器辅助翻译占位页）](README.zh-CN.md)

A computer-based and server-first platform for teams providing publicly accessible English-language test mock-practice services.

IELTMPS is intended for teams providing publicly accessible English-language test mock-practice services while retaining a self-hosted path for independent operators.

> [!NOTE]
> A complete Simplified Chinese translation is not yet available. The linked
> Chinese README is a machine-assisted translation placeholder for navigation
> and accessibility preparation. A full translation will be produced only
> after the English documentation and license-governance text stabilize.
> English remains the authoritative project-documentation version.
>
> This notice does not replace or modify any applicable software license.
> The original English texts of the GNU licenses govern the licensed software.

> [!IMPORTANT]
> IELTMPS is an independent, unofficial project. It is not affiliated with,
> endorsed by, sponsored by, or operated by the British Council, IDP IELTS,
> Cambridge University Press & Assessment, or IELTS Partners. Do not use
> official logos or imply that IELTMPS conducts an official examination.
>
> The current repository combines the IELTMPS Web Client, which has GPLv3-family
> upstream provenance through IELTS Atlas, with the independently developed
> IELTMPS Server. The eligible first-party Server scope is now licensed under
> `AGPL-3.0-only`; [LICENSE.md](LICENSE.md) defines that mixed-license boundary.
> The exact frontend GPL identifier remains unresolved. The former proprietary
> API-contract placeholder has been replaced, but no separately versioned
> contract artifact exists yet.
>
> Copyright ownership remains with the respective copyright holders.
> Open-source permissions are granted only under the applicable licenses;
> copyright ownership is not transferred. Software licenses do not
> automatically grant rights to questions, articles, audio, PDFs, images,
> explanations, fonts, dictionaries, logos, trade marks, or other separately
> copyrighted materials.
>
> The project is designed for public-interest and non-profit-oriented service
> teams. This is not a claim of nonprofit or charitable legal status. A
> maintainer-operated service may in the future be supported through voluntary
> contributions, sponsorship, resource-backed fees, and managed services.
> Those fees would cover operated services, third-party costs, resources, or
> support—not exclusive rights to source code. No payment, donation, or
> subscription system is currently evidenced in this repository.
>
> The maintainer-operated deployment is designed for Tor-only access. The
> public business-layer onion address has not yet been published. The IELTMPS
> Project recommends Tor Browser and intends to support it for its
> maintainer-operated Hosted Service once that service is launched. No public
> clearnet Hosted Service endpoint is currently published, and live operation
> has not been independently verified. Third-party Tor-capable browser integrations may
> work technically, but they are unsupported and are not considered
> privacy-equivalent to Tor Browser. Source code and public documentation may
> remain available through ordinary development platforms such as GitHub.

## Documentation

- [Usage](docs/USAGE.md)
- [Tor access](docs/TOR_ACCESS.md)
- [Service model](docs/SERVICE_MODEL.md)
- [Content policy](docs/CONTENT_POLICY.md)
- [Development status](docs/STATUS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Roadmap](ROADMAP.md)
- [Mixed-license scope](LICENSE.md)
- [Project notices](NOTICE.md)
- [GNU AGPL Version 3 text](LICENSES/AGPL-3.0-only.txt)

See [Licensing and governance](docs/STATUS.md#licensing-and-governance) for the current mixed-license classification and unresolved work.

## About IELTMPS

The IELTMPS Project develops the IELTMPS Web Client and IELTMPS Server as one server-first practice platform. The Web Client provides browser-based Reading, Listening, mock-practice, account, record, statistics, and data-management experiences. The Server provides authentication, session, record, administration, and protected-resource functions backed by PostgreSQL.

The currently shipped interface and several compatibility identifiers still contain historical IELTS Atlas or IELTS Practice naming. Those names are not being mechanically replaced in this documentation batch. Runtime branding, package names, container and database identifiers, browser-storage keys, release artifacts, and tests require separately planned compatibility migrations.

## Mission

IELTMPS aims to make serious computer-based English-language test practice more accessible to public-interest service teams and self-hosters. The project direction favors a server-assisted experience in which accounts, protected resources, durable records, and eventually authoritative result processing can be managed consistently across devices.

The project also keeps a clear boundary between public source code, separately authorized runtime content, and deployment secrets. Public availability of source code is not permission to redistribute every bundled or locally supplied learning resource. A sustainable service must respect both open-source obligations and the rights attached to educational content.

## Current platform capabilities

The following capabilities are available in tracked code, although their maturity and deployment requirements vary:

- A browser-based IELTMPS Web Client.
- Account registration and login.
- PostgreSQL-backed practice records and multi-device record access.
- Administration UI and API functions.
- TOTP, session management, and protected-resource middleware.
- Reading practice.
- Listening integration when separately supplied runtime content is authorized.
- Suite and mock-practice modes.
- Practice statistics.
- Data import and export.
- Browser-data backup and restore.
- Docker Compose development and self-hosted deployment.
- Tracked separation of business, administration, and authentication services.

“Available” means that implementation and supporting repository evidence are present. It does not certify a particular deployment, content set, security posture, or operating environment.

Several areas remain in active development: Tor deployment documentation and operational consistency, public-service readiness, server-authoritative behavior, release and corresponding-source compliance, and license/provenance governance. A public Hosted Service launch, publication of the business onion address, product AI/model API integration, payment workflows, turnkey PostgreSQL disaster recovery, and production-readiness certification are not currently evidenced.

## Hosted service and deployment models

IELTMPS distinguishes two deployment models.

The **IELTMPS Hosted Service** is the intended maintainer-operated service. Its public-interest direction, Tor-only access policy, funding boundaries, and readiness limits are described in the [service model](docs/SERVICE_MODEL.md) and [status document](docs/STATUS.md). The repository does not establish that this service is currently open to the public.

A **third-party self-hosted deployment** is operated independently by another person or organization. Self-hosters are responsible for infrastructure security, lawful content, user support, privacy notices, backups, abuse handling, and compliance with applicable software and content licenses. The project’s intended service policies do not automatically govern or endorse third-party deployments.

## Access through Tor

The maintainer-operated deployment is designed to expose its public business layer through the Tor network. The IELTMPS Project recommends Tor Browser and intends to support it for its maintainer-operated Hosted Service once that service is launched. The business onion address is not yet published, and no public clearnet Hosted Service endpoint is currently published.

Other Tor-capable browsers, extensions, proxies, and integrations are unsupported. They may behave differently and are not considered privacy-equivalent to Tor Browser. When an address is eventually published, users should verify it through a signed release announcement and another maintainer-controlled trusted channel. See [Tor access](docs/TOR_ACCESS.md).

## Architecture overview

The current architecture combines substantial browser-side practice logic with server-backed capabilities. The Web Client uses generated bundles, browser storage, local data sources, and local fallback paths. Authenticated operation can use the Server for accounts and PostgreSQL-backed practice records. Protected runtime resources are supplied separately from the public source tree.

Tracked deployment configuration separates business, administration, and authentication services, including Tor-based exposure, but live production operation has not been verified. The approved direction moves more trust-sensitive behavior—such as durable state and authoritative grading—toward the Server without pretending that this migration is already complete.

Future extension points may support third-party APIs, including model providers, but no product AI/model API integration is currently evidenced. See the [architecture overview](docs/ARCHITECTURE.md).

## Getting started

The recommended starting point is a server-assisted development or self-hosted environment. From the repository root, create a local backend environment file from the tracked example, review every required placeholder, and start the tracked Compose configuration:

```powershell
Copy-Item backend\.env.example backend\.env
docker compose --env-file backend\.env -f backend\docker-compose.yml up --build
```

Do not commit the resulting environment file. Do not reuse example or development credentials in an exposed deployment.

These commands are development/self-hosted starting points, not a complete production-security procedure. Internet-facing or onion-service operation requires a separate security review covering secrets, content authorization, reverse-proxy behavior, backups, monitoring, incident response, and access boundaries.

Current code still supports direct file and static operation. That behavior is transitional compatibility, not the long-term primary product direction. Removing or deprecating it requires a separate runtime migration; this documentation rewrite does not remove or disable it. See [Usage](docs/USAGE.md) for the current operating models.

## Current status

The repository contains a functional Web Client, server components, database migrations, administration and authentication features, test entry points, generated bundles, and multiple deployment configurations. These parts should not be interpreted as a verified public service or a general production certification.

The [development status](docs/STATUS.md) records available capabilities, active work, planned direction, absent evidence, legacy behavior, governance limits, and documentation gaps. It is the public source of truth for readiness wording in this documentation set.

## Roadmap

Near-term work focuses on identity and license governance, server stabilization, protected-resource boundaries, reproducible delivery, and release compliance. Later phases cover public-service policy, stable Tor access, extensibility, model-provider abstractions, cost controls, community governance, and sustainable operations.

Roadmap entries describe direction rather than release-date commitments. Planned features are not current features. See [ROADMAP.md](ROADMAP.md).

## Funding and paid capabilities

The project is public-interest and non-profit-oriented, but it does not claim a particular legal-entity or charitable status. The intended basic public-access model may be supported by voluntary contributions, sponsorship, donated infrastructure, or other operational support.

Managed hosting, resource-intensive processing, third-party services, support, and future model-provider access may create real costs. A maintainer-operated service may charge for those services or resources. Such fees would not provide exclusive rights to the applicable open-source source code and would not change the recipient’s rights under the applicable license.

AI model API access is one possible future paid capability. It is not a current product feature. The repository currently provides no evidenced billing, donation, or subscription workflow. See the [service model](docs/SERVICE_MODEL.md).

## Contributing direction

Contribution procedures will be formalized after license scope, notices, and governance responsibilities are settled. Until then, prospective contributors should keep changes focused, preserve the public/private resource boundary, avoid adding content without documented permission, and avoid manually editing generated bundles.

Contributors must not assume that adding a file transfers copyright ownership. Future contribution guidance will explain the applicable license, provenance expectations, generated-file rules, review gates, and treatment of third-party material.

## Security and privacy

Tracked authentication, TOTP, session, administration, protected-resource, proxy, and Tor configuration is evidence of implementation—not proof that every deployment is secure. Operators remain responsible for secrets, updates, backups, monitoring, user-data handling, network exposure, and incident response.

Never commit environment files, hidden-service keys, client-auth credentials, database exports, private runtime content, or production overlays. Public security and deployment guidance remains subject to security-owner review.

A dedicated confidential vulnerability-reporting channel has not yet been published. Until one is established, do not place exploit details, credentials, personal data, or other sensitive material in a public issue. A reporter may open a minimal, non-sensitive issue asking the maintainers to establish private contact, without disclosing the vulnerability itself.

Establishing and documenting a verified confidential reporting channel is required before public-service or security-readiness sign-off. The detailed reporting policy belongs to the future security-governance phase.

## Copyright, licensing and upstream attribution

IELTMPS is a mixed-license repository. The IELTMPS Web Client has GPLv3-family upstream provenance through IELTS Atlas. The exact “only” versus “or-later” identifier and the precise frontend file scope remain unresolved.

The eligible original IELTMPS Server scope identified in [LICENSE.md](LICENSE.md) is licensed under `AGPL-3.0-only`. See the [canonical AGPL text](LICENSES/AGPL-3.0-only.txt) and [NOTICE.md](NOTICE.md). The proprietary API-contract placeholder has been replaced, but no versioned contract artifact is published. The existing root `LICENSE` is preserved, and no final frontend SPDX identifier is assigned by this change.

Upstream and third-party rights remain with their respective rightsholders. Open-source licenses grant permissions under their terms without transferring copyright ownership. Git authorship, repository maintenance, and distribution do not by themselves establish ownership of every included work.

See [Licensing and governance](docs/STATUS.md#licensing-and-governance) for the current decisions and unresolved work.

## Content and trade-mark notice

Software licensing does not automatically cover examination questions, articles, audio, PDFs, images, explanations, fonts, dictionaries, logos, trade marks, or separately supplied practice resources. Public-service operators and self-hosters must have an independent legal basis to use and distribute their content.

IELTS-related names and marks belong to their respective owners. IELTMPS must remain clearly independent, avoid official branding, and avoid representing practice results as certified examination results. The repository has not completed a full rights inventory for all existing content categories. See the [content policy](docs/CONTENT_POLICY.md).
