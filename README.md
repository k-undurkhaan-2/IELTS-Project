# IELTMPS Project

**Interactive English Language Test Mock Practice System**

English | [简体中文](README.zh-CN.md)

`IELTS-Project` maintains the integrated IELTMPS server-backed Web Service for computer-based English-language test mock practice.

The repository owns the IELTMPS Server, production Web UI, Server/client integration, data and multi-device services, containerized deployment/release, and governance for that integrated service. It serves public-interest service teams and independent self-hosters. A maintainer-operated Hosted Service remains **Conditional**.

> [!NOTE]
> [README.md](README.md) is the canonical English project documentation.
> The [Simplified Chinese README](README.zh-CN.md) is a machine-assisted
> localization. If the translation differs, the English source governs
> project-documentation interpretation.
>
> This notice does not replace or modify any applicable software license.
> The original English texts of the GNU licenses govern the licensed software.

> [!IMPORTANT]
> IELTMPS is an independent, unofficial project. It is not affiliated with,
> endorsed by, sponsored by, or operated by the British Council, IDP IELTS,
> Cambridge University Press & Assessment, or IELTS Partners. Do not use
> official logos or imply that IELTMPS conducts an official examination.
>
> The production Web UI includes frontend code derived from IELTS Atlas.
> The confirmed upstream maintainer's self-authored frontend scope uses
> `GPL-3.0-or-later`; eligible original IELTMPS Server scope uses
> `AGPL-3.0-only`. [LICENSE.md](LICENSE.md) and [NOTICE.md](NOTICE.md) define
> the provenance-sensitive boundaries and exclusions. The GPL option is
> settled; the complete file/contributor provenance inventory remains unfinished.
> No separately versioned API-contract artifact is currently published.
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
> The Conditional maintainer-operated Hosted Service is intended to use
> Tor-only business access. No launch, availability, or public onion identity
> is promised. The business onion address has not been published. The project
> recommends Tor Browser and intends to support it if the service launches.
> No public clearnet Hosted Service endpoint is published or committed to,
> and live operation has not been independently verified. Third-party Tor-capable browser integrations may
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
- [Contributing](CONTRIBUTING.md)
- [Security reporting](.github/SECURITY.md)
- [CI policy](docs/CI_POLICY.md)
- [Roadmap](ROADMAP.md)
- [Mixed-license scope](LICENSE.md)
- [Project notices](NOTICE.md)
- [GNU AGPL Version 3 text](LICENSES/AGPL-3.0-only.txt)

See [Licensing and governance](docs/STATUS.md#licensing-and-governance) for the current mixed-license classification and unresolved work.

## About IELTMPS

The integrated Web Service combines the production IELTMPS Web Client with the IELTMPS Server. The Web Client provides browser-based Reading, Listening, mock-practice, account, record, statistics, and data-management experiences. The Server provides authentication, session, record, administration, and protected-resource functions backed by PostgreSQL.

Production Web UI remains an internal responsibility: Business, Auth, and Admin UI; account/security UX; server-backed practice; history/statistics; settings/data interfaces; multi-device state presentation; responsive and accessibility work; Server-contract integration; and production bundles.

Generic upstream-client/UI development, standalone/static-only or unrelated local applications, and provider/private/local AI applications are **Externalized** from long-term repository ownership. The repository may consume upstream revisions, integrate fixes, adapt upstream-derived frontend source, preserve compatibility, and build service-specific UI. Externalization does not remove the current integrated frontend or its service-required integration work.

Additional repositories may later exist, and a dedicated IELTMPS organization may later be considered. No such organization is currently established, and no external repository or replacement application is assumed to exist.

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

Several implemented areas remain incomplete: Tor deployment documentation and operational consistency, public-service readiness, server-authoritative behavior, release and corresponding-source compliance, and license/provenance governance. This describes maturity, not an active implementation campaign. A public Hosted Service launch, publication of the business onion address, product AI/model API integration, payment workflows, turnkey PostgreSQL disaster recovery, and production-readiness certification are not currently evidenced. Future provider-specific AI application implementation is externalized.

## Hosted service and deployment models

IELTMPS distinguishes maintainer-operated and independently self-hosted services.

The **IELTMPS Hosted Service** is **Conditional**. Its public-interest direction, intended Tor-only business access, funding boundaries, and readiness limits are described in the [service model](docs/SERVICE_MODEL.md) and [status document](docs/STATUS.md). Rights/provenance and content review, security review, terms/privacy/acceptable-use policies, monitoring, incident/abuse handling, recovery, upgrade/rollback, support limits, and operator capacity must support a separate readiness and launch decision. No public launch is established or scheduled.

A **third-party self-hosted deployment** is operated independently by another person or organization. Self-hosters are responsible for infrastructure security, lawful content, user support, privacy notices, backups, abuse handling, and compliance with applicable software and content licenses. The project’s intended service policies do not automatically govern or endorse third-party deployments.

Docker/containerized deployment is the intended long-term supported application deployment model, with Docker Compose as the current tracked starting point. Direct non-Docker application deployment remains present but is a **planned deprecation**. File/static/standalone operation remains current transitional capability pending **planned decoupling**. Removal or support withdrawal requires separately authorized migration and acceptance; ordinary development and test tooling may continue outside containers.

## Access through Tor

The Conditional maintainer-operated service is intended to expose its public business layer through the Tor network. The project recommends Tor Browser and intends to support it if the Hosted Service launches. The business onion address is not published or guaranteed, and no public clearnet Hosted Service endpoint is published or committed to.

Other Tor-capable browsers, extensions, proxies, and integrations are unsupported. They may behave differently and are not considered privacy-equivalent to Tor Browser. If an address is published, users should verify it through a signed release announcement and another maintainer-controlled trusted channel. See [Tor access](docs/TOR_ACCESS.md).

## Architecture overview

The current architecture combines substantial browser-side practice logic with server-backed capabilities. The Web Client uses generated bundles, browser storage, local data sources, and local fallback paths. Authenticated operation can use the Server for accounts and PostgreSQL-backed practice records. Protected runtime resources are supplied separately from the public source tree.

Tracked deployment configuration separates business, administration, and authentication services, including Tor-based exposure, but live production operation has not been verified. The approved direction moves more trust-sensitive behavior—such as durable state and authoritative grading—toward the Server without pretending that this migration is already complete.

Stable Server/client integration contracts and Server-owned data/multi-device semantics are core architectural objectives; they are not claims that versioned public contract artifacts or complete synchronization behavior already exist. Provider-specific AI applications are externalized. Only generic Server interoperability, security, authorization, privacy/data-release, and contract-required rate/quota boundaries remain internal where applicable. See the [architecture overview](docs/ARCHITECTURE.md).

## Getting started

The current tracked starting point for the integrated service is Docker Compose. From the repository root, create a local backend environment file from the tracked example, review every required placeholder, and start the tracked Compose configuration:

```powershell
Copy-Item backend\.env.example backend\.env
docker compose --env-file backend\.env -f backend\docker-compose.yml up --build
```

Do not commit the resulting environment file. Do not reuse example or development credentials in an exposed deployment.

These commands are development/self-hosted starting points, not a complete production-security procedure. Internet-facing or onion-service operation requires a separate security review covering secrets, content authorization, reverse-proxy behavior, backups, monitoring, incident response, and access boundaries.

Current code still supports file/static operation, local storage and fallback, and direct runtime paths. File/static/standalone decoupling and non-Docker application deployment deprecation are planned; no removal has occurred. Any removal or support withdrawal requires a separate runtime migration, compatibility and data-preservation plan, and acceptance. See [Usage](docs/USAGE.md) for the current operating models and [Development](docs/DEVELOPMENT.md) for legitimate outside-container tooling.

## Current status

The repository contains a functional Web Client, server components, database migrations, administration and authentication features, test entry points, generated bundles, and multiple deployment configurations. These parts should not be interpreted as a verified public service or a general production certification.

The [development status](docs/STATUS.md) records available capabilities, implementation limitations, absent evidence, transitional behavior, established governance, and remaining gaps. It is the public source of truth for present capability and readiness wording. GitHub issues and Projects record execution state. G1–G5 and final closeout have established the licensing decisions and provenance boundaries, Security/PVR policy, contribution policy, Roadmap model, canonical English and Chinese documentation, and cross-document reconciliation alongside the accepted CI governance foundation. Documentation Governance Baseline v1 is complete. Promotion to integration branches remains separately governed. Governance completion does not imply product, release, or Hosted Service readiness, or completion of unresolved provenance/rights/release work.

## Roadmap

The accepted Roadmap organizes direction into development tracks:

- Governance & Compliance.
- Server Platform & Integration Contracts.
- Data & Multi-device Services.
- Web Service UI & Client Integration.
- Containerized Deployment & Release.
- Conditional Hosted-Service Operations.

It also defines externalized workstreams and deprecation/migration boundaries. Roadmap entries describe direction, not current implementation, execution authority, or release-date commitments. See [ROADMAP.md](ROADMAP.md) for the full scope and dependencies.

## Funding and sustainability

The project is public-interest and non-profit-oriented, but it does not claim a particular legal-entity or charitable status. The intended basic public-access model may be supported by voluntary contributions, sponsorship, donated infrastructure, or other operational support.

Managed hosting, infrastructure, resource-intensive processing, third-party services, and support may create real costs. Optional future service fees would cover operated services or resources, would not provide exclusive rights to applicable open-source source code, and would not change recipients’ rights under the applicable license.

These are possible sustainability mechanisms, not an established business model. Provider-specific AI applications are externalized and are not a promised paid IELTMPS capability. The repository currently provides no evidenced payment, billing, donation, or subscription workflow. See the [service model](docs/SERVICE_MODEL.md).

## Contributing

The accepted [CONTRIBUTING.md](CONTRIBUTING.md) is the public contribution entry point. It covers scope, target branches, validation, licensing/provenance, generated files, review, and the public/private resource boundary. Internal contributions include the Server, production Web UI, integration contracts, data/multi-device services, and container/release integration, including necessary upstream-derived frontend fixes.

Target the active workstream identified by the relevant issue or maintainer. External contributors may use their own branch names; `codex/*` describes temporary branches in maintainer integration workflows. Public contribution procedures are distinct from maintainer integration transactions. Contributing does not transfer copyright ownership or supply rights in third-party material by assumption.

## Security and privacy

Tracked authentication, TOTP, session, administration, protected-resource, proxy, and Tor configuration is evidence of implementation—not proof that every deployment is secure. Operators remain responsible for secrets, updates, backups, monitoring, user-data handling, network exposure, and incident response.

Never commit environment files, hidden-service keys, client-auth credentials, database exports, private runtime content, or production overlays. Public security and deployment guidance remains subject to security-owner review.

The accepted [Security Policy](.github/SECURITY.md) governs reporting. GitHub Private Vulnerability Reporting is established: open the [repository security page](https://github.com/k-undurkhaan-2/IELTS-Project/security) and select **Report a vulnerability** for an undisclosed vulnerability. Do not open a public issue for it or publish exploit details, credentials, or personal data. Use synthetic data and redact sensitive information even in a private report.

Normal non-security bugs and documentation issues may use public issues. The reporting policy makes no response-time, payment, bounty, or CVE promise; an established reporting channel does not certify service security or readiness.

## Copyright, licensing and upstream attribution

IELTMPS is a mixed-license repository. In [upstream issue #96](https://github.com/sallowayma-git/IELTS-practice/issues/96), the [maintainer confirmation](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5141381894) establishes `GPL-3.0-or-later` for the upstream maintainer's self-authored frontend source within their authority at reference revision `2a1583decb48854a6297220c64de80ec1fcfe410`. The [downstream closeout clarification](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5143866503) preserves that qualified scope. This settles the SPDX option, not the unfinished file/contributor provenance inventory.

The eligible original IELTMPS Server scope identified in [LICENSE.md](LICENSE.md) is licensed under `AGPL-3.0-only`. See the [canonical AGPL text](LICENSES/AGPL-3.0-only.txt) and [NOTICE.md](NOTICE.md). No separately versioned artifact is published in the [API-contract directory](api-contract/README.md); future artifacts require explicit version and license metadata. The existing root [GNU GPL text](LICENSE) is preserved and is not a repository-wide license declaration.

The upstream confirmation excludes third-party material, fonts, wordlists/datasets, media, educational content, generated content/data outside the maintainer's authority, private resources, other contributors' work, downstream Server code, and independently authored downstream tooling. Independently governed material retains its own terms or unresolved rights status. Frontend bundles inherit the applicable terms and notice obligations of their identified inputs; generation grants no additional rights. Complete provenance, shared-tooling and mixed-input classification, content rights, documentation rights, release notices, and corresponding-source delivery remain unfinished.

Upstream and third-party rights remain with their respective rightsholders. Open-source licenses grant permissions under their terms without transferring copyright ownership. Git authorship, repository maintenance, and distribution do not by themselves establish ownership of every included work.

See [Licensing and governance](docs/STATUS.md#licensing-and-governance) for the current decisions and unresolved work.

## Content and trade-mark notice

Software licensing does not automatically cover examination questions, articles, audio, PDFs, images, explanations, fonts, dictionaries, logos, trade marks, or separately supplied practice resources. Public-service operators and self-hosters must have an independent legal basis to use and distribute their content.

IELTS-related names and marks belong to their respective owners. IELTMPS must remain clearly independent, avoid official branding, and avoid representing practice results as certified examination results. The repository has not completed a full rights inventory for all existing content categories. See the [content policy](docs/CONTENT_POLICY.md).
