# IELTMPS Project Roadmap

This roadmap describes the direction of the IELTMPS Project. It is not a release schedule, a promise of delivery dates, or evidence that a planned capability is already available. Priorities may change after technical, legal, security, content-rights, or operational review.

Internal worktree names, branch names, pull-request numbers, private deployment details, and credentials are intentionally excluded.

## Phase 0 – Identity and license governance

Establish a stable public foundation for the project:

- Adopt IELTMPS Project, Interactive English Language Test Mock Practice System, IELTMPS Web Client, IELTMPS Server, and IELTMPS Hosted Service as the canonical public terminology.
- Publish a concise authoritative English README and a synchronized documentation structure.
- Verify with upstream and rightsholders the exact GPL identifier and final file scope of the Web Client derived from IELTS Atlas.
- **Established:** Record owner authorization and apply `AGPL-3.0-only` metadata to the eligible original IELTMPS Server scope.
- Publish future versioned API-contract artifacts with explicit artifact-level license and version metadata.
- Expand the initial notices into a complete third-party and release-delivery notice set.
- Inventory content rights for fonts, images, dictionaries, wordlists, generated exams, explanations, Listening materials, and other separately copyrighted resources.
- Classify shared tooling and mixed generated outputs.
- **Established:** Publish the initial mixed-license scope and attribution documents.
- Define contribution and mixed-license classification rules.

Phase 0 remains open while the unresolved provenance, rights, shared-tooling, release-delivery, and contribution-policy work continues.

This phase does not mechanically rename historical runtime, package, storage, database, container, release, or test identifiers.

## Phase 1 – Server platform stabilization

Strengthen the server-assisted and self-hosted platform:

- Consolidate authentication and session authority.
- Clarify TOTP, step-up, account, administration, and protected-resource boundaries.
- Improve server-backed practice-record consistency across devices.
- Define the migration path from browser-authoritative behavior toward server-authoritative validation and grading.
- Design documented PostgreSQL backup and restore procedures.
- Keep public source, authorized private runtime content, and deployment secrets separate.
- Make development and self-hosted deployment reproducible.
- Bring static archives and container delivery into compliance with license, notice, corresponding-source, and provenance obligations.
- Add stronger release receipts, source association, and migration inventories.

Legacy file/static behavior may remain during this phase. Any removal or deprecation requires a separate compatibility migration.

## Phase 2 – Public service readiness

Prepare the intended maintainer-operated service without treating tracked configuration as proof of live operation:

- Complete security-owner review of Tor deployment guidance.
- Establish Tor-only public access for the business layer.
- Publish and maintain a stable business onion identity through trusted verification channels.
- Define terms of service, privacy information, and acceptable-use rules.
- Establish content-source records, rights review, correction, and takedown procedures.
- Define monitoring, incident response, recovery, and abuse-control processes.
- Test backup, restore, upgrade, and rollback procedures.
- Document service limits and support expectations.
- Establish an evidence-based readiness review before any public launch claim.

No public business onion address or public clearnet Hosted Service endpoint is promised by this roadmap.

## Phase 3 – Extensibility and AI-backed services

Develop optional extension capabilities only after the core platform and governance boundaries are stable:

- Define versioned extension interfaces.
- Add a model-provider abstraction rather than binding the product to one vendor.
- Support carefully separated user-provided and maintainer-managed model APIs.
- Introduce quotas, cost controls, failure handling, and clear service limits.
- Define privacy boundaries for prompts, learner data, generated responses, retention, and provider access.
- Require review and labeling for generated educational explanations.
- Distinguish free/open-source functionality from resource-backed managed capabilities.

AI model API support is a possible future capability, not an existing product feature. Any fee would cover operated services, provider usage, infrastructure, or support rather than exclusive source-code rights.

## Phase 4 – Sustainable governance and operations

Build a maintainable long-term project and service:

- Develop a broader community of maintainers and reviewers.
- Publish contribution, review, and release governance.
- Define decision-making and responsibility boundaries.
- Support voluntary contributions, sponsorship, and infrastructure assistance without claiming an unverified legal status.
- Publish appropriate operational transparency and service-status information.
- Maintain long-term release and security support policies.
- Periodically review licenses, notices, dependencies, content rights, privacy practices, and service sustainability.

Progress through these phases depends on evidence and review. A later phase may begin experimentally before every earlier item is complete, but public documentation must continue to distinguish implemented capabilities from intended direction.
