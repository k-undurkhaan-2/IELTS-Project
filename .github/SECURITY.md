# Security Policy

Report security vulnerabilities in the IELTMPS Project privately through
GitHub Private Vulnerability Reporting, which is enabled for this repository.
Open the [repository's security page](https://github.com/k-undurkhaan-2/IELTS-Project/security)
and select **Report a vulnerability** to send a private report to the maintainers.

**Do not open a public issue for an undisclosed vulnerability.** Keep exploit
details and other sensitive information out of public issues, pull requests,
and discussions.

## Scope

Reports may concern the IELTMPS Web Client, IELTMPS Server, or repository
tooling and configuration when a vulnerability materially affects
confidentiality, integrity, authorization, or availability. Security-sensitive
areas include, without being limited to:

- Authentication, sessions, authentication handoff, TOTP, and step-up flows.
- Authorization, user/admin privilege boundaries, and administration interfaces.
- Protected user and practice data, browser storage, import/export, and backups.
- Browser input handling, path traversal, and unauthorized static-resource access.
- Proxy and forwarded-header trust boundaries and Tor/onion deployment security.
- Secrets or credential exposure and dependency, build, release, or CI integrity.

## Ordinary issues

Normal bugs without security impact, feature requests, documentation errors,
ordinary UI defects, content or exam inaccuracies, and performance issues
without a security consequence may use the normal public issue process.
If an issue also has security impact, use the private reporting route above.

## What to include in a report

Provide enough information to understand and reproduce the issue safely:

- Affected component or path, and version or commit when known.
- Reproduction steps and the observed versus expected behavior.
- Security impact and the affected data or privilege boundary.
- Prerequisites, such as account role, access, or relevant configuration.
- A minimal proof of concept where appropriate, and a suggested mitigation
  if available.

Use synthetic data and redact sensitive values. Do not include real user
secrets, private data, production credentials, hidden-service private keys,
database dumps, private deployment addresses, or unnecessary sensitive
material, even in a private report.

## Disclosure expectations

Keep an unresolved vulnerability private until maintainers have had a
reasonable opportunity to investigate and coordinate disclosure with you.
Continue discussing reproduction details and proposed fixes through the
private report.

This policy does not promise a fixed response or remediation timeline,
payment, bug bounty eligibility, or CVE assignment.

## Supported versions and security support

No formal versioned security-support matrix is currently published. Reports
concerning the current maintained codebase and current releases may still be
submitted. This policy does not imply that every historical release or
deployment is actively supported.

## Relationship to the threat model

[SECURITY_THREAT_MODEL.md](../SECURITY_THREAT_MODEL.md) records engineering
threat assumptions, trust boundaries, attacker stories, and mitigations.
This policy governs vulnerability reporting; the threat model provides
technical context for security work.

## Deployment and readiness boundary

Tracked code and example configuration are not a blanket production-security
certification. The repository does not establish a hardened multi-tenant SaaS
or a security-reviewed public service. Public-service readiness, recovery,
monitoring, and operational review remain incomplete; see
[Development Status](../docs/STATUS.md).

Operators remain responsible for their deployment's secrets, access controls,
updates, backups, monitoring, and incident response. Threat-model mitigations
depend on the actual deployment and configuration and are not guaranteed for
every operator environment.
