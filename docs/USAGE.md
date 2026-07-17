# Usage

This guide describes the current user-facing operating models of the IELTMPS Project. It is an overview rather than a production runbook.

## Primary operating model

The supported primary direction is server-assisted use through either the maintainer-operated IELTMPS Hosted Service or a third-party self-hosted deployment.

A server-assisted deployment combines the IELTMPS Web Client with accounts, sessions, PostgreSQL-backed practice records, administration functions, and protected runtime resources. This model supports record access across devices and provides a foundation for moving trust-sensitive behavior toward the IELTMPS Server.

The repository does not establish that the maintainer-operated service is currently open to the public. Self-hosters must configure and secure their own environment and must supply only content they are authorized to use.

## Accounts and practice records

Tracked implementation supports registration and login. An authenticated user can use server-backed practice records stored in PostgreSQL. Those records can be accessed from more than one device when each device connects to the same deployment and the user signs in to the same account.

Current browser-side data remains important. Existing local records may be offered for import into an authenticated account, and local behavior may be used when remote access is unavailable. Users should confirm that an import or export contains the expected records before relying on it as a backup.

Account and record availability depends on the selected deployment. An account on one independently operated deployment does not imply an account or data transfer on another deployment.

## Reading practice

Reading practice is available in the Web Client. Tracked resources and generated exam data support browser-based passages, questions, navigation, answers, review, and statistics.

The presence of a Reading workflow does not establish that every passage, question, image, PDF, explanation, or generated exam is cleared for every public use. Maintainer-operated and third-party services must apply the [content policy](CONTENT_POLICY.md) to the material they publish.

## Listening practice

Listening integration is available when separately supplied runtime content is present and authorized. The public source tree contains integration code and a limited tracked shell, while private or separately controlled source material may be supplied outside the repository.

A missing Listening resource may therefore indicate that the selected deployment does not provide that content. Users should not copy or redistribute audio, questions, images, or explanations unless they have permission.

## Suite and mock-practice use

The Web Client supports suite and mock-practice flows that combine practice activities into a broader session. Current session logic includes substantial browser-side behavior.

Suite completion and displayed results should be treated as practice feedback. The long-term project direction is server-authoritative validation and grading, but that migration is not complete. IELTMPS does not conduct an official examination, and practice output is not a certified examination result.

## Statistics and records

The client can present practice history and summary statistics based on available local or server-backed records. Administrative statistics are also present in tracked server code.

Statistics reflect the data available to the current browser, account, and deployment. Local fallback, imports, deletions, incomplete sessions, or unavailable remote data can affect what is shown. The repository does not currently define a cross-deployment record federation service.

## Export and browser backup

Tracked interfaces support data export and browser-data backup and restore. These features can help users retain portable copies of practice information.

Exports may contain personal learning data. Store them securely, review them before sharing, and delete obsolete copies when appropriate. Browser backup is not a substitute for a tested PostgreSQL backup and disaster-recovery process operated by the deployment administrator.

Turnkey PostgreSQL disaster recovery is not currently evidenced. Self-hosters remain responsible for server-side database backup, restore testing, retention, and access control.

## Local fallback behavior

The current Web Client can use local data sources and local storage. Some remote-data paths fall back to local behavior after an unavailable or failed server request.

This fallback supports compatibility and continuity, but it can produce differences between browser-local and server-backed state. Users should not assume that a locally visible record has synchronized successfully. Operators should explain the storage model of their deployment.

The approved direction is to move durable and trust-sensitive state toward the Server while retaining intentional offline or recovery behavior only where it has a defined contract.

## Transitional file/static compatibility

Direct file and static operation remain implemented for legacy compatibility. They are not the recommended primary quick start for IELTMPS.

These modes do not provide the full account, PostgreSQL, administration, protected-resource, or multi-device experience. Browser restrictions can also vary when a page is loaded directly from local files.

This documentation change does not remove existing file/static behavior. Deprecation or removal requires a separate runtime migration and compatibility plan.

## Maintainer-operated service

The IELTMPS Hosted Service is the intended maintainer-operated deployment. Its direction is public-interest, non-profit-oriented, and Tor-only for the public business layer.

**Business onion address: Not yet published**

No public clearnet Hosted Service endpoint is currently published. Tracked configuration does not verify that a public service is live. Consult [Tor access](TOR_ACCESS.md) and [development status](STATUS.md) for the current public wording.

## Third-party self-hosted deployments

A third-party self-hosted deployment is operated independently from the IELTMPS maintainers. Its operator is responsible for:

- Infrastructure and application security.
- Lawful sourcing and publication of practice content.
- User-data handling and privacy information.
- Backups, restore testing, updates, monitoring, and incident response.
- Abuse handling and support.
- Compliance with applicable software and content licenses.

Availability of the source code does not imply endorsement of a third-party service. The maintainer-operated access policy, content set, support model, or service terms do not automatically apply to another deployment.

## Access and support boundaries

Tor Browser is the client that the IELTMPS Project recommends and intends to support for its maintainer-operated Hosted Service once that service is launched. Third-party Tor-capable browsers, extensions, proxies, or integrations are unsupported and are not considered privacy-equivalent to Tor Browser.

Source code and public project documentation may remain available on ordinary development platforms. That does not create a public clearnet application endpoint.

For a compact list of available, active, planned, and unevidenced capabilities, see [Development Status](STATUS.md).
