# IELTMPS Licensing Scope

## Overview

This is a mixed-license repository. Different files and materials are governed by different licenses or rights, and no single repository-wide declaration overrides those boundaries.

## IELTMPS Web Client

The IELTMPS Web Client is derived from IELTS Atlas. Locally available evidence supports GNU GPL Version 3 / GPLv3-family provenance, but the exact `only` versus `or-later` identification and the final frontend file manifest remain under upstream and rightsholder clarification.

The existing root [`LICENSE`](LICENSE) is preserved. This batch does not assign a new frontend SPDX identifier, and it does not state that every frontend asset or every repository file is GPL-licensed.

## IELTMPS Server

Eligible original IELTMPS Server files in the following scope are licensed under `AGPL-3.0-only`:

```text
backend/src/**
backend/scripts/**
backend/migrations/**
backend/admin/**
backend/auth/**
backend/test/**
backend/Dockerfile
backend/docker-compose*.yml
backend/*-proxy/**
backend/tor/**
backend/.env.example
backend/package.json
api-contract/README.md
```

Per-file SPDX headers identify eligible text files in this scope. The package metadata identifies the Server package license.

`backend/package-lock.json` is generated dependency metadata and is not given a per-file AGPL declaration by this batch. Third-party dependencies retain their own licenses. `backend/DEPLOYMENT-RUNBOOK.md` is not included in this batch's AGPL scope.

## API-contract directory

No separately versioned OpenAPI, Swagger, or JSON Schema contract is currently published in `api-contract/`. The tracked README in that directory is part of the authorized Server scope and is licensed under `AGPL-3.0-only`.

The directory is reserved for future versioned public interface artifacts. Each future artifact must identify its license and version explicitly. No proprietary API-contract product is currently present.

## Third-party software

Third-party components retain their original licenses, copyright notices, and attribution requirements. Confirmed examples include Three.js, ECDICT, npm dependencies, container base images, PostgreSQL, nginx, Tor, and Node.js. This list is not complete.

The Server's AGPL license does not relicense third-party protocols, dependencies, services, or separately owned software.

## Content and data

GPL and AGPL software licensing does not automatically license questions, articles, audio, PDFs, images, fonts, wordlists, dictionaries, explanations, generated examination material, private Listening resources, user data, databases, secrets, keys, or production configuration.

Each such item requires its own provenance, permission, license, or other lawful basis.

## Generated artifacts

Generated bundles and outputs follow the licensing and rights status of their inputs. They are not automatically covered by one blanket declaration merely because they are tracked, built, or distributed with the project.

## Copyright ownership

Copyright in original IELTMPS Server contributions:

Copyright © 2026 Kevin.

Copyright in upstream, contributor and third-party material remains with the respective copyright holders.

Licenses grant permissions under their terms; they do not transfer copyright ownership.

## License texts

- [Existing root GNU GPL text](LICENSE)
- [GNU Affero General Public License Version 3](LICENSES/AGPL-3.0-only.txt)
- [Project notices](NOTICE.md)

The original English license texts govern.

## No warranty

Licensed software is provided without warranty to the extent stated in the applicable license. This scope document does not create additional warranties, guarantees, or rights in separately owned material.
