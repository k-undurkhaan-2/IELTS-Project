# IELTMPS Licensing Scope

## Overview

This is a mixed-license repository. Different files and materials are governed by different licenses or rights, and no single repository-wide declaration overrides those boundaries.

## IELTMPS Web Client

The IELTMPS Web Client is derived from IELTS Atlas / `sallowayma-git/IELTS-practice`. The confirmed upstream-derived frontend source within the upstream maintainer's authorship and authority is licensed under `GPL-3.0-or-later`.

The authority is [upstream issue #96, "Confirmation requested: GPL option and upstream frontend scope"](https://github.com/sallowayma-git/IELTS-practice/issues/96), specifically the [maintainer confirmation by `githubSINGLE`](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5141381894) for reference revision `2a1583decb48854a6297220c64de80ec1fcfe410`. That revision identifies the confirmed code set; it is not a claim about the upstream repository's current head.

The confirmation covers the maintainer's self-authored frontend source in that code set, subject to the exclusions in the issue. The upstream-origin portions of `index.html`, `css/**`, `js/**`, `templates/**`, frontend assets, and source inputs to frontend bundles must be classified by their actual provenance. These paths describe where covered source may occur; they are not a blanket license for every file or later contribution in those locations. The confirmed SPDX option is settled; a complete downstream file-by-file provenance manifest remains separate work.

The [downstream closeout clarification](https://github.com/sallowayma-git/IELTS-practice/issues/96#issuecomment-5143866503) preserves the exclusions. The confirmation does not grant rights in third-party vendor files or assets, fonts, wordlists or datasets, media, questions or educational content, generated educational content or data outside that authority, private resources, or material owned by other contributors. It also excludes downstream Server code and independently authored downstream tooling. Those materials retain their independently applicable licenses or rights status; uncertain provenance must be recorded rather than assigned GPL or AGPL by assumption.

The existing root [GNU GPL Version 3 text](LICENSE) is preserved verbatim. The `GPL-3.0-or-later` option for the confirmed scope comes from the upstream confirmation, not from treating that text as a repository-wide license declaration.

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

Generated, minified, and bundled frontend artifacts inherit the applicable license terms and obligations of their identified source inputs and must retain relevant copyright, license, and attribution notices. This includes the confirmed `GPL-3.0-or-later` upstream source and any separately governed inputs; generation does not expand the upstream maintainer's authority or erase third-party rights.

Other generated outputs, including educational content and data, likewise follow the licensing and rights status of their inputs. They are not automatically covered by GPL or AGPL merely because they are tracked, built, or distributed with the project.

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
