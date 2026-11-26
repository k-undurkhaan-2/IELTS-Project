# Onion Deployment Runbook

This runbook records operational rules for the IELTS-practice business,
admin, and auth onion deployment.

## Hard Rules

- Do not run `docker compose down -v`.
- Do not delete `business_tor_hidden_service`, `admin_tor_hidden_service`, or
  `auth_tor_hidden_service` volumes.
- Do not delete onion hostname files.
- Do not open host ports.
- Do not modify UFW, SSH, netplan, router, or host firewall rules.
- Do not print `.env`, bridge lines, client auth files, hidden service private
  keys, or database contents.
- Production split-onion deployment must not start the base `tor` service from
  `backend/docker-compose.yml`. That service is legacy/dev only and must require
  the explicit `--profile legacy-onion` profile.
- Legacy direct-app account and TOTP-disable mutation APIs are retired. Do not
  reintroduce opt-in environment switches for `/api/auth/account/*` or
  `/api/auth/totp/disable`; self-service account security changes must use the
  scoped auth action flows.

## Proxy And Tor Recreate Rule

If an onion proxy container is recreated, force-recreate the matching Tor
container after the proxy is healthy.

Reason: Tor's `HiddenServicePort` target is configured as a Docker service
name, such as `business-proxy:80`, `admin-proxy:80`, or `auth-proxy:80`.
When Docker recreates a proxy container, the proxy can receive a new container
IP. A running Tor process can keep using the previously resolved target. The
symptom is cross-onion routing, for example business onion traffic reaching
`auth-proxy`, or auth onion traffic reaching `business-proxy`.

Required pairs:

- `business-proxy` changed or recreated -> recreate `business-tor`
- `admin-proxy` changed or recreated -> recreate `admin-tor`
- `auth-proxy` changed or recreated -> recreate `auth-tor`

Recreate only the matching Tor container. Do not delete volumes.

## App-Only Deployment

If only app code or static assets changed:

1. Back up changed target files.
2. Build/load `backend-app:latest`.
3. Recreate only `app` with `--no-build`.
4. Verify:
   - `curl -s http://127.0.0.1:3000/api/health`
   - onion hostnames unchanged
   - host ports still only `127.0.0.1:3000`

Proxy/Tor recreation is not required for app-only changes.

Use `--no-build` for target-host app recreates after loading an exported
`backend-app:latest` image. The compose graph still contains a `build:` entry
for development, and omitting `--no-build` can make the target host attempt a
slow or failing rebuild instead of using the already loaded image.

## Listening Runtime Assets

This section records the frozen A2 Listening delivery contract and the evidence
accepted for Issue #79. For Listening delivery, apply the additional applicable
checks in this section alongside the App-Only Deployment steps above. Prospective checks below require their own applicable
staging, runtime or operational authorization. Documentation acceptance does not
build an image, integrate Dev, provision private content or authorize deployment.
The standalone Documentation tree is not the accepted runtime candidate.
[Controlled scope #7188862914](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-7188862914)
defines this boundary.

### Public Listening Image Assets

The independently designed Listening frontend is delivered as a verified public
artifact under `/app/public/listening-frontend/`, outside the private bind target
`/app/ListeningPractice`. Its authenticated compatibility entry is
`/ListeningPractice/vip%20special/`; it is not interchangeable with the root
Reading frontend. Public distribution is limited to the 31 explicitly approved
source entries and the accepted generated dependency contract. Ignored local
files, private exams, audio, secrets and future additions are not included in
that authorization.
[A2 #6071665204](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-6071665204)
and [UI acceptance #6072766012](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-6072766012).

Accepted Security U03 excludes the private `ListeningPractice/` and
`ReadingPractice/` roots from application image construction. The approved
artifact is staged separately from exact public Git objects; the private roots
must not be copied into the context or image to restore public availability.
This runbook documents that accepted boundary and does not enforce the exclusion
itself. The accepted
[Security Dockerfile](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/backend/Dockerfile)
and [root exclusions](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/.dockerignore)
remain the implementation authorities.

The immutable public artifact identity is:

```yaml
UI_source: 1a576be93d7d18b8955adf5216efb311032bf62a
artifact_version: lpf-v1-1a576be93d7d-a2-fad166773fa6259a
manifest_blob: b3bdd14cbebb09779045bc25e5972c2ace85d39e
manifest_bytes: 12153
manifest_sha256: fad166773fa6259a18c752c240030aa228390f8380b7be5dacac3b8ba8d4b75d
logical_stage_sha256: 8207a9c1a9cf45ea14e56710837fca06ef61449794ca2b959d9c11b6f145315b
```

Use the exact canonical manifest at
[`developer/tests/ci/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a.manifest.json`](https://github.com/k-undurkhaan-2/IELTS-Project/blob/38aabbd0ac91a93b4a2462018ea0643ccb488040/developer/tests/ci/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a.manifest.json).
Do not reconstruct, reserialize, edit or replace it. Its inventories have
different purposes:

| Inventory | Count | Meaning |
| --- | ---: | --- |
| Approved public source entries | 31 | The complete frozen source allowlist |
| Runtime source entries | 24 | Approved source files included in the payload |
| Build-only entries | 4 | Approved source inputs excluded from the served payload |
| Optional entries | 3 | Approved source entries excluded from the served payload |
| Generated dependency records | 4 | Two payload dependencies plus two image-root-only dependencies |
| Generated payload files | 2 | Added to the 24 runtime source entries |
| Image-root-only dependencies | 2 | Required in the image, outside the 26-file artifact payload |
| Served artifact payload | 26 | Exactly 14,533,213 bytes |
| Complete staged output | 28 | The 26 payload files, exact manifest and immutable active locator |

The business UI retains the three established image assets
`assets/generated/listening-exams/manifest.js`,
`assets/generated/listening-exams/listening-index.compat.js` and
`assets/generated/listening-exams/listening-practice-unified.html`.
The fourth generated dependency is `js/bundles/listening-wrapper.bundle.js`.
All four image-root copies must match the manifest; the first two must also
appear byte-identically under the artifact's `payload/assets/generated/listening-exams/`.

| Generated dependency | Exact bytes | SHA-256 |
| --- | ---: | --- |
| `manifest.js` | 123988 | `aedc5fd800bbec50e0ec096c7c4005b2e9abe26d10102bcce9a768f9ede35802` |
| `listening-index.compat.js` | 174515 | `7aeb0d4a97315d023af74db50272168888f68f979e37f2a3f7e53391b64abc18` |
| `listening-practice-unified.html` | 1565 | `d3808b0237364a4268aa7c31032dc121b6cfdab3e061ca62bd9c40743034ba8c` |
| `listening-wrapper.bundle.js` | 57847 | `3e408155816a9971e194eca15c0259953811fe3892431c1427c59d612cb5defa` |

### Git-Object Staging and Image Construction

The accepted
[staging helper](https://github.com/k-undurkhaan-2/IELTS-Project/blob/38aabbd0ac91a93b4a2462018ea0643ccb488040/developer/tests/ci/stage_public_listening_frontend.py)
has Git blob `e904ff5a23198f0d00ba69450f7cc4bc27bb0daa`.
It acquires the exact UI commit into a new isolated bare object store, verifies
commit/tree/subtree, entry modes, blob IDs, lengths and SHA-256 values, and emits
only the frozen payload and controls. It does not copy a working-tree
`ListeningPractice` directory or execute a private generator. Git-object-only
staging is required; omitting the accepted generated dependencies is an error.

The following prospective command pair is supported by that helper. Its working
directory must be the root of a separately authorized accepted CI tooling
checkout at `38aabbd0ac91a93b4a2462018ea0643ccb488040`, with the exact helper
and canonical manifest, an admitted Python interpreter and Git executable,
public-source network access and writable transaction-owned staging space.
For `stage`, the output root must not already exist or have linked/reparse
ancestors; `verify` checks the newly created, existing stage.
The helper creates a temporary external bare store when no object-store option
is supplied. These commands are not instructions to run from the standalone
Documentation checkout.

```sh
python -I developer/tests/ci/stage_public_listening_frontend.py stage --output-root .ieltmps-build/public-listening-frontend
python -I developer/tests/ci/stage_public_listening_frontend.py verify --output-root .ieltmps-build/public-listening-frontend
```

Success returns exit 0 and a JSON report with 31 approved source entries,
24 runtime source entries, 2 generated payload entries, 26 served payload
entries / 14,533,213 bytes, 2 control files and 28 total staged files.
`output_identity_sha256` must equal the logical-stage digest above; unexpected
paths, manifest/source mismatches and private-content inputs must be zero.
Reported staging-contract failures return exit 2. Check the `stage` exit and
report before running `verify`; do not continue after a failed stage or use a
successful verification of an old output to override a staging failure. Any
nonzero exit or missing or mismatched expected evidence stops acceptance.
A stage/verify pair is not independent
two-run acceptance: F1 row A separately measured two fresh staging roots and
their complete inventories in each of the producer and verifier jobs.

The accepted staging layout, relative to the explicitly assembled
repository-root Docker context, is:

```text
.ieltmps-build/public-listening-frontend/
  active.json
  lpf-v1-1a576be93d7d-a2-fad166773fa6259a/
    manifest.json
    payload/
```

The staged root is Git-ignored but must be included in the explicitly constructed
context. The isolated runtime implementation copies only the verified stage into
that context, alongside the accepted source set and image-root dependencies.
The unchanged Security Dockerfile uses these literal, version-bound instructions:

```dockerfile
COPY .ieltmps-build/public-listening-frontend/active.json /app/public/listening-frontend/active.json
COPY .ieltmps-build/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/manifest.json /app/public/listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/manifest.json
COPY .ieltmps-build/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/payload/ /app/public/listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/payload/
```

The active locator is exactly 628 bytes with SHA-256
`515fa52a87943dab5b8f1c5624ba54a6f78e0d421f41553e4e1f8a77323086a4`.
It binds the immutable version, manifest identity, payload paths/counts/bytes and
source identities; it is not a mutable version-selection switch. The production
loader verifies the canonical locator, exact manifest, complete 26-file payload
and all four image-root dependencies before retaining verified public response
bytes. Unexpected files, links or integrity mismatches fail that admission.
[Loader source](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/backend/src/publicListeningFrontend.js).

An independently approved immutable base-image identity is required before an
authoritative image build. The accepted Dockerfile still spells
`FROM node:24-alpine`; that mutable tag does not satisfy the requirement.
The isolated verification enforced `--platform linux/amd64` and the named
build-context binding
`--build-context node:24-alpine=docker-image://docker.io/library/node@sha256:d8d97e479cdc64f052f81f129362168717c59783ade8dcc1abd22e1cca8dbd7c`,
then reconciled resolved materials, base rootfs, OCI config/layers, the same-build
Docker archive and the executed image ID. These are historical build parameters,
not a complete production build procedure.

| Isolated verification image | Approved immutable reference |
| --- | --- |
| Node application base | `docker.io/library/node@sha256:d8d97e479cdc64f052f81f129362168717c59783ade8dcc1abd22e1cca8dbd7c` |
| BuildKit | `docker.io/moby/buildkit@sha256:7583a0667093d941826bcd1d2878d6a360dfd08a82c93e6d6a6f6cce78801e12` |
| Synthetic PostgreSQL | `docker.io/library/postgres@sha256:9d9e487c1bd6413c52ccb3c02f46c8e37fa1e1d1a32a84519eb4e68d0ad1da30` |

These identities were approved for isolated verification in
[#7167678279](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-7167678279).
The approved Node image metadata identifies Node 24.22.3 / Alpine 3.24;
the control workflow separately pins Node 24.20.0 and Python 3.12.10.
Its browser contract is Playwright 1.56.1 / Chromium revision 1194.
These are verification identities, not production image or tool approval.
The frozen branch/base predicates in
[`issue79-runtime-verification.yml`](https://github.com/k-undurkhaan-2/IELTS-Project/blob/38aabbd0ac91a93b4a2462018ea0643ccb488040/.github/workflows/issue79-runtime-verification.yml)
make it an Issue #79 verification implementation, not a general deployment
workflow. No replacement digest, workflow dispatch or production rollout is
authorized by this section.

Before a separately authorized app recreation, the following standalone
presence check remains useful without any private runtime bind. First establish
and retain independent evidence that the local `backend-app:latest` tag resolves
to the exact application image approved for that operation, including its
immutable identity and coherent artifact/dependency set. A local tag is not
proof of provenance. Use the already loaded local image and keep the verified
tag-to-image binding stable through the check; this check does not authorize
pulling or retagging an image. Stop if the approved local image or that binding
cannot be established and maintained. Run from the admitted Docker client
environment; no repository working directory is required.

```sh
docker run --rm --entrypoint sh backend-app:latest -ec '
  test -s /app/assets/generated/listening-exams/manifest.js
  test -s /app/assets/generated/listening-exams/listening-index.compat.js
  test -s /app/assets/generated/listening-exams/listening-practice-unified.html
  test -s /app/js/bundles/listening-wrapper.bundle.js
'
```

Exit 0 means only that all four paths satisfied `test -s` (nonzero size); a
failed test stops the shell and returns nonzero. This check does not by itself
establish regular-file type, their hashes, the
complete artifact inventory, absence of private content in context/filesystem/
layers, authentication, private-resource availability or end-to-end readiness.
Those properties require their separately applicable verification evidence.

### Authenticated Delivery and CSP

The canonical public shell, its exact allowed payload paths, the root
`/assets/generated/listening-exams/manifest.js` and
`/assets/generated/listening-exams/listening-index.compat.js` routes, Listening
practice wrappers and private exams require valid content authentication.
A successful check needs the ordinary accepted session flow, matching session
verifier cookie, active server-side session registry and applicable audience.
No credentials or production login procedure are supplied here. The legacy
unconditional anonymous HTTP 200 expectation for the two generated indexes is
removed. A placeholder `/practice/listening/test` is not proof of an available
exam.

The following expectations apply to ordinary unconditioned GET/HEAD requests
and the explicit negative cases in the frozen Security implementation and
accepted runtime evidence. Verify responses only against a separately authorized
environment and the exact selected route; do not generalize one row's status,
content type or cache policy to another route.
[Security routing](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/backend/src/app.js),
[Security regressions](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/backend/test/publicListeningFrontend.test.js)
and [accepted runtime checks](https://github.com/k-undurkhaan-2/IELTS-Project/blob/38aabbd0ac91a93b4a2462018ea0643ccb488040/developer/tests/ci/public-listening-runtime/runtime.py).

| Route or condition | Prerequisite and outcome |
| --- | --- |
| Canonical shell directory/index and 26 allowed artifact paths | Valid session and loaded artifact: GET/HEAD 200; GET body matches the length and SHA-256 of the corresponding canonical payload record, HEAD has no body and retains the expected content length; `Cache-Control: private, no-store` |
| Two root generated index routes and their shell-relative counterparts | Valid session and loaded artifact: GET/HEAD 200; exact 123988/174515-byte records above; `application/javascript; charset=utf-8`; `private, no-store`; both route forms serve retained verified payload bytes |
| Other allowed payload extensions | HTML `text/html; charset=utf-8`, CSS `text/css; charset=utf-8`, JSON `application/json; charset=utf-8`, WOFF2 `font/woff2`, SVG `image/svg+xml`; payload JS uses `application/javascript; charset=utf-8` |
| Direct image-root wrapper HTML and wrapper JS dependency URLs | Accepted authenticated GET/HEAD measurements: 200 with body length and SHA-256 matching the applicable generated-dependency record on GET and no body on HEAD, `public, max-age=0`, and respectively `text/html; charset=UTF-8` / `application/javascript; charset=UTF-8`; the direct wrapper HTML remains behind canonical content authentication, and these static dependency URLs are distinct from the practice wrapper and two retained-buffer index routes |
| `/practice/listening/:examId` | Valid session, loaded artifact and resolvable existing exam: GET/HEAD 200; GET returns HTML with the accepted exam ID, source URL and base URL injected into the verified wrapper template, HEAD has no body and retains the expected content length; `text/html; charset=utf-8`; accepted response has no `Cache-Control` header |
| Existing contained raw private HTML, including nested compatibility path | Valid session and available resource: GET/HEAD 200; GET returns that private file, HEAD has no body; `text/html; charset=UTF-8` and `public, max-age=0` as measured; this cache header does not authorize anonymous access |
| Anonymous or expired session on canonical protected routes | 401 with HTML authentication response and `Cache-Control: no-store`; HEAD has no body; the response's refresh points to the accepted auth flow |
| Independently fresh session then revoked in the registry | 401 with `application/json; charset=utf-8`; GET body is `{"error":"Authentication required"}`, HEAD has no body; the accepted early registry rejection has no `Cache-Control` header |
| Noncanonical generated dependency aliases, including dot segments | 404 and `no-store` before authentication; accepted coverage includes authenticated, anonymous, expired and revoked cases |
| Unsupported absolute request target or leading double slash | 400 and `no-store` before content delivery |
| Encoded public-shell filename/traversal/separator | 400; wrong-case or noncanonical shell prefix is instead 404; a canonical but non-allowlisted shell file is 404 after valid authentication and artifact admission |
| Malformed nested private path | 400 after authentication; missing private file is 404 and a resolved root/target escaping the authorized containment boundary is 403 |
| Unresolvable exam ID or missing exam resource | Authenticated practice wrapper resolution returns 404; a known index entry alone does not guarantee private availability |
| Non-GET/HEAD method reaching the governed public handler | After authentication, 405 with `Allow: GET, HEAD` |
| Missing or invalid production public artifact/dependencies | Health is 503; canonical public/generated routes and practice wrappers fail closed with 503 after their authentication gate, with `no-store`; this is not a blanket status for every private or unrelated route |

Public-shell CSP, Listening Wrapper CSP and raw private-exam CSP remain separate.
The root generated index responses do not acquire the public-shell policy merely
because their bytes also occur under the shell-relative prefix. Preserve these
exact accepted literals from Security test blob
`475f2785d853213b1e7eeb5c8f1f0955267dae98`; no tightening, weakening or redesign
is specified.

Public shell (no sandbox directive):

```text
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src 'self' 'unsafe-inline'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; child-src 'self' blob:; worker-src 'self' blob:; manifest-src 'self'
```

Listening Wrapper:

```text
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'none'; frame-src 'self'; child-src 'self'; worker-src 'self' blob:; manifest-src 'self'
```

Raw private exam:

```text
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'none'; script-src 'self' 'unsafe-inline'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'self' blob:; manifest-src 'self'; sandbox allow-scripts allow-downloads allow-same-origin
```

### Private Listening Runtime Resources

When `app` runs under the Compose configuration with the existing bind in
[docker-compose.yml](docker-compose.yml), `/app/ListeningPractice` is supplied
externally by the host bind mount, rather than by the image:

```yaml
source: ../ListeningPractice
target: /app/ListeningPractice
read_only: true
bind:
  create_host_path: false
```

The host source must already exist before Compose starts or recreates `app`.
`create_host_path: false` prevents Compose from creating a missing host source;
`read_only: true` makes the mounted resource read-only inside the container.
The source is relative to the accepted Compose configuration in `backend/`.
This records the unchanged
[Compose contract](https://github.com/k-undurkhaan-2/IELTS-Project/blob/68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58/backend/docker-compose.yml),
not a new mount or provisioning procedure.

The public generated exam manifest supplies an exam's `path` and `filename`;
the resource must exist beneath `/app/ListeningPractice/<path>/<filename>` or
the accepted nested compatibility root
`/app/ListeningPractice/vip special/ListeningPractice/<path>/<filename>`.
The resolver checks the canonical root before the nested alternative and builds
the corresponding encoded URL. The nested handler independently anchors the
nested root to the real top-level mount and the target to the real nested root.
Missing resources fail resolution; outside-root targets and symlink escapes are
rejected. Do not infer mount presence, correct content or version compatibility
from a successful public-index response.

F1 row H verified canonical/nested synthetic fixtures, missing resources,
outside-mount and symlink boundaries, Docker mount `RW=false`, actual root
write rejection and unchanged fixture hashes. All 23 accepted Security tests
passed with zero skips in that isolated verification. Synthetic evidence does
not provision, inventory or accept real private exams/audio, assign their owner,
or establish production private-overlay readiness.

### Accepted Runtime Verification and Readiness

[F1 #7186218031](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-7186218031)
and [F2 #7186253851](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-7186253851)
accept the following isolated evidence. The runtime candidate combined the exact
Security commit tree at `68c8f36c2700b468d3ce8ffa0080c4ae6fbcca58` and complete accepted
18-path UI delta from `1a576be93d7d18b8955adf5216efb311032bf62a`, with separate
CI staging tooling from `d1f5bccc5acab9691e919b7a6be9201f39ccae1c`.
It was not an integrated Dev or production deployment.

| Row | Independently accepted coverage |
| --- | --- |
| A | Two Git-object-only stages per job; 31 approved entries, 26 payload files / 14,533,213 bytes, 28 total files, exact manifest and logical-stage digests |
| B | All four generated dependencies, exact source/stage/image bytes and required browser network closure |
| C | Complete transmitted context, exported filesystem and every OCI layer, including link/whiteout inspection; no excluded private roots, sentinels or local credentials |
| D | Digest-bound base and builder, resolved materials/rootfs/config/layers, same-build archive and executed identity; recorded npm/Node-cache nondeterminism is not a claim of bit-identical whole-image rebuilds |
| E | Fresh owned PostgreSQL state; unchanged production CMD, `NODE_ENV=production`, `USER node`, migrations/bootstrap, health and restart |
| F | 31 allowed GET/HEAD routes per job; 66 anonymous requests, 14 expired requests, 14 independently refreshed revoked-session cases, 46 negative requests and 288 alias cases |
| G | Exact independent comparison of shell, wrapper and raw-private CSP literals |
| H | Synthetic canonical/nested resources, missing/outside/symlink checks, read-only mount enforcement and all 23 accepted Security tests |
| I | Ten real-browser cases from ordinary registration/login to public entry, exam selection, wrapper/private iframe and question interaction, with trace/screenshots and policy/network checks |
| J | Separate producer/verifier environments, independent source/registry/context reconstruction, producer-image retest and complete evidence-index replay |

The accepted control Head is `7df1ff4f157e8aeb4e807329de4341adec13c5e2`.
[Runtime run 45772776303](https://github.com/k-undurkhaan-2/IELTS-Project/actions/runs/45772776303),
attempt 1, and [Required CI run 45772776348](https://github.com/k-undurkhaan-2/IELTS-Project/actions/runs/45772776348),
attempt 1, both completed successfully on that Head.
Producer job `139749115567` and verifier job `139750334459` ran independently;
the verifier retested producer image
`sha256:997850d5b4139ef04102491ee8ce9fcb4e27b84d724b3423b8fcf2536f858a9f`.
This is a historical verification image identity, not an approved production or
rollback image. Context SHA-256 is
`12e0482c96cf23d429e0e865c1ef55e08f9004dc4b6f3e4b39906ed10561f1f5`.

Retained evidence identities are producer artifact
[`15094778321`](https://github.com/k-undurkhaan-2/IELTS-Project/actions/runs/45772776303/artifacts/15094778321),
385,056,425 bytes / SHA-256
`502fbe7ace07ffd1c9be5ec10ea5282f3104786736fcf10543dde1bdb58a1b75`,
and verifier artifact
[`15094424748`](https://github.com/k-undurkhaan-2/IELTS-Project/actions/runs/45772776303/artifacts/15094424748),
487,118,607 bytes / SHA-256
`64b13741331b1b373f6077a67e3206ed5671b1379a6457249d81f9f8505dbdeb`.
F1 records independent rehash/replay of all 6,673 indexed files; this section
references that accepted work and does not claim a new replay.

[PR #115 M1 #7188307235](https://github.com/k-undurkhaan-2/IELTS-Project/issues/79#issuecomment-7188307235)
records delivery into `ci/master` at merge
`38aabbd0ac91a93b4a2462018ea0643ccb488040`, preserving tree
`e93ecd11d62b511f41b4055b80ea0a0221538b3a`.
F1/F2's earlier open/draft/unmerged statements remain historical observations.
Execution-time readback on 2026-11-26 confirms post-merge
[run 45793522178](https://github.com/k-undurkhaan-2/IELTS-Project/actions/runs/45793522178)
on that merge, event `push`, attempt 1, completed/successful
(updated `2026-11-26T10:30:28Z`). M1 and D0 recorded it as in progress at their
earlier observation times; those receipts remain unchanged. This successful
CI-domain result is not CI for a future Documentation candidate.

Domain-local UI/Security/CI acceptance, isolated cross-domain runtime verification,
future coordinated Dev integration acceptance, operational readiness, and final
release/deployment authorization are distinct decisions. The first two have the
specific evidence above; this section grants none of the latter decisions.
Health alone is insufficient to establish complete Listening delivery readiness:
public integrity, authenticated dependencies, private availability/compatibility,
mount containment and the actual entry-to-exam flow must also be established
under the applicable scope.

### Compatibility, Stop Conditions and Bounded Rollback

Treat the approved public artifact version, canonical manifest/active locator,
application image and route implementation, all generated dependencies, and
separately authorized private resources as one compatible delivery set.
The generated exam manifest (`assets/generated/listening-exams/manifest.js`)
supplies the exam references that must resolve to the authorized private paths
for that set. The canonical public artifact manifest is a separate integrity
inventory; it is not a private-content inventory or acceptance receipt.

Apply stop conditions to the stage whose acceptance or operation they govern:

- For public staging and authoritative image construction, stop if the applicable
  source, manifest, locator, payload, base-image or application-image identity
  cannot be authenticated; a required digest, byte or inventory check fails;
  an expected public dependency is missing; or the private-content exclusion
  boundary fails. Do not require a private runtime bind or real private resources
  in the image or build context.
- Before an app recreation that requires private Listening resources, stop if
  the separately approved delivery set or required host resource is absent,
  incompatible or not authorized, or if the required read-only bind contract
  cannot be established.
- For the applicable runtime or delivery acceptance, stop if canonical
  authenticated delivery fails, protected bytes are exposed without valid
  authentication, an expected dependency or required private resource is
  missing, mount presence/read-only operation or containment fails, or the
  image, generated indexes, wrapper and private paths are incompatible.
  Unexpected route status/headers, CSP mismatch or incomplete applicable
  runtime evidence also stop that acceptance.

Synthetic and standalone checks retain their approved boundaries; they do not
require real production private-resource provisioning. Do not use health or a
local tag to override any applicable failure, widen the allowlist, copy private
roots into the image or change CSP.

Rollback means restoration of a separately approved coherent prior delivery set,
with its immutable image/artifact/dependency identities and compatible authorized
private resources and mounts, followed by the checks applicable to that set.
Reverting only the locator, image, generated index or private-resource component
independently can create incompatible references and does not establish recovery.
No approved operational rollback target, production image identity, real private
provisioning responsibility or execution authority is supplied by this evidence.
Until those are separately established, this is a bounded rollback requirement,
not an executable recovery procedure or a recovery guarantee.

### Governance and Remaining Obligations

U02 remains `DEFERRED_DEPENDENCY`, and `PRIVATE_OVERLAY_READINESS_ACCEPTANCE`
remains `UNRESOLVED`. The bind facts and accepted synthetic verification do not
supply real private-resource manifests, ownership, provisioning, compatibility
acceptance or operational rollback authority. A Reading runtime mount or
deployment process remains unresolved and is outside Issue #64 scope.

[Issue #64 final acceptance #6168084148](https://github.com/k-undurkhaan-2/IELTS-Project/issues/64#issuecomment-6168084148)
and its separate [closure #6168806858](https://github.com/k-undurkhaan-2/IELTS-Project/issues/64#issuecomment-6168806858)
settled the narrow Documentation/Security convergence at Dev
`554f375527b95d9081bc2ded08d92478d40f74d5`; they did not settle Issue #79
delivery. Issue #79 remains independently open and still requires its own
coordinated Dev integration, validation and final acceptance before its
promotion/release/deployment block can be cleared. Preserve historical findings,
failed runs and accepted evidence; do not rewrite them as current outcomes.

BG-06 and other separate governance obligations remain separately governed.
Under [Issue #85 correction #6196867459](https://github.com/k-undurkhaan-2/IELTS-Project/issues/85#issuecomment-6196867459)
and the controlled Documentation scope, BG-06 closeout, U02/Reading ownership,
real private provisioning, Issue #113 implementation and new Docker/browser
qualification are not automatic prerequisites to documenting or revising this
contract. Their applicability must be justified under the acceptance scope of
the stage that actually needs them.

As stated in [Branch governance](../docs/BRANCH_GOVERNANCE.md#release-and-deployment-boundary),
branch role does not grant release or deployment authority. These checks do
not establish production readiness or authorize deployment or Hosted Service
launch. Documentation revision, candidate acceptance, and publication/review/
merge remain separately governed; none grants operational authority.

## Admin Password Maintenance Rotation

Admin accounts must not change their own password through the Web UI or Web
APIs. Rotate an admin password only through the server maintenance channel with
`backend/scripts/bootstrap-admin.mjs`.

Do not overwrite the long-lived target `backend/.env` for a one-time password
rotation. Do not commit the temporary file. Do not paste the password into a
shell command line, because command history or process listings can retain it.

Recommended flow:

1. On the local maintenance workstation, create a temporary POSIX-shell
   compatible env file, for example `admin-bootstrap.local.env`:

   ```sh
   ADMIN_USERNAME='admin'
   ADMIN_PASSWORD='replace-with-the-new-strong-admin-password'
   ADMIN_RESET_TOTP='false'
   ```

   Set `ADMIN_RESET_TOTP='true'` only when intentionally forcing the admin to
   re-enroll TOTP. Keep this file outside Git-tracked commit scope.

2. Copy the temporary file to the target user's home directory:

   ```sh
   scp admin-bootstrap.local.env \
     ieltsadmin@10.2.202.119:/home/ieltsadmin/.admin-bootstrap.env
   ```

3. On the target host, load the temporary values into the shell environment and
   run a one-off app container. This updates the admin account using the same
   app image and database settings as the deployed service, without recreating
   app, proxy, Tor, or database containers:

   ```sh
   cd /home/ieltsadmin/apps/IELTS-practice
   set +x
   ADMIN_BOOTSTRAP_ENV="$HOME/.admin-bootstrap.env"
   chmod 600 "$ADMIN_BOOTSTRAP_ENV"
   set -a
   . "$ADMIN_BOOTSTRAP_ENV"
   set +a

   docker compose --env-file backend/.env \
     -f backend/docker-compose.yml \
     -f backend/docker-compose.prod.override.yml \
     -f backend/docker-compose.business-onion.override.yml \
     -f backend/docker-compose.admin-onion.override.yml \
     -f backend/docker-compose.auth-onion.override.yml \
     --profile business-onion \
     --profile admin-onion \
     --profile auth-onion \
     run --rm --no-deps \
       -e ADMIN_USERNAME \
       -e ADMIN_PASSWORD \
       -e ADMIN_RESET_TOTP \
       app node scripts/bootstrap-admin.mjs

   rm -f "$ADMIN_BOOTSTRAP_ENV"
   unset ADMIN_USERNAME ADMIN_PASSWORD ADMIN_RESET_TOTP ADMIN_BOOTSTRAP_ENV
   ```

4. Confirm the command output reports only non-secret status and the expected
   admin username/role. It must not print `ADMIN_PASSWORD`.

5. Verify the old admin password no longer works and the new admin password
   starts the normal admin login flow. If `ADMIN_RESET_TOTP='false'`, the
   existing admin TOTP enrollment should still be required. If it was set to
   `true`, re-enroll TOTP from the admin auth flow.

6. Confirm no service topology changed:

   ```sh
   docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
   curl -s http://127.0.0.1:3000/api/health
   ss -ltnp | grep -E ':3000|:5432|:55432|:9050|:9051|:80|:443' || true
   ```

   Expected host listeners remain limited to `127.0.0.1:3000`, plus any
   explicitly accepted local-only postgres maintenance mapping.

## Legacy Base Tor Service

The base `tor` service in `backend/docker-compose.yml` is not part of the
production split-onion deployment. It is retained only for legacy/dev use and is
gated behind the explicit `legacy-onion` profile.

Default compose service checks must not include `tor`:

```sh
docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  config --services
```

Expected default services include `postgres` and `app`, but not `tor`.

To inspect or run the legacy service manually, opt in explicitly:

```sh
docker compose --profile legacy-onion \
  --env-file backend/.env \
  -f backend/docker-compose.yml \
  config --services
```

The split business, admin, and auth onion services are separate and continue to
use their own `business-onion`, `admin-onion`, and `auth-onion` profiles.

## Proxy Deployment

If any of these files changed:

- `backend/business-proxy/nginx.conf`
- `backend/admin-proxy/nginx.conf`
- `backend/auth-proxy/nginx.conf`

Then:

1. Back up the proxy config.
2. Recreate the changed proxy with `--no-deps --force-recreate`.
3. Wait for the proxy container to be running.
4. Recreate the matching Tor container with `--no-deps --force-recreate`.
5. Wait for `Bootstrapped 100% (done): Done`.
6. Verify the onion hostname is unchanged.

## Compose Examples

Business proxy change:

```sh
docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.business-onion.override.yml \
  --profile business-onion \
  up -d --no-deps --force-recreate business-proxy

docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.business-onion.override.yml \
  --profile business-onion \
  up -d --no-deps --force-recreate business-tor
```

Auth proxy change:

```sh
docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.auth-onion.override.yml \
  --profile auth-onion \
  up -d --no-deps --force-recreate auth-proxy

docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.auth-onion.override.yml \
  --profile auth-onion \
  up -d --no-deps --force-recreate auth-tor
```

Admin proxy change:

```sh
docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.admin-onion.override.yml \
  --profile admin-onion \
  up -d --no-deps --force-recreate admin-proxy

docker compose --env-file backend/.env \
  -f backend/docker-compose.yml \
  -f backend/docker-compose.prod.override.yml \
  -f backend/docker-compose.admin-onion.override.yml \
  --profile admin-onion \
  up -d --no-deps --force-recreate admin-tor
```

## Required Verification

After any proxy/Tor deployment:

```sh
curl -s http://127.0.0.1:3000/api/health

docker logs --tail=120 ielts-practice-business-tor | grep 'Bootstrapped 100%.*Done' || true
docker logs --tail=120 ielts-practice-admin-tor | grep 'Bootstrapped 100%.*Done' || true
docker logs --tail=120 ielts-practice-auth-tor | grep 'Bootstrapped 100%.*Done' || true

docker exec ielts-practice-business-tor sh -lc 'cat /var/lib/tor/hidden_service/hostname'
docker exec ielts-practice-admin-tor sh -lc 'cat /var/lib/tor/admin_hidden_service/hostname'
docker exec ielts-practice-auth-tor sh -lc 'cat /var/lib/tor/auth_hidden_service/hostname'

ss -ltnp | grep -E ':3000|:5432|:55432|:9050|:9051|:80|:443' || true
```

Expected:

- app health returns `{"ok":true}`
- each affected Tor container shows `Bootstrapped 100% (done): Done`
- onion hostnames are unchanged
- host ports expose only `127.0.0.1:3000`
- no host listeners on `5432`, `55432`, `9050`, `9051`, `80`, or `443`

## Manual Smoke Tests

Business onion:

- `/` loads the business app.
- unauthenticated login goes to the auth onion, not business `/auth/login`.
- `/admin` and `/api/admin` remain blocked.

Auth onion:

- `/` redirects to `/auth/login`.
- business login flow uses `/auth/business/login?state=...`.
- admin login flow uses `/auth/admin/login?state=...`.

Admin onion:

- client authorization is still required.
- unauthenticated `/admin` starts the admin auth flow.
- ordinary learner accounts cannot complete the admin flow.
