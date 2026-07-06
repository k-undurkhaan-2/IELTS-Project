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

The business UI depends on generated Listening runtime assets at:

- `assets/generated/listening-exams/manifest.js`
- `assets/generated/listening-exams/listening-index.compat.js`
- `assets/generated/listening-exams/listening-practice-unified.html`
- `ListeningPractice/`

Production app-image builds must include those files and directories. Do not
stage deployment sources from Git-tracked files only unless the generated
Listening index files are present in that staged source. If they are omitted,
the app can remain healthy while the business Listening entry disappears.

Before recreating `app`, verify the app image contains the generated Listening
index files:

```sh
docker run --rm --entrypoint sh backend-app:latest -lc '
  test -s /app/assets/generated/listening-exams/manifest.js
  test -s /app/assets/generated/listening-exams/listening-index.compat.js
  test -s /app/assets/generated/listening-exams/listening-practice-unified.html
  test -d /app/ListeningPractice
'
```

After recreating `app`, verify the public generated index endpoints return
`200` and that protected Listening practice content still requires auth:

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/assets/generated/listening-exams/manifest.js
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/assets/generated/listening-exams/listening-index.compat.js
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:3000/practice/listening/test
```

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
