# Development Guide

This guide lists tracked development entry points and general repository rules. It does not replace security-reviewed deployment procedures.

## Repository structure

The main public areas are:

- `index.html`, `js/`, `css/`, `src/`, and `templates/` for the IELTMPS Web Client.
- `assets/` for public runtime assets, generated practice data, vendor material, dictionaries, fonts, and images with differing provenance.
- `backend/` for the IELTMPS Server, PostgreSQL migrations, Compose configuration, and server tests.
- `scripts/` for the canonical bundle builder and supporting project scripts.
- `developer/` for development dependencies, tests, historical documentation, and release tooling.
- `ListeningPractice/` for a narrowly tracked integration shell around separately controlled runtime content.
- `docs/` for the approved public documentation set.

Not every tracked asset has the same license or content rights. Do not move private resources into a public path merely to make a local environment work.

## Development prerequisites

Choose tooling according to the work being performed:

- Node.js and npm for the Server, JavaScript tests, and bundle generation.
- Python for the tracked static and E2E test runners.
- Playwright and its browser dependencies for E2E flows.
- Docker with Compose support for the containerized development/self-hosted path.
- PostgreSQL when running the Server outside Compose.

Dependency setup is not fully consolidated into one cross-platform command. In particular, older testing documentation refers to environment assumptions that require local verification. Do not treat an absent dependency manifest or an old task document as an authoritative setup contract.

## Canonical bundle builder

The canonical frontend bundle command is:

```text
node scripts/build-bundles.mjs
```

Generated files identify this builder and state that they should not be edited by hand. Change canonical source first, run the builder in an authorized implementation batch, and review both source and generated output.

A separate VIP profile exists for the narrowly tracked compatibility shell, but it can interact with separately controlled resources. Do not run or document that profile as a general public workflow without confirming the resource boundary.

## Backend commands

The tracked backend package defines `start`, `test`, migration, administrator bootstrap, Compose-profile checking, and PostgreSQL smoke scripts.

For backend unit and integration tests:

```text
npm --prefix backend test
```

For a direct local backend workflow, the currently documented tracked commands are:

```text
npm --prefix backend install
npm --prefix backend run migrate
npm --prefix backend run bootstrap:admin
npm --prefix backend start
```

These commands require a locally configured backend environment. Never commit environment files or real credentials. Migration and bootstrap commands change local runtime state and should be run only for an intentional development environment.

## Static and E2E test entry points

The tracked static suite entry point is:

```text
python developer/tests/ci/run_static_suite.py
```

The tracked aggregate Python runner is:

```text
python developer/tests/run_all_tests.py
```

Tracked direct E2E flow entry points include:

```text
python developer/tests/e2e/suite_practice_flow.py
python developer/tests/e2e/listening_practice_flow.py
```

The developer package also defines Playwright and Vitest scripts:

```text
npm --prefix developer test
npm --prefix developer run test:unit
```

Python E2E commands require Playwright and a compatible browser installation. Listening tests can also depend on the authorized resource set available to the local environment. A command’s presence does not guarantee that every optional fixture or private resource is available.

Run the narrowest relevant check for an implementation change. This documentation-only batch does not execute builds or tests.

## Docker Compose development path

The tracked server-assisted development/self-hosted path starts from the environment example and base Compose file:

```powershell
Copy-Item backend\.env.example backend\.env
docker compose --env-file backend\.env -f backend\docker-compose.yml up --build
```

Review every required environment placeholder before starting. Do not commit the resulting file.

This path is a development/self-hosted starting point. It is not a complete public-service security procedure. Tor exposure, protected resources, backups, monitoring, reverse proxies, and production secrets require separate security-owner review.

## Documentation-only validation

For documentation-only work, use the following conservative command set because each command covers a different part of the working tree:

```powershell
git status --short --untracked-files=all
git diff --check
git diff --cached --check
git diff HEAD --check
git diff --name-only
git diff --cached --name-only
git ls-files --others --exclude-standard
```

`git diff --check` examines unstaged changes to tracked files. `git diff --cached --check` examines staged changes to tracked files. `git diff HEAD --check` checks staged and unstaged tracked changes relative to `HEAD`. Git diff commands do not automatically inspect untracked files, so enumerate those files with `git ls-files --others --exclude-standard` and validate them directly. Do not stage untracked files merely to validate them.

Inspect every changed Markdown file for:

- Relative links that point to missing files.
- README anchors that do not match actual headings.
- Claims that turn planned work into current functionality.
- Unsupported license identifiers or ownership claims.
- Real service addresses, credentials, or private topology.
- Terminology drift between IELTMPS Project, IELTMPS Web Client, IELTMPS Server, and IELTMPS Hosted Service.
- Accidental publication of private content.

For every untracked Markdown file reported by `git ls-files --others --exclude-standard`, directly check for trailing whitespace, a missing final newline, broken relative links, unbalanced code fences, and accidental local paths or secrets. On Windows, `git diff --no-index -- NUL <file>` is an optional way to display an untracked file for review; exit code `1` normally means that a difference was displayed.

Documentation-only validation does not require rebuilding the application when no source, generated bundle, package, deployment, or runtime file changed.

## Generated-file policy

Do not manually edit generated JavaScript bundles. The source change and canonical builder output must remain associated and reviewable.

Generated exam or content files require an additional content-rights check. Generation does not erase the rights attached to source articles, questions, audio, images, dictionaries, fonts, or explanations.

Release artifacts must eventually include applicable licenses, notices, and corresponding source. That work is separate from this documentation batch.

## Public and private resource separation

Keep these categories distinct:

1. Public source code and approved public documentation.
2. Public runtime assets with verified distribution rights.
3. Separately authorized private runtime content.
4. Deployment secrets and operator-specific configuration.
5. Local user data, database exports, backups, and logs.

Environment files, hidden-service keys, client-auth credentials, private overlays, database dumps, and private content must remain outside public commits and release artifacts.

If a feature appears broken because a private resource is missing, do not copy that resource into the repository. Confirm the source-of-truth and deployment contract first.

## Worktree discipline

Before editing:

- Confirm the repository root, current branch, HEAD, and working-tree status.
- Read applicable guard or task files.
- Preserve pre-existing user changes.
- Keep the diff within the authorized paths.
- Do not switch branches, clean files, or rewrite history to satisfy a task checkpoint.

After editing:

- Re-run the required status and diff checks.
- Verify that no unrelated or forbidden file changed.
- Leave staging, commits, pushes, merges, tags, and deployment to explicitly authorized follow-up work.

Security, protected resources, server authority, production deployment, and public/private resource questions require the designated integration and security review rather than an assumption by a documentation or frontend change.
