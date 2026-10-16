// SPDX-FileCopyrightText: 2026 Kevin
// SPDX-License-Identifier: AGPL-3.0-only

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const session = require('express-session');

const { MemoryAdminStore } = require('../src/admin');
const { createApp } = require('../src/app');
const { MemoryAuthStore } = require('../src/auth');
const { MemoryAuthHandoffStore } = require('../src/authHandoff');
const { MemoryAuthSessionStore } = require('../src/authSessions');
const { MemoryPracticeRecordStore } = require('../src/practiceRecords');
const {
    PublicListeningFrontendError,
    buildPublicListeningFrontendTestAuthority,
    loadPublicListeningFrontend
} = require('../src/publicListeningFrontend');
const { MemoryTotpStore } = require('../src/totp');

const TEST_SOURCE_COMMIT = 'a'.repeat(40);
const TEST_SOURCE_COMMIT_TREE = 'b'.repeat(40);
const TEST_SOURCE_TREE = 'c'.repeat(40);
const TEST_ARTIFACT_VERSION = 'lpf-test-a2-0000000000000000';
const TEST_MANIFEST_PATH = 'assets/generated/listening-exams/manifest.js';
const TEST_INDEX_PATH = 'assets/generated/listening-exams/listening-index.compat.js';
const ACCEPTED_A2_PUBLIC_SHELL_CSP = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src 'self' 'unsafe-inline'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; child-src 'self' blob:; worker-src 'self' blob:; manifest-src 'self'";
const EXPECTED_LISTENING_WRAPPER_CSP = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'none'; frame-src 'self'; child-src 'self'; worker-src 'self' blob:; manifest-src 'self'";
const EXPECTED_RAW_PRIVATE_LISTENING_CSP = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'none'; script-src 'self' 'unsafe-inline'; script-src-attr 'unsafe-inline'; style-src 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' data: blob:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'self' blob:; manifest-src 'self'; sandbox allow-scripts allow-downloads allow-same-origin";
const LISTENING_FIXTURE_BYTES = /PUBLIC-SHELL-BYTES|listening-p2-private|listeningExamIndex|Synthetic Wrapper|PRIVATE-EXAM-BYTES|LEGACY-LOWERCASE-PRIVATE-BYTES/;

function digest(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function writeFile(root, relativePath, value) {
    const targetPath = path.join(root, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, value);
    return targetPath;
}

function createSyntheticArtifact(t) {
    const artifactRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ielts-public-listening-artifact-'));
    const versionRoot = path.join(artifactRoot, TEST_ARTIFACT_VERSION);
    const payloadRoot = path.join(versionRoot, 'payload');
    const imageRoot = path.join(artifactRoot, 'image-root');
    const payload = new Map([
        [
            'index.html',
            Buffer.from('<!doctype html><title>Synthetic Public Listening Shell</title><p>PUBLIC-SHELL-BYTES</p>', 'utf8')
        ],
        [
            'css/main.css',
            Buffer.from('body { color: rgb(1, 2, 3); }\n', 'utf8')
        ],
        [
            TEST_MANIFEST_PATH,
            Buffer.from([
                'var __LISTENING_EXAM_MANIFEST__ = {',
                '  "listening-p2-private": {',
                '    "examId": "listening-p2-private",',
                '    "type": "listening",',
                '    "path": "P2/private",',
                '    "filename": "private.html",',
                '    "hasHtml": true',
                '  }',
                '};',
                ''
            ].join('\n'), 'utf8')
        ],
        [
            TEST_INDEX_PATH,
            Buffer.from('globalThis.listeningExamIndex = [{ id: "listening-p2-private", type: "listening" }];\n', 'utf8')
        ]
    ]);

    let payloadBytes = 0;
    for (const [payloadPath, value] of payload.entries()) {
        writeFile(payloadRoot, payloadPath, value);
        payloadBytes += value.length;
    }

    function integrityFields(value) {
        return {
            mode: '100644',
            git_blob: digest(Buffer.concat([Buffer.from('blob\0'), value])).slice(0, 40),
            length: value.length,
            sha256: digest(value)
        };
    }

    const approvedEntries = ['index.html', 'css/main.css'].map((payloadPath) => ({
        source_path: `ListeningPractice/vip special/${payloadPath}`,
        payload_path: payloadPath,
        role: 'runtime_required',
        included_in_runtime: true,
        ...integrityFields(payload.get(payloadPath))
    }));
    const wrapperHtml = Buffer.from('synthetic-wrapper-html', 'utf8');
    const wrapperBundle = Buffer.from('synthetic-wrapper-bundle', 'utf8');
    const generatedDependencies = [
        {
            source_path: TEST_MANIFEST_PATH,
            artifact_path: TEST_MANIFEST_PATH,
            required_image_path: '/app/assets/generated/listening-exams/manifest.js',
            ...integrityFields(payload.get(TEST_MANIFEST_PATH))
        },
        {
            source_path: TEST_INDEX_PATH,
            artifact_path: TEST_INDEX_PATH,
            required_image_path: '/app/assets/generated/listening-exams/listening-index.compat.js',
            ...integrityFields(payload.get(TEST_INDEX_PATH))
        },
        {
            source_path: 'assets/generated/listening-exams/listening-practice-unified.html',
            artifact_path: null,
            required_image_path: '/app/assets/generated/listening-exams/listening-practice-unified.html',
            ...integrityFields(wrapperHtml)
        },
        {
            source_path: 'js/bundles/listening-wrapper.bundle.js',
            artifact_path: null,
            required_image_path: '/app/js/bundles/listening-wrapper.bundle.js',
            ...integrityFields(wrapperBundle)
        }
    ];
    writeFile(imageRoot, 'assets/generated/listening-exams/listening-practice-unified.html', wrapperHtml);
    writeFile(imageRoot, 'js/bundles/listening-wrapper.bundle.js', wrapperBundle);

    const manifest = {
        schema: 'ieltmps.public-listening-frontend-manifest.v1',
        model: 'A2_ARTIFACT_RELATIVE_GENERATED_ASSETS',
        source_repository: 'fixture/repository',
        source_commit: TEST_SOURCE_COMMIT,
        source_commit_tree: TEST_SOURCE_COMMIT_TREE,
        source_tree: TEST_SOURCE_TREE,
        integrity_algorithm: 'SHA-256',
        approved_entries: approvedEntries,
        generated_dependencies: generatedDependencies
    };
    const manifestBuffer = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    const manifestSha256 = digest(manifestBuffer);
    writeFile(versionRoot, 'manifest.json', manifestBuffer);

    const authority = buildPublicListeningFrontendTestAuthority({
        artifactVersion: TEST_ARTIFACT_VERSION,
        manifestBytes: manifestBuffer.length,
        manifestSha256,
        payloadBytes,
        payloadPaths: Array.from(payload.keys()),
        sourceRepository: 'fixture/repository',
        sourceCommit: TEST_SOURCE_COMMIT,
        sourceCommitTree: TEST_SOURCE_COMMIT_TREE,
        sourceTree: TEST_SOURCE_TREE,
        approvedEntries: 2,
        runtimeSourceEntries: 2,
        buildOnlyEntries: 0,
        optionalEntries: 0,
        generatedDependencyRecords: 4,
        generatedPayloadEntries: 2,
        imageRootOnlyDependencies: 2
    });
    const locator = {
        schema: 'ieltmps.public-listening-frontend-active.v1',
        artifact_version: TEST_ARTIFACT_VERSION,
        manifest_path: `${TEST_ARTIFACT_VERSION}/manifest.json`,
        manifest_sha256: manifestSha256,
        manifest_bytes: manifestBuffer.length,
        payload_path: `${TEST_ARTIFACT_VERSION}/payload`,
        payload_files: payload.size,
        payload_bytes: payloadBytes,
        source_commit: TEST_SOURCE_COMMIT,
        source_tree: TEST_SOURCE_COMMIT_TREE,
        source_subtree: TEST_SOURCE_TREE
    };
    writeFile(artifactRoot, 'active.json', `${JSON.stringify(locator, null, 2)}\n`);

    t.after(() => {
        fs.rmSync(artifactRoot, { recursive: true, force: true });
    });
    return {
        artifactRoot,
        authority,
        locator,
        manifestBuffer,
        imageRoot,
        payload,
        payloadRoot,
        versionRoot
    };
}

function loadSyntheticArtifact(fixture) {
    return loadPublicListeningFrontend(
        fixture.artifactRoot,
        fixture.authority,
        { imageRoot: fixture.imageRoot }
    );
}

function createSyntheticStaticRoot(t) {
    const staticRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ielts-public-listening-static-'));
    writeFile(staticRoot, 'index.html', '<!doctype html><title>Synthetic App</title>');
    writeFile(staticRoot, 'assets/generated/listening-exams/listening-practice-unified.html', [
        '<!doctype html><html data-listening-wrapper="true"><head><title>Synthetic Wrapper</title></head>',
        '<body><div id="listening-wrapper-root" data-exam-id="" data-source-url="" data-base-href=""></div>',
        '<iframe id="listening-practice-frame"></iframe></body></html>'
    ].join(''));
    writeFile(
        staticRoot,
        'ListeningPractice/vip special/not-listed.js',
        'PRIVATE-FALLBACK-MUST-NOT-BE-SERVED\n'
    );
    writeFile(
        staticRoot,
        'ListeningPractice/vip special/ListeningPractice/P2/private/private.html',
        '<!doctype html><title>Synthetic Private Exam</title><p>PRIVATE-EXAM-BYTES</p>'
    );
    writeFile(
        staticRoot,
        'ListeningPractice/P1/legacy.html',
        '<!doctype html><title>Legacy lowercase private route</title><p>LEGACY-LOWERCASE-PRIVATE-BYTES</p>'
    );
    t.after(() => {
        fs.rmSync(staticRoot, { recursive: true, force: true });
    });
    return staticRoot;
}

async function listen(app) {
    const server = await new Promise((resolve, reject) => {
        const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
        listener.once('error', reject);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    return {
        baseUrl,
        close() {
            return new Promise((resolve, reject) => {
                server.close((error) => error ? reject(error) : resolve());
            });
        }
    };
}

function createCookieClient(baseUrl) {
    const cookies = new Map();
    let csrfToken = '';

    function splitSetCookie(value) {
        return String(value || '')
            .split(/,(?=\s*[^;,=\s]+=[^;,]*)/g)
            .map((item) => item.trim())
            .filter(Boolean);
    }

    function storeCookies(response) {
        const values = typeof response.headers.getSetCookie === 'function'
            ? response.headers.getSetCookie()
            : splitSetCookie(response.headers.get('set-cookie'));
        for (const value of values) {
            const first = value.split(';', 1)[0];
            const separator = first.indexOf('=');
            if (separator <= 0) continue;
            const name = first.slice(0, separator);
            const cookieValue = first.slice(separator + 1);
            if (cookieValue) cookies.set(name, cookieValue);
            else cookies.delete(name);
        }
    }

    async function request(method, requestPath, body) {
        const headers = {};
        if (cookies.size) {
            headers.cookie = Array.from(cookies.entries()).map(([name, value]) => `${name}=${value}`).join('; ');
        }
        if (csrfToken && method !== 'GET' && method !== 'HEAD') {
            headers['x-csrf-token'] = csrfToken;
        }
        if (body !== undefined) {
            headers['content-type'] = 'application/json';
        }
        const response = await fetch(`${baseUrl}${requestPath}`, {
            method,
            headers,
            redirect: 'manual',
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        storeCookies(response);
        const responseBody = Buffer.from(await response.arrayBuffer());
        const text = responseBody.toString('utf8');
        let json = null;
        try {
            json = text ? JSON.parse(text) : null;
        } catch (_) {
            json = null;
        }
        if (json?.csrfToken) csrfToken = json.csrfToken;
        return { response, body: responseBody, text, json };
    }

    function rawRequest(method, requestPath) {
        const target = new URL(baseUrl);
        const cookieHeader = Array.from(cookies.entries())
            .map(([name, value]) => `${name}=${value}`)
            .join('; ');
        return new Promise((resolve, reject) => {
            const request = http.request({
                hostname: target.hostname,
                port: target.port,
                method,
                path: requestPath,
                headers: cookieHeader ? { cookie: cookieHeader } : {}
            }, (response) => {
                const chunks = [];
                response.on('data', (chunk) => chunks.push(chunk));
                response.on('end', () => {
                    const responseBody = Buffer.concat(chunks);
                    const headers = new Headers();
                    for (const [name, value] of Object.entries(response.headers)) {
                        if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
                        else if (value !== undefined) headers.set(name, value);
                    }
                    resolve({
                        response: {
                            status: response.statusCode,
                            headers
                        },
                        body: responseBody,
                        text: responseBody.toString('utf8')
                    });
                });
            });
            request.once('error', reject);
            request.end();
        });
    }

    return {
        request,
        rawRequest,
        csrf() {
            return request('GET', '/api/auth/csrf');
        }
    };
}

async function createAuthenticatedFixtureClient(t, frontend, staticRoot) {
    const sessionStore = new session.MemoryStore();
    const authStore = new MemoryAuthStore({ sessionStore });
    const authSessionStore = new MemoryAuthSessionStore();
    const totpStore = new MemoryTotpStore();
    const practiceStore = new MemoryPracticeRecordStore();
    const adminStore = new MemoryAdminStore({ authStore, practiceStore, totpStore, sessionStore });
    const app = createApp({
        authStore,
        authSessionStore,
        totpStore,
        practiceStore,
        adminStore,
        authHandoffStore: new MemoryAuthHandoffStore(),
        sessionStore,
        sessionSecret: 'test-session-secret-0123456789abcdef',
        nodeEnv: 'test',
        staticRoot,
        publicListeningFrontendFixture: frontend,
        totpEnabled: false,
        trafficEnabled: false,
        rateLimit: { maxAttempts: 100, windowMs: 60_000 },
        totpEncryptionKey: 'test-totp-key'
    });
    const running = await listen(app);
    t.after(() => running.close());
    return {
        app,
        authSessionStore,
        authStore,
        client: createCookieClient(running.baseUrl)
    };
}

test('public Listening loader verifies its exact synthetic inventory and serves only retained bytes', async (t) => {
    const fixture = createSyntheticArtifact(t);
    const frontend = loadSyntheticArtifact(fixture);
    const expectedIndexBytes = Buffer.from(fixture.payload.get('index.html'));

    assert.equal(frontend.ready, true);
    assert.equal(frontend.artifactVersion, TEST_ARTIFACT_VERSION);
    assert.equal(frontend.payloadFiles, 4);
    assert.equal(frontend.payloadBytes, Array.from(fixture.payload.values())
        .reduce((total, value) => total + value.length, 0));
    assert.equal(frontend.hasShellFile('index.html'), true);
    assert.equal(frontend.hasShellFile('css/main.css'), true);
    assert.equal(frontend.hasShellFile(TEST_MANIFEST_PATH), true);
    assert.equal(frontend.hasShellFile('not-listed.js'), false);
    assert.match(frontend.getGeneratedText('/assets/generated/listening-exams/manifest.js'), /listening-p2-private/);

    const staticRoot = createSyntheticStaticRoot(t);
    const { client } = await createAuthenticatedFixtureClient(t, frontend, staticRoot);
    await client.csrf();
    const registered = await client.request('POST', '/api/auth/register', {
        username: 'retained_bytes_user',
        password: 'StrongPass1'
    });
    assert.equal(registered.response.status, 201);

    const mutatedDiskBytes = Buffer.from('MUTATED-AFTER-VERIFICATION', 'utf8');
    writeFile(fixture.payloadRoot, 'index.html', mutatedDiskBytes);
    const served = await client.request('GET', '/ListeningPractice/vip%20special/');
    assert.equal(served.response.status, 200);
    assert.deepEqual(served.body, expectedIndexBytes);
    assert.notDeepEqual(served.body, mutatedDiskBytes);
});

test('public Listening loader rejects Locator, Manifest, Payload and inventory corruption', async (t) => {
    await t.test('strict active locator schema', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        writeFile(fixture.artifactRoot, 'active.json', `${JSON.stringify({
            ...fixture.locator,
            unexpected: true
        })}\n`);
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            (error) => error instanceof PublicListeningFrontendError && /unexpected schema/.test(error.message)
        );
    });

    await t.test('Manifest bytes and digest', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        fs.appendFileSync(path.join(fixture.versionRoot, 'manifest.json'), ' ');
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            /Manifest byte length/
        );
    });

    await t.test('same-length Manifest corruption is rejected by SHA-256', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        const corrupted = Buffer.from(fixture.manifestBuffer);
        const mutationOffset = corrupted.indexOf(Buffer.from('fixture/repository', 'utf8'));
        assert.notEqual(mutationOffset, -1);
        corrupted[mutationOffset] ^= 1;
        assert.equal(corrupted.length, fixture.authority.manifestBytes);
        assert.notEqual(digest(corrupted), fixture.authority.manifestSha256);
        fs.writeFileSync(path.join(fixture.versionRoot, 'manifest.json'), corrupted);
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            /Manifest SHA-256/
        );
    });

    await t.test('per-file Payload checksum', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        const targetPath = path.join(
            fixture.payloadRoot,
            'css',
            'main.css'
        );
        const original = fs.readFileSync(targetPath);
        original[0] ^= 1;
        fs.writeFileSync(targetPath, original);
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            /payload integrity mismatch/
        );
    });

    await t.test('unexpected Payload file', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        writeFile(fixture.payloadRoot, 'unexpected.js', 'unexpected');
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            /does not match the authorized inventory/
        );
    });

    await t.test('image-root-only dependency checksum', (inner) => {
        const fixture = createSyntheticArtifact(inner);
        const targetPath = path.join(fixture.imageRoot, 'js', 'bundles', 'listening-wrapper.bundle.js');
        const original = fs.readFileSync(targetPath);
        original[0] ^= 1;
        fs.writeFileSync(targetPath, original);
        assert.throws(
            () => loadSyntheticArtifact(fixture),
            /Image-root dependency integrity mismatch/
        );
    });
});

test('public Listening loader rejects symlinked Payload entries and path escape', (t) => {
    const fixture = createSyntheticArtifact(t);
    const outsidePath = path.join(os.tmpdir(), `ielts-public-listening-outside-${path.basename(fixture.artifactRoot)}.css`);
    fs.writeFileSync(outsidePath, 'OUTSIDE-ARTIFACT-BYTES');
    t.after(() => fs.rmSync(outsidePath, { force: true }));
    const targetPath = path.join(
        fixture.payloadRoot,
        'css',
        'main.css'
    );
    fs.rmSync(targetPath);
    try {
        fs.symlinkSync(outsidePath, targetPath, 'file');
    } catch (error) {
        assert.fail(`required symlink fixture unavailable: ${error.message}`);
    }
    assert.throws(
        () => loadSyntheticArtifact(fixture),
        /symlink/
    );
});

test('authenticated A2 public routes enforce allowlists, CSP separation and private containment', async (t) => {
    const fixture = createSyntheticArtifact(t);
    const frontend = loadSyntheticArtifact(fixture);
    const staticRoot = createSyntheticStaticRoot(t);
    const { client, authSessionStore } = await createAuthenticatedFixtureClient(t, frontend, staticRoot);

    const accessMatrix = [
        { path: '/ListeningPractice/vip%20special/', forbidden: /PUBLIC-SHELL-BYTES/ },
        { path: '/assets/generated/listening-exams/manifest.js', forbidden: /listening-p2-private/ },
        { path: '/assets/generated/listening-exams/listening-index.compat.js', forbidden: /listeningExamIndex/ },
        { path: '/practice/listening/listening-p2-private', forbidden: /Synthetic Wrapper|data-listening-wrapper/ },
        {
            path: '/ListeningPractice/vip%20special/ListeningPractice/P2/private/private.html',
            forbidden: /PRIVATE-EXAM-BYTES/
        },
        { path: '/listeningpractice/P1/legacy.html', forbidden: /LEGACY-LOWERCASE-PRIVATE-BYTES/ }
    ];
    for (const { path: protectedPath, forbidden } of accessMatrix) {
        const anonymous = await client.request('GET', protectedPath);
        assert.equal(anonymous.response.status, 401, protectedPath);
        assert.doesNotMatch(anonymous.text, forbidden);
    }

    await client.csrf();
    const registered = await client.request('POST', '/api/auth/register', {
        username: 'synthetic_listening_user',
        password: 'StrongPass1'
    });
    assert.equal(registered.response.status, 201);

    const shell = await client.request('GET', '/ListeningPractice/vip%20special/');
    assert.equal(shell.response.status, 200);
    assert.match(shell.text, /PUBLIC-SHELL-BYTES/);
    assert.equal(shell.response.headers.get('content-security-policy'), ACCEPTED_A2_PUBLIC_SHELL_CSP);
    assert.doesNotMatch(shell.response.headers.get('content-security-policy') || '', /sandbox/);

    const explicitIndex = await client.request('GET', '/ListeningPractice/vip%20special/index.html');
    assert.equal(explicitIndex.response.status, 200);
    assert.match(explicitIndex.text, /PUBLIC-SHELL-BYTES/);

    const stylesheet = await client.request('GET', '/ListeningPractice/vip%20special/css/main.css');
    assert.equal(stylesheet.response.status, 200);
    assert.match(stylesheet.text, /rgb\(1, 2, 3\)/);
    assert.equal(stylesheet.response.headers.get('content-security-policy'), ACCEPTED_A2_PUBLIC_SHELL_CSP);

    const rootManifest = await client.request('GET', '/assets/generated/listening-exams/manifest.js');
    assert.equal(rootManifest.response.status, 200);
    assert.match(rootManifest.text, /listening-p2-private/);
    assert.notEqual(rootManifest.response.headers.get('content-security-policy'), ACCEPTED_A2_PUBLIC_SHELL_CSP);

    const rootIndex = await client.request('GET', '/assets/generated/listening-exams/listening-index.compat.js');
    assert.equal(rootIndex.response.status, 200);
    assert.match(rootIndex.text, /listeningExamIndex/);
    assert.notEqual(rootIndex.response.headers.get('content-security-policy'), ACCEPTED_A2_PUBLIC_SHELL_CSP);

    const shellManifest = await client.request(
        'GET',
        '/ListeningPractice/vip%20special/assets/generated/listening-exams/manifest.js'
    );
    assert.equal(shellManifest.response.status, 200);
    assert.match(shellManifest.text, /listening-p2-private/);
    assert.equal(shellManifest.response.headers.get('content-security-policy'), ACCEPTED_A2_PUBLIC_SHELL_CSP);

    const privateExam = await client.request(
        'GET',
        '/ListeningPractice/vip%20special/ListeningPractice/P2/private/private.html'
    );
    assert.equal(privateExam.response.status, 200);
    assert.match(privateExam.text, /PRIVATE-EXAM-BYTES/);
    const privateCsp = privateExam.response.headers.get('content-security-policy') || '';
    assert.equal(privateCsp, EXPECTED_RAW_PRIVATE_LISTENING_CSP);

    const legacyLowercasePrivate = await client.request('GET', '/listeningpractice/P1/legacy.html');
    assert.equal(legacyLowercasePrivate.response.status, 200);
    assert.match(legacyLowercasePrivate.text, /LEGACY-LOWERCASE-PRIVATE-BYTES/);
    assert.equal(
        legacyLowercasePrivate.response.headers.get('content-security-policy'),
        EXPECTED_RAW_PRIVATE_LISTENING_CSP
    );

    const wrapper = await client.request('GET', '/practice/listening/listening-p2-private');
    assert.equal(wrapper.response.status, 200);
    assert.match(wrapper.text, /Synthetic Wrapper/);
    assert.match(wrapper.text, /data-source-url="\/ListeningPractice\/vip%20special\/ListeningPractice\/P2\/private\/private.html"/);
    assert.match(wrapper.text, /data-base-href="\/ListeningPractice\/vip%20special\/ListeningPractice\/P2\/private\/"/);
    const wrapperCsp = wrapper.response.headers.get('content-security-policy') || '';
    assert.equal(wrapperCsp, EXPECTED_LISTENING_WRAPPER_CSP);

    for (const [method, rejectedPath, expectedStatus] of [
        ['GET', 'http://example.invalid/ListeningPractice/vip%20special/index.html', 400],
        ['HEAD', 'http://example.invalid/ListeningPractice/vip%20special/index.html', 400],
        ['GET', '/ListeningPractice/vip%20special/not-listed.js', 404],
        ['GET', '//ListeningPractice/vip%20special/index.html', 400],
        ['GET', '/ListeningPractice//vip%20special/index.html', 404],
        ['GET', '/listeningpractice/vip%20special/index.html', 404],
        ['GET', '/ListeningPractice/vip%20speciality/index.html', 404],
        ['GET', '/ListeningPractice/vip%2520special/index.html', 404],
        ['GET', '/ListeningPractice/vip%20special/%69ndex.html', 400],
        ['GET', '/ListeningPractice/vip%20special/%2e%2e/index.html', 400],
        ['GET', '/ListeningPractice/vip%20special/assets%2Fgenerated/listening-exams/manifest.js', 400],
        ['GET', '/assets/%67enerated/listening-exams/manifest.js', 404],
        ['GET', '//assets/generated/listening-exams/manifest.js', 400],
        ['GET', '/assets/generated/listening-exams/manifest.js.', 404],
        ['GET', '/assets/generated/listening-exams/manifest.js%2Fextra', 404],
        ['GET', '/ListeningPractice/vip%20special/ListeningPractice/%2e%2e/private.html', 400]
    ]) {
        const rejected = await client.rawRequest(method, rejectedPath);
        assert.equal(rejected.response.status, expectedStatus, `${method} ${rejectedPath}`);
        assert.doesNotMatch(rejected.text, LISTENING_FIXTURE_BYTES);
        assert.doesNotMatch(rejected.text, /PRIVATE-FALLBACK-MUST-NOT-BE-SERVED/);
    }

    const revoked = await authSessionStore.revokeSessionsForUser(registered.json.user.id, null);
    assert(revoked >= 1);
    for (const { path: protectedPath, forbidden } of accessMatrix) {
        const afterRevoke = await client.request('GET', protectedPath);
        assert.equal(afterRevoke.response.status, 401, protectedPath);
        assert.doesNotMatch(afterRevoke.text, forbidden);
    }
});

test('production readiness fails closed and production rejects fixture or root overrides', { concurrency: false }, async (t) => {
    const fixture = createSyntheticArtifact(t);
    const frontend = loadSyntheticArtifact(fixture);

    function createProductionOptions(label) {
        const sessionStore = new session.MemoryStore();
        const authStore = new MemoryAuthStore({ sessionStore });
        const authSessionStore = new MemoryAuthSessionStore();
        const totpStore = new MemoryTotpStore();
        const practiceStore = new MemoryPracticeRecordStore();
        const adminStore = new MemoryAdminStore({ authStore, practiceStore, totpStore, sessionStore });
        return {
            authStore,
            authSessionStore,
            totpStore,
            practiceStore,
            adminStore,
            authHandoffStore: new MemoryAuthHandoffStore(),
            sessionStore,
            nodeEnv: 'production',
            sessionSecret: `production-session-secret-${label}-0123456789abcdef`,
            authHandoffSecret: `production-handoff-secret-${label}-0123456789abcdef`,
            authPublicUrl: `http://${'a'.repeat(56)}.onion`,
            businessPublicUrl: `http://${'b'.repeat(56)}.onion`,
            adminPublicUrl: `http://${'c'.repeat(56)}.onion`,
            totpEnabled: false,
            trafficEnabled: false,
            totpEncryptionKey: 'production-totp-key-0123456789abcdef'
        };
    }

    const overrideOptions = createProductionOptions('override');
    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
        assert.throws(
            () => createApp({
                ...overrideOptions,
                nodeEnv: 'test',
                publicListeningFrontendFixture: frontend
            }),
            /available only to non-production tests/
        );
        assert.throws(
            () => createApp({
                ...overrideOptions,
                nodeEnv: 'test',
                publicListeningFrontendRoot: fixture.artifactRoot
            }),
            /not a supported runtime override/
        );
        assert.throws(
            () => createApp({
                ...overrideOptions,
                nodeEnv: 'test',
                publicListeningFrontendAuthority: fixture.authority
            }),
            /not a supported runtime override/
        );
        await assertUnavailableDataPlane(createApp, 'node-env-backstop', { nodeEnv: 'test' });
    } finally {
        if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = previousNodeEnv;
    }

    async function assertUnavailableDataPlane(createAppImplementation, label, optionOverrides = {}) {
        const app = createAppImplementation({
            ...createProductionOptions(label),
            ...optionOverrides
        });
        assert.equal(app.locals.publicListeningFrontendReadiness.required, true);
        assert.equal(app.locals.publicListeningFrontendReadiness.ready, false);
        assert.equal(app.locals.publicListeningFrontendReadiness.errorCode, 'PUBLIC_LISTENING_FRONTEND_INVALID');
        const running = await listen(app);
        t.after(() => running.close());
        const client = createCookieClient(running.baseUrl);

        const health = await client.request('GET', '/api/health');
        assert.equal(health.response.status, 503);
        assert.deepEqual(health.json, {
            ok: false,
            readiness: {
                publicListeningFrontend: 'unavailable'
            }
        });
        assert.doesNotMatch(health.text, LISTENING_FIXTURE_BYTES);

        await client.csrf();
        const registered = await client.request('POST', '/api/auth/register', {
            username: `unavailable_${label}`,
            password: 'StrongPass1'
        });
        assert.equal(registered.response.status, 201);

        for (const governedPath of [
            '/ListeningPractice/vip%20special/',
            '/ListeningPractice/vip%20special/index.html',
            '/ListeningPractice/vip%20special/css/main.css',
            '/ListeningPractice/vip%20special/assets/generated/listening-exams/manifest.js',
            '/assets/generated/listening-exams/manifest.js',
            '/assets/generated/listening-exams/listening-index.compat.js',
            '/practice/listening/listening-p2-private'
        ]) {
            const unavailable = await client.request('GET', governedPath);
            assert.equal(unavailable.response.status, 503, `${label}: ${governedPath}`);
            assert.equal(unavailable.response.headers.get('cache-control'), 'no-store');
            assert.doesNotMatch(unavailable.text, LISTENING_FIXTURE_BYTES);
        }
    }

    await assertUnavailableDataPlane(createApp, 'missing');

    const appModulePath = require.resolve('../src/app');
    const frontendModulePath = require.resolve('../src/publicListeningFrontend');
    const cachedAppModule = require.cache[appModulePath];
    const frontendModule = require(frontendModulePath);
    const originalProductionLoader = frontendModule.loadProductionPublicListeningFrontend;
    let createAppWithCorruptedArtifact;
    try {
        frontendModule.loadProductionPublicListeningFrontend = () => {
            throw new PublicListeningFrontendError('Synthetic production artifact corruption');
        };
        delete require.cache[appModulePath];
        createAppWithCorruptedArtifact = require(appModulePath).createApp;
    } finally {
        frontendModule.loadProductionPublicListeningFrontend = originalProductionLoader;
        if (cachedAppModule) require.cache[appModulePath] = cachedAppModule;
        else delete require.cache[appModulePath];
    }
    await assertUnavailableDataPlane(createAppWithCorruptedArtifact, 'corrupted');
});
