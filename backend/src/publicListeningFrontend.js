// SPDX-FileCopyrightText: 2026 Kevin
// SPDX-License-Identifier: AGPL-3.0-only

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_LISTENING_FRONTEND_ROOT = '/app/public/listening-frontend';
const PUBLIC_LISTENING_FRONTEND_VERSION = 'lpf-v1-1a576be93d7d-a2-fad166773fa6259a';
const PUBLIC_LISTENING_FRONTEND_MANIFEST_BYTES = 12153;
const PUBLIC_LISTENING_FRONTEND_MANIFEST_SHA256 = 'fad166773fa6259a18c752c240030aa228390f8380b7be5dacac3b8ba8d4b75d';
const PUBLIC_LISTENING_FRONTEND_PAYLOAD_BYTES = 14533213;
const PUBLIC_LISTENING_FRONTEND_PAYLOAD_FILES = 26;
const PUBLIC_LISTENING_FRONTEND_SOURCE_REPOSITORY = 'k-undurkhaan-2/IELTS-Project';
const PUBLIC_LISTENING_FRONTEND_SOURCE_COMMIT = '1a576be93d7d18b8955adf5216efb311032bf62a';
const PUBLIC_LISTENING_FRONTEND_SOURCE_COMMIT_TREE = '4fcd96bc3f8564311bdf31853f4ba2e320b3343d';
const PUBLIC_LISTENING_FRONTEND_SOURCE_TREE = '2b9c9ef46ae748e6cb187114c5887d8a2f509fd5';
const PUBLIC_LISTENING_FRONTEND_LOCATOR_SCHEMA = 'ieltmps.public-listening-frontend-active.v1';
const PUBLIC_LISTENING_FRONTEND_MANIFEST_SCHEMA = 'ieltmps.public-listening-frontend-manifest.v1';
const PUBLIC_LISTENING_FRONTEND_MODELS = Object.freeze([
    'A2_ARTIFACT_RELATIVE_GENERATED_ASSETS',
    'A2_PUBLIC_ARTIFACT_RELATIVE_GENERATED_ASSETS'
]);
const PUBLIC_LISTENING_SHELL_PREFIX = '/ListeningPractice/vip%20special/';

const PUBLIC_LISTENING_CSP = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'self'",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline'",
    "script-src-attr 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-src 'self'",
    "child-src 'self' blob:",
    "worker-src 'self' blob:",
    "manifest-src 'self'"
].join('; ');

const PUBLIC_LISTENING_FRONTEND_PAYLOAD_PATHS = Object.freeze([
    'assets/data/vocabulary.json',
    'assets/fonts/wenkai-regular.woff2',
    'assets/images/favicon.svg',
    'assets/scripts/complete-exam-data.js',
    'assets/vendor/three.min.js',
    'assets/wordlists/ielts_core.json',
    'css/heroui-bridge.css',
    'css/main.css',
    'css/onboarding.css',
    'index.html',
    'js/bundles/browse.bundle.js',
    'js/bundles/core-foundation.bundle.js',
    'js/bundles/diagnostics.bundle.js',
    'js/bundles/legacy-app.bundle.js',
    'js/bundles/listening-record-bridge.bundle.js',
    'js/bundles/more.bundle.js',
    'js/bundles/practice-page-enhancer.bundle.js',
    'js/bundles/practice.bundle.js',
    'js/bundles/reading-page.bundle.js',
    'js/bundles/runtime-entry.bundle.js',
    'js/bundles/session.bundle.js',
    'js/bundles/settings.bundle.js',
    'js/bundles/theme.bundle.js',
    'js/bundles/ui-shell.bundle.js',
    'assets/generated/listening-exams/manifest.js',
    'assets/generated/listening-exams/listening-index.compat.js'
]);

const PUBLIC_LISTENING_GENERATED_DEPENDENCIES = Object.freeze([
    Object.freeze({
        requestPath: '/assets/generated/listening-exams/manifest.js',
        payloadPath: 'assets/generated/listening-exams/manifest.js',
        sourcePath: 'assets/generated/listening-exams/manifest.js',
        requiredImagePath: '/app/assets/generated/listening-exams/manifest.js'
    }),
    Object.freeze({
        requestPath: '/assets/generated/listening-exams/listening-index.compat.js',
        payloadPath: 'assets/generated/listening-exams/listening-index.compat.js',
        sourcePath: 'assets/generated/listening-exams/listening-index.compat.js',
        requiredImagePath: '/app/assets/generated/listening-exams/listening-index.compat.js'
    })
]);

const PUBLIC_LISTENING_IMAGE_ROOT_DEPENDENCIES = Object.freeze([
    Object.freeze({
        sourcePath: 'assets/generated/listening-exams/listening-practice-unified.html',
        requiredImagePath: '/app/assets/generated/listening-exams/listening-practice-unified.html'
    }),
    Object.freeze({
        sourcePath: 'js/bundles/listening-wrapper.bundle.js',
        requiredImagePath: '/app/js/bundles/listening-wrapper.bundle.js'
    })
]);

const LOADED_FRONTEND_BRAND = Symbol('loadedPublicListeningFrontend');

const PRODUCTION_PUBLIC_LISTENING_FRONTEND_AUTHORITY = Object.freeze({
    locatorSchema: PUBLIC_LISTENING_FRONTEND_LOCATOR_SCHEMA,
    manifestSchema: PUBLIC_LISTENING_FRONTEND_MANIFEST_SCHEMA,
    models: PUBLIC_LISTENING_FRONTEND_MODELS,
    artifactVersion: PUBLIC_LISTENING_FRONTEND_VERSION,
    manifestBytes: PUBLIC_LISTENING_FRONTEND_MANIFEST_BYTES,
    manifestSha256: PUBLIC_LISTENING_FRONTEND_MANIFEST_SHA256,
    payloadFiles: PUBLIC_LISTENING_FRONTEND_PAYLOAD_FILES,
    payloadBytes: PUBLIC_LISTENING_FRONTEND_PAYLOAD_BYTES,
    payloadPaths: PUBLIC_LISTENING_FRONTEND_PAYLOAD_PATHS,
    sourceRepository: PUBLIC_LISTENING_FRONTEND_SOURCE_REPOSITORY,
    sourceCommit: PUBLIC_LISTENING_FRONTEND_SOURCE_COMMIT,
    sourceCommitTree: PUBLIC_LISTENING_FRONTEND_SOURCE_COMMIT_TREE,
    sourceTree: PUBLIC_LISTENING_FRONTEND_SOURCE_TREE,
    approvedEntries: 31,
    runtimeSourceEntries: 24,
    buildOnlyEntries: 4,
    optionalEntries: 3,
    generatedDependencyRecords: 4,
    generatedPayloadEntries: 2,
    imageRootOnlyDependencies: 2,
    allowedModes: Object.freeze(['100644']),
    generatedDependencies: PUBLIC_LISTENING_GENERATED_DEPENDENCIES,
    imageRootDependencies: PUBLIC_LISTENING_IMAGE_ROOT_DEPENDENCIES
});

class PublicListeningFrontendError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PublicListeningFrontendError';
        this.code = 'PUBLIC_LISTENING_FRONTEND_INVALID';
    }
}

function fail(message) {
    throw new PublicListeningFrontendError(message);
}

function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function assertExactObjectKeys(value, expectedKeys, label) {
    if (!isPlainObject(value)) {
        fail(`${label} must be an object`);
    }
    const actual = Object.keys(value).sort();
    const expected = [...expectedKeys].sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
        fail(`${label} has an unexpected schema`);
    }
}

function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function isPathInside(parent, child) {
    const parentPath = path.resolve(parent);
    const childPath = path.resolve(child);
    const relative = path.relative(parentPath, childPath);
    return relative === '' || (relative && !relative.startsWith('..') && !path.isAbsolute(relative));
}

function normalizePayloadPath(value) {
    if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0')) {
        fail('Manifest payload paths must be non-empty POSIX paths');
    }
    const withoutPayloadPrefix = value.startsWith('payload/') ? value.slice('payload/'.length) : value;
    if (!withoutPayloadPrefix
        || withoutPayloadPrefix.startsWith('/')
        || withoutPayloadPrefix.endsWith('/')
        || withoutPayloadPrefix.includes('//')) {
        fail(`Invalid Manifest payload path: ${value}`);
    }
    const segments = withoutPayloadPrefix.split('/');
    if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
        fail(`Invalid Manifest payload path: ${value}`);
    }
    if (path.posix.normalize(withoutPayloadPrefix) !== withoutPayloadPrefix) {
        fail(`Non-canonical Manifest payload path: ${value}`);
    }
    return withoutPayloadPrefix;
}

function validateManifestEntryIntegrity(record, identityPath, authority) {
    if (!authority.allowedModes.includes(record.mode)) {
        fail(`Manifest mode is not authorized for ${identityPath}`);
    }
    if (typeof record.git_blob !== 'string' || !/^[a-f0-9]{40}$/.test(record.git_blob)) {
        fail(`Manifest Git blob is invalid for ${identityPath}`);
    }
    if (!Number.isSafeInteger(record.length) || record.length < 0) {
        fail(`Manifest byte length is invalid for ${identityPath}`);
    }
    if (typeof record.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(record.sha256)) {
        fail(`Manifest SHA-256 is invalid for ${identityPath}`);
    }
}

function validateRequiredImagePath(value) {
    if (typeof value !== 'string'
        || !value.startsWith('/app/')
        || value.includes('\\')
        || value.includes('\0')
        || path.posix.normalize(value) !== value) {
        fail('Manifest required image path is invalid');
    }
    return value;
}

function validateControlManifest(manifest, authority) {
    assertExactObjectKeys(manifest, [
        'schema',
        'model',
        'source_repository',
        'source_commit',
        'source_commit_tree',
        'source_tree',
        'integrity_algorithm',
        'approved_entries',
        'generated_dependencies'
    ], 'Manifest');
    if (manifest.schema !== authority.manifestSchema
        || !authority.models.includes(manifest.model)
        || manifest.source_repository !== authority.sourceRepository
        || manifest.source_commit !== authority.sourceCommit
        || manifest.source_commit_tree !== authority.sourceCommitTree
        || manifest.source_tree !== authority.sourceTree
        || manifest.integrity_algorithm !== 'SHA-256') {
        fail('Manifest identity does not match the immutable artifact authority');
    }
    if (!Array.isArray(manifest.approved_entries)
        || manifest.approved_entries.length !== authority.approvedEntries) {
        fail('Manifest approved-entry inventory is invalid');
    }
    if (!Array.isArray(manifest.generated_dependencies)
        || manifest.generated_dependencies.length !== authority.generatedDependencyRecords) {
        fail('Manifest generated-dependency inventory is invalid');
    }

    const payloadRecords = [];
    const approvedSourcePaths = new Set();
    const roleCounts = new Map([
        ['runtime_required', 0],
        ['build_only', 0],
        ['optional', 0]
    ]);
    for (const entry of manifest.approved_entries) {
        assertExactObjectKeys(entry, [
            'source_path',
            'payload_path',
            'role',
            'included_in_runtime',
            'mode',
            'git_blob',
            'length',
            'sha256'
        ], 'Manifest approved entry');
        const sourcePath = normalizePayloadPath(entry.source_path);
        if (approvedSourcePaths.has(sourcePath)) {
            fail(`Manifest contains a duplicate approved source path: ${sourcePath}`);
        }
        approvedSourcePaths.add(sourcePath);
        if (!roleCounts.has(entry.role)) {
            fail(`Manifest role is invalid for ${sourcePath}`);
        }
        roleCounts.set(entry.role, roleCounts.get(entry.role) + 1);
        validateManifestEntryIntegrity(entry, sourcePath, authority);
        const runtimeRequired = entry.role === 'runtime_required';
        if (entry.included_in_runtime !== runtimeRequired) {
            fail(`Manifest runtime classification is inconsistent for ${sourcePath}`);
        }
        if (!runtimeRequired) {
            if (entry.payload_path !== null) {
                fail(`Non-runtime Manifest entry has a payload path: ${sourcePath}`);
            }
            continue;
        }
        const payloadPath = normalizePayloadPath(entry.payload_path);
        payloadRecords.push(Object.freeze({
            payloadPath,
            bytes: entry.length,
            sha256: entry.sha256,
            mode: entry.mode
        }));
    }
    if (roleCounts.get('runtime_required') !== authority.runtimeSourceEntries
        || roleCounts.get('build_only') !== authority.buildOnlyEntries
        || roleCounts.get('optional') !== authority.optionalEntries) {
        fail('Manifest approved-entry classifications do not match the artifact authority');
    }

    const generatedIdentity = new Map();
    for (const entry of manifest.generated_dependencies) {
        assertExactObjectKeys(entry, [
            'source_path',
            'artifact_path',
            'required_image_path',
            'mode',
            'git_blob',
            'length',
            'sha256'
        ], 'Manifest generated dependency');
        const sourcePath = normalizePayloadPath(entry.source_path);
        if (generatedIdentity.has(sourcePath)) {
            fail(`Manifest contains a duplicate generated dependency: ${sourcePath}`);
        }
        const artifactPath = entry.artifact_path === null
            ? null
            : normalizePayloadPath(entry.artifact_path);
        const requiredImagePath = validateRequiredImagePath(entry.required_image_path);
        validateManifestEntryIntegrity(entry, sourcePath, authority);
        generatedIdentity.set(sourcePath, {
            artifactPath,
            requiredImagePath,
            bytes: entry.length,
            sha256: entry.sha256,
            mode: entry.mode
        });
        if (artifactPath !== null) {
            payloadRecords.push(Object.freeze({
                payloadPath: artifactPath,
                bytes: entry.length,
                sha256: entry.sha256,
                mode: entry.mode
            }));
        }
    }

    const generatedPayloadEntries = manifest.generated_dependencies
        .filter((entry) => entry.artifact_path !== null);
    const imageRootOnlyEntries = manifest.generated_dependencies
        .filter((entry) => entry.artifact_path === null);
    if (generatedPayloadEntries.length !== authority.generatedPayloadEntries
        || imageRootOnlyEntries.length !== authority.imageRootOnlyDependencies) {
        fail('Manifest generated dependency classifications do not match the artifact authority');
    }
    for (const expected of authority.generatedDependencies) {
        const actual = generatedIdentity.get(expected.sourcePath);
        if (!actual
            || actual.artifactPath !== expected.payloadPath
            || actual.requiredImagePath !== expected.requiredImagePath) {
            fail(`Generated payload dependency identity mismatch: ${expected.sourcePath}`);
        }
    }
    for (const expected of authority.imageRootDependencies) {
        const actual = generatedIdentity.get(expected.sourcePath);
        if (!actual
            || actual.artifactPath !== null
            || actual.requiredImagePath !== expected.requiredImagePath) {
            fail(`Image-root-only dependency identity mismatch: ${expected.sourcePath}`);
        }
    }
    const imageRootRecords = authority.imageRootDependencies.map((expected) => {
        const actual = generatedIdentity.get(expected.sourcePath);
        return Object.freeze({
            sourcePath: expected.sourcePath,
            requiredImagePath: expected.requiredImagePath,
            bytes: actual.bytes,
            sha256: actual.sha256,
            mode: actual.mode
        });
    });
    return { payloadRecords, imageRootRecords };
}

function validateAuthority(authority) {
    if (!isPlainObject(authority)) {
        fail('Artifact authority is invalid');
    }
    if (!Array.isArray(authority.payloadPaths)
        || authority.payloadPaths.length !== authority.payloadFiles
        || new Set(authority.payloadPaths).size !== authority.payloadPaths.length) {
        fail('Artifact authority payload inventory is invalid');
    }
    if (!Array.isArray(authority.generatedDependencies) || authority.generatedDependencies.length !== 2) {
        fail('Artifact authority generated dependency inventory is invalid');
    }
    if (!Array.isArray(authority.imageRootDependencies) || authority.imageRootDependencies.length !== 2) {
        fail('Artifact authority image-root dependency inventory is invalid');
    }
    if (!Array.isArray(authority.allowedModes) || !authority.allowedModes.length) {
        fail('Artifact authority mode inventory is invalid');
    }
    if (!Number.isSafeInteger(authority.manifestBytes) || authority.manifestBytes <= 0) {
        fail('Artifact authority Manifest length is invalid');
    }
    if (typeof authority.manifestSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(authority.manifestSha256)) {
        fail('Artifact authority Manifest SHA-256 is invalid');
    }
    for (const name of [
        'payloadFiles',
        'payloadBytes',
        'approvedEntries',
        'runtimeSourceEntries',
        'buildOnlyEntries',
        'optionalEntries',
        'generatedDependencyRecords',
        'generatedPayloadEntries',
        'imageRootOnlyDependencies'
    ]) {
        if (!Number.isSafeInteger(authority[name]) || authority[name] < 0) {
            fail(`Artifact authority ${name} is invalid`);
        }
    }
    if (authority.runtimeSourceEntries + authority.buildOnlyEntries + authority.optionalEntries
        !== authority.approvedEntries
        || authority.runtimeSourceEntries + authority.generatedPayloadEntries !== authority.payloadFiles
        || authority.generatedPayloadEntries + authority.imageRootOnlyDependencies
            !== authority.generatedDependencyRecords) {
        fail('Artifact authority counts are inconsistent');
    }
    return authority;
}

function assertNoSymlinkSegments(rootPath, targetPath, expectDirectory = false) {
    const root = path.resolve(rootPath);
    const target = path.resolve(targetPath);
    if (!isPathInside(root, target)) {
        fail('Artifact path escapes its root');
    }
    const relative = path.relative(root, target);
    const paths = [root];
    if (relative) {
        let current = root;
        for (const segment of relative.split(path.sep)) {
            current = path.join(current, segment);
            paths.push(current);
        }
    }
    for (let index = 0; index < paths.length; index += 1) {
        let stats;
        try {
            stats = fs.lstatSync(paths[index]);
        } catch (error) {
            if (error && (error.code === 'ENOENT' || error.code === 'ENOTDIR')) {
                fail('Artifact input is missing');
            }
            throw error;
        }
        if (stats.isSymbolicLink()) {
            fail('Artifact input must not contain symlinks');
        }
        const isLast = index === paths.length - 1;
        if (!isLast && !stats.isDirectory()) {
            fail('Artifact path contains a non-directory segment');
        }
        if (isLast && expectDirectory && !stats.isDirectory()) {
            fail('Artifact directory input is invalid');
        }
        if (isLast && !expectDirectory && !stats.isFile()) {
            fail('Artifact file input is invalid');
        }
    }
}

function readArtifactFile(rootPath, targetPath) {
    assertNoSymlinkSegments(rootPath, targetPath, false);
    const rootRealpath = fs.realpathSync(rootPath);
    const targetRealpath = fs.realpathSync(targetPath);
    if (!isPathInside(rootRealpath, targetRealpath)) {
        fail('Artifact file resolves outside its root');
    }
    return fs.readFileSync(targetRealpath);
}

function readAndVerifyFile(rootPath, relativePath, record, label) {
    const absolutePath = path.join(rootPath, ...relativePath.split('/'));
    const buffer = readArtifactFile(rootPath, absolutePath);
    if (buffer.length !== record.bytes || sha256(buffer) !== record.sha256) {
        fail(`${label} integrity mismatch: ${relativePath}`);
    }
    if (process.platform !== 'win32') {
        const stats = fs.statSync(absolutePath);
        const actualMode = (stats.mode & 0o777).toString(8).padStart(3, '0');
        if (actualMode !== record.mode.slice(-3)) {
            fail(`${label} mode mismatch: ${relativePath}`);
        }
    }
    return buffer;
}

function walkPayloadFiles(payloadRoot) {
    const files = [];
    function visit(currentRoot, relativeRoot) {
        const entries = fs.readdirSync(currentRoot, { withFileTypes: true })
            .sort((left, right) => left.name.localeCompare(right.name, 'en'));
        for (const entry of entries) {
            const relativePath = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
            const absolutePath = path.join(currentRoot, entry.name);
            if (entry.isSymbolicLink()) {
                fail('Artifact payload must not contain symlinks');
            }
            if (entry.isDirectory()) {
                visit(absolutePath, relativePath);
                continue;
            }
            if (!entry.isFile()) {
                fail('Artifact payload contains an unsupported filesystem entry');
            }
            files.push(relativePath);
        }
    }
    visit(payloadRoot, '');
    return files;
}

function compareExactInventory(actualPaths, expectedPaths, label) {
    const actual = [...actualPaths].sort();
    const expected = [...expectedPaths].sort();
    if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
        fail(`${label} does not match the authorized inventory`);
    }
}

function parseJsonBuffer(buffer, label) {
    if (buffer.length === 0 || buffer[0] === 0xef) {
        fail(`${label} encoding is invalid`);
    }
    try {
        return JSON.parse(buffer.toString('utf8'));
    } catch (_) {
        fail(`${label} is not valid JSON`);
    }
}

function createLoadedState(authority, recordsByPath, buffersByPath) {
    const shellFiles = new Map();
    for (const payloadPath of authority.payloadPaths) {
        const record = recordsByPath.get(payloadPath);
        const buffer = buffersByPath.get(payloadPath);
        shellFiles.set(payloadPath, { record, buffer });
    }
    for (const dependency of authority.generatedDependencies) {
        const record = recordsByPath.get(dependency.payloadPath);
        const buffer = buffersByPath.get(dependency.payloadPath);
        if (!record || !buffer) {
            fail('Generated dependency is absent from the verified payload');
        }
    }

    const generatedFiles = new Map(authority.generatedDependencies.map((dependency) => [
        dependency.requestPath,
        {
            record: recordsByPath.get(dependency.payloadPath),
            buffer: buffersByPath.get(dependency.payloadPath)
        }
    ]));

    function sendBuffer(res, entry) {
        res.type(path.extname(entry.record.payloadPath));
        res.setHeader('Cache-Control', 'private, no-store');
        return res.send(entry.buffer);
    }

    const state = {
        ready: true,
        artifactVersion: authority.artifactVersion,
        manifestSha256: authority.manifestSha256,
        payloadFiles: authority.payloadFiles,
        payloadBytes: authority.payloadBytes,
        hasShellFile(relativePath) {
            return shellFiles.has(relativePath);
        },
        sendShellFile(relativePath, res) {
            const entry = shellFiles.get(relativePath);
            return entry ? sendBuffer(res, entry) : null;
        },
        hasGeneratedFile(requestPath) {
            return generatedFiles.has(requestPath);
        },
        sendGeneratedFile(requestPath, res) {
            const entry = generatedFiles.get(requestPath);
            return entry ? sendBuffer(res, entry) : null;
        },
        getGeneratedText(requestPath) {
            const entry = generatedFiles.get(requestPath);
            return entry ? entry.buffer.toString('utf8') : null;
        }
    };
    Object.defineProperty(state, LOADED_FRONTEND_BRAND, {
        value: true,
        enumerable: false,
        writable: false
    });
    return Object.freeze(state);
}

function loadPublicListeningFrontend(
    artifactRoot,
    authorityInput = PRODUCTION_PUBLIC_LISTENING_FRONTEND_AUTHORITY,
    options = {}
) {
    const authority = validateAuthority(authorityInput);
    const rootPath = path.resolve(artifactRoot);
    assertNoSymlinkSegments(rootPath, rootPath, true);

    const locatorPath = path.join(rootPath, 'active.json');
    const locatorBuffer = readArtifactFile(rootPath, locatorPath);
    if (locatorBuffer.length > 4096) {
        fail('Active locator exceeds its bounded size');
    }
    const locator = parseJsonBuffer(locatorBuffer, 'Active locator');
    assertExactObjectKeys(locator, [
        'schema',
        'artifact_version',
        'manifest_path',
        'manifest_sha256',
        'manifest_bytes',
        'payload_path',
        'payload_files',
        'payload_bytes',
        'source_commit',
        'source_tree',
        'source_subtree'
    ], 'Active locator');
    const expectedManifestPath = `${authority.artifactVersion}/manifest.json`;
    const expectedPayloadPath = `${authority.artifactVersion}/payload`;
    if (locator.schema !== authority.locatorSchema
        || locator.artifact_version !== authority.artifactVersion
        || locator.manifest_path !== expectedManifestPath
        || locator.manifest_bytes !== authority.manifestBytes
        || locator.manifest_sha256 !== authority.manifestSha256
        || locator.payload_path !== expectedPayloadPath
        || locator.payload_files !== authority.payloadFiles
        || locator.payload_bytes !== authority.payloadBytes
        || locator.source_commit !== authority.sourceCommit
        || locator.source_tree !== authority.sourceCommitTree
        || locator.source_subtree !== authority.sourceTree) {
        fail('Active locator does not match the immutable artifact authority');
    }
    const canonicalLocatorBuffer = Buffer.from(`${JSON.stringify({
        schema: authority.locatorSchema,
        artifact_version: authority.artifactVersion,
        manifest_path: expectedManifestPath,
        manifest_sha256: authority.manifestSha256,
        manifest_bytes: authority.manifestBytes,
        payload_path: expectedPayloadPath,
        payload_files: authority.payloadFiles,
        payload_bytes: authority.payloadBytes,
        source_commit: authority.sourceCommit,
        source_tree: authority.sourceCommitTree,
        source_subtree: authority.sourceTree
    }, null, 2)}\n`, 'utf8');
    if (!locatorBuffer.equals(canonicalLocatorBuffer)) {
        fail('Active locator bytes are not canonical');
    }

    const versionRoot = path.join(rootPath, authority.artifactVersion);
    const payloadRoot = path.join(versionRoot, 'payload');
    assertNoSymlinkSegments(rootPath, versionRoot, true);
    assertNoSymlinkSegments(rootPath, payloadRoot, true);
    const manifestPath = path.join(versionRoot, 'manifest.json');
    const manifestBuffer = readArtifactFile(rootPath, manifestPath);
    if (manifestBuffer.length !== authority.manifestBytes) {
        fail('Manifest byte length does not match the immutable artifact authority');
    }
    if (sha256(manifestBuffer) !== authority.manifestSha256) {
        fail('Manifest SHA-256 does not match the immutable artifact authority');
    }

    const manifest = parseJsonBuffer(manifestBuffer, 'Manifest');
    const { payloadRecords: manifestRecords, imageRootRecords } = validateControlManifest(manifest, authority);
    if (manifestRecords.length !== authority.payloadFiles) {
        fail('Manifest payload file count does not match the immutable artifact authority');
    }
    const recordsByPath = new Map();
    let declaredPayloadBytes = 0;
    for (const record of manifestRecords) {
        if (recordsByPath.has(record.payloadPath)) {
            fail(`Manifest contains a duplicate payload path: ${record.payloadPath}`);
        }
        recordsByPath.set(record.payloadPath, record);
        declaredPayloadBytes += record.bytes;
    }
    if (!Number.isSafeInteger(declaredPayloadBytes) || declaredPayloadBytes !== authority.payloadBytes) {
        fail('Manifest payload byte total does not match the immutable artifact authority');
    }
    compareExactInventory(recordsByPath.keys(), authority.payloadPaths, 'Manifest payload');

    const diskPaths = walkPayloadFiles(payloadRoot);
    compareExactInventory(diskPaths, authority.payloadPaths, 'Artifact payload');
    const buffersByPath = new Map();
    let verifiedPayloadBytes = 0;
    for (const payloadPath of authority.payloadPaths) {
        const record = recordsByPath.get(payloadPath);
        const buffer = readAndVerifyFile(payloadRoot, payloadPath, record, 'Artifact payload');
        buffersByPath.set(payloadPath, buffer);
        verifiedPayloadBytes += buffer.length;
    }
    if (verifiedPayloadBytes !== authority.payloadBytes) {
        fail('Artifact payload byte total does not match the immutable artifact authority');
    }

    const imageRoot = options.imageRoot;
    if (typeof imageRoot !== 'string' || !imageRoot) {
        fail('Image-root dependency verification root is required');
    }
    const resolvedImageRoot = path.resolve(imageRoot);
    assertNoSymlinkSegments(resolvedImageRoot, resolvedImageRoot, true);
    for (const record of imageRootRecords) {
        const relativeImagePath = path.posix.relative('/app', record.requiredImagePath);
        if (!relativeImagePath
            || relativeImagePath.startsWith('../')
            || path.posix.isAbsolute(relativeImagePath)
            || relativeImagePath !== record.sourcePath) {
            fail(`Image-root dependency path is invalid: ${record.sourcePath}`);
        }
        readAndVerifyFile(resolvedImageRoot, relativeImagePath, record, 'Image-root dependency');
    }

    return createLoadedState(authority, recordsByPath, buffersByPath);
}

function loadProductionPublicListeningFrontend() {
    return loadPublicListeningFrontend(
        PUBLIC_LISTENING_FRONTEND_ROOT,
        PRODUCTION_PUBLIC_LISTENING_FRONTEND_AUTHORITY,
        { imageRoot: '/app' }
    );
}

function isLoadedPublicListeningFrontend(value) {
    return Boolean(value && value[LOADED_FRONTEND_BRAND] === true && value.ready === true);
}

function buildPublicListeningFrontendTestAuthority(values) {
    if (!isPlainObject(values)) {
        fail('Test artifact authority is invalid');
    }
    return Object.freeze({
        locatorSchema: PUBLIC_LISTENING_FRONTEND_LOCATOR_SCHEMA,
        manifestSchema: PUBLIC_LISTENING_FRONTEND_MANIFEST_SCHEMA,
        models: Object.freeze([values.model || PUBLIC_LISTENING_FRONTEND_MODELS[0]]),
        artifactVersion: values.artifactVersion,
        manifestBytes: values.manifestBytes,
        manifestSha256: values.manifestSha256,
        payloadFiles: values.payloadPaths?.length,
        payloadBytes: values.payloadBytes,
        payloadPaths: Object.freeze([...(values.payloadPaths || [])]),
        sourceRepository: values.sourceRepository,
        sourceCommit: values.sourceCommit,
        sourceCommitTree: values.sourceCommitTree,
        sourceTree: values.sourceTree,
        approvedEntries: values.approvedEntries,
        runtimeSourceEntries: values.runtimeSourceEntries,
        buildOnlyEntries: values.buildOnlyEntries,
        optionalEntries: values.optionalEntries,
        generatedDependencyRecords: values.generatedDependencyRecords,
        generatedPayloadEntries: values.generatedPayloadEntries,
        imageRootOnlyDependencies: values.imageRootOnlyDependencies,
        allowedModes: Object.freeze(['100644']),
        generatedDependencies: Object.freeze((values.generatedDependencies || PUBLIC_LISTENING_GENERATED_DEPENDENCIES)
            .map((entry) => Object.freeze({ ...entry }))),
        imageRootDependencies: Object.freeze((values.imageRootDependencies || PUBLIC_LISTENING_IMAGE_ROOT_DEPENDENCIES)
            .map((entry) => Object.freeze({ ...entry })))
    });
}

function getRawRequestPath(requestUrl) {
    const requestTarget = String(requestUrl || '/');
    if (!requestTarget.startsWith('/')
        || requestTarget.startsWith('//')
        || requestTarget.includes('#')) {
        return null;
    }
    const queryIndex = requestTarget.indexOf('?');
    return (queryIndex === -1 ? requestTarget : requestTarget.slice(0, queryIndex)) || '/';
}

function decodePathVariants(rawPath) {
    const variants = [rawPath];
    let current = rawPath;
    for (let pass = 0; pass < 3; pass += 1) {
        let decoded;
        try {
            decoded = decodeURIComponent(current);
        } catch (_) {
            return { variants, invalid: true };
        }
        if (decoded === current) break;
        variants.push(decoded);
        current = decoded;
    }
    return { variants, invalid: false };
}

function classifyPublicListeningRequest(requestUrl) {
    const rawPath = getRawRequestPath(requestUrl);
    if (rawPath === null) {
        return { kind: 'reject', status: 400, reason: 'unsupported request-target form' };
    }
    const decoded = decodePathVariants(rawPath);
    const normalizedVariants = decoded.variants.map((variant) => {
        return variant.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase();
    });
    const generatedMatch = PUBLIC_LISTENING_GENERATED_DEPENDENCIES.find((entry) => {
        return normalizedVariants.includes(entry.requestPath.toLowerCase());
    });
    if (generatedMatch) {
        if (decoded.invalid || rawPath !== generatedMatch.requestPath) {
            return { kind: 'reject', status: 404, reason: 'non-canonical generated dependency path' };
        }
        return { kind: 'generated', requestPath: generatedMatch.requestPath };
    }
    const generatedAliasIntent = PUBLIC_LISTENING_GENERATED_DEPENDENCIES.some((entry) => {
        const canonicalPath = entry.requestPath.toLowerCase();
        return normalizedVariants.some((variant) => variant.startsWith(canonicalPath));
    });
    if (generatedAliasIntent) {
        return { kind: 'reject', status: 404, reason: 'generated dependency path alias' };
    }

    const publicIntent = decoded.variants.some((variant) => {
        return /^\/+listeningpractice\/+vip/i.test(variant.replace(/\\/g, '/'));
    });
    if (!publicIntent) {
        return null;
    }
    if (decoded.invalid || rawPath.includes('\\') || rawPath.includes('\0')) {
        return { kind: 'reject', status: 400, reason: 'invalid public Listening path' };
    }
    if (!rawPath.startsWith(PUBLIC_LISTENING_SHELL_PREFIX)) {
        return { kind: 'reject', status: 404, reason: 'non-canonical public Listening prefix' };
    }
    const suffix = rawPath.slice(PUBLIC_LISTENING_SHELL_PREFIX.length);
    if (!suffix) {
        return { kind: 'public', relativePath: 'index.html' };
    }
    if (suffix.startsWith('ListeningPractice/')) {
        return {
            kind: 'private-nested',
            relativePath: suffix.slice('ListeningPractice/'.length)
        };
    }
    if (suffix.includes('%') || suffix.includes('//') || suffix.endsWith('/')) {
        return { kind: 'reject', status: 400, reason: 'non-canonical public Listening file path' };
    }
    const segments = suffix.split('/');
    if (segments.some((segment) => !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment)
        || segment === '.'
        || segment === '..')) {
        return { kind: 'reject', status: 400, reason: 'invalid public Listening file path' };
    }
    return { kind: 'public', relativePath: suffix };
}

module.exports = {
    PUBLIC_LISTENING_CSP,
    PUBLIC_LISTENING_FRONTEND_ROOT,
    PUBLIC_LISTENING_FRONTEND_VERSION,
    PUBLIC_LISTENING_FRONTEND_MANIFEST_BYTES,
    PUBLIC_LISTENING_FRONTEND_MANIFEST_SHA256,
    PUBLIC_LISTENING_FRONTEND_PAYLOAD_BYTES,
    PUBLIC_LISTENING_FRONTEND_PAYLOAD_FILES,
    PUBLIC_LISTENING_FRONTEND_PAYLOAD_PATHS,
    PUBLIC_LISTENING_GENERATED_DEPENDENCIES,
    PRODUCTION_PUBLIC_LISTENING_FRONTEND_AUTHORITY,
    PublicListeningFrontendError,
    buildPublicListeningFrontendTestAuthority,
    classifyPublicListeningRequest,
    isLoadedPublicListeningFrontend,
    loadProductionPublicListeningFrontend,
    loadPublicListeningFrontend
};
