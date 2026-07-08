#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import assert from 'assert';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const listeningEntry = {
    id: 'listening-p1-guard',
    examId: 'listening-p1-guard',
    dataKey: 'listening-p1-guard',
    title: 'Listening Guard',
    type: 'listening',
    category: 'P1',
    path: 'P1/Guard/',
    filename: 'Guard.html',
    pdfFilename: 'Guard.pdf',
    audioFilename: 'audio.mp3',
    hasHtml: true,
    hasPdf: true,
    hasAudio: true,
    sourcePath: 'P1/Guard/Guard.html'
};

function loadScript(relativePath, context) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    vm.runInContext(source, context, { filename: relativePath });
}

function createScriptElement() {
    return {
        async: false,
        onload: null,
        onerror: null,
        parentNode: null,
        set src(value) {
            this._src = String(value);
        },
        get src() {
            return this._src || '';
        }
    };
}

function toAbsoluteUrl(value, baseHref) {
    return new URL(String(value), baseHref).href;
}

function createLazyLoaderHarness({
    protocol = 'http:',
    pathRoot = 'ListeningPractice/',
    availableUrls = [],
    genericResolverUrl = 'http://localhost/practice/listening/listening-p1-guard'
} = {}) {
    const resourceCoreCalls = [];
    const fetchCalls = [];
    const isFileProtocol = protocol === 'file:';
    const locationHref = isFileProtocol ? 'file:///D:/IELTS/index.html' : 'http://localhost/index.html';
    const locationOrigin = isFileProtocol ? 'null' : 'http://localhost';
    const available = new Set(availableUrls.map((url) => toAbsoluteUrl(url, locationHref)));
    let windowStub;
    const document = {
        baseURI: locationHref,
        querySelectorAll() {
            return [];
        },
        createElement(tag) {
            assert.strictEqual(tag, 'script');
            return createScriptElement();
        },
        head: {
            appendChild(script) {
                const pathname = decodeURIComponent(new URL(script.src).pathname).replace(/\\/g, '/');
                if (pathname.endsWith('/assets/generated/listening-exams/manifest.js')) {
                    windowStub.__LISTENING_EXAM_MANIFEST__ = {
                        [listeningEntry.id]: Object.assign({}, listeningEntry)
                    };
                }
                if (pathname.endsWith('/assets/generated/listening-exams/listening-index.compat.js')) {
                    windowStub.listeningExamIndex = [Object.assign({}, listeningEntry)];
                    windowStub.listeningExamIndex.pathRoot = pathRoot;
                }
                if (typeof script.onload === 'function') {
                    script.onload({ type: 'load' });
                }
            }
        }
    };

    windowStub = {
        location: {
            href: locationHref,
            origin: locationOrigin,
            protocol
        },
        document,
        fetch(url, options = {}) {
            const href = toAbsoluteUrl(url, locationHref);
            const method = options && options.method ? String(options.method).toUpperCase() : 'GET';
            fetchCalls.push({ url: href, method });
            const ok = available.has(href);
            return Promise.resolve({ ok, status: ok ? 200 : 404 });
        },
        ResourceCore: {
            resolveResource(entry, kind) {
                resourceCoreCalls.push({ entry, kind });
                return Promise.resolve({
                    url: genericResolverUrl,
                    attempts: [{ label: 'route', path: genericResolverUrl }]
                });
            }
        }
    };

    const context = vm.createContext({
        window: windowStub,
        document,
        console: { log() {}, warn() {}, error() {} },
        Promise,
        Object,
        Array,
        Set,
        Error,
        String,
        Boolean,
        Number,
        URL,
        encodeURIComponent,
        decodeURIComponent
    });

    loadScript('js/runtime/lazyLoader.js', context);
    return { window: windowStub, resourceCoreCalls, fetchCalls };
}

async function runLazyLoader(options = {}) {
    const harness = createLazyLoaderHarness(options);
    await harness.window.AppLazyLoader.ensureGroup('exam-data');
    return harness;
}

async function testHttpProbeUsesPathRootAndEntryPath() {
    const expectedUrl = 'http://localhost/ListeningPractice/P1/Guard/Guard.html';
    const { window, fetchCalls, resourceCoreCalls } = await runLazyLoader({
        availableUrls: [expectedUrl]
    });
    assert.strictEqual(resourceCoreCalls.length, 0, 'availability must not use ResourceCore generic route resolver');
    assert.deepStrictEqual(fetchCalls, [{ url: expectedUrl, method: 'HEAD' }]);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.url, expectedUrl);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.pathRoot, 'ListeningPractice');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.entryPath, 'P1/Guard/Guard.html');
}

async function testListeningAvailableWhenHttpSourceRootExists() {
    const expectedUrl = 'http://localhost/CustomListening/P1/Guard/Guard.html';
    const { window, fetchCalls } = await runLazyLoader({
        pathRoot: 'CustomListening/',
        availableUrls: [expectedUrl]
    });
    assert.deepStrictEqual(fetchCalls, [{ url: expectedUrl, method: 'HEAD' }]);
    assert.strictEqual(window.__defaultListeningLibraryAvailable, true);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'available');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, true);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'available');
}

async function testListeningUnavailableWhenHttpSourceRootIsWrong() {
    const wrongUrl = 'http://localhost/MissingListening/P1/Guard/Guard.html';
    const { window, fetchCalls } = await runLazyLoader({
        pathRoot: 'MissingListening/',
        availableUrls: ['http://localhost/ListeningPractice/P1/Guard/Guard.html']
    });
    assert.deepStrictEqual(fetchCalls, [{ url: wrongUrl, method: 'HEAD' }]);
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'source-root-unavailable');
}

async function testResourceCoreGenericResolverCandidateDoesNotCountAsSourceProof() {
    const genericUrl = 'http://localhost/ListeningPractice/P1/Guard/Guard.html';
    const wrongUrl = 'http://localhost/MissingListening/P1/Guard/Guard.html';
    const { window, fetchCalls, resourceCoreCalls } = await runLazyLoader({
        pathRoot: 'MissingListening/',
        availableUrls: [genericUrl],
        genericResolverUrl: genericUrl
    });
    assert.strictEqual(resourceCoreCalls.length, 0, 'ResourceCore candidate URLs must not be used as source availability proof');
    assert.deepStrictEqual(fetchCalls, [{ url: wrongUrl, method: 'HEAD' }]);
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
}

async function testListeningUnavailableWhenHttpSourceProbeFails() {
    const expectedUrl = 'http://localhost/ListeningPractice/P1/Guard/Guard.html';
    const { window, fetchCalls } = await runLazyLoader();
    assert.deepStrictEqual(fetchCalls, [{ url: expectedUrl, method: 'HEAD' }]);
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'source-root-unavailable');
}

async function testListeningUnavailableForLocalStaticFileModeEvenWhenResolveResourceReturnsUrl() {
    const { window, fetchCalls, resourceCoreCalls } = await runLazyLoader({
        protocol: 'file:',
        genericResolverUrl: 'file:///D:/IELTS/ListeningPractice/P1/Guard/Guard.html',
        availableUrls: ['file:///D:/IELTS/ListeningPractice/P1/Guard/Guard.html']
    });
    assert.strictEqual(resourceCoreCalls.length, 0, 'file:// availability must not call ResourceCore.resolveResource as proof');
    assert.strictEqual(fetchCalls.length, 0, 'local static file mode is intentionally unsupported; use a local HTTP server for development');
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'unsupported-environment');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'unsupported-environment');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'file:');
}

async function testListeningUnavailableForUnsupportedProtocol() {
    const { window, fetchCalls, resourceCoreCalls } = await runLazyLoader({
        protocol: 'app:',
        genericResolverUrl: 'app://local/ListeningPractice/P1/Guard/Guard.html'
    });
    assert.strictEqual(resourceCoreCalls.length, 0, 'unsupported protocols must not call ResourceCore.resolveResource as proof');
    assert.strictEqual(fetchCalls.length, 0);
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'unsupported-environment');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'unsupported-environment');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'app:');
}

function createLibraryManagerHarness(flags = {}) {
    const windowStub = {
        console: { log() {}, warn() {}, error() {} },
        __LISTENING_EXAM_MANIFEST__: {
            [listeningEntry.id]: Object.assign({}, listeningEntry)
        },
        listeningExamIndex: [Object.assign({}, listeningEntry)]
    };
    windowStub.listeningExamIndex.pathRoot = 'ListeningPractice/';
    if (Object.prototype.hasOwnProperty.call(flags, 'defaultAvailable')) {
        windowStub.__defaultListeningLibraryAvailable = flags.defaultAvailable;
    }
    if (Object.prototype.hasOwnProperty.call(flags, 'sourceAvailable')) {
        windowStub.__defaultListeningLibrarySourceAvailable = flags.sourceAvailable;
    }

    const context = vm.createContext({
        window: windowStub,
        globalThis: windowStub,
        console: windowStub.console,
        Object,
        Array,
        Set,
        Map,
        String,
        Number,
        Date,
        Math,
        JSON,
        Promise,
        encodeURIComponent,
        decodeURIComponent
    });
    loadScript('js/services/libraryManager.js', context);
    return windowStub;
}

function testLibraryManagerRequiresConfirmedAvailability() {
    let window = createLibraryManagerHarness();
    assert.strictEqual(
        window.LibraryManager.isBuiltInListeningLibraryAvailable(),
        false,
        'manifest/index alone must not expose built-in listening'
    );

    window = createLibraryManagerHarness({ sourceAvailable: false });
    assert.strictEqual(window.LibraryManager.isBuiltInListeningLibraryAvailable(), false);

    window = createLibraryManagerHarness({ sourceAvailable: true });
    assert.strictEqual(window.LibraryManager.isBuiltInListeningLibraryAvailable(), true);
}

try {
    await testHttpProbeUsesPathRootAndEntryPath();
    await testListeningAvailableWhenHttpSourceRootExists();
    await testListeningUnavailableWhenHttpSourceRootIsWrong();
    await testResourceCoreGenericResolverCandidateDoesNotCountAsSourceProof();
    await testListeningUnavailableWhenHttpSourceProbeFails();
    await testListeningUnavailableForLocalStaticFileModeEvenWhenResolveResourceReturnsUrl();
    await testListeningUnavailableForUnsupportedProtocol();
    testLibraryManagerRequiresConfirmedAvailability();
    console.log(JSON.stringify({
        status: 'pass',
        detail: 'listening availability guard tests passed'
    }, null, 2));
} catch (error) {
    console.error(error);
    console.log(JSON.stringify({
        status: 'fail',
        detail: error && error.message ? error.message : String(error)
    }, null, 2));
    process.exit(1);
}