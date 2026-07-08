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
    hasAudio: true
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

function createLazyLoaderHarness({ probeUrl, protocol = 'http:' }) {
    const probeCalls = [];
    const isFileProtocol = protocol === 'file:';
    const locationHref = isFileProtocol ? 'file:///D:/IELTS/index.html' : 'http://localhost/index.html';
    const locationOrigin = isFileProtocol ? 'null' : 'http://localhost';
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
                    windowStub.listeningExamIndex.pathRoot = 'ListeningPractice/';
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
        ResourceCore: {
            resolveResource(entry, kind) {
                probeCalls.push({ entry, kind });
                return Promise.resolve({
                    url: probeUrl || '',
                    attempts: [{ label: 'map', path: './ListeningPractice/P1/Guard/Guard.html' }]
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
        URL
    });

    loadScript('js/runtime/lazyLoader.js', context);
    return { window: windowStub, probeCalls };
}

async function runLazyLoader(probeUrl, options = {}) {
    const harness = createLazyLoaderHarness({ probeUrl, ...options });
    await harness.window.AppLazyLoader.ensureGroup('exam-data');
    return harness;
}

async function testListeningUnavailableWhenHttpSourceProbeFails() {
    const { window, probeCalls } = await runLazyLoader('');
    assert.strictEqual(probeCalls.length, 1, 'HTTP listening source should be probed once');
    assert.strictEqual(probeCalls[0].kind, 'html');
    assert.strictEqual(probeCalls[0].entry.type, 'listening');
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'http:');
}

async function testListeningAvailableWhenHttpSourceProbeSucceeds() {
    const { window, probeCalls } = await runLazyLoader('./ListeningPractice/P1/Guard/Guard.html');
    assert.strictEqual(probeCalls.length, 1, 'HTTP listening source should be probed once');
    assert.strictEqual(window.__defaultListeningLibraryAvailable, true);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'available');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, true);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'http:');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.url, './ListeningPractice/P1/Guard/Guard.html');
}

async function testListeningAvailableForFileProtocolWhenSourceResolves() {
    const { window, probeCalls } = await runLazyLoader('file:///D:/IELTS/ListeningPractice/P1/Guard/Guard.html', { protocol: 'file:' });
    assert.strictEqual(probeCalls.length, 1, 'file:// listening source should be resolved through ResourceCore');
    assert.strictEqual(probeCalls[0].kind, 'html');
    assert.strictEqual(probeCalls[0].entry.type, 'listening');
    assert.strictEqual(window.__defaultListeningLibraryAvailable, true);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'available');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, true);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'file:');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.url, 'file:///D:/IELTS/ListeningPractice/P1/Guard/Guard.html');
}

async function testListeningUnavailableForFileProtocolWhenSourceDoesNotResolve() {
    const { window, probeCalls } = await runLazyLoader('', { protocol: 'file:' });
    assert.strictEqual(probeCalls.length, 1, 'file:// listening source should still require ResourceCore confirmation');
    assert.strictEqual(window.__defaultListeningLibraryAvailable, false);
    assert.strictEqual(window.__defaultListeningLibraryAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailable, false);
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityReason, 'source-root-unavailable');
    assert.strictEqual(window.__defaultListeningLibrarySourceAvailabilityDetail.protocol, 'file:');

    const managerWindow = createLibraryManagerHarness({
        defaultAvailable: window.__defaultListeningLibraryAvailable,
        sourceAvailable: window.__defaultListeningLibrarySourceAvailable
    });
    assert.strictEqual(
        managerWindow.LibraryManager.isBuiltInListeningLibraryAvailable(),
        false,
        'file:// listening must stay hidden when ResourceCore cannot resolve a source'
    );
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
    await testListeningUnavailableWhenHttpSourceProbeFails();
    await testListeningAvailableWhenHttpSourceProbeSucceeds();
    await testListeningAvailableForFileProtocolWhenSourceResolves();
    await testListeningUnavailableForFileProtocolWhenSourceDoesNotResolve();
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