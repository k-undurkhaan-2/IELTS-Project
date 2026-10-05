#!/usr/bin/env node
import path from 'path';
import fs from 'fs';
import vm from 'vm';
import assert from 'assert';
import test from 'node:test';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');

function loadScript(relativePath, context) {
    const fullPath = path.join(repoRoot, relativePath);
    const code = fs.readFileSync(fullPath, 'utf8');
    vm.runInContext(code, context, { filename: relativePath });
}

function deepClone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value));
}

async function main() {
    const state = new Map();
    state.set('practice_records', [{ id: 'legacy_1', examId: 'legacy-a' }]);
    const storage = {
        async get(key, fallback = undefined) {
            if (state.has(key)) {
                return deepClone(state.get(key));
            }
            return deepClone(fallback);
        },
        async set(key, value) {
            state.set(key, deepClone(value));
        }
    };

    const sandboxWindow = {
        location: { href: 'http://localhost/' },
        showMessage() {},
        addEventListener() {},
        removeEventListener() {},
        document: { addEventListener() {}, removeEventListener() {} },
        PracticeCore: {
            store: {
                async listPracticeRecords() {
                    return [{ id: 'core_1', examId: 'core-a' }];
                }
            }
        },
        PracticeStore: {
            async list() {
                return [{ id: 'store_1', examId: 'store-a' }];
            },
            async save() {
                throw new Error('save should not be called in this case');
            },
            async replace() {
                throw new Error('replace should not be called in this case');
            }
        }
    };

    const sandbox = {
        window: sandboxWindow,
        document: sandboxWindow.document,
        storage,
        console,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        Math,
        Date,
        JSON,
        Array
    };
    sandbox.globalThis = sandbox.window;
    const context = vm.createContext(sandbox);

    loadScript('js/app/examSessionMixin.js', context);
    loadScript('js/app/suitePracticeMixin.js', context);

    const mixins = sandboxWindow.ExamSystemAppMixins;
    const app = {
        components: {
            practiceRecorder: {
                async getPracticeRecords() {
                    return [{ id: 'recorder_1', examId: 'recorder-a' }];
                }
            }
        },
        setStateCalls: [],
        setState(pathName, value) {
            this.setStateCalls.push({ pathName, value: deepClone(value) });
        },
        getState() { return null; }
    };

    Object.assign(app, mixins.examSession, mixins.suitePractice);

    const fromFiltering = await app._loadSuitePracticeRecordsForFiltering();
    assert.strictEqual(fromFiltering[0].id, 'recorder_1', '过滤读取应优先 PracticeRecorder');

    delete app.components.practiceRecorder;
    const fromStateSync = await app._listPracticeRecordsWithFallback({ includeRecorder: false });
    assert.strictEqual(fromStateSync[0].id, 'core_1', '无 recorder 时应回退 PracticeCore');

    delete sandboxWindow.PracticeCore;
    const fromStore = await app._listPracticeRecordsWithFallback({ includeRecorder: false });
    assert.strictEqual(fromStore[0].id, 'store_1', '无 PracticeCore 时应回退 PracticeStore');

    delete sandboxWindow.PracticeStore;
    const fromStorage = await app._listPracticeRecordsWithFallback({ includeRecorder: false });
    assert.strictEqual(fromStorage[0].id, 'legacy_1', '最终应回退 storage practice_records');

    await app._updatePracticeRecordsState();
    assert.strictEqual(app.setStateCalls.length, 1, '应同步一次 practice.records');
    assert.strictEqual(app.setStateCalls[0].pathName, 'practice.records');
    assert.strictEqual(app.setStateCalls[0].value[0].id, 'legacy_1');

    process.stdout.write(JSON.stringify({ status: 'pass', detail: 'suitePractice fallback 链统一并按顺序工作' }));
}

main().catch((error) => {
    const detail = error && error.stack ? error.stack : String(error);
    process.stdout.write(JSON.stringify({ status: 'fail', detail }));
    process.exit(1);
});

const plain = (value) => JSON.parse(JSON.stringify(value));

// Separate from the sequential suite regression: its frozen debt assertion must retain its identity.
function createSuiteNavigationHarness() {
    const stored = new Map();
    const window = {
        location: { origin: 'https://reading.test', href: 'https://reading.test/', protocol: 'https:' },
        addEventListener() {}, removeEventListener() {},
        sessionStorage: { setItem(key, value) { stored.set(key, value); }, getItem(key) { return stored.get(key) ?? null; } },
        practiceConfig: { suite: {} }
    };
    const document = { addEventListener() {}, removeEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; } };
    window.document = document;
    const context = vm.createContext({ window, document, console, URL, setTimeout, clearTimeout, setInterval() { return 1; }, clearInterval() {} });
    for (const relative of ['examSessionMixin.js', 'suitePracticeMixin.js']) {
        vm.runInContext(fs.readFileSync(new URL(`../../../js/app/${relative}`, import.meta.url), 'utf8'), context);
    }
    const messages = [];
    const page = { closed: false, focus() {}, document, postMessage(message) { messages.push(message); } };
    const session = {
        id: 'suite-direct', status: 'active', flowMode: 'simulation', currentIndex: 0, activeExamId: 'reading-p1',
        sequence: [1, 2, 3].map((part) => ({ examId: `reading-p${part}`, exam: { id: `reading-p${part}`, title: `Part ${part}`, category: `P${part}`, type: 'reading' } })),
        draftsByExam: {}, elapsedByExam: {}, results: [], windowRef: page, globalTimerAnchorMs: 1000
    };
    const app = { components: {}, getState() { return null; }, setState() {}, updateExamStatus() {} };
    Object.assign(app, window.ExamSystemAppMixins.examSession, window.ExamSystemAppMixins.suitePractice);
    app.currentSuiteSession = session;
    const opened = [];
    app.openExam = async (examId, options) => { opened.push({ examId, options }); return page; };
    return { app, session, page, opened, messages, stored };
}

function payload(targetIndex = 2) {
    return {
        targetIndex, direction: 'next', suiteSessionId: 'suite-direct',
        draft: { answers: { q1: 'B' }, highlights: [{ scope: 'left', text: 'keep' }], scrollY: 219, updatedAt: 100 },
        resultSnapshot: { answers: { q1: 'B' }, scoreInfo: { correct: 1, total: 1 } },
        elapsed: 83,
        timerSnapshot: { anchorMs: 1000, pausedOffsetMs: 2000, pausedAtMs: 86000, running: false }
    };
}

test('explicit non-adjacent target preserves drafts, results, highlights, scroll and timer', async () => {
    const h = createSuiteNavigationHarness();
    assert.strict.equal(await h.app._handleSimulationNavigate('reading-p1', payload(), h.page), true);
    assert.strict.equal(h.session.currentIndex, 2);
    assert.strict.equal(h.session.activeExamId, 'reading-p3');
    assert.strict.equal(h.opened[0].examId, 'reading-p3');
    assert.strict.equal(h.opened[0].options.sequenceIndex, 2);
    assert.strict.equal(h.opened[0].options.reuseWindow, h.page);
    assert.strict.deepEqual(plain(h.session.draftsByExam['reading-p1']), payload().draft);
    assert.strict.equal(h.session.elapsedByExam['reading-p1'], 83);
    const result = h.session.results.find((entry) => entry.examId === 'reading-p1');
    assert.strict.equal(result.answers.q1, 'B');
    const replay = h.app._buildSuiteEntryIndividualPayload(h.session, result);
    assert.strict.equal(replay.highlights[0].text, 'keep');
    assert.strict.equal(replay.scrollY, 219);
    assert.strict.equal(h.session.globalTimerAnchorMs, 1000);
    assert.strict.equal(h.session.suiteTimerPausedOffsetMs, 2000);
    assert.strict.equal(h.session.suiteTimerPausedAtMs, 86000);
    assert.strict.equal(h.session.suiteTimerRunning, false);
    const mirrored = JSON.parse(h.stored.get('ielts_sim_session'));
    assert.strict.equal(mirrored.currentIndex, 2);
    assert.strict.equal(mirrored.draftsByExam['reading-p1'].answers.q1, 'B');
    const context = h.messages.find((message) => message.type === 'SIMULATION_CONTEXT');
    assert.strict.equal(context.data.currentIndex, 2);
    assert.strict.equal(context.data.timerSnapshot.pausedOffsetMs, 2000);
    assert.strict.equal(context.data.timerSnapshot.running, false);

    assert.strict.equal(await h.app._handleSimulationNavigate('reading-p3', { targetIndex: 0 }, h.page), true);
    assert.strict.equal(h.session.currentIndex, 0);
    const restored = h.messages.filter((message) => message.type === 'SIMULATION_CONTEXT').at(-1).data;
    assert.strict.equal(restored.draft.answers.q1, 'B');
    assert.strict.equal(restored.elapsed, 83);
});

test('explicit invalid or same targets do not fall back to direction or save state', async () => {
    for (const target of [0, -1, 3, 99, 1.5, NaN, Infinity, null, undefined, '', '2', false, {}]) {
        const h = createSuiteNavigationHarness();
        assert.strict.equal(await h.app._handleSimulationNavigate('reading-p1', { ...payload(), targetIndex: target }, h.page), false, `target: ${String(target)}`);
        assert.strict.equal(h.opened.length, 0);
        assert.strict.equal(h.session.currentIndex, 0);
        assert.strict.deepEqual(h.session.draftsByExam, {});
        assert.strict.deepEqual(h.session.results, []);
    }
});

test('missing sequence entry, inactive session and navigation lock reject direct targets', async () => {
    for (const change of [
        (session) => { session.sequence[2] = { exam: {} }; },
        (session) => { session.sequence = null; },
        (session) => { session.status = 'completed'; },
        (session) => { session.flowMode = 'practice'; },
        (session) => { session.simulationNavigateLocked = true; }
    ]) {
        const h = createSuiteNavigationHarness();
        change(h.session);
        assert.strict.equal(await h.app._handleSimulationNavigate('reading-p1', payload(), h.page), false);
        assert.strict.equal(h.opened.length, 0);
    }
});

test('direct navigation retains newer draft authority and existing relative navigation', async () => {
    const h = createSuiteNavigationHarness();
    h.session.draftsByExam['reading-p1'] = { answers: { q1: 'newer' }, updatedAt: 200 };
    assert.strict.equal(await h.app._handleSimulationNavigate('reading-p1', payload(), h.page), true);
    assert.strict.equal(h.session.draftsByExam['reading-p1'].answers.q1, 'newer');
    assert.strict.equal(await h.app._handleSimulationNavigate('reading-p3', { direction: 'prev' }, h.page), true);
    assert.strict.equal(h.session.currentIndex, 1);
});

test('direct targets pass through the real message token, origin and source binding', async () => {
    for (const variant of ['valid', 'stale', 'missing-token', 'foreign-origin', 'opaque-origin', 'wrong-window', 'wrong-exam', 'wrong-suite', 'read-only']) {
        const h = createSuiteNavigationHarness();
        h.app.setupExamWindowCommunication(h.page, 'reading-p1', h.session.sequence[0].exam, { suiteSessionId: h.session.id, suiteFlowMode: 'simulation' });
        const info = h.app.ensureExamWindowSession('reading-p1', h.page);
        info.expectedSessionId = 'current-page-token';
        const data = { ...payload(), examId: 'reading-p1', sessionId: 'current-page-token', source: 'practice_page' };
        const event = { source: h.page, origin: 'https://reading.test', data: { type: 'SIMULATION_NAVIGATE', source: 'practice_page', data } };
        if (variant === 'stale') data.sessionId = 'old-page-token';
        if (variant === 'missing-token') delete data.sessionId;
        if (variant === 'foreign-origin') event.origin = 'https://foreign.test';
        if (variant === 'opaque-origin') event.origin = 'null';
        if (variant === 'wrong-window') event.source = { ...h.page };
        if (variant === 'wrong-exam') data.examId = 'reading-p2';
        if (variant === 'wrong-suite') data.suiteSessionId = 'old-suite';
        if (variant === 'read-only') info.readOnly = true;
        await h.app.messageHandlers.get('reading-p1')(event);
        assert.strict.equal(h.opened.length, variant === 'valid' ? 1 : 0, variant);
        assert.strict.equal(h.session.currentIndex, variant === 'valid' ? 2 : 0, variant);
    }
});
