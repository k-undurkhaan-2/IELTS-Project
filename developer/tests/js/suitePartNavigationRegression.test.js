#!/usr/bin/env node
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import test from 'node:test';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const source = fs.readFileSync(path.join(repoRoot, 'js', 'app', 'suitePracticeMixin.js'), 'utf8');

function createWindowStub(name = 'suite-window') {
    return {
        name,
        closed: false,
        messages: [],
        postMessage(payload, targetOrigin) {
            this.messages.push({ payload, targetOrigin });
        },
        focus() {}
    };
}

function loadSuiteMixin() {
    const storageData = new Map();
    const storage = {
        async get(key, fallback = null) {
            return storageData.has(key) ? storageData.get(key) : fallback;
        },
        async set(key, value) {
            storageData.set(key, value);
            return true;
        }
    };
    const sessionData = new Map();
    const sessionStorage = {
        getItem(key) {
            return sessionData.has(key) ? sessionData.get(key) : null;
        },
        setItem(key, value) {
            sessionData.set(key, String(value));
        },
        removeItem(key) {
            sessionData.delete(key);
        }
    };
    const document = {
        addEventListener() {},
        removeEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        createElement() { return { className: '', style: {} }; },
        dispatchEvent() { return true; }
    };
    const window = {
        document,
        storage,
        sessionStorage,
        location: { origin: 'http://localhost', href: 'http://localhost/' },
        localStorage: {
            getItem() { return null; },
            setItem() {},
            removeItem() {}
        },
        practiceConfig: { suite: {} },
        addEventListener() {},
        removeEventListener() {},
        showMessage() {},
        CustomEvent: function CustomEvent(type, init = {}) {
            return { type, detail: init.detail || null };
        }
    };
    const context = vm.createContext({
        window,
        document,
        storage,
        console,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        CustomEvent: window.CustomEvent
    });
    context.globalThis = window;
    window.globalThis = window;
    vm.runInContext(source, context, { filename: 'suitePracticeMixin.js' });
    return window.ExamSystemAppMixins.suitePractice;
}

function createSession() {
    const sequence = ['p1', 'p2', 'p3'].map((part, index) => ({
        examId: `reading-${part}`,
        exam: {
            id: `reading-${part}`,
            title: `Passage ${index + 1}`,
            category: part.toUpperCase()
        }
    }));
    return {
        id: 'suite-direct-navigation',
        status: 'active',
        sequence,
        currentIndex: 0,
        activeExamId: sequence[0].examId,
        flowMode: 'simulation',
        results: [],
        draftsByExam: {},
        elapsedByExam: {},
        windowName: 'ielts-suite-mode-tab',
        windowRef: createWindowStub()
    };
}

test('suite navigation honors a direct target index and rejects invalid targets', async () => {
    const mixin = loadSuiteMixin();
    const session = createSession();
    const openCalls = [];
    const app = Object.assign({
        currentSuiteSession: session,
        suiteExamMap: new Map(session.sequence.map((entry) => [entry.examId, session.id])),
        async openExam(examId, options = {}) {
            openCalls.push({ examId, options });
            return createWindowStub('target-window');
        }
    }, mixin);
    const sourceWindow = session.windowRef;

    const handled = await app._handleSimulationNavigate('reading-p1', {
        direction: 'next',
        targetIndex: 2,
        targetPartKey: 'p3'
    }, sourceWindow);

    assert.equal(handled, true);
    assert.equal(session.currentIndex, 2);
    assert.equal(session.activeExamId, 'reading-p3');
    assert.equal(openCalls.length, 1);
    assert.equal(openCalls[0].examId, 'reading-p3');
    assert.equal(openCalls[0].options.sequenceIndex, 2);

    const samePart = await app._handleSimulationNavigate('reading-p3', {
        direction: 'prev',
        targetIndex: 2
    }, sourceWindow);
    assert.equal(samePart, false);
    assert.equal(openCalls.length, 1);

    const outOfBounds = await app._handleSimulationNavigate('reading-p3', {
        direction: 'next',
        targetIndex: 3
    }, sourceWindow);
    assert.equal(outOfBounds, false);
    assert.equal(openCalls.length, 1);
});
