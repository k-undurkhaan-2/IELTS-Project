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
const source = fs.readFileSync(path.join(repoRoot, 'js', 'runtime', 'unifiedReadingPage.js'), 'utf8');

function createContext() {
    const context = {
        console,
        URL,
        URLSearchParams,
        setInterval() { return 1; },
        clearInterval() {},
        setTimeout(callback) {
            if (typeof callback === 'function') {
                callback();
            }
            return 1;
        },
        clearTimeout() {},
        requestAnimationFrame(callback) {
            if (typeof callback === 'function') {
                callback();
            }
            return 1;
        },
        addEventListener() {},
        removeEventListener() {},
        scrollY: 0,
        scrollX: 0,
        scrollTo() {},
        close() {},
        opener: null,
        parent: null,
        location: {
            href: 'http://127.0.0.1:3000/templates/reading.html?exam=test',
            origin: 'http://127.0.0.1:3000',
            protocol: 'http:',
            search: '?exam=test'
        },
        sessionStorage: {
            getItem() { return null; },
            setItem() {},
            removeItem() {}
        },
        document: {
            addEventListener() {},
            getElementById() { return null; },
            querySelector() { return null; },
            querySelectorAll() { return []; },
            createElement() {
                return {
                    className: '',
                    dataset: {},
                    style: {},
                    setAttribute() {},
                    appendChild() {},
                    querySelectorAll() { return []; },
                    addEventListener() {}
                };
            }
        },
        CSS: {
            escape(value) {
                return String(value);
            }
        },
        CustomEvent: class CustomEvent {
            constructor(type, init = {}) {
                this.type = type;
                this.detail = init.detail;
            }
        }
    };
    context.window = context;
    context.globalThis = context;
    return context;
}

function loadHooks() {
    const context = createContext();
    const patchedSource = source.replace(
        '    function persistSimulationDraftMirror(draft) {',
        [
            '    global.__UnifiedReadingDraftGuardHooks = {',
            '        sanitizeSimulationDraft,',
            '        cloneDraftSafely,',
            '        parseSimulationDraftStorage',
            '    };',
            '',
            '    function persistSimulationDraftMirror(draft) {'
        ].join('\n')
    );
    vm.createContext(context);
    vm.runInContext(patchedSource, context, { filename: 'unifiedReadingPage.js' });
    return context.__UnifiedReadingDraftGuardHooks;
}

test('simulation draft sanitizer removes unsafe keys and bounds restored data', () => {
    const hooks = loadHooks();
    const polluted = JSON.parse(`{
      "answers": {
        "q1": "A",
        "Q2": ${JSON.stringify(Array.from({ length: 60 }, (_, index) => `item-${index}`))},
        "q3": "${'x'.repeat(5000)}",
        "__proto__": "polluted",
        "constructor": "polluted",
        "prototype": "polluted"
      },
      "highlights": ${JSON.stringify(Array.from({ length: 650 }, (_, index) => ({
        scope: index % 2 === 0 ? 'left' : 'bad-scope',
        text: `highlight ${index}`,
        kind: index % 3 === 0 ? 'note' : 'script',
        occurrence: index,
        start: index + 5,
        end: index,
        attrs: { onclick: 'alert(1)' }
      })))},
      "scrollY": 999999999,
      "updatedAt": 12345,
      "__proto__": { "pollutedUnifiedDraft": true }
    }`);

    const sanitized = hooks.sanitizeSimulationDraft(polluted);

    assert.equal(Object.getPrototypeOf(sanitized.answers), null);
    assert.equal(Object.prototype.hasOwnProperty.call(sanitized.answers, '__proto__'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(sanitized.answers, 'constructor'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(sanitized.answers, 'prototype'), false);
    assert.equal(sanitized.answers.q1, 'A');
    assert.equal(sanitized.answers.q2.length, 40);
    assert.equal(sanitized.answers.q3.length, 4000);
    assert.equal(sanitized.highlights.length, 500);
    assert.equal(sanitized.highlights[0].kind, 'note');
    assert.equal(sanitized.highlights[1].kind, 'highlight');
    assert.equal(sanitized.highlights[0].scope, 'left');
    assert.equal(sanitized.highlights[1].scope, 'groups');
    assert.equal(Object.prototype.hasOwnProperty.call(sanitized.highlights[0], 'attrs'), false);
    assert(sanitized.highlights.every((entry) => entry.start <= entry.end));
    assert.equal(sanitized.scrollY, 10000000);
    assert.equal(sanitized.updatedAt, 12345);
    assert.equal(Object.prototype.pollutedUnifiedDraft, undefined);
});

test('simulation draft sanitizer tolerates hostile runtime objects', () => {
    const hooks = loadHooks();
    const throwingAnswers = new Proxy({}, {
        ownKeys() {
            throw new Error('no keys');
        }
    });
    const highlight = { text: 'safe highlight' };
    Object.defineProperty(highlight, 'start', {
        enumerable: true,
        get() {
            throw new Error('bad start');
        }
    });
    const draft = {
        answers: throwingAnswers,
        highlights: [highlight],
        get scrollY() {
            throw new Error('bad scroll');
        }
    };

    const sanitized = hooks.cloneDraftSafely(draft);

    assert.deepEqual(Object.keys(sanitized.answers), []);
    assert.equal(sanitized.highlights.length, 1);
    assert.equal(sanitized.highlights[0].text, 'safe highlight');
    assert.equal(sanitized.highlights[0].start, 0);
    assert.equal(sanitized.scrollY, 0);
});

// Part navigation exercises section identity and bubbling targets alongside draft preservation.
class Element {
    constructor(dataset = {}, parent = null) {
        this.dataset = dataset;
        this.parentElement = parent;
        this.attributes = new Map();
        this.listeners = new Map();
        const classes = new Set();
        this.classList = {
            toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); },
            contains(name) { return classes.has(name); }
        };
    }
    setAttribute(name, value) { this.attributes.set(name, String(value)); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    removeAttribute(name) { this.attributes.delete(name); }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    closest(selector) {
        if (selector.startsWith('.q-column') && this.dataset.part && this.dataset.questionId) return this;
        if (selector.startsWith('.q-item') && !this.dataset.part && this.dataset.questionId) return this;
        return this.parentElement?.closest(selector) || null;
    }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    fire(type, extra = {}) {
        const event = { target: this, currentTarget: this, prevented: false, preventDefault() { this.prevented = true; }, ...extra };
        this.listeners.get(type)?.(event);
        return event;
    }
}

function createPartNavigationHarness() {
    const sections = ['p1', 'p2', 'p3'].map((part) => new Element({ part }));
    const messages = [];
    const parent = { postMessage(envelope, origin) { messages.push({ envelope, origin }); } };
    const document = {
        addEventListener() {},
        getElementById(id) { return sections.find((section) => id === `part-section-${section.dataset.part.slice(1)}`) || null; },
        querySelector() { return null; },
        querySelectorAll(selector) {
            return selector === 'input[type="radio"][name="q1"]' ? [{ checked: true, value: 'B' }] : [];
        }
    };
    const context = vm.createContext({
        console, document, Element, HTMLElement: Element, URL, URLSearchParams,
        setTimeout, clearTimeout, setInterval, clearInterval,
        opener: parent, parent, scrollY: 219,
        location: { href: 'https://reading.test/reading.html', origin: 'https://reading.test', protocol: 'https:' },
        __READING_HIGHLIGHT_SHARED__: { snapshotHighlights() { return [{ scope: 'left', text: 'retained highlight' }]; } },
        __IELTS_PRACTICE_TIMER__: { getSnapshot() { return { durationSeconds: 83, anchorMs: 1000, pausedOffsetMs: 2000, pausedAtMs: 86000, running: false }; } }
    });
    context.window = context;
    const marker = "    document.addEventListener('DOMContentLoaded',";
    assert(source.includes(marker));
    vm.runInContext(source.replace(marker, `    global.__navigation = { state, dom, renderPartQuestions, navClickHandler, attachNavListeners, updatePartSectionState, dispatchSimulationNavigate, handleIncoming };\n${marker}`), context);
    const hooks = context.__navigation;
    Object.assign(hooks.state, {
        examId: 'reading-p1', sessionId: 'current-page', suiteSessionId: 'current-suite',
        simulationMode: true, simulationContextReady: true,
        simulationCtx: { currentIndex: 0, total: 3, canNext: true, canPrev: false },
        dataset: { meta: { category: 'P1' }, questionOrder: ['q1'], answerKey: { q1: 'B' }, groups: [] }
    });
    hooks.dom.partQuestions = sections.map((section) => new Element({}, section));
    return { ...hooks, sections, messages, context, parent };
}

test('active question controls keep IDs; inactive controls delegate through their column', () => {
    const h = createPartNavigationHarness();
    const active = h.renderPartQuestions('p1', [{ qId: 'q1', label: '1' }], true);
    const inactive = h.renderPartQuestions('p3', [{ qId: 'q27', label: '27' }], false);
    assert.strict.match(active, /<button[^>]*data-question-id="q1"/);
    assert.strict.doesNotMatch(inactive.match(/<button[^>]*>/)[0], /data-question-id/);
    assert.strict.match(inactive, /class="q-column" data-question-id="q27" data-part="p3"/);
    const column = new Element({ questionId: 'q27', part: 'p3' });
    const inactiveButton = new Element({}, column);
    h.navClickHandler({ target: inactiveButton });
    assert.strict.equal(h.messages.length, 1, 'column metadata still navigates');
    assert.strict.equal(h.messages[0].envelope.data.targetIndex, 2);
});

test('part section click sends a non-adjacent target through the existing snapshot envelope', () => {
    const h = createPartNavigationHarness();
    h.updatePartSectionState('p1');
    h.attachNavListeners();
    h.sections[2].fire('click');
    assert.strict.equal(h.messages.length, 1);
    const { envelope, origin } = h.messages[0];
    assert.strict.equal(origin, 'https://reading.test');
    assert.strict.equal(envelope.type, 'SIMULATION_NAVIGATE');
    assert.strict.equal(envelope.data.targetIndex, 2);
    assert.strict.equal(envelope.data.direction, 'next');
    assert.strict.equal(envelope.data.examId, 'reading-p1');
    assert.strict.equal(envelope.data.sessionId, 'current-page');
    assert.strict.equal(envelope.data.suiteSessionId, 'current-suite');
    assert.strict.equal(envelope.data.draft.answers.q1, 'B');
    assert.strict.equal(envelope.data.resultSnapshot.answers.q1, 'B');
    assert.strict.equal(envelope.data.draft.highlights[0].text, 'retained highlight');
    assert.strict.equal(envelope.data.draft.scrollY, 219);
    assert.strict.equal(envelope.data.elapsed, 83);
    assert.strict.equal(envelope.data.timerSnapshot.pausedOffsetMs, 2000);
    assert.strict.equal(envelope.data.timerSnapshot.running, false);
});

test('only switchable part sections activate on Enter or Space', () => {
    const h = createPartNavigationHarness();
    h.updatePartSectionState('p1');
    h.attachNavListeners();
    assert.strict.equal(h.sections[0].getAttribute('role'), 'group');
    assert.strict.equal(h.sections[0].tabIndex, -1);
    assert.strict.equal(h.sections[2].getAttribute('role'), 'button');
    assert.strict.equal(h.sections[2].tabIndex, 0);
    for (const key of ['Enter', ' ']) {
        assert.strict.equal(h.sections[2].fire('keydown', { key }).prevented, true);
    }
    assert.strict.equal(h.messages.length, 2);
    h.sections[2].fire('keydown', { key: 'ArrowRight' });
    h.sections[2].fire('keydown', { key: 'Enter', target: new Element() });
    assert.strict.equal(h.sections[0].fire('keydown', { key: 'Enter' }).prevented, false);
    h.state.readOnly = true;
    h.updatePartSectionState('p1');
    assert.strict.equal(h.sections[2].fire('keydown', { key: ' ' }).prevented, false);
    h.sections[2].fire('click');
    assert.strict.equal(h.messages.length, 2);
});

test('invalid, same, unavailable and out-of-suite part requests are rejected', () => {
    const changes = [
        { readOnly: true }, { simulationMode: false }, { simulationCtx: null },
        { suiteSessionId: null }, { sessionId: null },
        { simulationCtx: { currentIndex: 0, total: 3, canNext: false } },
        { simulationCtx: { currentIndex: 0, total: 2, canNext: true } },
        { simulationCtx: { currentIndex: 0, total: 0, canNext: true } },
        { simulationCtx: { currentIndex: 4, total: 3, canNext: true } }
    ];
    for (const change of changes) {
        const h = createPartNavigationHarness();
        Object.assign(h.state, change);
        h.navClickHandler({ target: new Element({ part: 'p3', questionId: 'q27' }) });
        assert.strict.equal(h.messages.length, 0, JSON.stringify(change));
    }
    for (const part of ['p0', 'p4', 'P3', 'invalid', 'p1']) {
        const h = createPartNavigationHarness();
        h.navClickHandler({ target: new Element({ part, questionId: 'q1' }) });
        assert.strict.equal(h.messages.length, 0, part);
    }
    const h = createPartNavigationHarness();
    h.state.dataset.meta.category = 'P3';
    h.state.simulationCtx = { currentIndex: 2, total: 3, canPrev: false };
    h.navClickHandler({ target: new Element({ part: 'p1', questionId: 'q1' }) });
    assert.strict.equal(h.messages.length, 0, 'canPrev guard');
    for (const target of [-1, 0, 3, 1.5, '2', null, NaN]) {
        const h = createPartNavigationHarness();
        assert.strict.equal(h.dispatchSimulationNavigate('next', null, target), false);
        assert.strict.equal(h.messages.length, 0, `invalid dispatch target ${String(target)}`);
    }
});

test('incoming navigation retains origin, source, suite and URL checks', () => {
    const h = createPartNavigationHarness();
    const original = h.context.location.href;
    const goodData = { suiteSessionId: 'current-suite', url: '/next.html' };
    for (const overrides of [
        { origin: 'https://elsewhere.test' }, { origin: 'null' }, { source: {} },
        { data: { type: 'SUITE_NAVIGATE', data: { ...goodData, suiteSessionId: 'old-suite' } } },
        { data: { type: 'SUITE_NAVIGATE', data: { ...goodData, url: 'https://elsewhere.test/next' } } }
    ]) {
        h.handleIncoming({ source: h.parent, origin: 'https://reading.test', data: { type: 'SUITE_NAVIGATE', data: goodData }, ...overrides });
        assert.strict.equal(h.context.location.href, original);
    }
    h.handleIncoming({ source: h.parent, origin: 'https://reading.test', data: { type: 'SUITE_NAVIGATE', data: goodData } });
    assert.strict.equal(h.context.location.href, 'https://reading.test/next.html');
});
