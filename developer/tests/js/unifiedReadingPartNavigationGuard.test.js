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

function createContext(options = {}) {
    const elements = options.elements || new Map();
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
        opener: options.opener || null,
        parent: options.parent || null,
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
            getElementById(id) { return elements.get(id) || null; },
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

function loadHooks(options = {}) {
    const context = createContext(options);
    const marker = '    function buildQuestionNav() {';
    assert(source.includes(marker), 'expected unified Reading question navigation renderer');
    const patchedSource = source.replace(
        marker,
        [
            '    global.__UnifiedReadingPartNavigationGuardHooks = {',
            '        renderPartQuestions,',
            '        resolvePartNavigation,',
            '        updatePartSectionState,',
            '        attachNavListeners,',
            '        dispatchSimulationNavigate,',
            '        setCurrentActiveQuestionId(questionId) {',
            '            state.currentActiveQuestionId = questionId;',
            '        },',
            '        setNavigationState(options = {}) {',
            "            state.dataset = { meta: { category: options.category || 'P1' }, questionOrder: [] };",
            '            state.simulationMode = options.simulationMode !== false;',
            '            state.simulationCtx = options.simulationCtx || { currentIndex: 0, total: 3, canPrev: false, canNext: true };',
            '            state.readOnly = options.readOnly === true;',
            "            state.suiteSessionId = options.suiteSessionId || 'suite-test';",
            '        }',
            '    };',
            '',
            marker
        ].join('\n')
    );
    vm.createContext(context);
    vm.runInContext(patchedSource, context, { filename: 'unifiedReadingPage.js' });
    return { hooks: context.__UnifiedReadingPartNavigationGuardHooks, context };
}

function getStartTags(markup, tagName) {
    return markup.match(new RegExp(`<${tagName}\\b[^>]*>`, 'g')) || [];
}

test('part navigation assigns question IDs only to active question controls', () => {
    const { hooks } = loadHooks();
    const questions = [
        { qId: 'q14', label: '14', status: 'answered' },
        { qId: 'q15', label: '15', status: '' }
    ];
    hooks.setCurrentActiveQuestionId('q14');

    const activeMarkup = hooks.renderPartQuestions('p1', questions, true);
    const inactiveMarkup = hooks.renderPartQuestions('p2', questions, false);
    const activeButtons = getStartTags(activeMarkup, 'button');
    const inactiveButtons = getStartTags(inactiveMarkup, 'button');
    const inactiveColumns = getStartTags(inactiveMarkup, 'div')
        .filter((tag) => tag.includes('class="q-column"'));

    assert.equal(activeButtons.length, 2);
    assert.match(activeButtons[0], /class="q-item answered active"/);
    assert.match(activeButtons[0], /data-question-id="q14"/);
    assert.match(activeButtons[1], /data-question-id="q15"/);

    assert.equal(inactiveButtons.length, 2);
    inactiveButtons.forEach((button) => {
        assert.match(button, /class="q-item [^"]* disabled"/);
        assert.doesNotMatch(button, /\sdata-question-id(?:=|\s|>)/);
    });

    assert.equal(inactiveColumns.length, 2);
    assert.match(inactiveColumns[0], /data-question-id="q14"/);
    assert.match(inactiveColumns[0], /data-part="p2"/);
    assert.match(inactiveColumns[1], /data-question-id="q15"/);
    assert.match(inactiveColumns[1], /data-part="p2"/);

    assert.match(
        source,
        /targetElement\?\.closest\('\.q-column\[data-question-id\]'\)/,
        'event delegation must continue resolving inactive Part clicks through the question column'
    );
});

function createClassList() {
    const values = new Set();
    return {
        toggle(name, enabled) {
            if (enabled) values.add(name);
            else values.delete(name);
        },
        contains(name) {
            return values.has(name);
        }
    };
}

function createPartSection() {
    const attributes = new Map();
    const listeners = new Map();
    const name = { classList: createClassList() };
    return {
        dataset: {},
        classList: createClassList(),
        tabIndex: 0,
        listeners,
        setAttribute(key, value) {
            attributes.set(key, String(value));
        },
        getAttribute(key) {
            return attributes.get(key) || null;
        },
        querySelector(selector) {
            return selector === '.part-nav-name' ? name : null;
        },
        addEventListener(type, handler) {
            listeners.set(type, handler);
        }
    };
}

test('part sections expose direct navigation and keyboard semantics only when switchable', () => {
    const sections = new Map([
        ['part-section-1', createPartSection()],
        ['part-section-2', createPartSection()],
        ['part-section-3', createPartSection()]
    ]);
    const messages = [];
    const opener = {
        postMessage(payload, targetOrigin) {
            messages.push({ payload, targetOrigin });
        }
    };
    const { hooks } = loadHooks({ elements: sections, opener });
    hooks.setNavigationState({ category: 'P1' });
    hooks.updatePartSectionState('p1');
    hooks.attachNavListeners();

    const current = sections.get('part-section-1');
    assert.equal(current.dataset.part, 'p1');
    assert.equal(current.classList.contains('active'), true);
    assert.equal(current.classList.contains('is-switchable'), false);
    assert.equal(current.tabIndex, -1);
    assert.equal(current.getAttribute('role'), 'group');
    assert.equal(current.getAttribute('aria-current'), 'step');

    for (const partNumber of [2, 3]) {
        const section = sections.get(`part-section-${partNumber}`);
        assert.equal(section.dataset.part, `p${partNumber}`);
        assert.equal(section.classList.contains('is-switchable'), true);
        assert.equal(section.tabIndex, 0);
        assert.equal(section.getAttribute('role'), 'button');
        assert.equal(section.getAttribute('aria-label'), `Go to Part ${partNumber}`);
        assert.equal(section.getAttribute('aria-current'), 'false');
        assert.equal(typeof section.listeners.get('click'), 'function');
        assert.equal(typeof section.listeners.get('keydown'), 'function');
    }

    let prevented = false;
    const p3Section = sections.get('part-section-3');
    p3Section.listeners.get('keydown')({
        target: p3Section,
        currentTarget: p3Section,
        key: 'Enter',
        preventDefault() {
            prevented = true;
        }
    });
    assert.equal(prevented, true);
    assert.equal(messages[0].payload.data.targetIndex, 2);
});

test('direct Part navigation sends a bounded target index to the suite controller', () => {
    const messages = [];
    const opener = {
        postMessage(payload, targetOrigin) {
            messages.push({ payload, targetOrigin });
        }
    };
    const { hooks } = loadHooks({ opener });
    hooks.setNavigationState({ category: 'P1' });
    const navigation = hooks.resolvePartNavigation('p3', 'p1');

    assert.equal(navigation.direction, 'next');
    assert.equal(navigation.targetIndex, 2);
    assert.equal(navigation.targetPartKey, 'p3');

    const sent = hooks.dispatchSimulationNavigate('next', {
        results: { answers: {} },
        answers: {},
        highlights: [],
        scrollY: 0,
        elapsed: 15,
        updatedAt: 123,
        timerSnapshot: { durationSeconds: 15 }
    }, navigation);

    assert.equal(sent, true);
    assert.equal(messages.length, 1);
    assert.equal(messages[0].payload.type, 'SIMULATION_NAVIGATE');
    assert.equal(messages[0].payload.data.direction, 'next');
    assert.equal(messages[0].payload.data.targetIndex, 2);
    assert.equal(messages[0].payload.data.targetPartKey, 'p3');
});
