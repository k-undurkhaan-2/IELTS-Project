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
    const marker = '    function buildQuestionNav() {';
    assert(source.includes(marker), 'expected unified Reading question navigation renderer');
    const patchedSource = source.replace(
        marker,
        [
            '    global.__UnifiedReadingPartNavigationGuardHooks = {',
            '        renderPartQuestions,',
            '        setCurrentActiveQuestionId(questionId) {',
            '            state.currentActiveQuestionId = questionId;',
            '        }',
            '    };',
            '',
            marker
        ].join('\n')
    );
    vm.createContext(context);
    vm.runInContext(patchedSource, context, { filename: 'unifiedReadingPage.js' });
    return context.__UnifiedReadingPartNavigationGuardHooks;
}

function getStartTags(markup, tagName) {
    return markup.match(new RegExp(`<${tagName}\\b[^>]*>`, 'g')) || [];
}

test('part navigation assigns question IDs only to active question controls', () => {
    const hooks = loadHooks();
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
