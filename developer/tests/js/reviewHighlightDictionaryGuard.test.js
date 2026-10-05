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
const source = fs.readFileSync(path.join(repoRoot, 'js', 'runtime', 'reviewHighlightDictionary.js'), 'utf8');

function createLocalStorage(seed = {}) {
    const store = new Map(Object.entries(seed).map(([key, value]) => [key, String(value)]));
    return {
        getItem(key) {
            return store.has(key) ? store.get(key) : null;
        },
        setItem(key, value) {
            store.set(key, String(value));
        },
        removeItem(key) {
            store.delete(key);
        }
    };
}

function loadReviewHighlightDictionary(options = {}) {
    const context = {
        console,
        Date,
        JSON: {
            parse(value) {
                if (typeof options.onJsonParse === 'function') {
                    options.onJsonParse(value);
                }
                return JSON.parse(value);
            },
            stringify: JSON.stringify
        },
        Map,
        Object,
        Set,
        String,
        Number,
        Array,
        WeakSet,
        module: { exports: {} },
        exports: {}
    };
    Object.assign(context, options.globals || {});
    context.globalThis = context;
    context.window = context;
    vm.createContext(context);
    const testSource = source.replace('    const api = {', '    global.__openDictionaryBubble = openBubble;\n    const api = {');
    vm.runInContext(testSource, context, { filename: 'reviewHighlightDictionary.js' });
    return { api: context.module.exports, context };
}

test('review highlight fallback vocab strips unsafe stored keys before saving', () => {
    const { api, context } = loadReviewHighlightDictionary();
    const unsafeStoredList = JSON.parse(`{
        "id": "reading-highlights",
        "name": "Reading highlights",
        "__proto__": { "pollutedReviewHighlight": true },
        "constructor": { "prototype": { "pollutedReviewHighlight": true } },
        "words": [
            {
                "id": "old-word",
                "word": "archive",
                "meaning": "old",
                "__proto__": { "pollutedReviewHighlight": true },
                "prototype": { "pollutedReviewHighlight": true },
                "constructor": { "prototype": { "pollutedReviewHighlight": true } }
            }
        ]
    }`);
    context.localStorage = createLocalStorage({
        [api.storageKey]: JSON.stringify({ data: unsafeStoredList })
    });

    api._test.writeFallbackVocab({
        word: 'example',
        meaning: 'sample meaning',
        definition: 'sample definition',
        sourceLabel: 'Unit test'
    });

    const savedEnvelope = JSON.parse(context.localStorage.getItem(api.storageKey));
    const savedList = savedEnvelope.data;
    assert.equal(Object.prototype.hasOwnProperty.call(savedList, '__proto__'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(savedList, 'prototype'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(savedList, 'constructor'), false);
    assert.equal(savedList.words.length, 2);

    const oldWord = savedList.words.find((word) => word.id === 'old-word');
    assert(oldWord);
    assert.equal(Object.prototype.hasOwnProperty.call(oldWord, '__proto__'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(oldWord, 'prototype'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(oldWord, 'constructor'), false);
    assert.equal(Object.prototype.pollutedReviewHighlight, undefined);
});

function bubbleHarness() {
    function events(target = {}) {
        const listeners = new Map();
        target.addEventListener = (type, fn, capture = false) => {
            const key = `${type}:${Boolean(capture)}`;
            const entries = listeners.get(key) || [];
            entries.push(fn);
            listeners.set(key, entries);
        };
        target.removeEventListener = (type, fn, capture = false) => {
            const key = `${type}:${Boolean(capture)}`;
            listeners.set(key, (listeners.get(key) || []).filter((entry) => entry !== fn));
        };
        target.fire = (type, event = {}) => {
            for (const capture of [true, false]) {
                [...(listeners.get(`${type}:${capture}`) || [])].forEach((fn) => fn(event));
            }
        };
        target.count = (type) => [true, false].reduce((sum, capture) => sum + (listeners.get(`${type}:${capture}`) || []).length, 0);
        return target;
    }
    class Element {
        static ELEMENT_NODE = 1;
        constructor() {
            events(this);
            this.style = {};
            this.dataset = {};
            this.children = [];
            this.nodeType = 1;
            this.classList = { toggle() {} };
            this.offsetWidth = 200;
            this.clientWidth = 184;
            this.offsetHeight = this.clientHeight = 160;
            this.scrollHeight = 400;
            this.scrollWidth = 184;
        }
        setAttribute() {}
        removeAttribute() {}
        matches(selector) { return selector === '.hl' && this.className === 'hl'; }
        querySelectorAll(selector) { return this.children.filter((child) => child.matches(selector)); }
        appendChild(child) { this.children.push(child); return child; }
        replaceChildren(...children) { this.children = children; }
        contains(node) { return node === this || this.children.some((child) => child.contains(node)); }
        closest(selector) { return this.matches(selector) ? this : null; }
        getBoundingClientRect() { return { left: 100, right: 300, top: 100, bottom: 260, width: 200, height: 160 }; }
    }
    const body = new Element();
    const head = new Element();
    const document = events({
        body, head,
        getElementById(id) { return [...body.children, ...head.children].find((node) => node.id === id) || null; },
        createElement() { return new Element(); },
        createDocumentFragment() { return new Element(); }
    });
    const globalEvents = events();
    const { api, context } = loadReviewHighlightDictionary({ globals: {
        ...globalEvents, document, Node: Element, HTMLElement: Element, HTMLButtonElement: Element,
        innerWidth: 900, innerHeight: 700,
        getComputedStyle() {
            return { overflowY: 'auto', overflowX: 'auto', borderLeftWidth: '1px', borderRightWidth: '1px', borderTopWidth: '1px', borderBottomWidth: '1px' };
        }
    } });
    const highlight = new Element();
    highlight.textContent = 'example';
    highlight.className = 'hl';
    body.appendChild(highlight);
    const open = () => context.__openDictionaryBubble(highlight);
    open();
    const bubble = document.getElementById('review-highlight-dictionary-bubble');
    return { api, open, bubble, document, highlight, window: globalEvents, outside: new Element(), Element };
}

test('dictionary inside scroll stays open; outside scroll and resize close it', () => {
    const h = bubbleHarness();
    const child = h.bubble.appendChild(new h.Element());
    for (const target of [h.bubble, child]) {
        h.window.fire('scroll', { target });
        assert.equal(h.bubble.style.display, 'block');
    }
    h.window.fire('scroll', { target: h.outside });
    assert.equal(h.bubble.style.display, 'none');
    h.open();
    h.window.fire('resize');
    assert.equal(h.bubble.style.display, 'none');
});

test('dictionary scrollbar clicks and zero-width overlay edges stay open within bounds', () => {
    const h = bubbleHarness();
    const click = (clientX, clientY) => h.document.fire('click', { target: h.outside, clientX, clientY });
    click(294, 180);
    assert.equal(h.bubble.style.display, 'block', 'measured vertical scrollbar');
    h.bubble.clientWidth = h.bubble.offsetWidth - 2;
    click(294, 180);
    assert.equal(h.bubble.style.display, 'block', 'zero-width vertical overlay scrollbar with 1px borders');
    h.bubble.clientHeight = h.bubble.offsetHeight - 2;
    h.bubble.scrollHeight = h.bubble.clientHeight;
    h.bubble.scrollWidth = 400;
    click(180, 255);
    assert.equal(h.bubble.style.display, 'block', 'horizontal overlay scrollbar with 1px borders');
    for (const point of [[270, 180], [301, 180], [294, 99], [294, 261]]) {
        h.open();
        click(...point);
        assert.equal(h.bubble.style.display, 'none', `outside bounded edge: ${point}`);
    }
    h.open();
    h.bubble.scrollWidth = h.bubble.clientWidth;
    click(294, 180);
    assert.equal(h.bubble.style.display, 'none', 'no overlay edge without overflowing content');
});

test('dictionary close detaches global handlers and reopen never duplicates them', () => {
    const h = bubbleHarness();
    for (let cycle = 0; cycle < 4; cycle += 1) {
        h.open();
        h.open();
        for (const [target, types] of [[h.document, ['click', 'keydown']], [h.window, ['resize', 'scroll']]]) {
            types.forEach((type) => assert.equal(target.count(type), 1, `${type} attached once`));
        }
        h.api.close();
        for (const [target, types] of [[h.document, ['click', 'keydown']], [h.window, ['resize', 'scroll']]]) {
            types.forEach((type) => assert.equal(target.count(type), 0, `${type} detached`));
        }
    }
});

test('dictionary content and interactive highlights remain inside-click safe', () => {
    const h = bubbleHarness();
    const child = h.bubble.appendChild(new h.Element());
    h.document.fire('click', { target: child });
    assert.equal(h.bubble.style.display, 'block');
    h.outside.closest = () => h.outside;
    h.document.fire('click', { target: h.outside });
    assert.equal(h.bubble.style.display, 'block');
    h.document.fire('keydown', { key: 'Escape' });
    assert.equal(h.bubble.style.display, 'none');
});

test('dictionary highlight keyboard activation remains available after close and repeated attach', () => {
    const h = bubbleHarness();
    const options = { roots: { left: h.document.body } };
    h.api.attach(options);
    h.api.attach(options);
    for (const key of ['Enter', ' ']) {
        let prevented = false;
        h.document.fire('keydown', { key, target: h.highlight, preventDefault() { prevented = true; } });
        assert.equal(prevented, true);
        assert.equal(h.bubble.style.display, 'block');
        h.api.close();
        assert.equal(h.document.count('keydown'), 1, 'only the single activation delegate remains');
        assert.equal(h.document.count('click'), 1, 'only the single activation delegate remains');
    }
});

test('review highlight context keeps shared references but drops cycles', () => {
    const { api } = loadReviewHighlightDictionary();
    const shared = { selected: 'same paragraph' };
    const context = {
        first: shared,
        second: shared
    };
    context.self = context;

    const normalized = api._test.normalizeContextValue(context);

    assert.deepEqual(normalized.first, { selected: 'same paragraph' });
    assert.deepEqual(normalized.second, { selected: 'same paragraph' });
    assert.equal(Object.prototype.hasOwnProperty.call(normalized, 'self'), false);
});

test('review highlight fallback rejects oversized storage before parsing', () => {
    let oversizedParsed = false;
    const { api, context } = loadReviewHighlightDictionary({
        onJsonParse(value) {
            if (String(value || '').length > 5 * 1024 * 1024) {
                oversizedParsed = true;
            }
        }
    });
    context.localStorage = createLocalStorage({
        [api.storageKey]: '{"data":{"words":[]},"padding":"' + 'x'.repeat((5 * 1024 * 1024) + 1) + '"}'
    });

    const saved = api._test.writeFallbackVocab({
        word: 'bounded',
        meaning: 'safe fallback',
        sourceLabel: 'Unit test'
    });

    assert.equal(saved, true);
    assert.equal(oversizedParsed, false, 'oversized fallback storage must be rejected before JSON.parse');
    const savedEnvelope = JSON.parse(context.localStorage.getItem(api.storageKey));
    assert.equal(savedEnvelope.data.words.length, 1);
    assert.equal(savedEnvelope.data.words[0].word, 'bounded');
});

test('review highlight fallback truncates saved text at valid Unicode boundaries', () => {
    const { api, context } = loadReviewHighlightDictionary();
    context.localStorage = createLocalStorage();

    const saved = api._test.writeFallbackVocab({
        word: `${'w'.repeat(159)}\uD83D\uDE00tail`,
        meaning: `${'m'.repeat(3999)}\uD83D\uDE00tail`,
        example: `${'e'.repeat(3999)}\uD83D\uDE00tail`,
        phonetic: `${'p'.repeat(199)}\uD83D\uDE00tail`,
        partOfSpeech: `${'s'.repeat(199)}\uD83D\uDE00tail`,
        selectedText: `${'x'.repeat(159)}\uD83D\uDE00tail`,
        sourceLabel: `${'l'.repeat(199)}\uD83D\uDE00tail`
    });

    assert.equal(saved, true);
    const savedEnvelope = JSON.parse(context.localStorage.getItem(api.storageKey));
    const [word] = savedEnvelope.data.words;

    assert.equal(word.word, 'w'.repeat(159));
    assert.equal(word.meaning, 'm'.repeat(3999));
    assert.equal(word.example, 'e'.repeat(3999));
    assert.equal(word.note.includes('p'.repeat(199)), true);
    assert.equal(word.note.includes('s'.repeat(199)), true);
    assert.equal(word.note.includes('x'.repeat(159)), true);
    assert.equal(word.note.includes('l'.repeat(199)), true);
    assert.equal(/[\uD800-\uDFFF]/.test([
        word.word,
        word.meaning,
        word.example,
        word.note
    ].join('')), false);
});
