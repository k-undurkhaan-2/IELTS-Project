#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (file) => fs.readFileSync(path.join(repoRoot, file), 'utf8');
const readingShell = read('assets/generated/reading-exams/reading-practice-unified.html');
const readingStyles = [...readingShell.matchAll(/<style>([\s\S]*?)<\/style>/g)].map(match => match[1]).join('\n');
const optionText = 'A long answer about museum opening hours and the different activities that visitors can enjoy during their visit.';
// Public synthetic content uses the shipped option styles and real entry bundles.
const fixture = `<div id="layout-fixture">
    <div class="choice-item"><label id="option"><input id="radio" type="radio" name="q1" value="A">${optionText}</label></div>
    <div class="tfng-options"><label id="inline-option"><input id="checkbox" type="checkbox" name="q2">NOT GIVEN in the reading passage</label></div>
    <label id="grid-option" style="display:grid;grid-template-columns:18px 1fr;gap:8px;margin:16px 0"><input id="grid-radio" type="radio" name="q3">${optionText}</label>
    <p id="mixed">Arrive at <strong id="strong">the north entrance</strong> with <input id="answer" name="q4" value="original answer" style="width:90px"> before visiting <em id="em">the main hall</em> and the garden.</p>
    <p id="block-start">The first paragraph includes a <strong>bold phrase</strong> and some ordinary words.</p>
    <p id="block-end">The second paragraph stays separate and retains its original spacing.</p>
    <table id="table" style="width:100%;table-layout:fixed"><tbody><tr><td id="cell-start">A table cell with several words.</td><td id="cell-end">Another cell keeps its own column.</td></tr></tbody></table>
    <p id="after">The next question should keep its position.</p>
</div>`;
const dataset = {
    examId: 'highlight-layout',
    meta: { title: 'Highlight layout regression', category: 'P1' },
    passage: { blocks: [{ html: '<p>A short synthetic passage.</p>' }] },
    questionGroups: [{ groupId: 'layout', bodyHtml: `<div class="group">${fixture}</div>`, questionIds: ['q1', 'q2', 'q3', 'q4'] }],
    questionOrder: ['q1', 'q2', 'q3', 'q4'],
    answers: { q1: 'A', q2: 'on', q3: 'on', q4: 'original answer' }
};

async function openFixture(page, kind, profile = 'default') {
    const bundleRoot = profile === 'vip' ? 'ListeningPractice/vip special/' : '';
    await page.route('http://highlight.test/**', route => {
        const pathname = new URL(route.request().url()).pathname;
        let body;
        let contentType = 'text/javascript';
        if (pathname.endsWith('/reading-practice-unified.html')) {
            body = readingShell;
            contentType = 'text/html';
        } else if (pathname === '/listening') {
            body = `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><style>${readingStyles}body{padding:20px;height:auto;overflow:auto}main{max-width:720px}#notes-panel{display:none}</style><main>${fixture}</main><aside id="notes-panel"><textarea></textarea></aside><script src="/js/bundles/listening-record-bridge.bundle.js"></script>`;
            contentType = 'text/html';
        } else if (pathname.endsWith('/manifest.js')) {
            body = 'window.__READING_EXAM_MANIFEST__ = { "highlight-layout": { dataKey: "highlight-layout", script: "./highlight-layout.js" } };';
        } else if (pathname.endsWith('/highlight-layout.js')) {
            body = `window.__READING_EXAM_DATA__.register('highlight-layout', ${JSON.stringify(dataset)});`;
        } else if (['/js/bundles/reading-page.bundle.js', '/js/bundles/listening-record-bridge.bundle.js'].includes(pathname)) {
            body = read(bundleRoot + pathname.slice(1));
        } else {
            return route.fulfill({ status: 404, body: '' });
        }
        return route.fulfill({ contentType, body });
    });
    await page.goto(kind === 'reading'
        ? 'http://highlight.test/assets/generated/reading-exams/reading-practice-unified.html?examId=highlight-layout'
        : 'http://highlight.test/listening');
    await page.locator('#option').waitFor();
    await page.waitForFunction(kind => kind === 'reading'
        ? !!window.__READING_HIGHLIGHT_SHARED__
        : !!document.__listeningHighlighterInstalled, kind);
    await page.evaluate(() => {
        window.originalNodes = [...document.querySelectorAll('#layout-fixture input, #strong, #em, #table, td, #block-start, #block-end')];
        window.answerInputEvents = 0;
        document.getElementById('answer').addEventListener('input', () => { window.answerInputEvents += 1; });
        // Adjacent text nodes and comments still form one anonymous flex item.
        const text = document.getElementById('option').lastChild;
        const tail = text.splitText(12);
        tail.parentNode.insertBefore(document.createComment('text boundary'), tail);
    });
}

async function measure(page) {
    return page.evaluate(() => {
        const root = document.getElementById('layout-fixture');
        const origin = root.getBoundingClientRect();
        const rect = bounds => [bounds.x - origin.x, bounds.y - origin.y, bounds.width, bounds.height];
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        const glyphs = [];
        while (walker.nextNode()) {
            const node = walker.currentNode;
            for (let index = 0; index < node.length; index += 1) {
                if (/\s/.test(node.data[index])) continue;
                const range = document.createRange();
                range.setStart(node, index);
                range.setEnd(node, index + 1);
                glyphs.push([node.data[index], ...rect(range.getBoundingClientRect())]);
            }
        }
        return {
            text: root.textContent,
            glyphs,
            controls: [...root.querySelectorAll('input')].map(node => [node.id, ...rect(node.getBoundingClientRect())]),
            next: rect(document.getElementById('after').getBoundingClientRect())
        };
    });
}

function assertLayout(before, after, message) {
    assert.equal(after.text, before.text, `${message}: text must be preserved`);
    for (const key of ['glyphs', 'controls', 'next']) {
        assert.equal(after[key].length, before[key].length, `${message}: ${key} count`);
        for (let index = 0; index < before[key].length; index += 1) {
            const expected = Array.isArray(before[key][index]) ? before[key][index] : [before[key][index]];
            const actual = Array.isArray(after[key][index]) ? after[key][index] : [after[key][index]];
            assert(expected.every((value, axis) => typeof value === 'number'
                ? Math.abs(value - actual[axis]) <= 0.1
                : value === actual[axis]), `${message}: ${key}[${index}] moved: ${JSON.stringify(expected)} -> ${JSON.stringify(actual)}`);
        }
    }
}

async function selectText(page, selector, text, endSelector) {
    await page.locator(selector).scrollIntoViewIfNeeded();
    await page.evaluate(({ selector, text, endSelector }) => {
        const element = document.querySelector(selector);
        const range = document.createRange();
        if (endSelector) {
            const end = document.querySelector(endSelector);
            range.setStart(element.firstChild, 0);
            range.setEnd(end.lastChild, end.lastChild.length);
        } else {
            const fullText = element.textContent;
            const start = text ? fullText.indexOf(text) : 0;
            const end = start + (text || fullText).length;
            if (start < 0) throw new Error(`Missing selected text: ${text}`);
            const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
            let offset = 0;
            let started = false;
            while (walker.nextNode()) {
                const node = walker.currentNode;
                const next = offset + node.length;
                if (!started && start < next) {
                    range.setStart(node, start - offset);
                    started = true;
                }
                if (started && end <= next) {
                    range.setEnd(node, end - offset);
                    break;
                }
                offset = next;
            }
        }
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        document.dispatchEvent(new Event('selectionchange'));
    }, { selector, text, endSelector });
}

async function annotate(page, kind, selector, text, { note = false, endSelector } = {}) {
    await selectText(page, selector, text, endSelector);
    const toolbar = kind === 'reading' ? '#selbar' : '#listening-selbar';
    await page.locator(toolbar).waitFor({ state: 'visible' });
    await page.locator(kind === 'reading'
        ? (note ? '#btnNote' : '#btnHL')
        : `${toolbar} [data-role="${note ? 'note' : 'highlight'}"]`).click();
    assert(await page.locator(`${selector} .hl`).count() > 0, `${kind}: ${selector} must be highlighted`);
    if (note) {
        assert.match(await page.locator('#notes-panel textarea').inputValue(), /museum opening hours/);
        await page.keyboard.press('Escape');
        await page.evaluate(() => {
            document.querySelector('#notes-panel').style.display = 'none';
            const overlay = document.querySelector('.overlay');
            if (overlay) overlay.style.display = 'none';
        });
    }
}

test('highlights preserve responsive text flow in reading and listening', { timeout: 180000 }, async t => {
    const browser = await chromium.launch({
        headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {})
    });
    try {
        for (const kind of ['reading', 'listening']) {
            for (const width of [320, 390, 768, 980, 981, 1024, 1440]) {
                await t.test(`${kind} at ${width}px`, async () => {
                    const page = await browser.newPage({ viewport: { width, height: 1000 } });
                    page.setDefaultTimeout(5000);
                    const errors = [];
                    page.on('pageerror', error => errors.push(error.message));
                    try {
                        await openFixture(page, kind);
                        const before = await measure(page);
                        const cases = [
                            ['#option', 'museum opening hours', { note: true }],
                            ['#inline-option', 'GIVEN'],
                            ['#grid-option', 'museum opening hours'],
                            ['#mixed', 'at the north entrance with  before visiting the main'],
                            ['#block-start', null, { endSelector: '#block-end' }],
                            ['#cell-start', null, { endSelector: '#cell-end' }]
                        ];
                        for (const [selector, text, options] of cases) {
                            await annotate(page, kind, selector, text, options);
                            assertLayout(before, await measure(page), `${kind} ${width}px ${selector}`);
                        }
                        // Resizing and larger text must lay out exactly as an
                        // unhighlighted copy under the same settings.
                        const records = kind === 'reading' ? await page.evaluate(() =>
                            __READING_HIGHLIGHT_SHARED__.snapshotHighlights({ main: document.getElementById('layout-fixture') })) : null;
                        if (records) assert.equal(records.length, await page.locator('#layout-fixture .hl').count(), 'repeated text must not drop saved highlights');
                        await page.setViewportSize({ width: width < 981 ? 1280 : 390, height: 1000 });
                        await page.evaluate(() => { document.documentElement.className = 'font-xlarge'; });
                        const enlarged = await measure(page);
                        await page.evaluate(() => {
                            document.querySelectorAll('#layout-fixture .hl').forEach(mark => {
                                const parent = mark.parentNode;
                                while (mark.firstChild) parent.insertBefore(mark.firstChild, mark);
                                mark.remove();
                                parent.normalize();
                            });
                        });
                        assertLayout(enlarged, await measure(page), `${kind} resized, 125% font size, removed`);
                        if (records) {
                            const restored = await page.evaluate(records => __READING_HIGHLIGHT_SHARED__.restoreHighlights(
                                { main: document.getElementById('layout-fixture') }, records), records);
                            assert.equal(restored, records.length, 'every saved highlight must restore');
                            assertLayout(enlarged, await measure(page), 'restored reading highlights');
                            assert(await page.locator('#option .hl[data-hl-type="note"]').count() > 0);
                            assert(await page.locator('#grid-option .hl').count() > 0, 'repeated selected text must restore at its own position');
                        }
                        assert.equal(await page.evaluate(() => originalNodes.every(node => node.isConnected && document.getElementById(node.id) === node)), true,
                            'original formatting elements, paragraphs, cells, and answer controls must survive');
                        await page.locator('#answer').fill('updated answer');
                        assert.equal(await page.evaluate(() => answerInputEvents), 1, 'answer event handlers must survive');
                        assert.deepEqual(errors, [], 'highlighting must not raise page errors');
                    } finally {
                        await page.close();
                    }
                });
            }
            await t.test(`${kind} VIP bundle, restored legacy ranges, and repeated removal`, async () => {
                const page = await browser.newPage({ viewport: { width: 390, height: 1000 } });
                page.setDefaultTimeout(5000);
                try {
                    await openFixture(page, kind, 'vip');
                    const before = await measure(page);
                    for (let cycle = 0; cycle < 3; cycle += 1) {
                        await annotate(page, kind, '#option', 'museum opening hours');
                        assertLayout(before, await measure(page), 'repeated highlight');
                        await selectText(page, '#option .hl');
                        await page.locator(kind === 'reading' ? '#btnUH' : '#listening-selbar [data-role="remove-highlight"]').click();
                        assert.equal(await page.locator('#option .hl').count(), 0);
                        assertLayout(before, await measure(page), 'toolbar removal');
                    }
                    await annotate(page, kind, '#mixed', 'at the north entrance with  before visiting the main');
                    await selectText(page, '#mixed');
                    await page.locator(kind === 'reading' ? '#btnNote' : '#listening-selbar [data-role="note"]').click();
                    assert.equal(await page.locator('#mixed .hl:not([data-hl-type="note"])').count(), 0, 'all selected fragments must become notes');
                    assert.match(await page.locator('#notes-panel textarea').inputValue(), /north entrance with\s+before visiting the main hall/);
                    await page.evaluate(() => {
                        document.querySelector('#notes-panel').style.display = 'none';
                        const overlay = document.querySelector('.overlay');
                        if (overlay) overlay.style.display = 'none';
                    });
                    await selectText(page, '#mixed');
                    await page.locator(kind === 'reading' ? '#btnUH' : '#listening-selbar [data-role="remove-highlight"]').click();
                    assert.equal(await page.locator('#mixed .hl').count(), 0, 'removal must cover all selected text fragments');
                    assertLayout(before, await measure(page), 'mixed-format note and removal');
                    if (kind === 'reading') {
                        await page.evaluate(() => {
                            const root = document.getElementById('layout-fixture');
                            const text = document.getElementById('mixed').textContent;
                            const start = __READING_HIGHLIGHT_SHARED__.getText(root).indexOf(text);
                            const restored = __READING_HIGHLIGHT_SHARED__.restoreHighlights({ main: root }, [{ scope: 'main', text, start, end: start + text.length }]);
                            if (restored !== 1) throw new Error('Legacy mixed-format highlight failed to restore');
                        });
                        assertLayout(before, await measure(page), 'legacy mixed-format restore');
                        await page.evaluate(() => __READING_HIGHLIGHT_SHARED__.wrapTextMatches(document.getElementById('grid-option'), 'museum opening hours'));
                        assertLayout(before, await measure(page), 'locator text matches');
                    }
                } finally {
                    await page.close();
                }
            });
        }
    } finally {
        await browser.close();
    }
});
