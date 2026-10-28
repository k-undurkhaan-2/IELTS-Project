#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const mark = 'span.hl[data-listening-highlight]';
const toolbar = '#listening-selbar';
const legacyToolbarIds = ['selbar', 'selToolbar', 'highlightToolbar', 'hl-toolbar', 'highlighter-btn', 'selBubble', 'selectionToolbar', 'selection-bar', 'sel-toolbar'];

// Public synthetic questions exercise the shipped bundles without depending on
// private listening content, recordings, or a running application server.
function fixture({ scope = 'main', notes = true } = {}) {
    const questionMarkup = `<p id="plain">Museum opening hours</p>
        <p id="complex"><span id="start">Arrive at </span><strong id="strong">the north</strong><input id="answer" name="q1" value="original answer"><em id="em"> hall</em><span id="end"> before nine.</span></p>
        <p id="quote">Bring your library card</p>
        <p id="mobile">Selected words near the edge</p>
        <button id="question-control" type="button">Question control text</button>
        <div contenteditable="true" id="editable">Editable answer text</div>`;
    const content = scope === 'body' ? questionMarkup
        : scope === 'main' ? `<main>${questionMarkup}</main>`
            : scope === 'split' ? `<div id="left-pane"><p id="cross-start">Left pane text</p>${questionMarkup}</div><div id="right-pane"><p id="cross-end">Right pane text</p></div>`
            : `<div class="questions-pane" id="left-pane">${questionMarkup}</div>`;
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>
        body { margin: 20px; font: 18px/1.6 Arial, sans-serif; }
        p { margin: 22px 0; }
        input { width: 110px; margin: 0 5px; }
        #mobile { text-align: right; }
        #notes-panel { display: none; }
        #selbar, #selToolbar { position: fixed; left: 0; top: 0; }
        #editable { margin-top: 16px; }
    </style></head><body>
    <header id="header">Header navigation text</header>
    <nav id="navigation">Navigation control text</nav>
    ${content}
    ${notes ? '<aside id="notes-panel"><textarea>Existing note\n</textarea></aside>' : ''}
    <button id="toggle-notes-btn" type="button">Notes</button>
    <aside id="notes" style="display: none">Existing card notes</aside>
    ${legacyToolbarIds.map(id => `<div id="${id}"><button type="button">Legacy annotation</button></div>`).join('')}
    <script>
        window.fixtureState = { answer: document.querySelector('#answer'), strong: document.querySelector('#strong'), em: document.querySelector('#em'), inputEvents: 0, noteEvents: 0, legacyNotesClicks: 0 };
        fixtureState.answer.addEventListener('input', () => { fixtureState.inputEvents += 1; });
        document.querySelector('#notes-panel textarea')?.addEventListener('input', () => { fixtureState.noteEvents += 1; });
        document.querySelector('#toggle-notes-btn').addEventListener('click', () => {
            fixtureState.legacyNotesClicks += 1;
            const panel = document.querySelector('#notes');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        });
    </script>
    <script src="/js/bundles/listening-record-bridge.bundle.js" defer></script>
    </body></html>`;
}

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname === '/wrapper') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-source-url=""', 'data-source-url="/fixture"'));
        return;
    }
    if (['/js/bundles/listening-wrapper.bundle.js', '/js/bundles/listening-record-bridge.bundle.js'].includes(url.pathname)) {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(path.join(repoRoot, url.pathname)));
        return;
    }
    if (url.pathname === '/fixture') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fixture({ scope: url.searchParams.get('scope') || 'main', notes: url.searchParams.get('notes') !== 'fallback' }));
        return;
    }
    response.writeHead(404).end();
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({
    headless: true,
    ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {})
});

async function openFixture(page, entry) {
    await page.goto(baseUrl + entry);
    if (entry === '/wrapper') await page.locator('#listening-practice-frame').waitFor();
    const frame = entry === '/wrapper'
        ? await page.locator('#listening-practice-frame').elementHandle().then(element => element.contentFrame())
        : page.mainFrame();
    await frame.waitForFunction(() => window.ListeningHighlighter && document.querySelector('#plain'));
    return frame;
}

async function selectMouse(page, frame, startSelector, endSelector = startSelector) {
    await frame.locator(startSelector).scrollIntoViewIfNeeded();
    const points = await frame.evaluate(({ startSelector, endSelector }) => {
        function endpoint(selector, end) {
            const walker = document.createTreeWalker(document.querySelector(selector), NodeFilter.SHOW_TEXT);
            const nodes = [];
            while (walker.nextNode()) if (walker.currentNode.textContent) nodes.push(walker.currentNode);
            const node = end ? nodes[nodes.length - 1] : nodes[0];
            const range = document.createRange();
            range.setStart(node, end ? node.length - 1 : 0);
            range.setEnd(node, end ? node.length : 1);
            const rect = range.getBoundingClientRect();
            return { x: end ? rect.right - 0.25 : rect.left + 0.25, y: rect.top + rect.height / 2 };
        }
        window.getSelection().removeAllRanges();
        return { start: endpoint(startSelector, false), end: endpoint(endSelector, true) };
    }, { startSelector, endSelector });
    const offset = frame.parentFrame() ? await (await frame.frameElement()).boundingBox() : { x: 0, y: 0 };
    await page.mouse.move(offset.x + points.start.x, offset.y + points.start.y);
    await page.mouse.down();
    await page.mouse.move(offset.x + points.end.x, offset.y + points.end.y, { steps: 12 });
    await page.mouse.up();
    const text = await frame.evaluate(() => window.getSelection().toString());
    assert(text.trim(), `mouse dragging ${startSelector} must select text`);
    await frame.locator(toolbar).waitFor({ state: 'visible' });
    return text;
}

async function selectRange(frame, selector) {
    await frame.locator(selector).evaluate(element => {
        const range = document.createRange();
        range.selectNodeContents(element);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        document.dispatchEvent(new Event('selectionchange'));
        element.dispatchEvent(new KeyboardEvent('keyup', { key: 'Shift', bubbles: true }));
    });
}

async function assertAnswerIntact(frame) {
    assert.deepEqual(await frame.evaluate(() => ({
        answer: document.querySelector('#answer') === fixtureState.answer,
        strong: document.querySelector('#strong') === fixtureState.strong,
        em: document.querySelector('#em') === fixtureState.em,
        value: fixtureState.answer.value,
        wrappedInput: Boolean(fixtureState.answer.closest('[data-listening-highlight]'))
    })), { answer: true, strong: true, em: true, value: 'original answer', wrappedInput: false },
    'annotating mixed content must preserve answer elements, values, and inline formatting');
}

async function exerciseDesktop(entry) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        const frame = await openFixture(page, entry);
        await frame.evaluate(() => {
            window.ListeningHighlighter.install(document);
            window.ListeningHighlighter.install(document);
        });

        const selected = await selectMouse(page, frame, '#plain');
        assert.equal(await frame.locator(toolbar).count(), 1, 'repeated installation must create one toolbar');
        for (const id of legacyToolbarIds) {
            assert.equal(await frame.locator(`#${id}`).isVisible(), false, `${id} must not compete with the new controls`);
        }
        await frame.locator(`${toolbar} [data-role="highlight"]`).click();
        assert.equal(await frame.locator(`#plain ${mark}`).allTextContents().then(texts => texts.join('')), selected);

        // A click on a mark must expose Remove without a fresh text selection.
        await frame.locator(`#plain ${mark}`).first().click();
        await frame.locator(`${toolbar} [data-role="remove-highlight"]`).click();
        assert.equal(await frame.locator(`#plain ${mark}`).count(), 0);
        assert.equal(await frame.locator('#plain').textContent(), 'Museum opening hours');

        const complexText = await selectMouse(page, frame, '#start', '#end');
        await frame.locator(`${toolbar} [data-role="highlight"]`).click();
        assert.equal(await frame.locator(`#complex ${mark}`).allTextContents().then(texts => texts.join('')), complexText);
        await assertAnswerIntact(frame);
        await selectMouse(page, frame, '#start', '#end');
        await frame.locator(`${toolbar} [data-role="remove-highlight"]`).click();
        assert.equal(await frame.locator(`#complex ${mark}`).count(), 0);
        await assertAnswerIntact(frame);
        await frame.locator('#answer').fill('updated answer');
        assert.equal(await frame.evaluate(() => fixtureState.inputEvents), 1, 'answer listeners must survive highlighting and removal');

        const quoted = await selectMouse(page, frame, '#quote');
        await frame.locator(`${toolbar} [data-role="note"]`).click();
        assert.equal(await frame.locator('#notes-panel textarea').inputValue(), `Existing note\n\n\n> ${quoted}\n`);
        assert.equal(await frame.locator('#notes-panel').isVisible(), true, 'Note must reveal the existing notes panel');
        assert.equal(await frame.evaluate(() => fixtureState.noteEvents), 1, 'Note must emit one input event for persistence');
        assert.equal(await frame.locator(`#quote ${mark}[data-hl-type="note"]`).count(), 1);

        // Browser selections in editable controls or chrome are never question annotations.
        for (const selector of ['#header', '#navigation', '#question-control', '#editable']) {
            await selectRange(frame, selector);
            await frame.locator(toolbar).waitFor({ state: 'hidden' });
            assert.equal(await frame.locator(`${selector} ${mark}`).count(), 0);
        }
        await frame.locator('#answer').focus();
        await frame.locator('#answer').evaluate(input => {
            input.select();
            input.dispatchEvent(new KeyboardEvent('keyup', { key: 'Shift', bubbles: true }));
        });
        await frame.locator(toolbar).waitFor({ state: 'hidden' });
        assert.equal(await frame.locator('#answer').inputValue(), 'updated answer');
        assert.deepEqual(errors, [], 'highlight and note interactions must not produce uncaught errors');
        console.log(`PASS ${entry}: selection, removal, mixed markup, answers, notes, excluded controls, repeated install`);
    } finally {
        await page.close();
    }
}

async function exerciseAlternateScopes() {
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        for (const scope of ['pane', 'body']) {
            const frame = await openFixture(page, `/fixture?scope=${scope}&notes=fallback`);
            const selected = await selectMouse(page, frame, '#quote');
            await frame.locator(`${toolbar} [data-role="note"]`).click();
            assert.equal(await frame.locator('#listening-highlight-notes').isVisible(), true);
            assert.equal(await frame.locator('#listening-highlight-notes textarea').inputValue(), `> ${selected}\n`);
            assert.equal(await frame.locator(`#quote ${mark}[data-hl-type="note"]`).count(), 1);
            const edited = `> ${selected}\nMy edited annotation`;
            await frame.locator('#listening-highlight-notes textarea').fill(edited);
            await frame.locator('#listening-highlight-notes').getByRole('button', { name: 'Close', exact: true }).click();
            assert.equal(await frame.locator('#listening-highlight-notes').isVisible(), false);
            await frame.locator('#listening-highlight-notes-toggle').click();
            assert.equal(await frame.locator('#listening-highlight-notes').isVisible(), true);
            assert.equal(await frame.locator('#listening-highlight-notes textarea').inputValue(), edited,
                'reopening highlight notes must retain edits without appending another quote');
            await frame.locator('#listening-highlight-notes').getByRole('button', { name: 'Close', exact: true }).click();
            await frame.locator('#toggle-notes-btn').click();
            assert.equal(await frame.locator('#notes').isVisible(), true, 'the existing Notes action must remain accessible');
            assert.equal(await frame.evaluate(() => fixtureState.legacyNotesClicks), 1);
            assert.equal(await frame.locator('#notes').textContent(), 'Existing card notes');
            assert.equal(await frame.locator('#listening-highlight-notes').isVisible(), false,
                'the existing Notes control must keep its own behavior');
            await selectRange(frame, '#header');
            await frame.locator(toolbar).waitFor({ state: 'hidden' });
        }

        const frame = await openFixture(page, '/fixture?scope=split');
        await frame.evaluate(() => {
            const start = document.querySelector('#cross-start').firstChild;
            const end = document.querySelector('#cross-end').firstChild;
            const range = document.createRange();
            range.setStart(start, 0);
            range.setEnd(end, end.length);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            document.dispatchEvent(new Event('selectionchange'));
        });
        await frame.locator(toolbar).waitFor({ state: 'hidden' });
        // Flush the selection handler so an initially hidden toolbar cannot
        // satisfy this assertion before the cross-pane range is inspected.
        await frame.evaluate(() => new Promise(resolve => setTimeout(resolve, 50)));
        assert.equal(await frame.locator(toolbar).isVisible(), false, 'separate question panes must not share an annotation range');
        assert.equal(await frame.locator(mark).count(), 0);
        assert.deepEqual(errors, [], 'alternate layouts must not produce uncaught errors');
        console.log('PASS alternate scopes: panes, body fallback, retained highlight notes, legacy Notes, excluded header and cross-pane selection');
    } finally {
        await page.close();
    }
}

async function exerciseTouch() {
    const context = await browser.newContext({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        const frame = await openFixture(page, '/wrapper');
        await frame.locator('#mobile').scrollIntoViewIfNeeded();
        // Set the browser's native selection as mobile selection handles do;
        // activate the toolbar with a real touch event rather than a mouse click.
        await selectRange(frame, '#mobile');
        await frame.locator(toolbar).waitFor({ state: 'visible' });
        const bounds = await frame.locator(toolbar).boundingBox();
        assert(bounds.x >= 0 && bounds.x + bounds.width <= 390.5, 'the complete toolbar must fit the narrow viewport');
        assert(bounds.y >= 0 && bounds.y + bounds.height <= 844.5, 'the toolbar must remain within the viewport vertically');
        await frame.locator(`${toolbar} [data-role="highlight"]`).tap();
        assert.equal(await frame.locator(`#mobile ${mark}`).allTextContents().then(texts => texts.join('')), 'Selected words near the edge');
        await frame.locator(`#mobile ${mark}`).first().tap();
        await frame.locator(`${toolbar} [data-role="remove-highlight"]`).tap();
        assert.equal(await frame.locator(`#mobile ${mark}`).count(), 0);
        assert.deepEqual(errors, [], 'touch interactions must not produce uncaught errors');
        console.log('PASS touch: 390px iframe toolbar bounds, highlight and removal');
    } finally {
        await context.close();
    }
}

try {
    await exerciseDesktop('/fixture');
    await exerciseDesktop('/wrapper');
    await exerciseAlternateScopes();
    await exerciseTouch();
} finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
}
