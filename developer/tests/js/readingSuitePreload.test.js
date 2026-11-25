#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const exams = [1, 2, 3].map(part => ({
    id: `p${part}-suite`, type: 'reading', category: `P${part}`, title: `Prepared passage ${part}`, hasHtml: true
}));
const manifest = Object.fromEntries(exams.map(exam => [exam.id, { dataKey: exam.id, script: `./${exam.id}.js` }]));
const datasets = Object.fromEntries(exams.map((exam, index) => [exam.id, {
    examId: exam.id, meta: { title: exam.title, category: exam.category },
    passage: { blocks: [{ bodyHtml: `<p>A synthetic passage ${index + 1} for the suite preload regression.</p>`
        + (index === 2 ? '<img src="./suite-image.svg" alt="Prepared illustration">' : '') }] },
    questionOrder: ['q1'], questionGroups: [{ groupId: 'group-1', kind: 'sentence_completion', questionIds: ['q1'],
        bodyHtml: '<label>Answer <input name="q1" type="text"></label>' }],
    answerKey: { q1: `answer-${index + 1}` }
}]));
const host = `<!doctype html><html><body><button id="start">Start suite</button>
<script src="/js/core/practiceCore.js"></script>
<script src="/js/app/examSessionMixin.js"></script>
<script src="/js/app/suitePracticeMixin.js"></script>
<script>
window.examIndex = ${JSON.stringify(exams)};
window.__READING_EXAM_MANIFEST__ = ${JSON.stringify(manifest)};
window.storage = {
    async get(key, fallback) { return JSON.parse(localStorage.getItem(key)) ?? fallback; },
    async set(key, value) { localStorage.setItem(key, JSON.stringify(value)); },
    async writePersistentValue(key, value) { return this.set(key, value); }
};
localStorage.setItem('exam_index', JSON.stringify(examIndex));
window.showMessage = () => {};
window.messages = [];
window.addEventListener('message', event => messages.push(event.data));
window.app = Object.assign({ components: {}, setState() {}, getState() {}, updateExamStatus() {}, refreshOverviewData() {} },
    window.ExamSystemAppMixins.examSession, window.ExamSystemAppMixins.suitePractice);
app.initializeSuiteMode();
document.getElementById('start').onclick = () => app._launchSuiteSessionFromSequence(
    examIndex.map(exam => ({ examId: exam.id, exam })),
    { flowMode: new URLSearchParams(location.search).get('mode') || 'simulation' }
);
</script></body></html>`;
const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'text/javascript;charset=utf-8');
    if (url.pathname === '/host') {
        response.setHeader('Content-Type', 'text/html;charset=utf-8');
        response.end(host);
    } else if (url.pathname.startsWith('/practice/reading/')) {
        response.setHeader('Content-Type', 'text/html;charset=utf-8');
        response.end(fs.readFileSync(path.join(root, 'assets/generated/reading-exams/reading-practice-unified.html'), 'utf8')
            .replace('<head>', '<head><base href="/assets/generated/reading-exams/">'));
    } else if (url.pathname === '/assets/generated/reading-exams/manifest.js') {
        response.end(`window.__READING_EXAM_MANIFEST__ = ${JSON.stringify(manifest)}; window.__READING_EXPLANATION_MANIFEST__ = {};`);
    } else if (/\/p[123]-suite\.js$/.test(url.pathname)) {
        const id = path.basename(url.pathname, '.js');
        response.end(`window.__READING_EXAM_DATA__.register(${JSON.stringify(id)}, ${JSON.stringify(datasets[id])});`);
    } else if (url.pathname.endsWith('/suite-image.svg')) {
        response.setHeader('Content-Type', 'image/svg+xml');
        response.end('<svg xmlns="http://www.w3.org/2000/svg" width="160" height="80"><rect width="160" height="80" fill="#dbeafe"/></svg>');
    } else if (url.pathname.startsWith('/js/')) {
        const target = path.resolve(root, '.' + url.pathname);
        if (target.startsWith(root + path.sep) && fs.existsSync(target)) response.end(fs.readFileSync(target));
        else response.writeHead(404).end();
    } else response.writeHead(404).end();
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({ headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {}) });
    for (const mode of ['simulation', 'classic', 'stationary', 'retry', 'cancel', 'slow'].filter(mode => !process.argv[2] || mode === process.argv[2])) {
        const context = await browser.newContext();
        const errors = [];
        const requests = [];
        context.on('page', page => {
            page.on('pageerror', error => errors.push(error.message));
            page.on('request', request => requests.push({ url: request.url(), type: request.resourceType() }));
            page.setDefaultTimeout(15000);
        });
        let releaseDataset;
        let releaseImage;
        const datasetGate = new Promise(resolve => { releaseDataset = resolve; });
        const imageGate = new Promise(resolve => { releaseImage = resolve; });
        let attempts = 0;
        await context.route('**/p3-suite.js', async route => {
            attempts += 1;
            if (mode === 'retry' && attempts === 1) return route.abort();
            await datasetGate;
            await route.continue();
        });
        await context.route('**/suite-image.svg', async route => {
            await imageGate;
            await route.continue();
        });
        const parent = await context.newPage();
        await parent.goto(`http://127.0.0.1:${server.address().port}/host?mode=${['classic', 'stationary'].includes(mode) ? mode : 'simulation'}`);
        const popupPromise = parent.waitForEvent('popup');
        await parent.locator('#start').click();
        const page = await popupPromise;
        await page.locator('#suite-loading-status').filter({ hasText: '2 / 3' }).waitFor();
        assert.equal(await page.locator('.shell').isVisible(), false, 'questions must stay hidden while any passage is loading');
        assert.deepEqual(await parent.evaluate(() => ({
            status: app.currentSuiteSession.status, anchor: app.currentSuiteSession.globalTimerAnchorMs,
            running: app.currentSuiteSession.suiteTimerRunning,
            ready: messages.filter(message => message.type === 'SESSION_READY').length
        })), { status: 'initializing', anchor: null, running: false, ready: 0 });
        if (mode === 'cancel') {
            assert.equal(await parent.evaluate(() => app._launchSuiteSessionFromSequence(app.currentSuiteSession.sequence)), false,
                'a second launch must not replace a suite that is still loading');
            await page.close();
            releaseDataset();
            releaseImage();
            await parent.waitForFunction(() => app.currentSuiteSession === null);
            assert.deepEqual(await parent.evaluate(() => JSON.parse(localStorage.getItem('practice_records') || '[]')), []);
            console.log('cancel: closing during loading releases the suite without recording an attempt');
            await context.close();
            continue;
        }
        // The parent normally stops its initial handshake after nine seconds.
        await page.waitForTimeout(mode === 'slow' ? 10200 : 1100);
        if (mode === 'retry') {
            await page.locator('#suite-loading-retry').click();
        }
        releaseDataset();
        await page.waitForFunction(() => document.querySelectorAll('#suite-loading-items progress')[2].value === 75);
        assert.equal(await page.locator('.shell').isVisible(), false, 'images must also finish before first display');
        if (process.env.IELTS_SUITE_SCREENSHOT && mode === 'simulation') {
            // document.fonts.ready also waits for the deliberately held image.
            const client = await context.newCDPSession(page);
            const capture = await client.send('Page.captureScreenshot');
            fs.mkdirSync(path.dirname(process.env.IELTS_SUITE_SCREENSHOT), { recursive: true });
            fs.writeFileSync(process.env.IELTS_SUITE_SCREENSHOT, Buffer.from(capture.data, 'base64'));
            await client.detach();
        }
        releaseImage();
        await page.locator('#suite-loading-dialog').waitFor({ state: 'detached' });
        await parent.waitForFunction(() => app.currentSuiteSession.status === 'active');
        const initialTiming = await page.evaluate(() => window.__IELTS_PRACTICE_TIMER__.getSnapshot());
        assert.equal(initialTiming.running, true);
        assert(initialTiming.durationSeconds < 1, 'loading time must not count toward the suite timer');
        const loadedRequests = requests.filter(request => request.type === 'document' || /p[123]-suite\.js/.test(request.url)).length;
        await page.evaluate(() => { window.suiteDocumentMarker = {}; window.firstAnswerNode = document.querySelector('[name=q1]'); });
        await page.locator('[name=q1]').fill('answer-1');
        await page.evaluate(() => {
            const range = document.createRange();
            const text = document.querySelector('#left p').firstChild;
            range.setStart(text, 0);
            range.setEnd(text, 11);
            getSelection().removeAllRanges();
            getSelection().addRange(range);
            document.dispatchEvent(new Event('selectionchange'));
        });
        await page.locator('#btnHL').click();
        assert.equal(await page.locator('#left .hl').textContent(), 'A synthetic');
        await page.locator('#submit-btn').click();
        if (mode === 'stationary') {
            await parent.waitForFunction(() => app.currentSuiteSession.pendingAdvance?.completedExamId === 'p1-suite');
            await page.locator('[data-review-dir=next]').click();
        }
        await page.waitForFunction(() => new URLSearchParams(location.search).get('examId') === 'p2-suite');
        assert.equal(await page.locator('[name=q1]').inputValue(), '', 'answers must stay scoped to each passage');
        assert.equal(await page.evaluate(() => !!window.suiteDocumentMarker), true, 'switches must keep the same document');
        await page.locator('[name=q1]').fill('answer-2');
        if (['simulation', 'retry', 'slow'].includes(mode)) {
            await page.locator('#timer').click();
            await page.locator('#reset-btn').click();
            await page.waitForFunction(() => new URLSearchParams(location.search).get('examId') === 'p1-suite');
            assert.equal(await page.locator('[name=q1]').inputValue(), 'answer-1');
            assert.equal(await page.locator('#left .hl').textContent(), 'A synthetic', 'highlights must survive revisiting a passage');
            assert.equal(await page.evaluate(() => window.__IELTS_PRACTICE_TIMER__.getSnapshot().running), false,
                'switching a passage must preserve a paused timer');
            await page.locator('#timer').click();
            assert.equal(await page.evaluate(() => firstAnswerNode === document.querySelector('[name=q1]')), true,
                'returning to a passage must reuse its prepared DOM');
            await page.locator('#submit-btn').click();
            await page.waitForFunction(() => new URLSearchParams(location.search).get('examId') === 'p2-suite');
            assert.equal(await page.locator('[name=q1]').inputValue(), 'answer-2');
        }
        assert.equal(requests.filter(request => request.type === 'document' || /p[123]-suite\.js/.test(request.url)).length, loadedRequests,
            'switching must not request another document or dataset, even with HTTP caching disabled');
        assert.equal((await page.evaluate(() => window.__IELTS_PRACTICE_TIMER__.getSnapshot())).anchorMs, initialTiming.anchorMs);
        await page.locator('#submit-btn').click();
        if (mode === 'stationary') await page.locator('[data-review-dir=next]').click();
        await page.waitForFunction(() => new URLSearchParams(location.search).get('examId') === 'p3-suite');
        assert.equal(await page.locator('[name=q1]').inputValue(), '');
        await page.locator('[name=q1]').fill('answer-3');
        assert.equal(await page.locator('#left img').evaluate(image => image.complete && image.naturalWidth > 0), true);
        assert.equal(requests.filter(request => request.type === 'document' || /p[123]-suite\.js/.test(request.url)).length, loadedRequests);
        await page.locator('#submit-btn').click();
        if (mode === 'stationary') await page.locator('[data-review-dir=next]').click();
        await parent.waitForFunction(() => app.currentSuiteSession === null);
        const records = await parent.evaluate(() => JSON.parse(localStorage.getItem('practice_records') || '[]'));
        assert.equal(records.length, 1, 'the three passages must still produce one suite record');
        assert.deepEqual(records[0].suiteEntries.map(entry => entry.answers.q1), ['answer-1', 'answer-2', 'answer-3']);
        assert.deepEqual(errors, []);
        console.log(`${mode}: suite loading, image gate, timer and cached passage navigation passed`);
        await context.close();
    }
} finally {
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
}
