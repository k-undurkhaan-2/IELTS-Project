#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixtures = JSON.parse(fs.readFileSync(path.join(root, 'developer/tests/fixtures/reading-answer-variants.json'), 'utf8'))
    .filter(item => !item.optional || fs.existsSync(path.join(root, `assets/generated/reading-exams/${item.examId}.js`)));
const totals = new Map();
for (const { examId } of fixtures) {
    vm.runInNewContext(fs.readFileSync(path.join(root, `assets/generated/reading-exams/${examId}.js`), 'utf8'), {
        window: { __READING_EXAM_DATA__: { register(id, data) { totals.set(id, data.questionOrder.length); } } }
    });
}
const cases = fixtures.flatMap(fixture => fixture.answers.map(answer => ({ ...fixture, answer, correct: true })));
cases.push(
    { examId: 'p1-low-34', questionId: 'q11', answer: ' FOUR ', correct: true },
    { examId: 'p1-low-34', questionId: 'q11', answer: '5', correct: false },
    { examId: 'p1-medium-119', questionId: 'q9', answer: '6000', correct: false },
    { examId: 'p3-high-161', questionId: 'q8', answer: 'a different camera', correct: false },
    { examId: 'p3-low-187', questionId: 'q10', answer: 'vigorous', correct: false }
);

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname === '/host') {
        const examId = url.searchParams.get('exam');
        if (!totals.has(examId)) return response.writeHead(404).end();
        response.setHeader('Content-Type', 'text/html;charset=utf-8');
        return response.end(`<!doctype html><html><body>
            <script>window.messages = []; addEventListener('message', event => messages.push(event.data));</script>
            <iframe id="practice" style="width:100%;height:850px" src="/assets/generated/reading-exams/reading-practice-unified.html?examId=${examId}"></iframe>
        </body></html>`);
    }
    const file = path.resolve(root, '.' + decodeURIComponent(url.pathname));
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return response.writeHead(404).end();
    }
    const mime = { '.js': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.json': 'application/json' };
    response.setHeader('Content-Type', (mime[path.extname(file)] || 'application/octet-stream') + ';charset=utf-8');
    response.end(fs.readFileSync(file));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({ headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {}) });
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    let completed = 0;
    for (const { examId, questionId, answer, correct } of cases) {
        await page.goto(`http://127.0.0.1:${server.address().port}/host?exam=${examId}`);
        const frame = page.frames().find(frame => frame.url().includes('reading-practice-unified.html'));
        const input = frame.locator(`input[name="${questionId}"]`).first();
        await input.waitFor();
        await page.evaluate(({ examId, sessionId }) => {
            document.getElementById('practice').contentWindow.postMessage({
                type: 'INIT_SESSION', data: { examId, sessionId }
            }, location.origin);
        }, { examId, sessionId: `variants-${completed}` });
        await page.waitForFunction(() => messages.some(message => message.type === 'SESSION_READY'));
        await input.fill(answer);
        await frame.getByRole('button', { name: 'Submit', exact: true }).press('Enter');
        await page.waitForFunction(() => messages.some(message => message.type === 'PRACTICE_COMPLETE'));
        const result = await page.evaluate(() => messages.find(message => message.type === 'PRACTICE_COMPLETE').data);
        assert.equal(result.answerComparison[questionId].isCorrect, correct, `${examId}/${questionId}: ${answer}`);
        assert.equal(result.scoreInfo.correct, correct ? 1 : 0, 'a text alternative earns one mark');
        assert.equal(result.scoreInfo.total, totals.get(examId), 'alternative count does not change exam total');
        assert.ok((await frame.locator('#results').textContent()).includes(answer.trim()), 'result shows submitted text');

        if (examId === 'p1-medium-119' && answer === '60,000') {
            await input.evaluate(input => { input.value = ''; });
            await page.evaluate(result => document.getElementById('practice').contentWindow.postMessage({
                type: 'REPLAY_PRACTICE_RECORD', data: { entry: result }
            }, location.origin), result);
            await input.evaluate(input => new Promise((resolve, reject) => {
                const started = Date.now();
                const timer = setInterval(() => {
                    if (input.value === '60,000') { clearInterval(timer); resolve(); }
                    else if (Date.now() - started > 5000) { clearInterval(timer); reject(new Error('Thousands separator lost in replay')); }
                }, 20);
            }));
        }
        completed++;
        if (completed % 10 === 0) console.log(`PASS: ${completed}/${cases.length} reading text submissions`);
    }
    assert.deepEqual(errors, []);
    console.log(`PASS: ${cases.length} browser submissions, exact scores, displayed answers and numeric replay`);
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
