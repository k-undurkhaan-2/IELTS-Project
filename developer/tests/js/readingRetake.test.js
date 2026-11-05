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
const examId = 'p1-reading-retake';
const dataset = {
    examId,
    meta: { title: 'Reading retake', category: 'P1', frequency: 'high' },
    passage: { blocks: [{ bodyHtml: '<p>A short synthetic passage for the retake regression.</p>' }] },
    questionOrder: ['q1', 'q2'],
    questionGroups: [{
        groupId: 'group-1', kind: 'sentence_completion', questionIds: ['q1', 'q2'],
        bodyHtml: '<label>Question 1 <input type="text" name="q1"></label><label>Question 2 <input type="text" name="q2"></label>'
    }],
    answerKey: { q1: 'answer', q2: 'expected' }
};

const host = `<!doctype html><html><body>
    <iframe id="practice" style="width:100%;height:750px"></iframe>
    <script src="/js/core/practiceCore.js"></script>
    <script src="/js/app/examSessionMixin.js"></script>
    <script>
        window.storage = {
            async get(key, fallback) { return JSON.parse(localStorage.getItem(key)) ?? fallback; },
            async set(key, value) { localStorage.setItem(key, JSON.stringify(value)); return true; },
            async writePersistentValue(key, value) { return this.set(key, value); }
        };
        window.examIndex = [{ id: '${examId}', title: 'Reading retake', type: 'reading', category: 'P1' }];
        window.showMessage = () => {};
        window.messages = [];
        window.addEventListener('message', event => messages.push(event.data));
        window.app = Object.assign({ components: {}, setState() {} }, window.ExamSystemAppMixins.examSession);
        // Keep the real parent protocol and persistence; replace only presentation.
        app.updateExamStatus = () => {};
        app.showRealCompletionNotification = () => {};
        const frame = document.getElementById('practice');
        app.setupExamWindowCommunication(frame.contentWindow, '${examId}', examIndex[0]);
        frame.onload = () => app.restartExamHandshake(frame.contentWindow, '${examId}');
        frame.src = '/reading?examId=${examId}';
    </script>
</body></html>`;

const scriptPaths = new Set(['/js/core/practiceCore.js', '/js/app/examSessionMixin.js', '/js/bundles/reading-page.bundle.js']);
const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    response.setHeader('Content-Type', 'text/html;charset=utf-8');
    if (url.pathname === '/host') response.end(host);
    else if (url.pathname === '/reading') {
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/reading-exams/reading-practice-unified.html'), 'utf8')
            .replace('<script src="./manifest.js"></script>', `<script>
                window.__READING_EXAM_MANIFEST__ = { '${examId}': { dataKey: '${examId}' } };
                window.__READING_EXPLANATION_MANIFEST__ = {};
            </script>`)
            .replace('</body>', `<script>window.__READING_EXAM_DATA__.register('${examId}', ${JSON.stringify(dataset)});</script></body>`));
    } else if (scriptPaths.has(url.pathname)) {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(path.join(repoRoot, url.pathname.slice(1))));
    } else response.writeHead(404).end();
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({
        headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {})
    });
    const scenarios = [
        { name: 'return', retake: 'Return to test' },
        { name: 'countdown', retake: 'Return to test', countdown: true },
        { name: 'reset', retake: 'Reset' }
    ];
    for (const { name, retake, countdown } of scenarios.filter(scenario => !process.argv[2] || scenario.name === process.argv[2])) {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        page.setDefaultTimeout(8000);
        let now = Date.UTC(2026, 0, 1);
        let releaseExplanation;
        try {
            if (name === 'return') {
                await page.addInitScript(() => window.addEventListener('message', event => {
                    if (window.holdRestartInit && /^(?:INIT_SESSION|init_exam_session)$/.test(event.data?.type)
                        && event.data.data?.sessionId !== window.previousSessionId) event.stopImmediatePropagation();
                }, true));
                const explanationGate = new Promise(resolve => { releaseExplanation = resolve; });
                await page.route('**/explanation.js', async route => {
                    await explanationGate;
                    await route.fulfill({ contentType: 'text/javascript', body: '/* Synthetic exam has no explanations. */' });
                });
            }
            await page.clock.setFixedTime(now);
            if (countdown) await page.addInitScript(() => localStorage.setItem('ielts_reading_timer_preferences_v2', JSON.stringify({
                mode: 'countdown', countdownMinutes: 1, expiryAction: 'auto-submit'
            })));
            await page.goto('http://127.0.0.1:' + server.address().port + '/host');
            await page.waitForFunction(() => messages.some(message => message.type === 'SESSION_READY'));
            const frame = page.frames().find(candidate => candidate.url().includes('/reading?'));
            if (name === 'return') await frame.evaluate(id => {
                window.__READING_EXPLANATION_MANIFEST__ = { [id]: { dataKey: id, script: '/explanation.js' } };
            }, examId);
            await frame.locator('[name=q1]').fill('answer');
            await frame.locator('[name=q2]').fill('wrong');

            let previous = [];
            for (let attempt = 0; attempt < 3; attempt++) {
                now += countdown ? 60000 : 3000;
                await page.clock.setFixedTime(now);
                if (!countdown) await frame.getByRole('button', { name: 'Submit', exact: true }).press('Enter');
                await page.waitForFunction(count => JSON.parse(localStorage.getItem('practice_records') || '[]').length === count, attempt + 1);
                const records = await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records')));
                const record = records[0];
                const completion = await page.evaluate(() => messages.filter(message => message.type === 'PRACTICE_COMPLETE').at(-1));
                assert.deepEqual(records.slice(1), previous, 'previous attempts stay intact');
                assert.equal(new Set(records.map(entry => entry.sessionId)).size, attempt + 1);
                assert.equal(new Set(records.map(entry => entry.id)).size, attempt + 1);
                assert.deepEqual(record.realData.answers, { q1: 'answer', q2: attempt ? 'expected' : 'wrong' });
                assert.equal(record.scoreInfo.correct, attempt ? 2 : 1);
                assert.equal(record.realData.duration, countdown ? 60 : 3, 'retake timing excludes earlier attempts and review');

                await frame.evaluate(message => parent.postMessage(message, location.origin), completion);
                await page.waitForTimeout(200);
                assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records'))), records,
                    'duplicate completion must not append or overwrite a record');
                previous = records;
                if (attempt === 2) break;

                now += 120000;
                await page.clock.setFixedTime(now);
                if (name === 'return') await frame.evaluate(previousId => {
                    window.previousSessionId = previousId;
                    window.holdRestartInit = true;
                }, record.sessionId);
                await frame.getByRole('button', { name: retake, exact: true }).click();
                if (name === 'return') {
                    await page.waitForFunction(previousId => app.examWindows.get('p1-reading-retake').expectedSessionId !== previousId,
                        record.sessionId);
                    await page.evaluate(previousId => document.getElementById('practice').contentWindow.postMessage({
                        type: 'INIT_SESSION', data: { examId: 'p1-reading-retake', sessionId: previousId }
                    }, location.origin), record.sessionId);
                    await page.waitForTimeout(100);
                    assert.equal(await frame.getByRole('button', { name: 'Submit', exact: true }).isDisabled(), true,
                        'a stale handshake must not allow submission under the completed session');
                    await frame.evaluate(() => { window.holdRestartInit = false; });
                    await page.evaluate(() => {
                        app._sendExamInitEnvelope('p1-reading-retake', document.getElementById('practice').contentWindow);
                    });
                }
                await page.waitForFunction(previousId => messages.some(message => message.type === 'SESSION_READY'
                    && message.data.sessionId && message.data.sessionId !== previousId
                    && message.data.sessionId === app.examWindows.get('p1-reading-retake').expectedSessionId), record.sessionId);
                assert.equal(await frame.locator('[name=q1]').inputValue(), retake === 'Reset' ? '' : 'answer');
                assert.equal(await frame.locator('[name=q2]').inputValue(), retake === 'Reset' ? '' : record.realData.answers.q2);
                await frame.waitForFunction(text => document.getElementById('timer').textContent === text, countdown ? '01:00' : '00:00');

                await frame.evaluate(message => {
                    parent.postMessage(message, location.origin);
                    parent.postMessage({ ...message, type: 'PRACTICE_RESET_REQUEST' }, location.origin);
                }, completion);
                await page.waitForTimeout(200);
                assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records'))), records,
                    'returning to the test and old messages must not save an unsubmitted attempt');
                await frame.locator('[name=q1]').fill('answer');
                await frame.locator('[name=q2]').fill('expected');
            }
            if (releaseExplanation) {
                const loaded = page.waitForResponse('**/explanation.js');
                releaseExplanation();
                await loaded;
                await page.waitForTimeout(100);
                assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records'))), previous,
                    'delayed explanations must not publish an old result under a newer session');
            }
            assert.deepEqual(errors, []);
            console.log('PASS: reading ' + name + ' preserves three distinct attempts, answers, timing and deduplication');
        } catch (error) {
            console.error({ name, errors, messages: await page.evaluate(() => window.messages?.slice(-5)) });
            throw error;
        } finally {
            releaseExplanation?.();
            await page.close();
        }
    }
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
