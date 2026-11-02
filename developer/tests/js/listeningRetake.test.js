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
const examId = 'listening-p1-retake';

function host(mode) {
    return `<!doctype html><html><body>
      <iframe id="practice" style="width:100%;height:750px"></iframe>
      <script src="/js/app/examSessionMixin.js"></script>
      <script>
        window.storage = {
          async get(key, fallback) { return JSON.parse(localStorage.getItem(key)) ?? fallback; },
          async set(key, value) { localStorage.setItem(key, JSON.stringify(value)); return true; }
        };
        window.examIndex = [{ id: '${examId}', title: 'Listening retake', type: 'listening', category: 'P1' }];
        window.showMessage = () => {};
        window.messages = [];
        window.addEventListener('message', event => messages.push(event.data));
        window.app = Object.assign({ components: {}, updateExamStatus() {}, showRealCompletionNotification() {}, setState() {} },
          window.ExamSystemAppMixins.examSession);
        // Exercise the real parent protocol and persistence with browser storage.
        // Only presentation is replaced; completion, reset and saving are production code.
        app.updateExamStatus = () => {};
        app.showRealCompletionNotification = () => {};
        const frame = document.getElementById('practice');
        app.setupExamWindowCommunication(frame.contentWindow, '${examId}', examIndex[0]);
        frame.onload = () => app._sendExamInitEnvelope('${examId}', frame.contentWindow);
        frame.src = '/wrapper?mode=${mode}';
      </script>
    </body></html>`;
}

function fixture(mode) {
    return `<!doctype html><html><body>
      <div class="header"></div>
      <main><input name="q1"><input name="q2"><div id="results"></div></main>
      <div class="bottom-bar"><span id="timer">00:00</span>
        ${mode === 'fallback' ? '' : '<button id="clear-btn">Clear</button>'}
        <button id="finish-btn">Finish</button>
      </div>
      <script>
        (() => {
          const finish = document.getElementById('finish-btn');
          const inputs = [...document.querySelectorAll('input')];
          const results = document.getElementById('results');
          finish.onclick = () => {
            results.hidden = false;
            results.innerHTML = '<table class="results-table"><tbody>' + inputs.map((input, index) => {
              const correct = input.value === ['answer', 'expected'][index];
              return '<tr><td>' + (index + 1) + '</td><td>' + input.value + '</td><td>' +
                ['answer', 'expected'][index] + '</td><td>' + (correct ? 'Correct' : 'Incorrect') + '</td></tr>';
            }).join('') + '</tbody></table>';
            finish.textContent = 'Return to Test';
          };
          const reset = document.getElementById('clear-btn');
          if (reset) reset.onclick = () => {
            if (!confirm('Clear all progress?')) return;
            if ('${mode}' === 'reload') { location.reload(); return; }
            inputs.forEach(input => { input.value = ''; });
            if ('${mode}' === 'stale-review') results.hidden = true;
            else results.innerHTML = '';
            finish.textContent = 'Finish';
          };
          setInterval(() => { document.getElementById('timer').textContent = String(Date.now()); }, 100);
        })();
      </script>
    </body></html>`;
}

const scriptPaths = new Set([
    '/js/app/examSessionMixin.js', '/js/bundles/listening-wrapper.bundle.js',
    '/js/bundles/listening-record-bridge.bundle.js'
]);
const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const mode = url.searchParams.get('mode') || 'reload';
    response.setHeader('Content-Type', 'text/html;charset=utf-8');
    if (url.pathname === '/host') response.end(host(mode));
    else if (url.pathname === '/wrapper') {
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-exam-id=""', 'data-exam-id="' + examId + '"')
            .replace('data-source-url=""', 'data-source-url="/fixture?mode=' + mode + '"'));
    } else if (url.pathname === '/fixture') response.end(fixture(mode));
    else if (scriptPaths.has(url.pathname)) {
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
    const scenarios = ['reload', 'in-place', 'stale-review', 'fallback'].map(mode => ({ mode, countdown: false }));
    scenarios.push({ mode: 'reload', countdown: true });
    for (const { mode, countdown } of scenarios) {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        let now = Date.UTC(2026, 0, 1);
        try {
            await page.clock.setFixedTime(now);
            if (countdown) await page.addInitScript(() => localStorage.setItem('ielts_listening_timer_preferences_v1', JSON.stringify({
                mode: 'countdown', countdownMinutes: 1, expiryAction: 'auto-submit'
            })));
            await page.goto('http://127.0.0.1:' + server.address().port + '/host?mode=' + mode);
            const sourceFrame = () => page.frames().find(frame => frame.url().includes('/fixture'));
            await page.waitForFunction(() => document.getElementById('practice').contentWindow.__listeningBridgeGetState?.().initialized);
            let frame = sourceFrame();
            await frame.locator('[name=q1]').fill('answer');
            await frame.locator('[name=q2]').fill('wrong');
            now += countdown ? 60000 : 5000;
            await page.clock.setFixedTime(now);
            if (!countdown) await frame.getByRole('button', { name: 'Submit', exact: true }).click();
            await page.waitForFunction(() => JSON.parse(localStorage.getItem('practice_records') || '[]').length === 1);
            const first = await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records'))[0]);
            const firstCompletion = await page.evaluate(() => messages.find(message => message.type === 'PRACTICE_COMPLETE'));
            assert.equal(first.scoreInfo.correct, 1);
            assert.equal(await page.evaluate(id => app.messageHandlers.has(id), examId), true,
                mode + ': completion must retain the parent message handler for Reset');

            if (mode !== 'fallback') {
                page.once('dialog', dialog => dialog.dismiss());
                await frame.getByRole('button', { name: 'Reset', exact: true }).click();
                await page.waitForTimeout(200);
                assert.equal(await frame.evaluate(() => window.__listeningBridgeGetState().sessionId), first.sessionId,
                    'cancelling Reset must keep the existing attempt');
                assert.equal(await frame.locator('#listening-wrapper-result-summary').count(), 1);
                page.once('dialog', dialog => dialog.accept());
            }

            now += 120000;
            await page.clock.setFixedTime(now);
            await frame.getByRole('button', { name: 'Reset', exact: true }).click();
            await page.waitForFunction(previousId => {
                const state = document.getElementById('practice').contentWindow.__listeningBridgeGetState?.();
                return state?.initialized && state.sessionId !== previousId && !state.completed;
            }, first.sessionId, { timeout: 5000 });
            frame = sourceFrame();
            await frame.waitForFunction(text => document.querySelector('[data-wrapper-timer=true]')?.textContent === text,
                countdown ? '01:00' : '00:00');
            assert.equal(await frame.locator('#listening-wrapper-result-summary').count(), 0);
            assert.equal(await frame.getByRole('button', { name: 'Notes', exact: true }).isVisible(), true);
            assert.equal(await frame.getByRole('button', { name: 'Exit', exact: true }).isVisible(), false);
            // Previously completed sessions cannot write records or reset the new attempt.
            const wrapper = page.frames().find(candidate => candidate.url().includes('/wrapper'));
            const resetSessionId = await frame.evaluate(() => window.__listeningBridgeGetState().sessionId);
            await wrapper.evaluate(message => {
                parent.postMessage(message, location.origin);
                parent.postMessage({ ...message, type: 'PRACTICE_RESET_REQUEST' }, location.origin);
            }, firstCompletion);
            await frame.evaluate(message => parent.postMessage(message, location.origin), firstCompletion);
            await page.waitForTimeout(1800);
            assert.equal(await frame.evaluate(() => window.__listeningBridgeGetState().sessionId), resetSessionId);
            assert.equal(await frame.locator('#listening-wrapper-result-summary').count(), 0,
                'a delayed completion from the old attempt must not restore its score or stop the new clock');
            assert.equal(await frame.locator('[data-wrapper-timer=true]').evaluate(timer => timer.classList.contains('paused')), false);
            assert.equal(await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records')).length), 1,
                'Reset and stale review DOM must not save an unsubmitted attempt');

            await frame.locator('[name=q1]').fill('answer');
            await frame.locator('[name=q2]').fill('expected');
            now += countdown ? 60000 : 3000;
            await page.clock.setFixedTime(now);
            if (!countdown) await frame.getByRole('button', { name: 'Submit', exact: true }).press('Enter');
            await page.waitForFunction(() => JSON.parse(localStorage.getItem('practice_records') || '[]').length === 2);
            await page.evaluate(id => app._sendExamInitEnvelope(id, document.getElementById('practice').contentWindow), examId);
            await frame.evaluate(() => { window.__listeningBridgeComplete({ allowGenerated: true }); });
            await page.waitForTimeout(1600);
            const records = await page.evaluate(() => JSON.parse(localStorage.getItem('practice_records')));
            assert.equal(records.length, 2, 'duplicate submit must not add a third record');
            assert.notEqual(records[0].sessionId, records[1].sessionId);
            assert.notEqual(records[0].id, records[1].id);
            assert.deepEqual(records[1].answers, { q1: 'answer', q2: 'wrong' }, 'first attempt stays intact');
            assert.deepEqual(records[0].answers, { q1: 'answer', q2: 'expected' });
            assert.equal(records[0].scoreInfo.correct, 2);
            assert.equal(records[0].realData.duration, countdown ? 60 : 3, 'retake excludes the previous attempt and review time');
            assert.deepEqual(errors, []);
            console.log('PASS: ' + mode + (countdown ? ' countdown auto-submit' : '') + ' Reset saves a separate listening attempt with fresh answers and timing');
        } catch (error) {
            console.error({ mode, errors, messages: await page.evaluate(() => window.messages?.slice(-5)) });
            throw error;
        } finally { await page.close(); }
    }
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
