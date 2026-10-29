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
const fixture = `<!doctype html><html><body>
    <div class="header"></div>
    <main class="main-content"><label>Question 1 <input name="q1" value="answer"></label></main>
    <div class="bottom-bar"><span id="timer">00:00</span><button id="finish-btn">Finish</button></div>
    <script>
        window.ANSWER_KEY = { q1: 'answer' };
        window.App = { state: { isReviewing: false }, config: { answerKey: ANSWER_KEY, questionList: [1] } };
        document.getElementById('finish-btn').addEventListener('click', function () {
            App.state.isReviewing = true;
            this.textContent = 'Submitted';
            this.disabled = true;
        });
    </script>
</body></html>`;

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname === '/host') {
        response.setHeader('Content-Type', 'text/html');
        response.end(`<!doctype html><html><body>
            <iframe id="wrapper" src="/wrapper" style="width:100%;height:700px"></iframe>
            <script>
                window.forwardedCompletions = [];
                window.addEventListener('message', event => {
                    const wrapper = document.getElementById('wrapper');
                    if (event.source !== wrapper.contentWindow || event.data.type !== 'PRACTICE_COMPLETE') return;
                    const timer = wrapper.contentDocument.getElementById('listening-practice-frame').contentDocument.querySelector('[data-wrapper-timer=true]');
                    forwardedCompletions.push({ message: event.data, text: timer.textContent, paused: timer.classList.contains('paused') });
                });
            </script>
        </body></html>`);
    } else if (url.pathname === '/wrapper') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-exam-id=""', 'data-exam-id="listening-p1-timer"')
            .replace('data-source-url=""', 'data-source-url="/fixture"'));
    } else if (url.pathname === '/fixture') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fixture);
    } else if (['/js/bundles/listening-wrapper.bundle.js', '/js/bundles/listening-record-bridge.bundle.js'].includes(url.pathname)) {
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
    const cases = [
        { name: 'elapsed submit', mode: 'elapsed', action: 'click' },
        { name: 'countdown keyboard submit', mode: 'countdown', action: 'keyboard' },
        { name: 'compatibility API completion', mode: 'elapsed', action: 'api' },
        { name: 'countdown auto-submit', mode: 'countdown', action: 'expiry' },
        { name: 'submit while paused', mode: 'elapsed', action: 'click', paused: true }
    ];
    for (const scenario of cases) {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        let now = Date.UTC(2026, 0, 1);
        try {
            await page.clock.setFixedTime(now);
            await page.addInitScript(preferences => {
                localStorage.setItem('ielts_listening_timer_preferences_v1', JSON.stringify(preferences));
            }, { mode: scenario.mode, countdownMinutes: 1, expiryAction: 'auto-submit' });
            await page.goto('http://127.0.0.1:' + server.address().port + '/host');
            const wrapper = page.frames().find(candidate => candidate.url().endsWith('/wrapper'));
            const frame = page.frames().find(candidate => candidate.url().includes('/fixture'));
            await frame.waitForFunction(() => typeof window.__listeningBridgeComplete === 'function');
            await wrapper.evaluate(() => window.dispatchEvent(new MessageEvent('message', {
                origin: location.origin,
                source: parent,
                data: { type: 'INIT_SESSION', data: { examId: 'listening-p1-timer', sessionId: 'timer-session', startTime: Date.now() } }
            })));
            await frame.waitForFunction(() => window.__listeningBridgeGetState().initialized);
            const timer = frame.locator('[data-wrapper-timer=true]');

            // A failed completion and ordinary bridge messages must leave time running.
            assert.equal(await wrapper.evaluate(() => window.__listeningBridgeComplete()), false);
            await frame.evaluate(() => parent.postMessage({ type: 'SESSION_READY', data: {} }, location.origin));
            now += 5000;
            await page.clock.setFixedTime(now);
            const beforeSubmit = scenario.mode === 'countdown' ? '00:55' : '00:05';
            await frame.waitForFunction(text => document.querySelector('[data-wrapper-timer=true]').textContent === text, beforeSubmit);
            assert.equal(await timer.evaluate(node => node.classList.contains('paused')), false);
            if (scenario.paused) {
                await timer.click();
                now += 15000;
                await page.clock.setFixedTime(now);
            }

            if (scenario.action === 'expiry') {
                now += 60000;
                await page.clock.setFixedTime(now);
            } else if (scenario.action === 'api') {
                assert.equal(await wrapper.evaluate(() => window.__listeningBridgeComplete({ allowGenerated: true })), true);
            } else if (scenario.action === 'keyboard') {
                await frame.getByRole('button', { name: 'Submit', exact: true }).press('Enter');
            } else {
                await frame.getByRole('button', { name: 'Submit', exact: true }).click();
            }
            await page.waitForFunction(() => forwardedCompletions.length === 1);
            const completion = await page.evaluate(() => forwardedCompletions[0]);
            assert.equal(completion.paused, true, scenario.name + ': stop the timer before forwarding completion');
            const stoppedText = scenario.action === 'expiry' ? '00:00' : beforeSubmit;
            assert.equal(completion.text, stoppedText);
            assert.equal(completion.message.data.scoreInfo.correct, 1);
            assert.equal(completion.message.data.sessionId, 'timer-session');

            // Several ticks in review and duplicate completion delivery keep the same time.
            now += 120000;
            await page.clock.setFixedTime(now);
            await frame.evaluate(message => parent.postMessage(message, location.origin), completion.message);
            await page.waitForFunction(() => forwardedCompletions.length === 2);
            await page.waitForTimeout(1100);
            assert.equal(await timer.textContent(), stoppedText);
            assert.equal(await timer.evaluate(node => node.classList.contains('paused')), true);

            if (scenario.paused) {
                // The existing manual resume control must exclude all paused/review time.
                await timer.click();
                now += 3000;
                await page.clock.setFixedTime(now);
                await frame.waitForFunction(() => document.querySelector('[data-wrapper-timer=true]').textContent === '00:08');
            }
            assert.deepEqual(errors, []);
            console.log('PASS ' + scenario.name + ': completion forwarding, frozen review time and valid result payload');
        } finally {
            await page.close();
        }
    }
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
