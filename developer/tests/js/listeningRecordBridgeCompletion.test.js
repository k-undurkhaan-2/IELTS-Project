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
  <main><input name="q1" value="answer"><input name="q2" value="wrong"><div id="results"></div></main>
  <div class="bottom-bar"><span id="timer">00:00</span><button id="finish-btn">Finish</button></div>
  <script>
    // Legacy source templates keep their app in a closure, so completion must
    // work from the rendered review without a window.App method hook.
    (() => {
      const finish = document.getElementById('finish-btn');
      function review() {
        document.getElementById('results').innerHTML = '<table class="results-table"><thead><tr><th>Question</th><th>Your Answer</th><th>Correct Answer</th><th>Result</th></tr></thead><tbody><tr><td>1</td><td>answer</td><td>answer</td><td>Correct</td></tr><tr><td>2</td><td>wrong</td><td>expected</td><td>Incorrect</td></tr></tbody></table>';
        finish.textContent = 'Return to Test';
      }
      finish.addEventListener('click', review);
      document.addEventListener('source-review-ready', review);
      // The wrapper also mutates navigation counters every second. A faster
      // source status update makes starvation deterministic in this fixture.
      setInterval(() => { document.getElementById('timer').textContent = String(Date.now()); }, 100);
    })();
  </script>
</body></html>`;
const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    response.setHeader('Content-Type', 'text/html;charset=utf-8');
    if (url.pathname === '/wrapper') {
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-exam-id=""', 'data-exam-id="listening-p1-completion"')
            .replace('data-source-url=""', 'data-source-url="/fixture"'));
    } else if (url.pathname === '/fixture') response.end(fixture);
    else if (['/js/bundles/listening-wrapper.bundle.js', '/js/bundles/listening-record-bridge.bundle.js'].includes(url.pathname)) {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(path.join(repoRoot, url.pathname.slice(1))));
    } else response.writeHead(404).end();
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
    browser = await chromium.launch({headless: true});
    for (const mode of ['click', 'observer']) {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        try {
            await page.addInitScript(() => {
                window.completions = [];
                window.addEventListener('message', event => {
                    if (event.data?.type === 'PRACTICE_COMPLETE') window.completions.push(event.data.data);
                });
            });
            await page.goto('http://127.0.0.1:' + server.address().port + '/wrapper');
            const frame = await page.locator('iframe').elementHandle().then(element => element.contentFrame());
            await frame.waitForFunction(() => document.querySelector('[data-listening-action=finish]'));
            if (mode === 'click') await frame.locator('[data-listening-action=finish]').click();
            else await frame.evaluate(() => document.dispatchEvent(new Event('source-review-ready')));
            await page.waitForFunction(() => window.completions.length === 1, null, {timeout: 3500});
            await page.waitForTimeout(1600);
            const messages = await page.evaluate(() => window.completions);
            assert.equal(messages.length, 1, mode + ': completion is emitted exactly once');
            assert.equal(messages[0].scoreInfo.total, 2);
            assert.equal(messages[0].scoreInfo.correct, 1);
            assert.equal(messages[0].answers.q1, 'answer');
            assert.equal(messages[0].answers.q2, 'wrong');
            assert.equal(await frame.evaluate(() => window.__listeningBridgeGetState().completed), true);
            assert.deepEqual(errors, []);
            console.log('PASS: ' + mode + ' completion survives continuous source and wrapper updates');
        } finally { await page.close(); }
    }
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
