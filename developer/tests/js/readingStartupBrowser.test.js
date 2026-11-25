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
const fixtureRoot = path.resolve(process.env.IELTS_READING_FIXTURE_ROOT || root);
const bundle = fs.readFileSync(path.join(fixtureRoot, 'js/bundles/reading-page.bundle.js'));
assert.ok(bundle.length < 400000, 'reading startup must not include the multi-megabyte dictionaries');

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const pathname = decodeURIComponent(url.pathname).replace(/^\/nested(?=\/)/, '');
    const file = path.resolve(fixtureRoot, '.' + pathname);
    if (!file.startsWith(fixtureRoot + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return response.writeHead(404).end();
    }
    const mime = { '.js': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.json': 'application/json' };
    response.setHeader('Content-Type', (mime[path.extname(file)] || 'application/octet-stream') + ';charset=utf-8');
    response.end(fs.readFileSync(file));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
let browser;
const errors = [];

async function openExam(examId) {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${base}/nested/assets/generated/reading-exams/reading-practice-unified.html?examId=${examId}`);
    await page.waitForFunction(() => document.getElementById('left').textContent.trim().length > 100
        && document.querySelector('#question-groups input, #question-groups select'));
    assert.equal(await page.evaluate(() => !!window.__LOCAL_DICTIONARIES__), false);
    assert.equal(await page.evaluate(() => performance.getEntriesByType('resource')
        .filter(entry => entry.name.includes('/wordlists/')).length), 0, 'questions render without dictionary requests');
    await page.evaluate(() => {
        const root = document.getElementById('left');
        for (const term of ['emperor', 'hygienic']) {
            const highlight = document.createElement('span');
            highlight.className = 'hl';
            highlight.id = `test-${term}`;
            highlight.textContent = term;
            root.prepend(highlight);
        }
        window.ReviewHighlightDictionary.enhance({ roots: { left: root }, isEnabled: () => true });
    });
    return page;
}

try {
    browser = await chromium.launch({ headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {}) });
    const page = await openExam('p2-high-120');
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const requests = [];
    await page.route('**/assets/wordlists/*.bundle.js?*', async route => {
        requests.push(route.request().url());
        await gate;
        await route.continue();
    });
    await page.locator('#test-emperor').click();
    const bubble = page.locator('#review-highlight-dictionary-bubble');
    await bubble.getByText('正在加载词典…', { exact: true }).waitFor();
    assert.equal(await bubble.locator('[data-vocab-add]').isDisabled(), true);
    await page.locator('#test-hygienic').click();
    await bubble.getByText('hygienic', { exact: true }).waitFor();
    release();
    await page.waitForFunction(() => document.getElementById('review-highlight-dictionary-bubble').textContent.includes('卫生'));
    assert.equal(requests.length, 2, 'concurrent lookups share the two asset requests');
    assert.ok(requests.every(url => url.startsWith(`${base}/nested/assets/wordlists/`)), 'assets stay on the application origin and prefix');
    assert.equal(await bubble.locator('.vocab-term').textContent(), 'hygienic', 'late results cannot replace the latest selection');
    await page.locator('#test-emperor').click();
    await page.waitForFunction(() => /皇帝|君主/.test(document.getElementById('review-highlight-dictionary-bubble').textContent));
    assert.equal(requests.length, 2, 'later lookups reuse loaded dictionaries');
    await page.close();

    const retryPage = await openExam('p2-high-25');
    let attempts = 0;
    await retryPage.route('**/assets/wordlists/ecdict_reading.bundle.js?*', route => {
        attempts++;
        return attempts === 1 ? route.abort('failed') : route.continue();
    });
    await retryPage.locator('#test-emperor').click();
    const retryBubble = retryPage.locator('#review-highlight-dictionary-bubble');
    await retryBubble.locator('[data-vocab-retry]').waitFor();
    assert.ok((await retryBubble.textContent()).includes('词典加载失败'));
    assert.ok(await retryPage.locator('#question-groups input, #question-groups select').count() > 0);
    await retryBubble.locator('[data-vocab-retry]').click();
    await retryPage.waitForFunction(() => /皇帝|君主/.test(document.getElementById('review-highlight-dictionary-bubble').textContent));
    assert.equal(attempts, 2, 'a failed dictionary request can be retried');
    await retryPage.close();
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'pass', startupBytes: bundle.length,
        exams: ['p2-high-120', 'p2-high-25'], checks: ['no eager dictionaries', 'deferred lookup',
            'shared requests', 'latest selection', 'cached lookup', 'load failure and retry', 'nested deployment paths'] }));
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
