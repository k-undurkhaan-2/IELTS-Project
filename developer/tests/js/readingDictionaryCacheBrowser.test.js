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
const dictionaryRequests = [];
const errors = [];
const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const pathname = decodeURIComponent(url.pathname).replace(/^\/nested(?=\/)/, '');
    const file = path.resolve(root, '.' + pathname);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return response.writeHead(404).end();
    }
    const mime = { '.js': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.json': 'application/json' };
    response.setHeader('Content-Type', (mime[path.extname(file)] || 'application/octet-stream') + ';charset=utf-8');
    // Prove application caching works even when the HTTP cache cannot help.
    response.setHeader('Cache-Control', 'no-store');
    response.end(fs.readFileSync(file));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}/nested`;
const examUrl = `${base}/assets/generated/reading-exams/reading-practice-unified.html?examId=p2-high-120`;
let browser;

function observe(page) {
    page.setDefaultTimeout(15000);
    page.on('pageerror', error => errors.push(error.message));
}

async function readyExam(page) {
    await page.waitForFunction(() => document.getElementById('left')?.textContent.trim().length > 100
        && document.querySelector('#question-groups input, #question-groups select'));
}

async function lookup(page) {
    return page.evaluate(async () => {
        await window.ReadingDictionaryAssets.ensureLoaded();
        return window.ReadingDictionaryAssets.getService().lookup('emperor');
    });
}

async function openExam(context) {
    const page = await context.newPage();
    observe(page);
    await page.goto(examUrl);
    await readyExam(page);
    return page;
}

async function alterCachedECDICT(page, field, value) {
    await page.evaluate(async ({ field, value }) => {
        await new Promise((resolve, reject) => {
            const request = indexedDB.open('ielts-reading-dictionaries', 1);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                const db = request.result;
                const transaction = db.transaction('dictionaries', 'readwrite');
                const store = transaction.objectStore('dictionaries');
                const key = new URL('../../wordlists/ecdict_reading.bundle.js', location.href).href;
                const read = store.get(key);
                read.onsuccess = () => store.put({ ...read.result, [field]: value }, key);
                transaction.oncomplete = () => { db.close(); resolve(); };
                transaction.onerror = () => { db.close(); reject(transaction.error); };
            };
        });
    }, { field, value });
}

try {
    browser = await chromium.launch({ headless: true,
        ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {}) });
    const context = await browser.newContext();
    context.on('page', observe);
    let release;
    let blocked = false;
    const gate = new Promise(resolve => { release = resolve; });
    await context.route('**/assets/wordlists/*.bundle.js?*', async route => {
        dictionaryRequests.push(route.request().url());
        await gate;
        return blocked ? route.abort('failed') : route.continue();
    });
    const main = await context.newPage();
    await main.goto(`${base}/index.html`);
    await main.waitForFunction(() => !!window.AppEntry && !!window.ReadingDictionaryAssets);
    await main.waitForFunction(() => document.querySelectorAll('script[src*="/wordlists/"]').length === 2);
    assert.equal(await main.evaluate(() => ReadingDictionaryAssets.isReady()), false);

    // A delayed preload cannot hold up either a popup or an embedded exam.
    const popupPromise = context.waitForEvent('page');
    await main.evaluate(url => { window.open(url, '_blank'); }, examUrl);
    const popup = await popupPromise;
    await readyExam(popup);
    await main.evaluate(url => {
        const iframe = document.createElement('iframe');
        iframe.id = 'dictionary-cache-frame';
        iframe.src = url;
        document.body.appendChild(iframe);
    }, examUrl);
    const frameElement = await main.locator('#dictionary-cache-frame').elementHandle();
    const frame = await frameElement.contentFrame();
    await readyExam(frame);
    const pendingPopup = lookup(popup);
    const pendingFrame = lookup(frame);
    release();
    for (const result of await Promise.all([pendingPopup, pendingFrame])) {
        assert.match(result.zh, /皇帝|君主/);
    }
    await main.evaluate(() => ReadingDictionaryAssets.preload());
    assert.equal(dictionaryRequests.length, 2, 'shell, popup, and iframe share the downloads');
    assert.equal(await popup.evaluate(() => ReadingDictionaryAssets.getService() === opener.DictionaryService), true);
    assert.equal(await frame.evaluate(() => ReadingDictionaryAssets.getService() === parent.DictionaryService), true);
    assert.ok(dictionaryRequests.every(url => url.startsWith(`${base}/assets/wordlists/`) && /v=[a-f0-9]{64}$/.test(url)));
    await main.close();
    assert.match((await lookup(popup)).zh, /皇帝|君主/, 'a loaded popup survives its opener closing');
    await popup.close();

    // A new page with no opener restores the persisted payloads while requests
    // to the dictionary origin are deliberately blocked.
    blocked = true;
    const cached = await openExam(context);
    assert.match((await lookup(cached)).zh, /皇帝|君主/);
    await cached.reload();
    await readyExam(cached);
    assert.match((await lookup(cached)).zh, /皇帝|君主/);
    assert.equal(dictionaryRequests.length, 2, 'independent pages and reloads use IndexedDB without downloading');

    blocked = false;
    await alterCachedECDICT(cached, 'version', 'stale-version');
    const refreshed = await openExam(context);
    assert.match((await lookup(refreshed)).zh, /皇帝|君主/);
    assert.equal(dictionaryRequests.length, 3, 'only an outdated dictionary is downloaded again');
    await alterCachedECDICT(refreshed, 'value', { entries: [] });
    const repaired = await openExam(context);
    assert.match((await lookup(repaired)).zh, /皇帝|君主/);
    assert.equal(dictionaryRequests.length, 4, 'invalid cached data is replaced');
    await context.close();

    const concurrentContext = await browser.newContext();
    let concurrentRequests = 0;
    await concurrentContext.route('**/assets/wordlists/*.bundle.js?*', route => {
        concurrentRequests++;
        return route.continue();
    });
    const pages = await Promise.all([openExam(concurrentContext), openExam(concurrentContext)]);
    for (const result of await Promise.all(pages.map(lookup))) assert.equal(result.found, true);
    assert.equal(concurrentRequests, 2, 'unrelated tabs coordinate cold-cache downloads through Web Locks');
    await concurrentContext.close();

    const orphanContext = await browser.newContext();
    const ownerPage = await orphanContext.newPage();
    let ownerDownloads = 0;
    let releaseOwner;
    const ownerGate = new Promise(resolve => { releaseOwner = resolve; });
    await orphanContext.route('**/assets/wordlists/*.bundle.js?*', async route => {
        if (route.request().frame().page() === ownerPage) {
            ownerDownloads++;
            await ownerGate;
            await route.abort().catch(() => {});
        } else {
            await route.continue();
        }
    });
    await ownerPage.goto(`${base}/index.html`);
    await ownerPage.waitForFunction(() => document.querySelectorAll('script[src*="/wordlists/"]').length === 2);
    const orphanPromise = orphanContext.waitForEvent('page');
    await ownerPage.evaluate(url => { window.open(url, '_blank'); }, examUrl);
    const orphan = await orphanPromise;
    observe(orphan);
    await readyExam(orphan);
    await orphan.evaluate(() => {
        window.pendingDictionary = ReadingDictionaryAssets.ensureLoaded();
    });
    await ownerPage.close();
    releaseOwner();
    await orphan.waitForFunction(() => ReadingDictionaryAssets.isReady());
    assert.match((await lookup(orphan)).zh, /皇帝|君主/);
    assert.equal(ownerDownloads, 2, 'the opener was closed while both downloads were pending');
    await orphanContext.close();

    // Storage denial and quota failures must not disable on-demand lookup.
    for (const failure of ['denied', 'quota', 'blocked']) {
        const fallbackContext = await browser.newContext();
        await fallbackContext.addInitScript(mode => {
            if (mode === 'denied') {
                Object.defineProperty(window, 'indexedDB', { get() { throw new DOMException('Denied', 'SecurityError'); } });
            } else if (mode === 'quota') {
                IDBObjectStore.prototype.put = () => { throw new DOMException('Full', 'QuotaExceededError'); };
            } else {
                Object.defineProperty(window, 'indexedDB', { value: { open() { return {}; } } });
            }
        }, failure);
        const fallbackPage = await openExam(fallbackContext);
        assert.match((await lookup(fallbackPage)).zh, /皇帝|君主/);
        await fallbackContext.close();
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'pass', checks: ['shell preload', 'nonblocking exam startup',
        'shared parent/popup/frame memory and index', 'persistent cache', 'reload with dictionary network blocked',
        'version invalidation', 'corrupt cache recovery', 'concurrent independent tabs', 'opener closed during preload',
        'storage denial/quota/timeout fallback', 'nested deployment paths'] }));
} finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
}
