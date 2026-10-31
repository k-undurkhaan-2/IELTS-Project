#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const { chromium } = createRequire(import.meta.url)('playwright');
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const workerPath = '/js/bundles/listening-audio-cache-worker.bundle.js';
const vipBridgePath = '/ListeningPractice/vip%20special/js/bundles/listening-record-bridge.bundle.js';
const cases = new Map();
let nextCase = 0;

function recording(seconds) {
    const wav = Buffer.alloc(44 + seconds * 8000 * 2);
    wav.write('RIFF');
    wav.writeUInt32LE(wav.length - 8, 4);
    wav.write('WAVEfmt ', 8);
    wav.writeUInt32LE(16, 16);
    wav.writeUInt16LE(1, 20);
    wav.writeUInt16LE(1, 22);
    wav.writeUInt32LE(8000, 24);
    wav.writeUInt32LE(16000, 28);
    wav.writeUInt16LE(2, 32);
    wav.writeUInt16LE(16, 34);
    wav.write('data', 36);
    wav.writeUInt32LE(wav.length - 44, 40);
    return wav;
}
const wav = recording(120);
const shortWav = recording(60);

function fixture(id, options) {
    return `<!doctype html><html><head><style>
      .progress-container { width:400px;height:24px;background:#ddd;margin:12px }
      .progress-bar { height:24px;background:#38f;width:0 }
    </style></head><body><input name="q1" aria-label="Answer">
    ${Array.from({ length: options.count || 1 }, (_, index) => `<section id="player${index}">
      <button class="play-pause-btn">Play</button><div class="progress-container"><div class="progress-bar"></div></div>
      <span class="time-display"></span>
      ${options.children ? `<audio preload="metadata"><source src="/media/audio.wav?case=${id}" type="audio/wav"></audio>`
        : `<audio src="/media/audio.wav?case=${id}" preload="metadata"></audio>`}
    </section>`).join('')}
    <script src="${options.vip ? vipBridgePath : '/js/bundles/listening-record-bridge.bundle.js'}" defer></script></body></html>`;
}

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const state = cases.get(url.searchParams.get('case'));
    if (url.pathname === '/fixture' && state) {
        // Exercise the service's actual boundary: raw listening pages cannot
        // fetch, but can run a self-hosted worker and play local blob media.
        response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; worker-src 'self'; media-src 'self' "
            + (state.options.blockBlob ? '' : 'blob:') + "; sandbox allow-scripts allow-same-origin allow-modals");
        response.setHeader('Set-Cookie', 'audio-cache-test=allowed; SameSite=Strict; Path=/');
        response.setHeader('Content-Type', 'text/html');
        response.end(fixture(url.searchParams.get('case'), state.options));
        return;
    }
    if (url.pathname.startsWith('/js/bundles/') || url.pathname === vipBridgePath) {
        const file = path.join(repoRoot, decodeURIComponent(url.pathname));
        if (!fs.existsSync(file)) { response.writeHead(404).end(); return; }
        response.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self'");
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(file));
        return;
    }
    if (url.pathname.startsWith('/media/') && state) {
        state.requests.push({ pathname: url.pathname, range: request.headers.range, cookie: request.headers.cookie });
        const bytes = url.pathname.endsWith('/new.wav') ? shortWav : wav;
        const range = /^bytes=(\d+)-(\d*)$/.exec(request.headers.range || '');
        if (!range) {
            state.fullRequests++;
            if (state.options.failure === 'http') { response.writeHead(503).end(); return; }
            if (state.options.failure === 'partial') {
                response.writeHead(206, { 'Content-Type': 'audio/wav', 'Content-Range': `bytes 0-43/${bytes.length}` }).end(bytes.subarray(0, 44));
                return;
            }
            if (state.options.failure === 'html') { response.writeHead(200, { 'Content-Type': 'text/html' }).end('<title>Login</title>'); return; }
            if (state.options.failure === 'redirect') { response.writeHead(302, { Location: '/media/redirect.wav?case=' + url.searchParams.get('case') }).end(); return; }
            if (state.options.failure === 'empty') { response.writeHead(200, { 'Content-Type': 'audio/wav' }).end(); return; }
            if (state.options.failure === 'oversized' || state.options.failure === 'truncated') {
                response.writeHead(200, { 'Content-Type': 'audio/wav', 'Content-Length': state.options.failure === 'oversized' ? 101 * 1024 * 1024 : bytes.length }).end(bytes.subarray(0, 44));
                return;
            }
            assert.match(request.headers.cookie || '', /audio-cache-test=allowed/, 'full downloads must retain same-origin session credentials');
            response.writeHead(200, { 'Content-Type': 'audio/wav', 'Content-Length': bytes.length, 'Cache-Control': 'no-store' });
            const prefix = 44 + 256 * 1024;
            response.write(bytes.subarray(0, prefix));
            const transfer = { response, pathname: url.pathname, completed: false, cancelled: false, finish() {
                if (!response.destroyed) { this.completed = true; response.end(bytes.subarray(prefix)); }
            } };
            state.transfers.push(transfer);
            response.on('close', () => { transfer.cancelled = !transfer.completed; });
            return;
        }
        const start = Number(range[1]);
        const end = range[2] ? Math.min(Number(range[2]), bytes.length - 1) : bytes.length - 1;
        response.writeHead(206, { 'Content-Type': 'audio/wav', 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1,
            'Content-Range': `bytes ${start}-${end}/${bytes.length}`, 'Cache-Control': 'no-store' });
        response.end(bytes.subarray(start, end + 1));
        return;
    }
    response.writeHead(404).end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true,
    ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {}) });

async function until(predicate, message) {
    const deadline = Date.now() + 5000;
    while (!predicate() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
    assert(predicate(), message);
}

async function open(options = {}) {
    const id = String(++nextCase);
    const state = { options, requests: [], fullRequests: 0, transfers: [] };
    cases.set(id, state);
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => {
        window.revokedAudioUrls = [];
        const revoke = URL.revokeObjectURL.bind(URL);
        URL.revokeObjectURL = url => { revokedAudioUrls.push(url); revoke(url); };
    });
    if (options.workerFailure) await context.route('**' + workerPath, route => route.fulfill({ status: 503, body: '' }));
    await page.goto(`${baseUrl}/fixture?case=${id}`);
    await page.waitForFunction(() => document.querySelector('audio').duration === 120);
    return { id, state, context, page, errors, close: async () => { await context.close(); assert.deepEqual(errors, []); } };
}

async function cached(page, selector = 'audio', duration = 120) {
    await page.waitForFunction(({ selector, duration }) => [...document.querySelectorAll(selector)].every(audio =>
        audio.src.startsWith('blob:') && audio.duration === duration && !audio.seeking), { selector, duration }, { timeout: 5000 });
}

async function fullCacheBeforePlay(vip = false) {
    const test = await open({ count: 2, vip });
    try {
        const { page, state, context } = test;
        await until(() => state.transfers.length === 1, 'question loading must start one complete download before Play');
        assert.deepEqual(await page.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.paused)), [true, true]);
        await page.getByRole('textbox', { name: 'Answer' }).fill('still usable while downloading');
        state.transfers[0].finish();
        await cached(page);
        const sources = await page.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.src));
        assert.equal(sources[0], sources[1], 'players sharing a recording must reuse its complete cache');
        assert.equal(state.fullRequests, 1);
        const requests = state.requests.length;
        await context.setOffline(true);
        await page.locator('#player0 button').click();
        await page.waitForFunction(() => !document.querySelector('audio').paused && document.querySelector('audio').currentTime > 0);
        await page.locator('audio').first().evaluate(audio => { audio.currentTime = 110; });
        await page.waitForFunction(() => !document.querySelector('audio').seeking && document.querySelector('audio').currentTime >= 110);
        assert.equal(state.requests.length, requests, 'cached playback and late seeking must not need the network');
        await page.locator('#player0').evaluate(node => node.remove());
        assert.equal(await page.evaluate(() => revokedAudioUrls.length), 0, 'retain cache while another player uses it');
        await page.locator('#player1').evaluate(node => node.remove());
        await page.waitForFunction(url => revokedAudioUrls.includes(url), sources[0]);
        console.log('PASS ' + (vip ? 'VIP ' : '') + 'full cache: eager download, credentials, deduplication, offline playback/seeking and final-consumer cleanup');
    } finally { await test.close(); }
}

async function preservePlaybackAndScrubbing(dragging) {
    const test = await open();
    try {
        const { page, state } = test;
        await until(() => state.transfers.length === 1, 'full download must start');
        await page.locator('audio').evaluate(audio => { audio.playbackRate = 1.5; audio.volume = 0.25; audio.muted = true; });
        const rect = await page.locator('.progress-container').boundingBox();
        if (dragging) {
            await page.mouse.move(rect.x + rect.width * 0.2, rect.y + 12);
            await page.mouse.down();
        } else {
            await page.locator('.play-pause-btn').click();
            await page.waitForFunction(() => document.querySelector('audio').currentTime > 0.1);
        }
        state.transfers[0].finish();
        await page.waitForFunction(() => document.querySelector('audio').dataset.listeningCache === 'ready');
        assert.equal(await page.locator('audio').evaluate(audio => audio.src.startsWith('blob:')), false, 'cache completion must not reload active playback or a drag');
        let position;
        if (dragging) {
            await page.mouse.move(rect.x + rect.width * 0.7, rect.y + 12, { steps: 8 });
            position = 84;
            await page.mouse.up();
        } else {
            position = await page.locator('audio').evaluate(audio => audio.currentTime);
            assert.equal(await page.locator('audio').evaluate(audio => audio.paused), false);
            await page.locator('.play-pause-btn').click();
        }
        await cached(page);
        const result = await page.locator('audio').evaluate(audio => ({ time: audio.currentTime, paused: audio.paused,
            rate: audio.playbackRate, volume: audio.volume, muted: audio.muted }));
        assert(Math.abs(result.time - position) < 1, 'cache adoption must retain the current/committed time');
        assert.equal(result.paused, true);
        assert.equal(result.rate, 1.5);
        assert.equal(result.volume, 0.25);
        assert.equal(result.muted, true);
        console.log('PASS ' + (dragging ? 'active drag' : 'active playback') + ': deferred cache adoption preserves position, pause, speed, volume and mute');
    } finally { await test.close(); }
}

async function sourceLifecycle(children) {
    const test = await open({ children });
    try {
        const { page, state, id } = test;
        await until(() => state.transfers.length === 1, 'initial download must start');
        if (children) {
            state.transfers[0].finish();
            await cached(page);
        }
        await page.evaluate(({ children, id }) => {
            const audio = document.querySelector('audio');
            const src = '/media/new.wav?case=' + id;
            if (children) audio.querySelector('source').src = src;
            else audio.src = src;
            audio.load();
        }, { children, id });
        await until(() => state.transfers.length === 2, 'new source must get its own cache');
        if (!children) await until(() => state.transfers[0].cancelled, 'obsolete source download must abort');
        state.transfers[1].finish();
        await cached(page, 'audio', 60);
        const blob = await page.locator('audio').evaluate(audio => audio.src);
        await page.locator('section').evaluate(node => { window.detachedPlayer = node; node.remove(); });
        await page.waitForFunction(url => revokedAudioUrls.includes(url), blob);
        await page.evaluate(() => document.body.appendChild(window.detachedPlayer));
        await until(() => state.transfers.length === 3, 'reinserted players must reload instead of using a revoked blob');
        state.transfers[2].finish();
        await cached(page, 'audio', 60);
        console.log('PASS ' + (children ? 'source child replacement' : 'source replacement') + ': stale download cleanup, new recording and detached-player reuse');
    } finally { await test.close(); }
}

async function fallbacks(options) {
    const test = await open(options);
    try {
        const { page, state } = test;
        if (options.blockBlob) {
            await until(() => state.transfers.length === 1, 'full download must start');
            state.transfers[0].finish();
        }
        await page.waitForFunction(() => document.querySelector('audio').dataset.listeningCache === 'streaming');
        assert.equal(await page.locator('audio').evaluate(audio => audio.src.startsWith('blob:')), false);
        await page.locator('.play-pause-btn').click();
        await page.waitForFunction(() => !document.querySelector('audio').paused && document.querySelector('audio').currentTime > 0);
        assert(!state.requests.some(request => request.pathname.endsWith('/redirect.wav')), 'cache downloads must not follow redirects');
        console.log('PASS cache fallback: ' + JSON.stringify(options) + ' preserves native streaming playback');
    } finally { await test.close(); }
}

async function abandonedDownload() {
    const test = await open();
    try {
        await until(() => test.state.transfers.length === 1, 'full download must start');
        await test.page.locator('section').evaluate(node => node.remove());
        await until(() => test.state.transfers[0].cancelled, 'removing a question must abort its incomplete download');
        console.log('PASS abandoned question: incomplete download is cancelled');
    } finally { await test.close(); }
}

async function workerSourceBoundaries() {
    const test = await open();
    try {
        await until(() => test.state.transfers.length === 1, 'full download must start');
        test.state.transfers[0].finish();
        await cached(test.page);
        const requestCount = test.state.requests.length;
        const results = await test.page.evaluate(async ({ workerPath, id }) => {
            const downloader = new Worker(workerPath);
            const targets = ['/api/profile', 'http://localhost:' + location.port + '/media/audio.wav?case=' + id];
            const replies = [];
            for (let index = 0; index < targets.length; index++) {
                replies.push(await new Promise(resolve => {
                    downloader.onmessage = event => resolve(event.data);
                    downloader.postMessage({ type: 'load', id: index + 1, url: targets[index] });
                }));
            }
            downloader.terminate();
            return replies;
        }, { workerPath, id: test.id });
        assert(results.every(result => result.failed && !result.blob));
        assert.equal(test.state.requests.length, requestCount, 'unsupported URLs must be rejected before making a request');
        console.log('PASS worker URL boundaries: unsupported paths and different origins do not produce downloads');
    } finally { await test.close(); }
}

try {
    await fullCacheBeforePlay();
    await fullCacheBeforePlay(true);
    await preservePlaybackAndScrubbing(false);
    await preservePlaybackAndScrubbing(true);
    await sourceLifecycle(false);
    await sourceLifecycle(true);
    for (const failure of ['http', 'partial', 'html', 'redirect', 'empty', 'oversized', 'truncated']) await fallbacks({ failure });
    await fallbacks({ workerFailure: true });
    await fallbacks({ blockBlob: true });
    await abandonedDownload();
    await workerSourceBoundaries();
} finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
}
