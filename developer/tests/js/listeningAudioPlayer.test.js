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

// Generated silence exercises the browser's real media clock and HTTP seeking
// without depending on private listening questions or recordings.
const duration = 120;
const sampleRate = 8000;
const wav = Buffer.alloc(44 + duration * sampleRate * 2);
wav.write('RIFF', 0);
wav.writeUInt32LE(wav.length - 8, 4);
wav.write('WAVEfmt ', 8);
wav.writeUInt32LE(16, 16);
wav.writeUInt16LE(1, 20);
wav.writeUInt16LE(1, 22);
wav.writeUInt32LE(sampleRate, 24);
wav.writeUInt32LE(sampleRate * 2, 28);
wav.writeUInt16LE(2, 32);
wav.writeUInt16LE(16, 34);
wav.write('data', 36);
wav.writeUInt32LE(wav.length - 44, 40);

function playerMarkup(id = 'first', alternate = false) {
    return `<div class="audio-player" id="${id}">
        <button class="play-pause-btn" type="button">Play</button>
        <div class="${alternate ? 'progress-area' : 'progress-container'}">
            <div class="progress-bar-wrapper"><div class="${alternate ? 'progress-fill' : 'progress-bar'}"></div></div>
        </div>
        <span class="time-display">00:00 / 00:00</span>
        <select class="playback-speed"><option value="1">1x</option><option value="1.5">1.5x</option></select>
        <audio src="/audio.wav" preload="metadata"></audio>
    </div>`;
}

const fixture = `<!doctype html><html><head><style>
    body { margin: 20px; }
    .audio-player { display: flex; align-items: center; gap: 10px; margin-bottom: 30px; }
    .progress-container, .progress-area { width: 400px; height: 24px; display: flex; align-items: center; }
    .progress-bar-wrapper { width: 100%; height: 8px; background: #ddd; }
    .progress-bar, .progress-fill { height: 8px; width: 0; background: #2684ff; }
</style></head><body>${playerMarkup()}${playerMarkup('second', true)}
<main><input name="q1" value="answer"><div id="results"></div></main>
<div class="bottom-bar"><button id="finish-btn" type="button">Finish</button></div>
<script>
    window.ANSWER_KEY = { q1: 'answer' };
    function showReview() {
        document.getElementById('results').innerHTML = '<table class="results-table"><thead><tr><th>Question</th><th>Your Answer</th><th>Correct Answer</th><th>Result</th></tr></thead><tbody><tr><td>1</td><td>answer</td><td>answer</td><td>Correct</td></tr></tbody></table>';
    }
    document.getElementById('finish-btn').addEventListener('click', showReview);
    document.addEventListener('source-review-ready', showReview);
    // Legacy players suppress UI updates while scrubbing and only reset their
    // flag on mouseup; the alternate template only implements click-to-seek.
    document.querySelectorAll('.audio-player').forEach(player => {
        const audio = player.querySelector('audio');
        const progress = player.querySelector('.progress-container, .progress-area');
        const bar = progress.querySelector('.progress-bar, .progress-fill');
        let scrubbing = false;
        function update() {
            if (audio.duration && !scrubbing) bar.style.width = audio.currentTime / audio.duration * 100 + '%';
        }
        function seek(event) {
            if (Number.isFinite(audio.duration)) {
                const rect = progress.getBoundingClientRect();
                audio.currentTime = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)) * audio.duration;
                update();
            }
        }
        if (player.id === 'first') {
            progress.addEventListener('mousedown', event => { scrubbing = true; seek(event); });
            document.addEventListener('mousemove', event => { if (scrubbing) seek(event); });
            document.addEventListener('mouseup', () => { scrubbing = false; });
        } else {
            progress.addEventListener('click', seek);
        }
        audio.addEventListener('timeupdate', update);
        audio.addEventListener('loadedmetadata', update);
        player.querySelector('button').onclick = () => audio.paused ? audio.play() : audio.pause();
        player.querySelector('select').onchange = event => { audio.playbackRate = Number(event.target.value); };
    });
</script><script src="/js/bundles/listening-record-bridge.bundle.js" defer></script>
</body></html>`;

const buttonVariants = [
    ['standard', 'class="play-pause-btn"', '&#9658;'],
    ['waste', 'class="play-btn" id="audio-toggle"', '▶'],
    ['trademark', 'class="play-pause" id="playPause"', '▶'],
    ['maple', 'class="btnIcon" id="playBtn"', '<div class="icon-tri"></div>'],
    ['without-progress', 'class="play-btn"', 'Play']
];

function buttonFixture() {
    return `<!doctype html><html><head><style>
        body { color: #fff; background: #fff; }
        section { margin: 16px; display: flex; gap: 12px; align-items: center; }
        button { position: relative; width: 38px; height: 38px; border: 0; border-radius: 50%; background: #2563eb; color: inherit; }
        .prog-wrap { width: 240px; height: 8px; background: #ddd; }
        .play-pause-btn.is-playing { font-size: 0 !important; }
        .play-pause-btn.is-playing::before, .play-pause-btn.is-playing::after { content: ''; position: absolute; top: 50%; width: 4px; height: 14px; background: currentColor; }
        .play-pause-btn.is-playing::before { left: calc(50% - 6px); }
        .play-pause-btn.is-playing::after { left: calc(50% + 2px); }
        .icon-tri { width: 0; height: 0; border-left: 14px solid white; border-top: 8px solid transparent; border-bottom: 8px solid transparent; }
    </style></head><body>${buttonVariants.map(([id, attrs, icon]) => `<section id="${id}">
        <div class="audio-flex"><button ${attrs}>${icon}</button>${id === 'without-progress' ? '' : '<div class="prog-wrap"><div class="prog-fill"></div></div><span class="time-txt"></span>'}</div>
        <audio src="/audio.wav" preload="metadata"></audio>
    </section>`).join('')}
    <script>
        window.nativeClicks = 0;
        document.querySelectorAll('section').forEach(player => {
            const audio = player.querySelector('audio'), button = player.querySelector('button');
            button.onclick = () => { window.nativeClicks++; audio.paused ? audio.play() : audio.pause(); };
            function legacyRender() {
                if (player.id === 'waste') return; // This template never updates its icon.
                button.innerHTML = audio.paused ? '<div class="icon-tri"></div>' : '<span>❚❚</span>';
                button.classList.toggle('is-playing', !audio.paused);
            }
            ['play', 'pause', 'timeupdate', 'ended'].forEach(type => audio.addEventListener(type, legacyRender));
        });
    </script><script src="/js/bundles/listening-record-bridge.bundle.js" defer></script></body></html>`;
}

const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (pathname === '/submit-host') {
        const wrapped = new URL(request.url, 'http://localhost').searchParams.has('wrapped');
        response.setHeader('Content-Type', 'text/html');
        response.end(`<!doctype html><html><body>
            <iframe id="practice" src="${wrapped ? '/wrapper' : '/fixture'}" style="width:100%;height:700px"></iframe>
            <script>
                window.completions = [];
                window.addEventListener('message', event => {
                    const frame = document.getElementById('practice');
                    if (event.source !== frame.contentWindow || event.data?.type !== 'PRACTICE_COMPLETE') return;
                    const source = frame.contentDocument.querySelector('iframe')?.contentDocument || frame.contentDocument;
                    completions.push({ data: event.data.data, paused: [...source.querySelectorAll('audio')].map(audio => audio.paused) });
                });
            </script>
        </body></html>`);
        return;
    }
    if (pathname === '/audio.wav') {
        const range = /^bytes=(\d+)-(\d*)$/.exec(request.headers.range || '');
        const start = range ? Number(range[1]) : 0;
        const end = range && range[2] ? Math.min(Number(range[2]), wav.length - 1) : wav.length - 1;
        response.writeHead(range ? 206 : 200, {
            'Content-Type': 'audio/wav',
            'Accept-Ranges': 'bytes',
            'Content-Length': end - start + 1,
            ...(range ? { 'Content-Range': `bytes ${start}-${end}/${wav.length}` } : {})
        });
        response.end(wav.subarray(start, end + 1));
        return;
    }
    if (pathname === '/wrapper' || pathname === '/button-wrapper') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-source-url=""', 'data-source-url="' + (pathname === '/wrapper' ? '/fixture' : '/buttons') + '"'));
        return;
    }
    if (['/js/bundles/listening-wrapper.bundle.js', '/js/bundles/listening-record-bridge.bundle.js'].includes(pathname)) {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(path.join(repoRoot, pathname)));
        return;
    }
    if (pathname === '/fixture') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fixture);
        return;
    }
    if (pathname === '/buttons') {
        response.setHeader('Content-Type', 'text/html');
        response.end(buttonFixture());
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

async function snapshot(frame, id = 'first') {
    return frame.locator(`#${id}`).evaluate(player => {
        const audio = player.querySelector('audio');
        const progress = player.querySelector('.progress-container, .progress-area');
        return {
            currentTime: audio.currentTime,
            paused: audio.paused,
            playbackRate: audio.playbackRate,
            width: parseFloat(progress.querySelector('.progress-bar, .progress-fill').style.width),
            value: Number(progress.getAttribute('aria-valuenow')),
            text: player.querySelector('.time-display').textContent
        };
    });
}

async function waitForTime(frame, seconds, id = 'first') {
    await frame.waitForFunction(({ id, seconds }) => {
        const audio = document.querySelector('#' + id + ' audio');
        return !audio.seeking && Math.abs(audio.currentTime - seconds) < 1;
    }, { id, seconds });
}

async function exerciseMouse(entry) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 650 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        await page.goto(baseUrl + entry);
        const frame = entry === '/wrapper' ? page.frames().find(candidate => candidate.parentFrame()) : page.mainFrame();
        await frame.waitForFunction(() => document.querySelector('#first audio')?.duration === 120);
        const progress = frame.locator('#first .progress-container');
        const rect = await progress.boundingBox();
        const x = fraction => rect.x + rect.width * fraction;
        const y = rect.y + rect.height / 2;

        await page.mouse.move(x(0.25), y);
        await page.mouse.down();
        await page.mouse.move(x(0.75), y, { steps: 8 });
        const preview = await snapshot(frame);
        assert(Math.abs(preview.width - 75) < 1, 'dragging must immediately preview the requested progress');
        assert.equal(preview.text, '01:30 / 02:00', 'dragging must update the displayed time');
        await page.mouse.up();
        await waitForTime(frame, 90);
        assert.equal((await snapshot(frame)).paused, true, 'seeking while paused must stay paused');
        assert.equal((await snapshot(frame, 'second')).currentTime, 0, 'seeking must affect only the associated audio');

        // Holding the pointer while media events arrive must not undo the preview.
        await frame.locator('#first button').click();
        await frame.locator('#first select').selectOption('1.5');
        await page.mouse.move(x(0.3), y);
        await page.mouse.down();
        await frame.locator('#first audio').evaluate(audio => audio.dispatchEvent(new Event('timeupdate')));
        assert(Math.abs((await snapshot(frame)).width - 30) < 1);
        await page.mouse.move(x(0.5), y, { steps: 5 });
        await page.mouse.up();
        await waitForTime(frame, 60);
        const playing = await snapshot(frame);
        assert.equal(playing.paused, false, 'seeking while playing must keep playing');
        assert.equal(playing.playbackRate, 1.5, 'seeking must retain playback speed');
        await frame.locator('#first button').click();

        await progress.focus();
        await page.keyboard.press('Home');
        await waitForTime(frame, 0);
        await page.keyboard.press('ArrowRight');
        await waitForTime(frame, 5);
        await page.keyboard.press('End');
        await waitForTime(frame, 120);

        // Pointer capture must finish drags beyond the bar and clamp both ends.
        for (const [fraction, expected] of [[-0.2, 0], [1.2, 120]]) {
            await page.mouse.move(x(0.5), y);
            await page.mouse.down();
            await page.mouse.move(x(fraction), y, { steps: 5 });
            await page.mouse.up();
            await waitForTime(frame, expected);
        }

        const alternate = frame.locator('#second .progress-area');
        await alternate.click({ position: { x: 100, y: 12 } });
        await waitForTime(frame, 30, 'second');

        // Unknown metadata must never result in NaN/Infinity media assignments.
        await frame.locator('#first audio').evaluate(audio => {
            Object.defineProperty(audio, 'duration', { configurable: true, value: Infinity });
            audio.dispatchEvent(new Event('durationchange'));
        });
        await page.mouse.click(x(0.25), y);
        assert.equal(await progress.getAttribute('aria-disabled'), 'true');
        assert.equal((await snapshot(frame)).currentTime, 120);
        await frame.locator('#first audio').evaluate(audio => {
            delete audio.duration;
            audio.dispatchEvent(new Event('loadedmetadata'));
        });
        await progress.click({ position: { x: 200, y: 12 } });
        await waitForTime(frame, 60);

        // A rebuilt question page must bind its new controls exactly once.
        await frame.locator('#second').evaluate((player, markup) => { player.outerHTML = markup; }, playerMarkup('second', true));
        await frame.waitForFunction(() => document.querySelector('#second audio').duration === 120);
        await frame.locator('#second .progress-area').click({ position: { x: 300, y: 12 } });
        await waitForTime(frame, 90, 'second');
        assert.deepEqual(errors, [], 'audio interactions must not produce uncaught errors');
        console.log(`PASS ${entry}: mouse, preview, playback state, keyboard, bounds, metadata, replacement`);
    } finally {
        await page.close();
    }
}

async function exerciseTouch() {
    const context = await browser.newContext({ hasTouch: true, viewport: { width: 1000, height: 650 } });
    const page = await context.newPage();
    try {
        await page.goto(baseUrl + '/wrapper');
        const frame = page.frames().find(candidate => candidate.parentFrame());
        await frame.waitForFunction(() => document.querySelector('#first audio')?.duration === 120);
        const rect = await frame.locator('#first .progress-container').boundingBox();
        const session = await context.newCDPSession(page);
        const touch = fraction => [{ x: rect.x + rect.width * fraction, y: rect.y + rect.height / 2 }];
        await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: touch(0.2) });
        await session.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: touch(0.8) });
        assert(Math.abs((await snapshot(frame)).width - 80) < 1, 'touch dragging must preview progress');
        await session.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
        await waitForTime(frame, 96);
        await session.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: touch(0.3) });
        await session.send('Input.dispatchTouchEvent', { type: 'touchCancel', touchPoints: [] });
        await waitForTime(frame, 96);
        assert(Math.abs((await snapshot(frame)).width - 80) < 1, 'cancelled drags must restore the actual position');
        console.log('PASS touch: iframe dragging and cancellation');
    } finally {
        await context.close();
    }
}

async function exerciseButtons(entry) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 650 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        await page.goto(baseUrl + entry);
        const frame = entry === '/button-wrapper' ? page.frames().find(candidate => candidate.parentFrame()) : page.mainFrame();
        await frame.waitForFunction(() => [...document.querySelectorAll('audio')].every(audio => audio.duration === 120));
        async function state(id, playing) {
            await frame.waitForFunction(({ id, playing }) => {
                const button = document.querySelector('#' + id + ' button');
                return button.dataset.listeningPlayback === (playing ? 'playing' : 'paused')
                    && button.getAttribute('aria-label') === (playing ? 'Pause audio' : 'Play audio');
            }, { id, playing });
        }
        const masks = new Set();
        for (const [id] of buttonVariants) {
            const button = frame.locator('#' + id + ' button');
            const audio = frame.locator('#' + id + ' audio');
            await state(id, false);
            const playMask = await button.evaluate(node => getComputedStyle(node, '::before').maskImage);
            assert.notEqual(playMask, 'none', 'every template must show an icon');
            masks.add(playMask);
            await button.click();
            await state(id, true);
            assert.equal(await audio.evaluate(node => node.paused), false, 'one click must start playback');
            assert.notEqual(await button.evaluate(node => getComputedStyle(node, '::before').maskImage), playMask);
            assert.equal(await button.evaluate(node => getComputedStyle(node, '::after').display), 'none', 'legacy pause bars must not overlap');
            assert.equal(await button.evaluate(node => [...node.children].every(child => getComputedStyle(child).display === 'none')), true, 'legacy SVG/CSS/text children must stay hidden after rewrites');
            await button.focus();
            await page.keyboard.press('Space');
            await state(id, false);
            await page.keyboard.press('Enter');
            await state(id, true);
            await audio.evaluate(node => node.pause());
            await state(id, false);
            await audio.evaluate(node => node.play());
            await state(id, true);
            await audio.evaluate(node => { node.currentTime = node.duration - 0.05; });
            await state(id, false);
            assert.equal(await audio.evaluate(node => node.ended), true, 'natural completion must restore the play icon');
            await button.click();
            await state(id, true);
            await audio.evaluate(node => node.load());
            await state(id, false);
        }
        assert.equal(masks.size, 1, 'all template families must share the rounded play icon');
        assert.equal(await frame.evaluate(() => window.nativeClicks), 0, 'legacy click handlers must not double-toggle playback');
        assert.equal(await frame.locator('#waste .time-txt').textContent(), '00:00 / 02:00');

        // Pending playback can be cancelled and an obsolete rejection must not
        // pause a later successful request.
        await frame.evaluate(() => {
            const audio = document.querySelector('#waste audio');
            window.pendingAudio = audio;
            window.originalPlay = audio.play;
            audio.play = () => new Promise((resolve, reject) => { window.rejectOldPlay = reject; });
            const button = document.querySelector('#waste button');
            button.click();
            button.click();
            audio.play = window.originalPlay;
            button.click();
            window.rejectOldPlay(new DOMException('Cancelled', 'AbortError'));
        });
        await state('waste', true);
        assert.equal(await frame.locator('#waste audio').evaluate(node => node.paused), false);
        await frame.locator('#waste button').click();
        await state('waste', false);

        await frame.evaluate(() => {
            const audio = document.querySelector('#waste audio');
            audio.play = () => Promise.reject(new DOMException('Playback blocked', 'NotAllowedError'));
            document.querySelector('#waste button').click();
        });
        await state('waste', false);
        await frame.evaluate(() => { window.pendingAudio.play = window.originalPlay; });

        // A missing source, followed by a recovered source, must remain usable.
        await frame.locator('#waste audio').evaluate(audio => { audio.src = '/missing-audio.wav'; audio.load(); });
        await frame.waitForFunction(() => document.querySelector('#waste audio').error);
        await frame.locator('#waste button').click();
        await state('waste', false);
        await frame.locator('#waste audio').evaluate(audio => { audio.src = '/audio.wav'; audio.load(); });
        await frame.waitForFunction(() => document.querySelector('#waste audio').duration === 120);
        await frame.locator('#waste button').click();
        await state('waste', true);
        await state('standard', false);

        // A media error can leave paused=false. The displayed play action must
        // still attempt playback on the first click, rather than only pausing.
        const retryCalls = await frame.locator('#waste audio').evaluate(audio => {
            Object.defineProperty(audio, 'error', { configurable: true, value: { code: 3 } });
            audio.dispatchEvent(new Event('error'));
            let calls = 0;
            const originalPlay = audio.play;
            audio.play = () => { calls++; throw new DOMException('Decode failed', 'NotSupportedError'); };
            document.querySelector('#waste button').click();
            audio.play = originalPlay;
            delete audio.error;
            return calls;
        });
        assert.equal(retryCalls, 1, 'an error-state play button must attempt playback immediately');
        await state('waste', false);
        await frame.locator('#waste button').click();
        await state('waste', true);

        // Replace only the button, then only the audio, as partial resets do.
        await frame.locator('#waste button').evaluate(button => { button.outerHTML = '<button class="play-btn" id="audio-toggle">▶</button>'; });
        await state('waste', true);
        await frame.locator('#waste button').click();
        await state('waste', false);
        await frame.locator('#waste audio').evaluate(audio => { audio.outerHTML = '<audio src="/audio.wav" preload="metadata"></audio>'; });
        await frame.waitForFunction(() => document.querySelector('#waste audio').duration === 120);
        await frame.evaluate(() => { window.ListeningAudioPlayer.install(document); });
        await frame.locator('#waste button').click();
        await state('waste', true);
        assert.equal(await frame.locator('#waste audio').evaluate(node => node.paused), false, 'replacement controls must bind exactly once');
        assert.deepEqual(errors, [], 'rejected playback must not cause uncaught errors');
        console.log(`PASS ${entry}: 5 button families, media state, keyboard, completion, reset, rejection, cancellation, isolation, replacement`);
    } finally {
        await page.close();
    }
}

async function exerciseSubmission(wrapped, action) {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
        const startedAt = Date.UTC(2026, 0, 1);
        if (action === 'expiry') {
            await page.clock.setFixedTime(startedAt);
            await page.addInitScript(() => localStorage.setItem('ielts_listening_timer_preferences_v1', JSON.stringify({
                mode: 'countdown', countdownMinutes: 1, expiryAction: 'auto-submit'
            })));
        }
        await page.goto(baseUrl + '/submit-host' + (wrapped ? '?wrapped=1' : ''));
        const frame = page.frames().find(candidate => new URL(candidate.url()).pathname === '/fixture');
        const apiFrame = wrapped ? page.frames().find(candidate => candidate.url().endsWith('/wrapper')) : frame;
        await frame.waitForFunction(() => typeof window.__listeningBridgeComplete === 'function'
            && [...document.querySelectorAll('audio')].every(audio => audio.duration === 120));
        await page.evaluate(() => document.getElementById('practice').contentWindow.postMessage({
            type: 'INIT_SESSION', data: { examId: 'listening-p1-audio', sessionId: 'audio-session', startTime: Date.now() }
        }, location.origin));
        await frame.waitForFunction(() => window.__listeningBridgeGetState().initialized);
        await frame.locator('#first .play-pause-btn').click();
        await frame.locator('#second .play-pause-btn').click();
        await frame.waitForFunction(() => [...document.querySelectorAll('audio')].every(audio => !audio.paused && audio.currentTime > 0));

        assert.equal(await apiFrame.evaluate(() => window.__listeningBridgeComplete()), false, 'an attempt without results must not complete');
        assert.deepEqual(await frame.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.paused)), [false, false], 'unsuccessful completion must leave playback running');
        if (action === 'already-paused') await frame.locator('#second .play-pause-btn').click();
        const beforeSubmit = await frame.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.currentTime));
        const finish = frame.locator(wrapped ? '[data-listening-action=finish]' : '#finish-btn');
        if (action === 'api') {
            assert.equal(await apiFrame.evaluate(() => window.__listeningBridgeComplete({ allowGenerated: true })), true);
        } else if (action === 'observer') {
            await frame.evaluate(() => document.dispatchEvent(new Event('source-review-ready')));
        } else if (action === 'keyboard') {
            await finish.press('Enter');
        } else if (action === 'expiry') {
            await page.clock.setFixedTime(startedAt + 61000);
        } else {
            await finish.click();
        }
        await page.waitForFunction(() => completions.length === 1, null, { timeout: 5000 });
        const completion = await page.evaluate(() => completions[0]);
        assert.deepEqual(completion.paused, [true, true], 'stop every recording before publishing completion');
        assert.equal(completion.data.scoreInfo.correct, 1);
        assert.equal(completion.data.answers.q1, 'answer');
        await frame.waitForFunction(() => [...document.querySelectorAll('.play-pause-btn')].every(button => button.dataset.listeningPlayback === 'paused' && button.getAttribute('aria-label') === 'Play audio'));
        const stoppedTimes = await frame.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.currentTime));
        stoppedTimes.forEach((time, index) => assert.ok(time >= beforeSubmit[index], 'submission must preserve the playback position'));
        await page.waitForTimeout(250);
        assert.deepEqual(await frame.locator('audio').evaluateAll(nodes => nodes.map(audio => audio.currentTime)), stoppedTimes, 'recordings must stay stopped after submission');

        // Review playback is still available, and duplicate completion is harmless.
        await frame.locator('#first .play-pause-btn').click();
        await frame.waitForFunction(() => !document.querySelector('#first audio').paused);
        assert.equal(await apiFrame.evaluate(() => window.__listeningBridgeComplete({ allowGenerated: true })), true);
        assert.equal(await frame.locator('#first audio').evaluate(audio => audio.paused), false);
        assert.equal(await page.evaluate(() => completions.length), 1);
        assert.deepEqual(errors, []);
        console.log('PASS ' + (wrapped ? 'wrapped' : 'direct') + ' ' + action + ': submission stops audio, preserves position, updates controls and permits review playback');
    } finally {
        await page.close();
    }
}

try {
    for (const wrapped of [false, true]) {
        for (const action of ['click', 'keyboard', 'api', 'observer', 'already-paused']) {
            await exerciseSubmission(wrapped, action);
        }
    }
    await exerciseSubmission(true, 'expiry');
    await exerciseMouse('/fixture');
    await exerciseMouse('/wrapper');
    await exerciseTouch();
    await exerciseButtons('/buttons');
    await exerciseButtons('/button-wrapper');
} finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
}
