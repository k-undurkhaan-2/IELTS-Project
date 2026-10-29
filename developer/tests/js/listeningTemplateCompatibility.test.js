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

// Public synthetic content reproduces the private templates' DOM contracts.
const families = [
    { name: 'spa', questionNumbers: [15, 16, 17, 18, 19, 20], headerControls: true, footerColumn: true, nav: 'q-nav-container', item: 'q-nav-item' },
    { name: 'standard', headerControls: true, nav: 'q-nav-container', item: 'q-nav-item' },
    { name: 'notes-padding', reverseNavigation: true, headerControls: true, nav: 'q-nav-container', item: 'q-nav-item', notesPadding: true },
    { name: 'international-club', headerControls: true, nav: 'q-nav-container', item: 'q-nav-item', legacySizing: true },
    { name: 'direct-settings', nav: 'q-nav-container', item: 'q-nav-item', nestedPanel: true },
    { name: 'driving', settings: 'settingsBtn', panel: 'settingsPanel', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesBtn', transcript: 'transcriptBtn', nav: 'qNav', item: 'nav-btn', q: 'q' },
    { name: 'waste', settings: 'setting-trigger', noPanel: true, timer: 'timer-box', notes: 'notes-trigger', transcript: 'trans-trigger', nav: 'nav-strip', item: 'nav-item', q: 'idx' },
    { name: 'adwaita', settings: 'settingsBtn', panel: 'settingsPanel', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesToggle', transcript: 'transcriptToggle', nav: 'qNav', item: 'q-nav', q: 'qnum' },
    { name: 'home-improvement', footerWrap: true, settings: 'settingsToggle', panel: 'settingsPanel', timer: 'timerDisplay', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesBtn', transcript: 'transcriptBtn', nav: 'navSquares', item: 'nav-item', q: 'q' },
    { name: 'silverton', settings: 'settingsBtn', panel: 'settings-menu', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesBtn', transcript: 'transcriptBtn', nav: 'navGrid', item: 'nav-item' },
    { name: 'trademark', footerWrap: true, settings: 'settingsToggle', panel: 'settingsPanel', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesBtn', transcript: 'transcriptBtn', nav: 'navContainer', item: 'nav-item', q: 'q' },
    { name: 'bike', settings: 'settingsBtn', panel: 'settingsPanel', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesBtn', transcript: 'transcriptBtn', nav: 'navContainer', item: 'nav-item', q: 'q' },
    { name: 'digital', settings: 'settingsBtn', finish: 'finishBtn', reset: 'clearBtn', notes: 'notesToggleBtn', transcript: 'transcriptToggleBtn', nav: 'qNavContainer', item: 'q-nav-item', q: 'q' },
    { name: 'inline', inlineSettings: true, inlineReset: true, inlineNotes: true, transcript: 'trans-btn', nav: 'q-nav', item: 'nav-item' },
    { name: 'home-features', noSettings: true, footer: 'footer-class', notes: 'notes-btn', transcript: 'trans-btn', nav: 'dot-bar', item: 'nav-item' },
    { name: 'maple', noHeader: true, audioHeader: true, noSettings: true, footer: 'bottomBar', finish: 'btnFinish', reset: 'btnClear', notes: 'btnNotes', noTranscript: true, nav: 'pager', item: 'bubble', q: 'q', delegated: true },
    { name: 'elephants', noHeader: true, noSettings: true, noNotes: true, noReset: true, noTimer: true, footer: 'semantic', finish: 'submitBtn', transcript: 'tToggle', nav: 'dotsContainer', item: 'dot' }
].map(family => ({
    settings: 'settings-btn', panel: 'settings-panel', timer: 'timer', finish: 'finish-btn',
    reset: 'clear-btn', notes: 'toggle-notes-btn', transcript: 'toggle-transcript-btn', q: 'qnum',
    questionNumbers: Array.from({ length: 10 }, (_, index) => index + 21), ...family
}));

function nativeFixture(family) {
    window.calls = { settings: 0, notes: 0, transcript: 0, finish: 0, reset: 0, navigation: 0, audio: 0 };
    window.originals = [];
    function retain(node) { if (node) originals.push({ node, id: node.id, parent: node.parentElement }); return node; }
    const nativePanel = document.getElementById(family.panel);
    if (family.name === 'home-features') {
        document.addEventListener('mouseup', event => {
            if (event.target.className && event.target.className.startsWith('hl-')) calls.selection = true;
        });
    }
    window.toggleSettings = function () { calls.settings++; if (nativePanel) nativePanel.style.display = nativePanel.style.display === 'none' ? 'block' : 'none'; };
    window.clearProgress = function () { calls.reset++; document.querySelector('[name=q' + family.questionNumbers[0] + ']').value = ''; };
    window.toggleNotes = function () { calls.notes++; document.body.classList.add('notes-open'); document.getElementById('notes').hidden = false; };
    retain(document.getElementById('native-notes-close')).addEventListener('click', () => { document.getElementById('notes').hidden = true; document.body.classList.remove('notes-open'); });
    if (!family.noSettings) {
        const settings = retain(family.inlineSettings ? document.querySelector('[onclick="toggleSettings()"]') : document.getElementById(family.settings));
        if (!family.inlineSettings && !family.noPanel) settings.addEventListener('click', event => { event.stopPropagation(); toggleSettings(); });
    }
    retain(document.getElementById(family.finish)).addEventListener('click', () => {
        calls.finish++;
        if (family.name === 'home-improvement') {
            const reviewing = calls.finish % 2 === 1;
            document.getElementById(family.finish).textContent = reviewing ? 'Return to Test' : 'Finish';
            if (reviewing) document.querySelectorAll('button').forEach(button => {
                if (![family.finish, family.reset, family.notes, family.transcript].includes(button.id)) button.disabled = true;
            });
            if (!reviewing) document.querySelectorAll('input').forEach(input => { input.disabled = false; });
        }
    });
    if (!family.noReset) {
        const reset = retain(family.inlineReset ? document.querySelector('[onclick="clearProgress()"]') : document.getElementById(family.reset));
        if (!family.inlineReset) reset.addEventListener('click', clearProgress);
    }
    if (!family.noNotes) {
        const notes = retain(family.inlineNotes ? document.querySelector('[onclick="toggleNotes()"]') : document.getElementById(family.notes));
        if (!family.inlineNotes) notes.addEventListener('click', toggleNotes);
    }
    if (!family.noTranscript) retain(document.getElementById(family.transcript)).addEventListener('click', () => { calls.transcript++; document.getElementById('questions').classList.toggle('transcript-open'); });
    if (!family.noTimer) {
        window.sourceTimer = retain(document.getElementById(family.timer));
        setInterval(() => { document.getElementById(family.timer).textContent = 'source clock'; }, 50);
    }
    window.sourceAudio = retain(document.getElementById('recording'));
    retain(document.getElementById('audio-play')).addEventListener('click', () => calls.audio++);
    window.sourceContent = document.getElementById('source-content');
    const nav = retain(document.getElementById(family.nav));
    window.renderSourceNavigation = function () {
        nav.textContent = '';
        for (const number of (family.reverseNavigation ? family.questionNumbers.slice().reverse() : family.questionNumbers)) {
            const item = document.createElement(family.delegated ? 'button' : 'div');
            item.className = family.item;
            item.textContent = number;
            item.dataset[family.q] = number;
            if (!family.delegated) item.onclick = () => { calls.navigation++; item.className = family.item + ' answered'; document.getElementById('question-' + number).scrollIntoView(); };
            nav.appendChild(item);
        }
    };
    if (family.delegated) nav.addEventListener('click', event => {
        const target = event.target.closest('.bubble');
        if (!target) return;
        calls.navigation++;
        target.className = 'bubble done';
        const targetNode = document.getElementById('anchor_q' + target.dataset.q);
        window.scrollTo({ top: targetNode.getBoundingClientRect().top + window.scrollY, behavior: 'smooth' });
    });
    renderSourceNavigation();
    window.__listeningBridgeGetState = () => ({ initialized: true });
}

function fixture(family) {
    const button = (id, text, onclick = '') => '<button ' + (id ? 'id="' + id + '"' : '') + (onclick ? ' onclick="' + onclick + '"' : '') + ' type="button">' + text + '</button>';
    const settings = family.noSettings ? '' : button(family.inlineSettings ? '' : family.settings, 'Text Size/Color', family.inlineSettings ? 'toggleSettings()' : '');
    const panel = family.noSettings || family.noPanel ? '' : '<aside id="' + family.panel + '" style="display:none"><div class="settings-group"><span class="settings-title">Font size</span><button data-size="large" type="button">Large</button><button type="button" data-native-locked disabled>Unavailable</button></div></aside>';
    const header = family.noHeader ? '' : '<div class="header"><h1>Practice title</h1>' + (family.headerControls ? '<div class="header-controls">' + settings + '</div>' : settings) + (family.nestedPanel ? panel : '') + '</div>';
    const audio = '<div class="audioBar"><button id="audio-play" type="button">Play</button><audio id="recording" data-original="true"></audio></div>';
    const audioHeader = family.audioHeader ? '<header><div class="wrap"><div class="title">Source title</div></div>' + audio + '</header>' : audio;
    const finish = button(family.finish, 'Finish');
    const reset = family.noReset ? '' : button(family.inlineReset ? '' : family.reset, 'Clear', family.inlineReset ? 'clearProgress()' : '');
    const notes = family.noNotes ? '' : button(family.inlineNotes ? '' : family.notes, 'Notes', family.inlineNotes ? 'toggleNotes()' : '');
    const transcript = family.noTranscript ? '' : button(family.transcript, 'Transcript');
    const footerTag = family.footer === 'semantic' ? 'footer' : 'div';
    const footerAttrs = family.footer === 'bottomBar' ? 'id="bottomBar" class="bottom"' : family.footer === 'footer-class' ? 'class="footer"' : family.footer === 'semantic' ? '' : 'class="bottom-bar"';
    const footer = '<' + footerTag + ' ' + footerAttrs + '><div class="original-footer-wrap"><div id="' + family.nav + '"></div><div class="original-actions">' + (family.noTimer ? '' : '<span id="' + family.timer + '">00:00</span>') + finish + reset + notes + transcript + '</div></div></' + footerTag + '>';
    return '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><style>'
        + 'body{margin:0;height:100vh;display:flex;flex-direction:column;font:16px Arial}.header{display:flex;justify-content:space-between}.main-content{flex:1;min-height:0;overflow:auto}.question{height:100px}.audioBar{padding:10px}aside{background:white;border:1px solid #ddd;padding:12px;position:fixed;right:12px;top:60px;z-index:3500}#notes{top:0;z-index:99;max-width:420px}#notes[hidden]{display:none}.original-actions{display:flex;gap:5px}button{cursor:pointer}'
        + (family.footerWrap ? '.bottom-bar{flex-wrap:wrap}' : '')
        + (family.footerColumn ? '.q-nav-container{flex-wrap:wrap;max-width:400px}@media(max-width:750px){.bottom-bar{flex-direction:column}}' : '')
        + (family.notesPadding ? 'body.notes-open{padding-right:420px}' : '')
        + (family.legacySizing ? 'body.listening-unified-ui .bottom-bar.listening-practice-nav,body.listening-unified-ui .practice-nav.listening-practice-nav{box-sizing:content-box!important;background:#fff!important;flex-wrap:nowrap!important}' : '')
        + '</style></head><body>' + header + (!family.nestedPanel ? panel : '') + audioHeader
        + '<main id="questions" class="main-content"><p id="source-content">Unchanged source content</p>'
        + family.questionNumbers.map(number => '<div class="question" id="question-' + number + '">' + (family.delegated ? '<span id="anchor_q' + number + '"></span>' : '') + '<label>Question ' + number + '<input name="q' + number + '" value="' + (family.noReset ? '' : 'original') + '"></label></div>').join('')
        + '</main>' + footer + '<aside id="notes" hidden><button id="native-notes-close" type="button">Close notes</button><p>Native notes</p></aside><script>('
        + nativeFixture.toString() + ')(' + JSON.stringify(family) + ')</script></body></html>';
}

const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname === '/wrapper') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fs.readFileSync(path.join(repoRoot, 'assets/generated/listening-exams/listening-practice-unified.html'), 'utf8')
            .replace('data-exam-id=""', 'data-exam-id="listening-p3-fixture"')
            .replace('data-source-url=""', 'data-source-url="/fixture?name=' + url.searchParams.get('name') + '"')
            .replace('/js/bundles/listening-wrapper.bundle.js', '/wrapper.js'));
    } else if (url.pathname === '/wrapper.js') {
        response.setHeader('Content-Type', 'text/javascript');
        response.end(fs.readFileSync(path.join(repoRoot, 'js/listeningUnifiedWrapper.js')));
    } else if (url.pathname === '/fixture') {
        response.setHeader('Content-Type', 'text/html');
        response.end(fixture(families.find(family => family.name === url.searchParams.get('name'))));
    } else response.writeHead(404).end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const baseUrl = 'http://127.0.0.1:' + server.address().port;
const browser = await chromium.launch({
    headless: true,
    ...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE ? { executablePath: process.env.IELTS_PLAYWRIGHT_EXECUTABLE } : {})
});

async function receivesPointer(locator) {
    assert.equal(await locator.evaluate(node => {
        const rect = node.getBoundingClientRect();
        const hit = node.ownerDocument.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
        return node === hit || node.contains(hit);
    }), true, 'another control must not cover the pointer target');
}

async function inViewport(locator, width, height) {
    const box = await locator.boundingBox();
    assert(box && box.width > 0 && box.height > 0, 'control must remain visible');
    assert(box.x >= -0.5 && box.x + box.width <= width + 0.5, 'control must fit horizontally: ' + JSON.stringify(box));
    assert(box.y >= -0.5 && box.y + box.height <= height + 0.5, 'control must fit vertically: ' + JSON.stringify(box));
}

try {
    for (const width of [1440, 1280, 390]) {
        const height = width === 1440 ? 900 : 844;
        const context = await browser.newContext({ viewport: { width, height } });
        try {
            for (const family of families.filter(family => width !== 1440 || family.footerWrap)) {
                const firstNumber = family.questionNumbers[0];
                const lastNumber = family.questionNumbers[family.questionNumbers.length - 1];
                const page = await context.newPage();
                const errors = [];
                page.on('pageerror', error => errors.push(error.message));
                try {
                    await page.goto(baseUrl + '/wrapper?name=' + family.name);
                    const frame = page.frames().find(candidate => candidate.parentFrame());
                    await frame.waitForSelector('#listening-wrapper-q-nav .q-nav-item:not(.listening-placeholder-q)');
                    assert.equal(await frame.locator('.listening-part-nav-section').count(), 4);
                    const proxyNumbers = await frame.locator('#listening-wrapper-q-nav .q-nav-item:not(.listening-placeholder-q)').evaluateAll(nodes => nodes.map(node => node.dataset.qnum));
                    assert.equal(proxyNumbers.length, family.questionNumbers.length, 'each native question must have one visible proxy');
                    assert.equal(new Set(proxyNumbers).size, family.questionNumbers.length, 'question proxies must not repeat native questions');
                    assert.deepEqual(proxyNumbers.map(Number), family.questionNumbers, 'proxy order must be ascending');
                    if (family.name === 'spa') {
                        const columns = await frame.locator('#listening-wrapper-q-nav [data-part="2"] .q-column').evaluateAll(nodes => nodes.map(node => ({ number: Number(node.dataset.questionId), disabled: node.querySelector('button').disabled })));
                        assert.deepEqual(columns.map(column => column.number), [11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
                        assert.deepEqual(columns.filter(column => column.disabled).map(column => column.number), [11, 12, 13, 14]);
                    }
                    if (family.reverseNavigation) {
                        const originalOrder = await frame.locator('[data-listening-role=navigation] > *').allTextContents();
                        assert.deepEqual(originalOrder.map(Number), family.questionNumbers.slice().reverse(), 'source navigation order must remain unchanged');
                        await frame.evaluate(() => { window.savedQuestionProxy = document.querySelector('#listening-wrapper-q-nav .q-nav-item:not(.listening-placeholder-q)'); });
                        await frame.waitForTimeout(1100);
                        assert.equal(await frame.evaluate(() => window.savedQuestionProxy === document.querySelector('#listening-wrapper-q-nav .q-nav-item:not(.listening-placeholder-q)')), true, 'a timer tick must not rebuild sorted proxies');
                    }
                    if (family.item === 'q-nav-item' && family.q === 'qnum') {
                        assert.equal(await frame.evaluate(number => document.querySelector('.q-nav-item[data-qnum="' + number + '"]') === document.querySelector('[data-listening-role=navigation] [data-qnum="' + number + '"]'), firstNumber), true, 'native global selectors must still resolve to native navigation');
                    }
                    for (const selector of ['.listening-settings-button', '[data-listening-action=finish]', '[data-listening-action=notes]', '[data-listening-action=reset]', '#listening-wrapper-timer']) {
                        await inViewport(frame.locator(selector), width, height);
                        await receivesPointer(frame.locator(selector));
                    }
                    await frame.locator('.listening-settings-button').click();
                    await frame.locator('.listening-settings-panel').waitFor({ state: 'visible' });
                    await inViewport(frame.locator('.listening-settings-panel'), width, height);
                    if (!family.noTranscript) {
                        await frame.locator('[data-listening-action=transcript]').click();
                        assert.equal(await frame.evaluate(() => calls.transcript), 1);
                    }
                    if (await frame.locator('.listening-settings-panel').isVisible()) await frame.locator('.listening-settings-button').click();
                    await frame.locator('.listening-settings-panel').waitFor({ state: 'hidden' });
                    await frame.locator('[data-listening-action=notes]').click();
                    if (!family.noNotes) {
                        assert.equal(await frame.evaluate(() => calls.notes), 1);
                        assert.equal(await frame.locator('#notes').isVisible(), true);
                        if (family.notesPadding) {
                            for (const selector of ['#listening-wrapper-q-nav [data-qnum="30"]', '[data-listening-action=reset]']) {
                                await inViewport(frame.locator(selector), width, height);
                                await receivesPointer(frame.locator(selector));
                            }
                        }
                        await inViewport(frame.locator('#native-notes-close'), width, height);
                        await receivesPointer(frame.locator('#native-notes-close'));
                        await frame.locator('#native-notes-close').click();
                        await frame.locator('#notes').waitFor({ state: 'hidden' });
                    } else {
                        await frame.locator('.listening-wrapper-notes').waitFor({ state: 'visible' });
                        await frame.locator('.listening-wrapper-notes button').click();
                    }
                    await frame.locator('[name=q' + firstNumber + ']').fill('changed');
                    await frame.locator('[data-listening-action=finish]').click();
                    assert.equal(await frame.evaluate(() => calls.finish), 1);
                    if (family.name === 'home-improvement') {
                        assert.equal(await frame.locator('[data-listening-action=finish]').isEnabled(), true);
                        assert.equal(await frame.locator('[data-listening-action=finish]').textContent(), 'Return to Test');
                        assert.equal(await frame.locator('#listening-wrapper-timer').isEnabled(), true);
                        assert.equal(await frame.locator('.listening-settings-button').isEnabled(), false, 'respect native review restrictions');
                        await frame.locator('[data-listening-action=finish]').click();
                        assert.equal(await frame.evaluate(() => calls.finish), 2);
                        assert.equal(await frame.locator('.listening-settings-button').isEnabled(), true, 'restore Settings after native return');
                        await frame.locator('.listening-settings-button').click();
                        await frame.locator('.listening-settings-panel').waitFor({ state: 'visible' });
                        assert.equal(await frame.locator('.listening-settings-panel [data-size=large]').isEnabled(), true);
                        assert.equal(await frame.locator('.listening-settings-panel [data-native-locked]').isEnabled(), false, 'preserve pre-existing disabled settings');
                        await frame.locator('.listening-settings-button').click();
                        await frame.locator('.listening-settings-panel').waitFor({ state: 'hidden' });
                        await frame.locator('[data-listening-action=notes]').click();
                        await frame.locator('#native-notes-close').click();
                    }
                    if (family.noReset) {
                        await Promise.all([
                            frame.waitForNavigation(),
                            frame.locator('[data-listening-action=reset]').click()
                        ]);
                        await frame.waitForSelector('#listening-wrapper-q-nav .q-nav-item:not(.listening-placeholder-q)');
                    } else await frame.locator('[data-listening-action=reset]').click();
                    assert.equal(await frame.locator('[name=q' + firstNumber + ']').inputValue(), '');
                    const firstQuestion = frame.locator('#listening-wrapper-q-nav [data-qnum="' + firstNumber + '"]');
                    await inViewport(firstQuestion, width, height);
                    await receivesPointer(frame.locator('#listening-wrapper-q-nav [data-qnum="' + lastNumber + '"]'));
                    await firstQuestion.click();
                    assert.equal(await frame.evaluate(() => calls.navigation), 1);
                    await frame.waitForFunction(number => document.querySelector('#listening-wrapper-q-nav [data-qnum="' + number + '"]').classList.contains('answered'), firstNumber);
                    await frame.evaluate(() => renderSourceNavigation());
                    await frame.waitForFunction(number => {
                        const proxy = document.querySelector('#listening-wrapper-q-nav [data-qnum="' + number + '"]');
                        return proxy._listeningSource.isConnected && proxy._listeningSource.textContent === String(number);
                    }, firstNumber);
                    await firstQuestion.click();
                    assert.equal(await frame.evaluate(() => calls.navigation), 2);
                    if (family.delegated) {
                        await frame.locator('#listening-wrapper-q-nav [data-qnum="' + lastNumber + '"]').click();
                        await frame.waitForFunction(() => {
                            const main = document.getElementById('questions');
                            const target = document.getElementById('anchor_q30').getBoundingClientRect();
                            const bounds = main.getBoundingClientRect();
                            return main.scrollTop > 0 && target.top >= bounds.top && target.bottom <= bounds.bottom;
                        });
                    }
                    assert.equal(await frame.evaluate(() => originals.every(({ node, id, parent }) => node.isConnected && node.parentElement === parent && (!id || document.getElementById(id) === node))), true, 'source IDs and ancestor chains must remain intact');
                    assert.equal(await frame.evaluate(() => sourceAudio === document.getElementById('recording') && sourceContent.textContent === 'Unchanged source content'), true);
                    if (!family.noTimer) assert.equal(await frame.evaluate(() => document.getElementById(sourceTimer.id) === sourceTimer && sourceTimer.textContent === 'source clock'), true);
                    for (const theme of ['dark', 'dark-mode']) {
                        await frame.evaluate(theme => {
                            document.body.classList.remove('dark', 'dark-mode');
                            document.body.classList.add(theme);
                        }, theme);
                        const colors = await frame.evaluate(() => ({
                            header: getComputedStyle(document.querySelector('.header')).backgroundColor,
                            footer: getComputedStyle(document.querySelector('.listening-practice-nav')).backgroundColor,
                            candidate: getComputedStyle(document.querySelector('.candidate-id')).color
                        }));
                        assert.equal(colors.header, 'rgb(30, 41, 59)', theme + ' header must use the dark palette');
                        assert.equal(colors.footer, 'rgb(30, 41, 59)', theme + ' footer must use the dark palette');
                        assert.equal(colors.candidate, 'rgb(248, 250, 252)', theme + ' header text must remain legible');
                    }
                    assert.deepEqual(errors, [], family.name + ' must not throw');
                    console.log('PASS ' + family.name + ' ' + width + 'px: controls, original nodes, delegated navigation, redraw and viewport');
                } finally {
                    await page.close();
                }
            }
        } finally {
            await context.close();
        }
    }
} finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
}
