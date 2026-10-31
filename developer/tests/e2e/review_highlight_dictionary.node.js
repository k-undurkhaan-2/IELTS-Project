#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const bubbleSelector = '#review-highlight-dictionary-bubble';

async function createFixture(browser, options = {}) {
    const context = await browser.newContext({
        viewport: { width: 1280, height: 800 },
        ...options
    });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    await page.route('http://dictionary.test/**', (route) => route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
            <style>* { box-sizing: border-box; } body { margin: 0; }
            main { min-height: 2000px; padding: 60px; }
            .hl { background: yellow; }</style></head><body>
            <main><span class="hl" id="first-term">example</span>
            <span class="hl" id="second-term">sample</span></main></body></html>`
    }));
    await page.goto('http://dictionary.test/');
    await page.addScriptTag({ path: path.join(repoRoot, 'js/runtime/reviewHighlightDictionary.js') });
    await page.evaluate(() => {
        window.savedLookups = [];
        window.ReviewHighlightDictionary.attach({
            roots: { main: document.querySelector('main') },
            lookupService: {
                lookup(term) {
                    return {
                        found: true,
                        term,
                        zh: 'Sample meaning',
                        en: 'Selectable dictionary definition for the interaction regression. '.repeat(100),
                        sourceLabel: 'Test dictionary'
                    };
                }
            },
            postMessage(type, payload) {
                window.savedLookups.push({ type, payload });
                return true;
            }
        });
    });
    return { context, page, bubble: page.locator(bubbleSelector) };
}

async function openDictionary(page) {
    await page.locator('#first-term').click();
    await page.locator(bubbleSelector).waitFor({ state: 'visible' });
}

test('review dictionary supports selection, scrolling, actions, and dismissal', { timeout: 60000 }, async (t) => {
    const browser = await chromium.launch({ headless: true });
    try {
        async function check(name, run, options) {
            await t.test(name, async () => {
                const fixture = await createFixture(browser, options);
                try {
                    await run(fixture);
                } finally {
                    await fixture.context.close();
                }
            });
        }

        await check('definition text can be selected with a double click', async ({ page, bubble }) => {
            await openDictionary(page);
            await bubble.locator('.vocab-text').nth(1).dblclick({ position: { x: 30, y: 10 } });
            assert.equal(await bubble.isVisible(), true);
            assert.match(await page.evaluate(() => window.getSelection().toString()), /Selectable/);
        });

        await check('dragging a selection beyond the popup edge keeps the selection and popup', async ({ page, bubble }) => {
            await openDictionary(page);
            const rect = await bubble.locator('.vocab-text').nth(1).boundingBox();
            await page.mouse.move(rect.x + 3, rect.y + 10);
            await page.mouse.down();
            await page.mouse.move(rect.x - 30, rect.y + 35, { steps: 10 });
            await page.mouse.up();
            assert.equal(await bubble.isVisible(), true);
            assert.notEqual(await page.evaluate(() => window.getSelection().toString().trim()), '');
        });

        await check('wheel scrolling and reaching the bottom do not dismiss or scroll the page', async ({ page, bubble }) => {
            await openDictionary(page);
            await bubble.hover();
            await page.mouse.wheel(0, 180);
            await page.waitForFunction((selector) => document.querySelector(selector).scrollTop > 0, bubbleSelector);
            assert.equal(await bubble.isVisible(), true);

            await bubble.evaluate((element) => { element.scrollTop = element.scrollHeight; });
            await page.waitForFunction((selector) => {
                const element = document.querySelector(selector);
                return element.scrollTop + element.clientHeight >= element.scrollHeight - 1;
            }, bubbleSelector);
            await page.mouse.wheel(0, 500);
            await page.waitForTimeout(150);
            assert.equal(await bubble.isVisible(), true);
            assert.equal(await page.evaluate(() => window.scrollY), 0);
        });

        await check('a nested scrollable definition also keeps the popup open', async ({ page, bubble }) => {
            await openDictionary(page);
            const definition = bubble.locator('.vocab-text').nth(1);
            await definition.evaluate((element) => {
                element.style.maxHeight = '120px';
                element.style.overflow = 'auto';
                element.scrollTop = 100;
            });
            await page.waitForFunction((selector) => {
                const definitions = document.querySelectorAll(`${selector} .vocab-text`);
                return definitions[1]?.scrollTop > 0;
            }, bubbleSelector);
            assert.equal(await bubble.isVisible(), true);
        });

        await check('switching terms and saving vocabulary still work', async ({ page, bubble }) => {
            await openDictionary(page);
            await page.locator('#second-term').click();
            assert.equal(await bubble.locator('.vocab-bubble-head .vocab-term').textContent(), 'sample');
            const addButton = bubble.locator('[data-vocab-add]');
            await addButton.click();
            assert.equal(await bubble.isVisible(), true);
            assert.equal(await addButton.isDisabled(), true);
            const saved = await page.evaluate(() => ({
                messages: window.savedLookups,
                words: JSON.parse(localStorage.getItem(window.ReviewHighlightDictionary.storageKey)).data.words
            }));
            assert.equal(saved.messages.length, 1);
            assert.equal(saved.messages[0].type, 'VOCAB_HIGHLIGHT_SAVE');
            assert.equal(saved.messages[0].payload.word, 'sample');
            assert.equal(saved.words[0].word, 'sample');
            assert.equal(saved.words[0].meaning, 'Sample meaning');
        });

        await check('explicit dismissal, outside interaction, and keyboard activation still work', async ({ page, bubble }) => {
            await openDictionary(page);
            await bubble.locator('[data-vocab-close]').click();
            assert.equal(await bubble.isVisible(), false);

            await page.locator('#first-term').focus();
            await page.keyboard.press('Enter');
            assert.equal(await bubble.isVisible(), true);
            await page.keyboard.press('Escape');
            assert.equal(await bubble.isVisible(), false);

            await page.locator('#first-term').focus();
            await page.keyboard.press('Space');
            assert.equal(await bubble.isVisible(), true);
            await page.mouse.click(1000, 100);
            assert.equal(await bubble.isVisible(), false);

            await openDictionary(page);
            await page.mouse.move(1000, 500);
            await page.mouse.wheel(0, 200);
            await bubble.waitFor({ state: 'hidden' });

            await openDictionary(page);
            await page.setViewportSize({ width: 1100, height: 760 });
            await bubble.waitFor({ state: 'hidden' });
        });

        await check('touch swipes scroll the definition and an outside tap dismisses it', async ({ page, bubble, context }) => {
            await page.locator('#first-term').tap();
            await bubble.waitFor({ state: 'visible' });
            const rect = await bubble.boundingBox();
            const client = await context.newCDPSession(page);
            const x = Math.round(rect.x + rect.width / 2);
            const y = Math.round(rect.y + rect.height - 60);
            await client.send('Input.dispatchTouchEvent', {
                type: 'touchStart', touchPoints: [{ x, y }]
            });
            for (let step = 1; step <= 8; step += 1) {
                await client.send('Input.dispatchTouchEvent', {
                    type: 'touchMove', touchPoints: [{ x, y: y - step * 20 }]
                });
                await page.waitForTimeout(20);
            }
            await client.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
            await page.waitForFunction((selector) => document.querySelector(selector).scrollTop > 0, bubbleSelector);
            assert.equal(await bubble.isVisible(), true);
            assert.equal(await page.evaluate(() => window.scrollY), 0);
            await page.touchscreen.tap(370, 740);
            assert.equal(await bubble.isVisible(), false);
        }, { viewport: { width: 390, height: 780 }, isMobile: true, hasTouch: true });
    } finally {
        await browser.close();
    }
});
