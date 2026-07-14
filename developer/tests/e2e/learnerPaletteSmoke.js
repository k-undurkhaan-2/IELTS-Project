#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from '@playwright/test';

const baseUrl = process.env.IELTS_BASE_URL || 'http://127.0.0.1:8765/';
const storageKey = 'ielts.learnerPalette';
const palettes = ['sage', 'steel', 'mist', 'warm'];
const pages = [
    { label: 'home', view: 'overview' },
    { label: 'settings', view: 'settings' },
    { label: 'account', view: 'account' },
    { label: 'statistics', view: 'practice' }
];
const outputDir = process.env.IELTS_PALETTE_QA_OUTPUT || path.join(
    os.tmpdir(),
    `ielts-learner-palette-qa-${new Date().toISOString().replace(/[:.]/g, '-')}`
);
fs.mkdirSync(outputDir, { recursive: true });

function attachDiagnostics(page, diagnostics) {
    page.on('console', (message) => {
        if (message.type() === 'error') {
            diagnostics.consoleErrors.push(message.text());
        }
    });
    page.on('pageerror', (error) => {
        diagnostics.pageErrors.push(String(error?.message || error));
    });
    page.on('requestfailed', (request) => {
        diagnostics.requestFailures.push({
            url: request.url(),
            error: request.failure()?.errorText || 'unknown'
        });
    });
    page.on('response', (response) => {
        if (response.status() >= 400) {
            diagnostics.httpErrors.push({ status: response.status(), url: response.url() });
        }
    });
}

function installPaletteTelemetry() {
    window.__learnerPaletteTelemetry = {
        navigationStart: performance.timeOrigin,
        initScriptTime: Number(performance.now().toFixed(2)),
        timeline: [],
        firstThemeCss: null,
        paints: []
    };
    let previous = Symbol('unset');
    const telemetry = window.__learnerPaletteTelemetry;
    const capture = (reason) => {
        const palette = document.body?.getAttribute('data-learner-palette') ?? null;
        if (palette === previous) return;
        previous = palette;
        telemetry.timeline.push({
            reason,
            palette,
            readyState: document.readyState,
            time: Number(performance.now().toFixed(2))
        });
    };
    const sampleThemeCss = () => {
        const body = document.body;
        const palette = body?.getAttribute('data-learner-palette') ?? null;
        const accent = body ? getComputedStyle(body).getPropertyValue('--learner-accent').trim() : '';
        if (!telemetry.firstThemeCss && palette && accent) {
            telemetry.firstThemeCss = {
                palette,
                accent,
                readyState: document.readyState,
                time: Number(performance.now().toFixed(2))
            };
        }
        if (!telemetry.firstThemeCss) requestAnimationFrame(sampleThemeCss);
    };
    new MutationObserver(() => capture('mutation')).observe(document, {
        attributes: true,
        attributeFilter: ['data-learner-palette'],
        childList: true,
        subtree: true
    });
    document.addEventListener('DOMContentLoaded', () => capture('DOMContentLoaded'));
    try {
        new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
                telemetry.paints.push({
                    name: entry.name,
                    time: Number(entry.startTime.toFixed(2)),
                    palette: document.body?.getAttribute('data-learner-palette') ?? null
                });
            });
        }).observe({ type: 'paint', buffered: true });
    } catch (_) { }
    capture('init-script');
    requestAnimationFrame(sampleThemeCss);
}

async function readPaletteTelemetry(page) {
    return page.evaluate(() => {
        const telemetry = window.__learnerPaletteTelemetry || {};
        const timeline = Array.isArray(telemetry.timeline) ? telemetry.timeline : [];
        const observed = timeline.filter((entry) => entry.palette !== null);
        return {
            navigationStart: telemetry.navigationStart,
            initScriptTime: telemetry.initScriptTime,
            timeline,
            firstAttribute: observed[0] || null,
            firstThemeCss: telemetry.firstThemeCss || null,
            paints: Array.isArray(telemetry.paints) ? telemetry.paints : [],
            finalPalette: document.body?.getAttribute('data-learner-palette') ?? null
        };
    });
}

function assertPaletteTelemetry(telemetry, expectedPalette, label) {
    assert.equal(telemetry.firstAttribute?.palette, expectedPalette, `${label} first attribute should be ${expectedPalette}`);
    assert.equal(telemetry.firstThemeCss?.palette, expectedPalette, `${label} first effective theme CSS should be ${expectedPalette}`);
    assert.equal(telemetry.finalPalette, expectedPalette, `${label} final palette should be ${expectedPalette}`);
    const wrongPalettes = telemetry.timeline
        .map((entry) => entry.palette)
        .filter((palette) => palette !== null && palette !== expectedPalette);
    assert.deepEqual(wrongPalettes, [], `${label} should not expose an intermediate wrong palette`);
}

async function waitForApplication(page, palette) {
    await page.waitForFunction(
        ({ key, expected }) => document.body?.getAttribute(key) === expected,
        { key: 'data-learner-palette', expected: palette },
        { timeout: 20_000 }
    );
    await page.waitForFunction(
        () => window.app && window.app.isInitialized && typeof window.app.navigateToView === 'function',
        null,
        { timeout: 20_000 }
    );
}

async function activateView(page, view) {
    await page.evaluate((nextView) => window.app.navigateToView(nextView), view);
    await page.waitForFunction(
        (nextView) => document.getElementById(`${nextView}-view`)?.classList.contains('active'),
        view,
        { timeout: 10_000 }
    );
}

async function inspectView(page, palette, view) {
    return page.evaluate(({ expectedPalette, viewName, key }) => {
        const target = document.getElementById(`${viewName}-view`);
        const heading = target?.querySelector('h1, h2, h3');
        const bodyStyle = getComputedStyle(document.body);

        function parseRgb(value) {
            const match = String(value || '').match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
            return match ? match.slice(1, 4).map(Number) : null;
        }

        function luminance(rgb) {
            const linear = rgb.map((channel) => {
                const value = channel / 255;
                return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
            });
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        }

        function effectiveBackground(element) {
            let current = element;
            while (current) {
                const value = getComputedStyle(current).backgroundColor;
                if (value && value !== 'rgba(0, 0, 0, 0)' && value !== 'transparent') {
                    return value;
                }
                current = current.parentElement;
            }
            return getComputedStyle(document.body).backgroundColor;
        }

        function contrastRatio(element) {
            if (!element) return null;
            const foreground = parseRgb(getComputedStyle(element).color);
            const background = parseRgb(effectiveBackground(element));
            if (!foreground || !background) return null;
            const lighter = Math.max(luminance(foreground), luminance(background));
            const darker = Math.min(luminance(foreground), luminance(background));
            return Number(((lighter + 0.05) / (darker + 0.05)).toFixed(2));
        }

        const selected = Array.from(document.querySelectorAll('.learner-palette-option[aria-pressed="true"]'))
            .map((button) => button.value);
        const swatch = document.querySelector(`.learner-palette-option[value="${expectedPalette}"] .learner-palette-swatch`);
        const swatchStyle = swatch ? getComputedStyle(swatch) : null;
        return {
            palette: document.body?.getAttribute('data-learner-palette'),
            persisted: localStorage.getItem(key),
            viewActive: Boolean(target?.classList.contains('active')),
            display: target ? getComputedStyle(target).display : null,
            heading: heading?.textContent?.replace(/\s+/g, ' ').trim() || '',
            headingContrast: contrastRatio(heading),
            accent: bodyStyle.getPropertyValue('--learner-accent').trim(),
            selectedSurface: bodyStyle.getPropertyValue('--learner-selected-surface').trim(),
            border: bodyStyle.getPropertyValue('--learner-border').trim(),
            background: bodyStyle.backgroundColor,
            selected,
            swatchBackground: swatchStyle?.backgroundColor || '',
            swatchBorder: swatchStyle?.borderColor || ''
        };
    }, { expectedPalette: palette, viewName: view, key: storageKey });
}

async function runStorageCase(browser, name, initScript, expectedPalette) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    await context.addInitScript(initScript, storageKey);
    await context.addInitScript(installPaletteTelemetry);
    const page = await context.newPage();
    const diagnostics = { consoleErrors: [], pageErrors: [], requestFailures: [], httpErrors: [] };
    attachDiagnostics(page, diagnostics);
    try {
        await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
        await waitForApplication(page, expectedPalette);
        const telemetry = await readPaletteTelemetry(page);
        assertPaletteTelemetry(telemetry, expectedPalette, name);
        return {
            name,
            palette: await page.getAttribute('body', 'data-learner-palette'),
            appReady: await page.evaluate(() => Boolean(window.app)),
            telemetry,
            diagnostics
        };
    } finally {
        await context.close();
    }
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
await context.addInitScript((key) => {
    if (!localStorage.getItem(key)) localStorage.setItem(key, 'warm');
    localStorage.setItem('hasSeenGplLicense', 'true');
}, storageKey);
await context.addInitScript(installPaletteTelemetry);

const page = await context.newPage();
const diagnostics = { consoleErrors: [], pageErrors: [], requestFailures: [], httpErrors: [] };
attachDiagnostics(page, diagnostics);
const matrix = [];
const accents = new Map();
const reloadTimings = [];

try {
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await waitForApplication(page, 'warm');
    const firstRenderTelemetry = await readPaletteTelemetry(page);
    assertPaletteTelemetry(firstRenderTelemetry, 'warm', 'initial warm load');

    for (const palette of palettes) {
        await activateView(page, 'settings');
        await page.locator(`.learner-palette-option[value="${palette}"]`).click();
        await page.waitForFunction(
            (expected) => document.body?.getAttribute('data-learner-palette') === expected,
            palette
        );
        assert.equal(await page.evaluate((key) => localStorage.getItem(key), storageKey), palette);

        await page.reload({ waitUntil: 'domcontentloaded', timeout: 30_000 });
        await waitForApplication(page, palette);
        assert.equal(await page.evaluate((key) => localStorage.getItem(key), storageKey), palette);
        const reloadTelemetry = await readPaletteTelemetry(page);
        assertPaletteTelemetry(reloadTelemetry, palette, `${palette} refresh`);
        reloadTimings.push({ palette, ...reloadTelemetry });

        for (const pageSpec of pages) {
            await activateView(page, 'overview');
            await activateView(page, pageSpec.view);
            const observation = await inspectView(page, palette, pageSpec.view);
            assert.equal(observation.palette, palette);
            assert.equal(observation.persisted, palette);
            assert.equal(observation.viewActive, true);
            assert.notEqual(observation.display, 'none');
            assert.ok(observation.accent, `${palette}/${pageSpec.label} should resolve --learner-accent`);
            assert.ok(observation.selectedSurface, `${palette}/${pageSpec.label} should resolve selected surface`);
            assert.ok(observation.border, `${palette}/${pageSpec.label} should resolve learner border`);
            assert.deepEqual(observation.selected, [palette]);
            assert.ok(
                observation.headingContrast === null || observation.headingContrast >= 3,
                `${palette}/${pageSpec.label} heading contrast should remain readable`
            );
            accents.set(palette, observation.accent);
            const screenshot = path.join(outputDir, `${palette}-${pageSpec.label}.png`);
            await page.screenshot({ path: screenshot, fullPage: true });
            matrix.push({ palette, page: pageSpec.label, view: pageSpec.view, screenshot, ...observation });
        }
    }

    assert.equal(new Set(accents.values()).size, palettes.length, 'each palette should resolve a distinct accent');

    const missingStorage = await runStorageCase(
        browser,
        'missing-storage',
        (key) => localStorage.removeItem(key),
        'sage'
    );
    const emptyStorage = await runStorageCase(
        browser,
        'empty-storage',
        (key) => localStorage.setItem(key, ''),
        'sage'
    );
    const invalidStorage = await runStorageCase(
        browser,
        'invalid-storage',
        (key) => localStorage.setItem(key, '{not-a-palette'),
        'sage'
    );
    const throwingStorage = await runStorageCase(
        browser,
        'throwing-storage',
        (key) => {
            const originalGetItem = Storage.prototype.getItem;
            const originalSetItem = Storage.prototype.setItem;
            Storage.prototype.getItem = function getItem(candidate) {
                if (candidate === key) throw new Error('palette getItem blocked');
                return originalGetItem.call(this, candidate);
            };
            Storage.prototype.setItem = function setItem(candidate, value) {
                if (candidate === key) throw new Error('palette setItem blocked');
                return originalSetItem.call(this, candidate, value);
            };
        },
        'sage'
    );
    const unavailableStorage = await runStorageCase(
        browser,
        'unavailable-storage',
        () => {
            Object.defineProperty(window, 'localStorage', {
                configurable: true,
                value: undefined
            });
        },
        'sage'
    );
    const storageCases = [missingStorage, emptyStorage, invalidStorage, throwingStorage, unavailableStorage];

    assert.equal(matrix.length, palettes.length * pages.length);
    assert.equal(diagnostics.pageErrors.length, 0, 'main QA page should have no uncaught page errors');
    storageCases.forEach((entry) => {
        assert.equal(entry.diagnostics.pageErrors.length, 0, `${entry.name} should not abort startup`);
    });

    const report = {
        status: 'pass',
        baseUrl,
        outputDir,
        browserVersion: browser.version(),
        firstRenderTelemetry,
        reloadTimings,
        matrix,
        storageCases,
        diagnostics
    };
    const reportPath = path.join(outputDir, 'learner-palette-smoke-report.json');
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    console.log(JSON.stringify({
        status: report.status,
        browserVersion: report.browserVersion,
        matrixEntries: matrix.length,
        firstRenderTelemetry,
        reloadTimings,
        consoleErrors: diagnostics.consoleErrors,
        pageErrors: diagnostics.pageErrors,
        requestFailures: diagnostics.requestFailures,
        httpErrors: diagnostics.httpErrors,
        storageCases: report.storageCases.map((entry) => ({
            name: entry.name,
            palette: entry.palette,
            appReady: entry.appReady,
            firstAttribute: entry.telemetry.firstAttribute,
            firstThemeCss: entry.telemetry.firstThemeCss,
            pageErrors: entry.diagnostics.pageErrors
        })),
        reportPath
    }, null, 2));
} finally {
    await context.close();
    await browser.close();
}
