#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const require = createRequire(import.meta.url);

function readSource(relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function resolveBrowserExecutable() {
    const candidates = [
        process.env.IELTS_PLAYWRIGHT_EXECUTABLE,
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser'
    ].filter(Boolean);
    return candidates.find((candidate) => fs.existsSync(candidate));
}

async function launchBrowser() {
    let chromium;
    try {
        ({ chromium } = require('playwright'));
    } catch (error) {
        throw new Error(`Playwright is required for learner UI runtime regression tests: ${error.message}`);
    }

    const executablePath = resolveBrowserExecutable();
    const options = { headless: true };
    if (executablePath) {
        options.executablePath = executablePath;
    }
    return chromium.launch(options);
}

function geometrySnapshotScript() {
    const round = (value) => Math.round(value * 1000) / 1000;
    const rect = (element) => {
        const value = element.getBoundingClientRect();
        return {
            left: round(value.left),
            top: round(value.top),
            width: round(value.width),
            height: round(value.height)
        };
    };
    const practiceView = document.getElementById('practice-view');
    const titleRow = document.querySelector('.practice-view__title-row');
    const toggle = document.getElementById('practice-summary-toggle');
    const region = document.getElementById('practice-summary-region');
    const toggleStyle = getComputedStyle(toggle);
    const regionStyle = getComputedStyle(region);
    return {
        practiceView: rect(practiceView),
        titleRow: rect(titleRow),
        toggle: rect(toggle),
        toggleBorder: {
            top: toggleStyle.borderTopWidth,
            right: toggleStyle.borderRightWidth,
            bottom: toggleStyle.borderBottomWidth,
            left: toggleStyle.borderLeftWidth
        },
        region: rect(region),
        regionDisplay: regionStyle.display
    };
}

function paletteGeometrySnapshotScript() {
    const round = (value) => Math.round(value * 1000) / 1000;
    const rect = (element) => {
        const value = element.getBoundingClientRect();
        return {
            left: round(value.left),
            top: round(value.top),
            width: round(value.width),
            height: round(value.height)
        };
    };
    const status = document.querySelector('.learner-palette-settings__status');
    return {
        panel: rect(document.querySelector('.test-palette-panel')),
        settings: rect(document.querySelector('.learner-palette-settings')),
        header: rect(document.querySelector('.learner-palette-settings__header')),
        status: rect(status),
        statusMinWidth: getComputedStyle(status).minWidth,
        options: rect(document.querySelector('.learner-palette-options')),
        buttons: Array.from(document.querySelectorAll('.learner-palette-option')).map((button) => ({
            value: button.value,
            rect: rect(button),
            border: getComputedStyle(button).borderTopWidth
        }))
    };
}

async function testPracticeSummaryAndPaletteGeometry(browser) {
    const page = await browser.newPage({ viewport: { width: 900, height: 700 } });
    try {
        const tokensCss = readSource('src/styles/tokens.css');
        const componentsCss = readSource('src/styles/components.css');
        const indexInteractions = readSource('js/presentation/indexInteractions.js');
        await page.setContent(`<!doctype html>
            <html>
            <head>
                <style>
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    ${tokensCss}
                    ${componentsCss}
                    body { padding: 24px; }
                    .test-shell { width: 640px; }
                    .test-palette-panel { display: grid; justify-content: center; width: 640px; margin-top: 24px; }
                    #practice-view, .practice-view__header, .practice-summary-region { width: 100%; }
                    .practice-summary-region { min-height: 144px; }
                </style>
            </head>
            <body class="ds-learning" data-learner-palette="sage">
                <main class="test-shell">
                    <section id="practice-view">
                        <header class="practice-view__header">
                            <div class="practice-view__title-row">
                                <h2>Practice records</h2>
                                <button
                                    id="practice-summary-toggle"
                                    class="practice-summary-toggle"
                                    type="button"
                                    data-index-action="toggle-practice-summary"
                                    aria-controls="practice-summary-region"
                                    aria-expanded="true"
                                    aria-label="Collapse practice summary"
                                >
                                    <span class="practice-summary-toggle__glyph" aria-hidden="true"></span>
                                </button>
                            </div>
                        </header>
                        <div id="practice-summary-region" class="practice-summary-region">
                            <button id="summary-focus-target" type="button">Summary action</button>
                        </div>
                    </section>
                    <section class="test-palette-panel">
                        <div class="learner-palette-settings">
                            <div class="learner-palette-settings__header">
                                <h4>学习配色</h4>
                                <span class="learner-palette-settings__status">当前: 灰绿 / Sage</span>
                            </div>
                            <div class="learner-palette-options">
                                <button class="learner-palette-option" value="sage"><span>灰绿 / Sage</span></button>
                                <button class="learner-palette-option" value="steel"><span>蓝灰 / Steel</span></button>
                                <button class="learner-palette-option" value="mist"><span>青灰 / Mist</span></button>
                                <button class="learner-palette-option" value="warm"><span>暖沙 / Warm</span></button>
                            </div>
                        </div>
                    </section>
                </main>
            </body>
            </html>`);
        await page.addScriptTag({ content: indexInteractions });

        const expanded = await page.evaluate(geometrySnapshotScript);
        assert.equal(expanded.toggle.width, 36, 'practice summary toggle must have a stable 36px width');
        assert.equal(expanded.toggle.height, 36, 'practice summary toggle must have a stable 36px height');
        assert.deepEqual(
            expanded.toggleBorder,
            { top: '1px', right: '1px', bottom: '1px', left: '1px' },
            'practice summary toggle must keep a one-pixel border on every side'
        );

        await page.locator('#practice-summary-toggle').click();
        const collapsedControlState = await page.evaluate(() => {
            const view = document.getElementById('practice-view');
            const button = document.getElementById('practice-summary-toggle');
            const region = document.getElementById('practice-summary-region');
            return {
                collapsed: view.classList.contains('is-practice-summary-collapsed'),
                expanded: button.getAttribute('aria-expanded'),
                hidden: region.getAttribute('aria-hidden'),
                inert: region.inert
            };
        });
        const collapsedState = {
            ...collapsedControlState,
            geometry: await page.evaluate(geometrySnapshotScript)
        };
        assert.equal(collapsedState.collapsed, true, 'toggle must apply the visual collapse class');
        assert.equal(collapsedState.expanded, 'false', 'toggle must expose the collapsed control state');
        assert.equal(collapsedState.hidden, 'true', 'collapsed summary must be hidden from assistive technology');
        assert.equal(collapsedState.inert, true, 'collapsed summary must not retain interactive descendants');
        assert.equal(collapsedState.geometry.regionDisplay, 'none', 'collapse class must visually hide the summary region');
        assert.deepEqual(
            collapsedState.geometry.toggle,
            expanded.toggle,
            'the native toggle geometry must not collapse with the summary region'
        );
        assert.deepEqual(
            collapsedState.geometry.titleRow,
            expanded.titleRow,
            'the title row geometry must remain stable while the summary is collapsed'
        );

        await page.locator('#practice-summary-toggle').click();
        const reexpandedControlState = await page.evaluate(() => {
            const view = document.getElementById('practice-view');
            const button = document.getElementById('practice-summary-toggle');
            const region = document.getElementById('practice-summary-region');
            return {
                collapsed: view.classList.contains('is-practice-summary-collapsed'),
                expanded: button.getAttribute('aria-expanded'),
                hidden: region.getAttribute('aria-hidden'),
                inert: region.inert
            };
        });
        const reexpandedState = {
            ...reexpandedControlState,
            geometry: await page.evaluate(geometrySnapshotScript)
        };
        assert.equal(reexpandedState.collapsed, false, 'second toggle must restore the expanded class state');
        assert.equal(reexpandedState.expanded, 'true', 'second toggle must restore aria-expanded');
        assert.equal(reexpandedState.hidden, 'false', 'second toggle must expose the summary region');
        assert.equal(reexpandedState.inert, false, 'expanded summary controls must be interactive');
        assert.notEqual(reexpandedState.geometry.regionDisplay, 'none', 'expanded summary must be visible');

        const palettes = ['sage', 'steel', 'mist', 'warm'];
        const paletteLabels = {
            sage: '当前: 灰绿 / Sage',
            steel: '当前: 蓝灰 / Steel',
            mist: '当前: 青灰 / Mist',
            warm: '当前: 暖沙 / Warm'
        };
        const paletteSnapshots = {};
        const paletteControlSnapshots = {};
        for (const palette of palettes) {
            await page.evaluate(({ nextPalette, nextLabel }) => {
                document.body.setAttribute('data-learner-palette', nextPalette);
                document.querySelector('.learner-palette-settings__status').textContent = nextLabel;
            }, { nextPalette: palette, nextLabel: paletteLabels[palette] });
            paletteSnapshots[palette] = await page.evaluate(geometrySnapshotScript);
            paletteControlSnapshots[palette] = await page.evaluate(paletteGeometrySnapshotScript);
        }

        const baseline = paletteSnapshots.sage;
        for (const palette of palettes.slice(1)) {
            const snapshot = paletteSnapshots[palette];
            assert.deepEqual(snapshot.practiceView, baseline.practiceView, `${palette} must preserve the practice container geometry`);
            assert.deepEqual(snapshot.titleRow, baseline.titleRow, `${palette} must preserve the title row geometry`);
            assert.deepEqual(snapshot.toggle, baseline.toggle, `${palette} must preserve the toggle geometry`);
            assert.deepEqual(snapshot.toggleBorder, baseline.toggleBorder, `${palette} must preserve toggle border widths`);
            assert.deepEqual(snapshot.region, baseline.region, `${palette} must preserve the summary container geometry`);
        }

        const controlBaseline = paletteControlSnapshots.sage;
        assert.notEqual(controlBaseline.statusMinWidth, '0px', 'palette status must reserve a stable text slot');
        controlBaseline.buttons.forEach((button) => {
            assert.equal(button.border, '1px', `${button.value} palette control must keep a one-pixel border`);
        });
        for (const palette of palettes.slice(1)) {
            const snapshot = paletteControlSnapshots[palette];
            assert.deepEqual(snapshot.settings, controlBaseline.settings, `${palette} must preserve palette container geometry`);
            assert.deepEqual(snapshot.header, controlBaseline.header, `${palette} must preserve palette header geometry`);
            assert.deepEqual(snapshot.status, controlBaseline.status, `${palette} must preserve palette status geometry`);
            assert.deepEqual(snapshot.options, controlBaseline.options, `${palette} must preserve palette option grid geometry`);
            assert.deepEqual(snapshot.buttons, controlBaseline.buttons, `${palette} must preserve every palette control geometry`);
        }

        return { expanded, collapsed: collapsedState.geometry, paletteSnapshots, paletteControlSnapshots };
    } finally {
        await page.close();
    }
}

async function testPracticeBeforeBrowse(browser) {
    const page = await browser.newPage({ viewport: { width: 900, height: 700 } });
    try {
        await page.setContent(`<!doctype html>
            <html>
            <body>
                <nav class="main-nav">
                    <button class="nav-btn active" data-view="overview">Overview</button>
                    <button class="nav-btn" data-view="browse">Browse</button>
                    <button class="nav-btn" data-view="practice">Practice</button>
                </nav>
                <section id="overview-view" class="view active"></section>
                <section id="browse-view" class="view"></section>
                <section id="practice-view" class="view">
                    <button id="practice-widget" type="button" disabled>Practice widget</button>
                </section>
            </body>
            </html>`);

        await page.evaluate(() => {
            window.__practiceRuntime = {
                calls: [],
                browseReady: false,
                suiteReady: false,
                readyUpdates: 0,
                widgetClicks: 0
            };
            window.__browsePromise = new Promise((resolve) => {
                window.__resolveBrowse = () => {
                    window.__practiceRuntime.browseReady = true;
                    resolve(true);
                };
            });
            window.__suitePromise = new Promise((resolve) => {
                window.__resolveSuite = () => {
                    window.__practiceRuntime.suiteReady = true;
                    resolve(true);
                };
            });
            window.ensureBrowseGroup = () => {
                window.__practiceRuntime.calls.push('ensure-browse');
                return window.__browsePromise;
            };
            window.AppActions = {
                ensurePracticeSuite() {
                    window.__practiceRuntime.calls.push('ensure-practice-suite');
                    return window.__suitePromise;
                }
            };
            window.updatePracticeView = () => {
                const state = window.__practiceRuntime;
                state.calls.push(`update:${state.browseReady}:${state.suiteReady}`);
                if (!state.browseReady || !state.suiteReady) {
                    return;
                }
                const widget = document.getElementById('practice-widget');
                widget.disabled = false;
                widget.onclick = () => {
                    state.widgetClicks += 1;
                };
                state.readyUpdates += 1;
            };
        });

        await page.addScriptTag({ content: readSource('js/boot-fallbacks.js') });
        await page.evaluate(() => window.showView('practice'));

        const beforeDependencies = await page.evaluate(() => ({
            ...window.__practiceRuntime,
            practiceActive: document.getElementById('practice-view').classList.contains('active'),
            browseActive: document.getElementById('browse-view').classList.contains('active'),
            widgetDisabled: document.getElementById('practice-widget').disabled
        }));
        assert.equal(beforeDependencies.practiceActive, true, 'Practice must activate without a prior Browse visit');
        assert.equal(beforeDependencies.browseActive, false, 'Practice-first must not require activating Browse');
        assert.deepEqual(
            beforeDependencies.calls.slice(0, 2),
            ['ensure-browse', 'ensure-practice-suite'],
            'Practice-first must initialize both Browse dependencies and the Practice suite'
        );
        assert.equal(beforeDependencies.widgetDisabled, true, 'the widget must wait for both runtime dependencies');

        await page.evaluate(() => window.__resolveBrowse());
        await page.evaluate(() => Promise.resolve());
        const afterBrowseOnly = await page.evaluate(() => ({ ...window.__practiceRuntime }));
        assert.equal(afterBrowseOnly.readyUpdates, 0, 'Practice view must not claim readiness before the suite is ready');

        await page.evaluate(() => window.__resolveSuite());
        await page.waitForFunction(() => window.__practiceRuntime.readyUpdates === 1);
        await page.locator('#practice-widget').click();
        const ready = await page.evaluate(() => ({
            ...window.__practiceRuntime,
            widgetDisabled: document.getElementById('practice-widget').disabled
        }));
        assert.equal(ready.browseReady, true, 'Browse dependencies must be ready after Practice-first initialization');
        assert.equal(ready.suiteReady, true, 'Practice suite must be ready after Practice-first initialization');
        assert.equal(ready.widgetDisabled, false, 'Practice widget must become interactive after dependencies are ready');
        assert.equal(ready.widgetClicks, 1, 'Practice widget interaction must work without visiting Browse first');
        assert(
            ready.calls.includes('update:true:true'),
            'Practice view must refresh after both dependency promises resolve'
        );

        return { beforeDependencies, afterBrowseOnly, ready };
    } finally {
        await page.close();
    }
}

async function main() {
    const browser = await launchBrowser();
    try {
        const summaryAndPalette = await testPracticeSummaryAndPaletteGeometry(browser);
        const practiceBeforeBrowse = await testPracticeBeforeBrowse(browser);
        console.log(JSON.stringify({
            status: 'pass',
            detail: 'learner UI runtime stabilization regression tests passed',
            tests: {
                practiceSummaryToggle: 'pass',
                practiceBeforeBrowse: 'pass',
                paletteLayoutStability: 'pass'
            },
            evidence: {
                expandedToggle: summaryAndPalette.expanded.toggle,
                collapsedToggle: summaryAndPalette.collapsed.toggle,
                practiceFirstCalls: practiceBeforeBrowse.ready.calls,
                widgetClicks: practiceBeforeBrowse.ready.widgetClicks
            }
        }, null, 2));
    } finally {
        await browser.close();
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
});
