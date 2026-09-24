#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { getBundleProfile } from '../../../scripts/bundle-manifest.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const storageKey = 'ielts.learnerPalette';
const palettes = ['sage', 'steel', 'mist', 'warm'];
const paletteLabels = {
    sage: '灰绿 / Sage',
    steel: '蓝灰 / Steel',
    mist: '青灰 / Mist',
    warm: '暖沙 / Warm'
};

function readRepoFile(relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function getUiShellBundleContract(profileName) {
    const profile = getBundleProfile(profileName);
    assert.equal(profile.name, profileName, `${profileName} profile should be available`);
    const bundle = profile.bundles.find((entry) => entry.outputPath === 'js/bundles/ui-shell.bundle.js');
    assert.ok(bundle, `${profileName} profile should declare ui-shell.bundle.js`);
    assert.ok(
        bundle.inputs.includes('js/app/main-entry.js'),
        `${profileName} ui-shell should include main-entry.js`
    );
    return bundle;
}

function readBundleSectionOrder(bundleSource) {
    return Array.from(
        bundleSource.matchAll(/^\/\* ===== (.+?) ===== \*\/$/gm),
        (match) => match[1]
    ).filter((section) => section !== 'bundle provided script markers');
}

function readBundleSection(bundleSource, inputPath, inputs) {
    const inputIndex = inputs.indexOf(inputPath);
    assert.notEqual(inputIndex, -1, `${inputPath} should be declared by the canonical manifest`);
    const startMarker = `/* ===== ${inputPath} ===== */`;
    const nextInput = inputs[inputIndex + 1];
    const endMarker = nextInput
        ? `/* ===== ${nextInput} ===== */`
        : '/* ===== bundle provided script markers ===== */';
    const start = bundleSource.indexOf(startMarker);
    const end = bundleSource.indexOf(endMarker, start + startMarker.length);
    assert.notEqual(start, -1, `bundle should contain the ${inputPath} source marker`);
    assert.notEqual(end, -1, `bundle should contain the marker following ${inputPath}`);
    return bundleSource.slice(start + startMarker.length, end).trim();
}

function createClassList(initialValues = []) {
    const values = new Set(initialValues.map(String));
    return {
        add(...names) {
            names.forEach((name) => values.add(String(name)));
        },
        remove(...names) {
            names.forEach((name) => values.delete(String(name)));
        },
        contains(name) {
            return values.has(String(name));
        },
        toggle(name, force) {
            const normalized = String(name);
            const enabled = force === undefined ? !values.has(normalized) : Boolean(force);
            if (enabled) values.add(normalized);
            else values.delete(normalized);
            return enabled;
        }
    };
}

function createStorage(seed = {}, options = {}) {
    const state = new Map(Object.entries(seed).map(([key, value]) => [key, String(value)]));
    const setCalls = [];
    return {
        getItem(key) {
            if (options.getError) throw options.getError;
            return state.has(key) ? state.get(key) : null;
        },
        setItem(key, value) {
            if (options.setError) throw options.setError;
            const normalizedValue = String(value);
            setCalls.push([String(key), normalizedValue]);
            state.set(String(key), normalizedValue);
        },
        dump() {
            return Object.fromEntries(state.entries());
        },
        setCalls
    };
}

function createButton(value) {
    const attributes = new Map([['aria-pressed', 'false']]);
    const listeners = new Map();
    return {
        value,
        textContent: paletteLabels[value],
        classList: createClassList(['learner-palette-option']),
        setAttribute(name, nextValue) {
            attributes.set(String(name), String(nextValue));
        },
        getAttribute(name) {
            return attributes.has(String(name)) ? attributes.get(String(name)) : null;
        },
        addEventListener(type, callback) {
            const eventType = String(type);
            const callbacks = listeners.get(eventType) || [];
            callbacks.push(callback);
            listeners.set(eventType, callbacks);
        },
        click() {
            const event = {
                defaultPrevented: false,
                preventDefault() {
                    this.defaultPrevented = true;
                }
            };
            (listeners.get('click') || []).forEach((callback) => callback(event));
            return event;
        },
        listenerCount(type) {
            return (listeners.get(String(type)) || []).length;
        }
    };
}

function createStatus() {
    let value = '';
    return {
        writes: 0,
        get textContent() {
            return value;
        },
        set textContent(nextValue) {
            this.writes += 1;
            value = String(nextValue);
        },
        resetWrites() {
            this.writes = 0;
        }
    };
}

function createPaletteDom(options = {}) {
    const buttons = (options.buttonValues || palettes).map(createButton);
    const status = options.includeStatus === false ? null : createStatus();
    const container = options.includeContainer === false ? null : {
        querySelectorAll(selector) {
            return selector === '.learner-palette-option[value]' ? buttons : [];
        },
        querySelector(selector) {
            return selector === '.learner-palette-settings__status' ? status : null;
        }
    };
    return { buttons, container, status };
}

function injectPaletteTestHooks(source) {
    const closing = "})(typeof window !== 'undefined' ? window : this);";
    const closingIndex = source.lastIndexOf(closing);
    assert.notEqual(closingIndex, -1, 'main-entry.js should retain its IIFE boundary');
    const hooks = `
    global.__learnerPaletteTestHooks = {
        normalizeLearnerPalette: normalizeLearnerPalette,
        readLearnerPalettePreference: readLearnerPalettePreference,
        applyLearnerPalette: applyLearnerPalette,
        initializeLearnerPalette: initializeLearnerPalette,
        syncLearnerPaletteSettings: syncLearnerPaletteSettings,
        setupLearnerPaletteSettings: setupLearnerPaletteSettings
    };
`;
    return source.slice(0, closingIndex) + hooks + source.slice(closingIndex);
}

function createHarness(options = {}) {
    const bodyAttributes = new Map();
    const body = options.includeBody === false ? null : {
        classList: createClassList(options.learningBody === false ? [] : ['ds-learning']),
        setAttribute(name, value) {
            bodyAttributes.set(String(name), String(value));
        },
        getAttribute(name) {
            return bodyAttributes.has(String(name)) ? bodyAttributes.get(String(name)) : null;
        }
    };
    let paletteDom = createPaletteDom(options);

    const documentListeners = new Map();
    const windowListeners = new Map();
    const document = {
        body,
        readyState: 'loading',
        addEventListener(type, callback) {
            documentListeners.set(String(type), callback);
        },
        querySelector(selector) {
            return selector === '.learner-palette-settings' ? paletteDom.container : null;
        }
    };
    const storage = createStorage(options.storageSeed, options.storageOptions);
    const window = {
        document,
        localStorage: options.storageAvailable === false ? undefined : storage,
        addEventListener(type, callback) {
            windowListeners.set(String(type), callback);
        }
    };
    const context = vm.createContext({
        window,
        document,
        console: { log() {}, warn() {}, error() {} },
        setTimeout() { return 1; },
        clearTimeout() {},
        Promise,
        URL,
        URLSearchParams
    });
    const source = injectPaletteTestHooks(readRepoFile('js/app/main-entry.js'));
    vm.runInContext(source, context, { filename: 'js/app/main-entry.js' });
    return {
        body,
        bodyAttributes,
        get buttons() {
            return paletteDom.buttons;
        },
        get container() {
            return paletteDom.container;
        },
        documentListeners,
        hooks: window.__learnerPaletteTestHooks,
        replacePaletteDom(nextOptions = {}) {
            paletteDom = createPaletteDom(nextOptions);
            return paletteDom;
        },
        get status() {
            return paletteDom.status;
        },
        storage,
        windowListeners
    };
}

function assertSelectedPalette(harness, palette) {
    assert.equal(harness.body?.getAttribute('data-learner-palette'), palette);
    harness.buttons.forEach((button) => {
        const selected = button.value === palette;
        assert.equal(button.getAttribute('aria-pressed'), selected ? 'true' : 'false');
        assert.equal(button.classList.contains('active'), selected);
    });
    if (harness.status) {
        assert.equal(harness.status.textContent, `当前: ${paletteLabels[palette]}`);
    }
}

test('default palette is sage before Settings is opened and Settings later synchronizes', () => {
    const startup = createHarness({ includeContainer: false });
    assert.equal(startup.hooks.readLearnerPalettePreference(), 'sage');
    assert.equal(startup.hooks.initializeLearnerPalette(), undefined);
    assert.equal(startup.body.getAttribute('data-learner-palette'), 'sage');

    const settings = createHarness();
    settings.hooks.initializeLearnerPalette();
    settings.hooks.setupLearnerPaletteSettings();
    assertSelectedPalette(settings, 'sage');

    const source = readRepoFile('js/app/main-entry.js');
    assert.ok(
        source.indexOf('initializeLearnerPalette();') < source.indexOf('initializeNavigationShell();'),
        'startup should restore the palette before navigation and Settings initialization'
    );
});

test('pre-paint evaluation restores every legal palette and safely falls back before DOM ready', () => {
    for (const palette of palettes) {
        const harness = createHarness({
            includeContainer: false,
            storageSeed: { [storageKey]: palette }
        });
        assert.equal(
            harness.body.getAttribute('data-learner-palette'),
            palette,
            `${palette} should be applied while document.readyState is still loading`
        );
    }

    for (const value of [undefined, '', 'unknown', '{"palette":"warm"}']) {
        const storageSeed = value === undefined ? {} : { [storageKey]: value };
        const harness = createHarness({ includeContainer: false, storageSeed });
        assert.equal(harness.body.getAttribute('data-learner-palette'), 'sage');
    }

    const throwing = createHarness({
        includeContainer: false,
        storageOptions: { getError: new Error('getItem blocked') }
    });
    assert.equal(throwing.body.getAttribute('data-learner-palette'), 'sage');

    const unavailable = createHarness({ includeContainer: false, storageAvailable: false });
    assert.equal(unavailable.body.getAttribute('data-learner-palette'), 'sage');

    const index = readRepoFile('index.html');
    const uiShellTag = '<script src="js/bundles/ui-shell.bundle.js"></script>';
    assert.equal(index.split(uiShellTag).length - 1, 1, 'ui-shell bundle should load exactly once');
    assert.ok(
        index.indexOf(uiShellTag) > index.indexOf('<body') &&
        index.indexOf(uiShellTag) < index.indexOf('<div id="boot-overlay"'),
        'the existing ui-shell bundle should block first body paint before visible learner content'
    );
    assert.equal(/<script(?![^>]*\bsrc=)[^>]*>/i.test(index), false, 'pre-paint restore must not add inline runtime');
});

test('all four legal palettes update the DOM, status, control state, and storage', () => {
    for (const palette of palettes) {
        const harness = createHarness();
        harness.hooks.setupLearnerPaletteSettings();
        harness.buttons.forEach((button) => assert.equal(button.listenerCount('click'), 1));
        const selectedButton = harness.buttons.find((button) => button.value === palette);
        const event = selectedButton.click();
        assert.equal(event.defaultPrevented, true);
        assertSelectedPalette(harness, palette);
        assert.equal(harness.storage.getItem(storageKey), palette);
        assert.deepEqual(harness.storage.setCalls, [[storageKey, palette]]);
    }
});

test('the last selection persists across reload/re-entry and normalization is stable', () => {
    const firstLoad = createHarness();
    firstLoad.hooks.setupLearnerPaletteSettings();
    firstLoad.buttons.find((button) => button.value === 'steel').click();
    firstLoad.buttons.find((button) => button.value === 'mist').click();
    firstLoad.buttons.find((button) => button.value === 'warm').click();
    assert.equal(firstLoad.storage.getItem(storageKey), 'warm');

    const refreshed = createHarness({ storageSeed: firstLoad.storage.dump() });
    refreshed.hooks.initializeLearnerPalette();
    refreshed.hooks.setupLearnerPaletteSettings();
    assertSelectedPalette(refreshed, 'warm');
    assert.equal(refreshed.storage.setCalls.length, 0, 'restore should not rewrite storage');
    assert.equal(refreshed.hooks.applyLearnerPalette(' WARM ', false), 'warm');
});

test('repeated Settings initialization does not attach duplicate palette handlers', () => {
    const harness = createHarness();
    harness.hooks.setupLearnerPaletteSettings();
    harness.hooks.setupLearnerPaletteSettings();
    harness.hooks.setupLearnerPaletteSettings();
    harness.buttons.forEach((button) => {
        assert.equal(
            button.listenerCount('click'),
            1,
            `${button.value} should retain exactly one click handler after repeated setup`
        );
    });

    const warmButton = harness.buttons.find((button) => button.value === 'warm');
    let unrelatedListenerCalls = 0;
    warmButton.addEventListener('click', () => { unrelatedListenerCalls += 1; });
    harness.storage.setCalls.length = 0;
    harness.status.resetWrites();
    warmButton.click();
    assert.equal(unrelatedListenerCalls, 1, 'unrelated listeners must remain intact');
    assert.deepEqual(harness.storage.setCalls, [[storageKey, 'warm']], 'one click should write storage once');
    assert.equal(harness.status.writes, 1, 'one click should synchronize status once');
    assertSelectedPalette(harness, 'warm');
});

test('rebuilt Settings DOM receives one handler per new option without disturbing old nodes', () => {
    const harness = createHarness();
    harness.hooks.setupLearnerPaletteSettings();
    const oldWarmButton = harness.buttons.find((button) => button.value === 'warm');
    let oldExternalCalls = 0;
    oldWarmButton.addEventListener('click', () => { oldExternalCalls += 1; });

    const rebuilt = harness.replacePaletteDom();
    harness.hooks.setupLearnerPaletteSettings();
    harness.hooks.setupLearnerPaletteSettings();
    rebuilt.buttons.forEach((button) => {
        assert.equal(button.listenerCount('click'), 1, `${button.value} rebuilt option should bind once`);
    });

    harness.storage.setCalls.length = 0;
    rebuilt.status.resetWrites();
    rebuilt.buttons.find((button) => button.value === 'steel').click();
    assert.deepEqual(harness.storage.setCalls, [[storageKey, 'steel']]);
    assert.equal(rebuilt.status.writes, 1);
    assertSelectedPalette(harness, 'steel');

    oldWarmButton.click();
    assert.equal(oldExternalCalls, 1, 'rebuilding Settings must not remove listeners from old nodes');
});

test('missing, empty, malformed, and unknown storage values safely fall back to sage', () => {
    const invalidValues = [undefined, '', 'unknown', '{"palette":"steel"}', '\u0000steel', '[]'];
    for (const value of invalidValues) {
        const storageSeed = value === undefined ? {} : { [storageKey]: value };
        const harness = createHarness({ storageSeed, includeContainer: false });
        assert.doesNotThrow(() => harness.hooks.initializeLearnerPalette());
        assert.equal(harness.body.getAttribute('data-learner-palette'), 'sage');
    }
});

test('storage get/set exceptions and unavailable storage never abort palette application', () => {
    const getFailure = createHarness({
        includeContainer: false,
        storageOptions: { getError: new Error('getItem unavailable') }
    });
    assert.doesNotThrow(() => getFailure.hooks.initializeLearnerPalette());
    assert.equal(getFailure.body.getAttribute('data-learner-palette'), 'sage');

    const setFailure = createHarness({
        includeContainer: false,
        storageOptions: { setError: new Error('setItem unavailable') }
    });
    assert.doesNotThrow(() => setFailure.hooks.applyLearnerPalette('mist', true));
    assert.equal(setFailure.body.getAttribute('data-learner-palette'), 'mist');

    const unavailable = createHarness({ includeContainer: false, storageAvailable: false });
    assert.doesNotThrow(() => unavailable.hooks.initializeLearnerPalette());
    assert.equal(unavailable.body.getAttribute('data-learner-palette'), 'sage');
    assert.doesNotThrow(() => unavailable.hooks.applyLearnerPalette('warm', true));
    assert.equal(unavailable.body.getAttribute('data-learner-palette'), 'warm');
});

test('missing status, missing option, missing container, and missing body are tolerated', () => {
    const missingContainer = createHarness({ includeContainer: false });
    assert.doesNotThrow(() => missingContainer.hooks.setupLearnerPaletteSettings());

    const missingStatusAndOption = createHarness({
        includeStatus: false,
        buttonValues: ['sage', 'steel', 'warm']
    });
    assert.doesNotThrow(() => missingStatusAndOption.hooks.setupLearnerPaletteSettings());
    assert.doesNotThrow(() => missingStatusAndOption.buttons[1].click());
    assert.equal(missingStatusAndOption.body.getAttribute('data-learner-palette'), 'steel');

    const missingBody = createHarness({ includeBody: false, includeContainer: false });
    assert.equal(missingBody.hooks.applyLearnerPalette('mist', true), 'mist');
    assert.equal(missingBody.storage.getItem(storageKey), 'mist');
});

test('four palette selectors expose the complete core token set and sage is the no-attribute fallback', () => {
    const tokens = readRepoFile('src/styles/tokens.css');
    const coreTokens = [
        '--learner-accent',
        '--learner-accent-hover',
        '--learner-accent-soft',
        '--learner-selected-surface',
        '--learner-selected-border',
        '--learner-selected-text',
        '--learner-secondary-surface',
        '--learner-secondary-border',
        '--learner-secondary-hover',
        '--learner-card-surface',
        '--learner-card-subtle',
        '--learner-border',
        '--learner-text',
        '--learner-text-muted',
        '--color-brand-primary',
        '--color-brand-secondary',
        '--color-brand-gradient'
    ];

    const sageMatch = tokens.match(/body\.ds-learning,\s*body\.ds-learning\[data-learner-palette="sage"\]\s*\{([\s\S]*?)\n\}/);
    assert.ok(sageMatch, 'sage should share the base body.ds-learning fallback selector');
    for (const token of coreTokens) {
        assert.ok(sageMatch[1].includes(`${token}:`), `sage fallback should define ${token}`);
    }

    for (const palette of palettes.slice(1)) {
        const pattern = new RegExp(`body\\.ds-learning\\[data-learner-palette="${palette}"\\]\\s*\\{([\\s\\S]*?)\\n\\}`);
        const match = tokens.match(pattern);
        assert.ok(match, `${palette} palette selector should exist`);
        for (const token of coreTokens) {
            assert.ok(match[1].includes(`${token}:`), `${palette} should define ${token}`);
        }
    }

    for (const palette of palettes) {
        assert.ok(
            tokens.includes(`.learner-palette-option[value="${palette}"]`),
            `${palette} swatch selector should exist`
        );
    }

    const index = readRepoFile('index.html');
    const optionValues = Array.from(
        index.matchAll(/class="learner-palette-option"[\s\S]*?value="([^"]+)"/g),
        (match) => match[1]
    );
    assert.deepEqual(optionValues, palettes);
    assert.equal(/<body[^>]*data-learner-palette=/i.test(index), false, 'body should rely on pre-paint restore plus the CSS sage fallback');
});

test('main-entry source and root/VIP ui-shell bundles follow the canonical manifest', () => {
    const source = readRepoFile('js/app/main-entry.js').replace(/\r\n?/g, '\n').trim();
    const rootBundle = readRepoFile('js/bundles/ui-shell.bundle.js').replace(/\r\n?/g, '\n');
    const vipBundle = readRepoFile('ListeningPractice/vip special/js/bundles/ui-shell.bundle.js')
        .replace(/\r\n?/g, '\n');
    const defaultContract = getUiShellBundleContract('default');
    const vipContract = getUiShellBundleContract('vip');

    assert.deepEqual(
        vipContract.inputs,
        defaultContract.inputs,
        'default and VIP ui-shell source order should share the canonical manifest contract'
    );
    assert.deepEqual(
        readBundleSectionOrder(rootBundle),
        [...defaultContract.inputs],
        'root ui-shell section order should match the default canonical manifest'
    );
    assert.deepEqual(
        readBundleSectionOrder(vipBundle),
        [...vipContract.inputs],
        'VIP ui-shell section order should match the VIP canonical manifest'
    );
    assert.equal(
        readBundleSection(rootBundle, 'js/app/main-entry.js', defaultContract.inputs),
        source,
        'root ui-shell should contain the current main-entry source'
    );
    assert.equal(
        readBundleSection(vipBundle, 'js/app/main-entry.js', vipContract.inputs),
        source,
        'VIP ui-shell should contain the current main-entry source'
    );
    assert.equal(
        readRepoFile('js/bundles/legacy-app.bundle.js').includes(storageKey),
        false,
        'PR #4 legacy bundle must not be required for learner palette behavior'
    );
});
