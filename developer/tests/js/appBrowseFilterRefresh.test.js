#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

function createHarness(storedFilter) {
    const storedData = new Map();
    if (storedFilter) storedData.set('browse_filter', storedFilter);
    const preferences = new Map();
    const storageReads = [];
    const activatedFilters = [];
    const context = {
        console: { log() {}, warn() {}, error() {}, info() {} },
        addEventListener() {},
        document: {
            addEventListener() {},
            getElementById() { return null; },
            querySelector() { return null; },
            querySelectorAll() { return []; }
        },
        localStorage: {
            getItem(key) { return preferences.get(key) ?? null; },
            setItem(key, value) { preferences.set(key, String(value)); }
        },
        storage: {
            async get(key, fallback) {
                storageReads.push(key);
                return storedData.has(key) ? storedData.get(key) : fallback;
            }
        }
    };
    context.window = context;
    vm.createContext(context);
    for (const relativePath of ['js/app/state-service.js', 'js/utils/BrowsePreferencesUtils.js', 'js/app.js']) {
        const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
        vm.runInContext(source, context, { filename: relativePath });
    }
    const app = vm.runInContext('new ExamSystemApp()', context);
    context.appStateService.connectApp(app);
    app.currentView = 'browse';
    app.onViewActivated = (view) => {
        assert.equal(view, 'browse');
        activatedFilters.push({ ...context.getPersistedBrowseFilter() });
    };
    return { app, context, storedData, storageReads, activatedFilters };
}

function assertFilter(harness, expected) {
    assert.deepEqual({ ...harness.app.getState('ui.browseFilter') }, expected);
    assert.deepEqual({ ...harness.context.appStateService.getBrowseFilter() }, expected);
    assert.deepEqual({ ...harness.context.getPersistedBrowseFilter() }, expected);
}

test('initial loading still restores the saved browse filter', async () => {
    const savedFilter = { category: 'P1', type: 'reading' };
    const harness = createHarness(savedFilter);
    await harness.app.loadInitialData();
    assertFilter(harness, savedFilter);
    assert.ok(harness.storageReads.includes('browse_filter'));
});

for (const storedFilter of [undefined, { category: 'P1', type: 'listening' }]) {
    test(`returning from reading preserves the active filter with ${storedFilter ? 'stale' : 'missing'} saved state`, async () => {
        const harness = createHarness(storedFilter);
        await harness.app.loadInitialData();
        const selectedFilter = { category: 'P2', type: 'reading' };
        harness.context.appStateService.setBrowseFilter(selectedFilter);

        const updatedRecords = [{ examId: 'reading-p2', accuracy: 0.8 }];
        harness.storedData.set('exam_index', [{ id: 'reading-p2', category: 'P2', type: 'reading' }]);
        harness.storedData.set('practice_records', updatedRecords);
        harness.storedData.set('user_stats', { totalPractices: 1 });
        harness.storageReads.length = 0;

        await harness.app.refreshData();

        assertFilter(harness, selectedFilter);
        assert.deepEqual(harness.activatedFilters, [selectedFilter]);
        assert.equal(harness.app.getState('exam.index')[0].id, 'reading-p2');
        assert.deepEqual(harness.app.getState('practice.records'), updatedRecords);
        assert.equal(harness.app.userStats.totalPractices, 1);
        assert.equal(harness.storageReads.includes('browse_filter'), false);
    });
}

test('a filter selected during an asynchronous refresh remains selected', async () => {
    const harness = createHarness({ category: 'P1', type: 'reading' });
    await harness.app.loadInitialData();
    harness.context.appStateService.setBrowseFilter({ category: 'P2', type: 'reading' });

    const originalGet = harness.context.storage.get;
    let releaseExamIndex;
    harness.context.storage.get = (key, fallback) => key === 'exam_index'
        ? new Promise((resolve) => { releaseExamIndex = resolve; })
        : originalGet(key, fallback);
    const refreshing = harness.app.refreshData();
    const latestFilter = { category: 'P3', type: 'reading' };
    harness.context.appStateService.setBrowseFilter(latestFilter);
    releaseExamIndex([]);
    await refreshing;

    assertFilter(harness, latestFilter);
    assert.deepEqual(harness.activatedFilters, [latestFilter]);
});
