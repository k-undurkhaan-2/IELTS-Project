#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

import { BUNDLE_PROFILES } from '../../../scripts/bundle-manifest.mjs';
import { normalizeEol, renderBundle } from '../../../scripts/build-bundles.mjs';

const repoRoot = new URL('../../../', import.meta.url);
const read = (relativePath) => fs.readFileSync(new URL(relativePath, repoRoot), 'utf8');
const window = {};
const context = vm.createContext({ window, console, Date });
vm.runInContext(read('js/core/practiceCore.js'), context);
vm.runInContext(read('js/views/legacyViewBundle.js').replace(
    '})(window);',
    'global.calculateHeatmap = calculatePracticeHeatmapData;\n})(window);'
), context);
const calculateHeatmap = window.calculateHeatmap;

function dailyCounts(records, year = 2026, month = 4) {
    const result = calculateHeatmap(records, new Date(year, month, 1));
    return Object.fromEntries(result.cells.filter((cell) => cell.count > 0)
        .map((cell) => [cell.dateKey, cell.count]));
}

function inTimezone(timezone, callback) {
    const previous = process.env.TZ;
    process.env.TZ = timezone;
    try {
        callback();
    } finally {
        if (previous === undefined) delete process.env.TZ;
        else process.env.TZ = previous;
    }
}

test('saving historical records preserves their practice dates and daily intensity', () => {
    const records = ['2026-05-01T08:00:00', '2026-05-01T11:00:00', '2026-05-12T16:00:00']
        .map((date, index) => window.PracticeCore.contracts.standardizeRecord({
            id: `historical-${index}`, type: 'reading', date, totalQuestions: 13
        }));
    assert.deepEqual(dailyCounts(records), { '2026-05-01': 2, '2026-05-12': 1 });
    const result = calculateHeatmap(records, new Date(2026, 4, 1));
    assert.equal(result.total, 3);
    assert.equal(result.activeDays, 2);
    assert.equal(result.averageSetsPerActiveDay, 1.5);
    assert(result.cells.find((cell) => cell.dateKey === '2026-05-01').level
        > result.cells.find((cell) => cell.dateKey === '2026-05-12').level);
});

test('explicit practice dates take precedence over completion and persistence timestamps', () => {
    const records = Object.freeze([
        Object.freeze({ date: '2026-05-01T23:50:00', endTime: '2026-05-02T00:15:00',
            createdAt: '2026-06-01T12:00:00', updatedAt: '2026-07-01T12:00:00' }),
        Object.freeze({ metadata: Object.freeze({ date: '2026-05-12' }),
            date: '2026-06-01T12:00:00', endTime: '2026-06-01T12:00:00' })
    ]);
    assert.deepEqual(dailyCounts(records), { '2026-05-01': 1, '2026-05-12': 1 });
    assert.deepEqual(dailyCounts(records, 2026, 5), {});
});

test('legacy and nested practice times are used before record creation time', () => {
    const practiceDate = '2026-05-12T10:30:00';
    const candidates = [
        { date: 'invalid', endTime: practiceDate, startTime: '2026-05-11T23:50:00' },
        { completedAt: practiceDate },
        { timestamp: practiceDate },
        { startTime: practiceDate },
        { startedAt: practiceDate },
        { realData: { date: practiceDate } },
        { realData: { endTime: practiceDate } },
        { realData: { completedAt: practiceDate } },
        { realData: { timestamp: practiceDate } },
        { realData: { startTime: practiceDate } },
        { realData: { startedAt: practiceDate } },
        { metadata: { completedAt: practiceDate } },
        { metadata: { startedAt: practiceDate } }
    ].map((record) => ({ ...record, createdAt: '2026-06-01T12:00:00', updatedAt: '2026-07-01T12:00:00' }));
    assert.deepEqual(dailyCounts(candidates), { '2026-05-12': candidates.length });
    for (const record of [
        { createdAt: practiceDate },
        { realData: { createdAt: practiceDate } },
        { metadata: { createdAt: practiceDate } }
    ]) {
        assert.deepEqual(dailyCounts([record]), { '2026-05-12': 1 });
    }
});

test('numeric timestamps in seconds or milliseconds, including strings, share the same day', () => {
    const instant = new Date(2026, 4, 12, 10, 30);
    const milliseconds = instant.getTime();
    const timestamps = [instant, instant.toISOString(), milliseconds, String(milliseconds),
        milliseconds / 1000, String(milliseconds / 1000), ` ${milliseconds} `];
    assert.deepEqual(dailyCounts(timestamps.map((timestamp) => ({ timestamp }))), {
        '2026-05-12': timestamps.length
    });
});

test('missing and invalid timestamps do not become activity on the update date', () => {
    const invalidValues = [null, undefined, '', ' ', false, true, {}, [], NaN, Infinity,
        'not-a-date', '2026-02-30', '2026-13-01', 1e20, '99999999999999999'];
    const records = [null, undefined, {}, ...invalidValues.map((date) => ({
        date, updatedAt: '2026-05-12T10:30:00'
    }))];
    assert.deepEqual(dailyCounts(records), {});
    assert.equal(calculateHeatmap(records, new Date(2026, 4, 1)).averageSetsPerActiveDay, 0);
    assert.deepEqual(dailyCounts([{ date: '2026-02-30', endTime: '2026-05-12T10:30:00' }]), {
        '2026-05-12': 1
    });
});

for (const timezone of ['UTC', 'Asia/Shanghai', 'America/Los_Angeles']) {
    test(`calendar dates and timestamp month boundaries use local days in ${timezone}`, () => {
        inTimezone(timezone, () => {
            assert.deepEqual(dailyCounts([{ date: '2026-05-01' }, { date: '2026-05-31' }]), {
                '2026-05-01': 1, '2026-05-31': 1
            });
            const records = [{ timestamp: '2026-04-30T16:30:00Z' }, { timestamp: '2026-05-01T01:30:00Z' }];
            assert.deepEqual(dailyCounts(records), timezone === 'Asia/Shanghai'
                ? { '2026-05-01': 2 } : (timezone === 'UTC' ? { '2026-05-01': 1 } : {}));
            assert.deepEqual(dailyCounts(records, 2026, 3), timezone === 'America/Los_Angeles'
                ? { '2026-04-30': 2 } : (timezone === 'UTC' ? { '2026-04-30': 1 } : {}));
            const december = calculateHeatmap([{ date: '2025-12-31' }], new Date(2025, 11, 1));
            assert.equal(december.total, 1);
            const leapMonth = calculateHeatmap([{ date: '2024-02-29' }], new Date(2024, 1, 1));
            assert.equal(leapMonth.cells.filter((cell) => cell.inMonth).length, 29);
            assert.equal(leapMonth.total, 1);
            const march = calculateHeatmap([{ date: '2026-03-08' }, { date: '2026-03-09' }], new Date(2026, 2, 1));
            assert.equal(march.activeDays, 2);
            assert.equal(new Set(march.cells.map((cell) => cell.dateKey)).size, march.cells.length);
        });
    });
}

test('both shipped browse bundles match the canonical sources', () => {
    for (const profile of Object.values(BUNDLE_PROFILES)) {
        const bundle = profile.bundles.find((entry) => entry.outputPath === 'js/bundles/browse.bundle.js');
        assert(normalizeEol(read(`${profile.outputRoot}/${bundle.outputPath}`))
            === renderBundle(profile.name, bundle.inputs), `${profile.name} browse bundle is stale`);
    }
});
