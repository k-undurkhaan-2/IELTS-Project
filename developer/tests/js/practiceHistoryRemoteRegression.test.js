#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
const root = process.env.IELTS_TEST_SOURCE_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
function harness(api = {}) {
    const history = [{ id: 'kept', type: 'listening', score: 1, date: '2026-11-23', duration: 216 }];
    const state = new Map([['practice_records', history]]);
    const window = { ExamData: {}, location: { pathname: '/', search: '', href: '/' } };
    const context = vm.createContext({ window, console: { warn() {}, error() {} }, Map, Set, Promise, Error });
    for (const file of ['js/data/dataSources/remotePracticeDataSource.js', 'js/data/repositories/baseRepository.js', 'js/data/repositories/practiceRepository.js', 'js/views/legacyViewBundle.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context, { filename: file });
    }
    const local = {
        async read(key, fallback) { return state.get(key) ?? fallback; },
        async write(key, value) { state.set(key, value); return true; },
        async remove(key) { state.delete(key); return true; }
    };
    const client = { isAuthenticated: () => true, ...api };
    const source = new window.ExamData.RemotePracticeDataSource(local, client);
    return { window, state, history, client, source, repo: new window.ExamData.PracticeRepository(source) };
}
async function deadline(work) {
    let timer;
    try { return await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('practice write queue deadlocked')), 300); })]); }
    finally { clearTimeout(timer); }
}
test('saving a remote attempt and deleting it leave the queue usable', async () => {
    let remote = [];
    const h = harness({
        async listPracticeRecords() { return remote; },
        async syncPracticeRecords(records) { remote = records; return { ok: true }; },
        async replacePracticeRecords(records) { remote = records; return records; }
    });
    const attempt = { id: 'attempt', type: 'listening', score: 1, date: '2026-11-23', duration: 216 };
    await deadline(h.repo.upsert(attempt));
    assert.equal(remote[0].duration, 216);
    assert.equal(await deadline(h.repo.removeById('attempt')), 1);
    await deadline(h.repo.upsert({ ...attempt, id: 'next-attempt' }));
    assert.deepEqual(Array.from(remote, r => r.id), ['next-attempt']);
});
for (const status of [0, 401, 403, 500]) for (const operation of ['replace', 'clear']) {
    test(`${operation} failure (${status}) preserves the mirror and rejects visibly`, async () => {
        const error = Object.assign(new Error('failed'), { status, payload: status === 403 ? { requiresDataManageStepUp: true, authActionStart: '/auth/business/data/start' } : {} });
        const h = harness({ async replacePracticeRecords() { throw error; }, async clearPracticeRecords() { throw error; } });
        await assert.rejects(() => operation === 'replace' ? h.source.write('practice_records', []) : h.source.remove('practice_records'), e => e === error);
        assert.deepEqual(h.state.get('practice_records'), h.history);
    });
}
test('history retains the same minute and second precision as the listening clock', () => {
    const h = harness();
    for (const [seconds, expected] of [[0,'00:00'],[5,'00:05'],[59,'00:59'],[60,'01:00'],[216,'03:36'],[426,'07:06'],[3907,'65:07']]) {
        assert.equal(h.window.PracticeHistoryRenderer.helpers.formatDurationShort(seconds), expected);
    }
});
