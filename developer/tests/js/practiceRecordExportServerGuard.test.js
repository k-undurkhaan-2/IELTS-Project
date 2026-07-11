#!/usr/bin/env node
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { webcrypto } from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');

function load(relativePath, context) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    vm.runInContext(source, context, { filename: relativePath });
}

function normalizeSource(value) {
    return String(value).replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
}

function extractBundleSection(bundleSource, sourcePath) {
    const marker = '/* ===== ' + sourcePath + ' ===== */';
    const start = bundleSource.indexOf(marker);
    assert(start >= 0, 'missing bundle section: ' + sourcePath);
    const contentStart = start + marker.length;
    const end = bundleSource.indexOf('\n/* ===== ', contentStart);
    assert(end > contentStart, 'missing bundle section end: ' + sourcePath);
    return normalizeSource(bundleSource.slice(contentStart, end));
}

{
    const fetchCalls = [];
    const windowStub = {
        ExamData: {},
        async fetch(url, options = {}) {
            fetchCalls.push([url, options]);
            return {
                status: 200,
                ok: true,
                async text() {
                    return JSON.stringify({ records: [{ id: 'remote-record' }] });
                }
            };
        }
    };
    const context = vm.createContext({ window: windowStub, console, JSON, Promise, Error });
    load('js/data/remoteApiClient.js', context);

    const client = new windowStub.ExamData.RemoteApiClient();
    client.user = { id: 'user-1' };
    assert.deepEqual(await client.exportPracticeRecords(), [{ id: 'remote-record' }]);
    assert.deepEqual(fetchCalls.map(([url]) => url), ['/api/practice-records/export']);
    assert.equal(fetchCalls[0][1].method, 'GET');
    assert.equal(fetchCalls[0][1].credentials, 'same-origin');
    assert.equal(fetchCalls[0][1].headers['X-CSRF-Token'], undefined);
}

{
    const store = new Map();
    const storage = {
        async get(key, fallback) { return store.has(key) ? store.get(key) : fallback; },
        async set(key, value) { store.set(key, value); }
    };
    let remoteCalls = 0;
    let localCalls = 0;
    const windowStub = {
        crypto: webcrypto,
        storage,
        remoteApiClient: {
            isAuthenticated() { return true; },
            async exportPracticeRecords() {
                remoteCalls += 1;
                return [{ id: 'server-owned-export', status: 'completed' }];
            }
        },
        practiceRecorder: {
            getPracticeRecords() {
                localCalls += 1;
                return [{ id: 'cached-local-record' }];
            }
        }
    };
    const context = vm.createContext({
        window: windowStub,
        storage,
        console,
        URL,
        JSON,
        Promise,
        Error,
        setInterval() { return 1; },
        clearInterval() {}
    });
    load('js/utils/dataBackupManager.js', context);

    const manager = new windowStub.DataBackupManager();
    const result = await manager.exportPracticeRecords({ includeStats: false });
    assert.deepEqual(JSON.parse(result.data).practiceRecords.map((record) => record.id), ['server-owned-export']);
    assert.equal(remoteCalls, 1);
    assert.equal(localCalls, 0);

    const denied = new Error('Recent authentication required');
    denied.status = 403;
    denied.payload = { requiresDataManageStepUp: true };
    windowStub.remoteApiClient.exportPracticeRecords = async () => { throw denied; };
    await assert.rejects(() => manager.exportPracticeRecords({ includeStats: false }), (error) => error === denied);
    assert.equal(localCalls, 0, 'authenticated remote export denial must not fall back to cached local records');
}

{
    const fallbackRecords = [{ id: 'cached-history' }];
    const localDataSource = {
        async read() { return fallbackRecords; },
        async write() { throw new Error('step-up denial must not overwrite the local cache'); }
    };
    const apiClient = {
        user: { id: 'user-1' },
        csrfToken: 'csrf-current',
        isAuthenticated() { return true; },
        async listPracticeRecords() {
            const error = new Error('Recent authentication required');
            error.status = 403;
            error.payload = { requiresDataManageStepUp: true };
            throw error;
        }
    };
    const windowStub = {
        ExamData: {
            cloneValue(value) { return JSON.parse(JSON.stringify(value)); }
        },
        console: { log() {}, warn() {}, error() {}, info() {} },
        dispatchEvent() {},
        CustomEvent: class CustomEvent {}
    };
    const context = vm.createContext({ window: windowStub, console: windowStub.console, JSON, Promise, Error });
    load('js/data/dataSources/remotePracticeDataSource.js', context);

    const dataSource = new windowStub.ExamData.RemotePracticeDataSource(localDataSource, apiClient);
    assert.deepEqual(await dataSource.read('practice_records', []), fallbackRecords);
    assert.deepEqual(apiClient.user, { id: 'user-1' });
    assert.equal(apiClient.csrfToken, 'csrf-current');
}

{
    const backendSource = fs.readFileSync(path.join(repoRoot, 'backend/src/practiceRecords.js'), 'utf8');
    assert(backendSource.includes("router.get('/export', requireDataManageStepUp, sendCompletePracticeRecords);"));
    assert(backendSource.includes("router.get('/', requireDataManageStepUp, sendCompletePracticeRecords);"));
    assert(!backendSource.includes("router.get('/', async (req, res, next) =>"));
}

{
    const remoteApiSource = fs.readFileSync(path.join(repoRoot, 'js/data/remoteApiClient.js'), 'utf8');
    const backupManagerSource = fs.readFileSync(path.join(repoRoot, 'js/utils/dataBackupManager.js'), 'utf8');
    const coreBundle = fs.readFileSync(path.join(repoRoot, 'js/bundles/core-foundation.bundle.js'), 'utf8');
    const settingsBundle = fs.readFileSync(path.join(repoRoot, 'js/bundles/settings.bundle.js'), 'utf8');
    const vipSettingsBundle = fs.readFileSync(
        path.join(repoRoot, 'ListeningPractice/vip special/js/bundles/settings.bundle.js'),
        'utf8'
    );

    assert.equal(extractBundleSection(coreBundle, 'js/data/remoteApiClient.js'), normalizeSource(remoteApiSource));
    assert.equal(extractBundleSection(settingsBundle, 'js/utils/dataBackupManager.js'), normalizeSource(backupManagerSource));
    assert.equal(extractBundleSection(vipSettingsBundle, 'js/utils/dataBackupManager.js'), normalizeSource(backupManagerSource));
}

console.log(JSON.stringify({
    status: 'pass',
    detail: 'server-owned practice-record export guard tests passed'
}, null, 2));
