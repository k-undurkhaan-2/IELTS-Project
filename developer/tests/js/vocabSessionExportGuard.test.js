#!/usr/bin/env node
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const source = fs.readFileSync(path.join(repoRoot, 'js/components/vocabSessionView.js'), 'utf8');

function createHarness({ stepUpAllowed = true, includeStepUpHelper = true, fetchPayload = null } = {}) {
    const state = {
        stepUpCalls: 0,
        storeInitCalls: 0,
        exportCalls: 0,
        downloadClicks: 0,
        messages: [],
        fetchCalls: 0
    };
    const body = {
        appendChild() {},
        removeChild() {}
    };
    const sandbox = {
        console: { log() {}, warn() {}, error() {}, info() {} },
        module: { exports: {} },
        exports: {},
        Blob,
        URL: {
            createObjectURL() {
                return 'blob:vocab-progress';
            },
            revokeObjectURL() {}
        },
        document: {
            body,
            createElement(tagName) {
                assert.equal(tagName, 'a');
                return {
                    href: '',
                    download: '',
                    click() {
                        state.downloadClicks += 1;
                    }
                };
            }
        },
        location: {
            href: 'http://business.local/?view=more',
            pathname: '/',
            search: '?view=more'
        },
        setTimeout() {},
        clearTimeout() {},
        showMessage(message, type) {
            state.messages.push({ message, type });
        },
        VocabDataIO: {
            async exportProgress() {
                state.exportCalls += 1;
                return new Blob(['{}'], { type: 'application/json' });
            }
        }
    };
    if (includeStepUpHelper) {
        sandbox.ensureBusinessDataManageStepUp = async () => {
            state.stepUpCalls += 1;
            return stepUpAllowed;
        };
    } else {
        sandbox.fetch = async (url, options) => {
            state.fetchCalls += 1;
            assert.equal(url, '/api/practice-records/data-manage/status');
            assert.equal(options.method, 'GET');
            return {
                ok: true,
                async json() {
                    return fetchPayload || { fresh: false, authActionStart: '/auth/business/data/start' };
                }
            };
        };
    }
    sandbox.globalThis = sandbox;
    const context = vm.createContext(sandbox);
    vm.runInContext(source, context, { filename: 'js/components/vocabSessionView.js' });
    const api = sandbox.module.exports;
    assert(api._test, 'vocab session view should expose module-only test hooks');
    api._test.setStoreForExportTest({
        async init() {
            state.storeInitCalls += 1;
        }
    });
    api._test.resetExportingForExportTest();
    return { api, sandbox, state };
}

{
    const { api, state } = createHarness({ stepUpAllowed: false });

    await api._test.handleExportRequest();

    assert.equal(state.stepUpCalls, 1, 'vocab progress export should check data-management step-up');
    assert.equal(state.storeInitCalls, 0, 'vocab progress export should not read store without step-up');
    assert.equal(state.exportCalls, 0, 'vocab progress export should not export without step-up');
    assert.equal(state.downloadClicks, 0, 'vocab progress export should not download without step-up');
}

{
    const { api, state } = createHarness({ includeStepUpHelper: false });

    await api._test.handleExportRequest();

    assert.equal(state.fetchCalls, 1, 'vocab progress export should fall back to data-management status check');
    assert.equal(state.exportCalls, 0, 'vocab progress export should not export without fresh status');
    assert.equal(state.downloadClicks, 0, 'vocab progress export should not download without fresh status');
}

{
    const { api, state } = createHarness({ stepUpAllowed: true });

    await api._test.handleExportRequest();

    assert.equal(state.stepUpCalls, 1, 'vocab progress export should check step-up before allowed export');
    assert.equal(state.storeInitCalls, 1, 'vocab progress export should still initialize store after step-up');
    assert.equal(state.exportCalls, 1, 'vocab progress export should proceed after step-up');
    assert.equal(state.downloadClicks, 1, 'allowed vocab progress export should download');
    assert.equal(state.messages.at(-1)?.type, 'success');
}

const handleStart = source.indexOf('async function handleExportRequest()');
assert(handleStart >= 0, 'vocab export handler should exist');
assert(
    source.indexOf('ensureVocabProgressExportDataManageStepUp()', handleStart) < source.indexOf('io.exportProgress()', handleStart),
    'vocab progress export should check data-management step-up before exporting progress'
);

for (const relativePath of [
    path.join('js', 'bundles', 'more.bundle.js'),
    path.join('ListeningPractice', 'vip special', 'js', 'bundles', 'more.bundle.js')
]) {
    const bundle = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    const bundleHandleStart = bundle.indexOf('async function handleExportRequest()');
    assert(bundleHandleStart >= 0, 'vocab progress bundle export guard should exist');
    assert(
        bundle.indexOf('ensureVocabProgressExportDataManageStepUp()', bundleHandleStart) < bundle.indexOf('io.exportProgress()', bundleHandleStart),
        `${relativePath} should check data-management step-up before exporting vocab progress`
    );
}

console.log(JSON.stringify({
    status: 'pass',
    detail: 'vocab session export step-up guard passed'
}, null, 2));