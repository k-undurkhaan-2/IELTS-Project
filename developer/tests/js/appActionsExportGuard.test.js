#!/usr/bin/env node
import assert from 'assert';
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const source = fs.readFileSync(path.join(repoRoot, 'js/presentation/app-actions.js'), 'utf8');

function createHarness({ stepUpAllowed, includeStepUpHelper = true, fetchPayload = null } = {}) {
    const state = {
        stepUpCalls: 0,
        suiteCalls: 0,
        exporterInstances: 0,
        exportCalls: 0,
        messages: []
    };

    const context = {
        console: { log() {}, warn() {}, error() {}, info() {} },
        Promise,
        URL,
        URLSearchParams,
        encodeURIComponent,
        setTimeout,
        clearTimeout,
        location: {
            href: 'http://business.local/?view=overview',
            origin: 'http://business.local',
            protocol: 'http:',
            pathname: '/',
            search: '?view=overview',
            hash: ''
        },
        document: {
            readyState: 'complete',
            querySelector() {
                return null;
            },
            addEventListener() {}
        },
        AppLazyLoader: {
            ensureGroup(groupName) {
                assert.equal(groupName, 'practice-suite');
                state.suiteCalls += 1;
                return Promise.resolve();
            }
        },
        MarkdownExporter: class TestMarkdownExporter {
            constructor() {
                state.exporterInstances += 1;
            }

            exportToMarkdown() {
                state.exportCalls += 1;
            }
        },
        showMessage(message, type) {
            state.messages.push({ message, type });
        }
    };
    if (includeStepUpHelper) {
        context.ensureBusinessDataManageStepUp = async () => {
            state.stepUpCalls += 1;
            return stepUpAllowed;
        };
    } else {
        context.fetch = async (url, options) => {
            state.stepUpCalls += 1;
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
    context.window = context;
    vm.createContext(context);
    vm.runInContext(source, context, { filename: 'js/presentation/app-actions.js' });
    return { context, state };
}

{
    const { context, state } = createHarness({ stepUpAllowed: false });

    await context.AppActions.exportPracticeMarkdown();

    assert.equal(state.stepUpCalls, 1, 'markdown export should check data-management step-up');
    assert.equal(state.suiteCalls, 0, 'markdown export should not load practice suite without step-up');
    assert.equal(state.exporterInstances, 0, 'markdown export should not create exporter without step-up');
    assert.equal(state.exportCalls, 0, 'markdown export should not download without step-up');
}

{
    const { context, state } = createHarness({ includeStepUpHelper: false });

    await context.AppActions.exportPracticeMarkdown();

    assert.equal(state.stepUpCalls, 1, 'markdown export should check status endpoint when helper is unavailable');
    assert.equal(state.suiteCalls, 0, 'markdown export should not load practice suite without fresh status');
    assert.equal(state.exportCalls, 0, 'markdown export should not download without fresh status');
    assert.match(context.location.href, /^\/auth\/business\/data\/start\?return_to=/);
}

{
    const { context, state } = createHarness({ stepUpAllowed: true });

    await context.AppActions.exportPracticeMarkdown();

    assert.equal(state.stepUpCalls, 1, 'markdown export should check step-up before allowed export');
    assert.equal(state.suiteCalls, 1, 'markdown export should load practice suite after step-up');
    assert.equal(state.exporterInstances, 1, 'markdown export should create exporter after step-up');
    assert.equal(state.exportCalls, 1, 'markdown export should proceed after step-up');
}

assert(
    source.indexOf('ensureMarkdownExportDataManageStepUp()') < source.indexOf('global.markdownExporter.exportToMarkdown()'),
    'app action source should check data-management step-up before markdown export'
);

console.log(JSON.stringify({
    status: 'pass',
    detail: 'app actions markdown export step-up guard passed'
}, null, 2));
