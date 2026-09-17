#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import assert from 'assert';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const source = fs.readFileSync(path.join(repoRoot, 'backend/admin/admin.js'), 'utf8');

class FakeClassList {
    constructor() {
        this.values = new Set();
    }

    toggle(name, active) {
        if (active) {
            this.values.add(name);
        } else {
            this.values.delete(name);
        }
    }

    contains(name) {
        return this.values.has(name);
    }
}

class FakeElement {
    constructor(id = '') {
        this.id = id;
        this.textContent = '';
        this.hidden = false;
        this.disabled = false;
        this.dataset = {};
        this.classList = new FakeClassList();
        this.children = [];
        this.listeners = new Map();
    }

    append(...children) {
        this.children.push(...children);
    }

    addEventListener(type, callback) {
        this.listeners.set(type, callback);
    }

    focus() {
        this.focused = true;
    }

    setAttribute(name, value) {
        this[name] = String(value);
    }
}

const elements = new Map();
const exportButtons = ['summary', 'users', 'practice-records', 'traffic'].map((exportDataset) => {
    const button = new FakeElement();
    button.dataset.exportDataset = exportDataset;
    return button;
});
const documentStub = {
    getElementById(id) {
        if (!elements.has(id)) {
            elements.set(id, new FakeElement(id));
        }
        return elements.get(id);
    },
    querySelectorAll(selector) {
        assert.equal(selector, '[data-export-dataset]', 'unexpected document selector');
        return exportButtons;
    },
    createElement(tag) {
        return new FakeElement(tag);
    },
    createElementNS(namespace, tag) {
        const element = new FakeElement(tag);
        element.namespaceURI = namespace;
        return element;
    },
    addEventListener() {},
    body: new FakeElement('body')
};

const windowStub = {
    __IELTS_ADMIN_TEST__: true,
    location: { href: 'http://127.0.0.1:3000/admin' },
    setTimeout() {},
    clearTimeout() {},
    document: documentStub
};
let unexpectedFetches = 0;
const fetchImpl = () => {
    unexpectedFetches += 1;
    throw new Error('fetch should not be called in this test');
};
const hostJson = globalThis.JSON;
let oversizedAdminResponseParsed = false;

const context = vm.createContext({
    window: windowStub,
    document: documentStub,
    console: { log() {}, warn() {}, error() {} },
    JSON: {
        parse(value, reviver) {
            if (String(value).length > 1024 * 1024) {
                oversizedAdminResponseParsed = true;
            }
            return hostJson.parse(value, reviver);
        },
        stringify(value, replacer, space) {
            return hostJson.stringify(value, replacer, space);
        }
    },
    URLSearchParams,
    fetch(...args) {
        return fetchImpl(...args);
    }
});
vm.runInContext(source, context, { filename: 'backend/admin/admin.js' });

const hooks = windowStub.__IELTS_ADMIN_TEST_HOOKS__;
assert(hooks, 'admin test hooks should be available');
assert.equal(typeof hooks.confirmAction, 'function');
assert.equal(typeof hooks.closeConfirm, 'function');
assert.equal(typeof hooks.parseAdminResponseJson, 'function');
assert.equal(typeof hooks.sanitizeStatusMessage, 'function');
assert.equal(typeof hooks.bindEvents, 'function');

hooks.bindEvents();
assert.equal(exportButtons.length, 4);
assert.deepEqual(exportButtons.map((button) => button.dataset.exportDataset), [
    'summary', 'users', 'practice-records', 'traffic'
]);
for (const button of exportButtons) {
    assert.equal(typeof button.listeners.get('click'), 'function', `${button.dataset.exportDataset} export must have a click listener`);
}
assert.equal(unexpectedFetches, 0, 'binding admin events must not fetch');

{
    assert.deepEqual(hooks.parseAdminResponseJson('{"ok":true}'), { ok: true });
    const oversized = `{"data":"${'x'.repeat(1024 * 1024 + 1)}"}`;
    assert.equal(hooks.parseAdminResponseJson(oversized), null);
    assert.equal(oversizedAdminResponseParsed, false, 'oversized admin API responses must be rejected before JSON.parse');
}

{
    const sanitized = hooks.sanitizeStatusMessage(
        'Request failed token=abc123 password:SecretPass1 Authorization: Bearer abc.def.ghi Basic dXNlcjpwYXNz https://example.test/cb?csrfToken=csrf-secret&keep=1'
    );
    assert(!sanitized.includes('abc123'));
    assert(!sanitized.includes('SecretPass1'));
    assert(!sanitized.includes('abc.def.ghi'));
    assert(!sanitized.includes('dXNlcjpwYXNz'));
    assert(!sanitized.includes('csrf-secret'));
    assert(sanitized.includes('token=[redacted]'));
    assert(sanitized.includes('password=[redacted]'));
    assert(sanitized.includes('Bearer [redacted]'));
    assert(sanitized.includes('Basic [redacted]'));
    assert(sanitized.includes('csrfToken=[redacted]'));
}

{
    const statusBoundary = hooks.sanitizeStatusMessage(`${'s'.repeat(236)}\uD83D\uDE00tail`);
    assert.equal(statusBoundary, `${'s'.repeat(236)}...`);
    assert(!/[\uD800-\uDFFF]/.test(statusBoundary), 'truncated admin status text must not retain unmatched surrogate halves');
}

const first = hooks.confirmAction({
    title: 'Delete old',
    message: 'First confirm',
    confirmText: 'Delete'
});
assert.equal(elements.get('confirm-dialog').hidden, false);
assert.equal(elements.get('confirm-title').textContent, 'Delete old');

const second = hooks.confirmAction({
    title: 'Delete new',
    message: 'Second confirm',
    confirmText: 'Delete now'
});

assert.equal(await first, false, 'opening a second confirmation must cancel the first pending action');
assert.equal(elements.get('confirm-title').textContent, 'Delete new');
assert.equal(elements.get('confirm-submit').textContent, 'Delete now');

hooks.closeConfirm(true);
assert.equal(await second, true);
assert.equal(elements.get('confirm-dialog').hidden, true);
assert.equal(hooks.state.confirmResolver, null);

assert(
    source.includes('if (state.confirmResolver)') &&
    source.includes('state.confirmResolver(false);') &&
    source.includes('confirmAction') &&
    source.includes('closeConfirm'),
    'admin confirm dialog must cancel any previous unresolved confirmation before opening a new one'
);
assert(
    source.includes('function truncateAdminText') &&
    source.includes("truncateAdminText(normalized, MAX_ADMIN_STATUS_CHARS, '...')"),
    'admin UI must use Unicode-safe truncation for status text'
);

{
    const loadUsersSource = source.match(/    async function loadUsers\(\) \{([\s\S]*?)\n    \}/)?.[1];
    assert(loadUsersSource, 'current user-list loader must be present');
    assert.match(
        loadUsersSource,
        /^\s*const requestId = state\.users\.requestId \+ 1;\s*state\.users\.requestId = requestId;\s*state\.users\.loading = true;/,
        'user-list requests must capture and advance the latest request ID before loading'
    );
    assert.match(
        loadUsersSource,
        /const payload = await [^\n]+;\s*if \(state\.users\.requestId !== requestId\) \{\s*return;\s*\}\s*renderUsers\(payload\);/,
        'stale user-list responses must return before rendering'
    );
    assert.match(
        loadUsersSource,
        /\} finally \{\s*if \(state\.users\.requestId === requestId\) \{\s*state\.users\.loading = false;\s*updatePagination\(\);\s*\}\s*\}\s*$/,
        'only the latest user-list request may clear loading and update pagination'
    );
    assert.equal((loadUsersSource.match(/state\.users\.loading\s*=\s*false/g) || []).length, 1);
}

{
    const deleteUserSource = source.match(/    async function deleteSelectedUser\(\) \{([\s\S]*?)\n    \}/)?.[1];
    assert(deleteUserSource, 'current selected-user deletion must be present');
    assert.match(
        deleteUserSource,
        /^\s*const user = state\.selectedUser;\s*if \(!user \|\| user\.id === state\.currentUserId\) return;\s*const confirmed = await confirmAction\(/,
        'user deletion must capture the selected object before asynchronous confirmation'
    );
    const afterConfirmation = deleteUserSource.slice(deleteUserSource.indexOf('await confirmAction('));
    assert.match(
        afterConfirmation,
        /await withAdminStepUp\(\(\) => request\(`\/api\/admin\/users\/\$\{encodeURIComponent\(user\.id\)\}`, \{\s*method: 'DELETE'\s*\}\)\);/,
        'confirmed user deletion must use the captured user ID'
    );
    assert(!afterConfirmation.includes('state.selectedUser'), 'user deletion must not reread the selection after confirmation');
}

assert.equal(unexpectedFetches, 0, 'admin frontend guard must not fetch');

console.log('adminFrontendGuard.test.js passed');
