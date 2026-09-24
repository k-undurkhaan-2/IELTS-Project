#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import { BUNDLE_PROFILES } from '../../../scripts/bundle-manifest.mjs';
import {
    normalizeEol,
    normalizeSourceText,
    renderBundle
} from '../../../scripts/build-bundles.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const builderPath = path.join(repoRoot, 'scripts', 'build-bundles.mjs');
const tempEvidenceRoots = [];

function run(executable, args, cwd = repoRoot) {
    return spawnSync(executable, args, {
        cwd,
        encoding: 'utf8',
        windowsHide: true
    });
}

function runGit(args) {
    return run('git', args, repoRoot);
}

function runBuilder(cwd, args = []) {
    return run(process.execPath, ['scripts/build-bundles.mjs', ...args], cwd);
}

function assertCommandPassed(result, label) {
    assert.equal(
        result.status,
        0,
        `${label} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
}

function outputPathFor(profile, outputPath) {
    return path.join(profile.outputRoot, outputPath);
}

function profileOutputPaths(profile) {
    return profile.bundles.map((bundle) => outputPathFor(profile, bundle.outputPath));
}

function sha256(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function outputHashes(fixtureRoot) {
    const hashes = {};
    for (const profile of Object.values(BUNDLE_PROFILES)) {
        for (const relativePath of profileOutputPaths(profile)) {
            hashes[`${profile.name}:${relativePath}`] = sha256(path.join(fixtureRoot, relativePath));
        }
    }
    return hashes;
}

function copyTextFile(relativePath, fixtureRoot, transform = (value) => value) {
    const sourcePath = path.join(repoRoot, relativePath);
    const targetPath = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, transform(fs.readFileSync(sourcePath, 'utf8')), 'utf8');
}

function createFixture(sourceEol = 'lf') {
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ielts-bundle-normalization-test-'));
    tempEvidenceRoots.push(fixtureRoot);
    copyTextFile('scripts/build-bundles.mjs', fixtureRoot);
    copyTextFile('scripts/bundle-manifest.mjs', fixtureRoot);

    const inputPaths = new Set();
    const outputPaths = new Set();
    for (const profile of Object.values(BUNDLE_PROFILES)) {
        profile.bundles.forEach((bundle) => {
            bundle.inputs.forEach((inputPath) => inputPaths.add(inputPath));
            outputPaths.add(outputPathFor(profile, bundle.outputPath));
        });
    }

    for (const inputPath of inputPaths) {
        copyTextFile(inputPath, fixtureRoot, (value) => {
            const lf = normalizeEol(value);
            return sourceEol === 'crlf' ? lf.replace(/\n/g, '\r\n') : lf;
        });
    }
    for (const outputPath of outputPaths) {
        copyTextFile(outputPath, fixtureRoot, (value) => normalizeEol(value));
    }
    return fixtureRoot;
}

function bundleDirectoryOutputs(fixtureRoot, profile) {
    const bundleDirectory = path.join(fixtureRoot, profile.outputRoot, 'js', 'bundles');
    return fs.readdirSync(bundleDirectory, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.endsWith('.bundle.js'))
        .map((entry) => `js/bundles/${entry.name}`)
        .sort();
}

test('manifest is explicit, tracked, public-source-only, and complete', () => {
    assert.deepEqual(Object.keys(BUNDLE_PROFILES), ['default', 'vip']);
    assert.equal(BUNDLE_PROFILES.default.outputRoot, '.');
    assert.equal(BUNDLE_PROFILES.vip.outputRoot, 'ListeningPractice/vip special');
    assert.equal(BUNDLE_PROFILES.default.allowUndeclaredOutputs, false);
    assert.equal(BUNDLE_PROFILES.vip.allowUndeclaredOutputs, false);

    for (const profile of Object.values(BUNDLE_PROFILES)) {
        const outputPaths = profile.bundles.map((bundle) => bundle.outputPath);
        assert.equal(new Set(outputPaths).size, outputPaths.length, `${profile.name} outputs must be unique`);
        assert.deepEqual(
            bundleDirectoryOutputs(repoRoot, profile),
            [...outputPaths].sort(),
            `${profile.name} bundle directory must exactly match its manifest`
        );

        for (const bundle of profile.bundles) {
            assert.equal(bundle.tracked, true, `${bundle.outputPath} must be tracked`);
            assert.equal(bundle.runtimeRequired, true, `${bundle.outputPath} must be runtime-owned`);
            assert.equal(bundle.publicSourcesOnly, true, `${bundle.outputPath} must be public-source-only`);
            assert(bundle.inputs.length > 0, `${bundle.outputPath} must declare source inputs`);

            const trackedOutput = runGit(['ls-files', '--error-unmatch', '--', outputPathFor(profile, bundle.outputPath)]);
            assertCommandPassed(trackedOutput, `tracked output ${profile.name}:${bundle.outputPath}`);
            const ignoredOutput = runGit(['check-ignore', '--quiet', '--no-index', '--', outputPathFor(profile, bundle.outputPath)]);
            assert.notEqual(ignoredOutput.status, 0, `${profile.name}:${bundle.outputPath} must not be ignored`);

            for (const inputPath of bundle.inputs) {
                assert.equal(path.isAbsolute(inputPath), false, `${inputPath} must be repository-relative`);
                assert(!inputPath.split('/').includes('..'), `${inputPath} must not escape the repository`);
                assert(!inputPath.startsWith('ListeningPractice/'), `${inputPath} must not use private Listening source`);
                assert(!/(^|\/)\.env(?:\.|$)/.test(inputPath), `${inputPath} must not be a secret input`);
                assert(fs.existsSync(path.join(repoRoot, inputPath)), `${inputPath} must exist`);
                assertCommandPassed(
                    runGit(['ls-files', '--error-unmatch', '--', inputPath]),
                    `tracked source ${inputPath}`
                );
            }
        }
    }
});

test('tracked bundles exactly match normalized manifest sources', () => {
    for (const profile of Object.values(BUNDLE_PROFILES)) {
        for (const bundle of profile.bundles) {
            const expected = renderBundle(profile.name, bundle.inputs, (inputPath) => (
                normalizeSourceText(fs.readFileSync(path.join(repoRoot, inputPath), 'utf8'))
            ));
            const actualPath = path.join(repoRoot, outputPathFor(profile, bundle.outputPath));
            const actual = normalizeEol(fs.readFileSync(actualPath, 'utf8'));
            assert.equal(actual, expected, `${profile.name}:${bundle.outputPath} must match its sources`);
            assert(!actual.includes(repoRoot), `${profile.name}:${bundle.outputPath} must not embed a machine path`);
            assert(!/^\/\* Generated by .*\d{4}-\d{2}-\d{2}/.test(actual), 'bundle header must not contain a timestamp');
        }
    }

    const settings = BUNDLE_PROFILES.vip.bundles.find((bundle) => bundle.outputPath.endsWith('/settings.bundle.js'));
    assert.deepEqual(settings.inputs, [
        'js/components/DataIntegrityManager.js',
        'js/utils/dataBackupManager.js'
    ]);
    const more = BUNDLE_PROFILES.vip.bundles.find((bundle) => bundle.outputPath.endsWith('/more.bundle.js'));
    assert(more.inputs.includes('js/components/vocabSessionView.js'), 'VIP more bundle must retain the PR #2 source section');
});

test('default/VIP order matrix and repeated builds are hash-stable', () => {
    const defaultOnly = createFixture();
    const defaultBefore = outputHashes(defaultOnly);
    assertCommandPassed(runBuilder(defaultOnly), 'default-only build');
    assert.deepEqual(outputHashes(defaultOnly), defaultBefore, 'default-only build must be clean');

    const vipOnly = createFixture();
    const vipBefore = outputHashes(vipOnly);
    assertCommandPassed(
        runBuilder(vipOnly, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'VIP-only build'
    );
    assert.deepEqual(outputHashes(vipOnly), vipBefore, 'VIP-only build must be clean');

    const defaultThenVip = createFixture();
    assertCommandPassed(runBuilder(defaultThenVip), 'default then VIP: default');
    assertCommandPassed(
        runBuilder(defaultThenVip, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'default then VIP: VIP'
    );
    const defaultThenVipHashes = outputHashes(defaultThenVip);

    const vipThenDefault = createFixture();
    assertCommandPassed(
        runBuilder(vipThenDefault, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'VIP then default: VIP'
    );
    assertCommandPassed(runBuilder(vipThenDefault), 'VIP then default: default');
    assert.deepEqual(outputHashes(vipThenDefault), defaultThenVipHashes, 'build order must not affect outputs');

    const repeatedVip = createFixture();
    assertCommandPassed(
        runBuilder(repeatedVip, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'repeated VIP: first'
    );
    const firstHashes = outputHashes(repeatedVip);
    assertCommandPassed(
        runBuilder(repeatedVip, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'repeated VIP: second'
    );
    assert.deepEqual(outputHashes(repeatedVip), firstHashes, 'second VIP build must be byte-stable');
});

test('LF output hashes are stable with LF or CRLF source checkouts', () => {
    const lfFixture = createFixture('lf');
    const crlfFixture = createFixture('crlf');
    for (const fixtureRoot of [lfFixture, crlfFixture]) {
        assertCommandPassed(runBuilder(fixtureRoot), 'EOL matrix default build');
        assertCommandPassed(
            runBuilder(fixtureRoot, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
            'EOL matrix VIP build'
        );
    }
    assert.deepEqual(outputHashes(crlfFixture), outputHashes(lfFixture));

    const representativePaths = [
        'js/bundles/runtime-entry.bundle.js',
        'ListeningPractice/vip special/js/bundles/runtime-entry.bundle.js'
    ];
    for (const autocrlf of ['true', 'false', 'input']) {
        for (const relativePath of representativePaths) {
            const result = runGit(['-c', `core.autocrlf=${autocrlf}`, 'check-attr', 'eol', '--', relativePath]);
            assertCommandPassed(result, `check-attr ${autocrlf}:${relativePath}`);
            assert.match(result.stdout, /: eol: lf\s*$/);
        }
    }
});

test('VIP listening wrapper uses the do-not-generate policy', () => {
    const rootWrapper = 'js/bundles/listening-wrapper.bundle.js';
    assert(BUNDLE_PROFILES.default.bundles.some((bundle) => bundle.outputPath === rootWrapper));
    assert(!BUNDLE_PROFILES.vip.bundles.some((bundle) => bundle.outputPath === rootWrapper));
    assert(BUNDLE_PROFILES.vip.retiredOutputs.includes(rootWrapper));

    const vipIndex = fs.readFileSync(path.join(repoRoot, 'ListeningPractice', 'vip special', 'index.html'), 'utf8');
    assert(!vipIndex.includes('listening-wrapper.bundle.js'), 'VIP shell must not reference a VIP-local wrapper');
    const backendTest = fs.readFileSync(path.join(repoRoot, 'backend', 'test', 'backend.test.js'), 'utf8');
    assert(
        backendTest.includes('/js/bundles/listening-wrapper.bundle.js'),
        'backend Listening pages must use the tracked root wrapper'
    );

    const fixtureRoot = createFixture();
    const retiredPath = path.join(fixtureRoot, BUNDLE_PROFILES.vip.outputRoot, rootWrapper);
    fs.writeFileSync(retiredPath, 'legacy ignored output\n', 'utf8');
    assertCommandPassed(
        runBuilder(fixtureRoot, ['--profile', 'vip', '--output-root', 'ListeningPractice/vip special']),
        'VIP retired-wrapper cleanup'
    );
    assert.equal(fs.existsSync(retiredPath), false, 'canonical VIP build must remove the retired output');
});

test('canonical entrypoint rejects unsafe roots, legacy logic, and undeclared outputs', () => {
    const missingVipRoot = run(process.execPath, [builderPath, '--profile', 'vip']);
    assert.notEqual(missingVipRoot.status, 0);
    assert.match(`${missingVipRoot.stdout}${missingVipRoot.stderr}`, /VIP output root must be explicit/);

    const wrongRoot = run(process.execPath, [builderPath, '--output-root', 'ListeningPractice/vip special']);
    assert.notEqual(wrongRoot.status, 0);
    assert.match(`${wrongRoot.stdout}${wrongRoot.stderr}`, /Profile default must write to \./);

    const legacyBuilder = path.join(repoRoot, 'ListeningPractice', 'vip special', 'scripts', 'build-bundles.mjs');
    const legacySource = fs.readFileSync(legacyBuilder, 'utf8');
    assert(!legacySource.includes('const bundles ='), 'legacy entrypoint must not retain bundle logic');
    const legacyResult = run(process.execPath, [legacyBuilder]);
    assert.notEqual(legacyResult.status, 0);
    assert.match(`${legacyResult.stdout}${legacyResult.stderr}`, /canonical root builder/);

    const fixtureRoot = createFixture();
    const extraOutput = path.join(fixtureRoot, 'js', 'bundles', 'undeclared.bundle.js');
    fs.writeFileSync(extraOutput, 'undeclared\n', 'utf8');
    const unexpectedResult = runBuilder(fixtureRoot);
    assert.notEqual(unexpectedResult.status, 0);
    assert.match(`${unexpectedResult.stdout}${unexpectedResult.stderr}`, /Undeclared bundle outputs/);
});

after(() => {
    const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
    for (const evidenceRoot of tempEvidenceRoots) {
        const resolved = path.resolve(evidenceRoot);
        assert(
            `${resolved}${path.sep}`.startsWith(tempRoot)
                && path.basename(resolved).startsWith('ielts-bundle-normalization-test-'),
            `refusing to remove unsafe test fixture: ${resolved}`
        );
        fs.rmSync(resolved, { recursive: true, force: true });
    }
});
