#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const core = require(path.join(root, 'js/utils/readingAnswerMatchCore.js'));
const choiceCore = require(path.join(root, 'js/utils/answerMatchCore.js'));
const allFixtures = JSON.parse(fs.readFileSync(path.join(root, 'developer/tests/fixtures/reading-answer-variants.json'), 'utf8'));
const exams = new Map();
const registry = { window: { __READING_EXAM_DATA__: { register: (id, data) => exams.set(id, data) } } };
const examDir = path.join(root, 'assets/generated/reading-exams');
for (const file of fs.readdirSync(examDir).filter(file => /^p[123]-.*\.js$/.test(file))) {
    vm.runInNewContext(fs.readFileSync(path.join(examDir, file), 'utf8'), registry, { filename: file });
}
vm.runInNewContext(fs.readFileSync(path.join(examDir, 'manifest.js'), 'utf8'), registry);
assert.deepEqual([...exams.keys()].sort(), Object.keys(registry.window.__READING_EXAM_MANIFEST__).sort(),
    'audit must cover every published reading exam');
// Optional imported exams are checked whenever that content is installed.
const fixtures = allFixtures.filter(item => !item.optional || exams.has(item.examId));

// Exercise the production page's collection, grading, totals and replay paths.
// Only the DOM and bootstrap are stubbed; grading functions are not replaced.
let answers = {};
const context = {
    console, URL, URLSearchParams,
    AnswerMatchCore: choiceCore, ReadingAnswerMatchCore: core,
    CSS: { escape: value => value },
    document: {
        addEventListener() {}, getElementById() { return null; }, querySelector() { return null; },
        querySelectorAll(selector) {
            const name = selector.match(/^\[name="(q\d+)"\]$/)?.[1];
            if (!name || !Object.hasOwn(answers, name)) return [];
            const values = Array.isArray(answers[name]) ? answers[name] : [answers[name]];
            return values.map(value => ({ type: 'text', tagName: 'INPUT', value }));
        }
    }
};
context.window = context;
const source = fs.readFileSync(path.join(root, 'js/runtime/unifiedReadingPage.js'), 'utf8');
vm.runInNewContext(source.replace("    document.addEventListener('DOMContentLoaded',", `
    global.__test = { state, compareAnswers, questionWeight, buildResults, buildReplayResults };
    document.addEventListener('DOMContentLoaded',`), context);
const page = context.__test;

let textQuestions = 0, answerEntries = 0, totalMarks = 0, checks = 0;
const variantQuestions = [];
for (const [examId, data] of exams) {
    page.state.dataset = data;
    answers = {};
    let expectedTotal = 0;
    for (const [questionId, expected] of Object.entries(data.answerKey)) {
        answerEntries++;
        const group = data.questionGroups.find(group => group.questionIds.includes(questionId));
        if (core.isTextKind(group.kind)) {
            textQuestions++;
            const variants = core.acceptedAnswers(expected);
            assert.ok(variants.length, `${examId} ${questionId} needs an answer`);
            if (variants.length > 1) variantQuestions.push(`${examId}/${questionId}`);
            for (const variant of variants) {
                for (const input of [variant, `  ${variant.toUpperCase().replace(/ /g, '   ')}  `]) {
                    assert.equal(page.compareAnswers(input, expected, questionId), true,
                        `${examId} ${questionId} must accept ${JSON.stringify(input)}`);
                    checks++;
                }
            }
            assert.equal(page.compareAnswers('', expected, questionId), false);
            assert.equal(page.compareAnswers('___incorrect___', expected, questionId), false);
            assert.equal(page.questionWeight(expected, questionId), 1, 'alternatives must never inflate marks');
            answers[questionId] = variants[0];
            expectedTotal++;
        } else {
            answers[questionId] = expected;
            expectedTotal += Array.isArray(expected) ? expected.length : 1;
        }
    }
    const result = page.buildResults();
    assert.equal(result.scoreInfo.correct, expectedTotal, `${examId} canonical answers must receive full marks`);
    assert.equal(result.scoreInfo.total, expectedTotal, `${examId} total must count blanks, not alternatives`);
    assert.equal(Object.values(result.questionTypePerformance).reduce((sum, entry) => sum + entry.total, 0), expectedTotal);
    totalMarks += expectedTotal;
}

for (const fixture of fixtures) {
    const data = exams.get(fixture.examId);
    page.state.dataset = data;
    for (const answer of fixture.answers) {
        answers = { [fixture.questionId]: answer };
        const result = page.buildResults();
        assert.equal(result.answerComparison[fixture.questionId].isCorrect, true, `${fixture.examId}: ${answer}`);
        assert.equal(result.scoreInfo.correct, 1, 'each accepted alternative earns exactly one mark');
        const replay = page.buildReplayResults({ answers, correctAnswers: data.answerKey });
        assert.equal(replay.answerComparison[fixture.questionId].isCorrect, true, 'replay fallback uses text matching');
    }
}
assert.deepEqual(variantQuestions.sort(), fixtures.map(item => `${item.examId}/${item.questionId}`).sort(),
    'every multi-answer text question must have reviewed fixtures');

for (const [actual, expected] of [
    ['FOUR', '4/four'], ['exercise', '(vigorous) exercise'], ['vigorous exercise', '(vigorous) exercise'],
    ['a panoramic camera', ['a panoramic camera', 'panoramic camera']],
    ['60 000', '60,000'], ['multi skilled', 'multi-skilled'], ['non timber forest products', 'non-timber forest products'],
    ['farmer\u2019s market', "farmer's market"], ['colour', 'color|colour'], ['1/2', '1/2']
]) assert.equal(core.matches(actual, expected), true, `${actual} should match ${JSON.stringify(expected)}`);

for (const [actual, expected] of [
    ['', '4/four'], ['5', '4/four'], ['four turkeys', '4/four'], ['4/five', '4/four'],
    ['a different camera', ['a panoramic camera', 'panoramic camera']], ['A', 'a panoramic camera'],
    ['6000', '60,000'], ['60,00', '60000'], ['-60000', '60,000'],
    ['166 weeks', '16.6 weeks'], ['7', '7%'], ['16.6', '16.6 weeks'], ['2', '1/2'],
    ['1', '1 mile'], ['hammer bones', 'hammer bone'], ['vigorous', '(vigorous) exercise'],
    ['ring, gold ring', ['ring', 'gold ring']], ['icecream', 'ice cream'],
    [['ring', 'wrong'], ['ring', 'gold ring']]
]) assert.equal(core.matches(actual, expected), false, `${JSON.stringify(actual)} must not match ${JSON.stringify(expected)}`);

console.log(JSON.stringify({ status: 'pass', passed: exams.size, total: exams.size,
    exams: exams.size, answerEntries, totalMarks, textQuestions,
    variantQuestions: fixtures.length, acceptedVariants: fixtures.reduce((sum, item) => sum + item.answers.length, 0),
    formatChecks: checks, detail: 'All reading answers, one-mark text alternatives and replay grading verified' }, null, 2));
