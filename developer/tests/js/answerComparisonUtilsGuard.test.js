#!/usr/bin/env node
import assert from 'assert';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const AnswerComparisonUtils = require(path.join(repoRoot, 'js', 'utils', 'answerComparisonUtils.js'));
const AnswerMatchCore = require(path.join(repoRoot, 'js', 'utils', 'answerMatchCore.js'));

for (const value of ['A', 'a', 'A. text', 'A) text']) {
    assert.equal(AnswerMatchCore.normalizeToken(value), 'A', `option token: ${value}`);
    assert.equal(AnswerMatchCore.compareAnswers(value, 'A'), true);
}
for (const value of ['A text', 'B answer', 'A: text', 'A-text', 'A.text']) {
    assert.equal(AnswerMatchCore.normalizeToken(value), value, `text answer: ${value}`);
    assert.equal(AnswerMatchCore.compareAnswers(value, value[0]), false);
}
assert.equal(AnswerMatchCore.compareAnswers('A text', 'a text'), true);
assert.equal(AnswerMatchCore.normalizeToken('  “long—term”  '), 'long-term');
assert.equal(AnswerMatchCore.compareAnswers('long-term', 'long term'), true);
assert.equal(AnswerMatchCore.normalizeToken('YES'), 'true');
assert.equal(AnswerMatchCore.normalizeToken('not-given'), 'not given');
assert.deepEqual(AnswerMatchCore.splitAnswerTokens('A, B'), ['A', 'B']);

const record = JSON.parse(`{
  "answerComparison": {
    "q1": {
      "userAnswer": "A",
      "correctAnswer": "A"
    },
    "__proto__": {
      "userAnswer": "polluted",
      "correctAnswer": "polluted"
    },
    "prototype": {
      "userAnswer": "polluted",
      "correctAnswer": "polluted"
    }
  },
  "answers": {
    "1": "A",
    "constructor": "polluted",
    "prototype": "polluted"
  },
  "correctAnswers": {
    "q1": "A",
    "__proto__": "polluted",
    "constructor": "polluted"
  },
  "scoreInfo": {
    "details": {
      "prototype": {
        "userAnswer": "polluted",
        "correctAnswer": "polluted"
      }
    }
  }
}`);

const entries = AnswerComparisonUtils.getNormalizedEntries(record);

assert.equal(Object.prototype.polluted, undefined);
assert.equal(entries.length, 1);
assert.equal(entries[0].canonicalKey, 'q1');
assert.equal(entries[0].userAnswer, 'A');
assert.equal(entries[0].correctAnswer, 'A');
assert.equal(entries[0].isCorrect, true);
assert(!entries.some((entry) => /(?:__proto__|prototype|constructor)/i.test(entry.canonicalKey)));
assert(!entries.some((entry) => entry.originalKeys.some((key) => /(?:__proto__|prototype|constructor)/i.test(key))));

const nestedRecord = JSON.parse(`{
  "id": "nested-record",
  "title": "Nested safety",
  "metadata": {
    "examTitle": "Nested safety",
    "nested": {
      "safe": "ok",
      "constructor": { "prototype": { "pollutedNestedAnswerComparison": true } }
    },
    "items": [
      {
        "label": "safe",
        "prototype": { "pollutedNestedAnswerComparison": true }
      }
    ]
  },
  "realData": {
    "__proto__": { "pollutedNestedAnswerComparison": true },
    "safe": {
      "constructor": { "prototype": { "pollutedNestedAnswerComparison": true } }
    }
  }
}`);
nestedRecord.metadata.self = nestedRecord.metadata;

const enriched = AnswerComparisonUtils.withEnrichedMetadata(nestedRecord);
assert.equal(Object.prototype.pollutedNestedAnswerComparison, undefined);
assert.equal(Object.prototype.hasOwnProperty.call(enriched, '__proto__'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.metadata, 'constructor'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.metadata.nested, 'constructor'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.metadata.items[0], 'prototype'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.realData, '__proto__'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.realData.safe, 'constructor'), false);
assert.equal(Object.prototype.hasOwnProperty.call(enriched.metadata, 'self'), false);
assert.equal(enriched.metadata.nested.safe, 'ok');

console.log(JSON.stringify({
    status: 'pass',
    detail: 'answer comparison utils prototype-pollution guard passed'
}, null, 2));
