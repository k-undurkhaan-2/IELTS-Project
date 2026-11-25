(function initReadingAnswerMatchCore(global) {
    'use strict';

    // This matcher is for one text answer. Choice sets keep their existing rules.
    const TEXT_KINDS = new Set([
        'short_answer', 'sentence_completion', 'summary_completion',
        'table_completion', 'diagram_completion', 'flow_chart',
        'short-answer', 'sentence-completion', 'summary-completion',
        'table-completion', 'diagram-labelling', 'flow-chart'
    ]);

    function isTextKind(kind) {
        return TEXT_KINDS.has(kind);
    }

    function normalize(value) {
        return String(value == null ? '' : value)
            .normalize('NFKC')
            .toLowerCase()
            .replace(/[“”]/g, '"')
            .replace(/[‘’]/g, "'")
            .replace(/[‐‑‒–—]/g, '-')
            .replace(/\s+/g, ' ')
            .trim()
            .replace(/^(["'])(.*)\1$/, '$2')
            .replace(/([a-z])-(?=[a-z])/g, '$1 ')
            // Only valid thousands grouping is formatting. Keep decimal points,
            // signs, fractions, units and malformed numbers significant.
            .replace(/\d[\d, ]*\d/g, number => (
                /^(?:[1-9]\d{0,2})(?:,\d{3})+$/.test(number)
                || /^(?:[1-9]\d{0,2})(?: \d{3})+$/.test(number)
            ) ? number.replace(/[, ]/g, '') : number)
            .trim();
    }

    function expandOptionalWords(text, depth = 0) {
        const match = text.match(/\(([^()]*)\)/);
        if (!match || depth >= 6) return [text];
        const before = text.slice(0, match.index);
        const after = text.slice(match.index + match[0].length);
        return [before + match[1] + after, before + after]
            .flatMap(value => expandOptionalWords(value, depth + 1));
    }

    function acceptedAnswers(expected) {
        const values = Array.isArray(expected) ? expected : [expected];
        return Array.from(new Set(values.flatMap(value => (
            // Numeric slashes can be fractions or dates, not alternatives.
            String(value == null ? '' : value).split(/\||(?<!\d)\/|\/(?!\d)/)
                .flatMap(value => expandOptionalWords(value))
                .map(value => value.replace(/\s+/g, ' ').trim())
                .filter(Boolean)
        ))));
    }

    function matches(actual, expected) {
        const accepted = new Set(acceptedAnswers(expected).map(normalize).filter(Boolean));
        // Some legacy questions render two fields with the same question ID.
        // Each supplied field must be valid; alternatives still earn one mark.
        const values = Array.isArray(actual) ? actual : [actual];
        return values.length > 0 && values.every(value => {
            const normalized = normalize(value);
            return normalized !== '' && accepted.has(normalized);
        });
    }

    const api = { isTextKind, normalize, acceptedAnswers, matches };
    global.ReadingAnswerMatchCore = api;
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
