(function initHighlightTextUtils(global) {
    'use strict';

    function ensureTextContainer(node) {
        const parent = node.parentElement;
        const view = node.ownerDocument?.defaultView;
        if (!parent || !view) return;
        const display = view.getComputedStyle(parent).display;
        if (!['flex', 'inline-flex', 'grid', 'inline-grid'].includes(display)) return;

        // Direct text in flex/grid forms one anonymous item. Keep that item
        // intact when highlighting splits its text into several inline nodes.
        const isTextRunNode = (sibling) => sibling && (sibling.nodeType === 3 || sibling.nodeType === 8);
        let first = node;
        while (isTextRunNode(first.previousSibling)) first = first.previousSibling;
        const container = node.ownerDocument.createElement('span');
        container.className = 'highlight-text-run';
        parent.insertBefore(container, first);
        while (isTextRunNode(first)) {
            const next = first.nextSibling;
            container.appendChild(first);
            first = next;
        }
    }

    function wrapRange(range, createHighlight, acceptTextNode = () => true) {
        if (!range || range.collapsed) return [];
        const root = range.commonAncestorContainer;
        const doc = root.ownerDocument;
        const walker = doc.createTreeWalker(root, 4 /* NodeFilter.SHOW_TEXT */);
        const slices = [];
        let node = root.nodeType === 3 ? root : walker.nextNode();
        while (node) {
            if (range.intersectsNode(node) && acceptTextNode(node)) {
                const start = node === range.startContainer ? range.startOffset : 0;
                const end = node === range.endContainer ? range.endOffset : node.length;
                if (end > start && node.textContent.slice(start, end).trim()) {
                    slices.push({ node, start, end });
                }
            }
            node = walker.nextNode();
        }

        // Capture all offsets before reparenting: live DOM ranges move when
        // their containers are wrapped. Only text moves, never answer controls,
        // formatting elements, paragraphs, or table cells.
        return slices.map((slice) => {
            ensureTextContainer(slice.node);
            const selected = doc.createRange();
            selected.setStart(slice.node, slice.start);
            selected.setEnd(slice.node, slice.end);
            const highlight = createHighlight();
            selected.surroundContents(highlight);
            return highlight;
        });
    }

    global.HighlightTextUtils = { ensureTextContainer, wrapRange };
})(typeof window !== 'undefined' ? window : globalThis);
