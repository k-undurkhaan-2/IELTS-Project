(function initListeningHighlighter(global) {
    'use strict';

    var ROOT_SELECTOR = [
        'main', '#main-content', '.main-content', '.content-area', '#left', '#right',
        '#left-pane', '#right-pane', '#leftPane', '#rightPane', '.questions-pane',
        '.transcript-pane', '#qPane', '#tPane', '#questions', '#question-container',
        '.questions-container', '.question-container', '.question', '#test-pages-container',
        '#test-content', '#testPages', '#testContentArea', '#questionsContainer',
        '#transcript-content', '#transcriptContent', '#transcript-body',
        '#transcript-container', '#transcriptFull'
    ].join(', ');
    var PANE_SELECTOR = '#left, #right, #left-pane, #right-pane, #leftPane, #rightPane, .questions-pane, .transcript-pane, #qPane, #tPane';
    var LEGACY_TOOLBAR_SELECTOR = '#selbar, #selToolbar, #highlightToolbar, #hl-toolbar, #highlighter-btn, #selBubble, #selectionToolbar, #selection-bar, #sel-toolbar';
    var NOTES_BUTTON_SELECTOR = '#toggle-notes-btn, #notesToggle, #note-btn, #notesBtn, #notesToggleBtn, #btnNotes, #notes-trigger, #notes-btn, #btn-note';
    var EXCLUDED_SELECTOR = [
        'script', 'style', 'noscript', 'input', 'textarea', 'select', 'button',
        'audio', 'video', 'svg', 'a', '[contenteditable]:not([contenteditable="false"])',
        '[draggable="true"]', '[role="slider"]', '[role="button"]',
        'header', 'nav', '.header', '.bottom-bar', '.practice-nav', '.audio-player',
        '#settings-panel', '#notes-panel', '#notes', '#notesPanel',
        '#notesSidebar', '#notes-sidebar', '#notes-side', '#notes-area',
        '#listening-selbar', '#listening-highlight-notes',
        LEGACY_TOOLBAR_SELECTOR
    ].join(', ');
    var HIGHLIGHT_SELECTOR = '.hl, .hl-blue, .hl-yellow';

    function install(doc) {
        if (!doc || !doc.body || doc.__listeningHighlighterInstalled) return;
        doc.__listeningHighlighterInstalled = true;
        var win = doc.defaultView || global;
        var lastRange = null;
        var activeHighlights = [];
        var selectionTimer = null;
        var positionFrame = null;
        var toolbar = doc.createElement('div');
        toolbar.id = 'listening-selbar';
        toolbar.setAttribute('role', 'toolbar');
        toolbar.setAttribute('aria-label', 'Text annotation');
        toolbar.hidden = true;
        function addButton(role, label, action) {
            var button = doc.createElement('button');
            button.type = 'button';
            button.dataset.role = role;
            button.textContent = label;
            button.addEventListener('click', action);
            toolbar.appendChild(button);
            return button;
        }
        addButton('highlight', 'Highlight', function () { applyHighlight('highlight'); });
        var removeButton = addButton('remove-highlight', 'Remove', removeHighlight);
        addButton('note', 'Note', addNote);
        doc.body.appendChild(toolbar);
        doc.body.classList.add('listening-highlight-enabled');
        var style = doc.createElement('style');
        style.id = 'listening-highlighter-style';
        style.textContent = [
            // Retain legacy nodes: their document listeners may still reference them.
            LEGACY_TOOLBAR_SELECTOR.split(', ').map(function (selector) { return '.listening-highlight-enabled ' + selector; }).join(', ') + ' { display: none !important; }',
            '#listening-selbar { position: fixed; z-index: 10000; display: flex; box-sizing: border-box; flex-wrap: wrap; gap: 4px; padding: 4px; border-radius: 6px; background: #1e293b; color: #fff; box-shadow: 0 4px 12px rgba(0,0,0,.25); user-select: none; -webkit-user-select: none; touch-action: manipulation; }',
            '#listening-selbar[hidden], #listening-selbar button[hidden], #listening-highlight-notes[hidden] { display: none !important; }',
            '#listening-selbar button { background: transparent; color: #fff; border: 0; padding: 6px 12px; cursor: pointer; border-radius: 4px; font: 400 .85rem system-ui, sans-serif; }',
            '#listening-selbar button:hover, #listening-selbar button:focus-visible { background: #334155; }',
            '.listening-highlight-enabled .hl, .listening-highlight-enabled .hl-yellow { background-color: #72361c; color: #fff; }',
            '.listening-highlight-enabled .hl[data-hl-type="note"], .listening-highlight-enabled .hl-blue { background-color: #0369d9; color: #fff; }',
            '@media (pointer: coarse), (max-width: 980px) { #listening-selbar button { min-height: 44px; min-width: 44px; } }',
            '#listening-highlight-notes { position: fixed; z-index: 10001; inset: 15% 16px auto; margin: auto; width: min(480px, calc(100% - 32px)); box-sizing: border-box; padding: 16px; border: 1px solid #64748b; border-radius: 8px; background: #fff; color: #0f172a; box-shadow: 0 8px 32px rgba(0,0,0,.3); }',
            '#listening-highlight-notes textarea { display: block; box-sizing: border-box; width: 100%; height: 180px; max-height: 45vh; margin: 12px 0; padding: 8px; font: inherit; background: inherit; color: inherit; }',
            '#listening-highlight-notes button { padding: 8px 16px; cursor: pointer; }',
            '#listening-highlight-notes-toggle { padding: 8px 12px; border: 1px solid #64748b; border-radius: 6px; background: #fff; color: #0f172a; cursor: pointer; }',
            '#listening-highlight-notes-toggle.floating { position: fixed; bottom: 16px; right: 16px; z-index: 9999; }',
            'body.dark-mode #listening-highlight-notes { background: #1e293b; color: #f8fafc; }'
        ].join('\n');
        (doc.head || doc.documentElement).appendChild(style);

        function elementFor(node) {
            return node && (node.nodeType === 1 ? node : node.parentElement);
        }

        function allowed(node) {
            var element = elementFor(node);
            return !!(element && element.isConnected && !element.closest(EXCLUDED_SELECTOR)
                && (!doc.querySelector(ROOT_SELECTOR) || element.closest(ROOT_SELECTOR)));
        }

        function hide() {
            toolbar.hidden = true;
            lastRange = null;
            activeHighlights = [];
        }

        function position() {
            if (toolbar.hidden || positionFrame !== null) return;
            positionFrame = win.requestAnimationFrame(function () {
                positionFrame = null;
                if (toolbar.hidden) return;
                var anchor = lastRange || activeHighlights[0];
                if (!anchor || !allowed(lastRange ? lastRange.startContainer : anchor)) {
                    hide();
                    return;
                }
                var rect = anchor.getBoundingClientRect();
                var viewport = win.visualViewport;
                var topEdge = viewport ? viewport.offsetTop : 0;
                var leftEdge = viewport ? viewport.offsetLeft : 0;
                var height = viewport ? viewport.height : win.innerHeight;
                var width = viewport ? viewport.width : doc.documentElement.clientWidth;
                var mobile = win.matchMedia('(pointer: coarse), (max-width: 980px)').matches;
                var gap = mobile ? 64 : 8;
                toolbar.style.maxWidth = Math.max(0, width - 16) + 'px';
                var minTop = topEdge + 8;
                var minLeft = leftEdge + 8;
                var maxTop = Math.max(minTop, topEdge + height - toolbar.offsetHeight - 8);
                var maxLeft = Math.max(minLeft, leftEdge + width - toolbar.offsetWidth - 8);
                var above = rect.top - toolbar.offsetHeight - gap;
                var below = rect.bottom + gap;
                var top = mobile && below <= maxTop ? below : (above >= minTop ? above : below);
                toolbar.style.top = Math.max(minTop, Math.min(top, maxTop)) + 'px';
                toolbar.style.left = Math.max(minLeft, Math.min(rect.left + rect.width / 2 - toolbar.offsetWidth / 2, maxLeft)) + 'px';
            });
        }

        function show() {
            removeButton.hidden = activeHighlights.length === 0;
            toolbar.hidden = false;
            position();
        }

        function updateSelection() {
            var selection = win.getSelection();
            if (!selection || selection.isCollapsed || !selection.rangeCount) {
                if (!activeHighlights.length || !activeHighlights[0].isConnected) hide();
                return;
            }
            var range = selection.getRangeAt(0);
            if (!range.toString().trim() || !allowed(range.startContainer) || !allowed(range.endContainer)) {
                hide();
                return;
            }
            if (elementFor(range.startContainer).closest(PANE_SELECTOR) !== elementFor(range.endContainer).closest(PANE_SELECTOR)) {
                hide();
                return;
            }
            lastRange = range.cloneRange();
            activeHighlights = Array.from(doc.querySelectorAll(HIGHLIGHT_SELECTOR)).filter(function (node) {
                return allowed(node) && range.intersectsNode(node);
            });
            show();
        }

        function clearSelection() {
            win.getSelection()?.removeAllRanges();
            hide();
        }

        function wrapSelection(kind) {
            if (!lastRange || lastRange.collapsed || !allowed(lastRange.startContainer) || !allowed(lastRange.endContainer)) return [];
            var range = lastRange;
            var root = range.commonAncestorContainer;
            var walker = doc.createTreeWalker(root, win.NodeFilter.SHOW_TEXT);
            var nodes = [];
            var node = root.nodeType === 3 ? root : walker.nextNode();
            while (node) {
                if (allowed(node) && range.intersectsNode(node) && !node.parentElement.closest(HIGHLIGHT_SELECTOR)) {
                    var start = node === range.startContainer ? range.startOffset : 0;
                    var end = node === range.endContainer ? range.endOffset : node.length;
                    if (node.textContent.slice(start, end).trim()) nodes.push({ node: node, start: start, end: end });
                }
                node = walker.nextNode();
            }
            // Wrap only text slices, leaving answer controls and their handlers in place.
            return nodes.map(function (entry) {
                var slice = doc.createRange();
                slice.setStart(entry.node, entry.start);
                slice.setEnd(entry.node, entry.end);
                var span = doc.createElement('span');
                span.className = 'hl';
                span.dataset.listeningHighlight = 'true';
                if (kind === 'note') span.dataset.hlType = 'note';
                slice.surroundContents(span);
                return span;
            });
        }

        function applyHighlight(kind) {
            if (!activeHighlights.length) wrapSelection(kind);
            clearSelection();
        }

        function removeHighlight() {
            activeHighlights.forEach(function (span) {
                var parent = span.parentNode;
                if (!parent || !allowed(span)) return;
                while (span.firstChild) parent.insertBefore(span.firstChild, span);
                parent.removeChild(span);
                parent.normalize();
            });
            clearSelection();
        }

        function getNotesArea() {
            var existing = doc.querySelector('#notes-panel textarea');
            if (existing) return existing;
            var panel = doc.getElementById('listening-highlight-notes');
            if (!panel) {
                panel = doc.createElement('section');
                panel.id = 'listening-highlight-notes';
                panel.setAttribute('role', 'dialog');
                panel.setAttribute('aria-label', 'Notes');
                var title = doc.createElement('strong');
                title.textContent = 'Highlight notes';
                var area = doc.createElement('textarea');
                area.setAttribute('aria-label', 'Notes');
                var close = doc.createElement('button');
                close.type = 'button';
                close.textContent = 'Close';
                close.addEventListener('click', function () { panel.hidden = true; });
                panel.append(title, area, close);
                doc.body.appendChild(panel);
                // Keep legacy card-based notes accessible alongside these quotes.
                var toggle = doc.createElement('button');
                toggle.id = 'listening-highlight-notes-toggle';
                toggle.type = 'button';
                toggle.textContent = 'Highlight notes';
                toggle.setAttribute('aria-controls', panel.id);
                toggle.addEventListener('click', function () {
                    panel.hidden = false;
                    area.focus();
                });
                var legacyNotesButton = doc.querySelector(NOTES_BUTTON_SELECTOR);
                if (legacyNotesButton) legacyNotesButton.insertAdjacentElement('afterend', toggle);
                else {
                    toggle.className = 'floating';
                    doc.body.appendChild(toggle);
                }
            }
            panel.hidden = false;
            return panel.querySelector('textarea');
        }

        function addNote() {
            var text = lastRange ? lastRange.toString().trim() : activeHighlights.map(function (node) { return node.textContent; }).join(' ').trim();
            if (!text) return;
            var highlights = activeHighlights.length ? activeHighlights : wrapSelection('note');
            highlights.forEach(function (span) { span.dataset.hlType = 'note'; span.classList.add('hl'); });
            var area = getNotesArea();
            area.value += (area.value ? '\n\n' : '') + '> ' + text + '\n';
            area.dispatchEvent(new win.Event('input', { bubbles: true }));
            var panel = area.closest('#notes-panel');
            if (panel) {
                panel.hidden = false;
                panel.style.display = 'flex';
                var overlay = doc.querySelector('.overlay');
                if (overlay) overlay.style.display = 'block';
                var settings = doc.getElementById('settings-panel');
                if (settings) settings.style.display = 'none';
            }
            clearSelection();
            area.focus();
            area.scrollTop = area.scrollHeight;
        }

        doc.addEventListener('selectionchange', function () {
            win.clearTimeout(selectionTimer);
            selectionTimer = win.setTimeout(updateSelection, 10);
        });
        // Pointer and mouse prevention keeps the selection intact until click/tap.
        toolbar.addEventListener('pointerdown', function (event) { if (event.button === 0) event.preventDefault(); });
        toolbar.addEventListener('mousedown', function (event) { event.preventDefault(); });
        doc.addEventListener('pointerdown', function (event) {
            if (!toolbar.contains(event.target)) hide();
        });
        doc.addEventListener('click', function (event) {
            if (toolbar.contains(event.target)) return;
            var highlight = elementFor(event.target)?.closest(HIGHLIGHT_SELECTOR);
            var selection = win.getSelection();
            if (highlight && allowed(highlight) && (!selection || selection.isCollapsed)) {
                lastRange = null;
                activeHighlights = [highlight];
                show();
            }
        });
        doc.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                hide();
                var panel = doc.getElementById('listening-highlight-notes');
                if (panel) panel.hidden = true;
            }
        });
        doc.addEventListener('scroll', position, true);
        win.addEventListener('resize', position);
        win.visualViewport?.addEventListener('resize', position);
        win.visualViewport?.addEventListener('scroll', position);
    }

    global.ListeningHighlighter = { install: install };
})(typeof window !== 'undefined' ? window : globalThis);
