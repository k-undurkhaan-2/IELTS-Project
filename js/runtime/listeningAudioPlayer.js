(function initListeningAudioPlayer(global) {
    'use strict';

    var PROGRESS_SELECTOR = '.progress-container, .progress-area, .progress-wrap, .prog-wrap, .progress-box, .progress-track, #seekBar';
    var FILL_SELECTOR = '.progress-bar, .progress-fill, .prog-fill, .pos';
    var TIME_SELECTOR = '.time-display, .time-text, .time-txt, .time, #timeDisp, #timeText';
    var PLAY_SELECTOR = 'button.play-pause-btn, button.play-btn, button.play-pause, button#playBtn';

    function installButtonStyle(doc) {
        if (doc.getElementById('listening-audio-button-style')) return;
        var style = doc.createElement('style');
        style.id = 'listening-audio-button-style';
        function icon(shape) {
            return 'url("data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' + shape + '</svg>') + '")';
        }
        var play = icon('<path d="M6 5.5C6 4.35 7.25 3.63 8.25 4.2L19.5 10.7C20.5 11.28 20.5 12.72 19.5 13.3L8.25 19.8C7.25 20.37 6 19.65 6 18.5Z"/>');
        var pause = icon('<rect x="6" y="4" width="4" height="16" rx="1.5"/><rect x="14" y="4" width="4" height="16" rx="1.5"/>');
        // Keep the native button and its contents: older templates retain child
        // references or rewrite innerHTML on every timeupdate. A masked pseudo
        // element survives those writes and replaces both text and CSS icons.
        style.textContent = [
            'button[data-listening-playback] { position: relative !important; font-size: 0 !important; line-height: 0 !important; }',
            'button[data-listening-playback] > * { display: none !important; }',
            'button[data-listening-playback]::before { content: "" !important; display: block !important; position: absolute !important; top: 50% !important; left: 50% !important; width: 18px !important; height: 18px !important; margin: 0 !important; padding: 0 !important; border: 0 !important; border-radius: 0 !important; background: currentColor !important; box-shadow: none !important; transform: translate(-50%, -50%) !important; pointer-events: none !important; -webkit-mask: ' + play + ' center / contain no-repeat !important; mask: ' + play + ' center / contain no-repeat !important; }',
            'button[data-listening-playback="playing"]::before { -webkit-mask-image: ' + pause + ' !important; mask-image: ' + pause + ' !important; }',
            'button[data-listening-playback]::after { content: none !important; display: none !important; }'
        ].join('\n');
        (doc.head || doc.documentElement).appendChild(style);
    }

    function bindPlayButton(audio, button) {
        var pendingPlay = false;
        var requestId = 0;
        var events = ['play', 'playing', 'pause', 'ended', 'emptied', 'abort', 'error', 'loadedmetadata'];

        function setAttribute(name, value) {
            if (button.getAttribute(name) !== value) button.setAttribute(name, value);
        }

        function isPlaying() {
            return !audio.paused && !audio.ended && !audio.error;
        }

        function render() {
            var playing = isPlaying();
            setAttribute('data-listening-playback', playing ? 'playing' : 'paused');
            setAttribute('aria-label', playing ? 'Pause audio' : 'Play audio');
            setAttribute('title', playing ? 'Pause audio' : 'Play audio');
        }

        function mediaChanged(event) {
            if (['pause', 'ended', 'emptied', 'abort', 'error'].indexOf(event.type) !== -1) {
                pendingPlay = false;
                requestId++;
            }
            render();
        }

        function toggle(event) {
            // Own this click once, before legacy listeners and inline handlers.
            // Otherwise two handlers can immediately undo each other's toggle.
            event.preventDefault();
            event.stopImmediatePropagation();
            if (button.disabled) return;
            var currentRequest = ++requestId;
            if (pendingPlay || isPlaying()) {
                pendingPlay = false;
                audio.pause();
                render();
                return;
            }
            pendingPlay = true;
            function settled() {
                if (currentRequest !== requestId) return;
                pendingPlay = false;
                render();
            }
            function failed() {
                if (currentRequest !== requestId) return;
                pendingPlay = false;
                audio.pause();
                render();
            }
            try {
                var result = audio.play();
                if (result && typeof result.then === 'function') result.then(settled, failed);
                else settled();
            } catch (_) {
                failed();
            }
            render();
        }

        button.addEventListener('click', toggle, true);
        events.forEach(function bind(type) { audio.addEventListener(type, mediaChanged); });
        render();
        return {
            audio: audio,
            render: render,
            destroy: function destroy() {
                requestId++;
                button.removeEventListener('click', toggle, true);
                events.forEach(function unbind(type) { audio.removeEventListener(type, mediaChanged); });
                button.removeAttribute('data-listening-playback');
            }
        };
    }

    function formatTime(seconds) {
        var value = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0;
        return String(Math.floor(value / 60)).padStart(2, '0') + ':' + String(value % 60).padStart(2, '0');
    }

    function bindPlayer(doc, audio, root, progress) {
        var win = doc.defaultView || global;
        var fill = progress.querySelector(FILL_SELECTOR);
        var knob = progress.querySelector('.knob');
        var time = root.querySelector(TIME_SELECTOR);
        var pointerId = null;
        var previewTime = null;
        var listeners = [];

        function listen(target, type, handler, options) {
            target.addEventListener(type, handler, options);
            listeners.push(function remove() { target.removeEventListener(type, handler, options); });
        }

        function duration() {
            return Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : 0;
        }

        function render() {
            var total = duration();
            var current = previewTime !== null ? previewTime : audio.currentTime;
            current = Number.isFinite(current) ? Math.min(total, Math.max(0, current)) : 0;
            var percent = (total ? current / total * 100 : 0) + '%';
            if (fill) fill.style.width = percent;
            if (knob) knob.style.left = percent;
            var text = formatTime(current) + ' / ' + formatTime(total);
            if (time && time.textContent !== text) time.textContent = text;
            progress.setAttribute('aria-valuemax', String(total));
            progress.setAttribute('aria-valuenow', String(current));
            progress.setAttribute('aria-valuetext', text);
            progress.setAttribute('aria-disabled', total ? 'false' : 'true');
        }

        function consume(event) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }

        function preview(event) {
            var rect = progress.getBoundingClientRect();
            if (!duration() || rect.width <= 0 || !Number.isFinite(event.clientX)) return;
            previewTime = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width)) * duration();
            render();
        }

        function seek(seconds) {
            if (duration() && Number.isFinite(seconds)) {
                try {
                    audio.currentTime = Math.min(duration(), Math.max(0, seconds));
                } catch (_) {
                    // A source can be replaced between the gesture and the seek.
                }
            }
            render();
        }

        function cancel() {
            var previousPointer = pointerId;
            pointerId = null;
            previewTime = null;
            if (previousPointer !== null && progress.hasPointerCapture && progress.hasPointerCapture(previousPointer)) {
                progress.releasePointerCapture(previousPointer);
            }
            render();
        }

        function start(event) {
            if (event.isPrimary === false || event.button !== 0 || pointerId !== null) return;
            consume(event);
            if (!duration()) return;
            pointerId = event.pointerId;
            progress.focus({ preventScroll: true });
            if (progress.setPointerCapture) {
                try { progress.setPointerCapture(pointerId); } catch (_) { }
            }
            preview(event);
        }

        function move(event) {
            if (pointerId === null || event.pointerId !== pointerId) return;
            consume(event);
            preview(event);
        }

        function finish(event) {
            if (pointerId === null || event.pointerId !== pointerId) return;
            consume(event);
            preview(event);
            var target = previewTime;
            cancel();
            // Commit once on release instead of issuing a new media request on
            // every move, without changing playback state or speed.
            seek(target);
        }

        function cancelPointer(event) {
            if (pointerId !== null && event.pointerId === pointerId) cancel();
        }

        function keyboardSeek(event) {
            var target = audio.currentTime;
            switch (event.key) {
                case 'ArrowLeft':
                case 'ArrowDown': target -= 5; break;
                case 'ArrowRight':
                case 'ArrowUp': target += 5; break;
                case 'Home': target = 0; break;
                case 'End': target = duration(); break;
                default: return;
            }
            consume(event);
            cancel();
            seek(target);
        }

        progress.setAttribute('role', 'slider');
        progress.setAttribute('tabindex', '0');
        progress.setAttribute('aria-label', 'Audio progress');
        progress.setAttribute('aria-orientation', 'horizontal');
        progress.setAttribute('aria-valuemin', '0');
        progress.style.touchAction = 'none';
        progress.style.userSelect = 'none';

        listen(progress, 'pointerdown', start, true);
        listen(win, 'pointermove', move, true);
        listen(win, 'pointerup', finish, true);
        listen(win, 'pointercancel', cancelPointer, true);
        listen(progress, 'lostpointercapture', cancelPointer);
        listen(win, 'blur', cancel);
        listen(progress, 'keydown', keyboardSeek, true);
        // Stop the original mouse handlers from starting a second scrubbing
        // session or seeking again when the captured pointer is released.
        listen(progress, 'mousedown', consume, true);
        listen(progress, 'click', consume, true);
        ['timeupdate', 'loadedmetadata', 'durationchange', 'seeked', 'ended'].forEach(function bindMediaEvent(type) {
            listen(audio, type, render);
        });
        listen(audio, 'emptied', cancel);
        listen(audio, 'error', cancel);
        render();

        return {
            audio: audio,
            destroy: function destroy() {
                cancel();
                listeners.forEach(function removeListener(remove) { remove(); });
            }
        };
    }

    function install(doc) {
        if (!doc || doc.__listeningAudioPlayerInstalled) return;
        doc.__listeningAudioPlayerInstalled = true;
        var controllers = new Map();
        var buttons = new Map();
        installButtonStyle(doc);

        function scan() {
            buttons.forEach(function removeDetached(controller, button) {
                if (!button.isConnected || !controller.audio.isConnected) {
                    controller.destroy();
                    buttons.delete(button);
                }
            });
            controllers.forEach(function removeDetached(controller, progress) {
                if (!progress.isConnected || !controller.audio.isConnected) {
                    controller.destroy();
                    controllers.delete(progress);
                }
            });
            Array.prototype.forEach.call(doc.querySelectorAll('audio'), function attach(audio) {
                // Some templates place audio beside, rather than inside, the
                // visible controls. Stop at the nearest unambiguous container.
                var root = audio.parentElement;
                var foundButton = false;
                var foundProgress = false;
                while (root) {
                    if (root.querySelectorAll('audio').length !== 1) return;
                    var button = !foundButton && root.querySelector(PLAY_SELECTOR);
                    if (button) {
                        var controller = buttons.get(button);
                        if (controller && controller.audio !== audio) {
                            controller.destroy();
                            buttons.delete(button);
                        }
                        if (!buttons.has(button)) buttons.set(button, bindPlayButton(audio, button));
                        else buttons.get(button).render();
                        foundButton = true;
                    }
                    var progress = !foundProgress && root.querySelector(PROGRESS_SELECTOR);
                    if (progress) {
                        if (!controllers.has(progress)) {
                            controllers.set(progress, bindPlayer(doc, audio, root, progress));
                        }
                        foundProgress = true;
                    }
                    if ((foundButton && foundProgress) || root === doc.body) return;
                    root = root.parentElement;
                }
            });
        }

        scan();
        var win = doc.defaultView || global;
        if (doc.body && typeof win.MutationObserver === 'function') {
            // Question switches and resets can replace the entire player.
            new win.MutationObserver(scan).observe(doc.body, { childList: true, subtree: true });
        }
    }

    global.ListeningAudioPlayer = { install: install };
})(typeof window !== 'undefined' ? window : globalThis);
