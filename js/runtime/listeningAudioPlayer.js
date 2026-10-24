(function initListeningAudioPlayer(global) {
    'use strict';

    var PROGRESS_SELECTOR = '.progress-container, .progress-area, .progress-wrap, .prog-wrap, .progress-box, .progress-track, #seekBar';
    var FILL_SELECTOR = '.progress-bar, .progress-fill, .prog-fill, .pos';
    var TIME_SELECTOR = '.time-display, .time-text, .time, #timeDisp, #timeText';

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
            // every move. Playback and speed remain under the existing controls.
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

        function scan() {
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
                while (root && root !== doc.body) {
                    if (root.querySelectorAll('audio').length !== 1) return;
                    var progress = root.querySelector(PROGRESS_SELECTOR);
                    if (progress) {
                        if (!controllers.has(progress)) {
                            controllers.set(progress, bindPlayer(doc, audio, root, progress));
                        }
                        return;
                    }
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
