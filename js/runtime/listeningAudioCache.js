(function initListeningAudioCache(global) {
    'use strict';

    var scriptUrl = global.document && global.document.currentScript && global.document.currentScript.src;

    function install(doc) {
        if (doc.__listeningAudioCache) return doc.__listeningAudioCache;
        var win = doc.defaultView || global;
        if (!/^https?:$/.test(win.location.protocol) || !win.Worker || !win.URL.createObjectURL) return null;
        var records = new Map();
        var downloads = new Map();
        var requests = new Map();
        var nextId = 0;
        var worker = null;
        var workerFailed = false;
        var closed = false;

        function sourceSignature(audio) {
            return JSON.stringify(Array.prototype.map.call(audio.querySelectorAll('source'), function describe(source) {
                return [source.getAttribute('src'), source.getAttribute('type')];
            }));
        }

        function sourceUrl(audio, record) {
            if (audio.srcObject) return '';
            var source = audio.getAttribute('src');
            if (record && record.applied && source === record.entry.objectUrl) {
                if (record.fromChildren && sourceSignature(audio) !== record.signature) {
                    audio.removeAttribute('src');
                    audio.load();
                    source = '';
                } else return record.url;
            }
            if (!source) {
                var candidates = audio.querySelectorAll('source[src]');
                for (var index = 0; index < candidates.length; index++) {
                    var candidate = candidates[index];
                    if (!candidate.type || audio.canPlayType(candidate.type)) {
                        source = candidate.getAttribute('src');
                        break;
                    }
                }
            }
            if (!source) return '';
            try {
                var url = new win.URL(source, audio.baseURI);
                if (/^https?:$/.test(url.protocol) && url.origin === win.location.origin
                    && !url.username && !url.password && !url.hash) return url.href;
            } catch (_) { }
            return '';
        }

        function state(record, value) {
            record.audio.setAttribute('data-listening-cache', value);
        }

        function apply(record) {
            var audio = record.audio;
            if (closed || records.get(audio) !== record || !audio.isConnected || sourceUrl(audio, record) !== record.url) return;
            if (record.entry.failed || record.failed) {
                audio.preload = 'auto';
                state(record, 'streaming');
                return;
            }
            if (!record.entry.objectUrl) return;
            state(record, 'ready');
            // Switching src reloads the decoder. Wait for a safe pause instead
            // of interrupting playback, a pending play(), or a drag gesture.
            if (record.applied || record.scrubbing || !audio.paused || audio.seeking || audio.ended) return;
            var position = audio.currentTime;
            var rate = audio.playbackRate;
            record.applied = true;
            audio.preload = 'auto';
            audio.src = record.entry.objectUrl;
            audio.load();
            // Set the default start position even before blob metadata arrives.
            if (Number.isFinite(position) && position > 0) audio.currentTime = position;
            audio.playbackRate = rate;
        }

        function failWorker() {
            workerFailed = true;
            if (worker) worker.terminate();
            worker = null;
            requests.clear();
            downloads.forEach(function fail(entry) {
                if (entry.objectUrl) return;
                entry.failed = true;
                entry.users.forEach(apply);
            });
        }

        function startDownload(entry) {
            try {
                if (workerFailed) throw new Error('Audio downloader unavailable');
                if (!worker) {
                    var base = new win.URL(scriptUrl || '/js/bundles/listening-record-bridge.bundle.js', doc.baseURI);
                    // The service serves its trusted worker under /js, including
                    // when a VIP compatibility page lives under ListeningPractice.
                    var workerUrl = /\/ListeningPractice\//i.test(base.pathname)
                        ? new win.URL('/js/bundles/listening-audio-cache-worker.bundle.js', base)
                        : new win.URL('listening-audio-cache-worker.bundle.js', base);
                    worker = new win.Worker(workerUrl.href);
                    worker.addEventListener('error', function workerError(event) {
                        event.preventDefault();
                        failWorker();
                    });
                    worker.addEventListener('message', function completed(event) {
                        var result = event.data || {};
                        var pending = requests.get(result.id);
                        if (!pending || closed) return;
                        requests.delete(result.id);
                        pending.failed = !result.blob || !result.blob.size;
                        if (!pending.failed) pending.objectUrl = win.URL.createObjectURL(result.blob);
                        pending.users.forEach(apply);
                    });
                }
                requests.set(entry.id, entry);
                worker.postMessage({ type: 'load', id: entry.id, url: entry.url });
            } catch (_) {
                failWorker();
            }
        }

        function release(record) {
            var audio = record.audio;
            record.listeners.forEach(function remove(listener) { audio.removeEventListener(listener[0], listener[1]); });
            // Detached players may later be reinserted. Do not leave them with
            // a revoked blob URL or keep downloading their original recording.
            if (record.applied && audio.getAttribute('src') === record.entry.objectUrl) {
                audio.preload = 'none';
                if (record.fromChildren) audio.removeAttribute('src');
                else audio.src = record.url;
            }
            audio.removeAttribute('data-listening-cache');
            records.delete(audio);
            record.entry.users.delete(record);
            if (record.entry.users.size) return;
            requests.delete(record.entry.id);
            if (worker) worker.postMessage({ type: 'cancel', id: record.entry.id });
            if (record.entry.objectUrl) win.URL.revokeObjectURL(record.entry.objectUrl);
            downloads.delete(record.url);
        }

        function attach(audio, url) {
            var entry = downloads.get(url);
            var fresh = !entry;
            if (!entry) {
                entry = { id: ++nextId, url: url, users: new Set(), objectUrl: '', failed: false };
                downloads.set(url, entry);
            }
            var record = {
                audio: audio, url: url, entry: entry, applied: false, failed: false, scrubbing: false,
                fromChildren: !audio.getAttribute('src'), signature: sourceSignature(audio), listeners: []
            };
            records.set(audio, record);
            entry.users.add(record);
            // Keep native streaming available while one shared full-file
            // download runs; metadata preload avoids two eager full downloads.
            audio.preload = 'metadata';
            state(record, 'loading');
            ['pause', 'seeked', 'loadedmetadata'].forEach(function listen(type) {
                var handler = function readyToApply() { apply(record); };
                record.listeners.push([type, handler]);
                audio.addEventListener(type, handler);
            });
            var onError = function cachedSourceFailed() {
                if (!record.applied || audio.getAttribute('src') !== entry.objectUrl) return;
                var position = audio.currentTime;
                var rate = audio.playbackRate;
                record.failed = true;
                record.applied = false;
                if (record.fromChildren) audio.removeAttribute('src');
                else audio.src = record.url;
                audio.preload = 'auto';
                audio.load();
                if (Number.isFinite(position) && position > 0) audio.currentTime = position;
                audio.playbackRate = rate;
                state(record, 'streaming');
            };
            record.listeners.push(['error', onError]);
            audio.addEventListener('error', onError);
            if (fresh) startDownload(entry);
            apply(record);
        }

        function scan() {
            if (closed) return;
            records.forEach(function reconcile(record, audio) {
                if (!audio.isConnected || sourceUrl(audio, record) !== record.url) release(record);
            });
            Array.prototype.forEach.call(doc.querySelectorAll('audio'), function visit(audio) {
                if (records.has(audio)) return;
                var url = sourceUrl(audio);
                if (url) attach(audio, url);
                else audio.preload = 'auto';
            });
        }

        var observer = new win.MutationObserver(scan);
        observer.observe(doc.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'type'] });
        var manager = {
            setScrubbing: function setScrubbing(audio, active) {
                var record = records.get(audio);
                if (!record) return;
                record.scrubbing = active;
                if (!active) Promise.resolve().then(function afterGesture() { apply(record); });
            }
        };
        doc.__listeningAudioCache = manager;
        win.addEventListener('pagehide', function dispose(event) {
            if (event.persisted) return;
            closed = true;
            observer.disconnect();
            records.forEach(release);
            if (worker) worker.terminate();
            worker = null;
        });
        scan();
        return manager;
    }

    global.ListeningAudioCache = { install: install };
})(typeof window !== 'undefined' ? window : globalThis);
