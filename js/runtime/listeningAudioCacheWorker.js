(function initListeningAudioCacheWorker(scope) {
    'use strict';

    var jobs = new Map();
    var MAX_BYTES = 100 * 1024 * 1024;

    scope.addEventListener('message', async function download(event) {
        var message = event.data || {};
        if (!Number.isSafeInteger(message.id) || message.id < 1) return;
        if (message.type === 'cancel') {
            if (jobs.has(message.id)) jobs.get(message.id).abort();
            jobs.delete(message.id);
            return;
        }
        if (message.type !== 'load' || jobs.has(message.id)) return;

        var controller = new AbortController();
        jobs.set(message.id, controller);
        try {
            var url = new URL(message.url, scope.location.href);
            // Accept same-origin media file URLs only, with no redirects or
            // caller-supplied request methods, credentials, or headers.
            if (!/^https?:$/.test(url.protocol) || url.origin !== scope.location.origin
                || url.username || url.password || !/\.(mp3|wav|ogg|oga|m4a|mp4|aac|flac|webm|opus)$/i.test(url.pathname)) {
                throw new Error('Unsupported audio source');
            }
            var response = await fetch(url.href, {
                credentials: 'same-origin', mode: 'same-origin', redirect: 'error', signal: controller.signal
            });
            var type = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
            if (response.status !== 200 || response.headers.has('content-range')
                || !(/^(audio|video)\//.test(type) || type === 'application/octet-stream')
                || Number(response.headers.get('content-length')) > MAX_BYTES) {
                throw new Error('Incomplete or unsupported audio response');
            }
            var reader = response.body.getReader();
            var chunks = [];
            var size = 0;
            while (true) {
                var chunk = await reader.read();
                if (chunk.done) break;
                size += chunk.value.byteLength;
                if (size > MAX_BYTES) throw new Error('Audio exceeds the memory cache limit');
                chunks.push(chunk.value);
            }
            if (!size) throw new Error('Empty audio response');
            if (jobs.get(message.id) === controller) {
                scope.postMessage({ id: message.id, blob: new Blob(chunks, { type: type }) });
            }
        } catch (_) {
            if (jobs.get(message.id) === controller) scope.postMessage({ id: message.id, failed: true });
            controller.abort();
        } finally {
            if (jobs.get(message.id) === controller) jobs.delete(message.id);
        }
    });
})(self);
