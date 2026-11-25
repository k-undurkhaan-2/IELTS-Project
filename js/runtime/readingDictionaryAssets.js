(function initReadingDictionaryAssets(global) {
    'use strict';

    const sourceUrl = document.currentScript && document.currentScript.src;
    const dictionaries = [
        {
            file: 'ielts_core.bundle.js',
            available: () => Array.isArray(global.__EMBEDDED_WORDLISTS__?.ielts_core)
                && global.__EMBEDDED_WORDLISTS__.ielts_core.length > 0
        },
        {
            file: 'ecdict_reading.bundle.js',
            available: () => Array.isArray(global.__LOCAL_DICTIONARIES__?.ecdict?.entries)
                && global.__LOCAL_DICTIONARIES__.ecdict.entries.length > 0
        }
    ];
    const pending = new Map();

    function load(dictionary) {
        if (dictionary.available()) return Promise.resolve();
        if (pending.has(dictionary.file)) return pending.get(dictionary.file);
        const promise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = new URL(`../../assets/wordlists/${dictionary.file}`, sourceUrl).href;
            script.async = true;
            let settled = false;
            const timeout = global.setTimeout(() => finish(new Error('reading_dictionary_timeout')), 60000);
            function finish(error) {
                if (settled) return;
                settled = true;
                global.clearTimeout(timeout);
                script.onload = script.onerror = null;
                script.remove();
                if (error) reject(error);
                else resolve();
            }
            script.onload = () => finish(dictionary.available() ? null : new Error('reading_dictionary_missing'));
            script.onerror = () => finish(new Error('reading_dictionary_failed'));
            document.head.appendChild(script);
        }).finally(() => pending.delete(dictionary.file));
        pending.set(dictionary.file, promise);
        return promise;
    }

    global.ReadingDictionaryAssets = {
        isReady: () => dictionaries.every(dictionary => dictionary.available()),
        ensureLoaded: () => Promise.all(dictionaries.map(load))
    };
})(window);
