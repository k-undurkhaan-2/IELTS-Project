(function initReadingDictionaryAssets(global) {
    'use strict';

    if (global.ReadingDictionaryAssets) return;

    // The bundle builder injects content hashes. Direct source loading skips
    // persistent caching so an unversioned development script cannot go stale.
    const ASSET_VERSIONS = null;
    const DATABASE_NAME = 'ielts-reading-dictionaries';
    const STORE_NAME = 'dictionaries';
    const CACHE_TIMEOUT_MS = 2000;
    const sourceUrl = document.currentScript && document.currentScript.src;
    const baseUrl = new URL('../../assets/wordlists/', sourceUrl || new URL('js/runtime/readingDictionaryAssets.js', document.baseURI));
    const dictionaries = [
        {
            file: 'ielts_core.bundle.js',
            read: () => global.__EMBEDDED_WORDLISTS__?.ielts_core,
            valid: value => Array.isArray(value) && value.length > 0
                && value.every(entry => entry && typeof entry.word === 'string' && typeof entry.meaning === 'string'),
            write(value) {
                global.__EMBEDDED_WORDLISTS__ = global.__EMBEDDED_WORDLISTS__ || {};
                global.__EMBEDDED_WORDLISTS__.ielts_core = value;
            }
        },
        {
            file: 'ecdict_reading.bundle.js',
            read: () => global.__LOCAL_DICTIONARIES__?.ecdict,
            valid: value => Array.isArray(value?.entries) && value.entries.length > 0
                && value.entries.every(entry => entry && typeof entry.w === 'string'
                    && (typeof entry.t === 'string' || typeof entry.d === 'string')),
            write(value) {
                global.__LOCAL_DICTIONARIES__ = global.__LOCAL_DICTIONARIES__ || {};
                global.__LOCAL_DICTIONARIES__.ecdict = value;
            }
        }
    ];
    const cacheKey = `reading-dictionaries-v1:${baseUrl.href}:${JSON.stringify(ASSET_VERSIONS)}`;
    const pending = new Map();
    let databasePromise;
    let loadPromise;
    let preloadPromise;
    let sharedService;

    // Only validate full payloads at the storage boundary, not on every lookup.
    function available(dictionary) {
        const value = dictionary.read();
        return dictionary.file === 'ielts_core.bundle.js'
            ? Array.isArray(value) && value.length > 0
            : Array.isArray(value?.entries) && value.entries.length > 0;
    }

    function getSharedOwner() {
        for (const key of ['parent', 'opener']) {
            try {
                const peer = global[key];
                if (!peer || peer === global || peer.closed) continue;
                const assets = peer.ReadingDictionaryAssets;
                if (assets && assets.cacheKey === cacheKey) return { assets, window: peer };
            } catch (_) { /* A cross-origin parent/opener is not a cache owner. */ }
        }
        return null;
    }

    function adopt(owner) {
        const snapshot = owner?.assets.snapshot();
        if (!snapshot) return false;
        dictionaries.forEach((dictionary, index) => dictionary.write(snapshot.values[index]));
        sharedService = snapshot.service;
        return true;
    }

    function isReady() {
        if (dictionaries.every(available)) return true;
        try { return adopt(getSharedOwner()); } catch (_) { return false; }
    }

    function loadFromOwner(owner) {
        return new Promise((resolve, reject) => {
            let settled = false;
            const unavailable = () => finish(false);
            const timer = global.setTimeout(unavailable, 60000);
            function finish(loaded, error) {
                if (settled) return;
                settled = true;
                global.clearTimeout(timer);
                try { owner.window.removeEventListener('pagehide', unavailable); } catch (_) { }
                if (error) reject(error);
                else resolve(loaded);
            }
            try {
                // A popup must not wait forever on a promise from an opener
                // that navigated away or closed during a background download.
                owner.window.addEventListener('pagehide', unavailable, { once: true });
                if (owner.window.closed) return finish(false);
                owner.assets.ensureLoaded({ localOnly: true }).then(() => {
                    if (settled) return;
                    try { finish(adopt(owner)); } catch (_) { finish(false); }
                }, error => finish(false, error));
            } catch (_) { finish(false); }
        });
    }

    function openDatabase() {
        if (databasePromise) return databasePromise;
        databasePromise = new Promise(resolve => {
            let settled = false;
            const timer = global.setTimeout(() => finish(null), CACHE_TIMEOUT_MS);
            function finish(database) {
                if (settled) {
                    database?.close();
                    return;
                }
                settled = true;
                global.clearTimeout(timer);
                resolve(database);
            }
            try {
                if (!ASSET_VERSIONS || !/^https?:$/.test(baseUrl.protocol) || !global.indexedDB) {
                    finish(null);
                    return;
                }
                const request = global.indexedDB.open(DATABASE_NAME, 1);
                request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
                request.onsuccess = () => {
                    const database = request.result;
                    database.onversionchange = () => {
                        database.close();
                        databasePromise = null;
                    };
                    finish(database);
                };
                request.onerror = request.onblocked = () => finish(null);
            } catch (_) { finish(null); }
        });
        return databasePromise;
    }

    async function accessCache(dictionary, value) {
        const database = await openDatabase();
        if (!database) return undefined;
        return new Promise(resolve => {
            let transaction;
            let result;
            let settled = false;
            const timer = global.setTimeout(() => {
                finish(undefined);
                try { transaction?.abort(); } catch (_) { }
            }, CACHE_TIMEOUT_MS);
            function finish(value) {
                if (settled) return;
                settled = true;
                global.clearTimeout(timer);
                resolve(value);
            }
            try {
                const writing = value !== undefined;
                transaction = database.transaction(STORE_NAME, writing ? 'readwrite' : 'readonly');
                const store = transaction.objectStore(STORE_NAME);
                const key = new URL(dictionary.file, baseUrl).href;
                const request = writing
                    ? store.put({ version: ASSET_VERSIONS[dictionary.file], value }, key)
                    : store.get(key);
                request.onsuccess = () => { result = request.result; };
                transaction.oncomplete = () => finish(result);
                transaction.onerror = transaction.onabort = () => finish(undefined);
            } catch (_) { finish(undefined); }
        });
    }

    function loadScript(dictionary) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            const url = new URL(dictionary.file, baseUrl);
            if (ASSET_VERSIONS) url.searchParams.set('v', ASSET_VERSIONS[dictionary.file]);
            script.src = url.href;
            script.async = true;
            script.fetchPriority = 'low';
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
            script.onload = () => finish(dictionary.valid(dictionary.read()) ? null : new Error('reading_dictionary_missing'));
            script.onerror = () => finish(new Error('reading_dictionary_failed'));
            document.head.appendChild(script);
        });
    }

    async function loadCached(dictionary) {
        if (available(dictionary)) return;
        const cached = await accessCache(dictionary);
        if (cached && cached.version === ASSET_VERSIONS?.[dictionary.file] && dictionary.valid(cached.value)) {
            dictionary.write(cached.value);
            return;
        }
        await loadScript(dictionary);
        await accessCache(dictionary, dictionary.read());
    }

    async function loadWithLock(dictionary) {
        // Independent tabs recheck IndexedDB inside the lock, so only the first
        // tab downloads a missing version. Parent/child pages also share memory.
        let entered = false;
        try {
            if (global.navigator?.locks?.request) {
                return await global.navigator.locks.request(`${cacheKey}:${dictionary.file}`, () => {
                    entered = true;
                    return loadCached(dictionary);
                });
            }
        } catch (error) {
            if (entered) throw error;
        }
        return loadCached(dictionary);
    }

    function load(dictionary) {
        if (available(dictionary)) return Promise.resolve();
        if (pending.has(dictionary.file)) return pending.get(dictionary.file);
        const promise = loadWithLock(dictionary).finally(() => pending.delete(dictionary.file));
        pending.set(dictionary.file, promise);
        return promise;
    }

    function ensureLoaded({ localOnly = false } = {}) {
        if (isReady()) return Promise.resolve();
        if (loadPromise) return loadPromise;
        loadPromise = (async () => {
            const owner = localOnly ? null : getSharedOwner();
            if (owner && await loadFromOwner(owner)) return;
            await Promise.all(dictionaries.map(load));
        })().finally(() => { loadPromise = null; });
        return loadPromise;
    }

    function whenIdle() {
        return new Promise(resolve => {
            if (typeof global.requestIdleCallback === 'function') {
                global.requestIdleCallback(resolve, { timeout: 3000 });
            } else {
                global.setTimeout(resolve, 0);
            }
        });
    }

    function getService() {
        return sharedService || global.DictionaryService;
    }

    function preload() {
        if (preloadPromise) return preloadPromise;
        preloadPromise = (async () => {
            if (document.readyState !== 'complete') {
                await new Promise(resolve => global.addEventListener('load', resolve, { once: true }));
            }
            await whenIdle();
            await ensureLoaded();
            await whenIdle();
            getService()?.init();
        })().catch(error => {
            preloadPromise = null;
            throw error;
        });
        return preloadPromise;
    }

    global.ReadingDictionaryAssets = {
        cacheKey,
        isReady,
        ensureLoaded,
        preload,
        getService,
        snapshot: () => dictionaries.every(available)
            ? { values: dictionaries.map(dictionary => dictionary.read()), service: getService() }
            : null
    };
})(window);
