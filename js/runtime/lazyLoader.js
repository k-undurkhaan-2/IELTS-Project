(function initLazyLoader(global) {
    'use strict';

    var manifest = Object.create(null);
    var scriptStatus = Object.create(null);
    var groupStatus = Object.create(null);
    var dependencies = Object.create(null);
    var providedScripts = new Set();
    var READING_EXAM_DATA_SCRIPT = 'assets/scripts/complete-exam-data.js';
    var LISTENING_EXAM_MANIFEST_SCRIPT = 'assets/generated/listening-exams/manifest.js';
    var LISTENING_EXAM_INDEX_SCRIPT = 'assets/generated/listening-exams/listening-index.compat.js';

    function summarizeLazyLoaderErrorForLog(error) {
        if (!error || typeof error !== 'object') {
            return { name: typeof error };
        }
        return {
            name: typeof error.name === 'string' && error.name ? error.name.slice(0, 80) : 'Error'
        };
    }

    function registerDefaultManifest() {
        manifest['exam-data'] = [
            READING_EXAM_DATA_SCRIPT
        ];

        manifest['state-core'] = [
            // Provided by js/bundles/core-foundation.bundle.js.
        ];

        manifest['practice-suite'] = [
            'js/bundles/practice.bundle.js'
        ];

        manifest['browse-runtime'] = [
            'js/bundles/browse.bundle.js'
        ];

        // 向后兼容旧组名
        manifest['browse-view'] = manifest['browse-runtime'].slice();

        manifest['session-suite'] = [
            'js/bundles/session.bundle.js'
        ];

        manifest['more-tools'] = [
            'js/bundles/more.bundle.js'
        ];

        manifest['theme-tools'] = [
            'js/bundles/theme.bundle.js'
        ];

        manifest['settings-tools'] = [
            'js/bundles/settings.bundle.js'
        ];

        manifest['diagnostics-tools'] = [
            'js/bundles/diagnostics.bundle.js'
        ];

        dependencies['state-core'] = [];
        dependencies['exam-data'] = [];
        dependencies['practice-suite'] = ['state-core'];
        dependencies['browse-runtime'] = ['state-core'];
        dependencies['browse-view'] = ['state-core'];
        dependencies['session-suite'] = ['browse-runtime', 'practice-suite'];
        dependencies['settings-tools'] = ['state-core'];
        dependencies['more-tools'] = ['state-core', 'settings-tools'];
        dependencies['theme-tools'] = [];
        dependencies['diagnostics-tools'] = ['state-core', 'settings-tools'];
    }

    function setBuiltInListeningAvailability(available, reason) {
        try {
            global.__defaultListeningLibraryAvailable = available === true;
            global.__defaultListeningLibraryAvailabilityReason = reason || (available ? 'available' : 'unavailable');
        } catch (_) { }
    }

    function normalizeScriptUrl(url) {
        if (!url) {
            return '';
        }
        try {
            return resolveTrustedScriptUrl(url);
        } catch (_) {
            return '';
        }
    }

    function resolveTrustedScriptUrl(url) {
        if (!url) {
            return '';
        }
        try {
            var baseHref = document.baseURI || (global.location && global.location.href) || 'http://localhost/';
            var resolved = new URL(String(url), baseHref);
            var protocol = (resolved.protocol || '').toLowerCase();
            if (!resolved.pathname || !resolved.pathname.toLowerCase().endsWith('.js')) {
                return '';
            }
            if (protocol === 'http:' || protocol === 'https:') {
                var origin = global.location && global.location.origin;
                return origin && origin !== 'null' && resolved.origin === origin ? resolved.href : '';
            }
            if (protocol === 'file:' && global.location && global.location.protocol === 'file:') {
                return resolved.href;
            }
        } catch (_) {
            return '';
        }
        return '';
    }

    function findExistingScriptTag(url) {
        if (typeof document === 'undefined') {
            return null;
        }
        var target = normalizeScriptUrl(url);
        if (!target) {
            return null;
        }
        var scripts = document.querySelectorAll('script[src]');
        for (var i = 0; i < scripts.length; i += 1) {
            var node = scripts[i];
            var srcAttr = node.getAttribute('src');
            if (!srcAttr) {
                continue;
            }
            if (normalizeScriptUrl(srcAttr) === target || normalizeScriptUrl(node.src) === target) {
                return node;
            }
        }
        return null;
    }

    function markProvided(files) {
        if (!Array.isArray(files)) {
            return;
        }
        files.forEach(function mark(file) {
            if (!file) {
                return;
            }
            var normalized = normalizeScriptUrl(file);
            providedScripts.add(normalized);
            scriptStatus[file] = 'loaded';
            if (normalized) {
                scriptStatus[normalized] = 'loaded';
            }
        });
    }

    function isProvided(url) {
        var normalized = normalizeScriptUrl(url);
        return providedScripts.has(normalized) || scriptStatus[url] === 'loaded' || scriptStatus[normalized] === 'loaded';
    }

    function loadScript(url) {
        if (!url) {
            return Promise.resolve();
        }
        var safeUrl = resolveTrustedScriptUrl(url);
        if (!safeUrl) {
            return Promise.reject(new Error('加载脚本失败: 不可信或不支持的脚本地址'));
        }
        url = safeUrl;
        if (isProvided(url)) {
            scriptStatus[url] = 'loaded';
            return Promise.resolve();
        }
        if (scriptStatus[url] === 'loaded') {
            return Promise.resolve();
        }
        if (scriptStatus[url] && scriptStatus[url].then) {
            return scriptStatus[url];
        }

        var existing = findExistingScriptTag(url);
        if (existing) {
            scriptStatus[url] = 'loaded';
            return Promise.resolve();
        }

        scriptStatus[url] = new Promise(function inject(resolve, reject) {
            var script = document.createElement('script');
            script.src = safeUrl;
            script.async = true;
            script.onload = function handleLoad() {
                scriptStatus[url] = 'loaded';
                resolve();
            };
            script.onerror = function handleError(error) {
                scriptStatus[url] = null;
                try {
                    if (script.parentNode) {
                        script.parentNode.removeChild(script);
                    }
                } catch (_) { }
                reject(new Error('加载脚本失败: ' + (error?.message || error)));
            };
            document.head.appendChild(script);
        });

        return scriptStatus[url];
    }

    function loadOptionalScript(url, label) {
        return loadScript(url).then(function onOptionalLoaded() {
            return true;
        }).catch(function onOptionalFailed(error) {
            scriptStatus[url] = null;
            try {
                console.warn('[LazyLoader] 可选脚本未加载，已跳过:', summarizeLazyLoaderErrorForLog(error));
            } catch (_) { }
            return false;
        });
    }

    function hasListeningManifest() {
        var manifestObject = global.__LISTENING_EXAM_MANIFEST__;
        return !!(
            manifestObject
            && typeof manifestObject === 'object'
            && Object.keys(manifestObject).length > 0
        );
    }

    function setBuiltInListeningSourceAvailability(available, reason, detail) {
        try {
            global.__defaultListeningLibrarySourceAvailable = available === true;
            global.__defaultListeningLibrarySourceAvailabilityReason = reason || (available ? 'available' : 'unavailable');
            global.__defaultListeningLibrarySourceAvailabilityDetail = detail || null;
        } catch (_) { }
    }

    function getListeningProbeEntry() {
        var index = Array.isArray(global.listeningExamIndex) ? global.listeningExamIndex : [];
        for (var i = 0; i < index.length; i += 1) {
            var entry = index[i];
            if (entry && entry.filename && entry.path && entry.hasHtml !== false) {
                return Object.assign({}, entry, { type: 'listening' });
            }
        }
        return null;
    }

    function getCurrentProtocol() {
        try {
            return global.location && global.location.protocol
                ? String(global.location.protocol).toLowerCase()
                : '';
        } catch (_) {
            return '';
        }
    }
    function hasProtocolPath(value) {
        return /^[a-z][a-z0-9+.-]*:/i.test(String(value || ''));
    }

    function normalizeListeningSourcePathPart(value, trimTrailing) {
        var raw = String(value || '').replace(/\\/g, '/').trim();
        if (!raw || hasProtocolPath(raw)) {
            return '';
        }
        raw = raw.replace(/^\/+/, '');
        return trimTrailing === false ? raw : raw.replace(/\/+$/, '');
    }

    function joinListeningSourcePath() {
        var parts = [];
        for (var i = 0; i < arguments.length; i += 1) {
            var part = normalizeListeningSourcePathPart(arguments[i]);
            if (part) {
                parts.push(part);
            }
        }
        return parts.join('/');
    }

    function encodeSourcePathSegment(segment) {
        try {
            return encodeURIComponent(decodeURIComponent(segment));
        } catch (_) {
            return encodeURIComponent(segment);
        }
    }

    function encodeSourcePathSegments(pathValue) {
        return String(pathValue || '')
            .split('/')
            .filter(Boolean)
            .map(encodeSourcePathSegment)
            .join('/');
    }

    function getListeningSourceRoot() {
        var index = Array.isArray(global.listeningExamIndex) ? global.listeningExamIndex : [];
        var configuredRoot = normalizeListeningSourcePathPart(index.pathRoot);
        return configuredRoot || 'ListeningPractice';
    }

    function getListeningEntrySourcePath(entry) {
        if (!entry || typeof entry !== 'object') {
            return '';
        }
        var sourcePath = normalizeListeningSourcePathPart(entry.sourcePath);
        if (sourcePath) {
            return sourcePath;
        }
        var entryPath = normalizeListeningSourcePathPart(entry.path);
        var filename = normalizeListeningSourcePathPart(entry.filename);
        if (!entryPath || !filename) {
            return '';
        }
        return joinListeningSourcePath(entryPath, filename);
    }

    function buildListeningSourceProbeUrl(entry) {
        var sourceRoot = getListeningSourceRoot();
        var entrySourcePath = getListeningEntrySourcePath(entry);
        if (!sourceRoot || !entrySourcePath) {
            return '';
        }
        var lowerRoot = sourceRoot.toLowerCase();
        var lowerEntryPath = entrySourcePath.toLowerCase();
        var combinedPath = lowerEntryPath === lowerRoot || lowerEntryPath.indexOf(lowerRoot + '/') === 0
            ? entrySourcePath
            : joinListeningSourcePath(sourceRoot, entrySourcePath);
        var encodedPath = encodeSourcePathSegments(combinedPath);
        if (!encodedPath) {
            return '';
        }
        try {
            var baseHref = document.baseURI || (global.location && global.location.href) || 'http://localhost/';
            var resolved = new URL(encodedPath, baseHref);
            return (resolved.protocol === 'http:' || resolved.protocol === 'https:') ? resolved.href : '';
        } catch (_) {
            return '';
        }
    }

    function responseIndicatesSourceAvailable(response) {
        if (!response) {
            return false;
        }
        var status = Number(response.status) || 0;
        return response.ok === true || status === 304;
    }

    function probeListeningSourceUrl(sourceUrl) {
        var fetcher = typeof global.fetch === 'function' ? global.fetch.bind(global) : null;
        if (!fetcher) {
            return Promise.resolve({ available: false, reason: 'source-probe-unavailable' });
        }
        return fetcher(sourceUrl, { method: 'HEAD', cache: 'no-store' }).then(function onHead(response) {
            if (responseIndicatesSourceAvailable(response)) {
                return { available: true, reason: 'available' };
            }
            if (response && Number(response.status) === 405) {
                return fetcher(sourceUrl, { method: 'GET', cache: 'no-store' }).then(function onGet(getResponse) {
                    return {
                        available: responseIndicatesSourceAvailable(getResponse),
                        reason: responseIndicatesSourceAvailable(getResponse) ? 'available' : 'source-root-unavailable'
                    };
                }).catch(function onGetFailed() {
                    return { available: false, reason: 'source-root-unavailable' };
                });
            }
            return { available: false, reason: 'source-root-unavailable' };
        }).catch(function onHeadFailed() {
            return { available: false, reason: 'source-root-unavailable' };
        });
    }
    function ensureBuiltInListeningSourceRoot() {
        var index = Array.isArray(global.listeningExamIndex) ? global.listeningExamIndex : [];
        if (!index.length) {
            setBuiltInListeningSourceAvailability(false, 'index-missing');
            return Promise.resolve(false);
        }

        var probeEntry = getListeningProbeEntry();
        if (!probeEntry) {
            setBuiltInListeningSourceAvailability(false, 'source-probe-entry-missing');
            return Promise.resolve(false);
        }

        var protocol = getCurrentProtocol();
        if (protocol !== 'http:' && protocol !== 'https:') {
            // Local static file mode is intentionally unsupported; use a local HTTP server for development.
            setBuiltInListeningSourceAvailability(false, 'unsupported-environment', { protocol: protocol || 'unknown' });
            return Promise.resolve(false);
        }

        var probeUrl = buildListeningSourceProbeUrl(probeEntry);
        if (!probeUrl) {
            setBuiltInListeningSourceAvailability(false, 'source-probe-url-missing', { protocol: protocol || 'unknown' });
            return Promise.resolve(false);
        }

        return probeListeningSourceUrl(probeUrl).then(function onListeningSourceProbe(result) {
            var available = result && result.available === true;
            var reason = result && result.reason ? result.reason : (available ? 'available' : 'source-root-unavailable');
            setBuiltInListeningSourceAvailability(
                available,
                reason,
                {
                    protocol: protocol || 'unknown',
                    pathRoot: getListeningSourceRoot(),
                    entryPath: getListeningEntrySourcePath(probeEntry),
                    url: probeUrl
                }
            );
            return available;
        });
    }

    function ensureOptionalListeningExamData() {
        setBuiltInListeningAvailability(false, 'pending-manifest');
        setBuiltInListeningSourceAvailability(false, 'pending-manifest');
        return loadOptionalScript(LISTENING_EXAM_MANIFEST_SCRIPT, 'listening manifest')
            .then(function afterManifestLoaded(loaded) {
                if (!loaded || !hasListeningManifest()) {
                    setBuiltInListeningAvailability(false, loaded ? 'manifest-empty' : 'manifest-missing');
                    setBuiltInListeningSourceAvailability(false, loaded ? 'manifest-empty' : 'manifest-missing');
                    return undefined;
                }
                return loadOptionalScript(LISTENING_EXAM_INDEX_SCRIPT, 'listening index')
                    .then(function afterListeningIndexLoaded(indexLoaded) {
                        if (!(
                            indexLoaded
                            && Array.isArray(global.listeningExamIndex)
                            && global.listeningExamIndex.length > 0
                        )) {
                            setBuiltInListeningAvailability(false, 'index-missing');
                            setBuiltInListeningSourceAvailability(false, 'index-missing');
                            return undefined;
                        }
                        return ensureBuiltInListeningSourceRoot().then(function afterListeningSourceChecked(sourceAvailable) {
                            var reason = sourceAvailable
                                ? 'available'
                                : (global.__defaultListeningLibrarySourceAvailabilityReason || 'source-root-unavailable');
                            setBuiltInListeningAvailability(sourceAvailable, reason);
                            return undefined;
                        });
                    });
            });
    }

    function loadBatch(batch) {
        if (!Array.isArray(batch) || batch.length === 0) {
            return Promise.resolve();
        }
        if (batch.length === 1) {
            return loadScript(batch[0]);
        }
        return Promise.all(batch.map(loadScript)).then(function () {
            return undefined;
        });
    }

    function loadByBatches(batches) {
        return batches.reduce(function chain(promise, batch) {
            return promise.then(function next() {
                return loadBatch(batch);
            });
        }, Promise.resolve());
    }

    function sequentialLoad(files) {
        return files.reduce(function chain(promise, file) {
            return promise.then(function next() {
                return loadScript(file);
            });
        }, Promise.resolve());
    }

    function loadGroup(groupName, files) {
        var list = Array.isArray(files) ? files.slice() : [];
        if (!list.length) {
            return Promise.resolve();
        }

        if (groupName === 'exam-data') {
            return sequentialLoad(list).then(ensureOptionalListeningExamData);
        }

        if ((groupName === 'browse-runtime' || groupName === 'browse-view') && list.indexOf('js/bundles/browse.bundle.js') === -1) {
            var mainIndex = list.indexOf('js/main.js');
            var withoutMain = mainIndex >= 0
                ? list.filter(function (file) { return file !== 'js/main.js'; })
                : list.slice();

            var batches = [
                ['js/views/legacyViewBundle.js'],
                ['js/app/examActions.js'],
                ['js/app/browseController.js'],
                ['js/presentation/message-center.js'],
                withoutMain.filter(function (file) {
                    return [
                        'js/views/legacyViewBundle.js',
                        'js/app/examActions.js',
                        'js/app/browseController.js',
                        'js/presentation/message-center.js',
                        'js/main.js'
                    ].indexOf(file) === -1;
                })
            ];
            if (mainIndex >= 0) {
                batches.push(['js/main.js']);
            }
            return loadByBatches(batches);
        }

        return sequentialLoad(list);
    }

    function mirrorAliasStatus(groupName, statusValue) {
        if (groupName === 'browse-runtime') {
            groupStatus['browse-view'] = statusValue;
        } else if (groupName === 'browse-view') {
            groupStatus['browse-runtime'] = statusValue;
        }
    }

    function refreshAppPrototypeIfNeeded(groupName) {
        try {
            if (global.ExamSystemAppMixins && typeof global.ExamSystemAppMixins.__applyToApp === 'function') {
                global.ExamSystemAppMixins.__applyToApp();
            }
        } catch (error) {
            console.warn('[LazyLoader] 重新挂载 mixins 失败:', summarizeLazyLoaderErrorForLog(error));
        }
    }

    function ensureGroup(groupName) {
        if (!groupName || !manifest[groupName]) {
            return Promise.resolve();
        }

        if (groupStatus[groupName] === 'loaded') {
            return groupName === 'exam-data'
                ? ensureOptionalListeningExamData()
                : Promise.resolve();
        }
        if (groupStatus[groupName] && groupStatus[groupName].then) {
            return groupStatus[groupName];
        }

        var required = dependencies[groupName] || [];
        groupStatus[groupName] = Promise.all(required.map(ensureGroup))
            .then(function () {
                return loadGroup(groupName, manifest[groupName]);
            })
            .then(function onGroupLoaded() {
                refreshAppPrototypeIfNeeded(groupName);
                groupStatus[groupName] = 'loaded';
                mirrorAliasStatus(groupName, 'loaded');
            }).catch(function onGroupFailed(error) {
                console.error('[LazyLoader] 组加载失败:', summarizeLazyLoaderErrorForLog(error));
                groupStatus[groupName] = null;
                mirrorAliasStatus(groupName, null);
                throw error;
            });
        mirrorAliasStatus(groupName, groupStatus[groupName]);

        return groupStatus[groupName];
    }

    function registerGroup(name, files) {
        if (!name || !Array.isArray(files)) {
            return;
        }
        manifest[name] = files.slice();
    }

    function getStatus(name) {
        if (!name) {
            return { manifest: Object.keys(manifest) };
        }
        return {
            loaded: groupStatus[name] === 'loaded',
            files: manifest[name] ? manifest[name].slice() : []
        };
    }

    registerDefaultManifest();

    global.AppLazyLoader = global.AppLazyLoader || {};
    global.AppLazyLoader.ensureGroup = ensureGroup;
    global.AppLazyLoader.registerGroup = registerGroup;
    global.AppLazyLoader.markProvided = markProvided;
    global.AppLazyLoader.getStatus = getStatus;
})(typeof window !== 'undefined' ? window : this);
