(function() {
    const MAX_ADMIN_STATUS_CHARS = 240;
    const MAX_ADMIN_RESPONSE_JSON_LENGTH = 1024 * 1024;
    const ADMIN_STATUS_AUTH_HEADER_PATTERN = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/\-=]+/gi;
    const ADMIN_STATUS_SECRET_VALUE_PATTERN = /\b((?:csrf|token|secret|password|recovery[_-]?code|totp)(?:[_-]?[A-Za-z0-9]*)?)\s*[:=]\s*([^&\s"'<>]+)/gi;
    const ADMIN_STATUS_SECRET_QUERY_PATTERN = /([?&](?:csrf|token|secret|password|recovery[_-]?code|totp)(?:[_-]?[A-Za-z0-9]*)?=)[^&\s"'<>]+/gi;
    const RECORD_LIMIT = 100;
    const ACCOUNT_REFRESH_INTERVAL_MS = 30 * 1000;

    const state = {
        csrfToken: '',
        userId: new URLSearchParams(window.location.search).get('userId') || '',
        loading: false,
        adminStepUpResolver: null,
        adminStepUpExpiresAt: 0
    };
    const ADMIN_AUTH_START = '/auth/admin/start?return_to=/admin/account';
    const ADMIN_AUTH_LOGOUT = '/auth/admin/logout?return_to=/admin/account';

    const nodes = {
        status: document.getElementById('status'),
        refreshButton: document.getElementById('refresh-button'),
        logoutButton: document.getElementById('logout-button'),
        accountTitle: document.getElementById('account-title'),
        profileAvatar: document.getElementById('profile-avatar'),
        profileUsername: document.getElementById('profile-username'),
        profileRole: document.getElementById('profile-role'),
        profileId: document.getElementById('profile-id'),
        profileCreated: document.getElementById('profile-created'),
        profileUpdated: document.getElementById('profile-updated'),
        metricRecords: document.getElementById('metric-records'),
        metricScore: document.getElementById('metric-score'),
        metricAccuracy: document.getElementById('metric-accuracy'),
        metricDuration: document.getElementById('metric-duration'),
        sessionsRefreshButton: document.getElementById('sessions-refresh-button'),
        sessionsRevokeOthersButton: document.getElementById('sessions-revoke-others-button'),
        sessionsList: document.getElementById('sessions-list'),
        recordsRange: document.getElementById('records-range'),
        recordsBody: document.getElementById('records-body'),
        adminStepUpDialog: document.getElementById('admin-step-up-dialog'),
        adminStepUpForm: document.getElementById('admin-step-up-form'),
        adminStepUpPassword: document.getElementById('admin-step-up-password'),
        adminStepUpCancel: document.getElementById('admin-step-up-cancel'),
        adminStepUpSubmit: document.getElementById('admin-step-up-submit'),
        adminStepUpError: document.getElementById('admin-step-up-error')
    };

    function truncateAdminText(value, maxLength, suffix = '') {
        const text = String(value ?? '');
        if (text.length <= maxLength) {
            return text;
        }
        const suffixText = String(suffix || '');
        const bodyLength = Math.max(0, maxLength - suffixText.length);
        let truncated = text.slice(0, bodyLength);
        if (/[\uD800-\uDBFF]$/.test(truncated)) {
            truncated = truncated.slice(0, -1);
        }
        return `${truncated}${suffixText}`;
    }

    function sanitizeStatusMessage(value, fallback = '') {
        const text = String(value ?? fallback)
            .replace(/[\u0000-\u001F\u007F]+/g, ' ')
            .replace(ADMIN_STATUS_SECRET_QUERY_PATTERN, '$1[redacted]')
            .replace(ADMIN_STATUS_SECRET_VALUE_PATTERN, '$1=[redacted]')
            .replace(ADMIN_STATUS_AUTH_HEADER_PATTERN, '$1 [redacted]')
            .replace(/\s+/g, ' ')
            .trim();
        const normalized = text || fallback;
        return truncateAdminText(normalized, MAX_ADMIN_STATUS_CHARS, '...');
    }

    function setStatus(message, kind = 'info') {
        const safeMessage = sanitizeStatusMessage(message);
        nodes.status.textContent = safeMessage;
        nodes.status.dataset.kind = kind;
        if (safeMessage) {
            window.setTimeout(() => {
                if (nodes.status.textContent === safeMessage) {
                    nodes.status.textContent = '';
                    nodes.status.removeAttribute('data-kind');
                }
            }, kind === 'error' ? 7000 : 3500);
        }
    }

    function parseAdminResponseJson(text) {
        if (typeof text !== 'string' || !text) {
            return null;
        }
        if (text.length > MAX_ADMIN_RESPONSE_JSON_LENGTH) {
            return null;
        }
        try {
            return JSON.parse(text);
        } catch (_) {
            return null;
        }
    }

    function storeCsrfTokenFromPayload(payload) {
        if (payload && typeof payload.csrfToken === 'string' && payload.csrfToken) {
            state.csrfToken = payload.csrfToken;
            return true;
        }
        return false;
    }

    function formatRequestError(response, payload) {
        if (payload && typeof payload.error === 'string' && payload.error) {
            return sanitizeStatusMessage(`${payload.error} (${response.status})`);
        }
        return sanitizeStatusMessage(`Request failed with ${response.status}`);
    }

    async function request(path, options = {}) {
        const headers = Object.assign({}, options.headers || {});
        const method = options.method || 'GET';
        const requiresCsrf = options.csrf !== false && method !== 'GET';
        if (options.body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        if (requiresCsrf) {
            if (!state.csrfToken) {
                throw new Error('CSRF token unavailable');
            }
            headers['X-CSRF-Token'] = state.csrfToken;
        }
        const response = await fetch(path, {
            method,
            headers,
            credentials: 'same-origin',
            body: options.body === undefined ? undefined : JSON.stringify(options.body)
        });
        const text = await response.text();
        const payload = parseAdminResponseJson(text);
        storeCsrfTokenFromPayload(payload);
        if (response.status === 403 && payload && payload.requiresAdminStepUp) {
            const error = new Error(payload.error || 'Admin step-up required');
            error.requiresAdminStepUp = true;
            throw error;
        }
        if ((response.status === 401 || response.status === 403) && options.authErrorMode === 'throw') {
            const error = new Error(formatRequestError(response, payload));
            error.status = response.status;
            error.payload = payload;
            throw error;
        }
        if (response.status === 401 || response.status === 403) {
            window.location.href = ADMIN_AUTH_START;
            throw new Error('Admin session expired');
        }
        if (!response.ok) {
            throw new Error(formatRequestError(response, payload));
        }
        return payload || {};
    }

    async function loadAuth() {
        const response = await fetch('/api/auth/me', {
            credentials: 'same-origin'
        });
        const text = await response.text();
        const payload = parseAdminResponseJson(text);
        storeCsrfTokenFromPayload(payload);
        if (!response.ok || !payload || !payload.user || payload.user.role !== 'admin') {
            window.location.href = ADMIN_AUTH_START;
            return false;
        }
        return true;
    }

    function formatDate(value) {
        if (!value) return '-';
        const date = new Date(value);
        if (Number.isNaN(Number(date))) return '-';
        return date.toLocaleString();
    }

    function formatNumber(value, digits = 0) {
        const number = Number(value);
        if (!Number.isFinite(number)) return '-';
        return new Intl.NumberFormat(undefined, {
            maximumFractionDigits: digits
        }).format(number);
    }

    function formatPercent(value) {
        const number = Number(value);
        if (!Number.isFinite(number)) return '-';
        return `${formatNumber(number, 1)}%`;
    }

    function calculateAccuracy(correctAnswers, totalQuestions, score = null) {
        const correct = Number(correctAnswers);
        const total = Number(totalQuestions);
        if (Number.isFinite(correct) && Number.isFinite(total) && total > 0) {
            return (correct / total) * 100;
        }
        const scoreValue = Number(score);
        return Number.isFinite(scoreValue) ? scoreValue : null;
    }

    function formatDuration(value) {
        const number = Number(value);
        if (!Number.isFinite(number) || number <= 0) return '-';
        return `${formatNumber(number, 1)} min`;
    }

    function formatSessionAudience(value) {
        const text = String(value || '').trim().toLowerCase();
        if (text === 'admin') return 'Admin session';
        if (text === 'auth') return 'Authentication session';
        return 'Business session';
    }

    function getSessionRevokeConfirm(session) {
        const audience = String(session?.audience || '').trim().toLowerCase();
        if (audience === 'auth') {
            return 'Revoke this authentication session? The user may need to sign in again before changing password, managing TOTP, or starting a new handoff.';
        }
        if (audience === 'admin') {
            return 'Revoke this admin session?';
        }
        return 'Revoke this business session?';
    }

    function closeAdminStepUp(value) {
        if (!state.adminStepUpResolver) return;
        const resolve = state.adminStepUpResolver;
        state.adminStepUpResolver = null;
        nodes.adminStepUpDialog.hidden = true;
        nodes.adminStepUpPassword.value = '';
        nodes.adminStepUpError.textContent = '';
        resolve(value);
    }

    function promptAdminStepUp() {
        if (state.adminStepUpResolver) {
            return Promise.resolve(false);
        }
        nodes.adminStepUpPassword.value = '';
        nodes.adminStepUpError.textContent = '';
        nodes.adminStepUpDialog.hidden = false;
        nodes.adminStepUpPassword.focus();
        return new Promise((resolve) => {
            state.adminStepUpResolver = resolve;
        });
    }

    async function submitAdminStepUp(event) {
        event.preventDefault();
        const password = nodes.adminStepUpPassword.value;
        nodes.adminStepUpPassword.value = '';
        nodes.adminStepUpError.textContent = '';
        nodes.adminStepUpSubmit.disabled = true;
        try {
            const payload = await request('/api/admin/action-step-up', {
                method: 'POST',
                body: { password },
                authErrorMode: 'throw'
            });
            const expiresAt = Date.parse(payload.expiresAt || '');
            state.adminStepUpExpiresAt = Number.isFinite(expiresAt) ? expiresAt : 0;
            closeAdminStepUp(true);
        } catch (error) {
            state.adminStepUpExpiresAt = 0;
            nodes.adminStepUpError.textContent = sanitizeStatusMessage(
                error.message || 'Admin confirmation failed'
            );
            nodes.adminStepUpPassword.focus();
        } finally {
            nodes.adminStepUpSubmit.disabled = false;
        }
    }

    async function ensureAdminStepUp() {
        if (state.adminStepUpExpiresAt && Date.now() < state.adminStepUpExpiresAt - 5000) {
            return;
        }
        const confirmed = await promptAdminStepUp();
        if (!confirmed) {
            throw new Error('Admin confirmation cancelled');
        }
    }

    async function withAdminStepUp(action) {
        await ensureAdminStepUp();
        try {
            return await action();
        } catch (error) {
            if (!error.requiresAdminStepUp) {
                throw error;
            }
            state.adminStepUpExpiresAt = 0;
            await ensureAdminStepUp();
            return action();
        }
    }

    function formatRecordTitle(record) {
        return record.title || record.payload?.title || record.examId || record.id || 'Untitled practice';
    }

    function renderUser(stats) {
        const user = stats.user || {};
        const username = user.username || 'Unknown user';
        const accuracy = calculateAccuracy(stats.correctAnswers, stats.totalQuestions, stats.averageScore);
        nodes.accountTitle.textContent = `${username} account`;
        nodes.profileAvatar.textContent = username.trim().charAt(0).toUpperCase() || '?';
        nodes.profileUsername.textContent = username;
        nodes.profileRole.textContent = user.role === 'admin' ? 'Admin' : 'User';
        nodes.profileId.textContent = user.id ? `ID ${user.id}` : 'ID -';
        nodes.profileCreated.textContent = `Created ${formatDate(user.createdAt)}`;
        nodes.profileUpdated.textContent = `Updated ${formatDate(user.updatedAt)}`;
        nodes.metricRecords.textContent = formatNumber(stats.recordCount);
        nodes.metricScore.textContent = stats.averageScore === null ? '-' : formatNumber(stats.averageScore, 1);
        nodes.metricAccuracy.textContent = formatPercent(accuracy);
        nodes.metricDuration.textContent = formatDuration(stats.totalStudyMinutes);
    }

    function setRecordsMessage(message) {
        nodes.recordsBody.textContent = '';
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = 6;
        cell.className = 'empty-cell';
        cell.textContent = message;
        row.append(cell);
        nodes.recordsBody.append(row);
    }

    function renderRecords(payload) {
        const records = Array.isArray(payload.records) ? payload.records : [];
        const total = Number(payload.total || records.length || 0);
        nodes.recordsRange.textContent = `${formatNumber(total)} ${total === 1 ? 'record' : 'records'}`;
        nodes.recordsBody.textContent = '';
        if (!records.length) {
            setRecordsMessage('No completed practice records yet.');
            return;
        }
        for (const record of records) {
            const row = document.createElement('tr');
            const title = document.createElement('td');
            const titleText = document.createElement('strong');
            titleText.textContent = formatRecordTitle(record);
            const recordId = document.createElement('span');
            recordId.textContent = record.id ? `Record ${record.id}` : 'Record -';
            title.append(titleText, recordId);

            const type = document.createElement('td');
            type.textContent = record.type || record.payload?.type || '-';
            const score = document.createElement('td');
            score.textContent = record.score === null || record.score === undefined ? '-' : formatNumber(record.score, 1);
            const accuracy = document.createElement('td');
            accuracy.textContent = formatPercent(calculateAccuracy(record.correctAnswers, record.totalQuestions, record.score));
            const duration = document.createElement('td');
            duration.textContent = formatDuration(record.duration);
            const updated = document.createElement('td');
            updated.textContent = formatDate(record.updatedAt || record.createdAt);
            row.append(title, type, score, accuracy, duration, updated);
            nodes.recordsBody.append(row);
        }
    }

    function setSessionsMessage(message) {
        if (!nodes.sessionsList) return;
        nodes.sessionsList.textContent = '';
        const empty = document.createElement('p');
        empty.className = 'sessions-empty';
        empty.textContent = message;
        nodes.sessionsList.append(empty);
    }

    function renderSessions(payload) {
        if (!nodes.sessionsList) return;
        const sessions = Array.isArray(payload.sessions) ? payload.sessions : [];
        nodes.sessionsList.textContent = '';
        if (!sessions.length) {
            setSessionsMessage('No active sessions found.');
            return;
        }
        for (const session of sessions) {
            const card = document.createElement('article');
            card.className = 'session-card';
            card.setAttribute('role', 'listitem');

            const body = document.createElement('div');
            body.className = 'session-card__body';
            const title = document.createElement('strong');
            title.textContent = session.deviceLabel || 'Signed-in browser';
            const meta = document.createElement('div');
            meta.className = 'session-card__meta';
            const audience = document.createElement('span');
            audience.textContent = formatSessionAudience(session.audience);
            const lastSeen = document.createElement('span');
            lastSeen.textContent = `Last seen ${formatDate(session.lastSeenAt || session.createdAt)}`;
            const expires = document.createElement('span');
            expires.textContent = `Expires ${formatDate(session.expiresAt)}`;
            meta.append(audience, lastSeen, expires);
            if (session.current) {
                const current = document.createElement('span');
                current.className = 'session-card__current';
                current.textContent = 'Current admin session';
                meta.append(current);
            }
            body.append(title, meta);

            const revoke = document.createElement('button');
            revoke.type = 'button';
            revoke.className = 'session-card__revoke';
            revoke.textContent = session.current ? 'Current session' : 'Revoke session';
            revoke.disabled = Boolean(session.current || !session.id);
            revoke.addEventListener('click', () => {
                revokeSession(session.id, session).catch((error) => setStatus(error.message, 'error'));
            });

            card.append(body, revoke);
            nodes.sessionsList.append(card);
        }
    }

    function setSessionControlsDisabled(disabled) {
        if (nodes.sessionsRefreshButton) {
            nodes.sessionsRefreshButton.disabled = disabled;
        }
        if (nodes.sessionsRevokeOthersButton) {
            nodes.sessionsRevokeOthersButton.disabled = disabled;
        }
    }

    async function revokeSession(sessionId, session = null) {
        const normalizedId = String(sessionId || '');
        if (!normalizedId) return;
        if (typeof window.confirm === 'function' && !window.confirm(getSessionRevokeConfirm(session))) {
            return;
        }
        await withAdminStepUp(() => request(`/api/admin/users/${encodeURIComponent(state.userId)}/sessions/${encodeURIComponent(normalizedId)}`, {
            method: 'DELETE'
        }));
        setStatus('Session revoked');
        await loadAccount();
    }

    async function revokeOtherSessions() {
        if (!state.userId) return;
        if (typeof window.confirm === 'function' && !window.confirm('Revoke every other active session for this user, including authentication sessions used for sign-in and security settings?')) {
            return;
        }
        await withAdminStepUp(() => request(`/api/admin/users/${encodeURIComponent(state.userId)}/sessions/revoke-others`, {
            method: 'POST',
            body: {}
        }));
        setStatus('Other sessions revoked');
        await loadAccount();
    }

    async function loadAccount() {
        if (!state.userId) {
            setRecordsMessage('Select a user from the admin user list first.');
            setSessionsMessage('Select a user from the admin user list first.');
            nodes.profileUsername.textContent = 'No user selected';
            setStatus('Missing user id', 'error');
            return;
        }
        state.loading = true;
        nodes.refreshButton.disabled = true;
        setSessionControlsDisabled(true);
        setRecordsMessage('Loading practice records...');
        setSessionsMessage('Loading active sessions...');
        try {
            const [stats, records, sessions] = await Promise.all([
                request(`/api/admin/users/${encodeURIComponent(state.userId)}/stats`, { csrf: false }),
                request(`/api/admin/users/${encodeURIComponent(state.userId)}/practice-records?limit=${RECORD_LIMIT}&offset=0`, { csrf: false }),
                request(`/api/admin/users/${encodeURIComponent(state.userId)}/sessions`, { csrf: false })
            ]);
            renderUser(stats);
            renderRecords(records);
            renderSessions(sessions);
            setStatus('Account data refreshed');
        } catch (error) {
            setStatus(error.message || 'Failed to load account data', 'error');
        } finally {
            state.loading = false;
            nodes.refreshButton.disabled = false;
            setSessionControlsDisabled(false);
        }
    }

    async function logout() {
        try {
            await request('/api/auth/logout', {
                method: 'POST'
            });
        } finally {
            window.location.href = ADMIN_AUTH_LOGOUT;
        }
    }

    async function init() {
        const authorized = await loadAuth();
        if (!authorized) return;
        nodes.refreshButton.addEventListener('click', () => {
            if (!state.loading) {
                loadAccount();
            }
        });
        if (nodes.sessionsRefreshButton) {
            nodes.sessionsRefreshButton.addEventListener('click', () => {
                if (!state.loading) {
                    loadAccount();
                }
            });
        }
        if (nodes.sessionsRevokeOthersButton) {
            nodes.sessionsRevokeOthersButton.addEventListener('click', () => {
                if (!state.loading) {
                    revokeOtherSessions().catch((error) => setStatus(error.message, 'error'));
                }
            });
        }
        window.setInterval(() => {
            if (!state.loading && document.visibilityState === 'visible') {
                loadAccount();
            }
        }, ACCOUNT_REFRESH_INTERVAL_MS);
        document.addEventListener('visibilitychange', () => {
            if (!state.loading && document.visibilityState === 'visible') {
                loadAccount();
            }
        });
        nodes.logoutButton.addEventListener('click', () => {
            logout().catch((error) => setStatus(error.message, 'error'));
        });
        nodes.adminStepUpForm.addEventListener('submit', (event) => {
            submitAdminStepUp(event).catch((error) => setStatus(error.message, 'error'));
        });
        nodes.adminStepUpCancel.addEventListener('click', () => closeAdminStepUp(false));
        nodes.adminStepUpDialog.addEventListener('click', (event) => {
            if (event.target === nodes.adminStepUpDialog) {
                closeAdminStepUp(false);
            }
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && !nodes.adminStepUpDialog.hidden) {
                closeAdminStepUp(false);
            }
        });
        await loadAccount();
    }

    init().catch((error) => setStatus(error.message || 'Admin account failed to initialize', 'error'));
})();
