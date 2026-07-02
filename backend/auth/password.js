(function() {
    const params = new URLSearchParams(window.location.search || '');
    const authState = params.get('state') || '';
    const state = {
        csrfToken: '',
        totpEnabled: false
    };

    const nodes = {
        status: document.getElementById('password-status'),
        form: document.getElementById('password-form'),
        currentPassword: document.getElementById('current-password'),
        totpRow: document.getElementById('password-totp-row'),
        totpToken: document.getElementById('password-totp-token'),
        newPassword: document.getElementById('new-password'),
        submit: document.getElementById('password-submit'),
        backLink: document.getElementById('password-back-link')
    };

    function parseJson(text) {
        if (!text) return null;
        try {
            return JSON.parse(text);
        } catch (_) {
            return null;
        }
    }

    function setStatus(message, kind) {
        nodes.status.textContent = message || '';
        nodes.status.classList.toggle('is-error', kind === 'error');
        nodes.status.classList.toggle('is-success', kind === 'success');
    }

    function parseState(rawState) {
        const encoded = String(rawState || '').split('.')[0] || '';
        if (!encoded) return null;
        try {
            const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
            return JSON.parse(atob(padded));
        } catch (_) {
            return null;
        }
    }

    function configureBackLink() {
        const payload = parseState(authState);
        const base = typeof payload?.targetBaseUrl === 'string' ? payload.targetBaseUrl.replace(/\/+$/g, '') : '';
        const returnTo = typeof payload?.returnTo === 'string' && payload.returnTo.startsWith('/') ? payload.returnTo : '/';
        nodes.backLink.href = base ? `${base}${returnTo}` : returnTo;
        return nodes.backLink.href;
    }

    function redirectBackToApp() {
        const href = nodes.backLink.href || '/';
        nodes.backLink.textContent = 'Return to app now';
        window.setTimeout(() => {
            window.location.assign(href);
        }, 3000);
    }

    async function request(path, options = {}) {
        const method = options.method || 'GET';
        const headers = Object.assign({}, options.headers || {});
        if (options.body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        if (method !== 'GET') {
            if (!state.csrfToken) {
                await loadCsrf();
            }
            headers['X-CSRF-Token'] = state.csrfToken;
        }
        const response = await fetch(path, {
            method,
            credentials: 'same-origin',
            headers,
            body: options.body === undefined ? undefined : JSON.stringify(options.body)
        });
        const text = await response.text();
        const payload = parseJson(text);
        if (payload && typeof payload.csrfToken === 'string' && payload.csrfToken) {
            state.csrfToken = payload.csrfToken;
        }
        if (response.status === 401) {
            throw new Error('Authentication required');
        }
        if (!response.ok) {
            throw new Error(payload?.error || `Request failed with ${response.status}`);
        }
        return payload || {};
    }

    async function loadCsrf() {
        const payload = await request('/api/auth/csrf');
        if (!payload.csrfToken) {
            throw new Error('Unable to start a secure auth session.');
        }
        state.csrfToken = payload.csrfToken;
    }

    async function loadTotpStatus() {
        const payload = await request('/api/auth/totp/status');
        state.totpEnabled = Boolean(payload?.status?.enabled);
        nodes.totpRow.hidden = !state.totpEnabled;
        nodes.totpToken.required = state.totpEnabled;
    }

    async function init() {
        if (!authState) {
            throw new Error('Valid auth action state is required.');
        }
        configureBackLink();
        await loadCsrf();
        await request('/api/auth/me');
        await loadTotpStatus();
        nodes.form.hidden = false;
        setStatus(state.totpEnabled
            ? 'Enter your current password, current TOTP or recovery code, and a new password.'
            : 'Enter your current password and a new password.');

        nodes.form.addEventListener('submit', async (event) => {
            event.preventDefault();
            nodes.submit.disabled = true;
            setStatus('Confirming recent authentication...');
            const currentPassword = nodes.currentPassword.value;
            const totpToken = nodes.totpToken.value.trim();
            try {
                if (state.totpEnabled) {
                    if (!totpToken) {
                        throw new Error('Enter your current TOTP or recovery code.');
                    }
                    await request('/api/auth/totp/verify', {
                        method: 'POST',
                        body: { token: totpToken }
                    });
                }
                await request('/api/auth/action-step-up', {
                    method: 'POST',
                    body: {
                        authState,
                        password: currentPassword
                    }
                });
                setStatus('Updating password...');
                await request('/api/auth/password-change', {
                    method: 'PATCH',
                    body: {
                        authState,
                        currentPassword,
                        newPassword: nodes.newPassword.value
                    }
                });
                nodes.form.reset();
                nodes.form.hidden = true;
                setStatus('Password updated. All sessions have been signed out. Returning to the app in 3 seconds. Sign in again with the new password.', 'success');
                redirectBackToApp();
            } catch (error) {
                setStatus(error.message || 'Password update failed.', 'error');
                nodes.submit.disabled = false;
            } finally {
                if (!nodes.form.hidden) {
                    nodes.submit.disabled = false;
                }
            }
        });
    }

    init().catch((error) => setStatus(error.message || 'Password page failed to initialize.', 'error'));
}());
