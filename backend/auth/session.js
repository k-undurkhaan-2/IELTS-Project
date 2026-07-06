(function() {
    const params = new URLSearchParams(window.location.search || '');
    const authState = params.get('state') || '';
    const state = {
        csrfToken: ''
    };
    const actionPayload = parseState(authState);
    const isDataManageAction = actionPayload?.intent === 'data-manage';

    const nodes = {
        status: document.getElementById('session-status'),
        form: document.getElementById('session-form'),
        password: document.getElementById('session-password'),
        submit: document.getElementById('session-submit'),
        backLink: document.getElementById('session-back-link')
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

    function getReturnUrl(payload) {
        const base = typeof payload?.targetBaseUrl === 'string' ? payload.targetBaseUrl.replace(/\/+$/g, '') : '';
        const returnTo = typeof payload?.returnTo === 'string' && payload.returnTo.startsWith('/') ? payload.returnTo : '/';
        return base ? `${base}${returnTo}` : returnTo;
    }

    function configureBackLink() {
        nodes.backLink.href = getReturnUrl(actionPayload);
        return nodes.backLink.href;
    }

    function getCallbackUrl(actionProof) {
        const base = typeof actionPayload?.targetBaseUrl === 'string' ? actionPayload.targetBaseUrl.replace(/\/+$/g, '') : '';
        const callbackPath = typeof actionPayload?.actionCallbackPath === 'string' && actionPayload.actionCallbackPath.startsWith('/auth/business/')
            ? actionPayload.actionCallbackPath
            : '/auth/business/session/callback';
        const target = base ? `${base}${callbackPath}` : callbackPath;
        const query = new URLSearchParams({
            state: authState,
            proof: actionProof
        });
        return `${target}?${query.toString()}`;
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

    async function init() {
        if (!authState) {
            throw new Error('Valid auth action state is required.');
        }
        configureBackLink();
        await loadCsrf();
        await request('/api/auth/me');
        nodes.form.hidden = false;
        setStatus(isDataManageAction
            ? 'Confirm your password before managing practice data.'
            : 'Confirm your password before managing active sessions.');

        nodes.form.addEventListener('submit', async (event) => {
            event.preventDefault();
            nodes.submit.disabled = true;
            setStatus('Confirming recent authentication...');
            try {
                const payload = await request('/api/auth/action-step-up', {
                    method: 'POST',
                    body: {
                        authState,
                        password: nodes.password.value
                    }
                });
                if (!payload.actionProof) {
                    throw new Error(isDataManageAction
                        ? 'Practice data confirmation failed.'
                        : 'Session management confirmation failed.');
                }
                nodes.form.reset();
                nodes.form.hidden = true;
                setStatus('Confirmed. Returning to the app...', 'success');
                window.location.assign(getCallbackUrl(payload.actionProof));
            } catch (error) {
                setStatus(error.message || 'Session confirmation failed.', 'error');
                nodes.submit.disabled = false;
            }
        });
    }

    init().catch((error) => setStatus(error.message || 'Session page failed to initialize.', 'error'));
}());
