(function() {
    const params = new URLSearchParams(window.location.search || '');
    const authState = params.get('state') || '';
    const state = {
        csrfToken: ''
    };

    const nodes = {
        status: document.getElementById('totp-status'),
        summary: document.getElementById('totp-summary'),
        setupPanel: document.getElementById('totp-setup-panel'),
        setupQr: document.getElementById('totp-qr'),
        setupSecret: document.getElementById('totp-secret'),
        setupUri: document.getElementById('totp-otpauth-link'),
        setupForm: document.getElementById('totp-setup-form'),
        setupToken: document.getElementById('totp-setup-token'),
        setupSubmit: document.getElementById('totp-setup-submit'),
        recoveryForm: document.getElementById('totp-recovery-form'),
        recoveryToken: document.getElementById('totp-recovery-token'),
        recoverySubmit: document.getElementById('totp-recovery-submit'),
        recoveryCodes: document.getElementById('totp-recovery-codes'),
        startSetup: document.getElementById('totp-start-setup'),
        backLink: document.getElementById('totp-back-link')
    };

    function parseJson(text) {
        if (!text) return null;
        try {
            return JSON.parse(text);
        } catch (_) {
            return null;
        }
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

    function setStatus(message, kind) {
        nodes.status.textContent = message || '';
        nodes.status.classList.toggle('is-error', kind === 'error');
        nodes.status.classList.toggle('is-success', kind === 'success');
    }

    function setVisible(node, visible) {
        node.hidden = !visible;
    }

    function normalizeQrDataUrl(value) {
        const text = String(value || '').replace(/\s+/g, '').trim();
        return /^data:image\/(?:png|gif|jpeg|webp);base64,[A-Za-z0-9+/=]+$/i.test(text) ? text : '';
    }

    function configureBackLink() {
        const payload = parseState(authState);
        const base = typeof payload?.targetBaseUrl === 'string' ? payload.targetBaseUrl.replace(/\/+$/g, '') : '';
        const returnTo = typeof payload?.returnTo === 'string' && payload.returnTo.startsWith('/') ? payload.returnTo : '/';
        nodes.backLink.href = base ? `${base}${returnTo}` : returnTo;
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

    function renderRecoveryCodes(codes) {
        nodes.recoveryCodes.textContent = '';
        (Array.isArray(codes) ? codes : []).forEach((code) => {
            const item = document.createElement('li');
            item.textContent = String(code || '');
            nodes.recoveryCodes.appendChild(item);
        });
        setVisible(nodes.recoveryCodes, true);
    }

    async function renderStatus() {
        const payload = await request('/api/auth/totp/status');
        const status = payload.status || {};
        setVisible(nodes.summary, true);
        nodes.summary.textContent = status.enabled
            ? `TOTP is enabled. Recovery codes remaining: ${Number(status.recoveryCodesRemaining || 0)}.`
            : 'TOTP is not enabled for this account.';
        setVisible(nodes.startSetup, !status.enabled);
        setVisible(nodes.recoveryForm, Boolean(status.enabled));
        setVisible(nodes.setupPanel, false);
        setVisible(nodes.recoveryCodes, false);
        setStatus(status.enabled
            ? 'Use your current TOTP or recovery code to generate a fresh recovery-code set.'
            : 'Enable TOTP to add a second authentication factor.');
        return status;
    }

    async function startSetup() {
        nodes.startSetup.disabled = true;
        setStatus('Preparing TOTP setup...');
        try {
            const payload = await request('/api/auth/totp/setup', { method: 'POST' });
            const qrSrc = normalizeQrDataUrl(payload.qrCodeDataUrl || payload.qrCode || payload.qr);
            if (qrSrc) {
                nodes.setupQr.src = qrSrc;
                nodes.setupQr.hidden = false;
            } else {
                nodes.setupQr.removeAttribute('src');
                nodes.setupQr.hidden = true;
            }
            nodes.setupSecret.textContent = payload.secret || '';
            if (typeof payload.otpauthUrl === 'string' && payload.otpauthUrl.startsWith('otpauth://')) {
                nodes.setupUri.href = payload.otpauthUrl;
                nodes.setupUri.hidden = false;
            } else {
                nodes.setupUri.removeAttribute('href');
                nodes.setupUri.hidden = true;
            }
            nodes.setupToken.value = '';
            setVisible(nodes.setupPanel, true);
            setVisible(nodes.startSetup, false);
            setStatus(qrSrc
                ? 'Scan the QR code, then enter the current code.'
                : 'QR image is unavailable. Use the text secret or setup URI instead.', qrSrc ? undefined : 'error');
        } catch (error) {
            setStatus(error.message || 'TOTP setup could not be started.', 'error');
            nodes.startSetup.disabled = false;
        }
    }

    async function submitSetup(event) {
        event.preventDefault();
        nodes.setupSubmit.disabled = true;
        setStatus('Enabling TOTP...');
        try {
            const payload = await request('/api/auth/totp/verify-setup', {
                method: 'POST',
                body: { token: nodes.setupToken.value.trim() }
            });
            nodes.setupForm.reset();
            renderRecoveryCodes(payload.recoveryCodes || []);
            setStatus('TOTP enabled. Save these recovery codes now.', 'success');
            await renderStatus();
            setVisible(nodes.recoveryCodes, true);
        } catch (error) {
            setStatus(error.message || 'TOTP setup failed.', 'error');
        } finally {
            nodes.setupSubmit.disabled = false;
        }
    }

    async function submitRecovery(event) {
        event.preventDefault();
        nodes.recoverySubmit.disabled = true;
        setStatus('Generating recovery codes...');
        try {
            const payload = await request('/api/auth/totp/recovery-codes', {
                method: 'POST',
                body: { token: nodes.recoveryToken.value.trim() }
            });
            nodes.recoveryForm.reset();
            renderRecoveryCodes(payload.recoveryCodes || []);
            setStatus('New recovery codes generated. Save them now.', 'success');
            await renderStatus();
            setVisible(nodes.recoveryCodes, true);
        } catch (error) {
            setStatus(error.message || 'Could not generate recovery codes.', 'error');
        } finally {
            nodes.recoverySubmit.disabled = false;
        }
    }

    async function init() {
        if (!authState) {
            throw new Error('Valid auth action state is required.');
        }
        configureBackLink();
        await loadCsrf();
        await request('/api/auth/me');
        const status = await renderStatus();
        nodes.startSetup.addEventListener('click', startSetup);
        nodes.setupQr.addEventListener('error', () => {
            nodes.setupQr.hidden = true;
            setStatus('QR image could not be displayed. Use the text secret or setup URI instead.', 'error');
        });
        nodes.setupForm.addEventListener('submit', submitSetup);
        nodes.recoveryForm.addEventListener('submit', submitRecovery);
        if (!status.enabled) {
            await startSetup();
        }
    }

    init().catch((error) => setStatus(error.message || 'TOTP page failed to initialize.', 'error'));
}());
