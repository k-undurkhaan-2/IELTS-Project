// SPDX-FileCopyrightText: 2026 Kevin
// SPDX-License-Identifier: AGPL-3.0-only

const crypto = require('node:crypto');

const AUTH_SESSION_AUDIENCES = new Set(['business', 'admin', 'auth']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeAuthSessionAudience(value) {
    const text = String(value || '').trim().toLowerCase();
    return AUTH_SESSION_AUDIENCES.has(text) ? text : '';
}

function createAuthSessionId() {
    return crypto.randomUUID();
}

function createAuthSessionHandle() {
    return crypto.randomBytes(32).toString('base64url');
}

function hashAuthSessionHandle(secret, handle) {
    return crypto.createHmac('sha256', String(secret || '')).update(String(handle || '')).digest('hex');
}

function isAuthSessionId(value) {
    return UUID_PATTERN.test(String(value || '').trim());
}

function toIsoString(value) {
    if (!value) {
        return null;
    }
    const time = value instanceof Date ? value.getTime() : new Date(value).getTime();
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
}

function summarizeAuthSessionDevice(userAgentSummary) {
    const source = String(userAgentSummary || '').toLowerCase();
    const browser = source.includes('edg/') || source.includes('edge/')
        ? 'Edge'
        : source.includes('firefox/')
            ? 'Firefox'
            : source.includes('chrome/') || source.includes('chromium/')
                ? 'Chrome'
                : source.includes('safari/')
                    ? 'Safari'
                    : 'Browser';
    const platform = source.includes('windows')
        ? 'Windows'
        : source.includes('android')
            ? 'Android'
            : source.includes('iphone') || source.includes('ipad') || source.includes('ios')
                ? 'iOS'
                : source.includes('mac os') || source.includes('macintosh')
                    ? 'macOS'
                    : source.includes('linux')
                        ? 'Linux'
                        : 'Unknown device';
    return `${browser} on ${platform}`;
}

function serializeAuthSession(record, options = {}) {
    if (!record) {
        return null;
    }
    const currentId = String(options.currentId || '');
    return {
        id: record.id,
        audience: normalizeAuthSessionAudience(record.audience) || 'business',
        current: Boolean(currentId && record.id === currentId),
        createdAt: toIsoString(record.created_at),
        lastSeenAt: toIsoString(record.last_seen_at),
        expiresAt: toIsoString(record.expires_at),
        revokedAt: toIsoString(record.revoked_at),
        totpVerified: Boolean(record.totp_verified_at),
        deviceLabel: summarizeAuthSessionDevice(record.user_agent_summary)
    };
}

class PostgresAuthSessionStore {
    constructor(db) {
        this.db = db;
    }

    async createSession(session) {
        const result = await this.db.query(
            `INSERT INTO auth_sessions (
                id, session_handle_hash, user_id, audience, expires_at,
                security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash
            )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, user_id, audience, created_at, last_seen_at, revoked_at, expires_at,
                       security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash`,
            [
                session.id,
                session.handleHash,
                session.userId,
                session.audience,
                session.expiresAt,
                Number.isInteger(session.securityEpoch) ? session.securityEpoch : 0,
                session.lastVerifierRotatedAt || null,
                session.totpVerifiedAt || null,
                session.userAgentSummary || null,
                session.ipHash || null
            ]
        );
        return result.rows[0] || null;
    }

    async getActiveSession(id, handleHash) {
        const result = await this.db.query(
            `UPDATE auth_sessions
             SET last_seen_at = now()
             WHERE id = $1
               AND session_handle_hash = $2
               AND revoked_at IS NULL
               AND expires_at > now()
             RETURNING id, user_id, audience, created_at, last_seen_at, revoked_at, expires_at,
                       security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash`,
            [id, handleHash]
        );
        return result.rows[0] || null;
    }

    async revokeSession(id) {
        if (!id) {
            return null;
        }
        const result = await this.db.query(
            `UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1
             RETURNING id, user_id, audience, created_at, last_seen_at, revoked_at, expires_at,
                       security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash`,
            [id]
        );
        return result.rows[0] || null;
    }

    async revokeSessionForUser(userId, sessionId) {
        if (!userId || !isAuthSessionId(sessionId)) {
            return null;
        }
        const result = await this.db.query(
            `UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1
               AND user_id = $2
             RETURNING id, user_id, audience, created_at, last_seen_at, revoked_at, expires_at,
                       security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash`,
            [sessionId, userId]
        );
        return result.rows[0] || null;
    }

    async revokeSessionsForUser(userId, exceptId = null) {
        if (!userId) {
            return 0;
        }
        const params = [userId];
        let exceptClause = '';
        if (exceptId) {
            params.push(exceptId);
            exceptClause = ` AND id <> $${params.length}`;
        }
        const result = await this.db.query(
            `UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE user_id = $1
               AND revoked_at IS NULL
               ${exceptClause}`,
            params
        );
        return result.rowCount || 0;
    }

    async listSessionsForUser(userId, options = {}) {
        if (!userId) {
            return [];
        }
        const limit = Math.max(1, Math.min(100, Number.parseInt(options.limit, 10) || 50));
        const includeRevoked = Boolean(options.includeRevoked);
        const includeExpired = Boolean(options.includeExpired);
        const conditions = ['user_id = $1'];
        if (!includeRevoked) {
            conditions.push('revoked_at IS NULL');
        }
        if (!includeExpired) {
            conditions.push('expires_at > now()');
        }
        const result = await this.db.query(
            `SELECT id, user_id, audience, created_at, last_seen_at, revoked_at, expires_at,
                    security_epoch, last_verifier_rotated_at, totp_verified_at, user_agent_summary, ip_hash
             FROM auth_sessions
             WHERE ${conditions.join(' AND ')}
             ORDER BY last_seen_at DESC, created_at DESC
             LIMIT $2`,
            [userId, limit]
        );
        return result.rows;
    }
}

class MemoryAuthSessionStore {
    constructor() {
        this.sessions = new Map();
    }

    async createSession(session) {
        const now = new Date().toISOString();
        const record = {
            id: session.id,
            session_handle_hash: session.handleHash,
            user_id: session.userId,
            audience: session.audience,
            created_at: now,
            last_seen_at: now,
            revoked_at: null,
            expires_at: session.expiresAt,
            security_epoch: Number.isInteger(session.securityEpoch) ? session.securityEpoch : 0,
            last_verifier_rotated_at: session.lastVerifierRotatedAt || null,
            totp_verified_at: session.totpVerifiedAt || null,
            user_agent_summary: session.userAgentSummary || null,
            ip_hash: session.ipHash || null
        };
        this.sessions.set(record.id, record);
        return { ...record };
    }

    async getActiveSession(id, handleHash) {
        const record = this.sessions.get(id);
        if (!record || record.session_handle_hash !== handleHash || record.revoked_at) {
            return null;
        }
        if (new Date(record.expires_at).getTime() <= Date.now()) {
            return null;
        }
        record.last_seen_at = new Date().toISOString();
        return { ...record };
    }

    async revokeSession(id) {
        const record = this.sessions.get(id);
        if (!record) {
            return null;
        }
        if (!record.revoked_at) {
            record.revoked_at = new Date().toISOString();
        }
        return { ...record };
    }

    async revokeSessionForUser(userId, sessionId) {
        if (!userId || !isAuthSessionId(sessionId)) {
            return null;
        }
        const record = this.sessions.get(sessionId);
        if (!record || record.user_id !== userId) {
            return null;
        }
        if (!record.revoked_at) {
            record.revoked_at = new Date().toISOString();
        }
        return { ...record };
    }

    async revokeSessionsForUser(userId, exceptId = null) {
        let count = 0;
        for (const record of this.sessions.values()) {
            if (record.user_id === userId && record.id !== exceptId && !record.revoked_at) {
                record.revoked_at = new Date().toISOString();
                count += 1;
            }
        }
        return count;
    }

    async listSessionsForUser(userId, options = {}) {
        if (!userId) {
            return [];
        }
        const limit = Math.max(1, Math.min(100, Number.parseInt(options.limit, 10) || 50));
        const includeRevoked = Boolean(options.includeRevoked);
        const includeExpired = Boolean(options.includeExpired);
        const now = Date.now();
        return Array.from(this.sessions.values())
            .filter((record) => record.user_id === userId)
            .filter((record) => includeRevoked || !record.revoked_at)
            .filter((record) => includeExpired || new Date(record.expires_at).getTime() > now)
            .sort((left, right) => {
                const leftSeen = new Date(left.last_seen_at || left.created_at).getTime();
                const rightSeen = new Date(right.last_seen_at || right.created_at).getTime();
                return rightSeen - leftSeen;
            })
            .slice(0, limit)
            .map((record) => ({ ...record }));
    }
}

module.exports = {
    AUTH_SESSION_AUDIENCES,
    MemoryAuthSessionStore,
    PostgresAuthSessionStore,
    createAuthSessionHandle,
    createAuthSessionId,
    hashAuthSessionHandle,
    isAuthSessionId,
    normalizeAuthSessionAudience,
    serializeAuthSession
};
