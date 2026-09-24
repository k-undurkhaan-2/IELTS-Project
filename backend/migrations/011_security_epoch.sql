-- SPDX-FileCopyrightText: 2026 Kevin
-- SPDX-License-Identifier: AGPL-3.0-only

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS security_epoch integer NOT NULL DEFAULT 0;

ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS security_epoch integer NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS auth_sessions_user_epoch_active_idx
    ON auth_sessions (user_id, security_epoch)
    WHERE revoked_at IS NULL;
