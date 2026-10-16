-- Sign-in sessions and password resets (CRM backend decision log #58).
-- A session's refresh token is a random value; only its SHA-256 is stored. Signing out revokes
-- one session; a password change or reset revokes them all. Sessions end after idle_days without
-- use (each refresh extends that) and never outlive absolute_expires_at.
CREATE TABLE refresh_sessions (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
       token_hash VARCHAR(64) NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       last_used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       expires_at TIMESTAMP NOT NULL,
       absolute_expires_at TIMESTAMP NOT NULL,
       revoked_at TIMESTAMP,
       user_agent VARCHAR(300),

       CONSTRAINT uk_refresh_sessions_token UNIQUE (token_hash)
);

CREATE INDEX idx_refresh_sessions_user ON refresh_sessions (user_id) WHERE revoked_at IS NULL;

-- One-time password reset links (30 minutes); only the SHA-256 of the token is stored
CREATE TABLE password_resets (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
       token_hash VARCHAR(64) NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       expires_at TIMESTAMP NOT NULL,
       used_at TIMESTAMP,

       CONSTRAINT uk_password_resets_token UNIQUE (token_hash)
);

CREATE INDEX idx_password_resets_user ON password_resets (user_id) WHERE used_at IS NULL;

ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP;
