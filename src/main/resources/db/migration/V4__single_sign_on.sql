-- Sign in with Google / Microsoft / any OpenID Connect provider (CRM backend decision log #61).

-- An account can be used without a password (signed up through a provider); a password can
-- still be set later with "forgot password".
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Which provider accounts belong to which user (provider + its stable subject id)
CREATE TABLE user_identities (
       id UUID PRIMARY KEY,
       user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
       provider VARCHAR(30) NOT NULL,
       subject VARCHAR(255) NOT NULL,
       email VARCHAR(320),
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       last_used_at TIMESTAMP,
       CONSTRAINT uk_user_identities UNIQUE (provider, subject)
);

-- A sign-in in progress: state (also in a cookie), nonce and PKCE verifier; 10 minutes
CREATE TABLE sso_states (
       state_hash VARCHAR(64) PRIMARY KEY,
       provider VARCHAR(30) NOT NULL,
       nonce VARCHAR(100) NOT NULL,
       code_verifier VARCHAR(200) NOT NULL,
       next_path VARCHAR(500),
       expires_at TIMESTAMP NOT NULL,
       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One-time codes the browser trades for a session after a provider sign-in; 60 seconds
CREATE TABLE sso_handoffs (
       code_hash VARCHAR(64) PRIMARY KEY,
       user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
       expires_at TIMESTAMP NOT NULL,
       used_at TIMESTAMP
);
