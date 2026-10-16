# auth-service

Accounts, passwords and JWTs for the Vendly CRM. Users sign in here; every other service checks
the RS256 access tokens it issues with the public key.

## API (`/auth-service/api/v1`, through the gateway)

| Endpoint | Notes |
|---|---|
| `POST /auth/login` | `{email, password}` → access token (30 min, JWT), refresh token (an opaque session token: 7 days after last use, 30 days at most), `expiresIn` in seconds. After 5 wrong passwords the account locks for 15 minutes (429). |
| `POST /auth/refresh` | `{refreshToken}` → new access token; extends the session and re-checks that the account is active. The refresh token itself doesn't change. |
| `POST /auth/logout` | `{refreshToken}` → 204; that session ends. |
| `POST /auth/logout-all` | Bearer access token → `{sessionsEnded}`; every session of the account ends. |
| `POST /auth/password/change` | Bearer access token + `{currentPassword, newPassword}` → a fresh session (same shape as login); every other session ends. |
| `POST /auth/password/reset` | `{token, newPassword}` from a reset link → 204; every session ends and a sign-in lock is cleared. Links last 30 minutes and work once. |
| `GET /auth/sso/providers` | The sign-in providers set up (Google / Microsoft / OIDC) → `[{id, name}]`. |
| `GET /auth/sso/{provider}/start?next=/path` | Browser goes here (full page load); off to the provider with state, nonce and PKCE. |
| `GET /auth/sso/{provider}/callback` | The provider sends the browser back here; then on to `<PUBLIC_URL>/sso/complete#code=…`, or `/login?sso_error=…`. Register this exact URL with the provider. |
| `POST /auth/sso/exchange` | `{code}` (one-time, 60 s) → a session, same as login. |
| `POST /internal/password-resets` | Internal token + `{email}` → `{token, expiresAt}` for an active account (404 otherwise). The CRM emails the link; never show it to anyone else. |
| `POST /auth/register` | Off (`credintel.auth.registration-enabled=false`): accounts come from invites. |
| `GET/POST /internal/users` | Service-to-service only (`X-Internal-Token`); the gateway blocks `/internal`. Used by the CRM backend when an invite is accepted. |

## Running locally

1. Put the development key pair in `config/certs/` (`jwt_private.pem`, `jwt_public.pem`) and the
   DB login in `config/application.properties` (`spring.datasource.username/password`). The
   `config/` folder is git-ignored.
   - New pair: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/certs/jwt_private.pem`
     then `openssl pkey -in config/certs/jwt_private.pem -pubout -out config/certs/jwt_public.pem`.
     The CRM backend's `jwt_public.pem` must match.
2. Run with the working directory set to this folder. Flyway creates or updates the schema on
   startup.

## Production

Run with `SPRING_PROFILES_ACTIVE=prod` (the Docker image does). Required:
- `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`, `EUREKA_URL`
- `JWT_PRIVATE_KEY_LOCATION`, `JWT_PUBLIC_KEY_LOCATION` (`file:/keys/...`): a production pair,
  never the development one
- `INTERNAL_API_TOKEN` (≥ 32 characters, the same value as the CRM backend)

Optional: `JWT_ACCESS_TOKEN_TTL_MS` (at most 1 h), `JWT_REFRESH_TOKEN_TTL_MS`, `DB_POOL_SIZE`,
`PORT`, `MANAGEMENT_PORT`.

Startup fails when:
- the keys aren't a pair
- a development key, the dev internal token or open sign-up is configured
- access tokens live longer than an hour

Health: `:8183/actuator/health/liveness` and `/readiness`.

**Rotating the signing key:** issue a new pair, deploy the public key to every verifying service
first (the CRM backend's `JWT_PUBLIC_KEY_LOCATION`), then switch auth-service. Users sign in
again once their refresh tokens expire.

## Sign in with a provider

Set `PUBLIC_URL` plus `GOOGLE_CLIENT_ID/SECRET`, `MICROSOFT_CLIENT_ID/SECRET` (`MICROSOFT_TENANT`,
default `common`) or `OIDC_ISSUER/NAME/CLIENT_ID/CLIENT_SECRET`. Only provider-verified emails are
accepted (Microsoft work accounts need the `xms_edov` optional claim). A provider account is linked
to the user with that email, or creates an account without a password. Joining a workspace still
needs an invite. `smoke/mock_oidc.py` is a tiny provider for tests.

## Checks

`smoke/run.sh` boots the service against a throwaway database and key pair and runs
`smoke/auth.py`. It covers:
- the internal API guard
- login and token types
- refresh
- lockout
- inactive accounts
- timing-safe login
