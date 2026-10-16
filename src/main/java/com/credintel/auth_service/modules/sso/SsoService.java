package com.credintel.auth_service.modules.sso;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;
import com.credintel.auth_service.modules.dao.UserRepository;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Sign-in through a provider, the OpenID Connect authorization-code flow with PKCE:
 * <ol>
 *   <li>start: a state (kept as a hash, and in a cookie), nonce and PKCE verifier; off to the provider;</li>
 *   <li>callback: state checked against the cookie, code traded for an id_token, which is verified;
 *       the provider account is matched to a user (by provider id, else by verified email; a new
 *       account is created when there's none); a one-time 60-second code goes back to the app;</li>
 *   <li>exchange: the app trades that code for a normal session.</li>
 * </ol>
 * Only addresses the provider vouches for count, so nobody can claim someone else's email. Joining
 * a workspace still needs an invite: an account by itself opens nothing.
 */
@Service
@Transactional
public class SsoService {

    private static final Logger log = LoggerFactory.getLogger(SsoService.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    /** Microsoft's directory for personal accounts (outlook.com, hotmail…): emails there are verified */
    private static final String MICROSOFT_CONSUMERS = "9188040d-6c67-4c5b-b112-36a304b66dad";
    private static final Pattern SAFE_NEXT = Pattern.compile("^/(?!/)[A-Za-z0-9/_\\-.?=&%]*$");

    public record Start(String redirectUrl, String state) {
    }

    private final SsoProviders providers;
    private final OidcClient oidc;
    private final UserRepository users;
    private final JdbcTemplate jdbc;

    public SsoService(SsoProviders providers, OidcClient oidc, UserRepository users, JdbcTemplate jdbc) {
        this.providers = providers;
        this.oidc = oidc;
        this.users = users;
        this.jdbc = jdbc;
    }

    public Start start(String providerId, String next) {
        SsoProviders.Provider provider = provider(providerId);
        String state = random();
        String nonce = random();
        String verifier = random() + random();
        jdbc.update("DELETE FROM sso_states WHERE expires_at < ?", Timestamp.valueOf(LocalDateTime.now()));
        jdbc.update("INSERT INTO sso_states (state_hash, provider, nonce, code_verifier, next_path, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                sha256(state), provider.id(), nonce, verifier, safeNext(next), Timestamp.valueOf(LocalDateTime.now().plusMinutes(10)));
        String url = UriComponentsBuilder.fromUriString(oidc.endpoints(provider).authorization())
                .queryParam("response_type", "code")
                .queryParam("client_id", provider.clientId())
                .queryParam("redirect_uri", providers.callbackUrl(provider))
                .queryParam("scope", "openid email profile")
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(sha256Bytes(verifier)))
                .queryParam("code_challenge_method", "S256")
                .queryParam("prompt", "select_account")
                .encode().build().toUriString();
        return new Start(url, state);
    }

    /** @return where to send the browser: the app's completion page (with a one-time code), or sign-in with an error */
    public String callback(String providerId, String state, String cookieState, String code, String error) {
        try {
            if (error != null) {
                throw new SsoException("cancelled");
            }
            if (state == null || code == null || cookieState == null || !MessageDigest.isEqual(state.getBytes(StandardCharsets.UTF_8),
                    cookieState.getBytes(StandardCharsets.UTF_8))) {
                throw new SsoException("expired");
            }
            List<Object[]> rows = jdbc.query("DELETE FROM sso_states WHERE state_hash = ? AND expires_at > ? RETURNING provider, nonce, code_verifier, next_path",
                    (rs, i) -> new Object[] {rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)},
                    sha256(state), Timestamp.valueOf(LocalDateTime.now()));
            if (rows.isEmpty() || !rows.get(0)[0].equals(providerId)) {
                throw new SsoException("expired");
            }
            SsoProviders.Provider provider = provider(providerId);
            Claims claims = oidc.verify(provider, oidc.exchange(provider, code, (String) rows.get(0)[2], providers.callbackUrl(provider)),
                    (String) rows.get(0)[1]);
            User user = resolveUser(provider, claims);
            String handoff = random();
            jdbc.update("INSERT INTO sso_handoffs (code_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    sha256(handoff), user.getId(), Timestamp.valueOf(LocalDateTime.now().plusSeconds(60)));
            String next = (String) rows.get(0)[3];
            return providers.publicUrl() + "/sso/complete#code=" + handoff + (next == null ? "" : "&next=" + java.net.URLEncoder.encode(next, StandardCharsets.UTF_8));
        } catch (SsoException e) {
            return providers.publicUrl() + "/login?sso_error=" + e.getMessage();
        } catch (RuntimeException e) {
            log.warn("Sign-in with {} failed", providerId, e);
            return providers.publicUrl() + "/login?sso_error=provider";
        }
    }

    /** The user behind a one-time code from the callback (it works once, for 60 seconds). */
    public UUID exchange(String code) {
        List<UUID> ids = jdbc.queryForList("UPDATE sso_handoffs SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id",
                UUID.class, Timestamp.valueOf(LocalDateTime.now()), sha256(code == null ? "" : code), Timestamp.valueOf(LocalDateTime.now()));
        if (ids.isEmpty()) {
            throw new SsoException("expired");
        }
        return ids.get(0);
    }

    /** Known provider account → its user; else a verified email → that user (linked now); else a new account. */
    private User resolveUser(SsoProviders.Provider provider, Claims claims) {
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new SsoException("bad_token");
        }
        List<UUID> linked = jdbc.queryForList("SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?", UUID.class, provider.id(), subject);
        User user;
        if (!linked.isEmpty()) {
            user = users.findById(linked.get(0)).orElseThrow(() -> new SsoException("bad_token"));
        } else {
            String email = verifiedEmail(provider, claims);
            user = users.findByEmailIgnoreCase(email).orElseGet(() -> create(email));
            jdbc.update("INSERT INTO user_identities (id, user_id, provider, subject, email) VALUES (?, ?, ?, ?, ?)",
                    UUID.randomUUID(), user.getId(), provider.id(), subject, email);
            log.info("Linked a {} sign-in to an account", provider.name());
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new SsoException("inactive");
        }
        jdbc.update("UPDATE user_identities SET last_used_at = ? WHERE provider = ? AND subject = ?",
                Timestamp.valueOf(LocalDateTime.now()), provider.id(), subject);
        return user;
    }

    private static String verifiedEmail(SsoProviders.Provider provider, Claims claims) {
        String email = claims.get("email", String.class);
        if (email == null || email.isBlank()) {
            throw new SsoException("no_email");
        }
        boolean verified = switch (provider.emailCheck()) {
            case VERIFIED_CLAIM -> truthy(claims.get("email_verified"));
            // work accounts: only when Microsoft says the organisation owns the domain (optional claim
            // xms_edov); trusting the bare claim would let anyone set any address in their own directory
            case MICROSOFT -> MICROSOFT_CONSUMERS.equals(claims.get("tid")) || truthy(claims.get("xms_edov"));
        };
        if (!verified) {
            throw new SsoException("unverified_email");
        }
        return email.strip().toLowerCase(Locale.ROOT);
    }

    private User create(String email) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setPasswordHash(null); // signs in through the provider; "forgot password" can add one later
        user.setStatus(UserStatus.ACTIVE);
        LocalDateTime now = LocalDateTime.now();
        user.setCreated_at(now);
        user.setUpdated_at(now);
        return users.saveAndFlush(user);
    }

    private SsoProviders.Provider provider(String id) {
        return providers.get(id).orElseThrow(() -> new SsoException("unknown_provider"));
    }

    /** Only paths inside the app (never another site) after signing in. */
    static String safeNext(String next) {
        return next != null && next.length() <= 500 && SAFE_NEXT.matcher(next).matches() ? next : null;
    }

    private static boolean truthy(Object value) {
        return Boolean.TRUE.equals(value) || "true".equals(value) || "1".equals(String.valueOf(value));
    }

    private static String random() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] sha256Bytes(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sha256(String s) {
        return HexFormat.of().formatHex(sha256Bytes(s));
    }
}
