package com.credintel.auth_service.modules.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Sign-in sessions. The refresh token is a random value handed to the browser once; only its hash
 * is kept, so a database leak doesn't hand out sessions. A session lasts {@code idleDays} after its
 * last use (each refresh extends it) and at most {@code maxDays} in total; signing out revokes it.
 * The token is not rotated on refresh: two tabs refreshing at once must not sign each other out.
 */
@Service
@Transactional
public class SessionService {

    private final JdbcTemplate jdbc;
    private final int idleDays;
    private final int maxDays;

    public SessionService(JdbcTemplate jdbc,
                          @Value("${credintel.auth.session-idle-days:7}") int idleDays,
                          @Value("${credintel.auth.session-max-days:30}") int maxDays) {
        this.jdbc = jdbc;
        this.idleDays = idleDays;
        this.maxDays = maxDays;
    }

    /** A new session; returns its refresh token (shown once). */
    public String create(UUID userId, String userAgent) {
        String token = Tokens.generate();
        LocalDateTime now = LocalDateTime.now();
        jdbc.update("""
                INSERT INTO refresh_sessions (id, user_id, token_hash, created_at, last_used_at, expires_at, absolute_expires_at, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                UUID.randomUUID(), userId, Tokens.hash(token), ts(now), ts(now),
                ts(now.plusDays(Math.min(idleDays, maxDays))), ts(now.plusDays(maxDays)), trim(userAgent));
        return token;
    }

    /** The user of a live session, which is extended; empty when unknown, revoked or expired. */
    public Optional<UUID> use(String token) {
        LocalDateTime now = LocalDateTime.now();
        List<UUID> users = jdbc.query("""
                UPDATE refresh_sessions
                   SET last_used_at = ?, expires_at = LEAST(?, absolute_expires_at)
                 WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
                RETURNING user_id""",
                (rs, i) -> rs.getObject(1, UUID.class),
                ts(now), ts(now.plusDays(idleDays)), Tokens.hash(token), ts(now));
        return users.stream().findFirst();
    }

    /** Signs one session out; unknown tokens are ignored (signing out never fails). */
    public void revoke(String token) {
        jdbc.update("UPDATE refresh_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                ts(LocalDateTime.now()), Tokens.hash(token));
    }

    /** Signs the user out everywhere; returns how many sessions ended. */
    public int revokeAll(UUID userId) {
        return jdbc.update("UPDATE refresh_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                ts(LocalDateTime.now()), userId);
    }

    /** Ended sessions are kept 30 days (when someone signed in), then removed. */
    public int purge() {
        return jdbc.update("DELETE FROM refresh_sessions WHERE COALESCE(revoked_at, expires_at) < ?",
                ts(LocalDateTime.now().minusDays(30)));
    }

    private static Timestamp ts(LocalDateTime t) {
        return Timestamp.valueOf(t);
    }

    private static String trim(String s) {
        return s == null ? null : s.length() > 300 ? s.substring(0, 300) : s;
    }
}
