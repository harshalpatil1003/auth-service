package com.credintel.auth_service.modules.services;

import com.credintel.auth_service.config.exception.AuthException;
import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;
import com.credintel.auth_service.modules.dao.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Password change (signed in, knowing the current password) and reset (a one-time link, 30 minutes).
 * Either one signs the person out everywhere and clears a sign-in lock. Reset links are created
 * through the internal API (the CRM emails them); only their hash is stored.
 */
@Service
@Transactional
public class PasswordService {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 100;

    public record ResetLink(String token, LocalDateTime expiresAt) {
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessions;
    private final LoginAttemptService loginAttempts;
    private final JdbcTemplate jdbc;
    private final int resetMinutes;

    public PasswordService(UserRepository userRepository, PasswordEncoder passwordEncoder, SessionService sessions,
                           LoginAttemptService loginAttempts, JdbcTemplate jdbc,
                           @Value("${credintel.auth.reset-link-minutes:30}") int resetMinutes) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessions = sessions;
        this.loginAttempts = loginAttempts;
        this.jdbc = jdbc;
        this.resetMinutes = resetMinutes;
    }

    /** A new reset link for an active account (earlier unused links stop working); empty otherwise. */
    public Optional<ResetLink> issueReset(String email) {
        Optional<User> user = userRepository.findByEmailIgnoreCase(email.trim());
        if (user.isEmpty() || user.get().getStatus() != UserStatus.ACTIVE) {
            return Optional.empty();
        }
        LocalDateTime now = LocalDateTime.now();
        jdbc.update("UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL", Timestamp.valueOf(now), user.get().getId());
        String token = Tokens.generate();
        LocalDateTime expiresAt = now.plusMinutes(resetMinutes);
        jdbc.update("INSERT INTO password_resets (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), user.get().getId(), Tokens.hash(token), Timestamp.valueOf(now), Timestamp.valueOf(expiresAt));
        return Optional.of(new ResetLink(token, expiresAt));
    }

    /** Sets a new password with a reset link; the link is used up. */
    public void reset(String token, String newPassword) {
        LocalDateTime now = LocalDateTime.now();
        List<UUID> users = jdbc.query("""
                UPDATE password_resets SET used_at = ?
                 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
                RETURNING user_id""",
                (rs, i) -> rs.getObject(1, UUID.class), Timestamp.valueOf(now), Tokens.hash(token), Timestamp.valueOf(now));
        User user = users.stream().findFirst().flatMap(userRepository::findById)
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(HttpStatus.BAD_REQUEST, "This reset link is invalid or has expired; ask for a new one"));
        setPassword(user, newPassword);
        // the reset proves who they are: a sign-in lock from earlier guesses ends too. Same
        // transaction and after the save, so the user row written above can't bring the lock back.
        userRepository.clearFailedLogins(user.getId());
    }

    /** Changes the password of a signed-in person who knows the current one; signs them out everywhere. */
    public User change(UUID userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Sign in again"));
        if (user.getPasswordHash() == null) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "You sign in with Google or Microsoft; use \"Forgot password?\" to add a password");
        }
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            loginAttempts.recordFailure(user.getId());
            throw new AuthException(HttpStatus.BAD_REQUEST, "The current password is wrong");
        }
        if (user.getPasswordHash() != null && passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "Choose a password different from the current one");
        }
        setPassword(user, newPassword);
        return user;
    }

    private void setPassword(User user, String newPassword) {
        check(newPassword, user.getEmail());
        LocalDateTime now = LocalDateTime.now();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(now);
        user.setUpdated_at(now);
        userRepository.saveAndFlush(user);
        sessions.revokeAll(user.getId());
        // any other outstanding link is dead too
        jdbc.update("UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL", Timestamp.valueOf(now), user.getId());
    }

    /** 8–100 characters, and not the email address. */
    public static void check(String password, String email) {
        if (password == null || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "Password must be " + MIN_LENGTH + " to " + MAX_LENGTH + " characters");
        }
        if (email != null && password.trim().equalsIgnoreCase(email.trim())) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "Don't use your email address as your password");
        }
    }
}
