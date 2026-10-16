package com.credintel.auth_service.modules.services;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;
import com.credintel.auth_service.modules.dao.UserRepository;
import com.credintel.auth_service.modules.dto.LoginRequest;
import com.credintel.auth_service.modules.dto.LoginResult;
import com.credintel.jwt.JwtTokenGenerator;
import com.credintel.jwt.JwtTokenValidator;
import com.credintel.jwt.TokenInfo;
import com.credintel.jwt.TokenType;
import io.jsonwebtoken.JwtException;
import com.credintel.auth_service.config.exception.AuthException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final JwtTokenValidator jwtTokenValidator;
    private final LoginAttemptService loginAttempts;
    private final SessionService sessions;
    private final long accessTokenSeconds;
    /** Compared against when the email is unknown, so both cases take the same (bcrypt) time. */
    private final String dummyHash;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenGenerator jwtTokenGenerator,
            JwtTokenValidator jwtTokenValidator,
            LoginAttemptService loginAttempts,
            SessionService sessions,
            @Value("${jwt.access-token-expiration}") long accessTokenExpirationMs) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenGenerator = jwtTokenGenerator;
        this.jwtTokenValidator = jwtTokenValidator;
        this.loginAttempts = loginAttempts;
        this.sessions = sessions;
        this.accessTokenSeconds = accessTokenExpirationMs / 1000;
        this.dummyHash = passwordEncoder.encode("timing-equaliser");
    }

    /** Checks the password and starts a session: a short-lived access token plus the session's refresh token. */
    @Transactional
    public LoginResult login(LoginRequest request, String userAgent) throws Exception {
        User user = validateLoginRequest(request);
        return startSession(user, userAgent);
    }

    /** A new session for an already authenticated user (sign-in, or right after a password change). */
    @Transactional
    public LoginResult startSession(User user, String userAgent) throws Exception {
        String accessToken = jwtTokenGenerator.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = sessions.create(user.getId(), userAgent);
        return new LoginResult(user.getId(), user.getEmail(), accessToken, refreshToken, accessTokenSeconds);
    }

    private User validateLoginRequest(LoginRequest request) {

        String email = request.getEmail()
                .trim()
                .toLowerCase();

        Optional<User> found = userRepository.findByEmailIgnoreCase(email);
        if (found.isEmpty()) {
            passwordEncoder.matches(request.getPassword(), dummyHash);
            throw AuthException.invalidCredentials();
        }
        User user = found.get();

        // checked before the password, so guesses during a lock don't count and can't succeed
        LocalDateTime lockedUntil = user.getLockedUntil();
        if (lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now())) {
            long minutes = Math.max(1, Duration.between(LocalDateTime.now(), lockedUntil).toMinutes() + 1);
            throw new AuthException(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many failed sign-in attempts. Try again in " + minutes + " minute" + (minutes == 1 ? "" : "s") + ".");
        }

        // accounts that only sign in through a provider have no password: same (bcrypt) time, same answer
        String hash = user.getPasswordHash() != null ? user.getPasswordHash() : dummyHash;
        if (!passwordEncoder.matches(request.getPassword(), hash) || user.getPasswordHash() == null) {

            loginAttempts.recordFailure(user.getId());
            throw AuthException.invalidCredentials();
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthException(HttpStatus.FORBIDDEN, "User account is not active");
        }

        if (user.getFailedLoginAttempts() > 0 || lockedUntil != null) {
            loginAttempts.recordSuccess(user.getId());
        }
        return user;
    }

    /**
     * A new access token for a live session (which is extended). Refresh tokens from before
     * sessions existed (JWTs) are unknown here, so those people simply sign in again.
     */
    @Transactional
    public String refreshAccessToken(String refreshToken) throws Exception {
        UUID userId = sessions.use(refreshToken)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Your session has ended; sign in again"));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Your session has ended; sign in again"));
        if (user.getStatus() != UserStatus.ACTIVE) {
            sessions.revokeAll(userId);
            throw new AuthException(HttpStatus.FORBIDDEN, "User account is not active");
        }
        return jwtTokenGenerator.generateAccessToken(user.getId(), user.getEmail());
    }

    /**
     * The signed-in user behind an access token (Authorization: Bearer …), for the few auth-service
     * endpoints that need one (change password, sign out everywhere).
     */
    public User requireUser(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Sign in first");
        }
        TokenInfo info;
        try {
            info = jwtTokenValidator.getTokenInfo(authorization.substring("Bearer ".length()).trim());
        } catch (JwtException | IllegalArgumentException e) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Sign in again");
        }
        if (info.getTokenType() != TokenType.ACCESS) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Sign in again");
        }
        return userRepository.findById(info.getUserId())
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Sign in again"));
    }
}
