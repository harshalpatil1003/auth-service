package com.credintel.auth_service.modules.services;

import com.credintel.auth_service.modules.dao.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Failed-login bookkeeping. Each call commits in its own transaction: the login that triggers it
 * ends with an exception, which would otherwise roll the count back.
 */
@Service
public class LoginAttemptService {

    private final UserRepository userRepository;
    private final int maxFailedLogins;
    private final int lockoutMinutes;

    public LoginAttemptService(
            UserRepository userRepository,
            @Value("${credintel.auth.max-failed-logins:5}") int maxFailedLogins,
            @Value("${credintel.auth.lockout-minutes:15}") int lockoutMinutes) {

        this.userRepository = userRepository;
        this.maxFailedLogins = maxFailedLogins;
        this.lockoutMinutes = lockoutMinutes;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(UUID userId) {
        userRepository.recordFailedLogin(userId, maxFailedLogins, LocalDateTime.now().plusMinutes(lockoutMinutes));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(UUID userId) {
        userRepository.clearFailedLogins(userId);
    }
}
