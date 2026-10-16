package com.credintel.auth_service.modules.dao;

import com.credintel.auth_service.modules.bean.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmailIgnoreCase(String email);

    boolean existsByEmailIgnoreCase(String email);

    /** Counts a failed login; at {@code max} failures the account locks until {@code lockUntil}. */
    @Modifying
    @Query(value = """
            UPDATE users
               SET failed_login_attempts = CASE WHEN failed_login_attempts + 1 >= :max THEN 0 ELSE failed_login_attempts + 1 END,
                   locked_until          = CASE WHEN failed_login_attempts + 1 >= :max THEN :lockUntil ELSE locked_until END
             WHERE id = :id
            """, nativeQuery = true)
    void recordFailedLogin(UUID id, int max, LocalDateTime lockUntil);

    @Modifying
    @Query(value = "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id", nativeQuery = true)
    void clearFailedLogins(UUID id);
}
