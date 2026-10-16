package com.credintel.auth_service.modules.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDateTime;

/** Daily: drops sessions ended over 30 days ago and reset links expired over a day ago. */
@Component
@EnableScheduling
public class AuthHousekeeping {

    private static final Logger log = LoggerFactory.getLogger(AuthHousekeeping.class);

    private final SessionService sessions;
    private final JdbcTemplate jdbc;

    public AuthHousekeeping(SessionService sessions, JdbcTemplate jdbc) {
        this.sessions = sessions;
        this.jdbc = jdbc;
    }

    @Scheduled(fixedDelay = 86_400_000, initialDelay = 300_000)
    public void purge() {
        int ended = sessions.purge();
        int links = jdbc.update("DELETE FROM password_resets WHERE expires_at < ?", Timestamp.valueOf(LocalDateTime.now().minusDays(1)));
        if (ended + links > 0) {
            log.info("Removed {} ended session(s) and {} expired reset link(s)", ended, links);
        }
    }
}
