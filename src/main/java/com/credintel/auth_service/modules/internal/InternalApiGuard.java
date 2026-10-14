package com.credintel.auth_service.modules.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Service-to-service authentication for /internal endpoints: callers send the shared secret
 * in {@value #HEADER}. With no secret configured, the internal API is disabled.
 */
@Component
public class InternalApiGuard {

    public static final String HEADER = "X-Internal-Token";
    private static final Logger log = LoggerFactory.getLogger(InternalApiGuard.class);

    private final byte[] token;

    public InternalApiGuard(@Value("${credintel.internal.token:}") String token) {
        this.token = token.getBytes(StandardCharsets.UTF_8);
        if (token.isBlank()) {
            log.warn("credintel.internal.token is not set: internal API is disabled");
        }
    }

    public void check(String presented) {
        if (token.length == 0) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Internal API is not configured");
        }
        // constant-time compare so the secret can't be guessed byte by byte
        if (presented == null || !MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid internal token");
        }
    }
}
