package com.credintel.auth_service.config.ops;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Refuses to start under the prod profile with settings that are only safe in development: the
 * dev internal token, keys loaded from the classpath or the development ./config/certs folder,
 * self-registration switched on, or very long-lived access tokens.
 */
@Component
@Profile("prod")
public class ProductionConfigCheck {

    static final String DEV_INTERNAL_TOKEN = "dev-only-internal-token-change-me";
    static final int MIN_TOKEN_LENGTH = 32;
    static final long MAX_ACCESS_TOKEN_MS = 60 * 60 * 1000L;

    private final Environment env;

    public ProductionConfigCheck(Environment env) {
        this.env = env;
    }

    @PostConstruct
    void check() {
        List<String> problems = new ArrayList<>();

        String token = env.getProperty("credintel.internal.token", "");
        if (token.equals(DEV_INTERNAL_TOKEN) || token.length() < MIN_TOKEN_LENGTH) {
            problems.add("INTERNAL_API_TOKEN must be a random secret of at least " + MIN_TOKEN_LENGTH
                    + " characters (e.g. openssl rand -hex 32), shared with the CRM backend");
        }
        for (String key : List.of("credintel.jwt.private-key", "credintel.jwt.public-key")) {
            String location = env.getProperty(key, "");
            if (location.startsWith("classpath:") || location.contains("config/certs")) {
                problems.add(key + " must point at the production key (file:/path/...), not a development key");
            }
        }
        if (env.getProperty("credintel.auth.registration-enabled", Boolean.class, false)) {
            problems.add("credintel.auth.registration-enabled must stay false: open sign-up lets anyone claim any email");
        }
        if (env.getProperty("jwt.access-token-expiration", Long.class, 0L) > MAX_ACCESS_TOKEN_MS) {
            problems.add("JWT_ACCESS_TOKEN_TTL_MS must be at most one hour; the frontend refreshes tokens on its own");
        }

        if (env.getProperty("eureka.client.enabled", Boolean.class, true)
                && env.getProperty("eureka.client.service-url.defaultZone", "").isBlank()) {
            problems.add("EUREKA_URL is required while Eureka is on (or set EUREKA_CLIENT_ENABLED=false)");
        }

        // sign-in providers: a client id needs its secret, and callbacks must come back over https
        boolean anySso = false;
        for (String id : java.util.List.of("google", "microsoft", "oidc")) {
            String clientId = env.getProperty("credintel.sso." + id + ".client-id", "");
            if (!clientId.isBlank()) {
                anySso = true;
                if (env.getProperty("credintel.sso." + id + ".client-secret", "").isBlank()) {
                    problems.add("credintel.sso." + id + ".client-secret is required when its client id is set");
                }
            }
        }
        String publicUrl = env.getProperty("credintel.sso.public-url", "");
        if (anySso && !publicUrl.startsWith("https://") && !publicUrl.matches("http://(localhost|127\\.0\\.0\\.1)(:\\d+)?/?")) {
            problems.add("PUBLIC_URL must be https:// for sign-in with Google/Microsoft (providers send people back there)");
        }

        if (!problems.isEmpty()) {
            throw new IllegalStateException("Production configuration is not safe to start:\n  - "
                    + String.join("\n  - ", problems));
        }
    }
}
