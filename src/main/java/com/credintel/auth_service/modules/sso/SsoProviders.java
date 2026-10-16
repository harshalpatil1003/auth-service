package com.credintel.auth_service.modules.sso;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The sign-in providers this installation offers: Google, Microsoft and one generic OpenID Connect
 * provider (Okta, Keycloak, Auth0…), each switched on by giving it a client id and secret.
 * Callbacks are {@code <public url>/auth-service/api/v1/auth/sso/<id>/callback}: register exactly
 * that address with the provider.
 */
@Component
public class SsoProviders {

    /** How a provider vouches for an email address. */
    public enum EmailCheck {
        /** {@code email_verified} is true (Google, most providers) */
        VERIFIED_CLAIM,
        /**
         * Microsoft: personal accounts' emails are verified; for work accounts only when Microsoft
         * says the organisation owns the domain ({@code xms_edov}, an optional claim to switch on)
         */
        MICROSOFT
    }

    public record Provider(String id, String name, String issuer, String clientId, String clientSecret, EmailCheck emailCheck,
                           boolean multiTenantIssuer) {
    }

    private final Map<String, Provider> providers;
    private final String publicUrl;

    public SsoProviders(Environment env) {
        this.publicUrl = env.getProperty("credintel.sso.public-url", "http://localhost:3000").replaceAll("/+$", "");
        Map<String, Provider> found = new LinkedHashMap<>();
        add(found, env, "google", "Google", "https://accounts.google.com", EmailCheck.VERIFIED_CLAIM, false);
        String msTenant = env.getProperty("credintel.sso.microsoft.tenant", "common");
        add(found, env, "microsoft", "Microsoft", "https://login.microsoftonline.com/" + msTenant + "/v2.0", EmailCheck.MICROSOFT,
                List.of("common", "organizations", "consumers").contains(msTenant));
        String issuer = env.getProperty("credintel.sso.oidc.issuer", "");
        if (!issuer.isBlank()) {
            add(found, env, "oidc", env.getProperty("credintel.sso.oidc.name", "Single sign-on"), issuer.replaceAll("/+$", ""),
                    EmailCheck.VERIFIED_CLAIM, false);
        }
        this.providers = Collections.unmodifiableMap(found);
    }

    private static void add(Map<String, Provider> into, Environment env, String id, String name, String issuer, EmailCheck check, boolean multiTenant) {
        String clientId = env.getProperty("credintel.sso." + id + ".client-id", "");
        String secret = env.getProperty("credintel.sso." + id + ".client-secret", "");
        if (!clientId.isBlank()) {
            into.put(id, new Provider(id, name, issuer, clientId, secret, check, multiTenant));
        }
    }

    public List<Provider> all() {
        return new ArrayList<>(providers.values());
    }

    public Optional<Provider> get(String id) {
        return Optional.ofNullable(providers.get(id));
    }

    public String publicUrl() {
        return publicUrl;
    }

    public String callbackUrl(Provider provider) {
        return publicUrl + "/auth-service/api/v1/auth/sso/" + provider.id() + "/callback";
    }

    public boolean secureCookies() {
        return URI.create(publicUrl).getScheme().equals("https");
    }
}
