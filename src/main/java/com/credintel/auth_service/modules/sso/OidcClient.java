package com.credintel.auth_service.modules.sso;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.security.Key;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Talks OpenID Connect to a provider: discovery (cached an hour), the token request (code + PKCE
 * verifier + client secret) and id_token checks (signature against the provider's published keys,
 * issuer, audience, expiry, nonce).
 */
@Component
public class OidcClient {

    public record Endpoints(String issuer, String authorization, String token, String jwks) {
    }

    private record Cached<T>(T value, long at) {
    }

    private static final long CACHE_MS = 3_600_000;

    private final RestClient http = RestClient.builder()
            .requestFactory(new org.springframework.http.client.JdkClientHttpRequestFactory(HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build()))
            .build();
    private final JsonMapper json;
    private final Map<String, Cached<Endpoints>> discovery = new ConcurrentHashMap<>();
    private final Map<String, Cached<JwkSet>> keys = new ConcurrentHashMap<>();

    public OidcClient(JsonMapper json) {
        this.json = json;
    }

    public Endpoints endpoints(SsoProviders.Provider provider) {
        Cached<Endpoints> cached = discovery.get(provider.id());
        if (cached != null && System.currentTimeMillis() - cached.at() < CACHE_MS) {
            return cached.value();
        }
        JsonNode doc = json.readTree(http.get().uri(provider.issuer() + "/.well-known/openid-configuration").retrieve().body(String.class));
        Endpoints endpoints = new Endpoints(doc.path("issuer").asText(), doc.path("authorization_endpoint").asText(),
                doc.path("token_endpoint").asText(), doc.path("jwks_uri").asText());
        discovery.put(provider.id(), new Cached<>(endpoints, System.currentTimeMillis()));
        return endpoints;
    }

    /** The id_token from exchanging an authorization code. */
    public String exchange(SsoProviders.Provider provider, String code, String verifier, String redirectUri) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("client_id", provider.clientId());
        form.add("client_secret", provider.clientSecret());
        form.add("code_verifier", verifier);
        String body = http.post().uri(endpoints(provider).token()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form).retrieve().body(String.class);
        String idToken = json.readTree(body).path("id_token").asText(null);
        if (idToken == null) {
            throw new SsoException("no_id_token");
        }
        return idToken;
    }

    /** Verified claims of an id_token; throws SsoException when anything doesn't hold. */
    public Claims verify(SsoProviders.Provider provider, String idToken, String nonce) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .keyLocator(new LocatorAdapter<Key>() {
                        @Override
                        protected Key locate(ProtectedHeader header) {
                            return key(provider, header.getKeyId());
                        }
                    })
                    .requireAudience(provider.clientId())
                    .clockSkewSeconds(60)
                    .build()
                    .parseSignedClaims(idToken)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new SsoException("bad_token");
        }
        String expected = endpoints(provider).issuer();
        if (provider.multiTenantIssuer()) {
            // Microsoft "common": the discovery issuer has a {tenantid} placeholder for the account's directory
            expected = expected.replace("{tenantid}", String.valueOf(claims.get("tid")));
        }
        if (!expected.equals(claims.getIssuer())) {
            throw new SsoException("bad_token");
        }
        if (!Objects.equals(nonce, claims.get("nonce", String.class))) {
            throw new SsoException("bad_token");
        }
        return claims;
    }

    /** A signing key by id; the key set is fetched again when a new key id shows up (key rotation). */
    private Key key(SsoProviders.Provider provider, String kid) {
        Cached<JwkSet> cached = keys.get(provider.id());
        Key found = cached == null || System.currentTimeMillis() - cached.at() > CACHE_MS ? null : find(cached.value(), kid);
        if (found == null) {
            JwkSet set = Jwks.setParser().build().parse(http.get().uri(endpoints(provider).jwks()).retrieve().body(String.class));
            keys.put(provider.id(), new Cached<>(set, System.currentTimeMillis()));
            found = find(set, kid);
        }
        if (found == null) {
            throw new SsoException("bad_token");
        }
        return found;
    }

    private static Key find(JwkSet set, String kid) {
        for (Jwk<?> jwk : set.getKeys()) {
            if (kid == null || kid.equals(jwk.getId())) {
                return jwk.toKey();
            }
        }
        return null;
    }
}
