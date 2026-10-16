package com.credintel.auth_service.config.security.config;

import com.credintel.jwt.JwtTokenGenerator;
import com.credintel.jwt.JwtTokenValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Signing (private) and verifying (public) keys. Startup fails when they aren't a pair: tokens
 * signed with one key and checked against another would be rejected by every service.
 */
@Configuration
public class JwtConfig {

    @Bean
    public JwtTokenGenerator jwtTokenGenerator(
            @Value("${credintel.jwt.private-key}")
            Resource privateKeyResource,

            @Value("${credintel.jwt.issuer}")
            String issuer,

            @Value("${jwt.access-token-expiration}")
            long accessTokenExpiration,

            @Value("${jwt.refresh-token-expiration}")
            long refreshTokenExpiration)
            throws Exception {

        PrivateKey privateKey = PemKeys.privateKey(privateKeyResource);

        return new JwtTokenGenerator(
                privateKey,
                issuer,
                accessTokenExpiration,
                refreshTokenExpiration
        );
    }

    @Bean
    public JwtTokenValidator jwtTokenValidator(
            @Value("${credintel.jwt.public-key}")
            Resource publicKeyResource,

            @Value("${credintel.jwt.private-key}")
            Resource privateKeyResource)
            throws Exception {

        PublicKey publicKey = PemKeys.publicKey(publicKeyResource);
        requireKeyPair(PemKeys.privateKey(privateKeyResource), publicKey);

        return new JwtTokenValidator(publicKey);
    }

    private static void requireKeyPair(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        byte[] probe = "credintel-key-pair-check".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(probe);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(probe);
        if (!verifier.verify(signature)) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_LOCATION and JWT_PUBLIC_KEY_LOCATION are not a key pair");
        }
    }
}
