package com.credintel.auth_service.config.security.config;

import com.credintel.crypto.CryptoUtils;
import com.credintel.jwt.JwtTokenGenerator;
import com.credintel.jwt.JwtTokenValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.security.PrivateKey;
import java.security.PublicKey;

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

        PrivateKey privateKey = CryptoUtils.getPrivateKey(privateKeyResource.getInputStream());

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
            Resource publicKeyResource)
            throws Exception {

        PublicKey publicKey = CryptoUtils.getPublicKey( publicKeyResource.getInputStream() );

        return new JwtTokenValidator(publicKey);
    }
}
