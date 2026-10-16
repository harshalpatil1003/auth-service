package com.credintel.auth_service.config.security.config;

import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Reads the RSA key pair from PEM files. Not credintel-crypto's CryptoUtils: its getPrivateKey
 * prints the whole private key to stdout, which would put the signing key in the logs.
 */
final class PemKeys {

    private PemKeys() {
    }

    /** PKCS#8 ("BEGIN PRIVATE KEY"), as written by {@code openssl genpkey}. */
    static PrivateKey privateKey(Resource resource) throws IOException, GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der(resource)));
    }

    /** X.509 SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"). */
    static PublicKey publicKey(Resource resource) throws IOException, GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der(resource)));
    }

    private static byte[] der(Resource resource) throws IOException {
        try (InputStream in = resource.getInputStream()) {
            String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return Base64.getDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
        }
    }
}
