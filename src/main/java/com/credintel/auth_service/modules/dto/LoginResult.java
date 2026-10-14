package com.credintel.auth_service.modules.dto;

import java.util.UUID;

public class LoginResult {
    private final UUID userId;
    private final String email;
    private final String accessToken;
    private final String refreshToken;
    private final long expiresIn;

    public LoginResult(
            UUID userId,
            String email,
            String accessToken,
            String refreshToken,
            long expiresIn) {

        this.userId = userId;
        this.email = email;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getEmail() {
        return email;
    }

    public UUID getUserId() {
        return userId;
    }

    public long getExpiresIn() {
        return expiresIn;
    }
}
