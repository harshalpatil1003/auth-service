package com.credintel.auth_service.modules.dto;

import com.credintel.auth_service.modules.bean.User;

import java.util.UUID;

public class LoginResponse {

    private UUID userId;
    private String email;
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn;

    public static LoginResponse from(LoginResult result) {
        LoginResponse response = new LoginResponse();

        response.userId = result.getUserId();
        response.email = result.getEmail();
        response.accessToken = result.getAccessToken();
        response.refreshToken = result.getRefreshToken();
        response.tokenType = "Bearer";
        response.expiresIn = result.getExpiresIn();

        return response;
    }

    // getters/setters

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}