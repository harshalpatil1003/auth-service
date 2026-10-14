package com.credintel.auth_service.config.exception;

import org.springframework.http.HttpStatus;

/** An authentication failure with the HTTP status the client should see. */
public class AuthException extends RuntimeException {

    private final HttpStatus status;

    public AuthException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public static AuthException invalidCredentials() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    public HttpStatus getStatus() {
        return status;
    }
}
