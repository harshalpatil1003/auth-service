package com.credintel.auth_service.modules.controller;

import com.credintel.auth_service.modules.dto.ChangePasswordRequest;
import com.credintel.auth_service.modules.dto.ResetPasswordRequest;
import com.credintel.auth_service.modules.services.PasswordService;
import com.credintel.auth_service.modules.services.SessionService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestHeader;
import java.util.Map;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.dto.*;
import com.credintel.auth_service.modules.services.AuthService;
import com.credintel.auth_service.modules.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    private final UserService userService;
    private final SessionService sessions;
    private final PasswordService passwords;
    private final boolean registrationEnabled;

    public AuthController(
            AuthService authService,
            UserService userService,
            SessionService sessions,
            PasswordService passwords,
            @Value("${credintel.auth.registration-enabled:false}") boolean registrationEnabled) {

        this.authService = authService;
        this.userService = userService;
        this.sessions = sessions;
        this.passwords = passwords;
        this.registrationEnabled = registrationEnabled;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody CreateUserRequest request) {

        // Open sign-up lets anyone claim any email, so accounts are created through invites
        // (internal API) unless self-registration is explicitly enabled.
        if (!registrationEnabled) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Self-registration is disabled");
        }

        User user = userService.createUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserResponse.from(user));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent) throws Exception {

        LoginResult loginResult = authService.login(request, userAgent);

        return ResponseEntity.ok(
                LoginResponse.from(loginResult)
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request) throws Exception {

        String accessToken = authService.refreshAccessToken( request.getRefreshToken());

        LoginResponse response = new LoginResponse();
        response.setAccessToken(accessToken);
        response.setTokenType("Bearer");

        return ResponseEntity.ok(response);
    }

    /** Ends this browser's session: its refresh token stops working. Never fails. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        sessions.revoke(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    /** Ends every session of the signed-in person (all browsers and devices). */
    @PostMapping("/logout-all")
    public Map<String, Integer> logoutAll(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return Map.of("sessionsEnded", sessions.revokeAll(authService.requireUser(authorization).getId()));
    }

    /**
     * Changes the password (the current one is required). Every session ends, including this one;
     * the answer is a fresh session so this browser stays signed in.
     */
    @PostMapping("/password/change")
    public LoginResponse changePassword(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                        @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
                                        @Valid @RequestBody ChangePasswordRequest request) throws Exception {
        User user = passwords.change(authService.requireUser(authorization).getId(), request.currentPassword(), request.newPassword());
        return LoginResponse.from(authService.startSession(user, userAgent));
    }

    /** Sets a new password from a reset link. Every session ends; sign in with the new password. */
    @PostMapping("/password/reset")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwords.reset(request.token(), request.newPassword());
        return ResponseEntity.noContent().build();
    }
}
