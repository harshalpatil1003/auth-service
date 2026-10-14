package com.credintel.auth_service.modules.controller;

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
    private final boolean registrationEnabled;

    public AuthController(
            AuthService authService,
            UserService userService,
            @Value("${credintel.auth.registration-enabled:false}") boolean registrationEnabled) {

        this.authService = authService;
        this.userService = userService;
        this.registrationEnabled = registrationEnabled;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @Valid @RequestBody CreateUserRequest request) throws Exception {

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
            @Valid @RequestBody LoginRequest request) throws Exception {

        LoginResult loginResult = authService.login(request);

        // JWT generation will be added in Step 2

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
}
