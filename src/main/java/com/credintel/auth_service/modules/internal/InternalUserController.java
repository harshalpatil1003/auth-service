package com.credintel.auth_service.modules.internal;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.dao.UserRepository;
import com.credintel.auth_service.modules.dto.CreateUserRequest;
import com.credintel.auth_service.modules.dto.UserResponse;
import com.credintel.auth_service.modules.services.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/**
 * Account lookup/creation for trusted services (e.g. the CRM backend accepting an invite).
 * Not for browsers: every call needs the shared internal token.
 */
@RestController
@RequestMapping("/internal/users")
public class InternalUserController {

    private final InternalApiGuard guard;
    private final UserRepository userRepository;
    private final UserService userService;

    public InternalUserController(
            InternalApiGuard guard,
            UserRepository userRepository,
            UserService userService) {

        this.guard = guard;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @GetMapping
    public UserResponse findByEmail(
            @RequestHeader(value = InternalApiGuard.HEADER, required = false) String token,
            @RequestParam String email) {

        guard.check(token);
        User user = userRepository.findByEmailIgnoreCase(email.trim())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return UserResponse.from(user);
    }

    @PostMapping
    public ResponseEntity<UserResponse> createUser(
            @RequestHeader(value = InternalApiGuard.HEADER, required = false) String token,
            @Valid @RequestBody CreateUserRequest request) throws Exception {

        guard.check(token);
        if (userRepository.existsByEmailIgnoreCase(request.getEmail().trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User already exists");
        }
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserResponse.from(userService.createUser(request)));
    }
}
