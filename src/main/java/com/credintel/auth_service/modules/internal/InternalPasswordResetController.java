package com.credintel.auth_service.modules.internal;

import com.credintel.auth_service.modules.dto.PasswordResetLinkRequest;
import com.credintel.auth_service.modules.dto.PasswordResetLinkResponse;
import com.credintel.auth_service.modules.services.PasswordService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Reset links for trusted services (the CRM emails them). Not for browsers. */
@RestController
@RequestMapping("/internal/password-resets")
public class InternalPasswordResetController {

    private final InternalApiGuard guard;
    private final PasswordService passwords;

    public InternalPasswordResetController(InternalApiGuard guard, PasswordService passwords) {
        this.guard = guard;
        this.passwords = passwords;
    }

    /**
     * A one-time password reset link for an active account (404 otherwise). The caller emails it
     * to the account's own address; it must never be shown to anyone else.
     */
    @PostMapping
    public ResponseEntity<PasswordResetLinkResponse> issue(
            @RequestHeader(value = InternalApiGuard.HEADER, required = false) String token,
            @Valid @RequestBody PasswordResetLinkRequest request) {

        guard.check(token);
        PasswordService.ResetLink link = passwords.issueReset(request.email())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No active account with this email"));
        return ResponseEntity.status(HttpStatus.CREATED).body(new PasswordResetLinkResponse(link.token(), link.expiresAt()));
    }
}
