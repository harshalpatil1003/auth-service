package com.credintel.auth_service.modules.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** @param token the one-time token from the reset link */
public record ResetPasswordRequest(@NotBlank @Size(max = 200) String token, @NotBlank @Size(min = 8, max = 100) String newPassword) {
}
