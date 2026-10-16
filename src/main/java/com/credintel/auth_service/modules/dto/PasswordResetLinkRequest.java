package com.credintel.auth_service.modules.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetLinkRequest(@NotBlank @Email String email) {
}
