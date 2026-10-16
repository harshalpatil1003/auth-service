package com.credintel.auth_service.modules.dto;

import java.time.LocalDateTime;

/** For trusted services only: the raw token goes into the link that is emailed, nowhere else. */
public record PasswordResetLinkResponse(String token, LocalDateTime expiresAt) {
}
