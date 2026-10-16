package com.credintel.auth_service.modules.sso;

/** A provider sign-in that can't go on; {@code code} is shown on the sign-in page (no details leak). */
public class SsoException extends RuntimeException {

    public SsoException(String code) {
        super(code);
    }
}
