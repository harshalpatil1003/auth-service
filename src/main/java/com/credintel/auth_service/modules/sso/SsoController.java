package com.credintel.auth_service.modules.sso;

import com.credintel.auth_service.config.exception.AuthException;
import com.credintel.auth_service.modules.dao.UserRepository;
import com.credintel.auth_service.modules.dto.LoginResponse;
import com.credintel.auth_service.modules.services.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Sign in with Google / Microsoft / an OpenID Connect provider. The browser goes to /start (a
 * full page load, not an API call), the provider sends it back to /callback, and the app trades
 * the one-time code from there at /exchange.
 */
@RestController
@RequestMapping("/auth/sso")
public class SsoController {

    private static final String COOKIE = "vendly_sso_state";
    private static final String COOKIE_PATH = "/auth-service/api/v1/auth/sso";

    public record ExchangeRequest(@NotBlank String code) {
    }

    private final SsoProviders providers;
    private final SsoService sso;
    private final AuthService authService;
    private final UserRepository users;

    public SsoController(SsoProviders providers, SsoService sso, AuthService authService, UserRepository users) {
        this.providers = providers;
        this.sso = sso;
        this.authService = authService;
        this.users = users;
    }

    /** The buttons to show on the sign-in page. */
    @GetMapping("/providers")
    public List<Map<String, String>> list() {
        return providers.all().stream().map(p -> Map.of("id", p.id(), "name", p.name())).toList();
    }

    @GetMapping("/{provider}/start")
    public ResponseEntity<Void> start(@PathVariable String provider, @RequestParam(required = false) String next) {
        try {
            SsoService.Start start = sso.start(provider, next);
            // the state also goes in a cookie only this browser has: a callback carrying someone
            // else's state (login CSRF) doesn't match it
            ResponseCookie cookie = ResponseCookie.from(COOKIE, start.state()).httpOnly(true).secure(providers.secureCookies())
                    .sameSite("Lax").path(COOKIE_PATH).maxAge(Duration.ofMinutes(10)).build();
            return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .location(URI.create(start.redirectUrl())).build();
        } catch (SsoException e) {
            return redirect(providers.publicUrl() + "/login?sso_error=" + e.getMessage());
        } catch (RuntimeException e) {
            return redirect(providers.publicUrl() + "/login?sso_error=provider");
        }
    }

    @GetMapping("/{provider}/callback")
    public ResponseEntity<Void> callback(@PathVariable String provider,
                                         @RequestParam(required = false) String state,
                                         @RequestParam(required = false) String code,
                                         @RequestParam(required = false) String error,
                                         @CookieValue(value = COOKIE, required = false) String cookieState) {
        ResponseCookie clear = ResponseCookie.from(COOKIE, "").httpOnly(true).secure(providers.secureCookies())
                .sameSite("Lax").path(COOKIE_PATH).maxAge(0).build();
        return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.SET_COOKIE, clear.toString())
                .location(URI.create(sso.callback(provider, state, cookieState, code, error))).build();
    }

    /** One-time code from the callback → a normal session (same answer as /auth/login). */
    @PostMapping("/exchange")
    public LoginResponse exchange(@Valid @RequestBody ExchangeRequest request,
                                  @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent) throws Exception {
        try {
            var user = users.findById(sso.exchange(request.code()))
                    .orElseThrow(() -> new AuthException(HttpStatus.UNAUTHORIZED, "Sign-in link expired; try again"));
            return LoginResponse.from(authService.startSession(user, userAgent));
        } catch (SsoException e) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, "Sign-in link expired; try again");
        }
    }

    private static ResponseEntity<Void> redirect(String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }
}
