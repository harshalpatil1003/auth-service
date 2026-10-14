package com.credintel.auth_service.modules.services;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;
import com.credintel.auth_service.modules.dao.UserRepository;
import com.credintel.auth_service.modules.dto.LoginRequest;
import com.credintel.auth_service.modules.dto.LoginResult;
import com.credintel.jwt.JwtTokenGenerator;
import com.credintel.jwt.JwtTokenValidator;
import com.credintel.jwt.TokenInfo;
import com.credintel.jwt.TokenType;
import io.jsonwebtoken.JwtException;
import org.apache.hc.client5.http.auth.InvalidCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final JwtTokenValidator jwtTokenValidator;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenGenerator jwtTokenGenerator,
            JwtTokenValidator jwtTokenValidator) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenGenerator = jwtTokenGenerator;
        this.jwtTokenValidator = jwtTokenValidator;
    }

    public LoginResult login(LoginRequest request) throws Exception {
        User user = validateLoginRequest(request);
        String accessToken =
                jwtTokenGenerator.generateAccessToken(
                        user.getId(),
                        user.getEmail()
                );

        String refreshToken =
                jwtTokenGenerator.generateRefreshToken(
                        user.getId(),
                        user.getEmail()
                );



        return new LoginResult(
                user.getId(),
                user.getEmail(),
                accessToken,
                refreshToken,
                123

        );

    }

    private User validateLoginRequest(LoginRequest request) throws Exception {

        String email = request.getEmail()
                .trim()
                .toLowerCase();

        User user = userRepository
                .findByEmailIgnoreCase(email)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "Invalid email or password"
                        ));

        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPasswordHash())) {

            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new Exception(
                    "User account is not active"
            );
            /*throw new UserInactiveException(
                    "User account is not active"
            );*/
        }

        return user;
    }

    public String refreshAccessToken(String refreshToken) throws Exception {

        TokenInfo tokenInfo;

        try {
            tokenInfo =
                    jwtTokenValidator.getTokenInfo(refreshToken);

        } catch (JwtException | IllegalArgumentException ex) {
            throw new Exception(
                    "Invalid refresh token"
            );
        }

        if (tokenInfo.getTokenType() != TokenType.REFRESH) {
            throw new Exception(
                    "Token is not a refresh token"
            );
        }

        User user = userRepository
                .findById(tokenInfo.getUserId())
                .orElseThrow(() ->
                        new Exception(
                                "Invalid refresh token"
                        ));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new Exception(
                    "User account is not active"
            );
        }

        return jwtTokenGenerator.generateAccessToken(
                user.getId(),
                user.getEmail()
        );
    }
}
