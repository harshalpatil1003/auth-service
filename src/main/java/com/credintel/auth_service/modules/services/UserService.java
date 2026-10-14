package com.credintel.auth_service.modules.services;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;
import com.credintel.auth_service.modules.dao.UserRepository;
import com.credintel.auth_service.modules.dto.CreateUserRequest;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User createUser(CreateUserRequest request) throws Exception {

        String email = request.getEmail().trim().toLowerCase();

        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new Exception(
                    "User already exists with email: " + email
            );
            /*throw new DuplicateEmailException(
                    "User already exists with email: " + email
            );*/
        }

        User user = new User();

        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setPasswordHash(
                passwordEncoder.encode(request.getPassword())
        );
        user.setStatus(UserStatus.ACTIVE);
        LocalDateTime now = LocalDateTime.now();
        user.setCreated_at(now);
        user.setUpdated_at(now);

        return userRepository.save(user);
    }
}
