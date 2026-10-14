package com.credintel.auth_service.modules.dto;

import com.credintel.auth_service.modules.bean.User;
import com.credintel.auth_service.modules.constants.UserStatus;

import java.util.UUID;

public class UserResponse {

    private UUID id;
    private String email;
    private UserStatus status;

    public static UserResponse from(User user) {
        UserResponse response = new UserResponse();

        response.setId(user.getId());
        response.setEmail(user.getEmail());
        response.setStatus(user.getStatus());

        return response;
    }

    // getters/setters

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }
}
