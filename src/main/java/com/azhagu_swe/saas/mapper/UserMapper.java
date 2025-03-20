package com.azhagu_swe.saas.mapper;

import java.util.Set;
import java.util.stream.Collectors;

import com.azhagu_swe.saas.dto.request.CreateUserRequest;
import com.azhagu_swe.saas.dto.request.UpdateUserRequest;
import com.azhagu_swe.saas.dto.response.UserResponse;
import com.azhagu_swe.saas.model.entity.Role;
import com.azhagu_swe.saas.model.entity.User;

public class UserMapper {

    public static UserResponse toUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        // Map roles to their names
        Set<String> roleNames = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        response.setRoles(roleNames);
        return response;
    }

    public static User toUser(CreateUserRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());
        // Role assignment will be handled in the service
        return user;
    }

    public static void updateUserFromRequest(User user, UpdateUserRequest request) {
        if (request.getUsername() != null && !request.getUsername().isBlank()) {
            user.setUsername(request.getUsername());
        }
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            user.setEmail(request.getEmail());
        }
        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(request.getPassword());
        }
        // Role updates will be handled in the service layer
    }
}
