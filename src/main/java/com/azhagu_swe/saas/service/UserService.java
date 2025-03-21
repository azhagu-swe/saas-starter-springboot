package com.azhagu_swe.saas.service;

import com.azhagu_swe.saas.constants.AppConstants;
import com.azhagu_swe.saas.exception.ResourceNotFoundException;
import com.azhagu_swe.saas.dto.request.CreateUserRequest;
import com.azhagu_swe.saas.dto.request.UpdateUserRequest;
import com.azhagu_swe.saas.dto.response.UserResponse;
import com.azhagu_swe.saas.mapper.UserMapper;
import com.azhagu_swe.saas.model.entity.Role;
import com.azhagu_swe.saas.model.entity.User;
import com.azhagu_swe.saas.model.repository.RoleRepository;
import com.azhagu_swe.saas.model.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

        private static final Logger logger = LoggerFactory.getLogger(UserService.class);

        private final UserRepository userRepository;
        private final RoleRepository roleRepository;
        private final PasswordEncoder passwordEncoder;

        @Transactional
        public UserResponse createUser(@Valid CreateUserRequest request) {
                if (userRepository.existsByUsername(request.getUsername())) {
                        logger.warn("Registration attempt with taken username: {}", request.getUsername());
                        throw new IllegalArgumentException("Username is already taken!");
                }
                if (userRepository.existsByEmail(request.getEmail())) {
                        logger.warn("Registration attempt with taken email: {}", request.getEmail());
                        throw new IllegalArgumentException("Email is already in use!");
                }
                User user = UserMapper.toUser(request);
                user.setPassword(passwordEncoder.encode(request.getPassword()));

                // Assign roles: if provided, use them; otherwise, use the default role.
                Set<String> roleNames = request.getRoleNames();
                Set<Role> roles = new HashSet<>();
                if (roleNames == null || roleNames.isEmpty()) {
                        Role defaultRole = roleRepository.findByName(AppConstants.DEFAULT_ROLE)
                                        .orElseThrow(() -> new ResourceNotFoundException("Role", "name",
                                                        AppConstants.DEFAULT_ROLE));
                        roles.add(defaultRole);
                } else {
                        roleNames.forEach(roleName -> {
                                Role role = roleRepository.findByName(roleName)
                                                .orElseThrow(() -> new ResourceNotFoundException("Role", "name",
                                                                roleName));
                                roles.add(role);
                        });
                }
                user.setRoles(roles);
                User savedUser = userRepository.save(user);
                logger.info("User created with id: {}", savedUser.getId());
                return UserMapper.toUserResponse(savedUser);
        }

        public List<UserResponse> getAllUsers() {
                List<User> users = userRepository.findAll();
                return users.stream()
                                .map(UserMapper::toUserResponse)
                                .collect(Collectors.toList());
        }

        public UserResponse getUserById(Long id) {
                User user = userRepository.findById(id)
                                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
                return UserMapper.toUserResponse(user);
        }

        @Transactional
        public UserResponse updateUser(Long id, @Valid UpdateUserRequest request) {
                User user = userRepository.findById(id)
                                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
                UserMapper.updateUserFromRequest(user, request);
                if (request.getPassword() != null && !request.getPassword().isBlank()) {
                        user.setPassword(passwordEncoder.encode(request.getPassword()));
                }
                if (request.getRoleNames() != null && !request.getRoleNames().isEmpty()) {
                        Set<Role> roles = request.getRoleNames().stream()
                                        .map(roleName -> roleRepository.findByName(roleName)
                                                        .orElseThrow(() -> new ResourceNotFoundException("Role", "name",
                                                                        roleName)))
                                        .collect(Collectors.toSet());
                        user.setRoles(roles);
                }
                User updatedUser = userRepository.save(user);
                logger.info("User updated with id: {}", updatedUser.getId());
                return UserMapper.toUserResponse(updatedUser);
        }

        @Transactional
        public void deleteUser(Long id) {
                User user = userRepository.findById(id)
                                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
                userRepository.delete(user);
                logger.info("User deleted with id: {}", id);
        }
}
