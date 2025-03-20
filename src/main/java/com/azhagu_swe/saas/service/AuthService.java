package com.azhagu_swe.saas.service;

import com.azhagu_swe.saas.constants.AppConstants;
import com.azhagu_swe.saas.constants.ErrorCodeConstants;
import com.azhagu_swe.saas.dto.request.*;
import com.azhagu_swe.saas.dto.response.ErrorResponse;
import com.azhagu_swe.saas.dto.response.JwtResponse;
import com.azhagu_swe.saas.dto.response.MessageResponse;
import com.azhagu_swe.saas.dto.response.TokenRefreshResponse;
import com.azhagu_swe.saas.exception.InvalidTokenException;
import com.azhagu_swe.saas.exception.ResourceNotFoundException;
import com.azhagu_swe.saas.model.entity.PasswordResetToken;
import com.azhagu_swe.saas.model.entity.RefreshToken;
import com.azhagu_swe.saas.model.entity.Role;
import com.azhagu_swe.saas.model.entity.User;
import com.azhagu_swe.saas.model.repository.RoleRepository;
import com.azhagu_swe.saas.model.repository.UserRepository;
import com.azhagu_swe.saas.security.service.RefreshTokenService;
import com.azhagu_swe.saas.security.service.UserDetailsImpl;
import com.azhagu_swe.saas.util.JwtUtils;
import jakarta.validation.Valid;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private PasswordResetService passwordResetService; // You had this. Good.
    @Autowired
    private EmailService emailService; // And this.

    @Transactional
    public ResponseEntity<?> authenticateUser(@Valid LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String accessToken = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

            return ResponseEntity.ok(new JwtResponse(
                    accessToken,
                    refreshToken.getToken(),
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
        } catch (BadCredentialsException e) {
            logger.warn("Failed login attempt for user: {}", loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("INVALID_CREDENTIALS", "Invalid username or password."));
        } catch (AuthenticationException e) {
            logger.error("Authentication failed: ", e); // Log more general authentication problems
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("AUTHENTICATION_FAILED", "Authentication failed."));
        } catch (Exception e) {
            logger.error("Unexpected error during authentication: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @Transactional // Important for database operations
    public ResponseEntity<?> registerUser(@Valid SignupRequest signUpRequest) {
        try {
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse(ErrorCodeConstants.USERNAME_TAKEN, "Username is already taken!"));
            }

            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse(ErrorCodeConstants.EMAIL_IN_USE, "Email is already in use!"));
            }

            User user = new User();
            user.setUsername(signUpRequest.getUsername());
            user.setEmail(signUpRequest.getEmail());
            user.setPassword(encoder.encode(signUpRequest.getPassword()));

            Set<String> strRoles = signUpRequest.getRole();
            Set<Role> roles = new HashSet<>();

            if (strRoles == null || strRoles.isEmpty()) {
                Role userRole = roleRepository.findByName(AppConstants.DEFAULT_ROLE)
                        .orElseThrow(() -> new ResourceNotFoundException("Role", "name", AppConstants.DEFAULT_ROLE));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    if ("admin".equalsIgnoreCase(role)) {
                        Role adminRole = roleRepository.findByName("Admin") // Make sure "Admin" matches your role names
                                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", role));
                        roles.add(adminRole);
                    } else {
                        Role userRole = roleRepository.findByName(AppConstants.DEFAULT_ROLE)
                                .orElseThrow(() -> new ResourceNotFoundException("Role", "name", role));
                        roles.add(userRole);
                    }
                });
            }

            user.setRoles(roles);
            userRepository.save(user);
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

        } catch (ResourceNotFoundException e) {
            logger.error("Role not found during registration: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("ROLE_NOT_FOUND", "Required role not found.")); // Consistent
        } catch (Exception e) {
            logger.error("Error during user registration: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR",
                            "An unexpected error occurred."));
        }
    }

    @Transactional
    public ResponseEntity<?> refreshToken(@Valid TokenRefreshRequest request) {
        try {
            String requestRefreshToken = request.getRefreshToken();
            return refreshTokenService.getByToken(requestRefreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUserId)
                    .map(userId -> {
                        User user = userRepository.findById(userId)
                                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId)); // Consistent
                        UserDetailsImpl userDetails = UserDetailsImpl.build(user); // Build UserDetails
                        String token = jwtUtils.generateJwtTokenForUser(userDetails); // Use the correct method
                        return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                    })
                    .orElseThrow(() -> new InvalidTokenException("Refresh token is not found. Please sign in again."));

        } catch (InvalidTokenException e) {
            logger.warn("Invalid refresh token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_TOKEN", e.getMessage()));
        } catch (ResourceNotFoundException e) {
            logger.error("User not found for refresh token: ", e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("USER_NOT_FOUND", "User associated with refresh token not found."));
        } catch (Exception e) {
            logger.error("Error during refresh token processing: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @Transactional
    public ResponseEntity<?> forgotPassword(@Valid ForgotPasswordRequest request) {
        try {
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new ResourceNotFoundException("User", "email", request.getEmail()));

            PasswordResetToken resetToken = passwordResetService.createPasswordResetTokenForUser(user);
            emailService.sendPasswordResetEmail(user.getEmail(), resetToken.getToken()); // Send the email.
            return ResponseEntity.ok(new MessageResponse("Password reset instructions sent to your email"));

        } catch (ResourceNotFoundException e) {
            logger.warn("Forgot password request for non-existent email: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("USER_NOT_FOUND", e.getMessage()));
        } catch (Exception e) {
            logger.error("Error during forgot password process: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @Transactional
    public ResponseEntity<?> resetPassword(@Valid ResetPasswordRequest request) {
        try {
            PasswordResetToken token = passwordResetService.validatePasswordResetToken(request.getToken());
            User user = token.getUser();
            user.setPassword(encoder.encode(request.getNewPassword()));
            userRepository.save(user);
            passwordResetService.deleteToken(token); // Invalidate the token after use.
            return ResponseEntity.ok(new MessageResponse("Password reset successfully"));

        } catch (InvalidTokenException e) {
            logger.warn("Invalid or expired password reset token used: {}", request.getToken());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_TOKEN", e.getMessage()));
        } catch (Exception e) {
            logger.error("Error during password reset: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    public boolean isUsernameAvailable(String username) {
        try {
            return !userRepository.existsByUsername(username);
        } catch (Exception e) {
            logger.error("Error checking username availability: ", e);
            // Consider whether to return true or false in case of an error.
            // Returning false (not available) is generally safer.
            return false;
        }
    }
}