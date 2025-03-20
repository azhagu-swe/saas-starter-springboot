package com.azhagu_swe.saas.service;

import com.azhagu_swe.saas.constants.AppConstants;
import com.azhagu_swe.saas.dto.request.*;
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

import org.hibernate.service.spi.ServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
    public JwtResponse authenticateUser(@Valid LoginRequest loginRequest) {
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
            return new JwtResponse(accessToken, refreshToken.getToken(), userDetails.getId(),
                    userDetails.getUsername(), userDetails.getEmail(), roles);
        } catch (BadCredentialsException e) {
            logger.warn("Failed login attempt for user: {}", loginRequest.getUsername());
            throw new BadCredentialsException("Invalid username or password");
        } catch (Exception e) {
            logger.error("Unexpected error during authentication: ", e);
            throw new ServiceException("Authentication error", e);
        }
    }

    @Transactional
    public MessageResponse registerUser(@Valid SignupRequest signUpRequest) {
        // Check if username already exists
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            logger.warn("Registration attempt with taken username: {}", signUpRequest.getUsername());
            throw new IllegalArgumentException("Username is already taken!");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            logger.warn("Registration attempt with taken email: {}", signUpRequest.getEmail());
            throw new IllegalArgumentException("Email is already in use!");
        }

        // Create and set up the user entity
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));

        // Set roles: if none provided, assign the default role
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            Role defaultRole = roleRepository.findByName(AppConstants.DEFAULT_ROLE)
                    .orElseThrow(() -> new ResourceNotFoundException("Role", "name", AppConstants.DEFAULT_ROLE));
            roles.add(defaultRole);
        } else {
            strRoles.forEach(roleName -> {
                Role role;
                if ("admin".equalsIgnoreCase(roleName)) {
                    role = roleRepository.findByName("Admin")
                            .orElseThrow(() -> new ResourceNotFoundException("Role", "name", roleName));
                } else {
                    role = roleRepository.findByName(AppConstants.DEFAULT_ROLE)
                            .orElseThrow(() -> new ResourceNotFoundException("Role", "name", roleName));
                }
                roles.add(role);
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getUsername());
        return new MessageResponse("User registered successfully!");
    }

    @Transactional
    public TokenRefreshResponse refreshToken(@Valid TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        // Retrieve the refresh token or throw an exception if not found
        RefreshToken refreshToken = refreshTokenService.getByToken(requestRefreshToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token is not found. Please sign in again."));

        // Verify the token's expiration, throwing an exception if it has expired
        refreshToken = refreshTokenService.verifyExpiration(refreshToken);

        // Retrieve the user associated with the token or throw if not found
        Long userId = refreshToken.getUserId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        // Build the user details and generate a new access token
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String newAccessToken = jwtUtils.generateJwtTokenForUser(userDetails);

        // Return the token refresh response
        return new TokenRefreshResponse(newAccessToken, requestRefreshToken);
    }

    @Transactional
    public MessageResponse forgotPassword(@Valid ForgotPasswordRequest request) {
        final String email = request.getEmail();

        // Retrieve user by email or throw ResourceNotFoundException (logged within the
        // exception)
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Forgot password request for non-existent email: {}", email);
                    return new ResourceNotFoundException("User", "email", email);
                });

        // Create a password reset token for the user
        PasswordResetToken resetToken = passwordResetService.createPasswordResetTokenForUser(user);

        // Attempt to send the password reset email; wrap MailException in a
        // ServiceException
        try {
            emailService.sendPasswordResetEmail(email, resetToken.getToken());
        } catch (MailException e) {
            logger.error("Error sending password reset email to {}: {}", email, e.getMessage(), e);
            throw new ServiceException("Failed to send password reset email. Please try again later.", e);
        }

        logger.info("Password reset instructions successfully sent to {}", email);
        return new MessageResponse("Password reset instructions sent to your email");
    }

    @Transactional
    public MessageResponse resetPassword(@Valid ResetPasswordRequest request) {
        try {
            PasswordResetToken token = passwordResetService.validatePasswordResetToken(request.getToken());
            User user = token.getUser();
            user.setPassword(encoder.encode(request.getNewPassword()));
            userRepository.save(user);
            passwordResetService.deleteToken(token);
            logger.info("Password reset successfully for user: {}", user.getUsername());
            return new MessageResponse("Password reset successfully");
        } catch (InvalidTokenException e) {
            logger.warn("Invalid or expired password reset token: {}", request.getToken());
            throw e; // Let the global exception handler process this
        } catch (ResourceNotFoundException e) {
            logger.warn("User or token not found during password reset: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during password reset", e);
            throw new RuntimeException("Password reset failed due to an unexpected error");
        }
    }

    public boolean isUsernameAvailable(String username) {
        try {
            return !userRepository.existsByUsername(username);
        } catch (Exception e) {
            logger.error("Error checking username availability for '{}': ", username, e);
            throw new ServiceException("Error checking username availability", e);
        }
    }
}