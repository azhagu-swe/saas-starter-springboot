package com.azhagu_swe.saas.controller;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.azhagu_swe.saas.dto.request.*;
import com.azhagu_swe.saas.dto.response.UsernameAvailabilityResponse;
import com.azhagu_swe.saas.exception.InvalidTokenException;
import com.azhagu_swe.saas.exception.ResourceNotFoundException;
import com.azhagu_swe.saas.dto.response.ErrorResponse;
import com.azhagu_swe.saas.dto.response.JwtResponse;
import com.azhagu_swe.saas.dto.response.MessageResponse;
import com.azhagu_swe.saas.dto.response.TokenRefreshResponse;
import com.azhagu_swe.saas.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints for user authentication and authorization")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @PostMapping("/signin")
    @Operation(summary = "User Sign-In", description = "Authenticates a user and returns JWT tokens.")
    @ApiResponse(responseCode = "200", description = "Successful authentication", content = @Content(schema = @Schema(implementation = JwtResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            return authService.authenticateUser(loginRequest);
        } catch (Exception e) {
            logger.error("Error during sign-in: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @PostMapping("/signup")
    @Operation(summary = "User Sign-Up", description = "Registers a new user.")
    @ApiResponse(responseCode = "200", description = "User registered successfully", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<?> signUp(@Valid @RequestBody SignupRequest signupRequest) {
        try {
            return authService.registerUser(signupRequest);
        } catch (Exception e) {
            logger.error("Error during sign-up: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @PostMapping("/refreshtoken")
    @Operation(summary = "Refresh Token", description = "Generates a new access token using a refresh token.")
    @ApiResponse(responseCode = "200", description = "Token refreshed successfully", content = @Content(schema = @Schema(implementation = TokenRefreshResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request", content = @Content(schema = @Schema(implementation = ErrorResponse.class))) // Corrected
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        try {
            return authService.refreshToken(request);
        } catch (InvalidTokenException e) {
            logger.warn("Invalid refresh token attempt: {}", e.getMessage()); // Log Specific
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_TOKEN", e.getMessage())); // Specific
        } catch (Exception e) {
            logger.error("Error during token refresh: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Forgot Password", description = "Initiates the password reset process.")
    @ApiResponse(responseCode = "200", description = "Password reset instructions sent", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "404", description = "User not found", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try {
            return authService.forgotPassword(request);
        } catch (ResourceNotFoundException e) {
            logger.warn("Forgot password attempt for non-existent user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("USER_NOT_FOUND", e.getMessage()));
        } catch (Exception e) {
            logger.error("Error during forgot password: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset Password", description = "Resets the user's password.")
    @ApiResponse(responseCode = "200", description = "Password reset successfully", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request / Invalid Token", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            return authService.resetPassword(request);
        } catch (InvalidTokenException e) {
            logger.warn("Invalid token during password reset: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_TOKEN", e.getMessage()));
        } catch (Exception e) {
            logger.error("Error during password reset: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }

    @GetMapping("/check-username")
    @Operation(summary = "Check Username Availability", description = "Checks if a username is available.")
    @ApiResponse(responseCode = "200", description = "Username availability check successful", content = @Content(schema = @Schema(implementation = UsernameAvailabilityResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<?> checkUsernameAvailability(@RequestParam String username) {
        try {
            boolean isAvailable = authService.isUsernameAvailable(username);
            return ResponseEntity.ok(new UsernameAvailabilityResponse(isAvailable));
        } catch (Exception e) {
            logger.error("Error during username availability check: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("SERVER_ERROR", "An unexpected error occurred."));
        }
    }
}