package com.azhagu_swe.saas.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.azhagu_swe.saas.dto.request.*;
import com.azhagu_swe.saas.dto.response.UsernameAvailabilityResponse;
import com.azhagu_swe.saas.dto.response.APIResponse;
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

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Endpoints for user authentication and authorization")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/signin")
    @Operation(summary = "User Sign-In", description = "Authenticates a user and returns JWT tokens.")
    @ApiResponse(responseCode = "200", description = "Successful authentication", content = @Content(schema = @Schema(implementation = JwtResponse.class)))
    public ResponseEntity<APIResponse<JwtResponse>> signIn(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse response = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(APIResponse.success("Successful authentication", response));
    }

    @PostMapping("/signup")
    @Operation(summary = "User Sign-Up", description = "Registers a new user.")
    @ApiResponse(responseCode = "201", description = "User registered successfully", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request", content = @Content(schema = @Schema(implementation = APIResponse.class)))
    public ResponseEntity<APIResponse<MessageResponse>> signUp(@Valid @RequestBody SignupRequest signupRequest) {
        // The service method will throw exceptions for error scenarios,
        // which will be handled by the global exception handler.
        MessageResponse response = authService.registerUser(signupRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(APIResponse.success("User registered successfully", response));
    }

    @PostMapping("/refreshtoken")
    @Operation(summary = "Refresh Token", description = "Generates a new access token using a refresh token.")
    @ApiResponse(responseCode = "200", description = "Token refreshed successfully", content = @Content(schema = @Schema(implementation = TokenRefreshResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<APIResponse<TokenRefreshResponse>> refreshToken(
            @Valid @RequestBody TokenRefreshRequest request) {
        // The service method throws exceptions that are handled globally.
        TokenRefreshResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(APIResponse.success("Token refreshed successfully", response));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Forgot Password", description = "Initiates the password reset process.")
    @ApiResponse(responseCode = "200", description = "Password reset instructions sent", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "404", description = "User not found", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public ResponseEntity<APIResponse<MessageResponse>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {
        // No try-catch here – exceptions are handled globally by GlobalExceptionHandler
        MessageResponse response = authService.forgotPassword(request);
        return ResponseEntity.ok(APIResponse.success("Password reset instructions sent", response));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset Password", description = "Resets the user's password.")
    @ApiResponse(responseCode = "200", description = "Password reset successfully", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request / Invalid Token", content = @Content(schema = @Schema(implementation = APIResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = APIResponse.class)))
    public ResponseEntity<APIResponse<MessageResponse>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {
        MessageResponse response = authService.resetPassword(request);
        return ResponseEntity.ok(APIResponse.success("Password reset successfully", response));
    }

    @GetMapping("/check-username")
    @Operation(summary = "Check Username Availability", description = "Checks if a username is available.")
    @ApiResponse(responseCode = "200", description = "Username availability check successful", content = @Content(schema = @Schema(implementation = UsernameAvailabilityResponse.class)))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(schema = @Schema(implementation = APIResponse.class)))
    public ResponseEntity<APIResponse<UsernameAvailabilityResponse>> checkUsernameAvailability(
            @RequestParam @Pattern(regexp = "^[a-zA-Z0-9_]{4,20}$", message = "Username must be 4-20 characters and contain only letters, digits, or underscores") String username) {
        boolean isAvailable = authService.isUsernameAvailable(username);
        UsernameAvailabilityResponse data = new UsernameAvailabilityResponse(username, isAvailable);
        return ResponseEntity.ok(APIResponse.success("Username availability check successful", data));
    }

}