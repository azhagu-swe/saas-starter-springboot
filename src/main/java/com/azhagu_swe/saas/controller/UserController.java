package com.azhagu_swe.saas.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.azhagu_swe.saas.dto.request.CreateUserRequest;
import com.azhagu_swe.saas.dto.request.UpdateUserRequest;
import com.azhagu_swe.saas.dto.response.APIResponse;
import com.azhagu_swe.saas.dto.response.MessageResponse;
import com.azhagu_swe.saas.dto.response.UserResponse;
import com.azhagu_swe.saas.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;

@Tag(name = "User Management", description = "Endpoints for managing users")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/create")
    @Operation(summary = "Create User", description = "Registers a new user.")
    @ApiResponse(responseCode = "201", description = "User registered successfully", content = @Content(schema = @Schema(implementation = UserResponse.class)))
    public ResponseEntity<APIResponse<UserResponse>> createUser(@Valid @RequestBody CreateUserRequest request) {
        UserResponse response = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(APIResponse.success("User registered successfully", response));
    }

    @GetMapping
    @Operation(summary = "Get All Users", description = "Retrieves a list of all users.")
    @ApiResponse(responseCode = "200", description = "Users retrieved successfully", content = @Content(schema = @Schema(implementation = UserResponse[].class)))
    public ResponseEntity<APIResponse<List<UserResponse>>> getAllUsers() {
        List<UserResponse> users = userService.getAllUsers();
        return ResponseEntity.ok(APIResponse.success("Users retrieved successfully", users));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get User By ID", description = "Retrieves a user by their ID.")
    @ApiResponse(responseCode = "200", description = "User retrieved successfully", content = @Content(schema = @Schema(implementation = UserResponse.class)))
    public ResponseEntity<APIResponse<UserResponse>> getUserById(@PathVariable Long id) {
        UserResponse response = userService.getUserById(id);
        return ResponseEntity.ok(APIResponse.success("User retrieved successfully", response));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update User", description = "Updates an existing user.")
    @ApiResponse(responseCode = "200", description = "User updated successfully", content = @Content(schema = @Schema(implementation = UserResponse.class)))
    public ResponseEntity<APIResponse<UserResponse>> updateUser(@PathVariable Long id,
            @Valid @RequestBody UpdateUserRequest request) {
        UserResponse response = userService.updateUser(id, request);
        return ResponseEntity.ok(APIResponse.success("User updated successfully", response));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete User", description = "Deletes a user by their ID.")
    @ApiResponse(responseCode = "200", description = "User deleted successfully", content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    public ResponseEntity<APIResponse<MessageResponse>> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok(APIResponse.success("User deleted successfully"));
    }
}
