package com.azhagu_swe.saas.controller;

import com.azhagu_swe.saas.dto.request.PermissionRequest;
import com.azhagu_swe.saas.dto.response.APIResponse;
import com.azhagu_swe.saas.dto.response.PermissionResponse;
import com.azhagu_swe.saas.service.PermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Tag(name = "Permissions", description = "Operations pertaining to permissions")
@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping
    @Operation(summary = "Get All Permissions", description = "Retrieves a list of all permissions.")
    @ApiResponse(responseCode = "200", description = "Successful retrieval", content = @Content(schema = @Schema(implementation = PermissionResponse.class)))
    public ResponseEntity<APIResponse<List<PermissionResponse>>> getAllPermissions() {
        List<PermissionResponse> responses = permissionService.getAllPermissions();
        return ResponseEntity.ok(APIResponse.success("Permissions retrieved successfully", responses));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get Permission by ID", description = "Retrieves a permission by its unique identifier.")
    @ApiResponse(responseCode = "200", description = "Successful retrieval", content = @Content(schema = @Schema(implementation = PermissionResponse.class)))
    public ResponseEntity<APIResponse<PermissionResponse>> getPermissionById(@PathVariable Long id) {
        PermissionResponse response = permissionService.getPermissionById(id);
        return ResponseEntity.ok(APIResponse.success("Permission retrieved successfully", response));
    }

    @PostMapping("/create")
    @Operation(summary = "Create Permission", description = "Creates a new permission.")
    @ApiResponse(responseCode = "201", description = "Permission created successfully", content = @Content(schema = @Schema(implementation = PermissionResponse.class)))
    public ResponseEntity<APIResponse<PermissionResponse>> createPermission(
            @Valid @RequestBody PermissionRequest request) {
        PermissionResponse response = permissionService.createPermission(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(APIResponse.success("Permission created successfully", response));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update Permission", description = "Updates an existing permission.")
    @ApiResponse(responseCode = "200", description = "Permission updated successfully", content = @Content(schema = @Schema(implementation = PermissionResponse.class)))
    public ResponseEntity<APIResponse<PermissionResponse>> updatePermission(
            @PathVariable Long id, @Valid @RequestBody PermissionRequest request) {
        PermissionResponse response = permissionService.updatePermission(id, request);
        return ResponseEntity.ok(APIResponse.success("Permission updated successfully", response));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete Permission", description = "Deletes a permission by its identifier.")
    @ApiResponse(responseCode = "204", description = "Permission deleted successfully")
    public ResponseEntity<APIResponse<Void>> deletePermission(@PathVariable Long id) {
        permissionService.deletePermission(id);
        return ResponseEntity.noContent().build();
    }
}
