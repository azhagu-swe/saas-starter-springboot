package com.azhagu_swe.saas.controller;

import com.azhagu_swe.saas.dto.request.RoleRequest;
import com.azhagu_swe.saas.dto.response.APIResponse;
import com.azhagu_swe.saas.dto.response.RoleResponse;
import com.azhagu_swe.saas.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse ;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "Role", description = "Operations pertaining to permissions")
@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    @Operation(summary = "Get All Roles", description = "Retrieves a paginated list of all roles.")
    @ApiResponse(responseCode = "200", description = "Roles retrieved successfully", 
             content = @Content(schema = @Schema(implementation = APIResponse.class)))
    public ResponseEntity<APIResponse<Page<RoleResponse>>> getAllRoles(@PageableDefault(size = 10) Pageable pageable) {
        Page<RoleResponse> rolesPage = roleService.getAllRoles(pageable);
        return ResponseEntity.ok(APIResponse.success("Roles retrieved successfully", rolesPage));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    @Operation(summary = "Get Role by ID", description = "Retrieves a role by its unique identifier.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role retrieved successfully", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class))),
            @ApiResponse(responseCode = "404", description = "Role not found", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class)))
    })
    public ResponseEntity<APIResponse<RoleResponse>> getRoleById(@PathVariable Long id) {
        RoleResponse response = roleService.getRoleById(id);
        return ResponseEntity.ok(APIResponse.success("Role retrieved successfully", response));
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    @Operation(summary = "Create Role", description = "Creates a new role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Role created successfully", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class))),
            @ApiResponse(responseCode = "409", description = "Role already exists", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class)))
    })
    public ResponseEntity<APIResponse<RoleResponse>> createRole(@Valid @RequestBody RoleRequest roleRequest) {
        RoleResponse response = roleService.createRole(roleRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(APIResponse.success("Role created successfully", response));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    @Operation(summary = "Update Role", description = "Updates an existing role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role updated successfully", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid request", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class))),
            @ApiResponse(responseCode = "404", description = "Role not found", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class)))
    })
    public ResponseEntity<APIResponse<RoleResponse>> updateRole(@PathVariable Long id,
                                                                @Valid @RequestBody RoleRequest roleRequest) {
        RoleResponse response = roleService.updateRole(id, roleRequest);
        return ResponseEntity.ok(APIResponse.success("Role updated successfully", response));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    @Operation(summary = "Delete Role", description = "Deletes a role by its identifier.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Role deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Role not found", 
                     content = @Content(schema = @Schema(implementation = APIResponse.class)))
    })
    public ResponseEntity<APIResponse<Void>> deleteRole(@PathVariable Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
