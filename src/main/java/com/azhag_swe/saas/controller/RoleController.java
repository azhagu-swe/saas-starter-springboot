package com.azhag_swe.saas.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.azhag_swe.saas.constants.ErrorCodeConstants;
import com.azhag_swe.saas.dto.request.RoleRequest;
import com.azhag_swe.saas.dto.response.ErrorResponse;
import com.azhag_swe.saas.dto.response.RoleResponse;
import com.azhag_swe.saas.exception.ResourceNotFoundException;
import com.azhag_swe.saas.mapper.RoleMapper;
import com.azhag_swe.saas.service.RoleService;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    public ResponseEntity<Page<RoleResponse>> getAllRoles(@PageableDefault(size = 10) Pageable pageable) {
        Page<RoleResponse> rolesPage = roleService.getAllRoles(pageable)
                .map(RoleMapper::mapToResponse);
        return ResponseEntity.ok(rolesPage);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    public ResponseEntity<?> getRoleById(@PathVariable Long id) {
        try {
            RoleResponse response = RoleMapper.mapToResponse(roleService.getRoleById(id));
            return ResponseEntity.ok(response);
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_NOT_FOUND, "Role not found with id: " + id));
        }
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    public ResponseEntity<?> createRole(@Valid @RequestBody RoleRequest roleRequest) {
        try {
            RoleResponse response = RoleMapper.mapToResponse(
                    roleService.createRole(RoleMapper.mapToEntity(roleRequest)));
            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_CREATE_ERROR,
                            "Error creating role: " + ex.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    public ResponseEntity<?> updateRole(@PathVariable Long id, @Valid @RequestBody RoleRequest roleRequest) {
        try {
            RoleResponse response = RoleMapper.mapToResponse(
                    roleService.updateRole(id, RoleMapper.mapToEntity(roleRequest)));
            return ResponseEntity.ok(response);
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_NOT_FOUND, "Role not found with id: " + id));
        } catch (Exception ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_UPDATE_ERROR,
                            "Error updating role: " + ex.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('Admin', 'Manager')")
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        try {
            roleService.deleteRole(id);
            return ResponseEntity.ok().build();
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_NOT_FOUND, "Role not found with id: " + id));
        } catch (Exception ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(ErrorCodeConstants.ROLE_DELETE_ERROR,
                            "Error deleting role: " + ex.getMessage()));
        }
    }
}
