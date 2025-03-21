package com.azhagu_swe.saas.mapper;

import java.util.stream.Collectors;

import com.azhagu_swe.saas.dto.request.RoleRequest;
import com.azhagu_swe.saas.dto.response.RoleResponse;
import com.azhagu_swe.saas.model.entity.Permission;
import com.azhagu_swe.saas.model.entity.Role;

/**
 * Utility class for mapping between Role entities and Role DTOs.
 */
public class RoleMapper {

    /**
     * Converts a Role entity to a RoleResponse DTO.
     *
     * @param role the Role entity to convert
     * @return a RoleResponse DTO containing role details
     */
    public static RoleResponse toResponse(Role role) {
        RoleResponse response = new RoleResponse();
        response.setId(role.getId());
        response.setName(role.getName());
        if (role.getPermissions() != null) {
            response.setPermissions(
                role.getPermissions()
                    .stream()
                    .map(Permission::getName)
                    .collect(Collectors.toSet())
            );
        }
        return response;
    }

    /**
     * Converts a RoleRequest DTO to a new Role entity.
     * Note: Mapping of permissions (from IDs) should be handled in the service layer.
     *
     * @param roleRequest the RoleRequest DTO
     * @return a new Role entity with basic properties populated
     */
    public static Role toEntity(RoleRequest roleRequest) {
        Role role = new Role();
        role.setName(roleRequest.getName());
        // Permissions mapping is handled in the service layer if needed.
        return role;
    }

    /**
     * Updates an existing Role entity with data from a RoleRequest DTO.
     * Note: If you need to update permissions, handle that in the service layer.
     *
     * @param role the existing Role entity to update
     * @param roleRequest the RoleRequest DTO containing updated data
     */
    public static void updateEntity(Role role, RoleRequest roleRequest) {
        role.setName(roleRequest.getName());
        // Permissions update can be handled here if required.
    }
}
