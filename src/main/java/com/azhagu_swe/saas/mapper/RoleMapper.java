package com.azhagu_swe.saas.mapper;

import java.util.stream.Collectors;

import com.azhagu_swe.saas.dto.request.RoleRequest;
import com.azhagu_swe.saas.dto.response.RoleResponse;
import com.azhagu_swe.saas.model.entity.Permission;
import com.azhagu_swe.saas.model.entity.Role;

public class RoleMapper {

    public static RoleResponse mapToResponse(Role role) {
        RoleResponse response = new RoleResponse();
        response.setId(role.getId());
        response.setName(role.getName());
        if (role.getPermissions() != null) {
            response.setPermissions(
                    role.getPermissions()
                            .stream()
                            .map(Permission::getName)
                            .collect(Collectors.toSet()));
        }
        return response;
    }

    public static Role mapToEntity(RoleRequest roleRequest) {
        Role role = new Role();
        role.setName(roleRequest.getName());
        // Note: Mapping permissions (from IDs) should be handled in the service layer.
        return role;
    }
}
