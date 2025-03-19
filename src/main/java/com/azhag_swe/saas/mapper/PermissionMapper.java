
package com.azhag_swe.saas.mapper;

import com.azhag_swe.saas.dto.request.PermissionRequest;
import com.azhag_swe.saas.dto.response.PermissionResponse;
import com.azhag_swe.saas.model.entity.Permission;

public class PermissionMapper {

    public static PermissionResponse toResponse(Permission permission) {
        PermissionResponse response = new PermissionResponse();
        response.setId(permission.getId());
        response.setName(permission.getName());
        return response;
    }

    public static Permission toEntity(PermissionRequest request) {
        Permission permission = new Permission();
        permission.setName(request.getName());
        return permission;
    }

    public static void updateEntity(Permission permission, PermissionRequest request) {
        permission.setName(request.getName());
    }
}
