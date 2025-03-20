package com.azhagu_swe.saas.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import java.util.Set;

@Data
public class RoleRequest {

    @NotBlank(message = "Role name is required")
    private String name;

    private Set<Long> permissionIds;

}
