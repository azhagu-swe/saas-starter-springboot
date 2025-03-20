package com.azhagu_swe.saas.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.util.Set;

@Data
public class UpdateUserRolesRequest {

    @NotNull(message = "User ID is required")
    private Long userId;

    private Set<String> roles;
}
