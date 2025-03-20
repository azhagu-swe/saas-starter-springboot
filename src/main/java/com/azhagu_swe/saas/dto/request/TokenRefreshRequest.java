package com.azhagu_swe.saas.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TokenRefreshRequest {

    @NotBlank(message = "Refresh token must not be blank")
    private String refreshToken;
}
