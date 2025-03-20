package com.azhag_swe.saas.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Username must not be blank")
    private String username;
  
    @NotBlank(message = "Password must not be blank")
    private String password;
}
