package com.azhag_swe.saas.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ResetPasswordRequest {

    @NotBlank(message = "Reset token must not be blank")
    private String token;

    @NotBlank(message = "New password is required")
    @Size(min = 6, max = 40, message = "New password must be between 6 and 40 characters")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*$", message = "New password must include at least one uppercase letter, one lowercase letter, and one digit")
    private String newPassword;
}
