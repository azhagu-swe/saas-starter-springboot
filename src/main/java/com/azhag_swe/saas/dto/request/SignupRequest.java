package com.azhag_swe.saas.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.util.Set;

@Data
public class SignupRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters long")
    // Example regex: password must contain at least one uppercase letter, one
    // lowercase letter, and one digit.
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*$", message = "Password must contain at least one uppercase letter, one lowercase letter, and one digit")
    private String password;

    // Optional: roles to be assigned (e.g., "USER", "ADMIN")
    private Set<String> role;
}
