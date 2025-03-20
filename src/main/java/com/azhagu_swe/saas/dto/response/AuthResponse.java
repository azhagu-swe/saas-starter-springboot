package com.azhagu_swe.saas.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;
    // Add any other relevant user information you want to return upon successful
    // authentication
    private Long userId;
    private String username;
}
