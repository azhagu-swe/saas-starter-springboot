package com.azhagu_swe.saas.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class UsernameAvailabilityResponse {

    private String useName;
    private boolean available;

}
