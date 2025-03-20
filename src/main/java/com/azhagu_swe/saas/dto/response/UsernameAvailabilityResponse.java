package com.azhagu_swe.saas.dto.response;

public class UsernameAvailabilityResponse {
    private boolean available;

    public UsernameAvailabilityResponse(boolean available) {
        this.available = available;
    }

    public boolean isAvailable() {
        return available;
    }
}
