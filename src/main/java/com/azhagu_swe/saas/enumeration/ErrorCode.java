package com.azhagu_swe.saas.enumeration;

public enum ErrorCode {
    // Authentication & Authorization Errors
    AUTH_INVALID_CREDENTIALS("AUTH001", "Invalid username or password."),
    AUTH_TOKEN_EXPIRED("AUTH002", "Refresh token has expired. Please sign in again."),
    AUTH_TOKEN_NOT_FOUND("AUTH003", "Refresh token not found. Please sign in again."),
    AUTH_ACCESS_DENIED("AUTH004", "Access denied. You do not have the required permissions."),

    // Validation Errors
    VALIDATION_FAILED("VAL001", "Input validation failed."),
    DUPLICATE_USERNAME("VAL002", "Username is already taken."),
    DUPLICATE_EMAIL("VAL003", "Email is already in use."),

    // Resource Errors
    RESOURCE_NOT_FOUND("RES404", "The requested resource was not found."),

    // HTTP Method Errors
    METHOD_NOT_ALLOWED("HTTP405", "HTTP method not allowed."),

    // General/Internal Errors
    INTERNAL_ERROR("INT500", "An internal server error occurred. Please try again later."), 
    ROLE_ALREADY_EXISTS("ROLE005", "Role already exists with the provided name.");

    private final String code;
    private final String message;

    ErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
