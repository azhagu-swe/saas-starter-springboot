package com.azhagu_swe.saas.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL) // Only include non-null fields in the JSON output
public class APIResponse<T> {

    private String status; // "success" or "error"
    private String message;
    private T data;
    private String errorCode; // Optional, for error cases

    // Constructor for successful responses
    public APIResponse(String status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.errorCode = null; // No error code for success
    }

    // Constructor for error responses
    public APIResponse(String status, String message, String errorCode) {
        this.status = status;
        this.message = message;
        this.data = null; // No data for errors
        this.errorCode = errorCode;
    }

    // Constructor for success responses without a message
    public APIResponse(String status, T data) {
        this.status = status;
        this.message = null;
        this.data = data;
        this.errorCode = null;
    }

    // Getters (and setters if you need them, but often getters are enough)
    public String getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public T getData() {
        return data;
    }

    public String getErrorCode() {
        return errorCode;
    }

    // Static factory methods for convenience (highly recommended)

    public static <T> APIResponse<T> success(T data) {
        return new APIResponse<>("success", null, data);
    }

    public static <T> APIResponse<T> success(String message, T data) {
        return new APIResponse<>("success", message, data);
    }

    public static <T> APIResponse<T> success(String message) {
        return new APIResponse<>("success", message, null);
    }

    public static <T> APIResponse<T> error(String message, String errorCode) {
        return new APIResponse<>("error", message, errorCode);
    }

    // Builder pattern (optional, but good for complex objects) - Inner class
    public static class Builder<T> {
        private String status;
        private String message;
        private T data;
        private String errorCode;

        public Builder(String status) {
            this.status = status;
        }

        public Builder<T> message(String message) {
            this.message = message;
            return this;
        }

        public Builder<T> data(T data) {
            this.data = data;
            return this;
        }

        public Builder<T> errorCode(String errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        public APIResponse<T> build() {
            if ("success".equals(status)) {
                return new APIResponse<>(status, message, data);
            } else if ("error".equals(status)) {
                return new APIResponse<>(status, message, errorCode);
            } else {
                throw new IllegalStateException("Status must be either 'success' or 'error'");
            }
        }
    }
}