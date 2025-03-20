package com.azhagu_swe.saas.exception;

import com.azhagu_swe.saas.constants.ErrorCodeConstants;
import com.azhagu_swe.saas.dto.response.APIResponse;
import com.azhagu_swe.saas.dto.response.ErrorResponse;
import com.azhagu_swe.saas.enumeration.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.stream.Collectors;

@ControllerAdvice
@ResponseBody
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // Handle custom ResourceNotFoundException
    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleResourceNotFound(ResourceNotFoundException ex, HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.RESOURCE_NOT_FOUND, "The requested resource was not found.");
    }

    // Handle Spring Security authentication exceptions
    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse handleAuthenticationException(AuthenticationException ex, HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.AUTHENTICATION_FAILED,
                "Authentication failed. Please check your credentials.");
    }

    // Handle Spring Security authorization exceptions (insufficient permissions)
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorResponse handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.ACCESS_DENIED,
                "You do not have permission to access this resource.");
    }

    // Handle validation exceptions from @Valid annotations
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleValidationExceptions(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String errorMessage = ex.getBindingResult().getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        logError(ex, request, errorMessage);
        return new ErrorResponse(ErrorCodeConstants.VALIDATION_ERROR, "Invalid input: " + errorMessage);
    }

    // Handle unsupported HTTP methods (405)
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public ErrorResponse handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex,
            HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.METHOD_NOT_ALLOWED, "HTTP method not supported for this endpoint.");
    }

    // Handle requests for URLs that don't exist (404)
    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleNoHandlerFoundException(NoHandlerFoundException ex, HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.RESOURCE_NOT_FOUND,
                "The requested URL was not found on the server.");
    }

    // Handle custom ApplicationException and its subclasses
    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<ErrorResponse> handleApplicationException(ApplicationException ex,
            HttpServletRequest request) {
        ErrorCode errorCode = ex.getErrorCode();
        HttpStatus status = getStatusFromErrorCode(errorCode);
        logError(ex, request, "ApplicationException: " + errorCode.getCode() + " - " + ex.getMessage());
        return new ResponseEntity<>(new ErrorResponse(errorCode.getCode(), ex.getMessage()), status);
    }

    // Handle all other exceptions (500)
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorResponse handleGlobalException(Exception ex, HttpServletRequest request) {
        logError(ex, request);
        return new ErrorResponse(ErrorCodeConstants.GENERAL_ERROR,
                "An unexpected error occurred. Please try again later.");
    }

    // Helper method to map ErrorCode to HttpStatus
    private HttpStatus getStatusFromErrorCode(ErrorCode errorCode) {
        return switch (errorCode) {
            case RESOURCE_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case AUTH_INVALID_CREDENTIALS, AUTH_TOKEN_NOT_FOUND, AUTH_TOKEN_EXPIRED -> HttpStatus.UNAUTHORIZED;
            case AUTH_ACCESS_DENIED -> HttpStatus.FORBIDDEN;
            case VALIDATION_FAILED, DUPLICATE_USERNAME, DUPLICATE_EMAIL -> HttpStatus.BAD_REQUEST;
            case METHOD_NOT_ALLOWED -> HttpStatus.METHOD_NOT_ALLOWED;
            case INTERNAL_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }

    // Helper methods for consistent error logging
    private void logError(Exception ex, HttpServletRequest request) {
        logger.error("Error processing request [{}]: ", request.getRequestURI(), ex);
    }

    private void logError(Exception ex, HttpServletRequest request, String message) {
        logger.error("{} - Request URI: {} - Exception: ", message, request.getRequestURI(), ex);
    }

    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleInvalidToken(InvalidTokenException ex, HttpServletRequest request) {
        logger.warn("Invalid token at {}: {}", request.getRequestURI(), ex.getMessage());
        return new ErrorResponse("INVALID_TOKEN", "Invalid or expired token provided.");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public APIResponse<?> handleIllegalArgumentException(IllegalArgumentException ex, HttpServletRequest request) {
        logger.warn("Bad request at {}: {}", request.getRequestURI(), ex.getMessage());
        return APIResponse.error(ex.getMessage(), ErrorCodeConstants.VALIDATION_ERROR);
    }

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<APIResponse<?>> handleServiceException(ServiceException ex, HttpServletRequest request) {
        logger.error("Service exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(APIResponse.error("A service error occurred. Please try again later.",
                        ErrorCodeConstants.GENERAL_ERROR));
    }

}
