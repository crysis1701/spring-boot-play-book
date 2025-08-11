package com.spring.play.ground.spring.infrastructure.adapter.in.web;

import com.spring.play.ground.spring.shared.exception.AuthenticationException;
import com.spring.play.ground.spring.shared.exception.AuthorizationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for all REST controllers
 * Provides consistent error responses across the application
 * Handles authentication, authorization, validation, and general errors
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    /**
     * Handles authentication exceptions
     * Returns 401 Unauthorized with error details
     * 
     * @param ex the authentication exception
     * @param request the web request context
     * @return error response with authentication failure details
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            final AuthenticationException ex,
            final WebRequest request) {
        
        log.warn("Authentication failed: {}", ex.getMessage());
        
        final ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .error("AUTHENTICATION_FAILED")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(extractPath(request))
                .build();
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }
    
    /**
     * Handles authorization exceptions
     * Returns 403 Forbidden with error details
     * 
     * @param ex the authorization exception
     * @param request the web request context
     * @return error response with authorization failure details
     */
    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleAuthorizationException(
            final AuthorizationException ex,
            final WebRequest request) {
        
        log.warn("Authorization failed: {}", ex.getMessage());
        
        final ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .error("AUTHORIZATION_FAILED")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(extractPath(request))
                .build();
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }
    
    /**
     * Handles validation exceptions from @Valid annotations
     * Returns 400 Bad Request with field-specific validation errors
     * 
     * @param ex the method argument validation exception
     * @param request the web request context
     * @return error response with validation failure details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationException(
            final MethodArgumentNotValidException ex,
            final WebRequest request) {
        
        log.warn("Validation failed for request: {}", request.getDescription(false));
        
        // Extract field validation errors
        final Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            if (error instanceof FieldError fieldError) {
                fieldErrors.put(fieldError.getField(), error.getDefaultMessage());
            } else {
                fieldErrors.put("general", error.getDefaultMessage());
            }
        });
        
        final ValidationErrorResponse errorResponse = ValidationErrorResponse.builder()
                .success(false)
                .error("VALIDATION_FAILED")
                .message("Request validation failed")
                .timestamp(Instant.now())
                .path(extractPath(request))
                .fieldErrors(fieldErrors)
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
    
    /**
     * Handles illegal argument exceptions
     * Returns 400 Bad Request with error details
     * 
     * @param ex the illegal argument exception
     * @param request the web request context
     * @return error response with bad request details
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
            final IllegalArgumentException ex,
            final WebRequest request) {
        
        log.warn("Illegal argument: {}", ex.getMessage());
        
        final ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .error("INVALID_ARGUMENT")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(extractPath(request))
                .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
    
    /**
     * Handles all other unexpected exceptions
     * Returns 500 Internal Server Error with generic error message
     * Logs full exception details for debugging
     * 
     * @param ex the unexpected exception
     * @param request the web request context
     * @return error response with internal server error details
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            final Exception ex,
            final WebRequest request) {
        
        log.error("Unexpected error occurred", ex);
        
        // Don't expose internal error details to clients in production
        final String message = "An unexpected error occurred. Please try again later.";
        
        final ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .error("INTERNAL_ERROR")
                .message(message)
                .timestamp(Instant.now())
                .path(extractPath(request))
                .build();
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
    
    /**
     * Extracts request path from WebRequest for error logging
     * Provides context about which endpoint caused the error
     * 
     * @param request the web request
     * @return extracted path or default value
     */
    private String extractPath(final WebRequest request) {
        final String description = request.getDescription(false);
        
        // Extract path from description like "uri=/api/auth/login"
        if (description != null && description.startsWith("uri=")) {
            return description.substring(4); // Remove "uri=" prefix
        }
        
        return "unknown";
    }
    
    /**
     * Standard error response DTO
     * Used for most error scenarios
     */
    @lombok.Builder
    public record ErrorResponse(
            boolean success,
            String error,
            String message,
            Instant timestamp,
            String path
    ) {}
    
    /**
     * Validation error response DTO
     * Extends standard error response with field-specific errors
     */
    @lombok.Builder
    public record ValidationErrorResponse(
            boolean success,
            String error,
            String message,
            Instant timestamp,
            String path,
            Map<String, String> fieldErrors
    ) {}
}
