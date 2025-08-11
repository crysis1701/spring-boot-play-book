package com.spring.play.ground.spring.shared.exception;

/**
 * Custom authorization exception for domain layer
 * Used when user lacks sufficient permissions for requested operation
 * Follows fail-fast principle for security violations
 */
public class AuthorizationException extends RuntimeException {
    
    /**
     * Creates authorization exception with error message
     * @param message descriptive error message for debugging
     */
    public AuthorizationException(final String message) {
        super(message);
    }
    
    /**
     * Creates authorization exception with error message and root cause
     * @param message descriptive error message for debugging
     * @param cause the underlying exception that caused this error
     */
    public AuthorizationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
