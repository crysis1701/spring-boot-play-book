package com.spring.play.ground.spring.shared.exception;

/**
 * Custom authentication exception for domain layer
 * Used when authentication fails in business logic
 * Extends RuntimeException to avoid forcing catch blocks throughout the application
 */
public class AuthenticationException extends RuntimeException {
    
    /**
     * Creates authentication exception with error message
     * @param message descriptive error message for debugging
     */
    public AuthenticationException(final String message) {
        super(message);
    }
    
    /**
     * Creates authentication exception with error message and root cause
     * @param message descriptive error message for debugging
     * @param cause the underlying exception that caused this error
     */
    public AuthenticationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
