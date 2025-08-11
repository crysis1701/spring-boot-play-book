package com.spring.play.ground.spring.domain.model;

import lombok.Builder;
import lombok.Value;

/**
 * Domain model representing authentication credentials
 * Immutable value object for login requests
 * Contains sensitive data that should be handled securely
 */
@Value
@Builder
public class AuthenticationRequest {
    
    /**
     * Username or email for authentication
     * Should be validated for format and sanitized
     */
    String username;
    
    /**
     * Plain text password for authentication
     * Should be immediately hashed and cleared from memory
     * Never log or persist this value
     */
    String password;
    
    /**
     * Optional additional authentication factor
     * Used for multi-factor authentication scenarios
     */
    String additionalFactor;
    
    /**
     * Creates a sanitized copy without sensitive data
     * Used for logging and debugging purposes
     * @return copy with password removed
     */
    public AuthenticationRequest sanitized() {
        return AuthenticationRequest.builder()
                .username(username)
                .password("[REDACTED]")
                .additionalFactor(additionalFactor != null ? "[REDACTED]" : null)
                .build();
    }
}
