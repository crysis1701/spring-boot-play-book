package com.spring.play.ground.spring.domain.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

/**
 * Domain model representing authentication response
 * Immutable value object containing authentication result
 * Used to return authentication status and tokens to clients
 */
@Value
@Builder
public class AuthenticationResponse {
    
    /**
     * Authentication token (JWT, session ID, etc.)
     * Used for subsequent API calls
     */
    String token;
    
    /**
     * Type of token (Bearer, Basic, etc.)
     * Indicates how the token should be used in requests
     */
    String tokenType;
    
    /**
     * Token expiration timestamp
     * Client should refresh token before this time
     */
    Instant expiresAt;
    
    /**
     * Authenticated user information
     * Contains user identity and metadata
     */
    User user;
    
    /**
     * Optional refresh token for token renewal
     * Used to obtain new access tokens without re-authentication
     */
    String refreshToken;
    
    /**
     * Checks if the token is still valid
     * @return true if token has not expired
     */
    public boolean isTokenValid() {
        return expiresAt != null && Instant.now().isBefore(expiresAt);
    }
    
    /**
     * Creates a response without sensitive token data
     * Used for logging purposes
     * @return sanitized copy for logging
     */
    public AuthenticationResponse sanitized() {
        return AuthenticationResponse.builder()
                .token("[REDACTED]")
                .tokenType(tokenType)
                .expiresAt(expiresAt)
                .user(user)
                .refreshToken(refreshToken != null ? "[REDACTED]" : null)
                .build();
    }
}
