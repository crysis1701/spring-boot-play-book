package com.spring.play.ground.spring.domain.port.out;

import com.spring.play.ground.spring.domain.model.User;

import java.time.Instant;

/**
 * Outbound port for JWT token operations
 * Defines contract for JSON Web Token handling
 * Implementation will be in infrastructure layer
 */
public interface JwtTokenProvider {
    
    /**
     * Generates JWT access token for authenticated user
     * Contains user claims and expiration information
     * @param user the authenticated user
     * @return JWT access token string
     */
    String generateAccessToken(User user);
    
    /**
     * Generates JWT refresh token for token renewal
     * Has longer expiration time than access token
     * @param user the authenticated user
     * @return JWT refresh token string
     */
    String generateRefreshToken(User user);
    
    /**
     * Validates JWT token signature and expiration
     * Checks token integrity and validity
     * @param token the JWT token to validate
     * @return true if token is valid, false otherwise
     */
    boolean validateToken(String token);
    
    /**
     * Extracts username from JWT token claims
     * Used to identify token owner
     * @param token the JWT token
     * @return username from token claims
     */
    String extractUsername(String token);
    
    /**
     * Extracts user ID from JWT token claims
     * Used for user identification
     * @param token the JWT token
     * @return user ID from token claims
     */
    String extractUserId(String token);
    
    /**
     * Extracts token expiration time
     * Used to check token validity
     * @param token the JWT token
     * @return expiration timestamp
     */
    Instant extractExpiration(String token);
    
    /**
     * Checks if token is expired
     * Compares expiration time with current time
     * @param token the JWT token
     * @return true if token is expired, false otherwise
     */
    boolean isTokenExpired(String token);
}
