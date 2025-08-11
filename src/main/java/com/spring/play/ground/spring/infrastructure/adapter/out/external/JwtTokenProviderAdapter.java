package com.spring.play.ground.spring.infrastructure.adapter.out.external;

import com.spring.play.ground.spring.domain.model.User;
import com.spring.play.ground.spring.domain.port.out.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT token provider implementation using JJWT library
 * Handles JWT token generation, validation, and claims extraction
 * Uses HMAC-SHA256 for token signing with configurable secret
 */
@Slf4j
@Component
public class JwtTokenProviderAdapter implements JwtTokenProvider {
    
    // JWT secret key for token signing and validation
    private final SecretKey secretKey;
    
    // Token expiration times in minutes
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;
    
    /**
     * Constructor with configurable JWT settings
     * @param jwtSecret base64-encoded secret for token signing
     * @param accessTokenExpiration access token expiration in minutes
     * @param refreshTokenExpiration refresh token expiration in minutes
     */
    public JwtTokenProviderAdapter(
            @Value("${app.jwt.secret:defaultSecretKeyThatShouldBeChangedInProduction}") final String jwtSecret,
            @Value("${app.jwt.access-token-expiration:15}") final long accessTokenExpiration,
            @Value("${app.jwt.refresh-token-expiration:10080}") final long refreshTokenExpiration) {
        
        // Create secure key from secret string
        this.secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        
        log.info("JWT Token Provider initialized with access token expiration: {} minutes", accessTokenExpiration);
    }
    
    /**
     * Generates JWT access token for authenticated user
     * Includes user claims and shorter expiration time
     * @param user the authenticated user
     * @return JWT access token string
     */
    @Override
    public String generateAccessToken(final User user) {
        log.debug("Generating access token for user: {}", user.getUsername());
        
        // Calculate expiration time
        final Instant expirationTime = Instant.now().plus(accessTokenExpiration, ChronoUnit.MINUTES);
        
        // Create token claims
        final Map<String, Object> claims = createUserClaims(user);
        claims.put("token_type", "access");
        
        // Build and sign JWT token
        return Jwts.builder()
                .subject(user.getUsername())
                .claims(claims)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(expirationTime))
                .signWith(secretKey)
                .compact();
    }
    
    /**
     * Generates JWT refresh token for token renewal
     * Includes minimal claims and longer expiration time
     * @param user the authenticated user
     * @return JWT refresh token string
     */
    @Override
    public String generateRefreshToken(final User user) {
        log.debug("Generating refresh token for user: {}", user.getUsername());
        
        // Calculate expiration time (longer than access token)
        final Instant expirationTime = Instant.now().plus(refreshTokenExpiration, ChronoUnit.MINUTES);
        
        // Create minimal claims for refresh token
        final Map<String, Object> claims = new HashMap<>();
        claims.put("user_id", user.getUserId());
        claims.put("token_type", "refresh");
        
        // Build and sign JWT refresh token
        return Jwts.builder()
                .subject(user.getUsername())
                .claims(claims)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(expirationTime))
                .signWith(secretKey)
                .compact();
    }
    
    /**
     * Validates JWT token signature and expiration
     * Parses token and verifies integrity
     * @param token the JWT token to validate
     * @return true if token is valid, false otherwise
     */
    @Override
    public boolean validateToken(final String token) {
        try {
            // Parse and validate token signature and expiration
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            
            return true;
        } catch (final Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Extracts username from JWT token claims
     * Used to identify token owner
     * @param token the JWT token
     * @return username from token subject
     */
    @Override
    public String extractUsername(final String token) {
        return extractClaims(token).getSubject();
    }
    
    /**
     * Extracts user ID from JWT token claims
     * Used for user identification
     * @param token the JWT token
     * @return user ID from token claims
     */
    @Override
    public String extractUserId(final String token) {
        return extractClaims(token).get("user_id", String.class);
    }
    
    /**
     * Extracts token expiration time
     * Used to check token validity
     * @param token the JWT token
     * @return expiration timestamp
     */
    @Override
    public Instant extractExpiration(final String token) {
        final Date expiration = extractClaims(token).getExpiration();
        return expiration.toInstant();
    }
    
    /**
     * Checks if token is expired
     * Compares expiration time with current time
     * @param token the JWT token
     * @return true if token is expired, false otherwise
     */
    @Override
    public boolean isTokenExpired(final String token) {
        try {
            final Instant expiration = extractExpiration(token);
            return Instant.now().isAfter(expiration);
        } catch (final Exception e) {
            log.debug("Error checking token expiration: {}", e.getMessage());
            return true; // Consider invalid tokens as expired
        }
    }
    
    /**
     * Extracts all claims from JWT token
     * Parses token and returns claims object
     * @param token the JWT token
     * @return claims object containing token data
     */
    private Claims extractClaims(final String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    
    /**
     * Creates user claims map for JWT token
     * Includes user information and roles
     * @param user the user to create claims for
     * @return map of user claims
     */
    private Map<String, Object> createUserClaims(final User user) {
        final Map<String, Object> claims = new HashMap<>();
        
        // Add user information to claims
        claims.put("user_id", user.getUserId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("roles", user.getRoles());
        claims.put("enabled", user.isEnabled());
        
        return claims;
    }
}
