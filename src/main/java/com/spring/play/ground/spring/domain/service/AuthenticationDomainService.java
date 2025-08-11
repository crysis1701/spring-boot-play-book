package com.spring.play.ground.spring.domain.service;

import com.spring.play.ground.spring.domain.model.AuthenticationRequest;
import com.spring.play.ground.spring.domain.model.AuthenticationResponse;
import com.spring.play.ground.spring.domain.model.User;
import com.spring.play.ground.spring.domain.port.in.AuthenticateUserUseCase;
import com.spring.play.ground.spring.domain.port.out.JwtTokenProvider;
import com.spring.play.ground.spring.domain.port.out.PasswordEncoder;
import com.spring.play.ground.spring.domain.port.out.UserRepository;
import com.spring.play.ground.spring.shared.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

/**
 * Domain service implementing authentication use cases
 * Contains core business logic for user authentication
 * Uses dependency injection through constructor (no Spring annotations in domain)
 */
@Slf4j
@RequiredArgsConstructor
public class AuthenticationDomainService implements AuthenticateUserUseCase {
    
    // Dependencies injected through constructor for testability
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    
    /**
     * Authenticates user with basic credentials
     * Validates username/password and returns basic authentication response
     * @param request authentication credentials
     * @return authentication response with user info
     */
    @Override
    public AuthenticationResponse authenticateBasic(final AuthenticationRequest request) {
        log.debug("Attempting basic authentication for user: {}", request.getUsername());
        
        // Validate input parameters
        validateAuthenticationRequest(request);
        
        // Find and validate user
        final User user = findAndValidateUser(request);
        
        // Update last login time
        updateUserLastLogin(user);
        
        // Create basic authentication response (no JWT token)
        return AuthenticationResponse.builder()
                .tokenType("Basic")
                .user(user)
                .expiresAt(Instant.now().plusSeconds(3600)) // 1 hour session
                .build();
    }
    
    /**
     * Authenticates user and generates JWT token
     * Validates credentials and creates JSON Web Token for API access
     * @param request authentication credentials
     * @return authentication response with JWT token
     */
    @Override
    public AuthenticationResponse authenticateJwt(final AuthenticationRequest request) {
        log.debug("Attempting JWT authentication for user: {}", request.getUsername());
        
        // Validate input parameters
        validateAuthenticationRequest(request);
        
        // Find and validate user
        final User user = findAndValidateUser(request);
        
        // Generate JWT tokens
        final String accessToken = jwtTokenProvider.generateAccessToken(user);
        final String refreshToken = jwtTokenProvider.generateRefreshToken(user);
        final Instant expiresAt = jwtTokenProvider.extractExpiration(accessToken);
        
        // Update last login time
        updateUserLastLogin(user);
        
        log.info("JWT authentication successful for user: {}", user.getUsername());
        
        return AuthenticationResponse.builder()
                .token(accessToken)
                .tokenType("Bearer")
                .expiresAt(expiresAt)
                .user(user)
                .refreshToken(refreshToken)
                .build();
    }
    
    /**
     * Refreshes JWT token using refresh token
     * Validates refresh token and generates new access token
     * @param refreshToken the refresh token to validate
     * @return new authentication response with fresh token
     */
    @Override
    public AuthenticationResponse refreshToken(final String refreshToken) {
        log.debug("Attempting to refresh JWT token");
        
        // Validate refresh token format
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new AuthenticationException("Refresh token is required");
        }
        
        // Validate refresh token
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new AuthenticationException("Invalid or expired refresh token");
        }
        
        // Extract user information from refresh token
        final String username = jwtTokenProvider.extractUsername(refreshToken);
        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthenticationException("User not found: " + username));
        
        // Validate user account status
        if (!user.isValidForAuthentication()) {
            throw new AuthenticationException("User account is disabled or locked: " + username);
        }
        
        // Generate new tokens
        final String newAccessToken = jwtTokenProvider.generateAccessToken(user);
        final String newRefreshToken = jwtTokenProvider.generateRefreshToken(user);
        final Instant expiresAt = jwtTokenProvider.extractExpiration(newAccessToken);
        
        log.info("Token refresh successful for user: {}", user.getUsername());
        
        return AuthenticationResponse.builder()
                .token(newAccessToken)
                .tokenType("Bearer")
                .expiresAt(expiresAt)
                .user(user)
                .refreshToken(newRefreshToken)
                .build();
    }
    
    /**
     * Validates JWT token
     * Checks token signature, expiration, and format
     * @param token the token to validate
     * @return true if token is valid
     */
    @Override
    public boolean validateToken(final String token) {
        try {
            return token != null && !token.trim().isEmpty() && jwtTokenProvider.validateToken(token);
        } catch (final Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Extracts username from JWT token
     * Used for identifying authenticated user from token
     * @param token the JWT token
     * @return username from token claims
     */
    @Override
    public String extractUsernameFromToken(final String token) {
        if (!validateToken(token)) {
            throw new AuthenticationException("Invalid token provided");
        }
        
        return jwtTokenProvider.extractUsername(token);
    }
    
    /**
     * Validates authentication request parameters
     * Ensures required fields are present and properly formatted
     * @param request the authentication request to validate
     */
    private void validateAuthenticationRequest(final AuthenticationRequest request) {
        if (request == null) {
            throw new AuthenticationException("Authentication request is required");
        }
        
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new AuthenticationException("Username is required");
        }
        
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new AuthenticationException("Password is required");
        }
        
        // Additional validation for username format (email or username)
        final String username = request.getUsername().trim();
        if (username.length() < 3 || username.length() > 255) {
            throw new AuthenticationException("Username must be between 3 and 255 characters");
        }
    }
    
    /**
     * Finds user and validates credentials
     * Looks up user by username/email and verifies password
     * @param request authentication request with credentials
     * @return validated user object
     */
    private User findAndValidateUser(final AuthenticationRequest request) {
        final String username = request.getUsername().trim();
        
        // Try to find user by username first, then by email
        final var userOptional = userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(username));
        
        final User user = userOptional
                .orElseThrow(() -> new AuthenticationException("Invalid username or password"));
        
        // Validate account status
        if (!user.isValidForAuthentication()) {
            throw new AuthenticationException("Account is disabled or locked");
        }
        
        // Validate password using secure comparison
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            log.warn("Failed authentication attempt for user: {}", username);
            throw new AuthenticationException("Invalid username or password");
        }
        
        return user;
    }
    
    /**
     * Updates user's last login timestamp
     * Records successful authentication for auditing
     * @param user the authenticated user
     */
    private void updateUserLastLogin(final User user) {
        try {
            userRepository.updateLastLogin(user.getUserId(), Instant.now());
        } catch (final Exception e) {
            // Log error but don't fail authentication for audit update failure
            log.error("Failed to update last login for user: {}", user.getUsername(), e);
        }
    }
}
