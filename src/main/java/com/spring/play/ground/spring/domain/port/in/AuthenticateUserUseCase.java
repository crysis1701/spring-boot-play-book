package com.spring.play.ground.spring.domain.port.in;

import com.spring.play.ground.spring.domain.model.AuthenticationRequest;
import com.spring.play.ground.spring.domain.model.AuthenticationResponse;

/**
 * Inbound port for authentication use cases
 * Defines contract for authentication operations in the domain
 * Implementation will be in the domain service layer
 */
public interface AuthenticateUserUseCase {
    
    /**
     * Authenticates user with basic username/password credentials
     * Validates credentials and returns authentication token
     * @param request authentication credentials
     * @return authentication response with token and user info
     * @throws com.spring.play.ground.spring.shared.exception.AuthenticationException if authentication fails
     */
    AuthenticationResponse authenticateBasic(AuthenticationRequest request);
    
    /**
     * Authenticates user and creates JWT token
     * Validates credentials and generates JSON Web Token
     * @param request authentication credentials
     * @return authentication response with JWT token
     * @throws com.spring.play.ground.spring.shared.exception.AuthenticationException if authentication fails
     */
    AuthenticationResponse authenticateJwt(AuthenticationRequest request);
    
    /**
     * Validates and refreshes an existing authentication token
     * Used for token renewal without re-entering credentials
     * @param refreshToken the refresh token to validate
     * @return new authentication response with refreshed token
     * @throws com.spring.play.ground.spring.shared.exception.AuthenticationException if refresh fails
     */
    AuthenticationResponse refreshToken(String refreshToken);
    
    /**
     * Validates an authentication token
     * Checks if token is valid and not expired
     * @param token the token to validate
     * @return true if token is valid, false otherwise
     */
    boolean validateToken(String token);
    
    /**
     * Extracts username from authentication token
     * Used to identify the authenticated user
     * @param token the authentication token
     * @return username associated with the token
     * @throws com.spring.play.ground.spring.shared.exception.AuthenticationException if token is invalid
     */
    String extractUsernameFromToken(String token);
}
