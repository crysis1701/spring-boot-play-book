package com.spring.play.ground.spring.infrastructure.adapter.in.web;

import com.spring.play.ground.spring.domain.model.AuthenticationRequest;
import com.spring.play.ground.spring.domain.model.AuthenticationResponse;
import com.spring.play.ground.spring.domain.port.in.AuthenticateUserUseCase;
import com.spring.play.ground.spring.shared.exception.AuthenticationException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for Basic Authentication endpoints
 * Handles username/password authentication with session-based security
 * Implements circuit breaker pattern for resilience
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/basic")
@RequiredArgsConstructor
@Validated
@Tag(name = "Basic Authentication", description = "Session-based authentication endpoints with username/password")
public class BasicAuthController {
    
    // Domain use case for authentication operations
    private final AuthenticateUserUseCase authenticateUserUseCase;
    
    /**
     * Authenticates user with basic credentials
     * Returns session-based authentication response
     * 
     * @param request authentication credentials with validation
     * @return authentication response with user info and session details
     */
    @Operation(
            summary = "Authenticate with Basic Auth",
            description = """
                    Authenticates user credentials and returns session-based authentication.
                    
                    **Use this endpoint for traditional session-based authentication.**
                    
                    The response includes:
                    - Session ID for subsequent requests
                    - User information and roles
                    - Session expiration time
                    """,
            tags = {"Basic Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentication successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = BasicAuthResponse.class),
                            examples = @ExampleObject(
                                    name = "Successful Basic Login",
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Authentication successful",
                                              "sessionId": "BASIC_SESSION_1691747000_abc123de",
                                              "username": "basicuser",
                                              "email": "basic@example.com",
                                              "roles": ["USER", "BASIC_TEST"],
                                              "expiresAt": "2025-08-11T11:45:00Z"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Authentication Failed",
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Authentication failed: Invalid username or password"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/login")
    @CircuitBreaker(name = "basic-auth", fallbackMethod = "loginFallback")
    public ResponseEntity<BasicAuthResponse> login(
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Basic authentication credentials",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = BasicAuthRequest.class),
                            examples = @ExampleObject(
                                    name = "Basic Login Example",
                                    value = """
                                            {
                                              "username": "basicuser",
                                              "password": "basic123456"
                                            }
                                            """
                            )
                    )
            )
            final BasicAuthRequest request) {
        log.info("Basic authentication attempt for user: {}", request.username());
        
        try {
            // Create domain authentication request
            final AuthenticationRequest authRequest = AuthenticationRequest.builder()
                    .username(request.username())
                    .password(request.password())
                    .build();
            
            // Authenticate user using domain service
            final AuthenticationResponse authResponse = authenticateUserUseCase.authenticateBasic(authRequest);
            
            // Convert to web response
            final BasicAuthResponse response = BasicAuthResponse.builder()
                    .success(true)
                    .message("Authentication successful")
                    .sessionId(generateSessionId()) // Generate session ID for basic auth
                    .username(authResponse.getUser().getUsername())
                    .email(authResponse.getUser().getEmail())
                    .roles(authResponse.getUser().getRoles())
                    .expiresAt(authResponse.getExpiresAt())
                    .build();
            
            log.info("Basic authentication successful for user: {}", request.username());
            return ResponseEntity.ok(response);
            
        } catch (final AuthenticationException e) {
            log.warn("Basic authentication failed for user: {} - {}", request.username(), e.getMessage());
            
            final BasicAuthResponse errorResponse = BasicAuthResponse.builder()
                    .success(false)
                    .message("Authentication failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    /**
     * Validates current session
     * Checks if session is still valid and returns user info
     * 
     * @param sessionId the session identifier to validate
     * @return session validation response
     */
    @Operation(
            summary = "Validate Basic Auth Session",
            description = """
                    Validates the current basic authentication session.
                    
                    **Use this endpoint to check if your session is still active.**
                    
                    The response includes:
                    - Session validity status
                    - Session identifier
                    - Validation message
                    """,
            tags = {"Basic Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Session validation result",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SessionValidationResponse.class),
                            examples = {
                                    @ExampleObject(
                                            name = "Valid Session",
                                            value = """
                                                    {
                                                      "valid": true,
                                                      "message": "Session is valid",
                                                      "sessionId": "BASIC_SESSION_1691747000_abc123de"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Invalid Session",
                                            value = """
                                                    {
                                                      "valid": false,
                                                      "message": "Invalid session format",
                                                      "sessionId": "short"
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Session is invalid or expired",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SessionValidationResponse.class),
                            examples = @ExampleObject(
                                    name = "Invalid Session Error",
                                    value = """
                                            {
                                              "valid": false,
                                              "message": "Invalid session format"
                                            }
                                            """
                            )
                    )
            )
    })
    @GetMapping("/validate")
    @CircuitBreaker(name = "basic-auth", fallbackMethod = "validateFallback")
    public ResponseEntity<SessionValidationResponse> validateSession(
            @Parameter(
                    description = "Session ID obtained from login response",
                    required = true,
                    example = "BASIC_SESSION_1691747000_abc123de"
            )
            @RequestHeader("X-Session-ID") @NotBlank final String sessionId) {
        
        log.debug("Validating session: {}", sessionId);
        
        try {
            // In a real implementation, you would validate the session against a session store
            // For demo purposes, we'll assume all non-empty session IDs are valid
            if (sessionId.length() < 10) {
                throw new AuthenticationException("Invalid session format");
            }
            
            final SessionValidationResponse response = SessionValidationResponse.builder()
                    .valid(true)
                    .message("Session is valid")
                    .sessionId(sessionId)
                    .build();
            
            return ResponseEntity.ok(response);
            
        } catch (final Exception e) {
            log.warn("Session validation failed for session: {} - {}", sessionId, e.getMessage());
            
            final SessionValidationResponse errorResponse = SessionValidationResponse.builder()
                    .valid(false)
                    .message("Session validation failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    /**
     * Logout endpoint for basic authentication
     * Invalidates the current session
     * 
     * @param sessionId the session identifier to invalidate
     * @return logout response
     */
    @Operation(
            summary = "Logout from Basic Auth Session",
            description = """
                    Logs out the user by invalidating the current basic authentication session.
                    
                    **Use this endpoint to securely end a user session.**
                    
                    The response includes:
                    - Logout success status
                    - Confirmation message
                    """,
            tags = {"Basic Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Logout successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponse.class),
                            examples = @ExampleObject(
                                    name = "Successful Logout",
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Logout successful"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Logout failed",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponse.class),
                            examples = @ExampleObject(
                                    name = "Logout Failed",
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Logout failed: Internal server error"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/logout")
    @CircuitBreaker(name = "basic-auth", fallbackMethod = "logoutFallback")
    public ResponseEntity<LogoutResponse> logout(
            @Parameter(
                    description = "Session ID to invalidate",
                    required = true,
                    example = "BASIC_SESSION_1691747000_abc123de"
            )
            @RequestHeader("X-Session-ID") @NotBlank final String sessionId) {
        
        log.info("Logout request for session: {}", sessionId);
        
        try {
            // In a real implementation, you would invalidate the session in your session store
            // For demo purposes, we'll just return success
            
            final LogoutResponse response = LogoutResponse.builder()
                    .success(true)
                    .message("Logout successful")
                    .build();
            
            log.info("Logout successful for session: {}", sessionId);
            return ResponseEntity.ok(response);
            
        } catch (final Exception e) {
            log.error("Logout failed for session: {} - {}", sessionId, e.getMessage());
            
            final LogoutResponse errorResponse = LogoutResponse.builder()
                    .success(false)
                    .message("Logout failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
    
    // Circuit breaker fallback methods
    
    /**
     * Fallback method for login when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<BasicAuthResponse> loginFallback(final BasicAuthRequest request, final Exception ex) {
        log.error("Basic auth login circuit breaker activated", ex);
        
        final BasicAuthResponse response = BasicAuthResponse.builder()
                .success(false)
                .message("Authentication service temporarily unavailable. Please try again later.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Fallback method for session validation when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<SessionValidationResponse> validateFallback(final String sessionId, final Exception ex) {
        log.error("Session validation circuit breaker activated", ex);
        
        final SessionValidationResponse response = SessionValidationResponse.builder()
                .valid(false)
                .message("Session validation service temporarily unavailable.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Fallback method for logout when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<LogoutResponse> logoutFallback(final String sessionId, final Exception ex) {
        log.error("Logout circuit breaker activated", ex);
        
        final LogoutResponse response = LogoutResponse.builder()
                .success(false)
                .message("Logout service temporarily unavailable.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Generates a session ID for basic authentication
     * In production, use a secure session management system
     * @return generated session identifier
     */
    private String generateSessionId() {
        return "BASIC_SESSION_" + System.currentTimeMillis() + "_" + 
               java.util.UUID.randomUUID().toString().substring(0, 8);
    }
    
    // Request/Response DTOs with validation
    
    /**
     * Request DTO for basic authentication login
     * Includes validation constraints for security
     */
    public record BasicAuthRequest(
            @NotBlank(message = "Username is required")
            @Size(min = 3, max = 255, message = "Username must be between 3 and 255 characters")
            String username,
            
            @NotBlank(message = "Password is required")
            @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
            String password
    ) {}
    
    /**
     * Response DTO for basic authentication
     * Contains authentication result and user information
     */
    @lombok.Builder
    public record BasicAuthResponse(
            boolean success,
            String message,
            String sessionId,
            String username,
            String email,
            java.util.Set<String> roles,
            java.time.Instant expiresAt
    ) {}
    
    /**
     * Response DTO for session validation
     * Contains session validity status
     */
    @lombok.Builder
    public record SessionValidationResponse(
            boolean valid,
            String message,
            String sessionId
    ) {}
    
    /**
     * Response DTO for logout operation
     * Contains logout operation result
     */
    @lombok.Builder
    public record LogoutResponse(
            boolean success,
            String message
    ) {}
}
