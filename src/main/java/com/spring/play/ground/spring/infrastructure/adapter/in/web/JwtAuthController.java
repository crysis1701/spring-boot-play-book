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
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
 * REST controller for JWT Authentication endpoints
 * Handles JSON Web Token-based authentication for stateless APIs
 * Implements circuit breaker pattern for resilience and fault tolerance
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/jwt")
@RequiredArgsConstructor
@Validated
@Tag(name = "JWT Authentication", description = "JWT-based authentication endpoints with access/refresh tokens")
public class JwtAuthController {
    
    // Domain use case for authentication operations
    private final AuthenticateUserUseCase authenticateUserUseCase;
    
    /**
     * Authenticates user and returns JWT tokens
     * Provides access token for API calls and refresh token for token renewal
     * 
     * @param request authentication credentials with validation
     * @return JWT authentication response with tokens and user info
     */
    @Operation(
            summary = "Authenticate with JWT",
            description = """
                    Authenticates user credentials and returns JWT access/refresh tokens.
                    
                    **Use this endpoint to get JWT tokens for API access.**
                    
                    The response includes:
                    - Access token (expires in 15 minutes)
                    - Refresh token (expires in 7 days)
                    - User information and roles
                    """,
            tags = {"JWT Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentication successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtAuthResponse.class),
                            examples = @ExampleObject(
                                    name = "Successful JWT Login",
                                    value = """
                                            {
                                              "success": true,
                                              "message": "JWT authentication successful",
                                              "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                              "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                              "tokenType": "Bearer",
                                              "expiresAt": "2025-08-11T11:58:00Z",
                                              "username": "jwtuser",
                                              "email": "jwt@example.com",
                                              "roles": ["USER", "JWT_TEST"]
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
                                              "message": "JWT authentication failed: Invalid username or password"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "503",
                    description = "Service unavailable (Circuit breaker open)",
                    content = @Content(mediaType = "application/json")
            )
    })
    @PostMapping("/login")
    @CircuitBreaker(name = "jwt-auth", fallbackMethod = "loginFallback")
    public ResponseEntity<JwtAuthResponse> login(
            @Valid @RequestBody 
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "JWT authentication credentials",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = JwtAuthRequest.class),
                            examples = @ExampleObject(
                                    name = "JWT Login Example",
                                    value = """
                                            {
                                              "username": "jwtuser",
                                              "password": "jwt123456"
                                            }
                                            """
                            )
                    )
            )
            final JwtAuthRequest request) {
        log.info("JWT authentication attempt for user: {}", request.username());
        
        try {
            // Create domain authentication request
            final AuthenticationRequest authRequest = AuthenticationRequest.builder()
                    .username(request.username())
                    .password(request.password())
                    .build();
            
            // Authenticate user using domain service
            final AuthenticationResponse authResponse = authenticateUserUseCase.authenticateJwt(authRequest);
            
            // Convert to web response
            final JwtAuthResponse response = JwtAuthResponse.builder()
                    .success(true)
                    .message("JWT authentication successful")
                    .accessToken(authResponse.getToken())
                    .refreshToken(authResponse.getRefreshToken())
                    .tokenType(authResponse.getTokenType())
                    .expiresAt(authResponse.getExpiresAt())
                    .username(authResponse.getUser().getUsername())
                    .email(authResponse.getUser().getEmail())
                    .roles(authResponse.getUser().getRoles())
                    .build();
            
            log.info("JWT authentication successful for user: {}", request.username());
            return ResponseEntity.ok(response);
            
        } catch (final AuthenticationException e) {
            log.warn("JWT authentication failed for user: {} - {}", request.username(), e.getMessage());
            
            final JwtAuthResponse errorResponse = JwtAuthResponse.builder()
                    .success(false)
                    .message("JWT authentication failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    /**
     * Refreshes JWT access token using refresh token
     * Allows clients to obtain new access tokens without re-authentication
     * 
     * @param request refresh token request
     * @return new JWT tokens
     */
    @Operation(
            summary = "Refresh JWT Access Token",
            description = """
                    Refreshes the JWT access token using a valid refresh token.
                    
                    **Use this endpoint to get a new access token without re-authentication.**
                    
                    The response includes:
                    - New access token with extended expiration
                    - New refresh token (rotated for security)
                    - Updated token expiration time
                    - User information
                    """,
            tags = {"JWT Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refresh successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtAuthResponse.class),
                            examples = @ExampleObject(
                                    name = "Successful Token Refresh",
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Token refresh successful",
                                              "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                              "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                              "tokenType": "Bearer",
                                              "expiresAt": "2025-08-11T11:45:00Z",
                                              "username": "jwtuser",
                                              "email": "jwt@example.com",
                                              "roles": ["USER", "JWT_TEST"]
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Refresh token is invalid or expired",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtAuthResponse.class),
                            examples = @ExampleObject(
                                    name = "Invalid Refresh Token",
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Token refresh failed: Refresh token expired or invalid"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/refresh")
    @CircuitBreaker(name = "jwt-auth", fallbackMethod = "refreshFallback")
    public ResponseEntity<JwtAuthResponse> refreshToken(
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Refresh token request",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = RefreshTokenRequest.class),
                            examples = @ExampleObject(
                                    name = "Refresh Token Request",
                                    value = """
                                            {
                                              "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                            }
                                            """
                            )
                    )
            )
            final RefreshTokenRequest request) {
        log.debug("JWT token refresh attempt");
        
        try {
            // Refresh token using domain service
            final AuthenticationResponse authResponse = authenticateUserUseCase.refreshToken(request.refreshToken());
            
            // Convert to web response
            final JwtAuthResponse response = JwtAuthResponse.builder()
                    .success(true)
                    .message("Token refresh successful")
                    .accessToken(authResponse.getToken())
                    .refreshToken(authResponse.getRefreshToken())
                    .tokenType(authResponse.getTokenType())
                    .expiresAt(authResponse.getExpiresAt())
                    .username(authResponse.getUser().getUsername())
                    .email(authResponse.getUser().getEmail())
                    .roles(authResponse.getUser().getRoles())
                    .build();
            
            log.info("JWT token refresh successful for user: {}", authResponse.getUser().getUsername());
            return ResponseEntity.ok(response);
            
        } catch (final AuthenticationException e) {
            log.warn("JWT token refresh failed: {}", e.getMessage());
            
            final JwtAuthResponse errorResponse = JwtAuthResponse.builder()
                    .success(false)
                    .message("Token refresh failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    /**
     * Validates JWT access token
     * Checks if token is valid, not expired, and properly signed
     * 
     * @param authorization the Authorization header with Bearer token
     * @return token validation response
     */
    @Operation(
            summary = "Validate JWT Access Token",
            description = """
                    Validates the JWT access token for authenticity and expiration.
                    
                    **Use this endpoint to verify if a JWT token is still valid.**
                    
                    The response includes:
                    - Token validity status
                    - Username associated with the token
                    - Validation message
                    """,
            tags = {"JWT Authentication"},
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token validation result",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TokenValidationResponse.class),
                            examples = {
                                    @ExampleObject(
                                            name = "Valid Token",
                                            value = """
                                                    {
                                                      "valid": true,
                                                      "message": "Token is valid",
                                                      "username": "jwtuser"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Invalid Token",
                                            value = """
                                                    {
                                                      "valid": false,
                                                      "message": "Token validation failed: Token expired or invalid"
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Token is invalid or malformed",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TokenValidationResponse.class),
                            examples = @ExampleObject(
                                    name = "Token Validation Error",
                                    value = """
                                            {
                                              "valid": false,
                                              "message": "Token validation failed: Malformed token"
                                            }
                                            """
                            )
                    )
            )
    })
    @GetMapping("/validate")
    @CircuitBreaker(name = "jwt-auth", fallbackMethod = "validateFallback")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Parameter(
                    description = "Bearer token in Authorization header",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            )
            @RequestHeader("Authorization") @NotBlank final String authorization) {
        
        log.debug("JWT token validation request");
        
        try {
            // Extract token from Authorization header
            final String token = extractTokenFromHeader(authorization);
            
            // Validate token using domain service
            final boolean isValid = authenticateUserUseCase.validateToken(token);
            
            if (isValid) {
                // Extract username from valid token
                final String username = authenticateUserUseCase.extractUsernameFromToken(token);
                
                final TokenValidationResponse response = TokenValidationResponse.builder()
                        .valid(true)
                        .message("Token is valid")
                        .username(username)
                        .build();
                
                return ResponseEntity.ok(response);
            } else {
                final TokenValidationResponse errorResponse = TokenValidationResponse.builder()
                        .valid(false)
                        .message("Token is invalid or expired")
                        .build();
                
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
            
        } catch (final Exception e) {
            log.warn("JWT token validation failed: {}", e.getMessage());
            
            final TokenValidationResponse errorResponse = TokenValidationResponse.builder()
                    .valid(false)
                    .message("Token validation failed: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    /**
     * Protected endpoint demonstrating JWT authentication
     * Requires valid JWT token in Authorization header
     * 
     * @param authorization the Authorization header with Bearer token
     * @return protected resource response
     */
    @Operation(
            summary = "Access protected resource",
            description = """
                    Demonstrates JWT token-based access to protected resources.
                    
                    **🔒 Requires valid JWT token in Authorization header**
                    
                    Use this endpoint to test your JWT tokens after login.
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication"),
            tags = {"JWT Authentication"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Access granted to protected resource",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ProtectedResourceResponse.class),
                            examples = @ExampleObject(
                                    name = "Protected Resource Access",
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Access granted to protected resource",
                                              "username": "jwtuser",
                                              "timestamp": "2025-08-11T10:45:30Z",
                                              "resource": "Protected data for authenticated user"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or missing JWT token",
                    content = @Content(mediaType = "application/json")
            )
    })
    @GetMapping("/protected")
    @CircuitBreaker(name = "jwt-auth", fallbackMethod = "protectedFallback")
    public ResponseEntity<ProtectedResourceResponse> protectedResource(
            @Parameter(
                    description = "JWT Bearer token for authentication",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            )
            @RequestHeader("Authorization") @NotBlank final String authorization) {
        
        log.debug("Access to protected resource requested");
        
        try {
            // Extract and validate token
            final String token = extractTokenFromHeader(authorization);
            
            if (!authenticateUserUseCase.validateToken(token)) {
                throw new AuthenticationException("Invalid or expired token");
            }
            
            // Extract user information
            final String username = authenticateUserUseCase.extractUsernameFromToken(token);
            
            final ProtectedResourceResponse response = ProtectedResourceResponse.builder()
                    .success(true)
                    .message("Access granted to protected resource")
                    .username(username)
                    .timestamp(java.time.Instant.now())
                    .resource("Protected data for authenticated user")
                    .build();
            
            log.info("Protected resource access granted for user: {}", username);
            return ResponseEntity.ok(response);
            
        } catch (final Exception e) {
            log.warn("Protected resource access denied: {}", e.getMessage());
            
            final ProtectedResourceResponse errorResponse = ProtectedResourceResponse.builder()
                    .success(false)
                    .message("Access denied: " + e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }
    
    // Circuit breaker fallback methods
    
    /**
     * Fallback method for login when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<JwtAuthResponse> loginFallback(final JwtAuthRequest request, final Exception ex) {
        log.error("JWT auth login circuit breaker activated", ex);
        
        final JwtAuthResponse response = JwtAuthResponse.builder()
                .success(false)
                .message("JWT authentication service temporarily unavailable. Please try again later.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Fallback method for token refresh when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<JwtAuthResponse> refreshFallback(final RefreshTokenRequest request, final Exception ex) {
        log.error("JWT token refresh circuit breaker activated", ex);
        
        final JwtAuthResponse response = JwtAuthResponse.builder()
                .success(false)
                .message("Token refresh service temporarily unavailable.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Fallback method for token validation when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<TokenValidationResponse> validateFallback(final String authorization, final Exception ex) {
        log.error("JWT token validation circuit breaker activated", ex);
        
        final TokenValidationResponse response = TokenValidationResponse.builder()
                .valid(false)
                .message("Token validation service temporarily unavailable.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Fallback method for protected resource when circuit breaker is open
     * Returns service unavailable response
     */
    public ResponseEntity<ProtectedResourceResponse> protectedFallback(final String authorization, final Exception ex) {
        log.error("Protected resource circuit breaker activated", ex);
        
        final ProtectedResourceResponse response = ProtectedResourceResponse.builder()
                .success(false)
                .message("Protected resource service temporarily unavailable.")
                .build();
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
    
    /**
     * Extracts JWT token from Authorization header
     * Removes "Bearer " prefix and validates format
     * @param authorization the Authorization header value
     * @return extracted JWT token
     */
    private String extractTokenFromHeader(final String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new AuthenticationException("Invalid Authorization header format. Expected: Bearer <token>");
        }
        
        final String token = authorization.substring(7); // Remove "Bearer " prefix
        
        if (token.trim().isEmpty()) {
            throw new AuthenticationException("JWT token is empty");
        }
        
        return token.trim();
    }
    
    // Request/Response DTOs with validation
    
    /**
     * Request DTO for JWT authentication login
     * Includes validation constraints for security
     */
    public record JwtAuthRequest(
            @NotBlank(message = "Username is required")
            @Size(min = 3, max = 255, message = "Username must be between 3 and 255 characters")
            String username,
            
            @NotBlank(message = "Password is required")
            @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
            String password
    ) {}
    
    /**
     * Request DTO for JWT token refresh
     * Contains refresh token for obtaining new access token
     */
    public record RefreshTokenRequest(
            @NotBlank(message = "Refresh token is required")
            String refreshToken
    ) {}
    
    /**
     * Response DTO for JWT authentication
     * Contains JWT tokens and user information
     */
    @lombok.Builder
    public record JwtAuthResponse(
            boolean success,
            String message,
            String accessToken,
            String refreshToken,
            String tokenType,
            java.time.Instant expiresAt,
            String username,
            String email,
            java.util.Set<String> roles
    ) {}
    
    /**
     * Response DTO for JWT token validation
     * Contains token validity status and user info
     */
    @lombok.Builder
    public record TokenValidationResponse(
            boolean valid,
            String message,
            String username
    ) {}
    
    /**
     * Response DTO for protected resource access
     * Contains protected data and access confirmation
     */
    @lombok.Builder
    public record ProtectedResourceResponse(
            boolean success,
            String message,
            String username,
            java.time.Instant timestamp,
            String resource
    ) {}
}
