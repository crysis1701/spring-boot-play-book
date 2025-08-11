package com.spring.play.ground.spring.domain.model;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.Set;

/**
 * Domain model representing an authenticated user in the system
 * Immutable value object that contains user identity and metadata
 * Uses record syntax for concise, immutable data structure (Java 24 feature)
 */
@Value
@Builder
public class User {
    
    /**
     * Unique identifier for the user
     * Should be UUID or similar unique value
     */
    String userId;
    
    /**
     * Unique username for authentication
     * Must be validated for format and uniqueness
     */
    String username;
    
    /**
     * User's email address
     * Used for communication and alternative login
     */
    String email;
    
    /**
     * Hashed password for authentication
     * Never store plain text passwords
     */
    String passwordHash;
    
    /**
     * Set of roles assigned to the user
     * Used for authorization decisions
     */
    Set<String> roles;
    
    /**
     * Indicates if the user account is active
     * Disabled accounts cannot authenticate
     */
    boolean enabled;
    
    /**
     * Indicates if the user account is not locked
     * Locked accounts cannot authenticate until unlocked
     */
    boolean accountNonLocked;
    
    /**
     * Timestamp when the user was created
     * Used for auditing and account management
     */
    Instant createdAt;
    
    /**
     * Timestamp when the user last logged in
     * Used for security monitoring and account cleanup
     */
    Instant lastLoginAt;
    
    /**
     * Checks if user has a specific role
     * @param role the role name to check
     * @return true if user has the role, false otherwise
     */
    public boolean hasRole(final String role) {
        return roles != null && roles.contains(role);
    }
    
    /**
     * Checks if user account is valid for authentication
     * @return true if account can be used for login
     */
    public boolean isValidForAuthentication() {
        return enabled && accountNonLocked;
    }
}
