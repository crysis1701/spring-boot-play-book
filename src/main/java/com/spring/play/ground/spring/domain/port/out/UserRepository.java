package com.spring.play.ground.spring.domain.port.out;

import com.spring.play.ground.spring.domain.model.User;

import java.util.Optional;

/**
 * Outbound port for user data access
 * Defines contract for user persistence operations
 * Implementation will be in infrastructure layer
 */
public interface UserRepository {
    
    /**
     * Finds user by username
     * Used for authentication and user lookup
     * @param username the username to search for
     * @return Optional containing user if found, empty otherwise
     */
    Optional<User> findByUsername(String username);
    
    /**
     * Finds user by email address
     * Used for alternative authentication methods
     * @param email the email address to search for
     * @return Optional containing user if found, empty otherwise
     */
    Optional<User> findByEmail(String email);
    
    /**
     * Finds user by unique identifier
     * Used for token-based user lookup
     * @param userId the unique user identifier
     * @return Optional containing user if found, empty otherwise
     */
    Optional<User> findById(String userId);
    
    /**
     * Saves or updates user information
     * Used for user registration and profile updates
     * @param user the user to save or update
     * @return saved user with any generated fields populated
     */
    User save(User user);
    
    /**
     * Checks if username already exists in the system
     * Used for registration validation
     * @param username the username to check
     * @return true if username exists, false otherwise
     */
    boolean existsByUsername(String username);
    
    /**
     * Checks if email already exists in the system
     * Used for registration validation
     * @param email the email to check
     * @return true if email exists, false otherwise
     */
    boolean existsByEmail(String email);
    
    /**
     * Updates user's last login timestamp
     * Used for security auditing and monitoring
     * @param userId the user identifier
     * @param loginTime the login timestamp
     */
    void updateLastLogin(String userId, java.time.Instant loginTime);
}
