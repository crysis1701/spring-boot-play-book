package com.spring.play.ground.spring.infrastructure.adapter.out.persistence;

import com.spring.play.ground.spring.domain.model.User;
import com.spring.play.ground.spring.domain.port.out.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * User repository adapter implementing domain port
 * Bridges between domain and JPA infrastructure
 * Handles entity-model conversion and database operations
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserRepositoryAdapter implements UserRepository {
    
    // JPA repository for database operations
    private final UserJpaRepository jpaRepository;
    
    /**
     * Finds user by username with case-insensitive search
     * Converts JPA entity to domain model
     * @param username the username to search for
     * @return Optional containing domain user if found
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(final String username) {
        log.debug("Finding user by username: {}", username);
        
        // Validate input parameter
        if (username == null || username.trim().isEmpty()) {
            log.debug("Username is null or empty, returning empty result");
            return Optional.empty();
        }
        
        // Query database and convert to domain model
        return jpaRepository.findByUsernameIgnoreCase(username.trim())
                .map(this::toDomainModel);
    }
    
    /**
     * Finds user by email with case-insensitive search
     * Converts JPA entity to domain model
     * @param email the email address to search for
     * @return Optional containing domain user if found
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(final String email) {
        log.debug("Finding user by email: {}", email);
        
        // Validate input parameter
        if (email == null || email.trim().isEmpty()) {
            log.debug("Email is null or empty, returning empty result");
            return Optional.empty();
        }
        
        // Query database and convert to domain model
        return jpaRepository.findByEmailIgnoreCase(email.trim())
                .map(this::toDomainModel);
    }
    
    /**
     * Finds user by unique identifier
     * Converts JPA entity to domain model
     * @param userId the unique user identifier
     * @return Optional containing domain user if found
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<User> findById(final String userId) {
        log.debug("Finding user by ID: {}", userId);
        
        // Validate input parameter
        if (userId == null || userId.trim().isEmpty()) {
            log.debug("User ID is null or empty, returning empty result");
            return Optional.empty();
        }
        
        // Query database and convert to domain model
        return jpaRepository.findById(userId.trim())
                .map(this::toDomainModel);
    }
    
    /**
     * Saves or updates user information
     * Converts domain model to JPA entity and persists
     * @param user the domain user to save
     * @return saved domain user with populated fields
     */
    @Override
    @Transactional
    public User save(final User user) {
        log.debug("Saving user: {}", user != null ? user.getUsername() : "null");
        
        // Validate input parameter
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        
        // Convert to entity and save
        final UserEntity entity = toEntity(user);
        final UserEntity savedEntity = jpaRepository.save(entity);
        
        log.info("User saved successfully: {}", savedEntity.getUsername());
        
        // Convert back to domain model
        return toDomainModel(savedEntity);
    }
    
    /**
     * Checks if username already exists (case-insensitive)
     * Used for registration validation
     * @param username the username to check
     * @return true if username exists, false otherwise
     */
    @Override
    @Transactional(readOnly = true)
    public boolean existsByUsername(final String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }
        
        final boolean exists = jpaRepository.existsByUsernameIgnoreCase(username.trim());
        log.debug("Username '{}' exists: {}", username, exists);
        
        return exists;
    }
    
    /**
     * Checks if email already exists (case-insensitive)
     * Used for registration validation
     * @param email the email to check
     * @return true if email exists, false otherwise
     */
    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmail(final String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        
        final boolean exists = jpaRepository.existsByEmailIgnoreCase(email.trim());
        log.debug("Email '{}' exists: {}", email, exists);
        
        return exists;
    }
    
    /**
     * Updates user's last login timestamp
     * Optimized update query for performance
     * @param userId the user identifier
     * @param loginTime the login timestamp
     */
    @Override
    @Transactional
    public void updateLastLogin(final String userId, final Instant loginTime) {
        log.debug("Updating last login for user ID: {}", userId);
        
        // Validate input parameters
        if (userId == null || userId.trim().isEmpty()) {
            log.warn("Cannot update last login: user ID is null or empty");
            return;
        }
        
        if (loginTime == null) {
            log.warn("Cannot update last login: login time is null");
            return;
        }
        
        try {
            // Use optimized update query
            jpaRepository.updateLastLoginAt(userId.trim(), loginTime);
            log.debug("Last login updated successfully for user ID: {}", userId);
        } catch (final Exception e) {
            log.error("Failed to update last login for user ID: {}", userId, e);
            throw e;
        }
    }
    
    /**
     * Converts JPA entity to domain model
     * Handles role parsing and field mapping
     * @param entity the JPA entity to convert
     * @return domain user model
     */
    private User toDomainModel(final UserEntity entity) {
        if (entity == null) {
            return null;
        }
        
        // Parse roles from comma-separated string
        final Set<String> roles = parseRoles(entity.getRoles());
        
        return User.builder()
                .userId(entity.getUserId())
                .username(entity.getUsername())
                .email(entity.getEmail())
                .passwordHash(entity.getPasswordHash())
                .roles(roles)
                .enabled(entity.getEnabled())
                .accountNonLocked(entity.getAccountNonLocked())
                .createdAt(entity.getCreatedAt())
                .lastLoginAt(entity.getLastLoginAt())
                .build();
    }
    
    /**
     * Converts domain model to JPA entity
     * Handles role serialization and field mapping
     * @param user the domain user to convert
     * @return JPA entity
     */
    private UserEntity toEntity(final User user) {
        if (user == null) {
            return null;
        }
        
        // Serialize roles to comma-separated string
        final String rolesString = serializeRoles(user.getRoles());
        
        return UserEntity.builder()
                .userId(user.getUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .passwordHash(user.getPasswordHash())
                .roles(rolesString)
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }
    
    /**
     * Parses comma-separated roles string into Set
     * Handles null and empty strings gracefully
     * @param rolesString comma-separated roles
     * @return set of role strings
     */
    private Set<String> parseRoles(final String rolesString) {
        if (rolesString == null || rolesString.trim().isEmpty()) {
            return new HashSet<>();
        }
        
        // Split by comma and trim whitespace
        return new HashSet<>(Arrays.asList(rolesString.split(","))
                .stream()
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .toList());
    }
    
    /**
     * Serializes role set to comma-separated string
     * Handles null and empty sets gracefully
     * @param roles set of role strings
     * @return comma-separated roles string
     */
    private String serializeRoles(final Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return null;
        }
        
        // Join roles with comma separator
        return String.join(",", roles);
    }
}
