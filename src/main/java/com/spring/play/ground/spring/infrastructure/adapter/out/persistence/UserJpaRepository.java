package com.spring.play.ground.spring.infrastructure.adapter.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

/**
 * Spring Data JPA repository for UserEntity operations
 * Provides database access methods with automatic implementation
 * Uses method naming conventions and custom queries
 */
@Repository
public interface UserJpaRepository extends JpaRepository<UserEntity, String> {
    
    /**
     * Finds user by username (case-insensitive)
     * Used for authentication and user lookup
     * @param username the username to search for
     * @return Optional containing user entity if found
     */
    @Query("SELECT u FROM UserEntity u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<UserEntity> findByUsernameIgnoreCase(@Param("username") String username);
    
    /**
     * Finds user by email address (case-insensitive)
     * Used for alternative authentication methods
     * @param email the email address to search for
     * @return Optional containing user entity if found
     */
    @Query("SELECT u FROM UserEntity u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<UserEntity> findByEmailIgnoreCase(@Param("email") String email);
    
    /**
     * Checks if username exists (case-insensitive)
     * Used for registration validation
     * @param username the username to check
     * @return true if username exists, false otherwise
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM UserEntity u WHERE LOWER(u.username) = LOWER(:username)")
    boolean existsByUsernameIgnoreCase(@Param("username") String username);
    
    /**
     * Checks if email exists (case-insensitive)
     * Used for registration validation
     * @param email the email to check
     * @return true if email exists, false otherwise
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM UserEntity u WHERE LOWER(u.email) = LOWER(:email)")
    boolean existsByEmailIgnoreCase(@Param("email") String email);
    
    /**
     * Updates user's last login timestamp
     * Custom update query for performance (avoids full entity update)
     * @param userId the user identifier
     * @param lastLoginAt the login timestamp
     */
    @Modifying
    @Query("UPDATE UserEntity u SET u.lastLoginAt = :lastLoginAt WHERE u.userId = :userId")
    void updateLastLoginAt(@Param("userId") String userId, @Param("lastLoginAt") Instant lastLoginAt);
    
    /**
     * Finds enabled users only
     * Used for security checks and user management
     * @param enabled the enabled status to filter by
     * @return list of enabled user entities
     */
    @Query("SELECT u FROM UserEntity u WHERE u.enabled = :enabled")
    java.util.List<UserEntity> findByEnabled(@Param("enabled") Boolean enabled);
    
    /**
     * Finds users created after specific timestamp
     * Used for analytics and user management
     * @param createdAfter the timestamp to filter by
     * @return list of recently created users
     */
    @Query("SELECT u FROM UserEntity u WHERE u.createdAt > :createdAfter ORDER BY u.createdAt DESC")
    java.util.List<UserEntity> findUsersCreatedAfter(@Param("createdAfter") Instant createdAfter);
}
