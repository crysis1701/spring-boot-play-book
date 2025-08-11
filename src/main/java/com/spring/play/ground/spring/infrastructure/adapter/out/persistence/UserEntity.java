package com.spring.play.ground.spring.infrastructure.adapter.out.persistence;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * JPA entity representing user data in the database
 * Maps domain User model to database table structure
 * Uses JPA annotations for ORM mapping
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_username", columnList = "username", unique = true),
    @Index(name = "idx_email", columnList = "email", unique = true)
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {
    
    /**
     * Primary key using UUID strategy
     * Provides better security than sequential IDs
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id", length = 36)
    private String userId;
    
    /**
     * Unique username for authentication
     * Indexed for fast lookup during login
     */
    @Column(name = "username", nullable = false, unique = true, length = 255)
    private String username;
    
    /**
     * User's email address
     * Indexed for alternative login and communication
     */
    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;
    
    /**
     * BCrypt hashed password
     * Never store plain text passwords
     */
    @Column(name = "password_hash", nullable = false, length = 60)
    private String passwordHash;
    
    /**
     * Comma-separated roles for the user
     * Stored as string for simplicity, could be normalized to separate table
     */
    @Column(name = "roles", length = 500)
    private String roles;
    
    /**
     * Account enabled status
     * Disabled accounts cannot authenticate
     */
    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;
    
    /**
     * Account lock status
     * Locked accounts cannot authenticate until unlocked
     */
    @Column(name = "account_non_locked", nullable = false)
    @Builder.Default
    private Boolean accountNonLocked = true;
    
    /**
     * Account creation timestamp
     * Automatically set when entity is persisted
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    
    /**
     * Last successful login timestamp
     * Updated on each successful authentication
     */
    @Column(name = "last_login_at")
    private Instant lastLoginAt;
    
    /**
     * Automatically set creation timestamp before persist
     * JPA lifecycle callback for audit trail
     */
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
