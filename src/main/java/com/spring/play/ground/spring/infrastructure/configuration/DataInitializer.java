package com.spring.play.ground.spring.infrastructure.configuration;

import com.spring.play.ground.spring.domain.model.User;
import com.spring.play.ground.spring.domain.port.out.PasswordEncoder;
import com.spring.play.ground.spring.domain.port.out.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Set;

/**
 * Data initialization component for development and testing
 * Creates default users with different roles for testing authentication methods
 * Runs after application startup to populate the database
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {
    
    // Dependencies for user creation
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Initializes test data after application startup
     * Creates sample users with different roles and permissions
     * Only runs if users don't already exist to avoid duplicates
     * 
     * @param args application startup arguments
     */
    @Override
    public void run(final ApplicationArguments args) {
        log.info("Starting data initialization...");
        
        try {
            // Create admin user if not exists
            createUserIfNotExists(
                    "admin",
                    "admin@example.com",
                    "admin123",
                    Set.of("ADMIN", "USER")
            );
            
            // Create regular user if not exists
            createUserIfNotExists(
                    "user",
                    "user@example.com",
                    "user123",
                    Set.of("USER")
            );
            
            // Create manager user if not exists
            createUserIfNotExists(
                    "manager",
                    "manager@example.com",
                    "manager123",
                    Set.of("MANAGER", "USER")
            );
            
            // Create test user for JWT testing
            createUserIfNotExists(
                    "jwtuser",
                    "jwt@example.com",
                    "jwt123456",
                    Set.of("USER", "JWT_TEST")
            );
            
            // Create test user for basic auth testing
            createUserIfNotExists(
                    "basicuser",
                    "basic@example.com",
                    "basic123456",
                    Set.of("USER", "BASIC_TEST")
            );
            
            log.info("Data initialization completed successfully");
            
        } catch (final Exception e) {
            log.error("Data initialization failed", e);
            throw new RuntimeException("Failed to initialize test data", e);
        }
    }
    
    /**
     * Creates a user if it doesn't already exist
     * Checks for existing username and email to avoid duplicates
     * 
     * @param username the username for the new user
     * @param email the email address for the new user
     * @param plainPassword the plain text password (will be hashed)
     * @param roles the set of roles to assign to the user
     */
    private void createUserIfNotExists(
            final String username,
            final String email,
            final String plainPassword,
            final Set<String> roles) {
        
        // Check if user already exists by username or email
        if (userRepository.existsByUsername(username)) {
            log.debug("User with username '{}' already exists, skipping creation", username);
            return;
        }
        
        if (userRepository.existsByEmail(email)) {
            log.debug("User with email '{}' already exists, skipping creation", email);
            return;
        }
        
        try {
            // Hash the password securely
            final String hashedPassword = passwordEncoder.encode(plainPassword);
            
            // Create user domain model
            final User user = User.builder()
                    .username(username)
                    .email(email)
                    .passwordHash(hashedPassword)
                    .roles(roles)
                    .enabled(true)
                    .accountNonLocked(true)
                    .createdAt(Instant.now())
                    .build();
            
            // Save user to repository
            final User savedUser = userRepository.save(user);
            
            log.info("Created user: {} with roles: {}", savedUser.getUsername(), roles);
            
        } catch (final Exception e) {
            log.error("Failed to create user: {}", username, e);
            throw new RuntimeException("Failed to create user: " + username, e);
        }
    }
}
