package com.spring.play.ground.spring.infrastructure.adapter.out.external;

import com.spring.play.ground.spring.domain.port.out.PasswordEncoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Password encoder implementation using BCrypt algorithm
 * Provides secure password hashing with salt generation
 * Uses Spring Security's BCryptPasswordEncoder for proven security
 */
@Slf4j
@Component
public class BCryptPasswordEncoderAdapter implements PasswordEncoder {
    
    // BCrypt encoder with strength 12 for enhanced security
    private final BCryptPasswordEncoder bCryptEncoder;
    
    /**
     * Constructor initializing BCrypt with secure strength level
     * Strength 12 provides good security-performance balance
     */
    public BCryptPasswordEncoderAdapter() {
        // Use strength 12 for enhanced security (default is 10)
        this.bCryptEncoder = new BCryptPasswordEncoder(12);
        log.info("BCrypt password encoder initialized with strength level 12");
    }
    
    /**
     * Hashes plain text password using BCrypt algorithm
     * Generates unique salt for each password to prevent rainbow table attacks
     * @param plainPassword the plain text password to hash
     * @return securely hashed password with embedded salt
     */
    @Override
    public String encode(final String plainPassword) {
        // Validate input parameter
        if (plainPassword == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        
        log.debug("Encoding password with BCrypt algorithm");
        
        // BCrypt automatically generates salt and includes it in the hash
        final String hashedPassword = bCryptEncoder.encode(plainPassword);
        
        // Clear sensitive data from memory (best effort)
        // Note: This doesn't guarantee clearance due to String immutability
        // For maximum security, use char[] instead of String
        
        return hashedPassword;
    }
    
    /**
     * Verifies plain text password against BCrypt hash
     * Uses constant-time comparison to prevent timing attacks
     * @param plainPassword the plain text password to verify
     * @param hashedPassword the stored BCrypt hash
     * @return true if passwords match, false otherwise
     */
    @Override
    public boolean matches(final String plainPassword, final String hashedPassword) {
        // Validate input parameters
        if (plainPassword == null || hashedPassword == null) {
            log.debug("Password verification failed: null parameters provided");
            return false;
        }
        
        // Validate hash format (BCrypt hashes start with $2a$, $2b$, or $2y$)
        if (!isValidBCryptHash(hashedPassword)) {
            log.warn("Invalid BCrypt hash format provided for verification");
            return false;
        }
        
        try {
            // BCrypt handles salt extraction and comparison internally
            final boolean matches = bCryptEncoder.matches(plainPassword, hashedPassword);
            
            if (!matches) {
                log.debug("Password verification failed: passwords do not match");
            }
            
            return matches;
        } catch (final Exception e) {
            log.error("Error during password verification", e);
            return false;
        }
    }
    
    /**
     * Checks if password hash needs to be upgraded to newer algorithm
     * BCrypt hashes generally don't need upgrading unless strength changes
     * @param hashedPassword the current password hash
     * @return true if hash should be upgraded, false otherwise
     */
    @Override
    public boolean upgradeEncoding(final String hashedPassword) {
        if (hashedPassword == null || !isValidBCryptHash(hashedPassword)) {
            return true; // Invalid hashes should be upgraded
        }
        
        try {
            // Extract strength from BCrypt hash format: $2a$strength$salt+hash
            final String[] parts = hashedPassword.split("\\$");
            if (parts.length >= 3) {
                final int currentStrength = Integer.parseInt(parts[2]);
                // Upgrade if current strength is less than our target strength (12)
                return currentStrength < 12;
            }
        } catch (final NumberFormatException e) {
            log.debug("Could not parse BCrypt strength from hash, recommending upgrade");
            return true;
        }
        
        return false;
    }
    
    /**
     * Validates BCrypt hash format
     * Checks if hash follows BCrypt format: $2[a|b|y]$rounds$salt+hash
     * @param hash the hash string to validate
     * @return true if hash appears to be valid BCrypt format
     */
    private boolean isValidBCryptHash(final String hash) {
        // BCrypt hashes have specific format and length requirements
        if (hash == null || hash.length() < 60) {
            return false;
        }
        
        // Check for BCrypt prefix patterns
        return hash.startsWith("$2a$") || 
               hash.startsWith("$2b$") || 
               hash.startsWith("$2y$");
    }
}
