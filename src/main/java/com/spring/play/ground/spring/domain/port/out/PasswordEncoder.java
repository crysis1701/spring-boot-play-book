package com.spring.play.ground.spring.domain.port.out;

/**
 * Outbound port for password hashing operations
 * Defines contract for secure password handling
 * Implementation will be in infrastructure layer using BCrypt or similar
 */
public interface PasswordEncoder {
    
    /**
     * Hashes a plain text password using secure algorithm
     * Uses salted hashing to prevent rainbow table attacks
     * @param plainPassword the plain text password to hash
     * @return securely hashed password
     */
    String encode(String plainPassword);
    
    /**
     * Verifies plain text password against hashed password
     * Uses constant-time comparison to prevent timing attacks
     * @param plainPassword the plain text password to verify
     * @param hashedPassword the stored hashed password
     * @return true if passwords match, false otherwise
     */
    boolean matches(String plainPassword, String hashedPassword);
    
    /**
     * Checks if password hash needs to be upgraded
     * Used when security requirements change over time
     * @param hashedPassword the current password hash
     * @return true if hash should be upgraded to stronger algorithm
     */
    boolean upgradeEncoding(String hashedPassword);
}
