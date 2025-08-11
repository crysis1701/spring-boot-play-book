package com.spring.play.ground.spring.shared.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Security utility class for common cryptographic operations
 * Uses SecureRandom for cryptographically strong random number generation
 * All methods are static for ease of use across the application
 */
public final class SecurityUtils {
    
    // Use SecureRandom for cryptographically strong random numbers
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Private constructor to prevent instantiation of utility class
    private SecurityUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
    
    /**
     * Generates cryptographically strong random bytes
     * Used for creating secure tokens, salts, and secrets
     * @param length number of random bytes to generate
     * @return byte array containing random data
     */
    public static byte[] generateSecureRandomBytes(final int length) {
        final var randomBytes = new byte[length];
        SECURE_RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }
    
    /**
     * Generates base64-encoded secure random string
     * Useful for creating API keys, session tokens, etc.
     * @param byteLength number of random bytes before base64 encoding
     * @return base64-encoded random string
     */
    public static String generateSecureRandomString(final int byteLength) {
        final byte[] randomBytes = generateSecureRandomBytes(byteLength);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    /**
     * Safely compares two strings in constant time
     * Prevents timing attacks on sensitive string comparisons
     * @param expected the expected string value
     * @param actual the actual string value to compare
     * @return true if strings are equal, false otherwise
     */
    public static boolean safeEquals(final String expected, final String actual) {
        if (expected == null || actual == null) {
            return expected == actual;
        }
        
        if (expected.length() != actual.length()) {
            return false;
        }
        
        // Perform constant-time comparison to prevent timing attacks
        int result = 0;
        for (int i = 0; i < expected.length(); i++) {
            result |= expected.charAt(i) ^ actual.charAt(i);
        }
        
        return result == 0;
    }
}
