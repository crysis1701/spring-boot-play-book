package com.spring.play.ground.spring.infrastructure.configuration;

import com.spring.play.ground.spring.domain.port.in.AuthenticateUserUseCase;
import com.spring.play.ground.spring.domain.port.out.JwtTokenProvider;
import com.spring.play.ground.spring.domain.port.out.PasswordEncoder;
import com.spring.play.ground.spring.domain.port.out.UserRepository;
import com.spring.play.ground.spring.domain.service.AuthenticationDomainService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for domain services
 * Wires domain services with their dependencies
 * Keeps domain layer clean by handling dependency injection here
 */
@Configuration
public class DomainConfiguration {
    
    /**
     * Creates authentication domain service bean
     * Injects required dependencies for authentication use cases
     * @param userRepository repository for user data access
     * @param passwordEncoder encoder for password hashing and verification
     * @param jwtTokenProvider provider for JWT token operations
     * @return configured authentication domain service
     */
    @Bean
    public AuthenticateUserUseCase authenticateUserUseCase(
            final UserRepository userRepository,
            final PasswordEncoder passwordEncoder,
            final JwtTokenProvider jwtTokenProvider) {
        
        return new AuthenticationDomainService(
                userRepository,
                passwordEncoder,
                jwtTokenProvider
        );
    }
}
