package com.spring.play.ground.spring.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Configuration
 * Configures security rules for different endpoints
 * Allows public access to Swagger UI and documentation endpoints
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    /**
     * Configure HTTP security with custom rules
     * - Allow public access to Swagger UI and OpenAPI documentation
     * - Allow public access to H2 console for development
     * - Allow public access to authentication endpoints
     * - Allow public access to actuator health endpoint
     * - Protect all other endpoints
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("Configuring Spring Security with custom rules");
        
        http
            // Disable CSRF for API endpoints (needed for REST APIs)
            .csrf(AbstractHttpConfigurer::disable)
            
            // Configure session management (stateless for JWT, stateful for basic auth)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )
            
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Allow public access to Swagger UI and OpenAPI documentation
                .requestMatchers(
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**",
                    "/api-docs/**",
                    "/v3/api-docs.yaml",
                    "/swagger-resources/**",
                    "/webjars/**"
                ).permitAll()
                
                // Allow public access to H2 console for development
                .requestMatchers("/h2-console/**").permitAll()
                
                // Allow public access to authentication endpoints
                .requestMatchers(
                    "/api/jwt-auth/login",
                    "/api/jwt-auth/refresh",
                    "/api/basic-auth/login"
                ).permitAll()
                
                // Allow public access to actuator health endpoint
                .requestMatchers("/actuator/health").permitAll()
                
                // Allow public access to root and error pages
                .requestMatchers("/", "/error", "/favicon.ico").permitAll()
                
                // Protect all other endpoints - require authentication
                .anyRequest().authenticated()
            )
            
            // Configure HTTP Basic authentication (for basic auth endpoints)
            .httpBasic(basic -> basic.realmName("Spring Authentication Demo"))
            
            // Configure form login (disabled for API-first approach)
            .formLogin(AbstractHttpConfigurer::disable)
            
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );

        // Allow frames for H2 console (development only)
        http.headers(headers -> headers
            .frameOptions(frameOptions -> frameOptions.sameOrigin())
        );

        log.info("Spring Security configuration completed");
        return http.build();
    }
}
