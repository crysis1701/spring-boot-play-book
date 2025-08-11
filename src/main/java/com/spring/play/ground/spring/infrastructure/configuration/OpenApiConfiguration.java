package com.spring.play.ground.spring.infrastructure.configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI/Swagger configuration for REST API documentation
 * Provides interactive API documentation with authentication support
 * Includes JWT Bearer token and Basic Authentication security schemes
 */
@Configuration
public class OpenApiConfiguration {
    
    /**
     * Creates OpenAPI configuration bean with comprehensive API documentation
     * Includes API info, security schemes, and server configuration
     * 
     * @return configured OpenAPI instance
     */
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(createApiInfo())
                .servers(createServers())
                .addSecurityItem(createJwtSecurityRequirement())
                .addSecurityItem(createBasicSecurityRequirement())
                .schemaRequirement("Bearer Authentication", createJwtSecurityScheme())
                .schemaRequirement("Basic Authentication", createBasicSecurityScheme());
    }
    
    /**
     * Creates API information metadata
     * Includes title, description, version, and contact details
     * 
     * @return API info configuration
     */
    private Info createApiInfo() {
        return new Info()
                .title("Spring Boot Authentication Demo API")
                .description("""
                        🔐 **Comprehensive Authentication Methods Demo**
                        
                        This API demonstrates **9 different authentication methods** in Spring Boot using **Hexagonal Architecture**.
                        
                        ## 🎯 **Available Authentication Methods:**
                        
                        ### ✅ **Currently Implemented:**
                        1. **Basic Authentication** - Session-based with username/password
                        2. **JWT Authentication** - JSON Web Tokens with refresh capability
                        
                        ### 🔧 **Coming Soon:**
                        3. **OAuth 2.0** - External provider integration
                        4. **LDAP Authentication** - Enterprise directory
                        5. **SAML 2.0** - Single Sign-On
                        6. **Database Authentication** - Custom user store
                        7. **In-Memory Authentication** - Development/testing
                        8. **Form-Based Authentication** - Web applications
                        9. **Custom Authentication** - Legacy system integration
                        
                        ## 🚀 **Key Features:**
                        - **Circuit Breaker Pattern** for resilience
                        - **BCrypt Password Hashing** (strength 12)
                        - **JWT with HMAC-SHA256** signing
                        - **Input Validation** and sanitization
                        - **Comprehensive Error Handling**
                        - **Hexagonal Architecture** for clean separation
                        
                        ## 🧪 **Test Users:**
                        | Username | Password | Roles |
                        |----------|----------|-------|
                        | admin | admin123 | ADMIN, USER |
                        | user | user123 | USER |
                        | manager | manager123 | MANAGER, USER |
                        | jwtuser | jwt123456 | USER, JWT_TEST |
                        | basicuser | basic123456 | USER, BASIC_TEST |
                        
                        ## 📋 **How to Use:**
                        1. **For JWT Authentication:**
                           - Use `/api/auth/jwt/login` to get access token
                           - Copy the `accessToken` from response
                           - Click 🔒 **Authorize** button above
                           - Enter: `Bearer <your-access-token>`
                           - Test protected endpoints
                        
                        2. **For Basic Authentication:**
                           - Use `/api/auth/basic/login` to get session
                           - Use the session ID in subsequent requests
                        
                        ## 🛡️ **Security Features:**
                        - **Password Security**: BCrypt with strength 12
                        - **JWT Security**: HMAC-SHA256 signing with configurable expiration
                        - **Input Validation**: Bean validation with custom constraints
                        - **Error Handling**: Security-aware error messages
                        - **Circuit Breaker**: Protection against service failures
                        """)
                .version("1.0.0")
                .contact(createContact())
                .license(createLicense());
    }
    
    /**
     * Creates contact information for API documentation
     * 
     * @return contact configuration
     */
    private Contact createContact() {
        return new Contact()
                .name("Spring Boot Learning Team")
                .email("developer@springboot-demo.com")
                .url("https://github.com/your-repo/spring-authentication-demo");
    }
    
    /**
     * Creates license information for API documentation
     * 
     * @return license configuration
     */
    private License createLicense() {
        return new License()
                .name("MIT License")
                .url("https://opensource.org/licenses/MIT");
    }
    
    /**
     * Creates server configurations for different environments
     * 
     * @return list of server configurations
     */
    private List<Server> createServers() {
        return List.of(
                new Server()
                        .url("http://localhost:8080")
                        .description("Development Server"),
                new Server()
                        .url("https://your-staging-url.com")
                        .description("Staging Server"),
                new Server()
                        .url("https://your-production-url.com")
                        .description("Production Server")
        );
    }
    
    /**
     * Creates JWT Bearer token security requirement
     * Used for JWT-based endpoint authentication
     * 
     * @return JWT security requirement
     */
    private SecurityRequirement createJwtSecurityRequirement() {
        return new SecurityRequirement()
                .addList("Bearer Authentication");
    }
    
    /**
     * Creates Basic Authentication security requirement
     * Used for basic authentication endpoints
     * 
     * @return Basic auth security requirement
     */
    private SecurityRequirement createBasicSecurityRequirement() {
        return new SecurityRequirement()
                .addList("Basic Authentication");
    }
    
    /**
     * Creates JWT Bearer token security scheme configuration
     * Defines how JWT tokens should be provided in requests
     * 
     * @return JWT security scheme
     */
    private SecurityScheme createJwtSecurityScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("""
                        **JWT Bearer Token Authentication**
                        
                        🔐 **How to get a token:**
                        1. Use the `/api/auth/jwt/login` endpoint with valid credentials
                        2. Copy the `accessToken` from the response
                        3. Click the 🔒 **Authorize** button above
                        4. Enter: `Bearer <your-access-token>`
                        
                        **Example:**
                        ```
                        Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
                        ```
                        
                        ⏰ **Token expires in 15 minutes** - use refresh token to get a new one
                        """);
    }
    
    /**
     * Creates Basic Authentication security scheme configuration
     * Defines how basic auth credentials should be provided
     * 
     * @return Basic auth security scheme
     */
    private SecurityScheme createBasicSecurityScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("basic")
                .description("""
                        **Basic Authentication**
                        
                        🔐 **How to authenticate:**
                        1. Use the `/api/auth/basic/login` endpoint to get a session
                        2. Use the returned session ID in subsequent requests
                        
                        **Note:** This is primarily for demonstration purposes.
                        In production, prefer JWT or OAuth 2.0 for API authentication.
                        """);
    }
    
    /**
     * Group JWT Authentication endpoints
     */
    @Bean
    public GroupedOpenApi jwtAuthApi() {
        return GroupedOpenApi.builder()
                .group("jwt-authentication")
                .displayName("JWT Authentication")
                .pathsToMatch("/api/auth/jwt/**")
                .build();
    }

    /**
     * Group Basic Authentication endpoints
     */
    @Bean
    public GroupedOpenApi basicAuthApi() {
        return GroupedOpenApi.builder()
                .group("basic-authentication") 
                .displayName("Basic Authentication")
                .pathsToMatch("/api/auth/basic/**")
                .build();
    }

    /**
     * Group all authentication endpoints
     */
    @Bean
    public GroupedOpenApi allAuthApi() {
        return GroupedOpenApi.builder()
                .group("all-authentication")
                .displayName("All Authentication APIs")
                .pathsToMatch("/api/**")
                .build();
    }
}
