# 📚 Episode 1: Spring Boot Authentication Deep Dive

## 🔐 Spring Boot Authentication Methods Demo

This project demonstrates **9 different authentication methods** in Spring Boot using **Hexagonal Architecture**, **Java 21**, and modern security practices.

## 🏗️ Architecture Overview

```
📁 Authentication Demo Structure
├── 🎯 Domain Layer (Pure Business Logic)
│   ├── models/ (User, AuthenticationRequest, AuthenticationResponse)
│   ├── services/ (AuthenticationDomainService)
│   └── ports/ (in: use cases, out: dependencies)
├── 🔌 Infrastructure Layer (Framework Code)
│   ├── adapters/in/web/ (REST Controllers)
│   ├── adapters/out/persistence/ (JPA Repositories)
│   ├── adapters/out/external/ (JWT, BCrypt)
│   └── configuration/ (Spring Configuration)
└── 🤝 Shared Layer (Cross-cutting concerns)
    ├── exceptions/ (Custom exceptions)
    └── utils/ (Security utilities)
```

## 🔐 Authentication Methods Implemented

### ✅ **1. Basic Authentication**
- **Endpoint**: `/api/auth/basic/login`
- **Method**: Session-based with username/password
- **Features**: Circuit breaker, validation, session management

### ✅ **2. JWT Authentication** 
- **Endpoint**: `/api/auth/jwt/login`
- **Method**: JSON Web Tokens with refresh capability
- **Features**: Access/refresh tokens, circuit breaker, protected endpoints

### 🔧 **Coming Next** (Ready for implementation):
3. **OAuth 2.0** - External provider integration
4. **LDAP Authentication** - Enterprise directory
5. **SAML 2.0** - Single Sign-On
6. **Database Authentication** - Custom user store
7. **In-Memory Authentication** - Development/testing
8. **Form-Based Authentication** - Web applications
9. **Custom Authentication** - Legacy system integration

---

## 🔄 Authentication Workflows & Mechanisms

### 1. 🔑 Basic Authentication Workflow

#### **How It Works:**
Basic Authentication uses HTTP Basic Authentication scheme with session management for subsequent requests.

#### **Step-by-Step Workflow:**

```mermaid
sequenceDiagram
    participant Client
    participant Controller
    participant Service
    participant Repository
    participant Database
    participant Session

    Client->>Controller: POST /api/auth/basic/login
    Note over Client,Controller: {username, password}
    
    Controller->>Service: authenticate(request)
    Note over Controller,Service: Circuit Breaker Protection
    
    Service->>Repository: findByUsername(username)
    Repository->>Database: SELECT user WHERE username=?
    Database-->>Repository: User entity
    Repository-->>Service: User domain object
    
    Service->>Service: validatePassword(plaintext, hashed)
    Note over Service: BCrypt comparison (strength 12)
    
    alt Authentication Success
        Service->>Session: createSession(user)
        Session-->>Service: sessionId
        Service-->>Controller: AuthResponse + sessionId
        Controller-->>Client: 200 OK + session cookie
    else Authentication Failure
        Service-->>Controller: AuthenticationException
        Controller-->>Client: 401 Unauthorized
    end
```

#### **Key Mechanisms:**

1. **Password Hashing**: BCrypt with strength 12
   ```java
   // Password encoding during user creation
   String hashedPassword = passwordEncoder.encode(rawPassword);
   
   // Password verification during login
   boolean matches = passwordEncoder.matches(rawPassword, hashedPassword);
   ```

2. **Session Management**: Server-side session storage
   ```java
   // Create session after successful authentication
   HttpSession session = request.getSession(true);
   session.setAttribute("userId", user.getId());
   session.setAttribute("roles", user.getRoles());
   ```

3. **Circuit Breaker Protection**: Resilience4j
   ```java
   @CircuitBreaker(name = "basicAuth", fallbackMethod = "fallbackAuthentication")
   public AuthenticationResponse authenticate(AuthenticationRequest request)
   ```

#### **Security Features:**
- **Constant-time comparison** prevents timing attacks
- **Secure random session IDs** prevent session hijacking
- **Session timeout** for automatic logout
- **CSRF protection** for web forms

---

### 2. 🎫 JWT Authentication Workflow

#### **How It Works:**
JWT (JSON Web Token) provides stateless authentication using signed tokens containing user claims.

#### **Step-by-Step Workflow:**

```mermaid
sequenceDiagram
    participant Client
    participant Controller
    participant Service
    participant JWTProvider
    participant Repository
    participant Database

    Client->>Controller: POST /api/auth/jwt/login
    Note over Client,Controller: {username, password}
    
    Controller->>Service: authenticate(request)
    Note over Controller,Service: Circuit Breaker Protection
    
    Service->>Repository: findByUsername(username)
    Repository->>Database: SELECT user WHERE username=?
    Database-->>Repository: User entity
    Repository-->>Service: User domain object
    
    Service->>Service: validatePassword(plaintext, hashed)
    Note over Service: BCrypt comparison
    
    alt Authentication Success
        Service->>JWTProvider: generateAccessToken(user)
        JWTProvider-->>Service: accessToken (15 min)
        Service->>JWTProvider: generateRefreshToken(user)
        JWTProvider-->>Service: refreshToken (7 days)
        Service-->>Controller: AuthResponse + tokens
        Controller-->>Client: 200 OK + JWT tokens
    else Authentication Failure
        Service-->>Controller: AuthenticationException
        Controller-->>Client: 401 Unauthorized
    end
    
    Note over Client: Store tokens securely
    
    Client->>Controller: GET /api/auth/jwt/protected
    Note over Client,Controller: Authorization: Bearer <accessToken>
    
    Controller->>JWTProvider: validateToken(accessToken)
    JWTProvider-->>Controller: User claims
    Controller-->>Client: 200 OK + protected data
```

#### **JWT Token Structure:**

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user123",
    "username": "jwtuser",
    "roles": ["USER", "JWT_TEST"],
    "iat": 1691750400,
    "exp": 1691754000
  },
  "signature": "HMAC-SHA256(base64UrlEncode(header) + '.' + base64UrlEncode(payload), secret)"
}
```

#### **Key Mechanisms:**

1. **Token Generation**: HMAC-SHA256 signing
   ```java
   public String generateAccessToken(User user) {
       return Jwts.builder()
           .setSubject(user.getUsername())
           .claim("roles", user.getRoles())
           .setIssuedAt(new Date())
           .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
           .signWith(getSigningKey(), SignatureAlgorithm.HS256)
           .compact();
   }
   ```

2. **Token Validation**: Signature verification
   ```java
   public Claims validateToken(String token) {
       return Jwts.parserBuilder()
           .setSigningKey(getSigningKey())
           .build()
           .parseClaimsJws(token)
           .getBody();
   }
   ```

3. **Refresh Token Mechanism**: Long-lived token for renewal
   ```java
   // Refresh token has longer expiration (7 days)
   public String generateRefreshToken(User user) {
       return Jwts.builder()
           .setSubject(user.getUsername())
           .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
           .signWith(getSigningKey(), SignatureAlgorithm.HS256)
           .compact();
   }
   ```

#### **Security Features:**
- **Stateless authentication** - no server-side session storage
- **Tamper-proof tokens** - HMAC-SHA256 signature
- **Automatic expiration** - short-lived access tokens (15 minutes)
- **Token refresh capability** - long-lived refresh tokens (7 days)
- **Role-based claims** - embedded in token payload

---

## 🛡️ Security Mechanisms Deep Dive

### 1. **Password Security (BCrypt)**

#### **How BCrypt Works:**
```java
// BCrypt internally performs:
// 1. Generate random salt (128-bit)
// 2. Apply key stretching (2^strength rounds)
// 3. Combine password + salt + rounds
// 4. Generate final hash

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // 2^12 = 4096 rounds
}
```

#### **Why BCrypt is Secure:**
- **Adaptive**: Can increase cost factor over time
- **Salted**: Each password gets unique salt
- **Slow**: Intentionally computationally expensive
- **Proven**: Extensively tested and reviewed

### 2. **JWT Security Considerations**

#### **Signing Key Management:**
```java
private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
}
```

#### **Token Validation Process:**
1. **Signature Verification**: Ensures token wasn't tampered with
2. **Expiration Check**: Prevents use of old tokens
3. **Claims Validation**: Verifies user and roles
4. **Format Validation**: Ensures proper JWT structure

### 3. **Circuit Breaker Pattern**

#### **Configuration:**
```properties
resilience4j.circuitbreaker.instances.basicAuth.sliding-window-size=10
resilience4j.circuitbreaker.instances.basicAuth.failure-rate-threshold=50
resilience4j.circuitbreaker.instances.basicAuth.wait-duration-in-open-state=30s
```

#### **States and Behavior:**
- **Closed**: Normal operation, counts failures
- **Open**: Blocks requests, returns fallback response
- **Half-Open**: Limited requests to test recovery

---

## 📋 **API Endpoints Reference**

### **Basic Authentication**
```http
POST /api/auth/basic/login
Content-Type: application/json

{
  "username": "basicuser",
  "password": "basic123456"
}

Response: {
  "message": "Authentication successful",
  "sessionId": "ABC123...",
  "expiresIn": "30 minutes"
}
```

### **JWT Authentication**
```http
POST /api/auth/jwt/login
Content-Type: application/json

{
  "username": "jwtuser", 
  "password": "jwt123456"
}

Response: {
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

### **Protected Resource Access**
```http
GET /api/auth/jwt/protected
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Response: {
  "message": "Access granted to protected resource",
  "user": "jwtuser",
  "roles": ["USER", "JWT_TEST"],
  "timestamp": "2025-08-11T10:30:00Z"
}
```

---

## 🔧 **Configuration Deep Dive**

### **Application Properties**
```properties
# JWT Configuration
app.jwt.secret=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
app.jwt.access-token-expiration=900000    # 15 minutes
app.jwt.refresh-token-expiration=604800000 # 7 days

# Circuit Breaker Configuration
resilience4j.circuitbreaker.instances.basicAuth.sliding-window-size=10
resilience4j.circuitbreaker.instances.basicAuth.failure-rate-threshold=50
resilience4j.circuitbreaker.instances.basicAuth.wait-duration-in-open-state=30s

# Database Configuration (H2)
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.username=sa
spring.datasource.password=

# JPA Configuration
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.format_sql=true
```

### **Test Users** (Created automatically)
| Username | Password | Roles | Purpose |
|----------|----------|-------|---------|
| admin | admin123456 | ADMIN, USER | Full access testing |
| user | user123456 | USER | Basic user testing |
| manager | manager123456 | MANAGER, USER | Role-based testing |
| jwtuser | jwt123456 | USER, JWT_TEST | JWT specific testing |
| basicuser | basic123456 | USER, BASIC_TEST | Basic auth testing |

---

## 🧪 **Testing Scenarios**

### **Scenario 1: Basic Authentication Flow**
```bash
# 1. Login with basic auth
curl -X POST http://localhost:8080/api/auth/basic/login \
  -H "Content-Type: application/json" \
  -d '{"username": "basicuser", "password": "basic123456"}'

# 2. Validate session
curl -X GET http://localhost:8080/api/auth/basic/validate \
  -H "X-Session-ID: <session-id-from-step-1>"

# 3. Logout
curl -X POST http://localhost:8080/api/auth/basic/logout \
  -H "X-Session-ID: <session-id-from-step-1>"
```

### **Scenario 2: JWT Authentication Flow**
```bash
# 1. Login with JWT
curl -X POST http://localhost:8080/api/auth/jwt/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jwtuser", "password": "jwt123456"}'

# 2. Access protected resource
curl -X GET http://localhost:8080/api/auth/jwt/protected \
  -H "Authorization: Bearer <access-token-from-step-1>"

# 3. Refresh token when expired
curl -X POST http://localhost:8080/api/auth/jwt/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh-token-from-step-1>"}'
```

### **Scenario 3: Circuit Breaker Testing**
```bash
# Send multiple invalid requests to trigger circuit breaker
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/auth/basic/login \
    -H "Content-Type: application/json" \
    -d '{"username": "invalid", "password": "invalid"}'
done

# Check circuit breaker status
curl -X GET http://localhost:8080/actuator/circuitbreakers
```

---

## 🔄 **Next Steps & Extensions**

### **Immediate Improvements:**
1. **Add rate limiting** to prevent brute force attacks
2. **Implement account lockout** after failed attempts
3. **Add password complexity requirements**
4. **Implement remember me functionality**

### **Advanced Features:**
1. **Multi-factor authentication (MFA)**
2. **Social login integration (OAuth 2.0)**
3. **LDAP/Active Directory integration**
4. **SAML 2.0 for enterprise SSO**

### **Production Considerations:**
1. **Use external secret management** (Azure Key Vault, AWS Secrets Manager)
2. **Implement proper logging and monitoring**
3. **Add security headers and CORS configuration**
4. **Use HTTPS in production**

---

## 🎯 **Learning Outcomes**

After completing this episode, you should understand:

1. **Authentication vs Authorization** - The fundamental difference
2. **Stateful vs Stateless** - Session-based vs token-based authentication
3. **Security Best Practices** - Password hashing, token management
4. **Circuit Breaker Pattern** - Building resilient systems
5. **Hexagonal Architecture** - Clean separation of concerns
6. **Spring Security Integration** - Modern security configuration

**Perfect foundation for building secure Spring Boot applications!** 🚀

---

## 📚 **Additional Resources**

- [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/)
- [JWT.io - JSON Web Token Debugger](https://jwt.io/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Resilience4j Documentation](https://resilience4j.readme.io/)
- [BCrypt Generator/Verifier](https://bcrypt-generator.com/)

---

*Episode 1 Complete! Ready for Episode 2: OAuth 2.0 & Social Login Integration* 🎬
