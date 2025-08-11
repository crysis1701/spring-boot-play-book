# 🔐 Spring Boot Authentication Methods Demo

This project demonstrates **9 different authentication methods** in Spring Boot using **Hexagonal Architecture**, **Java 24**, and modern security practices.

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

## 🚀 **Key Features Implemented**

### **✅ Security Best Practices**
- BCrypt password hashing (strength 12)
- JWT with HMAC-SHA256 signing
- Input validation and sanitization
- Constant-time string comparison
- Secure random token generation

### **✅ Circuit Breaker Pattern**
- Resilience4j integration
- Configurable failure thresholds
- Graceful degradation
- Service availability protection

### **✅ Modern Java 24 Features**
- Records for DTOs
- Text blocks for documentation
- Pattern matching
- Enhanced switch expressions
- Sealed classes ready

### **✅ Clean Code Practices**
- Comprehensive comments
- Validation at all layers
- Error handling with context
- Logging for debugging
- Immutable domain models

## 📋 **API Endpoints**

### **Basic Authentication**
```http
POST /api/auth/basic/login
GET  /api/auth/basic/validate
POST /api/auth/basic/logout
```

### **JWT Authentication**
```http
POST /api/auth/jwt/login
POST /api/auth/jwt/refresh
GET  /api/auth/jwt/validate
GET  /api/auth/jwt/protected
```

### **Development Tools**
```http
GET  /h2-console          # Database console
GET  /actuator/health     # Health checks
GET  /actuator/circuitbreakers  # Circuit breaker status
```

## 🔧 **Configuration**

### **Application Properties**
- JWT secret and expiration times
- Circuit breaker thresholds
- Database configuration (H2)
- Logging levels for debugging

### **Test Users** (Created automatically)
| Username | Password | Roles | Purpose |
|----------|----------|-------|---------|
| admin | admin123 | ADMIN, USER | Full access testing |
| user | user123 | USER | Basic user testing |
| manager | manager123 | MANAGER, USER | Role-based testing |
| jwtuser | jwt123456 | USER, JWT_TEST | JWT specific testing |
| basicuser | basic123456 | USER, BASIC_TEST | Basic auth testing |

## 🧪 **Testing Examples**

### **Basic Authentication Test**
```bash
curl -X POST http://localhost:8080/api/auth/basic/login \
  -H "Content-Type: application/json" \
  -d '{"username": "basicuser", "password": "basic123456"}'
```

### **JWT Authentication Test**
```bash
curl -X POST http://localhost:8080/api/auth/jwt/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jwtuser", "password": "jwt123456"}'
```

### **Protected Resource Test**
```bash
curl -X GET http://localhost:8080/api/auth/jwt/protected \
  -H "Authorization: Bearer <your-jwt-token>"
```

## 🛡️ **Security Features**

### **Password Security**
- BCrypt with strength 12
- Automatic salt generation
- Upgrade detection for hash algorithms
- Secure comparison methods

### **JWT Security**
- HMAC-SHA256 signing
- Configurable expiration
- Refresh token rotation
- Claims validation

### **Input Validation**
- Bean validation annotations
- Custom validation logic
- SQL injection prevention
- XSS protection ready

### **Error Handling**
- Global exception handler
- Consistent error responses
- Security-aware error messages
- Detailed logging for debugging

## 🔄 **Circuit Breaker Configuration**

```properties
# Sliding window of 10 requests
sliding-window-size=10

# Open circuit if 50% fail
failure-rate-threshold=50

# Wait 30s before retry
wait-duration-in-open-state=30s

# Allow 3 calls in half-open state
permitted-number-of-calls-in-half-open-state=3
```

## 📈 **Next Steps**

1. **Run the application**: `./mvnw spring-boot:run`
2. **Test endpoints** with the provided examples
3. **Monitor circuit breakers** via actuator
4. **Implement additional auth methods** as needed
5. **Customize for your requirements**

## 🎯 **Ready for Extension**

The hexagonal architecture makes it easy to:
- Add new authentication methods
- Swap implementations (different JWT providers, databases)
- Add new validation rules
- Integrate with external systems
- Test each layer independently

**Perfect foundation for learning Spring Boot security!** 🚀
