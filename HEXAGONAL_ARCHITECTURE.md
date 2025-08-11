# Hexagonal Architecture Structure

This project follows the **Hexagonal Architecture** (also known as **Ports and Adapters**) pattern, which promotes clean separation of concerns and makes the application more testable and maintainable.

## 🏗️ Architecture Overview

```
📁 src/main/java/com/spring/play/ground/spring/
├── 📁 domain/                          # Core business logic (The Hexagon)
│   ├── 📁 model/                       # Domain entities and value objects
│   ├── 📁 service/                     # Domain services (business logic)
│   └── 📁 port/                        # Interfaces defining contracts
│       ├── 📁 in/                      # Inbound ports (use cases)
│       └── 📁 out/                     # Outbound ports (dependencies)
├── 📁 infrastructure/                  # External concerns (Adapters)
│   ├── 📁 adapter/                     # Concrete implementations
│   │   ├── 📁 in/                      # Inbound adapters (drivers)
│   │   │   ├── 📁 web/                 # REST controllers, GraphQL
│   │   │   └── 📁 messaging/           # Message queues, events
│   │   └── 📁 out/                     # Outbound adapters (driven)
│   │       ├── 📁 persistence/         # Database, repositories
│   │       └── 📁 external/            # External APIs, services
│   └── 📁 configuration/               # Spring configuration classes
├── 📁 shared/                          # Cross-cutting concerns
│   ├── 📁 exception/                   # Common exceptions
│   └── 📁 util/                        # Utility classes
└── Application.java                    # Spring Boot main class
```

## 🎯 Core Principles

### 1. **Domain Layer** (The Hexagon Core)
- **No dependencies** on external frameworks or infrastructure
- Contains pure business logic
- Independent of Spring, databases, web frameworks

### 2. **Ports** (Interfaces)
- **Inbound Ports**: Define what the application can do (use cases)
- **Outbound Ports**: Define what the application needs (dependencies)

### 3. **Adapters** (Implementations)
- **Inbound Adapters**: Handle external requests (controllers, message listeners)
- **Outbound Adapters**: Implement external dependencies (repositories, APIs)

## 📋 Layer Descriptions

### 🎯 Domain Layer
```
domain/
├── model/          # Entities, Value Objects, Aggregates
├── service/        # Domain Services (business logic)
└── port/
    ├── in/         # Use cases (what the app can do)
    └── out/        # Dependencies (what the app needs)
```

**Rules:**
- ❌ No Spring annotations (except maybe `@Component` for services)
- ❌ No database annotations
- ❌ No web framework dependencies
- ✅ Pure Java business logic
- ✅ Domain-specific exceptions

### 🔌 Infrastructure Layer
```
infrastructure/
├── adapter/
│   ├── in/
│   │   ├── web/        # @RestController, @GraphQLController
│   │   └── messaging/  # @EventListener, @KafkaListener
│   └── out/
│       ├── persistence/    # @Repository, JPA entities
│       └── external/       # HTTP clients, external APIs
└── configuration/          # @Configuration classes
```

**Rules:**
- ✅ Spring annotations allowed
- ✅ Framework-specific code
- ✅ Infrastructure concerns
- ✅ Implements ports from domain

### 🤝 Shared Layer
```
shared/
├── exception/      # Common exceptions, error handling
└── util/          # Utility classes, constants
```

## 🔄 Data Flow

```
[External Request] 
    ↓
[Inbound Adapter] → [Inbound Port] → [Domain Service] → [Outbound Port] → [Outbound Adapter]
                                            ↓
                                    [Domain Model]
```

## 📝 Example Structure

Here's how a typical feature would be organized:

```java
// Domain
domain/model/User.java
domain/service/UserDomainService.java
domain/port/in/CreateUserUseCase.java
domain/port/out/UserRepository.java

// Infrastructure
infrastructure/adapter/in/web/UserController.java
infrastructure/adapter/out/persistence/UserJpaRepository.java
infrastructure/adapter/out/persistence/UserEntity.java
infrastructure/configuration/UserConfiguration.java
```

## ✅ Benefits

1. **Testability**: Easy to unit test domain logic
2. **Independence**: Core business logic is framework-agnostic
3. **Flexibility**: Easy to swap implementations
4. **Maintainability**: Clear separation of concerns
5. **Scalability**: Easier to modify and extend

## 🎯 Next Steps

1. Add dependencies for web and persistence
2. Create example domain models
3. Implement use cases with ports
4. Create adapters for REST API and database
5. Set up configuration classes

Ready to start building! 🚀
