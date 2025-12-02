# T4M User Manager - Architecture Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Core Architectural Patterns](#core-architectural-patterns)
   - [Security & Authentication Flow](#security--authentication-flow)
   - [Caching Strategy](#caching-strategy)
   - [Event-Driven Architecture](#event-driven-architecture)
   - [Async Processing with Virtual Threads](#async-processing-with-virtual-threads)
   - [Distributed Tracing & Observability](#distributed-tracing--observability)
4. [Component Responsibilities](#component-responsibilities)
5. [Data Flow Scenarios](#data-flow-scenarios)
6. [Extension Points](#extension-points)
7. [Troubleshooting & Observability](#troubleshooting--observability)

---

## System Overview

The T4M User Manager is a Spring Boot microservice that serves as the central authentication and authorization gateway for the Tec4MaaSEs platform. It provides a domain-specific API layer between frontend applications and Keycloak, abstracting identity management complexity while enforcing platform-specific business rules.

### Core Responsibilities

1. **User Authentication** - OAuth2/OpenID Connect flow with JWT token generation and refresh
2. **User Lifecycle Management** - Registration, activation, password management, logout, deletion
3. **Role-Based Access Control** - Three-tier hierarchy (Pilot Roles, User Roles, Organizations/Pilots)
4. **Organization Synchronization** - Kafka-driven updates from external organizational systems
5. **Multi-Tenant Support** - Users belong to organizations with isolated permissions

### Technology Stack

| Layer | Technology |
|-------|------------|
| Framework | Spring Boot 3.5.7, Java 21 |
| Security | Spring Security OAuth2 Resource Server |
| Identity Provider | Keycloak 16.1.1 |
| Caching | Caffeine (in-memory) |
| Messaging | Apache Kafka |
| Observability | Micrometer + Logback |
| API Documentation | OpenAPI 3.0 (Swagger) |
| Testing | JUnit 5, Mockito |

### Design Principles

- **Stateless Design**: Enables horizontal scaling and high availability
- **Defense-in-Depth Security**: Multiple validation layers at entry, business and integration points
- **Performance-First Caching**: Multi-layer caching with TTL-based eviction and race condition prevention
- **Event-Driven**: Spring Events for internal coordination, Kafka for cross-service communication
- **Observability**: Structured logging, health checks and custom metrics

---

## High-Level Architecture

### System Context

```
┌─────────────────┐
│   Frontend      │
│  Applications   │
└────────┬────────┘
         │ HTTPS/REST (JWT Bearer)
         ▼
┌─────────────────────────────────────────┐
│       T4M User Manager Service          │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │     Security Filters (3-layer)   │   │  ← Rate Limiting, JWT Validation, Attributes
│  └──────────────┬───────────────────┘   │
│                 ▼                       │
│  ┌──────────────────────────────────┐   │
│  │       REST Controllers           │   │  ← UserController, AdminController
│  └──────────────┬───────────────────┘   │
│                 ▼                       │
│  ┌──────────────────────────────────┐   │
│  │       Business Services          │   │  ← UserManagementService, KeycloakAdminService
│  └──────────────┬───────────────────┘   │
│                 ▼                       │
│  ┌──────────────────────────────────┐   │
│  │       Integration Layer          │   │  ← Keycloak Client, Kafka, SMTP
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
         │                    │
         ▼                    ▼
┌─────────────────┐    ┌─────────────────┐
│   Keycloak      │    │  Kafka Broker   │
│   (Identity)    │    │  (Events)       │
└─────────────────┘    └─────────────────┘
```

### Architectural Layers

1. **Security Layer**: Entry point with rate limiting, JWT validation, attribute checking
2. **API Layer**: RESTful controllers exposing user/admin operations
3. **Business Logic**: Domain services with caching, validation and business rules
4. **Integration Layer**: Adapters for Keycloak, Kafka and email
5. **Cross-Cutting**: Caching, async events, exception handling, observability

---

## Core Architectural Patterns

### Security & Authentication Flow

The service implements a **defense-in-depth security model** with multiple validation layers.

#### JWT Token Lifecycle

1. **Login Flow**
   - User sends credentials to `/api/user/authenticate`
   - Service forwards to Keycloak token endpoint
   - Keycloak validates credentials and returns JWT access + refresh tokens
   - Service returns tokens to client with user metadata

2. **Authenticated Request Flow**
   - Client includes JWT in `Authorization: Bearer <token>` header
   - Spring Security validates JWT signature against Keycloak public key
   - Custom `JwtAuthConverter` extracts roles from token claims
   - `JwtAttributesValidatorFilter` ensures required attributes present
   - Request-scoped `JwtContext` provides user information to controllers/services

3. **Token Refresh Flow**
   - Client sends refresh token to `/api/user/refresh-token`
   - Service forwards to Keycloak token endpoint
   - New access token returned if refresh token valid

#### Security Filter Chain

Requests pass through three security filters in order:

1. **RateLimitingFilter** (Updated in latest implementation)
   - **Authenticated Users**: 500 requests/minute per user ID (prevents legitimate user blocking)
   - **Anonymous Users**: 100 requests/minute per IP address (prevents abuse)
   - Uses Caffeine cache with Bucket4j token bucket algorithm
   - Handles X-Forwarded-For headers for proxied requests

2. **JwtAuthenticationFilter** (Spring Security)
   - Validates JWT signature using Keycloak's public key
   - Extracts authentication principal and authorities
   - Sets SecurityContext for request

3. **JwtAttributesValidatorFilter**
   - Validates presence of required custom attributes (pilot_code, pilot_role, user_role organization_id)
   - Returns 401 Unauthorized if attributes missing
   - Ensures tokens are properly enriched by Keycloak

### Role Hierarchy

The system implements a **three-tier role model**:

```
┌─────────────────────────────────────────────┐
│  Pilot Roles (System-Wide Authority)        │
├─────────────────────────────────────────────┤
│  SUPER_ADMIN: Full platform access          │
│  ADMIN: Organization-scoped management      │
│  USER: Basic user operations                │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│  User Roles (Functional Permissions)        │
├─────────────────────────────────────────────┤
│  IT, Procurement, etc. (More can be added   │
│     but it should remove eventually         │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│  Pilots/Organizations (Multi-Tenancy)       │
├─────────────────────────────────────────────┤
│  DEFAULT: System-wide users                 │
│  ORG_CODE: Organization-specific users      │
└─────────────────────────────────────────────┘
```

**Role Decision Logic:**
- SUPER_ADMIN can access ALL organizations
- ADMIN can only access their assigned organization
- USER has read-only access to their organization

### Caching Strategy

The service uses **Caffeine** for high-performance caching with **TTL-based eviction**:

| Cache Name | Contents | TTL | Purpose |
|------------|----------|-----|---------|
| `users` | UserDto by userId | 10 min | Avoid repeated Keycloak API calls for user data |
| `userRoles` | List<UserRoleDto> | 15 min | Cache available roles in system |
| `pilotRoles` | List<PilotDto> | 15 min | Cache system roles (SUPER_ADMIN, ADMIN, USER) |
| `pilots` | List<PilotDto> | 15 min | Cache all organizations/pilots |

### Event-Driven Architecture

Two event mechanisms serve different purposes:

#### 1. Spring Events (Internal Coordination)

Used for **intra-service async operations**:

- **OrganizationDeletionEvent**: When organization deleted, remove all its users asynchronously
- **OrganizationNameUpdateEvent**: When organization renamed, update all user attributes asynchronously

**Pattern:**
```java
@Async
@EventListener
public void handleOrganizationDeletion(OrganizationDeletionEvent event) {
    // Runs on virtual thread, won't block request
    List<UserDto> users = userManagementService.retrieveAllUsers();
    users.stream()
        .filter(user -> event.getPilotCode().equals(user.getPilotCode()))
        .forEach(user -> userManagementService.deleteUser(user.getUserId()));
}
```

#### 2. Kafka Events (Cross-Service Communication)

Used for **synchronizing with external organizational systems**:

- **Topic**: `user-management-in`
- **Consumer Group**: `t4m-user-manager`
- **Message Types**:
  - Organization created/updated/deleted
  - Contains: `event_id`, `event_type`, `priority`, `object`, `data`

**Processing Flow:**
1. Kafka message consumed by `KafkaMessageHandler`
2. Message validated for required fields
3. Event type determined (CREATE, UPDATE, DELETE)
4. Appropriate Keycloak operation performed
5. Caches evicted to reflect changes
6. Errors logged but don't crash consumer (resilience)

**Configuration Note**: Kafka connection type can be set via `spring.kafka.connection.type` property:
- `INTERNAL` (default): No SSL, for local development
- `EXTERNAL`: SSL/SASL authentication for production (requires `KAFKA_USERNAME`, `KAFKA_PASSWORD`, `KAFKA_CERT_PATH`)

### Async Processing with Virtual Threads

The service leverages **Java 21 virtual threads** for lightweight concurrency:

```properties
# application.properties
spring.threads.virtual.enabled=true
```

**Benefits:**
- Event handlers run asynchronously without blocking request threads
- Cache warmup on startup doesn't delay application initialization
- Email sending doesn't block user operations
- Thousands of virtual threads with minimal memory overhead

**Use Cases:**
- Spring `@Async` methods (event handlers, cache warmup)
- Kafka message processing
- Email notifications
- Any I/O-bound operations

### Distributed Tracing & Observability

The service implements **distributed tracing** using **Micrometer Tracing** with **OpenTelemetry** for request path visualization and performance analysis. Tracing helps debug issues by following request flows across service boundaries and identifying bottlenecks.

#### Why Distributed Tracing

In microservices architectures, a single user request often touches multiple services. Without tracing:
- Debugging requires correlating logs across services manually
- Performance bottlenecks are difficult to identify
- Request paths through the system are opaque

With tracing:
- **Trace IDs** link all operations for a single request
- **Spans** represent individual operations (database queries, HTTP calls, business logic)
- **Jaeger UI** visualizes the entire request journey with timing information

#### Enabling/Disabling Tracing

Tracing is controlled by a **feature flag** that defaults to **disabled** for zero overhead in development:

```properties
# application.properties
observability.tracing-enabled=${TRACING_ENABLED:false}
```

**Development Mode (Tracing Disabled)**:
```bash
# No environment variable needed - tracing disabled by default
docker-compose up
java -jar t4m-user-manager.jar

# Result: No trace overhead, standard logging
```

**Production Mode (Tracing Enabled)**:
```bash
# Enable tracing via environment variable
export TRACING_ENABLED=true
export OTLP_ENDPOINT=http://jaeger:4318/v1/traces

docker-compose up
java -jar t4m-user-manager.jar

# Result: Traces sent to Jaeger, trace IDs in logs
# Startup log confirms: "Distributed tracing with @Observed annotations is ENABLED"
```

#### Trace Components: Traces and Spans

**Trace**: A complete request journey from entry to exit.
- Assigned unique **Trace ID** (e.g., `a3f8b2c1d4e5f6g7`)
- Contains multiple spans representing operations

**Span**: A single operation within a trace.
- Has unique **Span ID** and references parent span
- Contains operation name, start/end timestamps, metadata
- Examples: HTTP request, database query, cache lookup, email send

**Example Trace for User Login**:
```
Trace ID: a3f8b2c1d4e5f6g7
│
├─ Span: POST /api/user/authenticate (root span)
│  ├─ Span: UserAuthService.authenticate
│  ├─ Span: HTTP POST to Keycloak token endpoint
│  ├─ Span: UserManagementService.retrieveUserById
│  │  └─ Span: cache.get (cache miss)
│  │     └─ Span: Keycloak Admin API user fetch
│  └─ Span: cache.put (store user in cache)
```

#### Logback Integration: Trace Correlation in Logs

The `logback-spring.xml` configuration **conditionally includes Trace ID and Span ID** in log output based on tracing status.

**When Tracing Enabled**:
```
[01-12-2025 16:45:23] [http-nio-8080-exec-1] INFO
UserAuthService.authenticate [TraceID: a3f8b2c1d4e5f6g7, SpanID: 1234567890abcdef]
- Authenticating user: john@example.com
```

**When Tracing Disabled**:
```
[01-12-2025 16:45:23] [http-nio-8080-exec-1] INFO
UserAuthService.authenticate - Authenticating user: john@example.com
```

**MDC (Mapped Diagnostic Context)**:
- `%X{traceId}`: Automatically populated by Micrometer with current trace ID
- `%X{spanId}`: Automatically populated with current span ID
- Available in all log statements within traced operations

**Benefits**:
- Copy trace ID from logs → paste in Jaeger UI → see complete request flow
- Correlate logs across multiple services using shared trace ID
- Zero-overhead logging when tracing disabled (no empty trace ID fields)

**Jaeger UI Features**:
- **Search Traces**: Filter by service, operation, duration, tags
- **Trace Timeline**: Visualize span hierarchy and timing
- **Service Dependencies**: See which services communicate
- **Metrics Dashboard**: Request rates, error rates, latencies

**OTLP Endpoints**:
- HTTP: `http://localhost:4318/v1/traces` (used by Spring Boot)
- gRPC: `http://localhost:4317` (alternative binary protocol)

#### OpenTelemetry Configuration

**OTLP Export Settings** (`application.properties`):
```properties
# OpenTelemetry Protocol endpoint for trace export
management.otlp.tracing.endpoint=${OTLP_ENDPOINT:http://localhost:4318/v1/traces}

# Sampling: 1.0 = 100% of traces captured (adjust for production)
management.tracing.sampling.probability=1.0

# Enable observations and metrics export
management.observations.annotations.enabled=${observability.tracing-enabled}
management.metrics.export.otlp.enabled=${observability.tracing-enabled}
management.metrics.export.otlp.endpoint=${OTLP_ENDPOINT:http://localhost:4318/v1/metrics}

# Service identifier in Jaeger
management.metrics.export.otlp.resource-attributes=service.name=t4m-user-manager
```

**Environment Variables**:
- `TRACING_ENABLED`: Feature flag (default: `false`)
- `OTLP_ENDPOINT`: Jaeger collector endpoint (default: `http://localhost:4318/v1/traces`)

**Sampling Strategy**:
- Currently: 100% sampling (`1.0`) for development/testing
- Production recommendation: Adjust based on traffic (e.g., `0.1` = 10% sampling)

**Conditional Loading**:
- If `observability.tracing-enabled=false`: `ObservedAspect` bean not created, zero overhead
- If `observability.tracing-enabled=true`: Full tracing infrastructure loaded

#### Using Tracing for Debugging

**Scenario**: User reports "Login is slow"

1. **Enable Tracing**: Set `TRACING_ENABLED=true` and restart service
2. **Reproduce Issue**: User logs in, note the trace ID from logs
3. **Open Jaeger UI**: Navigate to http://localhost:16686
4. **Search Trace**: Paste trace ID or search by operation `POST /api/user/authenticate`
5. **Analyze Timeline**:
   - See all spans in chronological order
   - Identify slow span (e.g., Keycloak token endpoint taking 2 seconds)
   - Drill into span tags for error details
6. **Root Cause**: Keycloak slow response → investigate Keycloak performance

**Example Trace Analysis**:
```
Trace: a3f8b2c1d4e5f6g7 (Total: 2.5s)
├─ POST /api/user/authenticate (2.5s)
│  ├─ UserAuthService.authenticate (2.3s)
│  │  └─ HTTP POST keycloak.example.com/token (2.2s) ← BOTTLENECK
│  └─ UserManagementService.retrieveUserById (0.2s)
│     ├─ cache.get users (0.001s - cache miss)
│     └─ Keycloak Admin API GET /users/123 (0.15s)
```

#### Production Considerations

**Sampling for High-Traffic Services**:
```properties
# Reduce sampling to 10% in production
management.tracing.sampling.probability=0.1
```

**Remote Jaeger Deployment**:
```properties
# Point to external Jaeger instance
management.otlp.tracing.endpoint=https://jaeger.production.example.com:4318/v1/traces
```

**Security**:
- Jaeger UI should be behind authentication in production
- Use HTTPS for OTLP endpoint in production
- Consider trace data retention policies (PII in span tags)

**Performance Impact**:
- Enabled tracing: ~1-2% CPU overhead with 100% sampling
- Disabled tracing: Zero overhead (code paths not executed)
- Network: Traces batched and sent every 60 seconds

---

## Component Responsibilities

### API Layer (Controllers)

#### UserController
**Purpose**: User-facing operations

**Key Endpoints:**
- `POST /api/user/authenticate` - Login with credentials
- `POST /api/user/refresh-token` - Refresh access token
- `POST /api/user/create` - Register new user (with email activation)
- `PUT /api/user/update` - Update user profile
- `POST /api/user/logout` - Invalidate session
- `GET /api/user/profile` - Get current user details
- `POST /api/user/reset-password` - Initiate password reset
- `POST /api/user/change-password` - Change password (authenticated)

**Access Control**: Most endpoints require authentication. Profile updates validated against JWT context.

#### AdminController
**Purpose**: Administrative operations (ADMIN/SUPER_ADMIN only)

**Key Endpoints:**
- `POST /api/admin/user/create` - Create user without activation
- `GET /api/admin/users` - List all users (filtered by organization for non-SUPER_ADMIN)
- `DELETE /api/admin/user/{userId}` - Delete user
- `GET /api/admin/pilots` - List organizations
- `GET /api/admin/roles` - List available roles

**Access Control**: Requires `ADMIN` or `SUPER_ADMIN` pilot role. Organization scoping enforced.

**OpenAPI Note**: Some endpoints hidden from Swagger for internal testing use only.

### Business Logic Layer (Services)

#### UserManagementService
**Responsibilities:**
- CRUD operations for users in Keycloak
- Group/role assignment
- Cache management for user data
- Pilot/organization management
- Interaction with KeycloakAdminService

**Design Pattern**: Interface-based (`IUserManagementService`) for testability.

**Key Methods:**
- `retrieveUserById(String userId)` - Cached user lookup
- `createUser(UserCreationDto)` - Create user with groups/roles
- `updateUser(String userId, UserCreationDto)` - Update user attributes
- `deleteUser(String userId)` - Delete user and trigger cascade events
- `retrieveAllUsers()` - Cached list of all users
- `retrieveAllPilots()` - Cached list of organizations

#### UserAuthService
**Responsibilities:**
- Authentication flow with Keycloak
- Token issuance and refresh
- Password reset/change operations
- User activation flow

**Security Considerations:**
- Never stores passwords (delegated to Keycloak)
- Validates activation tokens before enabling accounts
- Enforces password complexity via Keycloak policies

#### KeycloakAdminService
**Responsibilities:**
- Low-level Keycloak Admin API interactions
- Group/role management
- User representation transformations
- Caching for roles, pilots and user data

**Design**: Wraps Keycloak Admin Client with error handling and caching.

**Key Methods:**
- `retrieveGroupRepresentationByName(String name)` - Get pilot/organization by code
- `retrieveAllPilotRepresentations()` - List all organizations
- `retrieveAllUserRoles()` - List functional roles
- `retrieveAllPilotRoles()` - List system roles (SUPER_ADMIN, ADMIN, USER)
- `assignPilotRoleToUser(...)` - Grant system role
- `removePilotRoleFromUser(...)` - Revoke system role

#### CacheService
**Responsibilities:**
- Centralized cache eviction
- Prevents race conditions during updates
- Cache-aside pattern implementation

**Why Separate Service**: Ensures cache eviction happens BEFORE async events published, preventing stale data reads.

**Key Methods:**
- `evictIfPresent(String cacheName, String... keys)` - Selective eviction
- `evictAll(String cacheName)` - Clear entire cache
- Used by: UserManagementService, KeycloakAdminService, Event Handlers

#### EmailService
**Responsibilities:**
- Send activation emails with tokens
- Send password reset emails
- HTML email templating

**Configuration**: SMTP settings via `mail.host`, `mail.username`, `mail.app-password`.

### Integration Layer

#### Keycloak Integration
**Client Library**: `org.keycloak:keycloak-admin-client`

**Authentication**: Service account with admin credentials (`keycloak.credentials.secret`).

**Operations:**
- User CRUD via `UsersResource`
- Group (organization) management via `GroupsResource`
- Role assignment via `RoleMappingsResource`
- Token issuance via token endpoint

**Error Handling**: Wraps Keycloak exceptions in custom exceptions (`KeycloakException`, `ResourceNotPresentException`).

#### Kafka Integration
**Purpose**: Synchronize organizational changes from external systems.

**Configuration:**
- Bootstrap servers, group ID, topic name
- Connection type: `INTERNAL` (no SSL, default) or `EXTERNAL` (SSL/SASL with SCRAM-SHA-512)
- External mode requires: username, password, CA certificate (PEM format)
- Auto-offset reset: earliest

**Message Processing:**
- Deserializes to `EventDto`
- Validates required fields (`event_id`, `event_type`, `object`, `data`)
- Maps to Keycloak operations (create/update/delete groups)
- Publishes Spring events for user updates
- Logs errors but continues consuming (resilience)

**Error Handling**: `KafkaErrorHandler` logs errors, doesn't throw (avoids consumer death).

### Security Filters

#### RateLimitingFilter
**Purpose**: Prevent abuse and DDoS attacks.

**Strategy**:
- **Authenticated requests**: Rate limited by user ID (500 req/min)
- **Anonymous requests**: Rate limited by IP address (100 req/min)
- Uses Bucket4j token bucket algorithm with Caffeine cache
- Handles X-Forwarded-For header for proxied requests

#### JwtAttributesValidatorFilter
**Purpose**: Ensure JWT tokens have required custom attributes.

**Validates Presence Of:**
- `pilot_code`: Organization identifier
- `pilot_role`: System role (SUPER_ADMIN, ADMIN, USER)
- `user_role`: Functional role
- `organization_id`: Organization UUID

**Response**: Returns 401 Unauthorized with error message if attributes missing.

#### JwtAuthConverter
**Purpose**: Extract Spring Security authorities from Keycloak JWT claims.

**Logic:**
- Reads `resource_access` claim
- Extracts roles for configured client
- Converts to Spring Security `GrantedAuthority` objects
- Used by Spring Security for `@PreAuthorize` annotations

### Cross-Cutting Concerns

#### Exception Handling
**Global Handler**: `@ControllerAdvice` catches exceptions and returns standardized `BaseAppResponse<T>`.

**Custom Exceptions:**
- `KeycloakException`: Keycloak operation failures
- `ResourceNotPresentException`: Entity not found
- `ValidationException`: Input validation errors

**HTTP Status Mapping:**
- 400: Validation errors, bad requests
- 401: Authentication failures, missing/invalid JWT
- 403: Authorization failures (insufficient permissions)
- 404: Resource not found
- 429: Rate limit exceeded
- 500: Internal server errors

#### Context Management
**JwtContext** (Request-scoped bean):

**Purpose**: Provide convenient access to JWT claims and user data within a request.

**Lazy Loading**: Claims extracted on first access and cached for request lifetime.

**Key Methods:**
- `getUserId()`, `getEmail()`, `getUsername()`
- `getPilotRole()`, `getUserRole()`, `getPilotCode()`, `getOrganizationId()`
- `getCurrentUser()` - Fetches full UserDto from Keycloak (once per request)
- `isSuperAdmin()`, `isAdmin()`, `hasAdminPrivileges()`
- `canModifyPilot(String pilotCode)` - Authorization check

**Usage**: Controllers/services inject `JwtContext` to access authenticated user information.

---

## Data Flow Scenarios

### Scenario 1: User Login

```
1. User submits credentials to frontend
2. Frontend POST /api/user/authenticate with {username, password}
3. UserController.authenticateUser() validates input
4. UserAuthService.authenticate() calls Keycloak token endpoint
5. Keycloak validates credentials, returns access + refresh tokens
6. UserAuthService fetches user profile from Keycloak
7. Response includes tokens + user metadata (roles organization)
8. Frontend stores tokens, includes access token in subsequent requests
```

### Scenario 2: Get User Profile (Cached)

```
1. Frontend GET /api/user/profile with JWT in Authorization header
2. Security filters validate JWT, extract user ID
3. UserController.getUserProfile() calls UserManagementService
4. Service checks 'users' cache for user ID
   - Cache HIT: Return cached UserDto (10min TTL)
   - Cache MISS: Fetch from Keycloak, populate cache, return
5. Response includes user profile data
```

### Scenario 3: Update User (Cache Invalidation)

```
1. Frontend PUT /api/user/update with updated profile data
2. UserController validates user can only update own profile (via JwtContext)
3. UserManagementService.updateUser() updates Keycloak representation
4. Service evicts user from 'users' cache (via CacheService)
5. If organization changed, evicts 'pilots' cache
6. Response confirms update
7. Next profile fetch will miss cache, get fresh data from Keycloak
```

### Scenario 4: Organization Deletion (Event-Driven)

```
1. Kafka message received: {event_type: "DELETE", object: "organization", data: {pilot_code: "ORG123"}}
2. KafkaMessageHandler.handleOrganizationEvent() processes message
3. Finds Keycloak group by pilot_code
4. Deletes group from Keycloak (SYNCHRONOUS)
5. CacheService evicts caches (SYNCHRONOUS):
   - 'pilots' cache
   - 'users' cache entries for all users in organization
6. Spring event published: OrganizationDeletionEvent (ASYNCHRONOUS)
7. AppEventListener.handleOrganizationDeletion() receives event (on virtual thread)
8. Fetches all users, filters by organization
9. Deletes each user (Keycloak + cache eviction)
10. Process completes asynchronously without blocking Kafka consumer
```

### Scenario 5: User Registration with Email Activation

```
1. User submits registration form to frontend
2. Frontend POST /api/user/create with user details
3. UserController.createUser() validates input
4. UserAuthService.createUser() creates disabled Keycloak user
5. Generates activation token (UUID), stores in user attributes
6. EmailService.sendActivationEmail() sends HTML email with activation link (ASYNC)
7. Response confirms registration pending activation
8. User clicks activation link: GET /api/user/activate?token={token}
9. UserAuthService validates token, enables Keycloak account
10. User can now log in
```

---

## Extension Points

### Adding a New API Endpoint

1. **Define in Controller**:
   ```java
   @PostMapping("/new-endpoint")
   @PreAuthorize("hasAnyAuthority('ADMIN', 'SUPER_ADMIN')")
   public ResponseEntity<BaseAppResponse<ResultDto>> newEndpoint(@RequestBody RequestDto request) {
       ResultDto result = userManagementService.performNewOperation(request);
       return ResponseEntity.ok(BaseAppResponse.success(result, "Operation successful"));
   }
   ```

2. **Implement in Service**: Add method to `UserManagementService` or create new service.

3. **Update OpenAPI**: Annotations automatically generate Swagger documentation.

4. **Write Tests**: Unit tests for service logic, integration tests for endpoint.

### Adding a New Pilot Role

1. **Create in Keycloak**: Add new realm role (e.g., `MANAGER`).

2. **Update Enum**: Add to `PilotRole` enum if needed for programmatic checks.

3. **Update Authorization**: Add to `@PreAuthorize` annotations where role should have access.

4. **Cache Refresh**: `pilotRoles` cache automatically includes new role after TTL expires.

### Adding a New Cache

1. **Define Cache Name**: Add constant in service (e.g., `CUSTOM_CACHE = "customCache"`).

2. **Configure in Application Properties**:
   ```properties
   cache.custom.ttl=600
   ```

3. **Add @Cacheable Annotation**:
   ```java
   @Cacheable(value = "customCache", key = "#id")
   public CustomDto getCustomData(String id) { ... }
   ```

4. **Cache Eviction**: Use `CacheService.evictIfPresent("customCache", id)` when data changes.

### Adding a New Kafka Event Type

1. **Update EventDto**: Add new `OrganizationEventType` enum value.

2. **Implement Handler**: Add case in `KafkaMessageHandler.handleOrganizationEvent()`.

3. **Create Spring Event**: Define new event class if async processing needed.

4. **Add Event Listener**: Implement `@EventListener` method in `AppEventListener`.

5. **Test**: Mock Kafka messages, verify Keycloak operations.

### Adding a New Security Filter

1. **Create Filter**: Extend `OncePerRequestFilter`.

2. **Register in SecurityConfig**:
   ```java
   .addFilterBefore(new CustomFilter(), JwtAuthenticationFilter.class)
   ```

3. **Specify Order**: Filters execute in registration order.

4. **Test**: Write integration tests with `@SpringBootTest` and `@AutoConfigureMockMvc`.

---

## Troubleshooting & Observability

### Health Checks

**Actuator Endpoints:**
- `/actuator/health` - Overall application health
- `/actuator/health/liveness` - Liveness probe (Kubernetes)
- `/actuator/health/readiness` - Readiness probe (Kubernetes)
- `/actuator/metrics` - Micrometer metrics
- `/actuator/prometheus` - Prometheus-formatted metrics

**Custom Health Indicators**: Can add custom checks for Keycloak, Kafka connectivity.

### Logging

**Framework**: Logback with structured logging.

**Log Levels** (configurable via `logging.level.*`):
- **DEBUG**: Detailed flow (JWT extraction, cache operations)
- **INFO**: Request/response summaries, important state changes
- **WARN**: Rate limits exceeded, recoverable errors, cache warmup failures
- **ERROR**: Keycloak API failures, Kafka processing errors, unexpected exceptions

**Key Log Patterns:**
- `JwtContext created for authenticated request, userId: {userId}` - Request start
- `Cache hit for key: {key}` / `Cache miss for key: {key}` - Cache behavior
- `Rate limit exceeded for user: {userId}` - Rate limiting events
- `Error retrieving user: {message}` - Keycloak operation failures

### Metrics

**Micrometer Integration**: Custom metrics can be added via `MeterRegistry`.

**Useful Metrics** (standard Spring Boot):
- `http.server.requests` - Request counts, durations, status codes
- `jvm.memory.*` - Memory usage
- `jvm.threads.*` - Virtual thread stats
- `cache.gets` / `cache.puts` / `cache.evictions` - Cache performance

### Common Issues

#### "Rate limit exceeded" for Legitimate Users

**Cause**: Old implementation used global rate limit affecting all users.

**Solution**: Latest implementation uses per-user rate limiting for authenticated users (500 req/min), preventing NAT/proxy issues.

**Configuration**: Adjust limits in `RateLimitingFilter` constants:
```java
private static final long AUTHENTICATED_CAPACITY = 500;
private static final long AUTHENTICATED_REFILL = 100;
private static final long ANONYMOUS_CAPACITY = 100;
private static final long ANONYMOUS_REFILL = 20;
```

#### Users Not Found After Organization Update

**Cause**: Cache not evicted after organization changes.

**Solution**: Ensure `CacheService.evictIfPresent()` called BEFORE publishing async events.

**Check**: Review cache eviction order in `UserManagementService` and `KafkaMessageHandler`.

#### Keycloak Connection Errors

**Symptoms**: `Connect to localhost:9080 failed: Connection refused`

**Check**:
1. Keycloak running and accessible at configured URL
2. `keycloak.auth-server-url` property correct
3. Network connectivity (firewall, DNS)
4. Service account credentials valid (`keycloak.credentials.secret`)

**Debug**: Enable DEBUG logging for `gr.atc.t4m.service.KeycloakAdminService`.

#### Kafka Consumer Not Processing Messages

**Symptoms**: Messages sent but not processed, no logs.

**Check**:
1. Kafka broker accessible at `kafka.bootstrap-servers`
2. Check connection type (`spring.kafka.connection.type`)
3. Topic exists and consumer has permissions
4. Consumer group ID unique (`kafka.consumer.group-id`)
5. Verify message format matches `EventDto` structure

**Debug**: Enable DEBUG logging for `gr.atc.t4m.kafka`.

#### JWT Token Validation Failures

**Symptoms**: 401 Unauthorized responses.

**Check**:
1. Token not expired (check `exp` claim)
2. Token issued by correct Keycloak realm
3. `spring.security.oauth2.resourceserver.jwt.issuer-uri` matches token `iss` claim
4. Required custom attributes present (pilot_code, pilot_role, etc.)
5. Token signature valid (Keycloak public key accessible)

**Debug**: Enable DEBUG logging for `gr.atc.t4m.security`.

#### Cache Not Refreshing

**Symptoms**: Stale data returned despite updates.

**Check**:
1. TTL configured (`cache.*.ttl` properties)
2. Cache eviction called after updates
3. Cache names match between `@Cacheable` and eviction calls
4. Cache key expressions correct

**Debug**: Enable DEBUG logging for `org.springframework.cache`.

#### Virtual Thread Issues

**Symptoms**: High memory usage or thread starvation.

**Check**:
1. `spring.threads.virtual.enabled=true`
2. No blocking operations on carrier threads (avoid synchronized blocks in @Async methods)
3. Thread pool configuration appropriate for workload

**Monitor**: JVM metrics `jvm.threads.virtual.*`.

---

## Conclusion

The T4M User Manager follows a **layered, event-driven architecture** with **defense-in-depth security** and **performance-first caching**. Key design decisions prioritize **scalability** (stateless design), **reliability** (cache race condition prevention, Kafka error handling) and **maintainability** (clear separation of concerns, interface-driven design).

For detailed implementation examples, refer to the codebase. For operational procedures, see README.md.
