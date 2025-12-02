# T4M User Manager Service

## Overview

The T4M User Manager is a Spring Boot microservice that provides authentication and authorization services for the Tec4MaaSEs platform. It acts as a central gateway between frontend applications and Keycloak, offering domain-specific APIs for user management, role-based access control and organization synchronization.

**Key Capabilities:**
- OAuth2/OpenID Connect authentication with JWT tokens
- Multi-tenant user and organization management
- Role-based access control with three-tier hierarchy
- Kafka-driven organization synchronization
- High-performance caching with Caffeine
- Comprehensive observability and health monitoring

For detailed architecture, component design and data flows, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Deployment](#deployment)
7. [API Documentation](#api-documentation)
8. [License](#license)
9. [Contributors](#contributors)

---

## Quick Start

Get the service running locally:

```bash
# Clone the repository
git clone https://[username]@bitbucket.org/atc-code/ilab-tec4maases-user-manager.git
cd ilab-tec4maases-user-manager

# Start Keycloak and PostgreSQL with Docker Compose
cd keycloak && docker compose up -d

# Configure User Manager with env variables in properties file

# Build and run the service
mvn spring-boot:run
```

The service will be available at `http://localhost:8094` with OpenAPI documentation at `http://localhost:8094/api/user-manager/swagger-ui/index.html`.

---

## Prerequisites

### Required Software

- **Java 21** or higher (for virtual threads support)
- **Maven 3.9+** for building the project
- **Docker** and **Docker Compose** (for local Keycloak deployment)
- **Keycloak 16.1.1** with PostgreSQL backend
- **Apache Kafka** (optional, for organization event synchronization)

### External Services

The service requires the following external dependencies:

1. **Keycloak Instance**: Identity provider for authentication and user storage
2. **SMTP Server**: For sending activation and password reset emails
3. **Kafka Broker** (optional): For receiving organization management events

---

## Installation

### 1. Clone the Repository

```bash
git clone https://[username]@bitbucket.org/atc-code/ilab-tec4maases-user-manager.git
cd ilab-tec4maases-user-manager
```

### 2. Install Dependencies

```bash
mvn clean install
```

This will download all required dependencies and run the test suite to verify the installation.

### 3. Set Up Keycloak

#### Option A: Using Docker Compose (Recommended for Development)

The repository includes a `docker-compose.yml` file in the `keycloak` directory that starts Keycloak with PostgreSQL:

```bash
cd keycloak && docker compose up -d
```

This will start:
- PostgreSQL database on port 5432
- Keycloak on port 9080

**Default Keycloak Credentials:**
- Admin Username: `admin`
- Admin Password: `admin`
- Realm: Use the provided `realm_export.json` (automatically)

#### Option B: Using Existing Keycloak Instance

If you have an existing Keycloak deployment, ensure it meets these requirements:

1. Keycloak version 16.1.1 or compatible
2. A dedicated realm for T4M (e.g., `tec4maases`)
3. A confidential client configured with:
   - Valid redirect URIs
   - Service account enabled for admin operations
   - Client authentication enabled

---

## Configuration

### Environment Variables

All sensitive configuration should be provided via environment variables. Create a `.env` file or export these variables:

#### Required Configuration

```bash
# Application Settings
APP_PORT=8094
APP_URL=http://localhost:8094
APP_FRONTEND_URL=http://localhost:3000

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:9080
KEYCLOAK_REALM=t4m
KEYCLOAK_CLIENT_ID=t4m-client
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# CORS Configuration
CORS_DOMAINS=http://localhost:3000,http://localhost:3001

# Email Configuration (Gmail example)
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_APP_PASSWORD=your-app-specific-password
```

#### Optional Configuration

```bash
# Kafka Configuration (for organization synchronization)
KAFKA_CONNECTION_TYPE=INTERNAL                          # INTERNAL (default, no SSL) or EXTERNAL (with SSL/SASL)
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPICS=dataspace-organization-onboarding          # Kafka topic to consume from

# Kafka External/SSL Configuration (only needed when KAFKA_CONNECTION_TYPE=EXTERNAL)
KAFKA_USERNAME=your-kafka-username                      # SASL username
KAFKA_PASSWORD=your-kafka-password                      # SASL password
KAFKA_CERT_PATH=certs/kafka-ca.crt                      # Path to CA certificate (PEM format, in classpath)

# Distributed Tracing Configuration (Jaeger/OpenTelemetry)
TRACING_ENABLED=false                                   # Enable/disable distributed tracing
OTLP_ENDPOINT=http://localhost:4318/v1/traces           # OpenTelemetry collector endpoint

# Cache Configuration (defaults shown)
CACHE_PILOT_ROLES_TTL=3600        # 1 hour
CACHE_PILOT_CODES_TTL=1800        # 30 minutes
CACHE_USER_ROLES_TTL=3600         # 1 hour
CACHE_USERS_TTL=600               # 10 minutes
CACHE_MAX_SIZE=10000              # Max entries per cache
```

### Application Properties

The `src/main/resources/application.properties` file contains default values that can be overridden by environment variables:

```properties
# Server Configuration
server.port=${APP_PORT:8094}
application.url=${APP_URL:http://localhost:8094}

# Keycloak Configuration
keycloak.url=${KEYCLOAK_URL:http://localhost:9080}
keycloak.realm=${KEYCLOAK_REALM:t4m}
keycloak.client-id=${KEYCLOAK_CLIENT_ID:t4m-client}
keycloak.client-secret=${KEYCLOAK_CLIENT_SECRET}
keycloak.admin-username=${KEYCLOAK_ADMIN_USERNAME:admin}
keycloak.admin-password=${KEYCLOAK_ADMIN_PASSWORD:admin}

# CORS Configuration
spring.security.cors.domains=${CORS_DOMAINS:http://localhost:3000}

# Email Configuration
spring.mail.host=${MAIL_HOST:smtp.gmail.com}
spring.mail.port=${MAIL_PORT:587}
spring.mail.username=${MAIL_USERNAME}
spring.mail.password=${MAIL_APP_PASSWORD}
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

# Frontend URL (for email links)
app.frontend.url=${APP_FRONTEND_URL:http://localhost:3000}
```

### Email Configuration Guide

#### Gmail Setup

1. Enable 2-factor authentication on your Google account
2. Generate an app-specific password:
   - Go to Google Account → Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
3. Use the generated password as `MAIL_APP_PASSWORD`

#### Other Email Providers

For different SMTP providers, adjust the `MAIL_HOST` and `MAIL_PORT`:

```bash
# Microsoft 365 / Outlook
MAIL_HOST=smtp.office365.com
MAIL_PORT=587

# Google
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
```

### Kafka Configuration Guide

The service supports two Kafka connection modes controlled by `KAFKA_CONNECTION_TYPE`:

#### Internal Mode (Default - No SSL)

For local development and testing environments:

```bash
KAFKA_CONNECTION_TYPE=INTERNAL
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPICS=dataspace-organization-onboarding
```

**Behavior:**
- No SSL/TLS encryption
- No SASL authentication
- Suitable for local Docker Compose Kafka instances
- Lower latency, simpler configuration

#### External Mode (SSL/SASL Authentication)

For production and external Kafka brokers:

```bash
KAFKA_CONNECTION_TYPE=EXTERNAL
KAFKA_BOOTSTRAP_SERVERS=kafka.production.example.com:9093
KAFKA_TOPICS=dataspace-organization-onboarding
KAFKA_USERNAME=your-kafka-username
KAFKA_PASSWORD=your-kafka-password
KAFKA_CERT_PATH=certs/kafka-ca.crt
```

**Behavior:**
- SSL/TLS encryption enabled (`SASL_SSL` protocol)
- SASL authentication with `SCRAM-SHA-512` mechanism
- CA certificate loaded from classpath (PEM format)
- Required for secure production deployments

**CA Certificate Setup:**
1. Obtain the Kafka broker's CA certificate in PEM format
2. Place it in `src/main/resources/certs/kafka-ca.crt` (or another classpath location)
3. Set `KAFKA_CERT_PATH` to the classpath path (e.g., `certs/kafka-ca.crt`)

**Note:** The certificate path is relative to the classpath root (`src/main/resources`), not the filesystem.

### Distributed Tracing Configuration

Enable distributed tracing with Jaeger for request path visualization:

```bash
# Enable tracing
TRACING_ENABLED=true

# Point to Jaeger collector (OTLP endpoint)
OTLP_ENDPOINT=http://localhost:4318/v1/traces

# Start Jaeger with Docker Compose
docker-compose up jaeger

# Access Jaeger UI at http://localhost:16686
```

**Benefits:**
- Trace IDs automatically added to logs for correlation
- Visualize request flows across service boundaries
- Identify performance bottlenecks with span timing
- Debug production issues by searching traces in Jaeger UI

**Performance:**
- When disabled (`false`): Zero overhead, no tracing infrastructure loaded
- When enabled (`true`): ~1-2% CPU overhead with 100% sampling

For detailed tracing documentation, see [ARCHITECTURE.md - Distributed Tracing](ARCHITECTURE.md#distributed-tracing--observability).

---

## Running the Application

### Development Mode

Run directly with Maven (hot reload enabled):

```bash
mvn spring-boot:run
```

The application will start with the Spring Boot DevTools active, allowing for automatic restarts on code changes.

### Production Mode

Build and run the JAR file:

```bash
# Build the application
mvn clean package -DskipTests

# Run the JAR
java -jar target/t4m-user-manager-0.6.jar
```

### With Environment Variables

```bash
# Linux/macOS
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_CLIENT_SECRET=your-secret
mvn spring-boot:run

# Windows PowerShell
$env:KEYCLOAK_URL="https://keycloak.example.com"
$env:KEYCLOAK_CLIENT_SECRET="your-secret"
mvn spring-boot:run
```

### Verify Application Started

Once running, verify the application is healthy:

```bash
# Check health endpoint
curl http://localhost:8094/actuator/health

# Expected response
{
  "status": "UP",
  "components": {
    "keycloak": { "status": "UP" },
    "diskSpace": { "status": "UP" }
  }
}
```

---

## Deployment

### Docker Deployment

#### Build Docker Image

```bash
# Build the application JAR
mvn clean package -DskipTests

# Build Docker image
docker build -t t4m-user-manager:0.6 .
```

#### Run Docker Container

```bash
# Run with environment variables
docker run -d \
  -p 8094:8094 \
  --name t4m-user-manager \
  -e KEYCLOAK_URL=http://keycloak:9080 \
  -e KEYCLOAK_REALM=t4m \
  -e KEYCLOAK_CLIENT_ID=t4m-client \
  -e KEYCLOAK_CLIENT_SECRET=your-secret \
  -e KEYCLOAK_ADMIN_USERNAME=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e MAIL_HOST=smtp.gmail.com \
  -e MAIL_PORT=587 \
  -e MAIL_USERNAME=your-email@gmail.com \
  -e MAIL_APP_PASSWORD=your-app-password \
  -e CORS_DOMAINS=https://app.example.com \
  -e APP_FRONTEND_URL=https://app.example.com \
  t4m-user-manager:0.6
```

---

## API Documentation

### OpenAPI/Swagger UI

Interactive API documentation is available when the application is running:

**URL:** `http://localhost:8094/api/user-manager/swagger-ui/index.html`

The Swagger UI provides:
- Complete API endpoint documentation
- Request/response schema definitions
- Try-it-out functionality for testing endpoints
- Authentication configuration for protected endpoints

### OpenAPI Specification

Download the OpenAPI 3.0 specification in JSON format:

**URL:** `http://localhost:8094/api/user-manager/v3/api-docs`

This can be imported into API clients like Postman or Insomnia.

### API Endpoints Overview

**User Management:**
- `POST /api/users/authenticate` - Login with credentials
- `POST /api/users/refresh-token` - Refresh access token
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update current user profile
- `POST /api/users/logout` - Logout current user

**Admin Operations:**
- `GET /api/admin/pilots` - List all organizations
- `POST /api/admin/pilots` - Create new organization
- `GET /api/admin/users` - List users in organization
- `POST /api/admin/users` - Create new user
- `DELETE /api/admin/cache/reset` - Clear all caches

For complete endpoint documentation, see the Swagger UI or [ARCHITECTURE.md](ARCHITECTURE.md#api-layer-controllers).

---

### Getting Help

For detailed architecture information, see [ARCHITECTURE.md](ARCHITECTURE.md#troubleshooting--observability).

---

## Testing

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=UserManagementServiceTests

# Run with coverage report
mvn clean test jacoco:report
```

### Test Coverage

View the coverage report after running tests:

```bash
# Open in browser
open target/site/jacoco/index.html
```

---

## License

This project has received funding from the European Union's Horizon 2022 research and innovation programme, under Grant Agreement 101138517.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.

---

## Contributors

**Maintainer:** Alkis Aznavouridis (<a.aznavouridis@atc.gr>)

**Organization:** Athens Technology Center (ATC)

---

## Additional Resources

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Comprehensive architecture documentation
- **[Swagger UI](http://localhost:8094/api/user-manager/swagger-ui/index.html)** - Interactive API documentation
- **[Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/3.5.7/reference/html/)**
- **[Keycloak Documentation](https://www.keycloak.org/docs/16.1/)**
