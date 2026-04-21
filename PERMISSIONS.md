# Permission Management System

## Overview

The T4M User Manager implements a **role-based permission system** that controls access to various resources within the application. Permissions are organized by **organization** and **role**, enabling fine-grained access control across different pilot organizations.

## Core Concepts

### Permission Structure

Each permission consists of three components:

- **Organization**: The pilot organization (e.g., "ATC"")
- **Role**: The user's role within that organization (e.g., "IT", "MANAGEMENT")
- **Resource**: The system resource being accessed (e.g., "USER", "ORGANIZATION")
- **Scope**: The level of access granted (e.g., "View", "Manage")

### Permission Hierarchy

Permission scopes follow a hierarchical model where higher scopes inherit lower scope capabilities:

```
MANAGE > VIEW > NONE
```

- **MANAGE**: Full access including create, update, delete operations (includes VIEW)
- **VIEW**: Read-only access to resources
- **NONE**: No access to the resource

**Example**: A user with `MANAGE` scope on a resource automatically has `VIEW` permissions as well.

### Available Resources

The system defines permissions for the following resources:

- `ORGANIZATION` - Organization Management
- `PERMISSION` - Permission Management
- `USER` - User Management
- `ROLE` - Role Management
- `CONTRACT` - Contract Management
- `MS_REQUEST` - Manufacturing Service Request
- `PRODUCTION_ORDER` - Production Order
- `TECHNICAL_DOCUMENTATION` - Technical Documentation
- `FOLLOW_UP_INFO` - Follow-up Information
- `NEGOTIATION` - Negotiation
- `PERFORMANCE_RATING` - Performance Rating

## Token-Based Validation

### How It Works

The permission system integrates with JWT authentication to validate user permissions:

1. **User Authentication**: User authenticates and receives a JWT token containing:
   - User ID
   - Pilot Code (organization)
   - User Role

2. **Permission Check**: When accessing a protected resource, the system:
   - Extracts user information from the JWT token
   - Queries the permission matrix for the user's organization and role
   - Checks if the required permission exists with sufficient scope

3. **Access Decision**:
   - **Granted** if user has the exact permission or a higher scope
   - **Denied** otherwise

### API-Based Validation

Check if a user has specific permissions:

```http
GET /api/permissions/users/{userId}/permissions/{resource}/{scope}
```

**Example Request**:
```http
GET /api/permissions/users/123e4567-e89b-12d3-a456-426614174000/permissions/USER/Manage
Authorization: Bearer <jwt-token>
```

**Response (Success) - 200 Status Code (OK)**:
```json
{
  "data": true,
  "message": "User has the required permission",
  "success": true
}
```

**Response (Denied) - 4xx Status Code (Forbidden)**:
```json
{
  "data": false,
  "message": "User does not have the required permission",
  "success": true
}
```

### Programmatic Validation

Within application code, use the `IPermissionService`:

```java
@Autowired
private IPermissionService permissionService;

// Check if user has permission
boolean hasAccess = permissionService.hasPermission(
    userOrganization,  // From JWT: pilotCode
    userRole,          // From JWT: role
    "USER",            // Resource to access
    "Manage"           // Required scope
);

if (hasAccess) {
    // Proceed with operation
} else {
    // Deny access
}
```

## Permission Management

### Retrieve Organization Permissions

Get the complete permission matrix for an organization:

```http
GET /api/permissions/organizations/{organization}
```

### Retrieve Role-Specific Permissions

Get permissions for a specific role within an organization:

```http
GET /api/permissions/organizations/{organization}/roles/{role}
```

### Update Permissions

Update one or more permissions for an organization:

```http
PUT /api/permissions/organizations/{organization}
Content-Type: application/json

[
  {
    "organization": "ATC",
    "role": "admin",
    "resource": "USER",
    "scope": "Manage"
  }
]
```

### Get All User Permissions

Retrieve all permissions for a specific user:

```http
GET /api/permissions/users/{userId}/permissions
```

**Response**:
```json
{
  "data": {
    "userId": "123e4567-e89b-12d3-a456-426614174000",
    "permissions": {
      "USER": "Manage",
      "ORGANIZATION": "View",
      "CONTRACT": "Manage"
    }
  },
  "message": "User permissions retrieved successfully",
  "success": true
}
```

## Configuration

### Enabling/Disabling Permissions

# Database configuration for permissions
When a new organization is created, User management component receives also the VN it belongs
Based on the VN the matrix of the permissions is computed statically. 

## Use Cases

### Example 1: Protecting an Endpoint

```java
@PostMapping("/api/users")
public ResponseEntity<User> createUser(@RequestBody UserDto userDto) {
    // Extract user info from JWT (automatically done via JwtContext)
    String organization = jwtContext.getPilotCode();
    String role = jwtContext.getRole();

    // Check permission
    boolean canManageUsers = permissionService.hasPermission(
        organization,
        role,
        "USER",
        "Manage"
    );

    if (!canManageUsers) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    // Proceed with user creation
    User newUser = userService.createUser(userDto);
    return ResponseEntity.ok(newUser);
}
```

### Example 2: Hierarchical Permissions

A user with `MANAGE` scope automatically has `VIEW` access:

```java
// User has "Manage" scope on ORGANIZATION resource
boolean canView = permissionService.hasPermission(
    "ATC",
    "MANAGEMENT",
    "ORGANIZATION",
    "View"  // Checking for View access
);
// Returns TRUE because Manage > View
```

## Security Considerations

- All permission API endpoints require JWT authentication
- Permissions are validated on **every request** for protected resources
- JWT tokens contain immutable user information (pilotCode, role) that cannot be tampered with
- Permission changes take effect immediately without requiring user re-authentication
- The system supports case-insensitive resource and scope matching for flexibility
