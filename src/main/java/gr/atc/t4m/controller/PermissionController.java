package gr.atc.t4m.controller;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserPermissionsDto;
import gr.atc.t4m.enums.PermissionResource;
import gr.atc.t4m.enums.PermissionScope;
import gr.atc.t4m.service.interfaces.IPermissionService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.StringNormalizationUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.EnumSet;
import java.util.List;

@RestController
@Validated
@Tag(name = "Permission Controller", description = "Handles Static Permission Lookups")
@RequestMapping("/api/permissions")
public class PermissionController {

    private final IPermissionService permissionService;

    private final IUserManagementService userManagementService;

    public PermissionController(IPermissionService permissionService, IUserManagementService userManagementService) {
        this.userManagementService = userManagementService;
        this.permissionService = permissionService;
    }

    /**
     * Retrieve all permissions for a specific organization
     *
     * @param organization Organization name to retrieve permissions for
     * @return List of permissions for the organization
     */
    @Operation(summary = "Retrieve all permissions for an organization",
            description = "Fetches the static permission matrix associated with the organization's Value Network type.",
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")})
            @ApiResponse(responseCode = "404", description = "Organization not found")
    @GetMapping("/organizations/{organization}")
    public ResponseEntity<BaseAppResponse<List<PermissionDto>>> retrievePermissionsForOrganization(
            @Parameter(description = "Organization name", example = "ATC")
            @PathVariable @NotBlank String organization) {
        List<PermissionDto> permissions = permissionService.retrieveOrganizationPermissionMatrix(StringNormalizationUtils.normalize(organization));
        return new ResponseEntity<>(BaseAppResponse.success(permissions, "Permissions for organization retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve permissions for a specific role within an organization
     *
     * @param organization Organization name
     * @param role Role name to filter permissions
     * @return List of permissions for the specified role in the organization
     */
    @Operation(summary = "Retrieve permissions for a specific role in an organization",
            description = "Fetches all permissions assigned to a specific role within the specified organization.",
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token"),
            @ApiResponse(responseCode = "404", description = "Organization or role not found")
    })
    @GetMapping("/organizations/{organization}/roles/{role}")
    public ResponseEntity<BaseAppResponse<List<PermissionDto>>> retrievePermissionsForRoleInOrganization(
            @Parameter(description = "Organization name", example = "ATC")
            @PathVariable @NotBlank String organization,
            @Parameter(description = "Role name", example = "admin")
            @PathVariable @NotBlank String role) {
        List<PermissionDto> permissions = permissionService.retrievePermissionsForOrganizationAndRole(StringNormalizationUtils.normalize(organization), StringNormalizationUtils.normalize(role));
        return new ResponseEntity<>(BaseAppResponse.success(permissions, "Permissions for role in organization retrieved successfully"), HttpStatus.OK);
    }

    

    /**
     * Check if a specific user has a given permission
     *
     * @param userId User identifier
     * @param resource Resource to check permission for
     * @param scope Permission scope to verify
     * @return Boolean indicating whether user has the permission
     */
    @Operation(summary = "Check user permission",
            description = "Verifies if a specific user has the required permission for a given resource and scope. " +
                    "Returns true if permission exists, false otherwise.",
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User has the required permission"),
            @ApiResponse(responseCode = "400", description = "Invalid resource or scope"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token"),
    @ApiResponse(responseCode = "403", description = "User does not have the required permission"),
            @ApiResponse(responseCode = "404", description = "User not found")})
    @GetMapping("/users/{userId}/permissions/{resource}/{scope}")
    public ResponseEntity<BaseAppResponse<Boolean>> checkUserPermission(
            @Parameter(description = "User unique identifier", example = "123e4567-e89b-12d3-a456-426614174000")
            @PathVariable @NotBlank String userId,
            @Parameter(description = "Resource identifier", example = "User")
            @PathVariable @NotBlank String resource,
            @Parameter(description = "Permission scope", example = "Manage")
            @PathVariable @NotBlank String scope) {
        // Validate resource and scope
        if (!PermissionResource.isValid(resource)) {
            return new ResponseEntity<>(BaseAppResponse.error("Invalid input resource"), HttpStatus.BAD_REQUEST);
        }
        if (!PermissionScope.isValid(scope)) {
            return new ResponseEntity<>(BaseAppResponse.error("Invalid input scope"), HttpStatus.BAD_REQUEST);
        }
        // Retrieve user details
        UserDto user = userManagementService.retrieveUserById(userId);
        boolean hasPermission = permissionService.hasPermission(
                user.getPilotCode(),
                user.getUserRole(),
                resource,
                scope);
        if (hasPermission) {
            return new ResponseEntity<>(BaseAppResponse.success(true, "User has the required permission"), HttpStatus.OK);
        }
        return new ResponseEntity<>(BaseAppResponse.success(false, "User does not have the required permission"), HttpStatus.FORBIDDEN);
    }

    /**
     * Retrieve all permissions for a specific user
     *
     * @param userId User identifier
     * @return UserPermissionsDto containing userId and permissions map
     */
    @Operation(
            summary = "Get all user permissions as resource-to-scope map",
            description = """
                    Retrieves all permissions for a specific user in a simplified map format.

                    **Returns:**
                    - User ID
                    - Permissions map: resource name -> permission scope
                    """,
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User permissions retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token"),
            @ApiResponse(responseCode = "404", description = "User not found")})
    @GetMapping("/users/{userId}/permissions")
    public ResponseEntity<BaseAppResponse<UserPermissionsDto>> getAllUserPermissions(
            @Parameter(
                    description = "User unique identifier",
                    example = "123e4567-e89b-12d3-a456-426614174000",
                    required = true)
            @PathVariable @NotBlank String userId) {

        UserPermissionsDto userPermissions = permissionService.retrieveAllUserPermissions(userId);

        return new ResponseEntity<>(
                BaseAppResponse.success(userPermissions, "User permissions retrieved successfully"),
                HttpStatus.OK);
    }

    /**
     * Retrieve all available permission scopes
     *
     * @return List of all permission scope names
     */
    @Operation(summary = "Get all available permission scopes",
            description = "Returns a list of all defined permission scopes in the system (e.g., READ, WRITE, READ_WRITE, NONE).",
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Scopes retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")})
    @GetMapping("/scopes")
    public ResponseEntity<BaseAppResponse<List<String>>> retrieveAllScopes() {
        List<String> scopes = EnumSet.allOf(PermissionScope.class).stream().map(Enum::name).toList();
        return new ResponseEntity<>(BaseAppResponse.success(scopes, "All scopes retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all available permission resources
     *
     * @return List of all permission resource names
     */
    @Operation(summary = "Get all available permission resources",
            description = "Returns a list of all defined permission resources in the system (e.g., USERS, ORGANIZATIONS, PILOTS).",
            security = @SecurityRequirement(name = "bearer"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Resources retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")})
    @GetMapping("/resources")
    public ResponseEntity<BaseAppResponse<List<String>>> retrieveAllResources() {
        List<String> resources = EnumSet.allOf(PermissionResource.class).stream().map(Enum::name).toList();
        return new ResponseEntity<>(BaseAppResponse.success(resources, "All resources retrieved successfully"), HttpStatus.OK);
    }
}   
