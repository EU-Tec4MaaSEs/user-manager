package gr.atc.t4m.controller;

import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.JwtUtils;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    /**
     * System Roles (Pilot Roles): Roles that are assigned to a User when he signs-up and define their privileges
     * Pilots (Pilot Codes): Use case organizations
     * User Roles : Roles of user within the organization (Specific roles)
     */
    private final IKeycloakAdminService adminService;
    private final IUserManagementService userManagementService;

    private static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN";
    private static final String GLOBAL_PILOT_CODE = "ALL";

    public AdminController(IKeycloakAdminService adminService, IUserManagementService userManagementService) {
        this.adminService = adminService;
        this.userManagementService = userManagementService;
    }

    /*
     * Pilot Roles
     */

    /**
     * GET all System Roles or filter by Pilot (Based on the provided Pilot Role via JWT Token)
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilot Roles
     */
    @Operation(summary = "Retrieve all pilot roles (System generic roles)", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot/System roles retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping("/system/roles")
    public ResponseEntity<BaseAppResponse<List<String>>> retrieveAllSystemRoles(@AuthenticationPrincipal Jwt jwt) {
        // Validate token proper format
        String role = JwtUtils.extractPilotRole(jwt);

        // Set the flag to true or false according to the Role of User
        boolean isSuperAdmin = role.equalsIgnoreCase(SUPER_ADMIN_ROLE);

        return new ResponseEntity<>(BaseAppResponse.success(adminService.retrieveAllPilotRoles(isSuperAdmin), "Pilot/System roles retrieved successfully"), HttpStatus.OK);
    }

    /*
     * Pilots - Pilot Codes
     */

    /**
     * GET all Pilots (Pilot Codes) - Valid only for Super Admins
     *
     * @return List<String> : List of Pilots
     */
    @Operation(summary = "[SUPER_ADMIN] Retrieve all pilots from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot codes retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
    })
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/pilots")
    public ResponseEntity<BaseAppResponse<List<String>>> retrieveAllPilots() {
        return new ResponseEntity<>(BaseAppResponse.success(adminService.retrieveAllPilotCodes(), "Pilot codes retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Create a new Pilot in Keycloak
     *
     * @return Success message or Failure Message
     */
    @Operation(summary = "[SUPER_ADMIN] Create a new Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Pilot created successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "409", description = "Resource already exists")
    })
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @PostMapping("/pilots/create")
    @Hidden
    public ResponseEntity<BaseAppResponse<Void>> createPilot(@Parameter(
            description = "Pilot information",
            required = true) @Valid @RequestBody PilotCreationDto pilotData) {
        adminService.createPilot(pilotData);
        return new ResponseEntity<>(BaseAppResponse.success(null, "Pilot created successfully"), HttpStatus.CREATED);
    }

    /**
     * Delete a Pilot in Keycloak
     *
     * @param pilotName : Pilot name
     * @return Success message or Failure Message
     */
    @Operation(summary = "[SUPER_ADMIN] Delete an existing Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
    })
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping("/pilots/{pilotName}")
    public ResponseEntity<BaseAppResponse<Void>> deletePilotByName(@Parameter(
            name = "pilotName",
            description = "Name of the Pilot",
            example = "Test_Pilot",
            required = true) @PathVariable String pilotName) {
        // Delete Pilot in Keycloak
        adminService.deletePilotByName(pilotName.trim().toUpperCase());
        return new ResponseEntity<>(BaseAppResponse.success(null, "Pilot deleted successfully"), HttpStatus.OK);
    }

    /**
     * Update a Pilot in Keycloak
     */
    @Operation(summary = "Update an existing Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot updated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "403", description = "You are not authorized to update information on this pilot"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @PutMapping("/pilots/{pilotName}")
    public ResponseEntity<BaseAppResponse<Void>> updatePilot(@AuthenticationPrincipal Jwt jwt,
                                                              @Parameter(name = "pilotName",
                                                                      description = "Name of the Pilot",
                                                                      required = true) @PathVariable String pilotName,
                                                              @Parameter(name = "pilotData",
                                                                      description = "Updated pilot information - Not all fields required",
                                                                      required = true) @Valid @RequestBody PilotDto pilotData) {

        String pilotRole = JwtUtils.extractPilotRole(jwt);

        // Check if the user is a Super Admin
        if (!pilotRole.equalsIgnoreCase(SUPER_ADMIN_ROLE)) {
            String userId = JwtUtils.extractUserId(jwt);
            UserDto user = userManagementService.retrieveUserById(userId);
            if (!user.getPilotCode().equalsIgnoreCase(pilotName.trim().toUpperCase())) {
                return new ResponseEntity<>(BaseAppResponse.error("You are not authorized to update information on this pilot"), HttpStatus.FORBIDDEN);
            }
        }
        pilotData.setName(pilotName.trim().toUpperCase());

        // Update Pilot in Keycloak
        adminService.updatePilotByName(pilotData);
        return new ResponseEntity<>(BaseAppResponse.success(null, "Pilot updated successfully"), HttpStatus.OK);
    }


    /*
     * User Roles (Specific roles in Platform - Pilot)
     */

    /**
     * Create a new User Role in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Create a new User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User role created successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failed | Thrown when input data are invalid or required data are missing"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "409", description = "Resource already exists")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @PostMapping("/roles/create")
    public ResponseEntity<BaseAppResponse<Void>> createNewUserRole(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody UserRoleCreationDto userRole) {
        // Create User Role in Keycloak
        adminService.createUserRole(userRole);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User role created successfully"), HttpStatus.CREATED);
    }

    /**
     * Delete a User Role in Keycloak
     *
     * @param jwt      : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Delete a User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @DeleteMapping("/roles/{roleName}")
    public ResponseEntity<BaseAppResponse<Void>> deleteUserRole(@AuthenticationPrincipal Jwt jwt, @Parameter(
            name = "roleName",
            description = "Name of the role",
            example = "Test_User_Role",
            required = true) @PathVariable String roleName) {
        // Delete a User Role in Keycloak
        adminService.deleteUserRole(roleName.trim().toUpperCase());
        return new ResponseEntity<>(BaseAppResponse.success(null, "User role deleted successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve a User Role in Keycloak
     *
     * @param jwt      : JWT Token
     * @param roleName : Name of the Role
     * @return UserRoleDTO
     */
    @Operation(summary = "Retrieve a User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping("/roles/{roleName}")
    public ResponseEntity<BaseAppResponse<UserRoleDto>> retrieveUserRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String roleName) {
        // Fetch User Role given the Role Name (if exists)
        UserRoleDto userRole = adminService.retrieveUserRoleByName(roleName.trim().toUpperCase());
        return new ResponseEntity<>(BaseAppResponse.success(userRole, "User role retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Update a User Role in Keycloak
     *
     * @param jwt      : JWT Token
     * @param roleName : Name of the Role
     * @return Success message or Failure Message
     */
    @Operation(summary = "Update a User Role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role updated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @PutMapping("/roles/{roleName}")
    public ResponseEntity<BaseAppResponse<Void>> updateUserRole(@AuthenticationPrincipal Jwt jwt,
                                                                @Parameter(name = "roleName",
                                                                        description = "Name of the role",
                                                                        required = true) @PathVariable String roleName,
                                                                @Parameter(name = "userRole",
                                                                        description = "Updated user role information - Not all fields required",
                                                                        required = true) @Valid @RequestBody UserRoleDto userRole) {
        // If name was given convert it to upper case if not already defined that way
        userRole.setName(roleName.trim().toUpperCase());

        // Create User Role in Keycloak
        adminService.updateUserRole(userRole);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User role updated successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak User Roles
     *
     * @param jwt : JWT Token
     * @return List<UserRoleDTO> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping("/roles")
    public ResponseEntity<BaseAppResponse<List<UserRoleDto>>> retrieveAllUserRoles(@AuthenticationPrincipal Jwt jwt) {
        String pilotRole = JwtUtils.extractPilotRole(jwt);
        boolean isSuperAdmin = pilotRole.equalsIgnoreCase(SUPER_ADMIN_ROLE);

        return new ResponseEntity<>(BaseAppResponse.success(adminService.retrieveAllUserRoles(isSuperAdmin), "User roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all Keycloak User Roles filtered by Pilot Role
     *
     * @param jwt       : JWT Token
     * @param pilotRole : Pilot Role
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all user roles filtered by Pilot Role ('ADMIN', 'USER', etc.)", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User roles retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access")
    })
    @Hidden
    @GetMapping("/roles/type/{pilotRole}")
    public ResponseEntity<BaseAppResponse<List<String>>> retrieveAllUserRolesPerPilotRole(@AuthenticationPrincipal Jwt jwt,
                                                                                          @Parameter(name = "pilotRole",
                                                                                                  description = "Pilot role existent in Keycloak",
                                                                                                  required = true)
                                                                                          @PathVariable String pilotRole) {
        String pilot = JwtUtils.extractPilotCode(jwt);

        List<String> userRoles;
        if (pilot.equalsIgnoreCase(GLOBAL_PILOT_CODE))
            userRoles = adminService.retrieveAllUserRolesByType(pilotRole.trim().toUpperCase());
        else
            userRoles = adminService.retrieveAllUserRolesByTypeAndPilot(pilotRole.trim().toUpperCase(), pilot.trim().toUpperCase());

        return new ResponseEntity<>(BaseAppResponse.success(userRoles, "User roles retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Assign a User Role to a Pilot
     *
     * @param pilotCode : Pilot Code
     * @param userRole  : User Role to assign
     * @param jwt       : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Assign User Role to specific Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User role assigned successfully to pilot"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @Hidden
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @PutMapping("/pilots/{pilotCode}/assign/roles/{userRole}")
    public ResponseEntity<BaseAppResponse<Void>> assignUserRoleToPilot(@AuthenticationPrincipal Jwt jwt, @PathVariable String pilotCode, @PathVariable String userRole) {
        String formattedInputUserRole = userRole.trim().toUpperCase();
        String formattedInputPilotCode = pilotCode.trim().toUpperCase();

        // Assign User Role to Pilot
        adminService.assignUserRoleToPilot(formattedInputUserRole, formattedInputPilotCode);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User role assigned successfully to pilot"), HttpStatus.OK);
    }

}
