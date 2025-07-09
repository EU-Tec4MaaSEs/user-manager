package gr.atc.t4m.controller;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.PasswordsDto;
import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IUserAuthService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.JwtUtils;
import gr.atc.t4m.validation.ValidPassword;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Email;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@Slf4j
@Tag(name = "User Manager Controller", description = "Handles the API requests for User Authentication and Management")
public class UserController {

    private final IUserAuthService userAuthService;

    private final IUserManagementService userManagerService;

    private final IEmailService emailService;

    private static final String USER_ROLE = "USER";
    private static final String ADMIN_ROLE = "ADMIN";
    private static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN";
    private static final String GLOBAL_PILOT_CODE = "ALL";
    private static final String UNAUTHORIZED_ACTION = "You are unauthorized to request/modify this resource";

    //private final IEmailService emailService;

    public UserController(IUserAuthService userAuthService, IUserManagementService userManagerService, IEmailService emailService) {
        this.userAuthService = userAuthService;
        this.userManagerService = userManagerService;
        this.emailService = emailService;
    }

    /**
     * POST user credentials to generate a token from Keycloak
     *
     * @param credentials : Email and password of user
     * @return AuthenticationResponse
     */
    @Operation(summary = "Authenticate user given credentials", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication token generated successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failed")})
    @PostMapping(value = "/authenticate")
    public ResponseEntity<BaseAppResponse<AuthenticationResponseDto>> authenticateUser(@Valid @RequestBody CredentialsDto credentials) {
        return new ResponseEntity<>(
                BaseAppResponse.success(userAuthService.authenticate(credentials), "Authentication token generated successfully"),
                HttpStatus.OK);
    }

    /**
     * POST refresh token to refresh user's token before expiration
     *
     * @param refreshToken : Refresh Token
     * @return AuthenticationResponse
     */
    @Operation(summary = "Refresh user token", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication token generated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid / No input was given for requested resource")})
    @PostMapping(value = "/refresh-token")
    public ResponseEntity<BaseAppResponse<AuthenticationResponseDto>> refreshToken(@Parameter(name = "refreshToken", required = true, description = "JWT Refresh Token value") @RequestParam(name = "token") String refreshToken) {
        return new ResponseEntity<>(
                BaseAppResponse.success(userAuthService.refreshToken(refreshToken), "Authentication token generated successfully"),
                HttpStatus.OK);
    }

    /**
     * Logout user
     *
     * @param jwt : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Logout user", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(
            value = {@ApiResponse(responseCode = "200", description = "User logged out successfully"),
                    @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again."),
            })
    @PostMapping(value = "/logout")
    public ResponseEntity<BaseAppResponse<String>> logoutUser(@AuthenticationPrincipal Jwt jwt) {
        String userId = JwtUtils.extractUserId(jwt);
        userManagerService.logoutUser(userId);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User logged out successfully"),
                HttpStatus.OK);
    }

    /**
     * Creation of a new User by Super-Admin or Admin
     * Depends on the type of User implementing the request uses will be able
     * -  Admins can only create personnel inside their organization
     * -  Super Admins can create personnel for all pilots and create new Super Admins also
     *
     * @param newUser : User information
     * @param jwt     : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Create a new user in Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User created successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "409", description = "Resource already exists")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @PostMapping(value = "/create")
    public ResponseEntity<BaseAppResponse<String>> createUser(@RequestBody @Valid UserCreationDto newUser, @AuthenticationPrincipal Jwt jwt) {
        String authorizeUserPilotRole = JwtUtils.extractPilotRole(jwt);
        String authorizeUserPilotCode = JwtUtils.extractPilotCode(jwt);

        // Ensure that only Super Admins can create new Super Admins
        if (newUser.pilotRole().equals(SUPER_ADMIN_ROLE) && !authorizeUserPilotRole.equalsIgnoreCase(SUPER_ADMIN_ROLE))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "Only Super Admins can create other Super Admin users"), HttpStatus.FORBIDDEN);

        // Ensure that Admins can create personnel only inside their organization
        if (authorizeUserPilotRole.equals(ADMIN_ROLE) && !authorizeUserPilotCode.equalsIgnoreCase(newUser.pilotCode()))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "Admins can only create personnel inside their organization"), HttpStatus.FORBIDDEN);

        // Generate the activation token and create User
        String autogeneratedToken = UUID.randomUUID().toString();
        String userId = userManagerService.createUser(newUser, autogeneratedToken);

        UserDto savedUser = UserDto.fromUserCreationDto(newUser);
        savedUser.setUserId(userId);
        // Assign the essential roles to the User Asynchronously
        userManagerService.assignRolesToUser(savedUser);

        // Send activation link async
         String activationToken = userId.concat("@").concat(autogeneratedToken); // Token in activation Link will be: User ID + @ + Activation Token
         String fullName = newUser.firstName() + " " + newUser.lastName();
         emailService.sendActivationLink(fullName, newUser.email(), activationToken);

        return new ResponseEntity<>(BaseAppResponse.success(userId, "User created successfully"), HttpStatus.CREATED);
    }

    /**
     * Activate User and update his/her password
     *
     * @param token : Activation token with userId information and activation token stored in Keycloak
     * @param password : User's new password
     * @return message of success or failure
     */
    @Operation(summary = "Activate user", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User activated and password updated successfully."),
            @ApiResponse(responseCode = "400", description = "Invalid token was given as parameter"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "404", description = "Resource not found"),
            @ApiResponse(responseCode = "409", description = "User is already activated"),
    })
    @PostMapping(value = "/activate")
    public ResponseEntity<BaseAppResponse<String>> activateUser(@RequestParam String token,
                                                             @ValidPassword @RequestBody String password) {

        // Split the User ID and the Keycloak Activation Token
        List<String> tokenData = List.of(token.split("@"));

        // Ensure token inserted is valid - UserID # Activation Token
        if (tokenData.size() != 2)
            return new ResponseEntity<>(BaseAppResponse.error("Invalid token was given as parameter"), HttpStatus.BAD_REQUEST);

        String userId = tokenData.getFirst();
        String activationToken = tokenData.getLast();

        userManagerService.activateUser(userId, activationToken, password);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User activated and password updated successfully."), HttpStatus.OK);
    }

    /**
     * Update user's information in Keycloak
     *
     * @param updatedUserData: UserDTO Updated information
     * @param jwt:             JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Update user's information in Keycloak",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User updated successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PutMapping(value = "/{userId}")
    public ResponseEntity<BaseAppResponse<String>> updateUser(@Valid @RequestBody UserDto updatedUserData,
                                                              @AuthenticationPrincipal Jwt jwt,
                                                              @Parameter(name = "userId", required = true, description = "User ID to be updated") @PathVariable String userId) {

        String jwtRole = JwtUtils.extractPilotRole(jwt);
        String jwtPilot = JwtUtils.extractPilotCode(jwt);
        String jwtUserId = JwtUtils.extractUserId(jwt);

        // Only Super-Admins can update a user to 'SUPER-ADMIN'
        if (!jwtRole.equals(SUPER_ADMIN_ROLE) && updatedUserData.getPilotRole() != null && updatedUserData.getPilotRole().equalsIgnoreCase(SUPER_ADMIN_ROLE))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "Only user of type 'SUPER_ADMIN' can update a user to the 'SUPER_ADMIN' role"), HttpStatus.FORBIDDEN);

        // Users can only change their data
        if (jwtRole.equalsIgnoreCase(USER_ROLE) && !jwtUserId.equalsIgnoreCase(userId))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "User of type 'USER' can only update their own data"), HttpStatus.FORBIDDEN);

        UserDto existingUser = userManagerService.retrieveUserById(userId);

        // Admins can only alter users inside their organization
        if (jwtRole.equals(ADMIN_ROLE) && existingUser.getPilotCode() != null && !jwtPilot.equalsIgnoreCase(existingUser.getPilotCode()))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "User of type 'ADMIN' can only update user's inside their organization"), HttpStatus.FORBIDDEN);

        updatedUserData.setUserId(userId);
        // Update user
        userManagerService.updateUser(updatedUserData);

        // Assign the essential roles to the User Asynchronously after the Update
        userManagerService.assignRolesToUser(updatedUserData);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User updated successfully"), HttpStatus.OK);
    }

    /**
     * Change user's password in Keycloak
     *
     * @param passwords: Old and New passwords
     * @param jwt:       JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Change user's password in Keycloak",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User's password updated successfully"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PutMapping(value = "/change-password")
    public ResponseEntity<BaseAppResponse<String>> changePassword(@Valid @RequestBody PasswordsDto passwords,
                                                                  @AuthenticationPrincipal Jwt jwt) {

        String userId = JwtUtils.extractUserId(jwt);
        userManagerService.changePassword(passwords, userId);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User's password updated successfully"), HttpStatus.OK);
    }

    /**
     * Forget user's password functionality
     *
     * @param email: Email
     * @return Message of success or failure
     */
    @Operation(summary = "Send email to reset user's password", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email to reset password sent successfully to user"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "404", description = "Resource not found"),
            @ApiResponse(responseCode = "409", description = "User is not activated. Password can not be reset")
    })
    @PostMapping(value = "/forgot-password")
    public ResponseEntity<BaseAppResponse<String>> forgotPassword(@RequestBody @Email String email) {
        userManagerService.forgotPassword(email);
        return new ResponseEntity<>(BaseAppResponse.success(null, "Email to reset password sent successfully to user"), HttpStatus.OK);
    }

    /**
     * Reset user password given a token
     *
     * @param token    : Reset Token
     * @param password : New Password
     * @return Message of success or failure
     */
    @Operation(summary = "Reset user's password functionality given a reset token", security = @SecurityRequirement(name = ""))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User's password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid token was provided | Thrown if token format is invalid"),
            @ApiResponse(responseCode = "400", description = "Validation failed | Thrown if invalid password is provided"),
            @ApiResponse(responseCode = "403", description = "Reset token is invalid or there is no reset token for specific user. Please contact the admin of your organization"),
            @ApiResponse(responseCode = "409", description = "Resource not found | Thrown is user does not exist"),
    })
    @PutMapping(value = "/reset-password")
    public ResponseEntity<BaseAppResponse<String>> resetPassword(@RequestParam String token, @ValidPassword @RequestBody String password) {
        // Split the User ID and the Keycloak Activation Token
        List<String> tokenData = List.of(token.split("@"));

        // Ensure token inserted is valid - UserID # Activation Token
        if (tokenData.size() != 2)
            return new ResponseEntity<>(BaseAppResponse.error("Invalid token was provided"), HttpStatus.BAD_REQUEST);

        String userId = tokenData.getFirst();
        String resetToken = tokenData.getLast();

        // Reset password functionality
        userManagerService.resetPassword(userId, resetToken, password);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User's password reset successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all users from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param jwt: JWT Token
     * @return List<UserDTO>
     */
    @Operation(summary = "Retrieve all users from Keycloak",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping
    public ResponseEntity<BaseAppResponse<List<UserDto>>> retrieveAllUsers(@AuthenticationPrincipal Jwt jwt) {
        String pilot = JwtUtils.extractPilotCode(jwt);

        List<UserDto> users;
        if (pilot.equalsIgnoreCase(GLOBAL_PILOT_CODE))
            users = userManagerService.retrieveAllUsers();
        else
            users = userManagerService.retrieveUsersByPilotCode(pilot);
        return new ResponseEntity<>(BaseAppResponse.success(users, "Users retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all users from Keycloak for a specific Pilot
     *
     * @return List<UserDTO>
     */
    @Operation(summary = "[SUPER_ADMIN] Retrieve all users for a specific pilot",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(
            value = {@ApiResponse(responseCode = "200", description = "Users for pilot '{pilotCode}' retrieved successfully"),
                    @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
                    @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
                    @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token")
            })
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/pilots/{pilotCode}")
    public ResponseEntity<BaseAppResponse<List<UserDto>>> retrieveAllUsersByPilotCode(@Parameter(name = "pilotCode", required = true, description = "Pilot Code") @PathVariable String pilotCode) {
        List<UserDto> users = userManagerService.retrieveUsersByPilotCode(pilotCode.trim().toUpperCase());
        return new ResponseEntity<>(BaseAppResponse.success(users, "Users for pilot '" + pilotCode + "' retrieved successfully"), HttpStatus.OK);
    }

    /**
     * GET all users associated with a Role
     *
     * @param jwt : JWT Token
     * @param userRole : User Role
     * @return List<String> : List of User Roles
     */
    @Operation(summary = "Retrieve all users associated with a specific user role", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Users associated with the role retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role or the pilot"),
            @ApiResponse(responseCode = "403", description = "Non 'SUPER-ADMIN' users can not retrieve uses of role 'SUPER-ADMIN'"),
            @ApiResponse(responseCode = "403", description = "User of role 'ADMIN' or 'USER' can only retrieve users assigned to a specific User Role only within their organization"),
            @ApiResponse(responseCode = "403", description = "Token inserted is invalid. It does not contain any information about the user role")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping("/roles/{userRole}")
    public ResponseEntity<BaseAppResponse<List<UserDto>>> retrieve(@AuthenticationPrincipal Jwt jwt,
                                                                   @Parameter(name = "userRole",
                                                                           description = "User role existent in Keycloak",
                                                                           required = true)
                                                                   @PathVariable String userRole) {

        String jwtPilotRole = JwtUtils.extractPilotRole(jwt);
        String jwtPilot = JwtUtils.extractPilotCode(jwt);
        String formattedInputUserRole = userRole.trim().toUpperCase();

        return new ResponseEntity<>(BaseAppResponse.success(userManagerService.retrieveAllUsersByUserRole(jwtPilotRole, jwtPilot, formattedInputUserRole), "Users associated with the role retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Retrieve all users from Keycloak for a specific Pilot and User Role
     *
     * @return List<UserDTO>
     */
    @Operation(summary = "[SUPER_ADMIN] Retrieve all users for a specific pilot and user role",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(
            value = {@ApiResponse(responseCode = "200", description = "Users for pilot '{pilotCode}' and user role '{userRole}' retrieved successfully"),
                    @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
                    @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
                    @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token")
            })
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/pilots/{pilotCode}/roles/{userRole}")
    public ResponseEntity<BaseAppResponse<List<UserDto>>> retrieveAllUsersByPilotCodeAndUserRole(@Parameter(name = "pilotCode", required = true, description = "Pilot Code") @PathVariable String pilotCode,
                                                                                                 @Parameter(name = "userRole", required = true, description = "User Role") @PathVariable String userRole) {
        List<UserDto> users = userManagerService.retrieveUsersByPilotCodeAndUserRole(pilotCode.trim().toUpperCase(), userRole.trim().toUpperCase());
        return new ResponseEntity<>(BaseAppResponse.success(users, "Users for pilot '" + pilotCode + "' and user role '" + userRole + "' retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Search user by ID from Keycloak - Only for Super Admins / Pilot Admins
     *
     * @param userId: ID of the user
     * @param jwt:    JWT Token
     * @return UserDTO
     */
    @Operation(summary = "Get a user by ID",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @GetMapping("/{userId}")
    public ResponseEntity<BaseAppResponse<UserDto>> retrieveUserById(@Parameter(name = "userId", required = true, description = "User's ID") @PathVariable String userId, @AuthenticationPrincipal Jwt jwt) {
        String pilot = JwtUtils.extractPilotCode(jwt);
        UserDto user = userManagerService.retrieveUserById(userId);
        if (!pilot.equalsIgnoreCase(user.getPilotCode()) && pilot.equalsIgnoreCase(ADMIN_ROLE))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "User of type 'ADMIN' can only retrieve users information inside their organization"), HttpStatus.FORBIDDEN);

        return new ResponseEntity<>(BaseAppResponse.success(user, "User retrieved successfully"), HttpStatus.OK);
    }

    /**
     * Delete user from Keycloak - Only for Super Admins
     *
     * @param userId: ID of the user
     * @param jwt:    JWT Token
     * @return Message of success or failure
     */
    @Operation(summary = "Delete a user by ID from Keycloak",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters | Thrown when user can not access the specific resource"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token"),
            @ApiResponse(responseCode = "403", description = "You are unauthorized to request/modify this resource | Thrown when a user attempts to alter a resource that he/she is not authorized to access"),
            @ApiResponse(responseCode = "404", description = "Resource not found")
    })
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<BaseAppResponse<String>> deleteUserById(@Parameter(name = "userId", required = true, description = "User's ID") @PathVariable String userId, @AuthenticationPrincipal Jwt jwt) {
        String pilot = JwtUtils.extractPilotCode(jwt);
        String pilotRole = JwtUtils.extractPilotRole(jwt);

        // Locate user
        UserDto existingUser = userManagerService.retrieveUserById(userId);

        // Validate that ADMIN users can only delete Users inside their plant
        if (pilotRole.equalsIgnoreCase(ADMIN_ROLE) && !pilot.equalsIgnoreCase(existingUser.getPilotCode()))
            return new ResponseEntity<>(BaseAppResponse.error(UNAUTHORIZED_ACTION, "User with type 'ADMIN' can only delete users inside their organization"), HttpStatus.FORBIDDEN);

        // Delete the User
        userManagerService.deleteUser(userId);
        return new ResponseEntity<>(BaseAppResponse.success(null, "User deleted successfully"), HttpStatus.OK);
    }

    /**
     * Return the authentication information of User based on the inserted token
     *
     * @param jwt : JWT token
     * @return authentication information
     */
    @Operation(summary = "Retrieve User information based on the JWT token", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User information from given JWT Token retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again. | Thrown when no JWT Token is provided as Bearer Token"),
            @ApiResponse(responseCode = "403", description = "Invalid JWT token attributes | Thrown when some attributes are missing from the JWT Token")
    })
    @GetMapping("/auth/info")
    public ResponseEntity<BaseAppResponse<UserDto>> retrieveUserAuthInfo(@AuthenticationPrincipal Jwt jwt) {
        UserDto currentUser = UserDto.builder()
                .userId(JwtUtils.extractUserId(jwt))
                .email(JwtUtils.extractUserEmail(jwt))
                .username(JwtUtils.extractUsername(jwt))
                .firstName(JwtUtils.extractUserFirstName(jwt))
                .lastName(JwtUtils.extractUserLastName(jwt))
                .pilotRole(JwtUtils.extractPilotRole(jwt))
                .userRole(JwtUtils.extractUserRole(jwt))
                .pilotCode(JwtUtils.extractPilotCode(jwt))
                .build();

        return new ResponseEntity<>(BaseAppResponse.success(currentUser, "User information from given JWT Token retrieved successfully"), HttpStatus.OK);
    }
}
