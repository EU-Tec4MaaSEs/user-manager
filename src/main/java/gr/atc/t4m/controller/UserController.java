package gr.atc.t4m.controller;

import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.enums.PilotRole;
import gr.atc.t4m.service.interfaces.IUserAuthService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.JwtUtils;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@Slf4j
@Tag(name = "User Manager Controller", description = "Handles the API requests for User Authentication and Management")
public class UserController {

    private final IUserAuthService userAuthService;

    private final IUserManagementService userManagerService;

    //private final IEmailService emailService;

    public UserController(IUserAuthService userAuthService, IUserManagementService userManagerService){
        this.userAuthService = userAuthService;
        this.userManagerService = userManagerService;
        //this.emailService = emailService;
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
     *  -  Admins can only create personnel inside their organization
     *  -  Super Admins can create personnel for all pilots and create new Super Admins also
     *
     * @param newUser : User information
     * @param jwt : JWT Token
     * @return message of success or failure
     */
    @Operation(summary = "Create a new user in Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Unauthorized request. Check token and try again."),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
            @ApiResponse(responseCode = "403", description = "Only Super Admins can create other Super Admin users."),
            @ApiResponse(responseCode = "403", description = "Admins can only create personnel inside their organization"),
            @ApiResponse(responseCode = "409", description = "User already exists in Keycloak"),
            @ApiResponse(responseCode = "409", description = "User with the given email already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create user in Keycloak")})
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @PostMapping(value = "/create")
    public ResponseEntity<BaseAppResponse<String>> createUser(@RequestBody @Valid UserCreationDto newUser, @AuthenticationPrincipal Jwt jwt) {
        String authorizeUserPilotRole = JwtUtils.extractPilotRole(jwt);
        String authorizeUserPilotCode = JwtUtils.extractPilotCode(jwt);

        // Ensure that only Super Admins can create new Super Admins
        if (newUser.pilotRole().equals(PilotRole.SUPER_ADMIN.toString())
                && !authorizeUserPilotRole.equalsIgnoreCase(PilotRole.SUPER_ADMIN.toString()))
            return new ResponseEntity<>(BaseAppResponse.error("Unauthorized action",
                    "Only Super Admins can create other Super Admin users"), HttpStatus.FORBIDDEN);

        // Ensure that Admins can create personnel only inside their organization
        if (authorizeUserPilotRole.equals(PilotRole.ADMIN.toString())
                && authorizeUserPilotCode.equalsIgnoreCase(newUser.pilotCode()))
            return new ResponseEntity<>(BaseAppResponse.error("Unauthorized action",
                    "Admins can only create personnel inside their organization"), HttpStatus.FORBIDDEN);

        // Generate the activation token and create User
        String autogeneratedToken = UUID.randomUUID().toString();
        String userId = userManagerService.createUser(newUser, autogeneratedToken);

        // Assign the essential roles to the User Asynchronously
        userManagerService.assignRolesToUser(newUser, userId);

        // Send activation link async
        // String activationToken = userId.concat("@").concat(autogeneratedToken); // Token in activation Link will be: User ID + @ + Activation Token
        // String fullName = newUser.firstName() + " " + newUser.lastName();
        // emailService.sendActivationLink(fullName, newUser.email(), activationToken);

        return new ResponseEntity<>(
                BaseAppResponse.success(userId, "User created successfully"),
                HttpStatus.CREATED);
    }

    /**
     * Return the authentication information based on the inserted token
     *
     * @param authentication : JWT token
     * @return authentication information
     */
    @Operation(summary = "Retrieve Authentication Information based on the JWT token",
            security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200",
                    description = "Information about Authentication Information based on the JWT token",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = Authentication.class))}),
            @ApiResponse(responseCode = "403",
                    description = "Invalid authorization parameters. Check JWT or CSRF Token")})
    @GetMapping(value = "/auth-info")
    public ResponseEntity<Authentication> getAuthInfo(Authentication authentication) {
        return new ResponseEntity<>(authentication, HttpStatus.OK);
    }



}
