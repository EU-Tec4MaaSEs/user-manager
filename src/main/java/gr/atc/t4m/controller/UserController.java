package gr.atc.t4m.controller;

import gr.atc.t4m.service.interfaces.IUserAuthService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import gr.atc.t4m.dto.AuthenticationResponseDto;
import gr.atc.t4m.dto.CredentialsDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/users")
@Slf4j
@Tag(name = "User Manager Controller", description = "Handles the API requests for User Authentication and Management")
public class UserController {

    private final IUserAuthService userAuthService;

    public UserController(IUserAuthService userAuthService){
        this.userAuthService = userAuthService;
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
    public ResponseEntity<BaseAppResponse<AuthenticationResponseDto>> refreshToken(@RequestParam(name = "token") String refreshToken) {
        return new ResponseEntity<>(
                BaseAppResponse.success(userAuthService.refreshToken(refreshToken), "Authentication token generated successfully"),
                HttpStatus.OK);
    }


}
