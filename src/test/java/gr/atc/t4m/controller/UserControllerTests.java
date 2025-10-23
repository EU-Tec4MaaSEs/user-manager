package gr.atc.t4m.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.PasswordsDto;
import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.hamcrest.CoreMatchers.is;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;
import static gr.atc.t4m.exception.CustomExceptions.*;
import gr.atc.t4m.service.interfaces.IUserAuthService;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Nested;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@WebMvcTest(controllers = UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableMethodSecurity(prePostEnabled = true)
class UserControllerTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private IUserAuthService userAuthService;

    @MockitoBean
    private IUserManagementService userManagerService;

    @MockitoBean
    private IEmailService emailService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private CredentialsDto credentials;
    private AuthenticationResponseDto authenticationResponse;
    private UserDto testUser;
    private List<UserDto> listTestUsers;
    private static Jwt superAdminJwt;
    private static Jwt adminJwt;
    private static Jwt userJwt;

    @BeforeAll
    static void initSetup() {
        superAdminJwt = createMockJwtToken("SUPER_ADMIN", "SUPER_ADMIN", "ALL");
        adminJwt = createMockJwtToken("TEST", "ADMIN", "TEST");
        userJwt = createMockJwtToken("TEST", "USER", "TEST");
    }

    @BeforeEach
    void setup() {
        credentials = new CredentialsDto("test@test.com","TestPass123@");

        authenticationResponse = new AuthenticationResponseDto("accessToken", 1800, "JWT", "refreshToken", 1800);

        testUser = UserDto.builder()
                            .userId("1")
                            .email("test@test.com")
                            .firstName("Test")
                            .lastName("User")
                            .pilotCode("TEST")
                            .pilotRole("ADMIN")
                            .userRole("TEST")
                            .username("TestUser")
                            .password("TestPass123@")
                            .organizationId("mockId")
                            .build();

        listTestUsers = List.of(testUser);
    }

    @Nested
    @DisplayName("Authentication Tests")
    class AuthenticationTests {
        @DisplayName("Authenticate User: Success")
        @Test
        void givenUserCredentials_whenAuthenticate_thenReturnAccessTokens() throws Exception {
            // Given
            given(userAuthService.authenticate(credentials)).willReturn(authenticationResponse);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/authenticate")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(credentials)));

            // Then
            response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
                    .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.accessToken())));

        }

        @DisplayName("Refresh Token: Success")
        @Test
        void givenRefreshToken_whenRefreshToken_thenReturnNewAccessTokens() throws Exception {
            // Given
            given(userAuthService.refreshToken("test_token")).willReturn(authenticationResponse);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                    .contentType(MediaType.APPLICATION_JSON).param("token", "test_token"));

            // Then
            response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
                    .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.accessToken())));
        }

        @DisplayName("Refresh Token: No token provided / Failure")
        @Test
        void givenNoInput_whenRefreshToken_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid / No input was given for requested resource")));
        }

        @DisplayName("Authenticate User: Invalid Format of Credentials")
        @Test
        void givenInvalidUserCredentials_whenAuthenticate_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new CredentialsDto("email", "password"))));

            // Then
            response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Authenticate User: Wrong Credentials")
        @Test
        void givenWrongCredentials_whenAuthenticate_thenReturnUnauthorized() throws Exception {
            // Given
            given(userAuthService.authenticate(credentials))
                    .willThrow(InvalidAuthenticationCredentialsException.class);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(credentials)));

            // Then
            response.andExpect(status().isUnauthorized()).andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Authentication failed")));
        }

        @DisplayName("Authenticate User: No credentials given / Failure")
        @Test
        void givenNoInput_whenAuthenticate_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc
                    .perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)));
        }
    }

    @Nested
    @DisplayName("User Management Tests")
    class UserManagementTests {
        @DisplayName("Create User: Success")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenValidUser_whenCreateUser_thenReturnSuccess() throws Exception {
            // Given
            UserCreationDto newUser = new UserCreationDto("TestUser2", "Test", "User2", "test2@test.com", "USER", "TEST", "TEST");
            when(userManagerService.createUser(any(UserCreationDto.class), anyString())).thenReturn("test-user-id");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(newUser)));

            // Then
            response.andExpect(status().isCreated())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User created successfully")));
        }

        @DisplayName("Create User: Unauthorized Action / Admin creates user with role 'SUPER_ADMIN'")
        @WithMockUser("ADMIN")
        @Test
        void givenSuperAdminRoleAndAdminUser_whenCreateUser_thenUnauthorized() throws Exception {
            // Given
            UserCreationDto newUser = new UserCreationDto("TestUser2", "Test", "User2", "test2@test.com", "SUPER_ADMIN", "TEST", "TEST");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(newUser)));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
        }

        @DisplayName("Create User: Unauthorized Action / Admin creates user with different pilot code")
        @WithMockUser("ADMIN")
        @Test
        void givenDifferentPilotAndAdminUser_whenCreateUser_thenUnauthorized() throws Exception {
            // Given
            UserCreationDto newUser = new UserCreationDto("TestUser2", "Test", "User2", "test2@test.com", "ADMIN", "ANOTHER_PILOT", "TEST");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(newUser)));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")))
                    .andExpect(jsonPath("$.errors", is("Admins can only create personnel inside their organization")));
        }

        @DisplayName("Create User: Failed - Missing Values / Validation Failed")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenIncompleteUser_whenCreateUser_thenReturnBadRequest() throws Exception {
            // Given
            UserCreationDto newUser = new UserCreationDto(null, null, null, null,null, null,null);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(post("/api/users/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(newUser)));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Update User: Success")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenValidUser_whenUpdateUser_thenReturnSuccess() throws Exception {
            // Given
            given(userManagerService.retrieveUserById(anyString())).willReturn(testUser);
            UserDto updatedUserData = new UserDto();
            updatedUserData.setUserRole("MOCK_ROLE");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/test-id")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(updatedUserData)));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User updated successfully")));
        }

        @DisplayName("Update User: Unauthorized Action / Admin updates user to role 'SUPER_ADMIN'")
        @WithMockUser("ADMIN")
        @Test
        void givenSuperAdminRoleAndAdminUser_whenUpdateUser_thenUnauthorized() throws Exception {
            // Given
            UserDto updatedUserData = new UserDto();
            updatedUserData.setPilotRole("SUPER_ADMIN");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/test-id")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(updatedUserData)));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
        }

        @DisplayName("Update User: Unauthorized Action / Admin updates user of different pilot code")
        @WithMockUser("ADMIN")
        @Test
        void givenDifferentPilotAndAdminUser_whenUpdateUser_thenUnauthorized() throws Exception {
            // Given
            testUser.setPilotCode("INVALID_PILOT");
            given(userManagerService.retrieveUserById(anyString())).willReturn(testUser);
            UserDto updatedUserData = new UserDto();
            updatedUserData.setPilotCode("TEST_PILOT");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/test-id")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(updatedUserData)));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
        }

        @DisplayName("Update User: Unauthorized Action / User can only update their own user data")
        @WithMockUser("USER")
        @Test
        void givenUserRoleAndDifferentUserId_whenUpdateUser_thenUnauthorized() throws Exception {
            // Given
            UserDto updatedUserData = new UserDto();
            updatedUserData.setPilotCode("TEST");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(userJwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/not-user-id")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(updatedUserData)));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
        }

        @DisplayName("Update User: Failed - Missing Values / Validation Failed")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenInvalidUserData_whenUpdateUser_thenThrowException() throws Exception {
            // Given
            UserDto updatedUserData = new UserDto();
            updatedUserData.setPilotRole("INVALID_ROLE");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/test-id")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(updatedUserData)));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Change Password: Success")
        @WithMockUser
        @Test
        void givenValidPassword_whenChangePassword_thenReturnSuccess() throws Exception {
            // Given
            PasswordsDto passwords = new PasswordsDto("OldPassword123!", "NewPassword123@");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(passwords)));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User's password updated successfully")));
        }

        @DisplayName("Change Password: Validation Failed /Missing Password")
        @WithMockUser
        @Test
        void givenMissingPassword_whenChangePassword_thenReturnBadRequest() throws Exception {
            // Given
            PasswordsDto passwords = new PasswordsDto(null, "NewPassword123@");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(put("/api/users/change-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(passwords)));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }
    }

    @Nested
    @DisplayName("Resend Activation Email Tests")
    class ResendActivationEmailTests {

        @Nested
        @DisplayName("Super Admin Resend Tests")
        class SuperAdminResendTests {

            @DisplayName("Resend Activation Email : Success for Super Admin")
            @WithMockUser("SUPER_ADMIN")
            @Test
            void givenSuperAdminAndNotEnabledUser_whenResendActivationEmail_thenSuccess() throws Exception {
                // Given
                UserDto notEnabledUser = UserDto.builder()
                        .userId("user-123")
                        .email("user@test.com")
                        .firstName("John")
                        .lastName("Doe")
                        .pilotCode("ANOTHER_PILOT")
                        .enabled(false)
                        .build();

                given(userManagerService.retrieveUserById("user-123")).willReturn(notEnabledUser);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                // When
                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "user-123")
                        .contentType(MediaType.APPLICATION_JSON));

                // Then
                response.andExpect(status().isOk())
                        .andExpect(jsonPath("$.success", is(true)))
                        .andExpect(jsonPath("$.message", is("Activation email has been successfully sent to user")));

                verify(userManagerService).retrieveUserById("user-123");
                verify(userManagerService).updateActivationToken(eq("user-123"), anyString());
                verify(emailService).sendActivationLink(eq("John Doe"), eq("user@test.com"), anyString());
            }

            @DisplayName("Resend Activation Email : Super Admin can access any organization")
            @WithMockUser("SUPER_ADMIN")
            @Test
            void givenSuperAdminAndDifferentOrganization_whenResendActivationEmail_thenSuccess() throws Exception {
                // Given
                UserDto userFromDifferentOrg = UserDto.builder()
                        .userId("user-456")
                        .email("another@test.com")
                        .firstName("Jane")
                        .lastName("Smith")
                        .pilotCode("DIFFERENT_PILOT")
                        .enabled(false)
                        .build();

                given(userManagerService.retrieveUserById("user-456")).willReturn(userFromDifferentOrg);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                // When
                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "user-456")
                        .contentType(MediaType.APPLICATION_JSON));

                // Then
                response.andExpect(status().isOk())
                        .andExpect(jsonPath("$.success", is(true)));

                verify(userManagerService).updateActivationToken(eq("user-456"), anyString());
            }
        }

        @Nested
        @DisplayName("Admin Resend Activation Email Tests")
        class AdminResendTests {

            @DisplayName("Resend Activation Email : Success for Admin in same organization")
            @WithMockUser("ADMIN")
            @Test
            void givenAdminAndSameOrganization_whenResendActivationEmail_thenSuccess() throws Exception {
                // Given
                UserDto userInSameOrg = UserDto.builder()
                        .userId("user-789")
                        .email("colleague@test.com")
                        .firstName("Bob")
                        .lastName("Johnson")
                        .pilotCode("TEST")
                        .enabled(false)
                        .build();

                given(userManagerService.retrieveUserById("user-789")).willReturn(userInSameOrg);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                // When
                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "user-789")
                        .contentType(MediaType.APPLICATION_JSON));

                // Then
                response.andExpect(status().isOk())
                        .andExpect(jsonPath("$.success", is(true)))
                        .andExpect(jsonPath("$.message", is("Activation email has been successfully sent to user")));

                verify(userManagerService).retrieveUserById("user-789");
                verify(userManagerService).updateActivationToken(eq("user-789"), anyString());
                verify(emailService).sendActivationLink(eq("Bob Johnson"), eq("colleague@test.com"), anyString());
            }

            @DisplayName("Resend Activation Email : Forbidden for Admin in different organization")
            @WithMockUser("ADMIN")
            @Test
            void givenAdminAndDifferentOrganization_whenResendActivationEmail_thenForbidden() throws Exception {
                // Given
                UserDto userInDifferentOrg = UserDto.builder()
                        .userId("user-999")
                        .email("other@test.com")
                        .firstName("Alice")
                        .lastName("Williams")
                        .pilotCode("ANOTHER_PILOT")
                        .enabled(false)
                        .build();

                given(userManagerService.retrieveUserById("user-999")).willReturn(userInDifferentOrg);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                // When
                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "user-999")
                        .contentType(MediaType.APPLICATION_JSON));

                // Then
                response.andExpect(status().isForbidden())
                        .andExpect(jsonPath("$.success", is(false)))
                        .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")))
                        .andExpect(jsonPath("$.errors", is("Admins can only resend activation emails to users inside their organization")));

                verify(userManagerService).retrieveUserById("user-999");
                verify(userManagerService, never()).updateActivationToken(anyString(), anyString());
                verify(emailService, never()).sendActivationLink(anyString(), anyString(), anyString());
            }

            @DisplayName("Resend Activation Email : Conflict when user is already activated")
            @WithMockUser("SUPER_ADMIN")
            @Test
            void givenAlreadyEnabledUser_whenResendActivationEmail_thenConflict() throws Exception {
                UserDto enabledUser = UserDto.builder()
                        .userId("user-enabled")
                        .email("enabled@test.com")
                        .firstName("Active")
                        .lastName("User")
                        .pilotCode("TEST")
                        .enabled(true)
                        .build();

                given(userManagerService.retrieveUserById("user-enabled")).willReturn(enabledUser);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "user-enabled")
                        .contentType(MediaType.APPLICATION_JSON));

                response.andExpect(status().isConflict())
                        .andExpect(jsonPath("$.success", is(false)))
                        .andExpect(jsonPath("$.message", is("User is already activated. Activation email cannot be resent.")));

                verify(userManagerService).retrieveUserById("user-enabled");
                verify(userManagerService, never()).updateActivationToken(anyString(), anyString());
                verify(emailService, never()).sendActivationLink(anyString(), anyString(), anyString());
            }

            @DisplayName("Resend Activation Email : Not Found when user does not exist")
            @WithMockUser("SUPER_ADMIN")
            @Test
            void givenNonExistentUser_whenResendActivationEmail_thenNotFound() throws Exception {
                given(userManagerService.retrieveUserById("non-existent")).willThrow(ResourceNotPresentException.class);

                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .param("userId", "non-existent")
                        .contentType(MediaType.APPLICATION_JSON));

                response.andExpect(status().isNotFound())
                        .andExpect(jsonPath("$.success", is(false)))
                        .andExpect(jsonPath("$.message", is("Resource not found")));

                verify(userManagerService).retrieveUserById("non-existent");
                verify(userManagerService, never()).updateActivationToken(anyString(), anyString());
            }

            @DisplayName("Resend Activation Email : Bad Request when userId parameter is missing")
            @WithMockUser("SUPER_ADMIN")
            @Test
            void givenNoUserId_whenResendActivationEmail_thenBadRequest() throws Exception {
                JwtAuthenticationToken jwtAuthenticationToken =
                        new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
                SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

                ResultActions response = mockMvc.perform(post("/api/users/activation/email")
                        .contentType(MediaType.APPLICATION_JSON));

                response.andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.success", is(false)))
                        .andExpect(jsonPath("$.message", is("Invalid / No input was given for requested resource")));

                verify(userManagerService, never()).retrieveUserById(anyString());
            }
        }
    }

    @Nested
    @DisplayName("User Activation and Password Reset Tests")
    class ActivationAndResetTests {
        @DisplayName("Activate User: Success")
        @Test
        void givenInputToken_whenActivateUser_thenSuccess() throws Exception {
            // When
            ResultActions response = mockMvc.perform(post("/api/users/activate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString("Test123@"))
                    .param("token", "userId@token"));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User activated and password updated successfully.")));
        }

        @DisplayName("Activate User: No token provided / Failure")
        @Test
        void givenNoInputToken_whenActivateUser_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc.perform(post("/api/users/activate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString("Test123@"))
                    .param("token", "wrong-token"));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid token was given as parameter")));
        }

        @DisplayName("Activate User: No Password Provided / Failure")
        @Test
        void givenNoPassword_whenActivateUser_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc.perform(post("/api/users/activate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .param("token", "wrong-token"));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Activate User: Invalid Token")
        @Test
        void givenInvalidToken_whenActivateUser_thenReturnBadRequest() throws Exception {

            // When
            ResultActions response = mockMvc.perform(post("/api/users/activate")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid / No input was given for requested resource")));
        }

        @DisplayName("Forgot Password: Success")
        @WithMockUser
        @Test
        void givenValidEmail_whenForgotPassword_thenReturnSuccess() throws Exception {
            // Given
            String email = "test@test.com";

            // When
            ResultActions response = mockMvc.perform(
                    post("/api/users/forgot-password").contentType(MediaType.APPLICATION_JSON).content(email));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Email to reset password sent successfully to user")));
        }

        @DisplayName("Forgot Password: Invalid Email Format")
        @WithMockUser
        @Test
        void givenInvalidEmail_whenForgotPassword_thenReturnBadRequest() throws Exception {
            // Given
            String invalidEmail = "invalid-email";

            // When
            ResultActions response = mockMvc.perform(post("/api/users/forgot-password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(invalidEmail));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Reset Password: Success")
        @WithMockUser
        @Test
        void givenValidTokenAndPassword_whenResetPassword_thenReturnSuccess() throws Exception {
            // Given
            String token = "userId@resetToken";
            String newPassword = "NewPassword123@";

            // When
            ResultActions response = mockMvc.perform(put("/api/users/reset-password").param("token", token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(newPassword));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User's password reset successfully")));
        }

        @DisplayName("Reset Password: Invalid Token Format")
        @WithMockUser
        @Test
        void givenInvalidToken_whenResetPassword_thenReturnBadRequest() throws Exception {
            // Given
            String invalidToken = "invalid-token";
            String newPassword = "NewPassword123@";

            // When
            ResultActions response = mockMvc.perform(put("/api/users/reset-password")
                    .param("token", invalidToken).contentType(MediaType.APPLICATION_JSON).content(newPassword));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid token was provided")));
        }

        @DisplayName("Reset Password: Invalid Password Format")
        @Test
        void givenValidTokenAndInvalidPassword_whenResetPassword_thenReturnBadRequest() throws Exception {
            // Given
            String token = "userId@resetToken";
            String invalidPassword = "weakpass";

            // When
            ResultActions response = mockMvc.perform(put("/api/users/reset-password").param("token", token)
                    .contentType(MediaType.APPLICATION_JSON).content(invalidPassword));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }
    }

    @Nested
    @DisplayName("User Retrieval Tests")
    class UserRetrievalTests {
        @DisplayName("Fetch Users: Success for Super-Admins")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenSuperAdminRole_whenFetchUsers_thenReturnListOfUsers() throws Exception {
            // Given
            given(userManagerService.retrieveAllUsers()).willReturn(listTestUsers);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/users"));

            // Then
            response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Users retrieved successfully")))
                    .andExpect(jsonPath("$.data[0].email", is("test@test.com")));

            verify(userManagerService).retrieveAllUsers();
            verify(userManagerService, never()).retrieveUsersByPilotCode(anyString());
        }

        @DisplayName("Fetch Users: Success for Admins")
        @WithMockUser("ADMIN")
        @Test
        void givenAdminRole_whenFetchUsers_thenReturnListOfUsersFilteredByPilot() throws Exception {
            // Given
            given(userManagerService.retrieveUsersByPilotCode(anyString())).willReturn(listTestUsers);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/users"));

            // Then
            response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Users retrieved successfully")))
                    .andExpect(jsonPath("$.data[0].email", is("test@test.com")));

            verify(userManagerService, never()).retrieveAllUsers();
            verify(userManagerService).retrieveUsersByPilotCode(anyString());
        }

        @DisplayName("Fetch Users per Pilot: Success")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenValidJwt_whenGetUserIdsPerPilot_thenReturnListOfUserIds() throws Exception {
            // Given
            given(userManagerService.retrieveUsersByPilotCode(anyString())).willReturn(listTestUsers);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response =
                    mockMvc.perform(get("/api/users/pilots/mock-pilot"));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Users for pilot 'mock-pilot' retrieved successfully")))
                    .andExpect(jsonPath("$.data[0].userId", is("1")));
        }

        @DisplayName("Fetch User by ID: Success")
        @WithMockUser("ADMIN")
        @Test
        void givenValidUserId_whenFetchUser_thenReturnUser() throws Exception {
            // Given
            given(userManagerService.retrieveUserById(anyString())).willReturn(testUser);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/users/test-id"));

            // Then
            response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User retrieved successfully")))
                    .andExpect(jsonPath("$.data.email", is("test@test.com")));
        }

        @DisplayName("Fetch User by ID: Not Found")
        @WithMockUser("SUPER_ADMIN")
        @Test
        void givenInvalidUserId_whenRetrieveUser_thenThrowException() throws Exception {
            // Given
            given(userManagerService.retrieveUserById(anyString())).willThrow(ResourceNotPresentException.class);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/users/test-id"));

            // Then
            response.andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Resource not found")));
        }

        @DisplayName("Retrieve User Info from JWT: Success")
        @Test
        void givenValidJwtToken_whenGetUserAuth_thenUserDto() throws Exception {
            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/users/auth/info"));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User information from given JWT Token retrieved successfully")))
                    .andExpect(jsonPath("$.data.pilotRole", is("SUPER_ADMIN")))
                    .andExpect(jsonPath("$.data.userRole", is("SUPER_ADMIN")))
                    .andExpect(jsonPath("$.data.pilotCode", is("ALL")))
                    .andExpect(jsonPath("$.data.userId", is("test-id")))
                    .andExpect(jsonPath("$.data.email", is("test@test.com")))
                    .andExpect(jsonPath("$.data.firstName", is("Test")))
                    .andExpect(jsonPath("$.data.lastName", is("Test")));
        }

        @DisplayName("Retrieve Users by User Role and Organization : Success")
        @Test
        @WithMockUser(roles = "SUPER_ADMIN")
        void givenUserRoleAndOrganization_whenRetrieveUsersByUserRoleAndOrganization_thenReturnListOfUsers() throws Exception {
            // Given
            String pilotCode = "pilot1";
            String userRole = "admin";
            when(userManagerService.retrieveUsersByPilotCodeAndUserRole("PILOT1", "ADMIN"))
                    .thenReturn(listTestUsers);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When & Then
            mockMvc.perform(get("/api/users/pilots/{pilotCode}/roles/{userRole}", pilotCode, userRole)
                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Users for pilot 'pilot1' and user role 'admin' retrieved successfully")))
                    .andExpect(jsonPath("$.data", hasSize(1)))
                    .andExpect(jsonPath("$.data[0].userId", is("1")))
                    .andExpect(jsonPath("$.data[0].email", is("test@test.com")))
                    .andExpect(jsonPath("$.data[0].firstName", is("Test")))
                    .andExpect(jsonPath("$.data[0].lastName", is("User")));

            // Verify service was called with uppercase parameters
            verify(userManagerService, times(1))
                    .retrieveUsersByPilotCodeAndUserRole("PILOT1", "ADMIN");
        }

        @DisplayName("Retrieve Users by User Role and Organization : Forbidden")
        @Test
        @WithMockUser(roles = "USER")
        void retrieveAllUsersByPilotCodeAndUserRole_WithInsufficientRole_ShouldReturn403() throws Exception {
            // Given
            String pilotCode = "pilot1";
            String userRole = "admin";

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken =
                    new JwtAuthenticationToken(userJwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When & Then
            mockMvc.perform(get("/api/users/pilots/{pilotCode}/roles/{userRole}", pilotCode, userRole)
                    .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                    .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isForbidden());

            // Verify service was never called
            verify(userManagerService, never()).retrieveUsersByPilotCodeAndUserRole(anyString(), anyString());
        }

        @DisplayName("Successful retrieval of users for specific role")
        @Test
        void givenValidJwtAndUserRole_whenSuperAdmin_thenReturnUsers() throws Exception {
            // Given
            String userRole = "TEST";
            List<UserDto> mockUsers = Arrays.asList(
                    UserDto.builder().username("user1").build(),
                    UserDto.builder().username("user2").build()
            );

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // Mock service method
            when(userManagerService.retrieveAllUsersByUserRole(anyString(),anyString(),anyString())).thenReturn(mockUsers);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/users/roles/{userRole}", userRole)
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", Matchers.is(true)))
                    .andExpect(jsonPath("$.message", Matchers.is("Users associated with the role retrieved successfully")))
                    .andExpect(jsonPath("$.data[0].username", Matchers.is("user1")))
                    .andExpect(jsonPath("$.data[1].username", Matchers.is("user2")));
        }

        @DisplayName("Retrieve Auth Info: Success")
        @Test
        void givenValidJwt_whenRetrieveUserAuthInfo_thenReturnUserInfo() throws Exception {
            // Given
            String pilotRole = "PILOT";
            String userRole = "USER";
            String pilotCode = "TEST_PILOT";
            String organizationId = "TEST_ORGANIZATION_ID";

            // Create a mock JWT with claims
            Jwt mockJwt = createMockJwtToken(userRole, pilotRole, pilotCode);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(mockJwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/users/auth/info")
                    .contentType(MediaType.APPLICATION_JSON)
                    .with(jwt().jwt(mockJwt)));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", Matchers.is(true)))
                    .andExpect(jsonPath("$.message", Matchers.is("User information from given JWT Token retrieved successfully")))
                    .andExpect(jsonPath("$.data.userId", Matchers.is("test-id")))
                    .andExpect(jsonPath("$.data.email", Matchers.is("test@test.com")))
                    .andExpect(jsonPath("$.data.username", Matchers.is("TestUser")))
                    .andExpect(jsonPath("$.data.firstName", Matchers.is("Test")))
                    .andExpect(jsonPath("$.data.lastName", Matchers.is("Test")))
                    .andExpect(jsonPath("$.data.pilotRole", Matchers.is(pilotRole)))
                    .andExpect(jsonPath("$.data.userRole", Matchers.is(userRole)))
                    .andExpect(jsonPath("$.data.pilotCode", Matchers.is(pilotCode)))
                    .andExpect(jsonPath("$.data.organizationId", Matchers.is(organizationId)));
        }
    }

    private static Jwt createMockJwtToken(String userRole, String pilotRole, String pilotCode){
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");
        headers.put("typ", "JWT");

        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of(pilotRole)));
        claims.put("resource_access", Map.of("test-client", Map.of("roles", List.of(pilotRole))));
        claims.put("sub", "test-id");
        claims.put("pilot_code", pilotCode);
        claims.put("pilot_role", pilotRole);
        claims.put("user_role", userRole);
        claims.put("organization_id", "TEST_ORGANIZATION_ID");
        claims.put("family_name", "Test");
        claims.put("given_name", "Test");
        claims.put("email", "test@test.com");
        claims.put("preferred_username", "TestUser");

        return new Jwt(
                tokenValue,
                Instant.now(),
                Instant.now().plusSeconds(300),
                headers,
                claims
        );
    }
}
