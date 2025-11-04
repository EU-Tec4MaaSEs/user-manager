package gr.atc.t4m.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.context.JwtContext;
import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Nested;

@WebMvcTest(controllers = AdminController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableMethodSecurity(prePostEnabled = true)
class AdminControllerTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private JwtContext jwtContext;

    @MockitoBean
    private IKeycloakAdminService adminService;

    @MockitoBean
    private IUserManagementService userManagementService;

    @MockitoBean
    private CacheManager cacheManager;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static Jwt superAdminJwt;
    private static Jwt adminJwt;
    private static Jwt userJwt;

    @BeforeAll
    static void setup() {
        superAdminJwt = createMockJwtToken("SUPER_ADMIN", "SUPER_ADMIN", "ALL");
        adminJwt = createMockJwtToken("TEST", "ADMIN", "TEST");
        userJwt = createMockJwtToken("TEST", "USER", "TEST");
    }

    @Nested
    @DisplayName("System Roles Tests")
    class SystemRolesTests {
        @DisplayName("Get All System Roles: Success")
        @Test
        void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() throws Exception {
            // Given
            List<String> pilotRoles = List.of("ADMIN", "USER");
            given(adminService.retrieveAllPilotRoles(anyBoolean())).willReturn(pilotRoles);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/admin/system/roles")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot/System roles retrieved successfully")))
                    .andExpect(jsonPath("$.data", is(pilotRoles)));

            assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        }

        @DisplayName("Get All System Roles : Forbidden Access for User - 403 Error")
        @WithMockUser(roles = "USER")
        @Test
        void givenUserWithoutSuperAdminRole_whenGetAllUserRoles_thenReturnForbidden() throws Exception {
            // When
            ResultActions response = mockMvc.perform(get("/api/admin/roles")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden());

            assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        }
    }

    @Nested
    @DisplayName("Pilots (Pilot Codes) Tests")
    class PilotTests {
        @DisplayName("Get All Pilot Codes: Success")
        @WithMockUser(roles = "SUPER_ADMIN")
        @Test
        void givenValidJwt_whenGetAllPilotCodes_thenReturnPilotCodes() throws Exception {
            // Given
            List<String> pilotRoles = List.of("TEST1", "TEST2");
            given(adminService.retrieveAllPilotCodes()).willReturn(pilotRoles);

            // When
            ResultActions response = mockMvc.perform(get("/api/admin/pilots")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot codes retrieved successfully")))
                    .andExpect(jsonPath("$.data", is(pilotRoles)));

            assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        }

        @DisplayName("Get All Pilot Codes Admin: Unauthorized action")
        @WithMockUser(roles = "ADMIN")
        @Test
        void givenValidJwtAndAdminRole_whenGetAllPilotCodes_thenReturnUnauthorized() throws Exception {
            // When
            ResultActions response = mockMvc.perform(get("/api/admin/pilots")
                    .with(authentication(new JwtAuthenticationToken(
                            createMockJwtToken("TEST", "ADMIN", "TEST"),
                            List.of(new SimpleGrantedAuthority("ROLE_ADMIN")),
                            null)))
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)));
        }

        @DisplayName("Create a new pilot / organization : Success")
        @Test
        void givenPilotInformation_whenCreateNewPilotInSystem_thenReturnSuccess() throws Exception {
            // Given
            PilotCreationDto pilotData = new PilotCreationDto("TEST_PILOT", "Test Pilot", List.of("ADMIN"),
                    "https://example.com/verifiable-credential", null, "https://example.com/dsc", "mockId");

            // Formulate JWT
            Jwt token = createMockJwtToken("SUPER_ADMIN", "SUPER_ADMIN", "ALL");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(token, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/pilots/create")
                    .with(csrf())
                    .content(objectMapper.writeValueAsString(pilotData))
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isCreated())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot created successfully")));
        }

        @DisplayName("Create a new pilot / organization : Not Authorized")
        @WithMockUser(roles = "ADMIN")
        @Test
        void givenPilotInformationAndInvalidJWT_whenCreateNewPilotInSystem_thenReturnForbidden() throws Exception {
            // Given
            PilotCreationDto pilotData = new PilotCreationDto("TEST_PILOT", "Test Pilot", List.of("ADMIN"),
                    "https://example.com/verifiable-credential", null, "https://example.com/dsc", "mockId");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/pilots/create")
                    .with(csrf())
                    .content(objectMapper.writeValueAsString(pilotData))
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid authorization parameters")));
        }

        @DisplayName("Update Pilot for Super Admin: Success")
        @Test
        void givenValidSuperAdminJwtAndPilotData_whenUpdatePilot_thenReturnSuccess() throws Exception {
            String pilotName = "TEST_PILOT";
            PilotDto pilotUpdateData = PilotDto.builder()
                    .name(pilotName)
                    .globalName("Updated Test Pilot")
                    .verifiableCredential("https://updated.example.com/credential")
                    .dataSpaceConnectorUrl("https://updated.example.com/dsc")
                    .build();

            given(jwtContext.isSuperAdmin()).willReturn(true);

            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(pilotUpdateData)));

            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot updated successfully")));
        }

        @DisplayName("Update Pilot for Super Admin: Bad Request / Default pilot can not be updated")
        @Test
        void givenValidSuperAdminJwtAndDefaultPilot_whenUpdatePilot_thenReturnBadRequest() throws Exception {
            // Given
            String pilotName = "DEFAULT";
            PilotDto pilotUpdateData = PilotDto.builder()
                    .name(pilotName)
                    .globalName("Updated Test Pilot")
                    .verifiableCredential("https://updated.example.com/credential")
                    .dataSpaceConnectorUrl("https://updated.example.com/dsc")
                    .build();

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(pilotUpdateData)));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)));
        }

        @DisplayName("Update Pilot by Admin of same pilot: Success")
        @Test
        void givenValidAdminJwtAndSamePilotData_whenUpdatePilot_thenReturnSuccess() throws Exception {
            String pilotName = "TEST";
            PilotDto pilotUpdateData = PilotDto.builder()
                    .name(pilotName)
                    .globalName("Updated Test Pilot")
                    .verifiableCredential("https://updated.example.com/credential")
                    .dataSpaceConnectorUrl("https://updated.example.com/dsc")
                    .build();

            UserDto testUser = UserDto.builder()
                    .userId("testUserId")
                    .email("admin@test.com")
                    .pilotCode("TEST")
                    .build();

            given(jwtContext.isSuperAdmin()).willReturn(false);
            given(jwtContext.getCurrentUser()).willReturn(testUser);

            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(pilotUpdateData)));

            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot updated successfully")));
        }

        @DisplayName("Update Pilot by Admin of different pilot: Forbidden")
        @Test
        void givenValidAdminJwtAndDifferentPilotData_whenUpdatePilot_thenReturnForbidden() throws Exception {
            String pilotName = "DIFFERENT_PILOT";
            PilotDto pilotUpdateData = PilotDto.builder()
                    .name(pilotName)
                    .globalName("Updated Different Pilot")
                    .build();

            UserDto testUser = UserDto.builder()
                    .userId("testUserId")
                    .email("admin@test.com")
                    .pilotCode("TEST")
                    .build();

            given(jwtContext.isSuperAdmin()).willReturn(false);
            given(jwtContext.getCurrentUser()).willReturn(testUser);

            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(pilotUpdateData)));

            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("You are not authorized to update information on this pilot")));
        }

        @DisplayName("Update Pilot with invalid JSON: Bad Request")
        @Test
        void givenValidJwtAndMalformedJson_whenUpdatePilot_thenReturnBadRequest() throws Exception {
            // Given
            String pilotName = "TEST_PILOT";
            String malformedJson = "{ \"name\": \"TEST_PILOT\", \"invalidField\": }"; // Missing value - malformed JSON

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(malformedJson));

            // Then
            response.andExpect(status().isBadRequest());
        }

        @DisplayName("Delete Pilot by Super Admin: Success")
        @Test
        void givenValidSuperAdminJwt_whenDeletePilot_thenReturnSuccess() throws Exception {
            // Given
            String pilotName = "TEST_PILOT";

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("Pilot deleted successfully")));
        }

        @DisplayName("Delete Pilot by Super Admin: Bad request / Default Pilot can not be deleted")
        @Test
        void givenValidSuperAdminJwtAndDefaultPilot_whenDeletePilot_thenReturnError() throws Exception {
            // Given
            String pilotName = "DEFAULT";

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)));
        }

        @DisplayName("Delete Pilot by Admin: Forbidden")
        @Test
        void givenValidAdminJwt_whenDeletePilot_thenReturnForbidden() throws Exception {
            // Given
            String pilotName = "TEST_PILOT";

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/pilots/{pilotName}", pilotName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("User Roles Tests")
    class UserRolesTests {
        @DisplayName("Get All User Roles Super Admin: Success")
        @WithMockUser(roles = "SUPER_ADMIN")
        @Test
        void givenValidJwtForSuperAdmins_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
            // Given
            UserRoleDto userRoleDto = new UserRoleDto("1", "TEST_ROLE", "Test Role", "Role description");
            UserRoleDto superAdminRole = new UserRoleDto("2", "SUPER_ADMIN", "Super Admin", "Role description");
            List<UserRoleDto> roles = List.of(userRoleDto, superAdminRole);
            given(adminService.retrieveAllUserRoles(anyBoolean())).willReturn(roles);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/admin/roles")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                    .andExpect(jsonPath("$.data", Matchers.hasSize(2)));
        }

        @DisplayName("Get All User Roles Admin: Success")
        @WithMockUser(roles = "ADMIN")
        @Test
        void givenValidJwtForAdmins_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
            // Given
            UserRoleDto userRoleDto = new UserRoleDto("1", "TEST_ROLE", "Test Role", "Role description");
            given(adminService.retrieveAllUserRoles(anyBoolean())).willReturn(List.of(userRoleDto));

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(get("/api/admin/roles")
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                    .andExpect(jsonPath("$.data[0].name", is("TEST_ROLE")))
                    .andExpect(jsonPath("$.data", Matchers.hasSize(1)));
        }

        @DisplayName("Get All User Roles User: Unauthorized access")
        @WithMockUser(roles = "USER")
        @Test
        void givenValidJwtForUsers_whenGetAllUserRoles_thenReturnUnauthorized() throws Exception {
            // Given
            UserRoleDto userRoleDto = new UserRoleDto("1", "TEST_ROLE", "Test Role", "Role description");
            List<UserRoleDto> roles = List.of(userRoleDto);
            given(adminService.retrieveAllUserRoles(anyBoolean())).willReturn(roles);

            // When
            ResultActions response = mockMvc.perform(get("/api/admin/roles")
                    .with(authentication(new JwtAuthenticationToken(
                            userJwt,
                            List.of(new SimpleGrantedAuthority("ROLE_USER")),
                            null)))
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid authorization parameters")));
        }

        @DisplayName("Create New User Role: Success")
        @Test
        void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnSuccess() throws Exception {
            // Given
            UserRoleDto role = UserRoleDto.builder()
                    .name("TestRole")
                    .globalName("Test Role")
                    .description("Test description")
                    .build();

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .with(csrf())
                    .content(objectMapper.writeValueAsString(role)));

            // Then
            response.andExpect(status().isCreated())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User role created successfully")));
        }

        @DisplayName("Create new Role: Missing fields in request body")
        @Test
        void givenValidJwtAndNewRoleWithMissingFields_whenCreateNewUserRole_thenReturnBadRequest() throws Exception {
            // Given
            UserRoleCreationDto role = new UserRoleCreationDto("Test_Role", null, "Test description");

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .with(csrf())
                    .content(objectMapper.writeValueAsString(role)));

            // Then
            response.andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Validation failed")));
        }

        @DisplayName("Delete User Role: Success")
        @Test
        void givenValidJwtAndRoleName_whenDeleteUserRole_thenReturnSuccess() throws Exception {
            // Given
            String roleName = "TestRole";

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/roles/{roleName}", roleName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User role deleted successfully")));
        }

        @DisplayName("Retrieve User Role: Success")
        @Test
        void givenValidJwt_whenRetrieveUserRole_thenReturnUserRole() throws Exception {
            // Given
            String roleName = "TEST_ROLE";
            UserRoleDto expectedRole = UserRoleDto.builder()
                    .name(roleName.toUpperCase())
                    .name("TEST_ROLE")
                    .globalName("Test Role")
                    .description("Test description")
                    .build();

            // Mock service to return role
            given(adminService.retrieveUserRoleByName(anyString())).willReturn(expectedRole);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/{roleName}", roleName)
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User role retrieved successfully")))
                    .andExpect(jsonPath("$.data.name", is(roleName)));
        }

        @DisplayName("Update User Role: Success")
        @WithMockUser(roles = "SUPER_ADMIN")
        @Test
        void givenValidJwtAndRole_whenUpdateUserRole_thenReturnSuccess() throws Exception {
            // Given
            String roleName = "TestRole";
            UserRoleDto roleToUpdate = UserRoleDto.builder()
                    .name(roleName.toUpperCase())
                    .name("TestRole")
                    .globalName("Test Role")
                    .description("Test description")
                    .build();

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(roleToUpdate)));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("User role updated successfully")));
        }
    }

    @Nested
    @DisplayName("Cache Management Tests")
    class CacheManagementTests {

        @DisplayName("Reset All Caches: Success - Super Admin")
        @Test
        void givenSuperAdminJwt_whenResetAllCaches_thenReturnSuccess() throws Exception {
            // Given - Mock cache manager with multiple caches
            Cache pilotRolesCache = mock(Cache.class);
            Cache pilotCodesCache = mock(Cache.class);
            Cache userRolesCache = mock(Cache.class);
            Cache usersCache = mock(Cache.class);

            // When cache manager returns cache names
            given(cacheManager.getCacheNames())
                    .willReturn(List.of("pilotRoles", "pilotCodes", "userRoles", "users"));

            // When individual caches are requested
            given(cacheManager.getCache("pilotRoles")).willReturn(pilotRolesCache);
            given(cacheManager.getCache("pilotCodes")).willReturn(pilotCodesCache);
            given(cacheManager.getCache("userRoles")).willReturn(userRolesCache);
            given(cacheManager.getCache("users")).willReturn(usersCache);

            // Mock JWT authentication
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/cache/reset")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isOk())
                    .andExpect(jsonPath("$.success", is(true)))
                    .andExpect(jsonPath("$.message", is("All caches cleared successfully")));

            // Verify all caches were cleared
            verify(pilotRolesCache).clear();
            verify(pilotCodesCache).clear();
            verify(userRolesCache).clear();
            verify(usersCache).clear();
        }

        @DisplayName("Reset All Caches: Forbidden - Admin Role")
        @Test
        void givenAdminJwt_whenResetAllCaches_thenReturnForbidden() throws Exception {
            // Given - Mock JWT authentication with ADMIN role (not SUPER_ADMIN)
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/cache/reset")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)))
                    .andExpect(jsonPath("$.message", is("Invalid authorization parameters")));

            // Verify no caches were cleared
            verify(cacheManager, never()).getCacheNames();
        }

        @DisplayName("Reset All Caches: Forbidden - User Role")
        @WithMockUser(roles = "USER")
        @Test
        void givenUserJwt_whenResetAllCaches_thenReturnForbidden() throws Exception {
            // Given - Mock JWT authentication with USER role
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(userJwt,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

            // When
            ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/cache/reset")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON));

            // Then
            response.andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.success", is(false)));

            // Verify no caches were cleared
            verify(cacheManager, never()).getCacheNames();
        }
    }

    private static Jwt createMockJwtToken(String userRole, String pilotRole, String pilotCode) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");
        headers.put("typ", "JWT");

        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of(pilotRole)));
        claims.put("resource_access", Map.of("test-client", Map.of("roles", List.of(pilotRole))));
        claims.put("sub", UUID.randomUUID().toString());
        claims.put("pilot_code", pilotCode);
        claims.put("pilot_role", pilotRole);
        claims.put("user_role", userRole);

        return new Jwt(
                tokenValue,
                Instant.now(),
                Instant.now().plusSeconds(300),
                headers,
                claims
        );
    }
}
