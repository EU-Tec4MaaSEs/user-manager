package gr.atc.t4m.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
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
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AdminController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableMethodSecurity(prePostEnabled = true)
public class AdminControllerTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private IKeycloakAdminService adminService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static Jwt superAdminJwt;
    private static Jwt adminJwt;
    private static Jwt userJwt;

    @BeforeAll
    public static void setup() {
        superAdminJwt = createMockJwtToken("SUPER_ADMIN", "SUPER_ADMIN", "ALL");
        adminJwt = createMockJwtToken("TEST", "ADMIN", "TEST");
        userJwt = createMockJwtToken("TEST", "USER", "TEST");
    }

    @DisplayName("Get All User Roles (For Super-Admins): Success")
    @WithMockUser(roles = "SUPER_ADMIN")
    @Test
    void givenValidJwtForSuperAdmins_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
        // Given
        List<String> roles = List.of("TEST_ROLE");
        given(adminService.retrieveAllUserRoles()).willReturn(roles);

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
                .andExpect(jsonPath("$.data", is(roles)))
                .andExpect(jsonPath("$.data", Matchers.hasSize(1)));
    }

    @DisplayName("Get All User Roles (For Admins): Success")
    @WithMockUser(roles = "ADMIN")
    @Test
    void givenValidJwtForAdmins_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
        // Given
        List<String> roles = List.of("TEST_ROLE");
        given(adminService.retrieveAllUserRolesByPilot(anyString())).willReturn(roles);

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
                .andExpect(jsonPath("$.data", is(roles)))
                .andExpect(jsonPath("$.data", Matchers.hasSize(1)));
    }

    @DisplayName("Get All User Roles (For Users): Unauthorized access")
    @WithMockUser(roles = "USER")
    @Test
    void givenValidJwtForUsers_whenGetAllUserRoles_thenReturnUnauthorized() throws Exception {
        // Given
        List<String> roles = List.of("TEST_ROLE");
        given(adminService.retrieveAllUserRoles()).willReturn(roles);

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

    @DisplayName("Get All Pilot Codes (Admin): Unauthorized action")
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

    @DisplayName("Create new Role: Success")
    @Test
    void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnSuccess() throws Exception {
        // Given
        UserRoleDto role = UserRoleDto.builder()
                .name("TestRole")
                .pilotRole("ADMIN")
                .pilotCode("TEST_PILOT")
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

    @DisplayName("Create new Role: Unauthorized Admin request")
    @Test
    void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnUnauthorizedForAdminInDifferentPilots() throws Exception {
        // Given
        UserRoleDto role = UserRoleDto.builder()
                .name("TestRole")
                .pilotRole("ADMIN")
                .pilotCode("ANOTHER_PILOT")
                .build();

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf())
                .content(objectMapper.writeValueAsString(role)));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
    }

    @DisplayName("Create new Role: Missing fields in request body")
    @Test
    void givenValidJwtAndNewRoleWithMissingFields_whenCreateNewUserRole_thenReturnBadRequest() throws Exception {
        // Given
        UserRoleCreationDto role = new UserRoleCreationDto("TestRole", null, "ADMIN", null);

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

    @DisplayName("Delete User Role: Admin Unauthorized for Different Pilot")
    @Test
    void givenValidJwt_whenDeleteUserRoleInDifferentPilot_thenReturnForbidden() throws Exception {
        // Given
        String roleName = "TestRole";

        // Mock service to return role from different pilot
        given(adminService.retrieveUserRoleByName(anyString()))
                .willReturn(UserRoleDto.builder()
                        .name("TestRole")
                        .pilotRole("ADMIN")
                        .pilotCode("INVALID_TEST_PILOT")
                        .description("Test description")
                        .build());

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
    }

    @DisplayName("Retrieve User Role: Success")
    @Test
    void givenValidJwt_whenRetrieveUserRole_thenReturnUserRole() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDto expectedRole = UserRoleDto.builder()
                .name(roleName.toUpperCase())
                .pilotRole("ADMIN")
                .pilotCode("TEST")
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
                .andExpect(jsonPath("$.data.name", is(roleName.toUpperCase())));
    }

    @DisplayName("Update User Role: Success")
    @WithMockUser(roles = "SUPER_ADMIN")
    @Test
    void givenValidJwtAndRole_whenUpdateUserRole_thenReturnSuccess() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDto roleToUpdate = UserRoleDto.builder()
                .name(roleName.toUpperCase())
                .pilotRole("ADMIN")
                .pilotCode("TEST")
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

    @DisplayName("Update User Role: Admin Unauthorized for Different Pilot")
    @WithMockUser(roles = "ADMIN")
    @Test
    void givenValidJwt_whenUpdateUserRoleInDifferentPilot_thenReturnForbidden() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDto existingRole = UserRoleDto.builder()
                .pilotCode("ANOTHER_PILOT")
                .build();

        when(adminService.retrieveUserRoleByName(roleName.trim().toUpperCase())).thenReturn(existingRole);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(existingRole)));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
    }

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

    @DisplayName("Forbidden Access for User: 403 Error")
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

    @DisplayName("Retrieval of User Roles for a specific Pilot Role: Success")
    @WithMockUser(roles = "SUPER_ADMIN")
    @Test
    void givenValidJwtAndPilotCode_whenSuperAdmin_thenReturnUserRoleNames() throws Exception {
        // Given
        String pilotRole = "ADMIN";
        List<String> mockRoles = Arrays.asList("ROLE1", "ROLE2");

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveAllUserRolesByType(anyString())).thenReturn(mockRoles);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles/type/{pilotRole}", pilotRole)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                .andExpect(jsonPath("$.data[0]", is("ROLE1")))
                .andExpect(jsonPath("$.data[1]", is("ROLE2")));
    }

    @DisplayName("Successful retrieval of users for specific role")
    @Test
    void givenValidJwtAndUserRole_whenSuperAdmin_thenReturnUsers() throws Exception {
        // Given
        String userRole = "OPERATOR";
        List<UserDto> mockUsers = Arrays.asList(
                UserDto.builder().username("user1").build(),
                UserDto.builder().username("user2").build()
        );

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveAllUsersByUserRole(anyString())).thenReturn(mockUsers);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/{userRole}/users", userRole)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Users associated with the role retrieved successfully")))
                .andExpect(jsonPath("$.data[0].username", is("user1")))
                .andExpect(jsonPath("$.data[1].username", is("user2")));
    }

    @DisplayName("Create a new pilot / organization : Success")
    @Test
    void givenPilotInformation_whenCreateNewPilotInSystem_thenReturnSuccess() throws Exception {
        // Given
        PilotCreationDto pilotData = new PilotCreationDto("TEST_PILOT", List.of("ADMIN"));

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
        PilotCreationDto pilotData = new PilotCreationDto("TEST_PILOT", List.of("ADMIN"));

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


    @DisplayName("Assign a Role to Pilot : Success")
    @Test
    void givenPilotAndRole_whenAssignUserRoleToPilot_thenReturnSuccess() throws Exception {
        // Given
        String pilot = "TEST_PILOT";
        String role = "TEST_ROLE";

        UserRoleDto existingRole = UserRoleDto.builder()
                .name(role)
                .pilotCode("TEST_PILOT")
                .pilotRole("ADMIN").build();

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(superAdminJwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveUserRoleByName(anyString())).thenReturn(existingRole);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotCode}/assign/roles/{role}", pilot, role)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role assigned successfully to pilot")));
    }

    @DisplayName("Assign a Role to Pilot : Failed - Admin assigned role outside organization")
    @Test
    void givenDifferentPilotAndRole_whenAssignUserRoleToPilot_thenReturnSuccess() throws Exception {
        // Given
        String pilot = "TEST_PILOT";
        String role = "TEST_ROLE";

        UserRoleDto existingRole = UserRoleDto.builder().name(role).pilotCode("TEST_ANOTHER_PILOT").pilotRole("ADMIN").build();

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(adminJwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveUserRoleByName(anyString())).thenReturn(existingRole);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/pilots/{pilotCode}/assign/roles/{role}", pilot, role)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("You are unauthorized to request/modify this resource")));
    }

    private static Jwt createMockJwtToken(String userRole, String pilotRole, String pilotCode){
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
