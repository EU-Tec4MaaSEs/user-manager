package gr.atc.t4m.controller;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserPermissionsDto;
import gr.atc.t4m.service.interfaces.IPermissionService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean; 
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = PermissionController.class)
@AutoConfigureMockMvc(addFilters = false)
class PermissionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private IPermissionService permissionService;

    @MockitoBean
    private IUserManagementService userManagementService;

    @Test
    @DisplayName("GET /organizations/{org} - Success")
    void retrievePermissionsForOrganization_Success() throws Exception {
        PermissionDto dto = PermissionDto.builder()
                .organization("ATC")
                .resource("CONTRACT")
                .scope("MANAGE")
                .build();

        given(permissionService.retrieveOrganizationPermissionMatrix("ATC"))
                .willReturn(List.of(dto));

        mockMvc.perform(get("/api/permissions/organizations/ATC"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data[0].organization").value("ATC"))
                .andExpect(jsonPath("$.message").value("Permissions for organization retrieved successfully"));
    }

 @Test
@DisplayName("GET /organizations/{org}/roles/{role} - Success")
void retrievePermissionsForRoleInOrganization_Success() throws Exception {
    // 1. Arrange
    PermissionDto dto = PermissionDto.builder()
            .organization("ATC")
            .role("admin")
            .resource("USER")
            .scope("MANAGE")
            .build();

    given(permissionService.retrievePermissionsForOrganizationAndRole(
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.anyString()))
        .willReturn(List.of(dto));

    mockMvc.perform(get("/api/permissions/organizations/ATC/roles/admin"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data").isArray())
            // This path should now work because @Data provided the getters
            .andExpect(jsonPath("$.data[0].role").value("admin"));
}

    @Test
    @DisplayName("GET /users/{userId}/permissions/{res}/{scope} - Returns True")
    void checkUserPermission_ReturnsTrue() throws Exception {
        String userId = "user-123";
        UserDto mockUser = new UserDto();
        mockUser.setPilotCode("VN2");
        mockUser.setUserRole("ADMIN");

        given(userManagementService.retrieveUserById(userId)).willReturn(mockUser);
        given(permissionService.hasPermission("VN2", "ADMIN", "CONTRACT", "VIEW")).willReturn(true);

        mockMvc.perform(get("/api/permissions/users/user-123/permissions/CONTRACT/VIEW"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value(true));
    }

    @Test
    @DisplayName("GET /users/{userId}/permissions/{res}/{scope} - Returns Forbidden when false")
    void checkUserPermission_ReturnsForbidden() throws Exception {
        String userId = "user-123";
        UserDto mockUser = new UserDto();
        mockUser.setPilotCode("VN2");
        mockUser.setUserRole("USER");

        given(userManagementService.retrieveUserById(userId)).willReturn(mockUser);
        given(permissionService.hasPermission("VN2", "USER", "CONTRACT", "MANAGE")).willReturn(false);

        mockMvc.perform(get("/api/permissions/users/user-123/permissions/CONTRACT/MANAGE"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.data").value(false))
                .andExpect(jsonPath("$.message").value("User does not have the required permission"));
    }

    @Test
    @DisplayName("GET /users/{userId}/permissions/{res}/{scope} - Bad Request on invalid enum")
    void checkUserPermission_InvalidInput() throws Exception {
        mockMvc.perform(get("/api/permissions/users/user-123/permissions/INVALID_RES/VIEW"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid input resource"));
    }

    @Test
    @DisplayName("GET /users/{userId}/permissions - Success")
    void getAllUserPermissions_Success() throws Exception {
        UserPermissionsDto mockDto = new UserPermissionsDto();
        mockDto.setUserId("user-123");
        mockDto.setPermissions(Map.of("CONTRACT", "MANAGE"));

        given(permissionService.retrieveAllUserPermissions("user-123")).willReturn(mockDto);

        mockMvc.perform(get("/api/permissions/users/user-123/permissions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value("user-123"))
                .andExpect(jsonPath("$.data.permissions.CONTRACT").value("MANAGE"));
    }

    @Test
    @DisplayName("GET /scopes - Success")
    void retrieveAllScopes_Success() throws Exception {
        mockMvc.perform(get("/api/permissions/scopes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray())
                .andExpect(jsonPath("$.data[0]").exists());
    }

    @Test
    @DisplayName("GET /resources - Success")
    void retrieveAllResources_Success() throws Exception {
        mockMvc.perform(get("/api/permissions/resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").isArray());
    }
}