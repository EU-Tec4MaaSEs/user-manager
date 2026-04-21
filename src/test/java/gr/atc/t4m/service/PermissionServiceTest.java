package gr.atc.t4m.service;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserPermissionsDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

    @Mock
    private KeycloakAdminService keycloakAdminService;

    @Mock
    private IUserManagementService userManagementService;

    @InjectMocks
    private PermissionService permissionService;

    @Test
    @DisplayName("hasPermission - Should return true when user has required scope")
    void hasPermission_Success() {
        // Arrange
        String org = "ATC";
        String role = "ADMIN";
        // VN1 ADMIN has CONTRACT:MANAGE (based on your Matrix code)
        given(keycloakAdminService.retrieveValueNetworkAttribute(org)).willReturn("VN1");

        boolean result = permissionService.hasPermission(org, role, "CONTRACT", "VIEW");

        assertTrue(result, "ADMIN in VN1 should have VIEW access to CONTRACT (since they have MANAGE)");
    }

@Test
@DisplayName("hasPermission - Should fallback to VN2 when attribute is null")
void hasPermission_FallbackToDefault() {
    // Arrange
    String org = "UNKNOWN_ORG";
    given(keycloakAdminService.retrieveValueNetworkAttribute(org)).willReturn(null);

    // We check VN2 -> ADMIN -> USER -> MANAGE which we know is defined in your Matrix
    boolean result = permissionService.hasPermission(org, "ADMIN", "USER", "MANAGE");

    // Assert
    assertTrue(result, "Should have returned true because VN2 ADMIN has MANAGE on USER");
}

    @Test
    @DisplayName("retrieveAllUserPermissions - Should return DTO with permission map")
    void retrieveAllUserPermissions_Success() {
        // Arrange
        String userId = "user-123";
        UserDto user = new UserDto();
        user.setPilotCode("ATC");
        user.setUserRole("ADMIN");

        given(userManagementService.retrieveUserById(userId)).willReturn(user);
        given(keycloakAdminService.retrieveValueNetworkAttribute("ATC")).willReturn("VN1");

        UserPermissionsDto result = permissionService.retrieveAllUserPermissions(userId);

        assertNotNull(result);
        assertEquals(userId, result.getUserId());
        assertFalse(result.getPermissions().isEmpty());
        assertEquals("MANAGE", result.getPermissions().get("CONTRACT"));
    }

    @Test
    @DisplayName("retrieveOrganizationPermissionMatrix - Should return full list of DTOs")
    void retrieveOrganizationPermissionMatrix_Success() {
        String org = "ATC";
        given(keycloakAdminService.retrieveValueNetworkAttribute(org)).willReturn("VN3");

        List<PermissionDto> result = permissionService.retrieveOrganizationPermissionMatrix(org);

        assertNotNull(result);
        // Verify that the list contains items from VN3
        boolean containsVn3Data = result.stream().anyMatch(d -> d.getOrganization().equals("ATC"));
        assertTrue(containsVn3Data);
    }

 
}