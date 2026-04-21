package gr.atc.t4m.service;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserPermissionsDto;
import gr.atc.t4m.enums.PermissionResource;
import gr.atc.t4m.enums.PermissionScope;
import gr.atc.t4m.service.interfaces.IPermissionService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import io.micrometer.observation.annotation.Observed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Map;
import gr.atc.t4m.util.ValueNetworkMatrix;
@Service
public class PermissionService implements IPermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);
    private static final String DEFAULT_VN = "VN2";

    private final KeycloakAdminService keycloakAdminService;
    private final IUserManagementService userManagementService;

    public PermissionService(KeycloakAdminService keycloakAdminService, IUserManagementService userManagementService) {
        this.keycloakAdminService = keycloakAdminService;
        this.userManagementService = userManagementService;
    }

    @Cacheable(value = "permissions", key = "{#organization, #role, #resource, #scope}")
    @Observed(name = "hasPermission", contextualName = "checking-permission")
    @Override
    public boolean hasPermission(String organization, String role, String resource, String scope) {
        String vnType = keycloakAdminService.retrieveValueNetworkAttribute(organization);
        
        if (vnType == null) {
            log.warn("Organization {} has no Value Network attribute assigned", organization);
            vnType = DEFAULT_VN; //FALL BACK TO A DEFAULT VN
        }
        String normalizedRole = role.trim().toUpperCase();
        PermissionScope assignedScope = ValueNetworkMatrix.getPermission(
                vnType, 
                normalizedRole, 
                PermissionResource.fromString(resource)
        );

        PermissionScope requestedScope = PermissionScope.fromString(scope);

        if (assignedScope == null || requestedScope == null) {
            return false;
        }

        // Hierarchy check (MANAGE > VIEW > NONE)
        return assignedScope.contains(requestedScope);
    }

    @Override
    public UserPermissionsDto retrieveAllUserPermissions(String userId) {
        UserDto user = userManagementService.retrieveUserById(userId);
        String organization = user.getPilotCode();
        String role = user.getUserRole();

        // Get the VN for this org
        String vnType = keycloakAdminService.retrieveValueNetworkAttribute(organization);

        if (vnType == null) { 
           log.warn("Organization {} is missing 'valueNetwork' attribute. Falling back to default: VN2", organization);
           vnType = DEFAULT_VN; //FALL BACK TO A DEFAULT VN
        }
        
        // Map all resources to their scopes for this VN + Role combination
        Map<String, String> permissionMap = ValueNetworkMatrix.getAllPermissions(vnType, role);

        return UserPermissionsDto.builder()
                .userId(userId)
                .permissions(permissionMap)
                .build();
    }

    // Default implementations for interface methods that are now read-only
    @Override
    public List<PermissionDto> retrieveOrganizationPermissionMatrix(String organization) {
        String vnType = keycloakAdminService.retrieveValueNetworkAttribute(organization);
        return ValueNetworkMatrix.getMatrixForVN(organization, vnType);
    }
}