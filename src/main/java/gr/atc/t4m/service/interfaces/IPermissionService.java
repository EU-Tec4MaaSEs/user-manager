package gr.atc.t4m.service.interfaces;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.dto.UserPermissionsDto;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * Service interface for managing permissions within the application.
 */
public interface IPermissionService {

    default boolean hasPermission(String organization, String role, String resource, String scope) {
        return true;
    }

    default List<PermissionDto> retrieveOrganizationPermissionMatrix(String organization) {
        return Collections.emptyList();
    }

    default List<PermissionDto> retrievePermissionsForOrganizationAndRole(String organization, String role) {
        return Collections.emptyList();
    }

    default boolean hasAnyPermission(String organization, String role, String resource, List<String> scopes) {
        return scopes.stream().anyMatch(scope -> hasPermission(organization, role, resource, scope));
    }

    default boolean hasAllPermissions(String organization, String role, String resource, List<String> scopes) {
        return scopes.stream().allMatch(scope -> hasPermission(organization, role, resource, scope));
    }

    default UserPermissionsDto retrieveAllUserPermissions(String userId) {
        return UserPermissionsDto.builder()
                .userId(userId)
                .permissions(new HashMap<>())
                .build();
    }
}
