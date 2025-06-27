package gr.atc.t4m.service.interfaces;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.List;

public interface IKeycloakAdminService {
    /*---------------------
     * Group Management
     ---------------------*/
    List<String> retrieveAllPilotCodes();

    GroupRepresentation retrieveGroupRepresentationByName(String groupName);

    GroupRepresentation retrieveSubgroupRepresentationByName(String parentGroupId, String subGroupName);

    void createPilot(PilotCreationDto newPilot);

    void deletePilotByName(String pilot);

    void assignUserRoleToPilot(String userRole, String pilotCode);

    /*---------------------
     * Realm Management
     ---------------------*/
    RoleRepresentation retrieveRealmRepresentationByName(String pilotRole);

    List<String> retrieveAllPilotRoles(boolean isSuperAdmin);

    /*---------------------
     * Client Management
     ---------------------*/
    String retrieveClientId();

    ClientRepresentation retrieveClientRepresentationByName(String client);

    List<UserRoleDto> retrieveAllUserRoles(boolean isSuperAdmin);

    List<String> retrieveAllUserRolesByPilot(String pilotCode);

    List<String> retrieveAllUserRolesByType(String pilotRole);

    List<String> retrieveAllUserRolesByTypeAndPilot(String pilotRole, String pilotCode);

    UserRoleDto retrieveUserRoleByName(String userRole);

    void createUserRole(UserRoleCreationDto newUserRole);

    void deleteUserRole(String userRole);

    void updateUserRole(UserRoleDto updatedUserRole);
}
