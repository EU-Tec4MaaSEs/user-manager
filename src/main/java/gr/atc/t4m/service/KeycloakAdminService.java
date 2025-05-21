package gr.atc.t4m.service;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;

import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.*;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Slf4j
public class KeycloakAdminService implements IKeycloakAdminService {

    private final Keycloak keycloak;

    private final String realm;
    private final String client;
    private final List<String> excludedSuperAdminRoles;
    private final List<String> excludedDefaultRoles;
    private static final String PILOT_ROLE = "pilot_role";
    private static final String PILOT_CODE = "pilot_code";

    // Client ID is the UUID of the client - It is used in many operations, and thus we retrieve it once per Application Initialization
    private String clientId;
    private boolean shouldInitClientId;

    public KeycloakAdminService(Keycloak keycloak, KeycloakProperties keycloakProperties) {
        this.keycloak = keycloak;
        realm = keycloakProperties.realm();
        client = keycloakProperties.clientId();
        excludedSuperAdminRoles = Optional.ofNullable(keycloakProperties.excludedSuperAdminRoles())
                .map(s -> Arrays.stream(s.split(","))
                        .map(String::trim)
                        .filter(str -> !str.isEmpty())
                        .toList())
                .orElse(List.of());

        excludedDefaultRoles = Optional.ofNullable(keycloakProperties.excludedDefaultRoles())
                .map(s -> Arrays.stream(s.split(","))
                        .map(String::trim)
                        .filter(str -> !str.isEmpty())
                        .toList())
                .orElse(List.of());
        shouldInitClientId = Optional.ofNullable(keycloakProperties.initClientId()).orElse(true);
    }
    // Called after the initialization of the Service to retrieve the Client UUID
    @EventListener(ApplicationReadyEvent.class)
    public void retrieveClientIdAfterServiceInitialization() {
        if (!shouldInitClientId) {
            log.info("Skipping Keycloak client ID retrieval (initClientId is false)");
            return;
        }
        this.clientId = retrieveClientId();
        log.info("Client ID retrieved from Keycloak and local variable initialized successfully");
    }

    // Refresh Client ID every 24 hours
    @Scheduled(cron = "0 0 0 * * *")
    public void refreshClientId() {
        this.clientId = retrieveClientId();
    }
    @Override
    public List<String> retrieveAllPilotCodes() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllPilotCodes'");
    }
    @Override
    public GroupRepresentation retrieveGroupRepresentationByName(String groupName) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveGroupRepresentationByName'");
    }
    @Override
    public void createPilot(PilotCreationDto newPilot) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createPilot'");
    }
    @Override
    public void deletePilotByName(String pilot) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deletePilotByName'");
    }
    @Override
    public void assignUserRoleToPilot(String userRole, String pilotCode) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'assignUserRoleToPilot'");
    }
    @Override
    public RoleRepresentation retrieveRealmRepresentationByName(String pilotRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveRealmRepresentationByName'");
    }
    @Override
    public List<String> retrieveAllPilotRoles(boolean isSuperAdmin) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllPilotRoles'");
    }
    @Override
    public String retrieveClientId() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveClientId'");
    }
    @Override
    public ClientRepresentation retrieveClientRepresentationByName(String client) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveClientRepresentationByName'");
    }
    @Override
    public List<String> retrieveAllUserRoles() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllUserRoles'");
    }
    @Override
    public List<String> retrieveAllUserRolesByPilot(String pilotCode) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllUserRolesByPilot'");
    }
    @Override
    public List<String> retrieveAllUserRolesByType(String pilotRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllUserRolesByType'");
    }
    @Override
    public List<String> retrieveAllUserRolesByTypeAndPilot(String pilotRole, String pilotCode) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllUserRolesByTypeAndPilot'");
    }
    @Override
    public UserRoleDto retrieveUserRoleByName(String userRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveUserRoleByName'");
    }
    @Override
    public List<UserDto> retrieveAllUsersByUserRole(String userRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'retrieveAllUsersByUserRole'");
    }
    @Override
    public void createUserRole(UserRoleCreationDto newUserRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createUserRole'");
    }
    @Override
    public void deleteUserRole(String userRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deleteUserRole'");
    }
    @Override
    public void updateUserRole(UserRoleDto updatedUserRole) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'updateUserRole'");
    }
}
