package gr.atc.t4m.service;

import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;

import static gr.atc.t4m.exception.CustomExceptions.*;

import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.*;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
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
    private static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN";
    private static final String PILOT_ROLE = "pilot_role";
    private static final String PILOT_CODE = "pilot_code";

    // Client ID is the UUID of the client - It is used in many operations, and thus we retrieve it once per Application Initialization
    private String clientId;
    private final boolean shouldInitClientId;

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
        try {
            if (!shouldInitClientId) {
                log.info("Skipping Keycloak client ID retrieval (initClientId is false)");
                return;
            }
            this.clientId = retrieveClientId();
            log.info("Client ID retrieved from Keycloak and local variable initialized successfully");
        } catch (Exception e) {
            log.error("Error retrieving client ID: {}", e.getMessage(), e);
        }
    }

    // Refresh Client ID every 24 hours
    @Scheduled(cron = "0 0 0 * * *")
    public void refreshClientId() {
        this.clientId = retrieveClientId();
    }

    /*---------------------
     * Group Management
     ---------------------*/

    /**
     * Retrieve all Groups / Pilots
     *
     * @return List<String>
     */
    @Override
    @Cacheable("pilotCodes")
    public List<String> retrieveAllPilotCodes() {
        List<GroupRepresentation> groups = retrieveAllGroupRepresentations();

        return groups.stream()
                .map(GroupRepresentation::getName)
                .toList();
    }

    /**
     * Retrieve Group / Pilot by Name
     *
     * @param groupName : Group Name
     * @return GroupRepresentation
     */
    @Override
    public GroupRepresentation retrieveGroupRepresentationByName(String groupName) {
        List<GroupRepresentation> groups = retrieveAllGroupRepresentations();

        return groups.stream()
                .filter(group -> group.getName().equalsIgnoreCase(groupName))
                .findFirst()
                .orElse(null);
    }

    /**
     * Retrieve Group / Pilot by Name
     *
     * @param parentGroupId : Parent Group ID
     * @param subGroupName  : Sub Group Name
     * @return GroupRepresentation
     */
    @Override
    public GroupRepresentation retrieveSubgroupRepresentationByName(String parentGroupId, String subGroupName) {
        try {
            return keycloak.realm(realm)
                    .groups()
                    .group(parentGroupId)
                    .getSubGroups(null, null, false)
                    .stream()
                    .filter(subGroup -> subGroupName.equals(subGroup.getName()))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.warn("Error finding subgroup '{}' in parent group: {}", subGroupName, e.getMessage());
            return null;
        }
    }

    /**
     * Create a Pilot (Group) in Keycloak
     *
     * @param newPilot : Pilot Data
     * @throws ResourceAlreadyExistsException : Thrown if Pilot already exists
     * @throws KeycloakException              : Thrown if Error creating Pilot
     */
    @Override
    @CacheEvict(value = "pilotCodes", allEntries = true)
    public void createPilot(PilotCreationDto newPilot) {
        GroupRepresentation existingRepresentation = retrieveGroupRepresentationByName(newPilot.name());
        if (existingRepresentation != null)
            throw new ResourceAlreadyExistsException("Pilot '" + newPilot.name() + "' already exists");

        PilotDto pilotDto = new PilotDto();
        pilotDto.setName(newPilot.name());
        pilotDto.setSubGroups(newPilot.subGroups());

        try {
            keycloak.realm(realm)
                    .groups()
                    .add(PilotDto.toGroupRepresentation(pilotDto));
        } catch (Exception e) {
            log.error("Error creating pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error creating pilot", e);
        }
    }

    /**
     * Delete Pilot by Name
     *
     * @param pilot : Pilot Name
     * @throws ResourceNotPresentException : Thrown if Pilot not found
     * @throws KeycloakException           : Thrown if Error deleting Pilot
     */
    @Override
    @CacheEvict(value = "pilotCodes", allEntries = true)
    public void deletePilotByName(String pilot) {
        GroupRepresentation groupRepresentation = retrieveGroupRepresentationByName(pilot);
        if (groupRepresentation == null)
            throw new ResourceNotPresentException("Pilot '" + pilot + "' not found");

        try {
            keycloak.realm(realm)
                    .groups()
                    .group(groupRepresentation.getId())
                    .remove();
        } catch (Exception e) {
            log.error("Error deleting pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error deleting pilot", e);
        }
    }

    /**
     * Assign a User Role to a specific Pilot (Group)
     *
     * @param userRole  : User Role
     * @param pilotCode : Pilot Code
     * @throws ResourceNotPresentException : Thrown if Pilot not found or User Role not found
     */
    @Override
    public void assignUserRoleToPilot(String userRole, String pilotCode) {
        GroupRepresentation groupRepresentation = retrieveGroupRepresentationByName(pilotCode);
        if (groupRepresentation == null)
            throw new ResourceNotPresentException("Pilot '" + pilotCode + "' not found");

        RoleRepresentation roleRepresentation = retrieveClientRoleRepresentationByName(userRole);
        if (roleRepresentation == null)
            throw new ResourceNotPresentException("Role '" + userRole + "' not found");

        try {
            List<RoleRepresentation> groupRoleRepresentations = retrieveAllClientRoleRepresentationsForSpecificGroup(groupRepresentation.getId());

            // Check if Role already exists
            boolean isExistentInGroupRoles = groupRoleRepresentations.stream()
                    .anyMatch(r -> r.getName().equalsIgnoreCase(userRole));

            if (isExistentInGroupRoles)
                return;

            // Assign the non-existent role to the Group
            keycloak.realm(realm)
                    .groups()
                    .group(groupRepresentation.getId())
                    .roles()
                    .clientLevel(retrieveClientId())
                    .add(Collections.singletonList(roleRepresentation));
        } catch (Exception e) {
            log.error("Error assigning user role to pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error assigning user role to pilot", e);
        }
    }

    /*
     * Helper method to retrieve all stored Client RoleRepresentations for a specific Group (Pilot)
     */
    List<RoleRepresentation> retrieveAllClientRoleRepresentationsForSpecificGroup(String groupId) {
        try {
            return keycloak.realm(realm)
                    .groups()
                    .group(groupId)
                    .roles()
                    .clientLevel(retrieveClientId())
                    .listAll();
        } catch (Exception e) {
            log.error("Unable to retrieve client roles for group :{}", groupId);
            return Collections.emptyList();
        }
    }

    /*
     * Helper method to retrieve all stored GroupRepresentations
     */
    List<GroupRepresentation> retrieveAllGroupRepresentations() {
        try {
            return keycloak.realm(realm)
                    .groups()
                    .groups();
        } catch (Exception e) {
            log.error("Error retrieving keycloak groups: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /*---------------------
     * Realm Management
     ---------------------*/

    /**
     * Retrieve Realm Representation (Pilot Role) by Name
     *
     * @param pilotRole : Pilot Role Name - Realm Role
     * @return RoleRepresentation
     */
    @Override
    public RoleRepresentation retrieveRealmRepresentationByName(String pilotRole) {
        List<RoleRepresentation> realmRoles = retrieveAllRealmRepresentations();

        return realmRoles.stream()
                .filter(role -> role.getName().equalsIgnoreCase(pilotRole))
                .findFirst()
                .orElse(null);
    }

    /**
     * Retrieve all Pilot Roles (Realm Roles) from Keycloak
     *
     * @param isSuperAdmin : Flag to determine if Super Admin
     * @return List<String>
     */
    @Override
    @Cacheable(value = "pilotRoles", key = "#isSuperAdmin")
    public List<String> retrieveAllPilotRoles(boolean isSuperAdmin) {
        List<String> excludedRoles = isSuperAdmin ? excludedSuperAdminRoles : excludedDefaultRoles;
        return retrieveAllRealmRepresentations().stream()
                .map(RoleRepresentation::getName)
                .filter(role -> !excludedRoles.contains(role))
                .toList();
    }

    /*
     * Helper method to retrieve all stored GroupRepresentations
     */
    List<RoleRepresentation> retrieveAllRealmRepresentations() {
        try {
            return keycloak.realm(realm)
                    .roles()
                    .list();
        } catch (Exception e) {
            log.error("Error retrieving keycloak realm roles: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /*---------------------
     * Client Management
     ---------------------*/

    /**
     * Retrieve Client UUID setup from Application Properties
     *
     * @return String (Client UUID)
     */
    @Override
    public String retrieveClientId() {
        return clientId != null ? clientId : locateClientId();
    }

    /**
     * Retrieve the Client ID for the setup Client
     *
     * @return Client UUID
     * @throws ResourceNotPresentException : Thrown if Client not found
     */
    String locateClientId() {
        ClientRepresentation clientRepresentation = retrieveClientRepresentationByName(client);
        if (clientRepresentation == null) {
            throw new ResourceNotPresentException("Client '" + client + "' not found");
        }

        return clientRepresentation.getId();
    }

    /**
     * Retrieve Client Representation from Keycloak
     *
     * @param client : Client Name
     * @return ClientRepresentation
     */
    @Override
    public ClientRepresentation retrieveClientRepresentationByName(String client) {
        try {
            return keycloak.realm(realm)
                    .clients()
                    .findByClientId(client)
                    .getFirst();
        } catch (Exception e) {
            log.error("Error retrieving client: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Retrieve all User Roles (For Super Admins / Admins)
     *
     * @return List<UserRoleDto>
     */
    @Override
    @Cacheable(value = "userRoles", key = "#isSuperAdmin")
    public List<UserRoleDto> retrieveAllUserRoles(boolean isSuperAdmin) {
        List<RoleRepresentation> clientRoles = retrieveAllClientRoleRepresentations();

        List<UserRoleDto> userRoleList = new ArrayList<>(clientRoles.stream()
                .map(UserRoleDto::toUserRoleDTO)
                .toList());

        if (!isSuperAdmin)
            userRoleList.removeIf(userRole -> SUPER_ADMIN_ROLE.equalsIgnoreCase(userRole.getName()));

        return userRoleList;
    }

    /**
     * Retrieve all User Roles by Pilot Code
     *
     * @param pilotCode : Pilot Code
     * @return List<String>
     */
    @Override
    @Cacheable(value = "userRoles", key = "#pilotCode")
    public List<String> retrieveAllUserRolesByPilot(String pilotCode) {
        List<RoleRepresentation> clientRoles = retrieveAllClientRoleRepresentations();

        return clientRoles.stream()
                .filter(role -> { // Filter by whether the Pilot Code existing in Attributes
                    Map<String, List<String>> attributes = role.getAttributes();
                    if (attributes == null || !attributes.containsKey(PILOT_CODE)) {
                        return false;
                    }
                    List<String> pilotCodes = attributes.get(PILOT_CODE);
                    return pilotCodes != null && pilotCodes.contains(pilotCode);
                })
                .map(RoleRepresentation::getName) // Get the role names that are applicable
                .toList();
    }

    /**
     * Retrieve all User Roles by Pilot Role type (Admin - User)
     *
     * @param pilotRole : Pilot Role
     * @return List<String>
     */
    @Override
    @Cacheable(value = "userRoles", key = "#pilotRole")
    public List<String> retrieveAllUserRolesByType(String pilotRole) {
        List<RoleRepresentation> clientRoles = retrieveAllClientRoleRepresentations();

        return clientRoles.stream()
                .filter(role -> { // Filter by whether the Pilot Role existing in Attributes
                    Map<String, List<String>> attributes = role.getAttributes();
                    if (attributes == null || !attributes.containsKey(PILOT_ROLE)) {
                        return false;
                    }
                    List<String> pilotRoles = attributes.get(PILOT_ROLE);
                    return pilotRoles != null && pilotRoles.contains(pilotRole);
                })
                .map(RoleRepresentation::getName) // Get the role names that are applicable
                .toList();
    }

    /**
     * Retrieve all User Roles by Pilot Role type and Pilot Code
     *
     * @param pilotRole : Pilot Role
     * @param pilotCode : Pilot Code
     * @return List<String>
     */
    @Override
    @Cacheable(value = "userRoles", key = "#pilotRole + '::' #pilotCode")
    public List<String> retrieveAllUserRolesByTypeAndPilot(String pilotRole, String pilotCode) {
        List<RoleRepresentation> clientRoles = retrieveAllClientRoleRepresentations();

        return clientRoles.stream()
                .filter(role -> { // Filter by whether the Pilot Role existing in Attributes
                    Map<String, List<String>> attributes = role.getAttributes();
                    if (attributes == null || !attributes.containsKey(PILOT_ROLE) || !attributes.containsKey(PILOT_CODE)) {
                        return false;
                    }
                    List<String> pilotRoles = attributes.get(PILOT_ROLE);
                    List<String> pilotCodes = attributes.get(PILOT_CODE);
                    return pilotCodes != null && pilotCodes.contains(pilotCode) && pilotRoles != null && pilotRoles.contains(pilotRole);
                })
                .map(RoleRepresentation::getName) // Get the role names that are applicable
                .toList();
    }

    /**
     * Retrieve User Role by its name from Keycloak
     *
     * @param userRole : User Role Name
     * @return UserRoleDto
     * @throws ResourceNotPresentException : Thrown if User Role not found
     */
    @Override
    public UserRoleDto retrieveUserRoleByName(String userRole) {
        RoleRepresentation existingRepresentation = retrieveClientRoleRepresentationByName(userRole.toUpperCase());
        if (existingRepresentation == null)
            throw new ResourceNotPresentException("Role '" + userRole.toUpperCase() + "' not found");

        return UserRoleDto.toUserRoleDTO(existingRepresentation);
    }

    /**
     * Create new User Role for the specified Client
     *
     * @param newUserRole : UserRoleDto
     * @throws ResourceAlreadyExistsException : Thrown if User Role already exists in Keycloak
     * @throws KeycloakException              : Thrown if Error creating User Role in Keycloak
     */
    @Override
    @CacheEvict(value = "userRoles", allEntries = true)
    public void createUserRole(UserRoleCreationDto newUserRole) {
        RoleRepresentation existingRepresentation = retrieveClientRoleRepresentationByName(newUserRole.name().toUpperCase());
        if (existingRepresentation != null)
            throw new ResourceAlreadyExistsException("Role '" + newUserRole.name() + "' already exists");

        // Transform data to proper Representation
        UserRoleDto userRoleDto = UserRoleDto.fromUserRoleCreationDto(newUserRole);
        RoleRepresentation newRoleRepresentation = UserRoleDto.toRoleRepresentation(userRoleDto, null);

        try {
            keycloak.realm(realm)
                    .clients()
                    .get(retrieveClientId())
                    .roles()
                    .create(newRoleRepresentation);
        } catch (Exception e) {
            log.error("Unable to create new User Role - Error: {}", e.getMessage());
            throw new KeycloakException("Unable to create new User Role", e);
        }

    }

    /**
     * Delete User Role for the specified Client by Name
     *
     * @param userRole : User Role Name
     * @throws ResourceNotPresentException : Thrown if User Role not found
     * @throws KeycloakException           : Thrown if Error deleting User Role in Keycloak
     */
    @Override
    @CacheEvict(value = "userRoles", allEntries = true)
    public void deleteUserRole(String userRole) {
        RoleRepresentation existingRepresentation = retrieveClientRoleRepresentationByName(userRole.toUpperCase());
        if (existingRepresentation == null)
            throw new ResourceNotPresentException("Role '" + userRole.toUpperCase() + "' not found");

        try {
            keycloak.realm(realm)
                    .clients()
                    .get(retrieveClientId())
                    .roles()
                    .get(existingRepresentation.getName())
                    .remove();
        } catch (Exception e) {
            log.error("Unable to delete User Role - Error: {}", e.getMessage());
            throw new KeycloakException("Unable to delete User Role", e);
        }
    }

    /**
     * Update User Role for the specified Client in Keycloak
     *
     * @param updatedUserRole : Updated User Role data
     */
    @Override
    @CacheEvict(value = "userRoles", allEntries = true)
    public void updateUserRole(UserRoleDto updatedUserRole) {
        String userRole = updatedUserRole.getName();
        RoleRepresentation existingRepresentation = retrieveClientRoleRepresentationByName(userRole);
        if (existingRepresentation == null)
            throw new ResourceNotPresentException("Role '" + userRole + "' not found");

        RoleRepresentation updatedRoleRepresentation = UserRoleDto.toRoleRepresentation(updatedUserRole, existingRepresentation);
        try {
            keycloak.realm(realm)
                    .clients()
                    .get(retrieveClientId())
                    .roles()
                    .get(existingRepresentation.getName())
                    .update(updatedRoleRepresentation);
        } catch (Exception e) {
            log.error("Unable to update User Role - Error: {}", e.getMessage());
            throw new KeycloakException("Unable to update User Role", e);
        }
    }

    /*
     * Helper method to retrieve all stored Client RoleRepresentations
     */
    List<RoleRepresentation> retrieveAllClientRoleRepresentations() {
        try {
            return keycloak.realm(realm)
                    .clients()
                    .get(retrieveClientId())
                    .roles()
                    .list(false); // Set the Brief Representation to false in order to retrieve all info for the User Roles
        } catch (Exception e) {
            log.error("Error retrieving user roles: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /*
     * Helper method to retrieve a specific Client RoleRepresentation by UserRole name
     */
    RoleRepresentation retrieveClientRoleRepresentationByName(String userRole) {
        try {
            return keycloak.realm(realm)
                    .clients()
                    .get(retrieveClientId())
                    .roles()
                    .get(userRole)
                    .toRepresentation();
        } catch (Exception e) {
            log.error("Error retrieving user role {} - Error: {}", userRole, e.getMessage(), e);
            return null;
        }
    }
}
