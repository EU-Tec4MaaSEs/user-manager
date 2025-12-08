package gr.atc.t4m.service;

import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PasswordsDto;
import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.enums.OrganizationDataFields;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.StringNormalizationUtils;
import io.micrometer.observation.annotation.Observed;
import jakarta.validation.ValidationException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static gr.atc.t4m.exception.CustomExceptions.*;

@Service
@Slf4j
public class UserManagementService implements IUserManagementService {

    private final Keycloak keycloak;

    private final KeycloakProperties keycloakProperties;

    private final IKeycloakAdminService adminService;

    private final IEmailService emailService;

    private final CacheService cacheService;

    private static final long ACTIVATION_TOKEN_EXPIRY_MS = TimeUnit.DAYS.toMillis(3);

    private static final String USER_ACTIVATION_ERROR = "User is not activated. Password can not be reset";
    private static final String ACTIVATION_TOKEN = "activation_token";
    private static final String ACTIVATION_EXPIRY = "activation_expiry";
    private static final String RESET_TOKEN = "reset_token";
    private static final String PILOT_ROLE = "pilot_role";
    private static final String GLOBAL_PILOT_CODE = "ALL";
    private static final String DEFAULT_PILOT = "DEFAULT";
    private static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN";

    private final String realm;
    private final String serverUrl;
    private final String clientId;
    private final String clientSecret;


    public UserManagementService(Keycloak keycloak, KeycloakProperties keycloakProperties, IKeycloakAdminService adminService, IEmailService emailService, CacheService cacheService) {
        this.keycloak = keycloak;
        this.keycloakProperties = keycloakProperties;
        this.adminService = adminService;
        this.emailService = emailService;
        this.cacheService = cacheService;
        realm = keycloakProperties.realm();
        serverUrl = keycloakProperties.url();
        clientId = keycloakProperties.clientId();
        clientSecret = keycloakProperties.clientSecret();
    }

    /**
     * Handles logout of user in Async("taskExecutor") manner for better performance
     *
     * @param userId : User ID
     */
    @Async("taskExecutor")
    @Override
    public void logoutUser(String userId) {
        try {
            keycloak.realm(keycloakProperties.realm())
                    .users()
                    .get(userId)
                    .logout();
        } catch (NotFoundException e) {
            log.error("User with ID: {}, not found - Error: {}", userId, e.getMessage());
        } catch (Exception e) {
            log.error("Error during logout - Error: {}", e.getMessage());
        }
    }

    /**
     * Delete user from Keycloak
     *
     * @param userId : User ID
     * @throws ResourceNotPresentException : Thrown when user with given ID is not present in Keycloak
     * @throws KeycloakException           : When a Keycloak communication error occurs
     */
    @Observed(name = "user.delete", contextualName = "deleting-user")
    @Override
    public void deleteUser(String userId) {
        UserRepresentation user = retrieveUserRepresentationById(userId);
        if (user == null)
            throw new ResourceNotPresentException("User with ID " + userId + " not found");

        UserDto legacyUser = UserDto.fromUserRepresentation(user);
        try {
            keycloak.realm(realm)
                    .users()
                    .get(userId)
                    .remove();
            log.debug("User '{}' deleted successfully", userId);

            // Evict Caches
            cacheService.evictUserCaches(userId, legacyUser.getPilotCode(), legacyUser.getUserRole(), legacyUser.getPilotRole());
        } catch (Exception e) {
            log.error("Error deleting user {}: {}", userId, e.getMessage());
            throw new KeycloakException("Error deleting user with id = " + userId, e);
        }
    }

    /**
     * Create a new User in Keycloak
     *
     * @param userData           : User Information
     * @param autogeneratedToken : Activation Token
     * @return User ID
     * @throws ValidationException            : When input data are invalid (not exist in Keycloak)
     * @throws KeycloakException              : When a Keycloak communication error occurs
     * @throws ResourceAlreadyExistsException : When user's email already exists
     */
    @Observed(name = "user.create", contextualName = "creating-user")
    @Override
    public String createUser(UserCreationDto userData, String autogeneratedToken) {

        // Ensure that user doesn't exist in Auth Server
        UserRepresentation keycloakUser = retrieveUserRepresentationByEmail(userData.email());
        if (keycloakUser != null)
            throw new ResourceAlreadyExistsException("User with given email already exists in Keycloak");

        UserDto user = UserDto.fromUserCreationDto(userData);
        // Check if Pilot Code is not the Default or the Global, locate the corresponding Organization ID and store it as attribute of User
        if (!DEFAULT_PILOT.equalsIgnoreCase(user.getPilotCode()) && !GLOBAL_PILOT_CODE.equalsIgnoreCase(user.getPilotCode())) {
            GroupRepresentation groupRep = adminService.retrieveGroupRepresentationByName(user.getPilotCode());
            if (groupRep != null) {
                PilotDto pilotDto = PilotDto.fromGroupRepresentation(groupRep);
                if (pilotDto.getOrganizationId() != null) {
                    user.setOrganizationId(pilotDto.getOrganizationId());
                } else {
                    log.warn("Unable to retrieve organization ID for pilot code: {}", user.getPilotCode());
                }
            }
        }

        if (!hasValidKeycloakAttributes(user))
            throw new ValidationException("Some of the input data are not present in Keycloak (Pilot Role, Pilot Code, User Role)");

        // Set the activation token and expiry
        user.setActivationToken(autogeneratedToken);
        user.setTokenFlagRaised(false);
        user.setActivationExpiry(String.valueOf(System.currentTimeMillis() + ACTIVATION_TOKEN_EXPIRY_MS)); // 3 Days expiration time

        // Convert UserDto to UserRepresentation
        UserRepresentation newUser = UserDto.toUserRepresentation(user, null);
        try {
            Response response = keycloak.realm(realm)
                    .users()
                    .create(newUser);

            String createdUserId = extractUserIdFromResponse(response);

            // Evict Caches (normalized values)
            cacheService.evictUserCaches(
                    createdUserId,
                    StringNormalizationUtils.normalize(user.getPilotCode()),
                    StringNormalizationUtils.normalize(user.getUserRole()),
                    StringNormalizationUtils.normalize(user.getPilotRole())
            );

            return createdUserId;
        } catch (Exception e) {
            log.error("Error during user creation: {}", e.getMessage(), e);
            throw new KeycloakException("Error during user creation", e);
        }
    }

    /**
     * Extract UserId from Keycloak Response if successful
     *
     * @param response : Keycloak Response
     * @return UserId or Null
     */
    private String extractUserIdFromResponse(Response response) {
        // Check if the user was created successfully
        if (response.getStatus() == 201) {  // 201 Created
            // Extract user ID from Location header
            String locationHeader = response.getHeaderString("Location");
            String userId = extractUserIdFromLocation(locationHeader);
            log.info("User created successfully with ID: {}", userId);
            return userId;
        } else {
            // Handle error response
            String errorMsg = response.readEntity(String.class);
            log.error("Failed to create user in Keycloak. Status: {}, Response: {}", response.getStatus(), errorMsg);
            throw new KeycloakException("Failed to create user in Keycloak. Status: " + response.getStatus() + ", Response: " + errorMsg);
        }
    }

    /**
     * Extract user ID from Location header
     * Location format: <a href="http://keycloak-host:port/auth/admin/realms/">...</a>{realm}/users/{user-id}
     */
    private String extractUserIdFromLocation(String locationHeader) {
        if (locationHeader != null) {
            // Get the last part of the URL which is the user ID
            return locationHeader.substring(locationHeader.lastIndexOf('/') + 1);
        }
        throw new ResourceNotPresentException("User ID not found in response");
    }

    /**
     * Update a User in Keycloak
     *
     * @param user : Updated user data
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws ValidationException         : When input data are invalid (do not exist in Keycloak)
     * @throws KeycloakException           : When a Keycloak communication error occurs
     */
    @Observed(name = "user.update", contextualName = "updating-user")
    @Override
    public void updateUser(UserDto user) {
        if (!hasValidKeycloakAttributes(user))
            throw new ValidationException("Some of the input data are not present in Keycloak (Pilot Role, Pilot Code, User Role)");

        try {
            UserResource userResource = keycloak.realm(realm)
                    .users()
                    .get(user.getUserId());

            UserRepresentation existingUser = userResource.toRepresentation();
            if (existingUser == null)
                throw new ResourceNotPresentException("User with ID: " + user.getUserId() + " not found");

            // Capture legacy user data before update (for cache eviction)
            UserDto legacyUser = UserDto.fromUserRepresentation(existingUser);

            // Check if Pilot Code is altered and assign new Groups to User and change the Organization ID
            if (user.getPilotCode() != null) {
                String currentPilotRole = determinePilotRole(user, existingUser);
                GroupRepresentation groupRepr = adminService.retrieveGroupRepresentationByName(user.getPilotCode());

                String organizationId = extractOrganizationId(groupRepr, user.getPilotCode());
                user.setOrganizationId(organizationId);

                assignGroupsToUser(user.getPilotCode(), currentPilotRole, userResource);
            }


            userResource.update(UserDto.toUserRepresentation(user, existingUser));
            log.debug("User '{}' updated successfully", user.getUserId());

            // Evict Caches (normalized values)
            cacheService.evictLegacyUserCaches(
                    user.getUserId(),
                    StringNormalizationUtils.normalize(legacyUser.getPilotCode()),
                    StringNormalizationUtils.normalize(legacyUser.getUserRole()),
                    StringNormalizationUtils.normalize(legacyUser.getPilotRole()),
                    StringNormalizationUtils.normalize(user.getPilotCode()),
                    StringNormalizationUtils.normalize(user.getUserRole()),
                    StringNormalizationUtils.normalize(user.getPilotRole())
            );
        } catch (ResourceNotPresentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error updating user {}: {}", user.getUserId(), e.getMessage(), e);
            throw new KeycloakException("Error updating user with id = " + user.getUserId(), e);
        }
    }

    /*
     * Helper method to determine the Pilot Role
     */
    private String determinePilotRole(UserDto user, UserRepresentation existingUser) {
        return user.getPilotRole() != null
                ? user.getPilotRole()
                : existingUser.getAttributes().get(PILOT_ROLE).getFirst();
    }

    /*
     * Helper method to Extract Organization ID for a given Group Representation
     */
    private String extractOrganizationId(GroupRepresentation groupRepr, String pilotCode) {
        Map<String, List<String>> attributes = groupRepr.getAttributes();
        String orgIdKey = OrganizationDataFields.ORGANIZATION_ID.toString();

        if (attributes.isEmpty() || !attributes.containsKey(orgIdKey)) {
            throw new ResourceNotPresentException(
                    "Unable to locate Organization attributes in Group Representation for Pilot: " + pilotCode);
        }

        List<String> organizationIds = attributes.get(orgIdKey);
        if (organizationIds == null || organizationIds.isEmpty()) {
            throw new ResourceNotPresentException(
                    "Unable to locate Organization ID for Pilot: " + pilotCode);
        }

        return organizationIds.getFirst();
    }

    /*
     * Remove legacy group and include the new ones
     */
    void assignGroupsToUser(String pilotCode, String pilotRole, UserResource userResource) {
        try {
            userResource.groups().forEach(gr -> userResource.leaveGroup(gr.getId()));

            // Find parent group by name
            GroupRepresentation parentGroup = adminService.retrieveGroupRepresentationByName(pilotCode.trim().toUpperCase());
            if (parentGroup != null) {
                userResource.joinGroup(parentGroup.getId());

                // Find subgroup within the parent group
                GroupRepresentation roleGroup = adminService.retrieveSubgroupRepresentationByName(parentGroup.getId(), pilotRole.trim().toUpperCase());
                if (roleGroup != null) {
                    userResource.joinGroup(roleGroup.getId());
                } else {
                    log.warn("Role subgroup '{}' not found in parent group '{}'", pilotRole, pilotCode);
                }
            } else {
                log.warn("Parent group '{}' not found", pilotCode);
            }

        } catch (Exception e) {
            log.error("Error assigning groups to user: {}", e.getMessage(), e);
        }
    }

    /*
     * Helper method to define if input data are available in Keycloak
     */
    boolean hasValidKeycloakAttributes(UserDto user) {
        // Check valid user role but omit this check for Global Code of Super Admin
        if (user.getUserRole() != null && !user.getUserRole().equals(SUPER_ADMIN_ROLE)) {
            boolean validRole = adminService.retrieveAllUserRoles(true)
                    .stream()
                    .map(UserRoleDto::getName)
                    .toList()
                    .contains(StringNormalizationUtils.normalize(user.getUserRole()));
            if (!validRole) return false;
        }

        // Check valid pilot code but omit this check for Global Code of Super Admin
        if (user.getPilotCode() != null && !user.getPilotCode().equals(GLOBAL_PILOT_CODE)) {
            List<String> pilots = adminService.retrieveAllPilotCodes();
            boolean validPilotCode = pilots.contains(StringNormalizationUtils.normalize(user.getPilotCode()));
            if (!validPilotCode) return false;
        }

        if (user.getPilotRole() != null) {
            return adminService.retrieveAllPilotRoles(true)
                    .contains(StringNormalizationUtils.normalize(user.getPilotRole()));
        }

        return true;
    }


    /**
     * Retrieve all Users stored in Keycloak
     *
     * @return List<UserDto>
     */
    @Observed(name = "user.retrieve-all", contextualName = "retrieving-all-users")
    @Override
    @Cacheable(value = "users", key = "'all-users'")
    public List<UserDto> retrieveAllUsers() {
        try {
            List<UserRepresentation> users = keycloak.realm(realm)
                    .users()
                    .list();

            return users.stream()
                    .map(UserDto::fromUserRepresentation)
                    .toList();
        } catch (Exception e) {
            log.error("Error retrieving all users: {}", e.getMessage(), e);
            throw new KeycloakException("Error retrieving all users", e);
        }
    }

    /**
     * Retrieve all Users for a specific Pilot
     *
     * @param pilotCode : Pilot Code
     * @return List<UserDto>
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws KeycloakException           : When a Keycloak communication error occurs
     */
    @Override
    @Cacheable(value = "users", key = "#pilotCode")
    public List<UserDto> retrieveUsersByPilotCode(String pilotCode) {
        GroupRepresentation existingGroupRepresentation = adminService.retrieveGroupRepresentationByName(pilotCode);
        if (existingGroupRepresentation == null)
            throw new ResourceNotPresentException("Pilot code: '" + pilotCode + "' not found");

        try {
            return keycloak.realm(realm)
                    .groups()
                    .group(existingGroupRepresentation.getId())
                    .members()
                    .stream()
                    .map(UserDto::fromUserRepresentation)
                    .toList();
        } catch (Exception e) {
            log.error("Error retrieving users by pilot code: {}", e.getMessage(), e);
            throw new KeycloakException("Error retrieving users for pilot code '" + pilotCode, e);
        }
    }

    /**
     * Retrieve all users for a specific Pilot and User Role
     *
     * @param pilotCode : Pilot Code
     * @param userRole  : User Role
     * @return List<UserDto>
     */
    @Override
    @Cacheable(value = "users", key = "#pilotCode + '::' + #userRole")
    public List<UserDto> retrieveUsersByPilotCodeAndUserRole(String pilotCode, String userRole) {
        return retrieveUsersByPilotCode(pilotCode).stream()
                .filter(user -> user.getUserRole().equals(userRole))
                .toList();
    }

    /**
     *
     * @param jwtPilotRole : Pilot Role of user requested the resource
     * @param jwtPilot     : Pilot Code of user requested the resource
     * @param userRole     : User Role of user requested the resource
     * @return List<UserDto>
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws ForbiddenAccessException    : Thrown when a user has not the rights to access a resource
     */
    @Override
    @Cacheable(value = "users", key = "#userRole")
    public List<UserDto> retrieveAllUsersByUserRole(String jwtPilotRole, String jwtPilot, String userRole) {
        // Block non Super-Admin users to retrieve the list of users for 'SUPER_ADMIN' role
        if (!jwtPilotRole.equalsIgnoreCase(SUPER_ADMIN_ROLE) && userRole.equalsIgnoreCase(SUPER_ADMIN_ROLE))
            throw new ForbiddenAccessException("Non 'SUPER-ADMIN' users can not retrieve uses of role 'SUPER-ADMIN'");

        try {
            return keycloak.realm(realm)
                    .clients()
                    .get(adminService.retrieveClientId())
                    .roles()
                    .get(userRole)
                    .getUserMembers()
                    .stream()
                    .map(UserDto::fromUserRepresentation)
                    .toList();
        } catch (NotFoundException e) {
            throw new ResourceNotPresentException("Role '" + userRole + "' not found");
        } catch (Exception e) {
            throw new KeycloakException("Error retrieving users by specified role", e);
        }
    }

    /**
     * Retrieve User By ID
     *
     * @param userId : User ID
     * @return UserRepresentation
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     */
    @Override
    @Cacheable(value = "users", key = "#userId")
    public UserDto retrieveUserById(String userId) {
        UserRepresentation user = retrieveUserRepresentationById(userId);
        if (user == null)
            throw new ResourceNotPresentException("User with ID " + userId + " not found");

        return UserDto.fromUserRepresentation(user);
    }

    /**
     * Change user password operation - Note: Keycloak does not expose directly Users Credentials
     * So we need to check if we get an access token and if the operation is successful to reset the password
     *
     * @param passwords : Old and New password
     * @param userId    : User ID
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws InvalidPasswordException    : Thrown when given old password does not match with the stored password
     * @throws KeycloakException           : When a Keycloak communication error occurs
     */
    @Observed(name = "user.password-change", contextualName = "changing-user-password")
    @Override
    public void changePassword(PasswordsDto passwords, String userId) {
        // Retrieve current Users Resource
        UserResource userResource = retrieveUsersResourceById(userId);
        if (userResource == null)
            throw new ResourceNotPresentException("User with ID " + userId + " not found");

        // Validate Current Password
        if (!validateCurrentPassword(userResource.toRepresentation().getEmail(), passwords.oldPassword()))
            throw new InvalidPasswordException("Current password is incorrect");

        // Set new Password
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(passwords.newPassword());
        credential.setTemporary(false);

        // Reset the password
        try {
            userResource.resetPassword(credential);
            log.debug("Password successfully changed for user: {}", userId);
        } catch (Exception e) {
            log.error("Error updating user password {}: {}", userId, e.getMessage());
            throw new KeycloakException("Error updating user password with id = " + userId, e);
        }
    }

    /**
     * Validate current password by attempting to authenticate to Keycloak
     *
     * @param email       : User's email
     * @param oldPassword : Legacy Password
     * @return True on success, False on error
     */
    boolean validateCurrentPassword(String email, String oldPassword) {
        try (Keycloak testKeycloakAccess = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(email)
                .password(oldPassword)
                .build()) {

            testKeycloakAccess.tokenManager().getAccessToken();
            return true;
        } catch (Exception e) {
            log.debug("Password validation failed for user: {}", email);
            return false;
        }
    }

    /**
     * Send email to user with reset token and update his/her attributes accordingly
     *
     * @param email : User Email
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws UserActivateStatusException : Thrown when user is not activated
     */
    @Observed(name = "user.forgot-password", contextualName = "processing-forgot-password")
    @Override
    public void forgotPassword(String email) {
        UserRepresentation user = retrieveUserRepresentationByEmail(email);
        if (user == null)
            throw new ResourceNotPresentException("User with email " + email + " not found");

        if (!user.isEnabled())
            throw new UserActivateStatusException(USER_ACTIVATION_ERROR);

        // Formulate reset token and update user
        UserDto updatedUserData = new UserDto();
        updatedUserData.setResetToken(UUID.randomUUID().toString());
        updatedUserData.setTokenFlagRaised(false);
        updatedUserData.setUserId(user.getId());
        updateUser(updatedUserData);

        String resetToken = user.getId().concat("@").concat(updatedUserData.getResetToken());

        String fullName = user.getFirstName() + " " + user.getLastName();
        emailService.sendResetPasswordLink(fullName, email, resetToken);
    }

    /**
     * Reset user password
     *
     * @param userId     : User ID
     * @param resetToken : Reset Token
     * @param password   : New Password
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     * @throws UserActivateStatusException : Thrown when user is not activated
     */
    @Observed(name = "user.password-reset", contextualName = "resetting-user-password")
    @Override
    public void resetPassword(String userId, String resetToken, String password) {
        UserRepresentation user = retrieveUserRepresentationById(userId);
        if (user == null)
            throw new ResourceNotPresentException("User with id " + userId + " not found");

        // Validate that user is active otherwise throw an exception
        if (!user.isEnabled()) {
            throw new UserActivateStatusException(USER_ACTIVATION_ERROR);
        }

        // Validate that user contains reset token field
        if (user.getAttributes() == null || !user.getAttributes().containsKey(RESET_TOKEN) || !user.getAttributes().get(RESET_TOKEN).getFirst().equals(resetToken))
            // If any condition is not met, throw an exception
            throw new InvalidRefreshTokenException("Reset token is wrong or there is no reset token for specific user. Please contact the admin of your organization");

        try {
            UserResource userResource = keycloak.realm(realm)
                    .users()
                    .get(userId);

            // Step 1: Remove reset token from user attributes
            if (user.getAttributes() != null) {
                user.getAttributes().remove(RESET_TOKEN);
            }
            userResource.update(user);
            log.debug("Reset token removed for user '{}'", userId);

            // Step 2: Set the new password using the dedicated resetPassword endpoint
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(false);
            userResource.resetPassword(credential);

            log.info("Password successfully reset for user: {}", userId);
        } catch (Exception e) {
            log.error("Error resetting password for user {}: {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error resetting password for user with id = " + userId, e);
        }
    }

    /**
     * Activate user
     *
     * @param userId          : User ID
     * @param activationToken : Activation Token
     * @param password        : New Password
     * @throws ResourceNotPresentException : Thrown when a user if not found in Keycloak
     */
    @Observed(name = "user.activate", contextualName = "activating-user")
    @Override
    public void activateUser(String userId, String activationToken, String password) {
        UserRepresentation existingUser = retrieveUserRepresentationById(userId);
        if (existingUser == null)
            throw new ResourceNotPresentException("User with id " + userId + " not found");

        if (existingUser.isEnabled()) {
            throw new UserActivateStatusException("User is already active");
        }

        // Validate the activation token and its expiry
        // - Ensure that both ACTIVATION_TOKEN and ACTIVATION_EXPIRY attributes exist in the user's
        // attributes.
        // - Verify that the ACTIVATION_TOKEN matches the provided activationToken.
        // - Check that the ACTIVATION_EXPIRY time has not passed.
        if (existingUser.getAttributes() == null
                || !existingUser.getAttributes().containsKey(ACTIVATION_EXPIRY)
                || !existingUser.getAttributes().containsKey(ACTIVATION_TOKEN)
                || !existingUser.getAttributes().get(ACTIVATION_TOKEN).getFirst().equals(activationToken)
                || existingUser.getAttributes().get(ACTIVATION_EXPIRY).getFirst()
                .compareTo(String.valueOf(System.currentTimeMillis())) < 0) {
            // If any condition is not met, throw an exception
            throw new InvalidActivationAttributesException(
                    "Invalid activation token or activation expiry has passed. Please contact the admin of your organization.");
        }

        try {
            UserResource userResource = keycloak.realm(realm)
                    .users()
                    .get(userId);

            // Step 1: Enable user and remove activation tokens
            existingUser.setEnabled(true);
            if (existingUser.getAttributes() != null) {
                existingUser.getAttributes().remove(ACTIVATION_TOKEN);
                existingUser.getAttributes().remove(ACTIVATION_EXPIRY);
            }
            userResource.update(existingUser);
            log.debug("User '{}' enabled and activation tokens removed", userId);

            // Step 2: Set the password
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(false);

            userResource.resetPassword(credential);
            log.debug("Password set for user '{}'", userId);
        } catch (Exception e) {
            log.error("Error activating user {}: {}", userId, e.getMessage(), e);
            throw new KeycloakException("Error activating user with id = " + userId, e);
        }
    }

    /**
     * Call functions to assign roles to user
     *
     * @param userData : User details
     */
    @Async("taskExecutor")
    @Override
    public void assignRolesToUser(UserDto userData) {
        if (userData == null || userData.getUserId() == null)
            return;

        try {
            // Get user resource
            UserResource userResource = retrieveUsersResourceById(userData.getUserId());
            // Assign Realm Roles
            if (userData.getPilotRole() != null) {
                if (assignRealmRole(userData.getPilotRole(), userData.getUserId(), userResource))
                    log.info("Realm role '{}' assigned to user with ID: {}", userData.getPilotRole(), userData.getUserId());
                else
                    log.error("Realm role '{}' not assigned to user with ID: {}", userData.getPilotRole(), userData.getUserId());
            }


            // Assign Client Roles
            if (userData.getUserRole() != null) {
                if (assignClientRole(userData.getUserRole(), userData.getUserId(), userResource))
                    log.info("Client role '{}' assigned to user with ID: {}", userData.getUserRole(), userData.getUserId());
                else
                    log.error("Client role '{}' not assigned to user with ID: {}", userData.getUserRole(), userData.getUserId());
            }
        } catch (NotFoundException e) {
            log.error("User with ID: {} not found", userData.getUserId());
        } catch (Exception e) {
            log.error("Error retrieving user resource with ID: {}", userData.getUserId());
        }
    }

    /**
     * Function to assign Realm Role to user removing any legacy role
     *
     * @param pilotRole : Pilot Role to be assigned to User
     * @param userId    : ID of user
     */
    @Override
    public boolean assignRealmRole(String pilotRole, String userId, UserResource userResource) {
        try {
            RoleRepresentation newRealmRole = keycloak.realm(realm)
                    .roles()
                    .get(pilotRole)
                    .toRepresentation();

            // Get all realm roles for user
            List<RoleRepresentation> currentRealmRoles = userResource
                    .roles()
                    .realmLevel()
                    .listAll();

            // Check if user is already present
            if (currentRealmRoles.contains(newRealmRole)) {
                log.info("Realm Role '{}' already assigned to user with ID: {}", pilotRole, userId);
                return true;
            }

            // Remove all realm roles
            if (!currentRealmRoles.isEmpty()) {
                userResource.roles()
                        .realmLevel()
                        .remove(currentRealmRoles);
            }
            userResource.roles()
                    .realmLevel()
                    .add(List.of(newRealmRole));
            return true;
        } catch (NotFoundException e) {
            log.error("Realm role '{}' not found in Keycloak", pilotRole);
            return false;
        } catch (Exception e) {
            log.error("Unable to assign realm role of {} to user {}", pilotRole, userId);
            return false;
        }
    }

    /**
     * Function to assign Client Role to user
     *
     * @param userRole : User Role to be assigned to User
     * @param userId   : ID of user
     */
    @Override
    public boolean assignClientRole(String userRole, String userId, UserResource userResource) {
        String clientIdentification = adminService.retrieveClientId();
        try {
            RoleRepresentation newClientRole = keycloak.realm(realm)
                    .clients()
                    .get(clientIdentification)
                    .roles()
                    .get(userRole)
                    .toRepresentation();

            List<RoleRepresentation> currentClientRoles = userResource.roles()
                    .clientLevel(clientIdentification)
                    .listAll();

            // Check if user is already present
            if (currentClientRoles.contains(newClientRole)) {
                log.info("Client Role '{}' already assigned to user with ID: {}", userRole, userId);
                return true;
            }

            // Remove current roles and add new one
            if (!currentClientRoles.isEmpty()) {
                userResource.roles()
                        .clientLevel(clientIdentification)
                        .remove(currentClientRoles);
            }
            userResource.roles()
                    .clientLevel(clientIdentification)
                    .add(List.of(newClientRole));

            return true;
        } catch (NotFoundException e) {
            log.error("Client role '{}' not found in Keycloak", userRole);
            return false;
        } catch (Exception e) {
            log.error("Unable to assign client role of {} to user {}", userRole, userId);
            return false;
        }
    }

    /**
     * Retrieve a User By Email
     *
     * @param email : User Email
     * @return UserRepresentation
     */
    UserRepresentation retrieveUserRepresentationByEmail(String email) {
        try {
            List<UserRepresentation> users = keycloak.realm(realm)
                    .users()
                    .searchByEmail(email, true); // Search by Exact Match

            return users.stream()
                    .findFirst()
                    .orElse(null);
        } catch (NotFoundException e) {
            return null;
        } catch (Exception e) {
            log.error("Error retrieving user by email from Keycloak: {}", e.getMessage(), e);
            throw new KeycloakException("Error retrieving user by email from Keycloak", e);
        }
    }

    /**
     * Retrieve a User Representation By Email
     *
     * @param userId : User ID
     * @return UserRepresentation
     */
    UserRepresentation retrieveUserRepresentationById(String userId) {
        try {
            return keycloak.realm(realm)
                    .users()
                    .get(userId)
                    .toRepresentation();
        } catch (NotFoundException e) {
            return null;
        } catch (Exception e) {
            log.error("Error retrieving user from Keycloak: {}", e.getMessage(), e);
            throw new KeycloakException("Error retrieving user from Keycloak", e);
        }
    }

    /**
     * Retrieve a User Resource By Email
     *
     * @param userId : User ID
     * @return User Resource
     */
    UserResource retrieveUsersResourceById(String userId) {
        try {
            return keycloak.realm(realm)
                    .users()
                    .get(userId);
        } catch (NotFoundException e) {
            return null;
        } catch (Exception e) {
            log.error("Error retrieving user resource by ID from Keycloak: {}", e.getMessage(), e);
            throw new KeycloakException("Error retrieving user resource by ID from Keycloak", e);
        }
    }

    /**
     * Update activation token and expiry for a user (resend activation email)
     *
     * @param userId          : User ID
     * @param activationToken : New activation token
     * @throws ResourceNotPresentException : Thrown when a user is not found in Keycloak
     * @throws KeycloakException           : When a Keycloak communication error occurs
     */
    @Override
    public void updateActivationToken(String userId, String activationToken) {
        UserRepresentation existingUser = retrieveUserRepresentationById(userId);
        if (existingUser == null)
            throw new ResourceNotPresentException("User with ID " + userId + " not found");

        UserDto updatedUser = new UserDto();
        updatedUser.setUserId(userId);
        updatedUser.setActivationToken(activationToken);
        updatedUser.setActivationExpiry(String.valueOf(System.currentTimeMillis() + ACTIVATION_TOKEN_EXPIRY_MS));
        updatedUser.setTokenFlagRaised(false);
        updateUser(updatedUser);
        log.debug("Activation token updated for user with ID: {}", userId);
    }
}
