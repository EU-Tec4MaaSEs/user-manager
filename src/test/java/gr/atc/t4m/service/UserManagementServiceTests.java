package gr.atc.t4m.service;

import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.PasswordsDto;
import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import jakarta.validation.ValidationException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.*;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.util.ReflectionTestUtils;

import static gr.atc.t4m.exception.CustomExceptions.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Nested;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTests {

    @Mock
    private Keycloak keycloak;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private IKeycloakAdminService adminService;

    @Mock
    private IEmailService emailService;

    @Mock
    private RealmResource realmResource;

    @Mock
    private UsersResource usersResource;

    @Mock
    private UserResource userResource;

    @Mock
    private ClientsResource clientsResource;

    @Mock
    private ClientResource clientResource;

    @Mock
    private RoleResource roleResource;

    @Mock
    private RolesResource rolesResource;

    @Mock
    private GroupRepresentation parentGroup;

    @Mock
    private GroupRepresentation subGroup;

    @Mock
    private TokenManager mockTokenManager;

    @Mock
    private Response response;

    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @InjectMocks
    private UserManagementService userManagementService;

    private static final String TEST_REALM = "test-realm";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_PILOT_CODE = "TEST_PILOT";
    private static final String TEST_PILOT_ROLE = "ADMIN";
    private static final String TEST_USER_ROLE = "TEST_ROLE";
    private static final String ACTIVATION_TOKEN = "activation_token";
    private static final String ACTIVATION_EXPIRY = "activation_expiry";
    private static final String SERVER_URL = "http://keycloak.com";
    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";

    @BeforeEach
    void setUp() {
        lenient().when(keycloakProperties.realm()).thenReturn(TEST_REALM);
        lenient().when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
        lenient().when(realmResource.users()).thenReturn(usersResource);
        lenient().when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

        // Mock cache manager
        lenient().when(cacheManager.getCache("users")).thenReturn(cache);
        lenient().when(cache.evictIfPresent(any())).thenReturn(true);

        ReflectionTestUtils.setField(userManagementService, "realm", TEST_REALM);
        ReflectionTestUtils.setField(userManagementService, "serverUrl", SERVER_URL);
        ReflectionTestUtils.setField(userManagementService, "clientId", CLIENT_ID);
        ReflectionTestUtils.setField(userManagementService, "clientSecret", CLIENT_SECRET);
    }

    @Nested
    @DisplayName("User Lifecycle Tests")
    class UserLifecycleTests {
        @DisplayName("Logout User : Success")
        @Test
        void givenUserId_whenLogoutUser_thenSuccess() {
            // Given
            doNothing().when(userResource).logout();

            // When
            userManagementService.logoutUser(TEST_USER_ID);

            // Then
            verify(keycloak).realm(TEST_REALM);
            verify(realmResource).users();
            verify(usersResource).get(TEST_USER_ID);
            verify(userResource).logout();
        }

        @DisplayName("Logout User : User not Found")
        @Test
        void givenUserId_whenLogoutUser_thenUserNotFound() {
            // Given
            doThrow(new NotFoundException("User not found")).when(userResource).logout();

            // When & Then
            assertDoesNotThrow(() -> userManagementService.logoutUser(TEST_USER_ID));

            verify(userResource).logout();
        }

        @DisplayName("Logout User : General Exception")
        @Test
        void givenUserId_whenLogoutUser_thenGeneralException() {
            // Given
            doThrow(new RuntimeException("Connection error")).when(userResource).logout();

            // When & Then
            assertDoesNotThrow(() -> userManagementService.logoutUser(TEST_USER_ID));

            verify(userResource).logout();
        }

        @DisplayName("Delete User : Success")
        @Test
        void givenUserId_whenDeleteUser_thenSuccess() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setId(TEST_USER_ID);
            userRep.setEmail(TEST_EMAIL);

            // Mock the private method retrieveUserRepresentationById
            UserManagementService spyService = spy(userManagementService);
            doReturn(userRep).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            doNothing().when(userResource).remove();

            // When
            spyService.deleteUser(TEST_USER_ID);

            // Then
            verify(spyService).retrieveUserRepresentationById(TEST_USER_ID);
            verify(userResource).remove();
        }

        @DisplayName("Delete User : User Not Found")
        @Test
        void givenUserId_whenDeleteUser_thenUserNotFound() {
            // Given
            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            // When & Then
            ResourceNotPresentException exception = assertThrows(
                    ResourceNotPresentException.class,
                    () -> spyService.deleteUser(TEST_USER_ID)
            );

            assertEquals("User with ID " + TEST_USER_ID + " not found", exception.getMessage());
            verify(spyService).retrieveUserRepresentationById(TEST_USER_ID);
            verify(userResource, never()).remove();
        }

        @DisplayName("Delete User : Keycloak Exception")
        @Test
        void givenUserId_whenDeleteUser_thenKeycloakException() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setId(TEST_USER_ID);

            UserManagementService spyService = spy(userManagementService);
            doReturn(userRep).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            doThrow(new RuntimeException("Keycloak error")).when(userResource).remove();

            // When & Then
            KeycloakException exception = assertThrows(
                    KeycloakException.class,
                    () -> spyService.deleteUser(TEST_USER_ID)
            );

            assertEquals("Error deleting user with id = " + TEST_USER_ID, exception.getMessage());
            verify(userResource).remove();
        }

        @DisplayName("Create User : Success")
        @Test
        void createUser_Success() {
            // Given
            UserCreationDto userCreationDto = createTestUserCreationDto();
            String activationToken = "test-token";

            GroupRepresentation mockGroupRepresentation = new GroupRepresentation();
            mockGroupRepresentation.setId("test-group-id");
            mockGroupRepresentation.setName(TEST_PILOT_CODE);
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("ORGANIZATION_ID", List.of("test-org-123"));
            mockGroupRepresentation.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(true).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));
            doReturn(null).when(spyService).retrieveUserRepresentationByEmail(anyString());
            when(adminService.retrieveGroupRepresentationByName(TEST_PILOT_CODE)).thenReturn(mockGroupRepresentation);

            when(response.getStatus()).thenReturn(201);
            when(response.getHeaderString("Location")).thenReturn("http://keycloak/admin/realms/test/users/" + TEST_USER_ID);
            when(usersResource.create(any(UserRepresentation.class))).thenReturn(response);

            // When
            String result = spyService.createUser(userCreationDto, activationToken);

            // Then
            assertEquals(TEST_USER_ID, result);
            verify(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);
            verify(adminService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);
            verify(usersResource).create(any(UserRepresentation.class));
        }

        @DisplayName("Create User : User Already Exists")
        @Test
        void givenUserData_whenCreateUser_thenUserAlreadyExists() {
            // Given
            UserCreationDto userCreationDto = createTestUserCreationDto();
            String activationToken = "test-token";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setEmail(TEST_EMAIL);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);

            // When & Then
            ResourceAlreadyExistsException exception = assertThrows(
                    ResourceAlreadyExistsException.class,
                    () -> spyService.createUser(userCreationDto, activationToken)
            );

            assertEquals("User with given email already exists in Keycloak", exception.getMessage());
            verify(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);
            verify(usersResource, never()).create(any());
        }

        @DisplayName("Create User : Invalid Input Data / Resources not found in Keycloak")
        @Test
        void givenInvalidUserData_whenCreateUser_thenThrowException() {
            // Given
            UserCreationDto userCreationDto = createTestUserCreationDto();
            String activationToken = "test-token";

            GroupRepresentation mockGroupRepresentation = new GroupRepresentation();
            mockGroupRepresentation.setId("test-group-id");
            mockGroupRepresentation.setName(TEST_PILOT_CODE);
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("ORGANIZATION_ID", List.of("test-org-123"));
            mockGroupRepresentation.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(false).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));
            doReturn(null).when(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);
            when(adminService.retrieveGroupRepresentationByName(TEST_PILOT_CODE)).thenReturn(mockGroupRepresentation);

            // When & Then
            ValidationException exception = assertThrows(
                    ValidationException.class,
                    () -> spyService.createUser(userCreationDto, activationToken)
            );

            assertEquals("Some of the input data are not present in Keycloak (Pilot Role, Pilot Code, User Role)", exception.getMessage());
            verify(usersResource, never()).create(any());
        }

        @DisplayName("Create User : Keycloak Creation Exception")
        @Test
        void givenUserData_whenCreateUser_thenKeycloakCreationException() {
            // Given
            UserCreationDto userCreationDto = createTestUserCreationDto();
            String activationToken = "test-token";

            GroupRepresentation mockGroupRepresentation = new GroupRepresentation();
            mockGroupRepresentation.setId("test-group-id");
            mockGroupRepresentation.setName(TEST_PILOT_CODE);
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("ORGANIZATION_ID", List.of("test-org-123"));
            mockGroupRepresentation.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(true).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));
            doReturn(null).when(spyService).retrieveUserRepresentationByEmail(anyString());
            when(adminService.retrieveGroupRepresentationByName(TEST_PILOT_CODE)).thenReturn(mockGroupRepresentation);

            ReflectionTestUtils.setField(spyService, "realm", "");
            when(keycloak.realm(anyString())).thenThrow(new RuntimeException("Keycloak connection error"));

            try (MockedStatic<UserDto> mockedUserDto = mockStatic(UserDto.class)) {
                UserDto userDto = new UserDto();
                userDto.setActivationToken(activationToken);
                userDto.setTokenFlagRaised(false);
                userDto.setActivationExpiry(String.valueOf(System.currentTimeMillis() + 86400000));
                userDto.setPilotCode("TEST_PILOT");

                mockedUserDto.when(() -> UserDto.fromUserCreationDto(userCreationDto)).thenReturn(userDto);
                mockedUserDto.when(() -> UserDto.toUserRepresentation(any(UserDto.class), isNull()))
                        .thenReturn(new UserRepresentation());

                // When & Then
                KeycloakException exception = assertThrows(
                        KeycloakException.class,
                        () -> spyService.createUser(userCreationDto, activationToken)
                );

                assertEquals("Error during user creation", exception.getMessage());
                assertInstanceOf(RuntimeException.class, exception.getCause());
                assertEquals("Keycloak connection error", exception.getCause().getMessage());
            }
        }

        @DisplayName("Update User : Success")
        @Test
        void givenValidUser_whenUpdateUser_thenSuccess() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);
            userDto.setPilotRole(TEST_PILOT_ROLE);
            userDto.setEmail(TEST_EMAIL);

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(TEST_USER_ID);
            existingUser.setEmail(TEST_EMAIL);
            existingUser.setEnabled(true);
            existingUser.setAttributes(new HashMap<>());

            when(userResource.toRepresentation()).thenReturn(existingUser);
            doNothing().when(userResource).update(any(UserRepresentation.class));
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

            UserManagementService spyService = spy(userManagementService);
            doReturn(true).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));

            // When
            spyService.updateUser(userDto);

            // Then
            verify(usersResource).get(TEST_USER_ID);
            verify(userResource).update(any(UserRepresentation.class));
        }

        @DisplayName("Update User : Invalid Input Data")
        @Test
        void givenInvalidUserData_whenUpdateUser_thenThrowException() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);
            userDto.setPilotRole(TEST_PILOT_ROLE);
            userDto.setEmail(TEST_EMAIL);

            UserManagementService spyService = spy(userManagementService);
            doReturn(false).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));

            // When
            assertThrows(ValidationException.class, () ->
                    spyService.updateUser(userDto));
        }

        @DisplayName("Update User : With DEFAULT Code")
        @Test
        void givenUserWithRemovePilotCode_whenUpdateUser_thenNoGroupsAssigned() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);
            userDto.setPilotCode("DEFAULT");
            userDto.setPilotRole(TEST_PILOT_ROLE);
            userDto.setEmail(TEST_EMAIL);

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(TEST_USER_ID);
            existingUser.setEmail(TEST_EMAIL);
            existingUser.setEnabled(true);
            existingUser.setAttributes(new HashMap<>());

            when(userResource.toRepresentation()).thenReturn(existingUser);
            doNothing().when(userResource).update(any(UserRepresentation.class));
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

            UserManagementService spyService = spy(userManagementService);
            doReturn(true).when(spyService).hasValidKeycloakAttributes(any(UserDto.class));

            // When
            spyService.updateUser(userDto);

            // Then
            verify(usersResource).get(TEST_USER_ID);
            verify(userResource).update(any(UserRepresentation.class));
            verify(spyService).assignGroupsToUser(anyString(), anyString(), any(UserResource.class));
        }

        @DisplayName("Update User : User Not Found")
        @Test
        void givenNonexistentUser_whenUpdateUser_thenThrowResourceNotPresentException() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);
            when(userResource.toRepresentation()).thenReturn(null);
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

            // When & Then
            assertThrows(ResourceNotPresentException.class, () -> userManagementService.updateUser(userDto));
        }
    }

    @Nested
    @DisplayName("User Activation and Password Tests")
    class UserActivationAndPasswordTests {
        @DisplayName("Activate User : Success")
        @Test
        void givenValidUserAndToken_whenActivateUser_thenUserActivatedSuccessfully() {
            // Given
            String userId = "test-user-id";
            String activationToken = "valid-activation-token";
            String password = "newPassword123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put(ACTIVATION_TOKEN, List.of(activationToken));
            attributes.put(ACTIVATION_EXPIRY, List.of(String.valueOf(System.currentTimeMillis() + 3600000)));
            existingUser.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);
            when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
            when(realmResource.users()).thenReturn(usersResource);
            when(usersResource.get(userId)).thenReturn(userResource);
            doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));
            doNothing().when(userResource).update(any(UserRepresentation.class));

            // When
            spyService.activateUser(userId, activationToken, password);

            // Then
            InOrder inOrder = inOrder(userResource);
            inOrder.verify(userResource).update(argThat(user ->
                    user.isEnabled() &&
                    !user.getAttributes().containsKey(ACTIVATION_TOKEN) &&
                    !user.getAttributes().containsKey(ACTIVATION_EXPIRY)
            ));
            inOrder.verify(userResource).resetPassword(argThat(cred ->
                    cred.getType().equals(CredentialRepresentation.PASSWORD) &&
                            cred.getValue().equals(password) &&
                            !cred.isTemporary()
            ));
        }

        @DisplayName("Activate User : User Not Found")
        @Test
        void givenNonExistentUser_whenActivateUser_thenThrowResourceNotPresentException() {
            // Given
            String userId = "non-existent-user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            ResourceNotPresentException exception = assertThrows(
                    ResourceNotPresentException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("User with id " + userId + " not found", exception.getMessage());
        }

        @DisplayName("Activate User : User Already Active")
        @Test
        void givenAlreadyActiveUser_whenActivateUser_thenThrowUserActivateStatusException() {
            // Given
            String userId = "active-user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(true);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            UserActivateStatusException exception = assertThrows(
                    UserActivateStatusException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("User is already active", exception.getMessage());
        }

        @DisplayName("Activate User : Missing Attributes")
        @Test
        void givenUserWithNullAttributes_whenActivateUser_thenThrowInvalidActivationAttributesException() {
            // Given
            String userId = "user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);
            existingUser.setAttributes(null); // No attributes

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            InvalidActivationAttributesException exception = assertThrows(
                    InvalidActivationAttributesException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("Invalid activation token or activation expiry has passed. Please contact the admin of your organization.",
                    exception.getMessage());
            verify(spyService, never()).updateUser(any(UserDto.class));
        }

        @DisplayName("Activate User : Missing Activation Token Attribute")
        @Test
        void givenUserWithoutActivationToken_whenActivateUser_thenThrowInvalidActivationAttributesException() {
            // Given
            String userId = "user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put(ACTIVATION_EXPIRY, List.of(String.valueOf(System.currentTimeMillis() + 3600000)));
            // Missing ACTIVATION_TOKEN
            existingUser.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            InvalidActivationAttributesException exception = assertThrows(
                    InvalidActivationAttributesException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("Invalid activation token or activation expiry has passed. Please contact the admin of your organization.",
                    exception.getMessage());
            verify(spyService, never()).updateUser(any(UserDto.class));
        }

        @DisplayName("Activate User : Missing Activation Expiry Attribute")
        @Test
        void givenUserWithoutActivationExpiry_whenActivateUser_thenThrowInvalidActivationAttributesException() {
            // Given
            String userId = "user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put(ACTIVATION_TOKEN, List.of(activationToken));
            // Missing ACTIVATION_EXPIRY
            existingUser.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            InvalidActivationAttributesException exception = assertThrows(
                    InvalidActivationAttributesException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("Invalid activation token or activation expiry has passed. Please contact the admin of your organization.",
                    exception.getMessage());
            verify(spyService, never()).updateUser(any(UserDto.class));
        }

        @DisplayName("Activate User : Invalid Activation Token")
        @Test
        void givenInvalidActivationToken_whenActivateUser_thenThrowInvalidActivationAttributesException() {
            // Given
            String userId = "user-id";
            String providedToken = "wrong-activation-token";
            String storedToken = "correct-activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put(ACTIVATION_TOKEN, List.of(storedToken)); // Different from provided token
            attributes.put(ACTIVATION_EXPIRY, List.of(String.valueOf(System.currentTimeMillis() + 3600000)));
            existingUser.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            InvalidActivationAttributesException exception = assertThrows(
                    InvalidActivationAttributesException.class,
                    () -> spyService.activateUser(userId, providedToken, password)
            );

            assertEquals("Invalid activation token or activation expiry has passed. Please contact the admin of your organization.",
                    exception.getMessage());
            verify(spyService, never()).updateUser(any(UserDto.class));
        }

        @DisplayName("Activate User : Expired Activation Token")
        @Test
        void givenExpiredActivationToken_whenActivateUser_thenThrowInvalidActivationAttributesException() {
            // Given
            String userId = "user-id";
            String activationToken = "activation-token";
            String password = "password123";

            UserRepresentation existingUser = new UserRepresentation();
            existingUser.setId(userId);
            existingUser.setEnabled(false);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put(ACTIVATION_TOKEN, List.of(activationToken));
            attributes.put(ACTIVATION_EXPIRY, List.of(String.valueOf(System.currentTimeMillis() - 3600000))); // 1 hour ago (expired)
            existingUser.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);

            // When & Then
            InvalidActivationAttributesException exception = assertThrows(
                    InvalidActivationAttributesException.class,
                    () -> spyService.activateUser(userId, activationToken, password)
            );

            assertEquals("Invalid activation token or activation expiry has passed. Please contact the admin of your organization.",
                    exception.getMessage());
            verify(spyService, never()).updateUser(any(UserDto.class));
        }

        @DisplayName("Change Password : Success")
        @Test
        void givenValidOldPassword_whenChangePassword_thenSuccess() {
            // Given
            PasswordsDto passwords = new PasswordsDto("oldPass123@", "newPass123@");

            UserRepresentation userRepresentation = new UserRepresentation();
            userRepresentation.setEmail(TEST_EMAIL);

            UserManagementService spyService = spy(userManagementService);
            doReturn(userResource).when(spyService).retrieveUsersResourceById(TEST_USER_ID);
            when(userResource.toRepresentation()).thenReturn(userRepresentation);
            doReturn(true).when(spyService).validateCurrentPassword(TEST_EMAIL, passwords.oldPassword());
            doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

            // When
            spyService.changePassword(passwords, TEST_USER_ID);

            // Then
            verify(userResource).resetPassword(argThat(cred ->
                    cred.getType().equals(CredentialRepresentation.PASSWORD) &&
                            cred.getValue().equals(passwords.newPassword()) &&
                            !cred.isTemporary()));
        }

        @DisplayName("Change Password : User Not Found")
        @Test
        void givenInvalidUserId_whenChangePassword_thenThrowResourceNotPresentException() {
            // Given
            PasswordsDto passwords = new PasswordsDto("old", "new");
            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUsersResourceById(TEST_USER_ID);

            // Then
            assertThrows(ResourceNotPresentException.class,
                    () -> spyService.changePassword(passwords, TEST_USER_ID));
        }

        @DisplayName("Change Password : Invalid Old Password")
        @Test
        void givenWrongOldPassword_whenChangePassword_thenThrowInvalidPasswordException() {
            // Given
            PasswordsDto passwords = new PasswordsDto("wrongOld123@", "new123@@");

            UserRepresentation userRepresentation = new UserRepresentation();
            userRepresentation.setEmail(TEST_EMAIL);

            UserManagementService spyService = spy(userManagementService);

            doReturn(userResource).when(spyService).retrieveUsersResourceById(TEST_USER_ID);
            when(userResource.toRepresentation()).thenReturn(userRepresentation);
            doReturn(false).when(spyService).validateCurrentPassword(TEST_EMAIL, passwords.oldPassword());

            // Then
            assertThrows(InvalidPasswordException.class,
                    () -> spyService.changePassword(passwords, TEST_USER_ID));
        }

        @DisplayName("Change Password : Keycloak Communication Failure")
        @Test
        void givenResetPasswordThrowsException_whenChangePassword_thenThrowKeycloakException() {
            // Given
            PasswordsDto passwords = new PasswordsDto("oldPass", "newPass");

            UserRepresentation userRepresentation = new UserRepresentation();
            userRepresentation.setEmail(TEST_EMAIL);

            UserManagementService spyService = spy(userManagementService);

            doReturn(userResource).when(spyService).retrieveUsersResourceById(TEST_USER_ID);
            when(userResource.toRepresentation()).thenReturn(userRepresentation);
            doReturn(true).when(spyService).validateCurrentPassword(TEST_EMAIL, passwords.oldPassword());
            doThrow(RuntimeException.class).when(userResource).resetPassword(any(CredentialRepresentation.class));

            // Then
            assertThrows(KeycloakException.class,
                    () -> spyService.changePassword(passwords, TEST_USER_ID));
        }

        @DisplayName("Validate Current Password : Success")
        @Test
        void givenValidCredentials_whenValidateCurrentPassword_thenReturnsTrue() {
            try (MockedStatic<KeycloakBuilder> mockedBuilder = mockStatic(KeycloakBuilder.class)) {
                // Given
                KeycloakBuilder builderMock = mock(KeycloakBuilder.class);
                mockedBuilder.when(KeycloakBuilder::builder).thenReturn(builderMock);

                when(builderMock.serverUrl(SERVER_URL)).thenReturn(builderMock);
                when(builderMock.realm(TEST_REALM)).thenReturn(builderMock);
                when(builderMock.clientId(CLIENT_ID)).thenReturn(builderMock);
                when(builderMock.clientSecret(CLIENT_SECRET)).thenReturn(builderMock);
                when(builderMock.username("user@test.com")).thenReturn(builderMock);
                when(builderMock.password("valid-pass")).thenReturn(builderMock);
                when(builderMock.build()).thenReturn(keycloak);

                when(keycloak.tokenManager()).thenReturn(mockTokenManager);
                when(mockTokenManager.getAccessToken()).thenReturn(mock(AccessTokenResponse.class));

                // When - Then
                boolean result = userManagementService.validateCurrentPassword("user@test.com", "valid-pass");
                assertTrue(result);
            }
        }

        @DisplayName("Validate Current Password : Invalid Credentials")
        @Test
        void givenInvalidCredentials_whenValidateCurrentPassword_thenReturnsFalse() {
            try (MockedStatic<KeycloakBuilder> mockedBuilder = mockStatic(KeycloakBuilder.class)) {
                // Given
                KeycloakBuilder builderMock = mock(KeycloakBuilder.class);
                mockedBuilder.when(KeycloakBuilder::builder).thenReturn(builderMock);

                when(builderMock.serverUrl(SERVER_URL)).thenReturn(builderMock);
                when(builderMock.realm(TEST_REALM)).thenReturn(builderMock);
                when(builderMock.clientId(CLIENT_ID)).thenReturn(builderMock);
                when(builderMock.clientSecret(CLIENT_SECRET)).thenReturn(builderMock);
                when(builderMock.username("user@test.com")).thenReturn(builderMock);
                when(builderMock.password("wrong-pass")).thenReturn(builderMock);
                when(builderMock.build()).thenReturn(keycloak);

                when(keycloak.tokenManager()).thenReturn(mockTokenManager);
                when(mockTokenManager.getAccessToken()).thenThrow(new RuntimeException("Authentication failed"));

                // When - Then
                boolean result = userManagementService.validateCurrentPassword("user@test.com", "wrong-pass");
                assertFalse(result);
            }
        }

        @DisplayName("Forgot Password : Success")
        @Test
        void givenEnabledUser_whenForgotPassword_thenUpdateUserCalled() {
            UserRepresentation user = new UserRepresentation();
            user.setId(TEST_USER_ID);
            user.setEmail(TEST_EMAIL);
            user.setEnabled(true);
            user.setFirstName("John");
            user.setLastName("Doe");

            UserManagementService spyService = spy(userManagementService);
            doReturn(user).when(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);
            doNothing().when(spyService).updateUser(any(UserDto.class));

            // When
            spyService.forgotPassword(TEST_EMAIL);

            // Then
            verify(spyService).updateUser(any(UserDto.class));
        }

        @DisplayName("Forgot Password : User Not Found")
        @Test
        void givenInvalidEmail_whenForgotPassword_thenThrowResourceNotPresentException() {
            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);

            assertThrows(ResourceNotPresentException.class, () -> spyService.forgotPassword(TEST_EMAIL));
        }

        @DisplayName("Forgot Password : User Not Activated")
        @Test
        void givenDisabledUser_whenForgotPassword_thenThrowUserActivateStatusException() {
            UserRepresentation user = new UserRepresentation();
            user.setId(TEST_USER_ID);
            user.setEmail(TEST_EMAIL);
            user.setEnabled(false);

            UserManagementService spyService = spy(userManagementService);
            doReturn(user).when(spyService).retrieveUserRepresentationByEmail(TEST_EMAIL);

            assertThrows(UserActivateStatusException.class, () -> spyService.forgotPassword(TEST_EMAIL));
        }

        @DisplayName("Reset Password : Success")
        @Test
        void givenValidResetToken_whenResetPassword_thenPasswordReset() {
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("reset_token", List.of("valid-token"));

            UserRepresentation user = new UserRepresentation();
            user.setId(TEST_USER_ID);
            user.setEmail(TEST_EMAIL);
            user.setEnabled(true);
            user.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(user).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);
            when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
            when(realmResource.users()).thenReturn(usersResource);
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);
            doNothing().when(userResource).update(any(UserRepresentation.class));
            doNothing().when(userResource).resetPassword(any(CredentialRepresentation.class));

            // When
            spyService.resetPassword(TEST_USER_ID, "valid-token", "new-password");

            // Then
            verify(userResource).update(argThat(u ->
                    !u.getAttributes().containsKey("reset_token")
            ));
            verify(userResource).resetPassword(argThat(cred ->
                    cred.getType().equals(CredentialRepresentation.PASSWORD) &&
                    cred.getValue().equals("new-password") &&
                    !cred.isTemporary()
            ));
        }

        @DisplayName("Reset Password : User Not Found")
        @Test
        void givenInvalidUserId_whenResetPassword_thenThrowResourceNotPresentException() {
            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            assertThrows(ResourceNotPresentException.class,
                    () -> spyService.resetPassword(TEST_USER_ID, "token", "new-pass"));
        }

        @DisplayName("Reset Password : User Not Activated")
        @Test
        void givenDisabledUser_whenResetPassword_thenThrowUserActivateStatusException() {
            UserRepresentation user = new UserRepresentation();
            user.setEnabled(false);

            UserManagementService spyService = spy(userManagementService);
            doReturn(user).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            assertThrows(UserActivateStatusException.class,
                    () -> spyService.resetPassword(TEST_USER_ID, "token", "new-pass"));
        }

        @DisplayName("Reset Password : Invalid Reset Token")
        @Test
        void givenInvalidResetToken_whenResetPassword_thenThrowInvalidRefreshTokenException() {
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("reset_token", List.of("expected-token"));

            UserRepresentation user = new UserRepresentation();
            user.setId(TEST_USER_ID);
            user.setEnabled(true);
            user.setAttributes(attributes);

            UserManagementService spyService = spy(userManagementService);
            doReturn(user).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            assertThrows(InvalidRefreshTokenException.class,
                    () -> spyService.resetPassword(TEST_USER_ID, "wrong-token", "new-pass"));
        }

        @Nested
        @DisplayName("Update Activation Token Tests")
        class UpdateActivationTokenTests {

            @DisplayName("Update Activation Token : Success")
            @Test
            void givenValidUserIdAndToken_whenUpdateActivationToken_thenSuccess() {
                // Given
                String userId = "test-user-123";
                String newActivationToken = "new-activation-token-456";

                UserRepresentation existingUser = new UserRepresentation();
                existingUser.setId(userId);
                existingUser.setEmail(TEST_EMAIL);
                existingUser.setEnabled(false);

                UserManagementService spyService = spy(userManagementService);
                doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);
                doNothing().when(spyService).updateUser(any(UserDto.class));

                // When
                spyService.updateActivationToken(userId, newActivationToken);

                // Then
                ArgumentCaptor<UserDto> userDtoCaptor = ArgumentCaptor.forClass(UserDto.class);
                verify(spyService).updateUser(userDtoCaptor.capture());

                UserDto capturedUserDto = userDtoCaptor.getValue();
                assertThat(capturedUserDto.getUserId()).isEqualTo(userId);
                assertThat(capturedUserDto.getActivationToken()).isEqualTo(newActivationToken);
                assertThat(capturedUserDto.getActivationExpiry()).isNotNull();
                assertThat(capturedUserDto.isTokenFlagRaised()).isFalse();

                long expiryTime = Long.parseLong(capturedUserDto.getActivationExpiry());
                long currentTime = System.currentTimeMillis();
                long threeDaysInMs = 3 * 24 * 60 * 60 * 1000L;
                long expectedExpiry = currentTime + threeDaysInMs;
                assertThat(expiryTime).isBetween(expectedExpiry - 5000, expectedExpiry + 5000);
            }

            @DisplayName("Update Activation Token : User Not Found")
            @Test
            void givenNonExistentUser_whenUpdateActivationToken_thenThrowResourceNotPresentException() {
                // Given
                String userId = "non-existent-user";
                String activationToken = "activation-token";

                UserManagementService spyService = spy(userManagementService);
                doReturn(null).when(spyService).retrieveUserRepresentationById(userId);

                // When
                ResourceNotPresentException exception = assertThrows(
                        ResourceNotPresentException.class,
                        () -> spyService.updateActivationToken(userId, activationToken)
                );

                // Then
                assertThat(exception.getMessage()).isEqualTo("User with ID " + userId + " not found");
                verify(spyService).retrieveUserRepresentationById(userId);
                verify(spyService, never()).updateUser(any(UserDto.class));
            }

            @DisplayName("Update Activation Token : All Required Fields Are Set")
            @Test
            void givenValidRequest_whenUpdateActivationToken_thenAllFieldsAreSet() {
                // Given
                String userId = "test-user-complete";
                String activationToken = "complete-token";

                UserRepresentation existingUser = new UserRepresentation();
                existingUser.setId(userId);
                existingUser.setEmail("complete@test.com");
                existingUser.setEnabled(false);

                UserManagementService spyService = spy(userManagementService);
                doReturn(existingUser).when(spyService).retrieveUserRepresentationById(userId);
                doNothing().when(spyService).updateUser(any(UserDto.class));

                // When
                spyService.updateActivationToken(userId, activationToken);

                // Then
                ArgumentCaptor<UserDto> userDtoCaptor = ArgumentCaptor.forClass(UserDto.class);
                verify(spyService).updateUser(userDtoCaptor.capture());

                UserDto capturedUserDto = userDtoCaptor.getValue();
                assertThat(capturedUserDto.getUserId()).isEqualTo(userId);
                assertThat(capturedUserDto.getActivationToken()).isEqualTo(activationToken);
                assertThat(capturedUserDto.getActivationExpiry()).isNotNull();
                assertThat(capturedUserDto.isTokenFlagRaised()).isFalse();

                long expiryTime = Long.parseLong(capturedUserDto.getActivationExpiry());
                assertThat(expiryTime).isGreaterThan(System.currentTimeMillis());
            }
        }
    }

    @Nested
    @DisplayName("Role and Group Assignment Tests")
    class RoleAndGroupAssignmentTests {
        @DisplayName("Assign Group to User : Success")
        @Test
        void givenValidGroups_whenAssignGroupsToUser_thenJoinsBoth() {

            GroupRepresentation oldGroup = new GroupRepresentation();
            oldGroup.setId("old-id");

            when(userResource.groups()).thenReturn(List.of(oldGroup));
            when(adminService.retrieveGroupRepresentationByName(anyString())).thenReturn(parentGroup);
            when(parentGroup.getId()).thenReturn("parent-id");

            when(adminService.retrieveSubgroupRepresentationByName(anyString(), anyString())).thenReturn(subGroup);
            when(subGroup.getId()).thenReturn("sub-id");

            userManagementService.assignGroupsToUser(TEST_PILOT_CODE, TEST_PILOT_ROLE, userResource);

            verify(userResource).leaveGroup("old-id");
            verify(userResource).joinGroup("parent-id");
            verify(userResource).joinGroup("sub-id");
        }

        @DisplayName("Assign Group to User : Parent not found")
        @Test
        void givenNoParentGroup_whenAssignGroupsToUser_thenSkipsJoin() {
            when(userResource.groups()).thenReturn(List.of());

            when(adminService.retrieveGroupRepresentationByName(anyString())).thenReturn(null);

            userManagementService.assignGroupsToUser(TEST_PILOT_CODE, TEST_PILOT_ROLE, userResource);

            verify(userResource, never()).joinGroup(anyString());
        }

        @DisplayName("Assign Group to User : Sub Group not Found")
        @Test
        void givenNoSubgroup_whenAssignGroupsToUser_thenJoinsParentOnly() {
            when(userResource.groups()).thenReturn(List.of());

            when(adminService.retrieveGroupRepresentationByName(anyString())).thenReturn(parentGroup);
            when(parentGroup.getId()).thenReturn("parent-id");

            when(adminService.retrieveSubgroupRepresentationByName(anyString(), anyString())).thenReturn(null);

            userManagementService.assignGroupsToUser(TEST_PILOT_CODE, TEST_PILOT_ROLE, userResource);

            verify(userResource).joinGroup("parent-id");
            verify(userResource, never()).joinGroup("sub-id");
        }

        @DisplayName("Assign Roles to User : Success")
        @Test
        void givenValidUserDto_whenAssignRoles_thenRealmAndClientRolesAssigned() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);
            userDto.setPilotRole(TEST_PILOT_ROLE);
            userDto.setUserRole(TEST_USER_ROLE);

            // Mock UserResource
            UserResource userResource = mock(UserResource.class);

            UserManagementService spyService = spy(userManagementService);
            when(spyService.retrieveUsersResourceById(anyString())).thenReturn(userResource);
            doReturn(true).when(spyService).assignRealmRole(TEST_PILOT_ROLE, TEST_USER_ID, userResource);
            doReturn(true).when(spyService).assignClientRole(TEST_USER_ROLE, TEST_USER_ID, userResource);

            // When
            spyService.assignRolesToUser(userDto);

            // Then
            verify(spyService).assignRealmRole(TEST_PILOT_ROLE, TEST_USER_ID, userResource);
            verify(spyService).assignClientRole(TEST_USER_ROLE, TEST_USER_ID, userResource);
        }

        @DisplayName("Assign Roles to User : User Not Found")
        @Test
        void givenInvalidUser_whenAssignRoles_thenNoRoleAssigned() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(TEST_USER_ID);

            UserManagementService spyService = spy(userManagementService);
            // Mock NotFoundException
            doThrow(new NotFoundException("User not found")).when(spyService).retrieveUsersResourceById(TEST_USER_ID);

            // When
            spyService.assignRolesToUser(userDto);

            // Then
            verify(spyService, never()).assignRealmRole(any(), any(), any());
            verify(spyService, never()).assignClientRole(any(), any(), any());
        }

        @DisplayName("Assign Roles to User : Null UserDto")
        @Test
        void givenNullUserDto_whenAssignRoles_thenNoRoleAssigned() {
            UserManagementService spyService = spy(userManagementService);

            // When
            spyService.assignRolesToUser(null);

            // Then
            verify(spyService, never()).assignRealmRole(any(), any(), any());
            verify(spyService, never()).assignClientRole(any(), any(), any());
        }

        @DisplayName("Assign Roles to User : Null User Id")
        @Test
        void givenNullUserId_whenAssignRoles_thenNoRoleAssigned() {
            // Given
            UserDto userDto = new UserDto();
            userDto.setUserId(null);
            userDto.setPilotRole(TEST_PILOT_ROLE);
            userDto.setUserRole(TEST_USER_ROLE);

            UserManagementService spyService = spy(userManagementService);

            // When
            spyService.assignRolesToUser(userDto);

            // Then
            verify(spyService, never()).assignRealmRole(any(), any(), any());
            verify(spyService, never()).assignClientRole(any(), any(), any());
        }

        @DisplayName("Assign Realm Role : Success")
        @Test
        void givenValidRealmRole_whenAssignRealmRole_thenRoleAssignedAfterRemovingExisting() {
            // Given
            RoleRepresentation newRealmRole = new RoleRepresentation();
            newRealmRole.setName(TEST_PILOT_ROLE);

            RoleRepresentation existingRole1 = new RoleRepresentation();
            existingRole1.setName("existing-role-1");
            RoleRepresentation existingRole2 = new RoleRepresentation();
            existingRole2.setName("existing-role-2");
            List<RoleRepresentation> existingRoles = Arrays.asList(existingRole1, existingRole2);

            UserResource userResource = mock(UserResource.class);
            RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
            RoleScopeResource realmLevel = mock(RoleScopeResource.class);
            RolesResource rolesResource = mock(RolesResource.class);
            RoleResource roleResource = mock(RoleResource.class);

            // Mock the role retrieval
            when(realmResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_PILOT_ROLE)).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenReturn(newRealmRole);

            // Mock user resource and role mapping
            when(userResource.roles()).thenReturn(roleMappingResource);
            when(roleMappingResource.realmLevel()).thenReturn(realmLevel);
            when(realmLevel.listAll()).thenReturn(existingRoles);

            // When
            userManagementService.assignRealmRole(TEST_PILOT_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(realmLevel).remove(existingRoles);
            verify(realmLevel).add(List.of(newRealmRole));
        }

        @DisplayName("Assign Realm Role : No Existing Roles")
        @Test
        void givenValidRealmRoleAndNoExistingRoles_whenAssignRealmRole_thenRoleAssigned() {
            // Given
            RoleRepresentation newRealmRole = new RoleRepresentation();
            newRealmRole.setName(TEST_PILOT_ROLE);

            UserResource userResource = mock(UserResource.class);
            RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
            RoleScopeResource realmLevel = mock(RoleScopeResource.class);
            RolesResource rolesResource = mock(RolesResource.class);
            RoleResource roleResource = mock(RoleResource.class);

            // Mock the role retrieval
            when(realmResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_PILOT_ROLE)).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenReturn(newRealmRole);

            // Mock user resource and role mappings
            when(userResource.roles()).thenReturn(roleMappingResource);
            when(roleMappingResource.realmLevel()).thenReturn(realmLevel);
            when(realmLevel.listAll()).thenReturn(Collections.emptyList());

            // When
            userManagementService.assignRealmRole(TEST_PILOT_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(realmLevel, never()).remove(any());
            verify(realmLevel).add(List.of(newRealmRole));
        }

        @DisplayName("Assign Realm Role : Role Not Found")
        @Test
        void givenInvalidRealmRole_whenAssignRealmRole_thenExceptionHandled() {
            // Given
            UserResource userResource = mock(UserResource.class);
            RolesResource rolesResource = mock(RolesResource.class);

            when(realmResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_PILOT_ROLE)).thenThrow(new NotFoundException("Role not found"));

            // When
            userManagementService.assignRealmRole(TEST_PILOT_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(userResource, never()).roles();
        }

        @DisplayName("Assign Client Role : Success")
        @Test
        void givenValidClientRole_whenAssignClientRole_thenRoleAssignedAfterRemovingExisting() {
            // Given
            String clientId = "test-client-id";

            RoleRepresentation newClientRole = new RoleRepresentation();
            newClientRole.setName(TEST_USER_ROLE);

            RoleRepresentation existingClientRole1 = new RoleRepresentation();
            existingClientRole1.setName("existing-client-role-1");
            List<RoleRepresentation> existingClientRoles = List.of(existingClientRole1);

            UserResource userResource = mock(UserResource.class);
            RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
            RoleScopeResource clientLevel = mock(RoleScopeResource.class);

            ClientsResource clientsResource = mock(ClientsResource.class);
            ClientResource clientResource = mock(ClientResource.class);
            RolesResource clientRolesResource = mock(RolesResource.class);
            RoleResource roleResource = mock(RoleResource.class);

            // Mock client role retrieval
            when(adminService.retrieveClientId()).thenReturn(clientId);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(clientId)).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(clientRolesResource);
            when(clientRolesResource.get(TEST_USER_ROLE)).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenReturn(newClientRole);

            // Mock user resource and role mapping
            when(userResource.roles()).thenReturn(roleMappingResource);
            when(roleMappingResource.clientLevel(clientId)).thenReturn(clientLevel);
            when(clientLevel.listAll()).thenReturn(existingClientRoles);

            // When
            userManagementService.assignClientRole(TEST_USER_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(clientLevel).remove(existingClientRoles);
            verify(clientLevel).add(List.of(newClientRole));
        }

        @DisplayName("Assign Client Role : No Existing Roles")
        @Test
        void givenValidClientRoleAndNoExistingRoles_whenAssignClientRole_thenRoleAssigned() {
            // Given
            String clientId = "test-client-id";

            RoleRepresentation newClientRole = new RoleRepresentation();
            newClientRole.setName(TEST_USER_ROLE);

            UserResource userResource = mock(UserResource.class);
            RoleMappingResource roleMappingResource = mock(RoleMappingResource.class);
            RoleScopeResource clientLevel = mock(RoleScopeResource.class);

            ClientsResource clientsResource = mock(ClientsResource.class);
            ClientResource clientResource = mock(ClientResource.class);
            RolesResource clientRolesResource = mock(RolesResource.class);
            RoleResource roleResource = mock(RoleResource.class);

            // Mock client role retrieval
            when(adminService.retrieveClientId()).thenReturn(clientId);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(clientId)).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(clientRolesResource);
            when(clientRolesResource.get(TEST_USER_ROLE)).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenReturn(newClientRole);

            // Mock user resource and role mapping
            when(userResource.roles()).thenReturn(roleMappingResource);
            when(roleMappingResource.clientLevel(clientId)).thenReturn(clientLevel);
            when(clientLevel.listAll()).thenReturn(Collections.emptyList());

            // When
            userManagementService.assignClientRole(TEST_USER_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(clientLevel, never()).remove(any());
            verify(clientLevel).add(List.of(newClientRole));
        }

        @DisplayName("Assign Client Role : Role Not Found")
        @Test
        void givenInvalidClientRole_whenAssignClientRole_thenExceptionHandled() {
            // Given
            String clientId = "test-client-id";
            UserResource userResource = mock(UserResource.class);

            ClientsResource clientsResource = mock(ClientsResource.class);
            ClientResource clientResource = mock(ClientResource.class);
            RolesResource clientRolesResource = mock(RolesResource.class);

            when(adminService.retrieveClientId()).thenReturn(clientId);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(clientId)).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(clientRolesResource);
            when(clientRolesResource.get(TEST_USER_ROLE)).thenThrow(new NotFoundException("Client role not found"));

            // When
            userManagementService.assignClientRole(TEST_USER_ROLE, TEST_USER_ID, userResource);

            // Then
            verify(userResource, never()).roles();
        }
    }

    @Nested
    @DisplayName("User Retrieval Tests")
    class UserRetrievalTests {
        @DisplayName("Retrieve All Users : Success")
        @Test
        void whenRetrieveAllUsers_thenReturnListOfUserDto() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setId(TEST_USER_ID);
            userRep.setEmail(TEST_EMAIL);
            userRep.setEnabled(true);

            when(usersResource.list()).thenReturn(List.of(userRep));


            // When
            List<UserDto> result = userManagementService.retrieveAllUsers();

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertEquals(TEST_USER_ID, result.getFirst().getUserId());
        }

        @DisplayName("Retrieve All Users by User Role : Success - Super Admin")
        @Test
        void givenSuperAdminCredentials_whenRetrieveAllUsersByUserRole_thenReturnUserList() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setUsername("testuser");
            userRep.setFirstName("Test");
            userRep.setLastName("User");
            userRep.setAttributes(Map.of(
                    "pilot_role", List.of(TEST_PILOT_ROLE),
                    "pilot_code", List.of(TEST_PILOT_CODE),
                    "user_role", List.of(TEST_USER_ROLE)
            ));
            userRep.setEmail("test@test.com");
            userRep.setEnabled(true);
            userRep.setId("test-id");

            // Mock adminService.retrieveClientId()
            when(adminService.retrieveClientId()).thenReturn("client-UUID");

            // Mock Keycloak chain
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get("client-UUID")).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_USER_ROLE)).thenReturn(roleResource);
            when(roleResource.getUserMembers()).thenReturn(List.of(userRep));

            // When - Super Admin can access any role
            List<UserDto> users = userManagementService.retrieveAllUsersByUserRole(
                    "SUPER_ADMIN",
                    TEST_PILOT_CODE,
                    TEST_USER_ROLE
            );

            // Then
            assertEquals(1, users.size());
            assertEquals("testuser", users.getFirst().getUsername());
            assertEquals("Test", users.getFirst().getFirstName());
            assertEquals("User", users.getFirst().getLastName());
            assertEquals("test@test.com", users.getFirst().getEmail());
            assertEquals(TEST_PILOT_ROLE, users.getFirst().getPilotRole());
            assertEquals(TEST_PILOT_CODE, users.getFirst().getPilotCode());
            assertEquals(TEST_USER_ROLE, users.getFirst().getUserRole());
            assertEquals("test-id", users.getFirst().getUserId());
        }

        @DisplayName("Retrieve All Users by User Role : Success - Admin Same Pilot")
        @Test
        void givenAdminSamePilot_whenRetrieveAllUsersByUserRole_thenReturnUserList() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setUsername("testuser");
            userRep.setFirstName("Test");
            userRep.setLastName("User");
            userRep.setAttributes(Map.of(
                    "pilot_role", List.of("ADMIN"),
                    "pilot_code", List.of(TEST_PILOT_CODE),
                    "user_role", List.of(TEST_USER_ROLE)
            ));
            userRep.setEmail("test@test.com");
            userRep.setEnabled(true);
            userRep.setId("test-id");

            when(adminService.retrieveClientId()).thenReturn("client-UUID");

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get("client-UUID")).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_USER_ROLE)).thenReturn(roleResource);
            when(roleResource.getUserMembers()).thenReturn(List.of(userRep));

            // When - Admin accessing role within their pilot
            List<UserDto> users = userManagementService.retrieveAllUsersByUserRole(
                    "ADMIN",
                    TEST_PILOT_CODE,
                    TEST_USER_ROLE
            );

            // Then
            assertEquals(1, users.size());
            assertEquals("testuser", users.getFirst().getUsername());
        }

        @DisplayName("Retrieve All Users by User Role : Forbidden - Non Super Admin accessing Super Admin role")
        @Test
        void givenNonSuperAdmin_whenAccessingSuperAdminRole_thenThrowForbiddenAccessException() {
            // When & Then - Admin trying to access Super Admin role
            assertThrows(ForbiddenAccessException.class, () -> {
                userManagementService.retrieveAllUsersByUserRole(
                        "ADMIN",
                        TEST_PILOT_CODE,
                        "SUPER_ADMIN"
                );
            });
        }

        @DisplayName("Retrieve All Users by User Role : Not Found")
        @Test
        void givenInvalidUserRole_whenRetrieveUsersByUserRole_thenThrowResourceNotPresentException() {
            when(adminService.retrieveClientId()).thenReturn("client-UUID");

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get("client-UUID")).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_USER_ROLE)).thenThrow(new NotFoundException("Not Found"));

            // When & Then
            assertThrows(ResourceNotPresentException.class, () -> {
                userManagementService.retrieveAllUsersByUserRole(
                        "SUPER_ADMIN",
                        TEST_PILOT_CODE,
                        TEST_USER_ROLE
                );
            });
        }

        @DisplayName("Retrieve All Users by User Role : Keycloak Failure")
        @Test
        void givenKeycloakError_whenRetrieveUsersByUserRole_thenThrowKeycloakException() {
            // Given
            when(adminService.retrieveClientId()).thenReturn("client-UUID");

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get("client-UUID")).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(TEST_USER_ROLE)).thenThrow(new RuntimeException("Keycloak error"));

            // When & Then
            assertThrows(KeycloakException.class, () -> {
                userManagementService.retrieveAllUsersByUserRole(
                        "SUPER_ADMIN",
                        TEST_PILOT_CODE,
                        TEST_USER_ROLE
                );
            });
        }

        @DisplayName("Retrieve Users by Pilot Code : Success")
        @Test
        void givenPilotCode_whenRetrieveUsers_thenReturnUserList() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setId(TEST_USER_ID);
            userRep.setEmail(TEST_EMAIL);
            userRep.setEnabled(true);

            GroupRepresentation groupRepr = new GroupRepresentation();
            groupRepr.setId("test-id");
            when(adminService.retrieveGroupRepresentationByName(anyString())).thenReturn(groupRepr);

            GroupResource groupResource = mock(GroupResource.class);
            when(groupResource.members()).thenReturn(List.of(userRep));

            GroupsResource groupsResource = mock(GroupsResource.class);
            when(groupsResource.group(anyString())).thenReturn(groupResource);

            when(realmResource.groups()).thenReturn(groupsResource);


            // When
            List<UserDto> result = userManagementService.retrieveUsersByPilotCode(TEST_PILOT_CODE);

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertEquals(TEST_USER_ID, result.getFirst().getUserId());
        }

        @DisplayName("Retrieve Users by Pilot Code : Not Found")
        @Test
        void givenInvalidPilotCode_whenRetrieveUsers_thenThrowResourceNotPresentException() {
            // Given
            when(adminService.retrieveGroupRepresentationByName(anyString())).thenReturn(null);
            // When & Then
            assertThrows(ResourceNotPresentException.class,
                    () -> userManagementService.retrieveUsersByPilotCode(TEST_PILOT_CODE));
        }

        @DisplayName("Retrieve Users by Pilot Code and User Role : Success")
        @Test
        void givenPilotCodeAndUserRole_whenRetrieveUsersByPilotCodeAndUserRole_thenReturnUserList() {
            // Given
            String pilotCode = "TEST_PILOT";
            String userRole = "TEST_ROLE";
            UserDto mockUser = new UserDto();
            mockUser.setPilotCode("TEST_PILOT");
            mockUser.setUserRole("TEST_ROLE");
            mockUser.setUserId("ID-1");
            List<UserDto> mockUsersFromPilot = List.of(mockUser);

            // Mock the retrieveUsersByPilotCode method to return all users
            UserManagementService spyService = spy(userManagementService);
            doReturn(mockUsersFromPilot).when(spyService).retrieveUsersByPilotCode(pilotCode);

            // When
            List<UserDto> result = spyService.retrieveUsersByPilotCodeAndUserRole(pilotCode, userRole);

            // Then
            assertThat(result).hasSize(1);
            assertThat(result).extracting(UserDto::getUserRole).contains("TEST_ROLE");
            assertThat(result).extracting(UserDto::getUserId).contains("ID-1");
            assertThat(result).extracting(UserDto::getPilotCode).contains("TEST_PILOT");

            // Verify that retrieveUsersByPilotCode was called once
            verify(spyService, times(1)).retrieveUsersByPilotCode(pilotCode);
        }

        @DisplayName("Retrieve User by ID : Success")
        @Test
        void givenUserId_whenRetrieveUserById_thenReturnUserDto() {
            // Given
            UserRepresentation userRep = new UserRepresentation();
            userRep.setId(TEST_USER_ID);
            userRep.setEmail(TEST_EMAIL);
            userRep.setEnabled(true);

            UserManagementService spyService = spy(userManagementService);
            doReturn(userRep).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            // When
            UserDto userDto = spyService.retrieveUserById(TEST_USER_ID);

            // Then
            assertNotNull(userDto);
            assertEquals(TEST_USER_ID, userDto.getUserId());
        }

        @DisplayName("Retrieve User by ID : Not Found")
        @Test
        void givenInvalidUserId_whenRetrieveUserById_thenThrowResourceNotPresentException() {
            // Given
            UserManagementService spyService = spy(userManagementService);
            doReturn(null).when(spyService).retrieveUserRepresentationById(TEST_USER_ID);

            // When & Then
            assertThrows(ResourceNotPresentException.class, () -> spyService.retrieveUserById(TEST_USER_ID));
        }
    }

    @Nested
    @DisplayName("Internal Helper Method Tests")
    class InternalHelperMethodTests {
        @DisplayName("Parse response to extract user ID : Success")
        @Test
        void givenResponse_whenExtractUserIdFromResponse_thenSuccess() throws Exception {
            // Given
            when(response.getStatus()).thenReturn(201);
            when(response.getHeaderString("Location")).thenReturn("http://keycloak/admin/realms/test/users/" + TEST_USER_ID);

            // Use reflection to test private method
            Method method = UserManagementService.class.getDeclaredMethod("extractUserIdFromResponse", Response.class);
            method.setAccessible(true);

            // When
            String result = (String) method.invoke(userManagementService, response);

            // Then
            assertEquals(TEST_USER_ID, result);
        }

        @DisplayName("Parse response to extract user ID : Failure")
        @Test
        void givenResponse_whenExtractUserIdFromResponse_thenFailure() throws Exception {
            // Given
            when(response.getStatus()).thenReturn(400);
            when(response.readEntity(String.class)).thenReturn("Bad Request");
            Method method = UserManagementService.class.getDeclaredMethod("extractUserIdFromResponse", Response.class);
            method.setAccessible(true);

            // When & Then
            InvocationTargetException invocationException = assertThrows(
                    InvocationTargetException.class,
                    () -> method.invoke(userManagementService, response)
            );

            // Extract the actual exception from InvocationTargetException
            Throwable actualException = invocationException.getCause();
            assertInstanceOf(KeycloakException.class, actualException);
            assertTrue(actualException.getMessage().contains("Failed to create user in Keycloak. Status: 400"));
        }

        @DisplayName("Extract User ID from Location : Success")
        @Test
        void givenLocationHeader_whenExtractUserIdFromLocation_thenSuccess() throws Exception {
            // Given
            String locationHeader = "http://keycloak-host:8080/auth/admin/realms/test-realm/users/" + TEST_USER_ID;

            Method method = UserManagementService.class.getDeclaredMethod("extractUserIdFromLocation", String.class);
            method.setAccessible(true);

            // When
            String result = (String) method.invoke(userManagementService, locationHeader);

            // Then
            assertEquals(TEST_USER_ID, result);
        }

        @DisplayName("Extract User ID from Location : Failure")
        @Test
        void givenLocationHeader_whenExtractUserIdFromLocation_thenFailure() throws Exception {
            // Given
            when(response.getStatus()).thenReturn(400);
            when(response.readEntity(String.class)).thenReturn("Bad Request");

            Method method = UserManagementService.class.getDeclaredMethod("extractUserIdFromResponse", Response.class);
            method.setAccessible(true);

            // When & Then
            InvocationTargetException invocationException = assertThrows(
                    InvocationTargetException.class,
                    () -> method.invoke(userManagementService, response)
            );

            // Extract the actual exception from InvocationTargetException
            Throwable actualException = invocationException.getCause();
            assertInstanceOf(KeycloakException.class, actualException);
            assertTrue(actualException.getMessage().contains("Failed to create user in Keycloak. Status: 400"));
        }

        @DisplayName("Extract User ID from Location : Complex Path")
        @Test
        void givenComplexLocationHeader_whenExtractUserIdFromLocation_thenSuccess() throws Exception {
            // Given
            String locationHeader = "https://keycloak.example.com:8443/auth/admin/realms/my-realm/users/complex-user-id-123-abc";

            Method method = UserManagementService.class.getDeclaredMethod("extractUserIdFromLocation", String.class);
            method.setAccessible(true);

            // When
            String result = (String) method.invoke(userManagementService, locationHeader);

            // Then
            assertEquals("complex-user-id-123-abc", result);
        }

        @DisplayName("Retrieve User by Email : Found")
        @Test
        void givenValidEmail_whenRetrieveByEmail_thenReturnUser() {
            UserRepresentation user = new UserRepresentation();
            user.setEmail(TEST_EMAIL);

            when(usersResource.searchByEmail(TEST_EMAIL, true)).thenReturn(List.of(user));

            UserRepresentation result = userManagementService.retrieveUserRepresentationByEmail(TEST_EMAIL);

            assertNotNull(result);
            assertEquals(TEST_EMAIL, result.getEmail());
        }

        @DisplayName("Retrieve User by Email : Not Found")
        @Test
        void givenUnknownEmail_whenRetrieveByEmail_thenReturnNull() {
            when(usersResource.searchByEmail(TEST_EMAIL, true)).thenReturn(List.of());

            UserRepresentation result = userManagementService.retrieveUserRepresentationByEmail(TEST_EMAIL);
            assertNull(result);
        }

        @DisplayName("Retrieve User Representation by ID : Success")
        @Test
        void givenUserId_whenRetrieveUserRepresentationById_thenReturnUser() {
            UserRepresentation user = new UserRepresentation();
            user.setId(TEST_USER_ID);

            when(userResource.toRepresentation()).thenReturn(user);
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

            UserRepresentation result = userManagementService.retrieveUserRepresentationById(TEST_USER_ID);

            assertNotNull(result);
            assertEquals(TEST_USER_ID, result.getId());
        }

        @DisplayName("Retrieve User Resource by ID : Success")
        @Test
        void givenUserId_whenRetrieveUserResourceById_thenReturnUser() {
            // Given
            when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
            when(realmResource.users()).thenReturn(usersResource);
            when(usersResource.get(TEST_USER_ID)).thenReturn(userResource);

            // When
            UserResource result = userManagementService.retrieveUsersResourceById(TEST_USER_ID);

            // Then
            assertNotNull(result);
            assertEquals(userResource, result);
        }

        @DisplayName("Retrieve User Resource by ID : User Not Found")
        @Test
        void givenInvalidUserId_whenRetrieveUserById_thenReturnsNull() {
            // Given
            when(keycloak.realm(TEST_REALM)).thenReturn(realmResource);
            when(realmResource.users()).thenReturn(usersResource);
            when(usersResource.get(TEST_USER_ID)).thenThrow(new NotFoundException("User not found"));

            // When
            UserResource result = userManagementService.retrieveUsersResourceById(TEST_USER_ID);

            // Then
            assertNull(result);
        }
    }

    private UserCreationDto createTestUserCreationDto() {
        return new UserCreationDto(
                "JohnDoe",
                "John",
                "Doe",
                TEST_EMAIL,
                TEST_PILOT_ROLE,
                TEST_PILOT_CODE,
                TEST_USER_ROLE
        );
    }
}