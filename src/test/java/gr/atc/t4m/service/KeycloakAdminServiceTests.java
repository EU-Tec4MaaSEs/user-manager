package gr.atc.t4m.service;

import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserRoleDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import gr.atc.t4m.enums.T4mRole;
import gr.atc.t4m.events.OrganizationDeletionEvent;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

import static gr.atc.t4m.exception.CustomExceptions.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Nested;

@ExtendWith(MockitoExtension.class)
class KeycloakAdminServiceTests {
    @Mock
    private Keycloak keycloak;

    @Mock
    private KeycloakProperties keycloakProperties;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private RealmResource realmResource;

    @Mock
    private GroupsResource groupsResource;

    @Mock
    private GroupResource groupResource;

    @Mock
    private RoleResource roleResource;

    @Mock
    private RoleMappingResource roleMappingResource;

    @Mock
    private RoleScopeResource roleScopeResource;

    @Mock
    private RolesResource rolesResource;

    @Mock
    private ClientsResource clientsResource;

    @Mock
    private ClientResource clientResource;

    @Mock
    private ClientRepresentation clientRepresentation;

    @InjectMocks
    private KeycloakAdminService adminService;

    private static final String TEST_GROUP_NAME = "TEST_GROUP";
    private static final String TEST_GROUP_ID = "test-group-id";
    private static final String TEST_PILOT_CODE = "TEST_PILOT";
    private static final String TEST_USER_ROLE = "TEST_ROLE";
    private static final String TEST_PILOT_ROLE = "ADMIN";

    @BeforeEach
    void setUp() {
        lenient().when(keycloakProperties.realm()).thenReturn("test-realm");
        lenient().when(keycloakProperties.clientId()).thenReturn("client-name");
        lenient().when(keycloakProperties.excludedSuperAdminRoles()).thenReturn("DEFAULT_ROLES");
        lenient().when(keycloakProperties.excludedDefaultRoles()).thenReturn("SUPER_ADMIN,DEFAULT_ROLES");
        lenient().when(keycloakProperties.initClientId()).thenReturn(true);

        adminService = new KeycloakAdminService(keycloak, keycloakProperties, eventPublisher);
        lenient().when(keycloak.realm(anyString())).thenReturn(realmResource);
        lenient().when(realmResource.groups()).thenReturn(groupsResource);
    }

    @Nested
    @DisplayName("Client ID Tests")
    class ClientIdTests {
        @DisplayName("Retrieve Client ID on App Start-up : Success")
        @Test
        void givenShouldInitTrue_whenApplicationReady_thenClientIdRetrieved() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            ReflectionTestUtils.setField(spyService, "shouldInitClientId", true);

            doReturn("mocked-client-id").when(spyService).retrieveClientId();

            spyService.retrieveClientIdAfterServiceInitialization();

            String clientId = (String) ReflectionTestUtils.getField(spyService, "clientId");
            assertEquals("mocked-client-id", clientId);
        }

        @DisplayName("Retrieve Client ID on App Start-up : Skip with Flag False")
        @Test
        void givenShouldInitFalse_whenApplicationReady_thenClientIdNotRetrieved() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            ReflectionTestUtils.setField(spyService, "shouldInitClientId", false);

            spyService.retrieveClientIdAfterServiceInitialization();

            // Ensure retrieveClientId() is NOT called
            verify(spyService, never()).retrieveClientId();
        }

        @DisplayName("Refresh Client ID : should refresh and assign clientId")
        @Test
        void whenRefreshClientId_thenRetrieveAndSetClientId() {
            KeycloakAdminService spyService = Mockito.spy(adminService);

            doReturn("refreshed-client-id").when(spyService).retrieveClientId();

            spyService.refreshClientId();

            String clientId = (String) ReflectionTestUtils.getField(spyService, "clientId");
            assertEquals("refreshed-client-id", clientId);
        }

        @DisplayName("Retrieve Client ID : Value present in field")
        @Test
        void whenRetrieveClientId_thenReturnClientIdFromField() {
            ReflectionTestUtils.setField(adminService, "clientId", "client-name");
            String result = adminService.retrieveClientId();
            assertEquals("client-name", result);
        }

        @DisplayName("Locate Client ID : Success")
        @Test
        void whenClientExists_thenLocateClientIdReturnsId() {
            when(keycloak.realm("test-realm")).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.findByClientId(anyString())).thenReturn(List.of(clientRepresentation));
            when(clientRepresentation.getId()).thenReturn("test-id");

            String clientId = adminService.locateClientId();
            assertEquals("test-id", clientId);
        }

        @DisplayName("Locate Client ID : Client not found throws exception")
        @Test
        void whenClientDoesNotExist_thenLocateClientIdThrowsException() {
            when(keycloak.realm("test-realm")).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.findByClientId(anyString())).thenReturn(List.of());

            ResourceNotPresentException exception = assertThrows(
                    ResourceNotPresentException.class,
                    () -> adminService.locateClientId()
            );

            assertEquals("Client 'client-name' not found", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Group Management Tests")
    class GroupManagementTests {
        @DisplayName("Retrieve All Pilot Codes : Success")
        @Test
        void whenRetrieveAllPilotCodes_thenReturnListOfGroupNames() {
            GroupRepresentation group1 = new GroupRepresentation();
            group1.setName("GroupA");
            GroupRepresentation group2 = new GroupRepresentation();
            group2.setName("GroupB");

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(group1, group2));

            List<String> result = adminService.retrieveAllPilotCodes();

            assertEquals(List.of("GroupA", "GroupB"), result);
        }

        @DisplayName("Retrieve Group by Name : Success")
        @Test
        void givenGroupName_whenGroupExists_thenReturnGroupRepresentation() {
            GroupRepresentation group = new GroupRepresentation();
            group.setName(TEST_GROUP_NAME);

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(group));

            GroupRepresentation result = adminService.retrieveGroupRepresentationByName(TEST_GROUP_NAME);

            assertNotNull(result);
            assertEquals(TEST_GROUP_NAME, result.getName());
        }

        @DisplayName("Retrieve Group by Name : Not Found")
        @Test
        void givenGroupName_whenGroupNotExists_thenReturnNull() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(List.of()).when(spyService).retrieveAllGroupRepresentations();

            GroupRepresentation result = spyService.retrieveGroupRepresentationByName(TEST_GROUP_NAME);

            assertNull(result);
        }

        @DisplayName("Retrieve Sub Group by Name and Parent : Success")
        @Test
        void givenSubgroupExists_whenRetrieveSubgroup_thenReturnGroup() {
            String parentGroupId = "parent-id";
            String subGroupName = "MySubGroup";

            GroupRepresentation matchingSubGroup = new GroupRepresentation();
            matchingSubGroup.setId("sub-id");
            matchingSubGroup.setName(subGroupName);

            GroupResource mockGroupResource = mock(GroupResource.class);
            when(realmResource.groups()).thenReturn(groupsResource);
            when(groupsResource.group(parentGroupId)).thenReturn(mockGroupResource);
            when(mockGroupResource.getSubGroups(null, null, false)).thenReturn(List.of(matchingSubGroup));

            GroupRepresentation result = adminService.retrieveSubgroupRepresentationByName(parentGroupId, subGroupName);

            assertNotNull(result);
            assertEquals("sub-id", result.getId());
            assertEquals(subGroupName, result.getName());
        }

        @DisplayName("Retrieve Sub Group by Name and Parent : SubGroup Not Found")
        @Test
        void givenSubgroupDoesNotExist_whenRetrieveSubgroup_thenReturnNull() {
            String parentGroupId = "parent-id";
            String subGroupName = "UnknownGroup";

            GroupRepresentation otherGroup = new GroupRepresentation();
            otherGroup.setId("g2");
            otherGroup.setName("OtherGroup");

            GroupResource mockGroupResource = mock(GroupResource.class);
            when(realmResource.groups()).thenReturn(groupsResource);
            when(groupsResource.group(parentGroupId)).thenReturn(mockGroupResource);
            when(mockGroupResource.getSubGroups(null, null, false)).thenReturn(List.of(otherGroup));

            GroupRepresentation result = adminService.retrieveSubgroupRepresentationByName(parentGroupId, subGroupName);

            assertNull(result);
        }

        @DisplayName("Retrieve Sub Group by Name and Parent : Keycloak Error")
        @Test
        void givenException_whenRetrieveSubgroup_thenReturnNull() {
            String parentGroupId = "parent-id";
            String subGroupName = "AnyGroup";

            GroupResource mockGroupResource = mock(GroupResource.class);
            when(realmResource.groups()).thenReturn(groupsResource);
            when(groupsResource.group(parentGroupId)).thenReturn(mockGroupResource);
            when(mockGroupResource.getSubGroups(null, null, false)).thenThrow(new RuntimeException("Keycloak failure"));

            GroupRepresentation result = adminService.retrieveSubgroupRepresentationByName(parentGroupId, subGroupName);

            assertNull(result); // we expect null on error
        }

        @DisplayName("Create Pilot : Success")
        @Test
        void givenValidPilot_whenNotExists_thenCreatePilot() {
            // No existing group
            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of());

            PilotCreationDto dto = PilotCreationDto.builder()
                    .name(TEST_GROUP_NAME)
                    .globalName("Test Group Global Name")
                    .subGroups(List.of("ADMIN", "USER"))
                    .verifiableCredential("base64-encoded-credential")
                    .roles(Set.of(T4mRole.PROVIDER))
                    .dataSpaceConnectorUrl("http://example.com")
                    .build();

            // Mock the response from the add method
            Response response = mock(Response.class);
            when(response.getHeaderString("Location")).thenReturn("http://localhost/admin/realms/test-realm/groups/" + TEST_GROUP_ID);
            when(groupsResource.add(any(GroupRepresentation.class))).thenReturn(response);

            // Mock the subgroup creation
            GroupResource parentGroupResource = mock(GroupResource.class);
            when(groupsResource.group(TEST_GROUP_ID)).thenReturn(parentGroupResource);

            adminService.createPilot(dto);

            // Verify
            verify(parentGroupResource, times(2)).subGroup(any(GroupRepresentation.class));
        }

        @DisplayName("Create Pilot : Already Exists")
        @Test
        void givenPilotAlreadyExists_whenCreate_thenThrowResourceAlreadyExistsException() {
            GroupRepresentation group = new GroupRepresentation();
            group.setName(TEST_GROUP_NAME);

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(group));

            PilotCreationDto dto = PilotCreationDto.builder()
                    .name(TEST_GROUP_NAME)
                    .globalName("Test Group Global Name")
                    .subGroups(List.of())
                    .verifiableCredential("base64-encoded-credential")
                    .roles(Set.of(T4mRole.PROVIDER))
                    .dataSpaceConnectorUrl("http://example.com")
                    .build();

            assertThrows(ResourceAlreadyExistsException.class, () -> adminService.createPilot(dto));

            verify(groupsResource, never()).add(any());
        }

        @DisplayName("Create Pilot : Keycloak Error")
        @Test
        void givenValidPilotData_whenCreatePilotAndKeycloakError_thenThrowKeycloakException() {
            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of());

            PilotCreationDto dto = PilotCreationDto.builder()
                    .name(TEST_GROUP_NAME)
                    .globalName("Test Group Global Name")
                    .subGroups(List.of("ADMIN", "USER"))
                    .verifiableCredential("base64-encoded-credential")
                    .roles(Set.of(T4mRole.PROVIDER))
                    .dataSpaceConnectorUrl("http://example.com")
                    .build();

            when(groupsResource.add(any(GroupRepresentation.class))).thenThrow(new RuntimeException("Keycloak error"));

            assertThrows(KeycloakException.class, () -> adminService.createPilot(dto));
        }

        @DisplayName("Delete Pilot : Success")
        @Test
        void givenExistingPilot_whenDelete_thenRemoveCalled() {
            // Given
            GroupRepresentation group = new GroupRepresentation();
            group.setName(TEST_GROUP_NAME);
            group.setId(TEST_GROUP_ID);

            GroupResource groupResource = mock(GroupResource.class);
            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(group));
            when(groupsResource.group(TEST_GROUP_ID)).thenReturn(groupResource);

            // When
            adminService.deletePilotByName(TEST_GROUP_NAME);

            // Then
            verify(groupResource).remove();
            
            // Verify OrganizationDeletionEvent is published
            ArgumentCaptor<OrganizationDeletionEvent> eventCaptor = ArgumentCaptor.forClass(OrganizationDeletionEvent.class);
            verify(eventPublisher).publishEvent(eventCaptor.capture());
            
            OrganizationDeletionEvent publishedEvent = eventCaptor.getValue();
            assertEquals(TEST_GROUP_NAME, publishedEvent.getPilotName());
            assertEquals(adminService, publishedEvent.getSource());
        }

        @DisplayName("Delete Pilot : Not Found")
        @Test
        void givenInvalidPilot_whenDelete_thenThrowResourceNotPresentException() {
            // Given
            when(groupsResource.groups()).thenReturn(List.of());

            // When & Then
            assertThrows(ResourceNotPresentException.class, () -> adminService.deletePilotByName(TEST_GROUP_NAME));

            verify(groupsResource, never()).group(any());
            // Verify no event is published when pilot not found
            verify(eventPublisher, never()).publishEvent(any());
        }

        @DisplayName("Update Pilot : Success")
        @Test
        void givenValidPilotData_whenPilotExists_thenUpdatePilot() {
            GroupRepresentation existingGroup = new GroupRepresentation();
            existingGroup.setName(TEST_GROUP_NAME);
            existingGroup.setId(TEST_GROUP_ID);

            PilotDto pilotDto = PilotDto.builder()
                    .name(TEST_GROUP_NAME)
                    .globalName("Updated Global Name")
                    .build();

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(existingGroup));
            when(groupsResource.group(TEST_GROUP_ID)).thenReturn(groupResource);

            adminService.updatePilotByName(pilotDto);

            verify(groupResource).update(argThat(gr -> "Updated Global Name".equals(gr.getAttributes().get("GLOBAL_NAME").getFirst())));
        }

        @DisplayName("Update Pilot : Not Found")
        @Test
        void givenInvalidPilotData_whenPilotNotExists_thenThrowResourceNotPresentException() {
            PilotDto pilotDto = PilotDto.builder()
                    .name(TEST_GROUP_NAME)
                    .build();

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of());

            assertThrows(KeycloakException.class, () -> adminService.updatePilotByName(pilotDto));
        }

        @DisplayName("Update Pilot : Keycloak Error")
        @Test
        void givenValidPilotData_whenKeycloakError_thenThrowKeycloakException() {
            GroupRepresentation existingGroup = new GroupRepresentation();
            existingGroup.setName(TEST_GROUP_NAME);
            existingGroup.setId(TEST_GROUP_ID);

            PilotDto pilotDto = PilotDto.builder()
                    .name(TEST_GROUP_NAME)
                    .build();

            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(existingGroup));
            when(groupsResource.group(TEST_GROUP_ID)).thenReturn(groupResource);
            doThrow(new RuntimeException("Keycloak error")).when(groupResource).update(any());

            assertThrows(KeycloakException.class, () -> adminService.updatePilotByName(pilotDto));
        }

        @DisplayName("Assign User Role to Pilot : Success")
        @Test
        void givenValidPilotAndUserRole_whenAssignUserRoleToPilot_thenRoleAdded() {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setId("group-id");
            groupRepresentation.setName(TEST_PILOT_CODE);

            RoleRepresentation roleRepresentation = new RoleRepresentation();
            roleRepresentation.setName(TEST_USER_ROLE);

            // Spy service
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(groupRepresentation).when(spyService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);
            doReturn(roleRepresentation).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);
            doReturn(Collections.emptyList()).when(spyService).retrieveAllClientRoleRepresentationsForSpecificGroup("group-id");
            doReturn("test-client-id").when(spyService).retrieveClientId();

            // Mock Keycloak call chain
            GroupResource mockGroupResource = mock(GroupResource.class);
            RoleMappingResource mockRoleMappingResource = mock(RoleMappingResource.class);
            RoleScopeResource mockRoleScopeResource = mock(RoleScopeResource.class);

            when(realmResource.groups().group("group-id")).thenReturn(mockGroupResource);
            when(mockGroupResource.roles()).thenReturn(mockRoleMappingResource);
            when(mockRoleMappingResource.clientLevel("test-client-id")).thenReturn(mockRoleScopeResource);
            doNothing().when(mockRoleScopeResource).add(Collections.singletonList(roleRepresentation));

            // Execute
            spyService.assignUserRoleToPilot(TEST_USER_ROLE, TEST_PILOT_CODE);

            // Verify
            verify(mockRoleScopeResource).add(Collections.singletonList(roleRepresentation));
        }

        @DisplayName("Assign User Role to Pilot : Pilot Not Found")
        @Test
        void givenMissingPilot_whenAssignUserRoleToPilot_thenThrowResourceNotPresentException() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);

            ResourceNotPresentException exception = assertThrows(ResourceNotPresentException.class,
                    () -> spyService.assignUserRoleToPilot(TEST_USER_ROLE, TEST_PILOT_CODE));

            assertEquals("Pilot '" + TEST_PILOT_CODE + "' not found", exception.getMessage());
        }

        @Test
        @DisplayName("Assign User Role to Pilot : Role Not Found")
        void givenMissingUserRole_whenAssignUserRoleToPilot_thenThrowResourceNotPresentException() {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setId("group-id");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(groupRepresentation).when(spyService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            ResourceNotPresentException exception = assertThrows(ResourceNotPresentException.class,
                    () -> spyService.assignUserRoleToPilot(TEST_USER_ROLE, TEST_PILOT_CODE));

            assertEquals("Role '" + TEST_USER_ROLE + "' not found", exception.getMessage());
        }

        @DisplayName("Assign User Role to Pilot : Role Already Assigned")
        @Test
        void givenRoleAlreadyAssigned_whenAssignUserRoleToPilot_thenNoRoleAdded() {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setId("group-id");

            RoleRepresentation roleRepresentation = new RoleRepresentation();
            roleRepresentation.setName(TEST_USER_ROLE);

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(groupRepresentation).when(spyService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);
            doReturn(roleRepresentation).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);
            doReturn(List.of(roleRepresentation)).when(spyService).retrieveAllClientRoleRepresentationsForSpecificGroup("group-id");

            // Mock full chain
            RoleScopeResource mockRoleScopeResource = mock(RoleScopeResource.class);

            spyService.assignUserRoleToPilot(TEST_USER_ROLE, TEST_PILOT_CODE);

            verify(mockRoleScopeResource, never()).add(any());
        }

        @DisplayName("Assign User Role to Pilot : Exception Handling")
        @Test
        void givenExceptionDuringAssign_whenAssignUserRoleToPilot_thenThrowsKeycloakException() {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setId("group-id");

            RoleRepresentation roleRepresentation = new RoleRepresentation();
            roleRepresentation.setName(TEST_USER_ROLE);

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(groupRepresentation).when(spyService).retrieveGroupRepresentationByName(TEST_PILOT_CODE);
            doReturn(roleRepresentation).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);
            doReturn(Collections.emptyList()).when(spyService).retrieveAllClientRoleRepresentationsForSpecificGroup("group-id");

            KeycloakException ex = assertThrows(KeycloakException.class,
                    () -> spyService.assignUserRoleToPilot(TEST_USER_ROLE, TEST_PILOT_CODE));

            assertEquals("Error assigning user role to pilot", ex.getMessage());
        }

        @DisplayName("Retrieve All Client Role Representations for Specific Group : returns roles for group")
        @Test
        void givenGroupName_whenRetrieveAllClientRoleRepresentationsForSpecificGroup_returnsRoles() {
            String groupId = "group-1";
            RoleRepresentation role = new RoleRepresentation();
            role.setName("TEST_PILOT");

            ReflectionTestUtils.setField(adminService, "clientId", "client-id");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn("client-id").when(spyService).retrieveClientId();

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.groups()).thenReturn(groupsResource);
            when(groupsResource.group(anyString())).thenReturn(groupResource);
            when(groupResource.roles()).thenReturn(roleMappingResource);
            when(roleMappingResource.clientLevel(anyString())).thenReturn(roleScopeResource);
            when(roleScopeResource.listAll()).thenReturn(List.of(role));

            List<RoleRepresentation> result = spyService.retrieveAllClientRoleRepresentationsForSpecificGroup(groupId);
            assertEquals(1, result.size());
            assertEquals("TEST_PILOT", result.getFirst().getName());
        }

        @DisplayName("retrieveAllClientRoleRepresentationsForSpecificGroup : returns empty on error")
        @Test
        void retrieveAllClientRoleRepresentationsForSpecificGroup_returnsEmptyOnError() {
            when(keycloak.realm(anyString())).thenThrow(new RuntimeException("Keycloak error"));
            List<RoleRepresentation> result = adminService.retrieveAllClientRoleRepresentationsForSpecificGroup("group");
            assertTrue(result.isEmpty());
        }

        @DisplayName("Retrieve All Group Representations : returns all groups")
        @Test
        void retrieveAllGroupRepresentations_returnsAllGroups() {
            GroupRepresentation group = new GroupRepresentation();
            group.setName("TEST_PILOT");

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.groups()).thenReturn(groupsResource);
            when(groupsResource.groups(any(), any(), any(), anyBoolean())).thenReturn(List.of(group));

            List<GroupRepresentation> result = adminService.retrieveAllGroupRepresentations();
            assertEquals(1, result.size());
            assertEquals("TEST_PILOT", result.getFirst().getName());
        }

        @DisplayName("Retrieve All Group Representations : returns empty on failure")
        @Test
        void retrieveAllGroupRepresentations_returnsEmptyOnFailure() {
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.groups()).thenThrow(new RuntimeException("Error"));

            List<GroupRepresentation> result = adminService.retrieveAllGroupRepresentations();
            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("Realm Management Tests")
    class RealmManagementTests {
        @DisplayName("Retrieve Realm Representation By Name : Success")
        @Test
        void givenPilotRole_whenRetrieveRealmRepresentationByName_returnsRole() {
            RoleRepresentation role = new RoleRepresentation();
            role.setName("PILOT");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(List.of(role)).when(spyService).retrieveAllRealmRepresentations();

            RoleRepresentation result = spyService.retrieveRealmRepresentationByName("PILOT");
            assertNotNull(result);
            assertEquals("PILOT", result.getName());
        }

        @DisplayName("Retrieve Realm Representation By Name : Not Found")
        @Test
        void givenPilotRole_whenRetrieveRealmRepresentationByName_returnsNullWhenNotFound() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(List.of()).when(spyService).retrieveAllRealmRepresentations();

            RoleRepresentation result = spyService.retrieveRealmRepresentationByName("ADMIN");
            assertNull(result);
        }

        @DisplayName("Retrieve all Pilot Roles : Success")
        @Test
        void whenSuperAdminRole_whenRetrieveAllPilotRoles_thenSuccess() {
            RoleRepresentation r1 = new RoleRepresentation(); r1.setName("ADMIN");
            RoleRepresentation r2 = new RoleRepresentation(); r2.setName("SUPER_ADMIN");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(List.of(r1, r2)).when(spyService).retrieveAllRealmRepresentations();

            List<String> result = spyService.retrieveAllPilotRoles(true);
            assertEquals(List.of("ADMIN", "SUPER_ADMIN"), result);
        }

        @DisplayName("Retrieve all Pilot Roles : Success for ADMIN / Excludes SUPER_ADMIN role")
        @Test
        void givenAdminRole_whenRetrieveAllPilotRoles_thenExcludesSuperAdminRoles() {
            RoleRepresentation r1 = new RoleRepresentation(); r1.setName("ADMIN");
            RoleRepresentation r2 = new RoleRepresentation(); r2.setName("SUPER_ADMIN");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(List.of(r1, r2)).when(spyService).retrieveAllRealmRepresentations();

            List<String> result = spyService.retrieveAllPilotRoles(false);
            assertEquals(List.of("ADMIN"), result);
        }

        @DisplayName("retrieveAllRealmRepresentations : returns all realm roles")
        @Test
        void retrieveAllRealmRepresentations_returnsAllRoles() {
            RoleRepresentation role = new RoleRepresentation();
            role.setName("REALM_ROLE");

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.roles()).thenReturn(rolesResource);
            when(rolesResource.list()).thenReturn(List.of(role));

            List<RoleRepresentation> result = adminService.retrieveAllRealmRepresentations();
            assertEquals(1, result.size());
            assertEquals("REALM_ROLE", result.getFirst().getName());
        }

        @DisplayName("retrieveAllRealmRepresentations : returns empty on failure")
        @Test
        void retrieveAllRealmRepresentations_returnsEmptyOnFailure() {
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.roles()).thenThrow(new RuntimeException("Error"));

            List<RoleRepresentation> result = adminService.retrieveAllRealmRepresentations();
            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("Client Management Tests")
    class ClientManagementTests {
        @DisplayName("Retrieve Client Representation : Success")
        @Test
        void whenKeycloakReturnsClientRepresentation_thenReturnClientRepresentation() {
            when(keycloak.realm("test-realm")).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);

            ClientRepresentation clientRepresentation = new ClientRepresentation();
            when(clientsResource.findByClientId("test-client")).thenReturn(List.of(clientRepresentation));
            ClientRepresentation result = adminService.retrieveClientRepresentationByName("test-client");
            assertEquals(clientRepresentation, result);
        }

        @DisplayName("Retrieve Client Representation : Handles exception gracefully")
        @Test
        void whenKeycloakThrowsException_thenReturnNull() {
            when(keycloak.realm("test-realm")).thenReturn(realmResource);
            when(realmResource.clients()).thenThrow(new RuntimeException("Keycloak error"));

            ClientRepresentation result = adminService.retrieveClientRepresentationByName("test-client");
            assertNull(result);
        }

        @DisplayName("Retrieve all User Roles : Success")
        @Test
        void whenRetrieveAllUserRoles_thenSuccess(){
            List<RoleRepresentation> listRoleRepresentations = List.of(generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE));

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(listRoleRepresentations).when(spyService).retrieveAllClientRoleRepresentations();

            List<UserRoleDto> result = spyService.retrieveAllUserRoles(true);

            assertEquals(TEST_USER_ROLE, result.getFirst().getName());
            assertEquals(TEST_USER_ROLE, result.getFirst().getGlobalName());
            assertEquals(1, result.size());
        }

        @DisplayName("Retrieve User Role by Name : Success")
        @Test
        void whenRetrieveUserRoleByName_thenReturnUserRoleDto() {
            RoleRepresentation roleRep = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(roleRep).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            UserRoleDto result = spyService.retrieveUserRoleByName(TEST_USER_ROLE);
            assertNotNull(result);
            assertEquals(TEST_USER_ROLE, result.getName());
        }

        @DisplayName("Retrieve User Role by Name : Not Found")
        @Test
        void whenUserRoleNotFound_thenThrowResourceNotPresentException() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            assertThrows(ResourceNotPresentException.class, () -> {
                spyService.retrieveUserRoleByName(TEST_USER_ROLE);
            });
        }

        @DisplayName("Create User Role : Success")
        @Test
        void givenUserRoleData_whenCreateUserRole_thenSuccess() {
            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");

            UserRoleCreationDto dto = new UserRoleCreationDto(TEST_USER_ROLE, TEST_USER_ROLE, "TEST_DESCRIPTION");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);

            assertDoesNotThrow(() -> {
                spyService.createUserRole(dto);
            });
        }

        @DisplayName("Create User Role : Already Exists")
        @Test
        void givenUserRoleData_whenCreateUserRole_thenThrowResourceAlreadyExistsException() {
            RoleRepresentation existing = new RoleRepresentation();
            existing.setName(TEST_USER_ROLE);

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(existing).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            UserRoleCreationDto dto = new UserRoleCreationDto(TEST_USER_ROLE, TEST_USER_ROLE, "TEST_DESCRIPTION");

            assertThrows(ResourceAlreadyExistsException.class, () -> {
                spyService.createUserRole(dto);
            });
        }

        @DisplayName("Create User Role : Failure in Keycloak Call")
        @Test
        void givenUserRoleData_whenCreateUserRole_thenThrowKeycloakException() {
            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");

            UserRoleCreationDto dto = new UserRoleCreationDto(TEST_USER_ROLE, TEST_USER_ROLE, "TEST_DESCRIPTION");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            doThrow(RuntimeException.class).when(rolesResource).create(any());

            assertThrows(KeycloakException.class, () -> {
                spyService.createUserRole(dto);
            });
        }

        @DisplayName("Delete User Role : Success")
        @Test
        void givenUserRole_whenDeleteUserRole_thenSuccess() {
            RoleRepresentation roleRep = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(roleRep).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);

            assertDoesNotThrow(() -> spyService.deleteUserRole(TEST_USER_ROLE));
            verify(roleResource).remove();
        }

        @DisplayName("Delete User Role : Role Not Found")
        @Test
        void givenUserRole_whenDeleteUserRole_thenThrowNotFoundException() {
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            assertThrows(ResourceNotPresentException.class, () -> spyService.deleteUserRole(TEST_USER_ROLE));
        }

        @DisplayName("Delete User Role : Keycloak Failure")
        @Test
        void givenUserRole_whenDeleteUserRole_thenThrowKeycloakException() {
            RoleRepresentation roleRep = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(roleRep).when(spyService).retrieveClientRoleRepresentationByName(TEST_USER_ROLE);

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);
            doThrow(RuntimeException.class).when(roleResource).remove();

            assertThrows(KeycloakException.class, () -> spyService.deleteUserRole(TEST_USER_ROLE));
        }

        @DisplayName("Update User Role : Success")
        @Test
        void givenUserRoleData_whenUpdateUserRole_thenSuccess() {
            UserRoleDto dto = new UserRoleDto();
            dto.setName("ANOTHER_NAME");
            dto.setGlobalName("ANOTHER_NAME_GLOBAL");
            dto.setDescription("ANOTHER_DESCRIPTION");

            RoleRepresentation existing = new RoleRepresentation();
            existing.setName("TEST_ROLE");
            existing.setDescription("TEST_DESCRIPTION");
            Map<String, List<String>> pilotDataMap = new HashMap<>();
            pilotDataMap.put("pilot_role", List.of(TEST_PILOT_ROLE));
            pilotDataMap.put("pilot_code", List.of(TEST_PILOT_CODE));
            existing.setAttributes(pilotDataMap);


            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(existing).when(spyService).retrieveClientRoleRepresentationByName(anyString());

            RoleRepresentation updated = UserRoleDto.toRoleRepresentation(dto, existing);
            assertEquals(updated.getDescription(), dto.getDescription());
            assertEquals(updated.getName(), dto.getName());
            assertEquals(updated.getAttributes().get("global_name").getFirst(), dto.getGlobalName());

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);

            assertDoesNotThrow(() -> spyService.updateUserRole(dto));
            verify(roleResource).update(updated);
        }

        @DisplayName("Update User Role : Not Found User Role")
        @Test
        void givenUserRoleData_whenUpdateUserRole_thenThrowNotFoundException() {
            UserRoleDto dto = new UserRoleDto();
            dto.setName(TEST_USER_ROLE);
            dto.setGlobalName(TEST_USER_ROLE);
            dto.setDescription("TEST_DESCRIPTION");

            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(null).when(spyService).retrieveClientRoleRepresentationByName(anyString());

            assertThrows(ResourceNotPresentException.class, () -> spyService.updateUserRole(dto));
        }

        @DisplayName("Update User Role : Failure in Keycloak Call")
        @Test
        void givenUserRoleData_whenUpdateUserRole_thenThrowKeycloakException() {
            UserRoleDto dto = new UserRoleDto();
            dto.setName(TEST_USER_ROLE);
            dto.setGlobalName(TEST_USER_ROLE);
            RoleRepresentation existing = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            KeycloakAdminService spyService = Mockito.spy(adminService);
            doReturn(existing).when(spyService).retrieveClientRoleRepresentationByName(anyString());

            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);
            doThrow(RuntimeException.class).when(roleResource).update(any());

            assertThrows(KeycloakException.class, () -> spyService.updateUserRole(dto));
        }

        @DisplayName("Retrieve All Client Role Representations : Success")
        @Test
        void whenRetrieveAllClientRoles_thenReturnListOfRepresentations() {
            RoleRepresentation repr = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.list(false)).thenReturn(List.of(repr));

            List<RoleRepresentation> result = adminService.retrieveAllClientRoleRepresentations();
            assertEquals(1, result.size());
        }

        @DisplayName("Retrieve All Client Role Representations : Failure")
        @Test
        void whenRetrieveAllClientRoles_thenReturnEmptyList() {
            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.list(false)).thenThrow(new RuntimeException("Error"));

            List<RoleRepresentation> result = adminService.retrieveAllClientRoleRepresentations();
            assertTrue(result.isEmpty());
        }

        @DisplayName("Retrieve Client Role Representation By Name : Success")
        @Test
        void whenRetrieveClientRoleByName_thenReturnRepresentation() {
            RoleRepresentation repr = generateMockRoleRepresentation(TEST_USER_ROLE, TEST_USER_ROLE);

            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenReturn(repr);

            RoleRepresentation result = adminService.retrieveClientRoleRepresentationByName(TEST_USER_ROLE);
            assertNotNull(result);
            assertEquals(TEST_USER_ROLE, result.getName());
        }

        @DisplayName("Retrieve Client Role Representation By Name : Failure")
        @Test
        void givenUserRoleName_whenRetrieveClientRoleByName_thenReturnNull() {
            ReflectionTestUtils.setField(adminService, "clientId", "client-UUID");
            when(keycloak.realm(anyString())).thenReturn(realmResource);
            when(realmResource.clients()).thenReturn(clientsResource);
            when(clientsResource.get(anyString())).thenReturn(clientResource);
            when(clientResource.roles()).thenReturn(rolesResource);
            when(rolesResource.get(anyString())).thenReturn(roleResource);
            when(roleResource.toRepresentation()).thenThrow(RuntimeException.class);

            RoleRepresentation result = adminService.retrieveClientRoleRepresentationByName(TEST_USER_ROLE);
            assertNull(result);
        }
    }

    private RoleRepresentation generateMockRoleRepresentation(String name, String globalRole){
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setName(name);
        roleRepresentation.setDescription("TEST_DESCRIPTION");
        Map<String, List<String>> pilotDataMap = new HashMap<>();
        pilotDataMap.put("global_name", List.of(globalRole));
        roleRepresentation.setAttributes(pilotDataMap);
        return roleRepresentation;
    }
}
