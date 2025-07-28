package gr.atc.t4m.events;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("App Event Listener Tests")
class AppEventListenerTests {

    @Mock
    private IUserManagementService userManagementService;

    @InjectMocks
    private AppEventListener appEventListener;

    private OrganizationDeletionEvent event;
    private Object eventSource;

    @BeforeEach
    void setUp() {
        eventSource = new Object();
    }

    @Test
    @DisplayName("Handle Organization Deletion : Success")
    void givenMatchingPilotUsers_whenHandleOrganizationDeletion_thenPilotUnassigned() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto user1 = createUserDto("user1", "test_pilot");
        UserDto user2 = createUserDto("user2", "OTHER_PILOT");
        UserDto user3 = createUserDto("user3", "TEST_PILOT");
        
        List<UserDto> allUsers = Arrays.asList(user1, user2, user3);
        when(userManagementService.retrieveAllUsers()).thenReturn(allUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(2)).updateUser(userCaptor.capture());
        
        List<UserDto> updatedUsers = userCaptor.getAllValues();
        assertThat(updatedUsers).hasSize(2);
        assertThat(updatedUsers.get(0).getPilotCode()).isEqualTo("REMOVE_PILOT");
        assertThat(updatedUsers.get(1).getPilotCode()).isEqualTo("REMOVE_PILOT");
        
        // Verify user2 was not updated (different pilot)
        assertThat(user2.getPilotCode()).isEqualTo("OTHER_PILOT");
    }

    @Test
    @DisplayName("Handle Organization Deletion : Empty Users List")
    void givenEmptyUsersList_whenHandleOrganizationDeletion_thenNoUsersUpdated() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);
        
        when(userManagementService.retrieveAllUsers()).thenReturn(Collections.emptyList());

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        verify(userManagementService, never()).updateUser(any(UserDto.class));
    }

    @Test
    @DisplayName("Handle Organization Deletion : With Null Pilot Codes")
    void givenUsersWithNullPilotCodes_whenHandleOrganizationDeletion_thenOnlyMatchingUsersUpdated() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto userWithNullPilot = createUserDto("user1", null);
        UserDto userWithMatchingPilot = createUserDto("user2", "TEST_PILOT");
        
        List<UserDto> allUsers = Arrays.asList(userWithNullPilot, userWithMatchingPilot);
        when(userManagementService.retrieveAllUsers()).thenReturn(allUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(1)).updateUser(userCaptor.capture());
        
        UserDto updatedUser = userCaptor.getValue();
        assertThat(updatedUser.getPilotCode()).isEqualTo("REMOVE_PILOT");
        assertThat(updatedUser.getUsername()).isEqualTo("user2");
    }

    @Test
    @DisplayName("Handle Organization Deletion : Case Insensitive Matching")
    void givenMixedCasePilotNames_whenHandleOrganizationDeletion_thenAllMatchingUsersUpdated() {
        // Given
        String pilotName = "Test_Pilot"; // Mixed case
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto user1 = createUserDto("user1", "test_pilot"); // lowercase
        UserDto user2 = createUserDto("user2", "TEST_PILOT"); // uppercase
        UserDto user3 = createUserDto("user3", "Test_Pilot"); // mixed case
        
        List<UserDto> allUsers = Arrays.asList(user1, user2, user3);
        when(userManagementService.retrieveAllUsers()).thenReturn(allUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        verify(userManagementService, times(3)).updateUser(any(UserDto.class));
    }

    @Test
    @DisplayName("Handle Organization Deletion : Not updating users with different Pilot Codes")
    void givenUsersWithDifferentPilotCodes_whenHandleOrganizationDeletion_thenNoUsersUpdated() {
        // Given
        String pilotName = "TARGET_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto user1 = createUserDto("user1", "OTHER_PILOT");
        UserDto user2 = createUserDto("user2", "ANOTHER_PILOT");
        
        List<UserDto> allUsers = Arrays.asList(user1, user2);
        when(userManagementService.retrieveAllUsers()).thenReturn(allUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        verify(userManagementService, never()).updateUser(any(UserDto.class));
        
        // Verify original pilot codes remain unchanged
        assertThat(user1.getPilotCode()).isEqualTo("OTHER_PILOT");
        assertThat(user2.getPilotCode()).isEqualTo("ANOTHER_PILOT");
    }

    private UserDto createUserDto(String username, String pilotCode) {
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setUserId("id-" + username);
        userDto.setPilotCode(pilotCode);
        return userDto;
    }
}