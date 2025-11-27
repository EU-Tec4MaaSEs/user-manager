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

        UserDto user1 = createUserDto("user1", "TEST_PILOT");
        UserDto user2 = createUserDto("user2", "TEST_PILOT");

        List<UserDto> pilotUsers = Arrays.asList(user1, user2);
        when(userManagementService.retrieveUsersByPilotCode(pilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(2)).updateUser(userCaptor.capture());

        List<UserDto> updatedUsers = userCaptor.getAllValues();
        assertThat(updatedUsers).hasSize(2);
        assertThat(updatedUsers.get(0).getPilotCode()).isEqualTo("DEFAULT");
        assertThat(updatedUsers.get(0).getOrganizationId()).isEqualTo("DEFAULT");
        assertThat(updatedUsers.get(1).getPilotCode()).isEqualTo("DEFAULT");
        assertThat(updatedUsers.get(1).getOrganizationId()).isEqualTo("DEFAULT");
    }

    @Test
    @DisplayName("Handle Organization Deletion : Empty Users List")
    void givenEmptyUsersList_whenHandleOrganizationDeletion_thenNoUsersUpdated() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        when(userManagementService.retrieveUsersByPilotCode(pilotName)).thenReturn(Collections.emptyList());

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        verify(userManagementService, never()).updateUser(any(UserDto.class));
    }

    @Test
    @DisplayName("Handle Organization Deletion : Single User Updated")
    void givenSingleMatchingUser_whenHandleOrganizationDeletion_thenUserUpdated() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto userWithMatchingPilot = createUserDto("user1", "TEST_PILOT");

        List<UserDto> pilotUsers = List.of(userWithMatchingPilot);
        when(userManagementService.retrieveUsersByPilotCode(pilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(1)).updateUser(userCaptor.capture());

        UserDto updatedUser = userCaptor.getValue();
        assertThat(updatedUser.getPilotCode()).isEqualTo("DEFAULT");
        assertThat(updatedUser.getOrganizationId()).isEqualTo("DEFAULT");
        assertThat(updatedUser.getUsername()).isEqualTo("user1");
    }

    @Test
    @DisplayName("Handle Organization Deletion : Multiple Users Updated")
    void givenMultipleMatchingUsers_whenHandleOrganizationDeletion_thenAllUsersUpdated() {
        // Given
        String pilotName = "TEST_PILOT";
        event = new OrganizationDeletionEvent(eventSource, pilotName);

        UserDto user1 = createUserDto("user1", "TEST_PILOT");
        UserDto user2 = createUserDto("user2", "TEST_PILOT");
        UserDto user3 = createUserDto("user3", "TEST_PILOT");

        List<UserDto> pilotUsers = Arrays.asList(user1, user2, user3);
        when(userManagementService.retrieveUsersByPilotCode(pilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleUnassignmentOfPilotFromUsers(event);

        // Then
        verify(userManagementService, times(3)).updateUser(any(UserDto.class));
    }

    @Test
    @DisplayName("Handle Organization Name Update : Success")
    void givenMatchingPilotUsers_whenHandleOrganizationNameUpdate_thenPilotCodeUpdated() {
        // Given
        String newPilotName = "NEW_PILOT_NAME";
        OrganizationNameUpdateEvent nameUpdateEvent = new OrganizationNameUpdateEvent(eventSource, newPilotName);

        UserDto user1 = createUserDto("user1", "OLD_PILOT_NAME");
        UserDto user2 = createUserDto("user2", "OLD_PILOT_NAME");

        List<UserDto> pilotUsers = Arrays.asList(user1, user2);
        when(userManagementService.retrieveUsersByPilotCode(newPilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleModificationOfPilotFromUsers(nameUpdateEvent);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(2)).updateUser(userCaptor.capture());

        List<UserDto> updatedUsers = userCaptor.getAllValues();
        assertThat(updatedUsers).hasSize(2);
        assertThat(updatedUsers.getFirst().getPilotCode()).isEqualTo(newPilotName);
        assertThat(updatedUsers.get(1).getPilotCode()).isEqualTo(newPilotName);
    }

    @Test
    @DisplayName("Handle Organization Name Update : Empty Users List")
    void givenEmptyUsersList_whenHandleOrganizationNameUpdate_thenNoUsersUpdated() {
        // Given
        String newPilotName = "NEW_PILOT_NAME";
        OrganizationNameUpdateEvent nameUpdateEvent = new OrganizationNameUpdateEvent(eventSource, newPilotName);

        when(userManagementService.retrieveUsersByPilotCode(newPilotName)).thenReturn(Collections.emptyList());

        // When
        appEventListener.handleModificationOfPilotFromUsers(nameUpdateEvent);

        // Then
        verify(userManagementService, never()).updateUser(any(UserDto.class));
    }

    @Test
    @DisplayName("Handle Organization Name Update : Single User Updated")
    void givenSingleMatchingUser_whenHandleOrganizationNameUpdate_thenUserUpdated() {
        // Given
        String newPilotName = "UPDATED_PILOT";
        OrganizationNameUpdateEvent nameUpdateEvent = new OrganizationNameUpdateEvent(eventSource, newPilotName);

        UserDto user = createUserDto("user1", "OLD_PILOT");

        List<UserDto> pilotUsers = List.of(user);
        when(userManagementService.retrieveUsersByPilotCode(newPilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleModificationOfPilotFromUsers(nameUpdateEvent);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(1)).updateUser(userCaptor.capture());

        UserDto updatedUser = userCaptor.getValue();
        assertThat(updatedUser.getPilotCode()).isEqualTo(newPilotName);
        assertThat(updatedUser.getUsername()).isEqualTo("user1");
    }

    @Test
    @DisplayName("Handle Organization Name Update : Multiple Users Updated")
    void givenMultipleMatchingUsers_whenHandleOrganizationNameUpdate_thenAllUsersUpdated() {
        // Given
        String newPilotName = "RENAMED_PILOT";
        OrganizationNameUpdateEvent nameUpdateEvent = new OrganizationNameUpdateEvent(eventSource, newPilotName);

        UserDto user1 = createUserDto("user1", "ORIGINAL_PILOT");
        UserDto user2 = createUserDto("user2", "ORIGINAL_PILOT");
        UserDto user3 = createUserDto("user3", "ORIGINAL_PILOT");

        List<UserDto> pilotUsers = Arrays.asList(user1, user2, user3);
        when(userManagementService.retrieveUsersByPilotCode(newPilotName)).thenReturn(pilotUsers);

        // When
        appEventListener.handleModificationOfPilotFromUsers(nameUpdateEvent);

        // Then
        ArgumentCaptor<UserDto> userCaptor = ArgumentCaptor.forClass(UserDto.class);
        verify(userManagementService, times(3)).updateUser(userCaptor.capture());

        List<UserDto> updatedUsers = userCaptor.getAllValues();
        assertThat(updatedUsers).allMatch(user -> newPilotName.equals(user.getPilotCode()));
    }

    private UserDto createUserDto(String username, String pilotCode) {
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setUserId("id-" + username);
        userDto.setPilotCode(pilotCode);
        return userDto;
    }
}