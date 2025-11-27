package gr.atc.t4m.kafka;

import gr.atc.t4m.dto.EventDto;
import gr.atc.t4m.dto.PilotDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.OrganizationDataDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.enums.OrganizationEventType;
import gr.atc.t4m.enums.T4mRole;
import gr.atc.t4m.exception.CustomExceptions.*;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.representations.idm.GroupRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Kafka Message Handler Unit Tests")
class KafkaMessageHandlerTests {

    @Mock
    private IKeycloakAdminService keycloakAdminService;

    @Mock
    private IUserManagementService userManagementService;

    @Mock
    private IEmailService emailService;

    @InjectMocks
    private KafkaMessageHandler kafkaMessageHandler;

    private EventDto validEvent;
    private UserDto existingUser;

    @BeforeEach
    void setUp() {
        OrganizationDataDto organizationData = new OrganizationDataDto(
                "pilot123",
                "test_pilot",
                "test@example.com",
                Set.of(T4mRole.PROVIDER),
                "https://example.com/dsc",
                "base64-encoded-credential",
                "userId123"
        );

        validEvent = new EventDto(
                OrganizationEventType.ORGANIZATION_ONBOARDING.toString(),
                "Organization registration event",
                "user-manager",
                "test_pilot",
                "2023-10-01T10:00:00",
                "HIGH",
                organizationData
        );

        existingUser = UserDto.builder()
                .userId("userId123")
                .email("test@example.com")
                .firstName("John")
                .lastName("Doe")
                .pilotCode(null) // No organization assigned yet
                .build();
    }

    @Nested
    @DisplayName("Valid Kafka messages")
    class ValidMessageConsumption {

        @Test
        @DisplayName("Process Organization Registration: Success")
        void givenValidEvent_whenConsumeMessage_thenProcessSuccessfully() {
            // Given
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST_PILOT") &&
                    pilot.globalName().equals("test_pilot") &&
                    pilot.subGroups().containsAll(List.of("ADMIN", "USER")) &&
                    pilot.verifiableCredential().equals("base64-encoded-credential") &&
                    pilot.roles().equals(Set.of(T4mRole.PROVIDER)) &&
                    pilot.dataSpaceConnectorUrl().equals("https://example.com/dsc") &&
                    pilot.organizationId().equals("pilot123")
            ));

            verify(userManagementService).updateUser(argThat(user ->
                    user.getUserId().equals("userId123") &&
                    user.getPilotCode().equals("TEST_PILOT") &&
                    user.getOrganizationId().equals("pilot123")
            ));

            verify(emailService).sendOrganizationRegistrationEmail("John Doe", "test@example.com", "test_pilot");
        }

        @Test
        @DisplayName("Build Full Name: Success with first name only")
        void givenUserWithFirstNameOnly_whenConsumeMessage_thenUseFirstNameForEmail() {
            // Given
            existingUser.setLastName(null);
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(emailService).sendOrganizationRegistrationEmail("John", "test@example.com", "test_pilot");
        }

        @Test
        @DisplayName("Build Full Name: Success with last name only")
        void givenUserWithLastNameOnly_whenConsumeMessage_thenUseLastNameForEmail() {
            // Given
            existingUser.setFirstName(null);
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(emailService).sendOrganizationRegistrationEmail("Doe", "test@example.com", "test_pilot");
        }

        @Test
        @DisplayName("Build Full Name: Default name when no names provided")
        void givenUserWithNoNames_whenConsumeMessage_thenUseDefaultNameForEmail() {
            // Given
            existingUser.setFirstName("");
            existingUser.setLastName(" ");
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(emailService).sendOrganizationRegistrationEmail("User", "test@example.com", "test_pilot");
        }
    }

    @Nested
    @DisplayName("User Management exceptions")
    class UserManagementExceptionHandling {

        @Test
        @DisplayName("Handle User Not Found: Early termination when user missing")
        void givenUserNotFound_whenConsumeMessage_thenTerminateProcessing() {
            // Given
            when(userManagementService.retrieveUserById("userId123"))
                    .thenThrow(new ResourceNotPresentException("User not found"));

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(keycloakAdminService).createPilot(any(PilotCreationDto.class));
            verify(userManagementService).retrieveUserById("userId123");
            verify(userManagementService, never()).updateUser(any(UserDto.class));
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Skip Existing Organization: Early termination when user has pilot")
        void givenUserWithPilotCode_whenConsumeMessage_thenSkipProcessing() {
            // Given
            existingUser.setPilotCode("EXISTING_PILOT");
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(keycloakAdminService).createPilot(any(PilotCreationDto.class));
            verify(userManagementService).retrieveUserById("userId123");
            verify(userManagementService, never()).updateUser(any(UserDto.class));
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("Pilot creation data")
    class PilotCreationDataProcessing {

        @Test
        @DisplayName("Format Pilot Name: Uppercase conversion success")
        void givenLowercasePilotName_whenConsumeMessage_thenFormatToUppercase() {
            // Given
            OrganizationDataDto orgData = new OrganizationDataDto(
                    "pilot123",
                    "test_pilot_lowercase",
                    "test@example.com",
                    Set.of(T4mRole.CONSUMER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );
            EventDto lowerCaseEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_ONBOARDING.toString(),
                    "Organization registration event",
                    "user-manager",
                    "test_pilot_lowercase",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    orgData
            );
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(lowerCaseEvent);

            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST_PILOT_LOWERCASE") &&
                    pilot.organizationId().equals("pilot123")
            ));
        }

        @Test
        @DisplayName("Handle Pilot Name Spaces: Trim and format success")
        void givenPilotNameWithSpaces_whenConsumeMessage_thenTrimAndFormat() {
            // Given
            OrganizationDataDto spacedData = new OrganizationDataDto(
                    "pilot123",                                  // id
                    " test pilot ",                                 // name
                    "test@test.com",                                // Email
                    Set.of(T4mRole.PROVIDER),                       // role
                    "https://example.com/dsc",                      // dataSpaceConnectorUrl
                    "https://example.com/credential",               // verifiableCredential
                    "userId123"                                     // userId
            );
            EventDto spacedEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_ONBOARDING.toString(), // type
                    "Organization registration event",              // description
                    "user-manager",                                 // sourceComponent
                    " test pilot ",                                 // organization
                    "2023-10-01T10:00:00",                        // timestamp
                    "HIGH",                                         // priority
                    spacedData                                      // data
            );
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(spacedEvent);

            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST-PILOT") &&
                    pilot.organizationId().equals("pilot123")
            ));
        }

        @Test
        @DisplayName("Create Pilot Subgroups: Default subgroups assigned")
        void givenValidEvent_whenConsumeMessage_thenCreatePilotWithDefaultSubgroups() {
            // Given
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);

            // When
            kafkaMessageHandler.consume(validEvent);

            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.subGroups().equals(List.of("ADMIN", "USER"))
            ));
        }
    }

    @Nested
    @DisplayName("Organization deletion events")
    class OrganizationDeletionHandling {

        @Test
        @DisplayName("Delete Organization Pilot : Success")
        void givenDeleteEvent_whenConsumeMessage_thenDeletePilot() {
            // Given
            OrganizationDataDto organizationData = new OrganizationDataDto(
                    "pilot123",
                    "test_pilot",
                    "test@example.com",
                    Set.of(T4mRole.PROVIDER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );

            EventDto deleteEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_DELETED.toString(),
                    "Organization deletion event",
                    "user-manager",
                    "test_pilot",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    organizationData
            );

            // When
            kafkaMessageHandler.consume(deleteEvent);

            // Then
            verify(keycloakAdminService).deletePilotByName("TEST_PILOT");
            verify(userManagementService, never()).retrieveUserById(anyString());
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Delete Organization with Name Formatting : Success")
        void givenDeleteEventWithSpaces_whenConsumeMessage_thenDeletePilotWithFormattedName() {
            // Given
            OrganizationDataDto organizationData = new OrganizationDataDto(
                    "pilot123",
                    " test pilot ",
                    "test@example.com",
                    Set.of(T4mRole.CONSUMER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );

            EventDto deleteEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_DELETED.toString(),
                    "Organization deletion event",
                    "user-manager",
                    " test pilot ",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    organizationData
            );

            // When
            kafkaMessageHandler.consume(deleteEvent);

            // Then
            verify(keycloakAdminService).deletePilotByName("TEST-PILOT");
        }
    }

    @Nested
    @DisplayName("Organization update events")
    class OrganizationUpdateHandling {

        @Test
        @DisplayName("Update Existing Organization : Success")
        void givenUpdateEvent_whenConsumeMessage_thenUpdatePilot() {
            // Given
            OrganizationDataDto updatedOrgData = new OrganizationDataDto(
                    "pilot123",
                    "test-pilot-updated",
                    "updated@example.com",
                    Set.of(T4mRole.CONSUMER, T4mRole.PROVIDER),
                    "https://updated.example.com/dsc",
                    "updated-credential",
                    "userId123"
            );

            EventDto updateEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_UPDATED.toString(),
                    "Organization update event",
                    "Organization Management",
                    "test_pilot_updated",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    updatedOrgData
            );

            // Mock existing group representation
            GroupRepresentation existingGroup = new GroupRepresentation();
            existingGroup.setName("TEST_PILOT");
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("GLOBAL_NAME", List.of("old_global_name"));
            attributes.put("ORGANIZATION_ID", List.of("pilot123"));
            attributes.put("VERIFIABLE_CREDENTIALS", List.of("old-credential"));
            attributes.put("DATASPACE_CONNECTION_URL", List.of("https://old.example.com/dsc"));
            attributes.put("ROLES", List.of("CONSUMER"));
            existingGroup.setAttributes(attributes);

            when(keycloakAdminService.retrieveGroupRepresentationByOrganizationId("pilot123")).thenReturn(existingGroup);

            // When
            kafkaMessageHandler.consume(updateEvent);

            // Then
            verify(keycloakAdminService).retrieveGroupRepresentationByOrganizationId("pilot123");
            verify(userManagementService, never()).retrieveUserById(anyString());
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Update Non-Existent Organization : Skip Update")
        void givenUpdateEventForNonExistentPilot_whenConsumeMessage_thenSkipUpdate() {
            // Given
            OrganizationDataDto updatedOrgData = new OrganizationDataDto(
                    "pilot123",
                    "nonexistent_pilot",
                    "test@example.com",
                    Set.of(T4mRole.PROVIDER),
                    "https://example.com/dsc",
                    "credential",
                    "userId123"
            );

            EventDto updateEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_UPDATED.toString(),
                    "Organization update event",
                    "user-manager",
                    "nonexistent_pilot",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    updatedOrgData
            );

            when(keycloakAdminService.retrieveGroupRepresentationByOrganizationId("pilot123")).thenReturn(null);

            // When
            kafkaMessageHandler.consume(updateEvent);

            // Then
            verify(keycloakAdminService).retrieveGroupRepresentationByOrganizationId("pilot123");
            verify(keycloakAdminService, never()).updatePilotByName(any(PilotDto.class), anyString());
        }

        @Test
        @DisplayName("Update Organization with Keycloak Error : Handle Exception")
        void givenUpdateEventWithKeycloakError_whenConsumeMessage_thenHandleException() {
            // Given
            OrganizationDataDto updatedOrgData = new OrganizationDataDto(
                    "pilot123",
                    "test_pilot",
                    "test@example.com",
                    Set.of(T4mRole.PROVIDER),
                    "https://example.com/dsc",
                    "credential",
                    "userId123"
            );

            EventDto updateEvent = new EventDto(
                    OrganizationEventType.ORGANIZATION_UPDATED.toString(),
                    "Organization update event",
                    "user-manager",
                    "test_pilot",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    updatedOrgData
            );

            when(keycloakAdminService.retrieveGroupRepresentationByOrganizationId("pilot123"))
                    .thenThrow(new KeycloakException("Keycloak error"));

            // When
            kafkaMessageHandler.consume(updateEvent);

            // Then
            verify(keycloakAdminService).retrieveGroupRepresentationByOrganizationId("pilot123");
            verify(keycloakAdminService, never()).updatePilotByName(any(PilotDto.class), anyString());
        }
    }

    @Nested
    @DisplayName("Invalid event types")
    class InvalidEventTypeHandling {

        @Test
        @DisplayName("Process Unsupported Event Type : Discard Event")
        void givenInvalidEventType_whenConsumeMessage_thenDiscardEvent() {
            // Given
            OrganizationDataDto organizationData = new OrganizationDataDto(
                    "pilot123",
                    "test_pilot",
                    "test@example.com",
                    Set.of(T4mRole.PROVIDER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );

            EventDto invalidEvent = new EventDto(
                    "invalid.event.type",
                    "Invalid event",
                    "user-manager",
                    "test_pilot",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    organizationData
            );

            // When
            kafkaMessageHandler.consume(invalidEvent);

            // Then - No service methods should be called
            verify(keycloakAdminService, never()).createPilot(any(PilotCreationDto.class));
            verify(keycloakAdminService, never()).deletePilotByName(anyString());
            verify(keycloakAdminService, never()).updatePilotByName(any(PilotDto.class), anyString());
            verify(userManagementService, never()).retrieveUserById(anyString());
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("Process Null Event Type : Discard Event")
        void givenNullEventType_whenConsumeMessage_thenDiscardEvent() {
            // Given
            OrganizationDataDto organizationData = new OrganizationDataDto(
                    "pilot123",
                    "test_pilot",
                    "test@example.com",
                    Set.of(T4mRole.PROVIDER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );

            EventDto nullTypeEvent = new EventDto(
                    null,
                    "Event with null type",
                    "user-manager",
                    "test_pilot",
                    "2023-10-01T10:00:00",
                    "HIGH",
                    organizationData
            );

            // When
            kafkaMessageHandler.consume(nullTypeEvent);

            // Then - No service methods should be called
            verify(keycloakAdminService, never()).createPilot(any(PilotCreationDto.class));
            verify(keycloakAdminService, never()).deletePilotByName(anyString());
            verify(keycloakAdminService, never()).updatePilotByName(any(PilotDto.class), anyString());
            verify(userManagementService, never()).retrieveUserById(anyString());
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }
    }
}