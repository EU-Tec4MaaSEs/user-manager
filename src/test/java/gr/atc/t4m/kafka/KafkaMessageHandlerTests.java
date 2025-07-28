package gr.atc.t4m.kafka;

import gr.atc.t4m.dto.EventDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.OrganizationRegistrationDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
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
    private OrganizationRegistrationDto organizationData;

    @BeforeEach
    void setUp() {
        // Given - Setup test data
        organizationData = new OrganizationRegistrationDto(
                "pilot123",
                "test_pilot",
                "test@example.com",
                "userId123",
                Set.of(T4mRole.PROVIDER),
                "https://example.com/dsc",
                "base64-encoded-credential",
                "userId123"
        );
        
        validEvent = new EventDto(
                "organization.registration",
                "Organization registration event",
                "user-manager",
                "test_pilot",
                "2023-10-01T10:00:00Z",
                "Hig",
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
    @DisplayName("When consuming valid Kafka messages")
    class ValidMessageConsumption {

        @Test
        @DisplayName("Process Organization Registration: Success")
        void givenValidEvent_whenConsumeMessage_thenProcessSuccessfully() {
            // Given
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);
            
            // When
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST_PILOT") &&
                    pilot.globalName().equals("test_pilot") &&
                    pilot.subGroups().containsAll(List.of("ADMIN", "USER")) &&
                    pilot.verifiableCredential().equals("base64-encoded-credential") &&
                    pilot.roles().equals(Set.of(T4mRole.PROVIDER)) &&
                    pilot.dataSpaceConnectorUrl().equals("https://example.com/dsc")
            ));
            
            verify(userManagementService).updateUser(argThat(user ->
                    user.getUserId().equals("userId123") &&
                    user.getPilotCode().equals("TEST_PILOT")
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
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
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
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
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
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
            // Then
            verify(emailService).sendOrganizationRegistrationEmail("User", "test@example.com", "test_pilot");
        }
    }

    @Nested
    @DisplayName("When handling user management exceptions")
    class UserManagementExceptionHandling {

        @Test
        @DisplayName("Handle User Not Found: Early termination when user missing")
        void givenUserNotFound_whenConsumeMessage_thenTerminateProcessing() {
            // Given
            when(userManagementService.retrieveUserById("userId123"))
                    .thenThrow(new ResourceNotPresentException("User not found"));
            
            // When
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
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
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
            // Then
            verify(keycloakAdminService).createPilot(any(PilotCreationDto.class));
            verify(userManagementService).retrieveUserById("userId123");
            verify(userManagementService, never()).updateUser(any(UserDto.class));
            verify(emailService, never()).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }
    }

    @Nested
    @DisplayName("When processing pilot creation data")
    class PilotCreationDataProcessing {

        @Test
        @DisplayName("Format Pilot Name: Uppercase conversion success")
        void givenLowercasePilotName_whenConsumeMessage_thenFormatToUppercase() {
            // Given
            OrganizationRegistrationDto orgData = new OrganizationRegistrationDto(
                    "pilot123",
                    "test_pilot_lowercase",
                    "test@example.com",
                    "userId123",
                    Set.of(T4mRole.CONSUMER),
                    "https://example.com/dsc",
                    "base64-encoded-credential",
                    "userId123"
            );
            EventDto lowerCaseEvent = new EventDto(
                    "organization.registration",
                    "Organization registration event",
                    "user-manager",
                    "test_pilot_lowercase",
                    "2023-10-01T10:00:00Z",
                    "HIGH",
                    orgData
            );
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);
            
            // When
            kafkaMessageHandler.consume(lowerCaseEvent, "organization-registration-topic");
            
            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST_PILOT_LOWERCASE")
            ));
        }

        @Test
        @DisplayName("Handle Pilot Name Spaces: Trim and format success")
        void givenPilotNameWithSpaces_whenConsumeMessage_thenTrimAndFormat() {
            // Given
            OrganizationRegistrationDto spacedData = new OrganizationRegistrationDto(
                    "pilot123",                                     // id
                    " test pilot ",                                 // name
                    "test@example.com",                             // email
                    "userId123",                                    // contact (userId)
                    Set.of(T4mRole.PROVIDER),                       // role
                    "https://example.com/dsc",                      // dataSpaceConnectorUrl
                    "https://example.com/credential",               // verifiableCredential
                    "userId123"                                     // userId
            );
            EventDto spacedEvent = new EventDto(
                    "organization.registration",                    // type
                    "Organization registration event",              // description
                    "user-manager",                                 // sourceComponent
                    " test pilot ",                                 // organization
                    "2023-10-01T10:00:00Z",                        // timestamp
                    "HIGH",                                         // priority
                    spacedData                                      // data
            );
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);
            
            // When
            kafkaMessageHandler.consume(spacedEvent, "organization-registration-topic");
            
            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.name().equals("TEST-PILOT")
            ));
        }

        @Test
        @DisplayName("Create Pilot Subgroups: Default subgroups assigned")
        void givenValidEvent_whenConsumeMessage_thenCreatePilotWithDefaultSubgroups() {
            // Given
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);
            
            // When
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
            // Then
            verify(keycloakAdminService).createPilot(argThat(pilot ->
                    pilot.subGroups().equals(List.of("ADMIN", "USER"))
            ));
        }
    }

    @Nested
    @DisplayName("When processing in correct order")
    class ProcessingOrder {

        @Test
        @DisplayName("Process Sequence: Operations executed in order")
        void givenValidEvent_whenConsumeMessage_thenProcessInCorrectOrder() {
            // Given
            when(userManagementService.retrieveUserById("userId123")).thenReturn(existingUser);
            
            // When
            kafkaMessageHandler.consume(validEvent, "organization-registration-topic");
            
            // Then - Verify order of operations
            var inOrder = inOrder(keycloakAdminService, userManagementService, emailService);
            inOrder.verify(keycloakAdminService).createPilot(any(PilotCreationDto.class));
            inOrder.verify(userManagementService).retrieveUserById("userId123");
            inOrder.verify(userManagementService).updateUser(any(UserDto.class));
            inOrder.verify(emailService).sendOrganizationRegistrationEmail(anyString(), anyString(), anyString());
        }
    }
}