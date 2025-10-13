package gr.atc.t4m.kafka;

import gr.atc.t4m.dto.EventDto;
import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.service.interfaces.IEmailService;
import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import gr.atc.t4m.exception.CustomExceptions.*;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Optional;

@Service
@Slf4j
@Validated
public class KafkaMessageHandler {

    private static final String DEFAULT_PILOT = "DEFAULT";
    private final IKeycloakAdminService keycloakAdminService;
    private final IUserManagementService userManagementService;
    private final IEmailService emailService;

    public KafkaMessageHandler(IKeycloakAdminService keycloakAdminService, IUserManagementService userManagementService, IEmailService emailService) {
        this.keycloakAdminService = keycloakAdminService;
        this.userManagementService = userManagementService;
        this.emailService = emailService;
    }

    /**
     * Kafka consumer method to receive a JSON Event message - From Kafka Producers
     *
     * @param event: Event occurred in T4M
     */
    @KafkaListener(topics = "#{'${spring.kafka.consumer.topics}'.split(',')}", groupId = "${spring.kafka.consumer.group-id}", errorHandler = "kafkaErrorHandler")
    public void consume(@Valid EventDto event) {
        String globalName = event.data().name();
        String pilotName = String.join("-", globalName.trim().toUpperCase().split("\\s+"));
        String organizationId = event.data().id();

        try {
            // Create the record
            PilotCreationDto newPilot = PilotCreationDto.builder()
                    .name(pilotName)
                    .globalName(globalName)
                    .subGroups(List.of("ADMIN", "USER"))
                    .verifiableCredential(event.data().verifiableCredential())
                    .roles(event.data().role())
                    .dataSpaceConnectorUrl(event.data().dataSpaceConnectorUrl())
                    .organizationId(organizationId)
                    .build();

            keycloakAdminService.createPilot(newPilot);
            log.debug("Pilot created in Keycloak with name: {}", pilotName);
        } catch (KeycloakException | ResourceAlreadyExistsException e){
            log.error("Unable to create organization in Keycloak - Error: {}", e.getMessage());
            return;
        }

        // Assign organization to User
        UserDto existingUser;
        try {
            existingUser = userManagementService.retrieveUserById(event.data().userId());

            // Check whether user already has an organization assigned
            if (existingUser.getPilotCode() != null && !existingUser.getPilotCode().equalsIgnoreCase(DEFAULT_PILOT)) {
                log.warn("User with ID: {} already has an organization assigned: {}", existingUser.getUserId(), existingUser.getPilotCode());
                return;
            }

            existingUser.setPilotCode(pilotName);
            existingUser.setOrganizationId(organizationId);
            userManagementService.updateUser(existingUser);
            log.debug("User with ID: {} assigned to organization: {}", existingUser.getUserId(), pilotName);
        } catch (ResourceNotPresentException | ValidationException e){
            log.error("Unable to assign organization to designated user - Error: {}", e.getMessage());
            return;
        }

        // Send email after successful operation
        String fullName = buildFullName(existingUser.getFirstName(), existingUser.getLastName())
                .orElse("User");
        emailService.sendOrganizationRegistrationEmail(fullName, existingUser.getEmail(), globalName);
    }

   /*
    * Helper method for building full name
    */
    private Optional<String> buildFullName(String firstName, String lastName) {
        String first = (firstName != null && !firstName.trim().isEmpty()) ? firstName.trim() : null;
        String last = (lastName != null && !lastName.trim().isEmpty()) ? lastName.trim() : null;

        if (first != null && last != null) {
            return Optional.of(first + " " + last);
        } else if (first != null) {
            return Optional.of(first);
        } else if (last != null) {
            return Optional.of(last);
        } else {
            return Optional.empty();
        }
    }
}
