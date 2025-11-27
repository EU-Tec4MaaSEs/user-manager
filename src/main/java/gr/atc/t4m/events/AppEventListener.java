package gr.atc.t4m.events;


import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Handles application events
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AppEventListener {

    private final IUserManagementService userManagementService;

    private static final String DEFAULT_ORGANIZATION = "DEFAULT";

    @EventListener
    @Async(value = "taskExecutor")
    public void handleUnassignmentOfPilotFromUsers(OrganizationDeletionEvent appEvent) {
        String pilot = appEvent.getPilotName();

        List<UserDto> pilotUsers = userManagementService.retrieveUsersByPilotCode(pilot);
        if (pilotUsers.isEmpty()) {
            log.debug("No users found for pilot: {}", pilot);
            return;
        }

        // Unassign the pilot from all users with defined pilot code
        pilotUsers.stream()
                .forEach(user -> {
                    user.setPilotCode(DEFAULT_ORGANIZATION);
                    user.setOrganizationId(DEFAULT_ORGANIZATION);
                    userManagementService.updateUser(user);
                    log.debug("Unassigned pilot {} from user {} with ID: {}", pilot, user.getUsername(), user.getUserId());
                });
    }

    @EventListener
    @Async(value = "taskExecutor")
    public void handleModificationOfPilotFromUsers(OrganizationNameUpdateEvent appEvent) {
        String pilotName = appEvent.getPilotName();

        // User Groups have already been updated and thus the retrieval works with the new name
        List<UserDto> pilotUsers = userManagementService.retrieveUsersByPilotCode(pilotName);
        if (pilotUsers.isEmpty()) {
            log.debug("No users found for updated pilot: {}", pilotName);
            return;
        }

        // Modify Pilot name for all Users
        pilotUsers.stream()
                .forEach(user -> {
                    user.setPilotCode(pilotName);
                    userManagementService.updateUser(user);
                    log.debug("Modified Pilot Code '{}' for user '{}' with ID: '{}'", pilotName, user.getUsername(), user.getUserId());
                });
    }
}
