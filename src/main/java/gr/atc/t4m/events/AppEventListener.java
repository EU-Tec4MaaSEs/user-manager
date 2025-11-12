package gr.atc.t4m.events;


import java.util.List;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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

        List<UserDto> pilotUsers = userManagementService.retrieveAllUsers();
        if (pilotUsers.isEmpty()) {
            log.debug("No users found for pilot: {}", pilot);
            return;
        }

        // Unassign the pilot from all users with defined pilot code
        pilotUsers.stream()
                .filter(user -> pilot.equalsIgnoreCase(user.getPilotCode()))
                .forEach(user -> {
                    user.setPilotCode(DEFAULT_ORGANIZATION);
                    user.setOrganizationId(DEFAULT_ORGANIZATION);
                    userManagementService.updateUser(user);
                    log.debug("Unassigned pilot {} from user {} with ID: {}", pilot, user.getUsername(), user.getUserId());
                });
    }
}
