package gr.atc.t4m.config;

import gr.atc.t4m.service.interfaces.IKeycloakAdminService;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Cache warming component to preload frequently accessed data into cache on application startup
 */
@Component
@Slf4j
public class CacheWarmer {

    private final IKeycloakAdminService adminService;

    private final IUserManagementService userManagementService;

    public CacheWarmer(IKeycloakAdminService adminService, IUserManagementService userManagementService) {
        this.adminService = adminService;
        this.userManagementService = userManagementService;
    }

    /**
     * Warm up caches after application is fully started
     */
    @EventListener(ApplicationReadyEvent.class)
    @Async("taskExecutor")
    public void warmupCaches() {
        log.debug("Starting cache warmup...");

        try {
            // Warm up pilot codes cache
            adminService.retrieveAllPilotCodes().size();

            // Warm up pilot roles cache (for super admin)
            adminService.retrieveAllPilotRoles(true).size();

            // Warm up user roles cache (for super admin)
            adminService.retrieveAllUserRoles(true).size();

            // Warm up users
            userManagementService.retrieveAllUsers().size();

            log.debug("Caches warmed-up successfully!");
        } catch (Exception e) {
            log.warn("Cache warmup failed, but application will continue normally: {}", e.getMessage());
        }
    }
}
