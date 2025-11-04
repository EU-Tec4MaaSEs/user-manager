package gr.atc.t4m.context;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import gr.atc.t4m.util.JwtUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

/**
 * Request-scoped bean that holds JWT context and provides cached access to user data
 * <p>
 * This bean is created once per HTTP request and destroyed after the response is sent
 * It caches JWT claims and user data to avoid repeated parsing and Keycloak API calls
 */
@Component
@RequestScope
@Slf4j
public class JwtContext {

    @Getter
    private final Jwt jwt;

    private final IUserManagementService userManagementService;

    private String userId;
    private String pilotRole;
    private String pilotCode;
    private String userRole;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private String organizationId;
    private UserDto cachedUser;

    /**
     * Constructor with nullable JWT to handle unauthenticated requests
     */
    public JwtContext(@Nullable IUserManagementService userManagementService) {
        this.userManagementService = userManagementService;

        // Extract JWT from Security Context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            this.jwt = (Jwt) authentication.getPrincipal();
            log.debug("JwtContext created for authenticated request, userId: {}", getUserId());
        } else {
            this.jwt = null;
            log.debug("JwtContext created for unauthenticated request");
        }
    }

    /**
     * Check if request is authenticated
     */
    public boolean isAuthenticated() {
        return jwt != null;
    }

    // ========== Lazy-loaded JWT Claims ==========

    /**
     * Get user ID from JWT (lazy-loaded and cached)
     */
    public String getUserId() {
        if (userId == null && jwt != null) {
            userId = JwtUtils.extractUserId(jwt);
        }
        return userId;
    }

    /**
     * Get pilot role from JWT (SUPER_ADMIN, ADMIN, USER)
     */
    public String getPilotRole() {
        if (pilotRole == null && jwt != null) {
            pilotRole = JwtUtils.extractPilotRole(jwt);
        }
        return pilotRole;
    }

    /**
     * Get pilot code from JWT (organization identifier)
     */
    public String getPilotCode() {
        if (pilotCode == null && jwt != null) {
            pilotCode = JwtUtils.extractPilotCode(jwt);
        }
        return pilotCode;
    }

    /**
     * Get user role from JWT (application-specific role)
     */
    public String getUserRole() {
        if (userRole == null && jwt != null) {
            userRole = JwtUtils.extractUserRole(jwt);
        }
        return userRole;
    }

    /**
     * Get email from JWT
     */
    public String getEmail() {
        if (email == null && jwt != null) {
            email = JwtUtils.extractUserEmail(jwt);
        }
        return email;
    }

    /**
     * Get username from JWT
     */
    public String getUsername() {
        if (username == null && jwt != null) {
            username = JwtUtils.extractUsername(jwt);
        }
        return username;
    }

    /**
     * Get first name from JWT
     */
    public String getFirstName() {
        if (firstName == null && jwt != null) {
            firstName = JwtUtils.extractUserFirstName(jwt);
        }
        return firstName;
    }

    /**
     * Get last name from JWT
     */
    public String getLastName() {
        if (lastName == null && jwt != null) {
            lastName = JwtUtils.extractUserLastName(jwt);
        }
        return lastName;
    }

    /**
     * Get organization ID from JWT
     */
    public String getOrganizationId() {
        if (organizationId == null && jwt != null) {
            organizationId = JwtUtils.extractOrganizationIdOfUser(jwt);
        }
        return organizationId;
    }

    // ========== User Data (fetched from Keycloak) ==========

    /**
     * Get current user details from Keycloak
     *
     * This method fetches user data from Keycloak ONCE per request and caches it.
     * Subsequent calls return the cached value.
     *
     * @return UserDto with complete user information, or null if unauthenticated
     */
    public UserDto getCurrentUser() {
        if (cachedUser == null && getUserId() != null) {
            log.debug("Fetching user data from Keycloak for userId: {}", getUserId());
            cachedUser = userManagementService.retrieveUserById(getUserId());
        }
        return cachedUser;
    }

    // ========== Helper Methods ==========

    /**
     * Check if current user is a Super Admin
     */
    public boolean isSuperAdmin() {
        return "SUPER_ADMIN".equalsIgnoreCase(getPilotRole());
    }

    /**
     * Check if current user is an Admin (not Super Admin)
     */
    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(getPilotRole());
    }

    /**
     * Check if current user is a regular User
     */
    public boolean isUser() {
        return "USER".equalsIgnoreCase(getPilotRole());
    }

    /**
     * Check if current user has admin privileges (SUPER_ADMIN or ADMIN)
     */
    public boolean hasAdminPrivileges() {
        return isSuperAdmin() || isAdmin();
    }

    /**
     * Check if current user has global access (pilot code = ALL)
     */
    public boolean hasGlobalAccess() {
        return "ALL".equalsIgnoreCase(getPilotCode());
    }

    /**
     * Check if current user belongs to a specific pilot/organization
     *
     * @param pilotCode Pilot Code
     * @return True on success, False on error
     */
    public boolean belongsToPilot(String pilotCode) {
        String userPilotCode = getPilotCode();
        return userPilotCode != null && userPilotCode.equalsIgnoreCase(pilotCode);
    }

    /**
     * Check if current user can modify resources in a specific pilot
     * Super admins can modify any pilot, regular admins can only modify their own
     *
     * @param pilotCode Pilot Code
     * @return True on success, False on error
     */
    public boolean canModifyPilot(String pilotCode) {
        if (isSuperAdmin() || hasGlobalAccess()) {
            return true;
        }
        return belongsToPilot(pilotCode);
    }
}
