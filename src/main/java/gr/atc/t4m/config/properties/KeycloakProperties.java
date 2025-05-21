package gr.atc.t4m.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keycloak")
public record KeycloakProperties (
        String url,
        String realm,
        String clientId,
        String clientSecret,
        String adminUsername,
        String adminPassword,
        String tokenUri,
        String excludedSuperAdminRoles, // Excluded Realm Roles for Super Admins - Removes Defaults
        String excludedDefaultRoles, // Excluded Realm Roles for Admins - Removes Defaults + SUPER_ADMIN
        Boolean initClientId
){}
