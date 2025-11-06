package gr.atc.t4m.config;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import gr.atc.t4m.config.properties.KeycloakProperties;

/**
 * Keycloak Admin Client configuration with optimized connection pooling
 */
@Configuration
@Slf4j
public class KeycloakConfig {

    private final KeycloakProperties keycloakProperties;

    public KeycloakConfig(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Create Keycloak Admin Client with optimized connection pooling
     */
    @Bean
    public Keycloak keycloakAdminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.url())
                .realm("master")
                .clientId("admin-cli")
                .username(keycloakProperties.adminUsername())
                .password(keycloakProperties.adminPassword())
                .grantType(OAuth2Constants.PASSWORD)
                .build();
    }
}
