package gr.atc.t4m.config;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import gr.atc.t4m.config.properties.KeycloakProperties;

@Configuration
public class KeycloakConfig {

    private final KeycloakProperties keycloakProperties;

    public KeycloakConfig(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

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
