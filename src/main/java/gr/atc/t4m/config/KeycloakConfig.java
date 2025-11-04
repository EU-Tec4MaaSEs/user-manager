package gr.atc.t4m.config;

import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import gr.atc.t4m.config.properties.KeycloakProperties;

import java.util.concurrent.TimeUnit;

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
        ResteasyClient resteasyClient = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder())
                // Connection pool settings
                .connectionPoolSize(50)                             // Total connections across all hosts
                .maxPooledPerRoute(10)                              // Max connections per route/host
                .connectionCheckoutTimeout(10, TimeUnit.SECONDS)    // Timeout configurations
                .connectionTTL(5, TimeUnit.MINUTES)                 // Max connection lifetime
                .build();

        log.debug("Initializing Keycloak Admin Client with modern RESTEasy connection pool: maxTotal=50, maxPerRoute=10");

        return KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.url())
                .realm("master")
                .clientId("admin-cli")
                .username(keycloakProperties.adminUsername())
                .password(keycloakProperties.adminPassword())
                .grantType(OAuth2Constants.PASSWORD)
                .resteasyClient(resteasyClient)
                .build();
    }
}
