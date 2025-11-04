package gr.atc.t4m.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Configuration for RestClient
 */
@Configuration
@Slf4j
public class RestClientConfig {

    /**
     * Configure connection pooling for HTTP clients
     */
    @Bean
    public PoolingHttpClientConnectionManager connectionManager() {
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);                  // Maximum total connections across all routes
        connectionManager.setDefaultMaxPerRoute(20);         // Maximum connections per route

        // Connection configuration
        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(10))
                .setSocketTimeout(Timeout.ofSeconds(30))
                .setTimeToLive(Timeout.ofMinutes(5))
                .build();

        connectionManager.setDefaultConnectionConfig(connectionConfig);

        log.debug("HTTP Connection Pool initialized: maxTotal={}, maxPerRoute={}", 100, 20);
        return connectionManager;
    }

    /**
     * Configure HttpClient with connection pooling and timeouts
     */
    @Bean
    public CloseableHttpClient httpClient(PoolingHttpClientConnectionManager connectionManager) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                .setResponseTimeout(Timeout.ofSeconds(30))
                .build();

        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .evictIdleConnections(Timeout.ofSeconds(30))
                .build();
    }

    /**
     * RestClient bean for Keycloak authentication operations
     */
    @Bean
    public RestClient keycloakRestClient(CloseableHttpClient httpClient) {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

        return RestClient.builder()
                .requestFactory(factory)
                .build();
    }
}
