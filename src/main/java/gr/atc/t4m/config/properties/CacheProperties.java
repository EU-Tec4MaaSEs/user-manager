package gr.atc.t4m.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cache")
public record CacheProperties(
        int pilotRolesCacheTtl,
        int pilotCodesCacheTtl,
        int userRolesCacheTtl,
        int usersCacheTtl,
        int maxSize
) { }
