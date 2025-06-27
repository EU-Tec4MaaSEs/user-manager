package gr.atc.t4m.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import gr.atc.t4m.config.properties.CacheProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.support.CompositeCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
public class CacheConfig {

    private final CacheProperties cacheProperties;

    public CacheConfig(CacheProperties cacheProperties) {
        this.cacheProperties = cacheProperties;
    }

    @Bean
    @Primary
    public CacheManager cacheManager() {
        CompositeCacheManager compositeCacheManager = new CompositeCacheManager();

        List<CacheManager> cacheManagers = List.of(
                createCacheManager("pilotRoles", cacheProperties.pilotRolesCacheTtl()),
                createCacheManager("pilotCodes", cacheProperties.pilotCodesCacheTtl()),
                createCacheManager("userRoles", cacheProperties.userRolesCacheTtl()),
                createCacheManager("users", cacheProperties.usersCacheTtl())
        );

        compositeCacheManager.setCacheManagers(cacheManagers);
        compositeCacheManager.setFallbackToNoOpCache(false);

        return compositeCacheManager;
    }

    private CacheManager createCacheManager(String cacheName, int ttlSeconds) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(cacheName);
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .initialCapacity(cacheProperties.maxSize() / 4)
                .maximumSize(cacheProperties.maxSize())
                .expireAfterWrite(ttlSeconds, TimeUnit.SECONDS)
                .recordStats());
        return cacheManager;
    }
}
