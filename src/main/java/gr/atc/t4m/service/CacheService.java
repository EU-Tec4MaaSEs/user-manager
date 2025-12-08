package gr.atc.t4m.service;

import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Objects;

/**
 * Centralized cache management service for cache operation
 */
@Service
@Slf4j
public class CacheService {

    private final CacheManager cacheManager;

    // Cache name constants
    public static final String USERS_CACHE = "users";
    public static final String ALL_USERS_KEY = "all-users";

    public CacheService(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * Evicts a single cache entry if present.
     *
     * @param cacheName the name of the cache
     * @param key the cache key to evict
     * @return true if the entry was evicted, false if not found
     */
    @Observed(name = "cache.evict.single", contextualName = "evicting-single-cache-entry")
    public boolean evictIfPresent(String cacheName, Object key) {
        Cache cache = getCache(cacheName);
        if (cache == null) {
            log.warn("Cache '{}' not found, skipping eviction for key: {}", cacheName, key);
            return false;
        }

        return cache.evictIfPresent(key);
    }

    /**
     * Evicts multiple cache entries by their keys asynchronously.
     *
     * @param cacheName the name of the cache
     * @param keys collection of keys to evict
     */
    @Async("taskExecutor")
    @Observed(name = "cache.evict.multiple", contextualName = "evicting-multiple-cache-entries")
    public void evictMultiple(String cacheName, Collection<?> keys) {
        Cache cache = getCache(cacheName);
        if (cache == null) {
            log.warn("Cache '{}' not found, skipping eviction for {} keys", cacheName, keys.size());
            return;
        }
        for (Object key : keys) {
            if (key != null)
                cache.evictIfPresent(key);
        }
    }

    /**
     * Clears all entries from a specific cache asynchronously.
     *
     * @param cacheName the name of the cache to clear
     */
    @Async("taskExecutor")
    @Observed(name = "cache.clear", contextualName = "clearing-cache")
    public void clearCache(String cacheName) {
        Cache cache = getCache(cacheName);
        if (cache == null) {
            log.warn("Cache '{}' not found, skipping clear operation", cacheName);
            return;
        }

        cache.clear();
        log.debug("Cleared all entries from cache '{}'", cacheName);
    }

    /**
     * Evicts user-related caches when user data changes asynchronously.
     * Handles complex multi-key eviction patterns for user cache.
     *
     * @param userId the user ID
     * @param pilotCode the pilot code (can be null, should be normalized)
     * @param userRole the user role (can be null, should be normalized)
     * @param pilotRole the pilot role (can be null, should be normalized)
     */
    @Async("taskExecutor")
    @Observed(name = "cache.evict.user", contextualName = "evicting-user-caches")
    public void evictUserCaches(String userId, String pilotCode, String userRole, String pilotRole) {
        // Always evict user by ID
        evictIfPresent(USERS_CACHE, userId);

        // Always evict all-users aggregate
        evictIfPresent(USERS_CACHE, ALL_USERS_KEY);

        // Evict pilot code cache if provided
        if (pilotCode != null) {
            evictIfPresent(USERS_CACHE, pilotCode);
        }

        // Evict user role cache if provided
        if (userRole != null) {
            evictIfPresent(USERS_CACHE, userRole);
        }

        // Evict pilot role cache if provided
        if (pilotRole != null) {
            evictIfPresent(USERS_CACHE, pilotRole);
        }

        // Evict combined key if both are provided
        if (pilotCode != null && userRole != null) {
            String combinedKey = buildCombinedKey(pilotCode, userRole);
            evictIfPresent(USERS_CACHE, combinedKey);
        }
    }

    /**
     * Evicts legacy user cache entries when user attributes change asynchronously (Used commonly in Update Method)
     *
     * @param userId the user ID
     * @param oldPilotCode the previous pilot code (should be normalized)
     * @param oldUserRole the previous user role (should be normalized)
     * @param oldPilotRole the previous pilot role (should be normalized)
     * @param newPilotCode the new pilot code (optional, should be normalized)
     * @param newUserRole the new user role (optional, should be normalized)
     * @param newPilotRole the new pilot role (optional, should be normalized)
     */
    @Async("taskExecutor")
    @Observed(name = "cache.evict.legacy-user", contextualName = "evicting-legacy-user-caches")
    public void evictLegacyUserCaches(String userId, String oldPilotCode, String oldUserRole, String oldPilotRole,
                                      String newPilotCode, String newUserRole, String newPilotRole) {

        // Check if values actually changed
        boolean pilotCodeChanged = !Objects.equals(oldPilotCode, newPilotCode) && newPilotCode != null;
        boolean userRoleChanged = !Objects.equals(oldUserRole, newUserRole) && newUserRole != null;
        boolean pilotRoleChanged = !Objects.equals(oldPilotRole, newPilotRole) && newPilotRole != null;

        boolean anyChange = pilotCodeChanged || userRoleChanged || pilotRoleChanged;

        // Early return if nothing changed
        if (!anyChange) {
            return;
        }

        // Evict old pilot code cache if changed
        if (pilotCodeChanged && oldPilotCode != null) {
            evictIfPresent(USERS_CACHE, oldPilotCode);
            log.debug("Evicted cache for old pilot code: {}", oldPilotCode);
        }

        // Evict new pilot code cache if changed
        if (pilotCodeChanged && newPilotCode != null) {
            evictIfPresent(USERS_CACHE, newPilotCode);
            log.debug("Evicted cache for new pilot code: {}", newPilotCode);
        }

        // Evict old user role cache if changed
        if (userRoleChanged && oldUserRole != null) {
            evictIfPresent(USERS_CACHE, oldUserRole);
            log.debug("Evicting OLD user role cache: '{}'", oldUserRole);
        }

        // Evict new user role cache if changed
        if (userRoleChanged && newUserRole != null) {
            evictIfPresent(USERS_CACHE, newUserRole);
            log.debug("Evicting NEW user role cache: '{}'", newUserRole);

        }

        // Evict old pilot role cache if changed
        if (pilotRoleChanged && oldPilotRole != null) {
            evictIfPresent(USERS_CACHE, oldPilotRole);
            log.debug("Evicting OLD pilot role cache: '{}'", oldPilotRole);
        }

        // Evict new pilot role cache if changed
        if (pilotRoleChanged && newPilotRole != null) {
            evictIfPresent(USERS_CACHE, newPilotRole);
            log.debug("Evicting NEW pilot role cache: '{}'", newPilotRole);
        }

        // Evict old combined key (pilotCode::userRole) if either changed
        if ((pilotCodeChanged || userRoleChanged) && oldPilotCode != null && oldUserRole != null) {
            String combinedKey = buildCombinedKey(oldPilotCode, oldUserRole);
            evictIfPresent(USERS_CACHE, combinedKey);
            log.debug("Evicting OLD combined key cache: '{}'", combinedKey);
        }

        // Evict new combined key (pilotCode::userRole) if either changed
        if ((pilotCodeChanged || userRoleChanged) && newPilotCode != null && newUserRole != null) {
            String combinedKey = buildCombinedKey(newPilotCode, newUserRole);
            evictIfPresent(USERS_CACHE, combinedKey);
            log.debug("Evicting NEW combined key cache: '{}'", combinedKey);
        }

        // Evict user by ID when attributes change
        evictIfPresent(USERS_CACHE, userId);

        // Evict all-users aggregate when attributes change
        evictIfPresent(USERS_CACHE, ALL_USERS_KEY);
    }

    /**
     * Builds a combined cache key using consistent delimiter.
     *
     * @param parts the parts to combine
     * @return combined key string
     */
    public String buildCombinedKey(String... parts) {
        return String.join("::", parts);
    }


    /**
     * Retrieves a cache by name with null safety.
     *
     * @param cacheName the name of the cache
     * @return the Cache instance or null if not found
     */
    private Cache getCache(String cacheName) {
        return cacheManager.getCache(cacheName);
    }

    /**
     * Evicts all entries from all caches asynchronously
     */
    @Async("taskExecutor")
    @Observed(name = "cache.clear.all", contextualName = "clearing-all-caches")
    public void clearAllCaches() {
        cacheManager.getCacheNames().forEach(cacheName -> {
            Cache cache = cacheManager.getCache(cacheName);
            if (cache != null) {
                cache.clear();
            }
        });
        log.debug("Cleared all application caches");
    }
}
