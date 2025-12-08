package gr.atc.t4m.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.util.Arrays;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CacheService")
class CacheServiceTests {

    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache usersCache;

    @InjectMocks
    private CacheService cacheService;

    @BeforeEach
    void setUp() {
        lenient().when(cacheManager.getCache(CacheService.USERS_CACHE)).thenReturn(usersCache);
    }

    @Nested
    @DisplayName("Single Key Eviction")
    class SingleKeyEviction {

        @Test
        @DisplayName("Evict : Success")
        void givenValidCacheAndKey_whenEvictIfPresent_thenSuccess() {
            // Given
            String userId = "user-123";
            when(usersCache.evictIfPresent(userId)).thenReturn(true);

            // When
            boolean result = cacheService.evictIfPresent(CacheService.USERS_CACHE, userId);

            // Then
            assertThat(result).isTrue();
            verify(usersCache).evictIfPresent(userId);
        }

        @Test
        @DisplayName("Evict : Cache Not Found")
        void givenInvalidCache_whenEvictIfPresent_thenReturnFalse() {
            // Given
            when(cacheManager.getCache("invalid-cache")).thenReturn(null);

            // When
            boolean result = cacheService.evictIfPresent("invalid-cache", "key");

            // Then
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("Multiple Keys Eviction")
    class MultipleKeysEviction {

        @Test
        @DisplayName("Evict Multiple : Success")
        void givenValidKeys_whenEvictMultiple_thenSuccess() {
            // Given
            Collection<String> keys = Arrays.asList("key1", "key2", "key3");
            when(usersCache.evictIfPresent(anyString())).thenReturn(true);

            // When
            cacheService.evictMultiple(CacheService.USERS_CACHE, keys);

            // Then
            verify(usersCache, times(3)).evictIfPresent(anyString());
        }

        @Test
        @DisplayName("Evict Multiple : Cache Not Found")
        void givenInvalidCache_whenEvictMultiple_thenReturnFalse() {
            // Given
            when(cacheManager.getCache("invalid-cache")).thenReturn(null);
            Collection<String> keys = Arrays.asList("key1", "key2");

            // When
            cacheService.evictMultiple("invalid-cache", keys);

            // Then
            verify(usersCache, never()).evictIfPresent(any());
        }
    }

    @Nested
    @DisplayName("User Cache Eviction")
    class UserCacheEviction {

        @Test
        @DisplayName("Evict User Caches : Success")
        void givenUserAttributes_whenEvictUserCaches_thenEvictsAll() {
            // Given
            String userId = "user-123";
            String pilotCode = "PILOT-A";
            String userRole = "USER";
            String pilotRole = "ADMIN";
            when(usersCache.evictIfPresent(any())).thenReturn(true);

            // When
            cacheService.evictUserCaches(userId, pilotCode, userRole, pilotRole);

            // Then
            verify(usersCache).evictIfPresent(userId);
            verify(usersCache).evictIfPresent(pilotCode);
            verify(usersCache).evictIfPresent(userRole);
            verify(usersCache).evictIfPresent(pilotCode + "::" + userRole);
            verify(usersCache).evictIfPresent(CacheService.ALL_USERS_KEY);
        }
    }

    @Nested
    @DisplayName("Legacy User Cache Eviction")
    class LegacyUserCacheEviction {

        @Test
        @DisplayName("Evict Legacy Caches : Pilot Code Changed")
        void givenPilotCodeChanged_whenEvictLegacyCaches_thenEvictsOldPilot() {
            // Given
            String userId = "user-123";
            String oldPilotCode = "PILOT-A";
            String newPilotCode = "PILOT-B";
            when(usersCache.evictIfPresent(any())).thenReturn(true);

            // When
            cacheService.evictLegacyUserCaches(userId, oldPilotCode, "USER", "ADMIN",
                                               newPilotCode, "USER", "ADMIN");

            // Then
            verify(usersCache).evictIfPresent(oldPilotCode);
        }

        @Test
        @DisplayName("Evict Legacy Caches : No Changes")
        void givenNoChanges_whenEvictLegacyCaches_thenNoEviction() {
            // Given
            String userId = "user-123";
            String pilotCode = "PILOT-A";
            String userRole = "USER";
            String pilotRole = "ADMIN";

            // When
            cacheService.evictLegacyUserCaches(userId, pilotCode, userRole, pilotRole,
                                               pilotCode, userRole, pilotRole);

            // Then
            verify(usersCache, never()).evictIfPresent(any());
        }
    }

    @Nested
    @DisplayName("Cache Clearing")
    class CacheClearing {

        @Test
        @DisplayName("Clear Cache : Success")
        void givenValidCache_whenClearCache_thenClears() {
            // Given
            doNothing().when(usersCache).clear();

            // When
            cacheService.clearCache(CacheService.USERS_CACHE);

            // Then
            verify(usersCache).clear();
        }

        @Test
        @DisplayName("Clear All Caches : Success")
        void whenClearAllCaches_thenClearsAll() {
            // Given
            when(cacheManager.getCacheNames()).thenReturn(Arrays.asList("cache1", "cache2"));
            Cache cache1 = mock(Cache.class);
            Cache cache2 = mock(Cache.class);
            when(cacheManager.getCache("cache1")).thenReturn(cache1);
            when(cacheManager.getCache("cache2")).thenReturn(cache2);

            // When
            cacheService.clearAllCaches();

            // Then
            verify(cache1).clear();
            verify(cache2).clear();
        }
    }

    @Nested
    @DisplayName("Utility Methods")
    class UtilityMethods {

        @Test
        @DisplayName("Build Combined Key : Multiple Parts")
        void givenMultipleParts_whenBuildCombinedKey_thenCombinesWithSeparator() {
            // Given
            String part1 = "PILOT-A";
            String part2 = "USER";

            // When
            String result = cacheService.buildCombinedKey(part1, part2);

            // Then
            assertThat(result).isEqualTo("PILOT-A::USER");
        }

        @Test
        @DisplayName("Build Combined Key : Single Part")
        void givenSinglePart_whenBuildCombinedKey_thenReturnsSingle() {
            // Given
            String part = "PILOT-A";

            // When
            String result = cacheService.buildCombinedKey(part);

            // Then
            assertThat(result).isEqualTo("PILOT-A");
        }
    }
}
