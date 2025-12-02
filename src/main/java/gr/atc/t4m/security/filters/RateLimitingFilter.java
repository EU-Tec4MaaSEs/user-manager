package gr.atc.t4m.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import gr.atc.t4m.controller.BaseAppResponse;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Rate limiting filter with hybrid per-user/per-IP strategy
 * <p>
 * - Authenticated requests: Rate limited by user ID with higher limits
 * - Anonymous requests: Rate limited by IP address with lower limits
 * <p>
 * This approach prevents legitimate users from being blocked due to shared IPs while still protecting against anonymous abuse.
 */
@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {
    private final ObjectMapper objectMapper;

    // Cache of buckets per rate limit key (userId or IP)
    private final Cache<String, Bucket> bucketCache;

    // Rate limits for authenticated users (higher limits)
    private static final long AUTHENTICATED_CAPACITY = 500;
    private static final long AUTHENTICATED_REFILL = 100;

    // Rate limits for anonymous users (lower limits)
    private static final long ANONYMOUS_CAPACITY = 100;
    private static final long ANONYMOUS_REFILL = 20;

    public RateLimitingFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.bucketCache = Caffeine.newBuilder()
                .expireAfterAccess(10, TimeUnit.MINUTES)
                .maximumSize(10000)
                .build();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        // Determine rate limit key based on authentication status
        boolean isAuthenticated = isAuthenticated();
        String rateLimitKey = getRateLimitKey(request, isAuthenticated);
        log.debug("IP: {}", getClientIP(request));
        // Get or create bucket for this key
        Bucket bucket = bucketCache.get(rateLimitKey, key -> createBucket(isAuthenticated));

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for {}: {}", isAuthenticated ? "user" : "IP", rateLimitKey);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            BaseAppResponse<String> responseMessage = BaseAppResponse.error(
                    "Too many requests. Please try again later.",
                    "Rate Limit Exceeded");
            objectMapper.writeValue(response.getWriter(), responseMessage);
        }
    }

    /**
     * Check if the current request is authenticated
     */
    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getPrincipal() instanceof Jwt;
    }

    /**
     * Get the rate limit key based on authentication status
     * - Authenticated: user:userId
     * - Anonymous: ip:clientIP
     */
    private String getRateLimitKey(HttpServletRequest request, boolean isAuthenticated) {
        if (isAuthenticated) {
            String userId = extractUserId();
            return "user:" + userId;
        }
        return "ip:" + getClientIP(request);
    }

    /**
     * Extract user ID from JWT token in SecurityContext
     */
    private String extractUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        return "unknown";
    }

    /**
     * Extract client IP address from request
     * Handles X-Forwarded-For header for proxied requests
     */
    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Create a new bucket with appropriate limits based on authentication status
     */
    private Bucket createBucket(boolean isAuthenticated) {
        if (isAuthenticated) {
            return Bucket.builder()
                    .addLimit(limit -> limit.capacity(AUTHENTICATED_CAPACITY)
                            .refillGreedy(AUTHENTICATED_REFILL, Duration.ofMinutes(1)))
                    .build();
        } else {
            return Bucket.builder()
                    .addLimit(limit -> limit.capacity(ANONYMOUS_CAPACITY)
                            .refillGreedy(ANONYMOUS_REFILL, Duration.ofMinutes(1)))
                    .build();
        }
    }
}
