package gr.atc.t4m.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.benmanes.caffeine.cache.Cache;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitingFilterTests {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @Mock
    private Jwt jwt;

    private ObjectMapper objectMapper;
    private RateLimitingFilter rateLimitingFilter;
    private StringWriter responseWriter;

    private static final String TEST_USER_ID = "test-user-123";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        rateLimitingFilter = new RateLimitingFilter(objectMapper);
        responseWriter = new StringWriter();

        SecurityContextHolder.setContext(securityContext);
    }

    @DisplayName("Authenticated User : Allow Requests Within Limit")
    @Test
    void givenAuthenticatedUser_whenRequestsWithinLimit_thenAllow() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);
        when(jwt.getSubject()).thenReturn(TEST_USER_ID);

        // When
        for (int i = 0; i < 100; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(100)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Authenticated User : Block Requests Exceeding Limit")
    @Test
    void givenAuthenticatedUser_whenRequestsExceedLimit_thenBlock() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);
        when(jwt.getSubject()).thenReturn(TEST_USER_ID);
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // When
        for (int i = 0; i < 501; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(500)).doFilter(request, response);
        verify(response, atLeastOnce()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Authenticated User : Per-User Rate Limiting")
    @Test
    void givenMultipleUsers_whenEachMakesRequests_thenSeparateLimits() throws Exception {
        // Given
        String userId1 = "user-1";
        String userId2 = "user-2";
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        // When - User 1 makes 500 requests
        when(jwt.getSubject()).thenReturn(userId1);
        for (int i = 0; i < 500; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // When - User 2 makes 100 requests
        when(jwt.getSubject()).thenReturn(userId2);
        for (int i = 0; i < 100; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(600)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Authenticated User : Error Response When Limit Exceeded")
    @Test
    void givenAuthenticatedUser_whenLimitExceeded_thenReturnError() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);
        when(jwt.getSubject()).thenReturn(TEST_USER_ID);
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // When
        for (int i = 0; i < 501; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        verify(response).setContentType("application/json");
        String responseBody = responseWriter.toString();
        assertThat(responseBody).contains("Too many requests");
        assertThat(responseBody).contains("Rate Limit Exceeded");
    }

    @DisplayName("Anonymous User : Allow Requests Within Limit")
    @Test
    void givenAnonymousUser_whenRequestsWithinLimit_thenAllow() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        lenient().when(request.getRemoteAddr()).thenReturn(TEST_IP_ADDRESS);

        // When
        for (int i = 0; i < 50; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(50)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Anonymous User : Block Requests Exceeding Limit")
    @Test
    void givenAnonymousUser_whenRequestsExceedLimit_thenBlock() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn(TEST_IP_ADDRESS);
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // When
        for (int i = 0; i < 101; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(100)).doFilter(request, response);
        verify(response, atLeastOnce()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Anonymous User : Per-IP Rate Limiting")
    @Test
    void givenMultipleIPs_whenEachMakesRequests_thenSeparateLimits() throws Exception {
        // Given
        String ip1 = "192.168.1.1";
        String ip2 = "192.168.1.2";
        when(securityContext.getAuthentication()).thenReturn(null);

        // When - IP1 makes 100 requests
        when(request.getRemoteAddr()).thenReturn(ip1);
        for (int i = 0; i < 100; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // When - IP2 makes 50 requests
        when(request.getRemoteAddr()).thenReturn(ip2);
        for (int i = 0; i < 50; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(150)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Anonymous User : X-Forwarded-For Header")
    @Test
    void givenXForwardedForHeader_whenRequestsExceedLimit_thenBlock() throws Exception {
        // Given
        String realClientIp = "203.0.113.1";
        String xForwardedFor = realClientIp + ", 10.0.0.1, 10.0.0.2";
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getHeader("X-Forwarded-For")).thenReturn(xForwardedFor);
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // When
        for (int i = 0; i < 101; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(100)).doFilter(request, response);
        verify(response, atLeastOnce()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Anonymous User : Empty X-Forwarded-For Uses Remote Address")
    @Test
    void givenEmptyXForwardedFor_whenRequests_thenUseRemoteAddress() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getHeader("X-Forwarded-For")).thenReturn("");
        when(request.getRemoteAddr()).thenReturn(TEST_IP_ADDRESS);

        // When
        for (int i = 0; i < 50; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(50)).doFilter(request, response);
        verify(request, atLeast(50)).getRemoteAddr();
    }

    @DisplayName("Rate Limits : Authenticated Higher Than Anonymous")
    @Test
    void givenAuthenticatedVsAnonymous_whenSameRequests_thenAuthenticatedAllowed() throws Exception {
        // Given - Authenticated user
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);
        when(jwt.getSubject()).thenReturn("auth-user");

        // When - Make 200 authenticated requests
        for (int i = 0; i < 200; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(200)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());

        // Given - Anonymous user with new filter
        reset(filterChain, response, securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.50");
        lenient().when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
        RateLimitingFilter newFilter = new RateLimitingFilter(objectMapper);

        // When - Try 200 anonymous requests
        for (int i = 0; i < 200; i++) {
            newFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        verify(filterChain, times(100)).doFilter(request, response);
        verify(response, atLeast(1)).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @DisplayName("Bucket Cache : Reuse Bucket For Same User")
    @Test
    void givenSameUser_whenMultipleRequests_thenReuseBucket() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);
        when(jwt.getSubject()).thenReturn("same-user");

        // When
        for (int i = 0; i < 10; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache).isNotNull();
        assertThat(bucketCache.asMap()).hasSize(1);
        assertThat(bucketCache.asMap()).containsKey("user:same-user");
    }

    @DisplayName("Bucket Cache : Separate Buckets For Different Users")
    @Test
    void givenDifferentUsers_whenRequests_thenSeparateBuckets() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(jwt);

        // When
        when(jwt.getSubject()).thenReturn("user-1");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        when(jwt.getSubject()).thenReturn("user-2");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        when(jwt.getSubject()).thenReturn("user-3");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        // Then
        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache).isNotNull();
        assertThat(bucketCache.asMap()).hasSize(3);
        assertThat(bucketCache.asMap().keySet()).containsExactlyInAnyOrder(
                "user:user-1", "user:user-2", "user:user-3");
    }

    @DisplayName("Bucket Cache : Separate Buckets For Different IPs")
    @Test
    void givenDifferentIPs_whenRequests_thenSeparateBuckets() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        when(request.getRemoteAddr()).thenReturn("10.0.0.2");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        when(request.getRemoteAddr()).thenReturn("10.0.0.3");
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        // Then
        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache).isNotNull();
        assertThat(bucketCache.asMap()).hasSize(3);
        assertThat(bucketCache.asMap().keySet()).containsExactlyInAnyOrder(
                "ip:10.0.0.1", "ip:10.0.0.2", "ip:10.0.0.3");
    }

    @DisplayName("Edge Case : Null Authentication")
    @Test
    void givenNullAuthentication_whenRequest_thenUseIPRateLimit() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");

        // When
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(filterChain).doFilter(request, response);

        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache.asMap().keySet()).contains("ip:192.168.1.1");
    }

    @DisplayName("Edge Case : Non-JWT Principal")
    @Test
    void givenNonJwtPrincipal_whenRequest_thenUseIPRateLimit() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn("string-principal");
        when(request.getRemoteAddr()).thenReturn("192.168.1.2");

        // When
        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(filterChain).doFilter(request, response);

        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache.asMap().keySet()).contains("ip:192.168.1.2");
    }

    @DisplayName("Edge Case : X-Forwarded-For With Whitespace")
    @Test
    void givenXForwardedForWithWhitespace_whenRequest_thenTrimCorrectly() throws Exception {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getHeader("X-Forwarded-For")).thenReturn("  203.0.113.5  , 10.0.0.1 , 10.0.0.2  ");

        // When
        for (int i = 0; i < 50; i++) {
            rateLimitingFilter.doFilterInternal(request, response, filterChain);
        }

        // Then
        @SuppressWarnings("unchecked")
        Cache<String, Bucket> bucketCache = (Cache<String, Bucket>)
                ReflectionTestUtils.getField(rateLimitingFilter, "bucketCache");

        assertThat(bucketCache.asMap().keySet()).contains("ip:203.0.113.5");
    }
}
