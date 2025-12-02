package gr.atc.t4m.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.config.SecurityConfig;
import gr.atc.t4m.security.filters.RateLimitingFilter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityTests {

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    @InjectMocks
    private SecurityConfig securityConfig;

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private UnauthorizedEntryPoint unauthorizedEntryPoint;

    @DisplayName("Test corsConfigurationSource with multiple domains: Success")
    @Test
    void givenMultipleDomain_whenSetCorsConfigurationSource_thenSuccess() {
        // Given
        String corsDomainsRaw = "http://localhost:3000,http://localhost:3001";
        ReflectionTestUtils.setField(securityConfig, "corsDomainsRaw", corsDomainsRaw);

        // When
        CorsConfigurationSource corsConfigurationSource = securityConfig.corsConfigurationSource();
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setRequestURI("/api/users/authenticate");
        CorsConfiguration corsConfiguration = corsConfigurationSource.getCorsConfiguration(mockRequest);

        // Then
        assertNotNull(corsConfiguration);
        assertEquals(2, Objects.requireNonNull(corsConfiguration.getAllowedOrigins()).size());
        assertTrue(corsConfiguration.getAllowedOrigins().contains("http://localhost:3000"));
        assertTrue(corsConfiguration.getAllowedOrigins().contains("http://localhost:3001"));
        assertEquals(6, Objects.requireNonNull(corsConfiguration.getAllowedMethods()).size());
        assertTrue(corsConfiguration.getAllowedMethods().containsAll(
                Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")));
        assertEquals(1, Objects.requireNonNull(corsConfiguration.getAllowedHeaders()).size());
        assertEquals("*", corsConfiguration.getAllowedHeaders().getFirst());
        assertEquals(86400L, corsConfiguration.getMaxAge());
    }

    @DisplayName("Test corsConfigurationSource with single domain: Success")
    @Test
    void givenSingleDomain_whenSetCorsConfigurationSource_thenSuccess() {
        // Given
        String corsDomainsRaw = "http://localhost:3000";
        ReflectionTestUtils.setField(securityConfig, "corsDomainsRaw", corsDomainsRaw);

        // When
        CorsConfigurationSource corsConfigurationSource = securityConfig.corsConfigurationSource();
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setRequestURI("/api/users/authenticate");
        CorsConfiguration corsConfiguration = corsConfigurationSource.getCorsConfiguration(mockRequest);


        // Then
        assertNotNull(corsConfiguration);
        assertEquals(1, Objects.requireNonNull(corsConfiguration.getAllowedOrigins()).size());
        assertTrue(corsConfiguration.getAllowedOrigins().contains("http://localhost:3000"));
    }

    @DisplayName("Test defaultSecurityFilterChain configuration")
    @Test
    void defaultSecurityFilterChainConfiguration() throws Exception {
        // Set up the mock chain for HttpSecurity
        setupHttpSecurityMocks();

        // Given
        String corsDomainsRaw = "http://localhost:3000";
        ReflectionTestUtils.setField(securityConfig, "corsDomainsRaw", corsDomainsRaw);

        // When
        SecurityFilterChain result = securityConfig.defaultSecurityFilterChain(httpSecurity, unauthorizedEntryPoint);

        // Then - verify all required configurations were called
        verify(httpSecurity).sessionManagement(any());
        verify(httpSecurity).cors(any());
        verify(httpSecurity).csrf(any());
        verify(httpSecurity).exceptionHandling(any());
        verify(httpSecurity).authorizeHttpRequests(any());
        verify(httpSecurity).oauth2ResourceServer(any());
        verify(httpSecurity).build();

        assertNotNull(result);
    }

    /**
     * Helper method to set up all the mocks for HttpSecurity
     */
    private void setupHttpSecurityMocks() throws Exception {
        // Session management
        when(httpSecurity.sessionManagement(any())).thenReturn(httpSecurity);

        // CORS
        when(httpSecurity.cors(any())).thenReturn(httpSecurity);

        // CSRF
        when(httpSecurity.csrf(any())).thenReturn(httpSecurity);

        // Filter
        when(httpSecurity.addFilterBefore(any(), any())).thenReturn(httpSecurity);

        // Exception handling
        when(httpSecurity.exceptionHandling(any())).thenReturn(httpSecurity);

        // Authorize requests
        when(httpSecurity.authorizeHttpRequests(any())).thenReturn(httpSecurity);

        // OAuth2
        when(httpSecurity.oauth2ResourceServer(any())).thenReturn(httpSecurity);

        // Final build
        when(httpSecurity.build()).thenReturn(mock(DefaultSecurityFilterChain.class));
    }

    @DisplayName("RateLimiting Filter: Test filter allows requests under limit")
    @Test
    void givenAcceptableRequest_whenRateLimitingFilter_thenSuccess() throws ServletException, IOException {
        // Given
        RateLimitingFilter filter = new RateLimitingFilter(objectMapper);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // When
        filter.doFilter(request, response, filterChain);

        // Then
        assertEquals(200, response.getStatus());
    }

    @DisplayName("RateLimiting Filter: Test filter blocks requests over limit")
    @Test
    void givenTooManyRequests_whenRateLimitingFilter_thenError() throws ServletException, IOException {
        // Given - Anonymous user (no authentication) with IP-based rate limiting
        RateLimitingFilter filter = new RateLimitingFilter(objectMapper);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.2");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        // When - Make more requests than anonymous limit (100 requests)
        int requestCount = 120;
        for (int i = 0; i < requestCount; i++) {
            filter.doFilter(request, response, filterChain);
            if (response.getStatus() == 429) {
                // If we hit the rate limit, stop sending requests
                break;
            }
            // Reset response
            response = new MockHttpServletResponse();
            filterChain = new MockFilterChain();
        }

        // Then - Should be rate limited
        assertEquals(429, response.getStatus());
    }
}
