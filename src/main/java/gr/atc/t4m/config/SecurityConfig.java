package gr.atc.t4m.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import gr.atc.t4m.security.*;
import gr.atc.t4m.security.filters.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

        @Value("${spring.security.cors.domains}")
        private String corsDomainsRaw;

        private final RateLimitingFilter rateLimitingFilter;

        private final JwtAttributesValidatorFilter jwtAttributesValidatorFilter;

        public SecurityConfig(RateLimitingFilter rateLimitingFilter, JwtAttributesValidatorFilter jwtAttributesValidatorFilter) {
                this.rateLimitingFilter = rateLimitingFilter;
                this.jwtAttributesValidatorFilter = jwtAttributesValidatorFilter;
        }

        /**
         * Initialize and Configure Security Filter Chain of HTTP connection
         *
         * @param http       HttpSecurity
         * @param entryPoint UnauthorizedEntryPoint -> To add proper API Response to the
         *                   authorized request
         * @return SecurityFilterChain
         */
        @Bean
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, UnauthorizedEntryPoint entryPoint)
                        throws Exception {
                // Convert Keycloak Roles with class to Spring Security Roles
                JwtAuthConverter jwtAuthConverter = new JwtAuthConverter();

                // Set Session to Stateless so not to keep any information about the JWT
                http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                // Configure CORS access
                                .cors(corsCustomizer -> corsCustomizer.configurationSource(corsConfigurationSource()))
                                // Configure CSRF Token
                                .csrf(AbstractHttpConfigurer::disable)
                                // Rate Limit Filter
                                .addFilterBefore(rateLimitingFilter, BasicAuthenticationFilter.class)
                                .exceptionHandling(exc -> exc.authenticationEntryPoint(entryPoint))
                                // HTTP Requests authorization properties on URLs
                                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                                                .requestMatchers("/api/users/authenticate",
                                                "/api/users/refresh-token",
                                                "/api/users/activate",
                                                "/api/users/reset-password",
                                                "/api/users/forgot-password",
                                                "/api/user-manager/**")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                // JWT Authentication Configuration to use with Keycloak
                                .oauth2ResourceServer(oauth2ResourceServerCustomizer -> oauth2ResourceServerCustomizer
                                        .jwt(jwtCustomizer -> jwtCustomizer.jwtAuthenticationConverter(jwtAuthConverter)));

                // Validate proper JWT Attributes
                http.addFilterAfter(jwtAttributesValidatorFilter, BearerTokenAuthenticationFilter.class);
                return http.build();
        }

        /**
         * Settings for CORS
         *
         * @return CorsConfigurationSource
         */
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                // Split the string into a list of domains
                List<String> corsDomains = List.of(corsDomainsRaw.split(","));

                // Set CORS configuration
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(corsDomains);
                configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH","OPTIONS"));
                configuration.setAllowedHeaders(List.of("*"));
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(86400L);
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }
}
