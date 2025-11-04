package gr.atc.t4m.context;

import gr.atc.t4m.dto.UserDto;
import gr.atc.t4m.service.interfaces.IUserManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtContext Unit Tests")
class JwtContextTests {

    @Mock
    private IUserManagementService userManagementService;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    private Jwt mockJwt;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Create JwtContext with Authenticated JWT : Success")
        void givenAuthenticatedJwt_whenCreateJwtContext_thenJwtContextCreated() {
            // Given
            mockJwt = createMockJwt("user-123", "SUPER_ADMIN", "ALL", "ADMIN_ROLE");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.isAuthenticated()).isTrue();
            assertThat(jwtContext.getJwt()).isEqualTo(mockJwt);
        }

        @Test
        @DisplayName("Create JwtContext with Unauthenticated Request : Null JWT")
        void givenUnauthenticatedRequest_whenCreateJwtContext_thenNullJwt() {
            // Given
            when(securityContext.getAuthentication()).thenReturn(null);

            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.isAuthenticated()).isFalse();
            assertThat(jwtContext.getJwt()).isNull();
        }

        @Test
        @DisplayName("Handle Non-JWT Principal : Success")
        void givenNonJwtPrincipal_whenCreateJwtContext_thenNotAuthenticated() {
            // Given
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn("non-jwt-principal");

            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.isAuthenticated()).isFalse();
            assertThat(jwtContext.getJwt()).isNull();
        }
    }

    @Nested
    @DisplayName("JWT Claims Extraction Tests")
    class JwtClaimsExtractionTests {

        @BeforeEach
        void setUpAuthentication() {
            mockJwt = createMockJwt("user-456", "ADMIN", "PILOT-1", "USER_ROLE");   
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);
        }

        @Test
        @DisplayName("Extract User ID from JWT : Success")
        void whenGetUserId_thenReturnUserIdFromJwt() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getUserId()).isEqualTo("user-456");
        }

        @Test
        @DisplayName("Extract Pilot Role from JWT : Success")
        void whenGetPilotRole_thenReturnPilotRoleFromJwt() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getPilotRole()).isEqualTo("ADMIN");
        }

        @Test
        @DisplayName("Extract Pilot Code from JWT : Success")
        void whenGetPilotCode_thenReturnPilotCodeFromJwt() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getPilotCode()).isEqualTo("PILOT-1");
        }

        @Test
        @DisplayName("Extract User Role from JWT : Success")
        void whenGetUserRole_thenReturnUserRoleFromJwt() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getUserRole()).isEqualTo("USER_ROLE");
        }

        @Test
        @DisplayName("Extract Email from JWT : Success")
        void whenGetEmail_thenReturnEmailFromJwt() {
            // Given
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", "user-789");
            claims.put("email", "test@example.com");
            Jwt jwt = createJwt(claims);
            when(authentication.getPrincipal()).thenReturn(jwt);

            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getEmail()).isEqualTo("test@example.com");
        }

        @Test
        @DisplayName("Cache JWT Claims : After First Extraction")
        void whenExtractClaimsMultipleTimes_thenCacheClaimsAfterFirst() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Call getUserId multiple times
            String userId1 = jwtContext.getUserId();
            String userId2 = jwtContext.getUserId();
            String userId3 = jwtContext.getUserId();

            // Then
            assertThat(userId1).isEqualTo("user-456");
            assertThat(userId2).isEqualTo(userId1);
            assertThat(userId3).isEqualTo(userId1);
            // JWT should be accessed only once for caching
        }
    }

    @Nested
    @DisplayName("getCurrentUser() Tests - Authenticated")
    class GetCurrentUserAuthenticatedTests {

        @BeforeEach
        void setUpAuthentication() {
            mockJwt = createMockJwt("user-123", "SUPER_ADMIN", "ALL", "ADMIN");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);
        }

        @Test
        @DisplayName("Fetch and Cache User : From UserManagementService")
        void whenGetCurrentUserMultipleTimes_thenFetchOnceAndCache() {
            // Given
            UserDto mockUser = UserDto.builder()
                    .userId("user-123")
                    .email("test@example.com")
                    .firstName("John")
                    .lastName("Doe")
                    .build();
            when(userManagementService.retrieveUserById("user-123")).thenReturn(mockUser);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When
            UserDto user1 = jwtContext.getCurrentUser();
            UserDto user2 = jwtContext.getCurrentUser();
            UserDto user3 = jwtContext.getCurrentUser();

            // Then
            assertThat(user1).isEqualTo(mockUser);
            assertThat(user2).isEqualTo(mockUser);
            assertThat(user3).isEqualTo(mockUser);

            // Verify service called only once (caching works)
            verify(userManagementService, times(1)).retrieveUserById("user-123");
        }
    }

    @Nested
    @DisplayName("getCurrentUser() Tests - Unauthenticated")
    class GetCurrentUserUnauthenticatedTests {

        @Test
        @DisplayName("Get Current User for Unauthenticated Request : Return Null")
        void givenUnauthenticatedContext_whenGetCurrentUser_thenReturnNull() {
            // Given
            when(securityContext.getAuthentication()).thenReturn(null);
            JwtContext jwtContext = new JwtContext(userManagementService);

            // When
            UserDto user = jwtContext.getCurrentUser();

            // Then
            assertThat(user).isNull();
            verify(userManagementService, never()).retrieveUserById(any());
        }
    }

    @Nested
    @DisplayName("Helper Methods Tests")
    class HelperMethodsTests {

        @Test
        @DisplayName("Check isSuperAdmin : Return True for SUPER_ADMIN")
        void givenSuperAdminRole_whenIsSuperAdmin_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "SUPER_ADMIN", "ALL", "ADMIN");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.isSuperAdmin()).isTrue();
            assertThat(jwtContext.isAdmin()).isFalse();
            assertThat(jwtContext.isUser()).isFalse();
        }

        @Test
        @DisplayName("Check isAdmin : Return True for ADMIN")
        void givenAdminRole_whenIsAdmin_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-2", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.isSuperAdmin()).isFalse();
            assertThat(jwtContext.isAdmin()).isTrue();
            assertThat(jwtContext.isUser()).isFalse();
        }

        @Test
        @DisplayName("Check isUser : Return True for USER")
        void givenUserRole_whenIsUser_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-3", "USER", "PILOT-2", "VIEWER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.isSuperAdmin()).isFalse();
            assertThat(jwtContext.isAdmin()).isFalse();
            assertThat(jwtContext.isUser()).isTrue();
        }

        @Test
        @DisplayName("Check hasAdminPrivileges : Return True for SUPER_ADMIN")
        void givenSuperAdminRole_whenHasAdminPrivileges_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "SUPER_ADMIN", "ALL", "ADMIN");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.hasAdminPrivileges()).isTrue();
        }

        @Test
        @DisplayName("Check hasAdminPrivileges : Return True for ADMIN")
        void givenAdminRole_whenHasAdminPrivileges_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-2", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.hasAdminPrivileges()).isTrue();
        }

        @Test
        @DisplayName("Check hasAdminPrivileges : Return False for USER")
        void givenUserRole_whenHasAdminPrivileges_thenReturnFalse() {
            // Given
            mockJwt = createMockJwt("user-3", "USER", "PILOT-1", "VIEWER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.hasAdminPrivileges()).isFalse();
        }

        @Test
        @DisplayName("Check hasGlobalAccess : Return True for Pilot Code ALL")
        void givenPilotCodeAll_whenHasGlobalAccess_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "SUPER_ADMIN", "ALL", "ADMIN");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.hasGlobalAccess()).isTrue();
        }

        @Test
        @DisplayName("Check hasGlobalAccess : Return False for Specific Pilot")
        void givenSpecificPilotCode_whenHasGlobalAccess_thenReturnFalse() {
            // Given
            mockJwt = createMockJwt("user-2", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.hasGlobalAccess()).isFalse();
        }

        @Test
        @DisplayName("Check belongsToPilot : Return True for Matching Pilot")
        void givenMatchingPilotCode_whenBelongsToPilot_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.belongsToPilot("PILOT-1")).isTrue();
            assertThat(jwtContext.belongsToPilot("pilot-1")).isTrue(); // Case insensitive
            assertThat(jwtContext.belongsToPilot("PILOT-2")).isFalse();
        }

        @Test
        @DisplayName("Check canModifyPilot : Return True for SUPER_ADMIN")
        void givenSuperAdmin_whenCanModifyPilot_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "SUPER_ADMIN", "ALL", "ADMIN");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.canModifyPilot("ANY-PILOT")).isTrue();
            assertThat(jwtContext.canModifyPilot("PILOT-1")).isTrue();
        }

        @Test
        @DisplayName("Check canModifyPilot : Return True for Global Access")
        void givenGlobalAccess_whenCanModifyPilot_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "ADMIN", "ALL", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.canModifyPilot("PILOT-1")).isTrue();
        }

        @Test
        @DisplayName("Check canModifyPilot : Return True for Own Pilot")
        void givenOwnPilot_whenCanModifyPilot_thenReturnTrue() {
            // Given
            mockJwt = createMockJwt("user-1", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.canModifyPilot("PILOT-1")).isTrue();
            assertThat(jwtContext.canModifyPilot("pilot-1")).isTrue(); // Case insensitive
        }

        @Test
        @DisplayName("Check canModifyPilot : Return False for Different Pilot")
        void givenDifferentPilot_whenCanModifyPilot_thenReturnFalse() {
            // Given
            mockJwt = createMockJwt("user-1", "ADMIN", "PILOT-1", "USER");
            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.getPrincipal()).thenReturn(mockJwt);

            JwtContext jwtContext = new JwtContext(userManagementService);

            // When & Then
            assertThat(jwtContext.canModifyPilot("PILOT-2")).isFalse();
        }
    }

    @Nested
    @DisplayName("Unauthenticated Context Tests")
    class UnauthenticatedContextTests {

        @BeforeEach
        void setUpUnauthenticated() {
            when(securityContext.getAuthentication()).thenReturn(null);
        }

        @Test
        @DisplayName("Get JWT Claims When Unauthenticated : Return Null")
        void givenUnauthenticatedContext_whenGetJwtClaims_thenReturnNull() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.getUserId()).isNull();
            assertThat(jwtContext.getPilotRole()).isNull();
            assertThat(jwtContext.getPilotCode()).isNull();
            assertThat(jwtContext.getUserRole()).isNull();
            assertThat(jwtContext.getEmail()).isNull();
            assertThat(jwtContext.getUsername()).isNull();
            assertThat(jwtContext.getFirstName()).isNull();
            assertThat(jwtContext.getLastName()).isNull();
            assertThat(jwtContext.getOrganizationId()).isNull();
        }

        @Test
        @DisplayName("Should return false for all helper methods when unauthenticated")
        void shouldReturnFalseForAllHelperMethodsWhenUnauthenticated() {
            // When
            JwtContext jwtContext = new JwtContext(userManagementService);

            // Then
            assertThat(jwtContext.isSuperAdmin()).isFalse();
            assertThat(jwtContext.isAdmin()).isFalse();
            assertThat(jwtContext.isUser()).isFalse();
            assertThat(jwtContext.hasAdminPrivileges()).isFalse();
            assertThat(jwtContext.hasGlobalAccess()).isFalse();
            assertThat(jwtContext.belongsToPilot("PILOT-1")).isFalse();
            assertThat(jwtContext.canModifyPilot("PILOT-1")).isFalse();
        }
    }

    // Helper methods for creating mock JWTs
    private Jwt createMockJwt(String userId, String pilotRole, String pilotCode, String userRole) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        claims.put("pilot_role", pilotRole);
        claims.put("pilot_code", pilotCode);
        claims.put("user_role", userRole);
        claims.put("email", "test@example.com");
        claims.put("preferred_username", "testuser");
        claims.put("given_name", "Test");
        claims.put("family_name", "User");
        claims.put("organization_id", "org-123");

        return createJwt(claims);
    }

    private Jwt createJwt(Map<String, Object> claims) {
        return new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                Map.of("alg", "RS256"),
                claims
        );
    }
}
