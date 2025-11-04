package gr.atc.t4m.service;

import java.util.HashMap;
import java.util.Map;

import gr.atc.t4m.config.properties.KeycloakProperties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;

import static gr.atc.t4m.exception.CustomExceptions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserAuthService Tests - RestClient Implementation")
class UserAuthServiceTests {

    @Mock
    private RestClient restClient;

    @Mock
    private RestClient.RequestBodyUriSpec requestBodyUriSpec;

    @Mock
    private RestClient.RequestBodySpec requestBodySpec;

    @Mock
    private RestClient.ResponseSpec responseSpec;

    @Mock
    private KeycloakProperties keycloakProperties;

    @InjectMocks
    private UserAuthService userAuthService;

    private CredentialsDto credentials;

    private static final String MOCK_TOKEN = "mock-token";
    private static final String MOCK_EMAIL = "mockemail@test.com";
    private static final String MOCK_PASSWORD = "@Mock123@";
    private static final String MOCK_TOKEN_URI = "http://mock-token-uri";
    private static final String MOCK_CLIENT_ID = "mock-client";
    private static final String MOCK_CLIENT_SECRET = "client-secret";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    private static final String TOKEN = "access_token";

    @BeforeEach
    void initialSetup() {
        ReflectionTestUtils.setField(userAuthService, "tokenUri", MOCK_TOKEN_URI);
        ReflectionTestUtils.setField(userAuthService, "clientName", MOCK_CLIENT_ID);
        ReflectionTestUtils.setField(userAuthService, "clientSecret", MOCK_CLIENT_SECRET);
        ReflectionTestUtils.setField(userAuthService, "restClient", restClient);

        credentials = new CredentialsDto(MOCK_EMAIL, MOCK_PASSWORD);
    }

    @AfterEach
    void tearDown() {
        Mockito.reset(restClient, requestBodyUriSpec, requestBodySpec, responseSpec);
    }

    @DisplayName("Authenticate user: Success with credentials")
    @Test
    void givenCredentials_whenAuthenticate_thenReturnAuthenticationResponse() {
        // Given
        Map<String, Object> mockResponseBody = new HashMap<>();
        mockResponseBody.put(TOKEN, MOCK_TOKEN);
        mockResponseBody.put("expires_in", 1800);
        mockResponseBody.put("token_type", "JWT");
        mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, MOCK_TOKEN);
        mockResponseBody.put("refresh_expires_in", 1800);

        // Mock RestClient
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(MOCK_TOKEN_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(MultiValueMap.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(any(ParameterizedTypeReference.class))).thenReturn(mockResponseBody);

        // When
        AuthenticationResponseDto result = userAuthService.authenticate(credentials);

        // Then
        assertNotNull(result);
        assertEquals(MOCK_TOKEN, result.accessToken());
        assertEquals(1800, result.expiresIn());
        assertEquals("JWT", result.tokenType());
        assertEquals(MOCK_TOKEN, result.refreshToken());
        assertEquals(1800, result.refreshExpiresIn());
    }

    @DisplayName("Authenticate user: Failure with RestClientException")
    @Test
    void givenCredentials_whenAuthenticate_thenThrowException() {
        // Given
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(MOCK_TOKEN_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(MultiValueMap.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenThrow(new RestClientException("Unable to connect"));

        // When - Then
        assertThrows(InvalidAuthenticationCredentialsException.class,
                () -> userAuthService.authenticate(credentials));
    }

    @DisplayName("Refresh Token: Success")
    @Test
    void givenRefreshToken_whenRefreshToken_thenReturnAuthenticationResponse() {
        // Given
        String refreshToken = "mockRefreshToken";

        Map<String, Object> mockResponseBody = new HashMap<>();
        mockResponseBody.put(TOKEN, MOCK_TOKEN);
        mockResponseBody.put("expires_in", 1800);
        mockResponseBody.put("token_type", "JWT");
        mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, MOCK_TOKEN);
        mockResponseBody.put("refresh_expires_in", 1800);

        // Mock RestClient fluent API
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(MOCK_TOKEN_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(MultiValueMap.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(any(ParameterizedTypeReference.class))).thenReturn(mockResponseBody);

        // When
        AuthenticationResponseDto result = userAuthService.refreshToken(refreshToken);

        // Then
        assertNotNull(result);
        assertEquals(MOCK_TOKEN, result.accessToken());
        assertEquals(1800, result.expiresIn());
        assertEquals("JWT", result.tokenType());
        assertEquals(MOCK_TOKEN, result.refreshToken());
        assertEquals(1800, result.refreshExpiresIn());
    }

    @DisplayName("Refresh Token: Failure with RestClientException")
    @Test
    void givenInvalidRefreshToken_whenRefreshToken_thenThrowException() {
        // Given
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(MOCK_TOKEN_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_FORM_URLENCODED)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(MultiValueMap.class))).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenThrow(new RestClientException("Invalid token"));

        // When - Then
        assertThrows(InvalidRefreshTokenException.class,
                () -> userAuthService.refreshToken(MOCK_TOKEN));
    }
}
