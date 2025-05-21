package gr.atc.t4m.service;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import gr.atc.t4m.config.properties.KeycloakProperties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;

import static gr.atc.t4m.exception.CustomExceptions.*;

@ExtendWith(MockitoExtension.class)
class UserAuthServiceTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Mock
    private RestTemplate restTemplate;

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
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    private static final String GRANT_TYPE = "grant_type";
    private static final String TOKEN = "access_token";
    private static final String USERNAME = "username";
    private static final String SCOPE = "scope";
    private static final String PROTOCOL = "openid";

    @BeforeEach
    void initialSetup() {
        ReflectionTestUtils.setField(userAuthService, "tokenUri", MOCK_TOKEN_URI);
        ReflectionTestUtils.setField(userAuthService, "clientName", MOCK_CLIENT_ID);
        ReflectionTestUtils.setField(userAuthService, "clientSecret", MOCK_CLIENT_SECRET);
        ReflectionTestUtils.setField(userAuthService, "restTemplate", restTemplate);

        credentials = new CredentialsDto(MOCK_EMAIL, MOCK_PASSWORD);
    }

    @AfterEach
    void tearDown() {
        Mockito.reset(restTemplate);
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

        ResponseEntity<Map<String, Object>> mockResponse =
                new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

        // When
        when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
                any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

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
        when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
                any(ParameterizedTypeReference.class)))
                .thenThrow(new RestClientException("Unable to connect"));

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

        ResponseEntity<Map<String, Object>> mockResponse =
                new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

        // When
        when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
                any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

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
        when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
                any(ParameterizedTypeReference.class)))
                .thenThrow(new RestClientException("Invalid token"));

        // When - Then
        assertThrows(InvalidRefreshTokenException.class,
                () -> userAuthService.refreshToken(MOCK_TOKEN));
    }

    // Tests for getMultiValueMapHttpEntity
    @DisplayName("GetMultiValueMapHttpEntity: With Credentials")
    @Test
    void givenCredentials_whenGetMultiValueMapHttpEntity_thenReturnCorrectEntity() throws Exception {
        // Given
        HttpHeaders headers = new HttpHeaders();

        // Use reflection to access private method
        Method method = UserAuthService.class.getDeclaredMethod("getMultiValueMapHttpEntity",
                CredentialsDto.class, String.class, HttpHeaders.class);
        method.setAccessible(true);

        // When
        HttpEntity<MultiValueMap<String, String>> result =
                (HttpEntity<MultiValueMap<String, String>>) method.invoke(userAuthService, credentials, null, headers);

        // Then
        MultiValueMap<String, String> body = result.getBody();
        assertNotNull(body);
        assertEquals(credentials.email(), body.getFirst(USERNAME));
        assertEquals(GRANT_TYPE_PASSWORD, body.getFirst(GRANT_TYPE));
        assertEquals(PROTOCOL, body.getFirst(SCOPE));
    }

    @DisplayName("GetMultiValueMapHttpEntity: With Refresh Token")
    @Test
    void givenRefreshToken_whenGetMultiValueMapHttpEntity_thenReturnCorrectEntity() throws Exception {
        // Given
        HttpHeaders headers = new HttpHeaders();

        // Access private method
        Method method = UserAuthService.class.getDeclaredMethod("getMultiValueMapHttpEntity",
                CredentialsDto.class, String.class, HttpHeaders.class);
        method.setAccessible(true);

        // When
        HttpEntity<MultiValueMap<String, String>> result =
                (HttpEntity<MultiValueMap<String, String>>) method.invoke(userAuthService, null, MOCK_TOKEN, headers);

        // Then
        MultiValueMap<String, String> body = result.getBody();
        assertNotNull(body);
        assertEquals(GRANT_TYPE_REFRESH_TOKEN, body.getFirst(GRANT_TYPE));
        assertEquals(MOCK_TOKEN, body.getFirst(GRANT_TYPE_REFRESH_TOKEN));
        assertEquals(PROTOCOL, body.getFirst(SCOPE));
    }

    @DisplayName("ParseAuthenticationResponse: Success")
    @Test
    void givenValidResponse_whenParseAuthenticationResponse_thenReturnAuthenticationResponseDto() throws Exception {
        // Given
        Map<String, Object> mockResponseBody = new HashMap<>();
        mockResponseBody.put(TOKEN, MOCK_TOKEN);
        mockResponseBody.put("expires_in", 1800);
        mockResponseBody.put("token_type", "JWT");
        mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, MOCK_TOKEN);
        mockResponseBody.put("refresh_expires_in", 1800);

        ResponseEntity<Map<String, Object>> mockResponse =
                new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

        Method method = UserAuthService.class.getDeclaredMethod("parseAuthenticationResponse",
                ResponseEntity.class);
        method.setAccessible(true);

        // When
        AuthenticationResponseDto result =
                (AuthenticationResponseDto) method.invoke(userAuthService, mockResponse);

        // Then
        assertNotNull(result);
        assertEquals(MOCK_TOKEN, result.accessToken());
        assertEquals(1800, result.expiresIn());
        assertEquals("JWT", result.tokenType());
        assertEquals(MOCK_TOKEN, result.refreshToken());
        assertEquals(1800, result.refreshExpiresIn());
    }

    @DisplayName("ParseAuthenticationResponse: Null Response")
    @Test
    void givenNullResponse_whenParseAuthenticationResponse_thenThrowException() throws Exception {
        // Given
        Method method = UserAuthService.class.getDeclaredMethod("parseAuthenticationResponse",
                ResponseEntity.class);
        method.setAccessible(true);

        // When-Then
        try {
            method.invoke(userAuthService, (Object) null);
            fail("Expected exception was not thrown");
        } catch (InvocationTargetException e) {
            assertInstanceOf(InvalidAuthenticationCredentialsException.class, e.getCause());
            assertEquals("No or invalid response received from Resource Server while authenticating user",
                    e.getCause().getMessage());
        }
    }

    @DisplayName("ParseAuthenticationResponse: Response With Error Status")
    @Test
    void givenResponseWithErrorStatus_whenParseAuthenticationResponse_thenThrowException() throws Exception {
        // Given
        ResponseEntity<Map<String, Object>> errorResponse =
                new ResponseEntity<>(new HashMap<>(), HttpStatus.BAD_REQUEST);

        Method method = UserAuthService.class.getDeclaredMethod("parseAuthenticationResponse",
                ResponseEntity.class);
        method.setAccessible(true);

        // When-Then
        try {
            method.invoke(userAuthService, errorResponse);
            fail("Expected exception was not thrown");
        } catch (InvocationTargetException e) {
            assertInstanceOf(InvalidAuthenticationCredentialsException.class, e.getCause());
            assertEquals("No or invalid response received from Resource Server while authenticating user",
                    e.getCause().getMessage());
        }
    }

    @DisplayName("ParseAuthenticationResponse: Response With Missing Token")
    @Test
    void givenResponseWithMissingToken_whenParseAuthenticationResponse_thenThrowException() throws Exception {
        // Given
        Map<String, Object> incompleteBody = new HashMap<>();
        incompleteBody.put("expires_in", 1800);

        ResponseEntity<Map<String, Object>> incompleteResponse =
                new ResponseEntity<>(incompleteBody, HttpStatus.OK);

        Method method = UserAuthService.class.getDeclaredMethod("parseAuthenticationResponse",
                ResponseEntity.class);
        method.setAccessible(true);

        // When-Then
        try {
            method.invoke(userAuthService, incompleteResponse);
            fail("Expected exception was not thrown");
        } catch (InvocationTargetException e) {
            assertInstanceOf(InvalidAuthenticationCredentialsException.class, e.getCause());
            assertEquals("No or invalid response received from Resource Server while authenticating user",
                    e.getCause().getMessage());
        }
    }
}
/**/
