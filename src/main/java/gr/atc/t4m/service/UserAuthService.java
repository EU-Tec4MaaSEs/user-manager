package gr.atc.t4m.service;

import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;
import gr.atc.t4m.config.properties.KeycloakProperties;
import gr.atc.t4m.service.interfaces.IUserAuthService;
import org.slf4j.Logger;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

import static gr.atc.t4m.exception.CustomExceptions.*;

@Service
public class UserAuthService implements IUserAuthService {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(UserAuthService.class);

    private final String tokenUri;
    private final String clientName;
    private final String clientSecret;

    public UserAuthService(KeycloakProperties keycloakProperties) {
        this.tokenUri = keycloakProperties.tokenUri();
        this.clientName = keycloakProperties.clientId();
        this.clientSecret = keycloakProperties.clientSecret();
    }

    private final RestTemplate restTemplate = new RestTemplate();

    // Strings commonly used
    private static final String TOKEN = "access_token";
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String USERNAME = "username";
    private static final String SCOPE = "scope";
    private static final String PROTOCOL = "openid";

    /**
     * Authenticate the User Credentials in Keycloak and return JWT Token
     *
     * @param credentials : User email and password
     * @return AuthenticationResponseDTO
     */
    @Override
    public AuthenticationResponseDto authenticate(CredentialsDto credentials) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> entity = getMultiValueMapHttpEntity(credentials, null, headers);

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    tokenUri, HttpMethod.POST, entity, new ParameterizedTypeReference<>() {
                    });

            return parseAuthenticationResponse(response);

        } catch (RestClientException e) {
            log.error("Authentication failed: {}", e.getMessage(), e);
            throw new InvalidAuthenticationCredentialsException("Invalid credentials or authorization server error");
        }
    }


    /**
     * Generate new refresh token for user
     *
     * @param refreshToken : Refresh Token
     * @return AuthenticationResponseDTO
     */
    @Override
    public AuthenticationResponseDto refreshToken(String refreshToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> entity = getMultiValueMapHttpEntity(null, refreshToken, headers);

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    tokenUri, HttpMethod.POST, entity, new ParameterizedTypeReference<>() {
                    });

            return parseAuthenticationResponse(response);

        } catch (RestClientException e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            throw new InvalidRefreshTokenException("Refresh token is invalid or expired");
        }
    }

    /**
     * Create the MultiValueMap for HttpEntity
     *
     * @param credentials  : User Credentials (if exist)
     * @param refreshToken : Refresh Token (if exist)
     * @param headers      : Http Headers
     * @return HttpEntity
     */
    private HttpEntity<MultiValueMap<String, String>> getMultiValueMapHttpEntity(CredentialsDto credentials, String refreshToken, HttpHeaders headers) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        if (refreshToken == null) {
            body.add(CLIENT_ID, clientName);
            body.add(CLIENT_SECRET, clientSecret);
            body.add(USERNAME, credentials.email());
            body.add(GRANT_TYPE_PASSWORD, credentials.password());
            body.add(GRANT_TYPE, GRANT_TYPE_PASSWORD);
            body.add(SCOPE, PROTOCOL);
        } else {
            body.add(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
            body.add(GRANT_TYPE_REFRESH_TOKEN, refreshToken);
            body.add(CLIENT_ID, clientName);
            body.add(CLIENT_SECRET, clientSecret);
            body.add(SCOPE, PROTOCOL);
        }

        return new HttpEntity<>(body, headers);
    }

    /**
     * Parse the authentication response and return an AuthenticationResponseDTO.
     *
     * @param response : Response from Keycloak
     */
    private AuthenticationResponseDto parseAuthenticationResponse(ResponseEntity<Map<String, Object>> response) {
        return Optional.ofNullable(response)
                .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                .map(ResponseEntity::getBody)
                .filter(body -> body.get(TOKEN) != null)
                .map(body -> AuthenticationResponseDto.builder()
                        .accessToken((String) body.get(TOKEN))
                        .expiresIn((Integer) body.get("expires_in"))
                        .tokenType((String) body.get("token_type"))
                        .refreshToken((String) body.get(GRANT_TYPE_REFRESH_TOKEN))
                        .refreshExpiresIn((Integer) body.get("refresh_expires_in"))
                        .build())
                .orElseThrow(() -> new InvalidAuthenticationCredentialsException(
                        "No or invalid response received from Resource Server while authenticating user"));
    }
}
