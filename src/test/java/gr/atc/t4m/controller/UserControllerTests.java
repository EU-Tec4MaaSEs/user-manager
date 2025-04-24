package gr.atc.t4m.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static org.hamcrest.CoreMatchers.is;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import gr.atc.t4m.dto.AuthenticationResponseDto;
import gr.atc.t4m.dto.CredentialsDto;
import static gr.atc.t4m.exception.CustomExceptions.*;
import gr.atc.t4m.service.interfaces.IUserAuthService;

@SpringBootTest
@AutoConfigureMockMvc
@EnableMethodSecurity(prePostEnabled = true)
class UserControllerTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private IUserAuthService userAuthService;

    private static CredentialsDto credentials;
    private static AuthenticationResponseDto authenticationResponse;

    @BeforeAll
    static void setup() {
        credentials = CredentialsDto.builder()
                .email("test@test.com")
                .password("TestPass123@")
                .build();

        authenticationResponse = AuthenticationResponseDto.builder()
                .accessToken("accessToken")
                .expiresIn(1800)
                .tokenType("JWT")
                .refreshToken("refreshToken")
                .refreshExpiresIn(1800)
                .build();
    }

    @DisplayName("Authenticate User: Success")
    @Test
    void givenUserCredentials_whenAuthenticate_thenReturnAccessTokens() throws Exception {
        // Given
        given(userAuthService.authenticate(credentials)).willReturn(authenticationResponse);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(credentials)));

        // Then
        response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
                .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.getAccessToken())));

    }

    @DisplayName("Refresh Token: Success")
    @Test
    void givenRefreshToken_whenRefreshToken_thenReturnNewAccessTokens() throws Exception {
        // Given
        given(userAuthService.refreshToken("test_token")).willReturn(authenticationResponse);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                .contentType(MediaType.APPLICATION_JSON).param("token", "test_token"));

        // Then
        response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
                .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.getAccessToken())));
    }

    @DisplayName("Authenticate User: Invalid Format of Credentials")
    @Test
    void givenInvalidUserCredentials_whenAuthenticate_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new CredentialsDto("email", "password"))));

        // Then
        response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Validation failed")));
    }

    @DisplayName("Authenticate User: Wrong Credentials")
    @Test
    void givenWrongCredentials_whenAuthenticate_thenReturnUnauthorized() throws Exception {
        // Given
        given(userAuthService.authenticate(credentials))
                .willThrow(InvalidAuthenticationCredentialsException.class);

        // When
        ResultActions response = mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(credentials)));

        // Then
        response.andExpect(status().isUnauthorized()).andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Authentication failed")));
    }

    @DisplayName("Authenticate User: No credentials given / Failure")
    @Test
    void givenNoInput_whenAuthenticate_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc
                .perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)));
    }

    @DisplayName("Refresh Token: No token provided / Failure")
    @Test
    void givenNoInput_whenRefreshToken_thenReturnBadRequest() throws Exception {

        // When
        ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
                        .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Invalid / No input was given for requested resource")));
    }

}
