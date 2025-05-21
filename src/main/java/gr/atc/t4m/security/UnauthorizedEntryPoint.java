package gr.atc.t4m.security;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import gr.atc.t4m.controller.BaseAppResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // Check if the Path is excluded from Unauthorized handling
        String requestPath = request.getRequestURI();
        if (isExcludedPath(requestPath, request.getMethod())) {
            return;
        }

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");

        // Check the validity of the token
        String errorMessage = "Unauthorized request. Check token and try again.";
        String errorCode = "Invalid or missing Token";

        if (authException instanceof OAuth2AuthenticationException) {
            errorMessage = "Invalid JWT provided.";
            errorCode = "JWT has expired or is invalid";
        }

        BaseAppResponse<String> responseMessage = BaseAppResponse.error(errorMessage, errorCode);

        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getWriter(), responseMessage);

        response.getWriter().flush();
    }

    private boolean isExcludedPath(String path, String method) {
        // Define paths to exclude from unauthorized handling
        return path.equals("/api/users/refresh-token") ||
                path.equals("/api/users/authenticate") ||
                path.equals("/api/users/activate") || 
                path.equals("/api/users/forgot-password")||
                method.equals(HttpMethod.OPTIONS.toString());
    }
}