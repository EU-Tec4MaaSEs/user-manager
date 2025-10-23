package gr.atc.t4m.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.controller.BaseAppResponse;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {
    private final Bucket bucket;

    private final ObjectMapper objectMapper;

    public RateLimitingFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.bucket = Bucket.builder()
                .addLimit(limit -> limit.capacity(250).refillGreedy(50, Duration.ofMinutes(1)))
                .build();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            // Directly set the response status and body instead of throwing an exception
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            BaseAppResponse<String> responseMessage = BaseAppResponse.error("Too many requests. Please try again later.", "Rate Limit Exceeded");
            objectMapper.writeValue(response.getWriter(), responseMessage);
        }

    }
}
