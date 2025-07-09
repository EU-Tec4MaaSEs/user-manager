package gr.atc.t4m.exception;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.validation.ConstraintViolationException;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import gr.atc.t4m.controller.BaseAppResponse;
import static gr.atc.t4m.exception.CustomExceptions.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String VALIDATION_ERROR = "Validation failed";

    /*
     * Used for Request Body Validations in Requests
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> validationExceptionHandler(
            @NotNull MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return new ResponseEntity<>(BaseAppResponse.error(VALIDATION_ERROR, errors),
                HttpStatus.BAD_REQUEST);
    }

    /*
     * Validation fails on request parameters, path variables, or method arguments
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> constraintValidationExceptionHandler(
            @NotNull ConstraintViolationException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(violation ->
                errors.put(violation.getPropertyPath().toString(), violation.getMessage())
        );
        return new ResponseEntity<>(BaseAppResponse.error(VALIDATION_ERROR, errors),
                HttpStatus.BAD_REQUEST);
    }

    /*
     * Handles missing request body or missing data in request
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<BaseAppResponse<String>> handleHttpMessageNotReadableExceptionHandler(
            HttpMessageNotReadableException ex) {
        String errorMessage = "Required request body is missing or invalid.";

        // Check if instance is for InvalidFormat Validation
        if (ex.getCause() instanceof InvalidFormatException invalidFormatEx
                && invalidFormatEx.getTargetType().isEnum()) {
            String fieldName = invalidFormatEx.getPath().getFirst().getFieldName();
            String invalidValue = invalidFormatEx.getValue().toString();

            // Format the error message according to the Validation Type failure
            errorMessage = String.format("Invalid value '%s' for field '%s'. Allowed values are: %s",
                    invalidValue, fieldName, Arrays.stream(invalidFormatEx.getTargetType().getEnumConstants())
                            .map(Object::toString).collect(Collectors.joining(", ")));

        }
        // Generic error handling
        return ResponseEntity.badRequest().body(BaseAppResponse.error(VALIDATION_ERROR, errorMessage));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<BaseAppResponse<String>> resourceNotFoundHandler(
            @NonNull NoResourceFoundException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("Resource not found", ex.getMessage()),
                HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<BaseAppResponse<String>> inputNotProvidedExceptionHandler(
            @NonNull MissingServletRequestParameterException ex) {
        return new ResponseEntity<>(
                BaseAppResponse.error("Invalid / No input was given for requested resource", ex.getMessage()),
                HttpStatus.BAD_REQUEST);
    }

    /*
     * Handles validation for Method Parameters
     */
    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<BaseAppResponse<String>> validationExceptionHandler(
            @NonNull HandlerMethodValidationException ex) {
        return new ResponseEntity<>(BaseAppResponse.error(VALIDATION_ERROR, "Invalid input field"),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> handleAccessDeniedException(
            @NotNull AccessDeniedException ex) {
        return new ResponseEntity<>(BaseAppResponse.error(
                "Invalid authorization parameters", "You don't have the rights to access the resource or invalid token provided"), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(InvalidAuthenticationCredentialsException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> handleInvalidAuthenticationCredentialsException(@NotNull InvalidAuthenticationCredentialsException ex) {
        return new ResponseEntity<>(
                BaseAppResponse.error("Authentication failed", "Invalid authorization credentials provided"),
                HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(InvalidActivationAttributesException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> handleInvalidActivationAttributesException(
            @NotNull InvalidActivationAttributesException ex) {
        return new ResponseEntity<>(BaseAppResponse.error(ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<BaseAppResponse<Map<String, String>>> handleInvalidRefreshTokenException(
            @NotNull InvalidRefreshTokenException ex) {
        return new ResponseEntity<>(BaseAppResponse.error(ex.getMessage()), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(KeycloakException.class)
    public ResponseEntity<BaseAppResponse<String>> handleKeycloakException(@NotNull KeycloakException ex) {
        BaseAppResponse<String> response = BaseAppResponse.error(ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(DataRetrievalException.class)
    public ResponseEntity<BaseAppResponse<String>> handleDataRetrievalException(
            @NotNull DataRetrievalException ex) {
        BaseAppResponse<String> response = BaseAppResponse.error("Unable to retrieve requested data",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<BaseAppResponse<String>> handleGeneralException(@NotNull Exception ex) {
        return new ResponseEntity<>(BaseAppResponse.error("An unexpected error occurred", ex.getMessage()),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<BaseAppResponse<String>> handleResourceAlreadyExistsException(@NotNull ResourceAlreadyExistsException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("Resource already exists", ex.getMessage()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(ResourceNotPresentException.class)
    public ResponseEntity<BaseAppResponse<String>> handleResourceNotPresentException(@NotNull ResourceNotPresentException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("Resource not found", ex.getMessage()),
                HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(UserActivateStatusException.class)
    public ResponseEntity<BaseAppResponse<String>> handleUserAlreadyActivatedException(@NotNull UserActivateStatusException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("Activation failed", ex.getMessage()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<BaseAppResponse<String>> handleInvalidPasswordException(@NotNull InvalidPasswordException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("Password validation failed", ex.getMessage()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(ForbiddenAccessException.class)
    public ResponseEntity<BaseAppResponse<String>> handleForbiddenAccessException(@NotNull ForbiddenAccessException ex) {
        return new ResponseEntity<>(BaseAppResponse.error("You are unauthorized to request/modify this resource", ex.getMessage()),
                HttpStatus.FORBIDDEN);
    }
}

