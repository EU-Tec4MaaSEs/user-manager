package gr.atc.t4m.kafka;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.apache.kafka.clients.consumer.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.listener.ListenerExecutionFailedException;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.support.MethodArgumentNotValidException;
import org.springframework.validation.FieldError;
import org.springframework.validation.BindingResult;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Kafka Error Handler Unit Tests")
class KafkaErrorHandlerTests {

    private KafkaErrorHandler kafkaErrorHandler;

    @Mock
    private Message<?> message;

    @Mock
    private Consumer<?, ?> consumer;

    @Mock
    private ConstraintViolation<?> constraintViolation;

    @Mock
    private BindingResult bindingResult;

    @BeforeEach
    void setUp() {
        kafkaErrorHandler = new KafkaErrorHandler();
    }

    @Test
    @DisplayName("Handle Constraint Violation: Return null on validation error")
    void givenConstraintViolationException_whenHandleError_thenReturnNull() {
        // Given
        when(message.getPayload()).thenReturn("Invalid message payload");
        
        when(constraintViolation.getPropertyPath()).thenReturn(mock(jakarta.validation.Path.class));
        when(constraintViolation.getPropertyPath().toString()).thenReturn("eventType");
        when(constraintViolation.getMessage()).thenReturn("must not be null");
        when(constraintViolation.getInvalidValue()).thenReturn(null);
        
        Set<ConstraintViolation<?>> violations = Set.of(constraintViolation);
        ConstraintViolationException constraintException = new ConstraintViolationException("Validation failed", violations);
        
        ListenerExecutionFailedException exception = new ListenerExecutionFailedException(
                "Processing failed", constraintException);
        
        // When
        Object result = kafkaErrorHandler.handleError(message, exception, consumer);
        
        // Then
        assertThat(result).isNull();
        verify(message).getPayload();
    }

    @Test
    @DisplayName("Handle Method Argument Exception: Return null on method validation error")
    void givenMethodArgumentNotValidException_whenHandleError_thenReturnNull() {
        // Given
        when(message.getPayload()).thenReturn("Invalid method arguments");
        
        FieldError fieldError = new FieldError("eventDto", "eventType", null, false, null, null, "Event type is required");
        when(bindingResult.getFieldErrors()).thenReturn(java.util.List.of(fieldError));
        
        MethodArgumentNotValidException methodArgException = mock(MethodArgumentNotValidException.class);
        when(methodArgException.getBindingResult()).thenReturn(bindingResult);
        
        ListenerExecutionFailedException exception = new ListenerExecutionFailedException(
                "Method argument validation failed", methodArgException);
        
        // When
        Object result = kafkaErrorHandler.handleError(message, exception, consumer);
        
        // Then
        assertThat(result).isNull();
        verify(message).getPayload();
        verify(methodArgException).getBindingResult();
    }

    @Test
    @DisplayName("Handle Runtime Exception: Return null on unexpected error")
    void givenRuntimeException_whenHandleError_thenReturnNull() {
        // Given
        when(message.getPayload()).thenReturn("Message that caused unexpected error");
        
        RuntimeException unexpectedException = new RuntimeException("Unexpected processing error");
        ListenerExecutionFailedException exception = new ListenerExecutionFailedException(
                "Unexpected error", unexpectedException);
        
        // When
        Object result = kafkaErrorHandler.handleError(message, exception, consumer);
        
        // Then
        assertThat(result).isNull();
        verify(message).getPayload();
    }

    @Test
    @DisplayName("Handle Null Payload: Return null with null payload")
    void givenNullPayload_whenHandleError_thenReturnNull() {
        // Given
        when(message.getPayload()).thenReturn(null);
        
        RuntimeException cause = new RuntimeException("Processing error");
        ListenerExecutionFailedException exception = new ListenerExecutionFailedException("Error", cause);
        
        // When
        Object result = kafkaErrorHandler.handleError(message, exception, consumer);
        
        // Then
        assertThat(result).isNull();
        verify(message).getPayload();
    }

    @Test
    @DisplayName("Handle Complex Payload: Return null with complex object payload")
    void givenComplexObjectPayload_whenHandleError_thenReturnNull() {
        // Given
        TestMessagePayload complexPayload = new TestMessagePayload("test", 123);
        when(message.getPayload()).thenReturn(complexPayload);
        
        RuntimeException cause = new RuntimeException("Processing error");
        ListenerExecutionFailedException exception = new ListenerExecutionFailedException("Error", cause);
        
        // When
        Object result = kafkaErrorHandler.handleError(message, exception, consumer);
        
        // Then
        assertThat(result).isNull();
        verify(message).getPayload();
    }

    // Helper class for testing complex payload handling
    private static class TestMessagePayload {
        private final String field1;
        private final int field2;

        public TestMessagePayload(String field1, int field2) {
            this.field1 = field1;
            this.field2 = field2;
        }

        @Override
        public String toString() {
            return "TestMessagePayload{field1='" + field1 + "', field2=" + field2 + "}";
        }
    }
}