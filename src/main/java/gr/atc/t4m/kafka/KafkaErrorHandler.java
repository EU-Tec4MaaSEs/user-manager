package gr.atc.t4m.kafka;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.Consumer;
import org.springframework.kafka.listener.ConsumerAwareListenerErrorHandler;
import org.springframework.kafka.listener.ListenerExecutionFailedException;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.support.MethodArgumentNotValidException;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class KafkaErrorHandler implements ConsumerAwareListenerErrorHandler {

    @Override
    public Object handleError(Message<?> message, ListenerExecutionFailedException exception, Consumer<?, ?> consumer) {
        log.error("Kafka message processing failed for message: {}", message.getPayload());

        // Check if it's a validation exception
        Throwable cause = exception.getCause();
        switch (cause) {
            case ConstraintViolationException constraintException -> {
                log.error("Validation failed for Kafka message:");
                constraintException.getConstraintViolations().forEach(violation ->
                        log.error("ConstraintViolationException:  Field '{}': {} (rejected value: '{}')",
                                violation.getPropertyPath(),
                                violation.getMessage(),
                                violation.getInvalidValue())
                );
            }
            case MethodArgumentNotValidException methodArgException -> {
                log.error("Method argument validation failed:");
                methodArgException.getBindingResult().getFieldErrors().forEach(error ->
                        log.error("MethodArgumentNotValidException:  Field '{}': {} (rejected value: '{}')",
                                error.getField(),
                                error.getDefaultMessage(),
                                error.getRejectedValue())
                );
            }
            default -> log.error("Unexpected error processing Kafka message: {}", exception.getMessage(), exception);
        }

        // Return null to acknowledge message
        return null;
    }
}