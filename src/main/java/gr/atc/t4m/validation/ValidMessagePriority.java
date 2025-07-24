package gr.atc.t4m.validation;


import gr.atc.t4m.validation.validators.MessagePriorityValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = MessagePriorityValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidMessagePriority {
    String message() default "Invalid message priority. Valid values are: 'Low', 'Mid', 'High'";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}