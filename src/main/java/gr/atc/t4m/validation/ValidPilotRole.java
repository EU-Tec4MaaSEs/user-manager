package gr.atc.t4m.validation;

import gr.atc.t4m.validation.validators.PilotRoleValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PilotRoleValidator.class)
@Target({ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPilotRole {
    String message() default "Invalid pilot role inserted. Only 'USER', 'ADMIN' or 'SUPER_ADMIN' are valid";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}