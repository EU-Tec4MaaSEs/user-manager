package gr.atc.t4m.validation;

import gr.atc.t4m.validation.validators.PasswordValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {
    String message() default "Invalid password inserted. Should be at least 8 characters and contain at least the following: one capital case latter, one lower case and one special character";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}