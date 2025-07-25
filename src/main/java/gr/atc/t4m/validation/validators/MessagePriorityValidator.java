package gr.atc.t4m.validation.validators;

import gr.atc.t4m.enums.MessagePriority;
import gr.atc.t4m.validation.ValidMessagePriority;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.EnumUtils;

public class MessagePriorityValidator implements ConstraintValidator<ValidMessagePriority, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }

        return EnumUtils.isValidEnumIgnoreCase(MessagePriority.class, value);
    }
}
