package gr.atc.t4m.validation.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import gr.atc.t4m.validation.ValidPassword;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context){

        if (password == null)
            return true;
        /*
        Explanation:
            - At least one digit
            - At least one lower case char
            - At least one Capital char
            - At least one special char -> !@#$%^&*()_+-=[]{};':"\|,.<>/?~`
            - No whitespace
            - From 8 to 20 chars
         */
        String regExPattern = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?~`])(?=\\S+$).{8,20}$";

        // Build pattern and create a matcher to check the password
        Pattern pattern = Pattern.compile(regExPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(password);

        return matcher.matches();
    }
}
