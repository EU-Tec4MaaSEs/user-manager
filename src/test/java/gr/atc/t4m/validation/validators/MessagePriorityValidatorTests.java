package gr.atc.t4m.validation.validators;

import gr.atc.t4m.validation.ValidMessagePriority;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@DisplayName("Message Priority Validator Unit Tests")
class MessagePriorityValidatorTests {

    @Mock
    private ConstraintValidatorContext constraintValidatorContext;

    @Mock
    private ValidMessagePriority validMessagePriority;

    private MessagePriorityValidator validator;

    @BeforeEach
    void setUp() {
        validator = new MessagePriorityValidator();
        validator.initialize(validMessagePriority);
    }

    @Nested
    @DisplayName("When validating valid message priorities")
    class ValidMessagePriorityValidation {

        @ParameterizedTest(name = "Priority ''{0}'' should be valid")
        @ValueSource(strings = {"Low", "Mid", "High", "LOW", "MID", "HIGH", "low", "mid", "high"})
        @DisplayName("Should accept valid message priorities in any case")
        void shouldAcceptValidMessagePriorities(String priority) {
            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Low Priority: Success")
        void givenLowPriority_whenValidate_thenReturnTrue() {
            // Given
            String priority = "Low";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Mid Priority: Success")
        void givenMidPriority_whenValidate_thenReturnTrue() {
            // Given
            String priority = "Mid";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate High Priority: Success")
        void givenHighPriority_whenValidate_thenReturnTrue() {
            // Given
            String priority = "High";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Case Insensitive Low: Success")
        void givenUppercaseLow_whenValidate_thenReturnTrue() {
            // Given
            String priority = "LOW";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Case Insensitive Mid: Success")
        void givenUppercaseMid_whenValidate_thenReturnTrue() {
            // Given
            String priority = "MID";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Case Insensitive High: Success")
        void givenUppercaseHigh_whenValidate_thenReturnTrue() {
            // Given
            String priority = "HIGH";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Validate Lowercase Values: Success")
        void givenLowercaseValues_whenValidate_thenReturnTrue() {
            // Given
            String[] lowercasePriorities = {"low", "mid", "high"};

            // When & Then
            for (String priority : lowercasePriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                assertThat(result).as("Priority '%s' should be valid", priority).isTrue();
            }
        }
    }

    @Nested
    @DisplayName("When validating invalid message priorities")
    class InvalidMessagePriorityValidation {

        @ParameterizedTest(name = "Priority ''{0}'' should be invalid")
        @ValueSource(strings = {
                "Invalid", 
                "INVALID", 
                "Medium", 
                "MEDIUM", 
                "Critical", 
                "CRITICAL", 
                "Normal", 
                "NORMAL",
                "urgent",
                "URGENT",
                "",
                " ",
                "  ",
                "Lo w",
                "Hi gh",
                "M id",
                "123",
                "low-priority",
                "high_priority",
                "priority-high"
        })
        @DisplayName("Should reject invalid message priorities")
        void shouldRejectInvalidMessagePriorities(String priority) {
            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject Empty String: Validation failure")
        void givenEmptyString_whenValidate_thenReturnFalse() {
            // Given
            String priority = "";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject Whitespace String: Validation failure")
        void givenWhitespaceOnlyString_whenValidate_thenReturnFalse() {
            // Given
            String priority = "   ";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject String With Spaces: Validation failure")
        void givenStringWithSpaces_whenValidate_thenReturnFalse() {
            // Given
            String priority = "Lo w";

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject Numeric Values: Validation failure")
        void givenNumericValues_whenValidate_thenReturnFalse() {
            // Given
            String[] numericPriorities = {"1", "2", "3", "123", "0"};

            // When & Then
            for (String priority : numericPriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                assertThat(result).as("Numeric priority '%s' should be invalid", priority).isFalse();
            }
        }

        @Test
        @DisplayName("Reject Special Characters: Validation failure")
        void givenSpecialCharacters_whenValidate_thenReturnFalse() {
            // Given
            String[] specialCharPriorities = {"@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "="};

            // When & Then
            for (String priority : specialCharPriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                assertThat(result).as("Special character priority '%s' should be invalid", priority).isFalse();
            }
        }

        @Test
        @DisplayName("Reject Mixed Alphanumeric: Validation failure")
        void givenMixedAlphanumericValues_whenValidate_thenReturnFalse() {
            // Given
            String[] mixedPriorities = {"Low1", "Mid2", "High3", "1Low", "2Mid", "3High"};

            // When & Then
            for (String priority : mixedPriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                assertThat(result).as("Mixed alphanumeric priority '%s' should be invalid", priority).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("When validating null values")
    class NullValueValidation {

        @ParameterizedTest
        @NullSource
        @DisplayName("Should reject null values")
        void shouldRejectNullValues(String priority) {
            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject Null Value: Validation failure")
        void givenNullValue_whenValidate_thenReturnFalse() {
            // Given
            String priority = null;

            // When
            boolean result = validator.isValid(priority, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("When testing edge cases")
    class EdgeCaseValidation {

        @Test
        @DisplayName("Reject Leading Trailing Spaces: Validation failure with spaces")
        void givenStringWithLeadingTrailingSpaces_whenValidate_thenReturnFalse() {
            // Given
            String[] spacedPriorities = {" Low ", " Mid ", " High ", "  Low  ", "  Mid  ", "  High  "};

            // When & Then
            for (String priority : spacedPriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                // Note: EnumUtils.isValidEnumIgnoreCase does not trim strings, so these should be invalid
                assertThat(result).as("Priority with spaces '%s' should be invalid", priority).isFalse();
            }
        }

        @Test
        @DisplayName("Reject Very Long String: Validation failure")
        void givenVeryLongString_whenValidate_thenReturnFalse() {
            // Given
            String veryLongString = "Low".repeat(100);

            // When
            boolean result = validator.isValid(veryLongString, constraintValidatorContext);

            // Then
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Reject Unicode Characters: Validation failure")
        void givenUnicodeCharacters_whenValidate_thenReturnFalse() {
            // Given
            String[] unicodePriorities = {"Lôw", "Míd", "Hïgh", "低い", "中間", "高い"};

            // When & Then
            for (String priority : unicodePriorities) {
                boolean result = validator.isValid(priority, constraintValidatorContext);
                assertThat(result).as("Unicode priority '%s' should be invalid", priority).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("When testing validator initialization")
    class ValidatorInitialization {

        @Test
        @DisplayName("Initialize Validator: Success without error")
        void givenValidator_whenInitialize_thenSucceed() {
            // Given
            MessagePriorityValidator newValidator = new MessagePriorityValidator();

            // When & Then - Should not throw any exception
            newValidator.initialize(validMessagePriority);

            // Verify it works after initialization
            boolean result = newValidator.isValid("High", constraintValidatorContext);
            assertThat(result).isTrue();
        }
    }
}