package gr.atc.t4m.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("String Normalization Utility Tests")
class StringNormalizationUtilsTests {

    @Nested
    @DisplayName("normalize() Tests")
    class NormalizeTests {

        @Test
        @DisplayName("Normalize String : Uppercase and Trim")
        void whenNormalizeString_thenReturnUppercaseAndTrimmed() {
            String input = "  test case  ";

            String result = StringNormalizationUtils.normalize(input);

            assertThat(result).isEqualTo("TEST CASE");
        }
    }

    @Nested
    @DisplayName("normalizeEmail() Tests")
    class NormalizeEmailTests {

        @Test
        @DisplayName("Normalize Email : Lowercase and Trim")
        void whenNormalizeEmail_thenReturnLowercaseAndTrimmed() {
            String email = "  Test@Example.COM  ";

            String result = StringNormalizationUtils.normalizeEmail(email);

            assertThat(result).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("normalizeName() Tests")
    class NormalizeNameTests {

        @Test
        @DisplayName("Normalize Name : Convert to Title Case")
        void whenNormalizeName_thenConvertToTitleCase() {
            String name = "john doe";

            String result = StringNormalizationUtils.normalizeName(name);

            assertThat(result).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("Normalize Name with Multiple Spaces : Handle Correctly")
        void givenMultipleSpaces_whenNormalizeName_thenHandleCorrectly() {
            String name = "john    doe";

            String result = StringNormalizationUtils.normalizeName(name);

            assertThat(result).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("Normalize Single Word Name : Success")
        void givenSingleWordName_whenNormalizeName_thenCapitalizeFirst() {
            String name = "john";

            String result = StringNormalizationUtils.normalizeName(name);

            assertThat(result).isEqualTo("John");
        }
    }

    @Nested
    @DisplayName("normalizedEquals() Tests")
    class NormalizedEqualsTests {

        @Test
        @DisplayName("Compare Equal Normalized Strings : Return True")
        void givenEqualNormalizedStrings_whenNormalizedEquals_thenReturnTrue() {
            String str1 = "  Pilot-Code  ";
            String str2 = "pilot-code";

            boolean result = StringNormalizationUtils.normalizedEquals(str1, str2);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Compare Different Normalized Strings : Return False")
        void givenDifferentNormalizedStrings_whenNormalizedEquals_thenReturnFalse() {
            String str1 = "pilot-code-1";
            String str2 = "pilot-code-2";

            boolean result = StringNormalizationUtils.normalizedEquals(str1, str2);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Compare with Null Second String : Return False")
        void givenSecondStringNull_whenNormalizedEquals_thenReturnFalse() {
            boolean result = StringNormalizationUtils.normalizedEquals("test", null);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Compare with Both Strings Null : Return False")
        void givenBothStringsNull_whenNormalizedEquals_thenReturnFalse() {
            boolean result = StringNormalizationUtils.normalizedEquals(null, null);

            assertThat(result).isFalse();
        }
        @Test
        @DisplayName("Compare with Whitespace : Handle Correctly")
        void givenWhitespace_whenNormalizedEquals_thenHandleCorrectly() {
            String str1 = "   ADMIN   ";
            String str2 = "admin";

            boolean result = StringNormalizationUtils.normalizedEquals(str1, str2);

            assertThat(result).isTrue();
        }
    }
}
