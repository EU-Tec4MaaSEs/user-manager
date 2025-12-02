package gr.atc.t4m.util;

import lombok.experimental.UtilityClass;

/**
 * Utility class for string normalization operations
 */
@UtilityClass
public class StringNormalizationUtils {

    /**
     * Normalize a string by trimming whitespace and converting to uppercase
     *
     * @param input the string to normalize
     * @return normalized string (trimmed and uppercase), or null if input is null
     *
     * @example
     * normalize("  pilot-01  ") -> "PILOT-01"
     * <p>
     * normalize("admin") -> "ADMIN"
     */
    public static String normalize(String input) {
        return input == null ? null : input.trim().toUpperCase();
    }

    /**
     * Normalize a string by trimming whitespace, converting to uppercase and joining whitespaces with underscore
     *
     * @param input the string to normalize
     * @return normalized string (trimmed, underscored and uppercase), or null if input is null
     *
     * @example
     * normalize("test Role") -> "TEST_ROLE"
     */
    public static String normalizeUserRole(String input) {
        if (input == null) {
            return null;
        }
        return input.trim().toUpperCase().replace(' ', '_');
    }

    /**
     * Normalize email address (trim and lowercase)
     * Email addresses should be case-insensitive
     *
     * @param email the email to normalize
     * @return normalized email (trimmed and lowercase), or null if input is null
     *
     * @example
     * normalizeEmail("  User@Example.COM  ") -> "user@example.com"
     */
    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }

    /**
     * Normalize a name (trim and capitalize first letter of each word)
     *
     * @param name the name to normalize
     * @return normalized name with proper capitalization
     *
     * @example
     * normalizeName("  john doe  ") -> "John Doe"
     * <p>
     * normalizeName("MARY SMITH") -> "Mary Smith"
     */
    public static String normalizeName(String name) {
        if (name == null || name.isBlank()) {
            return name;
        }

        String trimmed = name.trim();
        String[] words = trimmed.split("\\s+");
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            if (words[i].length() > 0) {
                result.append(Character.toUpperCase(words[i].charAt(0)));
                if (words[i].length() > 1) {
                    result.append(words[i].substring(1).toLowerCase());
                }
                if (i < words.length - 1) {
                    result.append(" ");
                }
            }
        }

        return result.toString();
    }

    /**
     * Check if a normalized string matches another
     *
     * @param str1 first string
     * @param str2 second string
     * @return true if strings match after normalization
     */
    public static boolean normalizedEquals(String str1, String str2) {
        String normalized1 = normalize(str1);
        String normalized2 = normalize(str2);
        return normalized1 != null && normalized1.equals(normalized2);
    }
}
