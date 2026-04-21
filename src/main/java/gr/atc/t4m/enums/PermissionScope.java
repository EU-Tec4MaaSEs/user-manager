package gr.atc.t4m.enums;

import lombok.Getter;

@Getter
public enum PermissionScope {
    NONE("None"),
    VIEW("View"),
    MANAGE("Manage");

    private final String scope;

    PermissionScope(final String scope) {
        this.scope = scope;
    }

    @Override
    public String toString() {
        return scope;
    }

    /**
     * Converts a string to PermissionScope enum
     * Supports both enum name and scope value
     *
     * @param scope String representation (enum name or value)
     * @return PermissionScope enum or null if not found
     */
    public static PermissionScope fromString(String scope){
        if (scope == null) return null;

        for (PermissionScope value : values()) {
            if (value.name().equalsIgnoreCase(scope) ||
                value.getScope().equalsIgnoreCase(scope)) {
                return value;
            }
        }
        return null;
    }

    /**
     * Checks if this permission scope includes/contains another scope based on hierarchy
     * Hierarchy: MANAGE > VIEW > NONE
     *
     * @param requestedScope The scope being checked
     * @return true if this scope includes the requested scope
     */
    public boolean contains(PermissionScope requestedScope) {
        if (requestedScope == null) return false;

        // If scopes are equal, always true
        if (this == requestedScope) return true;

        // Apply hierarchy: MANAGE includes VIEW, VIEW does not include MANAGE
        return switch (this) {
            case MANAGE -> requestedScope == VIEW || requestedScope == NONE;
            case VIEW -> requestedScope == NONE;
            case NONE -> false;
        };
    }

    /**
     * Validates if a string represents a valid permission scope
     *
     * @param scope String to validate
     * @return true if valid permission scope
     */
    public static boolean isValid(String scope) {
        return fromString(scope) != null;
    }

    /**
     * Formats a scope string to its proper scope value
     *
     * @param scope Input scope string
     * @return Formatted scope value or original string if invalid
     */
    public static String formatScope(String scope) {
        PermissionScope ps = fromString(scope);
        return ps != null ? ps.getScope() : scope;
    }
}
