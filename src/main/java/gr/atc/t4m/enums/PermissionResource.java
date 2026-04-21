package gr.atc.t4m.enums;

import lombok.Getter;

@Getter
public enum PermissionResource {
    ORGANIZATION("Organization Management"),
    USER("User Management"),
    ROLE("Role Management"),
    CONTRACT("Contract Management"),
    MS_REQUEST("Manufacturing Service Request"),
    PRODUCTION_ORDER("Production Order"),
    TECHNICAL_DOCUMENTATION("Technical Documentation"),
    FOLLOW_UP_INFO("Follow-up Information"),
    NEGOTIATION("Negotiation"),
    PERFORMANCE_RATING("Performance Rating");

    private final String resource;

    PermissionResource(final String scope) {
        this.resource = scope;
    }

    @Override
    public String toString() {
        return resource;
    }

    /**
     * Converts a string to PermissionResource enum
     * Supports both enum name and resource value
     *
     * @param resource String representation (enum name or value)
     * @return PermissionResource enum or null if not found
     */
    public static PermissionResource fromString(String resource){
        if (resource == null) return null;

        for (PermissionResource value : values()) {
            // Check both enum name (USER) and resource value (User Management)
            if (value.name().equalsIgnoreCase(resource) ||
                value.getResource().equalsIgnoreCase(resource)) {
                return value;
            }
        }
        return null;
    }

    /**
     * Validates if a string represents a valid permission resource
     *
     * @param resource String to validate
     * @return true if valid permission resource
     */
    public static boolean isValid(String resource) {
        return fromString(resource) != null;
    }

    /**
     * Formats a resource string to its proper resource value
     *
     * @param resource Input resource string
     * @return Formatted resource value or original string if invalid
     */
    public static String formatResource(String resource) {
        PermissionResource pr = fromString(resource);
        return pr != null ? pr.getResource() : resource;
    }
}
