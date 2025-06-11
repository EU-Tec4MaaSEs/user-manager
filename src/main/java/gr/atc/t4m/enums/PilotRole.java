package gr.atc.t4m.enums;

/*
 * Enum for Pilot Roles
 */
public enum PilotRole {
    USER("USER"),
    ADMIN("ADMIN"),
    SUPER_ADMIN("SUPER_ADMIN");

    private final String role;

    PilotRole(final String role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return role;
    }
}