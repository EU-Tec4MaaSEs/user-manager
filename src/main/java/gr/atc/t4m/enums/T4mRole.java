package gr.atc.t4m.enums;

public enum T4mRole {
    PROVIDER("PROVIDER"),
    CONSUMER("CONSUMER");

    private final String role;

    T4mRole(final String role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return role;
    }
}
