package gr.atc.t4m.enums;

public enum OrganizationDataFields {
    T4M_ROLE("T4M_ROLE"),
    DATA_SPACE_CONNECTOR_URL("DATA_SPACE_CONNECTOR_URL"),
    ENCODED_VERIFIABLE_CREDENTIAL("ENCODED_VERIFIABLE_CREDENTIAL"),
    GLOBAL_NAME("GLOBAL_NAME"),
    ORGANIZATION_ID("ORGANIZATION_ID");

    private final String field;

    OrganizationDataFields(final String field) {
        this.field = field;
    }

    @Override
    public String toString() {
        return field;
    }
}
