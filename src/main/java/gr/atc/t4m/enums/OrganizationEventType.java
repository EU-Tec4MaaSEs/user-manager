package gr.atc.t4m.enums;

import lombok.Getter;

@Getter
public enum OrganizationEventType {
    ORGANIZATION_ONBOARDING("Organization_Onboarding"),
    ORGANIZATION_UPDATED("Organization_Updated"),
    ORGANIZATION_DELETED("Organization_Deleted");

    private final String type;

    OrganizationEventType(final String type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return type;
    }

    public static OrganizationEventType fromString(String type){
        for (OrganizationEventType value : values()) {
            if (value.getType().equalsIgnoreCase(type)) {
                return value;
            }
        }
        return null;
    }
}
