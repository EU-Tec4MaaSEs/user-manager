package gr.atc.t4m.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ValueNetworkValues {
    VN1("VN1"),
    VN2("VN2"),
    VN3("VN3");

    private final String code;

    ValueNetworkValues(String code) {
        this.code = code;
    }

    @JsonValue
    public String getCode() {
        return code;
    }
}