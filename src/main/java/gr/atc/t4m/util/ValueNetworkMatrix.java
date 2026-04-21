package gr.atc.t4m.util;

import gr.atc.t4m.dto.PermissionDto;
import gr.atc.t4m.enums.PermissionResource;
import gr.atc.t4m.enums.PermissionScope;
import gr.atc.t4m.enums.ValueNetworkValues;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ValueNetworkMatrix {

    public static final String DEFAULT_VN = "VN2";
    public static final String SUPER_ADMIN = "SUPER_ADMIN";
    public static final String PROCUREMENT_AND_COMMERCIAL = "PROCUREMENT_AND_COMMERCIAL";
    public static final String TECHNICAL_ENGINEERING = "TECHNICAL_ENGINEERING";
    public static final String PLANNING_AND_OPERATIONS = "PLANNING_AND_OPERATIONS"; 
    public static final String SALES_AND_BUSINESS_DEVELOPMENT= "SALES_AND_BUSINESS_DEVELOPMENT";
    public static final String IT_AND_SYSTEM_INTEGRATION= "IT_AND_SYSTEM_INTEGRATION";
    public static final String QUALITY_AND_COMPLIANCE= "QUALITY_AND_COMPLIANCE";
    public static final String ADMIN = "ADMIN";
    private static final Map<ValueNetworkValues, Map<String, Map<PermissionResource, PermissionScope>>> MATRIX = 
            new EnumMap<>(ValueNetworkValues.class);

    static {
        // ==========================================
        // VN1
        // ==========================================
        Map<String, Map<PermissionResource, PermissionScope>> vn1 = new HashMap<>();

        vn1.put(PROCUREMENT_AND_COMMERCIAL, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.NEGOTIATION, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(TECHNICAL_ENGINEERING, Map.of(
            PermissionResource.TECHNICAL_DOCUMENTATION, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(PLANNING_AND_OPERATIONS, Map.of(
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(SALES_AND_BUSINESS_DEVELOPMENT, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(IT_AND_SYSTEM_INTEGRATION, Map.of(
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE
        ));

        vn1.put(QUALITY_AND_COMPLIANCE, Map.of(
            PermissionResource.TECHNICAL_DOCUMENTATION, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(ADMIN, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.TECHNICAL_DOCUMENTATION, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.MANAGE,
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn1.put(SUPER_ADMIN, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.TECHNICAL_DOCUMENTATION, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.MANAGE,
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        MATRIX.put(ValueNetworkValues.VN1, Collections.unmodifiableMap(vn1));

        // ==========================================
        // VN2
        // ==========================================
        Map<String, Map<PermissionResource, PermissionScope>> vn2 = new HashMap<>();

        vn2.put(PROCUREMENT_AND_COMMERCIAL, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.NEGOTIATION, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.VIEW,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn2.put(PLANNING_AND_OPERATIONS, Map.of(
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE
        ));

        vn2.put(SALES_AND_BUSINESS_DEVELOPMENT, Map.of(
            PermissionResource.NEGOTIATION, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn2.put(ADMIN, Map.of(
            PermissionResource.ORGANIZATION, PermissionScope.MANAGE,
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE
        ));

        vn2.put(SUPER_ADMIN, Map.of(
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE
        ));

        MATRIX.put(ValueNetworkValues.VN2, Collections.unmodifiableMap(vn2));


        // ==========================================
        // VN3
        // ==========================================
        Map<String, Map<PermissionResource, PermissionScope>> vn3 = new HashMap<>();

        vn3.put(PROCUREMENT_AND_COMMERCIAL, Map.of(
            PermissionResource.CONTRACT, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.NEGOTIATION, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.MANAGE,
            PermissionResource.PERFORMANCE_RATING, PermissionScope.MANAGE
        ));

        vn3.put(TECHNICAL_ENGINEERING, Map.of(
            PermissionResource.TECHNICAL_DOCUMENTATION, PermissionScope.MANAGE,
            PermissionResource.NEGOTIATION, PermissionScope.MANAGE,
            PermissionResource.PRODUCTION_ORDER, PermissionScope.MANAGE,
            PermissionResource.ORGANIZATION, PermissionScope.VIEW,
            PermissionResource.MS_REQUEST, PermissionScope.MANAGE,
            PermissionResource.FOLLOW_UP_INFO, PermissionScope.VIEW
        ));

        vn3.put(IT_AND_SYSTEM_INTEGRATION, Map.of(
            PermissionResource.ORGANIZATION, PermissionScope.MANAGE,
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE
        ));

        vn3.put(ADMIN, Map.of(
            PermissionResource.ORGANIZATION, PermissionScope.MANAGE,
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE
        ));

        vn3.put(SUPER_ADMIN, Map.of(
            PermissionResource.USER, PermissionScope.MANAGE,
            PermissionResource.ROLE, PermissionScope.MANAGE
        ));

        MATRIX.put(ValueNetworkValues.VN3, Collections.unmodifiableMap(vn3));

    }

  private static ValueNetworkValues resolveVn(String vn) {
        try {
            return (vn == null) ? ValueNetworkValues.VN2 : ValueNetworkValues.valueOf(vn.toUpperCase());
        } catch (IllegalArgumentException e) {
            return ValueNetworkValues.VN2;
        }
    }

    public static PermissionScope getPermission(String vn, String role, PermissionResource res) {
        return java.util.Optional.ofNullable(MATRIX.get(resolveVn(vn)))
                .map(m -> m.get(role))
                .map(m -> m.get(res))
                .orElse(PermissionScope.NONE);
    }

    public static Map<String, String> getAllPermissions(String vn, String role) {
        Map<PermissionResource, PermissionScope> resMap = java.util.Optional.ofNullable(MATRIX.get(resolveVn(vn)))
                .map(m -> m.get(role))
                .orElse(Map.of());

        Map<String, String> result = new HashMap<>();
        resMap.forEach((k, v) -> result.put(k.name(), v.name()));
        return result;
    }

    public static List<PermissionDto> getMatrixForVN(String organization, String vnType) {
        String type = (vnType == null) ? DEFAULT_VN : vnType;
        Map<String, Map<PermissionResource, PermissionScope>> roleMap = MATRIX.get(resolveVn(type));
        
        if (roleMap == null) {
            return Collections.emptyList();
        }

        List<PermissionDto> dtos = new ArrayList<>();
        roleMap.forEach((role, resources) -> {
            resources.forEach((resource, scope) -> {
                dtos.add(PermissionDto.builder()
                    .organization(organization)
                    .role(role)
                    .resource(resource.name())
                    .scope(scope.name())
                    .build());
            });
        });
        return dtos;
    }
}