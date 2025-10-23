package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.t4m.dto.operations.PilotCreationDto;
import gr.atc.t4m.enums.OrganizationDataFields;
import gr.atc.t4m.enums.T4mRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.representations.idm.GroupRepresentation;

import java.util.*;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PilotDto {

    @JsonProperty("name")
    private String name;

    @JsonProperty("globalName")
    private String globalName;

    @JsonProperty("subGroups")
    private List<String> subGroups;

    @JsonProperty("verifiableCredential")
    private String verifiableCredential;

    @JsonProperty("organizationId")
    private String organizationId;

    @JsonProperty("roles")
    private Set<T4mRole> roles;

    @JsonProperty("dataSpaceConnectorUrl")
    private String dataSpaceConnectorUrl;


    /*
     * Helper method to convert a GroupDto to a GroupRepresentation
     */
    public static GroupRepresentation toGroupRepresentation(PilotDto pilotDto, GroupRepresentation existingGroup) {
        GroupRepresentation group = Optional.ofNullable(existingGroup)
                .orElseGet(GroupRepresentation::new);

        // Set the group name and path according to the pilot's global name, if available
        String groupName = Optional.ofNullable(pilotDto.getGlobalName())
                .map(String::trim)
                .map(String::toUpperCase)
                .map(name -> String.join("-", name.split("\\s+")))
                .orElse(pilotDto.getName());

        group.setName(groupName);
        group.setPath(groupName + "/");

        Optional.ofNullable(pilotDto.getSubGroups())
                .ifPresent(subGroupNames ->
                        group.setSubGroups(
                                subGroupNames.stream()
                                        .map(name -> {
                                            GroupRepresentation subGroup = new GroupRepresentation();
                                            subGroup.setName(name);
                                            return subGroup;
                                        })
                                        .toList()
                        )
                );

        // Build attributes map
        Map<String, List<String>> attributes = Optional.ofNullable(group.getAttributes())
                .map(HashMap::new) // Create a copy to avoid modifying the original
                .orElseGet(HashMap::new);

        // Add the new / updated attributes to the organization
        if (pilotDto.getRoles() != null) {
            setListAttributesIfPresent(attributes, OrganizationDataFields.T4M_ROLE.toString(),
                    pilotDto.getRoles().stream().map(T4mRole::toString).toList());
        }

        setAttributeIfPresent(attributes, OrganizationDataFields.DATA_SPACE_CONNECTOR_URL.toString(),
                pilotDto.getDataSpaceConnectorUrl());

        setAttributeIfPresent(attributes, OrganizationDataFields.ORGANIZATION_ID.toString(),
                pilotDto.getOrganizationId());

        setAttributeIfPresent(attributes, OrganizationDataFields.ENCODED_VERIFIABLE_CREDENTIAL.toString(),
                pilotDto.getVerifiableCredential());
        setAttributeIfPresent(attributes, OrganizationDataFields.GLOBAL_NAME.toString(),
                pilotDto.getGlobalName());

        if (!attributes.isEmpty()) {
            group.setAttributes(attributes);
        }

        return group;
    }

    /*
     * Helper method to set an attribute if the value is present
     */
    private static void setAttributeIfPresent(Map<String, List<String>> attributes,
                                              String key, String value) {
        if (value != null) {
            attributes.put(key, List.of(value));
        }
    }

    /*
     * Helper method to set a list attribute if the values are present
     */
    private static void setListAttributesIfPresent(Map<String, List<String>> attributes,
                                              String key, List<String> values) {
        if (values != null && !values.isEmpty()) {
            attributes.put(key, new ArrayList<>(values));
        }
    }

    /*
     * Helper method to convert a GroupRepresentation to GroupDto
     */
    public static PilotDto fromGroupRepresentation(GroupRepresentation group) {
        PilotDto pilotDto = new PilotDto();
        pilotDto.setName(group.getName());

        if (group.getSubGroups() != null)
            pilotDto.setSubGroups(group.getSubGroups().stream().map(GroupRepresentation::getName).toList());

        // Handle attributes
        if (group.getAttributes() != null) {
            Map<String, List<String>> attributes = group.getAttributes();

            // Extract roles
            if (attributes.containsKey(OrganizationDataFields.T4M_ROLE.toString())) {
                Set<T4mRole> roles = attributes.get(OrganizationDataFields.T4M_ROLE.toString())
                        .stream()
                        .map(roleString -> {
                            try {
                                return T4mRole.valueOf(roleString);
                            } catch (IllegalArgumentException e) {
                                return null;
                            }
                        })
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());
                pilotDto.setRoles(roles);
            }

            // Extract dataSpaceConnectorUrl
            pilotDto.setDataSpaceConnectorUrl(getAttributesValue(attributes,
                    OrganizationDataFields.DATA_SPACE_CONNECTOR_URL.toString()));

            // Extract verifiableCredential
            pilotDto.setVerifiableCredential(getAttributesValue(attributes,
                    OrganizationDataFields.ENCODED_VERIFIABLE_CREDENTIAL.toString()));

            // Extract globalName
            pilotDto.setGlobalName(getAttributesValue(attributes,
                    OrganizationDataFields.GLOBAL_NAME.toString()));

            // Extract organizationId
            pilotDto.setOrganizationId(getAttributesValue(attributes,
                    OrganizationDataFields.ORGANIZATION_ID.toString()));
        }

        return pilotDto;
    }

    private static String getAttributesValue(Map<String, List<String>> map, String key) {
        List<String> values = map.get(key);
        return (values != null && !values.isEmpty()) ? values.getFirst() : null;
    }

    /*
     * Helper method to convert a PilotCreationDto to PilotDto
     */
    public static PilotDto fromPilotCreationDto(PilotCreationDto pilotData) {
        return PilotDto.builder()
                .name(pilotData.name())
                .globalName(pilotData.globalName())
                .subGroups(pilotData.subGroups())
                .verifiableCredential(pilotData.verifiableCredential())
                .dataSpaceConnectorUrl(pilotData.dataSpaceConnectorUrl())
                .organizationId(pilotData.organizationId())
                .roles(pilotData.roles())
                .build();
    }
}
