package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import gr.atc.t4m.dto.operations.PilotCreationDto;
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
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PilotDto {

    @JsonProperty("name")
    private String name;

    @JsonProperty("globalName")
    private String globalName;

    @JsonProperty("subGroups")
    private List<String> subGroups;

    @JsonProperty("verifiableCredential")
    private String verifiableCredential;

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
                .map(String::toUpperCase)
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
            setListAttributesIfPresent(attributes, "T4M_ROLE",
                    pilotDto.getRoles().stream().map(T4mRole::toString).toList());
        }

        setAttributeIfPresent(attributes, "DATA_SPACE_CONNECTOR_URL",
                pilotDto.getDataSpaceConnectorUrl());

        setAttributeIfPresent(attributes, "ENCODED_VERIFIABLE_CREDENTIAL",
                pilotDto.getVerifiableCredential());
        setAttributeIfPresent(attributes, "GLOBAL_NAME",
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
            if (attributes.containsKey("T4M_ROLE")) {
                Set<T4mRole> roles = attributes.get("T4M_ROLE").stream()
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
            if (attributes.containsKey("DATA_SPACE_CONNECTOR_URL") &&
                    !attributes.get("DATA_SPACE_CONNECTOR_URL").isEmpty()) {
                pilotDto.setDataSpaceConnectorUrl(attributes.get("DATA_SPACE_CONNECTOR_URL").getFirst());
            }

            // Extract verifiableCredential
            if (attributes.containsKey("ENCODED_VERIFIABLE_CREDENTIAL") &&
                    !attributes.get("ENCODED_VERIFIABLE_CREDENTIAL").isEmpty()) {
                pilotDto.setVerifiableCredential(attributes.get("ENCODED_VERIFIABLE_CREDENTIAL").getFirst());
            }

            // Extract globalName
            if (attributes.containsKey("GLOBAL_NAME") &&
                    !attributes.get("GLOBAL_NAME").isEmpty()) {
                pilotDto.setGlobalName(attributes.get("GLOBAL_NAME").getFirst());
            }
        }

        return pilotDto;
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
                .roles(pilotData.roles())
                .build();
    }
}
