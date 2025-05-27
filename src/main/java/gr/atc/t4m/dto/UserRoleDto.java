package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.t4m.dto.operations.UserRoleCreationDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRoleDto {
    private static final String PILOT_ROLE = "pilot_role";
    private static final String PILOT_CODE = "pilot_code";

    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("pilotCode")
    private String pilotCode;

    @JsonProperty("pilotRole")
    private String pilotRole;

    @JsonProperty("description")
    private String description;

    /*
     * Helper method to transform a UserRoleCreationDto to a UserRoleDto
     */
    public static UserRoleDto fromUserRoleCreationDto(UserRoleCreationDto newUserRole){
        UserRoleDto userRoleDto = new UserRoleDto();
        userRoleDto.setName(newUserRole.name());
        userRoleDto.setPilotCode(newUserRole.pilotCode());
        userRoleDto.setPilotRole(newUserRole.pilotRole());
        if (newUserRole.description() != null)
            userRoleDto.setDescription(newUserRole.description());
        return userRoleDto;
    }

    /*
     * Helper method to transform a RoleRepresentation to a UserRoleDto
     */
    public static RoleRepresentation toRoleRepresentation(UserRoleDto userRole, RoleRepresentation existingRoleRepresentation){
        RoleRepresentation roleRepresentation = existingRoleRepresentation == null ? new RoleRepresentation() : existingRoleRepresentation;

        Optional.ofNullable(userRole.getName())
                .map(String::trim)
                .map(String::toUpperCase)
                .ifPresent(roleRepresentation::setName);

        Map<String, List<String>> attributes;
        // Used when role is initialized
        if (existingRoleRepresentation == null) {
            roleRepresentation.setComposite(false);
            roleRepresentation.setClientRole(true);
            attributes = new HashMap<>();
        } else {
            attributes = existingRoleRepresentation.getAttributes() != null ? existingRoleRepresentation.getAttributes() : new HashMap<>(); // Ensure that attributes is not empty or create a new HashMap
        }

        // Add pilot role attribute if included in UserRoleDTO
        Optional.ofNullable(userRole.getPilotRole())
                .map(Object::toString)
                .map(String::trim)
                .map(String::toUpperCase)
                .ifPresent(pilotRole -> attributes.put(PILOT_ROLE, List.of(pilotRole)));

        // Add pilot code attribute if included in UserRoleDTO
        Optional.ofNullable(userRole.getPilotCode())
                .map(Object::toString)
                .map(String::trim)
                .map(String::toUpperCase)
                .ifPresent(pilotCode -> attributes.put(PILOT_CODE, List.of(pilotCode)));

        // Update the attributes
        roleRepresentation.setAttributes(attributes);

        // Update the description
        Optional.ofNullable(userRole.getDescription())
                .map(Object::toString)
                .map(String::trim)
                .ifPresent(roleRepresentation::setDescription);

        return roleRepresentation;
    }

    /*
     * Helper method to transform a RoleRepresentation to a UserRoleDTO
     */
    public static UserRoleDto toUserRoleDTO(RoleRepresentation roleRepresentation) {
        return UserRoleDto.builder()
                .id(roleRepresentation.getId())
                .name(roleRepresentation.getName() != null ? roleRepresentation.getName() : null)
                .pilotCode(roleRepresentation.getAttributes() != null && roleRepresentation.getAttributes().containsKey(PILOT_CODE) && !roleRepresentation.getAttributes().get(PILOT_CODE).isEmpty() ? roleRepresentation.getAttributes().get(PILOT_CODE).getFirst(): null)
                .pilotRole(roleRepresentation.getAttributes() != null && roleRepresentation.getAttributes().containsKey(PILOT_ROLE) && !roleRepresentation.getAttributes().get(PILOT_ROLE).isEmpty() ? roleRepresentation.getAttributes().get(PILOT_ROLE).getFirst(): null)
                .description(roleRepresentation.getDescription() != null ? roleRepresentation.getDescription() : null)
                .build();
    }
}
