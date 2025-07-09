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
    private static final String GLOBAL_NAME = "global_name";

    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("globalName")
    private String globalName;

    @JsonProperty("description")
    private String description;

    /*
     * Helper method to transform a UserRoleCreationDto to a UserRoleDto
     */
    public static UserRoleDto fromUserRoleCreationDto(UserRoleCreationDto newUserRole){
        UserRoleDto userRoleDto = new UserRoleDto();
        userRoleDto.setName(newUserRole.name());
        userRoleDto.setGlobalName(newUserRole.globalName());
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
            attributes = existingRoleRepresentation.getAttributes() != null ? existingRoleRepresentation.getAttributes() : new HashMap<>();
        }

        // Add global name to attribute if included in UserRoleDTO
        Optional.ofNullable(userRole.getGlobalName())
                .map(Object::toString)
                .map(String::trim)
                .ifPresent(pilotRole -> attributes.put(GLOBAL_NAME, List.of(pilotRole)));

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
                .globalName(roleRepresentation.getAttributes() != null && roleRepresentation.getAttributes().containsKey(GLOBAL_NAME) && !roleRepresentation.getAttributes().get(GLOBAL_NAME).isEmpty() ? roleRepresentation.getAttributes().get(GLOBAL_NAME).getFirst(): null)
                .description(roleRepresentation.getDescription() != null ? roleRepresentation.getDescription() : null)
                .build();
    }
}
