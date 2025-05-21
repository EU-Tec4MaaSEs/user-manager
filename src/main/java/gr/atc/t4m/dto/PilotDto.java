package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.representations.idm.GroupRepresentation;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PilotDto {

    @NotEmpty(message = "Group name cannot be empty")
    @JsonProperty("name")
    private String name;

    @JsonProperty("subGroups")
    private List<String> subGroups;

    /*
     * Helper method to convert a GroupDto to a GroupRepresentation
     */
    public static GroupRepresentation toGroupRepresentation(PilotDto pilotDto) {
        GroupRepresentation group = new GroupRepresentation();
        group.setName(pilotDto.getName());

        if (pilotDto.getSubGroups() != null) {
            List<GroupRepresentation> subGroups = new ArrayList<>();
            for (String subGroupName : pilotDto.getSubGroups()){
                GroupRepresentation subGroup = new GroupRepresentation();
                subGroup.setName(subGroupName);
                subGroups.add(subGroup);
            }
            group.setSubGroups(subGroups);
        }
        return group;
    }

    /*
     * Helper method to convert a GroupRepresentation to GroupDto
     */
    public static PilotDto fromGroupRepresentation(GroupRepresentation group){
        PilotDto pilotDto = new PilotDto();
        pilotDto.setName(group.getName());

        if (group.getSubGroups() != null)
            pilotDto.setSubGroups(group.getSubGroups().stream().map(GroupRepresentation::getName).toList());

        return pilotDto;
    }
}
