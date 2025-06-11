package gr.atc.t4m.dto.operations;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;

@Builder
public record PilotCreationDto(

        @Schema(description = "Name of the Pilot",
                name = "name",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        @NotEmpty(message = "Pilot name cannot be empty")
        String name,

        @Schema(description = "Subgroups that the pilot belongs to (Auto-generated based on Pilot Roles)",
                name = "subGroups",
                type = "array",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
       List<String> subGroups
) {}
