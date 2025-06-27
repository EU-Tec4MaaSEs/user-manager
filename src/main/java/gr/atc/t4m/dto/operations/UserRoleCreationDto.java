package gr.atc.t4m.dto.operations;

import gr.atc.t4m.validation.ValidPilotRole;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;

@Builder
public record UserRoleCreationDto(

        @NotEmpty(message = "Role name cannot be empty")
        @Schema(description = "Name of the Role",
                name = "name",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String name,

        @NotEmpty(message = "Global name cannot be empty")
        @Schema(description = "Global name of the role, how it is presented in the UI",
                name = "globalName",
                type = "String",
                example = "Test Role",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String globalName,

        @NotEmpty(message = "Description cannot be empty")
        @Schema(description = "Brief description for the User role. Should define the purpose of the role",
                name = "description",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String description
) {}
