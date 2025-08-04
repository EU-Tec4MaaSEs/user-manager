package gr.atc.t4m.dto.operations;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record UserRoleCreationDto(

        @NotBlank(message = "Role name cannot be empty")
        @Schema(description = "Name of the Role",
                name = "name",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String name,

        @NotBlank(message = "Global name cannot be empty")
        @Schema(description = "Global name of the role, how it is presented in the UI",
                name = "globalName",
                type = "String",
                example = "Test Role",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String globalName,

        @NotBlank(message = "Description cannot be empty")
        @Schema(description = "Brief description for the User role. Should define the purpose of the role",
                name = "description",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String description
) {}
