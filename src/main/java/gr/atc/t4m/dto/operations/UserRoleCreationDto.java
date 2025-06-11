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

        @NotEmpty(message = "Pilot code cannot be empty")
        @Schema(description = "Pilot Code of the user. Pilot code must exist",
                name = "pilotCode",
                type = "String",
                example = "TEST_PILOT",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String pilotCode,

        @ValidPilotRole
        @NotEmpty(message = "Pilot role cannot be empty")
        @Schema(description = "Pilot Role of the user. Pilot role must exist",
                name = "pilotRole",
                type = "String",
                example = "'ADMIN' or 'USER' or 'SUPER_ADMIN'",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String pilotRole,

        @Schema(description = "Brief description for the User role. If not provided it will be auto-generated",
                name = "description",
                type = "String",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        String description
) {}
