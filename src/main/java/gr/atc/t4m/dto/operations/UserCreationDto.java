package gr.atc.t4m.dto.operations;

import gr.atc.t4m.validation.ValidPilotRole;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record UserCreationDto(

        @NotEmpty(message = "Username cannot be empty")
        @Schema(description = "Username of the user",
                name = "username",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String username,

        @NotEmpty(message = "First name cannot be empty")
        @Schema(description = "First name for the user",
                name = "firstName",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String firstName,

        @NotEmpty(message = "Last name cannot be empty")
        @Schema(description = "First name for the user",
                name = "firstName",
                type = "String",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String lastName,

        @NotEmpty(message = "Email cannot be empty")
        @Email(message = "Email must be valid")
        @Schema(description = "Email for the user",
                name = "email",
                type = "string",
                format = "email",
                example = "test@test.com",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String email,

        @NotNull(message = "Pilot role must be provided")
        @ValidPilotRole
        @Schema(description = "Pilot Role of the user. Pilot role must exist",
                name = "pilotRole",
                type = "String",
                example = "'ADMIN' or 'USER' or 'SUPER_ADMIN'",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String pilotRole,

        @NotEmpty(message = "Pilot code cannot be empty")
        @Schema(description = "Pilot Code of the user. Pilot code must exist",
                name = "pilotCode",
                type = "String",
                example = "TEST_PILOT",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String pilotCode,

        @NotEmpty(message = "User role cannot be empty")
        @Schema(description = "User Role of the user. User role must exist",
                name = "userRole",
                type = "String",
                example = "TEST_ROLE",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String userRole
) { }
