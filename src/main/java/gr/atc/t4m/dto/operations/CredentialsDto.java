package gr.atc.t4m.dto.operations;

import gr.atc.t4m.validation.ValidPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;

@Builder
public record CredentialsDto(

        @Email(message = "Email is not valid")
        @NotEmpty(message = "Email is required")
        @Schema(description = "Name of the Pilot",
                name = "email",
                type = "string",
                format = "email",
                example = "test@test.com",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String email,

        @ValidPassword
        @NotEmpty(message = "Password is required")
        @Schema(description = "User password. Must contain at least 1 Lowercase letter, 1 Uppercase letter, 1 Number and 1 Special Character. Should be at least 8 characters long",
                name = "password",
                type = "string",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String password

) {}