package gr.atc.t4m.dto.operations;

import gr.atc.t4m.validation.ValidPassword;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;

public record PasswordsDto(
        @ValidPassword
        @NotEmpty(message = "Password is required")
        @Schema(description = "User's old password. Must contain at least 1 Lowercase letter, 1 Uppercase letter, 1 Number and 1 Special Character. Should be at least 8 characters long",
                name = "oldPassword",
                type = "string",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String oldPassword,

        @ValidPassword
        @NotEmpty(message = "Password is required")
        @Schema(description = "User's new password. Must contain at least 1 Lowercase letter, 1 Uppercase letter, 1 Number and 1 Special Character. Should be at least 8 characters long",
                name = "oldPassword",
                type = "string",
                requiredMode = Schema.RequiredMode.REQUIRED)
        String newPassword) {
}
