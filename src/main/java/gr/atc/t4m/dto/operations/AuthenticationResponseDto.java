package gr.atc.t4m.dto.operations;

import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Builder;

@Builder
@Tag(name = "Authentication Response Object", description = "Authentication response object that contains information regarding token and expiration times. Applicable on authentication and refresh token processes")
public record AuthenticationResponseDto(

        @Schema(description = "JWT Service Token",
                name = "accessToken",
                type = "string",
                format = "JWT")
        String accessToken,

        @Schema(description = "Expiration time in seconds for the JWT Token",
                name = "expiresIn",
                type = "int")
        Integer expiresIn,

        @Schema(description = "Token Type",
                name = "tokenType",
                type = "string")
        String tokenType,

        @Schema(description = "JWT Refresh Token",
                name = "refreshToken",
                type = "string",
                format = "JWT")
        String refreshToken,

        @Schema(description = "Expiration time in seconds for the JWT Refresh Token",
                name = "refreshExpiresIn",
                type = "int")
        Integer refreshExpiresIn
) {}
