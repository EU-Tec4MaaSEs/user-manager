package gr.atc.t4m.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(name = "PermissionDTO", description = "Permission object")
public class PermissionDto {

    @Schema(description = "Organization Name for the permission", type = "String")
    private String organization;

    @Schema(description = "Role for the permission", type = "String")
    private String role;

    @Schema(description = "Resource for the permission", type = "String")
    private String resource;

    @Schema(description = "Scope for the permission", type = "String")
    private String scope;

}
