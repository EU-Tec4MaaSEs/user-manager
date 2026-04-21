package gr.atc.t4m.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(name = "UserPermissionsDTO", description = "Complete user permissions and authorities")
public class UserPermissionsDto {

    @Schema(description = "User unique identifier", example = "123e4567-e89b-12d3-a456-426614174000")
    private String userId;

    @Schema(description = "User's permissions in a Map")
    private Map<String, String> permissions;
}
