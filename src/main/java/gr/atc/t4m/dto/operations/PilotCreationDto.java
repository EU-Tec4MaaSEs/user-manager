package gr.atc.t4m.dto.operations;

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import gr.atc.t4m.enums.T4mRole;
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

        @Schema(description = "Global name of the Pilot (Auto-generated based on Pilot Roles)",
                name = "globalName",
                type = "String",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        String globalName,

        @Schema(description = "Subgroups that the pilot belongs to (Auto-generated based on Pilot Roles)",
                name = "subGroups",
                type = "array",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> subGroups,

        @JsonIgnore
        @Schema(description = "Base64 Encoding of the Verifiable Credential",
                name = "verifiableCredential",
                type = "String",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        String verifiableCredential,

        @JsonIgnore
        @Schema(description = "Factory dataspace connection URL",
                name = "roles",
                type = "array",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        Set<T4mRole> roles,

        @JsonIgnore
        @Schema(description = "Base64 Encoding of the Verifiable Credential",
                name = "dataSpaceConnectorUrl",
                type = "String",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        String dataSpaceConnectorUrl
) {}
