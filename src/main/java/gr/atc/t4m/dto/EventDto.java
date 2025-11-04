package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import gr.atc.t4m.dto.operations.OrganizationDataDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@JsonIgnoreProperties(ignoreUnknown = false)
public record EventDto(
        @NotBlank(message = "Event type is required")
        String type,

        String description,

        @NotBlank(message = "Source component is required")
        String sourceComponent,

        @NotBlank(message = "Organization name is required")
        String organization,

        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'")
        String timestamp,

        @NotBlank(message = "Priority is required")
        String priority,

        @Valid
        @NotNull(message = "Event data is required")
        OrganizationDataDto data
) {}

