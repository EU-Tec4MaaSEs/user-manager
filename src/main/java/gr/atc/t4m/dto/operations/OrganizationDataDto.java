package gr.atc.t4m.dto.operations;

import java.util.Set;

import gr.atc.t4m.enums.T4mRole;
import jakarta.validation.constraints.NotBlank;

public record OrganizationDataDto(

        @NotBlank(message = "Organization ID cannot be empty")
        String id,

        @NotBlank(message = "Organization name cannot be empty")
        String name,

        String contact,

        Set<T4mRole> role,

        String dataSpaceConnectorUrl,

        String verifiableCredential,

        @NotBlank(message = "User ID cannot be empty")
        String userId
) {}
