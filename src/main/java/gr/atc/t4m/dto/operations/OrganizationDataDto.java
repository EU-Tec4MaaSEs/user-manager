package gr.atc.t4m.dto.operations;

import gr.atc.t4m.enums.T4mRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record OrganizationDataDto(

        @NotBlank(message = "Organization ID cannot be empty")
        String id,

        @NotBlank(message = "Organization name cannot be empty")
        String name,

        @NotBlank(message = "Contact cannot be empty")
        String contact,

        Set<T4mRole> role,

        String dataSpaceConnectorUrl,

        String verifiableCredential,

        @NotBlank(message = "User ID cannot be empty")
        String userId
) {}
