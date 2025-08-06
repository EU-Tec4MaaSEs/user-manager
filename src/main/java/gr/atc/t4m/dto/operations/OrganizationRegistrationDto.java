package gr.atc.t4m.dto.operations;

import gr.atc.t4m.enums.T4mRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record OrganizationRegistrationDto(

        @NotBlank(message = "Organization ID cannot be empty")
        String id,

        @NotBlank(message = "Organization name cannot be empty")
        String name,

        @Email(message = "Email should be valid")
        @NotBlank(message = "Contact cannot be empty")
        String contact,

        @NotEmpty(message = "Organization description cannot be empty")
        Set<T4mRole> role,

        @NotBlank(message = "Data Space Connector URL cannot be empty")
        String dataSpaceConnectorUrl,

        @NotBlank(message = "Verifiable Credential cannot be empty")
        String verifiableCredential,

        @NotBlank(message = "User ID cannot be empty")
        String userId
) {}
