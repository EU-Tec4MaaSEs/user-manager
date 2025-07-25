package gr.atc.t4m.dto.operations;

import gr.atc.t4m.enums.T4mRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record OrganizationRegistrationDto(

        @NotEmpty(message = "Organization ID cannot be empty")
        String id,

        @NotEmpty(message = "Organization name cannot be empty")
        String name,

        @Email(message = "Email should be valid")
        @NotEmpty(message = "Email cannot be empty")
        String email,

        @NotEmpty(message = "Contact cannot be empty")
        String contact,

        @NotEmpty(message = "Organization description cannot be empty")
        Set<T4mRole> role,

        @NotEmpty(message = "Data Space Connector URL cannot be empty")
        String dataSpaceConnectorUrl,

        @NotEmpty(message = "Verifiable Credential cannot be empty")
        String verifiableCredential,

        @NotEmpty(message = "User ID cannot be empty")
        String userId
) {}
