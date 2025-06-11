package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.t4m.dto.operations.UserCreationDto;
import gr.atc.t4m.validation.ValidPassword;
import gr.atc.t4m.validation.ValidPilotRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Null;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.HashMap;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {
    private static final String PILOT_CODE = "pilot_code";
    private static final String PILOT_ROLE = "pilot_role";
    private static final String USER_ROLE = "user_role";
    private static final String ACTIVATION_TOKEN = "activation_token";
    private static final String RESET_TOKEN = "reset_token";
    private static final String ACTIVATION_EXPIRY = "activation_expiry";
    private static final String SUPER_ADMIN_PILOT = "ALL";

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("username")
    private String username;

    @ValidPassword
    @JsonIgnore
    @JsonProperty("password")
    private String password;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    @Email
    @JsonProperty("email")
    private String email;

    @ValidPilotRole
    @JsonProperty("pilotRole")
    private String pilotRole;

    @JsonProperty("pilotCode")
    private String pilotCode;

    @JsonProperty("userRole")
    private String userRole;

    @Null
    @JsonProperty("activationToken")
    @JsonIgnore
    private String activationToken;

    @Null
    @JsonProperty("activationExpiry")
    @JsonIgnore
    private String activationExpiry;

    @Null
    @JsonProperty("resetToken")
    @JsonIgnore
    private String resetToken;

    @JsonProperty("tokenFlag")
    @JsonIgnore
    private boolean tokenFlagRaised;

    /**
     * Transform a UserDTO to User Representation
     *
     * @param user : UserDTO with the updates
     * @param existingUser : Existing User Representation if provided
     * @return UserRepresentationDTO
     */
    public static UserRepresentation toUserRepresentation(UserDto user, UserRepresentation existingUser) {
        if (user == null)
            return existingUser;

        UserRepresentation keycloakUser;
        // User will be by default disabled until he activates its account and create a new password
        if (existingUser == null) {
            keycloakUser = new UserRepresentation();
            keycloakUser.setEnabled(false);
        } else {
            keycloakUser = existingUser;
        }

        updateUserDetails(user, keycloakUser, existingUser);
        updateUserTokenAttributes(user, keycloakUser, existingUser);
        updateUserAttributes(user, keycloakUser);

        return keycloakUser;
    }

    /**
     * Transform a UserRepresentation of Keycloak into UserDTO in User Manager
     *
     * @param keycloakUser : UserRepresentationDTO
     * @return UserDTO
     */
    public static UserDto fromUserRepresentation(UserRepresentation keycloakUser) {
        if (keycloakUser == null)
            return null;

        return UserDto.builder().userId(keycloakUser.getId())
                .email(keycloakUser.getEmail())
                .firstName(keycloakUser.getFirstName())
                .lastName(keycloakUser.getLastName())
                .username(keycloakUser.getUsername())
                .pilotCode(getPilotCodeAttribute(keycloakUser))
                .pilotRole(getPilotRoleAttribute(keycloakUser))
                .userRole(getUserRoleAttribute(keycloakUser))
                .activationToken(getAttributeValue(keycloakUser, ACTIVATION_TOKEN))
                .activationExpiry(getAttributeValue(keycloakUser, ACTIVATION_EXPIRY))
                .resetToken(getAttributeValue(keycloakUser, RESET_TOKEN))
                .tokenFlagRaised(false)
                .build();
    }

    private static String getAttributeValue(UserRepresentation user, String key) {
        if (user.getAttributes() == null || !user.getAttributes().containsKey(key)
                || user.getAttributes().get(key).isEmpty()) {
            return null;
        }
        return user.getAttributes().get(key).getFirst();
    }

    private static String getPilotCodeAttribute(UserRepresentation user) {
        return getAttributeValue(user, PILOT_CODE);
    }

    private static String getPilotRoleAttribute(UserRepresentation user) {
        return getAttributeValue(user, PILOT_ROLE);
    }

    private static String getUserRoleAttribute(UserRepresentation user) {
        return getAttributeValue(user, USER_ROLE);
    }

    /**
     * Update User Details and Credentials
     *
     * @param user : User input data
     * @param keycloakUser : Updated version of Keycloak user
     * @param existingUser : Existing user in Keycloak
     */
    private static void updateUserDetails(UserDto user, UserRepresentation keycloakUser,
                                          UserRepresentation existingUser) {
        if (user.getFirstName() != null) {
            keycloakUser.setFirstName(user.getFirstName());
        }

        if (user.getLastName() != null) {
            keycloakUser.setLastName(user.getLastName());
        }

        if (user.getEmail() != null) {
            keycloakUser.setEmail(user.getEmail());
            keycloakUser.setEmailVerified(true);
        }

        if (user.getUsername() != null && existingUser == null) {
            keycloakUser.setUsername(user.getUsername());
        }

        if (user.getPassword() != null && existingUser != null) {
            CredentialRepresentation userCredentials = new CredentialRepresentation();
            userCredentials.setTemporary(false);
            userCredentials.setType("password");
            userCredentials.setValue(user.getPassword());
            keycloakUser.setCredentials(List.of(userCredentials));
        }
    }

    /**
     * Update User and Pilot Roles and Groups of User
     *
     * @param user : User input data
     * @param keycloakUser : Updated version of Keycloak user
     */
    private static void updateUserAttributes(UserDto user, UserRepresentation keycloakUser) {
        // Attributes Field
        if (keycloakUser.getAttributes() == null) {
            keycloakUser.setAttributes(new HashMap<>());
        }

        if (user.getPilotRole() != null) {
            keycloakUser.getAttributes().put(PILOT_ROLE, List.of(user.getPilotRole()));
        }

        String finalPilotRole = user.getPilotRole() != null ? user.getPilotRole() : keycloakUser.getAttributes().get(PILOT_ROLE).getFirst();
        if (user.getPilotCode() != null) {
            if (!user.getPilotCode().equalsIgnoreCase(SUPER_ADMIN_PILOT)) {
                String pilotType = "/" + user.getPilotCode() + "/" + finalPilotRole;
                keycloakUser.setGroups(List.of("/" + user.getPilotCode(), pilotType));
            }
            keycloakUser.getAttributes().put(PILOT_CODE, List.of(user.getPilotCode()));
        }

        if (user.getUserRole() != null) {
            keycloakUser.getAttributes().put(USER_ROLE, List.of(user.getUserRole()));
        }
    }

    /**
     * Update user token attributes
     *
     * @param user : User input data
     * @param keycloakUser : Updated version of Keycloak user
     * @param existingUser : Existing user in Keycloak
     */
    private static void updateUserTokenAttributes(UserDto user, UserRepresentation keycloakUser,
                                                  UserRepresentation existingUser) {
        // Attributes Field
        if (keycloakUser.getAttributes() == null) {
            keycloakUser.setAttributes(new HashMap<>());
        }
        // Set activation token and expiration time as attributes - Two cases can be observed:
        // 1) Create a new user
        // 2) Activate user
        if (existingUser == null && user.getActivationExpiry() != null
                && user.getActivationToken() != null && !user.isTokenFlagRaised()) { // Creation of a new user
            keycloakUser.getAttributes().put(ACTIVATION_TOKEN, List.of(user.getActivationToken()));
            keycloakUser.getAttributes().put(ACTIVATION_EXPIRY, List.of(user.getActivationExpiry()));
        } else if (user.isTokenFlagRaised() && user.getActivationToken() != null
                && keycloakUser.getAttributes() != null) { // This will apply only after the user has been activated
            keycloakUser.getAttributes().remove(ACTIVATION_TOKEN);
            keycloakUser.getAttributes().remove(ACTIVATION_EXPIRY);
            keycloakUser.setEnabled(true); // Enable user
        }

        // Set Reset Token if exists (Case of forgot password) or Remove it in case of Reset Password
        if (user.getResetToken() != null && keycloakUser.getAttributes() != null) {
            if (!user.isTokenFlagRaised()) {
                keycloakUser.getAttributes().put(RESET_TOKEN, List.of(user.getResetToken()));
            } else {
                keycloakUser.getAttributes().remove(RESET_TOKEN);
            }
        }
    }

    /*
     * Helper method to convert a UserCreationDto to a UserDto
     */
    public static UserDto fromUserCreationDto(UserCreationDto userData) {
        return UserDto.builder()
                .email(userData.email())
                .firstName(userData.firstName())
                .lastName(userData.lastName())
                .username(userData.username())
                .pilotCode(userData.pilotCode())
                .pilotRole(userData.pilotRole())
                .userRole(userData.userRole())
                .build();
    }
}
