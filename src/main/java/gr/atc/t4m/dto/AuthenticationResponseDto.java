package gr.atc.t4m.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponseDto {

    @JsonProperty("accessToken")
    private String accessToken;

    @JsonProperty("expiresIn")
    private Integer expiresIn;

    @JsonProperty("tokenType")
    private String tokenType;

    @JsonProperty("refreshToken")
    private String refreshToken;

    @JsonProperty("refreshExpiresIn")
    private Integer refreshExpiresIn;
}
