package gr.atc.t4m.service.interfaces;

import gr.atc.t4m.dto.AuthenticationResponseDto;
import gr.atc.t4m.dto.CredentialsDto;

public interface IUserAuthService {

    AuthenticationResponseDto authenticate(CredentialsDto credentials);

    AuthenticationResponseDto refreshToken(String refreshToken);
}
