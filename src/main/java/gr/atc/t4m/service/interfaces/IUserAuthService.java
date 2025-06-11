package gr.atc.t4m.service.interfaces;

import gr.atc.t4m.dto.operations.AuthenticationResponseDto;
import gr.atc.t4m.dto.operations.CredentialsDto;

public interface IUserAuthService {

    AuthenticationResponseDto authenticate(CredentialsDto credentials);

    AuthenticationResponseDto refreshToken(String refreshToken);
}
