package gr.atc.t4m;

import gr.atc.t4m.config.properties.CacheProperties;
import gr.atc.t4m.config.properties.KeycloakProperties;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@Import(TestcontainersConfiguration.class)
@EnableConfigurationProperties({KeycloakProperties.class, CacheProperties.class})
@SpringBootTest
class T4mUserManagerApplicationTests {

	@MockitoBean
	private JwtDecoder jwtDecoder;

	@Test
	void contextLoads() {
		Assertions.assertNotNull(ApplicationContext.class);
	}

}
