package gr.atc.t4m;

import gr.atc.t4m.config.properties.CacheProperties;
import gr.atc.t4m.config.properties.EmailProperties;
import gr.atc.t4m.config.properties.KafkaProperties;
import gr.atc.t4m.config.properties.KeycloakProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableConfigurationProperties({KeycloakProperties.class, CacheProperties.class, EmailProperties.class, KafkaProperties.class})
@EnableScheduling
@EnableCaching
@EnableAsync
public class T4mUserManagerApplication {
	public static void main(String[] args) {
		SpringApplication.run(T4mUserManagerApplication.class, args);
	}
}
