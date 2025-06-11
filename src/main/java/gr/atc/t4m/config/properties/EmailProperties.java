package gr.atc.t4m.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring.mail")
public record EmailProperties(
        String username,
        String dashboardUrl,
        String projectName
) {}
