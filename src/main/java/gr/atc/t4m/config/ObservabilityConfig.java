package gr.atc.t4m.config;

import gr.atc.t4m.config.properties.ObservabilityProperties;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Configuration class for enabling distributed tracing with @Observed annotations
 */
@Configuration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(ObservabilityProperties.class)
@ConditionalOnProperty(name = "observability.tracing-enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class ObservabilityConfig {

    public ObservabilityConfig() {
        log.info("Distributed tracing with @Observed annotations is ENABLED");
    }

    /**
     * ObservedAspect bean to enable @Observed annotation support
     *
     * @param observationRegistry the observation registry for recording observations
     * @return ObservedAspect for processing @Observed annotations
     */
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        log.debug("Initializing ObservedAspect for distributed tracing");
        return new ObservedAspect(observationRegistry);
    }
}
