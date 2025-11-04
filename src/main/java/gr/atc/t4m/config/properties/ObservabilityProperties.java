package gr.atc.t4m.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for observability features including distributed tracing
 */
@ConfigurationProperties(prefix = "observability")
public record ObservabilityProperties(
        /**
         * Enable or disable distributed tracing with OpenTelemetry
         */
        Boolean tracingEnabled
) {
    /**
     * Default constructor with default value
     */
    public ObservabilityProperties {
        // Default to true if not specified
        if (tracingEnabled == null) {
            tracingEnabled = true;
        }
    }
}
