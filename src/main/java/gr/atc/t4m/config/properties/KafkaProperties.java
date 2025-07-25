package gr.atc.t4m.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;
import java.util.List;

@ConfigurationProperties(prefix = "spring.kafka")
public record KafkaProperties(
        String bootstrapServers,
        Consumer consumer
) {
    public record Consumer(
            String groupId,
            String autoOffsetReset,
            String topics,
            Boolean enableAutoCommit,
            String keyDeserializer,
            String valueDeserializer,
            Properties properties
    ) {
        /**
         * Get topics as a list, splitting by comma and trimming whitespace
         */
        public List<String> getTopicsList() {
            if (topics == null || topics.trim().isEmpty()) {
                return List.of();
            }

            return Arrays.stream(topics.split(","))
                    .map(String::trim)
                    .filter(topic -> !topic.isEmpty())
                    .toList();
        }
    }

    public record Properties(
            SchemaRegistry schemaRegistry
    ) {}

    public record SchemaRegistry(
            String url
    ) {}

}