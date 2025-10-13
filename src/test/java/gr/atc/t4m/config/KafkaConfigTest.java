package gr.atc.t4m.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.config.properties.KafkaProperties;
import gr.atc.t4m.dto.EventDto;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.ConsumerFactory;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Kafka Configuration Unit Tests")
class KafkaConfigTest {

    @Mock
    private KafkaProperties kafkaProperties;

    @Mock
    private KafkaProperties.Consumer consumerProperties;

    @Mock
    private KafkaProperties.External externalProperties;

    @Mock
    private ObjectMapper objectMapper;

    private KafkaConfig kafkaConfig;

    @BeforeEach
    void setUp() {
        // Given - Setup common mock behaviors
        when(kafkaProperties.consumer()).thenReturn(consumerProperties);
        when(consumerProperties.groupId()).thenReturn("test-group");
        when(consumerProperties.autoOffsetReset()).thenReturn("earliest");
        when(consumerProperties.enableAutoCommit()).thenReturn(true);

        kafkaConfig = new KafkaConfig(kafkaProperties, objectMapper);
    }

    @Nested
    @DisplayName("Internal Kafka Config : Success")
    class InternalKafkaConfigTest {

        @BeforeEach
        void setUpInternal() {
            // Given
            when(kafkaProperties.bootstrapServers()).thenReturn("localhost:9092");
        }

        @Test
        @DisplayName("Internal Kafka Config : Success")
        void givenInternalConfig_whenCreateConsumerFactory_thenNoSecurityConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.internalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();

            // Then
            assertThat(configs)
                    .containsEntry(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092")
                    .containsEntry(ConsumerConfig.GROUP_ID_CONFIG, "test-group")
                    .containsEntry(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
                    .containsEntry(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true)
                    .doesNotContainKeys("security.protocol", "sasl.mechanism", "sasl.jaas.config", "ssl.truststore.type");
        }

        @Test
        @DisplayName("Internal Kafka Config : Deserializers configured")
        void givenInternalConfig_whenCreateConsumerFactory_thenDeserializersConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.internalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();

            // Then
            assertThat(configs)
                    .containsKey(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG)
                    .containsKey(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG);
        }
    }

    @Nested
    @DisplayName("External Kafka Config : Success")
    class ExternalKafkaConfigTest {

        @BeforeEach
        void setUpExternal() {
            // Given
            when(kafkaProperties.bootstrapServers()).thenReturn("external-kafka:9093");
            when(kafkaProperties.external()).thenReturn(externalProperties);
            when(externalProperties.username()).thenReturn("test-user");
            when(externalProperties.password()).thenReturn("test-password");
            when(externalProperties.caCertPath()).thenReturn("certs/kafka-ca.crt");
        }

        @Test
        @DisplayName("External Kafka Config : SASL_SSL configured")
        void givenExternalConfig_whenCreateConsumerFactory_thenSecurityProtocolConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.externalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();

            // Then
            assertThat(configs)
                    .containsEntry("security.protocol", "SASL_SSL")
                    .containsEntry("sasl.mechanism", "SCRAM-SHA-512");
        }

        @Test
        @DisplayName("External Kafka Config : SASL authentication with credentials")
        void givenExternalConfig_whenCreateConsumerFactory_thenSaslConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.externalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();
            String jaasConfig = (String) configs.get("sasl.jaas.config");

            // Then
            assertThat(jaasConfig)
                    .isNotNull()
                    .contains("org.apache.kafka.common.security.scram.ScramLoginModule")
                    .contains("username=\"test-user\"")
                    .contains("password=\"test-password\"");
        }

        @Test
        @DisplayName("External Kafka Config : TLS with PEM certificate")
        void givenExternalConfig_whenCreateConsumerFactory_thenTlsConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.externalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();

            // Then
            assertThat(configs)
                    .containsEntry("ssl.truststore.type", "PEM")
                    .containsEntry("ssl.endpoint.identification.algorithm", "")
                    .containsKey("ssl.truststore.certificates");

            // Then - Verify certificate content is loaded
            String certContent = (String) configs.get("ssl.truststore.certificates");
            assertThat(certContent)
                    .contains("BEGIN CERTIFICATE")
                    .contains("END CERTIFICATE");
        }

        @Test
        @DisplayName("External Kafka Config : Bootstrap servers configured")
        void givenExternalConfig_whenCreateConsumerFactory_thenBootstrapServersConfigured() {
            // When
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.externalConsumerFactory();
            Map<String, Object> configs = consumerFactory.getConfigurationProperties();

            // Then
            assertThat(configs)
                    .containsEntry(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "external-kafka:9093")
                    .containsEntry(ConsumerConfig.GROUP_ID_CONFIG, "test-group");
        }

        @Test
        @DisplayName("External Kafka Config : Exception when certificate not found")
        void givenInvalidCertPath_whenCreateConsumerFactory_thenThrowException() {
            // Given - Invalid certificate path
            when(externalProperties.caCertPath()).thenReturn("invalid/path/cert.crt");

            // When & Then
            assertThatThrownBy(() -> kafkaConfig.externalConsumerFactory())
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("Failed to load Kafka CA certificate");
        }
    }

    @Nested
    @DisplayName("Kafka Listener Container Factory : Success")
    class KafkaListenerContainerFactoryTest {

        @Test
        @DisplayName("Kafka Listener Container Factory : Uses consumer factory")
        void givenConsumerFactory_whenCreateListenerFactory_thenFactoryConfigured() {
            // Given
            when(kafkaProperties.bootstrapServers()).thenReturn("localhost:9092");
            ConsumerFactory<String, EventDto> consumerFactory = kafkaConfig.internalConsumerFactory();

            // When
            var listenerFactory = kafkaConfig.kafkaListenerContainerFactory(consumerFactory);

            // Then
            assertThat(listenerFactory)
                    .isNotNull()
                    .extracting("consumerFactory")
                    .isEqualTo(consumerFactory);
        }
    }
}
