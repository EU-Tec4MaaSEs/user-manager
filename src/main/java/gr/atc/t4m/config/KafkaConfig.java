package gr.atc.t4m.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.t4m.config.properties.KafkaProperties;
import gr.atc.t4m.dto.EventDto;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer;
import org.springframework.kafka.support.serializer.JsonDeserializer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaConfig {

    private final KafkaProperties kafkaProperties;

    private final ObjectMapper objectMapper;

    public KafkaConfig(KafkaProperties kafkaProperties, ObjectMapper objectMapper) {
        this.kafkaProperties = kafkaProperties;
        this.objectMapper = objectMapper;
    }

    @Bean
    public ConsumerFactory<String, EventDto> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaProperties.bootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, kafkaProperties.consumer().groupId());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, kafkaProperties.consumer().autoOffsetReset());
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, kafkaProperties.consumer().enableAutoCommit());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);

        // Configure advanced JSON deserialization
        JsonDeserializer<EventDto> jsonDeserializer = new JsonDeserializer<>(EventDto.class, objectMapper);
        jsonDeserializer.addTrustedPackages("gr.atc.t4m.dto", "gr.atc.t4m.model");
        jsonDeserializer.setUseTypeHeaders(true);


        return new DefaultKafkaConsumerFactory<>(props,
                new ErrorHandlingDeserializer<>(new StringDeserializer()),
                new ErrorHandlingDeserializer<>(jsonDeserializer));
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, EventDto> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, EventDto> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}
