package gr.atc.t4m.controller;

import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(name = "BaseAppResponse", description = "Standard application response wrapper")
public class BaseAppResponse<T> {
    private T data;
    private Object errors;
    private String message;
    private boolean success;
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'")
    @Builder.Default
    private ZonedDateTime timestamp = ZonedDateTime.now();

    public static <T> BaseAppResponse<T> success(T data) {
        return BaseAppResponse.<T>builder()
                .success(true)
                .message("Operation successful")
                .data(data)
                .build();
    }

    public static <T> BaseAppResponse<T> success(T data, String message) {
        return BaseAppResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .build();
    }

    public static <T> BaseAppResponse<T> error(String message) {
        return BaseAppResponse.<T>builder()
                .success(false)
                .message(message)
                .build();
    }

    public static <T> BaseAppResponse<T> error(String message, Object errors) {
        return BaseAppResponse.<T>builder()
                .success(false)
                .message(message)
                .errors(errors)
                .build();
    }
}
