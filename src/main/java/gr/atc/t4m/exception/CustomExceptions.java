package gr.atc.t4m.exception;

public class CustomExceptions {

    private CustomExceptions() {}

    public static class KeycloakException extends RuntimeException {
        public KeycloakException(String message, Throwable cause) {
            super(message, cause);
        }

        public KeycloakException(String message) {
            super(message);
        }
    }

    public static class DataRetrievalException extends RuntimeException {
        public DataRetrievalException(String message, Throwable cause) {
            super(message, cause);
        }

        public DataRetrievalException(String message) {
            super(message);
        }
    }

    public static class InvalidActivationAttributesException extends RuntimeException {
        public InvalidActivationAttributesException(String message, Throwable cause) {
            super(message, cause);
        }

        public InvalidActivationAttributesException(String message) {
            super(message);
        }
    }

    public static class InvalidAuthenticationCredentialsException extends RuntimeException {
        public InvalidAuthenticationCredentialsException(String message, Throwable cause) {
            super(message, cause);
        }

        public InvalidAuthenticationCredentialsException(String message) {
            super(message);
        }
    }

    public static class InvalidRefreshTokenException extends RuntimeException {
        public InvalidRefreshTokenException(String message, Throwable cause) {
            super(message, cause);
        }

        public InvalidRefreshTokenException(String message) {
            super(message);
        }
    }

    public static class ResourceAlreadyExistsException extends RuntimeException {
        public ResourceAlreadyExistsException(String message, Throwable cause) {
            super(message, cause);
        }

        public ResourceAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class ResourceNotPresentException extends RuntimeException {
        public ResourceNotPresentException(String message, Throwable cause) {
            super(message, cause);
        }

        public ResourceNotPresentException(String message) {
            super(message);
        }
    }

    public static class UserActivateStatusException extends RuntimeException {
        public UserActivateStatusException(String message, Throwable cause) {
            super(message, cause);
        }

        public UserActivateStatusException(String message) {
            super(message);
        }
    }
}
