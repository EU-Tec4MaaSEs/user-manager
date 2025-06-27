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
        public DataRetrievalException(String message) {
            super(message);
        }
    }

    public static class InvalidActivationAttributesException extends RuntimeException {
        public InvalidActivationAttributesException(String message) {
            super(message);
        }
    }

    public static class InvalidAuthenticationCredentialsException extends RuntimeException {
        public InvalidAuthenticationCredentialsException(String message) {
            super(message);
        }
    }

    public static class InvalidRefreshTokenException extends RuntimeException {
        public InvalidRefreshTokenException(String message) {
            super(message);
        }
    }

    public static class ResourceAlreadyExistsException extends RuntimeException {
        public ResourceAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class ResourceNotPresentException extends RuntimeException {
        public ResourceNotPresentException(String message) {
            super(message);
        }
    }

    public static class UserActivateStatusException extends RuntimeException {
        public UserActivateStatusException(String message) {
            super(message);
        }
    }

    public static class InvalidPasswordException extends RuntimeException{
        public InvalidPasswordException(String message) {
            super(message);
        }
    }

    public static class ForbiddenAccessException extends RuntimeException{
        public ForbiddenAccessException(String message) { super(message); }
    }
}
