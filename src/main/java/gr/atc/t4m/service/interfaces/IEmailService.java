package gr.atc.t4m.service.interfaces;

import java.util.concurrent.CompletableFuture;

public interface IEmailService {
    CompletableFuture<Void> sendActivationLink(String fullName, String email, String activationToken);

    CompletableFuture<Void> sendResetPasswordLink(String fullName, String email, String resetToken);

    void sendOrganizationRegistrationEmail(String fullName, String email, String organizationName);
}
