package gr.atc.t4m.service;

import gr.atc.t4m.config.properties.EmailProperties;
import gr.atc.t4m.service.interfaces.IEmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
@Validated
public class EmailService implements IEmailService {

    private final String usernameMail;

    private final String dashboardUrl;

    private final String activateAccountSubject;
    private final String resetPasswordSubject;
    private final String organizationRegistrationSubject;

    private final JavaMailSender javaMailSender;

    public EmailService(EmailProperties emailProperties, JavaMailSender javaMailSender) {
        this.usernameMail = emailProperties.username();
        this.dashboardUrl = emailProperties.dashboardUrl();
        this.activateAccountSubject = "[EU-".concat(emailProperties.projectName()).concat("] ").concat("Welcome to ".concat(emailProperties.projectName()).concat("! Activate your account"));
        this.resetPasswordSubject = "[EU-".concat(emailProperties.projectName()).concat("] ").concat("Reset your password in ").concat(emailProperties.projectName());
        this.organizationRegistrationSubject = "[EU-".concat(emailProperties.projectName()).concat("] ").concat("Organization registered successfully in ").concat(emailProperties.projectName());
        this.javaMailSender = javaMailSender;
    }

    private static final String ACTIVATE_ACCOUNT_EMAIL_TEMPLATE = """
             <!DOCTYPE html>
                        <html>
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Account Activation</title>
                        </head>
                        <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
                          <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                            <p style="font-size: 16px;">Hello %s,</p>
             
                            <p style="font-size: 16px;">An account has been created for you in Tec4MaaSEs. Click the button below to activate your account and set up your password.</p>
             
                             <div style="text-align: center; margin: 40px 0;">
                                                                <a href="%s" style="
                                                                  display: inline-block;
                                                                  background-color: #93bafd;
                                                                  color: #ffffff;
                                                                  text-decoration: none;
                                                                  padding: 14px 22px;
                                                                  border-radius: 16px;
                                                                  font-size: 16px;
                                                                  font-weight: bold;
                                                                ">Activate Account</a>
                                <p style="text-align: center; font-size: 14px; color: #666; font-style: italic;"><strong>Note:</strong> This activation link will expire in 24 hours for security reasons.</p>
                             </div>
             
                            <p style="font-size: 16px;">If you didn't expect this invitation or believe it was sent by error, please ignore this email or contact our support team.</p>
             
                           <p style="font-size: 16px;">Best regards,<br>The Tec4MaaSEs Team</p>
                          </div>
                        </body>
                        </html>
             """;

    private static final String RESET_PASSWORD_EMAIL_TEMPLATE = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Reset Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
              <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                <p style="font-size: 16px;">Hello %s,</p>
            
                <p style="font-size: 16px;">You requested to reset password in Tec4MaaSEs. Click the button below to set up a new password.</p>
            
                 <div style="text-align: center; margin: 40px 0;">
                                                    <a href="%s" style="
                                                      display: inline-block;
                                                      background-color: #93bafd;
                                                      color: #ffffff;
                                                      text-decoration: none;
                                                      padding: 14px 22px;
                                                      border-radius: 16px;
                                                      font-size: 16px;
                                                      font-weight: bold;
                                                    ">Reset Password</a>
                 </div>
            
                <p style="font-size: 16px;">If you didn't expect this email or believe it was sent by error, please ignore this email or contact our support team.</p>
            
                <p style="font-size: 16px;">Best regards,<br>The Tec4MaaSEs Team</p>
              </div>
            </body>
            </html>
            """;

    private static final String ORGANIZATION_REGISTRATION_EMAIL = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Organization registered successfully in T4M</title>
            </head>
            <body style="font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.5;">
              <div style="max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);">
                <p style="font-size: 16px;">Hello %s,</p>
            
                <p style="font-size: 16px;">Your organization '%s' has been successfully registered in T4M. Click the button below to navigate to the login page.</p>
            
                 <div style="text-align: center; margin: 40px 0;">
                                                    <a href="%s" style="
                                                      display: inline-block;
                                                      background-color: #93bafd;
                                                      color: #ffffff;
                                                      text-decoration: none;
                                                      padding: 14px 22px;
                                                      border-radius: 16px;
                                                      font-size: 16px;
                                                      font-weight: bold;
                                                    ">Login to T4M Platform</a>
                 </div>
            
                <p style="font-size: 16px;">If you didn't expect this email or believe it was sent by error, please ignore this email or contact our support team.</p>
            
                <p style="font-size: 16px;">Best regards,<br>The Tec4MaaSEs Team</p>
              </div>
            </body>
            </html>
            """;

    /**
     * Formulate and send the user activation email
     *
     * @param fullName : Full name of the user
     * @param email : Email of the user
     * @param activationToken : Token to activate user
     * @return CompletableFuture<Void>
     */
    @Override
    @Async("taskExecutor")
    public CompletableFuture<Void> sendActivationLink(String fullName, String email, String activationToken) {
        return CompletableFuture.runAsync(() -> {
            // Create the activation link
            String activationLink = String.format("%s/activate-account?token=%s", dashboardUrl, activationToken);

            // Create the email template
            String htmlContent = String.format(ACTIVATE_ACCOUNT_EMAIL_TEMPLATE, fullName, activationLink
            );

            // Call function to send email
            sendMessage(email, htmlContent, activateAccountSubject);
        });
    }

    /**
     * Formulate and send the reset password email
     *
     * @param fullName : Full name of the user
     * @param email : Email of the user
     * @param resetToken : Token to reset the password
     * @return CompletableFuture<Void>
     */
    @Override
    @Async("taskExecutor")
    public CompletableFuture<Void> sendResetPasswordLink(String fullName, String email, String resetToken) {
        return CompletableFuture.runAsync(() -> {
            // Create the activation link
            String resetPasswordLink = String.format("%s/reset-password?token=%s", dashboardUrl, resetToken);

            // Create the email template
            String htmlContent = String.format(RESET_PASSWORD_EMAIL_TEMPLATE, fullName, resetPasswordLink
            );

            // Call function to send email
            sendMessage(email, htmlContent, resetPasswordSubject);
        });
    }


    /**
     * Formulate and send the organization registration success email
     *
     * @param fullName : Full name of the user
     * @param email : Email of the user
     * @param organizationName : Name of the organization
     */
    @Override
    public void sendOrganizationRegistrationEmail(String fullName, String email, String organizationName) {
        String htmlContent = String.format(ORGANIZATION_REGISTRATION_EMAIL, fullName, organizationName, dashboardUrl);

        sendMessage(email, htmlContent, organizationRegistrationSubject);
    }

    /**
     *  Method to send an email based on the text, subject, username and subject provided as parameters
     *
     * @param recipientAddress : To email address
     * @param text : Text to include
     * @param subject : Subject of the email
     */
    void sendMessage(String recipientAddress, String text, String subject) {
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(usernameMail);
            helper.setTo(recipientAddress);
            helper.setSubject(subject);
            helper.setText(text, true);
            log.info("Sending message to email: {}", recipientAddress);
            javaMailSender.send(message);
        } catch (MessagingException e) {
            log.error("Unable to send message to email: {} - Error: {}", recipientAddress, e.getMessage());
        }
    }
}
