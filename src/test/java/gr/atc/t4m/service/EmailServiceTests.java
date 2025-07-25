package gr.atc.t4m.service;

import gr.atc.t4m.config.properties.EmailProperties;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceTests {

    @Mock
    private JavaMailSender javaMailSender;

    @Mock
    private MimeMessage mimeMessage;

    @Mock
    private EmailProperties emailProperties;

    private EmailService emailService;

    private static final String TEST_USERNAME = "test@example.com";
    private static final String TEST_DASHBOARD_URL = "https://dashboard.example.com";
    private static final String TEST_PROJECT_NAME = "TestProject";
    private static final String TEST_FULL_NAME = "Test User";
    private static final String TEST_EMAIL = "mail@example.com";
    private static final String TEST_TOKEN = "test-token-123";

    @BeforeEach
    void setUp() {
        // Setup EmailProperties mock
        when(emailProperties.username()).thenReturn(TEST_USERNAME);
        when(emailProperties.dashboardUrl()).thenReturn(TEST_DASHBOARD_URL);
        when(emailProperties.projectName()).thenReturn(TEST_PROJECT_NAME);

        // Create EmailService instance
        emailService = new EmailService(emailProperties, javaMailSender);
    }

    @DisplayName("Initialize constructor : Success")
    @Test
    void givenBeans_whenConstructingClass_thenSuccess() {
        // Verify that constructor properly initializes all fields
        String expectedActivateSubject = "[EU-" + TEST_PROJECT_NAME + "] Welcome to " + TEST_PROJECT_NAME + "! Activate your account";
        String expectedResetSubject = "[EU-" + TEST_PROJECT_NAME + "] Reset your password in " + TEST_PROJECT_NAME;

        String usernameMail = (String) ReflectionTestUtils.getField(emailService, "usernameMail");
        String dashboardUrl = (String) ReflectionTestUtils.getField(emailService, "dashboardUrl");
        String activateAccountSubject = (String) ReflectionTestUtils.getField(emailService, "activateAccountSubject");
        String resetPasswordSubject = (String) ReflectionTestUtils.getField(emailService, "resetPasswordSubject");

        assertThat(usernameMail).isEqualTo(TEST_USERNAME);
        assertThat(dashboardUrl).isEqualTo(TEST_DASHBOARD_URL);
        assertThat(activateAccountSubject).isEqualTo(expectedActivateSubject);
        assertThat(resetPasswordSubject).isEqualTo(expectedResetSubject);
    }

    @DisplayName("Send Activation Link : Success")
    @Test
    void givenActivationToken_whenSendActivationLink_thenSuccess() throws Exception {
        // Given
        doNothing().when(javaMailSender).send(any(MimeMessage.class));
        // Setup JavaMailSender mock
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);

        // When
        CompletableFuture<Void> future = emailService.sendActivationLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);

        // Wait for async operation to complete
        future.get(5, TimeUnit.SECONDS);

        // Then
        verify(javaMailSender, times(1)).createMimeMessage();
        verify(javaMailSender, times(1)).send(mimeMessage);
    }

    @DisplayName("Send Reset Password Link : Success")
    @Test
    void givenResetPasswordToken_whenSendResetPasswordLink_thenSuccess() throws Exception {
        // Given
        doNothing().when(javaMailSender).send(any(MimeMessage.class));
        // Setup JavaMailSender mock
        when(javaMailSender.createMimeMessage()).thenReturn(mimeMessage);

        // When
        CompletableFuture<Void> future = emailService.sendResetPasswordLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);

        future.get(5, TimeUnit.SECONDS);

        // Then
        verify(javaMailSender, times(1)).createMimeMessage();
        verify(javaMailSender, times(1)).send(mimeMessage);
    }

    @DisplayName("Send Message : Success")
    @Test
    void sendMessage_ShouldConfigureMimeMessageCorrectly() throws MessagingException {
        // Given
        String testSubject = "Test Subject";
        String testText = "Test HTML Content";

        // MimeMessage
        MimeMessage realMessage = mock(MimeMessage.class);
        when(javaMailSender.createMimeMessage()).thenReturn(realMessage);

        // When
        emailService.sendMessage(TEST_EMAIL, testText, testSubject);

        // Then
        verify(javaMailSender, times(1)).createMimeMessage();
        verify(javaMailSender, times(1)).send(realMessage);
    }

    @DisplayName("Send Activation Link : Correct return Link")
    @Test
    void givenActivationToken_whenSendActivationLink_thenBuildProperActivationLink() throws Exception {
        // Given
        ArgumentCaptor<String> htmlContentCaptor = ArgumentCaptor.forClass(String.class);

        // Spy the service
        EmailService spyEmailService = spy(emailService);
        doNothing().when(spyEmailService).sendMessage(eq(TEST_EMAIL), htmlContentCaptor.capture(), anyString());

        // When
        CompletableFuture<Void> future = spyEmailService.sendActivationLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);
        future.get(5, TimeUnit.SECONDS);

        // Then
        String capturedHtmlContent = htmlContentCaptor.getValue();
        String expectedActivationLink = TEST_DASHBOARD_URL + "/activate-account?token=" + TEST_TOKEN;

        assertThat(capturedHtmlContent).contains(TEST_FULL_NAME);
        assertThat(capturedHtmlContent).contains(expectedActivationLink);
        assertThat(capturedHtmlContent).contains("Activate Account");
    }

    @DisplayName("Send Reset Password Link : Correct return Link")
    @Test
    void givenResetPasswordToken_whenSendResetPasswordLink_thenBuildProperResetPasswordLink() throws Exception {
        // Given
        ArgumentCaptor<String> htmlContentCaptor = ArgumentCaptor.forClass(String.class);

        // Create a spy to capture the sendMessage call
        EmailService spyEmailService = spy(emailService);
        doNothing().when(spyEmailService).sendMessage(eq(TEST_EMAIL), htmlContentCaptor.capture(), anyString());

        // When
        CompletableFuture<Void> future = spyEmailService.sendResetPasswordLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);
        future.get(5, TimeUnit.SECONDS);

        // Then
        String capturedHtmlContent = htmlContentCaptor.getValue();
        String expectedResetLink = TEST_DASHBOARD_URL + "/reset-password?token=" + TEST_TOKEN;

        assertThat(capturedHtmlContent).contains(TEST_FULL_NAME);
        assertThat(capturedHtmlContent).contains(expectedResetLink);
        assertThat(capturedHtmlContent).contains("Reset Password");
    }

    @DisplayName("Send Activation Link : Return CompletableFuture")
    @Test
    void sendActivationLink_ShouldReturnCompletableFuture() {
        // When
        CompletableFuture<Void> future = emailService.sendActivationLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);

        // Then
        assertThat(future).isNotNull();
        assertThat(future).isInstanceOf(CompletableFuture.class);
    }

    @DisplayName("Send Reset Password Link : Return CompletableFuture")
    @Test
    void sendResetPasswordLink_ShouldReturnCompletableFuture() {
        // When
        CompletableFuture<Void> future = emailService.sendResetPasswordLink(TEST_FULL_NAME, TEST_EMAIL, TEST_TOKEN);

        // Then
        assertThat(future).isNotNull();
        assertThat(future).isInstanceOf(CompletableFuture.class);
    }

    @DisplayName("Send Organization Registration Email : Success")
    @Test
    void givenOrganizationDetails_whenSendOrganizationRegistrationEmail_thenSuccess() {
        // Given
        String organizationName = "Test Organization";
        ArgumentCaptor<String> htmlContentCaptor = ArgumentCaptor.forClass(String.class);

        // Spy the service
        EmailService spyEmailService = spy(emailService);
        doNothing().when(spyEmailService).sendMessage(eq(TEST_EMAIL), htmlContentCaptor.capture(), anyString());

        // When
        spyEmailService.sendOrganizationRegistrationEmail(TEST_FULL_NAME, TEST_EMAIL, organizationName);

        // Then
        String capturedHtmlContent = htmlContentCaptor.getValue();
        assertThat(capturedHtmlContent).contains(TEST_FULL_NAME);
        assertThat(capturedHtmlContent).contains(organizationName);
        assertThat(capturedHtmlContent).contains(TEST_DASHBOARD_URL);
    }
}