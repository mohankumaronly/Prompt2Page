package com.rockrager.authentication.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final EmailTemplateService emailTemplateService;

    @Value("${mail.from.address:}")
    private String fromAddress;

    @Value("${mail.from.name:}")
    private String fromName;

    @Value("${mail.html.enabled:true}")
    private boolean htmlEmailEnabled;

    @Value("${app.base-url}")
    private String baseUrl;

    @Async
    public void sendVerificationEmail(String to, String userName, String token) {
        log.info("Sending verification email to: {}", to);

        try {
            String verificationLink = baseUrl + "/api/auth/verify-email?token=" + token;
            String subject = "Verify Your Email - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildVerificationEmailTemplate(userName, verificationLink);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextVerificationContent(verificationLink);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Verification email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", to, e);
            throw new RuntimeException("Unable to send verification email", e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String to, String userName, String token) {
        log.info("Sending password reset email to: {}", to);

        try {
            String resetLink = baseUrl + "/api/auth/reset-password?token=" + token;
            String subject = "Reset Your Password - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildPasswordResetEmailTemplate(userName, resetLink);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextResetContent(resetLink);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Password reset email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", to, e);
            throw new RuntimeException("Unable to send password reset email", e);
        }
    }

    @Async
    public void sendWelcomeEmail(String to, String userName) {
        log.info("Sending welcome email to: {}", to);

        try {
            String subject = "Welcome to RockRager Authentication!";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildWelcomeEmailTemplate(userName);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextWelcomeContent(userName);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("Welcome email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", to, e);
            // Don't throw for welcome emails - they're not critical
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlBody) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody, true);

            // FIXED: Safe way to set from address without encoding issues
            setFromAddressSafe(helper);

            mailSender.send(mimeMessage);

            log.debug("HTML email sent - To: {}, Subject: {}", to, subject);
        } catch (MessagingException | MailException e) {
            log.error("HTML email delivery failed - To: {}", to, e);
            throw new RuntimeException("Failed to send HTML email", e);
        }
    }

    private void sendPlainTextEmail(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            // FIXED: Safe way to set from address
            message.setFrom(getSafeFromAddress());

            mailSender.send(message);

            log.debug("Plain text email sent - To: {}, Subject: {}", to, subject);
        } catch (MailException e) {
            log.error("Plain text email delivery failed - To: {}", to, e);
            throw new RuntimeException("Failed to send plain text email", e);
        }
    }

    /**
     * Safely set the from address without encoding errors
     */
    private void setFromAddressSafe(MimeMessageHelper helper) throws MessagingException {
        String safeFromAddress = getSafeFromAddress();

        if (safeFromAddress == null || safeFromAddress.trim().isEmpty()) {
            log.warn("No from address configured, using default");
            helper.setFrom("noreply@localhost");
            return;
        }

        // If we have a display name and it's not empty, try to use it safely
        if (fromName != null && !fromName.trim().isEmpty() && !fromName.equals(fromAddress)) {
            try {
                // Try with display name (may still throw exception)
                helper.setFrom(safeFromAddress, sanitizeDisplayName(fromName));
            } catch (Exception e) {
                // Fallback: just use email address without display name
                log.warn("Failed to set from name, using email only: {}", e.getMessage());
                helper.setFrom(safeFromAddress);
            }
        } else {
            // Just use email address
            helper.setFrom(safeFromAddress);
        }
    }

    /**
     * Get safe from address (always just the email part)
     */
    private String getSafeFromAddress() {
        String address = fromAddress;

        // If fromAddress is empty, try to use a default
        if (address == null || address.trim().isEmpty()) {
            log.warn("No mail.from.address configured, using default");
            return "noreply@rockrager.com";
        }

        // Extract just the email address if there's a display name format
        // Example: "Name <email@domain.com>" -> "email@domain.com"
        if (address.contains("<") && address.contains(">")) {
            int start = address.indexOf("<");
            int end = address.indexOf(">");
            if (start < end && start > 0) {
                address = address.substring(start + 1, end);
            }
        }

        return address.trim();
    }

    /**
     * Sanitize display name by removing special characters
     */
    private String sanitizeDisplayName(String name) {
        if (name == null) return "";
        // Remove any problematic characters
        return name.replaceAll("[<>\\[\\]()]", "").trim();
    }

    private String buildPlainTextVerificationContent(String verificationLink) {
        return String.format("""
            Please verify your email address by clicking the link below:
            %s
            
            This link will expire in 24 hours.
            
            If you didn't create an account, please ignore this email.
            
            Best regards,
            RockRager Team
            """, verificationLink);
    }

    private String buildPlainTextResetContent(String resetLink) {
        return String.format("""
            Click the link below to reset your password:
            %s
            
            This link will expire in 1 hour.
            
            If you didn't request a password reset, please ignore this email.
            
            Best regards,
            RockRager Team
            """, resetLink);
    }

    private String buildPlainTextWelcomeContent(String userName) {
        return String.format("""
            Hello %s,
            
            Welcome to RockRager Authentication!
            
            Your account has been successfully verified.
            
            You can now log in to your account.
            
            Best regards,
            RockRager Team
            """, userName);
    }

    @Async
    public void sendOtpEmail(String to, String userName, String otpCode, int expiryMinutes) {
        log.info("Sending OTP email to: {}", to);

        try {
            String subject = "Your Login OTP - RockRager Authentication";

            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildOtpEmailTemplate(userName, otpCode, expiryMinutes);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                String textContent = buildPlainTextOtpContent(otpCode, expiryMinutes);
                sendPlainTextEmail(to, subject, textContent);
            }

            log.info("OTP email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send OTP email to: {}", to, e);
            throw new RuntimeException("Unable to send OTP email", e);
        }
    }

    private String buildPlainTextOtpContent(String otpCode, int expiryMinutes) {
        return String.format("""
        Hello,
        
        Your login OTP code is: %s
        
        This code will expire in %d minutes.
        
        Please enter this code to complete your login.
        
        If you didn't attempt to login, please ignore this email and secure your account.
        
        Best regards,
        RockRager Team
        """, otpCode, expiryMinutes);
    }

    @Async
    public void sendLoginNotificationEmail(String to, String userName, String subject, String body) {
        log.info("Sending login notification email to: {}", to);

        try {
            if (htmlEmailEnabled) {
                String htmlContent = emailTemplateService.buildLoginNotificationTemplate(userName, body);
                sendHtmlEmail(to, subject, htmlContent);
            } else {
                sendPlainTextEmail(to, subject, body);
            }
            log.info("Login notification email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", to, e);
            // Don't throw - notification is not critical
        }
    }
}