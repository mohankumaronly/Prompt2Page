package com.rockrager.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${spring.mail.username}")
    private String smtpUsername;

    @Value("${mail.from.address:${spring.mail.username}}")
    private String fromAddress;

    public void sendVerificationEmail(String to, String token) {
        log.info("========== 📧 EMAIL SERVICE: sendVerificationEmail CALLED ==========");
        log.info("📧 Method entered at: {}", System.currentTimeMillis());
        log.info("📧 Recipient: {}", to);
        log.info("📧 Token: {}", token);

        try {
            String subject = "Verify Your Email - RockRager Authentication";
            String verificationLink = baseUrl + "/api/auth/verify-email?token=" + token;

            log.info("📧 Base URL: {}", baseUrl);
            log.info("📧 Verification link: {}", verificationLink);
            log.info("📧 Subject: {}", subject);

            String body = String.format("""
                Hello,
                
                Thank you for registering with RockRager Authentication!
                
                Please verify your email address by clicking the link below:
                %s
                
                This link will expire in 24 hours.
                
                If you didn't create an account, please ignore this email.
                
                Best regards,
                RockRager Team
                """, verificationLink);

            log.info("📧 Email body created, length: {} characters", body.length());

            sendEmail(to, subject, body);

            log.info("📧 ========== sendVerificationEmail COMPLETED SUCCESSFULLY ==========");

        } catch (Exception e) {
            log.error("📧 ❌ EXCEPTION in sendVerificationEmail: {}", e.getMessage(), e);
            throw e;
        }
    }

    public void sendPasswordResetEmail(String to, String token) {
        log.info("========== 🔐 EMAIL SERVICE: sendPasswordResetEmail CALLED ==========");
        log.info("🔐 Method entered at: {}", System.currentTimeMillis());
        log.info("🔐 Recipient: {}", to);
        log.info("🔐 Token: {}", token);

        try {
            String subject = "Reset Your Password - RockRager Authentication";
            String resetLink = baseUrl + "/api/auth/reset-password?token=" + token;

            log.info("🔐 Base URL: {}", baseUrl);
            log.info("🔐 Reset link: {}", resetLink);
            log.info("🔐 Subject: {}", subject);

            String body = String.format("""
                Hello,
                
                We received a request to reset your password.
                
                Click the link below to reset your password:
                %s
                
                This link will expire in 1 hour.
                
                If you didn't request a password reset, please ignore this email or contact support.
                
                Best regards,
                RockRager Team
                """, resetLink);

            log.info("🔐 Email body created, length: {} characters", body.length());

            sendEmail(to, subject, body);

            log.info("🔐 ========== sendPasswordResetEmail COMPLETED SUCCESSFULLY ==========");

        } catch (Exception e) {
            log.error("🔐 ❌ EXCEPTION in sendPasswordResetEmail: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void sendEmail(String to, String subject, String body) {
        log.info("========== 📨 SEND EMAIL METHOD ==========");
        log.info("📨 Entering sendEmail at: {}", System.currentTimeMillis());
        log.info("📨 From address (configured): {}", fromAddress);
        log.info("📨 SMTP Username: {}", smtpUsername);
        log.info("📨 To: {}", to);
        log.info("📨 Subject: {}", subject);

        // Log email configuration details (without exposing full password)
        log.info("📨 Mail sender class: {}", mailSender.getClass().getName());

        try {
            log.info("📨 Creating SimpleMailMessage object...");
            SimpleMailMessage message = new SimpleMailMessage();

            log.info("📨 Setting message properties...");
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            message.setFrom(fromAddress);

            log.info("📨 Message created successfully");
            log.info("📨 Message details - From: {}, To: {}, Subject: {}",
                    message.getFrom(),
                    String.join(",", message.getTo()),
                    message.getSubject());

            log.info("📨 Attempting to send email via mailSender.send()...");
            log.info("📨 This is the CRITICAL MOMENT - checking SMTP connection...");

            // Record start time
            long startTime = System.currentTimeMillis();

            // ACTUAL EMAIL SENDING
            mailSender.send(message);

            // Record end time
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            log.info("✅✅✅ EMAIL SENT SUCCESSFULLY! ✅✅✅");
            log.info("✅ Time taken to send: {} ms", duration);
            log.info("✅ Recipient: {}", to);
            log.info("✅ From: {}", fromAddress);
            log.info("✅ Subject: {}", subject);
            log.info("✅ Check inbox/spam folder for: {}", to);

        } catch (MailException e) {
            log.error("❌❌❌ MAIL EXCEPTION CAUGHT ❌❌❌");
            log.error("❌ Exception type: {}", e.getClass().getName());
            log.error("❌ Exception message: {}", e.getMessage());
            log.error("❌ Stack trace:", e);

            // Check for specific SMTP errors
            String errorMsg = e.getMessage();
            if (errorMsg != null) {
                if (errorMsg.contains("Authentication")) {
                    log.error("❌ AUTHENTICATION FAILED - Check MAIL_USERNAME and MAIL_PASSWORD");
                } else if (errorMsg.contains("timed out") || errorMsg.contains("Timeout")) {
                    log.error("❌ CONNECTION TIMEOUT - Check MAIL_HOST and MAIL_PORT");
                } else if (errorMsg.contains("550")) {
                    log.error("❌ SENDER REJECTED - Check if sender '{}' is verified in Brevo", fromAddress);
                } else if (errorMsg.contains("501")) {
                    log.error("❌ SYNTAX ERROR - Check email format");
                } else if (errorMsg.contains("554")) {
                    log.error("❌ TRANSACTION FAILED - Sender may not be verified");
                }
            }

            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);

        } catch (Exception e) {
            log.error("💥💥💥 UNEXPECTED NON-MAIL EXCEPTION 💥💥💥");
            log.error("💥 Exception type: {}", e.getClass().getName());
            log.error("💥 Exception message: {}", e.getMessage());
            log.error("💥 Stack trace:", e);
            throw new RuntimeException("Unexpected error sending email: " + e.getMessage(), e);
        }

        log.info("📨 ========== SEND EMAIL METHOD COMPLETED ==========");
    }
}