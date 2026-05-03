package com.rockrager.authentication.service;

import com.rockrager.authentication.utils.EmailTemplateBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailTemplateService {

    private final EmailTemplateBuilder templateBuilder;

    public String buildVerificationEmailTemplate(String userName, String verificationLink) {
        try {
            return templateBuilder.buildVerificationEmail(userName, verificationLink);
        } catch (Exception e) {
            log.error("Failed to build verification email template for user: {}", userName, e);
            return buildFallbackVerificationTemplate(verificationLink);
        }
    }

    public String buildPasswordResetEmailTemplate(String userName, String resetLink) {
        try {
            return templateBuilder.buildPasswordResetEmail(userName, resetLink);
        } catch (Exception e) {
            log.error("Failed to build password reset email template for user: {}", userName, e);
            return buildFallbackResetTemplate(resetLink);
        }
    }

    public String buildWelcomeEmailTemplate(String userName) {
        try {
            return templateBuilder.buildWelcomeEmail(userName);
        } catch (Exception e) {
            log.error("Failed to build welcome email template for user: {}", userName, e);
            return buildFallbackWelcomeTemplate(userName);
        }
    }

    private String buildFallbackVerificationTemplate(String verificationLink) {
        return String.format("""
            <html>
            <body>
                <h2>Verify Your Email</h2>
                <p>Please click the link below to verify your email address:</p>
                <a href="%s">%s</a>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't create an account, please ignore this email.</p>
            </body>
            </html>
            """, verificationLink, verificationLink);
    }

    private String buildFallbackResetTemplate(String resetLink) {
        return String.format("""
            <html>
            <body>
                <h2>Reset Your Password</h2>
                <p>Click the link below to reset your password:</p>
                <a href="%s">%s</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
            </html>
            """, resetLink, resetLink);
    }

    private String buildFallbackWelcomeTemplate(String userName) {
        return String.format("""
            <html>
            <body>
                <h2>Welcome to RockRager!</h2>
                <p>Hello %s,</p>
                <p>Your account has been successfully verified!</p>
                <p>You can now log in to your account.</p>
            </body>
            </html>
            """, userName);
    }
}