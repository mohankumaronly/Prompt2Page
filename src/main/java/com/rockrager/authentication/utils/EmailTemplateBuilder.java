package com.rockrager.authentication.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class EmailTemplateBuilder {

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.name:RockRager Authentication}")
    private String appName;

    @Value("${app.support-email:support@rockrager.com}")
    private String supportEmail;

    public String buildVerificationEmail(String userName, String verificationLink) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "verificationLink", verificationLink,
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Verify Your Email Address",
                buildVerificationContent(variables),
                "warning",
                verificationLink
        );
    }

    public String buildPasswordResetEmail(String userName, String resetLink) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "resetLink", resetLink,
                "appName", appName,
                "supportEmail", supportEmail,
                "baseUrl", baseUrl,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Reset Your Password",
                buildPasswordResetContent(variables),
                "security",
                resetLink
        );
    }

    public String buildWelcomeEmail(String userName) {
        Map<String, String> variables = Map.of(
                "userName", userName != null ? userName : "User",
                "appName", appName,
                "supportEmail", supportEmail,
                "year", String.valueOf(java.time.Year.now().getValue())
        );

        return getEmailLayout(
                "Welcome to " + appName,
                buildWelcomeContent(variables),
                "success",
                null
        );
    }

    private String getEmailLayout(String title, String content, String type, String buttonLink) {
        String buttonHtml = "";
        if (buttonLink != null) {
            buttonHtml = String.format("""
                <div style="text-align: center; margin: 30px 0;">
                    <a href="%s" class="button" style="display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; text-decoration: none; border-radius: 6px; font-weight: 600;">%s</a>
                </div>
                """, buttonLink, title.equals("Verify Your Email Address") ? "Verify Email" : "Reset Password");
        }

        String typeColor = switch (type) {
            case "warning" -> "#ffc107";
            case "success" -> "#28a745";
            case "security" -> "#17a2b8";
            default -> "#667eea";
        };

        return String.format("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        background-color: #f4f4f5;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        max-width: 600px;
                        margin: 20px auto;
                        background: #ffffff;
                        border-radius: 12px;
                        overflow: hidden;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }
                    .header {
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white;
                        padding: 30px 20px;
                        text-align: center;
                    }
                    .header h1 {
                        margin: 0;
                        font-size: 24px;
                        font-weight: 600;
                    }
                    .content {
                        padding: 40px 30px;
                    }
                    .content p {
                        margin: 15px 0;
                    }
                    .button {
                        display: inline-block;
                        padding: 12px 30px;
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white !important;
                        text-decoration: none;
                        border-radius: 6px;
                        font-weight: 600;
                        text-align: center;
                    }
                    .info-box {
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        margin: 20px 0;
                        word-break: break-all;
                        font-family: monospace;
                        font-size: 14px;
                    }
                    .warning-box {
                        background: #fff3cd;
                        border-left: 4px solid #ffc107;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .security-box {
                        background: #d1ecf1;
                        border-left: 4px solid #17a2b8;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .success-box {
                        background: #d4edda;
                        border-left: 4px solid #28a745;
                        padding: 12px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .footer {
                        background: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        font-size: 12px;
                        color: #6c757d;
                        border-top: 1px solid #e9ecef;
                    }
                    .footer a {
                        color: #667eea;
                        text-decoration: none;
                    }
                    @media (max-width: 600px) {
                        .container {
                            margin: 10px;
                        }
                        .content {
                            padding: 20px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>%s</h1>
                    </div>
                    <div class="content">
                        %s
                        %s
                    </div>
                    <div class="footer">
                        <p>© %%s %s. All rights reserved.</p>
                        <p>Need help? <a href="mailto:%%s">Contact Support</a></p>
                        <p>This is an automated message, please do not reply to this email.</p>
                    </div>
                </div>
            </body>
            </html>
            """, title, title, content, buttonHtml, "%s", "%s");
    }

    private String buildVerificationContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>Thank you for registering with <strong>%s</strong>!</p>
            <p>Please verify your email address to get started:</p>
            
            <div class="info-box">
                <a href="%s" style="color: #667eea;">%s</a>
            </div>
            
            <div class="warning-box">
                ⏰ This verification link will expire in <strong>24 hours</strong> for security reasons.
            </div>
            
            <div class="warning-box">
                ⚠️ If you didn't create an account with %s, please ignore this email or 
                <a href="mailto:%s">contact our support team</a>.
            </div>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("verificationLink"),
                vars.get("verificationLink"),
                vars.get("appName"),
                vars.get("supportEmail")
        );
    }

    private String buildPasswordResetContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>We received a request to reset your password for your <strong>%s</strong> account.</p>
            <p>Click the link below to create a new password:</p>
            
            <div class="info-box">
                <a href="%s" style="color: #667eea;">%s</a>
            </div>
            
            <div class="warning-box">
                ⏰ This password reset link will expire in <strong>1 hour</strong> for security reasons.
            </div>
            
            <div class="security-box">
                🔒 If you didn't request a password reset, please ignore this email or 
                <a href="mailto:%s">contact support immediately</a> if you suspect unauthorized access.
            </div>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("resetLink"),
                vars.get("resetLink"),
                vars.get("supportEmail")
        );
    }

    private String buildWelcomeContent(Map<String, String> vars) {
        return String.format("""
            <p>Hello <strong>%s</strong>,</p>
            <p>Welcome to <strong>%s</strong>! We're thrilled to have you on board.</p>
            
            <div class="success-box">
                ✅ Your account has been successfully created and verified!
            </div>
            
            <p>Here's what you can do next:</p>
            <ul>
                <li>Log in to your account</li>
                <li>Update your profile information</li>
                <li>Explore our features</li>
            </ul>
            
            <p>If you have any questions or need assistance, feel free to <a href="mailto:%s">reach out to our support team</a>.</p>
            """,
                vars.get("userName"),
                vars.get("appName"),
                vars.get("supportEmail")
        );
    }
}