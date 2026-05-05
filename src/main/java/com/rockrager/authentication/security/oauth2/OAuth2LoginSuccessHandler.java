package com.rockrager.authentication.security.oauth2;

import com.rockrager.authentication.entity.AuthProvider;
import com.rockrager.authentication.entity.User;
import com.rockrager.authentication.entity.UserSession;
import com.rockrager.authentication.repository.UserRepository;
import com.rockrager.authentication.repository.UserSessionRepository;
import com.rockrager.authentication.security.jwt.JwtService;
import com.rockrager.authentication.service.DeviceInfoService;
import com.rockrager.authentication.service.EmailService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserSessionRepository userSessionRepository;
    private final DeviceInfoService deviceInfoService;
    private final EmailService emailService;

    @Value("${app.frontend.url:http://localhost:8080}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");
        String googleId = oAuth2User.getAttribute("sub");

        // Track session with location
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String deviceInfo = deviceInfoService.getDeviceSummary(userAgent);
        String location = deviceInfoService.getLocationFromIp(ipAddress);

        // Check if user is new or existing
        boolean isNewUser = !userRepository.findByEmail(email).isPresent();

        User user;

        if (isNewUser) {
            // Create new user with Google
            user = User.builder()
                    .firstName(firstName != null ? firstName : "Google")
                    .lastName(lastName != null ? lastName : "User")
                    .email(email)
                    .password("")
                    .emailVerified(true)
                    .otpEnabled(false)
                    .role("USER")
                    .googleId(googleId)
                    .authProvider(AuthProvider.GOOGLE)
                    .build();
            user = userRepository.save(user);
            log.info("Created new Google user: {}", email);

            // Send WELCOME email for new user
            sendWelcomeEmail(user, ipAddress, location, deviceInfo);

        } else {
            // Existing user
            user = userRepository.findByEmail(email).get();

            // If user exists with LOCAL provider but hasn't linked Google yet
            if (user.getAuthProvider() == AuthProvider.LOCAL && user.getGoogleId() == null) {
                user.setGoogleId(googleId);
                user = userRepository.save(user);
                log.info("Linked Google account to existing local user: {}", email);
            }

            // Check if this is a new device/login location
            boolean isNewDevice = checkIfNewDevice(user, ipAddress, deviceInfo);
            boolean isNewLocation = checkIfNewLocation(user, location);

            // Send login notification email for existing user
            sendLoginNotificationEmail(user, ipAddress, location, deviceInfo, isNewDevice, isNewLocation);
        }

        // Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        // Update last login info
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        user.setLastLoginDevice(deviceInfo);
        user.setLastLoginLocation(location);
        userRepository.save(user);

        // Create user session
        UserSession session = UserSession.builder()
                .user(user)
                .sessionId(UUID.randomUUID().toString())
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .location(location)
                .loginAt(LocalDateTime.now())
                .active(true)
                .build();
        userSessionRepository.save(session);

        // Set cookies
        setCookie(response, "accessToken", accessToken, 900);
        setCookie(response, "refreshToken", refreshToken, 604800);

        log.info("Google login successful for user: {} from IP: {}", email, ipAddress);

        response.sendRedirect(frontendUrl + "/dashboard.html");
    }

    private void sendWelcomeEmail(User user, String ipAddress, String location, String deviceInfo) {
        try {
            String loginTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String createdAt = user.getCreatedAt() != null ?
                    user.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) : loginTime;

            String htmlContent = String.format("""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <h2 style="color: #4CAF50;">Welcome %s %s! 🎉</h2>
                        <p>Thank you for joining RockRager Authentication!</p>
                        <h3>Account Details:</h3>
                        <ul>
                            <li><strong>Email:</strong> %s</li>
                            <li><strong>Login Method:</strong> Google Account</li>
                        </ul>
                        <h3>Login Information:</h3>
                        <ul>
                            <li><strong>Time:</strong> %s</li>
                            <li><strong>IP Address:</strong> %s</li>
                            <li><strong>Location:</strong> %s</li>
                            <li><strong>Device:</strong> %s</li>
                        </ul>
                        <p>If you didn't create this account, please contact support.</p>
                        <hr>
                        <p style="color: #666;">Best regards,<br>RockRager Team</p>
                    </div>
                </body>
                </html>
                """,
                    user.getFirstName(), user.getLastName(),
                    user.getEmail(),
                    loginTime, ipAddress, location, deviceInfo
            );

            emailService.sendGoogleWelcomeEmail(user.getEmail(), user.getFirstName(), htmlContent);
            log.info("Welcome email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", user.getEmail(), e);
        }
    }

    private void sendLoginNotificationEmail(User user, String ipAddress, String location, String deviceInfo,
                                            boolean isNewDevice, boolean isNewLocation) {
        try {
            String warningMessage = "";
            if (isNewDevice || isNewLocation) {
                StringBuilder warning = new StringBuilder();
                warning.append("<div style='background-color:#fff3cd;border:1px solid #ffc107;padding:10px;border-radius:5px;margin:10px 0;'>");
                warning.append("<strong>⚠️ Security Alert:</strong> This login appears to be from a ");
                if (isNewDevice) warning.append("new device");
                if (isNewDevice && isNewLocation) warning.append(" and ");
                if (isNewLocation) warning.append("new location");
                warning.append(" that you haven't used before.</div>");
                warningMessage = warning.toString();
            }

            String loginTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            String htmlContent = String.format("""
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                        <h2 style="color: #2196F3;">New Google Login Detected</h2>
                        <p>Hello %s %s,</p>
                        <p>We detected a new login using <strong>Google Authentication</strong>.</p>
                        %s
                        <h3>Login Details:</h3>
                        <ul>
                            <li><strong>Time:</strong> %s</li>
                            <li><strong>IP Address:</strong> %s</li>
                            <li><strong>Location:</strong> %s</li>
                            <li><strong>Device:</strong> %s</li>
                        </ul>
                        <p><strong>If this wasn't you:</strong> Please reset your password immediately.</p>
                        <hr>
                        <p style="color: #666;">Best regards,<br>RockRager Team</p>
                    </div>
                </body>
                </html>
                """,
                    user.getFirstName(), user.getLastName(),
                    warningMessage,
                    loginTime, ipAddress, location, deviceInfo
            );

            emailService.sendGoogleLoginEmail(user.getEmail(), user.getFirstName(), htmlContent);
            log.info("Login notification email sent to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send login notification email to: {}", user.getEmail(), e);
        }
    }

    private boolean checkIfNewDevice(User user, String ipAddress, String deviceInfo) {
        try {
            return !userSessionRepository.existsByUserAndDeviceInfoAndIpAddress(user, deviceInfo, ipAddress);
        } catch (Exception e) {
            log.warn("Error checking new device, assuming new device: {}", e.getMessage());
            return true;
        }
    }

    private boolean checkIfNewLocation(User user, String location) {
        try {
            return !userSessionRepository.existsByUserAndLocation(user, location);
        } catch (Exception e) {
            log.warn("Error checking new location, assuming new location: {}", e.getMessage());
            return true;
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }
}