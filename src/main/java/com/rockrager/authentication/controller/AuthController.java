package com.rockrager.authentication.controller;

import com.rockrager.authentication.dto.request.*;
import com.rockrager.authentication.dto.response.AuthResponse;
import com.rockrager.authentication.dto.response.LoginInitiateResponse;
import com.rockrager.authentication.repository.UserRepository;
import com.rockrager.authentication.service.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import com.rockrager.authentication.entity.User;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    @Value("${cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${cookie.same-site:Strict}")
    private String cookieSameSite;

    @Value("${cookie.refresh-token-max-age:604800}")
    private int refreshTokenMaxAge;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.login(request);

        Cookie refreshTokenCookie = new Cookie("refreshToken", authResponse.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(cookieSecure);
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setMaxAge(refreshTokenMaxAge);
        refreshTokenCookie.setAttribute("SameSite", cookieSameSite);
        response.addCookie(refreshTokenCookie);

        authResponse.setRefreshToken(null);

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/login/initiate")
    public ResponseEntity<LoginInitiateResponse> initiateLogin(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        String userAgent = httpRequest.getHeader("User-Agent");
        String clientIp = getClientIpAddress(httpRequest);

        if (request.getDeviceInfo() == null) {
            request.setDeviceInfo(userAgent);
        }
        if (request.getIpAddress() == null) {
            request.setIpAddress(clientIp);
        }
        if (request.getUserAgent() == null) {
            request.setUserAgent(userAgent);
        }

        LoginInitiateResponse response = authService.initiateLogin(request);
        return ResponseEntity.ok(response);
    }

    // NEW ENDPOINT - Verify OTP and Complete Login (Step 2)
    @PostMapping("/login/verify")
    public ResponseEntity<AuthResponse> verifyOtpAndLogin(
            @Valid @RequestBody OtpVerificationRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.verifyOtpAndLogin(request);

        if (authResponse.getRefreshToken() != null) {
            Cookie refreshTokenCookie = new Cookie("refreshToken", authResponse.getRefreshToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(cookieSecure);
            refreshTokenCookie.setPath("/api/auth");
            refreshTokenCookie.setMaxAge(refreshTokenMaxAge);
            refreshTokenCookie.setAttribute("SameSite", cookieSameSite);
            response.addCookie(refreshTokenCookie);
        }

        authResponse.setRefreshToken(null);

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            return ResponseEntity.badRequest().build();
        }

        AuthResponse authResponse = authService.refreshToken(refreshToken);

        Cookie refreshTokenCookie = new Cookie("refreshToken", authResponse.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(cookieSecure);
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setMaxAge(refreshTokenMaxAge);
        refreshTokenCookie.setAttribute("SameSite", cookieSameSite);
        response.addCookie(refreshTokenCookie);

        authResponse.setRefreshToken(null);

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            return ResponseEntity.badRequest().body("No refresh token found");
        }

        String result = authService.logout(refreshToken);

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(cookieSecure);
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request
    ) {
        return ResponseEntity.ok(authService.verifyEmail(request.getToken()));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmailWithParam(
            @RequestParam String token
    ) {
        return ResponseEntity.ok(authService.verifyEmail(token));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {
        return ResponseEntity.ok(authService.forgotPassword(request.getEmail()));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        return ResponseEntity.ok(authService.resetPassword(
                request.getToken(),
                request.getNewPassword()
        ));
    }

    @GetMapping("/reset-password")
    public ResponseEntity<String> resetPasswordWithParam(
            @RequestParam String token,
            @RequestParam String newPassword
    ) {
        return ResponseEntity.ok(authService.resetPassword(token, newPassword));
    }

    // Helper method to extract refresh token from cookies
    private String extractRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }
        return ipAddress;
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        log.info("GET /api/auth/me called");

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("message", "Not authenticated"));
        }

        String email = authentication.getName();
        log.info("Fetching user details for: {}", email);

        // Fetch full user from database
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("message", "User not found"));
        }

        return ResponseEntity.ok(Map.of(
                "user", Map.of(
                        "id", user.getId(),
                        "firstName", user.getFirstName(),
                        "lastName", user.getLastName(),
                        "email", user.getEmail(),
                        "emailVerified", user.isEmailVerified(),
                        "createdAt", user.getCreatedAt(),
                        "lastLoginAt", user.getLastLoginAt()
                )
        ));
    }


}