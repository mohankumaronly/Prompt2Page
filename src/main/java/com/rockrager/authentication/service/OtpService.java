package com.rockrager.authentication.service;

import com.rockrager.authentication.entity.OtpCode;
import com.rockrager.authentication.entity.User;
import com.rockrager.authentication.repository.OtpCodeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpCodeRepository otpCodeRepository;
    private final EmailService emailService;

    @Value("${otp.length:6}")
    private int otpLength;

    @Value("${otp.expiration-minutes:5}")
    private int otpExpirationMinutes;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generate and send OTP to user's email
     */
    @Transactional
    public String generateAndSendOtp(User user, String sessionId, String deviceInfo, String ipAddress) {
        // Generate OTP code
        String otpCode = generateOtpCode();

        // Calculate expiry time
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(otpExpirationMinutes);

        // Create OTP entity
        OtpCode otp = OtpCode.builder()
                .code(otpCode)
                .user(user)
                .sessionId(sessionId)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .expiresAt(expiresAt)
                .used(false)
                .build();

        otpCodeRepository.save(otp);

        // Send OTP via email
        try {
            emailService.sendOtpEmail(user.getEmail(), user.getFirstName(), otpCode, otpExpirationMinutes);
            log.info("OTP sent successfully to: {} for session: {}", user.getEmail(), sessionId);
        } catch (Exception e) {
            log.error("Failed to send OTP email to: {}", user.getEmail(), e);
            throw new RuntimeException("Unable to send OTP. Please try again.");
        }

        return otpCode;
    }

    /**
     * Validate OTP code
     */
    @Transactional
    public boolean validateOtp(String sessionId, String otpCode) {
        OtpCode otp = otpCodeRepository.findBySessionIdAndCode(sessionId, otpCode)
                .orElse(null);

        if (otp == null) {
            log.warn("Invalid OTP attempt for session: {}", sessionId);
            return false;
        }

        if (otp.isUsed()) {
            log.warn("OTP already used for session: {}", sessionId);
            return false;
        }

        if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("OTP expired for session: {}", sessionId);
            otpCodeRepository.delete(otp);
            return false;
        }

        // Mark OTP as used
        otp.setUsed(true);
        otp.setVerifiedAt(LocalDateTime.now());
        otpCodeRepository.save(otp);

        log.info("OTP validated successfully for session: {}", sessionId);
        return true;
    }

    /**
     * Generate random numeric OTP code
     */
    private String generateOtpCode() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    /**
     * Check if user has valid OTP for session
     */
    public boolean hasValidOtp(String sessionId) {
        return otpCodeRepository.findValidOtpBySessionId(sessionId, LocalDateTime.now()).isPresent();
    }

    /**
     * Clean up expired OTPs for user
     */
    @Transactional
    public void cleanupExpiredOtps(User user) {
        int deletedCount = otpCodeRepository.deleteExpiredOtpsByUser(user, LocalDateTime.now());
        if (deletedCount > 0) {
            log.debug("Cleaned up {} expired OTPs for user: {}", deletedCount, user.getEmail());
        }
    }

    /**
     * Get OTP expiry time in seconds
     */
    public int getOtpExpirySeconds() {
        return otpExpirationMinutes * 60;
    }

    /**
     * Resend OTP for existing session
     */
    @Transactional
    public String resendOtp(String sessionId, User user, String deviceInfo, String ipAddress) {
        // Delete old unused OTP for this session
        otpCodeRepository.deleteBySessionIdAndUsedFalse(sessionId);

        // Generate and send new OTP
        return generateAndSendOtp(user, sessionId, deviceInfo, ipAddress);
    }

    public Optional<OtpCode> getOtpRecord(String sessionId) {
        return otpCodeRepository.findBySessionId(sessionId);
    }
}