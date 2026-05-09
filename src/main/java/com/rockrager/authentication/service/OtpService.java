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
import java.util.concurrent.ConcurrentHashMap;

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

    private final ConcurrentHashMap<String, Boolean> processingMap = new ConcurrentHashMap<>();

    @Transactional
    public String generateAndSendOtp(User user, String sessionId, String deviceInfo, String ipAddress) {
        String userKey = user.getEmail();

        if (processingMap.putIfAbsent(userKey, Boolean.TRUE) != null) {
            log.warn("OTP generation already in progress for user: {}, waiting...", user.getEmail());

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            Optional<OtpCode> existingOtp = otpCodeRepository.findBySessionId(sessionId);
            if (existingOtp.isPresent() && !existingOtp.get().isUsed()) {
                log.info("Returning existing OTP for session: {}", sessionId);
                return existingOtp.get().getCode();
            }
            processingMap.remove(userKey);
        }

        try {
            Optional<OtpCode> existingOtp = otpCodeRepository.findBySessionId(sessionId);
            if (existingOtp.isPresent() && !existingOtp.get().isUsed()) {
                log.info("OTP already exists for session: {}, returning existing OTP", sessionId);
                return existingOtp.get().getCode();
            }

            String otpCode = generateOtpCode();

            log.info("Generating OTP for user: {}", user.getEmail());

            LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(otpExpirationMinutes);

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
            log.info("OTP saved to database for user: {}", user.getEmail());

            try {
                emailService.sendOtpEmail(user.getEmail(), user.getFirstName(), otpCode, otpExpirationMinutes);
                log.info("OTP email sent successfully to: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send OTP email to: {}", user.getEmail(), e);
                throw new RuntimeException("Unable to send OTP. Please try again.");
            }

            return otpCode;
        } finally {
            processingMap.remove(userKey);
        }
    }

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

        otp.setUsed(true);
        otp.setVerifiedAt(LocalDateTime.now());
        otpCodeRepository.save(otp);

        log.info("OTP validated successfully for session: {}", sessionId);
        return true;
    }

    private String generateOtpCode() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    public boolean hasValidOtp(String sessionId) {
        return otpCodeRepository.findValidOtpBySessionId(sessionId, LocalDateTime.now()).isPresent();
    }

    @Transactional
    public void cleanupExpiredOtps(User user) {
        int deletedCount = otpCodeRepository.deleteExpiredOtpsByUser(user, LocalDateTime.now());
        if (deletedCount > 0) {
            log.debug("Cleaned up {} expired OTPs for user: {}", deletedCount, user.getEmail());
        }
    }

    public int getOtpExpirySeconds() {
        return otpExpirationMinutes * 60;
    }

    @Transactional
    public String resendOtp(String sessionId, User user, String deviceInfo, String ipAddress) {
        otpCodeRepository.deleteBySessionIdAndUsedFalse(sessionId);
        return generateAndSendOtp(user, sessionId, deviceInfo, ipAddress);
    }

    public Optional<OtpCode> getOtpRecord(String sessionId) {
        return otpCodeRepository.findBySessionId(sessionId);
    }
}