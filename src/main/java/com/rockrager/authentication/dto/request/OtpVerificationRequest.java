package com.rockrager.authentication.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpVerificationRequest {

    @NotBlank(message = "Session ID is required")
    private String sessionId;

    @NotBlank(message = "OTP code is required")
    private String otpCode;
}