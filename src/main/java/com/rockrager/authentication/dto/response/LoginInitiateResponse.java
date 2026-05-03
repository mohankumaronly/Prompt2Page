package com.rockrager.authentication.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginInitiateResponse {
    private String sessionId;
    private boolean otpRequired;
    private String message;
    private String otpSentTo;
    private Long expiresIn;
}