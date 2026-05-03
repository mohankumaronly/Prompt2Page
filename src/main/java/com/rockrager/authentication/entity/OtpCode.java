package com.rockrager.authentication.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "otp_codes")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpCode {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false)
    private String code;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String sessionId;

    private String deviceInfo;

    private String ipAddress;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean used = false;

    private LocalDateTime verifiedAt;

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}