package com.rockrager.authentication.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSession {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true)
    private String sessionId;

    private String deviceInfo;

    private String ipAddress;

    private String location;

    @Column(nullable = false)
    private LocalDateTime loginAt;

    private LocalDateTime logoutAt;

    @Column(nullable = false)
    private boolean active = true;

    @PrePersist
    protected void onCreate() {
        loginAt = LocalDateTime.now();
    }
}