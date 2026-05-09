package com.rockrager.authentication.repository;

import com.rockrager.authentication.entity.OtpCode;
import com.rockrager.authentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpCodeRepository extends JpaRepository<OtpCode, UUID> {

    Optional<OtpCode> findBySessionIdAndCode(String sessionId, String code);

    Optional<OtpCode> findBySessionId(String sessionId);

    @Query("SELECT o FROM OtpCode o WHERE o.sessionId = :sessionId AND o.used = false AND o.expiresAt > :now")
    Optional<OtpCode> findValidOtpBySessionId(@Param("sessionId") String sessionId, @Param("now") LocalDateTime now);

    @Query("SELECT o FROM OtpCode o WHERE o.user.email = :email AND o.used = false AND o.expiresAt > :now")
    Optional<OtpCode> findActiveOtpByUserEmail(@Param("email") String email, @Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("DELETE FROM OtpCode o WHERE o.user = :user AND o.expiresAt < :now")
    int deleteExpiredOtpsByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("DELETE FROM OtpCode o WHERE o.sessionId = :sessionId AND o.used = false")
    void deleteBySessionIdAndUsedFalse(@Param("sessionId") String sessionId);

    @Modifying
    @Transactional
    @Query("DELETE FROM OtpCode o WHERE o.expiresAt < :now")
    int deleteAllExpiredOtps(@Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("DELETE FROM OtpCode o WHERE o.user = :user AND o.used = false")
    void deleteByUserAndUsedFalse(@Param("user") User user);
}