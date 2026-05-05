package com.rockrager.authentication.repository;

import com.rockrager.authentication.entity.User;
import com.rockrager.authentication.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    Optional<UserSession> findBySessionId(String sessionId);

    List<UserSession> findByUserAndActiveTrue(User user);

    @Modifying
    @Transactional
    @Query("UPDATE UserSession us SET us.active = false, us.logoutAt = :now WHERE us.sessionId = :sessionId")
    void deactivateSession(@Param("sessionId") String sessionId, @Param("now") LocalDateTime now);

    long countByUserAndActiveTrue(User user);

    // Add these methods for checking new devices and locations

    @Query("SELECT COUNT(us) > 0 FROM UserSession us WHERE us.user = :user AND us.deviceInfo = :deviceInfo AND us.ipAddress = :ipAddress")
    boolean existsByUserAndDeviceInfoAndIpAddress(@Param("user") User user, @Param("deviceInfo") String deviceInfo, @Param("ipAddress") String ipAddress);

    @Query("SELECT COUNT(us) > 0 FROM UserSession us WHERE us.user = :user AND us.location = :location")
    boolean existsByUserAndLocation(@Param("user") User user, @Param("location") String location);

}