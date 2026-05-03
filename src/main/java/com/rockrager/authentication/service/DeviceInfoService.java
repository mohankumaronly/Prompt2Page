package com.rockrager.authentication.service;

import com.rockrager.authentication.utils.IpGeoLocationUtil;
import com.rockrager.authentication.utils.UserAgentParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceInfoService {

    private final IpGeoLocationUtil ipGeoLocationUtil;
    private final UserAgentParser userAgentParser;

    public String getLocationFromIp(String ipAddress) {
        try {
            return ipGeoLocationUtil.getLocationFromIp(ipAddress);
        } catch (Exception e) {
            log.warn("Failed to get location for IP: {}", ipAddress, e);
            return "Unknown Location";
        }
    }

    public Map<String, String> parseUserAgent(String userAgent) {
        try {
            return userAgentParser.parse(userAgent);
        } catch (Exception e) {
            log.warn("Failed to parse user agent: {}", userAgent, e);
            return Map.of("device", "Unknown", "browser", "Unknown", "os", "Unknown");
        }
    }

    public String getDeviceSummary(String userAgent) {
        Map<String, String> parsed = parseUserAgent(userAgent);
        return String.format("%s on %s",
                parsed.getOrDefault("browser", "Unknown"),
                parsed.getOrDefault("os", "Unknown")
        );
    }
}