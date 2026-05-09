package com.rockrager.authentication.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Component
public class IpGeoLocationUtil {

    @Value("${ip.geolocation.enabled:false}")
    private boolean geoLocationEnabled;

    private final RestTemplate restTemplate = new RestTemplate();

    public String getLocationFromIp(String ipAddress) {
        if (!geoLocationEnabled) {
            return "Location tracking disabled";
        }

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            return "Unknown";
        }

        if (isPrivateIp(ipAddress)) {
            return "Local/Private Network";
        }

        try {
            // Using free ip-api.com (no API key required, rate limited to 45 requests/minute)
            String url = String.format("http://ip-api.com/json/%s?fields=status,city,region,country", ipAddress);
            Map<String, String> response = restTemplate.getForObject(url, Map.class);

            if (response != null && "success".equals(response.get("status"))) {
                String city = response.getOrDefault("city", "");
                String region = response.getOrDefault("region", "");
                String country = response.getOrDefault("country", "");

                if (!city.isEmpty() && !region.isEmpty()) {
                    return String.format("%s, %s, %s", city, region, country);
                } else if (!city.isEmpty()) {
                    return String.format("%s, %s", city, country);
                } else {
                    return country;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to get geolocation for IP: {}", ipAddress, e);
        }

        return "Unknown Location";
    }

    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("172.") ||
                ip.equals("127.0.0.1") ||
                ip.equals("localhost") ||
                ip.equals("0:0:0:0:0:0:0:1");
    }
}