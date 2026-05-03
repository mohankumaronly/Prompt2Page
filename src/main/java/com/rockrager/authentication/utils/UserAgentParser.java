package com.rockrager.authentication.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

@Slf4j
@Component
public class UserAgentParser {

    public Map<String, String> parse(String userAgent) {
        Map<String, String> result = new HashMap<>();

        if (userAgent == null || userAgent.isEmpty()) {
            result.put("device", "Unknown");
            result.put("browser", "Unknown");
            result.put("os", "Unknown");
            return result;
        }

        // Parse OS
        String os = parseOperatingSystem(userAgent);
        result.put("os", os);

        // Parse Browser
        String browser = parseBrowser(userAgent);
        result.put("browser", browser);

        // Parse Device Type
        String device = parseDeviceType(userAgent);
        result.put("device", device);

        return result;
    }

    private String parseOperatingSystem(String userAgent) {
        if (userAgent.contains("Windows")) return "Windows";
        if (userAgent.contains("Mac OS X")) return "macOS";
        if (userAgent.contains("Linux")) return "Linux";
        if (userAgent.contains("Android")) return "Android";
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iPod")) return "iOS";
        return "Unknown OS";
    }

    private String parseBrowser(String userAgent) {
        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) return "Chrome";
        if (userAgent.contains("Firefox")) return "Firefox";
        if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) return "Safari";
        if (userAgent.contains("Edg")) return "Edge";
        if (userAgent.contains("Opera") || userAgent.contains("OPR")) return "Opera";
        return "Unknown Browser";
    }

    private String parseDeviceType(String userAgent) {
        if (userAgent.contains("Mobile")) return "Mobile";
        if (userAgent.contains("Tablet") || userAgent.contains("iPad")) return "Tablet";
        return "Desktop";
    }
}