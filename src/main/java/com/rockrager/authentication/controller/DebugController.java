package com.rockrager.authentication.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/debug")
public class DebugController {

    @GetMapping("/headers")
    public Map<String, Object> getRequestInfo(HttpServletRequest request) {
        Map<String, Object> info = new HashMap<>();

        info.put("method", request.getMethod());
        info.put("requestURI", request.getRequestURI());
        info.put("servletPath", request.getServletPath());
        info.put("contextPath", request.getContextPath());
        info.put("pathInfo", request.getPathInfo());
        info.put("queryString", request.getQueryString());

        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        info.put("headers", headers);

        info.put("serverName", request.getServerName());
        info.put("serverPort", request.getServerPort());
        info.put("remoteAddr", request.getRemoteAddr());

        log.info("Debug request: {}", info);

        return info;
    }

    @PostMapping("/test-auth")
    public Map<String, String> testAuth() {
        return Map.of("message", "Authentication endpoint reached!");
    }
}