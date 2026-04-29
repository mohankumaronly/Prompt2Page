package com.rockrager.authentication.security.jwt;

import com.rockrager.authentication.security.user.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        String requestURI = request.getRequestURI();
        String contextPath = request.getContextPath();
        String pathInfo = request.getPathInfo();
        String queryString = request.getQueryString();

        // Log ALL possible path information
        log.info("========== REQUEST PATH DEBUG ==========");
        log.info("Method: {}", request.getMethod());
        log.info("ServletPath: '{}'", servletPath);
        log.info("RequestURI: '{}'", requestURI);
        log.info("ContextPath: '{}'", contextPath);
        log.info("PathInfo: '{}'", pathInfo);
        log.info("QueryString: '{}'", queryString);

        // Check if it matches our patterns
        boolean startsWithAuth = servletPath.startsWith("/api/auth");
        boolean exactTest = servletPath.equals("/test");
        boolean shouldNotFilter = startsWithAuth || exactTest;

        log.info("Starts with /api/auth? {}", startsWithAuth);
        log.info("Equals /test? {}", exactTest);
        log.info("Should NOT filter? {}", shouldNotFilter);
        log.info("========================================");

        return shouldNotFilter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String servletPath = request.getServletPath();
        String requestURI = request.getRequestURI();

        log.info(">>> doFilterInternal processing: {}", requestURI);
        log.info("ServletPath in doFilter: {}", servletPath);

        // Double-check if this should have been filtered
        if (servletPath.startsWith("/api/auth") || servletPath.equals("/test")) {
            log.warn("!!! WARNING: Request to {} reached doFilterInternal despite shouldNotFilter()!", servletPath);
            log.warn("This indicates shouldNotFilter() is not being called or is returning false!");
        }

        final String authHeader = request.getHeader("Authorization");
        log.info("Auth header present: {}", authHeader != null ? "Yes" : "No");

        if (authHeader != null) {
            log.info("Auth header starts with Bearer? {}", authHeader.startsWith("Bearer "));
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.info("No valid Bearer token, continuing chain without authentication");
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        log.info("JWT token extracted, length: {}", jwt.length());

        try {
            final String userEmail = jwtService.extractEmail(jwt);
            log.info("Email extracted from token: {}", userEmail);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("Attempting to authenticate user: {}", userEmail);

                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                log.info("UserDetails loaded: {}", userDetails.getUsername());

                if (jwtService.isTokenValid(jwt, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.info("✅ Successfully authenticated user: {}", userEmail);
                    log.info("Authorities: {}", userDetails.getAuthorities());
                } else {
                    log.warn("❌ Token invalid for user: {}", userEmail);
                }
            }
        } catch (Exception e) {
            log.error("Error processing JWT: {}", e.getMessage(), e);
            filterChain.doFilter(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }
}