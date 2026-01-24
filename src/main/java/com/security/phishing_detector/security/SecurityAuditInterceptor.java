package com.security.phishing_detector.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SecurityAuditInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String clientIP = getClientIP(request);
        String userAgent = request.getHeader("User-Agent");
        String method = request.getMethod();
        String uri = request.getRequestURI();

        // Log suspicious activities
        if (isSuspiciousRequest(request)) {
            logger.warn("Suspicious request detected - IP: {}, Method: {}, URI: {}, User-Agent: {}",
                       clientIP, method, uri, userAgent);
        }

        // Log API access for monitoring
        if (uri.startsWith("/api/")) {
            logger.info("API Access - IP: {}, Method: {}, URI: {}", clientIP, method, uri);
        }

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        if (ex != null) {
            String clientIP = getClientIP(request);
            logger.error("Exception occurred for request from IP: {} - URI: {} - Error: {}",
                        clientIP, request.getRequestURI(), ex.getMessage());
        }
    }

    private boolean isSuspiciousRequest(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String uri = request.getRequestURI();

        // Check for common attack patterns
        if (userAgent == null || userAgent.trim().isEmpty()) {
            return true; // No user agent is suspicious
        }

        // Check for SQL injection attempts in URI
        if (uri.matches(".*(\\b(union|select|insert|update|delete|drop|create|alter)\\b).*")) {
            return true;
        }

        // Check for XSS attempts
        if (uri.contains("<script") || uri.contains("javascript:") || uri.contains("onload=")) {
            return true;
        }

        // Check for directory traversal attempts
        if (uri.contains("../") || uri.contains("..\\")) {
            return true;
        }

        return false;
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }

        return request.getRemoteAddr();
    }
}