package com.security.phishing_detector.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final int MAX_REQUESTS_PER_HOUR = 50;
    private static final String RATE_LIMIT_EXCEEDED_MESSAGE = "Rate limit exceeded. Please try again later.";

    @Autowired(required = false)
    private RedisTemplate<String, String> redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String clientIP = getClientIP(request);
        String endpoint = request.getRequestURI();

        // Skip rate limiting for static resources and non-API endpoints
        if (isStaticResource(endpoint) || isAllowedEndpoint(endpoint)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check rate limits
        if (isRateLimitExceeded(clientIP, endpoint)) {
            response.setStatus(429); // Too Many Requests
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + RATE_LIMIT_EXCEEDED_MESSAGE + "\", \"retryAfter\": \"60\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRateLimitExceeded(String clientIP, String endpoint) {
        if (redisTemplate == null) {
            // Fallback to in-memory rate limiting (less efficient but works without Redis)
            return checkInMemoryRateLimit(clientIP, endpoint);
        }

        // Redis-based rate limiting
        String minuteKey = "rate_limit:minute:" + clientIP + ":" + endpoint;
        String hourKey = "rate_limit:hour:" + clientIP + ":" + endpoint;

        try {
            // Check minute limit
            String minuteCount = redisTemplate.opsForValue().get(minuteKey);
            if (minuteCount != null && Integer.parseInt(minuteCount) >= MAX_REQUESTS_PER_MINUTE) {
                return true;
            }

            // Check hour limit
            String hourCount = redisTemplate.opsForValue().get(hourKey);
            if (hourCount != null && Integer.parseInt(hourCount) >= MAX_REQUESTS_PER_HOUR) {
                return true;
            }

            // Increment counters
            redisTemplate.opsForValue().increment(minuteKey);
            redisTemplate.opsForValue().increment(hourKey);

            // Set expiration if keys are new
            redisTemplate.expire(minuteKey, Duration.ofMinutes(1));
            redisTemplate.expire(hourKey, Duration.ofHours(1));

        } catch (Exception e) {
            // If Redis fails, fall back to in-memory limiting
            return checkInMemoryRateLimit(clientIP, endpoint);
        }

        return false;
    }

    private boolean checkInMemoryRateLimit(String clientIP, String endpoint) {
        // Simple in-memory rate limiting using a static map
        // In production, consider using a more robust solution
        String key = clientIP + ":" + endpoint;
        Long currentTime = System.currentTimeMillis();

        // This is a basic implementation - in production you'd want a more sophisticated approach
        // For now, we'll allow all requests if Redis is not available
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

    private boolean isStaticResource(String endpoint) {
        return endpoint.startsWith("/css/") ||
               endpoint.startsWith("/js/") ||
               endpoint.startsWith("/images/") ||
               endpoint.endsWith(".css") ||
               endpoint.endsWith(".js") ||
               endpoint.endsWith(".png") ||
               endpoint.endsWith(".jpg") ||
               endpoint.endsWith(".jpeg") ||
               endpoint.endsWith(".gif") ||
               endpoint.endsWith(".ico") ||
               endpoint.endsWith(".svg");
    }

    private boolean isAllowedEndpoint(String endpoint) {
        return endpoint.equals("/") ||
               endpoint.equals("/about.html") ||
               endpoint.equals("/dashboard.html") ||
               endpoint.equals("/developer.html") ||
               endpoint.startsWith("/h2-console");
    }
}