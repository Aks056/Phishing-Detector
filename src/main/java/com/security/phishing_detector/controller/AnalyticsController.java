package com.security.phishing_detector.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.security.phishing_detector.service.AnalyticsService;

@RestController
@RequestMapping("/api/v1/analytics")
@CrossOrigin(origins = "*")
public class AnalyticsController {

    private final AnalyticsService analyticsService;

    public AnalyticsController(AnalyticsService analyticsService) {
        this.analyticsService = analyticsService;
    }

    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        try {
            System.out.println("AnalyticsController: Getting dashboard stats...");
            Map<String, Object> stats = analyticsService.getDashboardStats();
            System.out.println("AnalyticsController: Dashboard stats retrieved successfully. Keys: " + stats.keySet());
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            System.err.println("AnalyticsController: Error getting dashboard stats: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> getRecentAnalyses(@RequestParam(defaultValue = "10") int limit) {
        List<Map<String, Object>> recent = analyticsService.getRecentAnalyses(limit);
        return ResponseEntity.ok(recent);
    }
}