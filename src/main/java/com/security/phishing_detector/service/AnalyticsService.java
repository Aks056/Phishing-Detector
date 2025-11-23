package com.security.phishing_detector.service;

import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AnalyticsService {

    private final AnalysisHistoryRepository historyRepository;
    private final ThreatIntelligenceService threatIntelligenceService;

    @Autowired
    public AnalyticsService(AnalysisHistoryRepository historyRepository, ThreatIntelligenceService threatIntelligenceService) {
        this.historyRepository = historyRepository;
        this.threatIntelligenceService = threatIntelligenceService;
    }

    public Map<String, Object> getDashboardStats() {
        Map<String, Object> stats = new HashMap<>();

        // Basic counts
        long totalAnalyses = historyRepository.count();
        long threatCount = historyRepository.countByIsThreatDetected(true);
        long safeCount = totalAnalyses - threatCount;

        stats.put("totalAnalyses", totalAnalyses);
        stats.put("threatCount", threatCount);
        stats.put("safeCount", safeCount);
        stats.put("threatPercentage", totalAnalyses > 0 ? (threatCount * 100.0 / totalAnalyses) : 0.0);

        // Recent activity (last 7 days)
        LocalDateTime weekAgo = LocalDateTime.now().minusDays(7);
        List<AnalysisHistory> recentAnalyses = historyRepository.findByTimestampAfter(weekAgo);
        stats.put("recentAnalyses", recentAnalyses.size());

        // Threat intelligence stats
        stats.put("threatDbSize", threatIntelligenceService.getThreatDatabaseSize());
        stats.put("threatDbLastUpdate", threatIntelligenceService.getLastUpdate());

        // Top threat categories (from detection results)
        Map<String, Long> threatCategories = recentAnalyses.stream()
            .filter(AnalysisHistory::isThreatDetected)
            .flatMap(history -> history.getResults().stream())
            .filter(result -> result.getThreatDescription() != null)
            .collect(Collectors.groupingBy(
                result -> extractCategory(result.getThreatDescription()),
                Collectors.counting()
            ));

        stats.put("topThreatCategories", threatCategories.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(5)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

        // Daily analysis trend (last 7 days)
        Map<String, Long> dailyTrend = new LinkedHashMap<>();
        for (int i = 6; i >= 0; i--) {
            LocalDate date = LocalDate.now().minusDays(i);
            LocalDateTime startOfDay = date.atStartOfDay();
            LocalDateTime endOfDay = date.atTime(23, 59, 59);
            long count = historyRepository.findByTimestampBetween(startOfDay, endOfDay).size();
            dailyTrend.put(date.format(DateTimeFormatter.ofPattern("MMM dd")), count);
        }
        stats.put("dailyTrend", dailyTrend);

        // Risk score distribution
        Map<String, Long> riskDistribution = new LinkedHashMap<>();
        riskDistribution.put("Low (0-25)", (long) historyRepository.findByTotalRiskScoreBetween(0.0, 25.0).size());
        riskDistribution.put("Medium (26-50)", (long) historyRepository.findByTotalRiskScoreBetween(26.0, 50.0).size());
        riskDistribution.put("High (51-75)", (long) historyRepository.findByTotalRiskScoreBetween(51.0, 75.0).size());
        riskDistribution.put("Critical (76-100)", (long) historyRepository.findByTotalRiskScoreBetween(76.0, 100.0).size());
        stats.put("riskDistribution", riskDistribution);

        return stats;
    }

    private String extractCategory(String description) {
        if (description == null) return "Unknown";

        String lowerDesc = description.toLowerCase();
        if (lowerDesc.contains("ssl") || lowerDesc.contains("certificate")) return "SSL Issues";
        if (lowerDesc.contains("domain") || lowerDesc.contains("age")) return "Domain Issues";
        if (lowerDesc.contains("keyword") || lowerDesc.contains("suspicious")) return "Suspicious Content";
        if (lowerDesc.contains("url") || lowerDesc.contains("shortener")) return "URL Structure";
        if (lowerDesc.contains("threat") || lowerDesc.contains("intelligence")) return "Known Threats";
        if (lowerDesc.contains("https")) return "Protocol Issues";

        return "Other";
    }

    public List<Map<String, Object>> getRecentAnalyses(int limit) {
        return historyRepository.findTop10ByOrderByTimestampDesc().stream()
            .limit(limit)
            .map(this::convertToMap)
            .collect(Collectors.toList());
    }

    private Map<String, Object> convertToMap(AnalysisHistory history) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", history.getId());
        map.put("url", history.getUrl());
        map.put("timestamp", history.getTimestamp());
        map.put("isThreatDetected", history.isThreatDetected());
        map.put("totalRiskScore", history.getTotalRiskScore());
        map.put("results", history.getResults());
        return map;
    }
}