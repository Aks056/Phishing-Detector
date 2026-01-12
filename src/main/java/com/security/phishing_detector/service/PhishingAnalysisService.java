package com.security.phishing_detector.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.PhishingDetectionEngine;
import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.domain.RiskLevel;
import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.domain.UrlInfo;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;

@Service
public class PhishingAnalysisService {
    private final PhishingDetectionEngine detectionEngine;
    private final AnalysisHistoryRepository historyRepository;

    @Autowired
    public PhishingAnalysisService(PhishingDetectionEngine detectionEngine, AnalysisHistoryRepository historyRepository) {
        this.detectionEngine = detectionEngine;
        this.historyRepository = historyRepository;
    }

    public ThreatAnalysis analyzeUrl(String url) {
        try {
            UrlInfo urlInfo = new UrlInfo(url);

            if (!urlInfo.isValid()) {
                ThreatAnalysis errorAnalysis = createErrorAnalysis(url, "Invalid or malformed URL");
                saveHistory(url, errorAnalysis.isPhishing(), errorAnalysis.getRiskScore(), List.of());
                return errorAnalysis;
            }

            List<DetectionResult> results = detectionEngine.runAllRules(urlInfo);

            double totalRiskScore = results.stream()
                    .mapToDouble(DetectionResult::getRiskScore)
                    .sum();

            List<String> threats = results.stream()
                    .filter(DetectionResult::isThreatDetected)
                    .map(DetectionResult::getThreatDescription)
                    .collect(Collectors.toList());

            // Enhanced phishing detection logic
            boolean isPhishing = false;
            
            if (totalRiskScore >= 30) isPhishing = true;
            if (hasSuspiciousSubdomain(urlInfo)) isPhishing = true;
            if (!urlInfo.isHttps()) isPhishing = true;
            if (hasFakeBrandDetected(threats)) isPhishing = true;
            RiskLevel riskLevel = RiskLevel.fromScore(totalRiskScore);

            ThreatAnalysis analysis = new ThreatAnalysis(url, isPhishing, totalRiskScore, threats, riskLevel);
            saveHistory(url, isPhishing, totalRiskScore, results);

            return analysis;

        } catch (Exception e) {
            ThreatAnalysis errorAnalysis = createErrorAnalysis(url, "Error analyzing URL: " + e.getMessage());
            saveHistory(url, errorAnalysis.isPhishing(), errorAnalysis.getRiskScore(), List.of());
            return errorAnalysis;
        }
    }

    private void saveHistory(String url, boolean isThreatDetected, double totalRiskScore, List<DetectionResult> results) {
        AnalysisHistory history = new AnalysisHistory(url, isThreatDetected, totalRiskScore, results);
        historyRepository.save(history);
    }

    private ThreatAnalysis createErrorAnalysis(String url, String error) {
        return new ThreatAnalysis(
                url,
                true,
                100.0,
                List.of(error),
                RiskLevel.HIGH
        );
    }

    private boolean hasSuspiciousSubdomain(UrlInfo urlInfo) {
        int subdomainCount = urlInfo.getDomain().split("\\.").length;
        return subdomainCount > 4;
    }

    private boolean hasFakeBrandDetected(List<String> threats) {
        return threats.stream().anyMatch(threat -> 
            threat.toLowerCase().contains("homograph") || 
            threat.toLowerCase().contains("typosquat") ||
            threat.toLowerCase().contains("brand")
        );
    }
}