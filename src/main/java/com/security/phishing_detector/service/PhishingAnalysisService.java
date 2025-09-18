package com.security.phishing_detector.service;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.PhishingDetectionEngine;
import com.security.phishing_detector.domain.RiskLevel;
import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class PhishingAnalysisService {
    private final PhishingDetectionEngine detectionEngine;

    @Autowired
    public PhishingAnalysisService(PhishingDetectionEngine detectionEngine) {
        this.detectionEngine = detectionEngine;
    }

    public ThreatAnalysis analyzeUrl(String url) {
        try {
            UrlInfo urlInfo = new UrlInfo(url);

            if (!urlInfo.isValid()) {
                return createErrorAnalysis(url, "Invalid or malformed URL");
            }

            List<DetectionResult> results = detectionEngine.runAllRules(urlInfo);

            double totalRiskScore = results.stream()
                    .mapToDouble(DetectionResult::getRiskScore)
                    .sum();

            List<String> threats = results.stream()
                    .filter(DetectionResult::isThreatDetected)
                    .map(DetectionResult::getThreatDescription)
                    .collect(Collectors.toList());

            boolean isPhishing = totalRiskScore > 50;
            RiskLevel riskLevel = RiskLevel.fromScore(totalRiskScore);

            return new ThreatAnalysis(url, isPhishing, totalRiskScore, threats, riskLevel);

        } catch (Exception e) {
            return createErrorAnalysis(url, "Error analyzing URL: " + e.getMessage());
        }
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
}