package com.security.phishing_detector.detection;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.security.phishing_detector.domain.UrlInfo;

@Component
public class PhishingDetectionEngine {
    private final List<DetectionRule> detectionRules;

    public PhishingDetectionEngine(List<DetectionRule> detectionRules) {
        this.detectionRules = detectionRules;
    }
    
    public List<DetectionResult> runAllRules(UrlInfo urlInfo) {
        return detectionRules.stream()
            .map(rule -> rule.analyze(urlInfo))
            .collect(Collectors.toList());
    }
}