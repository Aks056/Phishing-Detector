package com.security.phishing_detector.detection;

import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class PhishingDetectionEngine {
    private final List<DetectionRule> detectionRules;
    
    @Autowired
    public PhishingDetectionEngine(List<DetectionRule> detectionRules) {
        this.detectionRules = detectionRules;
    }
    
    public List<DetectionResult> runAllRules(UrlInfo urlInfo) {
        return detectionRules.stream()
            .map(rule -> rule.analyze(urlInfo))
            .collect(Collectors.toList());
    }
}