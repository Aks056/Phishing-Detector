package com.security.phishing_detector.detection.rules;

import org.springframework.stereotype.Component;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;
import com.security.phishing_detector.service.ThreatIntelligenceService;

@Component
public class ThreatIntelligenceRule implements DetectionRule {

    private final ThreatIntelligenceService threatIntelligenceService;

    public ThreatIntelligenceRule(ThreatIntelligenceService threatIntelligenceService) {
        this.threatIntelligenceService = threatIntelligenceService;
    }

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (!threatIntelligenceService.isEnabled()) {
            return DetectionResult.safe();
        }

        String url = urlInfo.getOriginalUrl();
        if (threatIntelligenceService.isKnownPhishingUrl(url)) {
            return DetectionResult.threat(100.0, "URL found in real-time threat intelligence database");
        }

        return DetectionResult.safe();
    }
}