package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;
import com.security.phishing_detector.service.ThreatIntelligenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ThreatIntelligenceRule implements DetectionRule {

    private final ThreatIntelligenceService threatIntelligenceService;

    @Autowired
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